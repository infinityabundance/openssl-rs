#!/usr/bin/env python3
"""Consumer-closure engine for the safe-c33 campaign (V4).

The campaign's C2/C3 receipts describe the intended shape of a consumer
closure but record that no automated generator exists.  This tool builds one.

For a named downstream family it:

1. takes the exact downstream artefact and resolves the loader's *observed*
   library resolution for every ``DT_NEEDED`` OpenSSL soname, recording the
   artefact and each resolved DSO by SHA-256;
2. builds a reachable-call graph over the exact candidate DSOs: imported versioned
   symbols are the roots, direct call edges come from the linked machine code, and
   indirect control transfers are resolved per site from static evidence:
   GOT/PLT relocations, immutable dispatch and vtable tables (`.data.rel.ro`),
   compiler relative jump tables, literal callback stores, field-offset store
   summaries for reachable code, and an interprocedural argument summary for
   callback parameters.  A callback argument whose target set is otherwise
   unbounded is narrowed to the values contributed by callers that are
   themselves reachable in this family (reachable-caller target bounding); a
   non-image value from any reachable caller keeps the site unresolved.  A site
   that cannot be resolved is admitted at its evidence class (field /
   materialised / argument); only a site with no class at all admits the global
   address-taken union, and every such site is listed in the receipt.  A dynamic
   trace, when supplied, is recorded as observed execution
   only; it never narrows the graph, because executing a function does not prove
   unobserved paths unreachable.
3. joins every reachable source file to the safety obligations recorded in the
   V1 candidate freeze (production uncontracted unsafe operations) and to the
   boundary receipts that own them.  The queue is a union: uncontracted
   operations at this identity, documented operations a site receipt and the
   persistent ledger both name, and every obligation enumerated by the previous
   *ACCEPTED* closure whose operation still exists at the same stable identity
   (file + kind + enclosing item), regardless of its documentation state.  A
   contract is not a discharge, so adding one cannot remove an enumerated
   obligation from the queue;
4. adjudicates each obligation ``DISCHARGED`` / ``BLOCKED`` / ``UNKNOWN`` with
   explicit evidence and refuses the whole closure on a stale hash, a dangling
   edge, a missing boundary receipt or an UNKNOWN applicable dependency;
5. emits a machine-readable closure receipt.

What this establishes, and what it does not
-------------------------------------------
The static graph is an upper bound at linked-function granularity: every
direct call in the exact candidate machine code and the target set resolved for
every indirect control transfer.  A function is reachable when any resolved
edge or evidence-class bound admits it.  Functions never observed are still
reachable if a bound admits them.  Inlining is not represented: an inlined
callee's unsafe sites are attributed to the caller's file only when the compiler
emitted no out-of-line function for it.  This is a reachability analysis, not a
proof of memory safety, and ``DISCHARGED`` here means only that an existing
receipt covers the exact site; it does not re-audit the receipt.

Run inside the court container.  Nothing in this tool builds the crate or
modifies source; it reads the admitted install, the committed inventory and
the committed receipts.

Self-test:  python3 forensics/tools/consumer_closure.py --self-test
Example:    python3 forensics/tools/consumer_closure.py \
              --family cyrus-sasl \
              --artifact court/tmp/v4-sasl/candidate/src/plugins/.libs/libdigestmd5.so.3.0.0
"""

from __future__ import annotations

import argparse
import ast
import collections
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "openssl-rs/campaign/safe-c33/consumer-closure/v2"
TOOL = "forensics/tools/consumer_closure.py"
OPENSYM = re.compile(r"^(?:libcrypto|libssl)\.so(?:\.\d+)*$")
FUNC_TYPES = set("TtWw")
V1_PARTITION_PRODUCTION = "production"


# --------------------------------------------------------------------------- #
# small utilities
# --------------------------------------------------------------------------- #

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(argv, *, env=None, stdin=None, check=False):
    res = subprocess.run(argv, capture_output=True, text=True, env=env, input=stdin)
    if check and res.returncode != 0:
        raise RuntimeError(f"{argv[0]} failed ({res.returncode}): {res.stderr.strip()}")
    return res


def now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def parse_nm_line(line: str):
    """Return (address:int|None, type:str, name:str) for an nm row."""
    toks = line.split()
    if len(toks) < 3:
        return None
    if len(toks) == 3:
        a, typ, name = toks
    else:  # "addr type name" with extra columns from some nm builds
        a, typ, name = toks[0], toks[1], toks[2]
    try:
        addr = int(a, 16)
    except ValueError:
        return None
    return addr, typ, name


_LLVM_HASH_SUFFIX = re.compile(r"\.llvm\.[0-9A-Za-z_]+$")


def canonical_symbol_name(name: str) -> str:
    """Drop the compiler-generated content hash from a symbol name.

    LLVM appends a hash of the module identity to private globals
    (``.llvm.<hash>``).  The hash changes when an unrelated source line moves,
    so it names no distinct analysis subject; the address, size and kind in
    the same row keep two distinct symbols distinct.  The version suffix that
    ``nm -D`` prints (``name@@OPENSSL_3.0.0``) is also dropped, matching
    :func:`defined_symbols`.
    """
    return _LLVM_HASH_SUFFIX.sub(".llvm.<hash>", name.split("@")[0])


# --------------------------------------------------------------------------- #
# ELF / loader evidence
# --------------------------------------------------------------------------- #

def elf_dynamic(path: Path) -> dict:
    out = run(["readelf", "-dW", str(path)]).stdout
    needed, runpath, rpath, soname = [], [], [], None
    for line in out.splitlines():
        m = re.search(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", line)
        if m:
            needed.append(m.group(1))
            continue
        m = re.search(r"\(RUNPATH\)\s+Library runpath: \[(.*?)\]", line)
        if m:
            runpath = [x for x in m.group(1).split(":") if x]
            continue
        m = re.search(r"\(RPATH\)\s+Library rpath: \[(.*?)\]", line)
        if m:
            rpath = [x for x in m.group(1).split(":") if x]
            continue
        m = re.search(r"\(SONAME\)\s+Library soname: \[(.+?)\]", line)
        if m:
            soname = m.group(1)
    return {"soname": soname, "needed": needed, "runpath": runpath, "rpath": rpath}


def loader_resolution(artifact: Path, install: Path) -> dict:
    """Resolve libraries the way the loader does, with the refused install on
    LD_LIBRARY_PATH and an otherwise clean environment.  The raw ldd output is
    preserved; the classification is derived from it, never assumed."""
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LD_LIBRARY_PATH": str(install / "lib"),
        "OPENSSL_MODULES": str(install / "lib" / "ossl-modules"),
        "LC_ALL": "C",
    }
    ldd = shutil.which("ldd")
    rows = []
    if ldd:
        res = run([ldd, str(artifact)], env=env)
        raw = res.stdout + res.stderr
        for line in raw.splitlines():
            m = re.match(r"^\s*(\S+)\s+=>\s+(\S+)\s+\(0x[0-9a-f]+\)", line)
            if m:
                rows.append({"soname": m.group(1), "path": m.group(2)})
                continue
            m = re.match(r"^\s*(/lib64/ld-linux\S*)\s+\(0x[0-9a-f]+\)", line)
            if m:
                rows.append({"soname": "ld-linux-x86-64.so.2", "path": m.group(1)})
        method = "ldd with LD_LIBRARY_PATH=<install>/lib, LD_PRELOAD unset"
        rc = res.returncode
    else:  # pragma: no cover - the court image ships ldd
        raw, method, rc = "", "ldd unavailable: loader resolution NOT observed", 127
    return {"method": method, "command_exit": rc, "raw": raw, "rows": rows,
            "environment": {k: v for k, v in env.items() if k != "PATH"}}


def classify_resolution(dynamic: dict, resolution: dict, install: Path) -> dict:
    install_real = install.resolve()
    by_name = {r["soname"]: r["path"] for r in resolution["rows"]}
    openssl = {}
    problems = []
    for name in dynamic["needed"]:
        if not OPENSYM.match(name):
            continue
        path = by_name.get(name)
        if path is None:
            problems.append({"code": "DANGLING_EDGE",
                             "detail": f"{name} is DT_NEEDED but the loader did not resolve it"})
            continue
        real = Path(path).resolve()
        under = str(real).startswith(str(install_real) + os.sep)
        if not real.exists():
            problems.append({"code": "DANGLING_EDGE",
                             "detail": f"{name} resolved to missing file {real}"})
        openssl[name] = {
            "resolved_path": str(real),
            "resolved_sha256": sha256_file(real) if real.exists() else None,
            "under_admitted_install": under,
            "requested_by_dt_needed": name,
        }
        if not under:
            problems.append({"code": "STALE_HASH",
                             "detail": f"{name} resolved to {real}, outside the admitted "
                                       f"install {install_real}"})
    return {"openssl_sonames": openssl,
            "all_openssl_under_install": bool(openssl) and all(
                v["under_admitted_install"] for v in openssl.values()),
            "problems": problems}


def undefined_symbols(path: Path) -> list[dict]:
    out = run(["nm", "-D", "--undefined-only", str(path)]).stdout
    result = []
    for line in out.splitlines():
        toks = line.split()
        if len(toks) < 2:
            continue
        name = toks[-1]
        if name in ("U", "w", "v"):
            continue
        base, _, version = name.partition("@")
        result.append({"name": base, "version": version or None, "raw": name})
    return result


def defined_symbols(path: Path, *, dynamic: bool = False) -> dict:
    argv = ["nm", "-D", "--defined-only"] if dynamic else ["nm", "--defined-only"]
    out = run(argv + [str(path)]).stdout
    result = {}
    for line in out.splitlines():
        parsed = parse_nm_line(line)
        if parsed is None:
            continue
        addr, _typ, name = parsed
        result.setdefault(name.split("@")[0], addr)
    return result


# --------------------------------------------------------------------------- #
# conservative static call graph
# --------------------------------------------------------------------------- #

class DsoGraph:
    """Function-level graph over one linked candidate DSO.

    Nodes are function start addresses.  Edges are:
      * direct calls (``call <addr>``), and calls through a GOT slot whose
        annotated target is a function start;
      * address-taken code references (``lea``/``mov`` whose RIP-relative
        target is a function start);
      * function pointers stored in ``.data.rel.ro``/``.data``/``.rodata``/
        ``.init_array``/``.fini_array``.
    Unresolved indirect calls (``call *%reg``) are counted, not guessed.
    """

    def __init__(self, path: Path, workdir: Path):
        self.path = path
        self.name = path.name
        self.sha256 = sha256_file(path)
        self.workdir = workdir
        self.funcs = self._function_symbols()
        self.starts = sorted(self.funcs)
        self.start_set = set(self.starts)
        self.direct = collections.defaultdict(set)
        self.indirect_sites = 0
        self.indirect_funcs = collections.Counter()
        self.taken_code = set()
        self.taken_data = set()
        self.functions = []
        self.sections = self._elf_sections()
        self.relocs = self._elf_relocs()
        self.dynamic_defs = defined_symbols(path, dynamic=True)
        self.all_syms = self._all_symbols()
        self.sym_sizes = self._symbol_sizes()
        # Per-evidence records filled by the precision resolver / evidence pass.
        self.dlsym_literals = {}
        self.evidence_classes = collections.Counter()
        self.slot_funcs = {}
        self.slot_data = {}
        self.slot_syms = {}
        self._build_slots()
        self.runs = self._reloc_runs()
        self.static_offset_class = {}
        for run in self.runs:
            base = run[0]
            for slot in run:
                self.static_offset_class.setdefault(slot - base, set()).update(
                    self.slot_funcs.get(slot, ()))
        self._disassemble()
        self.precision = None

    def _function_symbols(self) -> dict:
        out = run(["nm", "--defined-only", str(self.path)]).stdout
        funcs = {}
        for line in out.splitlines():
            parsed = parse_nm_line(line)
            if parsed is None:
                continue
            addr, typ, name = parsed
            if typ in FUNC_TYPES:
                funcs.setdefault(addr, name)
        return funcs

    def _all_symbols(self) -> dict:
        """Every defined symbol address -> name (functions and data).

        ``names_at`` keeps *every* name at an address.  Identical-code folding
        gives several exported names one address (for example
        ``EVP_SIGNATURE_up_ref`` and ``EVP_KDF_up_ref``), so a fragment lookup
        that inspected only this dict's single name would miss an in-image
        alias and wrongly refuse a complete target set.
        """
        out = {}
        self.names_at = collections.defaultdict(set)
        for line in run(["nm", "--defined-only", str(self.path)]).stdout.splitlines():
            parsed = parse_nm_line(line)
            if parsed is None:
                continue
            addr, _typ, name = parsed
            out.setdefault(addr, name)
            self.names_at[addr].add(name)
        return out

    def _symbol_sizes(self) -> dict:
        """Defined symbol name -> byte size, from ``nm -S``."""
        out = {}
        for line in run(["nm", "-S", "--defined-only", str(self.path)]).stdout.splitlines():
            toks = line.split()
            if len(toks) < 4:
                continue
            try:
                size = int(toks[1], 16)
            except ValueError:
                continue
            out.setdefault(toks[3].split("@")[0], size)
        return out

    def cstring_at(self, addr: int):
        """The NUL-terminated ASCII identifier at ``addr``, or None.

        Used only for dlsym evidence: the symbol name must be a literal in an
        image section and must look like an exported-symbol name.
        """
        sec = self.section_of(addr)
        if sec is None:
            return None
        a, _off, size = self.sections[sec]
        rel = addr - a
        if rel < 0 or rel >= size:
            return None
        blob = self._section_bytes(sec)[rel:rel + 257]
        nul = blob.find(b"\x00")
        if nul <= 0:
            return None
        try:
            text = blob[:nul].decode("ascii")
        except UnicodeDecodeError:
            return None
        return text if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) else None

    def symbol_at(self, addr: int):
        return self.all_syms.get(addr)

    def seam_symbol(self, addr: int):
        """Name of an allocator-override global at ``addr``, or None.

        The crate's ``runtime::mem`` module keeps the three hooks installed by
        ``CRYPTO_set_mem_functions`` in writable globals.  A load from one of
        those globals is the public allocator-override seam (class O1), which is
        *not* statically bounded: any caller of the public setter can install a
        target outside this image.
        """
        name = self.all_syms.get(addr)
        if not name:
            return None
        m = re.search(r"(MALLOC_FN|REALLOC_FN|FREE_FN)", name)
        return m.group(1) if m else None

    def table_ptrs(self, base: int, count: int, *, stride: int = 8,
                   offset: int = 0, strict: bool = False):
        """Read ``count`` link-time table entries, returning (targets, incomplete).

        ``strict`` marks a table whose entries are all function pointers: a
        non-zero entry that is not a function start is then reported incomplete
        rather than silently ignored.  A table with a non-zero non-function
        entry is *not* evidence-resolved.
        """
        targets, incomplete = set(), []
        for k in range(count):
            addr = base + offset + k * stride
            v = self.static_slot(addr)
            if v is None or not v:
                incomplete.append(addr)
                continue
            ints = {x for x in v if isinstance(x, int) and x != 0}
            funcs = {x for x in ints if x in self.start_set}
            targets |= funcs
            if strict and ints - funcs:
                incomplete.append(addr)
        return targets, incomplete

    def _section_bytes(self, wanted: str):
        sec = self.sections.get(wanted)
        if not sec:
            return b""
        _addr, off, size = sec
        with open(self.path, "rb") as fh:
            fh.seek(off)
            return fh.read(size)

    def text_digest(self) -> tuple[str, int]:
        """sha256 and size of the executable ``.text`` bytes.

        This is the code half of the analysis identity (AGENTS.md section 22):
        a comment-only or documentation-only source edit produces a different
        DSO file digest while ``.text`` stays byte-identical.
        """
        blob = self._section_bytes(".text")
        return hashlib.sha256(blob).hexdigest(), len(blob)

    def symbol_table_rows(self) -> list:
        """Defined symbols as ``[name, addr, size, kind]``, sorted.

        The symbol table is the second half of the analysis identity.  Names
        carry no address information, so a compiler-generated content hash
        suffix is canonicalised (``.llvm.<hex>`` -> ``.llvm.<hash>``); the
        address, size and kind keep two distinct subjects distinct.
        """
        rows = []
        for line in run(["nm", "-S", "--defined-only", str(self.path)]).stdout.splitlines():
            toks = line.split()
            if len(toks) < 4:
                continue
            try:
                addr = int(toks[0], 16)
                size = int(toks[1], 16)
            except ValueError:
                continue
            rows.append([canonical_symbol_name(toks[3]), addr, size, toks[2]])
        rows.sort()
        return rows

    def _elf_sections(self) -> dict:
        out = {}
        self.section_types = {}
        self.section_flags = {}
        for line in run(["readelf", "-SW", str(self.path)]).stdout.splitlines():
            toks = line.split()
            if not toks or not toks[0].startswith("["):
                continue
            if toks[0] == "[":
                name, sec_type = toks[2], toks[3]
                try:
                    addr, off, size = int(toks[4], 16), int(toks[5], 16), int(toks[6], 16)
                except (ValueError, IndexError):
                    continue
            else:
                name, sec_type = toks[1], toks[2]
                try:
                    addr, off, size = int(toks[3], 16), int(toks[4], 16), int(toks[5], 16)
                except (ValueError, IndexError):
                    continue
            out[name] = (addr, off, size)
            self.section_types[name] = sec_type
            m = re.match(
                r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
                r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)",
                line)
            if m:
                self.section_flags[name] = m.group(7)
        return out

    # ------------------------------------------------------------------ #
    # analysis-input identity (AGENTS.md section 22)
    # ------------------------------------------------------------------ #
    #
    # ``analysis_identity`` must cover every input the graph derivation reads.
    # These helpers expose the byte ranges and the structural tables in a
    # canonical form; :func:`analysis_identity` hashes them.  A section that is
    # present but analysis-irrelevant is named in ``excluded_sections`` and is
    # not hashed.  Raw ``.symtab``/``.dynsym``/``.rela.*`` bytes are excluded
    # because their parsed forms are hashed instead (see the basis string).

    def analysis_section_descriptors(self) -> list:
        """Each analysis-relevant section's canonical descriptor.

        The derivation reads sections through ``section_of`` in more places
        than a hand-maintained allowlist can safely cover: ``static_slot``
        reads the GOT/data slots, ``switch_targets`` reads 4-byte entries from
        the section that contains a code-materialised base, and ``cstring_at``
        reads up to 257 bytes from the section that contains a dlsym-literal
        address.  The identity therefore binds **every allocated (SHF_ALLOC)
        section** and excludes only non-allocated metadata.  The required
        minimum (``.text``, ``.rodata``, ``.data``, ``.data.rel.ro``, ``.got``,
        ``.got.plt``) is necessarily a subset of that.
        """
        out = []
        for name, (addr, _off, size) in self.sections.items():
            flags = self.section_flags.get(name, "")
            if "A" not in flags:
                continue
            if any(name.startswith(prefix)
                   for prefix in ANALYSIS_IDENTITY_EXCLUDED_PREFIXES):
                continue
            sec_type = self.section_types.get(name)
            if sec_type == "NOBITS":
                digest = None
            else:
                digest = hashlib.sha256(self._section_bytes(name)).hexdigest()
            out.append({
                "name": name,
                "type": sec_type,
                "addr": addr,
                "size": size,
                "sha256": digest,
            })
        out.sort(key=lambda row: row["name"])
        return out

    def analysis_excluded_sections(self) -> list:
        """Present sections that the identity deliberately excludes."""
        included = {row["name"] for row in self.analysis_section_descriptors()}
        return sorted(name for name in self.sections if name not in included)

    def dynamic_symbol_rows(self) -> list:
        """Sorted ``[canonical name, addr, kind]`` rows of ``.dynsym``.

        ``export_index``, ``PrecisionResolver.exports`` and the dynamic-reloc
        widening all read this table.  It is a different analysis input from
        the full ``.symtab``: a version script can hide an in-image definition
        from ``.dynsym`` while ``.symtab`` still names it.
        """
        rows = []
        for line in run(["nm", "-D", "--defined-only", str(self.path)]).stdout.splitlines():
            parsed = parse_nm_line(line)
            if parsed is None:
                continue
            addr, typ, name = parsed
            rows.append([canonical_symbol_name(name), addr, typ])
        rows.sort()
        return rows

    def canonical_relocations(self) -> list:
        """Sorted ``[section, offset_in_section, type, symbol, addend]`` rows.

        The derivation's ``_build_slots`` reads the relocation addend and
        symbol for ``R_X86_64_RELATIVE``, ``R_X86_64_GLOB_DAT``,
        ``R_X86_64_JUMP_SLOT`` and ``R_X86_64_64``.  Offsets are made relative
        to the containing section so that the row is canonical; the section's
        virtual address is hashed in the section descriptor.
        """
        rows = []
        for off, typ, sym, add, _symval in self.relocs:
            section = self.section_of(off)
            rel_off = off - self.sections[section][0] if section else off
            rows.append([
                section,
                rel_off,
                typ,
                canonical_symbol_name(sym) if sym else None,
                add,
            ])
        rows.sort(key=lambda row: (
            row[0] or "", row[1], row[2], row[3] or "",
            row[4] if row[4] is not None else -1))
        return rows

    def dynamic_entries(self) -> dict:
        """The loader-relevant ``.dynamic`` entries (module selection input)."""
        d = elf_dynamic(self.path)
        return {
            "soname": d["soname"],
            "needed": sorted(d["needed"]),
            "runpath": list(d["runpath"]),
            "rpath": list(d["rpath"]),
        }

    def symbol_addresses_by_name(self) -> dict:
        """Every defined name (version-stripped) -> sorted addresses.

        ``names_at`` keeps every alias at an address (identical-code folding
        gives several exported names one address).  Resolution through this
        table must keep *all* addresses for a name: dropping one would narrow
        the bound.
        """
        index = collections.defaultdict(set)
        for addr, names in self.names_at.items():
            for name in names:
                index[name.split("@")[0]].add(addr)
        return {name: sorted(addrs) for name, addrs in index.items()}

    def _elf_relocs(self) -> list:
        out = []
        for line in run(["readelf", "-rW", str(self.path)]).stdout.splitlines():
            m = re.match(r"^([0-9a-f]{16})\s+([0-9a-f]{16})\s+(R_X86_64_\w+)\s*(.*)$", line)
            if not m:
                continue
            off, typ, rest = int(m.group(1), 16), m.group(3), m.group(4).strip()
            sym, add, symval = None, None, None
            parts = rest.split()
            if len(parts) == 1 and re.fullmatch(r"[0-9a-f]+", parts[0]):
                add = int(parts[0], 16)
            elif parts:
                try:
                    symval = int(parts[0], 16)
                except ValueError:
                    symval = None
                if len(parts) > 1 and not parts[1].startswith("+"):
                    sym = parts[1]
                if len(parts) > 3:
                    try:
                        add = int(parts[3], 16)
                    except ValueError:
                        add = 0
            out.append((off, typ, sym, add, symval))
        return out

    def _build_slots(self) -> None:
        for off, typ, sym, add, symval in self.relocs:
            if typ == "R_X86_64_RELATIVE":
                v = add
                if v is None:
                    continue
                if v in self.start_set:
                    self.slot_funcs.setdefault(off, set()).add(v)
                elif self.section_of(v):
                    self.slot_data.setdefault(off, set()).add(v)
            elif typ in ("R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"):
                if sym:
                    self.slot_syms.setdefault(off, set()).add(sym)
            elif typ == "R_X86_64_64":
                v = (symval or 0) + (add or 0)
                if v in self.start_set:
                    self.slot_funcs.setdefault(off, set()).add(v)
                elif symval is None and sym:
                    self.slot_syms.setdefault(off, set()).add(sym)
                elif self.section_of(v):
                    self.slot_data.setdefault(off, set()).add(v)

    def _reloc_runs(self) -> list:
        runs = []
        for off in sorted(self.slot_funcs):
            if runs and off - runs[-1][-1] <= 24:
                runs[-1].append(off)
            else:
                runs.append([off])
        return runs

    def section_of(self, addr: int):
        for name, (a, _o, s) in self.sections.items():
            if a <= addr < a + s:
                return name
        return None

    def is_data(self, addr: int) -> bool:
        sec = self.section_of(addr)
        return sec is not None and sec not in (".text", ".plt", ".plt.got")

    def containing(self, addr: int):
        import bisect
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.starts[i] if i >= 0 else None

    def read_u32(self, addr: int):
        """Raw little-endian u32 in an image section, or None."""
        sec = self.section_of(addr)
        if sec is None:
            return None
        a, _off, size = self.sections[sec]
        rel = addr - a
        if rel < 0 or rel + 4 > size:
            return None
        return struct.unpack_from("<I", self._section_bytes(sec), rel)[0]

    def read_u64(self, addr: int):
        """Raw little-endian u64 in an image section, or None."""
        sec = self.section_of(addr)
        if sec is None:
            return None
        a, _off, size = self.sections[sec]
        rel = addr - a
        if rel < 0 or rel + 8 > size:
            return None
        return struct.unpack_from("<Q", self._section_bytes(sec), rel)[0]

    def static_slot(self, addr: int):
        """Values fixed by load time (relocation, raw pointer, or BSS zero)."""
        if addr in self.slot_funcs:
            return frozenset(self.slot_funcs[addr])
        if addr in self.slot_data:
            return frozenset(self.slot_data[addr])
        if addr in self.slot_syms:
            return frozenset(("sym", s) for s in self.slot_syms[addr])
        sec = self.section_of(addr)
        if sec == ".bss":
            return frozenset({0})
        if sec in (".data", ".data.rel.ro", ".rodata", ".got", ".got.plt"):
            a, off, size = self.sections[sec]
            if 0 <= addr - a <= size - 8:
                with open(self.path, "rb") as fh:
                    fh.seek(off + (addr - a))
                    v = struct.unpack("<Q", fh.read(8))[0]
                if v in self.start_set:
                    return frozenset({v})
                if self.section_of(v):
                    return frozenset({v})
            return frozenset({0})
        return None

    def _disassemble(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        dis = self.workdir / (self.name + "." + self.sha256[:16] + ".dis")
        self.dis_path = dis
        if not dis.exists():
            with open(dis, "w") as fh:
                subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(self.path)],
                               stdout=fh, check=True)
        pat_head = re.compile(r"^([0-9a-f]+) <(.*)>:$")
        pat_ins = re.compile(r"^\s+([0-9a-f]+):\t(.*)$")
        pat_direct = re.compile(r"^(?:call|jmp)\w*\s+([0-9a-f]+) <")
        pat_comment = re.compile(r"#\s*([0-9a-f]+)\s+<")
        cur = None
        cur_insns = None
        with open(dis, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                m = pat_head.match(line)
                if m:
                    cur = int(m.group(1), 16)
                    cur_insns = []
                    self.functions.append((cur, cur_insns))
                    continue
                m = pat_ins.match(line)
                if not m or cur is None:
                    continue
                ins_addr = int(m.group(1), 16)
                text = m.group(2).strip()
                if cur_insns is not None:
                    cur_insns.append((ins_addr, text))
                toks = text.split()
                op = toks[0] if toks else ""
                if op.startswith("call"):
                    m2 = pat_direct.match(text)
                    if m2:
                        base = self._containing(int(m2.group(1), 16))
                        if base is not None and base != cur:
                            self.direct[cur].add(base)
                        continue
                    m3 = pat_comment.search(text)
                    if m3:
                        tgt = int(m3.group(1), 16)
                        if tgt in self.start_set:
                            if tgt != cur:
                                self.direct[cur].add(tgt)
                            continue
                    self.indirect_sites += 1
                    self.indirect_funcs[cur] += 1
                elif op.startswith("lea") or op.startswith("mov"):
                    for m3 in pat_comment.finditer(text):
                        tgt = int(m3.group(1), 16)
                        if tgt in self.start_set:
                            self.taken_code.add(tgt)
        for sec in (".data.rel.ro", ".data", ".data.rel.ro.local", ".rodata",
                    ".init_array", ".fini_array"):
            blob = self._section_bytes(sec)
            for i in range(0, max(0, len(blob) - 7), 8):
                value = struct.unpack_from("<Q", blob, i)[0]
                if value in self.start_set:
                    self.taken_data.add(value)

    def _containing(self, addr: int):
        lo, hi, best = 0, len(self.starts) - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.starts[mid] <= addr:
                best = self.starts[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    def init_roots(self) -> set:
        """Constructor/destructor entries are executed by the loader."""
        roots = set()
        for sec in (".init_array", ".fini_array"):
            blob = self._section_bytes(sec)
            for i in range(0, max(0, len(blob) - 7), 8):
                value = struct.unpack_from("<Q", blob, i)[0]
                if value in self.start_set:
                    roots.add(value)
        return roots

    @property
    def taken(self) -> set:
        return self.taken_code | self.taken_data

    @property
    def slot_func_targets(self) -> set:
        """Functions named in link-time-constant (relocated) data slots."""
        return {v for vs in self.slot_funcs.values() for v in vs}


# --------------------------------------------------------------------------- #
# precision resolver: per-site indirect-call resolution
# --------------------------------------------------------------------------- #

MAX_SET = 64
_TOP = None
_REGS = ["%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%rsp",
         "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"]
_SUBREG = {}
for _p, _subs in {
    "%rax": ("%eax", "%ax", "%al", "%ah"),
    "%rbx": ("%ebx", "%bx", "%bl", "%bh"),
    "%rcx": ("%ecx", "%cx", "%cl", "%ch"),
    "%rdx": ("%edx", "%dx", "%dl", "%dh"),
    "%rsi": ("%esi", "%si", "%sil"),
    "%rdi": ("%edi", "%di", "%dil"),
    "%rbp": ("%ebp", "%bp", "%bpl"),
    "%rsp": ("%esp", "%sp", "%spl"),
}.items():
    for _s in _subs:
        _SUBREG[_s] = _p
for _p in ("%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"):
    for _suf in ("d", "w", "b"):
        _SUBREG[_p + _suf] = _p
_CALLER_SAVED = {"%rax", "%rcx", "%rdx", "%rsi", "%rdi", "%r8", "%r9", "%r10", "%r11"}
_ARGREGS = ("%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9")


def _canon(reg):
    return _SUBREG.get(reg, reg)


def _is_compare(mn: str) -> bool:
    """True for a compare/test mnemonic, including objdump's size suffixes.

    A memory-operand compare is printed with its operand size (`cmpq $0,
    (%rsp)`); treating only bare `cmp` as a compare let the generic fall-through
    take the memory operand as a destination and clobber a tracked stack slot.
    """
    return (mn.startswith("cmp") or mn.startswith("test")
            or mn in ("ucomiss", "comiss", "ptest", "bt"))


def _split_ops(text):
    ops, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            ops.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        ops.append("".join(cur).strip())
    return ops


class PValue:
    """A finite set of concrete values (ints or symbolic tuples), or TOP."""
    __slots__ = ("s",)

    def __init__(self, s=_TOP):
        self.s = s

    @staticmethod
    def one(v):
        return PValue(frozenset({v}))

    def is_top(self):
        return self.s is None

    def union(self, other):
        other = _as_value(other)
        if self.s is None or other.s is None:
            return PValue()
        u = self.s | other.s
        if len(u) > MAX_SET:
            return PValue()
        return PValue(u)


def _as_value(x):
    if isinstance(x, PValue):
        return x
    if x is None:
        return PValue()
    return PValue(x)


class _Frame:
    __slots__ = ("regs", "stack", "escaped", "rsp", "comment_addr", "fstart",
                 "rbp_delta")

    def __init__(self):
        self.regs = {r: PValue() for r in _REGS}
        self.regs["%rsp"] = PValue.one(("rspbase",))
        for i, r in enumerate(_ARGREGS):
            self.regs[r] = PValue.one(("arg", i))
        self.stack = {}
        self.escaped = set()
        self.rsp = 0
        self.comment_addr = None
        self.fstart = None
        self.rbp_delta = None

    def copy(self):
        f = _Frame.__new__(_Frame)
        f.regs = dict(self.regs)
        f.stack = dict(self.stack)
        f.escaped = set(self.escaped)
        f.rsp = self.rsp
        f.comment_addr = self.comment_addr
        f.fstart = self.fstart
        f.rbp_delta = self.rbp_delta
        return f

    def merge(self, other):
        changed = False
        for r, v in other.regs.items():
            cur = _as_value(self.regs.get(r))
            u = cur.union(v)
            if u.s != cur.s:
                self.regs[r] = u
                changed = True
        for k, v in other.stack.items():
            cur = self.stack.get(k)
            u = _as_value(v) if cur is None else cur.union(v)
            if cur is None or u.s != cur.s:
                self.stack[k] = u
                changed = True
        if not other.escaped <= self.escaped:
            self.escaped |= other.escaped
            changed = True
        if other.rsp != self.rsp:
            if self.stack:
                self.stack.clear()
                changed = True
        return changed


class PrecisionResolver:
    """Resolve indirect control transfers with static evidence.

    Every site is assigned the set of candidate callees it can actually reach,
    or an explicit unresolved reason.  The resolver never uses an observed
    trace and never treats "not observed" as unreachable.
    """

    def __init__(self, g: "DsoGraph", imports: set | None = None):
        self.g = g
        self.sites = {}
        self.store_slots = collections.defaultdict(set)
        self.field_stores = collections.defaultdict(set)
        self.field_open = set()
        self.switch_cache = {}
        # Compiler switch tables carry an explicit bound: the `cmp $N, idx` /
        # unsigned-above branch that guards the table.  `switch_bounds[base]`
        # records the entry count decoded from that bound; a base absent from
        # the map has no recognised bound and keeps the conservative scan.
        self.switch_bounds = {}
        self.calls = []
        self.summary = collections.defaultdict(lambda: [set() for _ in _ARGREGS])
        # The calls list is the single owner of interprocedural argument values:
        # entries are (caller_fstart, callee_fstart, args, call_site).  Keeping
        # the call site in the existing list avoids a second per-call record.
        self.insns_by_func = dict(g.functions)
        self.summary_open = collections.defaultdict(set)
        self.exports = set(g.dynamic_defs.values())
        self.import_addrs = set(imports or ())
        self.class_counts = collections.Counter()
        self.unknown_call_args = set()
        self.returns = collections.defaultdict(set)
        self.dlsym_evidence = {}
        # Provenance mode (off by default; used only by the stored-value slot
        # rule).  It seeds each function's entry arguments symbolically and
        # records outgoing *stack* arguments at every call, so a writer's
        # stored value can be followed to the caller's parameter list.
        self.seed_entry_args = False
        self.capture_stack_args = False
        self.call_stack_args = {}
        # Global store summaries are not needed (and are very large) when only
        # call-argument provenance is wanted.
        self.record_stores = True

    # ---- dlsym evidence -------------------------------------------------- #

    def dlsym_literal(self, frame):
        """The literal symbol name passed to ``dlsym`` at this call, or None.

        Only a value that is a single in-image address pointing at a
        NUL-terminated identifier is accepted.  A computed, loaded or otherwise
        non-literal argument returns None, which leaves the site unresolved --
        that is the negative control for class R1.
        """
        v = _as_value(frame.regs.get("%rsi"))
        if v.is_top() or len(v.s) != 1:
            return None
        val = next(iter(v.s))
        if not isinstance(val, int):
            return None
        return self.g.cstring_at(val)

    # ---- values ---------------------------------------------------------- #

    def slot_value(self, addr):
        base = _as_value(self.g.static_slot(addr))
        if addr in self.store_slots:
            extra = self.store_slots[addr]
            if extra is None:
                return PValue()
            base = _as_value(base.s | extra) if not base.is_top() else PValue()
        return base

    def table_read(self, addr, scale, limit=256):
        out, complete = set(), True
        for k in range(limit):
            v = self.slot_value(addr + k * scale)
            if v.is_top():
                complete = False
                break
            ints = {x for x in v.s if isinstance(x, int)}
            if not ints:
                break
            out |= {x for x in ints if x in self.g.start_set}
        return out, complete

    def field_bound(self, off):
        out = {v for v in self.field_stores.get(off, ())
               if isinstance(v, int) and v in self.g.start_set}
        if off in self.field_open:
            out |= set(self.g.taken_code) | set(self.import_addrs)
        return out

    def field_bases(self, off):
        return {v for v in self.field_stores.get(off, ())
                if isinstance(v, int) and self.g.is_data(v)}

    def switch_targets(self, base, site_addr=None):
        key = (base, site_addr)
        if key in self.switch_cache:
            return self.switch_cache[key]
        sec = self.g.section_of(base)
        targets = set()
        if sec:
            a, _off, size = self.g.sections[sec]
            data = self.g._section_bytes(sec)
            start = base - a
            count = self.switch_bounds.get(site_addr) if site_addr is not None else None
            if count is not None:
                # Exact table length, from the compiler's own bounds check.
                end = min(len(data) - 3, start + count * 4)
            else:
                # No decodable bound: retain the conservative scan rather than
                # guessing a length.
                end = min(len(data) - 3, start + 65536)
            for i in range(start, end, 4):
                v = struct.unpack_from("<i", data, i)[0]
                tgt = base + v
                if tgt in self.g.start_set:
                    targets.add(tgt)
        self.switch_cache[key] = targets
        return targets

    def _record_switch_bounds(self, insns):
        """Decode compiler-emitted switch-table lengths for one function.

        A relative jump table is guarded by the compiler's own bound:
        ``cmp $N, idx`` followed by an unsigned-above branch.  ``N + 1``
        entries are then live (``N`` for ``jae``).  Reading past that bound
        admits whatever int32 happens to follow the table in ``.rodata`` as a
        relative entry, which invents reachability.  The bound is keyed by the
        indirect jump's own address, because the table base can be loaded well
        before the bound check and unrelated ``lea``s may sit in between.  A
        jump without a recognised bound keeps the conservative scan (negative
        control).
        """
        for i, (addr, text) in enumerate(insns):
            body = text.split("#", 1)[0].strip()
            if not (body.startswith("jmp") and "*" in body):
                continue
            # The index register of the relative table load, e.g.
            # `movslq (%rcx,%rax,4),%rax` or `movslq 0x0(%rbp,%rcx,4),%rax`.
            index = None
            for j in range(i - 1, max(-1, i - 9), -1):
                ins = insns[j][1].split("#", 1)[0].strip()
                m = re.match(r"^movs[lq]q?\s+.*\([^,]+,(%[a-z0-9]+),[48]\)", ins)
                if m:
                    index = _canon(m.group(1))
                    break
            for j in range(i - 1, max(-1, i - 31), -1):
                t = insns[j][1].split("#", 1)[0].strip()
                m = re.match(r"^cmp\w*\s+\$0x([0-9a-f]+),(%[a-z0-9]+)", t)
                if not m:
                    continue
                # A bound is evidence only when it compares the table's own
                # index register; a nearby compare of another value is not.
                if index is not None and _canon(m.group(2)) != index:
                    continue
                bound = int(m.group(1), 16)
                exclusive = False
                found = False
                for k in range(j + 1, i):
                    branch = insns[k][1].split("#", 1)[0].strip()
                    if re.match(r"^ja\s", branch):
                        found = True
                        break
                    if re.match(r"^jae\s", branch):
                        exclusive = True
                        found = True
                        break
                if not found:
                    # No unsigned-above branch between the compare and the
                    # indirect jump: this compare does not guard the table.
                    continue
                self.switch_bounds.setdefault(addr, bound if exclusive else bound + 1)
                break

    def summary_vals(self, f, k):
        """The argument summary for index ``k`` (empty beyond the register set).

        Provenance mode carries symbolic stack-argument values (indices 6 and
        above); the summary table covers only the six register arguments, so an
        out-of-range index has no summary rather than raising.
        """
        return self.summary[f][k] if 0 <= k < len(_ARGREGS) else set()

    def resolve_set(self, f, vals):
        if vals is None:
            return set(), True
        out = set()
        for b in vals:
            if isinstance(b, tuple) and b[0] == "arg":
                out |= self.summary_vals(f, b[1])
            else:
                out.add(b)
        return out, False

    def build_summary(self):
        consumer_obtainable = set(self.import_addrs)
        for f in self.import_addrs:
            consumer_obtainable |= self.returns.get(f, set())
        for f in self.exports:
            for k in range(len(_ARGREGS)):
                self.summary[f][k] |= consumer_obtainable
        changed, rounds = True, 0
        while changed and rounds < 8:
            changed = False
            rounds += 1
            for caller, callee, args, _call_site in self.calls:
                if callee is None:
                    continue
                for k, vs in enumerate(args):
                    vals = None if vs.is_top() else vs.s
                    res, bad = self.resolve_set(caller, vals)
                    if bad:
                        self.summary_open[callee].add(k)
                    new = {v for v in res if isinstance(v, int)}
                    if new - self.summary[callee][k]:
                        self.summary[callee][k] |= new
                        changed = True
        return rounds

    # ---- intraprocedural abstract interpretation ------------------------- #

    def frame_key(self, frame, opnd):
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", opnd)
        if not m:
            return None
        off = int(m.group(1), 16) if m.group(1) else 0
        if m.group(2) == "%rsp":
            return ("rsp", frame.rsp + off)
        if frame.rbp_delta is not None:
            return ("rsp", frame.rbp_delta + off)
        return None

    def eval(self, frame, opnd):
        opnd = opnd.strip()
        if opnd in frame.regs:
            return _as_value(frame.regs[opnd])
        if opnd.startswith("$"):
            try:
                return PValue.one(int(opnd[1:], 16))
            except ValueError:
                return PValue()
        key = self.frame_key(frame, opnd)
        if key is not None:
            return _as_value(frame.stack.get(key))
        if "(%rip)" in opnd and re.fullmatch(r"-?0x[0-9a-f]+\(%rip\)", opnd):
            addr = frame.comment_addr
            if addr is None:
                return PValue()
            seam = self.g.seam_symbol(addr)
            if seam is not None:
                vals = {("seam", seam)}
                v = self.slot_value(addr)
                if not v.is_top():
                    vals |= v.s
                return PValue(frozenset(vals))
            return self.slot_value(addr)
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+),(%r[a-z0-9]+),([148])\)", opnd)
        if m:
            off = int(m.group(1), 16) if m.group(1) else 0
            scale = int(m.group(4))
            base = frame.regs.get(m.group(2), PValue())
            if base.is_top():
                return PValue(frozenset({("field", off)}))
            out, fieldish = set(), False
            for b in base.s:
                if isinstance(b, int) and b != 0:
                    vals, complete = self.table_read(b + off, scale)
                    out |= vals
                    if not complete:
                        fieldish = True
                elif isinstance(b, int) and b == 0:
                    continue
                else:
                    fieldish = True
            if fieldish:
                out.add(("field", off))
            return PValue(frozenset(out)) if out else PValue()
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
        if m:
            base = frame.regs.get(m.group(2), PValue())
            off = int(m.group(1), 16) if m.group(1) else 0
            if base.is_top():
                return PValue(frozenset({("field", off)}))
            out, fieldish = set(), False
            for b in base.s:
                if isinstance(b, tuple) and b[0] in ("arg", "field"):
                    fieldish = True
                elif isinstance(b, tuple):
                    if b[0] == "rspbase":
                        v = _as_value(frame.stack.get(("rsp", frame.rsp + off)))
                    elif b[0] == "rbpbase":
                        k = ("rsp", frame.rbp_delta + off) if frame.rbp_delta is not None \
                            else ("rbp", off)
                        v = _as_value(frame.stack.get(k))
                    else:
                        fieldish = True
                        continue
                    if v.is_top():
                        fieldish = True
                    else:
                        out |= v.s or {0}
                elif isinstance(b, int):
                    if b == 0:
                        continue
                    if self.g.section_of(b) is None:
                        fieldish = True
                        continue
                    v = self.slot_value(b + off)
                    if v.is_top():
                        fieldish = True
                    else:
                        out |= v.s or {0}
                else:
                    fieldish = True
            if fieldish:
                out.add(("field", off))
            return PValue(frozenset(out)) if out else PValue()
        return PValue()

    def addr_of(self, frame, opnd):
        if "(%rip)" in opnd:
            tgt = frame.comment_addr
            return PValue.one(tgt) if tgt is not None else PValue()
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
        if m:
            base = frame.regs.get(m.group(2), PValue())
            off = int(m.group(1), 16) if m.group(1) else 0
            if base.is_top():
                return PValue()
            out = set()
            for b in base.s:
                if isinstance(b, tuple) and b[0] == "rspbase":
                    out.add(("rsp", frame.rsp + off))
                elif isinstance(b, tuple) and b[0] == "rbpbase":
                    if frame.rbp_delta is not None:
                        out.add(("rsp", frame.rbp_delta + off))
                    else:
                        out.add(("rbp", off))
                elif isinstance(b, int):
                    out.add(b + off)
                else:
                    return PValue()
            return PValue(frozenset(out))
        return PValue()

    def eval_indexed(self, frame, opnd):
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+),(%r[a-z0-9]+),([148])\)", opnd)
        if not m:
            return PValue()
        base = frame.regs.get(m.group(2), PValue())
        if base.is_top() or len(base.s) != 1:
            return PValue()
        b = next(iter(base.s))
        if isinstance(b, int):
            off = int(m.group(1), 16) if m.group(1) else 0
            return PValue(frozenset({("rel32", b + off)}))
        return PValue()

    # ---- site classification --------------------------------------------- #

    def note_site(self, kind, fstart, addr, text, targets, unresolved, reason,
                  klass, field_offsets=(), seam=None, arg_deps=(),
                  arg_targets=()):
        key = (fstart, addr, kind)
        prev = self.sites.get(key)
        if prev is None:
            self.sites[key] = {
                "kind": kind, "func": fstart, "addr": addr, "text": text,
                "targets": set(targets), "unresolved": unresolved,
                "reason": reason, "class": klass,
                "field_offsets": set(field_offsets), "seam": seam,
                "arg_deps": set(arg_deps),
                "arg_targets": set(arg_targets),
            }
            return
        prev["targets"] |= targets
        prev["field_offsets"] |= set(field_offsets)
        prev["arg_deps"] |= set(arg_deps)
        prev["arg_targets"] |= set(arg_targets)
        if seam and not prev.get("seam"):
            prev["seam"] = seam
        if unresolved and not prev["unresolved"]:
            prev["unresolved"] = True
            prev["reason"] = reason
            prev["class"] = klass

    def analyze_transfer(self, kind, frame, fstart, addr, text, opnd):
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+),(%r[a-z0-9]+),([148])\)", opnd)
        if m:
            off = int(m.group(1), 16) if m.group(1) else 0
            scale = int(m.group(4))
            base = _as_value(frame.regs.get(m.group(2)))
            if base.is_top():
                self.note_site(kind, fstart, addr, text,
                               self.field_bound(off), True, "field-of-unknown-base",
                               "field", field_offsets={off})
                return self.field_bound(off), True
            targets, unresolved = set(), False
            for b in base.s:
                if isinstance(b, int) and b != 0:
                    vals, complete = self.table_read(b + off, scale)
                    targets |= vals
                    if not complete:
                        unresolved = True
                elif isinstance(b, int) and b == 0:
                    continue
                else:
                    targets |= self.field_bound(off)
            self.note_site(kind, fstart, addr, text, targets, unresolved,
                           "indexed-table" if not unresolved else "indexed-table-partial",
                           "table" if not unresolved else "field")
            return targets, unresolved
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\(%rip\)", opnd)
        if m:
            slot = frame.comment_addr
            v = self.slot_value(slot) if slot is not None else PValue()
            if v.is_top():
                self.note_site(kind, fstart, addr, text, set(), True,
                               "rip-slot-open", "unclassified")
                return set(), True
            targets = set()
            for x in v.s:
                if isinstance(x, int) and x in self.g.start_set:
                    targets.add(x)
                elif isinstance(x, tuple) and x[0] == "sym":
                    targets.add(x)
            self.note_site(kind, fstart, addr, text, targets, False, "rip-slot",
                           "got-or-table")
            return targets, False
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
        if m:
            off = int(m.group(1), 16) if m.group(1) else 0
            if m.group(2) == "%rsp" or frame.rbp_delta is not None:
                key = self.frame_key(frame, opnd)
                sv = _as_value(frame.stack.get(key)) if key is not None else PValue()
                if sv.is_top():
                    self.note_site(kind, fstart, addr, text, set(), True,
                                   "stack-slot-open", "materialised")
                    return set(), True
                targets = set()
                unresolved = False
                seam = None
                arg_deps = set()
                arg_raw = set()
                for x in sv.s:
                    if isinstance(x, tuple) and x[0] == "arg":
                        vals = self.summary_vals(fstart, x[1])
                        targets |= vals
                        arg_deps.add(x[1])
                        arg_raw |= vals
                    elif isinstance(x, tuple) and x[0] == "field":
                        targets |= self.field_bound(x[1])
                    elif isinstance(x, tuple) and x[0] == "sym":
                        targets.add(x)
                    elif isinstance(x, tuple) and x[0] == "seam":
                        seam = x[1]
                    elif isinstance(x, int) and x in self.g.start_set:
                        targets.add(x)
                    elif isinstance(x, int) and x == 0:
                        pass
                    else:
                        unresolved = True
                self.note_site(kind, fstart, addr, text, targets, unresolved,
                               "stack-slot" if not unresolved else "stack-slot-partial",
                               "resolved" if not unresolved else "materialised",
                               seam=seam, arg_deps=arg_deps,
                               arg_targets={v for v in arg_raw
                                            if isinstance(v, int)
                                            and v in self.g.start_set})
                return targets, unresolved
            base = _as_value(frame.regs.get(m.group(2)))
            if base.is_top():
                self.note_site(kind, fstart, addr, text, self.field_bound(off),
                               True, "field-of-unknown-base", "field",
                               field_offsets={off})
                return self.field_bound(off), True
            targets, unresolved = set(), False
            seam = None
            for b in base.s:
                if isinstance(b, tuple) and b[0] == "seam":
                    seam = b[1]
                elif isinstance(b, tuple) and b[0] == "arg":
                    targets |= self.field_bound(off)
                    for tb in {x for x in self.summary_vals(fstart, b[1])
                               if isinstance(x, int) and self.g.is_data(x)}:
                        v = self.slot_value(tb + off)
                        if v.is_top():
                            unresolved = True
                        else:
                            targets |= {x for x in v.s if isinstance(x, int)
                                        and x in self.g.start_set}
                elif isinstance(b, tuple) and b[0] == "field":
                    if b[1] in self.field_open:
                        unresolved = True
                    for tb in self.field_bases(b[1]):
                        v = self.slot_value(tb + off)
                        if v.is_top():
                            unresolved = True
                        else:
                            targets |= {x for x in v.s if isinstance(x, int)
                                        and x in self.g.start_set}
                elif isinstance(b, int):
                    v = self.slot_value(b + off)
                    if v.is_top():
                        unresolved = True
                    else:
                        targets |= {x for x in v.s if isinstance(x, int)
                                    and x in self.g.start_set}
                elif isinstance(b, tuple) and b[0] in ("rsp", "rbp"):
                    v = _as_value(frame.stack.get(b))
                    if v.is_top():
                        unresolved = True
                    else:
                        targets |= {x for x in v.s if isinstance(x, int)
                                    and x in self.g.start_set}
                elif isinstance(b, tuple) and b[0] == "sym":
                    pass
                else:
                    unresolved = True
            klass = "resolved" if not unresolved else "field"
            self.note_site(kind, fstart, addr, text, targets, unresolved,
                           "base-slot" if not unresolved else "base-slot-partial",
                           klass, field_offsets={off}, seam=seam)
            return targets, unresolved
        if opnd in frame.regs:
            v = _as_value(frame.regs[opnd])
            if v.is_top():
                self.note_site(kind, fstart, addr, text, set(), True, "reg-top",
                               "materialised")
                return set(), True
            resolved, arg_open = set(), False
            arg_deps = set()
            arg_raw = set()
            for b in v.s:
                if isinstance(b, tuple) and b[0] == "arg":
                    vals = self.summary_vals(fstart, b[1])
                    resolved |= vals
                    arg_deps.add(b[1])
                    arg_raw |= vals
                    if not vals and b[1] in self.summary_open[fstart]:
                        arg_open = True
                else:
                    resolved.add(b)
            v = PValue(frozenset(resolved))
            targets, unresolved, switch, partial = set(), arg_open, set(), set()
            field_offsets = set()
            seam = None
            for b in v.s:
                if isinstance(b, int):
                    if b in self.g.start_set:
                        targets.add(b)
                    elif b == 0:
                        pass
                    elif self.g.is_data(b):
                        pass
                    else:
                        unresolved = True
                        partial.add("int")
                elif isinstance(b, tuple) and b[0] == "switch":
                    switch.add(b[1])
                elif isinstance(b, tuple) and b[0] == "field":
                    targets |= self.field_bound(b[1])
                    field_offsets.add(b[1])
                elif isinstance(b, tuple) and b[0] == "arg":
                    unresolved = True
                    partial.add("arg")
                elif isinstance(b, tuple) and b[0] == "sym":
                    targets.add(b)
                elif isinstance(b, tuple) and b[0] == "seam":
                    seam = b[1]
                elif isinstance(b, tuple) and b[0] in ("rsp", "rbp"):
                    sv = _as_value(frame.stack.get(b))
                    if sv.is_top():
                        unresolved = True
                        partial.add("stack")
                    else:
                        for x in sv.s:
                            if isinstance(x, int) and x in self.g.start_set:
                                targets.add(x)
                            elif isinstance(x, tuple) and x[0] in ("sym",):
                                targets.add(x)
                            elif isinstance(x, tuple) and x[0] == "field":
                                targets |= self.field_bound(x[1])
                                field_offsets.add(x[1])
                            elif isinstance(x, tuple) and x[0] == "arg":
                                unresolved = True
                                partial.add("arg")
                            elif isinstance(x, int) and x == 0:
                                pass
                            else:
                                unresolved = True
                                partial.add("other")
                else:
                    unresolved = True
                    partial.add("other")
            for t in switch:
                targets |= self.switch_targets(t, addr)
            klass = "resolved" if not unresolved else "materialised"
            self.note_site(kind, fstart, addr, text, targets, unresolved,
                           "reg-value" if not unresolved else
                           "reg-value-partial[" + ",".join(sorted(partial)) + "]",
                           klass, field_offsets=field_offsets, seam=seam,
                           arg_deps=arg_deps,
                           arg_targets={x for x in arg_raw
                                        if isinstance(x, int)
                                        and x in self.g.start_set})
            return targets, unresolved
        self.note_site(kind, fstart, addr, text, set(), True,
                       "unsupported-operand:" + opnd, "unclassified")
        return set(), True

    # ---- instruction semantics ------------------------------------------- #

    def assign(self, frame, dst, v):
        if dst in frame.regs:
            frame.regs[dst] = v
            return
        key = self.frame_key(frame, dst)
        if key is not None:
            frame.stack[key] = v
            return
        if not self.record_stores:
            return
        m = re.fullmatch(r"(-?0x[0-9a-f]+)\(%rip\)", dst)
        if m:
            slot = frame.comment_addr
            if slot is not None:
                self.record_store(slot, self.resolve_store_value(frame.fstart, v))
            return
        m = re.fullmatch(r"(-?0x[0-9a-f]+)\((%r[a-z0-9]+)\)", dst)
        if m and m.group(2) not in ("%rsp", "%rbp"):
            off = int(m.group(1), 16)
            v = self.resolve_store_value(frame.fstart, v)
            if v.is_top():
                self.field_open.add(off)
            else:
                self.field_stores[off] |= v.s

    @staticmethod
    def _arg_witness(insns, i):
        """First writer of each argument register on the linear path to a call.

        A single backward scan from the call instruction.  The abstract value
        at the call is the real evidence; this only records which instruction
        established it, and is deliberately local to the call site.
        """
        want = {_canon(r): r for r in _ARGREGS}
        found = {}
        for j in range(i - 1, max(-1, i - 64), -1):
            body = insns[j][1].split("#", 1)[0].strip()
            if not body:
                continue
            toks = body.split(None, 1)
            mn = toks[0]
            rest = toks[1].strip() if len(toks) > 1 else ""
            if mn.startswith("call"):
                break
            ops = _split_ops(rest)
            if not ops:
                continue
            dst = _canon(ops[-1]) if ops[-1] in _SUBREG else ops[-1]
            if dst in want and want[dst] not in found:
                found[want[dst]] = (insns[j][0], insns[j][1])
                if len(found) == len(want):
                    break
        return found

    def record_store(self, slot, v):
        cur = self.store_slots.get(slot)
        if cur is None:
            self.store_slots[slot] = set() if not v.is_top() else None
        elif cur is not None:
            if v.is_top():
                self.store_slots[slot] = None
            else:
                cur |= v.s

    def resolve_store_value(self, f, v):
        if v.is_top():
            return v
        out = set()
        for b in v.s:
            if isinstance(b, tuple) and b[0] == "arg":
                out |= self.summary_vals(f, b[1])
            elif isinstance(b, tuple) and b[0] == "field":
                out |= self.field_bound(b[1])
            elif isinstance(b, tuple) and b[0] == "sym":
                out.add(b)
            elif isinstance(b, tuple) and b[0] == "seam":
                out.add(b)
            elif isinstance(b, int):
                out.add(b)
        return PValue(frozenset(out)) if out else PValue.one(0)

    def escape(self, frame, v):
        if v.is_top():
            return
        for b in v.s:
            if isinstance(b, tuple) and b[0] in ("rsp", "rbp"):
                frame.escaped.add(b)

    def _capture_call_stack_args(self, fstart, addr, frame, count=4):
        """Record the outgoing stack arguments at this call.

        Index 6 is at 0(%rsp) before the call; index 7 at 8(%rsp), and so on.
        Only used in provenance mode.
        """
        vals = self.call_stack_args.get((fstart, addr))
        if vals is None:
            vals = [PValue() for _ in range(count)]
            self.call_stack_args[(fstart, addr)] = vals
        while len(vals) < count:
            vals.append(PValue())
        for k in range(count):
            v = _as_value(frame.stack.get(("rsp", frame.rsp + 8 * k)))
            if v.is_top():
                continue
            vals[k] = v if vals[k].is_top() else vals[k].union(v)

    def step(self, frame, fstart, insns, i):
        addr, text = insns[i]
        comment = None
        if "#" in text:
            c = text.split("#", 1)[1].strip()
            m = re.match(r"^([0-9a-f]+)", c)
            if m:
                comment = int(m.group(1), 16)
        frame.comment_addr = comment
        body = text.split("#", 1)[0].strip()
        toks = body.split(None, 1)
        mn = toks[0]
        rest = toks[1].strip() if len(toks) > 1 else ""
        raw_ops = _split_ops(rest)
        ops = [_canon(o) if o in _SUBREG else o for o in raw_ops]
        sub_dst = bool(raw_ops) and raw_ops[-1] in _SUBREG

        if mn.startswith("call") and rest.startswith("*"):
            opnd = rest.lstrip("*").strip()
            args = [_as_value(frame.regs[r]) for r in _ARGREGS]
            if self.capture_stack_args:
                self._capture_call_stack_args(fstart, addr, frame)
            targets, _unres = self.analyze_transfer(
                "call", frame, fstart, addr, text, opnd)
            retvals = set()
            for t in targets:
                if isinstance(t, int):
                    self.calls.append((fstart, t, args, addr))
                    retvals |= self.returns.get(t, set())
            if any(isinstance(t, tuple) and t[0] == "sym"
                   and t[1].split("@")[0] == "dlsym" for t in targets):
                lit = self.dlsym_literal(frame)
                if lit is not None:
                    exported = lit in self.g.dynamic_defs
                    rec = self.g.dlsym_literals.setdefault(
                        lit, {"sites": set(), "exported": exported})
                    rec["sites"].add((fstart, addr))
                    self.dlsym_evidence[(fstart, addr)] = rec
                    retvals = {("sym", lit)} if exported else set()
            if _unres:
                for a in args:
                    vals = None if a.is_top() else a.s
                    res, _bad = self.resolve_set(fstart, vals)
                    for v in res:
                        if isinstance(v, int):
                            self.unknown_call_args.add(v)
            for r in _CALLER_SAVED:
                frame.regs[r] = PValue()
            frame.regs["%rax"] = PValue(frozenset(retvals)) if retvals and not _unres \
                else PValue()
            for k in list(frame.stack):
                if k in frame.escaped:
                    frame.stack[k] = PValue()
            return
        if mn.startswith("call"):
            args = [_as_value(frame.regs[r]) for r in _ARGREGS]
            if self.capture_stack_args:
                self._capture_call_stack_args(fstart, addr, frame)
            m = re.match(r"^([0-9a-f]+)", rest)
            callee = None
            if m:
                callee = self.g.containing(int(m.group(1), 16))
                if callee is not None:
                    self.calls.append((fstart, callee, args, addr))
            for r in _CALLER_SAVED:
                frame.regs[r] = PValue()
            cname = (self.g.funcs.get(callee, "") if callee is not None else "")
            if cname.split("@")[0] == "dlsym":
                lit = self.dlsym_literal(frame)
                if lit is not None and lit in self.g.dynamic_defs:
                    frame.regs["%rax"] = PValue.one(("sym", lit))
            elif callee is not None and self.returns.get(callee):
                frame.regs["%rax"] = PValue(frozenset(self.returns[callee]))
            for k in list(frame.stack):
                if k in frame.escaped:
                    frame.stack[k] = PValue()
            return
        if mn.startswith("jmp") and rest.startswith("*"):
            opnd = rest.lstrip("*").strip()
            self.analyze_transfer("jmp", frame, fstart, addr, text, opnd)
            return
        if mn.startswith(("ret", "iret")):
            v = _as_value(frame.regs.get("%rax"))
            if not v.is_top():
                for b in v.s:
                    if isinstance(b, int):
                        self.returns[fstart].add(b)
                    elif isinstance(b, tuple) and b[0] == "sym":
                        self.returns[fstart].add(b)
            return
        if mn in ("nop", "nopw", "nopl") or mn.startswith("data16") or mn.startswith("cs"):
            return
        # Objdump emits a size suffix on memory-operand compares (`cmpq $0,
        # (%rsp)`); treating only the bare `cmp` mnemonic as a compare let the
        # generic fall-through below take the compare's last operand as a
        # destination and clobber the stack slot it was testing.
        if _is_compare(mn):
            return
        if mn.startswith(("push", "pop")):
            if mn == "push":
                frame.rsp -= 8
                if ops:
                    v = self.eval(frame, ops[0])
                    if self.capture_stack_args:
                        frame.stack[("rsp", frame.rsp)] = v
                    self.escape(frame, v)
            else:
                frame.rsp += 8
                if ops:
                    frame.regs[ops[0]] = PValue()
            return
        if mn == "mov" and len(ops) == 2 and ops[0] == "%rsp" and ops[1] == "%rbp":
            frame.regs["%rbp"] = PValue()
            frame.rbp_delta = frame.rsp
            return
        if mn == "mov" and len(ops) == 2:
            src, dst = ops
            if sub_dst and not src.startswith("$"):
                self.assign(frame, dst, PValue())
                return
            self.assign(frame, dst, self.eval(frame, src))
            return
        if mn == "lea" and len(ops) == 2:
            src, dst = ops
            self.assign(frame, dst, PValue() if sub_dst else self.addr_of(frame, src))
            return
        if mn in ("movzbl", "movzwl", "movslq", "movsbl", "movswl", "movsbq",
                  "movzwq", "movzbq") and len(ops) == 2:
            src, dst = ops
            v = self.eval_indexed(frame, src)
            if v.is_top():
                v = self.eval(frame, src)
                if not v.is_top():
                    v = PValue()
            self.assign(frame, dst, v)
            return
        if mn.startswith("cmov") and len(ops) == 2:
            src, dst = ops
            if sub_dst:
                frame.regs[dst] = PValue()
                return
            frame.regs[dst] = frame.regs.get(dst, PValue()).union(self.eval(frame, src))
            return
        if mn in ("xor", "sub") and len(ops) == 2 and ops[0] == ops[1] and ops[0] in frame.regs:
            frame.regs[ops[0]] = PValue.one(0)
            return
        if mn in ("add", "sub") and len(ops) == 2:
            src, dst = ops
            if dst == "%rsp" and src.startswith("$"):
                off = int(src[1:], 16)
                frame.rsp += -off if mn == "sub" else off
                return
            if sub_dst:
                frame.regs[dst] = PValue()
                return
            if dst in frame.regs:
                base = frame.regs[dst]
                if src.startswith("$") and not base.is_top():
                    off = int(src[1:], 16)
                    if mn == "sub":
                        off = -off
                    out = set()
                    for b in base.s:
                        if isinstance(b, tuple) and b[0] == "rel32":
                            out.add(("switch", b[1]))
                        elif isinstance(b, int):
                            out.add(b + off)
                        else:
                            out.add(b)
                    frame.regs[dst] = PValue(frozenset(out))
                    return
                if src in frame.regs and not base.is_top() and not frame.regs[src].is_top():
                    other = frame.regs[src]
                    out = set()
                    for a in base.s:
                        for b in other.s:
                            if isinstance(a, tuple) and a[0] == "rel32" and isinstance(b, int):
                                out.add(("switch", a[1]))
                            elif isinstance(b, tuple) and b[0] == "rel32" and isinstance(a, int):
                                out.add(("switch", b[1]))
                            elif isinstance(a, int) and isinstance(b, int):
                                out.add(a + b)
                            else:
                                out.add(a)
                    frame.regs[dst] = PValue(frozenset(out))
                    return
            frame.regs[dst] = PValue()
            return
        if mn in ("inc", "dec") and len(ops) == 1 and ops[0] in frame.regs:
            base = frame.regs[ops[0]]
            if base.is_top():
                frame.regs[ops[0]] = PValue()
            else:
                off = 1 if mn == "inc" else -1
                frame.regs[ops[0]] = PValue(frozenset(
                    b + off if isinstance(b, int) else b for b in base.s))
            return
        if ops:
            dst = ops[-1]
            if dst in frame.regs:
                frame.regs[dst] = PValue()
            else:
                key = self.frame_key(frame, dst)
                if key is not None:
                    frame.stack[key] = PValue()

    def analyze_function(self, fstart, insns):
        if not insns:
            return
        self._record_switch_bounds(insns)
        addr_index = {a: i for i, (a, _t) in enumerate(insns)}
        leaders = {0}
        for i, (_a, text) in enumerate(insns):
            m = re.match(r"^j\w+\s+([0-9a-f]+)", text)
            if m:
                t = int(m.group(1), 16)
                if t in addr_index:
                    leaders.add(addr_index[t])
                if i + 1 < len(insns):
                    leaders.add(i + 1)
            elif text.startswith("jmp") or text.startswith("ret"):
                if i + 1 < len(insns):
                    leaders.add(i + 1)
        leaders = sorted(leaders)
        block_of, blocks = {}, []
        for bi, lo in enumerate(leaders):
            hi = leaders[bi + 1] if bi + 1 < len(leaders) else len(insns)
            blocks.append((lo, hi))
            for i in range(lo, hi):
                block_of[i] = bi
        succ = collections.defaultdict(list)
        for bi, (_lo, hi) in enumerate(blocks):
            _la, last = insns[hi - 1]
            m = re.match(r"^(j\w+)\s+([0-9a-f]+)", last)
            if m:
                t = int(m.group(2), 16)
                if t in addr_index:
                    succ[bi].append(block_of[addr_index[t]])
                if not last.startswith("jmp") and hi < len(insns):
                    succ[bi].append(bi + 1)
            elif last.startswith("ret"):
                pass
            elif last.startswith("jmp"):
                pass
            elif hi < len(insns):
                succ[bi].append(bi + 1)
        entry = {0: _Frame()}
        entry[0].fstart = fstart
        if self.seed_entry_args:
            # Symbolic entry arguments.  Register arguments are indices 0-5;
            # stack arguments start at entry rsp + 8 (the return address is at
            # rsp) and are indices 6 and above.
            for k, r in enumerate(_ARGREGS):
                entry[0].regs[r] = PValue.one(("arg", k))
            for k in range(8):
                entry[0].stack[("rsp", 8 + 8 * k)] = PValue.one(("arg", 6 + k))
        work, iters = [0], 0
        while work:
            bi = work.pop()
            iters += 1
            if iters > 200000:
                break
            frame = entry[bi].copy()
            lo, hi = blocks[bi]
            for i in range(lo, hi):
                self.step(frame, fstart, insns, i)
            for s in succ[bi]:
                if s not in entry:
                    entry[s] = frame.copy()
                    work.append(s)
                elif entry[s].merge(frame):
                    work.append(s)

    def run(self, passes=3):
        for pass_no in range(1, passes + 1):
            if pass_no >= 2:
                self.build_summary()
                self.sites = {}
                self.store_slots = collections.defaultdict(set)
                self.field_stores = collections.defaultdict(set)
                self.field_open = set()
                self.unknown_call_args = set()
            self.calls = []
            self.call_stack_args = {}
            for fstart, insns in self.g.functions:
                self.analyze_function(fstart, insns)
        return self.sites

    def publish(self):
        g = self.g
        g.sites = self.sites
        g.field_stores = self.field_stores
        g.field_open = self.field_open
        g.unknown_call_arg_targets = set(self.unknown_call_args)
        g.precision_counts = collections.Counter(
            (s["class"], s["unresolved"]) for s in self.sites.values())
        g.site_reasons = collections.Counter(
            s["reason"] for s in self.sites.values())
        g.resolved_targets = {t for s in self.sites.values()
                              for t in s["targets"]}
        g.residual_sites = [s for s in self.sites.values() if s["unresolved"]]
        # Dynamic-relocation targets: a ``R_X86_64_GLOB_DAT``/``JUMP_SLOT``
        # slot whose symbol is *defined in this image* fixes a function address
        # exactly as a ``R_X86_64_RELATIVE`` run does.  ``slot_funcs`` only
        # holds the RELATIVE form, so without this widening a function reached
        # through a GOT slot (for example CRYPTO_cbc128_encrypt, referenced by
        # 25 slots from 21 callers) is absent from the module's
        # materialised-address evidence and a sound residual bound cannot
        # contain it.  Only symbol-defined addresses inside ``start_set`` are
        # admitted; imported symbols resolve in another DSO and are reached
        # through the export index instead.
        by_name = {}
        for addr, names in g.names_at.items():
            for name in names:
                by_name.setdefault(name.split("@")[0], addr)
        g.dynamic_reloc_targets = set()
        for names in g.slot_syms.values():
            for name in names:
                base = name.split("@")[0]
                addr = g.dynamic_defs.get(base)
                if addr is None:
                    addr = by_name.get(base)
                if addr in g.start_set:
                    g.dynamic_reloc_targets.add(addr)
        g.address_taken_union = (set(g.taken_code) | set(g.taken_data)
                                 | {v for vs in g.slot_funcs.values() for v in vs}
                                 | set(g.dynamic_reloc_targets))
        return g.sites


# --------------------------------------------------------------------------- #
# evidence classes for indirect sites inside the linked image
# --------------------------------------------------------------------------- #
#
# The precision resolver is deliberately local: a value it cannot follow is
# admitted at its evidence class rather than guessed.  The classes below encode
# evidence that is *external to the local value flow* but still bounds the target
# set at the link/image level.  Each class states the invariant it relies on; a
# class whose invariant cannot be checked against the exact candidate is not
# applied, and the site stays unresolved.

# R2: the linked Rust core/std image.  These are compiler-constructed
# trait-object vtables and runtime hooks (panic hook, Once initialiser, libc
# syscall/weak pointers, libunwind callback).  The crate cannot install an
# application-supplied OpenSSL callback through a Rust vtable: the vtable is
# built by the compiler for a trait object whose methods are monomorphised in
# core/std, and the only code that writes such a slot is that same std/core
# routine.  The target set is therefore the address-taken functions of the
# linked core/std image, never an application symbol.
RUST_RUNTIME_FRAGMENTS = ("CsgxBkk5gSRhY_4core", "Cs9k3SxhrAWiO_3std",
                          "___rustc")

# R3: link-time-constant OpenSSL tables.  Each key names the enclosing function
# and the table that fixes the entries; the tool re-reads the entries from the
# exact candidate image (a symbol + offset or a field-store set) rather than
# trusting a recorded target list.
R3_FUNCTIONS = ("11int_ctx_new", "12def_load_bio", "14template_clear",
                "6do_adb", "19camellia_ecb_cipher", "ECDH_compute_key")

# A1: provider / method-store dispatch.  The immediate callee is a built-in
# provider implementation in the image; the target set can only grow through a
# provider module loaded from configuration.  That path is reachable in these
# workloads: libssl's OPENSSL_init_ssl adds OPENSSL_INIT_LOAD_CONFIG
# unconditionally and SSL_CTX_new_ex calls it, so a configuration file can name
# an external module.  The *target set* is therefore unbounded, but the
# obligation is bounded by the public provider ABI contract, so the site is
# encoded as ABI_CONTRACT_PROVIDER (never as a resolved in-image target set).
A1_FUNCTIONS = ("algorithm_do_this", "ossl_method_store_cache_set",
                "ossl_method_store_fetch", "ossl_method_store_cache_get",
                "ossl_method_store_add", "impl_cache_flush_cache",
                "impl_cache_free_thunk", "impl_free_thunk",
                "alg_cleanup_by_provider", "alg_cleanup",
                "construct_evp_method", "destruct_evp_method",
                "ossl_method_construct_this", "ossl_method_construct_reserve_store",
                "inner_evp_generic_fetch", "provider_init",
                "ossl_provider_doall_activated", "encoder_import_cb",
                "cipher_generic_init_internal")

# A2: legacy method-table dispatch.  The immediate callee is a link-time entry
# of a built-in EVP_PKEY_METHOD/EVP_MD/EVP_CIPHER/BIO_METHOD/UI_METHOD/
# X509_LOOKUP_METHOD/CONF_METHOD table.  The bound holds only while the
# workload imports no setter for those families; the check below enforces it.
A2_FUNCTIONS = ("evp_pkey_asym_cipher_init", "evp_pkey_derive_init",
                "do_sigver_init", "pmeth_func_cmp",
                "PEM_ASN1_write_bio_internal", "ui_read", "check_crl")

# Setters that would let the workload install a table entry for the A2 families.
A2_REGISTRATION_SETTERS = frozenset({
    "EVP_MD_meth_new", "EVP_CIPHER_meth_new", "EVP_PKEY_meth_new",
    "EVP_PKEY_asn1_new", "EVP_PKEY_asn1_add0", "BIO_meth_new",
    "UI_create_method", "X509_LOOKUP_meth_new", "CONF_module_add",
})

# --------------------------------------------------------------------------- #
# contract-bounded classes
# --------------------------------------------------------------------------- #
#
# A contract-bounded class is *not* a resolved edge.  The site keeps an unbounded
# target set and stays in the closure's residual list; what the class establishes
# is that the site's safety precondition is carried by a public OpenSSL ABI
# contract, which AGENTS.md section 7 criterion 2 admits as a discharged caller
# obligation.  The receipt keeps these classes distinct from a statically
# resolved target set so a reader cannot mistake one for the other.
ABI_CONTRACT_PROVIDER = "ABI_CONTRACT_PROVIDER"
ABI_CONTRACT_ALLOCATOR = "ABI_CONTRACT_ALLOCATOR"
# A callback that is exactly a parameter of an exported function.  This is a
# contract about the *caller's* value, not about an in-image callback: the
# header declares the parameter as a function-pointer type and .dynsym makes
# the caller boundary external.  It never absorbs a finite in-image callback;
# those are deferred to the reachable-caller-target rule (see
# export_callback_witness).
ABI_CONTRACT_EXPORT_CALLBACK = "ABI_CONTRACT_EXPORT_CALLBACK"
ABI_CONTRACT_CLASSES = frozenset({ABI_CONTRACT_PROVIDER, ABI_CONTRACT_ALLOCATOR,
                                  ABI_CONTRACT_EXPORT_CALLBACK})

ABI_CONTRACTS = {
    ABI_CONTRACT_PROVIDER: {
        "resolution_kind": "contract-bounded (target set unbounded)",
        "contract": "OSSL_provider_init",
        "citation": [
            "include/openssl/core.h:40-44 -- struct ossl_dispatch_st { int function_id; "
            "void (*function)(void); }, and OSSL_DISPATCH_END { 0, NULL }: an array of "
            "dispatch elements is always terminated by function_id == 0",
            "include/openssl/core.h:186-195 -- typedef int OSSL_provider_init_fn("
            "const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, "
            "const OSSL_DISPATCH **out, void **provctx); |out| is the base-function "
            "array the provider returns to the core; |provctx| is passed to the "
            "provider's other context constructors",
            "include/openssl/core_dispatch.h:30-68 -- function identities start at 1 "
            "(0 terminates the table) and each OSSL_FUNC_* extractor names the "
            "signature the core will call",
            "include/openssl/provider.h:78-85 -- OSSL_PROVIDER_add_builtin("
            "OSSL_LIB_CTX *, const char *name, OSSL_provider_init_fn *init_fn); the "
            "same entry-point type is what an externally loaded module implements",
        ],
        "provider_obligation": (
            "a provider module returns its own dispatch table and owns the "
            "correctness and lifetime of every object it allocates: its provider "
            "context, algorithm contexts, key objects, and the memory behind the "
            "OSSL_FUNC_* callbacks it publishes; the core only calls those callbacks "
            "through the returned table"),
        "covers": (
            "the interface by which an out-of-image provider is entered, the shape of "
            "the dispatch table it returns, and the provider's own allocation "
            "correctness"),
        "does_not_cover": [
            "which module (if any) the effective configuration names; the target set "
            "is unbounded",
            "the memory safety or correctness of the external provider, which is the "
            "provider's own obligation after the ABI boundary",
            "reachability from these two workloads, or that a configuration file "
            "exists at run time",
            "application code not loaded as a provider; it is not a node in this "
            "closure",
            "in-image target completeness for the built-in provider path",
        ],
    },
    ABI_CONTRACT_EXPORT_CALLBACK: {
        "resolution_kind": "contract-bounded (target set unbounded)",
        "contract": "an exported C function's callback parameter",
        "citation": [
            "the exact prototype in the admitted install's include/openssl/*.h: "
            "the parameter is declared with a function-pointer typedef, so the "
            "value is supplied by the caller and the C ABI places no bound on it",
            "the same symbol is defined in the image's .dynsym, so any process "
            "that links libcrypto may call it with any callback",
            "include/openssl/modes.h:25/69 -- typedef void (*block128_f)(const "
            "unsigned char in[16], unsigned char out[16], const void *key); and "
            "CRYPTO_cfb128_encrypt(..., int enc, block128_f block)",
            "include/openssl/types.h:237 -- typedef int pem_password_cb(char *buf, "
            "int size, int rwflag, void *userdata); pem.h:537 passes it as "
            "b2i_PVK_bio_ex(BIO *in, pem_password_cb *cb, void *u, ...)",
        ],
        "covers": (
            "the public seam through which a C caller supplies a callback to an "
            "exported function; the function name, the parameter index and the "
            "declared callback type are the documented interface"),
        "does_not_cover": [
            "the behaviour or lifetime of the application's callback, which is "
            "the application's obligation once supplied",
            "a NULL argument where the header does not admit one; that is a "
            "C-invalid input, not a target",
            "which callback (if any) an in-image caller installs; the target set "
            "is unbounded",
            "a private wrapper whose callers are all in-image and finite: the "
            "witness defers it to reachable-caller-target instead",
            "reachability from the two workloads, or that an external caller "
            "exists at run time",
        ],
    },
    ABI_CONTRACT_ALLOCATOR: {
        "resolution_kind": "contract-bounded (target set unbounded)",
        "contract": "CRYPTO_set_mem_functions",
        "citation": [
            "include/openssl/crypto.h:367-375 -- typedef void *(*CRYPTO_malloc_fn)("
            "size_t num, const char *file, int line); typedef void *(*CRYPTO_realloc_fn)("
            "void *addr, size_t num, const char *file, int line); typedef void "
            "(*CRYPTO_free_fn)(void *addr, const char *file, int line); int "
            "CRYPTO_set_mem_functions(CRYPTO_malloc_fn, CRYPTO_realloc_fn, "
            "CRYPTO_free_fn)",
            "man3/CRYPTO_set_mem_functions (OpenSSL 3.6.4) -- the replacement "
            "allocator functions must have the same semantics as the standard C "
            "library malloc(), realloc() and free(); realloc may be NULL, in which "
            "case allocation/copy/free implements it; the functions must be installed "
            "before any other OpenSSL function is called; once installed, their "
            "correctness and thread safety are the application's responsibility",
        ],
        "covers": (
            "the public seam through which an application replaces the allocator "
            "triple, and the semantics the replacement must implement (matching "
            "malloc/free, and realloc or a NULL realloc with copy semantics)"),
        "does_not_cover": [
            "that any particular triple is installed; the target set is unbounded",
            "the correctness or thread safety of a replacement allocator, which is "
            "the application's obligation once installed",
            "the NULL globals observed in this configuration: that is a runtime fact, "
            "not a link-time bound",
            "direct calls to a replacement function outside the CRYPTO_* seam, or "
            "application allocations that never enter libcrypto",
        ],
    },
}


def contract_for(cls: str) -> dict | None:
    """The ABI-contract record for a contract-bounded site class."""
    return ABI_CONTRACTS.get(cls)


# --------------------------------------------------------------------------- #
# per-call-site witnesses (AGENTS.md section 22)
# --------------------------------------------------------------------------- #
#
# A contract-bounded class is evidence about *one function-pointer slot*, not
# about a function name.  The resolver may therefore apply ABI_CONTRACT_PROVIDER
# or ABI_CONTRACT_ALLOCATOR only when a witness connects the site's own slot to
# the contract: where the slot is written, by which reachable code, and which
# documented interface fills it.  A site that matches a class's shape but has no
# witness keeps its resolver class and stays unresolved; it is never absorbed by
# the class.  Two indirect calls are not the same edge because both are indirect.

WITNESS_SCHEMA = "openssl-rs/consumer-closure/per-call-site-witness/v1"

ALLOCATOR_SEAMS = ("MALLOC_FN", "REALLOC_FN", "FREE_FN")
ALLOCATOR_SETTER = "CRYPTO_set_mem_functions"

# The provider slots for which the image and the documented provider ABI agree
# on (a) the exact object/offset the indirect call reads and (b) the in-image
# code that writes it.  A function name alone is not a witness.
PROVIDER_SLOTS = (
    {
        "function": "provider_init",
        "slot_offset": 0x40,
        "slot": "OsslProvider.init_function (offset 0x40)",
        "writer": (
            "provider_new stores the caller-supplied init_function "
            "(src/provider/mod.rs:1892, called from OSSL_PROVIDER_add_builtin); "
            "provider_init binds a loaded module's OSSL_provider_init into the "
            "same slot (src/provider/init.rs:307)"),
        "writer_symbols": ("provider_new", "provider_init"),
        "interface": (
            "OSSL_provider_init_fn -- include/openssl/core.h:186-195; "
            "OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX *, const char *, "
            "OSSL_provider_init_fn *) -- include/openssl/provider.h:78-85; "
            "a loadable module exports the same entry point as "
            "OSSL_provider_init"),
        "basis": (
            "the site's recorded field offset is exactly init_function, and "
            "the writing functions are defined in this image"),
    },
    {
        "function": "encoder_import_cb",
        "slot_offset": 0x70,
        "slot": "OsslEncoder.import_object (offset 0x70)",
        "writer": (
            "encoder_from_algorithm copies the provider's OSSL_DISPATCH entry "
            "into import_object (src/encoder_meth.rs:446), reached from the "
            "in-image fetch at src/encoder_meth.rs:754; the callback is invoked "
            "at src/encoder_pkey.rs:318"),
        "writer_symbols": ("OSSL_ENCODER_fetch", "OSSL_ENCODER_CTX_new_for_pkey"),
        "interface": (
            "the provider's returned OSSL_DISPATCH table -- OSSL_provider_init "
            "(include/openssl/core.h:186-195) and "
            "OSSL_FUNC_ENCODER_IMPORT_OBJECT "
            "(include/openssl/core_dispatch.h)"),
        "basis": (
            "the site's recorded field offset is exactly import_object, and the "
            "in-image dispatch scan that fills it is reachable"),
    },
)

# Why the common in-image slots are *not* provider-ABI slots.  Keyed by a
# function-name fragment and, where it disambiguates, the offset.
INTERNAL_SLOT_NOTES = (
    ("ossl_method_construct_this", 0x28,
     "OsslMethodConstructMethod.construct (offset 0x28) is written by "
     "inner_evp_generic_fetch at src/evp/fetch.rs:1008-1014 with the in-image "
     "construct_evp_method; that is an internal Rust interface, not "
     "OSSL_provider_init"),
    ("ossl_method_construct_reserve_store", 0x00,
     "OsslMethodConstructMethod.get_tmp_store (offset 0) is written by "
     "inner_evp_generic_fetch (src/evp/fetch.rs:1009) with an in-image callback"),
    ("cipher_generic_init_internal", 0x00,
     "ProvCipherHw.init (offset 0) is selected from in-image static hardware "
     "tables (src/provider/cipher.rs, e.g. AES_XTS_HW); a third-party provider "
     "cannot supply this internal struct through OSSL_provider_init"),
    ("alg_cleanup", 0x20,
     "Method.free (offset 0x20) is the class destructor stored by "
     "ossl_method_store_add (src/property/store.rs:692); the class is in this crate"),
    ("impl_free_thunk", 0x20,
     "Method.free (offset 0x20), the in-image class destructor"),
    ("impl_cache_free_thunk", 0x20,
     "Method.free (offset 0x20), the in-image class destructor"),
    ("ossl_method_store_add", 0x20,
     "Method.free (offset 0x20), the caller-supplied class destructor"),
    ("impl_cache_flush_cache", 0x20,
     "Method.free (offset 0x20), the caller-supplied class destructor"),
    ("alg_cleanup_by_provider", 0x20,
     "Method.free (offset 0x20), the caller-supplied class destructor"),
    ("ossl_method_store_fetch", 0x18,
     "Method.up_ref (offset 0x18), the in-image class reference callback"),
    ("ossl_method_store_fetch", 0x20,
     "Method.free (offset 0x20), the in-image class destructor"),
    ("ossl_method_store_cache_get", 0x18,
     "Method.up_ref (offset 0x18), the in-image class reference callback"),
    ("ossl_method_store_cache_set", 0x20,
     "Method.free (offset 0x20), the in-image class destructor"),
    ("construct_evp_method", 0x30,
     "EvpMethodData.method_from_algorithm (offset 0x30) is the caller-supplied "
     "class constructor, an in-image Rust callback"),
    ("destruct_evp_method", 0x40,
     "EvpMethodData.destruct_method (offset 0x40) is the caller-supplied class "
     "destructor, an in-image Rust callback"),
    ("inner_evp_generic_fetch", None,
     "the class destructor argument free_method held in this frame; supplied by "
     "the EVP class wrapper, not by a provider"),
    # The compiler's AlgorithmData layout in this candidate puts reserve_store
    # at 0, fn_ at 8 and unreserve_store at 0x10 (not the source declaration
    # order; the struct is not repr(C)).
    ("algorithm_do_this", 0x00,
     "AlgorithmData.reserve_store (offset 0), an in-image walk callback"),
    ("algorithm_do_this", 0x08,
     "AlgorithmData.fn_ (offset 0x08), an in-image walk callback"),
    ("algorithm_do_this", 0x10,
     "AlgorithmData.unreserve_store (offset 0x10), an in-image walk callback"),
    ("ossl_provider_doall_activated", None,
     "the cb argument; OSSL_PROVIDER_do_all (exported) forwards an "
     "application-supplied callback, so no whole-function in-image target bound "
     "exists unless every caller reachable in this family contributes an "
     "in-image constant (reachable-caller target bounding)"),
)


# --------------------------------------------------------------------------- #
# In-image slot targets (target resolution, not a contract class)
# --------------------------------------------------------------------------- #
#
# The sites below are not provider-ABI edges.  Each reads a function-pointer
# slot whose writer is in this exact image, and the writer is reachable:
#   * an in-image initialiser (construct_evp_method, get_tmp_evp_method_store,
#     the walk callbacks) stored before the walk; or
#   * an in-image class callback stored by ossl_method_store_add / cache_set,
#     every one of whose reachable callers passes a link-time constant; or
#   * a static ProvCipherHw initialiser read from .data.rel.ro.
# A target set is claimed only when every named target resolves to a function
# start in this image and, for a function writer, the writer is reachable in
# the pre-closure.  This is *not* an ABI contract: it does not enter
# ABI_CONTRACT_CLASSES and cannot satisfy element 7's contract branch.

EVP_CLASS_FROM_TARGETS = (
    "evp_md_from_algorithm",
    "evp_cipher_from_algorithm",
    "evp_kdf_from_algorithm",
    "keymgmt_from_algorithm",       # also matches skeymgmt_from_algorithm
    "evp_signature_from_algorithm",
    "evp_asym_cipher_from_algorithm",
    "evp_mac_from_algorithm",
    "evp_rand_from_algorithm",
    "evp_keyexch_from_algorithm",
    "evp_kem_from_algorithm",
)

EVP_CLASS_UP_REF_TARGETS = (
    "EVP_MD_up_ref",
    "EVP_CIPHER_up_ref",
    "EVP_KDF_up_ref",
    "EVP_KEYMGMT_up_ref",
    "EVP_SIGNATURE_up_ref",
    "EVP_ASYM_CIPHER_up_ref",
    "EVP_MAC_up_ref",
    "EVP_SKEYMGMT_up_ref",
    "EVP_RAND_up_ref",
    "EVP_KEYEXCH_up_ref",
    "EVP_KEM_up_ref",
)

EVP_CLASS_FREE_TARGETS = (
    "EVP_MD_free",
    "EVP_CIPHER_free",
    "EVP_KDF_free",
    "EVP_KEYMGMT_free",
    "EVP_SIGNATURE_free",
    "EVP_ASYM_CIPHER_free",
    "EVP_MAC_free",
    "EVP_SKEYMGMT_free",
    "EVP_RAND_free",
    "EVP_KEYEXCH_free",
    "EVP_KEM_free",
)

# The method store also holds loaders, decoders and encoders; their add/cache
# callers pass these in-image callbacks to the same METHOD.free/up_ref slots.
METHOD_FREE_TARGETS = EVP_CLASS_FREE_TARGETS + (
    "OSSL_STORE_LOADER_free",
    "free_decoder",
    "OSSL_ENCODER_free",
)
METHOD_UP_REF_TARGETS = EVP_CLASS_UP_REF_TARGETS + (
    "OSSL_STORE_LOADER_up_ref",
    "OSSL_DECODER_up_ref",       # ICF: OSSL_ENCODER_up_ref is the same address
)

CIPHER_HW_INIT_TARGETS = (
    "cipher_hw_aes_initkey",
    "cipher_hw_sm4_initkey",
    "cipher_hw_aria_initkey",
    "cipher_hw_camellia_initkey",
    "cipher_hw_tdes_ede2_initkey",
    "cipher_hw_tdes_ede3_initkey",
    "cipher_hw_aes_xts_generic_initkey",
    "cipher_hw_sm4_xts_generic_initkey",
    "cipher_hw_aes_ocb_generic_initkey",
    "chacha20_initkey",
    "chacha20_poly1305_initkey",
    "aesni_cbc_hmac_sha1_init_key",
    "aesni_cbc_hmac_sha256_init_key",
)

EDGE_TARGET_WITNESS_SCHEMA = (
    "openssl-rs/consumer-closure/in-image-slot-target/v1")

# Reachable-caller target bounding is a *narrowing of an unbounded target set*,
# not an ABI contract.  It is deliberately absent from ABI_CONTRACT_CLASSES and
# never attaches a WITNESS_SCHEMA record: the site becomes target-resolved.
# v2 (round 4) records the per-call-site attribution of *every* caller row,
# reachable or excluded, with the same argument interpreter that produced the
# site's flat `arg_targets`.  The v1 fields are retained for compatibility.
REACHABLE_CALLER_SCHEMA = (
    "openssl-rs/consumer-closure/reachable-caller-target-bound/v2")

# Round-4 soundness direction.  Admitting a target is always safe for the upper
# bound; excluding one requires (i) the caller/writer is absent from the
# final-upper-bound oracle and (ii) the target is demonstrably produced by that
# subject.  Per-caller attribution is analyzer-produced from the same argument
# summary the flat site target set came from; record-level validation checks a
# record against itself and the oracle, not against a re-derivation.
UNATTRIBUTED_ADMISSION_REASON = (
    "the candidate target is not attributed to any caller row (neither a "
    "reachable caller nor an excluded caller); it is admitted, never dropped")
ATTRIBUTION_INCOMPLETE_PROPERTY = (
    "caller attribution incomplete: {n} candidate target(s) have no "
    "attributable caller")

EDGE_TARGET_SLOTS = (
    {
        "id": "EVT-MCM-CONSTRUCT",
        "function": ("ossl_method_construct_this",),
        "slot_offset": 0x28,
        "slot": "OsslMethodConstructMethod.construct (offset 0x28)",
        "targets": ("construct_evp_method",),
        "writer_symbols": ("inner_evp_generic_fetch",),
        "writer": ("0x51b27b lea construct_evp_method; 0x51b282 mov %rax,0x88(%rsp) "
                   "fills the frame's OsslMethodConstructMethod.construct slot "
                   "(src/evp/fetch.rs:1014, reached from inner_evp_generic_fetch)"),
        "source": "src/evp/fetch.rs:1014",
    },
    {
        "id": "EVT-MCM-GET-TMP",
        "function": ("ossl_method_construct_reserve_store",),
        "slot_offset": 0x00,
        "slot": "OsslMethodConstructMethod.get_tmp_store (offset 0x00)",
        "targets": ("get_tmp_evp_method_store",),
        "writer_symbols": ("inner_evp_generic_fetch",),
        "writer": ("0x51b23c lea get_tmp_evp_method_store; 0x51b243 mov %rax,0x60(%rsp) "
                   "fills the get_tmp_store slot (src/evp/fetch.rs:1009)"),
        "source": "src/evp/fetch.rs:1009",
    },
    {
        "id": "EVT-ALG-RESERVE",
        "function": ("algorithm_do_this",),
        "slot_offset": 0x00,
        "slot": "AlgorithmData.reserve_store (offset 0x00)",
        "targets": ("ossl_method_construct_reserve_store",),
        "writer_symbols": ("ossl_algorithm_do_all",),
        "writer": ("ossl_algorithm_do_all stores its reserve_store argument at "
                   "0x51de31; the only reachable supplier is inner_evp_generic_fetch "
                   "lea 0x23b4f0 at 0x51b32f (src/evp/method_store.rs:440)"),
        "source": "src/evp/method_store.rs:440",
    },
    {
        "id": "EVT-ALG-FN",
        "function": ("algorithm_do_this",),
        "slot_offset": 0x08,
        "slot": "AlgorithmData.fn_ (offset 0x08)",
        "targets": ("ossl_method_construct_this",),
        "writer_symbols": ("ossl_algorithm_do_all",),
        "writer": ("ossl_algorithm_do_all stores its fn argument at 0x51de35; "
                   "inner_evp_generic_fetch materialises it with lea 0x23b2c0 at "
                   "0x51b336 (src/evp/method_store.rs:440)"),
        "source": "src/evp/method_store.rs:440",
    },
    {
        "id": "EVT-ALG-UNRESERVE",
        "function": ("algorithm_do_this",),
        "slot_offset": 0x10,
        "slot": "AlgorithmData.unreserve_store (offset 0x10)",
        "targets": ("ossl_method_construct_unreserve_store",),
        "writer_symbols": ("ossl_algorithm_do_all",),
        "writer": ("ossl_algorithm_do_all stores its unreserve argument at "
                   "0x51de3f; inner_evp_generic_fetch materialises it with lea "
                   "0x23b540 at 0x51b31d (src/evp/method_store.rs:440)"),
        "source": "src/evp/method_store.rs:440",
    },
    {
        "id": "EVT-EVPM-FROM",
        "function": ("construct_evp_method",),
        "slot_offset": 0x30,
        "slot": "EvpMethodData.method_from_algorithm (offset 0x30)",
        "targets": EVP_CLASS_FROM_TARGETS,
        "writer_symbols": ("inner_evp_generic_fetch",),
        "writer": ("0x51b2b6 mov %rax,0x30(%rbp) stores the new_method argument; "
                   "every in-image caller materialises it with lea (e.g. 0x17a60b "
                   "evp_md_from_algorithm, 0x1ac675 evp_kem_from_algorithm); "
                   "src/evp/fetch.rs:1024"),
        "source": "src/evp/fetch.rs:1024",
    },
    {
        "id": "EVT-EVPM-DESTRUCT",
        "function": ("destruct_evp_method",),
        "slot_offset": 0x40,
        "slot": "EvpMethodData.destruct_method (offset 0x40)",
        "targets": EVP_CLASS_FREE_TARGETS,
        "writer_symbols": ("inner_evp_generic_fetch",),
        "writer": ("0x51b2be mov %rsi,0x40(%rbp) stores the free_method argument "
                   "(0x4d8(%rsp)); every in-image caller passes an in-image class "
                   "destructor (src/evp/fetch.rs:1026)"),
        "source": "src/evp/fetch.rs:1026",
    },
    {
        "id": "EVT-INNER-FREE-METHOD",
        "function": ("inner_evp_generic_fetch",),
        "slot_offset": None,
        "slot": "the free_method register/stack argument",
        "targets": EVP_CLASS_FREE_TARGETS,
        "writer_symbols": ("inner_evp_generic_fetch",),
        "writer": ("0x51b480 call *0x4d8(%rsp); every in-image direct caller pushes "
                   "an in-image class destructor at the call site (e.g. "
                   "0x17a4b9 push EVP_CIPHER_free, 0x1ac6a7 push EVP_KEM_free)"),
        "source": "src/evp/fetch.rs:1064",
    },
    {
        "id": "EVT-METHOD-FREE",
        "function": ("alg_cleanup", "impl_free_thunk", "impl_cache_free_thunk",
                     "ossl_method_store_add", "impl_cache_flush_cache",
                     "alg_cleanup_by_provider", "ossl_method_store_fetch",
                     "ossl_method_store_cache_set"),
        "slot_offset": 0x20,
        "slot": "Method.free (offset 0x20)",
        # The declared names are a cross-check only.  The target set is derived
        # from the values reachable code stores into the slot; an absent name
        # can never void the spec.
        "semantic_rule": "stored-value-provenance",
        "declared_targets": METHOD_FREE_TARGETS,
        "writer_symbols": ("ossl_method_store_add", "ossl_method_store_cache_set"),
        "writer": ("ossl_method_store_add stores method_destruct at 0x20 of the "
                   "Implementation; ossl_method_store_cache_set stores it at 0x20 "
                   "of the cache entry.  The stored values are derived from the "
                   "reachable call sites, not from a name list "
                   "(src/property/store.rs:692)"),
        "source": "src/property/store.rs:692",
    },
    {
        "id": "EVT-METHOD-UP-REF",
        "function": ("alg_cleanup", "impl_free_thunk", "impl_cache_free_thunk",
                     "ossl_method_store_add", "impl_cache_flush_cache",
                     "alg_cleanup_by_provider", "ossl_method_store_fetch",
                     "ossl_method_store_cache_get", "ossl_method_store_cache_set"),
        "slot_offset": 0x18,
        "slot": "Method.up_ref (offset 0x18)",
        "targets": METHOD_UP_REF_TARGETS,
        "writer_symbols": ("ossl_method_store_add", "ossl_method_store_cache_set"),
        "writer": ("ossl_method_store_add stores method_up_ref at 0x327d60 "
                   "(mov %rbp,0x18(%r15)); ossl_method_store_cache_set stores it at "
                   "0x329315.  Reachable callers pass in-image constants: the EVP "
                   "class up_ref functions, OSSL_STORE_LOADER_up_ref and "
                   "OSSL_DECODER_up_ref (src/property/store.rs:691)"),
        "source": "src/property/store.rs:691",
    },
    {
        "id": "EVT-METHOD-UP-REF-REG",
        "function": ("ossl_method_store_cache_set",),
        "slot_offset": None,
        "slot": "the up_ref register value in ossl_method_store_cache_set",
        "targets": METHOD_UP_REF_TARGETS,
        "writer_symbols": ("ossl_method_store_add", "ossl_method_store_cache_set"),
        "writer": ("0x329310 mov 0x40(%rsp),%rcx; 0x329315 mov %rcx,0x18(%r13); "
                   "0x329320 call *%rcx, so this register site is the same "
                   "method_up_ref argument as Method.up_ref"),
        "source": "src/property/store.rs:691",
    },
    {
        "id": "EVT-CIPHER-HW-INIT",
        "function": ("cipher_generic_init_internal",),
        "slot_offset": 0x00,
        "slot": "ProvCipherHw.init (offset 0x00)",
        "targets": CIPHER_HW_INIT_TARGETS,
        "writer_kind": "static-initialiser",
        "table_symbols": ("_HW", "HW_"),
        "writer": ("the loader writes each ProvCipherHw.init from the table's "
                   ".data.rel.ro initialiser (AES_XTS_HW 0x8076d0, "
                   "CHACHA20_HW 0x807850, CIPHER_HW_AES_HMAC_SHA1 0x80f560, ...); "
                   "each target below is the first qword of an in-image table"),
        "source": "src/provider/cipher.rs:3457-3463,5104,5695,6319,15403, ...",
    },
)


def _fragment_addrs(g: "DsoGraph", fragments) -> set | None:
    """All in-image function starts whose any name contains each fragment.

    Returns None when a fragment matches no defined function: the declared
    target set is then incomplete for this image and must not be claimed.
    """
    if isinstance(fragments, str):
        fragments = (fragments,)
    names_at = getattr(g, "names_at", None)
    out = set()
    for frag in fragments:
        hit = set()
        if names_at:
            for a, names in names_at.items():
                if a in g.start_set and any(frag in (n or "") for n in names):
                    hit.add(a)
        else:
            hit = {a for a, n in g.all_syms.items()
                   if frag in (n or "") and a in g.start_set}
        if not hit:
            return None
        out |= hit
    return out


def _static_initialiser_covers(g: "DsoGraph", targets: set, fragments) -> bool:
    """True when every target is the first qword of an in-image data table."""
    names_at = getattr(g, "names_at", {})
    found = set()
    for a, names in names_at.items():
        if not any(f in (n or "") for f in fragments for n in names):
            continue
        sec = g.section_of(a)
        if sec in (None, ".text", ".plt", ".bss"):
            continue
        v = g.static_slot(a)
        if not v:
            continue
        found |= {x for x in v if isinstance(x, int) and x in g.start_set}
    return bool(targets) and targets <= found


SEMANTIC_STORE_SCHEMA = (
    "openssl-rs/consumer-closure/stored-value-slot-target/v1")
MAX_PROVENANCE_DEPTH = 8
MAX_PROVENANCE_SITES = 512


def _insn_parts(text: str):
    body = text.split("#", 1)[0].strip()
    toks = body.split(None, 1)
    mn = toks[0] if toks else ""
    rest = toks[1].strip() if len(toks) > 1 else ""
    return mn, rest, _split_ops(rest)


def _insn_comment_addr(text: str):
    if "#" not in text:
        return None
    c = text.split("#", 1)[1].strip()
    m = re.match(r"^([0-9a-f]+)", c)
    return int(m.group(1), 16) if m else None


def _name_addrs(g: "DsoGraph", fragment: str) -> set:
    """In-image function starts whose any name contains ``fragment``.

    Unlike ``_fragment_addrs`` this never voids a spec: an absent name is an
    empty set plus a ``declared_but_absent`` row for the cross-check.
    """
    names_at = getattr(g, "names_at", None)
    if names_at:
        return {a for a, names in names_at.items()
                if a in g.start_set
                and any(fragment in (n or "") for n in names)}
    return {a for a, n in g.all_syms.items()
            if fragment in (n or "") and a in g.start_set}


def _semantic_frame_base(g: "DsoGraph", fstart: int):
    cache = getattr(g, "_semantic_frame_base", None)
    if cache is None:
        cache = {}
        g._semantic_frame_base = cache
    if fstart in cache:
        return cache[fstart]
    base = None
    for idx, (_a, text) in enumerate(g.precision.insns_by_func.get(fstart, ())):
        mn, _rest, ops = _insn_parts(text)
        if mn == "mov" and len(ops) == 2 and ops[0] == "%rsp" and ops[1] == "%rbp":
            base = (idx, _semantic_rsp_deltas(g, fstart)[idx])
            break
    cache[fstart] = base
    return base


def _semantic_rsp_deltas(g: "DsoGraph", fstart: int):
    """Entry-relative rsp delta at every instruction, from a CFG fixpoint.

    A linear scan is wrong across epilogues: the addq that restores the frame
    on an error path would otherwise reset the delta for a later block.
    """
    cache = getattr(g, "_semantic_deltas", None)
    if cache is None:
        cache = {}
        g._semantic_deltas = cache
    if fstart in cache:
        return cache[fstart]
    insns = g.precision.insns_by_func.get(fstart, ())
    n = len(insns)
    out = [None] * n
    idx_of = {a: i for i, (a, _t) in enumerate(insns)}
    leaders = {0}
    for i, (_a, text) in enumerate(insns):
        mn, _rest, _ops = _insn_parts(text)
        m = re.match(r"^j\w+\s+([0-9a-f]+)", text)
        if m and int(m.group(1), 16) in idx_of:
            leaders.add(idx_of[int(m.group(1), 16)])
        if m or mn.startswith(("jmp", "ret")):
            if i + 1 < n:
                leaders.add(i + 1)
    leaders = sorted(leaders)
    blocks, block_of = [], {}
    for bi, lo in enumerate(leaders):
        hi = leaders[bi + 1] if bi + 1 < len(leaders) else n
        blocks.append((lo, hi))
        for i in range(lo, hi):
            block_of[i] = bi
    succ = {}
    for bi, (_lo, hi) in enumerate(blocks):
        mn, _rest, _ops = _insn_parts(insns[hi - 1][1])
        m = re.match(r"^j\w+\s+([0-9a-f]+)", insns[hi - 1][1])
        s = []
        if m and int(m.group(1), 16) in idx_of:
            s.append(block_of[idx_of[int(m.group(1), 16)]])
            if not mn.startswith("jmp") and hi < n:
                s.append(bi + 1)
        elif mn.startswith(("ret", "jmp")):
            s = []
        elif hi < n:
            s = [bi + 1]
        succ[bi] = s
    entry = {0: 0}
    work = [0]
    while work:
        bi = work.pop()
        cur = entry[bi]
        lo, hi = blocks[bi]
        for i in range(lo, hi):
            out[i] = cur
            if cur is None:
                continue
            mn, _rest, ops = _insn_parts(insns[i][1])
            if mn == "push":
                cur -= 8
            elif mn == "pop":
                cur += 8
            elif (mn in ("sub", "add") and len(ops) == 2
                  and ops[1] == "%rsp" and ops[0].startswith("$")):
                off = int(ops[0][1:], 16)
                cur = cur - off if mn == "sub" else cur + off
        for s in succ[bi]:
            if s not in entry:
                entry[s] = cur
                work.append(s)
            elif entry[s] != cur:
                entry[s] = None
                work.append(s)
    cache[fstart] = out
    return out


def _semantic_last_write(g: "DsoGraph", fstart: int, idx: int, reg: str):
    """Reaching write to ``reg`` before ``idx`` within the same function."""
    insns = g.precision.insns_by_func.get(fstart, ())
    r = _canon(reg)
    for k in range(idx - 1, -1, -1):
        mn, _rest, ops = _insn_parts(insns[k][1])
        if mn.startswith("call"):
            if r in _CALLER_SAVED:
                return ("call", k, ops)
            continue
        if not ops or mn.startswith(("cmp", "test", "j", "nop", "ret", "push",
                                     "call", "ud2")):
            continue
        dst = _canon(ops[-1]) if ops[-1] in _SUBREG else ops[-1]
        if dst == r:
            return ("insn", k, ops)
    return ("entry", None, None)


_ENTRY_ARG_REGS = {"%rdi": 0, "%rsi": 1, "%rdx": 2, "%rcx": 3, "%r8": 4,
                   "%r9": 5}


def _semantic_slot(g: "DsoGraph", slot: int) -> dict:
    if slot in g.slot_syms:
        rows = []
        for raw in sorted(g.slot_syms[slot]):
            base = raw.split("@")[0]
            target = g.dynamic_defs.get(base)
            rows.append({"symbol": base, "target": target,
                         "image_bounded": target is not None})
        return {"kind": "relocation", "slot": slot, "symbols": rows}
    vals = g.slot_funcs.get(slot) or g.slot_data.get(slot)
    if vals:
        return {"kind": "static-slot", "slot": slot, "values": sorted(vals)}
    return {"kind": "unknown", "slot": slot,
            "why": "no relocation or static value at this slot"}


def _semantic_classify(g: "DsoGraph", fstart: int, idx: int, opnd: str,
                       depth: int = 0, witness=(), address_of=False) -> dict:
    """Provenance of one operand at instruction ``idx``."""
    insns = g.precision.insns_by_func.get(fstart, ())
    deltas = _semantic_rsp_deltas(g, fstart)
    opnd = opnd.strip()
    w = list(witness)
    if opnd.startswith("$"):
        try:
            return {"kind": "int", "value": int(opnd[1:], 16), "witness": w}
        except ValueError:
            return {"kind": "unknown", "why": "bad immediate", "witness": w}
    if re.fullmatch(r"-?0x[0-9a-f]+\(%rip\)", opnd):
        slot = _insn_comment_addr(insns[idx][1])
        if slot is None:
            return {"kind": "unknown", "why": "rip operand without address",
                    "witness": w}
        if address_of:
            return {"kind": "int", "value": slot, "witness": w}
        out = _semantic_slot(g, slot)
        out["witness"] = w
        return out
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", opnd)
    if m:
        off = int(m.group(1), 16) if m.group(1) else 0
        if m.group(2) == "%rsp":
            abs_off = None if deltas[idx] is None else deltas[idx] + off
        else:
            frame = _semantic_frame_base(g, fstart)
            abs_off = None if frame is None else frame[1] + off
            if frame is None:
                return _semantic_field_of_reg(g, fstart, idx, "%rbp", off,
                                              depth, w)
        if abs_off is None:
            return {"kind": "unknown", "why": "stack offset after rsp change",
                    "witness": w}
        if abs_off >= 8 and (abs_off - 8) % 8 == 0:
            return {"kind": "param", "index": 6 + (abs_off - 8) // 8,
                    "stack_offset": abs_off, "witness": w}
        return {"kind": "unknown", "why": f"stack local at {abs_off:#x}",
                "witness": w}
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
    if m:
        off = int(m.group(1), 16) if m.group(1) else 0
        return _semantic_field_of_reg(g, fstart, idx, m.group(2), off, depth, w)
    if opnd in _REGS or opnd in _SUBREG:
        r = _canon(opnd)
        kind, k, ops = _semantic_last_write(g, fstart, idx, r)
        if kind == "entry":
            if r in _ENTRY_ARG_REGS:
                return {"kind": "param", "index": _ENTRY_ARG_REGS[r],
                        "witness": w}
            return {"kind": "unknown", "why": f"entry value in {r}",
                    "witness": w}
        if kind == "call":
            return {"kind": "unknown", "why": f"{r} is a call result",
                    "witness": w}
        if depth >= MAX_PROVENANCE_DEPTH:
            return {"kind": "unknown", "why": "provenance depth bound",
                    "witness": w}
        mn_k, _rest_k, ops_k = _insn_parts(insns[k][1])
        src = ops_k[0] if len(ops_k) >= 2 else ""
        if mn_k in ("xor", "sub") and len(ops_k) == 2 and ops_k[0] == ops_k[1]:
            return {"kind": "int", "value": 0,
                    "witness": w + [insns[k][1]]}
        return _semantic_classify(g, fstart, k, src, depth + 1,
                                  w + [insns[k][1]],
                                  address_of=(mn_k == "lea"))
    return {"kind": "unknown", "why": "unsupported operand " + opnd,
            "witness": w}


def _semantic_field_of_reg(g: "DsoGraph", fstart: int, idx: int, reg: str,
                           off: int, depth: int, witness) -> dict:
    base = _semantic_classify(g, fstart, idx, reg, depth + 1, witness)
    if base.get("kind") == "param":
        return {"kind": "field", "offset": off,
                "base_param": base["index"], "witness": base.get("witness", [])}
    if base.get("kind") == "int" and base.get("value"):
        addr = base["value"]
        if g.section_of(addr) is not None:
            vals = g.static_slot(addr + off)
            if vals:
                ints = sorted(x for x in vals if isinstance(x, int))
                return {"kind": "table", "base": addr, "offset": off,
                        "values": ints, "witness": list(witness)}
    return {"kind": "unknown",
            "why": f"base of {off:#x} is neither a parameter nor a data pointer",
            "witness": list(witness)}


def _semantic_writer_sources(g: "DsoGraph", writer: int, offset: int) -> list:
    """Every store to ``offset`` in this writer, with its source provenance."""
    insns = g.precision.insns_by_func.get(writer, ())
    out = []
    for idx, (addr, text) in enumerate(insns):
        mn, _rest, ops = _insn_parts(text)
        if not mn.startswith("mov") or len(ops) != 2:
            continue
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", ops[1])
        if not m:
            continue
        doff = int(m.group(1), 16) if m.group(1) else 0
        if doff != offset:
            continue
        base = m.group(2)
        if base == "%rsp":
            out.append({"store": hex(addr), "instruction": text,
                        "base": base, "argument_index": None,
                        "reason": "frame-local object, not the method-store entry"})
            continue
        desc = _semantic_classify(g, writer, idx, ops[0], 0, (text,))
        out.append({"store": hex(addr), "instruction": text, "base": base,
                    "argument_index": (desc.get("index")
                                       if desc.get("kind") == "param" else None),
                    "descriptor": desc})
    return out


def _drop_s1_caches(g: "DsoGraph", *, all_caches: bool = True) -> None:
    attrs = ["_s1_docs_cache", "_s1_module_index", "_s1_dispatch_cache"]
    if all_caches:
        attrs += ["_s1_struct_cache", "_s1_layout_cache", "_s1_alias_cache",
                  "_s1_fn_cache", "_s1_ctx_cache", "_s1_demangle_cache",
                  "_s1_instance_cache", "_s1_sym_index",
                  "_s1_macro_static_cache"]
    for attr in attrs:
        if hasattr(g, attr):
            setattr(g, attr,
                    None if attr in ("_s1_docs_cache", "_s1_module_index",
                                     "_s1_dispatch_cache") else {})


def _semantic_provenance_resolver(g: "DsoGraph") -> "PrecisionResolver":
    r = getattr(g, "_semantic_precision", None)
    if r is None:
        # The semantic pass is the largest single allocation in this phase.
        # Release every S1 cache first; a later S1 site simply reloads them.
        _drop_s1_caches(g, all_caches=True)
        r = PrecisionResolver(g)
        r.seed_entry_args = True
        r.capture_stack_args = True
        r.record_stores = False
        r.run(passes=1)
        g._semantic_precision = r
    return r


def _semantic_call_index(g: "DsoGraph") -> dict:
    idx = getattr(g, "_semantic_call_index", None)
    if idx is not None:
        return idx
    # The S1 source corpus and its indexes are the largest retained state at
    # this point.  They are rebuilt lazily for a later S1 site, so release them
    # before the call index, which is built while the semantic resolver is live.
    _drop_s1_caches(g, all_caches=True)
    r = _semantic_provenance_resolver(g)
    # The index reads only ``calls`` and ``call_stack_args``.  Release the
    # interpreter's frames, store summaries and instruction maps before the
    # index is built instead of after, so peak memory is the larger of the two
    # rather than their sum.
    r.sites = {}
    r.store_slots.clear()
    r.field_stores.clear()
    r.field_open.clear()
    r.summary.clear()
    r.summary_open.clear()
    r.returns.clear()
    r.insns_by_func = {}
    idx = {}
    try:
        for position, (caller, callee, args, addr) in enumerate(r.calls):
            # Drop the consumed tuple: the call log is the largest single
            # allocation at this point and the index grows as it shrinks.
            r.calls[position] = None
            if callee is None:
                continue
            row = idx.setdefault(callee, {})
            key = (caller, addr)
            cur = row.get(key)
            stack = r.call_stack_args.get(key, ())
            if cur is None:
                row[key] = {"caller": caller, "call_site": addr,
                            "args": list(args), "stack": list(stack),
                            "open": [bool(a is None or a.is_top()) for a in args]}
            else:
                for k, a in enumerate(args):
                    if a is None or a.is_top():
                        continue
                    if k < len(cur["args"]):
                        prev = cur["args"][k]
                        cur["args"][k] = a if prev is None or prev.is_top() \
                            else prev.union(a)
                cur["open"] = [bool(a is None or a.is_top()) for a in args]
                if len(stack) > len(cur["stack"]):
                    cur["stack"] = list(stack)
    finally:
        # The index is the only state the rule needs.  Retaining the whole
        # provenance interpreter (call log, sites, summaries) alongside the
        # main resolver doubles peak memory for no benefit; the court container
        # has a hard 8 GiB limit.
        g._semantic_call_index = idx
        g._semantic_precision = None
        r.calls = []
        r.call_stack_args = {}
        r.sites = {}
        r.store_slots.clear()
        r.field_stores.clear()
        r.field_open.clear()
        r.summary.clear()
        r.summary_open.clear()
        r.returns.clear()
        r.insns_by_func = {}
    return idx


def _semantic_value(g: "DsoGraph", site: dict, index: int):
    if index < 6:
        if site.get("open", [False] * 6)[index]:
            return PValue()
        return site["args"][index]
    k = index - 6
    stack = site.get("stack") or ()
    return _as_value(stack[k]) if k < len(stack) else PValue()


def _semantic_atom_rows(g: "DsoGraph", value: PValue) -> list:
    if value is None or value.is_top():
        return [{"kind": "unknown", "why": "unknown call argument"}]
    rows = []
    for atom in value.s:
        if isinstance(atom, int):
            rows.append({"kind": "int", "value": atom})
        elif isinstance(atom, tuple) and atom[0] == "sym":
            base = atom[1].split("@")[0]
            target = g.dynamic_defs.get(base)
            slots = sorted(s for s, names in g.slot_syms.items()
                           if any(n.split("@")[0] == base for n in names))
            rows.append({"kind": "relocation", "symbol": base,
                         "slot": slots[0] if slots else None,
                         "symbols": [{"symbol": base, "target": target,
                                       "image_bounded": target is not None}]})
        elif isinstance(atom, tuple) and atom[0] == "field":
            rows.append({"kind": "field", "offset": atom[1]})
        elif isinstance(atom, tuple) and atom[0] == "arg":
            rows.append({"kind": "param", "index": atom[1]})
        else:
            rows.append({"kind": "unknown", "why": f"atom {atom!r}"})
    return rows


def _semantic_canonical_target(g: "DsoGraph", addr: int):
    """Collapse a one-line thunk to its callee (a thunk is not a target)."""
    chain = []
    cur = addr
    seen = set()
    for _ in range(4):
        if cur in seen or cur not in g.start_set:
            break
        seen.add(cur)
        insns = g.precision.insns_by_func.get(cur, ())
        body = [(a, t) for a, t in insns
                if not _insn_parts(t)[0].startswith(("endbr64", "nop", "cs",
                                                     "data16"))]
        if len(body) != 1:
            break
        mn, rest, _ops = _insn_parts(body[0][1])
        if not mn.startswith("jmp"):
            break
        nxt = None
        m = re.match(r"\*0x[0-9a-f]+\(%rip\)", rest)
        if m:
            slot = _insn_comment_addr(body[0][1])
            vals = set()
            if slot is not None:
                vals |= set(g.slot_funcs.get(slot, ()))
                if not vals:
                    sv = g.static_slot(slot) or ()
                    vals |= {x for x in sv if isinstance(x, int)}
            vals = {v for v in vals if v in g.start_set}
            if len(vals) == 1:
                nxt = next(iter(vals))
        else:
            m = re.match(r"([0-9a-f]+)\s*<", rest)
            if m:
                target = int(m.group(1), 16)
                nxt = target if target in g.start_set else g.containing(target)
        if nxt is None or nxt == cur:
            break
        chain.append({"from": hex(cur), "to": hex(nxt),
                      "instruction": body[0][1]})
        cur = nxt
    return cur, chain


def _semantic_param_targets(g: "DsoGraph", func: int, index: int, reachable: set,
                            depth: int, seen: set, chain: list):
    key = (func, index)
    if key in seen:
        return set(), f"recursive parameter provenance at {func:#x} arg {index}", chain
    if depth <= 0:
        return set(), "provenance depth bound", chain
    if func in set(g.dynamic_defs.values()):
        return set(), (f"parameter of dynamic export {func:#x} cannot be bounded "
                       "outside the image"), chain
    sites = _semantic_call_index(g).get(func) or {}
    reachable_sites = [sites[k] for k in sorted(sites) if sites[k]["caller"] in reachable]
    excluded = [sites[k] for k in sorted(sites) if sites[k]["caller"] not in reachable]
    for row in excluded:
        chain.append({"excluded_caller": g.funcs.get(row["caller"], "?"),
                      "call_site": hex(row["call_site"]),
                      "reason": "caller not in the family's reachable set"})
    if not reachable_sites:
        return set(), f"no reachable in-image caller of {func:#x}", chain
    if len(reachable_sites) > MAX_PROVENANCE_SITES:
        return set(), f"too many call sites for {func:#x}", chain
    targets = set()
    for site in reachable_sites:
        value = _semantic_value(g, site, index)
        for atom in _semantic_atom_rows(g, value):
            atom["func"] = site["caller"]
            got, why, sub = _semantic_resolve(g, atom, reachable, depth - 1,
                                              seen | {key}, [])
            row = {"caller": g.funcs.get(site["caller"], "?"),
                   "call_site": hex(site["call_site"]),
                   "argument_index": index, "value": atom,
                   "targets": [hex(t) for t in sorted(got)],
                   "failure": why, "chain": sub}
            chain.append(row)
            if why:
                return set(), f"{why} (at {row['caller']} {row['call_site']})", chain
            targets |= got
    return targets, None, chain


def _semantic_field_targets(g: "DsoGraph", off: int, reachable: set, depth: int,
                            seen: set, chain: list):
    """Follow one level: the object's field is filled by a known slot writer."""
    if depth <= 0:
        return set(), "provenance depth bound", chain
    results = []
    for spec in EDGE_TARGET_SLOTS:
        if spec.get("slot_offset") != off or spec.get("semantic_rule"):
            continue
        if spec["id"] == "EVT-METHOD-FREE":
            continue
        writers = set()
        for frag in spec.get("writer_symbols", ()):
            writers |= _name_addrs(g, frag)
        live = sorted(writers & reachable)
        if not live:
            continue
        index = None
        rows = []
        for writer in live:
            sources = _semantic_writer_sources(g, writer, off)
            indices = sorted({r["argument_index"] for r in sources
                              if r.get("argument_index") is not None})
            rows.append({"writer": g.funcs.get(writer, "?"), "sources": sources,
                         "argument_indices": indices})
            if len(indices) != 1 or (index is not None and indices[0] != index):
                index = None
                break
            index = indices[0]
        if index is None:
            continue
        targets = set()
        subchain = []
        failure = None
        for writer in live:
            got, why, sub = _semantic_param_targets(g, writer, index, reachable,
                                                    depth - 1, seen, [])
            subchain.append({"field_slot": spec["id"],
                             "writer": g.funcs.get(writer, "?"),
                             "argument_index": index,
                             "targets": [hex(t) for t in sorted(got)],
                             "failure": why, "chain": sub})
            if why:
                failure = why
                break
            targets |= got
        if failure:
            chain.append({"field_slot": spec["id"], "failure": failure,
                          "sources": rows, "chain": subchain})
            continue
        results.append((targets, spec, rows, subchain))
    if not results:
        return set(), f"field {off:#x} has no decidable slot writer", chain
    first = results[0][0]
    if any(r[0] != first for r in results[1:]):
        return set(), f"field {off:#x} has conflicting slot writers", chain
    targets, spec, rows, subchain = results[0]
    chain.append({"field_slot": spec["id"], "field_offset": hex(off),
                  "sources": rows, "targets": [hex(t) for t in sorted(targets)],
                  "chain": subchain})
    return targets, None, chain


def _semantic_resolve(g: "DsoGraph", atom: dict, reachable: set, depth: int,
                      seen: set, chain: list):
    kind = atom.get("kind")
    if kind == "int":
        v = atom.get("value")
        if v == 0:
            return set(), None, chain
        if v in g.start_set:
            return {v}, None, chain
        return set(), f"non-image immediate {v:#x}", chain
    if kind == "relocation":
        targets, bad = set(), []
        for row in atom.get("symbols") or ():
            if row.get("image_bounded") and row.get("target") in g.start_set:
                targets.add(row["target"])
            else:
                bad.append(row.get("symbol"))
        if bad:
            return set(), ("relocation names a symbol not defined in this "
                           "image: " + ", ".join(str(b) for b in bad)), chain
        return targets, None, chain
    if kind == "static-slot":
        vals = {v for v in atom.get("values", ()) if v in g.start_set}
        if not vals:
            return set(), "static slot has no in-image function value", chain
        return vals, None, chain
    if kind == "table":
        vals = {v for v in atom.get("values", ()) if v in g.start_set}
        if not vals:
            return set(), "table entry has no in-image function value", chain
        return vals, None, chain
    if kind == "field":
        return _semantic_field_targets(g, atom["offset"], reachable, depth - 1,
                                       seen, chain)
    if kind == "param":
        return _semantic_param_targets(g, atom["func"], atom["index"], reachable,
                                       depth - 1, seen, chain)
    return set(), "provenance is not image-bounded: " + str(atom.get("why")), chain


def semantic_method_free_targets(g: "DsoGraph", site: dict, name: str,
                                 reachable: set | None):
    """Method.free (offset 0x20) targets from the values reachable code stores.

    The declared target names are never the source of truth.  Each reachable
    writer's stored value is followed to its provenance (lea, GLOB_DAT of an
    in-image definition, a caller parameter chain, or one level of an object
    field whose slot writer is known).  Any reachable store whose provenance is
    not image-bounded keeps the site UNRESOLVED.

    Returns None when the site is not this slot; otherwise a record with
    ``resolved`` and, on success, ``targets``.  The derivation depends only on
    the image and the reachable set, so it is computed once per graph and the
    provenance interpreter is released immediately: the court container has a
    hard 8 GiB limit and the main resolver's state must survive alongside it.
    """
    spec = next((s for s in EDGE_TARGET_SLOTS if s["id"] == "EVT-METHOD-FREE"),
                None)
    if spec is None or not any(f in (name or "") for f in spec["function"]):
        return None
    if 0x20 not in set(site.get("field_offsets") or ()):
        return None
    if reachable is None:
        return {"schema": SEMANTIC_STORE_SCHEMA,
                "rule": "stored-value provenance at reachable writer call sites",
                "slot": "Method.free (offset 0x20)",
                "declared_source_of_truth": False,
                "site": hex(site["addr"]),
                "containing_function": name,
                "resolved": False,
                "refusal": "no reachability evidence was supplied"}
    shared = getattr(g, "_semantic_mf_cache", None)
    if shared is None or shared[0] is not reachable:
        record = _semantic_method_free_derivation(g, spec, reachable)
        g._semantic_mf_cache = (reachable, record)
        # The stored-value rule is done with the provenance interpreter.  Keep
        # only its small derivation record: retaining the whole interpreter
        # alongside the main resolver doubles peak memory for no benefit.
        g._semantic_call_index = None
        g._semantic_precision = None
        g._semantic_deltas = {}
        g._semantic_frame_base = {}
        shared = g._semantic_mf_cache
    record = dict(shared[1])
    record["site"] = hex(site["addr"])
    record["containing_function"] = name
    return record


def _semantic_method_free_derivation(g: "DsoGraph", spec: dict, reachable: set):
    record = {"schema": SEMANTIC_STORE_SCHEMA,
              "rule": "stored-value provenance at reachable writer call sites",
              "slot": "Method.free (offset 0x20)",
              "declared_source_of_truth": False}
    writers = []
    live_set = set()
    for frag in spec["writer_symbols"]:
        addrs = _name_addrs(g, frag)
        if not addrs:
            writers.append({"fragment": frag, "address": None, "symbol": None,
                            "present": False, "reachable": False})
        for a in sorted(addrs):
            writers.append({"fragment": frag, "address": hex(a),
                            "symbol": g.funcs.get(a, "?"), "present": True,
                            "reachable": a in reachable})
            if a in reachable:
                live_set.add(a)
    live = sorted(live_set)
    record["writers"] = writers
    # An excluded writer still carries a checkable witness: whether it is absent
    # from the image or present but outside the family's reachable set, and --
    # when its stored value is itself derivable -- which target it would store.
    # Without the would-store target an omitted exclusion would be invisible to
    # the accounting check below.
    idx = _semantic_call_index(g)
    excluded = []
    for w in writers:
        if w["reachable"]:
            continue
        row = {"fragment": w["fragment"], "address": w["address"],
               "symbol": w["symbol"],
               "reason": ("absent from the image" if not w["present"]
                          else "writer not in the family's reachable set"),
               "would_store_targets": None,
               "would_store_failure": None}
        if w["present"]:
            addr = int(w["address"], 16)
            sources = _semantic_writer_sources(g, addr, 0x20)
            indices = sorted({s["argument_index"] for s in sources
                              if s.get("argument_index") is not None})
            if len(indices) == 1:
                got, why = set(), None
                for key in sorted((idx.get(addr) or {})):
                    site_row = (idx.get(addr) or {})[key]
                    value = _semantic_value(g, site_row, indices[0])
                    for atom in _semantic_atom_rows(g, value):
                        atom["func"] = site_row["caller"]
                        t, why, _sub = _semantic_resolve(
                            g, atom, reachable, MAX_PROVENANCE_DEPTH, set(), [])
                        if why:
                            break
                        got |= t
                    if why:
                        break
                if why:
                    row["would_store_failure"] = why
                else:
                    row["would_store_targets"] = [
                        hex(_semantic_canonical_target(g, t)[0])
                        for t in sorted(got)]
            else:
                row["would_store_failure"] = (
                    "the store is not fed by exactly one parameter")
        excluded.append(row)
    record["excluded_writers"] = excluded
    if not live:
        record.update({"resolved": False,
                       "refusal": "no reachable method-store writer"})
        return record
    rows, index = [], None
    for writer in live:
        sources = _semantic_writer_sources(g, writer, 0x20)
        indices = sorted({r["argument_index"] for r in sources
                          if r.get("argument_index") is not None})
        rows.append({"writer": g.funcs.get(writer, "?"),
                     "writer_address": hex(writer), "stores": sources,
                     "argument_indices": indices})
        if len(indices) != 1 or (index is not None and indices[0] != index):
            index = None
            record.update({"resolved": False,
                           "refusal": ("a reachable writer's store into the slot "
                                       "is not fed by exactly one parameter"),
                           "writer_stores": rows})
            return record
        index = indices[0]
    if index is None:
        record.update({"resolved": False,
                       "refusal": "no writer stores a function parameter",
                       "writer_stores": rows})
        return record
    calls = []
    targets = set()
    failures = []
    for writer in live:
        sites = idx.get(writer) or {}
        for key in sorted(sites):
            site_row = sites[key]
            if site_row["caller"] not in reachable:
                calls.append({"caller": g.funcs.get(site_row["caller"], "?"),
                              "call_site": hex(site_row["call_site"]),
                              "writer": g.funcs.get(writer, "?"),
                              "included": False,
                              "reason": "caller not in the family's reachable set"})
                continue
            value = _semantic_value(g, site_row, index)
            row = {"caller": g.funcs.get(site_row["caller"], "?"),
                   "call_site": hex(site_row["call_site"]),
                   "writer": g.funcs.get(writer, "?"),
                   "argument_index": index,
                   "value": _semantic_atom_rows(g, value),
                   "included": True, "targets": [], "failure": None,
                   "chain": []}
            got = set()
            for atom in row["value"]:
                atom["func"] = site_row["caller"]
                t, why, sub = _semantic_resolve(g, atom, reachable,
                                                MAX_PROVENANCE_DEPTH, set(), [])
                row["chain"].append({"atom": atom, "targets": [hex(x) for x in sorted(t)],
                                     "failure": why, "chain": sub})
                if why:
                    row["failure"] = why
                    break
                got |= t
            row["targets"] = [hex(x) for x in sorted(got)]
            calls.append(row)
            if row["failure"]:
                failures.append(row)
            else:
                targets |= got
    record["writer_argument_index"] = index
    record["writer_stores"] = rows
    record["call_sites"] = calls
    if failures:
        record.update({"resolved": False,
                       "refusal": ("a reachable writer call site stores a value "
                                   "whose provenance is not image-bounded"),
                       "offending_call_sites": [
                           {"caller": f["caller"], "call_site": f["call_site"],
                            "failure": f["failure"]} for f in failures]})
        return record
    if not targets:
        record.update({"resolved": False,
                       "refusal": "the reachable call sites contribute no target"})
        return record
    canonical = {}
    collapses = []
    for t in sorted(targets):
        canon, chain = _semantic_canonical_target(g, t)
        canonical[t] = canon
        if canon != t:
            collapses.append({"stored": hex(t), "semantic": hex(canon),
                              "chain": chain})
    derived = set(canonical.values())
    declared_rows = {}
    declared_addrs = set()
    for frag in spec.get("declared_targets", ()):
        addrs = _name_addrs(g, frag)
        declared_rows[frag] = {"present": bool(addrs),
                               "addresses": [hex(a) for a in sorted(addrs)]}
        declared_addrs |= addrs
    declared_canon = {_semantic_canonical_target(g, a)[0] for a in declared_addrs}
    record.update({
        "resolved": True,
        "targets": [hex(a) for a in sorted(derived)],
        "target_count": len(derived),
        "stored_values": {hex(a): hex(b) for a, b in sorted(canonical.items())},
        "thunk_collapses": collapses,
        "declared_cross_check": {
            "source_of_truth": "stored-value provenance, not this list",
            "declared_targets": declared_rows,
            "declared_but_absent": [f for f, r in declared_rows.items()
                                    if not r["present"]],
            "derived_but_undeclared": [hex(a) for a in sorted(
                derived - declared_canon)],
            "declared_but_not_derived": [hex(a) for a in sorted(
                declared_canon - derived)],
        },
    })
    return record


def edge_target_witness(g: "DsoGraph", site: dict, name: str,
                        reachable: set | None):
    """The in-image slot's target set and record, or None.

    A function writer must be reachable in the pre-closure; a writer on no
    reachable path cannot have produced the slot value (negative control).
    """
    offsets = set(site.get("field_offsets") or ())
    for spec in EDGE_TARGET_SLOTS:
        if not any(f in (name or "") for f in spec["function"]):
            continue
        if spec.get("semantic_rule"):
            # The declared-name path must never run for a slot whose targets are
            # derived from stored values; the semantic rule is the only source
            # of truth and an absent name cannot void it.
            continue
        if spec["slot_offset"] is None:
            if offsets:
                continue
        elif spec["slot_offset"] not in offsets:
            continue
        targets = _fragment_addrs(g, spec["targets"])
        if not targets:
            continue
        if spec.get("writer_kind") == "static-initialiser":
            if not _static_initialiser_covers(g, targets, spec["table_symbols"]):
                continue
        else:
            if reachable is None:
                continue
            complete = True
            for frag in spec["writer_symbols"]:
                writers = _fragment_addrs(g, (frag,))
                if not writers or not (writers & reachable):
                    complete = False
                    break
            if not complete:
                continue
        return targets, spec
    return None


def _reloc_names(g: "DsoGraph", symbol: str) -> bool:
    base = (symbol or "").split("@")[0]
    if not base:
        return False
    for rec in getattr(g, "relocs", ()) or ():
        sym = (rec[2] or "").split("@")[0] if len(rec) > 2 else ""
        if sym and sym == base:
            return True
    return False


def _resolve_argument_summary(precision, caller: int, value):
    """Resolve one caller-recorded argument through its argument summary.

    This is the same summary expansion ``PrecisionResolver.resolve_set``
    performs when it builds ``arg_targets``: a literal is itself, and a
    forwarded parameter is replaced by the values that caller may pass.  The
    site's flat ``arg_targets`` was produced by that expansion, so per-caller
    attribution that uses it is recomputable rather than guessed.

    Returns ``(resolved_values, open)``; ``open`` is true when the argument was
    not recorded (a top or absent value), which is a reason to attribute
    nothing, never a reason to invent a target.
    """
    if value is None or value.is_top():
        return set(), True
    out = set()
    for b in value.s:
        if isinstance(b, tuple) and b and b[0] == "arg":
            out |= set(precision.summary_vals(caller, b[1]))
        else:
            out.add(b)
    return out, False


def _caller_attribution_rows(g, precision, caller: int, recs: dict, deps) -> tuple:
    """Per-call-site contribution rows for one caller, reachable or excluded.

    Every argument row carries the same shape used for reachable callers and
    the address targets it was resolved to.  ``contributed_targets`` is exactly
    the union of the per-call-site image targets, so the witness and the
    contribution list in the record are mutually checkable (v1.4).
    """
    rows, contributed = [], set()
    insns = getattr(precision, "insns_by_func", {}).get(caller, ())
    for call_addr in sorted(recs):
        args = recs[call_addr]
        idx = next((j for j, (a, _t) in enumerate(insns)
                    if a == call_addr), None)
        witness = (PrecisionResolver._arg_witness(insns, idx)
                   if idx is not None else {})
        arg_rows = []
        for k in deps:
            if k >= len(args):
                arg_rows.append({
                    "argument_index": k, "targets": [], "value": [],
                    "non_image_values": [], "unresolved": True,
                    "witness_instruction": []})
                continue
            value = args[k]
            resolved, open_ = _resolve_argument_summary(precision, caller, value)
            image = sorted(v for v in resolved
                           if isinstance(v, int) and v != 0
                           and v in g.start_set)
            non_image = sorted(str(v) for v in resolved
                               if not (isinstance(v, int) and v != 0
                                       and v in g.start_set))
            literal = sorted(hex(v) for v in
                             (() if value is None or value.is_top()
                              else value.s)
                             if isinstance(v, int))
            w = witness.get(_ARGREGS[k]) if k < len(_ARGREGS) else None
            arg_rows.append({
                "argument_index": k,
                "targets": [hex(v) for v in image],
                "value": literal,
                "non_image_values": non_image,
                "unresolved": bool(open_),
                "witness_instruction": (
                    [{"addr": hex(w[0]), "text": w[1]}] if w else []),
            })
            contributed |= set(image)
        rows.append({"call_site": hex(call_addr), "arguments": arg_rows})
    return rows, contributed


def _caller_exclusion(g: "DsoGraph", caller: int, import_addrs: set) -> dict:
    """Structured reason a caller is not part of the family's reachable set."""
    funcs = getattr(g, "funcs", {}) or {}
    all_syms = getattr(g, "all_syms", {}) or {}
    symbol = funcs.get(caller) or all_syms.get(caller) or "?"
    imported = caller in import_addrs
    relocated = _reloc_names(g, symbol)
    references = []
    if caller in (getattr(g, "taken_code", set()) or set()):
        references.append("lea/mov address materialisation")
    if caller in (getattr(g, "slot_func_targets", set()) or set()):
        references.append("function-pointer data slot")
    direct = getattr(g, "direct", {}) or {}
    callers = sorted(c for c, targets in direct.items() if caller in targets)
    if callers:
        references.append("direct call from " + ", ".join(hex(c) for c in callers))
    return {
        "function": hex(caller),
        "symbol": symbol,
        "in_reachable_set": False,
        "imported_by_consumer": imported,
        "in_image_relocation": relocated,
        "in_image_references": references,
        "reason": (
            "not in this family's reachable set: "
            + ("imported by the consumer" if imported
               else "not imported by the consumer")
            + (", has an in-image relocation" if relocated
               else ", no in-image relocation")
            + (", in-image references: " + "; ".join(references)
               if references else ", no in-image reference")),
    }


def reachable_caller_targets(g: "DsoGraph", site: dict, name: str,
                             reachable: set | None):
    """Bound an indirect site by the targets its *reachable* callers pass.

    This is a target-resolution rule, not an ABI contract.  It fires only when
    the site's unresolved target set derives solely from a function argument,
    every caller of that function is known from in-image call records, and
    every caller in the family's reachable set passes a finite set of in-image
    function starts for that argument.  Callers outside the reachable set are
    recorded (with their own per-call-site attribution), not admitted.  Any
    non-image argument from a reachable caller, a caller whose reachability
    cannot be established, or a non-argument target keeps the site unresolved.

    Soundness direction (round 4): admitting a target is always safe for the
    upper bound; excluding one requires (i) the caller/writer is absent from the
    final-upper-bound oracle and (ii) the target is demonstrably produced by
    that subject.  The attribution is analyzer-produced from the same argument
    summary the site's flat ``arg_targets`` came from; record-level validation
    checks the record against itself and the oracle, not against a
    re-derivation.

    Returns (record, None) or (None, refusal_reason).
    """
    if reachable is None:
        return None, "no reachability evidence was supplied"
    deps = sorted(site.get("arg_deps") or ())
    if not deps:
        return None, "the site does not read a function argument"
    fstart = site["func"]
    dynamic = getattr(g, "dynamic_defs", {}) or {}
    if fstart in set(dynamic.values()):
        return None, ("the containing function is a dynamic export; callers outside "
                      "the image cannot be bounded")
    precision = getattr(g, "precision", None)
    if precision is None:
        return None, "no resolver call-record evidence"
    calls = getattr(precision, "calls", ()) or ()
    records = collections.defaultdict(dict)
    edges = set()
    for caller, callee, args, call_addr in calls:
        edges.add((caller, call_addr, callee))
        if callee == fstart:
            records[caller][call_addr] = args
    direct = getattr(g, "direct", {}) or {}
    direct_callers = {c for c, targets in direct.items() if fstart in targets}
    # The rule's precondition is that every caller is known from in-image call
    # records.  A direct caller without one -- reachable or excluded -- makes the
    # flat candidate enumeration incomplete, so the site is not bounded.  The
    # round-4 fallback handles an excluded caller whose *recorded* argument is
    # unknown (its call-site row contributes nothing); it does not license a
    # bound when the caller's call record is missing altogether.
    for caller in sorted(direct_callers):
        if not records.get(caller):
            return None, f"caller {hex(caller)} has no recorded call arguments"
    # A function target reached from an unresolved indirect site has an unknown
    # caller argument; a resolved indirect site must carry its argument record.
    for (site_func, site_addr, kind), other in (getattr(g, "sites", {}) or {}).items():
        if kind != "call" or fstart not in (other.get("targets") or ()):
            continue
        if other.get("unresolved"):
            return None, (f"indirect call site {hex(site_addr)} can target this "
                          "function with an unbounded argument")
        if (site_func, site_addr, fstart) not in edges:
            return None, (f"indirect call site {hex(site_addr)} targets this "
                          "function without an argument record")
    callers = set(records) | direct_callers
    if not callers:
        return None, "no in-image caller"
    site_targets = set(site.get("targets") or ())
    if any(not isinstance(t, int) for t in site_targets):
        return None, "the site has a non-address target"
    arg_targets = {t for t in (site.get("arg_targets") or ()) if isinstance(t, int)}
    if site_targets - arg_targets:
        return None, "the site has targets that do not derive from the argument"
    import_addrs = (getattr(precision, "import_addrs", set()) or set()) \
        | (getattr(g, "import_addrs", set()) or set())
    bounded = set()
    excluded_union = set()
    reachable_rows, excluded_rows = [], []
    for caller in sorted(callers):
        recs = records.get(caller) or {}
        if caller not in reachable:
            row = _caller_exclusion(g, caller, import_addrs)
            row["reachable"] = False
            # Round 4: an excluded caller's contribution is recorded with the
            # *same* per-call-site shape and the same argument-summary
            # interpreter used for reachable callers.  A caller that forwards
            # its own parameter therefore contributes exactly the values its
            # summary admits -- which is where the site's flat `arg_targets`
            # came from.  A caller with no recorded call arguments contributes
            # nothing and its row is empty; nothing is inferred from its name.
            call_rows, contributed = _caller_attribution_rows(
                g, precision, caller, recs, deps)
            row["call_sites"] = call_rows
            row["contributed_targets"] = [hex(t) for t in sorted(contributed)]
            excluded_union |= contributed
            excluded_rows.append(row)
            continue
        if not recs:
            return None, (f"reachable caller {hex(caller)} has no recorded call "
                          "arguments")
        caller_targets = set()
        call_rows = []
        for call_addr in sorted(recs):
            args = recs[call_addr]
            insns = getattr(precision, "insns_by_func", {}).get(caller, ())
            idx = next((j for j, (a, _t) in enumerate(insns)
                        if a == call_addr), None)
            witness = (PrecisionResolver._arg_witness(insns, idx)
                       if idx is not None else {})
            arg_rows = []
            for k in deps:
                if k >= len(args):
                    return None, (f"call site {hex(call_addr)} does not record "
                                  f"argument {k}")
                val = args[k]
                if val is None or val.is_top():
                    return None, (f"reachable caller {hex(caller)} passes an unknown "
                                  f"value as argument {k}")
                vals = val.s
                if not vals:
                    return None, (f"reachable caller {hex(caller)} passes an empty "
                                  f"value as argument {k}")
                bad = sorted(str(v) for v in vals
                             if not (isinstance(v, int) and v != 0
                                     and v in g.start_set))
                if bad:
                    return None, (f"reachable caller {hex(caller)} passes a "
                                  f"non-image value as argument {k}: "
                                  + ", ".join(bad[:4]))
                caller_targets |= set(vals)
                w = witness.get(_ARGREGS[k]) if k < len(_ARGREGS) else None
                # `argument`/`value` are the v1 fields (kept for compatibility);
                # `argument_index`/`targets` are the v2 per-call-site shape.
                arg_rows.append({
                    "argument": k,
                    "argument_index": k,
                    "value": [hex(v) for v in sorted(vals)],
                    "targets": [hex(v) for v in sorted(vals)],
                    "non_image_values": [],
                    "unresolved": False,
                    "witness_instruction": (
                        [{"addr": hex(w[0]), "text": w[1]}] if w else []),
                })
            call_rows.append({"call_site": hex(call_addr), "arguments": arg_rows})
        bounded |= caller_targets
        reachable_rows.append({
            "function": hex(caller),
            "symbol": getattr(g, "funcs", {}).get(caller, "?"),
            "reachable": True,
            "reason": None,
            "call_sites": call_rows,
            "contributed_targets": [hex(t) for t in sorted(caller_targets)],
        })
    if not reachable_rows:
        return None, "no reachable in-image caller"
    if not bounded:
        return None, "the reachable callers contribute no in-image target"
    if not (bounded <= site_targets):
        return None, ("a reachable caller contributes a target absent from the "
                      "recorded site set")
    if not excluded_rows:
        return None, ("no caller is excluded; the site is not narrowed from a "
                      "wider caller set")
    # Candidates are the site's flat argument-target union.  A candidate that
    # no caller row attributes is *not* droppable: it is admitted conservatively
    # by the record builder (round 4).  Computing it here keeps the derivation
    # and the record's `unattributed_targets` identical by construction.
    attributed = bounded | excluded_union
    unattributed = sorted(arg_targets - attributed)
    return {
        "schema": REACHABLE_CALLER_SCHEMA,
        "rule": "reachable-caller target bounding",
        "not_a_contract_class": True,
        "contract_bounded": False,
        "call_site": hex(site["addr"]),
        "argument_indices": deps,
        "reachable_callers": reachable_rows,
        "excluded_callers": excluded_rows,
        "bounded_targets": [hex(t) for t in sorted(bounded)],
        "attributed_targets": [hex(t) for t in sorted(attributed)],
        "unattributed_targets": [hex(t) for t in unattributed],
    }, None


def _image_defines(g: "DsoGraph", fragments) -> bool:
    """True when at least one named writer is defined in this exact image."""
    if isinstance(fragments, str):
        fragments = (fragments,)
    names = set(g.all_syms.values()) if hasattr(g, "all_syms") else set()
    return any(fragment in (n or "") for fragment in fragments for n in names)


def _switch_table_base(g: "DsoGraph", insns, i: int):
    """The relative switch table base read by ``jmp *reg`` at index i, or None."""
    for k in range(i - 1, max(-1, i - 14), -1):
        mn, _rest, ops = _insn_parts(insns[k][1])
        if mn != "movslq" or not ops:
            continue
        m = re.fullmatch(
            r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+),(%r[a-z0-9]+),4\)",
            ops[0])
        if not m:
            continue
        base_reg = _canon(m.group(2))
        for j in range(k - 1, max(-1, k - 8), -1):
            jmn, _jrest, jops = _insn_parts(insns[j][1])
            if not jops or _canon(jops[-1]) != base_reg:
                continue
            if jmn not in ("lea", "mov"):
                continue
            addr = _insn_comment_addr(insns[j][1])
            if addr is not None and g.section_of(addr) is not None:
                return addr
    return None


def _switch_entries(g: "DsoGraph", base: int, site_addr: int):
    """Raw relative switch-table targets, using the compiler's own bound.

    ``PrecisionResolver.switch_targets`` keeps only entries that are function
    starts.  A CFG needs the interior block targets too, so this reads the same
    bounded table without that filter.  No bound means no decoding.
    """
    count = getattr(g.precision, "switch_bounds", {}).get(site_addr)
    if not count or count <= 0 or count > 4096:
        return None
    sec = g.section_of(base)
    if sec is None:
        return None
    a, _off, _size = g.sections[sec]
    data = g._section_bytes(sec)
    start = base - a
    out = set()
    for k in range(count):
        if start + 4 * k + 4 > len(data):
            break
        v = struct.unpack_from("<i", data, start + 4 * k)[0]
        out.add(base + v)
    return out


def _function_cfg(g: "DsoGraph", fstart: int) -> dict:
    """Basic blocks, successors and open (indirect-jump) blocks for one function.

    The precision resolver tracks abstract values along linear paths; a witness
    needs a reaching definition, so the path question has to be answered on the
    CFG.  A block reached from an indirect jump is *open*: any register may
    hold a value this image does not account for, and a query whose block is in
    that forward closure is refused rather than guessed.
    """
    cache = getattr(g, "_fn_cfg_cache", None)
    if cache is None:
        cache = {}
        g._fn_cfg_cache = cache
    if fstart in cache:
        return cache[fstart]
    insns = g.precision.insns_by_func.get(fstart, ())
    n = len(insns)
    idx_of = {a: i for i, (a, _t) in enumerate(insns)}
    switch_targets = {}
    if n and getattr(g, "precision", None) is not None:
        rec = getattr(g.precision, "_record_switch_bounds", None)
        if rec is not None:
            rec(insns)
        for i, (a, text) in enumerate(insns):
            mn, rest, _ops = _insn_parts(text)
            if mn != "jmp" or not rest.startswith("*"):
                continue
            base = _switch_table_base(g, insns, i)
            if base is None:
                continue
            ts = _switch_entries(g, base, a)
            if not ts:
                ts = {t for t in g.precision.switch_targets(base, a)
                      if t in idx_of}
            if ts:
                switch_targets[i] = ts
    leaders = {0} if n else set()
    for i, (_a, text) in enumerate(insns):
        mn, rest, _ops = _insn_parts(text)
        if mn.startswith("j"):
            m = re.match(r"^([0-9a-f]+)", rest)
            if m and int(m.group(1), 16) in idx_of:
                leaders.add(idx_of[int(m.group(1), 16)])
            if i + 1 < n:
                leaders.add(i + 1)
        elif mn.startswith(("ret", "iret", "ud2")):
            if i + 1 < n:
                leaders.add(i + 1)
    for ts in switch_targets.values():
        for t in ts:
            if t in idx_of:
                leaders.add(idx_of[t])
    leaders = sorted(leaders)
    blocks, block_of = [], {}
    for bi, lo in enumerate(leaders):
        hi = leaders[bi + 1] if bi + 1 < len(leaders) else n
        blocks.append((lo, hi))
        for i in range(lo, hi):
            block_of[i] = bi
    succ, open_blocks = {}, set()
    for bi, (_lo, hi) in enumerate(blocks):
        mn, rest, _ops = _insn_parts(insns[hi - 1][1])
        s = []
        if mn == "jmp":
            if rest.startswith("*"):
                ts = switch_targets.get(hi - 1)
                if ts:
                    for t in ts:
                        if t in idx_of:
                            s.append(block_of[idx_of[t]])
                        else:
                            open_blocks.add(bi)
                else:
                    open_blocks.add(bi)
            else:
                m = re.match(r"^([0-9a-f]+)", rest)
                if m and int(m.group(1), 16) in idx_of:
                    s.append(block_of[idx_of[int(m.group(1), 16)]])
                else:
                    open_blocks.add(bi)
        elif mn.startswith("j"):
            m = re.match(r"^([0-9a-f]+)", rest)
            if m and int(m.group(1), 16) in idx_of:
                s.append(block_of[idx_of[int(m.group(1), 16)]])
            else:
                open_blocks.add(bi)
            if hi < n:
                s.append(block_of[hi])
        elif mn.startswith(("ret", "iret", "ud2")):
            pass
        elif hi < n:
            s.append(block_of[hi])
        succ[bi] = sorted(set(s))
    open_reach = set(open_blocks)
    work = list(open_blocks)
    while work:
        bi = work.pop()
        for s in succ.get(bi, ()):
            if s not in open_reach:
                open_reach.add(s)
                work.append(s)
    cfg = {"insns": insns, "blocks": blocks, "block_of": block_of,
           "succ": succ, "open_reach": open_reach}
    cache[fstart] = cfg
    return cfg


_ENTRY_DEF = -1
_TOP_DEFS = None
_NO_STORE = -2
_COMPARE_MN = ("cmp", "test", "ucom", "comi", "ptest", "bt")


def _defined_regs_at(text: str) -> set:
    """Registers an instruction writes (a call writes the caller-saved set)."""
    mn, _rest, ops = _insn_parts(text)
    if mn.startswith("call"):
        return set(_CALLER_SAVED)
    if not ops or mn.startswith(_COMPARE_MN + ("j", "nop", "ret", "iret",
                                              "push", "ud2")):
        return set()
    if mn.startswith("pop"):
        dst = ops[0]
        return {_canon(dst)} if (dst in _REGS or dst in _SUBREG) else set()
    dst = ops[-1]
    if dst in _REGS or dst in _SUBREG:
        return {_canon(dst)}
    return set()


def _reaching_table(g: "DsoGraph", fstart: int, cfg: dict):
    """Per-block reaching definitions (reg -> set of instruction indices).

    ``_ENTRY_DEF`` means the incoming value is not defined in this function
    (the entry parameter).  A ``None`` entry is TOP (an unresolved merge); the
    enclosing query refuses it.
    """
    cache = getattr(g, "_reaching_cache", None)
    if cache is None:
        cache = {}
        g._reaching_cache = cache
    if fstart in cache:
        return cache[fstart]
    insns, blocks, succ = cfg["insns"], cfg["blocks"], cfg["succ"]
    nb = len(blocks)
    inb = [None] * nb
    outb = [None] * nb
    if nb:
        inb[0] = {r: {_ENTRY_DEF} for r in _REGS}
    spent = 0
    changed = True
    while changed and spent < 400:
        spent += 1
        changed = False
        for bi, (lo, hi) in enumerate(blocks):
            if inb[bi] is None:
                continue
            state = {r: set(v) for r, v in inb[bi].items()}
            for i in range(lo, hi):
                for r in _defined_regs_at(insns[i][1]):
                    state[r] = {i}
            outb[bi] = state
            for s in succ.get(bi, ()):
                if s in cfg["open_reach"]:
                    continue
                if inb[s] is None:
                    inb[s] = {r: set(v) for r, v in state.items()}
                    changed = True
                else:
                    for r, v in state.items():
                        cur = inb[s].get(r)
                        if cur is None:
                            inb[s][r] = set(v)
                            changed = True
                        else:
                            nv = cur | v
                            if nv != cur:
                                inb[s][r] = nv
                                changed = True
    if spent >= 400:
        inb = [None] * nb
    cache[fstart] = inb
    return inb


def _reaching_defs(g: "DsoGraph", fstart: int, idx: int, reg: str):
    """Definitions of ``reg`` that reach instruction ``idx``.

    Returns a set of instruction indices, ``_ENTRY_DEF``, or None for TOP.
    """
    cfg = _function_cfg(g, fstart)
    bi = cfg["block_of"].get(idx)
    if bi is None:
        return None
    lo, _hi = cfg["blocks"][bi]
    # A definition in the site's own block needs no predecessor analysis, so it
    # is still usable when the function has an indirect jump elsewhere (the
    # block itself is only "open" if a predecessor is).
    for k in range(idx - 1, lo - 1, -1):
        if reg in _defined_regs_at(cfg["insns"][k][1]):
            return {k}
    if bi in cfg["open_reach"]:
        return None
    inb = _reaching_table(g, fstart, cfg)
    if inb[bi] is None:
        return None
    return set(inb[bi].get(reg, {_ENTRY_DEF}))


def _single_def(g: "DsoGraph", fstart: int, idx: int, reg: str):
    defs = _reaching_defs(g, fstart, idx, reg)
    if defs is None or len(defs) != 1:
        return None
    return next(iter(defs))


def _insn(g: "DsoGraph", fstart: int, idx: int) -> str:
    insns = g.precision.insns_by_func.get(fstart, ())
    return insns[idx][1] if 0 <= idx < len(insns) else ""


def _containing(g: "DsoGraph", addr: int):
    """Function start containing ``addr`` (synthetic graphs answer exactly)."""
    if hasattr(g, "containing"):
        return g.containing(addr)
    return addr if addr in g.start_set else None


def _direct_call_target(g: "DsoGraph", fstart: int, idx: int):
    """(address, function-start) when instruction idx is a direct in-image call."""
    mn, rest, _ops = _insn_parts(_insn(g, fstart, idx))
    if mn != "call" or rest.startswith("*"):
        return None
    m = re.match(r"^([0-9a-f]+)", rest)
    if not m:
        return None
    addr = int(m.group(1), 16)
    target = _containing(g, addr)
    if target is None and addr in g.start_set:
        target = addr
    return (addr, target) if target is not None else None


def _stack_slot_abs(g: "DsoGraph", fstart: int, idx: int, opnd: str):
    """Entry-relative offset of a frame operand, or None."""
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", opnd.strip())
    if not m:
        return None
    off = int(m.group(1), 16) if m.group(1) else 0
    deltas = _semantic_rsp_deltas(g, fstart)
    if m.group(2) == "%rsp":
        delta = deltas[idx] if idx < len(deltas) else None
        if delta is None:
            delta = _prologue_delta(g, fstart)
        return None if delta is None else delta + off
    frame = _semantic_frame_base(g, fstart)
    if frame is None:
        return None
    return frame[1] + off


def _stack_slot_writes(g: "DsoGraph", fstart: int, target: int) -> list:
    """Every store and every address materialisation of one frame slot."""
    insns = g.precision.insns_by_func.get(fstart, ())
    stores, escapes = [], []
    for i, (_a, text) in enumerate(insns):
        mn, _rest, ops = _insn_parts(text)
        if not ops:
            continue
        dst = ops[-1]
        if dst.endswith("(%rsp)") or dst.endswith("(%rbp)"):
            abs_off = _stack_slot_abs(g, fstart, i, dst)
            if abs_off == target and not mn.startswith(_COMPARE_MN + ("lea",)):
                stores.append((i, ops[0], text))
        if mn == "lea":
            abs_off = _stack_slot_abs(g, fstart, i, ops[0]) if ops else None
            if abs_off == target:
                escapes.append((i, text))
    return [{"kind": "store", "index": i, "source": src, "text": text}
            for i, src, text in stores] + [
            {"kind": "address", "index": i, "text": text}
            for i, text in escapes]


def _witness(cls: str, name: str, site: dict, *, slot: str, writer: str,
             interface: str, basis: str, contract_bounded: bool = True) -> dict:
    return {
        "schema": WITNESS_SCHEMA,
        "class": cls,
        "contract_bounded": contract_bounded,
        "function": name,
        "call_site": hex(site["addr"]),
        "slot": slot,
        "writer": writer,
        "interface": interface,
        "basis": basis,
    }


def _internal_slot_note(name: str, offsets, seam=None) -> str:
    for fragment, offset, note in INTERNAL_SLOT_NOTES:
        if fragment not in (name or ""):
            continue
        if offset is None or offset in (offsets or ()):
            return note
    if seam:
        return (f"the resolver recorded the allocator seam {seam}, but this image "
                "does not expose the hook global and CRYPTO_set_mem_functions")
    if offsets:
        return ("an in-image object field at offset "
                f"{', '.join(hex(o) for o in sorted(offsets))}; this image carries "
                "no documented provider interface that writes it")
    return ("an in-image value in this frame; this image carries no documented "
            "provider interface that writes it")


# --------------------------------------------------------------------------- #
# source-backed witnesses for the S2/S3/S4 mechanisms
# --------------------------------------------------------------------------- #
#
# These witnesses answer a narrower question than the resolver's abstract
# interpreter: where did *this* value come from on the CFG path to this site?
# The resolver's linear scan is deliberately cheap and can pick a write from a
# non-dominating branch; a witness must not.  Every helper below therefore asks
# the CFG for the reaching definition and refuses a merge it cannot enumerate.

_EVIDENCE_ENV = {"repo": None, "install": None}
# Test-only mutation switches (AGENTS.md section 16 negative controls).  A
# mutation disables exactly one refusal so the matching negative fixture must
# flip to accepted; nothing outside --self-test sets these.
_MUTED = set()


def _repo_root(g=None) -> Path | None:
    root = getattr(g, "source_root", None) if g is not None else None
    if root:
        return Path(root)
    if _EVIDENCE_ENV.get("repo"):
        return Path(_EVIDENCE_ENV["repo"])
    return None


def _install_root(g=None) -> Path | None:
    root = getattr(g, "install_prefix", None) if g is not None else None
    if root:
        return Path(root)
    if _EVIDENCE_ENV.get("install"):
        return Path(_EVIDENCE_ENV["install"])
    return None


def _has_insns(g: "DsoGraph") -> bool:
    return (getattr(g, "precision", None) is not None
            and hasattr(g.precision, "insns_by_func"))


def _site_operand(site: dict) -> str:
    text = site.get("text") or ""
    body = text.split("#", 1)[0]
    if "*" in body:
        return body.split("*", 1)[1].strip()
    return ""


def _reg_origin(g: "DsoGraph", fstart: int, idx: int, reg: str,
                depth: int = 0):
    """Single-provenance origin of a register at instruction ``idx``.

    Returns ``{"kind": "param", "index": n}``, ``{"kind": "call",
    "callee": n, "call_site": n}``, ``{"kind": "load", "offset": n,
    "base_reg": r, "at": n}``, ``{"kind": "int", "value": n}`` or
    ``{"kind": "unknown", "why": ...}``.  A value with more than one reaching
    definition is refused; it is never unioned.
    """
    if depth > 8:
        return {"kind": "unknown", "why": "provenance depth bound"}
    defs = _reaching_defs(g, fstart, idx, reg)
    if defs is None:
        return {"kind": "unknown", "why": "open or non-convergent CFG"}
    if defs == {_ENTRY_DEF}:
        if reg in _ENTRY_ARG_REGS:
            return {"kind": "param", "index": _ENTRY_ARG_REGS[reg]}
        return {"kind": "unknown", "why": f"entry value in {reg}"}
    if len(defs) != 1:
        return {"kind": "unknown",
                "why": "multiple reaching definitions: "
                       + ", ".join(hex(g.precision.insns_by_func[fstart][k][0])
                                    for k in sorted(defs) if k >= 0)}
    k = next(iter(defs))
    mn, _rest, ops = _insn_parts(_insn(g, fstart, k))
    addr = g.precision.insns_by_func[fstart][k][0]
    if mn.startswith("call"):
        symbol = _nested_alloc_symbol(g, fstart, k)
        if symbol is not None:
            alloc = _nested_alloc_size(g, fstart, k, depth + 1)
            if alloc is None:
                return {"kind": "alloc-unknown", "symbol": symbol,
                        "call_site": k, "addr": addr}
            return {"kind": "alloc", "symbol": alloc["symbol"],
                    "size": alloc["size"], "call_site": k, "addr": addr}
        direct = _direct_call_target(g, fstart, k)
        if direct is None:
            return {"kind": "unknown", "why": "indirect call result"}
        return {"kind": "call", "callee": direct[1], "call_site": k,
                "callee_addr": direct[0], "addr": addr}
    if mn in ("xor", "sub") and len(ops) == 2 and ops[0] == ops[1]:
        return {"kind": "int", "value": 0, "addr": addr}
    if mn not in ("mov", "movq", "movl", "movzbl", "movzwl", "movslq",
                  "lea", "and"):
        return {"kind": "unknown", "why": f"unexpected writer {mn}"}
    src = ops[0] if len(ops) >= 2 else ""
    if not src:
        return {"kind": "unknown", "why": "writer without source"}
    if src.startswith("$"):
        try:
            return {"kind": "int", "value": int(src[1:], 16), "addr": addr}
        except ValueError:
            return {"kind": "unknown", "why": "bad immediate"}
    if src in _REGS or src in _SUBREG:
        return _reg_origin(g, fstart, k, _canon(src), depth + 1)
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", src)
    if m:
        off = int(m.group(1), 16) if m.group(1) else 0
        return {"kind": "load", "offset": off, "base_reg": m.group(2),
                "at": k, "addr": addr}
    return {"kind": "unknown", "why": "unsupported source " + src}


def _param_of_operand(g: "DsoGraph", fstart: int, idx: int, opnd: str):
    """The callback parameter this operand reads, with its single provenance.

    Handles a register that still holds the entry argument, a register copied
    from one, a reload from the entry spill slot, and a stack-passed argument.
    A frame slot with any other writer is refused.
    """
    opnd = opnd.strip()
    if opnd in _REGS or opnd in _SUBREG:
        origin = _reg_origin(g, fstart, idx, _canon(opnd))
        if origin.get("kind") == "param":
            return {"kind": "param", "index": origin["index"],
                    "provenance": [{"step": "entry-register",
                                    "reg": _canon(opnd)}]}
        if origin.get("kind") == "load":
            stack = _stack_param(g, fstart, origin["at"], origin["offset"],
                                 origin["base_reg"])
            if stack is not None:
                return stack
        return {"kind": "unknown", "why": f"operand {opnd}: "
                                                   + origin.get("why", origin["kind"])}
    stack = _stack_param(g, fstart, idx, opnd, None)
    if stack is not None:
        return stack
    return {"kind": "unknown", "why": f"operand {opnd} is not a parameter"}


def _store_slot_at(g: "DsoGraph", fstart: int, idx: int, slot: int) -> bool:
    """True when instruction idx writes the frame slot at ``slot``."""
    mn, _rest, ops = _insn_parts(_insn(g, fstart, idx))
    if not ops or mn.startswith(_COMPARE_MN + ("lea",)):
        return False
    dst = ops[-1]
    if not (dst.endswith("(%rsp)") or dst.endswith("(%rbp)")):
        return False
    return _stack_slot_abs(g, fstart, idx, dst) == slot


def _reaching_store_table(g: "DsoGraph", fstart: int, cfg: dict, slot: int):
    """Per-block last store reaching the block end for one frame slot.

    ``None`` is TOP (an open predecessor); an empty set means no store on any
    analysed path, which is a direct stack argument rather than a spill.
    """
    cache = getattr(g, "_reaching_store_cache", None)
    if cache is None:
        cache = {}
        g._reaching_store_cache = cache
    key = (fstart, slot)
    if key in cache:
        return cache[key]
    blocks, succ = cfg["blocks"], cfg["succ"]
    nb = len(blocks)
    inb = [None] * nb
    outb = [None] * nb
    if nb:
        inb[0] = frozenset({_NO_STORE})
    spent = 0
    changed = True
    while changed and spent < 400:
        spent += 1
        changed = False
        for bi, (lo, hi) in enumerate(blocks):
            if inb[bi] is None:
                continue
            last = None
            for i in range(lo, hi):
                if _store_slot_at(g, fstart, i, slot):
                    last = i
            out = frozenset({last}) if last is not None else inb[bi]
            outb[bi] = out
            for s in succ.get(bi, ()):
                if s in cfg["open_reach"]:
                    continue
                if inb[s] is None:
                    inb[s] = out
                    changed = True
                else:
                    nv = inb[s] | out
                    if nv != inb[s]:
                        inb[s] = nv
                        changed = True
    if spent >= 400:
        inb = [None] * nb
    cache[key] = inb
    return inb


def _reaching_stores(g: "DsoGraph", fstart: int, idx: int, slot: int):
    """Stores to a frame slot that reach instruction idx (set), or None."""
    cfg = _function_cfg(g, fstart)
    bi = cfg["block_of"].get(idx)
    if bi is None:
        return None
    lo, _hi = cfg["blocks"][bi]
    for k in range(idx - 1, lo - 1, -1):
        if _store_slot_at(g, fstart, k, slot):
            return {k}
    if bi in cfg["open_reach"]:
        return None
    inb = _reaching_store_table(g, fstart, cfg, slot)
    if inb is None or inb[bi] is None:
        return None
    return set(inb[bi])


def _slot_address_taken(g: "DsoGraph", fstart: int, slot: int) -> bool:
    """True when the frame slot's address is materialised anywhere."""
    insns = g.precision.insns_by_func.get(fstart, ())
    for i, (_a, text) in enumerate(insns):
        mn, _rest, ops = _insn_parts(text)
        if mn == "lea" and ops and _stack_slot_abs(g, fstart, i, ops[0]) == slot:
            return True
    return False


def _slot_alias_in_block(g: "DsoGraph", fstart: int, idx: int, slot: int,
                         allowed: set) -> bool:
    """True when the site's own block materialises the slot outside ``allowed``.

    A frame slot reused by an earlier block is not an alias of the value at the
    site: only an address taken in the site's block can reach the site without
    a call boundary.  The construction ``lea`` instructions are passed in
    ``allowed``; any other one refuses the witness.
    """
    cfg = _function_cfg(g, fstart)
    bi = cfg["block_of"].get(idx)
    if bi is None:
        return True
    lo, _hi = cfg["blocks"][bi]
    for i in range(lo, idx):
        mn, _rest, ops = _insn_parts(_insn(g, fstart, i))
        if mn != "lea" or not ops or i in allowed:
            continue
        if _stack_slot_abs(g, fstart, i, ops[0]) == slot:
            return True
    return False


def _stack_param(g: "DsoGraph", fstart: int, idx: int, opnd, base_reg):
    """A stack slot that is exactly a parameter or its entry spill."""
    if base_reg is None:
        m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", opnd.strip())
        if not m:
            return None
        base_reg = m.group(2)
        abs_off = _stack_slot_abs(g, fstart, idx, opnd)
    else:
        if base_reg not in ("%rsp", "%rbp"):
            return None
        abs_off = _stack_slot_abs(g, fstart, idx,
                                  (hex(opnd) if opnd else "") + "(" + base_reg + ")")
    if abs_off is None:
        return None
    if _slot_alias_in_block(g, fstart, idx, abs_off, set()):
        return None
    writes = _reaching_stores(g, fstart, idx, abs_off)
    if writes is None:
        return None
    if not writes:
        return None
    if writes == {_NO_STORE}:
        # Incoming stack argument: entry rsp+8 is argument 6.
        if abs_off >= 8 and (abs_off - 8) % 8 == 0:
            return {"kind": "param", "index": 6 + (abs_off - 8) // 8,
                    "stack_offset": abs_off,
                    "provenance": [{"step": "stack-argument",
                                    "offset": hex(abs_off)}]}
        return None
    if _NO_STORE in writes:
        # One path does not write the slot; the value is not a single spill.
        return None
    indices = set()
    provenance = []
    for i in sorted(writes):
        _mn, _rest, ops = _insn_parts(_insn(g, fstart, i))
        src = ops[0] if ops else ""
        if src not in _REGS and src not in _SUBREG:
            return None
        origin = _reg_origin(g, fstart, i, _canon(src))
        if origin.get("kind") != "param":
            return None
        indices.add(origin["index"])
        provenance.append({"step": "entry-spill",
                           "addr": hex(g.precision.insns_by_func[fstart][i][0]),
                           "text": _insn(g, fstart, i)})
    if len(indices) != 1:
        return None
    return {"kind": "param", "index": next(iter(indices)),
            "spill_site": str(provenance[0]["addr"]), "provenance": provenance}


def _callers_of(g: "DsoGraph", callee: int) -> list:
    """Direct in-image call sites of one function, scanned on demand.

    A global caller index holds one tuple per direct call in the image; the
    closure already sits close to its per-process data limit, so the index is
    built per queried callee (there are only a few per witness) and cached.
    """
    cache = getattr(g, "_callers_cache", None)
    if cache is None:
        cache = {}
        g._callers_cache = cache
    if callee in cache:
        return cache[callee]
    out = []
    for fstart, insns in g.precision.insns_by_func.items():
        for i, (addr, text) in enumerate(insns):
            mn, rest, _ops = _insn_parts(text)
            if mn != "call" or rest.startswith("*"):
                continue
            m = re.match(r"^([0-9a-f]+)", rest)
            if not m:
                continue
            if _containing(g, int(m.group(1), 16)) == callee:
                out.append((fstart, i, addr))
    cache[callee] = out
    return out


def _direct_call_index(g: "DsoGraph") -> dict:
    idx = getattr(g, "_direct_call_index_cache", None)
    if idx is not None:
        return idx
    idx = collections.defaultdict(list)
    for fstart, insns in g.precision.insns_by_func.items():
        for i, (addr, text) in enumerate(insns):
            mn, rest, _ops = _insn_parts(text)
            if mn != "call" or rest.startswith("*"):
                continue
            m = re.match(r"^([0-9a-f]+)", rest)
            if not m:
                continue
            target = _containing(g, int(m.group(1), 16))
            if target is not None:
                idx[target].append((fstart, i, addr))
    g._direct_call_index_cache = idx
    return idx


def _arg_origin_at_call(g: "DsoGraph", caller: int, call_idx: int, k: int):
    """Origin of argument ``k`` at a direct call, as a parameter or a refusal."""
    if k < len(_ARGREGS):
        return _param_of_operand(g, caller, call_idx, _ARGREGS[k])
    # Stack argument at entry offset 8 + 8*(k-6), expressed at this call.
    delta = _semantic_rsp_deltas(g, caller)[call_idx]
    if delta is None:
        return {"kind": "unknown", "why": "stack offset after rsp change"}
    abs_off = delta + 8 + 8 * (k - 6)
    writes = _reaching_stores(g, caller, call_idx, abs_off)
    if writes is None:
        return {"kind": "unknown", "why": "open stack argument"}
    if writes == {_NO_STORE}:
        return {"kind": "param", "index": k}
    if not writes or _NO_STORE in writes:
        return {"kind": "unknown", "why": "stack argument has several origins"}
    origins = []
    for wi in sorted(writes):
        _mn, _rest, ops = _insn_parts(_insn(g, caller, wi))
        if not ops or ops[0] not in _REGS:
            return {"kind": "unknown", "why": "stack argument has a writer"}
        origins.append(_reg_origin(g, caller, wi, _canon(ops[0])))
    if len(origins) == 1 and origins[0].get("kind") == "param":
        return origins[0]
    return {"kind": "unknown", "why": "stack argument has several origins"}


def _export_name(g: "DsoGraph", fstart: int):
    """The .dynsym name defining this exact function start, or None."""
    for n in (getattr(g, "names_at", {}) or {}).get(fstart, ()):
        base = (n or "").split("@")[0]
        if base and getattr(g, "dynamic_defs", {}).get(base) == fstart:
            return base
    name = (getattr(g, "funcs", {}) or {}).get(fstart)
    if name:
        base = name.split("@")[0]
        if getattr(g, "dynamic_defs", {}).get(base) == fstart:
            return base
    return None


# ---- source-backed header / source checks ------------------------------- #

def _header_texts(g: "DsoGraph"):
    root = _install_root(g)
    if root is None:
        return []
    hdr = Path(root) / "include" / "openssl"
    if not hdr.is_dir():
        return []
    cache = getattr(g, "_header_text_cache", None)
    if cache is not None:
        return cache
    out = []
    for path in sorted(hdr.glob("*.h")):
        try:
            out.append((path, path.read_text(errors="replace")))
        except OSError:
            continue
    g._header_text_cache = out
    return out


def _split_params(decl: str) -> list:
    start = decl.find("(")
    if start < 0:
        return []
    depth, cur, out = 0, [], []
    for ch in decl[start + 1:]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return [p for p in out if p and p != "void"]


def _header_callback_param(g: "DsoGraph", symbol: str, index: int):
    """The declared callback parameter, or a refusal string."""
    texts = _header_texts(g)
    if not texts:
        return None, "no admitted install headers"
    # Function typedefs: name -> (file, line, is_pointer).
    fntypes = {}
    for path, text in texts:
        for m in re.finditer(
                r"typedef\s+[^;{}]*?\(\s*\*\s*(\w+)\s*\)\s*\([^;{}]*\)\s*;",
                text):
            line = text.count("\n", 0, m.start()) + 1
            fntypes[m.group(1)] = (path.name, line, True)
        for m in re.finditer(
                r"typedef\s+[^;{}()]*?\b(\w+)\s*\([^;{}]*\)\s*;", text):
            line = text.count("\n", 0, m.start()) + 1
            fntypes.setdefault(m.group(1), (path.name, line, False))
    found = []
    for path, text in texts:
        for m in re.finditer(r"(?<![\w.])" + re.escape(symbol) + r"\s*\(", text):
            # A declaration is preceded by a return type on the same line.
            line_start = text.rfind("\n", 0, m.start()) + 1
            prefix = text[line_start:m.start()].strip()
            if not prefix or prefix.endswith(("=", ".", "->", ",")):
                continue
            depth, end = 0, None
            for off, ch in enumerate(text[m.start():]):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = m.start() + off + 1
                        break
            if end is None:
                continue
            decl = text[m.start():end]
            params = _split_params(decl)
            if index >= len(params):
                continue
            param = params[index]
            line = text.count("\n", 0, m.start()) + 1
            pname = None
            mm = re.search(r"\(\s*\*\s*(\w+)\s*\)", param)
            direct = bool(mm)
            if mm:
                pname = mm.group(1)
            else:
                ids = re.findall(r"[A-Za-z_]\w*", param)
                if len(ids) >= 2:
                    pname = ids[-1]
            ftype = None
            for name, info in fntypes.items():
                if re.search(r"\b" + re.escape(name) + r"\b", param):
                    ftype = (name, info)
                    break
            is_cb = direct or (ftype is not None
                               and ("*" in param or ftype[1][2]))
            found.append({
                "symbol": symbol, "index": index, "name": pname,
                "declaration": f"{path.name}:{line}",
                "parameter_text": " ".join(param.split()),
                "typedef": (f"{ftype[1][0]}:{ftype[1][1]}" if ftype else None),
                "type_typedef": (ftype[0] if ftype else None),
                "callback": is_cb,
            })
    if not found:
        return None, "the symbol is not declared in the admitted headers"
    cbs = [f for f in found if f["callback"]]
    non = [f for f in found if not f["callback"]]
    if non:
        return None, "a declaration does not declare the parameter as a callback"
    if not cbs:
        return None, "the header declares the parameter as a non-callback"
    if len({(c["type_typedef"], c["parameter_text"]) for c in cbs}) != 1:
        return None, "inconsistent callback declarations"
    return cbs[0], None


def _source_field_assignments(g: "DsoGraph", relpath: str, field: str):
    """Every ``.field = ...`` in one source file, with its enclosing function."""
    root = _repo_root(g)
    if root is None:
        return None, "source root unavailable"
    path = Path(root) / relpath
    if not path.is_file():
        return None, f"source file {relpath} is absent"
    cache = getattr(g, "_source_cache", None)
    if cache is None:
        cache = {}
        g._source_cache = cache
    key = (relpath, field)
    if key in cache:
        return cache[key]
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as e:
        return None, f"cannot read {relpath}: {e}"
    pat = re.compile(r"\." + re.escape(field) + r"\s*=")
    hits = []
    for i, line in enumerate(lines, 1):
        if not pat.search(line) or line.lstrip().startswith("//"):
            continue
        fn = None
        for j in range(i - 1, -1, -1):
            m = re.search(r"\bfn\s+(\w+)", lines[j])
            if m:
                fn = m.group(1)
                break
        hits.append({"line": i, "function": fn,
                     "text": line.strip()[:160]})
    out = (hits, None)
    cache[key] = out
    return out


# ---- S3: a fetched provider method-table slot --------------------------- #

def _fields(offsets, source_line):
    return {off: (field, fnid, source_line)
            for off, field, fnid in offsets}


FETCH_FAMILIES = (
    {
        "family": "EVP_KDF",
        "fetch": ("EVP_KDF_fetch", "evp_kdf_fetch_from_prov",
                  "inner_evp_generic_fetch"),
        "writer": ("evp_kdf_from_algorithm", "kdf_from_algorithm"),
        "object": "EvpKdf",
        "source_file": "src/evp/kdf.rs",
        "fields": {off: (field, fnid)
                   for off, field, fnid in (
                       (0x28, "newctx", "OSSL_FUNC_KDF_NEWCTX"),
                       (0x30, "dupctx", "OSSL_FUNC_KDF_DUPCTX"),
                       (0x38, "freectx", "OSSL_FUNC_KDF_FREECTX"),
                       (0x40, "reset", "OSSL_FUNC_KDF_RESET"),
                       (0x48, "derive", "OSSL_FUNC_KDF_DERIVE"),
                       (0x50, "gettable_params", "OSSL_FUNC_KDF_GETTABLE_PARAMS"),
                       (0x58, "gettable_ctx_params",
                        "OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS"),
                       (0x60, "settable_ctx_params",
                        "OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS"),
                       (0x68, "get_params", "OSSL_FUNC_KDF_GET_PARAMS"),
                       (0x70, "get_ctx_params", "OSSL_FUNC_KDF_GET_CTX_PARAMS"),
                       (0x78, "set_ctx_params", "OSSL_FUNC_KDF_SET_CTX_PARAMS"),
                       (0x80, "set_skey", "OSSL_FUNC_KDF_SET_SKEY"),
                       (0x88, "derive_skey", "OSSL_FUNC_KDF_DERIVE_SKEY"),
                   )},
        "interface": (
            "the provider's returned OSSL_DISPATCH table -- "
            "include/openssl/core.h:40-44 (function_id plus function pointer) "
            "and include/openssl/core_dispatch.h's OSSL_FUNC_kdf_* ids; "
            "src/evp/kdf.rs:209-244 is the #[repr(C)] EvpKdf the fetch builds"),
    },
    {
        "family": "EVP_MAC",
        "fetch": ("EVP_MAC_fetch", "evp_mac_fetch_from_prov",
                  "inner_evp_generic_fetch"),
        "writer": ("evp_mac_from_algorithm", "mac_from_algorithm"),
        "object": "EvpMac",
        "source_file": "src/evp/mac.rs",
        "fields": {off: (field, fnid)
                   for off, field, fnid in (
                       (0x28, "newctx", "OSSL_FUNC_MAC_NEWCTX"),
                       (0x30, "dupctx", "OSSL_FUNC_MAC_DUPCTX"),
                       (0x38, "freectx", "OSSL_FUNC_MAC_FREECTX"),
                       (0x40, "init", "OSSL_FUNC_MAC_INIT"),
                       (0x48, "update", "OSSL_FUNC_MAC_UPDATE"),
                       (0x50, "final", "OSSL_FUNC_MAC_FINAL"),
                       (0x58, "gettable_params", "OSSL_FUNC_MAC_GETTABLE_PARAMS"),
                       (0x60, "gettable_ctx_params",
                        "OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS"),
                       (0x68, "settable_ctx_params",
                        "OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS"),
                       (0x70, "get_params", "OSSL_FUNC_MAC_GET_PARAMS"),
                       (0x78, "get_ctx_params", "OSSL_FUNC_MAC_GET_CTX_PARAMS"),
                       (0x80, "set_ctx_params", "OSSL_FUNC_MAC_SET_CTX_PARAMS"),
                       (0x88, "init_skey", "OSSL_FUNC_MAC_INIT_SKEY"),
                   )},
        "interface": (
            "the provider's returned OSSL_DISPATCH table -- "
            "include/openssl/core.h:40-44 and core_dispatch.h's "
            "OSSL_FUNC_mac_* ids; src/evp/mac.rs:237-281 is the #[repr(C)] "
            "EvpMac the fetch builds"),
    },
    {
        "family": "EVP_KEM",
        "fetch": ("EVP_KEM_fetch", "evp_kem_fetch_from_prov",
                  "inner_evp_generic_fetch"),
        "writer": ("evp_kem_from_algorithm", "kem_from_algorithm"),
        "object": "EvpKem",
        "source_file": "src/evp/kem.rs",
        "fields": {off: (field, fnid)
                   for off, field, fnid in (
                       (0x28, "newctx", "OSSL_FUNC_KEM_NEWCTX"),
                       (0x30, "encapsulate_init", "OSSL_FUNC_KEM_ENCAPSULATE_INIT"),
                       (0x38, "encapsulate", "OSSL_FUNC_KEM_ENCAPSULATE"),
                       (0x40, "decapsulate_init", "OSSL_FUNC_KEM_DECAPSULATE_INIT"),
                       (0x48, "decapsulate", "OSSL_FUNC_KEM_DECAPSULATE"),
                       (0x50, "freectx", "OSSL_FUNC_KEM_FREECTX"),
                       (0x58, "dupctx", "OSSL_FUNC_KEM_DUPCTX"),
                       (0x60, "get_ctx_params", "OSSL_FUNC_KEM_GET_CTX_PARAMS"),
                       (0x68, "gettable_ctx_params",
                        "OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS"),
                       (0x70, "set_ctx_params", "OSSL_FUNC_KEM_SET_CTX_PARAMS"),
                       (0x78, "settable_ctx_params",
                        "OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS"),
                       (0x80, "auth_encapsulate_init",
                        "OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT"),
                       (0x88, "auth_decapsulate_init",
                        "OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT"),
                   )},
        "interface": (
            "the provider's returned OSSL_DISPATCH table -- "
            "include/openssl/core.h:40-44 and core_dispatch.h's "
            "OSSL_FUNC_kem_* ids; src/evp/kem.rs:155-196 is the #[repr(C)] "
            "EvpKem the fetch builds"),
    },
)


def _fetch_family_by_callee(name: str):
    for spec in FETCH_FAMILIES:
        if any(f in (name or "") for f in spec["fetch"][:2]):
            return spec
    return None


def _writer_reference(g: "DsoGraph", fstart: int, call_idx: int):
    """The family writer materialised before an inner_evp_generic_fetch call."""
    insns = g.precision.insns_by_func.get(fstart, ())
    refs = set()
    for k in range(call_idx - 1, max(-1, call_idx - 48), -1):
        text = insns[k][1]
        mn, _rest, _ops = _insn_parts(text)
        if mn.startswith("call"):
            break
        addr = _insn_comment_addr(text)
        if addr is None or addr not in g.start_set:
            continue
        nm = g.funcs.get(_containing(g, addr))
        if nm:
            refs.add((addr, nm))
    return sorted(refs)


def _base_fetch(g: "DsoGraph", fstart: int, idx: int, reg: str, depth=0):
    """The fetch call whose return is in ``reg`` at ``idx``, or a refusal.

    Returns ``(spec, fetch_index, evidence)``.  A merge is accepted only when
    every reaching definition is the same family fetch; anything else refuses.
    A zero definition is a NULL sentinel: a path that keeps it cannot reach the
    indirect call without faulting on the dereference that reads the slot, so
    it contributes no target to the call.
    """
    if depth > 4:
        return None, "provenance depth bound"
    defs = _reaching_defs(g, fstart, idx, reg)
    if defs is None:
        return None, "open or non-convergent CFG"
    if not defs or _ENTRY_DEF in defs:
        return None, "the base value is not defined in this function"
    out = []
    nulls = 0
    for k in sorted(defs):
        if k < 0:
            return None, "entry value reaches the base register"
        mn, _rest, ops = _insn_parts(_insn(g, fstart, k))
        if mn in ("xor", "sub") and len(ops) == 2 and ops[0] == ops[1]:
            nulls += 1
            continue
        if mn in ("mov", "movq") and ops and ops[0] == "$0x0":
            nulls += 1
            continue
        direct = _direct_call_target(g, fstart, k)
        if mn == "call" and direct is not None:
            cname = g.funcs.get(direct[1], "")
            if "inner_evp_generic_fetch" in cname:
                refs = _writer_reference(g, fstart, k)
                matched = [spec for spec in FETCH_FAMILIES
                           if any(any(w in (n or "") for w in spec["writer"])
                                  for a, n in refs)]
                if len(matched) != 1:
                    return None, ("the generic fetch's construct callback does not "
                                  "name exactly one family writer")
                spec = matched[0]
                matches = [(a, n) for a, n in refs
                           if any(w in (n or "") for w in spec["writer"])]
                out.append((spec, k, {"callee": cname,
                                      "construct": matches[0][1]}))
                continue
            spec = _fetch_family_by_callee(cname)
            if spec is None:
                return None, f"base is the return of {cname or hex(direct[0])}"
            out.append((spec, k, {"callee": cname}))
            continue
        if mn in ("mov", "movq") and ops and ops[-1] in _REGS + list(_SUBREG):
            src = ops[0]
            if src in _REGS or src in _SUBREG:
                sub_spec, sub_why = _base_fetch(g, fstart, k, _canon(src), depth + 1)
                if sub_spec is None:
                    return None, sub_why
                # A copy: the same fetch, one more provenance step.
                spec, fi, ev = sub_spec
                ev = dict(ev)
                ev["copy"] = {"addr": hex(g.precision.insns_by_func[fstart][k][0]),
                              "text": _insn(g, fstart, k)}
                out.append((spec, fi, ev))
                continue
            m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", src)
            if m:
                stack = _stack_param(g, fstart, k, src, None)
                if stack is not None:
                    return None, "the base is a stack parameter, not a fetch return"
                q = _stack_slot_abs(g, fstart, k, src)
                if q is None:
                    return None, "the base is a stack load with no frame offset"
                writes = _reaching_stores(g, fstart, k, q)
                if writes is None or len(writes) != 1 or _NO_STORE in writes:
                    return None, "the base stack slot has several writers"
                wi = next(iter(writes))
                _wmn, _wrest, wops = _insn_parts(_insn(g, fstart, wi))
                if not wops or wops[0] not in _REGS:
                    return None, "the base stack slot holds a non-register"
                sub_spec, sub_why = _base_fetch(
                    g, fstart, wi, _canon(wops[0]), depth + 1)
                if sub_spec is None:
                    return None, sub_why
                spec, fi, ev = sub_spec
                out.append((spec, fi, ev))
                continue
        return None, f"the base writer is {mn}, not a fetch result"
    specs = {o[0]["family"] for o in out}
    if not out:
        return None, "only NULL reaches the base register"
    if len(specs) != 1:
        return None, "the base merges different fetch families"
    spec, fi, ev = out[0]
    if nulls:
        ev = dict(ev)
        ev["null_paths"] = nulls
    return (spec, fi, ev), None


def fetch_slot_witness(g: "DsoGraph", site: dict, name: str):
    """Witness for an in-image EVP method object's provider-dispatch slot.

    The slot must be a field of the object the family fetch returns, and the
    field must be the one the documented OSSL_FUNC_* id fills.  The writer is
    checked against the source: exactly one assignment in the family file, in
    the family's from_algorithm function.
    """
    if site.get("kind") not in ("call", "jmp"):
        return None
    if not _has_insns(g):
        return None
    fstart = site["func"]
    idx = None
    for i, (a, _t) in enumerate(g.precision.insns_by_func.get(fstart, ())):
        if a == site["addr"]:
            idx = i
            break
    if idx is None:
        return None
    opnd = _site_operand(site)
    member_offset = None
    base_reg = None
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
    if m:
        member_offset = int(m.group(1), 16) if m.group(1) else 0
        base_reg = m.group(2)
        base_at = idx
    elif opnd in _REGS or opnd in _SUBREG:
        reg = _canon(opnd)
        origin = _reg_origin(g, fstart, idx, reg)
        if origin.get("kind") != "load":
            return None
        member_offset = origin["offset"]
        base_reg = origin["base_reg"]
        base_at = origin["at"]
    else:
        return None
    base_result, why = _base_fetch(g, fstart, base_at, _canon(base_reg))
    if base_result is None:
        if "fetch-base-not-return" in _MUTED:
            base_result = (FETCH_FAMILIES[0], idx,
                           {"callee": "mutation-forced"})
        else:
            return None
    spec, fetch_idx, fetch_ev = base_result
    fields = spec["fields"]
    slot_fields = fields.get(member_offset)
    if slot_fields is None:
        if "fetch-slot-outside" in _MUTED:
            slot_fields = ("forced_field", "forced_id")
        else:
            return None
    field, fnid = slot_fields
    hits, src_why = _source_field_assignments(g, spec["source_file"], field)
    bad_writer = (hits is None or len(hits) != 1
                  or not any(w in ((hits[0]["function"] or "")
                                   if hits else "") for w in spec["writer"]))
    if bad_writer:
        if "fetch-source-writer" in _MUTED:
            hits = hits or [{"line": 0, "function": spec["writer"][0],
                             "text": "mutation-forced"}]
        else:
            return None
    writer_fn = hits[0]["function"] or ""
    fetch_addr = g.precision.insns_by_func[fstart][fetch_idx][0]
    return {
        "schema": WITNESS_SCHEMA,
        "class": ABI_CONTRACT_PROVIDER,
        "contract_bounded": True,
        "function": name,
        "call_site": hex(site["addr"]),
        "operand": {"member_offset": hex(member_offset),
                    "base_reg": _canon(base_reg)},
        "fetch": {
            "caller": name,
            "call_site": hex(fetch_addr),
            "callee": fetch_ev.get("callee"),
            "construct": fetch_ev.get("construct"),
            "method_family": spec["family"],
        },
        "object_slot": {
            "object_offset": hex(member_offset),
            "object": spec["object"],
            "field": field,
            "function_id": fnid,
        },
        "writer": (
            f"{spec['source_file']}:{hits[0]['line']} in {writer_fn}: "
            f"{hits[0]['text']}"),
        "writer_sites": [{"file": spec["source_file"],
                          "line": hits[0]["line"],
                          "function": writer_fn,
                          "text": hits[0]["text"]}],
        "interface": spec["interface"],
        "basis": (
            "the indirect operand reads exactly this #[repr(C)] field of the "
            "object the family fetch returns; the field is assigned exactly "
            "once in the image, from the OSSL_DISPATCH entry the function id "
            "names"),
        "slot": (f"{spec['object']}.{field} (offset {member_offset:#x}, "
                 f"{fnid})"),
    }


# ---- S2: an exported function's callback parameter ---------------------- #


def export_callback_witness(g: "DsoGraph", site: dict, name: str):
    """Witness for a callback that is exactly an exported parameter.

    Returns ``(witness, refusal)``; a refusal may set ``defer`` so the caller
    records the mandatory deferral to reachable-caller-target rather than
    absorbing a finite in-image callback.  A value is accepted only when every
    in-image call chain forwards the same parameter to an exported entry point.
    """
    if site.get("kind") not in ("call", "jmp"):
        return None, None
    if not _has_insns(g):
        return None, None
    fstart = site["func"]
    idx = None
    for i, (a, _t) in enumerate(g.precision.insns_by_func.get(fstart, ())):
        if a == site["addr"]:
            idx = i
            break
    if idx is None:
        return None, None
    opnd = _site_operand(site)
    param = _param_of_operand(g, fstart, idx, opnd)
    if param is None or param.get("kind") != "param":
        if "export-not-param" in _MUTED:
            param = {"kind": "param", "index": 3, "provenance": []}
        else:
            return None, None
    index = param["index"]

    export = _export_name(g, fstart)
    chain = []
    roots = set()
    in_image = []
    seen = set()
    frontier = [(fstart, index)]
    while frontier:
        fn, k = frontier.pop()
        if (fn, k) in seen:
            continue
        seen.add((fn, k))
        ex = _export_name(g, fn)
        if ex is not None:
            roots.add((ex, k))
            continue
        callers = _callers_of(g, fn)
        if not callers:
            # A private function reached only through a table or an indirect
            # call: its caller is not enumerable here.  It is recorded, never
            # treated as a fixed value.
            in_image.append({"function": g.funcs.get(fn), "param": k,
                             "reason": "no in-image direct caller"})
            continue
        for caller, ci, _addr in callers:
            origin = _arg_origin_at_call(g, caller, ci, k)
            if origin.get("kind") != "param":
                in_image.append({"function": g.funcs.get(caller),
                                 "call_site": hex(_addr),
                                 "reason": "passes a non-parameter value",
                                 "origin": origin.get("kind")})
                continue
            chain.append({"callee": g.funcs.get(fn),
                          "callee_param": k,
                          "caller": g.funcs.get(caller),
                          "caller_param": origin["index"],
                          "call_site": hex(_addr)})
            frontier.append((caller, origin["index"]))
    if not roots:
        if "export-no-root" in _MUTED:
            roots.add(("CRYPTO_cfb128_encrypt", index))
        else:
            return None, {"defer": True,
                          "refusal": "no exported entry point receives the "
                                     "parameter; the callers are in-image and "
                                     "finite",
                          "in_image_callers": in_image}
    root_indices = {k for _s, k in roots}
    if len(root_indices) != 1:
        return None, {"refusal": "exported entry points disagree on the parameter"}
    root_index = next(iter(root_indices))
    parsed = []
    for symbol in sorted(s for s, _k in roots):
        cb, why = _header_callback_param(g, symbol, root_index)
        if cb is None:
            if "export-header-non-callback" in _MUTED:
                cb = {"symbol": symbol, "index": root_index, "name": "forced",
                      "declaration": "forced:0", "parameter_text": "forced",
                      "typedef": "forced:0", "type_typedef": "forced",
                      "callback": True}
            else:
                return None, {"refusal": f"{symbol}: {why}"}
        parsed.append((symbol, cb))
    if len({(c["type_typedef"], c["parameter_text"]) for _s, c in parsed}) != 1:
        return None, {"refusal": "exported declarations disagree on the callback"}
    symbol, cb = parsed[0]
    witness = {
        "schema": WITNESS_SCHEMA,
        "class": ABI_CONTRACT_EXPORT_CALLBACK,
        "contract_bounded": True,
        "function": name,
        "call_site": hex(site["addr"]),
        "operand": {"kind": "reg" if opnd.startswith("%") else "memory",
                    "text": opnd},
        "parameter": {
            "name": cb["name"],
            "index": root_index,
            "declaration": cb["declaration"],
            "type_typedef": cb["type_typedef"],
            "typedef_declaration": cb["typedef"],
            "parameter_text": cb["parameter_text"],
        },
        "site_parameter": index,
        "export": {"symbol": symbol, "in_dynsym": True,
                   "symbols": sorted(s for s, _k in roots)},
        "provenance": param.get("provenance") or [],
        "caller_chain": chain,
        "in_image_callers": in_image,
        "caller_boundary": ("external application; the target set is unbounded "
                            "by the C ABI"),
        "does_not_cover": [
            "NULL where the header does not admit it -- a C-invalid input",
            "the behaviour or lifetime of the application's callback",
            "which callback an external caller supplies",
        ],
        "slot": (f"{symbol} parameter {root_index} ({cb['name']})"),
        "writer": (
            "the caller supplies the value at the exported C ABI boundary; "
            "no in-image writer stores a different value into the parameter"),
        "interface": (f"{cb['declaration']} declares {cb['name']} as "
                      f"{cb['type_typedef']} ({cb['typedef']})"),
        "basis": ("the operand is exactly this entry parameter (single linear "
                  "provenance), every in-image call chain forwards it "
                  "unchanged, and the root function is in .dynsym"),
    }
    return witness, None


# ---- S4: a local function pointer with a finite assignment set ---------- #

def _prologue_delta(g: "DsoGraph", fstart: int):
    """Entry-relative rsp delta established by the prologue.

    Used only when the CFG's rsp dataflow has a merge conflict (for example a
    switch tail-call): the compiler's prologue is still a fixed frame, and the
    query is a slot in a block that has not run an epilogue.
    """
    cache = getattr(g, "_prologue_delta_cache", None)
    if cache is None:
        cache = {}
        g._prologue_delta_cache = cache
    if fstart in cache:
        return cache[fstart]
    cur = 0
    for _a, text in g.precision.insns_by_func.get(fstart, ()):
        mn, _rest, ops = _insn_parts(text)
        if mn == "push":
            cur -= 8
        elif mn == "pop":
            cur += 8
        elif mn in ("sub", "add") and len(ops) == 2 and ops[1] == "%rsp" \
                and ops[0].startswith("$"):
            try:
                n = int(ops[0][1:], 16)
            except ValueError:
                break
            cur = cur - n if mn == "sub" else cur + n
        elif mn.startswith(("cmp", "test", "j", "call", "ret", "iret", "ud2")):
            break
    cache[fstart] = cur
    return cur


def _frame_abs(g: "DsoGraph", fstart: int, idx: int, off: int, base: str):
    if base == "%rsp":
        deltas = _semantic_rsp_deltas(g, fstart)
        delta = deltas[idx] if idx < len(deltas) else None
        if delta is None:
            delta = _prologue_delta(g, fstart)
        return None if delta is None else delta + off
    if base == "%rbp":
        frame = _semantic_frame_base(g, fstart)
        return None if frame is None else frame[1] + off
    return None


def _stack_load_origin(g: "DsoGraph", fstart: int, idx: int, reg: str, depth=0):
    """Origin of a register, following a spill/reload through one frame slot."""
    if depth > 4:
        return {"kind": "unknown", "why": "stack provenance depth bound"}
    origin = _reg_origin(g, fstart, idx, reg)
    if origin.get("kind") != "load" or origin.get("base_reg") not in ("%rsp", "%rbp"):
        return origin
    off = _frame_abs(g, fstart, origin["at"], origin["offset"], origin["base_reg"])
    if off is None:
        return {"kind": "unknown", "why": "frame offset after rsp change"}
    writes = _reaching_stores(g, fstart, idx, off)
    if writes is None or len(writes) != 1 or _NO_STORE in writes:
        return {"kind": "unknown", "why": "frame slot has several writers"}
    wi = next(iter(writes))
    _mn, _rest, wops = _insn_parts(_insn(g, fstart, wi))
    if not wops or wops[0] not in _REGS:
        return {"kind": "unknown", "why": "frame slot holds a non-register"}
    return _stack_load_origin(g, fstart, wi, _canon(wops[0]), depth + 1)


def _lea_frame_offsets(g: "DsoGraph", fstart: int, idx: int, src: str):
    """Frame slots a ``lea`` store source can denote (one distinct offset)."""
    if src not in _REGS and src not in _SUBREG:
        return None
    defs = _reaching_defs(g, fstart, idx, _canon(src))
    if defs is None or not defs or _ENTRY_DEF in defs:
        return None
    out = set()
    for d in defs:
        mn, _rest, ops = _insn_parts(_insn(g, fstart, d))
        if mn != "lea" or not ops:
            return None
        off = _stack_slot_abs(g, fstart, d, ops[0])
        if off is None:
            return None
        out.add(off)
    return out if len(out) == 1 else None


def _lea_functions(g: "DsoGraph", fstart: int, idx: int, src: str):
    """Function starts a store source can denote; a partial set refuses."""
    if src not in _REGS and src not in _SUBREG:
        return None
    defs = _reaching_defs(g, fstart, idx, _canon(src))
    if defs is None or not defs or _ENTRY_DEF in defs:
        return None
    out = set()
    for d in defs:
        mn, _rest, ops = _insn_parts(_insn(g, fstart, d))
        if mn != "lea" or not ops:
            return None
        taddr = _insn_comment_addr(_insn(g, fstart, d))
        if taddr is None or taddr not in g.start_set:
            return None
        out.add((taddr, d))
    return out or None


def _lea_frame_offset(g: "DsoGraph", fstart: int, idx: int, src: str):
    if src not in _REGS and src not in _SUBREG:
        return None
    d = _single_def(g, fstart, idx, _canon(src))
    if d is None:
        return None
    mn, _rest, ops = _insn_parts(_insn(g, fstart, d))
    if mn != "lea" or not ops:
        return None
    return _stack_slot_abs(g, fstart, d, ops[0])


def _lea_function(g: "DsoGraph", fstart: int, idx: int, src: str):
    if src not in _REGS and src not in _SUBREG:
        return None
    d = _single_def(g, fstart, idx, _canon(src))
    if d is None:
        return None
    mn, _rest, ops = _insn_parts(_insn(g, fstart, d))
    if mn != "lea" or not ops:
        return None
    taddr = _insn_comment_addr(_insn(g, fstart, d))
    if taddr is None or taddr not in g.start_set:
        return None
    return (taddr, d)


def local_fptr_witness(g: "DsoGraph", site: dict, name: str):
    """Resolve a call through a closure/slot built from a finite address set.

    Shape: ``call *0(reg)`` where ``reg`` is loaded from a pointer parameter
    and every in-image caller builds the pointed-to slot from a finite set of
    ``lea <function>`` stores.  The slot may be reached through one extra
    pointer (a Rust closure passed by reference).  Every stored value must be
    a function start and every writer must be accounted for; a partial set is
    refused, never unioned.
    """
    if site.get("kind") != "call":
        return None
    if not _has_insns(g):
        return None
    fstart = site["func"]
    idx = None
    for i, (a, _t) in enumerate(g.precision.insns_by_func.get(fstart, ())):
        if a == site["addr"]:
            idx = i
            break
    if idx is None:
        return None
    opnd = _site_operand(site)
    m = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", opnd)
    if not m:
        return None
    field_off = int(m.group(1), 16) if m.group(1) else 0
    origin = _stack_load_origin(g, fstart, idx, _canon(m.group(2)))
    if origin.get("kind") != "load":
        return None
    base_reg = origin["base_reg"]
    base_origin = _stack_load_origin(g, fstart, origin["at"], _canon(base_reg))
    outer_off = origin["offset"]
    if base_origin.get("kind") == "param":
        k = base_origin["index"]
    elif base_origin.get("kind") == "load":
        # One more object level: [param] holds the pointer that is read.
        sub = _stack_load_origin(g, fstart, base_origin["at"],
                                 _canon(base_origin["base_reg"]))
        if sub.get("kind") != "param":
            return None
        k = sub["index"]
        outer_off += base_origin["offset"]
    else:
        return None
    callers = _callers_of(g, fstart)
    if not callers:
        return None
    targets = set()
    assignments = []
    for caller, ci, _addr in callers:
        if k >= len(_ARGREGS):
            return None
        origin_arg = _reg_origin(g, caller, ci, _ARGREGS[k])
        if origin_arg.get("kind") != "load":
            # A forwarded parameter would need its own caller chain; this
            # mechanism resolves a locally built closure only.
            return None
        if origin_arg.get("base_reg") not in ("%rsp", "%rbp"):
            return None
        amn, _arest, _aops = _insn_parts(
            _insn(g, caller, origin_arg["at"]))
        if amn != "lea":
            return None
        arg_slot = _frame_abs(g, caller, origin_arg["at"],
                              origin_arg["offset"], origin_arg["base_reg"])
        if arg_slot is None:
            return None
        slot = arg_slot + outer_off
        if _slot_alias_in_block(g, caller, ci, slot, {origin_arg["at"]}):
            return None
        wset = _reaching_stores(g, caller, ci, slot)
        if wset is None or _NO_STORE in wset:
            return None
        stores = sorted(wset)
        if not stores:
            return None
        direct, pointer = set(), set()
        for si in stores:
            _smn, _srest, sops = _insn_parts(_insn(g, caller, si))
            src = sops[0] if sops else ""
            if src not in _REGS:
                return None
            fns = _lea_functions(g, caller, si, src)
            if fns:
                for taddr, lea_i in fns:
                    direct.add((taddr, si, lea_i))
                continue
            ptrs = _lea_frame_offsets(g, caller, si, src)
            if not ptrs:
                if "local-non-function" in _MUTED:
                    continue
                return None
            pointer |= ptrs
        if direct and pointer:
            return None
        caller_targets = set()
        for taddr, store_i, lea_i in sorted(direct):
            caller_targets.add(taddr)
            assignments.append({
                "caller": g.funcs.get(caller),
                "store": hex(g.precision.insns_by_func[caller][store_i][0]),
                "assignment": hex(g.precision.insns_by_func[caller][lea_i][0]),
                "target": hex(taddr),
                "target_symbol": g.funcs.get(taddr),
            })
        for inner in sorted(pointer):
            inner_slot = inner + field_off
            iset = _reaching_stores(g, caller, ci, inner_slot)
            if iset is None or _NO_STORE in iset:
                return None
            istores = sorted(iset)
            if not istores:
                return None
            for si in istores:
                _imn, _irest, iops = _insn_parts(_insn(g, caller, si))
                src = iops[0] if iops else ""
                if src not in _REGS:
                    return None
                fns = _lea_functions(g, caller, si, src)
                if not fns:
                    if "local-non-function" in _MUTED:
                        continue
                    return None
                for taddr, lea_i in fns:
                    caller_targets.add(taddr)
                    assignments.append({
                        "caller": g.funcs.get(caller),
                        "store": hex(g.precision.insns_by_func[caller][si][0]),
                        "assignment": hex(g.precision.insns_by_func[caller][lea_i][0]),
                        "target": hex(taddr),
                        "target_symbol": g.funcs.get(taddr),
                    })
        targets |= caller_targets
    if (not targets or not targets <= g.start_set) \
            and "local-non-function" not in _MUTED:
        return None
    return {
        "schema": "openssl-rs/consumer-closure/local-function-pointer/v1",
        "class": "local-function-pointer",
        "contract_bounded": False,
        "function": name,
        "call_site": hex(site["addr"]),
        "slot": (f"closure field {field_off:#x} reached through parameter "
                 f"{k} and a frame address"),
        "assignments": assignments,
        "targets": [hex(t) for t in sorted(targets)],
        "no_other_write": True,
        "basis": ("every in-image caller builds the slot from a finite set of "
                  "in-image function addresses and no other store reaches it; "
                  "all stored addresses are function starts"),
    }


# ---- S1: field-sensitive static-table instance dispatch ----------------- #
#
# Design note (AGENTS.md sections 7, 8, 10 and 22).
#
# The residual this class addresses is an indirect call through a *table
# member* selected from a *pointer field of an object* whose pointer field is
# written from a finite set of static tables.  The existing resolver records
# global stores keyed by displacement only (``field_stores``); in this DSO
# offset 0x8 alone has thousands of stores, so an offset-keyed completeness
# claim is impossible.  S1 therefore uses the field-sensitive points-to
# discipline: a store belongs to the key
#
#       (object type T, pointer-slot offset o, member offset m)
#
# only when T is established from the source signature (or the source cast that
# introduces the context), o is established from the load that produces the
# call's base register, and m is the member read by the call.  Each key has its
# own writer set, which is restricted by the static dispatch table that pairs
# the consumer with its constructor.  This is the type-qualified partitioning
# of Andersen-style constraints discussed by Diwan/McKinley/Moss ("Type-based
# alias analysis", 1998); no stronger claim is made here.
#
# The dispatch table gives the constructor pairing without a whole-program
# field store database: an ``OsslDispatch`` table is an immutable array of
# (function_id, pointer) entries, and the provider ABI pairs
# OSSL_FUNC_CIPHER_NEWCTX with the cipher entry that consumes the context.  The
# site function must be a table entry target or in the direct-call closure of
# one; the writer set is the NEWCTX entry's direct-call closure; every other
# cohort entry is checked for a store to the same field and refuses the site if
# it stores anything else.  A reachable direct caller outside the cohort also
# refuses the site (the context could have come from another constructor).
#
# The base object is first qualified as the function's declared context
# parameter: the entry argument, a whole-register copy chain, or a reload from
# a frame slot whose every reaching store is that same parameter.  Every
# reaching definition must agree; branches are never unioned into a may-alias.
#
# Refusals are conjunctions, never unions: any one failure leaves the site
# target-bounded.  A partially enumerated instance set is never unioned.

S1_WITNESS_SCHEMA = "openssl-rs/consumer-closure/static-table-instance/v1"
S1_IMMUTABLE_SECTIONS = (".data.rel.ro", ".data.rel.ro.local", ".rodata")
_S1_SOURCE_SUFFIX = ".rs"


def _s1_docs(g: "DsoGraph"):
    """Every tracked source file, read once per candidate image."""
    cache = getattr(g, "_s1_docs_cache", None)
    if cache is not None:
        return cache
    docs = {}
    root = _repo_root(g)
    if root is not None:
        for path in sorted((root / "src").rglob("*" + _S1_SOURCE_SUFFIX)):
            try:
                docs[path.relative_to(root).as_posix()] = path.read_text(
                    errors="replace")
            except OSError:
                continue
    g._s1_docs_cache = docs
    return docs


def _s1_brace_span(text: str, open_at: int):
    """End index of the ``{...}`` starting at ``open_at``, or None."""
    if open_at < 0 or open_at >= len(text) or text[open_at] != "{":
        return None
    depth, i, n = 0, open_at, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _s1_struct_defs(g: "DsoGraph", type_name: str):
    """All ``struct type_name`` definitions, with their repr(C) status."""
    cache = getattr(g, "_s1_struct_cache", None)
    if cache is None:
        cache = {}
        g._s1_struct_cache = cache
    key = ("defs", type_name)
    if key in cache:
        return cache[key]
    pat = re.compile(
        r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?struct\s+"
        + re.escape(type_name) + r"\b")
    out = []
    for path, text in _s1_docs(g).items():
        for m in pat.finditer(text):
            brace = text.find("{", m.end())
            if brace < 0:
                continue
            # A tuple/unit struct has ``;`` before the body brace.
            semi = text.find(";", m.end(), brace)
            if semi >= 0:
                continue
            end = _s1_brace_span(text, brace)
            if end is None:
                continue
            prefix = text[max(0, m.start() - 600):m.start()]
            out.append({
                "file": path,
                "line": text.count("\n", 0, m.start()) + 1,
                "body": text[brace + 1:end - 1],
                "repr_c": bool(re.search(r"#\[repr\s*\(\s*C\b", prefix)),
            })
    cache[key] = out
    return out


def _s1_strip_field(chunk: str):
    chunk = re.sub(r"(?m)^\s*///.*$", "", chunk)
    chunk = re.sub(r"(?m)^\s*//!.*$", "", chunk)
    chunk = re.sub(r"/\*.*?\*/", "", chunk, flags=re.S)
    chunk = re.sub(r"(?m)^\s*//.*$", "", chunk)
    chunk = re.sub(r"#\[[^\]]*\]", "", chunk)
    return chunk.strip()


def _s1_split_fields(body: str):
    """Top-level comma split of a repr(C) struct body."""
    chunks, cur = [], []
    depth = 0
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "/" and i + 1 < n and body[i + 1] == "/":
            j = body.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and body[i + 1] == "*":
            j = body.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            chunks.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        chunks.append("".join(cur))
    out = []
    for chunk in chunks:
        text = _s1_strip_field(chunk)
        if not text:
            continue
        m = re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?"
                     r"([A-Za-z_]\w*)\s*:\s*(.+)$", text, re.S)
        if not m:
            continue
        out.append((m.group(1), " ".join(m.group(2).split())))
    return out


def _s1_struct_fields(g: "DsoGraph", type_name: str):
    """Field list of the unique repr(C) definition, or None."""
    defs = _s1_struct_defs(g, type_name)
    repr_defs = [d for d in defs if d["repr_c"]]
    if len(repr_defs) != 1:
        return None
    fields = _s1_split_fields(repr_defs[0]["body"])
    return (fields, repr_defs[0]) if fields else None


def _s1_type_alias(g: "DsoGraph", name: str):
    cache = getattr(g, "_s1_alias_cache", None)
    if cache is None:
        cache = {}
        g._s1_alias_cache = cache
    if name in cache:
        return cache[name]
    pat = re.compile(r"\btype\s+" + re.escape(name) + r"\s*=\s*([^;]+);")
    hits = set()
    for _path, text in _s1_docs(g).items():
        for m in pat.finditer(text):
            hits.add(" ".join(m.group(1).split()))
    cache[name] = hits.pop() if len(hits) == 1 else None
    return cache[name]


_S1_CONST_SCALAR = r"(?:usize|isize|u8|u16|u32|u64|i8|i16|i32|i64|size_t)"


def _s1_const_exprs(g: "DsoGraph"):
    """Source integer constants, by name, when the definition is unique.

    A struct layout is decidable only when every field size is.  Array
    lengths are frequently written as a constant expression
    (``[u8; 4 * SLH_DSA_MAX_N]``), which the literal-only rule could not
    evaluate; the same source documents that give the field types also give
    the constants.  A name defined more than once with different text is
    ambiguous and is not evaluated.
    """
    cache = getattr(g, "_s1_const_cache", None)
    if cache is not None:
        return cache
    hits = {}
    pat = re.compile(
        r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?const\s+"
        r"([A-Za-z_]\w*)\s*:\s*" + _S1_CONST_SCALAR + r"\s*=\s*([^;]+);")
    for _path, text in _s1_docs(g).items():
        for m in pat.finditer(text):
            hits.setdefault(m.group(1), set()).add(
                " ".join(m.group(2).split()))
    out = {name: next(iter(vals)) if len(vals) == 1 else None
           for name, vals in hits.items()}
    g._s1_const_cache = out
    return out


def _s1_eval_int(g: "DsoGraph", expr: str, seen=()):
    """Evaluate a source integer expression, or None.

    Only integer literals, previously resolved constants, parentheses and
    ``+ - * / %`` are accepted.  Division must be exact, so a platform or
    compiler difference cannot silently change an array length.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError):
        return None

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return _s1_const_value(g, node.id, seen)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            val = ev(node.operand)
            return -val if val is not None else None
        if isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div,
                          ast.FloorDiv, ast.Mod)):
            left, right = ev(node.left), ev(node.right)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if right == 0:
                return None
            if isinstance(node.op, ast.Mod):
                return left % right
            if left % right != 0:
                return None
            return left // right
        return None

    value = ev(tree)
    return value if isinstance(value, int) and value >= 0 else None


def _s1_const_value(g: "DsoGraph", name: str, seen=frozenset()):
    if name in seen:
        return None
    expr = _s1_const_exprs(g).get(name)
    if expr is None:
        return None
    return _s1_eval_int(g, expr, frozenset(seen) | {name})


def _s1_type_size(g: "DsoGraph", type_text: str, seen=()):
    """(size, alignment) of a repr(C) field type, or None if not decidable."""
    t = " ".join((type_text or "").split())
    if not t:
        return None
    if t.startswith("Option<") and t.endswith(">"):
        inner = t[len("Option<"):-1].strip()
        if "fn" in inner:
            return (8, 8)
        return None
    if "fn" in t:
        return (8, 8)
    if t.startswith("*const") or t.startswith("*mut"):
        return (8, 8)
    prim = {
        "usize": (8, 8), "isize": (8, 8), "size_t": (8, 8),
        "ssize_t": (8, 8), "u64": (8, 8), "i64": (8, 8),
        "uint64_t": (8, 8), "int64_t": (8, 8), "c_ulong": (8, 8),
        "c_long": (8, 8), "c_uint": (4, 4), "c_int": (4, 4),
        "u32": (4, 4), "i32": (4, 4), "uint32_t": (4, 4),
        "int32_t": (4, 4), "c_ushort": (2, 2), "u16": (2, 2),
        "c_short": (2, 2), "c_uchar": (1, 1), "u8": (1, 1),
        "i8": (1, 1), "c_char": (1, 1),
    }
    if t in prim:
        return prim[t]
    m = re.fullmatch(r"\[(.+);\s*([^\]]+)\]", t)
    if m:
        inner = _s1_type_size(g, m.group(1), seen)
        count_text = m.group(2).strip()
        try:
            count = int(count_text, 0)
        except ValueError:
            count = _s1_eval_int(g, count_text)
            if count is None:
                return None
        if inner is None:
            return None
        return (inner[0] * count, inner[1])
    alias = _s1_type_alias(g, t)
    if alias is not None and alias != t:
        return _s1_type_size(g, alias, seen + (t,))
    nested = _s1_struct_layout(g, t, seen)
    if nested is None:
        return None
    return (nested["size"], nested["align"])


def _s1_struct_layout(g: "DsoGraph", type_name: str, seen=()):
    """Repr(C) layout of a source struct, or None."""
    if type_name in seen or len(seen) > 6:
        return None
    cache = getattr(g, "_s1_layout_cache", None)
    if cache is None:
        cache = {}
        g._s1_layout_cache = cache
    if type_name in cache:
        return cache[type_name]
    defs = _s1_struct_defs(g, type_name)
    if len(defs) != 1:
        cache[type_name] = None
        return None
    fields = _s1_split_fields(defs[0]["body"])
    if not fields:
        cache[type_name] = None
        return None
    infos = []
    for name, ftype in fields:
        info = _s1_type_size(g, ftype, seen + (type_name,))
        if info is None:
            cache[type_name] = None
            return None
        size, falign = info
        if falign <= 0 or falign & (falign - 1):
            cache[type_name] = None
            return None
        infos.append((name, ftype, size, falign))
    # A table struct without repr(C) is still layout-stable when every field
    # has the same size and alignment: the offset *set* is then independent of
    # field order.  Member *names* are recorded only for repr(C) because the
    # compiler may reorder other structs.
    homogeneous = (len({(s, a) for _n, _t, s, a in infos}) == 1
                   and infos[0][2] == infos[0][3])
    if not defs[0]["repr_c"] and not homogeneous:
        cache[type_name] = None
        return None
    off, align = 0, 1
    rows = []
    for name, ftype, size, falign in infos:
        off = (off + falign - 1) // falign * falign
        rows.append({
            "offset": off, "name": name, "type": ftype,
            "option": ftype.startswith("Option<"),
            "named": defs[0]["repr_c"],
        })
        off += size
        align = max(align, falign)
    size = (off + align - 1) // align * align
    out = {"name": type_name, "size": size, "align": align,
           "fields": rows, "file": defs[0]["file"],
           "line": defs[0]["line"],
           "repr_c": defs[0]["repr_c"],
           "homogeneous": homogeneous}
    cache[type_name] = out
    return out


def _s1_src_fn(g: "DsoGraph", relpath: str, fn_name: str):
    """Header/body span of one source function, or None."""
    cache = getattr(g, "_s1_fn_cache", None)
    if cache is None:
        cache = {}
        g._s1_fn_cache = cache
    key = (relpath, fn_name)
    if key in cache:
        return cache[key]
    text = _s1_docs(g).get(relpath)
    if text is None:
        cache[key] = None
        return None
    pat = re.compile(r"\bfn\s+" + re.escape(fn_name) + r"\s*\(")
    hits = []
    for m in pat.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line = text[line_start:m.start()].strip()
        if line.startswith("///") or line.startswith("//"):
            continue
        open_paren = text.find("(", m.end() - 1)
        depth, i = 0, open_paren
        close_paren = None
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    close_paren = i
                    break
            i += 1
        if close_paren is None:
            continue
        brace = text.find("{", close_paren)
        if brace < 0:
            continue
        # A ``;`` before the brace means a declaration, not a definition.
        if text.find(";", close_paren, brace) >= 0:
            continue
        end = _s1_brace_span(text, brace)
        if end is None:
            continue
        hits.append({
            "file": relpath,
            "line": text.count("\n", 0, m.start()) + 1,
            "header": text[m.start():brace + 1],
            "body": text[brace + 1:end - 1],
        })
    out = hits[0] if len(hits) == 1 else None
    cache[key] = out
    return out


def _s1_demangled(g: "DsoGraph", fstart: int):
    cache = getattr(g, "_s1_demangle_cache", None)
    if cache is None:
        cache = {}
        g._s1_demangle_cache = cache
    if fstart in cache:
        return cache[fstart]
    mangled = (getattr(g, "funcs", {}) or {}).get(fstart)
    dm = None
    if mangled:
        lines = demangle([mangled])
        dm = lines[0] if lines else None
    cache[fstart] = dm
    return dm


def _s1_site_context(g: "DsoGraph", fstart: int):
    """(source file, function name, context type) for the site function."""
    cache = getattr(g, "_s1_ctx_cache", None)
    if cache is None:
        cache = {}
        g._s1_ctx_cache = cache
    if fstart in cache:
        return cache[fstart]
    dm = _s1_demangled(g, fstart)
    out = None
    if dm:
        m = CRATE_NS.match(dm)
        if m:
            segs = m.group(1).split("::")
            if len(segs) >= 2:
                root = _repo_root(g)
                fn_name = segs[-1]
                relpath = None
                if root is not None:
                    fallback = getattr(g, "_s1_module_index", None)
                    if fallback is None:
                        fallback = build_module_index(root / "src")
                        g._s1_module_index = fallback
                    relpath = module_to_file("::".join(segs[:-1]),
                                             root / "src", fallback)
                if relpath:
                    span = _s1_src_fn(g, relpath, fn_name)
                    if span is not None:
                        ctx = _s1_fn_context(span, fn_name)
                        if ctx is not None and ctx.get("type") is None:
                            ctx = _s1_inlined_fn_context(g, span,
                                                         ctx.get("param"))
                        if ctx is not None and ctx.get("type"):
                            out = {"file": relpath, "function": fn_name,
                                   "line": span["line"], **ctx}
    cache[fstart] = out
    return out


def _s1_fn_context(span: dict, fn_name: str):
    """The context parameter of a source function and its declared type."""
    header = span["header"]
    m = re.search(r"\(", header)
    if not m:
        return None
    depth, i = 0, m.start()
    end = None
    while i < len(header):
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    if end is None:
        return None
    params, cur, depth = [], [], 0
    for ch in header[m.start() + 1:end]:
        if ch in "([<":
            depth += 1
        elif ch in ")]>:":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            params.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        params.append("".join(cur).strip())
    if not params:
        return None
    first = params[0]
    mm = re.match(r"([A-Za-z_]\w*)\s*:\s*(.+)$", first, re.S)
    if not mm:
        return None
    var, ptype = mm.group(1), " ".join(mm.group(2).split())
    tm = re.search(r"(?:\*\s*(?:const|mut)\s*|&\s*(?:mut\s*)?)([A-Za-z_]\w*)",
                   ptype)
    if not tm:
        return None
    typ = tm.group(1)
    if typ in ("c_void", "void"):
        body = span["body"]
        cast = re.search(
            r"(?:let\s+)?([A-Za-z_]\w*)\s*(?::[^=]*)?=\s*([A-Za-z_]\w*)"
            r"\s*\.\s*cast\s*::\s*<\s*([A-Za-z_]\w*)\s*>", body)
        if cast is None:
            # The type may still be established by an inlined callee; the
            # caller resolves that from the wrapper's unique call edge.
            return {"var": var, "type": None, "param": var,
                    "param_index": 0, "declared": " ".join(first.split()),
                    "c_void": True}
        return {"var": cast.group(1), "type": cast.group(3),
                "param": var, "param_index": 0,
                "declared": " ".join(first.split())}
    return {"var": var, "type": typ, "param": var, "param_index": 0,
            "declared": " ".join(first.split())}


_RUST_NON_CALL_WORDS = {
    "if", "while", "for", "match", "loop", "return", "unsafe", "as",
    "in", "let", "move", "Some", "Ok", "Err", "size_of", "align_of",
    "addr_of", "addr_of_mut", "cast", "from", "into",
}


def _s1_strip_comments(text: str) -> str:
    """Remove Rust line and block comments (the bodies here are declarations,
    so a string literal containing ``//`` is not expected; if one occurs the
    unique-call rule simply refuses)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _s1_inlined_fn_context(g: "DsoGraph", span: dict, var: str):
    """The context type a thin wrapper's inlined callee establishes.

    ``ossl_gcm_dinit(vctx: *mut c_void, ...)`` is exactly
    ``{ gcm_init(vctx, ...) }``, and ``gcm_init`` is the function that casts
    ``vctx`` to ``*mut ProvGcmCtx``.  The cast is not a guess about which
    callee the compiler chose: when the indirect call is observed inside the
    wrapper's own instruction stream, the wrapper's body was inlined, and the
    wrapper's only use of its context parameter is the first argument of its
    only call.  The attribution is refused unless every one of those facts is
    unique: one call, one use of the parameter, one source definition of the
    callee, one cast target, and a decidable layout for that target.
    """
    if not var:
        return None
    body = span.get("body") or ""
    stripped = _s1_strip_comments(body)
    if len(re.findall(r"\b" + re.escape(var) + r"\b", stripped)) != 1:
        return None
    calls = [c for c in re.findall(r"\b([A-Za-z_]\w*)\s*\(", stripped)
             if c not in _RUST_NON_CALL_WORDS]
    if len(calls) != 1:
        return None
    callee = calls[0]
    arg = re.search(r"\b" + re.escape(callee) + r"\s*\(\s*"
                    + re.escape(var) + r"\s*[,)]", stripped)
    if arg is None:
        return None
    defs = []
    for path, text in _s1_docs(g).items():
        for mm in re.finditer(
                r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?"
                r"(?:extern\s+\"C\"\s+)?fn\s+" + re.escape(callee)
                + r"\s*\((.*?)\)", text, re.S):
            defs.append((path, mm))
    if len(defs) != 1:
        return None
    path, mm = defs[0]
    pm = re.match(r"\s*([A-Za-z_]\w*)\s*:\s*(.+?)(?:,|$)", mm.group(1),
                  re.S)
    if pm is None:
        return None
    pvar, ptype = pm.group(1), " ".join(pm.group(2).split())
    if _s1_pointee(ptype) not in ("c_void", "void"):
        return None
    cspan = _s1_src_fn(g, path, callee)
    if cspan is None:
        return None
    casts = set(re.findall(
        r"\b" + re.escape(pvar) + r"\s*\.\s*cast\s*::\s*<\s*"
        r"([A-Za-z_]\w*)\s*>", cspan.get("body") or ""))
    if len(casts) != 1:
        return None
    target = casts.pop()
    # The cast proves the type name.  A decidable *byte layout* is a separate
    # question that the downstream rules answer (and refuse honestly when they
    # cannot); requiring it here would discard a proven cast fact.
    if _s1_struct_fields(g, target) is None:
        return None
    return {"var": pvar, "type": target, "param": var, "param_index": 0,
            "declared": " ".join((span.get("header") or "").split()),
            "via": "inlined-callee", "callee": callee,
            "witness": f"{path}:{cspan['line']}"}


def _s1_cast_types(g: "DsoGraph", ctx_info: dict, field: str):
    """Concrete source types the site function casts this object field to.

    A cast is the source's own statement that the pointer stored in ``field``
    denotes the target layout.  It is used only when the target is a decidable
    struct layout and has declared static instances in this image, so the
    field-sensitive conjunction is unchanged: the writers of the pointer slot
    must still store exactly those declared instances.
    """
    span = _s1_src_fn(g, ctx_info["file"], ctx_info["function"])
    if span is None:
        return []
    pat = re.compile(r"\b" + re.escape(field)
                     + r"\s*\.\s*cast\s*::\s*<\s*([A-Za-z_]\w*)\s*>")
    return sorted({m.group(1) for m in pat.finditer(span["body"])})


def _s1_rust_last_segment(name: str):
    """Last identifier of a legacy Rust mangled path, or None.

    The path is a sequence of ``<decimal length><identifier>`` segments after
    the crate disambiguator.  Parsing the declared lengths (rather than
    guessing a suffix) keeps names such as ``SM4_GCM_HW`` and ``CAST5_CBC_HW``
    intact: their internal digits are part of the identifier, not a length.
    """
    m = re.search(r"Cs[0-9A-Za-z]+_", name or "")
    if not m:
        return None
    pos, last = m.end(), None
    while pos < len(name):
        n = re.match(r"\d+", name[pos:])
        if not n:
            return None
        length = int(n.group(0))
        ident_at = pos + len(n.group(0))
        ident = name[ident_at:ident_at + length]
        if len(ident) != length:
            return None
        last = ident
        pos = ident_at + length
    return last


def _s1_symbol_index(g: "DsoGraph"):
    cache = getattr(g, "_s1_sym_index", None)
    if cache is not None:
        return cache
    exact, short = {}, {}
    for addr, names in (getattr(g, "names_at", {}) or {}).items():
        for raw in names:
            name = (raw or "").split("@")[0]
            if not name:
                continue
            exact[name] = addr
            best = _s1_rust_last_segment(name)
            if best:
                short.setdefault(best, set()).add(addr)
    cache = {"exact": exact, "short": short}
    g._s1_sym_index = cache
    return cache


def _s1_symbol_address(g: "DsoGraph", name: str):
    """Image address and mangled symbol name for a source static, or None."""
    idx = _s1_symbol_index(g)
    if name in idx["exact"]:
        addr = idx["exact"][name]
        return addr, name
    cands = idx["short"].get(name) or set()
    if len(cands) == 1:
        addr = next(iter(cands))
        for raw in (getattr(g, "names_at", {}) or {}).get(addr, ()):
            sym = (raw or "").split("@")[0]
            if sym.endswith(f"{len(name)}{name}"):
                return addr, sym
        return addr, name
    return None


def _s1_macro_static_names(g: "DsoGraph", table_type: str):
    """Identifiers produced by ``macro_rules!`` bodies as ``static $x: T``."""
    cache = getattr(g, "_s1_macro_static_cache", None)
    if cache is None:
        cache = {}
        g._s1_macro_static_cache = cache
    if table_type in cache:
        return cache[table_type]
    defs = {}
    for _path, text in _s1_docs(g).items():
        for m in re.finditer(r"macro_rules!\s*(\w+)\s*\{", text):
            open_at = text.find("{", m.end() - 1)
            end = _s1_brace_span(text, open_at)
            if end is None:
                continue
            body = text[open_at:end]
            names = set(re.findall(
                r"\bstatic\s+\$(\w+)\s*:\s*" + re.escape(table_type) + r"\b",
                body))
            if not names:
                continue
            decl = re.search(r"\(([^()]*)\)\s*=>", body)
            if decl is None:
                continue
            formal = [p.strip() for p in decl.group(1).split(",")]
            defs[m.group(1)] = {"names": names, "formal": formal}
    if not defs:
        cache[table_type] = set()
        return set()
    out = set()
    for _path, text in _s1_docs(g).items():
        for macro, spec in defs.items():
            pat = re.compile(r"\b" + re.escape(macro) + r"\s*!\s*([\(\[\{])")
            for m in pat.finditer(text):
                open_ch = m.group(1)
                close_ch = {"(": ")", "[": "]", "{": "}"}[open_ch]
                depth, i, close_at = 0, m.end() - 1, None
                while i < len(text):
                    if text[i] == open_ch:
                        depth += 1
                    elif text[i] == close_ch:
                        depth -= 1
                        if depth == 0:
                            close_at = i
                            break
                    i += 1
                if close_at is None:
                    continue
                raw = text[m.end():close_at]
                args, cur, depth = [], [], 0
                for ch in raw:
                    if ch in "([{<":
                        depth += 1
                    elif ch in ")]}>":
                        depth = max(0, depth - 1)
                    if ch == "," and depth == 0:
                        args.append("".join(cur).strip())
                        cur = []
                    else:
                        cur.append(ch)
                if cur:
                    args.append("".join(cur).strip())
                for formal, arg in zip(spec["formal"], args):
                    pm = re.match(r"\$(\w+)\s*:", formal)
                    am = re.fullmatch(r"(?:pub\s+)?([A-Za-z_]\w*)", arg)
                    if pm and am and pm.group(1) in spec["names"]:
                        out.add(am.group(1))
    cache[table_type] = out
    return out


def _s1_declared_instances(g: "DsoGraph", table_type: str):
    """Every source ``static NAME: table_type`` with an address in this image."""
    cache = getattr(g, "_s1_instance_cache", None)
    if cache is None:
        cache = {}
        g._s1_instance_cache = cache
    if table_type in cache:
        return cache[table_type]
    pat = re.compile(r"\bstatic\s+([A-Za-z_]\w*)\s*:\s*"
                     + re.escape(table_type) + r"\s*=")
    found = []
    for path, text in _s1_docs(g).items():
        for m in pat.finditer(text):
            found.append((m.group(1), path))
    for name in sorted(_s1_macro_static_names(g, table_type)):
        found.append((name, "macro_rules! (generated static)"))
    out, absent = {}, []
    for name, path in found:
        hit = _s1_symbol_address(g, name)
        if hit is None:
            absent.append({"name": name, "file": path})
            continue
        addr, sym = hit
        if addr in out:
            continue
        out[addr] = {"name": name, "symbol": sym, "addr": addr}
    result = {"instances": out, "absent_from_image": absent}
    cache[table_type] = result
    return result


# ---- S1 base-object qualification (2026-10-29) -------------------------- #
#
# A store ``mov value, off(base)`` is a cohort store only when ``base`` is
# proven to designate an object of the type that declares the pointer field.
# The admitted origins are an entry parameter of that type, a load of a
# pointer-typed field of that type, an allocation/constructor whose result type
# is that type, and a cast to that type.  A base proven to be a *different*
# object is excluded with the reason recorded; an unknown base refuses the
# site.  Nothing here trusts an offset alone: the DSO has 98,005 offset-keyed
# stores, so a base-typing conjunct is what makes the store set field-sensitive.

_S1_SCALAR_RET = re.compile(
    r"(?:(?:c_)?(?:int|uint|char|short|long|size_t|ssize_t|void)"
    r"|[ui](?:8|16|32|64|128|size)|f(?:32|64)|bool)$")
_S1_ALLOC_SYM = re.compile(
    r"(?:CRYPTO_)?(?:zalloc|malloc|calloc|realloc|memdup|secure_malloc|"
    r"clear_malloc|clear_free)$")


def _s1_pointee(type_text: str):
    """Pointee name of a pointer/reference type, or None."""
    t = " ".join((type_text or "").split())
    m = re.search(r"(?:\*\s*(?:const|mut)|&\s*(?:mut\s+)?)\s*"
                  r"([A-Za-z_]\w*)", t)
    return m.group(1) if m else None


def _s1_resolve_type(g: "DsoGraph", type_text: str):
    """The named object type a source type string denotes, or None."""
    t = " ".join((type_text or "").split())
    if not t or t.startswith("Option<"):
        return None
    name = _s1_pointee(t)
    if name is None:
        ids = re.findall(r"[A-Za-z_]\w*", t)
        name = ids[-1] if ids else None
    if name is None:
        return None
    alias = _s1_type_alias(g, name)
    if alias is not None and alias != name:
        nxt = _s1_pointee(alias)
        if nxt is None:
            ids = re.findall(r"[A-Za-z_]\w*", alias)
            nxt = ids[-1] if ids else None
        if nxt:
            name = nxt
    return name


def _s1_prefix_chain(g: "DsoGraph", type_name: str, base: str,
                     depth: int = 0):
    """``[T, ..., base]`` when base is T's first field, transitively.

    Every step is a ``#[repr(C)]`` struct whose *first* field has offset zero,
    so the base layout is a prefix of T's layout at the same offsets.
    """
    if not type_name:
        return None
    if type_name == base:
        return [base]
    if depth >= 5:
        return None
    fields = _s1_struct_fields(g, type_name)
    layout = _s1_struct_layout(g, type_name)
    if fields is None:
        return None
    if layout is not None and layout["fields"] \
            and layout["fields"][0]["offset"] != 0:
        return None
    first_type = fields[0][0][1]
    if (first_type.startswith("*") or first_type.startswith("&")
            or first_type.startswith("Option<") or first_type.startswith("[")):
        return None
    inner = _s1_resolve_type(g, first_type)
    if inner is None or inner == type_name:
        return None
    chain = _s1_prefix_chain(g, inner, base, depth + 1)
    return None if chain is None else [type_name] + chain


def _s1_type_compatible(g: "DsoGraph", type_text: str, base: str) -> dict:
    """Whether a declared type is ``base`` or carries it as its first field."""
    t = " ".join((type_text or "").split())
    if not t or t.startswith("Option<"):
        return {"admitted": False, "type": t or None,
                "why": "Option/empty type is not the object type"}
    resolved = _s1_resolve_type(g, t)
    if resolved is None:
        return {"admitted": False, "type": None, "why": "no type name"}
    if resolved == base:
        return {"admitted": True, "type": resolved, "exact": True,
                "prefix": [base]}
    chain = _s1_prefix_chain(g, resolved, base)
    if chain:
        return {"admitted": True, "type": resolved, "exact": False,
                "prefix": chain}
    return {"admitted": False, "type": resolved,
            "why": (f"{resolved} is not {base} and does not carry it as "
                    "its first field")}


def _s1_signature(span: dict):
    """Explicit parameter types and the return type of a source function."""
    header = span.get("header") or ""
    m = re.search(r"\(", header)
    if not m:
        return None
    depth, end, i = 0, None, m.start()
    while i < len(header):
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    if end is None:
        return None
    inner = header[m.start() + 1:end]
    params, cur, depth = [], [], 0
    for ch in inner:
        if ch in "([<":
            depth += 1
        elif ch in ")]>" :
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            params.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        params.append("".join(cur).strip())
    ptypes = []
    for p in params:
        if not p:
            continue
        mm = re.match(r"[A-Za-z_]\w*\s*:\s*(.+)$", p, re.S)
        ptypes.append(" ".join((mm.group(1) if mm else p).split()))
    after = header[end + 1:]
    at = after.find("->")
    if at < 0:
        ret = "()"
    else:
        ret = after[at + 2:].split("{", 1)[0]
        ret = re.split(r"\bwhere\b", ret, maxsplit=1)[0]
        ret = " ".join(ret.split()) or "()"
    return {"params": ptypes, "ret": ret}


def _s1_return_uses_sret(ret: str):
    """Whether the return value is passed through a hidden first pointer."""
    t = " ".join((ret or "").split())
    if not t or t in ("()", "!"):
        return False
    if t.startswith("*") or t.startswith("&"):
        return False
    if t.startswith("Option<"):
        inner = t[len("Option<"):-1].strip() if t.endswith(">") else ""
        if (inner.startswith("*") or inner.startswith("&")
                or inner.startswith("NonNull<")
                or inner.startswith("NonZero")):
            return False
        return True
    return not _S1_SCALAR_RET.match(t)


def _s1_abi_types(sig: dict, idx: int):
    """Declared types an entry argument register can carry."""
    params = sig.get("params") or []
    if _s1_return_uses_sret(sig.get("ret")):
        if idx == 0:
            return [{"role": "sret-return", "type": sig.get("ret")}]
        j = idx - 1
        return ([{"role": f"param{j}", "type": params[j]}]
                if 0 <= j < len(params) else [])
    return ([{"role": f"param{idx}", "type": params[idx]}]
            if 0 <= idx < len(params) else [])


def _s1_writer_source(g: "DsoGraph", wf: int):
    """(file, span) of a writer's source function, or None."""
    cache = getattr(g, "_s1_writer_src_cache", None)
    if cache is None:
        cache = {}
        g._s1_writer_src_cache = cache
    if wf in cache:
        return cache[wf]
    dm = _s1_demangled(g, wf)
    name, out = None, None
    if dm:
        m = CRATE_NS.match(dm)
        if m:
            segs = m.group(1).split("::")
            if len(segs) >= 2:
                name = segs[-1]
                root = _repo_root(g)
                if root is not None:
                    fallback = getattr(g, "_s1_module_index", None)
                    if fallback is None:
                        fallback = build_module_index(root / "src")
                        g._s1_module_index = fallback
                    relpath = module_to_file("::".join(segs[:-1]),
                                             root / "src", fallback)
                    if relpath:
                        span = _s1_src_fn(g, relpath, name)
                        if span is not None:
                            out = {"file": relpath, "span": span,
                                   "name": name, "via": "module"}
        if name is None:
            name = dm.split("::")[-1].strip()
    if out is None and name:
        hits = []
        for path in sorted(_s1_docs(g)):
            span = _s1_src_fn(g, path, name)
            if span is not None:
                hits.append({"file": path, "span": span,
                             "name": name, "via": "unique-name"})
        if len(hits) == 1:
            out = hits[0]
    cache[wf] = out
    return out


_S1_RUST_KEYWORDS = {
    "unsafe", "extern", "fn", "let", "mut", "pub", "crate", "self",
    "super", "use", "mod", "static", "const", "struct", "enum", "impl",
    "trait", "type", "where", "if", "else", "match", "return", "break",
    "continue", "while", "for", "in", "as", "loop", "move", "ref",
    "true", "false", "core", "crate", "c_void", "c_int", "c_uint",
    "c_uchar", "c_char", "usize", "isize", "u8", "u16", "u32", "u64",
    "i8", "i16", "i32", "i64", "bool", "Option", "Some", "None",
}


def _s1_macro_sources(g: "DsoGraph", name: str):
    """Function definitions a macro-generated writer expands to.

    A macro-generated dispatch wrapper has no literal ``fn`` of its own.  The
    constructor can be an identifier argument of the invocation, or it can be
    called (with a fixed name) by the macro's own body -- both are followed, so
    a macro that hard-codes its sub-constructor is not silently untyped.
    """
    cache = getattr(g, "_s1_macro_arg_cache", None)
    if cache is None:
        cache = {}
        g._s1_macro_arg_cache = cache
    if name in cache:
        return cache[name]
    out = []
    seen = set()
    tok = re.compile(r"\b" + re.escape(name) + r"\b")
    idpat = re.compile(r"\b([A-Za-z_]\w*)\b")
    docs = _s1_docs(g)

    def _add(path, ident, via):
        if ident in seen or ident in _S1_RUST_KEYWORDS:
            return
        span = _s1_src_fn(g, path, ident)
        if span is not None:
            seen.add(ident)
            out.append({"file": path, "span": span, "name": ident,
                        "via": via})

    for path, text in docs.items():
        if name not in text:
            continue
        for mm in re.finditer(r"\b([A-Za-z_]\w*)!\s*\(", text):
            open_at = text.find("(", mm.end() - 1)
            depth, i, end = 0, open_at, None
            while i < len(text):
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
                i += 1
            if end is None:
                continue
            args = text[open_at + 1:end]
            if not tok.search(args):
                continue
            for arg in args.split(","):
                am = re.match(r"\s*([A-Za-z_]\w*)", arg)
                if am and am.group(1) != name:
                    _add(path, am.group(1), "macro-arg")
            macro_name = mm.group(1)
            defs = getattr(g, "_s1_macro_def_cache", None)
            if defs is None:
                defs = {}
                g._s1_macro_def_cache = defs
            if macro_name not in defs:
                hit = None
                for dpath, dtext in docs.items():
                    dm = re.search(r"macro_rules!\s*" + re.escape(macro_name)
                                   + r"\s*\{", dtext)
                    if not dm:
                        continue
                    brace = dtext.find("{", dm.start())
                    bend = _s1_brace_span(dtext, brace)
                    if bend is not None:
                        hit = (dpath, dtext[brace + 1:bend - 1])
                        break
                defs[macro_name] = hit
            hit = defs.get(macro_name)
            if hit is not None:
                for ident in sorted(set(idpat.findall(hit[1]))):
                    _add(hit[0], ident, "macro-body")
    cache[name] = out
    return out


def _s1_construct_witness(g: "DsoGraph", span: dict, base: str, via: str):
    """The unique compatible allocation/constructor type in one function."""
    body = span.get("body") or ""
    hits = []
    for m in re.finditer(r"Owned[A-Za-z_]*\s*::\s*<\s*([A-Za-z_]\w*)\s*>",
                         body):
        hits.append({"type": m.group(1), "kind": "owned-constructor",
                     "witness": f"{span['file']}:{span['line']}",
                     "via": via})
    if not hits:
        for m in re.finditer(
                r"(?:\.\s*cast\s*::\s*<|as\s+\*\s*(?:const|mut)\s+)"
                r"([A-Za-z_]\w*)", body):
            hits.append({"type": m.group(1), "kind": "cast",
                         "witness": f"{span['file']}:{span['line']}",
                         "via": via})
    comp = []
    for h in hits:
        c = _s1_type_compatible(g, h["type"], base)
        if c.get("admitted"):
            comp.append(dict(h, prefix=c.get("prefix"),
                             exact=c.get("exact")))
    owned = [h for h in comp if h["kind"] == "owned-constructor"]
    pool = owned or comp
    seen = {}
    for h in pool:
        seen.setdefault(h["type"], h)
    if len(seen) == 1:
        return next(iter(seen.values()))
    if seen:
        return {"ambiguous": sorted(seen)}
    return None


def _s1_writer_construct(g: "DsoGraph", wf: int, base: str):
    """The allocation type a writer's base can denote, or None.

    An ``Owned*::<T>`` allocation in the writer (or in the function a
    macro-generated wrapper expands to) is preferred; a cast in the writer's
    own literal source is the fallback.  A cast found in an unrelated function
    that merely appears in a macro body is not evidence about this allocation
    and is not used.
    """
    cache = getattr(g, "_s1_construct_cache", None)
    if cache is None:
        cache = {}
        g._s1_construct_cache = cache
    key = (wf, base)
    if key in cache:
        return cache[key]
    sources = []
    src = _s1_writer_source(g, wf)
    if src is not None:
        sources.append(src)
    name = (src or {}).get("name")
    if name is None:
        dm = _s1_demangled(g, wf) or (g.funcs.get(wf) or "")
        name = dm.split("::")[-1].split("@")[0].strip() if dm else None
    if name:
        sources.extend(_s1_macro_sources(g, name))
    owned, casts, amb = [], [], set()
    for s in sources:
        w = _s1_construct_witness(g, s["span"], base, s["via"])
        if not isinstance(w, dict):
            continue
        if w.get("ambiguous"):
            amb.update(w["ambiguous"])
            continue
        if w.get("kind") == "owned-constructor":
            owned.append(w)
        elif w.get("kind") == "cast" and s.get("via") in ("module",
                                                          "unique-name"):
            casts.append(w)
    pool = owned or casts
    distinct = {}
    for h in pool:
        distinct.setdefault(h["type"], h)
    if len(distinct) == 1:
        cache[key] = next(iter(distinct.values()))
        return cache[key]
    if len(distinct) > 1:
        cache[key] = {"ambiguous": sorted(distinct)}
        return cache[key]
    if amb:
        cache[key] = {"ambiguous": sorted(amb)}
        return cache[key]
    cache[key] = None
    return None


def _s1_call_symbol(g: "DsoGraph", fstart: int, idx: int):
    """Symbol a call instruction names, directly or through its GOT slot."""
    text = _insn(g, fstart, idx)
    if "#" in text:
        m = re.search(r"<([A-Za-z_][\w]*)", text.split("#", 1)[1])
        if m:
            return m.group(1)
    direct = _direct_call_target(g, fstart, idx)
    if direct is not None:
        return (g.funcs.get(direct[1]) or "").split("@")[0]
    return None


def _s1_call_def(g: "DsoGraph", fstart: int, idx: int, reg: str,
                 depth: int = 0):
    """Index of the call that produced ``reg``, or None."""
    if depth > 8:
        return None
    defs = _reaching_defs(g, fstart, idx, reg)
    if defs is None or len(defs) != 1 or defs == {_ENTRY_DEF}:
        return None
    k = next(iter(defs))
    mn, _rest, ops = _insn_parts(_insn(g, fstart, k))
    if mn.startswith("call"):
        return k
    if mn in ("mov", "movq") and len(ops) >= 2 and (ops[0] in _REGS
                                                     or ops[0] in _SUBREG):
        return _s1_call_def(g, fstart, k, _canon(ops[0]), depth + 1)
    return None


def _s1_store_base_witness_raw(g: "DsoGraph", wf: int, store: dict,
                               decl_type: str, slot_off: int):
    """Qualify, exclude, or refuse one store's base object."""
    origin = _reg_origin(g, wf, store["index"], _canon(store["base"]))
    kind = origin.get("kind")
    rec = {"function": g.funcs.get(wf, hex(wf)),
           "store_site": hex(store["addr"]), "origin_kind": kind}
    if kind == "param":
        src = _s1_writer_source(g, wf)
        sig = _s1_signature(src["span"]) if src else None
        if sig is None:
            rec.update(qualified=False, unknown=True,
                       reason="entry-parameter origin without a source "
                              "signature")
            return rec
        cands = _s1_abi_types(sig, origin.get("index"))
        if not cands:
            rec.update(qualified=False, unknown=True,
                       reason="entry index has no declared type")
            return rec
        compat = [(c, _s1_type_compatible(g, c["type"], decl_type))
                  for c in cands]
        admitted = [(c, t) for c, t in compat if t.get("admitted")]
        if admitted and len(admitted) == len(compat):
            c, t = admitted[0]
            rec.update(qualified=True, origin="entry-parameter",
                       declared_role=c["role"], declared_type=c["type"],
                       prefix=t.get("prefix"), exact=t.get("exact"),
                       witness=f"{src['file']}:{src['span']['line']}")
            return rec
        if not admitted:
            if "s1-base-different" in _MUTED:
                rec.update(qualified=False, unknown=True,
                           reason="mutation: different-object base trusted")
                return rec
            rec.update(qualified=False, excluded=True,
                       origin="entry-parameter",
                       reason=("base is an entry value of declared type "
                               + ", ".join(f"{c['role']}:{c['type']}"
                                           for c, _t in compat)
                               + f", not {decl_type}"))
            return rec
        rec.update(qualified=False, unknown=True,
                   reason="ambiguous ABI parameter mapping across the "
                          "return-slot shift")
        return rec
    if kind == "load":
        outer = _reg_origin(g, wf, origin["at"],
                            _canon(origin["base_reg"]))
        if outer.get("kind") == "param":
            src = _s1_writer_source(g, wf)
            sig = _s1_signature(src["span"]) if src else None
            cands = _s1_abi_types(sig, outer.get("index")) if sig else []
            for c in cands:
                owner = _s1_resolve_type(g, c["type"])
                layout = _s1_struct_layout(g, owner) if owner else None
                if layout is None:
                    continue
                row = next((r for r in layout["fields"]
                            if r["offset"] == origin["offset"]), None)
                if row is None:
                    continue
                comp = _s1_type_compatible(g, row["type"], decl_type)
                if comp.get("admitted"):
                    rec.update(qualified=True, origin="pointer-field-load",
                               field_type=row["type"], owner=owner,
                               prefix=comp.get("prefix"),
                               exact=comp.get("exact"),
                               witness=f"{src['file']}:{src['span']['line']}")
                    return rec
                if "s1-base-different" in _MUTED:
                    continue
                rec.update(qualified=False, excluded=True,
                           origin="pointer-field-load",
                           reason=(f"base is field {row['name']}:"
                                   f"{row['type']} of {owner}, not a pointer "
                                   f"to {decl_type}"))
                return rec
        rec.update(qualified=False, unknown=True,
                   reason="load origin with no decidable owning type")
        return rec
    if kind in ("call", "alloc", "alloc-unknown", "unknown"):
        if kind == "call":
            call_idx = origin.get("call_site")
            sym = ((g.funcs.get(origin.get("callee")) or "").split("@")[0]
                   or _s1_call_symbol(g, wf, call_idx))
            target = origin.get("callee")
        elif kind in ("alloc", "alloc-unknown"):
            call_idx = origin.get("call_site")
            sym = origin.get("symbol")
            target = None
        elif "call" in str(origin.get("why") or ""):
            call_idx = _s1_call_def(g, wf, store["index"],
                                    _canon(store["base"]))
            sym = _s1_call_symbol(g, wf, call_idx) if call_idx is not None \
                else None
            target = None
        else:
            rec.update(qualified=False, unknown=True,
                       reason="unproven base origin: "
                              + str(origin.get("why") or kind))
            return rec
        if target is not None and not (sym and _S1_ALLOC_SYM.search(sym)):
            csrc = _s1_writer_source(g, target)
            sig = _s1_signature(csrc["span"]) if csrc else None
            if sig is not None:
                comp = _s1_type_compatible(g, sig["ret"], decl_type)
                if comp.get("admitted"):
                    rec.update(qualified=True, origin="constructor-result",
                               constructor_type=comp["type"],
                               constructor_kind="return-type",
                               prefix=comp.get("prefix"),
                               exact=comp.get("exact"),
                               witness=(f"{csrc['file']}:"
                                        f"{csrc['span']['line']}"))
                    return rec
        if sym and _S1_ALLOC_SYM.search(sym):
            w = _s1_writer_construct(g, wf, decl_type)
            if isinstance(w, dict) and w.get("type"):
                rec.update(qualified=True, origin="allocation-constructor",
                           constructor_type=w["type"],
                           constructor_kind=w["kind"],
                           prefix=w.get("prefix"), exact=w.get("exact"),
                           witness=w.get("witness"))
                return rec
            if isinstance(w, dict) and w.get("ambiguous"):
                rec.update(qualified=False, unknown=True,
                           reason="multiple compatible constructor types: "
                                  + ", ".join(w["ambiguous"]))
                return rec
        rec.update(qualified=False, unknown=True,
                   reason=("call origin "
                           + (f"to {sym}" if sym else "with no resolvable "
                              "symbol")
                           + " without a typed constructor witness"))
        return rec
    rec.update(qualified=False, unknown=True,
               reason="unproven base origin: " + str(origin.get("why") or kind))
    return rec


def _s1_store_base_witness(g: "DsoGraph", wf: int, store: dict,
                           decl_type: str, slot_off: int):
    """Base-object qualification with its mutation control."""
    rec = _s1_store_base_witness_raw(g, wf, store, decl_type, slot_off)
    if rec.get("unknown") and "s1-base-unknown" in _MUTED:
        return dict(rec, unknown=False, excluded=True,
                    reason="mutation: unknown base trusted as a different "
                           "object")
    return rec


# ---- S1 prefix-compatible instance enumeration (2026-10-29) ------------- #
#
# A writer may store a concrete ``#[repr(C)]`` type T whose declared layout
# begins with the field type B.  The instance set is then the union of the
# declared statics of B and of every admitted T, and the union must account
# for *every* cohort store.  A T whose first field is not B (or a layout-
# identical first field with a source cast to B) is not admitted, so a store
# of one refuses the site instead of silently widening it.


def _s1_static_type(g: "DsoGraph", addr: int):
    """The source type of the static at ``addr``, or None."""
    cache = getattr(g, "_s1_static_type_cache", None)
    if cache is None:
        cache = {}
        g._s1_static_type_cache = cache
    if addr in cache:
        return cache[addr]
    out = None
    for raw in (getattr(g, "names_at", {}) or {}).get(addr, ()):
        short = _s1_rust_last_segment(raw) or (raw or "").split("@")[0]
        if not short:
            continue
        pat = re.compile(r"\bstatic\s+" + re.escape(short)
                         + r"\s*:\s*([A-Za-z_]\w*)\s*=")
        hits = set()
        for _path, text in _s1_docs(g).items():
            for m in pat.finditer(text):
                hits.add(m.group(1))
        if len(hits) == 1:
            out = hits.pop()
            break
    cache[addr] = out
    return out


def _s1_static_cast_witness(g: "DsoGraph", type_name: str, base: str):
    """A source cast of a T static's first field to B, or None."""
    cache = getattr(g, "_s1_static_cast_cache", None)
    if cache is None:
        cache = {}
        g._s1_static_cast_cache = cache
    key = (type_name, base)
    if key in cache:
        return cache[key]
    inst = _s1_declared_instances(g, type_name).get("instances") or {}
    names = {v["name"] for v in inst.values() if v.get("name")}
    if not names:
        return None
    alt = "|".join(re.escape(n) for n in sorted(names))
    pat = re.compile(r"addr_of!\s*\(\s*(?:" + alt + r")\b[^)]*\)\s*"
                     r"\.cast::<\s*" + re.escape(base) + r"\s*>")
    pat2 = re.compile(r"\(\s*(?:" + alt + r")\s+as\s+\*\s*const\s+"
                      + re.escape(base) + r"\s*\)")
    for path, text in _s1_docs(g).items():
        m = pat.search(text) or pat2.search(text)
        if m:
            cache[key] = (f"{path}:"
                          f"{text.count(chr(10), 0, m.start()) + 1}")
            return cache[key]
    cache[key] = None
    return None


def _s1_prefix_witness(g: "DsoGraph", type_name: str, base: str,
                       used_offsets):
    """Admit a concrete first-field-compatible type, with both witnesses."""
    if type_name == base:
        return None
    fields = _s1_struct_fields(g, type_name)
    layout = _s1_struct_layout(g, type_name)
    blayout = _s1_struct_layout(g, base)
    if fields is None or blayout is None or not fields[0]:
        return None
    if layout is not None and layout["fields"] \
            and layout["fields"][0]["offset"] != 0:
        return None
    first_name, first_type = fields[0][0]
    exact = _s1_resolve_type(g, first_type) == base
    cast = None
    prefix_object = base
    if not exact:
        inner = _s1_resolve_type(g, first_type)
        flayout = _s1_struct_layout(g, inner) if inner else None
        if flayout is None:
            if "s1-prefix-first-field" not in _MUTED:
                return None
            flayout = blayout
            prefix_object = base
        else:
            prefix_object = inner
        offsets = set(used_offsets or ())
        offsets |= {r["offset"] for r in blayout["fields"]}
        if "s1-prefix-layout" not in _MUTED:
            for off in offsets:
                b = next((r for r in blayout["fields"]
                          if r["offset"] == off), None)
                f = next((r for r in flayout["fields"]
                          if r["offset"] == off), None)
                if b is None or f is None:
                    return None
                # The ABI slot is what matters: same offset and same
                # size/alignment.  `Option<fn>` and `fn` occupy the same
                # eight-byte pointer slot, and the concrete row is allowed
                # to model a NULL the base type declares non-nullable.
                if _s1_type_size(g, b["type"]) \
                        != _s1_type_size(g, f["type"]):
                    return None
        cast = _s1_static_cast_witness(g, type_name, base)
        if cast is None:
            return None
    return {
        "type": type_name, "repr_c": True,
        "first_field": {"name": first_name, "type": first_type,
                        "offset": 0},
        "first_field_is_base": bool(exact),
        "prefix_object_type": prefix_object,
        "source_witness": ((f"{layout.get('file')}:{layout.get('line')}")
                           if layout is not None
                           else f"{fields[1].get('file')}:"
                                f"{fields[1].get('line')}"),
        "layout_witness": {
            "base_size": blayout["size"],
            "type_size": (layout["size"] if layout is not None else None),
            "offsets": sorted({hex(o) for o in (set(used_offsets or ())
                                               | {r["offset"] for r in
                                                  blayout["fields"]})}),
            "extra_offsets": (sorted({hex(o) for o in
                                      range(blayout["size"], layout["size"],
                                            8)})
                              if layout is not None else []),
        },
        "cast_witness": cast,
    }


def _s1_dispatch_tables(g: "DsoGraph"):
    """Decode immutable ``OsslDispatch`` tables from the exact image."""
    cache = getattr(g, "_s1_dispatch_cache", None)
    if cache is not None:
        return cache
    sizes = getattr(g, "sym_sizes", {}) or {}
    out, seen = [], set()
    for addr, names in (getattr(g, "names_at", {}) or {}).items():
        if addr in seen:
            continue
        sec = g.section_of(addr)
        if sec not in S1_IMMUTABLE_SECTIONS:
            continue
        size = None
        sym = None
        for raw in names:
            name = (raw or "").split("@")[0]
            if name in sizes:
                size, sym = sizes[name], name
                break
        if size is None or size < 32 or size > 0x1000 or size % 16:
            continue
        entries = []
        valid = True
        terminated = False
        for k in range(size // 16):
            fid = g.read_u32(addr + k * 16)
            ptrs = g.static_slot(addr + k * 16 + 8)
            ints = {x for x in (ptrs or ()) if isinstance(x, int)}
            if fid is None or len(ints) != 1:
                valid = False
                break
            ptr = next(iter(ints))
            if fid == 0:
                if ptr != 0:
                    valid = False
                terminated = True
                break
            if not (1 <= fid <= 14) or ptr == 0 or ptr not in g.start_set:
                valid = False
                break
            entries.append({"id": fid, "target": ptr})
        if not valid or not terminated or not entries:
            continue
        if not any(e["id"] == 1 for e in entries):
            continue
        seen.add(addr)
        out.append({"addr": addr, "symbol": sym or g.all_syms.get(addr),
                    "section": sec, "entries": entries})
    g._s1_dispatch_cache = out
    return out


def _s1_closure(g: "DsoGraph", roots, depth: int = 2):
    seen = set(roots)
    frontier = set(roots)
    for _ in range(depth):
        nxt = set()
        for f in frontier:
            for callee in (getattr(g, "direct", {}) or {}).get(f, ()):
                if callee not in seen:
                    seen.add(callee)
                    nxt.add(callee)
        frontier = nxt
    return seen


def _s1_store_value(g: "DsoGraph", fstart: int, idx: int, src: str,
                    slot_off: int):
    """(value, kind) for a stored operand; kind ``identity`` means a reload."""
    src = src.strip()
    if src.startswith("$"):
        try:
            return int(src[1:], 16), "immediate"
        except ValueError:
            return None, "bad-immediate"
    if src in _REGS or src in _SUBREG:
        origin = _reg_origin(g, fstart, idx, _canon(src))
        kind = origin.get("kind")
        if kind == "int":
            return origin.get("value"), "immediate"
        if kind == "load":
            if origin.get("offset") == slot_off:
                return None, "identity"
            insn = _insn(g, fstart, origin.get("at", -1))
            addr = _insn_comment_addr(insn)
            if addr is not None:
                return addr, "static"
            return None, "non-static-load"
        return None, "origin:" + str(kind)
    if re.fullmatch(r"-?0x[0-9a-f]+\(%rip\)", src):
        # The objdump comment on the store carries the link address.
        comment = _insn_comment_addr(_insn(g, fstart, idx))
        return (comment, "static") if comment is not None else (None,
                                                                "rip-slot")
    return None, "unsupported-source"


def _s1_scalar_stores(g: "DsoGraph", fstart: int, slot_off: int):
    """Scalar 8-byte stores to ``slot_off(base)`` in one function."""
    out = []
    for i, (addr, text) in enumerate(
            (getattr(g, "precision", None).insns_by_func.get(fstart, ())
             if _has_insns(g) else ())):
        body = text.split("#", 1)[0].strip()
        m = re.fullmatch(
            r"(mov|movq|movabs)\s+(.+),\s*(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)\s*",
            body)
        if not m:
            continue
        src = m.group(2).strip()
        disp = m.group(3) or "0"
        base = m.group(4)
        try:
            off = int(disp, 16)
        except ValueError:
            continue
        if base in ("%rsp", "%rbp") or off != slot_off:
            continue
        out.append({"index": i, "addr": addr, "src": src, "base": base})
    return out


def _s1_null_guard(g: "DsoGraph", fstart: int, idx: int, member_off: int,
                   base_reg: str):
    """Guard address for a nullable member, or None."""
    insns = g.precision.insns_by_func.get(fstart, ()) if _has_insns(g) else ()
    lo = max(0, idx - 40)
    member_reg = None
    mem_pat = re.compile(r"(-?0x[0-9a-f]+)?\(%r[a-z0-9]+\)")
    for k in range(idx - 1, lo - 1, -1):
        text = insns[k][1].split("#", 1)[0].strip()
        mm = re.fullmatch(r"mov(?:q)?\s+(%r[a-z0-9]+),\s*"
                          r"(-?0x[0-9a-f]+)\((%r[a-z0-9]+)\)", text)
        if mm and int(mm.group(2), 16) == member_off \
                and mm.group(3) == base_reg:
            member_reg = _canon(mm.group(1))
            break
        if mem_pat.search(text) and "test" in text:
            return insns[k][0]
    if member_reg is None and _canon(base_reg) not in _REGS:
        return None
    reg = member_reg or _canon(base_reg)
    for k in range(idx - 1, lo - 1, -1):
        text = insns[k][1].split("#", 1)[0].strip()
        mn, rest, ops = _insn_parts(text)
        if mn == "test" and len(ops) == 2 and _canon(ops[0]) == reg \
                and _canon(ops[1]) == reg:
            for j in range(k + 1, min(len(insns), k + 5)):
                mn2, rest2, _o = _insn_parts(insns[j][1])
                if mn2.startswith("j") and re.match(r"^[0-9a-f]+", rest2):
                    return insns[k][0]
                if mn2.startswith(("call", "ret")):
                    break
        if mn == "cmp" and len(ops) == 2 \
                and ops[0] in ("$0x0", "$0") and _canon(ops[1]) == reg:
            for j in range(k + 1, min(len(insns), k + 5)):
                mn2, rest2, _o = _insn_parts(insns[j][1])
                if mn2.startswith("j") and re.match(r"^[0-9a-f]+", rest2):
                    return insns[k][0]
                if mn2.startswith(("call", "ret")):
                    break
    return None


def _s1_refusal(reason: str, **extra) -> dict:
    rec = {"schema": S1_WITNESS_SCHEMA, "class": "static-table-instance",
           "contract_bounded": False, "resolved": False,
           "refusal": reason}
    rec.update(extra)
    return rec


def _s1_ctx_param(g: "DsoGraph", fstart: int, idx: int, reg: str,
                  want: int, seen: frozenset = frozenset()):
    """Prove that ``reg`` at ``idx`` holds the context parameter ``want``.

    This qualifies the *object* rather than widening the table.  Every
    reaching definition must independently establish the same parameter:

    * the entry argument register for ``want``;
    * a whole-register ``mov`` whose source is again proven (a compiler copy
      into a callee-saved register);
    * a reload from a frame slot whose every reaching store is proven to be
      that same parameter, as established by ``_stack_param``.

    A branch that cannot be proved refuses the whole object, so two paths are
    never unioned into a may-alias, and a call result or a different parameter
    never qualifies.  This is the only admission: a partially proven reaching
    definition returns None.
    """
    reg = _canon(reg) if reg in _SUBREG else reg
    key = (idx, reg)
    if key in seen:
        return None
    seen = seen | {key}
    defs = _reaching_defs(g, fstart, idx, reg)
    if not defs:
        return None
    insns = g.precision.insns_by_func.get(fstart, ())
    proofs = []
    for d in sorted(defs):
        if d == _ENTRY_DEF:
            if _ENTRY_ARG_REGS.get(reg) != want:
                return None
            proofs.append({"step": "entry-register", "reg": reg})
            continue
        if not (0 <= d < len(insns)):
            return None
        mn, _rest, ops = _insn_parts(insns[d][1])
        if mn not in ("mov", "movq") or len(ops) < 2:
            return None
        dst = ops[-1]
        if dst not in _REGS or _canon(dst) != reg:
            return None
        src = ops[0].strip()
        proof = None
        if src in _REGS:
            proof = _s1_ctx_param(g, fstart, d, src, want, seen)
            if proof is not None:
                proofs.append({"step": "register-copy",
                               "addr": hex(insns[d][0]), "src": src})
        elif re.fullmatch(r"(-?0x[0-9a-f]+)?\((%rsp|%rbp)\)", src):
            spill = _stack_param(g, fstart, d, src, None)
            if spill is not None and spill.get("index") == want:
                proof = spill
                proofs.append({"step": "frame-slot-reload",
                               "addr": hex(insns[d][0]), "slot": src,
                               "provenance": spill.get("provenance")})
        if proof is None:
            return None
    return {"kind": "param", "index": want, "via": proofs}


def static_table_instance_witness(g: "DsoGraph", site: dict, name: str,
                                  reachable: set | None = None,
                                  trace: list | None = None):
    """Prove (or refuse) a field-sensitive static-table instance dispatch.

    Returns None when this site is not a field-dispatch candidate at all; a
    dict with ``resolved`` otherwise.  Every refusal is recorded and leaves the
    site target-bounded -- callers must not fall through to a weaker class.

    ``trace`` is an optional diagnostic list.  When supplied, the name of the
    gate that rejected a non-candidate is appended to it.  It never changes the
    returned value and is never populated by the closure itself.
    """
    def _miss(gate):
        if trace is not None:
            trace.append(gate)
        return None

    if site.get("kind") != "call" or not _has_insns(g):
        return _miss("not-call-or-no-insns")
    fstart = site.get("func")
    insns = g.precision.insns_by_func.get(fstart, ())
    idx = next((i for i, (a, _t) in enumerate(insns) if a == site.get("addr")),
               None)
    if idx is None:
        return _miss("site-not-in-function")
    ctx_info = _s1_site_context(g, fstart)
    if ctx_info is None:
        return _miss("no-context-type")
    # Only the pointer fields of T are needed.  T itself need not have a
    # fully decidable layout: the pointer-slot offset is read from the load
    # that produces the call's base, and the table type U carries the layout
    # that the member offsets are checked against.
    tfields = _s1_struct_fields(g, ctx_info["type"])
    if tfields is None:
        return _miss("context-layout-undecidable")
    pointer_fields = []
    for fname, ftype in tfields[0]:
        m = re.match(r"\*\s*(?:const|mut)\s+([A-Za-z_]\w*)", ftype)
        if not m:
            continue
        ulayout = _s1_struct_layout(g, m.group(1))
        if ulayout is None:
            continue
        pointer_fields.append({"field": fname,
                               "table_type": m.group(1), "layout": ulayout,
                               "declaration": (f"{tfields[1]['file']}:"
                                               f"{tfields[1]['line']}")})
    if not pointer_fields:
        return _miss("no-pointer-field-with-layout")

    text = site.get("text") or ""
    m = re.search(r"call\w*\s+\*(.+)$", text.split("#", 1)[0].strip())
    if not m:
        return _miss("operand-not-field")
    operand = m.group(1).strip()
    member_off = None
    base_reg = None
    chain = []
    mo = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", operand)
    if mo:
        member_off = int(mo.group(1), 16) if mo.group(1) else 0
        base_reg = mo.group(2)
    elif operand in _REGS or operand in _SUBREG:
        base_reg = _canon(operand)
    else:
        return _miss("operand-is-not-register-or-field")
    origin = _reg_origin(g, fstart, idx, base_reg)
    chain = []
    if mo:
        if origin.get("kind") != "load":
            if "s1-base-not-table" not in _MUTED:
                return _miss("base-not-field-load")
            # Mutation only: the call operand is not a field load.  Use the
            # observed member offset so the rest of the checks still run.
            slot_off = member_off
            table_reg = base_reg
            slot_load_idx = idx
        else:
            slot_off = origin["offset"]
            table_reg = origin["base_reg"]
            slot_load_idx = origin["at"]
    else:
        if origin.get("kind") != "load":
            return _miss("base-reg-not-field-load")
        member_off = origin["offset"]
        table_reg = origin["base_reg"]
        slot_load_idx = origin["at"]
        slot_origin = _reg_origin(g, fstart, slot_load_idx, table_reg)
        if slot_origin.get("kind") != "load":
            if "s1-base-not-table" not in _MUTED:
                return _miss("table-reg-not-field-load")
            slot_off = member_off
        else:
            slot_off = slot_origin["offset"]
            chain.append({"step": "load member",
                          "addr": (hex(insns[slot_load_idx][0])
                                   if slot_load_idx < len(insns) else None),
                          "member_offset": hex(member_off)})
            table_reg = slot_origin["base_reg"]
            slot_load_idx = slot_origin["at"]
    want = ctx_info.get("param_index")
    table_object_reg = (_canon(table_reg) if table_reg in _SUBREG
                        else table_reg)
    if "s1-ctx-object" in _MUTED:
        # Mutation control: fall back to the single-provenance resolver, which
        # cannot follow a spill or a two-path copy.
        ctx_origin = _reg_origin(g, fstart, slot_load_idx, table_object_reg)
        if (ctx_origin.get("kind") != "param"
                or ctx_origin.get("index") != want):
            ctx_origin = None
    else:
        ctx_origin = _s1_ctx_param(g, fstart, slot_load_idx,
                                   table_object_reg, want)
    ctx_failure = ctx_origin is None
    if not ctx_failure:
        slot_load_addr = (insns[slot_load_idx][0]
                          if slot_load_idx < len(insns) else None)
        chain.insert(0, {"step": "parameter ctx",
                         "param": ctx_info.get("param"),
                         "register": table_reg,
                         "index": ctx_origin.get("index")})
        chain.insert(1, {"step": "load pointer_slot",
                         "addr": hex(slot_load_addr) if slot_load_addr else None,
                         "offset": hex(slot_off)})

    tables = [t for t in _s1_dispatch_tables(g)
              if fstart in _s1_closure(g, [e["target"] for e in t["entries"]], 2)]
    if not tables:
        return _miss("no-dispatch-table")
    if ctx_failure:
        # This is a genuine dispatch candidate (the pointer slot and a table
        # were found), so an unproven base object is a named refusal.  A site
        # that is not a candidate returned above and still falls through to
        # whatever weaker evidence class it had before.
        if "s1-base-not-table" not in _MUTED:
            return _s1_refusal(
                "ctx-not-proven-parameter", function=name,
                call_site=hex(site["addr"]),
                operand={"base_reg": base_reg,
                         "member_offset": hex(member_off)},
                context={"type": ctx_info["type"],
                         "param": ctx_info.get("param"),
                         "index": want,
                         "register": table_object_reg,
                         "slot_load": hex(insns[slot_load_idx][0])
                         if slot_load_idx < len(insns) else None})
        ctx_origin = {"kind": "param", "index": want, "via": "mutation"}
    cohort = set()
    writers = set()
    paired = []
    for t in tables:
        roots = [e["target"] for e in t["entries"] if e["id"] == 1]
        if len(roots) != 1:
            return _s1_refusal("dispatch-without-single-newctx", function=name,
                               call_site=hex(site["addr"]),
                               dispatch_tables=[hex(t["addr"])],
                               chain=chain)
        cohort |= _s1_closure(g, [e["target"] for e in t["entries"]], 2)
        t_writers = _s1_closure(g, roots, 2)
        writers |= t_writers
        t["_writers"] = t_writers
        paired.append({"table": t["symbol"], "addr": hex(t["addr"]),
                       "newctx": g.funcs.get(roots[0], hex(roots[0]))})
    if reachable is not None:
        callers = _direct_call_index(g).get(fstart, [])
        outside = sorted({c for c, _i, _a in callers
                          if c in reachable and c not in cohort})
        if outside and "s1-caller-outside-cohort" not in _MUTED:
            return _s1_refusal("caller-outside-cohort", function=name,
                               call_site=hex(site["addr"]),
                               callers=[g.funcs.get(c, hex(c)) for c in outside],
                               dispatch_tables=[hex(t["addr"]) for t in tables],
                               chain=chain)

    type_candidates = []
    considered = []
    for cand in pointer_fields:
        type_candidates.append(cand)
        for cast_type in _s1_cast_types(g, ctx_info, cand["field"]):
            layout = _s1_struct_layout(g, cast_type)
            if layout is None:
                considered.append({"object": ctx_info["type"],
                                   "field": cand["field"],
                                   "table_type": cast_type,
                                   "reason": "cast target has no decidable layout"})
                continue
            type_candidates.append({"field": cand["field"],
                                    "table_type": cast_type,
                                    "layout": layout,
                                    "declaration": cand["declaration"],
                                    "via_cast": True})
    candidates = []
    for cand in type_candidates:
        if member_off not in {r["offset"] for r in cand["layout"]["fields"]}:
            considered.append({"object": ctx_info["type"],
                               "field": cand["field"],
                               "table_type": cand["table_type"],
                               "reason": ("member offset is not a field of "
                                          "this layout")})
            continue
        base_union = _s1_declared_instances(g, cand["table_type"])
        instances = dict(base_union["instances"])
        used_offsets = [r["offset"] for r in cand["layout"]["fields"]]
        found = {}
        unaccounted = []
        outside_writers = []
        unproven_base = []
        excluded_base = []
        writer_rows = []
        outside_rows = []
        for wf in sorted(writers):
            for store in _s1_scalar_stores(g, wf, slot_off):
                bq = _s1_store_base_witness(g, wf, store,
                                            ctx_info["type"], slot_off)
                if bq.get("excluded"):
                    excluded_base.append(bq)
                    continue
                if not bq.get("qualified"):
                    unproven_base.append(bq)
                    continue
                value, kind = _s1_store_value(g, wf, store["index"],
                                              store["src"], slot_off)
                writer_rows.append((wf, store, value, kind, bq))
        for cf in sorted(cohort - writers):
            for store in _s1_scalar_stores(g, cf, slot_off):
                bq = _s1_store_base_witness(g, cf, store,
                                            ctx_info["type"], slot_off)
                if bq.get("excluded"):
                    excluded_base.append(bq)
                    continue
                if not bq.get("qualified"):
                    unproven_base.append(bq)
                    continue
                value, kind = _s1_store_value(g, cf, store["index"],
                                              store["src"], slot_off)
                outside_rows.append((cf, store, value, kind, bq))
        # Admit the concrete first-field-compatible types the writers store;
        # the instance union is then the base's declared instances plus every
        # admitted type's declared instances.  A stored type that is not
        # admitted stays unaccounted and refuses the site: it is never
        # silently unioned into the set.
        seen_types = set()
        for _f, _s, value, kind, _b in writer_rows + outside_rows:
            if kind in ("immediate", "static") and isinstance(value, int):
                st = _s1_static_type(g, value)
                if st:
                    seen_types.add(st)
        prefix_types = {}
        for tn in sorted(seen_types):
            if "s1-prefix-types" in _MUTED:
                break
            w = _s1_prefix_witness(g, tn, cand["table_type"], used_offsets)
            if w is None:
                continue
            prefix_types[tn] = w
            more = _s1_declared_instances(g, tn).get("instances") or {}
            for a, rec in more.items():
                instances.setdefault(a, rec)
        if not instances:
            considered.append({"object": ctx_info["type"],
                               "field": cand["field"],
                               "table_type": cand["table_type"],
                               "reason": ("no declared static instance in "
                                          "this image")})
            continue
        for wf, store, value, kind, bq in writer_rows:
            if kind == "identity":
                found.setdefault((wf, store["addr"]), {
                    "function": g.funcs.get(wf, hex(wf)),
                    "store_site": hex(store["addr"]),
                    "value": "identity(reload of the same slot)",
                    "kind": kind})
                continue
            if value is None or kind not in ("immediate", "static"):
                unaccounted.append({"function": g.funcs.get(wf, hex(wf)),
                                    "store_site": hex(store["addr"]),
                                    "reason": kind})
                continue
            if value not in instances:
                if "s1-undeclared-store" not in _MUTED:
                    unaccounted.append({"function": g.funcs.get(wf, hex(wf)),
                                        "store_site": hex(store["addr"]),
                                        "value": hex(value),
                                        "reason": ("not a declared instance "
                                                   "of an admitted type for "
                                                   + cand["table_type"])})
                continue
            found[(wf, store["addr"])] = {
                "function": g.funcs.get(wf, hex(wf)),
                "store_site": hex(store["addr"]),
                "value": hex(value), "kind": kind,
                "base_origin": bq.get("origin"),
                "base_witness": bq.get("witness")}
        for cf, store, value, kind, bq in outside_rows:
            if kind == "identity":
                continue
            if value is None or kind not in ("immediate", "static") \
                    or value not in instances:
                outside_writers.append({
                    "function": g.funcs.get(cf, hex(cf)),
                    "store_site": hex(store["addr"]),
                    "value": (hex(value) if value is not None else kind)})
            else:
                found[(cf, store["addr"])] = {
                    "function": g.funcs.get(cf, hex(cf)),
                    "store_site": hex(store["addr"]),
                    "value": hex(value), "kind": kind,
                    "base_origin": bq.get("origin"),
                    "base_witness": bq.get("witness")}
        if unproven_base:
            candidates.append({"candidate": cand, "ok": False,
                               "unaccounted": unaccounted,
                               "outside": outside_writers,
                               "unproven_base": unproven_base,
                               "excluded_base": excluded_base,
                               "prefix_types": prefix_types,
                               "instances": instances,
                               "found": found})
            continue
        if unaccounted or outside_writers:
            candidates.append({"candidate": cand, "ok": False,
                               "unaccounted": unaccounted,
                               "outside": outside_writers,
                               "unproven_base": [],
                               "excluded_base": excluded_base,
                               "prefix_types": prefix_types,
                               "instances": instances,
                               "found": found})
            continue
        if not found:
            candidates.append({"candidate": cand, "ok": False,
                               "unaccounted": [], "outside": [],
                               "unproven_base": [],
                               "excluded_base": excluded_base,
                               "prefix_types": prefix_types,
                               "instances": instances, "found": {},
                               "reason": "no-writer"})
            continue
        # Each matched dispatch table must contribute at least one declared
        # instance.  A table whose constructor contributed nothing leaves the
        # instance set partial; that is refused, never unioned.
        per_table = []
        for t in tables:
            tw = t["_writers"]
            vals = [v for (wf, _sa), v in found.items()
                    if wf in tw and v["value"].startswith("0x")]
            per_table.append(bool(vals))
        if not all(per_table) and "s1-partial-instances" not in _MUTED:
            candidates.append({"candidate": cand, "ok": False,
                               "unaccounted": [], "outside": [],
                               "unproven_base": [],
                               "excluded_base": excluded_base,
                               "prefix_types": prefix_types,
                               "instances": instances,
                               "found": found,
                               "reason": "partial-instance-set"})
            continue
        candidates.append({"candidate": cand, "ok": True,
                           "unaccounted": [], "outside": [],
                           "unproven_base": [],
                           "excluded_base": excluded_base,
                           "prefix_types": prefix_types,
                           "instances": instances,
                           "found": found})

    good = [c for c in candidates if c["ok"]]
    if len(good) != 1:
        if good:
            reason = "ambiguous-field"
        elif not candidates:
            reason = "no-declared-instance-type"
        elif any(c.get("unproven_base") for c in candidates):
            # A store wrote the slot but its base object is not proven to be the
            # declared context type.  It is neither a different object (which
            # would be excluded) nor a member of the cohort: the writer set is
            # open, so the site refuses.
            reason = "unproven-cohort-store"
        elif any(c.get("outside") for c in candidates):
            # A reachable cohort function other than the constructor's closure
            # stores to the same displacement; the store's base object is not
            # established as the context type, so the writer set is open.
            reason = "unproven-cohort-store"
        elif any(c.get("unaccounted") for c in candidates):
            # A writer stores a value that is not a declared instance of the
            # effective table type (the base-typed, generic store case).
            reason = "unaccounted-writer-store"
        elif any(c.get("reason") == "partial-instance-set"
                 for c in candidates):
            reason = "partial-instance-set"
        elif any(c.get("reason") == "no-writer" for c in candidates):
            reason = "no-writer"
        else:
            reason = "no-complete-instance-candidate"
        return _s1_refusal(reason, function=name, call_site=hex(site["addr"]),
                           operand={"base_reg": base_reg,
                                    "member_offset": hex(member_off)},
                           chain=chain,
                           dispatch_tables=[hex(t["addr"]) for t in tables],
                           considered_types=considered,
                           candidates=[{"object": ctx_info["type"],
                                        "field": c["candidate"]["field"],
                                        "table": c["candidate"]["table_type"],
                                        "ok": c["ok"],
                                        "unaccounted_table_pointers":
                                            c.get("unaccounted", []),
                                        "stores_outside_writers":
                                            c.get("outside", []),
                                        "unproven_base_stores":
                                            c.get("unproven_base", []),
                                        "excluded_different_object_stores":
                                            c.get("excluded_base", []),
                                        "prefix_compatible_types":
                                            sorted(c.get("prefix_types", {})),
                                        "reason": c.get("reason")}
                                       for c in candidates])
    chosen = good[0]
    cand = chosen["candidate"]
    ulayout = cand["layout"]
    declared = _s1_declared_instances(g, cand["table_type"])
    instances = chosen.get("instances") or declared["instances"]

    instance_rows = []
    targets = set()
    unaccounted_tables = []
    shape_failures = []
    for addr in sorted({int(v["value"], 16) for v in chosen["found"].values()
                        if v["value"].startswith("0x")}):
        inst = instances.get(addr)
        if inst is None:
            continue
        inst_type = _s1_static_type(g, addr)
        is_prefix = (inst_type is not None
                     and inst_type != cand["table_type"])
        prefix_w = (chosen.get("prefix_types", {}).get(inst_type)
                    if is_prefix else None)
        obj_type = ((prefix_w or {}).get("prefix_object_type")
                    or cand["table_type"])
        olayout = _s1_struct_layout(g, obj_type) or ulayout
        sec = g.section_of(addr)
        if sec not in S1_IMMUTABLE_SECTIONS and "s1-mutable-table" not in _MUTED:
            unaccounted_tables.append({"table": inst["name"],
                                       "addr": hex(addr),
                                       "section": sec})
            continue
        members = {}
        derived_but_undeclared = []
        declared_but_absent = []
        for row in olayout["fields"]:
            members[hex(row["offset"])] = None
        size = None
        for raw in (getattr(g, "names_at", {}) or {}).get(addr, ()):
            sym = (raw or "").split("@")[0]
            if sym in (getattr(g, "sym_sizes", {}) or {}):
                size = g.sym_sizes[sym]
                break
        if size is None:
            shape_failures.append({"table": inst["name"],
                                   "reason": "no symbol size"})
            continue
        derived = [o for o in range(0, size, 8)]
        declared_offs = [r["offset"] for r in olayout["fields"]]
        if is_prefix and size > olayout["size"]:
            # The instance's declared type carries the base as its first
            # field: only the base prefix belongs to this field's layout.  The
            # prefix's own offsets were checked against the base layout when
            # the type was admitted, so compare the base prefix here and
            # record the extra members rather than refusing them.
            derived = [o for o in range(0, olayout["size"], 8)]
        elif size != olayout["size"]:
            derived_but_undeclared = [o for o in derived if o not in declared_offs]
            declared_but_absent = [o for o in declared_offs if o not in derived]
            if "s1-shape-mismatch" not in _MUTED:
                shape_failures.append({
                    "table": inst["name"],
                    "derived_size": hex(size),
                    "declared_size": hex(ulayout["size"]),
                    "derived_but_undeclared": [hex(o) for o in derived_but_undeclared],
                    "declared_but_absent": [hex(o) for o in declared_but_absent]})
                continue
        member_ok = True
        for row in olayout["fields"]:
            vals = g.static_slot(addr + row["offset"])
            ints = {x for x in (vals or ()) if isinstance(x, int)}
            if len(ints) != 1:
                if "s1-shape-mismatch" not in _MUTED:
                    member_ok = False
                members[hex(row["offset"])] = None
                continue
            value = next(iter(ints))
            if value == 0:
                if not row["option"]:
                    if "s1-member-not-function" not in _MUTED:
                        member_ok = False
                else:
                    guard = _s1_null_guard(g, fstart, idx, row["offset"],
                                           base_reg)
                    if guard is None and "s1-null-no-guard" not in _MUTED:
                        member_ok = False
                    else:
                        members[hex(row["offset"])] = {
                            "value": None, "guard": hex(guard) if guard else None}
                continue
            if value not in g.start_set:
                if "s1-member-not-function" not in _MUTED:
                    member_ok = False
                members[hex(row["offset"])] = {"value": hex(value),
                                                "not_function": True}
                continue
            members[hex(row["offset"])] = {"value": hex(value),
                                            "symbol": g.funcs.get(value)}
            if row["offset"] == member_off:
                targets.add(value)
        if not member_ok:
            shape_failures.append({"table": inst["name"],
                                   "reason": "member not an in-image function start"})
            continue
        instance_rows.append({
            "addr": hex(addr), "symbol": inst["symbol"],
            "section": sec, "members": members,
            "declared_type": inst_type or cand["table_type"],
            "prefix_compatible": bool(is_prefix),
            "extra_members_after_base": (
                [hex(o) for o in range(olayout["size"], size, 8)]
                if is_prefix and size > olayout["size"] else []),
            "shape_ok": (not derived_but_undeclared and not declared_but_absent),
        })
    if unaccounted_tables or shape_failures:
        return _s1_refusal("table-shape-or-section", function=name,
                           call_site=hex(site["addr"]),
                           pointer_slot={"object": ctx_info["type"],
                                         "offset": hex(slot_off),
                                         "field": cand["field"]},
                           unaccounted_table_pointers=unaccounted_tables,
                           shape_failures=shape_failures,
                           chain=chain)
    if not instance_rows or not targets:
        return _s1_refusal("no-target-at-member", function=name,
                           call_site=hex(site["addr"]),
                           pointer_slot={"object": ctx_info["type"],
                                         "offset": hex(slot_off),
                                         "field": cand["field"]},
                           member_offset=hex(member_off), chain=chain)
    if len(instance_rows) != len({int(v["value"], 16)
                                  for v in chosen["found"].values()
                                  if v["value"].startswith("0x")}) \
            and "s1-partial-instances" not in _MUTED:
        return _s1_refusal("partial-instance-set", function=name,
                           call_site=hex(site["addr"]),
                           pointer_slot={"object": ctx_info["type"],
                                         "offset": hex(slot_off),
                                         "field": cand["field"]},
                           instances=[r["addr"] for r in instance_rows],
                           chain=chain)
    if member_off == 0 and "s1-mutable-table" in _MUTED:
        pass
    return {
        "schema": S1_WITNESS_SCHEMA,
        "class": "static-table-instance",
        "contract_bounded": False,
        "resolved": True,
        "function": name,
        "call_site": hex(site["addr"]),
        "operand": {"base_reg": base_reg, "member_offset": hex(member_off)},
        "pointer_slot": {"object": ctx_info["type"],
                         "offset": hex(slot_off),
                         "field": cand["field"],
                         "declaration": cand["declaration"]},
        "member": next(({"offset": hex(r["offset"]), "name": r["name"],
                          "type": r["type"]}
                         for r in ulayout["fields"]
                         if r["offset"] == member_off), None),
        "effective_type": {
            "table_type": cand["table_type"],
            "via_cast": bool(cand.get("via_cast")),
            "layout": {"file": ulayout.get("file"),
                       "line": ulayout.get("line"),
                       "size": hex(ulayout["size"])}},
        "instances": instance_rows,
        "stored_by": sorted(chosen["found"].values(),
                            key=lambda r: (r["function"], r["store_site"])),
        "chain": chain,
        "dispatch_tables": paired,
        "conditions": ([
            "field-sensitive-key",
            "base-object-qualified",
            "single-newctx-per-table",
            "caller-in-cohort",
            "declared-instance-writers",
            "instance-union-complete",
        ] + (["prefix-compatible-base"]
             if chosen.get("prefix_types") else [])),
        "completeness": {
            "unaccounted_table_pointers": [],
            "unscanned_writers": [],
            "base_object_qualified": True,
            "excluded_different_object_stores":
                chosen.get("excluded_base", []),
            "prefix_compatible_types":
                chosen.get("prefix_types", {}),
        },
        "targets": [hex(t) for t in sorted(targets)],
        "basis": ("field-sensitive static-table instance dispatch: the base "
                  "register is loaded from one pointer field of the documented "
                  "context type, the dispatch table pairs its constructor, every "
                  "scalar store to that field in the cohort writes a declared "
                  "table, and every table member is an in-image function start"),
    }


# ---- S2b: nested static-instance dispatch (2026-10-31) ----------------- #
#
# A second-level dispatch that S1 cannot see: the context object holds a
# pointer to a static instance of a repr(C) struct of function pointers, and
# the call reads a member of that instance.  The class this removes is
# ``base-slot-partial``: the pointer field is offset-keyed ``open`` because at
# least one store to the same displacement has an unresolved value, even when
# every store whose base object is the declared context type writes a declared
# static instance.
#
# Completeness is established by an image-wide instruction fact, not by an
# absence of evidence: every instruction of every function in the image is
# scanned, and every store that can write the pointer field is either excluded
# as a different object, accounted as a declared instance (or NULL), or refuses
# the site.  A non-scalar store that overlaps the pointer slot also refuses.
# The rule never shrinks the conservative bound on a failure.

NESTED_WITNESS_SCHEMA = "openssl-rs/consumer-closure/nested-static-instance/v1"

_NESTED_SCALAR_STORE = re.compile(
    r"(mov|movq|movabs)\s+(.+),\s*(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)\s*")
_NESTED_NONSCALAR_STORE = re.compile(
    r"(movl|movw|movb|movsd|movss|movups|movupd|movdqu|movdqa|movaps|movapd|"
    r"vmovdqu|vmovdqa|vmovups|vmovupd|vmovaps|movlps|movhps|vmovdqu64|"
    r"vmovdqa64)\s+(.+),\s*(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)\s*")
_NESTED_NONSCALAR_WIDTH = {
    "movl": 4, "movw": 2, "movb": 1, "movsd": 8, "movss": 4,
    "movups": 16, "movupd": 16, "movdqu": 16, "movdqa": 16,
    "movaps": 16, "movapd": 16, "vmovdqu": 16, "vmovdqa": 16,
    "vmovups": 16, "vmovupd": 16, "vmovaps": 16, "vmovdqu64": 16,
    "vmovdqa64": 16, "movlps": 8, "movhps": 8,
}


def _nested_refusal(reason: str, **extra) -> dict:
    rec = {"schema": NESTED_WITNESS_SCHEMA, "class": "nested-static-instance",
           "contract_bounded": False, "resolved": False,
           "refusal": reason}
    rec.update(extra)
    return rec


def _nested_store_index(g: "DsoGraph"):
    """Every store in the image, keyed by the 8-byte slot it can write.

    The fact is the instruction stream itself, so the writer set is complete
    relative to the analysed image: an unobserved writer cannot be silently
    absent.  A store through ``%rsp``/``%rbp`` is a frame operation, not an
    object-field writer, and is not indexed.
    """
    cache = getattr(g, "_nested_store_index_cache", None)
    if cache is not None:
        return cache
    scalar = collections.defaultdict(list)
    nonscalar = collections.defaultdict(list)
    if _has_insns(g):
        for wf, insns in g.precision.insns_by_func.items():
            for i, (addr, text) in enumerate(insns):
                body = text.split("#", 1)[0].strip()
                m = _NESTED_SCALAR_STORE.fullmatch(body)
                if m:
                    base = m.group(4)
                    if base in ("%rsp", "%rbp"):
                        continue
                    try:
                        off = int(m.group(3) or "0", 16)
                    except ValueError:
                        continue
                    scalar[off].append({
                        "function": wf, "index": i, "addr": addr,
                        "src": m.group(2).strip(), "base": base})
                    continue
                m = _NESTED_NONSCALAR_STORE.fullmatch(body)
                if not m:
                    continue
                base = m.group(4)
                if base in ("%rsp", "%rbp"):
                    continue
                try:
                    off = int(m.group(3) or "0", 16)
                except ValueError:
                    continue
                width = _NESTED_NONSCALAR_WIDTH.get(m.group(1), 0)
                if width <= 0:
                    continue
                # A non-scalar store can touch a slot that is not its start.
                first = off & ~7
                for q in range(first, off + width, 8):
                    nonscalar[q].append({
                        "function": wf, "index": i, "addr": addr,
                        "src": m.group(2).strip(), "base": base,
                        "mnemonic": m.group(1), "width": width,
                        "offset": off})
    cache = (dict(scalar), dict(nonscalar))
    g._nested_store_index_cache = cache
    return cache


def _nested_body_cast(g: "DsoGraph", wf: int, decl_type: str):
    """A unique source cast of the writer's entry object to ``decl_type``."""
    src = _s1_writer_source(g, wf)
    if src is None:
        return None
    w = _s1_construct_witness(g, src["span"], decl_type, "body")
    if isinstance(w, dict) and w.get("type"):
        return w
    return w if isinstance(w, dict) and w.get("ambiguous") else None


def _nested_store_base_witness(g: "DsoGraph", wf: int, store: dict,
                               decl_type: str, slot_off: int):
    """Qualify a store's base object, including a c_void body cast.

    ``_s1_store_base_witness_raw`` treats a declared ``*mut c_void`` entry
    parameter as a different object.  That is right for a store on an unrelated
    object and wrong for the recurring provider shape
    ``let ctx = vctx.cast::<ProvCipherCtx>(); (*ctx).hw = ...``.  The cast is a
    source fact about the same register, so it qualifies the base only when the
    declared type is c_void and the writer's body names exactly one compatible
    target.  An ambiguous cast refuses.
    """
    origin = _reg_origin(g, wf, store["index"], _canon(store["base"]))
    if origin.get("kind") == "param":
        src = _s1_writer_source(g, wf)
        sig = _s1_signature(src["span"]) if src else None
        cands = _s1_abi_types(sig, origin.get("index")) if sig else []
        if cands and all("c_void" in str(c.get("type") or "") for c in cands):
            cast = _nested_body_cast(g, wf, decl_type)
            if isinstance(cast, dict) and cast.get("type"):
                return {"qualified": True, "origin": "entry-parameter-cast",
                        "declared_type": cands[0].get("type"),
                        "cast_type": cast.get("type"),
                        "witness": cast.get("witness")}
            if isinstance(cast, dict) and cast.get("ambiguous"):
                return {"qualified": False, "unknown": True,
                        "reason": ("ambiguous body cast to " + decl_type
                                   + ": " + ", ".join(cast["ambiguous"]))}
    return _s1_store_base_witness_raw(g, wf, store, decl_type, slot_off)


def _nested_param_values(g: "DsoGraph", fstart: int, k: int,
                         seen: frozenset = frozenset(), depth: int = 0):
    """Every value an entry parameter can carry, or a named refusal.

    The caller set is the complete set of direct call sites in the image.  A
    function whose address is taken, exported, or named by a relocated slot can
    be entered without a direct call, so its argument domain is not finite and
    the rule refuses.  Every argument value is read from the semantic call
    index; a forwarded parameter is followed to its own callers.  No value is
    guessed from a declared symbol name.
    """
    key = (fstart, k)
    if depth > 6 or key in seen:
        return None, "parameter-recursion"
    if getattr(g, "taken_code", None) and fstart in g.taken_code:
        return None, "parameter-address-taken"
    exported = {a for a in (getattr(g, "dynamic_defs", {}) or {}).values()}
    if fstart in exported:
        return None, "parameter-exported"
    for vals in (getattr(g, "slot_funcs", {}) or {}).values():
        if fstart in vals:
            return None, "parameter-in-relocated-slot"
    idx = _semantic_call_index(g)
    rows = idx.get(fstart) or {}
    callers = {(c, a) for c, _i, a in _callers_of(g, fstart)}
    if not rows or set(rows) != callers:
        return None, "parameter-caller-set-incomplete"
    out = set()
    for (caller, _call_site), row in rows.items():
        if k < len(_ARGREGS):
            v = row["args"][k] if k < len(row["args"]) else None
        else:
            j = k - len(_ARGREGS)
            stack = row.get("stack") or ()
            v = stack[j] if j < len(stack) else None
        if v is None or v.is_top():
            return None, "parameter-open-argument"
        for comp in v.s:
            if isinstance(comp, int):
                out.add(comp)
            elif isinstance(comp, tuple) and comp[0] == "arg":
                sub, why = _nested_param_values(
                    g, caller, comp[1], seen | {key}, depth + 1)
                if sub is None:
                    return None, why
                out |= sub
            else:
                return None, "parameter-non-image-value"
    return out, None


_NESTED_CONST_TABLE_MAX = 4096


def _nested_data_symbol(g: "DsoGraph", addr: int):
    """The immutable data symbol containing ``addr``, or None.

    A local Rust ``const`` table is materialised in ``.data.rel.ro``/``.rodata``
    under a linker-generated whole-object symbol (``anon.``... or the item's own
    name).  Its size is the length times the element stride, so the containing
    symbol is what makes the table's length known.
    """
    cache = getattr(g, "_nested_data_symbol_cache", None)
    if cache is None:
        rows = []
        sym_sizes = getattr(g, "sym_sizes", {}) or {}
        for start, name in (getattr(g, "all_syms", {}) or {}).items():
            if start in (getattr(g, "start_set", set()) or set()):
                continue
            size = sym_sizes.get((name or "").split("@")[0])
            if not size or size <= 0:
                continue
            sec = g.section_of(start)
            if sec not in S1_IMMUTABLE_SECTIONS:
                continue
            rows.append((start, size, name, sec))
        rows.sort()
        cache = rows
        g._nested_data_symbol_cache = cache
    best = None
    for start, size, name, sec in cache:
        if start <= addr < start + size:
            best = (start, size, name, sec)
        elif start > addr:
            break
    return best


def _nested_const_table_at(g: "DsoGraph", addr: int, stride: int,
                           member_off: int):
    """The constant table containing ``addr``, with every element checked.

    The rule is not specific to one Rust type: a value is a finite set of
    addresses into a constant table when (a) the containing immutable data
    symbol's size is a whole multiple of the element stride, (b) the observed
    address is an element start, and (c) the member the call reads is an
    in-image function start in *every* element.  The length is derived from the
    symbol size, not from the observed ``lea``s, so the complete element set is
    returned even when only some elements are selected by the writer's phi.
    """
    if stride is None or stride <= 0:
        return {"ok": False, "reason": "local-const-table-stride-unknown"}
    row = _nested_data_symbol(g, addr)
    if row is None:
        return {"ok": False, "reason": "local-const-table-not-in-image"}
    base, size, name, sec = row
    rel = addr - base
    if rel % stride or size % stride:
        return {"ok": False, "reason": "local-const-table-shape-unknown",
                "base": base, "table": name, "size": size, "stride": stride}
    count = size // stride
    if count < 1 or count > _NESTED_CONST_TABLE_MAX:
        return {"ok": False,
                "reason": "local-const-table-length-out-of-range",
                "base": base, "table": name, "count": count}
    elements = [base + k * stride for k in range(count)]
    for elem in elements:
        vals = g.static_slot(elem + member_off)
        ints = {x for x in (vals or ()) if isinstance(x, int)}
        if len(ints) != 1:
            return {"ok": False,
                    "reason": "local-const-table-element-unresolved",
                    "base": base, "table": name, "element": hex(elem),
                    "member_offset": hex(member_off)}
        value = next(iter(ints))
        if value == 0 or value not in g.start_set:
            return {"ok": False,
                    "reason": "local-const-table-element-not-function",
                    "base": base, "table": name, "element": hex(elem),
                    "member_offset": hex(member_off),
                    "value": hex(value)}
    return {"ok": True, "base": base, "size": size, "stride": stride,
            "count": count, "elements": elements, "symbol": name,
            "section": sec}


def _nested_lea_addrs(g: "DsoGraph", fstart: int, idx: int, reg: str,
                      depth: int = 0, seen: frozenset = frozenset()):
    """Addresses a register can hold when every definition is a ``lea``.

    A CFG merge (a phi) has several reaching definitions and a ``cmov`` select
    has two possible sources.  Both are finite only when every alternative is a
    ``lea``; any other definition returns None so the caller keeps its previous
    refusal rather than guessing.  A merge is never partially enumerated.
    """
    key = (fstart, idx, reg)
    if depth > 6 or key in seen:
        return None
    defs = _reaching_defs(g, fstart, idx, reg)
    if defs is None or not defs:
        return None
    out = set()
    for k in sorted(defs):
        if k is None or k < 0:
            return None
        text = _insn(g, fstart, k)
        mn, _rest, ops = _insn_parts(text)
        if mn == "lea":
            addr = _insn_comment_addr(text)
            if addr is None:
                return None
            out.add(addr)
            continue
        if mn.startswith("cmov") and len(ops) >= 2:
            a = _nested_lea_addrs(g, fstart, k, _canon(ops[0]), depth + 1,
                                  seen | {key})
            b = _nested_lea_addrs(g, fstart, k, _canon(ops[1]), depth + 1,
                                  seen | {key})
            if a is None or b is None:
                return None
            out |= a | b
            continue
        if mn in ("mov", "movq") and len(ops) >= 2 \
                and (ops[0] in _REGS or ops[0] in _SUBREG):
            sub = _nested_lea_addrs(g, fstart, k, _canon(ops[0]), depth + 1,
                                    seen | {key})
            if sub is None:
                return None
            out |= sub
            continue
        return None
    return out or None


def _nested_store_value(g: "DsoGraph", wf: int, store: dict, slot_off: int,
                        *, table_stride: int | None = None,
                        table_member_off: int | None = None):
    """Values a store can write, or a named refusal.

    ``identity`` is a reload of the same slot and adds no new target.  A phi of
    ``lea``s into one local constant table resolves to every element of that
    table (the length comes from the containing symbol, so the set is complete,
    not just the observed branches).  Any other value that is not an immediate,
    a static address, or a finite parameter domain is a refusal; it is never
    dropped from the writer set.
    """
    src = store["src"]
    if (src in _REGS or src in _SUBREG) and table_stride:
        addrs = _nested_lea_addrs(g, wf, store["index"], _canon(src))
        # A declared static instance keeps its existing (source-typed) path.  The
        # local-table rule owns only addresses with no declared static type;
        # this is what keeps it from re-interpreting an ordinary static table.
        if addrs and all(_s1_static_type(g, a) is None for a in addrs):
            tables = [_nested_const_table_at(
                g, a, table_stride,
                table_member_off if table_member_off is not None else 0)
                for a in sorted(addrs)]
            base = tables[0].get("base")
            if base is not None and all(t.get("base") == base
                                        for t in tables):
                first = tables[0]
                if not first.get("ok"):
                    # Only an established table whose length is known can
                    # refuse on an element.  A shape we could not establish is
                    # not evidence of a table, so the previous refusal stands.
                    if first.get("reason") in (
                            "local-const-table-element-unresolved",
                            "local-const-table-element-not-function"):
                        return None, first.get("reason")
                elif set(addrs) <= set(first["elements"]):
                    return set(first["elements"]), None
                else:
                    return None, "phi-lea-not-a-table-element"
    if src in _REGS or src in _SUBREG:
        origin = _reg_origin(g, wf, store["index"], _canon(src))
        if origin.get("kind") == "param":
            return _nested_param_values(g, wf, origin["index"])
        if origin.get("kind") == "load":
            spill = _stack_param(g, wf, origin["at"], origin["offset"],
                                 origin["base_reg"])
            if spill is not None:
                return _nested_param_values(g, wf, spill["index"])
    value, kind = _s1_store_value(g, wf, store["index"], src, slot_off)
    if kind == "identity":
        return set(), None
    if kind in ("immediate", "static"):
        return {value}, None
    return None, kind


def _nested_whole_struct_copy(g: "DsoGraph", wf: int, store: dict,
                              owner_type: str, ulayout: dict):
    """Witness for a same-owner whole-object copy that adds no target value.

    A non-scalar store is such a copy only when (a) the destination base is an
    object of exactly ``owner_type``, (b) the store starts at offset 0 and its
    width covers the whole layout, and (c) the copied register is loaded from
    the same offset of another object proven to be ``owner_type``.  Such a copy
    propagates the field bytes of a same-typed source; the field's own writers
    already produce every value it can carry, so it cannot synthesise a new
    target and does not widen the proven set.  A copy without the source
    witness is not given this argument and still refuses.
    """
    if store.get("offset") != 0:
        return None
    if (store.get("width") or 0) < (ulayout.get("size") or 0):
        return None
    dest = _nested_owner_type(g, wf, store["index"],
                              _canon(store["base"]))
    if dest.get("kind") != "type" or dest.get("type") != owner_type:
        return None
    src = (store.get("src") or "").strip()
    if not src.startswith("%xmm"):
        return None
    insns = g.precision.insns_by_func.get(wf, ())
    for k in range(store["index"] - 1, max(-1, store["index"] - 12), -1):
        mn, _rest, ops = _insn_parts(insns[k][1])
        if len(ops) != 2 or not mn.startswith(
                ("movups", "movaps", "movdqu", "movdqa")):
            continue
        if ops[1].strip() != src:
            continue
        mo = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)",
                          ops[0].strip())
        if not mo:
            continue
        off = int(mo.group(1), 16) if mo.group(1) else 0
        if off != store["offset"]:
            continue
        source = _nested_owner_type(g, wf, k, _canon(mo.group(2)))
        if source.get("kind") == "type" and source.get("type") == owner_type:
            return {"origin": "same-owner-whole-object-copy",
                    "source_load": hex(insns[k][0]),
                    "source_owner": owner_type,
                    "width": store["width"],
                    "layout_size": ulayout["size"],
                    "dest_origin": dest.get("origin"),
                    "source_origin": source.get("origin"),
                    "source_symbol_owner":
                        source.get("type") if source.get("symbol") else None,
                    "source_symbol_basis": source.get("symbol_basis")}
        return None
    return None


_NESTED_RAW_STORE = (
    "ptr::write", "write_volatile", "copy_nonoverlapping", "memcpy",
    "memmove", "transmute", "ptr::copy",
)


def _nested_source_could_write(g: "DsoGraph", wf: int, field: str,
                               ctx_type: str, pointee: str, slot_off: int):
    """A source-level negative witness for an unproven-base store.

    Returns ``(True, why)`` when the writer's source could name this field
    (in which case the store is a real writer and the site must refuse), and
    ``(False, why)`` only when the function never names the field, the context
    type, the pointee type or the byte offset and contains no raw-store
    primitive.  A missing source is never a negative witness.
    """
    src = _s1_writer_source(g, wf)
    if src is None:
        return True, "no-source"
    body = ((src.get("span") or {}).get("body") or "") \
        + "\n" + ((src.get("span") or {}).get("header") or "")
    off = hex(slot_off)
    needles = {field, ctx_type, pointee, off, off.upper().replace("0X", "0x")}
    if any(n and n in body for n in needles):
        return True, "source-names-field-or-type"
    if any(r in body for r in _NESTED_RAW_STORE):
        return True, "source-has-raw-store-primitive"
    return False, "source-omits-field-type-and-offset"


_NESTED_MAX_CHAIN = 4


# Allocation-size attribution (S2b).  A store whose base register is the
# result of an in-function allocation is qualified by the requested block
# size, never by proximity: the base must be the allocation result itself and
# exactly one declared layout of that size may cover the store displacement.
_NESTED_ALLOCATORS = {
    "CRYPTO_zalloc": (0,),
    "CRYPTO_malloc": (0,),
    "malloc": (0,),
    "__libc_malloc": (0,),
    "__rust_alloc": (0,),
    "__rust_alloc_zeroed": (0,),
    "alloc": (0,),
    "calloc": (0, 1),
    "__libc_calloc": (0, 1),
}

_S1_DECL_PRIM = {
    "usize": (8, 8), "isize": (8, 8), "size_t": (8, 8),
    "ssize_t": (8, 8), "u64": (8, 8), "i64": (8, 8),
    "uint64_t": (8, 8), "int64_t": (8, 8), "c_ulong": (8, 8),
    "c_long": (8, 8), "c_uint": (4, 4), "c_int": (4, 4),
    "u32": (4, 4), "i32": (4, 4), "uint32_t": (4, 4),
    "int32_t": (4, 4), "c_ushort": (2, 2), "u16": (2, 2),
    "c_short": (2, 2), "c_uchar": (1, 1), "u8": (1, 1),
    "i8": (1, 1), "c_char": (1, 1),
}


def _s1_decl_defs(g: "DsoGraph"):
    """Every declared struct/union definition, in one source pass.

    ``_s1_struct_defs`` re-scans the whole source tree per type name.  The
    allocation-size rule needs the complete declared-type population, so the
    scan is done once and cached; the records carry the explicit
    ``#[repr(align(N))]`` that changes a type's size.
    """
    cache = getattr(g, "_s1_decl_defs_cache", None)
    if cache is not None:
        return cache
    out = collections.defaultdict(list)
    pat = re.compile(r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?"
                     r"(struct|union)\s+([A-Za-z_]\w*)\b")
    for path, text in _s1_docs(g).items():
        for m in pat.finditer(text):
            brace = text.find("{", m.end())
            if brace < 0:
                continue
            semi = text.find(";", m.end(), brace)
            if semi >= 0:
                continue
            end = _s1_brace_span(text, brace)
            if end is None:
                continue
            prefix = text[max(0, m.start() - 600):m.start()]
            align = 0
            am = re.search(r"#\[repr\s*\(((?:[^()]|\([^()]*\))*)\)\s*\]"
                           r"(?:\s*#\[[^\]]*\])*\s*$", prefix)
            if am is not None:
                am2 = re.search(r"align\s*\(\s*(\d+)\s*\)", am.group(1))
                if am2:
                    align = int(am2.group(1))
            out[m.group(2)].append({
                "kind": m.group(1), "file": path,
                "line": text.count("\n", 0, m.start()) + 1,
                "body": text[brace + 1:end - 1],
                "repr_c": bool(re.search(r"#\[repr\s*\(\s*C\b", prefix)),
                "explicit_align": align,
            })
    g._s1_decl_defs_cache = dict(out)
    return g._s1_decl_defs_cache


def _s1_decl_type_size(g: "DsoGraph", type_text: str, seen=()):
    """(size, alignment) of a declared type, union/align aware.

    The existing ``_s1_type_size`` deliberately refuses an embedded union and
    does not read ``#[repr(align(N))]``.  Allocation attribution needs the
    actual ``size_of::<T>()`` for the whole declared population, so this
    variant resolves a union as its widest member and honours an explicit
    alignment; it is otherwise the same declared-type arithmetic.
    """
    t = " ".join((type_text or "").split())
    if not t:
        return None
    if t.startswith("Option<") and t.endswith(">"):
        inner = t[len("Option<"):-1].strip()
        if "fn" in inner:
            return (8, 8)
        alias = _s1_type_alias(g, inner) or _s1_type_alias(
            g, inner.split("::")[-1])
        if alias is not None and _s1_decl_type_size(g, alias, seen) == (8, 8):
            return (8, 8)
        return None
    if "fn" in t:
        return (8, 8)
    if t.startswith("*const") or t.startswith("*mut") or t.startswith("&"):
        return (8, 8)
    if t in _S1_DECL_PRIM:
        return _S1_DECL_PRIM[t]
    m = re.fullmatch(r"\[(.+);\s*([^\]]+)\]", t)
    if m:
        inner = _s1_decl_type_size(g, m.group(1), seen)
        if inner is None:
            return None
        count_text = m.group(2).strip()
        try:
            count = int(count_text, 0)
        except ValueError:
            count = _s1_eval_int(g, count_text)
        if count is None:
            return None
        return (inner[0] * count, inner[1])
    alias = _s1_type_alias(g, t) or _s1_type_alias(g, t.split("::")[-1])
    if alias is not None and alias != t:
        return _s1_decl_type_size(g, alias, seen + (t,))
    if t in seen or len(seen) > 8:
        return None
    layout = _s1_decl_layout(g, t, seen)
    if layout is None:
        return None
    return (layout["size"], layout["align"])


def _s1_decl_layout(g: "DsoGraph", type_name: str, seen=()):
    """Declared layout of one struct/union, or None.

    Returns ``{"size", "align", "fields": [{"name", "offset", "size",
    "type"}]}``.  A struct keeps the existing decidable rule (unique
    definition, ``repr(C)`` or homogeneous fields); a union is admitted only
    with ``repr(C)`` and is sized as its widest member.
    """
    if not type_name or type_name in seen or len(seen) > 8:
        return None
    cache = getattr(g, "_s1_decl_layout_cache", None)
    if cache is None:
        cache = {}
        g._s1_decl_layout_cache = cache
    if type_name in cache:
        return cache[type_name]
    defs = _s1_decl_defs(g).get(type_name) or []
    if len(defs) != 1:
        cache[type_name] = None
        return None
    d = defs[0]
    fields = _s1_split_fields(d["body"])
    if not fields:
        cache[type_name] = None
        return None
    infos = []
    for name, ftype in fields:
        info = _s1_decl_type_size(g, ftype, seen + (type_name,))
        if info is None:
            cache[type_name] = None
            return None
        infos.append((name, ftype, info[0], info[1]))
    if d["kind"] == "union":
        if not d["repr_c"]:
            cache[type_name] = None
            return None
        align = max([a for _n, _t, _s, a in infos] + [d["explicit_align"]])
        size = max(s for _n, _t, s, _a in infos)
        size = (size + align - 1) // align * align
        rows = [{"name": n, "offset": 0, "size": s, "type": t}
                for n, t, s, _a in infos]
        out = {"name": type_name, "size": size, "align": align,
               "fields": rows, "kind": "union"}
        cache[type_name] = out
        return out
    homogeneous = (len({(s, a) for _n, _t, s, a in infos}) == 1
                   and infos[0][2] == infos[0][3])
    if not d["repr_c"] and not homogeneous:
        cache[type_name] = None
        return None
    off, align = 0, 1
    rows = []
    for name, ftype, size, falign in infos:
        align = max(align, falign)
        off = (off + falign - 1) // falign * falign
        rows.append({"name": name, "offset": off, "size": size,
                     "type": ftype})
        off += size
    align = max(align, d["explicit_align"])
    size = (off + align - 1) // align * align
    out = {"name": type_name, "size": size, "align": align,
           "fields": rows, "kind": "struct"}
    cache[type_name] = out
    return out


def _s1_decl_layout_index(g: "DsoGraph"):
    """Declared layout population, grouped by ``size_of::<T>()``."""
    cache = getattr(g, "_s1_decl_layout_index_cache", None)
    if cache is not None:
        return cache
    index = collections.defaultdict(list)
    for name in sorted(_s1_decl_defs(g)):
        layout = _s1_decl_layout(g, name)
        if layout is not None:
            index[layout["size"]].append((name, layout))
    g._s1_decl_layout_index_cache = dict(index)
    return g._s1_decl_layout_index_cache


def _s1_decl_candidates(g: "DsoGraph", size: int, offset: int, width: int):
    """Declared layouts of exactly ``size`` with a field covering the store."""
    out = []
    for name, layout in _s1_decl_layout_index(g).get(size, ()):
        row = next((f for f in layout["fields"]
                    if f["offset"] <= offset
                    and offset + width <= f["offset"] + f["size"]), None)
        if row is not None:
            out.append((name, row))
    return out


def _nested_alloc_symbol(g: "DsoGraph", fstart: int, idx: int):
    """Allocator symbol a call instruction invokes, or None.

    A direct call is named by its annotation.  A call through a relocation
    slot is named by the slot's relocation symbol, never by objdump's nearest
    symbol-plus-offset comment.
    """
    text = _insn(g, fstart, idx)
    mn, rest, _ops = _insn_parts(text)
    if not mn.startswith("call"):
        return None
    names = set()
    if rest.startswith("*"):
        slot = _insn_comment_addr(text)
        if slot is not None:
            info = _semantic_slot(g, slot)
            if info.get("kind") == "relocation":
                names |= {row["symbol"].split("@")[0]
                          for row in info.get("symbols") or ()}
    else:
        m = re.search(r"<([^>]+)>", text)
        if m:
            names.add(m.group(1).split("@")[0])
    for name in sorted(names):
        if name in _NESTED_ALLOCATORS:
            return name
    return None


def _nested_alloc_size(g: "DsoGraph", fstart: int, idx: int, depth: int = 0):
    """Requested block size of an allocation call, or None.

    The size is the call's first argument (``calloc``'s first two, multiplied)
    and must be a single-provenance integer.  A dynamic or open size is not
    decidable and keeps the refusal; it is never guessed.
    """
    if depth > 8:
        return None
    symbol = _nested_alloc_symbol(g, fstart, idx)
    if symbol is None:
        return None
    args = _NESTED_ALLOCATORS[symbol]
    values = []
    for k in args:
        origin = _reg_origin(g, fstart, idx, _ARGREGS[k], depth + 1)
        if origin.get("kind") != "int" or origin.get("value", 0) <= 0:
            return None
        values.append(origin["value"])
    size = values[0]
    for value in values[1:]:
        if size > (1 << 63) // value:
            return None
        size *= value
    return {"symbol": symbol, "size": size, "call_site": idx}


def _nested_alloc_owner(g: "DsoGraph", size: int, offset: int, width: int):
    """Unique declared type for an allocation-backed store, or a refusal."""
    cands = _s1_decl_candidates(g, size, offset, width)
    names = sorted({name for name, _row in cands})
    if len(names) == 1:
        name = names[0]
        row = next(row for cand, row in cands if cand == name)
        return {"kind": "type", "type": name,
                "origin": "allocation-size", "allocation_size": size,
                "allocation_field": row["name"],
                "allocation_field_offset": row["offset"]}
    if not names:
        return {"kind": "unknown",
                "why": (f"allocation-size {size:#x} has no declared layout "
                        f"covering {offset:#x}")}
    return {"kind": "unknown",
            "why": (f"allocation-size {size:#x} is ambiguous at {offset:#x}: "
                    + ", ".join(names)),
            "candidates": names}


def _nested_struct_type(g: "DsoGraph", type_text: str):
    """Named repr(C) struct a declared pointer type denotes, or None.

    A decidable *byte layout* is not required here: an owner type only has to
    be a declared struct so the (type, offset) field key is meaningful.  The
    rules that need offsets (member lookup, prefix compatibility) ask for the
    layout and refuse when it cannot be decided.
    """
    t = " ".join((type_text or "").split())
    if t.startswith("Option<") and t.endswith(">"):
        t = t[len("Option<"):-1].strip()
    if not (t.startswith("*") or t.startswith("&")):
        return None
    name = _s1_pointee(t)
    if not name or name in ("c_void", "void"):
        return None
    owner = _s1_resolve_type(g, t) or name
    return owner if _s1_struct_fields(g, owner) is not None else None


def _nested_pointee_type(g: "DsoGraph", field_type: str):
    """Pointee struct type of a pointer field, or None.

    A field whose declared type is an opaque pointer (``*mut c_void``) is not
    resolved here: the cast that makes it concrete is a separate source fact,
    and guessing one through an inlined callee is exactly what this rule does
    not do.
    """
    t = " ".join((field_type or "").split())
    if t.startswith("Option<") and t.endswith(">"):
        t = t[len("Option<"):-1].strip()
    if not (t.startswith("*") or t.startswith("&")):
        return None
    name = _s1_pointee(t)
    if not name or name in ("c_void", "void"):
        return None
    owner = _s1_resolve_type(g, t) or name
    return owner if _s1_struct_layout(g, owner) is not None else None


def _nested_body_type(g: "DsoGraph", wf: int):
    """The one struct type a writer's own body casts the entry object to."""
    src = _s1_writer_source(g, wf)
    if src is None:
        return None
    body = src["span"].get("body") or ""
    casts = set(re.findall(r"\.\s*cast\s*::\s*<\s*([A-Za-z_]\w*)\s*>",
                           body))
    casts |= set(re.findall(r"Owned[A-Za-z_]*\s*::\s*<\s*([A-Za-z_]\w*)\s*>",
                            body))
    types = {t for t in casts if _s1_struct_fields(g, t) is not None}
    return next(iter(types)) if len(types) == 1 else None


_NESTED_RECEIVER_PARAMS = ("self", "&self", "&mut self", "mut self")


def _nested_symbol_path_name(text: str):
    """Last path segment of a demangled type/path, without generics."""
    t = " ".join((text or "").split())
    t = re.sub(r"^(?:&|\*)\s*(?:mut|const)?\s*", "", t)
    t = t.split("<", 1)[0]
    segs = [s for s in t.split("::") if s]
    return segs[-1] if segs else None


def _nested_symbol_split_as(inner: str):
    """Split ``T as Trait`` at a top-level `` as ``."""
    depth = 0
    for i in range(len(inner)):
        ch = inner[i]
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        elif depth == 0 and inner.startswith(" as ", i):
            return inner[:i].strip(), inner[i + 4:].strip()
    return inner.strip(), None


def _nested_symbol_method(demangled: str):
    """``(receiver, trait, method)`` named by a Rust method symbol, or None.

    The receiver type is the only parameter type Rust mangling carries: a
    method ``<T as Trait>::f`` or ``<T>::f`` names ``T``.  A free function's
    parameter list is not encoded.  This parser therefore returns None for
    every non-method symbol rather than guessing one.
    """
    s = re.sub(r"\[[0-9a-f]+\]", "", demangled or "").strip()
    if not s.startswith("<"):
        return None
    depth, end = 0, None
    for i, ch in enumerate(s):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return None
    inner = s[1:end]
    tail = s[end + 1:].lstrip(":")
    m = re.match(r"([A-Za-z_]\w*)", tail)
    if m is None:
        return None
    receiver, trait = _nested_symbol_split_as(inner)
    return receiver, trait, m.group(1)


def _nested_symbol_trait_method(g: "DsoGraph", trait_text: str, method: str):
    """(file, declaration signature) of a trait method, or None.

    The symbol supplies the concrete receiver type; the trait declaration
    supplies the *shape* of the method.  Both are needed: the symbol does not
    say which parameter a register carries, and a receiver is only the first
    argument when the return value does not use the hidden sret slot.  A
    missing or ambiguous declaration is not evidence and yields None.
    """
    trait_name = _nested_symbol_path_name(trait_text)
    if not trait_name:
        return None
    path = None
    root = _repo_root(g)
    if root is not None:
        t = re.sub(r"\[[0-9a-f]+\]", "", trait_text)
        segs = [s for s in t.split("::") if s]
        if segs and segs[0] == "openssl_rs":
            segs = segs[1:]
        mod = "::".join(segs[:-1])
        if mod:
            fallback = getattr(g, "_s1_module_index", None)
            if fallback is None:
                fallback = build_module_index(root / "src")
                g._s1_module_index = fallback
            path = module_to_file(mod, root / "src", fallback)
    docs = _s1_docs(g)
    paths = [path] if path in docs else list(docs)
    for rel in paths:
        text = docs.get(rel)
        if text is None:
            continue
        tm = re.search(r"\btrait\s+" + re.escape(trait_name) + r"\b", text)
        if tm is None:
            continue
        brace = text.find("{", tm.end())
        if brace < 0:
            continue
        end = _s1_brace_span(text, brace)
        if end is None:
            continue
        body = text[brace + 1:end - 1]
        fm = re.search(r"\bfn\s+" + re.escape(method) + r"\s*\(", body)
        if fm is None:
            continue
        op = body.find("(", fm.end() - 1)
        depth, cp = 0, None
        for i in range(op, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    cp = i
                    break
        if cp is None:
            continue
        sig = _s1_signature({"header": body[fm.start():cp + 1]})
        if sig is None:
            continue
        line = text.count("\n", 0, fm.start()) + 1
        return {"file": rel, "line": line, "sig": sig}
    return None


def _nested_symbol_receiver_owner(g: "DsoGraph", fstart: int, index):
    """Owner type carried by a method symbol's receiver, or None.

    A store base is typed from the symbol only when (a) it is the first entry
    parameter, (b) the enclosing symbol names a trait method receiver, and
    (c) the trait declaration shows that the first parameter is the receiver
    and that the return does not use the hidden sret slot.  Any failure is
    undetermined: no-symbol-found is never treated as a different owner.
    """
    if index != 0:
        return None
    cache = getattr(g, "_nested_symbol_owner_cache", None)
    if cache is None:
        cache = {}
        g._nested_symbol_owner_cache = cache
    key = (fstart, index)
    if key in cache:
        return cache[key]
    out = None
    dm = _s1_demangled(g, fstart)
    method = _nested_symbol_method(dm) if dm else None
    if method is not None:
        receiver, trait, name = method
        rtype = _nested_symbol_path_name(receiver)
        if (rtype and trait
                and _s1_struct_fields(g, rtype) is not None):
            shape = _nested_symbol_trait_method(g, trait, name)
            if shape is not None:
                sig = shape["sig"]
                params = sig.get("params") or []
                first = params[0] if params else ""
                is_receiver = (first in _NESTED_RECEIVER_PARAMS
                               or bool(re.search(r"\bSelf\b", first)))
                if (is_receiver
                        and not _s1_return_uses_sret(sig.get("ret"))):
                    out = {
                        "kind": "type", "type": rtype,
                        "origin": "entry-parameter+symbol-receiver",
                        "symbol_basis": "method-receiver",
                        "symbol": dm,
                        "symbol_trait": _nested_symbol_path_name(trait),
                        "symbol_method": name,
                        "symbol_witness": f"{shape['file']}:{shape['line']}",
                    }
    cache[key] = out
    return out


# Whole-object primitives whose parameter ABI names the pointee type.  A
# monomorphised instantiation carries the element type T as a generic
# argument, and every listed parameter is ``*T``/``*mut T``, so a store
# through that parameter writes a T.  A function outside this table is not
# guessed: a free function's generic arguments do not say which register
# carries which parameter.
_NESTED_SYMBOL_POINTER_PARAMS = {
    "drop_in_place": {0},
    "write": {0},
    "write_volatile": {0},
    "replace": {0},
    "copy_nonoverlapping": {0, 1},
    "copy": {0, 1},
    "memcpy": {0, 1},
    "memmove": {0, 1},
}


def _nested_symbol_no_hash(text: str) -> str:
    return re.sub(r"\[[0-9a-f]+\]", "", text or "")


def _nested_symbol_call_tail(demangled: str):
    """``(name, generic-arguments-or-None)`` of the final call segment.

    Only the *function* segment is parsed.  Generic arguments elsewhere in
    the path belong to a containing impl or type and do not type this
    function's parameters.
    """
    s = _nested_symbol_no_hash(demangled).strip()
    depth, cut = 0, -1
    for i, ch in enumerate(s):
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        elif depth == 0 and s.startswith("::", i):
            cut = i
    tail = s[cut + 2:] if cut >= 0 else s
    m = re.fullmatch(r"([A-Za-z_]\w*)\s*(?:::\s*)?(?:<(.*)>)?", tail)
    if m is None:
        return None, None
    return m.group(1), m.group(2)


def _nested_symbol_split_args(text: str):
    """Split a generic-argument list at top-level commas."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            out.append(text[start:i].strip())
            start = i + 1
    out.append(text[start:].strip())
    return [a for a in out if a]


def _nested_symbol_exact_crate_struct(g: "DsoGraph", text: str):
    """The crate struct named exactly by one generic argument, or None.

    A wrapper (``Option<..>``, a reference, an array, a tuple, another
    generic) is not the pointee itself, so it is not accepted: naming a
    struct *inside* a wrapper does not make the base that struct.
    """
    t = " ".join((text or "").split())
    t = _nested_symbol_no_hash(t)
    if not re.fullmatch(r"openssl_rs(?:::[A-Za-z_]\w*)+", t):
        return None
    name = t.split("::")[-1]
    return name if _s1_struct_layout(g, name) is not None else None


def _nested_symbol_generic_owner(g: "DsoGraph", fstart: int, index):
    """Owner type named by a whole-object primitive's generic argument.

    Applies only when the writer has no Rust source mapping (the symbol is
    then the only attribution available), the symbol is one of the listed
    primitives, and the base is a parameter that primitive declares as
    ``*T``/``*mut T``.  The generic argument must name exactly one declared
    crate struct with a decidable layout.  No type, several types, a wrapper
    or an unmapped type is undetermined and keeps the refusal.
    """
    if index is None or _s1_writer_source(g, fstart) is not None:
        return None
    dm = _s1_demangled(g, fstart)
    if not dm:
        return None
    name, arg_text = _nested_symbol_call_tail(dm)
    params = _NESTED_SYMBOL_POINTER_PARAMS.get(name or "")
    if params is None or index not in params or not arg_text:
        return None
    candidates = set()
    for arg in _nested_symbol_split_args(arg_text):
        owner = _nested_symbol_exact_crate_struct(g, arg)
        if owner is not None:
            candidates.add(owner)
    if len(candidates) != 1:
        return None
    owner = next(iter(candidates))
    return {"kind": "type", "type": owner,
            "origin": "entry-parameter+symbol-generic",
            "symbol_basis": "generic-argument",
            "symbol": dm, "symbol_method": name,
            "symbol_argument": owner}


def _nested_owner_from_param(g: "DsoGraph", fstart: int, index, via: str):
    """Owner type of an entry parameter, or a named unknown."""
    src = _s1_writer_source(g, fstart)
    sig = _s1_signature(src["span"]) if src else None
    cands = _s1_abi_types(sig, index) if sig else []
    types = set()
    for c in cands:
        t = c.get("type") or ""
        owner = _nested_struct_type(g, t)
        if owner is not None:
            types.add(owner)
        elif _s1_pointee(t) in ("c_void", "void"):
            cast = _nested_body_type(g, fstart)
            if cast is not None:
                types.add(cast)
    if len(types) == 1:
        return {"kind": "type", "type": next(iter(types)), "origin": via}
    if not types:
        symbol = _nested_symbol_receiver_owner(g, fstart, index)
        if symbol is None:
            symbol = _nested_symbol_generic_owner(g, fstart, index)
        if symbol is not None:
            return symbol
    return {"kind": "unknown",
            "why": "entry parameter has no unique owner type"}


def _nested_owner_type(g: "DsoGraph", fstart: int, idx: int, reg: str,
                       depth: int = 0, member_off: int | None = None):
    """The (owning type, field) a store base register denotes, or a refusal.

    This is the type side of the field-sensitive index.  It follows declared
    layouts: an entry parameter (with a unique source cast when the parameter
    is opaque), a field load from a proven owner, a constructor return type,
    or a unique allocation of known size.  A chain is followed to its declared
    end; no stored value of an intermediate pointer is inferred.
    """
    if depth > _NESTED_MAX_CHAIN:
        return {"kind": "unknown", "why": "owner-chain depth"}
    origin = _reg_origin(g, fstart, idx, _canon(reg))
    kind = origin.get("kind")
    if kind == "alloc":
        if member_off is None:
            return {"kind": "unknown",
                    "why": "allocation is not the store base"}
        return _nested_alloc_owner(g, origin["size"], member_off, 8)
    if kind == "alloc-unknown":
        return {"kind": "unknown",
                "why": ("allocation-size-unresolved: "
                        + str(origin.get("symbol")))}
    if kind == "param":
        return _nested_owner_from_param(g, fstart, origin.get("index"),
                                        "entry-parameter")
    if kind == "load":
        if origin.get("base_reg") in ("%rsp", "%rbp"):
            spill = _stack_param(g, fstart, origin.get("at"),
                                 origin.get("offset"), origin.get("base_reg"))
            if spill is None:
                return {"kind": "unknown",
                        "why": "frame load is not a parameter spill"}
            return _nested_owner_from_param(g, fstart, spill.get("index"),
                                            "frame-slot")
        outer = _nested_owner_type(g, fstart, origin.get("at"),
                                   origin.get("base_reg"), depth + 1)
        if outer.get("kind") != "type":
            return outer
        layout = _s1_struct_layout(g, outer["type"])
        if layout is None:
            return {"kind": "unknown",
                    "why": "owner layout undecidable"}
        row = next((r for r in layout["fields"]
                    if r["offset"] == origin.get("offset")), None)
        if row is None:
            return {"kind": "unknown",
                    "why": "no declared field at load offset"}
        pointee = _nested_pointee_type(g, row["type"])
        if pointee is None:
            return {"kind": "unknown",
                    "why": "field is not a pointer to a decidable struct"}
        return {"kind": "type", "type": pointee, "origin": "field-load",
                "owner": outer["type"], "field": row["name"]}
    if kind == "call":
        target = origin.get("callee")
        csrc = _s1_writer_source(g, target) if target else None
        sig = _s1_signature(csrc["span"]) if csrc else None
        if sig is not None:
            owner = _nested_pointee_type(g, sig.get("ret"))
            if owner is not None:
                return {"kind": "type", "type": owner,
                        "origin": "constructor-result"}
        cast = _nested_body_type(g, fstart)
        if cast is not None:
            return {"kind": "type", "type": cast,
                    "origin": "allocation-cast"}
        return {"kind": "unknown",
                "why": "call result has no decidable owner type"}
    if kind == "int":
        return {"kind": "unknown", "why": "integer base"}
    return {"kind": "unknown",
            "why": origin.get("why") or "unproven base origin"}


def _nested_chain_desc(hops, ctx_type):
    return {"context_type": ctx_type,
            "hops": [{"offset": hex(h.get("offset")),
                      "base_reg": h.get("base_reg")}
                     for h in reversed(hops)]}


def _nested_resolve_chain(g: "DsoGraph", hops, ctx_type: str, ctx_info: dict):
    """Resolve the declared types along a chain, from the context outward.

    ``hops`` is ordered from the call's slot load back towards the context.
    Each hop must name a field at its exact displacement in the previous
    hop's pointee layout.  The final (outermost) field is the pointer slot the
    call dereferences; its owner type is what the writer index is keyed on.
    """
    owner = ctx_type
    field = None
    offset = None
    declaration = None
    rows = []
    for hop in reversed(hops):
        layout = _s1_struct_layout(g, owner)
        if layout is None:
            return {"refusal": "no-pointee-layout",
                    "chain": _nested_chain_desc(hops, ctx_type)}
        row = next((r for r in layout["fields"]
                    if r["offset"] == hop.get("offset")), None)
        if row is None:
            return {"refusal": "no-pointee-layout",
                    "chain": _nested_chain_desc(hops, ctx_type)}
        nxt = _nested_pointee_type(g, row["type"])
        if nxt is None and _s1_pointee(row["type"]) in ("c_void", "void"):
            casts = [t for t in _s1_cast_types(g, ctx_info, row["name"])
                     if _s1_struct_layout(g, t) is not None]
            if len(casts) == 1:
                nxt = casts[0]
        if nxt is None:
            return {"refusal": "no-pointee-layout",
                    "chain": _nested_chain_desc(hops, ctx_type)}
        rows.append({"owner": owner, "offset": hex(hop.get("offset")),
                     "field": row["name"], "field_type": row["type"],
                     "pointee": nxt})
        field, offset = row, hop.get("offset")
        declaration = f"{layout['file']}:{layout['line']}"
        owner = nxt
    table_layout = _s1_struct_layout(g, owner)
    if table_layout is None:
        return {"refusal": "no-pointee-layout",
                "chain": rows}
    return {"owner": rows[-1]["owner"], "field": field, "offset": offset,
            "table_type": owner, "layout": table_layout,
            "declaration": declaration, "chain": rows}


def _nested_direct_candidate(g: "DsoGraph", ctx_info: dict,
                             member_off: int):
    """Legacy direct-context candidate when the owner layout is undecidable.

    A context type with an embedded union (for example ``ProvCipherCtx``'
    ``stream`` or ``ProvGcmCtx``'s ``GcmCtx``) has no decidable byte layout,
    yet its *declared field list* still names the pointer field whose pointee
    declares the member the call reads.  Exactly as the pre-index rule did, a
    unique pointee type is admitted; the writer index remains keyed by the
    proven owner type and the actual load displacement, so the store set is
    still field-sensitive even though the field's name cannot be resolved.
    An absent or ambiguous candidate refuses.
    """
    fields = _s1_struct_fields(g, ctx_info.get("type") or "")
    if fields is None:
        return {"status": "none"}
    cands = []
    for fname, ftype in fields[0]:
        mm = re.match(r"\*\s*(?:const|mut)\s+([A-Za-z_]\w*)", ftype)
        if not mm:
            continue
        ulayout = _s1_struct_layout(g, mm.group(1))
        if ulayout is None:
            continue
        row = next((r for r in ulayout["fields"]
                    if r["offset"] == member_off), None)
        if row is None:
            continue
        cands.append({"field": fname, "table_type": mm.group(1),
                      "layout": ulayout, "member": row,
                      "declaration": (f"{fields[1]['file']}:"
                                      f"{fields[1]['line']}")})
    distinct = {c["table_type"] for c in cands}
    if not cands:
        return {"status": "none"}
    if len(distinct) != 1:
        return {"status": "ambiguous", "types": sorted(distinct)}
    return {"status": "ok", "candidate": cands[0]}


def _nested_index_one(g: "DsoGraph", out: dict, store: dict,
                      owner_type: str, member_off: int, nonscalar: bool):
    """Place one store in exactly one field-index bucket."""
    wf = store["function"]
    bq = _nested_store_base_witness(g, wf, store, owner_type, member_off)
    rec = {"store": store, "base": bq, "nonscalar": nonscalar}
    if bq.get("qualified"):
        out["nonscalar" if nonscalar else "scalar"].append(
            dict(rec, disposition="writer"))
        return
    if bq.get("excluded"):
        out["disjoint"].append(dict(rec, disposition="disjoint"))
        return
    owner = _nested_owner_type(g, wf, store["index"],
                               _canon(store["base"]), member_off=member_off)
    if owner.get("kind") == "type":
        # A symbol-derived receiver type is a base-type witness, not a
        # value witness.  Keep it in the record so a later reader can see
        # which evidence qualified or excluded the store.
        if owner.get("symbol"):
            bq = dict(bq, symbol_owner=owner["type"],
                      symbol_basis=owner.get("symbol_basis"),
                      symbol=owner.get("symbol"),
                      symbol_origin=owner.get("origin"))
            rec = {"store": store, "base": bq, "nonscalar": nonscalar}
        # A prefix-compatible owner (in either direction) shares the field
        # offset, so the store is a writer of this field.  Only two decidable
        # layouts with no prefix relation prove disjointness; an undecidable
        # layout is never a disjointness proof.  An allocation-size owner is
        # itself a declared layout, so the same rule applies through the
        # allocation-aware layout population.
        forward = _s1_type_compatible(g, owner["type"], owner_type)
        backward = _s1_type_compatible(g, owner_type, owner["type"])
        if forward.get("admitted") or backward.get("admitted"):
            out["nonscalar" if nonscalar else "scalar"].append(
                dict(rec, disposition="writer", owner=owner["type"],
                     prefix=forward.get("prefix") or backward.get("prefix")))
            return
        if owner.get("origin") == "allocation-size":
            decidable = (_s1_decl_layout(g, owner["type"]) is not None
                         and _s1_decl_layout(g, owner_type) is not None)
        else:
            decidable = (_s1_struct_layout(g, owner["type"]) is not None
                         and _s1_struct_layout(g, owner_type) is not None)
        if decidable:
            out["disjoint"].append(dict(
                rec, disposition="disjoint", owner=owner["type"],
                reason="field-sensitive owner type"))
            return
    out["unqualified"].append(dict(rec, owner=owner))


def _nested_field_writer_set(g: "DsoGraph", owner_type: str, member_off: int):
    """Every store that can write ``owner_type``'s field at ``member_off``.

    Completeness: the candidate superset is the image-wide store index at that
    displacement (and every non-scalar store whose byte range covers it).  A
    store at a different displacement cannot write the field.  Each candidate
    is then keyed by its owning type: this field's type (a writer), a provably
    different non-prefix type (disjoint), or an unestablished type
    (unqualified, never silently dropped).  The result is cached per
    ``(owner type, member offset)``, which is the field-sensitive key.
    """
    cache = getattr(g, "_nested_field_writer_cache", None)
    if cache is None:
        cache = {}
        g._nested_field_writer_cache = cache
    key = (owner_type, member_off)
    if key in cache:
        return cache[key]
    scalar, nonscalar = _nested_store_index(g)
    out = {"owner_type": owner_type, "offset": member_off,
           "scalar": [], "nonscalar": [], "disjoint": [],
           "unqualified": []}
    for store in scalar.get(member_off, []):
        _nested_index_one(g, out, store, owner_type, member_off, False)
    for store in nonscalar.get(member_off, []):
        _nested_index_one(g, out, store, owner_type, member_off, True)
    cache[key] = out
    return out


def nested_static_instance_witness(g: "DsoGraph", site: dict, name: str,
                                   reachable: set | None = None):
    """Prove a second-level static-instance dispatch, or refuse it by name.

    Returns None when the site is not the shape this rule owns; a dict with
    ``resolved`` otherwise.  A refusal leaves the site's existing class,
    targets and conservative bound untouched.
    """
    if site.get("kind") != "call" or not _has_insns(g):
        return None
    if site.get("reason") != "base-slot-partial":
        return None
    fstart = site.get("func")
    insns = g.precision.insns_by_func.get(fstart, ())
    idx = next((i for i, (a, _t) in enumerate(insns)
                if a == site.get("addr")), None)
    if idx is None:
        return None
    text = site.get("text") or ""
    m = re.search(r"call\w*\s+\*(.+)$", text.split("#", 1)[0].strip())
    if not m:
        return None
    operand = m.group(1).strip()
    mo = re.fullmatch(r"(-?0x[0-9a-f]+)?\((%r[a-z0-9]+)\)", operand)
    if not mo:
        return None
    member_off = int(mo.group(1), 16) if mo.group(1) else 0
    base_reg = mo.group(2)
    origin = _reg_origin(g, fstart, idx, _canon(base_reg))
    if origin.get("kind") != "load":
        return None
    # A one-level object chain (``base = ctx->a->b``) is a sequence of loads.
    # Walk from the call's table register back towards the context parameter.
    # Only the final pointer field's writers are enumerated; the earlier hops
    # establish declared types from their pointee layouts and infer no value.
    hops = [origin]
    cur = _reg_origin(g, fstart, origin.get("at"),
                      _canon(origin.get("base_reg")))
    while cur.get("kind") == "load":
        if cur.get("base_reg") in ("%rsp", "%rbp"):
            spill = _stack_param(g, fstart, cur.get("at"), cur.get("offset"),
                                 cur.get("base_reg"))
            cur = ({"kind": "param", "index": spill.get("index"),
                    "via": "frame-slot", "spill": spill}
                   if spill is not None else
                   {"kind": "unknown",
                    "why": "frame slot is not a parameter"})
            break
        if len(hops) > _NESTED_MAX_CHAIN:
            return _nested_refusal("chain-depth", function=name,
                                   call_site=hex(site["addr"]))
        hops.append(cur)
        cur = _reg_origin(g, fstart, cur.get("at"),
                          _canon(cur.get("base_reg")))
    ctx_info = _s1_site_context(g, fstart)
    if ctx_info is None:
        outer = hops[1] if len(hops) > 1 else cur
        if outer.get("kind") == "param":
            return _nested_refusal(
                "no-context-type", function=name,
                call_site=hex(site["addr"]),
                operand={"base_reg": base_reg, "member_offset": hex(member_off)},
                pointer_slot=hex(origin.get("offset")))
        return None
    want = ctx_info.get("param_index")
    last = hops[-1]
    ctx_origin = _s1_ctx_param(g, fstart, last.get("at"),
                               _canon(last.get("base_reg")), want)
    if cur.get("kind") != "param" or ctx_origin is None:
        return _nested_refusal(
            "ctx-not-proven-parameter", function=name,
            call_site=hex(site["addr"]),
            operand={"base_reg": base_reg, "member_offset": hex(member_off)},
            pointer_slot=hex(origin.get("offset")),
            context={"type": ctx_info["type"], "param": ctx_info.get("param")},
            chain=_nested_chain_desc(hops, ctx_info.get("type")))
    chain = _nested_resolve_chain(g, hops, ctx_info["type"], ctx_info)
    if chain.get("refusal"):
        # A direct context field whose owner type has no decidable layout
        # (an embedded union) still has a declared field list.  Admit the
        # unique pointee candidate exactly as the pre-index rule did; the
        # writer index is keyed by the proven owner type and the actual load
        # displacement.  A chain cannot fall back: its intermediate types
        # must be resolved from real layouts.
        if len(hops) == 1 and _s1_struct_layout(g, ctx_info["type"]) is None:
            direct = _nested_direct_candidate(g, ctx_info, member_off)
            if direct["status"] == "ambiguous":
                return _nested_refusal(
                    "ambiguous-pointee-type", function=name,
                    call_site=hex(site["addr"]),
                    pointee_types=direct["types"])
            if direct["status"] != "ok":
                return _nested_refusal(
                    "no-pointee-layout", function=name,
                    call_site=hex(site["addr"]),
                    operand={"member_offset": hex(member_off)},
                    chain=chain.get("chain"),
                    context={"type": ctx_info["type"],
                             "param": ctx_info.get("param")})
            c = direct["candidate"]
            chain = {"owner": ctx_info["type"],
                     "field": {"name": c["field"]},
                     "offset": origin.get("offset"),
                     "table_type": c["table_type"],
                     "layout": c["layout"],
                     "declaration": c["declaration"],
                     "chain": None}
        else:
            return _nested_refusal(
                chain["refusal"], function=name,
                call_site=hex(site["addr"]),
                operand={"base_reg": base_reg,
                         "member_offset": hex(member_off)},
                chain=chain.get("chain"),
                context={"type": ctx_info["type"],
                         "param": ctx_info.get("param")})
    final_owner = chain["owner"]
    final_field = chain["field"]
    slot_off = chain["offset"]
    table_type = chain["table_type"]
    ulayout = chain["layout"]
    member_row = next((r for r in ulayout["fields"]
                       if r["offset"] == member_off), None)
    if member_row is None:
        return _nested_refusal("no-pointee-layout", function=name,
                               call_site=hex(site["addr"]),
                               operand={"member_offset": hex(member_off)},
                               pointer_slot={"object": final_owner,
                                             "field": final_field["name"],
                                             "offset": hex(slot_off)},
                               chain=chain.get("chain"))
    cand = {"field": final_field["name"], "table_type": table_type,
            "layout": ulayout, "member": member_row,
            "declaration": chain["declaration"]}
    # The writer index is keyed by (owning type, declared member offset), not
    # by bare displacement.  A store at the same displacement under a provably
    # different owner type is disjoint from this field and is excluded; a store
    # whose owner type cannot be established remains unqualified and is decided
    # by the source-level negative witness or refuses the site.
    indexed = _nested_field_writer_set(g, final_owner, slot_off)
    rows = (indexed["scalar"] + indexed["nonscalar"] + indexed["unqualified"])
    if not rows:
        return _nested_refusal("no-writer", function=name,
                               call_site=hex(site["addr"]),
                               pointer_slot={"object": final_owner,
                                             "field": cand["field"],
                                             "offset": hex(slot_off)})
    admitted_offsets = [r["offset"] for r in ulayout["fields"]]
    writer_rows, excluded, unproven, unaccounted = [], [], [], []
    source_excluded = []
    for rec in indexed["disjoint"]:
        excluded.append(dict(rec["base"],
                             field_sensitive_owner=rec.get("owner"),
                             exclusion="different-owner-type"))
    for rec in indexed["scalar"]:
        store, bq = rec["store"], rec["base"]
        values, why = _nested_store_value(
            g, store["function"], store, slot_off,
            table_stride=ulayout["size"], table_member_off=member_off)
        if why is not None or values is None:
            unaccounted.append({"function": g.funcs.get(store["function"],
                                                         hex(store["function"])),
                                "store_site": hex(store["addr"]),
                                "reason": why or "unresolved-value"})
            continue
        if not values:
            continue
        writer_rows.append({"store": store, "base": bq, "values": values})
    overlapping = []
    same_owner_copies = []
    for rec in indexed["nonscalar"]:
        store, bq = rec["store"], rec["base"]
        # A qualified non-scalar store whose base and source are both this
        # owner type and whose range covers the whole object is a struct
        # assignment.  It copies the field bytes of a same-typed object, so it
        # can only propagate a value the field's own writers already produce;
        # it is accounted, not refused, and adds no target.  Anything without
        # that source witness is still an unexplained overlap.
        copy = _nested_whole_struct_copy(g, store["function"], store,
                                         final_owner, ulayout)
        if copy is not None:
            same_owner_copies.append(dict(
                copy,
                function=g.funcs.get(store["function"],
                                     hex(store["function"])),
                store_site=hex(store["addr"])))
            continue
        # The store's range covers the field and its owner type is this field's
        # owner type, so the overlap is real and its value cannot be accounted
        # from the scalar store value model: refuse.  A non-scalar store under
        # a provably different owner type is in ``disjoint`` instead.
        overlapping.append({"function": g.funcs.get(store["function"],
                                                      hex(store["function"])),
                            "store_site": hex(store["addr"]),
                            "mnemonic": store["mnemonic"],
                            "width": store["width"],
                            "base": bq})
    for rec in indexed["unqualified"]:
        store, bq = rec["store"], rec["base"]
        could, why = _nested_source_could_write(
            g, store["function"], cand["field"], final_owner,
            cand["table_type"], slot_off)
        if rec.get("nonscalar"):
            if not could:
                source_excluded.append(
                    {"function": g.funcs.get(store["function"],
                                              hex(store["function"])),
                     "store_site": hex(store["addr"]),
                     "reason": why, "non_scalar": True})
                continue
            overlapping.append({"function": g.funcs.get(store["function"],
                                                          hex(store["function"])),
                                "store_site": hex(store["addr"]),
                                "mnemonic": store["mnemonic"],
                                "width": store["width"],
                                "base": bq})
            continue
        if could:
            unproven.append(dict(bq, source_witness=why,
                                 field_sensitive_owner=rec.get("owner")))
        else:
            source_excluded.append(
                {"function": g.funcs.get(store["function"],
                                          hex(store["function"])),
                 "store_site": hex(store["addr"]),
                 "reason": why})
    pointer_slot = {"object": final_owner, "field": cand["field"],
                    "offset": hex(slot_off),
                    "declaration": cand["declaration"],
                    "field_key": f"{final_owner}.{cand['field']}@{hex(slot_off)}",
                    "chain": chain.get("chain")}
    if unproven or unaccounted or overlapping or not writer_rows:
        return _nested_refusal(
            "writer-set-incomplete", function=name,
            call_site=hex(site["addr"]),
            operand={"base_reg": base_reg, "member_offset": hex(member_off)},
            pointer_slot=pointer_slot,
            unproven_base_stores=unproven,
            unaccounted_values=unaccounted,
            overlapping_non_scalar_stores=overlapping,
            source_excluded_stores=source_excluded,
            same_owner_whole_struct_copies=same_owner_copies,
            stores_at_slot=len(rows))
    declared = _s1_declared_instances(g, cand["table_type"])["instances"]
    values = sorted({v for row in writer_rows for v in row["values"]})
    stored = {v for v in values if isinstance(v, int) and v != 0}
    prefix_types = {}
    admitted = dict(declared)
    const_tables = {}
    unknown_values = []
    for value in sorted(stored):
        st = _s1_static_type(g, value)
        if st is None:
            # A local ``const`` table has no declared-static name, so the
            # source-type lookup is empty.  The containing immutable data
            # symbol supplies the length; every element's selected member must
            # be an in-image function start, and the complete element set is
            # admitted rather than only the elements a branch selected.
            table = _nested_const_table_at(g, value, ulayout["size"],
                                           member_off)
            if table.get("ok") and value in table["elements"]:
                admitted.setdefault(value, {
                    "name": f"{table['symbol']}+{value - table['base']:#x}",
                    "symbol": table["symbol"], "addr": value,
                    "local_const_table": True,
                    "element_size": table["stride"]})
                const_tables[value] = {
                    "symbol": table["symbol"], "base": hex(table["base"]),
                    "size": hex(table["size"]), "stride": hex(table["stride"]),
                    "count": table["count"],
                    "elements": [hex(e) for e in table["elements"]]}
                continue
            unknown_values.append(hex(value))
            continue
        if st != cand["table_type"]:
            w = _s1_prefix_witness(g, st, cand["table_type"],
                                   admitted_offsets)
            if w is None:
                unknown_values.append(hex(value))
                continue
            prefix_types[st] = w
            more = _s1_declared_instances(g, st).get("instances") or {}
            for a, rec in more.items():
                admitted.setdefault(a, rec)
    if unknown_values:
        return _nested_refusal("unaccounted-writer-value", function=name,
                               call_site=hex(site["addr"]),
                               pointer_slot=pointer_slot,
                               undeclared_values=unknown_values)
    undeclared = sorted(hex(v) for v in stored if v not in admitted)
    if undeclared:
        return _nested_refusal("undeclared-instance", function=name,
                               call_site=hex(site["addr"]),
                               pointer_slot=pointer_slot,
                               undeclared_values=undeclared)
    instance_rows, targets, shape_failures = [], set(), []
    for addr in sorted(stored):
        inst = admitted[addr]
        inst_type = _s1_static_type(g, addr) or cand["table_type"]
        is_prefix = inst_type != cand["table_type"]
        prefix_w = prefix_types.get(inst_type) if is_prefix else None
        obj_type = ((prefix_w or {}).get("prefix_object_type")
                    or cand["table_type"])
        olayout = _s1_struct_layout(g, obj_type) or ulayout
        sec = g.section_of(addr)
        if sec not in S1_IMMUTABLE_SECTIONS:
            shape_failures.append({"instance": inst["name"],
                                   "addr": hex(addr), "reason": "mutable-section",
                                   "section": sec})
            continue
        size = None
        if inst.get("local_const_table"):
            # The containing symbol is the whole array; the instance extent is
            # one element, whose stride is the declared element type's size.
            size = inst.get("element_size")
        else:
            for raw in (getattr(g, "names_at", {}) or {}).get(addr, ()):
                raw_sym = (raw or "").split("@")[0]
                if raw_sym in (getattr(g, "sym_sizes", {}) or {}):
                    size = g.sym_sizes[raw_sym]
                    break
        if size is None or size < olayout["size"]:
            shape_failures.append({"instance": inst["name"],
                                   "addr": hex(addr),
                                   "reason": "symbol-smaller-than-layout",
                                   "symbol_size": size,
                                   "layout_size": olayout["size"]})
            continue
        members = {}
        ok = True
        for row in olayout["fields"]:
            vals = g.static_slot(addr + row["offset"])
            ints = {x for x in (vals or ()) if isinstance(x, int)}
            if len(ints) != 1:
                ok = False
                members[hex(row["offset"])] = None
                continue
            v = next(iter(ints))
            if v == 0:
                guard = None
                if not row["option"]:
                    ok = False
                else:
                    guard = _s1_null_guard(g, fstart, idx, row["offset"],
                                           base_reg)
                    if guard is None:
                        ok = False
                members[hex(row["offset"])] = {
                    "value": None,
                    "guard": hex(guard) if guard is not None else None}
                continue
            if v not in g.start_set:
                ok = False
                members[hex(row["offset"])] = {"value": hex(v),
                                                "not_function": True}
                continue
            members[hex(row["offset"])] = {"value": hex(v),
                                            "symbol": g.funcs.get(v)}
            if row["offset"] == member_off:
                targets.add(v)
        if not ok:
            shape_failures.append({"instance": inst["name"],
                                   "addr": hex(addr),
                                   "reason": "member-not-function-start"})
            continue
        instance_rows.append({"addr": hex(addr), "symbol": inst["name"],
                              "section": sec, "declared_type": inst_type,
                              "prefix_compatible": is_prefix,
                              "members": members})
    if shape_failures or not instance_rows or not targets:
        return _nested_refusal("instance-shape-or-target", function=name,
                               call_site=hex(site["addr"]),
                               pointer_slot=pointer_slot,
                               shape_failures=shape_failures,
                               instances=[r["addr"] for r in instance_rows])
    scanned = sum(len(v) for v in g.precision.insns_by_func.values()) \
        if _has_insns(g) else 0
    return {
        "schema": NESTED_WITNESS_SCHEMA,
        "class": "nested-static-instance",
        "contract_bounded": False,
        "resolved": True,
        "function": name,
        "call_site": hex(site["addr"]),
        "operand": {"base_reg": base_reg, "member_offset": hex(member_off)},
        "pointer_slot": pointer_slot,
        "member": {"offset": hex(member_off), "name": cand["member"]["name"],
                    "type": cand["member"]["type"]},
        "instances": instance_rows,
        "stored_by": [
            {"function": g.funcs.get(r["store"]["function"],
                                      hex(r["store"]["function"])),
             "store_site": hex(r["store"]["addr"]),
             "values": [hex(v) for v in sorted(r["values"])],
             "base_origin": (r["base"].get("origin")
                             or r["base"].get("symbol_origin")),
             "base_witness": (r["base"].get("witness")
                              or r["base"].get("symbol_witness")),
             "base_symbol_owner": r["base"].get("symbol_owner"),
             "base_symbol_basis": r["base"].get("symbol_basis")}
            for r in writer_rows],
        "prefix_compatible_types": sorted(prefix_types),
        "local_const_tables": [const_tables[v] for v in sorted(const_tables)],
        "excluded_different_object_stores": excluded,
        "same_owner_whole_struct_copies": same_owner_copies,
        "conditions": [
            "second-level-static-instance-shape",
            "declared-chain-types",
            "base-object-qualified",
            "field-sensitive-writer-index",
            "image-wide-writer-scan-complete",
            "declared-instance-writers",
            "local-const-table-length-from-symbol-and-stride",
            "every-member-in-image-function-start",
            "no-unproven-overlapping-non-scalar-store",
            "same-owner-whole-object-copy-propagates-existing-values",
        ],
        "completeness": {
            "rule": ("every instruction of every function in the analysed "
                     "image was scanned into a displacement index; every store "
                     "at the final field's declared member offset (and every "
                     "non-scalar store whose byte range covers it) is keyed by "
                     "its owning type: this field's type is a writer, a "
                     "provably different non-prefix type is disjoint, and an "
                     "unestablished type is unqualified and either excluded by "
                     "a source-level negative witness or refuses the site.  A "
                     "store at a different displacement cannot write the "
                     "field.  Each hop of a chain contributes only its declared "
                     "type, never a stored value.  A writer value that is a phi "
                     "or select of lea instructions into one in-image constant "
                     "table resolves to every element of that table: the "
                     "length is the containing immutable symbol's size divided "
                     "by the declared element stride, so the set is complete "
                     "even when a branch selects only some elements, and every "
                     "element's selected member must be an in-image function "
                     "start.  A non-scalar store that genuinely overlaps the "
                     "field refuses unless it is a same-owner whole-object "
                     "copy: such a copy starts at byte 0, covers the whole "
                     "declared layout, and loads its bytes from the same offset "
                     "of an object proven to be the same owner type, so it can "
                     "only propagate a value the field's own writers already "
                     "produce and adds no target.  No value is inferred from a "
                     "declared name."),
            "functions_scanned": len(g.precision.insns_by_func),
            "instructions_scanned": scanned,
            "writer_index_key": {"owner_type": final_owner,
                                 "field": cand["field"],
                                 "offset": hex(slot_off)},
            "stores_at_slot": len(rows),
            "qualified_writers": len(writer_rows),
            "excluded_different_object_stores": len(excluded),
            "source_excluded_stores": len(source_excluded),
            "unproven_base_stores": 0,
            "unaccounted_values": 0,
            "overlapping_non_scalar_stores": 0,
            "same_owner_whole_struct_copies": len(same_owner_copies),
            "local_const_tables": len(const_tables),
        },
        "targets": [hex(t) for t in sorted(targets)],
        "basis": ("a second-level static-instance dispatch resolved through "
                  "a field-sensitive (owning type, member offset) writer "
                  "index: each hop's declared pointee type is taken from the "
                  "source layout (a one-level object chain is supported), "
                  "and every store that can write the final pointer field "
                  "writes a declared static instance of that type (or NULL); "
                  "the selected member of every stored instance is an "
                  "in-image function start"),
    }


# ---- S6: triage records (not a class) ---------------------------------- #

S6_FUNCTIONS = {
    "msblob2key_decode": {
        "mechanism": "in-image #[repr(C)] KeytypeDesc dispatch",
        "is_evp_pkey_asn1_method": False,
        "finding": (
            "the indirect operand is (*desc).read_private_key/read_public_key/"
            "adjust_key of a static KeytypeDesc (src/provider/decode_msblob2key.rs"),
        "disposition": "target-bounded; the right mechanism is the S1 static-table "
                       "instance dispatch, deferred to the next batch",
    },
    "do_PVK_key_bio": {
        "mechanism": "pem_password_cb application callback parameter",
        "is_evp_pkey_asn1_method": False,
        "finding": (
            "%rbp is the pem_password_cb parameter (src/pem/pvkfmt.rs:1679), "
            "forwarded from b2i_DSA_PVK_bio_ex/b2i_RSA_PVK_bio_ex/b2i_PVK_bio_ex"),
        "disposition": "a genuine application callback; if the export-callback "
                       "chain proves, ABI_CONTRACT_EXPORT_CALLBACK applies, "
                       "otherwise it stays target-bounded",
    },
}


def _s6_triage(name: str):
    for frag, rec in S6_FUNCTIONS.items():
        if frag in (name or ""):
            return dict(rec, function=name)
    return None


def allocator_contract_witness(g: "DsoGraph", site: dict, name: str) -> dict | None:
    """Witness for the CRYPTO_set_mem_functions seam at this exact site."""
    seam = site.get("seam")
    if not seam or seam not in ALLOCATOR_SEAMS or not is_o1_function(name):
        return None
    if not _image_defines(g, seam):
        return None
    if not _image_defines(g, ALLOCATOR_SETTER):
        return None
    return _witness(
        ABI_CONTRACT_ALLOCATOR, name, site,
        slot=f"{seam} (the crate's allocator-hook global; offset 0)",
        writer=("CRYPTO_set_mem_functions stores the application's replacement "
                "triple into these globals; the in-image default is selected "
                "when the global is NULL"),
        interface=("CRYPTO_set_mem_functions -- include/openssl/crypto.h:367-375 "
                   "and man3/CRYPTO_set_mem_functions"),
        basis=("this site reads exactly this seam global, and both the global "
               "and the public setter are defined in this image"),
    )


def provider_contract_witness(g: "DsoGraph", site: dict, name: str) -> dict | None:
    """Witness for an OSSL_provider_init dispatch slot at this exact site."""
    fetch = fetch_slot_witness(g, site, name)
    if fetch is not None:
        return fetch
    offsets = site.get("field_offsets") or set()
    for spec in PROVIDER_SLOTS:
        if spec["function"] not in (name or ""):
            continue
        if spec["slot_offset"] not in offsets:
            # The site does not read the documented slot; a name match is not a
            # witness.
            continue
        if not _image_defines(g, spec["writer_symbols"]):
            continue
        return _witness(
            ABI_CONTRACT_PROVIDER, name, site,
            slot=spec["slot"], writer=spec["writer"],
            interface=spec["interface"], basis=spec["basis"],
        )
    return None


ABI_CONTRACT_WITNESS = {
    ABI_CONTRACT_PROVIDER: provider_contract_witness,
    ABI_CONTRACT_ALLOCATOR: allocator_contract_witness,
}


def contract_witness(cls: str, g: "DsoGraph", site: dict, name: str) -> dict | None:
    """The class's witness for this exact site, or None.  No witness, no class."""
    fn = ABI_CONTRACT_WITNESS.get(cls)
    return fn(g, site, name) if fn else None


def evaluate_predicate_element_7(reachable_residual_sites, unclassified_sites) -> dict:
    """Element 7 under AGENTS.md section 7 criterion 2.

    An unresolved *target set* is still reported as such.  The element is met
    only when every remaining reachable unresolved site is contract-bounded and
    no reachable site is unclassified; an unrecognised indirect edge is
    target-bounded unresolved and therefore keeps the element failing.
    """
    contract_sites = [(d, f, s) for d, f, s in reachable_residual_sites
                      if s.get("class") in ABI_CONTRACT_CLASSES]
    target_bounded = [(d, f, s) for d, f, s in reachable_residual_sites
                      if s.get("class") not in ABI_CONTRACT_CLASSES]
    by_class = collections.Counter(s["class"] for _d, _f, s in contract_sites)
    established = not target_bounded and not unclassified_sites
    if not reachable_residual_sites:
        why = "no unresolved dynamic dispatch remains"
    elif established:
        why = ("every reachable unresolved site is contract-bounded by a public "
               "OpenSSL ABI contract (section 7 criterion 2); no target-bounded "
               "unresolved site and no unclassified site remains")
    else:
        why = (f"{len(target_bounded)} reachable unresolved site(s) are not "
               "contract-bounded, and/or an unclassified site is reachable")
    return {
        "established": established,
        "status": ("PASS (contract-bounded)" if established else "FAIL"),
        "basis": ("AGENTS.md section 7 criterion 2: a required precondition may be "
                  "established by an external ABI contract"),
        "reachable_unresolved_sites": len(reachable_residual_sites),
        "target_bounded_unresolved_sites": len(target_bounded),
        "contract_bounded_sites": len(contract_sites),
        "contract_bounded_by_class": dict(sorted(by_class.items())),
        "unclassified_reachable_sites": len(unclassified_sites),
        "target_sets_remain_unbounded": bool(contract_sites),
        "why": why,
    }

# O1: the allocator-override seam.  The resolver's reachable residual is the
# three sites the audit names -- the MALLOC_FN selection in
# runtime::err::append_current and the FREE_FN selection in the SlotStr and
# PendingReleaseGuard drop glue.  The same seam also appears in inlined
# CRYPTO_free/CRYPTO_malloc code, where the resolver resolves the static fallback
# to default_free/default_malloc; those sites are not part of the residual and
# are recorded separately (see the receipt's allocator contract bound).
def is_o1_function(name: str) -> bool:
    """The three allocator-seam functions the audit names.

    Other drop glue in this image also inlines a ``FREE_FN`` selection; those are
    resolved by the static fallback and are not part of the audited residual.
    The SlotStr drop *glue* is distinguished from ``SlotStr::Drop::drop``, which
    dispatches ``CRYPTO_free`` through the dlsym route (class R1).
    """
    return ("append_current" in name or "PendingReleaseGuard" in name
            or ("drop_glue" in name and "SlotStr" in name))


def residual_class_targets(g: "DsoGraph") -> set:
    """The resolver's conservative residual bound for a non-unclassified site.

    These are exactly the functions a previously unresolved site contributed to
    the upper bound.  Keeping them in a resolved evidence-class site preserves
    the closure's reachability upper bound; the evidence class itself states the
    *narrower* invariant (std/core image, built-in table, or method ABI).
    """
    out = set(g.taken_code)
    for vals in getattr(g, "field_stores", {}).values():
        out |= {v for v in vals if isinstance(v, int) and v in g.start_set}
    out |= {v for v in getattr(g, "unknown_call_arg_targets", ())
            if v in g.start_set}
    return out


def is_rust_runtime(name: str) -> bool:
    return any(frag in (name or "") for frag in RUST_RUNTIME_FRAGMENTS)


def _sym_addr(g: "DsoGraph", fragment: str):
    """Return (address, symbol, size) for a defined data symbol, or None."""
    for addr, name in g.all_syms.items():
        if fragment in name and g.section_of(addr) not in (None, ".text", ".plt"):
            return addr, name, g.sym_sizes.get(name.split("@")[0], 0)
    return None


def rust_runtime_targets(g: "DsoGraph") -> set:
    pool = g.taken_code | g.taken_data | g.slot_func_targets
    return {a for a in pool
            if a in g.funcs and is_rust_runtime(g.funcs[a])}


def method_table_targets(g: "DsoGraph") -> set:
    """Functions named by link-time-constant tables in the image.

    This is the bound for a built-in method/provider table: every entry is a
    relocation-resolved function pointer in ``.data.rel.ro``/``.rodata``.  A
    consumer-registered callback is not in this set, which is exactly why the
    A2 class also requires the absence of a registration setter import.
    """
    targets = set(g.slot_func_targets)
    for vals in getattr(g, "field_stores", {}).values():
        targets |= {v for v in vals if isinstance(v, int) and v in g.start_set}
    return targets


def r3_targets(g: "DsoGraph", name: str, site: dict):
    """Read an R3 table from the exact candidate image.

    Returns (targets, incomplete, table_description).  ``incomplete`` names the
    entries that could not be established as in-image function pointers; a
    non-empty list means the evidence does not bound the site.
    """
    if "11int_ctx_new" in name:
        sym = _sym_addr(g, "PMETH_STANDARD_METHODS")
        if not sym:
            return set(), ["PMETH_STANDARD_METHODS: symbol absent"], "PMETH_STANDARD_METHODS"
        addr, _n, size = sym
        count = max(1, size // 8)
        targets, bad = g.table_ptrs(addr, count, strict=True)
        return targets, bad, f"PMETH_STANDARD_METHODS[{count}]"
    if "12def_load_bio" in name:
        sym = _sym_addr(g, "DEFAULT_METHOD")
        if not sym:
            return set(), ["DEFAULT_METHOD: symbol absent"], "DEFAULT_CONF_METHOD"
        addr, _n, _size = sym
        targets, bad = g.table_ptrs(addr, 1, offset=0x10, strict=True)
        return targets, bad, "DEFAULT_CONF_METHOD.load_bio"
    if "19camellia_ecb_cipher" in name:
        # EvpCamelliaKey::block is a per-context function pointer installed by
        # camellia_init_key from in-image block functions; the reachable store
        # summary at the block field is the table contents.
        vals = {v for v in getattr(g, "field_stores", {}).get(0, ())
                if isinstance(v, int) and v in g.start_set}
        return vals, ([] if vals else ["camellia block field: no store"]), \
            "EvpCamelliaKey.block (field-store set)"
    if "14template_clear" in name or "6do_adb" in name:
        # The resolver already read the static ASN1_TEMPLATE/ASN1_ADB entries
        # it could follow; those targets are link-time constants in the image.
        vals = {t for t in site.get("targets", ()) if isinstance(t, int) and t in g.start_set}
        return vals, ([] if vals else ["ASN1 template/ADB: no entries"]), \
            "static ASN1_TEMPLATE/ASN1_ADB"
    if "ECDH_compute_key" in name:
        sym = _sym_addr(g, "DEFAULT_EC_KEY_METHOD")
        if not sym:
            return set(), ["DEFAULT_EC_KEY_METHOD: symbol absent"], "default EC_KEY_METHOD"
        addr, _n, _size = sym
        ptr = g.static_slot(addr)
        ints = {x for x in (ptr or ()) if isinstance(x, int) and x != 0}
        if len(ints) != 1:
            return set(), ["DEFAULT_EC_KEY_METHOD: not a single pointer"], \
                "default EC_KEY_METHOD"
        table = next(iter(ints))
        # The method table's 13 columns are function pointers or NULL; a
        # non-code column is a name/flags field, not a dispatch entry.
        targets, _bad = g.table_ptrs(table, 13, strict=False)
        return targets, ([] if targets else ["EC_KEY_METHOD: no entries"]), \
            "default EC_KEY_METHOD table"
    return set(), ["no R3 evidence"], "none"


def _match(name: str, fragments) -> bool:
    return any(f in (name or "") for f in fragments)


def _resolve(g: "DsoGraph", site: dict, targets: set, klass: str, reason: str) -> None:
    site["targets"] |= {t for t in targets if isinstance(t, int) and t in g.start_set}
    site["unresolved"] = False
    site["class"] = klass
    site["reason"] = reason


def apply_evidence_classes(g: "DsoGraph", workload_imports: set,
                           reachable: set | None = None) -> dict:
    """Apply the R2/R3/A1/A2 evidence classes to one candidate DSO.

    Only unresolved sites are considered.  A class is applied only when its
    invariant is checkable against this exact image; otherwise the site keeps
    its resolver reason.  O1 (the allocator seam) is already marked
    ABI_CONTRACT_ALLOCATOR by the resolver and is never resolved here: the
    contract bounds its obligation, not its target set.

    ``reachable`` is the pre-closure function set for this DSO.  In-image slot
    target resolution requires the slot's function writer to be in it; with no
    reachability evidence (``None``) the rule does not fire, which is the
    negative control.
    """
    stats = collections.Counter()
    residual = residual_class_targets(g)
    rust = rust_runtime_targets(g)
    for (_fstart, _addr, _kind), site in g.sites.items():
        name = g.funcs.get(site["func"], "")
        triage = _s6_triage(name)
        if triage is not None:
            site["s6_triage"] = triage
        # A pre-classified site is accepted only with its own witness.  A class
        # name, a private field or a comment is not evidence (AGENTS.md section
        # 22); a site that arrives without one is demoted, never inherited.
        if site["class"] in ABI_CONTRACT_CLASSES:
            witness = site.get("witness") or {}
            if (witness.get("schema") == WITNESS_SCHEMA
                    and witness.get("contract_bounded") is True
                    and witness.get("class") == site["class"]):
                stats["contract_witness_validated"] += 1
                continue
            site["contract_class_candidate"] = site["class"]
            site["witness"] = _witness(
                site["class"], name, site,
                slot="unknown", writer="unknown", interface="unknown",
                basis=("a contract class was carried without a per-call-site "
                       "witness; refused"),
                contract_bounded=False)
            site["class"] = "unclassified"
            site["unresolved"] = True
            site["reason"] = "contract-class-without-witness:" + str(site["reason"])
            stats["contract_class_demoted"] += 1
            continue
        if not site["unresolved"]:
            continue
        # O1: the allocator seam.  The seam is a witness only when this exact
        # site reads a named hook global and the image defines both the global
        # and the public setter.  It is deliberately left unresolved even where a
        # static fallback exists: the hook set is a runtime fact about this
        # configuration, not a link-time bound.
        if site.get("seam") and is_o1_function(name):
            witness = contract_witness(ABI_CONTRACT_ALLOCATOR, g, site, name)
            if witness is not None:
                site["class"] = ABI_CONTRACT_ALLOCATOR
                site["unresolved"] = True
                site["reason"] = ("allocator-override-seam:" + site["seam"]
                                  + " (per-call-site witness)")
                site["witness"] = witness
                stats["O1_contract_bounded"] += 1
            else:
                site["contract_class_candidate"] = ABI_CONTRACT_ALLOCATOR
                site["witness"] = _witness(
                    ABI_CONTRACT_ALLOCATOR, name, site,
                    slot=site.get("seam") or "unknown allocator seam",
                    writer=("no CRYPTO_set_mem_functions writer established in "
                            "this image"),
                    interface="CRYPTO_set_mem_functions",
                    basis="allocator class requested without a witness",
                    contract_bounded=False)
                site["reason"] = ("allocator-seam-without-witness:"
                                  + str(site.get("seam") or ""))
                stats["O1_witness_missing"] += 1
            continue
        # Stored-value slot targets: Method.free is written only by the in-image
        # method-store writers, so its target set is derived from the values
        # reachable code stores, never from declared symbol names.  A reachable
        # store whose provenance is not image-bounded keeps the site unresolved.
        sem = semantic_method_free_targets(g, site, name, reachable)
        if sem is not None:
            site["semantic_store_target"] = sem
            if sem.get("resolved"):
                site["targets"] = {int(t, 16) for t in sem["targets"]}
                site["unresolved"] = False
                site["class"] = "semantic-store-target"
                site["reason"] = ("stored-value provenance:Method.free "
                                  "(offset 0x20), "
                                  f"{sem.get('target_count', 0)} target(s)")
                stats["T_semantic_store_resolved"] += 1
            else:
                site["targets"] = set()
                site["unresolved"] = True
                site["class"] = "field"
                site["reason"] = ("semantic-store-unresolved:"
                                  + str(sem.get("refusal") or "unknown"))
                stats["T_semantic_store_unresolved"] += 1
            continue
        if is_rust_runtime(name):
            if rust:
                _resolve(g, site, rust | residual, "rust-std-core",
                         "linked core/std trait-object or runtime hook; no application callback")
                stats["R2_resolved"] += 1
            else:
                stats["R2_no_targets"] += 1
            continue
        if _match(name, R3_FUNCTIONS):
            targets, incomplete, table = r3_targets(g, name, site)
            if targets and not incomplete:
                _resolve(g, site, targets | residual, "static-table",
                         "link-time-constant table read from the image: " + table)
                stats["R3_resolved"] += 1
            else:
                site["reason"] = "static-table-incomplete:" + table
                stats["R3_unresolved"] += 1
            continue
        # S1: a field-sensitive static-table instance dispatch.  The witness
        # keys on (object type, pointer-slot offset, member offset), restricts
        # the writer set by the static dispatch table that pairs the consumer
        # with its constructor, and refuses the whole site on any failed
        # condition.  A refused site never falls through to a weaker class.
        s1 = static_table_instance_witness(g, site, name, reachable)
        if getattr(g, "_semantic_precision", None) is not None:
            # Once the semantic resolver exists the process is close to its
            # data limit; do not retain the S1 source corpus across sites.
            _drop_s1_caches(g, all_caches=False)
        if s1 is not None:
            if s1.get("resolved"):
                targets = {int(t, 16) for t in s1["targets"]}
                _resolve(g, site, targets | residual, "static-table-instance",
                         ("field-sensitive static-table instance dispatch: "
                          + s1["pointer_slot"]["object"] + "."
                          + s1["pointer_slot"]["field"] + " at "
                          + s1["pointer_slot"]["offset"] + " -> "
                          + str(len(s1["instances"])) + " declared table(s)"))
                site["static_instance_witness"] = s1
                stats["S1_static_instance_resolved"] += 1
            else:
                site["static_instance_refusal"] = s1
                site["reason"] = ("static-instance-refused:"
                                  + str(s1.get("refusal")))
                stats["S1_static_instance_refused"] += 1
            continue
        # S2b: a second-level static-instance dispatch that S1 declines because
        # the consumer is not in a decoded dispatch table.  Completeness is an
        # image-wide instruction fact; a refusal keeps the site's existing
        # class, targets and conservative bound unchanged.
        nested = nested_static_instance_witness(g, site, name, reachable)
        if nested is not None:
            if nested.get("resolved"):
                targets = {int(t, 16) for t in nested["targets"]}
                _resolve(g, site, targets | residual, "nested-static-instance",
                         ("second-level static-instance dispatch: "
                          + nested["pointer_slot"]["object"] + "."
                          + nested["pointer_slot"]["field"] + " at "
                          + nested["pointer_slot"]["offset"] + " -> "
                          + str(len(nested["instances"]))
                          + " stored declared static instance(s)"))
                site["nested_instance_witness"] = nested
                stats["S2b_nested_instance_resolved"] += 1
            else:
                # The refusal is recorded, but the site still falls through to
                # the weaker evidence classes: those have their own soundness
                # arguments, and blocking them would lose a previously
                # established resolution.  The conservative bound is never
                # shrunk here.
                site["nested_instance_refusal"] = nested
                stats["S2b_nested_instance_refused"] += 1
        # A local function pointer built from a finite, fully enumerated set of
        # in-image addresses.  This is a target claim (every stored value is a
        # function start and every writer is accounted for), never a contract.
        local = local_fptr_witness(g, site, name)
        if local is not None:
            targets = {int(t, 16) for t in local["targets"]}
            if targets and targets <= g.start_set:
                site["targets"] = set(targets)
                site["unresolved"] = False
                site["class"] = "local-function-pointer"
                site["reason"] = ("local function-pointer assignment: "
                                  f"{len(local['assignments'])} assignment(s), "
                                  f"{len(targets)} target(s)")
                site["local_fptr_witness"] = local
                stats["T_local_fptr_resolved"] += 1
                continue
        # In-image slot targets: the slot's writer is known in this image, so
        # the target set is resolved rather than contract-bounded.  This is a
        # target claim, not an ABI contract, and it never sets an
        # ABI_CONTRACT_* class.
        edge = edge_target_witness(g, site, name, reachable)
        if edge is not None:
            targets, spec = edge
            site["targets"] |= targets
            site["unresolved"] = False
            site["class"] = "in-image-slot"
            site["reason"] = "in-image-slot:" + spec["slot"]
            site["edge_target_witness"] = {
                "schema": EDGE_TARGET_WITNESS_SCHEMA,
                "id": spec["id"],
                "slot": spec["slot"],
                "targets": [hex(t) for t in sorted(targets)],
                "writer": spec["writer"],
                "source": spec["source"],
            }
            stats["T_in_image_slot_resolved"] += 1
            continue
        # Reachable-caller target bounding: an unbounded argument target set is
        # narrowed to the values contributed by callers that are themselves
        # reachable.  This is a target claim, not an ABI contract; a reachable
        # caller passing a non-image value keeps the site unresolved.
        bound, refusal = reachable_caller_targets(g, site, name, reachable)
        if bound is not None:
            targets = {int(t, 16) for t in bound["bounded_targets"]}
            # Round 4: a candidate the complete caller mapping cannot attribute
            # is admitted into the site's target set.  Admitting is monotone and
            # safe for the upper bound; the closure and the record therefore
            # agree, and the oracle covers what the record claims.  Excluding
            # such a target would need a subject that demonstrably produces it.
            unattributed = {int(t, 16)
                            for t in (bound.get("unattributed_targets") or ())}
            site["targets"] = set(targets) | unattributed
            site["unresolved"] = False
            site["class"] = "reachable-caller-target"
            site["reason"] = ("reachable-caller target bounding: callers "
                              + ", ".join(r["function"] for r in bound["reachable_callers"])
                              + " pass in-image callback addresses")
            site["reachable_caller_bound"] = bound
            stats["RCB_reachable_caller_resolved"] += 1
            continue
        if site.get("arg_deps"):
            site["reachable_caller_bound_refusal"] = refusal
            stats["RCB_reachable_caller_unresolved"] += 1
        # S3: a fetched EVP method object's provider-dispatch slot.  This is
        # the ABI_CONTRACT_PROVIDER class with a fetch-slot witness: the base
        # is proven to be the family fetch's return and the offset is the
        # documented field the OSSL_FUNC_* id fills.
        fetch = fetch_slot_witness(g, site, name)
        if fetch is not None:
            site["targets"] |= residual
            site["class"] = ABI_CONTRACT_PROVIDER
            site["unresolved"] = True
            site["reason"] = ("provider fetch-slot witness: "
                              + fetch["slot"])
            site["witness"] = fetch
            stats["S3_fetch_slot_contract_bounded"] += 1
            continue
        # S2: a callback that is exactly an exported function's parameter.
        # The mandatory deferral is enforced inside the witness: a private
        # chain with finite in-image callers is refused and left to the
        # reachable-caller-target rule.
        export_cb, cb_refusal = export_callback_witness(g, site, name)
        if export_cb is not None:
            site["class"] = ABI_CONTRACT_EXPORT_CALLBACK
            site["unresolved"] = True
            site["reason"] = ("exported-callback ABI contract: "
                              + export_cb["slot"])
            site["witness"] = export_cb
            stats["S2_export_callback_contract_bounded"] += 1
            continue
        if cb_refusal:
            site["export_callback_refusal"] = cb_refusal
            stats["S2_export_callback_unresolved"] += 1
        if _match(name, A1_FUNCTIONS):
            witness = contract_witness(ABI_CONTRACT_PROVIDER, g, site, name)
            if witness is not None:
                site["targets"] |= residual
                site["class"] = ABI_CONTRACT_PROVIDER
                site["reason"] = ("provider ABI contract witness: "
                                  + witness["slot"])
                site["witness"] = witness
                stats["A1_contract_bounded"] += 1
            else:
                # The name matched a provider-shape function, but this site's
                # slot is not written by the documented provider interface.  It
                # stays unresolved and target-bounded; it is not absorbed by the
                # class and no count is preserved by widening it.
                offsets = site.get("field_offsets") or set()
                slot = ("object field "
                        + ", ".join(hex(o) for o in sorted(offsets))
                        if offsets else "register/stack value")
                note = _internal_slot_note(name, offsets, site.get("seam"))
                site["contract_class_candidate"] = ABI_CONTRACT_PROVIDER
                site["witness"] = _witness(
                    ABI_CONTRACT_PROVIDER, name, site,
                    slot=slot, writer=note,
                    interface="not a documented provider interface",
                    basis="A1 name match without a per-call-site provider witness",
                    contract_bounded=False)
                site["reason"] = "provider-contract-witness-missing:" + note
                stats["A1_witness_missing"] += 1
            continue
        if _match(name, A2_FUNCTIONS):
            if workload_imports & A2_REGISTRATION_SETTERS:
                site["class"] = "ABI_OPEN_METHOD_TABLE"
                site["reason"] = ("legacy method-table ABI: the workload imports a "
                                  "method-table setter")
                stats["A2_abi_open"] += 1
            elif residual:
                _resolve(g, site, residual, "legacy-method-abi",
                         "built-in link-time method table; no A2 setter imported")
                stats["A2_resolved"] += 1
            else:
                stats["A2_no_targets"] += 1
            continue
        triage = _s6_triage(name)
        if triage is not None and site.get("unresolved"):
            stats["S6_triaged_not_absorbed"] += 1
        stats["unmatched"] += 1
    g.evidence_classes.update(stats)
    g.residual_sites = [s for s in g.sites.values() if s["unresolved"]]
    g.resolved_targets = {t for s in g.sites.values() for t in s["targets"]}
    g.precision_counts = collections.Counter((s["class"], s["unresolved"])
                                             for s in g.sites.values())
    # Witness caches are scoped to this classification pass.  They are dropped
    # before the closure's admission and edge-record phases, which already run
    # close to the court's per-process data limit.
    for attr in ("_fn_cfg_cache", "_reaching_cache", "_reaching_store_cache",
                 "_callers_cache", "_source_cache", "_prologue_delta_cache",
                 "_direct_call_index_cache", "_nested_store_index_cache"):
        if hasattr(g, attr):
            setattr(g, attr, {})
    # The source corpus and every S1 index are the largest allocations here;
    # drop them as soon as the classification pass is over (the edge-record
    # phase has its own budget).
    _drop_s1_caches(g, all_caches=True)
    if hasattr(g, "_header_text_cache"):
        g._header_text_cache = None
    return dict(stats)


# --------------------------------------------------------------------------- #
# per-edge provenance records (AGENTS.md sections 7 and 22)
# --------------------------------------------------------------------------- #
#
# Every indirect site the resolver classifies emits a record that separates what
# the analysis proved from what it approximated.  The identity is semantic (the
# source operation, defining function, call-site role and a per-target provenance
# chain); a machine address is recorded only as an artifact-local witness.
#
# v1.2 makes every exclusion claim *self-witnessing*:
#
#   * the reason names the subject of the claim (the target, the callers, the
#     writer, or the reachable caller set), and a `claim` object binds that
#     subject to a closed claim kind and to the record's own module.  A blanket
#     "not in the reachable set" no longer says what is supposed to be absent;
#   * the candidate set is recomputed from `candidate_source`, a separate
#     enumeration of how candidates were derived, rather than trusted from the
#     accounting ledger;
#   * the reachability oracle is the union of *every* name at every reachable
#     address, so an identical-code-folding alias cannot escape a negative
#     check, and an unknown module fails closed;
#   * an empty admitted set is never claimed as proved, and a record whose
#     defining function has no symbol is never proved or contract-bounded;
#   * the population is streamed to a JSONL sidecar and validated on the fly, so
#     the receipt is bounded in memory and size (v1.1 OOMed the ssh closure).

EDGE_RECORD_SCHEMA = "openssl-rs/campaign/safe-c33/edge-record/v1.4"
DISPOSITION_PROVED = "PROVED_TARGET_SET"
DISPOSITION_CONTRACT = "CONTRACT_BOUNDED"
DISPOSITION_UNRESOLVED = "UNRESOLVED"
DISPOSITIONS = (DISPOSITION_PROVED, DISPOSITION_CONTRACT,
                DISPOSITION_UNRESOLVED)
# v1.3 splits the vocabulary by *row kind*.  A target drop and a subject-scoped
# reachability claim are different claims and can no longer share a list: an
# `exclusions[]` row is always a target drop, and an auxiliary caller/writer row
# is always a subject claim.  This makes the v1.2 hole -- a caller/writer-scoped
# label hiding a reachable dropped target inside `exclusions[]` -- inexpressible
# rather than merely checked against.
TARGET_DROP_REASONS = frozenset({
    "target-not-in-reachable-set",            # subject: the excluded target
    "not-contributed-by-reachable-callers",   # bound per caller in candidate_source
    "declared-name-absent",                   # bound by evidence.targets
    "no-reachable-writer",                    # bound to the writer subject rows
    "provenance-unbounded",                   # subject: the value
    "non-image-value",                        # subject: the value
})
SUBJECT_ROW_REASONS = frozenset({
    "caller-not-in-reachable-set",            # subject: the named callers
    "writer-not-in-reachable-set",            # subject: the method-store writer
    "provenance-unbounded",                   # subject: the value
})
EXCLUSION_REASONS = TARGET_DROP_REASONS | SUBJECT_ROW_REASONS
ROW_KINDS = frozenset({"target-drop", "subject"})
ROW_KIND_VOCABULARY = {
    "target-drop": TARGET_DROP_REASONS,
    "subject": SUBJECT_ROW_REASONS,
}
# Reasons whose claim is a negative reachability statement about named subjects.
REACHABILITY_CLAIM_KINDS = frozenset({
    "target-not-in-reachable-set",
    "caller-not-in-reachable-set",
    "writer-not-in-reachable-set",
})
# `target_reachability` is derived from the disposition, never self-described:
# a target set is claimed exactly when the disposition is PROVED_TARGET_SET.
TARGET_REACHABILITY_VALUES = frozenset({"claimed", "not-claimed"})
CANDIDATE_SOURCE_KINDS = frozenset({
    "store-writer-call-sites", "argument-targets", "resolver-admitted-set",
})
# Closed vocabulary of derivation steps.  A derivation is evidence only when it
# is built from these steps; a step name the checker does not know is a claim it
# cannot interpret, and a step with no payload is a name without evidence.
EDGE_CHAIN_STEPS = frozenset({
    "store-writer", "call-site", "relocation", "argument",
    "code-materialised", "field", "field-slot", "thunk",
    "linkage", "abi-contract", "resolver", "unbounded",
    # Round 4: the target is a candidate that no caller row attributes, so it
    # is admitted conservatively instead of being dropped.  This is a widening
    # of the upper bound, never a proof that the target is reachable.
    "unattributed-admission",
    # The sound bound reaches a subject the derivation excluded.  The exclusion
    # was false, so the subject's contribution is admitted; this step names the
    # refuting bound and never claims the target is reachable by itself.
    "refutation-admission",
})
# A step that says the value could not be bounded.  A target claimed as proved
# must never rest on one: "unbounded" records the absence of a derivation.
# `unattributed-admission` is deliberately *not* here: it names a candidate the
# enumeration already contains and that is admitted for the upper bound, so the
# claimed set is still the complete candidate set.
EDGE_UNPROVED_STEPS = frozenset({"unbounded"})
# Each reason names the evidence that makes it checkable.  A free-text reason is
# not a reason: the validator requires these fields to be present and non-null.
EXCLUSION_EVIDENCE_KEYS = {
    "target-not-in-reachable-set": ("reachable_set_member", "reachable_basis"),
    "caller-not-in-reachable-set": ("reachable_set_member", "reachable_basis"),
    "writer-not-in-reachable-set": ("reachable_set_member", "reachable_basis"),
    "not-contributed-by-reachable-callers": ("reachable_basis",),
    # `targets` is checked separately, not merely for presence: it is the
    # structured mapping that replaces the free-text `target_derivation`.
    "declared-name-absent": ("declared_name", "present"),
    "no-reachable-writer": ("writer", "derived_targets", "reachable_writers"),
    "provenance-unbounded": ("failure",),
    "non-image-value": ("value", "in_image"),
}
# What each exclusion reason claims, in one checkable sentence.  The validator
# refuses a claim whose evidence does not establish the sentence; a reason whose
# meaning is only in prose has no validator.
EXCLUSION_SEMANTICS = {
    "target-not-in-reachable-set": (
        "the excluded target itself is absent from the final upper-bound "
        "reachable set"),
    "caller-not-in-reachable-set": (
        "every named caller is absent from the final upper-bound reachable set; "
        "no claim is made about the target it would have contributed"),
    "writer-not-in-reachable-set": (
        "the named method-store writer is absent from the final upper-bound "
        "reachable set; no claim is made about the target it would have stored"),
    "not-contributed-by-reachable-callers": (
        "the excluded target is contributed by an excluded caller and by no "
        "reachable caller, recomputed from candidate_source; every excluded "
        "caller is absent from the bound and every reachable caller is in it; "
        "no claim is made that the target itself is unreachable"),
    "declared-name-absent": (
        "the declared symbol name is not defined by this image, and it is the "
        "structured source of exactly the listed, candidate, unreachable target"),
    "no-reachable-writer": (
        "no reachable writer produces the excluded target"),
    "provenance-unbounded": (
        "the value's provenance could not be bounded to this image"),
    "non-image-value": (
        "the value is not an address defined in this image"),
}
# The only admissible basis for a negative reachability claim is a sound
# over-approximation (the final upper bound).  The derivation-time oracle is the
# pre-closure direct set, which is an under-approximation: it is retained as the
# derivation input, never as evidence that something is unreachable.
REACHABILITY_ORACLE_SCHEMA = (
    "openssl-rs/campaign/safe-c33/reachability-oracle/v1")
REACHABILITY_BASES = frozenset({"final-upper-bound", "pre-closure-direct"})
EDGE_RECORD_SAMPLE_DEFAULT = 500
EDGE_DEFECT_RENDER_LIMIT = 200
EDGE_AUDIT_RENDER_LIMIT = 2000


def _is_named_function(name) -> bool:
    """A semantic identity needs a real defining function, not a placeholder."""
    return isinstance(name, str) and name not in ("", "?")


class ReachabilityOracle:
    """The final upper-bound reachable set, per module, as the only admissible
    evidence for a negative reachability claim.  A negative claim needs a sound
    over-approximation; the pre-closure direct set is an under-approximation and
    is therefore not acceptable as its own witness.

    A reachable *address* contributes **every** name the image records for it
    (`funcs`, `all_syms` and `names_at`).  Keeping one name per address lets an
    identical-code-folding alias at a reachable address escape a negative
    check, so the set is the union, not a representative.
    """

    schema = REACHABILITY_ORACLE_SCHEMA

    def __init__(self, graphs: dict, upper_reach):
        self._upper_nodes = {}
        self._upper_symbols = {}
        self._image_symbols = {}
        for module, g in (graphs or {}).items():
            nodes = frozenset((d, a) for d, a in (upper_reach or ())
                              if d == module)
            symbols = set()
            for _d, addr in nodes:
                names = set()
                for table_name in ("funcs", "all_syms"):
                    sym = (getattr(g, table_name, {}) or {}).get(addr)
                    if sym:
                        names.add(sym)
                names.update((getattr(g, "names_at", {}) or {}).get(addr) or ())
                for sym in names:
                    if sym:
                        symbols.add(str(sym).split("@")[0])
            image = set()
            for sym in (getattr(g, "all_syms", {}) or {}).values():
                if sym:
                    image.add(str(sym).split("@")[0])
            for names in (getattr(g, "names_at", {}) or {}).values():
                for sym in names:
                    if sym:
                        image.add(str(sym).split("@")[0])
            self._upper_nodes[module] = nodes
            self._upper_symbols[module] = frozenset(symbols)
            self._image_symbols[module] = frozenset(image)

    def knows(self, module) -> bool:
        return module in self._upper_nodes

    def upper_nodes(self, module):
        """The (module, address) nodes of the final upper bound, or None."""
        return self._upper_nodes.get(module)

    def reachable_symbols(self, module):
        """Every normalised name at every reached address, or None."""
        return self._upper_symbols.get(module)

    def image_symbols_for(self, module):
        """Every normalised symbol name the module defines, or None."""
        return self._image_symbols.get(module)

    def is_reachable(self, module, symbol, address=None):
        """(reachable, basis, checkable) for one enumerated subject.

        ``checkable`` is False for a module the oracle does not cover: an
        unknown module is not evidence that a subject is absent.
        """
        nodes = self._upper_nodes.get(module)
        reach = self._upper_symbols.get(module)
        if nodes is None or reach is None:
            return None, "unavailable", False
        if address is not None and (module, address) in nodes:
            return True, "final-upper-bound", True
        if isinstance(symbol, str) and symbol and symbol != "?" \
                and symbol in reach:
            return True, "final-upper-bound", True
        return False, "final-upper-bound", True

    def describe(self) -> dict:
        return {
            "schema": self.schema,
            "modules": sorted(self._upper_nodes),
            "upper_nodes": {m: len(self._upper_nodes[m])
                            for m in sorted(self._upper_nodes)},
        }


def _oracle_observe(oracle, module, symbol, address=None):
    """(observed, basis, checkable) for one negative reachability claim."""
    if oracle is None:
        return None, "pre-closure-direct", False
    reachable, basis, checkable = oracle.is_reachable(module, symbol, address)
    if not checkable:
        return None, "pre-closure-direct", False
    return reachable, basis, True


def _reach_evidence(oracle, module, symbol, *, extra=None,
                    symbols_checked=None, addresses=None) -> dict:
    """Evidence for a negative reachability claim, honestly observed.

    The module is fixed by the row's ``claim`` object, never by free text in
    this evidence block; ``subject_addresses`` is an artifact-local fallback
    for a subject that has no name.
    """
    evidence = {"reachable_set_member": False, "symbol": symbol,
                "reachable_basis": "pre-closure-direct"}
    if extra:
        evidence.update(extra)
    address = (addresses or {}).get(symbol)
    observed, basis, _checkable = _oracle_observe(oracle, module, symbol,
                                                  address)
    if observed is not None:
        evidence["reachable_set_member"] = observed
    evidence["reachable_basis"] = basis
    if symbols_checked is not None:
        evidence["symbols_checked"] = list(symbols_checked)
    if addresses:
        evidence["subject_addresses"] = {
            key: (hex(value) if isinstance(value, int) else value)
            for key, value in addresses.items() if value is not None}
    return evidence


def _claim(kind: str, module: str, subjects, **extra) -> dict:
    """A claim names its kind, the record module and its subjects."""
    claim = {"kind": kind, "module": module, "subjects": list(subjects)}
    claim.update(extra)
    return claim


def _edge_symbol(g, value) -> str:
    """The semantic name of a target; an address is never the identity."""
    if isinstance(value, tuple) and value and value[0] == "sym":
        return str(value[1]).split("@")[0]
    if isinstance(value, int):
        sym = ((getattr(g, "funcs", {}) or {}).get(value)
               or (getattr(g, "all_syms", {}) or {}).get(value))
        return str(sym).split("@")[0] if sym else f"<{value:#x}>"
    return str(value)


def _addr_name(g, value) -> str:
    """A semantic name for an address given as an int or a hex string."""
    try:
        addr = value if isinstance(value, int) else int(value, 16)
    except (TypeError, ValueError):
        return str(value)
    return _edge_symbol(g, addr)


def _edge_atom_step(g, atom: dict) -> dict:
    kind = atom.get("kind")
    if kind == "relocation":
        return {"step": "relocation", "symbol": atom.get("symbol"),
                "slot": atom.get("slot")}
    if kind == "param":
        return {"step": "argument", "index": atom.get("index")}
    if kind == "int":
        return {"step": "code-materialised",
                "symbol": _edge_symbol(g, atom.get("value"))}
    if kind == "field":
        return {"step": "field", "offset": hex(atom.get("offset"))}
    return {"step": "unbounded", "why": atom.get("why")}


def _edge_chain_steps(g, node, out: list) -> None:
    """Flatten a provenance record into store/argument/relocation/lea/thunk steps."""
    if isinstance(node, list):
        for item in node:
            _edge_chain_steps(g, item, out)
        return
    if not isinstance(node, dict):
        return
    if isinstance(node.get("atom"), dict):
        out.append(_edge_atom_step(g, node["atom"]))
    if isinstance(node.get("value"), list):
        for atom in node["value"]:
            if isinstance(atom, dict) and "kind" in atom:
                out.append(_edge_atom_step(g, atom))
    if "field_slot" in node:
        out.append({"step": "field-slot", "slot": node.get("field_slot"),
                    "field_offset": node.get("field_offset"),
                    "writer": node.get("writer"),
                    "argument_index": node.get("argument_index")})
    for key in ("chain", "chains"):
        if isinstance(node.get(key), (list, dict)):
            _edge_chain_steps(g, node[key], out)


def _edge_role(site: dict) -> str:
    if site.get("semantic_store_target") is not None:
        return "method-store-slot"
    if site.get("edge_target_witness"):
        return "in-image-data-slot"
    if site.get("reachable_caller_bound"):
        return "argument-callback"
    if site.get("class") in ABI_CONTRACT_CLASSES:
        return "abi-contract-dispatch"
    if site.get("unresolved"):
        return "unresolved-dispatch"
    return "value-flow"


def _record_call_sites(g, rows) -> list:
    """Project bound-level call sites into the record's name-bearing shape.

    The addresses stay as artifact-local witnesses; ``targets`` is the semantic
    name set that ``contributed_targets`` must equal, so a record cannot carry a
    contribution its own call-site witness does not show.
    """
    out = []
    for cs in rows or ():
        args = []
        for arg in cs.get("arguments") or ():
            addresses = [hx for hx in (arg.get("targets") or ())]
            args.append({
                "argument_index": arg.get("argument_index",
                                           arg.get("argument")),
                "targets": sorted({_addr_name(g, hx) for hx in addresses}),
                "target_addresses": sorted(addresses),
                "witness_instruction": arg.get("witness_instruction") or [],
            })
        out.append({"call_site": cs.get("call_site"), "arguments": args})
    return out


def _edge_disposition(site: dict, name=None):
    """(disposition, demotion, missing_property).

    A target set is only "proved" when the resolver admitted at least one target
    and the defining function has a symbol.  v1.1 silently proved an empty set
    for 584 real records; an empty set is a resolver gap, not a proof, and is
    demoted here (the demotion is counted in the receipt so the gap stays
    visible).  A record with no defining symbol cannot be attributed to a
    function and is never proved or contract-bounded.
    """
    contract = site.get("class") in ABI_CONTRACT_CLASSES
    named = _is_named_function(name)
    if contract:
        if not named:
            return (DISPOSITION_UNRESOLVED, "no-defining-symbol",
                    "the containing function has no symbol, so the ABI "
                    "contract cannot be attributed to a function")
        return DISPOSITION_CONTRACT, None, None
    if site.get("unresolved"):
        return DISPOSITION_UNRESOLVED, None, None
    if not named:
        # The no-symbol rule takes precedence: the record cannot be attributed
        # to a function at all, so that is the missing property to name.
        return (DISPOSITION_UNRESOLVED, "no-defining-symbol",
                "the containing function has no symbol, so a target set "
                "cannot be attributed to a function")
    if not (site.get("targets") or ()):
        return (DISPOSITION_UNRESOLVED, "empty-target-set",
                site.get("reason") or
                "empty target set: the resolver admitted no target and "
                "enumerated no candidates")
    return DISPOSITION_PROVED, None, None


def _edge_record(g, site: dict, ordinal: int, oracle=None, seen_ids=None) -> dict:
    module = getattr(g, "name", None) or "?"
    fstart = site.get("func", 0)
    site_addr = site.get("addr", 0)
    funcs = getattr(g, "funcs", {}) or {}
    name = funcs.get(fstart, "?")
    role = _edge_role(site)
    disposition, demotion, demotion_property = _edge_disposition(site, name)
    admitted = sorted(_edge_symbol(g, t) for t in (site.get("targets") or ()))
    candidates = set(admitted)
    enumeration = "resolver-admitted-set"
    candidate_source = {"kind": "resolver-admitted-set",
                        "class": site.get("class"),
                        "reason": site.get("reason")}
    exclusions = []
    extra = {}
    chains = collections.defaultdict(list)
    refutation = site.get("refutation_admission") or {}
    refutation_targets = set(refutation.get("targets") or ())
    refutation_chains = {}
    for row in refutation.get("admitted") or ():
        if not isinstance(row, dict):
            continue
        step = {"step": "refutation-admission",
                "subject": row.get("subject"),
                "role": row.get("role"),
                "basis": row.get("basis") or "final-upper-bound"}
        for nm in row.get("targets") or ():
            refutation_chains.setdefault(nm, []).append(step)
    # Set only by the round-4 zero-attribution fallback: the record cannot emit
    # a bounded set, so it becomes UNRESOLVED and names the incomplete property.
    fallback_missing = None
    unattributed = []

    semantics = site.get("semantic_store_target")
    edge_witness = site.get("edge_target_witness")
    caller_bound = site.get("reachable_caller_bound")
    if semantics is not None:
        # Only a resolved derivation enumerates its candidates.  An unresolved
        # row may contain a partial target set from rows that did not fail; it
        # is not a candidate set and must not be reported as if it were.
        resolved = bool(semantics.get("resolved"))
        enumeration = "complete" if resolved else "not-applicable"
        candidates = set()
        source_rows = []
        collapsed = set()
        declared = []
        stored_values = semantics.get("stored_values") or {}
        for row in semantics.get("call_sites") or ():
            caller = row.get("caller")
            call_site = row.get("call_site")
            base = [
                {"step": "store-writer", "writer": row.get("writer"),
                 "argument_index": row.get("argument_index")},
                {"step": "call-site", "caller": caller,
                 "call_site": call_site},
            ]
            sub = []
            _edge_chain_steps(g, row.get("chain") or (), sub)
            if row.get("included") is False:
                extra.setdefault("excluded_callers", []).append({
                    "target": caller or "?",
                    "reason": "caller-not-in-reachable-set",
                    "row_kind": "subject",
                    "claim": _claim("caller-not-in-reachable-set", module,
                                    [caller or "?"]),
                    "evidence": _reach_evidence(
                        oracle, module, caller,
                        symbols_checked=[caller] if caller else []),
                    "call_site": call_site,
                })
                source_rows.append({
                    "caller": caller, "call_site": call_site,
                    "included": False,
                    "reason": "caller-not-in-reachable-set", "targets": []})
                continue
            if row.get("failure"):
                extra.setdefault("unbounded_call_sites", []).append({
                    "target": call_site or caller or "?",
                    "reason": "provenance-unbounded",
                    "row_kind": "subject",
                    "claim": _claim("provenance-unbounded", module, []),
                    "evidence": {"failure": row.get("failure")},
                    "caller": caller,
                })
                source_rows.append({
                    "caller": caller, "call_site": call_site,
                    "included": False,
                    "reason": "provenance-unbounded", "targets": []})
                continue
            names = set()
            for hx in row.get("targets") or ():
                nm = _addr_name(g, stored_values.get(hx, hx))
                names.add(nm)
                if resolved:
                    candidates.add(nm)
                    chains[nm].extend(base + sub)
            source_rows.append({
                "caller": caller, "call_site": call_site,
                "included": True,
                "targets": sorted(names) if resolved else []})
        for collapse in semantics.get("thunk_collapses") or ():
            nm = _addr_name(g, collapse.get("semantic"))
            chains[nm].append({
                "step": "thunk",
                "from_symbol": _addr_name(g, collapse.get("stored")),
                "to_symbol": nm,
            })
            if resolved:
                candidates.add(nm)
                collapsed.add(nm)
        writer_rows = []
        for w in semantics.get("excluded_writers") or ():
            would = w.get("would_store_targets") or []
            if not w.get("would_store_failure") and not would:
                continue
            declared_name = w.get("fragment")
            writer_symbol = w.get("symbol") or "?"
            writer_address = w.get("address")
            writer_absent = (w.get("reason") == "absent from the image"
                             and isinstance(declared_name, str)
                             and bool(declared_name))
            would_names = [_addr_name(g, hx) for hx in would]
            # The excluded writer's would-store values are candidates: they are
            # exactly what the exclusion accounts for, even when the overall
            # derivation is unresolved.
            candidates.update(would_names)
            writer_rows.append({
                "symbol": writer_symbol, "address": writer_address,
                "included": False,
                "reason": ("declared-name-absent" if writer_absent else
                           "writer-not-in-reachable-set"),
                "targets": sorted(set(would_names))})
            if writer_absent:
                # The declared writer is absent from the image.  The structured
                # mapping is the list of targets it would store; a free-text
                # derivation is never evidence (v1.2 R2).
                for nm in would_names:
                    exclusions.append({
                        "target": nm,
                        "reason": "declared-name-absent",
                        "row_kind": "target-drop",
                        "claim": _claim("declared-name-absent", module,
                                        [declared_name]),
                        "evidence": {"declared_name": declared_name,
                                     "present": False,
                                     "targets": sorted(set(would_names)),
                                     "fragment": declared_name},
                    })
            else:
                # The writer is present but outside this family's reachable set.
                # The target drop and the writer subject are different claims and
                # now live in different lists: `exclusions[]` is always a target
                # drop, and the writer is a `writer-not-in-reachable-set` subject
                # row bound to the site's targets by `would_store_targets`.
                for nm in would_names:
                    exclusions.append({
                        "target": nm,
                        "reason": "no-reachable-writer",
                        "row_kind": "target-drop",
                        "claim": _claim("no-reachable-writer", module, []),
                        "evidence": {
                            "writer": writer_symbol,
                            "derived_targets": sorted(set(admitted)),
                            "reachable_writers": [],
                            "would_store_targets": sorted(set(would_names)),
                            "writer_address": writer_address,
                        },
                    })
                extra.setdefault("excluded_writers", []).append({
                    "target": writer_symbol,
                    "reason": "writer-not-in-reachable-set",
                    "row_kind": "subject",
                    "claim": _claim("writer-not-in-reachable-set", module,
                                    [writer_symbol]),
                    "evidence": _reach_evidence(
                        oracle, module, writer_symbol,
                        extra={"writer_address": writer_address,
                               "would_store_targets": sorted(set(would_names)),
                               "would_store": list(would)},
                        symbols_checked=[writer_symbol],
                        addresses={writer_symbol: writer_address}),
                })
            if w.get("would_store_failure"):
                extra.setdefault("excluded_writers", []).append({
                    "target": writer_symbol,
                    "reason": "provenance-unbounded",
                    "row_kind": "subject",
                    "claim": _claim("provenance-unbounded", module, []),
                    "evidence": {"failure": w["would_store_failure"]},
                    "writer_address": writer_address,
                })
        cross = semantics.get("declared_cross_check") or {}
        if resolved:
            # `declared_but_absent` is a cross-check observation, not a target
            # drop: there is no target to bind to the absent name.  It stays in
            # the precision ledger (`declared_cross_check`) and is not emitted as
            # an exclusion, because a target drop must name a candidate target.
            deref = set(admitted)
            for frag, info in (cross.get("declared_targets") or {}).items():
                if not info.get("present"):
                    continue
                names = set()
                for hx in info.get("addresses") or ():
                    nm = _addr_name(g, hx)
                    names.add(nm)
                    candidates.add(nm)
                    if nm not in deref:
                        exclusions.append({
                            "target": nm,
                            "reason": "no-reachable-writer",
                            "row_kind": "target-drop",
                            "claim": _claim("no-reachable-writer", module, []),
                            "evidence": {
                                "writer": "the reachable method-store writers",
                                "derived_targets": sorted(deref),
                                "reachable_writers": [],
                                "declared_name": frag,
                                "address": hx},
                        })
                declared.append({"name": frag,
                                 "targets": sorted(names)})
        else:
            extra["semantic_refusal"] = semantics.get("refusal")
        extra["source_of_truth"] = "stored-value provenance"
        extra["slot"] = semantics.get("slot")
        candidate_source = {
            "kind": "store-writer-call-sites",
            "resolved": resolved,
            "rows": source_rows,
            "writers": writer_rows,
            "collapsed": sorted(collapsed),
            "declared": declared,
        }
        if refutation_targets:
            candidate_source["refutation_targets"] = sorted(refutation_targets)
    elif edge_witness is not None:
        enumeration = "complete"
        extra["witness_id"] = edge_witness.get("id")
        for nm in admitted:
            chains[nm] = [
                {"step": "store-writer", "writer": edge_witness.get("writer")},
                {"step": "linkage", "source": edge_witness.get("source"),
                 "slot": edge_witness.get("slot")},
            ]
    elif caller_bound is not None:
        # Caller-scoped narrowing.  A dropped target is very often reachable in
        # its own right (the v1m provider case dropped 178 reachable targets);
        # the sound claim is about the *callers*, never the target.  The record
        # embeds the reachable and excluded caller sets so the drop is
        # recomputable from the record alone.
        enumeration = "complete"
        candidates |= {_edge_symbol(g, t)
                       for t in (site.get("arg_targets") or ())}
        reachable_rows = []
        reachable_contrib = set()
        for row in caller_bound.get("reachable_callers") or ():
            steps = []
            if row.get("admitted_by_refutation"):
                steps.append({"step": "refutation-admission",
                              "subject": row.get("symbol"),
                              "role": ADMISSION_ROLE_CALLER,
                              "basis": "final-upper-bound"})
            steps.append({"step": "argument", "caller": row.get("symbol")})
            for cs in row.get("call_sites") or ():
                for arg in cs.get("arguments") or ():
                    for wi in arg.get("witness_instruction") or ():
                        steps.append({"step": "code-materialised",
                                      "instruction": wi.get("text")})
            names = set()
            for hx in row.get("contributed_targets") or ():
                nm = _addr_name(g, hx)
                names.add(nm)
                chains[nm].extend(steps)
            reachable_contrib |= names
            rec_row = {
                "symbol": row.get("symbol") or "?",
                "address": row.get("function"),
                "reachable": True,
                "reason": None,
                "call_sites": _record_call_sites(g, row.get("call_sites")),
                "contributed_targets": sorted(names),
            }
            if row.get("admitted_by_refutation"):
                rec_row["admitted_by_refutation"] = True
            reachable_rows.append(rec_row)
        excluded_callers = caller_bound.get("excluded_callers") or []
        excluded_rows = []
        excluded_addresses = {}
        excluded_contrib = set()
        for c in excluded_callers:
            symbol = c.get("symbol") or "?"
            excluded_addresses[symbol] = c.get("function")
            names = sorted({_addr_name(g, hx)
                            for hx in (c.get("contributed_targets") or ())})
            excluded_contrib |= set(names)
            excluded_rows.append({
                "symbol": symbol,
                "address": c.get("function"),
                "reachable": False,
                "reason": "caller-not-in-reachable-set",
                "call_sites": _record_call_sites(g, c.get("call_sites")),
                "contributed_targets": names,
            })
        excluded_symbols = sorted({r["symbol"] for r in excluded_rows})
        # The candidates above are the site's flat argument-target union.  Every
        # caller row is embedded with its own per-call-site witness, so the
        # exclusion set is recomputable from the record.  A caller row may only
        # widen the candidate set here (normally a no-op); a candidate that no
        # row attributes is *admitted*, never dropped -- the conservative
        # direction of round 4.
        candidates |= reachable_contrib | excluded_contrib
        attributed = (reachable_contrib | excluded_contrib) & candidates
        attribution_fallback = bool(candidates) and not attributed
        if attribution_fallback:
            # No caller row attributes any candidate.  The narrowing has no
            # support, so no bounded set may be emitted: the record is
            # UNRESOLVED and names the incomplete attribution.
            disposition = DISPOSITION_UNRESOLVED
            demotion = None
            fallback_missing = ATTRIBUTION_INCOMPLETE_PROPERTY.format(
                n=len(candidates))
            admitted = []
            unattributed = sorted(candidates)
        else:
            unattributed = sorted(candidates - reachable_contrib
                                  - excluded_contrib)
            admitted_set = set(admitted)
            for nm in unattributed:
                admitted_set.add(nm)
                chains[nm].append({
                    "step": "unattributed-admission",
                    "reason": UNATTRIBUTED_ADMISSION_REASON})
            admitted = sorted(admitted_set)
        if unattributed:
            for nm in unattributed:
                extra.setdefault("unattributed_admissions", []).append({
                    "dso": module,
                    "site": hex(site_addr),
                    "function": name,
                    "target": nm,
                    "reason": (fallback_missing
                               or UNATTRIBUTED_ADMISSION_REASON),
                })
        claim_callers = [{"symbol": r["symbol"],
                          "address": r["address"],
                          "contributed_targets": r["contributed_targets"]}
                         for r in reachable_rows]
        if not attribution_fallback:
            for dropped in sorted(candidates - set(admitted)):
                # Only an excluded caller's contribution can be dropped: a
                # target attributed to a reachable caller is admitted by the
                # derivation, and an unattributed one is admitted above.
                exclusions.append({
                    "target": dropped,
                    "reason": "not-contributed-by-reachable-callers",
                    "row_kind": "target-drop",
                    "claim": _claim(
                        "not-contributed-by-reachable-callers", module, [],
                        reachable_callers=claim_callers,
                        excluded_callers=excluded_symbols),
                    "evidence": {
                        "reachable_basis": ("final-upper-bound"
                                            if oracle is not None
                                            else "pre-closure-direct"),
                        "subject_addresses": excluded_addresses,
                    },
                })
        for c in excluded_callers:
            symbol = c.get("symbol") or "?"
            extra.setdefault("excluded_callers", []).append({
                "target": symbol,
                "reason": "caller-not-in-reachable-set",
                "row_kind": "subject",
                "claim": _claim("caller-not-in-reachable-set", module,
                                [symbol]),
                "evidence": _reach_evidence(
                    oracle, module, symbol,
                    extra={"in_image_attribution": c.get("contributed_targets"),
                           "in_image_references":
                           c.get("in_image_references")},
                    symbols_checked=[symbol],
                    addresses={symbol: c.get("function")}),
            })
        candidate_source = {
            "kind": "argument-targets",
            "callers": reachable_rows,
            "excluded_callers": excluded_rows,
            "argued_by": sorted({r["symbol"] for r in reachable_rows}
                                | set(excluded_symbols)),
            "targets": sorted(candidates),
            "unattributed_targets": sorted(unattributed),
        }
        refuted_callers = sorted(
            r["symbol"] for r in reachable_rows
            if r.get("admitted_by_refutation"))
        if refuted_callers:
            candidate_source["refutation_admitted_callers"] = refuted_callers
    elif site.get("class") in ABI_CONTRACT_CLASSES:
        w = site.get("witness") or {}
        extra["witness_id"] = (f"{site.get('class')}:{w.get('slot') or 'unknown'}")
        extra["contract_bounded"] = True
        for nm in admitted:
            chains[nm] = [{"step": "abi-contract",
                           "slot": w.get("slot"),
                           "interface": w.get("interface")}]
    else:
        for nm in admitted:
            chains[nm] = [{"step": "resolver", "class": site.get("class"),
                           "reason": site.get("reason")}]

    # A refuted exclusion's contribution is admitted with its witness.  The
    # target is added to the candidate enumeration (it is a real candidate the
    # derivation would have produced) and carries its own derivation step; a
    # target that already has a chain from the widened derivation keeps it.
    for nm in sorted(refutation_targets):
        candidates.add(nm)
        if nm not in chains:
            chains[nm] = list(refutation_chains.get(nm) or [{
                "step": "refutation-admission",
                "role": "stored-value-provenance",
                "basis": "final-upper-bound"}])
    if refutation:
        extra["refutation_admissions"] = refutation.get("admitted") or []
        extra["refuted_exclusions"] = refutation.get("refuted") or []
        if refutation.get("missing_property"):
            extra["refutation_missing_property"] = refutation["missing_property"]

    chain_rows = [{"target": nm, "derivation": chains[nm]}
                  for nm in sorted(chains)]
    admitted_set = set(admitted)
    excluded_set = {e["target"] for e in exclusions if e.get("target")}
    accounted = admitted_set | excluded_set
    unattributed_set = set(unattributed)
    unaccounted = (sorted(candidates - accounted - unattributed_set)
                   if enumeration == "complete" else [])

    # Derived, never self-described: a record claims a target set exactly when
    # its disposition is PROVED_TARGET_SET.  v1.2 let an UNRESOLVED record say
    # "claimed", which made the field an assertion rather than a consequence.
    target_reachability = ("claimed" if disposition == DISPOSITION_PROVED
                           else "not-claimed")

    missing = None
    if disposition == DISPOSITION_UNRESOLVED:
        missing = (fallback_missing
                   or demotion_property
                   or (semantics or {}).get("refusal")
                   or site.get("reason")
                   or "the resolver recorded no target set and no reason")

    base_id = (f"{module}::{name}::{site.get('kind')}::{role}::{ordinal}")
    edge_id = base_id
    if seen_ids is not None:
        if edge_id in seen_ids:
            digest = hashlib.sha256(json.dumps(
                {"text": site.get("text"),
                 "site_address": hex(site_addr),
                 "chain": [c["target"] for c in chain_rows]},
                sort_keys=True).encode()).hexdigest()[:16]
            edge_id = f"{base_id}::{digest}"
        seen_ids.add(edge_id)

    return {
        "schema": EDGE_RECORD_SCHEMA,
        "edge_id": edge_id,
        "semantic_identity": {
            "source_operation": site.get("text"),
            "operation_kind": site.get("kind"),
            "defining_function": name,
            "call_site_role": role,
            "provenance_chain": chain_rows,
            "artifact_local_witness": {
                "module": module,
                "function_address": hex(fstart),
                "site_address": hex(site_addr),
                "identity_note": ("addresses are artifact-local witnesses; "
                                  "they are not the identity of the edge"),
            },
        },
        "disposition": disposition,
        "disposition_demotion": demotion,
        "target_set": admitted if disposition == DISPOSITION_PROVED else [],
        "target_set_claim": disposition == DISPOSITION_PROVED,
        "target_reachability": target_reachability,
        "witness_id": extra.get("witness_id"),
        "missing_property": missing,
        "exclusions": exclusions,
        "candidate_source": candidate_source,
        **{k: v for k, v in extra.items() if k not in ("witness_id",)},
        "exclusion_accounting": {
            "candidate_enumeration": enumeration,
            "candidate_targets": sorted(candidates),
            "admitted_targets": sorted(admitted_set),
            "excluded_targets": sorted(excluded_set),
            "unaccounted_targets": unaccounted,
        },
    }


def iter_edge_records(graphs: dict, oracle=None):
    """Yield one provenance record for every indirect site, in module order."""
    for dso_name in sorted(graphs):
        g = graphs[dso_name]
        ordinals = collections.Counter()
        seen_ids = set()
        keys = sorted(getattr(g, "sites", {}) or {},
                      key=lambda k: (k[0], k[1], str(k[2])))
        for key in keys:
            site = g.sites[key]
            seed = (site.get("func"), _edge_role(site))
            ordinals[seed] += 1
            yield _edge_record(g, site, ordinals[seed], oracle, seen_ids)


def build_edge_records(graphs: dict, oracle=None, sink=None):
    """One provenance record per indirect site.

    With ``sink`` the population is produced, handed to the sink and released;
    only a compact summary is returned, so a 52k-record closure does not have to
    hold the population in memory.  Without ``sink`` the list is returned (the
    test and corpus callers).

    When ``oracle`` is supplied, every negative reachability claim carries the
    observation made against the final upper bound rather than the
    derivation-time (pre-closure, under-approximating) reachable set.
    """
    if sink is None:
        return list(iter_edge_records(graphs, oracle))
    count = 0
    for record in iter_edge_records(graphs, oracle):
        sink(record)
        count += 1
    return {"schema": EDGE_RECORD_SCHEMA, "count": count}


def _is_symbol_name(value) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value))


def _subject_addresses(evidence) -> dict:
    """Normalise a row's optional artifact-local subject addresses."""
    raw = evidence.get("subject_addresses") if isinstance(evidence, dict) else None
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key, value in raw.items():
        try:
            out[key] = value if isinstance(value, int) else int(value, 16)
        except (TypeError, ValueError):
            continue
    return out


def _absent_subject_defects(rid, where, reason, subjects, evidence,
                            module, oracle):
    """Shared checks for a claim that named subjects are absent from the bound."""
    defects = []
    member = evidence.get("reachable_set_member")
    if member is not False:
        defects.append(
            f"{rid}: {where} ({reason}) asserts reachable_set_member="
            f"{member!r}; a negative reachability claim requires exactly False")
    basis = evidence.get("reachable_basis")
    if basis not in REACHABILITY_BASES:
        defects.append(f"{rid}: {where} ({reason}) has reachability basis "
                       f"{basis!r}")
    checked = evidence.get("symbols_checked")
    if (not isinstance(checked, list) or not checked
            or not all(isinstance(s, str) and s for s in checked)
            or (bool(subjects) and set(checked) != set(subjects))):
        # v1.1 accepted an empty list when a free `reachable_caller_count` was
        # zero.  The count was not recomputable and had no production producer;
        # the exemption is gone, so the covered symbols are mandatory and must
        # be exactly the subjects.
        defects.append(f"{rid}: {where} ({reason}) does not list the symbols "
                       "its claim covers")
    symbol = evidence.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        defects.append(f"{rid}: {where} ({reason}) names no symbol")
    if oracle is not None and module:
        if basis != "final-upper-bound":
            defects.append(
                f"{rid}: {where} ({reason}) claims basis {basis!r}; an "
                "oracle-backed negative claim requires final-upper-bound")
        addresses = _subject_addresses(evidence)
        for subject in subjects:
            if not _is_symbol_name(subject) and subject not in addresses:
                defects.append(
                    f"{rid}: {where} ({reason}) subject {subject!r} is not a "
                    "symbol and carries no address")
                continue
            observed, _basis, checkable = oracle.is_reachable(
                module, subject, addresses.get(subject))
            if not checkable:
                defects.append(f"{rid}: {where} ({reason}) is not checkable: "
                               f"the oracle does not cover module {module!r}")
                break
            if observed is not member:
                defects.append(
                    f"{rid}: {where} ({reason}) claims reachable_set_member="
                    f"{member!r} but the final upper bound holds {observed} "
                    f"for {subject!r}")
    return defects


def _row_kind_placement_defect(rid, where, row, expected_kind):
    """A row belongs to exactly one list kind; the kind is part of the claim."""
    kind = row.get("row_kind")
    if kind not in ROW_KINDS:
        return (f"{rid}: {where} has no row_kind from {sorted(ROW_KINDS)}")
    if kind != expected_kind:
        if expected_kind == "target-drop":
            return (f"{rid}: {where} is in exclusions[] with row_kind {kind!r}; "
                    "a target drop cannot be justified by a caller/writer claim")
        return (f"{rid}: {where} is an auxiliary subject row with row_kind "
                f"{kind!r}; a target drop cannot be recorded as a subject claim")
    return None


def _row_reason_vocab_defect(rid, where, reason, expected_kind):
    """The reason must belong to the vocabulary of the row's list kind."""
    vocabulary = ROW_KIND_VOCABULARY[expected_kind]
    if reason not in vocabulary:
        return (f"{rid}: {where} reason {reason!r} is not a "
                f"{expected_kind} reason ({', '.join(sorted(vocabulary))})")
    return None


def _exclusion_row_defects(rid, where, row, module, oracle, rec,
                           expected_kind):
    """Per-reason checks for one exclusion or auxiliary claim row.

    A reason is accepted only when the row's ``claim`` names the right subject
    and its evidence establishes the sentence in ``EXCLUSION_SEMANTICS``.
    Presence of a field is not the claim: booleans are compared with ``is``, and
    a supplied oracle must corroborate every negative.
    """
    if not isinstance(row, dict):
        return [f"{rid}: {where} is not an object"]
    defects = []
    target = row.get("target")
    if not isinstance(target, str) or not target:
        defects.append(f"{rid}: {where} names no target")
        target = None
    reason = row.get("reason")
    if reason not in EXCLUSION_REASONS:
        defects.append(f"{rid}: {where} has no checkable reason ({reason!r})")
        return defects
    kind_defect = _row_kind_placement_defect(rid, where, row, expected_kind)
    if kind_defect:
        return defects + [kind_defect]
    vocab_defect = _row_reason_vocab_defect(rid, where, reason, expected_kind)
    if vocab_defect:
        return defects + [vocab_defect]
    claim = row.get("claim")
    if not isinstance(claim, dict):
        return defects + [f"{rid}: {where} ({reason}) has no claim object"]
    if claim.get("kind") != reason:
        defects.append(
            f"{rid}: {where} claim kind {claim.get('kind')!r} is not the "
            f"reason {reason!r}")
    cmodule = claim.get("module")
    if not isinstance(cmodule, str) or not cmodule:
        defects.append(f"{rid}: {where} claim names no module")
    elif module and cmodule != module:
        defects.append(
            f"{rid}: {where} claim module {cmodule!r} is not the record's "
            f"module {module!r}")
    subjects = claim.get("subjects")
    if not isinstance(subjects, list) or not all(
            isinstance(s, str) and s for s in subjects):
        defects.append(f"{rid}: {where} claim subjects are not a list of names")
        subjects = []
    evidence = row.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        return defects + [f"{rid}: {where} ({reason}) has no evidence"]
    missing = [k for k in EXCLUSION_EVIDENCE_KEYS[reason]
               if evidence.get(k) is None]
    if missing:
        defects.append(f"{rid}: {where} ({reason}) lacks evidence fields "
                       + ", ".join(missing))
    if oracle is not None and isinstance(cmodule, str) and cmodule \
            and not oracle.knows(cmodule):
        defects.append(f"{rid}: {where} ({reason}) is not checkable: the "
                       f"oracle does not cover module {cmodule!r}")
        oracle = None

    if reason == "target-not-in-reachable-set":
        # The claim is about the excluded target itself (H1).  v1.1 validated
        # only the evidence's free `symbol`, so an exclusion of a reachable
        # target whose evidence named a different, absent symbol validated.
        if target and subjects != [target]:
            defects.append(
                f"{rid}: {where} ({reason}) must claim about exactly the "
                f"excluded target {target!r}, not {subjects}")
        symbol = evidence.get("symbol")
        if target and symbol != target:
            defects.append(
                f"{rid}: {where} ({reason}) evidence names {symbol!r} but the "
                f"excluded target is {target!r}")
        defects.extend(_absent_subject_defects(
            rid, where, reason, subjects or ([target] if target else []),
            evidence, cmodule or module, oracle))
    elif reason == "caller-not-in-reachable-set":
        if not subjects:
            defects.append(f"{rid}: {where} ({reason}) names no caller")
        defects.extend(_absent_subject_defects(
            rid, where, reason, subjects, evidence, cmodule or module, oracle))
    elif reason == "writer-not-in-reachable-set":
        if len(subjects) != 1:
            defects.append(f"{rid}: {where} ({reason}) must name exactly one "
                           f"writer, got {subjects}")
        would = evidence.get("would_store_targets")
        if not isinstance(would, list) or not all(
                isinstance(t, str) and t for t in would):
            defects.append(f"{rid}: {where} ({reason}) has no "
                           "would_store_targets list binding the subject to "
                           "the site's targets")
        defects.extend(_absent_subject_defects(
            rid, where, reason, subjects, evidence, cmodule or module, oracle))
    elif reason == "not-contributed-by-reachable-callers":
        # The per-caller mapping is not read here: it is recomputed from
        # candidate_source by _argument_binding_defects.  This branch checks the
        # claim's shape and the oracle membership of the named callers.
        rows = claim.get("reachable_callers")
        if not isinstance(rows, list) or not rows:
            defects.append(f"{rid}: {where} ({reason}) embeds no reachable "
                           "caller set")
            rows = []
        for entry in rows:
            if not isinstance(entry, dict):
                defects.append(f"{rid}: {where} ({reason}) caller row is not "
                               "an object")
                continue
            symbol = entry.get("symbol")
            if not isinstance(symbol, str) or not symbol:
                defects.append(f"{rid}: {where} ({reason}) caller row names no "
                               "caller")
            targets = entry.get("contributed_targets")
            if not isinstance(targets, list) or not all(
                    isinstance(t, str) and t for t in targets):
                defects.append(f"{rid}: {where} ({reason}) caller {symbol!r} "
                               "has no contributed target list")
        excluded = claim.get("excluded_callers")
        if not isinstance(excluded, list) or not excluded or not all(
                isinstance(s, str) and s for s in excluded):
            defects.append(f"{rid}: {where} ({reason}) embeds no excluded "
                           "caller list")
            excluded = []
        basis = evidence.get("reachable_basis")
        if basis not in REACHABILITY_BASES:
            defects.append(f"{rid}: {where} ({reason}) has reachability basis "
                           f"{basis!r}")
        if oracle is not None and cmodule:
            if basis != "final-upper-bound":
                defects.append(
                    f"{rid}: {where} ({reason}) claims basis {basis!r}; an "
                    "oracle-backed claim requires final-upper-bound")
            for entry in rows:
                symbol = entry.get("symbol") if isinstance(entry, dict) else None
                if not isinstance(symbol, str) or not symbol:
                    continue
                address = entry.get("address")
                try:
                    address = int(address, 16) if isinstance(address, str) else address
                except ValueError:
                    address = None
                observed, _basis, checkable = oracle.is_reachable(
                    cmodule, symbol, address)
                if not checkable or observed is not True:
                    defects.append(
                        f"{rid}: {where} ({reason}) embeds a caller {symbol!r} "
                        "that is not established as reachable in the final "
                        "upper bound")
            addresses = _subject_addresses(evidence)
            for symbol in excluded:
                observed, _basis, checkable = oracle.is_reachable(
                    cmodule, symbol, addresses.get(symbol))
                if not checkable or observed is not False:
                    defects.append(
                        f"{rid}: {where} ({reason}) embeds an excluded caller "
                        f"{symbol!r} that the final upper bound reaches or "
                        "cannot check")
    elif reason == "declared-name-absent":
        name = evidence.get("declared_name")
        if not isinstance(name, str) or not name:
            defects.append(f"{rid}: {where} ({reason}) names no declared symbol")
        elif subjects != [name]:
            defects.append(
                f"{rid}: {where} ({reason}) must claim about exactly the "
                f"declared name {name!r}, not {subjects}")
        if evidence.get("present") is not False:
            defects.append(
                f"{rid}: {where} ({reason}) asserts present="
                f"{evidence.get('present')!r}; an absent name requires exactly "
                "False")
        listed = evidence.get("targets")
        if not isinstance(listed, list) or not listed or not all(
                isinstance(t, str) and t for t in listed):
            # v1.2 accepted a free-text `target_derivation`; a string is never
            # a structured mapping from a declared name to a dropped target.
            defects.append(
                f"{rid}: {where} ({reason}) has no structured evidence.targets "
                "list; a free-text derivation is not evidence")
            listed = []
        if target and listed and target not in listed:
            defects.append(
                f"{rid}: {where} ({reason}) excludes target {target!r} but the "
                f"declared mapping names {listed}")
        if oracle is not None and cmodule and isinstance(name, str) and name:
            image = oracle.image_symbols_for(cmodule)
            if image is not None and name in image:
                defects.append(f"{rid}: {where} ({reason}) claims {name!r} is "
                               "absent but the image defines it")
        if oracle is not None and cmodule and target:
            observed, _basis, checkable = oracle.is_reachable(cmodule, target)
            if not checkable or observed is not False:
                defects.append(
                    f"{rid}: {where} ({reason}) drops target {target!r} under an "
                    "absent declared name although the final upper bound "
                    "reaches it (or cannot check it)")
    elif reason == "no-reachable-writer":
        writer = evidence.get("writer")
        if not isinstance(writer, str) or not writer:
            defects.append(f"{rid}: {where} ({reason}) names no writer")
        derived = evidence.get("derived_targets")
        if not isinstance(derived, list):
            defects.append(f"{rid}: {where} ({reason}) records no derived "
                           "target list")
        elif target and target in derived:
            defects.append(
                f"{rid}: {where} ({reason}) excludes {target!r} although its "
                "own derived_targets contain it")
        reachable = evidence.get("reachable_writers")
        if not isinstance(reachable, list) or reachable:
            defects.append(f"{rid}: {where} ({reason}) must record "
                           "reachable_writers == [], the claim it makes")
    elif reason == "provenance-unbounded":
        failure = evidence.get("failure")
        if not isinstance(failure, str) or not failure:
            defects.append(f"{rid}: {where} ({reason}) records no failure")
    elif reason == "non-image-value":
        if evidence.get("in_image") is not False:
            defects.append(
                f"{rid}: {where} ({reason}) asserts in_image="
                f"{evidence.get('in_image')!r}; a non-image claim requires "
                "exactly False")
        value = evidence.get("value")
        if oracle is not None and cmodule and _is_symbol_name(value):
            image = oracle.image_symbols_for(cmodule)
            if image is not None and value in image:
                defects.append(f"{rid}: {where} ({reason}) claims {value!r} is "
                               "not an image symbol but the image defines it")
    return defects


def _candidate_source_defects(rid, rec, oracle, module):
    """Recompute candidates from ``candidate_source``; return (set|None, defects).

    ``None`` means "the candidates are exactly the admitted resolver set" (the
    ``resolver-admitted-set`` kind).  A separate enumeration is mandatory:
    v1.1 trusted the accounting ledger, so deleting an exclusion and its
    candidate left no trace.
    """
    source = rec.get("candidate_source")
    if not isinstance(source, dict):
        return None, [f"{rid}: candidate_source is missing; the candidate set "
                      "is not separately determined"]
    kind = source.get("kind")
    if kind not in CANDIDATE_SOURCE_KINDS:
        return None, [f"{rid}: candidate_source kind {kind!r} is not checkable"]
    defects = []
    if kind == "store-writer-call-sites":
        rows = source.get("rows")
        if not isinstance(rows, list):
            defects.append(f"{rid}: candidate_source rows are not a list")
            rows = []
        resolved = source.get("resolved") is True
        names = set()
        for row in rows:
            if not isinstance(row, dict):
                defects.append(f"{rid}: candidate_source row is not an object")
                continue
            caller = row.get("caller")
            if not isinstance(caller, str) or not caller:
                defects.append(f"{rid}: candidate_source row names no caller")
            included = row.get("included")
            if not isinstance(included, bool):
                defects.append(f"{rid}: candidate_source row for {caller!r} "
                               "does not say whether it is included")
            targets = row.get("targets")
            if not isinstance(targets, list) or not all(
                    isinstance(t, str) and t for t in targets):
                defects.append(f"{rid}: candidate_source row for {caller!r} "
                               "has no target list")
                targets = []
            if included is True:
                names.update(targets)
            else:
                reason = row.get("reason")
                if reason == "caller-not-in-reachable-set":
                    # H6: an excluded semantic call-site row is itself a claim,
                    # separate from any auxiliary list.  The caller -- never
                    # the target -- must be absent from the bound.
                    if oracle is not None and module and caller:
                        if not oracle.knows(module):
                            pass  # record-level unknown-module defect
                        else:
                            observed, _b, checkable = oracle.is_reachable(
                                module, caller, None)
                            if not checkable or observed is not False:
                                defects.append(
                                    f"{rid}: candidate_source excludes caller "
                                    f"{caller!r} but the final upper bound "
                                    "reaches it (or cannot check it)")
                elif reason != "provenance-unbounded":
                    defects.append(
                        f"{rid}: candidate_source row for {caller!r} is "
                        f"excluded with reason {reason!r}, which is not a "
                        "caller or provenance claim")
        if not resolved and source.get("resolved") is not False:
            defects.append(f"{rid}: candidate_source does not say whether the "
                           "store-writer enumeration resolved")
        collapsed = source.get("collapsed") or []
        if not isinstance(collapsed, list) or not all(
                isinstance(t, str) and t for t in collapsed):
            defects.append(f"{rid}: candidate_source collapsed list is invalid")
        else:
            names.update(collapsed)
        writers = source.get("writers") or []
        if not isinstance(writers, list):
            defects.append(f"{rid}: candidate_source writers list is invalid")
            writers = []
        for entry in writers:
            if not isinstance(entry, dict):
                defects.append(f"{rid}: candidate_source writer entry is not an "
                               "object")
                continue
            reason = entry.get("reason")
            if reason not in ("declared-name-absent",
                              "writer-not-in-reachable-set"):
                defects.append(f"{rid}: candidate_source writer entry has "
                               f"reason {reason!r}, which is not a writer "
                               "claim")
            targets = entry.get("targets")
            if not isinstance(targets, list) or not all(
                    isinstance(t, str) and t for t in targets):
                defects.append(f"{rid}: candidate_source writer entry has no "
                               "target list")
                continue
            names.update(targets)
        declared = source.get("declared") or []
        if not isinstance(declared, list):
            defects.append(f"{rid}: candidate_source declared list is invalid")
            declared = []
        for entry in declared:
            if not isinstance(entry, dict):
                defects.append(f"{rid}: candidate_source declared entry is not "
                               "an object")
                continue
            targets = entry.get("targets")
            if not isinstance(targets, list) or not all(
                    isinstance(t, str) and t for t in targets):
                defects.append(f"{rid}: candidate_source declared entry "
                               "has no target list")
                continue
            names.update(targets)
        # A refuted exclusion's contribution is a candidate the widened
        # derivation produced (or the retained old targets it would have
        # stored).  It is enumerated separately so the candidate set stays a
        # separate source rather than being read back from the admitted set.
        refuted_targets = source.get("refutation_targets") or []
        if not isinstance(refuted_targets, list) or not all(
                isinstance(t, str) and t for t in refuted_targets):
            defects.append(f"{rid}: candidate_source refutation_targets is not "
                           "a target-name list")
        else:
            names.update(refuted_targets)
        return names, defects, {}
    if kind == "argument-targets":
        targets = source.get("targets")
        if not isinstance(targets, list) or not targets or not all(
                isinstance(t, str) and t for t in targets):
            return (None, defects + [f"{rid}: argument-targets candidate source "
                                     "has no target list"], {})
        candidates = set(targets)
        detail = {"kind": "argument-targets", "valid": False,
                  "callers": {}, "excluded": {},
                  "union_callers": set(), "union_excluded": set(),
                  "callsite_union": {}, "unattributed": set(),
                  "targets": candidates}
        callers = source.get("callers")
        excluded = source.get("excluded_callers")
        refuted_callers = source.get("refutation_admitted_callers") or []
        if not isinstance(refuted_callers, list) or not all(
                isinstance(s, str) and s for s in refuted_callers):
            defects.append(f"{rid}: argument-targets "
                           "refutation_admitted_callers is not a name list")
            refuted_callers = []
        callers_ok = isinstance(callers, list) and bool(callers)
        # A caller-bound narrowing used to require at least one excluded caller.
        # After admission by refutation there may be none: every excluded caller
        # was reached by the sound bound.  The empty set is not a negative claim
        # when the record names the admitted callers and the validator confirms
        # each of them is in the final upper bound; without that witness the
        # shape is still refused.
        excluded_ok = (isinstance(excluded, list)
                       and (bool(excluded) or bool(refuted_callers)))
        if not callers_ok:
            # v1.2 let the claim's self-asserted `contributed_targets` stand in
            # for the caller mapping.  Without an embedded mapping the drop is
            # not recomputable, so no dependent check may run (and a fabricated
            # claim list cannot supply one).
            defects.append(f"{rid}: argument-targets candidate source embeds "
                           "no caller mapping (symbol -> contributed_targets)")
        if not excluded_ok:
            defects.append(f"{rid}: argument-targets candidate source embeds "
                           "no excluded-caller mapping "
                           "(symbol -> contributed_targets)")
        if not (callers_ok and excluded_ok):
            return candidates, defects, {}
        for label, rows in (("caller", callers),
                            ("excluded caller", excluded)):
            for entry in rows:
                if not isinstance(entry, dict):
                    defects.append(f"{rid}: argument-targets {label} entry is "
                                   "not an object")
                    continue
                symbol = entry.get("symbol")
                if not isinstance(symbol, str) or not symbol:
                    defects.append(f"{rid}: argument-targets {label} entry "
                                   "names no symbol")
                    continue
                contributed = entry.get("contributed_targets")
                if not isinstance(contributed, list) or not all(
                        isinstance(t, str) and t for t in contributed):
                    defects.append(f"{rid}: argument-targets {label} "
                                   f"{symbol!r} has no contributed_targets "
                                   "list")
                    contributed = []
                mapping = detail["callers"] if label == "caller" \
                    else detail["excluded"]
                mapping[symbol] = set(contributed)
                # Round 4: every caller row carries the per-call-site witness
                # that produced its contribution.  `contributed_targets` must
                # equal the union of the argument targets the row itself
                # shows, so a contribution cannot be asserted without a
                # witness (an empty call-site list can therefore contribute
                # nothing).  This checks the record against itself; it is not a
                # re-derivation from the image.
                call_sites = entry.get("call_sites")
                site_union = set()
                if not isinstance(call_sites, list):
                    defects.append(f"{rid}: argument-targets {label} "
                                   f"{symbol!r} has no per-call-site witness "
                                   "list")
                else:
                    for cs in call_sites:
                        if not isinstance(cs, dict):
                            defects.append(f"{rid}: argument-targets {label} "
                                           f"{symbol!r} call-site is not an "
                                           "object")
                            continue
                        args = cs.get("arguments")
                        if not isinstance(args, list):
                            defects.append(f"{rid}: argument-targets {label} "
                                           f"{symbol!r} call-site has no "
                                           "argument list")
                            continue
                        for arg in args:
                            if not isinstance(arg, dict):
                                defects.append(f"{rid}: argument-targets {label} "
                                               f"{symbol!r} argument is not an "
                                               "object")
                                continue
                            index = arg.get("argument_index")
                            if not isinstance(index, int):
                                defects.append(f"{rid}: argument-targets {label} "
                                               f"{symbol!r} argument has no "
                                               "argument_index")
                            arg_targets = arg.get("targets")
                            if not isinstance(arg_targets, list) or not all(
                                    isinstance(t, str) and t
                                    for t in arg_targets):
                                defects.append(f"{rid}: argument-targets {label} "
                                               f"{symbol!r} argument "
                                               f"{index!r} has no target "
                                               "list")
                                continue
                            site_union |= set(arg_targets)
                detail["callsite_union"][symbol] = site_union
                if site_union != set(contributed):
                    defects.append(
                        f"{rid}: argument-targets {label} {symbol!r} "
                        "contributed_targets are not the union of its "
                        "per-call-site targets")
        detail["union_callers"] = set().union(
            *detail["callers"].values()) if detail["callers"] else set()
        detail["union_excluded"] = set().union(
            *detail["excluded"].values()) if detail["excluded"] else set()
        # The refutation-admitted callers are ordinary reachable caller rows.
        # The list is evidence about *why* the excluded mapping may be empty, so
        # every name must name such a row (it is then oracle-checked below with
        # every other reachable caller).
        for symbol in refuted_callers:
            if symbol not in detail["callers"]:
                defects.append(
                    f"{rid}: refutation-admitted caller {symbol!r} has no "
                    "reachable caller row")
        detail["refuted_callers"] = set(refuted_callers)
        argued_by = source.get("argued_by")
        if not isinstance(argued_by, list) or not argued_by or not all(
                isinstance(s, str) and s for s in argued_by):
            defects.append(f"{rid}: argument-targets candidate source names no "
                           "callers")
        attributed = detail["union_callers"] | detail["union_excluded"]
        invented = sorted(attributed - candidates)
        if invented:
            defects.append(f"{rid}: argument-targets attributes target(s) that "
                           "are not candidates: " + ", ".join(invented[:8]))
        # Round 4: candidate targets that no caller row attributes are admitted
        # conservatively.  The record names them in both candidate_source and
        # `unattributed_admissions`; the validator requires the two to agree and
        # requires every name to be a genuine, non-attributed candidate.
        un = source.get("unattributed_targets")
        if un is None:
            un = []
        if not isinstance(un, list) or not all(
                isinstance(t, str) and t for t in un):
            defects.append(f"{rid}: argument-targets unattributed_targets is "
                           "not a target-name list")
            un = []
        detail["unattributed"] = set(un)
        outside = sorted(detail["unattributed"] - candidates)
        if outside:
            defects.append(f"{rid}: argument-targets names unattributed "
                           "target(s) that are not candidates: "
                           + ", ".join(outside[:8]))
        detail["valid"] = not any("embeds no" in d for d in defects)
        if oracle is not None and module and oracle.knows(module):
            for symbol in detail["callers"]:
                observed, _b, checkable = oracle.is_reachable(module, symbol)
                if not checkable or observed is not True:
                    defects.append(
                        f"{rid}: argument-targets reachable caller {symbol!r} "
                        "is not in the final upper bound")
            for symbol in detail["excluded"]:
                observed, _b, checkable = oracle.is_reachable(module, symbol)
                if not checkable or observed is not False:
                    defects.append(
                        f"{rid}: argument-targets excluded caller {symbol!r} "
                        "is reached by the final upper bound or cannot be "
                        "checked")
        return candidates, defects, detail
    # resolver-admitted-set: the candidates are exactly the admitted set; an
    # exclusion cannot hide here because admitted targets can never also be
    # excluded.
    if source.get("class") is None and source.get("reason") is None:
        defects.append(f"{rid}: resolver-admitted-set candidate source names "
                       "neither a class nor a reason")
    return None, defects, {}


def _argument_binding_defects(rid, rec, oracle, module, detail, acct_admitted,
                             excluded, candidates):
    """Recompute every caller-bound target drop from ``candidate_source``.

    v1.2 read the claim's self-asserted ``contributed_targets``.  A record could
    therefore omit the one reachable caller that contributes the dropped target
    and still validate.  The mapping, the two contribution sets, the admitted
    set and the candidate set are now recomputed from candidate_source; the
    claim's mapping must equal the source's for the same symbols.

    Round 4 adds the conservative direction: a candidate that no caller row
    attributes is admitted, never dropped.  The record lists those admissions
    in ``unattributed_admissions`` and ``candidate_source.unattributed_targets``,
    and the two must agree.  A site whose *entire* candidate set is
    unattributable must be UNRESOLVED with the named missing property; it may
    not claim a bounded set.
    """
    defects = []
    callers = detail["callers"]
    excluded_map = detail["excluded"]
    union_callers = detail["union_callers"]
    union_excluded = detail["union_excluded"]
    unattributed = set(detail.get("unattributed") or ())
    disposition = rec.get("disposition")
    ident = rec.get("semantic_identity") or {}
    witness = ident.get("artifact_local_witness") or {}
    attribution = union_callers | union_excluded
    rows = [e for e in (rec.get("exclusions") or ()) if isinstance(e, dict)
            and e.get("reason") == "not-contributed-by-reachable-callers"]
    for row in rows:
        claim = row.get("claim") or {}
        claim_callers = claim.get("reachable_callers")
        mapping = {}
        if isinstance(claim_callers, list):
            for entry in claim_callers:
                if not isinstance(entry, dict):
                    continue
                symbol = entry.get("symbol")
                targets = entry.get("contributed_targets")
                if isinstance(symbol, str) and isinstance(targets, list):
                    mapping[symbol] = {t for t in targets if isinstance(t, str)}
        if mapping != callers:
            defects.append(
                f"{rid}: the claim's reachable-caller mapping does not equal "
                f"candidate_source's (claim {sorted(mapping)}, source "
                f"{sorted(callers)})")
        claim_excluded = claim.get("excluded_callers")
        if (not isinstance(claim_excluded, list)
                or set(claim_excluded) != set(excluded_map)):
            defects.append(
                f"{rid}: the claim's excluded-caller set does not equal "
                "candidate_source's")
    for row in rows:
        target = row.get("target")
        if not isinstance(target, str) or not target:
            continue
        if target not in union_excluded:
            defects.append(
                f"{rid}: excluded target {target!r} is not contributed by any "
                "excluded caller in candidate_source")
        if target in union_callers:
            defects.append(
                f"{rid}: excluded target {target!r} is contributed by a "
                "reachable caller in candidate_source")

    # ---- round-4 unattributed admissions -------------------------------- #
    admissions = rec.get("unattributed_admissions")
    if admissions is None:
        admissions = []
    if not isinstance(admissions, list):
        defects.append(f"{rid}: unattributed_admissions is not a list")
        admissions = []
    admitted_unattributed = set()
    for entry in admissions:
        if not isinstance(entry, dict):
            defects.append(f"{rid}: unattributed admission is not an object")
            continue
        target = entry.get("target")
        if not isinstance(target, str) or not target:
            defects.append(f"{rid}: unattributed admission names no target")
            continue
        admitted_unattributed.add(target)
        if entry.get("dso") != module:
            defects.append(f"{rid}: unattributed admission for {target!r} "
                           "names another module")
        if entry.get("site") != witness.get("site_address"):
            defects.append(f"{rid}: unattributed admission for {target!r} "
                           "names another site")
        if entry.get("function") != ident.get("defining_function"):
            defects.append(f"{rid}: unattributed admission for {target!r} "
                           "names another function")
        if not entry.get("reason"):
            defects.append(f"{rid}: unattributed admission for {target!r} "
                           "carries no reason")
    if admitted_unattributed != unattributed:
        defects.append(
            f"{rid}: unattributed_admissions {sorted(admitted_unattributed)} "
            "are not candidate_source's unattributed_targets "
            f"{sorted(unattributed)}")
    for target in sorted(admitted_unattributed):
        if target not in candidates:
            defects.append(f"{rid}: unattributed admission {target!r} is not "
                           "a candidate")
        if target in attribution:
            defects.append(f"{rid}: unattributed admission {target!r} is "
                           "attributed to a caller row")
        if target in excluded:
            defects.append(f"{rid}: unattributed admission {target!r} is "
                           "also excluded; an unattributable target is "
                           "admitted, never dropped")
        if disposition != DISPOSITION_UNRESOLVED \
                and target not in acct_admitted:
            defects.append(f"{rid}: unattributed admission {target!r} is not "
                           "admitted")

    # A caller-bound narrowing with *no* attributable candidate has no support
    # for a bounded set: it must be UNRESOLVED and name the incomplete
    # attribution, and it may not admit anything.
    has_attribution = bool(attribution & candidates)
    if candidates and not has_attribution:
        if disposition != DISPOSITION_UNRESOLVED:
            defects.append(
                f"{rid}: a caller-bound record with no attributable candidate "
                f"claims {disposition!r}")
        else:
            missing = rec.get("missing_property") or ""
            if not missing.startswith("caller attribution incomplete:"):
                defects.append(
                    f"{rid}: the attribution-incomplete fallback does not "
                    "name its missing property")
            if acct_admitted:
                defects.append(
                    f"{rid}: the attribution-incomplete fallback admits "
                    f"targets {sorted(acct_admitted)}")
            if unattributed != candidates:
                defects.append(
                    f"{rid}: the attribution-incomplete fallback does not "
                    "name every candidate as unattributed")

    if has_attribution:
        if oracle is not None and isinstance(module, str) and module \
                and oracle.knows(module):
            image = oracle.image_symbols_for(module)
            expected = (union_callers & image) if image is not None \
                else union_callers
            expected = expected | unattributed
            if acct_admitted != expected:
                defects.append(
                    f"{rid}: admitted_targets {sorted(acct_admitted)} are not "
                    "the reachable callers' contributed image targets plus "
                    "the unattributed admissions "
                    f"{sorted(expected)}")
        elif not acct_admitted <= (union_callers | unattributed):
            defects.append(
                f"{rid}: admitted_targets are not contributed by the "
                "reachable callers or admitted as unattributed in "
                "candidate_source")
    if candidates is not None and candidates != (acct_admitted | excluded
                                                 | unattributed):
        defects.append(
            f"{rid}: candidates {sorted(candidates)} are not admitted plus "
            "excluded plus unattributed "
            f"{sorted(acct_admitted | excluded | unattributed)}")
    return defects


def _derivation_defects(rid, chains):
    """Validate every provenance row; return (defects, derived, unproved)."""
    defects, derived, unproved = [], set(), set()
    if not isinstance(chains, list):
        return [f"{rid}: semantic identity has no provenance chain list"], derived, unproved
    for row in chains:
        if not isinstance(row, dict):
            defects.append(f"{rid}: provenance chain row is not an object")
            continue
        target = row.get("target")
        if not isinstance(target, str) or not target:
            defects.append(f"{rid}: provenance chain row has no target name")
            continue
        derivation = row.get("derivation")
        ok = True
        if not isinstance(derivation, list) or not derivation:
            defects.append(f"{rid}: provenance derivation for {target!r} is empty")
            ok = False
        else:
            for step in derivation:
                if not isinstance(step, dict):
                    defects.append(f"{rid}: provenance step for {target!r} is not "
                                   "an object")
                    ok = False
                    continue
                name = step.get("step")
                if name not in EDGE_CHAIN_STEPS:
                    defects.append(f"{rid}: provenance step {name!r} for "
                                   f"{target!r} is outside the closed vocabulary")
                    ok = False
                if not any(k != "step" and v is not None
                           for k, v in step.items()):
                    defects.append(f"{rid}: provenance step {name!r} for "
                                   f"{target!r} carries no payload")
                    ok = False
        if ok:
            derived.add(target)
            if any(isinstance(s, dict) and s.get("step") in EDGE_UNPROVED_STEPS
                   for s in derivation):
                unproved.add(target)
    return defects, derived, unproved


def _validate_record(rec: dict, oracle=None) -> list:
    """Every claim must be checkable; the record's ledgers are mutually
    redundant and cross-checked against the graph-derived oracle."""
    defects = []
    rid = rec.get("edge_id", "?")
    disposition = rec.get("disposition")
    ident = rec.get("semantic_identity") or {}
    witness = ident.get("artifact_local_witness") or {}
    module = witness.get("module")
    for field in ("source_operation", "defining_function", "call_site_role"):
        if not ident.get(field):
            defects.append(f"{rid}: semantic identity lacks {field}")
    if not isinstance(module, str) or not module:
        defects.append(f"{rid}: semantic identity names no module")
    elif oracle is not None and not oracle.knows(module):
        # Unknown module fails closed: "the oracle does not cover it" is a
        # defect, never a pass.
        defects.append(f"{rid}: the oracle does not cover the record's module "
                       f"{module!r}; the claim is not checkable")
    if disposition not in DISPOSITIONS:
        defects.append(f"{rid}: unknown disposition {disposition!r}")
        return defects
    defining = ident.get("defining_function")
    if disposition in (DISPOSITION_PROVED, DISPOSITION_CONTRACT) \
            and not _is_named_function(defining):
        defects.append(
            f"{rid}: {disposition} has no defining function symbol "
            f"({defining!r}); a target set cannot be attributed")
    if disposition == DISPOSITION_PROVED and not rec.get("target_set"):
        defects.append(f"{rid}: PROVED_TARGET_SET with an empty target set")
    if disposition == DISPOSITION_CONTRACT and not rec.get("witness_id"):
        defects.append(f"{rid}: CONTRACT_BOUNDED without a witness id")
    if disposition == DISPOSITION_UNRESOLVED and not rec.get("missing_property"):
        defects.append(f"{rid}: UNRESOLVED without a missing property")

    target_reachability = rec.get("target_reachability", "claimed")
    if target_reachability not in TARGET_REACHABILITY_VALUES:
        defects.append(f"{rid}: target_reachability {target_reachability!r} is "
                       "outside the closed vocabulary")
    expected_reachability = ("claimed" if disposition == DISPOSITION_PROVED
                             else "not-claimed")
    if target_reachability != expected_reachability:
        defects.append(
            f"{rid}: target_reachability {target_reachability!r} is not derived "
            f"from disposition {disposition!r} (expected "
            f"{expected_reachability!r})")

    exclusions = [e for e in (rec.get("exclusions") or ())
                  if isinstance(e, dict)]
    for ex in exclusions:
        defects.extend(_exclusion_row_defects(
            rid, f"exclusion {ex.get('target')!r}", ex, module, oracle, rec,
            "target-drop"))
    # These are exclusion claims outside the ``exclusions`` list; they get the
    # same row shape and the same checks, otherwise a dropped target could hide
    # in an auxiliary list.
    aux_rows = []
    for key in ("excluded_callers", "excluded_writers",
                "unbounded_call_sites"):
        rows = rec.get(key)
        if rows is None:
            continue
        if not isinstance(rows, list):
            defects.append(f"{rid}: {key} is not a list")
            continue
        for row in rows:
            label = (row.get("target") if isinstance(row, dict) else "?")
            defects.extend(_exclusion_row_defects(
                rid, f"{key} entry {label!r}", row, module, oracle, rec,
                "subject"))
            if isinstance(row, dict):
                aux_rows.append(row)

    chain_defects, derived, unproved = _derivation_defects(
        rid, ident.get("provenance_chain"))
    defects.extend(chain_defects)

    accounting = rec.get("exclusion_accounting")
    if not isinstance(accounting, dict):
        defects.append(f"{rid}: exclusion accounting is missing")
        return defects
    claimed = set(rec.get("target_set") or ())
    acct_admitted = set(accounting.get("admitted_targets") or ())
    excluded = {e.get("target") for e in exclusions
                if isinstance(e.get("target"), str) and e.get("target")}
    stored_excluded = set(accounting.get("excluded_targets") or ())
    if stored_excluded != excluded:
        defects.append(
            f"{rid}: accounting excluded_targets {sorted(stored_excluded)} "
            f"do not match the record's exclusions {sorted(excluded)}")

    candidates_recomputed, source_defects, source_detail = \
        _candidate_source_defects(rid, rec, oracle, module)
    defects.extend(source_defects)
    stored_candidates = set(accounting.get("candidate_targets") or ())
    if candidates_recomputed is None:
        candidates = stored_candidates
        if candidates != acct_admitted:
            defects.append(
                f"{rid}: a resolver-admitted-set enumeration must equal the "
                f"admitted set {sorted(acct_admitted)}, not "
                f"{sorted(candidates)}")
        if excluded:
            defects.append(
                f"{rid}: an exclusion cannot rest on the resolver-admitted-set "
                "enumeration, which has no separate source")
    else:
        candidates = candidates_recomputed
        if stored_candidates != candidates:
            defects.append(
                f"{rid}: candidate_targets do not match candidate_source "
                f"(stored {sorted(stored_candidates)}, recomputed "
                f"{sorted(candidates)})")
    if not acct_admitted <= candidates:
        defects.append(
            f"{rid}: admitted target(s) are not candidates of the "
            "enumeration: " + ", ".join(sorted(acct_admitted - candidates)[:8]))
    # `declared-name-absent` no longer exempts a target from the candidate set:
    # the target must be enumerated by candidate_source and bound by the row's
    # structured evidence.targets.  A free-text `target_derivation` never was a
    # candidate source.
    invented = sorted(excluded - candidates)
    if invented:
        defects.append(
            f"{rid}: exclusion target(s) are not candidates of the "
            "enumeration: " + ", ".join(invented[:8]))
    for row in exclusions:
        if row.get("reason") == "declared-name-absent":
            evidence = row.get("evidence") or {}
            listed = evidence.get("targets")
            if isinstance(listed, list):
                outside = sorted({t for t in listed if isinstance(t, str)
                                  and t not in candidates})
                if outside:
                    defects.append(
                        f"{rid}: declared-name-absent evidence.targets are "
                        "not candidates of the enumeration: "
                        + ", ".join(outside[:8]))
    for row in aux_rows:
        if row.get("reason") == "writer-not-in-reachable-set":
            would = (row.get("evidence") or {}).get("would_store_targets")
            if isinstance(would, list):
                outside = sorted({t for t in would if isinstance(t, str)
                                  and t not in candidates})
                if outside:
                    defects.append(
                        f"{rid}: writer-not-in-reachable-set "
                        "would_store_targets are not candidates of the "
                        "enumeration: " + ", ".join(outside[:8]))
    if source_detail.get("kind") == "argument-targets" \
            and source_detail.get("valid"):
        defects.extend(_argument_binding_defects(
            rid, rec, oracle, module, source_detail, acct_admitted, excluded,
            candidates))

    if disposition == DISPOSITION_PROVED:
        if claimed != acct_admitted:
            defects.append(
                f"{rid}: target_set {sorted(claimed)} is not the accounted "
                f"admitted set {sorted(acct_admitted)}")
        both = sorted(claimed & excluded)
        if both:
            defects.append(f"{rid}: admitted target(s) also excluded: "
                           + ", ".join(both[:8]))
        missing = sorted(claimed - derived)
        if missing:
            defects.append(f"{rid}: PROVED target(s) without a derivation: "
                           + ", ".join(missing[:8]))
        unproved_claimed = sorted(claimed & unproved)
        if unproved_claimed:
            defects.append(
                f"{rid}: claimed proved without an image-bounded derivation: "
                + ", ".join(unproved_claimed[:8]))
    elif disposition == DISPOSITION_CONTRACT:
        if claimed:
            defects.append(f"{rid}: CONTRACT_BOUNDED claims a target set")
        missing = sorted(acct_admitted - derived)
        if missing:
            defects.append(f"{rid}: contract-bounded target(s) without a "
                           "derivation: " + ", ".join(missing[:8]))
        both = sorted(acct_admitted & excluded)
        if both:
            defects.append(f"{rid}: admitted target(s) also excluded: "
                           + ", ".join(both[:8]))
        unproved_admitted = sorted(acct_admitted & unproved)
        if unproved_admitted:
            defects.append(f"{rid}: contract-bounded target(s) rest on an "
                           "unbounded step: "
                           + ", ".join(unproved_admitted[:8]))
    else:
        if claimed:
            defects.append(f"{rid}: UNRESOLVED claims a target set")
        if rec.get("target_set_claim") is not False:
            defects.append(f"{rid}: UNRESOLVED asserts target_set_claim")

    if accounting.get("candidate_enumeration") == "complete":
        # Recompute from the record itself rather than trusting the stored
        # accounting block: a stale or edited block must not hide a dropped
        # target.  Names are compared as sets: identical-code folding gives
        # several names to one address, so list length is not evidence.  An
        # unattributed admission (round 4) accounts for a candidate without
        # claiming it reachable.
        source_unattributed = (
            set(source_detail.get("unattributed") or ())
            if source_detail.get("kind") == "argument-targets" else set())
        unaccounted = sorted(candidates - acct_admitted - excluded
                             - source_unattributed)
        if unaccounted:
            defects.append(
                f"{rid}: excluded target(s) without a reason: "
                + ", ".join(unaccounted[:8]))
        stored_unaccounted = accounting.get("unaccounted_targets") or []
        if set(stored_unaccounted) != set(unaccounted):
            defects.append(
                f"{rid}: unaccounted_targets is stale: stored "
                f"{sorted(stored_unaccounted)}, recomputed {unaccounted}")
    return defects


class EdgeRecordValidator:
    """Stateful validator: per-record checks plus a duplicate-identity set."""

    def __init__(self, oracle=None):
        self.oracle = oracle
        self.seen_ids = set()

    def feed(self, rec) -> list:
        if not isinstance(rec, dict):
            return ["an edge record is not an object"]
        rid = rec.get("edge_id", "?")
        defects = []
        if not isinstance(rid, str) or not rid:
            defects.append("an edge record has no edge_id")
        elif rid in self.seen_ids:
            # v1.1 seeded ordinals by (function, role) but omitted the role
            # from edge_id, so two records could share one identity.
            defects.append(f"{rid}: duplicate edge_id (two records share one "
                           "identity)")
        else:
            self.seen_ids.add(rid)
        defects.extend(_validate_record(rec, self.oracle))
        return defects


def validate_edge_records(records: list, oracle=None) -> list:
    """Every claim must be checkable; the record's ledgers are mutually
    redundant and cross-checked against the graph-derived oracle.

    The admitted set is derived from three places that must agree: the
    ``target_set`` the record claims, the ``admitted_targets`` accounting block,
    and the provenance chains.  The candidate set comes from
    ``candidate_source``, separately from the accounting block.  With an
    oracle, every negative reachability claim is additionally checked against
    the final upper bound.
    """
    validator = EdgeRecordValidator(oracle)
    defects = []
    for rec in records:
        defects.extend(validator.feed(rec))
    return defects


def edge_refusal_for(defects: list):
    """The closure-level refusal for an uncheckable edge record."""
    if not defects:
        return None
    return {
        "code": "EDGE_RECORD_EXCLUSION_UNSOUND",
        "detail": ("the edge provenance record is not checkable: "
                   + "; ".join(defects[:8])),
    }


def edge_closure_refusal(records: list, oracle=None):
    """Validate a record set and return (defects, refusal).  A refusal here is
    the object `build_receipt` appends before emitting the closure."""
    defects = validate_edge_records(records, oracle)
    return defects, edge_refusal_for(defects)


def _audit_observation(oracle, module, symbol, address=None):
    if oracle is None:
        return None, "unavailable", False
    return oracle.is_reachable(module, symbol, address)


def _audit_symbol(oracle, module, symbol, address=None):
    """(in_final_upper_bound, basis) for one excluded symbol; unknown fails closed."""
    reachable, basis, checkable = _audit_observation(oracle, module, symbol,
                                                    address)
    if not checkable:
        return True, "unavailable"
    return bool(reachable), basis


def _audit_row(rec, oracle, claim_kind, target, symbol, expected,
               address=None):
    ident = rec.get("semantic_identity") or {}
    witness = ident.get("artifact_local_witness") or {}
    module = witness.get("module")
    observed, basis, checkable = _audit_observation(oracle, module, symbol,
                                                    address)
    violation = (not checkable) or (bool(observed) != (expected == "present"))
    return {
        "module": module,
        "edge_id": rec.get("edge_id"),
        "site": witness.get("site_address"),
        "function": ident.get("defining_function"),
        "role": ident.get("call_site_role"),
        "claim_kind": claim_kind,
        "target": target,
        "subject": symbol,
        "expected": expected,
        "in_final_upper_bound": bool(observed),
        "oracle_basis": basis,
        "checkable": bool(checkable),
        "violation": violation,
    }


def _audit_record(rec, oracle) -> list:
    """Audit every subject-scoped claim of one record against the bound.

    v1.1 walked only site metadata: a semantic call-site row with
    ``included: false`` and a caller-bound dropped target were never audited,
    and ``exclusions[].target`` was never checked.  The audit now walks the
    record, which is the object that actually carries the claims.
    """
    rows = []
    if not isinstance(rec, dict):
        return rows
    all_rows = [e for e in (rec.get("exclusions") or ()) if isinstance(e, dict)]
    for key in ("excluded_callers", "excluded_writers",
                "unbounded_call_sites"):
        all_rows.extend(r for r in (rec.get(key) or ()) if isinstance(r, dict))
    for row in all_rows:
        reason = row.get("reason")
        claim = row.get("claim") or {}
        evidence = row.get("evidence") or {}
        target = row.get("target")
        if reason in REACHABILITY_CLAIM_KINDS:
            addresses = _subject_addresses(evidence)
            for subject in claim.get("subjects") or ():
                rows.append(_audit_row(rec, oracle, reason, target, subject,
                                       "absent", addresses.get(subject)))
        elif reason == "declared-name-absent":
            # The declared name is checked by the validator; the *dropped
            # target* is a negative reachability claim in its own right and is
            # audited against the final upper bound here.
            for listed in (evidence.get("targets") or ()):
                rows.append(_audit_row(rec, oracle, reason, target, listed,
                                       "absent"))
        elif reason == "not-contributed-by-reachable-callers":
            addresses = _subject_addresses(evidence)
            for entry in claim.get("reachable_callers") or ():
                if not isinstance(entry, dict):
                    continue
                address = entry.get("address")
                try:
                    address = (int(address, 16) if isinstance(address, str)
                               else address)
                except ValueError:
                    address = None
                rows.append(_audit_row(rec, oracle, reason, target,
                                       entry.get("symbol"), "present", address))
            for subject in claim.get("excluded_callers") or ():
                rows.append(_audit_row(rec, oracle, reason, target, subject,
                                       "absent", addresses.get(subject)))
    source = rec.get("candidate_source") or {}
    if isinstance(source, dict) and source.get("kind") == "store-writer-call-sites":
        for row in source.get("rows") or ():
            if not isinstance(row, dict):
                continue
            if row.get("included") is False \
                    and row.get("reason") == "caller-not-in-reachable-set":
                rows.append(_audit_row(rec, oracle, "candidate-source-caller",
                                       None, row.get("caller"), "absent"))
    return rows


def reachability_exclusion_audit(graphs: dict, oracle, records=None) -> list:
    """Every reachability-based exclusion, checked against the final upper bound.

    The final upper bound is authoritative.  A claim that a caller, writer or
    dropped target is unreachable is a violation when the bound contains it,
    whichever branch of the derivation produced the claim.  An unknown module is
    itself a violation: "not checkable" is never a pass.
    """
    if records is None:
        records = build_edge_records(graphs, oracle)
    rows = []
    for rec in records:
        rows.extend(_audit_record(rec, oracle))
    return rows


def edge_record_summary(records: list) -> dict:
    counts = collections.Counter(r.get("disposition") for r in records)
    reasons = collections.Counter(
        e.get("reason") for r in records for e in (r.get("exclusions") or ()))
    demotions = collections.Counter(r.get("disposition_demotion")
                                    for r in records
                                    if r.get("disposition_demotion"))
    return {
        "schema": EDGE_RECORD_SCHEMA,
        "count": len(records),
        "dispositions": dict(sorted(counts.items())),
        "exclusion_reasons": dict(sorted(reasons.items())),
        "demotions": dict(sorted(demotions.items())),
    }


def _sample_view(rec: dict, cap: int = 32) -> dict:
    """A bounded projection of one record for the receipt.

    The population is in the JSONL sidecar; the sample exists so a reader can
    see the shape of every non-proved / exclusion-bearing / reachable-residual
    record without embedding 52k records (or their full lists) in the receipt.
    Exclusions are kept in full because they are the claims under review.
    """
    ident = dict(rec.get("semantic_identity") or {})
    chain = list(ident.get("provenance_chain") or ())
    ident["provenance_chain"] = chain[:cap]
    ident["provenance_chain_count"] = len(chain)
    accounting = dict(rec.get("exclusion_accounting") or {})
    for key in ("candidate_targets", "admitted_targets"):
        values = list(accounting.get(key) or ())
        accounting[key] = values[:cap]
        accounting[f"{key}_count"] = len(values)
    source = dict(rec.get("candidate_source") or {})
    if isinstance(source.get("rows"), list):
        rows = []
        for row in source["rows"][:cap]:
            item = dict(row)
            targets = list(item.get("targets") or ())
            item["targets"] = targets[:cap]
            item["target_count"] = len(targets)
            rows.append(item)
        source["rows"] = rows
        source["row_count"] = len(rec["candidate_source"]["rows"])
    if isinstance(source.get("targets"), list):
        targets = list(source["targets"])
        source["targets"] = targets[:cap]
        source["target_count"] = len(targets)
    return {
        "schema": rec.get("schema"),
        "edge_id": rec.get("edge_id"),
        "semantic_identity": ident,
        "disposition": rec.get("disposition"),
        "disposition_demotion": rec.get("disposition_demotion"),
        "target_set": rec.get("target_set"),
        "target_set_claim": rec.get("target_set_claim"),
        "target_reachability": rec.get("target_reachability"),
        "witness_id": rec.get("witness_id"),
        "missing_property": rec.get("missing_property"),
        "exclusions": rec.get("exclusions") or [],
        "excluded_callers": rec.get("excluded_callers") or [],
        "excluded_writers": rec.get("excluded_writers") or [],
        "unbounded_call_sites": rec.get("unbounded_call_sites") or [],
        "candidate_source": source,
        "exclusion_accounting": accounting,
        "unattributed_admissions": (
            list(rec.get("unattributed_admissions") or ())[:cap]),
        "unattributed_admissions_count": len(
            rec.get("unattributed_admissions") or ()),
        "sample_list_cap": cap,
    }


class EdgeRecordStream:
    """Validate, audit and persist edge records in one bounded pass.

    v1.1 accumulated every record and then ``json.dumps(receipt)`` in memory,
    which OOMed the ssh closure at the court's default 4 GiB.  The population is
    streamed to a JSONL sidecar (one JSON object per line); the receipt keeps
    counts, defects, audit rows and a bounded sample.
    """

    def __init__(self, oracle=None, path=None, sample_cap=None,
                 reachable_residual=()):
        self.oracle = oracle
        self.validator = EdgeRecordValidator(oracle)
        self.sample_cap = (EDGE_RECORD_SAMPLE_DEFAULT if sample_cap is None
                           else int(sample_cap))
        self.reachable_residual = set(reachable_residual)
        self.count = 0
        self.dispositions = collections.Counter()
        self.reasons = collections.Counter()
        self.demoted = collections.Counter()
        self.demoted_sites = []
        self.defects = []
        self._priority_sample = []
        self._other_sample = []
        self.sample_eligible = 0
        self.sample_truncated = False
        self.audit_rows = []
        self.audit_total = 0
        self.violations = 0
        self.violation_rows = []
        self.unattributed_total = 0
        self.unattributed_rows = []
        self.refutation_admissions = 0
        self.refuted_exclusions = collections.Counter()
        self.path = Path(path) if path is not None else None
        self.records_sha256 = None
        self._hash = hashlib.sha256()
        self._fh = open(self.path, "w") if self.path is not None else None
        self._written = 0

    def feed(self, record: dict) -> list:
        self.count += 1
        line = json.dumps(record, sort_keys=True) + "\n"
        self._hash.update(line.encode())
        if self._fh is not None:
            self._fh.write(line)
            self._written += 1
            if self._written % 200 == 0:
                self._fh.flush()
        self.dispositions[record.get("disposition")] += 1
        for row in record.get("exclusions") or ():
            if isinstance(row, dict):
                self.reasons[row.get("reason")] += 1
        demotion = record.get("disposition_demotion")
        if demotion:
            self.demoted[demotion] += 1
            if len(self.demoted_sites) < 40:
                ident = record.get("semantic_identity") or {}
                witness = ident.get("artifact_local_witness") or {}
                self.demoted_sites.append({
                    "module": witness.get("module"),
                    "function": ident.get("defining_function"),
                    "site": witness.get("site_address"),
                    "demotion": demotion,
                })
        self.defects.extend(self.validator.feed(record))
        admissions = record.get("unattributed_admissions") or ()
        if isinstance(admissions, list):
            self.unattributed_total += len(admissions)
            for entry in admissions:
                if len(self.unattributed_rows) < EDGE_AUDIT_RENDER_LIMIT:
                    self.unattributed_rows.append(entry)
        refuted = record.get("refuted_exclusions") or ()
        if isinstance(refuted, list):
            for entry in refuted:
                if isinstance(entry, dict):
                    self.refuted_exclusions[entry.get("role") or "?"] += 1
        admitted = record.get("refutation_admissions") or ()
        if isinstance(admitted, list):
            self.refutation_admissions += len(admitted)
        for row in _audit_record(record, self.oracle):
            self.audit_total += 1
            if row.get("violation"):
                self.violations += 1
                if len(self.violation_rows) < 8:
                    self.violation_rows.append(row)
            if len(self.audit_rows) < EDGE_AUDIT_RENDER_LIMIT:
                self.audit_rows.append(row)
        priority = self._sample_priority(record)
        if priority is not None:
            self.sample_eligible += 1
            view = _sample_view(record)
            if priority == 0:
                # The claims under review (every exclusion-bearing record and
                # every reachable residual site) are admitted first so a large
                # UNRESOLVED population cannot crowd them out of the sample.
                if len(self._priority_sample) < self.sample_cap:
                    self._priority_sample.append(view)
                    overflow = (len(self._priority_sample)
                                + len(self._other_sample) - self.sample_cap)
                    if overflow > 0:
                        del self._other_sample[:overflow]
                else:
                    self.sample_truncated = True
            elif len(self._priority_sample) + len(self._other_sample) \
                    < self.sample_cap:
                self._other_sample.append(view)
            else:
                self.sample_truncated = True
        return record

    __call__ = feed

    def _sample_priority(self, record):
        """0 = exclusion/reachable-residual, 1 = non-PROVED, None = other."""
        ident = record.get("semantic_identity") or {}
        witness = ident.get("artifact_local_witness") or {}
        if record.get("exclusions"):
            return 0
        if (witness.get("module"), witness.get("site_address")) in \
                self.reachable_residual:
            return 0
        if record.get("disposition") != DISPOSITION_PROVED:
            return 1
        return None

    @property
    def sample(self):
        return self._priority_sample + self._other_sample

    def close(self):
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None
        self.records_sha256 = self._hash.hexdigest()

    def summary(self) -> dict:
        return {
            "schema": EDGE_RECORD_SCHEMA,
            "count": self.count,
            "dispositions": dict(sorted(self.dispositions.items())),
            "exclusion_reasons": dict(sorted(self.reasons.items())),
            "unattributed_admissions": {
                "count": self.unattributed_total,
                "truncated": self.unattributed_total
                             > len(self.unattributed_rows),
                "rule": ("a candidate target that no caller row attributes is "
                         "admitted into the upper bound and never dropped; the "
                         "list is the receipt's account of those admissions"),
                "admissions": self.unattributed_rows,
            },
            "refutation_admissions": {
                "count": self.refutation_admissions,
                "refuted_exclusions_by_role": dict(
                    sorted(self.refuted_exclusions.items())),
                "rule": ("an exclusion the final upper bound refutes is "
                         "admitted with its witness on the record that carries "
                         "it; the subject and the admitted targets are named in "
                         "the record's refutation_admissions"),
            },
        }


def _tool_identity() -> dict:
    """The exact validator identity bound into every receipt (AGENTS.md 22)."""
    path = Path(__file__).resolve()
    return {"path": TOOL, "version": 5,
            "sha256": sha256_file(path),
            "schema": EDGE_RECORD_SCHEMA}


def _edge_records_path(args, repo: Path, artifact_sha: str,
                       workdir: Path) -> Path:
    """Where the record sidecar goes.

    The default is always the (gitignored) workdir: a multi-hundred-MB sidecar
    must never land beside ``--output`` by accident.  ``--edge-records`` is the
    only way to choose another path, and it is explicit.
    """
    explicit = getattr(args, "edge_records", None)
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = (repo / path).resolve()
        return path
    return workdir / f"edge-records.{artifact_sha[:16]}.jsonl"


def _admissibility(tool_sha256: str, artifact_sha256: str,
                   records_sha256, sidecar_lines: int) -> dict:
    """The identity chain a reader must re-run to admit a record set.

    Record-level validation cannot distinguish an analyzer-produced record from
    a forged one that is internally consistent.  This block is the binding a
    reader needs: the pinned validator digest, the record schema, the analysed
    artefact, the sidecar digest and its line count.
    """
    return {
        "validator_sha256": tool_sha256,
        "record_schema": EDGE_RECORD_SCHEMA,
        "artifact_sha256": artifact_sha256,
        "records_sha256": records_sha256,
        "sidecar_lines": sidecar_lines,
    }


ANALYSIS_IDENTITY_SCHEMA = "openssl-rs/campaign/safe-c33/analysis-identity/v2"
UNRESOLVED_BOUND_SCHEMA = "openssl-rs/campaign/safe-c33/unresolved-site-bound/v1"

# Sections the identity always binds when present (the required minimum from
# the P0-A specification).  The implementation binds *every* SHF_ALLOC section,
# so this list is documentation and a required-subset check, not the whole set.
ANALYSIS_IDENTITY_SECTIONS = (
    ".text",
    ".plt",
    ".plt.got",
    ".init",
    ".fini",
    ".rodata",
    ".data",
    ".data.rel.ro",
    ".data.rel.ro.local",
    ".got",
    ".got.plt",
    ".init_array",
    ".fini_array",
)
# SHT_NOBITS: the analysis reads the address/size (section_of) and treats a
# .bss slot as zero; there are no file bytes to hash.
ANALYSIS_IDENTITY_NOBITS_SECTIONS = (".bss",)

# Non-allocated / metadata sections that are never an analysis input.  The
# selection is "SHF_ALLOC minus these prefixes", so a new allocated section is
# bound automatically rather than silently omitted.
ANALYSIS_IDENTITY_EXCLUDED_PREFIXES = (
    ".debug_",
    ".zdebug_",
    ".note",
    ".comment",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
    ".gnu.build.attributes",
)
# Named for the receipt's basis string.
ANALYSIS_IDENTITY_EXCLUDED_CLASSES = (
    ".debug_*",
    ".zdebug_*",
    ".comment",
    ".note*",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
    ".gnu.build.attributes",
    "every non-allocated section (SHF_ALLOC is absent)",
)


def _analysis_identity_basis() -> str:
    return (
        "sha256 over, in module-name order, each module name and a canonical "
        "JSON input record: every allocated (SHF_ALLOC) section's (name, ELF "
        "type, virtual address, size, sha256 of its bytes), the sorted "
        "relocation table (section, section-relative offset, type, canonical "
        "symbol, addend), the sorted [name, addr, size, kind] defined-symbol "
        "rows, the sorted dynamic-symbol rows, and the loader entries "
        "(SONAME/NEEDED/RUNPATH/RPATH). Required minimum sections: "
        + ", ".join(ANALYSIS_IDENTITY_SECTIONS)
        + "; NOBITS sections (address/size only): "
        + ", ".join(ANALYSIS_IDENTITY_NOBITS_SECTIONS)
        + ". Excluded: "
        + ", ".join(ANALYSIS_IDENTITY_EXCLUDED_CLASSES)
        + ". ``.llvm.<hash>`` and ``@@VERSION`` suffixes are canonicalised as "
        "in the symbol table; the DSO file digest is recorded as a non-identity."
    )


def reachable_function_entries(graphs: dict, upper_reach,
                                *, canonical: bool = True) -> list:
    """The sorted ``module:hex_address:name`` entries of the reachable set.

    ``canonical`` applies the same name canonicalisation as
    :func:`analysis_identity` (drop the compiler ``.llvm.<hash>`` suffix and the
    symbol-version suffix).  Those suffixes are a function of the build
    directory and source bytes, not of the analysis subject: a comment-only
    edit changes every affected name hash while the address, size and kind do
    not move.  A movement digest built from the raw names would therefore
    report movement for a neutral rebuild.  The raw form is still available as
    an explicitly non-identity observation.
    """
    entries = []
    for dso_name, addr in upper_reach:
        name = (getattr(graphs[dso_name], "funcs", {}) or {}).get(addr)
        if name is None:
            continue
        if canonical:
            name = canonical_symbol_name(name)
        entries.append(f"{dso_name}:{addr:#x}:{name}")
    return sorted(entries)


def reachable_functions_digest(entries) -> str:
    """sha256 over the newline-terminated sorted reachable-function entries."""
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry.encode() + b"\n")
    return digest.hexdigest()


def _canonical_json_digest(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def analysis_identity(graphs: dict) -> dict:
    """A canonical identity for the *analysis input* (AGENTS.md section 22).

    The DSO file digest is **not** an analysis identity: a comment-only source
    edit changes the file digest (build paths, debug strings, the
    ``.llvm.<hash>`` names) while the executable bytes and the symbol
    addresses are unchanged.  The identity therefore hashes every input the
    graph derivation consumes, per module:

      * each analysis-relevant section's name, ELF type, virtual address, size
        and byte digest (``DsoGraph.analysis_section_descriptors``);
      * the canonical relocation table ``(section, offset, type, symbol,
        addend)`` that supplies GOT/PLT and dispatch-slot targets;
      * the sorted ``[name, addr, size, kind]`` defined-symbol rows;
      * the sorted dynamic-symbol rows (the export set);
      * the loader entries (SONAME/NEEDED/RUNPATH/RPATH).

    Analysis-irrelevant metadata (``.debug_*``, ``.comment``, ``.note*``,
    ``.gnu_debuglink``, the build-id note, and raw symbol/relocation section
    bytes whose parsed forms are hashed) is excluded and named in ``basis``.
    Two modules with the same identity have the same input to this analysis;
    that is not a claim that the analysis is complete.
    """
    outer = hashlib.sha256()
    outer.update(ANALYSIS_IDENTITY_SCHEMA.encode() + b"\0")
    modules = {}
    for name in sorted(graphs):
        g = graphs[name]
        text_sha, text_size = g.text_digest()
        rows = g.symbol_table_rows()
        sym_sha = _canonical_json_digest(rows)

        section_fn = getattr(g, "analysis_section_descriptors", None)
        sections = section_fn() if callable(section_fn) else []
        excluded_fn = getattr(g, "analysis_excluded_sections", None)
        excluded = excluded_fn() if callable(excluded_fn) else []

        reloc_fn = getattr(g, "canonical_relocations", None)
        relocs = reloc_fn() if callable(reloc_fn) else []
        reloc_sha = _canonical_json_digest(relocs)

        dynrows_fn = getattr(g, "dynamic_symbol_rows", None)
        dynrows = dynrows_fn() if callable(dynrows_fn) else []
        dyn_sha = _canonical_json_digest(dynrows)

        entries_fn = getattr(g, "dynamic_entries", None)
        entries = entries_fn() if callable(entries_fn) else {}
        entries_sha = _canonical_json_digest(entries)

        # The hashed record is the full canonical input.  The receipt keeps the
        # digests and counts: the full relocation list is ~46k rows for the real
        # libcrypto and would bloat the receipt without adding evidence beyond
        # the digest and the negative control that exercises it.
        input_record = {
            "sections": sections,
            "relocations": relocs,
            "symbol_rows": rows,
            "dynamic_symbol_rows": dynrows,
            "dynamic_entries": entries,
        }
        input_sha = _canonical_json_digest(input_record)

        modules[name] = {
            "text_sha256": text_sha,
            "text_size": text_size,
            "symbol_rows": len(rows),
            "symbol_table_sha256": sym_sha,
            "dynamic_symbol_rows": len(dynrows),
            "dynamic_symbol_table_sha256": dyn_sha,
            "relocations": len(relocs),
            "relocation_table_sha256": reloc_sha,
            "dynamic_entries_sha256": entries_sha,
            "sections": sections,
            "excluded_sections": excluded,
            "input_sha256": input_sha,
            "dso_sha256": getattr(g, "sha256", None),
            "dso_sha256_is_analysis_identity": False,
        }
        outer.update(name.encode() + b"\0" + input_sha.encode() + b"\0")
    included_union = sorted({row["name"] for module in modules.values()
                             for row in module["sections"]})
    return {
        "schema": ANALYSIS_IDENTITY_SCHEMA,
        "basis": _analysis_identity_basis(),
        "included_sections": included_union,
        "required_sections": list(ANALYSIS_IDENTITY_SECTIONS),
        "nobits_sections": list(ANALYSIS_IDENTITY_NOBITS_SECTIONS),
        "excluded_classes": list(ANALYSIS_IDENTITY_EXCLUDED_CLASSES),
        "digest": outer.hexdigest(),
        "modules": modules,
        "note": (
            "the DSO file digest is recorded as a non-identity: it changes with "
            "build paths and debug strings when the executable bytes do not. "
            "Input completeness is not proved by this digest: it binds the "
            "enumerated inputs, and a future analysis that reads another section "
            "must extend the enumeration."),
    }


def unresolved_site_bound(g: "DsoGraph", site: dict) -> set:
    """Every value a residual site may target -- **independent of its class**.

    Soundness rule (why this is not the class-specific set): the reachable set
    is a may-analysis, so it must be monotone under precision loss.  A site
    that is re-classified from ``PROVED_TARGET_SET`` to ``UNRESOLVED`` must not
    admit *fewer* targets than it did before.  The only way to guarantee that
    against an arbitrary re-classification is to bound every residual site by
    the union of *all* materialised-address evidence in the module:

      * ``address_taken_union`` (code and data materialisations, relocated
        function slots, and in-image dynamic-relocation targets),
      * ``taken_code`` (kept explicitly so the source is named in the record),
      * every integer stored into a field by reachable code,
      * values passed at unresolved call sites,
      * the site's own resolver ``targets`` and ``arg_targets``.

    A class-specific set may still be reported as precision metadata (it is,
    in ``precision.unresolved_by_class`` and the per-site class), but it is
    never the sole bound.  A bound may be **widened** for soundness; it is
    never narrowed by classification.
    """
    values = set()
    values |= set(getattr(g, "address_taken_union", ()) or ())
    values |= set(getattr(g, "taken_code", ()) or ())
    for stored in (getattr(g, "field_stores", None) or {}).values():
        values |= set(stored)
    values |= set(getattr(g, "unknown_call_arg_targets", ()) or ())
    values |= set(site.get("targets") or ())
    values |= set(site.get("arg_targets") or ())
    return values


def _symbol_base(symbol: str) -> str:
    """The version-stripped form of a relocation symbol name."""
    return symbol.split("@", 1)[0]


# Resolution order for a symbolic residual-bound value (P0-B).  The order is
# fixed by the task and recorded in every disposition row, so a reader can see
# which path actually resolved a symbol.
SYMBOL_RESOLUTION_ORDER = (
    "exact-export",
    "version-stripped-export",
    "names-at",
    "dynamic-symbol-table",
    "soname-qualified-import",
    "plt-stub",
)

# A *documented* external interface may cover a symbol that is not defined by
# the closed candidate DSO set.  This table is deliberately exact-name only and
# deliberately small: an OpenSSL-shaped name, a name absent from the table, or a
# name whose interface is not cited here is ``blocking``, never external.  It is
# not a wildcard and it is not a way to clear a refusal.
EXTERNAL_SYMBOL_CONTRACTS = {
    "malloc": {
        "interface": "ISO/IEC 9899:2018 7.22.3 malloc",
        "why_outside": (
            "the C library allocator is resolved by the process loader, not by "
            "any candidate OpenSSL DSO; the consumer owns the allocator contract"),
    },
    "calloc": {
        "interface": "ISO/IEC 9899:2018 7.22.3 calloc",
        "why_outside": "C library allocator resolved by the process loader",
    },
    "realloc": {
        "interface": "ISO/IEC 9899:2018 7.22.3 realloc",
        "why_outside": "C library allocator resolved by the process loader",
    },
    "free": {
        "interface": "ISO/IEC 9899:2018 7.22.3 free",
        "why_outside": "C library allocator resolved by the process loader",
    },
    "memcpy": {
        "interface": "ISO/IEC 9899:2018 7.24.2.1 memcpy",
        "why_outside": "C library memory function resolved by the process loader",
    },
    "memmove": {
        "interface": "ISO/IEC 9899:2018 7.24.2.2 memmove",
        "why_outside": "C library memory function resolved by the process loader",
    },
    "memset": {
        "interface": "ISO/IEC 9899:2018 7.24.6.1 memset",
        "why_outside": "C library memory function resolved by the process loader",
    },
    "memcmp": {
        "interface": "ISO/IEC 9899:2018 7.24.4.1 memcmp",
        "why_outside": "C library memory function resolved by the process loader",
    },
    "strlen": {
        "interface": "ISO/IEC 9899:2018 7.24.6.3 strlen",
        "why_outside": "C library string function resolved by the process loader",
    },
    "strcmp": {
        "interface": "ISO/IEC 9899:2018 7.24.4.2 strcmp",
        "why_outside": "C library string function resolved by the process loader",
    },
    "__stack_chk_fail": {
        "interface": "GNU C library stack-smashing protector runtime (libc)",
        "why_outside": "libc runtime stub resolved by the process loader",
    },
    "dlopen": {
        "interface": "POSIX.1-2017 dlopen",
        "why_outside": "dynamic loader interface resolved by libc/ld.so",
    },
    "dlsym": {
        "interface": "POSIX.1-2017 dlsym",
        "why_outside": "dynamic loader interface resolved by libc/ld.so",
    },
    "dlclose": {
        "interface": "POSIX.1-2017 dlclose",
        "why_outside": "dynamic loader interface resolved by libc/ld.so",
    },
    "dlerror": {
        "interface": "POSIX.1-2017 dlerror",
        "why_outside": "dynamic loader interface resolved by libc/ld.so",
    },
    "deflate": {
        "interface": "zlib manual, deflate()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "inflate": {
        "interface": "zlib manual, inflate()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "deflateInit_": {
        "interface": "zlib manual, deflateInit_()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "inflateInit_": {
        "interface": "zlib manual, inflateInit_()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "deflateEnd": {
        "interface": "zlib manual, deflateEnd()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "inflateEnd": {
        "interface": "zlib manual, inflateEnd()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
    "crc32": {
        "interface": "zlib manual, crc32()",
        "why_outside": "zlib is a separate DSO resolved by the process loader",
    },
}


def _plt_stub_targets(g, base: str, slot_offsets) -> list:
    """PLT entries whose jump targets one of ``base``'s relocation slots.

    ``objdump`` annotates a PLT stub's indirect jump with the GOT slot, e.g.
    ``jmp *0x2f3d(%rip) # 895ff8 <malloc@GLIBC_2.2.5>``.  A stub is a valid
    in-image function node for that slot; it is the last resolution path before
    the symbol is declared blocking.
    """
    wanted = set(slot_offsets)
    if not wanted:
        return []
    start_set = getattr(g, "start_set", set()) or set()
    section_of = getattr(g, "section_of", None)
    out = set()
    for fstart, insns in getattr(g, "functions", ()) or ():
        if fstart not in start_set or not callable(section_of):
            continue
        if section_of(fstart) not in (".plt", ".plt.got"):
            continue
        for _ins_addr, text in insns:
            head = text.split("#", 1)[0]
            if "jmp" not in head:
                continue
            m = re.search(r"#\s*([0-9a-f]+)\s+<", text)
            if m and int(m.group(1), 16) in wanted:
                out.add(fstart)
                break
    return sorted(out)


def _resolve_symbolic_value(g, dso_name: str, symbol: str,
                            export_index: dict) -> dict:
    """Resolve one symbolic residual-bound value through the fixed order.

    Returns a disposition row.  ``resolved`` carries every in-image target the
    path found; ``external-contract`` names the documented interface; anything
    else is ``blocking`` and is refused by :func:`closure_refusals`.
    """
    base = _symbol_base(symbol)
    slot_offsets = sorted(
        off for off, names in (getattr(g, "slot_syms", {}) or {}).items()
        if any(_symbol_base(n) == base for n in names))
    row = {
        "symbol": symbol,
        "base": base,
        "module": dso_name,
        "disposition": "blocking",
        "path": None,
        "targets": [],
        "slot_offsets": [f"0x{off:x}" for off in slot_offsets],
        "sites": [],
        "reason": None,
        "external_interface": None,
        "external_justification": None,
    }

    def resolved(path: str, targets):
        row.update(disposition="resolved", path=path,
                   targets=[[m, a] for m, a in targets])
        return row

    # 1. exact export (bare name in the resolved candidate export index)
    target = export_index.get(symbol)
    if target:
        return resolved("exact-export", [target])
    # 2. version-stripped export
    target = export_index.get(base)
    if target:
        return resolved("version-stripped-export", [target])
    # 3. ICF/alias names: every address at which the defined symbol table
    #    names this symbol.  Keep all addresses; an ICF alias is not one edge.
    index_fn = getattr(g, "symbol_addresses_by_name", None)
    if callable(index_fn):
        by_name = index_fn()
    else:
        by_name = collections.defaultdict(list)
        for addr, names in (getattr(g, "names_at", {}) or {}).items():
            for name in names:
                by_name[name.split("@")[0]].append(addr)
    addrs = sorted(a for a in by_name.get(base, ())
                   if a in (getattr(g, "start_set", set()) or set()))
    if addrs:
        return resolved("names-at", [(dso_name, a) for a in addrs])
    # 4. dynamic-symbol table of this module
    addr = (getattr(g, "dynamic_defs", {}) or {}).get(base)
    if addr in (getattr(g, "start_set", set()) or set()):
        return resolved("dynamic-symbol-table", [(dso_name, addr)])
    # 5. SONAME-qualified import (``libcrypto.so.3:NAME``)
    if ":" in symbol:
        soname, _, rest = symbol.partition(":")
        target = export_index.get(rest) or export_index.get(_symbol_base(rest))
        if target and target[0] == soname:
            return resolved("soname-qualified-import", [target])
    # 6. PLT stub
    stubs = _plt_stub_targets(g, base, slot_offsets)
    if stubs:
        return resolved("plt-stub", [(dso_name, a) for a in stubs])
    # Documented external interface, or blocking.
    contract = EXTERNAL_SYMBOL_CONTRACTS.get(base)
    if contract:
        row.update(disposition="external-contract", path="external-contract",
                   external_interface=contract["interface"],
                   external_justification=contract["why_outside"])
        return row
    row["reason"] = (
        "no exact or version-stripped export, names-at alias, dynamic symbol, "
        "SONAME-qualified import or PLT stub resolves this symbol, and no "
        "documented external interface covers it")
    return row


def _bound_nodes(g, dso_name: str, values, export_index: dict,
                 site: tuple | None = None) -> tuple[set, int, list]:
    """Map bound values to reachable nodes, widening rather than narrowing.

    An integer that is a defined function start is its own node.  An integer
    that lies inside executable code is mapped to its enclosing function start
    (a widening: a transfer into the middle of a function still reaches that
    function).  Any other integer is not an executable address and cannot be a
    function entry; it is counted, not silently discarded.  A symbolic target
    is resolved through the fixed :data:`SYMBOL_RESOLUTION_ORDER`; every
    symbolic value yields a disposition row, so none is counted and discarded.
    """
    nodes = set()
    non_code = 0
    symbols = []
    start_set = getattr(g, "start_set", set()) or set()
    section_of = getattr(g, "section_of", None)
    containing = getattr(g, "containing", None)
    for value in values:
        if isinstance(value, tuple):
            if len(value) == 2 and value[0] == "sym":
                row = _resolve_symbolic_value(g, dso_name, value[1], export_index)
                if site is not None:
                    row["sites"] = sorted(set(row.get("sites") or [])
                                          | {f"0x{site[1]:x}"})
                for target in row.get("targets") or ():
                    nodes.add((target[0], target[1]))
                symbols.append(row)
            continue
        if not isinstance(value, int) or isinstance(value, bool):
            continue
        if value in start_set:
            nodes.add((dso_name, value))
            continue
        section = section_of(value) if callable(section_of) else None
        if section in (".text", ".plt", ".plt.got") and callable(containing):
            base = containing(value)
            if base is not None:
                nodes.add((dso_name, base))
                continue
        non_code += 1
    return nodes, non_code, symbols


def build_graph(graphs: dict, roots: set, export_index: dict,
                import_nodes: set | None = None,
                max_rounds: int | None = None) -> dict:
    """Union reachability over all candidate DSOs, as a least fixed point.

    Direct call edges come from the linked machine code.  Indirect sites carry
    the target set the precision resolver established.  A site whose value is
    genuinely data-dependent is admitted at its **evidence class** (a field
    offset, an argument summary, or a code-materialised address) for reporting,
    but its reachability bound is the class-independent union in
    :func:`unresolved_site_bound`.

    Residual admission is iterated to convergence (chaotic/worklist iteration,
    Kildall 1973; Cousot & Cousot 1977):

        reach = walk(roots)
        repeat: bound = union of unresolved_site_bound over every unresolved
                site whose containing function is in reach;
                reach' = walk(reach | bound);
        until reach' == reach

    Each round is monotone (the bound never shrinks and ``walk`` is a graph
    closure), so the sequence is increasing in a finite lattice of function
    nodes and terminates; ``max_rounds`` bounds the iteration and a failure to
    converge is reported, never silently accepted.
    """
    import_nodes = {n for n in (import_nodes or ()) if n and n[0] in graphs}
    site_edges = collections.defaultdict(set)
    resolved_targets = set()
    for g in graphs.values():
        for key, s in getattr(g, "sites", {}).items():
            fstart = key[0]
            for t in s["targets"]:
                node = None
                if isinstance(t, int):
                    node = (g.name, t)
                elif isinstance(t, tuple) and t[0] == "sym":
                    node = export_index.get(t[1])
                if node is not None:
                    site_edges[(g.name, fstart)].add(node)
                    resolved_targets.add(node)

    unresolved_by_func = collections.defaultdict(list)
    for g in graphs.values():
        for key, s in getattr(g, "sites", {}).items():
            if s["unresolved"]:
                unresolved_by_func[(g.name, key[0])].append(s)

    def walk(initial):
        reach = set(initial)
        frontier = list(initial)
        while frontier:
            nxt = []
            for dso_name, addr in frontier:
                g = graphs.get(dso_name)
                if g is None:
                    continue
                for t in g.direct.get(addr, ()):
                    node = (dso_name, t)
                    if node not in reach:
                        reach.add(node)
                        nxt.append(node)
                for node in site_edges.get((dso_name, addr), ()):
                    if node not in reach:
                        reach.add(node)
                        nxt.append(node)
                sym = g.funcs.get(addr)
                if sym:
                    other = export_index.get(sym.split("@")[0])
                    if other and other not in reach:
                        reach.add(other)
                        nxt.append(other)
            frontier = nxt
        return reach

    # Module-global half of the bound.  Computed once: it does not depend on
    # the site, only on the module's materialised-address evidence.  It is the
    # production bound helper applied to an empty site, so the mutation control
    # ("narrow the bound by class") exercises this exact code path.
    module_values = {}
    module_bound = {}
    bound_sources = {}
    # Every symbolic value in the bound gets exactly one disposition row
    # (resolved / external-contract / blocking).  A site-extra occurrence adds
    # its call-site address; the row is never dropped and a bare count is not
    # the evidence.
    symbol_dispositions = {}

    def merge_symbol(row, site=None):
        key = (row["module"], row["symbol"])
        cur = symbol_dispositions.get(key)
        if cur is None:
            cur = dict(row)
            cur["targets"] = [list(t) for t in (row.get("targets") or [])]
            cur["slot_offsets"] = list(row.get("slot_offsets") or [])
            cur["sites"] = []
            symbol_dispositions[key] = cur
        for target in row.get("targets") or []:
            if target not in cur["targets"]:
                cur["targets"].append(list(target))
        for off in row.get("slot_offsets") or []:
            if off not in cur["slot_offsets"]:
                cur["slot_offsets"].append(off)
        if site is not None:
            cur["sites"].append(f"0x{site[1]:x}")
        cur["sites"] = sorted(set(cur["sites"]))
        cur["slot_offsets"] = sorted(set(cur["slot_offsets"]))

    for dso_name, g in graphs.items():
        values = unresolved_site_bound(g, {})
        module_values[dso_name] = values
        nodes, non_code, symbol_rows = _bound_nodes(
            g, dso_name, values, export_index)
        for row in symbol_rows:
            merge_symbol(row)
        module_bound[dso_name] = nodes
        field_values = {v for stored in (getattr(g, "field_stores", None)
                                         or {}).values() for v in stored}
        bound_sources[dso_name] = {
            "module": dso_name,
            "taken_code": len(getattr(g, "taken_code", ()) or ()),
            "taken_data": len(getattr(g, "taken_data", ()) or ()),
            "slot_func_targets": len(getattr(g, "slot_func_targets", ()) or ()),
            "dynamic_reloc_targets": len(
                getattr(g, "dynamic_reloc_targets", ()) or ()),
            "address_taken_union": len(
                getattr(g, "address_taken_union", ()) or ()),
            "field_store_values": len(field_values),
            "unknown_call_arg_targets": len(
                getattr(g, "unknown_call_arg_targets", ()) or ()),
            "bound_values": len(values),
            "bound_nodes": len(nodes),
            "non_code_values": non_code,
            "symbol_values": len(symbol_rows),
            "resolved_symbol_values": sum(
                1 for r in symbol_rows if r["disposition"] == "resolved"),
            "external_contract_symbol_values": sum(
                1 for r in symbol_rows
                if r["disposition"] == "external-contract"),
            "unresolved_symbol_values": sum(
                1 for r in symbol_rows if r["disposition"] == "blocking"),
            "symbol_disposition_symbols": sorted(r["symbol"]
                                                 for r in symbol_rows),
        }

    # Site-specific half: the site's own resolver targets, on top of the same
    # module union.  Computed once.
    site_extra = {}
    for dso_name, sites in unresolved_by_func.items():
        g = graphs.get(dso_name[0])
        for s in sites:
            if g is None:
                site_extra[id(s)] = set()
                continue
            extra = unresolved_site_bound(g, s) - module_values[dso_name[0]]
            if not extra:
                site_extra[id(s)] = set()
                continue
            site = (dso_name[0], s.get("addr", dso_name[1]))
            nodes, _non_code, symbol_rows = _bound_nodes(
                g, dso_name[0], extra, export_index, site=site)
            for row in symbol_rows:
                merge_symbol(row, site=site)
            site_extra[id(s)] = nodes

    total_functions = sum(len(getattr(g, "funcs", {})) for g in graphs.values())
    if max_rounds is None:
        max_rounds = 4 * total_functions + 8
    max_rounds = max(1, int(max_rounds))

    direct_reach = walk(set(roots) | import_nodes)
    reach = set(direct_reach)
    round_sizes = [len(reach)]
    sites_scanned_per_round = [0]
    converged = False
    rounds = 0
    bound = set()
    last_growth = None
    for rnd in range(1, max_rounds + 1):
        rounds = rnd
        bound = set()
        scanned = 0
        for (dso_name, fstart), sites in unresolved_by_func.items():
            if (dso_name, fstart) not in reach:
                continue
            bound |= module_bound[dso_name]
            for s in sites:
                scanned += 1
                bound |= site_extra[id(s)]
        nxt = walk(reach | bound | import_nodes)
        round_sizes.append(len(nxt))
        sites_scanned_per_round.append(scanned)
        if nxt == reach:
            converged = True
            break
        last_growth = len(nxt) - len(reach)
        reach = nxt
    if not converged:
        reach = nxt

    reachable_residual_sites = []
    unclassified = set()
    for (dso_name, fstart), sites in unresolved_by_func.items():
        if (dso_name, fstart) not in reach:
            continue
        for s in sites:
            reachable_residual_sites.append((dso_name, fstart, s))
            if s["class"] == "unclassified":
                unclassified.add((dso_name, fstart, s["reason"]))
    reachable_residual_sites.sort(key=lambda r: (r[0], r[1], r[2].get("addr", 0)))

    disposition_rows = sorted(symbol_dispositions.values(),
                              key=lambda r: (r["module"], r["symbol"]))
    disposition_summary = {
        "schema": "openssl-rs/campaign/safe-c33/symbol-disposition/v1",
        "resolution_order": list(SYMBOL_RESOLUTION_ORDER),
        "resolved": sum(1 for r in disposition_rows
                        if r["disposition"] == "resolved"),
        "external-contract": sum(1 for r in disposition_rows
                                 if r["disposition"] == "external-contract"),
        "blocking": sum(1 for r in disposition_rows
                        if r["disposition"] == "blocking"),
        "rule": (
            "every symbolic value in the module residual bound and in a "
            "residual site's own bound is resolved through the fixed order "
            "exact-export, version-stripped-export, names-at, "
            "dynamic-symbol-table, soname-qualified-import, plt-stub; a "
            "symbol covered by a cited documented external interface is "
            "external-contract; every other symbol is blocking and is "
            "refused, never counted and discarded"),
    }

    return {
        "direct_reachable": direct_reach,
        "upper_reachable": reach,
        "converged": converged,
        "closure_rounds": rounds,
        "round_sizes": round_sizes,
        "sites_scanned_per_round": sites_scanned_per_round,
        "max_rounds": max_rounds,
        "nonconvergent_detail": (None if converged else {
            "round_cap": max_rounds,
            "last_growth": last_growth,
            "reach_size": len(reach),
        }),
        "address_taken_union": {(g.name, a) for g in graphs.values()
                                for a in getattr(g, "address_taken_union", ())},
        "resolved_site_targets": resolved_targets,
        "residual_bound": bound,
        "residual_bound_nodes": len(bound),
        "symbol_dispositions": disposition_rows,
        "symbol_disposition_summary": disposition_summary,
        "bound_evidence_sources": {
            "schema": UNRESOLVED_BOUND_SCHEMA,
            "rule": (
                "a residual site's bound is address_taken_union plus taken_code "
                "plus every field-store value plus every unresolved-call argument "
                "target plus the site's own resolver targets and arg_targets; "
                "it is independent of the site's class, so a precision loss can "
                "only widen it"),
            "modules": bound_sources,
            "unresolved_sites": sum(len(v) for v in unresolved_by_func.values()),
            "sites_with_site_targets": sum(
                1 for sites in unresolved_by_func.values() for s in sites
                if site_extra.get(id(s))),
        },
        "reachable_residual_sites": reachable_residual_sites,
        "unclassified_sites": sorted(unclassified, key=lambda x: (x[0], x[1])),
        "indirect_reachable_functions": len({f for _d, f, _s in
                                             reachable_residual_sites}),
    }


def closure_refusals(closure: dict) -> list:
    """Closure refusals: non-convergence and unresolved symbolic targets.

    A symbol in the residual bound that resolves by no path and is not covered
    by a cited external interface can become a missing dependency.  It is a
    refusal naming every blocking symbol and site, not a count.
    """
    refusals = []
    if not closure.get("converged", True):
        detail = closure.get("nonconvergent_detail") or {}
        refusals.append({
            "code": "CLOSURE_NONCONVERGENT",
            "detail": (
                "the residual-admission least fixed point did not converge within "
                f"{detail.get('round_cap')} round(s); the last round added "
                f"{detail.get('last_growth')} node(s) and the reachable set is "
                f"{detail.get('reach_size')} node(s). The bound is partial and no "
                "reachability claim may be drawn from it"),
        })
    blocking = [row for row in (closure.get("symbol_dispositions") or [])
                if row.get("disposition") == "blocking"]
    if blocking:
        refusals.append({
            "code": "CLOSURE_UNRESOLVED_SYMBOL",
            "detail": (
                f"{len(blocking)} symbolic target(s) in the residual bound "
                "resolve by no documented path (exact export, version-stripped "
                "export, names-at alias, dynamic symbol, SONAME-qualified "
                "import, PLT stub) and are covered by no cited external "
                "interface; a missing symbol can be a missing dependency"),
            "symbols": [
                {"symbol": row["symbol"],
                 "module": row["module"],
                 "slot_offsets": row.get("slot_offsets") or [],
                 "sites": row.get("sites") or [],
                 "reason": row.get("reason")}
                for row in blocking
            ],
        })
    return refusals


# --------------------------------------------------------------------------- #
# admission by refutation (AGENTS.md sections 7 and 22)
# --------------------------------------------------------------------------- #
#
# Every exclusion in this analyzer was derived against the *pre-closure direct*
# reachable set, which is an under-approximation.  The sound bound (the final
# upper bound) reaches callers and writers that derivation excluded.  Refusing
# every such site is honest but leaves the closure unusable; the sound
# disposition is the opposite of the refusal: if the bound reaches an excluded
# subject, the exclusion is false, so the targets it would have contributed are
# admitted and the closure is recomputed.  Admission may only add targets; the
# exclusions that survive the bound stay exclusions and remain validated.
ADMISSION_SCHEMA = "openssl-rs/campaign/safe-c33/refutation-admission/v1"
MAX_ADMISSION_PASSES = 4
ADMISSION_SITE_RENDER_LIMIT = 200
ADMISSION_ROW_RENDER_LIMIT = 2000
ADMISSION_ROLE_CALLER = "reachable-caller"
ADMISSION_ROLE_WRITER = "method-store-writer"
ADMISSION_ROLE_CALLSITE = "method-store-callsite-caller"
ADMISSION_ROLES = (ADMISSION_ROLE_CALLER, ADMISSION_ROLE_WRITER,
                   ADMISSION_ROLE_CALLSITE)


def _hex_addr(value):
    """An artifact-local address from an int or a hex string, else None."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value:
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def _oracle_reaches(oracle, module, symbol, address=None) -> bool:
    """True only when the sound bound positively reaches the subject.

    ``checkable`` false (an unmodelled module) is not a refutation: an
    unavailable oracle can never turn an exclusion into an admission.
    """
    if oracle is None:
        return False
    reachable, _basis, checkable = oracle.is_reachable(
        module, symbol, _hex_addr(address))
    return bool(checkable and reachable)


def _oracle_module_addresses(oracle, g) -> set:
    """Every address of ``g`` whose name the upper bound reaches.

    The oracle answers by address *or* by name (an identical-code-folding
    alias at another address contributes the name).  A re-derivation that used
    only the reached node addresses could keep an exclusion the oracle
    refutes, so the set is the union of the reached nodes and every address the
    image records under a reached name.
    """
    module = getattr(g, "name", None)
    nodes = oracle.upper_nodes(module) if oracle is not None else None
    if nodes is None:
        return set()
    reach = set(oracle.reachable_symbols(module) or ())
    addrs = {a for _m, a in nodes}
    for table in ("funcs", "all_syms"):
        for addr, name in (getattr(g, table, {}) or {}).items():
            if name and str(name).split("@")[0] in reach:
                addrs.add(addr)
    for addr, names in (getattr(g, "names_at", {}) or {}).items():
        if any(str(n).split("@")[0] in reach for n in (names or ())):
            addrs.add(addr)
    return addrs


def _admission_targets(g, values) -> tuple[set, list]:
    """(function-start addresses, rejected values) from hex/int targets."""
    starts = getattr(g, "start_set", set()) or set()
    accepted, rejected = set(), []
    for value in values or ():
        addr = _hex_addr(value)
        if addr is None or addr not in starts:
            rejected.append(str(value))
            continue
        accepted.add(addr)
    return accepted, rejected


def _caller_row_is_bounded(row) -> bool:
    """True when an excluded caller's recorded contribution is finite.

    A row with no recorded call site, an open (top) argument, or a non-image
    value does not establish a finite target set.  The subject is still
    reachable -- it is admitted as a reachable caller -- but the site cannot
    keep a finite target set and must become UNRESOLVED.
    """
    call_sites = row.get("call_sites")
    if not isinstance(call_sites, list) or not call_sites:
        return False
    for cs in call_sites:
        args = cs.get("arguments") if isinstance(cs, dict) else None
        if not isinstance(args, list) or not args:
            return False
        for arg in args:
            if not isinstance(arg, dict):
                return False
            if arg.get("unresolved") or arg.get("non_image_values"):
                return False
    return True


def _recompute_caller_bound(bound: dict, site: dict) -> None:
    """Keep the bound's derived target lists equal to its caller rows.

    Admission moves a caller from ``excluded_callers`` to
    ``reachable_callers``; the reported ``bounded``/``attributed``/
    ``unattributed`` sets are recomputed from the rows so the receipt does not
    describe the pre-admission narrowing.
    """
    def union(rows):
        out = set()
        for row in rows or ():
            for value in (row or {}).get("contributed_targets") or ():
                addr = _hex_addr(value)
                if addr is not None:
                    out.add(addr)
        return out

    bounded = union(bound.get("reachable_callers"))
    excluded = union(bound.get("excluded_callers"))
    arg_targets = {a for a in (_hex_addr(t) for t in site.get("arg_targets") or ())
                   if a is not None}
    bound["bounded_targets"] = [hex(a) for a in sorted(bounded)]
    bound["attributed_targets"] = [hex(a) for a in sorted(bounded | excluded)]
    bound["unattributed_targets"] = [
        hex(a) for a in sorted(arg_targets - bounded - excluded)]


def _merge_refutation(site: dict, refuted: list, admitted: list,
                      targets, unresolved: bool, missing_property) -> None:
    """Accumulate one site's refutation record (admission is monotone)."""
    current = site.get("refutation_admission")
    if not isinstance(current, dict):
        current = {"schema": ADMISSION_SCHEMA, "refuted": [], "admitted": [],
                   "targets": [], "unresolved": False,
                   "missing_property": None}
    current["refuted"].extend(refuted)
    current["admitted"].extend(admitted)
    current["targets"] = sorted(set(current.get("targets") or ())
                                | set(targets))
    current["unresolved"] = bool(current.get("unresolved") or unresolved)
    if missing_property:
        current["missing_property"] = missing_property
    site["refutation_admission"] = current


def _admit_caller_bound(g, site: dict, bound: dict, oracle,
                        module: str) -> tuple[bool, list, list]:
    """Admit the excluded callers the sound bound reaches.

    Returns (changed, admitted rows, refuted rows).  A moved caller becomes a
    reachable caller (that is what the refutation establishes) and its recorded
    ``contributed_targets`` are added to the site's target set.  A caller whose
    contribution is not finite keeps its place as a reachable caller but makes
    the site UNRESOLVED with a named property: the target set is no longer
    finite, so a finite claim would be unsound.
    """
    excluded = list(bound.get("excluded_callers") or ())
    moved, kept = [], []
    for row in excluded:
        if isinstance(row, dict) and _oracle_reaches(
                oracle, module, row.get("symbol"), row.get("function")):
            moved.append(row)
        else:
            kept.append(row)
    if not moved:
        return False, [], []
    reachable_rows = bound.setdefault("reachable_callers", [])
    was_unresolved = bool(site.get("unresolved"))
    admitted, refuted = [], []
    added_targets = set()
    unbounded = []
    for row in moved:
        rec = dict(row)
        rec["reachable"] = True
        rec["reason"] = None
        rec["admitted_by_refutation"] = True
        reachable_rows.append(rec)
        targets, rejected = _admission_targets(
            g, rec.get("contributed_targets") or ())
        bounded = _caller_row_is_bounded(rec)
        if not bounded or rejected:
            unbounded.append(rec.get("symbol") or "?")
        added_targets |= targets
        admitted.append({
            "role": ADMISSION_ROLE_CALLER,
            "subject": rec.get("symbol") or "?",
            "address": rec.get("function"),
            "targets": [_edge_symbol(g, t) for t in sorted(targets)],
            "bounded": bool(bounded and not rejected),
            "basis": "final-upper-bound",
        })
        refuted.append({
            "role": ADMISSION_ROLE_CALLER,
            "subject": rec.get("symbol") or "?",
            "address": rec.get("function"),
        })
    site["targets"] = set(site.get("targets") or ()) | added_targets
    bound["excluded_callers"] = kept
    _recompute_caller_bound(bound, site)
    if unbounded:
        missing = ("refutation-unbounded: caller(s) reached by the final upper "
                   "bound have no finite recorded image target set: "
                   + ", ".join(sorted(unbounded)))
        # A previously unresolved site stays unresolved: re-resolving it would
        # remove the class-independent bound and could lose reachability.
        site["unresolved"] = True
        site["class"] = "reachable-caller-target (refutation-unbounded)"
        site["reason"] = missing
        _merge_refutation(site, refuted, admitted,
                          [_edge_symbol(g, t) for t in sorted(added_targets)],
                          True, missing)
    else:
        note = ("reachable-caller target bounding (refutation-widened): "
                + ", ".join(r["subject"] for r in admitted)
                + " are reached by the final upper bound")
        site["class"] = "reachable-caller-target (refutation-widened)"
        site["reason"] = note
        site["unresolved"] = was_unresolved
        _merge_refutation(site, refuted, admitted,
                          [_edge_symbol(g, t) for t in sorted(added_targets)],
                          False, note)
    return True, admitted, refuted


def _fresh_callsite_targets(fresh: dict, call_site, g):
    """Targets the widened derivation now records for one call site."""
    targets = set()
    bounded = False
    for row in fresh.get("call_sites") or ():
        if not isinstance(row, dict) or row.get("included") is not True:
            continue
        if row.get("call_site") != call_site:
            continue
        if row.get("failure"):
            continue
        got, _rejected = _admission_targets(g, row.get("targets") or ())
        targets |= got
        bounded = True
    return targets, bounded


def _admit_semantic_store(g, site: dict, sem: dict, oracle, module: str,
                          name: str, reachable_fn) -> tuple[bool, list, list]:
    """Re-derive a stored-value site when the sound bound refutes an exclusion.

    The derivation's exclusions were computed against the pre-closure direct
    set.  Rather than guess what a refuted writer or writer-caller would have
    stored, the derivation is recomputed with the sound bound's function set:
    the refuted subject becomes an ordinary included row with its real
    provenance chain, and every exclusion that survives is one the bound still
    does not reach.  The old targets are retained (admission is monotone), and
    a derivation that is no longer finite makes the site UNRESOLVED.
    """
    refuted = []
    for row in sem.get("excluded_writers") or ():
        if isinstance(row, dict) and _oracle_reaches(
                oracle, module, row.get("symbol"), row.get("address")):
            refuted.append({"role": ADMISSION_ROLE_WRITER,
                            "subject": row.get("symbol") or "?",
                            "address": row.get("address"),
                            "_row": row})
    for row in sem.get("call_sites") or ():
        if isinstance(row, dict) and row.get("included") is False and \
                _oracle_reaches(oracle, module, row.get("caller")):
            refuted.append({"role": ADMISSION_ROLE_CALLSITE,
                            "subject": row.get("caller") or "?",
                            "address": row.get("call_site"),
                            "_row": row})
    if not refuted:
        return False, [], []
    fresh = semantic_method_free_targets(g, site, name, reachable_fn())
    if fresh is None:
        return False, [], []
    old_targets = set(site.get("targets") or ())
    was_unresolved = bool(site.get("unresolved"))
    fresh_targets, fresh_rejected = _admission_targets(
        g, fresh.get("targets") or ())
    admitted, public_refuted = [], []
    added = set()
    unbounded = []
    for entry in refuted:
        row = entry.pop("_row")
        public_refuted.append(dict(entry))
        targets, bounded = set(), False
        if entry["role"] == ADMISSION_ROLE_WRITER:
            if row.get("would_store_failure"):
                unbounded.append(entry["subject"])
            elif row.get("would_store_targets") is not None:
                targets, rejected = _admission_targets(
                    g, row.get("would_store_targets") or ())
                bounded = not rejected
                if rejected:
                    unbounded.append(entry["subject"])
        else:
            targets, bounded = _fresh_callsite_targets(
                fresh, entry["address"], g)
            if not bounded:
                unbounded.append(entry["subject"])
        added |= targets
        admitted.append({
            "role": entry["role"],
            "subject": entry["subject"],
            "address": entry["address"],
            "targets": [_edge_symbol(g, t) for t in sorted(targets)],
            "bounded": bool(bounded),
            "basis": "final-upper-bound",
        })
    fresh_resolved = bool(fresh.get("resolved"))
    if fresh_resolved:
        added |= fresh_targets
    else:
        unbounded.append("the widened derivation")
    if fresh_rejected:
        unbounded.append("a widened target that is not a function start")
    site["semantic_store_target"] = fresh
    site["targets"] = old_targets | added
    names = [_edge_symbol(g, t) for t in sorted(added)]
    if unbounded or not fresh_resolved:
        missing = ("refutation-unbounded: "
                   + str(fresh.get("refusal") or ", ".join(sorted(unbounded)))
                   + "; a subject reached by the final upper bound leaves the "
                   "stored-value target set not finite")
        site["unresolved"] = True
        site["class"] = "semantic-store-target (refutation-unbounded)"
        site["reason"] = missing
        # An unresolved record enumerates no complete target set, so the
        # retained targets must be named in candidate_source or the record's
        # own accounting cannot bind them.  They are the stored-value targets
        # the pre-widening derivation already produced.
        names = [_edge_symbol(g, t) for t in sorted(site["targets"])]
        _merge_refutation(site, public_refuted, admitted, names, True, missing)
    else:
        note = ("stored-value provenance:Method.free (offset 0x20), "
                f"{len(fresh_targets)} target(s), refutation-widened")
        site["class"] = "semantic-store-target (refutation-widened)"
        site["reason"] = note
        # Never narrow: a previously unresolved site stays unresolved.
        site["unresolved"] = was_unresolved
        _merge_refutation(site, public_refuted, admitted, names, False, note)
    return True, admitted, public_refuted


def admit_refuted_exclusions(graphs: dict, oracle) -> dict:
    """One admission sweep: turn every bound-refuted exclusion into admission.

    The pass is monotone by construction.  It only adds targets to a site and
    removes a refuted row from an exclusion list; it never removes a target and
    never turns an unresolved site into a resolved one.  The caller owns closure
    recomputation (:func:`admission_fixpoint`) because grown target sets can
    grow the reachable set and refute further exclusions.
    """
    report = {
        "schema": ADMISSION_SCHEMA,
        "changed": False,
        "refuted_exclusions": {role: 0 for role in ADMISSION_ROLES},
        "admitted_by_refutation": {"count": 0, "targets": [], "rows": []},
        "sites": [],
    }
    for module in sorted(graphs):
        g = graphs[module]
        reachable_cache = []

        def module_reachable():
            if not reachable_cache:
                reachable_cache.append(_oracle_module_addresses(oracle, g))
            return reachable_cache[0]

        for key in sorted(getattr(g, "sites", {}) or {},
                          key=lambda k: (k[0], k[1], str(k[2]))):
            site = g.sites[key]
            name = (getattr(g, "funcs", {}) or {}).get(site.get("func", 0), "?")
            site_admitted, site_refuted = [], []
            changed = False
            bound = site.get("reachable_caller_bound")
            if isinstance(bound, dict):
                step, admitted, refuted = _admit_caller_bound(
                    g, site, bound, oracle, module)
                changed |= step
                site_admitted += admitted
                site_refuted += refuted
            sem = site.get("semantic_store_target")
            if isinstance(sem, dict):
                step, admitted, refuted = _admit_semantic_store(
                    g, site, sem, oracle, module, name, module_reachable)
                changed |= step
                site_admitted += admitted
                site_refuted += refuted
            if not changed:
                continue
            report["changed"] = True
            for entry in site_refuted:
                report["refuted_exclusions"][entry["role"]] += 1
            report["admitted_by_refutation"]["rows"].extend(
                dict(entry, dso=module, function=name,
                     call_site=hex(site.get("addr", 0)))
                for entry in site_admitted)
            report["sites"].append({
                "dso": module,
                "function": name,
                "call_site": hex(site.get("addr", 0)),
                "roles": sorted({e["role"] for e in site_admitted}),
                "refuted": site_refuted,
                "admitted": site_admitted,
                "class": site.get("class"),
                "unresolved": bool(site.get("unresolved")),
                "reason": site.get("reason"),
            })
    rows = report["admitted_by_refutation"]["rows"]
    report["admitted_by_refutation"]["count"] = len(rows)
    report["admitted_by_refutation"]["targets"] = sorted({
        target for row in rows for target in row.get("targets") or ()})
    return report


def admission_fixpoint(graphs: dict, close, *,
                       max_passes: int = MAX_ADMISSION_PASSES) -> tuple[dict, dict]:
    """Iterate admission and closure recomputation to a least fixed point.

    ``close()`` returns a :func:`build_graph` result for the current site state.
    Each admission sweep can only add targets, and the closure is a monotone
    graph closure, so the sequence is increasing in a finite lattice and
    terminates.  The cap is a safety property, not the termination argument: a
    cap exhaustion is reported as ``ADMISSION_NONCONVERGENT`` by the caller and
    no reachability claim may rest on it.
    """
    closure = close()
    summary = {
        "schema": ADMISSION_SCHEMA,
        "passes": 0,
        "max_passes": int(max_passes),
        "converged": True,
        "refuted_exclusions": {role: 0 for role in ADMISSION_ROLES},
        "admitted_by_refutation": {"count": 0, "targets": [], "rows": []},
        "sites": [],
        "nonconvergent_detail": None,
    }
    rows: list = []
    targets = set()
    row_total = 0
    while True:
        oracle = ReachabilityOracle(graphs, closure["upper_reachable"])
        step = admit_refuted_exclusions(graphs, oracle)
        if not step["changed"]:
            break
        summary["passes"] += 1
        for role, count in step["refuted_exclusions"].items():
            summary["refuted_exclusions"][role] += count
        for row in step["admitted_by_refutation"]["rows"]:
            row_total += 1
            rows.append(dict(row, pass_index=summary["passes"]))
        targets |= set(step["admitted_by_refutation"]["targets"])
        summary["sites"].extend(step["sites"])
        if summary["passes"] > summary["max_passes"]:
            summary["converged"] = False
            summary["nonconvergent_detail"] = {
                "pass_cap": summary["max_passes"],
                "passes": summary["passes"],
                "last_site_count": len(step["sites"]),
                "reach_size": len(closure["upper_reachable"]),
            }
            break
        closure = close()
    if len(rows) > ADMISSION_ROW_RENDER_LIMIT:
        summary["admitted_by_refutation"]["truncated"] = True
        rows = rows[:ADMISSION_ROW_RENDER_LIMIT]
    if len(summary["sites"]) > ADMISSION_SITE_RENDER_LIMIT:
        summary["sites_truncated"] = True
        summary["sites"] = summary["sites"][:ADMISSION_SITE_RENDER_LIMIT]
    summary["admitted_by_refutation"]["count"] = row_total
    summary["admitted_by_refutation"]["rows"] = rows
    summary["admitted_by_refutation"]["targets"] = sorted(targets)
    return closure, summary


def direct_only_closure(graphs: dict, root_nodes: set, export_index: dict) -> set:
    """Narrow view: direct/PLT edges only, no address-taken admission."""
    reach = set(root_nodes)
    frontier = list(root_nodes)
    while frontier:
        nxt = []
        for dso_name, addr in frontier:
            g = graphs[dso_name]
            for target in g.direct.get(addr, ()):
                node = (dso_name, target)
                if node not in reach:
                    reach.add(node)
                    nxt.append(node)
            sym = g.funcs.get(addr)
            if sym:
                other = export_index.get(sym.split("@")[0])
                if other and other not in reach:
                    reach.add(other)
                    nxt.append(other)
        frontier = nxt
    return reach


# --------------------------------------------------------------------------- #
# source mapping
# --------------------------------------------------------------------------- #

CRATE_NS = re.compile(r"openssl_rs\[[0-9a-f]+\]::([A-Za-z0-9_:]+)")


def demangle(names: list[str]) -> list[str]:
    if not names:
        return []
    res = subprocess.run(["c++filt"], input="\n".join(names), capture_output=True, text=True)
    return res.stdout.splitlines()


def build_module_index(src_root: Path) -> dict:
    """Map a bare module name to files, for modules declared with ``#[path]``.

    ``#[path = "sm3/legacy_sm3.rs"] mod legacy_sm3;`` demangles as
    ``openssl_rs::legacy_sm3`` even though the file is under ``src/sm3/``.  The
    exact-path search cannot see that; this index supplies the only-matching
    fallback and stays silent when a bare name is ambiguous.
    """
    index = collections.defaultdict(list)
    for p in src_root.rglob("*.rs"):
        name = p.parent.name if p.name == "mod.rs" else p.stem
        index[name].append(p.relative_to(src_root.parent).as_posix())
    return {k: sorted(v) for k, v in index.items()}


def module_to_file(module: str, src_root: Path, fallback: dict | None = None) -> str | None:
    segs = module.split("::")
    for k in range(len(segs), 0, -1):
        stem = "/".join(segs[:k])
        for suffix in (f"{stem}.rs", f"{stem}/mod.rs"):
            if (src_root / suffix).is_file():
                return "src/" + suffix
    if fallback:
        for seg in reversed(segs):
            candidates = fallback.get(seg) or []
            if len(candidates) == 1:
                return candidates[0]
    return None


def map_reachable_files(graphs: dict, nodes: set, repo: Path) -> tuple[set, list]:
    names = []
    for dso_name, addr in nodes:
        sym = graphs[dso_name].funcs.get(addr)
        if sym:
            names.append(sym)
    demangled = demangle(sorted(set(names)))
    files = set()
    unmapped = []
    fallback = build_module_index(repo / "src")
    for raw, dem in zip(sorted(set(names)), demangled):
        found = False
        for m in CRATE_NS.finditer(dem):
            f = module_to_file(m.group(1), repo / "src", fallback)
            if f:
                files.add(f)
                found = True
                break
        if not found and "openssl_rs[" in dem:
            unmapped.append({"symbol": raw, "demangled": dem[:240]})
    return files, unmapped


def index_export_sites(repo: Path, inventory_files: list[str]) -> dict:
    """Map a ``#[no_mangle]``/``#[export_name]`` C export to its source file."""
    pat_no_mangle = re.compile(
        r"#\s*\[\s*(?:no_mangle|unsafe\(no_mangle\))\s*\]\s*"
        r"(?:(?:#\s*\[[^\]]*\]\s*)*)"
        r"(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z0-9_]+)")
    pat_export_name = re.compile(
        r"#\s*\[\s*export_name\s*=\s*\"([^\"]+)\"\s*\]\s*"
        r"(?:(?:#\s*\[[^\]]*\]\s*)*)"
        r"(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z0-9_]+)")
    index = collections.defaultdict(set)
    for relpath in inventory_files:
        p = repo / relpath
        if not p.is_file():
            continue
        text = p.read_text(errors="replace")
        for m in pat_no_mangle.finditer(text):
            index[m.group(1)].add(relpath)
        for m in pat_export_name.finditer(text):
            index[m.group(1)].add(relpath)
            index[m.group(2)].add(relpath)
    return {k: sorted(v) for k, v in index.items()}


# --------------------------------------------------------------------------- #
# obligations, boundaries, mechanism state
# --------------------------------------------------------------------------- #

SITE_RECEIPT_KIND = "site-enumerating-boundary-receipt"

MECHANISM_RULES = [
    (re.compile(r"^src/runtime/err\.rs$|^src/runtime/dso_shared\.rs$"), "ERR"),
    (re.compile(r"^src/runtime/bio/"), "BIO"),
    (re.compile(r"^src/runtime/(?:mem|owned_buf|member_slot|foreign|mem_coords|lhash|ex_data|init)\.rs$|"
                r"^src/runtime/stack|^src/runtime/buffer"), "RUNTIME_ALLOC_OWNERSHIP"),
    (re.compile(r"^src/runtime/thread|^src/context/namemap\.rs$|^src/runtime/rcu\.rs$"),
     "RUNTIME_CONCURRENCY"),
    (re.compile(r"^src/ssl/"), "SSL_SESSION"),
    (re.compile(r"^src/x509/"), "X509_VERIFY_POLICY"),
    (re.compile(r"^src/(?:asn1|ocsp|ts|objects)/"), "ASN1_OCSP"),
    (re.compile(r"^src/(?:evp|provider|ec|rsa|dsa|dh|bn|ffc|hpke|ml_dsa|ml_kem|slh_dsa|"
                r"mac|property|param|digest|des|aes|camellia|seed|srp|md5|sha|sm3)/"),
     "EVP_PKEY_PROVIDER"),
    (re.compile(r"^src/(?:decoder_lib|decoder_meth|decoder_pkey|encoder_meth|encoder_pkey)\.rs$"),
     "EVP_PKEY_PROVIDER"),
    (re.compile(r"^src/(?:rand|cms|store|pem|pkcs7|pkcs12|cmp|crmf)/"),
     "RAND_CMS_STORE_KEYFMT"),
]


def load_obligation_mechanisms(state_doc: dict) -> dict:
    """Exact (file, line, kind) -> mechanism record from state.json.

    Per-site classifications for obligations a file-level rule would
    misattribute (a heterogeneous file, or an operation whose owner is not the
    file's dominant subsystem).  They only classify: the mechanism's own state
    and receipts still decide whether anything is discharged.
    """
    out = {}
    for rec in state_doc.get("obligation_mechanisms") or []:
        key = (rec.get("file"), rec.get("line"), rec.get("kind"))
        if rec.get("mechanism"):
            out[key] = rec
    return out


def mechanism_for(file: str, mechanisms: dict,
                  obligation: dict | None = None,
                  obligation_mechanisms: dict | None = None) -> tuple[str | None, str]:
    if obligation is not None and obligation_mechanisms:
        rec = obligation_mechanisms.get(
            (file, obligation.get("line"), obligation.get("kind")))
        if rec is not None:
            return rec["mechanism"], (
                "obligation-override:state.json#/obligation_mechanisms")
        # A contracted operation enrolled from the census's per-site records
        # carries the census coordinate, which may have drifted from the
        # ledger's coordinate by the lines a `# Safety` prelude added.  The
        # enrollment already resolves that drift by stable identity; resolve it
        # here too, or a documented site loses its mechanism and is reported
        # UNKNOWN instead of BLOCKED.  A contract is not a discharge.
        item = obligation.get("item")
        if item:
            for r in obligation_mechanisms.values():
                if (r.get("file") == file
                        and r.get("kind") == obligation.get("kind")
                        and r.get("operation") == item
                        and r.get("mechanism")):
                    return r["mechanism"], (
                        "obligation-override:state.json#/obligation_mechanisms "
                        "(stable identity file/kind/operation; +N-line drift)")
    for mid, rec in mechanisms.items():
        if file in (rec.get("converted_files_on_branch") or []):
            return mid, "converted_files_on_branch"
    for pat, mid in MECHANISM_RULES:
        if pat.search(file):
            return mid, "directory-rule:" + pat.pattern
    return None, "unmapped"


def operation_stable_identity(file: str, kind: str | None, item: str | None,
                              line) -> str:
    """Stable operation identity: file + kind + enclosing item.

    Line numbers are provenance, not identity.  A documentation or attribute
    edit shifts lines but must not change which operation an obligation names.
    A legacy inventory without enclosing-item records falls back to the line
    and says so in the returned string; callers must surface that basis.
    """
    if item:
        return f"{file}::{kind}::{item}"
    return f"{file}::{kind}::<line:{line}>"


def operation_key(record: dict) -> tuple:
    """Hashable stable identity for an inventory or closure operation record."""
    item = record.get("item")
    if item:
        return (record.get("file"), record.get("kind"), item)
    return (record.get("file"), record.get("kind"), None, record.get("line"))


def carry_forward_candidates(previous: dict, contracts: dict,
                             queued: collections.Counter,
                             reachable_files: set[str] | None = None,
                             reachability_evidence: dict | None = None
                             ) -> tuple[list[dict], dict]:
    """Obligations the previous applied closure enumerated, carried forward.

    The queue is a union: an obligation enumerated by the previous *ACCEPTED*
    closure stays queued while its operation still exists at the same stable
    identity (file + kind + enclosing item) **and** its file is in the current
    closure's reachable-file set, whatever its documentation state or ledger
    membership.  Only a discharge receipt, the operation's disappearance from
    the current census, or the loss of its file's reachability may remove it.

    Reachability is evidence, not documentation: an unreachable file cannot
    own a reachable obligation at this artifact, so carrying its operations
    forward would inflate the queue with sites the closure never reached.  The
    removal is recorded with the reason ``no-longer-reachable-at-this-artifact``
    and cites the reachable-file evidence; it is never silent.

    ``queued`` is the multiplicity of each stable identity already enrolled at
    this identity from the live census and site receipts.  Membership is merged
    as a multiset maximum, so an operation that is already queued is not added
    twice and two same-named operations in one file are not collapsed into one.

    The returned record keeps the previous enumeration coordinate as ``line``
    (provenance; the coordinate at which the discharge receipts were
    adjudicated) and records the current census coordinate separately, because
    the carry-forward is about obligation identity, not line stability.
    Operations enumerated by the previous closure that the current per-site
    census no longer contains, or whose file is not reachable, are returned in
    ``removed`` with a reason.
    """
    contracted = contracts.get("contracted_operations")
    production_census = []
    for rec in contracted or []:
        if rec.get("partition") == V1_PARTITION_PRODUCTION:
            production_census.append(("contracted", rec))
    for rec in contracts.get("blockers") or []:
        if rec.get("partition") == V1_PARTITION_PRODUCTION:
            production_census.append(("uncontracted", rec))

    by_stable = collections.defaultdict(list)
    by_exact = collections.defaultdict(list)
    for state, rec in production_census:
        by_stable[operation_key(rec)].append((state, rec))
        by_exact[(rec.get("file"), rec.get("line"), rec.get("kind"))].append(
            (state, rec))

    groups = collections.OrderedDict()
    for rec in previous.get("obligations") or []:
        sid = rec.get("stable_id") or operation_stable_identity(
            rec.get("file"), rec.get("kind"), rec.get("item"), rec.get("line"))
        groups.setdefault(sid, []).append(rec)

    out: list[dict] = []
    already = 0
    removed: list[dict] = []
    ambiguous: list[dict] = []
    for sid in sorted(groups):
        group = sorted(groups[sid],
                       key=lambda r: (r.get("line") or 0, r.get("id") or ""))
        available = queued.get(sid, 0)
        for prev in group:
            if available > 0:
                available -= 1
                already += 1
                continue
            f, kind = prev.get("file"), prev.get("kind")
            line = prev.get("line")
            item = prev.get("item")
            matched = by_stable.get(operation_key(prev), [])
            if not matched:
                matched = by_exact.get((f, line, kind), [])
            if reachable_files is not None and f not in reachable_files:
                census_lines = sorted({r.get("line") for _s, r in matched
                                       if r.get("line") is not None})
                evidence = dict(reachability_evidence or {})
                evidence.update({
                    "file": f,
                    "file_in_reachable_set": False,
                    "basis": (
                        "the file is absent from this closure's reachable-file "
                        "set (the same final linked-code upper bound used to "
                        "enroll every other obligation); reachability is "
                        "evidence, so an operation in an unreachable file "
                        "cannot be carried forward at this artifact"),
                })
                removed.append({
                    "file": f, "line": line, "kind": kind,
                    "item": item, "stable_id": sid,
                    "previous_id": prev.get("id"),
                    "previous_status": prev.get("status"),
                    "previous_discharge_receipt": prev.get("discharge_receipt"),
                    "reason": "no-longer-reachable-at-this-artifact",
                    "reason_detail": (
                        "enumerated by the previous applied closure, but this "
                        "closure's reachable-file set does not contain the "
                        "file; an unreachable operation is not an obligation "
                        "at this artifact"),
                    "operation_still_in_census": bool(matched),
                    "current_census_lines": census_lines,
                    "reachable_file_evidence": evidence,
                })
                continue
            if not matched:
                if contracted is not None:
                    removed.append({
                        "file": f, "line": line, "kind": kind,
                        "item": item, "stable_id": sid,
                        "previous_id": prev.get("id"),
                        "previous_status": prev.get("status"),
                        "reason": (
                            "enumerated by the previous applied closure, but the "
                            "current inventory's per-site enumeration contains no "
                            "production operation at this stable identity (file, "
                            "kind, enclosing item); the operation no longer "
                            "exists as a source unsafe operation"),
                    })
                    continue
                # Legacy inventory (no per-site contracted records): the
                # previous enumeration is the only existence evidence.  Never
                # drop what cannot be shown removed.
                state = prev.get("contract") or "uncontracted"
                basis = ("carry-forward: the current inventory predates per-site "
                         "contracted-operation records, so existence rests on the "
                         "previous applied closure's enumeration")
                current_line = None
            else:
                states = {s for s, _r in matched}
                state = "contracted" if "contracted" in states else "uncontracted"
                lines = sorted({r.get("line") for _s, r in matched
                                if r.get("line") is not None})
                exact_line = next((r.get("line") for _s, r in matched
                                   if r.get("line") == line), None)
                if exact_line is not None:
                    current_line = exact_line
                elif len(lines) == 1:
                    current_line = lines[0]
                else:
                    current_line = None
                    ambiguous.append({
                        "file": f, "line": line, "kind": kind, "item": item,
                        "stable_id": sid,
                        "reason": ("several current production operations share "
                                   "this stable identity and none is at the "
                                   "previous coordinate; the previous coordinate "
                                   "is retained and the ambiguity is recorded"),
                        "current_lines": lines,
                    })
                if state == "contracted":
                    basis = ("attached # Safety / SAFETY contract in the current "
                             "inventory; a contract is not a discharge")
                else:
                    basis = ("no attached # Safety / SAFETY contract in the "
                             "current inventory")
            out.append({
                "id": f"V1:{f}:{line}:{kind}",
                "stable_id": sid,
                "file": f,
                "line": line,
                "line_provenance": (
                    "previous applied closure's enumeration coordinate; stable "
                    "identity is file+kind+enclosing item, the line is provenance"),
                "current_census_line": current_line,
                "line_drift": (current_line - line
                               if isinstance(current_line, int)
                               and isinstance(line, int) else None),
                "site_receipt_line": None,
                "site_receipt_ledger_line": None,
                "kind": kind,
                "item": item,
                "partition": V1_PARTITION_PRODUCTION,
                "v1_reason": prev.get("v1_reason"),
                "contract": state,
                "contract_basis": basis,
                "site_receipt": None,
                "site_boundary": None,
                "ledger_basis": None,
                "carried_forward_from": {
                    "receipt": previous.get("receipt"),
                    "receipt_sha256": previous.get("receipt_sha256"),
                    "previous_id": prev.get("id"),
                    "previous_line": prev.get("line"),
                    "previous_status": prev.get("status"),
                    "previous_discharge_receipt": prev.get("discharge_receipt"),
                },
            })

    removed_by_reason = collections.Counter(r.get("reason") for r in removed)
    summary = {
        "previous_obligation_count": sum(len(g) for g in groups.values()),
        "already_present_count": already,
        "carried_forward_count": len(out),
        "removed_count": len(removed),
        "removed_by_reason": dict(sorted(removed_by_reason.items())),
        "removed": removed,
        "ambiguous_identity_count": len(ambiguous),
        "ambiguous_identity": ambiguous,
        "reachability_filter_applied": reachable_files is not None,
        "reachability_evidence": reachability_evidence,
        "suppressed": [],
    }
    return out, summary


def obligation_candidates(contracts: dict, files_upper: set[str],
                          boundaries_by_file: dict,
                          obligation_mechanisms: dict,
                          carry_forward: dict | None = None,
                          reachability_evidence: dict | None = None
                          ) -> tuple[list[dict], dict]:
    """Build the obligation set: a union that cannot shrink on documentation.

    Enrollment rule
    ---------------
    The queue is the union of three bounded sources:

    (a) the reachable production operations that are still unsafe and have no
        attached contract;
    (b) documented operations named by a mechanism's site-enumerating
        boundary receipt *and* by the persistent ledger
        ``state.json#/obligation_mechanisms``;
    (c) every obligation enumerated by the previous *ACCEPTED* closure whose
        operation still exists at the same stable identity (file + kind +
        enclosing item) and whose file is still reachable, regardless of its
        contract state and regardless of the ledger -- passed in as
        ``carry_forward`` (see :func:`carry_forward_candidates`).

    (c) is the monotonicity guard.  Source (b) is bounded by a receipt and the
    ledger, so attaching a ``# Safety`` prelude to an operation that no receipt
    names used to remove it from the queue without a discharge.  Carry-forward
    re-enrolls exactly the operations a previous closure already enumerated; it
    does not enroll the inventory's other contracted operations (the tens of
    thousands that no closure ever enumerated).  Documentation state can move
    an operation between ``uncontracted`` and ``contracted``; it can never remove
        documentation state; it can never remove
    it.  An operation leaves only when a discharge receipt names it (decided
    later by :func:`adjudicate`), when the inventory no longer contains it, or
    when its file is no longer reachable at this artifact.  The first two are
    recorded in ``enrollment.excluded`` (site path) or
    ``enrollment.carry_forward.removed``; the third is
    ``enrollment.carry_forward.removed`` with the reason
    ``no-longer-reachable-at-this-artifact``.

    A plan site with no ledger record was never an obligation; enrolling it
    would grow the target set rather than preserve it, so it is skipped.  For
    every ledger entry that no in-scope site plan names, the gap is recorded in
    ``enrollment.ledger_entries_without_site_plan`` (uncontracted-only enrollment
    then applies).
    """
    obligations: list[dict] = []
    seen: set[tuple] = set()

    def add(rec: dict) -> bool:
        key = (rec["file"], rec["line"], rec["kind"])
        if key in seen:
            return False
        seen.add(key)
        obligations.append(rec)
        return True

    blockers = contracts.get("blockers") or []
    production = [b for b in blockers
                  if b.get("partition") == V1_PARTITION_PRODUCTION]
    for b in production:
        f = b.get("file")
        if f not in files_upper:
            continue
        item = b.get("item")
        add({
            "id": f"V1:{f}:{b.get('line')}:{b.get('kind')}",
            "stable_id": operation_stable_identity(
                f, b.get("kind"), item, b.get("line")),
            "file": f,
            "line": b.get("line"),
            "line_provenance": (
                "V1 census operation coordinate at the inventory source head"),
            "kind": b.get("kind"),
            "item": item,
            "partition": b.get("partition"),
            "v1_reason": b.get("reason"),
            "contract": "uncontracted",
            "contract_basis": (b.get("reason")
                               or "no attached # Safety / SAFETY: contract"),
            "site_receipt": None,
            "ledger_basis": None,
        })

    contracted = contracts.get("contracted_operations")
    contracted_by_exact: dict[tuple, dict] = {}
    contracted_by_stable: dict[tuple, dict] = {}
    for rec in contracted or []:
        contracted_by_exact.setdefault(
            (rec.get("file"), rec.get("line"), rec.get("kind")), rec)
        if rec.get("item"):
            contracted_by_stable.setdefault(
                (rec.get("file"), rec.get("kind"), rec.get("item")), rec)

    ledger_stable: dict[tuple, dict] = {}
    for rec in obligation_mechanisms.values():
        operation = rec.get("operation")
        if operation:
            ledger_stable.setdefault(
                (rec.get("file"), rec.get("kind"), operation), rec)

    enrolled: list[dict] = []
    excluded: list[dict] = []
    planned: set[tuple] = set()

    for f in sorted(files_upper):
        for b in boundaries_by_file.get(f, []):
            kind, line = b.get("kind"), b.get("line")
            if kind is None or line is None:
                continue
            planned.add((f, line, kind))
            key = (f, line, kind)
            if key in seen:
                continue  # already enrolled as an uncontracted obligation
            ledger_rec = obligation_mechanisms.get(key)
            if ledger_rec is None and b.get("operation"):
                ledger_rec = ledger_stable.get((f, kind, b["operation"]))
            if ledger_rec is None:
                # Never an obligation in the persistent ledger; a plan site
                # alone does not enroll it (that would grow the target set).
                continue
            rec = contracted_by_exact.get(key)
            if rec is None and b.get("operation"):
                rec = contracted_by_stable.get((f, kind, b["operation"]))
            if rec is not None:
                if rec.get("partition") != V1_PARTITION_PRODUCTION:
                    excluded.append({
                        "file": f, "line": line, "kind": kind,
                        "reason": "contracted operation is not production-partitioned"})
                    continue
                item = rec.get("item") or b.get("operation")
                # The census record is the operation's coordinate at the
                # inventory identity; the site receipt/ledger line is provenance.
                # A stable-identity match is exactly the +N-line drift case.
                if rec.get("line") is not None:
                    line = rec["line"]
                basis = ("contracted operation record in the inventory at this "
                         "identity (contracts.contracted_operations)")
            else:
                if contracted is not None:
                    # The census enumerates every operation.  Absent from both the
                    # uncontracted blocker set and the contracted records, the
                    # operation no longer exists at this identity.
                    excluded.append({
                        "file": f, "line": line, "kind": kind,
                        "reason": (
                            "named by a site receipt and the persistent ledger, but "
                            "the inventory's per-site enumeration contains it in "
                            "neither the uncontracted blockers nor the contracted "
                            "operations; the operation no longer exists at this "
                            "identity (site receipt is stale)")})
                    continue
                # Legacy inventory: blockers are its complete uncontracted
                # enumeration, so a plan+ledger site absent from them is
                # documented.  Existence rests on the site receipt's own
                # enumeration because this inventory predates per-site records.
                item = b.get("operation") or ledger_rec.get("operation")
                basis = (
                    "site receipt enumerates the operation and the inventory's "
                    "uncontracted blocker set does not contain it; this inventory "
                    "predates per-site contracted-operation records, so existence "
                    "rests on the site receipt's enumeration")
            record = {
                "id": f"V1:{f}:{line}:{kind}",
                "stable_id": operation_stable_identity(f, kind, item, line),
                "file": f,
                "line": line,
                "line_provenance": (
                    "contracted-operation record coordinate at the inventory source "
                    "head" if contracted is not None
                    else "site-receipt coordinate; inventory predates per-site records"),
                "site_receipt_line": b.get("line"),
                "site_receipt_ledger_line": ledger_rec.get("line"),
                "kind": kind,
                "item": item,
                "partition": V1_PARTITION_PRODUCTION,
                "v1_reason": None,
                "contract": "contracted",
                "contract_basis": basis,
                "site_receipt": b.get("receipt"),
                "site_boundary": b.get("id"),
                "ledger_basis": ledger_rec.get("basis"),
            }
            if add(record):
                enrolled.append({
                    "id": record["id"],
                    "stable_id": record["stable_id"],
                    "file": f, "line": line, "kind": kind,
                    "item": item,
                    "site_receipt": b.get("receipt"),
                    "site_boundary": b.get("id"),
                    "mechanism": ledger_rec.get("mechanism"),
                    "contract_basis": basis,
                })

    cf_records: list[dict] = []
    cf_summary: dict = {"applied": False,
                        "reason": "no previous applied closure supplied"}
    if carry_forward and carry_forward.get("applied"):
        queued = collections.Counter(o["stable_id"] for o in obligations)
        cf_records, cf_summary = carry_forward_candidates(
            carry_forward, contracts, queued,
            reachable_files=files_upper,
            reachability_evidence=reachability_evidence)
        cf_summary.update({
            "applied": True,
            "receipt": carry_forward.get("receipt"),
            "receipt_sha256": carry_forward.get("receipt_sha256"),
            "receipt_generated_utc": carry_forward.get("receipt_generated_utc"),
            "receipt_verdict": carry_forward.get("receipt_verdict"),
            "receipt_source_head": carry_forward.get("receipt_source_head"),
            "receipt_inventory_path": carry_forward.get("receipt_inventory_path"),
            "receipt_artifact_path": carry_forward.get("receipt_artifact_path"),
            "receipt_artifact_sha256": carry_forward.get("receipt_artifact_sha256"),
            "selection": carry_forward.get("selection"),
            "discovered_candidate_count": carry_forward.get(
                "discovered_candidate_count"),
            "contracted_operations_never_enumerated": len(
                contracts.get("contracted_operations") or []),
            "boundedness_note": (
                "only operations the previous applied closure enumerated are "
                "carried forward; the inventory's contracted operations that no "
                "closure enumerated are never enrolled by this path"),
        })
        for rec in cf_records:
            if add(rec):
                cf_summary.setdefault("carried_forward", []).append({
                    "id": rec["id"],
                    "stable_id": rec["stable_id"],
                    "file": rec["file"], "line": rec["line"],
                    "current_census_line": rec.get("current_census_line"),
                    "kind": rec["kind"], "item": rec["item"],
                    "contract": rec["contract"],
                    "previous_status": (rec.get("carried_forward_from") or {}).get(
                        "previous_status"),
                })
            else:
                # The previous coordinate is now occupied by a different
                # operation.  Retry at the current census coordinate so the
                # obligation is never silently lost; if that also collides, it
                # is recorded and the caller refuses instead of dropping it.
                current = rec.get("current_census_line")
                alt = dict(rec)
                if isinstance(current, int) and current != rec.get("line"):
                    alt.update({
                        "id": f"V1:{rec['file']}:{current}:{rec['kind']}",
                        "line": current,
                        "line_provenance": (
                            "current census coordinate; the previous applied "
                            "closure's coordinate is occupied by a different "
                            "operation"),
                    })
                if alt is not rec and add(alt):
                    cf_summary.setdefault("carried_forward", []).append({
                        "id": alt["id"],
                        "stable_id": alt["stable_id"],
                        "file": alt["file"], "line": alt["line"],
                        "current_census_line": alt.get("current_census_line"),
                        "kind": alt["kind"], "item": alt["item"],
                        "contract": alt["contract"],
                        "previous_status": (
                            alt.get("carried_forward_from") or {}).get(
                                "previous_status"),
                        "previous_coordinate_occupied": True,
                    })
                else:
                    cf_summary["suppressed"].append({
                        "file": rec["file"], "line": rec["line"],
                        "kind": rec["kind"], "item": rec["item"],
                        "stable_id": rec["stable_id"],
                        "reason": ("the previous coordinate and the current "
                                   "census coordinate are both already occupied "
                                   "in the obligation queue"),
                    })
        cf_summary["carried_forward_count"] = len(cf_records) - len(
            cf_summary["suppressed"])

    gaps = []
    for key, rec in sorted(obligation_mechanisms.items()):
        if key in planned or key in seen:
            continue
        gaps.append({
            "file": key[0], "line": key[1], "kind": key[2],
            "mechanism": rec.get("mechanism"),
            "reason": ("no site-enumerating boundary receipt in scope names this "
                       "persistent-ledger operation; uncontracted-only enrollment "
                       "applies and the gap is recorded here"),
        })

    obligations.sort(key=lambda o: (o["file"], o["line"] or 0, o["kind"] or ""))
    enrollment = {
        "contracted_records_present": contracted is not None,
        "contracted_record_count": len(contracted or []),
        "contract_scope": contracts.get("contracted_operations_scope"),
        "enrolled": enrolled,
        "enrolled_count": len(enrolled),
        "excluded": excluded,
        "excluded_count": len(excluded),
        "ledger_entries_without_site_plan": gaps,
        "carry_forward": cf_summary,
        "rule": (
            "union of uncontracted production blockers + contracted production "
            "operations named by an in-scope site-enumerating boundary receipt "
            "and by state.json#/obligation_mechanisms + every obligation the "
            "previous ACCEPTED closure enumerated whose operation still exists "
            "at the same stable identity; documentation state only changes the "
            "contract field, never membership"),
    }
    return obligations, enrollment


def load_boundaries(boundary_dir: Path) -> tuple[dict, dict]:
    """Return (by_file, by_id) across every boundary receipt.

    Two receipt families are admitted: the ``boundary-sweep-B*.json`` sweep
    receipts, and site-enumerating receipts named ``*-sites.json`` that declare
    ``kind`` as :data:`SITE_RECEIPT_KIND`.  A site receipt is evidence that a
    file's reachable operations were enumerated and given a disposition.  It is
    *not* evidence that any site is discharged: the adjudicator still requires
    a SAFETY_DISCHARGED scope whose disposition names the exact site, so a site
    receipt alone can only move an obligation from UNKNOWN to BLOCKED.
    """
    by_file = collections.defaultdict(list)
    by_id = {}
    paths = sorted(boundary_dir.glob("boundary-sweep-B*.json"))
    for p in sorted(boundary_dir.glob("*-sites.json")):
        try:
            doc = json.loads(p.read_text())
        except Exception:
            continue
        if doc.get("kind") != SITE_RECEIPT_KIND:
            continue
        paths.append(p)
    for p in paths:
        try:
            doc = json.loads(p.read_text())
        except Exception:
            continue
        receipt = doc.get("receipt") or p.stem
        for b in doc.get("boundaries") or []:
            rec = {
                "receipt": receipt,
                "id": b.get("id"),
                "file": b.get("file"),
                "line": b.get("line"),
                "kind": b.get("kind"),
                "operation": b.get("operation"),
                "mechanism": b.get("mechanism"),
                "disposition": b.get("disposition"),
                "date": doc.get("date"),
            }
            if rec["file"]:
                by_file[rec["file"]].append(rec)
            if rec["id"]:
                by_id.setdefault(rec["id"], []).append(rec)
    return by_file, by_id


def parse_scope_sites(receipt_doc: dict) -> dict:
    """Parse surface[].sites entries like ``src/runtime/err.rs:726-733``."""
    out = collections.defaultdict(list)
    pat = re.compile(r"^(src/[^:]+):(\d+)(?:-(\d+))?$")
    for entry in receipt_doc.get("surface") or []:
        for site in entry.get("sites") or []:
            m = pat.match(str(site))
            if not m:
                continue
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
            out[m.group(1)].append((lo, hi, entry.get("id")))
    return out


def discharge_plane(status_doc: dict, boundary_dir: Path) -> dict:
    mechanisms = {}
    for rec in status_doc.get("mechanism_discharges") or []:
        mechanisms[rec.get("id")] = rec
    scoped = {}
    for rec in status_doc.get("scoped_boundary_discharges") or []:
        for bid in rec.get("discharged_boundaries") or []:
            scoped[bid] = rec
    err_scope = {}
    err_path = boundary_dir / "mechanism-discharge-ERR.json"
    if err_path.is_file():
        doc = json.loads(err_path.read_text())
        err_scope = {"receipt": "mechanism-discharge-ERR.json",
                     "mechanism": doc.get("mechanism"),
                     "sites": parse_scope_sites(doc),
                     "state": (doc.get("discharge_eligibility") or {}).get("state")}
    return {"mechanism_discharges": mechanisms, "scoped_boundary_discharges": scoped,
            "err_scope": err_scope}


SCOPE_RANGE = re.compile(r"(src/[A-Za-z0-9_./-]+\.rs):(\d+)(?:-(\d+))?")
BARE_RANGE = re.compile(r"(?:^|[^\d])(\d+)(?:-(\d+))?(?=,|;|$|\))")


def scoped_ranges(disposition: str) -> dict:
    """Line ranges a scoped disposition declares, keyed by file.

    A scoped discharge is evidence only for the sites it names.  ``B27-X2`` says
    "the refused loader_set_params path"; that does not cover an arbitrary
    operation elsewhere in ``store_lib.rs``.  Ranges are therefore parsed from
    the disposition itself (B29 writes ``src/ui/ui_openssl.rs:111-124, 269-290``).
    """
    out = collections.defaultdict(list)
    if not disposition:
        return out
    current = None
    for chunk in re.split(r"[;,)]", disposition):
        chunk = chunk.strip()
        m = SCOPE_RANGE.search(chunk)
        if m:
            current = m.group(1)
            lo = int(m.group(2))
            hi = int(m.group(3) or lo)
            out[current].append((lo, hi))
            continue
        if current:
            m = BARE_RANGE.search(chunk)
            if m:
                lo = int(m.group(1))
                hi = int(m.group(2) or lo)
                out[current].append((lo, hi))
    return out


def scope_item(name) -> str | None:
    """The enclosing item a boundary operation names, without a module prefix.

    Site receipts qualify an operation with its module (``sha1::dupctx``),
    while the census records the enclosing item alone (``dupctx``).  The final
    path component is the item both sides share; the qualifier is extra
    resolution, not a different operation.  A boundary that names no operation
    establishes no identity and therefore cannot establish a discharge.
    """
    if not name:
        return None
    item = str(name).split("::")[-1].strip()
    return item or None


def adjudicate(obligation: dict, mechanisms: dict, boundaries: list[dict],
               plane: dict) -> dict:
    mechanism = obligation["mechanism"]
    state = mechanisms.get(mechanism, {}).get("state") if mechanism else None
    boundary_ids = [b["id"] for b in boundaries]
    obligation["boundary_receipt_present"] = bool(boundaries)
    obligation["boundary_ids"] = boundary_ids
    obligation["boundary_dispositions"] = sorted(
        {b["disposition"] for b in boundaries if b.get("disposition")})
    obligation["mechanism_state"] = state
    obligation["mechanism_state_source"] = (
        mechanisms.get(mechanism, {}).get("state_source") if mechanism else None)

    # 1. an explicit mechanism-scope receipt that names this exact site
    if state == "SAFETY_DISCHARGED":
        mech_id = mechanism
        rec = next((r for r in plane["mechanism_discharges"].values()
                    if r.get("state") == "SAFETY_DISCHARGED"
                    and (r.get("id", "").startswith(mech_id or "") or
                         mech_id in (r.get("mechanism") or ""))), None)
        err = plane.get("err_scope") or {}
        covered = False
        if err.get("mechanism") == mechanism:
            for lo, hi, _sid in err.get("sites", {}).get(obligation["file"], []):
                if lo <= obligation["line"] <= hi:
                    covered = True
                    break
        if covered:
            obligation["status"] = "DISCHARGED"
            obligation["discharge_receipt"] = err.get("receipt")
            obligation["status_reason"] = (
                "mechanism-scope SAFETY_DISCHARGED receipt names this file/line range")
            return obligation
        obligation["status"] = "UNKNOWN"
        obligation["discharge_receipt"] = (rec or {}).get("id")
        obligation["status_reason"] = (
            "mechanism is SAFETY_DISCHARGED, but the receipt's declared surface does "
            "not enumerate this exact site; consumer-scope re-adjudication required")
        return obligation

    # 2. a scoped discharge, only for the *stable identity* its disposition
    #    names.  A line range may narrow that match; it may never establish it.
    #    The range is checked against the operation's current census coordinate,
    #    not the coordinate the previous closure enumerated, so a discharge
    #    cannot be inherited by a drifted (or different) operation.
    scoped_attempt = []
    stale_rejections = []
    current_line = (obligation.get("current_census_line")
                    if isinstance(obligation.get("current_census_line"), int)
                    else obligation["line"])
    for b in boundaries:
        rec = plane["scoped_boundary_discharges"].get(b["id"])
        if not rec:
            continue
        ranges = scoped_ranges(b.get("disposition") or "")
        file_ranges = ranges.get(obligation["file"], [])
        covers_current = any(lo <= current_line <= hi for lo, hi in file_ranges)
        covers_previous = any(lo <= obligation["line"] <= hi
                              for lo, hi in file_ranges)
        boundary_item = scope_item(b.get("operation"))
        identity_match = (
            b.get("file") == obligation["file"]
            and b.get("kind") == obligation.get("kind")
            and boundary_item is not None
            and obligation.get("item") is not None
            and boundary_item == obligation["item"])
        scoped_attempt.append({
            "boundary": b["id"], "receipt": rec.get("receipt"),
            "declared_ranges": {k: v for k, v in ranges.items()},
            "boundary_operation": b.get("operation"),
            "identity_match": identity_match,
            "covers_current_coordinate": covers_current,
            "covers_previous_coordinate": covers_previous,
            "previous_coordinate": obligation["line"],
            "current_coordinate": current_line,
            "covers_site": identity_match and covers_current,
        })
        if identity_match and covers_current:
            obligation["status"] = "DISCHARGED"
            obligation["discharge_receipt"] = rec.get("receipt") or rec.get("artifact")
            obligation["status_reason"] = (
                f"boundary {b['id']} is scoped-SAFETY_DISCHARGED and names the "
                f"operation by stable identity ({obligation['file']}, "
                f"{obligation.get('kind')}, {obligation.get('item')}) at its "
                f"current census coordinate {current_line}")
            obligation["scoped_discharge_attempts"] = scoped_attempt
            return obligation
        if (not covers_current and covers_previous
                and (identity_match or obligation.get("carried_forward_from"))):
            stale_rejections.append({
                "boundary": b["id"],
                "receipt": rec.get("receipt") or rec.get("artifact"),
                "declared_ranges": {k: [list(x) for x in v]
                                    for k, v in ranges.items()},
                "declared_range_for_file": [list(x) for x in file_ranges],
                "boundary_operation": b.get("operation"),
                "operation": obligation.get("item"),
                "identity_match": identity_match,
                "previous_coordinate": obligation["line"],
                "current_coordinate": current_line,
                "reason": (
                    "the receipt's declared range covers the previous "
                    "enumerated coordinate but not the operation's current "
                    "census coordinate; a line range may only narrow a "
                    "stable-identity match, never establish it"),
            })
    if scoped_attempt:
        obligation["scoped_discharge_attempts"] = scoped_attempt
    if stale_rejections:
        obligation["stale_discharge_rejections"] = stale_rejections
        first = stale_rejections[0]
        obligation["status"] = "BLOCKED"
        obligation["discharge_receipt"] = None
        obligation["status_reason"] = (
            "stale scoped discharge refused: boundary "
            f"{first['boundary']} declares {first['declared_range_for_file']} "
            f"for {first['boundary_operation']!r}, but this operation "
            f"({obligation.get('item')!r}) is at current census coordinate "
            f"{first['current_coordinate']} (previously enumerated at "
            f"{first['previous_coordinate']}); the declared range does not "
            "cover the current coordinate, and a line range may only narrow a "
            "stable-identity match, never establish it")
        return obligation

    # 3. no boundary receipt at all
    if not boundaries:
        obligation["status"] = "UNKNOWN"
        obligation["discharge_receipt"] = None
        obligation["status_reason"] = (
            "no boundary-sweep receipt owns this reachable file; the unsafe site is "
            "reachable and its ownership boundary is unrecorded")
        return obligation

    # 4. mechanism with no ownership reconstruction
    if state == "UNSAFE_OPEN":
        obligation["status"] = "BLOCKED"
        obligation["discharge_receipt"] = None
        obligation["status_reason"] = (
            "mechanism state is UNSAFE_OPEN: no ownership reconstruction and no "
            "SAFETY_DISCHARGED receipt")
        return obligation

    # 5. reconstructed/contracted but not discharged
    if state == "OWNERSHIP_RECONSTRUCTED":
        obligation["status"] = "BLOCKED"
        obligation["discharge_receipt"] = None
        extra = ""
        if scoped_attempt:
            extra = (" A scoped SAFETY_DISCHARGED boundary exists for this file but its "
                     "disposition does not name this line; blanket discharge is refused.")
        obligation["status_reason"] = (
            "mechanism state is OWNERSHIP_RECONSTRUCTED and the owning boundary is "
            f"{'/'.join(sorted({str(b.get('disposition')) for b in boundaries}))}; "
            "the V1 operation is uncontracted and no SAFETY_DISCHARGED receipt covers it."
            + extra)
        return obligation

    obligation["status"] = "UNKNOWN"
    obligation["discharge_receipt"] = None
    obligation["status_reason"] = (
        "no mechanism state could be established for this reachable file")
    return obligation


# --------------------------------------------------------------------------- #
# inventory freshness
# --------------------------------------------------------------------------- #

def git_blob_hashes(repo: Path, commit: str, files: list[str]) -> tuple[dict, str | None]:
    """Return {path: sha256} of the blobs at ``commit`` using cat-file --batch."""
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out = {}
    try:
        for f in files:
            proc.stdin.write(f"{commit}:{f}\n".encode())
            proc.stdin.flush()
            header = proc.stdout.readline().decode(errors="replace").strip()
            if not header or header.endswith(" missing"):
                out[f] = None
                continue
            parts = header.split()
            if len(parts) < 3 or parts[1] != "blob":
                out[f] = None
                continue
            size = int(parts[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing newline
            out[f] = hashlib.sha256(data).hexdigest()
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        proc.wait()
    return out, None


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #

SOURCE_ROOT_HASH_RULE_CANONICAL = (
    "sha256(canonical_json(sorted [[relpath, size, sha256], ...])) over the "
    "pristine source tree")
SOURCE_ROOT_HASH_RULE_DOMAIN = (
    "sha256('openssl-rs/source-tree/v1\\0' + for each sorted path under the "
    "extracted tree: path + '\\0' + bytes + '\\0')")


def hash_rule_class(rule) -> str | None:
    """Classify a recorded source-tree hash rule by the digest it produces.

    Two rules are in circulation under the field name ``source_root_hash``.
    The build/link atlas (``downstream_build_link._source_root_hash``) emits the
    canonical-JSON ``[[relpath, size, sha256]]`` digest; a rebuilt-downstream
    build record emits the domain-separated ``openssl-rs/source-tree/v1``
    digest.  They can never be equal, so comparing them is a rule collision,
    not staleness.
    """
    if not rule:
        return None
    text = str(rule).lower()
    if "canonical_json" in text or "canonical json" in text:
        return "canonical-json-tree"
    if "source-tree/v1" in text:
        return "domain-separated-tree"
    return "unrecognised"


def source_root_hash_checks(record: dict, ledger: dict | None) -> tuple[dict, list]:
    """Compare like with like, and never delete either digest check.

    * equal rule classes -> compare ``source_root_hash``; a difference is
      ``STALE_HASH``;
    * different rule classes -> ``HASH_RULE_MISMATCH`` naming both rules (the
      two values are not comparable, so neither is a staleness verdict);
    * ``source_tree_domain_hash`` on both sides -> compare it directly.
    """
    checks = {}
    refusals = []
    record_rule = record.get("source_root_hash_rule")
    ledger_rule = (ledger or {}).get("source_root_hash_rule")
    record_class = hash_rule_class(record_rule)
    ledger_class = hash_rule_class(ledger_rule)
    if ledger_class is None and (ledger or {}).get("source_root_hash"):
        # The atlas field is produced by downstream_build_link._source_root_hash,
        # which hashes canonical JSON; the atlas carries no separate rule field.
        ledger_class = "canonical-json-tree"
        ledger_rule = ledger_rule or SOURCE_ROOT_HASH_RULE_CANONICAL
    checks["source_root_hash_rule"] = {
        "build_record": record_rule,
        "build_record_class": record_class,
        "atlas": ledger_rule,
        "atlas_class": ledger_class,
    }

    record_hash = record.get("source_root_hash")
    ledger_hash = (ledger or {}).get("source_root_hash")
    if record_hash and ledger_hash:
        if record_class and ledger_class and record_class != ledger_class:
            checks["source_root_hash_matches_atlas"] = None
            checks["hash_rule_matches"] = False
            refusals.append({
                "code": "HASH_RULE_MISMATCH",
                "detail": (
                    f"build record source_root_hash uses {record_rule!r} "
                    f"({record_class}) but the atlas uses {ledger_rule!r} "
                    f"({ledger_class}); the two digests are not comparable"),
                "build_record_rule": record_rule,
                "atlas_rule": ledger_rule,
            })
        else:
            checks["hash_rule_matches"] = True
            checks["source_root_hash_matches_atlas"] = record_hash == ledger_hash
            if not checks["source_root_hash_matches_atlas"]:
                refusals.append({
                    "code": "STALE_HASH",
                    "detail": "build record pristine source tree hash does not "
                              "match the atlas row for the same recipe",
                })

    record_domain = record.get("source_tree_domain_hash")
    ledger_domain = (ledger or {}).get("source_tree_domain_hash")
    if record_domain and ledger_domain:
        checks["source_tree_domain_hash_matches_atlas"] = (
            record_domain == ledger_domain)
        if not checks["source_tree_domain_hash_matches_atlas"]:
            refusals.append({
                "code": "STALE_HASH",
                "detail": "build record domain-separated source tree hash does "
                          "not match the atlas row for the same recipe",
            })
    return checks, refusals


def resolve_carry_forward(repo: Path, args, family: str, artifact: Path,
                          artifact_sha: str) -> tuple[dict, list[dict]]:
    """Load the previous applied closure whose obligations are carried forward.

    The source must be an **ACCEPTED** closure for the same family and the same
    artifact name.  A rejected or refused receipt is not a queue authority, and
    a receipt for a different executable is not this consumer.  When no explicit
    path is supplied the most recent such receipt in the carry-forward directory
    is used, so a run cannot silently regress to the pre-carry-forward queue.
    """
    refusals: list[dict] = []
    if getattr(args, "no_carry_forward", False):
        return {"applied": False,
                "reason": "carry-forward disabled by --no-carry-forward "
                          "(control run; the queue is not monotone)"}, refusals

    explicit = getattr(args, "carry_forward_closure", None)
    discovered = None
    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = (repo / path).resolve()
        if not path.is_file():
            refusals.append({
                "code": "CARRY_FORWARD_SOURCE_INVALID",
                "detail": f"carry-forward closure {explicit} does not exist"})
            return {"applied": False, "reason": "source not found"}, refusals
        selection = "explicit --carry-forward-closure"
    else:
        search = Path(getattr(args, "carry_forward_dir", "court/inventory"))
        if not search.is_absolute():
            search = (repo / search).resolve()
        candidates = []
        for p in (sorted(search.glob("closure-*.json")) if search.is_dir() else []):
            try:
                doc = json.loads(p.read_text())
            except Exception:
                continue
            if doc.get("family") != family:
                continue
            if (doc.get("verdict") or {}).get("state") != "ACCEPTED":
                continue
            other = doc.get("artifact_identity") or {}
            if Path(str(other.get("path") or "")).name != artifact.name:
                continue
            if other.get("sha256") == artifact_sha:
                continue
            candidates.append((doc.get("generated_utc") or "", str(p), p))
        discovered = len(candidates)
        if not candidates:
            return {"applied": False,
                    "reason": ("no ACCEPTED closure for this family and artifact "
                               "name was found in the carry-forward directory")}, refusals
        candidates.sort()
        path = Path(candidates[-1][2])
        selection = ("most recent ACCEPTED closure for this family and artifact "
                     "name in the carry-forward directory")

    doc = json.loads(path.read_text())
    problems = []
    if doc.get("schema") != SCHEMA:
        problems.append(f"schema {doc.get('schema')!r} is not {SCHEMA!r}")
    if doc.get("family") != family:
        problems.append(f"family {doc.get('family')!r} is not {family!r}")
    state = (doc.get("verdict") or {}).get("state")
    if state != "ACCEPTED":
        problems.append(f"verdict is {state!r}, not 'ACCEPTED'")
    other = doc.get("artifact_identity") or {}
    if Path(str(other.get("path") or "")).name != artifact.name:
        problems.append(
            f"artifact {other.get('path')!r} is not the analysed artefact "
            f"{artifact.name!r}")
    if not isinstance(doc.get("obligations"), list):
        problems.append("no obligations array")
    if problems:
        refusals.append({
            "code": "CARRY_FORWARD_SOURCE_INVALID",
            "detail": (f"{rel(path, repo)} cannot be the carry-forward source: "
                       + "; ".join(problems))})
        return {"applied": False, "reason": "invalid source"}, refusals

    source_ident = doc.get("source_identity") or {}
    return {
        "applied": True,
        "receipt": rel(path, repo),
        "receipt_sha256": sha256_file(path),
        "receipt_generated_utc": doc.get("generated_utc"),
        "receipt_verdict": state,
        "receipt_source_head": source_ident.get("repository_head"),
        "receipt_inventory_path": source_ident.get("inventory_path"),
        "receipt_artifact_path": other.get("path"),
        "receipt_artifact_sha256": other.get("sha256"),
        "obligations": doc.get("obligations") or [],
        "selection": selection,
        "discovered_candidate_count": discovered,
    }, refusals


def build_receipt(args) -> dict:
    repo = Path(args.repo).resolve()
    tool_identity = _tool_identity()
    tool_sha = tool_identity["sha256"]
    install = (repo / args.install).resolve()
    _EVIDENCE_ENV["repo"] = str(repo)
    _EVIDENCE_ENV["install"] = str(install)
    artifact = Path(args.artifact)
    if not artifact.is_absolute():
        artifact = (repo / artifact).resolve()
    workdir = Path(args.workdir)
    if not workdir.is_absolute():
        workdir = (repo / workdir).resolve()

    inventory_path = (repo / args.inventory).resolve()
    state_path = (repo / args.state).resolve()
    status_path = (repo / args.campaign_status).resolve()
    boundary_dir = (repo / args.boundary_dir).resolve()

    inventory = json.loads(inventory_path.read_text())
    state_doc = json.loads(state_path.read_text())
    status_doc = json.loads(status_path.read_text())
    mechanisms = {m["id"]: dict(m, state_source=f"state.json#/mechanisms[id={m['id']}]")
                  for m in state_doc.get("mechanisms") or []}
    # CAMPAIGN-STATUS carries mechanism discharges newer than state.json (ERR-1).
    # A dispatched mechanism must not be adjudicated from the older registry
    # state; overlay the newer SAFETY_DISCHARGED entry and record its source.
    for rec in status_doc.get("mechanism_discharges") or []:
        if rec.get("state") != "SAFETY_DISCHARGED":
            continue
        mid = str(rec.get("id") or "").split("-")[0]
        if mid in mechanisms:
            mechanisms[mid] = dict(mechanisms[mid], state="SAFETY_DISCHARGED",
                                   state_source=("CAMPAIGN-STATUS.json#/mechanism_discharges"
                                                 f"[id={rec.get('id')}]"),
                                   state_scope=rec.get("scope"))
    boundaries_by_file, _boundaries_by_id = load_boundaries(boundary_dir)
    plane = discharge_plane(status_doc, boundary_dir)
    obligation_mechanisms = load_obligation_mechanisms(state_doc)

    refusals = []
    notes = []

    # ---- 1. artefact and loader identity ---------------------------------- #
    if not artifact.is_file():
        raise SystemExit(f"artifact not found: {artifact}")
    dynamic = elf_dynamic(artifact)
    resolution = loader_resolution(artifact, install)
    classification = classify_resolution(dynamic, resolution, install)
    refusals.extend(classification["problems"])

    artifact_sha = sha256_file(artifact)
    inventory_head = (inventory.get("identity") or {}).get("source_head")
    binaries = ((inventory.get("identity") or {}).get("binary") or {}).get("artefacts") or {}

    # stale-hash check: every resolved OpenSSL DSO must be the inventory's DSO
    for soname, rec in classification["openssl_sonames"].items():
        expected = (binaries.get(soname) or {}).get("sha256")
        rec["inventory_sha256"] = expected
        rec["matches_inventory"] = expected == rec["resolved_sha256"]
        if expected is None:
            refusals.append({"code": "STALE_HASH",
                             "detail": f"{soname}: the inventory records no identity for this DSO"})
        elif not rec["matches_inventory"]:
            refusals.append({"code": "STALE_HASH",
                             "detail": f"{soname}: loader resolved {rec['resolved_sha256']} "
                                       f"but the inventory records {expected}"})

    # ---- 2. imported symbols ---------------------------------------------- #
    graphs = {}
    export_index = {}
    dso_paths = {}
    for soname, rec in classification["openssl_sonames"].items():
        p = Path(rec["resolved_path"])
        if p.is_file():
            dso_paths[soname] = p
            for name, addr in defined_symbols(p, dynamic=True).items():
                export_index.setdefault(name, (p.name, addr))
    imports = undefined_symbols(artifact)
    imported = []
    for imp in imports:
        target = export_index.get(imp["name"])
        if target is None:
            continue
        imported.append({"name": imp["name"], "version": imp["version"],
                         "lib": target[0]})
    if not imported:
        refusals.append({"code": "DANGLING_EDGE",
                         "detail": "the artefact imports no symbol defined by a resolved "
                                   "candidate OpenSSL DSO"})

    # dangling edges: an imported OpenSSL-looking name that no candidate DSO defines
    for imp in imports:
        if re.match(r"^(?:SSL|TLS|EVP|DES|RSA|EC|BN|X509|PEM|BIO|ERR|CRYPTO|OPENSSL|"
                    r"HMAC|MD5|SHA|AES|RAND|ASN1|OCSP|CMS|PKCS)", imp["name"]):
            if imp["name"] not in export_index:
                refusals.append({"code": "DANGLING_EDGE",
                                 "detail": f"imported {imp['name']} is not exported by any "
                                           f"resolved candidate OpenSSL DSO"})

    if getattr(args, "skip_graph_on_refusal", False) and args.build_record:
        bp = Path(args.build_record)
        if not bp.is_absolute():
            bp = (repo / bp).resolve()
        if not bp.is_file():
            refusals.append({"code": "STALE_HASH",
                             "detail": f"build record {bp} does not exist"})
        else:
            rec = json.loads(bp.read_text())
            if rec.get("artifact_sha256") not in (None, artifact_sha):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record artefact digest does not match "
                                           "the analysed artefact"})
            if rec.get("install_prefix") not in (None, rel(install, repo)):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record install prefix does not match the "
                                           "admitted install"})

    if getattr(args, "skip_graph_on_refusal", False) and refusals:
        return {
            "schema": SCHEMA,
            "tool": tool_identity,
            "generated_utc": now_utc(),
            "family": args.family,
            "artifact_identity": {
                "path": rel(artifact, repo),
                "sha256": artifact_sha,
                "dynamic": dynamic,
            },
            "candidate_identity": {
                "install_prefix": rel(install, repo),
                "libcrypto_so_3_sha256": classification["openssl_sonames"].get(
                    "libcrypto.so.3", {}).get("resolved_sha256"),
                "all_openssl_under_install": classification["all_openssl_under_install"],
            },
            "loader_resolution": {
                "method": resolution["method"],
                "resolved": resolution["rows"],
                "openssl_sonames": classification["openssl_sonames"],
            },
            "refusals": refusals,
            "verdict": {
                "state": "REFUSED",
                "safe_compatible": False,
                "reason": "closure refused: " + "; ".join(
                    f"{r['code']} ({r['detail']})" for r in refusals),
            },
            "counts": {"reachable_files": 0, "reachable_production_obligations": 0,
                       "DISCHARGED": 0, "BLOCKED": 0, "UNKNOWN": 0},
            "note": "graph evaluation skipped by --skip-graph-on-refusal; the refusal is "
                    "itself the control result",
            "non_claims": [
                "This control run proves only that the named refusal fires; it does not "
                "exercise the precision resolver.",
            ],
        }

    for p in dso_paths.values():
        graphs[p.name] = DsoGraph(p, workdir)

    import_nodes = set()
    for imp in imported:
        target = export_index.get(imp["name"])
        if target:
            import_nodes.add(target)
    workload_imports = {imp["name"] for imp in imports}
    evidence_stats = {}
    for g in graphs.values():
        g.precision = PrecisionResolver(
            g, imports={addr for dso, addr in import_nodes if dso == g.name})
        g.precision.run()
        g.precision.publish()

    root_nodes = set(import_nodes)
    for imp in imported:
        target = export_index.get(imp["name"])
        if target and target[0] in graphs:
            root_nodes.add((target[0], target[1]))
    for g in graphs.values():
        for addr in g.init_roots():
            root_nodes.add((g.name, addr))

    # Pre-closure: reachability under the evidence that exists before in-image
    # slot targets are applied.  A slot writer is admissible only when it is
    # reachable here; a writer on no reachable path cannot have written the
    # slot (the rule's negative control).
    pre_closure = build_graph(graphs, root_nodes, export_index, import_nodes)
    pre_reachable = collections.defaultdict(set)
    for dso_name, addr in pre_closure["direct_reachable"]:
        pre_reachable[dso_name].add(addr)

    for g in graphs.values():
        evidence_stats[g.name] = apply_evidence_classes(
            g, workload_imports, pre_reachable.get(g.name, set()))

    closure = build_graph(graphs, root_nodes, export_index, import_nodes)
    # Admission by refutation (AGENTS.md section 22).  Inductive exclusions were
    # derived against the pre-closure direct set; the sound upper bound may
    # reach the callers/writers they excluded.  Refusing those sites leaves the
    # closure unusable, so each refuted exclusion is admitted with its witness
    # and the closure is recomputed until no admission grows the bound.  The
    # pass is monotone and may only add targets.
    closure, admission = admission_fixpoint(
        graphs,
        lambda: build_graph(graphs, root_nodes, export_index, import_nodes))
    direct_reach = closure["direct_reachable"]
    upper_reach = closure["upper_reachable"]
    refusals.extend(closure_refusals(closure))
    if not admission["converged"]:
        detail = admission.get("nonconvergent_detail") or {}
        refusals.append({
            "code": "ADMISSION_NONCONVERGENT",
            "detail": (
                "refutation admission did not reach a fixed point within "
                f"{detail.get('pass_cap')} pass(es); the last pass admitted "
                f"{detail.get('last_site_count')} site(s) and the reachable set "
                f"is {detail.get('reach_size')} node(s).  The target sets are "
                "partial and no reachability claim may be drawn from them"),
        })

    # The reachable function set is persisted with the receipt, so a movement
    # between candidates can be adjudicated from the receipt instead of the
    # multi-gigabyte record sidecar (AGENTS.md section 22).  The entries and the
    # digest use the analysis identity's name canonicalisation: the raw
    # `.llvm.<hash>` suffix changes with the build directory and source bytes
    # while the address set is identical, so hashing it would report movement
    # for a neutral rebuild.  The raw digest is retained as a non-identity.
    reachable_functions = reachable_function_entries(graphs, upper_reach)
    _raw_functions = reachable_function_entries(graphs, upper_reach,
                                                canonical=False)
    reachable_functions_sha256 = reachable_functions_digest(reachable_functions)
    reachable_functions_raw_sha256 = reachable_functions_digest(_raw_functions)
    reachable_functions_canonicalised = sum(
        1 for entry in _raw_functions
        if canonical_symbol_name(entry.split(":", 2)[2]) != entry.split(":", 2)[2])
    reachable_functions_per_module = collections.Counter(
        entry.split(":", 1)[0] for entry in reachable_functions)
    analysis_ident = analysis_identity(graphs)

    # ---- edge provenance records ----------------------------------------- #
    # Every indirect site emits a semantic record.  The *final upper bound* is
    # the authoritative oracle for every negative reachability claim: the
    # derivation-time reachable set is the pre-closure direct set, which is an
    # under-approximation and cannot prove an absence.
    oracle = ReachabilityOracle(graphs, upper_reach)
    # The population is streamed to a sidecar and validated/audited in the same
    # pass.  Nothing here retains 52k records: the receipt keeps counts, the
    # defects, the audit rows and a bounded sample.  v1.1 kept the population
    # and then json.dumps()ed it, which OOMed the ssh closure at 4 GiB.
    records_path = _edge_records_path(args, repo, artifact_sha, workdir)
    records_path.parent.mkdir(parents=True, exist_ok=True)
    residual_sites = {(d, hex(s.get("addr", 0)))
                      for d, _a, s in closure["reachable_residual_sites"]}
    stream = EdgeRecordStream(
        oracle, path=records_path,
        sample_cap=getattr(args, "max_record_sample",
                           EDGE_RECORD_SAMPLE_DEFAULT),
        reachable_residual=residual_sites)
    try:
        build_edge_records(graphs, oracle, sink=stream)
    finally:
        stream.close()
    edge_records = stream  # summary/counters live on the stream
    edge_defects = stream.defects
    edge_refusal = edge_refusal_for(edge_defects)
    if edge_refusal is not None:
        refusals.append(edge_refusal)

    # Every reachability-based exclusion -- reachable-caller bounding,
    # method-store writer exclusion, a dropped target, or a semantic call-site
    # row -- is re-checked against the final upper bound as it streams.  An
    # "excluded" subject that the bound admits makes the exclusion unsafe, so
    # the closure refuses rather than accepting the narrowed set.
    reachability_audit = stream.audit_rows
    reachability_violations = stream.violation_rows
    if stream.violations:
        refusals.append({
            "code": "REACHABILITY_EXCLUSION_UNSOUND",
            "detail": (
                "a reachability-based exclusion contradicts the final upper "
                "bound (site, role, subject): "
                + ", ".join(
                    f"{r['site']} {r['role']} {r['subject']}"
                    for r in reachability_violations)),
        })

    reachable_names = set()
    for dso_name, addr in upper_reach:
        sym = graphs[dso_name].funcs.get(addr)
        if sym:
            reachable_names.add(sym.split("@")[0])
    dyn_exports = set()
    for p in dso_paths.values():
        dyn_exports |= set(defined_symbols(p, dynamic=True))
    reachable_exports = sorted(reachable_names & dyn_exports)

    def matching(pred):
        return sorted(n for n in reachable_names if pred(n))

    allocator_hooks = matching(lambda n: n in {
        "CRYPTO_set_mem_functions", "CRYPTO_set_mem_debug",
        "CRYPTO_set_locking_callback", "CRYPTO_set_id_callback",
        "CRYPTO_get_mem_functions", "OPENSSL_atexit"})
    dynamic_lookup = matching(lambda n: n in {
        "dlsym", "dlopen", "dlerror", "DSO_bind_func", "DSO_bind_var",
        "DSO_dsobyaddr", "DSO_convert_filename"})
    cb_re = re.compile(r"(?:^|_)(?:set|ctl)[A-Za-z0-9_]*(?:cb|callback)", re.I)
    callback_registrars = matching(
        lambda n: bool(cb_re.search(n)) or n.startswith("BIO_meth_set_"))
    provider_symbols = {
        "OSSL_PROVIDER_load", "OSSL_PROVIDER_try_load", "OSSL_PROVIDER_unload",
        "OSSL_PROVIDER_add_builtin", "OSSL_PROVIDER_set_default_search_path",
        "OSSL_PROVIDER_available", "OSSL_PROVIDER_do_all",
        "OSSL_LIB_CTX_load_config", "OSSL_LIB_CTX_set0_default",
        "EVP_set_default_properties", "EVP_add_cipher", "EVP_add_digest",
        "EVP_add_alg_module", "ENGINE_by_id", "ENGINE_load_builtin_engines",
        "OPENSSL_init_crypto", "OPENSSL_MODULES",
    }
    provider_reachable = matching(lambda n: n in provider_symbols)
    consumer_provider_imports = sorted(imp["name"] for imp in imported
                                       if imp["name"] in provider_symbols)
    special_edges = {
        "constructor_destructor_roots": sum(len(g.init_roots()) for g in graphs.values()),
        "address_taken_global_union": len(closure["address_taken_union"]),
        "residual_class_admitted": len(closure["residual_bound"]),
        "reachable_residual_sites": len(closure["reachable_residual_sites"]),
        "unclassified_reachable_sites": [
            {"dso": d, "function": hex(a), "reason": r}
            for d, a, r in closure["unclassified_sites"]],
        "address_taken_data_pointers": sum(len(g.taken_data) for g in graphs.values()),
        "allocator_hook_registrars_reachable": allocator_hooks,
        "callback_registrars_reachable_count": len(callback_registrars),
        "callback_registrars_reachable_sample": callback_registrars[:40],
        "dynamic_name_lookup_reachable": dynamic_lookup,
        "consumer_imported_provider_registration": consumer_provider_imports,
        "provider_registration_or_selection_reachable": provider_reachable,
        "provider_narrowing": (
            "the consumer imports no provider installation/selection symbol and no "
            "dynamic name lookup, and the reachable set contains "
            f"{len(provider_reachable)} provider/engine selection symbol(s); provider "
            "dispatch is therefore limited to built-in providers whose tables are "
            "reached through the resolver, not to a dynamically registered provider"),
        "note": ("each listed class was checked against the reachable set of the exact "
                 "candidate code; an empty list is an observed absence on this closure, "
                 "not an assumption.  A reachable dynamic name lookup would be an "
                 "unmodelled edge class because the static graph cannot resolve names"),
    }

    files_upper, unmapped_upper = map_reachable_files(graphs, upper_reach, repo)
    files_direct, _ = map_reachable_files(graphs, direct_reach, repo)

    # ---- 3. symbol -> defining file, and per-symbol direct closure --------- #
    per_file = (inventory.get("contracts") or {}).get("per_file") or {}
    inventory_files = sorted(per_file)
    export_sites = index_export_sites(repo, inventory_files)

    symbols = []
    for imp in imported:
        target = export_index[imp["name"]]
        defs = export_sites.get(imp["name"], [])
        direct_nodes = direct_only_closure(graphs, {(target[0], target[1])}, export_index)
        dfiles, _ = map_reachable_files(graphs, direct_nodes, repo)
        dfiles.update(defs)
        symbols.append({
            "name": imp["name"],
            "version": imp["version"],
            "lib": imp["lib"],
            "defining_file": defs[0] if defs else None,
            "all_defining_files": defs,
            "definition_resolved": bool(defs),
            "direct_reachable_files": sorted(dfiles),
        })
        if not defs:
            notes.append(f"{imp['name']}: no #[no_mangle]/#[export_name] definition was "
                         f"located in the inventory source set")
        if defs and defs[0] not in files_upper:
            notes.append(f"{imp['name']}: lexical definition {defs[0]} is not in the "
                         f"binary-mapped reachable file set; added from source evidence")
            files_upper.add(defs[0])

    # ---- 4. obligations --------------------------------------------------- #
    contracts = inventory.get("contracts") or {}
    blockers = contracts.get("blockers") or []
    production = [b for b in blockers if b.get("partition") == V1_PARTITION_PRODUCTION]
    carry_forward, carry_refusals = resolve_carry_forward(
        repo, args, args.family, artifact, artifact_sha)
    refusals.extend(carry_refusals)
    reachability_evidence = {
        "source": "graph.reachable_files (the final linked-code upper bound)",
        "artifact_path": rel(artifact, repo),
        "artifact_sha256": artifact_sha,
        "reachable_file_count": len(files_upper),
        "rule": ("carry-forward requires the file to be reachable at this "
                 "artifact; an unreachable file is recorded as removed with "
                 "reason no-longer-reachable-at-this-artifact"),
    }
    obligations, enrollment = obligation_candidates(
        contracts, files_upper, boundaries_by_file, obligation_mechanisms,
        carry_forward=carry_forward,
        reachability_evidence=reachability_evidence)
    for o in obligations:
        mech, basis = mechanism_for(o["file"], mechanisms, o, obligation_mechanisms)
        o["mechanism"] = mech
        o["mechanism_basis"] = basis
        o["status"] = None
        o["discharge_receipt"] = None
        o["status_reason"] = None
    for o in obligations:
        adjudicate(o, mechanisms, boundaries_by_file.get(o["file"], []), plane)
        if o.get("contract") == "contracted":
            if o.get("carried_forward_from"):
                o["documentation_note"] = (
                    "documented (attached contract) but retained in the obligation "
                    "queue by carry-forward from the previous applied closure "
                    f"{o['carried_forward_from'].get('receipt')}; a contract is "
                    "not a discharge")
                previous = o.get("status_reason") or ""
                separator = (". " if previous and not previous.rstrip().endswith(".")
                             else " ")
                o["status_reason"] = (previous + separator if previous else "") + (
                    "The operation is documented (an attached # Safety/SAFETY "
                    "contract) but remains enrolled by carry-forward from "
                    f"{o['carried_forward_from'].get('receipt')}; a contract "
                    "transfers the obligation to the caller, it does not "
                    "discharge it.")
                continue
            o["documentation_note"] = (
                "documented (attached contract) but retained in the obligation "
                "queue because it is named by site receipt "
                f"{o.get('site_receipt')} and by state.json#/obligation_mechanisms; "
                "a contract is not a discharge")
            previous = o.get("status_reason") or ""
            separator = ". " if previous and not previous.rstrip().endswith(".") else " "
            o["status_reason"] = (previous + separator if previous else "") + (
                "The operation is documented (an attached # Safety/SAFETY contract) "
                "but remains enrolled; a contract transfers the obligation to the "
                "caller, it does not discharge it.")

    suppressed = (enrollment.get("carry_forward") or {}).get("suppressed") or []
    if suppressed:
        refusals.append({
            "code": "CARRY_FORWARD_SUPPRESSED",
            "detail": (
                f"{len(suppressed)} obligation(s) enumerated by the previous "
                "applied closure could not be enrolled at either the previous "
                "or the current census coordinate; they must not be silently "
                "dropped")})

    # per-symbol join over the narrow direct-call view.  Every symbol is a root of
    # the same global upper bound; the direct view is reported as a narrow,
    # non-proof view so the symbols remain distinguishable.
    for sym in symbols:
        dfiles = set(sym["direct_reachable_files"])
        ids = [o["id"] for o in obligations if o["file"] in dfiles]
        sym["direct_reachable_obligation_ids"] = ids
        sym["direct_reachable_obligation_count"] = len(ids)
        sym["direct_view_basis"] = (
            "direct call/PLT edges only; a narrow view, not an upper bound and not "
            "a proof that the listed sites are the only reachable ones")

    excluded_production = [
        {"file": b.get("file"), "line": b.get("line"), "kind": b.get("kind"),
         "reason": "file is not in the conservative upper-bound reachable set"}
        for b in production if b.get("file") not in files_upper
    ]

    counts = collections.Counter(o["status"] for o in obligations)
    by_mechanism = collections.Counter(o["mechanism"] or "<unmapped>" for o in obligations)
    stale_discharges = [o for o in obligations
                        if o.get("stale_discharge_rejections")]
    cf_enrollment = enrollment.get("carry_forward") or {}

    # ---- 5. freshness of the inventory at its own source head ------------- #
    reachable_inventory_files = sorted(files_upper & set(inventory_files))
    blob_hashes, _ = git_blob_hashes(repo, inventory_head, reachable_inventory_files)
    stale = []
    for f in reachable_inventory_files:
        recorded = per_file[f].get("source_sha256")
        actual = blob_hashes.get(f)
        if recorded and actual and recorded != actual:
            stale.append({"file": f, "recorded": recorded, "actual": actual})
    if stale:
        refusals.append({"code": "STALE_HASH",
                         "detail": f"{len(stale)} reachable file(s) do not match the V1 "
                                   f"source hash at {inventory_head[:9]}: " +
                                   ", ".join(s["file"] for s in stale[:8])})

    # ---- 6. refusal synthesis --------------------------------------------- #
    missing_boundary = sorted({o["file"] for o in obligations
                               if not o["boundary_receipt_present"]})
    if missing_boundary:
        refusals.append({
            "code": "MISSING_BOUNDARY_RECEIPT",
            "detail": f"{len(missing_boundary)} reachable file(s) carry production "
                      f"obligations but no boundary-sweep receipt owns them",
            "files": missing_boundary,
        })
    unknown = [o for o in obligations if o["status"] == "UNKNOWN"]
    if unknown:
        refusals.append({
            "code": "UNKNOWN_OBLIGATION",
            "detail": f"{len(unknown)} reachable production obligation(s) could not be "
                      f"adjudicated DISCHARGED or BLOCKED",
            "obligations": [o["id"] for o in unknown],
        })

    known = set(mechanisms)
    unmapped_mechanisms = sorted({o["mechanism"] for o in obligations
                                  if o["mechanism"] not in known and o["mechanism"]})
    if unmapped_mechanisms:
        refusals.append({"code": "UNKNOWN_MECHANISM",
                         "detail": "reachable files map to no registered mechanism: " +
                                   ", ".join(unmapped_mechanisms)})
    unmapped_files = sorted({o["file"] for o in obligations if o["mechanism"] is None})
    if unmapped_files:
        refusals.append({"code": "UNKNOWN_MECHANISM",
                         "detail": f"{len(unmapped_files)} reachable file(s) with production "
                                   f"obligations map to no registered mechanism",
                         "files": unmapped_files})

    # ---- 7. observed trace (optional, never narrowing) -------------------- #
    trace = {"available": False, "note": "no observed execution trace was supplied; the "
                                         "closure is the static upper bound alone"}
    if args.trace:
        tp = Path(args.trace)
        if not tp.is_absolute():
            tp = (repo / tp).resolve()
        if tp.is_file():
            doc = json.loads(tp.read_text())
            executed = doc.get("executed_symbols") or doc.get("symbols") or []
            trace = {"available": True, "path": rel(tp, repo),
                     "executed_symbol_count": len(executed),
                     "note": "a trace proves the named functions executed; it does not "
                             "prove unobserved paths unreachable and did not narrow the "
                             "static upper bound"}

    # ---- 8. ledger record ------------------------------------------------- #
    ledger = None
    ledger_path = (repo / args.ledger).resolve()
    if ledger_path.is_file():
        atlas = json.loads(ledger_path.read_text())
        body = atlas.get("body") or atlas
        for row in body.get("runs") or []:
            if row.get("family_id") == f"family:{args.family}" and row.get("subject") == "candidate":
                ledger = {
                    "run_id": row.get("run_id"),
                    "level": row.get("level"),
                    "outcome": row.get("outcome"),
                    "recipe_id": row.get("recipe_id"),
                    "source_sha256": row.get("source_sha256"),
                    "source_root_hash": row.get("source_root_hash"),
                    "source_root_hash_rule": row.get("source_root_hash_rule"),
                    "source_tree_domain_hash": row.get("source_tree_domain_hash"),
                    "artifact_rel": (row.get("linkage") or {}).get("artifact_rel"),
                    "artifact_sha256_recorded": (row.get("linkage") or {}).get("artifact_sha256"),
                    "recorded_candidate_install": (body.get("candidate_identity") or {}).get(
                        "libcrypto_so_3_sha256"),
                    "artifact_matches_this_build": (
                        (row.get("linkage") or {}).get("artifact_sha256") == artifact_sha),
                }
                break
    if ledger and not ledger["artifact_matches_this_build"]:
        notes.append("the build-link atlas row was produced against a different candidate "
                     "install, so its artefact digest does not match this rebuild; the "
                     "admitted install digest is the authority used for freshness")

    # ---- 8b. build provenance (when the downstream artefact was rebuilt) --- #
    build_record = None
    if args.build_record:
        bp = Path(args.build_record)
        if not bp.is_absolute():
            bp = (repo / bp).resolve()
        if not bp.is_file():
            refusals.append({"code": "STALE_HASH",
                             "detail": f"build record {bp} does not exist"})
        else:
            rec = json.loads(bp.read_text())
            checks = {}
            checks["artifact_sha256_matches"] = (
                rec.get("artifact_sha256") in (None, artifact_sha))
            checks["install_prefix_matches"] = (
                rec.get("install_prefix") in (None, rel(install, repo)))
            source_checks, source_refusals = source_root_hash_checks(rec, ledger)
            checks.update(source_checks)
            refusals.extend(source_refusals)
            if not checks.get("artifact_sha256_matches", True):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record artefact digest does not match the "
                                           "analysed artefact"})
            if not checks.get("install_prefix_matches", True):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record install prefix does not match the "
                                           "admitted install"})
            build_record = {"path": rel(bp, repo), "record": rec, "checks": checks}

    # ---- 9. receipt ------------------------------------------------------- #
    source_head = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    branch = run(["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "-C", str(repo), "status", "--porcelain",
                      "--untracked-files=no"]).stdout.strip())

    verdict_state = "REFUSED" if refusals else "ACCEPTED"
    receipt = {
        "schema": SCHEMA,
        "tool": tool_identity,
        "generated_utc": now_utc(),
        "family": args.family,
        "source_identity": {
            "repository_head": source_head,
            "branch": branch,
            "tracked_tree_dirty": dirty,
            "inventory_path": rel(inventory_path, repo),
            "inventory_source_head": inventory_head,
            "inventory_is_ancestor_or_equal": (
                run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                     inventory_head or "HEAD", "HEAD"]).returncode == 0),
            "note": ("the admitted install is the V1 frozen candidate; the working tree may "
                     "be a descendant, so obligations are joined to the inventory at the "
                     "inventory's own source head, not the working tree"),
        },
        "candidate_identity": {
            "install_prefix": rel(install, repo),
            "libcrypto_so_3_sha256": classification["openssl_sonames"].get(
                "libcrypto.so.3", {}).get("resolved_sha256"),
            "libssl_so_3_sha256": classification["openssl_sonames"].get(
                "libssl.so.3", {}).get("resolved_sha256"),
            "all_openssl_under_install": classification["all_openssl_under_install"],
        },
        "artifact_identity": {
            "path": rel(artifact, repo),
            "sha256": artifact_sha,
            "dynamic": dynamic,
            "build_provenance": build_record,
        },
        "loader_resolution": {
            "method": resolution["method"],
            "command_exit": resolution["command_exit"],
            "environment": resolution["environment"],
            "resolved": resolution["rows"],
            "openssl_sonames": classification["openssl_sonames"],
            "raw_ldd": resolution["raw"],
        },
        "ledger_record": ledger,
        "symbol_evidence": {
            "imported_symbol_count": len(imported),
            "imported_symbols": symbols,
        },
        "graph": {
            "method": (
                "function-level static graph over the exact candidate DSOs: nm-defined "
                "functions; objdump direct call edges; and an intraprocedural abstract "
                "interpreter that resolves indirect control transfers from relocations "
                "(GOT/PLT), immutable dispatch tables, relative jump tables, literal "
                "callback stores, field-offset stores in reachable code, and an "
                "interprocedural argument summary.  A site that cannot be resolved keeps "
                "its evidence class; only a site with no class admits the global "
                "address-taken union"),
            "upper_bound_rule": (
                "least fixed point of a monotone transfer function (Kildall 1973; "
                "Cousot & Cousot 1977): direct edges + the resolver's per-site "
                "target sets +, for every unresolved site whose containing "
                "function is reachable, the class-independent evidence union "
                "(materialised addresses, relocated function slots including "
                "in-image GLOB_DAT/JUMP_SLOT targets, field-store values and "
                "unresolved-call argument targets) plus the site's own targets. "
                "The union iterates until the reachable set stops growing; a "
                "class-specific set is precision reporting only and can never "
                "narrow the bound, so losing precision cannot lose reachability"),
            "closure": {
                "schema": UNRESOLVED_BOUND_SCHEMA,
                "analysis_identity": analysis_ident,
                "analysis_identity_basis": (
                    "the DSO file digest is not an analysis identity: a "
                    "comment-only edit changes it with byte-identical analysis "
                    "sections and symbol addresses; the identity hashes every "
                    "analysis-relevant section (name/type/address/size/bytes), "
                    "the canonical relocation table, the defined- and dynamic-"
                    "symbol tables and the loader entries, and excludes "
                    "analysis-irrelevant metadata (basis string in "
                    "analysis_identity.basis)"),
                "closure_rounds": closure["closure_rounds"],
                "max_rounds": closure["max_rounds"],
                "round_sizes": closure["round_sizes"],
                "sites_scanned_per_round": closure["sites_scanned_per_round"],
                "converged": closure["converged"],
                "nonconvergent_detail": closure["nonconvergent_detail"],
                "refutation_admission": {
                    "schema": admission["schema"],
                    "passes": admission["passes"],
                    "max_passes": admission["max_passes"],
                    "converged": admission["converged"],
                    "nonconvergent_detail": admission["nonconvergent_detail"],
                    "refuted_exclusions": admission["refuted_exclusions"],
                    "admitted_by_refutation": {
                        "count": admission["admitted_by_refutation"]["count"],
                        "targets": admission["admitted_by_refutation"]["targets"],
                    },
                    "rule": (
                        "an exclusion derived against the pre-closure direct set "
                        "that the sound upper bound reaches is false: the "
                        "subject's contribution is admitted with a witness and "
                        "the closure is recomputed, until no admission grows "
                        "the bound (cap 4 passes; exhaustion is "
                        "ADMISSION_NONCONVERGENT).  Admission may only add "
                        "targets; exclusions the bound does not reach survive "
                        "and remain validated"),
                },
                "residual_bound_nodes": closure["residual_bound_nodes"],
                "symbol_dispositions": closure["symbol_dispositions"],
                "symbol_disposition_summary": closure[
                    "symbol_disposition_summary"],
                "bound_evidence_sources": closure["bound_evidence_sources"],
                "reachable_functions_count": len(reachable_functions),
                "reachable_functions_sha256": reachable_functions_sha256,
                "reachable_functions_sha256_rule": (
                    "sha256 over the newline-terminated sorted "
                    "'module:hex_address:canonical_name' entries; the name is "
                    "canonicalised (compiler .llvm.<hash> and symbol-version "
                    "suffix removed) exactly as the analysis identity "
                    "canonicalises its symbol rows, so a comment-only rebuild "
                    "cannot move the digest"),
                "reachable_functions_raw_name_sha256": (
                    reachable_functions_raw_sha256),
                "reachable_functions_raw_name_sha256_rule": (
                    "sha256 over the same entries with the raw nm name; it "
                    "embeds the build-dependent .llvm.<hash> and is recorded "
                    "as a non-identity, not as movement evidence"),
                "reachable_functions_canonicalised_entries": (
                    reachable_functions_canonicalised),
                "reachable_functions_per_module": dict(
                    sorted(reachable_functions_per_module.items())),
                "reachable_functions": reachable_functions,
            },
            "direct_reachable_functions": len(direct_reach),
            "upper_bound_reachable_functions": len(upper_reach),
            "address_taken_functions": len(closure["address_taken_union"]),
            "reachable_functions_with_indirect_calls": closure[
                "indirect_reachable_functions"],
            "reachable_export_symbols": {
                "count": len(reachable_exports),
                "sample": reachable_exports[:80],
                "note": ("candidate DSO exports reached by the graph, including the 12 "
                         "consumer imports; the consumer-imported set is in "
                         "symbol_evidence"),
            },
            "special_edges": special_edges,
            "direct_reachable_files": len(files_direct),
            "upper_bound_reachable_files": len(files_upper),
            "reachable_files": sorted(files_upper),
            "unmapped_crate_functions": {
                "count": len(unmapped_upper),
                "samples": unmapped_upper[:20],
                "note": ("crate-namespace functions with no module-path mapping; they are a "
                         "coverage limit of the demangler, not a claim of unreachability"),
            },
            "per_dso": {
                name: {
                    "function_symbols": len(g.funcs),
                    "direct_edges": sum(len(v) for v in g.direct.values()),
                    "indirect_sites": len(getattr(g, "sites", {})),
                    "resolved_indirect_sites": sum(
                        1 for s in getattr(g, "sites", {}).values() if not s["unresolved"]),
                    "unresolved_indirect_sites": sum(
                        1 for s in getattr(g, "sites", {}).values() if s["unresolved"]),
                    "functions_with_unresolved_indirect_calls": len(
                        {k[0] for k, s in getattr(g, "sites", {}).items() if s["unresolved"]}),
                    "address_taken_code_refs": len(g.taken_code),
                    "address_taken_data_pointers": len(g.taken_data),
                    "site_classes": dict(sorted(
                        (str(k), v) for k, v in getattr(g, "precision_counts", {}).items())),
                } for name, g in graphs.items()
            },
            "observed_trace": trace,
            "limits": [
                "inlined callees have no out-of-line function node; their code is "
                "attributed to the caller, so a source file whose only contribution is "
                "inlined has no node of its own",
                "the resolver is an over-approximation: an unresolved site is admitted "
                "at its evidence class, and every unclassified site is listed rather "
                "than silently dropped",
                "the residual bound is class-independent and therefore monotone, but "
                "it is still a may-bound: a function that no materialised-address "
                "source names is not admitted, so monotonicity is not completeness",
                "the analysis identity binds the enumerated analysis inputs "
                "(sections, relocations, defined and dynamic symbol tables, "
                "loader entries); it is not a proof of input completeness: a "
                "derivation that starts reading a new section must extend the "
                "enumeration, and two candidates with identical enumerated "
                "inputs but a different unenumerated fact would collide",
                "a dynamic trace proves execution, not unreachability, and never "
                "narrowed this graph",
                "function-level reachability is not a proof that a site is safe; it "
                "bounds which obligations apply",
            ],
        },
        "precision": {
            "purpose": (
                "replace the global address-taken collapse with per-site, "
                "evidence-bound target sets; every residual site states why it remains "
                "unresolved"),
            "totals": {
                "indirect_sites": sum(len(getattr(g, "sites", {})) for g in graphs.values()),
                "resolved_sites": sum(
                    1 for g in graphs.values()
                    for s in getattr(g, "sites", {}).values() if not s["unresolved"]),
                "unresolved_sites": sum(
                    1 for g in graphs.values()
                    for s in getattr(g, "sites", {}).values() if s["unresolved"]),
                "reachable_unresolved_sites": len(closure["reachable_residual_sites"]),
                "reachable_target_bounded_unresolved_sites": sum(
                    1 for _d, _f, s in closure["reachable_residual_sites"]
                    if s.get("class") not in ABI_CONTRACT_CLASSES),
                "reachable_contract_bounded_sites": sum(
                    1 for _d, _f, s in closure["reachable_residual_sites"]
                    if s.get("class") in ABI_CONTRACT_CLASSES),
                "unclassified_reachable_sites": len(closure["unclassified_sites"]),
                "resolved_by_reachable_caller": sum(
                    1 for g in graphs.values() for s in g.sites.values()
                    if s.get("reachable_caller_bound")),
            },
            "classes": {
                "got_or_table": {
                    "mechanism": "call/jump through an absolute slot",
                    "evidence": "readelf -rW relocation (RELATIVE/GLOB_DAT/JUMP_SLOT) or raw pointer",
                    "invariant": (
                        "the slot's value is fixed by the dynamic loader and the slot "
                        "lies in .got/.got.plt/.data.rel.ro/.rodata, which are immutable "
                        "after relocation; a writable .data/.bss slot is used only with "
                        "the union of all stores performed by reachable code"),
                },
                "table": {
                    "mechanism": "static dispatch/vtable table read with a known base",
                    "evidence": ".data.rel.ro relocation runs",
                    "invariant": (
                        "the base address is a link-time constant (lea or a relocated "
                        "pointer), so every entry is a relocation-resolved function "
                        "address; an unfilled or open entry makes the site unresolved"),
                },
                "switch": {
                    "mechanism": "compiler relative jump table",
                    "evidence": "4-byte relative entries from a known .rodata base",
                    "invariant": (
                        "the table base is a link-time constant and every entry is "
                        "decoded; targets that are function starts are admitted, "
                        "intra-function targets add no new node"),
                },
                "field": {
                    "mechanism": "object-field dispatch (callback or method pointer)",
                    "evidence": (
                        "stores to that offset by reachable code, consumer-imported "
                        "values and the return values of consumer-imported constructors, "
                        "and code-materialised addresses when the field is open"),
                    "invariant": (
                        "a function value installed in a reachable object at a known "
                        "offset is either written by reachable code (store summary), "
                        "supplied by the consumer (its imported symbols and their "
                        "returns, since the artefact has no dynamic name lookup), or "
                        "address-materialised in reachable code; an open field adds the "
                        "code-materialised set"),
                },
                "materialised": {
                    "mechanism": "direct call through a value with no static table provenance",
                    "evidence": "address-of materialisations in reachable code + consumer imports",
                    "invariant": (
                        "after GOT/table/switch/field resolution, a remaining value can "
                        "only be an address taken in reachable code or a value supplied "
                        "by the consumer; a site that cannot be assigned even this class "
                        "is listed as unclassified and admits the global union"),
                },
            },
            "invariants_summary": (
                "Each class is narrowed only by evidence that fixes the possible values "
                "at the site.  A trace never narrows anything.  Functions that are not "
                "observed remain reachable if any bound admits them.  The residual class "
                "is a bound, not a claim that every listed function is called."),
            "residual_sites": [
                {"dso": d, "function": hex(f),
                 "call_site": hex(s.get("addr", 0)),
                 "reason": s["reason"],
                 "class": s["class"], "text": s["text"][:160]}
                for d, f, s in closure["reachable_residual_sites"][:200]],
            "static_table_instance": {
                "schema": S1_WITNESS_SCHEMA,
                "rule": (
                    "field-sensitive key (object type, pointer-slot offset, "
                    "member offset); the base object is the function's "
                    "declared context parameter, proven through the entry "
                    "register, whole-register copies or a frame spill whose "
                    "every reaching store is the same parameter (branches are "
                    "never unioned); the effective table type is the declared "
                    "pointer-field type or a source cast of that field to a "
                    "decidable repr(C) layout; every scalar store to the slot "
                    "in the dispatch table's constructor cohort must write a "
                    "declared static instance of that type; every member read "
                    "must be an in-image function start; a partial instance "
                    "set or a mutable table refuses the site rather than "
                    "unioning it"),
                "summary": {
                    "resolved": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("static_instance_witness")),
                    "refused": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("static_instance_refusal")),
                    "by_refusal": dict(sorted(collections.Counter(
                        str((s.get("static_instance_refusal") or {}).get(
                            "refusal"))
                        for g in graphs.values() for s in g.sites.values()
                        if s.get("static_instance_refusal")).items())),
                },
                "resolved_sites": [
                    {"dso": name,
                     "function": w.get("function"),
                     "call_site": w.get("call_site"),
                     "operator": s.get("text", "")[:160],
                     "operand": w.get("operand"),
                     "pointer_slot": w.get("pointer_slot"),
                     "member": w.get("member"),
                     "effective_type": w.get("effective_type"),
                     "instances": [r.get("symbol") or r.get("addr")
                                   for r in w.get("instances", [])],
                     "instances_detail": [
                         {"symbol": r.get("symbol"),
                          "declared_type": r.get("declared_type"),
                          "prefix_compatible": r.get("prefix_compatible")}
                         for r in w.get("instances", [])],
                     "conditions": w.get("conditions"),
                     "prefix_compatible_types":
                         (w.get("completeness") or {}).get(
                             "prefix_compatible_types"),
                     "excluded_different_object_stores":
                         (w.get("completeness") or {}).get(
                             "excluded_different_object_stores"),
                     "targets": w.get("targets")}
                    for name, g in graphs.items() for s in g.sites.values()
                    for w in [s.get("static_instance_witness") or {}]
                    if w],
                "refused_sites": [
                    {"dso": name,
                     "function": w.get("function"),
                     "call_site": w.get("call_site"),
                     "operator": s.get("text", "")[:160],
                     "refusal": w.get("refusal"),
                     "operand": w.get("operand"),
                     "pointer_slot": w.get("pointer_slot"),
                     "dispatch_tables": w.get("dispatch_tables"),
                     "considered_types": w.get("considered_types"),
                     "candidates": w.get("candidates"),
                     "chain": w.get("chain")}
                    for name, g in graphs.items() for s in g.sites.values()
                    for w in [s.get("static_instance_refusal") or {}]
                    if w],
            },
            "nested_static_instance": {
                "schema": NESTED_WITNESS_SCHEMA,
                "rule": (
                    "a second-level static-instance dispatch: the context "
                    "parameter loads a pointer field whose declared pointee is "
                    "a repr(C) struct; every store to that pointer field in "
                    "the image is enumerated by scanning every instruction of "
                    "every function, and each is either excluded as a "
                    "different object, accounted as a declared static "
                    "instance (or NULL), or refuses the site; an overlapping "
                    "non-scalar store refuses as well.  Every stored "
                    "instance's selected member must be an in-image function "
                    "start"),
                "summary": {
                    "resolved": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("nested_instance_witness")),
                    "refused": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("nested_instance_refusal")),
                    "by_refusal": dict(sorted(collections.Counter(
                        str((s.get("nested_instance_refusal") or {}).get(
                            "refusal"))
                        for g in graphs.values() for s in g.sites.values()
                        if s.get("nested_instance_refusal")).items())),
                },
                "resolved_sites": [
                    {"dso": name,
                     "function": w.get("function"),
                     "call_site": w.get("call_site"),
                     "pointer_slot": w.get("pointer_slot"),
                     "member": w.get("member"),
                     "instances": [r.get("symbol") for r in
                                   w.get("instances", [])],
                     "stored_by": w.get("stored_by"),
                     "conditions": w.get("conditions"),
                     "targets": w.get("targets")}
                    for name, g in graphs.items() for s in g.sites.values()
                    for w in [s.get("nested_instance_witness") or {}]
                    if w],
                "refused_sites": [
                    {"dso": name,
                     "function": w.get("function"),
                     "call_site": w.get("call_site"),
                     "refusal": w.get("refusal"),
                     "pointer_slot": w.get("pointer_slot"),
                     "unproven_base_stores": w.get("unproven_base_stores"),
                     "unaccounted_values": w.get("unaccounted_values"),
                     "overlapping_non_scalar_stores":
                         w.get("overlapping_non_scalar_stores")}
                    for name, g in graphs.items() for s in g.sites.values()
                    for w in [s.get("nested_instance_refusal") or {}]
                    if w],
            },
            "unclassified_reachable_sites": closure["unclassified_sites"],
            "evidence_classes": evidence_stats,
            "dlsym_literals": {
                name: {lit: {"sites": len(rec["sites"]), "exported": rec["exported"]}
                       for lit, rec in sorted(g.dlsym_literals.items())}
                for name, g in graphs.items()},
            "dlsym_literals_naming_missing_exports": sorted({
                lit for g in graphs.values() for lit, rec in g.dlsym_literals.items()
                if not rec["exported"]}),
            "unresolved_by_class": dict(collections.Counter(
                s["class"] for g in graphs.values() for s in g.sites.values()
                if s["unresolved"])),
            "semantic_store_target_bounding": {
                "rule": (
                    "a slot written by reachable code is bounded by the values "
                    "those writers actually store, resolved through their "
                    "provenance: an in-image lea, a GLOB_DAT of a symbol defined "
                    "in this image, a caller parameter chain, or one level of an "
                    "object field whose slot writer is known.  Any reachable store "
                    "whose provenance is not image-bounded keeps the site "
                    "UNRESOLVED.  Declared symbol names are a cross-check, never "
                    "the source of truth, and a declared-but-absent name cannot "
                    "void the rule."),
                "schema": SEMANTIC_STORE_SCHEMA,
                "sites": [
                    {"dso": name,
                     "function": g.funcs.get(s["func"], "?"),
                     "call_site": hex(s["addr"]),
                     "resolved": s["semantic_store_target"].get("resolved"),
                     "targets": s["semantic_store_target"].get("targets"),
                     "writer_argument_index": s["semantic_store_target"].get(
                         "writer_argument_index"),
                     "writers": s["semantic_store_target"].get("writers"),
                     "excluded_writers": s["semantic_store_target"].get(
                         "excluded_writers"),
                     "call_sites": s["semantic_store_target"].get("call_sites"),
                     "declared_cross_check": s["semantic_store_target"].get(
                         "declared_cross_check"),
                     "refusal": s["semantic_store_target"].get("refusal"),
                     "offending_call_sites": s["semantic_store_target"].get(
                         "offending_call_sites")}
                    for name, g in graphs.items() for s in g.sites.values()
                    if s.get("semantic_store_target")],
                "counts": {
                    "resolved": sum(1 for g in graphs.values()
                                    for s in g.sites.values()
                                    if (s.get("semantic_store_target") or {}).get(
                                        "resolved")),
                    "unresolved": sum(1 for g in graphs.values()
                                      for s in g.sites.values()
                                      if s.get("semantic_store_target")
                                      and not s["semantic_store_target"].get(
                                          "resolved")),
                },
                "declared_but_absent": sorted({
                    f for g in graphs.values() for s in g.sites.values()
                    for f in ((s.get("semantic_store_target") or {}).get(
                        "declared_cross_check") or {}).get("declared_but_absent", ())}),
                "derived_but_undeclared": sorted({
                    a for g in graphs.values() for s in g.sites.values()
                    for a in ((s.get("semantic_store_target") or {}).get(
                        "declared_cross_check") or {}).get(
                            "derived_but_undeclared", ())}),
            },
            "witness_rule": {
                "requirement": (
                    "AGENTS.md section 22: a contract-bounded class is applied "
                    "only with a per-call-site witness naming the slot, its "
                    "reachable writer and the documented interface that fills "
                    "it; a site lacking one stays unresolved"),
                "schema": WITNESS_SCHEMA,
                "witness_backed": [
                    {"dso": name, "function": g.funcs.get(s["func"], "?"),
                     "call_site": hex(s["addr"]), "class": s["class"],
                     "slot": s["witness"]["slot"]}
                    for name, g in graphs.items() for s in g.sites.values()
                    if s.get("class") in ABI_CONTRACT_CLASSES
                    and (s.get("witness") or {}).get("contract_bounded") is True],
                "witness_missing": [
                    {"dso": name, "function": g.funcs.get(s["func"], "?"),
                     "call_site": hex(s["addr"]),
                     "candidate_class": s.get("contract_class_candidate"),
                     "slot": (s.get("witness") or {}).get("slot"),
                     "writer": (s.get("witness") or {}).get("writer"),
                     "reason": s["reason"]}
                    for name, g in graphs.items() for s in g.sites.values()
                    if s.get("contract_class_candidate") and s["unresolved"]
                    and s.get("class") not in ABI_CONTRACT_CLASSES],
                "counts": {
                    "contract_bounded": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s["unresolved"] and s["class"] in ABI_CONTRACT_CLASSES),
                    "witness_backed": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("class") in ABI_CONTRACT_CLASSES
                        and (s.get("witness") or {}).get("contract_bounded") is True),
                    "candidate_without_witness": sum(
                        1 for g in graphs.values() for s in g.sites.values()
                        if s.get("contract_class_candidate") and s["unresolved"]
                        and s.get("class") not in ABI_CONTRACT_CLASSES),
                },
            },
            "reachable_caller_target_bounding": {
                "rule": (
                    "an indirect site whose target set was unbounded is bounded by "
                    "the argument values contributed by callers that are themselves "
                    "in this family's reachable set; every caller row -- reachable "
                    "or excluded -- carries the per-call-site witness and the "
                    "argument-summary attribution that produced its contribution; "
                    "a non-image argument from any reachable caller, an unknown "
                    "caller, or a non-argument target keeps the site unresolved; a "
                    "candidate that no caller row attributes is admitted into the "
                    "upper bound (never dropped) and is listed in "
                    "unattributed_admissions"),
                "schema": REACHABLE_CALLER_SCHEMA,
                "not_a_contract_class": True,
                "abi_contract_class": None,
                "sites": [
                    {"dso": name,
                     "function": g.funcs.get(s["func"], "?"),
                     "call_site": hex(s["addr"]),
                     "class": s["class"],
                     "argument_indices": s["reachable_caller_bound"][
                         "argument_indices"],
                     "reachable_callers": s["reachable_caller_bound"][
                         "reachable_callers"],
                     "excluded_callers": s["reachable_caller_bound"][
                         "excluded_callers"],
                     "bounded_targets": s["reachable_caller_bound"][
                         "bounded_targets"],
                     "attributed_targets": s["reachable_caller_bound"].get(
                         "attributed_targets", []),
                     "unattributed_targets": s["reachable_caller_bound"].get(
                         "unattributed_targets", [])}
                    for name, g in graphs.items() for s in g.sites.values()
                    if s.get("reachable_caller_bound")],
                "count": sum(
                    1 for g in graphs.values() for s in g.sites.values()
                    if s.get("reachable_caller_bound")),
                "excluded_caller_audit": [
                    {"dso": r["dso"], "site": r["site"],
                     "excluded_caller": r["symbol_address"],
                     "excluded_symbol": r["symbol"],
                     "in_final_upper_bound": r["in_final_upper_bound"]}
                    for r in reachability_audit
                    if r["role"] == "reachable-caller"],
                "excluded_caller_violations": [
                    r for r in reachability_violations
                    if r["role"] == "reachable-caller"],
            },
            "abi_contract_bounded": {
                "allocator": {
                    "class": ABI_CONTRACT_ALLOCATOR,
                    "resolution_kind": "contract-bounded (target set unbounded)",
                    "sites": [{"dso": name, "function": hex(s["func"]),
                               "function_name": g.funcs.get(s["func"], "?"),
                               "site": hex(s["addr"]), "reason": s["reason"],
                               "witness": s.get("witness"),
                               "resolved": False}
                              for name, g in graphs.items() for s in g.sites.values()
                              if s["unresolved"] and s["class"] == ABI_CONTRACT_ALLOCATOR],
                    "bound": "public CRYPTO_set_mem_functions ABI; any caller-supplied triple",
                    "contract": ABI_CONTRACTS[ABI_CONTRACT_ALLOCATOR],
                    "runtime_fact_not_static_bound": (
                        "the globals are NULL in this configuration, so the in-image "
                        "default is selected; that is a runtime fact, not a link-time bound"),
                },
                "provider": {
                    "class": ABI_CONTRACT_PROVIDER,
                    "resolution_kind": "contract-bounded (target set unbounded)",
                    "sites": [{"dso": name, "function": hex(s["func"]),
                               "function_name": g.funcs.get(s["func"], "?"),
                               "site": hex(s["addr"]), "reason": s["reason"],
                               "witness": s.get("witness"),
                               "resolved": False}
                              for name, g in graphs.items() for s in g.sites.values()
                              if s["unresolved"] and s["class"] == ABI_CONTRACT_PROVIDER],
                    "bound": "public OSSL_provider_init provider ABI",
                    "contract": ABI_CONTRACTS[ABI_CONTRACT_PROVIDER],
                    "why_open": (
                        "a provider module selected by configuration can return its "
                        "own dispatch table; the target set is unbounded"),
                },
                "distinct_from_resolved": (
                    "a statically resolved edge has resolved=true and an in-image "
                    "target set; every site above has resolved=false and an unbounded "
                    "target set, and is counted in reachable_unresolved_sites"),
            },
            "predicate_element_7": evaluate_predicate_element_7(
                closure["reachable_residual_sites"], closure["unclassified_sites"]),
            "refutation_admission": {
                "schema": admission["schema"],
                "rule": (
                    "each row names the exclusion subject the final upper bound "
                    "reaches, the targets admitted with it, and whether the "
                    "admission left the site's target set finite.  A site whose "
                    "admitted caller/writer has no finite recorded contribution "
                    "becomes UNRESOLVED with a named refutation-unbounded "
                    "property rather than keeping an unsound finite claim"),
                "admission_passes": admission["passes"],
                "max_passes": admission["max_passes"],
                "converged": admission["converged"],
                "refuted_exclusions": admission["refuted_exclusions"],
                "admitted_by_refutation": admission["admitted_by_refutation"],
                "sites": admission["sites"],
                "sites_truncated": admission.get("sites_truncated", False),
            },
            "settled": (
                ("every reachable unresolved site is contract-bounded (section 7 "
                 "criterion 2); no target-bounded unresolved site and no "
                 "unclassified site is reachable")
                if evaluate_predicate_element_7(
                    closure["reachable_residual_sites"],
                    closure["unclassified_sites"])["established"] else
                ("at least one reachable unresolved site is target-bounded: its slot "
                 "has no per-call-site witness for a documented ABI contract (for "
                 "example an internal Rust callback), or the site has no evidence "
                 "class and admits the global address-taken union")),
        },
        "edge_provenance": {
            **stream.summary(),
            "rule": (
                "every indirect site emits a semantic identity (source "
                "operation, defining function, call-site role, per-target "
                "provenance chain) plus a disposition; an address is recorded "
                "only as an artifact-local witness; every row carries a "
                "row_kind from a closed vocabulary, so `exclusions[]` holds "
                "only target drops and the auxiliary lists hold only subject "
                "claims; every target drop is bound to a structured "
                "subject-to-target mapping (candidate_source for caller-bound "
                "drops, evidence.targets for declared-name drops, writer "
                "would_store_targets for writer drops); a caller-bound drop is "
                "recomputed from candidate_source's per-call-site witnesses, and "
                "a candidate that no caller row attributes is admitted and "
                "listed in unattributed_admissions; every claim is bound "
                "to the record's own module; a chain step comes from a closed "
                "vocabulary and carries a payload"),
            "refusal_rule": (
                "a row whose row_kind or reason belongs to the other list "
                "kind, a target dropped without a checkable structured "
                "mapping, a claim whose mapping disagrees with the "
                "recomputed candidate_source, an exclusion whose subject "
                "disagrees with its target or module, a claim that disagrees "
                "with a mutually redundant ledger (target_set, "
                "candidate_source, admitted_targets, derivation, disposition-"
                "derived target_reachability), a duplicate edge identity, a "
                "proved/contract record with an empty target or no defining "
                "symbol, or a reachability exclusion that contradicts the "
                "final upper bound refuses the closure with "
                "EDGE_RECORD_EXCLUSION_UNSOUND / REACHABILITY_EXCLUSION_UNSOUND"),
            "defects_total": len(edge_defects),
            "defects": (edge_defects
                        if len(edge_defects) <= EDGE_DEFECT_RENDER_LIMIT
                        else edge_defects[:EDGE_DEFECT_RENDER_LIMIT]),
            "defects_complete": len(edge_defects) <= EDGE_DEFECT_RENDER_LIMIT,
            "demotions": {
                "vacuous_target_sets_demoted":
                    stream.demoted.get("empty-target-set", 0),
                "no_symbol_function_demoted":
                    stream.demoted.get("no-defining-symbol", 0),
                "first_sites": stream.demoted_sites,
                "note": (
                    "an empty admitted set or a missing defining symbol is a "
                    "resolver gap, not a proof; those records are demoted to "
                    "UNRESOLVED so the gap stays visible instead of being "
                    "counted as PROVED_TARGET_SET"),
            },
            "records_path": rel(records_path, repo),
            "records_path_basis": (
                "repo-relative when the sidecar is inside the repository, "
                "otherwise absolute; the default is the gitignored workdir and "
                "--edge-records is the only override"),
            "records_sha256": stream.records_sha256,
            "records_bytes": (records_path.stat().st_size
                              if records_path.is_file() else None),
            "sidecar_lines": stream.count,
            "validator_sha256": tool_sha,
            "admissibility": _admissibility(
                tool_sha, artifact_sha, stream.records_sha256, stream.count),
            "records_sample": stream.sample,
            "records_sample_eligible": stream.sample_eligible,
            "records_sample_truncated": stream.sample_truncated,
            "sample_cap": stream.sample_cap,
            "sample_policy": (
                "records_sample is a bounded selection, not the population. "
                "Exclusion-bearing records and reachable residual sites are "
                "admitted first (every exclusion is a claim under review); "
                "non-PROVED records then fill the remaining slots, in stream "
                "order, up to sample_cap records in total.  Long per-record "
                "lists are truncated to sample_list_cap entries and keep a "
                "count; the complete population is the JSONL sidecar named by "
                "records_path (digest records_sha256), one record per line"),
            "reachability_oracle": {
                "schema": REACHABILITY_ORACLE_SCHEMA,
                "basis": "final-upper-bound",
                "authoritative": True,
                "audit": reachability_audit,
                "audit_total": stream.audit_total,
                "audit_truncated":
                    stream.audit_total > len(reachability_audit),
                "violations": stream.violations,
                "violation_examples": reachability_violations,
                "note": (
                    "the final upper bound is authoritative for every "
                    "reachability-based exclusion; a reachable address "
                    "contributes every name the image records for it, an "
                    "unknown module is a violation (never 'unavailable is "
                    "fine'), and pre-closure direct reach is retained only as "
                    "the derivation input"),
            },
        },
        "obligations": obligations,
        "documented_enrollment": enrollment,
        "closure_scope": {
            "v1_production_operations": len(production),
            "included_in_upper_bound": len(obligations),
            "documented_operations_enrolled": enrollment["enrolled_count"],
            "carried_forward_obligations": (
                enrollment.get("carry_forward") or {}).get(
                    "carried_forward_count", 0),
            "excluded_from_upper_bound": excluded_production,
            "exclusion_basis": (
                "a production operation is excluded only when its file has no function "
                "whose address is reachable in the exact candidate linked code; this is "
                "the same static upper bound used for every obligation, not a separate "
                "narrowing"),
        },
        "counts": {
            "reachable_files": len(files_upper),
            "reachable_production_obligations": len(obligations),
            "DISCHARGED": counts.get("DISCHARGED", 0),
            "BLOCKED": counts.get("BLOCKED", 0),
            "UNKNOWN": counts.get("UNKNOWN", 0),
            "by_mechanism": dict(sorted(by_mechanism.items())),
            "v1_production_operations_total": len(production),
            "v1_uncontracted_operations_total": len(blockers),
            "carried_forward": (enrollment.get("carry_forward") or {}).get(
                "carried_forward_count", 0),
            "carried_forward_removed": cf_enrollment.get("removed_count", 0),
            "carried_forward_removed_by_reason": cf_enrollment.get(
                "removed_by_reason", {}),
            "stale_discharge_rejections": len(stale_discharges),
            "stale_discharge_sites": [
                {"id": o["id"], "item": o.get("item"),
                 "rejections": o["stale_discharge_rejections"]}
                for o in stale_discharges],
        },
        "boundary_coverage": {
            "reachable_files_with_receipt": sorted(
                {o["file"] for o in obligations if o["boundary_receipt_present"]}),
            "reachable_files_without_receipt": missing_boundary,
        },
        "refusals": refusals,
        "verdict": {
            "state": verdict_state,
            "safe_compatible": False,
            "reason": (
                "no refusal condition fired"
                if not refusals else
                "closure refused: " + "; ".join(
                    f"{r['code']} ({r['detail']})" for r in refusals)),
        },
        "notes": notes,
        "non_claims": [
            "This is a reachability measurement, not a memory-safety proof and not a "
            "SAFE_COMPATIBLE promotion.",
            "DISCHARGED means an existing committed receipt covers the exact site; this "
            "tool did not re-audit, re-run or independently review that receipt.",
            "The upper bound is a function-level linked-code over-approximation, not a "
            "whole-program or source-level call graph.",
            "Record-level validation proves internal consistency and agreement with "
            "the graph-derived final upper bound.  It does not prove that a record "
            "was produced by this analyzer rather than forged: a forged record that "
            "is internally consistent is outside its power.  Admissibility needs "
            "the identity chain in edge_provenance.admissibility (validator sha256, "
            "record schema, artefact sha256, sidecar digest and line count) and a "
            "re-run of the pinned validator over the pinned sidecar.",
            "No crate build, test, Miri, ASan or cryptographic court was run by this tool.",
            "The residual bound is a monotone may-bound, not a completeness proof: it "
            "cannot admit a target that no materialised-address evidence names, and "
            "the fixpoint is over the linked image plus the resolved OpenSSL DSOs, not "
            "a whole-program call graph.",
            "The analysis identity is over .text and the symbol table.  It is not a "
            "byte-for-byte reproducibility claim across toolchains and it does not "
            "cover data-section contents.",
            "The dynamic-trace axis is absent unless a trace is supplied; its absence is "
            "recorded, not treated as evidence.",
        ],
    }
    return receipt


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

def self_test() -> int:
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    check("opensym libcrypto", bool(OPENSYM.match("libcrypto.so.3")), True)
    check("opensym libssl3", bool(OPENSYM.match("libssl.so.3")), True)
    check("opensym other", bool(OPENSYM.match("libcrypto.a")), False)

    # nm line parsing
    check("nm defined", parse_nm_line("0000000000000123 T EVP_rc4"), (0x123, "T", "EVP_rc4"))
    check("nm undef", parse_nm_line("                 U EVP_rc4"), None)

    # adjudication truth table
    mechs = {
        "ERR": {"state": "SAFETY_DISCHARGED"},
        "BIO": {"state": "UNSAFE_OPEN"},
        "EVP_PKEY_PROVIDER": {"state": "OWNERSHIP_RECONSTRUCTED"},
        "SSL_SESSION": {"state": "OWNERSHIP_RECONSTRUCTED"},
    }
    plane = {
        "mechanism_discharges": {"ERR-1": {"id": "ERR-1", "state": "SAFETY_DISCHARGED",
                                           "mechanism": "ERR error-queue"}},
        "scoped_boundary_discharges": {"B23-WPKT-1": {"receipt": "boundary-sweep-B23"}},
        "err_scope": {"receipt": "mechanism-discharge-ERR.json", "mechanism": "ERR",
                      "sites": {"src/runtime/err.rs": [(10, 20, "ERR-01")]}},
    }
    def ob(file, line, mech, kind="UNSAFE_FN_DEF", item="f", current=None):
        rec = {"file": file, "line": line, "mechanism": mech, "status": None,
               "discharge_receipt": None, "status_reason": None,
               "kind": kind, "item": item}
        if current is not None:
            rec["current_census_line"] = current
        return rec
    def bound(file, kind, operation, disposition):
        return {"id": "B23-WPKT-1", "file": file, "kind": kind,
                "operation": operation, "disposition": disposition}
    check("discharged exact", adjudicate(ob("src/runtime/err.rs", 15, "ERR"), mechs, [],
                                         plane)["status"], "DISCHARGED")
    check("unknown err outside surface",
          adjudicate(ob("src/runtime/err.rs", 999, "ERR"), mechs, [], plane)["status"],
          "UNKNOWN")
    check("blocked unsafe_open",
          adjudicate(ob("src/runtime/bio/x.rs", 1, "BIO"), mechs,
                     [{"id": "B1", "disposition": "CONTRACTED"}], plane)["status"],
          "BLOCKED")
    check("blocked reconstructed",
          adjudicate(ob("src/evp/x.rs", 1, "EVP_PKEY_PROVIDER"), mechs,
                     [{"id": "B2", "disposition": "CONTRACTED"}], plane)["status"],
          "BLOCKED")
    check("unknown no receipt",
          adjudicate(ob("src/new/x.rs", 1, "EVP_PKEY_PROVIDER"), mechs, [], plane)["status"],
          "UNKNOWN")
    # a scoped discharge without a declared line range discharges nothing (B27-X2
    # names only the loader_set_params path; it must not cover the whole file).
    check("scoped boundary without range does not discharge",
          adjudicate(ob("src/ssl/x.rs", 1, "SSL_SESSION"), mechs,
                     [bound("src/ssl/x.rs", "UNSAFE_FN_DEF", "f",
                            "SAFETY_DISCHARGED")],
                     plane)["status"],
          "BLOCKED")
    check("scoped range covers site",
          adjudicate(ob("src/ssl/x.rs", 40, "SSL_SESSION"), mechs,
                     [bound("src/ssl/x.rs", "UNSAFE_FN_DEF", "f",
                            "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)")],
                     plane)["status"],
          "DISCHARGED")
    # a line range may only narrow a stable-identity match, never establish it
    check("scoped range alone does not establish identity",
          adjudicate(ob("src/ssl/x.rs", 40, "SSL_SESSION"), mechs,
                     [bound("src/ssl/x.rs", "UNSAFE_FN_DEF", "other",
                            "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)")],
                     plane)["status"],
          "BLOCKED")
    check("scoped range does not blanket-discharge",
          adjudicate(ob("src/ssl/x.rs", 999, "SSL_SESSION"), mechs,
                     [bound("src/ssl/x.rs", "UNSAFE_FN_DEF", "f",
                            "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)")],
                     plane)["status"],
          "BLOCKED")
    # the range is checked against the current census coordinate, not a stale one
    stale_ob = adjudicate(ob("src/ssl/x.rs", 40, "SSL_SESSION", current=60),
                          mechs,
                          [bound("src/ssl/x.rs", "UNSAFE_FN_DEF", "f",
                                 "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)")],
                          plane)
    check("stale range does not discharge a drifted coordinate",
          (stale_ob["status"], bool(stale_ob.get("stale_discharge_rejections"))),
          ("BLOCKED", True))
    check("scoped range parser", scoped_ranges(
        "SAFETY_DISCHARGED (scope: src/ui/ui_openssl.rs:111-124, 269-290)"),
        {"src/ui/ui_openssl.rs": [(111, 124), (269, 290)]})

    # site receipts: only the declared kind is admitted, and it never discharges
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "good-sites.json").write_text(json.dumps({
            "kind": SITE_RECEIPT_KIND, "receipt": "good-sites",
            "boundaries": [{"id": "X-1", "file": "src/x.rs",
                            "mechanism": "EVP_PKEY_PROVIDER",
                            "disposition": "BLOCKED"}]}))
        (d / "other-sites.json").write_text(json.dumps({
            "kind": "something-else",
            "boundaries": [{"id": "Y-1", "file": "src/y.rs",
                            "mechanism": "EVP_PKEY_PROVIDER",
                            "disposition": "BLOCKED"}]}))
        bf, _ = load_boundaries(d)
        check("site receipt admitted", sorted(bf), ["src/x.rs"])
        check("site receipt alone is BLOCKED",
              adjudicate(ob("src/x.rs", 1, "EVP_PKEY_PROVIDER"), mechs,
                         bf["src/x.rs"], plane)["status"], "BLOCKED")

    # ---- negative control: an unclassified indirect site is broad ---------- #
    class _FakeG:
        name = "control.so"
        funcs = {0x10: "root", 0x20: "materialised", 0x30: "table_entry"}
        start_set = set(funcs)
        direct = {0x10: set()}
        taken_code = {0x20}
        taken_data = {0x30}
        address_taken_union = {0x20, 0x30}
        field_stores = {}
        static_offset_class = {}
        sites = {}

        def init_roots(self):
            return set()

    g = _FakeG()
    g.sites = {(0x10, 0x11, "call"): {
        "kind": "call", "func": 0x10, "addr": 0x11, "text": "call *%rax",
        "targets": set(), "unresolved": True, "reason": "unsupported-operand",
        "class": "unclassified"}}
    broad = build_graph({g.name: g}, {(g.name, 0x10)}, {})
    check("negative control unclassified admits global set",
          (g.name, 0x30) in broad["upper_reachable"], True)
    g.sites = {(0x10, 0x11, "call"): {
        "kind": "call", "func": 0x10, "addr": 0x11, "text": "call *%rax",
        "targets": set(), "unresolved": True, "reason": "reg-top",
        "class": "materialised"}}
    narrow = build_graph({g.name: g}, {(g.name, 0x10)}, {})
    check("materialised class admits address-of set",
          (g.name, 0x20) in narrow["upper_reachable"], True)
    # The monotone rule: a classified site is bounded by the class-independent
    # union, never by its class set alone.  v1.4 admitted only taken_code for a
    # non-unclassified site, so dropping from PROVED to UNRESOLVED could shrink
    # the reachable set.  The class is still recorded as precision metadata.
    check("a classified site is bounded by the class-independent union (monotone)",
          (g.name, 0x30) in narrow["upper_reachable"], True)
    check("the class remains available as precision metadata",
          g.sites[(0x10, 0x11, "call")]["class"], "materialised")

    # ---- least-fixed-point residual admission ----------------------------- #
    # root -> dispatch A (unresolved) -> B -> dispatch B (unresolved) -> C.
    # B has no direct predecessor: it is reached only through A's residual
    # admission, so a single pass never scans B's own unresolved site.
    class _NestedG:
        name = "nested.so"
        funcs = {0x10: "root", 0x20: "dispatch_a", 0x30: "b",
                 0x40: "dispatch_b", 0x50: "c"}
        start_set = set(funcs)
        direct = {0x10: {0x20}, 0x20: set(), 0x30: {0x40}, 0x40: set(),
                  0x50: set()}
        taken_code = set()
        taken_data = set()
        address_taken_union = set()
        field_stores = {}
        unknown_call_arg_targets = set()
        sites = {}

    def _nested_graph():
        g = _NestedG()
        g.sites = {
            (0x20, 0x21, "call"): {
                "kind": "call", "func": 0x20, "addr": 0x21,
                "text": "call *%rax", "targets": set(), "unresolved": True,
                "reason": "reg-top", "class": "materialised",
                "arg_targets": {0x30}},
            (0x40, 0x41, "call"): {
                "kind": "call", "func": 0x40, "addr": 0x41,
                "text": "call *%rax", "targets": set(), "unresolved": True,
                "reason": "reg-top", "class": "materialised",
                "arg_targets": {0x50}},
        }
        return g

    g = _nested_graph()
    one_pass = build_graph({g.name: g}, {(g.name, 0x10)}, {}, max_rounds=1)
    g = _nested_graph()
    fixpoint = build_graph({g.name: g}, {(g.name, 0x10)}, {})
    check("nested dispatch: B is not directly reachable",
          (g.name, 0x30) in fixpoint["direct_reachable"], False)
    check("nested dispatch: a one-pass closure omits C",
          (g.name, 0x50) in one_pass["upper_reachable"], False)
    check("nested dispatch: a one-pass closure does not converge",
          one_pass["converged"], False)
    check("nested dispatch: the fixpoint includes C",
          (g.name, 0x50) in fixpoint["upper_reachable"], True)
    check("nested dispatch: the fixpoint converges in three rounds",
          (fixpoint["converged"], fixpoint["closure_rounds"]), (True, 3))
    check("nested dispatch: round sizes record the growth",
          fixpoint["round_sizes"], [2, 4, 5, 5])
    check("nested dispatch: sites are scanned per round",
          fixpoint["sites_scanned_per_round"], [0, 1, 2, 2])

    nonconv = closure_refusals(one_pass)
    check("non-convergence produces CLOSURE_NONCONVERGENT",
          [r["code"] for r in nonconv], ["CLOSURE_NONCONVERGENT"])
    check("the non-convergence refusal names the round cap and growth",
          ("1 round" in nonconv[0]["detail"],
           "added 2 node" in nonconv[0]["detail"],
           one_pass["nonconvergent_detail"]["round_cap"]),
          (True, True, 1))
    check("a converged closure emits no refusal", closure_refusals(fixpoint), [])

    # ---- monotone per-site bound ------------------------------------------ #
    class _MonoG:
        name = "monotone.so"
        funcs = {0x10: "root", 0x20: "materialised_target",
                 0x30: "field_target", 0x40: "argument_target",
                 0x50: "got_target"}
        start_set = set(funcs)
        taken_code = {0x20}
        taken_data = {0x30}
        # 0x50 is admitted only by the dynamic-relocation widening (the real
        # CRYPTO_cbc128_encrypt shape): the old class-specific bound could not
        # contain it, so a PROVED->UNRESOLVED reclassification lost it.
        address_taken_union = {0x20, 0x30, 0x50}
        dynamic_reloc_targets = {0x50}
        field_stores = {0x20: {0x30}}
        unknown_call_arg_targets = {0x40}

    mono = _MonoG()
    proved_site = {"kind": "call", "func": 0x10, "addr": 0x11,
                   "text": "call *%rax", "targets": {0x20, 0x50},
                   "unresolved": False, "class": "PROVED_TARGET_SET",
                   "arg_targets": set()}
    proved_set = set(proved_site["targets"])
    residual_site = {**proved_site, "unresolved": True,
                     "class": "materialised", "targets": set()}
    bound = unresolved_site_bound(mono, residual_site)
    check("monotone bound contains the previously proved target set",
          proved_set <= bound, True)
    class_sets = {
        "taken_code": set(mono.taken_code),
        "taken_data": set(mono.taken_data),
        "address_taken_union": set(mono.address_taken_union),
        "dynamic_reloc_targets": set(mono.dynamic_reloc_targets),
        "field_stores": {v for vs in mono.field_stores.values() for v in vs},
        "unknown_call_arg_targets": set(mono.unknown_call_arg_targets),
        "site_targets": set(proved_site["targets"])
                        | set(proved_site["arg_targets"]),
    }
    check("monotone bound contains every class-specific set",
          {k: v <= bound for k, v in class_sets.items()},
          {k: True for k in class_sets})
    # The residual site's own targets are empty (the resolver lost them), so
    # the union -- not the site -- is what keeps 0x50 reachable.
    check("the residual bound survives losing the site's own targets",
          (residual_site["targets"], 0x50 in bound), (set(), True))

    # ---- admission by refutation ----------------------------------------- #
    # The exclusion was derived against the pre-closure direct set.  When the
    # sound bound reaches the excluded caller, the exclusion is false: the
    # caller's contribution is admitted and the closure recomputed.  A caller
    # the bound does not reach keeps its exclusion, and an admitted caller
    # whose contribution is not finite turns the site UNRESOLVED.
    class _AdmissionG:
        name = "admission-fixture.so"
        funcs = {0x10: "site_func", 0x20: "target_ok",
                 0x30: "excluded_caller", 0x40: "target_dropped",
                 0x50: "reachable_caller"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}
        taken_code = set()
        taken_data = set()
        address_taken_union = set()
        dynamic_reloc_targets = set()
        field_stores = {}
        unknown_call_arg_targets = set()
        slot_func_targets = set()
        sites = {}

        def __init__(self):
            self.direct = {0x10: {0x50}}

        def section_of(self, _a):
            return ".text"

        def containing(self, a):
            return max(x for x in self.funcs if x <= a)

        def static_slot(self, _a):
            return None

        def seam_symbol(self, _a):
            return None

        def cstring_at(self, _a):
            return None

        def is_data(self, _a):
            return False

    def _admission_fixture(*, reach_excluded, unbounded=False):
        g = _AdmissionG()
        if reach_excluded:
            g.direct = {0x10: {0x50, 0x30}}
        excluded_targets = [] if unbounded else ["0x40"]
        excluded_args = [{
            "argument_index": 0, "targets": list(excluded_targets),
            "non_image_values": ["<top>"] if unbounded else [],
            "unresolved": bool(unbounded), "witness_instruction": []}]
        arg_targets = {0x20} | ({0x40} if not unbounded else set())
        g.sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": {0x20},
            "unresolved": False, "class": "reachable-caller-target",
            "reason": "reachable-caller target bounding",
            "field_offsets": set(), "arg_deps": {0}, "arg_targets": arg_targets,
            "reachable_caller_bound": {
                "reachable_callers": [{
                    "function": "0x50", "symbol": "reachable_caller",
                    "reachable": True, "reason": None,
                    "call_sites": [{"call_site": "0x51", "arguments": [{
                        "argument": 0, "argument_index": 0,
                        "targets": ["0x20"], "non_image_values": [],
                        "unresolved": False, "witness_instruction": []}]}],
                    "contributed_targets": ["0x20"]}],
                "excluded_callers": [{
                    "function": "0x30", "symbol": "excluded_caller",
                    "reachable": False, "reason": "not in this family's "
                    "reachable set", "in_image_references": [],
                    "call_sites": [{"call_site": "0x31",
                                    "arguments": excluded_args}],
                    "contributed_targets": excluded_targets}],
                "bounded_targets": ["0x20"],
                "attributed_targets": [hex(a) for a in sorted(arg_targets)],
                "unattributed_targets": []}}}
        return g

    def _admission_run(g, *, admit=True):
        close = lambda: build_graph({g.name: g}, {(g.name, 0x10)}, {})
        if not admit:
            return close(), None
        return admission_fixpoint({g.name: g}, close)

    g1 = _admission_fixture(reach_excluded=True)
    closure1, report1 = _admission_run(g1)
    site1 = g1.sites[(0x10, 0x11, "call")]
    bound1 = site1["reachable_caller_bound"]
    oracle1 = ReachabilityOracle({g1.name: g1}, closure1["upper_reachable"])
    records1 = build_edge_records({g1.name: g1}, oracle1)
    check("a refuted exclusion admits the caller's target",
          (0x40 in site1["targets"],
           (g1.name, 0x40) in closure1["upper_reachable"]), (True, True))
    check("a refuted exclusion is removed and its caller is marked",
          (bound1["excluded_callers"],
           [r.get("admitted_by_refutation") for r in bound1["reachable_callers"]]),
          ([], [None, True]))
    check("admission reports its pass, role and targets",
          (report1["passes"],
           report1["refuted_exclusions"][ADMISSION_ROLE_CALLER],
           report1["admitted_by_refutation"]["count"],
           report1["admitted_by_refutation"]["targets"]),
          (1, 1, 1, ["target_dropped"]))
    check("the refutation-widened record validates against the sound bound",
          validate_edge_records(records1, oracle1), [])
    check("the refutation-widened record has no audit violation",
          [r for r in reachability_exclusion_audit(
              {g1.name: g1}, oracle1, records1) if r["violation"]], [])

    g2 = _admission_fixture(reach_excluded=False)
    closure2, report2 = _admission_run(g2)
    site2 = g2.sites[(0x10, 0x11, "call")]
    oracle2 = ReachabilityOracle({g2.name: g2}, closure2["upper_reachable"])
    records2 = build_edge_records({g2.name: g2}, oracle2)
    check("a caller the sound bound does not reach keeps its exclusion",
          (site2["targets"],
           len(site2["reachable_caller_bound"]["excluded_callers"]),
           report2["passes"]), ({0x20}, 1, 0))
    check("the surviving exclusion validates",
          validate_edge_records(records2, oracle2), [])

    g3 = _admission_fixture(reach_excluded=True, unbounded=True)
    closure3, report3 = _admission_run(g3)
    site3 = g3.sites[(0x10, 0x11, "call")]
    oracle3 = ReachabilityOracle({g3.name: g3}, closure3["upper_reachable"])
    records3 = build_edge_records({g3.name: g3}, oracle3)
    check("an admitted caller with no finite contribution is UNRESOLVED",
          (site3["unresolved"], "refutation-unbounded" in site3["reason"],
           site3["reachable_caller_bound"]["excluded_callers"]),
          (True, True, []))
    check("the refutation-unbounded record names its missing property",
          [(r["disposition"], bool(r["missing_property"]))
           for r in records3], [(DISPOSITION_UNRESOLVED, True)])
    check("the refutation-unbounded record validates",
          validate_edge_records(records3, oracle3), [])

    # ---- analysis identity is not the DSO digest --------------------------- #
    class _IdG:
        name = "identity.so"

        def __init__(self, dso_sha, rows=None, *, data_sha="d" * 64,
                     reloc_add=0x10, comment="c"):
            self.sha256 = dso_sha
            self._rows = rows or [["f", 0x10, 8, "T"], ["g", 0x20, 16, "T"]]
            self._data_sha = data_sha
            self._reloc_add = reloc_add
            self._comment = comment

        def text_digest(self):
            return "a" * 64, 4096

        def symbol_table_rows(self):
            return list(self._rows)

        def analysis_section_descriptors(self):
            return [
                {"name": ".text", "type": "PROGBITS", "addr": 0x1000,
                 "size": 4096, "sha256": "a" * 64},
                {"name": ".data.rel.ro", "type": "PROGBITS", "addr": 0x3000,
                 "size": 64, "sha256": self._data_sha},
            ]

        def analysis_excluded_sections(self):
            return [".comment", ".debug_info"]

        def canonical_relocations(self):
            return [[".data.rel.ro", 0x0, "R_X86_64_RELATIVE", None,
                     self._reloc_add]]

        def dynamic_symbol_rows(self):
            return [["f", 0x10, "T"], ["g", 0x20, "T"]]

        def dynamic_entries(self):
            return {"soname": "identity.so", "needed": ["libc.so.6"],
                    "runpath": [], "rpath": []}

    id_a = analysis_identity({"identity.so": _IdG("0" * 64)})
    id_b = analysis_identity({"identity.so": _IdG("f" * 64)})
    id_c = analysis_identity({"identity.so": _IdG(
        "0" * 64, [["f", 0x10, 8, "T"], ["g", 0x20, 24, "T"]])})
    id_data = analysis_identity({"identity.so": _IdG(
        "0" * 64, data_sha="e" * 64)})
    id_reloc = analysis_identity({"identity.so": _IdG(
        "0" * 64, reloc_add=0x20)})
    id_comment = analysis_identity({"identity.so": _IdG(
        "0" * 64, comment="z")})
    check("analysis identity is unchanged by a DSO digest change",
          (id_a["digest"] == id_b["digest"],
           id_a["modules"]["identity.so"]["dso_sha256"]
           != id_b["modules"]["identity.so"]["dso_sha256"]), (True, True))
    check("analysis identity changes with a symbol-table change",
          id_a["digest"] == id_c["digest"], False)
    check("analysis identity changes with a data-section byte change "
          "while .text and symbol rows stay identical",
          (id_a["modules"]["identity.so"]["sections"]
           != id_data["modules"]["identity.so"]["sections"],
           id_a["modules"]["identity.so"]["text_sha256"]
           == id_data["modules"]["identity.so"]["text_sha256"],
           id_a["modules"]["identity.so"]["symbol_table_sha256"]
           == id_data["modules"]["identity.so"]["symbol_table_sha256"],
           id_a["digest"] != id_data["digest"]), (True, True, True, True))
    check("analysis identity changes with a relocation addend change",
          (id_a["modules"]["identity.so"]["relocation_table_sha256"]
           != id_reloc["modules"]["identity.so"]["relocation_table_sha256"],
           id_a["digest"] != id_reloc["digest"]), (True, True))
    check("analysis identity ignores excluded metadata",
          id_a["digest"] == id_comment["digest"], True)
    check("the identity names the included and excluded inputs",
          (".text" in id_a["included_sections"]
           and ".data.rel.ro" in id_a["included_sections"]
           and ".debug_*" in id_a["excluded_classes"]
           and ".comment" in id_a["modules"]["identity.so"]["excluded_sections"]),
          True)
    check("the DSO digest is recorded as a non-identity",
          id_a["modules"]["identity.so"]["dso_sha256_is_analysis_identity"],
          False)
    check("compiler-generated hash suffixes are canonicalised",
          [canonical_symbol_name(n) for n in (
              "_RNvCs123_4core3fmt8_$LT$T$u20$as$u20$X$GT$.llvm.1a2b3c4d",
              "CRYPTO_cbc128_encrypt@@OPENSSL_3.0.0",
              "plain_symbol")],
          ["_RNvCs123_4core3fmt8_$LT$T$u20$as$u20$X$GT$.llvm.<hash>",
           "CRYPTO_cbc128_encrypt", "plain_symbol"])

    # The movement digest must be a function of the analysis identity, not of
    # the build directory: two neutral builds differ only in the .llvm.<hash>
    # suffix values, and the raw-name digest would report movement for a
    # comment-only edit.
    class _NameG:
        name = "names.so"

        def __init__(self, suffix):
            self.funcs = {0x10: f"local_fn.llvm.{suffix}",
                          0x20: "CRYPTO_export@@OPENSSL_3.0.0"}

    reach_a = {("names.so", 0x10), ("names.so", 0x20)}
    names_a = reachable_function_entries({"names.so": _NameG("111")}, reach_a)
    names_b = reachable_function_entries({"names.so": _NameG("222")}, reach_a)
    raw_a = reachable_function_entries({"names.so": _NameG("111")}, reach_a,
                                       canonical=False)
    raw_b = reachable_function_entries({"names.so": _NameG("222")}, reach_a,
                                       canonical=False)
    check("the reachable-function digest canonicalises build-dependent names",
          (names_a == names_b,
           reachable_functions_digest(names_a)
           == reachable_functions_digest(names_b),
           reachable_functions_digest(raw_a)
           != reachable_functions_digest(raw_b)),
          (True, True, True))

    # ---- symbolic-target dispositions (P0-B) ------------------------------ #
    # Every symbolic value in the bound gets exactly one disposition.  The
    # blocking case must refuse; an alias-resolved case must not; an
    # external-contract case must be recorded without a refusal; and disabling
    # the refusal must make the blocking case fail.
    class _SymbolG:
        name = "symbol-disposition.so"
        funcs = {0x10: "root", 0x20: "alias_target", 0x30: "dyn_target",
                 0x40: "plt_stub"}
        start_set = set(funcs)
        direct = {}
        taken_code = set()
        taken_data = set()
        field_stores = {}
        unknown_call_arg_targets = set()
        dynamic_reloc_targets = set()
        slot_syms = {0x2000: {"plt_target"}}
        names_at = {0x20: {"alias_target"}}
        dynamic_defs = {"dyn_target": 0x30}
        functions = [(0x40, [(0x40, "jmp *0x1000(%rip) # 2000 <plt_target@plt>")])]
        sections = {".text": (0x0, 0, 0x100), ".plt": (0x40, 0, 0x10)}

        def __init__(self, symbol):
            self.address_taken_union = {("sym", symbol)}
            self.sites = {(0x10, 0x11, "call"): {
                "kind": "call", "func": 0x10, "addr": 0x11,
                "text": "call *%rax", "targets": set(), "unresolved": True,
                "reason": "test", "class": "unclassified",
                "arg_targets": set()}}

        def section_of(self, addr):
            if addr == 0x40:
                return ".plt"
            return ".text" if 0 <= addr < 0x100 else None

        def containing(self, addr):
            base = [a for a in sorted(self.start_set) if a <= addr]
            return base[-1] if base else None

    def _symbol_closure(symbol, export_index=None):
        g = _SymbolG(symbol)
        closure = build_graph({g.name: g}, {(g.name, 0x10)},
                              export_index or {})
        return closure, g

    blocking_closure, _ = _symbol_closure("no_such_symbol")
    blocking_rows = [r for r in blocking_closure["symbol_dispositions"]
                     if r["symbol"] == "no_such_symbol"]
    check("an unresolved symbol gets a blocking disposition",
          [(r["disposition"], r["path"]) for r in blocking_rows],
          [("blocking", None)])
    blocking_refusals = closure_refusals(blocking_closure)
    check("an unresolved symbol produces CLOSURE_UNRESOLVED_SYMBOL",
          [(r["code"], [s["symbol"] for s in r.get("symbols", [])])
           for r in blocking_refusals],
          [("CLOSURE_UNRESOLVED_SYMBOL", ["no_such_symbol"])])

    alias_closure, _ = _symbol_closure("alias_target")
    alias_rows = [r for r in alias_closure["symbol_dispositions"]
                  if r["symbol"] == "alias_target"]
    check("a names-at alias resolves and is not a refusal",
          ([(r["disposition"], r["path"]) for r in alias_rows],
           [a for _m, a in alias_rows[0]["targets"]],
           closure_refusals(alias_closure)),
          ([("resolved", "names-at")], [0x20], []))

    dyn_closure, _ = _symbol_closure("dyn_target")
    dyn_rows = [r for r in dyn_closure["symbol_dispositions"]
                if r["symbol"] == "dyn_target"]
    check("a dynamic-symbol-table target resolves",
          [(r["disposition"], r["path"]) for r in dyn_rows],
          [("resolved", "dynamic-symbol-table")])

    plt_closure, _ = _symbol_closure("plt_target")
    plt_rows = [r for r in plt_closure["symbol_dispositions"]
                if r["symbol"] == "plt_target"]
    check("a PLT-stub target resolves",
          [(r["disposition"], r["path"], r["targets"]) for r in plt_rows],
          [("resolved", "plt-stub", [["symbol-disposition.so", 0x40]])])

    export_closure, _ = _symbol_closure(
        "versioned_fn@@V", {"versioned_fn": ("symbol-disposition.so", 0x30)})
    export_rows = [r for r in export_closure["symbol_dispositions"]
                   if r["symbol"] == "versioned_fn@@V"]
    check("a version-stripped export resolves",
          [(r["disposition"], r["path"]) for r in export_rows],
          [("resolved", "version-stripped-export")])

    qual_closure, _ = _symbol_closure(
        "symbol-disposition.so:qualified_fn",
        {"qualified_fn": ("symbol-disposition.so", 0x30)})
    qual_rows = [r for r in qual_closure["symbol_dispositions"]
                 if r["symbol"].endswith("qualified_fn")]
    check("a SONAME-qualified import resolves",
          [(r["disposition"], r["path"]) for r in qual_rows],
          [("resolved", "soname-qualified-import")])

    external_closure, _ = _symbol_closure("malloc")
    external_rows = [r for r in external_closure["symbol_dispositions"]
                     if r["symbol"] == "malloc"]
    check("an external-contract symbol is recorded without a refusal",
          ([(r["disposition"], bool(r["external_interface"])) for r in external_rows],
           closure_refusals(external_closure)),
          ([("external-contract", True)], []))

    _orig_symbol_refusals = globals()["closure_refusals"]

    def _drop_symbol_refusal(closure):
        return [r for r in _orig_symbol_refusals(closure)
                if r["code"] != "CLOSURE_UNRESOLVED_SYMBOL"]

    globals()["closure_refusals"] = _drop_symbol_refusal
    try:
        symbol_refusal_disabled_fails = not any(
            r["code"] == "CLOSURE_UNRESOLVED_SYMBOL"
            for r in closure_refusals(blocking_closure))
    finally:
        globals()["closure_refusals"] = _orig_symbol_refusals

    # ---- mutation controls ------------------------------------------------- #
    # Each mutation disables exactly one mechanism; the named case must then
    # fail.  A PASS here is evidence that the case is sensitive to the
    # mechanism, not that the mechanism is complete.
    def _nested_reaches_c(max_rounds=None):
        g = _nested_graph()
        res = build_graph({g.name: g}, {(g.name, 0x10)}, {},
                          max_rounds=max_rounds)
        return (g.name, 0x50) in res["upper_reachable"]

    def _narrow_bound_by_class(g, site):
        if site.get("class") == "unclassified":
            return set(getattr(g, "address_taken_union", ()) or ())
        return (set(getattr(g, "taken_code", ()) or ())
                | set(site.get("targets") or ()))

    _orig_bound = globals()["unresolved_site_bound"]
    globals()["unresolved_site_bound"] = _narrow_bound_by_class
    try:
        narrowed = unresolved_site_bound(mono, residual_site)
    finally:
        globals()["unresolved_site_bound"] = _orig_bound

    _orig_refusals = globals()["closure_refusals"]
    globals()["closure_refusals"] = lambda _closure: []
    try:
        no_refusal = closure_refusals(one_pass)
    finally:
        globals()["closure_refusals"] = _orig_refusals

    # Admission mutations.  Disabling admission must make the refuted case
    # fail (the target is not admitted and the record refuses); admitting
    # unconditionally must make the surviving-exclusion case fail (the caller
    # is moved even though the bound does not reach it, and the validator
    # refuses the false positive claim).
    g4 = _admission_fixture(reach_excluded=True)
    closure4, _report4 = _admission_run(g4, admit=False)
    site4 = g4.sites[(0x10, 0x11, "call")]
    oracle4 = ReachabilityOracle({g4.name: g4}, closure4["upper_reachable"])
    records4 = build_edge_records({g4.name: g4}, oracle4)
    admission_disabled_fails = (
        0x40 not in site4["targets"]
        and bool(site4["reachable_caller_bound"]["excluded_callers"])
        and bool(validate_edge_records(records4, oracle4)))

    g5 = _admission_fixture(reach_excluded=False)
    site5 = g5.sites[(0x10, 0x11, "call")]
    bound5 = site5["reachable_caller_bound"]
    moved = bound5["excluded_callers"].pop()
    moved["admitted_by_refutation"] = True
    bound5["reachable_callers"].append(moved)
    site5["targets"] |= {0x40}
    closure5 = build_graph({g5.name: g5}, {(g5.name, 0x10)}, {})
    oracle5 = ReachabilityOracle({g5.name: g5}, closure5["upper_reachable"])
    records5 = build_edge_records({g5.name: g5}, oracle5)
    unconditional_admission_fails = (
        not bound5["excluded_callers"]
        and bool(validate_edge_records(records5, oracle5)))

    mutation_matrix = [
        {"mutation": "single-pass closure (no iteration)",
         "case": "fixpoint-reaches-nested-unresolved",
         "case_fails": not _nested_reaches_c(max_rounds=1),
         "expected": True},
        {"mutation": "class-narrowed bound",
         "case": "monotone-bound-under-classification-loss",
         "case_fails": not (proved_set <= narrowed),
         "expected": True},
        {"mutation": "non-convergence refusal removed",
         "case": "closure-nonconvergent-refusal",
         "case_fails": no_refusal == [],
         "expected": True},
        {"mutation": "refutation admission disabled",
         "case": "admission-refuted-caller",
         "case_fails": admission_disabled_fails,
         "expected": True},
        {"mutation": "unconditional admission (no bound check)",
         "case": "admission-surviving-caller",
         "case_fails": unconditional_admission_fails,
         "expected": True},
        {"mutation": "CLOSURE_UNRESOLVED_SYMBOL refusal removed",
         "case": "unresolved-symbol-refusal",
         "case_fails": symbol_refusal_disabled_fails,
         "expected": True},
    ]
    check("mutation matrix: every mutation flips its named case",
          [(row["case"], row["case_fails"] == row["expected"])
           for row in mutation_matrix],
          [(row["case"], True) for row in mutation_matrix])
    print("[consumer-closure] mutation matrix: " + "; ".join(
        f"{r['mutation']} -> {r['case']} "
        f"{'fails as required' if r['case_fails'] else 'STILL PASSES'}"
        for r in mutation_matrix))

    # ---- source-backed witnesses: S2/S3/S4 (AGENTS.md section 22) ---------- #
    class _WPrecision:
        def __init__(self, insns):
            self.insns_by_func = insns

    class _WG:
        def __init__(self, insns, funcs, dyn=(), source_root=None, install=None):
            self.name = "witness.so"
            self.funcs = dict(funcs)
            self.start_set = set(funcs)
            self.names_at = {a: {n} for a, n in funcs.items()}
            self.dynamic_defs = {n: a for a, n in funcs.items() if n in dyn}
            self.all_syms = dict(funcs)
            self.precision = _WPrecision({f: list(v) for f, v in insns.items()})
            self.source_root = source_root
            self.install_prefix = install
            self.sites = {}

        def containing(self, addr):
            best = None
            for f in self.start_set:
                if f <= addr and (best is None or f > best):
                    best = f
            return best

    def _wrepo(td, text):
        root = Path(td)
        p = root / "src" / "evp"
        p.mkdir(parents=True, exist_ok=True)
        (p / "kdf.rs").write_text(text)
        return root

    def _winstall(td, header):
        root = Path(td)
        p = root / "include" / "openssl"
        p.mkdir(parents=True, exist_ok=True)
        (p / "modes.h").write_text(header)
        return root

    # S3: a fetched EvpKdf slot.  The base is the inner_evp_generic_fetch
    # return, the offset is gettable_ctx_params, and the source assigns it once
    # in evp_kdf_from_algorithm.
    def _fetch_fixture(off=0x58, base_call=True, two_assign=False):
        td = tempfile.mkdtemp()
        src = ("fn evp_kdf_from_algorithm() {\n"
               "    (*kdf).gettable_ctx_params = entry_function(fns);\n"
               "    (*kdf).settable_ctx_params = entry_function(fns);\n"
               "    (*kdf).forced_field = 1;\n"
               "}\n")
        if two_assign:
            src += ("fn other() {\n    (*kdf).gettable_ctx_params = x;\n}\n")
        repo = _wrepo(td, src)
        insns = {0x100: [
            (0x100, "lea    0x200(%rip),%r9        # 300 <evp_kdf_from_algorithm>"),
            (0x105, "mov    %r9,0x30(%rsp)"),
            (0x10a, "mov    %rsp,%rdi"),
            (0x10f, "call   200 <inner_evp_generic_fetch>" if base_call
                    else "mov    %rdi,%rax"),
            (0x114, "mov    %rax,%rbx"),
            (0x119, "test   %rbx,%rbx"),
            (0x11c, "je     130 <target+0x30>"),
            (0x120, f"mov    {hex(off)}(%rbx),%rax"),
            (0x125, "test   %rax,%rax"),
            (0x128, "je     130 <target+0x30>"),
            (0x12a, "call   *%rax"),
            (0x130, "ret"),
        ]}
        funcs = {0x100: "target", 0x200: "...inner_evp_generic_fetch",
                 0x300: "...evp_kdf_from_algorithm", 0x400: "unused"}
        g = _WG(insns, funcs, source_root=repo)
        site = {"kind": "call", "func": 0x100, "addr": 0x12A,
                "text": "call   *%rax", "arg_deps": set()}
        return g, site

    def _fetch_witness(off=0x58, base_call=True, two_assign=False):
        g, site = _fetch_fixture(off, base_call, two_assign)
        return fetch_slot_witness(g, site, "target")

    w = _fetch_witness()
    check("S3 fetch-slot witness applies", w is not None, True)
    check("S3 fetch-slot names the OSSL_FUNC id",
          (w or {}).get("slot"),
          "EvpKdf.gettable_ctx_params (offset 0x58, "
          "OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS)")
    check("S3 fetch-slot records the family and fetch call",
          ((w or {}).get("fetch") or {}).get("method_family"), "EVP_KDF")
    check("S3 base not a fetch return is refused",
          _fetch_witness(base_call=False), None)
    check("S3 offset outside the declared fields is refused",
          _fetch_witness(off=0x100), None)
    check("S3 two source assignments are refused",
          _fetch_witness(two_assign=True), None)

    # S2: an exported function's callback parameter.
    def _export_fixture(param=True, noncb=False, exported=True):
        td = tempfile.mkdtemp()
        header = ("typedef void (*block128_f)(const unsigned char in[16],\n"
                  "    unsigned char out[16], const void *key);\n"
                  "void CRYPTO_cfb128_encrypt(const unsigned char *in,\n"
                  "    unsigned char *out, size_t len, "
                  + ("int block" if noncb else "block128_f block") + ");\n")
        install = _winstall(td, header)
        insns = {0x500: [
            (0x500, "push   %rbp"),
            (0x501, "mov    %rdi,%rax"),
            (0x504, "mov    %rcx,%r11" if param else "mov    $0x123,%rcx"),
            (0x507, "call   *%rcx"),
            (0x509, "ret"),
        ]}
        funcs = {0x500: "CRYPTO_cfb128_encrypt", 0x600: "unused"}
        dyn = {"CRYPTO_cfb128_encrypt"} if exported else set()
        g = _WG(insns, funcs, dyn=dyn, install=install)
        site = {"kind": "call", "func": 0x500, "addr": 0x507,
                "text": "call   *%rcx", "arg_deps": set()}
        return g, site

    def _export_witness(param=True, noncb=False, exported=True):
        g, site = _export_fixture(param, noncb, exported)
        return export_callback_witness(g, site, "CRYPTO_cfb128_encrypt")

    w, why = _export_witness()
    check("S2 export-callback witness applies", w is not None, True)
    check("S2 export-callback records the header declaration",
          (w or {}).get("parameter", {}).get("declaration"), "modes.h:3")
    check("S2 export-callback records the typedef",
          (w or {}).get("parameter", {}).get("type_typedef"), "block128_f")
    check("S2 value not exactly the parameter is refused",
          _export_witness(param=False)[0], None)
    check("S2 header declaring a non-callback is refused",
          _export_witness(noncb=True)[0], None)
    w2, why2 = _export_witness(exported=False)
    check("S2 finite in-image private chain is deferred",
          (w2, (why2 or {}).get("defer")), (None, True))

    # S4: a local closure built from a finite assignment set.
    def _local_fixture(partial=False, extra=False):
        callee = [(0x700, "mov    (%rcx),%r13"),
                  (0x703, "call   *0x0(%r13)"),
                  (0x705, "ret")]
        caller = [
            (0x800, "push   %rbp"),
            (0x801, "sub    $0x20,%rsp"),
            (0x805, "cmp    $0x0,%rdi"),
            (0x809, "je     818 <caller+0x18>"),
            (0x80b, "lea    0x100(%rip),%rax        # 900 <fnA>"),
            (0x810, "mov    %rax,0x18(%rsp)"),
            (0x815, "jmp    820 <caller+0x20>"),
            (0x818, "lea    0x108(%rip),%rax        # 910 <fnB>"),
            (0x81d, "mov    %rax,0x18(%rsp)"),
            (0x820, "lea    0x18(%rsp),%rax"),
            (0x825, "mov    %rax,0x8(%rsp)"),
            (0x82a, "lea    0x8(%rsp),%rcx"),
            (0x82f, "call   700 <traverse>"),
            (0x834, "ret"),
        ]
        if partial:
            caller[9] = (0x818, "mov    %rdi,%rax")
            caller[10] = (0x81d, "jmp    820 <caller+0x20>")
        if extra:
            caller[7] = (0x818, "mov    %rdi,%rax")
        funcs = {0x700: "traverse", 0x800: "caller", 0x900: "fnA",
                 0x910: "fnB"}
        g = _WG({0x700: callee, 0x800: caller}, funcs)
        site = {"kind": "call", "func": 0x700, "addr": 0x703,
                "text": "call   *0x0(%r13)", "arg_deps": set()}
        return g, site

    def _local_witness(partial=False, extra=False):
        g, site = _local_fixture(partial, extra)
        return local_fptr_witness(g, site, "traverse")

    lw = _local_witness()
    check("S4 local-fptr witness applies", lw is not None, True)
    check("S4 local-fptr records the finite target set",
          (lw or {}).get("targets"), ["0x900", "0x910"])
    check("S4 a path with no store is refused",
          _local_witness(partial=True), None)
    check("S4 a non-function store is refused",
          _local_witness(extra=True), None)

    # S1: field-sensitive static-table instance dispatch.
    def _s1_source(nullable=False, cast=False, cast_missing=False,
                   prefix=False, prefix_nonbase=False, prefix_layout=False,
                   prefix_cast=False, different_object=False,
                   unknown_base=False, fourth=False):
        cipher = ("unsafe extern \"C\" fn(*mut Wctx) -> c_int"
                  if not nullable else
                  "Option<unsafe extern \"C\" fn(*mut Wctx) -> c_int>")
        fn = "unsafe extern \"C\" fn(*mut Wctx) -> c_int"
        tail = ""
        if different_object:
            tail += (
                "#[repr(C)]\n"
                "pub(crate) struct WOther {\n"
                "    pub tag: usize,\n"
                "    pub slot: usize,\n"
                "}\n"
                "unsafe fn other_dup(p: *mut WOther, value: usize) {\n"
                "    (*p).slot = value;\n"
                "}\n")
        if unknown_base:
            tail += (
                "unsafe fn unknown_store(\n"
                "    p: *mut c_void,\n"
                "    value: usize,\n"
                ") -> *mut c_void {\n"
                "    let f: unsafe extern \"C\" fn(*mut c_void) -> *mut c_void\n"
                "        = core::mem::transmute(p);\n"
                "    f(value as *mut c_void)\n"
                "}\n")
        if prefix or prefix_nonbase or prefix_layout or prefix_cast:
            if prefix_nonbase:
                rows = (
                    "#[repr(C)]\n"
                    "pub(crate) struct WBase {\n"
                    f"    pub init: {fn},\n"
                    f"    pub cipher: {fn},\n"
                    f"    pub fini: {fn},\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WRow {\n"
                    "    pub tag: u64,\n"
                    f"    pub cipher: {fn},\n"
                    f"    pub fini: {fn},\n"
                    "}\n")
                inits = [f"WRow {{ tag: {k}, cipher: f{k}, fini: g{k} }}"
                         for k in range(3)]
            elif prefix_layout:
                rows = (
                    "#[repr(C)]\n"
                    "pub(crate) struct WBase {\n"
                    f"    pub init: {fn},\n"
                    f"    pub cipher: {fn},\n"
                    f"    pub fini: {fn},\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WBadBase {\n"
                    f"    pub init: {fn},\n"
                    f"    pub cipher: {fn},\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WRow {\n"
                    "    pub base: WBadBase,\n"
                    f"    pub fini: {fn},\n"
                    "}\n")
                inits = [f"WRow {{ base: WBadBase {{ init: f{k}, "
                         f"cipher: g{k} }}, fini: h{k} }}" for k in range(3)]
            elif prefix_cast:
                rows = (
                    "#[repr(C)]\n"
                    "pub(crate) struct WBase {\n"
                    f"    pub init: {fn},\n"
                    f"    pub cipher: {fn},\n"
                    f"    pub fini: {fn},\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WPrefix {\n"
                    f"    pub init: {fn},\n"
                    "    pub cipher: Option<unsafe extern \"C\" "
                    "fn(*mut Wctx) -> c_int>,\n"
                    "    pub fini: Option<unsafe extern \"C\" "
                    "fn(*mut Wctx) -> c_int>,\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WRow {\n"
                    "    pub base: WPrefix,\n"
                    f"    pub extra: {fn},\n"
                    "}\n")
                inits = [f"WRow {{ base: WPrefix {{ init: f{k}, "
                         f"cipher: Some(g{k}), fini: Some(h{k}) }}, "
                         f"extra: f{k} }}" for k in range(3)]
            else:
                rows = (
                    "#[repr(C)]\n"
                    "pub(crate) struct WBase {\n"
                    f"    pub init: {fn},\n"
                    f"    pub cipher: {fn},\n"
                    f"    pub fini: {fn},\n"
                    "}\n"
                    "#[repr(C)]\n"
                    "pub(crate) struct WRow {\n"
                    "    pub base: WBase,\n"
                    f"    pub extra: {fn},\n"
                    "}\n")
                inits = [f"WRow {{ base: WBase {{ init: f{k}, "
                         f"cipher: g{k}, fini: h{k} }}, extra: f{k} }}"
                         for k in range(3)]
            body = (
                rows
                + "#[repr(C)]\n"
                "pub(crate) struct Wctx {\n"
                "    pub flags: c_uint,\n"
                "    pub hw: *const WBase,\n"
                "}\n"
                + "".join(f"static TBL_{n}: WRow = {v};\n"
                          for n, v in zip("ABC", inits))
                + "unsafe fn site(ctx: *mut Wctx, out: *mut c_uchar) -> c_int {\n"
                "    let hw = (*ctx).hw;\n"
                "    ((*hw).cipher)(ctx, out)\n"
                "}\n")
            writers = "".join(
                f"unsafe fn newctx_{n.lower()}(provctx: *mut c_void) "
                "-> *mut c_void {\n"
                "    let owner = OwnedCtx::<Wctx>::new();\n"
                "    let ctx = owner.as_ptr();\n"
                "    (*ctx).hw = core::ptr::addr_of!(TBL_" + n
                + ").cast::<WBase>();\n"
                "    owner.into_raw().cast()\n"
                "}\n" for n in "ABC")
            return body + writers + tail
        # The exact and via-cast fixtures.
        if cast or cast_missing:
            target = "WMissing" if cast_missing else "WTable"
            body = (
                "#[repr(C)]\n"
                "pub(crate) struct WBase {\n"
                "    pub init: unsafe extern \"C\" fn(*mut Wctx) -> c_int,\n"
                "}\n"
                "#[repr(C)]\n"
                "pub(crate) struct WTable {\n"
                "    pub base: WBase,\n"
                f"    pub cipher: {cipher},\n"
                "    pub fini: unsafe extern \"C\" fn(*mut Wctx) -> c_int,\n"
                "}\n"
                "#[repr(C)]\n"
                "pub(crate) struct Wctx {\n"
                "    pub flags: c_uint,\n"
                "    pub hw: *const WBase,\n"
                "}\n"
                "static TBL_A: WTable = WTable { base: WBase { init: f0 }, "
                "cipher: f1, fini: f2 };\n"
                "static TBL_B: WTable = WTable { base: WBase { init: g0 }, "
                "cipher: g1, fini: g2 };\n"
                "static TBL_C: WTable = WTable { base: WBase { init: h0 }, "
                "cipher: h1, fini: h2 };\n"
                "unsafe fn site(ctx: *mut Wctx, out: *mut c_uchar) -> c_int {\n"
                f"    let hw = (*ctx).hw.cast::<{target}>();\n"
                "    ((*hw).cipher)(ctx, out)\n"
                "}\n")
        else:
            body = (
                "#[repr(C)]\n"
                "pub(crate) struct WTable {\n"
                "    pub init: unsafe extern \"C\" fn(*mut Wctx) -> c_int,\n"
                f"    pub cipher: {cipher},\n"
                "    pub fini: unsafe extern \"C\" fn(*mut Wctx) -> c_int,\n"
                "}\n"
                "#[repr(C)]\n"
                "pub(crate) struct Wctx {\n"
                "    pub flags: c_uint,\n"
                "    pub hw: *const WTable,\n"
                "}\n"
                "static TBL_A: WTable = WTable { init: f0, cipher: f1, fini: f2 };\n"
                "static TBL_B: WTable = WTable { init: g0, cipher: g1, fini: g2 };\n"
                "static TBL_C: WTable = WTable { init: h0, cipher: h1, fini: h2 };\n"
                + ("static TBL_D: WTable = WTable { init: i0, cipher: i1, "
                   "fini: i2 };\n" if fourth else "")
                + "unsafe fn site(ctx: *mut Wctx, out: *mut c_uchar) -> c_int {\n"
                "    let hw = (*ctx).hw;\n"
                "    ((*hw).cipher)(ctx, out)\n"
                "}\n")
        writers = "".join(
            f"unsafe fn newctx_{n.lower()}(provctx: *mut c_void) "
            "-> *mut c_void {\n"
            "    let owner = OwnedCtx::<Wctx>::new();\n"
            "    let ctx = owner.as_ptr();\n"
            "    (*ctx).hw = &TBL_" + n + ";\n"
            "    owner.into_raw().cast()\n"
            "}\n" for n in ("ABCD" if fourth else "ABC"))
        return body + writers + tail

    class _S1G:
        def __init__(self, insns, funcs, data_syms, sizes, static_values,
                     u32, sections, direct=None, source_root=None):
            self.name = "s1.so"
            self.funcs = dict(funcs)
            self.start_set = set(funcs)
            self.names_at = collections.defaultdict(set)
            for a, n in funcs.items():
                self.names_at[a].add(n)
            for a, n in data_syms.items():
                self.names_at[a].add(n)
            self.all_syms = {a: sorted(ns)[0]
                             for a, ns in self.names_at.items()}
            self.sym_sizes = dict(sizes)
            self.sections = dict(sections)
            self.precision = _WPrecision({f: list(v) for f, v in insns.items()})
            self.source_root = source_root
            self.install_prefix = None
            self.direct = collections.defaultdict(set, direct or {})
            self._static_values = dict(static_values)
            self._u32 = dict(u32)
            self.sites = {}

        def section_of(self, a):
            for name, (base, _off, size) in self.sections.items():
                if base <= a < base + size:
                    return name
            return None

        def is_data(self, a):
            sec = self.section_of(a)
            return sec is not None and sec not in (".text", ".plt", ".plt.got")

        def containing(self, a):
            best = None
            for f in self.start_set:
                if f <= a and (best is None or f > best):
                    best = f
            return best

        def static_slot(self, a):
            return frozenset(self._static_values.get(a, {0}))

        def read_u32(self, a):
            return self._u32.get(a)

    S1_SITE, S1_NEW_A, S1_NEW_B, S1_NEW_C = 0x1000, 0x1100, 0x1200, 0x1240
    S1_NEW_D = 0x1360
    S1_ZALLOC, S1_ROGUE = 0x1500, 0x1300
    S1_OTHER, S1_UNKNOWN = 0x1280, 0x12c0
    S1_TBL = {0x3000: "A", 0x3100: "B", 0x3200: "C"}
    S1_MEM = {0x3000: (0x2000, 0x2010, 0x2020),
              0x3100: (0x2100, 0x2110, 0x2120),
              0x3200: (0x2200, 0x2210, 0x2220)}
    S1_TBL_D = {0x3300: "D"}
    S1_MEM_D = (0x2300, 0x2310, 0x2320)
    S1_FUNCS = {0x3400: "FUNCS_A", 0x3440: "FUNCS_B", 0x3480: "FUNCS_C"}
    S1_FUNCS_D = {0x34c0: "FUNCS_D"}

    def _s1_sym(letter):
        return ("_RNvNtNtCs3iYjyFzWfzV_10openssl_rs8provider10cipher_gcm5TBL_"
                + letter)

    def _s1_fixture(nullable=False, shape="memory", undeclared=False,
                    bad_member=False, mutable=False, shape_extra=False,
                    rogue=False, third_store=True, guard=True,
                    null_member=False, cast=False, cast_missing=False,
                    prefix=False, prefix_nonbase=False, prefix_layout=False,
                    prefix_cast=False, different_object=False,
                    unknown_base=False, fourth=False):
        td = tempfile.mkdtemp()
        repo = Path(td)
        path = repo / "src" / "provider" / "cipher_gcm.rs"
        path.parent.mkdir(parents=True)
        path.write_text(_s1_source(
            nullable, cast, cast_missing, prefix=prefix,
            prefix_nonbase=prefix_nonbase, prefix_layout=prefix_layout,
            prefix_cast=prefix_cast, different_object=different_object,
            unknown_base=unknown_base, fourth=fourth))
        funcs = {
            S1_SITE: "_RNvNtNtCs3iYjyFzWfzV_10openssl_rs8provider10cipher_gcm4site",
            S1_NEW_A: "newctx_a", S1_NEW_B: "newctx_b",
            S1_NEW_C: "newctx_c", S1_ZALLOC: "zalloc",
        }
        if fourth:
            funcs[S1_NEW_D] = "newctx_d"
        for base in ((0x2000, 0x2100, 0x2200, 0x2300) if fourth
                     else (0x2000, 0x2100, 0x2200)):
            for k in range(3):
                funcs[base + k * 0x10] = f"member_{base:x}_{k}"
        if rogue:
            funcs[S1_ROGUE] = "rogue"
        if different_object:
            funcs[S1_OTHER] = "other_dup"
        if unknown_base:
            funcs[S1_UNKNOWN] = "unknown_store"
        insns = {}
        if shape == "memory":
            insns[S1_SITE] = [(0x1000, "mov    0x8(%rdi),%r8"),
                              (0x1004, "call   *0x8(%r8)"),
                              (0x1008, "ret")]
        elif shape == "register":
            insns[S1_SITE] = [(0x1000, "mov    0x8(%rdi),%r8"),
                              (0x1004, "mov    0x8(%r8),%rax")]
            if guard:
                insns[S1_SITE] += [(0x1008, "test   %rax,%rax"),
                                   (0x100a, "je     1010 <site+0x10>")]
            insns[S1_SITE] += [(0x100c if guard else 0x1008,
                                "call   *%rax"),
                               (0x1010 if guard else 0x100c, "ret")]
        elif shape == "copy":
            insns[S1_SITE] = [(0x1000, "mov    %rdi,%r14"),
                              (0x1004, "mov    0x8(%r14),%r8"),
                              (0x1008, "call   *0x8(%r8)"),
                              (0x100c, "ret")]
        elif shape == "copy-rogue":
            insns[S1_SITE] = [(0x1000, "mov    %rsi,%r14"),
                              (0x1004, "mov    0x8(%r14),%r8"),
                              (0x1008, "call   *0x8(%r8)"),
                              (0x100c, "ret")]
        elif shape in ("copy-multi", "copy-multi-rogue"):
            second = ("mov    %rsi,%r14"
                      if shape == "copy-multi-rogue" else "mov    %rdi,%r14")
            insns[S1_SITE] = [(0x1000, "test   %rdi,%rdi"),
                              (0x1004, "je     1010 <site+0x10>"),
                              (0x1006, "mov    %rdi,%r14"),
                              (0x100a, "jmp    1014 <site+0x14>"),
                              (0x1010, second),
                              (0x1014, "mov    0x8(%r14),%r8"),
                              (0x1018, "call   *0x8(%r8)"),
                              (0x101c, "ret")]
        elif shape == "spill":
            insns[S1_SITE] = [(0x1000, "mov    %rdi,0x10(%rsp)"),
                              (0x1004, "mov    0x10(%rsp),%r14"),
                              (0x1008, "mov    0x8(%r14),%r8"),
                              (0x100c, "call   *0x8(%r8)"),
                              (0x1010, "ret")]
        elif shape == "spill-rogue":
            insns[S1_SITE] = [(0x1000, "mov    %rdi,0x10(%rsp)"),
                              (0x1004, "mov    %rsi,0x10(%rsp)"),
                              (0x1008, "mov    0x10(%rsp),%r14"),
                              (0x100c, "mov    0x8(%r14),%r8"),
                              (0x1010, "call   *0x8(%r8)"),
                              (0x1014, "ret")]
        elif shape in ("spill-multi", "spill-multi-rogue"):
            second = ("mov    %rsi,0x10(%rsp)"
                      if shape == "spill-multi-rogue"
                      else "mov    %rdi,0x10(%rsp)")
            insns[S1_SITE] = [(0x1000, "test   %rdi,%rdi"),
                              (0x1004, "je     1010 <site+0x10>"),
                              (0x1006, "mov    %rdi,0x10(%rsp)"),
                              (0x100a, "jmp    1014 <site+0x14>"),
                              (0x1010, second),
                              (0x1014, "mov    0x10(%rsp),%r14"),
                              (0x1018, "mov    0x8(%r14),%r8"),
                              (0x101c, "call   *0x8(%r8)"),
                              (0x1020, "ret")]
        else:
            insns[S1_SITE] = [(0x1000, "call   *0x8(%rdi)"),
                              (0x1004, "ret")]
        site_addr = next(a for a, t in insns[S1_SITE] if "call" in t)

        def newctx(addr, table_addr, extra=None):
            rows = [(addr, "mov    $0x40,%edi"),
                    (addr + 5, "call   1500 <zalloc>"),
                    (addr + 10, "mov    %rax,%rbx"),
                    (addr + 15,
                     f"lea    0x0(%rip),%rcx        # {table_addr:x} <table>"),
                    (addr + 22, "mov    %rcx,0x8(%rbx)")]
            if extra is not None:
                rows += [(addr + 26,
                          f"lea    0x0(%rip),%rdx        # {extra:x} <anon>"),
                         (addr + 33, "mov    %rdx,0x8(%rbx)")]
            rows += [(addr + 40, "ret")]
            return rows

        tbl_a = 0x5000 if mutable else 0x3000
        insns[S1_NEW_A] = newctx(S1_NEW_A, tbl_a,
                                 0x3f00 if undeclared else None)
        insns[S1_NEW_B] = newctx(S1_NEW_B, 0x3100)
        insns[S1_NEW_C] = (newctx(S1_NEW_C, 0x3200) if third_store
                           else [(S1_NEW_C, "ret")])
        if fourth:
            insns[S1_NEW_D] = newctx(S1_NEW_D, 0x3300)
        if rogue:
            insns[S1_ROGUE] = [(0x1300, "call   1000 <site>"),
                               (0x1305, "ret")]
        if different_object:
            insns[S1_OTHER] = [(0x1280, "mov    %rsi,0x8(%rdi)"),
                               (0x1284, "ret")]
        if unknown_base:
            insns[S1_UNKNOWN] = [(0x12c0, "call   *(%rdi)"),
                                 (0x12c2, "mov    %rcx,0x8(%rax)"),
                                 (0x12c7, "ret")]
        static_values, u32, sizes = {}, {}, {}
        data_syms = {}
        tables = dict(S1_TBL)
        if fourth:
            tables.update(S1_TBL_D)
        for base, letter in tables.items():
            addr = tbl_a if base == 0x3000 else base
            data_syms[addr] = _s1_sym(letter)
            sizes[_s1_sym(letter)] = (0x20 if (shape_extra and base == 0x3000)
                                      else 0x18)
            members = S1_MEM.get(base) or S1_MEM_D
            for k, member in enumerate(members):
                value = member
                if bad_member and base == 0x3000 and k == 1:
                    value = 0x9999
                if null_member and base == 0x3000 and k == 1:
                    value = 0
                static_values[addr + k * 8] = {value}
        if shape_extra:
            static_values[tbl_a + 0x18] = {0x2030}
            funcs[0x2030] = "extra_member"
        dispatch = dict(S1_FUNCS)
        if fourth:
            dispatch.update(S1_FUNCS_D)
        newctx_all = (S1_NEW_A, S1_NEW_B, S1_NEW_C,
                      S1_NEW_D) if fourth else (S1_NEW_A, S1_NEW_B, S1_NEW_C)
        for i, (addr, name) in enumerate(sorted(
                dispatch.items(), key=lambda kv: kv[0])):
            sizes[name] = 0x30
            data_syms[addr] = name
            newctx_addr = newctx_all[i]
            u32[addr] = 1
            static_values[addr + 8] = {newctx_addr}
            u32[addr + 0x10] = 6
            static_values[addr + 0x18] = {S1_SITE}
            u32[addr + 0x20] = 0
            static_values[addr + 0x28] = {0}
        sections = {".text": (0x1000, 0, 0x1000),
                    ".data.rel.ro": (0x3000, 0, 0x1000),
                    ".data": (0x5000, 0, 0x1000)}
        direct = {S1_ROGUE: {S1_SITE}} if rogue else {}
        if different_object:
            direct.setdefault(S1_SITE, set()).add(S1_OTHER)
        if unknown_base:
            direct.setdefault(S1_SITE, set()).add(S1_UNKNOWN)
        g = _S1G(insns, funcs, data_syms, sizes, static_values, u32,
                 sections, direct=direct, source_root=repo)
        site = {"kind": "call", "func": S1_SITE, "addr": site_addr,
                "text": next(t for a, t in insns[S1_SITE]
                             if a == site_addr), "arg_deps": set()}
        return g, site, funcs

    def _s1_witness(**kw):
        g, site, funcs = _s1_fixture(**kw)
        reachable = set(funcs)
        if not kw.get("rogue"):
            reachable.discard(S1_ROGUE)
        return static_table_instance_witness(g, site, "site", reachable)

    sw = _s1_witness()
    check("S1 field-sensitive witness applies", bool(sw and sw.get("resolved")),
          True)
    check("S1 witness records the pointer slot",
          (sw or {}).get("pointer_slot", {}).get("object"), "Wctx")
    check("S1 witness records three instances",
          len((sw or {}).get("instances", [])), 3)
    check("S1 witness unions only the requested member",
          (sw or {}).get("targets"), ["0x2010", "0x2110", "0x2210"])
    check("S1 witness records each writer",
          sorted(r["function"] for r in (sw or {}).get("stored_by", [])),
          ["newctx_a", "newctx_b", "newctx_c"])
    sw2 = _s1_witness(shape="register", nullable=True, null_member=True,
                      guard=True)
    check("S1 Option<fn> NULL with a recorded guard resolves",
          bool(sw2 and sw2.get("resolved")), True)
    check("S1 Option<fn> NULL accepts only the other tables",
          (sw2 or {}).get("targets"), ["0x2110", "0x2210"])
    sw3 = _s1_witness(cast=True)
    check("S1 source cast to the concrete table type resolves",
          bool(sw3 and sw3.get("resolved")), True)
    check("S1 cast witness records the effective type",
          ((sw3 or {}).get("effective_type") or {}).get("via_cast"), True)
    check("S1 cast witness unions the cast layout's member",
          (sw3 or {}).get("targets"), ["0x2010", "0x2110", "0x2210"])
    check("S1 cast to a type with no declared instance is refused",
          (_s1_witness(cast_missing=True) or {}).get("refusal"),
          "no-declared-instance-type")
    check("S1 undeclared stored value is refused",
          (_s1_witness(undeclared=True) or {}).get("resolved", False), False)
    check("S1 non-function member is refused",
          (_s1_witness(bad_member=True) or {}).get("resolved", False), False)
    check("S1 mutable table section is refused",
          (_s1_witness(mutable=True) or {}).get("resolved", False), False)
    check("S1 unproven base register is refused",
          (_s1_witness(shape="direct") or {}).get("resolved", False), False)
    check("S1 reachable caller outside the cohort is refused",
          (_s1_witness(rogue=True) or {}).get("resolved", False), False)
    check("S1 derived/declared member mismatch is refused",
          (_s1_witness(shape_extra=True) or {}).get("resolved", False), False)
    check("S1 partial instance set is refused",
          (_s1_witness(third_store=False) or {}).get("resolved", False), False)
    check("S1 Option<fn> NULL without a guard is refused",
          (_s1_witness(shape="register", nullable=True, null_member=True,
                       guard=False) or {}).get("resolved", False), False)

    # Base-object qualification: a store into a different object is excluded
    # with its reason, and an unknown base origin still refuses.
    sw4 = _s1_witness(different_object=True)
    check("S1 same-offset store into an unrelated object is excluded",
          bool(sw4 and sw4.get("resolved")), True)
    check("S1 excluded store records its base type",
          [r.get("origin") for r in
           ((sw4 or {}).get("completeness") or {}).get(
               "excluded_different_object_stores", [])],
          ["entry-parameter"])
    check("S1 unknown base origin still refuses",
          (_s1_witness(unknown_base=True) or {}).get("refusal"),
          "unproven-cohort-store")

    # Prefix-compatible instance enumeration.
    sw5 = _s1_witness(prefix=True)
    check("S1 prefix-compatible instance type resolves",
          bool(sw5 and sw5.get("resolved")), True)
    ptypes = ((sw5 or {}).get("completeness") or {}).get(
        "prefix_compatible_types", {}) or {}
    check("S1 prefix witness records the first-field source witness",
          bool((ptypes.get("WRow") or {}).get("source_witness")), True)
    check("S1 prefix witness records the layout witness",
          ((ptypes.get("WRow") or {}).get("layout_witness") or {}).get(
              "offsets"), ["0x0", "0x10", "0x8"])
    check("S1 prefix-compatible-base is in the conjunction",
          "prefix-compatible-base" in ((sw5 or {}).get("conditions") or []),
          True)
    sw6 = _s1_witness(prefix_cast=True)
    check("S1 layout-equivalent first field with a source cast resolves",
          bool(sw6 and sw6.get("resolved")), True)
    check("S1 first-field-incompatible type is refused",
          (_s1_witness(prefix_nonbase=True) or {}).get("resolved", False),
          False)
    check("S1 layout-incompatible prefix type is refused",
          (_s1_witness(prefix_layout=True) or {}).get("resolved", False),
          False)

    # Context-object qualification: a compiler copy, a frame spill and two
    # agreeing paths admit; one unproven path refuses the whole object.  The
    # fourth-instance case proves the newly admitted object still widens by a
    # real static instance rather than dropping or inventing a target.
    swc = _s1_witness(shape="copy")
    check("S1 context copy chain resolves",
          bool(swc and swc.get("resolved")), True)
    check("S1 context copy keeps only the requested member",
          (swc or {}).get("targets"), ["0x2010", "0x2110", "0x2210"])
    swsp = _s1_witness(shape="spill")
    check("S1 context frame spill resolves",
          bool(swsp and swsp.get("resolved")), True)
    swcm = _s1_witness(shape="copy-multi")
    check("S1 two agreeing context copies resolve",
          bool(swcm and swcm.get("resolved")), True)
    swsm = _s1_witness(shape="spill-multi")
    check("S1 two agreeing frame stores resolve",
          bool(swsm and swsm.get("resolved")), True)
    swfour = _s1_witness(shape="spill", fourth=True)
    check("S1 context spill admits a newly added static instance",
          bool(swfour and swfour.get("resolved")), True)
    check("S1 context spill widens to the fourth table target",
          (swfour or {}).get("targets"),
          ["0x2010", "0x2110", "0x2210", "0x2310"])
    check("S1 a copy from a different parameter is refused",
          (_s1_witness(shape="copy-rogue") or {}).get("refusal"),
          "ctx-not-proven-parameter")
    check("S1 a frame slot overwritten from a different parameter is refused",
          (_s1_witness(shape="spill-rogue") or {}).get("refusal"),
          "ctx-not-proven-parameter")
    check("S1 one unproven copy path refuses the whole object",
          (_s1_witness(shape="copy-multi-rogue") or {}).get("refusal"),
          "ctx-not-proven-parameter")
    check("S1 one unproven frame-store path refuses the whole object",
          (_s1_witness(shape="spill-multi-rogue") or {}).get("refusal"),
          "ctx-not-proven-parameter")

    mut_rows = []

    def _mutation(name, fn):
        _MUTED.add(name)
        try:
            return fn()
        finally:
            _MUTED.discard(name)

    mut_rows.append(("fetch-base-not-return",
                     lambda: _fetch_witness(base_call=False)))
    mut_rows.append(("fetch-slot-outside",
                     lambda: _fetch_witness(off=0x100)))
    mut_rows.append(("fetch-source-writer",
                     lambda: _fetch_witness(two_assign=True)))
    mut_rows.append(("export-not-param",
                     lambda: _export_witness(param=False)[0]))
    mut_rows.append(("export-header-non-callback",
                     lambda: _export_witness(noncb=True)[0]))
    mut_rows.append(("export-no-root",
                     lambda: _export_witness(exported=False)[0]))
    mut_rows.append(("local-non-function",
                     lambda: _local_witness(extra=True)))

    def _s1_accept(**kw):
        w = _s1_witness(**kw)
        return w if (w and w.get("resolved")) else None

    mut_rows += [
        ("s1-undeclared-store", lambda: _s1_accept(undeclared=True)),
        ("s1-member-not-function", lambda: _s1_accept(bad_member=True)),
        ("s1-mutable-table", lambda: _s1_accept(mutable=True)),
        ("s1-base-not-table", lambda: _s1_accept(shape="direct")),
        ("s1-caller-outside-cohort", lambda: _s1_accept(rogue=True)),
        ("s1-shape-mismatch", lambda: _s1_accept(shape_extra=True)),
        ("s1-partial-instances", lambda: _s1_accept(third_store=False)),
        ("s1-null-no-guard",
         lambda: _s1_accept(shape="register", nullable=True,
                            null_member=True, guard=False)),
    ]
    check("witness mutation matrix: each refusal flips its negative",
          [(name, _mutation(name, fn) is not None) for name, fn in mut_rows],
          [(name, True) for name, _fn in mut_rows])
    print("[consumer-closure] witness mutation matrix: " + "; ".join(
        f"{name} -> negative accepted" for name, _fn in mut_rows))

    # The base/prefix extensions have their own load-bearing mutations.  Some
    # disable an exclusion (so the positive case must then refuse), some
    # disable an admission (so the negative case must then resolve).
    mut2 = [
        ("s1-base-different", lambda: _s1_witness(different_object=True),
         False, "unproven-cohort-store"),
        ("s1-base-unknown", lambda: _s1_witness(unknown_base=True),
         True, None),
        ("s1-prefix-types", lambda: _s1_witness(prefix=True),
         False, "no-declared-instance-type"),
        ("s1-prefix-first-field", lambda: _s1_witness(prefix_nonbase=True),
         True, None),
        ("s1-prefix-layout", lambda: _s1_witness(prefix_layout=True),
         True, None),
        ("s1-ctx-object", lambda: _s1_witness(shape="spill"),
         False, "ctx-not-proven-parameter"),
        ("s1-ctx-object", lambda: _s1_witness(shape="copy-multi"),
         False, "ctx-not-proven-parameter"),
    ]
    mut2_results = []
    for name, fn, _wr, _rf in mut2:
        w = _mutation(name, fn) or {}
        mut2_results.append((name, bool(w.get("resolved")),
                             w.get("refusal")))
    check("witness mutation matrix 2: base/prefix checks are load-bearing",
          mut2_results,
          [(name, wr, rf) for name, _fn, wr, rf in mut2])
    print("[consumer-closure] witness mutation matrix 2: " + "; ".join(
        f"{name} -> resolved={w} refusal={r}"
        for name, w, r in mut2_results))

    # ---- evidence-class controls ------------------------------------------ #
    # R1: a non-literal dlsym argument must not be resolved.
    class _DG:
        def cstring_at(self, addr):
            return "ERR_get_state" if addr == 0x500 else None

    class _DF:
        def __init__(self, value):
            self.regs = {"%rsi": value}

    class _DR:
        g = _DG()

    check("dlsym literal resolves",
          PrecisionResolver.dlsym_literal(_DR(), _DF(PValue.one(0x500))),
          "ERR_get_state")
    check("dlsym top argument is not evidence",
          PrecisionResolver.dlsym_literal(_DR(), _DF(PValue())), None)
    check("dlsym symbolic argument is not evidence",
          PrecisionResolver.dlsym_literal(_DR(), _DF(PValue.one(("arg", 1)))), None)
    check("dlsym non-string address is not evidence",
          PrecisionResolver.dlsym_literal(_DR(), _DF(PValue.one(0x600))), None)

    # R3: a table with an unfilled/non-code entry is not evidence-complete.
    class _TG:
        start_set = {0x1000, 0x2000}

        def static_slot(self, addr):
            return {0x1000: {0x1000}, 0x1008: {0x2000},
                    0x1010: {0x3000}}.get(addr, None)

    r3_t, r3_bad = DsoGraph.table_ptrs(_TG(), 0x1000, 2, strict=True)
    check("R3 table reads in-image entries", r3_t, {0x1000, 0x2000})
    check("R3 unfilled entry stays incomplete", r3_bad, [])
    r3_t, r3_bad = DsoGraph.table_ptrs(_TG(), 0x1000, 3, strict=True)
    check("R3 non-code entry is incomplete", r3_bad, [0x1010])

    # Switch-table precision: the compiler's own bound is evidence.  The
    # absence of a bound is the negative control and must keep the
    # conservative scan rather than an invented length.
    check("compare mnemonic with size suffix",
          [_is_compare(m) for m in ("cmp", "cmpq", "testb", "cmovne")],
          [True, True, True, False])

    class _SG:
        start_set = {0x200, 0x300, 0x400, 0x500, 0x600}
        sections = {".rodata": (0x1000, 0, 5 * 4)}

        def section_of(self, addr):
            return ".rodata" if 0x1000 <= addr < 0x1014 else None

        def _section_bytes(self, _name):
            return b"".join(struct.pack("<i", v - 0x1000)
                            for v in (0x200, 0x300, 0x400, 0x500, 0x600))

    class _SR:
        def __init__(self, bounds):
            self.g = _SG()
            self.switch_cache = {}
            self.switch_bounds = bounds

    bounded = _SR({0x20: 3})
    check("switch bound decodes only the live entries",
          PrecisionResolver.switch_targets(bounded, 0x1000, 0x20),
          {0x200, 0x300, 0x400})
    unbounded = _SR({})
    check("switch without a bound keeps the conservative scan (negative control)",
          0x500 in PrecisionResolver.switch_targets(unbounded, 0x1000, 0x20), True)

    insns = [(0x10, "cmp    $0x2,%eax"), (0x13, "ja     0x40"),
             (0x15, "lea    0x0(%rip),%rcx        # 1000 <tbl>"),
             (0x1c, "movslq (%rcx,%rax,4),%rax"),
             (0x20, "jmp    *%rax")]
    rb = _SR({})
    PrecisionResolver._record_switch_bounds(rb, insns)
    check("switch bound recorded from cmp/ja", rb.switch_bounds, {0x20: 3})
    no_cmp = _SR({})
    PrecisionResolver._record_switch_bounds(no_cmp, [
        (0x15, "lea    0x0(%rip),%rcx        # 1000 <tbl>"),
        (0x20, "jmp    *%rax")])
    check("switch without cmp keeps no bound (negative control)",
          no_cmp.switch_bounds, {})
    wrong_reg = _SR({})
    PrecisionResolver._record_switch_bounds(wrong_reg, [
        (0x10, "cmp    $0x2,%ebx"), (0x13, "ja     0x40"),
        (0x15, "lea    0x0(%rip),%rcx        # 1000 <tbl>"),
        (0x1c, "movslq (%rcx,%rax,4),%rax"),
        (0x20, "jmp    *%rax")])
    check("switch bound ignores a compare of a different register (negative control)",
          wrong_reg.switch_bounds, {})

    check("O1 names the three audited functions",
          [is_o1_function(n) for n in (
              "...err14append_current", "...err7SlotStr...drop_glue",
              "...errNtB5_19PendingReleaseGuard...Drop4drop",
              "...errNtB5_7SlotStr...Drop4drop")],
          [True, True, True, False])

    # A2: the setter-import predicate is the negative control.
    class _EG:
        name = "control.so"
        start_set = {0x10, 0x20, 0x40}
        funcs = {0x10: "_RNvNt...CsgxBkk5gSRhY_4core3fmt...",
                 0x20: "app_owned_function",
                 0x30: "_RNvNt...CsgxBkk5gSRhY_4core3fmt...impl",
                 0x40: "_RNvNt...PEM_ASN1_write_bio_internal"}
        all_syms = {
            0x9000: "...runtime3mem9MALLOC_FN",
            0x9008: "...runtime3mem7FREE_FN",
            0x9010: "...runtime3mem10REALLOC_FN",
            0x9018: "CRYPTO_set_mem_functions",
            0x9020: "...provider12provider_new",
            0x9028: "...provider4init13provider_init",
            0x9030: "OSSL_ENCODER_fetch",
        }
        taken_code = {0x30}
        taken_data = set()
        slot_funcs = {0x900: {0x30}}
        field_stores = {}
        unknown_call_arg_targets = set()
        evidence_classes = collections.Counter()
        sites = {}
        residual_sites = []
        resolved_targets = set()
        precision_counts = collections.Counter()

        @property
        def slot_func_targets(self):
            return {0x30}

    def _site(func, seam=None):
        return {"kind": "call", "func": func, "addr": func + 1,
                "text": "call *%rax", "targets": set(), "unresolved": True,
                "reason": "field-of-unknown-base", "class": "field",
                "field_offsets": set(), "seam": seam}

    eg = _EG()
    a2 = _site(0x40)
    eg.sites = {(0x40, 0x41, "call"): a2}
    apply_evidence_classes(eg, {"EVP_MD_meth_new"})
    check("A2 with an imported setter stays unresolved", a2["unresolved"], True)
    eg = _EG()
    a2 = _site(0x40)
    eg.sites = {(0x40, 0x41, "call"): a2}
    apply_evidence_classes(eg, set())
    check("A2 without a setter resolves", a2["unresolved"], False)

    eg = _EG()
    r2 = _site(0x10)
    eg.sites = {(0x10, 0x11, "call"): r2}
    apply_evidence_classes(eg, set())
    check("R2 std/core site resolves", r2["unresolved"], False)
    eg = _EG()
    app = _site(0x20)
    eg.sites = {(0x20, 0x21, "call"): app}
    apply_evidence_classes(eg, set())
    check("application namespace is not R2", app["unresolved"], True)

    eg = _EG()
    o1 = _site(0x41, seam="FREE_FN")
    eg.funcs[0x41] = "...errNtB5_7SlotStr...drop_glue"
    eg.sites = {(0x41, 0x42, "call"): o1}
    apply_evidence_classes(eg, set())
    check("O1 seam is contract-bounded", o1["class"], ABI_CONTRACT_ALLOCATOR)
    check("O1 seam stays unresolved", o1["unresolved"], True)
    check("O1 seam is not a resolved target set", o1["targets"], set())
    check("O1 contract cites the printf triple",
          "CRYPTO_set_mem_functions" in ABI_CONTRACTS[ABI_CONTRACT_ALLOCATOR]["contract"],
          True)

    # ---- per-call-site witness rule (AGENTS.md section 22) ---------------- #
    # Positive control: provider_init reads init_function, whose documented
    # writer is in this image.
    eg = _EG()
    prov = _site(0x50)
    prov["field_offsets"] = {0x40}
    eg.funcs[0x50] = "...provider4init13provider_init"
    eg.sites = {(0x50, 0x51, "call"): prov}
    apply_evidence_classes(eg, set())
    check("provider_init with the documented slot is contract-bounded",
          prov["class"], ABI_CONTRACT_PROVIDER)
    check("provider_init witness names the exact slot",
          (prov.get("witness") or {}).get("slot"),
          "OsslProvider.init_function (offset 0x40)")
    check("provider_init witness is contract_bounded",
          (prov.get("witness") or {}).get("contract_bounded"), True)

    # Negative control: an A1-shaped name whose slot is an internal callback is
    # NOT absorbed by the class; it stays unresolved and target-bounded.
    eg = _EG()
    mis = _site(0x60)
    mis["field_offsets"] = {0x28}
    eg.funcs[0x60] = "...method_store26ossl_method_construct_this"
    eg.sites = {(0x60, 0x61, "call"): mis}
    apply_evidence_classes(eg, set())
    check("A1 name with a non-provider slot stays unresolved", mis["unresolved"], True)
    check("A1 name with a non-provider slot is not contract-bounded",
          mis["class"] in ABI_CONTRACT_CLASSES, False)
    check("A1 name with a non-provider slot records the missing witness",
          (mis.get("witness") or {}).get("contract_bounded"), False)
    e7 = evaluate_predicate_element_7([("control.so", 0x60, mis)], [])
    check("A1 name without a witness keeps element 7 failing",
          e7["established"], False)

    # ---- in-image slot targets: a target claim, not an ABI contract -------- #
    def _edge_graph():
        eg = _EG()
        eg.start_set = set(eg.start_set) | {0x70, 0x80}
        eg.funcs[0x60] = "...method_store26ossl_method_construct_this"
        eg.funcs[0x70] = "...evp5fetch23inner_evp_generic_fetch"
        eg.funcs[0x80] = "...evp5fetch20construct_evp_method"
        eg.all_syms = dict(eg.all_syms)
        eg.all_syms.update({
            0x60: "...method_store26ossl_method_construct_this",
            0x70: "...evp5fetch23inner_evp_generic_fetch",
            0x80: "...evp5fetch20construct_evp_method",
        })
        s = _site(0x60)
        s["field_offsets"] = {0x28}
        eg.sites = {(0x60, 0x61, "call"): s}
        return eg, s

    eg, s = _edge_graph()
    apply_evidence_classes(eg, set(), {0x70})
    check("in-image slot with a reachable writer resolves", s["unresolved"], False)
    check("in-image slot resolves to the exact target", s["targets"], {0x80})
    check("in-image slot is not contract-bounded",
          s["class"] in ABI_CONTRACT_CLASSES, False)
    check("in-image slot records the writer and its source",
          (s.get("edge_target_witness") or {}).get("id"), "EVT-MCM-CONSTRUCT")

    # Negative control: the same slot with an unreachable writer stays open.
    eg, s = _edge_graph()
    apply_evidence_classes(eg, set(), {0x10})
    check("in-image slot with an unreachable writer stays unresolved",
          s["unresolved"], True)
    check("unreachable writer is not absorbed by a contract class",
          s["class"] in ABI_CONTRACT_CLASSES, False)

    # Negative control: a writer absent from the image stays unresolved.
    eg, s = _edge_graph()
    del eg.all_syms[0x70]
    apply_evidence_classes(eg, set(), {0x70, 0x80})
    check("in-image slot with an absent writer stays unresolved",
          s["unresolved"], True)

    # Negative control for the static-initialiser branch: a declared target
    # must be the first qword of an in-image data table.
    class _SIG:
        start_set = {0x1000, 0x2000}
        names_at = {0x9000: {"AES_XTS_HW"}, 0x9008: {"runtime_function"}}

        def section_of(self, a):
            return ".data.rel.ro" if a == 0x9000 else ".text"

        def static_slot(self, a):
            return {0x9000: {0x1000}}.get(a)

    check("static initialiser covers its first qword",
          _static_initialiser_covers(_SIG(), {0x1000}, ("_HW",)), True)
    check("static initialiser refuses a non-table target",
          _static_initialiser_covers(_SIG(), {0x2000}, ("_HW",)), False)

    # ---- reachable-caller target bounding --------------------------------- #
    # A synthetic two-caller case: the fixed caller is reachable and the
    # parameter-forwarding caller is not -> resolved to the fixed target.
    # Inverting reachability must leave the site unresolved.
    class _P:
        import_addrs = set()

        def __init__(self, calls, insns=None):
            self.calls = calls
            self.insns_by_func = insns or {}
            self.summary = collections.defaultdict(
                lambda: [set() for _ in _ARGREGS])

        def summary_vals(self, f, k):
            return (self.summary[f][k] if 0 <= k < len(_ARGREGS)
                    else set())

    class _RCG:
        name = "control.so"
        funcs = {0x10: "root", 0x20: "fixed_caller", 0x30: "param_caller",
                 0x40: "doall_like", 0x50: "fixed_target",
                 0x60: "other_target"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        direct = {0x10: {0x20}, 0x20: {0x40}, 0x30: {0x40}}
        dynamic_defs = {}
        taken_code = set()
        taken_data = set()
        slot_funcs = {}
        field_stores = {}
        unknown_call_arg_targets = set()
        relocs = []
        evidence_classes = collections.Counter()
        residual_sites = []
        resolved_targets = set()
        precision_counts = collections.Counter()

        @property
        def slot_func_targets(self):
            return set()

    def _rcb_graph():
        g = _RCG()
        g.sites = {(0x40, 0x41, "call"): {
            "kind": "call", "func": 0x40, "addr": 0x41,
            "text": "call *%rbp", "targets": {0x50, 0x60},
            "unresolved": True, "reason": "reg-value-partial[arg]",
            "class": "materialised", "field_offsets": set(), "seam": None,
            "arg_deps": {1}, "arg_targets": {0x50, 0x60}}}
        g.precision = _P([
            (0x20, 0x40, [PValue(), PValue.one(0x50)], 0x25),
            (0x30, 0x40, [PValue(), PValue.one(("arg", 1))], 0x35),
        ], {
            0x20: [
                (0x24, "lea    0x2c8(%rip),%rsi  # 50 <fixed_target>"),
                (0x25, "call   0x40 <doall_like>")],
            0x30: [(0x35, "call   0x40 <doall_like>")],
        })
        return g, g.sites[(0x40, 0x41, "call")]

    g, s = _rcb_graph()
    apply_evidence_classes(g, set(), {0x10, 0x20, 0x40})
    check("reachable fixed caller narrows the site", s["unresolved"], False)
    # The excluded caller forwards its parameter but has no summary value, so
    # its contribution is empty.  The flat candidate is therefore unattributed
    # and is admitted (round 4), never dropped: the site keeps both targets.
    check("unattributed candidate is admitted rather than dropped",
          s["targets"], {0x50, 0x60})
    check("reachable-caller bound is not a contract class",
          s["class"] in ABI_CONTRACT_CLASSES, False)
    check("reachable-caller bound has no ABI witness",
          "witness" in s, False)
    rcb = s.get("reachable_caller_bound") or {}
    check("reachable-caller bound records its schema",
          rcb.get("schema"), REACHABLE_CALLER_SCHEMA)
    check("reachable-caller bound records the excluded caller",
          [r["function"] for r in rcb.get("excluded_callers", [])], ["0x30"])
    check("reachable-caller bound records the witness instruction",
          rcb["reachable_callers"][0]["call_sites"][0]["arguments"][0]
          ["witness_instruction"][0]["text"].startswith("lea"), True)

    # Inverse: the parameter-forwarding caller is reachable -> unresolved.
    g, s = _rcb_graph()
    apply_evidence_classes(g, set(), {0x10, 0x30, 0x40})
    check("reachable parameter caller keeps the site unresolved",
          s["unresolved"], True)
    check("reachable parameter caller is not absorbed by a contract class",
          s["class"] in ABI_CONTRACT_CLASSES, False)
    check("reachable parameter caller records the refusal",
          "non-image value" in (s.get("reachable_caller_bound_refusal") or ""),
          True)

    # Both callers reachable is the same refusal.
    g, s = _rcb_graph()
    apply_evidence_classes(g, set(), {0x10, 0x20, 0x30, 0x40})
    check("reachable fixed and parameter callers keep the site unresolved",
          s["unresolved"], True)

    # No reachability evidence -> unresolved (negative control).
    g, s = _rcb_graph()
    apply_evidence_classes(g, set(), None)
    check("no reachability evidence keeps caller bounding off",
          s["unresolved"], True)

    # Round 4: an excluded caller that forwards its own parameter contributes
    # exactly the values its argument summary admits -- the same expansion that
    # produced the site's flat arg_targets.  With no summary values it
    # contributes nothing (and the target is admitted, not dropped).
    g, s = _rcb_graph()
    g.precision.summary[0x30][1] = {0x60}
    apply_evidence_classes(g, set(), {0x10, 0x20, 0x40})
    exrow = s["reachable_caller_bound"]["excluded_callers"][0]
    check("excluded caller attribution resolves a forwarded parameter",
          (exrow["contributed_targets"],
           exrow["call_sites"][0]["arguments"][0]["targets"]),
          (["0x60"], ["0x60"]))
    check("reachable caller row is marked reachable",
          s["reachable_caller_bound"]["reachable_callers"][0]["reachable"],
          True)

    # ---- stored-value provenance for Method.free (offset 0x20) ------------- #
    # The slot is bounded by the values reachable code stores, never by the
    # declared symbol names.  Controls (a)-(e) are exercised here.
    _insns = {
        0x10: [(0x10, "ret")],
        0x100: [
            (0x100, "push   %rbx"),
            (0x101, "sub    $0x8,%rsp"),
            (0x102, "mov    0x18(%rsp),%rax"),
            (0x103, "mov    %rax,0x20(%rbx)"),
            (0x104, "ret")],
        0x200: [
            (0x200, "push   %rbx"),
            (0x201, "sub    $0x8,%rsp"),
            (0x202, "mov    0x18(%rsp),%rax"),
            (0x203, "mov    %rax,0x20(%rbx)"),
            (0x204, "ret")],
        0x300: [(0x300, "ret")],
        0x400: [(0x400, "ret")],
        0x410: [(0x410, "jmp    *0x8bf0(%rip)        # 9000 <OSSL_ENCODER_free>")],
        0x420: [(0x420, "ret")],
        0x500: [
            (0x500, "push   %rbx"),
            (0x501, "sub    $0x8,%rsp"),
            (0x502, "mov    0x18(%rsp),%rax"),
            (0x503, "mov    %rax,0x20(%rbx)"),
            (0x504, "ret")],
        0x600: [(0x600, "ret")],
    }

    class _P2:
        import_addrs = set()

        def __init__(self, calls, insns):
            self.calls = calls
            self.insns_by_func = insns
            self.summary = collections.defaultdict(
                lambda: [set() for _ in _ARGREGS])

        def summary_vals(self, f, k):
            return (self.summary[f][k] if 0 <= k < len(_ARGREGS)
                    else set())

    class _MG:
        name = "control.so"
        funcs = {
            0x10: "...property5store11alg_cleanup",
            0x100: "...property5store21ossl_method_store_add",
            0x200: "...property5store27ossl_method_store_cache_set",
            0x300: "...decoder_meth20put_decoder_in_store",
            0x400: "OSSL_DECODER_free",
            0x410: "...decoder_meth12thunk_to_free",
            0x420: "OSSL_ENCODER_free",
            0x500: "...property5store21ossl_method_store_add.dead",
            0x600: "dead_target",
        }
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}
        dynamic_defs = {"OSSL_DECODER_free": 0x400,
                        "OSSL_ENCODER_free": 0x420}
        slot_syms = {}
        slot_funcs = {0x9000: {0x420}}
        slot_data = {}
        taken_code = set()
        taken_data = set()
        field_stores = {}
        unknown_call_arg_targets = set()
        evidence_classes = collections.Counter()
        residual_sites = []
        resolved_targets = set()
        precision_counts = collections.Counter()

        def section_of(self, a):
            return ".text" if a < 0x9000 else ".data"

        def static_slot(self, a):
            return {0x9000: frozenset({0x420})}.get(a)

        @property
        def slot_func_targets(self):
            return set()

    def _row(call_site, stack, caller=0x300):
        return {"caller": caller, "call_site": call_site,
                "args": [PValue() for _ in range(6)],
                "stack": list(stack), "open": [True] * 6}

    def _mg_graph(bad=None):
        g = _MG()
        g.precision = _P2([], dict(_insns))
        g._semantic_call_index = {
            0x100: {(0x300, 0x301): _row(0x301, [PValue.one(0x410)]),
                    (0x300, 0x303): _row(0x303, [PValue.one(0x400)])},
            0x200: {(0x300, 0x305): _row(0x305, [PValue.one(0x410)])},
            0x500: {(0x300, 0x307): _row(0x307, [PValue.one(0x600)])},
        }
        if bad is not None:
            g._semantic_call_index[0x100][(0x300, 0x301)] = _row(
                0x301, [bad])
        g.sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call   *0x20(%rbp)", "targets": set(),
            "unresolved": True, "reason": "field-of-unknown-base",
            "class": "field", "field_offsets": {0x20}, "seam": None,
            "arg_deps": set()}}
        return g, g.sites[(0x10, 0x11, "call")]

    _reach = {0x10, 0x100, 0x200, 0x300, 0x400, 0x410, 0x420}
    _name = "...property5store11alg_cleanup"
    g, s = _mg_graph()
    rec = semantic_method_free_targets(g, s, _name, _reach)
    check("stored-value slot resolves from reachable stores",
          rec.get("resolved"), True)
    check("stored-value slot target set is derived, not declared",
          rec.get("targets"), ["0x400", "0x420"])

    # (b) the declared name is absent but the store provenance is finite.
    check("declared-but-absent free_decoder is reported",
          "free_decoder" in rec["declared_cross_check"]["declared_but_absent"],
          True)
    check("derived-but-undeclared OSSL_DECODER_free is reported",
          "0x400" in rec["declared_cross_check"]["derived_but_undeclared"],
          True)

    # (c) the thunk and its callee collapse to one semantic target.
    check("a thunk and its callee collapse to one target",
          [c["stored"] for c in rec["thunk_collapses"]], ["0x410"])
    check("the thunk address is not itself a target",
          "0x410" in rec["targets"], False)

    # (d) an unreachable writer does not contribute, and is recorded as excluded.
    check("an unreachable writer's target is absent from the bound",
          "0x600" in rec["targets"], False)
    check("the unreachable writer is recorded as excluded",
          any(w.get("address") == "0x500" for w in rec["excluded_writers"]),
          True)
    g2, s2 = _mg_graph()
    rec2 = semantic_method_free_targets(
        g2, s2, _name, _reach | {0x500})
    check("marking the writer reachable makes its target appear (canary)",
          "0x600" in rec2["targets"], True)

    # (a) a reachable store whose value is an unbounded caller argument keeps
    # the site unresolved.
    g3, s3 = _mg_graph(bad=PValue.one(("arg", 3)))
    rec3 = semantic_method_free_targets(g3, s3, _name, _reach)
    check("argument-derived store keeps the slot unresolved",
          rec3.get("resolved"), False)
    check("the offending call site is named",
          len(rec3.get("offending_call_sites") or ()), 1)

    # (e) the old declared-name path cannot run for this slot: _fragment_addrs
    # is made to raise and the rule must neither call it nor void the spec.
    _orig_fragment_addrs = globals()["_fragment_addrs"]

    def _boom(*_a, **_k):
        raise AssertionError("_fragment_addrs must not be used here")

    globals()["_fragment_addrs"] = _boom
    try:
        g4, s4 = _mg_graph()
        rec4 = semantic_method_free_targets(g4, s4, _name, _reach)
        apply_evidence_classes(g4, set(), _reach)
    finally:
        globals()["_fragment_addrs"] = _orig_fragment_addrs
    check("the stored-value rule never calls _fragment_addrs",
          rec4.get("resolved"), True)
    check("the closure resolves the site without the declared-name helper",
          (s4["unresolved"], s4["class"]),
          (False, "semantic-store-target"))
    check("stored-value targets are not an ABI contract class",
          s4["class"] in ABI_CONTRACT_CLASSES, False)

    # ---- per-edge provenance records (section 7 / section 22) -------------- #
    # A valid record separates what was proved from what was approximated, and
    # every dropped target carries a checkable reason.
    g5, _s5 = _mg_graph()
    apply_evidence_classes(g5, set(), _reach)
    records = build_edge_records({g5.name: g5})
    check("the edge record set validates", validate_edge_records(records), [])
    check("every classified site emits a record", len(records), len(g5.sites))
    rec0 = records[0]
    check("the edge record identity is semantic, not an address",
          (rec0["semantic_identity"]["defining_function"],
           rec0["semantic_identity"]["call_site_role"]),
          (_name, "method-store-slot"))
    check("the address is recorded only as an artifact-local witness",
          "site_address" in rec0["semantic_identity"]["artifact_local_witness"],
          True)
    check("the edge record disposition is PROVED_TARGET_SET",
          rec0["disposition"], DISPOSITION_PROVED)
    check("each proved target carries a derivation",
          sorted(c["target"] for c in rec0["semantic_identity"]["provenance_chain"]),
          rec0["target_set"])
    check("the unreachable writer's target is excluded with a witness",
          any(e.get("target") == "dead_target"
              and e.get("reason") == "no-reachable-writer"
              and e.get("row_kind") == "target-drop"
              for e in rec0["exclusions"]), True)
    check("the writer itself is a subject row, not a target drop",
          any(w.get("target") == g5.funcs.get(0x500)
              and w.get("reason") == "writer-not-in-reachable-set"
              and w.get("row_kind") == "subject"
              and w.get("evidence", {}).get("would_store_targets")
              == ["dead_target"]
              for w in rec0.get("excluded_writers") or ()), True)

    # The refusal test required by this subphase: inject an exclusion with no
    # reason and require the closure to refuse it.
    bad = json.loads(json.dumps(rec0))
    bad["exclusions"].append({"target": "OSSL_DECODER_free",
                              "reason": None, "evidence": {}})
    bad_defects, bad_refusal = edge_closure_refusal([bad])
    check("an exclusion without a reason is a defect", bool(bad_defects), True)
    check("the closure refuses an uncheckable exclusion",
          bad_refusal["code"], "EDGE_RECORD_EXCLUSION_UNSOUND")

    # A stale accounting block cannot hide a removed exclusion: the validator
    # recomputes from the record.
    omitted = json.loads(json.dumps(rec0))
    omitted["exclusions"] = [e for e in omitted["exclusions"]
                             if e.get("target") != "dead_target"]
    check("dropping an exclusion is refused even with stale accounting",
          bool(validate_edge_records([omitted])), True)

    # An exclusion that names a reason but carries no evidence is also refused.
    evidence_free = json.loads(json.dumps(rec0))
    evidence_free["exclusions"].append({
        "target": "OSSL_DECODER_free",
        "reason": "not-in-reachable-set", "evidence": {}})
    check("an exclusion without evidence is a defect",
          bool(validate_edge_records([evidence_free])), True)

    # ---- mutually redundant accounting, derivation and oracle controls ---- #
    # Each control mutates exactly one ledger of an otherwise valid record and
    # requires the validator to refuse it.  These are the canaries for the two
    # defects this subphase fixes: an admitted set taken from the record's own
    # accounting (A), and a reachability exclusion that its evidence does not
    # establish (B).
    def _mutated(mutator):
        rec = json.loads(json.dumps(rec0))
        mutator(rec)
        return validate_edge_records([rec])

    check("dropping a target from target_set only is refused",
          bool(_mutated(lambda r: r["target_set"].pop())), True)
    check("removing a provenance chain row for a claimed target is refused",
          bool(_mutated(
              lambda r: r["semantic_identity"]["provenance_chain"].pop())),
          True)

    def _set_first_step(step):
        def apply(rec):
            rec["semantic_identity"]["provenance_chain"][0]["derivation"][0] = step
        return apply

    check("an unknown derivation step is refused",
          bool(_mutated(_set_first_step({"step": "trust-me"}))), True)
    check("a derivation step with no payload is refused",
          bool(_mutated(_set_first_step({"step": "resolver"}))), True)

    def _exclude_admitted(rec):
        name = rec["target_set"][0]
        rec["exclusions"].append({
            "target": name,
            "reason": "target-not-in-reachable-set",
            "row_kind": "target-drop",
            "claim": {"kind": "target-not-in-reachable-set",
                      "module": rec["semantic_identity"]
                                ["artifact_local_witness"]["module"],
                      "subjects": [name]},
            "evidence": {"reachable_set_member": False, "symbol": name,
                         "reachable_basis": "pre-closure-direct",
                         "symbols_checked": [name]}})

    check("an exclusion naming an admitted target is refused",
          bool(_mutated(_exclude_admitted)), True)

    def _flip_member(rec):
        for row in rec.get("excluded_writers") or ():
            if row.get("reason") == "writer-not-in-reachable-set":
                row["evidence"]["reachable_set_member"] = True

    check("flipping reachable_set_member to True is refused",
          bool(_mutated(_flip_member)), True)
    check("stale admitted_targets accounting is refused",
          bool(_mutated(
              lambda r: r["exclusion_accounting"]["admitted_targets"].pop())),
          True)

    # A `declared-name-absent` row is a target drop bound by a structured
    # `evidence.targets` list.  The v1.2 fixture emitted a cross-check name as
    # if it were a dropped target; that is no longer an exclusion.  The controls
    # below use a crafted record so each new check is exercised directly.
    check("the semantic fixture no longer emits a declared-name cross-check as "
          "a target drop",
          [e for e in rec0["exclusions"]
           if e.get("reason") == "declared-name-absent"], [])

    check("declared-name-absent with present=True is refused",
          bool(_mutated(lambda r: r["exclusions"].append({
              "target": r["target_set"][0],
              "reason": "declared-name-absent",
              "row_kind": "target-drop",
              "claim": {"kind": "declared-name-absent",
                        "module": r["semantic_identity"]
                                  ["artifact_local_witness"]["module"],
                        "subjects": ["absent_name"]},
              "evidence": {"declared_name": "absent_name",
                           "present": True, "targets": ["absent_name"]}}))), True)

    # Issue-B control: an oracle that places the excluded writer in the final
    # upper bound must make the record (and the audit) refuse.  The writer is
    # excluded because it was outside the *pre-closure direct* set; the final
    # upper bound admits it, so the negative claim is unsound.
    dead_writer = [e for e in (rec0.get("excluded_writers") or ())
                   if e.get("reason") == "writer-not-in-reachable-set"]
    check("the fixture carries a reachability exclusion for the dead writer",
          bool(dead_writer), True)
    oracle_dead = ReachabilityOracle({g5.name: g5}, {(g5.name, 0x500)})
    records_dead = build_edge_records({g5.name: g5}, oracle_dead)
    dead_audit = [r for r in
                  reachability_exclusion_audit({g5.name: g5}, oracle_dead,
                                               records_dead)
                  if r["claim_kind"] == "writer-not-in-reachable-set"]
    check("an excluded writer the final upper bound reaches is refused",
          (bool(validate_edge_records(records_dead, oracle_dead)),
           any(r["in_final_upper_bound"] for r in dead_audit)),
          (True, True))

    # Positive control: the same records with an oracle that does not reach the
    # writer validate cleanly, so the refusal above is caused by the oracle.
    oracle_live = ReachabilityOracle({g5.name: g5},
                                     {(g5.name, a) for a in _reach})
    records_live = build_edge_records({g5.name: g5}, oracle_live)
    check("a writer outside the upper bound validates cleanly (positive control)",
          validate_edge_records(records_live, oracle_live), [])
    check("the audit reports no violation when the writer is outside the bound",
          [r for r in
           reachability_exclusion_audit({g5.name: g5}, oracle_live,
                                        records_live)
           if r["violation"]], [])

    # The oracle check has a separate role: a record whose evidence was
    # built against a truthful oracle is still refused when the oracle used to
    # validate it disagrees.  Without this check the record would pass on its
    # own (internally consistent) account.
    records_truth = build_edge_records({g5.name: g5}, oracle_live)
    check("a record built against a truthful oracle validates",
          validate_edge_records(records_truth, oracle_live), [])
    check("the same record is refused by a disagreeing oracle",
          bool(validate_edge_records(records_truth, oracle_dead)), True)

    # The provenance resolver seeds entry arguments and records outgoing stack
    # arguments, which is what lets a writer's parameter be followed.
    class _PG:
        funcs = {0x100: "W", 0x500: "F", 0x600: "L", 0x700: "T"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}
        dynamic_defs = {}
        slot_syms = {}
        slot_funcs = {}
        slot_data = {}
        taken_code = set()
        taken_data = set()
        field_stores = {}
        unknown_call_arg_targets = set()
        import_addrs = set()
        direct = {}
        functions = [
            (0x100, [(0x100, "mov    0x8(%rsp),%rax"),
                     (0x101, "mov    %rax,0x20(%rbx)"),
                     (0x102, "ret")]),
            (0x500, [(0x500, "mov    0x8(%rsp),%rax"),
                     (0x501, "push   %rax"),
                     (0x502, "call   100 <W>"),
                     (0x503, "ret")]),
            (0x600, [(0x600, "lea    0x100(%rip),%r10        # 400 <T>"),
                     (0x601, "push   %r10"),
                     (0x602, "call   100 <W>"),
                     (0x603, "ret")]),
        ]

        def containing(self, a):
            return max(x for x in self.funcs if x <= a)

        def section_of(self, _a):
            return ".text"

        def static_slot(self, _a):
            return None

        def seam_symbol(self, _a):
            return None

        def cstring_at(self, _a):
            return None

        def is_data(self, _a):
            return False

    pg = _PG()
    prov = PrecisionResolver(pg)
    prov.seed_entry_args = True
    prov.capture_stack_args = True
    prov.run(passes=1)
    fwd = prov.call_stack_args.get((0x500, 0x502)) or []
    check("provenance mode forwards a caller stack argument symbolically",
          fwd and not fwd[0].is_top() and ("arg", 6) in fwd[0].s, True)
    lea = prov.call_stack_args.get((0x600, 0x602)) or []
    check("provenance mode records an outgoing lea stack argument",
          lea and not lea[0].is_top() and 0x400 in lea[0].s, True)

    # Negative control: an allocator seam with no global/setter in the image is
    # not evidence for CRYPTO_set_mem_functions.
    eg = _EG()
    eg.all_syms = {}
    o1_missing = _site(0x41, seam="FREE_FN")
    eg.funcs[0x41] = "...errNtB5_7SlotStr...drop_glue"
    eg.sites = {(0x41, 0x42, "call"): o1_missing}
    apply_evidence_classes(eg, set())
    check("allocator seam without image evidence is not contract-bounded",
          o1_missing["class"] in ABI_CONTRACT_CLASSES, False)
    check("allocator seam without image evidence stays unresolved",
          o1_missing["unresolved"], True)

    # Negative control: an indirect edge the resolver and every evidence class
    # cannot recognise is NOT given a contract class and still admits the broad
    # unresolved set, so element 7 cannot be claimed from the contract encoding.
    eg = _EG()
    unknown = _site(0x20)
    unknown["class"] = "field-of-unknown-base"
    eg.sites = {(0x20, 0x21, "call"): unknown}
    apply_evidence_classes(eg, set())
    check("unrecognised edge stays unresolved", unknown["unresolved"], True)
    check("unrecognised edge has no contract class",
          unknown["class"] in ABI_CONTRACT_CLASSES, False)
    e7 = evaluate_predicate_element_7([("control.so", 0x20, unknown)], [])
    check("unrecognised edge keeps element 7 failing", e7["established"], False)
    check("unrecognised edge is target-bounded unresolved",
          e7["target_bounded_unresolved_sites"], 1)
    check("unrecognised edge produces the broad unresolved set",
          e7["contract_bounded_sites"], 0)

    # A site that *is* contract-bounded does not make a *resolved* claim.
    e7 = evaluate_predicate_element_7([("control.so", 0x41, o1)], [])
    check("contract-bounded element 7 passes", e7["established"], True)
    check("contract-bounded still records an unbounded target set",
          e7["target_sets_remain_unbounded"], True)

    # module -> file mapping needs a real tree; use the tool's own repo when present
    repo = Path(__file__).resolve().parents[2]
    if (repo / "src").is_dir():
        check("module mapping", module_to_file("runtime::err", repo / "src"),
              "src/runtime/err.rs")
        check("module mapping mod", module_to_file("runtime::bio::owned", repo / "src"),
              "src/runtime/bio/owned.rs")

    # export-site index on a known export
    if (repo / "src").is_dir():
        index = index_export_sites(repo, ["src/evp/cipher_ctx.rs", "src/evp/e_rc4.rs"])
        check("export index EVP_rc4", "src/evp/e_rc4.rs" in index.get("EVP_rc4", []), True)
        check("export index EVP_CIPHER_CTX_new",
              "src/evp/cipher_ctx.rs" in index.get("EVP_CIPHER_CTX_new", []), True)

    # mechanism routing
    check("mechanism err", mechanism_for("src/runtime/err.rs", {})[0], "ERR")
    check("mechanism bio", mechanism_for("src/runtime/bio/bss_mem.rs", {})[0], "BIO")
    check("mechanism evp", mechanism_for("src/evp/pkey_ctx.rs", {})[0], "EVP_PKEY_PROVIDER")
    check("mechanism ssl", mechanism_for("src/ssl/ssl_lib.rs", {})[0], "SSL_SESSION")
    check("mechanism x509", mechanism_for("src/x509/v3_utl.rs", {})[0], "X509_VERIFY_POLICY")
    check("mechanism none", mechanism_for("src/apps/verify.rs", {})[0], None)
    overrides = {("src/apps/verify.rs", 104, "UNSAFE_FN_DEF"):
                 {"mechanism": "X509_VERIFY_POLICY"}}
    check("mechanism obligation override",
          mechanism_for("src/apps/verify.rs", {},
                        {"line": 104, "kind": "UNSAFE_FN_DEF"},
                        overrides)[0], "X509_VERIFY_POLICY")
    check("mechanism override absent",
          mechanism_for("src/apps/verify.rs", {},
                        {"line": 999, "kind": "UNSAFE_FN_DEF"},
                        overrides)[0], None)

    # ---- v1.2 hole controls (reviewer H1-H10) ----------------------------- #
    # Every control below isolates one check: it is refused when the check is
    # enabled and accepted when that check alone is disabled (see the
    # mutation table in edge-validator-hardening.json).
    MOD = "libfoo.so"

    class _CallerG:
        name = MOD
        funcs = {0x700: "site_func", 0x1000: "target_ok",
                 0x1100: "target_dropped", 0x1200: "excluded_caller",
                 0x1300: "reachable_caller", 0x1400: "target_unreachable",
                 0x2000: "alias_primary", 0x3000: "reachable_target"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}

    def _caller_fixture():
        g = _CallerG()
        g.names_at = {a: set(n) for a, n in _CallerG.funcs.items()}
        g.sites = {(0x700, 0x701, "call"): {
            "kind": "call", "func": 0x700, "addr": 0x701,
            "text": "call *%rax", "targets": {0x1000},
            "unresolved": False, "reason": "reachable-caller target bounding",
            "class": "reachable-caller-target", "field_offsets": set(),
            "arg_deps": {0}, "arg_targets": {0x1100},
            "reachable_caller_bound": {
                "reachable_callers": [{
                    "function": "0x1300", "symbol": "reachable_caller",
                    "reachable": True, "reason": None,
                    "call_sites": [{"call_site": "0x1301", "arguments": [{
                        "argument": 0, "argument_index": 0,
                        "value": ["0x1000"], "targets": ["0x1000"],
                        "non_image_values": [], "unresolved": False,
                        "witness_instruction": [
                            {"addr": "0x12ff", "text": "lea"}]}]}],
                    "contributed_targets": ["0x1000"]}],
                "excluded_callers": [{
                    "function": "0x1200", "symbol": "excluded_caller",
                    "reachable": False,
                    "in_reachable_set": False, "reason": "x",
                    "in_image_references": [],
                    "call_sites": [{"call_site": "0x1201", "arguments": [{
                        "argument": 0, "argument_index": 0,
                        "value": [], "targets": ["0x1100"],
                        "non_image_values": [], "unresolved": True,
                        "witness_instruction": [
                            {"addr": "0x11ff", "text": "mov"}]}]}],
                    "contributed_targets": ["0x1100"]}],
                "bounded_targets": ["0x1000"]}}}
        return g

    def _caller_oracle(g):
        return ReachabilityOracle(
            {MOD: g},
            {(MOD, a) for a in (0x700, 0x1000, 0x1100, 0x1300, 0x3000)})

    def _caller_record(alias=False):
        g = _caller_fixture()
        if alias:
            g.names_at[0x3000] = {"reachable_target", "alias_secondary"}
        oracle = _caller_oracle(g)
        rec = _edge_record(g, g.sites[(0x700, 0x701, "call")], 1, oracle)
        return g, oracle, rec

    def _clone(rec):
        return json.loads(json.dumps(rec))

    gC, oC, rC = _caller_record()
    # H10 positive control: the v1m caller-bound shape.  The dropped target is
    # reachable in its own right; the excluded caller is not.  The claim is
    # caller-scoped, so this must validate cleanly with no audit violation.
    check("H10 v1m caller-bound shape validates cleanly",
          validate_edge_records([rC], oC), [])
    check("H10 dropped target is reachable; the excluded caller is not",
          (oC.is_reachable(MOD, "target_dropped")[0],
           oC.is_reachable(MOD, "excluded_caller")[0]), (True, False))
    check("H10 the audit reports no violation",
          [r for r in reachability_exclusion_audit({MOD: gC}, oC, [rC])
           if r["violation"]], [])

    # ---- round-4 attribution controls ------------------------------------- #
    def _bound_record(reachable_contrib, excluded_contrib, admitted):
        """Build a record from a bound whose contributions we control."""
        g = _caller_fixture()
        site = g.sites[(0x700, 0x701, "call")]
        bound = site["reachable_caller_bound"]
        rrow = bound["reachable_callers"][0]
        rrow["contributed_targets"] = list(reachable_contrib)
        rrow["call_sites"][0]["arguments"][0]["targets"] = \
            list(reachable_contrib)
        erow = bound["excluded_callers"][0]
        erow["contributed_targets"] = list(excluded_contrib)
        erow["call_sites"][0]["arguments"][0]["targets"] = \
            list(excluded_contrib)
        site["targets"] = set(admitted)
        oracle = _caller_oracle(g)
        return g, oracle, _edge_record(g, site, 1, oracle)

    # H11: no caller attributes target_dropped.  It is admitted (widening the
    # upper bound), never dropped, and the record validates cleanly.
    gI, oI, rI = _bound_record(["0x1000"], [], [0x1000])
    check("H11 an unattributed candidate is admitted, not dropped",
          ([e["target"] for e in rI["exclusions"]],
           sorted(rI["exclusion_accounting"]["admitted_targets"]),
           [a["target"] for a in (rI.get("unattributed_admissions") or ())],
           validate_edge_records([rI], oI)),
          ([], ["target_dropped", "target_ok"], ["target_dropped"], []))

    # H12: no caller attributes *any* candidate.  No bounded set is emitted:
    # the record is UNRESOLVED and names the incomplete attribution.
    gZ, oZ, rZ = _bound_record([], [], [])
    check("H12 a wholly unattributable bounding is unresolved",
          (rZ["disposition"], rZ["target_set"],
           rZ["missing_property"],
           rZ["exclusion_accounting"]["admitted_targets"],
           validate_edge_records([rZ], oZ)),
          (DISPOSITION_UNRESOLVED, [],
           ATTRIBUTION_INCOMPLETE_PROPERTY.format(n=1), [], []))

    # H13: a contribution must be the union of its own call-site witness.  The
    # excluded caller keeps its contribution but loses the call site that would
    # witness it, so the drop is unsupported and only this check refuses it.
    h13 = _clone(rC)
    h13["candidate_source"]["excluded_callers"][0]["call_sites"] = []
    check("H13 a contribution without its call-site witness is refused",
          bool(validate_edge_records([h13], oC)), True)

    # H14: an unattributed admission cannot name a contributed target.
    h14 = _clone(rI)
    if h14.get("unattributed_admissions"):
        h14["unattributed_admissions"][0]["target"] = "target_ok"
    check("H14 a forged unattributed admission is refused",
          bool(validate_edge_records([h14], oI)), True)

    # H15: a record with zero attribution cannot claim a bounded set.
    h15 = _clone(rZ)
    h15["disposition"] = DISPOSITION_PROVED
    h15["target_set"] = sorted(rZ["candidate_source"]["targets"])
    h15["target_set_claim"] = True
    h15["target_reachability"] = "claimed"
    h15["missing_property"] = None
    h15["exclusion_accounting"]["admitted_targets"] = sorted(
        rZ["candidate_source"]["targets"])
    h15["semantic_identity"]["provenance_chain"] = [
        {"target": t, "derivation": [{"step": "unattributed-admission",
                                        "reason": "forged"}]}
        for t in h15["target_set"]]
    check("H15 a zero-attribution record cannot claim PROVED_TARGET_SET",
          bool(validate_edge_records([h15], oZ)), True)

    def _target_claim(target, subject, checked=None):
        return {
            "target": target,
            "reason": "target-not-in-reachable-set",
            "row_kind": "target-drop",
            "claim": {"kind": "target-not-in-reachable-set", "module": MOD,
                      "subjects": [subject]},
            "evidence": {"reachable_set_member": False, "symbol": subject,
                         "reachable_basis": "final-upper-bound",
                         "symbols_checked": ([subject] if checked is None
                                              else checked)}}

    # H1: the exclusion target is a different, reachable symbol than the one
    # the evidence names.  v1.1 validated only the evidence symbol.
    h1 = _clone(rC)
    h1["exclusions"] = [_target_claim("reachable_target", "excluded_caller")]
    h1["candidate_source"]["targets"] = ["reachable_target", "target_ok"]
    h1["exclusion_accounting"].update({
        "candidate_targets": ["reachable_target", "target_ok"],
        "excluded_targets": ["reachable_target"]})
    check("H1 target/evidence binding",
          bool(validate_edge_records([h1], oC)), True)

    # H2: the claim is rebound to a different DSO that also reaches the named
    # caller, so only the module-identity rule can catch it.
    class _OtherG:
        name = "libbar.so"
        funcs = {0x1300: "reachable_caller", 0x9000: "other_func"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}

    og = _OtherG()
    o2 = ReachabilityOracle(
        {MOD: gC, "libbar.so": og},
        {(MOD, a) for a in (0x700, 0x1000, 0x1100, 0x1300, 0x3000)}
        | {("libbar.so", 0x1300)})
    h2 = _clone(rC)
    for row in (h2["exclusions"] + (h2.get("excluded_callers") or [])):
        row["claim"]["module"] = "libbar.so"
    check("H2 claim module binding",
          bool(validate_edge_records([h2], o2)), True)

    # H3: an ICF alias at a reachable address.  The oracle must expose every
    # name at the address, not one representative.
    gA, oA, rA = _caller_record(alias=True)
    h3 = _clone(rA)
    h3["exclusions"] = [_target_claim("alias_secondary", "alias_secondary")]
    h3["candidate_source"]["targets"] = ["alias_secondary", "target_ok"]
    h3["exclusion_accounting"].update({
        "candidate_targets": ["alias_secondary", "target_ok"],
        "excluded_targets": ["alias_secondary"]})
    check("H3 ICF alias at a reachable address",
          bool(validate_edge_records([h3], oA)), True)

    # H4: the removed caller-count exemption.  A forged count and an empty
    # symbols_checked list do not excuse the claim; the field is not read (and
    # is not produced), so the row is refused.
    h4 = _clone(rC)
    h4["exclusions"] = [_target_claim("excluded_caller", "excluded_caller",
                                      checked=[])]
    h4["exclusions"][0]["evidence"]["reachable_caller_count"] = 0
    h4["candidate_source"]["targets"] = ["excluded_caller", "target_ok"]
    h4["exclusion_accounting"].update({
        "candidate_targets": ["excluded_caller", "target_ok"],
        "excluded_targets": ["excluded_caller"]})
    check("H4 forged caller count no longer exempts symbols_checked",
          bool(validate_edge_records([h4], oC)), True)
    check("H4 the caller-count exemption is structurally absent",
          "reachable_caller_count" not in json.dumps(rC), True)

    # H5a: no-reachable-writer whose own derived_targets contain the target.
    h5 = _clone(rC)
    h5["exclusions"] = [{
        "target": "target_dropped", "reason": "no-reachable-writer",
        "claim": {"kind": "no-reachable-writer", "module": MOD,
                  "subjects": []},
        "evidence": {"writer": "w",
                     "derived_targets": ["target_dropped", "target_ok"],
                     "reachable_writers": []}}]
    check("H5 no-reachable-writer contradicting its own derived_targets",
          bool(validate_edge_records([h5], oC)), True)

    # H5b: declared-name-absent naming an unrelated absent symbol for a target
    # whose mapping is not explained.
    h5b = _clone(rC)
    h5b["target_reachability"] = "not-claimed"
    h5b["exclusions"] = [{
        "target": "target_dropped", "reason": "declared-name-absent",
        "claim": {"kind": "declared-name-absent", "module": MOD,
                  "subjects": ["unrelated_absent_name"]},
        "evidence": {"declared_name": "unrelated_absent_name",
                     "present": False}}]
    check("H5 declared-name-absent for an unrelated target",
          bool(validate_edge_records([h5b], oC)), True)

    # H6a: a semantic call-site row with included:false naming a reachable
    # caller.  The auxiliary list is untouched, so only the candidate-source
    # walk can catch it.  The record is built against the oracle so the
    # pre-closure-basis defect cannot mask the control.
    h6 = _clone(next(r for r in records_live
                    if r["semantic_identity"]["call_site_role"]
                    == "method-store-slot"))
    h6["candidate_source"]["rows"].append({
        "caller": g5.funcs[0x300], "call_site": "0x999",
        "included": False, "reason": "caller-not-in-reachable-set",
        "targets": []})
    check("H6 semantic included:false caller row is audited",
          bool(validate_edge_records([h6], oracle_live)), True)

    # H6b: the claim omits the reachable caller's contribution.  The
    # recomputable candidate_source still says the reachable caller contributes
    # target_ok, so the claim's mapping disagrees with the source.
    h6b = _clone(rC)
    for row in h6b["exclusions"]:
        if row["reason"] == "not-contributed-by-reachable-callers":
            row["claim"]["reachable_callers"][0]["contributed_targets"] = []
    check("H6 caller-bound dropped target contributed by a reachable caller",
          bool(validate_edge_records([h6b], oC)), True)

    # H7: delete the exclusion and its candidate from the accounting block.
    # candidate_source still names it, so the deletion is refused.
    h7 = _clone(rC)
    h7["exclusions"] = []
    h7["exclusion_accounting"].update({
        "excluded_targets": [], "candidate_targets": ["target_ok"]})
    check("H7 exclusion and candidate both deleted",
          bool(validate_edge_records([h7], oC)), True)

    # H8: an empty admitted set and a definition-less function are resolver
    # gaps, never proofs.
    class _EmptyG:
        name = "empty.so"
        funcs = {0x10: "empty_func", 0x20: "unused"}
        start_set = set(funcs)
        all_syms = dict(funcs)
        names_at = {a: {n} for a, n in funcs.items()}
        sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": set(), "unresolved": False,
            "reason": None, "class": "field", "field_offsets": set(),
            "seam": None, "arg_deps": set()}}

    eG = _EmptyG()
    eRec = build_edge_records({"empty.so": eG})[0]
    check("H8 an empty target set is demoted",
          (eRec["disposition"], eRec["disposition_demotion"]),
          (DISPOSITION_UNRESOLVED, "empty-target-set"))

    class _NoSymG:
        name = "nosym.so"
        funcs = {}
        start_set = set()
        all_syms = {}
        names_at = {}
        sites = {(0x10, 0x11, "call"): {
            "kind": "call", "func": 0x10, "addr": 0x11,
            "text": "call *%rax", "targets": {0x99}, "unresolved": False,
            "reason": None, "class": "field", "field_offsets": set(),
            "seam": None, "arg_deps": set()}}

    nRec = build_edge_records({"nosym.so": _NoSymG()})[0]
    check("H8 a definition-less function is demoted",
          (nRec["disposition"], nRec["disposition_demotion"]),
          (DISPOSITION_UNRESOLVED, "no-defining-symbol"))
    badq = _clone(nRec)
    badq["disposition"] = DISPOSITION_PROVED
    badq["target_set"] = ["<0x99>"]
    badq["target_set_claim"] = True
    check("H8 the validator refuses a proved record with no defining symbol",
          bool(validate_edge_records([badq])), True)

    # H9: two records may not share an identity.  v1.1 seeded ordinals by
    # (function, role) but omitted the role from edge_id.
    check("H9 duplicate edge_id is refused",
          bool(validate_edge_records([_clone(rC), _clone(rC)], oC)), True)

    # ---- v1.3 row-kind, target-drop binding and identity controls ---------- #
    # Every control below is isolated: the mutation table in
    # edge-validator-hardening.json disables exactly the named check and requires
    # this control (and only this control) to change verdict.

    def _declared_rec(target="target_unreachable", listed=None,
                      name="unrelated_absent_name", include_targets=True):
        rec = _clone(rC)
        listed = [target] if listed is None else listed
        evidence = {"declared_name": name, "present": False}
        if include_targets:
            evidence["targets"] = list(listed)
        rec["exclusions"] = [{
            "target": target,
            "reason": "declared-name-absent",
            "row_kind": "target-drop",
            "claim": {"kind": "declared-name-absent", "module": MOD,
                      "subjects": [name]},
            "evidence": evidence,
        }]
        rec["candidate_source"]["targets"] = sorted({"target_ok", target})
        rec["candidate_source"]["excluded_callers"][0][
            "contributed_targets"] = []
        rec["candidate_source"]["excluded_callers"][0]["call_sites"] = []
        rec["exclusion_accounting"].update({
            "candidate_targets": rec["candidate_source"]["targets"],
            "admitted_targets": ["target_ok"],
            "excluded_targets": [target],
            "unaccounted_targets": [],
        })
        return rec

    c_rowkind = _clone(rC)
    c_rowkind["exclusions"][0]["row_kind"] = "subject"
    check("v1.3 exclusion row kind",
          bool(validate_edge_records([c_rowkind], oC)), True)

    c_vocab = _clone(rC)
    c_vocab["exclusions"].append({
        "target": "target_dropped",
        "reason": "writer-not-in-reachable-set",
        "row_kind": "target-drop",
        "claim": {"kind": "writer-not-in-reachable-set", "module": MOD,
                  "subjects": ["excluded_caller"]},
        "evidence": {"reachable_set_member": False,
                     "reachable_basis": "final-upper-bound",
                     "symbol": "excluded_caller",
                     "symbols_checked": ["excluded_caller"],
                     "would_store_targets": ["target_dropped"]}})
    check("v1.3 target-drop reason vocabulary",
          bool(validate_edge_records([c_vocab], oC)), True)

    c_decltext = _declared_rec(include_targets=False)
    c_decltext["exclusions"][0]["claim"]["target_derivation"] = (
        "a free-text claim is not a mapping")
    check("v1.3 declared-name structured targets",
          bool(validate_edge_records([c_decltext], oC)), True)

    c_declmember = _declared_rec(listed=["target_ok"])
    check("v1.3 declared-name target membership",
          bool(validate_edge_records([c_declmember], oC)), True)

    c_declreach = _declared_rec(target="target_dropped",
                                listed=["target_dropped"])
    check("v1.3 declared-name target unreachable",
          bool(validate_edge_records([c_declreach], oC)), True)

    c_declcand = _declared_rec(
        listed=["target_unreachable", "invented_name"])
    check("v1.3 declared-name targets are candidates",
          bool(validate_edge_records([c_declcand], oC)), True)

    c_argmap = _clone(rC)
    del c_argmap["candidate_source"]["callers"]
    check("v1.3 argument-target caller mapping required",
          bool(validate_edge_records([c_argmap], oC)), True)

    # R3: both the claim and candidate_source say a reachable caller
    # contributes the dropped target.  The mapping agrees, but the target is
    # then not droppable and the admitted set is not the reachable image set.
    c_argrecomp = _clone(rC)
    c_argrecomp["candidate_source"]["callers"][0]["contributed_targets"] = [
        "target_ok", "target_dropped"]
    c_argrecomp["candidate_source"]["callers"][0]["call_sites"][0][
        "arguments"][0]["targets"] = ["target_ok", "target_dropped"]
    for row in c_argrecomp["exclusions"]:
        if row["reason"] == "not-contributed-by-reachable-callers":
            row["claim"]["reachable_callers"][0]["contributed_targets"] = [
                "target_ok", "target_dropped"]
    check("v1.3 caller contributions recomputed",
          bool(validate_edge_records([c_argrecomp], oC)), True)

    c_argexcluded = _clone(rC)
    c_argexcluded["candidate_source"]["excluded_callers"][0][
        "contributed_targets"] = ["target_ok"]
    c_argexcluded["candidate_source"]["excluded_callers"][0][
        "call_sites"][0]["arguments"][0]["targets"] = ["target_ok"]
    check("v1.3 dropped target attributed to an excluded caller",
          bool(validate_edge_records([c_argexcluded], oC)), True)

    c_argcand = _clone(rC)
    c_argcand["exclusion_accounting"]["candidate_enumeration"] = "not-applicable"
    c_argcand["candidate_source"]["targets"].append("extra_candidate")
    c_argcand["exclusion_accounting"]["candidate_targets"].append(
        "extra_candidate")
    check("v1.3 candidates equal admitted plus excluded",
          bool(validate_edge_records([c_argcand], oC)), True)

    c_writerwould = _clone(rec0)
    for row in c_writerwould.get("excluded_writers") or ():
        if row.get("reason") == "writer-not-in-reachable-set":
            row["evidence"].pop("would_store_targets", None)
    check("v1.3 writer would_store_targets binding",
          bool(validate_edge_records([c_writerwould])), True)

    c_targetreach = _clone(rC)
    c_targetreach["target_reachability"] = "not-claimed"
    check("v1.3 target_reachability is derived",
          bool(validate_edge_records([c_targetreach], oC)), True)

    with tempfile.TemporaryDirectory() as td:
        wd = Path(td) / "workdir"

        class _A:
            output = str(Path(td) / "receipt.json")
            edge_records = None

        resolved = _edge_records_path(_A(), Path(td), "ab" * 32, wd)
        check("v1.3 sidecar default is under the workdir",
              (resolved.parent == wd,
               resolved.name.startswith("edge-records.")), (True, True))

    tool_identity = _tool_identity()
    check("v1.3 tool identity carries the validator sha256",
          (len(tool_identity.get("sha256") or "") == 64,
           tool_identity.get("schema") == EDGE_RECORD_SCHEMA), (True, True))

    # ---- source-root hash rule collision (AGENTS.md section 22) ----------- #
    # The build record and the build/link atlas both name a "source_root_hash"
    # but hash different things.  Comparing them is a rule collision, not
    # staleness.  The atlas has no rule field because its producer
    # (downstream_build_link._source_root_hash) is canonical-JSON by
    # construction.
    atlas_h = {"source_root_hash": "a" * 64}
    rec_domain = {"source_root_hash": "b" * 64,
                  "source_root_hash_rule": SOURCE_ROOT_HASH_RULE_DOMAIN}
    c1, r1 = source_root_hash_checks(rec_domain, atlas_h)
    check("different source-root hash rules are HASH_RULE_MISMATCH, not STALE_HASH",
          [r["code"] for r in r1], ["HASH_RULE_MISMATCH"])
    check("the mismatch names both rules and their classes",
          (c1["source_root_hash_rule"]["build_record_class"],
           c1["source_root_hash_rule"]["atlas_class"]),
          ("domain-separated-tree", "canonical-json-tree"))
    rec_same = {"source_root_hash": "a" * 64,
                "source_root_hash_rule": SOURCE_ROOT_HASH_RULE_CANONICAL}
    c2, r2 = source_root_hash_checks(rec_same, atlas_h)
    check("equal rules and equal digests pass",
          (r2, c2["source_root_hash_matches_atlas"], c2["hash_rule_matches"]),
          ([], True, True))
    c3, r3 = source_root_hash_checks(
        dict(rec_same, source_root_hash="c" * 64), atlas_h)
    check("equal rules with different digests stay STALE_HASH",
          [r["code"] for r in r3], ["STALE_HASH"])
    c4, r4 = source_root_hash_checks(
        dict(rec_domain, source_tree_domain_hash="e" * 64),
        {"source_root_hash": "a" * 64, "source_tree_domain_hash": "d" * 64})
    check("a domain-hash difference is STALE_HASH",
          sorted(r["code"] for r in r4), ["HASH_RULE_MISMATCH", "STALE_HASH"])

    if failures:
        print("[consumer-closure] SELF-TEST FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print(f"[consumer-closure] self-test ok: parsing, adjudication truth table, "
          f"module/file mapping, export-site index, mechanism routing, precision "
          f"narrowing, unclassified-site negative control, R1/R2/R3/A2/O1 "
          f"evidence-class controls, the per-call-site witness rule "
          f"(AGENTS.md section 22), the in-image slot target rule "
          f"(reachable-writer and static-initialiser negative controls), "
          f"reachable-caller target bounding (fixed-vs-parameter caller controls), "
          f"per-edge provenance records (unaccounted/unwitnessed exclusion "
          f"refusal), mutually redundant target accounting, the closed "
          f"derivation vocabulary, the final-upper-bound reachability oracle "
          f"(writer-exclusion negative and positive controls), the v1.2 "
          f"subject-scoped claim controls (H1 target/evidence binding, H2 module "
          f"binding, H3 ICF aliases, H4 caller-count exemption removal, H5 "
          f"self-contradicting evidence, H6 audit coverage, H7 candidate deletion, "
          f"H8 vacuous-set demotion, H9 duplicate identities, H10 v1m "
          f"caller-scoped positive control), the v1.3 row-kind and "
          f"target-binding controls (row kind, reason vocabulary, structured "
          f"declared targets, target attribution, recomputed caller "
          f"contributions, candidate equality, writer would_store_targets, "
          f"derived target_reachability, sidecar default and tool identity), the "
          f"least-fixed-point residual admission (nested unresolved dispatch, "
          f"non-convergence refusal), the monotone class-independent site bound, "
          f"the analysis identity (DSO digest is not an identity; sections, "
          f"relocations, defined and dynamic symbols and loader entries are "
          f"bound), admission by refutation (refuted caller admitted and closure "
          f"recomputed, surviving exclusion validated, infinite contribution "
          f"demoted to UNRESOLVED), the symbolic-target dispositions "
          f"(blocking refusal, names-at alias, dynamic symbol, PLT stub, "
          f"external contract), and the mutation matrix (single pass, class-"
          f"narrowed bound, refusal removed, admission disabled, unconditional "
          f"admission, unresolved-symbol refusal removed), and the source-backed "
          f"S2/S3/S4 witness controls (exported-callback parameter, fetched "
          f"provider slot, local function-pointer assignment; every refusal "
          f"condition is mutation-tested)")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--family")
    ap.add_argument("--artifact", help="exact downstream binary or DSO")
    ap.add_argument("--install", default="artifacts/phase2/install")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("--inventory",
                    default="forensics/memory-safety/campaign/safe-c33/atlas-refresh/"
                            "v1-candidate-freeze.json")
    ap.add_argument("--state",
                    default="forensics/memory-safety/campaign/safe-c33/state.json")
    ap.add_argument("--campaign-status",
                    default="forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json")
    ap.add_argument("--boundary-dir",
                    default="forensics/memory-safety/campaign/safe-c33/atlas-refresh")
    ap.add_argument("--ledger", default="forensics/downstream/build-link-atlas.json")
    ap.add_argument("--trace", help="optional observed-execution trace (JSON)")
    ap.add_argument("--build-record",
                    help="optional provenance JSON for a rebuilt downstream artefact")
    ap.add_argument("--workdir", default="court/tmp/v4-consumer-closure")
    ap.add_argument("--skip-graph-on-refusal", action="store_true",
                    help="stop after identity/import refusals; used for negative controls")
    ap.add_argument("--output")
    ap.add_argument("--edge-records",
                    help="explicit JSONL sidecar path; the default is "
                         "<workdir>/edge-records.<artifact_sha[:16]>.jsonl and "
                         "is never written beside --output")
    ap.add_argument("--max-record-sample", type=int,
                    default=EDGE_RECORD_SAMPLE_DEFAULT,
                    help="maximum records embedded in the receipt sample; the "
                         "full population is always written to the JSONL "
                         "sidecar")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument(
        "--carry-forward-closure",
        help="previously ACCEPTED closure receipt whose enumerated obligations are "
             "carried forward into this queue; must be the same family and "
             "artifact name")
    ap.add_argument(
        "--carry-forward-dir", default="court/inventory",
        help="directory scanned for the most recent ACCEPTED closure when "
             "--carry-forward-closure is omitted")
    ap.add_argument(
        "--no-carry-forward", action="store_true",
        help="control only: do not carry forward a previous closure (the queue is "
             "then not monotone under documentation edits)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.family or not args.artifact:
        ap.error("--family and --artifact are required unless --self-test is used")

    receipt = build_receipt(args)
    if args.output:
        out = Path(args.output)
        if not out.is_absolute():
            out = Path(args.repo).resolve() / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"[consumer-closure] wrote {out}")
    if args.summary or not args.output:
        c = receipt["counts"]
        print(f"[consumer-closure] family={receipt['family']} "
              f"verdict={receipt['verdict']['state']}")
        print(f"  reachable files={c['reachable_files']} "
              f"obligations={c['reachable_production_obligations']} "
              f"DISCHARGED={c['DISCHARGED']} BLOCKED={c['BLOCKED']} "
              f"UNKNOWN={c['UNKNOWN']}")
        print(f"  carried_forward={c['carried_forward']} "
              f"removed={c['carried_forward_removed']} "
              f"removed_by_reason={c['carried_forward_removed_by_reason']} "
              f"stale_discharge_rejections={c['stale_discharge_rejections']}")
        cf = receipt["documented_enrollment"].get("carry_forward") or {}
        for r in cf.get("removed") or []:
            ev = r.get("reachable_file_evidence") or {}
            print(f"  CARRIED-REMOVED {r.get('file')}:{r.get('line')} "
                  f"{r.get('kind')} {r.get('item')} reason={r.get('reason')} "
                  f"(reachable_files={ev.get('reachable_file_count')} "
                  f"artifact_sha256={str(ev.get('artifact_sha256'))[:12]})")
        for o in receipt["obligations"]:
            for sj in o.get("stale_discharge_rejections") or []:
                print(f"  STALE-DISCHARGE-REFUSED {o['id']} boundary={sj['boundary']} "
                      f"range={sj['declared_range_for_file']} "
                      f"previous={sj['previous_coordinate']} "
                      f"current={sj['current_coordinate']}")
        p = receipt["precision"]["totals"]
        print(f"  precision: indirect={p['indirect_sites']} "
              f"resolved={p['resolved_sites']} unresolved={p['unresolved_sites']} "
              f"reachable_unresolved={p['reachable_unresolved_sites']} "
              f"target_bounded={p['reachable_target_bounded_unresolved_sites']} "
              f"contract_bounded={p['reachable_contract_bounded_sites']} "
              f"unclassified={p['unclassified_reachable_sites']}")
        e7 = receipt["precision"]["predicate_element_7"]
        print(f"  element-7={e7['status']} "
              f"contract_bounded_by_class={e7['contract_bounded_by_class']}")
        cl = receipt["graph"]["closure"]
        print(f"  closure: rounds={cl['closure_rounds']} "
              f"converged={cl['converged']} "
              f"reachable_functions={cl['reachable_functions_count']} "
              f"sha256={cl['reachable_functions_sha256']} "
              f"analysis_identity={cl['analysis_identity']['digest']}")
        for r in receipt["refusals"]:
            print(f"  REFUSAL {r['code']}: {r['detail']}")
    return 0 if receipt["verdict"]["state"] == "ACCEPTED" else 1


if __name__ == "__main__":
    sys.exit(main())
