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
   boundary receipts that own them;
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

    def _elf_sections(self) -> dict:
        out = {}
        for line in run(["readelf", "-SW", str(self.path)]).stdout.splitlines():
            toks = line.split()
            if not toks or not toks[0].startswith("["):
                continue
            if toks[0] == "[":
                name = toks[2]
                try:
                    addr, off, size = int(toks[4], 16), int(toks[5], 16), int(toks[6], 16)
                except (ValueError, IndexError):
                    continue
            else:
                name = toks[1]
                try:
                    addr, off, size = int(toks[3], 16), int(toks[4], 16), int(toks[5], 16)
                except (ValueError, IndexError):
                    continue
            out[name] = (addr, off, size)
        return out

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
        g.address_taken_union = (set(g.taken_code) | set(g.taken_data)
                                 | {v for vs in g.slot_funcs.values() for v in vs})
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
ABI_CONTRACT_CLASSES = frozenset({ABI_CONTRACT_PROVIDER, ABI_CONTRACT_ALLOCATOR})

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
REACHABLE_CALLER_SCHEMA = (
    "openssl-rs/consumer-closure/reachable-caller-target-bound/v1")

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


def _semantic_provenance_resolver(g: "DsoGraph") -> "PrecisionResolver":
    r = getattr(g, "_semantic_precision", None)
    if r is None:
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
    r = _semantic_provenance_resolver(g)
    idx = {}
    try:
        for caller, callee, args, addr in r.calls:
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
    recorded, not admitted.  Any non-image argument from a reachable caller, a
    caller whose reachability cannot be established, or a non-argument target
    keeps the site unresolved.

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
    reachable_rows, excluded_rows = [], []
    for caller in sorted(callers):
        recs = records.get(caller) or {}
        if caller not in reachable:
            excluded_rows.append(_caller_exclusion(g, caller, import_addrs))
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
                arg_rows.append({
                    "argument": k,
                    "value": [hex(v) for v in sorted(vals)],
                    "witness_instruction": (
                        [{"addr": hex(w[0]), "text": w[1]}] if w else []),
                })
            call_rows.append({"call_site": hex(call_addr), "arguments": arg_rows})
        bounded |= caller_targets
        reachable_rows.append({
            "function": hex(caller),
            "symbol": getattr(g, "funcs", {}).get(caller, "?"),
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
    }, None


def _image_defines(g: "DsoGraph", fragments) -> bool:
    """True when at least one named writer is defined in this exact image."""
    if isinstance(fragments, str):
        fragments = (fragments,)
    names = set(g.all_syms.values()) if hasattr(g, "all_syms") else set()
    return any(fragment in (n or "") for fragment in fragments for n in names)


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
            site["targets"] = set(targets)
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
        stats["unmatched"] += 1
    g.evidence_classes.update(stats)
    g.residual_sites = [s for s in g.sites.values() if s["unresolved"]]
    g.resolved_targets = {t for s in g.sites.values() for t in s["targets"]}
    g.precision_counts = collections.Counter((s["class"], s["unresolved"])
                                             for s in g.sites.values())
    return dict(stats)


# --------------------------------------------------------------------------- #
# per-edge provenance records (AGENTS.md sections 7 and 22)
# --------------------------------------------------------------------------- #
#
# Every indirect site the resolver classifies emits a record that separates what
# the analysis proved from what it approximated.  The identity is semantic (the
# source operation, defining function, call-site role and a per-target provenance
# chain); a machine address is recorded only as an artifact-local witness.  A
# target is only ever dropped with a reason that the record itself carries
# evidence for; `validate_edge_records` refuses an unaccounted exclusion, and
# `build_receipt` turns that refusal into a refusal of the whole closure.

EDGE_RECORD_SCHEMA = "openssl-rs/campaign/safe-c33/edge-record/v1"
DISPOSITION_PROVED = "PROVED_TARGET_SET"
DISPOSITION_CONTRACT = "CONTRACT_BOUNDED"
DISPOSITION_UNRESOLVED = "UNRESOLVED"
DISPOSITIONS = (DISPOSITION_PROVED, DISPOSITION_CONTRACT,
                DISPOSITION_UNRESOLVED)
EXCLUSION_REASONS = frozenset({
    "not-in-reachable-set",
    "no-reachable-writer",
    "provenance-unbounded",
    "declared-name-absent",
    "non-image-value",
})
# Each reason names the evidence that makes it checkable.  A free-text reason is
# not a reason: the validator requires these fields to be present and non-null.
EXCLUSION_EVIDENCE_KEYS = {
    "not-in-reachable-set": ("reachable_set_member", "symbol"),
    "no-reachable-writer": ("writer", "derived_targets"),
    "provenance-unbounded": ("failure",),
    "declared-name-absent": ("declared_name", "present"),
    "non-image-value": ("value",),
}


def _edge_symbol(g, value) -> str:
    """The semantic name of a target; an address is never the identity."""
    if isinstance(value, tuple) and value and value[0] == "sym":
        return str(value[1]).split("@")[0]
    if isinstance(value, int):
        sym = ((getattr(g, "funcs", {}) or {}).get(value)
               or (getattr(g, "all_syms", {}) or {}).get(value))
        return str(sym).split("@")[0] if sym else f"<{value:#x}>"
    return str(value)


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


def _edge_disposition(site: dict) -> str:
    if site.get("class") in ABI_CONTRACT_CLASSES:
        return DISPOSITION_CONTRACT
    if site.get("unresolved"):
        return DISPOSITION_UNRESOLVED
    return DISPOSITION_PROVED


def _edge_record(g, site: dict, ordinal: int) -> dict:
    fstart = site.get("func", 0)
    name = (getattr(g, "funcs", {}) or {}).get(fstart, "?")
    disposition = _edge_disposition(site)
    role = _edge_role(site)
    admitted = sorted(_edge_symbol(g, t) for t in (site.get("targets") or ()))
    candidates = set(admitted)
    enumeration = "resolver-admitted-set"
    exclusions = []
    extra = {}
    chains = collections.defaultdict(list)

    semantics = site.get("semantic_store_target")
    edge_witness = site.get("edge_target_witness")
    caller_bound = site.get("reachable_caller_bound")
    if semantics is not None:
        # Only a resolved derivation enumerates its candidates.  An unresolved
        # row may contain a partial target set from rows that did not fail; it
        # is not a candidate set and must not be reported as if it were.
        enumeration = ("complete" if semantics.get("resolved")
                       else "not-applicable")
        candidates = set()
        stored_values = semantics.get("stored_values") or {}
        for row in semantics.get("call_sites") or ():
            base = [
                {"step": "store-writer", "writer": row.get("writer"),
                 "argument_index": row.get("argument_index")},
                {"step": "call-site", "caller": row.get("caller"),
                 "call_site": row.get("call_site")},
            ]
            sub = []
            _edge_chain_steps(g, row.get("chain") or (), sub)
            if row.get("included") is False:
                extra.setdefault("excluded_callers", []).append({
                    "caller": row.get("caller"),
                    "call_site": row.get("call_site"),
                    "reason": "not-in-reachable-set",
                    "evidence": {"reachable_set_member": False,
                                 "symbol": row.get("caller")},
                })
                continue
            if row.get("failure"):
                extra.setdefault("unbounded_call_sites", []).append({
                    "caller": row.get("caller"),
                    "call_site": row.get("call_site"),
                    "reason": "provenance-unbounded",
                    "evidence": {"failure": row.get("failure")},
                })
                continue
            for hx in row.get("targets") or ():
                nm = _edge_symbol(g, int(stored_values.get(hx, hx), 16))
                if semantics.get("resolved"):
                    candidates.add(nm)
                    chains[nm].extend(base + sub)
        for collapse in semantics.get("thunk_collapses") or ():
            nm = _edge_symbol(g, int(collapse["semantic"], 16))
            chains[nm].append({
                "step": "thunk",
                "from_symbol": _edge_symbol(g, int(collapse["stored"], 16)),
                "to_symbol": nm,
            })
        for w in semantics.get("excluded_writers") or ():
            would = w.get("would_store_targets") or []
            if not w.get("would_store_failure") and not would:
                continue
            reason = ("declared-name-absent" if w.get("reason") ==
                      "absent from the image" else "not-in-reachable-set")
            for hx in would:
                nm = _edge_symbol(g, int(hx, 16))
                if semantics.get("resolved"):
                    candidates.add(nm)
                exclusions.append({
                    "target": nm,
                    "reason": reason,
                    "evidence": ({
                        "declared_name": w.get("fragment"),
                        "present": False,
                        "fragment": w.get("fragment"),
                    } if reason == "declared-name-absent" else {
                        "reachable_set_member": False,
                        "symbol": w.get("symbol"),
                        "writer_address": w.get("address"),
                        "would_store": list(would),
                    }),
                })
            if w.get("would_store_failure"):
                extra.setdefault("excluded_writers", []).append({
                    "symbol": w.get("symbol"),
                    "writer_address": w.get("address"),
                    "reason": "provenance-unbounded",
                    "evidence": {"failure": w["would_store_failure"]},
                })
        cross = semantics.get("declared_cross_check") or {}
        if semantics.get("resolved"):
            for frag in cross.get("declared_but_absent") or ():
                exclusions.append({
                    "target": frag,
                    "reason": "declared-name-absent",
                    "evidence": {"declared_name": frag, "present": False},
                })
            deref = set(admitted)
            for frag, info in (cross.get("declared_targets") or {}).items():
                if not info.get("present"):
                    continue
                for hx in info.get("addresses") or ():
                    nm = _edge_symbol(g, int(hx, 16))
                    candidates.add(nm)
                    if nm not in deref:
                        exclusions.append({
                            "target": nm,
                            "reason": "no-reachable-writer",
                            "evidence": {
                                "writer": "the reachable method-store writers",
                                "derived_targets": sorted(deref),
                                "declared_name": frag,
                                "address": hx},
                        })
        else:
            extra["semantic_refusal"] = semantics.get("refusal")
        extra["source_of_truth"] = "stored-value provenance"
        extra["slot"] = semantics.get("slot")
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
        candidates |= {_edge_symbol(g, t)
                       for t in (site.get("arg_targets") or ())}
        excluded_callers = caller_bound.get("excluded_callers") or []
        for row in caller_bound.get("reachable_callers") or ():
            steps = [{"step": "argument", "caller": row.get("symbol")}]
            for cs in row.get("call_sites") or ():
                for arg in cs.get("arguments") or ():
                    for wi in arg.get("witness_instruction") or ():
                        steps.append({"step": "code-materialised",
                                      "instruction": wi.get("text")})
            for hx in row.get("contributed_targets") or ():
                chains[_edge_symbol(g, int(hx, 16))].extend(steps)
        for dropped in sorted(candidates - set(admitted)):
            exclusions.append({
                "target": dropped,
                "reason": "not-in-reachable-set",
                "evidence": {
                    "reachable_set_member": False,
                    "symbol": dropped,
                    "excluded_callers": [
                        {"symbol": c.get("symbol"),
                         "function": c.get("function"),
                         "reference": c.get("reason")}
                        for c in excluded_callers],
                },
            })
        for c in excluded_callers:
            extra.setdefault("excluded_callers", []).append({
                "caller": c.get("symbol"),
                "reason": "not-in-reachable-set",
                "evidence": {"reachable_set_member": False,
                             "symbol": c.get("symbol"),
                             "in_image_references": c.get("in_image_references")},
            })
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

    chain_rows = [{"target": nm, "derivation": chains[nm]}
                  for nm in sorted(chains)]
    admitted_set = set(admitted)
    excluded_set = {e["target"] for e in exclusions if e.get("target")}
    accounted = admitted_set | excluded_set
    unaccounted = sorted(candidates - accounted) if enumeration == "complete" else []

    missing = None
    if disposition == DISPOSITION_UNRESOLVED:
        missing = ((semantics or {}).get("refusal")
                   or site.get("reason")
                   or "the resolver recorded no target set and no reason")

    return {
        "schema": EDGE_RECORD_SCHEMA,
        "edge_id": f"{name}::{site.get('kind')}::{ordinal}",
        "semantic_identity": {
            "source_operation": site.get("text"),
            "operation_kind": site.get("kind"),
            "defining_function": name,
            "call_site_role": role,
            "provenance_chain": chain_rows,
            "artifact_local_witness": {
                "module": getattr(g, "name", "?"),
                "function_address": hex(fstart),
                "site_address": hex(site.get("addr", 0)),
                "identity_note": ("addresses are artifact-local witnesses; "
                                  "they are not the identity of the edge"),
            },
        },
        "disposition": disposition,
        "target_set": admitted if disposition == DISPOSITION_PROVED else [],
        "target_set_claim": disposition == DISPOSITION_PROVED,
        "witness_id": extra.get("witness_id"),
        "missing_property": missing,
        "exclusions": exclusions,
        **{k: v for k, v in extra.items() if k not in ("witness_id",)},
        "exclusion_accounting": {
            "candidate_enumeration": enumeration,
            "candidate_targets": sorted(candidates),
            "admitted_targets": sorted(admitted_set),
            "excluded_targets": sorted(excluded_set),
            "unaccounted_targets": unaccounted,
        },
    }


def build_edge_records(graphs: dict) -> list:
    """One provenance record for every indirect site in every closed DSO."""
    records = []
    for dso_name in sorted(graphs):
        g = graphs[dso_name]
        ordinals = collections.Counter()
        keys = sorted(getattr(g, "sites", {}) or {},
                      key=lambda k: (k[0], k[1], str(k[2])))
        for key in keys:
            site = g.sites[key]
            seed = (site.get("func"), _edge_role(site))
            ordinals[seed] += 1
            records.append(_edge_record(g, site, ordinals[seed]))
    return records


def validate_edge_records(records: list) -> list:
    """Every exclusion must be checkable; an unaccounted target is a defect."""
    defects = []
    for rec in records:
        rid = rec.get("edge_id", "?")
        disposition = rec.get("disposition")
        ident = rec.get("semantic_identity") or {}
        for field in ("source_operation", "defining_function", "call_site_role"):
            if not ident.get(field):
                defects.append(f"{rid}: semantic identity lacks {field}")
        if disposition not in DISPOSITIONS:
            defects.append(f"{rid}: unknown disposition {disposition!r}")
            continue
        if disposition == DISPOSITION_PROVED and not rec.get("target_set"):
            defects.append(f"{rid}: PROVED_TARGET_SET with an empty target set")
        if disposition == DISPOSITION_CONTRACT and not rec.get("witness_id"):
            defects.append(f"{rid}: CONTRACT_BOUNDED without a witness id")
        if disposition == DISPOSITION_UNRESOLVED and not rec.get("missing_property"):
            defects.append(f"{rid}: UNRESOLVED without a missing property")
        for ex in rec.get("exclusions") or ():
            reason = ex.get("reason")
            if reason not in EXCLUSION_REASONS:
                defects.append(
                    f"{rid}: excluded target {ex.get('target')!r} has no "
                    "checkable reason")
                continue
            evidence = ex.get("evidence")
            if not isinstance(evidence, dict) or not evidence:
                defects.append(
                    f"{rid}: exclusion {ex.get('target')!r} ({reason}) has no "
                    "evidence")
                continue
            absent = [k for k in EXCLUSION_EVIDENCE_KEYS[reason]
                      if evidence.get(k) is None]
            if absent:
                defects.append(
                    f"{rid}: exclusion {ex.get('target')!r} ({reason}) lacks "
                    "evidence fields " + ", ".join(absent))
        accounting = rec.get("exclusion_accounting") or {}
        if accounting.get("candidate_enumeration") == "complete":
            # Recompute from the record itself rather than trusting the stored
            # accounting block: a stale or edited block must not hide a dropped
            # target.
            candidates = set(accounting.get("candidate_targets") or ())
            admitted = set(accounting.get("admitted_targets") or ())
            excluded = {e.get("target") for e in (rec.get("exclusions") or ())}
            unaccounted = sorted(candidates - admitted - excluded - {None})
            if unaccounted:
                defects.append(
                    f"{rid}: excluded target(s) without a reason: "
                    + ", ".join(unaccounted[:8]))
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


def edge_closure_refusal(records: list):
    """Validate a record set and return (defects, refusal).  A refusal here is
    the object `build_receipt` appends before emitting the closure."""
    defects = validate_edge_records(records)
    return defects, edge_refusal_for(defects)


def edge_record_summary(records: list) -> dict:
    counts = collections.Counter(r.get("disposition") for r in records)
    reasons = collections.Counter(
        e.get("reason") for r in records for e in (r.get("exclusions") or ()))
    return {
        "schema": EDGE_RECORD_SCHEMA,
        "count": len(records),
        "dispositions": dict(sorted(counts.items())),
        "exclusion_reasons": dict(sorted(reasons.items())),
    }


def build_graph(graphs: dict, roots: set, export_index: dict,
                import_nodes: set | None = None) -> dict:
    """Union reachability over all candidate DSOs, with per-site targets.

    Direct call edges come from the linked machine code.  Indirect sites carry
    the target set the precision resolver established.  A site whose value is
    genuinely data-dependent is admitted at its **evidence class** (a field
    offset, an argument summary, or a code-materialised address), never from a
    trace.  Only a site whose operand cannot be classified at all admits the
    global address-taken union; the receipt records every such site.
    """
    import_nodes = import_nodes or set()
    site_edges = collections.defaultdict(set)
    sites_by_func = collections.defaultdict(list)
    for g in graphs.values():
        for key, s in getattr(g, "sites", {}).items():
            fstart = key[0]
            sites_by_func[g.name].append((fstart, s))
            for t in s["targets"]:
                node = None
                if isinstance(t, int):
                    node = (g.name, t)
                elif isinstance(t, tuple) and t[0] == "sym":
                    node = export_index.get(t[1])
                if node is not None:
                    site_edges[(g.name, fstart)].add(node)

    def walk(initial, extra_for):
        reach = set(initial)
        frontier = list(initial)
        while frontier:
            nxt = []
            for dso_name, addr in frontier:
                g = graphs[dso_name]
                targets = set(g.direct.get(addr, ()))
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

    direct_reach = walk(roots, None)

    # residual bounds, computed per DSO from evidence classes
    residual_bound = set()
    unclassified = set()
    reachable_residual_sites = []
    for dso_name, addr in direct_reach:
        g = graphs[dso_name]
        for fstart, s in sites_by_func.get(dso_name, ()):
            if fstart != addr or not s["unresolved"]:
                continue
            reachable_residual_sites.append((dso_name, addr, s))
            if s["class"] == "unclassified":
                unclassified.add((dso_name, addr, s["reason"]))
                residual_bound |= {(dso_name, a) for a in g.address_taken_union}
            else:
                residual_bound |= {(dso_name, a) for a in g.taken_code}
                for vals in getattr(g, "field_stores", {}).values():
                    residual_bound |= {(dso_name, v) for v in vals
                                      if isinstance(v, int) and v in g.start_set}
                residual_bound |= {(dso_name, v) for v in
                                   getattr(g, "unknown_call_arg_targets", ())
                                   if v in g.start_set}
    residual_bound |= {n for n in import_nodes if n[0] in graphs}

    upper = walk(set(direct_reach) | residual_bound, None)
    return {
        "direct_reachable": direct_reach,
        "upper_reachable": upper,
        "address_taken_union": {(g.name, a) for g in graphs.values()
                                for a in g.address_taken_union},
        "resolved_site_targets": {n for edges in site_edges.values() for n in edges},
        "residual_bound": residual_bound,
        "reachable_residual_sites": reachable_residual_sites,
        "unclassified_sites": sorted(unclassified, key=lambda x: (x[0], x[1])),
        "indirect_reachable_functions": len({f for dso_name, f, _s in
                                             reachable_residual_sites}),
    }


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
    for mid, rec in mechanisms.items():
        if file in (rec.get("converted_files_on_branch") or []):
            return mid, "converted_files_on_branch"
    for pat, mid in MECHANISM_RULES:
        if pat.search(file):
            return mid, "directory-rule:" + pat.pattern
    return None, "unmapped"


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

    # 2. a scoped discharge, only for the exact ranges its disposition names
    scoped_attempt = []
    for b in boundaries:
        rec = plane["scoped_boundary_discharges"].get(b["id"])
        if not rec:
            continue
        ranges = scoped_ranges(b.get("disposition") or "")
        hit = any(lo <= obligation["line"] <= hi
                  for lo, hi in ranges.get(obligation["file"], []))
        scoped_attempt.append({"boundary": b["id"], "receipt": rec.get("receipt"),
                               "declared_ranges": {k: v for k, v in ranges.items()},
                               "covers_site": hit})
        if hit:
            obligation["status"] = "DISCHARGED"
            obligation["discharge_receipt"] = rec.get("receipt") or rec.get("artifact")
            obligation["status_reason"] = (
                f"boundary {b['id']} is scoped-SAFETY_DISCHARGED and its disposition "
                f"explicitly names line {obligation['line']}")
            obligation["scoped_discharge_attempts"] = scoped_attempt
            return obligation
    if scoped_attempt:
        obligation["scoped_discharge_attempts"] = scoped_attempt

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

def build_receipt(args) -> dict:
    repo = Path(args.repo).resolve()
    install = (repo / args.install).resolve()
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
            "tool": {"path": TOOL, "version": 3},
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
    direct_reach = closure["direct_reachable"]
    upper_reach = closure["upper_reachable"]

    # ---- edge provenance records ----------------------------------------- #
    # Every indirect site emits a semantic record.  An exclusion without a
    # checkable reason is a defect, and the closure refuses rather than
    # emitting a record that silently dropped a target.
    edge_records = build_edge_records(graphs)
    edge_defects, edge_refusal = edge_closure_refusal(edge_records)
    if edge_refusal is not None:
        refusals.append(edge_refusal)

    # Reachable-caller bounding uses the pre-closure reachable set, while the
    # final upper bound can admit a few additional targets from evidence
    # classes.  An "excluded" caller that the final upper bound admits would
    # make the exclusion unsafe, so the closure refuses rather than accepting
    # the narrowed set.
    rcb_audit = []
    for g in graphs.values():
        for s in g.sites.values():
            rcb = s.get("reachable_caller_bound")
            if not rcb:
                continue
            for excluded in rcb["excluded_callers"]:
                node = (g.name, int(excluded["function"], 16))
                rcb_audit.append({
                    "dso": g.name,
                    "site": hex(s["addr"]),
                    "excluded_caller": excluded["function"],
                    "excluded_symbol": excluded["symbol"],
                    "in_final_upper_bound": node in upper_reach,
                })
    rcb_violations = [r for r in rcb_audit if r["in_final_upper_bound"]]
    if rcb_violations:
        refusals.append({
            "code": "RCB_EXCLUDED_CALLER_REACHABLE",
            "detail": (
                "a caller excluded by reachable-caller target bounding is in "
                "the final upper bound: "
                + ", ".join(f"{r['excluded_symbol']} at {r['site']}"
                             for r in rcb_violations)),
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
    blockers = (inventory.get("contracts") or {}).get("blockers") or []
    production = [b for b in blockers if b.get("partition") == V1_PARTITION_PRODUCTION]
    obligations = []
    for b in production:
        f = b.get("file")
        if f not in files_upper:
            continue
        mech, basis = mechanism_for(f, mechanisms, b, obligation_mechanisms)
        obligations.append({
            "id": f"V1:{f}:{b.get('line')}:{b.get('kind')}",
            "file": f,
            "line": b.get("line"),
            "kind": b.get("kind"),
            "partition": b.get("partition"),
            "v1_reason": b.get("reason"),
            "mechanism": mech,
            "mechanism_basis": basis,
            "status": None,
            "discharge_receipt": None,
            "status_reason": None,
        })
    obligations.sort(key=lambda o: (o["file"], o["line"] or 0, o["kind"] or ""))
    for o in obligations:
        adjudicate(o, mechanisms, boundaries_by_file.get(o["file"], []), plane)

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
            if ledger and ledger.get("source_root_hash") and rec.get("source_root_hash"):
                checks["source_root_hash_matches_atlas"] = (
                    rec["source_root_hash"] == ledger["source_root_hash"])
            if not checks.get("artifact_sha256_matches", True):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record artefact digest does not match the "
                                           "analysed artefact"})
            if not checks.get("install_prefix_matches", True):
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record install prefix does not match the "
                                           "admitted install"})
            if checks.get("source_root_hash_matches_atlas") is False:
                refusals.append({"code": "STALE_HASH",
                                 "detail": "build record pristine source tree hash does not "
                                           "match the atlas row for the same recipe"})
            build_record = {"path": rel(bp, repo), "record": rec, "checks": checks}

    # ---- 9. receipt ------------------------------------------------------- #
    source_head = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    branch = run(["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    dirty = bool(run(["git", "-C", str(repo), "status", "--porcelain",
                      "--untracked-files=no"]).stdout.strip())

    verdict_state = "REFUSED" if refusals else "ACCEPTED"
    receipt = {
        "schema": SCHEMA,
        "tool": {"path": TOOL, "version": 3},
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
                "direct edges + the resolver's per-site target sets + the residual class "
                "(functions address-materialised in reachable code, consumer-imported "
                "symbols, values stored into object fields by reachable code, and values "
                "passed at unresolved call sites); the global address-taken union is "
                "admitted only for an unclassified site, and any such site is listed "
                "in precision.unclassified_reachable_sites"),
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
                {"dso": d, "function": hex(f), "reason": s["reason"],
                 "class": s["class"], "text": s["text"][:160]}
                for d, f, s in closure["reachable_residual_sites"][:80]],
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
                    "in this family's reachable set; a non-image argument from any "
                    "reachable caller, an unknown caller, or a non-argument target "
                    "keeps the site unresolved"),
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
                         "bounded_targets"]}
                    for name, g in graphs.items() for s in g.sites.values()
                    if s.get("reachable_caller_bound")],
                "count": sum(
                    1 for g in graphs.values() for s in g.sites.values()
                    if s.get("reachable_caller_bound")),
                "excluded_caller_audit": rcb_audit,
                "excluded_caller_violations": rcb_violations,
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
            **(edge_record_summary(edge_records)),
            "rule": (
                "every indirect site emits a semantic identity (source "
                "operation, defining function, call-site role, per-target "
                "provenance chain) plus a disposition; an address is recorded "
                "only as an artifact-local witness; every excluded target "
                "carries a checkable reason and the evidence used"),
            "refusal_rule": (
                "a target dropped without a checkable exclusion reason, or an "
                "exclusion without evidence, refuses the closure with "
                "EDGE_RECORD_EXCLUSION_UNSOUND"),
            "defects": edge_defects,
            "records": edge_records,
        },
        "obligations": obligations,
        "closure_scope": {
            "v1_production_operations": len(production),
            "included_in_upper_bound": len(obligations),
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
            "No crate build, test, Miri, ASan or cryptographic court was run by this tool.",
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
    def ob(file, line, mech):
        return {"file": file, "line": line, "mechanism": mech, "status": None,
                "discharge_receipt": None, "status_reason": None}
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
                     [{"id": "B23-WPKT-1", "disposition": "SAFETY_DISCHARGED"}],
                     plane)["status"],
          "BLOCKED")
    check("scoped range covers site",
          adjudicate(ob("src/ssl/x.rs", 40, "SSL_SESSION"), mechs,
                     [{"id": "B23-WPKT-1",
                       "disposition": "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)"}],
                     plane)["status"],
          "DISCHARGED")
    check("scoped range does not blanket-discharge",
          adjudicate(ob("src/ssl/x.rs", 999, "SSL_SESSION"), mechs,
                     [{"id": "B23-WPKT-1",
                       "disposition": "SAFETY_DISCHARGED (scope: src/ssl/x.rs:30-50)"}],
                     plane)["status"],
          "BLOCKED")
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
    check("materialised class does not admit global table entry",
          (g.name, 0x30) in narrow["upper_reachable"], False)

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
    check("reachable fixed caller resolves the site", s["unresolved"], False)
    check("reachable fixed caller bounds the target set", s["targets"], {0x50})
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
              and e.get("reason") == "not-in-reachable-set"
              for e in rec0["exclusions"]), True)

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
          f"and per-edge provenance records (unaccounted/unwitnessed exclusion "
          f"refusal)")
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
    ap.add_argument("--summary", action="store_true")
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
        for r in receipt["refusals"]:
            print(f"  REFUSAL {r['code']}: {r['detail']}")
    return 0 if receipt["verdict"]["state"] == "ACCEPTED" else 1


if __name__ == "__main__":
    sys.exit(main())
