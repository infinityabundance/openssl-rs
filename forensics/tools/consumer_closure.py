#!/usr/bin/env python3
"""Consumer-closure engine for the safe-c33 campaign (V4).

The campaign's C2/C3 receipts describe the intended shape of a consumer
closure but record that no automated generator exists.  This tool builds one.

For a named downstream family it:

1. takes the exact downstream artefact and resolves the loader's *observed*
   library resolution for every ``DT_NEEDED`` OpenSSL soname, recording the
   artefact and each resolved DSO by SHA-256;
2. builds a conservative reachable-call graph over the exact candidate DSOs:
   imported versioned symbols are the roots, direct call edges come from the
   linked machine code, and function pointers, callbacks, provider dispatch
   tables, constructors/destructors and allocator hooks enter through
   address-taken code/data references.  A dynamic trace, when supplied, is
   recorded as observed execution only; it never narrows the graph, because
   executing a function does not prove unobserved paths unreachable;
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
direct call in the exact candidate machine code and every function whose
address is materialised in an executable or data section.  Functions never
called indirectly are not reachable; functions called indirectly are all
admitted once any reachable function performs an unresolved indirect call.
Inlining is not represented: an inlined callee's unsafe sites are attributed
to the caller's file only when the compiler emitted no out-of-line function
for it.  This is a reachability analysis, not a proof of memory safety, and
``DISCHARGED`` here means only that an existing receipt covers the exact site;
it does not re-audit the receipt.

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
        self.workdir = workdir
        self.funcs = self._function_symbols()
        self.starts = sorted(self.funcs)
        self.start_set = set(self.starts)
        self.direct = collections.defaultdict(set)
        self.indirect_sites = 0
        self.indirect_funcs = collections.Counter()
        self.taken_code = set()
        self.taken_data = set()
        self._disassemble()

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

    def _section_bytes(self, wanted: str):
        out = run(["readelf", "-SW", str(self.path)]).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 7 or parts[1] != wanted:
                continue
            try:
                off = int(parts[4], 16)
                size = int(parts[5], 16)
            except ValueError:
                continue
            with open(self.path, "rb") as fh:
                fh.seek(off)
                return fh.read(size)
        return b""

    def _disassemble(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        dis = self.workdir / (self.name + ".dis")
        if not dis.exists():
            with open(dis, "w") as fh:
                subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(self.path)],
                               stdout=fh, check=True)
        pat_head = re.compile(r"^([0-9a-f]+) <(.*)>:$")
        pat_ins = re.compile(r"^\s+([0-9a-f]+):\t(.*)$")
        pat_direct = re.compile(r"^(?:call|jmp)\w*\s+([0-9a-f]+) <")
        pat_comment = re.compile(r"#\s*([0-9a-f]+)\s+<")
        cur = None
        with open(dis, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                m = pat_head.match(line)
                if m:
                    cur = int(m.group(1), 16)
                    continue
                m = pat_ins.match(line)
                if not m or cur is None:
                    continue
                text = m.group(2)
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


def build_graph(graphs: dict, roots: set, export_index: dict) -> dict:
    """Union reachability over all candidate DSOs.

    ``roots`` is a set of (dso_name, address).  Direct edges stay inside one
    DSO; a call/PLT reference to an exported symbol of another candidate DSO is
    carried across.  Any unresolved indirect call reachable anywhere admits the
    union of all address-taken functions (the conservative upper bound)."""
    reach = set(roots)
    frontier = list(roots)
    taken_all = set()
    for g in graphs.values():
        taken_all |= {(g.name, a) for a in g.taken}
    while frontier:
        nxt = []
        for dso_name, addr in frontier:
            g = graphs[dso_name]
            for target in g.direct.get(addr, ()):
                node = (dso_name, target)
                if node not in reach:
                    reach.add(node)
                    nxt.append(node)
            # a PLT/direct target that is an exported symbol of another DSO
            sym = g.funcs.get(addr)
            if sym:
                base = sym.split("@")[0]
                other = export_index.get(base)
                if other and other not in reach:
                    reach.add(other)
                    nxt.append(other)
        frontier = nxt
    indirect_reachable = sum(
        1 for dso_name, addr in reach
        if graphs[dso_name].indirect_funcs.get(addr))
    upper = set(reach)
    if indirect_reachable:
        # An unresolved indirect call can target any address-taken function.
        # Those functions are not leaves: their own direct callees must also be
        # admitted, otherwise the "upper bound" would silently drop code that a
        # reachable indirect target calls directly.
        upper |= taken_all
        frontier = list(upper)
        while frontier:
            nxt = []
            for dso_name, addr in frontier:
                g = graphs[dso_name]
                for target in g.direct.get(addr, ()):
                    node = (dso_name, target)
                    if node not in upper:
                        upper.add(node)
                        nxt.append(node)
                sym = g.funcs.get(addr)
                if sym:
                    other = export_index.get(sym.split("@")[0])
                    if other and other not in upper:
                        upper.add(other)
                        nxt.append(other)
            frontier = nxt
    return {
        "direct_reachable": reach,
        "upper_reachable": upper,
        "indirect_reachable_functions": indirect_reachable,
        "address_taken_union": taken_all,
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


def mechanism_for(file: str, mechanisms: dict) -> tuple[str | None, str]:
    for mid, rec in mechanisms.items():
        if file in (rec.get("converted_files_on_branch") or []):
            return mid, "converted_files_on_branch"
    for pat, mid in MECHANISM_RULES:
        if pat.search(file):
            return mid, "directory-rule:" + pat.pattern
    return None, "unmapped"


def load_boundaries(boundary_dir: Path) -> tuple[dict, dict]:
    """Return (by_file, by_id) across every boundary-sweep receipt."""
    by_file = collections.defaultdict(list)
    by_id = {}
    paths = sorted(boundary_dir.glob("boundary-sweep-B*.json"))
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

    for p in dso_paths.values():
        graphs[p.name] = DsoGraph(p, workdir)

    root_nodes = set()
    for imp in imported:
        target = export_index.get(imp["name"])
        if target and target[0] in graphs:
            root_nodes.add((target[0], target[1]))
    for g in graphs.values():
        for addr in g.init_roots():
            root_nodes.add((g.name, addr))

    closure = build_graph(graphs, root_nodes, export_index)
    direct_reach = closure["direct_reachable"]
    upper_reach = closure["upper_reachable"]

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
    special_edges = {
        "constructor_destructor_roots": sum(len(g.init_roots()) for g in graphs.values()),
        "address_taken_functions_admitted": len(closure["address_taken_union"]),
        "address_taken_data_pointers": sum(len(g.taken_data) for g in graphs.values()),
        "allocator_hook_registrars_reachable": allocator_hooks,
        "callback_registrars_reachable_count": len(callback_registrars),
        "callback_registrars_reachable_sample": callback_registrars[:40],
        "dynamic_name_lookup_reachable": dynamic_lookup,
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
        mech, basis = mechanism_for(f, mechanisms)
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
        "tool": {"path": TOOL, "version": 2},
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
                "function-level static graph over the exact candidate DSOs: "
                "nm-defined functions, objdump direct call edges, address-taken code "
                "references, function pointers in .data.rel.ro/.data/.rodata, "
                ".init_array/.fini_array roots; unresolved indirect calls admit all "
                "address-taken functions (conservative upper bound)"),
            "upper_bound_rule": (
                "once any reachable function performs an unresolved indirect call, every "
                "function whose address is materialised anywhere in the candidate DSOs "
                "is admitted; the upper bound is the reachable set used for adjudication"),
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
                    "unresolved_indirect_sites": g.indirect_sites,
                    "functions_with_unresolved_indirect_calls": len(g.indirect_funcs),
                    "address_taken_code_refs": len(g.taken_code),
                    "address_taken_data_pointers": len(g.taken_data),
                } for name, g in graphs.items()
            },
            "observed_trace": trace,
            "limits": [
                "inlined callees have no out-of-line function node; their code is "
                "attributed to the caller, so a source file whose only contribution is "
                "inlined has no node of its own",
                "unresolved indirect calls are not resolved per call site; the bound "
                "admits the global address-taken set instead of guessing a target",
                "a dynamic trace proves execution, not unreachability, and never "
                "narrowed this graph",
                "function-level reachability is not a proof that a site is safe; it "
                "bounds which obligations apply",
            ],
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

    if failures:
        print("[consumer-closure] SELF-TEST FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print(f"[consumer-closure] self-test ok: parsing, adjudication truth table, "
          f"module/file mapping, export-site index, mechanism routing")
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
        for r in receipt["refusals"]:
            print(f"  REFUSAL {r['code']}: {r['detail']}")
    return 0 if receipt["verdict"]["state"] == "ACCEPTED" else 1


if __name__ == "__main__":
    sys.exit(main())
