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
   callback parameters.  A site that cannot be resolved is admitted at its
   evidence class (field / materialised / argument); only a site with no class at
   all admits the global address-taken union, and every such site is listed in the
   receipt.  A dynamic trace, when supplied, is recorded as observed execution
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
        self.calls = []
        self.summary = collections.defaultdict(lambda: [set() for _ in _ARGREGS])
        self.summary_open = collections.defaultdict(set)
        self.exports = set(g.dynamic_defs.values())
        self.import_addrs = set(imports or ())
        self.class_counts = collections.Counter()
        self.unknown_call_args = set()
        self.returns = collections.defaultdict(set)

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

    def switch_targets(self, base):
        if base in self.switch_cache:
            return self.switch_cache[base]
        sec = self.g.section_of(base)
        targets = set()
        if sec:
            a, _off, size = self.g.sections[sec]
            data = self.g._section_bytes(sec)
            start = base - a
            end = min(len(data) - 3, start + 65536)
            for i in range(start, end, 4):
                v = struct.unpack_from("<i", data, i)[0]
                tgt = base + v
                if tgt in self.g.start_set:
                    targets.add(tgt)
        self.switch_cache[base] = targets
        return targets

    def resolve_set(self, f, vals):
        if vals is None:
            return set(), True
        out = set()
        for b in vals:
            if isinstance(b, tuple) and b[0] == "arg":
                out |= self.summary[f][b[1]]
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
            for caller, callee, args in self.calls:
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
            return self.slot_value(addr) if addr is not None else PValue()
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
                  klass, field_offsets=()):
        key = (fstart, addr, kind)
        prev = self.sites.get(key)
        if prev is None:
            self.sites[key] = {
                "kind": kind, "func": fstart, "addr": addr, "text": text,
                "targets": set(targets), "unresolved": unresolved,
                "reason": reason, "class": klass,
                "field_offsets": set(field_offsets),
            }
            return
        prev["targets"] |= targets
        prev["field_offsets"] |= set(field_offsets)
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
                for x in sv.s:
                    if isinstance(x, tuple) and x[0] == "arg":
                        targets |= self.summary[fstart][x[1]]
                    elif isinstance(x, tuple) and x[0] == "field":
                        targets |= self.field_bound(x[1])
                    elif isinstance(x, tuple) and x[0] == "sym":
                        targets.add(x)
                    elif isinstance(x, int) and x in self.g.start_set:
                        targets.add(x)
                    elif isinstance(x, int) and x == 0:
                        pass
                    else:
                        unresolved = True
                self.note_site(kind, fstart, addr, text, targets, unresolved,
                               "stack-slot" if not unresolved else "stack-slot-partial",
                               "resolved" if not unresolved else "materialised")
                return targets, unresolved
            base = _as_value(frame.regs.get(m.group(2)))
            if base.is_top():
                self.note_site(kind, fstart, addr, text, self.field_bound(off),
                               True, "field-of-unknown-base", "field",
                               field_offsets={off})
                return self.field_bound(off), True
            targets, unresolved = set(), False
            for b in base.s:
                if isinstance(b, tuple) and b[0] == "arg":
                    targets |= self.field_bound(off)
                    for tb in {x for x in self.summary[fstart][b[1]]
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
                           klass, field_offsets={off})
            return targets, unresolved
        if opnd in frame.regs:
            v = _as_value(frame.regs[opnd])
            if v.is_top():
                self.note_site(kind, fstart, addr, text, set(), True, "reg-top",
                               "materialised")
                return set(), True
            resolved, arg_open = set(), False
            for b in v.s:
                if isinstance(b, tuple) and b[0] == "arg":
                    vals = self.summary[fstart][b[1]]
                    resolved |= vals
                    if not vals and b[1] in self.summary_open[fstart]:
                        arg_open = True
                else:
                    resolved.add(b)
            v = PValue(frozenset(resolved))
            targets, unresolved, switch, partial = set(), arg_open, set(), set()
            field_offsets = set()
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
                targets |= self.switch_targets(t)
            klass = "resolved" if not unresolved else "materialised"
            self.note_site(kind, fstart, addr, text, targets, unresolved,
                           "reg-value" if not unresolved else
                           "reg-value-partial[" + ",".join(sorted(partial)) + "]",
                           klass, field_offsets=field_offsets)
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
                out |= self.summary[f][b[1]]
            elif isinstance(b, tuple) and b[0] == "field":
                out |= self.field_bound(b[1])
            elif isinstance(b, tuple) and b[0] == "sym":
                addr = self.g.dynamic_defs.get(b[1])
                out.add(addr if addr is not None else 0)
            elif isinstance(b, int):
                out.add(b)
        return PValue(frozenset(out)) if out else PValue.one(0)

    def escape(self, frame, v):
        if v.is_top():
            return
        for b in v.s:
            if isinstance(b, tuple) and b[0] in ("rsp", "rbp"):
                frame.escaped.add(b)

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
            targets, _unres = self.analyze_transfer(
                "call", frame, fstart, addr, text, opnd)
            retvals = set()
            for t in targets:
                if isinstance(t, int):
                    self.calls.append((fstart, t, args))
                    retvals |= self.returns.get(t, set())
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
            m = re.match(r"^([0-9a-f]+)", rest)
            callee = None
            if m:
                callee = self.g.containing(int(m.group(1), 16))
                if callee is not None:
                    self.calls.append((fstart, callee, args))
            for r in _CALLER_SAVED:
                frame.regs[r] = PValue()
            if callee is not None and self.returns.get(callee):
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
            return
        if mn in ("nop", "nopw", "nopl") or mn.startswith("data16") or mn.startswith("cs"):
            return
        if mn in ("cmp", "test", "ucomiss", "comiss", "ptest", "bt"):
            return
        if mn.startswith(("push", "pop")):
            if mn == "push":
                frame.rsp -= 8
                if ops:
                    self.escape(frame, self.eval(frame, ops[0]))
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

    def run(self):
        for pass_no in (1, 2, 3):
            if pass_no == 2:
                self.build_summary()
                self.sites = {}
                self.store_slots = collections.defaultdict(set)
                self.field_stores = collections.defaultdict(set)
                self.field_open = set()
                self.unknown_call_args = set()
            elif pass_no == 3:
                self.build_summary()
                self.sites = {}
                self.store_slots = collections.defaultdict(set)
                self.field_stores = collections.defaultdict(set)
                self.field_open = set()
                self.unknown_call_args = set()
            self.calls = []
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

    closure = build_graph(graphs, root_nodes, export_index, import_nodes)
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
                "unclassified_reachable_sites": len(closure["unclassified_sites"]),
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
            "settled": ("the only reachable unresolved sites are field- or "
                        "materialised-class sites; no unclassified site is reachable"
                        if not closure["unclassified_sites"] else
                        "at least one reachable site has no evidence class and admits "
                        "the global address-taken union"),
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
          f"narrowing and unclassified-site negative control")
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
        for r in receipt["refusals"]:
            print(f"  REFUSAL {r['code']}: {r['detail']}")
    return 0 if receipt["verdict"]["state"] == "ACCEPTED" else 1


if __name__ == "__main__":
    sys.exit(main())
