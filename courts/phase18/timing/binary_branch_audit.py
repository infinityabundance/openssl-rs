#!/usr/bin/env python3
"""binary_branch_audit.py -- per-function branch/division/cmov audit of the
built libcrypto DSO.

REVIEW AID, NOT A PROOF.  This script says what instructions the compiler
emitted in a named function's address range.  It does NOT establish that a
branch condition is secret-dependent: that needs taint tracking at the binary
level (BINSEC -checkct with a validated -sse-script, T16, is not yet
validated).  Every row must be read against the Rust source, whose function
carries the secret classification.

What is measured for each named function (looked up in the DSO's symbol table,
so the range is the compiler's own function boundary, not a hand-picked
window):

  * every conditional jump, with
      - the nearest preceding flag-setting instruction inside the same basic
        block (the condition's provenance: register compare, memory compare,
        memory arithmetic, ...),
      - the fall-through window to the next control transfer, tagged
        ``memory`` when it reads/writes memory, ``division`` when it contains
        div/idiv, ``call`` when it calls, else ``arithmetic/control``;
  * div/idiv instructions (latency and, on x86, possible variable timing);
  * cmov*, setcc and loop/overflow-check branch families (jo/jno), which are
    what "cmov versus branch lowering" and "overflow-checks in release"
    questions turn on;
  * direct call targets containing dispatch-looking names, and any cpuid in
    the range, for the CPU-feature-dispatch question.

Invocation (inside the court, from /work):

    python3 courts/phase18/timing/binary_branch_audit.py \
        artifacts/phase2/install/lib/libcrypto.so.3 > court/tmp/t14/branch-audit.md

The DSO should be the one produced by forensics/tools/build_phase2.sh (the
Phase 2 link of target/release/libopenssl_rs.a).  The script prints the DSO
digest so a receipt can bind the measurement to the artefact.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass

# (family, short symbol name).  The short name is the final length-prefixed
# identifier of the Rust v0 mangled symbol, matched exactly so that e.g.
# `mod_inverse_consttime` is not confused with `BN_mod_inverse_consttime`.
TARGETS = [
    ("Montgomery multiply (core)", "mont_mul_into"),
    ("Montgomery multiply (allocating wrapper)", "mont_mul_fallible"),
    ("Constant-time ladder core", "mod_exp_core_consttime_from_parts"),
    ("Constant-time inversion", "mod_inverse_consttime"),
    ("ECDSA scalar ladder (driver)", "ossl_ec_scalar_mul_ladder"),
    ("EC ladder step (secret core)", "ossl_ec_GFp_simple_ladder_step"),
    ("RSA CRT arms", "rsa_ossl_mod_exp"),
]

FLAG_SETTERS = {
    "test", "cmp", "add", "sub", "sbb", "adc", "and", "or", "xor",
    "inc", "dec", "neg", "shl", "sal", "shr", "sar", "rol", "ror",
    "rcl", "rcr", "mul", "imul", "bt", "bts", "btr", "btc", "popcnt",
    "lzcnt", "tzcnt", "andn",
}

SYMBOL_RE = re.compile(r"^([0-9a-f]+)\s+[lg]\s+F\s+\.text\s+([0-9a-f]+)\s+(\S+)\s*$")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*)$")


@dataclass
class Insn:
    addr: int
    mnem: str
    ops: str

    @property
    def text(self) -> str:
        return f"{self.mnem} {self.ops}".strip()


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def symbol_table(dso: str) -> list[tuple[int, int, str]]:
    """Defined .text symbols as (address, size, full symbol)."""
    out: list[tuple[int, int, str]] = []
    for line in run(["objdump", "-t", dso]).splitlines():
        m = SYMBOL_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    return out


def find_symbols(symtab: list[tuple[int, int, str]], name: str):
    """All defined .text symbols whose v0-mangled final identifier is exactly
    `name`.

    The suffix is length-prefixed, so `mod_inverse_consttime` cannot match
    `BN_mod_inverse_consttime`. Every match is returned: this auditor is a gate,
    so an ambiguous name must be refused rather than resolved to whichever
    symbol happened to be first in the table.
    """
    suffix = f"{len(name)}{name}"
    return [(addr, size, sym) for addr, size, sym in symtab
            if sym.endswith(suffix)]


def disassemble(dso: str, start: int, stop: int) -> list[Insn]:
    text = run([
        "objdump", "-d", "--no-show-raw-insn",
        f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", dso,
    ])
    insns: list[Insn] = []
    for line in text.splitlines():
        m = INSN_RE.match(line)
        if not m:
            continue
        insns.append(Insn(int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return insns


def is_jcc(insn: Insn) -> bool:
    return insn.mnem.startswith("j") and insn.mnem not in {"jmp", "jmpq"}


def is_control(insn: Insn) -> bool:
    return insn.mnem.startswith("j") or insn.mnem in {"ret", "retq", "call", "callq"}


def target_of(insn: Insn) -> int | None:
    m = re.match(r"\s*([0-9a-f]+)\s", insn.ops + " ")
    return int(m.group(1), 16) if m else None


def has_mem(ops: str) -> bool:
    return "(" in ops


def base_mnem(mnem: str) -> str:
    """Strip the AT&T operand-size suffix (`decl`, `cmpq`, `divl`, ...)."""
    if len(mnem) > 2 and mnem[-1] in "bwlq" and mnem[:-1] in FLAG_SETTERS | {"div", "idiv"}:
        return mnem[:-1]
    return mnem


def cond_provenance(insns: list[Insn], i: int) -> tuple[str, Insn | None]:
    """Nearest flag-setting instruction before the jump, within the block."""
    for j in range(i - 1, max(-1, i - 30), -1):
        insn = insns[j]
        if is_control(insn):
            break
        mnem = base_mnem(insn.mnem)
        if mnem not in FLAG_SETTERS:
            continue
        if mnem in {"div", "idiv"}:
            return "div (no flags)", insn
        src = "mem" if has_mem(insn.ops) else "reg/arith"
        return src, insn
    return "unknown", None


def guarded_window(insns: list[Insn], i: int) -> tuple[str, list[Insn]]:
    """What the fall-through path touches before the next control transfer."""
    window: list[Insn] = []
    tags: set[str] = set()
    for j in range(i + 1, min(len(insns), i + 11)):
        insn = insns[j]
        window.append(insn)
        if base_mnem(insn.mnem) in {"div", "idiv"}:
            tags.add("division")
        elif has_mem(insn.ops):
            tags.add("memory")
        elif insn.mnem in {"call", "callq"}:
            tags.add("call")
        if is_control(insn):
            break
    if not tags:
        tags.add("arithmetic/control")
    return "+".join(sorted(tags)), window


def audit(dso: str, family: str, short: str, symtab) -> tuple[str, dict, list[dict]]:
    matches = find_symbols(symtab, short)
    if not matches:
        return family, {"failure": "missing", "short": short}, []
    if len(matches) > 1:
        return family, {"failure": "ambiguous", "short": short,
                        "candidates": [s for _, _, s in matches]}, []
    addr, size, sym = matches[0]
    if size == 0:
        size = 16
    insns = disassemble(dso, addr, addr + size)
    if not insns:
        return family, {"failure": "empty-disassembly", "short": short,
                        "symbol": sym, "addr": addr, "size": size}, []
    rows: list[dict] = []
    counts = {
        "symbol": sym, "addr": addr, "size": size, "insns": len(insns),
        "jcc": 0, "div": 0, "cmov": 0, "setcc": 0, "jo": 0, "loop": 0,
        "calls": 0, "cpuid": 0, "dispatch_calls": [], "div_rows": [],
        "missing": False, "failure": None,
    }
    for i, insn in enumerate(insns):
        if insn.mnem == "cpuid":
            counts["cpuid"] += 1
        if base_mnem(insn.mnem) in {"div", "idiv"}:
            counts["div"] += 1
            counts["div_rows"].append((insn.addr, insn.text))
        if insn.mnem.startswith("cmov"):
            counts["cmov"] += 1
        if insn.mnem.startswith("set"):
            # `setcc` family; x86 has no arithmetic mnemonic beginning with `set`.
            counts["setcc"] += 1
        if insn.mnem in {"jo", "jno"}:
            counts["jo"] += 1
        if insn.mnem in {"loop", "loope", "loopne"}:
            counts["loop"] += 1
        if insn.mnem in {"call", "callq"}:
            counts["calls"] += 1
            cm = re.search(r"<([^>]+)>", insn.ops)
            if cm:
                name = cm.group(1)
                if any(k in name.lower() for k in
                       ("cpuid", "x25519_fe64_eligible", "ia32cap", "aesni",
                        "avx", "dispatch", "ifunc", "cpu_indicator")):
                    counts["dispatch_calls"].append((insn.addr, name))
        if not is_jcc(insn):
            continue
        counts["jcc"] += 1
        src, setter = cond_provenance(insns, i)
        guarded, _ = guarded_window(insns, i)
        tgt = target_of(insn)
        direction = "?" if tgt is None else ("back" if tgt < insn.addr else "fwd")
        rows.append({
            "family": family, "addr": insn.addr, "off": insn.addr - addr,
            "jcc": insn.mnem, "src": src,
            "setter": "?" if setter is None else f"0x{setter.addr:x}: {setter.text}",
            "guarded": guarded, "target": "?" if tgt is None else f"0x{tgt:x}",
            "dir": direction,
        })
    return family, counts, rows


def scan_cpuid(dso: str) -> tuple[int, list[int]]:
    text = run(["objdump", "-d", "--no-show-raw-insn", dso])
    addrs = []
    for line in text.splitlines():
        m = INSN_RE.match(line)
        if m and m.group(2) == "cpuid":
            addrs.append(int(m.group(1), 16))
    return len(addrs), addrs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dso", nargs="?",
                    default="artifacts/phase2/install/lib/libcrypto.so.3")
    ap.add_argument("--no-cpuid-scan", action="store_true",
                    help="skip the whole-DSO cpuid scan")
    args = ap.parse_args()

    digest = hashlib.sha256(open(args.dso, "rb").read()).hexdigest()
    symtab = symbol_table(args.dso)
    results = [audit(args.dso, fam, short, symtab) for fam, short in TARGETS]

    print("# Binary branch audit — review aid, not a proof")
    print()
    print(f"- DSO: `{args.dso}`")
    print(f"- SHA-256: `{digest}`")
    print(f"- objdump: `{run(['objdump', '--version']).splitlines()[0]}`")
    print("- Secret-dependence is NOT established here. A conditional jump is")
    print("  listed because the compiler emitted it in the named function; the")
    print("  reviewer maps each condition to the Rust source's secret")
    print("  classification. BINSEC `-checkct` (T16) is not yet validated.")
    print()
    print("## Per-function summary")
    print()
    print("| function | symbol @ offset | bytes | insns | jcc | div/idiv | cmov | setcc | jo/jno | loop | calls | cpuid |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for fam, c, _ in results:
        if c.get("failure"):
            if c["failure"] == "ambiguous":
                cand = ", ".join(f"`{s}`" for s in c.get("candidates", [])[:3])
                print(f"| {fam} | **ambiguous** (`{c['short']}`: {cand}) | | | | | | | | | | |")
            else:
                print(f"| {fam} | **{c['failure']}** (`{c['short']}`) | | | | | | | | | | |")
            continue
        print(f"| {fam} | `{c['symbol']}` @ 0x{c['addr']:x} | {c['size']} | "
              f"{c['insns']} | {c['jcc']} | {c['div']} | {c['cmov']} | "
              f"{c['setcc']} | {c['jo']} | {c['loop']} | {c['calls']} | {c['cpuid']} |")

    failures = [(fam, c) for fam, c, _ in results if c.get("failure")]
    print()
    print("## Coverage")
    print()
    print(f"- expected targets: {len(TARGETS)}")
    print(f"- resolved uniquely and disassembled: {len(TARGETS) - len(failures)}")
    print(f"- failed: {len(failures)}")
    for fam, c in failures:
        extra = ""
        if c["failure"] == "ambiguous":
            extra = " candidates: " + ", ".join(c.get("candidates", []))
        print(f"  - {fam} (`{c['short']}`): {c['failure']}{extra}")

    print()
    print("## Divisions")
    print()
    any_div = False
    for fam, c, _ in results:
        for addr, text in c.get("div_rows", []):
            any_div = True
            print(f"- **{fam}** `+0x{addr - c['addr']:x}` (0x{addr:x}): `{text}`")
    if not any_div:
        print("- none in any audited range.")

    print()
    print("## Dispatch-looking direct calls in the audited ranges")
    print()
    any_dispatch = False
    for fam, c, _ in results:
        for addr, name in c.get("dispatch_calls", []):
            any_dispatch = True
            print(f"- **{fam}** `+0x{addr - c['addr']:x}` -> `{name}`")
    if not any_dispatch:
        print("- none.")

    if not args.no_cpuid_scan:
        n, addrs = scan_cpuid(args.dso)
        in_range = []
        for fam, c, _ in results:
            if c.get("failure"):
                continue
            for a in addrs:
                if c["addr"] <= a < c["addr"] + c["size"]:
                    in_range.append((fam, a))
        print()
        print("## Whole-DSO cpuid scan")
        print()
        print(f"- `cpuid` instructions in the DSO: **{n}**")
        print(f"- of those inside the audited ranges: **{len(in_range)}**")
        if addrs[:20]:
            print("- first addresses: " + ", ".join(f"0x{a:x}" for a in addrs[:20]))

    print()
    print("## Conditional jumps, per branch")
    print()
    print("`src` is the nearest preceding flag-setting instruction's operand class "
          "(mem = the flags were computed against a memory operand); `guarded` is "
          "what the fall-through window touches before the next transfer. Neither "
          "is a secret-taint result.")
    print()
    print("| function | offset | jcc | src | setter | guarded | target | dir |")
    print("|---|---:|---|---|---|---|---:|---|")
    for fam, c, rows in results:
        for r in rows:
            print(f"| {fam} | +0x{r['off']:x} | {r['jcc']} | {r['src']} | "
                  f"`{r['setter']}` | {r['guarded']} | {r['target']} | {r['dir']} |")
    if failures:
        print()
        print("FAIL-CLOSED: one or more named targets were not resolved to a "
              "single non-empty function. This report is not a gate result.",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
