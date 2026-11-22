#!/usr/bin/env python3
"""binary_branch_audit.py -- per-function branch/division/cmov audit of the
built libcrypto DSO.

REVIEW AID, NOT A PROOF.  This script says what instructions the compiler
emitted in a named function's address range.  It does NOT establish that a
branch condition is secret-dependent: that needs taint tracking at the binary
level (BINSEC -checkct with a validated -sse-script, T16).  Every row must be
read against the Rust source, whose function carries the secret classification.

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

    # bind the run to an artefact digest (refused on mismatch)
    python3 courts/phase18/timing/binary_branch_audit.py \
        --expect-sha256 <hex> artifacts/phase2/install/lib/libcrypto.so.3

The DSO should be the one produced by forensics/tools/build_phase2.sh (the
Phase 2 link of target/release/libopenssl_rs.a).  The script prints the DSO
digest so a receipt can bind the measurement to the artefact.

Fail-closed contract (the exit status is authoritative; the report is a
convenience):

  0  every target in the inventory resolved to exactly one symbol with a
     non-zero size, and its disassembly was non-empty, aligned to the symbol
     start, contiguous, and covered the declared extent.
  1  one or more targets were refused: missing, ambiguous symbol, zero-size
     (unknown extent), empty disassembly, misaligned start, a hole in the
     decoded stream, or a truncated range.  The specific target and reason are
     named on stderr.
  2  the invocation or the tool failed: unreadable/unsupported DSO, objdump
     absent, objdump failure or timeout, malformed targets inventory.
  3  --expect-sha256 did not match the DSO that was about to be audited.

Symbol resolution is exact and unique.  A Rust v0 mangled identifier is
length-prefixed, so the final identifier is matched only when the digits
immediately before it parse to exactly its length; an identifier whose length
merely *ends* with those digits is not a match.  More than one match is refused
rather than resolved to whichever symbol came first in the table.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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

EXIT_OK = 0
EXIT_TARGET = 1
EXIT_USAGE = 2
EXIT_IDENTITY = 3

# Longest x86-64 instruction is 15 bytes.  A larger step between two decoded
# instruction addresses means bytes in the declared range were never decoded.
MAX_INSN_BYTES = 15


class Refusal(Exception):
    """A condition that makes the audit's population invalid."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Insn:
    addr: int
    mnem: str
    ops: str

    @property
    def text(self) -> str:
        return f"{self.mnem} {self.ops}".strip()


def objdump_bin() -> str:
    return os.environ.get("OBJDUMP", "objdump")


def run(cmd: list[str], timeout: float, what: str) -> str:
    """Run a tool, refusing on absence, failure or timeout.

    Every subprocess this auditor starts is bounded: a hung objdump is a
    refusal, never an unbounded wait and never an empty result read as a pass.
    """
    exe = cmd[0]
    if shutil.which(exe) is None:
        raise Refusal(EXIT_USAGE, f"{what}: executable not found: {exe}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Refusal(EXIT_USAGE, f"{what}: timeout after {timeout:g}s: {' '.join(cmd)}")
    except OSError as exc:
        raise Refusal(EXIT_USAGE, f"{what}: cannot run {exe}: {exc}")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        detail = detail[0][:200] if detail else "(no diagnostic)"
        raise Refusal(
            EXIT_USAGE,
            f"{what}: exited {proc.returncode}: {' '.join(cmd)}: {detail}",
        )
    return proc.stdout


def read_dso(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise Refusal(EXIT_USAGE, f"cannot read DSO '{path}': {exc}")
    if not data:
        raise Refusal(EXIT_USAGE, f"DSO '{path}' is empty")
    if data[:4] != b"\x7fELF":
        head = data[:4].hex()
        raise Refusal(
            EXIT_USAGE,
            f"unsupported format: '{path}' is not an ELF file (first bytes {head})",
        )
    return data


def symbol_table(dso: str, timeout: float) -> list[tuple[int, int, str]]:
    """Defined .text symbols as (address, size, full symbol)."""
    out: list[tuple[int, int, str]] = []
    text = run([objdump_bin(), "-t", dso], timeout, "objdump -t")
    for line in text.splitlines():
        m = SYMBOL_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    return out


def find_symbols(symtab: list[tuple[int, int, str]], name: str):
    """All defined .text symbols whose v0-mangled final identifier is exactly
    `name`.

    Rust v0 mangles an identifier as "<decimal length><identifier>", so the
    match is accepted only when the digits immediately preceding the name parse
    to exactly ``len(name)``.  A plain ``endswith`` test is not sufficient: an
    identifier of length 117 named ``mont_mul_into`` would end with
    ``13mont_mul_into`` and be accepted by it.  Every match is returned; the
    caller refuses an ambiguous name rather than resolving it to whichever
    symbol happened to be first in the table.
    """
    pattern = re.compile(r"(\d+)" + re.escape(name) + r"$")
    matches = []
    for addr, size, sym in symtab:
        m = pattern.search(sym)
        if m and int(m.group(1)) == len(name):
            matches.append((addr, size, sym))
    return matches


def disassemble(dso: str, start: int, stop: int, timeout: float) -> list[Insn]:
    text = run([
        objdump_bin(), "-d", "--no-show-raw-insn",
        f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", dso,
    ], timeout, f"objdump -d 0x{start:x}-0x{stop:x}")
    insns: list[Insn] = []
    for line in text.splitlines():
        m = INSN_RE.match(line)
        if not m:
            continue
        insns.append(Insn(int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return insns


def disassembly_problem(insns: list[Insn], start: int, size: int) -> str | None:
    """Why the decoded stream cannot stand in for the declared range, or None.

    Silent truncation is the failure this guards against: a tool that prints
    a prefix of the function, or skips bytes it cannot decode, must not leave
    a shorter population that is then counted as resolved.
    """
    if not insns:
        return "empty-disassembly"
    if insns[0].addr != start:
        return f"misaligned-start:+0x{insns[0].addr - start:x}"
    steps = [b.addr - a.addr for a, b in zip(insns, insns[1:])]
    if any(step <= 0 or step > MAX_INSN_BYTES for step in steps):
        worst = max(steps) if steps else 0
        return f"disassembly-hole:largest-step={worst}"
    uncovered = start + size - insns[-1].addr
    if uncovered > MAX_INSN_BYTES:
        return f"disassembly-truncated:{uncovered}-bytes-undecoded"
    return None


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


def audit(dso: str, family: str, short: str, symtab, timeout: float) -> tuple[str, dict, list[dict]]:
    matches = find_symbols(symtab, short)
    if not matches:
        return family, {"failure": "missing", "short": short}, []
    if len(matches) > 1:
        return family, {"failure": "ambiguous", "short": short,
                        "candidates": [s for _, _, s in matches]}, []
    addr, size, sym = matches[0]
    if size == 0:
        # A zero-size symbol has no declared extent.  Inventing one (the audit
        # used to assume 16 bytes) would report an instruction stream for an
        # arbitrary window and count it as resolved.
        return family, {"failure": "zero-size", "short": short,
                        "symbol": sym, "addr": addr}, []
    try:
        insns = disassemble(dso, addr, addr + size, timeout)
    except Refusal as exc:
        reason = "timeout" if "timeout" in exc.message else "tool-failure"
        return family, {"failure": reason, "short": short,
                        "symbol": sym, "addr": addr, "size": size,
                        "detail": exc.message}, []
    problem = disassembly_problem(insns, addr, size)
    if problem:
        reason = problem.split(":", 1)[0]
        return family, {"failure": reason, "short": short,
                        "symbol": sym, "addr": addr, "size": size,
                        "detail": problem}, []
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


def scan_cpuid(dso: str, timeout: float) -> tuple[int, list[int]]:
    text = run([objdump_bin(), "-d", "--no-show-raw-insn", dso], timeout,
               "objdump -d (cpuid scan)")
    addrs = []
    for line in text.splitlines():
        m = INSN_RE.match(line)
        if m and m.group(2) == "cpuid":
            addrs.append(int(m.group(1), 16))
    return len(addrs), addrs


def load_targets(path: str | None) -> list[tuple[str, str]]:
    if path is None:
        targets = list(TARGETS)
    else:
        try:
            with open(path, "rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Refusal(EXIT_USAGE, f"cannot read targets inventory '{path}': {exc}")
        if not isinstance(document, list) or not document:
            raise Refusal(EXIT_USAGE, f"targets inventory '{path}' must be a non-empty list")
        targets = []
        for index, entry in enumerate(document):
            if not isinstance(entry, dict) or set(entry) != {"family", "symbol"}:
                raise Refusal(EXIT_USAGE,
                              f"targets inventory entry {index} must be "
                              f'{{"family": ..., "symbol": ...}}')
            family, symbol = entry["family"], entry["symbol"]
            if not isinstance(family, str) or not family:
                raise Refusal(EXIT_USAGE, f"targets inventory entry {index}: empty family")
            if not isinstance(symbol, str) or not symbol:
                raise Refusal(EXIT_USAGE, f"targets inventory entry {index}: empty symbol")
            targets.append((family, symbol))
    if not targets:
        raise Refusal(EXIT_USAGE, "the expected-target inventory is empty")
    seen: set[str] = set()
    for _, symbol in targets:
        if symbol in seen:
            raise Refusal(EXIT_USAGE, f"duplicate target symbol in inventory: {symbol}")
        seen.add(symbol)
    return targets


def report_failure(family: str, counts: dict) -> None:
    reason = counts["failure"]
    detail = counts.get("detail")
    extra = ""
    if reason == "ambiguous":
        extra = " candidates=" + ",".join(counts.get("candidates", []))
    if detail:
        extra += f" detail={detail}"
    print(
        f'REFUSED target="{family}" symbol="{counts["short"]}" reason={reason}{extra}',
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dso", nargs="?",
                    default="artifacts/phase2/install/lib/libcrypto.so.3")
    ap.add_argument("--no-cpuid-scan", action="store_true",
                    help="skip the whole-DSO cpuid scan")
    ap.add_argument("--targets-file", default=None,
                    help="JSON list of {family, symbol} to audit, replacing the "
                         "built-in inventory (used by the refusal controls)")
    ap.add_argument("--expect-sha256", default=None,
                    help="refuse (exit 3) unless the DSO has this SHA-256")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="per-tool timeout in seconds (default 120)")
    args = ap.parse_args(argv)

    try:
        targets = load_targets(args.targets_file)
        data = read_dso(args.dso)
        digest = hashlib.sha256(data).hexdigest()
        if args.expect_sha256 is not None:
            expected = args.expect_sha256.strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise Refusal(EXIT_USAGE,
                              f"--expect-sha256 is not a 64-hex-digit digest: {args.expect_sha256!r}")
            if digest != expected:
                raise Refusal(
                    EXIT_IDENTITY,
                    f'candidate-identity-mismatch: target="{args.dso}" '
                    f"expected={expected} observed={digest}",
                )
        if args.timeout <= 0:
            raise Refusal(EXIT_USAGE, "--timeout must be positive")
        if shutil.which(objdump_bin()) is None:
            raise Refusal(EXIT_USAGE,
                          f"objdump not found: {objdump_bin()} (set OBJDUMP to override)")
        symtab = symbol_table(args.dso, args.timeout)
        objdump_version = run([objdump_bin(), "--version"], args.timeout,
                              "objdump --version").splitlines()[0]
        results = [audit(args.dso, fam, short, symtab, args.timeout)
                   for fam, short in targets]
        cpuid = None
        if not args.no_cpuid_scan:
            cpuid = scan_cpuid(args.dso, args.timeout)
    except Refusal as exc:
        print(f"binary_branch_audit: REFUSED: {exc.message}", file=sys.stderr)
        return exc.code

    print("# Binary branch audit — review aid, not a proof")
    print()
    print(f"- DSO: `{args.dso}`")
    print(f"- SHA-256: `{digest}`")
    print(f"- objdump: `{objdump_version}`")
    print("- Secret-dependence is NOT established here. A conditional jump is")
    print("  listed because the compiler emitted it in the named function; the")
    print("  reviewer maps each condition to the Rust source's secret")
    print("  classification. BINSEC `-checkct` (T16) can establish control-flow")
    print("  and memory-address dependence on a declared secret split; it does")
    print("  not model microarchitectural timing.")
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
                detail = f": {c['detail']}" if c.get("detail") else ""
                print(f"| {fam} | **{c['failure']}** (`{c['short']}`{detail}) | | | | | | | | | | |")
            continue
        print(f"| {fam} | `{c['symbol']}` @ 0x{c['addr']:x} | {c['size']} | "
              f"{c['insns']} | {c['jcc']} | {c['div']} | {c['cmov']} | "
              f"{c['setcc']} | {c['jo']} | {c['loop']} | {c['calls']} | {c['cpuid']} |")

    failures = [(fam, c) for fam, c, _ in results if c.get("failure")]
    print()
    print("## Coverage")
    print()
    print(f"- expected targets: {len(targets)}")
    print(f"- resolved uniquely and disassembled: {len(targets) - len(failures)}")
    print(f"- failed: {len(failures)}")
    for fam, c in failures:
        extra = ""
        if c["failure"] == "ambiguous":
            extra = " candidates: " + ", ".join(c.get("candidates", []))
        if c.get("detail"):
            extra += f" detail: {c['detail']}"
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

    if cpuid is not None:
        n, addrs = cpuid
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

    for fam, c in failures:
        report_failure(fam, c)
    if failures:
        print(
            f"binary_branch_audit: FAIL-CLOSED: {len(failures)} of {len(targets)} "
            "expected targets were refused; this report is not a gate result.",
            file=sys.stderr,
        )
        return EXIT_TARGET
    print(
        f"binary_branch_audit: {len(targets)} expected targets resolved uniquely "
        f"with complete disassembly; candidate sha256={digest}",
        file=sys.stderr,
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
