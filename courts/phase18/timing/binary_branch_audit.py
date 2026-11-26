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
     start, byte-contiguous, and ended exactly at the declared extent.
  1  one or more targets were refused: missing, ambiguous symbol, zero-size
     (unknown extent), empty disassembly, misaligned start, a gap, an overlap,
     a disassembly that ends before or past the declared extent, or a decoded
     byte count that does not equal the extent.  The specific target and
     reason are named on stderr.
  2  the invocation or the tool failed: unreadable/unsupported DSO, objdump
     absent, objdump failure or timeout, malformed targets inventory.
  3  --expect-sha256 did not match the DSO that was about to be audited.

Symbol resolution is exact and unique.  A Rust v0 mangled identifier is
length-prefixed, so the final identifier is matched only when the digits
immediately before it parse to exactly its length; an identifier whose length
merely *ends* with those digits is not a match.  More than one match is refused
rather than resolved to whichever symbol came first in the table.

## Inline resolution (``resolves_to``)

A release optimiser may inline a small wrapper so completely that no
out-of-line body survives, while the work it forwards to is still present under
another symbol.  An inventory target may declare that mapping:

    {"family": ..., "symbol": "wrapper",
     "resolves_to": "wrapper_extended",
     "inlining": {"suffix": "_extended", "caller": "caller_symbol",
                  "constant_argument": "push $0x0",
                  "producer": "<compiler producer string>",
                  "check": "<what established the inlining>"}}

The mapping is not taken on trust.  It is consulted **only** when the intended
symbol has no out-of-line body, and it is admitted **only** when the audit
re-establishes each of these facts from the artefact:

  * ``resolves_to`` is exactly ``symbol + suffix``, and the symbol table carries
    that identifier with a v0 length prefix equal to its whole length, so a
    differently named function cannot be substituted;
  * the carrier resolves uniquely and has a non-zero extent with complete
    disassembly (the ordinary checks below);
  * ``caller`` resolves to one defined symbol whose own disassembly is complete,
    and that caller contains a direct ``call`` to the carrier's entry, so the
    intended call path really reaches the carrier;
  * the instruction ``constant_argument`` appears between the previous control
    transfer and that call, so the constant the wrapper supplied (e.g. the
    ``None`` tag of a one-line forwarder) is present at the site;
  * ``producer`` occurs in the artefact's bytes, binding the recorded compiler
    identity to this DSO rather than to the inventory.

The report records both names, so a mapped target still shows that the intended
target was reached.  What the mapping cannot prove is that the wrapper's source
was inlined rather than deleted and its caller edited to the same call: those
produce the same instruction stream.  That residual is stated here and the
inventory's ``check`` field records the source-level fact; the audit claims only
the facts listed above.  When the intended symbol does have an out-of-line body
the mapping is not used and that body is audited.

Named refusals for a declared mapping: ``inline-witness-inconsistent``,
``inline-carrier-missing``, ``inline-carrier-ambiguous``,
``inline-caller-unverified``, ``inline-call-witness-missing``,
``inline-constant-argument-missing``, ``inline-producer-absent``.
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

@dataclass(frozen=True)
class Inlining:
    """The recorded justification for a target that has no out-of-line body.

    Every field is re-established from the artefact at audit time; see the
    module docstring.  `check` is a record of the source-level fact, not a
    check the audit executes.
    """

    suffix: str
    caller: str
    constant_argument: str
    producer: str
    check: str


@dataclass(frozen=True)
class Target:
    family: str
    module: str | None
    symbol: str
    resolves_to: str | None = None
    inlining: Inlining | None = None


# (family, module, short symbol name, optional inline resolution).  The short
# name is the final length-prefixed identifier of the Rust v0 mangled symbol,
# matched exactly so that e.g. `mod_inverse_consttime` is not confused with
# `BN_mod_inverse_consttime`.  When `module` is present the match additionally
# requires the preceding v0 path component to be exactly that module, using the
# same length-prefix check for both identifiers.  This names a free function
# whose final identifier alone is not unique-or-resolvable (P-256's
# `mont_reduce_into` follows the module `p256`, whose trailing digits merge with
# the function's length prefix).  It is an exact, more specific match; it does
# not relax the short-name rule.
#
# `resolves_to`/`inlining` are used only when the optimiser left no out-of-line
# body for the named symbol; see the module docstring.  The P-256 ladder core is
# the observed case: `mod_exp_core_consttime_from_parts` is a one-line forwarder
# to `..._from_parts_prepared(.., None)`, inlined into its caller `BN_mod_exp` on
# the PFP-2 digests, so the only out-of-line body is the prepared entry point.
TARGETS = [
    Target("Montgomery multiply (core)", None, "mont_mul_into"),
    Target("Montgomery multiply (allocating wrapper)", None, "mont_mul_fallible"),
    Target(
        "Constant-time ladder core", None, "mod_exp_core_consttime_from_parts",
        resolves_to="mod_exp_core_consttime_from_parts_prepared",
        inlining=Inlining(
            suffix="_prepared",
            caller="BN_mod_exp",
            constant_argument="push $0x0",
            producer="clang LLVM (rustc version 1.98.1 (48a229cea 2026-09-01))",
            check=(
                "mod_exp_core_consttime_from_parts(ad, pd, md, n) is the "
                "one-line forwarder to "
                "mod_exp_core_consttime_from_parts_prepared(ad, pd, md, n, "
                "None); in the release DSO its only non-test caller BN_mod_exp "
                "calls the prepared entry directly with the None tag, so no "
                "out-of-line body of the wrapper is emitted"
            ),
        ),
    ),
    Target("Constant-time inversion", None, "mod_inverse_consttime"),
    Target("ECDSA scalar ladder (driver)", None, "ossl_ec_scalar_mul_ladder"),
    Target("EC ladder step (secret core)", None, "ossl_ec_GFp_simple_ladder_step"),
    Target("RSA CRT arms", None, "rsa_ossl_mod_exp"),
    Target("P-256 Montgomery reduction", "p256", "mont_reduce_into"),
    Target("P-256 x86-64 multiply", "p256", "wide_mul_x86"),
]

FLAG_SETTERS = {
    "test", "cmp", "add", "sub", "sbb", "adc", "and", "or", "xor",
    "inc", "dec", "neg", "shl", "sal", "shr", "sar", "rol", "ror",
    "rcl", "rcr", "mul", "imul", "bt", "bts", "btr", "btc", "popcnt",
    "lzcnt", "tzcnt", "andn",
}

SYMBOL_RE = re.compile(r"^([0-9a-f]+)\s+[lg]\s+F\s+\.text\s+([0-9a-f]+)\s+(\S+)\s*$")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*)$")
# Raw-bytes form emitted by `objdump -d --insn-width=16`:
#   4a0000:\teb 07 ...\tjmp 4a0009 <...>
# The decoded length is the number of byte pairs, not the step to the next
# address.  A step of at most 15 bytes only says the next instruction starts
# within the maximum instruction length; it does not say the intervening bytes
# were decoded.
DISASM_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+(\S.*)$")

EXIT_OK = 0
EXIT_TARGET = 1
EXIT_USAGE = 2
EXIT_IDENTITY = 3

# Longest x86-64 instruction is 15 bytes.  This is a sanity bound on a
# decoded length, not the coverage test: coverage requires every byte between
# consecutive instruction boundaries to have been decoded.
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
    size: int
    mnem: str
    ops: str

    @property
    def end(self) -> int:
        return self.addr + self.size

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


def find_symbols(symtab: list[tuple[int, int, str]], name: str,
                 module: str | None = None):
    """All defined .text symbols whose v0-mangled final identifier is exactly
    `name`, optionally preceded by the v0 path component `module`.

    Rust v0 mangles an identifier as "<decimal length><identifier>", so the
    match is accepted only when the digits immediately preceding the name parse
    to exactly ``len(name)``.  A plain ``endswith`` test is not sufficient: an
    identifier of length 117 named ``mont_mul_into`` would end with
    ``13mont_mul_into`` and be accepted by it.  Every match is returned; the
    caller refuses an ambiguous name rather than resolving it to whichever
    symbol happened to be first in the table.

    With `module`, both the module and the name must be complete length-prefixed
    identifiers.  That disambiguates a free function whose short name is not
    resolvable on its own: `p256` ends in digits, so the mangled suffix is
    ``4p25616mont_reduce_into`` and both prefixes are checked exactly.
    """
    if module is None:
        pattern = re.compile(r"(\d+)" + re.escape(name) + r"$")
        matches = []
        for addr, size, sym in symtab:
            m = pattern.search(sym)
            if m and int(m.group(1)) == len(name):
                matches.append((addr, size, sym))
        return matches
    pattern = re.compile(
        r"(\d+)" + re.escape(module) + r"(\d+)" + re.escape(name) + r"$")
    matches = []
    for addr, size, sym in symtab:
        m = pattern.search(sym)
        if (m and int(m.group(1)) == len(module)
                and int(m.group(2)) == len(name)):
            matches.append((addr, size, sym))
    return matches


def disassemble(dso: str, start: int, stop: int, timeout: float) -> list[Insn]:
    """Decode [start, stop) with the raw bytes retained.

    The decoded length of each instruction comes from its byte field, so the
    audit can require `end(I_i) == start(I_{i+1})` rather than inferring
    coverage from address deltas.
    """
    text = run([
        objdump_bin(), "-d", "--insn-width=16",
        f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", dso,
    ], timeout, f"objdump -d 0x{start:x}-0x{stop:x}")
    insns: list[Insn] = []
    for line in text.splitlines():
        m = DISASM_RE.match(line)
        if not m:
            continue
        raw = m.group(2).split()
        body = m.group(3).strip()
        if not raw or not body:
            continue
        parts = body.split(None, 1)
        mnem = parts[0]
        ops = parts[1] if len(parts) > 1 else ""
        insns.append(Insn(int(m.group(1), 16), len(raw), mnem, ops))
    return insns


def disassembly_problem(insns: list[Insn], start: int, size: int) -> str | None:
    """Why the decoded stream cannot stand in for the declared range, or None.

    The invariant is byte coverage, not an address-gap bound.  Each decoded
    instruction must start where the previous one ended, the first must start
    at the symbol address, and the last must end exactly at the admitted
    function boundary.  Silent truncation, a skipped short instruction, an
    overlap and an overrun are all named refusals.
    """
    if not insns:
        return "empty-disassembly"
    if insns[0].addr != start:
        return f"misaligned-start:+0x{insns[0].addr - start:x}"

    boundary = start + size
    previous_end = start
    decoded = 0
    for insn in insns:
        offset = insn.addr - start
        if insn.size <= 0:
            return f"zero-length-instruction:+0x{offset:x}"
        if insn.size > MAX_INSN_BYTES:
            return f"invalid-instruction-length:{insn.size}-bytes@+0x{offset:x}"
        if insn.addr > previous_end:
            gap = insn.addr - previous_end
            return f"disassembly-hole:gap=+0x{gap:x}@+0x{previous_end - start:x}"
        if insn.addr < previous_end:
            overlap = previous_end - insn.addr
            return f"disassembly-overlap:overlap=0x{overlap:x}@+0x{offset:x}"
        previous_end = insn.end
        decoded += insn.size

    if previous_end < boundary:
        return f"disassembly-truncated:{boundary - previous_end}-bytes-undecoded"
    if previous_end > boundary:
        return f"disassembly-overrun:{previous_end - boundary}-bytes-past-boundary"
    if decoded != size:
        return f"byte-count-mismatch:decoded={decoded}:extent={size}"
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


def find_exact(symtab: list[tuple[int, int, str]], name: str):
    """Defined symbols named exactly `name`, else the exact v0 identifier match.

    An ABI-exported caller is a plain C identifier (`BN_mod_exp`), which the v0
    length-prefix rule does not apply to.  A Rust caller still resolves through
    the same exact rule `find_symbols` uses.
    """
    exact = [entry for entry in symtab if entry[2] == name]
    return exact if exact else find_symbols(symtab, name)


def _identifier_is(symbol: str, identifier: str) -> bool:
    """True when `symbol` ends with the v0 form `<len(identifier)><identifier>`."""
    m = re.search(r"(\d+)" + re.escape(identifier) + r"$", symbol)
    return m is not None and int(m.group(1)) == len(identifier)


def verify_inline_mapping(dso: str, target: Target, symtab, timeout: float,
                          data: bytes):
    """Re-establish a declared `resolves_to` mapping from the artefact.

    Returns ``(carrier, witness, failure)``.  On success `carrier` is the
    ``(addr, size, symbol)`` entry to audit and `witness` is the verified call
    path.  On any unverified fact, `failure` is a refusal dict and the caller
    refuses the target -- the mapping is never admitted on the inventory's
    word alone.
    """
    if target.resolves_to is None or target.inlining is None:
        raise Refusal(EXIT_USAGE, "verify_inline_mapping called without a mapping")
    rule = target.inlining
    full = target.symbol + rule.suffix
    # (1) the declared carrier must be exactly the target's identifier plus the
    # recorded suffix.  A differently named function cannot be substituted,
    # which is what makes control (c) ("an existing symbol that is not the
    # body") detectable instead of guessed at.
    if target.resolves_to != full:
        return None, None, {
            "failure": "inline-witness-inconsistent",
            "detail": f"resolves_to={target.resolves_to} != symbol+suffix={full}",
        }
    carriers = [entry for entry in find_symbols(symtab, full)
                if _identifier_is(entry[2], full)]
    if not carriers:
        return None, None, {
            "failure": "inline-carrier-missing",
            "detail": f"no defined .text symbol ends with {len(full)}{full}",
        }
    if len(carriers) > 1:
        return None, None, {
            "failure": "inline-carrier-ambiguous",
            "candidates": [s for _, _, s in carriers],
        }
    carrier = carriers[0]
    addr, size, sym = carrier
    if size == 0:
        return None, None, {
            "failure": "zero-size", "symbol": sym, "addr": addr,
        }
    # (2) the recorded producer string must be a property of this artefact.
    if rule.producer.encode() not in data:
        return None, None, {
            "failure": "inline-producer-absent",
            "detail": f"producer string not in the DSO: {rule.producer!r}",
        }
    # (3) the recorded caller must exist, disassemble completely, and contain a
    # direct call to the carrier's entry: the intended call path reaches it.
    callers = find_exact(symtab, rule.caller)
    if not callers:
        return None, None, {
            "failure": "inline-caller-unverified",
            "detail": f"caller {rule.caller!r} is not a defined symbol",
        }
    if len(callers) > 1:
        return None, None, {
            "failure": "inline-caller-unverified",
            "detail": f"caller {rule.caller!r} is ambiguous",
        }
    caddr, csize, csym = callers[0]
    if csize == 0:
        return None, None, {
            "failure": "inline-caller-unverified",
            "detail": f"caller {csym!r} has no declared extent",
        }
    try:
        cinsns = disassemble(dso, caddr, caddr + csize, timeout)
    except Refusal as exc:
        return None, None, {
            "failure": "inline-caller-unverified",
            "detail": f"caller {csym!r}: {exc.message}",
        }
    problem = disassembly_problem(cinsns, caddr, csize)
    if problem:
        return None, None, {
            "failure": "inline-caller-unverified",
            "detail": f"caller {csym!r}: {problem}",
        }
    wanted = " ".join(rule.constant_argument.split())
    site = None
    for i, insn in enumerate(cinsns):
        if insn.mnem not in {"call", "callq"} or target_of(insn) != addr:
            continue
        # (4) the wrapper's forwarded constant must be at the site: scan back to
        # the previous control transfer (bounded by 16 instructions).
        for j in range(i - 1, max(-1, i - 17), -1):
            previous = cinsns[j]
            if is_control(previous):
                break
            if previous.text == wanted:
                site = (insn, previous)
                break
        if site is not None:
            break
    if site is None:
        calls_carrier = any(
            insn.mnem in {"call", "callq"} and target_of(insn) == addr
            for insn in cinsns
        )
        return None, None, {
            "failure": ("inline-constant-argument-missing" if calls_carrier
                        else "inline-call-witness-missing"),
            "detail": (f"caller {csym!r} -> 0x{addr:x}: "
                       + (f"no instruction {wanted!r} before the call"
                          if calls_carrier
                          else "no direct call to the carrier")),
        }
    call, constant = site
    witness = {
        "caller": csym,
        "call_addr": call.addr,
        "call_offset": call.addr - caddr,
        "constant": constant.text,
        "carrier": sym,
        "producer": rule.producer,
        "check": rule.check,
    }
    return carrier, witness, None


def audit(dso: str, target: Target, symtab, timeout: float,
          data: bytes) -> tuple[str, dict, list[dict]]:
    family = target.family
    label = (target.symbol if target.module is None
             else f"{target.module}::{target.symbol}")
    inline_used = False
    witness = None
    matches = find_symbols(symtab, target.symbol, target.module)
    if not matches:
        if target.resolves_to is None:
            return family, {"failure": "missing", "short": label}, []
        carrier, witness, failure = verify_inline_mapping(
            dso, target, symtab, timeout, data)
        if failure is not None:
            failure.update({"short": label, "resolves_to": target.resolves_to})
            return family, failure, []
        matches = [carrier]
        inline_used = True
    if len(matches) > 1:
        return family, {"failure": "ambiguous", "short": label,
                        "candidates": [s for _, _, s in matches]}, []
    addr, size, sym = matches[0]
    if size == 0:
        # A zero-size symbol has no declared extent.  Inventing one (the audit
        # used to assume 16 bytes) would report an instruction stream for an
        # arbitrary window and count it as resolved.
        return family, {"failure": "zero-size", "short": label,
                        "symbol": sym, "addr": addr}, []
    try:
        insns = disassemble(dso, addr, addr + size, timeout)
    except Refusal as exc:
        reason = "timeout" if "timeout" in exc.message else "tool-failure"
        return family, {"failure": reason, "short": label,
                        "symbol": sym, "addr": addr, "size": size,
                        "detail": exc.message}, []
    problem = disassembly_problem(insns, addr, size)
    if problem:
        reason = problem.split(":", 1)[0]
        return family, {"failure": reason, "short": label,
                        "symbol": sym, "addr": addr, "size": size,
                        "detail": problem}, []
    rows: list[dict] = []
    counts = {
        "symbol": sym, "addr": addr, "size": size, "insns": len(insns),
        "jcc": 0, "div": 0, "cmov": 0, "setcc": 0, "jo": 0, "loop": 0,
        "calls": 0, "cpuid": 0, "dispatch_calls": [], "div_rows": [],
        "missing": False, "failure": None,
        "intended": label, "declared_inline": target.resolves_to is not None,
        "resolves_to": target.resolves_to,
        "inline_used": inline_used, "inline_witness": witness,
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


INLINE_KEYS = {"suffix", "caller", "constant_argument", "producer", "check"}


def _load_inlining(index: int, value) -> Inlining:
    if not isinstance(value, dict) or set(value) != INLINE_KEYS:
        raise Refusal(EXIT_USAGE,
                      f"targets inventory entry {index}: 'inlining' must have exactly "
                      f"the keys {sorted(INLINE_KEYS)}")
    for key in sorted(INLINE_KEYS):
        if not isinstance(value[key], str) or not value[key].strip():
            raise Refusal(EXIT_USAGE,
                          f"targets inventory entry {index}: 'inlining.{key}' must be "
                          "a non-empty string")
    return Inlining(
        suffix=value["suffix"], caller=value["caller"],
        constant_argument=value["constant_argument"],
        producer=value["producer"], check=value["check"],
    )


def load_targets(path: str | None) -> list[Target]:
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
        base_keys = ({"family", "symbol"}, {"family", "module", "symbol"})
        inline_keys = tuple(keys | {"resolves_to", "inlining"} for keys in base_keys)
        bare_mapping = tuple(keys | {"resolves_to"} for keys in base_keys)
        targets = []
        for index, entry in enumerate(document):
            if not isinstance(entry, dict) or set(entry) not in (
                    base_keys + inline_keys + bare_mapping):
                raise Refusal(EXIT_USAGE,
                              f"targets inventory entry {index} must be one of "
                              f'{{"family", "symbol"}}, '
                              f'{{"family", "module", "symbol"}}, or either with '
                              f'"resolves_to" (and its "inlining" evidence)')
            family, symbol = entry["family"], entry["symbol"]
            module = entry.get("module")
            if not isinstance(family, str) or not family:
                raise Refusal(EXIT_USAGE, f"targets inventory entry {index}: empty family")
            if not isinstance(symbol, str) or not symbol:
                raise Refusal(EXIT_USAGE, f"targets inventory entry {index}: empty symbol")
            if module is not None and (not isinstance(module, str) or not module):
                raise Refusal(EXIT_USAGE, f"targets inventory entry {index}: empty module")
            resolves_to = entry.get("resolves_to")
            inlining = None
            if resolves_to is not None:
                if not isinstance(resolves_to, str) or not resolves_to:
                    raise Refusal(EXIT_USAGE,
                                  f"targets inventory entry {index}: empty resolves_to")
                inlining = _load_inlining(index, entry.get("inlining"))
            targets.append(Target(family, module, symbol, resolves_to, inlining))
    if not targets:
        raise Refusal(EXIT_USAGE, "the expected-target inventory is empty")
    seen: set[tuple[str | None, str]] = set()
    for target in targets:
        if (target.module, target.symbol) in seen:
            label = (target.symbol if target.module is None
                     else f"{target.module}::{target.symbol}")
            raise Refusal(EXIT_USAGE, f"duplicate target symbol in inventory: {label}")
        seen.add((target.module, target.symbol))
    return targets


def report_failure(family: str, counts: dict) -> None:
    reason = counts["failure"]
    detail = counts.get("detail")
    extra = ""
    if reason == "ambiguous":
        extra = " candidates=" + ",".join(counts.get("candidates", []))
    if detail:
        extra += f" detail={detail}"
    maps = (f' resolves_to="{counts["resolves_to"]}"'
            if counts.get("resolves_to") else "")
    print(
        f'REFUSED target="{family}" symbol="{counts["short"]}"{maps} '
        f'reason={reason}{extra}',
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
        results = [audit(args.dso, target, symtab, args.timeout, data)
                   for target in targets]
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
        print(f"| {fam} | `{c['symbol']}` @ 0x{c['addr']:x}"
              + (f" (carries `{c['intended']}`)" if c.get("inline_used") else "")
              + f" | {c['size']} | "
              f"{c['insns']} | {c['jcc']} | {c['div']} | {c['cmov']} | "
              f"{c['setcc']} | {c['jo']} | {c['loop']} | {c['calls']} | {c['cpuid']} |")

    failures = [(fam, c) for fam, c, _ in results if c.get("failure")]
    print()
    print("## Coverage")
    print()
    print(f"- expected targets: {len(targets)}")
    print(f"- resolved uniquely and disassembled: {len(targets) - len(failures)}")
    mapped = [(fam, c) for fam, c, _ in results
              if not c.get("failure") and c.get("inline_used")]
    if mapped:
        print(f"- of those, audited through a verified inline mapping: {len(mapped)}")
        for fam, c in mapped:
            print(f"  - {fam}: intended `{c['intended']}` -> carrier `{c['symbol']}`")
    print(f"- failed: {len(failures)}")
    for fam, c in failures:
        extra = ""
        if c["failure"] == "ambiguous":
            extra = " candidates: " + ", ".join(c.get("candidates", []))
        if c.get("detail"):
            extra += f" detail: {c['detail']}"
        print(f"  - {fam} (`{c['short']}`): {c['failure']}{extra}")

    declared = [(fam, c) for fam, c, _ in results if c.get("declared_inline")]
    if declared:
        print()
        print("## Inline mappings declared by the inventory")
        print()
        print("A mapping is admitted only when the audit re-establishes the "
              "name derivation (`resolves_to` is `symbol` + `suffix`), the "
              "carrier's extent, a direct call from the declared caller, the "
              "wrapper's constant argument at that site, and the producer string "
              "in this DSO. It does not prove the wrapper was inlined rather "
              "than source-edited away; those are the same instructions (see the "
              "module docstring).")
        print()
        print("| target | carrier | state | caller | call site | constant | carrier extent | producer |")
        print("|---|---|---|---|---|---|---:|---|")
        for fam, c in declared:
            intended = c.get("intended", c.get("short"))
            if c.get("inline_used"):
                w = c["inline_witness"]
                print(f"| `{intended}` | `{w['carrier']}` | **verified, audited** | "
                      f"`{w['caller']}` | +0x{w['call_offset']:x} | "
                      f"`{w['constant']}` | {c['size']} B | "
                      f"`{w['producer']}` |")
            elif c.get("failure"):
                print(f"| `{intended}` | `{c.get('resolves_to', '?')}` | "
                      f"**refused: {c['failure']}** | | | | | |")
            else:
                print(f"| `{intended}` | `{c.get('resolves_to', '?')}` | "
                      f"not used (out-of-line body present) | | | | | |")
        for fam, c in declared:
            if c.get("inline_used"):
                print()
                print(f"- **{fam}** recorded check: {c['inline_witness']['check']}")

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
    mapped_note = (f"; {len(mapped)} resolved through a verified inline mapping"
                   if mapped else "")
    print(
        f"binary_branch_audit: {len(targets)} expected targets resolved uniquely "
        f"with complete disassembly{mapped_note}; candidate sha256={digest}",
        file=sys.stderr,
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
