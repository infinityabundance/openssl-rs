#!/usr/bin/env python3
"""instrument_qualify.py -- re-validate the instrument register against reality.

The register (`evidence/etp3/instruments.json`) states, for each instrument the
assurance campaign relies on: the one question it may answer, what it must never
be cited for, how its version is identified, its failure modes, its soundness
limits, its paired sensitivity control, and how it fails closed.  This tool is
the executable half of that statement:

    python3 forensics/tools/instrument_qualify.py check      # validate + controls
    python3 forensics/tools/instrument_qualify.py validate   # register only
    python3 forensics/tools/instrument_qualify.py controls   # controls only
    python3 forensics/tools/instrument_qualify.py controls --only branch-audit-gate

`validate` refuses when the register is malformed, an instrument path is
absent, a recorded version string is no longer produced by the tool, an
executable control is not bound to a known control id, a recorded control's
bound evidence file has changed, or a status claims more than its evidence.

`controls` executes the refusal controls and the sensitivity controls.  It
refuses when a case returns an exit status other than the expected one, when
the expected refusal text is absent from stderr, or when a control that must
fire does not.  `check` additionally requires the live case table to match the
table recorded in the register, so a control whose behaviour changed cannot
leave the register silently green.

Two statuses are distinct on purpose:

  PASS          an executable control ran in this invocation and every case
                matched its expectation.
  RECORDED      the control was executed for a bound, tracked evidence artefact
                whose digest still matches.  It is never reported as PASS.

Exit status: 0 only when every requested check passed.  1 for any refusal,
2 for a usage error.  Nothing here runs a build of the crate; the controls
compile only their own small fixtures and reuse the tracked Phase-2 DSO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = REPO_ROOT / "evidence" / "etp3" / "instruments.json"

REGISTRY_SCHEMA = "openssl-rs/instrument-qualification/1"

KINDS = {"tool", "script", "harness", "suite"}
STATUSES = {"PASS", "RECORDED", "NOT_RUN"}

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

EXECUTABLE_CONTROLS = {
    "branch-audit-gate",
    "binsec-gate",
    "ctgrind-sensitivity",
    "dudect-sensitivity",
    "pmu-venue-probe",
    "differential-analysis-controls",
    "etp-claims-controls",
    "reproducibility-comparison-control",
    "alloc-probe-control",
}


class Refusal(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# strict JSON


def load_json_strict(path: Path):
    """Load JSON, refusing duplicate keys and non-finite numbers.

    A register with two values for one key has no single meaning, and a
    control that cannot be interpreted must not be reported as passing.
    """

    def pairs_hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise Refusal("IQ_JSON_DUPLICATE_KEY", f"{path}: duplicate key {key!r}")
            seen.add(key)
        return dict(pairs)

    def reject_constant(token):
        raise Refusal("IQ_JSON_NON_FINITE", f"{path}: non-finite number {token}")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise Refusal("IQ_REGISTRY_UNREADABLE", f"{path}: {exc}")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise Refusal("IQ_REGISTRY_UNREADABLE", f"{path}: not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        raise Refusal("IQ_REGISTRY_UNREADABLE", f"{path}: invalid JSON: {exc}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# process helpers


@dataclass
class Case:
    name: str
    exit: int
    expected: tuple[int, ...]
    ok: bool
    detail: str = ""


@dataclass
class ControlResult:
    control_id: str
    cases: list[Case] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.cases)

    def table(self) -> list[dict]:
        return [{"name": c.name, "exit": c.exit} for c in self.cases]


def run_cmd(cmd: list[str], *, env: dict | None = None, timeout: float = 300.0,
            cwd: Path | None = None) -> tuple[int, str, str]:
    merged = dict(os.environ)
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(cwd or REPO_ROOT), env=merged,
        )
    except FileNotFoundError:
        return 127, "", f"executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return 124, out, err + f"\n[instrument_qualify] host-side timeout after {timeout:g}s"
    return proc.returncode, proc.stdout, proc.stderr


def case(name: str, result: tuple[int, str, str], expected: tuple[int, ...],
         refusal: str | None) -> Case:
    rc, out, err = result
    text = out + err
    ok = rc in expected and (refusal is None or refusal in text)
    detail = "" if ok else f"stdout={out.strip()[:300]!r} stderr={err.strip()[:300]!r}"
    return Case(name=name, exit=rc, expected=expected, ok=ok, detail=detail)


def write_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def compile_fixture(tmp: Path, asm: str, name: str) -> Path:
    """Build a tiny shared object from assembly; no crate, no headers."""
    source = tmp / f"{name}.S"
    source.write_text(asm, encoding="utf-8")
    out = tmp / f"{name}.so"
    rc, o, e = run_cmd(["cc", "-shared", "-nostdlib", "-o", str(out), str(source)])
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"cannot build {name}.so: {e.strip()[:300]}")
    return out


def compile_elf(tmp: Path, name: str = "tiny") -> Path:
    source = tmp / f"{name}.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    out = tmp / name
    rc, o, e = run_cmd(["cc", "-o", str(out), str(source)])
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"cannot build {name}: {e.strip()[:300]}")
    return out


def manifest(tmp: Path, entries: list[tuple[str, str]], name: str = "targets.json") -> Path:
    path = tmp / name
    path.write_text(
        json.dumps([{"family": f, "symbol": s} for f, s in entries], indent=1) + "\n",
        encoding="utf-8",
    )
    return path


AUDIT = "courts/phase18/timing/binary_branch_audit.py"
BINSEC = "courts/phase18/timing/binsec_checkct.sh"
VENDORED_DUDECT_HEADER = "courts/phase18/timing/third_party/dudect/dudect.h"
VENDORED_DUDECT_SHA256 = "3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da"

GOOD_ASM = """
    .text
    .globl _RNvNtCx_8fixture13mont_mul_into
    .type _RNvNtCx_8fixture13mont_mul_into,@function
_RNvNtCx_8fixture13mont_mul_into:
    pushq %rbp
    movq %rsp, %rbp
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
    addl $1, %eax
    nop
    subl $2, %eax
    imull $3, %eax, %eax
    andl $255, %eax
1:
    cmovne %eax, %edi
    movl %edi, %eax
    popq %rbp
    ret
    .size _RNvNtCx_8fixture13mont_mul_into, .-_RNvNtCx_8fixture13mont_mul_into
    .globl _RNvNtCx_17mont_mul_fallible
    .type _RNvNtCx_17mont_mul_fallible,@function
_RNvNtCx_17mont_mul_fallible:
    cmpl $1, %edi
    jne 2f
    ret
2:
    xorl %eax, %eax
    ret
    .size _RNvNtCx_17mont_mul_fallible, .-_RNvNtCx_17mont_mul_fallible
"""

AMBIGUOUS_ASM = """
    .text
    .globl _RNvNtCxA_8fixture13mont_mul_into
    .type _RNvNtCxA_8fixture13mont_mul_into,@function
_RNvNtCxA_8fixture13mont_mul_into:
    ret
    .size _RNvNtCxA_8fixture13mont_mul_into, .-_RNvNtCxA_8fixture13mont_mul_into
    .globl _RNvNtCxB_8fixture13mont_mul_into
    .type _RNvNtCxB_8fixture13mont_mul_into,@function
_RNvNtCxB_8fixture13mont_mul_into:
    ret
    .size _RNvNtCxB_8fixture13mont_mul_into, .-_RNvNtCxB_8fixture13mont_mul_into
"""

ZERO_SIZE_ASM = """
    .text
    .globl _RNvNtCx_8fixture13mont_mul_into
    .type _RNvNtCx_8fixture13mont_mul_into,@function
_RNvNtCx_8fixture13mont_mul_into:
    ret
"""


# ---------------------------------------------------------------------------
# control: binary branch audit


def control_branch_audit_gate(tmp: Path) -> ControlResult:
    result = ControlResult("branch-audit-gate")
    script = REPO_ROOT / AUDIT
    good = compile_fixture(tmp, GOOD_ASM, "good")
    ambiguous = compile_fixture(tmp, AMBIGUOUS_ASM, "ambiguous")
    zero = compile_fixture(tmp, ZERO_SIZE_ASM, "zero")
    manifest_good = manifest(tmp, [("fixture core", "mont_mul_into"),
                                   ("fixture wrapper", "mont_mul_fallible")],
                             "targets-good.json")
    manifest_missing = manifest(tmp, [("fixture absent", "absent_target")],
                                "targets-missing.json")
    manifest_one = manifest(tmp, [("fixture core", "mont_mul_into")],
                            "targets-one.json")

    base = [sys.executable, str(script), "--no-cpuid-scan"]

    def audit(*extra: str, env: dict | None = None):
        return run_cmd(base + list(extra), env=env, timeout=120)

    result.cases.append(case(
        "resolves exact unique symbols and exits 0",
        audit("--targets-file", str(manifest_good), str(good)),
        (0,), None))
    result.cases.append(case(
        "ambiguous symbol is refused",
        audit("--targets-file", str(manifest_one), str(ambiguous)),
        (1,), "reason=ambiguous"))
    result.cases.append(case(
        "missing target is refused",
        audit("--targets-file", str(manifest_missing), str(good)),
        (1,), "reason=missing"))
    result.cases.append(case(
        "zero-size symbol is refused (no invented extent)",
        audit("--targets-file", str(manifest_one), str(zero)),
        (1,), "reason=zero-size"))

    text_file = tmp / "not-an-elf.txt"
    text_file.write_text("this is not an ELF file\n", encoding="utf-8")
    result.cases.append(case(
        "non-ELF input is refused",
        audit("--targets-file", str(manifest_good), str(text_file)),
        (2,), "unsupported format"))
    result.cases.append(case(
        "wrong-candidate digest is refused",
        audit("--targets-file", str(manifest_good), "--expect-sha256", "0" * 64,
              str(good)),
        (3,), "candidate-identity-mismatch"))

    real_objdump = shutil.which("objdump")
    if real_objdump is None:
        raise Refusal("IQ_CONTROL_TOOL_ABSENT", "objdump not found")

    truncating = write_executable(tmp / "objdump-truncated", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
{real_objdump} "$@" | awk 'BEGIN{{n=0}} /^[[:space:]]*[0-9a-f]+:/{{n++; if (n>4) exit}} {{print}}'
""")
    holing = write_executable(tmp / "objdump-holed", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
{real_objdump} "$@" | awk 'BEGIN{{n=0}} /^[[:space:]]*[0-9a-f]+:/{{n++; k[n]=$0; next}} {{print}} END{{print k[1]; print k[2]; print k[n-1]; print k[n]}}'
""")
    hanging = write_executable(tmp / "objdump-hanging", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
exec sleep 30
""")
    emptying = write_executable(tmp / "objdump-empty", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
echo "file format elf64-x86-64"
exit 0
""")
    # A one-byte instruction is removed and every remaining address step stays
    # within the 15-byte maximum instruction length.  The old address-gap test
    # accepts this transcript; decoded instruction lengths expose the 1-byte
    # hole.
    omitting = write_executable(tmp / "objdump-omit-short", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
{real_objdump} "$@" | awk '!/^[[:space:]]*[0-9a-f]+:.*[[:space:]]nop[[:space:]]*$/'
""")
    overlapping = write_executable(tmp / "objdump-overlap", f"""#!/bin/sh
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
{real_objdump} "$@" | awk 'BEGIN{{dup=0}} {{print}} /^[[:space:]]*[0-9a-f]+:/ && dup==0 {{print; dup=1}}'
""")
    overrunning = write_executable(tmp / "objdump-overrun", f"""#!/bin/bash
for a in "$@"; do
  case "$a" in
    -t|--version) exec {real_objdump} "$@" ;;
  esac
done
stop=
for a in "$@"; do
  case "$a" in
    --stop-address=*) stop=${{a#*=}} ;;
  esac
done
{real_objdump} "$@"
if [ -n "$stop" ]; then
  printf '  %x:\\t90\\t\\tnop\\n' "$((stop))"
fi
""")

    result.cases.append(case(
        "truncated disassembly is refused, not counted as resolved",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(truncating)}),
        (1,), "disassembly-truncated"))
    result.cases.append(case(
        "empty disassembly is refused",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(emptying)}),
        (1,), "reason=empty-disassembly"))
    result.cases.append(case(
        "a hole in the decoded stream is refused",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(holing)}),
        (1,), "disassembly-hole"))
    result.cases.append(case(
        "an omitted short instruction is refused (byte coverage, not address gaps)",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(omitting)}),
        (1,), "disassembly-hole"))
    result.cases.append(case(
        "an overlap in the decoded stream is refused",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(overlapping)}),
        (1,), "disassembly-overlap"))
    result.cases.append(case(
        "a disassembly ending past the declared boundary is refused",
        audit("--targets-file", str(manifest_one), str(good),
              env={"OBJDUMP": str(overrunning)}),
        (1,), "disassembly-overrun"))
    result.cases.append(case(
        "a hung tool is a bounded refusal",
        audit("--targets-file", str(manifest_one), "--timeout", "1", str(good),
              env={"OBJDUMP": str(hanging)}),
        (1,), "reason=timeout"))
    result.summary.append("fixtures: 3 shared objects built from assembly; "
                          "truncation, omission of a one-byte instruction, "
                          "hole, overlap, overrun and hang injected through "
                          "objdump shims; the coverage test uses decoded "
                          "instruction lengths")
    return result


# ---------------------------------------------------------------------------
# control: BINSEC wrapper


BINSEC_SHIM = """#!/bin/sh
case " $* " in
  *" -version "*) echo "Binsec version 0.0.0-fake-control" ; exit 0 ;;
esac
case "$EQ_MODE" in
  secure)          echo '[checkct:result] Program status is : secure' ; exit 0 ;;
  secure_timed)    echo '[checkct:result] Program status is : secure (0.030)' ; exit 0 ;;
  secure_nonzero)  echo '[checkct:result] Program status is : secure' ; exit 1 ;;
  insecure_zero)   echo '[checkct:result] Program status is : insecure' ; exit 0 ;;
  insecure_nonzero) echo '[checkct:result] Program status is : insecure' ; exit 1 ;;
  unknown)         echo '[checkct:result] Program status is : unknown' ; exit 0 ;;
  mixed)           printf '%s\\n' '[checkct:result] Program status is : secure' '[checkct:result] Program status is : insecure' ; exit 0 ;;
  duplicate_secure) printf '%s\\n' '[checkct:result] Program status is : secure' '[checkct:result] Program status is : secure' ; exit 0 ;;
  multiple_insecure) printf '%s\\n' '[checkct:result] Program status is : insecure' '[checkct:result] Program status is : insecure' ; exit 0 ;;
  trailing_text)   echo '[checkct:result] Program status is : secure (0.030) but the exploration was incomplete' ; exit 0 ;;
  silent)          exit 0 ;;
  crash)           echo 'fatal: unsupported instruction' >&2 ; exit 2 ;;
  truncated)       echo '[checkct:result] Program status is : sec' ; exit 0 ;;
  hang)            sleep 30 ; exit 0 ;;
  *)               echo "unknown fake mode" >&2 ; exit 9 ;;
esac
"""

Z3_SHIM = """#!/bin/sh
[ "$1" = "--version" ] && echo "Z3 version 0.0.0-fake-control"
exit 0
"""


def control_binsec_gate(tmp: Path) -> ControlResult:
    result = ControlResult("binsec-gate")
    script = REPO_ROOT / BINSEC
    elf = compile_elf(tmp, "tiny-elf")
    cfg = tmp / "fake.cfg"
    cfg.write_text("starting from main\nexplore all\n", encoding="utf-8")
    not_an_elf = tmp / "not-an-elf.txt"
    not_an_elf.write_text("this is not an ELF file\n", encoding="utf-8")
    binsec = write_executable(tmp / "binsec-shim", BINSEC_SHIM)
    z3 = write_executable(tmp / "z3-shim", Z3_SHIM)

    def run_binsec(mode: str, *extra: str, expect_sha: str | None = None):
        env = {"BINSEC_BIN": str(binsec), "BINSEC_Z3": str(z3),
               "EQ_MODE": mode, "BINSEC_WALL_TIMEOUT": "20"}
        if expect_sha is not None:
            env["BINSEC_EXPECT_SHA256"] = expect_sha
        return run_cmd(["bash", str(script), *extra, str(cfg), str(elf)],
                       env=env, timeout=120)

    result.cases.append(case(
        "secure verdict exits 0",
        run_binsec("secure"), (0,), "T16 verdict: secure"))
    result.cases.append(case(
        "a secure verdict carrying BINSEC's timing suffix is accepted",
        run_binsec("secure_timed"), (0,), "T16 verdict: secure"))
    result.cases.append(case(
        "insecure verdict exits nonzero even when the tool exits zero",
        run_binsec("insecure_zero"), (1,), "T16 verdict: insecure"))
    result.cases.append(case(
        "insecure verdict with a nonzero tool status still exits nonzero",
        run_binsec("insecure_nonzero"), (1,), "T16 verdict: insecure"))
    result.cases.append(case(
        "unknown verdict is not a pass",
        run_binsec("unknown"), (4,), "unknown (incomplete; NOT a pass)"))
    result.cases.append(case(
        "mixed secure and insecure verdicts are refused when the tool exits zero",
        run_binsec("mixed"), (6,), "mixed-verdicts"))
    result.cases.append(case(
        "two secure verdicts are refused as duplicated",
        run_binsec("duplicate_secure"), (6,), "duplicate-secure"))
    result.cases.append(case(
        "two non-secure verdicts are refused as multiple",
        run_binsec("multiple_insecure"), (6,), "multiple-verdicts"))
    result.cases.append(case(
        "a verdict line with additional text is refused",
        run_binsec("trailing_text"), (3,), "verdict-trailing-text"))
    result.cases.append(case(
        "--require-secure refuses insecure",
        run_binsec("insecure_zero", "--require-secure"), (8,), "required-secure"))
    result.cases.append(case(
        "--require-secure refuses unknown",
        run_binsec("unknown", "--require-secure"), (8,), "required-secure"))
    result.cases.append(case(
        "silent tool is refused (zero bytes on both streams)",
        run_binsec("silent"), (3,), "no-output"))
    result.cases.append(case(
        "crash before a verdict is refused",
        run_binsec("crash"), (3,), "no-verdict-line"))
    result.cases.append(case(
        "truncated result line is refused",
        run_binsec("truncated"), (3,), "no-verdict-line"))
    result.cases.append(case(
        "a secure verdict with a nonzero tool status is inconsistent",
        run_binsec("secure_nonzero"), (6,), "inconsistent output"))
    result.cases.append(case(
        "wall-clock timeout is a bounded refusal",
        run_cmd(["bash", str(script), str(cfg), str(elf)],
                env={"BINSEC_BIN": str(binsec), "BINSEC_Z3": str(z3),
                     "EQ_MODE": "hang", "BINSEC_WALL_TIMEOUT": "1"},
                timeout=120),
        (6,), "timeout"))
    result.cases.append(case(
        "wrong-candidate digest is refused",
        run_binsec("secure", expect_sha="0" * 64), (5,), "candidate-identity-mismatch"))
    result.cases.append(case(
        "non-ELF input is refused before the tool runs",
        run_cmd(["bash", str(script), str(cfg), str(not_an_elf)],
                env={"BINSEC_BIN": str(binsec), "BINSEC_Z3": str(z3),
                     "EQ_MODE": "secure"}, timeout=60),
        (2,), "unsupported-format"))
    result.cases.append(case(
        "missing script is refused",
        run_cmd(["bash", str(script), str(tmp / "absent.cfg"), str(elf)],
                env={"BINSEC_BIN": str(binsec), "BINSEC_Z3": str(z3),
                     "EQ_MODE": "secure"}, timeout=60),
        (2,), "cannot-read-script"))
    result.summary.append("binsec and z3 are stand-in executables; this control "
                          "validates the wrapper's exit-status contract, not the "
                          "solver's verdicts (the real solver is qualified "
                          "separately in entry binsec-checkct)")
    return result


# ---------------------------------------------------------------------------
# control: ctgrind sensitivity


def control_ctgrind_sensitivity(tmp: Path) -> ControlResult:
    result = ControlResult("ctgrind-sensitivity")
    include = REPO_ROOT / "artifacts/phase2/install/include"
    libdir = REPO_ROOT / "artifacts/phase2/install/lib"
    binary = tmp / "ct_bn"
    rc, out, err = run_cmd([
        "cc", "-D_GNU_SOURCE", "-O1", "-g", f"-I{include}",
        str(REPO_ROOT / "courts/phase18/timing/ct_bn.c"),
        f"-L{libdir}", "-lcrypto", f"-Wl,-rpath,{libdir}", "-o", str(binary),
    ], timeout=300)
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"ctgrind harness did not compile: {err[:400]}")
    env = {"LD_LIBRARY_PATH": str(libdir)}
    result.cases.append(case(
        "positive control (deliberately leaky comparator) fires",
        run_cmd(["valgrind", "--tool=memcheck", "--error-exitcode=99", str(binary),
                 "cmpnaive"], env=env, timeout=300),
        (99,), None))
    result.cases.append(case(
        "negative control (constant-time comparator) is clean",
        run_cmd(["valgrind", "--tool=memcheck", "--error-exitcode=99", str(binary),
                 "cmpcmp"], env=env, timeout=300),
        (0,), None))
    result.summary.append("debug-profile C harness linked against the tracked "
                          "Phase-2 DSO; exit 99 is valgrind's configured "
                          "error-exitcode")
    return result


# ---------------------------------------------------------------------------
# control: dudect sensitivity


def control_dudect_sensitivity(tmp: Path) -> ControlResult:
    result = ControlResult("dudect-sensitivity")
    include = REPO_ROOT / "artifacts/phase2/install/include"
    libdir = REPO_ROOT / "artifacts/phase2/install/lib"
    binary = tmp / "dudect_bn"
    header = REPO_ROOT / VENDORED_DUDECT_HEADER
    header_dir = header.parent
    if not header.is_file():
        raise Refusal(
            "IQ_CONTROL_PREREQUISITE",
            f"vendored dudect header is absent: {VENDORED_DUDECT_HEADER}",
        )
    observe = sha256_file(header)
    if observe != VENDORED_DUDECT_SHA256:
        raise Refusal(
            "IQ_CONTROL_PREREQUISITE",
            f"vendored dudect header {VENDORED_DUDECT_HEADER} changed: "
            f"recorded {VENDORED_DUDECT_SHA256[:12]}..., observed {observe[:12]}...",
        )
    rc, out, err = run_cmd([
        "cc", "-O2", "-g", f"-I{include}", f"-I{header_dir}",
        str(REPO_ROOT / "courts/phase18/timing/dudect_bn.c"),
        f"-L{libdir}", "-lcrypto", "-lm", f"-Wl,-rpath,{libdir}", "-o", str(binary),
    ], timeout=300)
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"dudect harness did not compile: {err[:400]}")
    env = {"LD_LIBRARY_PATH": str(libdir)}
    prefix: list[str] = []
    if shutil.which("taskset"):
        prefix = ["taskset", "-c", "1"]

    def dudect(mode: str):
        rc, out, err = run_cmd(prefix + [str(binary), mode, "20000"], env=env, timeout=600)
        text = out + err
        state = None
        m = re.search(rf"dudect\.done mode={re.escape(mode)} batches=\d+ state=(\d+)", text)
        if m:
            state = int(m.group(1))
        return rc, text, state

    rc, text, state = dudect("cmpnaive")
    result.cases.append(Case(
        name="positive control (naive comparator) reports leakage",
        exit=rc,
        expected=(0,),
        ok=state == 0,
        detail=f"state={state} tail={text[-300:]!r}",
    ))
    rc, text, state = dudect("cmpcmp")
    result.cases.append(Case(
        name="negative control (constant-time comparator) reports no leakage evidence",
        exit=rc,
        expected=(1,),
        ok=state == 1,
        detail=f"state={state} tail={text[-300:]!r}",
    ))
    result.summary.append("20000 measurements per batch at the recorded geometry, "
                          "pinned with taskset -c 1; the vendored header is the "
                          "pinned dc269651 copy with its digest checked before "
                          "the harness is built; the harness's own exit status "
                          "is inverted (0 = leakage), so the state line is the "
                          "observation that is checked")
    return result


# ---------------------------------------------------------------------------
# control: PMU venue probe


def control_pmu_venue_probe(tmp: Path) -> ControlResult:
    result = ControlResult("pmu-venue-probe")
    probe_src = REPO_ROOT / "courts/phase18/timing/pmu_probe.c"
    probe = tmp / "pmu_probe"
    rc, out, err = run_cmd(["cc", "-O2", "-o", str(probe), str(probe_src)], timeout=120)
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"pmu_probe did not compile: {err[:300]}")
    rc, out, err = run_cmd([str(probe)], timeout=60)
    text = out + err
    result.cases.append(Case(
        name="CPUID reports no architectural PMU at this venue",
        exit=rc,
        expected=(0,), ok=(rc == 0 and "cpuid.0A.version=0" in text), detail=text[:400]))
    rc, out, err = run_cmd(["perf", "stat", "-e", "cycles", "true"], timeout=60)
    text = out + err
    result.cases.append(Case(
        name="perf cannot count cycles (no PMU counter)",
        exit=rc,
        expected=(0, 1),
        ok="not supported" in text,
        detail=text[:400]))
    rc, out, err = run_cmd(["perf", "stat", "-e", "task-clock", "true"], timeout=60)
    text = out + err
    result.cases.append(Case(
        name="perf software events work (so the cycles failure is the venue, not a broken tool)",
        exit=rc,
        expected=(0,),
        ok=(rc == 0 and "task-clock" in text),
        detail=text[:400]))
    result.summary.append("this is a venue probe: absence of a PMU is recorded as a "
                          "venue limitation, not as an instrument property")
    return result


# ---------------------------------------------------------------------------
# control: analysis suites


def _suite_control(control_id: str, script: str, minimum: int) -> ControlResult:
    result = ControlResult(control_id)
    rc, out, err = run_cmd([sys.executable, str(REPO_ROOT / script)], timeout=900)
    text = out + err
    m = re.search(r"Ran (\d+) tests?", text)
    ran = int(m.group(1)) if m else -1
    ok = rc == 0 and ran >= minimum and "FAILED" not in text
    result.cases.append(Case(
        name=f"{script} passes with at least {minimum} tests",
        exit=0 if ok else 1,
        expected=(0,), ok=ok,
        detail=f"rc={rc} ran={ran} tail={text[-300:]!r}"))
    return result


def control_differential_analysis(tmp: Path) -> ControlResult:
    result = _suite_control("differential-analysis-controls",
                            "forensics/tools/tests/test_analyse_bench_api.py", 34)
    result.summary.append("covers the population, order, cross-verification and "
                          "strict-JSON refusals of the differential campaign "
                          "analyser; the live cross-library differential is bound "
                          "to PFP-0 and is not re-run here")
    return result


def control_etp_claims(tmp: Path) -> ControlResult:
    result = _suite_control("etp-claims-controls",
                            "forensics/tools/tests/test_etp_claims.py", 59)
    result.summary.append("covers the claim-algebra refusals, including admission "
                          "of exclusion witnesses and duplicate-key refusal")
    return result


def control_alloc_probe(tmp: Path) -> ControlResult:
    result = ControlResult("alloc-probe-control")
    lib = tmp / "liballocprobe.so"
    rc, out, err = run_cmd([
        "cc", "-O2", "-fPIC", "-shared",
        str(REPO_ROOT / "courts/phase18/timing/alloc_probe.c"),
        "-ldl", "-o", str(lib),
    ], timeout=120)
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"alloc_probe did not compile: {err[:300]}")
    source = tmp / "probe_user.c"
    source.write_text(
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "void allocprobe_reset(void);\n"
        "unsigned long allocprobe_alloc_calls(void);\n"
        "void allocprobe_fail_after(unsigned long);\n"
        "int main(void) {\n"
        "  void *a, *b, *c, *d; unsigned long n;\n"
        "  allocprobe_reset(); a = malloc(16); b = malloc(16);\n"
        "  n = allocprobe_alloc_calls();\n"
        "  printf(\"count=%lu first=%d second=%d\\n\", n, a != NULL, b != NULL);\n"
        "  free(a); free(b);\n"
        "  allocprobe_reset(); allocprobe_fail_after(2);\n"
        "  c = malloc(16); d = malloc(16);\n"
        "  printf(\"forced first=%d second=%d\\n\", c != NULL, d != NULL);\n"
        "  if (c) free(c); if (d) free(d);\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    exe = tmp / "probe_user"
    rc, out, err = run_cmd([
        "cc", "-O2", str(source), f"-L{tmp}", "-lallocprobe",
        f"-Wl,-rpath,{tmp}", "-o", str(exe),
    ], timeout=120)
    if rc != 0:
        raise Refusal("IQ_CONTROL_FIXTURE", f"probe consumer did not compile: {err[:300]}")
    rc, out, err = run_cmd([str(exe)], env={"LD_PRELOAD": str(lib)}, timeout=120)
    text = out + err
    result.cases.append(Case(
        name="the probe counts every allocation entry point it interposes",
        exit=rc, expected=(0,),
        ok=(rc == 0 and "count=2 first=1 second=1" in text), detail=text[:300]))
    result.cases.append(Case(
        name="the forced-failure path fails exactly the requested allocation",
        exit=rc, expected=(0,),
        ok=(rc == 0 and "forced first=1 second=0" in text), detail=text[:300]))
    result.summary.append("alloc_probe.c built as the LD_PRELOAD object the PFP-0 "
                          "campaign uses; the fixture allocates twice and then "
                          "forces the second allocation to fail")
    return result


def control_reproducibility(tmp: Path) -> ControlResult:
    result = ControlResult("reproducibility-comparison-control")
    rc, out, err = run_cmd(
        ["bash", str(REPO_ROOT / "forensics/tools/build_reproducibility.sh"),
         "--self-test"],
        timeout=300,
    )
    text = out + err
    ok = (rc == 0 and "SELFTEST identical-archives OK" in text
          and "SELFTEST differing-archives detected" in text)
    result.cases.append(Case(
        name="identical archives compare equal and a differing byte is detected",
        exit=0 if ok else 1,
        expected=(0,), ok=ok,
        detail=f"rc={rc} tail={text[-400:]!r}"))
    result.summary.append("exercises the archive/comparison primitives on a tiny "
                          "fixture; the full two-build recipe is bound to ETP-2 and "
                          "is not re-run")
    return result


CONTROLS = {
    "branch-audit-gate": control_branch_audit_gate,
    "binsec-gate": control_binsec_gate,
    "ctgrind-sensitivity": control_ctgrind_sensitivity,
    "dudect-sensitivity": control_dudect_sensitivity,
    "pmu-venue-probe": control_pmu_venue_probe,
    "differential-analysis-controls": control_differential_analysis,
    "etp-claims-controls": control_etp_claims,
    "reproducibility-comparison-control": control_reproducibility,
    "alloc-probe-control": control_alloc_probe,
}


def run_control(control_id: str) -> ControlResult:
    if control_id not in CONTROLS:
        raise Refusal("IQ_CONTROL_UNKNOWN", f"no implementation for control {control_id!r}")
    with tempfile.TemporaryDirectory(prefix="etp3-") as tmpdir:
        return CONTROLS[control_id](Path(tmpdir))


# ---------------------------------------------------------------------------
# register validation


INSTRUMENT_FIELDS = {
    "id", "name", "kind", "paths", "invocation", "intended_use", "not_its_use",
    "version_validation", "failure_modes", "soundness_limits", "scope",
    "sensitivity_control", "fail_closed",
}


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise Refusal(code, message)


def validate_instrument(index: int, entry: dict, root: Path) -> None:
    where = f"instruments[{index}]"
    require(isinstance(entry, dict), "IQ_INSTRUMENT_TYPE", f"{where} is not an object")
    missing = INSTRUMENT_FIELDS - set(entry)
    extra = set(entry) - INSTRUMENT_FIELDS
    require(not missing, "IQ_INSTRUMENT_FIELD", f"{where}: missing fields {sorted(missing)}")
    require(not extra, "IQ_INSTRUMENT_FIELD", f"{where}: unknown fields {sorted(extra)}")
    ident = entry["id"]
    require(isinstance(ident, str) and ident, "IQ_INSTRUMENT_ID", f"{where}: empty id")
    require(entry["kind"] in KINDS, "IQ_INSTRUMENT_KIND",
            f"{where} ({ident}): kind must be one of {sorted(KINDS)}")
    require(isinstance(entry["paths"], list) and entry["paths"],
            "IQ_INSTRUMENT_PATH", f"{where} ({ident}): paths must be a non-empty list")
    for rel in entry["paths"]:
        require(isinstance(rel, str) and rel, "IQ_INSTRUMENT_PATH",
                f"{where} ({ident}): non-string path")
        require((root / rel).exists(), "IQ_PATH_MISSING",
                f"{where} ({ident}): path does not exist: {rel}")
    for field_name in ("intended_use", "invocation"):
        require(isinstance(entry[field_name], str) and entry[field_name],
                "IQ_INSTRUMENT_FIELD", f"{where} ({ident}): {field_name} must be text")
    for field_name in ("not_its_use", "soundness_limits"):
        require(isinstance(entry[field_name], list) and entry[field_name],
                "IQ_INSTRUMENT_FIELD",
                f"{where} ({ident}): {field_name} must be a non-empty list")

    version = entry["version_validation"]
    require(isinstance(version, dict), "IQ_VERSION", f"{where} ({ident}): version not an object")
    for key in ("command", "observed", "identity_method"):
        require(isinstance(version.get(key), str) and version.get(key),
                "IQ_VERSION", f"{where} ({ident}): version_validation.{key} must be text")

    # A nonzero version probe is not the default contract.  One tool may
    # legitimately print its version and then exit nonzero, but an instrument
    # must declare that allowance per entry, with a justification, or the
    # checker refuses the nonzero probe.
    accept_nonzero = version.get("accept_nonzero_exit", False)
    require(isinstance(accept_nonzero, bool), "IQ_VERSION",
            f"{where} ({ident}): version_validation.accept_nonzero_exit must be a boolean")
    justification = version.get("nonzero_exit_justification")
    if accept_nonzero:
        require(isinstance(justification, str) and justification.strip(),
                "IQ_VERSION_JUSTIFICATION",
                f"{where} ({ident}): accept_nonzero_exit requires a non-empty "
                f"version_validation.nonzero_exit_justification")

    rc, out, err = run_cmd(["bash", "-c", version["command"]], timeout=60)
    text = out + err
    if rc != 0 and version["observed"] not in text:
        raise Refusal(
            "IQ_VERSION_COMMAND",
            f"{where} ({ident}): version command failed: rc={rc} {text.strip()[:200]}",
        )
    require(version["observed"] in text, "IQ_VERSION_MISMATCH",
            f"{where} ({ident}): recorded version {version['observed']!r} not produced "
            f"by {version['command']!r}; observed: {text.strip()[:200]!r}")
    if rc != 0 and not accept_nonzero:
        raise Refusal(
            "IQ_VERSION_NONZERO",
            f"{where} ({ident}): version command exited {rc} while printing the "
            f"recorded string; this instrument does not declare "
            f"accept_nonzero_exit, so a nonzero probe is refused "
            f"({version['command']!r})",
        )

    modes = entry["failure_modes"]
    require(isinstance(modes, dict), "IQ_FAILURE_MODES",
            f"{where} ({ident}): failure_modes must be an object")
    required_modes = {"false_positive", "false_negative", "silent_truncation",
                      "unsupported_target", "crash", "partial_output", "wrong_candidate"}
    require(required_modes <= set(modes), "IQ_FAILURE_MODES",
            f"{where} ({ident}): failure_modes missing {sorted(required_modes - set(modes))}")
    for key in required_modes:
        require(isinstance(modes[key], str) and modes[key], "IQ_FAILURE_MODES",
                f"{where} ({ident}): failure_modes.{key} must be text")

    scope = entry["scope"]
    require(isinstance(scope, dict) and isinstance(scope.get("profile"), str)
            and scope["profile"] and isinstance(scope.get("statement"), str)
            and scope["statement"], "IQ_SCOPE",
            f"{where} ({ident}): scope.profile and scope.statement are required")

    control = entry["sensitivity_control"]
    require(isinstance(control, dict), "IQ_CONTROL",
            f"{where} ({ident}): sensitivity_control must be an object")
    for key in ("mode", "status", "positive", "negative", "observed"):
        require(key in control, "IQ_CONTROL",
                f"{where} ({ident}): sensitivity_control.{key} is required")
    require(control["status"] in STATUSES, "IQ_CONTROL_STATUS",
            f"{where} ({ident}): status must be one of {sorted(STATUSES)}")
    require(control["mode"] in {"executable", "recorded"}, "IQ_CONTROL",
            f"{where} ({ident}): mode must be executable or recorded")
    if control["mode"] == "executable":
        cid = control.get("control_id")
        require(isinstance(cid, str) and cid in EXECUTABLE_CONTROLS, "IQ_CONTROL_UNKNOWN",
                f"{where} ({ident}): control_id must be one of "
                f"{sorted(EXECUTABLE_CONTROLS)}")
        require(control["status"] in {"PASS", "NOT_RUN"}, "IQ_CONTROL_STATUS",
                f"{where} ({ident}): an executable control cannot be RECORDED")
        require(isinstance(control["observed"], dict)
                and isinstance(control["observed"].get("cases"), list),
                "IQ_CONTROL", f"{where} ({ident}): observed.cases must be a list")
        prerequisite = control.get("prerequisite")
        if prerequisite is not None:
            require(isinstance(prerequisite, dict)
                    and isinstance(prerequisite.get("path"), str)
                    and isinstance(prerequisite.get("sha256"), str)
                    and isinstance(prerequisite.get("settling_method"), str),
                    "IQ_CONTROL_PREREQUISITE",
                    f"{where} ({ident}): prerequisite needs path, sha256 and "
                    f"settling_method")
            pre = root / prerequisite["path"]
            require(pre.exists(), "IQ_CONTROL_PREREQUISITE",
                    f"{where} ({ident}): control prerequisite is absent: "
                    f"{prerequisite['path']} ({prerequisite['settling_method']})")
            require(sha256_file(pre) == prerequisite["sha256"],
                    "IQ_CONTROL_PREREQUISITE",
                    f"{where} ({ident}): control prerequisite {prerequisite['path']} "
                    f"changed; re-qualify the control")
    else:
        binding = control.get("binding")
        require(isinstance(binding, dict) and isinstance(binding.get("path"), str)
                and isinstance(binding.get("sha256"), str), "IQ_RECORD_BINDING",
                f"{where} ({ident}): a recorded control needs binding.path and "
                f"binding.sha256")
        require(control["status"] == "RECORDED", "IQ_CONTROL_STATUS",
                f"{where} ({ident}): a recorded control's status must be RECORDED, "
                f"never {control['status']}")
        require(isinstance(control.get("settling_method"), str)
                and control["settling_method"], "IQ_RECORD_BINDING",
                f"{where} ({ident}): a recorded control needs settling_method")
        bound = root / binding["path"]
        require(bound.exists(), "IQ_RECORD_BINDING",
                f"{where} ({ident}): bound evidence is absent: {binding['path']}")
        require(sha256_file(bound) == binding["sha256"], "IQ_RECORD_STALE",
                f"{where} ({ident}): bound evidence {binding['path']} changed "
                f"(recorded {binding['sha256'][:12]}..., now "
                f"{sha256_file(bound)[:12]}...)")
        assertions = control.get("assertions")
        require(isinstance(assertions, list) and assertions, "IQ_RECORD_BINDING",
                f"{where} ({ident}): recorded control needs assertions")
        text = bound.read_text(encoding="utf-8", errors="replace")
        for assertion in assertions:
            require(isinstance(assertion, str) and assertion in text,
                    "IQ_RECORD_STALE",
                    f"{where} ({ident}): bound evidence no longer contains "
                    f"{assertion!r}")

    fail_closed = entry["fail_closed"]
    require(isinstance(fail_closed, dict)
            and isinstance(fail_closed.get("exit_statuses"), dict)
            and isinstance(fail_closed.get("refusal_text"), str)
            and fail_closed["refusal_text"], "IQ_FAIL_CLOSED",
            f"{where} ({ident}): fail_closed.exit_statuses and .refusal_text required")


def validate_registry(document, root: Path) -> list[dict]:
    require(isinstance(document, dict), "IQ_REGISTRY_TYPE", "registry is not an object")
    for key in ("schema", "generated", "disclaimer", "venue", "instruments"):
        require(key in document, "IQ_REGISTRY_FIELD", f"registry missing {key}")
    require(document["schema"] == REGISTRY_SCHEMA, "IQ_REGISTRY_SCHEMA",
            f"schema must be {REGISTRY_SCHEMA!r}")
    require("not a security result" in document["disclaimer"], "IQ_DISCLAIMER",
            "disclaimer must state that instrument qualification is not a security result")
    venue = document["venue"]
    require(isinstance(venue, dict) and "pmu_present" in venue
            and "limitations" in venue, "IQ_VENUE",
            "venue must record pmu_present and limitations")
    require(venue["pmu_present"] is False, "IQ_VENUE",
            "this venue records no usable PMU; a different venue needs a new register")
    require(isinstance(venue["limitations"], list) and venue["limitations"],
            "IQ_VENUE", "venue.limitations must be a non-empty list")
    instruments = document["instruments"]
    require(isinstance(instruments, list) and instruments, "IQ_REGISTRY_FIELD",
            "instruments must be a non-empty list")
    seen = set()
    for index, entry in enumerate(instruments):
        validate_instrument(index, entry, root)
        ident = entry["id"]
        require(ident not in seen, "IQ_INSTRUMENT_ID", f"duplicate instrument id {ident!r}")
        seen.add(ident)
    return instruments


def check_against_controls(instruments: list[dict]) -> list[str]:
    lines: list[str] = []
    failures: list[str] = []
    for entry in instruments:
        control = entry["sensitivity_control"]
        if control["mode"] != "executable":
            lines.append(f"RECORDED {entry['id']}: bound to {control['binding']['path']}")
            continue
        if control["status"] == "NOT_RUN":
            lines.append(f"NOT_RUN  {entry['id']}: no control claimed")
            continue
        result = run_control(control["control_id"])
        live = result.table()
        recorded = [{"name": c.get("name"), "exit": c.get("exit")}
                    for c in control["observed"]["cases"]]
        if not result.passed:
            bad = [c for c in result.cases if not c.ok]
            failures.append(
                f"CONTROL_FAILED {entry['id']} ({control['control_id']}): "
                + "; ".join(f"{c.name} exit={c.exit} expected={c.expected}" for c in bad))
            continue
        if live != recorded:
            failures.append(
                f"CONTROL_STALE {entry['id']} ({control['control_id']}): live case "
                f"table differs from the register; recorded={recorded} live={live}")
            continue
        lines.append(f"PASS     {entry['id']} ({control['control_id']}): "
                     f"{len(live)} cases")
    if failures:
        raise Refusal("IQ_CONTROL_FAILED", "\n".join(failures))
    return lines


# ---------------------------------------------------------------------------
# CLI


def load_registry(path: Path):
    document = load_json_strict(path)
    return document


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", nargs="?", default="check",
                        choices=("check", "validate", "controls"))
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--only", action="append", default=[],
                        help="restrict controls to these instrument ids")
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    try:
        document = load_registry(Path(args.registry).resolve())
        instruments = validate_registry(document, root)
        print(f"REGISTER ok: {len(instruments)} instruments, schema {document['schema']}")
        for entry in instruments:
            print(f"  - {entry['id']}: version {entry['version_validation']['observed']!r}")
        if args.command == "validate":
            return EXIT_OK
        selected = instruments
        if args.only:
            unknown = sorted(set(args.only) - {e["id"] for e in instruments})
            require(not unknown, "IQ_SELECTION", f"--only names unknown instruments {unknown}")
            selected = [e for e in instruments if e["id"] in args.only]
        for line in check_against_controls(selected):
            print(line)
        print("QUALIFICATION ok: every requested control passed and matched the register")
        return EXIT_OK
    except Refusal as exc:
        print(f"REFUSED: {exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
