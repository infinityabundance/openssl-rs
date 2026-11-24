#!/usr/bin/env python3
"""adversarial_qualification.py -- A22: eight adversarial qualification experiments.

The problem this tool addresses is not "does the instrument work". It is: **an
instrument that cannot fail is not a measurement**. An instrument the project
relies on is exercised with an input on which it is *supposed* to refuse or
report a failure, and the observation is recorded. If the instrument returns
success, the instrument has a defect and this tool says so; it does not repair
another item's instrument, it records the finding with its owning item.

Eight experiments are mandatory (``REQUIRED_EXPERIMENTS``). Each declares:

* **witnesses** -- a constructed input, the refusal the instrument should
  produce, and whether that witness is ``rejected`` (the instrument must refuse)
  or ``accepted`` (the instrument must *not* refuse). The accepted witness is
  the canary's input;
* **an expected refusal** -- a named exit status and a named code, or the
  explicit expectation "some nonzero exit carrying some named refusal" where the
  instrument has no code of its own;
* **a canary** -- the same harness output, scored by a *deliberately weak*
  detector (``accept_any``: any observation counts as a refusal). The canary
  requires that the weak detector says ``QUALIFIED`` where the strict detector
  says ``DEFECT``, and that the strict detector *does* see a refusal on a
  declared detection reference. A harness that reports the same verdict under
  both detectors would be hard-wired, and the canary refuses it.

Verdicts are per experiment and are never merged upward:

  ``QUALIFIED``  every rejected witness produced the named refusal.
  ``DEFECT``     no rejected witness produced a refusal: the instrument
                 returned success when it should not have.
  ``PARTIAL``    some witnesses refused and some did not.
  ``NOT_RUN``    a prerequisite (an external tool, or a build the experiment
                 needs) is unavailable, with the reason.

``NOT_RUN`` never counts as a qualification: ``assert_all_qualified`` refuses
with ``AQ_REFUSED_NOT_RUN_AS_QUALIFIED``.

Refusal codes (stable; ``docs/ADVERSARIAL-QUALIFICATION.md`` names every one,
and ``forensics/tools/tests/test_adversarial_qualification.py`` refuses a code
that appears in one and not the other):

  ``AQ_REFUSED_EXPERIMENT_ABSENT``      a required experiment, or the instrument
                                        file it names, is absent from the tree
  ``AQ_REFUSED_NO_CANARY``              an experiment declares no canary input
  ``AQ_REFUSED_NOT_RUN_AS_QUALIFIED``   a ``NOT_RUN`` experiment is asked to
                                        count as a qualification
  ``AQ_REFUSED_EXPECTED_ABSENT``        a rejected witness declares no expected
                                        exit status or no expected code
  ``AQ_REFUSED_WITNESS_ABSENT``         a declared witness produced no
                                        observation, or a recorded witness line
                                        no longer exists in the tree
  ``AQ_REFUSED_UNSTABLE``               two runs of one experiment disagree
  ``AQ_REFUSED_CANARY_NOT_DETECTED``    the canary did not discriminate: the
                                        strict detector did not report
                                        ``DEFECT`` on the accepted input, the
                                        weak detector did not report
                                        ``QUALIFIED``, or the strict detector
                                        missed the detection reference
  ``AQ_DEFECT_FOUND``                   an experiment's verdict is ``DEFECT`` or
                                        ``PARTIAL``: the instrument returned
                                        success when it should have refused

What qualification establishes, and what it does not
----------------------------------------------------
It establishes that **these instruments refused these inputs**, and that the
harness can tell a refusal from an acceptance (the canary). It does **not**
establish that an instrument is sound, complete, or correct on any other input.
Where a fixture stands in for a real tool -- the BINSEC and Z3 shims (E1, E2),
the two objdump shims (E3), the mutated timing receipt (E4), the constructed
valgrind logs (E5), the synthetic omission population (E8) -- the real solver,
timing harness (and candidate DSO) or memcheck run did not happen. Every such
substitution is recorded in the experiment's ``reported`` block and in
``docs/ADVERSARIAL-QUALIFICATION.md`` under ``NOT_RUN``.

Usage:

    python3 forensics/tools/adversarial_qualification.py run [--json] [--runs N]
    python3 forensics/tools/adversarial_qualification.py explain E1
    python3 forensics/tools/adversarial_qualification.py canary [--json]

Exit status: 0 when all eight are ``QUALIFIED`` (``canary``: all eight canaries
detected); 1 when any is ``DEFECT``/``PARTIAL``/``NOT_RUN`` or a refusal fires;
2 for a usage error.

SPDX-License-Identifier: Apache-2.0
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
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/adversarial_qualification.py"

#: The worktree HEAD this item was measured on. Recording the constant, rather
#: than the live HEAD, is what lets the producer re-run byte-identically after
#: the orchestrator commits the item: the evidence is bound to the candidate it
#: measured, not to whatever commit happens to be checked out later. The refresh
#: after the E5/E6/E7 repairs re-measured the eight experiments at the repair
#: commit; the earlier record named ``6e64e644c``.
BASE_COMMIT = "e4029e0d5"
BASE_COMMIT_LONG = "e4029e0d5c4300bb097e1241c0bab34b069c9da6"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "AQ_OK"
CODE_USAGE = "AQ_USAGE"

VERDICT_QUALIFIED = "QUALIFIED"
VERDICT_DEFECT = "DEFECT"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_NOT_RUN = "NOT_RUN"
VERDICTS = (VERDICT_QUALIFIED, VERDICT_DEFECT, VERDICT_PARTIAL, VERDICT_NOT_RUN)

AQ_REFUSED_EXPERIMENT_ABSENT = "AQ_REFUSED_EXPERIMENT_ABSENT"
AQ_REFUSED_NO_CANARY = "AQ_REFUSED_NO_CANARY"
AQ_REFUSED_NOT_RUN_AS_QUALIFIED = "AQ_REFUSED_NOT_RUN_AS_QUALIFIED"
AQ_REFUSED_EXPECTED_ABSENT = "AQ_REFUSED_EXPECTED_ABSENT"
AQ_REFUSED_WITNESS_ABSENT = "AQ_REFUSED_WITNESS_ABSENT"
AQ_REFUSED_UNSTABLE = "AQ_REFUSED_UNSTABLE"
AQ_REFUSED_CANARY_NOT_DETECTED = "AQ_REFUSED_CANARY_NOT_DETECTED"
AQ_DEFECT_FOUND = "AQ_DEFECT_FOUND"

#: Every refusal, with the wrong conclusion it prevents. Stable identifiers.
REFUSALS: dict[str, dict[str, str]] = {
    AQ_REFUSED_EXPERIMENT_ABSENT: {
        "condition": "a required experiment id is absent from the registry, the "
                     "registry names an instrument file that does not exist, or "
                     "``explain``/``--only`` names an id the registry does not have",
        "prevents": "that seven experiments read as the eight the item requires, "
                    "and that an experiment about a file the tree no longer holds "
                    "counts as qualified",
    },
    AQ_REFUSED_NO_CANARY: {
        "condition": "an experiment declares no accepted (canary) witness, or its "
                     "canary block names no detection reference",
        "prevents": "that a green verdict is evidence only that no test was written, "
                    "because nothing shows the harness can tell a refusal from an "
                    "acceptance",
    },
    AQ_REFUSED_NOT_RUN_AS_QUALIFIED: {
        "condition": "``assert_all_qualified`` is given a result whose verdict is "
                     "``NOT_RUN``",
        "prevents": "that an unavailable instrument is reported as a qualified one; "
                    "a deferred experiment is never a pass",
    },
    AQ_REFUSED_EXPECTED_ABSENT: {
        "condition": "a rejected witness declares no expected exit status, or no "
                     "expected code and no explicit ``any-refusal`` expectation",
        "prevents": "that an experiment cannot fail because it never said what a "
                    "failure would look like",
    },
    AQ_REFUSED_WITNESS_ABSENT: {
        "condition": "a declared witness produced no observation, or a classified "
                     "register consumer file is absent",
        "prevents": "that a removed witness, or a consumer list that has drifted, "
                    "silently shrinks the experiment",
    },
    AQ_REFUSED_UNSTABLE: {
        "condition": "two runs of the same experiment over the same inputs produce "
                     "different observations",
        "prevents": "that a single favourable run is quoted as the experiment's "
                    "result; an unstable measurement is not a measurement",
    },
    AQ_REFUSED_CANARY_NOT_DETECTED: {
        "condition": "the strict detector reports a refusal on an accepted input, "
                     "the weak detector does not report ``QUALIFIED`` on it, or the "
                     "strict detector misses the experiment's own detection reference",
        "prevents": "that the harness verdict is produced by the harness rather than "
                    "by the instrument's behaviour",
    },
    AQ_DEFECT_FOUND: {
        "condition": "an experiment's observed verdict is ``DEFECT`` or ``PARTIAL``",
        "prevents": "that an instrument which returned success when it should have "
                    "refused is recorded as qualified, or that the finding is dropped "
                    "because another experiment passed",
    },
}

#: The eight experiments the item requires. A registry missing one is refused.
REQUIRED_EXPERIMENTS = ("E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8")

BINSEC = "courts/phase18/timing/binsec_checkct.sh"
AUDIT = "courts/phase18/timing/binary_branch_audit.py"
SUMMARIZE_CT = "courts/phase18/timing/summarize_ct.py"
DUDECT_HEADER = "courts/phase18/timing/third_party/dudect/dudect.h"
PREREG_CHECK = "forensics/tools/preregistration_check.py"
PREREG = "evidence/etp-t7/PREREGISTRATION.json"
DUDECT_RECEIPT = "evidence/etp-t7/DUDECT-ETP-T7.json"
SECRETS = "evidence/etp-t7/SECRETS.json"
SARIF = "forensics/tools/sarif_adapter.py"
SIDE_CHANNEL = "forensics/tools/side_channel_erasure.py"
INSTRUMENT_QUALIFY = "forensics/tools/instrument_qualify.py"
POLICY_ENGINE = "forensics/tools/policy_engine.py"
POLICY = "evidence/a20/POLICY.json"
POLICY_PIN = "evidence/a20/POLICY-PIN.json"
OMISSION = "forensics/tools/omission.py"

#: A named refusal in some tool's output. Instruments that carry their own
#: codes (`***_REFUSED_***`) and instruments that print a REASON line are both
#: covered; the accepted-input check requires *neither* to be present.
REFUSAL_CODE_RE = re.compile(r"\b[A-Z][A-Z0-9]*_REFUSED[A-Z0-9_]*\b")
REFUSAL_WORD_RE = re.compile(r"\brefused\b", re.IGNORECASE)


class Refusal(Exception):
    """A stable refusal: ``code`` is printed and never reworded."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class PrerequisiteMissing(Exception):
    """An external tool or a build the experiment needs is unavailable."""


class WitnessAbsent(Exception):
    """A declared witness produced no observation."""


# ---------------------------------------------------------------------------
# Digests and normalisation
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _cap(text: str, limit: int = 4000) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


class Canon:
    """Normalise machine-specific text so two runs are byte-comparable.

    A temporary directory, the repository root and the interpreter path all
    differ between runs and machines. They are replaced by stable tokens; the
    fixture bytes themselves are deterministic (verified by the two-run
    stability check), so everything else is left exactly as observed.
    """

    def __init__(self, tmp: Path) -> None:
        self.tokens = [
            (str(tmp.resolve()), "<tmp>"),
            (str(tmp), "<tmp>"),
            (str(REPO_ROOT.resolve()), "<repo>"),
            (str(REPO_ROOT), "<repo>"),
            (sys.executable, "python3"),
            ("/usr/bin/python3", "python3"),
        ]
        self.version_lines = re.compile(
            r"^(- objdump: |# binsec: |# z3: ).*$", re.MULTILINE
        )
        # The A20 engine prints the digest of the *pin document*. The pin this
        # experiment writes embeds the run's temporary policy path, so its digest
        # legitimately differs between runs; the policy digest (the thing under
        # test) is stable and is left alone.
        self.pin_digest = re.compile(r"\bpin=[0-9a-f]{64}")

    def text(self, value: str) -> str:
        for needle, token in self.tokens:
            value = value.replace(needle, token)
        value = self.version_lines.sub(r"\1<tool-version>", value)
        return self.pin_digest.sub("pin=<pin-digest>", value)

    def command(self, argv: list[str], env: dict[str, str] | None = None) -> str:
        prefix = ""
        if env:
            prefix = " ".join(f"{key}={self.text(value)}" for key, value in sorted(env.items()))
            prefix += " "
        return self.text(prefix + " ".join(argv))


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 180.0,
    cwd: Path | None = None,
) -> tuple[int, str]:
    merged = dict(os.environ)
    merged.pop("AQ_MODE", None)
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd or REPO_ROOT),
            env=merged,
        )
    except FileNotFoundError:
        return 127, f"executable-not-found: {argv[0]}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, f"{out}\ntimeout after {timeout:g}s"
    # stderr is merged into stdout at the file-descriptor level, so the recorded
    # order is the order the instrument wrote, not stdout-then-stderr.
    return proc.returncode, proc.stdout


def write_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise PrerequisiteMissing(f"{name} is not on PATH")


def compile_asm(tmp: Path, name: str, asm: str) -> Path:
    require_tool("cc")
    source = tmp / f"{name}.S"
    source.write_text(asm, encoding="utf-8")
    out = tmp / f"{name}.so"
    rc, text = run(["cc", "-shared", "-nostdlib", "-o", str(out), str(source)])
    if rc != 0:
        raise PrerequisiteMissing(f"cc could not build {name}.so: {text.strip()[:300]}")
    return out


def compile_elf(tmp: Path, name: str) -> Path:
    require_tool("cc")
    source = tmp / f"{name}.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    out = tmp / name
    rc, text = run(["cc", "-o", str(out), str(source)])
    if rc != 0:
        raise PrerequisiteMissing(f"cc could not build {name}: {text.strip()[:300]}")
    return out


# ---------------------------------------------------------------------------
# Fixtures (the constructed inputs; every digest is taken from these bytes)
# ---------------------------------------------------------------------------

BINSEC_SHIM = """#!/bin/sh
# A stand-in BINSEC. It produces the verdict lines a real BINSEC emits; it does
# not run a solver, so this control qualifies the wrapper's contract, not any
# solver verdict.
case " $* " in
  *" -version "*) echo "Binsec version 0.0.0-aq-control" ; exit 0 ;;
esac
case "${AQ_MODE:-}" in
  secure)          echo '[checkct:result] Program status is : secure' ; exit 0 ;;
  secure_nonzero)  echo '[checkct:result] Program status is : secure' ; exit 1 ;;
  mixed)           printf '%s\\n' '[checkct:result] Program status is : secure' \
                                    '[checkct:result] Program status is : insecure' ; exit 0 ;;
  timed_pair)      printf '%s\\n' '[checkct:result] Program status is : secure' \
                                    '[checkct:result] Program status is : secure (0.030)' ; exit 0 ;;
  trailing_ws)     printf '[checkct:result] Program status is : secure \\n' ; exit 0 ;;
  trailing_text)   echo '[checkct:result] Program status is : secure (0.030) but the exploration was incomplete' ; exit 0 ;;
  silent)          exit 0 ;;
  *)               echo "unknown fake mode" >&2 ; exit 9 ;;
esac
"""

Z3_SHIM = """#!/bin/sh
[ "$1" = "--version" ] && echo "Z3 version 0.0.0-aq-control"
exit 0
"""

AUDIT_SYMBOL = "audit_symbol"
AUDIT_ASM = """
    .text
    .globl _RNvNtCx_2aq12audit_symbol
    .type _RNvNtCx_2aq12audit_symbol,@function
_RNvNtCx_2aq12audit_symbol:
    pushq %rbp
    movq %rsp, %rbp
    cmpl $0, %edi
    je 1f
    xorl %eax, %eax
    addl $1, %eax
    nop
    subl $2, %eax
1:
    popq %rbp
    ret
    .size _RNvNtCx_2aq12audit_symbol, .-_RNvNtCx_2aq12audit_symbol
"""

#: No `.size`, so the symbol table declares an extent of zero. The audit must
#: refuse rather than invent a window.
AUDIT_ZERO_ASM = """
    .text
    .globl _RNvNtCx_2aq12audit_symbol
    .type _RNvNtCx_2aq12audit_symbol,@function
_RNvNtCx_2aq12audit_symbol:
    ret
"""

#: The final identifier is `audit_symbol` but the v0 length prefix says 99. The
#: exact length-prefixed match must reject it; a plain `endswith` would accept.
AUDIT_MALFORMED_ASM = """
    .text
    .globl _RNvNtCx_2aq99audit_symbol
    .type _RNvNtCx_2aq99audit_symbol,@function
_RNvNtCx_2aq99audit_symbol:
    ret
    .size _RNvNtCx_2aq99audit_symbol, .-_RNvNtCx_2aq99audit_symbol
"""

OBJDUMP_TRUNCATE_SHIM = """#!/bin/sh
case "$1" in
  -t|--version) exec /usr/bin/objdump "$@" ;;
esac
exec /usr/bin/objdump "$@" | awk 'BEGIN{n=0} /^[[:space:]]*[0-9a-f]+:/{n++; if (n>3) exit} {print}'
"""

OBJDUMP_MALFORMED_SHIM = """#!/bin/sh
case "$1" in
  -t)
    printf '%s\\n' '0000000000001000 g     F .text	00000000000000zz _RNvNtCx_2aq12audit_symbol'
    exit 0 ;;
  --version) exec /usr/bin/objdump "$@" ;;
  *) exec /usr/bin/objdump "$@" ;;
esac
"""

OMISSION_PLAN = {
    "id": "AQ-FREEZE",
    "candidate": {"commit": "0" * 40, "branch": "staging"},
    "frozenAt": "2026-11-24T00:00:00Z",
    "state": "FROZEN",
    "members": [
        {
            "id": "present",
            "path": "gate/present.bin",
            "phase": "AQ",
            "predicate": "a produced member exists",
            "required": True,
        },
        {
            "id": "absent",
            "path": "gate/absent.bin",
            "phase": "AQ",
            "predicate": "a produced member exists",
            "required": True,
        },
    ],
}

#: Consumers of the instrument register, classified by how they read it.
#: ``permissive`` used to mean the bytes are parsed by ``json.loads`` with no
#: duplicate-key hook, so ``{"a":1,"a":2}`` reads as ``{"a":2}``. The two
#: consumers that did so are repaired: each now reads the register with
#: ``harden.loads`` and refuses a duplicate key with ``PH_REFUSED_DUPLICATE_KEY``.
#: A consumer's witness is now the observed refusal of the duplicate-key
#: document, not the presence of a source line: a legitimate repair changed the
#: old lines and made a text-bound witness non-reproducible. The ``probe``
#: field names the behaviour that is run; ``shared-loader`` and
#: ``byte-identity`` consumers are classified but are exercised through the
#: strict reader (``instrument_qualify``) or not parsed at all.
REGISTER_CONSUMERS = [
    {
        "path": "forensics/tools/instrument_qualify.py",
        "item": "ETP-3",
        "loader": "strict",
        "reason": "load_json_strict: object_pairs_hook rejects a duplicate key, "
                  "non-finite numbers and a BOM",
        "probe": {"mode": "shared-loader", "entry": "instrument_qualify.load_json_strict"},
    },
    {
        "path": "forensics/tools/etp6_verify.py",
        "item": "ETP-6",
        "loader": "strict",
        "reason": "delegates to instrument_qualify.load_registry, which is "
                  "load_json_strict",
        "probe": {"mode": "shared-loader", "entry": "etp6_verify -> instrument_qualify.load_registry"},
    },
    {
        "path": "forensics/tools/release_gate.py",
        "item": "release gate (item 4)",
        "loader": "strict",
        "reason": "runs `instrument_qualify.py check --registry`, so the parser is "
                  "the strict one",
        "probe": {"mode": "shared-loader", "entry": "release_gate -> instrument_qualify.py check"},
    },
    {
        "path": "forensics/tools/etp_t1_seed.py",
        "item": "ETP-T1",
        "loader": "strict",
        "reason": "load_instruments uses harden.loads, which refuses a duplicate "
                  "key, a BOM, trailing data and non-finite numbers",
        "probe": {"mode": "cli", "entry": "etp_t1_seed --instruments",
                  "refusal": "PH_REFUSED_DUPLICATE_KEY"},
    },
    {
        "path": "forensics/tools/freshness.py",
        "item": "A7",
        "loader": "strict",
        "reason": "_instrument_entries uses harden.loads and raises JsonError on a "
                  "refusal, so a duplicate key no longer resolves last-wins",
        "probe": {"mode": "function", "entry": "freshness._instrument_entries",
                  "refusal": "PH_REFUSED_DUPLICATE_KEY"},
    },
    {
        "path": "forensics/tools/intoto.py",
        "item": "A9",
        "loader": "byte-identity",
        "reason": "names the register as a subject and hashes its bytes; it does "
                  "not parse it, so a parse-level difference is not observed here",
        "probe": {"mode": "byte-identity", "entry": "digest only"},
    },
    {
        "path": "forensics/tools/verify.py",
        "item": "ETP-0",
        "loader": "byte-identity",
        "reason": "binds the register by digest only",
        "probe": {"mode": "byte-identity", "entry": "digest only"},
    },
]


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    case: str
    kind: str  # "rejected" | "accepted" | "detection"
    input: dict
    command: str
    exit: int | None
    output: str
    output_sha256: str
    output_truncated: bool
    expectation: dict

    def to_dict(self) -> dict:
        return {
            "case": self.case,
            "kind": self.kind,
            "input": self.input,
            "command": self.command,
            "exit": self.exit,
            "output": self.output,
            "outputSha256": self.output_sha256,
            "outputTruncated": self.output_truncated,
            "expected": self.expectation,
        }


@dataclass
class ExperimentSpec:
    id: str
    title: str
    instruments: tuple[str, ...]
    hypothesis: str
    expected: str
    harness: object
    canary_accepted: str
    canary_detection: str
    notes: str = ""


def _input_ref(parts: dict[str, bytes], description: str) -> dict:
    digest = hashlib.sha256()
    for name in sorted(parts):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(parts[name])
    return {
        "kind": "generated",
        "producedBy": TOOL_PATH,
        "description": description,
        "parts": sorted(parts),
        "sha256": digest.hexdigest(),
    }


def _observe(
    canon: Canon,
    *,
    case: str,
    kind: str,
    input_ref: dict,
    argv: list[str],
    env: dict[str, str] | None,
    expectation: dict,
    timeout: float = 180.0,
) -> Observation:
    rc, text = run(argv, env=env, timeout=timeout)
    normalised = canon.text(text)
    full_sha = sha256_bytes(normalised.encode("utf-8"))
    capped, truncated = _cap(normalised)
    return Observation(
        case=case,
        kind=kind,
        input=input_ref,
        command=canon.command(argv, env),
        exit=rc,
        output=capped,
        output_sha256=full_sha,
        output_truncated=truncated,
        expectation=expectation,
    )


def _expectation(exit: object, code: str | None) -> dict:
    return {"exit": exit, "code": code}


def refusal_present(text: str) -> bool:
    return bool(REFUSAL_CODE_RE.search(text) or REFUSAL_WORD_RE.search(text))


def strict_detects(observation: Observation) -> bool:
    """Did the instrument behave as this witness requires?

    ``rejected``/``detection``: the declared exit status (or any nonzero), *and*
    the declared code (or any named refusal). ``accepted``: the declared exit
    status and *no* named refusal anywhere in the output. A ``detection``
    witness is a refused input that is used only as the canary's reference, so
    it does not enter the experiment's verdict.
    """
    expectation = observation.expectation
    wanted_exit = expectation.get("exit")
    wanted_code = expectation.get("code")
    text = observation.output

    def exit_ok() -> bool:
        if wanted_exit is None:
            return True
        if wanted_exit == "nonzero":
            return observation.exit is not None and observation.exit != 0
        return observation.exit in wanted_exit

    if observation.kind == "accepted":
        return exit_ok() and not refusal_present(text)
    if wanted_code == "any-refusal":
        code_ok = refusal_present(text)
    elif wanted_code:
        code_ok = wanted_code in text
    else:
        code_ok = True
    return exit_ok() and code_ok


def accept_any(observation: Observation) -> bool:
    """The deliberately weak detector: any observation counts as a refusal."""
    return True


# ---------------------------------------------------------------------------
# Harnesses. Each returns (observations, reported) and never repairs a tool.
# ---------------------------------------------------------------------------


def _require(path: str) -> Path:
    target = REPO_ROOT / path
    if not target.is_file():
        raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"{path} does not exist")
    return target


def harness_binsec_verdicts(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    script = _require(BINSEC)
    elf = compile_elf(tmp, "aq-tiny")
    cfg = tmp / "aq.cfg"
    cfg.write_text("starting from main\nexplore all\n", encoding="utf-8")
    shim = write_executable(tmp / "binsec-aq", BINSEC_SHIM)
    z3 = write_executable(tmp / "z3-aq", Z3_SHIM)
    source = _input_ref(
        {
            "binsec_shim": BINSEC_SHIM.encode(),
            "z3_shim": Z3_SHIM.encode(),
            "cfg": cfg.read_bytes(),
            "elf": elf.read_bytes(),
        },
        "stand-in BINSEC and Z3 executables, a trivial ELF and an SSE script",
    )

    def one(mode: str, case: str, kind: str, expectation: dict) -> Observation:
        env = {
            "BINSEC_BIN": str(shim),
            "BINSEC_Z3": str(z3),
            "AQ_MODE": mode,
            "BINSEC_WALL_TIMEOUT": "20",
        }
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=["bash", str(script), str(cfg), str(elf)],
            env=env,
            expectation=expectation,
        )

    observations = [
        one("mixed", "conflicting-verdicts", "rejected",
            _expectation([6], "mixed-verdicts")),
        one("secure_nonzero", "secure-with-nonzero-status", "rejected",
            _expectation([6], "secure-verdict-with-tool-status-1")),
        one("trailing_text", "verdict-with-trailing-text", "rejected",
            _expectation([3], "verdict-trailing-text")),
        one("secure", "secure-accepted", "accepted", _expectation([0], None)),
    ]
    mixed = observations[0]
    verdict_lines = [
        line for line in mixed.output.splitlines() if line.startswith("[checkct:result]")
    ]
    printed = [
        line for line in mixed.output.splitlines() if line.startswith("T16 verdict:")
    ]
    refusal_lines = [
        line for line in mixed.output.splitlines() if "REFUSED" in line
    ]
    return (
        observations,
        {
            "substitution": "the BINSEC and Z3 executables are stand-ins; the "
                            "wrapper's exit-status and verdict-population contract is "
                            "qualified, no solver verdict was produced",
            "mixed_case": {
                "verdict_lines": verdict_lines,
                "exit": mixed.exit,
                "verdict_printed": printed[0] if printed else None,
                "refusal": refusal_lines[0] if refusal_lines else None,
                "reading": "the wrapper prints both BINSEC status lines, then refuses "
                           "by name; it never prints `T16 verdict: ...`, so no caller can "
                           "read a verdict from this run",
            },
        },
    )


def harness_binsec_population(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    script = _require(BINSEC)
    elf = compile_elf(tmp, "aq-tiny")
    cfg = tmp / "aq.cfg"
    cfg.write_text("starting from main\nexplore all\n", encoding="utf-8")
    shim = write_executable(tmp / "binsec-aq", BINSEC_SHIM)
    z3 = write_executable(tmp / "z3-aq", Z3_SHIM)
    source = _input_ref(
        {
            "binsec_shim": BINSEC_SHIM.encode(),
            "z3_shim": Z3_SHIM.encode(),
            "cfg": cfg.read_bytes(),
            "elf": elf.read_bytes(),
        },
        "stand-in BINSEC and Z3 executables, a trivial ELF and an SSE script",
    )

    def one(mode: str, case: str, kind: str, expectation: dict) -> Observation:
        env = {
            "BINSEC_BIN": str(shim),
            "BINSEC_Z3": str(z3),
            "AQ_MODE": mode,
            "BINSEC_WALL_TIMEOUT": "20",
        }
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=["bash", str(script), str(cfg), str(elf)],
            env=env,
            expectation=expectation,
        )

    return (
        [
            one("silent", "zero-verdict-lines", "rejected",
                _expectation([3], "no-output")),
            one("timed_pair", "two-secure-lines", "rejected",
                _expectation([6], "duplicate-secure")),
            one("trailing_ws", "verdict-trailing-whitespace", "rejected",
                _expectation([3], "verdict-trailing-text")),
            one("secure", "secure-accepted", "accepted", _expectation([0], None)),
        ],
        {
            "prefix_match": "the second secure line is `secure (0.030)`, for which "
                            "`secure` is a prefix; the anchored grammar counts two "
                            "secure verdicts and refuses the ambiguity",
            "substitution": "stand-in BINSEC; the wrapper's grammar is qualified, "
                            "not a solver",
        },
    )


def harness_branch_audit(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    script = _require(AUDIT)
    require_tool("objdump")
    good = compile_asm(tmp, "aq-good", AUDIT_ASM)
    zero = compile_asm(tmp, "aq-zero", AUDIT_ZERO_ASM)
    malformed = compile_asm(tmp, "aq-malformed", AUDIT_MALFORMED_ASM)
    one = tmp / "aq-one.json"
    one.write_text(json.dumps([{"family": "aq core", "symbol": AUDIT_SYMBOL}]) + "\n")
    absent = tmp / "aq-absent.json"
    absent.write_text(json.dumps([{"family": "aq absent", "symbol": "absent_symbol"}]) + "\n")
    truncate = write_executable(tmp / "objdump-truncate", OBJDUMP_TRUNCATE_SHIM)
    bad_table = write_executable(tmp / "objdump-malformed", OBJDUMP_MALFORMED_SHIM)
    source = _input_ref(
        {
            "good_asm": AUDIT_ASM.encode(),
            "zero_asm": AUDIT_ZERO_ASM.encode(),
            "malformed_asm": AUDIT_MALFORMED_ASM.encode(),
            "one_manifest": one.read_bytes(),
            "absent_manifest": absent.read_bytes(),
            "truncate_shim": OBJDUMP_TRUNCATE_SHIM.encode(),
            "malformed_shim": OBJDUMP_MALFORMED_SHIM.encode(),
            "good_so": good.read_bytes(),
        },
        "three shared objects built from assembly, two inventories and two objdump shims",
    )
    def one_case(
        case: str,
        kind: str,
        args: list[str],
        expectation: dict,
        env: dict[str, str] | None = None,
    ) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[sys.executable, str(script), *args],
            env=env,
            expectation=expectation,
        )

    observations = [
        one_case("zero-size-symbol", "rejected",
                 ["--targets-file", str(one), str(zero)],
                 _expectation([1], "reason=zero-size")),
        one_case("malformed-length-prefix", "rejected",
                 ["--targets-file", str(one), str(malformed)],
                 _expectation([1], "reason=missing")),
        one_case("malformed-symbol-table-entry", "rejected",
                 ["--targets-file", str(one), str(good)],
                 _expectation([1], "reason=missing"),
                 env={"OBJDUMP": str(bad_table)}),
        one_case("target-absent", "rejected",
                 ["--targets-file", str(absent), str(good)],
                 _expectation([1], "reason=missing")),
        one_case("disassembly-shorter-than-extent", "rejected",
                 ["--targets-file", str(one), str(good)],
                 _expectation([1], "disassembly-truncated"),
                 env={"OBJDUMP": str(truncate)}),
        one_case("good-symbol-accepted", "accepted",
                 ["--targets-file", str(one), str(good)], _expectation([0], None)),
    ]
    text = script.read_text(encoding="utf-8")

    def find_line(needle: str) -> int:
        for number, line in enumerate(text.splitlines(), 1):
            if needle in line:
                return number
        raise WitnessAbsent(f"{AUDIT}: no line contains {needle!r}")

    raw_line = find_line("raw = m.group(2).split()")
    max_line = find_line("MAX_INSN_BYTES = 15")
    return observations, {
        "coverage_from": "decoded instruction byte lengths (`len(raw)` at "
                         f"{AUDIT}:{raw_line}), not an address gap and not a maximum "
                         "instruction length",
        "max_insn_bytes": f"`MAX_INSN_BYTES = 15` at {AUDIT}:{max_line} is a sanity "
                          "bound on one decoded length, not the coverage test",
        "diagnosis": "a malformed symbol-table entry is refused as `reason=missing`; "
                     "there is no separate `malformed` code, so the audit refuses "
                     "without naming the malformation as such",
    }


def harness_timing(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    script = _require(PREREG_CHECK)
    prereg = _require(PREREG)
    receipt_path = _require(DUDECT_RECEIPT)
    base = json.loads(receipt_path.read_text(encoding="utf-8"))

    def write(mutate) -> Path:
        document = json.loads(json.dumps(base))
        mutate(document)
        out = tmp / f"aq-{hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()[:12]}.json"
        out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out

    merged = write(
        lambda doc: (
            doc["modes"]["cmpcmp"].update(total_measurements=10000, batches_run=1),
            doc["modes"]["cmpnaive"].update(total_measurements=10000, batches_run=1),
        )
    )
    short = write(lambda doc: doc["modes"]["cmpnaive"].update(total_measurements=5000, batches_run=1))
    failed = write(lambda doc: doc["modes"]["cmpnaive"].update(state=1))
    source = _input_ref(
        {
            "base_receipt": receipt_path.read_bytes(),
            "merged_receipt": merged.read_bytes(),
            "short_receipt": short.read_bytes(),
            "failed_receipt": failed.read_bytes(),
        },
        "the recorded dudect receipt and three mutations of it",
    )

    def one(case: str, kind: str, path: Path, expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[
                sys.executable, str(script),
                "--prereg", str(prereg),
                "--instance", "ETP-T7-DUDECT-INSTRUMENT-CONTROLS-1",
                "--receipt", str(path),
                "--repo-root", str(REPO_ROOT),
            ],
            env=None,
            expectation=expectation,
        )

    observations = [
        one("under-sampled-one-batch", "rejected", merged,
            _expectation([1], "PR_EARLY_STOP_WITHOUT_LEAK")),
        one("below-per-batch", "rejected", short,
            _expectation([1], "PR_TOTAL_NOT_MULTIPLE")),
        one("positive-control-ttest-failed", "rejected", failed,
            _expectation([1], "PR_POSITIVE_CONTROL_DID_NOT_FIRE")),
        one("recorded-receipt-accepted", "accepted", receipt_path,
            _expectation([0], None)),
    ]

    header = _require(DUDECT_HEADER).read_text(encoding="utf-8")

    def constant(name: str) -> int:
        match = re.search(
            rf"^#define\s+{re.escape(name)}\b(.*?)(?=^#|\Z)",
            header,
            re.MULTILINE | re.DOTALL,
        )
        digits = re.search(r"\d+", match.group(1)) if match else None
        if digits is None:
            raise WitnessAbsent(f"{DUDECT_HEADER}: no integer in #define {name}")
        return int(digits.group(0))

    geometry = base.get("geometry") or {}
    modes = base.get("modes") or {}
    return observations, {
        "thresholds": {
            "t_threshold_moderate": constant("t_threshold_moderate"),
            "t_threshold_bananas": constant("t_threshold_bananas"),
            "enough_measurements": constant("DUDECT_ENOUGH_MEASUREMENTS"),
            "source": DUDECT_HEADER,
        },
        "declared_geometry": {
            "per_batch": geometry.get("per_batch"),
            "max_batches": geometry.get("max_batches"),
            "runs": geometry.get("runs"),
        },
        "sample_counts_used": {
            name: {
                "total_measurements": entry.get("total_measurements"),
                "batch_size": geometry.get("per_batch"),
                "batches_run": entry.get("batches_run"),
                "state": entry.get("state"),
                "max_abs_t": entry.get("max_abs_t"),
            }
            for name, entry in sorted(modes.items())
        },
        "substitution": "the dudect harness and the real candidate DSO did not run; "
                        "the evidence validator is qualified on the recorded receipt "
                        "and on mutations of it",
    }


E5_CLAIM_DRIVER = '''#!/usr/bin/env python3
"""A thin adapter: call side_channel_erasure.check_claim and map its refusals
to an exit status. The refusal codes are the instrument's own."""
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import side_channel_erasure as se  # noqa: E402

claim = json.loads(Path(sys.argv[2]).read_text())
secrets = json.loads(Path(sys.argv[3]).read_text())
prereg = json.loads(Path(sys.argv[4]).read_text())
expected = None if sys.argv[5] == "-" else sys.argv[5]
refusals = se.check_claim(claim, secrets, prereg, expected_binary_identity=expected)
for code, detail in refusals:
    print(f"{code}: {detail}", file=sys.stderr)
print("AQ_ACCEPTED" if not refusals else "AQ_REFUSED")
raise SystemExit(1 if refusals else 0)
'''

#: The identity A22 supplies as the artefact under test for the mismatch
#: witness. It is a fixture, not the identity of a built binary: the experiment
#: proves that a supplied expectation is compared, not that a production caller
#: supplies one. ``E5_CLAIM_MISMATCHED`` records a different identity.
E5_EXPECTED_IDENTITY = "sha256:" + "aa" * 32

E5_CLAIM_MISMATCHED = {
    "id": "AQ-CT-IDENTITY",
    "kind": "constant_time",
    "statement": "the Montgomery ladder branch is constant-time",
    "evidence": {
        "kind": "ctgrind",
        "harness": "bn::bignum::tests::ctgrind_secret_base_fold_and_ladder",
        "binary_identity": "sha256:" + "de" * 32,
        "tainted_inputs": ["secret_scalar"],
    },
    "scope": {"artefact": "release"},
    "mechanism_ref": "BN-MONT-LADDER",
}

E5_CLAIM_NO_IDENTITY = {
    "id": "AQ-CT-NO-IDENTITY",
    "kind": "constant_time",
    "statement": "the Montgomery ladder branch is constant-time",
    "evidence": {
        "kind": "ctgrind",
        "harness": "bn::bignum::tests::ctgrind_secret_base_fold_and_ladder",
        "tainted_inputs": ["secret_scalar"],
    },
    "scope": {"artefact": "release"},
    "mechanism_ref": "BN-MONT-LADDER",
}


def harness_ctgrind(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    script = _require(SUMMARIZE_CT)
    _require(SIDE_CHANNEL)
    _require(SECRETS)
    _require(PREREG)
    empty = tmp / "aq-empty.log"
    empty.write_bytes(b"")
    unrelated = tmp / "aq-unrelated.log"
    unrelated.write_text(
        "==1== Memcheck, a memory error detector\n"
        "==1== Command: ./nothing-much\n"
        "==1==\n==1== HEAP SUMMARY:\n==1==   in use at exit: 0 bytes in 0 blocks\n",
        encoding="utf-8",
    )
    finding = tmp / "aq-finding.log"
    finding.write_text(
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x1000: mont_mul_into (fixture.S:6)\n"
        "==1==    by 0x2000: caller (fixture.S:20)\n",
        encoding="utf-8",
    )
    driver = write_executable(tmp / "aq-e5-claim.py", E5_CLAIM_DRIVER)
    mismatched = tmp / "aq-claim-mismatched.json"
    mismatched.write_text(json.dumps(E5_CLAIM_MISMATCHED, indent=2) + "\n", encoding="utf-8")
    no_identity = tmp / "aq-claim-no-identity.json"
    no_identity.write_text(json.dumps(E5_CLAIM_NO_IDENTITY, indent=2) + "\n", encoding="utf-8")
    source = _input_ref(
        {
            "empty_log": empty.read_bytes(),
            "unrelated_log": unrelated.read_bytes(),
            "finding_log": finding.read_bytes(),
            "claim_driver": E5_CLAIM_DRIVER.encode(),
            "claim_mismatched": mismatched.read_bytes(),
            "claim_no_identity": no_identity.read_bytes(),
        },
        "two valgrind logs, one log with a finding, and two ctgrind claims",
    )

    def summarize(log: Path, case: str, kind: str, expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[sys.executable, str(script), "0", str(log)],
            env=None,
            expectation=expectation,
        )

    def claim(path: Path, case: str, kind: str, expectation: dict,
              expected: str | None = None) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[
                sys.executable, str(driver), str(REPO_ROOT / "forensics/tools"),
                str(path), str(REPO_ROOT / SECRETS), str(REPO_ROOT / PREREG),
                expected if expected is not None else "-",
            ],
            env=None,
            expectation=expectation,
        )

    observations = [
        summarize(empty, "empty-log", "rejected",
                  _expectation([3], "CT_SUMMARY_EMPTY_LOG")),
        summarize(unrelated, "unrelated-log-only", "rejected",
                  _expectation([4], "CT_SUMMARY_UNRELATED_LOG")),
        claim(mismatched, "candidate-identity-mismatch", "rejected",
              _expectation([1], "CTGRIND_BINARY_IDENTITY_MISMATCH"),
              expected=E5_EXPECTED_IDENTITY),
        summarize(finding, "log-with-a-finding", "accepted", _expectation([0], None)),
        claim(no_identity, "missing-identity-detection-reference", "detection",
              _expectation([1], "CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT")),
    ]
    return observations, {
        "summarizer_contract": f"{SUMMARIZE_CT} now has an outcome contract: 0 is a "
                               "parsed, non-empty report; 3 empty, 4 unrelated or "
                               "zero-context, 5 malformed, 6 unreadable; no counts "
                               "are printed on a refusal",
        "identity_binding": "side_channel_erasure.check_claim compares the recorded "
                            "binary_identity with an expected identity when one is "
                            "supplied, and refuses a mismatch with "
                            "CTGRIND_BINARY_IDENTITY_MISMATCH",
        "identity_expectation": {
            "supplied": E5_EXPECTED_IDENTITY,
            "claim": E5_CLAIM_MISMATCHED["evidence"]["binary_identity"],
            "scope": "the expected identity is an A22 fixture, not a digest of a "
                     "built candidate binary",
        },
        "residual": "with no expected identity supplied, rule 2 remains presence-only: "
                    "A22's mismatch witness supplies one, but no production caller was "
                    "shown to supply it and no candidate binary was built",
        "detection_reference": "the claim with no `binary_identity` at all is refused "
                               "CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT, which shows the "
                               "same adjudicator does refuse when a field is absent",
    }


E6_DRIVER = '''#!/usr/bin/env python3
"""A thin adapter: call the SARIF adapter's own checks and map a Refusal to an
exit status. The refusal codes are the instrument's own."""
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import sarif_adapter as sa  # noqa: E402

mode = sys.argv[2]
try:
    if mode == "native-record":
        meta = sa._project_secrets(Path(sys.argv[3]))
        print(f"AQ_ACCEPTED findings={len(meta['findings'])}")
    else:
        document = json.loads(Path(sys.argv[3]).read_text())
        sa.validate_emission(document)
        print(f"AQ_ACCEPTED results={len(document['runs'][0]['results'])}")
except sa.Refusal as refusal:
    print(f"{refusal.code}: {refusal.detail}", file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0)
'''


def harness_sarif(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    _require(SARIF)
    _require(SECRETS)
    require_tool("python3")
    driver = write_executable(tmp / "aq-e6-sarif.py", E6_DRIVER)

    record = json.loads((REPO_ROOT / SECRETS).read_text(encoding="utf-8"))
    record["counts"] = dict(record["counts"])
    record["counts"]["SECRET_DATA"] = record["counts"]["SECRET_DATA"] + 1
    mirror = tmp / "mirror"
    (mirror / "evidence/etp-t7").mkdir(parents=True)
    (mirror / "evidence/etp-t7/SECRETS.json").write_text(json.dumps(record), encoding="utf-8")

    if str(REPO_ROOT / "forensics/tools") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "forensics/tools"))
    try:
        import sarif_adapter as sa  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - an absent module is a refusal
        raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"{SARIF}: {exc}") from exc
    try:
        document = sa.build_document(REPO_ROOT)
    except sa.Refusal as refusal:
        raise PrerequisiteMissing(
            f"{SARIF} refused to build the live emission: {refusal.code}: {refusal.detail}"
        ) from refusal
    emission = tmp / "aq-emission.json"
    emission.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    mutated = json.loads(json.dumps(document))
    run_zero = mutated["runs"][0]
    declared = run_zero["properties"]["a1"]["projection"]["projectedTotal"]
    if declared != len(run_zero["results"]):
        raise WitnessAbsent("the live emission's projectedTotal is not its result count")
    del run_zero["results"][0]
    truncated = tmp / "aq-emission-short.json"
    truncated.write_text(json.dumps(mutated, sort_keys=True), encoding="utf-8")

    source = _input_ref(
        {
            "mutated_record": (mirror / "evidence/etp-t7/SECRETS.json").read_bytes(),
            "live_emission": emission.read_bytes(),
            "short_emission": truncated.read_bytes(),
            "driver": E6_DRIVER.encode(),
        },
        "a native record whose declared population exceeds its entries, the live "
        "emission, and the same emission with one result removed",
    )

    def one(case: str, kind: str, mode: str, path: Path, expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[sys.executable, str(driver), str(REPO_ROOT / "forensics/tools"), mode, str(path)],
            env=None,
            expectation=expectation,
        )

    observations = [
        one("native-population-mismatch", "rejected", "native-record", mirror,
            _expectation([1], "SARIF_REFUSED_POPULATION_MISMATCH")),
        one("emission-result-count-mismatch", "rejected", "emission", truncated,
            _expectation([1], "SARIF_REFUSED_POPULATION_MISMATCH")),
        one("live-record-accepted", "accepted", "native-record", REPO_ROOT,
            _expectation([0], None)),
        one("live-emission-accepted", "accepted", "emission", emission,
            _expectation([0], None)),
    ]
    return observations, {
        "record_population": "the projection refuses a record whose declared counts "
                             "do not equal its entries (SARIF_REFUSED_POPULATION_MISMATCH)",
        "emission_population": "validate_emission refuses an emission whose result "
                               "count disagrees with projection.projectedTotal, with "
                               "the per-rule tallies, with the level counts, or with "
                               "the native population (SARIF_REFUSED_POPULATION_MISMATCH)",
        "emission_shape": {
            "run": 0,
            "declared_projectedTotal": declared,
            "results_before": declared,
            "results_after": declared - 1,
        },
        "substitution": "no SARIF consumer ran; the adapter's own checks were called",
    }


E7_DRIVER = '''#!/usr/bin/env python3
"""A thin adapter over the two strict readers and the repaired register
consumer. The refusal codes are theirs; the adapter only maps an exception to
an exit status."""
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import instrument_qualify as iq  # noqa: E402
import policy_engine as pe  # noqa: E402

path = Path(sys.argv[2])
which = sys.argv[3]
try:
    if which == "instrument-qualify":
        iq.load_json_strict(path)
    elif which == "policy-engine":
        pe.parse_json(path.read_bytes())
    elif which == "freshness":
        import freshness  # noqa: E402

        class _Repo:
            def text(self, commit, relative):
                return path.read_text(encoding="utf-8")

        try:
            freshness._instrument_entries(_Repo(), "0" * 40)
        except freshness.JsonError as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(1)
    else:
        print(f"AQ_USAGE: unknown consumer {which!r}", file=sys.stderr)
        raise SystemExit(2)
except iq.Refusal as refusal:
    print(refusal.code, file=sys.stderr)
    raise SystemExit(1)
except ValueError as error:
    print(f"PE_JSON_REFUSED: {error}", file=sys.stderr)
    raise SystemExit(1)
print("AQ_ACCEPTED")
raise SystemExit(0)
'''

E7_INPUTS = {
    "duplicate-key": b'{"a":1,"a":2}\n',
    "bom": b'\xef\xbb\xbf{"a":1}\n',
    "trailing-data": b'{"a":1}\ntrailing\n',
    "well-formed": b'{"a":1}\n',
}


def harness_strict_reader(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    _require(INSTRUMENT_QUALIFY)
    _require(POLICY_ENGINE)
    _require("forensics/tools/etp_t1_seed.py")
    _require("forensics/tools/freshness.py")
    driver = write_executable(tmp / "aq-e7-strict.py", E7_DRIVER)
    paths: dict[str, Path] = {}
    for name, data in E7_INPUTS.items():
        target = tmp / f"aq-{name}.json"
        target.write_bytes(data)
        paths[name] = target

    consumers = []
    for entry in REGISTER_CONSUMERS:
        consumer_path = REPO_ROOT / entry["path"]
        if not consumer_path.is_file():
            raise Refusal(AQ_REFUSED_WITNESS_ABSENT, f"{entry['path']} does not exist")
        consumers.append(
            {
                "path": entry["path"],
                "item": entry["item"],
                "loader": entry["loader"],
                "reason": entry["reason"],
                "probe": dict(entry["probe"]),
            }
        )

    tree = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "forensics/tools").glob("*.py")
        if path.relative_to(REPO_ROOT).as_posix() != TOOL_PATH
        and "evidence/etp3/instruments.json" in path.read_text(encoding="utf-8")
    )
    classified = sorted(entry["path"] for entry in REGISTER_CONSUMERS)
    unclassified = [item for item in tree if item not in classified]
    if unclassified:
        raise Refusal(
            AQ_REFUSED_WITNESS_ABSENT,
            f"a register consumer the list does not classify: {unclassified}",
        )

    source = _input_ref(
        {name: data for name, data in E7_INPUTS.items()} | {"driver": E7_DRIVER.encode()},
        "three malformed JSON documents, one well-formed document and the adapter",
    )

    def one(case: str, kind: str, which: str, name: str, expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[sys.executable, str(driver), str(REPO_ROOT / "forensics/tools"),
                  str(paths[name]), which],
            env=None,
            expectation=expectation,
        )

    # The two consumers that used to parse the register permissively are
    # witnessed by behaviour: run each one's own loader over the duplicate-key
    # document and require the refusal code. The seed's CLI is used so its
    # graph output goes to <tmp> rather than the worktree.
    seed_observation = _observe(
        canon,
        case="duplicate-key-etp-t1-seed",
        kind="rejected",
        input_ref=source,
        argv=[
            sys.executable, str(REPO_ROOT / "forensics/tools/etp_t1_seed.py"),
            "--instruments", str(paths["duplicate-key"]),
            "--output", str(tmp / "etp-t1-graph.json"),
        ],
        env=None,
        expectation=_expectation([1], "PH_REFUSED_DUPLICATE_KEY"),
    )
    freshness_observation = one(
        "duplicate-key-freshness", "rejected", "freshness", "duplicate-key",
        _expectation([1], "PH_REFUSED_DUPLICATE_KEY"),
    )

    observations = [
        one("duplicate-key-instrument", "rejected", "instrument-qualify", "duplicate-key",
            _expectation([1], "IQ_JSON_DUPLICATE_KEY")),
        one("bom-instrument", "rejected", "instrument-qualify", "bom",
            _expectation([1], "IQ_REGISTRY_UNREADABLE")),
        one("trailing-data-instrument", "rejected", "instrument-qualify", "trailing-data",
            _expectation([1], "IQ_REGISTRY_UNREADABLE")),
        one("duplicate-key-policy", "rejected", "policy-engine", "duplicate-key",
            _expectation([1], "PE_JSON_REFUSED")),
        one("bom-policy", "rejected", "policy-engine", "bom",
            _expectation([1], "PE_JSON_REFUSED")),
        one("trailing-data-policy", "rejected", "policy-engine", "trailing-data",
            _expectation([1], "PE_JSON_REFUSED")),
        seed_observation,
        freshness_observation,
        one("well-formed-instrument", "accepted", "instrument-qualify", "well-formed",
            _expectation([0], None)),
        one("well-formed-policy", "accepted", "policy-engine", "well-formed",
            _expectation([0], None)),
    ]
    consumer_probes = [
        {
            "path": "forensics/tools/etp_t1_seed.py",
            "case": seed_observation.case,
            "exit": seed_observation.exit,
            "refusalObserved": strict_detects(seed_observation),
        },
        {
            "path": "forensics/tools/freshness.py",
            "case": freshness_observation.case,
            "exit": freshness_observation.exit,
            "refusalObserved": strict_detects(freshness_observation),
        },
    ]
    accepted_by = [probe["path"] for probe in consumer_probes if probe["exit"] == 0]
    return observations, {
        "consumers": consumers,
        "consumer_probes": consumer_probes,
        "permissive_consumer_count": len(accepted_by),
        "permissive_consumers": accepted_by,
        "finding": (
            "the duplicate-key document is still accepted by: " + ", ".join(accepted_by)
            if accepted_by
            else "no tracked consumer accepts the duplicate-key document: both "
                 "etp_t1_seed.load_instruments and freshness._instrument_entries now "
                 "refuse it with PH_REFUSED_DUPLICATE_KEY. The earlier finding that "
                 "those two consumers read the register with plain json.loads is "
                 "historical (repaired in e4029e0d5)."
        ),
        "history": "on 6e64e644c etp_t1_seed.py (ETP-T1) and freshness.py (A7) read "
                   "the register with plain json.loads; both now read it with "
                   "harden.loads and refuse a duplicate key",
        "scope": "the duplicate-key input is the A11 pair {\"a\":1,\"a\":2}",
    }


def harness_policy_omission(tmp: Path, canon: Canon) -> tuple[list[Observation], dict]:
    _require(OMISSION)
    _require(POLICY_ENGINE)
    _require(POLICY)
    _require(POLICY_PIN)
    if str(REPO_ROOT / "forensics/tools") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "forensics/tools"))
    import policy_engine as pe  # noqa: WPS433

    policy = json.loads((REPO_ROOT / POLICY).read_text(encoding="utf-8"))
    pin = json.loads((REPO_ROOT / POLICY_PIN).read_text(encoding="utf-8"))

    def policy_files(name: str, mutate) -> tuple[Path, Path]:
        document = json.loads(json.dumps(policy))
        mutate(document)
        document["digest"] = pe.policy_digest(document)
        target = tmp / f"aq-policy-{name}.json"
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pin_document = json.loads(json.dumps(pin))
        pin_document["policyDigest"] = document["digest"]
        pin_document["policyPath"] = str(target.resolve())
        target_pin = tmp / f"aq-pin-{name}.json"
        target_pin.write_text(json.dumps(pin_document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return target, target_pin

    allow_policy, allow_pin = policy_files("default-allow", lambda doc: doc.update(default="allow"))
    score_policy, score_pin = policy_files("scores", lambda doc: doc.update(scores=True))

    # Omission: freeze -> close -> sign -> verify. The setup calls are not
    # witnesses; a failure in setup is a witness that produced nothing.
    observed_dir = tmp / "aq-observed"
    observed_dir.mkdir()
    (observed_dir / "present.bin").write_bytes(b"present\n")
    plan = tmp / "aq-plan.json"
    plan.write_text(json.dumps(OMISSION_PLAN, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    freeze = tmp / "aq-FREEZE.json"
    closure = tmp / "aq-closure.json"
    envelope = tmp / "aq-closure.envelope.json"
    setup: list[tuple[list[str], dict[str, str] | None]] = [
        ([sys.executable, str(REPO_ROOT / OMISSION), "freeze", str(plan), str(freeze)], None),
        ([sys.executable, str(REPO_ROOT / OMISSION), "close", "--observe-dir",
          str(observed_dir), "--recorded-at", "2026-11-24T01:00:00Z", str(freeze), str(closure)], None),
        ([sys.executable, str(REPO_ROOT / OMISSION), "sign", str(closure), str(envelope)], None),
    ]
    for argv, env in setup:
        rc, text = run(argv, env=env)
        if rc != 0:
            raise WitnessAbsent(f"omission setup failed: {canon.text(text).strip()[:300]}")

    closed = json.loads(closure.read_text(encoding="utf-8"))
    passing = json.loads(json.dumps(closed))
    passing["summary"]["pass"] = True
    passing_path = tmp / "aq-closure-pass.json"
    passing_path.write_text(json.dumps(passing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    passing_env = tmp / "aq-closure-pass.envelope.json"
    rc, text = run([sys.executable, str(REPO_ROOT / OMISSION), "sign", str(passing_path), str(passing_env)])
    if rc != 0:
        raise WitnessAbsent(f"omission sign failed: {canon.text(text).strip()[:300]}")

    mutated = json.loads(json.dumps(closed))
    mutated["summary"]["produced"] = 2
    mutated["summary"]["missing"] = 0
    mutated["members"][1]["state"] = "PRODUCED"
    mutated_path = tmp / "aq-closure-mutated.json"
    mutated_path.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    source = _input_ref(
        {
            "plan": plan.read_bytes(),
            "closed": closure.read_bytes(),
            "envelope": envelope.read_bytes(),
            "passing": passing_path.read_bytes(),
            "mutated": mutated_path.read_bytes(),
            # The two pins embed the run's temporary policy path; digest their
            # normalised form so the recorded input identity is comparable.
            "allow_policy": allow_policy.read_bytes(),
            "allow_pin": canon.text(allow_pin.read_text(encoding="utf-8")).encode("utf-8"),
            "score_policy": score_policy.read_bytes(),
            "score_pin": canon.text(score_pin.read_text(encoding="utf-8")).encode("utf-8"),
        },
        "two mutated policies with matching pins, a frozen population, and a signed "
        "reconciliation in three forms",
    )
    candidate = pin["candidate"]["commit"]

    def policy_case(case: str, path: Path, pin_path: Path, expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind="rejected",
            input_ref=source,
            argv=[sys.executable, str(REPO_ROOT / POLICY_ENGINE), "evaluate",
                  "--policy", str(path), "--pin", str(pin_path), "--candidate", candidate],
            env=None,
            expectation=expectation,
        )

    def omission_case(case: str, kind: str, args: list[str], expectation: dict) -> Observation:
        return _observe(
            canon,
            case=case,
            kind=kind,
            input_ref=source,
            argv=[sys.executable, str(REPO_ROOT / OMISSION), "verify", *args],
            env=None,
            expectation=expectation,
        )

    observations = [
        policy_case("default-allow", allow_policy, allow_pin,
                    _expectation([1], "PE_REFUSED_DEFAULT_ALLOW")),
        policy_case("policy-with-a-score", score_policy, score_pin,
                    _expectation([1], "PE_REFUSED_SCORE")),
        omission_case("pass-over-a-missing-member", "rejected",
                      [str(freeze), str(passing_path), str(passing_env)],
                      _expectation([1], "OM_REFUSED_PASS_WITH_MISSING")),
        omission_case("signed-bytes-mutated", "rejected",
                      [str(freeze), str(mutated_path), str(envelope)],
                      _expectation([1], "OM_REFUSED_RECONCILIATION_MUTATED")),
        omission_case("clean-reconciliation-accepted", "accepted",
                      [str(freeze), str(closure), str(envelope)], _expectation([0], None)),
        _observe(
            canon,
            case="live-policy-accepted", kind="accepted", input_ref=source,
            argv=[sys.executable, str(REPO_ROOT / POLICY_ENGINE), "evaluate",
                  "--candidate", candidate],
            env=None,
            expectation=_expectation([1], None),
        ),
    ]
    return observations, {
        "policy_default_allow": "validate_policy refuses default != 'deny'",
        "policy_score": "validate_policy refuses scores != false",
        "omission_pass_with_missing": "verify re-derives the summary and refuses a "
                                      "PASS while a required member is MISSING",
        "omission_mutated": "verify compares the envelope payload with the canonical "
                            "reconciliation bytes before checking the reconciliation",
        "accepted_note": "the live policy evaluates to DENY with no refusal code; "
                         "a denial is not a refusal code and the accepted witness "
                         "requires only that no refusal code fires",
        "pin_digest_note": "the `pin=` digest in the engine's output is recorded as "
                           "<pin-digest>: the pin embeds the run's temporary policy "
                           "path, so its digest is not comparable across runs. The "
                           "policy digest, which is what the refusal is about, is "
                           "left exactly as printed",
    }


EXPERIMENTS: list[ExperimentSpec] = [
    ExperimentSpec(
        id="E1",
        title="BINSEC wrapper: conflicting verdicts",
        instruments=(BINSEC,),
        hypothesis="A transcript carrying both a secure and an insecure verdict cannot "
                   "be resolved by the order of its lines, and a secure verdict that "
                   "carries any text after it is ambiguous.",
        expected="the wrapper refuses a mixed transcript, a secure verdict with a "
                 "nonzero tool status, and a verdict line with trailing text",
        harness=harness_binsec_verdicts,
        canary_accepted="secure-accepted",
        canary_detection="conflicting-verdicts",
        notes="the prior fail-open was `grep -Fq secure`, which accepted the mixed "
              "transcript; the anchored population parser is what is measured here",
    ),
    ExperimentSpec(
        id="E2",
        title="BINSEC wrapper: missing or duplicated verdict",
        instruments=(BINSEC,),
        hypothesis="Zero verdict lines is not a verdict, and two secure lines are not "
                   "one secure verdict.",
        expected="the wrapper refuses silence, two secure lines (one of which the "
                 "`secure` token is a prefix of) and a verdict line with trailing "
                 "whitespace",
        harness=harness_binsec_population,
        canary_accepted="secure-accepted",
        canary_detection="two-secure-lines",
        notes="the ambiguity witness is `secure (0.030)`, whose verdict token is a "
              "prefix-compatible second secure line",
    ),
    ExperimentSpec(
        id="E3",
        title="Binary branch audit: zero-size and malformed symbols",
        instruments=(AUDIT,),
        hypothesis="An extent the symbol table does not declare, an entry the table "
                   "cannot parse, an absent target and a disassembly shorter than the "
                   "extent each make the audit's population invalid.",
        expected="the audit refuses each with a named reason and exits nonzero",
        harness=harness_branch_audit,
        canary_accepted="good-symbol-accepted",
        canary_detection="zero-size-symbol",
        notes="coverage is established from decoded instruction byte lengths, not "
              "from address gaps or a maximum instruction length",
    ),
    ExperimentSpec(
        id="E4",
        title="Timing instrument: under-sampled or failed run",
        instruments=(PREREG_CHECK, DUDECT_RECEIPT),
        hypothesis="A run that stopped before its registered batch budget, a run whose "
                   "total is not a multiple of the batch size, and a positive control "
                   "that leaves its registered direction each make the receipt unable "
                   "to support a timing claim.",
        expected="the receipt validator refuses each with its named code and exits "
                 "nonzero; never a pass",
        harness=harness_timing,
        canary_accepted="recorded-receipt-accepted",
        canary_detection="under-sampled-one-batch",
        notes="the threshold and the sample count are reported from the pinned header "
              "and the recorded receipt, not typed into this tool",
    ),
    ExperimentSpec(
        id="E5",
        title="ctgrind: no errors because nothing ran",
        instruments=(SUMMARIZE_CT, SIDE_CHANNEL),
        hypothesis="A ctgrind result with zero contexts is indistinguishable from a run "
                   "that produced no memcheck output at all, and a claim whose "
                   "binary identity differs from the recorded one must not be admitted.",
        expected="the ctgrind evidence path refuses an empty log "
                 "(CT_SUMMARY_EMPTY_LOG), a log with only unrelated output "
                 "(CT_SUMMARY_UNRELATED_LOG), and a candidate-identity mismatch when "
                 "an expected identity is supplied "
                 "(CTGRIND_BINARY_IDENTITY_MISMATCH)",
        harness=harness_ctgrind,
        canary_accepted="log-with-a-finding",
        canary_detection="missing-identity-detection-reference",
        notes="this is the experiment the item expected to be able to fail; it now "
              "refuses all three. A22 supplies a fixture expected identity, so the "
              "mismatch is witnessed; the residual is that a caller which supplies "
              "no identity is still presence-only, and no candidate binary was built",
    ),
    ExperimentSpec(
        id="E6",
        title="SARIF: population mismatch",
        instruments=(SARIF,),
        hypothesis="A native record whose declared population disagrees with its own "
                   "entries, and an emission whose result count disagrees with the "
                   "record, each make the projection's population statement false.",
        expected="the adapter refuses both with SARIF_REFUSED_POPULATION_MISMATCH",
        harness=harness_sarif,
        canary_accepted="live-emission-accepted",
        canary_detection="native-population-mismatch",
        notes="the native-record half and the emission half are both implemented; "
              "the live emission is accepted, the one-result-short emission is refused",
    ),
    ExperimentSpec(
        id="E7",
        title="Strict parser versus a permissive consumer",
        instruments=(INSTRUMENT_QUALIFY, POLICY_ENGINE),
        hypothesis="A duplicate key, a byte-order mark and trailing data each have no "
                   "single meaning, so a strict reader refuses them while json.loads "
                   "accepts the first by keeping the last value.",
        expected="both strict readers refuse all three inputs; both repaired "
                 "register consumers refuse the duplicate-key document with "
                 "PH_REFUSED_DUPLICATE_KEY, and a finding is recorded only if a "
                 "consumer still accepts it",
        harness=harness_strict_reader,
        canary_accepted="well-formed-instrument",
        canary_detection="duplicate-key-instrument",
        notes="the duplicate-key input is the A11 pair {\"a\":1,\"a\":2}; the two "
              "consumers are witnessed by running their own loader, not by the "
              "presence of a source line",
    ),
    ExperimentSpec(
        id="E8",
        title="Policy and omission",
        instruments=(POLICY_ENGINE, OMISSION),
        hypothesis="A default-allow policy, a scored policy, a PASS over a missing "
                   "member and signed bytes changed after signing each produce a "
                   "conclusion the record does not support.",
        expected="each is refused with its named code: PE_REFUSED_DEFAULT_ALLOW, "
                 "PE_REFUSED_SCORE, OM_REFUSED_PASS_WITH_MISSING, "
                 "OM_REFUSED_RECONCILIATION_MUTATED",
        harness=harness_policy_omission,
        canary_accepted="clean-reconciliation-accepted",
        canary_detection="default-allow",
        notes="the policy is the live A20 policy with one field changed and its "
              "digest recomputed, so the shape refusal is the one under test",
    ),
]


# ---------------------------------------------------------------------------
# Verdicts, canary, stability
# ---------------------------------------------------------------------------


@dataclass
class CanaryResult:
    accepted_case: str
    detection_case: str
    probes: list[dict] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return all(probe["ok"] for probe in self.probes)

    def to_dict(self) -> dict:
        return {
            "acceptedCase": self.accepted_case,
            "detectionCase": self.detection_case,
            "detected": self.detected,
            "probes": self.probes,
        }


@dataclass
class ExperimentResult:
    spec: ExperimentSpec
    verdict: str
    reason: str
    observations: list[Observation]
    canary: CanaryResult | None
    reported: dict
    instrument_sha256: dict
    refused: int
    rejected: int
    codes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.spec.id,
            "title": self.spec.title,
            "hypothesis": self.spec.hypothesis,
            "expected": self.spec.expected,
            "instruments": list(self.spec.instruments),
            "instrumentSha256": self.instrument_sha256,
            "verdict": self.verdict,
            "reason": self.reason,
            "refusedWitnesses": self.refused,
            "rejectedWitnesses": self.rejected,
            "codes": self.codes,
            "observations": [observation.to_dict() for observation in self.observations],
            "canary": self.canary.to_dict() if self.canary else None,
            "reported": self.reported,
            "notes": self.spec.notes,
        }


def _instrument_digests(spec: ExperimentSpec) -> dict:
    digests: dict[str, str] = {}
    for relative in spec.instruments:
        path = REPO_ROOT / relative
        if not path.is_file():
            raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"{spec.id}: {relative} does not exist")
        digests[relative] = sha256_file(path)
    return digests


def _verdict(spec: ExperimentSpec, observations: list[Observation]) -> tuple[str, str, int, int]:
    rejected = [item for item in observations if item.kind == "rejected"]
    if not rejected:
        raise Refusal(AQ_REFUSED_EXPECTED_ABSENT, f"{spec.id}: no rejected witness")
    refused = [item for item in rejected if strict_detects(item)]
    if len(refused) == len(rejected):
        return VERDICT_QUALIFIED, "every rejected witness produced its named refusal", len(refused), len(rejected)
    missing = [item.case for item in rejected if not strict_detects(item)]
    if not refused:
        return (
            VERDICT_DEFECT,
            "the instrument returned success on: " + ", ".join(missing),
            len(refused),
            len(rejected),
        )
    return (
        VERDICT_PARTIAL,
        "refused " + str(len(refused)) + " of " + str(len(rejected)) + "; accepted: " + ", ".join(missing),
        len(refused),
        len(rejected),
    )


def _canary(spec: ExperimentSpec, observations: list[Observation]) -> CanaryResult:
    accepted = {item.case: item for item in observations if item.kind == "accepted"}
    detection_pool = {
        item.case: item for item in observations if item.kind in ("rejected", "detection")
    }
    if spec.canary_accepted not in accepted:
        raise Refusal(
            AQ_REFUSED_NO_CANARY,
            f"{spec.id}: no accepted witness named {spec.canary_accepted!r}",
        )
    if spec.canary_detection not in detection_pool:
        raise Refusal(
            AQ_REFUSED_NO_CANARY,
            f"{spec.id}: no detection reference named {spec.canary_detection!r}",
        )
    canary_input = accepted[spec.canary_accepted]
    detection = detection_pool[spec.canary_detection]
    primary = next(item for item in observations if item.kind == "rejected")
    # Flip the accepted input's role: ask the same harness whether *this* input
    # produced the refusal the experiment expects. The instrument accepted it,
    # so the strict detector must report that no refusal occurred. A weak
    # detector that accepts any observation reports the opposite.
    flipped = replace(
        canary_input,
        case=f"{canary_input.case}/flipped",
        kind="rejected",
        expectation=dict(primary.expectation),
    )
    probes = [
        {
            "probe": "strict-detector-on-the-accepted-input",
            "case": flipped.case,
            "detected": strict_detects(flipped),
            "expected": False,
            "ok": not strict_detects(flipped),
            "means": "the harness reports DEFECT when the instrument accepted the input",
        },
        {
            "probe": "weak-detector-on-the-same-input",
            "case": flipped.case,
            "detected": accept_any(flipped),
            "expected": True,
            "ok": accept_any(flipped),
            "means": "a detector that accepts any observation reports QUALIFIED on the "
                     "same input, so the strict detector is what produces the verdict",
        },
        {
            "probe": "strict-detector-on-the-detection-reference",
            "case": detection.case,
            "detected": strict_detects(detection),
            "expected": True,
            "ok": strict_detects(detection),
            "means": "the harness does see a refusal when the instrument produces one",
        },
    ]
    return CanaryResult(
        accepted_case=spec.canary_accepted,
        detection_case=spec.canary_detection,
        probes=probes,
    )


def _observations_equal(first: list[Observation], second: list[Observation]) -> bool:
    def canonical(items: list[Observation]) -> str:
        return json.dumps([item.to_dict() for item in items], sort_keys=True)

    return canonical(first) == canonical(second)


def run_experiment(spec: ExperimentSpec, *, runs: int = 2, tmp_root: Path | None = None) -> ExperimentResult:
    if runs < 1:
        raise Refusal(CODE_USAGE, "runs must be at least 1")
    digests = _instrument_digests(spec)
    if tmp_root is None:
        with tempfile.TemporaryDirectory(prefix="aq-") as directory:
            return run_experiment(spec, runs=runs, tmp_root=Path(directory))
    attempts: list[tuple[list[Observation], dict]] = []
    for _ in range(runs):
        with tempfile.TemporaryDirectory(prefix="aq-run-", dir=tmp_root) as directory:
            tmp = Path(directory)
            canon = Canon(tmp)
            try:
                observations, reported = spec.harness(tmp, canon)
            except PrerequisiteMissing as missing:
                return ExperimentResult(
                    spec=spec,
                    verdict=VERDICT_NOT_RUN,
                    reason=str(missing),
                    observations=[],
                    canary=None,
                    reported={},
                    instrument_sha256=digests,
                    refused=0,
                    rejected=0,
                    codes=[],
                )
            except WitnessAbsent as absent:
                raise Refusal(AQ_REFUSED_WITNESS_ABSENT, f"{spec.id}: {absent}") from absent
            attempts.append((observations, reported))
    if len(attempts) > 1 and not _observations_equal(attempts[0][0], attempts[1][0]):
        raise Refusal(
            AQ_REFUSED_UNSTABLE,
            f"{spec.id}: two runs over identical inputs produced different observations",
        )
    observations, reported = attempts[0]
    for item in observations:
        if item.kind == "rejected":
            expectation = item.expectation
            if expectation.get("exit") is None or (
                expectation.get("code") is None and expectation.get("code") != "any-refusal"
            ):
                raise Refusal(
                    AQ_REFUSED_EXPECTED_ABSENT,
                    f"{spec.id}/{item.case}: a rejected witness declares no expected "
                    "exit status or code",
                )
    verdict, reason, refused, rejected = _verdict(spec, observations)
    canary = _canary(spec, observations)
    codes: list[str] = []
    if verdict in (VERDICT_DEFECT, VERDICT_PARTIAL):
        codes.append(AQ_DEFECT_FOUND)
    if not canary.detected:
        codes.append(AQ_REFUSED_CANARY_NOT_DETECTED)
    return ExperimentResult(
        spec=spec,
        verdict=verdict,
        reason=reason,
        observations=observations,
        canary=canary,
        reported=reported,
        instrument_sha256=digests,
        refused=refused,
        rejected=rejected,
        codes=codes,
    )


def select(experiments: list[ExperimentSpec], only: str | None) -> list[ExperimentSpec]:
    ids = [spec.id for spec in experiments]
    missing = [identifier for identifier in REQUIRED_EXPERIMENTS if identifier not in ids]
    if missing:
        raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"the registry omits {missing}")
    if only is None:
        return experiments
    chosen = [spec for spec in experiments if spec.id == only]
    if not chosen:
        raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"no experiment {only!r} in the registry")
    return chosen


def run_all(
    *,
    runs: int = 2,
    only: str | None = None,
    experiments: list[ExperimentSpec] | None = None,
    tmp_root: Path | None = None,
) -> list[ExperimentResult]:
    chosen = select(experiments if experiments is not None else EXPERIMENTS, only)
    return [run_experiment(spec, runs=runs, tmp_root=tmp_root) for spec in chosen]


def assert_all_qualified(results: list[ExperimentResult]) -> list[ExperimentResult]:
    """Refuse to count a NOT_RUN as a qualification, then refuse a defect."""
    for result in results:
        if result.verdict == VERDICT_NOT_RUN:
            raise Refusal(
                AQ_REFUSED_NOT_RUN_AS_QUALIFIED,
                f"{result.spec.id}: NOT_RUN ({result.reason}) is not a qualification",
            )
    for result in results:
        if result.verdict in (VERDICT_DEFECT, VERDICT_PARTIAL):
            raise Refusal(
                AQ_DEFECT_FOUND,
                f"{result.spec.id}: {result.verdict} -- {result.reason}",
            )
    for result in results:
        if result.canary is None or not result.canary.detected:
            raise Refusal(
                AQ_REFUSED_CANARY_NOT_DETECTED,
                f"{result.spec.id}: the canary did not discriminate",
            )
        if result.verdict != VERDICT_QUALIFIED:
            raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"{result.spec.id}: not qualified")
    return results


def summary(results: list[ExperimentResult]) -> dict:
    counts = {verdict: 0 for verdict in VERDICTS}
    for result in results:
        counts[result.verdict] += 1
    codes = sorted({code for result in results for code in result.codes})
    return {
        "experiments": len(results),
        "qualified": counts[VERDICT_QUALIFIED],
        "defect": counts[VERDICT_DEFECT],
        "partial": counts[VERDICT_PARTIAL],
        "notRun": counts[VERDICT_NOT_RUN],
        "allQualified": counts[VERDICT_QUALIFIED] == len(results) == len(REQUIRED_EXPERIMENTS),
        "codes": codes,
    }


# ---------------------------------------------------------------------------
# Synthetic experiments, used only by the refusal controls
# ---------------------------------------------------------------------------


def _stub_spec(
    identifier: str,
    harness,
    *,
    canary_accepted: str = "accepted",
    canary_detection: str = "rejected",
    instruments: tuple[str, ...] = (BINSEC,),
) -> ExperimentSpec:
    return ExperimentSpec(
        id=identifier,
        title=f"synthetic control {identifier}",
        instruments=instruments,
        hypothesis="a synthetic experiment, used only to exercise the harness's own refusals",
        expected="a refusal",
        harness=harness,
        canary_accepted=canary_accepted,
        canary_detection=canary_detection,
        notes="control-only; never an evidence population",
    )


def _stub_observation(case: str, kind: str, exit: int, output: str, expectation: dict) -> Observation:
    return Observation(
        case=case,
        kind=kind,
        input={"kind": "synthetic", "description": "control-only"},
        command=f"synthetic {case}",
        exit=exit,
        output=output,
        output_sha256=sha256_bytes(output.encode()),
        output_truncated=False,
        expectation=expectation,
    )


def _stub_harness(rejects: bool, hardwired: bool = False):
    def harness(tmp: Path, canon: Canon):
        del tmp, canon
        rejected = _stub_observation(
            "rejected", "rejected", 1 if rejects else 0,
            "AQ_REFUSED_SYNTHETIC: refused" if rejects else "AQ_ACCEPTED",
            _expectation("nonzero", "any-refusal"),
        )
        # `hardwired` models a harness whose input is not what it reports on: the
        # accepted witness is dressed as a refusal, so flipping it still reads as
        # a refusal and the canary must notice.
        accepted = _stub_observation(
            "accepted", "accepted", 1 if hardwired else 0,
            "AQ_REFUSED_SYNTHETIC: a refusal on the accepted input" if hardwired else "AQ_ACCEPTED",
            _expectation([0], None),
        )
        return [rejected, accepted], {"synthetic": True}

    return harness


def _unstable_harness():
    state = {"n": 0}

    def harness(tmp: Path, canon: Canon):
        state["n"] += 1
        exit_code = 1 if state["n"] == 1 else 0
        rejected = _stub_observation(
            "rejected", "rejected", exit_code,
            "AQ_REFUSED_SYNTHETIC: refused" if exit_code else "AQ_ACCEPTED",
            _expectation("nonzero", "any-refusal"),
        )
        accepted = _stub_observation("accepted", "accepted", 0, "AQ_ACCEPTED", _expectation([0], None))
        return [rejected, accepted], {"synthetic": True}

    return harness


# ---------------------------------------------------------------------------
# Controls: one per refusal code, plus the canary record
# ---------------------------------------------------------------------------


def _control(identifier: str, code: str | None, description: str, thunk, **extra) -> dict:
    observed: dict = {"codes": [], "verdict": None, "detail": ""}
    try:
        value = thunk()
        if isinstance(value, ExperimentResult):
            observed["verdict"] = value.verdict
            observed["detail"] = value.reason
            observed["codes"] = list(value.codes)
        else:
            observed["detail"] = str(value)
    except Refusal as refusal:
        observed["codes"] = [refusal.code]
        observed["detail"] = refusal.message
    except PrerequisiteMissing as missing:
        observed["detail"] = f"NOT_RUN: {missing}"
    established = (code in observed["codes"]) if code else not observed["codes"]
    return {
        "id": identifier,
        "kind": "control-only",
        "code": code,
        "description": description,
        "observed": observed,
        "established": established,
        **extra,
    }


def build_controls() -> dict:
    def run_stub(harness, *, runs: int = 2) -> ExperimentResult:
        return run_experiment(_stub_spec("C", harness), runs=runs)

    def absent_experiment() -> None:
        select([spec for spec in EXPERIMENTS if spec.id != "E8"], None)

    def absent_instrument() -> ExperimentResult:
        return run_experiment(
            _stub_spec("C", _stub_harness(True), instruments=("forensics/tools/absent-aq-tool.py",))
        )

    def no_canary() -> ExperimentResult:
        return run_experiment(_stub_spec("C", _stub_harness(True), canary_accepted="not-a-witness"))

    def expected_absent() -> ExperimentResult:
        def harness(tmp: Path, canon: Canon):
            del tmp, canon
            return (
                [
                    _stub_observation("rejected", "rejected", 1, "AQ_REFUSED_SYNTHETIC", _expectation(None, None)),
                    _stub_observation("accepted", "accepted", 0, "AQ_ACCEPTED", _expectation([0], None)),
                ],
                {},
            )

        return run_experiment(_stub_spec("C", harness))

    def witness_absent() -> ExperimentResult:
        def harness(tmp: Path, canon: Canon):
            del tmp, canon
            raise WitnessAbsent("the declared input is absent")

        return run_experiment(_stub_spec("C", harness))

    def unstable() -> ExperimentResult:
        return run_experiment(_stub_spec("C", _unstable_harness()), runs=2)

    def canary_not_detected() -> ExperimentResult:
        return run_experiment(_stub_spec("C", _stub_harness(True, hardwired=True)), runs=1)

    def defect_found() -> ExperimentResult:
        def harness(tmp: Path, canon: Canon):
            del tmp, canon
            return (
                [
                    _stub_observation("rejected", "rejected", 0, "AQ_ACCEPTED",
                                      _expectation("nonzero", "any-refusal")),
                    _stub_observation("detected", "detection", 1,
                                      "AQ_REFUSED_SYNTHETIC: refused",
                                      _expectation([1], "AQ_REFUSED_SYNTHETIC")),
                    _stub_observation("accepted", "accepted", 0, "AQ_ACCEPTED",
                                      _expectation([0], None)),
                ],
                {},
            )

        spec = _stub_spec("C", harness, canary_detection="detected")
        return run_experiment(spec, runs=1)

    def not_run_as_qualified() -> None:
        def harness(tmp: Path, canon: Canon):
            del tmp, canon
            raise PrerequisiteMissing("cc is not on PATH")

        result = run_experiment(_stub_spec("C", harness), runs=1)
        assert_all_qualified([result])

    def qualified_stub() -> ExperimentResult:
        return run_experiment(_stub_spec("C", _stub_harness(True)), runs=2)

    controls = [
        _control(
            "experiment-absent", AQ_REFUSED_EXPERIMENT_ABSENT,
            "a registry missing one of the eight required experiments",
            absent_experiment,
        ),
        _control(
            "experiment-instrument-absent", AQ_REFUSED_EXPERIMENT_ABSENT,
            "an experiment naming an instrument file the tree does not hold",
            absent_instrument,
        ),
        _control(
            "no-canary", AQ_REFUSED_NO_CANARY,
            "an experiment whose canary names no accepted witness",
            no_canary,
        ),
        _control(
            "not-run-as-qualified", AQ_REFUSED_NOT_RUN_AS_QUALIFIED,
            "a NOT_RUN experiment passed to assert_all_qualified",
            not_run_as_qualified,
        ),
        _control(
            "expected-absent", AQ_REFUSED_EXPECTED_ABSENT,
            "a rejected witness with no expected exit status or code",
            expected_absent,
        ),
        _control(
            "witness-absent", AQ_REFUSED_WITNESS_ABSENT,
            "a declared witness that produced no observation",
            witness_absent,
        ),
        _control(
            "unstable", AQ_REFUSED_UNSTABLE,
            "a harness whose two runs over identical inputs disagree",
            unstable,
        ),
        _control(
            "canary-not-detected", AQ_REFUSED_CANARY_NOT_DETECTED,
            "a harness that also reports a refusal on the accepted input",
            canary_not_detected,
        ),
        _control(
            "defect-found", AQ_DEFECT_FOUND,
            "an instrument that accepts the input it should refuse",
            defect_found,
        ),
        _control(
            "positive-qualified", None,
            "a harness that refuses the rejected input and accepts the accepted one",
            qualified_stub,
        ),
    ]
    return {
        "controls": controls,
        "coversEveryCode": sorted(
            {control["code"] for control in controls if control["code"]}
        ) == sorted(REFUSALS),
    }


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


def experiments_document() -> dict:
    experiments = []
    for spec in EXPERIMENTS:
        experiments.append(
            {
                "id": spec.id,
                "title": spec.title,
                "instruments": list(spec.instruments),
                "instrumentSha256": _instrument_digests(spec),
                "hypothesis": spec.hypothesis,
                "expected": spec.expected,
                "witnesses": [
                    {
                        "case": case,
                        "kind": kind,
                        "expectation": expectation,
                    }
                    for case, kind, expectation in _declared_witnesses(spec)
                ],
                "canary": {
                    "accepted": spec.canary_accepted,
                    "detection": spec.canary_detection,
                    "rule": "the strict detector must report DEFECT on the accepted input "
                            "and QUALIFIED on the detection reference; the weak detector "
                            "(accept_any) must report QUALIFIED on the accepted input",
                },
                "notes": spec.notes,
            }
        )
    return {
        "schema": "openssl-rs/a22/experiments/1",
        "item": "A22",
        "baseCommit": _base_commit(),
        "baseCommitLong": BASE_COMMIT_LONG,
        "tool": {"path": TOOL_PATH, "sha256": sha256_file(Path(__file__))},
        "requiredExperiments": list(REQUIRED_EXPERIMENTS),
        "refusalCodes": {
            code: {"condition": entry["condition"], "prevents": entry["prevents"]}
            for code, entry in sorted(REFUSALS.items())
        },
        "canaryRule": "every experiment runs the same harness twice: once with the strict "
                      "detector, once with a deliberately weak detector that accepts any "
                      "observation. A harness that cannot report DEFECT on an input the "
                      "instrument accepted is not measuring anything.",
        "experiments": experiments,
    }


def _declared_witnesses(spec: ExperimentSpec) -> list[tuple[str, str, dict]]:
    """The witness designs, without running the harness.

    The designs live in the harness functions; this table mirrors them so the
    design document can be emitted without executing an instrument. A test
    refuses a design document whose witness set differs from the live
    observations' case set.
    """
    table = {
        "E1": [
            ("conflicting-verdicts", "rejected", _expectation([6], "mixed-verdicts")),
            ("secure-with-nonzero-status", "rejected",
             _expectation([6], "secure-verdict-with-tool-status-1")),
            ("verdict-with-trailing-text", "rejected",
             _expectation([3], "verdict-trailing-text")),
            ("secure-accepted", "accepted", _expectation([0], None)),
        ],
        "E2": [
            ("zero-verdict-lines", "rejected", _expectation([3], "no-output")),
            ("two-secure-lines", "rejected", _expectation([6], "duplicate-secure")),
            ("verdict-trailing-whitespace", "rejected",
             _expectation([3], "verdict-trailing-text")),
            ("secure-accepted", "accepted", _expectation([0], None)),
        ],
        "E3": [
            ("zero-size-symbol", "rejected", _expectation([1], "reason=zero-size")),
            ("malformed-length-prefix", "rejected", _expectation([1], "reason=missing")),
            ("malformed-symbol-table-entry", "rejected",
             _expectation([1], "reason=missing")),
            ("target-absent", "rejected", _expectation([1], "reason=missing")),
            ("disassembly-shorter-than-extent", "rejected",
             _expectation([1], "disassembly-truncated")),
            ("good-symbol-accepted", "accepted", _expectation([0], None)),
        ],
        "E4": [
            ("under-sampled-one-batch", "rejected",
             _expectation([1], "PR_EARLY_STOP_WITHOUT_LEAK")),
            ("below-per-batch", "rejected", _expectation([1], "PR_TOTAL_NOT_MULTIPLE")),
            ("positive-control-ttest-failed", "rejected",
             _expectation([1], "PR_POSITIVE_CONTROL_DID_NOT_FIRE")),
            ("recorded-receipt-accepted", "accepted", _expectation([0], None)),
        ],
        "E5": [
            ("empty-log", "rejected", _expectation([3], "CT_SUMMARY_EMPTY_LOG")),
            ("unrelated-log-only", "rejected",
             _expectation([4], "CT_SUMMARY_UNRELATED_LOG")),
            ("candidate-identity-mismatch", "rejected",
             _expectation([1], "CTGRIND_BINARY_IDENTITY_MISMATCH")),
            ("log-with-a-finding", "accepted", _expectation([0], None)),
            ("missing-identity-detection-reference", "detection",
             _expectation([1], "CTGRIND_WITHOUT_HARNESS_IDENTITY_TAINT")),
        ],
        "E6": [
            ("native-population-mismatch", "rejected",
             _expectation([1], "SARIF_REFUSED_POPULATION_MISMATCH")),
            ("emission-result-count-mismatch", "rejected",
             _expectation([1], "SARIF_REFUSED_POPULATION_MISMATCH")),
            ("live-record-accepted", "accepted", _expectation([0], None)),
            ("live-emission-accepted", "accepted", _expectation([0], None)),
        ],
        "E7": [
            ("duplicate-key-instrument", "rejected",
             _expectation([1], "IQ_JSON_DUPLICATE_KEY")),
            ("bom-instrument", "rejected", _expectation([1], "IQ_REGISTRY_UNREADABLE")),
            ("trailing-data-instrument", "rejected",
             _expectation([1], "IQ_REGISTRY_UNREADABLE")),
            ("duplicate-key-policy", "rejected", _expectation([1], "PE_JSON_REFUSED")),
            ("bom-policy", "rejected", _expectation([1], "PE_JSON_REFUSED")),
            ("trailing-data-policy", "rejected", _expectation([1], "PE_JSON_REFUSED")),
            ("duplicate-key-etp-t1-seed", "rejected",
             _expectation([1], "PH_REFUSED_DUPLICATE_KEY")),
            ("duplicate-key-freshness", "rejected",
             _expectation([1], "PH_REFUSED_DUPLICATE_KEY")),
            ("well-formed-instrument", "accepted", _expectation([0], None)),
            ("well-formed-policy", "accepted", _expectation([0], None)),
        ],
        "E8": [
            ("default-allow", "rejected", _expectation([1], "PE_REFUSED_DEFAULT_ALLOW")),
            ("policy-with-a-score", "rejected", _expectation([1], "PE_REFUSED_SCORE")),
            ("pass-over-a-missing-member", "rejected",
             _expectation([1], "OM_REFUSED_PASS_WITH_MISSING")),
            ("signed-bytes-mutated", "rejected",
             _expectation([1], "OM_REFUSED_RECONCILIATION_MUTATED")),
            ("clean-reconciliation-accepted", "accepted", _expectation([0], None)),
            ("live-policy-accepted", "accepted", _expectation([1], None)),
        ],
    }
    return table[spec.id]


def results_document(results: list[ExperimentResult], *, runs: int) -> dict:
    return {
        "schema": "openssl-rs/a22/results/1",
        "item": "A22",
        "baseCommit": _base_commit(),
        "baseCommitLong": BASE_COMMIT_LONG,
        "detail": "measured",
        "runs": runs,
        "tool": {"path": TOOL_PATH, "sha256": sha256_file(Path(__file__))},
        "canaryRule": "strict detector on the accepted input must be DEFECT, the weak "
                      "detector on the same input must be QUALIFIED, and the strict "
                      "detector on the detection reference must be QUALIFIED",
        "summary": summary(results),
        "experiments": [result.to_dict() for result in results],
    }


def controls_document(controls: dict, results: list[ExperimentResult]) -> dict:
    return {
        "schema": "openssl-rs/a22/controls/1",
        "item": "A22",
        "detail": "control-only",
        "baseCommit": _base_commit(),
        "baseCommitLong": BASE_COMMIT_LONG,
        "tool": {"path": TOOL_PATH, "sha256": sha256_file(Path(__file__))},
        "controls": controls["controls"],
        "coversEveryCode": controls["coversEveryCode"],
        "canary": [
            {
                "experiment": result.spec.id,
                **(result.canary.to_dict() if result.canary else {"detected": False}),
            }
            for result in results
        ],
        "allCanariesDetected": all(
            result.canary is not None and result.canary.detected for result in results
        ),
    }


def _base_commit() -> str:
    return BASE_COMMIT


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_run(results: list[ExperimentResult]) -> int:
    for result in results:
        canary = result.canary.detected if result.canary else False
        print(
            f"aq: {result.spec.id} {result.verdict} refused={result.refused}/{result.rejected} "
            f"canary={'detected' if canary else 'NOT-DETECTED'} codes="
            f"{','.join(result.codes) if result.codes else 'NONE'} -- {result.reason}"
        )
    totals = summary(results)
    print(
        f"aq: experiments={totals['experiments']} qualified={totals['qualified']} "
        f"defect={totals['defect']} partial={totals['partial']} notRun={totals['notRun']} "
        f"allQualified={str(totals['allQualified']).lower()} "
        f"codes={','.join(totals['codes']) if totals['codes'] else 'NONE'}"
    )
    return EXIT_OK if totals["allQualified"] else EXIT_REFUSED


def _print_canary(results: list[ExperimentResult]) -> int:
    detected = 0
    for result in results:
        canary = result.canary
        if canary is None:
            print(f"aq: canary {result.spec.id} NOT-DETECTED (no canary)")
            continue
        if canary.detected:
            detected += 1
        failed = [probe["probe"] for probe in canary.probes if not probe["ok"]]
        print(
            f"aq: canary {result.spec.id} "
            f"{'detected' if canary.detected else 'NOT-DETECTED'} "
            f"accepted={canary.accepted_case} detection={canary.detection_case}"
            + (f" failed={','.join(failed)}" if failed else "")
        )
    print(f"aq: canary experiments={len(results)} detected={detected}")
    return EXIT_OK if detected == len(results) else EXIT_REFUSED


def _explain(identifier: str) -> int:
    chosen = [spec for spec in EXPERIMENTS if spec.id == identifier]
    if not chosen:
        raise Refusal(AQ_REFUSED_EXPERIMENT_ABSENT, f"no experiment {identifier!r}")
    spec = chosen[0]
    print(f"experiment: id={spec.id} title={spec.title}")
    print(f"  instruments: {', '.join(spec.instruments)}")
    for relative in spec.instruments:
        path = REPO_ROOT / relative
        digest = sha256_file(path) if path.is_file() else "ABSENT"
        print(f"    {relative} sha256={digest}")
    print(f"  hypothesis: {spec.hypothesis}")
    print(f"  expected: {spec.expected}")
    print(f"  canary: accepted={spec.canary_accepted} detection={spec.canary_detection}")
    for case, kind, expectation in _declared_witnesses(spec):
        print(f"  witness: case={case} kind={kind} expected={json.dumps(expectation, sort_keys=True)}")
    print(f"  notes: {spec.notes}")
    recorded = REPO_ROOT / "evidence/a22/RESULTS.json"
    if recorded.is_file():
        document = json.loads(recorded.read_text(encoding="utf-8"))
        entry = next(
            (item for item in document.get("experiments", []) if item.get("id") == spec.id),
            None,
        )
        if entry is None:
            print("  recorded: absent from evidence/a22/RESULTS.json")
        else:
            print(
                f"  recorded: verdict={entry.get('verdict')} "
                f"refused={entry.get('refusedWitnesses')}/{entry.get('rejectedWitnesses')} "
                f"canary={'detected' if (entry.get('canary') or {}).get('detected') else 'NOT-DETECTED'}"
            )
            print(f"  recorded-reason: {entry.get('reason')}")
    else:
        print("  recorded: no evidence/a22/RESULTS.json in the tree")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="adversarial_qualification.py",
        description="A22: eight adversarial qualification experiments.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run the eight experiments")
    run_parser.add_argument("--json", action="store_true")
    run_parser.add_argument("--runs", type=int, default=2)
    run_parser.add_argument("--only", default=None)

    canary_parser = sub.add_parser("canary", help="run the canary (negative control)")
    canary_parser.add_argument("--json", action="store_true")
    canary_parser.add_argument("--only", default=None)

    explain_parser = sub.add_parser("explain", help="explain one experiment")
    explain_parser.add_argument("experiment")

    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if arguments.command == "explain":
            return _explain(arguments.experiment)
        if arguments.command == "canary":
            results = run_all(runs=1, only=arguments.only)
            if arguments.json:
                print(json.dumps(controls_document(build_controls(), results)["canary"],
                                 indent=2, sort_keys=True))
            return _print_canary(results)
        if arguments.runs < 1:
            raise Refusal(CODE_USAGE, "--runs must be at least 1")
        results = run_all(runs=arguments.runs, only=arguments.only)
        if arguments.json:
            print(json.dumps(results_document(results, runs=arguments.runs), indent=2, sort_keys=True))
            return EXIT_OK if summary(results)["allQualified"] else EXIT_REFUSED
        return _print_run(results)
    except Refusal as refusal:
        print(f"{refusal.code}: {refusal.message}", file=sys.stderr)
        return EXIT_REFUSED if refusal.code != CODE_USAGE else EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
