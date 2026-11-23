#!/usr/bin/env python3
"""verify.py -- one public verification interface for this repository (ETP-T12).

One entry point, runnable from a clean checkout with no private state, that
reports each verification step separately and fails closed.  It is a dispatcher:
every subcommand invokes a verification tool that already exists in this
repository.  Nothing here re-implements a check.

What the interface guarantees
-----------------------------
* A step that could not run is ``NOT_RUN`` with the missing prerequisite named.
  It is never reported as a pass and never silently omitted.
* A step whose tool exited non-zero is ``FAIL``.  A step that hit a resource
  bound, including a timeout, is ``BLOCKED``.
* A step whose tool read a private path (``court/``, ``target/``, a gitignored
  download or prefix) declares that path; the interface reports whether it is
  present in this checkout and never treats its presence as the step's evidence.
  Identity digests are computed over Git-tracked files only.
* ``verify all`` exits non-zero when any required step is not ``PASS`` and the
  output names every non-passing step.
* ``--json`` emits one document, sorted and timestamp-free, so two runs over the
  same checkout produce byte-identical output.  Each step carries the evidence
  identity it read and the digest of the tool that produced the verdict.
* A step that needs the network is refused unless the run declares ``--network``.
  ``--network`` is a declaration, not a probe; a wrong declaration surfaces as
  that step's own failure.

Exit contract
-------------
    0  every selected required step is PASS
    1  at least one selected step is not PASS (for a single step: it is not PASS)
    2  the invocation was refused before any step ran: unknown subcommand, a
       checkout that cannot be read, or a malformed selection

What this interface does not establish
--------------------------------------
It does not decide that any claim is true.  It reports what the delegated tools
observed at this candidate and binds each verdict to the tool and evidence
digests it used.  It does not sandbox those tools: an undeclared read of private
state would be a defect in a step's own tool, and the declarations below are the
claim that a reviewer audits.  ``docs/PUBLIC-VERIFICATION.md`` states, per
subcommand, what it needs, what it establishes and what it does not.

Python 3.11 standard library only.

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
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "openssl-rs/verify/1"
INTERFACE = "ETP-T12"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

STATUS_ORDER = {"PASS": 0, "NOT_RUN": 1, "BLOCKED": 2, "FAIL": 3}

# Private roots this interface knows about.  A step names the ones its own tool
# may read; the interface reports which of them exist.  Existence is probed with
# stat(); this file reads no gitignored content itself.
PRIVATE_ROOTS = (
    "court",
    "target",
    "forensics/authorities/downloads",
    "forensics/authorities/prefix",
    "artifacts/phase2/shell",
)

MEMORY_FLOOR_BYTES = 24 * 1024 ** 3  # AGENTS.md section 6.1

AUTHORITY_DSO = ("forensics/authorities/prefix/openssl-3.6.4-production/"
                 "lib/libcrypto.so.3")

T10_RECORD = "evidence/etp-t10/EXCLUSIONS.json"

# The family-to-receipt map is the one evidence/etp-t10/EXCLUSIONS.json records.
# It is repeated here only so that the step names exist when that record is
# absent; the guard then reports the absence as a FAIL rather than guessing.
CONSUMER_FAMILIES = {
    "curl": "evidence/closure-curl-049.json",
    "ssh": "evidence/closure-ssh-b85c.json",
    "sshd": "evidence/closure-sshd-b85c.json",
}


# ---------------------------------------------------------------------------
# declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    cwd: str = ""
    timeout: int = 900
    # exit codes the delegate documents as "could not run", with the reason
    not_run_codes: tuple[tuple[int, str], ...] = ()
    # exit codes the delegate documents as a resource bound
    blocked_codes: tuple[int, ...] = ()


@dataclass(frozen=True)
class Step:
    name: str
    title: str
    required: bool
    needs: tuple[str, ...]
    tools: tuple[str, ...]
    identity: tuple[str, ...]
    reads_gitignored: tuple[str, ...]
    commands: tuple[Command, ...]
    pass_reason: str
    establishes: str
    does_not: str
    parser: str = "generic"
    guard: str = ""
    required_for_all: bool = True


def _add(step: Step) -> None:
    STEPS[step.name] = step


STEPS: dict[str, Step] = {}

_add(Step(
    name="manifest",
    title="the frozen package manifest describes this commit",
    required=True,
    needs=("git",),
    tools=("forensics/tools/etp6_package.py",),
    identity=("evidence/etp6/MANIFEST.json",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/etp6_package.py",
                            "--commit", "HEAD", "--out", "{tmp}/etp6-package")),),
    pass_reason="the staged selection matches the frozen package manifest",
    establishes="every input the tracked ETP-6 package manifest names is present at "
                "this commit with the recorded SHA-256",
    does_not="does not establish that a package was ever built, archived or "
             "published, nor any property of its contents",
    parser="manifest",
))

_add(Step(
    name="rebuild",
    title="two independent release builds agree byte-for-byte",
    required=True,
    needs=("bash", "rustc", "cargo", "court", "memory:24"),
    tools=("forensics/tools/build_reproducibility.sh",),
    identity=("Cargo.lock", "rust-toolchain.toml"),
    reads_gitignored=(),
    commands=(Command(argv=("bash", "forensics/tools/build_reproducibility.sh",
                            "--out", "{tmp}/repro", "--clean")),),
    pass_reason="the static archive and the linked DSO are byte-identical across two "
                "independently produced builds",
    establishes="that the release library is a function of its inputs in this venue",
    does_not="does not establish that the build is correct, nor that another host or "
             "toolchain reproduces it; the authority differential is a separate step",
    parser="rebuild",
))

_add(Step(
    name="proofs",
    title="the independent reference reproduces its published populations",
    required=True,
    needs=("python",),
    tools=("forensics/etp5_crypto/make_vectors.py",
           "forensics/etp5_crypto/driver.py"),
    identity=("forensics/etp5_crypto/vectors", "evidence/etp-t5/RESULTS.json"),
    reads_gitignored=(),
    commands=(
        Command(argv=("{python}", "make_vectors.py", "--check"),
                cwd="forensics/etp5_crypto"),
        Command(argv=("{python}", "driver.py", "--self-test"),
                cwd="forensics/etp5_crypto"),
    ),
    pass_reason="the reference regenerates every tracked vector byte-for-byte and the "
                "difference classifier passes its own controls",
    establishes="that the independent reference and its classifier are intact and "
                "reproducible from the tracked vectors",
    does_not="does not run the reference against the candidate or the authority; that "
             "campaign is the differential step and needs a built candidate and the "
             "authority prefix",
    parser="proofs",
))

_add(Step(
    name="differential",
    title="candidate and pinned authority agree with the independent reference",
    required=True,
    needs=("bash", "rustc", "cargo", "court", "memory:24", "authority-prefix"),
    tools=("forensics/etp5_crypto/run_etp5.sh",),
    identity=("forensics/etp5_crypto/vectors", "forensics/authorities/AUTHORITIES.json"),
    reads_gitignored=("forensics/authorities/prefix", "court"),
    commands=(Command(argv=("bash", "forensics/etp5_crypto/run_etp5.sh")),),
    pass_reason="every sampled case agrees across the reference, the candidate and the "
                "pinned authority, and every difference is classified",
    establishes="bounded differential agreement on the sampled populations",
    does_not="does not establish algorithm correctness universally, constant-time "
             "behaviour, memory safety or refinement",
    parser="differential",
))

_add(Step(
    name="instruments",
    title="every instrument is registered and its control fires",
    required=True,
    needs=("python",),
    tools=("forensics/tools/instrument_qualify.py",),
    identity=("evidence/etp3/instruments.json",),
    reads_gitignored=("court",),
    commands=(Command(argv=("{python}", "forensics/tools/instrument_qualify.py",
                            "check")),),
    pass_reason="the register validates and every requested executable control passed in "
                "the venue that ran it",
    establishes="that each instrument's identity matches the register and that its "
                "control demonstrated sensitivity to the defect class it names",
    does_not="does not establish that an instrument is adequate for untested inputs; an "
             "absent external tool is NOT_RUN rather than a sensitivity result",
    parser="instruments",
))

_add(Step(
    name="controls",
    title="the verification tools' own controls fire",
    required=True,
    needs=("python",),
    tools=("forensics/tools/tests",),
    identity=("forensics/tools/tests",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "-m", "unittest", "discover", "-s", "tests",
                            "-p", "test_*.py"), cwd="forensics/tools"),),
    pass_reason="every tool control suite passed",
    establishes="that the verification tools' negative controls, determinism checks and "
                "refusal paths pass at this candidate",
    does_not="does not establish that a control is complete for its defect class, and "
             "does not run the court-level instrument controls",
    parser="controls",
))

_add(Step(
    name="receipts",
    title="interop receipts and manifests are self-consistent",
    required=True,
    needs=("python",),
    tools=("courts/phase18/interop/check_receipts.py",),
    identity=("courts/phase18/interop",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "courts/phase18/interop/check_receipts.py",
                            "--summary")),),
    pass_reason="every receipt parses, every withdrawal names its successor, and every "
                "manifest log exists with the recorded digest",
    establishes="the evidence-integrity rules R1-R5 over the committed interop receipts",
    does_not="does not establish that a receipt's measurements are true; a manifest that "
             "points into court/ fails the log rule in a clean checkout by design",
    parser="receipts",
))

_add(Step(
    name="claims",
    title="the claim set validates under the claim algebra",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/etp_claims.py",),
    identity=("evidence/etp/claims.json", "evidence/etp/claim.schema.json"),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/etp_claims.py", "validate")),),
    pass_reason="the committed claim set passes the schema, the cross-field laws and the "
                "Git-bound digest re-derivation",
    establishes="that no claim cites evidence that cannot be re-derived at the identity "
                "it names",
    does_not="does not establish that any claim is true; a valid claim set may contain "
             "CONTRADICTED or NOT_ESTABLISHED members",
    parser="claims",
))

_add(Step(
    name="freshness",
    title="no current evidence carries forward across a changed dependency",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/freshness.py",),
    identity=("evidence/etp-t9/DEPENDENCIES.json",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/freshness.py", "check")),),
    pass_reason="every artefact is unaffected, history, invalidated or explicitly "
                "unresolved with a named reason, and no undeclared carry-forward remains",
    establishes="the per-artefact verdicts and the refusal rules over them",
    does_not="does not establish that an UNAFFECTED verdict is a fresh measurement; the "
             "identity triage bounds what the verdict can mean",
    parser="freshness",
))

_add(Step(
    name="independence",
    title="the recorded role assignments satisfy the independence classes",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/independence.py",),
    identity=("evidence/etp-t8/ROLES.json", "evidence/etp-t8/ASSIGNMENTS.json"),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/independence.py",
                            "check")),),
    pass_reason="every assignment satisfies the class it claims, with recorded dissent",
    establishes="that assignments claiming independence do not share a party where the "
                "class forbids it",
    does_not="does not create an external party; an unknown distinctness is reported, "
             "never assumed",
    parser="independence",
))

_add(Step(
    name="closure",
    title="the closure-discipline evidence holds",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/closure_discipline.py",),
    identity=("evidence/etp-t10/EXCLUSIONS.json",
              "evidence/etp-t10/OPAQUE-OPERATIONS.json",
              "evidence/etp-t10/AGGREGATES.json"),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/closure_discipline.py",
                            "check")),),
    pass_reason="no exclusion row fails its bar, every opaque operation is scoped and no "
                "aggregate hides a blocked row",
    establishes="the five-requirement bar over the recorded exclusion rows and the "
                "aggregate refusal rule",
    does_not="does not establish that an admitted exclusion is sound, only that its "
             "argument is recorded and checkable",
    parser="closure",
))

_add(Step(
    name="scheduling",
    title="each recorded change set carries the evidence its tier requires",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/scheduling.py",),
    identity=("evidence/etp-t11/CHANGE-SETS.json",
              "evidence/etp-t11/RUNS.json",
              "evidence/etp-t11/CACHE.json"),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/scheduling.py", "report",
                            "--change-sets", "evidence/etp-t11/CHANGE-SETS.json",
                            "--runs", "evidence/etp-t11/RUNS.json",
                            "--store", "evidence/etp-t11/CACHE.json")),),
    pass_reason="every requirement of every change set's tier is SATISFIED",
    establishes="the minimum tier each recorded change set needs and which required "
                "evidence is satisfied, NOT_RUN, FAILED, REFUSED or BLOCKED",
    does_not="does not run the required checks; a cache hit is evidence bound to its "
             "identity, not a fresh measurement",
    parser="scheduling",
))

_add(Step(
    name="traceability",
    title="the requirements graph has no undeclared orphan",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/traceability.py",),
    identity=("evidence/etp-t1/TRACEABILITY.json",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/traceability.py",
                            "validate")),),
    pass_reason="the graph validates and every declared orphan is reproduced",
    establishes="the typed traceability graph and its declared-orphan register at the "
                "identity the nodes name",
    does_not="does not establish population completeness; the orphan reasons are "
             "arguments, not proofs",
    parser="traceability",
))

_add(Step(
    name="hazards",
    title="the hazard register agrees with the traceability graph",
    required=True,
    needs=("python", "git"),
    tools=("forensics/tools/hazard_register.py",),
    identity=("evidence/etp-t2/HAZARDS.json",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/hazard_register.py",
                            "validate")),),
    pass_reason="the register validates and every projected field and edge matches the "
                "graph",
    establishes="that the register and the graph describe the same hazards, barriers and "
                "release claims",
    does_not="does not establish that a barrier works; barriers are classified by the "
             "evidence recorded for them",
    parser="hazards",
))

_add(Step(
    name="binary",
    title="the recorded TCB and per-target claim matrix are bound",
    required=True,
    needs=("python",),
    tools=("forensics/tools/binary_assurance.py",),
    identity=("evidence/etp-t6/TCB.json", "evidence/etp-t6/CLAIM-MATRIX.json"),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/binary_assurance.py",
                            "check")),),
    pass_reason="the TCB validates and no claim crosses a target, profile or TCB "
                "boundary",
    establishes="that every asserted binary claim names an artefact at its own target, "
                "profile and TCB",
    does_not="does not establish source-to-binary correspondence, and an unbound claim "
             "is recorded rather than promoted",
    parser="binary",
))

_add(Step(
    name="docs",
    title="hand-written claims agree with their generated sources",
    required=True,
    needs=("python",),
    tools=("forensics/tools/docs_consistency.py",),
    identity=("docs",),
    reads_gitignored=(),
    commands=(Command(argv=("{python}", "forensics/tools/docs_consistency.py")),),
    pass_reason="every checked quantity in the documents agrees with its generated source",
    establishes="that the documentation's derived figures match the artefacts they cite",
    does_not="does not establish that prose is complete or that an exempt figure is "
             "correct",
    parser="docs",
))

_add(Step(
    name="authority",
    title="the pinned authorities verify against their published digests",
    required=False,
    needs=("python", "network"),
    tools=("forensics/tools/authority_acquire.py",),
    identity=("forensics/authorities/AUTHORITIES.json",),
    reads_gitignored=("forensics/authorities/downloads", "forensics/authorities/prefix"),
    commands=(Command(argv=("{python}", "forensics/tools/authority_acquire.py",
                            "--all", "--verify-only")),),
    pass_reason="every admitted authority archive matches its published digest",
    establishes="that the local authority archives are the ones the registry admits",
    does_not="does not establish that an upstream release is trustworthy; this step is "
             "not part of `all` because it needs the network",
    parser="authority",
    required_for_all=False,
))


def consumer_step(family: str, receipt: str) -> Step:
    return Step(
        name=f"consumer-{family}",
        title=f"the {family} closure exclusions pass the ETP-T10 bar",
        required=True,
        needs=("python", "git"),
        tools=("forensics/tools/closure_discipline.py",),
        identity=(receipt, T10_RECORD),
        reads_gitignored=("court", "artifacts/phase2/install"),
        commands=(Command(argv=("{python}", "forensics/tools/closure_discipline.py",
                                "audit", "--receipt", receipt)),),
        pass_reason="every exclusion row in the recorded closure receipt passes the "
                    "five-requirement bar",
        establishes="the exclusion bar and opaque-operation scope over the recorded "
                    "closure receipt for one consumer family",
        does_not="does not establish that an admitted exclusion is sound; an absent "
                 "private inventory makes every dependent row fail",
        parser="consumer",
        guard="consumer",
    )


ALL_ORDER = (
    "manifest", "rebuild", "proofs", "differential", "instruments", "controls",
    "receipts", "claims", "freshness", "independence", "closure", "scheduling",
    "traceability", "hazards", "binary", "docs",
)

QUEUE_STEPS = (
    "manifest", "rebuild", "proofs", "instruments", "controls", "receipts",
    "claims", "freshness", "independence", "closure", "scheduling",
)


# ---------------------------------------------------------------------------
# context, execution
# ---------------------------------------------------------------------------


@dataclass
class Context:
    root: Path
    network: bool
    tmpdir: str
    env: dict[str, str]
    candidate: dict
    private_state: dict[str, dict]
    warnings: tuple[str, ...] = ()

    @property
    def private_present(self) -> tuple[str, ...]:
        return tuple(sorted(path for path, entry in self.private_state.items()
                            if entry.get("private_entries", 0) > 0))


@dataclass(frozen=True)
class ExecRequest:
    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str]
    timeout: int


@dataclass
class ExecResult:
    exit: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


def subprocess_execute(request: ExecRequest) -> ExecResult:
    try:
        proc = subprocess.run(
            list(request.argv), cwd=str(request.cwd), env=request.env,
            capture_output=True, text=True, timeout=request.timeout,
        )
        return ExecResult(exit=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return ExecResult(exit=None, stdout=out, stderr=err, timed_out=True)
    except OSError as exc:
        return ExecResult(exit=None, stderr=f"{type(exc).__name__}: {exc}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str | None:
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        proc = subprocess.run(["git", "-C", str(root)] + list(args),
                              capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _git_bytes(root: Path, *args: str) -> bytes | None:
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        proc = subprocess.run(["git", "-C", str(root)] + list(args),
                              capture_output=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _tracked_files(root: Path, relative: str) -> list[str] | None:
    """The Git-tracked files under ``relative``, or None when git cannot say."""
    raw = _git_bytes(root, "ls-files", "-z", "--", relative)
    if raw is None:
        return None
    names = [item for item in raw.decode("utf-8", "replace").split("\0") if item]
    return names


def _walk_files(path: Path) -> list[Path]:
    files = []
    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue
        if "__pycache__" in item.parts or item.suffix == ".pyc":
            continue
        files.append(item)
    return files


def digest_path(root: Path, relative: str) -> dict:
    path = root / relative
    if not path.exists():
        return {"path": relative, "state": "absent"}
    if path.is_file():
        return {"path": relative, "state": "present", "kind": "file",
                "sha256": _sha256_file(path)}
    tracked = _tracked_files(root, relative)
    if tracked is None:
        digest = hashlib.sha256()
        for item in _walk_files(path):
            digest.update(str(item.relative_to(path)).encode("utf-8") + b"\0")
            digest.update(_sha256_file(item).encode("ascii") + b"\n")
        return {"path": relative, "state": "present", "kind": "directory",
                "population": "filesystem (git unavailable)", "sha256": digest.hexdigest()}
    digest = hashlib.sha256()
    for name in tracked:
        item = root / name
        if not item.is_file():
            continue
        digest.update(str(Path(name).relative_to(relative)).encode("utf-8") + b"\0")
        digest.update(_sha256_file(item).encode("ascii") + b"\n")
    return {"path": relative, "state": "present", "kind": "directory",
            "population": "git-tracked", "sha256": digest.hexdigest()}


def candidate_identity(root: Path) -> dict:
    commit = _git(root, "rev-parse", "HEAD")
    if commit is None:
        return {"commit": "UNKNOWN", "branch": "UNKNOWN", "tree": "UNKNOWN",
                "tracked_changes": "UNKNOWN", "untracked_changes": "UNKNOWN",
                "clean": "UNKNOWN",
                "note": "not a readable Git checkout; steps needing git are NOT_RUN"}
    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD") or "UNKNOWN"
    tree = _git(root, "rev-parse", "HEAD^{tree}") or "UNKNOWN"
    tracked = _git(root, "status", "--porcelain", "--untracked-files=no") or ""
    everything = _git(root, "status", "--porcelain") or ""
    tracked_changes = len([line for line in tracked.splitlines() if line.strip()])
    untracked_changes = len([line for line in everything.splitlines() if line.strip()]) \
        - tracked_changes
    return {"commit": commit, "branch": branch, "tree": tree,
            "tracked_changes": tracked_changes,
            "untracked_changes": untracked_changes,
            "clean": tracked_changes == 0}


def private_state_report(root: Path,
                         declared: tuple[str, ...] = PRIVATE_ROOTS) -> dict[str, dict]:
    """Describe each declared root without reading its content.

    ``tracked_files`` counts the files Git tracks under the path; they are part
    of the checkout.  ``private_entries`` counts the untracked or ignored
    entries Git reports there, which is what the declaration is about.  A root
    that exists with tracked files and no private entries is a tracked directory,
    not private state.
    """
    report: dict[str, dict] = {}
    for relative in declared:
        path = root / relative
        entry: dict = {"exists": path.exists()}
        if entry["exists"]:
            tracked = _tracked_files(root, relative)
            entry["tracked_files"] = "UNKNOWN" if tracked is None else len(tracked)
            status = _git(root, "status", "--porcelain", "--ignored=matching",
                          "--", relative)
            if status is None:
                entry["private_entries"] = sum(1 for _ in path.rglob("*"))
            else:
                entry["private_entries"] = len([line for line in status.splitlines()
                                                if line.strip()])
        else:
            entry["tracked_files"] = 0
            entry["private_entries"] = 0
        report[relative] = entry
    return report


def _mem_available_bytes() -> int | None:
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", text, re.MULTILINE)
    return int(match.group(1)) * 1024 if match else None


def _resolved_env(network: bool, tmpdir: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TMPDIR"] = tmpdir
    env["GIT_OPTIONAL_LOCKS"] = "0"
    if not network:
        # Defence in depth against an accidental network attempt, not a sandbox.
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                     "ALL_PROXY", "all_proxy"):
            env.pop(name, None)
        env["NO_PROXY"] = "*"
        env["no_proxy"] = "*"
    return env


def build_context(root: Path, network: bool, tmpdir: str) -> Context:
    warnings = []
    record = _load_json(root / T10_RECORD)
    recorded = (record or {}).get("consumers") or {}
    for family, receipt in CONSUMER_FAMILIES.items():
        if not (root / receipt).is_file():
            warnings.append(f"consumer-{family}: the recorded receipt {receipt} is absent")
        elif family not in recorded:
            warnings.append(f"consumer-{family}: {T10_RECORD} records no such family")
    return Context(
        root=root,
        network=network,
        tmpdir=tmpdir,
        env=_resolved_env(network, tmpdir),
        candidate=candidate_identity(root),
        private_state=private_state_report(root),
        warnings=tuple(sorted(warnings)),
    )


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# prerequisites
# ---------------------------------------------------------------------------


def check_need(need: str, ctx: Context) -> tuple[bool, str]:
    if need == "python":
        ok = bool(sys.executable) and Path(sys.executable).exists()
        return ok, (f"python3 at {sys.executable}" if ok else "python3 is not available")
    if need == "network":
        return ctx.network, ("the network was declared with --network" if ctx.network else
                             "this step needs the network; the run declares none "
                             "(pass --network only when it is actually available)")
    if need in ("git", "bash", "rustc", "cargo", "cc", "valgrind", "perf"):
        found = shutil.which(need)
        return (True, found) if found else (False, f"{need} is not installed")
    if need == "court":
        ok = Path("/.dockerenv").exists()
        return ok, ("running inside a container" if ok else
                    "this step must run inside docker/openssl-rs-court.sh")
    if need == "memory:24":
        observed = _mem_available_bytes()
        if observed is None:
            return False, "MemAvailable could not be read, so no build is started"
        if observed < MEMORY_FLOOR_BYTES:
            return False, (f"MemAvailable {observed / 1024 ** 3:.0f} GiB is below the "
                           f"24 GiB floor AGENTS.md section 6.1 requires before a build")
        return True, f"MemAvailable {observed / 1024 ** 3:.0f} GiB"
    if need == "authority-prefix":
        ok = (ctx.root / AUTHORITY_DSO).is_file()
        return ok, (AUTHORITY_DSO if ok else
                    f"{AUTHORITY_DSO} is absent (the authority prefix is gitignored and "
                    "must be acquired inside the court)")
    return False, f"unknown prerequisite {need!r}"


def prerequisites(step: Step, ctx: Context) -> tuple[bool, str, list[dict]]:
    records: list[dict] = []
    for need in step.needs:
        ok, detail = check_need(need, ctx)
        records.append({"requirement": need, "available": ok, "detail": detail})
        if not ok:
            return False, f"requires {need}: {detail}", records
    for tool in step.tools:
        if not (ctx.root / tool).exists():
            records.append({"requirement": f"tool:{tool}", "available": False,
                            "detail": "the tool this step delegates to is absent"})
            return False, f"the tool {tool} is absent from this checkout", records
        records.append({"requirement": f"tool:{tool}", "available": True,
                        "detail": "present"})
    return True, "", records


def _consumer_guard(step: Step, ctx: Context) -> str | None:
    family = step.name[len("consumer-"):]
    record = _load_json(ctx.root / T10_RECORD)
    if not isinstance(record, dict):
        return f"the record that names this receipt, {T10_RECORD}, is absent or unreadable"
    consumers = record.get("consumers") or {}
    entry = consumers.get(family)
    if not isinstance(entry, dict):
        return f"{T10_RECORD} records no consumer family {family!r}"
    receipt = entry.get("receipt")
    declared = dict(zip(("receipt",), step.identity))
    if receipt != declared["receipt"]:
        return (f"{T10_RECORD} names {receipt!r} for family {family!r}, "
                f"not {declared['receipt']!r}")
    path = ctx.root / receipt
    if not path.is_file():
        return f"the recorded closure receipt {receipt} is absent"
    current = _sha256_file(path)
    recorded = entry.get("receipt_sha256")
    if recorded != current:
        return (f"the closure receipt {receipt} has digest {current}, but the identity "
                f"ETP-T10 audited is {recorded}")
    return None


GUARDS = {"consumer": _consumer_guard}


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------


def _tail_lines(text: str, limit: int = 8) -> list[str]:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def _json_output(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    decoder = json.JSONDecoder()
    for start in range(len(text)):
        if text[start] != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            continue
        return value
    return None


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def normalise(text: str, ctx: Context) -> str:
    text = str(text).replace(str(ctx.root), "<repo>")
    text = text.replace(ctx.tmpdir, "<tmp>")
    text = re.sub(r"/tmp/[^\s\"']*", "<tmp>", text)
    text = re.sub(r"\b\d+\.\d+\s*s\b", "<elapsed>", text)
    return text


def _failing(results: list[dict]) -> dict | None:
    for record in results:
        if record["status"] != "PASS":
            return record
    return None


def summarise(results: list[dict], step: Step, ctx: Context) -> str:
    return PARSERS.get(step.parser, _reason_generic)(results, step, ctx)


def _reason_generic(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    if record["status"] == "BLOCKED":
        return record["detail"]
    text = (record["summary"][-1] if record["summary"] else "") or record["detail"]
    return f"{record['exit'] if record['exit'] is not None else 'no exit'}: {text}"


def _reason_manifest(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    stderr = record["raw_stderr"]
    hard = len(re.findall(r"^\s+HARD\s", stderr, re.MULTILINE))
    return (f"{_first_line(stderr)} ({hard} hard refusal(s) against "
            f"evidence/etp6/MANIFEST.json at this commit)")


def _reason_rebuild(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    if record["status"] == "BLOCKED":
        return record["detail"]
    return (f"build_reproducibility.sh exited {record['exit']}: "
            f"{record['summary'][-1] if record['summary'] else 'no output'}")


def _reason_proofs(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    text = record["summary"][-1] if record["summary"] else record["detail"]
    return f"{text} (check {record['index'] + 1}/{len(results)})"


def _reason_instruments(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    lines = [line for line in record["summary"] if line.startswith("REFUSED")]
    return lines[-1] if lines else (record["summary"][-1] if record["summary"]
                                   else record["detail"])


def _reason_controls(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    text = record["raw_stdout"] + record["raw_stderr"]
    ran = [line for line in text.splitlines() if line.startswith("Ran ")]
    verdict = [line for line in text.splitlines() if line.startswith(("FAILED", "OK"))]
    failures = [line for line in text.splitlines() if line.startswith("FAIL: ")
                or line.startswith("ERROR: ")]
    detail = "; ".join((ran[-1:] + verdict[-1:]) or [record["detail"]])
    if failures:
        detail += "; first: " + failures[0]
    return detail


def _reason_receipts(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    line = [line for line in record["summary"] if line.startswith("receipts=")]
    return line[-1] if line else (record["summary"][-1] if record["summary"]
                                 else record["detail"])


def _reason_claims(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        passed = [item for item in results if item["status"] == "PASS"]
        document = _json_output(passed[-1]["raw_stdout"]) if passed else None
        count = document.get("claims") if isinstance(document, dict) else None
        return f"{step.pass_reason} ({count} claims)" if count else step.pass_reason
    document = _json_output(record["raw_stdout"])
    if isinstance(document, dict):
        refusals = document.get("refusals") or []
        first = refusals[0] if refusals else {}
        return (f"{document.get('refusal_count', len(refusals))} refusal(s); "
                f"first: {first.get('rule', '?')} at {first.get('path', '?')}: "
                f"{first.get('detail', '?')}")
    return _reason_generic(results, step, ctx)


def _reason_freshness(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    document = _json_output(record["raw_stdout"])
    if isinstance(document, dict):
        artefacts = document.get("artefacts") or {}
        verdicts = artefacts.get("by_verdict") or {}
        refusals = document.get("refusals") or []
        first = refusals[0] if refusals else {}
        verdict_text = ", ".join(f"{key}={value}" for key, value in sorted(verdicts.items()))
        reason = (f"status {document.get('status', '?')}; {artefacts.get('total', '?')} "
                  f"artefact(s) ({verdict_text}); {len(refusals)} refusal(s)")
        if first:
            reason += f"; first: {first.get('rule', '?')} at {first.get('where', '?')}"
        return reason
    return _reason_generic(results, step, ctx)


def _reason_independence(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    text = record["raw_stdout"] + record["raw_stderr"]
    refusals = [line.strip() for line in text.splitlines()
                if line.startswith("REFUSED ")]
    if refusals:
        return f"{len(refusals)} refusal(s); first: {refusals[0]}"
    return _first_line(text) or _reason_generic(results, step, ctx)


def _reason_closure(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    document = _json_output(record["raw_stdout"])
    if isinstance(document, dict):
        refusals = document.get("aggregate_refusals") or []
        names = ", ".join(item.get("aggregate", "?") for item in refusals) or "none"
        return (f"{len(refusals)} aggregate refusal(s) ({names}); "
                f"{document.get('opaque_unscoped_rows', '?')} opaque row(s) unscoped")
    return _reason_generic(results, step, ctx)


def _reason_scheduling(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    document = _json_output(record["raw_stdout"])
    if isinstance(document, dict):
        totals = document.get("totals") or {}
        counts = totals.get("by_state") or {}
        count_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
        return (f"status {document.get('status', '?')} over "
                f"{totals.get('change_sets', '?')} change set(s) and "
                f"{totals.get('requirements', '?')} requirement(s) ({count_text})")
    return _reason_generic(results, step, ctx)


def _reason_traceability(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    lines = [line for line in record["summary"] if line.startswith("orphans:")]
    return lines[-1] if lines else _reason_generic(results, step, ctx)


def _reason_hazards(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    lines = [line for line in record["summary"] if line.startswith("barrier states:")]
    return lines[-1] if lines else _reason_generic(results, step, ctx)


def _reason_binary(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    return _first_line(record["raw_stderr"]) or _reason_generic(results, step, ctx)


def _reason_docs(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    text = record["raw_stdout"] + record["raw_stderr"]
    lines = [line for line in text.splitlines()
             if "does not agree" in line or line.startswith("docs-consistency: FAIL")]
    return lines[-1].strip() if lines else _reason_generic(results, step, ctx)


def _reason_differential(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    return (f"run_etp5.sh exited {record['exit']}: "
            f"{record['summary'][-1] if record['summary'] else 'no output'}")


def _reason_consumer(results: list[dict], step: Step, ctx: Context) -> str:
    record = _failing(results)
    if record is None:
        return step.pass_reason
    document = _json_output(record["raw_stdout"])
    if isinstance(document, dict):
        inventory = document.get("inventory_availability") or {}
        reason = (f"{document.get('exclusions_failing', '?')} of "
                  f"{document.get('exclusion_rows', '?')} exclusion row(s) fail")
        if not inventory.get("available", True):
            reason += (f"; the recorded inventory {inventory.get('path', '?')} is absent "
                       "(private state)")
        return reason
    return _reason_generic(results, step, ctx)


PARSERS = {
    "generic": _reason_generic,
    "manifest": _reason_manifest,
    "rebuild": _reason_rebuild,
    "proofs": _reason_proofs,
    "differential": _reason_differential,
    "instruments": _reason_instruments,
    "controls": _reason_controls,
    "receipts": _reason_receipts,
    "claims": _reason_claims,
    "freshness": _reason_freshness,
    "independence": _reason_independence,
    "closure": _reason_closure,
    "scheduling": _reason_scheduling,
    "traceability": _reason_traceability,
    "hazards": _reason_hazards,
    "binary": _reason_binary,
    "docs": _reason_docs,
    "consumer": _reason_consumer,
}


# ---------------------------------------------------------------------------
# one step
# ---------------------------------------------------------------------------


def _materialise(argv: tuple[str, ...], ctx: Context) -> tuple[str, ...]:
    resolved = []
    for item in argv:
        if item == "{python}":
            resolved.append(sys.executable or "python3")
        elif item == "{tmp}":
            resolved.append(ctx.tmpdir)
        else:
            resolved.append(item)
    return tuple(resolved)


def _display(argv: tuple[str, ...]) -> list[str]:
    return ["python3" if item == sys.executable else item for item in argv]


def _combine(statuses: list[str]) -> str:
    return max(statuses, key=lambda status: STATUS_ORDER[status]) if statuses else "PASS"


def run_step(step: Step, ctx: Context, execute=None) -> dict:
    execute = execute or subprocess_execute
    record: dict = {
        "name": step.name,
        "title": step.title,
        "required": step.required,
        "establishes": step.establishes,
        "does_not": step.does_not,
        "reads_gitignored": list(step.reads_gitignored),
        "private_state_declared": list(step.reads_gitignored),
        "private_state_present": [path for path in step.reads_gitignored
                                  if ctx.private_state.get(path, {}).get(
                                      "private_entries", 0) > 0],
        "evidence_identity": [digest_path(ctx.root, path) for path in step.identity],
        "tool_digest": [digest_path(ctx.root, path) for path in step.tools],
        "checks": [],
        "status": "NOT_RUN",
        "reason": "not executed",
    }
    ok, detail, needs = prerequisites(step, ctx)
    record["prerequisites"] = needs
    if not ok:
        record["reason"] = detail
        return record

    if step.guard:
        refusal = GUARDS[step.guard](step, ctx)
        if refusal is not None:
            record["status"] = "FAIL"
            record["reason"] = refusal
            return record

    results: list[dict] = []
    for index, command in enumerate(step.commands):
        argv = _materialise(command.argv, ctx)
        request = ExecRequest(argv=argv, cwd=(ctx.root / command.cwd),
                              env=ctx.env, timeout=command.timeout)
        outcome = execute(request)
        if outcome.timed_out:
            status = "BLOCKED"
            reason = f"timed out after {command.timeout}s (resource bound)"
        elif outcome.exit == 0:
            status, reason = "PASS", ""
        elif outcome.exit is not None and outcome.exit in dict(command.not_run_codes):
            status = "NOT_RUN"
            reason = dict(command.not_run_codes)[outcome.exit]
        elif outcome.exit is not None and outcome.exit in command.blocked_codes:
            status = "BLOCKED"
            reason = f"the delegate reported a resource bound (exit {outcome.exit})"
        else:
            status = "FAIL"
            reason = (f"exit {outcome.exit}" if outcome.exit is not None
                      else "the command could not be started")
        result = {
            "index": index,
            "argv": _display(argv),
            "cwd": command.cwd or ".",
            "exit": outcome.exit,
            "status": status,
            "detail": reason,
            "summary": [normalise(line, ctx)
                        for line in _tail_lines(outcome.stdout + "\n" + outcome.stderr)],
            "raw_stdout": outcome.stdout,
            "raw_stderr": outcome.stderr,
        }
        results.append(result)
        record["checks"].append({key: value for key, value in result.items()
                                 if not key.startswith("raw_")})

    record["status"] = _combine([result["status"] for result in results])
    record["reason"] = (step.pass_reason if record["status"] == "PASS"
                        else normalise(summarise(results, step, ctx), ctx))
    return record


# ---------------------------------------------------------------------------
# selection and reporting
# ---------------------------------------------------------------------------


def steps_for(root: Path) -> dict[str, Step]:
    table = dict(STEPS)
    for family, receipt in CONSUMER_FAMILIES.items():
        table[f"consumer-{family}"] = consumer_step(family, receipt)
    return table


def known_steps(root: Path) -> list[str]:
    table = steps_for(root)
    return [name for name in ALL_ORDER if name in table] + [
        "authority"] + sorted(name for name in table if name.startswith("consumer-"))


def all_steps(root: Path) -> list[str]:
    table = steps_for(root)
    return [name for name in ALL_ORDER if name in table] + sorted(
        name for name in table if name.startswith("consumer-"))


def run(names: list[str], ctx: Context, execute=None) -> dict:
    table = steps_for(ctx.root)
    unknown = [name for name in names if name not in table]
    if unknown:
        raise KeyError(unknown[0])
    steps = [run_step(table[name], ctx, execute=execute) for name in names]
    # `all` gates on the required steps; a single requested step gates on itself,
    # so an optional step cannot be requested and then reported as a pass while
    # the run exits 0.
    single = len(steps) == 1
    gating = [step for step in steps if step["required"] or single]
    failed_required = [step["name"] for step in gating if step["status"] != "PASS"]
    counts = {status: sum(1 for step in steps if step["status"] == status)
              for status in STATUS_ORDER}
    return {
        "schema": SCHEMA,
        "interface": INTERFACE,
        "candidate": ctx.candidate,
        "root": str(ctx.root),
        "invocation": {
            "network": ctx.network,
            "tmpdir": "<tmp>",
            "steps": names,
        },
        "private_state": {
            "known_roots": ctx.private_state,
            "present": list(ctx.private_present),
            "note": "tracked_files counts Git-tracked files under a declared root and "
                    "is part of the checkout; private_entries counts the untracked or "
                    "ignored entries Git reports there.  This interface reads no "
                    "gitignored content, and each step names the private paths its "
                    "own tool may read",
        },
        "warnings": list(ctx.warnings),
        "steps": steps,
        "counts": {"selected": len(steps), "by_status": counts},
        "non_passing": [step["name"] for step in steps if step["status"] != "PASS"],
        "status": "FAIL" if failed_required else "PASS",
    }


def render_text(document: dict) -> str:
    candidate = document["candidate"]
    lines = [
        "openssl-rs public verification",
        f"interface  {document['interface']} ({document['schema']})",
        f"candidate  {candidate.get('commit', 'UNKNOWN')} "
        f"[{candidate.get('branch', 'UNKNOWN')}] "
        f"clean={candidate.get('clean', 'UNKNOWN')} (tracked) "
        f"untracked={candidate.get('untracked_changes', 'UNKNOWN')}",
        f"root       {document['root']}",
        f"network    {'declared available' if document['invocation']['network'] else 'not declared (offline)'}",
        "private    " + ("present: " + ", ".join(document["private_state"]["present"])
                         if document["private_state"]["present"]
                         else "no untracked or ignored entries under the declared roots"),
        "",
    ]
    width = max(len(step["name"]) for step in document["steps"])
    for index, step in enumerate(document["steps"], start=1):
        required = "required" if step["required"] else "optional"
        lines.append(f"[{index:>2}/{len(document['steps'])}] "
                     f"{step['name']:<{width}}  {step['status']:<7} ({required})  "
                     f"{step['reason']}")
        for check in step["checks"]:
            lines.append(f"        {' '.join(check['argv'])} -> exit {check['exit']} "
                         f"({check['status']})")
    lines.append("")
    lines.append(f"RESULT: {document['status']} "
                 f"({document['counts']['by_status'].get('PASS', 0)}/"
                 f"{len(document['steps'])} steps PASS)")
    if document["non_passing"]:
        lines.append("not PASS:")
        for step in document["steps"]:
            if step["status"] != "PASS":
                lines.append(f"  {step['name']}: {step['status']}: {step['reason']}")
    return "\n".join(lines) + "\n"


def explain(table: dict[str, Step], names: list[str]) -> str:
    lines = []
    for name in names:
        step = table[name]
        lines.append(f"{name}  ({'required' if step.required else 'optional'}; "
                     f"{'in `all`' if step.required_for_all else 'not in `all`'})")
        lines.append(f"  needs:        {', '.join(step.needs)}")
        lines.append(f"  delegates to: {', '.join(step.tools)}")
        lines.append(f"  establishes:  {step.establishes}")
        lines.append(f"  does not:     {step.does_not}")
        if step.reads_gitignored:
            lines.append(f"  private:      {', '.join(step.reads_gitignored)}")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="Exit 0 only when every selected step is PASS; 1 when any is not; "
               "2 for a refused invocation.",
    )
    parser.add_argument("command", nargs="?",
                        help="a subcommand name, `all`, or `list`")
    parser.add_argument("--json", action="store_true",
                        help="emit one machine-readable document")
    parser.add_argument("--network", action="store_true",
                        help="declare that the network is available (default: offline)")
    parser.add_argument("--explain", action="store_true",
                        help="print each step's prerequisites, establishment and "
                             "non-claims")
    parser.add_argument("--list", action="store_true", help="list the subcommands")
    parser.add_argument("--tmp", default=None,
                        help="temporary root for steps that need one (default: a fresh "
                             "directory under TMPDIR)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    table = steps_for(root)

    if args.list:
        for name in known_steps(root):
            step = table[name]
            role = "required" if step.required else "optional"
            in_all = "in all" if step.required_for_all else "not in all"
            print(f"{name}\t{role}\t{in_all}")
        return EXIT_PASS

    if args.explain:
        if args.command in (None, "all"):
            names = known_steps(root)
        else:
            names = [args.command]
        unknown = [name for name in names if name not in table]
        if unknown:
            print(f"verify: unknown subcommand {unknown[0]!r}", file=sys.stderr)
            return EXIT_USAGE
        sys.stdout.write(explain(table, names))
        return EXIT_PASS

    name = args.command or "list"
    if name == "all":
        names = all_steps(root)
    elif name in table:
        names = [name]
    else:
        print(f"verify: unknown subcommand {name!r}; known: "
              f"{', '.join(known_steps(root))}, all, list", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.tmp:
            tmpdir = args.tmp
            Path(tmpdir).mkdir(parents=True, exist_ok=True)
        else:
            tmpdir = tempfile.mkdtemp(prefix="openssl-rs-verify-")
        ctx = build_context(root, network=args.network, tmpdir=tmpdir)
        document = run(names, ctx)
    except KeyError as exc:  # pragma: no cover - guarded above
        print(f"verify: unknown step {exc.args[0]!r}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"verify: cannot inspect {root}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        sys.stdout.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(document))
    return EXIT_PASS if document["status"] == "PASS" else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
