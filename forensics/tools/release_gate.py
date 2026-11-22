#!/usr/bin/env python3
"""release_gate.py -- one fail-closed decision for a release candidate.

What this gate decides
----------------------
A release candidate passes only when every required item below passes, in the
order the queue defines.  There is no score, no weighting and no partial pass:
one refused item refuses the release.

  1. candidate identity   the gate is reading the commit it was asked about,
                          and (under --require-clean) that tree is clean;
  2. claim set            `evidence/etp/claims.json` validates under the claim
                          algebra, and no claim is in a state that forbids a
                          release:
                            * `CONTRADICTED`, `REFUTED` or `WITHDRAWN`;
                            * `NOT_ESTABLISHED` when a graduation is requested
                              (--graduation, or a `SAFE_COMPATIBLE` member);
                            * a positive verdict over evidence whose declared
                              state is `WITHDRAWN`, `REFUTED` or
                              `NOT_ESTABLISHED`;
  3. receipts             `courts/phase18/interop/check_receipts.py` holds over
                          the interop evidence (rules R1-R5);
  4. instruments          `forensics/tools/instrument_qualify.py check` holds:
                          the register validates and every executable control
                          passes in the venue that ran it;
  5. external package     a built ETP-6 package is present and its own
                          `verify.sh` (or `etp6_verify.py`) passes;
  6. documentation        `forensics/tools/docs_consistency.py` holds.

Every item is required.  A tool that cannot be found, a package that was not
supplied, or a checker that cannot run is a refusal with a named rule, never a
skip.  This is the difference between a gate and a checklist.

Output
------
One line per refused item, naming the rule and the artefact that refused it:

    REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-004: verdict CONTRADICTED -- <basis>
    REFUSED RG_PACKAGE_MISSING -: no --package was supplied

Exit status: 0 only when nothing was refused; 1 when anything was refused; 2
for a usage error.  `--json` emits the same decision as one sorted document for
retention alongside a release.

Candidate identity
------------------
`--candidate REF` defaults to `HEAD`.  The gate evaluates the working tree and
refuses `RG_CANDIDATE_NOT_CHECKED_OUT` unless `HEAD` is that commit: it will not
report on a commit it is not reading.  `--require-clean` additionally refuses a
worktree with any uncommitted tracked or untracked path (ignored paths excluded),
which is what the release procedure uses, because `cargo publish` packages the
working tree and not the commit; the default is off so a dry run during
development is still possible, and the identity line records the dirty state
either way.

The package
-----------
`--package` accepts an unpacked ETP-6 package root (the directory holding
`MANIFEST.json` and `verify.sh`) or the `.tar.gz` that
`forensics/tools/etp6_package.py` produced.  An archive is unpacked into a
temporary directory with absolute paths, parent traversal, device nodes and
links refused.  No package means `RG_PACKAGE_MISSING`: the external-reproduction
item is required, so an absent package is not "not applicable".

What this gate does not establish
---------------------------------
It does not decide that a claim is true, that an instrument result is
representative, that the package was produced by an independent party, or that
the release is safe.  It decides only that the named machinery accepted this
candidate.  A passing gate is evidence that the checks ran and held; it is not a
security, compatibility or cryptographic result (AGENTS.md section 8).

Usage
-----
    python3 forensics/tools/release_gate.py
    python3 forensics/tools/release_gate.py --candidate v0.0.50 --require-clean \
        --package /tmp/etp6-unpacked
    python3 forensics/tools/release_gate.py --json
    python3 forensics/tools/release_gate.py --self-test

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable

EXIT_PASS = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CLAIMS = ROOT / "evidence/etp/claims.json"
CLAIM_SCHEMA = ROOT / "evidence/etp/claim.schema.json"
CLAIM_TOOL = ROOT / "forensics/tools/etp_claims.py"
RECEIPT_TOOL = ROOT / "courts/phase18/interop/check_receipts.py"
INTEROP_DIR = ROOT / "courts/phase18/interop"
INSTRUMENT_TOOL = ROOT / "forensics/tools/instrument_qualify.py"
INSTRUMENT_REGISTRY = ROOT / "evidence/etp3/instruments.json"
DOCS_TOOL = ROOT / "forensics/tools/docs_consistency.py"

# Verdict states that forbid a release outright.  `SUPERSEDED` is not one: the
# claim was current and has been replaced, which is a history fact, not a
# present contradiction.  It is reported in the summary and never as a pass.
FORBIDDING_VERDICTS = {
    "CONTRADICTED": "RG_CLAIM_CONTRADICTED",
    "REFUTED": "RG_CLAIM_REFUTED",
    "WITHDRAWN": "RG_CLAIM_WITHDRAWN",
}

# Evidence states that cannot support a positive verdict.
NON_CURRENT_EVIDENCE = {"WITHDRAWN", "REFUTED", "NOT_ESTABLISHED"}

# Verdicts that assert a positive result.  A graduation modality is also a
# positive assertion, and the claim algebra already refuses a graduation over
# non-current evidence; this gate names the artefact.
POSITIVE_VERDICTS = {"ESTABLISHED", "SAFE_COMPATIBLE"}

GRADUATED_MODALITIES = {"PROOF_OBLIGATIONS_DISCHARGED", "BINARY_REFINEMENT_VERIFIED"}

# One line per refused item is the contract; a checker that emits thousands of
# lines is still one refused item, so the detail is compacted to a bounded
# number of named lines and the count is never hidden.
MAX_DETAIL_LINES = 40


@dataclass(frozen=True)
class Refusal:
    rule: str
    artefact: str
    detail: str

    def line(self) -> str:
        return f"REFUSED {self.rule} {self.artefact}: {self.detail}"


@dataclass
class Results:
    refusals: list[Refusal]
    recorded: list[str]

    def refused(self) -> bool:
        return bool(self.refusals)


def _run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    """Run a checker.  Absence and timeout are outcomes, not exceptions."""
    return subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _missing_tool(rule: str, path: Path) -> Refusal:
    return Refusal(rule, str(path), "checker is absent; a missing checker is a refusal, not a skip")


def _bounded(lines: list[str]) -> list[str]:
    clean = [line.rstrip() for line in lines if line.strip()]
    if len(clean) <= MAX_DETAIL_LINES:
        return clean
    omitted = len(clean) - MAX_DETAIL_LINES
    return clean[:MAX_DETAIL_LINES] + [f"... {omitted} further line(s) omitted; see the checker output"]


# ---------------------------------------------------------------------------
# 1. Candidate identity
# ---------------------------------------------------------------------------
def resolve_candidate(root: Path, ref: str) -> tuple[str | None, list[Refusal]]:
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "--no-optional-locks", *args],
            cwd=str(root),
            text=True,
            capture_output=True,
            timeout=120,
        )

    resolved = git("rev-parse", "--verify", f"{ref}^{{commit}}")
    if resolved.returncode != 0:
        detail = (resolved.stderr or resolved.stdout).strip().splitlines()
        return None, [Refusal("RG_CANDIDATE_UNRESOLVED", ref,
                              detail[-1] if detail else "git rev-parse failed")]
    candidate = resolved.stdout.strip()
    head = git("rev-parse", "--verify", "HEAD").stdout.strip()
    refusals: list[Refusal] = []
    if head != candidate:
        refusals.append(Refusal(
            "RG_CANDIDATE_NOT_CHECKED_OUT", candidate,
            f"HEAD is {head}; the gate evaluates the checked-out tree and will not "
            f"report on a commit it is not reading",
        ))
    return candidate, refusals


def worktree_state(root: Path) -> tuple[bool, list[str]]:
    status = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain", "--untracked-files=normal"],
        cwd=str(root), text=True, capture_output=True, timeout=120,
    )
    dirty = [line for line in status.stdout.splitlines() if line.strip()]
    return bool(dirty), dirty


# ---------------------------------------------------------------------------
# 2. Claim set
# ---------------------------------------------------------------------------
def _claim_verdict(claim: dict) -> str:
    verdict = claim.get("verdict") or {}
    return str(verdict.get("state", "UNKNOWN"))


def scan_claims(document: dict, graduation_requested: bool) -> tuple[list[Refusal], list[str]]:
    """The release rules over claim states, independent of schema validation."""
    refusals: list[Refusal] = []
    recorded: list[str] = []
    claims = document.get("claims") or []
    if any(_claim_verdict(c) == "SAFE_COMPATIBLE" for c in claims) or any(
        c.get("modality") in GRADUATED_MODALITIES for c in claims
    ):
        graduation_requested = True

    for claim in claims:
        ident = str(claim.get("id", "<no id>"))
        state = _claim_verdict(claim)
        basis = str((claim.get("verdict") or {}).get("basis", "")).strip()
        if state in FORBIDDING_VERDICTS:
            refusals.append(Refusal(
                FORBIDDING_VERDICTS[state], ident,
                f"verdict {state}" + (f" -- {basis}" if basis else ""),
            ))
        elif state == "NOT_ESTABLISHED" and graduation_requested:
            refusals.append(Refusal(
                "RG_CLAIM_NOT_ESTABLISHED", ident,
                "verdict NOT_ESTABLISHED while a graduation is requested",
            ))
        elif state == "SUPERSEDED":
            recorded.append(f"claim {ident}: verdict SUPERSEDED (recorded, not a release block)")
        elif state == "NOT_ESTABLISHED":
            recorded.append(f"claim {ident}: verdict NOT_ESTABLISHED (no graduation requested)")

        if state in POSITIVE_VERDICTS:
            for record in claim.get("evidence") or []:
                declared = record.get("state") or {}
                value = declared.get("value") if isinstance(declared, dict) else None
                if value in NON_CURRENT_EVIDENCE:
                    refusals.append(Refusal(
                        "RG_CLAIM_WITHDRAWN_EVIDENCE",
                        f"{ident}/{record.get('id', '?')}",
                        f"positive verdict {state} over {record.get('path', '?')} whose "
                        f"declared state is {value} ({declared.get('artefact', '?')} "
                        f"@{declared.get('revision', '?')})",
                    ))
    return refusals, recorded


def check_claims(
    root: Path,
    claims: Path,
    schema: Path,
    graduation_requested: bool,
    timeout: int = 900,
) -> Results:
    refusals: list[Refusal] = []
    recorded: list[str] = []
    if not CLAIM_TOOL.is_file():
        return Results([_missing_tool("RG_CLAIM_TOOL_MISSING", CLAIM_TOOL)], [])
    if not claims.is_file():
        return Results([Refusal("RG_CLAIMS_MISSING", str(claims), "claim document is absent")], [])

    validated = _run(
        [PYTHON, str(CLAIM_TOOL), "validate", "--document", str(claims), "--schema", str(schema)],
        root, timeout,
    )
    if validated.returncode != 0:
        parsed = False
        try:
            payload = json.loads(validated.stdout)
            parsed = True
            for row in payload.get("refusals", []):
                refusals.append(Refusal(
                    "RG_CLAIMS_INVALID",
                    f"{row.get('path', '?')}",
                    f"{row.get('rule', '?')}: {row.get('detail', '?')}",
                ))
        except (ValueError, TypeError):
            pass
        if not parsed:
            detail = _bounded((validated.stderr or validated.stdout).splitlines())
            refusals.append(Refusal(
                "RG_CLAIM_TOOL_FAILED", str(claims),
                detail[-1] if detail else f"validator exited {validated.returncode}",
            ))

    # The per-claim release rules run even when schema validation refused the
    # document, so a withdrawn-evidence claim is named rather than hidden behind
    # a generic schema failure.
    try:
        document = json.loads(claims.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        refusals.append(Refusal("RG_CLAIMS_UNREADABLE", str(claims), str(exc)))
        return Results(refusals, recorded)

    rule_refusals, rule_recorded = scan_claims(document, graduation_requested)
    refusals.extend(rule_refusals)
    recorded.extend(rule_recorded)

    conjoined = _run([PYTHON, str(CLAIM_TOOL), "conjoin", "--document", str(claims)], root, timeout)
    if conjoined.returncode != 0:
        detail = _bounded((conjoined.stderr or conjoined.stdout).splitlines())
        refusals.append(Refusal(
            "RG_CLAIM_CONJOIN_FAILED", str(claims),
            detail[-1] if detail else f"conjoin exited {conjoined.returncode}",
        ))
    else:
        try:
            verdict = json.loads(conjoined.stdout).get("verdict")
            recorded.append(f"claim conjunction: {verdict}")
        except (ValueError, TypeError):
            refusals.append(Refusal(
                "RG_CLAIM_CONJOIN_UNPARSABLE", str(claims),
                "conjoin produced no parsable verdict",
            ))

    identity = document.get("source_identity") or {}
    if identity.get("commit"):
        recorded.append(f"claim source identity: {identity['commit']}")
    return Results(refusals, recorded)


# ---------------------------------------------------------------------------
# 3. Interop receipts
# ---------------------------------------------------------------------------
def check_receipts(root: Path, interop_dir: Path, timeout: int = 600) -> Results:
    if not RECEIPT_TOOL.is_file():
        return Results([_missing_tool("RG_RECEIPT_TOOL_MISSING", RECEIPT_TOOL)], [])
    if not interop_dir.is_dir():
        return Results([Refusal("RG_RECEIPT_DIR_MISSING", str(interop_dir),
                                "interop evidence directory is absent")], [])
    run = _run(
        [PYTHON, str(RECEIPT_TOOL), "--dir", str(interop_dir), "--summary"],
        root, timeout,
    )
    recorded = [line for line in run.stdout.splitlines() if line.strip()]
    if run.returncode == 0:
        return Results([], recorded)
    problems = _bounded(run.stderr.splitlines())
    if not problems:
        problems = [f"checker exited {run.returncode} with no diagnostic"]
    return Results([Refusal("RG_RECEIPT", str(interop_dir), p) for p in problems], recorded)


# ---------------------------------------------------------------------------
# 4. Instrument register
# ---------------------------------------------------------------------------
def check_instruments(
    root: Path,
    registry: Path,
    mode: str = "check",
    timeout: int = 3600,
) -> Results:
    if not INSTRUMENT_TOOL.is_file():
        return Results([_missing_tool("RG_INSTRUMENT_TOOL_MISSING", INSTRUMENT_TOOL)], [])
    if not registry.is_file():
        return Results([Refusal("RG_INSTRUMENT_REGISTRY_MISSING", str(registry),
                                "instrument register is absent")], [])
    run = _run(
        [PYTHON, str(INSTRUMENT_TOOL), mode, "--registry", str(registry)],
        root, timeout,
    )
    if run.returncode == 0:
        recorded = [line for line in run.stdout.splitlines() if line.strip()][-1:]
        return Results([], recorded)
    problems = _bounded((run.stderr or "").splitlines()) or _bounded(run.stdout.splitlines())
    if not problems:
        problems = [f"instrument checker exited {run.returncode} with no diagnostic"]
    return Results([Refusal("RG_INSTRUMENT", str(registry), p) for p in problems], [])


# ---------------------------------------------------------------------------
# 5. External package
# ---------------------------------------------------------------------------
def _safe_extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"archive member escapes the destination: {member.name}")
            if member.islnk() or member.issym() or member.isdev():
                raise ValueError(f"archive member is a link or device: {member.name}")
        tar.extractall(destination)


def _package_runner(package: Path) -> list[str] | None:
    if (package / "verify.sh").is_file():
        return ["bash", "verify.sh"]
    verifier = package / "forensics/tools/etp6_verify.py"
    if verifier.is_file():
        return [PYTHON, str(verifier)]
    return None


def check_package(package: Path | None, timeout: int = 5400) -> Results:
    if package is None:
        return Results([Refusal(
            "RG_PACKAGE_MISSING", "-",
            "no --package was supplied; the ETP-6 external-package verifier is a "
            "required release item, so an absent package is a refusal",
        )], [])
    if not package.exists():
        return Results([Refusal("RG_PACKAGE_MISSING", str(package),
                                "the named package does not exist")], [])

    temporary: tempfile.TemporaryDirectory | None = None
    try:
        if package.is_file():
            if not package.name.endswith((".tar.gz", ".tgz")):
                return Results([Refusal("RG_PACKAGE_INVALID", str(package),
                                        "package is neither a directory nor a .tar.gz")], [])
            temporary = tempfile.TemporaryDirectory(prefix="release-gate-package-")
            unpacked = Path(temporary.name)
            try:
                _safe_extract(package, unpacked)
            except (tarfile.TarError, ValueError, OSError) as exc:
                return Results([Refusal("RG_PACKAGE_INVALID", str(package), str(exc))], [])
            package_root = unpacked
        else:
            package_root = package

        runner = _package_runner(package_root)
        if runner is None:
            return Results([Refusal(
                "RG_PACKAGE_INVALID", str(package),
                "no verify.sh and no forensics/tools/etp6_verify.py at the package root",
            )], [])
        run = _run(runner, package_root, timeout)
        if run.returncode == 0:
            result = [line for line in run.stdout.splitlines() if line.strip().startswith("RESULT:")]
            return Results([], [f"package {package}: {result[-1] if result else 'verifier exited 0'}"])
        problems = _bounded([
            line for line in (run.stdout + "\n" + run.stderr).splitlines()
            if line.strip() and ("FAIL" in line or "REFUSED" in line or "RESULT:" in line
                                 or "missing" in line.lower())
        ])
        if not problems:
            problems = [f"verifier exited {run.returncode} with no diagnostic"]
        return Results([Refusal("RG_PACKAGE", str(package), p) for p in problems], [])
    finally:
        if temporary is not None:
            temporary.cleanup()


# ---------------------------------------------------------------------------
# 6. Documentation consistency
# ---------------------------------------------------------------------------
def check_docs(root: Path, timeout: int = 600, command: list[str] | None = None) -> Results:
    if command is None:
        if not DOCS_TOOL.is_file():
            return Results([_missing_tool("RG_DOCS_TOOL_MISSING", DOCS_TOOL)], [])
        command = [PYTHON, str(DOCS_TOOL)]
    run = _run(command, root, timeout)
    if run.returncode == 0:
        recorded = [line for line in run.stdout.splitlines() if line.strip()][-1:]
        return Results([], recorded)
    problems = [line.strip() for line in run.stdout.splitlines() if "STALE:" in line]
    if not problems:
        problems = _bounded((run.stderr or run.stdout).splitlines())
    if not problems:
        problems = [f"documentation checker exited {run.returncode} with no diagnostic"]
    return Results([Refusal("RG_DOCS", "docs/", p) for p in problems], [])


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------
def evaluate(args: argparse.Namespace) -> Results:
    root = ROOT
    recorded: list[str] = []
    refusals: list[Refusal] = []

    candidate, identity_refusals = resolve_candidate(root, args.candidate)
    refusals.extend(identity_refusals)
    dirty, dirty_files = worktree_state(root)
    state = (
        f"{len(dirty_files)} uncommitted path(s) (tracked or untracked; ignored paths excluded)"
        if dirty else "clean worktree (ignored paths excluded)"
    )
    recorded.append(f"candidate {candidate or args.candidate}; {state}")
    if args.require_clean and dirty:
        refusals.append(Refusal(
            "RG_CANDIDATE_DIRTY", candidate or args.candidate,
            f"{len(dirty_files)} uncommitted path(s); a release is evaluated from a "
            f"committed tree, because `cargo publish` packages the working tree: "
            + ", ".join(dirty_files[:10]),
        ))

    claims = Path(args.claims).resolve() if args.claims else CLAIMS
    schema = Path(args.schema).resolve() if args.schema else CLAIM_SCHEMA
    result = check_claims(root, claims, schema, args.graduation)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    interop = Path(args.interop_dir).resolve() if args.interop_dir else INTEROP_DIR
    result = check_receipts(root, interop)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    registry = Path(args.instruments_registry).resolve() if args.instruments_registry else INSTRUMENT_REGISTRY
    result = check_instruments(root, registry, args.instrument_mode)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_package(Path(args.package).resolve() if args.package else None)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_docs(root)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    return Results(refusals, recorded)


def self_test() -> int:
    """Prove the gate refuses each named failure class.

    The fixtures are constructed in a temporary directory from the committed
    claim document, so the test does not depend on the current verdicts being
    either green or red.  Receipt, instrumentation and package controls call the
    real checkers; the documentation control drives the gate's adapter with a
    checker that reports a stale claim, because `docs_consistency.py` binds its
    repository root at import and cannot be pointed at a fixture tree.  The real
    documentation checker is also run as a positive control, which is what shows
    the adapter is connected to it.
    """
    failures: list[str] = []
    cases: list[tuple[str, str]] = []

    def expect(name: str, results: Results, rule: str) -> None:
        hit = any(r.rule == rule for r in results.refusals)
        cases.append((name, rule))
        if not hit:
            failures.append(f"{name}: expected {rule}, got {[r.rule for r in results.refusals]}")

    with tempfile.TemporaryDirectory(prefix="release-gate-self-test-") as temporary:
        tmp = Path(temporary)
        document = json.loads(CLAIMS.read_text(encoding="utf-8"))
        claims = document["claims"]

        # A schema-valid document with a CONTRADICTED member.
        contradicted = json.loads(json.dumps(document))
        for claim in contradicted["claims"]:
            if claim["verdict"]["state"] == "ESTABLISHED":
                claim["derived_from"]["verdict"] = "CONTRADICTED"
                claim["verdict"] = {
                    "state": "CONTRADICTED",
                    "basis": "self-test fixture: two tracked records disagree",
                }
                claim["contradiction"] = {
                    "parties": [
                        {"id": "fixture-a", "source": "docs/NON_CLAIMS.md",
                         "assertion": "fixture assertion A", "asserted_verdict": "ESTABLISHED",
                         "evidence": ["docs/NON_CLAIMS.md"]},
                        {"id": "fixture-b", "source": "docs/RELEASE_GATES.md",
                         "assertion": "fixture assertion B", "asserted_verdict": "REFUTED",
                         "evidence": ["docs/RELEASE_GATES.md"]},
                    ],
                    "resolution_owner": "SELFTEST",
                }
                break
        contradicted_path = tmp / "claims-contradicted.json"
        contradicted_path.write_text(json.dumps(contradicted), encoding="utf-8")
        expect(
            "contradicted claim",
            check_claims(ROOT, contradicted_path, CLAIM_SCHEMA, False),
            "RG_CLAIM_CONTRADICTED",
        )

        # A positive verdict whose cited evidence the artefact declares withdrawn.
        withdrawn = json.loads(json.dumps(document))
        for claim in withdrawn["claims"]:
            if claim["verdict"]["state"] == "ESTABLISHED" and claim.get("evidence"):
                record = claim["evidence"][0]
                record["state"] = {
                    "value": "WITHDRAWN",
                    "artefact": record.get("path", "fixture"),
                    "revision": "self-test",
                }
                break
        withdrawn_path = tmp / "claims-withdrawn-evidence.json"
        withdrawn_path.write_text(json.dumps(withdrawn), encoding="utf-8")
        expect(
            "withdrawn-evidence claim",
            check_claims(ROOT, withdrawn_path, CLAIM_SCHEMA, False),
            "RG_CLAIM_WITHDRAWN_EVIDENCE",
        )

        # A receipt that does not parse.
        receipts = tmp / "receipts"
        receipts.mkdir()
        (receipts / "RECEIPT-self-test.json").write_text("{ not json", encoding="utf-8")
        expect("failing receipt", check_receipts(ROOT, receipts), "RG_RECEIPT")

        # A register that is not a register.
        bad_registry = tmp / "instruments.json"
        bad_registry.write_text("{}", encoding="utf-8")
        expect(
            "invalid instrument register",
            check_instruments(ROOT, bad_registry, "check"),
            "RG_INSTRUMENT",
        )

        # No package at all.
        expect("missing package", check_package(None), "RG_PACKAGE_MISSING")

        # A package whose own verifier refuses.
        package = tmp / "package"
        package.mkdir()
        (package / "verify.sh").write_text(
            "#!/bin/sh\necho '[1/1] digests FAIL (required) fixture failure'\nexit 1\n",
            encoding="utf-8",
        )
        expect("failing package verifier", check_package(package), "RG_PACKAGE")

        # A documentation checker that reports a stale claim.
        stale_checker = tmp / "stale-docs-checker.py"
        stale_checker.write_text(
            "import sys\nprint('  STALE: docs/FIXTURE.md: fixture claim contradicts its generator')\n"
            "sys.exit(1)\n",
            encoding="utf-8",
        )
        expect(
            "documentation inconsistency",
            check_docs(ROOT, command=[PYTHON, str(stale_checker)]),
            "RG_DOCS",
        )

        if DOCS_TOOL.is_file():
            real_docs = check_docs(ROOT)
            cases.append(("real documentation checker (positive control)", "no refusal"))
            if real_docs.refusals:
                failures.append(
                    "real documentation checker (positive control): "
                    f"unexpected refusals {[r.rule for r in real_docs.refusals]}"
                )

    for name, rule in cases:
        status = "ok" if not any(f.startswith(name + ":") for f in failures) else "FAIL"
        print(f"  {status:4s} {name}: expected {rule}")
    if failures:
        for failure in failures:
            print(f"release-gate self-test: {failure}")
        print("release-gate self-test: FAIL")
        return EXIT_REFUSED
    print(f"release-gate self-test: ok ({len(cases)} cases)")
    return EXIT_PASS


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--candidate", default="HEAD",
                        help="commit to evaluate (default HEAD; the tree must be checked out there)")
    parser.add_argument("--require-clean", action="store_true",
                        help="refuse a dirty tracked worktree (the release procedure uses this)")
    parser.add_argument("--claims", default=None, help="claim document (default evidence/etp/claims.json)")
    parser.add_argument("--schema", default=None, help="claim schema (default evidence/etp/claim.schema.json)")
    parser.add_argument("--graduation", action="store_true",
                        help="a graduation is requested, so NOT_ESTABLISHED members refuse")
    parser.add_argument("--interop-dir", default=None,
                        help="interop evidence directory (default courts/phase18/interop)")
    parser.add_argument("--instruments-registry", default=None,
                        help="instrument register (default evidence/etp3/instruments.json)")
    parser.add_argument("--instrument-mode", choices=("check", "validate"), default="check",
                        help="instrument mode; check runs the executable controls (default)")
    parser.add_argument("--package", default=None,
                        help="unpacked ETP-6 package root or its .tar.gz")
    parser.add_argument("--json", action="store_true", help="emit one machine-readable decision")
    parser.add_argument("--self-test", action="store_true",
                        help="prove the gate refuses each named failure class")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    results = evaluate(args)
    if args.json:
        payload = {
            "candidate": args.candidate,
            "recorded": results.recorded,
            "refusals": [{"rule": r.rule, "artefact": r.artefact, "detail": r.detail}
                         for r in results.refusals],
            "verdict": "REFUSED" if results.refused() else "PASS",
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for line in results.recorded:
            print(f"release-gate: {line}")
        for refusal in results.refusals:
            print(refusal.line())
        if results.refused():
            print(f"release-gate: REFUSED ({len(results.refusals)} item(s))")
        else:
            print("release-gate: PASS (candidate, claims, receipts, instruments, package, docs)")

    return EXIT_REFUSED if results.refused() else EXIT_PASS


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
