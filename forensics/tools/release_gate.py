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
                            * a current claim whose required evidence the
                              identity triage marks `UNCERTIFIABLE`
                              (`RG_CLAIM_UNCERTIFIABLE_EVIDENCE`) or
                              `HISTORICAL` (`RG_CLAIM_HISTORICAL_EVIDENCE`),
                              naming the artefact;
  2b. identity triage     `evidence/etp-t9/IDENTITY-TRIAGE.json` is present and
                          bound to the committed dependency registry. An absent
                          triage is `RG_TRIAGE_MISSING`, a triage for another
                          registry is `RG_TRIAGE_STALE`;
  3. receipts             `courts/phase18/interop/check_receipts.py` holds over
                          the interop evidence (rules R1-R5);
  4. instruments          `forensics/tools/instrument_qualify.py check` holds:
                          the register validates and every executable control
                          passes in the venue that ran it;
  5. external package     a built ETP-6 package is present, its own
                          `verify.sh` (or `etp6_verify.py`) passes, and the
                          package's recorded `candidate.commit`/`candidate.tree`
                          equal the candidate the gate resolved (or an explicit
                          `--package-supersedes` identity the gate records);
  6. documentation        `forensics/tools/docs_consistency.py` holds.
  7. role authorisation   the `release` action is `AUTHORISED` under
                          `forensics/tools/authorisation.py`, its role record and
                          its action policy; a refused or not-run release
                          authorisation is `RG_AUTHORISATION_REFUSED`, and an
                          absent tool or record is never a skip.
  8. thresholds           the `release` threshold is `MET` under
                          `forensics/tools/thresholds.py` over distinct
                          established trust domains; an unmet, unreachable or
                          not-run threshold is `RG_THRESHOLD_UNMET`, and an
                          absent tool or record is never a skip.
  9. release policy       the pinned A20 policy is `ADMIT` under
                          `forensics/tools/policy_engine.py`, a conjunction of
                          obligations with denial by default; a `DENY` decision
                          is `RG_POLICY_DENIED` naming the unmet obligations and
                          every code, and an absent tool or record is never a
                          skip.
 10. transparency         `forensics/tools/continuous_enforcement.py check`
                          holds: the B0 registry and B4 publication record are
                          present and agree with the addendum, no claim asserts
                          publication or admission the B4 record contradicts,
                          every `transparency` field is defined by the schema and
                          bound by digest, the public non-claims are written, and
                          no gate item or previously checked transparency code
                          has disappeared.  Each refusal is reported with the
                          tool's `CE_REFUSED_*` code, and an absent tool is
                          `RG_TRANSPARENCY_TOOL_MISSING`, never a skip.

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

The package's own `MANIFEST.json` records the commit and tree it was built from,
and that identity is compared with `--candidate`: a package for another commit
is refused as `RG_PACKAGE_CANDIDATE_MISMATCH` naming both identities, because
reproducing a different commit cannot evidence this release.  A genuinely
different identity is admitted only through the explicit
`--package-supersedes REF` flag, whose resolved commit is recorded in the
decision; the flag is never inferred from the package.

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
DEPENDENCY_REGISTRY = ROOT / "evidence/etp-t9/DEPENDENCIES.json"
IDENTITY_TRIAGE = ROOT / "evidence/etp-t9/IDENTITY-TRIAGE.json"
RECEIPT_TOOL = ROOT / "courts/phase18/interop/check_receipts.py"
INTEROP_DIR = ROOT / "courts/phase18/interop"
INSTRUMENT_TOOL = ROOT / "forensics/tools/instrument_qualify.py"
INSTRUMENT_REGISTRY = ROOT / "evidence/etp3/instruments.json"
DOCS_TOOL = ROOT / "forensics/tools/docs_consistency.py"
AUTHORISATION_TOOL = ROOT / "forensics/tools/authorisation.py"
AUTHORISATION_RECORD = ROOT / "evidence/a14/AUTHORISATION.json"
AUTHORISATION_ROLES = ROOT / "evidence/a14/ROLES.json"
THRESHOLD_TOOL = ROOT / "forensics/tools/thresholds.py"
THRESHOLD_DECLARATIONS = ROOT / "evidence/a15/THRESHOLDS.json"
THRESHOLD_APPROVALS = ROOT / "evidence/a15/APPROVALS.json"
THRESHOLD_DOMAINS = ROOT / "evidence/a15/DOMAINS.json"
POLICY_TOOL = ROOT / "forensics/tools/policy_engine.py"
POLICY_RECORD = ROOT / "evidence/a20/POLICY.json"
POLICY_PIN = ROOT / "evidence/a20/POLICY-PIN.json"
TRANSPARENCY_TOOL = ROOT / "forensics/tools/continuous_enforcement.py"
TRANSPARENCY_REGISTRY = ROOT / "evidence/b0/REGISTRY.json"
TRANSPARENCY_PUBLICATION = ROOT / "evidence/b4/PUBLICATION.json"
TRANSPARENCY_CLAIMS = ROOT / "evidence/etp/claims.json"
TRANSPARENCY_SCHEMA = ROOT / "evidence/etp/claim.schema.json"
TRANSPARENCY_NONCLAIMS = ROOT / "docs/TRANSPARENCY-NON-CLAIMS.md"
TRANSPARENCY_GATE = ROOT / "forensics/tools/release_gate.py"
TRANSPARENCY_ENFORCEMENT = ROOT / "evidence/b8/ENFORCEMENT.json"
TRANSPARENCY_DOCUMENT = ROOT / "docs/CONTINUOUS-ENFORCEMENT.md"

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

# Claim states whose required evidence is not examined for freshness. A claim
# that is already refused is named once, a `NOT_ESTABLISHED` claim asserts that
# the property is not established, and a `RISK_ACCEPTED` claim asserts a
# governance decision rather than a property of the artefact. None of them can
# support a positive conclusion for the release to withhold.  A `SAFE_COMPATIBLE`
# verdict is not in this set and is still examined.
NON_ASSERTIVE_CLAIM_STATES = set(FORBIDDING_VERDICTS) | {
    "SUPERSEDED", "NOT_ESTABLISHED", "RISK_ACCEPTED"
}

# The identity-triage classes that may not support a current claim.
TRIAGE_CLASSES = ("DERIVED", "DECLARED", "HISTORICAL", "UNCERTIFIABLE")
TRIAGE_SCHEMA = "openssl-rs/etp/identity-triage/1"

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
def resolve_commit(root: Path, ref: str) -> tuple[str | None, str]:
    """Resolve a ref to a commit without requiring it to be checked out."""
    run = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        cwd=str(root), text=True, capture_output=True, timeout=120,
    )
    if run.returncode != 0:
        detail = (run.stderr or run.stdout).strip().splitlines()
        return None, (detail[-1] if detail else "git rev-parse failed")
    return run.stdout.strip(), ""


def resolve_tree(root: Path, commit: str) -> str | None:
    """The tree a resolved commit names, or None when it cannot be read."""
    run = subprocess.run(
        ["git", "--no-optional-locks", "rev-parse", "--verify", f"{commit}^{{tree}}"],
        cwd=str(root), text=True, capture_output=True, timeout=120,
    )
    return run.stdout.strip() if run.returncode == 0 and run.stdout.strip() else None


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


def scan_claims(
    document: dict, graduation_requested: bool, triage: dict[str, dict] | None = None
) -> tuple[list[Refusal], list[str]]:
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

        # The identity triage decides whether the evidence a current claim
        # requires can be certified current at all. Both rules name the artefact:
        # the refusal is about that artefact, not about the claim's topic.
        if triage and state not in NON_ASSERTIVE_CLAIM_STATES:
            seen: set[str] = set()
            for record in claim.get("evidence") or []:
                path = record.get("path") if isinstance(record, dict) else None
                if not isinstance(path, str) or path in seen:
                    continue
                seen.add(path)
                entry = triage.get(path) or {}
                if entry.get("class") == "UNCERTIFIABLE":
                    refusals.append(Refusal(
                        "RG_CLAIM_UNCERTIFIABLE_EVIDENCE",
                        f"{ident}/{path}",
                        f"claim {ident} ({state}) requires {path}, which has no certifiable identity: "
                        f"{entry.get('cause')} {entry.get('cause_name')} -- {entry.get('reason')}",
                    ))
                elif entry.get("class") == "HISTORICAL":
                    commit = (entry.get("identity") or {}).get("commit", "?")
                    refusals.append(Refusal(
                        "RG_CLAIM_HISTORICAL_EVIDENCE",
                        f"{ident}/{path}",
                        f"claim {ident} ({state}) requires {path}, which is a record of "
                        f"{entry.get('rule')} at {commit} and may not be cited as current evidence",
                    ))
    return refusals, recorded


def check_claims(
    root: Path,
    claims: Path,
    schema: Path,
    graduation_requested: bool,
    timeout: int = 900,
    triage: dict[str, dict] | None = None,
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

    rule_refusals, rule_recorded = scan_claims(document, graduation_requested, triage)
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
# 2b. Identity triage
# ---------------------------------------------------------------------------
def load_triage(path: Path, registry: Path) -> tuple[dict[str, dict] | None, list[Refusal]]:
    """Load the identity triage and check that it is bound to the registry.

    The triage is a required item: an artefact with no certifiable identity
    cannot support a current claim, and an absent triage would silently restore
    the permissive behaviour this item exists to remove. A record that binds a
    different registry is stale, and a class outside the closed set is refused
    rather than treated as non-blocking.
    """
    if not path.is_file():
        return None, [Refusal(
            "RG_TRIAGE_MISSING", str(path),
            "the identity triage is required; an artefact with no certifiable identity cannot support a "
            "current claim, so an absent triage is a refusal rather than a skip",
        )]
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, [Refusal("RG_TRIAGE_MISSING", str(path), f"the identity triage is unreadable: {exc}")]
    if not isinstance(document, dict) or document.get("schema") != TRIAGE_SCHEMA:
        return None, [Refusal("RG_TRIAGE_STALE", str(path), f"schema must be {TRIAGE_SCHEMA!r}")]
    try:
        binding = json.loads(registry.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, [Refusal("RG_TRIAGE_STALE", str(path), f"the dependency registry is unreadable: {exc}")]
    if document.get("registry_recorded_at_commit") != binding.get("recorded_at_commit"):
        return None, [Refusal(
            "RG_TRIAGE_STALE", str(path),
            f"the triage binds registry {document.get('registry_recorded_at_commit')!r}; the committed "
            f"registry records {binding.get('recorded_at_commit')!r}",
        )]
    records = document.get("artefacts")
    if not isinstance(records, list) or not records:
        return None, [Refusal("RG_TRIAGE_STALE", str(path), "the triage records no artefact")]
    index: dict[str, dict] = {}
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return None, [Refusal("RG_TRIAGE_STALE", str(path), "a triage record names no path")]
        if item.get("path") in index:
            return None, [Refusal("RG_TRIAGE_STALE", str(path), f"{item['path']} is triaged twice")]
        if item.get("class") not in TRIAGE_CLASSES:
            return None, [Refusal(
                "RG_TRIAGE_STALE", str(path),
                f"{item['path']}: class {item.get('class')!r} is not one of {list(TRIAGE_CLASSES)}",
            )]
        index[item["path"]] = item
    counts = document.get("counts") or {}
    for name in TRIAGE_CLASSES:
        actual = sum(1 for item in records if item.get("class") == name)
        if counts.get(name) != actual:
            return None, [Refusal(
                "RG_TRIAGE_STALE", str(path),
                f"counts.{name} records {counts.get(name)!r}; the records give {actual}",
            )]
    return index, []


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


# The package manifest locations: a built ETP-6 archive places `MANIFEST.json`
# at its root; this repository keeps the same document under evidence/etp6/
# until a package is built, so both are read.
PACKAGE_MANIFESTS = ("MANIFEST.json", "evidence/etp6/MANIFEST.json")


def _load_package_manifest(package_root: Path) -> tuple[dict | None, str | None]:
    """The package manifest and the relative path it was read from."""
    for relative in PACKAGE_MANIFESTS:
        path = package_root / relative
        if not path.is_file():
            continue
        try:
            return json.loads(path.read_text(encoding="utf-8")), relative
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None, relative
    return None, None


def check_package(
    package: Path | None,
    candidate: str | None,
    candidate_tree: str | None = None,
    supersedes: str | None = None,
    timeout: int = 5400,
) -> Results:
    """Verify the package and bind its recorded candidate to the gate's.

    `candidate` is the commit `resolve_candidate` produced, and `candidate_tree`
    its tree.  A package that records another commit or tree is refused as
    `RG_PACKAGE_CANDIDATE_MISMATCH` naming both identities.  `supersedes` is an
    explicitly resolved commit the operator has declared the package was built
    for; the acceptance is recorded, never inferred.
    """
    refusals: list[Refusal] = []
    recorded: list[str] = []
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

        manifest, manifest_path = _load_package_manifest(package_root)
        if manifest_path is None:
            refusals.append(Refusal(
                "RG_PACKAGE_MANIFEST_ABSENT", str(package),
                "the package root holds no MANIFEST.json (or evidence/etp6/MANIFEST.json), "
                "so the package's candidate identity cannot be read",
            ))
        elif manifest is None:
            refusals.append(Refusal(
                "RG_PACKAGE_MANIFEST_INVALID", str(package),
                f"{manifest_path} does not parse as JSON, so the package's candidate "
                "identity cannot be read",
            ))
        else:
            identity = manifest.get("candidate") if isinstance(manifest, dict) else None
            package_commit = identity.get("commit") if isinstance(identity, dict) else None
            package_tree = identity.get("tree") if isinstance(identity, dict) else None
            if not isinstance(package_commit, str) or not package_commit:
                refusals.append(Refusal(
                    "RG_PACKAGE_MANIFEST_INVALID", str(package),
                    f"{manifest_path} records no candidate.commit",
                ))
            elif not isinstance(candidate, str) or not candidate:
                refusals.append(Refusal(
                    "RG_PACKAGE_CANDIDATE_MISMATCH", package_commit,
                    f"the package was built for {package_commit}, but the gate resolved "
                    "no candidate to compare it with",
                ))
            elif package_commit != candidate:
                if supersedes is not None and supersedes == package_commit:
                    recorded.append(
                        f"package {package}: candidate {package_commit} accepted as an "
                        f"explicit supersession of the gate candidate {candidate}"
                    )
                else:
                    refusals.append(Refusal(
                        "RG_PACKAGE_CANDIDATE_MISMATCH", package_commit,
                        f"the package was built for {package_commit}, but the gate is "
                        f"gating {candidate}; a package for another commit cannot "
                        "evidence this release (an explicit --package-supersedes is "
                        "the only admitted exception)",
                    ))
            else:
                recorded.append(
                    f"package {package}: candidate {package_commit} matches the gate candidate"
                )
                if (
                    isinstance(package_tree, str) and package_tree
                    and isinstance(candidate_tree, str) and candidate_tree
                    and package_tree != candidate_tree
                ):
                    refusals.append(Refusal(
                        "RG_PACKAGE_CANDIDATE_MISMATCH", package_tree,
                        f"the package records tree {package_tree}, but candidate "
                        f"{candidate} has tree {candidate_tree}",
                    ))

        runner = _package_runner(package_root)
        if runner is None:
            refusals.append(Refusal(
                "RG_PACKAGE_INVALID", str(package),
                "no verify.sh and no forensics/tools/etp6_verify.py at the package root",
            ))
            return Results(refusals, recorded)
        run = _run(runner, package_root, timeout)
        if run.returncode == 0:
            result = [line for line in run.stdout.splitlines() if line.strip().startswith("RESULT:")]
            recorded.append(f"package {package}: {result[-1] if result else 'verifier exited 0'}")
            return Results(refusals, recorded)
        problems = _bounded([
            line for line in (run.stdout + "\n" + run.stderr).splitlines()
            if line.strip() and ("FAIL" in line or "REFUSED" in line or "RESULT:" in line
                                 or "missing" in line.lower())
        ])
        if not problems:
            problems = [f"verifier exited {run.returncode} with no diagnostic"]
        refusals.extend(Refusal("RG_PACKAGE", str(package), p) for p in problems)
        return Results(refusals, recorded)
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
# 7. Role authorisation
# ---------------------------------------------------------------------------
def check_authorisation(
    root: Path,
    authorisations: Path | None = None,
    assignments: Path | None = None,
    timeout: int = 600,
    command: list[str] | None = None,
    at: str | None = None,
) -> Results:
    """The `release` action must be authorisation, not merely signed.

    The check runs the A14 decision procedure live rather than trusting a
    recorded verdict, and it joins the gate as one refusal row.  A refused or
    not-run decision is `RG_AUTHORISATION_REFUSED`; an absent tool, record or
    role document is a refusal with its own rule, because a missing role check
    must never read as permission.
    """
    record = Path(authorisations).resolve() if authorisations else AUTHORISATION_RECORD
    roles = Path(assignments).resolve() if assignments else AUTHORISATION_ROLES
    if command is None:
        if not AUTHORISATION_TOOL.is_file():
            return Results([_missing_tool("RG_AUTHORISATION_TOOL_MISSING", AUTHORISATION_TOOL)], [])
        if not record.is_file():
            return Results([Refusal(
                "RG_AUTHORISATION_MISSING", str(record),
                "no A14 authorisation record; an absent role check is a refusal, not a skip",
            )], [])
        if not roles.is_file():
            return Results([Refusal(
                "RG_AUTHORISATION_ROLES_MISSING", str(roles),
                "no A14 role record; an absent role check is a refusal, not a skip",
            )], [])
        command = [
            PYTHON, str(AUTHORISATION_TOOL), "authorise", "release",
            "--authorisations", str(record), "--assignments", str(roles), "--json",
        ]
        if at is not None:
            command.extend(["--at", at])
    run = _run(command, root, timeout)
    payload = None
    if run.stdout.strip():
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            payload = None
    if not isinstance(payload, dict) or "outcome" not in payload:
        detail = _bounded((run.stderr or run.stdout).splitlines())
        return Results([Refusal(
            "RG_AUTHORISATION_ERROR", "a14/release",
            detail[-1] if detail else f"authorisation checker exited {run.returncode} with no decision",
        )], [])
    outcome = str(payload.get("outcome", "UNKNOWN"))
    codes = ",".join(payload.get("codes") or []) or "NONE"
    face = payload.get("faceValue") or {}
    face_codes = ",".join(face.get("codes") or []) or "NONE"
    if outcome == "AUTHORISED" and run.returncode == 0:
        return Results([], [f"release authorisation AUTHORISED (codes NONE; face-value codes {face_codes})"])
    if outcome in {"REFUSED", "NOT_RUN"}:
        return Results([Refusal(
            "RG_AUTHORISATION_REFUSED", "a14/release",
            f"outcome={outcome} codes={codes}; face-value codes={face_codes}",
        )], [])
    return Results([Refusal(
        "RG_AUTHORISATION_ERROR", "a14/release",
        f"authorisation checker returned outcome {outcome!r} with exit {run.returncode}",
    )], [])


# ---------------------------------------------------------------------------
# 8. Trust-domain thresholds
# ---------------------------------------------------------------------------
def check_thresholds(
    root: Path,
    declarations: Path | None = None,
    approvals: Path | None = None,
    domains: Path | None = None,
    roles: Path | None = None,
    threshold: str = "release",
    timeout: int = 600,
    command: list[str] | None = None,
    at: str | None = None,
) -> Results:
    """The `release` threshold must be MET over distinct established domains.

    The check runs the A15 decision procedure live rather than trusting a
    recorded verdict.  A threshold that is not `MET` is one refusal row,
    ``RG_THRESHOLD_UNMET``; an absent tool or record is a refusal with its own
    rule, because a missing threshold check must never read as permission.
    """
    declaration = Path(declarations).resolve() if declarations else THRESHOLD_DECLARATIONS
    approvals_path = Path(approvals).resolve() if approvals else THRESHOLD_APPROVALS
    domains_path = Path(domains).resolve() if domains else THRESHOLD_DOMAINS
    roles_path = Path(roles).resolve() if roles else AUTHORISATION_ROLES
    if command is None:
        if not THRESHOLD_TOOL.is_file():
            return Results([_missing_tool("RG_THRESHOLD_TOOL_MISSING", THRESHOLD_TOOL)], [])
        for label, path in (
            ("declaration", declaration),
            ("approvals", approvals_path),
            ("domains", domains_path),
        ):
            if not path.is_file():
                return Results([Refusal(
                    "RG_THRESHOLD_MISSING", str(path),
                    f"no A15 {label} record; an absent threshold check is a "
                    "refusal, not a skip",
                )], [])
        if not roles_path.is_file():
            return Results([Refusal(
                "RG_THRESHOLD_ROLES_MISSING", str(roles_path),
                "no A14 role record; the threshold role check is a refusal, not a skip",
            )], [])
        command = [
            PYTHON, str(THRESHOLD_TOOL), "evaluate", threshold,
            "--thresholds", str(declaration), "--approvals", str(approvals_path),
            "--domains", str(domains_path), "--roles", str(roles_path), "--json",
        ]
        if at is not None:
            command.extend(["--at", at])
    run = _run(command, root, timeout)
    payload = None
    if run.stdout.strip():
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            payload = None
    if not isinstance(payload, dict) or "outcome" not in payload:
        detail = _bounded((run.stderr or run.stdout).splitlines())
        return Results([Refusal(
            "RG_THRESHOLD_ERROR", f"a15/{threshold}",
            detail[-1] if detail else f"threshold checker exited {run.returncode} with no decision",
        )], [])
    outcome = str(payload.get("outcome", "UNKNOWN"))
    codes = ",".join(payload.get("codes") or []) or "NONE"
    distinct = payload.get("distinctDomains", 0)
    available = payload.get("availableDomains", 0)
    k = (payload.get("threshold") or {}).get("k")
    if outcome == "MET" and run.returncode == 0:
        return Results([], [
            f"{threshold} threshold MET (k={k} distinctDomains={distinct} codes {codes})"
        ])
    if outcome in {"UNMET", "UNREACHABLE", "NOT_RUN"}:
        return Results([Refusal(
            "RG_THRESHOLD_UNMET", f"a15/{threshold}",
            f"outcome={outcome} codes={codes} distinctDomains={distinct} "
            f"availableDomains={available}",
        )], [])
    return Results([Refusal(
        "RG_THRESHOLD_ERROR", f"a15/{threshold}",
        f"threshold checker returned outcome {outcome!r} with exit {run.returncode}",
    )], [])


# ---------------------------------------------------------------------------
# 9. Release policy (A20)
# ---------------------------------------------------------------------------
def check_policy(
    root: Path,
    policy: Path | None = None,
    pin: Path | None = None,
    timeout: int = 600,
    command: list[str] | None = None,
) -> Results:
    """The pinned policy must be admitted by a conjunction of obligations.

    The check runs the A20 engine live rather than trusting a recorded decision.
    A `DENY` decision is one refusal row, ``RG_POLICY_DENIED``, carrying the
    unmet obligations and every refusal code, because a decision that lists what
    failed is the whole point of a conjunctive policy; an absent tool, policy or
    pin is a refusal with its own rule, never a skip.
    """
    record = Path(policy).resolve() if policy else POLICY_RECORD
    pin_path = Path(pin).resolve() if pin else POLICY_PIN
    if command is None:
        if not POLICY_TOOL.is_file():
            return Results([_missing_tool("RG_POLICY_TOOL_MISSING", POLICY_TOOL)], [])
        for label, path in (("policy", record), ("pin", pin_path)):
            if not path.is_file():
                return Results([Refusal(
                    "RG_POLICY_MISSING", str(path),
                    f"no A20 {label} record; an absent policy is a refusal, not a skip",
                )], [])
        command = [
            PYTHON, str(POLICY_TOOL), "evaluate",
            "--policy", str(record), "--pin", str(pin_path), "--json",
        ]
    run = _run(command, root, timeout)
    payload = None
    if run.stdout.strip():
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            payload = None
    if not isinstance(payload, dict) or "decision" not in payload:
        detail = _bounded((run.stderr or run.stdout).splitlines())
        return Results([Refusal(
            "RG_POLICY_ERROR", "a20/release",
            detail[-1] if detail else f"policy engine exited {run.returncode} with no decision",
        )], [])
    decision = str(payload.get("decision", "UNKNOWN"))
    unmet = ",".join(payload.get("unmet") or []) or "NONE"
    codes = ",".join(payload.get("codes") or []) or "NONE"
    if decision == "ADMIT" and run.returncode == 0:
        return Results([], [
            f"release policy ADMIT ({payload.get('obligationCount')} obligation(s), codes {codes})"
        ])
    if decision == "DENY":
        return Results([Refusal(
            "RG_POLICY_DENIED", "a20/release",
            f"decision=DENY unmet={unmet} codes={codes}",
        )], [])
    return Results([Refusal(
        "RG_POLICY_ERROR", "a20/release",
        f"policy engine returned decision {decision!r} with exit {run.returncode}",
    )], [])


# ---------------------------------------------------------------------------
# 10. Transparency enforcement (B8)
# ---------------------------------------------------------------------------
def check_transparency(
    root: Path,
    registry: Path | None = None,
    publication: Path | None = None,
    claims: Path | None = None,
    schema: Path | None = None,
    nonclaims: Path | None = None,
    gate: Path | None = None,
    enforcement: Path | None = None,
    document: Path | None = None,
    timeout: int = 300,
    command: list[str] | None = None,
) -> Results:
    """The admitted transparency profile must still be enforced.

    The check runs ``continuous_enforcement.py`` live.  Its refusals already
    carry stable ``CE_REFUSED_*`` codes, so each one is one gate refusal row
    naming the artefact; the gate adds only the two rules for the tool itself
    (absent and unparseable).  An absent enforcement record, a removed gate item
    and a non-claims document that stopped naming an unestablished property are
    therefore release refusals, not documentation drift.
    """
    if command is None:
        if not TRANSPARENCY_TOOL.is_file():
            return Results([_missing_tool("RG_TRANSPARENCY_TOOL_MISSING", TRANSPARENCY_TOOL)], [])
        command = [
            PYTHON, str(TRANSPARENCY_TOOL), "check", "--json",
            "--registry", str(registry or TRANSPARENCY_REGISTRY),
            "--publication", str(publication or TRANSPARENCY_PUBLICATION),
            "--claims", str(claims or TRANSPARENCY_CLAIMS),
            "--schema", str(schema or TRANSPARENCY_SCHEMA),
            "--nonclaims", str(nonclaims or TRANSPARENCY_NONCLAIMS),
            "--gate", str(gate or TRANSPARENCY_GATE),
            "--enforcement", str(enforcement or TRANSPARENCY_ENFORCEMENT),
            "--document", str(document or TRANSPARENCY_DOCUMENT),
        ]
    run = _run(command, root, timeout)
    payload = None
    if run.stdout.strip():
        try:
            payload = json.loads(run.stdout)
        except json.JSONDecodeError:
            payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("refusals"), list):
        detail = _bounded((run.stderr or run.stdout).splitlines())
        return Results([Refusal(
            "RG_TRANSPARENCY_ERROR", "b8/enforcement",
            detail[-1] if detail else f"transparency checker exited {run.returncode} with no decision",
        )], [])
    refusals = [
        Refusal(
            str(row.get("code", "CE_REFUSED_USAGE")),
            str(row.get("artefact", "-")),
            str(row.get("detail", "-")),
        )
        for row in payload["refusals"]
        if isinstance(row, dict)
    ]
    population = payload.get("population") if isinstance(payload.get("population"), dict) else {}
    recorded = []
    if not refusals:
        recorded.append(
            "transparency enforcement: "
            f"{population.get('claimCount', 0)} claim(s) checked, "
            f"{population.get('claimsWithTransparency', 0)} carry a transparency field, "
            "no refusal"
        )
    return Results(refusals, recorded)


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
    registry = Path(args.dependency_registry).resolve() if args.dependency_registry else DEPENDENCY_REGISTRY
    triage_path = Path(args.triage).resolve() if args.triage else IDENTITY_TRIAGE
    triage_index, triage_refusals = load_triage(triage_path, registry)
    refusals.extend(triage_refusals)
    if triage_index is not None:
        counts = {name: sum(1 for item in triage_index.values() if item.get("class") == name)
                  for name in TRIAGE_CLASSES}
        recorded.append(
            f"identity triage {triage_path.name}: "
            + ", ".join(f"{counts[name]} {name}" for name in TRIAGE_CLASSES)
            + f"; {counts['UNCERTIFIABLE']} artefact(s) cannot support a claim"
        )
    result = check_claims(root, claims, schema, args.graduation, triage=triage_index)
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

    supersedes: str | None = None
    if args.package_supersedes:
        supersedes, detail = resolve_commit(root, args.package_supersedes)
        if supersedes is None:
            refusals.append(Refusal(
                "RG_PACKAGE_SUPERSESSION_UNRESOLVED", args.package_supersedes, detail
            ))
    candidate_tree = resolve_tree(root, candidate) if candidate else None
    result = check_package(
        Path(args.package).resolve() if args.package else None,
        candidate,
        candidate_tree,
        supersedes,
    )
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_docs(root)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_authorisation(
        root,
        Path(args.authorisations).resolve() if getattr(args, "authorisations", None) else None,
        Path(args.assignments).resolve() if getattr(args, "assignments", None) else None,
    )
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_thresholds(
        root,
        Path(args.threshold_declarations).resolve()
        if getattr(args, "threshold_declarations", None) else None,
        Path(args.threshold_approvals).resolve()
        if getattr(args, "threshold_approvals", None) else None,
        Path(args.threshold_domains).resolve()
        if getattr(args, "threshold_domains", None) else None,
    )
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_policy(
        root,
        Path(args.policy_record).resolve() if getattr(args, "policy_record", None) else None,
        Path(args.policy_pin).resolve() if getattr(args, "policy_pin", None) else None,
    )
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    result = check_transparency(root)
    refusals.extend(result.refusals)
    recorded.extend(result.recorded)

    return Results(refusals, recorded)


def self_test() -> int:
    """Prove the gate refuses each named failure class.

    The fixtures are constructed in a temporary directory from the committed
    claim document, so the test does not depend on the current verdicts being
    either green or red.  The identity-triage controls use a three-record fixture
    triage, so the uncertifiable and historical rules are proven without
    depending on the committed classes.  Receipt, instrumentation and package
    controls call the real checkers; the documentation control drives the gate's
    adapter with a checker that reports a stale claim, because
    `docs_consistency.py` binds its repository root at import and cannot be
    pointed at a fixture tree.  The real documentation checker is also run as a
    positive control, which is what shows the adapter is connected to it.
    """
    failures: list[str] = []
    cases: list[tuple[str, str]] = []

    def expect(name: str, results: Results, rule: str) -> None:
        hit = any(r.rule == rule for r in results.refusals)
        cases.append((name, rule))
        if not hit:
            failures.append(f"{name}: expected {rule}, got {[r.rule for r in results.refusals]}")

    def expect_detail(name: str, results: Results, rule: str, needle: str) -> None:
        hit = any(r.rule == rule and needle in r.detail for r in results.refusals)
        cases.append((name, f"{rule} naming {needle}"))
        if not hit:
            failures.append(
                f"{name}: expected {rule} naming {needle}, got "
                f"{[(r.rule, r.detail[:80]) for r in results.refusals]}"
            )

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

        # The repaired record is accepted, and a SAFE_COMPATIBLE assertion over the
        # same b85c record is still refused by the algebra.  This is the
        # two-direction control ETP-T15 requires: accepting a RISK_ACCEPTED record
        # is not accepting a SAFE_COMPATIBLE one.
        repaired = json.loads(json.dumps(document))
        repaired_claim = next(
            claim for claim in repaired["claims"]
            if claim["id"] == "ETP0-CLM-030"
        )
        repaired_path = tmp / "claims-repaired.json"
        repaired_path.write_text(json.dumps(repaired), encoding="utf-8")
        repaired_results = check_claims(ROOT, repaired_path, CLAIM_SCHEMA, False)
        cases.append(("repaired risk-accepted claim (positive control)", "no claim refusal"))
        if any(r.rule.startswith("RG_CLAIM_") for r in repaired_results.refusals):
            failures.append(
                "repaired risk-accepted claim (positive control): unexpected claim refusals "
                f"{[r.rule for r in repaired_results.refusals]}"
            )
        promoted = json.loads(json.dumps(document))
        promoted_claim = next(
            claim for claim in promoted["claims"]
            if claim["id"] == "ETP0-CLM-030"
        )
        promoted_claim["verdict"] = {
            "state": "SAFE_COMPATIBLE",
            "basis": "self-test fixture: assert the withdrawn graduation as a graduated property",
        }
        promoted_claim.pop("reconciliation", None)
        promoted_claim["closure"] = {
            "dependencies": ["evidence/closure-ssh-b85c.json"],
            "unresolved_dependencies": ["closure-ssh-b85c: verdict.safe_compatible=false"],
            "complete": False,
        }
        promoted_path = tmp / "claims-promoted.json"
        promoted_path.write_text(json.dumps(promoted), encoding="utf-8")
        expect_detail(
            "safe-compatible assertion over the withdrawn graduation",
            check_claims(ROOT, promoted_path, CLAIM_SCHEMA, False),
            "RG_CLAIMS_INVALID",
            "EG_GRADUATED_WITH_OPEN_OBLIGATION",
        )

        # A claim that is derived from a CONTRADICTED ETP-0 verdict may not be
        # promoted; only a bound ETP-T15 reconciliation to RISK_ACCEPTED or
        # SUPERSEDED is admitted, and the positive direction is refused.
        promoted_with_reconciliation = json.loads(json.dumps(document))
        promoted_claim = next(
            claim for claim in promoted_with_reconciliation["claims"]
            if claim["id"] == "ETP0-CLM-030"
        )
        promoted_claim["verdict"] = {
            "state": "SAFE_COMPATIBLE",
            "basis": "self-test fixture: reconciliation used to raise a contradiction",
        }
        promoted_claim["closure"] = {
            "dependencies": ["evidence/closure-ssh-b85c.json"],
            "unresolved_dependencies": [],
            "complete": True,
        }
        promoted_recon_path = tmp / "claims-promoted-reconciliation.json"
        promoted_recon_path.write_text(
            json.dumps(promoted_with_reconciliation), encoding="utf-8"
        )
        expect_detail(
            "reconciliation used as a promotion",
            check_claims(ROOT, promoted_recon_path, CLAIM_SCHEMA, False),
            "RG_CLAIMS_INVALID",
            "EG_RECONCILIATION_PROMOTION",
        )
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

        # The identity triage: an uncertifiable dependency refuses, a historical
        # dependency refuses with its own rule, and a derived dependency is the
        # positive control that neither rule fires without cause.
        triage_document = {
            "schema": TRIAGE_SCHEMA,
            "registry_recorded_at_commit": "fixture",
            "counts": {"DERIVED": 1, "DECLARED": 0, "HISTORICAL": 1, "UNCERTIFIABLE": 1, "total": 3},
            "artefacts": [
                {"path": "docs/NON_CLAIMS.md", "class": "UNCERTIFIABLE", "cause": "U1",
                 "cause_name": "multi-commit-no-declaration", "reason": "self-test fixture"},
                {"path": "docs/RELEASE_GATES.md", "class": "HISTORICAL",
                 "rule": "introduced-at-single-commit", "identity": {"commit": "0" * 40}},
                {"path": "evidence/fixture-derived.json", "class": "DERIVED",
                 "rule": "tracked-input-at-head", "identity": {"commit": "0" * 40}},
            ],
        }
        triage_index = {item["path"]: item for item in triage_document["artefacts"]}

        def triage_claim(path: str) -> dict:
            return {
                "claims": [
                    {
                        "id": "SELFTEST-TRIAGE",
                        "verdict": {"state": "PARTIAL"},
                        "evidence": [{"id": "EV-1", "path": path}],
                    }
                ]
            }

        expect(
            "uncertifiable dependency",
            Results(*scan_claims(triage_claim("docs/NON_CLAIMS.md"), False, triage_index)),
            "RG_CLAIM_UNCERTIFIABLE_EVIDENCE",
        )
        expect(
            "historical dependency",
            Results(*scan_claims(triage_claim("docs/RELEASE_GATES.md"), False, triage_index)),
            "RG_CLAIM_HISTORICAL_EVIDENCE",
        )
        derived = scan_claims(triage_claim("evidence/fixture-derived.json"), False, triage_index)
        cases.append(("derived dependency (positive control)", "no refusal"))
        if derived[0]:
            failures.append(
                "derived dependency (positive control): unexpected refusals "
                f"{[item.rule for item in derived[0]]}"
            )

        def triage_results(path: Path) -> Results:
            _, refusals = load_triage(path, DEPENDENCY_REGISTRY)
            return Results(refusals, [])

        expect("missing identity triage", triage_results(tmp / "absent-triage.json"), "RG_TRIAGE_MISSING")
        stale_triage = tmp / "stale-triage.json"
        stale_triage.write_text(json.dumps(triage_document), encoding="utf-8")
        expect("stale identity triage", triage_results(stale_triage), "RG_TRIAGE_STALE")

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

        # Packages: absence, verifier outcome, and the package-to-candidate
        # binding. The two positive controls show the comparison is connected:
        # the same package passes when it matches, and passes when the operator
        # declares an explicit supersession.
        gate_candidate = "1" * 40
        gate_tree = "2" * 40
        other_candidate = "3" * 40
        other_tree = "4" * 40
        passing = "#!/bin/sh\necho 'RESULT: PASS (1/1 required steps PASS)'\nexit 0\n"
        failing = "#!/bin/sh\necho '[1/1] digests FAIL (required) fixture failure'\nexit 1\n"

        def package_at(name: str, commit: str, tree: str, verifier: str) -> Path:
            root = tmp / name
            root.mkdir()
            (root / "MANIFEST.json").write_text(
                json.dumps({
                    "schema": "openssl-rs/etp6/package-manifest/1",
                    "candidate": {"commit": commit, "tree": tree},
                }),
                encoding="utf-8",
            )
            (root / "verify.sh").write_text(verifier, encoding="utf-8")
            return root

        expect("missing package", check_package(None, gate_candidate), "RG_PACKAGE_MISSING")

        expect(
            "failing package verifier",
            check_package(
                package_at("package-failing", gate_candidate, gate_tree, failing),
                gate_candidate,
                gate_tree,
            ),
            "RG_PACKAGE",
        )

        expect_detail(
            "package for another candidate",
            check_package(
                package_at("package-other", other_candidate, other_tree, passing),
                gate_candidate,
                gate_tree,
            ),
            "RG_PACKAGE_CANDIDATE_MISMATCH",
            other_candidate,
        )

        expect_detail(
            "package for another tree",
            check_package(
                package_at("package-other-tree", gate_candidate, other_tree, passing),
                gate_candidate,
                gate_tree,
            ),
            "RG_PACKAGE_CANDIDATE_MISMATCH",
            other_tree,
        )

        package_no_manifest = tmp / "package-no-manifest"
        package_no_manifest.mkdir()
        (package_no_manifest / "verify.sh").write_text(passing, encoding="utf-8")
        expect(
            "package without a manifest",
            check_package(package_no_manifest, gate_candidate, gate_tree),
            "RG_PACKAGE_MANIFEST_ABSENT",
        )

        matching = check_package(
            package_at("package-matching", gate_candidate, gate_tree, passing),
            gate_candidate,
            gate_tree,
        )
        cases.append(("matching package candidate (positive control)", "no refusal"))
        if matching.refusals:
            failures.append(
                "matching package candidate (positive control): unexpected refusals "
                f"{[item.rule for item in matching.refusals]}"
            )

        superseded = check_package(
            package_at("package-superseded", other_candidate, other_tree, passing),
            gate_candidate,
            gate_tree,
            other_candidate,
        )
        cases.append(("explicit package supersession (positive control)", "no refusal"))
        if superseded.refusals:
            failures.append(
                "explicit package supersession (positive control): unexpected refusals "
                f"{[item.rule for item in superseded.refusals]}"
            )

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

        # A15: an unmet threshold refuses, a MET threshold is recorded, an
        # unparseable result is an error and an absent record is not a skip.
        unmet_shim = (
            "import json,sys;"
            "print(json.dumps({'outcome':'UNREACHABLE',"
            "'codes':['TH_REFUSED_THRESHOLD_UNREACHABLE'],"
            "'distinctDomains':0,'availableDomains':0,'threshold':{'k':2}}));"
            "sys.exit(1)"
        )
        expect(
            "unmet threshold",
            check_thresholds(ROOT, command=[PYTHON, "-c", unmet_shim]),
            "RG_THRESHOLD_UNMET",
        )
        met_shim = (
            "import json,sys;"
            "print(json.dumps({'outcome':'MET','codes':[],"
            "'distinctDomains':2,'availableDomains':2,'threshold':{'k':2}}));"
            "sys.exit(0)"
        )
        met = check_thresholds(ROOT, command=[PYTHON, "-c", met_shim])
        cases.append(("met threshold (positive control)", "no refusal"))
        if met.refusals:
            failures.append(
                "met threshold (positive control): unexpected refusals "
                f"{[item.rule for item in met.refusals]}"
            )
        expect(
            "unparseable threshold evaluation",
            check_thresholds(ROOT, command=[PYTHON, "-c", "print('not json')"]),
            "RG_THRESHOLD_ERROR",
        )
        expect(
            "missing threshold record",
            check_thresholds(ROOT, declarations=tmp / "absent-threshold.json"),
            "RG_THRESHOLD_MISSING",
        )

        # A20: a denied policy refuses and names the unmet obligations; an
        # admitted policy is recorded; an unparseable result is an error and an
        # absent record is not a skip.
        denied_shim = (
            "import json,sys;"
            "print(json.dumps({'decision':'DENY','unmet':['A12.fixture'],"
            "'codes':[],'obligationCount':1,'requiredCount':1}));"
            "sys.exit(1)"
        )
        expect_detail(
            "denied policy",
            check_policy(ROOT, command=[PYTHON, "-c", denied_shim]),
            "RG_POLICY_DENIED",
            "A12.fixture",
        )
        admit_shim = (
            "import json,sys;"
            "print(json.dumps({'decision':'ADMIT','unmet':[],"
            "'codes':[],'obligationCount':1,'requiredCount':1}));"
            "sys.exit(0)"
        )
        admitted = check_policy(ROOT, command=[PYTHON, "-c", admit_shim])
        cases.append(("admitted policy (positive control)", "no refusal"))
        if admitted.refusals:
            failures.append(
                "admitted policy (positive control): unexpected refusals "
                f"{[item.rule for item in admitted.refusals]}"
            )
        expect(
            "unparseable policy decision",
            check_policy(ROOT, command=[PYTHON, "-c", "print('not json')"]),
            "RG_POLICY_ERROR",
        )
        expect(
            "missing policy record",
            check_policy(ROOT, policy=tmp / "absent-policy.json"),
            "RG_POLICY_MISSING",
        )

        # B8: the transparency item runs the real checker. One case proves it
        # refuses an assertion the B4 record contradicts; the positive control
        # proves it does not refuse an honest NOT_ADMITTED record. The other
        # rules are exercised one per code in test_continuous_enforcement.py.
        digest = "a" * 64

        def transparency_claim(state: str, **extra: object) -> dict:
            block: dict = {"state": state}
            block.update(extra)
            return {
                "claims": [
                    {
                        "id": "B8-SELFTEST",
                        "authority": {"kind": "repository-policy"},
                        "transparency": block,
                    }
                ]
            }

        published_claim = tmp / "claims-transparency-published.json"
        published_claim.write_text(json.dumps(transparency_claim(
            "PUBLISHED",
            profile="public-good-rekor-v2",
            statementDigest=digest,
            bundleDigest=digest,
            publishedAt="2026-11-24T00:00:00Z",
        )), encoding="utf-8")
        expect(
            "transparency publication claim",
            check_transparency(ROOT, claims=published_claim),
            "CE_REFUSED_PUBLICATION_CLAIM",
        )

        honest_claim = tmp / "claims-transparency-not-admitted.json"
        honest_claim.write_text(json.dumps(transparency_claim(
            "NOT_ADMITTED", profile="public-good-rekor-v2"
        )), encoding="utf-8")
        honest_results = check_transparency(ROOT, claims=honest_claim)
        cases.append(("honest not-admitted transparency claim (positive control)", "no refusal"))
        if honest_results.refusals:
            failures.append(
                "honest not-admitted transparency claim (positive control): "
                f"unexpected refusals {[item.rule for item in honest_results.refusals]}"
            )

        expect(
            "missing transparency registry",
            check_transparency(ROOT, registry=tmp / "absent-registry.json"),
            "CE_REFUSED_PROFILE_ABSENT",
        )
        expect(
            "missing public non-claims",
            check_transparency(ROOT, nonclaims=tmp / "absent-non-claims.md"),
            "CE_REFUSED_NONCLAIMS_ABSENT",
        )
        removed_gate = tmp / "release-gate-without-item-10.py"
        removed_gate.write_text(
            Path(__file__).resolve().read_text(encoding="utf-8").replace(
                "def check_transparency(", "def transparency_removed("
            ),
            encoding="utf-8",
        )
        expect(
            "transparency enforcement regression",
            check_transparency(ROOT, gate=removed_gate),
            "CE_REFUSED_ENFORCEMENT_REGRESSION",
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
    parser.add_argument("--triage", default=None,
                        help="identity triage (default evidence/etp-t9/IDENTITY-TRIAGE.json)")
    parser.add_argument("--dependency-registry", default=None,
                        help="dependency registry the triage must bind (default evidence/etp-t9/DEPENDENCIES.json)")
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
    parser.add_argument("--package-supersedes", default=None,
                        help="explicitly accept a package built for REF rather than "
                             "--candidate; the resolved identity is recorded")
    parser.add_argument("--authorisations", default=None,
                        help="A14 authorisation record (default evidence/a14/AUTHORISATION.json)")
    parser.add_argument("--assignments", default=None,
                        help="A14 role record (default evidence/a14/ROLES.json)")
    parser.add_argument("--threshold-declarations", default=None,
                        help="A15 threshold declarations (default evidence/a15/THRESHOLDS.json)")
    parser.add_argument("--threshold-approvals", default=None,
                        help="A15 approvals (default evidence/a15/APPROVALS.json)")
    parser.add_argument("--threshold-domains", default=None,
                        help="A15 domain inventory (default evidence/a15/DOMAINS.json)")
    parser.add_argument("--policy-record", default=None,
                        help="A20 policy (default evidence/a20/POLICY.json)")
    parser.add_argument("--policy-pin", default=None,
                        help="A20 policy pin (default evidence/a20/POLICY-PIN.json)")
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
            print("release-gate: PASS (candidate, claims, receipts, instruments, "
                  "package, docs, authorisation, thresholds, policy, transparency)")

    return EXIT_REFUSED if results.refused() else EXIT_PASS


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
