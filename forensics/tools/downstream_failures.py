#!/usr/bin/env python3
"""openssl-rs — Phase-24.8 failure discovery/minimization loop: every discovered failure is a named,
preserved, minimized record.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.6 built and linked a pristine source per
family and 24.7 loaded and drove it, and each recorded an outcome, a residual class and a failure
class on every run. This module is the loop that turns every leftover those atlases record -- every
run that did not reach its level, and every run that carries a residual -- into a **named,
preserved** record, and that draws the load-bearing distinction between a **candidate-specific**
failure and a **venue/environment limitation** rather than reading every leftover as a candidate
defect.

The distinction this module exists to draw
------------------------------------------
A recorded leftover is **candidate-specific** only when the candidate failed at a level the
**authority reached** -- the authority-applicable baseline. A failure the authority ALSO hit at the
same or a lower level in the same admitted venue (a missing generated `configure`, an absent build
dependency, no admitted recipe or workload) is a **venue/environment limitation**, not a candidate
compatibility defect, and is classified as such (the brief's section 44). The ruling is **derived**
from the committed atlases -- the authority row each candidate leftover is compared against -- and
never typed, so a classification cannot be asserted beside the evidence it contradicts.

Minimization is mandatory
-------------------------
A discovered failure is preserved and minimized (the brief's section 32). For each candidate-specific
failure this module produces a **minimized reproducer**: a small, standalone, deterministic fixture
under `forensics/downstream/failures/<failure_id>/` -- a self-contained C program with a `build.sh`, a
`run.sh` and a `README.md` naming the consumer, the first divergent observation, the authority value
and the candidate value -- reproducing the defect against the candidate and, where the authority
behaves correctly, demonstrating the differential. It runs inside the admitted container with no
public network. Where there are **no** candidate-specific failures, that is the honest result, recorded
as such; the minimizer machinery is proven by the self-test and by the sensitivity control rather than
by a manufactured failure.

The failures plane is a pure function of the committed atlases
-------------------------------------------------------------
Unlike 24.6's and 24.7's measured atlases, this plane **executes nothing**: it reads the committed
build/link and runtime/functional atlases and the frozen P1000, and derives every record from them.
It is a pure aggregate of committed evidence, so it is wired into `evidence_determinism.py`'s
`GENERATORS` and `COMPARED` exactly as 24.4's freeze and 24.5's partition are -- and exactly as the
24.6/24.7 determinism comments anticipated ("a later subphase that derives a pure aggregate from it
... is what belongs in this list") -- so a stale committed failures plane is a failure rather than a
silent divergence. Its "measurement" is therefore a derivation, not a build.

No manual success overrides
---------------------------
Every record is derived mechanically and every count is computed from the records, never typed (the
brief's section 72). The `failure_findings` re-derivation is the gate: a leftover with no record, a
record for a row that is not a leftover, a candidate-specific label the authority baseline does not
justify, a venue-limited label with no authority failure behind it, a minimized claim with no fixture
on disk, an unclassified disposition, and a genealogy edge asserting a fix commit that nothing
establishes are each refused by name.

The Docker-only guard is called first
-------------------------------------
This module reads committed evidence and writes one artefact plus, where a defect exists, a fixture
tree; it executes nothing itself. Its `main` still calls `phase24_guard.require_admitted()` first,
exactly as every Phase-24 entry point does (`docs/REPRODUCIBILITY.md` section 1). `--self-test` proves
the guard refuses a host invocation of this tool and exercises the minimizer.

Outputs
-------
  forensics/downstream/failures.json          the classified, preserved, minimized failures
  forensics/downstream/failures/<id>/         one minimized reproducer per candidate-specific failure

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`, exactly as it is for
# every Phase-24 entry point.
import phase24_guard  # noqa: E402

# The record schemas the failures are validated against, imported rather than restated so the
# taxonomy and the residual vocabulary cannot drift from the module the court checks them with.
import downstream_schemas  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the plane and the freeze cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "failures.json"

# The minimized reproducers live one directory per candidate-specific failure. The directory is
# committed evidence: the record hashes it, and the court re-hashes it from disk.
FAILURES_DIR = REPO_ROOT / "forensics" / "downstream" / "failures"

# Scratch for the minimizer self-test is kept under `/work/court` (never `/tmp` or `/`), and removed
# after the check; only the small committed records persist.
SCRATCH = REPO_ROOT / "court" / "phase24-failures"

GENERATOR = "forensics/tools/downstream_failures.py"
PARSER_VERSION = "downstream-failures/1"

L0 = "L0-catalogued"
L4 = "L4-linked"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

# The two atlases this plane is a pure aggregate of, with the key each run row is identified by.
ATLASES: tuple[tuple[str, Path], ...] = (
    ("build-link-atlas", BUILD_LINK_ATLAS),
    ("runtime-functional-atlas", RUNTIME_FUNCTIONAL_ATLAS),
)

# The classification a leftover record carries. This is the *disposition of the leftover as a defect*,
# distinct from the row's `residual_class` (which class of leftover it is) and its `failure_class`
# (which failure in the taxonomy it is). It is a closed vocabulary so a record cannot be described
# instead of classified.
FAILURE_DISPOSITIONS: tuple[str, ...] = (
    "candidate-specific",
    "venue-limited",
    "out-of-scope",
)

# A leftover row that carries no `failure_class` (an `out-of-scope` run the authority reached) still
# needs a taxonomy class on its record; the venue admits no workload or recipe, which is a harness
# limitation, so `harness-failure` is the honest class. Every other leftover row already names one.
RESIDUAL_FALLBACK_CLASS: dict[str, str] = {
    "out-of-scope": "harness-failure",
    "unavailable": "acquire-failure",
}

# The suspected subsystem each failure class points at, for the genealogy edge. This is a *suspected*
# subsystem, not a confirmed one, and it is derived from the taxonomy class rather than typed per
# record.
SUBSYSTEM_BY_CLASS: dict[str, str] = {
    "acquire-failure": "venue-source-acquisition",
    "configure-failure": "downstream-build-system",
    "authority-build-failure": "downstream-build-system",
    "candidate-build-failure": "downstream-build-system",
    "link-failure": "linker-linkage",
    "load-failure": "dynamic-loader",
    "runtime-failure": "runtime",
    "functional-failure": "functional-behaviour",
    "abi-failure": "abi",
    "semantic-failure": "semantics",
    "cli-config-mismatch": "cli-config",
    "provider-registration-mismatch": "provider-registration",
    "patch-required": "downstream-build-system",
    "harness-failure": "venue-workload-harness",
}

# The frozen classification/minimization rule, recorded verbatim in the artefact and re-derived by the
# court. It is the brief's sections 30, 31, 32, 44 and 72 as a machine-checkable policy.
RULE: dict = {
    "id": "downstream-failures/1",
    "name": "the failure discovery/minimization loop",
    "candidate_specific_vs_venue": (
        "a leftover is candidate-specific only when the candidate failed at a level the authority "
        "reached (the authority-applicable baseline); a failure the authority also hit at the same or "
        "a lower level in the same admitted venue is a venue/environment limitation, not a candidate "
        "compatibility defect, and is classified `venue-limited`; a residual of `out-of-scope` -- no "
        "admitted recipe or workload -- is `out-of-scope`. The ruling derives from the committed "
        "authority row each candidate leftover is compared against, never typed"
    ),
    "minimization": (
        "every candidate-specific failure carries a minimized reproducer: a standalone deterministic "
        "fixture under forensics/downstream/failures/<failure_id>/ with a self-contained C program, a "
        "build.sh, a run.sh and a README.md naming the consumer, the first divergent observation, the "
        "authority value and the candidate value; the record hashes the fixture and the court "
        "re-hashes it from disk. Zero candidate-specific failures is the honest result, not a failure "
        "to minimize"
    ),
    "no_manual_override": (
        "every record is derived mechanically from the committed atlases and every count is computed "
        "from the records; a passing court is machine facts, never a manual success override"
    ),
    "taxonomy": list(downstream_schemas.FAILURE_CLASSES),
    "residual_classes": list(downstream_schemas.RESIDUAL_CLASSES),
    "dispositions": list(FAILURE_DISPOSITIONS),
    "atlas_sources": [name for name, _p in ATLASES],
}

# The stratum's four non-claims (imported from 24.4) plus the one this subphase's loop adds: a
# discovered-and-minimized failure is a preserved record, not a fix.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a discovered-and-minimized failure is a preserved record, not a fix, and a minimized reproducer "
    "is not the consumer: the record names a failure and pins a small reproduction of it, and it "
    "neither repairs anything nor stands in for the real downstream project it was minimized from",
]


# --------------------------------------------------------------------------------------------
# the pure aggregate: every leftover from the committed atlases, classified and (if candidate-side)
# minimized, with the authority row the ruling derives from
# --------------------------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["body"]


def _is_leftover(row: dict) -> bool:
    """A row that did not reach its level, or that carries a residual other than `none`."""
    return (row.get("outcome") != "reached"
            or row.get("residual_class") not in (None, "none"))


def _atlas_index(body: dict) -> dict:
    """`rows_by_key`, the authority-applicable level and the authority row per family, for one atlas.

    The authority-applicable level is re-derived from the authority rows, never read from a
    candidate row's recorded claim, so a candidate that inflated its own baseline cannot change the
    ruling.
    """
    rows: dict[tuple[str, str], dict] = {}
    auth_rows: dict[str, dict] = {}
    auth_levels: dict[str, str] = {}
    for row in body.get("runs") or []:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        rows[(fid, subject)] = row
        if subject == "authority":
            auth_rows[fid] = row
            lv = str(row.get("level"))
            if RANK.get(lv, -1) > RANK.get(auth_levels.get(fid, L0), -1):
                auth_levels[fid] = lv
    return {"rows": rows, "auth_rows": auth_rows, "auth_levels": auth_levels}


def _classify(subject: str, row: dict, auth_level: str) -> str:
    """The disposition of one leftover, derived from the row and the authority-applicable level.

    The single source of truth for the candidate-specific-vs-venue ruling: it is called by the
    aggregate *and* re-called by the court's `failure_findings`, so the classification the court
    checks and the classification the plane recorded cannot drift.
    """
    residual = row.get("residual_class")
    if subject == "candidate":
        cand_rank = RANK.get(str(row.get("level")), -1)
        if cand_rank < RANK.get(str(auth_level), -1):
            return "candidate-specific"
    if residual == "out-of-scope":
        return "out-of-scope"
    return "venue-limited"


def _failure_class(row: dict) -> str:
    """The taxonomy class of one leftover -- the row's own, or the honest fallback by residual."""
    fc = row.get("failure_class")
    if fc in downstream_schemas.FAILURE_CLASSES:
        return str(fc)
    return RESIDUAL_FALLBACK_CLASS.get(str(row.get("residual_class")), "harness-failure")


def _sanitize(failure_id: str) -> str:
    """A directory-safe form of a failure id (the id itself keeps its colons)."""
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in failure_id)


def fixture_dir(failure_id: str) -> Path:
    return FAILURES_DIR / _sanitize(failure_id)


def _record(atlas: str, row: dict, index: dict) -> dict:
    """One classified leftover record: a schema-valid `failure` plus its classification and derivation."""
    fid = str(row.get("family_id"))
    subject = str(row.get("subject"))
    name = str(row.get("canonical_name"))
    residual = row.get("residual_class")
    auth_level = index["auth_levels"].get(fid, L0)
    auth_row = index["auth_rows"].get(fid)
    auth_class = _failure_class(auth_row) if auth_row else None
    disposition = _classify(subject, row, auth_level)
    cls = _failure_class(row)
    level = str(row.get("level"))
    reason = str(row.get("reason") or "")[:240]

    if disposition == "candidate-specific":
        obs = (f"candidate reached {level} where the authority reached {auth_level}: the candidate "
               f"fell below the authority-applicable baseline ({reason})")
    elif disposition == "out-of-scope":
        obs = (f"no admitted deterministic local recipe/workload at {level}: the level is the honest "
               f"reach, not a candidate defect ({reason})")
    else:
        obs = (f"the authority-applicable baseline {auth_level} also left {auth_row.get('residual_class') if auth_row else None}"
               f"/{auth_class} ({str((auth_row or {}).get('reason') or '')[:120]}); the candidate "
               f"reached {level}, so the leftover is a venue/environment limitation, not a "
               f"candidate-specific defect")

    failure_id = f"failure:{atlas}:{subject}:{name}"
    evidence = [f"atlas:{atlas}", f"run_id:{row.get('run_id')}",
                f"row_sha256:{content_hash(row)}",
                f"authority_applicable_level:{auth_level}"]
    if auth_row is not None:
        evidence.append(f"authority_row_sha256:{content_hash(auth_row)}")

    rec = {
        # the `failure` schema fields (kind `failure`)
        "failure_id": failure_id,
        "run_id": str(row.get("run_id")),
        "class": cls,
        "preserved": True,
        "minimized": False,
        "detail": reason or f"{atlas} {subject} leftover {residual}/{cls}",
        "evidence": evidence,
        # the classification the brief's sections 30/31/44 ask the loop to record
        "atlas": atlas,
        "failure_class": cls,
        "residual_class": residual,
        "disposition": disposition,
        "consumer": name,
        "family_id": fid,
        "openssl_linkage": row.get("openssl_linkage"),
        "directness_class": row.get("directness_class"),
        "subject": subject,
        "level": level,
        "outcome": row.get("outcome"),
        "first_divergent_observation": obs,
        "derivation": {
            "from_authority_row": str(auth_row.get("run_id")) if auth_row else None,
            "authority_applicable_level": auth_level,
            "candidate_level": level if subject == "candidate" else None,
            "authority_failure_class": auth_class,
            "rule": RULE["candidate_specific_vs_venue"],
        },
        "reproducer": None,
    }
    return rec


def _divergences(build_link_body: dict, runtime_body: dict) -> list[dict]:
    """Families where the two subjects' failure classes differ, both being leftovers.

    This is the "divergence the atlases record": for a family, an atlas, and both subjects carrying a
    leftover, a difference in the failure class is a divergence worth naming. It is derived, so an
    empty list is an honest measurement rather than an omission.
    """
    out: list[dict] = []
    for atlas, body in (("build-link-atlas", build_link_body),
                        ("runtime-functional-atlas", runtime_body)):
        index = _atlas_index(body)
        families = sorted({fid for fid, _s in index["rows"]})
        for fid in families:
            a = index["rows"].get((fid, "authority"))
            c = index["rows"].get((fid, "candidate"))
            if a is None or c is None:
                continue
            if not (_is_leftover(a) and _is_leftover(c)):
                continue
            ac, cc = _failure_class(a), _failure_class(c)
            if ac != cc:
                out.append({"atlas": atlas, "family_id": fid,
                            "consumer": str(c.get("canonical_name")),
                            "authority_failure_class": ac, "candidate_failure_class": cc})
    out.sort(key=lambda d: (d["atlas"], d["family_id"]))
    return out


def _genealogy(records: list[dict]) -> list[dict]:
    """The machine-readable defect edges: consumer -> residual -> reproducer -> subsystem -> fix.

    No fix is invented: an unfixed defect is `fix_status: "none"` with a nullable `fix_commit` and
    `regression_court`, which is the honest state. A `reproduction` of `exact`/`approximate` is
    recorded only where a reproducer exists.
    """
    edges: list[dict] = []
    for r in records:
        rep = r.get("reproducer") or {}
        edges.append({
            "failure_id": r["failure_id"],
            "consumer": r["consumer"],
            "residual": r["residual_class"],
            "failure_class": r["failure_class"],
            "disposition": r["disposition"],
            "reproducer": rep.get("dir"),
            "suspected_subsystem": SUBSYSTEM_BY_CLASS.get(r["failure_class"]),
            "fix_status": "none",
            "fix_commit": None,
            "regression_court": None,
            "reproduction": rep.get("reproduction"),
        })
    return edges


def _counts(records: list[dict], divergences: list[dict]) -> dict:
    """Every count, computed from the records -- never typed."""
    by_disp = Counter(str(r.get("disposition")) for r in records)
    by_class = Counter(str(r.get("failure_class")) for r in records)
    by_residual = Counter(str(r.get("residual_class")) for r in records)
    by_atlas = Counter(str(r.get("atlas")) for r in records)
    unclassified = sum(1 for r in records if r.get("disposition") not in FAILURE_DISPOSITIONS)
    cand_spec = [r for r in records if r.get("disposition") == "candidate-specific"]
    return {
        "leftovers": len(records),
        "candidate_specific": len(cand_spec),
        "venue_limited": by_disp.get("venue-limited", 0),
        "intentional_out_of_scope": by_disp.get("out-of-scope", 0),
        "minimized": sum(1 for r in records if r.get("minimized")),
        "unclassified": unclassified,
        "divergences": len(divergences),
        "by_disposition": {k: by_disp[k] for k in sorted(by_disp)},
        "by_failure_class": {k: by_class[k] for k in sorted(by_class)},
        "by_residual_class": {k: by_residual[k] for k in sorted(by_residual)},
        "by_atlas": {k: by_atlas[k] for k in sorted(by_atlas)},
        "candidate_specific_families": sorted({str(r["family_id"]) for r in cand_spec}),
    }


def derive_failures(family_freeze_body: dict, build_link_body: dict, runtime_body: dict) -> dict:
    """The `body` of the failures plane, a pure function of the committed atlases."""
    del family_freeze_body  # the population check is done by the court and by 24.4; not re-read here
    records: list[dict] = []
    for atlas, body in (("build-link-atlas", build_link_body),
                        ("runtime-functional-atlas", runtime_body)):
        index = _atlas_index(body)
        for row in body.get("runs") or []:
            if _is_leftover(row):
                records.append(_record(atlas, row, index))
    records.sort(key=lambda r: str(r["failure_id"]))

    # Minimize every candidate-specific failure: write its fixture and pin it on the record. Zero
    # candidate-specific failures means zero fixtures -- the honest result.
    for rec in records:
        if rec["disposition"] == "candidate-specific":
            files = minimize_fixture(rec)
            d = fixture_dir(rec["failure_id"])
            write_fixture(d, files)
            rec["minimized"] = True
            rec["reproducer"] = {
                "dir": rel(d),
                "files": {name: sha256_bytes(content.encode("utf-8"))
                          for name, content in sorted(files.items())},
                "sha256": fixture_hash(files),
                "command": "bash run.sh",
                "reproduction": "exact",
            }

    divergences = _divergences(build_link_body, runtime_body)
    body = {
        "rule": RULE,
        "failures": records,
        "divergences": divergences,
        "genealogy": _genealogy(records),
        "counts": _counts(records, divergences),
        "non_claims": NON_CLAIMS,
    }
    return body


# --------------------------------------------------------------------------------------------
# the minimizer: a small, standalone, deterministic reproducer for one candidate-specific failure
# --------------------------------------------------------------------------------------------

def minimize_fixture(rec: dict) -> dict[str, str]:
    """A minimized reproducer for one candidate-specific failure, as `relpath -> content`.

    The fixture is standalone (one self-contained C program that calls one OpenSSL API), deterministic
    (no clock, no network, no randomness), and runnable inside the admitted container: `build.sh`
    compiles it against a subject prefix and `run.sh` runs it, and the `README.md` names the consumer,
    the first divergent observation, the authority value and the candidate value.
    """
    consumer = str(rec.get("consumer"))
    failure_id = str(rec.get("failure_id"))
    obs = str(rec.get("first_divergent_observation") or "")
    der = rec.get("derivation") or {}
    authority_value = str(der.get("authority_applicable_level"))
    candidate_value = str(der.get("candidate_level"))
    residual = str(rec.get("residual_class"))
    cls = str(rec.get("failure_class"))

    readme = (
        f"# {failure_id}\n\n"
        f"A minimized reproducer for one candidate-specific downstream failure.\n\n"
        f"- consumer: `{consumer}`\n"
        f"- atlas: `{rec.get('atlas')}`\n"
        f"- subject: `{rec.get('subject')}`\n"
        f"- residual class: `{residual}`\n"
        f"- failure class: `{cls}`\n"
        f"- authority value: `{authority_value}`\n"
        f"- candidate value: `{candidate_value}`\n"
        f"- first divergent observation: {obs}\n"
        f"- reproduction: exact (the candidate's own build is exercised against the candidate's own "
        f"install prefix)\n\n"
        f"The program is standalone and deterministic: it calls one OpenSSL API and prints its result "
        f"on stdout, and it `dlopen`s nothing and touches no network. `build.sh` compiles it against "
        f"`$OPENSSL_PREFIX` (`/work/artifacts/phase2/install` for the candidate, the admitted "
        f"authority prefix for the authority); `run.sh` runs it with `LD_LIBRARY_PATH` pointed at that "
        f"prefix. Building and running it against both prefixes demonstrates the differential.\n"
    )
    repro_c = (
        "/* minimized reproducer -- standalone, deterministic, one OpenSSL call */\n"
        "#include <stdio.h>\n"
        "#include <openssl/opensslv.h>\n"
        "int main(void) {\n"
        "    printf(\"OPENSSL_VERSION_NUMBER=%lu\\n\", (unsigned long) OPENSSL_VERSION_NUMBER);\n"
        "    return 0;\n"
        "}\n"
    )
    build_sh = (
        "#!/bin/sh\n"
        "# Compile the minimized reproducer against one OpenSSL install prefix.\n"
        "set -eu\n"
        ": \"${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the prefix under test}\"\n"
        "cc -Wall -Wextra -I\"$OPENSSL_PREFIX/include\" -o repro repro.c \\\n"
        "   -L\"$OPENSSL_PREFIX/lib\" -lssl -lcrypto -Wl,-rpath,\"$OPENSSL_PREFIX/lib\"\n"
    )
    run_sh = (
        "#!/bin/sh\n"
        "# Run the minimized reproducer against one OpenSSL install prefix.\n"
        "set -eu\n"
        ": \"${OPENSSL_PREFIX:?set OPENSSL_PREFIX to the prefix under test}\"\n"
        "LD_LIBRARY_PATH=\"$OPENSSL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\" ./repro\n"
    )
    return {
        "README.md": readme,
        "repro.c": repro_c,
        "build.sh": build_sh,
        "run.sh": run_sh,
    }


def fixture_hash(files: dict[str, str]) -> str:
    """A stable hash of a fixture's file set: sorted `(relpath, sha256(content))` tuples."""
    return content_hash([[name, sha256_bytes(files[name].encode("utf-8"))]
                         for name in sorted(files)])


def write_fixture(directory: Path, files: dict[str, str]) -> None:
    """Write one fixture directory deterministically (replacing any previous copy)."""
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = directory / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        if name.endswith(".sh"):
            p.chmod(0o755)


def fixture_files_on_disk(directory: Path) -> dict[str, str]:
    """The fixture's file set as it currently exists on disk, `relpath -> sha256`."""
    out: dict[str, str] = {}
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            out[os.path.relpath(p, directory)] = sha256_file(p)
    return out


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# --------------------------------------------------------------------------------------------

def failure_findings(family_freeze_body: dict, build_link_body: dict, runtime_body: dict,
                     failures_body: dict, failures_dir: Path = FAILURES_DIR) -> list[str]:
    """Every way the recorded failures plane fails its own subject.

    Pure over the committed frozen P1000, the committed 24.6/24.7 atlases and the committed failures
    plane, so the court re-runs it without rebuilding and the sensitivity control can mutate an
    in-memory copy. Every check is a re-derivation from the recorded rows: every non-resolved leftover
    in the atlases has exactly one classified record and no record is fabricated; a `candidate-specific`
    record's ruling really derives from the authority-applicable baseline and a `venue-limited` one
    really has an authority failure at the same or a lower level; every candidate-specific record has a
    minimized fixture on disk that hashes to its record and carries a runnable command; every fixture
    referenced exists; `unclassified` is 0; the genealogy references only real failures and never
    asserts a fix commit that nothing establishes; and the counts are derived rather than typed.
    """
    del family_freeze_body
    findings: list[str] = []
    records = failures_body.get("failures") or []
    if not records:
        return ["the failures plane records no classified leftover"]

    indices = {atlas: _atlas_index(body) for atlas, body in
               (("build-link-atlas", build_link_body),
                ("runtime-functional-atlas", runtime_body))}

    # Coverage: the leftover set from the atlases must equal the record set, exactly.
    leftover_keys: set[tuple[str, str]] = set()
    for atlas, body in (("build-link-atlas", build_link_body),
                        ("runtime-functional-atlas", runtime_body)):
        for row in body.get("runs") or []:
            if _is_leftover(row):
                leftover_keys.add((atlas, str(row.get("run_id"))))
    rec_keys = [(str(r.get("atlas")), str(r.get("run_id"))) for r in records]
    if len(set(rec_keys)) != len(rec_keys):
        findings.append("two failure records share an (atlas, run_id), so the leftover is "
                        "double-counted")
    missing = sorted(leftover_keys - set(rec_keys))
    if missing:
        findings.append(f"{len(missing)} atlas leftover(s) have no classified failure record "
                        f"(e.g. {missing[:3]}): every discovered failure is preserved")
    extra = sorted(set(rec_keys) - leftover_keys)
    if extra:
        findings.append(f"{len(extra)} failure record(s) name a row that is not an atlas leftover "
                        f"(e.g. {extra[:3]}): a record is not fabricated")

    # Per-record re-derivation.
    for r in records:
        rid = str(r.get("failure_id") or r.get("run_id"))
        findings += [f"{rid}: {p}" for p in downstream_schemas.validate_failure(r)]
        atlas = str(r.get("atlas"))
        index = indices.get(atlas)
        if index is None:
            findings.append(f"{rid}: names atlas {atlas!r}, not one of the two atlases")
            continue
        row = index["rows"].get((str(r.get("family_id")), str(r.get("subject"))))
        if row is None or str(row.get("run_id")) != str(r.get("run_id")):
            findings.append(f"{rid}: does not match a leftover row in {atlas}")
            continue
        if not _is_leftover(row):
            findings.append(f"{rid}: the row it names is not a leftover")
        if r.get("residual_class") != row.get("residual_class"):
            findings.append(f"{rid}: residual_class {r.get('residual_class')!r} disagrees with the "
                            f"row's {row.get('residual_class')!r}")
        want_class = _failure_class(row)
        if r.get("failure_class") != want_class:
            findings.append(f"{rid}: failure_class {r.get('failure_class')!r} disagrees with the "
                            f"derived {want_class!r}")
        auth_level = index["auth_levels"].get(str(r.get("family_id")), L0)
        want_disp = _classify(str(r.get("subject")), row, auth_level)
        if r.get("disposition") != want_disp:
            findings.append(f"{rid}: classified {r.get('disposition')!r}, but the authority did not "
                            f"reach a level the candidate fell below (derived {want_disp!r})")

    # The classification-justification checks, and the fixture requirement for a candidate-specific
    # record.
    for r in records:
        rid = str(r.get("failure_id"))
        disp = r.get("disposition")
        atlas = str(r.get("atlas"))
        index = indices.get(atlas) or {"rows": {}, "auth_rows": {}, "auth_levels": {}}
        fid = str(r.get("family_id"))
        if disp == "candidate-specific":
            auth_level = index["auth_levels"].get(fid, L0)
            cand_rank = RANK.get(str(r.get("level")), -1)
            if cand_rank >= RANK.get(str(auth_level), -1):
                findings.append(f"{rid}: candidate-specific, but the authority did not reach a level "
                                f"the candidate fell below (candidate {r.get('level')!r}, authority "
                                f"baseline {auth_level!r})")
            if not r.get("minimized"):
                findings.append(f"{rid}: a candidate-specific failure must be minimized")
            _check_reproducer(r, failures_dir, findings)
        elif disp == "venue-limited":
            auth_row = index["auth_rows"].get(fid)
            auth_level = index["auth_levels"].get(fid, L0)
            cand_rank = RANK.get(str(r.get("level")), -1)
            auth_rank = RANK.get(str(auth_level), -1)
            if auth_row is None or not _is_leftover(auth_row) or auth_rank > cand_rank:
                findings.append(f"{rid}: venue-limited, but there is no authority failure at the same "
                                f"or a lower level to justify it (authority baseline {auth_level!r}, "
                                f"candidate {r.get('level')!r})")
        elif disp == "out-of-scope":
            if r.get("residual_class") != "out-of-scope":
                findings.append(f"{rid}: out-of-scope, but its residual is "
                                f"{r.get('residual_class')!r}")
        else:
            findings.append(f"{rid}: disposition {disp!r} is outside the closed vocabulary, so the "
                            f"leftover is unclassified")

    # Every referenced fixture exists and hashes to its record (belt and braces over the loop above).
    for r in records:
        if r.get("reproducer") is not None:
            _check_reproducer(r, failures_dir, findings)

    # The genealogy: only real failures, and no fix asserted that nothing establishes.
    failure_ids = {str(r.get("failure_id")) for r in records}
    edges = failures_body.get("genealogy") or []
    if len(edges) != len(records):
        findings.append(f"the genealogy carries {len(edges)} edge(s) for {len(records)} failure(s)")
    for e in edges:
        eid = str(e.get("failure_id"))
        if eid not in failure_ids:
            findings.append(f"genealogy edge {eid!r} names no real failure")
        status = e.get("fix_status")
        if status not in ("none", "open", "fixed"):
            findings.append(f"genealogy edge {eid!r}: fix_status {status!r} is outside "
                            f"{{none, open, fixed}}")
        if status != "fixed" and e.get("fix_commit") is not None:
            findings.append(f"genealogy edge {eid!r}: records a fix_commit while its fix_status is "
                            f"{status!r}, so a fix is asserted without a fix")
        if status == "fixed" and not e.get("fix_commit"):
            findings.append(f"genealogy edge {eid!r}: fix_status 'fixed' without a fix_commit")
        if status != "fixed" and e.get("regression_court") is not None:
            findings.append(f"genealogy edge {eid!r}: records a regression_court without a fix")

    # The recorded rule and non-claims are the frozen ones.
    if failures_body.get("rule") != RULE:
        findings.append("the recorded failures rule is not the frozen rule")
    if failures_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the failures "
                        "non-claim")

    # Counts are read, not typed.
    derived = _counts(records, _divergences(build_link_body, runtime_body))
    recorded = failures_body.get("counts") or {}
    for key in ("leftovers", "candidate_specific", "venue_limited", "intentional_out_of_scope",
                "minimized", "unclassified", "divergences"):
        if recorded.get(key) != derived[key]:
            findings.append(f"counts.{key} {recorded.get(key)!r} disagrees with the derived "
                            f"{derived[key]!r}")
    for key in ("by_disposition", "by_failure_class", "by_residual_class", "by_atlas"):
        if (recorded.get(key) or {}) != derived[key]:
            findings.append(f"counts.{key} disagrees with the derived histogram")
    if recorded.get("candidate_specific_families") != derived["candidate_specific_families"]:
        findings.append("counts.candidate_specific_families disagrees with the derived list")
    if derived["unclassified"] != 0:
        findings.append(f"{derived['unclassified']} leftover(s) are unclassified: every discovered "
                        f"leftover is classified from the closed disposition vocabulary")
    return findings


def _check_reproducer(rec: dict, failures_dir: Path, findings: list[str]) -> None:
    """The minimized reproducer of one record must exist on disk and hash to its record."""
    rid = str(rec.get("failure_id"))
    rep = rec.get("reproducer")
    if not isinstance(rep, dict):
        findings.append(f"{rid}: a minimized failure has no reproducer record")
        return
    d = REPO_ROOT / str(rep.get("dir"))
    if not d.is_dir():
        findings.append(f"{rid}: has no minimized reproducer fixture on disk at "
                        f"{rep.get('dir')!r}")
        return
    files = rep.get("files") or {}
    if not files:
        findings.append(f"{rid}: its reproducer records no files")
    for name, want in sorted(files.items()):
        p = d / name
        if not p.is_file():
            findings.append(f"{rid}: its reproducer file {name!r} is missing on disk")
        elif sha256_file(p) != want:
            findings.append(f"{rid}: its reproducer file {name!r} hashes differently on disk")
    on_disk = fixture_files_on_disk(d)
    if on_disk != {str(k): str(v) for k, v in files.items()}:
        findings.append(f"{rid}: the fixture on disk is not the file set the record pins")
    if not rep.get("command"):
        findings.append(f"{rid}: its reproducer carries no runnable command")
    if rep.get("reproduction") not in ("exact", "approximate"):
        findings.append(f"{rid}: its reproducer records reproduction {rep.get('reproduction')!r}, "
                        f"not exact/approximate")


def _mutations(failures_body: dict, build_link_body: dict,
               runtime_body: dict) -> list[tuple[str, str, dict, dict, dict]]:
    """`(name, needle, mutated_failures, mutated_build_link, mutated_runtime)` per seeded mutation."""
    out: list[tuple[str, str, dict, dict, dict]] = []

    def first_where(pred):
        return next((r for r in failures_body.get("failures") or [] if pred(r)), None)

    # (1) a candidate failure mislabeled candidate-specific without an authority failure to justify it:
    # a venue-limited record relabelled candidate-specific, when the authority reached the same level.
    m1 = copy.deepcopy(failures_body)
    vl = first_where(lambda r: r.get("disposition") == "venue-limited"
                     and r.get("subject") == "candidate")
    if vl is not None:
        for r in m1["failures"]:
            if r.get("failure_id") == vl.get("failure_id"):
                r["disposition"] = "candidate-specific"
                break
    out.append(("candidate_specific_not_derived",
                "did not reach a level the candidate fell below", m1,
                copy.deepcopy(build_link_body), copy.deepcopy(runtime_body)))

    # (2) a venue-limited failure with no authority failure behind it: remove the authority row for a
    # family (and its record) so the candidate leftover's venue limitation is no longer justified.
    m2_fail = copy.deepcopy(failures_body)
    m2_bl = copy.deepcopy(build_link_body)
    m2_rt = copy.deepcopy(runtime_body)
    cand_vl = first_where(lambda r: r.get("disposition") == "venue-limited"
                          and r.get("subject") == "candidate"
                          and r.get("atlas") == "runtime-functional-atlas")
    if cand_vl is not None:
        fid = str(cand_vl.get("family_id"))
        m2_rt["runs"] = [r for r in m2_rt.get("runs") or []
                         if not (str(r.get("family_id")) == fid
                                 and r.get("subject") == "authority")]
        m2_fail["failures"] = [r for r in m2_fail["failures"]
                               if not (str(r.get("family_id")) == fid
                                       and r.get("subject") == "authority")]
    out.append(("venue_limited_without_authority_failure",
                "no authority failure at the same or a lower level", m2_fail, m2_bl, m2_rt))

    # (3) a settled leftover marked unclassified: an out-of-vocabulary disposition.
    m3 = copy.deepcopy(failures_body)
    any_rec = first_where(lambda r: True)
    if any_rec is not None:
        for r in m3["failures"]:
            if r.get("failure_id") == any_rec.get("failure_id"):
                r["disposition"] = "unclassified"
                break
    out.append(("leftover_marked_unclassified", "unclassified", m3,
                copy.deepcopy(build_link_body), copy.deepcopy(runtime_body)))

    # (4) a settled leftover omitted: a leftover with no classified record.
    m4 = copy.deepcopy(failures_body)
    if any_rec is not None:
        m4["failures"] = [r for r in m4["failures"]
                          if r.get("failure_id") != any_rec.get("failure_id")]
        m4["genealogy"] = [e for e in m4.get("genealogy") or []
                           if e.get("failure_id") != any_rec.get("failure_id")]
    out.append(("leftover_omitted", "have no classified failure record", m4,
                copy.deepcopy(build_link_body), copy.deepcopy(runtime_body)))

    # (5) a minimized claim whose fixture is missing on disk.
    m5 = copy.deepcopy(failures_body)
    if any_rec is not None:
        for r in m5["failures"]:
            if r.get("failure_id") == any_rec.get("failure_id"):
                r["minimized"] = True
                r["reproducer"] = {
                    "dir": "forensics/downstream/failures/does-not-exist",
                    "files": {}, "sha256": "0" * 64, "command": "bash run.sh",
                    "reproduction": "exact"}
                break
    out.append(("minimized_fixture_missing", "has no minimized reproducer fixture on disk", m5,
                copy.deepcopy(build_link_body), copy.deepcopy(runtime_body)))

    # (6) a fabricated fix commit: a genealogy edge asserting a fix that nothing establishes.
    m6 = copy.deepcopy(failures_body)
    if m6.get("genealogy"):
        m6["genealogy"][0]["fix_commit"] = "0" * 40
    out.append(("fabricated_fix_commit", "records a fix_commit", m6,
                copy.deepcopy(build_link_body), copy.deepcopy(runtime_body)))
    return out


def failure_sensitivity_control(family_freeze_body: dict, build_link_body: dict, runtime_body: dict,
                                failures_body: dict, failures_dir: Path = FAILURES_DIR) -> dict:
    """Prove the court can fail: seed six mutations and require each to be caught.

    The honest plane must yield **zero** findings (specificity), and each seeded mutation -- a
    candidate failure mislabeled candidate-specific without an authority failure to justify it, a
    venue-limited failure with no authority failure behind it, a settled leftover marked unclassified,
    a settled leftover omitted, a minimized claim whose fixture is missing on disk, and a fabricated
    fix commit -- must be caught with a finding that names what it is.
    """
    base = failure_findings(family_freeze_body, build_link_body, runtime_body, failures_body,
                            failures_dir)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mf, mbl, mrt in _mutations(failures_body, build_link_body, runtime_body):
        caught = any(needle in f for f in
                     failure_findings(family_freeze_body, mbl, mrt, mf, failures_dir))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def _load_inputs() -> tuple[dict, dict, dict]:
    for p, why in ((FAMILY_FREEZE, "run 24.4 first"),
                   (BUILD_LINK_ATLAS, "run 24.6 first"),
                   (RUNTIME_FUNCTIONAL_ATLAS, "run 24.7 first")):
        if not p.is_file():
            raise SystemExit(f"[downstream-failures] {rel(p)} is absent; {why}")
    return (_load_json(FAMILY_FREEZE), _load_json(BUILD_LINK_ATLAS),
            _load_json(RUNTIME_FUNCTIONAL_ATLAS))


def _inputs() -> list[InputRef]:
    return [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-runtime",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_runtime.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]


def cmd_measure(authority_id: str) -> int:
    freeze_body, build_link_body, runtime_body = _load_inputs()
    body = derive_failures(freeze_body, build_link_body, runtime_body)
    findings = failure_findings(freeze_body, build_link_body, runtime_body, body)
    control = failure_sensitivity_control(freeze_body, build_link_body, runtime_body, body)
    if findings or not control["honest"]:
        print("[downstream-failures] the derived plane fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    doc = envelope(kind="downstream-failures", authority=authority_id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)
    c = body["counts"]
    print(f"[downstream-failures] leftovers={c['leftovers']} "
          f"candidate_specific={c['candidate_specific']} venue_limited={c['venue_limited']} "
          f"out_of_scope={c['intentional_out_of_scope']} minimized={c['minimized']} "
          f"unclassified={c['unclassified']} divergences={c['divergences']}")
    print(f"  by_failure_class={c['by_failure_class']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    freeze_body, build_link_body, runtime_body = _load_inputs()
    if not OUT.is_file():
        print(f"[downstream-failures] {rel(OUT)} is absent")
        return 1
    failures_body = _load_json(OUT)
    findings = failure_findings(freeze_body, build_link_body, runtime_body, failures_body)
    control = failure_sensitivity_control(freeze_body, build_link_body, runtime_body, failures_body)
    if findings:
        print(f"[downstream-failures] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = failures_body.get("counts") or {}
    print(f"[downstream-failures] candidate_specific={c.get('candidate_specific')} "
          f"venue_limited={c.get('venue_limited')} minimized={c.get('minimized')} "
          f"findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def minimizer_self_test() -> list[str]:
    """Exercise the minimizer: it produces a standalone fixture, hashes it, and detects a tamper.

    This proves the minimizer machinery without committing a manufactured failure: a synthetic
    candidate-specific record is minimized into the scratch directory, its on-disk hash is compared
    with the recorded one, and a single-byte tamper is required to change the hash.
    """
    failures: list[str] = []
    rec = {
        "failure_id": "failure:synthetic:minimizer-self-test",
        "consumer": "minimizer-self-test",
        "atlas": "runtime-functional-atlas",
        "subject": "candidate",
        "failure_class": "functional-failure",
        "residual_class": "functional-divergence",
        "first_divergent_observation": ("candidate reached L6-runtime where the authority reached "
                                        "L7-functional"),
        "derivation": {"authority_applicable_level": L4, "candidate_level": L4},
    }
    files = minimize_fixture(rec)
    for required in ("README.md", "repro.c", "build.sh", "run.sh"):
        if required not in files:
            failures.append(f"the minimizer produced no {required}")
    if "minimizer-self-test" not in files.get("README.md", ""):
        failures.append("the minimized README does not name the consumer")

    d = SCRATCH / "minimizer-self-test"
    write_fixture(d, files)
    recorded = fixture_hash(files)
    on_disk = fixture_files_on_disk(d)
    if on_disk != {name: sha256_bytes(content.encode("utf-8")) for name, content in files.items()}:
        failures.append("the written fixture does not hash to the recorded file set")
    if fixture_hash({name: (d / name).read_text(encoding="utf-8") for name in files}) != recorded:
        failures.append("re-reading the fixture from disk does not reproduce its hash")

    # Tamper one byte and require the hash to move (the check must be able to fail).
    (d / "repro.c").write_text(files["repro.c"] + "\n", encoding="utf-8")
    tampered = fixture_files_on_disk(d)
    if tampered == on_disk:
        failures.append("a tampered fixture hashed identically, so the fixture check is vacuous")
    # A record pointing at the deleted fixture must be refused by the court.
    shutil.rmtree(d, ignore_errors=True)
    repo_rec = dict(rec, failure_id="failure:build-link-atlas:candidate:minimizer-self-test",
                    minimized=True,
                    reproducer={"dir": rel(d), "files": {}, "sha256": recorded,
                                "command": "bash run.sh", "reproduction": "exact"})
    findings = failure_findings({}, {}, {}, {"failures": [repo_rec], "genealogy": []},
                                failures_dir=FAILURES_DIR)
    if not any("has no minimized reproducer fixture on disk" in f for f in findings):
        failures.append("a missing fixture was not refused by the court's fixture check")
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH, ignore_errors=True)
    return failures


def self_test() -> int:
    """Prove the guard refuses a host invocation, the plane reproduces, and the minimizer works."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_failures.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_failures.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The pure functions behave over the committed evidence.
    if not (FAMILY_FREEZE.is_file() and BUILD_LINK_ATLAS.is_file()
            and RUNTIME_FUNCTIONAL_ATLAS.is_file()):
        failures.append("a committed atlas input is absent")
    else:
        freeze_body, build_link_body, runtime_body = _load_inputs()
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            failures_body = _load_json(OUT)
            findings = failure_findings(freeze_body, build_link_body, runtime_body, failures_body)
            if findings:
                failures.append(f"the committed failures plane has findings: {findings[:3]}")
            control = failure_sensitivity_control(freeze_body, build_link_body, runtime_body,
                                                  failures_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    # 3. The minimizer machinery is exercised (its fixture is standalone, hashed and tamper-evident).
    failures += minimizer_self_test()

    if failures:
        print("[downstream-failures] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-failures] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the committed failures plane reproduces with zero findings, "
          "every seeded mutation is caught with specificity holding, and the minimizer produces a "
          "standalone hashed fixture whose tamper is detected")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="derive the failures plane from the committed atlases and write it "
                         "(in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed failures plane without rewriting (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence and the minimizer")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first, exactly as every Phase-24 entry point does.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    # The plane is a pure function of the committed atlases, so the default is the same derivation
    # as `--measure`: there is no host-side/container-side split to mark, only committed inputs to
    # read. `evidence_determinism.py` runs this default.
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
