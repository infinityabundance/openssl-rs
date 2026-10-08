#!/usr/bin/env python3
"""openssl-rs — Phase-24.11 candidate freeze: the candidate identity content-addressed, and the
precommitted holdout run against it exactly once.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.5 fixed the precommitted partition
(`forensics/downstream/holdout.json`): 200 holdout families that are **never** looked at while a
patch is chosen, and 800 development families the compatibility defects are found and fixed against.
24.6 built and linked the population, 24.7 loaded and drove it, 24.8 classified/preserved/minimized
the failures, 24.9 measured the deep tier and 24.10 the separate hostility corpus. This module is the
freeze: the **candidate identity is frozen and content-addressed**, and the precommitted holdout is
run against exactly that candidate **once**, so the holdout is a real out-of-sample measurement
rather than a set measured after the defects were already known (the brief's section 41).

The frozen candidate identity
-----------------------------
The candidate the holdout is measured against is a **content-addressed** record of the drop-in
install: the `libssl`/`libcrypto` soname digests, the exported headers, the pkg-config metadata and
the provider modules, plus the crate name and version (read from `Cargo.toml`) and the admitted
container venue (the image identity and platform the committed manifest
`forensics/downstream/container.json` records). The install content this hashes **must reproduce
from the committed install**, so the holdout is measured against a candidate a reader can recompute,
not a banner. The source commit (`git rev-parse HEAD`) is carried **as recorded provenance**, not as
part of the reproducible install identity: it is excluded from `identity_hash` and from the
live-equality comparison, because the live HEAD necessarily moves when this artefact's own commit
lands -- a self-reference the earlier record could never satisfy. A recorded commit that is not the
literal `unknown` must name a commit that exists in the repository's history (checked with
`git cat-file -e <sha>^{commit}`); `unknown` is accepted only when git is genuinely absent from the
venue.

The exactly-once holdout, and the immutable first run
-----------------------------------------------------
The holdout set is read from the precommitted partition and **never re-selected** -- its
`partition_root_hash` must match 24.5's and every member must reproduce from the frozen rule. The
holdout is measured with the **same recipe/workload machinery** 24.6 and 24.7 use (the recipe
catalogue, the ELF/linkage helpers, the resource limits, the specimen/variant construction and the
runtime/functional workloads are imported, not re-implemented), under **both** subjects, so the
out-of-sample set is measured the same way the development set was. A family with no admitted
recipe gets an honest `not_attempted`/`unavailable` row with a reason rather than being omitted.

The **first run** is recorded immutably. A re-invocation measures the holdout again but stores the
new measurement under `reruns[]`, attesting the first run's hash; `first_run` is never overwritten,
so the first-run score is preserved verbatim (the brief's sections 41 and 42).

The learning curve is preserved, not hidden
-------------------------------------------
The development cohort's first-run measurement (the committed 24.6/24.7 atlases restricted to the
development cohort), the holdout's first run (this artefact) and the post-development state (the
fixes chosen) are recorded **separately** and never collapsed. The operative precommitment rule is
that a holdout family may not be used to choose a patch: the development-side failure plane must
cite no holdout family as a source of a fix, and no candidate-specific defect may belong to a
holdout family.

Nothing here is a security proof, and the batch is honest about its venue
------------------------------------------------------------------------
A holdout result over a selected population is an out-of-sample measurement of **that population**,
not of all downstream software, and a **venue-limited** holdout member -- one with no admitted
recipe or workload in this venue -- is neither a pass nor a fail.

This tool fetches, compiles and runs real downstream releases, so `phase24_guard.require_admitted()`
is the first statement of `main` and a host invocation is refused (`docs/REPRODUCIBILITY.md`
section 1).

Why this artefact is not in `evidence_determinism.py`'s `GENERATORS` or `COMPARED`
----------------------------------------------------------------------------------
It is **measurement**, not a pure function of committed inputs: it fetches, compiles and drives a
real downstream release inside the court container against the frozen candidate, so the level a run
reaches and its normalised transcript are a function of the court's toolchain and of the network, not
of committed inputs -- the same precedent as 24.6's build/link atlas, 24.7's runtime/functional
atlas, 24.9's high-value tier, 24.10's hostility corpus and the Phase-17 measured corpus. Regenerating
it needs a compiler, a prefix and the network, none of which a host CI runner has, and the Docker-only
guard refuses a host invocation before it builds anything. The court `RT-CANDIDATE-FREEZE` re-runs
only this module's **pure** functions over the committed artefact and never rebuilds.

Outputs
-------
  forensics/downstream/candidate-freeze.json   the frozen candidate identity and the once-run holdout

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches,
# compiles and runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (fetch/extract/run/ELF inspection/resource limits) are reused through
# 24.6/24.7, which re-export none of them themselves: importing both keeps one code path.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue, its specimen/variant/run construction, its
# source-root hash and its `measure_family` orchestration are **imported and reused**, so the holdout
# builds exactly the build the atlas built (the brief's "no divergent predicate").
import downstream_build_link as bl  # noqa: E402

# The 24.7 runtime/functional atlas: its workload helpers (the PKI fixture, the local runners), its
# load proof, its normaliser and its `run` construction are imported and reused, so a holdout run is
# the exact workload machinery 24.7 measured with.
import downstream_runtime as rt  # noqa: E402

# The 24.5 holdout tool: its partition derivation and its `classify_p1000` are imported so the court
# re-derives the precommitted partition through the same rule 24.5 fixed, never a second predicate.
import downstream_holdout as ho  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the freeze and the population cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
HOLDOUT = REPO_ROOT / "forensics" / "downstream" / "holdout.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
RUNTIME_FUNCTIONAL_ATLAS = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"
FAILURES = REPO_ROOT / "forensics" / "downstream" / "failures.json"
HIGH_VALUE_TIER = REPO_ROOT / "forensics" / "downstream" / "high-value-tier.json"
HOSTILITY_CORPUS = REPO_ROOT / "forensics" / "downstream" / "hostility-corpus.json"
CONTAINER_MANIFEST = REPO_ROOT / "forensics" / "downstream" / "container.json"
CARGO_TOML = REPO_ROOT / "Cargo.toml"
OUT = REPO_ROOT / "forensics" / "downstream" / "candidate-freeze.json"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

GENERATOR = "forensics/tools/downstream_candidate_freeze.py"
PARSER_VERSION = "downstream-candidate-freeze/1"

L0 = "L0-catalogued"
L1 = "L1-admitted-source"
L2 = "L2-configured"
L3 = "L3-built"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
L8 = "L8-authority-equivalent"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

SUBJECTS = ("authority", "candidate")

# The same normalisation policy 24.7 uses: only genuinely nondeterministic and contract-irrelevant
# values. Everything else -- return codes, error classes, certificate decisions, protocol/algorithm
# choices -- is evidence and is never normalised (the brief's section 46).
NORMALISATION_TAG = rt.NORMALISATION_TAG
NORMALISATION_ALLOWED = rt.NORMALISATION_ALLOWED
NORMALISATION_NEVER = rt.NORMALISATION_NEVER

NO_RECIPE_REASON = (
    "no admitted pristine-source build recipe is recorded for this family; the holdout does not "
    "manufacture a source URL, so the family is venue-limited rather than a pass or a fail"
)

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: an out-of-sample measurement of a selected population is not a claim
# about all downstream software, and a venue-limited member is neither a pass nor a fail.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a holdout result over a selected population is an out-of-sample measurement of that population, "
    "not of all downstream software, and a venue-limited holdout member is not a pass or a fail",
]


# ---------------------------------------------------------------------------------------------------
# the frozen rule: the candidate identity, the exactly-once holdout policy, the learning curve and
# the local-only / normalisation policy. Recorded verbatim in the artefact and re-derived by the court.
# ---------------------------------------------------------------------------------------------------

RULE: dict = {
    "id": "downstream-candidate-freeze/1",
    "name": "the candidate freeze and the exactly-once holdout",
    "candidate_identity": (
        "the candidate is content-addressed from its drop-in install: the libssl.so.3 and "
        "libcrypto.so.3 digests, the exported OpenSSL headers, the pkg-config metadata and the "
        "provider modules (ossl-modules), plus the crate name and version (read from Cargo.toml) and "
        "the admitted container venue (the image identity and platform the committed manifest "
        "forensics/downstream/container.json records). The install content this hashes must "
        "reproduce from the committed install, and the holdout is measured against exactly it. The "
        "source commit (git rev-parse HEAD) is carried as recorded provenance, not as part of the "
        "reproducible identity: it is excluded from identity_hash and from the live-equality "
        "comparison, because live HEAD moves when this artefact's own commit lands; a recorded "
        "commit other than the literal `unknown` must name a commit that exists in the repository "
        "history (git cat-file -e), and `unknown` is accepted only when git is genuinely absent"
    ),
    "holdout_policy": (
        "the holdout set is read from the precommitted 24.5 partition and never re-selected; the "
        "recorded set must equal the precommitted holdout and its partition_root_hash must match. The "
        "holdout is run against the frozen candidate exactly once; the first_run result is immutable "
        "-- a re-invocation appends a rerun record attesting the first run's hash and never "
        "overwrites first_run"
    ),
    "levels": [L5, L6, L7],
    "subjects": list(SUBJECTS),
    "authority_applicable_baseline": (
        "a holdout family's authority-applicable baseline is the highest level its authority runs "
        "reached; a candidate run reaches it when its own level rank is at least that rank, and a "
        "candidate row never claims a level above it"
    ),
    "drop_in_rule": (
        "DROP_IN_PASS requires the same pristine source, an authority baseline that reached at least "
        "L4-linked, candidate linkage proven, candidate_specific_patch_count 0 and a residual of "
        "none, with the candidate level at least the authority-applicable level; a family whose "
        "authority did not reach L4-linked is DROP_IN_NOT_APPLICABLE, because the drop-in question is "
        "not posed for a specimen the authority itself never linked"
    ),
    "learning_curve": (
        "the first-run measurement is preserved and never hidden: the development cohort's first-run "
        "measurement (the committed 24.6 build/link atlas and 24.7 runtime atlas restricted to the "
        "development cohort), the holdout's first run (this artefact) and the post-development state "
        "(the fixes chosen) are recorded separately and never collapsed"
    ),
    "no_patch_from_the_holdout": (
        "no holdout family may be used to choose a patch: the development-side failure plane must "
        "cite no holdout family as a source of a fix, and no candidate-specific defect in it may "
        "belong to a holdout family"
    ),
    "local_only": (
        "every L6/L7 workload runs against local peers only -- the admitted authority's own openssl "
        "CLI and the subject-linked program, on loopback; no run touches the public internet. The "
        "network is used only to acquire a pinned pristine source, exactly as 24.6/24.7 fetched it"
    ),
    "normalisation": {
        "tag": NORMALISATION_TAG,
        "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
        "policy": (
            "the same normaliser is applied to both subjects; it replaces only absolute paths, "
            "ports, PIDs, timestamps and addresses, and never a return code, an error class, a "
            "certificate decision, or a protocol/algorithm choice"
        ),
    },
    "accounting": (
        "every holdout family has exactly one accounting row: a family whose authority baseline "
        "reached L4-linked reads `measured`, every other family reads `venue_limited` with a reason, "
        "never omitted and never fabricated into a pass"
    ),
    "confinement": (
        "each fetch, build and run runs inside the admitted court container under its cgroup caps and "
        "this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": census.MAKE_JOBS, "step_timeout_seconds": census.STEP_TIMEOUT,
                  "fetch_timeout_seconds": census.FETCH_TIMEOUT,
                  "launch_timeout_seconds": census.LAUNCH_TIMEOUT},
}


# ---------------------------------------------------------------------------------------------------
# the frozen candidate identity (a pure read of the committed install; the holdout is measured
# against exactly this)
# ---------------------------------------------------------------------------------------------------

def _tree_digest(root: Path) -> dict:
    """A content hash of a directory tree: sorted `(relpath, size, sha256)`, symlinks skipped."""
    if not root.is_dir():
        return {"present": False, "count": 0, "sha256": None}
    entries: list[list] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            entries.append([p.relative_to(root).as_posix(), p.stat().st_size, sha256_file(p)])
    return {"present": True, "count": len(entries), "sha256": content_hash(entries)}


def _cargo_meta() -> dict:
    """The crate name and version, read from `Cargo.toml` rather than typed."""
    data = tomllib.loads(CARGO_TOML.read_text(encoding="utf-8"))
    package = data.get("package") or {}
    return {"crate_name": str(package.get("name") or "unknown"),
            "crate_version": str(package.get("version") or "unknown")}


def _source_commit() -> str:
    """The source commit the candidate is at (`git rev-parse HEAD`); `unknown` if git is absent.

    This is **recorded provenance**, not part of the reproducible install identity: it is never
    compared to live HEAD (see `candidate_identity` and `candidate_freeze_findings`).
    """
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT),
                         capture_output=True, text=True, check=False)
    return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else "unknown"


def _git_present() -> bool:
    """Whether git is available in the venue, so a recorded `unknown` commit is not a failure."""
    return shutil.which("git") is not None


def _commit_exists(sha: str) -> bool:
    """Whether `sha` names a commit in this repository's history (`git cat-file -e <sha>^{commit}`).

    The recorded source commit's provenance check: a commit that does not exist in the repository
    is not provenance, it is an unverifiable claim.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
        return False
    res = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=str(REPO_ROOT),
                         capture_output=True, text=True, check=False)
    return res.returncode == 0


# The identity keys that are **not** part of the reproducible install content: the recorded
# `source_commit` (provenance, existence-checked separately, never a live-HEAD binding) and the
# `identity_hash` itself (derived from the content). Excluding them is what lets the identity
# reproduce across the commit that lands this artefact.
_PROVENANCE_KEYS = ("source_commit", "identity_hash")


def identity_content(ident: dict) -> dict:
    """The reproducible install identity: the candidate record minus its recorded provenance.

    Used both to compute `identity_hash` and to compare a recorded identity against a freshly
    derived one, so a live-HEAD move cannot fail an otherwise-reproducible identity.
    """
    return {k: v for k, v in ident.items() if k not in _PROVENANCE_KEYS}


def _container_venue() -> dict:
    """The admitted container venue, from the committed manifest (image identity and platform)."""
    man = json.loads(CONTAINER_MANIFEST.read_text(encoding="utf-8"))
    return {"image": str(man.get("image")), "platform": str(man.get("platform")),
            "marker": str(man.get("marker"))}


def candidate_identity() -> dict:
    """The frozen candidate install identity, plus the source commit as recorded provenance.

    `identity_hash` is the content hash of the **install identity** -- everything except the
    recorded `source_commit` and `identity_hash` itself -- so it reproduces from the committed
    install rather than moving with the commit that lands this artefact.
    """
    libssl = CANDIDATE_PREFIX / "lib" / "libssl.so.3"
    libcrypto = CANDIDATE_PREFIX / "lib" / "libcrypto.so.3"
    meta = _cargo_meta()
    core = {
        "install_prefix": rel(CANDIDATE_PREFIX),
        "libssl_soname": "libssl.so.3",
        "libssl_sha256": sha256_file(libssl) if libssl.is_file() else "unknown",
        "libcrypto_soname": "libcrypto.so.3",
        "libcrypto_sha256": sha256_file(libcrypto) if libcrypto.is_file() else "unknown",
        "headers": _tree_digest(CANDIDATE_PREFIX / "include" / "openssl"),
        "pkgconfig": _tree_digest(CANDIDATE_PREFIX / "lib" / "pkgconfig"),
        "ossl_modules": _tree_digest(CANDIDATE_PREFIX / "lib" / "ossl-modules"),
        "crate_name": meta["crate_name"],
        "crate_version": meta["crate_version"],
        "container": _container_venue(),
    }
    ident = dict(core)
    ident["source_commit"] = _source_commit()          # recorded provenance, excluded from the hash
    ident["identity_hash"] = content_hash(core)
    return ident


# ---------------------------------------------------------------------------------------------------
# the precommitted holdout partition (read from 24.5's artefact; re-derived from the frozen rule)
# ---------------------------------------------------------------------------------------------------

def holdout_members(holdout_body: dict) -> list[dict]:
    """The precommitted holdout members, in frozen P1000 rank order."""
    hol = list(((holdout_body.get("partition") or {}).get("holdout")) or [])
    hol.sort(key=lambda r: int(r.get("p1000_rank")))
    return hol


def development_members(holdout_body: dict) -> list[dict]:
    """The precommitted development members, in frozen P1000 rank order."""
    dev = list(((holdout_body.get("partition") or {}).get("development")) or [])
    dev.sort(key=lambda r: int(r.get("p1000_rank")))
    return dev


def _members_set_hash(members: list[dict]) -> str:
    return content_hash(sorted(str(m.get("family_id")) for m in members))


def holdout_block(holdout_body: dict) -> dict:
    """The precommitment this run measured against: the 24.5 partition, content-addressed."""
    hol, dev = holdout_members(holdout_body), development_members(holdout_body)
    return {
        "source": rel(HOLDOUT),
        "rule_id": (holdout_body.get("rule") or {}).get("id"),
        "partition_root_hash": holdout_body.get("partition_root_hash"),
        "set_hash": _members_set_hash(hol),
        "development_set_hash": _members_set_hash(dev),
        "family_count": len(hol),
        "development_count": len(dev),
    }


# ---------------------------------------------------------------------------------------------------
# the once-only holdout run (the same machinery 24.6/24.7 use, scoped to the holdout set)
# ---------------------------------------------------------------------------------------------------

def measure_holdout(members: list[dict], authority_id: str) -> dict:
    """Run the holdout under both subjects and return the run rows, specimens, variants and limits."""
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-candidate-freeze] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    auth_defined = census.authority_defined_symbols(auth_prefix)
    cand_defined = census.authority_defined_symbols(CANDIDATE_PREFIX)

    rows: list[dict] = []
    specimens: dict[str, dict] = {}
    variants: dict[str, dict] = {}
    started = time.monotonic()
    try:
        for m in members:
            name = str(m.get("canonical_name"))
            fid = str(m.get("family_id"))
            fam = {
                "family_id": fid,
                "canonical_name": name,
                "openssl_linkage": m.get("openssl_linkage"),
                "directness_class": m.get("directness_class"),
                "_rank": m.get("p1000_rank"),
            }
            recipe = bl._RECIPE_BY_FAMILY.get(name)
            if recipe is None:
                for subject in SUBJECTS:
                    rows.append(rt._not_attempted(
                        fam, subject, level=L0, failure_class="acquire-failure",
                        residual="unavailable", reason=NO_RECIPE_REASON, recipe=None,
                        specimen_id=None, variant_id=None, source_sha256=None, limits=limits,
                        prefix=auth_prefix))
                continue

            # The exact build intent 24.6/24.7 used: the pristine source acquired once and built
            # against both subjects with the single {prefix} substitution.
            bl_rows, specimen, variant = bl.measure_family(
                fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
            if specimen:
                specimens[specimen["specimen_id"]] = specimen
            if variant:
                variants[variant["variant_id"]] = variant
            spec_id = f"specimen:{name}:{recipe['version']}"
            variant_id = f"variant:{name}:{recipe['version']}:pristine"
            source_sha = next((r.get("source_sha256") for r in bl_rows if r.get("source_sha256")),
                              None)
            root_hash = next((r.get("source_root_hash") for r in bl_rows
                              if r.get("source_root_hash")), None)

            for subject in SUBJECTS:
                root = census._single_source_root(bl.SCRATCH / name / subject / "src")
                if name not in rt.PROGRAMS:
                    rows.append(rt._not_attempted(
                        fam, subject, level=L1, failure_class="link-failure", residual="unlinked",
                        reason=("no admitted runtime intent (load argv/workload) is recorded for this "
                                "program in this venue; only the build/link levels were measured"),
                        recipe=recipe, specimen_id=spec_id, variant_id=variant_id,
                        source_sha256=source_sha, limits=limits, prefix=auth_prefix))
                    continue
                if root is None:
                    rows.append(rt._not_attempted(
                        fam, subject, level=L1, failure_class="acquire-failure",
                        residual="unavailable",
                        reason="the holdout rebuild produced no source tree to load from",
                        recipe=recipe, specimen_id=spec_id, variant_id=variant_id,
                        source_sha256=source_sha, limits=limits, prefix=auth_prefix))
                    continue
                rows.append(rt._measure_subject_runtime(
                    fam, recipe, subject,
                    auth_prefix if subject == "authority" else CANDIDATE_PREFIX, auth_prefix,
                    root, source_sha, root_hash, limits))
                print(f"  [holdout {m.get('p1000_rank'):>4}] {name:<12} {subject:<9} "
                      f"{rows[-1]['level']:<16} {str(rows[-1].get('reason') or '')[:60]}"[:150],
                      flush=True)
    finally:
        census._cleanup(bl.SCRATCH)
        census._cleanup(rt.SCRATCH)

    for row in rows:
        row["run_id"] = f"run:holdout:{row.get('subject')}:{row.get('canonical_name')}"
        row["holdout"] = True
        row["first_run"] = True
        row["evidence"] = list(row.get("evidence") or []) + ["holdout", "first_run"]
    rt._apply_baseline(rows)
    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))
    return {"runs": rows,
            "specimens": sorted(specimens.values(), key=lambda s: str(s["specimen_id"])),
            "variants": sorted(variants.values(), key=lambda v: str(v["variant_id"])),
            "limits": limits, "elapsed_seconds": round(time.monotonic() - started, 3),
            "authority_prefix": rel(auth_prefix)}


# ---------------------------------------------------------------------------------------------------
# the drop-in verdicts and the first-run summary (pure over the holdout run)
# ---------------------------------------------------------------------------------------------------

def _baseline_map(rows: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(out.get(fid, L0), -1):
                out[fid] = str(r.get("level"))
    return out


def _by_subject(rows: list[dict]) -> dict:
    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def outcomes(subject: str, outcome: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject and r.get("outcome") == outcome)

    return {
        subject: {"loaded": levels(subject, L5), "runtime": levels(subject, L6),
                  "functional": levels(subject, L7), "failed": outcomes(subject, "failed"),
                  "not_attempted": outcomes(subject, "not_attempted")}
        for subject in SUBJECTS
    }


def _candidate_failures(rows: list[dict]) -> dict[str, int]:
    hist: dict[str, int] = {}
    for r in rows:
        if r.get("subject") == "candidate" and r.get("outcome") in ("failed", "not_attempted"):
            fc = r.get("failure_class")
            if fc:
                hist[str(fc)] = hist.get(str(fc), 0) + 1
    return hist


def _verdict_counts(verdicts: list[dict]) -> dict[str, int]:
    out = {v: 0 for v in downstream_schemas.DROP_IN_VERDICTS}
    for rec in verdicts:
        v = str(rec.get("verdict"))
        out[v] = out.get(v, 0) + 1
    return out


def derive_verdict_for(baseline_level: str, cand_row: dict | None) -> str:
    """The baseline-normalized verdict for one family, re-derived from its rows."""
    if cand_row is None:
        return "DROP_IN_NOT_APPLICABLE"
    base_rank = RANK.get(str(baseline_level), -1)
    cand_rank = RANK.get(str(cand_row.get("level")), -1)
    if base_rank < RANK[L4]:
        return "DROP_IN_NOT_APPLICABLE"
    if cand_rank < base_rank:
        return "DROP_IN_FAIL"
    if (bool(cand_row.get("linkage_proven"))
            and str(cand_row.get("residual_class")) == "none"
            and int(cand_row.get("candidate_specific_patch_count") or 0) == 0):
        return "DROP_IN_PASS"
    return "DROP_IN_PARTIAL"


def derive_verdicts(members: list[dict], rows: list[dict]) -> list[dict]:
    """One schema-valid `drop_in_verdict` per holdout family that has a specimen (a recipe)."""
    baseline = _baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    out: list[dict] = []
    for m in members:
        fid, name = str(m.get("family_id")), str(m.get("canonical_name"))
        c = cand.get(fid)
        spec_id = (c or {}).get("specimen_id")
        if not spec_id:
            continue
        base = baseline.get(fid, L0)
        verdict = derive_verdict_for(base, c)
        out.append({
            "verdict_id": f"verdict:holdout:{name}",
            "family_id": fid,
            "canonical_name": name,
            "specimen_id": spec_id,
            "variant_id": (c or {}).get("variant_id"),
            "verdict": verdict,
            "pristine_source_id": spec_id,
            "authority_baseline": base,
            "authority_applicable_level": base,
            "candidate_level": str((c or {}).get("level")),
            "linkage_proven": bool((c or {}).get("linkage_proven")),
            "candidate_specific_patch_count": int((c or {}).get("candidate_specific_patch_count")
                                                  or 0),
            "residual_class": (c or {}).get("residual_class"),
            "evidence": [f"holdout:1", f"family:{fid}", f"run_id:{(c or {}).get('run_id')}",
                         f"baseline:{base}"],
        })
    out.sort(key=lambda v: str(v["verdict_id"]))
    return out


def derive_first_run(members: list[dict], rows: list[dict], verdicts: list[dict]) -> dict:
    """The immutable first-run summary, computed from the holdout run -- never typed."""
    baseline = _baseline_map(rows)
    fids = [str(m.get("family_id")) for m in members]
    fid_set = set(fids)
    recipe_fids = {str(r.get("family_id")) for r in rows if r.get("has_recipe")} & fid_set
    measurable = [fid for fid in fids if RANK.get(baseline.get(fid, L0), -1) >= RANK[L4]]
    measurable_set = set(measurable)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    reaches = 0
    for fid in measurable:
        c = cand.get(fid)
        if c is not None and RANK.get(str(c.get("level")), -1) >= RANK.get(baseline.get(fid, L0), -1):
            reaches += 1
    return {
        "holdout_families": len(fids),
        "recipe_backed_families": len(recipe_fids),
        "measurable_families": len(measurable),
        "venue_limited_families": len(fids) - len(measurable_set),
        "by_subject": _by_subject(rows),
        "candidate_reaches_baseline": reaches,
        "candidate_failures": _candidate_failures(rows),
        "verdicts": _verdict_counts(verdicts),
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


def derive_counts(members: list[dict], rows: list[dict], verdicts: list[dict],
                  accounting: list[dict]) -> dict:
    """Every count, computed from the rows, the verdicts and the accounting -- never typed."""
    c = dict(derive_first_run(members, rows, verdicts))
    c["rows"] = len(rows)
    c["accounting"] = {
        "measured": sum(1 for a in accounting if a.get("selection") == "measured"),
        "venue_limited": sum(1 for a in accounting if a.get("selection") == "venue_limited"),
    }
    return c


def derive_accounting(members: list[dict], rows: list[dict], verdicts: list[dict]) -> list[dict]:
    """One accounting row per holdout family: measured or venue-limited, with a reason."""
    baseline = _baseline_map(rows)
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    auth = {str(r.get("family_id")): r for r in rows if r.get("subject") == "authority"}
    vmap = {str(v.get("family_id")): str(v.get("verdict")) for v in verdicts}
    recipe_fids = {str(r.get("family_id")) for r in rows if r.get("has_recipe")}
    out: list[dict] = []
    for m in members:
        fid = str(m.get("family_id"))
        base = baseline.get(fid, L0)
        measured = RANK.get(base, -1) >= RANK[L4]
        c = cand.get(fid) or {}
        reason = None if measured else (c.get("reason") or (auth.get(fid) or {}).get("reason")
                                        or "no admitted recipe/workload in this venue")
        out.append({
            "family_id": fid,
            "canonical_name": str(m.get("canonical_name")),
            "p1000_rank": m.get("p1000_rank"),
            "band": m.get("band"),
            "openssl_linkage": m.get("openssl_linkage"),
            "selection": "measured" if measured else "venue_limited",
            "has_recipe": fid in recipe_fids,
            "authority_applicable_baseline": base,
            "candidate_level": str(c.get("level")),
            "reaches_baseline": bool(c.get("reaches_baseline")),
            "verdict": vmap.get(fid),
            "reason": reason,
        })
    out.sort(key=lambda r: (int(r["p1000_rank"]) if r.get("p1000_rank") is not None else 10 ** 9,
                            str(r["family_id"])))
    return out


# ---------------------------------------------------------------------------------------------------
# the learning curve (the brief's section 42: first-run vs post-fix vs final, never collapsed)
# ---------------------------------------------------------------------------------------------------

def _development_summary(dev_members: list[dict], inputs: dict) -> dict:
    """The development cohort's first-run measurement, from the committed 24.6/24.7 atlases."""
    dev_ids = {str(m.get("family_id")) for m in dev_members}
    rt_rows = [r for r in (inputs["runtime"].get("runs") or [])
               if str(r.get("family_id")) in dev_ids]
    bl_rows = [r for r in (inputs["build_link"].get("runs") or [])
               if str(r.get("family_id")) in dev_ids]
    baseline = _baseline_map(rt_rows)
    measurable = [fid for fid in dev_ids if RANK.get(baseline.get(fid, L0), -1) >= RANK[L4]]
    meas_set = set(measurable)
    cand = {str(r.get("family_id")): r for r in rt_rows if r.get("subject") == "candidate"}
    reaches = 0
    for fid in measurable:
        c = cand.get(fid)
        if c is not None and RANK.get(str(c.get("level")), -1) >= RANK.get(baseline.get(fid, L0), -1):
            reaches += 1
    return {
        "cohort": "development",
        "families": len(dev_ids),
        "source": ("the committed 24.6 build/link atlas and 24.7 runtime atlas, restricted to the "
                   "development cohort"),
        "atlas_rows": {"build_link": len(bl_rows), "runtime": len(rt_rows)},
        "by_subject": _by_subject(rt_rows),
        "measurable_families": len(measurable),
        "venue_limited_families": len(dev_ids) - len(meas_set),
        "candidate_reaches_baseline": reaches,
        "candidate_failures": _candidate_failures(rt_rows),
    }


def _post_development_state(inputs: dict) -> dict:
    """The fixes chosen after the development loop, derived from the committed failure plane."""
    fb = inputs["failures"]
    cand_specific = [r for r in (fb.get("failures") or [])
                     if r.get("disposition") == "candidate-specific"]
    fixes = [e for e in (fb.get("genealogy") or [])
             if e.get("fix_status") not in (None, "none") or e.get("fix_commit")
             or e.get("regression_court")]
    return {
        "candidate_specific_defects_found": len(cand_specific),
        "fixes_chosen": len(fixes),
        "fix_statuses": sorted({str(e.get("fix_status")) for e in (fb.get("genealogy") or [])}),
    }


def derive_learning_curve(inputs: dict, dev_members: list[dict], first_run: dict) -> dict:
    """The preserved learning curve: development first-run, holdout first-run, post-development."""
    return {
        "development_first_run": _development_summary(dev_members, inputs),
        "holdout_first_run": dict(first_run),
        "post_development_state": _post_development_state(inputs),
        "holdout_used_to_choose_a_patch": False,
        "atlas_scope": (
            "the committed 24.6 build/link and 24.7 runtime atlases are population-wide: they "
            "measured every frozen family under both subjects (a family with no admitted recipe is a "
            "cheap honest not_attempted row), so the candidate had been observed against the holdout "
            "families before this freeze. What the precommitment preserves -- and what 24.11 records "
            "-- is that no patch was chosen from any family (zero candidate-specific defects, zero "
            "fixes), so no holdout family influenced a fix, and the holdout's first_run is recorded "
            "here once and never rewritten"
        ),
    }


# ---------------------------------------------------------------------------------------------------
# the artefact
# ---------------------------------------------------------------------------------------------------

def _inputs_list() -> list[InputRef]:
    refs = [
        InputRef(name="holdout", path=HOLDOUT),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="runtime-functional-atlas", path=RUNTIME_FUNCTIONAL_ATLAS),
        InputRef(name="failures", path=FAILURES),
        InputRef(name="high-value-tier", path=HIGH_VALUE_TIER),
        InputRef(name="hostility-corpus", path=HOSTILITY_CORPUS),
        InputRef(name="container-manifest", path=CONTAINER_MANIFEST),
        InputRef(name="downstream-candidate-freeze",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_candidate_freeze.py"),
        InputRef(name="downstream-holdout",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_holdout.py"),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-runtime",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_runtime.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    return refs


def write_outputs(body: dict, authority_id: str) -> None:
    doc = envelope(kind="downstream-candidate-freeze", authority=authority_id,
                   inputs=_inputs_list(), body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


def _load_json(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("body", doc)


# ---------------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# ---------------------------------------------------------------------------------------------------

def load_inputs() -> dict:
    """Every committed input the derivation and the court re-read."""
    return {
        "holdout": _load_json(HOLDOUT),
        "families": _load_json(FAMILIES),
        "family_freeze": _load_json(FAMILY_FREEZE),
        "build_link": _load_json(BUILD_LINK_ATLAS),
        "runtime": _load_json(RUNTIME_FUNCTIONAL_ATLAS),
        "failures": _load_json(FAILURES),
        "high_value": _load_json(HIGH_VALUE_TIER),
        "hostility": _load_json(HOSTILITY_CORPUS),
    }


def _fix_source_findings(failures_body: dict, member_ids: set[str]) -> list[str]:
    """Whether the development-side failure plane used a holdout family to choose a patch (SS41)."""
    out: list[str] = []
    by_failure = {str(r.get("failure_id")): r for r in (failures_body.get("failures") or [])}
    for rec in failures_body.get("failures") or []:
        if (rec.get("disposition") == "candidate-specific"
                and str(rec.get("family_id")) in member_ids):
            out.append(f"the development-side failure plane carries a candidate-specific defect for a "
                       f"holdout family ({rec.get('family_id')}): the holdout must not be used to "
                       f"choose a patch")
    for edge in failures_body.get("genealogy") or []:
        chosen = (edge.get("fix_status") not in (None, "none") or bool(edge.get("fix_commit"))
                  or bool(edge.get("regression_court")))
        if not chosen:
            continue
        rec = by_failure.get(str(edge.get("failure_id"))) or {}
        fid = str(rec.get("family_id") or edge.get("family_id"))
        if fid in member_ids:
            out.append(f"a holdout family ({fid}) is cited as a source of a fix in the "
                       f"development-side failure plane: the holdout must not be used to choose a "
                       f"patch")
    return out


def candidate_freeze_findings(inputs: dict, body: dict) -> list[str]:
    """Every way the recorded candidate freeze and holdout run fail their own subject.

    Pure over the committed holdout partition, the committed families/frozen P1000, the committed
    failure plane and the live candidate install (its digests are re-read), so the court re-runs it
    without rebuilding and the sensitivity control can mutate an in-memory copy. Every check is a
    re-derivation: the frozen candidate identity reproduces from the committed install; the holdout
    set equals the precommitted partition and reproduces from the frozen rule, with a matching
    `partition_root_hash`; `first_run` is present, equals the summary derived from the holdout run and
    is attested unchanged by every rerun; every holdout family has an accounting row; a candidate row
    never claims a level above the authority-applicable baseline; a family's verdict is the derived
    one; `candidate_specific_patch_count` is 0; the counts are derived not typed; and no holdout
    family is a source of a fix in the development-side failure plane.
    """
    findings: list[str] = []
    holdout_body = inputs["holdout"]
    freeze_body = inputs["family_freeze"]
    members = holdout_members(holdout_body)
    member_ids = {str(m.get("family_id")) for m in members}

    # 1. The recorded rule and non-claims are the frozen ones.
    if body.get("rule") != RULE:
        findings.append("the recorded rule is not the frozen candidate-freeze rule")
    if body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the holdout "
                        "non-claim")

    # 2. The frozen candidate identity reproduces from the committed install. The recorded
    #    `source_commit` is provenance, not install identity, so it is excluded from the equality and
    #    from the hash (a live HEAD necessarily moves when this artefact's own commit lands); its
    #    existence is checked separately below.
    live = candidate_identity()
    recorded_ident = body.get("candidate_identity") or {}
    if identity_content(recorded_ident) != identity_content(live):
        findings.append("the frozen candidate identity does not reproduce from the committed "
                        f"install: recorded identity_hash "
                        f"{recorded_ident.get('identity_hash')!r} vs derived "
                        f"{live.get('identity_hash')!r}")
    if recorded_ident.get("identity_hash") != content_hash(identity_content(recorded_ident)):
        findings.append("candidate_identity.identity_hash does not reproduce from its own record")
    # The recorded source commit is provenance: it must name a commit that exists in this
    # repository's history (existence-checked with `git cat-file -e <sha>^{commit}`), and `unknown`
    # is acceptable only when git is genuinely absent from the venue. It is never compared to live
    # HEAD, so the artefact's own commit landing cannot make it wrong.
    recorded_commit = str(recorded_ident.get("source_commit") or "unknown")
    if recorded_commit == "unknown":
        if _git_present():
            findings.append("the recorded source_commit is 'unknown' while git is present in the "
                            "venue, so the provenance was not recorded")
    elif not _commit_exists(recorded_commit):
        findings.append(f"the recorded source_commit {recorded_commit!r} does not name a commit in "
                        f"this repository's history (git cat-file -e <sha>^{{commit}} failed)")

    # 3. The holdout set equals the precommitted partition and reproduces from the frozen rule.
    want_block = holdout_block(holdout_body)
    recorded_block = body.get("holdout") or {}
    if recorded_block.get("partition_root_hash") != holdout_body.get("partition_root_hash"):
        findings.append("the recorded partition_root_hash does not match the precommitted holdout "
                        "partition")
    if recorded_block.get("set_hash") != want_block["set_hash"]:
        findings.append("the recorded holdout set_hash does not equal the precommitted holdout set: "
                        "the holdout could have been re-selected after a candidate result")
    if recorded_block.get("family_count") != want_block["family_count"]:
        findings.append(f"the recorded holdout family_count {recorded_block.get('family_count')!r} "
                        f"is not the precommitted {want_block['family_count']}")
    if recorded_block.get("development_set_hash") != want_block["development_set_hash"]:
        findings.append("the recorded development set_hash does not equal the precommitted "
                        "development set")
    # The precommitted partition itself must reproduce from the frozen P1000 by the 24.5 rule.
    _derived_dev, derived_hol = ho.derive_partition(freeze_body)
    derived_ids = {str(m.get("family_id")) for m in derived_hol}
    if derived_ids != member_ids:
        findings.append("the precommitted holdout does not reproduce from the frozen P1000 by the "
                        "24.5 rule")

    # 4. The holdout run rows.
    run = body.get("holdout_run") or {}
    rows = run.get("runs") or []
    verdicts = run.get("verdicts") or []
    if not rows:
        return findings + ["the holdout run records no run"]
    seen_ids: set[str] = set()
    by_fs: dict[tuple[str, str], dict] = {}
    for row in rows:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        name = str(row.get("canonical_name"))
        findings += [f"{name}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_ids:
            findings.append(f"two holdout rows share run_id {rid!r}")
        seen_ids.add(rid)
        if fid not in member_ids:
            findings.append(f"{name}: a holdout run row is not a precommitted holdout member -- the "
                            f"holdout must be read from 24.5, never re-selected")
        by_fs[(fid, subject)] = row

        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{name}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")
        if not row.get("local_only"):
            findings.append(f"{name}/{subject}: a holdout row is not marked local-only")
        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted", "unavailable"):
            if not row.get("reason"):
                findings.append(f"{name}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{name}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{name}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")

        level_rank = RANK.get(str(row.get("level")), -1)
        if level_rank >= RANK[L5]:
            if not row.get("linkage_proven"):
                findings.append(f"{name}/{subject}: claims {row.get('level')} but its load/linkage "
                                f"is not proven")
            proof = row.get("load_proof") or {}
            if proof.get("proven") is not True:
                findings.append(f"{name}/{subject}: a {row.get('level')} row carries no proven load "
                                f"proof")
            if subject == "candidate" and row.get("resolved_under_authority"):
                findings.append(f"{name}/{subject}: a candidate {row.get('level')} row resolves the "
                                f"authority prefix")
        if level_rank >= RANK[L6]:
            ts = str(row.get("transcript_sha256") or "")
            if len(ts) != 64:
                findings.append(f"{name}/{subject}: a {row.get('level')} row has no non-empty "
                                f"transcript hash")
            norm = row.get("normalisation") or {}
            if norm.get("tag") != NORMALISATION_TAG:
                findings.append(f"{name}/{subject}: a {row.get('level')} row carries no normalisation "
                                f"tag")
            bad = [c for c in (norm.get("normalises") or []) if c not in NORMALISATION_ALLOWED]
            if bad:
                findings.append(f"{name}/{subject}: the normalisation erases evidence ({sorted(bad)})")

    # Every holdout family has both-subject runs, and the candidate never claims above the baseline.
    baseline = _baseline_map(rows)
    for m in members:
        fid, name = str(m.get("family_id")), str(m.get("canonical_name"))
        for subject in SUBJECTS:
            if (fid, subject) not in by_fs:
                findings.append(f"{name}: no {subject} holdout run")
    for row in rows:
        if row.get("subject") != "candidate":
            continue
        fid = str(row.get("family_id"))
        base = baseline.get(fid, L0)
        if str(row.get("authority_applicable_level")) != base:
            findings.append(f"{row.get('canonical_name')}/candidate: records "
                            f"authority_applicable_level {row.get('authority_applicable_level')!r}, "
                            f"but the authority rows reached {base!r}")
        if RANK.get(str(row.get("level")), -1) > RANK.get(base, -1):
            findings.append(f"{row.get('canonical_name')}/candidate: claims {row.get('level')}, above "
                            f"the authority-applicable baseline {base!r} the authority reached")
        want_reach = RANK.get(str(row.get("level")), -1) >= RANK.get(base, -1)
        if bool(row.get("reaches_baseline")) != want_reach:
            findings.append(f"{row.get('canonical_name')}/candidate: reaches_baseline is "
                            f"{row.get('reaches_baseline')!r}, but {row.get('level')!r} against "
                            f"{base!r} is {want_reach}")

    # 5. The verdicts are schema-valid and are the derived verdicts.
    cand = {str(r.get("family_id")): r for r in rows if r.get("subject") == "candidate"}
    verdict_by_family: dict[str, str] = {}
    seen_verdict_ids: set[str] = set()
    for rec in verdicts:
        findings += [f"verdict {rec.get('verdict_id')}: {p}"
                     for p in downstream_schemas.validate_drop_in_verdict(rec)]
        vid = str(rec.get("verdict_id"))
        if vid in seen_verdict_ids:
            findings.append(f"two verdicts share verdict_id {vid!r}")
        seen_verdict_ids.add(vid)
        fid = str(rec.get("family_id"))
        verdict_by_family[fid] = str(rec.get("verdict"))
        if fid not in member_ids:
            findings.append(f"{rec.get('verdict_id')}: a verdict is not a precommitted holdout "
                            f"member")
        want = derive_verdict_for(baseline.get(fid, L0), cand.get(fid))
        if str(rec.get("verdict")) != want:
            findings.append(f"{rec.get('verdict_id')}: verdict {rec.get('verdict')!r} is not the "
                            f"derived {want!r}")

    # 6. first_run is present, matches the holdout run, and every rerun attests it unchanged.
    first = body.get("first_run")
    if not isinstance(first, dict) or not first:
        return findings + ["the candidate freeze records no first_run summary"]
    derived_first = derive_first_run(members, rows, verdicts)
    if first != derived_first:
        findings.append("the recorded first_run does not equal the summary derived from the holdout "
                        "run: the first-run score was rewritten")
    for rr in body.get("reruns") or []:
        if str(rr.get("first_run_hash")) != content_hash(first):
            findings.append(f"rerun {rr.get('rerun_index')!r} does not attest the recorded first_run: "
                            f"first_run was rewritten after a rerun")

    # 7. Every holdout family has exactly one accounting row.
    accounting = body.get("accounting") or []
    acc_ids = [str(a.get("family_id")) for a in accounting]
    if len(set(acc_ids)) != len(acc_ids):
        findings.append("the accounting covers a holdout family more than once")
    acc_set = set(acc_ids)
    missing = sorted(member_ids - acc_set)
    if missing:
        findings.append(f"{len(missing)} holdout family(ies) have no accounting row "
                        f"(e.g. {missing[:3]})")
    extra = sorted(acc_set - member_ids)
    if extra:
        findings.append(f"the accounting carries a family outside the precommitted holdout set "
                        f"(e.g. {extra[:3]})")
    for a in accounting:
        fid = str(a.get("family_id"))
        if fid not in member_ids:
            continue
        want_sel = "measured" if RANK.get(baseline.get(fid, L0), -1) >= RANK[L4] else "venue_limited"
        if str(a.get("selection")) != want_sel:
            findings.append(f"{a.get('canonical_name')}: accounting selection {a.get('selection')!r} "
                            f"is not the derived {want_sel!r}")
        if want_sel == "venue_limited" and not a.get("reason"):
            findings.append(f"{a.get('canonical_name')}: a venue_limited holdout family carries no "
                            f"reason")

    # 8. Counts are read, not typed.
    derived_counts = derive_counts(members, rows, verdicts, accounting)
    recorded_counts = body.get("counts") or {}
    for key in ("holdout_families", "recipe_backed_families", "measurable_families",
                "venue_limited_families", "candidate_reaches_baseline",
                "candidate_specific_patch_count", "rows"):
        if recorded_counts.get(key) != derived_counts[key]:
            findings.append(f"counts.{key} {recorded_counts.get(key)!r} disagrees with the derived "
                            f"{derived_counts[key]!r}")
    if recorded_counts.get("accounting") != derived_counts["accounting"]:
        findings.append("counts.accounting disagrees with the derived accounting")
    if (recorded_counts.get("verdicts") or {}) != derived_counts["verdicts"]:
        findings.append("counts.verdicts disagrees with the derived verdicts")
    if (recorded_counts.get("candidate_failures") or {}) != derived_counts["candidate_failures"]:
        findings.append("counts.candidate_failures disagrees with the derived histogram")
    for subject in SUBJECTS:
        for rung in ("loaded", "runtime", "functional", "failed", "not_attempted"):
            got = (recorded_counts.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived_counts["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")

    # 9. The learning curve preserves first-run vs post-development, and no holdout family chose a fix.
    lc = body.get("learning_curve") or {}
    if lc.get("holdout_first_run") != first:
        findings.append("learning_curve.holdout_first_run is not the recorded first_run: the "
                        "first-run score was moved")
    if lc.get("holdout_used_to_choose_a_patch") is not False:
        findings.append("learning_curve records the holdout as used to choose a patch")
    findings += _fix_source_findings(inputs["failures"], member_ids)
    return findings


def _mutations(inputs: dict, body: dict) -> list[tuple[str, str, dict, dict]]:
    """`(name, needle, mutated_inputs, mutated_body)` for each seeded mutation."""
    out: list[tuple[str, str, dict, dict]] = []
    members = holdout_members(inputs["holdout"])
    dev = development_members(inputs["holdout"])
    run = body.get("holdout_run") or {}

    # (1) a precommitted holdout member swapped for a development member.
    m1 = copy.deepcopy(body)
    if members and dev:
        hol0 = members[0]
        swap = dev[0]
        for rec in m1["holdout_run"]["runs"]:
            if str(rec.get("family_id")) == str(hol0.get("family_id")):
                rec["family_id"] = str(swap.get("family_id"))
                rec["canonical_name"] = str(swap.get("canonical_name"))
        for rec in m1["accounting"]:
            if str(rec.get("family_id")) == str(hol0.get("family_id")):
                rec["family_id"] = str(swap.get("family_id"))
                rec["canonical_name"] = str(swap.get("canonical_name"))
        for rec in m1["holdout_run"]["verdicts"]:
            if str(rec.get("family_id")) == str(hol0.get("family_id")):
                rec["family_id"] = str(swap.get("family_id"))
    out.append(("holdout_member_swapped_for_development",
                "not a precommitted holdout member", inputs, m1))

    # (2) a mutated partition_root_hash.
    m2 = copy.deepcopy(body)
    m2["holdout"]["partition_root_hash"] = "0" * 64
    out.append(("mutated_partition_root", "partition_root_hash", inputs, m2))

    # (3) a first_run rewritten after a rerun that attests the original.
    m3 = copy.deepcopy(body)
    m3["reruns"] = list(m3.get("reruns") or []) + [{
        "rerun_index": len(m3.get("reruns") or []) + 1,
        "candidate_identity_hash": (body.get("candidate_identity") or {}).get("identity_hash"),
        "first_run_hash": content_hash(body.get("first_run")),
        "summary": body.get("first_run"),
    }]
    m3["first_run"] = dict(m3["first_run"], candidate_reaches_baseline=0)
    out.append(("first_run_rewritten_after_rerun", "first_run was rewritten after a rerun", inputs, m3))

    # (4) a candidate row claiming a level above the authority-applicable baseline, marked pass.
    m4 = copy.deepcopy(body)
    cand = next((r for r in m4["holdout_run"]["runs"] if r.get("subject") == "candidate"
                 and RANK.get(str(r.get("level")), -1) < RANK[L8]), None)
    if cand is not None:
        cand["level"] = L8
        cand["outcome"] = "reached"
        cand["residual_class"] = "none"
        cand["reaches_baseline"] = True
        for v in m4["holdout_run"]["verdicts"]:
            if str(v.get("family_id")) == str(cand.get("family_id")):
                v["verdict"] = "DROP_IN_PASS"
                v["candidate_level"] = L8
                v["linkage_proven"] = True
                v["residual_class"] = "none"
    out.append(("candidate_level_above_authority_baseline",
                "above the authority-applicable baseline", inputs, m4))

    # (5) a holdout family cited as a source of a fix in the development-side failure plane.
    mi = copy.deepcopy(inputs)
    if members:
        fid = str(members[0].get("family_id"))
        name = str(members[0].get("canonical_name"))
        fid2 = "failure:injected:holdout"
        mi["failures"]["failures"] = list(mi["failures"].get("failures") or []) + [{
            "failure_id": fid2, "family_id": fid, "consumer": name,
            "disposition": "candidate-specific", "class": "functional-failure",
        }]
        mi["failures"]["genealogy"] = list(mi["failures"].get("genealogy") or []) + [{
            "failure_id": fid2, "family_id": fid, "consumer": name, "fix_status": "fixed",
            "fix_commit": "deadbeef", "regression_court": "RT-INJECTED",
        }]
    out.append(("holdout_family_cited_as_fix", "must not be used to choose a patch", mi, body))

    # (6) a mutated count.
    m6 = copy.deepcopy(body)
    m6["counts"]["venue_limited_families"] = 0
    out.append(("mutated_count", "disagrees with the derived", inputs, m6))
    return out


def candidate_freeze_sensitivity_control(inputs: dict, body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each caught with specificity holding.

    The honest freeze must yield **zero** findings (specificity), and each seeded mutation -- a
    precommitted holdout member swapped for a development member, a mutated partition_root_hash, a
    first_run rewritten after a rerun, a candidate row claiming a level above the authority-applicable
    baseline marked pass, a holdout family cited as a source of a fix, and a mutated count -- must be
    caught with a finding naming it.
    """
    base = candidate_freeze_findings(inputs, body)
    control: dict = {"baseline_findings": len(base), "specificity_holds": not base}
    honest = not base
    for name, needle, mi, mb in _mutations(inputs, body):
        caught = any(needle in f for f in candidate_freeze_findings(mi, mb))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# ---------------------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------------------

def _load_all_inputs() -> dict:
    for path, what, sub in ((HOLDOUT, "holdout partition", "24.5"),
                            (FAMILY_FREEZE, "frozen P1000", "24.4"),
                            (FAMILIES, "families", "24.2"),
                            (BUILD_LINK_ATLAS, "build/link atlas", "24.6"),
                            (RUNTIME_FUNCTIONAL_ATLAS, "runtime/functional atlas", "24.7"),
                            (FAILURES, "failures plane", "24.8"),
                            (HIGH_VALUE_TIER, "high-value tier", "24.9"),
                            (HOSTILITY_CORPUS, "hostility corpus", "24.10")):
        if not path.is_file():
            raise SystemExit(f"[downstream-candidate-freeze] {rel(path)} is absent; run {sub} first")
    return load_inputs()


def _compose_body(inputs: dict, authority_id: str, measurement: dict, ident: dict,
                  existing: dict | None) -> dict:
    """Compose the artefact body, preserving an existing immutable first_run across a re-run."""
    holdout_body = inputs["holdout"]
    members = holdout_members(holdout_body)
    dev_members = development_members(holdout_body)
    rows, verdicts = measurement["runs"], measurement["verdicts"]
    accounting = derive_accounting(members, rows, verdicts)
    counts = derive_counts(members, rows, verdicts, accounting)
    measured_first = derive_first_run(members, rows, verdicts)

    reruns: list[dict] = []
    if existing and isinstance(existing.get("first_run"), dict) and existing["first_run"]:
        first_run = existing["first_run"]          # immutable: never overwritten
        reruns = list(existing.get("reruns") or [])
        reruns.append({
            "rerun_index": len(reruns) + 1,
            "candidate_identity_hash": ident["identity_hash"],
            "first_run_hash": content_hash(first_run),
            "summary": measured_first,
            "holdout_run": {"runs": rows, "verdicts": verdicts},
        })
        # The recorded holdout_run, accounting and learning curve stay the first run's, so a rerun
        # cannot move the first-run score; the new measurement is carried under `reruns`.
        holdout_run = existing.get("holdout_run") or {"runs": rows, "verdicts": verdicts,
                                                      "specimens": [], "variants": []}
        learning = existing.get("learning_curve") or derive_learning_curve(
            inputs, dev_members, first_run)
    else:
        first_run = measured_first
        holdout_run = {"runs": rows, "verdicts": verdicts,
                       "specimens": measurement["specimens"], "variants": measurement["variants"]}
        learning = derive_learning_curve(inputs, dev_members, first_run)

    return {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": measurement["authority_prefix"],
        "candidate_identity": ident,
        "holdout": holdout_block(holdout_body),
        "holdout_run": holdout_run,
        "accounting": accounting if not reruns else (existing.get("accounting") or accounting),
        "first_run": first_run,
        "reruns": reruns,
        "learning_curve": learning,
        "counts": counts if not reruns else (existing.get("counts") or counts),
        "resource_limits": measurement["limits"],
        "non_claims": NON_CLAIMS,
    }


def cmd_measure(authority_id: str) -> int:
    inputs = _load_all_inputs()
    members = holdout_members(inputs["holdout"])
    if len(members) != 200:
        print(f"[downstream-candidate-freeze] the precommitted holdout carries {len(members)} "
              f"family(ies), not the precommitted 200")
        return 1
    existing = _load_json(OUT) if OUT.is_file() else None
    ident = candidate_identity()
    print(f"[downstream-candidate-freeze] running the precommitted holdout ({len(members)} "
          f"families) against the frozen candidate {rel(CANDIDATE_PREFIX)} "
          f"(identity {ident['identity_hash'][:16]}..., version {ident['crate_version']}, commit "
          f"{ident['source_commit'][:12]})", flush=True)
    measurement = measure_holdout(members, authority_id)
    measurement["verdicts"] = derive_verdicts(members, measurement["runs"])
    body = _compose_body(inputs, authority_id, measurement, ident, existing)
    findings = candidate_freeze_findings(inputs, body)
    control = candidate_freeze_sensitivity_control(inputs, body)
    if findings or not control["honest"]:
        print("[downstream-candidate-freeze] the measured freeze fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    fr = body["first_run"]
    print(f"[downstream-candidate-freeze] holdout={c['holdout_families']} "
          f"recipe_backed={c['recipe_backed_families']} measurable={c['measurable_families']} "
          f"venue_limited={c['venue_limited_families']}")
    for subject in SUBJECTS:
        s = c["by_subject"][subject]
        print(f"  {subject:<9} loaded={s['loaded']} runtime={s['runtime']} "
              f"functional={s['functional']} failed={s['failed']} "
              f"not_attempted={s['not_attempted']}")
    print(f"  first_run: reaches_baseline={fr['candidate_reaches_baseline']} "
          f"verdicts={fr['verdicts']} candidate_failures={fr['candidate_failures']} "
          f"reruns={len(body['reruns'])}")
    print(f"  identity_hash={ident['identity_hash']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not OUT.is_file():
        print(f"[downstream-candidate-freeze] {rel(OUT)} is absent")
        return 1
    inputs = _load_all_inputs()
    body = _load_json(OUT)
    findings = candidate_freeze_findings(inputs, body)
    control = candidate_freeze_sensitivity_control(inputs, body)
    if findings:
        print(f"[downstream-candidate-freeze] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    print(f"[downstream-candidate-freeze] holdout={c.get('holdout_families')} "
          f"measurable={c.get('measurable_families')} "
          f"reaches_baseline={c.get('candidate_reaches_baseline')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_candidate_freeze.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_candidate_freeze.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. `candidate-freeze.json` is in the freeze's candidate-result artefact set, so a later freeze's
    #    scan excludes it exactly as it excludes the other post-freeze candidate artefacts.
    from downstream_freeze import CANDIDATE_RESULT_ARTEFACTS  # noqa: E402
    if "candidate-freeze.json" not in CANDIDATE_RESULT_ARTEFACTS:
        failures.append("candidate-freeze.json is not in downstream_freeze."
                        "CANDIDATE_RESULT_ARTEFACTS")

    # 3. The recipe/workload helpers are reused, not re-implemented.
    if not hasattr(bl, "measure_family") or not hasattr(rt, "_measure_subject_runtime"):
        failures.append("the 24.6/24.7 build/runtime machinery is not the imported one")

    # 4. The pure functions behave over the committed evidence.
    missing = [rel(p) for p in (HOLDOUT, FAMILY_FREEZE, BUILD_LINK_ATLAS, RUNTIME_FUNCTIONAL_ATLAS,
                                FAILURES, HIGH_VALUE_TIER, HOSTILITY_CORPUS)
               if not p.is_file()]
    if missing:
        failures.append(f"{', '.join(missing)} is absent")
    else:
        inputs = _load_all_inputs()
        if len(holdout_members(inputs["holdout"])) != 200:
            failures.append("the precommitted holdout does not carry 200 family(ies)")
        ident = candidate_identity()
        if ident["libssl_sha256"] == "unknown" or ident["crate_version"] == "unknown":
            failures.append("the candidate identity does not reproduce from the committed install")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            body = _load_json(OUT)
            findings = candidate_freeze_findings(inputs, body)
            if findings:
                failures.append(f"the committed freeze has findings: {findings[:3]}")
            control = candidate_freeze_sensitivity_control(inputs, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-candidate-freeze] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-candidate-freeze] self-test ok: the guard refuses a host invocation of this "
          "tool (marker and flag both named), the candidate identity reproduces from the committed "
          "install, the committed freeze reproduces with zero findings, and every seeded mutation (a "
          "holdout member swapped for a development member, a mutated partition root, a first_run "
          "rewritten after a rerun, a candidate level above the authority baseline, a holdout family "
          "cited as a fix source, and a mutated count) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the precommitted holdout against the frozen candidate (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed freeze without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches, compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
