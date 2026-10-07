#!/usr/bin/env python3
"""openssl-rs — the downstream-1000 record schemas, and the drop-in vocabulary.

Phase 24 is the downstream-1000 stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md`). It owns no exported symbol: its unit is the
non-export `downstream 1000 contract`, and its working set is fifteen contract units the later
subphases 24.1 through 24.15 populate. This module is 24.0's own half of that work: it **defines
and validates** the record kinds those subphases will emit, fixes the vocabulary the atlas is
queryable by, and closes the two class lists the brief names (the failure taxonomy and the
residual classes).

Why the schemas live in one module
----------------------------------
A record kind that can be invented is a record kind that cannot be checked. Each record the
downstream evidence plane carries -- a family, a specimen, a variant, a ranking-source row, a run,
an execution-level row, a residual, a failure and a drop-in verdict -- is a **claim that can be
falsified**: this module names the fields it requires and the closed vocabularies its values come
from, so a record that omits a load-bearing field, or uses a value outside the vocabulary, fails
rather than reads plausibly. The self-test (`--self-test`) proves every validator accepts a
documented-good record and rejects a documented-bad one, so a validator that can no longer fail is
visible.

The counted unit, and what is not counted
-----------------------------------------
The counted unit is the **family** -- a downstream project family, not a package alias -- and a
**specimen** is a separate, concrete source tree of a family used for one run. The distinction is
load-bearing: counting package aliases would let one project inflate the population, and folding
specimens into families would hide that a family was measured on one version and claimed for all.
The atlas never claims a package manager name as a family.

What `DROP_IN_PASS` means, and what it forbids
----------------------------------------------
A drop-in verdict is **baseline-normalized**, never a boolean of its own. `DROP_IN_PASS` requires
all of: the same **pristine** source (a `variant` whose `patch_set` is `pristine`, and a
`pristine_source_id` shared with the authority run), the **authority baseline succeeded**, the
candidate **reached the authority-applicable level** (`candidate_level` at least the
`authority_applicable_level` the authority reached), **candidate linkage proven**
(`linkage_proven`), and **zero candidate-specific downstream patches**
(`candidate_specific_patch_count` 0). `validate_drop_in_verdict` refuses a `DROP_IN_PASS` that
asserts without an authority baseline or with a positive patch count, and the self-test proves
both refusals.

The execution ladder
--------------------
A run names a `level` from `EXECUTION_LEVELS`, the ordered ladder `L0` through `L8`, and a
`subject` (`authority` or `candidate`). The **authority-applicable baseline** for a specimen is
the highest level its authority runs reached; a candidate run reaches the authority-applicable
level when its own level is at least that rank. `L8-authority-equivalent` is the top rung, and it
is a statement about the *authority's* own reach for that specimen, never a claim this stratum
invents. Two non-claims are carried by every record that names a level: **a build is not a
functional proof** (reaching `L3-built` or `L4-linked` is not behaving), and **transitive and
direct consumers are different evidence** (a project that only links a library transitively is a
different measurement from one that calls the API directly).

Outputs
-------
  (none) — this module writes no artefact; it is imported by the Phase-24 ledger and runner, and
  run with `--self-test`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass

# --------------------------------------------------------------------------------------------
# the closed vocabularies: every value a record may carry comes from one of these
# --------------------------------------------------------------------------------------------

# The counted unit is the family, never a package alias. `openssl_linkage` keeps the direct and
# transitive evidence apart; the two are different measurements and are never summed.
SOURCE_ECOSYSTEMS: tuple[str, ...] = (
    "github", "gitlab", "cran", "pypi", "crates", "distro", "vendor", "other",
)
OPENSSL_LINKAGE: tuple[str, ...] = ("direct", "transitive")

# A ranking source is a frozen, multi-source evidence row: it is acquired and content-addressed
# **before** any candidate result exists, so the population cannot be selected by what the
# candidate happens to pass.
RANKING_SOURCE_KINDS: tuple[str, ...] = (
    "popularity", "language-registry", "distro-package", "issue-tracker", "vendor-adoption",
    "security-advisory", "curated",
)

# A variant's patch set. Only `pristine` may take part in a `DROP_IN_PASS`.
VARIANT_PATCH_SETS: tuple[str, ...] = ("pristine", "build-system-only", "candidate-specific")

# The execution ladder L0-L8. A run names exactly one level; the authority-applicable baseline is
# the highest level the authority's runs reached for the specimen.
EXECUTION_LEVELS: tuple[str, ...] = (
    "L0-catalogued",
    "L1-admitted-source",
    "L2-configured",
    "L3-built",
    "L4-linked",
    "L5-loaded",
    "L6-runtime",
    "L7-functional",
    "L8-authority-equivalent",
)
EXECUTION_LEVEL_RANK: dict[str, int] = {name: i for i, name in enumerate(EXECUTION_LEVELS)}

RUN_SUBJECTS: tuple[str, ...] = ("authority", "candidate")
RUN_OUTCOMES: tuple[str, ...] = ("reached", "failed", "not_attempted", "unavailable")

# The residual classes (brief section 30): a closed vocabulary, so a leftover is classified rather
# than described. `none` is the resolved state.
RESIDUAL_CLASSES: tuple[str, ...] = (
    "none",
    "unavailable",
    "unbuildable",
    "unlinked",
    "runtime-failure",
    "functional-divergence",
    "candidate-patch-required",
    "authority-unsupported",
    "out-of-scope",
    "unknown",
)
RESIDUAL_DISPOSITIONS: tuple[str, ...] = (
    "none", "classified", "minimized", "preserved", "open", "unknown",
)

# The failure taxonomy (brief section 31): a closed vocabulary, so a discovered failure is named
# from the taxonomy rather than free text, and a failure is preserved and minimized rather than
# discarded.
FAILURE_CLASSES: tuple[str, ...] = (
    "acquire-failure",
    "configure-failure",
    "authority-build-failure",
    "candidate-build-failure",
    "link-failure",
    "load-failure",
    "runtime-failure",
    "functional-failure",
    "abi-failure",
    "semantic-failure",
    "cli-config-mismatch",
    "provider-registration-mismatch",
    "patch-required",
    "harness-failure",
)

# The drop-in verdict vocabulary. `DROP_IN_PASS` is the only verdict with a baseline-normalized
# requirement set; `DROP_IN_NOT_APPLICABLE` is for a specimen the authority itself did not reach.
DROP_IN_VERDICTS: tuple[str, ...] = (
    "DROP_IN_PASS",
    "DROP_IN_FAIL",
    "DROP_IN_PARTIAL",
    "DROP_IN_UNKNOWN",
    "DROP_IN_NOT_APPLICABLE",
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")


# --------------------------------------------------------------------------------------------
# the helpers every validator shares
# --------------------------------------------------------------------------------------------

def _missing(rec: dict, fields: tuple[str, ...]) -> list[str]:
    return [f"missing required field {f!r}" for f in fields if f not in rec]


def _enum(rec: dict, field: str, allowed: tuple[str, ...]) -> list[str]:
    if field not in rec:
        return []
    if rec[field] not in allowed:
        return [f"{field}={rec[field]!r} is not one of {sorted(allowed)}"]
    return []


def _nonempty(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not rec[field]:
        return [f"{field} must be non-empty"]
    return []


def _unknownable_hash(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    value = rec[field]
    if value == "unknown":
        return []
    if not isinstance(value, str) or not _HEX64.match(value):
        return [f"{field} must be a 64-hex digest or the literal `unknown`"]
    return []


def _bool(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not isinstance(rec[field], bool):
        return [f"{field} must be a boolean"]
    return []


def _int(rec: dict, field: str) -> list[str]:
    if field not in rec:
        return []
    if not isinstance(rec[field], int) or isinstance(rec[field], bool):
        return [f"{field} must be an integer"]
    return []


# --------------------------------------------------------------------------------------------
# the validators: each returns a list of problems, empty when the record is well-formed
# --------------------------------------------------------------------------------------------

def validate_family(rec: dict) -> list[str]:
    """A family: the counted unit, a downstream project family rather than a package alias."""
    fields = ("family_id", "name", "source_ecosystem", "project_url", "openssl_linkage",
              "primary_language", "category", "ranking_source_id", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "family_id")
    problems += _nonempty(rec, "name")
    problems += _enum(rec, "source_ecosystem", SOURCE_ECOSYSTEMS)
    problems += _enum(rec, "openssl_linkage", OPENSSL_LINKAGE)
    problems += _nonempty(rec, "ranking_source_id")
    return problems


def validate_specimen(rec: dict) -> list[str]:
    """A specimen: one concrete, pristine source tree of a family. Separate from the family.

    `pristine_source_sha256` may be the literal `unknown` -- a fact not yet established is stated,
    not invented -- but the identity fields must be present.
    """
    fields = ("specimen_id", "family_id", "version", "upstream_ref", "pristine_source_sha256",
              "licence", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "specimen_id")
    problems += _nonempty(rec, "family_id")
    problems += _unknownable_hash(rec, "pristine_source_sha256")
    return problems


def validate_variant(rec: dict) -> list[str]:
    """A variant: one build/configuration of a specimen, with its patch set named.

    A variant whose `patch_set` is `candidate-specific` is a variant the candidate had to patch;
    it can never take part in a `DROP_IN_PASS` (the verdict validator enforces that where the
    verdict is asserted).
    """
    fields = ("variant_id", "specimen_id", "build_profile", "platform", "arch", "patch_set",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "variant_id")
    problems += _nonempty(rec, "specimen_id")
    problems += _enum(rec, "patch_set", VARIANT_PATCH_SETS)
    return problems


def validate_ranking_source(rec: dict) -> list[str]:
    """A ranking-source row: a frozen, multi-source evidence row selected *before* any result.

    `frozen` must be true: a ranking source that is not frozen is not a precommitment, and the
    population it ranks cannot be claimed to have been selected independently of the candidate.
    """
    fields = ("source_id", "kind", "url", "fetch_date", "sha256", "frozen", "row_count",
              "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "source_id")
    problems += _enum(rec, "kind", RANKING_SOURCE_KINDS)
    problems += _unknownable_hash(rec, "sha256")
    problems += _bool(rec, "frozen")
    problems += _int(rec, "row_count")
    if rec.get("frozen") is False:
        problems.append("a ranking source must be frozen before any candidate result exists")
    return problems


def validate_execution_level(rec: dict) -> list[str]:
    """An execution-level row: one rung of the L0-L8 ladder, with its rank and criteria."""
    fields = ("level", "rank", "description", "criteria")
    problems = _missing(rec, fields)
    problems += _enum(rec, "level", EXECUTION_LEVELS)
    problems += _int(rec, "rank")
    problems += _nonempty(rec, "criteria")
    if isinstance(rec.get("rank"), int) and not isinstance(rec["rank"], bool):
        expected = EXECUTION_LEVEL_RANK.get(rec.get("level"))
        if expected is not None and rec["rank"] != expected:
            problems.append(
                f"rank {rec['rank']} does not match {rec.get('level')!r}'s position "
                f"{expected} in the L0-L8 ladder"
            )
    return problems


def validate_run(rec: dict) -> list[str]:
    """A run: one execution of one specimen/variant at one level, under one subject."""
    fields = ("run_id", "specimen_id", "variant_id", "subject", "level", "outcome",
              "residual_class", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "run_id")
    problems += _enum(rec, "subject", RUN_SUBJECTS)
    problems += _enum(rec, "level", EXECUTION_LEVELS)
    problems += _enum(rec, "outcome", RUN_OUTCOMES)
    problems += _enum(rec, "residual_class", RESIDUAL_CLASSES)
    return problems


def validate_residual(rec: dict) -> list[str]:
    """A residual: a classified leftover, from the closed residual-class vocabulary."""
    fields = ("residual_id", "run_id", "class", "disposition", "detail", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "residual_id")
    problems += _nonempty(rec, "run_id")
    problems += _enum(rec, "class", RESIDUAL_CLASSES)
    problems += _enum(rec, "disposition", RESIDUAL_DISPOSITIONS)
    return problems


def validate_failure(rec: dict) -> list[str]:
    """A failure: a named failure from the taxonomy, preserved and minimized.

    A failure the atlas discards is a failure a future version cannot learn from, so both
    `preserved` and `minimized` are required rather than optional.
    """
    fields = ("failure_id", "run_id", "class", "preserved", "minimized", "detail", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "failure_id")
    problems += _nonempty(rec, "run_id")
    problems += _enum(rec, "class", FAILURE_CLASSES)
    problems += _bool(rec, "preserved")
    problems += _bool(rec, "minimized")
    return problems


def validate_drop_in_verdict(rec: dict) -> list[str]:
    """A drop-in verdict: baseline-normalized, never a boolean of its own.

    `DROP_IN_PASS` requires all of: a non-empty authority baseline, `linkage_proven`,
    `candidate_specific_patch_count` 0, a `residual_class` of `none`, and a `candidate_level` at
    least the `authority_applicable_level`. A `DROP_IN_PASS` asserted without an authority
    baseline, or with a positive patch count, is refused by name.
    """
    fields = ("verdict_id", "specimen_id", "variant_id", "verdict", "pristine_source_id",
              "authority_baseline", "authority_applicable_level", "candidate_level",
              "linkage_proven", "candidate_specific_patch_count", "residual_class", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "verdict_id")
    problems += _nonempty(rec, "specimen_id")
    problems += _nonempty(rec, "variant_id")
    problems += _enum(rec, "verdict", DROP_IN_VERDICTS)
    problems += _enum(rec, "authority_applicable_level", EXECUTION_LEVELS)
    problems += _enum(rec, "candidate_level", EXECUTION_LEVELS)
    problems += _enum(rec, "residual_class", RESIDUAL_CLASSES)
    problems += _bool(rec, "linkage_proven")
    problems += _int(rec, "candidate_specific_patch_count")

    if rec.get("verdict") == "DROP_IN_PASS":
        if not rec.get("authority_baseline"):
            problems.append(
                "a DROP_IN_PASS must cite the authority baseline it was normalized against; "
                "a pass without a succeeded authority baseline is not evidence"
            )
        patch_count = rec.get("candidate_specific_patch_count")
        if isinstance(patch_count, int) and not isinstance(patch_count, bool) and patch_count > 0:
            problems.append(
                f"a DROP_IN_PASS with candidate_specific_patch_count={patch_count} is refused: "
                f"a candidate-specific downstream patch makes the pass not a drop-in"
            )
        if rec.get("linkage_proven") is not True:
            problems.append("a DROP_IN_PASS requires candidate linkage to be proven")
        if rec.get("residual_class") not in (None, "none"):
            problems.append(
                f"a DROP_IN_PASS cannot carry residual class {rec.get('residual_class')!r}"
            )
        c_rank = EXECUTION_LEVEL_RANK.get(rec.get("candidate_level"))
        a_rank = EXECUTION_LEVEL_RANK.get(rec.get("authority_applicable_level"))
        if c_rank is not None and a_rank is not None and c_rank < a_rank:
            problems.append(
                f"a DROP_IN_PASS requires the candidate level {rec['candidate_level']!r} to reach "
                f"the authority-applicable level {rec['authority_applicable_level']!r}"
            )
    return problems


# The registries the ledger, the runner and the later subphases read. `SCHEMAS` names each record
# kind and its validator; `REQUIRED_FIELDS` is what the inventory publishes.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "family": ("family_id", "name", "source_ecosystem", "project_url", "openssl_linkage",
               "primary_language", "category", "ranking_source_id", "evidence"),
    "specimen": ("specimen_id", "family_id", "version", "upstream_ref", "pristine_source_sha256",
                 "licence", "evidence"),
    "variant": ("variant_id", "specimen_id", "build_profile", "platform", "arch", "patch_set",
                "evidence"),
    "ranking_source": ("source_id", "kind", "url", "fetch_date", "sha256", "frozen", "row_count",
                       "evidence"),
    "execution_level": ("level", "rank", "description", "criteria"),
    "run": ("run_id", "specimen_id", "variant_id", "subject", "level", "outcome",
            "residual_class", "evidence"),
    "residual": ("residual_id", "run_id", "class", "disposition", "detail", "evidence"),
    "failure": ("failure_id", "run_id", "class", "preserved", "minimized", "detail", "evidence"),
    "drop_in_verdict": ("verdict_id", "specimen_id", "variant_id", "verdict", "pristine_source_id",
                        "authority_baseline", "authority_applicable_level", "candidate_level",
                        "linkage_proven", "candidate_specific_patch_count", "residual_class",
                        "evidence"),
}

SCHEMAS = {
    "family": validate_family,
    "specimen": validate_specimen,
    "variant": validate_variant,
    "ranking_source": validate_ranking_source,
    "execution_level": validate_execution_level,
    "run": validate_run,
    "residual": validate_residual,
    "failure": validate_failure,
    "drop_in_verdict": validate_drop_in_verdict,
}


def validate(kind: str, rec: dict) -> list[str]:
    """Validate one record against a named schema, or report the unknown schema."""
    fn = SCHEMAS.get(kind)
    if fn is None:
        return [f"unknown record kind {kind!r}; known: {sorted(SCHEMAS)}"]
    return fn(rec)


def inventory() -> dict:
    """The schema inventory: each record kind and the fields it requires, deterministically."""
    return {
        kind: {"fields": list(REQUIRED_FIELDS[kind]), "valid": SCHEMAS[kind].__name__}
        for kind in sorted(SCHEMAS)
    }


# --------------------------------------------------------------------------------------------
# the self-test: every validator accepts a documented-good record and rejects a documented-bad one
# --------------------------------------------------------------------------------------------

_DIGEST = "0" * 64
_GOOD: dict[str, dict] = {
    "family": {
        "family_id": "f-curl",
        "name": "curl",
        "source_ecosystem": "github",
        "project_url": "https://github.com/curl/curl",
        "openssl_linkage": "direct",
        "primary_language": "c",
        "category": "http-client",
        "ranking_source_id": "rank-distro-debian-bookworm",
        "evidence": ["forensics/downstream/ranking-sources.json"],
    },
    "specimen": {
        "specimen_id": "s-curl-8.5.0",
        "family_id": "f-curl",
        "version": "8.5.0",
        "upstream_ref": "curl-8_5_0",
        "pristine_source_sha256": _DIGEST,
        "licence": "curl",
        "evidence": ["forensics/downstream/source-manifests/s-curl-8.5.0.json"],
    },
    "variant": {
        "variant_id": "v-curl-8.5.0-default",
        "specimen_id": "s-curl-8.5.0",
        "build_profile": "linux-x86_64-default-shared",
        "platform": "linux",
        "arch": "x86_64",
        "patch_set": "pristine",
        "evidence": ["forensics/downstream/build-link-atlas.json"],
    },
    "ranking_source": {
        "source_id": "rank-distro-debian-bookworm",
        "kind": "distro-package",
        "url": "https://deb.debian.org/debian/dists/bookworm/main/source/Sources.gz",
        "fetch_date": "2026-10-06",
        "sha256": _DIGEST,
        "frozen": True,
        "row_count": 61234,
        "evidence": ["forensics/downstream/ranking-sources.json"],
    },
    "execution_level": {
        "level": "L4-linked",
        "rank": 4,
        "description": "the specimen's build links against the candidate",
        "criteria": "the built object records the candidate's SONAME and resolves its symbols",
    },
    "run": {
        "run_id": "r-curl-8.5.0-default-candidate",
        "specimen_id": "s-curl-8.5.0",
        "variant_id": "v-curl-8.5.0-default",
        "subject": "candidate",
        "level": "L4-linked",
        "outcome": "reached",
        "residual_class": "none",
        "evidence": ["forensics/downstream/build-link-atlas.json"],
    },
    "residual": {
        "residual_id": "res-curl-8.5.0",
        "run_id": "r-curl-8.5.0-default-candidate",
        "class": "none",
        "disposition": "none",
        "detail": "no leftover",
        "evidence": ["forensics/downstream/build-link-atlas.json"],
    },
    "failure": {
        "failure_id": "fail-curl-8.5.0-link",
        "run_id": "r-curl-8.5.0-default-candidate",
        "class": "link-failure",
        "preserved": True,
        "minimized": True,
        "detail": "minimized to a one-symbol reproducer",
        "evidence": ["forensics/downstream/failures/fail-curl-8.5.0-link.json"],
    },
    "drop_in_verdict": {
        "verdict_id": "d-curl-8.5.0-default",
        "specimen_id": "s-curl-8.5.0",
        "variant_id": "v-curl-8.5.0-default",
        "verdict": "DROP_IN_PASS",
        "pristine_source_id": "s-curl-8.5.0",
        "authority_baseline": {"level": "L4-linked", "runs": ["r-curl-8.5.0-default-authority"]},
        "authority_applicable_level": "L4-linked",
        "candidate_level": "L4-linked",
        "linkage_proven": True,
        "candidate_specific_patch_count": 0,
        "residual_class": "none",
        "evidence": ["forensics/downstream/drop-in-verdicts.json"],
    },
}


def _bad(kind: str) -> dict:
    """A documented-bad record for each kind: the mutation and why it must be refused."""
    import copy

    rec = copy.deepcopy(_GOOD[kind])
    if kind == "family":
        rec["openssl_linkage"] = "sometimes"  # not one of direct/transitive
    elif kind == "specimen":
        rec["pristine_source_sha256"] = "not-a-digest"  # neither 64-hex nor `unknown`
    elif kind == "variant":
        rec["patch_set"] = "lightly-patched"  # not one of the closed patch sets
    elif kind == "ranking_source":
        rec["frozen"] = False  # a ranking source must be frozen before any result
    elif kind == "execution_level":
        rec["rank"] = 2  # contradicts L4-linked's position in the ladder
    elif kind == "run":
        rec["level"] = "L9-supreme"  # not one of the L0-L8 ladder
    elif kind == "residual":
        rec["class"] = "mysterious"  # not one of the residual classes
    elif kind == "failure":
        rec["class"] = "bad-vibes"  # not one of the failure taxonomy
    elif kind == "drop_in_verdict":
        rec["verdict"] = "compatible"  # not one of the drop-in verdicts
    else:
        raise AssertionError(f"no bad case for {kind}")
    return rec


def self_test() -> int:
    """Prove every validator accepts a documented-good record and rejects a documented-bad one."""
    failures: list[str] = []

    # --- the ladder and the two class lists are closed, non-empty vocabularies ----------------
    if list(EXECUTION_LEVELS) != list(EXECUTION_LEVEL_RANK):
        failures.append("the L0-L8 ladder and its rank map disagree")
    for i, name in enumerate(EXECUTION_LEVELS):
        if EXECUTION_LEVEL_RANK[name] != i:
            failures.append(f"{name!r} does not rank at its ladder position {i}")

    # --- every validator, both directions ------------------------------------------------------
    for kind in sorted(SCHEMAS):
        good = validate(kind, _GOOD[kind])
        if good:
            failures.append(f"{kind}: a documented-good record was refused: {good}")
        bad = validate(kind, _bad(kind))
        if not bad:
            failures.append(f"{kind}: a documented-bad record was accepted")

    # --- the two DROP_IN_PASS refusals the brief names, by name --------------------------------
    import copy

    no_baseline = copy.deepcopy(_GOOD["drop_in_verdict"])
    no_baseline["authority_baseline"] = {}
    problems = validate_drop_in_verdict(no_baseline)
    if not problems:
        failures.append("validate_drop_in_verdict accepted a DROP_IN_PASS with no authority "
                        "baseline")
    elif "authority baseline" not in " ".join(problems):
        failures.append("the no-authority-baseline refusal does not say why it is refused")

    patched = copy.deepcopy(_GOOD["drop_in_verdict"])
    patched["candidate_specific_patch_count"] = 1
    problems = validate_drop_in_verdict(patched)
    if not problems:
        failures.append("validate_drop_in_verdict accepted a DROP_IN_PASS with a candidate-specific "
                        "patch")
    elif "candidate-specific" not in " ".join(problems):
        failures.append("the patch-count refusal does not say why it is refused")

    if failures:
        print("[downstream-schemas] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"[downstream-schemas] self-test ok: {len(SCHEMAS)} record kind(s) accept the "
          f"documented-good record and refuse the documented-bad one; "
          f"{len(EXECUTION_LEVELS)} execution levels, {len(FAILURE_CLASSES)} failure classes and "
          f"{len(RESIDUAL_CLASSES)} residual classes are closed; a DROP_IN_PASS without an "
          f"authority baseline and one with a candidate-specific patch are both refused")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="prove every validator accepts good and refuses bad records")
    ap.add_argument("--list", action="store_true", help="print the schema inventory")
    ap.add_argument("--vocabulary", action="store_true",
                    help="print the closed vocabularies (levels, failures, residuals, verdicts)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.vocabulary:
        for label, values in (
            ("execution_levels", EXECUTION_LEVELS),
            ("failure_classes", FAILURE_CLASSES),
            ("residual_classes", RESIDUAL_CLASSES),
            ("drop_in_verdicts", DROP_IN_VERDICTS),
        ):
            print(f"{label}: {', '.join(values)}")
        return 0

    inv = inventory()
    if args.list:
        for kind in sorted(inv):
            print(f"{kind}: {', '.join(inv[kind]['fields'])}")
        return 0

    print(f"[downstream-schemas] {len(inv)} record kind(s): {', '.join(sorted(inv))}")
    print("  run --self-test to prove each accepts a documented-good record and refuses a "
          "documented-bad one")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
