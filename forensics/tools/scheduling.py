#!/usr/bin/env python3
"""Scheduling as an executable policy (ETP-T11).

The problem this tool exists for
--------------------------------
The verification schedule in `AGENTS.md` is a table of tiers. A table is a
preference unless something computes it. In practice a change was described as
"FAST" or "BATCH" because that is what the author believed, and a requirement
that was not run was recorded as context rather than as a gap. This tool makes
three of those decisions executable and one of them impossible:

* the **tier** a change set requires is derived from the changed paths, the
  build inputs, the tools that derive evidence, the instrument register, the
  venue, the shared mechanisms and the exported ABI — never from preference;
* the **evidence** a tier requires is a fixed set of named checks, and every
  check reports `SATISFIED`, `NOT_RUN`, `FAILED`, `BLOCKED` or `REFUSED`;
* a recorded result is **reused only at its full applicability identity**
  (source, tool, instrument, target/profile, population), so a changed tool
  version, a changed population or a changed profile recomputes rather than
  reuses, and an incomplete identity never reuses at all;
* a run that hits a memory, time or disk bound is **`BLOCKED`** with the bound
  and the observed value. It is never `PASS` and it is never reported as a
  deferral.

The rule table is data (`RULES`), printed by `rules`, and exercised by the
controls in `forensics/tools/tests/test_scheduling.py`. A rule that no control
can reach is a rule that does not decide anything.

What this tool does not decide
------------------------------
It does not run the checks it names. It does not decide whether a cached result
is true of the candidate, only whether the result is bound to the exact identity
it is read as describing. It does not turn a `NOT_RUN` into a `PASS`, and it
does not infer that an unclassified path is documentation: an unclassified path
is scheduled at `BATCH` because it might be an input. `EXTERNAL` is in the tier
vocabulary but is never derived from a change set: handing a candidate to an
external reproducer is a declared act, and a diff cannot perform it.

Exit codes (failure is always non-zero)
---------------------------------------
  0  a proven success: `cache-get` hit with `PASS`, or an aggregate whose
     every required check is `SATISFIED`, or a listing (`tier`, `rules`,
     `require` without an evaluated change set)
  1  an aggregate that is `NOT_RUN`, `FAILED` or `REFUSED`
  2  a refusal: malformed input, an unresolvable commit, an incomplete or
     unbound identity, a cache entry that cannot be admitted
  3  `cache-get` miss (no entry for this exact identity)
  4  `BLOCKED`: a resource bound was hit, or a `BLOCKED` result is in the
     aggregate. `BLOCKED` outranks every other aggregate state
  5  `cache-get` hit with `FAILED`

Determinism
-----------
No timestamp is written, every list is sorted on a documented key, and the same
inputs produce byte-identical output. A cache entry carries the digest of its
own identity and is re-validated on read, so a hand-edited entry is refused
rather than reused.

Python 3.11 standard library only.

Usage
-----
    python3 forensics/tools/scheduling.py tier --base A --head B
    python3 forensics/tools/scheduling.py tier --paths-file PATHS
    python3 forensics/tools/scheduling.py rules
    python3 forensics/tools/scheduling.py require --tier BATCH
    python3 forensics/tools/scheduling.py require --tier BOUNDARY \
        --runs evidence/etp-t11/RUNS.json --store evidence/etp-t11/CACHE.json \
        --change-set cs-example
    python3 forensics/tools/scheduling.py cache-put --check FAST_FMT \
        --identity ID.json --result PASS --memory-bound-mib 6144 \
        --memory-observed-mib 37 --time-bound-s 900 --time-observed-s 12.5 \
        --disk-bound-mib 4096 --disk-observed-mib 3
    python3 forensics/tools/scheduling.py cache-get --check FAST_FMT --identity ID.json
    python3 forensics/tools/scheduling.py identity --source-commit HEAD \
        --tool-path forensics/tools/scheduling.py --population-file POP.json \
        --out ID.json
    python3 forensics/tools/scheduling.py report \
        --change-sets evidence/etp-t11/CHANGE-SETS.json \
        --runs evidence/etp-t11/RUNS.json --store evidence/etp-t11/CACHE.json \
        --out evidence/etp-t11/TIERS.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import freshness  # noqa: E402  (the change classifier and Git reader, reused)

SCHEMA = "openssl-rs/etp/scheduling/1"
CACHE_SCHEMA = "openssl-rs/etp/scheduling-cache/1"
RUNS_SCHEMA = "openssl-rs/etp/scheduling-runs/1"
SETS_SCHEMA = "openssl-rs/etp/scheduling-change-sets/1"

ITEM = "ETP-T11"

# ---------------------------------------------------------------------------
# Tiers and the evidence each one requires
# ---------------------------------------------------------------------------

# Ordered from cheapest to most expensive. `EXTERNAL` is a declared promotion,
# never a change-set decision; see the module docstring.
TIERS = ("FAST", "BATCH", "BOUNDARY", "SEAL", "EXTERNAL")
TIER_RANK = {tier: index for index, tier in enumerate(TIERS)}

# Every check has one stable identifier. The identifier is what a recorded
# result is cached under, so renaming one invalidates the cache by design.
CHECK_INFO: dict[str, dict[str, str]] = {
    "FAST_FMT": {
        "tier": "FAST",
        "requirement": "cargo fmt --all -- --check",
    },
    "FAST_CLIPPY": {
        "tier": "FAST",
        "requirement": "a clippy check of the touched targets",
    },
    "FAST_FOCUSED_TESTS": {
        "tier": "FAST",
        "requirement": "name-filtered tests for the changed units",
    },
    "FAST_STRUCTURAL_GUARDS": {
        "tier": "FAST",
        "requirement": (
            "structural guards: allocator seam at the authority's size/file/line, "
            "#[repr(C)] layouts, exported symbols, unsafe lint attributes and a "
            "SAFETY contract for every new unsafe operation"
        ),
    },
    "BATCH_SUITE_SERIAL": {
        "tier": "BATCH",
        "requirement": "the full library suite, serially",
    },
    "BATCH_SUITE_PARALLEL": {
        "tier": "BATCH",
        "requirement": "the full library suite with --test-threads=4",
    },
    "BATCH_CLIPPY": {
        "tier": "BATCH",
        "requirement": "cargo clippy --all-targets -- -D warnings",
    },
    "BATCH_AFFECTED_PROBES": {
        "tier": "BATCH",
        "requirement": "the affected adversarial probes",
    },
    "BATCH_AFFECTED_COURTS": {
        "tier": "BATCH",
        "requirement": "the affected compatibility courts",
    },
    "BATCH_RECEIPT": {
        "tier": "BATCH",
        "requirement": "a compact receipt committed with the batch",
    },
    "BOUNDARY_INDEPENDENT_AUDIT": {
        "tier": "BOUNDARY",
        "requirement": "an independent caller and dependency-closure audit",
    },
    "BOUNDARY_MODEL_CONTROLS": {
        "tier": "BOUNDARY",
        "requirement": "targeted model controls (Miri/Loom/mutation) on the changed boundary",
    },
    "BOUNDARY_SANITIZER_CONTROLS": {
        "tier": "BOUNDARY",
        "requirement": "targeted sanitizer controls (ASan/TSan) on the changed boundary",
    },
    "BOUNDARY_AUTHORITY_DIFFERENTIAL": {
        "tier": "BOUNDARY",
        "requirement": "an authority differential for every changed semantic",
    },
    "BOUNDARY_NEGATIVE_CONTROL": {
        "tier": "BOUNDARY",
        "requirement": "a negative control showing the instrument fires",
    },
    "BOUNDARY_REVIEWER_INDEPENDENCE": {
        "tier": "BOUNDARY",
        "requirement": "a reviewer that is not the author",
    },
    "SEAL_DEPENDENCY_CLOSURE": {
        "tier": "SEAL",
        "requirement": "the full applicable dependency closure",
    },
    "SEAL_PROBE_SUITE": {
        "tier": "SEAL",
        "requirement": "the complete probe suite",
    },
    "SEAL_FORENSIC_REGENERATION": {
        "tier": "SEAL",
        "requirement": "full forensic regeneration",
    },
    "SEAL_HELD_OUT_COMPAT": {
        "tier": "SEAL",
        "requirement": (
            "held-out and broad compatibility and cryptographic assurance against "
            "the exact candidate"
        ),
    },
    "SEAL_INDEPENDENT_REVIEW": {
        "tier": "SEAL",
        "requirement": "independent review of the claim and its evidence",
    },
    "SEAL_REPRODUCIBILITY": {
        "tier": "SEAL",
        "requirement": "a reproducible rebuild from the frozen source candidate",
    },
    "EXTERNAL_REPRODUCTION": {
        "tier": "EXTERNAL",
        "requirement": "reproduction by an independent venue from the published bundle",
    },
    "EXTERNAL_BUNDLE": {
        "tier": "EXTERNAL",
        "requirement": "the published source, binary and identity bundle",
    },
    "EXTERNAL_VENUE_IDENTITY": {
        "tier": "EXTERNAL",
        "requirement": "the external venue's identity and toolchain recorded",
    },
}


def required_checks(tier: str, cumulative: bool = True) -> list[dict[str, Any]]:
    """The checks a tier requires.

    Requirements accumulate: a `BOUNDARY` change that never ran `fmt` is not a
    `BOUNDARY` change with a smaller requirement, it is an incomplete one. The
    `from_tier` field names the tier that introduced each check.
    """
    if tier not in TIERS:
        raise SchedulingRefusal("SC_UNKNOWN_TIER", f"unknown tier {tier!r}")
    limit = TIER_RANK[tier]
    rows: list[dict[str, Any]] = []
    for check, info in CHECK_INFO.items():
        rank = TIER_RANK[info["tier"]]
        if rank == limit or (cumulative and rank < limit):
            rows.append({"check": check, "from_tier": info["tier"], "requirement": info["requirement"]})
    return sorted(rows, key=lambda row: (TIER_RANK[row["from_tier"]], row["check"]))


# ---------------------------------------------------------------------------
# The rule table: change class -> minimum tier
# ---------------------------------------------------------------------------

# Reusable ownership/unsafe abstractions, from `AGENTS.md` section 1, plus the
# stack (`OPENSSL_sk_*`, carried by almost every public collection) and the FFI
# layer. A change here can alter an obligation that many mechanisms rely on, so
# it requires the independent audit the `BOUNDARY` tier names.
SHARED_MECHANISMS = (
    "src/asn1/owned.rs",
    "src/ec/smpl.rs",
    "src/evp/digest.rs",
    "src/evp/e_aes.rs",
    "src/evp/pkey_ctx.rs",
    "src/hpke/mod.rs",
    "src/pem/pvkfmt.rs",
    "src/provider/cipher.rs",
    "src/provider/kdf.rs",
    "src/runtime/bio/owned.rs",
    "src/runtime/stack.rs",
    "src/ssl/ssl_lib.rs",
    "src/ssl/statem/statem_srvr.rs",
    "src/store/store_lib.rs",
    "src/ui/ui_lib.rs",
    "src/x509/v3_utl.rs",
)

SHARED_MECHANISM_PREFIXES = ("src/ffi/",)

# The exported-symbol version script defines the ABI every consumer links
# against. Changing it changes the artefact a consumer was measured against.
EXPORTED_ABI = "artifacts/phase2/libcrypto.ld"

# A claim document change that adds or removes a `SAFE_COMPATIBLE` assertion
# changes a consumer's graduation state, which is a `SEAL` question rather than
# an evidence edit.
CLAIMS_DOCUMENT = "evidence/etp/claims.json"
GRADUATION_MARKER = "SAFE_COMPATIBLE"


@dataclass(frozen=True)
class Rule:
    """One row of the rule table.

    `match` is the kind of predicate, not a description: the implementation is
    `_rule_matches`, and `rules` prints this table so a document and the code
    can be compared rather than trusted.
    """

    id: str
    tier: str
    match: str
    value: str
    why: str
    class_name: str


RULES: tuple[Rule, ...] = (
    Rule(
        "SC_RULE_EXPORTED_ABI",
        "SEAL",
        "exact",
        EXPORTED_ABI,
        "the exported-symbol version script defines the ABI every consumer links "
        "against; a consumer measurement is only meaningful against the exact "
        "artefact it was taken from",
        "exported_abi",
    ),
    Rule(
        "SC_RULE_GRADUATION_CLAIM",
        "SEAL",
        "graduation_claim",
        CLAIMS_DOCUMENT,
        "a change to the claim document that adds or removes a SAFE_COMPATIBLE "
        "assertion changes a consumer family's graduation state, which requires "
        "the full closure and the held-out compatibility evidence",
        "graduation_claim",
    ),
    Rule(
        "SC_RULE_SHARED_MECHANISM",
        "BOUNDARY",
        "shared_mechanism",
        "",
        "a reusable ownership or unsafe abstraction that other mechanisms depend "
        "on; its contract, not only its code, is what changed",
        "shared_mechanism",
    ),
    Rule(
        "SC_RULE_INSTRUMENT",
        "BOUNDARY",
        "prefix",
        "evidence/etp3/",
        "the instrument register and the harnesses it names: every result produced "
        "with the instrument is bound to its identity",
        "instrument",
    ),
    Rule(
        "SC_RULE_INDEPENDENCE",
        "BOUNDARY",
        "prefix",
        "evidence/etp-t6/",
        "the trusted computing base and independence records: a change can "
        "invalidate an independence claim that is not otherwise observable",
        "independence",
    ),
    Rule(
        "SC_RULE_VENUE",
        "BOUNDARY",
        "venue",
        "",
        "the court image, launcher and entrypoint that supplied the environment of "
        "every measurement",
        "venue",
    ),
    Rule(
        "SC_RULE_BUILD_INPUT",
        "BATCH",
        "build",
        "",
        "a build input shapes the binary, so every binary-derived measurement "
        "must be recomputed",
        "build",
    ),
    Rule(
        "SC_RULE_TOOL",
        "BATCH",
        "tool",
        "",
        "a tool that derives or checks evidence: its own tests and the evidence it "
        "produced are invalidated",
        "tool",
    ),
    Rule(
        "SC_RULE_SOURCE",
        "BATCH",
        "source",
        "",
        "crate source changes the artefact, which requires the full suite and the "
        "affected courts before an integration checkpoint",
        "source",
    ),
    Rule(
        "SC_RULE_UNCLASSIFIED",
        "BATCH",
        "other",
        "",
        "an unclassified path is treated as an input, never as documentation: "
        "guessing 'docs' is how an input stops being scheduled",
        "other",
    ),
    Rule(
        "SC_RULE_EVIDENCE_ONLY",
        "FAST",
        "evidence",
        "",
        "a receipt or atlas that no candidate build reads; it does not invalidate "
        "a candidate, so the cheap gate is the right one",
        "evidence",
    ),
    Rule(
        "SC_RULE_DOCS",
        "FAST",
        "docs",
        "",
        "documentation; the documentation-consistency check is the focused check",
        "docs",
    ),
)

RULE_BY_ID = {rule.id: rule for rule in RULES}


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


class SchedulingRefusal(Exception):
    """A named refusal. `rule` is a stable identifier, never a message."""

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule}: {detail}")
        self.rule = rule
        self.detail = detail

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "detail": self.detail}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_hex(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dump_json(document: Any) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def print_json(document: Any) -> None:
    sys.stdout.write(dump_json(document))


def _hash_problem(value: Any) -> bool:
    return not (isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value))


def _commit_problem(value: Any) -> bool:
    return not (isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value))


# ---------------------------------------------------------------------------
# Change classification
# ---------------------------------------------------------------------------


def is_shared_mechanism(path: str) -> bool:
    if path in SHARED_MECHANISMS:
        return True
    return any(path.startswith(prefix) for prefix in SHARED_MECHANISM_PREFIXES)


def _graduation_changed(repo: freshness.Git, base: str, head: str, status: str) -> bool:
    """Did the change set alter a `SAFE_COMPATIBLE` assertion?

    An added or deleted claim document is conservatively a graduation change
    because the assertion cannot be compared. An unreadable diff is also
    conservatively a graduation change: silence is not evidence of non-impact.
    """
    if status != "M":
        return True
    result = repo.run("diff", "--no-color", "-U0", base, head, "--", CLAIMS_DOCUMENT)
    if result.returncode != 0:
        return True
    for line in result.stdout.decode("utf-8", "surrogateescape").splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line[:1] in ("+", "-") and GRADUATION_MARKER in line:
            return True
    return False


def _rule_matches(rule: Rule, path: str, change_class: str) -> bool:
    if rule.match == "exact":
        return path == rule.value
    if rule.match == "prefix":
        return path == rule.value.rstrip("/") or path.startswith(rule.value)
    if rule.match == "shared_mechanism":
        return is_shared_mechanism(path)
    if rule.match == "venue":
        return change_class == "venue" or path in freshness.VENUE_INPUTS
    if rule.match in ("build", "tool", "source", "other", "evidence", "docs"):
        return change_class == rule.match
    raise SchedulingRefusal("SC_RULE_UNIMPLEMENTED", f"rule {rule.id!r} has match {rule.match!r}")


def classify_path(
    path: str,
    repo: freshness.Git | None = None,
    base: str | None = None,
    head: str | None = None,
    status: str = "M",
) -> Rule:
    """The rule that decides a single changed path.

    A claims-document change needs its content, so without a repository and a
    range it is conservatively a graduation change. A caller that supplies a
    range gets the content decision instead.
    """
    if path == CLAIMS_DOCUMENT:
        if repo is None or base is None or head is None:
            return RULE_BY_ID["SC_RULE_GRADUATION_CLAIM"]
        if _graduation_changed(repo, base, head, status):
            return RULE_BY_ID["SC_RULE_GRADUATION_CLAIM"]
    change_class = freshness.change_class(path)
    for rule in RULES:
        if rule.match == "graduation_claim":
            continue
        if _rule_matches(rule, path, change_class):
            return rule
    raise SchedulingRefusal("SC_RULE_UNMATCHED", f"no rule matches {path!r}")


def _class_name(path: str) -> str:
    if is_shared_mechanism(path):
        return "shared_mechanism"
    return freshness.change_class(path)


MAX_PATHS_PER_GROUP = 40


def decide(
    repo: freshness.Git | None,
    base: str | None,
    head: str | None,
    changed: Iterable[dict[str, str]],
) -> dict[str, Any]:
    """Derive the minimum tier a change set requires.

    The tier is the maximum over the paths, not the average and not the first
    interesting path: one shared-mechanism file makes a change set `BOUNDARY`
    however many documents accompany it.
    """
    rows: list[dict[str, Any]] = []
    for row in changed:
        path = str(row.get("path", ""))
        status = str(row.get("status", "M"))
        if not path:
            continue
        rule = classify_path(path, repo, base, head, status)
        rows.append(
            {
                "path": path,
                "status": status,
                "class": _class_name(path),
                "rule": rule.id,
                "tier": rule.tier,
            }
        )
    if not rows:
        raise SchedulingRefusal(
            "SC_EMPTY_CHANGE_SET",
            "the range names no changed path; an empty change set cannot be scheduled "
            "because it cannot be distinguished from a wrong range",
        )

    groups: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        groups.setdefault((row["rule"], row["class"]), []).append(row["path"])

    by_class: list[dict[str, Any]] = []
    for (rule_id, class_name), paths in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])):
        ordered = sorted(paths)
        rule = RULE_BY_ID[rule_id]
        by_class.append(
            {
                "rule": rule.id,
                "tier": rule.tier,
                "why": rule.why,
                "class": class_name,
                "count": len(ordered),
                "paths": ordered[:MAX_PATHS_PER_GROUP],
                "omitted": max(0, len(ordered) - MAX_PATHS_PER_GROUP),
            }
        )

    top = max((row["tier"] for row in rows), key=lambda tier: TIER_RANK[tier])
    deciding = sorted(row["path"] for row in rows if row["tier"] == top)
    deciding_rule = min(
        (row["rule"] for row in rows if row["tier"] == top),
        key=lambda rule_id: rule_id,
    )
    return {
        "count": len(rows),
        "tier": top,
        "rule": deciding_rule,
        "why": RULE_BY_ID[deciding_rule].why,
        "deciding_paths": deciding[:MAX_PATHS_PER_GROUP],
        "deciding_omitted": max(0, len(deciding) - MAX_PATHS_PER_GROUP),
        "by_class": by_class,
    }


# ---------------------------------------------------------------------------
# Applicability identity
# ---------------------------------------------------------------------------

IDENTITY_FIELDS = ("source", "tool", "instrument", "target", "population")
SOURCE_FIELDS = ("commit", "tree")
TOOL_FIELDS = ("paths", "digest")
INSTRUMENT_FIELDS = ("name", "config")
TARGET_FIELDS = ("profile", "triple", "features")
POPULATION_FIELDS = ("items", "digest")


def _problem(rule: str, detail: str) -> dict[str, str]:
    return {"rule": rule, "detail": detail}


def tool_digest(paths: list[dict[str, str]]) -> str:
    ordered = sorted(
        ({"path": str(item.get("path", "")), "sha256": str(item.get("sha256", ""))} for item in paths),
        key=lambda item: item["path"],
    )
    return sha256_hex(canonical(ordered))


def population_digest(items: list[str]) -> str:
    return sha256_hex(canonical(sorted(items)))


def identity_digest(identity: dict[str, Any]) -> str:
    return sha256_hex(canonical({field: identity.get(field) for field in IDENTITY_FIELDS}))


def normalise_identity(document: Any) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Validate an applicability identity and return its canonical form.

    An identity is complete only when all five fields are present and internally
    consistent. Anything else yields problems, and a caller must not reuse a
    result: an incomplete identity is the mechanism by which a stale result
    gets read as a fresh one.
    """
    if not isinstance(document, dict):
        return None, [_problem("SC_IDENTITY_NOT_OBJECT", "an applicability identity is a JSON object")]

    problems: list[dict[str, str]] = []
    unknown = sorted(set(document) - set(IDENTITY_FIELDS))
    if unknown:
        problems.append(
            _problem(
                "SC_IDENTITY_UNKNOWN_FIELD",
                f"{unknown} would not be part of the identity digest and is refused rather than ignored",
            )
        )
    for field in IDENTITY_FIELDS:
        if field not in document:
            problems.append(_problem("SC_IDENTITY_MISSING_FIELD", field))

    identity: dict[str, Any] = {}

    source = document.get("source")
    if isinstance(source, dict):
        extra = sorted(set(source) - set(SOURCE_FIELDS))
        if extra:
            problems.append(_problem("SC_IDENTITY_UNKNOWN_FIELD", f"source.{extra}"))
        if _commit_problem(source.get("commit")):
            problems.append(_problem("SC_IDENTITY_BAD_COMMIT", "a source commit is a full 40-hex revision"))
        if _commit_problem(source.get("tree")):
            problems.append(_problem("SC_IDENTITY_BAD_TREE", "a source tree is a full 40-hex revision"))
        identity["source"] = {"commit": source.get("commit"), "tree": source.get("tree")}
    elif source is not None:
        problems.append(_problem("SC_IDENTITY_NOT_OBJECT", "source"))

    tool = document.get("tool")
    if isinstance(tool, dict):
        extra = sorted(set(tool) - set(TOOL_FIELDS))
        if extra:
            problems.append(_problem("SC_IDENTITY_UNKNOWN_FIELD", f"tool.{extra}"))
        paths = tool.get("paths")
        if not isinstance(paths, list) or not paths:
            problems.append(_problem("SC_IDENTITY_TOOL_EMPTY", "a tool identity names at least one tool path"))
            paths = []
        normalised_paths: list[dict[str, str]] = []
        for item in paths:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                problems.append(
                    _problem("SC_IDENTITY_TOOL_ENTRY", "each tool path is {path, sha256} and nothing else")
                )
                continue
            if not isinstance(item.get("path"), str) or not item["path"]:
                problems.append(_problem("SC_IDENTITY_TOOL_ENTRY", "a tool path is a non-empty string"))
                continue
            if _hash_problem(item.get("sha256")):
                problems.append(_problem("SC_IDENTITY_TOOL_DIGEST", f"{item['path']}: sha256 is 64 lowercase hex"))
                continue
            normalised_paths.append({"path": item["path"], "sha256": item["sha256"]})
        computed = tool_digest(normalised_paths)
        if tool.get("digest") != computed:
            problems.append(
                _problem(
                    "SC_IDENTITY_TOOL_DIGEST_MISMATCH",
                    "the declared tool digest does not match its paths, so the entry is not bound",
                )
            )
        identity["tool"] = {"paths": normalised_paths, "digest": computed}
    elif tool is not None:
        problems.append(_problem("SC_IDENTITY_NOT_OBJECT", "tool"))

    instrument = document.get("instrument")
    if isinstance(instrument, dict):
        extra = sorted(set(instrument) - set(INSTRUMENT_FIELDS))
        if extra:
            problems.append(_problem("SC_IDENTITY_UNKNOWN_FIELD", f"instrument.{extra}"))
        if not isinstance(instrument.get("name"), str) or not instrument["name"]:
            problems.append(_problem("SC_IDENTITY_INSTRUMENT_NAME", "an instrument is named"))
        if not isinstance(instrument.get("config"), dict):
            problems.append(
                _problem(
                    "SC_IDENTITY_INSTRUMENT_CONFIG",
                    "an instrument configuration is an object; a missing configuration is not the same as none",
                )
            )
        identity["instrument"] = {"name": instrument.get("name"), "config": instrument.get("config")}
    elif instrument is not None:
        problems.append(_problem("SC_IDENTITY_NOT_OBJECT", "instrument"))

    target = document.get("target")
    if isinstance(target, dict):
        extra = sorted(set(target) - set(TARGET_FIELDS))
        if extra:
            problems.append(_problem("SC_IDENTITY_UNKNOWN_FIELD", f"target.{extra}"))
        if not isinstance(target.get("profile"), str) or not target["profile"]:
            problems.append(_problem("SC_IDENTITY_TARGET_PROFILE", "a target profile is named"))
        if not isinstance(target.get("triple"), str) or not target["triple"]:
            problems.append(_problem("SC_IDENTITY_TARGET_TRIPLE", "a target triple is named"))
        features = target.get("features")
        if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
            problems.append(_problem("SC_IDENTITY_TARGET_FEATURES", "features is a list of strings"))
            features = []
        identity["target"] = {
            "profile": target.get("profile"),
            "triple": target.get("triple"),
            "features": sorted(features),
        }
    elif target is not None:
        problems.append(_problem("SC_IDENTITY_NOT_OBJECT", "target"))

    pop = document.get("population")
    if isinstance(pop, dict):
        extra = sorted(set(pop) - set(POPULATION_FIELDS))
        if extra:
            problems.append(_problem("SC_IDENTITY_UNKNOWN_FIELD", f"population.{extra}"))
        items = pop.get("items")
        if not isinstance(items, list) or not items:
            problems.append(
                _problem("SC_IDENTITY_POPULATION_EMPTY", "the exact population is a non-empty list of identifiers")
            )
            items = []
        if any(not isinstance(item, str) or not item for item in items):
            problems.append(_problem("SC_IDENTITY_POPULATION_ENTRY", "every population item is a non-empty string"))
        if len(set(items)) != len(items):
            problems.append(
                _problem(
                    "SC_IDENTITY_POPULATION_DUPLICATE",
                    "a duplicate population item would hide that one case ran twice",
                )
            )
        computed_population = population_digest(items)
        if pop.get("digest") != computed_population:
            problems.append(
                _problem(
                    "SC_IDENTITY_POPULATION_DIGEST_MISMATCH",
                    "the declared population digest does not match its items",
                )
            )
        identity["population"] = {"items": sorted(items), "digest": computed_population}
    elif pop is not None:
        problems.append(_problem("SC_IDENTITY_NOT_OBJECT", "population"))

    if problems:
        return None, problems
    return identity, []


def build_identity(
    commit: str,
    tree: str,
    tool_paths: list[dict[str, str]],
    instrument_name: str,
    instrument_config: dict[str, Any],
    profile: str,
    triple: str,
    features: list[str],
    population: list[str],
) -> dict[str, Any]:
    document = {
        "source": {"commit": commit, "tree": tree},
        "tool": {"paths": tool_paths, "digest": tool_digest(tool_paths)},
        "instrument": {"name": instrument_name, "config": instrument_config},
        "target": {"profile": profile, "triple": triple, "features": sorted(features)},
        "population": {"items": sorted(population), "digest": population_digest(population)},
    }
    identity, problems = normalise_identity(document)
    if identity is None:
        raise SchedulingRefusal("SC_IDENTITY_INBUILT", canonical(problems))
    return identity


# ---------------------------------------------------------------------------
# Resource bounds and exhaustion
# ---------------------------------------------------------------------------

RESOURCE_KINDS = ("memory_mib", "time_s", "disk_mib")
RESULTS = ("PASS", "FAILED", "BLOCKED")
PROVENANCE = ("run", "control")


def resource_problems(resources: Any, result: str) -> tuple[list[dict[str, str]], list[str]]:
    """Validate a result's resource observation and name the exhausted kinds.

    Every recorded result carries a bound and an observed value for memory,
    time and disk. A result without them is not admissible, because an
    unobserved run that happened to finish is indistinguishable from a run that
    was killed just after writing its verdict.
    """
    problems: list[dict[str, str]] = []
    exhausted: list[str] = []
    if not isinstance(resources, dict):
        return (
            [_problem("SC_RESOURCES_MISSING", "a result carries memory, time and disk bounds with observed values")],
            [],
        )
    unknown = sorted(set(resources) - set(RESOURCE_KINDS))
    if unknown:
        problems.append(_problem("SC_RESOURCES_UNKNOWN_KIND", f"{unknown}"))
    for kind in RESOURCE_KINDS:
        entry = resources.get(kind)
        if not isinstance(entry, dict):
            problems.append(_problem("SC_RESOURCES_MISSING", kind))
            continue
        extra = sorted(set(entry) - {"bound", "observed"})
        if extra:
            problems.append(_problem("SC_RESOURCES_UNKNOWN_FIELD", f"{kind}.{extra}"))
        bound = entry.get("bound")
        observed = entry.get("observed")
        if not isinstance(bound, (int, float)) or isinstance(bound, bool) or bound <= 0:
            problems.append(_problem("SC_RESOURCES_BOUND", f"{kind}: bound is a positive number"))
            continue
        if not isinstance(observed, (int, float)) or isinstance(observed, bool) or observed < 0:
            problems.append(_problem("SC_RESOURCES_OBSERVED", f"{kind}: observed is a non-negative number"))
            continue
        if observed > bound:
            exhausted.append(kind)
    if result in ("PASS", "FAILED") and exhausted:
        problems.append(
            _problem(
                "SC_RESULT_EXCEEDS_BOUND",
                f"{exhausted} exceeded its bound; a resource-exhausted run is BLOCKED, never {result}",
            )
        )
    if result == "BLOCKED" and not exhausted:
        problems.append(
            _problem(
                "SC_BLOCKED_WITHOUT_BOUND",
                "a BLOCKED result names the bound it hit and the observed value; without them it is a claim",
            )
        )
    return problems, sorted(exhausted)


# ---------------------------------------------------------------------------
# The content-addressed cache
# ---------------------------------------------------------------------------

CACHE_KEYS = {"schema", "item", "purpose", "entries", "note"}
ENTRY_KEYS = {
    "check",
    "identity",
    "identity_digest",
    "result",
    "resources",
    "exhausted",
    "evidence",
    "provenance",
    "note",
}


def empty_store() -> dict[str, Any]:
    return {
        "schema": CACHE_SCHEMA,
        "item": ITEM,
        "purpose": (
            "content-addressed results keyed by full applicability identity; an entry is "
            "reused only when source, tool, instrument, target/profile and population all match"
        ),
        "entries": [],
    }


def validate_store(document: Any) -> None:
    if not isinstance(document, dict):
        raise SchedulingRefusal("SC_CACHE_NOT_OBJECT", "the cache store is a JSON object")
    if document.get("schema") != CACHE_SCHEMA:
        raise SchedulingRefusal("SC_CACHE_SCHEMA", f"expected {CACHE_SCHEMA}")
    unknown = sorted(set(document) - CACHE_KEYS)
    if unknown:
        raise SchedulingRefusal("SC_CACHE_UNKNOWN_KEY", f"{unknown}")
    if not isinstance(document.get("entries"), list):
        raise SchedulingRefusal("SC_CACHE_ENTRIES", "entries is a list")
    for entry in document["entries"]:
        if not isinstance(entry, dict):
            raise SchedulingRefusal("SC_CACHE_ENTRY_NOT_OBJECT", "an entry is a JSON object")
        unknown = sorted(set(entry) - ENTRY_KEYS)
        if unknown:
            raise SchedulingRefusal("SC_CACHE_ENTRY_UNKNOWN_KEY", f"{unknown}")
        if entry.get("check") not in CHECK_INFO:
            raise SchedulingRefusal("SC_CACHE_ENTRY_CHECK", f"unknown check {entry.get('check')!r}")
        if entry.get("result") not in RESULTS:
            raise SchedulingRefusal("SC_CACHE_ENTRY_RESULT", f"unknown result {entry.get('result')!r}")
        if entry.get("provenance") not in PROVENANCE:
            raise SchedulingRefusal(
                "SC_CACHE_ENTRY_PROVENANCE",
                "an entry states whether it came from a run or from a control",
            )
        if not isinstance(entry.get("evidence"), list) or not all(
            isinstance(item, str) for item in entry.get("evidence", [])
        ):
            raise SchedulingRefusal("SC_CACHE_ENTRY_EVIDENCE", "evidence is a list of paths")
        if _hash_problem(entry.get("identity_digest")):
            raise SchedulingRefusal("SC_CACHE_ENTRY_DIGEST", "identity_digest is 64 lowercase hex")


def load_store(path: Path) -> dict[str, Any]:
    if not path.exists():
        return empty_store()
    try:
        document = freshness.load_json(path)
    except freshness.JsonError as exc:
        raise SchedulingRefusal("SC_CACHE_UNREADABLE", str(exc)) from exc
    validate_store(document)
    return document


def save_store(path: Path, document: dict[str, Any]) -> None:
    document["entries"] = sorted(
        document["entries"],
        key=lambda entry: (entry.get("check", ""), entry.get("identity_digest", "")),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_json(document), encoding="utf-8")


def _entry_identity(entry: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    identity, problems = normalise_identity(entry.get("identity"))
    if identity is None:
        return None, problems
    if entry.get("identity_digest") != identity_digest(identity):
        problems.append(
            _problem(
                "SC_CACHE_ENTRY_UNBOUND",
                "the stored identity doesn't hash to the identity_digest it claims; the entry was edited",
            )
        )
    return identity, problems


def cache_put(
    store: dict[str, Any],
    check: str,
    identity: dict[str, Any],
    result: str,
    resources: dict[str, Any],
    evidence: list[str],
    provenance: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Insert one result, or refuse. The store is mutated only on success."""
    if check not in CHECK_INFO:
        raise SchedulingRefusal("SC_UNKNOWN_CHECK", check)
    if result not in RESULTS:
        raise SchedulingRefusal("SC_UNKNOWN_RESULT", result)
    if provenance not in PROVENANCE:
        raise SchedulingRefusal("SC_UNKNOWN_PROVENANCE", provenance)
    problems, exhausted = resource_problems(resources, result)
    if problems:
        raise SchedulingRefusal(problems[0]["rule"], canonical(problems))
    digest = identity_digest(identity)
    entry: dict[str, Any] = {
        "check": check,
        # A deep copy: the stored identity must not alias the caller's object,
        # or a later edit would change what the record is bound to.
        "identity": copy.deepcopy(identity),
        "identity_digest": digest,
        "result": result,
        "resources": resources,
        "evidence": sorted(set(evidence)),
        "provenance": provenance,
    }
    if result == "BLOCKED":
        entry["exhausted"] = exhausted
    if note:
        entry["note"] = note
    for existing in store["entries"]:
        if existing.get("check") == check and existing.get("identity_digest") == digest:
            if existing == entry:
                return {"status": "UNCHANGED", "check": check, "identity_digest": digest}
            raise SchedulingRefusal(
                "SC_CACHE_CONFLICT",
                "a different result is already stored for this check and identity; "
                "recompute under a new identity rather than overwriting the record",
            )
    store["entries"].append(entry)
    return {"status": "STORED", "check": check, "identity_digest": digest, "result": result}


@dataclass(frozen=True)
class CacheHit:
    kind: str  # HIT | MISS | REFUSED
    entry: dict[str, Any] | None = None
    refusal: dict[str, str] | None = None
    detail: str = ""


def cache_get(store: dict[str, Any], check: str, identity: dict[str, Any]) -> CacheHit:
    """Look up one result by exact applicability identity.

    A `MISS` and a `REFUSED` are different outcomes. A changed tool version, a
    changed population or a changed profile is a `MISS`: the same question was
    asked of a different subject, so it is recomputed. A malformed or unbound
    entry is a `REFUSED`: the store itself cannot be read, and neither outcome
    is ever reported as a hit.
    """
    if check not in CHECK_INFO:
        return CacheHit("REFUSED", refusal=_problem("SC_UNKNOWN_CHECK", check))
    requested, problems = normalise_identity(identity)
    if requested is None or problems:
        return CacheHit(
            "REFUSED",
            refusal=_problem("SC_IDENTITY_INCOMPLETE", canonical(problems or [])),
        )
    identity = requested
    digest = identity_digest(identity)
    candidates = [
        entry for entry in store["entries"] if entry.get("check") == check and entry.get("identity_digest") == digest
    ]
    if not candidates:
        return CacheHit("MISS", detail="no entry for this check and exact identity")
    if len(candidates) > 1:
        return CacheHit(
            "REFUSED",
            refusal=_problem("SC_CACHE_AMBIGUOUS", "more than one entry shares this check and identity"),
        )
    entry = candidates[0]
    stored, problems = _entry_identity(entry)
    if stored is None or problems:
        return CacheHit(
            "REFUSED",
            refusal=_problem("SC_CACHE_ENTRY_INCOMPLETE", canonical(problems)),
        )
    if _entry_digest(stored) != digest:
        return CacheHit(
            "REFUSED",
            refusal=_problem("SC_CACHE_IDENTITY_MISMATCH", "the stored identity is not the requested identity"),
        )
    resource_issues, _ = resource_problems(entry.get("resources"), str(entry.get("result")))
    if resource_issues:
        return CacheHit(
            "REFUSED",
            refusal=_problem("SC_CACHE_ENTRY_RESOURCES", canonical(resource_issues)),
        )
    return CacheHit("HIT", entry=entry)


def _entry_digest(identity: dict[str, Any]) -> str:
    return identity_digest(identity)


# ---------------------------------------------------------------------------
# Declared evidence records and requirement evaluation
# ---------------------------------------------------------------------------

STATE_ORDER = {"SATISFIED": 0, "NOT_RUN": 1, "FAILED": 2, "REFUSED": 3, "BLOCKED": 4}

RUN_KEYS = {"id", "checks", "change_sets", "status", "identity", "resources", "evidence", "note"}


def validate_runs(document: Any) -> None:
    if not isinstance(document, dict):
        raise SchedulingRefusal("SC_RUNS_NOT_OBJECT", "the runs document is a JSON object")
    if document.get("schema") != RUNS_SCHEMA:
        raise SchedulingRefusal("SC_RUNS_SCHEMA", f"expected {RUNS_SCHEMA}")
    unknown = sorted(set(document) - {"schema", "item", "purpose", "runs", "controls"})
    if unknown:
        raise SchedulingRefusal("SC_RUNS_UNKNOWN_KEY", f"{unknown}")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise SchedulingRefusal("SC_RUNS_LIST", "runs is a list")
    seen: set[str] = set()
    for run in runs:
        if not isinstance(run, dict):
            raise SchedulingRefusal("SC_RUNS_ENTRY_NOT_OBJECT", "a run is a JSON object")
        unknown = sorted(set(run) - RUN_KEYS)
        if unknown:
            raise SchedulingRefusal("SC_RUNS_ENTRY_UNKNOWN_KEY", f"{unknown}")
        run_id = run.get("id")
        if not isinstance(run_id, str) or not run_id:
            raise SchedulingRefusal("SC_RUNS_ENTRY_ID", "a run has a non-empty id")
        if run_id in seen:
            raise SchedulingRefusal("SC_RUNS_DUPLICATE_ID", run_id)
        seen.add(run_id)
        checks = run.get("checks")
        if not isinstance(checks, list) or not checks:
            raise SchedulingRefusal("SC_RUNS_ENTRY_CHECKS", f"{run_id}: checks is a non-empty list")
        for check in checks:
            if check not in CHECK_INFO:
                raise SchedulingRefusal("SC_RUNS_ENTRY_CHECK", f"{run_id}: unknown check {check!r}")
        sets = run.get("change_sets")
        if not isinstance(sets, list) or not all(isinstance(item, str) and item for item in sets):
            raise SchedulingRefusal("SC_RUNS_ENTRY_SETS", f"{run_id}: change_sets is a list of identifiers")
        if run.get("status") not in ("NOT_RUN", "SATISFIED", "FAILED", "BLOCKED"):
            raise SchedulingRefusal("SC_RUNS_ENTRY_STATUS", f"{run_id}: unknown status {run.get('status')!r}")
        evidence = run.get("evidence")
        if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
            raise SchedulingRefusal("SC_RUNS_ENTRY_EVIDENCE", f"{run_id}: evidence is a list of paths")

    # Controls are records of observed behaviour. A control that did not agree
    # with its expectation, or that does not say it is simulated, is refused
    # rather than left in the file as if it had demonstrated something.
    controls = document.get("controls", [])
    if not isinstance(controls, list):
        raise SchedulingRefusal("SC_CONTROLS_LIST", "controls is a list")
    for control in controls:
        if not isinstance(control, dict):
            raise SchedulingRefusal("SC_CONTROLS_ENTRY", "a control is a JSON object")
        name = control.get("control")
        if not isinstance(name, str) or not name:
            raise SchedulingRefusal("SC_CONTROLS_ENTRY", "a control has a non-empty name")
        if not isinstance(control.get("simulated"), bool):
            raise SchedulingRefusal(
                "SC_CONTROLS_UNLABELLED",
                f"{name}: a control states whether it was simulated; an unlabelled control is evidence of nothing",
            )
        if control.get("agrees") is not True:
            raise SchedulingRefusal(
                "SC_CONTROLS_DISAGREE",
                f"{name}: the observed behaviour does not match the expectation, so the control failed",
            )


def resolve_run(run: dict[str, Any], check: str, store: dict[str, Any]) -> dict[str, Any]:
    """Resolve one declaration's claim about one check.

    A `SATISFIED` declaration is admitted only from a cache entry bound to the
    complete identity it states. An incomplete identity is refused, not
    downgraded: the declaration exists, and it cannot be read.
    """
    base = {
        "run": run.get("id"),
        "check": check,
        "evidence": sorted(run.get("evidence", [])),
    }
    status = run.get("status")
    if status == "NOT_RUN":
        return {**base, "state": "NOT_RUN", "detail": run.get("note") or "declared not run"}
    if status == "FAILED":
        return {**base, "state": "FAILED", "detail": run.get("note") or "declared failed"}
    if status == "BLOCKED":
        problems, _ = resource_problems(run.get("resources"), "BLOCKED")
        if problems:
            return {
                **base,
                "state": "REFUSED",
                "detail": "a BLOCKED declaration names the bound and the observed value: " + canonical(problems),
            }
        return {**base, "state": "BLOCKED", "detail": run.get("note") or "declared blocked", "resources": run["resources"]}
    if status != "SATISFIED":
        return {**base, "state": "REFUSED", "detail": f"unknown declared status {status!r}"}

    identity, problems = normalise_identity(run.get("identity"))
    if identity is None or problems:
        return {
            **base,
            "state": "REFUSED",
            "detail": "a SATISFIED declaration needs a complete applicability identity; "
            + canonical(problems or [_problem("SC_IDENTITY_MISSING_FIELD", "identity")]),
        }
    hit = cache_get(store, check, identity)
    if hit.kind == "REFUSED":
        return {
            **base,
            "state": "REFUSED",
            "detail": "the cache entry cannot be admitted: " + canonical([hit.refusal or {}]),
        }
    if hit.kind == "MISS":
        return {
            **base,
            "state": "REFUSED",
            "detail": "declared SATISFIED but no cached result is bound to this exact identity",
        }
    entry = hit.entry or {}
    if entry.get("provenance") != "run":
        return {
            **base,
            "state": "REFUSED",
            "detail": "the cached result is a control entry; a control is not evidence for a candidate",
        }
    result = entry.get("result")
    if result == "BLOCKED":
        return {**base, "state": "BLOCKED", "detail": "the cached result is BLOCKED", "resources": entry.get("resources")}
    if result == "FAILED":
        return {
            **base,
            "state": "FAILED",
            "detail": "declared SATISFIED but the cached result is FAILED",
        }
    return {
        **base,
        "state": "SATISFIED",
        "detail": "cached PASS at this exact identity",
        "resources": entry.get("resources"),
    }


def aggregate(rows: list[dict[str, Any]], checks: list[str]) -> dict[str, Any]:
    """The aggregate verdict, with every non-satisfied row visible.

    `BLOCKED` outranks everything: a run that hit a memory, time or disk bound
    must not be summarised as a deferral. `REFUSED` outranks `FAILED` because a
    record that cannot be read is not evidence of failure either.
    """
    by_check: dict[str, list[dict[str, Any]]] = {check: [] for check in checks}
    for row in rows:
        by_check.setdefault(row["check"], []).append(row)

    resolved: dict[str, str] = {}
    for check in checks:
        candidates = by_check.get(check) or []
        if not candidates:
            resolved[check] = "NOT_RUN"
            continue
        resolved[check] = max(candidates, key=lambda row: STATE_ORDER[row["state"]])["state"]

    counts = {state: 0 for state in STATE_ORDER}
    for state in resolved.values():
        counts[state] += 1
    status = max(resolved.values(), key=lambda state: STATE_ORDER[state]) if resolved else "NOT_RUN"
    blocked = [
        {
            "check": row["check"],
            "run": row.get("run"),
            "resources": row.get("resources"),
            "detail": row.get("detail"),
        }
        for row in rows
        if row["state"] == "BLOCKED"
    ]
    return {
        "status": status,
        "counts": counts,
        "checks": resolved,
        "blocked": blocked,
        "not_satisfied": sorted(check for check, state in resolved.items() if state != "SATISFIED"),
    }


def evaluate(
    tier: str,
    runs: list[dict[str, Any]],
    store: dict[str, Any],
    change_set: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Resolve every required check against the declared records."""
    required = required_checks(tier)
    checks = [row["check"] for row in required]
    rows: list[dict[str, Any]] = []
    for run in sorted(runs, key=lambda item: str(item.get("id"))):
        if change_set not in (run.get("change_sets") or []):
            continue
        for check in run.get("checks") or []:
            if check not in checks:
                continue
            rows.append(resolve_run(run, check, store))
    aggregate_row = aggregate(rows, checks)
    return required, aggregate_row, rows


def exit_code_for(status: str) -> int:
    if status == "SATISFIED":
        return 0
    if status == "BLOCKED":
        return 4
    return 1


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


def _paths_from_args(args: argparse.Namespace) -> list[dict[str, str]] | None:
    paths: list[str] = list(args.paths or [])
    if args.paths_file:
        path = Path(args.paths_file)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SchedulingRefusal("SC_PATHS_UNREADABLE", str(exc)) from exc
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            document = None
        if isinstance(document, list):
            paths.extend(str(item) for item in document)
        else:
            paths.extend(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))
    if not paths:
        return None
    return [{"path": path, "status": "M"} for path in paths]


def mode_tier(args: argparse.Namespace) -> int:
    paths = _paths_from_args(args)
    repo: freshness.Git | None = None
    base: str | None = None
    head: str | None = None
    if paths is None:
        if not args.base:
            raise SchedulingRefusal(
                "SC_NO_CHANGE_SET",
                "--base/--head or --paths/--paths-file is required; there is no default change set",
            )
        repo = freshness.Git(Path(args.repo).resolve())
        base = repo.resolve(args.base)
        head = repo.resolve(args.head or "HEAD")
        if base is None or head is None:
            raise SchedulingRefusal("SC_RANGE_UNRESOLVED", "a commit in the range does not resolve")
        paths = repo.changed(base, head)
    decision = decide(repo, base, head, paths)
    print_json(
        {
            "schema": SCHEMA,
            "mode": "tier",
            "item": ITEM,
            "base": base,
            "head": head,
            "status": "OK",
            **decision,
        }
    )
    return 0


def mode_rules(args: argparse.Namespace) -> int:
    print_json(
        {
            "schema": SCHEMA,
            "mode": "rules",
            "item": ITEM,
            "tiers": list(TIERS),
            "rules": [
                {
                    "id": rule.id,
                    "tier": rule.tier,
                    "match": rule.match,
                    "value": rule.value,
                    "class": rule.class_name,
                    "why": rule.why,
                }
                for rule in RULES
            ],
            "requirements": {tier: [row["check"] for row in required_checks(tier)] for tier in TIERS},
            "shared_mechanisms": list(SHARED_MECHANISMS),
            "shared_mechanism_prefixes": list(SHARED_MECHANISM_PREFIXES),
            "exported_abi": EXPORTED_ABI,
            "claims_document": CLAIMS_DOCUMENT,
            "status": "OK",
        }
    )
    return 0


def mode_require(args: argparse.Namespace) -> int:
    required = required_checks(args.tier)
    if args.runs is None:
        print_json(
            {
                "schema": SCHEMA,
                "mode": "require",
                "item": ITEM,
                "tier": args.tier,
                "cumulative": True,
                "requirements": required,
                "status": "OK",
            }
        )
        return 0
    if not args.change_set:
        raise SchedulingRefusal(
            "SC_CHANGE_SET_REQUIRED",
            "evaluating declared records needs --change-set; requirements are per change set",
        )
    try:
        runs_doc = freshness.load_json(Path(args.runs))
    except freshness.JsonError as exc:
        raise SchedulingRefusal("SC_RUNS_UNREADABLE", str(exc)) from exc
    validate_runs(runs_doc)
    store = load_store(Path(args.store))
    _, aggregate_row, rows = evaluate(args.tier, runs_doc.get("runs", []), store, args.change_set)
    print_json(
        {
            "schema": SCHEMA,
            "mode": "require",
            "item": ITEM,
            "tier": args.tier,
            "change_set": args.change_set,
            "requirements": required,
            "rows": rows,
            "aggregate": aggregate_row,
            "status": aggregate_row["status"],
        }
    )
    return exit_code_for(aggregate_row["status"])


def _identity_from_file(path: str) -> dict[str, Any]:
    try:
        document = freshness.load_json(Path(path))
    except freshness.JsonError as exc:
        raise SchedulingRefusal("SC_IDENTITY_UNREADABLE", str(exc)) from exc
    identity, problems = normalise_identity(document)
    if identity is None:
        raise SchedulingRefusal("SC_IDENTITY_INCOMPLETE", canonical(problems or []))
    return identity


def mode_cache_put(args: argparse.Namespace) -> int:
    store = load_store(Path(args.store))
    identity = _identity_from_file(args.identity)
    resources = {
        kind: {"bound": getattr(args, f"{kind}_bound"), "observed": getattr(args, f"{kind}_observed")}
        for kind in RESOURCE_KINDS
    }
    outcome = cache_put(
        store,
        args.check,
        identity,
        args.result,
        resources,
        list(args.evidence or []),
        args.provenance,
        args.note,
    )
    save_store(Path(args.store), store)
    print_json({**outcome, "entry": len(store["entries"])})
    return 0


def mode_cache_get(args: argparse.Namespace) -> int:
    store = load_store(Path(args.store))
    identity = _identity_from_file(args.identity)
    hit = cache_get(store, args.check, identity)
    if hit.kind == "MISS":
        print_json({"status": "MISS", "check": args.check, "detail": hit.detail})
        return 3
    if hit.kind == "REFUSED":
        print_json({"status": "REFUSED", "check": args.check, "refusal": hit.refusal})
        return 2
    entry = hit.entry or {}
    print_json(
        {
            "status": "HIT",
            "check": args.check,
            "result": entry.get("result"),
            "resources": entry.get("resources"),
            "exhausted": entry.get("exhausted", []),
            "evidence": entry.get("evidence", []),
            "provenance": entry.get("provenance"),
        }
    )
    result = entry.get("result")
    if result == "PASS":
        return 0
    if result == "BLOCKED":
        return 4
    return 5


def _tool_paths_at(repo: freshness.Git, commit: str, paths: list[str], root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    problems: list[dict[str, str]] = []
    for rel in sorted(set(paths)):
        blob = repo.blob(commit, rel)
        if blob is None:
            problems.append(_problem("SC_TOOL_ABSENT_AT_COMMIT", rel))
            continue
        digest = sha256_bytes(blob)
        live = root / rel
        if not live.exists():
            problems.append(_problem("SC_TOOL_ABSENT_IN_WORKTREE", rel))
            continue
        if sha256_bytes(live.read_bytes()) != digest:
            problems.append(
                _problem(
                    "SC_TOOL_DRIFT",
                    f"{rel} differs between {commit[:12]} and the working tree; the identity "
                    "would describe a tool other than the one that runs",
                )
            )
            continue
        rows.append({"path": rel, "sha256": digest})
    if problems:
        raise SchedulingRefusal("SC_TOOL_IDENTITY", canonical(problems))
    return rows


def mode_identity(args: argparse.Namespace) -> int:
    root = Path(args.repo).resolve()
    repo = freshness.Git(root)
    commit = repo.resolve(args.source_commit)
    if commit is None:
        raise SchedulingRefusal("SC_COMMIT_UNRESOLVED", args.source_commit)
    tree = repo.run("rev-parse", f"{commit}^{{tree}}")
    if tree.returncode != 0:
        raise SchedulingRefusal("SC_TREE_UNRESOLVED", commit)
    tree_id = tree.stdout.decode("ascii").strip()
    if not args.tool_path:
        raise SchedulingRefusal("SC_TOOL_REQUIRED", "at least one --tool-path is required")
    tool_paths = _tool_paths_at(repo, commit, args.tool_path, root)
    config: dict[str, Any] = {}
    if args.instrument_config:
        try:
            loaded = freshness.load_json(Path(args.instrument_config))
        except freshness.JsonError as exc:
            raise SchedulingRefusal("SC_INSTRUMENT_CONFIG", str(exc)) from exc
        if not isinstance(loaded, dict):
            raise SchedulingRefusal("SC_INSTRUMENT_CONFIG", "the instrument configuration is a JSON object")
        config = loaded
    population: list[str] = list(args.population or [])
    if args.population_file:
        try:
            loaded_population = freshness.load_json(Path(args.population_file))
        except freshness.JsonError as exc:
            raise SchedulingRefusal("SC_POPULATION_UNREADABLE", str(exc)) from exc
        if not isinstance(loaded_population, list) or not all(isinstance(item, str) for item in loaded_population):
            raise SchedulingRefusal("SC_POPULATION_SHAPE", "the population file is a JSON list of identifiers")
        population.extend(loaded_population)
    identity = build_identity(
        commit=commit,
        tree=tree_id,
        tool_paths=tool_paths,
        instrument_name=args.instrument_name,
        instrument_config=config,
        profile=args.profile,
        triple=args.triple,
        features=list(args.features or []),
        population=population,
    )
    rendered = dump_json(identity)
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print_json({"status": "WRITTEN", "out": args.out, "identity_digest": identity_digest(identity)})
    else:
        sys.stdout.write(rendered)
    return 0


def mode_report(args: argparse.Namespace) -> int:
    root = Path(args.repo).resolve()
    repo = freshness.Git(root)
    try:
        sets_doc = freshness.load_json(Path(args.change_sets))
    except freshness.JsonError as exc:
        raise SchedulingRefusal("SC_SETS_UNREADABLE", str(exc)) from exc
    if not isinstance(sets_doc, dict) or sets_doc.get("schema") != SETS_SCHEMA:
        raise SchedulingRefusal("SC_SETS_SCHEMA", f"expected {SETS_SCHEMA}")
    declared = sets_doc.get("change_sets")
    if not isinstance(declared, list) or not declared:
        raise SchedulingRefusal("SC_SETS_EMPTY", "a report needs at least one change set")
    try:
        runs_doc = freshness.load_json(Path(args.runs))
    except freshness.JsonError as exc:
        raise SchedulingRefusal("SC_RUNS_UNREADABLE", str(exc)) from exc
    validate_runs(runs_doc)
    store = load_store(Path(args.store))

    ids: set[str] = set()
    change_sets: list[dict[str, Any]] = []
    for entry in declared:
        if not isinstance(entry, dict):
            raise SchedulingRefusal("SC_SETS_ENTRY", "a change set is a JSON object")
        identifier = entry.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise SchedulingRefusal("SC_SETS_ENTRY", "a change set has a non-empty id")
        if identifier in ids:
            raise SchedulingRefusal("SC_SETS_DUPLICATE", identifier)
        ids.add(identifier)
        base = repo.resolve(entry.get("base"))
        head = repo.resolve(entry.get("head"))
        if base is None or head is None:
            raise SchedulingRefusal(
                "SC_SETS_UNRESOLVED",
                f"{identifier}: base={entry.get('base')!r} head={entry.get('head')!r} does not resolve",
            )
        changed = repo.changed(base, head)
        decision = decide(repo, base, head, changed)
        required, aggregate_row, rows = evaluate(decision["tier"], runs_doc.get("runs", []), store, identifier)
        change_sets.append(
            {
                "id": identifier,
                "purpose": entry.get("purpose"),
                "base": base,
                "head": head,
                **decision,
                "required": required,
                "rows": rows,
                "aggregate": aggregate_row,
            }
        )

    change_sets.sort(key=lambda item: item["id"])
    payload = {
        "schema": SCHEMA,
        "mode": "report",
        "item": ITEM,
        "purpose": (
            "the minimum tier each real change set requires, the evidence that tier requires, "
            "and which of it is satisfied, NOT_RUN, FAILED, REFUSED or BLOCKED"
        ),
        "change_sets": change_sets,
        "totals": {
            "change_sets": len(change_sets),
            "requirements": sum(len(item["required"]) for item in change_sets),
            "by_state": {
                state: sum(item["aggregate"]["counts"][state] for item in change_sets) for state in STATE_ORDER
            },
        },
        "status": max(
            (item["aggregate"]["status"] for item in change_sets),
            key=lambda state: STATE_ORDER[state],
        ),
    }
    rendered = dump_json(payload)
    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
        print_json(
            {
                "status": payload["status"],
                "change_sets": len(change_sets),
                "totals": payload["totals"],
                "out": args.out,
            }
        )
    else:
        sys.stdout.write(rendered)
    return exit_code_for(payload["status"])


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    tier = sub.add_parser("tier", help="derive the minimum tier a change set requires")
    tier.add_argument("--repo", default=str(REPO_ROOT))
    tier.add_argument("--base")
    tier.add_argument("--head")
    tier.add_argument("--paths", action="append", default=[])
    tier.add_argument("--paths-file")

    rules = sub.add_parser("rules", help="print the rule table and the requirement sets")

    require = sub.add_parser("require", help="the evidence a tier requires, optionally evaluated")
    require.add_argument("--tier", required=True, choices=list(TIERS))
    require.add_argument("--runs")
    require.add_argument("--store", default=str(REPO_ROOT / "evidence" / "etp-t11" / "CACHE.json"))
    require.add_argument("--change-set")

    put = sub.add_parser("cache-put", help="store one result under its full applicability identity")
    put.add_argument("--store", default=str(REPO_ROOT / "evidence" / "etp-t11" / "CACHE.json"))
    put.add_argument("--check", required=True, choices=sorted(CHECK_INFO))
    put.add_argument("--identity", required=True)
    put.add_argument("--result", required=True, choices=list(RESULTS))
    put.add_argument("--memory-bound-mib", dest="memory_mib_bound", type=float, required=True)
    put.add_argument("--memory-observed-mib", dest="memory_mib_observed", type=float, required=True)
    put.add_argument("--time-bound-s", dest="time_s_bound", type=float, required=True)
    put.add_argument("--time-observed-s", dest="time_s_observed", type=float, required=True)
    put.add_argument("--disk-bound-mib", dest="disk_mib_bound", type=float, required=True)
    put.add_argument("--disk-observed-mib", dest="disk_mib_observed", type=float, required=True)
    put.add_argument("--evidence", action="append", default=[])
    put.add_argument("--provenance", default="run", choices=list(PROVENANCE))
    put.add_argument("--note")

    get = sub.add_parser("cache-get", help="reuse a result only at its exact identity")
    get.add_argument("--store", default=str(REPO_ROOT / "evidence" / "etp-t11" / "CACHE.json"))
    get.add_argument("--check", required=True, choices=sorted(CHECK_INFO))
    get.add_argument("--identity", required=True)

    identity = sub.add_parser("identity", help="build a complete applicability identity from a commit")
    identity.add_argument("--repo", default=str(REPO_ROOT))
    identity.add_argument("--source-commit", default="HEAD")
    identity.add_argument("--tool-path", action="append", default=[])
    identity.add_argument("--instrument-name", default="python3-stdlib-unittest")
    identity.add_argument("--instrument-config")
    identity.add_argument("--profile", default="debug")
    identity.add_argument("--triple", default="x86_64-unknown-linux-gnu")
    identity.add_argument("--features", action="append", default=[])
    identity.add_argument("--population", action="append", default=[])
    identity.add_argument("--population-file")
    identity.add_argument("--out")

    report = sub.add_parser("report", help="apply the policy to named change sets")
    report.add_argument("--repo", default=str(REPO_ROOT))
    report.add_argument("--change-sets", required=True)
    report.add_argument("--runs", required=True)
    report.add_argument("--store", default=str(REPO_ROOT / "evidence" / "etp-t11" / "CACHE.json"))
    report.add_argument("--out")

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "tier": mode_tier,
        "rules": mode_rules,
        "require": mode_require,
        "cache-put": mode_cache_put,
        "cache-get": mode_cache_get,
        "identity": mode_identity,
        "report": mode_report,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except SchedulingRefusal as refusal:
        print_json({"status": "REFUSED", **refusal.as_dict()})
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
