#!/usr/bin/env python3
"""openssl-rs — the multitrack record schemas, and the historical version model.

Phase 23 is the multitrack authority stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-23-MULTITRACK-SUBPHASES.md`). It owns no exported symbol: its unit is the non-export
`multitrack authority contract`, and its working set is twelve contract units the later subphases
23.1 through 23.12 populate. This module is 23.0's own half of that work: it **defines and
validates** the record kinds those subphases will emit, and it models the two OpenSSL version
encodings so the lineage has a chronology.

Why the schemas live in one module
----------------------------------
A record kind that can be invented is a record kind that cannot be checked. Each record the
multitrack evidence plane carries -- a release node, an authority node, a lineage edge, an entity
lineage relation, a compatibility view, a compatibility edge, a negative obligation, a support-status
row, a delta receipt, a security observation, the assembled matrix -- is a **claim that can be
falsified**: this module names the fields it requires and the closed vocabularies its values come
from, so a record that omits a load-bearing field, or uses a value outside the vocabulary, fails
rather than reads plausibly. The self-test (`--self-test`) proves every validator accepts a
documented-good record and rejects a documented-bad one, so a validator that can no longer fail is
visible.

The version model, and what it is not
-------------------------------------
OpenSSL numbers its releases two ways, and the lineage spans both:

  * the **pre-3.0 encoded scheme**, `MNNFFPPS`, behind `OPENSSL_VERSION_NUMBER`: one hex nibble of
    major, two of minor, two of fix, two of patch and one of status. The patch letters are the
    patch field (`1.0.2u` is patch 21, `0x1000215f`), and after `z` the letters continue `za`,
    `zb`, ... (`0.9.8zh` is patch 34, `0x0090822f`).
  * the **3.0-plus scheme**, `MAJOR.MINOR.PATCH`, encoded `(major<<28)|(minor<<20)|(patch<<4)`.

`parse_version` decodes either form and `chronological_order` orders them correctly -- the
documented examples `0.9.8 < 0.9.8zh < 1.0.0 < 1.0.2u < 1.1.0 < 1.1.1w < 3.0.0 < 3.6.5 < 4.0.3`
are asserted in the self-test.

**This ordering is chronology, and it is not compatibility.** `validate_compatibility_edge`
rejects an evidence kind of `version_order`, and a self-test proves it: a newer version is not
thereby compatible, and a compatibility claim carries the dimension, the direction and the
evidence it was measured from (D535; `docs/PARITY_MODEL.md` sections 3 and 4).

Outputs
-------
  (none) — this module writes no artefact; it is imported by the Phase-23 ledger and runner, and
  run with `--self-test`.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import re
import sys
from dataclasses import dataclass

# --------------------------------------------------------------------------------------------
# the closed vocabularies: every value a record may carry comes from one of these
# --------------------------------------------------------------------------------------------

SCHEME_PRE_3_0 = "pre-3.0-mnnffpps"
SCHEME_3_0_PLUS = "3.0-plus-major-minor-patch"
VERSION_SCHEMES: tuple[str, ...] = (SCHEME_PRE_3_0, SCHEME_3_0_PLUS)

RELEASE_CHANNELS: tuple[str, ...] = (
    "final", "alpha", "beta", "development", "historical_auxiliary",
)
PUBLIC_OR_EXTENDED: tuple[str, ...] = ("public", "extended")
MAINLINE_OR_AUXILIARY: tuple[str, ...] = ("mainline", "auxiliary")

LINEAGE_EDGE_KINDS: tuple[str, ...] = (
    "chronological_successor",
    "git_ancestry",
    "branch_fork",
    "maintenance_successor",
    "security_backport",
    "declared_abi_compatibility",
    "observed_compatibility",
)

ENTITY_RELATIONS: tuple[str, ...] = (
    "same_entity",
    "renamed_to",
    "moved_to",
    "signature_changed",
    "layout_changed",
    "kind_changed",
    "split_into",
    "merged_from",
    "deprecated",
    "removed",
    "reintroduced",
    "semantic_successor",
    "unknown_relationship",
)

# The dimensions a compatibility view or edge may be about (docs/PARITY_MODEL.md section 3).
COMPAT_DIMENSIONS: tuple[str, ...] = (
    "source_api",
    "abi",
    "semantic",
    "behavioural",
    "cli_config",
    "provider_registration",
    "protocol",
    "error",
    "ownership",
    "concurrency",
)

# Direction is explicit and never symmetric (D535).
COMPAT_DIRECTIONS: tuple[str, ...] = ("candidate_to_reference", "reference_to_candidate")
COMPAT_STATUSES: tuple[str, ...] = ("compatible", "incompatible", "partial", "unknown",
                                    "not_measured")

# The evidence kinds a compatibility edge may rest on. **`version_order` is deliberately absent**:
# numeric ordering is a chronology, not a compatibility measurement.
EVIDENCE_KINDS: tuple[str, ...] = (
    "upstream_declaration",
    "atlas_differential",
    "court_transcript",
    "build_records",
    "source_manifest",
    "entity_lineage",
    "negative_obligation",
    "security_observation",
    "manual_adjudication",
)

# The semantic observation vocabulary (added by 23.8). A semantic observation is one normalized
# reading of an authority-to-authority (or candidate-to-authority) probe, and its classification is
# the *release-delta* kind it is: `agreed` when both sides read the same, `release_identity` for a
# version-stamp movement the release is defined by, `declaration_added` / `declaration_removed` for a
# declaration present on one side only, `behaviour_changed` for a measured behavioural movement, and
# `implementation_size_only` for a delta the 23.6 engine records as a machine-code size movement
# whose behaviour agrees. There is deliberately no `unclassified` member: a difference that cannot
# be classified is refused by the validator rather than read plausibly.
SEMANTIC_CLASSIFICATIONS: tuple[str, ...] = (
    "agreed",
    "release_identity",
    "declaration_added",
    "declaration_removed",
    "behaviour_changed",
    "implementation_size_only",
)

NEGATIVE_OBLIGATION_KINDS: tuple[str, ...] = (
    "must_exist",
    "must_not_exist",
    "must_be_opaque",
    "must_be_public",
    "must_be_exported",
    "must_not_be_exported",
)
NEGATIVE_OBLIGATION_STATES: tuple[str, ...] = ("open", "satisfied", "unknown")

# The security-lineage vocabulary (added by 23.14). A security observation is one
# (vulnerability, maintained-branch fix) row: the identity it is about, the affected range, the
# fixed release, the branch, the upstream severity, the affected subsystem, the FIPS impact when
# upstream states one, and the **candidate disposition** -- whether the candidate's view never
# contained the defect, safely diverges from the vulnerable historical behaviour, cannot yet claim
# the fix, or (the forbidden value) would preserve the vulnerable behaviour. `preserve` is refused
# by name: a row whose disposition re-adopts a fixed behaviour is exactly what
# docs/SECURITY_DIVERGENCE_POLICY.md section 1 forbids.
SECURITY_SEVERITIES: tuple[str, ...] = ("critical", "high", "moderate", "low", "unknown")
SECURITY_DISPOSITIONS: tuple[str, ...] = (
    "never_contained",
    "safe_divergence",
    "unresolved",
    "preserve_vulnerable_behaviour",
)
SECURITY_FIPS_IMPACTS: tuple[str, ...] = ("no", "yes", "not_stated", "unknown")

# The support-status ladder. `archaeological-only` is a terminal status *outside* the ladder: a
# node that is studied and not supported has climbed no rung.
SUPPORT_LADDER: tuple[str, ...] = (
    "catalogued",
    "admitted-source",
    "built-authority",
    "atlas-complete",
    "candidate-view",
    "runtime-evidenced",
    "downstream-evidenced",
    "maintained",
)
SUPPORT_TERMINAL: tuple[str, ...] = ("archaeological-only",)
SUPPORT_STATUSES: tuple[str, ...] = SUPPORT_LADDER + SUPPORT_TERMINAL

# The ladder's **core** is the contiguous climb every supported node makes: a release must be
# catalogued before it is admitted, admitted before it is built, and built before its atlas can be
# complete. The rungs above the core (`candidate-view`, `runtime-evidenced`, `downstream-evidenced`,
# `maintained`) are each read from an **independent evidence plane** (23.10), so a node may attain
# them without the intermediate additive rungs -- 0.9.8zh is `downstream-evidenced` from a real
# consumer with no `candidate-view`/`runtime-evidenced` -- while a skipped core rung is refused.
SUPPORT_CORE: tuple[str, ...] = SUPPORT_LADDER[:4]

# The population record (added by 23.10). It is the historical-population row for one catalogue
# node: the support status it has reached over `SUPPORT_LADDER`, the rungs it attained with
# evidence, and -- where it is not built -- the honest reason it is not. `outcome` is the finer
# disposition, `scope` says whether the node is on the public final-release lineage the ladder
# tracks, and `runtime_compatible` is true only when the node attained `runtime-evidenced`, so an
# unavailable release is never recorded runtime-compatible.
POPULATION_OUTCOMES: tuple[str, ...] = (
    "built", "acquired", "catalogued", "unavailable", "out-of-population-scope",
)
POPULATION_SCOPES: tuple[str, ...] = ("final-release-lineage", "out-of-population-scope")
# The major ABI/architecture epochs the population covers, by version shape. `out-of-scope` carries
# a node outside the public final-release lineage so every record states an epoch rather than a
# blank; the court requires every other epoch to hold at least one built representative.
POPULATION_EPOCHS: tuple[str, ...] = (
    "pre-1.0", "1.0.x", "1.1.x", "3.x", "3.6+/4.x", "out-of-scope",
)

# The downstream-multitrack record (added by 23.11). It is one **unmodified real downstream
# consumer** exercised against one **built authority**: the consumer and its version, the authority
# it was built against (release plus the build profile and platform the authority node records),
# the build result, the workload it ran and the observation that workload produced. `outcome` is
# `passed` only when the consumer genuinely built and ran against that authority; `not_run` is an
# honest unavailability (a pair whose consumer cannot be built against the epoch, recorded with the
# reason and the raw configure evidence) and is never a pass. `role` keeps the **primary** consumer
# -- the one contemporary with the epoch that covers it -- apart from a **maintained** consumer
# attempted against an epoch it does not reach.
DOWNSTREAM_ROLES: tuple[str, ...] = ("primary", "maintained")
DOWNSTREAM_OUTCOMES: tuple[str, ...] = ("passed", "not_run", "failed")

# The ABI/history façade vocabulary (added by 23.7). A façade record says which *kind* of
# compatibility object it is, and each kind carries its own closed vocabulary. The public-layout
# epoch and the engine/provider/init/thread models are the typed compatibility-policy axes, and a
# record's value is checked against the axis it belongs to.
FACADE_KINDS: tuple[str, ...] = ("public_layout", "prototype", "architecture", "init_thread")
PUBLIC_LAYOUT_EPOCHS: tuple[str, ...] = ("transparent_pre_1_1_0", "opaque_post_1_1_0")
PROTOTYPE_CONTRACT_KINDS: tuple[str, ...] = ("function", "macro")
ENGINE_MODELS: tuple[str, ...] = ("engine", "deprecated_engine", "no_engine")
PROVIDER_MODELS: tuple[str, ...] = ("no_provider", "provider_store")
INIT_MODELS: tuple[str, ...] = ("explicit_global_init", "automatic_init")
THREAD_MODELS: tuple[str, ...] = ("application_locking_callbacks", "internal_thread_support")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")


# --------------------------------------------------------------------------------------------
# the historical version parser and order model
# --------------------------------------------------------------------------------------------

class VersionError(ValueError):
    """A version string this model cannot decode, with the reason."""


@dataclass(frozen=True)
class Version:
    """A decoded OpenSSL version, in either scheme.

    `release` is the third numeric component (the `fix` field pre-3.0, the `patch` field in
    3.0-plus) and `patch` is the fourth (the patch letters pre-3.0, always 0 in 3.0-plus). The two
    are kept apart so a comparison tuple is well-defined across the two schemes without pretending
    the fields mean the same thing.
    """

    raw: str
    scheme: str
    major: int
    minor: int
    release: int
    patch: int
    status: int
    pre_release: str
    number: int

    def order_key(self) -> tuple:
        # Chronology, not compatibility: a final release sorts after its own pre-releases.
        return (self.major, self.minor, self.release, self.patch,
                1 if not self.pre_release else 0, self.pre_release)


_V_3PLUS = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:[-+](?P<pre>[A-Za-z0-9.\-]+))?$"
)
_V_PRE = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<fix>\d+)(?P<letters>[a-z]{0,2})"
    r"(?:[-+](?P<pre>[A-Za-z0-9.\-]+))?$"
)


def _letters_to_patch(letters: str) -> int:
    """The patch level a pre-3.0 letter suffix encodes.

    `a`..`z` are 1..26; after `z` OpenSSL continues `za`, `zb`, ... `zz`, where the second letter
    is 1..26 and the value is `26 + n`. `0.9.8zh` is therefore 34 and `1.0.2u` is 21.
    """
    if letters == "":
        return 0
    if len(letters) == 1:
        return ord(letters) - ord("a") + 1
    if letters[0] == "z":
        return 26 + (ord(letters[1]) - ord("a") + 1)
    raise VersionError(
        f"the patch suffix {letters!r} is not a pre-3.0 OpenSSL spelling "
        f"(single `a`..`z`, or `za`..`zz`)"
    )


def parse_version(text: str) -> Version:
    """Decode an OpenSSL version string in either scheme.

    The discriminator is the major number: OpenSSL 3.0 and later use `MAJOR.MINOR.PATCH`, and
    everything before it uses the encoded `MAJOR.MINOR.FIX[letters]` form. A string that matches
    neither, or whose letters are not a legal suffix, raises `VersionError` rather than being
    guessed at.
    """
    t = (text or "").strip()
    m3 = _V_3PLUS.match(t)
    if m3 is not None and int(m3.group("major")) >= 3:
        major = int(m3.group("major"))
        minor = int(m3.group("minor"))
        patch = int(m3.group("patch"))
        pre = m3.group("pre") or ""
        status = 0  # 3.0-plus release status nibble
        number = (major << 28) | (minor << 20) | (patch << 4) | status
        return Version(t, SCHEME_3_0_PLUS, major, minor, patch, 0, status, pre, number)
    mpre = _V_PRE.match(t)
    if mpre is not None:
        major = int(mpre.group("major"))
        minor = int(mpre.group("minor"))
        fix = int(mpre.group("fix"))
        letters = mpre.group("letters")
        pre = mpre.group("pre") or ""
        patch = _letters_to_patch(letters)
        status = 0xf if not pre else 0x0
        number = ((major << 28) | (minor << 20) | (fix << 12)
                  | (patch << 4) | status)
        return Version(t, SCHEME_PRE_3_0, major, minor, fix, patch, status, pre, number)
    raise VersionError(
        f"{text!r} is not decodable in either OpenSSL scheme: `MAJOR.MINOR.PATCH` for 3.0+, "
        f"`MAJOR.MINOR.FIX[letters]` before it"
    )


def version_scheme(text: str) -> str:
    """The scheme `text` is encoded in, or `VersionError`."""
    return parse_version(text).scheme


def openssl_version_number(text: str) -> int:
    """The decoded `OPENSSL_VERSION_NUMBER`-style integer for `text`."""
    return parse_version(text).number


def chronological_order(a: str, b: str) -> int:
    """`-1`, `0` or `1` for `a` before, equal to, or after `b` in the lineage's chronology.

    **This is not a compatibility comparison.** It orders releases; it makes no claim that a
    later release is compatible with a candidate, and no compatibility record may cite it.
    """
    ka, kb = parse_version(a).order_key(), parse_version(b).order_key()
    return (ka > kb) - (ka < kb)


def sorted_releases(values: list[str]) -> list[str]:
    """`values` in chronological order, by the same model `chronological_order` uses."""
    return sorted(values, key=lambda v: parse_version(v).order_key())


# --------------------------------------------------------------------------------------------
# field helpers
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


# --------------------------------------------------------------------------------------------
# the validators: each returns a list of problems, empty when the record is well-formed
# --------------------------------------------------------------------------------------------

def validate_release_node(rec: dict) -> list[str]:
    """A release node: one upstream release, with the identity of its scheme and source.

    `release_date`, `upstream_tag`, `upstream_commit`, `official_source_artifact` and
    `source_sha256` may each be the literal `unknown` -- a fact not yet established is stated, not
    invented -- but the identity and classification fields must be present.
    """
    fields = ("release_id", "display_version", "version_scheme", "release_channel",
              "release_date", "public_or_extended", "mainline_or_auxiliary", "upstream_tag",
              "upstream_commit", "official_source_artifact", "source_sha256",
              "declared_support_class", "declared_compatibility_family", "licence_epoch",
              "known_parent_edges", "metadata_provenance")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "release_id")
    problems += _enum(rec, "version_scheme", VERSION_SCHEMES)
    problems += _enum(rec, "release_channel", RELEASE_CHANNELS)
    problems += _enum(rec, "public_or_extended", PUBLIC_OR_EXTENDED)
    problems += _enum(rec, "mainline_or_auxiliary", MAINLINE_OR_AUXILIARY)
    for f in ("declared_support_class", "declared_compatibility_family", "licence_epoch"):
        problems += _nonempty(rec, f)
    if "display_version" in rec:
        try:
            parsed = parse_version(str(rec["display_version"]))
        except VersionError as exc:
            problems.append(f"display_version: {exc}")
        else:
            if rec.get("version_scheme") != parsed.scheme:
                problems.append(
                    f"version_scheme={rec.get('version_scheme')!r} contradicts the scheme "
                    f"{parsed.scheme!r} display_version {rec['display_version']!r} is written in"
                )
    date = rec.get("release_date")
    if date is not None and date != "unknown" and not (isinstance(date, str) and _DATE.match(date)):
        problems.append("release_date must be YYYY, YYYY-MM or YYYY-MM-DD, or the literal `unknown`")
    commit = rec.get("upstream_commit")
    if commit is not None and commit != "unknown" and not (
        isinstance(commit, str) and _HEX_COMMIT.match(commit)
    ):
        problems.append("upstream_commit must be a 7-40 hex commit or the literal `unknown`")
    problems += _unknownable_hash(rec, "source_sha256")
    parents = rec.get("known_parent_edges")
    if "known_parent_edges" in rec and not (
        isinstance(parents, list) and all(isinstance(p, str) for p in parents)
    ):
        problems.append("known_parent_edges must be a list of release ids")
    prov = rec.get("metadata_provenance")
    if "metadata_provenance" in rec and not (
        (isinstance(prov, str) and prov) or (isinstance(prov, list) and prov)
    ):
        problems.append("metadata_provenance must be a non-empty string or list")
    return problems


def validate_authority_node(rec: dict) -> list[str]:
    """An authority node: one *built* authority over a release, bound to a profile and hashes.

    An authority is always explicit and singular (D534): it names the release and the exact
    platform, architecture, profile, toolchain and build environment, and the binary and
    installed hashes that bind the build.
    """
    fields = ("authority_id", "release_id", "platform", "arch", "build_profile", "toolchain",
              "build_environment", "binary_hashes", "installed_hashes", "metadata_provenance")
    problems = _missing(rec, fields)
    for f in ("authority_id", "release_id", "platform", "arch", "build_profile", "toolchain"):
        problems += _nonempty(rec, f)
    for f in ("binary_hashes", "installed_hashes"):
        value = rec.get(f)
        if f in rec and not (isinstance(value, dict) and value):
            problems.append(f"{f} must be a non-empty hash map")
        elif isinstance(value, dict):
            for key, digest in value.items():
                if digest != "unknown" and not (isinstance(digest, str) and _HEX64.match(digest)):
                    problems.append(f"{f}[{key!r}] must be a 64-hex digest or `unknown`")
    env = rec.get("build_environment")
    if "build_environment" in rec and not (isinstance(env, (dict, str)) and env):
        problems.append("build_environment must be a non-empty mapping or string")
    return problems


def validate_lineage_edge(rec: dict) -> list[str]:
    """A lineage edge: a typed, directed relationship between two nodes, never a compatibility claim.

    `direction` is the **sense the edge is read in**, and it is load-bearing: `forward` means the
    relationship is read from `from_id` to `to_id`, `reverse` means it is read from `to_id` to
    `from_id`. Every edge carries both endpoints, its kind, its sense and the provenance it was read
    from, so the relationship cannot be re-read in the opposite direction silently.

    A `declared_abi_compatibility` edge is a **declaration** -- upstream's ABI promise -- and must be
    marked `declared: true`; it is never candidate evidence (the stratum's non-claim
    "upstream's ABI promise is not candidate evidence").
    """
    fields = ("edge_id", "kind", "from_id", "to_id", "direction", "evidence",
              "metadata_provenance")
    problems = _missing(rec, fields)
    for f in ("edge_id", "from_id", "to_id"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "kind", LINEAGE_EDGE_KINDS)
    problems += _enum(rec, "direction", ("forward", "reverse"))
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty (a lineage edge is not self-evident)")
    prov = rec.get("metadata_provenance")
    if "metadata_provenance" in rec and not (
        (isinstance(prov, str) and prov) or (isinstance(prov, list) and prov)
    ):
        problems.append("metadata_provenance must be a non-empty string or list (a lineage edge "
                        "with no provenance is an assertion)")
    if rec.get("kind") == "security_backport" and not rec.get("security_reference"):
        problems.append("a security_backport edge must name the security_reference it backports")
    if rec.get("kind") in ("declared_abi_compatibility", "observed_compatibility"):
        problems += _enum(rec, "dimension", COMPAT_DIMENSIONS)
    if rec.get("kind") == "declared_abi_compatibility" and rec.get("declared") is not True:
        problems.append("a declared_abi_compatibility edge must be marked `declared: true`: it "
                        "records upstream's ABI promise, never a candidate measurement")
    return problems


def validate_entity_lineage(rec: dict) -> list[str]:
    """What became of one public entity across releases."""
    fields = ("entity_id", "relation", "entity_kind", "present_in", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "entity_id")
    problems += _enum(rec, "relation", ENTITY_RELATIONS)
    if "present_in" in rec and not (isinstance(rec["present_in"], list) and rec["present_in"]):
        problems.append("present_in must be a non-empty list of release ids")
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    relation = rec.get("relation")
    if relation in ("renamed_to", "moved_to", "semantic_successor") and not rec.get("successor"):
        problems.append(f"relation {relation!r} must name its successor")
    if relation == "split_into":
        succ = rec.get("successors")
        if not (isinstance(succ, list) and len(succ) >= 2):
            problems.append("split_into must name two or more successors")
    if relation == "merged_from":
        preds = rec.get("predecessors")
        if not (isinstance(preds, list) and len(preds) >= 2):
            problems.append("merged_from must name two or more predecessors")
    if relation == "removed" and not rec.get("removed_in"):
        problems.append("removed must name the release it was removed in")
    if relation == "reintroduced" and not (rec.get("removed_in") and rec.get("reintroduced_in")):
        problems.append("reintroduced must name both removed_in and reintroduced_in")
    return problems


def validate_compatibility_view(rec: dict) -> list[str]:
    """A compatibility view: directional, dimension-specific, evidence-bearing, never a boolean.

    The refusal this encodes is D535: a view that carries a bare `compatible` boolean and no
    dimension or direction is exactly the claim the model forbids, so it is a problem rather than
    a terse form. The view also states its `evidence_kind`, and **`version_order` is refused by
    name**: numeric ordering is a chronology, not a compatibility measurement, so a view may not
    cite an ordering as the evidence it was derived from (docs/PARITY_MODEL.md sections 3 and 4).
    """
    fields = ("view_id", "subject_id", "reference_id", "dimension", "direction", "status",
              "evidence_kind", "evidence", "support_status", "non_claims")
    problems = _missing(rec, fields)
    for f in ("view_id", "subject_id", "reference_id"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "dimension", COMPAT_DIMENSIONS)
    problems += _enum(rec, "direction", COMPAT_DIRECTIONS)
    problems += _enum(rec, "status", COMPAT_STATUSES)
    problems += _enum(rec, "support_status", SUPPORT_STATUSES)
    kind = rec.get("evidence_kind")
    if kind == "version_order":
        problems.append(
            "evidence_kind `version_order` is refused: a compatibility view is never derived from "
            "numeric ordering (D535, docs/PARITY_MODEL.md section 4)"
        )
    elif "evidence_kind" in rec and kind not in EVIDENCE_KINDS:
        problems.append(f"evidence_kind={kind!r} is not one of {sorted(EVIDENCE_KINDS)}")
    if "compatible" in rec:
        problems.append(
            "a compatibility view may not carry a bare `compatible` boolean: compatibility is "
            "directional and dimension-specific (D535)"
        )
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty (a view inherits no receipt across versions)")
    if "non_claims" in rec and not rec["non_claims"]:
        problems.append("non_claims must be non-empty")
    if rec.get("subject_id") and rec.get("reference_id") and not rec.get("direction"):
        problems.append("a view between two nodes must state its direction")
    return problems


def validate_compatibility_edge(rec: dict) -> list[str]:
    """A directional compatibility edge on one dimension, with non-ordering evidence.

    **`version_order` is not an evidence kind.** A record whose evidence kind is `version_order`
    is rejected by name, so numeric ordering can never stand in for a measurement (D535).
    """
    fields = ("edge_id", "from_id", "to_id", "dimension", "direction", "status", "evidence_kind",
              "evidence")
    problems = _missing(rec, fields)
    for f in ("edge_id", "from_id", "to_id"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "dimension", COMPAT_DIMENSIONS)
    problems += _enum(rec, "direction", COMPAT_DIRECTIONS)
    problems += _enum(rec, "status", COMPAT_STATUSES)
    kind = rec.get("evidence_kind")
    if kind == "version_order":
        problems.append(
            "evidence_kind `version_order` is refused: compatibility is not derived from numeric "
            "ordering (D535, docs/PARITY_MODEL.md section 4)"
        )
    elif "evidence_kind" in rec and kind not in EVIDENCE_KINDS:
        problems.append(f"evidence_kind={kind!r} is not one of {sorted(EVIDENCE_KINDS)}")
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    return problems


def validate_negative_obligation(rec: dict) -> list[str]:
    """A negative (or positive) obligation: `must_not_exist` is a first-class obligation (D536)."""
    fields = ("obligation_id", "kind", "subject", "scope", "rationale", "evidence", "state")
    problems = _missing(rec, fields)
    for f in ("obligation_id", "subject", "rationale"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "kind", NEGATIVE_OBLIGATION_KINDS)
    problems += _enum(rec, "state", NEGATIVE_OBLIGATION_STATES)
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    scope = rec.get("scope")
    if "scope" in rec and not (scope in ("release", "authority") or isinstance(scope, dict)):
        problems.append("scope must be `release`, `authority`, or a mapping of both")
    return problems


def validate_support_status(rec: dict) -> list[str]:
    """A support-status row: the ladder rungs a node has climbed, ordered.

    `rungs_attained` must be an ordered subsequence of `SUPPORT_LADDER` with no duplicates, and the
    rungs `SUPPORT_CORE` names must form a **prefix** -- a node cannot skip a core rung. The rungs
    above the core are each read from an independent evidence plane (23.10), so a node may attain
    them without the intermediate additive rungs; `status` is the highest rung attained, and
    `archaeological-only` has climbed none. Every rung a node claims is backed by evidence, which is
    the court's check rather than the schema's (the schema sees the shape, not the artefact).
    """
    fields = ("subject_id", "status", "rungs_attained", "evidence")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "subject_id")
    problems += _enum(rec, "status", SUPPORT_STATUSES)
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    rungs = rec.get("rungs_attained")
    if "rungs_attained" in rec and not isinstance(rungs, list):
        problems.append("rungs_attained must be a list")
        return problems
    if isinstance(rungs, list):
        if any(r not in SUPPORT_LADDER for r in rungs):
            problems.append(f"rungs_attained contains a name outside {list(SUPPORT_LADDER)}")
        elif len(set(rungs)) != len(rungs):
            problems.append("rungs_attained names a rung twice")
        else:
            indices = [SUPPORT_LADDER.index(r) for r in rungs]
            if indices != sorted(indices):
                problems.append(
                    f"rungs_attained must be ordered along the ladder {list(SUPPORT_LADDER)}, so "
                    f"a rung cannot be attained out of order"
                )
            core = [r for r in rungs if r in SUPPORT_CORE]
            if core != list(SUPPORT_CORE[: len(core)]):
                problems.append(
                    f"the core rungs {list(SUPPORT_CORE)} must be climbed as a prefix, so a node "
                    f"cannot skip a core rung it did not evidence"
                )
    status = rec.get("status")
    if status in SUPPORT_LADDER and isinstance(rungs, list) and rungs:
        if max(rungs, key=SUPPORT_LADDER.index) != status:
            problems.append(
                f"status {status!r} is not the highest rung of rungs_attained {rungs!r}: a "
                f"support status is the highest rung an evidence plane reached"
            )
    if status == "archaeological-only" and isinstance(rungs, list) and rungs:
        problems.append("an archaeological-only node has climbed no rung, so rungs_attained must "
                        "be empty")
    return problems


def validate_population_record(rec: dict) -> list[str]:
    """A historical-population row: a node's support status, the rungs it climbed, and its reason.

    The load-bearing refusal is the one the brief fixes: a node recorded `runtime_compatible` that
    did not attain `runtime-evidenced` -- in particular an unavailable release -- is refused, so a
    release that cannot be reproducibly built is never counted runtime-compatible. A ladder
    `status` must be the highest rung in `rungs_attained`; `archaeological-only` has climbed none,
    so it carries an empty rung list.
    """
    fields = ("release_id", "display_version", "release_channel", "epoch", "scope", "outcome",
              "status", "rungs_attained", "runtime_compatible", "reason", "evidence")
    problems = _missing(rec, fields)
    for f in ("release_id", "display_version", "reason"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "release_channel", RELEASE_CHANNELS)
    problems += _enum(rec, "epoch", POPULATION_EPOCHS)
    problems += _enum(rec, "scope", POPULATION_SCOPES)
    problems += _enum(rec, "outcome", POPULATION_OUTCOMES)
    problems += _enum(rec, "status", SUPPORT_STATUSES)
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    rungs = rec.get("rungs_attained")
    if "rungs_attained" in rec and not isinstance(rungs, list):
        problems.append("rungs_attained must be a list")
        return problems
    if isinstance(rungs, list):
        status = rec.get("status")
        if any(r not in SUPPORT_LADDER for r in rungs):
            problems.append(f"rungs_attained contains a name outside {list(SUPPORT_LADDER)}")
        elif len(set(rungs)) != len(rungs):
            problems.append("rungs_attained names a rung twice")
        if status in SUPPORT_LADDER:
            if not rungs:
                problems.append(f"status {status!r} is a ladder rung but rungs_attained is empty")
            elif max(rungs, key=SUPPORT_LADDER.index) != status:
                problems.append(
                    f"status {status!r} is not the highest rung of rungs_attained {rungs!r}: a "
                    f"population status is the highest rung an evidence plane reached"
                )
        if status == "archaeological-only" and rungs:
            problems.append("an archaeological-only node has climbed no rung, so rungs_attained "
                            "must be empty")
    compatible = rec.get("runtime_compatible")
    if "runtime_compatible" in rec and not isinstance(compatible, bool):
        problems.append("runtime_compatible must be a boolean")
    if compatible is True and not (isinstance(rungs, list) and "runtime-evidenced" in rungs):
        problems.append(
            "runtime_compatible is true but the node did not attain `runtime-evidenced`: a "
            "release is never counted runtime-compatible without runtime evidence, and an "
            "unavailable release never is"
        )
    return problems


def validate_downstream_epoch(rec: dict) -> list[str]:
    """A downstream-multitrack record: one unmodified consumer against one built authority.

    The load-bearing refusals are the ones the brief fixes (docs/PHASE-23-MULTITRACK-SUBPHASES.md
    row 23.11, brief section 40): a `passed` consumer must carry a genuine build and a genuine run
    -- a claim of a pass with `build.ok` or `run.ok` false is refused, so a consumer that was not
    actually built and exercised is never read as passing -- and a `not_run` / `failed` record must
    carry the reason it did not run and must not claim a passing build or run. Every record names
    the authority (release, build profile and platform), so a result is never relayed across
    authorities, and every record names the consumer and its version, so a pass names what actually
    consumed the authority.
    """
    fields = ("trial_id", "epoch", "role", "consumer", "consumer_version", "source",
              "authority_id", "release_id", "authority", "outcome", "build", "run",
              "observation", "reason", "evidence")
    problems = _missing(rec, fields)
    for f in ("trial_id", "consumer", "consumer_version", "authority_id", "release_id"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "epoch", POPULATION_EPOCHS)
    problems += _enum(rec, "role", DOWNSTREAM_ROLES)
    problems += _enum(rec, "outcome", DOWNSTREAM_OUTCOMES)
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    authority = rec.get("authority")
    if "authority" in rec and not isinstance(authority, dict):
        problems.append("authority must be an object naming the release, build profile and platform")
    elif isinstance(authority, dict):
        for f in ("authority_id", "release_id", "build_profile", "platform"):
            if not authority.get(f):
                problems.append(f"authority.{f} must be present and non-empty")
    build = rec.get("build")
    run = rec.get("run")
    if "build" in rec and not isinstance(build, dict):
        problems.append("build must be an object")
    if "run" in rec and not isinstance(run, dict):
        problems.append("run must be an object")
    outcome = rec.get("outcome")
    if outcome == "passed":
        if isinstance(build, dict) and build.get("ok") is not True:
            problems.append(
                "a passing consumer must have build.ok true: a pass is the built artifact, not "
                "the claim"
            )
        if isinstance(run, dict) and run.get("ok") is not True:
            problems.append(
                "a passing consumer must have run.ok true: a built consumer that ran no workload "
                "is not a pass"
            )
        if not rec.get("observation"):
            problems.append("a passing consumer must state the observation its workload made")
    elif outcome in ("not_run", "failed"):
        if not rec.get("reason"):
            problems.append(f"an {outcome} record must carry the reason it did not pass")
        if isinstance(build, dict) and build.get("ok") is True:
            problems.append(f"an {outcome} record must not claim a passing build")
        if isinstance(run, dict) and run.get("ok") is True:
            problems.append(f"an {outcome} record must not claim a passing run")
    return problems


def validate_delta_receipt(rec: dict) -> list[str]:
    """A delta-engine record: the added / removed / changed surface between two nodes."""
    fields = ("receipt_id", "from_id", "to_id", "dimension", "direction", "added", "removed",
              "changed", "evidence")
    problems = _missing(rec, fields)
    for f in ("receipt_id", "from_id", "to_id"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "dimension", COMPAT_DIMENSIONS)
    problems += _enum(rec, "direction", COMPAT_DIRECTIONS)
    for f in ("added", "removed", "changed"):
        if f in rec and not isinstance(rec[f], list):
            problems.append(f"{f} must be a list")
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty (the delta is computed, never hand-listed)")
    return problems


def validate_security_observation(rec: dict) -> list[str]:
    """A security-lineage observation: one historical vulnerability, observed and never
    reintroduced.

    (Extended by 23.14.) One record is one **(vulnerability, maintained-branch fix)** row: it names
    the vulnerability identity (`vulnerability_id`), the affected range, the fixed release
    (`fixed_in`, `release_id`), the maintained `branch`, the upstream `severity`, the affected
    `subsystem`, the `fips_impact` upstream states (or `not_stated`), and the **candidate
    disposition**. A release whose source is not publicly available is an *external release
    reference* (`external_release_reference: true`) and is never an authority
    (`authority_id` must be null); the binding is one vulnerability identity to many branch-fix
    rows.

    The load-bearing refusal is the one the policy fixes: `reintroduced` must be the literal false,
    and a `candidate_disposition` of `preserve_vulnerable_behaviour` is refused **by name** -- a
    view may never re-adopt the behaviour a fixed release moved away from
    (`docs/SECURITY_DIVERGENCE_POLICY.md` sections 1 and 3).
    """
    fields = ("observation_id", "vulnerability_id", "release_id", "affected", "fixed_in",
              "reference", "branch", "severity", "subsystem", "fips_impact",
              "candidate_disposition", "external_release_reference", "authority_id", "evidence",
              "reintroduced")
    problems = _missing(rec, fields)
    for f in ("observation_id", "vulnerability_id", "release_id", "affected", "fixed_in",
              "reference", "branch"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "severity", SECURITY_SEVERITIES)
    disposition = rec.get("candidate_disposition")
    if disposition == "preserve_vulnerable_behaviour":
        problems.append(
            "candidate_disposition `preserve_vulnerable_behaviour` is refused: a security view may "
            "never re-adopt the behaviour a fixed release moved away from "
            "(docs/SECURITY_DIVERGENCE_POLICY.md sections 1 and 3)"
        )
    elif "candidate_disposition" in rec and disposition not in SECURITY_DISPOSITIONS:
        problems.append(f"candidate_disposition={disposition!r} is not one of "
                        f"{sorted(SECURITY_DISPOSITIONS)}")
    if "external_release_reference" in rec and not isinstance(rec["external_release_reference"],
                                                             bool):
        problems.append("external_release_reference must be a boolean")
    subsystem = rec.get("subsystem")
    if "subsystem" in rec:
        if not isinstance(subsystem, dict) or not subsystem.get("token"):
            problems.append("subsystem must be a mapping naming the affected subsystem token")
    fips = rec.get("fips_impact")
    if "fips_impact" in rec:
        if not isinstance(fips, dict):
            problems.append("fips_impact must be a mapping (upstream's statement, or not_stated)")
        else:
            if not isinstance(fips.get("stated"), bool):
                problems.append("fips_impact.stated must be a boolean")
            if fips.get("impact") not in SECURITY_FIPS_IMPACTS:
                problems.append(f"fips_impact.impact={fips.get('impact')!r} is not one of "
                                f"{sorted(SECURITY_FIPS_IMPACTS)}")
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty")
    if rec.get("reintroduced") is not False:
        problems.append(
            "reintroduced must be the literal false: a historical vulnerability is observed and "
            "never reintroduced (docs/SECURITY_DIVERGENCE_POLICY.md section 1)"
        )
    return problems


def validate_parameterization_receipt(rec: dict) -> list[str]:
    """A parameterization receipt: the same code path over several authorities, with every
    measured absence a counted zero that carries its provenance.

    The load-bearing invariant is that a `measured_absence` row is never an omission: it must
    carry `count == 0` **and** non-empty evidence. A receipt whose census row claims an absence
    with no evidence, or an absence with a nonzero count, is refused.
    """
    fields = ("receipt_id", "default_authority", "plane_order", "censuses",
              "measured_absences", "byte_identity")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "receipt_id")
    problems += _nonempty(rec, "default_authority")
    if "plane_order" in rec and not rec["plane_order"]:
        problems.append("plane_order must list the shared plane set")
    censuses = rec.get("censuses")
    if "censuses" in rec and not isinstance(censuses, dict):
        problems.append("censuses must be a mapping of authority id -> census")
        return problems
    absent = rec.get("measured_absences")
    if "measured_absences" in rec and not isinstance(absent, dict):
        problems.append("measured_absences must be a mapping of authority id -> plane list")
    for aid, census in sorted((censuses or {}).items()):
        if not isinstance(census, dict):
            problems.append(f"census[{aid}] must be a mapping")
            continue
        if census.get("authority_id") != aid:
            problems.append(f"census[{aid}] names authority_id {census.get('authority_id')!r}")
        planes = census.get("planes")
        if not isinstance(planes, list) or not planes:
            problems.append(f"census[{aid}] must carry a non-empty plane list")
            continue
        for row in planes:
            if not isinstance(row, dict) or not row.get("plane"):
                problems.append(f"census[{aid}] carries a plane row with no name")
                continue
            if row.get("status") not in ("produced", "measured_absence"):
                problems.append(f"census[{aid}] plane {row['plane']!r} status "
                                f"{row.get('status')!r} is not produced/measured_absence")
            if row.get("status") == "measured_absence":
                if row.get("count") != 0:
                    problems.append(f"census[{aid}] measured absence {row['plane']!r} has "
                                    f"count {row.get('count')!r}, not zero")
                ev = row.get("evidence")
                if not ev:
                    problems.append(f"census[{aid}] measured absence {row['plane']!r} carries "
                                    f"no evidence (an absence is a counted claim)")
    byte_identity = rec.get("byte_identity")
    if "byte_identity" in rec:
        if not isinstance(byte_identity, dict):
            problems.append("byte_identity must be a mapping")
        else:
            if not byte_identity.get("authority_id"):
                problems.append("byte_identity must name the authority it binds")
            if not isinstance(byte_identity.get("files"), list):
                problems.append("byte_identity.files must be a list")
    return problems


def validate_abi_facade(rec: dict) -> list[str]:
    """An ABI/history façade record: a public layout, a prototype, or an epoch model.

    The record kind is discriminated by `facade_kind`, and each kind carries its own required
    fields and closed vocabulary. Every record names the **adapter** that translates it to or from
    the shared implementation, so a record whose only link to the canonical internals would be a
    blind cast fails rather than reads plausibly. A public-layout record's fields must be a
    non-overlapping, increasing-offset partition of a struct at least as large as its last field,
    and its `header_sha256` must be a real digest or the literal `unknown`.
    """
    fields = ("facade_id", "facade_kind", "authority_id", "release_id", "epoch", "adapter",
              "evidence", "not_established")
    problems = _missing(rec, fields)
    for f in ("facade_id", "authority_id", "release_id", "epoch", "adapter"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "facade_kind", FACADE_KINDS)
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty (a façade cites the authority it was read from)")
    if "not_established" in rec and not isinstance(rec["not_established"], list):
        problems.append("not_established must be a list (empty when the record is fully settled)")

    kind = rec.get("facade_kind")
    if kind == "public_layout":
        problems += _missing(rec, ("struct_name", "c_tag", "canonical_c_tag", "rust_type",
                                   "header", "installed_header", "header_sha256",
                                   "public_layout_epoch", "sizeof", "alignof", "fields",
                                   "canonical_type", "canonical_authority_id",
                                   "canonical_public_layout_epoch", "layout_check"))
        for f in ("struct_name", "c_tag", "canonical_c_tag", "rust_type", "header",
                  "canonical_type", "canonical_authority_id", "layout_check"):
            problems += _nonempty(rec, f)
        problems += _enum(rec, "public_layout_epoch", PUBLIC_LAYOUT_EPOCHS)
        problems += _enum(rec, "canonical_public_layout_epoch", PUBLIC_LAYOUT_EPOCHS)
        problems += _unknownable_hash(rec, "header_sha256")
        size = rec.get("sizeof")
        align = rec.get("alignof")
        if not isinstance(size, int) or size <= 0:
            problems.append("sizeof must be a positive integer")
        if not isinstance(align, int) or align <= 0:
            problems.append("alignof must be a positive integer")
        rows = rec.get("fields")
        if not isinstance(rows, list) or not rows:
            problems.append("fields must be a non-empty list")
        else:
            previous_end = 0
            for i, field in enumerate(rows):
                if not isinstance(field, dict):
                    problems.append(f"fields[{i}] must be a mapping")
                    continue
                for key in ("name", "c_type", "offset", "size"):
                    if key not in field:
                        problems.append(f"fields[{i}] is missing {key!r}")
                offset, width = field.get("offset"), field.get("size")
                if not isinstance(offset, int) or not isinstance(width, int) or width <= 0:
                    problems.append(f"fields[{i}] ({field.get('name')!r}) needs integer offset/size")
                    continue
                if offset < previous_end:
                    problems.append(
                        f"fields[{i}] ({field.get('name')!r}) at {offset} overlaps the previous "
                        f"field, which ends at {previous_end}"
                    )
                previous_end = offset + width
            if isinstance(size, int) and previous_end > size:
                problems.append(
                    f"the last field ends at {previous_end}, past sizeof {size}"
                )
    elif kind == "prototype":
        problems += _missing(rec, ("symbol", "eras", "authority_specific"))
        problems += _nonempty(rec, "symbol")
        if rec.get("authority_specific") is not True:
            problems.append("authority_specific must be the literal true: the point of the record "
                            "is that the eras declare the symbol differently")
        eras = rec.get("eras")
        if not isinstance(eras, list) or len(eras) < 2:
            problems.append("eras must name at least the historical and canonical declarations")
        else:
            for i, era in enumerate(eras):
                if not isinstance(era, dict):
                    problems.append(f"eras[{i}] must be a mapping")
                    continue
                for key in ("era", "authority_id", "declaration", "kind", "header"):
                    if key not in era:
                        problems.append(f"eras[{i}] is missing {key!r}")
                if era.get("kind") not in PROTOTYPE_CONTRACT_KINDS:
                    problems.append(
                        f"eras[{i}].kind={era.get('kind')!r} is not one of "
                        f"{sorted(PROTOTYPE_CONTRACT_KINDS)}"
                    )
    elif kind == "architecture":
        problems += _missing(rec, ("engine_model", "provider_model"))
        problems += _enum(rec, "engine_model", ENGINE_MODELS)
        problems += _enum(rec, "provider_model", PROVIDER_MODELS)
    elif kind == "init_thread":
        problems += _missing(rec, ("init_model", "thread_model", "callbacks"))
        problems += _enum(rec, "init_model", INIT_MODELS)
        problems += _enum(rec, "thread_model", THREAD_MODELS)
        cbs = rec.get("callbacks")
        if "callbacks" in rec and not (isinstance(cbs, list)
                                       and all(isinstance(c, str) for c in cbs)):
            problems.append("callbacks must be a list of symbol names")
    return problems


def validate_semantic_observation(rec: dict) -> list[str]:
    """A semantic observation: one normalized reading of one probe, on two named authorities.

    (Added by 23.8.) The record is the *shared normalized observation vocabulary*: the same
    `vocabulary` key and the same `observed_a` / `observed_b` fields on both sides, so the two runs
    are read the same way and a comparison is a comparison rather than a translation. A value that
    could not be observed is the literal `<absent>` rather than a missing field, so an equal reading
    can never be confused with an unobserved one. The `classification` is the release-delta kind and
    is checked against the closed vocabulary; an `agreed` reading and a `release_identity` reading
    that disagree with `agreement` are both refused, because either would let a difference be read as
    sameness or sameness be read as a difference. Where a delta row carries the reading, `release_delta`
    names the fine dimension and the entity the 23.6 engine keys the row by, so the observation is
    tied to the delta engine rather than restated beside it.
    """
    fields = ("observation_id", "vocabulary", "dimension", "authority_a", "authority_b",
              "observed_a", "observed_b", "agreement", "classification", "release_delta",
              "evidence")
    problems = _missing(rec, fields)
    for f in ("observation_id", "vocabulary", "authority_a", "authority_b", "classification"):
        problems += _nonempty(rec, f)
    problems += _enum(rec, "dimension", COMPAT_DIMENSIONS)
    problems += _enum(rec, "classification", SEMANTIC_CLASSIFICATIONS)
    for f in ("observed_a", "observed_b"):
        if f in rec and not isinstance(rec[f], str):
            problems.append(f"{f} must be a string (the normalized value, or `<absent>`)")
    agreement = rec.get("agreement")
    if not isinstance(agreement, bool):
        problems.append("agreement must be a boolean")
    else:
        classification = rec.get("classification")
        if agreement and classification != "agreed":
            problems.append("an agreeing observation must be classified `agreed`")
        if not agreement and classification == "agreed":
            problems.append("a divergent observation must not be classified `agreed`")
    delta = rec.get("release_delta")
    if delta is not None:
        if not isinstance(delta, dict):
            problems.append("release_delta must be null or a mapping")
        else:
            for key in ("dimension", "entity_id"):
                if not delta.get(key):
                    problems.append(f"release_delta must name its {key}")
    if "evidence" in rec and not rec["evidence"]:
        problems.append("evidence must be non-empty (an observation cites the raw transcript it "
                        "was read from)")
    return problems


def validate_compatibility_matrix(rec: dict) -> list[str]:
    """The assembled matrix: cells that are each directional and dimension-specific."""
    fields = ("matrix_id", "rows", "generated_from")
    problems = _missing(rec, fields)
    problems += _nonempty(rec, "matrix_id")
    if "generated_from" in rec and not rec["generated_from"]:
        problems.append("generated_from must be non-empty")
    rows = rec.get("rows")
    if "rows" in rec and not isinstance(rows, list):
        problems.append("rows must be a list")
        return problems
    for i, cell in enumerate(rows or []):
        if not isinstance(cell, dict):
            problems.append(f"rows[{i}] must be a mapping")
            continue
        if "compatible" in cell:
            problems.append(f"rows[{i}] carries a bare `compatible` boolean; cells are directional")
        if not cell.get("dimension"):
            problems.append(f"rows[{i}] must name its dimension")
        if not cell.get("direction"):
            problems.append(f"rows[{i}] must name its direction")
    return problems


# The registries the ledger, the runner and the later subphases read. `SCHEMAS` names each record
# kind and its validator; `REQUIRED_FIELDS` is what the inventory publishes.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "release_node": ("release_id", "display_version", "version_scheme", "release_channel",
                     "release_date", "public_or_extended", "mainline_or_auxiliary", "upstream_tag",
                     "upstream_commit", "official_source_artifact", "source_sha256",
                     "declared_support_class", "declared_compatibility_family", "licence_epoch",
                     "known_parent_edges", "metadata_provenance"),
    "authority_node": ("authority_id", "release_id", "platform", "arch", "build_profile",
                       "toolchain", "build_environment", "binary_hashes", "installed_hashes",
                       "metadata_provenance"),
    "lineage_edge": ("edge_id", "kind", "from_id", "to_id", "direction", "evidence",
                     "metadata_provenance"),
    "entity_lineage": ("entity_id", "relation", "entity_kind", "present_in", "evidence"),
    "delta_receipt": ("receipt_id", "from_id", "to_id", "dimension", "direction", "added",
                      "removed", "changed", "evidence"),
    "compatibility_view": ("view_id", "subject_id", "reference_id", "dimension", "direction",
                           "status", "evidence_kind", "evidence", "support_status", "non_claims"),
    "compatibility_edge": ("edge_id", "from_id", "to_id", "dimension", "direction", "status",
                           "evidence_kind", "evidence"),
    "negative_obligation": ("obligation_id", "kind", "subject", "scope", "rationale", "evidence",
                            "state"),
    "security_observation": ("observation_id", "vulnerability_id", "release_id", "affected",
                             "fixed_in", "reference", "branch", "severity", "subsystem",
                             "fips_impact", "candidate_disposition", "external_release_reference",
                             "authority_id", "evidence", "reintroduced"),
    "support_status": ("subject_id", "status", "rungs_attained", "evidence"),
    "population_record": ("release_id", "display_version", "release_channel", "epoch", "scope",
                          "outcome", "status", "rungs_attained", "runtime_compatible", "reason",
                          "evidence"),
    "compatibility_matrix": ("matrix_id", "rows", "generated_from"),
    "parameterization_receipt": ("receipt_id", "default_authority", "plane_order", "censuses",
                                 "measured_absences", "byte_identity"),
    "abi_facade": ("facade_id", "facade_kind", "authority_id", "release_id", "epoch", "adapter",
                   "evidence", "not_established"),
    "semantic_observation": ("observation_id", "vocabulary", "dimension", "authority_a",
                             "authority_b", "observed_a", "observed_b", "agreement",
                             "classification", "release_delta", "evidence"),
    "downstream_epoch": ("trial_id", "epoch", "role", "consumer", "consumer_version", "source",
                         "authority_id", "release_id", "authority", "outcome", "build", "run",
                         "observation", "reason", "evidence"),
}

SCHEMAS = {
    "release_node": validate_release_node,
    "authority_node": validate_authority_node,
    "lineage_edge": validate_lineage_edge,
    "entity_lineage": validate_entity_lineage,
    "delta_receipt": validate_delta_receipt,
    "compatibility_view": validate_compatibility_view,
    "compatibility_edge": validate_compatibility_edge,
    "negative_obligation": validate_negative_obligation,
    "security_observation": validate_security_observation,
    "support_status": validate_support_status,
    "population_record": validate_population_record,
    "compatibility_matrix": validate_compatibility_matrix,
    "parameterization_receipt": validate_parameterization_receipt,
    "abi_facade": validate_abi_facade,
    "semantic_observation": validate_semantic_observation,
    "downstream_epoch": validate_downstream_epoch,
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
    "release_node": {
        "release_id": "openssl-1.1.1w",
        "display_version": "1.1.1w",
        "version_scheme": SCHEME_PRE_3_0,
        "release_channel": "final",
        "release_date": "2023-09-11",
        "public_or_extended": "public",
        "mainline_or_auxiliary": "mainline",
        "upstream_tag": "OpenSSL_1_1_1w",
        "upstream_commit": "a1b2c3d",
        "official_source_artifact": "openssl-1.1.1w.tar.gz",
        "source_sha256": _DIGEST,
        "declared_support_class": "lts",
        "declared_compatibility_family": "openssl-1.1",
        "licence_epoch": "OpenSSL",
        "known_parent_edges": ["openssl-1.1.1v"],
        "metadata_provenance": ["forensics/authorities/SOURCE_MANIFEST.3.6.4.json"],
    },
    "authority_node": {
        "authority_id": "openssl-3.6.4-production",
        "release_id": "openssl-3.6.4",
        "platform": "linux",
        "arch": "x86_64",
        "build_profile": "linux-x86_64-default-shared-legacy-notests",
        "toolchain": "gcc-12.2",
        "build_environment": {"image": "openssl-rs-court:1"},
        "binary_hashes": {"libcrypto.so.3": _DIGEST},
        "installed_hashes": {"include/openssl/ssl.h": _DIGEST},
        "metadata_provenance": ["forensics/atlas/BUILD_RECORDS.json"],
    },
    "lineage_edge": {
        "edge_id": "L-3.6.3-3.6.4",
        "kind": "maintenance_successor",
        "from_id": "openssl-3.6.3",
        "to_id": "openssl-3.6.4",
        "direction": "forward",
        "evidence": ["forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json"],
        "metadata_provenance": ["docs/AUTHORITY_POLICY.md"],
    },
    "entity_lineage": {
        "entity_id": "SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "relation": "same_entity",
        "entity_kind": "macro",
        "present_in": ["openssl-3.6.3", "openssl-3.6.4"],
        "evidence": ["forensics/atlas/openssl-3.6.4-production/macros.json"],
    },
    "delta_receipt": {
        "receipt_id": "D-3.6.3-3.6.4-macros",
        "from_id": "openssl-3.6.3",
        "to_id": "openssl-3.6.4",
        "dimension": "source_api",
        "direction": "reference_to_candidate",
        "added": ["SSL_VALUE_QUIC_MAX_PENDING_CONNS"],
        "removed": [],
        "changed": [],
        "evidence": ["forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json"],
    },
    "compatibility_view": {
        "view_id": "V-3.6.4-source_api",
        "subject_id": "openssl-rs",
        "reference_id": "openssl-3.6.4",
        "dimension": "source_api",
        "direction": "candidate_to_reference",
        "status": "compatible",
        "evidence_kind": "atlas_differential",
        "evidence": ["forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json"],
        "support_status": "atlas-complete",
        "non_claims": ["one platform/profile is not every platform/profile"],
    },
    "compatibility_edge": {
        "edge_id": "E-3.6.3-3.6.4-source_api",
        "from_id": "openssl-3.6.3",
        "to_id": "openssl-3.6.4",
        "dimension": "source_api",
        "direction": "reference_to_candidate",
        "status": "compatible",
        "evidence_kind": "atlas_differential",
        "evidence": ["forensics/atlas/differential/openssl-3.6.3-historical-vs-openssl-3.6.4-production.json"],
    },
    "negative_obligation": {
        "obligation_id": "N-ERR_put_error-not-exported",
        "kind": "must_not_be_exported",
        "subject": "ERR_put_error",
        "scope": "authority",
        "rationale": "a NOEXIST row declares the symbol deliberately not exported",
        "evidence": ["util/libcrypto.num"],
        "state": "satisfied",
    },
    "security_observation": {
        "observation_id": "SO-CVE-2016-0777-openssl-1.0.2g",
        "vulnerability_id": "CVE-2016-0777",
        "release_id": "openssl-1.0.2g",
        "affected": "from 1.0.2 before 1.0.2g",
        "fixed_in": "1.0.2g",
        "reference": "CVE-2016-0777",
        "branch": "1.0.2",
        "severity": "high",
        "subsystem": {"token": "crypto/bn", "basis": "advisory keyword BN_mod_sqrt",
                      "source_quote": "The BN_mod_sqrt() function ..."},
        "fips_impact": {"stated": False, "impact": "not_stated", "source_quote": ""},
        "candidate_disposition": "never_contained",
        "external_release_reference": False,
        "authority_id": None,
        "evidence": ["docs/SECURITY_DIVERGENCE_POLICY.md",
                     "forensics/multitrack/security-source.json"],
        "reintroduced": False,
    },
    "support_status": {
        "subject_id": "openssl-3.6.4",
        "status": "built-authority",
        "rungs_attained": ["catalogued", "admitted-source", "built-authority"],
        "evidence": ["forensics/atlas/BUILD_RECORDS.json"],
    },
    "population_record": {
        "release_id": "openssl-1.0.2u",
        "display_version": "1.0.2u",
        "release_channel": "final",
        "epoch": "1.0.x",
        "scope": "final-release-lineage",
        "outcome": "built",
        "status": "built-authority",
        "rungs_attained": ["catalogued", "admitted-source", "built-authority"],
        "runtime_compatible": False,
        "reason": "built in the historical venue; no committed atlas exists for this authority",
        "evidence": ["forensics/multitrack/historical-build-receipts.json"],
    },
    "compatibility_matrix": {
        "matrix_id": "M-2026-10-06",
        "rows": [{
            "subject_id": "openssl-rs",
            "reference_id": "openssl-3.6.4",
            "dimension": "source_api",
            "direction": "candidate_to_reference",
            "status": "compatible",
        }],
        "generated_from": ["forensics/multitrack/compatibility-views.json"],
    },
    "parameterization_receipt": {
        "receipt_id": "PARAM-openssl-3.6.4-production",
        "default_authority": "openssl-3.6.4-production",
        "plane_order": ["source-tree", "providers", "quic"],
        "censuses": {
            "openssl-3.6.4-production": {
                "authority_id": "openssl-3.6.4-production",
                "planes": [{"plane": "providers", "status": "produced", "count": 388,
                            "evidence": {"manifest_paths_matched": 388}}],
            },
            "openssl-0.9.8zh-historical": {
                "authority_id": "openssl-0.9.8zh-historical",
                "planes": [{"plane": "providers", "status": "measured_absence", "count": 0,
                            "evidence": {"manifest_paths_matched": 0,
                                         "detail": "0.9.8zh predates the 3.0.0 provider model"}}],
            },
        },
        "measured_absences": {"openssl-0.9.8zh-historical": ["providers"]},
        "byte_identity": {"authority_id": "openssl-3.6.4-production",
                          "files": [{"path": "forensics/atlas/openssl-3.6.4-production/functions.json",
                                     "sha256": _DIGEST}]},
    },
    "abi_facade": {
        "facade_id": "F-EVP_MD_CTX-0.9.8zh",
        "facade_kind": "public_layout",
        "authority_id": "openssl-0.9.8zh-historical",
        "release_id": "openssl-0.9.8zh",
        "epoch": "0.9.8zh",
        "struct_name": "EVP_MD_CTX",
        "c_tag": "env_md_ctx_st",
        "canonical_c_tag": "evp_md_ctx_st",
        "rust_type": "FacadeEvpMdCtx",
        "header": "crypto/evp/evp.h",
        "installed_header": "openssl/evp.h",
        "header_sha256": _DIGEST,
        "public_layout_epoch": "transparent_pre_1_1_0",
        "sizeof": 32,
        "alignof": 8,
        "fields": [
            {"name": "digest", "c_type": "const EVP_MD *", "offset": 0, "size": 8},
            {"name": "engine", "c_type": "ENGINE *", "offset": 8, "size": 8},
            {"name": "flags", "c_type": "unsigned long", "offset": 16, "size": 8},
            {"name": "md_data", "c_type": "void *", "offset": 24, "size": 8},
        ],
        "canonical_type": "crate::evp::digest::EvpMdCtx",
        "canonical_authority_id": "openssl-3.6.4-production",
        "canonical_public_layout_epoch": "opaque_post_1_1_0",
        "adapter": "compat::adapters::evp_md_ctx_from_pre_1_1_0",
        "layout_check": "compat::layout_generated::FacadeEvpMdCtx",
        "not_established": [],
        "evidence": ["forensics/authorities/SOURCE_MANIFEST.0.9.8zh.json#crypto/evp/evp.h"],
    },
    "semantic_observation": {
        "observation_id": "SO-presence-SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "vocabulary": "presence.SSL_VALUE_QUIC_MAX_PENDING_CONNS",
        "dimension": "source_api",
        "authority_a": "openssl-3.6.3-historical",
        "authority_b": "openssl-3.6.4-production",
        "observed_a": "<absent>",
        "observed_b": "16",
        "agreement": False,
        "classification": "declaration_added",
        "release_delta": {"dimension": "api_presence",
                           "entity_id": "macro:SSL_VALUE_QUIC_MAX_PENDING_CONNS"},
        "evidence": ["forensics/multitrack/semantic-courts.json#raw_transcripts"],
    },
    "downstream_epoch": {
        "trial_id": "pre-1.0--curl-7.46.0",
        "epoch": "pre-1.0",
        "role": "primary",
        "consumer": "curl",
        "consumer_version": "7.46.0",
        "source": {"url": "https://curl.se/download/curl-7.46.0.tar.gz", "sha256": _DIGEST,
                   "artifact": "curl-7.46.0.tar.gz"},
        "authority_id": "openssl-0.9.8zh-historical",
        "release_id": "openssl-0.9.8zh",
        "authority": {"authority_id": "openssl-0.9.8zh-historical",
                      "release_id": "openssl-0.9.8zh",
                      "build_profile": "linux-x86_64-historical-shared",
                      "platform": "linux", "arch": "x86_64", "venue": "openssl-rs-historical"},
        "outcome": "passed",
        "build": {"ok": True, "configure_argv": ["./configure", "--with-ssl=..."],
                  "configure_exit": 0, "make_exit": 0,
                  "linked": ["libssl.so.0.9.8", "libcrypto.so.0.9.8"],
                  "version_line": "curl 7.46.0 (x86_64-pc-linux-gnu) libcurl/7.46.0 "
                                  "OpenSSL/0.9.8zh"},
        "run": {"ok": True, "http_code": 200, "tls": "TLSv1.2", "exit_code": 0,
                "server": "authority bin/openssl s_server",
                "command": "curl -skv -m 15 -o /dev/null https://127.0.0.1:PORT/"},
        "observation": "curl 7.46.0 linked the OpenSSL 0.9.8zh authority and completed a "
                       "TLSv1.2 HTTPS GET (HTTP 200).",
        "reason": "built unmodified against the authority's headers and libraries and run",
        "evidence": ["forensics/multitrack/downstream-multitrack.json#records/"
                     "pre-1.0--curl-7.46.0/raw"],
    },
}


def _bad(kind: str) -> dict:
    """A documented-bad record for each kind: the mutation and why it must be refused."""
    rec = copy.deepcopy(_GOOD[kind])
    if kind == "release_node":
        rec["version_scheme"] = SCHEME_3_0_PLUS  # contradicts the pre-3.0 display_version
    elif kind == "authority_node":
        rec["binary_hashes"] = {}  # an authority with no binary hashes binds nothing
    elif kind == "lineage_edge":
        rec["kind"] = "compatible"  # not a lineage edge kind
    elif kind == "entity_lineage":
        rec["relation"] = "renamed_to"
        rec.pop("successor", None)  # a rename with no successor
    elif kind == "delta_receipt":
        rec["added"] = "SSL_VALUE_QUIC_MAX_PENDING_CONNS"  # a set, not a list
    elif kind == "compatibility_view":
        rec = {"view_id": "V", "subject_id": "s", "reference_id": "r",
               "compatible": True}  # the forbidden boolean
    elif kind == "compatibility_edge":
        rec["evidence_kind"] = "version_order"  # ordering is not compatibility
    elif kind == "negative_obligation":
        rec["kind"] = "must_be_fast"  # not one of the obligation kinds
    elif kind == "security_observation":
        rec["reintroduced"] = True  # a reintroduced vulnerability
    elif kind == "support_status":
        rec["rungs_attained"] = ["catalogued", "built-authority"]  # a skipped rung
    elif kind == "population_record":
        # an unavailable node recorded runtime-compatible is the exact over-claim the brief
        # refuses: the ladder rung it did not reach would be read as a runtime claim
        rec["status"] = "archaeological-only"
        rec["rungs_attained"] = []
        rec["runtime_compatible"] = True
    elif kind == "compatibility_matrix":
        rec["rows"] = [{"dimension": "source_api"}]  # a cell with no direction
    elif kind == "parameterization_receipt":
        # an absence with no evidence is an omission dressed as a measurement
        rec["censuses"]["openssl-0.9.8zh-historical"]["planes"][0]["evidence"] = {}
    elif kind == "abi_facade":
        # a public layout whose fields overlap is not a layout any compiler produces
        rec["fields"][1]["offset"] = 0
    elif kind == "semantic_observation":
        # a divergent reading classified as agreement would let a difference be read as sameness
        rec["classification"] = "agreed"
    elif kind == "downstream_epoch":
        # a pass claimed with no built artifact is exactly the false pass brief section 40 refuses:
        # the consumer was never built against the authority, so `passed` is a claim, not evidence
        rec["build"]["ok"] = False
    else:
        raise AssertionError(f"no bad case for {kind}")
    return rec


def self_test() -> int:
    """Prove the parser, the order model and every validator accept good and reject bad records."""
    failures: list[str] = []

    # --- the parser and the order model -------------------------------------------------
    document_good = {
        "0.9.8": SCHEME_PRE_3_0,
        "0.9.8zh": SCHEME_PRE_3_0,
        "1.0.0": SCHEME_PRE_3_0,
        "1.0.2u": SCHEME_PRE_3_0,
        "1.1.0": SCHEME_PRE_3_0,
        "1.1.1w": SCHEME_PRE_3_0,
        "3.0.0": SCHEME_3_0_PLUS,
        "3.6.5": SCHEME_3_0_PLUS,
        "4.0.3": SCHEME_3_0_PLUS,
    }
    for text, scheme in document_good.items():
        try:
            got = parse_version(text).scheme
        except VersionError as exc:
            failures.append(f"parse_version({text!r}) raised {exc}")
            continue
        if got != scheme:
            failures.append(f"parse_version({text!r}) scheme {got!r}, expected {scheme!r}")

    order = ["0.9.8", "0.9.8zh", "1.0.0", "1.0.2u", "1.1.0", "1.1.1w", "3.0.0", "3.6.5", "4.0.3"]
    if sorted_releases(list(reversed(order))) != order:
        failures.append(f"sorted_releases did not produce the documented order {order}")
    for earlier, later in zip(order, order[1:]):
        if chronological_order(earlier, later) != -1:
            failures.append(f"chronological_order({earlier!r}, {later!r}) is not -1")
    if chronological_order("0.9.8zh", "0.9.8") != 1:
        failures.append("a letter release must sort after its base release")

    # The encoded numbers, for the forms whose values are documented upstream.
    for text, expected in (("0.9.8", 0x0090800f), ("0.9.8zh", 0x0090822f),
                           ("1.0.0", 0x1000000f), ("1.0.2u", 0x1000215f),
                           ("1.1.0", 0x1010000f), ("1.1.1w", 0x1010117f),
                           ("3.0.0", 0x30000000), ("3.6.5", 0x30600050),
                           ("4.0.3", 0x40000030)):
        try:
            got = openssl_version_number(text)
        except VersionError as exc:
            failures.append(f"openssl_version_number({text!r}) raised {exc}")
            continue
        if got != expected:
            failures.append(
                f"openssl_version_number({text!r}) = 0x{got:08x}, expected 0x{expected:08x}")

    # A version order is not a compatibility claim: the edge validator must refuse it.
    if not validate_compatibility_edge(_bad("compatibility_edge")):
        failures.append("validate_compatibility_edge accepted a `version_order` evidence kind")
    if "numeric ordering" not in " ".join(validate_compatibility_edge(_bad("compatibility_edge"))):
        failures.append("the version_order refusal does not say why ordering is not compatibility")

    # A view is a claim on a dimension, not a boolean and not an ordering: the view validator must
    # refuse both the bare `compatible` flag and a `version_order` evidence kind.
    boolean_view = dict(_GOOD["compatibility_view"], compatible=True)
    if not validate_compatibility_view(boolean_view):
        failures.append("validate_compatibility_view accepted a bare `compatible` boolean")
    ordering_view = dict(_GOOD["compatibility_view"], evidence_kind="version_order")
    if not validate_compatibility_view(ordering_view):
        failures.append("validate_compatibility_view accepted a `version_order` evidence kind")
    if "numeric ordering" not in " ".join(validate_compatibility_view(ordering_view)):
        failures.append("the view's version_order refusal does not say why ordering is not "
                        "compatibility")

    # A population row is never runtime-compatible without runtime evidence: the validator must
    # refuse the over-claim that would count an unavailable release as runtime-compatible.
    overclaim = dict(_GOOD["population_record"], runtime_compatible=True)
    if not validate_population_record(overclaim):
        failures.append("validate_population_record accepted runtime_compatible with no "
                        "runtime-evidenced rung")
    if "runtime-compatible" not in " ".join(validate_population_record(overclaim)):
        failures.append("the population runtime-compatible refusal does not say why")

    # The ladder's core is a prefix, but its additive rungs are independent evidence planes (23.10):
    # the validator must accept the documented independent-rung form and refuse a skipped core rung.
    independent = {
        "subject_id": "openssl-0.9.8zh",
        "status": "downstream-evidenced",
        "rungs_attained": ["catalogued", "admitted-source", "built-authority", "atlas-complete",
                           "downstream-evidenced"],
        "evidence": ["forensics/multitrack/downstream-multitrack.json"],
    }
    if validate_support_status(independent):
        failures.append("validate_support_status refused the documented independent-rung form: "
                        f"{validate_support_status(independent)}")
    core_skip = dict(_GOOD["support_status"], rungs_attained=["catalogued", "built-authority"])
    if not validate_support_status(core_skip):
        failures.append("validate_support_status accepted a node that skipped the core rung "
                        "`admitted-source`")
    if "skip" not in " ".join(validate_support_status(core_skip)):
        failures.append("the support-status core-skip refusal does not say a rung was skipped")

    # A security observation never re-adopts a fixed behaviour: the validator must refuse both a
    # `reintroduced` true and a `preserve_vulnerable_behaviour` disposition (23.14).
    reintroduced = dict(_GOOD["security_observation"], reintroduced=True)
    if not validate_security_observation(reintroduced):
        failures.append("validate_security_observation accepted reintroduced=true")
    preserving = dict(_GOOD["security_observation"],
                      candidate_disposition="preserve_vulnerable_behaviour")
    if not validate_security_observation(preserving):
        failures.append("validate_security_observation accepted a preserve_vulnerable_behaviour "
                        "disposition, which re-adopts a fixed behaviour")
    if "never re-adopt" not in " ".join(validate_security_observation(preserving)):
        failures.append("the preserve refusal does not say why a view may not re-adopt the "
                        "behaviour a fixed release moved away from")

    # A declared ABI edge is a declaration, and every lineage edge carries provenance.
    unmarked = dict(_GOOD["lineage_edge"], kind="declared_abi_compatibility", dimension="abi")
    if not validate_lineage_edge(unmarked):
        failures.append("validate_lineage_edge accepted a declared_abi_compatibility edge with no "
                        "`declared` marker")
    unprovenanced = dict(_GOOD["lineage_edge"], metadata_provenance=[])
    if not validate_lineage_edge(unprovenanced):
        failures.append("validate_lineage_edge accepted a lineage edge with no provenance")

    # The ABI/history façade kinds: every kind accepts a documented-good record, and the two
    # load-bearing refusals (a prototype that claims no era difference, and a façade with no
    # adapter) are each caught.
    prototype_good = {
        "facade_id": "P-HMAC_Init_ex", "facade_kind": "prototype",
        "authority_id": "openssl-0.9.8zh-historical", "release_id": "openssl-0.9.8zh",
        "epoch": "0.9.8zh", "symbol": "HMAC_Init_ex", "authority_specific": True,
        "adapter": "compat::prototypes::hmac_init_ex",
        "eras": [
            {"era": "0.9.8zh", "authority_id": "openssl-0.9.8zh-historical",
             "declaration": "void (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
             "kind": "function", "header": "hmac.h"},
            {"era": "3.6.4", "authority_id": "openssl-3.6.4-production",
             "declaration": "int (HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *)",
             "kind": "function", "header": "hmac.h"},
        ],
        "evidence": ["forensics/multitrack/abi-facades.json"], "not_established": [],
    }
    for kind, extra in (
        ("architecture", {"engine_model": "engine", "provider_model": "no_provider"}),
        ("init_thread", {"init_model": "explicit_global_init",
                         "thread_model": "application_locking_callbacks", "callbacks": []}),
    ):
        rec = dict(prototype_good, facade_id=f"X-{kind}", facade_kind=kind, **extra)
        problems_here = validate_abi_facade(rec)
        if problems_here:
            failures.append(f"abi_facade ({kind}): a documented-good record was refused: "
                            f"{problems_here}")
    if validate_abi_facade(prototype_good):
        failures.append(f"abi_facade (prototype): a documented-good record was refused: "
                        f"{validate_abi_facade(prototype_good)}")
    no_difference = dict(prototype_good, authority_specific=False)
    if not validate_abi_facade(no_difference):
        failures.append("validate_abi_facade accepted a prototype claiming no era difference")
    no_adapter = {k: v for k, v in _GOOD["abi_facade"].items() if k != "adapter"}
    if not validate_abi_facade(no_adapter):
        failures.append("validate_abi_facade accepted a façade with no canonical adapter")

    # A downstream pass is the built artifact and the run, not the claim: the validator must refuse
    # a `passed` consumer with no build and a `not_run` consumer with no reason.
    no_build = copy.deepcopy(_GOOD["downstream_epoch"])
    no_build["build"]["ok"] = False
    if not validate_downstream_epoch(no_build):
        failures.append("validate_downstream_epoch accepted a passed consumer with build.ok false")
    no_reason = copy.deepcopy(_GOOD["downstream_epoch"])
    no_reason["outcome"] = "not_run"
    no_reason["reason"] = ""
    no_reason["build"]["ok"] = False
    no_reason["run"]["ok"] = False
    if not validate_downstream_epoch(no_reason):
        failures.append("validate_downstream_epoch accepted a not_run consumer with no reason")

    # --- every validator, both directions -----------------------------------------------
    for kind in sorted(SCHEMAS):
        good = validate(kind, _GOOD[kind])
        if good:
            failures.append(f"{kind}: a documented-good record was refused: {good}")
        bad = validate(kind, _bad(kind))
        if not bad:
            failures.append(f"{kind}: a documented-bad record was accepted")

    if failures:
        print("[multitrack-schemas] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"[multitrack-schemas] self-test ok: {len(SCHEMAS)} record kind(s) accept the "
          f"documented-good record and refuse the documented-bad one; "
          f"{len(document_good)} version form(s) parse and the documented order holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true",
                    help="prove the parser and every validator accept good and refuse bad records")
    ap.add_argument("--list", action="store_true", help="print the schema inventory")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    inv = inventory()
    if args.list:
        for kind in sorted(inv):
            print(f"{kind}: {', '.join(inv[kind]['fields'])}")
        return 0

    print(f"[multitrack-schemas] {len(inv)} record kind(s): {', '.join(sorted(inv))}")
    print("  run --self-test to prove each accepts a documented-good record and refuses a "
          "documented-bad one")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
