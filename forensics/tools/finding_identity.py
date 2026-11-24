#!/usr/bin/env python3
"""finding_identity.py -- the single finding-identity model.

Every consumer that names a finding, an artefact binding or a candidate identity
uses this module, so there is one definition of each identity rather than one per
tool. The model is described normatively in `docs/FINDING-IDENTITY.md`; this
docstring states the contract the code enforces.

Three identities
----------------
1. **Rule identity** -- the class of finding. Occurrence-independent:
   `ruleFingerprint = SHA-256("a1-rule/v1" NUL ruleId)`.
2. **Logical finding identity** -- the same underlying finding across runs,
   candidates and code motion. It is computed by this module from a *logical key*
   whose construction is registered per key class, and every registered class
   declares the native fields it uses and the location fields it excludes:
   `logicalFingerprint = SHA-256("a1-logical/v1" NUL ruleId NUL logicalKey)`.
3. **Exact occurrence identity** -- this location, in this artefact, at this
   digest, for this candidate:
   `exactFingerprint = SHA-256("a1-exact/v1" NUL ruleId NUL logicalKey NUL
   subjectUri NUL digestScope ":" digest NUL regionKey)`.

The wire format is `a1/v1`. The labels `a1Rule/v1`, `a1Logical/v1` and
`a1Exact/v1` are the recorded labels of that single model, not a SARIF-specific
scheme: they were fixed by the SARIF profile before the model was extracted, and
changing them would invalidate every recorded fingerprint. The model identifier is
reported alongside every value it produces.

What is preserved and what is not
---------------------------------
A logical identity is preserved across an edit only when every field of its key is
unchanged; that is derived by recomputing the key, never asserted. An exact
identity is preserved only when the rule, key, subject binding, scope, digest and
region are all equal. When preservation cannot be derived, a new identity is
correct and reusing the old one is a defect. `classify_motion` reports the
relationship; `require_preservation` refuses an unjustified preservation claim.

Collisions
----------
Two members that share a fingerprint are a **set**. `collision_groups` returns
every member, `collision_report` counts and lists them, and no function in this
module merges, deduplicates or drops a member. `attribute` resolves a fingerprint
to a single member only when exactly one member matches; otherwise it refuses,
because attributing a conclusion to an ambiguous identity would support the
conclusion with the wrong finding. A collision is a refusal condition when a
caller asks for attribution without a discriminator, never a silent merge.

Reuse prohibitions
------------------
`relate` requires a stated relationship from a closed set and refuses:
an exact identity reused across artefacts or across candidates; a logical
identity presented as an exact occurrence; a fingerprint applied to an identity it
does not name; and any relation with no stated relationship. A logical match
permits a logical conclusion only -- `Permit.authorises_exact_reuse` is false and
`authorise_scope` refuses an exact-scoped use of it.

Conservative by construction
----------------------------
* A key class may not use a location field; the registry declares the exclusions
  and a test asserts no registered key depends on a line, column, offset or
  address.
* A binding must carry the algorithm its scope requires (`artifact`,
  `source-tree` and `record` are SHA-256; `candidate-commit` is a Git object id),
  so a commit id is never read as file bytes.
* An identity that cannot be derived from recorded native fields is refused; this
  module does not invent a field to make an identity convenient.

What this module does not do
----------------------------
It does not decide whether a finding is true, current, reachable or severe; it
establishes identity, not state (Article 1). It does not add location precision:
the region records only what the native data states, and macro expansion,
monomorphisation, C-ABI and optimised-code location semantics are A4's subject. It
does not read Git and does not re-derive cited bytes; the claim algebra and the
freshness engine do that and use this module for the identity vocabulary.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

MODEL_ID = "a1/v1"

# Recorded labels of the single model. Changing any of them invalidates every
# recorded fingerprint; a new model version needs a migration (Article 10).
WIRE_KEYS = {
    "rule": "a1Rule/v1",
    "logical": "a1Logical/v1",
    "exact": "a1Exact/v1",
}
_RULE_DOMAIN = "a1-rule/v1"
_LOGICAL_DOMAIN = "a1-logical/v1"
_EXACT_DOMAIN = "a1-exact/v1"

ALGORITHM_SHA256 = "sha-256"
ALGORITHM_GIT_OBJECT = "sha1-git-object"
ALGORITHM_ABBREVIATED = "abbreviated-commit"

DIGEST_SCOPES = ("artifact", "source-tree", "candidate-commit", "record")
SCOPE_ALGORITHM = {
    "artifact": ALGORITHM_SHA256,
    "source-tree": ALGORITHM_SHA256,
    "candidate-commit": ALGORITHM_GIT_OBJECT,
    "record": ALGORITHM_SHA256,
}

# Refusal codes. Each names a condition, not a tool.
FI_REFUSED_DIGEST_FORM = "FI_REFUSED_DIGEST_FORM"
FI_REFUSED_UNKNOWN_SCOPE = "FI_REFUSED_UNKNOWN_SCOPE"
FI_REFUSED_SCOPE_ALGORITHM = "FI_REFUSED_SCOPE_ALGORITHM"
FI_REFUSED_UNKNOWN_KEY_CLASS = "FI_REFUSED_UNKNOWN_KEY_CLASS"
FI_REFUSED_KEY_FIELD = "FI_REFUSED_KEY_FIELD"
FI_REFUSED_UNKNOWN_IDENTITY = "FI_REFUSED_UNKNOWN_IDENTITY"
FI_REFUSED_AMBIGUOUS_ATTRIBUTION = "FI_REFUSED_AMBIGUOUS_ATTRIBUTION"
FI_REFUSED_CROSS_ARTEFACT_REUSE = "FI_REFUSED_CROSS_ARTEFACT_REUSE"
FI_REFUSED_CROSS_CANDIDATE_REUSE = "FI_REFUSED_CROSS_CANDIDATE_REUSE"
FI_REFUSED_NOT_SAME_OCCURRENCE = "FI_REFUSED_NOT_SAME_OCCURRENCE"
FI_REFUSED_NOT_SAME_LOGICAL_FINDING = "FI_REFUSED_NOT_SAME_LOGICAL_FINDING"
FI_REFUSED_NOT_CODE_MOTION = "FI_REFUSED_NOT_CODE_MOTION"
FI_REFUSED_UNSTATED_RELATIONSHIP = "FI_REFUSED_UNSTATED_RELATIONSHIP"
FI_REFUSED_INSUFFICIENT_RELATIONSHIP = "FI_REFUSED_INSUFFICIENT_RELATIONSHIP"
FI_REFUSED_UNJUSTIFIED_PRESERVATION = "FI_REFUSED_UNJUSTIFIED_PRESERVATION"
FI_REFUSED_RECORDED_FINGERPRINT_MISMATCH = (
    "FI_REFUSED_RECORDED_FINGERPRINT_MISMATCH"
)


class IdentityRefusal(Exception):
    """A refusal to produce or consume an identity. Carries a stable code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Digests, canonical JSON and identity tokens
# --------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """Canonical JSON used for every digest input and every candidate token."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(Path(path).read_bytes())


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_HEX = re.compile(r"^[0-9a-f]{40}$")
_ABBREVIATED_HEX = re.compile(r"^[0-9a-f]{7,39}$")


def identity_token_kind(value: Any) -> str | None:
    """Classify a recorded identity token by its form.

    A 64-hex value is SHA-256 over bytes. A 40-hex value is a Git object id,
    which this project computes as SHA-1 over the object header and bytes; it is
    named `sha1-git-object` so a commit id is not mistaken for the content digest
    of a file. A 7..39-hex value is an abbreviated commit id and is an identity
    only when the full object is resolvable. Anything else is not an identity
    token. Case is not normalised: the recorded convention is lower-case, and a
    value outside it is not silently accepted.
    """
    if not isinstance(value, str):
        return None
    token = value.strip()
    if _SHA256_HEX.match(token):
        return ALGORITHM_SHA256
    if _GIT_OBJECT_HEX.match(token):
        return ALGORITHM_GIT_OBJECT
    if _ABBREVIATED_HEX.match(token):
        return ALGORITHM_ABBREVIATED
    return None


def digest_algorithm(value: Any) -> str:
    """The algorithm of a full-length digest, named rather than assumed."""
    kind = identity_token_kind(value)
    if kind in (ALGORITHM_SHA256, ALGORITHM_GIT_OBJECT):
        return kind
    raise IdentityRefusal(
        FI_REFUSED_DIGEST_FORM,
        f"{value!r} is not a full-length sha-256 or Git object identifier",
    )


def is_git_identity_token(value: Any) -> bool:
    """True for a full or abbreviated Git object id, false for content bytes.

    A 64-hex value is SHA-256 over content and is not a commit identity. This is
    the rule the freshness engine uses when it reads an artefact's own identity
    from a structured field: a content digest there is a different kind of value
    and must not be read as a commit.
    """
    return identity_token_kind(value) in (ALGORITHM_GIT_OBJECT, ALGORITHM_ABBREVIATED)


def normalise_text(text: Any) -> str:
    """Whitespace-normalise recorded prose for a prose-keyed logical key."""
    return " ".join(str(text).split())


# --------------------------------------------------------------------------
# Logical keys: one registered construction per class
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyClass:
    """What a logical key is built from, and what it must never include."""

    name: str
    fields: tuple[str, ...]
    excludes: tuple[str, ...]
    location_independent: bool
    prose_keyed: bool
    note: str


KEY_CLASSES: dict[str, KeyClass] = {
    "register-entry": KeyClass(
        "register-entry",
        ("id",),
        ("path", "line", "column", "byteOffset", "address"),
        True,
        False,
        "the native register entry id; the entry may be reported against any path",
    ),
    "primitive-name": KeyClass(
        "primitive-name",
        ("name",),
        ("dso", "byteOffset", "address", "line"),
        True,
        False,
        "the native timing primitive name; the function offset is not identity",
    ),
    "normalised-text": KeyClass(
        "normalised-text",
        ("text",),
        ("ordinal",),
        True,
        True,
        "the native not-run item text, whitespace-normalised; a rewording is a "
        "different logical finding",
    ),
    "path-symbol-status": KeyClass(
        "path-symbol-status",
        ("path", "symbol", "status"),
        ("line", "column", "byteOffset", "address"),
        False,
        False,
        "an unsafe obligation site; moving the function to another file changes "
        "the key, which is why that motion yields a new identity",
    ),
    "path-symbol-class": KeyClass(
        "path-symbol-class",
        ("path", "symbol", "class"),
        ("line", "column", "byteOffset", "address"),
        False,
        False,
        "a contract-absent site; same path dependence as path-symbol-status",
    ),
    "literal": KeyClass(
        "literal",
        ("value",),
        ("count", "members", "line"),
        True,
        False,
        "a record-level condition that occurs once per record",
    ),
    "stable-id": KeyClass(
        "stable-id",
        ("id",),
        ("line", "ordinal", "callSite"),
        True,
        False,
        "the native record's own stable identifier",
    ),
    "obligation-boundary-receipt": KeyClass(
        "obligation-boundary-receipt",
        ("obligation", "boundary", "receipt"),
        ("ordinal", "line"),
        True,
        False,
        "a disposition conflict identified by its obligation, boundary and receipt",
    ),
    "dso-class-reason": KeyClass(
        "dso-class-reason",
        ("dso", "class", "reason"),
        ("function", "callSite", "byteOffset", "address"),
        True,
        False,
        "an unresolved indirect site; the addresses move with the build and are "
        "deliberately excluded",
    ),
    "field-path": KeyClass(
        "field-path",
        ("json_path",),
        ("count", "sample", "line"),
        True,
        False,
        "a record-level condition named by its native JSON field path; the key is "
        "a locator inside a record, not a source path",
    ),
    "refutation": KeyClass(
        "refutation",
        ("text", "digest_chars"),
        ("ordinal",),
        True,
        True,
        "a recorded refutation, keyed by a digest of its whitespace-normalised "
        "text; the a1/v1 scheme records 16 hex characters, so a collision is "
        "64-bit rather than 256-bit and collision detection is load-bearing",
    ),
    "mechanism": KeyClass(
        "mechanism",
        ("name",),
        ("count", "obligations", "ordinal"),
        True,
        False,
        "an adjudication mechanism name",
    ),
    "obligation-decision": KeyClass(
        "obligation-decision",
        ("obligation", "decision"),
        ("ledgerPointer", "line"),
        True,
        False,
        "a reconciliation row; its ledger pointer is positional and excluded",
    ),
}


def _require_field(fields: Mapping[str, Any], name: str, key_class: str) -> Any:
    if name not in fields or fields[name] is None:
        raise IdentityRefusal(
            FI_REFUSED_KEY_FIELD,
            f"key class {key_class!r} requires field {name!r}",
        )
    return fields[name]


def _join(parts: Iterable[Any]) -> str:
    return "::".join(str(part) for part in parts)


def _build_register_entry(fields: Mapping[str, Any]) -> str:
    return str(_require_field(fields, "id", "register-entry"))


def _build_primitive_name(fields: Mapping[str, Any]) -> str:
    return str(_require_field(fields, "name", "primitive-name"))


def _build_normalised_text(fields: Mapping[str, Any]) -> str:
    return normalise_text(_require_field(fields, "text", "normalised-text"))


def _build_path_symbol_status(fields: Mapping[str, Any]) -> str:
    return _join(
        (
            _require_field(fields, "path", "path-symbol-status"),
            _require_field(fields, "symbol", "path-symbol-status"),
            _require_field(fields, "status", "path-symbol-status"),
        )
    )


def _build_path_symbol_class(fields: Mapping[str, Any]) -> str:
    return _join(
        (
            _require_field(fields, "path", "path-symbol-class"),
            _require_field(fields, "symbol", "path-symbol-class"),
            _require_field(fields, "class", "path-symbol-class"),
        )
    )


def _build_literal(fields: Mapping[str, Any]) -> str:
    return str(_require_field(fields, "value", "literal"))


def _build_stable_id(fields: Mapping[str, Any]) -> str:
    return str(_require_field(fields, "id", "stable-id"))


def _build_obligation_boundary_receipt(fields: Mapping[str, Any]) -> str:
    return _join(
        (
            _require_field(fields, "obligation", "obligation-boundary-receipt"),
            _require_field(fields, "boundary", "obligation-boundary-receipt"),
            _require_field(fields, "receipt", "obligation-boundary-receipt"),
        )
    )


def _build_dso_class_reason(fields: Mapping[str, Any]) -> str:
    return _join(
        (
            _require_field(fields, "dso", "dso-class-reason"),
            _require_field(fields, "class", "dso-class-reason"),
            _require_field(fields, "reason", "dso-class-reason"),
        )
    )


def _build_field_path(fields: Mapping[str, Any]) -> str:
    return str(_require_field(fields, "json_path", "field-path"))


def _build_refutation(fields: Mapping[str, Any]) -> str:
    text = normalise_text(_require_field(fields, "text", "refutation"))
    chars = _require_field(fields, "digest_chars", "refutation")
    if not isinstance(chars, int) or chars < 8 or chars > 64:
        raise IdentityRefusal(
            FI_REFUSED_KEY_FIELD,
            f"refutation digest_chars must be an integer in 8..64, got {chars!r}",
        )
    return "refutation::" + digest_bytes(text.encode("utf-8"))[:chars]


def _build_mechanism(fields: Mapping[str, Any]) -> str:
    return "mechanism::" + str(_require_field(fields, "name", "mechanism"))


def _build_obligation_decision(fields: Mapping[str, Any]) -> str:
    return _join(
        (
            _require_field(fields, "obligation", "obligation-decision"),
            _require_field(fields, "decision", "obligation-decision"),
        )
    )


_BUILDERS: dict[str, Callable[[Mapping[str, Any]], str]] = {
    "register-entry": _build_register_entry,
    "primitive-name": _build_primitive_name,
    "normalised-text": _build_normalised_text,
    "path-symbol-status": _build_path_symbol_status,
    "path-symbol-class": _build_path_symbol_class,
    "literal": _build_literal,
    "stable-id": _build_stable_id,
    "obligation-boundary-receipt": _build_obligation_boundary_receipt,
    "dso-class-reason": _build_dso_class_reason,
    "field-path": _build_field_path,
    "refutation": _build_refutation,
    "mechanism": _build_mechanism,
    "obligation-decision": _build_obligation_decision,
}


def logical_key(key_class: str, **fields: Any) -> str:
    """Build a logical key from native fields under a registered class."""
    spec = KEY_CLASSES.get(key_class)
    if spec is None:
        raise IdentityRefusal(
            FI_REFUSED_UNKNOWN_KEY_CLASS,
            f"{key_class!r} is not a registered logical key class",
        )
    return _BUILDERS[key_class](fields)


# --------------------------------------------------------------------------
# Bindings, regions and findings
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Binding:
    """The artefact a finding is about, and the digest that names its bytes."""

    uri: str
    digest: str
    digest_scope: str
    algorithm: str = field(init=False, default="")

    def __post_init__(self) -> None:
        if not isinstance(self.uri, str) or not self.uri:
            raise IdentityRefusal(FI_REFUSED_UNKNOWN_SCOPE, "binding has no uri")
        if self.digest_scope not in DIGEST_SCOPES:
            raise IdentityRefusal(
                FI_REFUSED_UNKNOWN_SCOPE,
                f"digest scope {self.digest_scope!r} is not one of {DIGEST_SCOPES}",
            )
        expected = SCOPE_ALGORITHM[self.digest_scope]
        observed = identity_token_kind(self.digest)
        if observed != expected:
            raise IdentityRefusal(
                FI_REFUSED_SCOPE_ALGORITHM,
                f"scope {self.digest_scope!r} requires {expected}, but "
                f"{self.digest!r} is {observed or 'not a digest'}",
            )
        object.__setattr__(self, "algorithm", expected)

    def as_dict(self) -> dict:
        return {
            "uri": self.uri,
            "digestScope": self.digest_scope,
            "algorithm": self.algorithm,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class Region:
    """The location the native data records, and nothing more precise."""

    kind: str
    line: int | None = None
    byte_offset: int | None = None
    address: int | None = None
    locator: str | None = None

    def __post_init__(self) -> None:
        if self.kind == "source":
            if not isinstance(self.line, int):
                raise IdentityRefusal(
                    FI_REFUSED_KEY_FIELD, "a source region requires an integer line"
                )
        elif self.kind == "binary":
            if not isinstance(self.byte_offset, int) or not isinstance(self.address, int):
                raise IdentityRefusal(
                    FI_REFUSED_KEY_FIELD,
                    "a binary region requires an integer byte offset and address",
                )
        elif self.kind == "record":
            if not isinstance(self.locator, str) or not self.locator:
                raise IdentityRefusal(
                    FI_REFUSED_KEY_FIELD, "a record region requires a JSON locator"
                )
        else:
            raise IdentityRefusal(
                FI_REFUSED_KEY_FIELD, f"unknown region kind {self.kind!r}"
            )

    def key(self) -> str:
        if self.kind == "source":
            return f"line={self.line}"
        if self.kind == "binary":
            return f"byteOffset={self.byte_offset};address={self.address}"
        return f"locator={self.locator}"

    @classmethod
    def from_native(
        cls,
        *,
        path: str | None,
        line: int | None,
        byte_offset: int | None,
        address: int | None,
        locator: str,
    ) -> "Region":
        """The most precise region the native finding records.

        The precedence is fixed: a recorded source line, then a recorded binary
        offset and address, then the record's own JSON locator. A finding with no
        line is not given one.
        """
        if path is not None and line is not None:
            return cls("source", line=int(line))
        if byte_offset is not None:
            return cls("binary", byte_offset=int(byte_offset), address=address)
        return cls("record", locator=str(locator))


def candidate_token(candidate: Any) -> str | None:
    """A canonical token for a candidate identity, compared byte for byte."""
    if candidate is None:
        return None
    if isinstance(candidate, str):
        return candidate
    return canonical_json(candidate)


@dataclass(frozen=True)
class Finding:
    """One finding with the three identities its recorded fields determine."""

    rule_id: str
    logical_key: str
    binding: Binding
    region: Region
    candidate: Any
    key_class: str | None = None
    native_locator: str = ""
    candidate_token: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise IdentityRefusal(FI_REFUSED_KEY_FIELD, "finding has no rule id")
        object.__setattr__(self, "candidate_token", candidate_token(self.candidate))

    @property
    def rule_fingerprint(self) -> str:
        return rule_fingerprint(self.rule_id)

    @property
    def logical_fingerprint(self) -> str:
        return logical_fingerprint(self.rule_id, self.logical_key)

    @property
    def exact_fingerprint(self) -> str:
        return exact_fingerprint(
            self.rule_id, self.logical_key, self.binding, self.region
        )

    @property
    def fingerprints(self) -> dict[str, str]:
        return {
            WIRE_KEYS["rule"]: self.rule_fingerprint,
            WIRE_KEYS["logical"]: self.logical_fingerprint,
            WIRE_KEYS["exact"]: self.exact_fingerprint,
        }

    def same_binding(self, other: "Finding") -> bool:
        return self.binding == other.binding

    def same_candidate(self, other: "Finding") -> bool:
        return self.candidate_token == other.candidate_token

    def as_dict(self) -> dict:
        return {
            "model": MODEL_ID,
            "ruleId": self.rule_id,
            "keyClass": self.key_class,
            "logicalKey": self.logical_key,
            "binding": self.binding.as_dict(),
            "region": self.region.key(),
            "candidateToken": self.candidate_token,
            "nativeLocator": self.native_locator,
            "fingerprints": self.fingerprints,
        }


def _fingerprint(domain: str, *parts: str) -> str:
    payload = "\x00".join((domain,) + tuple(parts))
    return digest_bytes(payload.encode("utf-8"))


def rule_fingerprint(rule_id: str) -> str:
    return _fingerprint(_RULE_DOMAIN, rule_id)


def logical_fingerprint(rule_id: str, key: str) -> str:
    return _fingerprint(_LOGICAL_DOMAIN, rule_id, key)


def exact_fingerprint(
    rule_id: str, key: str, binding: Binding, region: Region
) -> str:
    return _fingerprint(
        _EXACT_DOMAIN,
        rule_id,
        key,
        binding.uri,
        f"{binding.digest_scope}:{binding.digest}",
        region.key(),
    )


def identify(
    *,
    rule_id: str,
    key_class: str,
    binding: Binding,
    region: Region,
    candidate: Any,
    native_locator: str = "",
    **key_fields: Any,
) -> Finding:
    """Build a finding through the registered key class and its identities."""
    key = logical_key(key_class, **key_fields)
    return Finding(
        rule_id=rule_id,
        logical_key=key,
        binding=binding,
        region=region,
        candidate=candidate,
        key_class=key_class,
        native_locator=native_locator,
    )


# --------------------------------------------------------------------------
# Positional identities for records that carry no logical key
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PositionalIdentity:
    """An identity that includes a recorded location, and what that costs.

    Some records (an indirect call site, a production operation, an omitted edge)
    store only positional data: a file and line, a function and call site, or an
    edge and a target. Such a value identifies the recorded position and nothing
    else. It is deliberately marked `portable=False`: it may not be compared, or
    reused, across candidates, because the same position at a different build is
    not the same code.
    """

    kind: str
    text: str
    portable: bool = False
    includes_location: bool = True

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "text": self.text,
            "portable": self.portable,
            "includesLocation": self.includes_location,
        }


def row_identity(path: Any, line: Any, kind: Any) -> PositionalIdentity:
    """`file:line:kind` as recorded by a consumer-closure row."""
    return PositionalIdentity("row", f"{path}:{line}:{kind}")


def site_identity(dso: Any, function: Any, call_site: Any) -> PositionalIdentity:
    """`dso:function:call_site` as recorded for an indirect site."""
    return PositionalIdentity("site", f"{dso}:{function}:{call_site}")


def target_identity(edge: Any, target: Any) -> PositionalIdentity:
    """`edge#target=target` as recorded for a dropped target."""
    return PositionalIdentity("target", f"{edge}#target={target}")


# --------------------------------------------------------------------------
# Code motion
# --------------------------------------------------------------------------

RELATION_UNCHANGED = "unchanged"
RELATION_LOCATION_MOVED = "location-moved"
RELATION_ARTEFACT_BYTES_CHANGED = "artefact-bytes-changed"
RELATION_SUBJECT_CHANGED = "subject-changed"
RELATION_LOGICAL_KEY_CHANGED = "logical-key-changed"
RELATION_DIFFERENT_RULE = "different-rule"

MOTION_CASES = (
    "moved-within-file",
    "moved-to-another-file",
    "renamed",
    "reformatted",
    "insertion-above",
    "deletion-above",
    "file-split",
    "file-merge",
)


@dataclass(frozen=True)
class MotionVerdict:
    """What one edit did to the three identities, and why."""

    relation: str
    logical_preserved: bool
    exact_preserved: bool
    reason: str
    key_class: str | None = None

    def as_dict(self) -> dict:
        return {
            "relation": self.relation,
            "logicalPreserved": self.logical_preserved,
            "exactPreserved": self.exact_preserved,
            "reason": self.reason,
            "keyClass": self.key_class,
        }


def classify_motion(before: Finding, after: Finding) -> MotionVerdict:
    """Classify one edit from the recorded fields alone.

    Preservation is derived: the logical key is compared, then the binding, then
    the region. Nothing is assumed about the edit's intent, and a field change
    that cannot be shown to be immaterial yields a new identity.
    """
    key_class = before.key_class or after.key_class
    if before.rule_id != after.rule_id:
        return MotionVerdict(
            RELATION_DIFFERENT_RULE,
            False,
            False,
            "the rule id changed, so the finding class changed",
            key_class,
        )
    if before.logical_key != after.logical_key:
        spec = KEY_CLASSES.get(before.key_class or after.key_class or "")
        suffix = ""
        if spec is not None:
            if spec.prose_keyed:
                suffix = (
                    f"; the class {spec.name!r} is keyed by prose, so a rewording is "
                    "a new identity"
                )
            elif spec.location_independent:
                suffix = (
                    f"; the class {spec.name!r} is location-independent, so the "
                    "changed field is a native identity field rather than a location"
                )
            else:
                suffix = f"; the class {spec.name!r} uses a field that changed"
        return MotionVerdict(
            RELATION_LOGICAL_KEY_CHANGED,
            False,
            False,
            "a registered logical-key field changed value; no equivalence between "
            "the two keys is recorded, so the logical identity is new" + suffix,
            key_class,
        )
    if before.binding.uri != after.binding.uri:
        return MotionVerdict(
            RELATION_SUBJECT_CHANGED,
            True,
            False,
            "the logical key is unchanged, but the subject artefact changed, so the "
            "exact occurrence is new",
            key_class,
        )
    if before.binding.digest != after.binding.digest:
        return MotionVerdict(
            RELATION_ARTEFACT_BYTES_CHANGED,
            True,
            False,
            "the logical key is unchanged; the artefact bytes changed, so the exact "
            "occurrence at the new digest is new",
            key_class,
        )
    if before.region != after.region:
        return MotionVerdict(
            RELATION_LOCATION_MOVED,
            True,
            False,
            "the logical key is unchanged and the location moved within one artefact "
            "digest, so only the exact occurrence changed",
            key_class,
        )
    return MotionVerdict(
        RELATION_UNCHANGED,
        True,
        True,
        "every field of the rule, key, binding and region is unchanged",
        key_class,
    )


def require_preservation(before: Finding, after: Finding) -> MotionVerdict:
    """Refuse an unjustified claim that the logical identity was preserved."""
    verdict = classify_motion(before, after)
    if not verdict.logical_preserved:
        raise IdentityRefusal(
            FI_REFUSED_UNJUSTIFIED_PRESERVATION,
            f"{verdict.relation}: {verdict.reason}",
        )
    return verdict


# --------------------------------------------------------------------------
# Collisions
# --------------------------------------------------------------------------

COLLISION_POLICY = (
    "a colliding fingerprint is a set: every member is retained, counted and "
    "visible; no member is merged, deduplicated or dropped; attribution requires "
    "exactly one matching member, and a claim may never rest on an ambiguous one"
)


def _fingerprint_of(finding: Finding, kind: str) -> str:
    if kind == "rule":
        return finding.rule_fingerprint
    if kind == "logical":
        return finding.logical_fingerprint
    if kind == "exact":
        return finding.exact_fingerprint
    raise IdentityRefusal(
        FI_REFUSED_UNKNOWN_IDENTITY,
        f"fingerprint kind {kind!r} is not one of ('rule', 'logical', 'exact')",
    )


def collision_groups(
    findings: Iterable[Finding], kind: str = "exact"
) -> dict[str, tuple[Finding, ...]]:
    """Every group of two or more members sharing a fingerprint, in key order."""
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        buckets.setdefault(_fingerprint_of(finding, kind), []).append(finding)
    return {
        fingerprint: tuple(members)
        for fingerprint, members in sorted(buckets.items())
        if len(members) > 1
    }


def collision_report(findings: Iterable[Finding], kind: str = "exact") -> dict:
    """A full, untruncated report of every colliding group."""
    findings = list(findings)
    groups = collision_groups(findings, kind)
    entries = []
    for fingerprint, members in groups.items():
        entries.append(
            {
                "fingerprint": fingerprint,
                "ruleIds": sorted({member.rule_id for member in members}),
                "count": len(members),
                "members": [member.as_dict() for member in members],
            }
        )
    return {
        "model": MODEL_ID,
        "fingerprintKind": kind,
        "population": len(findings),
        "collisionCount": len(entries),
        "collisionMembers": sum(entry["count"] for entry in entries),
        "groups": entries,
        "policy": COLLISION_POLICY,
    }


def attribute(
    findings: Iterable[Finding],
    fingerprint: str,
    kind: str = "exact",
    discriminator: Callable[[Finding], bool] | None = None,
) -> Finding:
    """Resolve a fingerprint to exactly one member, or refuse.

    A discriminator narrows a collision but does not by itself make an
    attribution: the narrowed set must still contain exactly one member. When it
    contains more, or none, the refusal stands, because a conclusion attributed to
    the wrong member is worse than no attribution.
    """
    candidates = [
        finding for finding in findings if _fingerprint_of(finding, kind) == fingerprint
    ]
    if not candidates:
        raise IdentityRefusal(
            FI_REFUSED_UNKNOWN_IDENTITY,
            f"no finding has {kind} fingerprint {fingerprint}",
        )
    if discriminator is not None:
        candidates = [finding for finding in candidates if discriminator(finding)]
        if not candidates:
            raise IdentityRefusal(
                FI_REFUSED_UNKNOWN_IDENTITY,
                f"the discriminator matches no member of {kind} fingerprint "
                f"{fingerprint}",
            )
    if len(candidates) > 1:
        raise IdentityRefusal(
            FI_REFUSED_AMBIGUOUS_ATTRIBUTION,
            f"{kind} fingerprint {fingerprint} is shared by {len(candidates)} "
            f"members ({', '.join(sorted(f.native_locator for f in candidates))}); "
            "a collision is a set and a claim may not be attributed to one member "
            "without a discriminator that leaves exactly one",
        )
    return candidates[0]


# --------------------------------------------------------------------------
# Reuse across artefacts, candidates and time
# --------------------------------------------------------------------------

RELATIONSHIP_SAME_OCCURRENCE = "same-occurrence"
RELATIONSHIP_SAME_LOGICAL_FINDING = "same-logical-finding"
RELATIONSHIP_CODE_MOTION = "code-motion"
RELATIONSHIP_DISTINCT = "distinct"

RELATIONSHIPS = (
    RELATIONSHIP_SAME_OCCURRENCE,
    RELATIONSHIP_SAME_LOGICAL_FINDING,
    RELATIONSHIP_CODE_MOTION,
    RELATIONSHIP_DISTINCT,
)

SCOPE_EXACT = "exact"
SCOPE_LOGICAL = "logical"
SCOPE_NONE = "none"


@dataclass(frozen=True)
class Permit:
    """What a stated relationship authorises, and what it does not."""

    relationship: str
    scope: str
    authorises_exact_reuse: bool
    cross_artefact: bool
    cross_candidate: bool
    detail: str

    def as_dict(self) -> dict:
        return {
            "relationship": self.relationship,
            "scope": self.scope,
            "authorisesExactReuse": self.authorises_exact_reuse,
            "crossArtefact": self.cross_artefact,
            "crossCandidate": self.cross_candidate,
            "detail": self.detail,
        }


def relate(left: Finding, right: Finding, relationship: str) -> Permit:
    """State how two findings relate, refusing an unsupported relation.

    `same-occurrence` is the only relationship that authorises reuse of an
    exact-scoped conclusion (a suppression, discharge, receipt or cache entry). A
    logical match authorises a logical conclusion only.
    """
    if relationship not in RELATIONSHIPS:
        raise IdentityRefusal(
            FI_REFUSED_UNSTATED_RELATIONSHIP,
            f"{relationship!r} is not a stated relationship; a fingerprint is not "
            f"evidence that two findings are the same without one of {RELATIONSHIPS}",
        )
    cross_artefact = not left.same_binding(right)
    cross_candidate = not left.same_candidate(right)
    exact_equal = left.exact_fingerprint == right.exact_fingerprint
    logical_equal = left.logical_fingerprint == right.logical_fingerprint

    if relationship == RELATIONSHIP_DISTINCT:
        return Permit(
            relationship,
            SCOPE_NONE,
            False,
            cross_artefact,
            cross_candidate,
            "no relation is claimed; no identity or conclusion transfers",
        )

    if relationship == RELATIONSHIP_SAME_OCCURRENCE:
        if cross_candidate:
            raise IdentityRefusal(
                FI_REFUSED_CROSS_CANDIDATE_REUSE,
                "an exact occurrence at one candidate may not be reused as the same "
                "occurrence at another candidate",
            )
        if cross_artefact:
            raise IdentityRefusal(
                FI_REFUSED_CROSS_ARTEFACT_REUSE,
                "an exact identity names one artefact binding; reuse across "
                "artefacts is refused",
            )
        if not exact_equal:
            raise IdentityRefusal(
                FI_REFUSED_NOT_SAME_OCCURRENCE,
                "the exact identities differ, so this is not the same occurrence",
            )
        return Permit(
            relationship,
            SCOPE_EXACT,
            True,
            False,
            False,
            "same rule, key, artefact binding, digest and region at the same candidate",
        )

    if relationship == RELATIONSHIP_SAME_LOGICAL_FINDING:
        if not logical_equal:
            raise IdentityRefusal(
                FI_REFUSED_NOT_SAME_LOGICAL_FINDING,
                "the logical identities differ, so this is not the same finding",
            )
        return Permit(
            relationship,
            SCOPE_LOGICAL,
            False,
            cross_artefact,
            cross_candidate,
            "the logical finding is the same; the occurrence, its artefact binding "
            "and its candidacy are not, so only a logical conclusion transfers",
        )

    # code-motion
    if not logical_equal:
        raise IdentityRefusal(
            FI_REFUSED_NOT_CODE_MOTION,
            "a logical identity change is not code motion: the key field that "
            "changed may be a different finding",
        )
    if not (cross_artefact or left.region != right.region):
        raise IdentityRefusal(
            FI_REFUSED_NOT_CODE_MOTION,
            "nothing moved; the finding is the same occurrence and an exact "
            "relationship is available",
        )
    return Permit(
        relationship,
        SCOPE_LOGICAL,
        False,
        cross_artefact,
        cross_candidate,
        "code motion preserves the logical identity and changes the exact one; it "
        "does not transfer an exact-scoped conclusion",
    )


def authorise_scope(permit: Permit, scope: str) -> None:
    """Refuse an exact-scoped use of a permit that established only a logical one."""
    if scope == SCOPE_EXACT and not permit.authorises_exact_reuse:
        raise IdentityRefusal(
            FI_REFUSED_INSUFFICIENT_RELATIONSHIP,
            f"the stated relationship {permit.relationship!r} authorises at most "
            f"{permit.scope} scope; exact-scoped reuse needs same-occurrence",
        )


def authorise_about(permit: Permit, finding: Finding, binding: Binding) -> None:
    """Refuse a conclusion about an artefact the permit's identity does not name.

    Even a logical relationship between two artefacts does not authorise a
    conclusion about one of them. The conclusion must be about the artefact the
    identity names, and a claim about a different artefact needs that
    artefact's own exact identity.
    """
    if permit.scope == SCOPE_NONE:
        raise IdentityRefusal(
            FI_REFUSED_INSUFFICIENT_RELATIONSHIP,
            "no relation is claimed, so no conclusion about an artefact transfers",
        )
    if finding.binding != binding:
        raise IdentityRefusal(
            FI_REFUSED_CROSS_ARTEFACT_REUSE,
            f"a {permit.scope}-scope relationship naming {finding.binding.uri!r} does "
            f"not authorise a conclusion about {binding.uri!r}",
        )


def permits_reuse(
    left: Finding, right: Finding, relationship: str, scope: str = SCOPE_EXACT
) -> bool:
    """True only when the relationship authorises that scope; raises otherwise."""
    permit = relate(left, right, relationship)
    authorise_scope(permit, scope)
    return True
