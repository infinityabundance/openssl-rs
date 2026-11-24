#!/usr/bin/env python3
"""independent_verify.py -- independent envelope verification (A12).

Why this tool exists
--------------------
A signature by the party that produced an envelope is not evidence to a third
party.  A verifier that selects its key from the envelope, or that verifies with
the same secret the signer used, can only report that the bytes are internally
consistent; it cannot report that somebody else vouched for them.  This module
makes the difference mechanical:

  * the trust root is selected by the **policy**, never by the envelope's
    unauthenticated ``keyid``;
  * a symmetric root is refused for an independence claim, because the verifier
    holds the same secret as the signer and could have produced the signature;
  * a trust root whose provenance is inside the candidate tree is refused;
  * an unrecorded root, a digest mismatch, a stale root and two roots claiming
    one keyid are refused;
  * a root in the candidate's or the producer's trust domain is refused;
  * a recorded self-issued basis is refused;
  * the DSSE signature is verified over the received PAE by a caller-supplied
    public verifier (this module implements no new signature primitive);
  * the payload's statement must name the artefact under test at the digest the
    artefact's bytes actually have.

The result is one of ``INDEPENDENTLY_VERIFIED``, ``SELF_ISSUED``,
``UNVERIFIED`` or ``NOT_RUN``.  ``SELF_ISSUED`` is not a pass and is never
counted as one.

What this module does not do
----------------------------
It does not implement a signature primitive, distribute a key, decide a role,
apply a threshold, read a Sigstore bundle or consult a transparency log.  Those
are A13-A17's.  It does not prove that the signer is who a trust root names; it
proves only that the verification decision was made outside the candidate and
the producing party, under a recorded policy.

Usage
-----
    python3 forensics/tools/independent_verify.py roots [--roots PATH]
    python3 forensics/tools/independent_verify.py verify <envelope> <artefact> \
        [--roots PATH]
    python3 forensics/tools/independent_verify.py qualify [--roots PATH]

Exit status: 0 for an independent verification (``verify``) or a successful
inventory command, 1 for a refusal or a non-independent outcome, 2 for a usage
error.  The code and the outcome are always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
from datetime import date
from pathlib import Path
from typing import Any, Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import harden  # noqa: E402
import intoto  # noqa: E402

TOOL_PATH = "forensics/tools/independent_verify.py"
MODEL_ID = "a12/v1"
INVENTORY_SCHEMA = "openssl-rs/a12/trust-roots/1"
VERIFICATION_SCHEMA = "openssl-rs/a12/verification/1"
CONTROLS_SCHEMA = "openssl-rs/a12/controls/1"
DEFAULT_ROOTS = "evidence/a12/TRUST-ROOTS.json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "IV_OK"
CODE_USAGE = "IV_USAGE"

OUTCOME_VERIFIED = "INDEPENDENTLY_VERIFIED"
OUTCOME_SELF_ISSUED = "SELF_ISSUED"
OUTCOME_UNVERIFIED = "UNVERIFIED"
OUTCOME_NOT_RUN = "NOT_RUN"
OUTCOMES = (
    OUTCOME_VERIFIED,
    OUTCOME_SELF_ISSUED,
    OUTCOME_UNVERIFIED,
    OUTCOME_NOT_RUN,
)

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

IV_REFUSED_ENVELOPE = "IV_REFUSED_ENVELOPE"
IV_REFUSED_KEY_FROM_ENVELOPE = "IV_REFUSED_KEY_FROM_ENVELOPE"
IV_REFUSED_SYMMETRIC = "IV_REFUSED_SYMMETRIC"
IV_REFUSED_CANDIDATE_TRUST_ROOT = "IV_REFUSED_CANDIDATE_TRUST_ROOT"
IV_REFUSED_TRUST_ROOT_UNRECORDED = "IV_REFUSED_TRUST_ROOT_UNRECORDED"
IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH = "IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH"
IV_REFUSED_SAME_DOMAIN = "IV_REFUSED_SAME_DOMAIN"
IV_REFUSED_SELF_ISSUED = "IV_REFUSED_SELF_ISSUED"
IV_REFUSED_SIGNATURE = "IV_REFUSED_SIGNATURE"
IV_REFUSED_PAYLOAD_NOT_SUBJECT = "IV_REFUSED_PAYLOAD_NOT_SUBJECT"
IV_REFUSED_SUBJECT_ABSENT = "IV_REFUSED_SUBJECT_ABSENT"
IV_REFUSED_SUBJECT_MISMATCH = "IV_REFUSED_SUBJECT_MISMATCH"
IV_REFUSED_NO_PUBLIC_VERIFIER = "IV_REFUSED_NO_PUBLIC_VERIFIER"
IV_REFUSED_TRUST_ROOT_STALE = "IV_REFUSED_TRUST_ROOT_STALE"
IV_REFUSED_MULTIPLE_ROOTS = "IV_REFUSED_MULTIPLE_ROOTS"

REFUSALS: dict[str, dict[str, str]] = {
    IV_REFUSED_ENVELOPE: {
        "condition": (
            "the received bytes are not a DSSE envelope this verifier can parse, "
            "or the received payloadType is not the in-toto statement type"
        ),
        "prevents": (
            "that a malformed, re-serialised or non-attestation envelope is read as "
            "the envelope that was signed"
        ),
    },
    IV_REFUSED_KEY_FROM_ENVELOPE: {
        "condition": (
            "the policy names no keyid, so the only keyid available is the "
            "envelope's unauthenticated hint"
        ),
        "prevents": (
            "that the envelope chooses its own trust root: a signer cannot nominate "
            "the key that will judge it"
        ),
    },
    IV_REFUSED_SYMMETRIC: {
        "condition": (
            "the selected trust root is symmetric (or records no public material)"
        ),
        "prevents": (
            "that a verifier holding the signer's secret reports independence: it "
            "could have produced the signature itself"
        ),
    },
    IV_REFUSED_CANDIDATE_TRUST_ROOT: {
        "condition": (
            "the selected trust root's provenance record is inside the candidate "
            "tree under test, or the trust-root inventory itself is inside the "
            "evidence being verified"
        ),
        "prevents": (
            "that the candidate supplies the key, the seed or the record that "
            "authorises itself"
        ),
    },
    IV_REFUSED_TRUST_ROOT_UNRECORDED: {
        "condition": (
            "the policy's keyid names no root in the recorded inventory, or the "
            "inventory is absent or malformed"
        ),
        "prevents": (
            "that a key is trusted because it appears in an envelope without a "
            "recorded origin"
        ),
    },
    IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH: {
        "condition": (
            "the provenance record is absent or its bytes do not hash to the "
            "recorded digest"
        ),
        "prevents": (
            "that a changed key record is read as the record that established the "
            "root"
        ),
    },
    IV_REFUSED_SAME_DOMAIN: {
        "condition": (
            "the selected root's trustDomain equals the candidate's or the "
            "producer's, or no trust domain is recorded"
        ),
        "prevents": (
            "that a root inside the producing party is reported as an external "
            "trust domain"
        ),
    },
    IV_REFUSED_SELF_ISSUED: {
        "condition": (
            "the root records a self-issued basis, records no independence basis, "
            "or states a same-party basis"
        ),
        "prevents": (
            "that a self-signed claim is counted as a third-party verification"
        ),
    },
    IV_REFUSED_SIGNATURE: {
        "condition": (
            "no signature attributed to the policy-selected keyid verifies over the "
            "PAE of the received bytes under the caller-supplied public verifier"
        ),
        "prevents": (
            "that a signature by another key, or over different bytes, is accepted "
            "as the selected root's signature"
        ),
    },
    IV_REFUSED_PAYLOAD_NOT_SUBJECT: {
        "condition": (
            "the verified payload is not a canonical in-toto Statement v1, or the "
            "statement's subject digest for the artefact is not the digest of the "
            "artefact's bytes"
        ),
        "prevents": (
            "that an attestation about different bytes is read as an attestation "
            "about the artefact under test"
        ),
    },
    IV_REFUSED_SUBJECT_ABSENT: {
        "condition": "the artefact under test is absent, so its digest cannot be recomputed",
        "prevents": (
            "that a missing artefact is treated as matching an absent digest"
        ),
    },
    IV_REFUSED_SUBJECT_MISMATCH: {
        "condition": (
            "the statement names no subject whose name is the artefact under test"
        ),
        "prevents": (
            "that a statement about one artefact is read as a statement about "
            "another"
        ),
    },
    IV_REFUSED_NO_PUBLIC_VERIFIER: {
        "condition": (
            "the trust root is acceptable but the caller supplied no public verifier"
        ),
        "prevents": (
            "that this module invents a signature primitive, or that an unchecked "
            "signature is reported as verified"
        ),
    },
    IV_REFUSED_TRUST_ROOT_STALE: {
        "condition": (
            "the root's recordedAt is older than the policy's asOf minus "
            "maxRootAgeDays"
        ),
        "prevents": (
            "that an expired root is read as current"
        ),
    },
    IV_REFUSED_MULTIPLE_ROOTS: {
        "condition": "two inventory entries claim the policy's keyid",
        "prevents": (
            "that one keyid resolves to two keys and the reader chooses one"
        ),
    },
}

# Root-level refusals that establish the envelope was issued by the same party.
SAME_PARTY_CODES = frozenset(
    {
        IV_REFUSED_SYMMETRIC,
        IV_REFUSED_CANDIDATE_TRUST_ROOT,
        IV_REFUSED_SAME_DOMAIN,
        IV_REFUSED_SELF_ISSUED,
    }
)
# Root-level refusals that leave independence undecided rather than self-issued.
UNVERIFIED_ROOT_CODES = frozenset(
    {
        IV_REFUSED_TRUST_ROOT_UNRECORDED,
        IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH,
        IV_REFUSED_TRUST_ROOT_STALE,
        IV_REFUSED_MULTIPLE_ROOTS,
    }
)
ROOT_CODES = SAME_PARTY_CODES | UNVERIFIED_ROOT_CODES


class Refusal(Exception):
    """A stable refusal code and the conclusion it prevents."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _fail(code: str, message: str) -> None:
    raise Refusal(code, message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Paths, dates and the inventory.
# ---------------------------------------------------------------------------


def _base(policy: Mapping[str, Any]) -> Path:
    value = policy.get("baseDir")
    return Path(value) if value else REPO_ROOT


def _resolve(path: Path | str, base: Path) -> Path:
    given = Path(path)
    return given if given.is_absolute() else (base / given)


def _within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _normalise_artefact(path: str) -> str:
    return Path(path).as_posix().lstrip("./")


def _parse_date(value: Any, where: str) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        _fail(IV_REFUSED_TRUST_ROOT_STALE, f"{where}: {value!r} is not an ISO date")
    return None


def load_inventory(path: Path | str) -> dict[str, Any]:
    """Read the trust-root inventory from its own tracked record.

    The inventory is deliberately a separate record from the evidence being
    verified.  A missing or malformed record is a refusal, never an empty
    inventory: an empty inventory would silently trust nothing instead of
    reporting that nothing is recorded.
    """
    given = Path(path)
    try:
        raw = given.read_bytes()
    except OSError as error:
        _fail(
            IV_REFUSED_TRUST_ROOT_UNRECORDED,
            f"{given}: the trust-root inventory is absent ({error})",
        )
    try:
        document = harden.loads(raw)
    except harden.Refusal as refusal:
        _fail(
            IV_REFUSED_TRUST_ROOT_UNRECORDED,
            f"{given}: the trust-root inventory is not strict JSON ({refusal.code})",
        )
    if not isinstance(document, dict):
        _fail(
            IV_REFUSED_TRUST_ROOT_UNRECORDED,
            f"{given}: the trust-root inventory is not an object",
        )
    roots = document.get("roots")
    if not isinstance(roots, list):
        _fail(
            IV_REFUSED_TRUST_ROOT_UNRECORDED,
            f"{given}: the trust-root inventory has no roots array",
        )
    return document


def policy_from_inventory(
    document: Mapping[str, Any], path: Path | str | None = None
) -> dict[str, Any]:
    """Build the policy record the verifier consumes from the inventory.

    The keyid, the candidate and producer domains, the candidate root and the
    freshness bound are read from the recorded policy.  None of them is taken
    from the envelope.
    """
    recorded = document.get("policy")
    if not isinstance(recorded, Mapping):
        _fail(IV_REFUSED_TRUST_ROOT_UNRECORDED, "the inventory has no policy object")
    policy = dict(recorded)
    policy["trustRoots"] = document
    if path is not None:
        policy["trustRootsPath"] = str(path)
    policy.setdefault("baseDir", str(REPO_ROOT))
    return policy


def _root_is_symmetric(root: Mapping[str, Any]) -> bool:
    return root.get("symmetric") is True or not root.get("publicMaterial")


def _self_issued_basis(root: Mapping[str, Any]) -> bool:
    if root.get("selfIssued") is True:
        return True
    basis = root.get("independenceBasis")
    if not isinstance(basis, str) or not basis.strip():
        return True
    lowered = " ".join(basis.lower().split())
    markers = (
        "self-issued",
        "self issued",
        "self-signed",
        "self signed",
        "same-party",
        "same party",
        "none:",
        "none -",
    )
    return any(marker in lowered for marker in markers)


def _root_is_external(root: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    if _root_is_symmetric(root) or _self_issued_basis(root):
        return False
    base = _base(policy)
    provenance = root.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    path = provenance.get("path")
    if not isinstance(path, str) or not path:
        return False
    candidate = _resolve(policy.get("candidateRoot", "."), base)
    if _within(_resolve(path, base), candidate):
        return False
    domain = root.get("trustDomain")
    if not isinstance(domain, str) or not domain:
        return False
    return domain not in {
        policy.get("candidateDomain"),
        policy.get("producerDomain"),
    }


def qualify(document: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    """Report what the inventory could independently verify, without verifying.

    A qualification of zero external roots is a successful qualification of an
    inventory that cannot establish independence; it is not a verification and
    it is not a pass.
    """
    roots = document.get("roots")
    if not isinstance(roots, list):
        _fail(IV_REFUSED_TRUST_ROOT_UNRECORDED, "the inventory has no roots array")
    external = [root for root in roots if isinstance(root, Mapping) and _root_is_external(root, policy)]
    symmetric = [root for root in roots if isinstance(root, Mapping) and _root_is_symmetric(root)]
    return {
        "roots": len(roots),
        "externalRoots": len(external),
        "symmetricRoots": len(symmetric),
        "externalKeyids": [root.get("keyid") for root in external],
        "outcome": OUTCOME_NOT_RUN if not external else OUTCOME_VERIFIED,
    }


# ---------------------------------------------------------------------------
# The verifier.
# ---------------------------------------------------------------------------


def _check(
    result: dict[str, Any], number: int, name: str, status: str, code: str | None = None,
    detail: str | None = None,
) -> None:
    row: dict[str, Any] = {"check": number, "name": name, "status": status}
    if code is not None:
        row["code"] = code
    if detail:
        row["detail"] = detail
    result["checks"].append(row)


def _add(result: dict[str, Any], code: str) -> None:
    if code not in result["codes"]:
        result["codes"].append(code)


def _root_selected_by_policy(
    result: dict[str, Any],
    document: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, str | None]:
    """Checks 1-6. Return the selected root and a root-level refusal, if any."""
    base = _base(policy)

    # 1. The policy selects the keyid. The envelope's keyid is a hint only.
    policy_keyid = policy.get("keyid")
    signatures = document.get("signatures")
    envelope_keyids: list[str] = []
    if isinstance(signatures, list):
        for entry in signatures:
            if isinstance(entry, Mapping) and isinstance(entry.get("keyid"), str):
                envelope_keyids.append(entry["keyid"])
    result["keyid"] = {
        "selectedBy": "policy",
        "policyKeyid": policy_keyid,
        "envelopeKeyids": envelope_keyids,
    }
    if not isinstance(policy_keyid, str) or not policy_keyid.strip():
        _add(result, IV_REFUSED_KEY_FROM_ENVELOPE)
        _check(
            result, 1, "trust root selected by the policy",
            "REFUSED", IV_REFUSED_KEY_FROM_ENVELOPE,
            "the policy names no keyid; the envelope's hint cannot select a root",
        )
        return None, IV_REFUSED_KEY_FROM_ENVELOPE
    _check(result, 1, "trust root selected by the policy", "PASS")

    # The inventory is a separate record. It may not be read from the candidate
    # evidence under verification.
    inventory = policy.get("trustRoots")
    roots_path = policy.get("trustRootsPath")
    if roots_path:
        candidate_evidence = policy.get("candidateEvidenceRoot")
        if isinstance(candidate_evidence, str) and _within(
            _resolve(roots_path, base), _resolve(candidate_evidence, base)
        ):
            _add(result, IV_REFUSED_CANDIDATE_TRUST_ROOT)
            _check(
                result, 4, "trust root recorded outside the candidate",
                "REFUSED", IV_REFUSED_CANDIDATE_TRUST_ROOT,
                "the inventory is inside the candidate evidence being verified",
            )
            return None, IV_REFUSED_CANDIDATE_TRUST_ROOT
    if inventory is None and roots_path:
        try:
            inventory = load_inventory(roots_path)
        except Refusal as refusal:
            _add(result, refusal.code)
            _check(
                result, 4, "trust root recorded outside the candidate",
                "REFUSED", refusal.code, refusal.message,
            )
            return None, refusal.code
    if not isinstance(inventory, Mapping) or not isinstance(inventory.get("roots"), list):
        _add(result, IV_REFUSED_TRUST_ROOT_UNRECORDED)
        _check(
            result, 4, "trust root recorded outside the candidate",
            "REFUSED", IV_REFUSED_TRUST_ROOT_UNRECORDED,
            "no trust-root inventory is recorded",
        )
        return None, IV_REFUSED_TRUST_ROOT_UNRECORDED

    roots = inventory["roots"]
    matching = [
        root for root in roots
        if isinstance(root, Mapping) and root.get("keyid") == policy_keyid
    ]

    selected: Mapping[str, Any] | None = None
    root_failure: str | None = None

    # 4 (first part): recorded exactly once.
    if len(matching) > 1:
        _add(result, IV_REFUSED_MULTIPLE_ROOTS)
        _check(
            result, 4, "trust root recorded exactly once",
            "REFUSED", IV_REFUSED_MULTIPLE_ROOTS,
            f"{len(matching)} roots claim {policy_keyid!r}",
        )
        root_failure = IV_REFUSED_MULTIPLE_ROOTS
    elif not matching:
        _add(result, IV_REFUSED_TRUST_ROOT_UNRECORDED)
        _check(
            result, 4, "trust root recorded exactly once",
            "REFUSED", IV_REFUSED_TRUST_ROOT_UNRECORDED,
            f"the policy keyid {policy_keyid!r} names no recorded root",
        )
        root_failure = IV_REFUSED_TRUST_ROOT_UNRECORDED
    else:
        selected = matching[0]
        _check(result, 4, "trust root recorded exactly once", "PASS")

    if selected is None:
        for number, name in (
            (2, "root is public, not symmetric"),
            (3, "root provenance is outside the candidate tree"),
            (5, "root is in a distinct trust domain"),
            (6, "root records a non-self-issued basis"),
        ):
            _check(result, number, name, "NOT_RUN")
        return None, root_failure

    result["root"] = dict(selected)

    # 2. A symmetric root cannot establish independence.
    if _root_is_symmetric(selected):
        _add(result, IV_REFUSED_SYMMETRIC)
        _check(
            result, 2, "root is public, not symmetric",
            "REFUSED", IV_REFUSED_SYMMETRIC,
            "the verifier would hold the signer's secret",
        )
        root_failure = root_failure or IV_REFUSED_SYMMETRIC
    else:
        _check(result, 2, "root is public, not symmetric", "PASS")

    # 3. The provenance record must be outside the candidate tree.
    provenance = selected.get("provenance")
    provenance_path = provenance.get("path") if isinstance(provenance, Mapping) else None
    if not isinstance(provenance_path, str) or not provenance_path:
        _add(result, IV_REFUSED_TRUST_ROOT_UNRECORDED)
        _check(
            result, 3, "root provenance is outside the candidate tree",
            "REFUSED", IV_REFUSED_TRUST_ROOT_UNRECORDED,
            "the root records no provenance path",
        )
        root_failure = root_failure or IV_REFUSED_TRUST_ROOT_UNRECORDED
    else:
        resolved = _resolve(provenance_path, base)
        candidate = _resolve(policy.get("candidateRoot", "."), base)
        if _within(resolved, candidate):
            _add(result, IV_REFUSED_CANDIDATE_TRUST_ROOT)
            _check(
                result, 3, "root provenance is outside the candidate tree",
                "REFUSED", IV_REFUSED_CANDIDATE_TRUST_ROOT,
                f"{provenance_path} is inside {policy.get('candidateRoot', '.')}",
            )
            root_failure = root_failure or IV_REFUSED_CANDIDATE_TRUST_ROOT
        else:
            _check(result, 3, "root provenance is outside the candidate tree", "PASS")

    # 4 (second part): provenance digest and freshness.
    digest_failure = None
    if isinstance(provenance_path, str) and provenance_path:
        resolved = _resolve(provenance_path, base)
        recorded = provenance.get("sha256") if isinstance(provenance, Mapping) else None
        if not isinstance(recorded, str) or not recorded:
            digest_failure = IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH
            detail = "the root records no provenance digest"
        elif not resolved.is_file():
            digest_failure = IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH
            detail = f"{provenance_path} is absent"
        else:
            actual = sha256_bytes(resolved.read_bytes())
            if actual != recorded:
                digest_failure = IV_REFUSED_TRUST_ROOT_DIGEST_MISMATCH
                detail = f"{provenance_path} hashes to {actual}, not {recorded}"
            else:
                detail = None
        if digest_failure:
            _add(result, digest_failure)
            _check(
                result, 4, "root provenance digest matches",
                "REFUSED", digest_failure, detail,
            )
            root_failure = root_failure or digest_failure
        else:
            _check(result, 4, "root provenance digest matches", "PASS")
    else:
        _check(result, 4, "root provenance digest matches", "NOT_RUN")

    as_of = policy.get("asOf")
    max_age = policy.get("maxRootAgeDays")
    if as_of is not None and max_age is not None:
        recorded_at = _parse_date(selected.get("recordedAt"), "recordedAt")
        as_of_date = _parse_date(as_of, "asOf")
        if recorded_at is None or as_of_date is None:
            _add(result, IV_REFUSED_TRUST_ROOT_STALE)
            _check(
                result, 4, "root is fresh",
                "REFUSED", IV_REFUSED_TRUST_ROOT_STALE,
                "the root records no usable recordedAt",
            )
            root_failure = root_failure or IV_REFUSED_TRUST_ROOT_STALE
        elif (as_of_date - recorded_at).days > int(max_age):
            _add(result, IV_REFUSED_TRUST_ROOT_STALE)
            _check(
                result, 4, "root is fresh",
                "REFUSED", IV_REFUSED_TRUST_ROOT_STALE,
                f"recordedAt {recorded_at} is older than {max_age} days at {as_of_date}",
            )
            root_failure = root_failure or IV_REFUSED_TRUST_ROOT_STALE
        else:
            _check(result, 4, "root is fresh", "PASS")
    else:
        _check(result, 4, "root is fresh", "NOT_RUN")

    # 5. The trust domain must differ from the candidate's and the producer's.
    domain = selected.get("trustDomain")
    forbidden = {
        policy.get("candidateDomain"),
        policy.get("producerDomain"),
    }
    if not isinstance(domain, str) or not domain:
        _add(result, IV_REFUSED_SAME_DOMAIN)
        _check(
            result, 5, "root is in a distinct trust domain",
            "REFUSED", IV_REFUSED_SAME_DOMAIN,
            "the root records no trust domain",
        )
        root_failure = root_failure or IV_REFUSED_SAME_DOMAIN
    elif domain in forbidden:
        _add(result, IV_REFUSED_SAME_DOMAIN)
        _check(
            result, 5, "root is in a distinct trust domain",
            "REFUSED", IV_REFUSED_SAME_DOMAIN,
            f"{domain!r} is the candidate's or the producer's domain",
        )
        root_failure = root_failure or IV_REFUSED_SAME_DOMAIN
    else:
        _check(result, 5, "root is in a distinct trust domain", "PASS")

    # 6. A self-issued basis is refused.
    if _self_issued_basis(selected):
        _add(result, IV_REFUSED_SELF_ISSUED)
        _check(
            result, 6, "root records a non-self-issued basis",
            "REFUSED", IV_REFUSED_SELF_ISSUED,
            "the root's independence basis is absent or self-issued",
        )
        root_failure = root_failure or IV_REFUSED_SELF_ISSUED
    else:
        _check(result, 6, "root records a non-self-issued basis", "PASS")

    return selected, root_failure


def verify(
    envelope_bytes: Any,
    policy: Mapping[str, Any],
    public_verify: Callable[[str, bytes, bytes, Any], bool] | None = None,
) -> dict[str, Any]:
    """Independently verify one envelope under a recorded policy.

    ``public_verify(keyid, pae_bytes, signature_bytes, public_material) -> bool``
    is caller-supplied.  This module implements no signature primitive: when the
    trust root is acceptable and no verifier is supplied, the outcome is
    ``NOT_RUN`` and never a pass.  When a root-level refusal already establishes
    that the envelope is not independent, the outcome is ``SELF_ISSUED`` (or
    ``UNVERIFIED``) even without a verifier, because the independence question is
    decided by the root, not by an unchecked signature.
    """
    result: dict[str, Any] = {
        "model": MODEL_ID,
        "outcome": OUTCOME_NOT_RUN,
        "independentlyVerified": False,
        "codes": [],
        "checks": [],
        "keyid": None,
        "root": None,
        "signatureChecked": False,
        "payloadSha256": None,
        "statement": None,
        "artefact": None,
    }

    if isinstance(envelope_bytes, (dict, list, str)) or not isinstance(
        envelope_bytes, (bytes, bytearray, memoryview)
    ):
        _add(result, IV_REFUSED_ENVELOPE)
        _check(
            result, 0, "envelope received as bytes",
            "REFUSED", IV_REFUSED_ENVELOPE,
            f"verification takes bytes, not {type(envelope_bytes).__name__}",
        )
        result["outcome"] = OUTCOME_UNVERIFIED
        result["checks"].sort(key=lambda row: row["check"])
        return result

    raw = bytes(envelope_bytes)
    try:
        document = harden.loads(raw)
    except harden.Refusal as refusal:
        _add(result, IV_REFUSED_ENVELOPE)
        _check(
            result, 0, "envelope received as bytes",
            "REFUSED", IV_REFUSED_ENVELOPE,
            f"the envelope is not strict JSON ({refusal.code}): {refusal.message}",
        )
        result["outcome"] = OUTCOME_UNVERIFIED
        result["checks"].sort(key=lambda row: row["check"])
        return result
    if not isinstance(document, dict):
        _add(result, IV_REFUSED_ENVELOPE)
        _check(
            result, 0, "envelope received as bytes",
            "REFUSED", IV_REFUSED_ENVELOPE,
            "the envelope is not a JSON object",
        )
        result["outcome"] = OUTCOME_UNVERIFIED
        result["checks"].sort(key=lambda row: row["check"])
        return result

    selected, root_failure = _root_selected_by_policy(result, document, policy)
    base = _base(policy)
    policy_keyid = policy.get("keyid")
    artefact_name = policy.get("artefact")
    artefact_name = _normalise_artefact(artefact_name) if isinstance(artefact_name, str) else None

    if artefact_name:
        result["artefact"] = {
            "path": artefact_name,
            "present": _resolve(artefact_name, base).is_file(),
        }

    # If the root already decides the independence question, a signature check is
    # informative but cannot upgrade the outcome.
    root_decided = root_failure is not None
    run_signature = public_verify is not None and (not root_decided or selected is not None)

    payload: bytes | None = None

    if not run_signature:
        _check(
            result, 7, "signature over the received PAE",
            "NOT_RUN",
            IV_REFUSED_NO_PUBLIC_VERIFIER if not root_decided and public_verify is None else None,
            "no public verifier was supplied" if public_verify is None else None,
        )
        _check(result, 8, "payload denotes the artefact's bytes", "NOT_RUN")
        _check(result, 9, "statement names the artefact under test", "NOT_RUN")
        if not root_decided and public_verify is None:
            _add(result, IV_REFUSED_NO_PUBLIC_VERIFIER)
    else:
        def verifier(sig_keyid: str, pae_bytes: bytes, signature: bytes) -> bool:
            if sig_keyid != policy_keyid:
                return False
            try:
                return bool(
                    public_verify(
                        str(policy_keyid), pae_bytes, signature,
                        selected.get("publicMaterial") if selected else None,
                    )
                )
            except Exception:  # a verifier that raises has not verified anything
                return False

        try:
            report = dsse.verify_pae(
                raw,
                verifier,
                expected_payload_type=dsse.IN_TOTO_PAYLOAD_TYPE,
                require_statement=False,
            )
        except dsse.Refusal as refusal:
            if refusal.code in (
                dsse.DS_REFUSED_SIGNATURE_INVALID,
                dsse.DS_REFUSED_PAE_RESERIALISED,
            ):
                code = IV_REFUSED_SIGNATURE
            elif refusal.code == dsse.DS_REFUSED_PAYLOAD_NOT_STATEMENT:
                code = IV_REFUSED_PAYLOAD_NOT_SUBJECT
            else:
                code = IV_REFUSED_ENVELOPE
            result["signatureChecked"] = True
            _add(result, code)
            _check(
                result, 7, "signature over the received PAE",
                "REFUSED", code, refusal.message,
            )
            _check(result, 8, "payload denotes the artefact's bytes", "NOT_RUN")
            _check(result, 9, "statement names the artefact under test", "NOT_RUN")
        else:
            result["signatureChecked"] = True
            payload = report["payload"]
            result["payloadSha256"] = sha256_bytes(payload)
            _check(result, 7, "signature over the received PAE", "PASS")

            statement: Mapping[str, Any] | None = None
            try:
                statement = intoto.decode(payload, repo_root=None)
            except intoto.Refusal as refusal:
                _add(result, IV_REFUSED_PAYLOAD_NOT_SUBJECT)
                _check(
                    result, 8, "payload denotes the artefact's bytes",
                    "REFUSED", IV_REFUSED_PAYLOAD_NOT_SUBJECT,
                    f"the verified payload is not a canonical Statement v1 "
                    f"({refusal.code}): {refusal.message}",
                )
            if statement is not None:
                result["statement"] = {
                    "predicateType": statement.get("predicateType"),
                    "subjectCount": len(statement.get("subject", [])),
                }
                subjects = statement.get("subject")
                matching = []
                if isinstance(subjects, list):
                    matching = [
                        subject for subject in subjects
                        if isinstance(subject, Mapping)
                        and subject.get("name") == artefact_name
                    ]
                if not artefact_name:
                    _add(result, IV_REFUSED_SUBJECT_MISMATCH)
                    _check(
                        result, 9, "statement names the artefact under test",
                        "REFUSED", IV_REFUSED_SUBJECT_MISMATCH,
                        "the policy names no artefact under test",
                    )
                elif not matching:
                    _add(result, IV_REFUSED_SUBJECT_MISMATCH)
                    _check(
                        result, 9, "statement names the artefact under test",
                        "REFUSED", IV_REFUSED_SUBJECT_MISMATCH,
                        f"no subject is named {artefact_name!r}",
                    )
                    _check(
                        result, 8, "payload denotes the artefact's bytes",
                        "NOT_RUN",
                    )
                else:
                    _check(result, 9, "statement names the artefact under test", "PASS")
                    digest = matching[0].get("digest")
                    declared = (
                        digest.get("sha256") if isinstance(digest, Mapping) else None
                    )
                    path = _resolve(artefact_name, base)
                    if not path.is_file():
                        _add(result, IV_REFUSED_SUBJECT_ABSENT)
                        _check(
                            result, 8, "payload denotes the artefact's bytes",
                            "REFUSED", IV_REFUSED_SUBJECT_ABSENT,
                            f"{artefact_name} is absent",
                        )
                        result["artefact"] = {
                            "path": artefact_name, "present": False,
                        }
                    else:
                        actual = sha256_bytes(path.read_bytes())
                        result["artefact"] = {
                            "path": artefact_name,
                            "present": True,
                            "sha256": actual,
                            "declaredSha256": declared,
                        }
                        if not isinstance(declared, str) or actual != declared:
                            _add(result, IV_REFUSED_PAYLOAD_NOT_SUBJECT)
                            _check(
                                result, 8, "payload denotes the artefact's bytes",
                                "REFUSED", IV_REFUSED_PAYLOAD_NOT_SUBJECT,
                                f"{artefact_name} hashes to {actual}, not {declared}",
                            )
                        else:
                            _check(
                                result, 8, "payload denotes the artefact's bytes",
                                "PASS",
                            )

    # Decide the outcome. A root-level same-party refusal is stronger than an
    # unchecked signature: independence was never available.
    same_party = [code for code in result["codes"] if code in SAME_PARTY_CODES]
    undecided_root = [code for code in result["codes"] if code in UNVERIFIED_ROOT_CODES]
    other_failures = [
        code for code in result["codes"]
        if code not in ROOT_CODES and code != IV_REFUSED_NO_PUBLIC_VERIFIER
    ]
    if IV_REFUSED_ENVELOPE in result["codes"] and not result["checks"]:
        result["outcome"] = OUTCOME_UNVERIFIED
    elif same_party:
        result["outcome"] = OUTCOME_SELF_ISSUED
    elif undecided_root:
        result["outcome"] = OUTCOME_UNVERIFIED
    elif other_failures:
        result["outcome"] = OUTCOME_UNVERIFIED
    elif public_verify is None:
        result["outcome"] = OUTCOME_NOT_RUN
    else:
        result["outcome"] = OUTCOME_VERIFIED
    result["independentlyVerified"] = result["outcome"] == OUTCOME_VERIFIED
    result["checks"].sort(key=lambda row: row["check"])
    return result


# ---------------------------------------------------------------------------
# Reporting helpers.
# ---------------------------------------------------------------------------


def _primary_code(result: Mapping[str, Any]) -> str:
    codes = result.get("codes") or []
    return codes[0] if codes else CODE_OK


def _codes_text(result: Mapping[str, Any]) -> str:
    codes = result.get("codes") or []
    return ",".join(codes) if codes else CODE_OK


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _load_policy(roots_path: str) -> dict[str, Any]:
    document = load_inventory(roots_path)
    return policy_from_inventory(document, roots_path)


def _command_roots(roots_path: str) -> int:
    try:
        document = load_inventory(roots_path)
        policy = policy_from_inventory(document, roots_path)
    except Refusal as refusal:
        print(f"roots: code={refusal.code} outcome={OUTCOME_NOT_RUN} {refusal.message}",
              file=sys.stderr)
        return EXIT_REFUSED
    roots = document["roots"]
    for root in roots:
        if not isinstance(root, Mapping):
            continue
        print(
            "root: keyid={} algorithm={} symmetric={} trustDomain={} external={} "
            "provenance={}".format(
                root.get("keyid"),
                root.get("algorithm"),
                str(_root_is_symmetric(root)).lower(),
                root.get("trustDomain"),
                str(_root_is_external(root, policy)).lower(),
                (root.get("provenance") or {}).get("path"),
            )
        )
    qualification = qualify(document, policy)
    digest = sha256_bytes(Path(roots_path).read_bytes())
    print(
        f"roots: code={CODE_OK} roots={qualification['roots']} "
        f"externalRoots={qualification['externalRoots']} "
        f"symmetricRoots={qualification['symmetricRoots']} "
        f"inventorySha256={digest} outcome={qualification['outcome']}"
    )
    return EXIT_OK


def _command_verify(envelope: str, artefact: str, roots_path: str) -> int:
    try:
        policy = _load_policy(roots_path)
    except Refusal as refusal:
        print(
            f"verify: code={refusal.code} outcome={OUTCOME_NOT_RUN} {refusal.message}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    policy["artefact"] = artefact
    try:
        raw = Path(envelope).read_bytes()
    except OSError as error:
        print(
            f"verify: code={IV_REFUSED_ENVELOPE} outcome={OUTCOME_UNVERIFIED} "
            f"{envelope}: {error}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    result = verify(raw, policy, None)
    print(
        f"verify: code={_primary_code(result)} outcome={result['outcome']} "
        f"independentlyVerified={str(result['independentlyVerified']).lower()} "
        f"envelope={envelope} artefact={artefact} codes={_codes_text(result)}"
    )
    return EXIT_OK if result["outcome"] == OUTCOME_VERIFIED else EXIT_REFUSED


def _command_qualify(roots_path: str) -> int:
    try:
        document = load_inventory(roots_path)
        policy = policy_from_inventory(document, roots_path)
        qualification = qualify(document, policy)
    except Refusal as refusal:
        print(
            f"qualify: code={refusal.code} outcome={OUTCOME_NOT_RUN} {refusal.message}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    print(
        f"qualify: code={CODE_OK} roots={qualification['roots']} "
        f"externalRoots={qualification['externalRoots']} "
        f"symmetricRoots={qualification['symmetricRoots']} "
        f"outcome={qualification['outcome']}"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="independent_verify.py", add_help=True)
    subparsers = parser.add_subparsers(dest="command")
    roots_parser = subparsers.add_parser("roots")
    roots_parser.add_argument("--roots", default=DEFAULT_ROOTS)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("envelope")
    verify_parser.add_argument("artefact")
    verify_parser.add_argument("--roots", default=DEFAULT_ROOTS)
    qualify_parser = subparsers.add_parser("qualify")
    qualify_parser.add_argument("--roots", default=DEFAULT_ROOTS)
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exit_error:
        if exit_error.code == 0:
            return EXIT_OK
        print(f"{CODE_USAGE}: the command line was not understood", file=sys.stderr)
        return EXIT_USAGE
    try:
        if parsed.command == "roots":
            return _command_roots(parsed.roots)
        if parsed.command == "verify":
            return _command_verify(parsed.envelope, parsed.artefact, parsed.roots)
        if parsed.command == "qualify":
            return _command_qualify(parsed.roots)
    except Refusal as refusal:
        print(f"{refusal}", file=sys.stderr)
        return EXIT_REFUSED
    print(f"{CODE_USAGE}: no command was given", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
