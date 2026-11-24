#!/usr/bin/env python3
"""reproducibility.py -- signature reproducibility is not artefact reproducibility.

Why this tool exists
--------------------
Two claims are routinely conflated:

* **Signature reproducibility** -- signing the same bytes twice with the same key
  produces the same signature, or a different one.  This is a property of the
  *scheme* and its inputs.  HMAC-SHA256, RSA PKCS#1 v1.5 and Ed25519 are
  deterministic; ECDSA with a fresh per-signature nonce is randomised.  A
  randomised scheme producing a different signature each time is working as
  designed, not failing.

* **Artefact reproducibility** -- building the same inputs twice produces the
  same bytes.  This is a property of the *build*: its sources, toolchain,
  environment and recipe.

Neither implies the other.  A byte-identical signature over an artefact says
nothing about whether that artefact can be rebuilt.  A byte-identical rebuild
says nothing about whether the signer is deterministic.  This module keeps the
two axes separate, names the four combinations and records, for each, the
inference a consumer may **not** draw.

The nonce-reuse refusal is not a reproducibility property.  A randomised
signature scheme that emits the same signature twice over the same message has
reused its per-signature nonce (or its randomness); for ECDSA that leaks the
private key from two signatures, so it is a key-recovery defect.  It is refused
as `SR_REFUSED_NONCE_REUSE`, not reported as a reproducibility success.

What this module does not do
----------------------------
It implements no signature scheme and no build.  It reads records: signature
attempts and rebuild records.  It does not decide authenticity, identity,
authorisation, independence or trust; those are A10, A12 and A14-A17.

Usage
-----
    python3 forensics/tools/reproducibility.py signature <envelope> <attempt>...
    python3 forensics/tools/reproducibility.py artefact <subject> <rebuild-record>
    python3 forensics/tools/reproducibility.py classify

Exit status: 0 when the selected question is answered with a supported
state, 1 when the answer is a refusal (the stable code is always printed),
2 for a usage error (``SR_USAGE`` is printed).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/reproducibility.py"

MODEL_ID = "a13/v1"
SIGNATURE_SCHEMA = "openssl-rs/a13/signature/1"
ARTEFACT_SCHEMA = "openssl-rs/a13/artefact/1"
CLASSIFICATION_SCHEMA = "openssl-rs/a13/classification/1"
CONTROLS_SCHEMA = "openssl-rs/a13/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "SR_OK"
CODE_USAGE = "SR_USAGE"

# ---------------------------------------------------------------------------
# The two axes.  Each state is stable and licenses exactly one reading.
# ---------------------------------------------------------------------------

SIGNATURE_STABLE = "SIGNATURE_STABLE"
SIGNATURE_VARIES = "SIGNATURE_VARIES"
SIGNATURE_NONCE_REUSED = "SIGNATURE_NONCE_REUSED"
SIGNATURE_UNKNOWN = "SIGNATURE_UNKNOWN"

ARTEFACT_REPRODUCIBLE = "ARTEFACT_REPRODUCIBLE"
ARTEFACT_DIFFERS = "ARTEFACT_DIFFERS"
ARTEFACT_NOT_REBUILT = "ARTEFACT_NOT_REBUILT"
ARTEFACT_UNKNOWN = "ARTEFACT_UNKNOWN"

SIGNATURE_STATES = (
    SIGNATURE_STABLE,
    SIGNATURE_VARIES,
    SIGNATURE_NONCE_REUSED,
    SIGNATURE_UNKNOWN,
)
ARTEFACT_STATES = (
    ARTEFACT_REPRODUCIBLE,
    ARTEFACT_DIFFERS,
    ARTEFACT_NOT_REBUILT,
    ARTEFACT_UNKNOWN,
)

# ---------------------------------------------------------------------------
# Refusal codes.  Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

SR_REFUSED_SIGNATURE_AS_ARTEFACT = "SR_REFUSED_SIGNATURE_AS_ARTEFACT"
SR_REFUSED_ARTEFACT_AS_SIGNATURE = "SR_REFUSED_ARTEFACT_AS_SIGNATURE"
SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE = (
    "SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE"
)
SR_REFUSED_NONDETERMINISTIC_AS_FAILURE = "SR_REFUSED_NONDETERMINISTIC_AS_FAILURE"
SR_REFUSED_NONCE_REUSE = "SR_REFUSED_NONCE_REUSE"
SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST = "SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST"
SR_REFUSED_SEED_AS_KEY = "SR_REFUSED_SEED_AS_KEY"
SR_REFUSED_INPUTS_UNSTATED = "SR_REFUSED_INPUTS_UNSTATED"
SR_REFUSED_REBUILD_NOT_RUN = "SR_REFUSED_REBUILD_NOT_RUN"
SR_REFUSED_SCHEME_UNRECORDED = "SR_REFUSED_SCHEME_UNRECORDED"
SR_REFUSED_REPLAY_AS_REPRODUCTION = "SR_REFUSED_REPLAY_AS_REPRODUCTION"
SR_REFUSED_ATTEMPTS_INSUFFICIENT = "SR_REFUSED_ATTEMPTS_INSUFFICIENT"
SR_REFUSED_ATTEMPT_MALFORMED = "SR_REFUSED_ATTEMPT_MALFORMED"
SR_REFUSED_DETERMINISTIC_VARIED = "SR_REFUSED_DETERMINISTIC_VARIED"

REFUSALS: dict[str, dict[str, str]] = {
    SR_REFUSED_SIGNATURE_AS_ARTEFACT: {
        "condition": (
            "a stable signature state is read as evidence that the artefact can "
            "be rebuilt"
        ),
        "prevents": (
            "that repeated identical signatures are counted as a reproducible "
            "build; the signature is a function of the signer's inputs, the build "
            "is a function of the build's inputs"
        ),
    },
    SR_REFUSED_ARTEFACT_AS_SIGNATURE: {
        "condition": (
            "a reproducible artefact state is read as evidence that the signer is "
            "deterministic, or that a randomised signer is faulty"
        ),
        "prevents": (
            "that a byte-identical rebuild is called a deterministic signature, or "
            "a randomised signature is called a build defect"
        ),
    },
    SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE: {
        "condition": (
            "a deterministic signature scheme (or a symmetric test key derived "
            "from a fixed seed) is presented as an independent party"
        ),
        "prevents": (
            "that determinism is read as independence; independence is A12's "
            "question and requires a distinct trust domain and a root outside the "
            "producer"
        ),
    },
    SR_REFUSED_NONDETERMINISTIC_AS_FAILURE: {
        "condition": (
            "a randomised scheme produces different signatures over the same bytes"
        ),
        "prevents": (
            "that a per-signature nonce or fresh randomness is reported as a "
            "defect; varying output is the expected property of a randomised "
            "scheme"
        ),
    },
    SR_REFUSED_NONCE_REUSE: {
        "condition": (
            "a randomised scheme produces the same signature twice, or records "
            "the same nonce for two signatures"
        ),
        "prevents": (
            "that nonce or randomness reuse is recorded as reproducibility; for "
            "ECDSA two signatures over one nonce recover the private key, so it is "
            "a key-recovery defect"
        ),
    },
    SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST: {
        "condition": (
            "a DSSE envelope digest, or another signed-record digest, is offered "
            "as the digest of a build artefact"
        ),
        "prevents": (
            "that the digest of the envelope that carries a statement is read as "
            "the digest of the artefact the statement describes"
        ),
    },
    SR_REFUSED_SEED_AS_KEY: {
        "condition": (
            "a raw seed is recorded as the signing key, rather than a key derived "
            "from it"
        ),
        "prevents": (
            "that a fixed public test seed is treated as a production key or a "
            "trust root; the A10 key is derived from a seed and is labelled "
            "test-only"
        ),
    },
    SR_REFUSED_INPUTS_UNSTATED: {
        "condition": (
            "the two attempts, or the two builds, do not record the same inputs, "
            "or an attempt or rebuild record omits the inputs it depends on"
        ),
        "prevents": (
            "that a comparison of different inputs is reported as a repetition of "
            "the same input"
        ),
    },
    SR_REFUSED_REBUILD_NOT_RUN: {
        "condition": (
            "no rebuild record exists, or the recorded rebuild outcome is NOT_RUN"
        ),
        "prevents": (
            "that a stable recorded digest, or an unrun rebuild, is reported as a "
            "reproducible build"
        ),
    },
    SR_REFUSED_SCHEME_UNRECORDED: {
        "condition": "the scheme is absent from the registry",
        "prevents": (
            "that an unknown scheme is assigned a determinism class and compared "
            "as if its repeat behaviour were known"
        ),
    },
    SR_REFUSED_REPLAY_AS_REPRODUCTION: {
        "condition": (
            "the rebuild record describes a replay of existing bytes rather than "
            "an independent rebuild"
        ),
        "prevents": (
            "that copying or re-reading a product is counted as rebuilding it"
        ),
    },
    SR_REFUSED_ATTEMPTS_INSUFFICIENT: {
        "condition": "fewer than two signature attempts are recorded",
        "prevents": (
            "that one signature is called stable or varying; a repetition needs at "
            "least two attempts"
        ),
    },
    SR_REFUSED_ATTEMPT_MALFORMED: {
        "condition": (
            "an attempt record has no decodable signature, or is not a record"
        ),
        "prevents": (
            "that a missing or undecodable signature is treated as an attempt and "
            "silently compared"
        ),
    },
    SR_REFUSED_DETERMINISTIC_VARIED: {
        "condition": (
            "a scheme declared deterministic produces different signatures over "
            "recorded-identical inputs"
        ),
        "prevents": (
            "that a deterministic scheme's varying output is accepted as normal "
            "reproducibility, hiding a non-deterministic signer or a wrong scheme "
            "record"
        ),
    },
}


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
    return hashlib.sha256(bytes(data)).hexdigest()


# ---------------------------------------------------------------------------
# The scheme registry: determinism class and the repeat comparison.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scheme:
    name: str
    deterministic: bool
    symmetric: bool
    randomised: bool
    repeat: str
    note: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "deterministic": self.deterministic,
            "symmetric": self.symmetric,
            "randomised": self.randomised,
            "repeat": self.repeat,
            "note": self.note,
        }


SCHEMES: dict[str, Scheme] = {
    "hmac-sha256": Scheme(
        name="hmac-sha256",
        deterministic=True,
        symmetric=True,
        randomised=False,
        repeat="byte-equality",
        note=(
            "HMAC is a deterministic function of (key, message). It is symmetric: "
            "the verifier holds the signing key, so it can never establish "
            "independence (A12)."
        ),
    ),
    "rsa-pkcs1v15": Scheme(
        name="rsa-pkcs1v15",
        deterministic=True,
        symmetric=False,
        randomised=False,
        repeat="byte-equality",
        note=(
            "RSASSA-PKCS1-v1_5 is deterministic for a fixed key and message. Two "
            "different signatures over the same bytes indicate different inputs or "
            "a defective signer."
        ),
    ),
    "ed25519": Scheme(
        name="ed25519",
        symmetric=False,
        deterministic=True,
        randomised=False,
        repeat="byte-equality",
        note=(
            "Ed25519 derives its per-signature scalar deterministically from the "
            "key and message, so repeated signing is byte-identical."
        ),
    ),
    "ecdsa": Scheme(
        name="ecdsa",
        deterministic=False,
        symmetric=False,
        randomised=True,
        repeat="non-equality-and-nonce-reuse-check",
        note=(
            "ECDSA with fresh randomness (or a per-signature nonce) produces a "
            "different signature each time. Varying output is expected; repeated "
            "output means the nonce or randomness was reused, which leaks the "
            "private key."
        ),
    ),
}


def scheme_record(name: str) -> Scheme | None:
    return SCHEMES.get(name)


# ---------------------------------------------------------------------------
# Signature attempts and the signature axis.
# ---------------------------------------------------------------------------


def _decode_signature(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            return None
        return raw
    return None


def _nonce_token(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return str(value)


def _signature_result(
    state: str,
    code: str,
    scheme: str | None,
    record: Scheme | None,
    attempts: int,
    *,
    detail: str,
    signature_digests: Sequence[str] = (),
    envelope_digests: Sequence[str] = (),
    nonce_reused: bool = False,
) -> dict[str, Any]:
    return {
        "state": state,
        "code": code,
        "refusals": [] if code == CODE_OK else [code],
        "scheme": scheme,
        "deterministic": None if record is None else record.deterministic,
        "symmetric": None if record is None else record.symmetric,
        "randomised": None if record is None else record.randomised,
        "repeat": None if record is None else record.repeat,
        "attempts": attempts,
        "signatureSha256": list(signature_digests),
        "envelopeSha256": list(envelope_digests),
        "nonceReused": nonce_reused,
        "detail": detail,
    }


def signature_evidence(
    envelope_attempts: Sequence[Mapping[str, Any]],
    scheme: str,
) -> dict[str, Any]:
    """Compare repeated signing attempts on the signature axis.

    Each attempt is a record with ``signature`` (base64 or bytes) and ``inputs``
    (a non-empty mapping naming the key and message it signed).  An optional
    ``nonce`` is compared for a randomised scheme, and ``keyKind`` distinguishes
    a derived key from a raw seed.  A deterministic scheme is compared by byte
    equality; a randomised scheme by non-equality **and** a nonce-reuse check.

    The result is one of ``SIGNATURE_STABLE``, ``SIGNATURE_VARIES``,
    ``SIGNATURE_NONCE_REUSED`` or ``SIGNATURE_UNKNOWN``.
    """
    attempt_list = list(envelope_attempts)
    record = scheme_record(scheme)
    if record is None:
        return _signature_result(
            SIGNATURE_UNKNOWN,
            SR_REFUSED_SCHEME_UNRECORDED,
            scheme,
            None,
            len(attempt_list),
            detail=(
                f"the scheme {scheme!r} is not in the registry, so its repeat "
                "behaviour is unknown and it is not compared"
            ),
        )
    if len(attempt_list) < 2:
        return _signature_result(
            SIGNATURE_UNKNOWN,
            SR_REFUSED_ATTEMPTS_INSUFFICIENT,
            scheme,
            record,
            len(attempt_list),
            detail=(
                f"{len(attempt_list)} attempt(s) recorded; a repetition needs at "
                "least two"
            ),
        )

    decoded: list[dict[str, Any]] = []
    for index, attempt in enumerate(attempt_list, 1):
        if not isinstance(attempt, Mapping):
            return _signature_result(
                SIGNATURE_UNKNOWN,
                SR_REFUSED_ATTEMPT_MALFORMED,
                scheme,
                record,
                len(attempt_list),
                detail=f"attempt {index} is not a record",
            )
        signature = _decode_signature(attempt.get("signature"))
        if not signature:
            return _signature_result(
                SIGNATURE_UNKNOWN,
                SR_REFUSED_ATTEMPT_MALFORMED,
                scheme,
                record,
                len(attempt_list),
                detail=(
                    f"attempt {index} carries no decodable signature"
                ),
            )
        key_kind = attempt.get("keyKind")
        if key_kind in ("seed", "raw-seed"):
            return _signature_result(
                SIGNATURE_UNKNOWN,
                SR_REFUSED_SEED_AS_KEY,
                scheme,
                record,
                len(attempt_list),
                detail=(
                    f"attempt {index} records a raw seed as the signing key; a "
                    "seed is not a key and a fixed test seed is not a trust root"
                ),
            )
        inputs = attempt.get("inputs")
        if not isinstance(inputs, Mapping) or not inputs:
            return _signature_result(
                SIGNATURE_UNKNOWN,
                SR_REFUSED_INPUTS_UNSTATED,
                scheme,
                record,
                len(attempt_list),
                detail=f"attempt {index} records no inputs",
            )
        decoded.append(
            {
                "signature": signature,
                "signatureSha256": sha256_bytes(signature),
                "inputs": dict(inputs),
                "nonce": _nonce_token(attempt.get("nonce")),
                "envelopeSha256": attempt.get("envelopeSha256"),
            }
        )

    first_inputs = decoded[0]["inputs"]
    for index, attempt in enumerate(decoded[1:], 2):
        if attempt["inputs"] != first_inputs:
            return _signature_result(
                SIGNATURE_UNKNOWN,
                SR_REFUSED_INPUTS_UNSTATED,
                scheme,
                record,
                len(attempt_list),
                detail=(
                    f"attempt {index} records different inputs from attempt 1; a "
                    "repetition must compare the same inputs"
                ),
            )

    signatures = [attempt["signature"] for attempt in decoded]
    signature_digests = [attempt["signatureSha256"] for attempt in decoded]
    envelope_digests = [
        attempt["envelopeSha256"]
        for attempt in decoded
        if isinstance(attempt["envelopeSha256"], str)
    ]

    if record.randomised:
        nonces = [attempt["nonce"] for attempt in decoded if attempt["nonce"] is not None]
        repeated_nonce = len(set(nonces)) < len(nonces)
        repeated_signature = len(set(signatures)) < len(signatures)
        if repeated_nonce or repeated_signature:
            return _signature_result(
                SIGNATURE_NONCE_REUSED,
                SR_REFUSED_NONCE_REUSE,
                scheme,
                record,
                len(attempt_list),
                detail=(
                    "the randomised scheme repeated a signature"
                    if repeated_signature
                    else "the randomised scheme repeated a nonce"
                )
                + "; this is nonce or randomness reuse, a key-recovery defect, "
                "not reproducibility",
                signature_digests=signature_digests,
                envelope_digests=envelope_digests,
                nonce_reused=True,
            )
        return _signature_result(
            SIGNATURE_VARIES,
            CODE_OK,
            scheme,
            record,
            len(attempt_list),
            detail=(
                "the randomised scheme produced distinct signatures over the same "
                "inputs, which is expected and is not a failure"
            ),
            signature_digests=signature_digests,
            envelope_digests=envelope_digests,
        )

    if len(set(signatures)) == 1:
        return _signature_result(
            SIGNATURE_STABLE,
            CODE_OK,
            scheme,
            record,
            len(attempt_list),
            detail=(
                "the deterministic scheme produced byte-identical signatures over "
                "the same inputs"
            ),
            signature_digests=signature_digests,
            envelope_digests=envelope_digests,
        )
    return _signature_result(
        SIGNATURE_VARIES,
        SR_REFUSED_DETERMINISTIC_VARIED,
        scheme,
        record,
        len(attempt_list),
        detail=(
            "the scheme is declared deterministic but its signatures differ over "
            "recorded-identical inputs"
        ),
        signature_digests=signature_digests,
        envelope_digests=envelope_digests,
    )


# ---------------------------------------------------------------------------
# The artefact axis.
# ---------------------------------------------------------------------------


def _artefact_result(
    state: str,
    code: str,
    subject: Any,
    rebuild: Any,
    *,
    detail: str,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "state": state,
        "code": code,
        "refusals": [] if code == CODE_OK else [code],
        "subject": subject,
        "rebuild": rebuild,
        "reproducibilityClaimed": state == ARTEFACT_REPRODUCIBLE,
        "detail": detail,
        "reason": reason,
    }


_HEX64 = set("0123456789abcdef")


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _HEX64
    )


def artefact_evidence(
    subject: Mapping[str, Any],
    rebuild: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Decide the artefact axis from a rebuild record, never from a digest.

    ``subject`` names an artefact and its digest.  ``rebuild`` must be a record
    of an actual rebuild: its inputs, its outcome and, for a completed rebuild,
    the two build digests.  An absent record, a ``NOT_RUN`` outcome or a replay
    is ``ARTEFACT_NOT_REBUILT``; a stable digest alone is never reproducible.
    """
    if not isinstance(subject, Mapping):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the subject is not a record and states no identity",
        )
    kind = subject.get("kind")
    if kind == "envelope":
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST,
            subject,
            rebuild,
            detail=(
                "the subject is an envelope or signed record, not a build "
                "artefact; its digest is not a build digest"
            ),
        )

    if not rebuild:
        return _artefact_result(
            ARTEFACT_NOT_REBUILT,
            SR_REFUSED_REBUILD_NOT_RUN,
            subject,
            rebuild,
            detail="no rebuild record exists for this subject",
            reason="no rebuild record",
        )
    if not isinstance(rebuild, Mapping):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the rebuild record is not a record",
        )
    if rebuild.get("method") == "replay":
        return _artefact_result(
            ARTEFACT_NOT_REBUILT,
            SR_REFUSED_REPLAY_AS_REPRODUCTION,
            subject,
            rebuild,
            detail=(
                "the record describes a replay of existing bytes, not an "
                "independent rebuild"
            ),
            reason=str(rebuild.get("reason") or "replay"),
        )

    outcome = rebuild.get("outcome")
    if isinstance(outcome, str) and outcome.upper() == "NOT_RUN":
        return _artefact_result(
            ARTEFACT_NOT_REBUILT,
            SR_REFUSED_REBUILD_NOT_RUN,
            subject,
            rebuild,
            detail="the recorded rebuild outcome is NOT_RUN",
            reason=str(rebuild.get("reason") or "the rebuild did not run"),
        )

    inputs = rebuild.get("inputs")
    if not isinstance(inputs, Mapping) or not inputs:
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the rebuild record states no inputs",
        )
    if not isinstance(outcome, str):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the rebuild record states no outcome",
        )

    normalised = outcome.upper()
    if normalised not in ("REPRODUCED", "DIFFERS"):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail=f"the outcome {outcome!r} is not a recorded rebuild outcome",
        )

    digests = rebuild.get("digests")
    if not isinstance(digests, Mapping):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the rebuild record states no build digests",
        )
    first = digests.get("first")
    second = digests.get("second")
    if not (_is_digest(first) and _is_digest(second)):
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail="the two build digests are not recorded as SHA-256 values",
        )

    subject_digest = subject.get("sha256")
    recorded_subject = rebuild.get("subjectSha256")
    if normalised == "REPRODUCED":
        if not (_is_digest(subject_digest) and _is_digest(recorded_subject)):
            return _artefact_result(
                ARTEFACT_UNKNOWN,
                SR_REFUSED_INPUTS_UNSTATED,
                subject,
                rebuild,
                detail=(
                    "a reproduced build must bind both the subject digest and the "
                    "rebuild's subject digest"
                ),
            )
        if first != second:
            return _artefact_result(
                ARTEFACT_DIFFERS,
                CODE_OK,
                subject,
                rebuild,
                detail="the two rebuilds produced different bytes",
            )
        if recorded_subject != subject_digest:
            return _artefact_result(
                ARTEFACT_DIFFERS,
                CODE_OK,
                subject,
                rebuild,
                detail=(
                    "the rebuild reproduced, but its product digest is not the "
                    "subject's digest"
                ),
            )
        return _artefact_result(
            ARTEFACT_REPRODUCIBLE,
            CODE_OK,
            subject,
            rebuild,
            detail=(
                "two independent rebuilds produced the same bytes and that digest "
                "is the subject's"
            ),
        )

    if first == second:
        return _artefact_result(
            ARTEFACT_UNKNOWN,
            SR_REFUSED_INPUTS_UNSTATED,
            subject,
            rebuild,
            detail=(
                "the outcome says DIFFERS but the recorded build digests are equal"
            ),
        )
    return _artefact_result(
        ARTEFACT_DIFFERS,
        CODE_OK,
        subject,
        rebuild,
        detail="the two rebuilds produced different bytes",
    )


# ---------------------------------------------------------------------------
# Classification: the four combinations, and what each forbids.
# ---------------------------------------------------------------------------

COMBINATION_LABELS: dict[tuple[str, str], str] = {
    (SIGNATURE_STABLE, ARTEFACT_REPRODUCIBLE):
        "STABLE_SIGNATURE__REPRODUCIBLE_ARTEFACT",
    (SIGNATURE_STABLE, ARTEFACT_NOT_REBUILT):
        "STABLE_SIGNATURE__NOT_REBUILT_ARTEFACT",
    (SIGNATURE_VARIES, ARTEFACT_REPRODUCIBLE):
        "VARYING_SIGNATURE__REPRODUCIBLE_ARTEFACT",
    (SIGNATURE_VARIES, ARTEFACT_NOT_REBUILT):
        "VARYING_SIGNATURE__NOT_REBUILT_ARTEFACT",
}

_DIFFERS_LABELS: dict[str, str] = {
    SIGNATURE_STABLE: "STABLE_SIGNATURE__DIFFERING_ARTEFACT",
    SIGNATURE_VARIES: "VARYING_SIGNATURE__DIFFERING_ARTEFACT",
}

_PERMITTED = {
    (SIGNATURE_STABLE, ARTEFACT_REPRODUCIBLE): (
        "the signer repeated its signature byte-for-byte and two independent "
        "rebuilds produced the same artefact bytes; these are two separate "
        "measurements and neither is evidence for the other"
    ),
    (SIGNATURE_STABLE, ARTEFACT_NOT_REBUILT): (
        "the signer repeated its signature byte-for-byte; the artefact has no "
        "rebuild record, so no build-reproducibility claim is available"
    ),
    (SIGNATURE_VARIES, ARTEFACT_REPRODUCIBLE): (
        "the randomised signer varied as designed and two independent rebuilds "
        "produced the same artefact bytes; varying signatures are not a build "
        "defect"
    ),
    (SIGNATURE_VARIES, ARTEFACT_NOT_REBUILT): (
        "the randomised signer varied as designed and the artefact has no rebuild "
        "record; neither axis is evidence for the other"
    ),
}


def classify(
    signature: Mapping[str, Any] | str,
    artefact: Mapping[str, Any] | str,
) -> dict[str, Any]:
    """Name the combination and the inferences a consumer may not draw.

    ``signature`` and ``artefact`` are the evidence records returned by
    :func:`signature_evidence` and :func:`artefact_evidence`, or their state
    strings.  A nonce-reused signature or an unknown state is a refusal, not a
    combination.
    """
    signature_record = signature if isinstance(signature, Mapping) else {}
    artefact_record = artefact if isinstance(artefact, Mapping) else {}
    signature_state = (
        signature_record.get("state") if isinstance(signature, Mapping) else signature
    )
    artefact_state = (
        artefact_record.get("state") if isinstance(artefact, Mapping) else artefact
    )

    if signature_state == SIGNATURE_NONCE_REUSED:
        _fail(
            SR_REFUSED_NONCE_REUSE,
            "a randomised scheme repeated a signature or nonce; this is a "
            "key-recovery defect and is not classified as reproducibility",
        )
    if signature_state not in (SIGNATURE_STABLE, SIGNATURE_VARIES):
        _fail(
            str(signature_record.get("code") or SR_REFUSED_ATTEMPTS_INSUFFICIENT),
            f"the signature state {signature_state!r} is not a measured "
            "stable/varying result",
        )
    if artefact_state not in (
        ARTEFACT_REPRODUCIBLE,
        ARTEFACT_NOT_REBUILT,
        ARTEFACT_DIFFERS,
    ):
        _fail(
            str(artefact_record.get("code") or SR_REFUSED_REBUILD_NOT_RUN),
            f"the artefact state {artefact_state!r} is not a measured "
            "reproducible/not-rebuilt result",
        )

    if artefact_state == ARTEFACT_DIFFERS:
        combination = _DIFFERS_LABELS[signature_state]
        permitted = (
            "a rebuild ran and produced different bytes; no reproducibility "
            "claim is available, and the signature axis does not change that"
        )
    else:
        combination = COMBINATION_LABELS[(signature_state, artefact_state)]
        permitted = _PERMITTED[(signature_state, artefact_state)]

    prohibited = [
        SR_REFUSED_SIGNATURE_AS_ARTEFACT,
        SR_REFUSED_ARTEFACT_AS_SIGNATURE,
        SR_REFUSED_ENVELOPE_DIGEST_AS_BUILD_DIGEST,
    ]
    deterministic = signature_record.get("deterministic")
    randomised = signature_record.get("randomised")
    scheme = signature_record.get("scheme")
    if scheme in SCHEMES:
        deterministic = SCHEMES[scheme].deterministic
        randomised = SCHEMES[scheme].randomised
    if deterministic:
        prohibited.append(SR_REFUSED_DETERMINISTIC_SCHEME_AS_INDEPENDENCE)
    if randomised:
        prohibited.append(SR_REFUSED_NONDETERMINISTIC_AS_FAILURE)
    if signature_record.get("scheme") in SCHEMES:
        prohibited.append(SR_REFUSED_SEED_AS_KEY)
    if artefact_state == ARTEFACT_NOT_REBUILT:
        prohibited.append(
            SR_REFUSED_REPLAY_AS_REPRODUCTION
            if artefact_record.get("code") == SR_REFUSED_REPLAY_AS_REPRODUCTION
            else SR_REFUSED_REBUILD_NOT_RUN
        )
    codes = set(prohibited)
    for record in (signature_record, artefact_record):
        code = record.get("code")
        if isinstance(code, str) and code != CODE_OK:
            codes.add(code)
    return {
        "combination": combination,
        "signature": signature_state,
        "artefact": artefact_state,
        "scheme": scheme,
        "deterministic": deterministic,
        "symmetric": signature_record.get("symmetric"),
        "prohibited": prohibited,
        "codes": sorted(codes),
        "permitted": permitted,
        "signatureCode": signature_record.get("code", CODE_OK),
        "artefactCode": artefact_record.get("code", CODE_OK),
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _print(title: str, document: Mapping[str, Any]) -> None:
    parts = [
        f"{title}:",
        f"code={document.get('code')}",
        f"state={document.get('state')}",
    ]
    for key in (
        "combination",
        "scheme",
        "attempts",
        "subjectName",
        "reproducibilityClaimed",
    ):
        if key in document and document[key] is not None:
            parts.append(f"{key}={document[key]}")
    print(" ".join(parts))


def _command_signature(label: str, attempt_files: Sequence[str]) -> int:
    attempts: list[dict[str, Any]] = []
    schemes: set[str] = set()
    for attempt_file in attempt_files:
        record = _load_json(Path(attempt_file))
        if not isinstance(record, Mapping):
            print(
                f"{SR_REFUSED_ATTEMPT_MALFORMED}: {attempt_file} is not a record",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        attempts.append(dict(record))
        scheme = record.get("scheme")
        if isinstance(scheme, str):
            schemes.add(scheme)
    scheme = next(iter(schemes)) if len(schemes) == 1 else "unrecorded"
    result = signature_evidence(attempts, scheme)
    print(
        f"signature: code={result['code']} state={result['state']} "
        f"envelope={label} scheme={result['scheme']} "
        f"attempts={result['attempts']} "
        f"deterministic={result['deterministic']} "
        f"symmetric={result['symmetric']} "
        f"nonceReused={result['nonceReused']} "
        f"detail={result['detail']}"
    )
    return EXIT_OK if result["code"] == CODE_OK else EXIT_REFUSED


def _command_artefact(subject_file: str, rebuild_file: str) -> int:
    subject = _load_json(Path(subject_file))
    if not isinstance(subject, Mapping):
        print(
            f"{SR_REFUSED_INPUTS_UNSTATED}: {subject_file} is not a subject record",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    rebuild: Any
    if rebuild_file == "-":
        rebuild = None
    else:
        path = Path(rebuild_file)
        rebuild = _load_json(path) if path.is_file() else None
    result = artefact_evidence(subject, rebuild)
    name = subject.get("name") or subject.get("path")
    print(
        f"artefact: code={result['code']} state={result['state']} "
        f"subject={name} reproducibilityClaimed={result['reproducibilityClaimed']} "
        f"detail={result['detail']}"
    )
    return EXIT_OK if result["code"] == CODE_OK else EXIT_REFUSED


def _real_documents() -> tuple[dict[str, Any], dict[str, Any]]:
    signature_path = REPO_ROOT / "evidence" / "a13" / "SIGNATURE.json"
    artefact_path = REPO_ROOT / "evidence" / "a13" / "ARTEFACT.json"
    return _load_json(signature_path), _load_json(artefact_path)


def _command_classify() -> int:
    signature_document, artefact_document = _real_documents()
    signatures = {
        row["name"]: row for row in signature_document.get("signatures", [])
    }
    subjects = {
        row["name"]: row for row in artefact_document.get("subjects", [])
    }
    failures = 0
    for name in sorted(signatures):
        signature = signatures[name]
        artefact = subjects.get(name)
        if artefact is None:
            continue
        result = classify(
            {
                "state": signature["state"],
                "code": signature["code"],
                "scheme": signature["scheme"],
                "deterministic": signature["schemeRecord"]["deterministic"],
                "symmetric": signature["schemeRecord"]["symmetric"],
                "randomised": signature["schemeRecord"]["randomised"],
            },
            {
                "state": artefact["state"],
                "code": artefact["code"],
                "subject": artefact["subject"],
            },
        )
        print(
            f"classify: name={name} combination={result['combination']} "
            f"signature={result['signature']} artefact={result['artefact']} "
            f"prohibited={','.join(result['codes'])}"
        )
    for name in sorted(subjects):
        if name in signatures:
            continue
        artefact = subjects[name]
        print(
            f"classify: combination=UNPAIRED artefact={artefact['state']} "
            f"code={artefact['code']} subject={name} "
            f"prohibited={SR_REFUSED_REBUILD_NOT_RUN}"
        )
    return EXIT_OK if failures == 0 else EXIT_REFUSED


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="reproducibility.py", add_help=True)
    subparsers = parser.add_subparsers(dest="command")
    signature_parser = subparsers.add_parser("signature")
    signature_parser.add_argument("envelope")
    signature_parser.add_argument("attempts", nargs="+")
    artefact_parser = subparsers.add_parser("artefact")
    artefact_parser.add_argument("subject")
    artefact_parser.add_argument("rebuild")
    subparsers.add_parser("classify")
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exit_error:
        if exit_error.code == 0:
            return EXIT_OK
        print(f"{CODE_USAGE}: the command line was not understood", file=sys.stderr)
        return EXIT_USAGE
    try:
        if parsed.command == "signature":
            return _command_signature(parsed.envelope, parsed.attempts)
        if parsed.command == "artefact":
            return _command_artefact(parsed.subject, parsed.rebuild)
        if parsed.command == "classify":
            return _command_classify()
    except Refusal as refusal:
        print(f"{refusal}", file=sys.stderr)
        return EXIT_REFUSED
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"{SR_REFUSED_INPUTS_UNSTATED}: {error}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    print(f"{CODE_USAGE}: no command was given", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
