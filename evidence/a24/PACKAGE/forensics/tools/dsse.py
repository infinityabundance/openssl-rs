#!/usr/bin/env python3
"""dsse.py -- DSSE v1 envelopes with the exact PAE over the received bytes.

Why this tool exists
--------------------
A DSSE (Dead Simple Signing Envelope) v1 envelope is::

    {"payloadType": <string>, "payload": <base64>,
     "signatures": [{"keyid": <string>, "sig": <base64>}]}

and its signature is over a pre-authentication encoding of the payload::

    PAE(type, body) = "DSSEv1" SP decimal(len(type)) SP type SP
                      decimal(len(body)) SP body

where ``SP`` is one 0x20 and every length is the **byte** length in decimal
ASCII with no padding. The concatenation is over the exact bytes.

The rule
--------
Verification is over the bytes that were received. A verifier that parses the
payload into an object and re-encodes it before computing the PAE breaks the
binding: a difference in whitespace, key order, escaping or number form makes a
different byte string, so a "helpful" canonicaliser turns a signed statement into
a different statement than the one that was signed. This module therefore:

  * accepts **received bytes** for verification, never a parsed object;
  * parses the **envelope** only, with duplicate-key detection;
  * base64-decodes the payload strictly (canonical padding and alphabet, no
    trailing data) and uses those decoded bytes as the PAE body;
  * computes the PAE from ``payloadType`` as received and those decoded bytes;
  * never parses the payload before the signature check and never re-encodes it;
  * optionally decodes the payload as an in-toto Statement v1 (A9) *after* the
    signature check, and refuses a valid envelope whose payload is not a
    statement when a statement is required.

What this module does not do
----------------------------
It makes **no trust decision**. Key selection, key distribution, identity,
authorisation, transparency and the root of trust are A12/A14/A16's. The signer
is a caller-supplied callable; the verifier is a caller-supplied callable; the
``keyid`` inside an envelope is an unauthenticated hint and this module never
uses it to choose a key. The deterministic HMAC-SHA256 helper in this file exists
so the command line and the evidence producer have a signer at all: it is
labelled ``test-only``, it is derived from a fixed public seed, and a signature
made with it establishes framing and PAE, never authenticity.

Forward extensions, oversized payloads, signature-count bounds and algorithm
downgrade rules are A11's; independent cryptographic verification is A12's.

Usage
-----
    python3 forensics/tools/dsse.py pae <type> <payload-file>
    python3 forensics/tools/dsse.py sign <statement> <out>
    python3 forensics/tools/dsse.py verify <envelope> [--expected-type TYPE]
                                                  [--require-statement]

Exit status: 0 for success, 1 for a refusal (the stable code is always printed),
2 for a usage error (``DS_USAGE`` is printed).

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = "forensics/tools/dsse.py"

MODEL_ID = "a10/v1"
ENVELOPE_SCHEMA = "openssl-rs/a10/envelopes/1"
CONTROLS_SCHEMA = "openssl-rs/a10/controls/1"

PAE_PREFIX = b"DSSEv1"
PAE_SEPARATOR = b" "
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "DS_OK"
CODE_USAGE = "DS_USAGE"

# ---------------------------------------------------------------------------
# Refusal codes. Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

DS_REFUSED_ENVELOPE_INVALID = "DS_REFUSED_ENVELOPE_INVALID"
DS_REFUSED_DUPLICATE_KEY = "DS_REFUSED_DUPLICATE_KEY"
DS_REFUSED_PAYLOAD_TYPE_MISSING = "DS_REFUSED_PAYLOAD_TYPE_MISSING"
DS_REFUSED_PAYLOAD_TYPE_MISMATCH = "DS_REFUSED_PAYLOAD_TYPE_MISMATCH"
DS_REFUSED_BASE64_NONCANONICAL = "DS_REFUSED_BASE64_NONCANONICAL"
DS_REFUSED_PAYLOAD_ABSENT = "DS_REFUSED_PAYLOAD_ABSENT"
DS_REFUSED_SIGNATURES_ABSENT = "DS_REFUSED_SIGNATURES_ABSENT"
DS_REFUSED_SIGNATURE_INVALID = "DS_REFUSED_SIGNATURE_INVALID"
DS_REFUSED_PAE_RESERIALISED = "DS_REFUSED_PAE_RESERIALISED"
DS_REFUSED_PAE_LENGTH = "DS_REFUSED_PAE_LENGTH"
DS_REFUSED_PAYLOAD_NOT_STATEMENT = "DS_REFUSED_PAYLOAD_NOT_STATEMENT"
DS_REFUSED_TRAILING_BYTES = "DS_REFUSED_TRAILING_BYTES"
DS_REFUSED_OBJECT_SUPPLIED = "DS_REFUSED_OBJECT_SUPPLIED"

REFUSALS: dict[str, dict[str, str]] = {
    DS_REFUSED_ENVELOPE_INVALID: {
        "condition": (
            "the envelope is not a JSON object with exactly payloadType, payload "
            "and signatures, or a field has the wrong JSON type"
        ),
        "prevents": (
            "that an array, a bare payload, an unknown top-level field or a "
            "non-string field is read as a DSSE envelope"
        ),
    },
    DS_REFUSED_DUPLICATE_KEY: {
        "condition": "the envelope's JSON contains a duplicated object key",
        "prevents": (
            "that a second payloadType, payload or sig is silently discarded and a "
            "different field is the one verified"
        ),
    },
    DS_REFUSED_PAYLOAD_TYPE_MISSING: {
        "condition": "the envelope has no payloadType field",
        "prevents": (
            "that a payload is verified with a default or inferred type, so the "
            "signed type boundary is lost"
        ),
    },
    DS_REFUSED_PAYLOAD_TYPE_MISMATCH: {
        "condition": (
            "verification is bound to an expected payload type and the received "
            "payloadType is not it"
        ),
        "prevents": (
            "that a payload signed under one type is verified or read as another "
            "(a generic payload read as a statement, or a statement as a generic "
            "payload)"
        ),
    },
    DS_REFUSED_BASE64_NONCANONICAL: {
        "condition": (
            "the payload or a signature is not canonical standard base64: wrong "
            "alphabet, missing or excess padding, non-zero pad bits, or trailing "
            "data"
        ),
        "prevents": (
            "that two different encodings of the same bytes are both accepted, or "
            "that bytes are recovered from a non-canonical encoding"
        ),
    },
    DS_REFUSED_PAYLOAD_ABSENT: {
        "condition": "the envelope has no payload field",
        "prevents": (
            "that an envelope with no payload is verified against an empty byte "
            "string"
        ),
    },
    DS_REFUSED_SIGNATURES_ABSENT: {
        "condition": "the envelope has no signatures field, or the list is empty",
        "prevents": "that an unsigned payload is read as a signed one",
    },
    DS_REFUSED_SIGNATURE_INVALID: {
        "condition": "no supplied signature verifies over the PAE of the received bytes",
        "prevents": (
            "that a payload whose bytes, type or signature changed is accepted"
        ),
    },
    DS_REFUSED_PAE_RESERIALISED: {
        "condition": (
            "the PAE body is not the decoded payload bytes, or the signature "
            "verifies only over a canonical re-encoding of the payload"
        ),
        "prevents": (
            "that a payload parsed and re-encoded before verification is accepted "
            "as the payload that was signed"
        ),
    },
    DS_REFUSED_PAE_LENGTH: {
        "condition": (
            "a PAE byte string declares a type or body length that does not match "
            "its bytes, or uses a non-canonical decimal"
        ),
        "prevents": (
            "that a PAE with a wrong length prefix is read as the concatenation it "
            "claims to be"
        ),
    },
    DS_REFUSED_PAYLOAD_NOT_STATEMENT: {
        "condition": (
            "a statement is required and the verified payload is not a structurally "
            "valid in-toto Statement v1 (A9)"
        ),
        "prevents": (
            "that a structurally valid envelope over arbitrary bytes is read as an "
            "in-toto attestation"
        ),
    },
    DS_REFUSED_TRAILING_BYTES: {
        "condition": "the envelope bytes carry data after the JSON value",
        "prevents": (
            "that a second document appended to an envelope is ignored while the "
            "first is verified"
        ),
    },
    DS_REFUSED_OBJECT_SUPPLIED: {
        "condition": (
            "verification was given a parsed object or decoded text instead of the "
            "received bytes"
        ),
        "prevents": (
            "that a caller's in-memory representation, which has lost the received "
            "byte identity, is verified as those bytes"
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
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# PAE: the exact pre-authentication encoding.
# ---------------------------------------------------------------------------


def pae(payload_type: str, body: bytes) -> bytes:
    """``DSSEv1`` SP decimal(len(type)) SP type SP decimal(len(body)) SP body.

    The type is encoded as UTF-8 and its length is its UTF-8 byte length, not its
    character count. The body is used exactly as given, with no parsing.
    """
    if not isinstance(payload_type, str):
        raise TypeError("the payload type is a str")
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("the PAE body is bytes")
    type_bytes = payload_type.encode("utf-8")
    body_bytes = bytes(body)
    return b"".join(
        (
            PAE_PREFIX,
            PAE_SEPARATOR,
            str(len(type_bytes)).encode("ascii"),
            PAE_SEPARATOR,
            type_bytes,
            PAE_SEPARATOR,
            str(len(body_bytes)).encode("ascii"),
            PAE_SEPARATOR,
            body_bytes,
        )
    )


def _decimal(raw: bytes, where: str) -> int:
    if not raw:
        _fail(DS_REFUSED_ENVELOPE_INVALID, f"{where}: an empty length field")
    for byte in raw:
        if not 0x30 <= byte <= 0x39:
            _fail(DS_REFUSED_ENVELOPE_INVALID, f"{where}: a non-decimal length field")
    if len(raw) > 1 and raw[:1] == b"0":
        _fail(
            DS_REFUSED_PAE_LENGTH,
            f"{where}: a length with a leading zero is not the decimal this encoding "
            "writes",
        )
    return int(raw)


def parse_pae(pae_bytes: bytes) -> tuple[str, bytes]:
    """Parse a PAE byte string and return ``(payload_type, body)``.

    The parse is strict and complete: the prefix, the separators, the lengths and
    the two fields must consume every byte. A declared length that does not match
    the remaining bytes is ``DS_REFUSED_PAE_LENGTH``; a malformed prefix or digit
    run is ``DS_REFUSED_ENVELOPE_INVALID``. The type must be valid UTF-8.
    """
    raw = bytes(pae_bytes)
    prefix = PAE_PREFIX + PAE_SEPARATOR
    if not raw.startswith(prefix):
        _fail(
            DS_REFUSED_ENVELOPE_INVALID,
            "the PAE does not begin with the DSSEv1 prefix and separator",
        )
    at = len(prefix)
    space = raw.find(PAE_SEPARATOR, at)
    if space < 0:
        _fail(DS_REFUSED_ENVELOPE_INVALID, "the PAE has no separator after the type length")
    type_length = _decimal(raw[at:space], "type length")
    start = space + 1
    if start + type_length > len(raw):
        _fail(
            DS_REFUSED_PAE_LENGTH,
            f"the PAE declares a {type_length}-byte type but fewer bytes remain",
        )
    type_bytes = raw[start : start + type_length]
    cursor = start + type_length
    if raw[cursor : cursor + 1] != PAE_SEPARATOR:
        _fail(DS_REFUSED_PAE_LENGTH, "the PAE type is not followed by a separator")
    cursor += 1
    space = raw.find(PAE_SEPARATOR, cursor)
    if space < 0:
        _fail(DS_REFUSED_ENVELOPE_INVALID, "the PAE has no separator after the body length")
    body_length = _decimal(raw[cursor:space], "body length")
    cursor = space + 1
    if cursor + body_length > len(raw):
        _fail(
            DS_REFUSED_PAE_LENGTH,
            f"the PAE declares a {body_length}-byte body but fewer bytes remain",
        )
    body = raw[cursor : cursor + body_length]
    cursor += body_length
    if cursor != len(raw):
        _fail(
            DS_REFUSED_PAE_LENGTH,
            f"the PAE has {len(raw) - cursor} byte(s) after the declared body",
        )
    try:
        payload_type = type_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(DS_REFUSED_ENVELOPE_INVALID, f"the PAE type is not UTF-8: {error}")
    if pae(payload_type, body) != raw:
        _fail(DS_REFUSED_PAE_LENGTH, "the PAE is not the encoding of its own fields")
    return payload_type, body


def check_pae_body(pae_bytes: bytes, payload_type: str, body: bytes) -> None:
    """Require that a PAE is exactly the encoding of ``(payload_type, body)``.

    This is the received-bytes rule made structural. If a verifier ever computed
    the PAE over a parsed and re-encoded payload, the body inside the PAE would
    not be the decoded bytes received; that is refused rather than accepted.
    """
    parsed_type, parsed_body = parse_pae(pae_bytes)
    if parsed_type != payload_type or parsed_body != bytes(body):
        _fail(
            DS_REFUSED_PAE_RESERIALISED,
            "the PAE body is not the decoded payload bytes: the payload was parsed "
            "and re-encoded before verification",
        )


# ---------------------------------------------------------------------------
# Strict base64. Two encodings of one byte string must not both be accepted.
# ---------------------------------------------------------------------------

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def strict_b64decode(text: Any, where: str) -> bytes:
    """Decode canonical standard base64 with padding; refuse everything else."""
    if not isinstance(text, str):
        _fail(DS_REFUSED_BASE64_NONCANONICAL, f"{where}: a base64 value is a string")
    if len(text) % 4 != 0:
        _fail(
            DS_REFUSED_BASE64_NONCANONICAL,
            f"{where}: the length is not a multiple of four, so the padding is not "
            "canonical",
        )
    unpadded = text.rstrip("=")
    padding = len(text) - len(unpadded)
    if padding > 2:
        _fail(DS_REFUSED_BASE64_NONCANONICAL, f"{where}: more than two padding characters")
    if any(character not in _B64_ALPHABET for character in unpadded):
        _fail(
            DS_REFUSED_BASE64_NONCANONICAL,
            f"{where}: a character outside the standard base64 alphabet",
        )
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as error:
        _fail(DS_REFUSED_BASE64_NONCANONICAL, f"{where}: {error}")
    if base64.b64encode(raw).decode("ascii") != text:
        _fail(
            DS_REFUSED_BASE64_NONCANONICAL,
            f"{where}: re-encoding the decoded bytes does not reproduce the value "
            "(non-zero pad bits or non-canonical padding)",
        )
    return raw


def strict_b64encode(raw: bytes) -> str:
    return base64.b64encode(bytes(raw)).decode("ascii")


# ---------------------------------------------------------------------------
# The envelope. Signing is a caller-supplied function; no key is selected here.
# ---------------------------------------------------------------------------


def _require_payload_type(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _fail(DS_REFUSED_ENVELOPE_INVALID, "payloadType is a non-empty string")
    return value


def envelope(
    payload_type: str,
    payload_bytes: bytes,
    signer: Callable[[bytes], tuple[str, bytes]],
) -> dict[str, Any]:
    """Build an envelope over the exact ``payload_bytes`` with one signature.

    ``signer`` receives the PAE bytes and returns ``(keyid, signature_bytes)``.
    This module does not choose, distribute or trust a key; ``keyid`` is carried
    as an unauthenticated hint only.
    """
    _require_payload_type(payload_type)
    document: dict[str, Any] = {
        "payloadType": payload_type,
        "payload": strict_b64encode(bytes(payload_bytes)),
        "signatures": [],
    }
    return sign(document, signer)


def sign(
    document: Mapping[str, Any],
    signer: Callable[[bytes], tuple[str, bytes]],
) -> dict[str, Any]:
    """Append a signature over the PAE of an envelope's payload.

    The payload is base64-decoded strictly and the PAE is computed over those
    bytes; nothing is re-serialised. A new document is returned; the caller's is
    not mutated.
    """
    if not callable(signer):
        raise TypeError("the signer is a callable bytes -> (keyid, signature_bytes)")
    if not isinstance(document, Mapping):
        _fail(DS_REFUSED_ENVELOPE_INVALID, "an envelope is a JSON object")
    payload_type = document.get("payloadType")
    if "payloadType" not in document:
        _fail(DS_REFUSED_PAYLOAD_TYPE_MISSING, "the envelope has no payloadType")
    _require_payload_type(payload_type)
    if "payload" not in document:
        _fail(DS_REFUSED_PAYLOAD_ABSENT, "the envelope has no payload")
    body = strict_b64decode(document["payload"], "payload")
    signatures = document.get("signatures", [])
    if not isinstance(signatures, list):
        _fail(DS_REFUSED_SIGNATURES_ABSENT, "signatures is a list")
    pae_bytes = pae(payload_type, body)
    keyid, signature = signer(pae_bytes)
    if not isinstance(keyid, str):
        raise TypeError("the signer's keyid is a str")
    if not isinstance(signature, (bytes, bytearray, memoryview)):
        raise TypeError("the signer's signature is bytes")
    produced = dict(document)
    produced["signatures"] = list(signatures) + [
        {"keyid": keyid, "sig": strict_b64encode(bytes(signature))}
    ]
    return produced


def encode_envelope(document: Mapping[str, Any]) -> bytes:
    """The canonical bytes this tool writes for an envelope.

    This canonical form is for producing reproducible evidence only. Verification
    never re-encodes an envelope and never re-encodes a payload.
    """
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Verification over the received bytes.
# ---------------------------------------------------------------------------


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            _fail(
                DS_REFUSED_DUPLICATE_KEY,
                f"the envelope repeats the key {key!r}; the later value would "
                "silently replace the verified one",
            )
        seen[key] = value
    return seen


def _parse_envelope(envelope_bytes: Any) -> dict[str, Any]:
    if isinstance(envelope_bytes, (dict, list, str)):
        _fail(
            DS_REFUSED_OBJECT_SUPPLIED,
            f"verification takes the received bytes, not {type(envelope_bytes).__name__}: "
            "a parsed or decoded value has lost the received byte identity",
        )
    if not isinstance(envelope_bytes, (bytes, bytearray, memoryview)):
        _fail(
            DS_REFUSED_OBJECT_SUPPLIED,
            f"verification takes bytes, not {type(envelope_bytes).__name__}",
        )
    raw = bytes(envelope_bytes)
    if not raw:
        _fail(DS_REFUSED_ENVELOPE_INVALID, "the envelope is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        _fail(DS_REFUSED_ENVELOPE_INVALID, f"the envelope is not UTF-8 JSON: {error}")
    decoder = json.JSONDecoder(object_pairs_hook=_pairs_without_duplicates)
    stripped = text.lstrip(" \t\r\n")
    try:
        document, end = decoder.raw_decode(stripped)
    except json.JSONDecodeError as error:
        _fail(DS_REFUSED_ENVELOPE_INVALID, f"the envelope is not JSON: {error}")
    if stripped[end:].strip(" \t\r\n"):
        _fail(
            DS_REFUSED_TRAILING_BYTES,
            f"the envelope carries {len(stripped) - end} character(s) after the JSON "
            "value",
        )
    if not isinstance(document, dict):
        _fail(DS_REFUSED_ENVELOPE_INVALID, "the envelope is a JSON object")
    return document


def _signatures(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    if "signatures" not in document:
        _fail(DS_REFUSED_SIGNATURES_ABSENT, "the envelope has no signatures field")
    entries = document["signatures"]
    if not isinstance(entries, list) or not entries:
        _fail(DS_REFUSED_SIGNATURES_ABSENT, "signatures is a non-empty list")
    parsed: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        where = f"signatures[{index}]"
        if not isinstance(entry, dict):
            _fail(DS_REFUSED_ENVELOPE_INVALID, f"{where}: a signature is an object")
        if set(entry) != {"keyid", "sig"}:
            _fail(
                DS_REFUSED_ENVELOPE_INVALID,
                f"{where}: a signature has exactly keyid and sig, not "
                f"{sorted(map(str, entry))}",
            )
        if not isinstance(entry["keyid"], str):
            _fail(DS_REFUSED_ENVELOPE_INVALID, f"{where}: keyid is a string")
        parsed.append(
            {
                "keyid": entry["keyid"],
                "sig": strict_b64decode(entry["sig"], f"{where}.sig"),
            }
        )
    return parsed


def _canonical_payload(body: bytes) -> bytes | None:
    """A canonical re-encoding of the payload, used only to *name* a refusal.

    It is never a verification input: a signature that verifies over this form
    and not over the received bytes is refused, never accepted. Duplicate keys or
    non-finite numbers make it unavailable.
    """
    try:
        value = json.loads(body.decode("utf-8"))
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (UnicodeDecodeError, ValueError, TypeError):
        return None


def _accepts(
    signatures: list[dict[str, Any]],
    pae_bytes: bytes,
    verifier: Callable[[str, bytes, bytes], bool],
) -> str | None:
    for entry in signatures:
        if verifier(entry["keyid"], pae_bytes, entry["sig"]):
            return entry["keyid"]
    return None


def verify_pae(
    envelope_bytes: Any,
    verifier: Callable[[str, bytes, bytes], bool],
    *,
    expected_payload_type: str | None = None,
    require_statement: bool = False,
    classify_reserialisation: bool = True,
) -> dict[str, Any]:
    """Verify an envelope against its PAE over the exact received bytes.

    ``verifier(keyid, pae_bytes, signature_bytes) -> bool`` is the caller's trust
    decision; ``keyid`` is an unauthenticated hint and this module does not use it
    to select a key. ``expected_payload_type`` binds verification to the type the
    payload must have been signed under. ``require_statement`` additionally
    decodes the *verified* payload as an in-toto Statement v1 (A9).

    The payload is never parsed before the signature check. It is parsed after it
    only when ``require_statement`` asks, and the bytes returned are always the
    received bytes, never a re-encoding.
    """
    if not callable(verifier):
        raise TypeError("the verifier is a callable (keyid, pae, sig) -> bool")
    document = _parse_envelope(envelope_bytes)
    if "payloadType" not in document:
        _fail(DS_REFUSED_PAYLOAD_TYPE_MISSING, "the envelope has no payloadType")
    if "payload" not in document:
        _fail(DS_REFUSED_PAYLOAD_ABSENT, "the envelope has no payload")
    if "signatures" not in document:
        _fail(DS_REFUSED_SIGNATURES_ABSENT, "the envelope has no signatures field")
    if set(document) != {"payloadType", "payload", "signatures"}:
        _fail(
            DS_REFUSED_ENVELOPE_INVALID,
            "the envelope has exactly payloadType, payload and signatures; forward "
            f"extensions are A11's, not read here: {sorted(map(str, document))}",
        )
    payload_type = document["payloadType"]
    if not isinstance(payload_type, str):
        _fail(DS_REFUSED_ENVELOPE_INVALID, "payloadType is a string")
    if not isinstance(document["payload"], str):
        _fail(DS_REFUSED_ENVELOPE_INVALID, "payload is a base64 string")
    body = strict_b64decode(document["payload"], "payload")
    signatures = _signatures(document)
    if expected_payload_type is not None and payload_type != expected_payload_type:
        _fail(
            DS_REFUSED_PAYLOAD_TYPE_MISMATCH,
            f"the envelope declares {payload_type!r}, but verification is bound to "
            f"{expected_payload_type!r}",
        )
    pae_bytes = pae(payload_type, body)
    check_pae_body(pae_bytes, payload_type, body)
    keyid = _accepts(signatures, pae_bytes, verifier)
    if keyid is None and classify_reserialisation:
        canonical = _canonical_payload(body)
        if canonical is not None and canonical != body:
            if _accepts(signatures, pae(payload_type, canonical), verifier):
                _fail(
                    DS_REFUSED_PAE_RESERIALISED,
                    "a signature verifies only over a canonical re-encoding of the "
                    "payload, not over the received bytes: the payload was "
                    "re-serialised before verification",
                )
    if keyid is None:
        _fail(
            DS_REFUSED_SIGNATURE_INVALID,
            "no supplied signature verifies over the PAE of the received bytes",
        )
    statement: dict[str, Any] | None = None
    if require_statement:
        statement = _require_statement(body)
    return {
        "payloadType": payload_type,
        "payload": body,
        "keyid": keyid,
        "paeSha256": sha256_bytes(pae_bytes),
        "envelopeSha256": sha256_bytes(bytes(envelope_bytes)),
        "statement": statement,
    }


def verify_received_bytes(
    received_bytes: Any,
    verifier: Callable[[str, bytes, bytes], bool],
    **options: Any,
) -> dict[str, Any]:
    """The received-bytes entry point for envelope verification.

    Named for the rule it enforces: the argument is the exact byte string that
    arrived, and a parsed object, a list or decoded text is refused. It is a thin
    wrapper over `verify_pae` so there is one implementation of the rule.
    """
    return verify_pae(received_bytes, verifier, **options)


def _require_statement(body: bytes) -> dict[str, Any]:
    """Decode a verified payload as an A9 Statement v1; a non-statement is refused.

    A9's `decode` with ``repo_root=None`` checks the statement's structure and
    canonical form without re-hashing subjects, because this module makes no claim
    about the subject files. The subject digest and record bindings are A9's.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import intoto  # noqa: PLC0415 - imported lazily so DSSE framing has no A9 dependency

    try:
        return intoto.decode(body, repo_root=None)
    except intoto.Refusal as refusal:
        _fail(
            DS_REFUSED_PAYLOAD_NOT_STATEMENT,
            f"the verified payload is not an in-toto Statement v1 ({refusal.code}): "
            f"{refusal.message}",
        )
    raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Test-only signer. A fixed public seed; not a trust root; selects no key.
# ---------------------------------------------------------------------------

TEST_ONLY_SEED = b"openssl-rs/a10/test-only-hmac-sha256-seed/v1"
TEST_ONLY_SIGNER_LABEL = "test-only HMAC-SHA256 (fixed public seed; not a trust root)"


def test_only_key(seed: bytes = TEST_ONLY_SEED) -> bytes:
    """The deterministic key the test-only signer uses. Not a secret."""
    return hashlib.sha256(b"a10/test-only/key/" + bytes(seed)).digest()


def test_only_keyid(seed: bytes = TEST_ONLY_SEED) -> str:
    return "test-only:hmac-sha256:" + sha256_bytes(test_only_key(seed))[:16]


def test_only_signer(
    seed: bytes = TEST_ONLY_SEED,
) -> Callable[[bytes], tuple[str, bytes]]:
    key = test_only_key(seed)
    keyid = test_only_keyid(seed)

    def signer(pae_bytes: bytes) -> tuple[str, bytes]:
        return keyid, hmac.new(key, pae_bytes, hashlib.sha256).digest()

    return signer


def test_only_verifier(
    seed: bytes = TEST_ONLY_SEED,
) -> Callable[[str, bytes, bytes], bool]:
    """Verify with the test key, ignoring ``keyid``. No key selection happens."""
    key = test_only_key(seed)

    def verifier(keyid: str, pae_bytes: bytes, signature: bytes) -> bool:
        expected = hmac.new(key, pae_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    return verifier


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _command_pae(payload_type: str, payload_file: str) -> int:
    raw = Path(payload_file).read_bytes()
    encoded = pae(payload_type, raw)
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    print(
        f"pae: code={CODE_OK} payloadType={payload_type!r} "
        f"typeLength={len(payload_type.encode('utf-8'))} bodyLength={len(raw)} "
        f"paeSha256={sha256_bytes(encoded)}",
        file=sys.stderr,
    )
    return EXIT_OK


def _command_sign(statement: str, out: str) -> int:
    seed = TEST_ONLY_SEED
    keyid = test_only_keyid(seed)
    payload_bytes = Path(statement).read_bytes()
    document = envelope(
        IN_TOTO_PAYLOAD_TYPE, payload_bytes, test_only_signer(seed)
    )
    Path(out).write_bytes(encode_envelope(document))
    print(
        f"sign: code={CODE_OK} payloadType={IN_TOTO_PAYLOAD_TYPE} "
        f"keyid={keyid} payloadSha256={sha256_bytes(payload_bytes)} out={out}",
        file=sys.stdout,
    )
    return EXIT_OK


def _command_verify(
    envelope_file: str, expected: str | None, require_statement: bool
) -> int:
    raw = Path(envelope_file).read_bytes()
    report = verify_pae(
        raw,
        test_only_verifier(),
        expected_payload_type=expected,
        require_statement=require_statement,
    )
    print(
        f"verify: code={CODE_OK} payloadType={report['payloadType']} "
        f"keyid={report['keyid']} payloadSha256={sha256_bytes(report['payload'])} "
        f"paeSha256={report['paeSha256']} envelopeSha256={report['envelopeSha256']}",
        file=sys.stdout,
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="dsse.py", add_help=True)
    subparsers = parser.add_subparsers(dest="command")
    pae_parser = subparsers.add_parser("pae")
    pae_parser.add_argument("payload_type")
    pae_parser.add_argument("payload_file")
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("statement")
    sign_parser.add_argument("out")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("envelope")
    verify_parser.add_argument("--expected-type", default=None)
    verify_parser.add_argument("--require-statement", action="store_true")
    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exit_error:
        if exit_error.code == 0:
            return EXIT_OK
        print(f"{CODE_USAGE}: the command line was not understood", file=sys.stderr)
        return EXIT_USAGE
    try:
        if parsed.command == "pae":
            return _command_pae(parsed.payload_type, parsed.payload_file)
        if parsed.command == "sign":
            return _command_sign(parsed.statement, parsed.out)
        if parsed.command == "verify":
            return _command_verify(
                parsed.envelope, parsed.expected_type, parsed.require_statement
            )
    except Refusal as refusal:
        print(f"{refusal}", file=sys.stderr)
        return EXIT_REFUSED
    except OSError as error:
        print(
            f"{DS_REFUSED_ENVELOPE_INVALID}: {error}",
            file=sys.stderr,
        )
        return EXIT_REFUSED
    print(f"{CODE_USAGE}: no command was given", file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
