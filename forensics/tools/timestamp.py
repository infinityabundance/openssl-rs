#!/usr/bin/env python3
"""timestamp.py -- an offline RFC 3161 timestamp verifier and the nine-times model.

Two claims, never one
---------------------
A timestamp token carries a *message imprint*: a digest of some artefact.  That a
token's imprint equals an artefact's digest is checkable **offline** with nothing
but a hash.  That a *trusted authority asserted a time* additionally requires the
token signature, a TSA certificate chain, the ``id-kp-timeStamping`` extended key
usage, and a root of trust that the verifier admits.  This venue has no TSA, no
certificate, no root and no network, so the strongest outcome any real artefact
here can reach is ``TIMESTAMP_IMPRINT_VERIFIED_UNTRUSTED``.  When a caller supplies
a certificate and a verification function the signature and EKU are checked and the
best outcome is ``TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED``.  It is never
``TIMESTAMP_TRUSTED``: this module has no admitted trust root, and a caller-supplied
root is the caller's assertion, not an admission.

That distinction is why ``TIMESTAMP_TRUSTED`` exists as a named outcome but is
unreachable: ``verify_token`` asserts it was not produced.  A fixture token is not
an authority even when it verifies.

What is implemented, and from what
----------------------------------
The parser is written from RFC 3161 and the CMS structures it imports, with a
strict DER reader written for this purpose:

    TimeStampToken ::= ContentInfo
      ContentInfo ::= SEQUENCE { contentType id-signedData,
                                 content [0] EXPLICIT SignedData }
      SignedData  ::= SEQUENCE { version, digestAlgorithms SET,
                                 encapContentInfo, certificates [0] OPTIONAL,
                                 crls [1] OPTIONAL, signerInfos SET }
      EncapsulatedContentInfo ::= SEQUENCE { eContentType id-ct-TSTInfo,
                                             eContent [0] EXPLICIT OCTET STRING }
      TSTInfo ::= SEQUENCE {
          version INTEGER, policy TSAPolicyId,
          messageImprint MessageImprint, serialNumber INTEGER,
          genTime GeneralizedTime, accuracy Accuracy OPTIONAL,
          ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
          tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
      MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
                                    hashedMessage OCTET STRING }
      Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL,
                              millis [0] INTEGER (1..999) OPTIONAL,
                              micros [1] INTEGER (1..999) OPTIONAL }

The DER reader refuses indefinite lengths, non-minimal lengths and integers,
high-tag-number form, unconsumed children and trailing bytes.  That strictness is
the point: a lenient reader accepts a token two readers disagree about.

The nine times
--------------
RFC 3161 supplies one time (``genTime``).  §B.9 of
``docs/ETP-ADDENDUM-B.md`` requires **nine separate times, never conflated**:
source creation, experimental execution, evidence production, statement
authentication, trusted timestamping, transparency inclusion, witness observation,
release promotion, and subsequent correction or revocation.  This module models
them as nine slots, each with a value, a source, a recorder, an accuracy and an
``established`` state, and refuses a record that is collapsed, unsourced, or
ordered inconsistently.  A single ``timestamp`` field cannot represent them.

No network
----------
The module opens no socket and invokes no external program.  It imports no
``socket``, ``subprocess``, ``urllib`` or ``http`` module, and contains no
invocation of ``openssl``, ``tsget`` or ``curl``.  ``test_timestamp.py`` checks
both the source and the loaded modules.  There is no live-service path; the
``TS_REFUSED_LIVE_SERVICE`` code exists because a token that asserts a live-service
verification is refused rather than believed.

Control fixtures
----------------
``control_token``, ``control_certificate`` and ``control_root`` build deterministic
DER fixtures for the refusal controls.  They are **control-only**: the signature
is HMAC-SHA256 under a fixed public test seed (OID ``hmacWithSHA256``), not an
X.509 signature; the certificate is structurally parseable but carries no valid
CA signature; the policy OID is fixture-local.  They exist to show the verifier
refuses a malformed, wrong or untrusted token -- never to supply a token that the
evidence could mistake for an authority's.

Usage
-----
    python3 forensics/tools/timestamp.py times [--file evidence/b2/TIMES.json]
    python3 forensics/tools/timestamp.py verify --artifact <path> [--token <path>]
        [--algorithm sha256] [--certificate <der>] [--root <der>] [--require-root]
        [--expected-nonce N] [--control-fixture VARIANT]
    python3 forensics/tools/timestamp.py scan [--root .]

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

TOOL_PATH = "forensics/tools/timestamp.py"
MODEL_ID = "b2/timestamp/1"
SCHEMA_TIMES = "openssl-rs/b2/times/1"
SCHEMA_TOKENS = "openssl-rs/b2/tokens/1"
SCHEMA_VERIFICATION = "openssl-rs/b2/verification/1"
SCHEMA_CONTROLS = "openssl-rs/b2/controls/1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2

CODE_OK = "TS_OK"
CODE_USAGE = "TS_REFUSED_USAGE"
CODE_IO = "TS_REFUSED_IO"
CODE_NO_TOKEN = "TS_NO_TOKEN"

# --- outcome names ---------------------------------------------------------
OUTCOME_NO_TOKEN = "TIMESTAMP_NO_TOKEN"
OUTCOME_IMPRINT_VERIFIED_UNTRUSTED = "TIMESTAMP_IMPRINT_VERIFIED_UNTRUSTED"
OUTCOME_SIGNATURE_VERIFIED_UNTRUSTED = "TIMESTAMP_SIGNATURE_VERIFIED_UNTRUSTED"
# Defined so that "never TRUSTED" is a testable statement rather than an omission.
# No code path in this module produces it.
OUTCOME_TRUSTED = "TIMESTAMP_TRUSTED"
OUTCOME_REFUSED = "TIMESTAMP_REFUSED"

# --- refusal codes ---------------------------------------------------------
TS_REFUSED_DER = "TS_REFUSED_DER"
TS_REFUSED_VERSION = "TS_REFUSED_VERSION"
TS_REFUSED_IMPRINT = "TS_REFUSED_IMPRINT"
TS_REFUSED_ALGORITHM = "TS_REFUSED_ALGORITHM"
TS_REFUSED_GEN_TIME = "TS_REFUSED_GEN_TIME"
TS_REFUSED_EKU = "TS_REFUSED_EKU"
TS_REFUSED_NONCE = "TS_REFUSED_NONCE"
TS_REFUSED_SIGNATURE = "TS_REFUSED_SIGNATURE"
TS_REFUSED_ROOT = "TS_REFUSED_ROOT"
TS_REFUSED_LIVE_SERVICE = "TS_REFUSED_LIVE_SERVICE"
TS_REFUSED_TIME_COLLAPSED = "TS_REFUSED_TIME_COLLAPSED"
TS_REFUSED_TIME_UNSOURCED = "TS_REFUSED_TIME_UNSOURCED"
TS_REFUSED_ORDER = "TS_REFUSED_ORDER"
TS_REFUSED_ACCURACY = "TS_REFUSED_ACCURACY"
TS_REFUSED_TIME_MODEL = "TS_REFUSED_TIME_MODEL"

REFUSALS: dict[str, dict[str, str]] = {
    TS_REFUSED_DER: {
        "condition": (
            "the token is not one strictly encoded DER value: an indefinite or "
            "non-minimal length, a high-tag-number form, a non-minimal INTEGER, an "
            "unconsumed child, a missing signed attribute, or trailing bytes"
        ),
        "prevents": (
            "that two readers disagree about the bytes a token contains; a lenient "
            "reader accepts what the signer did not encode"
        ),
    },
    TS_REFUSED_VERSION: {
        "condition": (
            "the TSTInfo version is not 1, or the CMS SignedData version is not 3"
        ),
        "prevents": (
            "that a token encoded to a different structure is read as an RFC 3161 v1 token"
        ),
    },
    TS_REFUSED_IMPRINT: {
        "condition": (
            "the messageImprint digest is not the artifact's digest under the named "
            "algorithm, or hashedMessage is not the algorithm's digest length"
        ),
        "prevents": (
            "that a token for another artefact is reported as a timestamp of this one"
        ),
    },
    TS_REFUSED_ALGORITHM: {
        "condition": (
            "the messageImprint algorithm is not the algorithm the caller declared, "
            "is unknown, or the signer digest algorithm is unknown"
        ),
        "prevents": (
            "that a token hashed with one algorithm is verified under another"
        ),
    },
    TS_REFUSED_GEN_TIME: {
        "condition": (
            "genTime is absent, is not GeneralizedTime UTC with a trailing Z, or is "
            "not a valid calendar instant"
        ),
        "prevents": (
            "that an absent or malformed time is read as the authority's asserted time"
        ),
    },
    TS_REFUSED_EKU: {
        "condition": (
            "a caller-supplied certificate lacks the extended key usage "
            "id-kp-timeStamping (1.3.6.1.5.5.7.3.8)"
        ),
        "prevents": (
            "that a certificate not authorised for timestamping is accepted as a TSA certificate"
        ),
    },
    TS_REFUSED_NONCE: {
        "condition": (
            "the caller expected a nonce and the token carries none, or carries a "
            "different nonce"
        ),
        "prevents": (
            "that a replayed or unrelated token answers a request whose nonce it does not carry"
        ),
    },
    TS_REFUSED_SIGNATURE: {
        "condition": (
            "the caller-supplied verification function rejects the token's signature, "
            "or the message-digest signed attribute disagrees with the eContent"
        ),
        "prevents": (
            "that an unsigned or altered TSTInfo is reported as signed by the certificate"
        ),
    },
    TS_REFUSED_ROOT: {
        "condition": (
            "the caller required an admitted root and supplied none, the supplied root "
            "is not self-issued, the leaf issuer does not match the root subject, or a "
            "supplied chain-verification function rejects the chain"
        ),
        "prevents": (
            "that a token is reported under a root it does not chain to"
        ),
    },
    TS_REFUSED_LIVE_SERVICE: {
        "condition": (
            "the token asserts that verification requires the live timestamping service, "
            "or the caller asks for a live-service check"
        ),
        "prevents": (
            "a claim of online verification in a venue that opens no socket; no offline "
            "evidence can establish a live service"
        ),
    },
    TS_REFUSED_TIME_COLLAPSED: {
        "condition": (
            "two of the nine §B.9 slots carry the same value from the same source and "
            "recorder, i.e. one time was copied into another slot"
        ),
        "prevents": (
            "that distinct events are reported as one instant because a record collapsed them"
        ),
    },
    TS_REFUSED_TIME_UNSOURCED: {
        "condition": (
            "a slot has a value but no tracked source, names a bare clock read, or "
            "infers experimental execution from a later timestamp"
        ),
        "prevents": (
            "that an unsourced or inferred instant is reported as a recorded time"
        ),
    },
    TS_REFUSED_ORDER: {
        "condition": (
            "a later slot's value precedes an earlier slot's value in the declared order "
            "and no explanation is recorded for the inversion"
        ),
        "prevents": (
            "that a backdated submission is presented as a normal chronological record"
        ),
    },
    TS_REFUSED_ACCURACY: {
        "condition": (
            "an accuracy component is out of range (millis or micros not in 1..999, "
            "seconds negative), or a nine-times slot has an unknown accuracy token"
        ),
        "prevents": (
            "that an impossible accuracy is read as the precision of an asserted time"
        ),
    },
    TS_REFUSED_TIME_MODEL: {
        "condition": (
            "the nine-times record does not have exactly the nine §B.9 slots, in "
            "order, with their declared kinds and clauses"
        ),
        "prevents": (
            "that a record with a missing, extra, renamed or kind-changed slot is read "
            "as the nine-times model"
        ),
    },
}

REFUSAL_CODES = (
    TS_REFUSED_DER,
    TS_REFUSED_VERSION,
    TS_REFUSED_IMPRINT,
    TS_REFUSED_ALGORITHM,
    TS_REFUSED_GEN_TIME,
    TS_REFUSED_EKU,
    TS_REFUSED_NONCE,
    TS_REFUSED_SIGNATURE,
    TS_REFUSED_ROOT,
    TS_REFUSED_LIVE_SERVICE,
    TS_REFUSED_TIME_COLLAPSED,
    TS_REFUSED_TIME_UNSOURCED,
    TS_REFUSED_ORDER,
    TS_REFUSED_ACCURACY,
    TS_REFUSED_TIME_MODEL,
)

# --- OIDs ------------------------------------------------------------------
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_EKU = "2.5.29.37"
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_HMAC_SHA256 = "1.2.840.113549.2.9"
OID_RSA = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_COMMON_NAME = "2.5.4.3"

ALGORITHMS: dict[str, str] = {
    "sha1": OID_SHA1,
    "sha256": OID_SHA256,
    "sha384": OID_SHA384,
    "sha512": OID_SHA512,
}
OID_ALGORITHMS = {oid: name for name, oid in ALGORITHMS.items()}
DIGEST_SIZES = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

# Fixture-local policy OIDs.  They are not assigned to any TSA; the second one
# exists only so a control can assert a live-service verification.
POLICY_FIXTURE = "1.2.3.4.5.6.7.8.1"
POLICY_LIVE_SERVICE = "1.2.3.4.5.6.7.8.2"

CONTROL_SEED = b"openssl-rs/b2/control-tsa/hmac-sha256/v1"
CONTROL_LEAF_CN = "control fixture TSA"
CONTROL_ROOT_CN = "control fixture root"
CONTROL_GEN_TIME = "20261124000000Z"
MAX_TOKEN_BYTES = 1 << 20


# ---------------------------------------------------------------------------
# Strict DER
# ---------------------------------------------------------------------------
class Refusal(Exception):
    """A refusal with a stable code and, where known, the axis results."""

    def __init__(self, code: str, message: str, axes: Mapping[str, str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.axes = dict(axes or {})


@dataclass(frozen=True)
class TLV:
    data: bytes
    tag: int
    start: int
    content_start: int
    end: int

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def content(self) -> bytes:
        return self.data[self.content_start:self.end]

    @property
    def full(self) -> bytes:
        return self.data[self.start:self.end]


def _refuse(message: str, code: str = TS_REFUSED_DER) -> None:
    raise Refusal(code, message)


def _read_length(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end:
        _refuse("truncated DER length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        _refuse("indefinite length is not DER")
    count = first & 0x7F
    if count > 4:
        _refuse("DER length uses more than four octets")
    if pos + count > end:
        _refuse("truncated DER long-form length")
    raw = data[pos:pos + count]
    if raw[0] == 0:
        _refuse("leading zero in DER length")
    length = int.from_bytes(raw, "big")
    if length < 0x80:
        _refuse("long-form length for a short value")
    return length, pos + count


def _read_tlv(data: bytes, pos: int, end: int) -> TLV:
    if pos >= end:
        _refuse("truncated DER value")
    start = pos
    tag = data[pos]
    pos += 1
    if tag & 0x1F == 0x1F:
        _refuse("high-tag-number form is not accepted")
    length, pos = _read_length(data, pos, end)
    content_end = pos + length
    if content_end > end:
        _refuse("DER value extends past its container")
    return TLV(data, tag, start, pos, content_end)


def _single(data: bytes, where: str) -> TLV:
    value = _read_tlv(data, 0, len(data))
    if value.end != len(data):
        _refuse(f"{where}: {len(data) - value.end} trailing byte(s)")
    return value


def _children(data: bytes, value: TLV) -> list[TLV]:
    result: list[TLV] = []
    pos = value.content_start
    while pos < value.end:
        child = _read_tlv(data, pos, value.end)
        result.append(child)
        pos = child.end
    return result


def _expect(value: TLV, tag: int, where: str) -> None:
    if value.tag != tag:
        _refuse(f"{where}: expected tag 0x{tag:02x}, found 0x{value.tag:02x}")


def _integer_content(content: bytes, where: str, *, nonnegative: bool = True) -> int:
    if not content:
        _refuse(f"{where}: empty INTEGER")
    if content[0] & 0x80:
        if nonnegative:
            _refuse(f"{where}: negative INTEGER where a non-negative value is required")
        number = int.from_bytes(content, "big", signed=True)
    else:
        number = int.from_bytes(content, "big")
    if len(content) > 1:
        if content[0] == 0x00 and content[1] & 0x80 == 0:
            _refuse(f"{where}: non-minimal INTEGER (redundant 0x00)")
        if content[0] == 0xFF and content[1] & 0x80:
            _refuse(f"{where}: non-minimal INTEGER (redundant 0xff)")
    return number


def _integer(data: bytes, value: TLV, where: str, *, nonnegative: bool = True) -> int:
    _expect(value, 0x02, where)
    return _integer_content(value.content, where, nonnegative=nonnegative)


def _oid(data: bytes, value: TLV, where: str) -> str:
    _expect(value, 0x06, where)
    content = value.content
    if not content:
        _refuse(f"{where}: empty OBJECT IDENTIFIER")
    first = content[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    number = 0
    fresh = True
    for byte in content[1:]:
        if fresh and byte == 0x80:
            _refuse(f"{where}: non-minimal OBJECT IDENTIFIER component")
        number = (number << 7) | (byte & 0x7F)
        fresh = bool(byte & 0x80) is False
        if fresh:
            arcs.append(number)
            number = 0
    if not fresh:
        _refuse(f"{where}: truncated OBJECT IDENTIFIER component")
    if len(arcs) < 2:
        _refuse(f"{where}: OBJECT IDENTIFIER has fewer than two arcs")
    return ".".join(str(arc) for arc in arcs)


def _octets(value: TLV, where: str) -> bytes:
    _expect(value, 0x04, where)
    return value.content


def _parse_algid(data: bytes, value: TLV, where: str) -> tuple[str, TLV | None]:
    _expect(value, 0x30, where)
    parts = _children(data, value)
    if not 1 <= len(parts) <= 2:
        _refuse(f"{where}: AlgorithmIdentifier has {len(parts)} elements")
    oid = _oid(data, parts[0], where)
    return oid, (parts[1] if len(parts) == 2 else None)


# ---------------------------------------------------------------------------
# TSTInfo
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Accuracy:
    seconds: int | None
    millis: int | None
    micros: int | None

    @property
    def text(self) -> str:
        parts = []
        if self.seconds is not None:
            parts.append(f"seconds={self.seconds}")
        if self.millis is not None:
            parts.append(f"millis={self.millis}")
        if self.micros is not None:
            parts.append(f"micros={self.micros}")
        return ",".join(parts) if parts else "unspecified"


@dataclass(frozen=True)
class TSTInfo:
    version: int
    policy: str
    algorithm_oid: str
    algorithm: str | None
    hashed_message: bytes
    serial: int
    gen_time: str
    gen_time_utc: datetime | None
    accuracy: Accuracy | None
    ordering: bool
    nonce: int | None
    tsa_present: bool
    extensions_present: bool


_GENERALIZED = re.compile(
    r"^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})"
    r"(?P<minute>\d{2})(?P<second>\d{2})(?P<fraction>\.\d+)?Z$"
)


def _generalized_time(value: TLV, where: str) -> tuple[str, datetime | None]:
    _expect(value, 0x18, where)
    try:
        text = value.content.decode("ascii")
    except UnicodeDecodeError:
        _refuse(f"{where}: genTime is not ASCII", TS_REFUSED_GEN_TIME)
    match = _GENERALIZED.match(text)
    if match is None:
        _refuse(
            f"{where}: genTime {text!r} is not GeneralizedTime UTC with a trailing Z",
            TS_REFUSED_GEN_TIME,
        )
    fraction = match.group("fraction") or ""
    micro = int((fraction[1:] + "000000")[:6]) if fraction else 0
    try:
        instant = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            micro,
            tzinfo=timezone.utc,
        )
    except ValueError as error:
        _refuse(f"{where}: genTime {text!r} is not a valid instant ({error})", TS_REFUSED_GEN_TIME)
    return text, instant


def _accuracy(data: bytes, value: TLV, where: str) -> Accuracy:
    _expect(value, 0x30, where)
    parts = _children(data, value)
    seconds: int | None = None
    millis: int | None = None
    micros: int | None = None
    position = 0
    if position < len(parts) and parts[position].tag == 0x02:
        seconds = _integer(data, parts[position], f"{where}.seconds", nonnegative=True)
        position += 1
    if position < len(parts) and parts[position].tag == 0x80:
        millis = _integer_content(
            parts[position].content, f"{where}.millis", nonnegative=True
        )
        if not 1 <= millis <= 999:
            _refuse(f"{where}: millis {millis} is outside 1..999", TS_REFUSED_ACCURACY)
        position += 1
    if position < len(parts) and parts[position].tag == 0x81:
        micros = _integer_content(
            parts[position].content, f"{where}.micros", nonnegative=True
        )
        if not 1 <= micros <= 999:
            _refuse(f"{where}: micros {micros} is outside 1..999", TS_REFUSED_ACCURACY)
        position += 1
    if position != len(parts):
        _refuse(f"{where}: {len(parts) - position} unexpected accuracy element(s)")
    if seconds is not None and seconds < 0:
        _refuse(f"{where}: negative accuracy seconds", TS_REFUSED_ACCURACY)
    return Accuracy(seconds, millis, micros)


def parse_tstinfo(data: bytes) -> TSTInfo:
    top = _single(data, "TSTInfo")
    _expect(top, 0x30, "TSTInfo")
    parts = _children(data, top)
    if len(parts) < 4:
        _refuse("TSTInfo has fewer than four mandatory elements")
    version = _integer(data, parts[0], "TSTInfo.version", nonnegative=True)
    if version != 1:
        _refuse(f"TSTInfo.version is {version}, not 1", TS_REFUSED_VERSION)
    policy = _oid(data, parts[1], "TSTInfo.policy")

    imprint = parts[2]
    _expect(imprint, 0x30, "TSTInfo.messageImprint")
    imprint_parts = _children(data, imprint)
    if len(imprint_parts) != 2:
        _refuse("messageImprint does not have exactly two elements")
    algorithm_oid, _parameters = _parse_algid(data, imprint_parts[0], "messageImprint.hashAlgorithm")
    hashed_message = _octets(imprint_parts[1], "messageImprint.hashedMessage")

    serial = _integer(data, parts[3], "TSTInfo.serialNumber", nonnegative=True)

    if len(parts) < 5:
        _refuse("TSTInfo.genTime is absent", TS_REFUSED_GEN_TIME)
    if parts[4].tag != 0x18:
        _refuse("TSTInfo.genTime is absent", TS_REFUSED_GEN_TIME)
    gen_time, gen_time_utc = _generalized_time(parts[4], "TSTInfo.genTime")

    position = 5
    accuracy: Accuracy | None = None
    ordering = False
    nonce: int | None = None
    tsa_present = False
    extensions_present = False
    if position < len(parts) and parts[position].tag == 0x30:
        accuracy = _accuracy(data, parts[position], "TSTInfo.accuracy")
        position += 1
    if position < len(parts) and parts[position].tag == 0x01:
        if len(parts[position].content) != 1:
            _refuse("TSTInfo.ordering is not a one-octet BOOLEAN")
        ordering = parts[position].content != b"\x00"
        position += 1
    if position < len(parts) and parts[position].tag == 0x02:
        nonce = _integer(data, parts[position], "TSTInfo.nonce", nonnegative=True)
        position += 1
    if position < len(parts) and parts[position].tag == 0xA0:
        tsa_present = True
        position += 1
    if position < len(parts) and parts[position].tag == 0xA1:
        extensions_present = True
        position += 1
    if position != len(parts):
        _refuse(f"TSTInfo has {len(parts) - position} unexpected trailing element(s)")

    return TSTInfo(
        version=version,
        policy=policy,
        algorithm_oid=algorithm_oid,
        algorithm=OID_ALGORITHMS.get(algorithm_oid),
        hashed_message=hashed_message,
        serial=serial,
        gen_time=gen_time,
        gen_time_utc=gen_time_utc,
        accuracy=accuracy,
        ordering=ordering,
        nonce=nonce,
        tsa_present=tsa_present,
        extensions_present=extensions_present,
    )


# ---------------------------------------------------------------------------
# CMS / TimeStampToken
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Token:
    tst: TSTInfo
    econtent: bytes
    digest_oid: str
    signature_oid: str
    signature: bytes
    signed_attrs: bytes  # the DER SET OF encoding that the signature covers
    content_type_oid: str | None
    message_digest: bytes | None
    certificates: tuple[bytes, ...]
    certificate_count: int


def parse_token(data: bytes) -> Token:
    if not data:
        _refuse("empty token")
    if len(data) > MAX_TOKEN_BYTES:
        _refuse(f"token is larger than {MAX_TOKEN_BYTES} bytes")
    content_info = _single(data, "ContentInfo")
    _expect(content_info, 0x30, "ContentInfo")
    parts = _children(data, content_info)
    if len(parts) != 2:
        _refuse("ContentInfo does not have exactly two elements")
    content_type = _oid(data, parts[0], "ContentInfo.contentType")
    if content_type != OID_SIGNED_DATA:
        _refuse(f"ContentInfo.contentType is {content_type}, not id-signedData")
    _expect(parts[1], 0xA0, "ContentInfo.content")
    explicit = _children(data, parts[1])
    if len(explicit) != 1:
        _refuse("ContentInfo.content does not wrap exactly one SignedData")
    signed_data = explicit[0]
    _expect(signed_data, 0x30, "SignedData")
    fields = _children(data, signed_data)
    if len(fields) < 4:
        _refuse("SignedData has fewer than four elements")
    version = _integer(data, fields[0], "SignedData.version", nonnegative=True)
    if version != 3:
        _refuse(f"SignedData.version is {version}, not 3", TS_REFUSED_VERSION)
    _expect(fields[1], 0x31, "SignedData.digestAlgorithms")
    if not _children(data, fields[1]):
        _refuse("SignedData.digestAlgorithms is empty")
    for alg in _children(data, fields[1]):
        _parse_algid(data, alg, "SignedData.digestAlgorithms")

    encap = fields[2]
    _expect(encap, 0x30, "SignedData.encapContentInfo")
    encap_parts = _children(data, encap)
    if not 1 <= len(encap_parts) <= 2:
        _refuse("encapContentInfo has an unexpected element count")
    econtent_type = _oid(data, encap_parts[0], "encapContentInfo.eContentType")
    if econtent_type != OID_TSTINFO:
        _refuse(f"eContentType is {econtent_type}, not id-ct-TSTInfo")
    if len(encap_parts) != 2:
        _refuse("encapContentInfo has no eContent")
    _expect(encap_parts[1], 0xA0, "encapContentInfo.eContent")
    octet_parts = _children(data, encap_parts[1])
    if len(octet_parts) != 1:
        _refuse("eContent does not wrap exactly one OCTET STRING")
    econtent = _octets(octet_parts[0], "eContent")

    position = 3
    certificates: tuple[bytes, ...] = ()
    if position < len(fields) and fields[position].tag == 0xA0:
        certificates = tuple(child.full for child in _children(data, fields[position]))
        position += 1
    if position < len(fields) and fields[position].tag == 0xA1:
        position += 1  # crls are not parsed and not used
    if position >= len(fields):
        _refuse("SignedData has no signerInfos")
    _expect(fields[position], 0x31, "SignedData.signerInfos")
    signers = _children(data, fields[position])
    if position != len(fields) - 1:
        _refuse("SignedData has elements after signerInfos")
    if len(signers) != 1:
        _refuse(f"signerInfos has {len(signers)} entries; exactly one is required")

    signer = signers[0]
    _expect(signer, 0x30, "SignerInfo")
    signer_fields = _children(data, signer)
    if len(signer_fields) < 5:
        _refuse("SignerInfo has fewer than five elements")
    _integer(data, signer_fields[0], "SignerInfo.version", nonnegative=True)
    # sid is issuerAndSerialNumber or subjectKeyIdentifier; both are skipped here
    # because the caller supplies the certificate under test.
    digest_oid, _ = _parse_algid(data, signer_fields[2], "SignerInfo.digestAlgorithm")
    if digest_oid not in OID_ALGORITHMS:
        _refuse(f"SignerInfo.digestAlgorithm {digest_oid} is unknown", TS_REFUSED_ALGORITHM)
    position = 3
    signed_attrs = b""
    content_type_oid: str | None = None
    message_digest: bytes | None = None
    if position < len(signer_fields) and signer_fields[position].tag == 0xA0:
        attrs = signer_fields[position]
        attribute_values: dict[str, list[bytes]] = {}
        for attribute in _children(data, attrs):
            _expect(attribute, 0x30, "Attribute")
            attribute_parts = _children(data, attribute)
            if len(attribute_parts) != 2:
                _refuse("Attribute does not have exactly two elements")
            attribute_oid = _oid(data, attribute_parts[0], "Attribute.type")
            _expect(attribute_parts[1], 0x31, "Attribute.values")
            values = _children(data, attribute_parts[1])
            if not values:
                _refuse("Attribute has an empty value set")
            attribute_values.setdefault(attribute_oid, []).extend(value.full for value in values)
        if OID_CONTENT_TYPE not in attribute_values or len(attribute_values[OID_CONTENT_TYPE]) != 1:
            _refuse("signedAttrs must contain exactly one content-type attribute")
        content_type_value = _read_tlv(attribute_values[OID_CONTENT_TYPE][0], 0, len(attribute_values[OID_CONTENT_TYPE][0]))
        if content_type_value.end != len(attribute_values[OID_CONTENT_TYPE][0]):
            _refuse("content-type attribute has trailing bytes")
        content_type_oid = _oid(
            attribute_values[OID_CONTENT_TYPE][0], content_type_value, "content-type"
        )
        if OID_MESSAGE_DIGEST not in attribute_values or len(attribute_values[OID_MESSAGE_DIGEST]) != 1:
            _refuse("signedAttrs must contain exactly one message-digest attribute")
        digest_value = _read_tlv(
            attribute_values[OID_MESSAGE_DIGEST][0],
            0,
            len(attribute_values[OID_MESSAGE_DIGEST][0]),
        )
        if digest_value.end != len(attribute_values[OID_MESSAGE_DIGEST][0]):
            _refuse("message-digest attribute has trailing bytes")
        message_digest = _octets(digest_value, "message-digest")
        # The signature is over the DER SET OF encoding, not the implicit [0] form.
        signed_attrs = b"\x31" + data[attrs.start + 1:attrs.content_start] + attrs.content
        position += 1
    else:
        _refuse("SignerInfo has no signedAttrs; an RFC 3161 token requires them")

    signature_oid, _ = _parse_algid(data, signer_fields[position], "SignerInfo.signatureAlgorithm")
    position += 1
    if position >= len(signer_fields):
        _refuse("SignerInfo has no signature")
    signature = _octets(signer_fields[position], "SignerInfo.signature")
    position += 1
    if position < len(signer_fields) and signer_fields[position].tag == 0xA1:
        position += 1
    if position != len(signer_fields):
        _refuse("SignerInfo has unexpected trailing elements")

    tst = parse_tstinfo(econtent)
    return Token(
        tst=tst,
        econtent=econtent,
        digest_oid=digest_oid,
        signature_oid=signature_oid,
        signature=signature,
        signed_attrs=signed_attrs,
        content_type_oid=content_type_oid,
        message_digest=message_digest,
        certificates=certificates,
        certificate_count=len(certificates),
    )


# ---------------------------------------------------------------------------
# Certificates (only what EKU and a root-presence check need)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Certificate:
    issuer: bytes
    subject: bytes
    serial: int
    extended_key_usage: tuple[str, ...]
    self_issued: bool


def parse_certificate(data: bytes) -> Certificate:
    top = _single(data, "Certificate")
    _expect(top, 0x30, "Certificate")
    parts = _children(data, top)
    if len(parts) != 3:
        _refuse("Certificate does not have exactly three elements")
    tbs = parts[0]
    _expect(tbs, 0x30, "TBSCertificate")
    fields = _children(data, tbs)
    position = 0
    if not fields:
        _refuse("TBSCertificate is empty")
    if fields[position].tag == 0xA0:
        version_parts = _children(data, fields[position])
        if len(version_parts) != 1:
            _refuse("TBSCertificate.version is not one INTEGER")
        _integer(data, version_parts[0], "TBSCertificate.version", nonnegative=True)
        position += 1
    if position + 6 > len(fields):
        _refuse("TBSCertificate is missing mandatory fields")
    serial = _integer(data, fields[position], "TBSCertificate.serialNumber", nonnegative=True)
    position += 1
    _parse_algid(data, fields[position], "TBSCertificate.signature")  # signature AlgorithmIdentifier
    position += 1
    issuer = fields[position].full
    position += 1
    _expect(fields[position], 0x30, "TBSCertificate.validity")
    position += 1
    subject = fields[position].full
    position += 1
    _expect(fields[position], 0x30, "TBSCertificate.subjectPublicKeyInfo")
    position += 1
    eku: tuple[str, ...] = ()
    for extra in fields[position:]:
        if extra.tag == 0xA3:
            wrapped = _children(data, extra)
            if len(wrapped) != 1:
                _refuse("certificate extensions are not one SEQUENCE")
            _expect(wrapped[0], 0x30, "Extensions")
            for extension in _children(data, wrapped[0]):
                _expect(extension, 0x30, "Extension")
                extension_parts = _children(data, extension)
                if not 2 <= len(extension_parts) <= 3:
                    _refuse("Extension has an unexpected element count")
                extension_oid = _oid(data, extension_parts[0], "Extension.extnID")
                value_index = 1
                if extension_parts[1].tag == 0x01:
                    value_index = 2
                if value_index >= len(extension_parts):
                    _refuse("Extension has no extnValue")
                octets = _octets(extension_parts[value_index], "Extension.extnValue")
                if extension_oid == OID_EKU:
                    inner = _single(octets, "ExtendedKeyUsage")
                    _expect(inner, 0x30, "ExtendedKeyUsage")
                    eku = tuple(
                        _oid(octets, item, "ExtendedKeyUsage.KeyPurposeId")
                        for item in _children(octets, inner)
                    )
        elif extra.tag in (0xA1, 0xA2):
            continue
        else:
            _refuse(f"TBSCertificate has an unexpected field with tag 0x{extra.tag:02x}")
    return Certificate(
        issuer=issuer,
        subject=subject,
        serial=serial,
        extended_key_usage=eku,
        self_issued=(issuer == subject),
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Verification:
    code: str
    outcome: str
    detail: str
    imprint: str = "NOT_RUN"
    signature: str = "NOT_RUN"
    chain: str = "NOT_RUN"
    eku: str = "NOT_RUN"
    root: str = "NOT_RUN"
    nonce: str = "NOT_RUN"
    accuracy: str = "NOT_RUN"
    policy: str | None = None
    serial: int | None = None
    algorithm: str | None = None
    gen_time: str | None = None
    imprint_hex: str | None = None
    token_certificates: int = 0

    @property
    def accepted(self) -> bool:
        return self.code == CODE_OK

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "outcome": self.outcome,
            "detail": self.detail,
            "imprint": self.imprint,
            "signature": self.signature,
            "chain": self.chain,
            "eku": self.eku,
            "root": self.root,
            "nonce": self.nonce,
            "accuracy": self.accuracy,
            "policy": self.policy,
            "serial": self.serial,
            "algorithm": self.algorithm,
            "genTime": self.gen_time,
            "imprintHex": self.imprint_hex,
            "tokenCertificates": self.token_certificates,
            "trusted": False,
        }


def _artifact_bytes(artifact: bytes | bytearray | str | Path) -> tuple[bytes, str]:
    if isinstance(artifact, (bytes, bytearray)):
        return bytes(artifact), "bytes"
    path = Path(artifact)
    try:
        return path.read_bytes(), str(path)
    except OSError as error:
        raise Refusal(CODE_IO, str(error))


def verify_token(
    token_der: bytes,
    artifact: bytes | bytearray | str | Path,
    *,
    algorithm: str = "sha256",
    certificate: bytes | None = None,
    verify_signature: Callable[[bytes, bytes, bytes, str, str], bool] | None = None,
    trust_root: bytes | None = None,
    verify_chain: Callable[[bytes, bytes], bool] | None = None,
    require_root: bool = False,
    expected_nonce: int | None = None,
    live_service: bool = False,
) -> Verification:
    """Verify a token's imprint offline, and only as far as its trust allows.

    The signature, chain, EKU and root are ``NOT_RUN`` unless the caller supplies
    the certificate and the verification function.  Even with all of them the
    outcome is ``..._UNTRUSTED``: a caller-supplied root is not an admitted root,
    and this module admits no TSA.  ``TIMESTAMP_TRUSTED`` is never returned.
    """
    axes: dict[str, str] = {}
    try:
        if live_service:
            raise Refusal(
                TS_REFUSED_LIVE_SERVICE,
                "a live-service verification was requested; this verifier opens no socket",
                axes,
            )
        token = parse_token(token_der)
        tst = token.tst
        axes["algorithm"] = tst.algorithm or tst.algorithm_oid
        axes["gen_time"] = tst.gen_time
        axes["accuracy"] = tst.accuracy.text if tst.accuracy else "unspecified"

        if tst.policy == POLICY_LIVE_SERVICE:
            raise Refusal(
                TS_REFUSED_LIVE_SERVICE,
                "the token asserts a live-service verification; no offline evidence can establish it",
                axes,
            )

        if algorithm not in ALGORITHMS:
            raise Refusal(
                TS_REFUSED_ALGORITHM,
                f"declared algorithm {algorithm!r} is not one of {sorted(ALGORITHMS)}",
                axes,
            )
        if tst.algorithm_oid != ALGORITHMS[algorithm]:
            raise Refusal(
                TS_REFUSED_ALGORITHM,
                f"the token's imprint algorithm is {tst.algorithm_oid}, "
                f"the caller declared {ALGORITHMS[algorithm]} ({algorithm})",
                axes,
            )
        expected_size = DIGEST_SIZES[algorithm]
        if len(tst.hashed_message) != expected_size:
            raise Refusal(
                TS_REFUSED_IMPRINT,
                f"hashedMessage is {len(tst.hashed_message)} bytes, {algorithm} needs {expected_size}",
                axes,
            )

        body, description = _artifact_bytes(artifact)
        digest = hashlib.new(algorithm, body).digest()
        if not hmac.compare_digest(digest, tst.hashed_message):
            raise Refusal(
                TS_REFUSED_IMPRINT,
                f"the message imprint is not the digest of {description}",
                axes,
            )
        axes["imprint"] = "PASS"
        axes["imprint_hex"] = digest.hex()

        if expected_nonce is not None:
            if tst.nonce is None:
                raise Refusal(
                    TS_REFUSED_NONCE,
                    f"the caller expected nonce {expected_nonce}; the token carries none",
                    axes,
                )
            if tst.nonce != expected_nonce:
                raise Refusal(
                    TS_REFUSED_NONCE,
                    f"the caller expected nonce {expected_nonce}; the token carries {tst.nonce}",
                    axes,
                )
            axes["nonce"] = "PASS"
        elif tst.nonce is not None:
            axes["nonce"] = "RECORDED"
        else:
            axes["nonce"] = "ABSENT"

        # The CMS content binding is a hash comparison, not a signature check.
        if token.content_type_oid != OID_TSTINFO:
            raise Refusal(
                TS_REFUSED_SIGNATURE,
                f"the signed content-type attribute is {token.content_type_oid}, not id-ct-TSTInfo",
                axes,
            )
        signer_digest_name = OID_ALGORITHMS[token.digest_oid]
        expected_content_digest = hashlib.new(signer_digest_name, token.econtent).digest()
        if token.message_digest is None or not hmac.compare_digest(
            token.message_digest, expected_content_digest
        ):
            raise Refusal(
                TS_REFUSED_SIGNATURE,
                "the signed message-digest attribute is not the digest of the eContent",
                axes,
            )

        base = dict(
            code=CODE_OK,
            outcome=OUTCOME_IMPRINT_VERIFIED_UNTRUSTED,
            detail=(
                "the message imprint matches the artefact; no certificate and verification "
                "function were supplied, so the signature, chain, EKU and root are NOT_RUN"
            ),
            imprint="PASS",
            nonce=axes.get("nonce", "NOT_RUN"),
            accuracy=axes["accuracy"],
            policy=tst.policy,
            serial=tst.serial,
            algorithm=algorithm,
            gen_time=tst.gen_time,
            imprint_hex=axes["imprint_hex"],
            token_certificates=token.certificate_count,
        )

        if certificate is None or verify_signature is None:
            if require_root:
                raise Refusal(
                    TS_REFUSED_ROOT,
                    "the caller requires an admitted root, but no certificate/verification "
                    "function and no root were supplied",
                    {**axes, "imprint": "PASS"},
                )
            return Verification(**base)

        leaf = parse_certificate(certificate)
        if OID_KP_TIMESTAMPING not in leaf.extended_key_usage:
            raise Refusal(
                TS_REFUSED_EKU,
                "the supplied certificate lacks id-kp-timeStamping (1.3.6.1.5.5.7.3.8)",
                {**axes, "imprint": "PASS", "eku": "FAIL", "signature": "NOT_RUN"},
            )
        axes["eku"] = "PASS"

        accepted = verify_signature(
            certificate,
            token.signed_attrs,
            token.signature,
            token.digest_oid,
            token.signature_oid,
        )
        if not accepted:
            raise Refusal(
                TS_REFUSED_SIGNATURE,
                "the caller-supplied verification function rejected the token signature",
                {**axes, "imprint": "PASS", "eku": "PASS", "signature": "FAIL"},
            )
        axes["signature"] = "PASS"

        base = {
            **base,
            "outcome": OUTCOME_SIGNATURE_VERIFIED_UNTRUSTED,
            "detail": (
                "the imprint matches and the supplied verification function accepted the "
                "signature; the chain and root are NOT_RUN and a caller-supplied certificate "
                "is not an admitted TSA"
            ),
            "signature": "PASS",
            "eku": "PASS",
            "nonce": axes.get("nonce", "NOT_RUN"),
        }

        if trust_root is None:
            if require_root:
                raise Refusal(
                    TS_REFUSED_ROOT,
                    "the caller requires an admitted root and supplied none",
                    {**axes, "imprint": "PASS", "eku": "PASS", "signature": "PASS"},
                )
            return Verification(**base)

        root_certificate = parse_certificate(trust_root)
        if not root_certificate.self_issued:
            raise Refusal(
                TS_REFUSED_ROOT,
                "the supplied root is not self-issued",
                {**axes, "imprint": "PASS", "eku": "PASS", "signature": "PASS", "root": "FAIL"},
            )
        if leaf.issuer != root_certificate.subject:
            raise Refusal(
                TS_REFUSED_ROOT,
                "the certificate's issuer is not the supplied root's subject",
                {**axes, "imprint": "PASS", "eku": "PASS", "signature": "PASS", "root": "FAIL"},
            )
        if verify_chain is not None:
            if not verify_chain(certificate, trust_root):
                raise Refusal(
                    TS_REFUSED_ROOT,
                    "the supplied chain-verification function rejected the chain",
                    {**axes, "imprint": "PASS", "eku": "PASS", "signature": "PASS", "root": "FAIL"},
                )
            axes["chain"] = "PASS"
            root_axis = "PRESENCE_ONLY"
        else:
            root_axis = "PRESENCE_ONLY"

        # A caller assertion is not an admission.  The outcome deliberately stays
        # UNTRUSTED and no branch sets OUTCOME_TRUSTED.
        result = Verification(
            **{
                **base,
                "detail": (
                    "the imprint, signature, EKU and root presence were checked; the root is "
                    "the caller's assertion, not an admitted trust root, so the time is UNTRUSTED"
                ),
                "chain": axes.get("chain", "NOT_RUN"),
                "root": root_axis,
            }
        )
        if result.outcome == OUTCOME_TRUSTED:
            raise AssertionError("no code path may produce TIMESTAMP_TRUSTED")
        return result
    except Refusal as refusal:
        axes = {**refusal.axes}
        base = {
            "code": refusal.code,
            "outcome": OUTCOME_REFUSED,
            "detail": refusal.message,
        }
        for name in ("imprint", "signature", "chain", "eku", "root", "nonce"):
            if name in axes:
                base[name] = axes[name]
        if "accuracy" in axes:
            base["accuracy"] = axes["accuracy"]
        if "algorithm" in axes and axes["algorithm"] in ALGORITHMS:
            base["algorithm"] = axes["algorithm"]
        if "gen_time" in axes:
            base["gen_time"] = axes["gen_time"]
        if "imprint_hex" in axes:
            base["imprint_hex"] = axes["imprint_hex"]
        return Verification(**base)


# ---------------------------------------------------------------------------
# The nine times of §B.9
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Slot:
    name: str
    clause: str
    kind: str


SLOTS: tuple[Slot, ...] = (
    Slot("source-creation", "docs/ETP-ADDENDUM-B.md §B.9 time 1: source creation", "local"),
    Slot(
        "experimental-execution",
        "docs/ETP-ADDENDUM-B.md §B.9 time 2: experimental execution",
        "local",
    ),
    Slot("evidence-production", "docs/ETP-ADDENDUM-B.md §B.9 time 3: evidence production", "local"),
    Slot(
        "statement-authentication",
        "docs/ETP-ADDENDUM-B.md §B.9 time 4: statement authentication",
        "client",
    ),
    Slot(
        "trusted-timestamping",
        "docs/ETP-ADDENDUM-B.md §B.9 time 5: trusted timestamping",
        "authority",
    ),
    Slot(
        "transparency-inclusion",
        "docs/ETP-ADDENDUM-B.md §B.9 time 6: transparency inclusion",
        "log",
    ),
    Slot(
        "witness-observation",
        "docs/ETP-ADDENDUM-B.md §B.9 time 7: witness observation",
        "verifier",
    ),
    Slot("release-promotion", "docs/ETP-ADDENDUM-B.md §B.9 time 8: release promotion", "publication"),
    Slot(
        "correction-or-revocation",
        "docs/ETP-ADDENDUM-B.md §B.9 time 9: subsequent correction or revocation",
        "publication",
    ),
)
SLOT_NAMES = tuple(slot.name for slot in SLOTS)
SLOT_KINDS = {slot.name: slot.kind for slot in SLOTS}

# (earlier, later) pairs; each later value must not precede its earlier value.
ORDER_INVARIANTS: tuple[tuple[str, str], ...] = (
    ("source-creation", "experimental-execution"),
    ("experimental-execution", "evidence-production"),
    ("evidence-production", "statement-authentication"),
    ("statement-authentication", "trusted-timestamping"),
    ("trusted-timestamping", "transparency-inclusion"),
    ("transparency-inclusion", "witness-observation"),
    ("transparency-inclusion", "release-promotion"),
    ("release-promotion", "correction-or-revocation"),
)

NO_SOURCE = {"", "none", None}
CLOCK_SOURCES = {"clock", "system clock", "wall clock", "now", "read the clock"}
ACCURACY_TOKENS = {"second", "minute", "hour", "day", "unknown"}
ESTABLISHED_VALUES = {True: "true", False: "false", "unknown": "unknown"}


def _established(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value == "unknown":
        return "unknown"
    raise Refusal(TS_REFUSED_TIME_MODEL, f"established {value!r} is not true, false or unknown")


def _parse_time(value: str) -> tuple[datetime, str]:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc), "day"
        except ValueError as error:
            raise Refusal(TS_REFUSED_TIME_UNSOURCED, f"time {value!r} is not a date: {error}")
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        instant = datetime.fromisoformat(text)
    except ValueError as error:
        raise Refusal(TS_REFUSED_TIME_UNSOURCED, f"time {value!r} is not ISO 8601: {error}")
    if instant.tzinfo is None:
        raise Refusal(
            TS_REFUSED_TIME_UNSOURCED,
            f"time {value!r} has no timezone; a local clock read is not a recorded time",
        )
    return instant.astimezone(timezone.utc), "instant"


def validate_times(artefact: Mapping[str, Any], where: str = "artefact") -> list[dict[str, str]]:
    """Return every refusal the nine-slot record earns, with its stable code."""
    refusals: list[dict[str, str]] = []
    slots = artefact.get("slots")
    if not isinstance(slots, list):
        return [{"code": TS_REFUSED_TIME_MODEL, "message": f"{where}: slots is not a list"}]
    names = [slot.get("name") for slot in slots if isinstance(slot, Mapping)]
    if names != list(SLOT_NAMES):
        return [
            {
                "code": TS_REFUSED_TIME_MODEL,
                "message": (
                    f"{where}: slots are {names!r}, not the nine §B.9 slots in order "
                    f"{list(SLOT_NAMES)!r}"
                ),
            }
        ]
    by_name: dict[str, Mapping[str, Any]] = {}
    for slot in slots:
        if not isinstance(slot, Mapping):
            refusals.append(
                {"code": TS_REFUSED_TIME_MODEL, "message": f"{where}: a slot is not an object"}
            )
            continue
        name = slot.get("name")
        by_name[name] = slot
        clause = slot.get("clause")
        if not isinstance(clause, str) or not clause:
            refusals.append(
                {"code": TS_REFUSED_TIME_MODEL, "message": f"{where}/{name}: clause is absent"}
            )
        if slot.get("kind") != SLOT_KINDS.get(name):
            refusals.append(
                {
                    "code": TS_REFUSED_TIME_MODEL,
                    "message": (
                        f"{where}/{name}: kind {slot.get('kind')!r} is not "
                        f"{SLOT_KINDS.get(name)!r}"
                    ),
                }
            )

    parsed: dict[str, tuple[datetime, str]] = {}
    for name, slot in by_name.items():
        try:
            state = _established(slot.get("established"))
        except Refusal as refusal:
            refusals.append({"code": refusal.code, "message": f"{where}/{name}: {refusal.message}"})
            continue
        value = slot.get("value")
        source = slot.get("source")
        recorded_by = slot.get("recordedBy")
        accuracy = slot.get("accuracy")

        if value is not None:
            if not isinstance(value, str) or not value:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": f"{where}/{name}: value is not a non-empty string",
                    }
                )
                continue
            if source in NO_SOURCE:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": f"{where}/{name}: a value has no tracked source",
                    }
                )
            if isinstance(source, str) and source.strip().lower() in CLOCK_SOURCES:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": (
                            f"{where}/{name}: source {source!r} is a clock read; a clock is "
                            "not a record and no clock is trustworthy because it is read"
                        ),
                    }
                )
            if not isinstance(recorded_by, str) or not recorded_by:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": f"{where}/{name}: a value has no recordedBy",
                    }
                )
            try:
                parsed[name] = _parse_time(value)
            except Refusal as refusal:
                refusals.append({"code": refusal.code, "message": f"{where}/{name}: {refusal.message}"})

        if state == "true":
            if value is None:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": f"{where}/{name}: established is true but the value is absent",
                    }
                )
            if source in NO_SOURCE:
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": f"{where}/{name}: established is true but no source is named",
                    }
                )
            if accuracy not in ACCURACY_TOKENS:
                refusals.append(
                    {
                        "code": TS_REFUSED_ACCURACY,
                        "message": (
                            f"{where}/{name}: accuracy {accuracy!r} is not one of "
                            f"{sorted(ACCURACY_TOKENS)}"
                        ),
                    }
                )
        elif value is None and state == "false" and accuracy is not None:
            if accuracy not in ACCURACY_TOKENS and accuracy != "unknown":
                refusals.append(
                    {
                        "code": TS_REFUSED_ACCURACY,
                        "message": f"{where}/{name}: accuracy {accuracy!r} is not a known token",
                    }
                )

        if name == "experimental-execution" and isinstance(source, str):
            folded = source.strip().lower()
            if "timestamp" in folded or folded == "slot:trusted-timestamping":
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_UNSOURCED,
                        "message": (
                            f"{where}/{name}: execution time is inferred from a later timestamp; "
                            "§B.9 forbids that inference"
                        ),
                    }
                )

    # No slot may reuse another slot's value from the same source and recorder.
    for index, first in enumerate(SLOT_NAMES):
        for second in SLOT_NAMES[index + 1:]:
            left = by_name.get(first, {})
            right = by_name.get(second, {})
            if left.get("value") is None or right.get("value") is None:
                continue
            if left.get("value") != right.get("value"):
                continue
            if (
                left.get("source") == right.get("source")
                and left.get("recordedBy") == right.get("recordedBy")
            ):
                refusals.append(
                    {
                        "code": TS_REFUSED_TIME_COLLAPSED,
                        "message": (
                            f"{where}: {first} and {second} carry the same value "
                            f"{left.get('value')!r} from the same source and recorder; "
                            "one time was collapsed into another slot"
                        ),
                    }
                )

    for earlier, later in ORDER_INVARIANTS:
        if earlier not in parsed or later not in parsed:
            continue
        left_value, left_precision = parsed[earlier]
        right_value, right_precision = parsed[later]
        if left_precision != right_precision:
            continue  # a day and an instant are not comparable here
        if right_value < left_value:
            explanation = by_name.get(later, {}).get("explanation")
            if not isinstance(explanation, str) or not explanation.strip():
                refusals.append(
                    {
                        "code": TS_REFUSED_ORDER,
                        "message": (
                            f"{where}: {later} ({by_name[later].get('value')}) precedes "
                            f"{earlier} ({by_name[earlier].get('value')}) and no explanation "
                            "is recorded"
                        ),
                    }
                )
    return refusals


def validate_times_document(document: Mapping[str, Any]) -> list[dict[str, str]]:
    refusals: list[dict[str, str]] = []
    artefacts = document.get("artefacts")
    if not isinstance(artefacts, list):
        return [{"code": TS_REFUSED_TIME_MODEL, "message": "the record has no artefacts list"}]
    for artefact in artefacts:
        identifier = artefact.get("id", "?") if isinstance(artefact, Mapping) else "?"
        refusals.extend(validate_times(artefact, where=f"artefact {identifier}"))
    return refusals


def canonical_slots() -> list[dict[str, Any]]:
    return [
        {
            "name": slot.name,
            "clause": slot.clause,
            "kind": slot.kind,
            "value": None,
            "source": "none",
            "recordedBy": "none",
            "accuracy": "unknown",
            "established": "unknown",
            "reason": None,
        }
        for slot in SLOTS
    ]


# ---------------------------------------------------------------------------
# Deterministic control fixtures (control-only; never evidence)
# ---------------------------------------------------------------------------
def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_integer(number: int) -> bytes:
    if number < 0:
        raise ValueError("control fixtures encode non-negative integers only")
    if number == 0:
        raw = b"\x00"
    else:
        raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _der_oid(oid: str) -> bytes:
    arcs = [int(part) for part in oid.split(".")]
    if len(arcs) < 2:
        raise ValueError("an OID needs two arcs")
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        stack = [arc & 0x7F]
        arc >>= 7
        while arc:
            stack.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(stack))
    return _tlv(0x06, bytes(body))


def _sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    ordered = sorted(items)  # DER SET OF ordering
    return _tlv(0x31, b"".join(ordered))


def _null() -> bytes:
    return _tlv(0x05, b"")


def _utc_time(text: str) -> bytes:
    return _tlv(0x17, text.encode("ascii"))


def _generalized(text: str) -> bytes:
    return _tlv(0x18, text.encode("ascii"))


def _algorithm(oid: str) -> bytes:
    return _sequence(_der_oid(oid), _null())


def _name(common_name: str) -> bytes:
    return _sequence(_set(_sequence(_der_oid(OID_COMMON_NAME), _tlv(0x0C, common_name.encode("utf-8")))))


def control_certificate(*, with_eku: bool = True, root: bool = False) -> bytes:
    """A structurally parseable certificate fixture.  It is not a CA certificate."""
    subject = _name(CONTROL_ROOT_CN if root else CONTROL_LEAF_CN)
    issuer = _name(CONTROL_ROOT_CN)
    signature_algorithm = _algorithm(OID_SHA256_WITH_RSA)
    spki = _sequence(_algorithm(OID_RSA), _tlv(0x03, b"\x00" + bytes(range(32))))
    validity = _sequence(_utc_time("260101000000Z"), _utc_time("271231235959Z"))
    fields = [
        _tlv(0xA0, _der_integer(2)),
        _der_integer(1 if root else 2),
        signature_algorithm,
        issuer,
        validity,
        subject,
        spki,
    ]
    if with_eku:
        extension = _sequence(
            _der_oid(OID_EKU),
            _tlv(0x04, _sequence(_der_oid(OID_KP_TIMESTAMPING))),
        )
        fields.append(_tlv(0xA3, _sequence(extension)))
    tbs = _sequence(*fields)
    signature_value = _tlv(0x03, b"\x00" + bytes(range(32, 64)))
    return _sequence(tbs, signature_algorithm, signature_value)


def control_root() -> bytes:
    return control_certificate(with_eku=False, root=True)


def _tstinfo(
    *,
    version: int = 1,
    policy: str = POLICY_FIXTURE,
    algorithm_oid: str = OID_SHA256,
    digest: bytes,
    gen_time: str | None = CONTROL_GEN_TIME,
    accuracy: tuple[int | None, int | None, int | None] | None = (0, 1, 1),
    nonce: int | None = 7,
) -> bytes:
    imprint = _sequence(_algorithm(algorithm_oid), _tlv(0x04, digest))
    fields = [
        _der_integer(version),
        _der_oid(policy),
        imprint,
        _der_integer(1),
    ]
    if gen_time is not None:
        fields.append(_generalized(gen_time))
    if accuracy is not None:
        seconds, millis, micros = accuracy
        accuracy_fields = []
        if seconds is not None:
            accuracy_fields.append(_der_integer(seconds))
        if millis is not None:
            accuracy_fields.append(_tlv(0x80, _der_integer(millis)[2:]))
        if micros is not None:
            accuracy_fields.append(_tlv(0x81, _der_integer(micros)[2:]))
        fields.append(_sequence(*accuracy_fields))
    if nonce is not None:
        fields.append(_der_integer(nonce))
    return _sequence(*fields)


def _control_signature(signed_attrs: bytes, *, corrupt: bool = False) -> bytes:
    signature = hmac.new(CONTROL_SEED, signed_attrs, hashlib.sha256).digest()
    if corrupt:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
    return signature


def control_token(
    variant: str = "valid",
    *,
    artifact: bytes,
    algorithm: str = "sha256",
    certificate: bytes | None = None,
) -> bytes:
    """Build a deterministic control-only token for the named refusal variant.

    The signature is HMAC-SHA256 under a fixed public seed, encoded with the
    ``hmacWithSHA256`` OID.  It is not an X.509 signature and no TSA issued it.
    """
    digest = hashlib.new(algorithm, artifact).digest()
    version = 1
    policy = POLICY_FIXTURE
    gen_time: str | None = CONTROL_GEN_TIME
    accuracy: tuple[int | None, int | None, int | None] | None = (0, 1, 1)
    nonce: int | None = 7
    corrupt_signature = False

    if variant == "unsupported-version":
        version = 2
    elif variant == "wrong-imprint":
        digest = hashlib.sha256(b"an unrelated artefact").digest()
    elif variant == "wrong-algorithm":
        digest = hashlib.sha384(artifact).digest()
    elif variant == "absent-gen-time":
        gen_time = None
    elif variant == "invalid-accuracy":
        accuracy = (0, 1000, None)
    elif variant == "live-service":
        policy = POLICY_LIVE_SERVICE
    elif variant == "nonce-mismatch":
        nonce = 7
    elif variant == "bad-signature":
        corrupt_signature = True
    elif variant not in (
        "valid",
        "missing-eku",
        "absent-root",
        "malformed-der",
        "trailing-byte",
    ):
        raise ValueError(f"unknown control fixture {variant!r}")

    tstinfo = _tstinfo(
        version=version,
        policy=policy,
        algorithm_oid=ALGORITHMS[algorithm] if variant != "wrong-algorithm" else OID_SHA384,
        digest=digest,
        gen_time=gen_time,
        accuracy=accuracy,
        nonce=nonce,
    )
    if variant == "wrong-algorithm":
        # The 48-byte SHA-384 digest is encoded under SHA-384; the caller will
        # declare sha256, which is the condition the control exercises.
        tstinfo = _tstinfo(
            version=version,
            policy=policy,
            algorithm_oid=OID_SHA384,
            digest=hashlib.sha384(artifact).digest(),
            gen_time=gen_time,
            accuracy=accuracy,
            nonce=nonce,
        )

    econtent = tstinfo
    content_digest = hashlib.sha256(econtent).digest()
    attributes = [
        _sequence(_der_oid(OID_CONTENT_TYPE), _set(_der_oid(OID_TSTINFO))),
        _sequence(_der_oid(OID_MESSAGE_DIGEST), _set(_tlv(0x04, content_digest))),
    ]
    attributes_content = b"".join(sorted(attributes))
    signed_attrs_set = b"\x31" + _der_length(len(attributes_content)) + attributes_content
    signature = _control_signature(signed_attrs_set, corrupt=corrupt_signature)
    signed_attrs_implicit = _tlv(0xA0, attributes_content)

    leaf = certificate if certificate is not None else control_certificate(
        with_eku=(variant != "missing-eku")
    )
    leaf_certificate = parse_certificate(leaf)
    sid = _sequence(leaf_certificate.issuer, _der_integer(leaf_certificate.serial))
    signer_info = _sequence(
        _der_integer(1),
        sid,
        _algorithm(OID_SHA256),
        signed_attrs_implicit,
        _algorithm(OID_HMAC_SHA256),
        _tlv(0x04, signature),
    )
    signed_data = _sequence(
        _der_integer(3),
        _set(_algorithm(OID_SHA256)),
        _sequence(_der_oid(OID_TSTINFO), _tlv(0xA0, _tlv(0x04, econtent))),
        _tlv(0xA0, leaf),
        _set(signer_info),
    )
    token = _sequence(_der_oid(OID_SIGNED_DATA), _tlv(0xA0, signed_data))

    if variant == "malformed-der":
        return token[:-5]
    if variant == "trailing-byte":
        return token + b"\x00"
    return token


def control_verify_signature(
    certificate: bytes,
    signed_attrs: bytes,
    signature: bytes,
    digest_oid: str,
    signature_oid: str,
) -> bool:
    """The control-only verification function: HMAC under a fixed public seed."""
    if signature_oid != OID_HMAC_SHA256:
        return False
    if digest_oid != OID_SHA256:
        return False
    expected = hmac.new(CONTROL_SEED, signed_attrs, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def control_times(variant: str = "valid") -> dict[str, Any]:
    """A deterministic nine-slot fixture for the time-model controls."""
    slots = canonical_slots()
    by_name = {slot["name"]: slot for slot in slots}

    def set_slot(
        name: str,
        value: str,
        source: str,
        recorded_by: str,
        accuracy: str = "second",
        established: Any = True,
        explanation: str | None = None,
    ) -> None:
        slot = by_name[name]
        slot.update(
            {
                "value": value,
                "source": source,
                "recordedBy": recorded_by,
                "accuracy": accuracy,
                "established": established,
            }
        )
        if explanation is not None:
            slot["explanation"] = explanation

    set_slot("source-creation", "2026-11-24T00:00:00Z", "git:show:control/v1:source", "git")
    set_slot("experimental-execution", "2026-11-24T01:00:00Z", "git:show:control/v1:run", "git")
    set_slot("evidence-production", "2026-11-24T02:00:00Z", "git:show:control/v1:evidence", "git")
    set_slot("statement-authentication", "2026-11-24T03:00:00Z", "git:show:control/v1:sign", "git")
    set_slot("trusted-timestamping", "2026-11-24T04:00:00Z", "git:show:control/v1:token", "git")
    set_slot("transparency-inclusion", "2026-11-24T05:00:00Z", "git:show:control/v1:log", "git")
    set_slot("witness-observation", "2026-11-24T06:00:00Z", "git:show:control/v1:witness", "git")
    set_slot("release-promotion", "2026-11-24T07:00:00Z", "git:show:control/v1:release", "git")
    set_slot("correction-or-revocation", "2026-11-24T08:00:00Z", "git:show:control/v1:correction", "git")

    if variant == "collapsed":
        for name in SLOT_NAMES:
            by_name[name].update(
                {
                    "value": "2026-11-24T00:00:00Z",
                    "source": "git:show:control/v1:one-time",
                    "recordedBy": "git",
                }
            )
    elif variant == "unsourced":
        by_name["evidence-production"].update(
            {"value": "2026-11-24T02:00:00Z", "source": "none", "recordedBy": "none"}
        )
    elif variant == "clock-source":
        by_name["evidence-production"].update(
            {"value": "2026-11-24T02:00:00Z", "source": "system clock", "recordedBy": "git"}
        )
    elif variant == "out-of-order":
        by_name["statement-authentication"].update({"value": "2026-11-24T00:30:00Z"})
    elif variant == "out-of-order-explained":
        by_name["experimental-execution"].update(
            {
                "value": "2026-11-20T00:00:00Z",
                "explanation": "the original claimed execution date is preserved (§B.9)",
            }
        )
    elif variant == "execution-from-timestamp":
        by_name["experimental-execution"].update(
            {"value": "2026-11-24T04:00:00Z", "source": "trusted-timestamping"}
        )
    elif variant == "missing-slot":
        slots = slots[:-1]
    elif variant == "bad-accuracy":
        by_name["evidence-production"].update({"accuracy": "nanoseconds-ish"})
    elif variant != "valid":
        raise ValueError(f"unknown times control fixture {variant!r}")

    return {"id": f"control-times-{variant}", "slots": slots}


# ---------------------------------------------------------------------------
# Scanning for tokens
# ---------------------------------------------------------------------------
TOKEN_SUFFIXES = (".tsr", ".tst", ".p7s", ".der", ".cms")
SCAN_SKIP = {".git", "target", "node_modules", "court", "__pycache__"}


def scan_for_tokens(root: Path) -> tuple[list[Path], int]:
    """Return files that parse as an RFC 3161 token, plus the number scanned.

    Only binary token suffixes are considered.  A control fixture lives in
    ``evidence/b2/CONTROLS.json`` as base64 and is not a file in the tree, so it
    is not reported as a token.
    """
    found: list[Path] = []
    scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SCAN_SKIP for part in path.parts):
            continue
        if path.suffix.lower() not in TOKEN_SUFFIXES:
            continue
        scanned += 1
        try:
            if path.stat().st_size > MAX_TOKEN_BYTES:
                continue
            parse_token(path.read_bytes())
        except (OSError, Refusal):
            continue
        found.append(path)
    return found, scanned


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_times(document: Mapping[str, Any]) -> int:
    refusals = validate_times_document(document)
    for artefact in document.get("artefacts", []):
        print(f"artefact={artefact.get('id')} kind={artefact.get('kind')}")
        for slot in artefact.get("slots", []):
            print(
                "  slot={name} kind={kind} established={established} value={value} "
                "source={source} recordedBy={recordedBy} accuracy={accuracy}".format(
                    name=slot.get("name"),
                    kind=slot.get("kind"),
                    established=slot.get("established"),
                    value=slot.get("value"),
                    source=slot.get("source"),
                    recordedBy=slot.get("recordedBy"),
                    accuracy=slot.get("accuracy"),
                )
            )
    if refusals:
        for refusal in refusals:
            print(f"code={refusal['code']} {refusal['message']}")
        return EXIT_REFUSED
    print(f"code={CODE_OK} artefacts={len(document.get('artefacts', []))} slots={len(SLOT_NAMES)}")
    return EXIT_OK


def _command_times(args: argparse.Namespace) -> int:
    path = Path(args.file)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        print(f"code={CODE_IO} {error}")
        return EXIT_USAGE
    except json.JSONDecodeError as error:
        print(f"code={TS_REFUSED_TIME_MODEL} {path}: {error}")
        return EXIT_REFUSED
    return _print_times(document)


def _command_verify(args: argparse.Namespace) -> int:
    artifact = Path(args.artifact)
    if args.control_fixture:
        try:
            body = artifact.read_bytes()
        except OSError as error:
            print(f"code={CODE_IO} {error}")
            return EXIT_USAGE
        try:
            token = control_token(
                args.control_fixture,
                artifact=body,
                algorithm=args.algorithm,
            )
        except ValueError as error:
            print(f"code={TS_REFUSED_TIME_MODEL} {error}")
            return EXIT_USAGE
        certificate = None
        if args.certificate:
            certificate = Path(args.certificate).read_bytes()
        elif args.control_fixture in ("valid", "bad-signature", "absent-root"):
            certificate = control_certificate()
        verification = verify_token(
            token,
            body,
            algorithm=args.algorithm,
            certificate=certificate,
            verify_signature=control_verify_signature if certificate is not None else None,
            trust_root=Path(args.root).read_bytes() if args.root else None,
            require_root=args.require_root,
            expected_nonce=args.expected_nonce,
            live_service=args.live_service,
        )
    else:
        if args.token:
            try:
                token = Path(args.token).read_bytes()
            except OSError as error:
                print(f"code={CODE_IO} {error}")
                return EXIT_USAGE
        else:
            print(f"code={CODE_NO_TOKEN} outcome={OUTCOME_NO_TOKEN} no token was supplied")
            return EXIT_OK
        try:
            artifact_body = artifact.read_bytes()
        except OSError as error:
            print(f"code={CODE_IO} {error}")
            return EXIT_USAGE
        verification = verify_token(
            token,
            artifact_body,
            algorithm=args.algorithm,
            certificate=Path(args.certificate).read_bytes() if args.certificate else None,
            trust_root=Path(args.root).read_bytes() if args.root else None,
            require_root=args.require_root,
            expected_nonce=args.expected_nonce,
            live_service=args.live_service,
        )

    print(
        "code={code} outcome={outcome} imprint={imprint} signature={signature} "
        "chain={chain} eku={eku} root={root} nonce={nonce} accuracy={accuracy}".format(
            **verification.as_dict()
        )
    )
    print(
        f"algorithm={verification.algorithm} genTime={verification.gen_time} "
        f"policy={verification.policy} serial={verification.serial} "
        f"tokenCertificates={verification.token_certificates} trusted=false"
    )
    print(f"detail={verification.detail}")
    return EXIT_OK if verification.accepted else EXIT_REFUSED


def _command_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    try:
        found, scanned = scan_for_tokens(root)
    except OSError as error:
        print(f"code={CODE_IO} {error}")
        return EXIT_USAGE
    print(f"code={CODE_OK} tokens={len(found)} files={scanned} root={root}")
    for path in found:
        print(f"token={path.relative_to(root)}")
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="timestamp.py", description="offline RFC 3161 verifier and nine-times model"
    )
    sub = parser.add_subparsers(dest="command")

    times = sub.add_parser("times", help="validate the nine §B.9 slots")
    times.add_argument("--file", default="evidence/b2/TIMES.json")

    verify = sub.add_parser("verify", help="verify a token's imprint offline")
    verify.add_argument("--artifact", required=True)
    verify.add_argument("--token")
    verify.add_argument("--algorithm", default="sha256")
    verify.add_argument("--certificate")
    verify.add_argument("--root")
    verify.add_argument("--require-root", action="store_true")
    verify.add_argument("--expected-nonce", type=int)
    verify.add_argument("--live-service", action="store_true")
    verify.add_argument(
        "--control-fixture",
        help="build a deterministic control-only token instead of reading --token",
    )

    scan = sub.add_parser("scan", help="find RFC 3161 tokens in the tree")
    scan.add_argument("--root", default=".")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    handlers = {"times": _command_times, "verify": _command_verify, "scan": _command_scan}
    if args.command not in handlers:
        print(f"code={CODE_USAGE} no command")
        print(parser.format_usage().strip())
        return EXIT_USAGE
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
