#!/usr/bin/env python3
"""sigstore_bundle.py -- an offline profile validator for Sigstore bundles (A16).

Why this tool exists
--------------------
A Sigstore bundle is a *portable record*: it carries a DSSE envelope, the
signing certificate chain (or a public key), a transparency-log entry with an
inclusion promise or proof, and a timestamp.  Portability is the point and also
the trap: the bundle carries the **evidence**, not the **roots**.  The log's
public key, the CA root that gives the certificate its meaning, and the
timestamp authority's root are *not* in the bundle.  A validator that reads the
bundle alone and prints "verified" has confused "the record is well formed"
with "the record is true".

The rule
--------
This module is an **offline** validator with explicitly stated trust-root and
freshness assumptions.  It:

  * contacts no network service, installs or invokes no Sigstore client, and
    shells out to nothing (enforced structurally, see
    ``network_or_client_findings`` and the matching test);
  * parses the bundle with ``harden.loads`` (the one strict reader), so a
    duplicated key, a BOM, a non-finite number or trailing data is refused;
  * checks the profile shape, the certificate validity window against the
    transparency entry's ``integratedTime``, the issuer and SAN against a
    policy-supplied identity, the payload/artefact digest binding, the tlog
    entry kind and index consistency, the presence of an inclusion promise or
    proof, and the presence of a timestamp;
  * calls **caller-supplied** verifiers for the certificate path, the DSSE
    signature, the inclusion proof and the timestamp.  It implements no
    signature primitive and holds no root;
  * records every check that could not run as ``NOT_RUN`` and refuses to return
    ``BUNDLE_VERIFIED_OFFLINE`` while any check is ``NOT_RUN``.

``BUNDLE_VERIFIED_OFFLINE`` therefore means: *this bundle's decision procedure
ran to completion against the verifiers the caller supplied and every one of
them accepted.*  It does not mean the transparency log or the CA is trusted by
this project, and it does not mean a bundle exists here.  It does not.

The real state
--------------
There is no Sigstore bundle, no transparency-log public key, no CA root and no
timestamp-authority root in this tree (``evidence/a16/INVENTORY.json`` records
``bundles: 0``, ``transparencyLogs: 0``, ``certificates: 0``).  The four A10
envelopes are self-issued DSSE signed by a fixed public test key; they are not
Sigstore bundles and are not counted as any.  Consequently every real
``validate`` invocation here is ``NOT_RUN``: absence is not a pass.

Profile
-------
Only ``application/vnd.dev.sigstore.bundle.v0.3+json`` is validated.  The v0.1
and v0.2 shapes are different (they use a ``content`` oneof and a versioned
media type); this item does not validate them, so it refuses them as an
unsupported version (``SB_REFUSED_VERSION``) rather than guessing.  The field
list is ``bundle_profile()`` and is also written to ``evidence/a16/PROFILE.json``.

Exit status
-----------
``0`` only for ``BUNDLE_VERIFIED_OFFLINE`` and for the ``profile`` command, ``1``
for ``BUNDLE_INVALID`` / ``BUNDLE_UNVERIFIABLE_OFFLINE`` / ``NOT_RUN``, ``2`` for
a usage or unreadable-input error.  The code and the outcome are always printed.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import dsse  # noqa: E402
import harden  # noqa: E402

TOOL_PATH = "forensics/tools/sigstore_bundle.py"
MODEL_ID = "a16/v1"
REPORT_SCHEMA = "openssl-rs/a16/bundle-validation/1"
PROFILE_SCHEMA = "openssl-rs/a16/bundle-profile/1"
INVENTORY_SCHEMA = "openssl-rs/a16/bundle-inventory/2"
CONTROLS_SCHEMA = "openssl-rs/a16/controls/1"

MEDIA_TYPE_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
SIGSTORE_BUNDLE_PREFIX = "application/vnd.dev.sigstore.bundle"
SUPPORTED_VERSION = "v0.3"
REFUSED_VERSIONS = ("v0.1", "v0.2")

TLOG_KIND = "dsse"
TLOG_API_VERSION = "0.0.1"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
CODE_OK = "SB_OK"
CODE_USAGE = "SB_USAGE"

OUTCOME_VERIFIED = "BUNDLE_VERIFIED_OFFLINE"
OUTCOME_INVALID = "BUNDLE_INVALID"
OUTCOME_UNVERIFIABLE = "BUNDLE_UNVERIFIABLE_OFFLINE"
OUTCOME_NOT_RUN = "NOT_RUN"
OUTCOMES = (
    OUTCOME_VERIFIED,
    OUTCOME_INVALID,
    OUTCOME_UNVERIFIABLE,
    OUTCOME_NOT_RUN,
)

# ---------------------------------------------------------------------------
# Refusal codes.  Each is stable and names the wrong conclusion it prevents.
# ---------------------------------------------------------------------------

SB_REFUSED_MEDIATYPE = "SB_REFUSED_MEDIATYPE"
SB_REFUSED_VERSION = "SB_REFUSED_VERSION"
SB_REFUSED_BUNDLE_INVALID = "SB_REFUSED_BUNDLE_INVALID"
SB_REFUSED_MATERIAL = "SB_REFUSED_MATERIAL"
SB_REFUSED_CERT_CHAIN = "SB_REFUSED_CERT_CHAIN"
SB_REFUSED_CERT_ROOT_ABSENT = "SB_REFUSED_CERT_ROOT_ABSENT"
SB_REFUSED_EXPIRED_CERT = "SB_REFUSED_EXPIRED_CERT"
SB_REFUSED_ISSUER_MISMATCH = "SB_REFUSED_ISSUER_MISMATCH"
SB_REFUSED_IDENTITY_MISMATCH = "SB_REFUSED_IDENTITY_MISMATCH"
SB_REFUSED_PAYLOAD_DIGEST = "SB_REFUSED_PAYLOAD_DIGEST"
SB_REFUSED_TLOG_ABSENT = "SB_REFUSED_TLOG_ABSENT"
SB_REFUSED_TLOG_KIND = "SB_REFUSED_TLOG_KIND"
SB_REFUSED_INTEGRATED_TIME = "SB_REFUSED_INTEGRATED_TIME"
SB_REFUSED_INCLUSION_PROOF = "SB_REFUSED_INCLUSION_PROOF"
SB_REFUSED_LOG_KEY_ABSENT = "SB_REFUSED_LOG_KEY_ABSENT"
SB_REFUSED_TIMESTAMP_ABSENT = "SB_REFUSED_TIMESTAMP_ABSENT"
SB_REFUSED_TIMESTAMP_ROOT_ABSENT = "SB_REFUSED_TIMESTAMP_ROOT_ABSENT"
SB_REFUSED_TIMESTAMP_INVALID = "SB_REFUSED_TIMESTAMP_INVALID"
SB_REFUSED_SIGNATURE = "SB_REFUSED_SIGNATURE"
SB_REFUSED_DUPLICATE_KEY = "SB_REFUSED_DUPLICATE_KEY"
SB_REFUSED_POLICY_ABSENT = "SB_REFUSED_POLICY_ABSENT"
SB_REFUSED_NETWORK_OR_CLIENT = "SB_REFUSED_NETWORK_OR_CLIENT"
SB_REFUSED_INPUT_ABSENT = "SB_REFUSED_INPUT_ABSENT"

CODE_ORDER: tuple[str, ...] = (
    SB_REFUSED_MEDIATYPE,
    SB_REFUSED_VERSION,
    SB_REFUSED_BUNDLE_INVALID,
    SB_REFUSED_DUPLICATE_KEY,
    SB_REFUSED_MATERIAL,
    SB_REFUSED_CERT_CHAIN,
    SB_REFUSED_CERT_ROOT_ABSENT,
    SB_REFUSED_EXPIRED_CERT,
    SB_REFUSED_ISSUER_MISMATCH,
    SB_REFUSED_IDENTITY_MISMATCH,
    SB_REFUSED_PAYLOAD_DIGEST,
    SB_REFUSED_TLOG_ABSENT,
    SB_REFUSED_TLOG_KIND,
    SB_REFUSED_INTEGRATED_TIME,
    SB_REFUSED_INCLUSION_PROOF,
    SB_REFUSED_LOG_KEY_ABSENT,
    SB_REFUSED_TIMESTAMP_ABSENT,
    SB_REFUSED_TIMESTAMP_ROOT_ABSENT,
    SB_REFUSED_TIMESTAMP_INVALID,
    SB_REFUSED_SIGNATURE,
    SB_REFUSED_POLICY_ABSENT,
    SB_REFUSED_NETWORK_OR_CLIENT,
    SB_REFUSED_INPUT_ABSENT,
)

REFUSALS: dict[str, dict[str, str]] = {
    SB_REFUSED_MEDIATYPE: {
        "condition": (
            "the document is not a Sigstore bundle: mediaType is absent, is not a "
            "string, or names no Sigstore bundle profile"
        ),
        "prevents": (
            "that an arbitrary JSON object (an A10 envelope, a policy, an atlas "
            "record) is read as a Sigstore bundle"
        ),
    },
    SB_REFUSED_VERSION: {
        "condition": (
            "the mediaType names a Sigstore bundle version other than v0.3, "
            "including v0.1 and v0.2, whose shapes this item does not validate"
        ),
        "prevents": (
            "that a later or earlier bundle shape is read with v0.3 field names, "
            "so a field is silently absent and a check passes vacuously"
        ),
    },
    SB_REFUSED_BUNDLE_INVALID: {
        "condition": (
            "the bytes are not strict JSON, the top level is not an object, a "
            "top-level field is unknown, dsseEnvelope is absent or malformed, or "
            "the embedded DSSE envelope is not canonical base64"
        ),
        "prevents": (
            "that a malformed or partially shaped bundle is read as a bundle and "
            "a missing field becomes an empty default"
        ),
    },
    SB_REFUSED_MATERIAL: {
        "condition": (
            "verificationMaterial is absent or not an object, names neither "
            "x509CertificateChain nor publicKey, or carries publicKey material "
            "that this profile cannot bind to an issuer, SAN and validity window"
        ),
        "prevents": (
            "that a bundle with no signing material, or with material this profile "
            "cannot identify, is read as having a signing identity"
        ),
    },
    SB_REFUSED_CERT_CHAIN: {
        "condition": (
            "x509CertificateChain is not an object with a non-empty certificates "
            "list of canonical base64 DER certificates, a certificate is not "
            "parseable DER, or the supplied certificate verifier rejected the chain"
        ),
        "prevents": (
            "that an absent, malformed or rejected certificate chain is treated as "
            "a verified chain"
        ),
    },
    SB_REFUSED_CERT_ROOT_ABSENT: {
        "condition": (
            "no certificate verifier or CA root was supplied by policy, so the "
            "chain cannot be verified offline"
        ),
        "prevents": (
            "that an unverified certificate chain is treated as verified because "
            "the certificate parsed"
        ),
    },
    SB_REFUSED_EXPIRED_CERT: {
        "condition": (
            "the signing certificate is not yet valid or already expired at the "
            "transparency entry's integratedTime"
        ),
        "prevents": (
            "that a certificate valid at some other time is used to sign an entry "
            "made outside its validity window"
        ),
    },
    SB_REFUSED_ISSUER_MISMATCH: {
        "condition": (
            "the signing certificate's issuer does not equal the policy-supplied "
            "expected issuer"
        ),
        "prevents": (
            "that a certificate from another issuer is accepted under a policy "
            "that names a different one"
        ),
    },
    SB_REFUSED_IDENTITY_MISMATCH: {
        "condition": (
            "the signing certificate carries no SAN identity equal to the "
            "policy-supplied expected identity of the requested type"
        ),
        "prevents": (
            "that a certificate for a different workload or domain is accepted as "
            "the identity the policy names"
        ),
    },
    SB_REFUSED_PAYLOAD_DIGEST: {
        "condition": (
            "the SHA-256 of the DSSE payload bytes is not the SHA-256 of the "
            "artefact under verification"
        ),
        "prevents": (
            "that a signed payload for one artefact is presented as a signature "
            "over a different artefact"
        ),
    },
    SB_REFUSED_TLOG_ABSENT: {
        "condition": "verificationMaterial carries no tlogEntries, or the list is empty",
        "prevents": (
            "that a bundle with no transparency entry is read as logged and "
            "therefore omits nothing"
        ),
    },
    SB_REFUSED_TLOG_KIND: {
        "condition": (
            "a tlog entry's kindVersion is absent, or its kind/version is not the "
            "DSSE Rekor entry (dsse / 0.0.1)"
        ),
        "prevents": (
            "that a hashedrekord or another entry type is read as the DSSE entry "
            "for this envelope"
        ),
    },
    SB_REFUSED_INTEGRATED_TIME: {
        "condition": (
            "a tlog entry's logIndex or integratedTime is not a non-negative "
            "integer, the inclusion proof's logIndex disagrees with the entry, or "
            "treeSize does not cover logIndex"
        ),
        "prevents": (
            "that an entry with a malformed or inconsistent index/time is used to "
            "place the certificate's validity window"
        ),
    },
    SB_REFUSED_INCLUSION_PROOF: {
        "condition": (
            "a tlog entry has neither an inclusion promise nor an inclusion proof, "
            "the proof is malformed, or the supplied log verifier rejected it"
        ),
        "prevents": (
            "that an unproven or rejected log entry is treated as included in the "
            "log"
        ),
    },
    SB_REFUSED_LOG_KEY_ABSENT: {
        "condition": (
            "the policy supplied no transparency-log public key, or no log "
            "verifier was supplied, so inclusion cannot be checked offline"
        ),
        "prevents": (
            "that the presence of an inclusion proof is treated as proof that it "
            "verifies"
        ),
    },
    SB_REFUSED_TIMESTAMP_ABSENT: {
        "condition": "the bundle carries no RFC 3161 timestamp when the profile requires one",
        "prevents": (
            "that a bundle with no timestamp is read as having a freshness "
            "attestation"
        ),
    },
    SB_REFUSED_TIMESTAMP_ROOT_ABSENT: {
        "condition": (
            "no timestamp-authority root or timestamp verifier was supplied by "
            "policy, so the timestamp cannot be verified offline"
        ),
        "prevents": (
            "that an unverified timestamp is treated as a verified one"
        ),
    },
    SB_REFUSED_TIMESTAMP_INVALID: {
        "condition": (
            "an RFC 3161 timestamp is malformed, or the supplied timestamp "
            "verifier rejected it"
        ),
        "prevents": (
            "that a malformed or rejected timestamp is read as a freshness proof"
        ),
    },
    SB_REFUSED_SIGNATURE: {
        "condition": (
            "the DSSE signature is absent or malformed, or the supplied signature "
            "verifier rejected it, or no signature verifier was supplied"
        ),
        "prevents": (
            "that an unverified or rejected DSSE signature is treated as the "
            "envelope's authentication"
        ),
    },
    SB_REFUSED_DUPLICATE_KEY: {
        "condition": (
            "harden.loads found a duplicated object key at any depth in the bundle"
        ),
        "prevents": (
            "that a second mediaType, payload or integratedTime is silently "
            "discarded and a different field is the one validated"
        ),
    },
    SB_REFUSED_POLICY_ABSENT: {
        "condition": (
            "no policy supplied, or the policy lacks expectedIssuer or "
            "expectedIdentity, so the issuer and identity checks cannot run"
        ),
        "prevents": (
            "that a certificate is accepted with no expected issuer or identity, "
            "so any issuer and any SAN pass"
        ),
    },
    SB_REFUSED_NETWORK_OR_CLIENT: {
        "condition": (
            "the module source imports a network client or a process-spawning "
            "module, or calls a shell/Sigstore client"
        ),
        "prevents": (
            "that an 'offline' validator contacts a log or CA, or delegates to "
            "cosign, rekor-cli, sigstore, openssl or curl"
        ),
    },
    SB_REFUSED_INPUT_ABSENT: {
        "condition": "the bundle or the artefact named on the command line does not exist",
        "prevents": (
            "that an absent record is reported as validated; absence is NOT_RUN, "
            "never a pass"
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
# A minimal DER reader.  It extracts the certificate's *claimed* validity
# window, issuer and SAN.  It verifies no signature and builds no path: that is
# the caller's cert_verify.  A parsed fact is not an authenticated fact.
# ---------------------------------------------------------------------------


class CertificateError(Exception):
    """A DER certificate this profile cannot read."""


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise CertificateError("truncated length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise CertificateError("indefinite length is not DER")
    if count > 4:
        raise CertificateError("length exceeds the profile bound")
    if offset + count > len(data):
        raise CertificateError("truncated length")
    if data[offset] == 0:
        raise CertificateError("non-minimal length")
    length = int.from_bytes(data[offset : offset + count], "big")
    offset += count
    if length < 0x80:
        raise CertificateError("non-minimal length")
    return length, offset


def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise CertificateError("truncated tag")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise CertificateError("high-tag-number form is not used by this profile")
    length, offset = _der_length(data, offset)
    end = offset + length
    if end > len(data):
        raise CertificateError("truncated value")
    return tag, data[offset:end], end


def _der_children(body: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(body):
        tag, value, offset = _der_tlv(body, offset)
        children.append((tag, value))
    return children


def _der_oid(body: bytes) -> str:
    if not body:
        raise CertificateError("empty object identifier")
    first = body[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    pending = False
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            arcs.append(value)
            value = 0
    if pending:
        raise CertificateError("truncated object identifier")
    return ".".join(str(arc) for arc in arcs)


_STRING_TAGS = {
    0x0C: "utf-8",     # UTF8String
    0x12: "ascii",     # NumericString
    0x13: "ascii",     # PrintableString
    0x14: "latin-1",   # TeletexString
    0x16: "ascii",     # IA5String
    0x1A: "ascii",     # VisibleString
    0x1C: "utf-32-be", # UniversalString
    0x1E: "utf-16-be", # BMPString
}


def _der_string(tag: int, body: bytes) -> str:
    encoding = _STRING_TAGS.get(tag)
    if encoding is None:
        raise CertificateError(f"unsupported directory string tag 0x{tag:02x}")
    try:
        return body.decode(encoding)
    except UnicodeDecodeError as error:
        raise CertificateError(f"undecodable directory string: {error}") from error


_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}


def _escape_name_value(value: str) -> str:
    escaped = []
    for index, character in enumerate(value):
        if character in '\\,+=<>;"':
            escaped.append("\\" + character)
        elif character == " " and (index == 0 or index == len(value) - 1):
            escaped.append("\\ ")
        else:
            escaped.append(character)
    return "".join(escaped)


def _der_name(tag: int, body: bytes) -> str:
    if tag != 0x30:
        raise CertificateError("a Name is a SEQUENCE")
    rdns: list[str] = []
    for set_tag, set_body in _der_children(body):
        if set_tag != 0x31:
            raise CertificateError("a RelativeDistinguishedName is a SET")
        attributes: list[str] = []
        for atv_tag, atv_body in _der_children(set_body):
            if atv_tag != 0x30:
                raise CertificateError("an AttributeTypeAndValue is a SEQUENCE")
            parts = _der_children(atv_body)
            if len(parts) != 2 or parts[0][0] != 0x06:
                raise CertificateError("an AttributeTypeAndValue is (OID, value)")
            key = _OID_NAMES.get(_der_oid(parts[0][1]), _der_oid(parts[0][1]))
            attributes.append(f"{key}={_escape_name_value(_der_string(*parts[1]))}")
        attributes.sort()
        rdns.append("+".join(attributes))
    return ",".join(rdns)


_UTC_TIME = 0x17
_GENERALIZED_TIME = 0x18


def _der_time(tag: int, body: bytes) -> datetime:
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as error:
        raise CertificateError(f"a time is ASCII: {error}") from error
    if not text.endswith("Z"):
        raise CertificateError("a profile time ends with Z")
    digits = text[:-1]
    if not digits.isdigit():
        raise CertificateError("a profile time is decimal digits and Z")
    if tag == _UTC_TIME:
        if len(digits) != 12:
            raise CertificateError("UTCTime is YYMMDDHHMMSSZ")
        year = int(digits[0:2])
        year += 1900 if year >= 50 else 2000
        rest = digits[2:]
    elif tag == _GENERALIZED_TIME:
        if len(digits) != 14:
            raise CertificateError("GeneralizedTime is YYYYMMDDHHMMSSZ")
        year = int(digits[0:4])
        rest = digits[4:]
    else:
        raise CertificateError(f"unsupported time tag 0x{tag:02x}")
    try:
        return datetime(
            year,
            int(rest[0:2]),
            int(rest[2:4]),
            int(rest[4:6]),
            int(rest[6:8]),
            int(rest[8:10]),
            tzinfo=timezone.utc,
        )
    except ValueError as error:
        raise CertificateError(f"invalid time field: {error}") from error


_SAN_OID = "2.5.29.17"


def _general_names(octets: bytes) -> list[dict[str, str]]:
    tag, body, end = _der_tlv(octets, 0)
    if tag != 0x30 or end != len(octets):
        raise CertificateError("subjectAltName is a SEQUENCE")
    names: list[dict[str, str]] = []
    for name_tag, value in _der_children(body):
        if name_tag in (0x81, 0x82, 0x86):
            try:
                text = value.decode("ascii")
            except UnicodeDecodeError as error:
                raise CertificateError(f"a GeneralName is IA5String: {error}") from error
            kind = {0x81: "email", 0x82: "dns", 0x86: "uri"}[name_tag]
            names.append({"type": kind, "value": text})
        elif name_tag == 0x87:
            names.append({"type": "ip", "value": value.hex()})
    return names


def _extensions(body: bytes) -> list[dict[str, str]]:
    tag, inner, end = _der_tlv(body, 0)
    if tag != 0x30 or end != len(body):
        raise CertificateError("extensions is a SEQUENCE")
    names: list[dict[str, str]] = []
    for extension_tag, extension_body in _der_children(inner):
        if extension_tag != 0x30:
            raise CertificateError("an Extension is a SEQUENCE")
        parts = _der_children(extension_body)
        if len(parts) < 2 or parts[0][0] != 0x06:
            raise CertificateError("an Extension starts with an OID")
        oid = _der_oid(parts[0][1])
        value = parts[-1]
        if value[0] != 0x04:
            raise CertificateError("an Extension value is an OCTET STRING")
        if oid == _SAN_OID:
            names.extend(_general_names(value[1]))
    return names


def parse_certificate(der_bytes: bytes) -> dict[str, Any]:
    """Extract the *claimed* validity window, issuer and SAN from a certificate.

    This is a structural parse.  It verifies no signature, builds no path,
    checks no revocation and decides no trust.  The issuer string is what the
    certificate says about itself; it becomes an authenticated issuer only if
    ``cert_verify`` accepts the chain.
    """
    tag, body, end = _der_tlv(der_bytes, 0)
    if tag != 0x30 or end != len(der_bytes):
        raise CertificateError("a Certificate is one SEQUENCE of the whole input")
    parts = _der_children(body)
    if len(parts) != 3:
        raise CertificateError("a Certificate is (tbsCertificate, algorithm, signature)")
    if parts[0][0] != 0x30 or parts[1][0] != 0x30 or parts[2][0] != 0x03:
        raise CertificateError("a Certificate has the wrong component tags")
    fields = _der_children(parts[0][1])
    index = 0
    if fields and fields[0][0] == 0xA0:
        version = _der_children(fields[0][1])
        if len(version) != 1 or version[0][0] != 0x02:
            raise CertificateError("version is [0] EXPLICIT INTEGER")
        index = 1
    if len(fields) < index + 6:
        raise CertificateError("tbsCertificate is missing a required field")
    serial, signature, issuer, validity, subject, _spki = fields[index : index + 6]
    if serial[0] != 0x02:
        raise CertificateError("serialNumber is an INTEGER")
    if signature[0] != 0x30 or issuer[0] != 0x30 or validity[0] != 0x30:
        raise CertificateError("tbsCertificate field tags are wrong")
    if subject[0] != 0x30:
        raise CertificateError("subject is a Name")
    times = _der_children(validity[1])
    if len(times) != 2:
        raise CertificateError("Validity is (notBefore, notAfter)")
    not_before = _der_time(*times[0])
    not_after = _der_time(*times[1])
    if not_before > not_after:
        raise CertificateError("notBefore is after notAfter")
    identities: list[dict[str, str]] = []
    for extension_tag, extension_body in fields[index + 6 :]:
        if extension_tag == 0xA3:
            identities.extend(_extensions(extension_body))
        elif extension_tag not in (0x81, 0x82):
            raise CertificateError("unexpected tbsCertificate field")
    return {
        "notBefore": not_before.isoformat().replace("+00:00", "Z"),
        "notAfter": not_after.isoformat().replace("+00:00", "Z"),
        "notBeforeEpoch": int(not_before.timestamp()),
        "notAfterEpoch": int(not_after.timestamp()),
        "issuer": _der_name(*issuer),
        "subject": _der_name(*subject),
        "identities": identities,
        "sha256": sha256_bytes(der_bytes),
    }


def _epoch_seconds(value: int) -> datetime:
    if value < 0 or value > 253402300799:
        raise CertificateError("integratedTime is outside the representable range")
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=value)


# ---------------------------------------------------------------------------
# The bundle profile.  Written to evidence/a16/PROFILE.json by the producer.
# ---------------------------------------------------------------------------


def bundle_profile() -> dict[str, Any]:
    """The profile this validator implements, field by field."""
    return {
        "schema": PROFILE_SCHEMA,
        "model": MODEL_ID,
        "mediaType": MEDIA_TYPE_V03,
        "supportedVersions": [SUPPORTED_VERSION],
        "refusedVersions": list(REFUSED_VERSIONS),
        "refusedVersionBehaviour": (
            "v0.1 and v0.2 use a different shape and a versioned media type; they "
            "are refused with SB_REFUSED_VERSION rather than read with v0.3 names"
        ),
        "fields": [
            {
                "path": "mediaType",
                "required": True,
                "type": "string",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_MEDIATYPE,
                "cannotEstablish": "that the bundle was produced by any particular tool",
            },
            {
                "path": "verificationMaterial",
                "required": True,
                "type": "object",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_MATERIAL,
                "cannotEstablish": "that the signing material belongs to the expected party",
            },
            {
                "path": "verificationMaterial.x509CertificateChain.certificates[].rawBytes",
                "required": True,
                "type": "list of canonical base64 DER certificates",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_CERT_CHAIN,
                "cannotEstablish": "that any certificate is signed by a trusted CA",
            },
            {
                "path": "certificate.validity",
                "required": True,
                "type": "notBefore <= integratedTime <= notAfter",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_EXPIRED_CERT,
                "cannotEstablish": "that the certificate was not revoked after issue",
            },
            {
                "path": "certificate.issuer",
                "required": True,
                "type": "string, policy compared",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_ISSUER_MISMATCH,
                "cannotEstablish": "that the issuer actually issued this certificate until cert_verify accepts the path",
            },
            {
                "path": "certificate.subjectAltName",
                "required": True,
                "type": "SAN identity, policy compared",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_IDENTITY_MISMATCH,
                "cannotEstablish": "that the workload actually controls the identity until cert_verify accepts the path",
            },
            {
                "path": "dsseEnvelope.payload",
                "required": True,
                "type": "canonical base64 bytes",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_PAYLOAD_DIGEST,
                "cannotEstablish": "that the payload is true, only that its bytes are the artefact's bytes",
            },
            {
                "path": "dsseEnvelope.signatures[].sig",
                "required": True,
                "type": "canonical base64 signature over the DSSE PAE",
                "offlineCheckable": "caller-supplied only",
                "checkedBy": SB_REFUSED_SIGNATURE,
                "cannotEstablish": "that the signature verifies without a signature verifier",
            },
            {
                "path": "verificationMaterial.tlogEntries[]",
                "required": True,
                "type": "non-empty list",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_TLOG_ABSENT,
                "cannotEstablish": "that the log is honest or append-only",
            },
            {
                "path": "tlogEntries[].kindVersion",
                "required": True,
                "type": "{kind: dsse, version: 0.0.1}",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_TLOG_KIND,
                "cannotEstablish": "that the entry body is the envelope in this bundle",
            },
            {
                "path": "tlogEntries[].logIndex and .integratedTime",
                "required": True,
                "type": "non-negative integers; proof index agrees",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_INTEGRATED_TIME,
                "cannotEstablish": "that the log assigned the index or time",
            },
            {
                "path": "tlogEntries[].inclusionPromise | .inclusionProof",
                "required": True,
                "type": "one of the two, structurally valid",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_INCLUSION_PROOF,
                "cannotEstablish": "that the proof is valid without the log public key",
            },
            {
                "path": "verificationMaterial.timestampVerificationData.rfc3161Timestamps[]",
                "required": True,
                "type": "non-empty list of signed timestamps",
                "offlineCheckable": True,
                "checkedBy": SB_REFUSED_TIMESTAMP_ABSENT,
                "cannotEstablish": "that the timestamp authority signed it without the TSA root",
            },
        ],
        "trustRoots": {
            "logPublicKey": {
                "suppliedBy": "policy.logKey, verified by the caller's log_verify",
                "presentInTree": False,
                "absentCode": SB_REFUSED_LOG_KEY_ABSENT,
                "cannotCheckOffline": "whether the log is append-only, honest or globally consistent",
            },
            "caRoot": {
                "suppliedBy": "policy.caRoots, verified by the caller's cert_verify",
                "presentInTree": False,
                "absentCode": SB_REFUSED_CERT_ROOT_ABSENT,
                "cannotCheckOffline": "revocation (OCSP/CRL), name constraints across a real path, and whether the CA is trustworthy",
            },
            "timestampAuthorityRoot": {
                "suppliedBy": "policy.timestampRoots, verified by the caller's timestamp_verify",
                "presentInTree": False,
                "absentCode": SB_REFUSED_TIMESTAMP_ROOT_ABSENT,
                "cannotCheckOffline": "whether the TSA's clock was correct at signing time",
            },
            "expectedIssuerAndIdentity": {
                "suppliedBy": "policy.expectedIssuer and policy.expectedIdentity",
                "presentInTree": False,
                "absentCode": SB_REFUSED_POLICY_ABSENT,
                "cannotCheckOffline": "that the expected identity is the one the policy writer intended",
            },
        },
        "freshness": {
            "integratedTime": "from the tlog entry, used to place the certificate validity window",
            "certificateWindow": "inclusive: notBefore <= integratedTime <= notAfter",
            "timestamp": "required by this profile; its own verification is NOT_RUN without a TSA root",
            "liveClock": "not consulted; a bundle is judged at its integratedTime, not at the validator's clock",
            "cannotCheckOffline": "whether the log's integratedTime is earlier than a later revocation",
        },
        "outcomes": list(OUTCOMES),
        "nonClaims": [
            "BUNDLE_VERIFIED_OFFLINE is not a judgement that the log or the CA is trustworthy",
            "BUNDLE_VERIFIED_OFFLINE does not mean the payload is true",
            "no bundle exists in this tree, so no real bundle is verified",
        ],
    }


# ---------------------------------------------------------------------------
# Recording and evaluation.
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.not_run: list[str] = []

    def passed(self, check: str, detail: str = "") -> None:
        self.checks.append(
            {"check": check, "status": "pass", "code": None, "detail": detail}
        )

    def refused(self, check: str, code: str, detail: str) -> None:
        self.checks.append(
            {"check": check, "status": "fail", "code": code, "detail": detail}
        )
        raise Refusal(code, detail)

    def skipped(self, check: str, code: str, detail: str) -> None:
        self.checks.append(
            {"check": check, "status": "not-run", "code": code, "detail": detail}
        )
        self.not_run.append(code)


def _ordered_codes(codes: list[str]) -> list[str]:
    unique = set(codes)
    ordered = [code for code in CODE_ORDER if code in unique]
    ordered.extend(sorted(unique - set(ordered)))
    return ordered


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _b64(value: Any, where: str, code: str) -> bytes:
    try:
        return dsse.strict_b64decode(value, where)
    except dsse.Refusal as refusal:
        _fail(code, f"{where}: {refusal.message}")


def _strict_bundle(bundle_bytes: bytes) -> dict[str, Any]:
    try:
        document = harden.loads(bundle_bytes)
    except harden.Refusal as refusal:
        if refusal.code == harden.PH_REFUSED_DUPLICATE_KEY:
            _fail(SB_REFUSED_DUPLICATE_KEY, refusal.message)
        _fail(SB_REFUSED_BUNDLE_INVALID, f"the strict reader refused the bundle: {refusal.message}")
    if not isinstance(document, dict):
        _fail(SB_REFUSED_BUNDLE_INVALID, "a bundle is a JSON object")
    return document


def _policy_value(policy: Mapping[str, Any] | None, key: str) -> Any:
    if not isinstance(policy, Mapping):
        return None
    return policy.get(key)


def _evaluate(
    bundle_bytes: bytes,
    artefact_bytes: bytes,
    policy: Mapping[str, Any] | None,
    cert_verify: Callable[..., bool] | None,
    signature_verify: Callable[..., bool] | None,
    log_verify: Callable[..., bool] | None,
    timestamp_verify: Callable[..., bool] | None,
    recorder: _Recorder,
    facts: dict[str, Any],
) -> None:
    document = _strict_bundle(bundle_bytes)
    recorder.passed("strict-json", "parsed by harden.loads with duplicate-key detection")

    media_type = document.get("mediaType")
    if not isinstance(media_type, str) or not media_type:
        recorder.refused(
            "media-type",
            SB_REFUSED_MEDIATYPE,
            "mediaType is a non-empty string naming a Sigstore bundle profile",
        )
    facts["mediaType"] = media_type
    if media_type != MEDIA_TYPE_V03:
        if SIGSTORE_BUNDLE_PREFIX in media_type:
            recorder.refused(
                "media-type",
                SB_REFUSED_VERSION,
                f"mediaType {media_type!r} is not {MEDIA_TYPE_V03!r}; the v0.1 and "
                "v0.2 shapes are not validated by this item and are refused as "
                "unsupported versions",
            )
        recorder.refused(
            "media-type",
            SB_REFUSED_MEDIATYPE,
            f"mediaType {media_type!r} names no Sigstore bundle profile",
        )
    recorder.passed("media-type", MEDIA_TYPE_V03)

    if set(document) - {"mediaType", "verificationMaterial", "dsseEnvelope"}:
        recorder.refused(
            "bundle-shape",
            SB_REFUSED_BUNDLE_INVALID,
            "a v0.3 bundle has mediaType, verificationMaterial and dsseEnvelope; "
            f"this one also has {sorted(set(document) - {'mediaType', 'verificationMaterial', 'dsseEnvelope'})}",
        )
    envelope = document.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        recorder.refused(
            "bundle-shape",
            SB_REFUSED_BUNDLE_INVALID,
            "dsseEnvelope is a JSON object",
        )
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        recorder.refused(
            "bundle-shape",
            SB_REFUSED_BUNDLE_INVALID,
            "the embedded DSSE envelope has exactly payloadType, payload and "
            f"signatures, not {sorted(envelope)}",
        )
    payload_type = envelope.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        recorder.refused(
            "bundle-shape", SB_REFUSED_BUNDLE_INVALID, "payloadType is a non-empty string"
        )
    if not isinstance(envelope.get("payload"), str):
        recorder.refused(
            "bundle-shape", SB_REFUSED_BUNDLE_INVALID, "payload is a base64 string"
        )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        recorder.refused(
            "bundle-shape",
            SB_REFUSED_SIGNATURE,
            "the DSSE envelope carries a non-empty signatures list",
        )
    payload = _b64(envelope["payload"], "dsseEnvelope.payload", SB_REFUSED_BUNDLE_INVALID)
    facts["payloadSha256"] = sha256_bytes(payload)
    facts["payloadType"] = payload_type
    recorder.passed("bundle-shape", "the embedded DSSE envelope is present and shaped")

    material = document.get("verificationMaterial")
    if not isinstance(material, dict):
        recorder.refused(
            "verification-material",
            SB_REFUSED_MATERIAL,
            "verificationMaterial is a JSON object",
        )
    chain = material.get("x509CertificateChain")
    public_key = material.get("publicKey")
    if chain is None and public_key is None:
        recorder.refused(
            "verification-material",
            SB_REFUSED_MATERIAL,
            "verificationMaterial names x509CertificateChain or publicKey",
        )
    if chain is None:
        recorder.refused(
            "verification-material",
            SB_REFUSED_MATERIAL,
            "publicKey material carries no issuer, SAN or validity window; this "
            "profile requires x509CertificateChain",
        )
    if not isinstance(chain, dict):
        recorder.refused(
            "certificate-chain", SB_REFUSED_CERT_CHAIN, "x509CertificateChain is an object"
        )
    certificates = chain.get("certificates")
    if not isinstance(certificates, list) or not certificates:
        recorder.refused(
            "certificate-chain",
            SB_REFUSED_CERT_CHAIN,
            "x509CertificateChain.certificates is a non-empty list",
        )
    chain_ders: list[bytes] = []
    for index, certificate in enumerate(certificates):
        if not isinstance(certificate, dict) or not isinstance(certificate.get("rawBytes"), str):
            recorder.refused(
                "certificate-chain",
                SB_REFUSED_CERT_CHAIN,
                f"certificates[{index}].rawBytes is a base64 string",
            )
        chain_ders.append(
            _b64(certificate["rawBytes"], f"certificates[{index}].rawBytes", SB_REFUSED_CERT_CHAIN)
        )
    leaf_der = chain_ders[0]
    try:
        certificate_info = parse_certificate(leaf_der)
        for index, other in enumerate(chain_ders[1:], start=1):
            parse_certificate(other)
    except CertificateError as error:
        recorder.refused(
            "certificate-chain",
            SB_REFUSED_CERT_CHAIN,
            f"the certificate chain is not parseable DER: {error}",
        )
    facts["certificate"] = certificate_info
    facts["certificateChainLength"] = len(chain_ders)
    recorder.passed(
        "certificate-chain",
        f"{len(chain_ders)} certificate(s); the claimed window is "
        f"{certificate_info['notBefore']}..{certificate_info['notAfter']}",
    )

    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or not entries:
        recorder.refused(
            "tlog-entry",
            SB_REFUSED_TLOG_ABSENT,
            "verificationMaterial.tlogEntries is a non-empty list",
        )
    entry_facts: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            recorder.refused(
                "tlog-entry", SB_REFUSED_TLOG_ABSENT, f"tlogEntries[{index}] is an object"
            )
    recorder.passed("tlog-entry", f"{len(entries)} transparency entr(ies) present")

    for index, entry in enumerate(entries):
        kind_version = entry.get("kindVersion")
        if (
            not isinstance(kind_version, dict)
            or kind_version.get("kind") != TLOG_KIND
            or kind_version.get("version") != TLOG_API_VERSION
        ):
            recorder.refused(
                "tlog-kind",
                SB_REFUSED_TLOG_KIND,
                f"tlogEntries[{index}].kindVersion is {{kind: {TLOG_KIND!r}, "
                f"version: {TLOG_API_VERSION!r}}}, not {kind_version!r}",
            )
    recorder.passed("tlog-kind", f"every entry is {TLOG_KIND}/{TLOG_API_VERSION}")

    integrated_times: list[int] = []
    for index, entry in enumerate(entries):
        log_index = entry.get("logIndex")
        integrated_time = entry.get("integratedTime")
        if not _is_int(log_index) or log_index < 0:
            recorder.refused(
                "integrated-time",
                SB_REFUSED_INTEGRATED_TIME,
                f"tlogEntries[{index}].logIndex is a non-negative integer",
            )
        if not _is_int(integrated_time) or integrated_time <= 0:
            recorder.refused(
                "integrated-time",
                SB_REFUSED_INTEGRATED_TIME,
                f"tlogEntries[{index}].integratedTime is a positive integer",
            )
        proof = entry.get("inclusionProof")
        if isinstance(proof, dict):
            if proof.get("logIndex") != log_index:
                recorder.refused(
                    "integrated-time",
                    SB_REFUSED_INTEGRATED_TIME,
                    f"tlogEntries[{index}].inclusionProof.logIndex "
                    f"{proof.get('logIndex')!r} disagrees with logIndex {log_index!r}",
                )
            tree_size = proof.get("treeSize")
            if not _is_int(tree_size) or tree_size <= log_index:
                recorder.refused(
                    "integrated-time",
                    SB_REFUSED_INTEGRATED_TIME,
                    f"tlogEntries[{index}].inclusionProof.treeSize must cover logIndex",
                )
        integrated_times.append(integrated_time)
        entry_facts.append(
            {
                "logIndex": log_index,
                "integratedTime": integrated_time,
                "kind": TLOG_KIND,
                "version": TLOG_API_VERSION,
            }
        )
    facts["tlogEntries"] = entry_facts
    recorder.passed(
        "integrated-time",
        f"logIndex/integratedTime are consistent: {[e['integratedTime'] for e in entry_facts]}",
    )

    for integrated_time in integrated_times:
        try:
            moment = _epoch_seconds(integrated_time)
        except CertificateError as error:
            recorder.refused(
                "certificate-window", SB_REFUSED_INTEGRATED_TIME, str(error)
            )
        iso = moment.isoformat().replace("+00:00", "Z")
        if integrated_time < certificate_info["notBeforeEpoch"]:
            recorder.refused(
                "certificate-window",
                SB_REFUSED_EXPIRED_CERT,
                f"the certificate is not yet valid: integratedTime {iso} precedes "
                f"notBefore {certificate_info['notBefore']}",
            )
        if integrated_time > certificate_info["notAfterEpoch"]:
            recorder.refused(
                "certificate-window",
                SB_REFUSED_EXPIRED_CERT,
                f"the certificate is expired: integratedTime {iso} is after "
                f"notAfter {certificate_info['notAfter']}",
            )
    recorder.passed(
        "certificate-window",
        "every integratedTime is inside the certificate validity window",
    )

    expected_issuer = _policy_value(policy, "expectedIssuer")
    expected_identity = _policy_value(policy, "expectedIdentity")
    if not isinstance(expected_issuer, str) or not expected_issuer:
        recorder.skipped(
            "issuer-policy",
            SB_REFUSED_POLICY_ABSENT,
            "no policy supplied an expected issuer, so the issuer is not checked",
        )
    elif certificate_info["issuer"] != expected_issuer:
        recorder.refused(
            "issuer-policy",
            SB_REFUSED_ISSUER_MISMATCH,
            f"the certificate claims issuer {certificate_info['issuer']!r}, the "
            f"policy expects {expected_issuer!r}",
        )
    else:
        recorder.passed("issuer-policy", "the certificate's issuer equals the policy")

    if not isinstance(expected_identity, str) or not expected_identity:
        recorder.skipped(
            "identity-policy",
            SB_REFUSED_POLICY_ABSENT,
            "no policy supplied an expected identity, so the SAN is not checked",
        )
    else:
        identity_type = _policy_value(policy, "identityType")
        matches = [
            identity
            for identity in certificate_info["identities"]
            if identity["value"] == expected_identity
            and (identity_type is None or identity["type"] == identity_type)
        ]
        if not matches:
            recorder.refused(
                "identity-policy",
                SB_REFUSED_IDENTITY_MISMATCH,
                f"no SAN identity equals {expected_identity!r}"
                + (f" of type {identity_type!r}" if identity_type else "")
                + f"; the certificate carries {certificate_info['identities']!r}",
            )
        recorder.passed("identity-policy", f"the SAN contains {expected_identity!r}")

    artefact_digest = sha256_bytes(artefact_bytes)
    if facts["payloadSha256"] != artefact_digest:
        recorder.refused(
            "payload-digest",
            SB_REFUSED_PAYLOAD_DIGEST,
            f"the DSSE payload digest {facts['payloadSha256']} is not the artefact "
            f"digest {artefact_digest}",
        )
    recorder.passed("payload-digest", "the payload bytes are the artefact bytes")

    proof_objects: list[Any] = []
    for index, entry in enumerate(entries):
        promise = entry.get("inclusionPromise")
        proof = entry.get("inclusionProof")
        if promise is None and proof is None:
            recorder.refused(
                "inclusion-present",
                SB_REFUSED_INCLUSION_PROOF,
                f"tlogEntries[{index}] has neither an inclusion promise nor an "
                "inclusion proof",
            )
        if promise is not None:
            if not isinstance(promise, dict) or not isinstance(
                promise.get("signedEntryTimestamp"), str
            ):
                recorder.refused(
                    "inclusion-present",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"tlogEntries[{index}].inclusionPromise.signedEntryTimestamp is "
                    "a base64 string",
                )
            _b64(
                promise["signedEntryTimestamp"],
                f"tlogEntries[{index}].inclusionPromise.signedEntryTimestamp",
                SB_REFUSED_INCLUSION_PROOF,
            )
        if proof is not None:
            if not isinstance(proof, dict):
                recorder.refused(
                    "inclusion-present",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"tlogEntries[{index}].inclusionProof is an object",
                )
            root = _b64(
                proof.get("rootHash"),
                f"tlogEntries[{index}].inclusionProof.rootHash",
                SB_REFUSED_INCLUSION_PROOF,
            )
            if len(root) != 32:
                recorder.refused(
                    "inclusion-present",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"tlogEntries[{index}].inclusionProof.rootHash is a 32-byte digest",
                )
            hashes = proof.get("hashes")
            if not isinstance(hashes, list):
                recorder.refused(
                    "inclusion-present",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"tlogEntries[{index}].inclusionProof.hashes is a list",
                )
            for hash_index, value in enumerate(hashes):
                decoded = _b64(
                    value,
                    f"tlogEntries[{index}].inclusionProof.hashes[{hash_index}]",
                    SB_REFUSED_INCLUSION_PROOF,
                )
                if len(decoded) != 32:
                    recorder.refused(
                        "inclusion-present",
                        SB_REFUSED_INCLUSION_PROOF,
                        f"tlogEntries[{index}].inclusionProof.hashes[{hash_index}] "
                        "is a 32-byte digest",
                    )
            checkpoint = proof.get("checkpoint")
            if not isinstance(checkpoint, dict) or not isinstance(
                checkpoint.get("envelope"), str
            ) or not checkpoint.get("envelope"):
                recorder.refused(
                    "inclusion-present",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"tlogEntries[{index}].inclusionProof.checkpoint.envelope is a "
                    "non-empty string",
                )
        proof_objects.append(proof if proof is not None else promise)
    recorder.passed(
        "inclusion-present",
        "every entry carries an inclusion promise or a structurally valid proof",
    )

    log_key = _policy_value(policy, "logKey")
    if not log_key:
        recorder.skipped(
            "inclusion-verified",
            SB_REFUSED_LOG_KEY_ABSENT,
            "no transparency-log public key was supplied by policy, so inclusion "
            "is NOT_RUN (presence is not verification)",
        )
    elif log_verify is None:
        recorder.skipped(
            "inclusion-verified",
            SB_REFUSED_LOG_KEY_ABSENT,
            "a log key is recorded but no log_verify callable was supplied, so "
            "inclusion is NOT_RUN",
        )
    else:
        for index, entry in enumerate(entry_facts):
            if not log_verify(log_key, entry, proof_objects[index]):
                recorder.refused(
                    "inclusion-verified",
                    SB_REFUSED_INCLUSION_PROOF,
                    f"the supplied log verifier rejected tlogEntries[{index}]",
                )
        recorder.passed(
            "inclusion-verified", "the supplied log verifier accepted every entry"
        )

    if signature_verify is None:
        recorder.skipped(
            "dsse-signature",
            SB_REFUSED_SIGNATURE,
            "no signature verifier was supplied, so the DSSE signature is NOT_RUN",
        )
    else:
        def verifier(keyid: str, pae_bytes: bytes, signature: bytes) -> bool:
            return bool(
                signature_verify(payload_type, pae_bytes, signature, leaf_der)
            )

        try:
            dsse.verify_pae(dsse.encode_envelope(envelope), verifier)
        except dsse.Refusal as refusal:
            recorder.refused(
                "dsse-signature",
                SB_REFUSED_SIGNATURE,
                f"the embedded envelope did not verify ({refusal})",
            )
        recorder.passed("dsse-signature", "the supplied signature verifier accepted the envelope")

    if cert_verify is None:
        recorder.skipped(
            "certificate-path",
            SB_REFUSED_CERT_ROOT_ABSENT,
            "no CA root or certificate verifier was supplied, so the chain is NOT_RUN",
        )
    else:
        accepted = bool(
            cert_verify(
                leaf_der,
                chain_ders,
                min(integrated_times),
                expected_issuer,
                expected_identity,
            )
        )
        if not accepted:
            recorder.refused(
                "certificate-path",
                SB_REFUSED_CERT_CHAIN,
                "the supplied certificate verifier rejected the chain",
            )
        recorder.passed(
            "certificate-path", "the supplied certificate verifier accepted the chain"
        )

    timestamp_data = material.get("timestampVerificationData")
    stamps = timestamp_data.get("rfc3161Timestamps") if isinstance(timestamp_data, dict) else None
    if not isinstance(stamps, list) or not stamps:
        recorder.refused(
            "timestamp-present",
            SB_REFUSED_TIMESTAMP_ABSENT,
            "verificationMaterial.timestampVerificationData.rfc3161Timestamps is "
            "a non-empty list; this profile requires a timestamp",
        )
    stamp_bytes: list[bytes] = []
    for index, stamp in enumerate(stamps):
        if not isinstance(stamp, dict) or not isinstance(stamp.get("signedTimestamp"), str):
            recorder.refused(
                "timestamp-present",
                SB_REFUSED_TIMESTAMP_INVALID,
                f"rfc3161Timestamps[{index}].signedTimestamp is a base64 string",
            )
        stamp_bytes.append(
            _b64(
                stamp["signedTimestamp"],
                f"rfc3161Timestamps[{index}].signedTimestamp",
                SB_REFUSED_TIMESTAMP_INVALID,
            )
        )
    recorder.passed("timestamp-present", f"{len(stamps)} RFC 3161 timestamp(s) present")

    timestamp_root = _policy_value(policy, "timestampRoots")
    if not timestamp_root:
        recorder.skipped(
            "timestamp-verified",
            SB_REFUSED_TIMESTAMP_ROOT_ABSENT,
            "no timestamp-authority root was supplied by policy, so the timestamp "
            "is NOT_RUN",
        )
    elif timestamp_verify is None:
        recorder.skipped(
            "timestamp-verified",
            SB_REFUSED_TIMESTAMP_ROOT_ABSENT,
            "a timestamp root is recorded but no timestamp_verify callable was "
            "supplied, so the timestamp is NOT_RUN",
        )
    else:
        for index, raw in enumerate(stamp_bytes):
            if not timestamp_verify(raw, artefact_digest, leaf_der):
                recorder.refused(
                    "timestamp-verified",
                    SB_REFUSED_TIMESTAMP_INVALID,
                    f"the supplied timestamp verifier rejected rfc3161Timestamps[{index}]",
                )
        recorder.passed(
            "timestamp-verified", "the supplied timestamp verifier accepted every timestamp"
        )


def _base_report() -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "model": MODEL_ID,
        "profileMediaType": MEDIA_TYPE_V03,
        "outcome": None,
        "code": None,
        "codes": [],
        "checks": [],
        "notRun": [],
        "bundleSha256": None,
        "artefactSha256": None,
        "payloadSha256": None,
        "mediaType": None,
        "certificate": None,
        "tlogEntries": [],
    }


def validate_bundle(
    bundle_bytes: Any,
    artefact_bytes: Any,
    *,
    policy: Mapping[str, Any] | None = None,
    cert_verify: Callable[..., bool] | None = None,
    signature_verify: Callable[..., bool] | None = None,
    log_verify: Callable[..., bool] | None = None,
    timestamp_verify: Callable[..., bool] | None = None,
) -> dict[str, Any]:
    """Validate one bundle offline against the supplied policy and verifiers.

    ``cert_verify``, ``signature_verify``, ``log_verify`` and
    ``timestamp_verify`` are the caller's trust decisions; this module supplies
    none.  A check whose verifier or root is absent is ``NOT_RUN``, and the
    outcome is then ``BUNDLE_UNVERIFIABLE_OFFLINE``, never ``VERIFIED``.
    """
    if not isinstance(bundle_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("validate_bundle takes the bundle's received bytes")
    if not isinstance(artefact_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("validate_bundle takes the artefact's bytes")
    for name, callable_ in (
        ("cert_verify", cert_verify),
        ("signature_verify", signature_verify),
        ("log_verify", log_verify),
        ("timestamp_verify", timestamp_verify),
    ):
        if callable_ is not None and not callable(callable_):
            raise TypeError(f"{name} is a callable or None")

    raw = bytes(bundle_bytes)
    artefact = bytes(artefact_bytes)
    recorder = _Recorder()
    facts: dict[str, Any] = {}
    report = _base_report()
    report["bundleSha256"] = sha256_bytes(raw)
    report["artefactSha256"] = sha256_bytes(artefact)

    try:
        try:
            _evaluate(
                raw,
                artefact,
                policy,
                cert_verify,
                signature_verify,
                log_verify,
                timestamp_verify,
                recorder,
                facts,
            )
        except Refusal as refusal:
            if not any(
                check["status"] == "fail" and check["code"] == refusal.code
                for check in recorder.checks
            ):
                recorder.checks.append(
                    {
                        "check": "refusal",
                        "status": "fail",
                        "code": refusal.code,
                        "detail": refusal.message,
                    }
                )
            raise
    except Refusal as refusal:
        report["outcome"] = OUTCOME_INVALID
        report["code"] = refusal.code
        report["codes"] = [refusal.code]
        report["checks"] = recorder.checks
        report["notRun"] = _ordered_codes(recorder.not_run)
        report.update(_facts(facts))
        return report

    report["checks"] = recorder.checks
    report["notRun"] = _ordered_codes(recorder.not_run)
    report.update(_facts(facts))
    if recorder.not_run:
        codes = _ordered_codes(recorder.not_run)
        report["outcome"] = OUTCOME_UNVERIFIABLE
        report["code"] = codes[0]
        report["codes"] = codes
        return report
    report["outcome"] = OUTCOME_VERIFIED
    report["code"] = CODE_OK
    report["codes"] = []
    return report


def _facts(facts: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "mediaType": facts.get("mediaType"),
        "payloadSha256": facts.get("payloadSha256"),
        "payloadType": facts.get("payloadType"),
        "certificate": facts.get("certificate"),
        "certificateChainLength": facts.get("certificateChainLength"),
        "tlogEntries": facts.get("tlogEntries", []),
    }


def not_run_report(code: str, detail: str) -> dict[str, Any]:
    """A report for a record that does not exist.  Absence is never a pass."""
    report = _base_report()
    report["outcome"] = OUTCOME_NOT_RUN
    report["code"] = code
    report["codes"] = [code]
    report["checks"] = [
        {"check": "input-present", "status": "not-run", "code": code, "detail": detail}
    ]
    report["notRun"] = [code]
    return report


def validate_paths(
    bundle_path: Path | str,
    artefact_path: Path | str,
    *,
    policy: Mapping[str, Any] | None = None,
    cert_verify: Callable[..., bool] | None = None,
    signature_verify: Callable[..., bool] | None = None,
    log_verify: Callable[..., bool] | None = None,
    timestamp_verify: Callable[..., bool] | None = None,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    artefact = Path(artefact_path)
    for path, role in ((bundle, "bundle"), (artefact, "artefact")):
        if not path.is_file():
            return not_run_report(
                SB_REFUSED_INPUT_ABSENT,
                f"the {role} {str(path)!r} does not exist; absence is NOT_RUN",
            )
    return validate_bundle(
        bundle.read_bytes(),
        artefact.read_bytes(),
        policy=policy,
        cert_verify=cert_verify,
        signature_verify=signature_verify,
        log_verify=log_verify,
        timestamp_verify=timestamp_verify,
    )


# ---------------------------------------------------------------------------
# The structural no-network / no-client rule.
# ---------------------------------------------------------------------------

FORBIDDEN_MODULES = {
    "requests",
    "urllib",
    "urllib2",
    "urllib3",
    "http",
    "httpx",
    "aiohttp",
    "socket",
    "ssl",
    "ftplib",
    "telnetlib",
    "smtplib",
    "subprocess",
    "webbrowser",
}
FORBIDDEN_CLIENTS = frozenset({"cosign", "rekor-cli", "sigstore", "curl", "openssl"})
_SHELL_ATTRIBUTES = frozenset(
    {
        "system",
        "popen",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "posix_spawn",
        "posix_spawnp",
    }
)


def network_or_client_findings(source: str) -> list[dict[str, str]]:
    """Return the structural reasons a module source would be refused.

    This is a source inspection, not a sandbox: an import spelled from a
    runtime string, or a command assembled at run time, is not detected.  The
    limit is stated rather than hidden, and this module itself must return an
    empty list (the matching test enforces it).
    """
    findings: list[dict[str, str]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return [
            {
                "code": SB_REFUSED_NETWORK_OR_CLIENT,
                "kind": "unparsable",
                "detail": str(error),
            }
        ]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_MODULES:
                    findings.append(
                        {
                            "code": SB_REFUSED_NETWORK_OR_CLIENT,
                            "kind": "import",
                            "detail": alias.name,
                        }
                    )
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_MODULES:
                findings.append(
                    {
                        "code": SB_REFUSED_NETWORK_OR_CLIENT,
                        "kind": "import",
                        "detail": node.module or "",
                    }
                )
        elif isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name) and function.id in FORBIDDEN_CLIENTS:
                findings.append(
                    {
                        "code": SB_REFUSED_NETWORK_OR_CLIENT,
                        "kind": "client",
                        "detail": function.id,
                    }
                )
            if (
                isinstance(function, ast.Attribute)
                and function.attr in _SHELL_ATTRIBUTES
                and isinstance(function.value, ast.Name)
                and function.value.id in {"os", "posix", "subprocess"}
            ):
                findings.append(
                    {
                        "code": SB_REFUSED_NETWORK_OR_CLIENT,
                        "kind": "shell",
                        "detail": f"{function.value.id}.{function.attr}",
                    }
                )
            for argument in node.args:
                if isinstance(argument, (ast.List, ast.Tuple)) and argument.elts:
                    first = argument.elts[0]
                    if isinstance(first, ast.Constant) and first.value in FORBIDDEN_CLIENTS:
                        findings.append(
                            {
                                "code": SB_REFUSED_NETWORK_OR_CLIENT,
                                "kind": "client",
                                "detail": str(first.value),
                            }
                        )
    return findings


def module_source() -> str:
    return Path(__file__).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The real inventory.  There is no bundle in the tree; this says so.
#
# The population is *frozen*.  It is the explicit member list of tracked
# evidence JSON that existed at the declared candidate, each member bound to
# its sha256, and it is read from the record (``evidence/a16/INVENTORY.json``),
# never from a live glob.  The earlier version counted a live glob, which
# included this item's own records and every later item's, so the committed
# count stopped reproducing the moment another item added evidence.  A glob
# match that is not a member is now reported as ``NEW_SINCE_RECORD`` with its
# digest and counted separately; it never enlarges the recorded population, and
# a changed or removed member is refused with ``PH_REFUSED_POPULATION_DRIFT``.
# The machinery is ``harden``'s, imported rather than reimplemented.
# ---------------------------------------------------------------------------

INVENTORY_GLOBS = ("evidence/**/*.json",)
POPULATION_GLOB = "evidence/*.json"  # fnmatch form of INVENTORY_GLOBS; '*' crosses '/'
CERTIFICATE_GLOBS = (
    "evidence/**/*.pem",
    "evidence/**/*.crt",
    "evidence/**/*.der",
    "evidence/**/*.p7b",
    "evidence/**/*.p12",
)
CERTIFICATE_GLOBS_FNMATCH = (
    "evidence/*.pem",
    "evidence/*.crt",
    "evidence/*.der",
    "evidence/*.p7b",
    "evidence/*.p12",
)
A10_ENVELOPE_DIR = "evidence/a10/ENVELOPES"
INVENTORY_RECORD = REPO_ROOT / "evidence/a16/INVENTORY.json"
POPULATION_SELF = "evidence/a16/INVENTORY.json"
POPULATION_BINDING = harden.POPULATION_FROZEN

# This item's own records are not population members.  Each one embeds
# ``sourceIdentity.baseCommit``; if such a record were also a member bound to its
# own digest, the digest would depend on the commit hash, which depends on the
# record's bytes -- a commit-hash fixed point that no commit can satisfy.  They
# are therefore excluded *by identity*, separately from the declared cut below.
# A11 does the same thing for its own records: no ``evidence/a11/*`` path is a
# member of ``evidence/a11/SCAN.json``.
POPULATION_IDENTITY_EXCLUDED = (
    POPULATION_SELF,
    "evidence/a16/PROFILE.json",
    "evidence/a16/CONTROLS.json",
)

# The declared excluded set.  A11's scan population is every tracked evidence
# JSON (``evidence/*.json``) except its own three records, so it includes this
# item's records; if this item's population also included A11's three records,
# each record would have to contain the other's digest.  A11 is the broader
# population and absorbs this item's records, so this item declares the three A11
# records excluded, records the exclusion and its reason in ``INVENTORY.json``,
# and reports them as ``NEW_SINCE_RECORD`` through :func:`growth_report`.  The
# set is closed and exactly these three paths: an exclusion that could silently
# absorb an unrelated record would be a way to hide growth, not to break a cycle.
POPULATION_EXCLUDED_PATHS = (
    "evidence/a11/CONTROLS.json",
    "evidence/a11/DIFFERENTIAL.json",
    "evidence/a11/SCAN.json",
)
POPULATION_EXCLUDED_REASON = (
    "mutual digest binding: A11's scan population is every tracked evidence JSON "
    "and therefore contains this item's records, so this population cannot also "
    "contain A11's three records without a digest cycle. A11 absorbs this item's "
    "records; these three are declared excluded here and are reported "
    "NEW_SINCE_RECORD by growth_report, never absorbed into the frozen count."
)
POPULATION_EXCLUDED_RESULT = harden.RESULT_NEW_SINCE_RECORD


def _refuse_population(message: str) -> None:
    """Refuse with harden's stable population-drift code, never with a pass."""
    raise harden.Refusal(harden.PH_REFUSED_POPULATION_DRIFT, message)


def freeze_population(
    paths: Iterable[str],
    *,
    repo_root: Path | str = REPO_ROOT,
    blobs: Callable[[str], bytes] | None = None,
) -> list[dict[str, Any]]:
    """Bind an explicit path list to bytes, sorted by path.

    Without ``blobs`` this is :func:`harden.freeze_population` and reads the
    working tree.  With ``blobs`` every digest is read from the supplied source
    (the candidate commit's blobs), so an uncommitted member cannot be absorbed.
    """
    paths = list(paths)
    identity = sorted(set(paths) & set(POPULATION_IDENTITY_EXCLUDED))
    if identity:
        _refuse_population(
            f"{', '.join(identity)} cannot be a member of this population: each "
            "record embeds sourceIdentity.baseCommit, so a digest of its bytes "
            "would depend on the commit hash that depends on those bytes (a "
            "commit-hash fixed point). It is excluded by identity."
        )
    excluded = set(paths) & set(POPULATION_EXCLUDED_PATHS)
    if excluded:
        _refuse_population(
            "the declared exclusion cannot be overridden: "
            f"{', '.join(sorted(excluded))}"
        )
    if blobs is not None:
        members: list[dict[str, Any]] = []
        for relative in sorted(paths):
            data = blobs(relative)
            members.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                }
            )
        return members
    return harden.freeze_population(sorted(paths), repo_root=repo_root)


def verify_population(
    members: Iterable[dict[str, Any]],
    *,
    repo_root: Path | str = REPO_ROOT,
    blobs: Callable[[str], bytes] | None = None,
) -> list[dict[str, Any]]:
    """Re-hash every declared member at this tree or in the candidate blobs.

    The population and its count come from the member list only.  A changed,
    removed or malformed member is refused with ``PH_REFUSED_POPULATION_DRIFT``;
    a file that matches the glob but is not a member cannot enlarge the answer
    (see :func:`growth_report`).  ``blobs`` binds every measurement to an exact
    candidate instead of the working tree.
    """
    declared = list(members)
    paths = [member["path"] for member in declared]
    if len(set(paths)) != len(paths):
        _refuse_population("the declared population repeats a path")
    for member in declared:
        if not isinstance(member.get("sha256"), str) or len(member["sha256"]) != 64:
            _refuse_population(f"a declared member has no sha256: {member.get('path')!r}")
    if blobs is None:
        current = {
            row["path"]: row
            for row in harden.freeze_population(paths, repo_root=repo_root)
        }
    else:
        current = {}
        for relative in paths:
            data = blobs(relative)
            current[relative] = {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
    for member in declared:
        row = current[member["path"]]
        if row["sha256"] != member["sha256"]:
            _refuse_population(
                f"changed: {row['path']}: sha256 {row['sha256']} != declared "
                f"{member['sha256']}"
            )
    return sorted(current.values(), key=lambda row: row["path"])


def declared_population(path: Path | str = INVENTORY_RECORD) -> dict[str, Any]:
    """The frozen population the record declares; a live glob is not a substitute.

    The record is the declared candidate.  If it has no ``population`` block
    bound ``FROZEN`` there is nothing to reproduce, and inventing the population
    from the tree now is exactly the defect this binds away.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        _refuse_population(f"{path}: the declared population record is unreadable: {error}")
    try:
        document = harden.loads(raw)
    except harden.Refusal as refusal:
        _refuse_population(
            f"{path}: the declared population record is not strictly readable: "
            f"{refusal.code}"
        )
    if not isinstance(document, dict):
        _refuse_population(f"{path}: the declared population record is not an object")
    population = document.get("population")
    if not isinstance(population, dict) or population.get("binding") != POPULATION_BINDING:
        _refuse_population(
            f"{path}: no population is declared {POPULATION_BINDING}; a live glob is "
            "not a substitute for a declared candidate"
        )
    members = population.get("members")
    if not isinstance(members, list) or not members:
        _refuse_population(f"{path}: the frozen population has no member list")
    excluded = population.get("excluded")
    excluded_paths = excluded.get("paths") if isinstance(excluded, dict) else None
    if not isinstance(excluded_paths, list) or tuple(excluded_paths) != POPULATION_EXCLUDED_PATHS:
        _refuse_population(
            f"{path}: the declared exclusion is not the closed set "
            f"{list(POPULATION_EXCLUDED_PATHS)}"
        )
    identity_members = sorted(
        {
            member.get("path")
            for member in members
            if isinstance(member, dict) and isinstance(member.get("path"), str)
        }
        & set(POPULATION_IDENTITY_EXCLUDED)
    )
    if identity_members:
        _refuse_population(
            f"{path}: {', '.join(identity_members)} cannot be a member of this "
            "population: each record embeds sourceIdentity.baseCommit, so binding "
            "it to a population frozen at that commit is a commit-hash fixed "
            "point. It is excluded by identity, not by the declared cut."
        )
    certificates = document.get("certificatePopulation")
    certificate_members = (
        certificates.get("members") if isinstance(certificates, dict) else None
    )
    if not isinstance(certificate_members, list):
        _refuse_population(f"{path}: the certificate population has no member list")
    return {
        "frozenAtCandidate": population.get("frozenAtCandidate"),
        "members": members,
        "certificateMembers": certificate_members,
    }


def _growth(
    patterns: tuple[str, ...],
    members: Iterable[dict[str, Any]],
    *,
    repo_root: Path | str,
    live_paths: Iterable[str] | None,
) -> list[dict[str, Any]]:
    members = list(members)
    if live_paths is not None:
        live = [
            path
            for path in live_paths
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
        ]
        entries: list[dict[str, Any]] = []
        for pattern in patterns:
            entries.extend(
                harden.population_growth(
                    members,
                    glob=pattern,
                    repo_root=repo_root,
                    excluded_prefixes=(),
                    live_paths=live,
                )
            )
        return entries
    entries = []
    for pattern in patterns:
        entries.extend(
            harden.population_growth(
                members, glob=pattern, repo_root=repo_root, excluded_prefixes=()
            )
        )
    return entries


def growth_report(
    members: Iterable[dict[str, Any]],
    certificate_members: Iterable[dict[str, Any]] = (),
    *,
    repo_root: Path | str = REPO_ROOT,
    live_paths: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Glob matches that are not frozen members, as ``NEW_SINCE_RECORD``.

    Each entry carries its path, digest and size and is counted separately: the
    frozen population and its recorded count are unchanged.  Nothing is excluded
    from this report, so a file in any directory (including this item's own) is
    visible.  A member that has left the live population is refused rather than
    absorbed.
    """
    entries = _growth(
        (POPULATION_GLOB,), members, repo_root=repo_root, live_paths=live_paths
    )
    entries.extend(
        _growth(
            CERTIFICATE_GLOBS_FNMATCH,
            certificate_members,
            repo_root=repo_root,
            live_paths=live_paths,
        )
    )
    unique: dict[str, dict[str, Any]] = {}
    for entry in entries:
        unique.setdefault(entry["path"], entry)
    return [unique[path] for path in sorted(unique)]


def inventory(
    members: Iterable[dict[str, Any]],
    certificate_members: Iterable[dict[str, Any]] = (),
    *,
    frozen_at_candidate: str | None = None,
    repo_root: Path | str = REPO_ROOT,
    blobs: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Measure the frozen population.  A bundle is a *file* whose top level is one.

    Only members are read.  A control-only document that embeds synthetic
    bundles is not a bundle and is reported as a candidate file; the A10
    envelopes are self-issued DSSE, not Sigstore bundles, and are counted
    separately from the frozen member paths.
    """
    root = Path(repo_root)
    population = verify_population(members, repo_root=root, blobs=blobs)
    certificate_population = verify_population(
        certificate_members, repo_root=root, blobs=blobs
    )
    candidate_files: list[dict[str, Any]] = []
    bundle_files: list[dict[str, Any]] = []
    logs: set[str] = set()
    certificates = 0
    for row in population:
        relative = row["path"]
        data = (
            blobs(relative) if blobs is not None else (root / relative).read_bytes()
        )
        if SIGSTORE_BUNDLE_PREFIX.encode("ascii") not in data:
            continue
        try:
            document = harden.loads(data)
        except harden.Refusal as refusal:
            candidate_files.append(
                {
                    "path": relative,
                    "topLevelMediaType": None,
                    "reason": f"strict reader refused it: {refusal.code}",
                }
            )
            continue
        top_level = document.get("mediaType") if isinstance(document, dict) else None
        if isinstance(top_level, str) and top_level.startswith(SIGSTORE_BUNDLE_PREFIX):
            material = document.get("verificationMaterial")
            chains = material.get("x509CertificateChain") if isinstance(material, dict) else None
            if isinstance(chains, dict) and isinstance(chains.get("certificates"), list):
                certificates += len(chains["certificates"])
            entries = material.get("tlogEntries") if isinstance(material, dict) else None
            if isinstance(entries, list):
                for entry in entries:
                    log_id = entry.get("logId") if isinstance(entry, dict) else None
                    key_id = log_id.get("keyId") if isinstance(log_id, dict) else None
                    if isinstance(key_id, str) and key_id:
                        logs.add(key_id)
            bundle_files.append({"path": relative, "mediaType": top_level})
        else:
            candidate_files.append(
                {
                    "path": relative,
                    "topLevelMediaType": top_level,
                    "reason": (
                        "the media type appears in this document, but its top "
                        "level is not a bundle: it is a profile or a control-only "
                        "fixture"
                    ),
                }
            )
    envelopes = [
        row["path"]
        for row in population
        if row["path"].startswith(f"{A10_ENVELOPE_DIR}/")
        and row["path"].endswith(".json")
    ]
    return {
        "schema": INVENTORY_SCHEMA,
        "model": MODEL_ID,
        "populationGlob": list(INVENTORY_GLOBS),
        "population": {
            "binding": POPULATION_BINDING,
            "glob": POPULATION_GLOB,
            "globSemantics": (
                "tracked files matched with fnmatch.fnmatchcase; '*' matches "
                "across '/', so this covers evidence/**/*.json"
            ),
            "basis": (
                "the explicit member list below, declared at the candidate; not "
                "a live glob"
            ),
            "excluded": {
                "paths": list(POPULATION_EXCLUDED_PATHS),
                "reason": POPULATION_EXCLUDED_REASON,
                "result": POPULATION_EXCLUDED_RESULT,
            },
            "identityExcluded": {
                "paths": list(POPULATION_IDENTITY_EXCLUDED),
                "reason": (
                    "each of these records embeds sourceIdentity.baseCommit, so "
                    "a member digest would depend on the commit hash that "
                    "depends on the record's bytes: a commit-hash fixed point. "
                    "They are excluded by identity, not by the declared cut, "
                    "which remains exactly the three A11 records."
                ),
            },
            "frozenAtCandidate": frozen_at_candidate,
            "files": len(population),
            "members": [
                {"path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}
                for row in population
            ],
            "growthPolicy": (
                "a verification re-hashes every member and reports a glob match "
                "that is not a member as NEW_SINCE_RECORD, counted separately; "
                "growth never changes this count, and a removed or changed member "
                "is refused with PH_REFUSED_POPULATION_DRIFT"
            ),
        },
        "populationFiles": len(population),
        "certificateGlob": list(CERTIFICATE_GLOBS),
        "certificatePopulation": {
            "binding": POPULATION_BINDING,
            "glob": list(CERTIFICATE_GLOBS_FNMATCH),
            "basis": (
                "the explicit member list below, declared at the candidate; not "
                "a live glob"
            ),
            "frozenAtCandidate": frozen_at_candidate,
            "files": len(certificate_population),
            "members": [
                {"path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"]}
                for row in certificate_population
            ],
        },
        "certificateFiles": len(certificate_population),
        "bundles": len(bundle_files),
        "transparencyLogs": len(logs),
        "certificates": certificates,
        "bundleFiles": bundle_files,
        "candidateFiles": candidate_files,
        "a10Envelopes": len(envelopes),
        "a10EnvelopeNote": (
            "the A10 envelopes are self-issued DSSE signed by a fixed public "
            "test key; they are not Sigstore bundles, carry no certificate, no "
            "transparency entry and no timestamp, and are not counted as any"
        ),
        "explanation": (
            "No Sigstore bundle, transparency-log public key, CA root or "
            "timestamp-authority root exists in the population frozen at the "
            "declared candidate.  The measured counts are 0 bundles, 0 log keys "
            "and 0 certificates; that is the honest result, not an omission.  A "
            "record added since the candidate is NEW_SINCE_RECORD and requires an "
            "explicit re-freeze and a fresh inventory before it can be counted."
        ),
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def _print_report(report: Mapping[str, Any]) -> None:
    print(
        f"validate: code={report['code']} outcome={report['outcome']} "
        f"mediaType={report['mediaType']} checks={len(report['checks'])} "
        f"notRun={','.join(report['notRun']) if report['notRun'] else 'none'}"
    )
    for check in report["checks"]:
        code = check["code"] or "-"
        print(
            f"  check: id={check['check']} status={check['status']} code={code} "
            f"detail={check['detail']}"
        )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="sigstore_bundle.py", add_help=True)
    subparsers = parser.add_subparsers(dest="command")
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("bundle")
    validate_parser.add_argument("artefact")
    validate_parser.add_argument("--issuer", default=None)
    validate_parser.add_argument("--identity", default=None)
    validate_parser.add_argument("--identity-type", default=None)
    subparsers.add_parser("profile")
    subparsers.add_parser("inventory")

    try:
        parsed = parser.parse_args(arguments)
    except SystemExit as exit_error:
        if exit_error.code == 0:
            return EXIT_OK
        print(f"{CODE_USAGE}: the command line was not understood", file=sys.stderr)
        return EXIT_USAGE

    if parsed.command is None:
        print(f"{CODE_USAGE}: no command was given", file=sys.stderr)
        return EXIT_USAGE

    if parsed.command == "profile":
        print(json.dumps(bundle_profile(), indent=2, sort_keys=True))
        print(
            f"profile: code={CODE_OK} outcome=NOT_APPLICABLE "
            f"mediaType={MEDIA_TYPE_V03}"
        )
        return EXIT_OK

    if parsed.command == "inventory":
        try:
            declared = declared_population()
            measured = inventory(
                declared["members"],
                declared["certificateMembers"],
                frozen_at_candidate=declared["frozenAtCandidate"],
            )
            growth = growth_report(
                declared["members"], declared["certificateMembers"]
            )
        except harden.Refusal as refusal:
            print(
                f"{refusal.code}: {refusal.message} outcome={OUTCOME_NOT_RUN}",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        print(json.dumps(measured, indent=2, sort_keys=True))
        print(
            f"inventory: code={CODE_OK} outcome={OUTCOME_NOT_RUN} "
            f"bundles={measured['bundles']} "
            f"transparencyLogs={measured['transparencyLogs']} "
            f"certificates={measured['certificates']} "
            f"population={measured['populationFiles']} files"
        )
        for entry in growth:
            print(
                f"growth: result={entry['result']} path={entry['path']} "
                f"sha256={entry['sha256']} bytes={entry['bytes']}",
                file=sys.stderr,
            )
        print(
            f"population: binding={measured['population']['binding']} "
            f"files={measured['populationFiles']} growth={len(growth)}",
            file=sys.stderr,
        )
        return EXIT_OK

    policy: dict[str, Any] | None = None
    if parsed.issuer or parsed.identity:
        policy = {}
        if parsed.issuer:
            policy["expectedIssuer"] = parsed.issuer
        if parsed.identity:
            policy["expectedIdentity"] = parsed.identity
        if parsed.identity_type:
            policy["identityType"] = parsed.identity_type
    try:
        report = validate_paths(
            parsed.bundle,
            parsed.artefact,
            policy=policy,
        )
    except OSError as error:
        print(
            f"{SB_REFUSED_INPUT_ABSENT}: {error} outcome={OUTCOME_NOT_RUN}",
            file=sys.stderr,
        )
        return EXIT_USAGE
    _print_report(report)
    if report["outcome"] == OUTCOME_VERIFIED:
        return EXIT_OK
    if report["outcome"] == OUTCOME_NOT_RUN:
        return EXIT_REFUSED
    return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
