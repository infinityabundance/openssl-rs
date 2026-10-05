#!/usr/bin/env python3
"""openssl-rs — the Phase 18 hostile X.509 / malformed-input corpus (18.2's fixity).

Why this file exists
--------------------
`RT-HOSTILE-X509` drives a *fixed* malformed-input corpus through the candidate's
`src/x509/`, `src/asn1/` and `src/pem/` readers, and the plan
(`docs/PHASE-18-SUBPHASES.md`, sections 2 and 3.1) requires the corpus, its size and its
provenance to be recorded in the court's row rather than described in prose. A corpus
recalled in the runner would be neither reproducible nor challengeable, so the bytes live
here as an enumerated table and this generator writes them.

`courts/phase18/fixtures/hostile-x509/` then holds one file per entry, named
`<arm>__<id>.bin`, with a stable id. The *arm* is the reader entry point the bytes are fed
to: `cert` (`d2i_X509`), `crl` (`d2i_X509_CRL`), `req` (`d2i_X509_REQ`), `xext`
(`d2i_X509_EXTENSION`), `xexts` (`d2i_X509_EXTENSIONS`), `gn` (`d2i_GENERAL_NAMES`),
`atype` (`d2i_ASN1_TYPE`), `gtime`/`utime` (`d2i_ASN1_GENERALIZEDTIME`/`d2i_ASN1_UTCTIME`),
`alg` (`d2i_X509_ALGOR`), `spki` (`d2i_X509_PUBKEY`), and the three PEM containers
`pemcert`/`pemcrl`/`pemreq` (`PEM_read_bio_X509`/`_X509_CRL`/`_X509_REQ`). The probe reads
no manifest — it derives the arm and the id from the filename — so the manifest exists for
provenance and for the court's freshness check, not as an input the instrument parses.

The base objects are the fixed Phase 17 fixtures (`courts/phase17/fixtures/`): the v3
`leaf.pem` certificate (extensions and TBSCertificate to mutate in place), the v1
`cert.der` certificate, `crl.pem`, and `req.pem`. They are read, never written; their
hashes are recorded in the corpus provenance. Every malformed entry is a pure function of
those bytes plus the table below.

What the corpus does, and does not, claim
-----------------------------------------
It is a fixed enumeration, not a fuzzer: truncated and oversized DER certificates, ASN.1
length bombs (deep nesting, huge declared lengths, indefinite-length misuse), malformed
TBSCertificate fields (version, serial, signature `AlgorithmIdentifier`, validity, subject,
SPKI bit string), bad extensions (duplicate, unknown, critical, malformed SAN and name
constraints), bad signature `AlgorithmIdentifier`s, malformed PEM containers (bad base64,
missing/extra delimiters, wrong labels), malformed CRLs and CSRs, and time / bit-string edge
cases. Each arm carries a *well-formed* control entry so the authority differential control
is non-vacuous: a corpus that reached no valid input would prove nothing about the parser.
It is **not** a coverage claim: a surface no entry reaches is named in the court's row, not
counted as passing (section 3.1).

Determinism
-----------
Every byte is a pure function of this file and the four committed fixtures. The runner
writes the files with `write()` and the manifest with `atlas_common.write_json` (sorted
keys, trailing newline); `--check` re-derives the table and compares the committed files and
manifest byte for byte, so a hand-edited fixture fails rather than silently changing what
the court drove.

    python3 forensics/tools/gen_hostile_x509_corpus.py            # write the corpus
    python3 forensics/tools/gen_hostile_x509_corpus.py --check    # verify the committed corpus

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    sha256_bytes,
    sha256_file,
    write_json,
)

OUT_DIR = REPO_ROOT / "courts" / "phase18" / "fixtures" / "hostile-x509"
MANIFEST = OUT_DIR / "MANIFEST.json"
GENERATOR = "forensics/tools/gen_hostile_x509_corpus.py"

# The fixed base objects (Phase 17's fixtures). Read, never written.
FIXTURES = REPO_ROOT / "courts" / "phase17" / "fixtures"
BASE_CERT_V3 = FIXTURES / "leaf.pem"
BASE_CERT_V1 = FIXTURES / "cert.der"
BASE_CRL = FIXTURES / "crl.pem"
BASE_REQ = FIXTURES / "req.pem"


@dataclass(frozen=True)
class Entry:
    """One corpus entry: a stable id, the reader arm, and the bytes."""

    id: str
    arm: str
    category: str
    description: str
    data: bytes

    @property
    def filename(self) -> str:
        return f"{self.arm}__{self.id}.bin"


# ---------------------------------------------------------------------------
# DER builders (the bytes the corpus is assembled from)
# ---------------------------------------------------------------------------

def dlen(n: int) -> bytes:
    """A DER definite length, minimal form."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + dlen(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return der(0x30, b"".join(parts))


def octet(b: bytes) -> bytes:
    return der(0x04, b)


def boolean(v: bool) -> bytes:
    return der(0x01, b"\xff" if v else b"\x00")


def integer(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    body = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return der(0x02, body)


def bitstring(b: bytes, unused: int = 0) -> bytes:
    return der(0x03, bytes([unused]) + b)


def utf8(b: bytes) -> bytes:
    return der(0x0c, b)


def oid(*arcs: int) -> bytes:
    body = bytes([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(chunk))
    return der(0x06, body)


# A free function `seq_of(parts)` because `seq(*list)` collides with the frozenset names.
def seq_of(parts: list[bytes]) -> bytes:
    return seq(*parts)


# ---------------------------------------------------------------------------
# A minimal DER walker, to locate the fields of the fixed base objects
# ---------------------------------------------------------------------------

def _tlv(der_bytes: bytes, off: int) -> tuple[int, int, int]:
    """`(tag, content_start, content_len)` for the TLV at `off`. High tags are refused."""
    tag = der_bytes[off]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number form not supported by the walker")
    i = off + 1
    first = der_bytes[i]
    i += 1
    if first == 0x80:
        raise ValueError("indefinite length not supported by the walker")
    if first & 0x80:
        n = first & 0x7F
        ln = int.from_bytes(der_bytes[i:i + n], "big")
        i += n
    else:
        ln = first
    return tag, i, ln


def _children(der_bytes: bytes, off: int) -> list[tuple[int, int, int]]:
    """`(tag, start, end)` for every child of the constructed value at `off`."""
    _tag, cs, ln = _tlv(der_bytes, off)
    end = cs + ln
    out: list[tuple[int, int, int]] = []
    i = cs
    while i < end:
        t, c, l = _tlv(der_bytes, i)
        out.append((t, i, c + l))
        i = c + l
    return out


def _replace(der_bytes: bytes, start: int, end: int, repl: bytes) -> bytes:
    return der_bytes[:start] + repl + der_bytes[end:]


# ---------------------------------------------------------------------------
# The fixed base objects and the fields the malformed entries mutate
# ---------------------------------------------------------------------------

def _pem_bytes(path: Path) -> bytes:
    """Decode the first PEM block in `path` to its DER bytes (pure base64, no library)."""
    text = path.read_bytes()
    m = re.search(rb"-----BEGIN [^-]+-----(.*?)-----END", text, re.S)
    if m is None:
        raise SystemExit(f"gen_hostile_x509_corpus: {rel(path)} has no PEM block")
    return base64.b64decode(re.sub(rb"\s", b"", m.group(1)))


def _base_bytes(path: Path) -> bytes:
    if path.suffix == ".pem":
        return _pem_bytes(path)
    return path.read_bytes()


class _Bases:
    """The fixed base objects and the offsets the in-place mutations use.

    The base v3 certificate's layout is located once, by the walker, so every mutation is a
    byte edit of a committed fixture rather than a re-encoded document.
    """

    def __init__(self) -> None:
        self.cert_v3 = _base_bytes(BASE_CERT_V3)
        self.cert_v1 = _base_bytes(BASE_CERT_V1)
        self.crl = _base_bytes(BASE_CRL)
        self.req = _base_bytes(BASE_REQ)
        # cert = SEQUENCE { tbs, sigalg, sigval } -- `_children` returns (tag, start, end)
        # where `start` is the child's own TLV header, so `_children(cert, tbs_start)` walks
        # the TBS directly.
        outer = _children(self.cert_v3, 0)
        self.tbs_start, self.tbs_end = outer[0][1], outer[0][2]
        self.sigalg_start, self.sigalg_end = outer[1][1], outer[1][2]
        self.sigval_start, self.sigval_end = outer[2][1], outer[2][2]
        # tbs = SEQUENCE { [0] version, INTEGER serial, SEQUENCE sigalg, SEQUENCE issuer,
        #                  SEQUENCE validity, SEQUENCE subject, SEQUENCE spki, [3] exts }
        by_tag: dict[int, list[tuple[int, int]]] = {}
        for t, s, e in _children(self.cert_v3, self.tbs_start):
            by_tag.setdefault(t, []).append((s, e))
        self.tbs_version = by_tag.get(0xA0, [(0, 0)])[0]
        self.tbs_serial = by_tag.get(0x02, [(0, 0)])[0]
        seqs = by_tag.get(0x30, [])
        self.tbs_sigalg = seqs[0] if len(seqs) > 0 else (0, 0)
        self.tbs_issuer = seqs[1] if len(seqs) > 1 else (0, 0)
        self.tbs_validity = seqs[2] if len(seqs) > 2 else (0, 0)
        self.tbs_subject = seqs[3] if len(seqs) > 3 else (0, 0)
        self.tbs_spki = seqs[4] if len(seqs) > 4 else (0, 0)
        self.tbs_exts = by_tag.get(0xA3, [(0, 0)])[0]
        # The first extension in the [3] EXTS field: the first child of the field.
        self.ext_first = self.tbs_exts
        if self.tbs_exts != (0, 0):
            exts_children = _children(self.cert_v3, self.tbs_exts[0])
            if exts_children:
                self.ext_first = (exts_children[0][1], exts_children[0][2])


_B: _Bases | None = None


def bases() -> _Bases:
    global _B
    if _B is None:
        _B = _Bases()
    return _B


# A valid SAN `GENERAL_NAMES`: SEQUENCE { [2] dNSName "example.test" }.
_SAN_DNS = bytes([0x82, 0x0C]) + b"example.test"
_SAN_VALID = seq(der(0x82, b"example.test"))

# A valid name constraints body: SEQUENCE { [0] permittedSubtrees { SEQUENCE { [2] dNSName } } }
_NC_VALID = seq(
    der(0xA0, seq(seq(der(0x82, b".example.test")))),
)

# The extension envelopes the `xext`/`xexts` arms drive (OIDs: 2.5.29.17 SAN, 2.5.29.19 BC,
# 2.5.29.30 NC, and an unknown 2.5.29.255).
_OID_SAN = oid(2, 5, 29, 17)
_OID_BC = oid(2, 5, 29, 19)
_OID_NC = oid(2, 5, 29, 30)
_OID_KM = oid(2, 5, 29, 15)
_OID_UNKNOWN = oid(2, 5, 29, 255)


def _ext(o: bytes, data: bytes, critical: bool = False) -> bytes:
    parts = [o]
    if critical:
        parts.append(boolean(True))
    parts.append(octet(data))
    return seq(*parts)


# Time encodings.
_GTIME_VALID = der(0x18, b"20250101000000Z")
_UTIME_VALID = der(0x17, b"250101000000Z")


# ---------------------------------------------------------------------------
# The corpus, in entry order
# ---------------------------------------------------------------------------

def entries() -> list[Entry]:
    """The enumerated corpus, read top to bottom as the coverage it is."""
    B = bases()
    E: list[Entry] = []

    def add(id: str, arm: str, category: str, description: str, data: bytes) -> None:
        E.append(Entry(id=id, arm=arm, category=category, description=description,
                       data=data))

    # --- controls: well-formed objects every arm must parse --------------------------------
    add("cert-valid", "cert", "control",
        "a well-formed v3 certificate (the Phase 17 leaf); the authority differential "
        "control for the DER certificate reader", B.cert_v3)
    add("cert-v1-valid", "cert", "control",
        "a well-formed v1 certificate (the Phase 17 cert.der)", B.cert_v1)
    add("crl-valid", "crl", "control",
        "a well-formed CRL (the Phase 17 crl.pem, base64-decoded)", B.crl)
    add("req-valid", "req", "control",
        "a well-formed CSR (the Phase 17 req.pem, base64-decoded)", B.req)
    add("xext-valid", "xext", "control",
        "a well-formed subjectAltName extension", _ext(_OID_SAN, _SAN_VALID))
    add("xext-bc-valid", "xext", "control",
        "a well-formed basicConstraints extension",
        _ext(_OID_BC, seq(boolean(True))))
    add("xext-nc-valid", "xext", "control",
        "a well-formed nameConstraints extension", _ext(_OID_NC, _NC_VALID))
    add("xexts-valid", "xexts", "control",
        "a well-formed SEQUENCE of two distinct extensions (keyUsage + basicConstraints)",
        seq(_ext(_OID_KM, bitstring(b"\x80")), _ext(_OID_BC, seq(boolean(True)))))
    add("gn-valid", "gn", "control",
        "a well-formed GENERAL_NAMES with one dNSName", _SAN_VALID)
    add("atype-valid", "atype", "control",
        "a well-formed ASN.1 INTEGER", integer(42))
    add("gtime-valid", "gtime", "control",
        "a well-formed GeneralizedTime", _GTIME_VALID)
    add("utime-valid", "utime", "control",
        "a well-formed UTCTime", _UTIME_VALID)
    add("alg-valid", "alg", "control",
        "the certificate's own signature AlgorithmIdentifier",
        B.cert_v3[B.sigalg_start:B.sigalg_end])
    add("spki-valid", "spki", "control",
        "the certificate's own SubjectPublicKeyInfo",
        B.cert_v3[B.tbs_spki[0]:B.tbs_spki[1]])

    # --- truncated DER certificates ---------------------------------------------------------
    cert = B.cert_v3
    for k, why in ((0, "empty"), (1, "one byte of the SEQUENCE header"),
                   (3, "a truncated length"), (8, "inside the TBS header"),
                   (40, "inside the TBS fields"), (len(cert) // 2, "half the document"),
                   (len(cert) - 1, "the final byte short")):
        add(f"cert-trunc-{why.replace(' ', '-')}", "cert", "truncated",
            f"the certificate truncated to {k} byte(s): {why}", cert[:k])
    add("cert-sigval-trunc", "cert", "truncated",
        "the certificate truncated inside the signatureValue BIT STRING",
        cert[:B.sigval_start + 6])

    # --- oversized / length-disagreement DER certificates ----------------------------------
    add("cert-trailing-1", "cert", "oversized",
        "the certificate plus one trailing byte", cert + b"\x00")
    add("cert-trailing-64", "cert", "oversized",
        "the certificate plus 64 trailing bytes", cert + bytes(64))
    add("cert-len-huge", "cert", "oversized",
        "the certificate with its outer length declared as 0x7fffffff (a length bomb)",
        b"\x30\x84\x7f\xff\xff\xff" + cert[4:])
    add("cert-len-short", "cert", "oversized",
        "the certificate with its outer length declared as 16",
        b"\x30\x81\x10" + cert[3:])
    add("cert-len-overlong", "cert", "oversized",
        "the certificate with an overlong three-byte length for the same value",
        b"\x30\x83\x00\x02\xfc" + cert[4:])
    add("cert-len-indefinite", "cert", "oversized",
        "the certificate's outer SEQUENCE under an indefinite length, terminated",
        b"\x30\x80" + cert[4:] + b"\x00\x00")
    add("cert-len-zero", "cert", "oversized",
        "the certificate's outer length declared as zero", b"\x30\x00" + cert[2:])

    # --- ASN.1 length bombs and misuse ------------------------------------------------------
    bomb = b"\x30\x84\x7f\xff\xff\xff" + bytes(16)
    add("asn1-len-2g", "atype", "length-bomb",
        "a SEQUENCE declaring 0x7fffffff bytes over a 16-byte body", bomb)
    add("asn1-len-10m", "atype", "length-bomb",
        "a SEQUENCE declaring 0x00a00000 bytes (10 MiB) over a 16-byte body",
        b"\x30\x83\xa0\x00\x00" + bytes(16))
    add("asn1-len-ff", "atype", "length-bomb",
        "a SEQUENCE declaring 255 bytes over a 4-byte body",
        b"\x30\x81\xff" + bytes(4))
    add("asn1-len-indefinite", "atype", "length-bomb",
        "a SEQUENCE under an indefinite length", b"\x30\x80" + bytes(4) + b"\x00\x00")
    add("asn1-len-truncated", "atype", "length-bomb",
        "a SEQUENCE whose long-form length is truncated", b"\x30\x84\x7f")
    add("asn1-len-nonminimal", "atype", "length-bomb",
        "a SEQUENCE with a non-minimal two-byte length for a 3-byte body",
        b"\x30\x82\x00\x03" + bytes(3))
    add("asn1-high-tag", "atype", "length-bomb",
        "a high-tag-number constructed tag", b"\x3f\x81\x01\x00")
    add("asn1-empty", "atype", "malformed-asn1", "an empty input", b"")
    add("asn1-zero-len", "atype", "malformed-asn1",
        "an empty SEQUENCE", b"\x30\x00")
    add("asn1-trunc-int", "atype", "malformed-asn1",
        "an INTEGER declaring 4 bytes with none present", b"\x02\x04")
    add("asn1-indef-nested", "atype", "length-bomb",
        "three nested indefinite-length SEQUENCEs", b"\x30\x80\x30\x80\x30\x80\x00\x00\x00\x00")

    # --- malformed TBSCertificate fields (in-place byte edits of the v3 base) --------------
    def tbs_edit(start: int, end: int, repl: bytes) -> bytes:
        return _replace(cert, start, end, repl)

    vs, ve = B.tbs_version
    add("tbs-version-7", "cert", "malformed-tbs",
        "the version INTEGER changed to 7 (outside the defined range)",
        tbs_edit(vs, ve, b"\xa0\x03\x02\x01\x07"))
    add("tbs-version-ff", "cert", "malformed-tbs",
        "the version INTEGER changed to 255", tbs_edit(vs, ve, b"\xa0\x03\x02\x01\xff"))
    ss, se = B.tbs_serial
    add("tbs-serial-empty", "cert", "malformed-tbs",
        "the serialNumber replaced with a zero-length INTEGER",
        tbs_edit(ss, se, b"\x02\x00"))
    add("tbs-serial-neg", "cert", "malformed-tbs",
        "the serialNumber's first byte forced negative",
        tbs_edit(ss, se, cert[ss:ss + 3] + bytes([cert[ss + 3] | 0x80]) + cert[ss + 4:se]))
    gs, ge = B.tbs_sigalg
    add("tbs-sigalg-unknown", "cert", "malformed-tbs",
        "the TBS signature AlgorithmIdentifier's OID arc changed to an unknown value",
        tbs_edit(gs, ge, _alg_unknown_oid(cert[gs:ge])))
    add("tbs-sigalg-noparams", "cert", "malformed-tbs",
        "the TBS signature AlgorithmIdentifier's parameters removed",
        tbs_edit(gs, ge, _alg_noparams(cert[gs:ge])))
    xs, xe = B.tbs_validity
    add("tbs-validity-tag", "cert", "malformed-tbs",
        "the validity's first time tag changed to an invalid 0x99",
        tbs_edit(xs, xe, _field_first_tag(cert, xs, xe, 0x99)))
    add("tbs-validity-trunc", "cert", "malformed-tbs",
        "the validity field truncated", tbs_edit(xs, xe, cert[xs:xs + 3]))
    us, ue = B.tbs_subject
    add("tbs-subject-tag", "cert", "malformed-tbs",
        "the subject's first attribute string tag changed to a reserved 0x1f",
        tbs_edit(us, ue, _subject_first_string_tag(cert, us, ue, 0x1F)))
    ps, pe = B.tbs_spki
    add("tbs-spki-bitstr-len", "cert", "malformed-tbs",
        "the SPKI subjectPublicKey BIT STRING's length inflated",
        tbs_edit(ps, pe, cert[ps:ps + 2] + b"\x7f" + cert[ps + 3:pe]))
    es, ee = B.tbs_exts
    add("tbs-exts-unknown-oid", "cert", "malformed-tbs",
        "the [3] extensions field's first extension OID arc changed to an unknown value",
        tbs_edit(es, ee, _ext_unknown_field(cert, es, ee)))
    add("tbs-exts-trunc", "cert", "malformed-tbs",
        "the [3] extensions field truncated inside its first extension",
        tbs_edit(B.tbs_exts[0], B.tbs_exts[1], cert[B.tbs_exts[0]:B.tbs_exts[0] + 6]))

    # --- bad extensions, driven through the extension readers ------------------------------
    add("xext-unknown-oid", "xext", "extensions",
        "an extension with an unknown OID and a well-formed body",
        _ext(_OID_UNKNOWN, _SAN_VALID))
    add("xext-unknown-oid-zero", "xext", "extensions",
        "an unknown zero-length extension", _ext(_OID_UNKNOWN, b""))
    add("xext-critical-san", "xext", "extensions",
        "a critical subjectAltName extension", _ext(_OID_SAN, _SAN_VALID, critical=True))
    add("xext-critical-unknown", "xext", "extensions",
        "a critical unknown extension", _ext(_OID_UNKNOWN, b"\x01\x02", critical=True))
    add("xext-critical-bc", "xext", "extensions",
        "a critical basicConstraints extension with a malformed body",
        _ext(_OID_BC, b"\x00", critical=True))
    add("xext-duplicate", "xexts", "extensions",
        "the same subjectAltName extension twice",
        seq(_ext(_OID_SAN, _SAN_VALID), _ext(_OID_SAN, _SAN_VALID)))
    add("xexts-mixed", "xexts", "extensions",
        "a critical unknown, a duplicate SAN and a malformed keyUsage in one sequence",
        seq(_ext(_OID_UNKNOWN, b"", critical=True), _ext(_OID_SAN, _SAN_VALID),
            _ext(_OID_SAN, _SAN_VALID), _ext(_OID_KM, b"\xff")))
    add("xexts-empty", "xexts", "extensions", "an empty extension sequence", b"\x30\x00")
    # malformed SAN bodies
    add("san-empty", "xext", "extensions",
        "subjectAltName with an empty body", _ext(_OID_SAN, b""))
    add("san-not-seq", "xext", "extensions",
        "subjectAltName whose body is an INTEGER, not a SEQUENCE",
        _ext(_OID_SAN, integer(1)))
    add("san-bad-name-tag", "xext", "extensions",
        "subjectAltName with a GeneralName tag 0xff",
        _ext(_OID_SAN, seq(der(0xFF, b"x"))))
    add("san-len-overrun", "xext", "extensions",
        "subjectAltName whose dNSName length runs past the body",
        _ext(_OID_SAN, seq(b"\x82\xff" + b"short")))
    add("san-nested", "xext", "extensions",
        "subjectAltName containing a nested SEQUENCE where a GeneralName belongs",
        _ext(_OID_SAN, seq(seq(der(0x82, b"x")))))
    # malformed name constraints bodies
    add("nc-empty", "xext", "extensions",
        "nameConstraints with an empty body", _ext(_OID_NC, b""))
    add("nc-bad-subtree", "xext", "extensions",
        "nameConstraints with a GeneralSubtree whose dNSName tag is wrong",
        _ext(_OID_NC, seq(der(0xA0, seq(seq(der(0xFF, b"x")))))))
    add("nc-len-overrun", "xext", "extensions",
        "nameConstraints whose subtree length runs past the body",
        _ext(_OID_NC, seq(der(0xA0, b"\x30\xff\x82\x01x"))))
    add("nc-empty-subtree", "xext", "extensions",
        "nameConstraints with an empty permittedSubtrees SEQUENCE",
        _ext(_OID_NC, seq(der(0xA0, seq()))))
    add("nc-not-seq", "xext", "extensions",
        "nameConstraints whose body is an OCTET STRING, not a SEQUENCE",
        _ext(_OID_NC, octet(b"x")))
    # malformed extension envelopes
    add("xext-empty", "xext", "extensions", "an empty extension", b"\x30\x00")
    add("xext-trunc", "xext", "extensions", "a truncated extension",
        _ext(_OID_SAN, _SAN_VALID)[:6])
    add("xext-no-value", "xext", "extensions",
        "an extension carrying only its OID", seq(_OID_SAN))
    add("xext-oid-only-int", "xext", "extensions",
        "an extension whose second element is an INTEGER, not the value OCTET STRING",
        seq(_OID_SAN, integer(3)))

    # --- bad signature AlgorithmIdentifiers -------------------------------------------------
    add("alg-unknown-oid", "alg", "sigalg",
        "an AlgorithmIdentifier with an unknown OID",
        seq(_OID_UNKNOWN, der(0x05, b"")))
    add("alg-noparams", "alg", "sigalg",
        "a bare AlgorithmIdentifier with no parameters",
        seq(oid(1, 2, 840, 113549, 1, 1, 11)))
    add("alg-null-params", "alg", "sigalg",
        "an AlgorithmIdentifier with an explicit NULL parameter",
        seq(oid(1, 2, 840, 113549, 1, 1, 11), der(0x05, b"")))
    add("alg-bad-params", "alg", "sigalg",
        "an AlgorithmIdentifier whose parameters are an INTEGER, not NULL",
        seq(oid(1, 2, 840, 113549, 1, 1, 11), integer(1)))
    add("alg-trunc", "alg", "sigalg", "a truncated AlgorithmIdentifier",
        B.cert_v3[B.sigalg_start:B.sigalg_start + 4])
    add("alg-empty-seq", "alg", "sigalg", "an empty SEQUENCE", b"\x30\x00")
    add("spki-trunc", "spki", "sigalg",
        "a truncated SubjectPublicKeyInfo",
        B.cert_v3[B.tbs_spki[0]:B.tbs_spki[0] + 10])
    add("spki-bad-bitstr", "spki", "sigalg",
        "a SubjectPublicKeyInfo whose BIT STRING length is inflated",
        B.cert_v3[B.tbs_spki[0]:B.tbs_spki[0] + 2] + b"\x7f" + B.cert_v3[B.tbs_spki[0] + 3:B.tbs_spki[1]])

    # --- malformed PEM containers -----------------------------------------------------------
    pem_cert = BASE_CERT_V3.read_bytes()
    pem_crl = BASE_CRL.read_bytes()
    pem_req = BASE_REQ.read_bytes()
    add("pemcert-valid", "pemcert", "control",
        "a well-formed PEM certificate", pem_cert)
    add("pemcrl-valid", "pemcrl", "control", "a well-formed PEM CRL", pem_crl)
    add("pemreq-valid", "pemreq", "control", "a well-formed PEM CSR", pem_req)
    add("pemcert-no-begin", "pemcert", "pem",
        "a PEM certificate with the BEGIN line removed",
        _drop_line(pem_cert, b"-----BEGIN CERTIFICATE-----"))
    add("pemcert-no-end", "pemcert", "pem",
        "a PEM certificate with the END line removed",
        _drop_line(pem_cert, b"-----END CERTIFICATE-----"))
    add("pemcert-wrong-label", "pemcert", "pem",
        "a PEM certificate whose label is CERTIFICATE REQUEST",
        pem_cert.replace(b"CERTIFICATE", b"CERTIFICATE REQUEST"))
    add("pemcert-bad-b64", "pemcert", "pem",
        "a PEM certificate with a corrupt base64 character",
        _corrupt_b64(pem_cert))
    add("pemcert-empty-b64", "pemcert", "pem",
        "a PEM certificate with an empty body",
        b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    add("pemcert-short-b64", "pemcert", "pem",
        "a PEM certificate whose base64 body is truncated to 12 bytes",
        _truncate_b64(pem_cert, 12))
    add("pemcert-extra-data", "pemcert", "pem",
        "a PEM certificate with trailing garbage after the END line",
        pem_cert + b"garbage\n")
    add("pemcert-crlf", "pemcert", "pem",
        "a PEM certificate with CRLF line endings",
        pem_cert.replace(b"\n", b"\r\n"))
    add("pemcert-no-final-newline", "pemcert", "pem",
        "a PEM certificate with no trailing newline",
        pem_cert.rstrip(b"\n"))
    add("pemcert-lower-tag", "pemcert", "pem",
        "a PEM certificate whose BEGIN label is lower-case",
        pem_cert.replace(b"-----BEGIN CERTIFICATE-----", b"-----BEGIN certificate-----"))
    add("pemcert-two-certs", "pemcert", "pem",
        "two concatenated PEM certificates", pem_cert + pem_cert)
    add("pemcert-key-as-cert", "pemcert", "pem",
        "a private-key PEM fed to the certificate reader",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    add("pemcert-padding-bad", "pemcert", "pem",
        "a PEM certificate whose base64 padding is stripped",
        pem_cert.replace(b"\n-----END", b"-----END").replace(b"=", b""))
    add("pemcrl-no-end", "pemcrl", "pem",
        "a PEM CRL with the END line removed",
        _drop_line(pem_crl, b"-----END X509 CRL-----"))
    add("pemcrl-wrong-label", "pemcrl", "pem",
        "a PEM CRL whose label is CRL (not X509 CRL)",
        pem_crl.replace(b"X509 CRL", b"CRL"))
    add("pemcrl-bad-b64", "pemcrl", "pem",
        "a PEM CRL with a corrupt base64 character", _corrupt_b64(pem_crl))
    add("pemreq-no-begin", "pemreq", "pem",
        "a PEM CSR with the BEGIN line removed",
        _drop_line(pem_req, b"-----BEGIN CERTIFICATE REQUEST-----"))
    add("pemreq-wrong-label", "pemreq", "pem",
        "a PEM CSR whose label is CERTIFICATE",
        pem_req.replace(b"CERTIFICATE REQUEST", b"CERTIFICATE"))
    add("pemreq-trunc-b64", "pemreq", "pem",
        "a PEM CSR whose base64 body is truncated to 20 bytes",
        _truncate_b64(pem_req, 20))

    # --- malformed CRLs ---------------------------------------------------------------------
    crl = B.crl
    for k, why in ((0, "empty"), (1, "one byte"), (len(crl) // 2, "half"),
                   (len(crl) - 1, "one byte short")):
        add(f"crl-trunc-{why.replace(' ', '-')}", "crl", "crl",
            f"the CRL truncated to {k} byte(s): {why}", crl[:k])
    add("crl-trailing", "crl", "crl", "the CRL plus 16 trailing bytes", crl + bytes(16))
    add("crl-len-huge", "crl", "crl",
        "the CRL with its outer length declared 0x7fffffff",
        b"\x30\x84\x7f\xff\xff\xff" + crl[4:])
    add("crl-len-indefinite", "crl", "crl",
        "the CRL's outer SEQUENCE under an indefinite length",
        b"\x30\x80" + crl[4:] + b"\x00\x00")

    # --- malformed CSRs ---------------------------------------------------------------------
    req = B.req
    for k, why in ((0, "empty"), (1, "one byte"), (len(req) // 2, "half"),
                   (len(req) - 1, "one byte short")):
        add(f"req-trunc-{why.replace(' ', '-')}", "req", "req",
            f"the CSR truncated to {k} byte(s): {why}", req[:k])
    add("req-trailing", "req", "req", "the CSR plus 16 trailing bytes", req + bytes(16))
    add("req-len-huge", "req", "req",
        "the CSR with its outer length declared 0x7fffffff",
        b"\x30\x84\x7f\xff\xff\xff" + req[4:])
    add("req-len-indefinite", "req", "req",
        "the CSR's outer SEQUENCE under an indefinite length",
        b"\x30\x80" + req[4:] + b"\x00\x00")

    # --- time / bit-string edge cases --------------------------------------------------------
    add("gtime-no-z", "gtime", "time", "a GeneralizedTime without the Z terminator",
        der(0x18, b"20250101000000"))
    add("gtime-bad-digit", "gtime", "time",
        "a GeneralizedTime with a non-digit", der(0x18, b"2025010x000000Z"))
    add("gtime-short", "gtime", "time", "a GeneralizedTime truncated",
        der(0x18, b"2025010100000Z"))
    add("gtime-leap-second", "gtime", "time",
        "a GeneralizedTime at second 60", der(0x18, b"20250630235960Z"))
    add("gtime-year-zero", "gtime", "time", "a GeneralizedTime in year 0000",
        der(0x18, b"00000101000000Z"))
    add("gtime-empty", "gtime", "time", "an empty GeneralizedTime", der(0x18, b""))
    add("gtime-overflow", "gtime", "time",
        "a GeneralizedTime with an out-of-range month 99", der(0x18, b"20259901000000Z"))
    add("utime-no-z", "utime", "time", "a UTCTime without the Z terminator",
        der(0x17, b"250101000000"))
    add("utime-bad-digit", "utime", "time",
        "a UTCTime with a non-digit", der(0x17, b"25010100000xZ"))
    add("utime-short", "utime", "time", "a UTCTime truncated",
        der(0x17, b"25010100000Z"))
    add("utime-empty", "utime", "time", "an empty UTCTime", der(0x17, b""))
    add("utime-overflow", "utime", "time",
        "a UTCTime with an out-of-range day 99", der(0x17, b"250199000000Z"))
    add("bitstr-bad-unused", "atype", "bitstring",
        "a BIT STRING declaring 8 unused bits", b"\x03\x02\x08\x00")
    add("bitstr-empty", "atype", "bitstring", "a zero-length BIT STRING", b"\x03\x00")
    add("bitstr-len-overrun", "atype", "bitstring",
        "a BIT STRING declaring 16 bytes with two present", b"\x03\x10\x00\xff")

    return E


# ---------------------------------------------------------------------------
# The in-place helpers the malformed-TBSCertificate entries use
# ---------------------------------------------------------------------------

def _alg_unknown_oid(alg: bytes) -> bytes:
    """The AlgorithmIdentifier `alg` with its OID's final content byte changed to an
    arc no signature scheme names."""
    try:
        o = _children(alg, 0)[0]
        if o[0] != 0x06:
            return alg
        return alg[:o[2] - 1] + b"\x7f" + alg[o[2]:]
    except (ValueError, IndexError):
        return alg


def _alg_noparams(alg: bytes) -> bytes:
    """The AlgorithmIdentifier's OID alone, parameters dropped."""
    try:
        o = _children(alg, 0)[0]
        return seq(alg[o[1]:o[2]])
    except (ValueError, IndexError):
        return alg


def _field_first_tag(der_bytes: bytes, off: int, end: int, tag: int) -> bytes:
    """The constructed field `[off, end)` with its first child's tag byte replaced."""
    ch = _children(der_bytes, off)
    if not ch:
        return der_bytes[off:end]
    s = ch[0][1]
    return der_bytes[off:s] + bytes([tag]) + der_bytes[s + 1:end]


def _subject_first_string_tag(der_bytes: bytes, off: int, end: int, tag: int) -> bytes:
    """The subject name `[off, end)` with its first AttributeTypeAndValue's string tag
    replaced."""
    try:
        rdn = _children(der_bytes, off)[0]
        atv = _children(der_bytes, rdn[1])[0]
        val = _children(der_bytes, atv[1])[1]
    except (ValueError, IndexError):
        return der_bytes[off:end]
    s = val[1]
    return der_bytes[off:s] + bytes([tag]) + der_bytes[s + 1:end]


def _ext_unknown_field(der_bytes: bytes, off: int, end: int) -> bytes:
    """The `[3]` extensions field `[off, end)` with the first extension's OID's final
    content byte changed to 0x7f."""
    try:
        exts_seq = _children(der_bytes, off)[0]
        ext0 = _children(der_bytes, exts_seq[1])[0]
        oid = _children(der_bytes, ext0[1])[0]
        if oid[0] != 0x06:
            return der_bytes[off:end]
    except (ValueError, IndexError):
        return der_bytes[off:end]
    return der_bytes[off:oid[2] - 1] + b"\x7f" + der_bytes[oid[2]:end]


def _drop_line(pem: bytes, line: bytes) -> bytes:
    return b"".join(ln for ln in pem.splitlines(keepends=True)
                    if line not in ln)


def _corrupt_b64(pem: bytes) -> bytes:
    lines = pem.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.startswith(b"-----") or not ln.strip():
            continue
        body = bytearray(ln)
        for j, c in enumerate(body):
            if c not in (0x0A, 0x0D) and c not in b"+=":
                body[j] = ord("#")  # not a base64 character
                break
        lines[i] = bytes(body)
        break
    return b"".join(lines)


def _truncate_b64(pem: bytes, keep: int) -> bytes:
    lines = pem.splitlines(keepends=True)
    out: list[bytes] = []
    counted = 0
    for ln in lines:
        if ln.startswith(b"-----"):
            out.append(ln)
            continue
        strip = ln.rstrip(b"\r\n")
        if counted < keep:
            take = strip[:keep - counted]
            counted += len(take)
            out.append(take + b"\n")
    return b"".join(out)


# ---------------------------------------------------------------------------
# Manifest, write, verify
# ---------------------------------------------------------------------------

def provenance() -> dict:
    """The hashes of the fixed base objects the corpus mutates (read, never written)."""
    out: dict[str, dict] = {}
    for name, path in (("base-cert-v3", BASE_CERT_V3), ("base-cert-v1", BASE_CERT_V1),
                       ("base-crl", BASE_CRL), ("base-req", BASE_REQ)):
        out[name] = {"path": rel(path), "sha256": sha256_file(path)}
    return out


def manifest() -> dict:
    """The corpus manifest body: one record per entry plus the counts."""
    rows = [
        {
            "id": e.id,
            "arm": e.arm,
            "category": e.category,
            "description": e.description,
            "file": e.filename,
            "bytes": len(e.data),
            "sha256": sha256_bytes(e.data),
        }
        for e in entries()
    ]
    by_category: dict[str, int] = {}
    by_arm: dict[str, int] = {}
    for e in entries():
        by_category[e.category] = by_category.get(e.category, 0) + 1
        by_arm[e.arm] = by_arm.get(e.arm, 0) + 1
    return {
        "entries": rows,
        "counts": {
            "entries": len(rows),
            "total_bytes": sum(r["bytes"] for r in rows),
            "by_category": dict(sorted(by_category.items())),
            "by_arm": dict(sorted(by_arm.items())),
        },
        "provenance": provenance(),
        "note": (
            "The Phase 18 hostile X.509 / malformed-input corpus: one file per entry, named "
            "`<arm>__<id>.bin`, with the stable id and the reader arm the bytes are fed to. "
            "It is a fixed enumeration, not a fuzzer, and not a coverage claim. "
            "`forensics/tools/gen_hostile_x509_corpus.py` is the source of truth and "
            "`--check` proves the committed files are the ones it derives."
        ),
    }


def write() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    keep = {e.filename for e in entries()}
    for stale in OUT_DIR.glob("*.bin"):
        if stale.name not in keep:
            stale.unlink()
    for e in entries():
        (OUT_DIR / e.filename).write_bytes(e.data)
    doc = envelope(
        kind="hostile-x509-corpus",
        generator=GENERATOR,
        inputs=[InputRef(name="corpus-generator", path=REPO_ROOT / GENERATOR)]
        + [InputRef(name=n, path=p) for n, p in
           (("base-cert-v3", BASE_CERT_V3), ("base-cert-v1", BASE_CERT_V1),
            ("base-crl", BASE_CRL), ("base-req", BASE_REQ))],
        body=manifest(),
    )
    write_json(MANIFEST, doc)


def verify() -> list[str]:
    """Problems between the committed corpus and the table above, or an empty list."""
    problems: list[str] = []
    for e in entries():
        p = OUT_DIR / e.filename
        if not p.is_file():
            problems.append(f"{e.filename}: absent")
        elif p.read_bytes() != e.data:
            problems.append(f"{e.filename}: bytes differ from the enumerated entry")
    if not MANIFEST.is_file():
        problems.append("MANIFEST.json: absent")
        return problems
    committed = json.loads(MANIFEST.read_text(encoding="utf-8")).get("body", {})
    if committed != manifest():
        problems.append("MANIFEST.json: body differs from the derived manifest")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="verify the committed corpus instead of writing it")
    args = ap.parse_args(argv)
    if args.check:
        problems = verify()
        if problems:
            print(f"[hostile-x509-corpus] FAIL: {len(problems)} stale entr(y/ies)")
            for p in problems:
                print(f"  STALE: {p}")
            return 1
        m = manifest()["counts"]
        print(f"[hostile-x509-corpus] ok: {m['entries']} entries, {m['total_bytes']} bytes "
              f"({rel(OUT_DIR)})")
        return 0
    write()
    m = manifest()["counts"]
    print(f"[hostile-x509-corpus] wrote {m['entries']} entries, {m['total_bytes']} bytes "
          f"-> {rel(OUT_DIR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
