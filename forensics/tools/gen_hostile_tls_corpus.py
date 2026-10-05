#!/usr/bin/env python3
"""openssl-rs — the Phase 18 hostile TLS corpus (18.1's fixity).

Why this file exists
--------------------
`RT-HOSTILE-TLS` drives a *fixed* malformed-input corpus through the real record layer and
the TLS 1.3 flight, and the plan (`docs/PHASE-18-SUBPHASES.md`, section 3.1) requires the
corpus, its size and its provenance to be recorded in the court's row rather than described
in prose. A corpus recalled in the runner would be neither reproducible nor challengeable,
so the bytes live here as an enumerated, byte-exact table and this generator writes them.

`courts/phase18/fixtures/hostile-tls/` then holds one file per entry, named
`<role>__<id>.bin`, with a stable id. The role is the side that *receives* the bytes: a
`server` entry is fed into `SSL_accept` (the ClientHello / record reader) and a `client`
entry into `SSL_connect` (the ServerHello / flight reader). The probe reads no manifest --
it derives the role from the filename -- so the manifest exists for provenance and for the
court's freshness check, not as an input the instrument parses.

What the corpus does, and does not, claim
-----------------------------------------
It is a fixed enumeration, not a fuzzer: the entries below are the malformed-record,
handshake-message and extension-body shapes the plan names (bogus record types/lengths/
versions, truncated and oversized handshake headers, malformed ClientHello / ServerHello /
extension bodies for `key_share`, `supported_versions`, ALPN, SNI and `signature_algorithms`,
bad CCS and bad Finished, and length-mismatch records). It includes a *well-formed* control
entry per role so the authority differential control is non-vacuous: a corpus that reached no
valid input would prove nothing about the parser. It is **not** a coverage claim: a surface no
entry reaches is named in the court's row, not counted as passing (section 3.1).

Determinism
-----------
Every byte is a pure function of this file. The runner writes the files with `write()` and the
manifest with `atlas_common.write_json` (sorted keys, trailing newline); `--check` re-derives
the table and compares the committed files and manifest byte for byte, so a hand-edited
fixture fails rather than silently changing what the court drove.

    python3 forensics/tools/gen_hostile_tls_corpus.py            # write the corpus
    python3 forensics/tools/gen_hostile_tls_corpus.py --check    # verify the committed corpus

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import json
import struct
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
    write_json,
)

OUT_DIR = REPO_ROOT / "courts" / "phase18" / "fixtures" / "hostile-tls"
MANIFEST = OUT_DIR / "MANIFEST.json"
GENERATOR = "forensics/tools/gen_hostile_tls_corpus.py"

ROLE_SERVER = "server"
ROLE_CLIENT = "client"


@dataclass(frozen=True)
class Entry:
    """One corpus entry: a stable id, the side that receives the bytes, and the bytes."""

    id: str
    role: str
    category: str
    description: str
    data: bytes

    @property
    def filename(self) -> str:
        return f"{self.role}__{self.id}.bin"


# ---------------------------------------------------------------------------
# TLS presentation builders (the bytes the corpus is assembled from)
# ---------------------------------------------------------------------------

_CT = {
    "server_hello": 2,
    "client_hello": 1,
    "finished": 20,
    "unknown": 0xFF,
}


def rec(rtype: int, version: int, body: bytes) -> bytes:
    """A TLS record whose declared length is `len(body)`."""
    return bytes([rtype, (version >> 8) & 0xFF, version & 0xFF,
                  (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body


def rec_len(rtype: int, version: int, declared: int, body: bytes) -> bytes:
    """A TLS record whose declared length is `declared`, which may disagree with `body`."""
    return bytes([rtype, (version >> 8) & 0xFF, version & 0xFF,
                  (declared >> 8) & 0xFF, declared & 0xFF]) + body


def hs(mtype: int, body: bytes, declared: int | None = None) -> bytes:
    """A handshake message whose declared length defaults to `len(body)`."""
    ln = len(body) if declared is None else declared
    return bytes([mtype, (ln >> 16) & 0xFF, (ln >> 8) & 0xFF, ln & 0xFF]) + body


def ext(etype: int, body: bytes, declared: int | None = None) -> bytes:
    """A TLS extension whose declared length defaults to `len(body)`."""
    ln = len(body) if declared is None else declared
    return struct.pack(">HH", etype, ln) + body


def _vec16(items: bytes) -> bytes:
    return struct.pack(">H", len(items)) + items


def ext_supported_versions(versions: tuple[int, ...]) -> bytes:
    return ext(43, bytes([len(versions) * 2])
               + b"".join(struct.pack(">H", v) for v in versions))


def ext_supported_groups(groups: tuple[int, ...]) -> bytes:
    return ext(10, _vec16(b"".join(struct.pack(">H", g) for g in groups)))


def ext_key_share(entries: tuple[tuple[int, bytes], ...]) -> bytes:
    body = b"".join(struct.pack(">HH", g, len(k)) + k for g, k in entries)
    return ext(51, _vec16(body))


def ext_signature_algorithms(algs: tuple[int, ...]) -> bytes:
    return ext(13, _vec16(b"".join(struct.pack(">H", a) for a in algs)))


def ext_alpn(protocols: tuple[bytes, ...]) -> bytes:
    body = b"".join(bytes([len(p)]) + p for p in protocols)
    return ext(16, _vec16(body))


def ext_sni(name: bytes, name_type: int = 0) -> bytes:
    entry = bytes([name_type]) + _vec16(name)
    return ext(0, _vec16(entry))


def ext_ec_point_formats(formats: tuple[int, ...]) -> bytes:
    return ext(11, bytes([len(formats)]) + bytes(formats))


# A valid X25519 public key: the RFC 7748 base point (u = 9, little-endian).
_X25519 = b"\x09" + bytes(31)

# The server's fixed flight fixtures (Phase 17's): a server context that reaches the
# ServerHello needs a certificate, and reusing the fixed one keeps the probe off the clock
# and off the network.
_CERT = "/work/courts/phase17/fixtures/signer.pem"
_KEY = "/work/courts/phase17/fixtures/rsa-key.pem"

_VALID_EXTS = (
    ext_supported_versions((0x0304,))
    + ext_supported_groups((0x001D,))
    + ext_key_share(((0x001D, _X25519),))
    + ext_signature_algorithms((0x0804,))
)


def client_hello(legacy: bytes = b"\x03\x03", random32: bytes = bytes(32),
                 session_id: bytes = b"", ciphers: tuple[int, ...] = (0x1301,),
                 compression: bytes = b"\x00", exts: bytes = b"") -> bytes:
    body = legacy + random32 + bytes([len(session_id)]) + session_id
    body += _vec16(b"".join(struct.pack(">H", c) for c in ciphers))
    body += bytes([len(compression)]) + compression
    body += _vec16(exts)
    return body


def server_hello(legacy: bytes = b"\x03\x03", random32: bytes = bytes(32),
                 session_id: bytes = b"", cipher: int = 0x1301, compression: int = 0,
                 exts: bytes = b"") -> bytes:
    body = legacy + random32 + bytes([len(session_id)]) + session_id
    body += struct.pack(">H", cipher) + bytes([compression])
    body += _vec16(exts)
    return body


def ch_record(exts: bytes = _VALID_EXTS, legacy: bytes = b"\x03\x03",
              recver: int = 0x0301) -> bytes:
    return rec(0x16, recver, hs(1, client_hello(legacy=legacy, exts=exts)))


def _sh_valid_ish() -> bytes:
    exts = ext_supported_versions_server(0x0304) + ext_key_share_server(0x001D, _X25519)
    return rec(0x16, 0x0303, hs(2, server_hello(exts=exts)))


def ext_supported_versions_server(version: int) -> bytes:
    return ext(43, struct.pack(">H", version))


def ext_key_share_server(group: int, key: bytes) -> bytes:
    return ext(51, struct.pack(">HH", group, len(key)) + key)


# ---------------------------------------------------------------------------
# The corpus, in entry order
# ---------------------------------------------------------------------------

def entries() -> list[Entry]:
    """The enumerated corpus, read top to bottom as the coverage it is."""
    E: list[Entry] = []

    def add(id: str, category: str, description: str, data: bytes,
            role: str = ROLE_SERVER) -> None:
        E.append(Entry(id=id, role=role, category=category,
                       description=description, data=data))

    # --- the control: a well-formed TLS 1.3 ClientHello the server must parse -------------
    add("ch-min-valid", "control",
        "a well-formed TLS 1.3 ClientHello (supported_versions/key_share/"
        "signature_algorithms); the authority differential control", ch_record())
    add("ch-min-valid-rec0303", "control",
        "the same ClientHello under a 0x0303 record version",
        ch_record(recver=0x0303))
    add("ch-min-valid-rec0301", "control",
        "the same ClientHello under a 0x0301 record version",
        ch_record(recver=0x0301))
    add("ch-no-key-share", "control",
        "a ClientHello with supported_versions/supported_groups/signature_algorithms but "
        "no key_share (the HelloRetryRequest path)",
        ch_record(exts=ext_supported_versions((0x0304,))
                  + ext_supported_groups((0x001D,))
                  + ext_signature_algorithms((0x0804,))))
    add("ch-split-record", "control",
        "the same well-formed ClientHello split across two plaintext records",
        _split(ch_record()))
    add("sh-valid-ish", "control",
        "a structurally well-formed TLS 1.3 ServerHello (supported_versions/key_share), "
        "as a client receives it", _sh_valid_ish(), role=ROLE_CLIENT)

    # --- record layer: type, version, length ---------------------------------------------
    add("record-empty", "record", "a zero-byte record", b"")
    add("record-trunc-1", "record", "one byte of a record header", b"\x16")
    add("record-trunc-4", "record", "four bytes of a record header", b"\x16\x03\x01\x00")
    add("record-type-ff", "record", "record type 0xff", rec(0xFF, 0x0301, b""))
    add("record-type-00", "record", "record type 0x00", rec(0x00, 0x0301, b""))
    add("record-ssl2", "record", "an SSLv2 ClientHello (first byte has the high bit set)",
        b"\x80\x2e\x01\x03\x01" + bytes(41))
    add("record-version-0200", "record", "record version 0x0200 (SSLv2)",
        rec(0x16, 0x0200, hs(1, client_hello(exts=_VALID_EXTS))))
    add("record-version-ffff", "record", "record version 0xffff",
        rec(0x16, 0xFFFF, hs(1, client_hello(exts=_VALID_EXTS))))
    add("record-len-zero", "record", "record declaring length 0", rec(0x16, 0x0301, b""))
    add("record-len-short", "record",
        "record declaring length 100 over a 5-byte body", rec_len(0x16, 0x0301, 100, bytes(5)))
    add("record-len-over-max", "record",
        "record declaring 16385 bytes (one over the plaintext maximum)",
        rec_len(0x16, 0x0301, 0x4001, bytes(16)))
    add("record-len-huge", "record",
        "record declaring 65535 bytes over a 32-byte body",
        rec_len(0x16, 0x0301, 0xFFFF, bytes(32)))
    add("record-appdata-first", "record",
        "an application-data record before the handshake", rec(0x17, 0x0303, b"hello"))
    add("record-alert-first", "record", "an alert record before the handshake",
        rec(0x15, 0x0303, b"\x02\x28"))
    add("record-alert-bad", "record", "an alert record with bogus level/description",
        rec(0x15, 0x0303, b"\xff\xff"))
    add("record-ccs-first", "record",
        "a ChangeCipherSpec record before the handshake (the middlebox path)",
        rec(0x14, 0x0303, b"\x01"))
    add("record-ccs-badlen", "record", "a CCS record whose body is two bytes",
        rec(0x14, 0x0303, b"\x01\x02"))
    add("record-ccs-badver", "record", "a CCS record under version 0x0301",
        rec(0x14, 0x0301, b"\x01"))
    add("record-ccs-badvalue", "record", "a CCS record whose body is 0x02",
        rec(0x14, 0x0303, b"\x02"))
    add("record-heartbeat-first", "record", "a heartbeat record before the handshake",
        rec(0x18, 0x0303, b"\x01\x00\x01"))

    # --- handshake header ---------------------------------------------------------------
    add("hs-trunc-hdr-1", "handshake", "a handshake header of one byte",
        rec(0x16, 0x0301, b"\x01"))
    add("hs-trunc-hdr-3", "handshake", "a handshake header of three bytes",
        rec(0x16, 0x0301, b"\x01\x00\x00"))
    add("hs-len-mismatch-short", "handshake",
        "a ClientHello whose handshake length is four bytes short",
        rec(0x16, 0x0301, hs(1, client_hello(exts=_VALID_EXTS),
                              declared=len(client_hello(exts=_VALID_EXTS)) - 4)))
    add("hs-len-mismatch-long", "handshake",
        "a ClientHello whose handshake length runs past the record",
        rec(0x16, 0x0301, hs(1, client_hello(exts=_VALID_EXTS),
                              declared=len(client_hello(exts=_VALID_EXTS)) + 64)))
    add("hs-len-huge", "handshake", "a handshake length of 0xffffff over 16 bytes",
        rec(0x16, 0x0301, b"\x01\xff\xff\xff" + bytes(16)))
    add("hs-type-finished-first", "handshake", "a Finished message before the handshake",
        rec(0x16, 0x0301, hs(20, bytes(32))))
    add("hs-type-unknown", "handshake", "an unknown handshake type 0xff",
        rec(0x16, 0x0301, hs(0xFF, bytes(8))))
    add("hs-type-serverhello", "handshake", "a ServerHello offered to a server",
        rec(0x16, 0x0301, hs(2, server_hello())))
    add("hs-two-in-one-record", "handshake",
        "a well-formed ClientHello followed by a Finished in one record",
        rec(0x16, 0x0301, hs(1, client_hello(exts=_VALID_EXTS)) + hs(20, bytes(32))))

    # --- ClientHello structure ----------------------------------------------------------
    add("ch-trunc-version", "clienthello", "a ClientHello truncated inside legacy_version",
        rec(0x16, 0x0301, hs(1, b"\x03")))
    add("ch-trunc-random", "clienthello", "a ClientHello truncated inside the random",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(10))))
    add("ch-trunc-sidlen", "clienthello",
        "a ClientHello truncated before the session-id length",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(32))))
    add("ch-sid-overrun", "clienthello", "a session-id length of 200 with 8 bytes",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(32) + b"\xc8" + bytes(8))))
    add("ch-ciphers-len-overrun", "clienthello",
        "a cipher-suite vector length of 0xff00 with one suite",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(32) + b"\x00"
                              + b"\xff\x00" + b"\x13\x01")))
    add("ch-ciphers-empty", "clienthello", "a cipher-suite vector of length 0",
        rec(0x16, 0x0301, hs(1, client_hello(ciphers=(), exts=_VALID_EXTS))))
    add("ch-ciphers-odd", "clienthello", "a cipher-suite vector of odd length",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(32) + b"\x00"
                              + b"\x00\x01\x13")))
    add("ch-comp-overrun", "clienthello",
        "a compression-methods length past the record",
        rec(0x16, 0x0301, hs(1, b"\x03\x03" + bytes(32) + b"\x00"
                              + b"\x00\x02\x13\x01" + b"\xff" + bytes(8))))
    add("ch-comp-empty", "clienthello", "a compression-methods vector of length 0",
        rec(0x16, 0x0301, hs(1, client_hello(compression=b"", exts=_VALID_EXTS))))
    add("ch-ext-len-overrun", "clienthello",
        "a ClientHello whose extensions total length runs past the record",
        rec(0x16, 0x0301, hs(1, client_hello(exts=_VALID_EXTS)[:-2]
                              + b"\xff\xff" + _VALID_EXTS)))
    add("ch-no-extensions", "clienthello", "a TLS 1.2-style ClientHello with no extensions",
        rec(0x16, 0x0301, hs(1, client_hello(ciphers=(0x1301, 0xC02F), exts=b""))))
    add("ch-legacy-0304", "clienthello", "a ClientHello with legacy_version 0x0304",
        ch_record(legacy=b"\x03\x04"))
    add("ch-legacy-0000", "clienthello", "a ClientHello with legacy_version 0x0000",
        ch_record(legacy=b"\x00\x00"))
    add("ch-ext-dup-supported-versions", "clienthello",
        "a ClientHello carrying supported_versions twice",
        ch_record(exts=ext_supported_versions((0x0304,))
                  + ext_supported_versions((0x0303,))))

    # --- extension bodies ---------------------------------------------------------------
    add("ext-sv-empty", "extension", "supported_versions with an empty body",
        ch_record(exts=ext(43, b"")))
    add("ext-sv-short", "extension", "supported_versions with a one-byte body",
        ch_record(exts=ext(43, b"\x02")))
    add("ext-sv-len-mismatch", "extension",
        "supported_versions whose list length disagrees with the body",
        ch_record(exts=ext(43, b"\x04" + b"\x03\x04")))
    add("ext-sv-badversion", "extension", "supported_versions offering only 0x0305",
        ch_record(exts=ext_supported_versions((0x0305,))))
    add("ext-sv-legacy-only", "extension", "supported_versions offering 0x0300..0x0303",
        ch_record(exts=ext_supported_versions((0x0300, 0x0301, 0x0302, 0x0303))))
    add("ext-sv-ext-len-overrun", "extension",
        "supported_versions whose extension length runs past the record",
        ch_record(exts=ext(43, b"\x02\x03\x04", declared=0xF0F0)))
    add("ext-ks-empty", "extension", "key_share with an empty body",
        ch_record(exts=ext_key_share(())))
    add("ext-ks-len-mismatch", "extension",
        "key_share whose list length disagrees with its entries",
        ch_record(exts=ext(51, struct.pack(">H", 0xFF)
                           + struct.pack(">HH", 0x001D, len(_X25519)) + _X25519)))
    add("ext-ks-bad-group", "extension", "key_share for an unknown group 0xffff",
        ch_record(exts=ext_supported_groups((0xFFFF,)) + ext_key_share(((0xFFFF, _X25519),))))
    add("ext-ks-short-key", "extension", "key_share with a 4-byte X25519 key",
        ch_record(exts=ext_key_share(((0x001D, b"\x01\x02\x03\x04"),))))
    add("ext-ks-overrun-entry", "extension",
        "key_share whose entry length runs past the extension body",
        ch_record(exts=ext(51, struct.pack(">H", 6)
                           + struct.pack(">HH", 0x001D, 0x00FF) + _X25519)))
    add("ext-ks-duplicate", "extension", "key_share carrying the same group twice",
        ch_record(exts=ext_key_share(((0x001D, _X25519), (0x001D, _X25519)))))
    add("ext-alpn-empty", "extension", "ALPN with an empty body",
        ch_record(exts=ext(16, b"")))
    add("ext-alpn-len-mismatch", "extension",
        "ALPN whose protocol-list length disagrees with the body",
        ch_record(exts=ext(16, struct.pack(">H", 0x40) + b"\x02h2")))
    add("ext-alpn-zero-name", "extension", "ALPN with a zero-length protocol name",
        ch_record(exts=ext(16, _vec16(b"\x00"))))
    add("ext-alpn-overrun", "extension",
        "ALPN whose protocol name runs past the list",
        ch_record(exts=ext(16, _vec16(b"\xffh2"))))
    add("ext-sni-empty", "extension", "SNI with an empty body", ch_record(exts=ext(0, b"")))
    add("ext-sni-bad-type", "extension", "SNI with name_type 0x02",
        ch_record(exts=ext_sni(b"example.test", name_type=0x02)))
    add("ext-sni-len-mismatch", "extension",
        "SNI whose server-name-list length disagrees with the body",
        ch_record(exts=ext(0, struct.pack(">H", 0xFF) + b"\x00" + _vec16(b"example.test"))))
    add("ext-sni-empty-name", "extension", "SNI with a zero-length host name",
        ch_record(exts=ext_sni(b"")))
    add("ext-sigalgs-empty", "extension", "signature_algorithms with an empty body",
        ch_record(exts=ext(13, b"")))
    add("ext-sigalgs-len-mismatch", "extension",
        "signature_algorithms whose vector length disagrees with the body",
        ch_record(exts=ext(13, b"\x08" + b"\x08\x04")))
    add("ext-sigalgs-unknown", "extension",
        "signature_algorithms offering only an unknown scheme 0xffff",
        ch_record(exts=ext_signature_algorithms((0xFFFF,))))
    add("ext-groups-empty", "extension", "supported_groups with an empty body",
        ch_record(exts=ext(10, b"")))
    add("ext-groups-len-mismatch", "extension",
        "supported_groups whose list length disagrees with the body",
        ch_record(exts=ext(10, b"\x08\x00\x1d")))
    add("ext-ecpf-empty", "extension", "ec_point_formats with an empty body",
        ch_record(exts=ext(11, b"")))
    add("ext-ecpf-bad-format", "extension", "ec_point_formats naming format 0x05",
        ch_record(exts=ext_ec_point_formats((0x05,))))
    add("ext-unknown", "extension", "an unknown extension type 0xfade",
        ch_record(exts=ext(0xFADE, b"\x00\x01\x02")))
    add("ext-zero-length-unknown", "extension",
        "an unknown zero-length extension alongside a valid flight",
        ch_record(exts=_VALID_EXTS + ext(0xFADE, b"")))

    # --- client side: malformed ServerHello / flight ------------------------------------
    add("sh-empty", "serverhello", "a zero-byte server flight", b"", role=ROLE_CLIENT)
    add("sh-trunc", "serverhello", "a ServerHello truncated inside the random",
        rec(0x16, 0x0303, hs(2, b"\x03\x03" + bytes(8))), role=ROLE_CLIENT)
    add("sh-hs-len-overrun", "serverhello",
        "a ServerHello whose handshake length runs past the record",
        rec(0x16, 0x0303, hs(2, server_hello(), declared=0x0100)), role=ROLE_CLIENT)
    add("sh-bad-legacy-version", "serverhello",
        "a ServerHello with legacy_version 0x0304",
        rec(0x16, 0x0303, hs(2, server_hello(legacy=b"\x03\x04"))), role=ROLE_CLIENT)
    add("sh-bad-cipher", "serverhello", "a ServerHello naming a cipher not offered",
        rec(0x16, 0x0303, hs(2, server_hello(cipher=0x009C))), role=ROLE_CLIENT)
    add("sh-ext-len-overrun", "serverhello",
        "a ServerHello whose extensions length runs past the record",
        rec(0x16, 0x0303, hs(2, server_hello(exts=b"\x00" * 8)[:-2] + b"\xff\xff")),
        role=ROLE_CLIENT)
    add("sh-ks-short", "serverhello", "a ServerHello key_share with a 4-byte key",
        rec(0x16, 0x0303, hs(2, server_hello(
            exts=ext_supported_versions_server(0x0304)
            + ext_key_share_server(0x001D, b"\x01\x02\x03\x04")))), role=ROLE_CLIENT)
    add("sh-unknown-hs-type", "serverhello",
        "a server flight whose first message is a ClientHello",
        rec(0x16, 0x0303, hs(1, client_hello())), role=ROLE_CLIENT)
    add("sh-ccs-first", "serverhello",
        "a server flight beginning with a ChangeCipherSpec",
        rec(0x14, 0x0303, b"\x01") + _sh_valid_ish(), role=ROLE_CLIENT)

    return E


def _split(data: bytes) -> bytes:
    """Split one record into two records carrying the same handshake bytes.

    The declared handshake length runs across the record boundary, which is the fencing
    the record layer must reassemble rather than reject.
    """
    payload = data[5:]
    cut = 5
    return rec_len(0x16, 0x0301, cut, payload[:cut]) + rec_len(0x16, 0x0301, len(payload) - cut,
                                                              payload[cut:])


def manifest() -> dict:
    """The corpus manifest body: one record per entry plus the counts."""
    rows = [
        {
            "id": e.id,
            "role": e.role,
            "category": e.category,
            "description": e.description,
            "file": e.filename,
            "bytes": len(e.data),
            "sha256": sha256_bytes(e.data),
        }
        for e in entries()
    ]
    by_category: dict[str, int] = {}
    by_role: dict[str, int] = {}
    for e in entries():
        by_category[e.category] = by_category.get(e.category, 0) + 1
        by_role[e.role] = by_role.get(e.role, 0) + 1
    return {
        "entries": rows,
        "counts": {
            "entries": len(rows),
            "total_bytes": sum(r["bytes"] for r in rows),
            "by_category": dict(sorted(by_category.items())),
            "by_role": dict(sorted(by_role.items())),
        },
        "note": (
            "The Phase 18 hostile TLS corpus: one file per entry, named "
            "`<role>__<id>.bin`, with the stable id and the side that receives the bytes. "
            "It is a fixed enumeration, not a fuzzer, and not a coverage claim. "
            "`forensics/tools/gen_hostile_tls_corpus.py` is the source of truth and "
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
        kind="hostile-tls-corpus",
        generator=GENERATOR,
        inputs=[InputRef(name="corpus-generator", path=REPO_ROOT / GENERATOR)],
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
            print(f"[hostile-tls-corpus] FAIL: {len(problems)} stale entr(y/ies)")
            for p in problems:
                print(f"  STALE: {p}")
            return 1
        m = manifest()["counts"]
        print(f"[hostile-tls-corpus] ok: {m['entries']} entries, {m['total_bytes']} bytes "
              f"({rel(OUT_DIR)})")
        return 0
    write()
    m = manifest()["counts"]
    print(f"[hostile-tls-corpus] wrote {m['entries']} entries, {m['total_bytes']} bytes "
          f"-> {rel(OUT_DIR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
