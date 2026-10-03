#!/usr/bin/env python3
"""openssl-rs — regenerate `courts/phase12/rt_cms_der.h` from the authority's own openssl.

The two fixtures RT-CMS decodes are generated once with the admitted authority's `openssl cms`
from the source tree's fixed `test/certs/root-{cert,key}.pem`, so neither side depends on a clock
or a key generated at run time. `-noattr` removes the signer's `signingTime`, which is what makes
the signed fixture a fixed instant; the embedded bytes are the contract either way.

Run inside the court container:

    bash docker/openssl-rs-court.sh exec sh -c 'cd /work && python3 forensics/tools/gen_cms_fixture.py'

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "forensics" / "authorities" / "build" / "openssl-3.6.4-production"
SRC = REPO / "forensics" / "authorities" / "src" / "openssl-3.6.4"
OPENSSL = BUILD / "apps" / "openssl"
OUT = REPO / "courts" / "phase12" / "rt_cms_der.h"
WORK = Path("/tmp/cms_fixture")


def generate() -> tuple[bytes, bytes, bytes, bytes]:
    WORK.mkdir(parents=True, exist_ok=True)
    content = WORK / "content.bin"
    content.write_bytes(b"cms fixed content\n")
    env = {"LD_LIBRARY_PATH": str(BUILD), "PATH": "/usr/bin:/bin"}
    signed = WORK / "signed.der"
    enveloped = WORK / "enveloped.der"
    subprocess.run(
        [
            str(OPENSSL), "cms", "-sign", "-binary", "-nodetach", "-noattr", "-md", "sha256",
            "-in", str(content), "-signer", str(SRC / "test/certs/root-cert.pem"),
            "-inkey", str(SRC / "test/certs/root-key.pem"), "-outform", "DER", "-out", str(signed),
        ],
        check=True, env=env,
    )
    subprocess.run(
        [
            str(OPENSSL), "cms", "-encrypt", "-binary", "-aes128", "-in", str(content),
            "-outform", "DER", "-out", str(enveloped), str(SRC / "test/certs/root-cert.pem"),
        ],
        check=True, env=env,
    )
    cert_pem = (SRC / "test/certs/root-cert.pem").read_bytes()
    key_pem = (SRC / "test/certs/root-key.pem").read_bytes()
    return signed.read_bytes(), enveloped.read_bytes(), cert_pem, key_pem


def array(name: str, data: bytes) -> str:
    rows = [f"static const unsigned char {name}[] = {{"]
    line = "   "
    for i, b in enumerate(data):
        line += f" 0x{b:02x},"
        if (i + 1) % 12 == 0:
            rows.append(line)
            line = "   "
    if line.strip():
        rows.append(line)
    rows.append("};")
    rows.append(f"#define {name}_len {len(data)}")
    return "\n".join(rows)


HEADER = """/*
 * rt_cms_der.h -- fixed CMS fixtures for RT-CMS, generated once with the authority's own openssl
 * (3.6.4) from the fixed test certs and embedded so both sides decode the same bytes.
 *
 *   signed.der     openssl cms -sign -binary -nodetach -noattr -md sha256 \\
 *                      -in content.bin -signer root-cert.pem -inkey root-key.pem -outform DER
 *   enveloped.der  openssl cms -encrypt -binary -aes128 -in content.bin -outform DER root-cert.pem
 *
 * `-noattr` removes the signer's signingTime, so the signed fixture is a fixed instant rather
 * than a clock reading; the embedded bytes are the contract either way.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
"""


def main() -> int:
    signed, enveloped, cert_pem, key_pem = generate()
    OUT.write_text(HEADER + "\n" + array("rt_cms_signed_der", signed) + "\n\n"
                   + array("rt_cms_enveloped_der", enveloped) + "\n\n"
                   + array("rt_cms_cert_pem", cert_pem + b"\x00") + "\n\n"
                   + array("rt_cms_key_pem", key_pem + b"\x00") + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(signed)} + {len(enveloped)} bytes; "
          f"cert {len(cert_pem)} B, key {len(key_pem)} B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
