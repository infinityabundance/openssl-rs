#!/usr/bin/env python3
"""openssl-rs — derive the named-prime constants from the admitted authority.

Why this exists
---------------
`BN_get0_nist_prime_*` and `BN_get_rfc*_prime_*` return fixed large integers. The
alternative to generating them is transcribing them out of `bn_const.c` and
`bn_nist.c`, which is the one thing this project refuses to do with a constant that
another party defines: a transcription error in a 8192-bit prime is invisible to
every test that does not compare against the authority, and `BN_get0_nist_prime_*` is
feeded straight into `BN_nist_mod_*` where a wrong value silently changes every result.

So the values are *asked of the authority*: a C probe compiled against the admitted
prefix calls each function, prints `BN_bn2hex`, and this tool emits the byte arrays
into `src/bn/prime_data.rs`.

The generated file carries the authority identity and each value's SHA-256, so the
data is bound to the build it came from rather than to this repository's history.

Usage (inside the court, which is where the authority prefix lives):

    python3 forensics/tools/gen_bn_primes.py

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
    write_text,
)

OUT_RS = REPO_ROOT / "src" / "bn" / "prime_data.rs"
OUT_JSON = REPO_ROOT / "forensics" / "atlas" / "bn-primes.json"
GENERATOR = "forensics/tools/gen_bn_primes.py"

# The exported names, in the order the generator writes them. Each is checked to be
# present in the authority's DSO by `--check-dso` style verification elsewhere; here
# the probe simply fails to link if one is absent, which is the loudest possible
# signal.
GET0 = [
    "BN_get0_nist_prime_192",
    "BN_get0_nist_prime_224",
    "BN_get0_nist_prime_256",
    "BN_get0_nist_prime_384",
    "BN_get0_nist_prime_521",
]
GET_RFC = [
    "BN_get_rfc2409_prime_768",
    "BN_get_rfc2409_prime_1024",
    "BN_get_rfc3526_prime_1536",
    "BN_get_rfc3526_prime_2048",
    "BN_get_rfc3526_prime_3072",
    "BN_get_rfc3526_prime_4096",
    "BN_get_rfc3526_prime_6144",
    "BN_get_rfc3526_prime_8192",
]


def probe_source() -> str:
    """The C probe: one `key=value` line per prime, and never a bare `printf` of a
    pointer."""
    lines = [
        "#include <openssl/bn.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "",
        "static void emit(const char *key, const BIGNUM *b)",
        "{",
        "    char *hex;",
        "    if (b == NULL) { printf(\"%s=NONE\\n\", key); return; }",
        "    hex = BN_bn2hex(b);",
        "    if (hex == NULL) { printf(\"%s=ALLOCFAIL\\n\", key); return; }",
        "    printf(\"%s=%s\\n\", key, hex);",
        "    OPENSSL_free(hex);",
        "}",
        "",
        "int main(void)",
        "{",
    ]
    for name in GET0:
        lines.append(f"    emit(\"{name}\", {name}());")
    for name in GET_RFC:
        lines.append(f"    emit(\"{name}\", {name}(NULL));")
    lines += ["    return 0;", "}", ""]
    return "\n".join(lines)


def to_bytes(hexdigits: str) -> bytes:
    """Hex without a leading `-`, padded to an even number of digits.

    `BN_bn2hex` is byte-oriented, so its output is already even-length; the pad is a
    guard rather than a fixup, and it is deliberately not silent about which case it
    took.
    """
    text = hexdigits.strip()
    if text.startswith("-"):
        raise SystemExit(f"{GENERATOR}: unexpected negative prime {text!r}")
    if len(text) % 2:
        text = "0" + text
    return bytes.fromhex(text)


def rust_array(name: str, value: bytes) -> str:
    """One `pub(crate) const` as a byte array, wrapped at a readable width."""
    lines = [f"/// {name} — {len(value) * 8} bits."]
    lines.append(f"pub(crate) const {name}: [u8; {len(value)}] = [")
    for i in range(0, len(value), 12):
        chunk = ", ".join(f"0x{b:02X}" for b in value[i:i + 12])
        lines.append(f"    {chunk},")
    lines.append("];")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    work = REPO_ROOT / "court" / "bn-primes"
    work.mkdir(parents=True, exist_ok=True)
    src = work / "bn_primes_probe.c"
    write_text(src, probe_source())

    binp = work / "bn_primes_probe"
    res = run([
        "clang", "-std=c11", "-Wall", "-O1", "-D_GNU_SOURCE",
        "-I", str(auth.prefix / "include"),
        "-o", str(binp), str(src),
        "-L", str(auth.libdir), "-lcrypto",
        f"-Wl,-rpath,{auth.libdir}",
    ])
    if not res.ok:
        raise SystemExit(f"{GENERATOR}: the probe did not compile:\n{res.stderr}")
    res = run([str(binp)])
    if not res.ok:
        raise SystemExit(f"{GENERATOR}: the probe did not run:\n{res.stderr}")

    values: dict[str, bytes] = {}
    for line in res.stdout.splitlines():
        if "=" not in line:
            continue
        key, _, raw = line.partition("=")
        if raw in ("NONE", "ALLOCFAIL"):
            raise SystemExit(f"{GENERATOR}: {key} answered {raw}")
        values[key] = to_bytes(raw)

    missing = [n for n in GET0 + GET_RFC if n not in values]
    if missing:
        raise SystemExit(f"{GENERATOR}: no value for {missing}")

    body = [
        "//! The authority's named primes — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_bn_primes.py` inside the court",
        "//! container. The values are read back from the admitted authority rather than",
        "//! transcribed from `bn_const.c`, because a typo in an 8192-bit prime is",
        "//! invisible to everything except a comparison with the authority itself.",
        "//!",
        f"//! Authority: `{auth.id}`.",
        "",
        "// The constants are named after the authority's own exported functions, so a",
        "// reader can check one against `nm libcrypto.so.3` without a mapping table.",
        "// Renaming them to Rust case would break that correspondence and buy nothing:",
        "// they are data, referenced from exactly one module.",
        "#![allow(non_upper_case_globals)]",
        "",
    ]
    record = []
    for name in GET_RFC + GET0:
        value = values[name]
        body.append(rust_array(name, value))
        body.append("")
        record.append({
            "symbol": name,
            "bits": len(value) * 8,
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        })

    write_text(OUT_RS, "\n".join(body))

    doc = envelope(
        kind="bn-primes",
        authority=auth.id,
        inputs=[InputRef(name="authority-symbols",
                         path=REPO_ROOT / "forensics" / "atlas" / auth.id
                         / "symbols-libcrypto.json")],
        body={"primes": record,
              "counts": {"primes": len(record), "bytes": sum(r["bytes"] for r in record)}},
        generator=GENERATOR,
    )
    write_json(OUT_JSON, doc)

    print(f"[bn-primes] authority={auth.id} primes={len(record)}")
    for r in record:
        print(f"  {r['symbol']:<28} {r['bits']:>5} bits  sha256={r['sha256'][:16]}")
    print(f"  -> {rel(OUT_RS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
