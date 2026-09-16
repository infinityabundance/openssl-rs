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
import json
import re
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


def render_rust(authority_id: str, record: list[dict], values: dict[str, bytes]) -> str:
    """The generated file, as a pure function of the authority identity and the record.

    Factored out so that the weak tier can rebuild it from the committed JSON alone. That is
    what makes the check exact rather than approximate: both tiers call this, so a difference
    is a difference in the *inputs* and never in the rendering.
    """
    body = [
        "//! The authority's named primes — GENERATED, do not edit.",
        "//!",
        "//! Regenerate with `forensics/tools/gen_bn_primes.py` inside the court",
        "//! container. The values are read back from the admitted authority rather than",
        "//! transcribed from `bn_const.c`, because a typo in an 8192-bit prime is",
        "//! invisible to everything except a comparison with the authority itself.",
        "//!",
        f"//! Authority: `{authority_id}`.",
        "",
        "// The constants are named after the authority's own exported functions, so a",
        "// reader can check one against `nm libcrypto.so.3` without a mapping table.",
        "// Renaming them to Rust case would break that correspondence and buy nothing:",
        "// they are data, referenced from exactly one module.",
        "#![allow(non_upper_case_globals)]",
        "",
    ]
    for r in record:
        body.append(rust_array(r["symbol"], values[r["symbol"]]))
        body.append("")
    return "\n".join(body)


def check_against_artefact() -> int:
    """The weak tier: rebuild the generated Rust from the committed artefact.

    Used when the authority is absent, which is the case on every runner that has only the
    repository. It catches a hand-edited `prime_data.rs` and a JSON that has drifted from it.
    It cannot catch the authority having changed -- the authority is pinned by archive hash
    elsewhere, and the court, which has it, re-derives. Which tier ran is printed, because a
    check that silently weakens is the thing this project exists not to have.

    The *values* are not in the JSON, only their SHA-256, so the rebuild takes the bytes out of
    the committed Rust and re-hashes them: a byte changed in `prime_data.rs` then changes the
    digest and fails, which is the property that matters. The alternative -- storing 8192-bit
    primes twice -- would put two copies of the same data in the repository and let them
    disagree.
    """
    if not OUT_JSON.is_file() or not OUT_RS.is_file():
        print(
            f"[{GENERATOR}] neither the authority nor the pair "
            f"{rel(OUT_JSON)}/{rel(OUT_RS)} is present; nothing can be checked",
            file=sys.stderr,
        )
        return 1
    doc = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    record = doc["body"]["primes"]
    rust = OUT_RS.read_text(encoding="utf-8")

    # Recover the bytes from the committed Rust, so the digest check is against what is on
    # disk rather than against what the JSON wishes were on disk.
    values: dict[str, bytes] = {}
    for r in record:
        name = r["symbol"]
        m = re.search(
            rf"^pub\(crate\) const {re.escape(name)}: \[u8; \d+\] = \[\n(.*?)\n\];$",
            rust, re.M | re.S)
        if m is None:
            print(
                f"[{GENERATOR}] {rel(OUT_RS)} has no `{name}` array, which "
                f"{rel(OUT_JSON)} records as one of {len(record)} primes",
                file=sys.stderr,
            )
            return 1
        # Every byte is its own `0xNN` token, twelve to a line; joining the tokens rather
        # than stripping a prefix per line is what makes the recovery independent of the
        # wrapping width.
        body = re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1))
        if not body:
            print(
                f"[{GENERATOR}] {name} in {rel(OUT_RS)} has no byte literals",
                file=sys.stderr,
            )
            return 1
        values[name] = bytes(int(b, 16) for b in body)
        if len(values[name]) != r["bytes"] or hashlib.sha256(values[name]).hexdigest() != r["sha256"]:
            print(
                f"[{GENERATOR}] {name} in {rel(OUT_RS)} does not hash to the value "
                f"{rel(OUT_JSON)} records; the generated file was edited by hand or the "
                f"artefact is stale",
                file=sys.stderr,
            )
            return 1

    expected = render_rust(doc["authority"], record, values)
    if rust != expected:
        exp = expected.splitlines()
        act = rust.splitlines()
        at = next((i for i, (a, b) in enumerate(zip(act, exp)) if a != b),
                  min(len(act), len(exp)))
        print(
            f"[{GENERATOR}] {rel(OUT_RS)} does not match {rel(OUT_JSON)}; first "
            f"difference at line {at + 1}:\n"
            f"  committed: {act[at] if at < len(act) else '<eof>'}\n"
            f"  from json: {exp[at] if at < len(exp) else '<eof>'}",
            file=sys.stderr,
        )
        return 1

    print(
        f"[bn-primes] ok (weak tier, authority absent): {rel(OUT_RS)} matches "
        f"{rel(OUT_JSON)} over {len(record)} primes"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    # The values come from a probe compiled against the **admitted authority prefix**, so a
    # runner without the authority cannot derive them. Two tiers, exactly as
    # `gen_ctype_table.py` and `gen_err_raise_sites.py`: re-derive when the prefix is present,
    # and rebuild-and-compare from the committed pair when it is not. Which tier ran is
    # printed. See docs/DECISIONS.md D135, which closes the gap D109 recorded for both of the
    # `.rs` generators.
    if not (resolve_authority(args.authority).prefix / "include" / "openssl" / "bn.h").is_file():
        return check_against_artefact()

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

    record = []
    for name in GET_RFC + GET0:
        value = values[name]
        record.append({
            "symbol": name,
            "bits": len(value) * 8,
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        })

    write_text(OUT_RS, render_rust(auth.id, record, values))

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
