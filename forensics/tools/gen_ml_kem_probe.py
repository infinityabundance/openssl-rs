#!/usr/bin/env python3
"""Generate `courts/phase8/ml_kem_probe.h` from the authority's own ML-KEM keygen KATs.

The probe header is a *generated* table, not a transcription (D33's rule): every byte in it is
read back out of `forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/
evppkey_ml_kem_{512,768,1024}_keygen.txt`, the same files the crate's unit tests parse and the
authority's own `evp_test` driver reads. Three things come out of each file's first record:

  * `Ctrl = hexseed:<hex>` -- the 64-byte `(d, z)` generation seed, which is what
    `EVP_PKEY_CTX_set_params`'s `OSSL_PKEY_PARAM_ML_KEM_SEED` carries, so `EVP_PKEY_generate`
    must reproduce the vector's keypair;
  * `CtrlOut = hexpub:<hex>` -- the expected encapsulation key, so the generated object's
    `pub` can be compared against the vector's own bytes rather than against a second
    transcription (a wrong constant here would be agreed on by both sides and invisible to a
    differential court -- D392, and D402's second-copy lesson);
  * the variant's name, so the row is named in a probe of the court that courts it.

Usage: `python3 forensics/tools/gen_ml_kem_probe.py`
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = REPO_ROOT / "forensics" / "authorities" / "src" / "openssl-3.6.4"
DATA = AUTHORITY / "test" / "recipes" / "30-test_evp_data"
OUT = REPO_ROOT / "courts" / "phase8" / "ml_kem_probe.h"

# The three variants, in the authority's `deflt_keymgmt[]` order.
VARIANTS = [("ML-KEM-512", 512), ("ML-KEM-768", 768), ("ML-KEM-1024", 1024)]


def first_record(text: str) -> dict[str, str]:
    """The first record's `key = value` pairs, up to the second `KeyGen` line."""
    out: dict[str, str] = {}
    seen_keygen = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = (p.strip() for p in line.split("=", 1))
        if k == "KeyGen":
            if seen_keygen:
                break
            seen_keygen = True
            continue
        if k == "CtrlOut":
            continue
        out.setdefault(k, v)
    # `CtrlOut` lines are repeated, so collect them by prefix.
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("CtrlOut = hexpub:"):
            out["hexpub"] = line.split(":", 1)[1]
            break
    return out


def ident(name: str) -> str:
    return name.lower().replace("-", "_")


def render_bytes(prefix: str, data: bytes) -> str:
    lines = [f"static const unsigned char {prefix}[{len(data)}] = {{"]
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i : i + 12])
        lines.append(f"    {chunk},")
    lines.append("};")
    return "\n".join(lines)


def main() -> int:
    rows = []
    for name, _bits in VARIANTS:
        path = DATA / f"evppkey_ml_kem_{name.split('-')[-1]}_keygen.txt"
        rec = first_record(path.read_text())
        seed = bytes.fromhex(rec["Ctrl"].split(":", 1)[1])
        pub = bytes.fromhex(rec["hexpub"])
        if len(seed) != 64:
            raise SystemExit(f"[ml-kem-probe] fatal: {path.name}'s seed is {len(seed)} bytes")
        rows.append((name, ident(name), seed, pub))

    body = [
        "/*",
        " * The three ML-KEM keygen vectors `courts/phase8/rt_keymgmt_probe.c` drives.",
        " *",
        " * **Generated, not transcribed** -- `forensics/tools/gen_ml_kem_probe.py` reads every",
        " * byte below out of the authority's own `test/recipes/30-test_evp_data/",
        " * evppkey_ml_kem_{512,768,1024}_keygen.txt`, the file the authority's `evp_test` driver",
        " * and this crate's `src/ml_kem/tests.rs` both read. Each row carries the vector's",
        " * 64-byte `(d, z)` seed -- what `OSSL_PKEY_PARAM_ML_KEM_SEED` takes -- and its expected",
        " * encapsulation key, so a generated object is compared against the vector's own bytes.",
        " *",
        " * Nothing is typed: a wrong constant here would be agreed on by both sides and invisible",
        " * to a differential court (D392, D402).",
        " */",
        "#ifndef OSSL_RS_ML_KEM_PROBE_H",
        "#define OSSL_RS_ML_KEM_PROBE_H",
        "",
        "#include <stddef.h>",
        "",
        "struct ml_kem_probe_row {",
        "    const char *name;",
        "    const unsigned char *seed;",
        "    size_t seedlen;",
        "    const unsigned char *pub;",
        "    size_t publen;",
        "};",
        "",
    ]
    for name, ident_name, seed, pub in rows:
        body.append(f"/* `{name}`: the vector's `hexseed`, then its `hexpub`. */")
        body.append(render_bytes(f"{ident_name}_seed", seed))
        body.append(render_bytes(f"{ident_name}_pub", pub))
        body.append("")
    body.append("static const struct ml_kem_probe_row ml_kem_kat_rows[3] = {")
    for name, ident_name, seed, pub in rows:
        body.append(
            f'    {{ "{name}", {ident_name}_seed, {len(seed)}, {ident_name}_pub, {len(pub)} }},'
        )
    body.append("};")
    body.append("")
    body.append("#endif /* OSSL_RS_ML_KEM_PROBE_H */")
    OUT.write_text("\n".join(body) + "\n")
    print(f"[ml-kem-probe] {len(rows)} row(s); wrote {OUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
