#!/usr/bin/env python3
"""openssl-rs — the PKCS#12 KDF construction-vector generator behind `CT-PKCS12`.

`CT-PKCS12` is the second, *construction* evidence plane for Phase 10's PKCS#12 key derivation —
`crypto/pkcs12/p12_key.c`'s `PKCS12_key_gen_uni`, which derives through the provider `PKCS12KDF`
row (`providers/implementations/kdfs/pkcs12kdf.c`, landed in `src/provider/kdf.rs`). `RT-PKCS12`
answers "does the candidate behave like the authority"; this court answers "does the candidate
produce the corpus's bytes", which the differential plane cannot answer, because two
implementations can agree byte for byte and both be wrong
(`forensics/tools/correctness_vectors.py`'s header, D201/D208).

The corpus, as found in the pinned tree (verified, not assumed)
-------------------------------------------------------------
`test/recipes/30-test_evp_data/evppbe_pkcs12.txt` is a `test/evp_test.c` data file with `PBE =
pkcs12` stanzas, six of them. `test/evp_test.c`'s `pbe_test_init` selects `PBE_TYPE_PKCS12` for the
`pkcs12` spelling and `pbe_test_run` (`test/evp_test.c:3425-3439`) fetches the stanza's `MD` and
calls **`PKCS12_key_gen_uni(pass, pass_len, salt, salt_len, id, iter, key_len, key, md)`**, then
compares the result with the stanza's `Key`. The `Password` field is `parse_bin`'d — the raw bytes,
not a text password — which is why the probe passes them to `PKCS12_key_gen_uni` and not to the
`asc`/`utf8` façades.

So the corpus is a **derivation KAT**: the inputs are `Password`, `Salt`, `id`, `iter` and `MD`, the
expected value is `Key`, and there is exactly one per stanza. The labels are
`pkcs12.<two-digit-emitted-index>` in file order, a purely positional rule the C probe reproduces
exactly, so neither side reads the other.

What is declined, and on what rule
----------------------------------
  * `test/recipes/30-test_evp_data/evppbe_pbkdf2.txt` — its identical-shaped stanzas are `PBE =
    pbkdf2` and drive `PKCS5_PBKDF2_HMAC`, which is Phase 7's (`src/evp/p5_crpt2.rs`), not this
    unit's. Mirroring them here would credit the PKCS#12 court with another stratum's work, the way
    `gen_drbg_vectors.py` declines `evpkdf_hmac_drbg.txt`. It is named in `inputs[]` as declined.
  * `test/recipes/80-test_pkcs12.t` and its `80-test_pkcs12_data/` — the container recipe. Every
    case in it reads or writes a `PKCS12` `PFX` through the `PKCS7`/`X509` object layers, which are
    Phase 12's and Phase 11's; none of them is a KDF vector, and the container is not this
    subphase's. Named in `inputs[]` as declined.

Zero new dependencies
---------------------
Only the Python standard library and `forensics/tools/atlas_common.py`; the probe is C in
`courts/phase10/ct_pkcs12.c` and links only the candidate distribution shell. Nothing here fetches,
vendors or shells out for a corpus.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    authority_source,
    rel,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/gen_pkcs12_vectors.py"
VECTOR_PATH = REPO_ROOT / "forensics" / "vectors" / "pkcs12.json"

# The corpus, relative to the admitted source tree.
CORPUS_RELPATH = "test/recipes/30-test_evp_data/evppbe_pkcs12.txt"
# Declined inputs, each named with its reason (see the module docstring).
DECLINED_PBKDF2_RELPATH = "test/recipes/30-test_evp_data/evppbe_pbkdf2.txt"
DECLINED_RECIPE_RELPATH = "test/recipes/80-test_pkcs12.t"

PRIMARY_SOURCE = (
    "PKCS#12 (RFC 7292) Appendix B -- the key/IV derivation; mirrored from the pinned authority's "
    "own test/recipes/30-test_evp_data/evppbe_pkcs12.txt (Title = `PKCS12 tests`)"
)

NOTE = (
    "One value per stanza: `pkcs12.NN` is `Key`, the lowercase hex of `PKCS12_key_gen_uni`'s "
    "`key_len`-byte output for the stanza's own Password/Salt/id/iter/MD. The inputs are re-read "
    "from {corpus} by the probe, so they are not typed twice. Excluded: {corpus}'s sibling "
    "`evppbe_pbkdf2.txt` (PBE = pbkdf2, a different unit) and the `80-test_pkcs12.t` container "
    "recipe (PKCS7/X509, not this unit). All six `PBE = pkcs12` stanzas are mirrored."
)


def corpus_path() -> Path:
    """The pinned corpus, resolved through the authority registry (never typed as an abs path)."""
    return authority_source(PRODUCTION_AUTHORITY) / CORPUS_RELPATH


def _stanzas(text: str) -> list[tuple[int, list[str]]]:
    """Split the corpus the way `evp_test` reads it: a blank line ends a stanza, `#` never does."""
    stanzas: list[tuple[int, list[str]]] = []
    current: list[str] = []
    start = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "":
            if current:
                stanzas.append((start, current))
                current = []
            continue
        if line.startswith("#"):
            continue
        if not current:
            start = lineno
        current.append(line)
    if current:
        stanzas.append((start, current))
    return stanzas


def _fields(pairs: list[str]) -> dict[str, str]:
    """A stanza's plain keys, last-wins on duplicates."""
    plain: dict[str, str] = {}
    for line in pairs:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        plain[key.strip()] = value.strip()
    return plain


def _mirror(text: str, corpus_relpath: str):
    """Mirror every `PBE = pkcs12` stanza; return `(vectors, omitted)`."""
    vectors: list[dict] = []
    omitted: list[dict] = []
    seen = 0
    title: str | None = None

    for lineno, pairs in _stanzas(text):
        plain = _fields(pairs)
        if "PBE" not in plain:
            if "Title" in plain:
                title = plain["Title"]
            continue
        if plain["PBE"] != "pkcs12":
            omitted.append({"line": lineno, "pbe": plain["PBE"], "title": title,
                            "reason": "not a PBE = pkcs12 stanza (a different unit's corpus)"})
            continue
        for key in ("Password", "Salt", "Key", "id", "iter", "MD"):
            if key not in plain:
                raise SystemExit(
                    f"{corpus_relpath}:{lineno}: a PBE = pkcs12 stanza lacks {key}"
                )
        label = f"pkcs12.{seen:02d}"
        seen += 1
        vectors.append({
            "label": label,
            "id": int(plain["id"]),
            "iter": int(plain["iter"]),
            "md": plain["MD"],
            "expected": plain["Key"].lower(),
            "note": (f"Key = lowercase hex of PKCS12_key_gen_uni's output; mirror "
                     f"{corpus_relpath} line {lineno}"
                     f"{'' if title is None else f', Title {title!r}'}"),
        })

    return vectors, omitted


def build_document(corpus: Path) -> dict:
    vectors, _omitted = _mirror(corpus.read_text(encoding="utf-8"), rel(corpus))
    body = {
        "court": "CT-PKCS12",
        "algorithm": "pkcs12-kdf",
        "primary_source": PRIMARY_SOURCE,
        "provenance": {
            "corpus": rel(corpus),
            "corpus_sha256": sha256_file(corpus),
            "note": NOTE.format(corpus=rel(corpus)),
        },
        "vectors": vectors,
    }
    inputs = [
        InputRef(name="authority-evp-pkcs12-vector-file", path=corpus).resolved(),
        InputRef(
            name="declined-pbkdf2-vector-file",
            path=authority_source(PRODUCTION_AUTHORITY) / DECLINED_PBKDF2_RELPATH,
            note="declined: PBE = pbkdf2 drives PKCS5_PBKDF2_HMAC (Phase 7), not PKCS12KDF",
        ).resolved(),
        InputRef(
            name="declined-pkcs12-container-recipe",
            path=authority_source(PRODUCTION_AUTHORITY) / DECLINED_RECIPE_RELPATH,
            note="declined: the PFX container reads/writes through PKCS7/X509 (Phases 12/11)",
        ).resolved(),
    ]
    return {
        "schema": "openssl-rs/correctness-vectors/v1",
        "kind": "correctness-vectors",
        "generator": GENERATOR,
        "authority": PRODUCTION_AUTHORITY,
        "inputs": inputs,
        "body": body,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=None,
                    help="override the corpus path (default: the pinned authority's "
                         "evppbe_pkcs12.txt)")
    ap.add_argument("--out", type=Path, default=VECTOR_PATH)
    args = ap.parse_args(argv)

    corpus = args.corpus if args.corpus is not None else corpus_path()
    if not corpus.is_file():
        raise SystemExit(f"gen_pkcs12_vectors: corpus not found: {corpus}")

    doc = build_document(corpus)
    digest = write_json(args.out, doc)
    body = doc["body"]
    print(f"gen_pkcs12_vectors: {rel(args.out)}  sha256={digest}")
    print(f"  corpus {rel(corpus)}")
    print(f"  vectors {len(body['vectors'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
