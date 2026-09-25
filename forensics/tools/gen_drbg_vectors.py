#!/usr/bin/env python3
"""openssl-rs — the DRBG construction-vector generator behind `CT-DRBG`.

`CT-DRBG` is the second, *construction* evidence plane for Phase 9's three provider DRBGs —
`providers/implementations/rands/drbg_ctr.c.in`, `drbg_hash.c.in` and `drbg_hmac.c.in`, published
as the default provider's three `OSSL_OP_RAND` rows. `RT-DRBG` answers "does the candidate behave
like the authority"; this court answers "does the candidate produce the standard's bytes", which
the differential plane cannot answer, because two implementations can agree byte for byte and both
be wrong (`forensics/tools/correctness_vectors.py`'s header, D201/D208).

The corpus, as found in the pinned tree (verified, not assumed)
-------------------------------------------------------------
`test/recipes/30-test_evp_data/evprand.txt` (79987 lines, sha256 recorded in `inputs[]`) is a
`test/evp_test.c` data file, **not** a hand-written KAT sheet. Its stanzas are the *modern*
`EVP_RAND` shape: `test/evp_test.c`'s `rand_test_init`/`rand_test_run` (`rand_test_run` at
`test/evp_test.c:3809-3928`) fetch the named DRBG with `EVP_RAND_fetch`, fetch a **`TEST-RAND`**
parent (`EVP_RAND_fetch(libctx, "TEST-RAND", "-fips")`, `:3692`), set the parent's strength, set
the DRBG's `cipher`/`digest`/`use_derivation_function` (and a hard-coded `"HMAC"` MAC) through
`EVP_RAND_CTX_set_params`, then per repeat instantiate the *parent* with
`test_entropy`/`test_nonce`, instantiate the *child* with the personalisation string, and call
`EVP_RAND_generate` **twice**, comparing the corpus's `Output.N` with the bytes the *second*
generate produced (`:3892-3908`). The header at line 30-31 names the source and the URL:

    # Test vectors come from:
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/
    #   documents/drbg/drbgtestvectors.zip

So the corpus is NIST CAVP `drbgtestvectors.zip`, reached through OpenSSL's own driver. No network
fetch is used and none is permitted (`docs/AUTHORITY_POLICY.md`): the bytes are already in the
pinned tree.

The `RAND = ` stanza count, measured from the file, is **967**: CTR-DRBG 289, HASH-DRBG 339,
HMAC-DRBG 339. 960 stanzas carry 15 repeats (`.0`..`.14`) and 1 (the `CAVP Large Seed`) carries
one; the remaining 6 carry no output at all. The `Type`s, `Title`s and per-DRBG counts are the
generated file's own census; this docstring types no number the generator does not also emit.

`evpkdf_hmac_drbg.txt` is **not** mirrored here
----------------------------------------------
`forensics/tools/phase9_courts.py`'s `PENDING_COURTS["CT-DRBG"]` says the pinned tree also carries
"`evpkdf_hmac_drbg.txt` … the HMAC-DRBG KDF cases". That sentence is accurate about the file's
*contents* and misleads about this court's *subject*: that file's stanzas are
`KDF = HMAC-DRBG-KDF`, i.e. `providers/implementations/kdfs/hmacdrbg_kdf.c.in`'s `EVP_KDF` row, not
`OSSL_OP_RAND`'s `HMAC-DRBG`. A KDF test exercises a different dispatch table with different
params (`digest:`/`hexentropy:`/`hexnonce:` controls) and is a separate court's corpus; mirroring
it into `CT-DRBG` would credit the DRBG row with another unit's work. It is named in `inputs[]`
as a *declined* input so the omission is auditable rather than silent.

What is reachable, and through which parameter
---------------------------------------------
The CAVP cases set entropy, nonce and personalisation string, and the **DRBG provider does not
accept `test_entropy`/`test_nonce` at all**: `drbg_ctr_set_ctx_params`' settable list is
`properties`, `cipher`, `use_derivation_function`, `core_prov_name`, `reseed_requests`,
`reseed_time_interval`; `drbg_hash` is the same with `digest`; `drbg_hmac` with `digest`/`mac`
(`drbg_ctr.c.in:820-827`, `drbg_hash.c.in:628-636`, `drbg_hmac.c.in:564-573`). The two keys live
on **`TEST-RAND`** (`test_rng.c.in:336-345`, `test_rng_set_ctx_params`), which is why the corpus is
driven through a `TEST-RAND` **parent** exactly as `evp_test` drives it. The personalisation string
is `EVP_RAND_instantiate`'s own argument, not a ctx param. So every in-scope output case is
reachable; the *only* unreachable stanzas are the six gated on `Availablein = fips`.

Left out, and on what rule
--------------------------
Two rules, both stated and both applied identically by the probe:

  * a stanza whose first-class keys include **`Availablein`** or **`Result`** is skipped. Six
    stanzas are `Availablein = fips` (`evprand.txt:79925`, `:79932`, `:79941`, `:79953`, `:79965`,
    `:79977`), the "truncated digests are not allowed" / "FIPS indicator callbacks" tests. They run
    only inside the FIPS provider (`test/evp_test.c:5369-5375`), this profile builds no FIPS module
    (D310), and four of the six expect `Result = EVP_RAND_CTX_set_params` — a *refusal*, not an
    output, and two more set `CtrlInit = digest-check:0`. None is a construction vector for the
    default provider's rows.
  * a stanza that carries no `RAND` key (a `Title = ` header) is metadata, not a case.

Nothing else is omitted: every remaining stanza (961 of them) and every repeat is mirrored, so the
`Output.N` bytes this court checks are the corpus's own and a shortened corpus would be visible in
the generator's own census.

The probe's share of the work
-----------------------------
The vector file carries the *expected* bytes; the inputs `EVP_RAND_instantiate`/`generate` need are
**re-read from the same corpus at run time** by `courts/phase9/ct_drbg.c`, not typed into the JSON.
That mirrors `ct_digest`/`ct_cipher`, whose inputs live in a call file the runner hands the probe,
and it is the point of the plane: a value that is re-read cannot be a transcription error. The two
sides derive their labels from the same positional rule (see `_label`), so the labels align without
either side reading the other.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

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

GENERATOR = "forensics/tools/gen_drbg_vectors.py"
VECTOR_PATH = REPO_ROOT / "forensics" / "vectors" / "drbg.json"

# The corpus, relative to the admitted source tree.
CORPUS_RELPATH = "test/recipes/30-test_evp_data/evprand.txt"
# Declined input: the HMAC-DRBG **KDF** vector file (a different unit; see the module docstring).
DECLINED_RELPATH = "test/recipes/30-test_evp_data/evpkdf_hmac_drbg.txt"

# The three DRBG rows, in the default provider's own table order (`defltprov.c:404-414`).
DRBG_ORDER = ("CTR-DRBG", "HASH-DRBG", "HMAC-DRBG")

# The `OSSL_OP_RAND` param keys the provider's settable list does *not* carry, and which therefore
# arrive through the `TEST-RAND` parent: named here so the reachability note above is checkable.
CORPUS_INPUT_FIELDS = (
    "Entropy",
    "Nonce",
    "PersonalisationString",
    "AdditionalInputA",
    "AdditionalInputB",
    "EntropyPredictionResistanceA",
    "EntropyPredictionResistanceB",
    "ReseedEntropy",
    "ReseedAdditionalInput",
)

PRIMARY_SOURCE = (
    "NIST CAVP drbgtestvectors.zip (SP 800-90A); "
    "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/"
    "documents/drbg/drbgtestvectors.zip"
)

NOTE = (
    "output.N is the corpus's own Output.N for repeat N, printed as lowercase hex; the stanza's "
    "other keys (Entropy.N, Nonce.N, PersonalisationString.N, AdditionalInputA/B.N, "
    "EntropyPredictionResistanceA/B.N, ReseedEntropy.N, ReseedAdditionalInput.N) are the inputs the "
    "probe re-reads from the same corpus. Mirrored from {corpus} by {gen}. Excluded: 6 stanzas "
    "gated on `Availablein = fips` (lines 79925, 79932, 79941, 79953, 79965, 79977) -- the FIPS "
    "provider is not built in this profile, four of them expect a refusal (Result), and two set "
    "CtrlInit. All other RAND stanzas and repeats are mirrored."
)


def corpus_path() -> Path:
    """The pinned corpus, resolved through the authority registry (never typed as an abs path)."""
    return authority_source(PRODUCTION_AUTHORITY) / CORPUS_RELPATH


def _split_numbered(key: str) -> tuple[str, int] | None:
    """`<name>.<n>` -> `(name, n)` when the suffix is all digits; else `None`."""
    dot = key.rfind(".")
    if dot <= 0:
        return None
    suffix = key[dot + 1:]
    if not suffix.isdigit():
        return None
    return key[:dot], int(suffix)


def _stanzas(text: str) -> list[tuple[int, list[tuple[int, str]]]]:
    """Split the corpus into stanzas the way `evp_test` reads it.

    A stanza is the run of lines up to the next blank line; `#`-comment lines are ignored and never
    terminate one (the corpus contains none between a stanza's own lines -- verified -- so this is
    exactly `evp_test`'s rule and not a loosening). Each stanza is `(first_line_number, pairs)`.
    """
    stanzas: list[tuple[int, list[tuple[int, str]]]] = []
    current: list[tuple[int, str]] = []
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
        current.append((lineno, line))
    if current:
        stanzas.append((start, current))
    return stanzas


def _fields(pairs: list[tuple[int, str]]) -> tuple[dict, dict]:
    """A stanza's plain keys and its `<name>.<n>` keys, last-wins on duplicates."""
    plain: dict[str, str] = {}
    numbered: dict[tuple[str, int], str] = {}
    for _lineno, line in pairs:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        split = _split_numbered(key)
        if split is None:
            plain[key] = value
        else:
            numbered[split] = value
    return plain, numbered


def _mirror(text: str, corpus_relpath: str):
    """Mirror every in-scope `RAND` stanza; return `(vectors, omitted)`.

    A stanza is in scope iff it has a `RAND` key and neither `Availablein` nor `Result`. The label
    is `<drbg-lowercased>.<emitted-index>` -- a purely positional rule the C probe reproduces
    exactly (its `ct_flush` counts emitted stanzas per DRBG in the same file order). `output.N`
    keys are the corpus's `Output.N`, lowercased, so the bytes the probe prints compare as strings.
    """
    vectors: list[dict] = []
    omitted: list[dict] = []
    seen: dict[str, int] = {drbg: 0 for drbg in DRBG_ORDER}
    title: str | None = None

    for lineno, pairs in _stanzas(text):
        plain, numbered = _fields(pairs)
        if "RAND" not in plain:
            if "Title" in plain:
                title = plain["Title"]
            continue

        drbg = plain["RAND"]
        if "Availablein" in plain or "Result" in plain:
            omitted.append({"line": lineno, "drbg": drbg, "title": title,
                            "reason": "gated: Availablein/Result (FIPS-provider-only)"})
            continue
        if drbg not in DRBG_ORDER:
            omitted.append({"line": lineno, "drbg": drbg, "title": title,
                            "reason": "unknown DRBG name"})
            continue

        outputs = {index: value for (name, index), value in numbered.items() if name == "Output"}
        if not outputs:
            omitted.append({"line": lineno, "drbg": drbg, "title": title,
                            "reason": "no Output.N (no construction value)"})
            continue

        label = f"{drbg.lower()}.{seen[drbg]}"
        seen[drbg] += 1
        expected = {f"output.{index}": outputs[index].lower() for index in sorted(outputs)}
        # Sanity: the repeats are Contiguous from 0, which is what the probe assumes.
        if sorted(outputs) != list(range(len(outputs))):
            raise SystemExit(f"{corpus_relpath}:{lineno}: Output.N is not contiguous")
        vectors.append({
            "label": label,
            "drbg": drbg,
            "expected": expected,
            "note": (f"output.N = lowercase hex; mirror {corpus_relpath} line {lineno}"
                     f"{'' if title is None else f', Title {title!r}'}"),
        })

    return vectors, omitted, seen


def build_document(corpus: Path) -> dict:
    text = corpus.read_text(encoding="utf-8")
    vectors, _omitted, seen = _mirror(text, rel(corpus))
    total_outputs = sum(len(v["expected"]) for v in vectors)
    provenance_note = NOTE.format(corpus=rel(corpus), gen=GENERATOR) + (
        f" Census: {len(vectors)} stanzas ({', '.join(f'{d} {seen[d]}' for d in DRBG_ORDER)}), "
        f"{total_outputs} outputs."
    )
    body = {
        "court": "CT-DRBG",
        "algorithm": "drbg",
        "primary_source": PRIMARY_SOURCE,
        "provenance": {
            "corpus": rel(corpus),
            "corpus_sha256": sha256_file(corpus),
            "note": provenance_note,
        },
        "vectors": vectors,
    }
    inputs = [
        InputRef(name="authority-evp-rand-vector-file", path=corpus).resolved(),
        InputRef(
            name="declined-hmac-drbg-kdf-vector-file",
            path=authority_source(PRODUCTION_AUTHORITY) / DECLINED_RELPATH,
            note="declined: the HMAC-DRBG **KDF** row, not the OSSL_OP_RAND HMAC-DRBG row",
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
                    help="override the corpus path (default: the pinned authority's evprand.txt)")
    ap.add_argument("--out", type=Path, default=VECTOR_PATH)
    args = ap.parse_args(argv)

    corpus = args.corpus if args.corpus is not None else corpus_path()
    if not corpus.is_file():
        raise SystemExit(f"gen_drbg_vectors: corpus not found: {corpus}")

    doc = build_document(corpus)
    digest = write_json(args.out, doc)
    body = doc["body"]
    per = {d: 0 for d in DRBG_ORDER}
    for v in body["vectors"]:
        per[v["drbg"]] += 1
    print(f"gen_drbg_vectors: {rel(args.out)}  sha256={digest}")
    print(f"  corpus {rel(corpus)}")
    print(f"  stanzas {len(body['vectors'])} "
          f"({', '.join(f'{d} {per[d]}' for d in DRBG_ORDER)}), "
          f"outputs {sum(len(v['expected']) for v in body['vectors'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
