#!/usr/bin/env python3
"""openssl-rs — Phase 8's remaining provider *registration rows*, grouped by the unit that lands them.

Why this exists
---------------
`forensics/atlas/provider-algorithms.json` (D237) is the census of every algorithm registration
row *every* admitted provider publishes: `providers/defltprov.c`'s `deflt_ciphers[]`,
`deflt_kdfs[]`, `deflt_keymgmt[]` and their siblings are arrays of `OSSL_ALGORITHM`, and a row can
be missing from the crate — and from every export ledger — and still be a missing piece of the
contract. It records each row's `implementation_state` (`implemented` / `unimplemented`),
`owning_phase`, `table_symbol` and `dispatch_table_symbol`, but it is one flat list of a few
thousand rows and it does not say **which translation unit lands which row**. Phase 8 owns 306 of
them, of which 137 are unlanded; a session that wants to land them needs the work grouped by
`providers/implementations/**` file, because that is the unit of transcription (D327: a unit is
transcribed *whole*) and the unit a court arm can be written against.

So this document is a **projection**, not a plan written by hand: every count, name, table,
dispatch symbol and translation unit below is *read* from the census and from the pinned
authority's own provider tree (the unit that defines each `dispatch_table_symbol`), and the crate
file a table currently lives in is read from the crate's own `deflt_query`. Nothing here is a
parity claim; see `docs/PARITY_MODEL.md`.

How the translation unit is derived, and why it is not typed
-------------------------------------------------------------
A row's `dispatch_table_symbol` is the authority's own symbol (e.g. `ossl_kdf_hkdf_functions`),
and the unit that *defines* it is found from the pinned source tree alone, with no dependency on
the host's binutils (`check_evidence_portability.py`'s subject): a literal definition
(`SYM[] = {`) is a direct hit, and a macro-generated table — the `##`-concatenating
`MAKE_KEYMGMT_FUNCTIONS`, `RSA_SIG_FUNCTIONS`, `KDF_KEYEXCH_FUNCTIONS`, `MAKE_KDF_HKDF_FIXED_
DIGEST_FUNCTIONS` and their kin — is resolved by expanding each `#define` over each invocation in
the same file and requiring the *array definition* (`SYM[]`) in the result, so a file that merely
*references* the symbol is not mistaken for the one that defines it. The resolver answers exactly
one unit for every one of the 127 symbols this document groups, and was cross-checked against
`nm` over the authority's own `libcrypto.a` during development (127/127 agree); `nm` is not run
here.

Outputs
-------
  docs/PHASE-8-PROVIDER-ROWS.md

Why it is not a pipeline generator
----------------------------------
It is a *plan* renderer, like `docs/PHASE-8-SUBPHASES.md` itself, rather than an evidence artefact:
it needs the pinned authority's source tree (gitignored, `forensics/authorities/src/`) to resolve
translation units, so it has no tier for a runner that does not download the authority. It is
therefore not listed in `evidence_determinism.py`'s `GENERATORS`, and the document records the
census content hash it was rendered from so a reader can see when it has gone stale and re-run it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, content_hash, rel, write_text  # noqa: E402

GENERATOR = "forensics/tools/phase8_provider_rows.py"
ATLAS = REPO_ROOT / "forensics" / "atlas" / "provider-algorithms.json"
AUTHORITY = REPO_ROOT / "forensics" / "authorities" / "src" / "openssl-3.6.4"
PROVIDER_ROOT = AUTHORITY / "providers"
CRATE_QUERY = REPO_ROOT / "src" / "provider" / "digest.rs"
OUT = REPO_ROOT / "docs" / "PHASE-8-PROVIDER-ROWS.md"

# A unit **withheld** on this pass, keyed by the translation unit's repo-relative path, with the
# measured reason. It is a *claim about the authority and the crate*, so it is reviewed when the
# unit moves, and the document renders it under the unit's own heading rather than leaving an
# unexplained remainder. Two kinds are recorded here: a unit whose closure is not *reachable*
# (D382's `argon2.c.in`, D384's exchange units) and a unit that is reachable only behind a
# prerequisite or that the census tool itself refuses (D385's keymgmt units). Being here does
# **not** change the census: the rows stay `unimplemented` and the totals count them as unlanded.
# D386 discharged the one tool refusal this map recorded -- the authority's many-to-one dispatch
# symbols (`kdf_legacy_kmgmt.c`, `mac_legacy_kmgmt.c`) are now described by a partition-equality
# check in `gen_provider_algorithms.py` rather than refused -- so the legacy-KDF unit is landed and
# the remaining entries are reachability or prerequisite holds only.
WITHHELD: dict[str, str] = {
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/kdfs/argon2.c.in": (
        "**Withheld: not reachable on this profile, and recorded rather than stubbed.** The arm "
        "this profile compiles is *threaded*: `configuration.h:36` defines `OPENSSL_THREADS` and "
        "neither `OPENSSL_NO_DEFAULT_THREAD_POOL` nor `OPENSSL_NO_THREAD_POOL` is set, so "
        "`argon2.c.in:41-47` does **not** define `ARGON2_NO_THREADS` and `fill_mem_blocks_mt` "
        "(`:561-626`) is compiled alongside `fill_mem_blocks_st`. It calls "
        "`ossl_crypto_thread_start`, `ossl_crypto_thread_join` and `ossl_crypto_thread_clean`, "
        "three **internal** functions of `crypto/threads_pthread.c` (declared in "
        "`include/internal/thread.h:19`, not installed, so they are not in the export atlas and "
        "have no owning phase). The crate implements none of them, so D327's whole transcription "
        "cannot close: the three rows `ARGON2D`, `ARGON2I` and `ARGON2ID` become reachable once "
        "`crypto/threads_pthread.c`'s thread-start/join/clean trio lands, and only then."
    ),
    # The `OSSL_OP_KEYEXCH` group. D386 landed the crate's `OSSL_OP_KEYMGMT` arm -- the gate this
    # comment used to describe as absent -- and, on it, the `kdf_exch.c` unit. D387 landed
    # `dh_kmgmt.c` and `dh_exch.c.in`; D388 landed `ecx_kmgmt.c.in` and `ecx_exch.c.in`; D390 landed
    # `ec_kmgmt.c` and `ecdh_exch.c.in`, so **every `OSSL_OP_KEYEXCH` row the authority's
    # `deflt_keyexch[]` holds is landed and this group has no entry here.** The KEM group's one
    # entry is below, beside the keymgmt units.
    # The keymgmt group's **prerequisite-held and unreachable** units. `kdf_legacy_kmgmt.c` is
    # landed (D386), `dh_kmgmt.c` is landed (D387), `ecx_kmgmt.c.in`, `mac_legacy_kmgmt.c` and
    # `ec_kmgmt.c` are landed (D388-D390), and `rsa_kmgmt.c` and `dsa_kmgmt.c` land at D391 with the
    # two crypto validators they were held on -- so **every row of the authority's
    # `deflt_keymgmt[]` that this profile's crate can build is now landed**, and the entries below
    # are the four PQC units, each built on an implementation the crate does not have.
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/ml_dsa_kmgmt.c.in": (
        "**Withheld: not reachable.** The unit's three rows (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`) "
        "are built on `ossl_ml_dsa_*` (`crypto/ml_dsa/`), which the crate does not have -- its "
        "function list (`ossl_ml_dsa_key_new`/`_free`/`_dup`/`_equal`, "
        "`ossl_ml_dsa_generate_key`, the encode/decode pair and the `_sig_*` family) matches no "
        "symbol in this tree."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/ml_kem_kmgmt.c.in": (
        "**Withheld: not reachable.** The unit's three rows (`ML-KEM-512`, `ML-KEM-768`, "
        "`ML-KEM-1024`) are built on `ossl_ml_kem_*` (`crypto/ml_kem/`), which the crate does not "
        "have -- `ossl_ml_kem_encap_rand`/`_encap_seed`, `ossl_ml_kem_decap`, the key "
        "encode/decode pair and `ossl_ml_kem_get_vinfo` are none of them in this tree."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/mlx_kmgmt.c.in": (
        "**Withheld: not reachable.** The unit's four hybrid rows (`X25519MLKEM768`, "
        "`X448MLKEM1024`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) are built on **both** an ECX "
        "or EC half and the ML-KEM half: they call `ossl_ml_kem_get_vinfo` and `ossl_mlx_*`, and "
        "depend on `crypto/ml_kem/` and `crypto/mlx/`, neither of which is in this tree."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/slh_dsa_kmgmt.c.in": (
        "**Withheld: not reachable.** The unit's twelve rows (`SLH-DSA-SHA2-*`, `SLH-DSA-SHAKE-*`) "
        "are built on `ossl_slh_dsa_*` (`crypto/slh_dsa/`), which the crate does not have -- "
        "`ossl_slh_dsa_generate_key`, `ossl_slh_dsa_key_dup`/`_equal`/`_free`/`_get`, and the "
        "`ossl_slh_dsa_hash_ctx_new`/`_free` pair are none of them in this tree."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/kem/ec_kem.c.in": (
        "**Withheld: the unit's `EC` KEM row, on a partial transcription that is named rather "
        "than claimed.** `src/provider/ec_kem.rs` carries **one** of the unit's functions, "
        "`ossl_ec_dhkem_derive_private` (`ec_kem.c.in:387-461`), `#[no_mangle]` because the "
        "authority defines it non-`static` and `crypto/ec/ec_key.c`'s `ossl_ec_generate_key_dhkem` "
        "calls it across translation units -- which is exactly what D390's `ec_kmgmt.c` landing "
        "needs. The rest of the unit is the `EC` KEM row's own dispatch "
        "(`ossl_ec_asym_kem_functions`, `:805-822`) and the twelve `eckem_*` functions plus the "
        "`dhkem_encap`/`dhkem_decap` pair it dispatches to, and it is **not** transcribed: "
        "the row's public-key decode path and its `OSSL_PKEY_PARAM_DHKEM_IKM` generate path reach "
        "`eckey_frompub`/`eckey_check` and the HPKE-derived encapsulation the crate models only "
        "partly, so the one row that would land (`OSSL_OP_KEM` `EC`, `defltprov.c:533`) is left "
        "`unimplemented` rather than half-driven. The function that *is* landed is drivable and "
        "driven: `RT-KEYMGMT`'s `EC` arm builds the key `ossl_ec_generate_key_dhkem` would be "
        "reached on. The entry stays until the row's own dispatch lands, so the census and this "
        "document agree that the row is open."
    ),
    # The `OSSL_OP_SIGNATURE` group. D392 opened the operation: the `deflt_query` arm and
    # `DEFLT_SIGNATURES` land with `mac_legacy_sig.c`'s four rows and `dsa_sig.c.in`'s ten. D393
    # landed `ecdsa_sig.c.in`'s ten on `der_ec_sig.c`, D394 `eddsa_sig.c.in`'s five on
    # `der_ecx_key.c`, and D395 `rsa_sig.c.in`'s fourteen on `der_rsa_sig.c`, `der_rsa_key.c`'s PSS
    # params writer and `securitycheck*.c` -- so **every reachable `OSSL_OP_SIGNATURE` row is now
    # landed** and the entries below are the units that remain, each held on a named callee or on a
    # `crypto/` implementation the crate does not have.
    #
    # `dsa_sig.c.in` is **not** here: its only non-FIPS prerequisites are
    # `providers/common/digest_to_nid.c` and `der_dsa_sig.c`, both landed as
    # `src/provider/digest_to_nid.rs` and `src/provider/der_dsa_sig.rs`. That is the measurement
    # that let DSA land before RSA and ECDSA: `ossl_dsa_check_key`, the callee this comment would
    # otherwise have named, is reached only from `dsa_sig.c.in`'s `#ifdef FIPS_MODULE` block at
    # `:266`, so `providers/common/securitycheck.c` is not on the DSA path at all.
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/signature/ecdsa_sig.c.in": (
        "**Withheld: the unit's ten rows, on one unlanded callee.** `ossl_digest_get_approved_nid` "
        "is already landed (`src/provider/digest_to_nid.rs`), so what remains is "
        "`providers/common/der/der_ec_sig.c`'s `ossl_DER_w_algorithmIdentifier_ECDSA_with_MD` "
        "(`ecdsa_sig.c.in:234`), which is not in this tree. Everything else the unit reaches is "
        "either landed (`ossl_ecdsa_deterministic_sign` is `src/ec/ecdsa_ossl.rs`'s) or inside a "
        "`#ifdef FIPS_MODULE` arm, so it is the smallest remaining signature prerequisite."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/signature/eddsa_sig.c.in": (
        "**Withheld: the unit's five rows, on one unlanded callee.** `eddsa_signverify_init` builds "
        "the AlgorithmIdentifier through "
        "`providers/common/der/der_ecx_key.c`'s `ossl_DER_w_algorithmIdentifier_ED25519` and "
        "`_ED448` (`eddsa_sig.c.in:279-282`), which is not in this tree. The four OIDs and the two "
        "writers are the whole prerequisite: every other callee "
        "(`ossl_ed25519_sign`/`_verify`, `ossl_ed448_sign`/`_verify`, `ossl_ecx_key_up_ref`/"
        "`_free`) is landed, so `EdDSA` is one small unit behind `DSA`'s landing."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/signature/sm2_sig.c.in": (
        "**Withheld: the unit's one row, on two unlanded units.** `sm2_sig.c.in`'s sign path is "
        "`ossl_sm2_internal_sign`/`ossl_sm2_internal_verify` and `ossl_sm2_compute_z_digest` "
        "(`crypto/sm2/sm2_sign.c`), and its AlgorithmIdentifier comes from "
        "`providers/common/der/der_sm2_sig.c`. Neither unit is in this tree, so the single `SM2` "
        "row costs two whole transcriptions and lands with them."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/signature/ml_dsa_sig.c.in": (
        "**Withheld: not reachable.** The unit's three rows (`ML-DSA-44`, `ML-DSA-65`, "
        "`ML-DSA-87`) dispatch to `ossl_ml_dsa_*` (`crypto/ml_dsa/`), which the crate does not "
        "have."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/signature/slh_dsa_sig.c.in": (
        "**Withheld: not reachable.** The unit's twelve rows (`SLH-DSA-SHA2-*`, "
        "`SLH-DSA-SHAKE-*`) dispatch to `ossl_slh_dsa_*` (`crypto/slh_dsa/`), which the crate does "
        "not have."
    ),
}

# The operations this document's first section executes. The task that commissioned this
# document names them: the `OSSL_OP_KDF` rows and the `OSSL_OP_SKEYMGMT` pair. They are listed
# rather than derived because they are *this session's* choice of where to start, and a plan
# document is allowed to state its own order — but the rows under them are read, not typed.
FIRST_GROUP = ("OSSL_OP_KDF", "OSSL_OP_SKEYMGMT")

# --- the crate's own `deflt_query`, so a table's crate home is read, not typed -----------------

ARM = re.compile(
    r"if\s+operation_id\s*==\s*([A-Za-z0-9_:]+)\s*\{\s*return\s+([A-Za-z0-9_:]+)\s*(\(\)|\.as_ptr\(\))\s*;"
)


def crate_files() -> dict[str, str]:
    """`OSSL_OP_*` -> the crate file whose table `deflt_query` answers for it.

    The same anchors `gen_provider_algorithms.py` walks: the arms of `deflt_query` in
    `src/provider/digest.rs`, and the module each arm's table path names.
    """
    text = CRATE_QUERY.read_text(encoding="utf-8")
    start = text.index('unsafe extern "C" fn deflt_query(')
    end = text.index("\n}", start)
    out: dict[str, str] = {}
    for m in ARM.finditer(text[start:end]):
        operation = m.group(1).split("::")[-1]
        segments = m.group(2).split("::")
        if len(segments) == 1:
            path = CRATE_QUERY
        else:
            module = REPO_ROOT / "src" / Path(*segments[1:-1])
            path = module.with_suffix(".rs")
            if not path.is_file():
                path = module / "mod.rs"
        out[operation] = rel(path)
    return out


# --- the translation unit that defines a dispatch-table symbol, from the source tree alone ----

DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\(([^)]*)\)\s*(.*)$")


def logical_lines(text: str) -> list[str]:
    """The preprocessor's line-splicing: a trailing backslash joins the next physical line."""
    out: list[str] = []
    buf: str | None = None
    for line in text.splitlines():
        buf = line if buf is None else buf + line
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        out.append(buf)
        buf = None
    if buf is not None:
        out.append(buf)
    return out


def macro_defines(text: str) -> dict[str, tuple[str, str]]:
    """`NAME -> (params, body)` for every `##`-concatenating function-like macro in a file."""
    out: dict[str, tuple[str, str]] = {}
    for line in logical_lines(text):
        m = DEFINE.match(line)
        if m and "##" in m.group(3):
            out[m.group(1)] = (m.group(2), m.group(3))
    return out


def defines_symbol(defs: dict[str, tuple[str, str]], text: str, symbol: str) -> bool:
    """Whether expanding one of the file's `##` macros yields an *array definition* of `symbol`.

    The array declarator (`SYMBOL[]`) is what separates a definition from a reference: the encoder
    and decoder templates name `ossl_<alg>_keymgmt_functions` inside their own dispatch macro, and
    without this test they would be read as the unit that defines it.
    """
    array = re.compile(r"\b" + re.escape(symbol) + r"\s*\[\s*\]")
    for name, (params, body) in defs.items():
        plist = [p.strip() for p in params.split(",")] if params.strip() else []
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(([^()]*)\)", text):
            args = [a.strip() for a in m.group(1).split(",")]
            if len(args) != len(plist):
                continue
            expanded = body
            for p, a in zip(plist, args):
                expanded = re.sub(r"\b" + re.escape(p) + r"\b", lambda _m, a=a: a, expanded)
            if array.search(expanded.replace("##", "")):
                return True
    return False


def unit_index() -> tuple[dict[str, str], dict[str, dict[str, tuple[str, str]]]]:
    """The provider `.c`/`.c.in` files, their texts, and their macro tables."""
    files = sorted(
        p for p in PROVIDER_ROOT.rglob("*") if p.suffix == ".c" or p.name.endswith(".c.in")
    )
    texts = {p: p.read_text(encoding="utf-8", errors="replace") for p in files}
    defs = {p: macro_defines(texts[p]) for p in files}
    return texts, defs


def resolve_unit(symbol: str, texts: dict, defs: dict) -> str:
    """The `providers/implementations/**` unit that defines `symbol`, exactly one."""
    literal = [
        p
        for p, t in texts.items()
        if "/include/" not in str(p) and re.search(r"\b" + re.escape(symbol) + r"\s*\[", t)
    ]
    if len(literal) == 1:
        return rel(literal[0])
    hits = [
        p
        for p in texts
        if "/include/" not in str(p) and defines_symbol(defs[p], texts[p], symbol)
    ]
    if len(hits) != 1:
        raise SystemExit(
            f"[phase8-provider-rows] {symbol} resolves to {len(hits)} unit(s) "
            f"({[rel(p) for p in hits]}); a row whose unit is ambiguous must not be grouped in "
            "silence"
        )
    return rel(hits[0])


# --- the document -------------------------------------------------------------------------------


def load_atlas() -> dict:
    return json.loads(ATLAS.read_text(encoding="utf-8"))


def main() -> int:
    doc = load_atlas()
    rows = doc["body"]["rows"]
    # The census carries no `body_hash` of its own; its body's content hash is the same kind of
    # provenance and is a function of the rows alone.
    census_hash = content_hash(doc["body"])
    crate = crate_files()
    texts, defs = unit_index()

    owned = [r for r in rows if r["owning_phase"] == 8]
    implemented = [r for r in owned if r["implementation_state"] == "implemented"]
    unlanded = [r for r in owned if r["implementation_state"] == "unimplemented"]

    first = [r for r in owned if r["operation"] in FIRST_GROUP]
    rest = [r for r in unlanded if r["operation"] not in FIRST_GROUP]
    first_landed = [r for r in first if r["implementation_state"] == "implemented"]
    universe = first + rest

    units: dict[str, list[dict]] = {}
    for r in universe:
        units.setdefault(resolve_unit(r["dispatch_table_symbol"], texts, defs), []).append(r)

    def crate_file_for(row: dict) -> str:
        return crate.get(row["operation"], "_no arm yet_")

    lines: list[str] = []
    w = lines.append

    w("# Phase 8 provider rows — the remaining registration rows, grouped by translation unit")
    w("")
    w("Generated by `forensics/tools/phase8_provider_rows.py` from")
    w("`forensics/atlas/provider-algorithms.json` (the authority-derived census, D237) and the")
    w("pinned authority's own provider tree, which is where each `dispatch_table_symbol`'s")
    w("defining translation unit is read from. **Do not edit by hand.** Every count, name, table")
    w("and unit below is a function of those inputs; the census body's content hash is recorded at")
    w("the foot of this document so a reader can see which generation it describes. Nothing here")
    w("is a parity claim; see `docs/PARITY_MODEL.md`.")
    w("")
    w("A row's **translation unit** is the `providers/implementations/**` file that defines its")
    w("`dispatch_table_symbol` — the file `docs/DECISIONS.md` D327 transcribes *whole*. The")
    w("**crate file** column names where the authority's `deflt_*` table, were it published, would")
    w("live: the module the crate's own `deflt_query` answers that operation with, or a dash while")
    w("the operation has no arm.")
    w("")
    w("## Totals")
    w("")
    w("Read from the census's own `implementation_state` for the rows this stratum owns")
    w("(`owning_phase == 8`).")
    w("")
    w("| quantity | count |")
    w("|---|---|")
    w(f"| provider rows this stratum owns | {len(owned)} |")
    w(f"| of those, implemented | {len(implemented)} |")
    w(f"| of those, unlanded | {len(unlanded)} |")
    w("")
    w(
        f"The document below names all **{len(unlanded)}** unlanded rows this stratum owns across "
        f"**{len(units)}** translation units, and — so the first group can be read whole — the "
        f"**{len(first_landed)}** already-landed rows of the two operations that group covers: the "
        f"first group in full ({len(first)} rows in `OSSL_OP_KDF` and `OSSL_OP_SKEYMGMT`) plus "
        f"every other unlanded row ({len(rest)}). The identity "
        f"`{len(owned)} = {len(implemented)} + {len(unlanded)}` holds."
    )
    w("")
    w("## The first group: the `OSSL_OP_KDF` rows and the `OSSL_OP_SKEYMGMT` pair")
    w("")
    w("Every row this stratum owns under these two operations, landed or not, so a reader can see")
    w("the group whole. The work order is this table's unit order, and each unit is transcribed")
    w("whole (D327); a unit whose closure is not reachable is named here with its coordinate")
    w("rather than stubbed.")
    w("")
    first_units: dict[str, list[dict]] = {}
    for r in first:
        first_units.setdefault(resolve_unit(r["dispatch_table_symbol"], texts, defs), []).append(r)
    for unit in sorted(first_units):
        w(f"### `{unit}`")
        w("")
        w("| table | dispatch table symbol | operation | algorithm name(s) | state | crate file |")
        w("|---|---|---|---|---|---|")
        for r in sorted(first_units[unit], key=lambda r: (r["operation"], r["row_order"])):
            w(
                f"| `{r['table_symbol']}` | `{r['dispatch_table_symbol']}` | `{r['operation']}` | "
                f"`{':'.join(r['aliases'])}` | {r['implementation_state']} | `{crate_file_for(r)}` |"
            )
        w("")
        if unit in WITHHELD:
            w(WITHHELD[unit])
            w("")
    w("## The remaining rows, grouped by translation unit")
    w("")
    w("Every other unlanded row this stratum owns, grouped by the unit that defines its")
    w("`dispatch_table_symbol`, then listed by its `deflt_*` table in the authority's order.")
    w("")
    for unit in sorted(units):
        if unit in first_units:
            # The first group's units are shown whole above; the rows of theirs that remain
            # unlanded are not repeated here.
            continue
        group = units[unit]
        w(f"### `{unit}` — {len(group)} row(s)")
        w("")
        w("| table | dispatch table symbol | operation | algorithm name(s) | crate file |")
        w("|---|---|---|---|---|")
        for r in sorted(group, key=lambda r: (r["operation"], r["table_symbol"], r["row_order"])):
            w(
                f"| `{r['table_symbol']}` | `{r['dispatch_table_symbol']}` | `{r['operation']}` | "
                f"`{':'.join(r['aliases'])}` | `{crate_file_for(r)}` |"
            )
        w("")
        if unit in WITHHELD:
            w(WITHHELD[unit])
            w("")
    w("## Provenance")
    w("")
    w("| field | value |")
    w("|---|---|")
    w(f"| generator | `{GENERATOR}` |")
    w(f"| census | `{rel(ATLAS)}` |")
    w(f"| census content hash | `{census_hash}` |")
    w(f"| authority tree | `{rel(AUTHORITY)}` |")
    w(f"| crate query read | `{rel(CRATE_QUERY)}` |")
    w("")

    write_text(OUT, "\n".join(lines) + "\n")
    print(
        f"[phase8-provider-rows] {len(owned)} owned, {len(implemented)} implemented, "
        f"{len(unlanded)} unlanded; named {len(universe)} rows in {len(units)} unit(s); "
        f"wrote {rel(OUT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
