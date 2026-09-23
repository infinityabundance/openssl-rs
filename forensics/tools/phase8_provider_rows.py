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
    # `dh_kmgmt.c` and `dh_exch.c.in`, so neither of those is here any more. `ecdh_exch.c.in` is
    # withheld on the `EC` keymgmt row and the `EC_GROUP`/`EC_POINT` layer; `ecx_exch.c.in` on the
    # four ECX keymgmt rows of `ecx_kmgmt.c.in`.
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/exchange/ecdh_exch.c.in": (
        "**Withheld: behind the `EC` keymgmt row, and the old reason was stale.** The keymgmt gate "
        "is open (D386) and the `ECDH` row needs the `EC` keymgmt row. D334 recorded "
        "`EC_GROUP`/`EC_POINT` as one indivisible landing not made and this entry named it as a "
        "second hold; **D387 re-measured and it is no longer true**: `EC_GROUP_new_by_curve_name` "
        "(`src/ec/curve.rs`) builds a real group from the generated curve tables and "
        "`EC_POINT_new`/`EC_POINT_mul` (`src/ec/lib.rs`) with the wNAF and ladder "
        "(`src/ec/mult.rs`) are landed. Of the 47 `EC*`/`EVP*`/`OSSL*`/`BN*`/`ossl_*` names this "
        "unit calls, the only ones the crate does not carry are the `OSSL_FIPS_IND_*` macros, "
        "all of which are inside `#ifdef FIPS_MODULE` and not this profile's. Nothing in the unit "
        "blocks it: the `EC` keymgmt row does."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/exchange/ecx_exch.c.in": (
        "**Withheld: behind the `ecx_kmgmt.c.in` unit.** The keymgmt gate is open (D386); this unit "
        "needs the four `X25519`/`X448`/`ED25519`/`ED448` keymgmt rows, which are not transcribed. "
        "Its own layer is present (`ossl_ecx_key_up_ref`, `ossl_ecx_key_free` and "
        "`ossl_ecx_compute_key` are landed in `src/ec/ecx_key.rs`), so nothing in this unit blocks "
        "it: the four keymgmt rows do."
    ),
    # The keymgmt group's **prerequisite-held and unreachable** units. `kdf_legacy_kmgmt.c` is
    # landed (D386) and `dh_kmgmt.c` is landed (D387), so neither is here. `ecx_kmgmt.c.in` and
    # `mac_legacy_kmgmt.c` are reachable-but-untranscribed -- their closures were not shown
    # unreachable, so they are not here, exactly as D385 kept `dh_kmgmt.c` out. The four PQC units
    # below are each built on an implementation the crate does not have.
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/rsa_kmgmt.c": (
        "**Withheld: reachable only behind a prerequisite that D327 deliberately left out.** The "
        "unit's `rsa_validate` (`:390-410`) calls `ossl_rsa_validate_pairwise`, "
        "`ossl_rsa_validate_private` and `ossl_rsa_validate_public` **outside any `#ifdef "
        "FIPS_MODULE`** guard, and those three live in `crypto/rsa/rsa_chk.c` as one-line calls to "
        "`ossl_rsa_sp800_56b_check_public`/`_private` (`crypto/rsa/rsa_sp800_56b_check.c`). D327 "
        "did not transcribe `rsa_sp800_56b_check.c` because nothing on the generate path reached "
        "it; `rsa_kmgmt.c` does, so the two rows `RSA` and `RSA-PSS` need that unit landed first. "
        "Everything else it calls is present (`ossl_rsa_new_with_ctx`, `ossl_rsa_todata`, "
        "`ossl_rsa_fromdata`, `ossl_rsa_dup`, the whole `ossl_rsa_pss_params_30_*` family)."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/dsa_kmgmt.c": (
        "**Withheld: same class as `rsa_kmgmt.c`.** It calls `ossl_dsa_check_pairwise`, "
        "`ossl_dsa_check_params`, `ossl_dsa_check_priv_key` and `ossl_dsa_check_pub_key` -- "
        "`crypto/dsa/dsa_check.c`'s validators, none of which the crate has -- so the `DSA` row "
        "needs that unit first. Everything else it calls is present (`ossl_dsa_new`, "
        "`ossl_dsa_dup`, `ossl_dsa_key_fromdata`, `ossl_dsa_ffc_params_fromdata`, "
        "`ossl_dsa_generate_ffc_parameters` and the `ossl_ffc_params_*` family)."
    ),
    "forensics/authorities/src/openssl-3.6.4/providers/implementations/keymgmt/ec_kmgmt.c": (
        "**Withheld: behind two small functions, and the old reason was stale.** D334 recorded "
        "`EC_GROUP`/`EC_POINT` and their arithmetic as one indivisible landing not made, and this "
        "entry named it as the hold (`CT-EC` is `PENDING` for it). **D387 re-measured and it is no "
        "longer the crate's state**: `EC_GROUP_new_by_curve_name` (`src/ec/curve.rs`) builds a real "
        "group from the generated curve tables, `EC_POINT_new`/`EC_POINT_mul` (`src/ec/lib.rs`) "
        "and the wNAF/ladder (`src/ec/mult.rs`) are landed, and `EC_POINT_point2oct` "
        "(`src/ec/oct.rs`) serializes. Of the 97 `EC*`/`EVP*`/`OSSL*`/`BN*`/`ossl_*` names the unit "
        "calls, the only genuine missing ones are `ossl_ec_generate_key_dhkem` (`:1294`, reached "
        "only when the caller sets `OSSL_PKEY_PARAM_DHKEM_IKM`) and `ossl_sm2_key_private_check` "
        "(`:902`, the SM2 row's private-key validate); `ossl_fips_ind_ec_key_check` (`:1281`) is "
        "inside `#ifdef FIPS_MODULE` and is not this profile's. So the two rows `EC` and `SM2` "
        "wait on those two functions and the unit's own size (1,492 lines), not on the object "
        "layer -- and with them `ecdh_exch.c.in` and `ec_kem.c.in` become drivable."
    ),
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
