# Phase 10 — Key formats, PKCS#12 and STORE, as subphases

## 0. What this stratum is, and what it is not

Phase 10 is the key-format layer: the `OSSL_ENCODER`/`OSSL_DECODER` codec framework and the
provider rows that publish its codecs, the PKCS#12 container, `OSSL_STORE`, and the
`PEM_*`/`d2i_*`/`i2d_*` key-format helpers the earlier strata handed forward.

It is **not** the primitives the codecs encode. A codec here is an `OSSL_OP_ENCODER`/`OSSL_OP_DECODER`
registration row and the translation unit behind it, over key objects Phase 8 already builds; the
asymmetric key types, their ASN.1 method objects and their provider keymgmt are Phase 8's, and the
`EVP_PKEY` layer the rows construct into is Phase 7's. Nor is it PKCS#7: the stratum's name in
`docs/RELEASE_GATES.md` §1 reads "Key formats + PKCS + STORE", and **"PKCS" here is PKCS#12 alone**
— `forensics/atlas/symbol-ownership.json` assigns every one of the 118 `pkcs7.h` exports to
Phase 12, and every one of the 117 `pkcs12.h` exports to this stratum (§4.4 is the measurement).

**Why this stratum is being planned while Phase 8 has sealed.** Phase 8's 8.8 and 8.9 rows landed
the `crypto/encode_decode/` framework and the PKCS#8/PVK readers as their own work, because
`crypto/evp/p_lib.c:1196`'s `print_pkey` reaches `OSSL_ENCODER_CTX_new_for_pkey` first (D362) and
the `pem.h` readers reach `OSSL_DECODER_CTX_new_for_pkey` (D363–D367). The result is that **79 of
this stratum's exports and 8 more are already `implemented`** before its first subphase, and the
ten open `deferrals` Phase 7 made to it (§1) are the ones those landings did not cover. This
document is that scope, measured.

## 1. The measurement this plan rests on

Every number below is read from `forensics/atlas/`, not typed, and `forensics/phase10-obligations.json`
is authoritative for the present.

**Phase 10's atlas-owned universe is 272 exports, all `libcrypto`, over four headers.** Reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 10`:

| header | exports | what it declares |
|---|---|---|
| `pkcs12.h` | 117 | the `PKCS12`/`PKCS12_SAFEBAG` object, `PKCS8_encrypt`/`decrypt`, the `PKCS12_*` API |
| `store.h` | 76 | `OSSL_STORE_*`, the `OSSL_STORE_INFO` and `OSSL_STORE_LOADER` objects, `OSSL_STORE_SEARCH` |
| `decoder.h` | 41 | the `OSSL_DECODER_*` context and instance API |
| `encoder.h` | 38 | the `OSSL_ENCODER_*` context and instance API |

**It also receives 26 hand-offs**, discovered from the other ledgers (`phase*-obligations.json` rows
whose `owning_phase` is 10) rather than listed here:

| from phase | count | header | what it is |
|---|---|---|---|
| 5 | 16 | `pem.h` | the `b2i_*`/`i2b_*` PVK readers and writers, the `d2i_PKCS8PrivateKey*`/`i2d_PKCS8PrivateKey*` spellings |
| 7 | 10 | `evp.h` (9), `pem.h` (1) | `PEM_write_bio_PrivateKey_traditional`, the four `d2i_PrivateKey*`/`d2i_AutoPrivateKey*` and the five `i2d_*` names |

That is a working set of **298 exports**. **Eighty-seven of them are already implemented** — all 79
`encoder.h`/`decoder.h` exports and 8 `pkcs12.h` ones (`PKCS12_item_decrypt_d2i`, `PKCS12_pbe_crypt`,
`PKCS8_decrypt` and their `_ex` twins, plus the `i2d_encrypt` pair, landed by D368) — so
`open_in_this_stratum` is **211**, not 298. `forensics/phase10-obligations.json` carries the exact
lists and `forensics/atlas/implemented-surface.json` is where each of the 87 is read from.

**The 272 atlas-owned exports are defined by 25 authority translation units**
(`forensics/atlas/export-defining-units.json`'s `units_by_owner_phase[10]`): six under
`crypto/encode_decode/` (`encoder_lib.c` 16, `encoder_meth.c` 16, `encoder_pkey.c` 6,
`decoder_lib.c` 20, `decoder_meth.c` 16, `decoder_pkey.c` 5), fifteen under `crypto/pkcs12/`
(`p12_asn.c` 22, `p12_sbag.c` 22, `p12_attr.c` 12, `p12_add.c` 10, `p12_crt.c` 11, `p12_decr.c` 6,
`p12_key.c` 6, `p12_p8e.c` 4, `p12_crpt.c` 3, `p12_init.c` 2, `p12_p8d.c` 2, `p12_mutl.c` 7,
`p12_utl.c` 8, `p12_kiss.c` 1, `p12_npas.c` 1) and four under `crypto/store/` (`store_lib.c` 49,
`store_register.c` 16, `store_meth.c` 10, `store_strings.c` 1). The 26 hand-offs are defined by
`crypto/pem/pvkfmt.c` (10), `crypto/pem/pem_pk8.c` (6), `crypto/asn1/i2d_evp.c` (5),
`crypto/asn1/d2i_pr.c` (4) and `crypto/pem/pem_pkey.c` (1).

**Phase 10 owns 636 provider registration rows**, every one of them `unimplemented`
(`forensics/atlas/provider-algorithms.json`; `forensics/phase-state.json`'s
`body.phases[10].provider_rows.owned` reads the same number). They are the `base` and `default`
providers' copies of the same 318: **241 `OSSL_OP_ENCODER` rows** over 29 algorithm names (the DER,
PEM and text encodings of `RSA`, `RSA-PSS`, the EC family, the post-quantum key types and the rest),
**76 `OSSL_OP_DECODER` rows** over 30 names, and **1 `OSSL_OP_STORE` row** (`file`). The census's
`projection` also reads `handed_on[10] = 39` — rows the plan gives a *later* phase.

## 1a. The decomposition: rows are not units

The reviewer's warning is a measurement this plan was written without. §1 records **636 provider
registration rows**, and the trap reads them as 636 implementations. They are not: the 636 are the
`default` and `base` providers' copies of **318 distinct dispatch-table symbols**
(`forensics/atlas/provider-algorithms.json`, `row_count` 996 over all providers; the phase-10 slice
is 318 `dispatch_table_symbol` values each appearing twice, `provider` `default` and `base`,
`source` `providers/defltprov.c:675-687` and `providers/baseprov.c:67-85`). Both provider files
`#include` the same generated `providers/encoders.inc` and `providers/decoders.inc` with a different
`ENCODER_PROVIDER`/`DECODER_PROVIDER`, so one authority table is two rows and one unit is two rows
per table. **The irreducible unit is the translation unit, not the row.**

Each of the 318 symbols is defined by exactly one translation unit under
`forensics/authorities/src/openssl-3.6.4/providers/implementations/encode_decode/` (or
`storemgmt/file_store.c` for the one `OSSL_OP_STORE` row). Measured by reading the table symbols
`nm --defined-only` reports from the authority's own build objects
(`forensics/authorities/build/openssl-3.6.4-production/providers/implementations/encode_decode/`)
and joining them to the census's `dispatch_table_symbol`, in rows (base + default):

| unit | distinct tables | rows |
|---|---|---|
| `encode_key2any.c` | 206 | 412 |
| `decode_der2key.c` | 69 | 138 |
| `encode_key2text.c` | 29 | 58 |
| `encode_key2ms.c` | 4 | 8 |
| `encode_key2blob.c` | 2 | 4 |
| `decode_msblob2key.c` | 2 | 4 |
| `decode_pvk2key.c` | 2 | 4 |
| `decode_spki2typespki.c` | 1 | 2 |
| `decode_pem2der.c` | 1 | 2 |
| `decode_epki2pki.c` | 1 | 2 |
| `storemgmt/file_store.c` | 1 | 2 |

**Eleven units, not 636 rows, and not 318.** The three biggest are `encode_key2any.c` (412 rows
over 206 tables generated by one `MAKE_ENCODER` macro, `:1407-1472`), `decode_der2key.c` (138 rows
over 69 tables generated by one `D2I_PUBKEY_NOCTX`/`DECLARE_DER2KEY_FUNCTIONS` pair) and
`encode_key2text.c` (58 rows over 29 tables generated by one `MAKE_TEXT_ENCODER` macro, `:652-696`).
A row is a `MAKE_ENCODER(kind)` expansion, and the engine is shared by every row of its unit, so the
ratio of rows to new code is the unit's, not the row's.

**None of the eleven is transcribed yet, and none is pure registration.** Phase 8's 8.8/8.9 chain
landed the *framework* — `crypto/encode_decode/{encoder_meth,encoder_lib,encoder_pkey}.c`
(`src/encoder_*.rs`, D360-D362) and `decoder_meth/decoder_lib/decoder_pkey.c` (`src/decoder_*.rs`,
D363-D367) — but `forensics/atlas/export-defining-units.json`'s `units_by_owner_phase[10]` names
those six under `crypto/encode_decode/`, **not** under `providers/implementations/encode_decode/`.
The framework dispatches to a provider codec; it implements none. Measured: no crate module defines
any symbol of the eleven units (no `key2any_encode`, no `key2text_encode`, no `file_store_functions`;
the four earlier hits on those names are comments in `src/dsa/object.rs`, `src/rsa/object.rs`,
`src/dh/object.rs` and `src/slh_dsa/key.rs` naming them as unlanded). The only shared provider-side
unit is `endecoder_common.c` (103 lines: `ossl_prov_import_key`/`ossl_prov_free_key` and
`ossl_read_der`), which every one of the eleven calls; it is transcribed whole in
`src/provider/endecoder_common.rs` with the first unit.

**The dependency closure decides the order, and it is not the plan's order.** Measured against the
crate's landed surface:

* `encode_key2text.c` (58 rows): its per-key-type printers call only landed object accessors
  (`DH_get0_*`, `DSA_get0_*`, `EC_KEY_*`, `RSA_get0_*`, the ECX key fields) and three helpers of
  `crypto/encode_decode/encoder_lib.c` (`ossl_bio_print_labeled_bignum`/`_buf`/`_ffc_params`) that
  Phase 8 **withheld** with a `divergences` row whose stated landing condition is "the first provider
  encoder". This unit is that first provider encoder: the three helpers land with it.
* `decode_der2key.c` (138 rows): every arm reads its DER through `ossl_read_der` and, for the PKCS#8
  and SPKI structures, through `d2i_PKCS8_PRIV_KEY_INFO` and `ossl_d2i_<type>_PKCS8`/`_PUBKEY`. The
  first two are landed, but the `ossl_d2i_*` backends are not (`src/rsa/object.rs:723`, `:1854` and
  `src/dh/object.rs:407` name `decode_der2key.c` as "beyond this phase"), so a decoder that would
  construct a key is blocked until 10.6's hand-offs.
* `encode_key2any.c` (412 rows): the single largest unit and 63 KB, but its per-type serialisers
  (`rsa_*_to_der` -> `i2d_RSAPrivateKey`, `:989-1001`) are the same "key serialization objects" whose
  DER readers the decoders lack; it wants 10.6 too.
* `encode_key2ms.c` (8 rows): writes through `i2b_*` (`providers/implementations/encode_decode/
  encode_key2ms.c:53`, `:69`), which are `crypto/pem/pvkfmt.c` and open hand-offs — 10.6.
* `encode_key2blob.c` (4 rows): the **only** other unit with a fully landed closure (`i2o_ECPublicKey`,
  landed in `src/ec/ameth.rs`), and it is a two-table unit — the "unlocks two" the ordering rejects.
* `decode_pem2der.c`, `decode_epki2pki.c`, `decode_spki2typespki.c` (2 rows each): the PEM structural
  chain, whose `ossl_spki2typespki_der_decode` reaches `ossl_x509_algor_is_sm2`, which
  `forensics/prerequisites.json` assigns to Phase 11.

So the biggest mover with a landed closure is **`encode_key2text.c`: 58 rows for one 745-line unit
and three helper functions**, and that is 10.1's first slice. Eleven of its twenty-nine tables are
published (`RSA`, `RSA-PSS`, `DH`, `DHX`, `DSA`, `EC`, `ED25519`, `ED448`, `X25519`, `X448`, `SM2`,
22 rows over the two providers); the eighteen `ML-KEM`/`ML-DSA`/`SLH-DSA` tables are **not published**
because their `*_to_text` helpers live in `ml_kem_codecs.c`, `ml_dsa_codecs.c` and
`crypto/slh_dsa/slh_dsa_key.c`, none of which is landed — §3.5's `pending` case. The remaining nine
units are 10.1's later slices in the order above, with the decoders waiting on 10.6.

**What the measurement corrects in §2.** The plan's 10.1 row names `crypto/encode_decode/
encoder_pkey.c`, `decoder_pkey.c` and the provider half of `*_meth.c`/`*_lib.c` as the units to
write. Those are the already-landed framework (§4.1's own finding) and are not rows at all. The rows
are published by the eleven units above, and §2's 10.1 row now says so. **No unit is pure
registration**: the landed framework makes a row *reachable*, but every one of the eleven units
carries its own engine, so a row over it is new code, not a table entry.

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 10.0 | **The plan and the census** | `docs/PHASE-10-SUBPHASES.md`, and the measurement in §1. The ledger (`forensics/phase10-obligations.json`) and its generator land with it; **the runner and the reference-basis probe do not, and §4.3 is why they cannot**: `run_courts.py` refuses a stratum in `in-progress` with no runner and `court_coverage.py` refuses the 87 inherited `implemented` exports until a reference probe covers them, and neither can be satisfied by this subphase's files. | 8.8–8.9 (the codec framework and the readers), `phase-state.json` | — |
| 10.1 | **The codec rows** | the `OSSL_OP_ENCODER`/`OSSL_OP_DECODER` registration rows the census gives this stratum (241 and 76, one per provider), which measurement (§1a) resolves to **eleven row-publishing units, not 636 rows**: `encode_key2any.c` (412 rows), `decode_der2key.c` (138), `encode_key2text.c` (58), `encode_key2ms.c` (8), `encode_key2blob.c`/`decode_msblob2key.c`/`decode_pvk2key.c` (4 each) and `decode_spki2typespki.c`/`decode_pem2der.c`/`decode_epki2pki.c` (2 each). **The 79 `encoder.h`/`decoder.h` exports and the `crypto/encode_decode/` framework are already landed** (8.8's D362–D367 chain), so this subphase adds rows rather than symbols. **The first slice is `encode_key2text.c`** — 58 rows over one unit, the biggest mover whose dependency closure is landed — which publishes 22 of its rows and leaves its eighteen PQC tables `pending` (§3.5). `D-DECODER-ABSENT-1` (`forensics/divergence-obligations.json`) is **not** retired by this slice: it names "the DER/PEM decoder rows and the keymgmt rows they construct into", and those decoders wait on 10.6's `ossl_d2i_*` hand-offs (§1a). | 8.8 | `RT-CODEC` |
| 10.2 | **The PKCS#12 object and its ASN.1** | `crypto/pkcs12/p12_asn.c` (22 exports), `p12_sbag.c` (22), `p12_attr.c` (12) and `p12_utl.c` (8): the `PKCS12`/`PKCS12_SAFEBAG`/`PKCS12_BAGS`/`PKCS12_MAC_DATA` item groups, the SafeBag accessors and the attribute helpers. Sixty-four of the ledger's open rows. | 10.0 | `RT-PKCS12` |
| 10.3 | **The PKCS#12 container construction** | `p12_add.c` (10), `p12_crt.c` (11), `p12_mutl.c` (7), `p12_init.c` (2) and `p12_npas.c` (1): `PKCS12_create(_ex/_ex2)`, the `PKCS12_add_*` family and the MAC setup. Thirty-one rows. | 10.2 | `RT-PKCS12` (shared) |
| 10.4 | **The PKCS#12 key derivation and PBE pair** | `p12_key.c` (6), `p12_crpt.c` (3), `p12_decr.c` (6), `p12_p8d.c` (2), `p12_p8e.c` (4) and `p12_kiss.c` (1): `PKCS12_key_gen_*`, `PKCS12_pbe_crypt(_ex)`, the `PKCS12_item_*` pair and `PKCS8_encrypt`/`decrypt`. Twenty-two exports of which eight are landed (all of `p12_decr.c` and `p12_p8d.c`, D368), so fourteen are open; **`p12_crpt.c`'s landing retires `D-PBE-PKCS12-KEYGEN-1`** — the six `builtin_pbe[]` rows whose keygen columns are NULL until it exists (D192). | 10.2 | `CT-PKCS12` (the KDF and PBE vectors) |
| 10.5 | **STORE** | `crypto/store/store_lib.c` (49 exports), `store_register.c` (16), `store_meth.c` (10) and `store_strings.c` (1): `OSSL_STORE_open(_ex)`, the `OSSL_STORE_INFO` type and its constructor/accessor family, the `OSSL_STORE_LOADER` object and its registry, and `OSSL_STORE_SEARCH`. Seventy-six rows. | 10.1, 10.4 | `RT-STORE` |
| 10.6 | **The key-format hand-offs** | the 26 symbols phases 5 and 7 handed forward, in the order the strata that own their headers: `crypto/pem/pvkfmt.c` (10), `crypto/pem/pem_pk8.c` (6), `crypto/asn1/i2d_evp.c` (5), `crypto/asn1/d2i_pr.c` (4) and `crypto/pem/pem_pkey.c` (1). This retires the two `units` records that name `crypto/asn1/d2i_pr.c` and `crypto/asn1/i2d_evp.c` in `forensics/prerequisites.json`. | 10.1, 10.5 | `RT-KEYFORMAT` |
| 10.7 | **The seal** | nothing in the crate — evidence: `docs/PHASE-10-KEYFORMATS-SEAL.md` | 10.0–10.6 | — |

The seven rows above the seal are this stratum's work, and the seal is the document that records
what they establish rather than a row that builds anything.

The order is forced twice over. 10.1's codec rows cannot be fetched before the framework that
dispatches them exists, and the framework is already there, so 10.1 is first among the work rather
than first overall. 10.5's `file` loader decodes what 10.4's PKCS#8 half produces — the `pvkfmt.c`
and `pem_pk8.c` readers 10.6 carries are what a `OSSL_STORE` file load actually reaches — so the
store's decoder arm lands after the decryption pair it calls.

**The dependency order inside 10.1 was measured rather than assumed, and the measurement moved it.**
`nm --undefined-only` over the authority's own build objects, joined to the crate's landed surface,
shows that §1a's account of *which* unit waits on what was wrong in two places. **`decode_der2key.c`
(138 rows) does not wait on 10.6 at all**: its closure is landed except for four PQC codec helpers,
`ossl_ml_kem_d2i_PKCS8`/`_PUBKEY` and `ossl_ml_dsa_d2i_PKCS8`/`_PUBKEY`, which live in
`ml_kem_codecs.c`/`ml_dsa_codecs.c` and are in neither 10.6 nor §1a's eleven publishers. **`encode_key2any.c`
(412 rows) waits on more than 10.6**: the same four PQC helpers, plus 10.6's six container writers
(`PEM_write_bio_PKCS8`, `PEM_write_bio_PKCS8_PRIV_KEY_INFO`, `PEM_write_bio_X509_PUBKEY`,
`i2d_PKCS8_bio`, `i2d_PKCS8_PRIV_KEY_INFO_bio`, `i2d_X509_PUBKEY_bio`), plus 10.4's `PKCS8_encrypt_ex`,
which is open. So the two big units are gated first on the **PQC codec helper units**, not on 10.6, and
pulling 10.6 forward would unblock neither — it would unblock only the three small PVK/MSBLOB units,
which is a reason to leave 10.6 where it is. The order to work in is therefore the small unblocked
units, then the PQC codec helpers, then `decode_der2key.c`, then `encode_key2any.c` once 10.6 and 10.4
have landed. **The eleven publishers are not the whole closure**: a row-publishing unit's engine may
call a helper unit that publishes no rows of its own, and §1a's table is a census of publishers rather
than of closure.

## 3. What each subphase must honour

**3.1 A codec's identity is the authority's bytes, not round-trip closure.** A transcription whose
encoder writes a key and whose decoder reads it back satisfies every round-trip a probe could
write and is a different library. The difference is observable in three places and each is
machine-checked: the differential transcript (`OSSL_ENCODER_to_data`/`to_bio`/`to_fp`'s exact
bytes, the error queue and coordinates for a malformed input, the alias and selection behaviour
under `OSSL_ENCODER_CTX_set_output_type`/`set_selection`); the provider census's per-row
`dispatch_table_symbol`, `algorithm_names`, `aliases` and `property_definition`
(`forensics/atlas/provider-algorithms.json`), which pin the row's identity rather than its
behaviour; and `forensics/atlas/provider-court-coverage.json`, which requires every implemented row
to be named by a probe of a court that covers its stratum. **A codec that round-trips is not a
codec; it is observable at those three joins, and 10.1's `RT-CODEC` is where the first is read.**

**3.2 PKCS#12's identity is a DER document, and its bytes are the contract.** The container is
`PKCS12`'s own ASN.1 item group, so a transcription's output is comparable byte for byte against
the authority's: the `PFX` structure's order, the `SafeBag`'s attribute set and its ordering, the
`MacData`'s `digestAlgorithm`/`salt`/`iterations` and the `PKCS12_gen_mac`/`PKCS12_verify_mac`
pair's answer. The PBE half is a byte transcript too — `PKCS12_pbe_crypt` over a fixed
salt/iteration/IV produces the same key and the same ciphertext on both sides, and `p12_key.c`'s
`PKCS12_key_gen_*` is the PKCS#12 KDF, whose output is a fixed vector. `CT-PKCS12` carries those
vectors, and `RT-PKCS12` compares the container bytes rather than a parsed structure.

**3.3 STORE's identity is a fetch and a loader contract.** `OSSL_STORE_open` resolves an
`OSSL_STORE_LOADER` through the provider store, so the same finding D240 recorded for the DRBG
rows applies here unchanged: the loader's sub-fetches and its decoder resolve in the library
context of the provider that published the row, and `PROV_LIBCTX_OF(provctx)` is load-bearing
rather than incidental. What a differential court can compare is the `OSSL_STORE_INFO` type and
refcount surface, the `OSSL_STORE_eof`/`error`/`expect` state machine, and the refusal arms — an
unknown scheme, a NULL URI, a loader that answers a NULL `load` — with the error queue. What it
cannot compare is the loader's *private* attachment beyond the pointers it reports.

**3.4 The hand-offs are byte codecs with an error coordinate.** The 26 are `d2i_*`/`i2d_*`/`PEM_*`
names whose only visible output is bytes, so 10.6's evidence is the same as 10.1's: the exact
encoding of a fixed key against the authority, and the error queue and coordinate for each
malformed-input arm. `d2i_PrivateKey*`/`d2i_AutoPrivateKey*` are the subtle ones — they try
`d2i_PrivateKey_decoder` first and fall back to `ossl_d2i_PrivateKey_legacy`
(`crypto/asn1/d2i_pr.c:172`-`:175`, `:247`-`:250`), so a probe that only drove the provider path
would measure half the function.

**3.5 Nothing here is a parity claim about a key's meaning.** A codec that produces the authority's
bytes for a key this crate can build has not been shown to produce the authority's bytes for every
key, and the post-quantum encoder rows (§1's 29 algorithm names) will reach key types whose own
strata have their own open work. The measured surface is the one above, and a row that cannot be
driven is named as `pending` rather than counted as passing.

## 4. Measured corrections, and the precondition

**4.1 The `OSSL_ENCODER_*`/`OSSL_DECODER_*` framework is not Phase 10's to land, and Phase 8's own
plan says it is.** `docs/PHASE-8-SUBPHASES.md:16-18` states the boundary as "`RAND`/DRBG is Phase
9's, `OSSL_ENCODER_*`/`OSSL_DECODER_*` and the key formats are Phase 10's", and that is true of
*ownership*: the atlas assigns all 79 `encoder.h`/`decoder.h` exports to this stratum (§1). It is
false of *landing*. Phase 8's 8.8 row (`docs/PHASE-8-SUBPHASES.md:151`) records D362 transcribing
`src/encoder_meth.rs`, `src/encoder_lib.rs` and `src/encoder_pkey.rs` because `print_pkey`
(`crypto/evp/p_lib.c:1196`) calls `OSSL_ENCODER_CTX_new_for_pkey` first, and the 8.9 row
(`:152`) records the decoder chain closing at D363–D367 because the `pem.h` readers reach
`OSSL_DECODER_CTX_new_for_pkey`. The measurement is `forensics/atlas/implemented-surface.json`:
all 41 `decoder.h` and all 38 `encoder.h` exports are implemented. So a plan that opened with "the
whole working set is open, as every earlier activation did" would be wrong, and §1 records the
87 instead.

**4.2 D175's and D177's `x509.h` attributions name Phase 10 and the atlas names Phase 11.** D175
(`docs/DECISIONS.md:10355`-`:10361`) gates `p5_crpt.c`/`p5_crpt2.c` "on Phase 10, by a *type*",
reading `PBEPARAM`'s declaration in `include/openssl/x509.h.in:261` and concluding "the ownership
atlas assigns it to the stratum owning `x509.h` — Phase 10". Measured: `x509.h` is **Phase 11's**
— `forensics/atlas/symbol-ownership.json` gives all 548 of its exports to phase 11 and none to
phase 10 — and `forensics/atlas/typedef-owners.json` gives `PBEPARAM` `owner_phase: 11`. D177
(`docs/DECISIONS.md:10533`-`:10534`) likewise lists `X509_PUBKEY` and `PKCS8_PRIV_KEY_INFO` as
"Phase 10's object"; both are declared in `types.h` and carry `owner_phase: null` in that same
typedef atlas, so they are unowned rather than this stratum's. D192 already corrected the reading in
place (`docs/DECISIONS.md:11745`-`:11747` records that `PBEPARAM_it`/`d2i_PBEPARAM`/`X509_ALGOR_it`
"are Phase 11's by `symbol-ownership.json`"); this plan records it because a Phase 10 plan that
believed it owed `PBEPARAM` would carry another stratum's work.

**4.3 The precondition this plan places on 10.0, and it is not optional.** Two fail-closed joiners
refuse this stratum's activation as specified, and both are measured rather than argued:

* `run_courts.py` refuses a stratum that is not `not-started` and has no runner: "phase 10
  (in-progress) is not `not-started` and has no runner". Phase 9 satisfied this by landing
  `forensics/tools/phase9_courts.py` in the same commit; this stratum cannot, because a runner with
  nothing to run is what `NO_RUNNER_YET` exists for and that table is empty, and because a runner
  that *did* register a court would need a probe (§4.3's second bullet).
* `court_coverage.py` refuses the 87 inherited `implemented` exports: "87 implemented export(s) of a
  stratum that has begun is in none of directly-courted, indirectly-courted or non-observable". They
  sit in the atlas's `not_yet_begun` list today (`forensics/atlas/court-coverage.json`, 87 rows for
  phase 10) because Phase 10 had no ledger; **the ledger's landing is what moves them into scope**,
  and the commit that lands it must also land a phase-10 reference-basis probe that references the
  87 by name, registered in `court_coverage.py`'s `reference_probes` table as `RT-RUNTIME-REF` and
  `RT-EVP-REF` are for theirs. None of the 87 is an undefined dynamic symbol of any staged candidate
  probe in `artifacts/phase*/probes/` — measured — so no existing court covers them.

So the activation order is: the reference probe and the runner land **with** the ledger, not after
it, or `forensics/tools/pipeline.sh` fails at `run_courts.py` and `court_coverage.py` and the tree
carries an activation whose two evidence joiners refuse it. This document states the precondition;
the probe and runner are `courts/phase10/` work and are not part of the plan-and-census subphase's
files.

**4.4 The stratum's name says "PKCS" and only PKCS#12 is its.** `docs/RELEASE_GATES.md` §1 names
stratum 10 "Key formats + PKCS + STORE". Measured: `forensics/atlas/symbol-ownership.json` assigns
all 118 `pkcs7.h` exports to phase 12, 19 `x509.h` ones (`PKCS7_*`/`PKCS8_*`/`PKCS5_*` spellings) to
phase 11 and 9 `evp.h` ones to phase 7; only the 117 `pkcs12.h` rows are phase 10's. D64
(`docs/DECISIONS.md:2354`-`:2355`) already recorded the split for Phase 5's hand-offs ("12 to Phase 10
(`pkcs12.h`) ... 141 to Phase 12 (`cms.h`, `ocsp.h`, `ts.h`, `pkcs7.h`, ...)"). A plan that read
"PKCS" as PKCS#7 as well would claim 118 of Phase 12's exports.

## 5. Process

This stratum inherits Phase 8's and Phase 9's process unchanged: a subphase lands its code, its
court and its regenerated artefacts in **one commit**; every export carries a court edge in
`forensics/atlas/court-coverage.json` on the commit that lands it (D236) — **and 4.3 is the
measurement of what that rule means for a stratum whose exports were landed by an earlier one**;
every provider row it publishes is named by a probe of a court that covers it (D245); and an
artefact that a source change moves is regenerated in the same commit. `docs/DECISIONS.md` is
append-only and this document is not a decision record.

**4.5 This plan's own boundaries are the census's, and the census will correct them.** The subphase
table above was written from the defining units in `forensics/atlas/export-defining-units.json` and
the 298-row measurement in §1. D283's equivalent table for Phase 8 was corrected twice by
measurement — by D285, which found that most of a slice was another stratum's, and by D287, which
found a prerequisite the slice's name could not show — and Phase 9's was corrected by D296 within
its own activation. The same is expected here and is not a defect in this document: the census is
the authority, and a subphase that discovers its unit is somewhere else records that rather than
forcing the row.

**Landed exports (checked against the ledger):**

Eighty-seven, and every one was landed by an earlier stratum rather than by this one: the 41
`decoder.h` and 38 `encoder.h` exports of Phase 8's 8.8/8.9 chain (D362–D367), and the 8
`pkcs12.h` decryption and PKCS#8 names of D368 (`PKCS12_item_decrypt_d2i`, `PKCS12_item_decrypt_d2i_ex`,
`PKCS12_item_i2d_encrypt`, `PKCS12_item_i2d_encrypt_ex`, `PKCS12_pbe_crypt`, `PKCS12_pbe_crypt_ex`,
`PKCS8_decrypt`, `PKCS8_decrypt_ex`). No export of this stratum's own work has landed, and no
provider row has.

**Open exports (checked against the ledger):**

Two hundred and eleven. The PKCS#12 block is 109 of them — the container object and its ASN.1
(`PKCS12`, `PKCS12_SAFEBAG`, `PKCS12_BAGS`, `PKCS12_MAC_DATA` and their accessors, `PKCS12_create`,
`PKCS12_parse`, `PKCS12_key_gen_*`, `PKCS12_pbe_crypt`'s siblings, `PKCS12_set_mac`,
`PKCS12_verify_mac`, `PKCS12_gen_mac`, the `PKCS12_add_*` family, `PKCS8_encrypt`, `d2i_PKCS12*`,
`i2d_PKCS12*`) — and the STORE block is all 76 (`OSSL_STORE_open`, the `OSSL_STORE_INFO` family, the
`OSSL_STORE_LOADER` object and registry, `OSSL_STORE_SEARCH`, `OSSL_STORE_attach`/`load`/`expect`).
The 26 hand-offs are the PVK and PKCS#8 container reads and writes
(`b2i_PVK_bio`, `b2i_PrivateKey`, `d2i_PKCS8PrivateKey_bio`, `i2d_PKCS8PrivateKey_nid_fp`), the four
`d2i_PrivateKey*`/`d2i_AutoPrivateKey*` and the five `i2d_*` names, and
`PEM_write_bio_PrivateKey_traditional`.

**Why 10.0 is staged over two commits, and §4.3 is why it is not one.** The plan and the census
land with the stratum's ledger, because `phase_state.py` refuses any stratum that has a plan, a
ledger or a court file on disk without a `STRATUM_EVIDENCE` row. But the two joiners §4.3 measures
need a reference probe and a runner that this subphase's files do not carry, so the commit that
lands the ledger is the commit that must land them — a second commit, in `courts/phase10/` and
`forensics/tools/phase10_courts.py`, before `forensics/tools/pipeline.sh` can reach
`PIPELINE OK`.

## 6. The pulled-forward X.509 subphases

D450 measured this stratum's remaining distance as "14 exports and 2 provider rows, all reachable only
through ~45,000 lines of Phase 11's object graph", and the owner asked that the subset actually needed by
the blocked rows be measured rather than assumed. This section is that measurement. It agrees with
D442 and D444 rather than correcting them: the subset is the certificate object graph, and it does not
factor into a first slice small enough to land.

**What was measured.** `nm --undefined-only` over the authority's `openssl-3.6.4-production` build
objects, seeded from the objects that carry the blocked rows — `crypto/store/libcrypto-lib-store_lib.o`,
`crypto/store/libcrypto-lib-store_result.o`, all fifteen `crypto/pkcs12/*.o`,
`providers/implementations/storemgmt/{file_store,file_store_any2obj}.o` — then iterated over the authority
translation units that define each crate-**unlanded** name. "Landed" is read from
`forensics/atlas/implemented-surface.json` (the compiled crate's defined surface) and the definition-based
source scan, never from the bare word.

| closure | authority units | unlanded symbols | authority lines |
|---|---:|---:|---:|
| the blocked rows (19 seed objects) | 143 | 507 | 50,031 |
| the same plus the brief's decoder objects (`libdefault-lib-decode_*.o`; 25 seeds) | 158 | 537 | 61,497 |
| D450's `X509` object graph, for comparison | 127 | 538 | ~45,241 |

The difference from D450's 127 is stated plainly because it is the opposite of the hoped one: the
blocked rows' closure is **larger**, not smaller, and it is D450's certificate graph **plus** the
twenty-five blocked units themselves. The decoder objects add eight `keymgmt` units (`dh_kmgmt.c`,
`dsa_kmgmt.c`, `ec_kmgmt.c`, `ecx_kmgmt.c`, `ml_dsa_kmgmt.c`, `ml_kem_kmgmt.c`, `rsa_kmgmt.c`,
`slh_dsa_kmgmt.c`) whose codec helpers those objects reach; every one is already implemented and no
blocked row reaches it, so that row is not this stratum's work and the 143-unit row is the honest one.

**Why the subset does not factor.** A unit-level dependency partition of the 143-unit closure (edge:
unit U depends on unit V when U's objects name a symbol V defines; strongly-connected components
condensed; packed at a 3,500-line budget) gives **eight dependency-ordered chunks**. Seven are at or
under the budget; the eighth is the certificate object graph and it is **one strongly-connected
component of 75 units and 30,711 lines** — `x_x509.c`'s `X509_it` template and its `x509_cb` aux
callbacks name `AUTHORITY_KEYID_free`/`CRL_DIST_POINTS_free`/`ossl_policy_cache_free`/
`GENERAL_NAMES_free`/`NAME_CONSTRAINTS_free`/`IPAddressFamily_free`/`ASIdentifiers_free`
(`v3_akid.c`/`v3_crld.c`/`pcy_*.c`/`v3_genn.c`/`v3_ncons.c`/`v3_addr.c`/`v3_asid.c`), and those units'
own templates reach back into `x509_cmp.c`/`x509_vfy.c`/`x_all.c`/`pk7_*.c`/`ocsp_*.c`/`ct_*.c`. That
cycle is the one D442 and D444 already recorded; this section is its size.

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 10.8 | **The X.509 object core** *(landed, D451)* | `x_x509.c` (310), `x_name.c` (552), `x_crl.c` (542)'s object half, `x_exten.c`, `crypto/asn1/x_val.c`: the `X509`/`X509_CINF`/`X509_NAME`/`X509_NAME_ENTRY`/`X509_CRL`/`X509_CRL_INFO`/`X509_REVOKED`/`X509_EXTENSION`/`X509_VAL` items and their lifecycles, `d2i_X509`/`i2d_X509`/`d2i_X509_CRL`/`i2d_X509_CRL`, the `ASN1_ITYPE_EXTERN` name hooks and `i2d_re_X509_tbs`. Closed `OSSL_STORE_INFO_get1_CERT`, `_get1_CRL` and the CERT/CRL arms of `OSSL_STORE_INFO_free`. | — | `RT-STORE` |
| 10.9 | **The digest substrate** | the engine table `X509_digest` reaches through `ossl_asn1_item_digest_ex` (`crypto/engine/`'s nine built units — `eng_all`, `eng_ctrl`, `eng_init`, `eng_lib`, `eng_list`, `eng_table`, `tb_asnmth`, `tb_digest`, `tb_pkmeth`), `crypto/o_str.c`, `crypto/ctype.c`, `crypto/defaults.c`; **12 units, 2,975 lines**. Closes no Phase-10 export or row. | — | — |
| 10.10 | **The ASN.1 digest/sign/verify layer** | `a_digest.c`, `a_sign.c`, `asn1_lib.c`, `evp/digest.c`, and the `X509_NAME_oneline` half of `x509_obj.c`; **5 units, 2,293 lines**. Closes no export or row. | 10.9 | — |
| 10.11 | **The name, print and `v3` dispatch layer** | `x_name.c` (`X509_NAME_it`/`X509_NAME_ENTRY_it` and the `_new`/`_free`/`_dup`/`d2i_`/`i2d_` family), `x_exten.c` (`X509_EXTENSION_it`), `x_pubkey.c`, `x509_v3.c`, `x509name.c`, `x509rset.c`, `a_strex.c`, `a_verify.c`, `x_spki.c`, `evp/evp_pkey.c`; **10 units, 3,487 lines**. This is the first half of the brief's (a): `X509_NAME`'s item and its `i2d_X509_NAME`. | 10.10 | `RT-STORE` (later) |
| 10.12 | **The leaf extension items and the policy graph** | `x_val.c` (`X509_VAL_it`), `x_x509a.c` (`X509_CERT_AUX_it`, the alias/keyid accessors), `x509_txt.c`, `pcy_lib.c`, `pcy_node.c`, `v3_audit_id.c`, `v3_group_ac.c`, `v3_ia5.c`, `v3_ind_iss.c`, `v3_ist.c`, `v3_no_ass.c`, `v3_pcia.c`, `v3_skid.c`; plus the `http`/`punycode` units `x_all.c` reaches; **16 units, 3,490 lines**. | 10.11 | — |
| 10.13 | **The remaining leaf extension items** | `v3_timespec.c`, `v3_pku.c`, `v3_utf8.c`, `v3_no_rev_avail.c`, `v3_single_use.c`, `v3_soa_id.c`; **6 units, 875 lines**. | 10.11 | — |
| 10.14 | **The certificate object graph (one SCC)** *(decomposed in §7; 10.14.1–10.14.2 landed)* | the 75-unit, **30,711-line** strongly-connected component: `x_x509.c`/`x_crl.c` (`X509_it`/`X509_CRL_it` and lifecycle), `x509_cmp.c`, `x509_set.c`, `x509cset.c`, `t_x509.c`, `x_all.c`, `x509_vfy.c`, `x509_lu.c`, `x509_vpm.c`, `x509_trust.c`, `x509_acert.c`, `x509_req.c`, `x_attrib.c`, all `v3_*.c`, `pcy_cache.c`/`pcy_data.c`/`pcy_map.c`/`pcy_tree.c`, `pk7_*.c`, `ocsp/*`, `ct/*`, `asn1_gen.c`. **This is the second half of the brief's (a) and the whole of its (b).** | 10.9–10.13 | `RT-STORE`, `RT-PKCS12`, `RT-KEYFORMAT` |
| 10.15 | **The PKCS#12 certificate layer** | the fifteen `crypto/pkcs12/` units (`p12_add.c`'s `PKCS12_add_cert`, `p12_crt.c`'s `PKCS12_create(_ex/_ex2)`, `p12_sbag.c`'s `PKCS12_SAFEBAG_*`, `p12_kiss.c`'s `PKCS12_parse`, and the landed rest); **3,170 lines**. Closes the eleven `pkcs12.h` rows D447 left open. | 10.14 | `RT-PKCS12` |
| 10.16 | **STORE result and the file loader** | `store_lib.c` (the carved CERT/CRL arms of `OSSL_STORE_INFO_free`/`_get1_CERT`/`_get1_CRL`/`OSSL_STORE_find`, and `OSSL_STORE_load`), `store_result.c`, `file_store.c`, `file_store_any2obj.c`; **4 units, 3,030 lines**. Closes `OSSL_STORE_load`, `OSSL_STORE_INFO_get1_CERT`, `OSSL_STORE_INFO_get1_CRL` and the two `file` `OSSL_OP_STORE` rows. | 10.14 | `RT-STORE` |

**The unit-level SCC is not a function-level one, and 10.8 is the proof.** This section first
concluded that no subphase could land because the 30,711-line component "cannot be cut at unit
granularity". That was true of the units and false of the work: **10.8 landed the `X509` object core**
-- the `X509`/`X509_CINF`/`X509_NAME`/`X509_CRL`/`X509_EXTENSION`/`X509_VAL` items and their
lifecycles, `x_name.c`, `x_exten.c`, `x_val.c` and `x_crl.c`'s object half -- by withholding each
function whose closure is unlanded rather than the unit that contains it, closing
`OSSL_STORE_INFO_get1_CERT`, `OSSL_STORE_INFO_get1_CRL` and the CERT/CRL arms of
`OSSL_STORE_INFO_free`. The unit-level SCC is what a linker sees; the transcription's frontier is
the call graph, and it is smaller. 10.8–10.12 (13,120 lines) still close no Phase-10 export or row
on their own, and the remaining distance is measured per subphase rather than assumed. The old
conclusion, kept because the correction is the point:

> No subphase lands, because the first one the brief asks for is 6.6. 6.1–6.5 (13,120 lines) close no
> Phase-10 export or row; 6.6 is the 30,711-line component and cannot be cut at unit granularity without
breaking the free callbacks' closure; 6.7 and 6.8 stay blocked behind it. The brief's first subphase —
the `X509`/`X509_NAME`/`X509_ALGOR`/`X509_CRL` ASN.1 items and object lifecycle — is a nine-unit,
2,678-line slice of the authority text (`x_x509.c` 310, `x_name.c` 552, `x_crl.c` 542, `x_x509a.c` 174,
`x_exten.c` 27, `asn1/x_val.c` 20, `x509_set.c` 309, `x509cset.c` 185, `t_x509.c` 559), but its
**dependency-complete** closure is **123 units and 43,555 lines**: `X509_it` cannot be built without the
graph. A function-level pass (each undefined relocation attributed to its containing symbol) lowers the
needed code to **39 units and ~19,600 unit-lines**, but it does not change the ordering — `X509_free`'s
callback still names the seven `*_free` functions above — and it under-counts the ASN.1 item templates,
which the compiler emits as local data, so it is a lower bound rather than a fourth row above.

**The consequence for the ledger.** `forensics/phase10-obligations.json` reads `286 implemented /
12 open` (D451 closed the two `OSSL_STORE_INFO` readers) and `forensics/atlas/provider-algorithms.json`
`634 implemented / 2 open`; no export, no row, no Phase-11 evidence, ledger, plan, seal or state row
is created, and Phase 11 still derives `not-started`. This section is a measurement of what a future
slice must take as one unit, not a deferral: the size is a number. **Its 10.14 row is decomposed in
section 7 below**, one sub-subphase at a time.

## 7. The decomposition of 10.14, sub-subphase by sub-subphase

Section 6 measured 10.14 as the second half of the brief's `(a)` and the whole of its `(b)`: one
strongly-connected component of **75 units and 30,711 authority lines**, which the plan left as a
single row because no unit-level cut of it is dependency-complete. D451 proved the cut is at the
**call graph**, not at the units, and 10.8–10.13 landed six slices of the surrounding leaves with it.
This section is the measurement that turns the 10.14 row itself into a dependency-ordered list, and
it is written the way the ledger is measured rather than estimated.

**What was measured, and how.** `nm --undefined-only` over the authority's own
`openssl-3.6.4-production` build objects, seeded from the objects that carry Phase 10's two remaining
blockers — the 19 objects of `crypto/store/store_lib.o`, `crypto/store/store_result.o`, the fifteen
`crypto/pkcs12/p12_*.o` and the two `providers/implementations/storemgmt/file_store*.o` — with each
undefined name resolved to the translation unit that *defines* it (`nm --defined-only`) and tested
against the crate's compiled surface (`forensics/atlas/implemented-surface.json`) **and** its
transcribed units (`forensics/atlas/transcription-edges.json`), never against the bare word. The
strict compiled-surface closure is **494 units / 152,091 lines**; excluding the units the crate has
already transcribed leaves **318 units / 66,745 lines**, and scoped to the certificate subsystem
(the four `crypto/x509`/`pkcs7`/`ocsp`/`ct` trees, the `pkcs12` and `store` residues, and
`crypto/asn1/asn1_gen.c`/`x_spki.c`) the unlanded frontier is:

| closure | authority units | authority lines |
|---|---:|---:|
| the blocked rows, strict compiled-surface closure | 494 | 152,091 |
| the same minus already-transcribed units | 318 | 66,745 |
| the certificate subsystem, unlanded and in scope, **before this session's 10.14.1 landing** | **100** | **32,326** |
| the same **after** 10.14.1 | 76 | 27,335 |

Section 6's 143-unit / 50,031-line row for the same seeds is smaller because its landed test was a
definition-based **source** scan, which credits a partially-transcribed unit as whole; the compiled
surface the brief specifies is the conservative test, and the sizes below use it. The 100 pre-landing
units are the corpus. The order is read from the measured call edges rather than
assumed: the nm joins show `v3_purp.c` naming `x509_cmp.c` (5 names), `x509_ext.c` (4) and
`x509_set.c` (2); `x509_vfy.c` naming `x509_cmp.c` (12), `v3_purp.c` (9), `x509_vpm.c` (9),
`x509cset.c` (8), the OCSP units (10) and `pcy_tree.c` (2); `x_all.c` naming the `X509_REQ`/
`X509_ACERT` items and `x509_req.c`; and `store_result.c`/`file_store*.o` naming `PKCS12_parse`,
the decoder context and `ossl_store_handle_load_result`. That is the expected order — comparison and
accessors first, then the name/extension substrate, then the policy graph and the verify engine, then
PKCS#7/OCSP/CT, then the two blockers — and it is confirmed rather than assumed.

**The sub-subphases.** Each is dependency-complete at the function level, in the sense 10.8
established: it lands every function whose closure is satisfied by its own units or an earlier
sub-subphase, and withholds by name any function whose closure is not. Sizes are authority lines,
read from `forensics/authorities/src/openssl-3.6.4/`.

| # | Sub-subphase | Owns (authority units, lines) | Depends on | Closes |
|---|---|---|---|---|
| 10.14.1 | **The certificate comparison and accessor surface** *(landed, this session)* | `x509_cmp.c` (594, 27 of 32 fns), `x509cset.c` (185), `x509type.c` (84), and `x509_set.c`'s un-withheld `X509_get_version`/`X509_set_version`/`ossl_x509_set1_time` (~50); **~913** | — | none; unblocks 10.14.2–10.14.15 |
| 10.14.2 | **The certificate encode/decode faces and the defaults** *(landed, this session)* | `x_all.c` (881, 73 of 98 fns), `x509_def.c` (116, 2 of 6), `x509spki.c` + `crypto/asn1/x_spki.c` (75 + 28, whole), `x509_meth.c` (157, withheld whole), `x509rset.c` (42, already a doc-and-withholds module from D454); **~1,299** | 10.14.1 | none |
| 10.14.3 | **The extension value and string utilities** | `v3_utl.c` (1449), `v3_prn.c` (215); **~1,664** | 10.14.1 | none |
| 10.14.4 | **The general names, constraints and configuration layer** | `v3_ncons.c` (862), `v3_conf.c` (599), `v3_genn.c` (269); **~1,730** | 10.14.3 | none |
| 10.14.5 | **The purpose table, the extension cache and the dispatch** | `v3_purp.c` (1147) and `v3_lib.c`'s withheld lookup half (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`, ~150) over `standard_exts.h`'s 63 tables; **~1,300** | 10.14.3, 10.14.4, 10.14.6–10.14.8 (the tables it dispatches to) | none; **un-withholds 10.14.1's withheld `X509_cmp` and four `X509_add_cert*`** |
| 10.14.6 | **The extension tables, part A: names, key usage and policy** | `v3_crld.c` (724), `v3_san.c` (689), `v3_cpols.c` (515), `v3_akid.c` (237), `v3_extku.c` (125), `v3_bitst.c` (100), `v3_pcons.c` (91), `v3_bcons.c` (85), `v3_akeya.c` (23); **~2,589** | 10.14.3, 10.14.7/10.14.8 (identity items), 10.13's `v3_pku`/`v3_timespec` | none |
| 10.14.7 | **The extension tables, part B: address and identifier** | `v3_addr.c` (1359), `v3_asid.c` (871); **~2,230** | 10.14.3 | none |
| 10.14.8 | **The extension tables, part C: the remainder** | `v3_admis.c` (355), `v3_pci.c` (323), `v3_sxnet.c` (259), `v3_ac_tgt.c` (253), `v3_aaa.c` (128), `v3_attrdesc.c` (178), `v3_attrmap.c` (116), `v3_authattid.c` (79), `v3_battcons.c` (86), `v3_rolespec.c` (95), `v3_sda.c` (88), `v3_tlsf.c` (137), `v3_usernotice.c` (96), `v3_enum.c` (53), `v3_int.c` (43), `v3_iobo.c` (32); **~2,321** | 10.14.3, 10.14.4 | none |
| 10.14.9 | **The policy graph** | `pcy_tree.c` (726), `pcy_cache.c` (226), `pcy_data.c` (81), `pcy_map.c` (77); **~1,110** (with `pcy_node.c`'s 157 still withheld on D455's two-part blocker) | 10.14.5, 10.14.6 | none |
| 10.14.10 | **The trust, verification-parameter and store-lookup layer** | `x509_lu.c` (958), `x509_vpm.c` (648), `by_dir.c` (448), `by_store.c` (293), `x509_trust.c` (298), `by_file.c` (284), `x509_d2.c` (117); **~3,046** | 10.14.1, 10.14.2, 10.14.5 | none |
| 10.14.11 | **The printers and the request/attribute objects** | `t_x509.c` (559), `x509_req.c` (350), `x509_acert.c` (328), `t_acert.c` (289), `x_ietfatt.c` (239), `t_req.c` (216), `x509aset.c` (177), `x_req.c` (167), `t_crl.c` (99); **~2,424** | 10.14.3, 10.14.5, 10.14.6 | none; un-withholds 10.14.2's `x509rset.c` |
| 10.14.12 | **The verification engine** | `x509_vfy.c` (3,984) | 10.14.9, 10.14.10, 10.14.5 | none; **un-withholds 10.14.1's withheld `X509_cmp`/`X509_add_cert*` for the last time** |
| 10.14.13 | **PKCS#7** | `pk7_doit.c` (1299), `pk7_smime.c` (546), `pk7_attr.c` (137), `pk7_mime.c` (73), `bio_pk7.c` (19), `pk7_lib.c`'s remaining 20; **~2,094** | 10.14.10, 10.14.11 | none; **prerequisite of 10.15** |
| 10.14.14 | **OCSP** | `ocsp_ext.c` (466), `ocsp_vfy.c` (438), `ocsp_cl.c` (368), `ocsp_srv.c` (326), `ocsp_prn.c` (251), `v3_ocsp.c` (234), `ocsp_asn.c` (135), `ocsp_lib.c` (113), `ocsp_http.c` (68); **~2,399** | 10.14.12, 10.14.13 | none |
| 10.14.15 | **CT** | `ct_oct.c` (403), `ct_sct.c` (385), `ct_log.c` (335), `ct_sct_ctx.c` (274), `ct_b64.c` (174), `ct_vfy.c` (138), `ct_prn.c` (127), `ct_policy.c` (113), `ct_x509v3.c` (104); **~2,053** | 10.14.11, 10.14.12 | none |
| 10.15 | **The PKCS#12 certificate layer** (section 6's row, unchanged) | the fifteen `crypto/pkcs12/` units' remaining halves: `p12_sbag.c` (292), `p12_add.c`/`p12_crt.c` (~400), `p12_mutl.c` (552), `p12_kiss.c` (274); **~1,518** | 10.14.13 (PKCS#7), 10.14.11 (the `X509` objects) | **the eleven `pkcs12.h` exports** (`PKCS12_SAFEBAG_create_cert`/`_crl`, `_get1_cert(_ex)`/`_get1_crl(_ex)`, `PKCS12_add_cert`, `PKCS12_create(_ex/_ex2)`, `PKCS12_parse`) |
| 10.16 | **STORE result and the file loader** (section 6's row, unchanged) | `store_result.c` (667), `store_lib.c`'s carved `OSSL_STORE_load` half, `file_store.c` (828), `file_store_any2obj.c` (330); **~1,825** | 10.14.13 (the decoder chain `store_result` calls), 10.15 | **`OSSL_STORE_load` and the two `file` `OSSL_OP_STORE` rows** |

**10.14.2 landed, and what it leaves.** The second sub-subphase, and the first whose section 7
dependency is partly **forward** (10.14.4's `v3_genn`/`x509_req` items for `x_all`'s faces).
`src/x509/x_all.rs` transcribes **73 of `x_all.c`'s 98 functions**: the sign/verify doors
(`X509_verify`, `X509_sign`/`_ctx`, `X509_CRL_sign`/`_ctx`), the certificate/CRL `d2i_*`/`i2d_*`
`fp`/`bio` faces, the digest family (`X509_pubkey_digest`, `X509_digest`, `X509_digest_sig`,
`X509_CRL_digest`, `X509_NAME_digest`), the PKCS#8 / `X509_PUBKEY` / private-key / public-key
stream faces, the RSA/DSA/EC key stream faces, and the two `NETSCAPE_SPKI` faces. It **withholds
24 by name, each with its blocker**: `X509_REQ_verify_ex`, `X509_REQ_verify`, `X509_REQ_sign`,
`X509_REQ_sign_ctx`, `d2i_X509_REQ_fp`/`_bio`, `i2d_X509_REQ_fp`/`_bio` and `X509_REQ_digest` (the
`X509_REQ` type, 10.14.11); `X509_ACERT_verify`, `X509_ACERT_sign`, `X509_ACERT_sign_ctx`,
`d2i_X509_ACERT_fp`/`_bio` and `i2d_X509_ACERT_fp`/`_bio` (`X509_ACERT`, 10.14.11);
`simple_get_asn1`, `X509_load_http` and `X509_CRL_load_http` (`OSSL_HTTP_get`, the `http`/`punycode`
units withheld since D455); `d2i_PKCS7_fp`/`_bio`, `i2d_PKCS7_fp`/`_bio` and
`PKCS7_ISSUER_AND_SERIAL_digest` (`d2i_PKCS7`/`i2d_PKCS7` and its item, 10.14.13). `x509_def.rs`
lands the two environment-name defaults and withholds the four forensic-`OPENSSLDIR` paths (Phase
16); `x509_meth.rs` withholds `x509_meth.c` whole (the `X509_LOOKUP`/`X509_LOOKUP_METHOD` types,
10.14.10); `x509rset.c` stays the doc-and-three-withholds module D454 left. `i2d_X509_PUBKEY_bio`
(`:685-689`) is already landed in `src/x509/x_pubkey.rs` (10.3) and is not defined a second time.
Because the `NETSCAPE_SPKI` object was the only blocker of the two `NETSCAPE_SPKI` faces,
`crypto/asn1/x_spki.c` and `x509spki.c` land whole with them rather than being withheld again. Two
helpers were un-withheld so the faces could be written: `X509_get0_extensions` (`x509_set.c`, read
by `X509_sign`) and `X509_get0_pubkey_bitstr` (`x_pubkey.c`, read by `X509_pubkey_digest`).
`RT-STORE` moves from 531 to **670** observations.

**The classical RSA verify path is named, not courted around.** `X509_verify` over an RSA-signed
object (and `NETSCAPE_SPKI_verify` over one) resolves its digest by name through
`EVP_get_digestbyname`, which this crate answers NULL for every built-in name — the Phase 13
legacy-`OBJ_NAME` divergence D333/D343 record (`add_all_legacy_methods` is a no-op,
`src/runtime/init.rs:234`). That path is therefore incomparable, so the probe prints it as
`pending.X509_verify.rsa=` and drives `X509_verify`/`NETSCAPE_SPKI_verify` over an **Ed25519**
signature, which needs no digest-name lookup; the signing faces are driven over the fixed RSA
key, whose PKCS#1 v1.5 output is deterministic.

**The remaining distance is re-measured at the next slice, not assumed here.** 10.14.2 removes its
five units (`x_all.c`, `x509_def.c`, `x509_meth.c`, `x509spki.c`, `x_spki.c`; 1,299 lines) from the
set of *untranscribed* units, but the strict compiled-surface frontier is a closure of undefined
names, so a unit leaves it only when every name the closure needs is defined; the withheld faces
keep `x_all.c`, `x509_def.c` and the wholly-withheld `x509_meth.c` in it. D457's last measured
total — **76 units / 27,335 lines after 10.14.1** — is therefore kept as dated, and the next slice
re-reads it with the same nm join, exactly as D457 did.

**What each blocker a reader might expect does *not* close.** 10.8 already closed
`OSSL_STORE_INFO_get1_CERT`, `OSSL_STORE_INFO_get1_CRL` and the CERT/CRL arms of
`OSSL_STORE_INFO_free`, so 10.16 closes **one** export, not three; the section 6 row that names all
three is superseded by D451 and the corrected count is one. Every 10.14.x row closes no export and no
provider row on its own — that is the expected shape for a dependency sub-subphase, exactly as 10.9's
and 10.10's were — and the twelve exports and two rows are closed by 10.15 and 10.16 alone.

**Why the first sub-subphase is the one that landed.** 10.14.1 is the smallest slice whose closure
is wholly landed, and the six subphases D451–D456 landed had already put every one of its callees in
place. It is **~913 authority lines**, under the ~3,500-line session budget, so it landed rather than
being withheld a third time. Its dependency facts were verified by the same nm join that produced the
table: its only unlanded callees were `ossl_x509_set1_time` (un-withheld here), `X509_check_purpose`
(`v3_purp.c`, 10.14.5) and `X509_self_signed` (`x509_vfy.c`, 10.14.12), which is why `X509_cmp` and
the four `X509_add_cert*` names are withheld by name with those blockers rather than stubbed. The
`x509_cmp ↔ v3_purp ↔ x509_vfy` cycle the two withheld names sit in is the SCC section 6 described,
and cutting it at the call graph is what makes 10.14.1 landable at all.

**The readiness re-measurement, and the order it corrects (this session).** Before landing
anything the same `nm --undefined-only` join was re-run over the authority's objects, resolving
this time each undefined name to the object that defines it and testing that name against the
crate's compiled surface **and** its ordinary Rust definitions (a `pub fn` without `#[no_mangle]`
is landed code though not a C symbol — `ossl_safe_getenv`, `ossl_ctype_check`,
`ossl_pkcs7_ctx_get0_libctx` and their kind), with a whole-unit cascade: land a unit when every
name its own object leaves undefined is already provided. The measurement falsifies a numeric
reading of the table above.

* **No 10.14.N row is closure-ready at row granularity.** The cascade lands four units and stalls:
  `v3_genn.c` (10.14.4), `v3_akeya.c` (10.14.6, a table-only leaf no court can name), `pcy_node.c`
  (10.14.9, D455's two-part blocker: unnameable from the export surface and called by nothing
  landed) and `bio_pk7.c` (10.14.13). Every other 10.14.x unit has at least one unlanded callee,
  so the certificate subsystem is still one function-level cycle.
* **10.14.3 is still not ready, and its blockers are named exactly** — so it was not started.
  `v3_utl.c` leaves `X509V3_get_d2i` (`v3_lib.c`, 10.14.5), `GENERAL_NAME_print` (`v3_san.c`,
  10.14.6), `X509_REQ_get_extensions`/`_get_subject_name` (`x509_req.c`, 10.14.11),
  `AUTHORITY_INFO_ACCESS_free` (`v3_info.c`) and `X509_get_ext_d2i` (`x509_ext.c`) undefined;
  `v3_prn.c` needs `X509V3_EXT_get` (`v3_lib.c`) and `X509V3_conf_free` (`v3_utl.c`). None landed.
* **Three units the table never names are on the critical path**, and are assigned here rather
  than left implicit: `x509_ext.c` (170 lines; `X509_get_ext_d2i`/`X509_add_ext`/`X509_delete_ext`
  and the CRL twins; blocks 10.14.3, 10.14.12 and 10.14.15) to **10.14.5**, since its only two
  callees are `v3_lib.c`'s lookup half; `v3_info.c` (155; `AUTHORITY_INFO_ACCESS_*`/
  `ACCESS_DESCRIPTION_*`; blocks 10.14.3 and 10.14.14) to **10.14.6**; `v3_pmaps.c` (109;
  `ossl_v3_policy_mappings`; blocks 10.14.9) to **10.14.9**.
* **The row that was ready is 10.15's, not any 10.14.x's** — the measurement, not the table's
  numeric order, is why this session landed there.

**10.15 lands its certificate-bag and container-builder units.** The four `crypto/pkcs12/` units
the cascade found whole-unit ready are transcribed: `p12_sbag.c`'s six cert/CRL names
(`PKCS12_SAFEBAG_get1_cert`/`_crl`/`_ex`, `create_cert`/`create_crl`), `p12_crt.c`'s
`PKCS12_create(_ex/_ex2)` and `PKCS12_add_cert` with the three static helpers `copy_bag_attr`,
`pkcs12_add_cert_bag` and `pkcs12_remove_bag` (`p12_add.c` and `p12_mutl.c` were already whole).
The blockers the table recorded — `X509_it`/`X509_CRL_it`, `ossl_x509*_set0_libctx`,
`X509_alias_get0`/`X509_keyid_get0`, `X509_check_private_key`, `X509_digest`,
`PKCS12_item_pack_safebag` — all landed in 10.8/10.11/10.14.1/10.14.2, so the frontier moved and
the names were un-withheld rather than kept again (D451's rule); the table's claim that 10.15 needs
10.14.13 and 10.14.11 is therefore **falsified for these four units**. **Ten of the twelve open
`pkcs12.h` exports close** (`PKCS12_SAFEBAG_create_cert`/`_crl`, `_get1_cert(_ex)`/`_get1_crl(_ex)`,
`PKCS12_add_cert`, `PKCS12_create(_ex/_ex2)`); the two that remain are `PKCS12_parse`
(`ossl_x509_add_cert_new`, `x509_cmp.c`, 10.14.1) and `OSSL_STORE_load` (10.16). `RT-PKCS12` moves
from 292 to **317** observations, driving the bag builders and the three `create` spellings over
the shared fixed certificate/CRL DER with the plain contentInfo and no MAC so the `PFX` bytes are
comparable; `p12_crt.c` becomes a `gen_err_raise_sites.py` entry (stem `PKCS12_CRT`), its four
`PKCS12_R_INVALID_NULL_ARGUMENT`/`PKCS12_R_CALLBACK_FAILED` sites now reachable.

**10.14.4 lands `v3_genn.c` whole** — the cascade's one court-drivable hub. `src/x509/v3_genn.rs`
transcribes the `OTHERNAME`/`EDIPARTYNAME`/`GENERAL_NAME` templates, the `GENERAL_NAMES`
`SEQUENCE OF`, their generated item groups and the eleven hand-written functions, and adds a
`gen_err_raise_sites.py` entry (stem `V3_GENN`). Its closure was satisfied by landed items alone
(`X509_NAME_it`, `ASN1_ANY_it`, `DIRECTORYSTRING_it`, the `ASN1_*_it` string items, `ASN1_dup`, the
comparators), which is what makes it the hub the remaining tables wait on. Its two sibling units
**stay withheld by name**: `v3_conf.c` (blocked by `X509V3_EXT_get_nid` `v3_lib.c`,
`X509V3_conf_free`/`X509V3_parse_list` `v3_utl.c`, `X509_REQ_add_extensions` `x509_req.c`,
`ASN1_generate_v3` `asn1_gen.c`) and `v3_ncons.c` (blocked by `GENERAL_NAME_print`/
`v2i_GENERAL_NAME_ex` `v3_san.c`, `ossl_ipaddr_to_asc` `v3_utl.c`, `OSSL_parse_url` `http_lib.c`,
`ossl_a2ulabel` `punycode.c`). `RT-STORE` moves from 671 to **709** observations.

**The remaining distance, re-measured.** After this session **10 of the fifteen remaining
sub-subphases are untouched** (10.14.3, 10.14.5–10.14.8, 10.14.10–10.14.12, 10.14.14, 10.14.15)
and **five are partial** (10.14.4, 10.14.9, 10.14.13, 10.15, 10.16, one to four units landed
each). The keystone is still the `v3_lib.c ↔ the tables ↔ v3_utl.c` cycle, cut at the function
level inside `v3_utl.c`: its six blockers are confined to `X509_get1_email`, `X509_get1_ocsp`,
`X509_REQ_get1_email`, `do_x509_check`'s four callers and `OSSL_GENERAL_NAMES_print`, so landing
the rest of `v3_utl.c` is what makes the forty-odd table units, then `v3_lib.c`'s lookup half, then
`x509_ext.c` and 10.14.3 itself reachable. The 2 remaining open exports are closed by 10.15 and
10.16 alone.

**The critical path was re-measured against D459, and its "one name" is not the closure.** D459
records `PKCS12_parse`'s single blocker as `ossl_x509_add_cert_new` (10.14.1's withhold) and
`ossl_x509_add_cert_new`'s as `X509_self_signed` (`x509_vfy.c`). Both are the *immediate* edge and
both are true; neither is the closure. The same `nm --undefined-only` join, seeded from the
authority's `crypto/x509/libcrypto-lib-x509_vfy.o` and `libcrypto-lib-v3_purp.o`, resolves
`X509_self_signed`'s body to `ossl_x509v3_cache_extensions` (`v3_purp.c`, 10.14.5), whose own
closure is the whole certificate subsystem: **94 build objects, 333 unlanded names, 73 unlanded
units and 32,158 authority lines**. Seeded instead from `store_result.o` it is **96 objects, 335
names, 75 units and 33,099 lines** — the same 10.14.5–10.14.15 frontier counted this session as
D459's 75 units / 26,157 lines under the certificate-only scope. So the four open items are not
two short chains and a small loader: pieces 1 and 2 sit behind the unfactored SCC, and none of
`X509_self_signed`, the four `X509_add_cert*` names, `PKCS12_parse`, `OSSL_STORE_load` or the two
`file` rows is closure-ready at function granularity. The next real move is unchanged from D459's
last paragraph: the function-level cut inside `v3_utl.c`, which is the keystone the tables,
`v3_lib.c`'s lookup half and then `v3_purp.c`'s cache all wait on. Nothing was landed and nothing
was withheld again; the 296/2 and 634/2 counts stand.

**10.16 lands `file_store.c` and `file_store_any2obj.c`, and the two `file` rows resolve.** The
unit is **1,261 authority lines** (`file_store.c` 900 + `file_store_any2obj.c` 361), transcribed
whole into `src/provider/file_store.rs` and `src/provider/file_store_any2obj.rs`; **nothing is
withheld by name** -- every callee its object leaves undefined is landed (the decoder front doors
and chain, `X509_NAME_hash_ex`, the `X509_NAME` object and printer, the directory walk, the
core-BIO bridge and the parameter layer). `deflt_query` and `base_query` answer `DEFLT_STORES` and
`BASE_STORES` on `OSSL_OP_STORE` (22), and both rows carry `ossl_file_store_functions`'s seven
callbacks. `RT-STORE` moves from **709 to 716 observations**, and the two rows are `implemented`
with **0 unmatched** in `provider-court-coverage.json`.

**The divergence the previous slice met was in the row, not in the shared fetch path, and that was
measured rather than assumed.** The reverted candidate raised `ERR_LIB_OSSL_STORE`/
`ERR_R_UNSUPPORTED` (`44.524556`) at `store_meth.c:362`. Reading that site: its `unsupported` flag
is `flag_construct_error_occurred == 0`, so `ERR_R_UNSUPPORTED` means `construct_loader` was **never
called** -- a map with no entry, or a NULL map. An arm whose row reached `construct_loader` but whose
dispatch table failed the four-clause sanity check would answer `ERR_R_FETCH_FAILED` (`269`)
instead. The first divergent step is therefore `algorithm_do_map`'s entry loop: the `OSSL_OP_STORE`
arm exposed no row. Re-running the shared path with a well-formed one-entry table resolved the
fetch on the first try, and re-running it with an empty table reproduced the exact prior
signature (`lib=44 reason=524556 fetch=null`); the shared path (`OSSL_STORE_LOADER_fetch` ->
`ossl_method_store_fetch`/`ossl_method_construct` -> `ossl_provider_query_operation` ->
`deflt_query`/`base_query`) is intact. The engine's mandatory callbacks are what make the row
resolve: `loader_from_algorithm` refuses a loader without `open`/`attach`, `load`, `eof` and
`close` (`store_meth.c:241`), and `ossl_file_store_functions` carries all four. `file_store.c`'
remaining consumer is `store_result.c`'s `ossl_store_handle_load_result`, which `OSSL_STORE_load`
still withholds on `PKCS12_parse`; the two units are independent, so the rows publish truthfully
while that export stays open.

**10.14.3 lands the reachable half of `v3_utl.c` at function granularity, and the cut is measured.**
The keystone D459 named is done: `crypto/x509/v3_utl.c`'s 51 hand-written functions are cut
by the function-level closure (`court/v3utl_cut.py`, the same `nm --undefined-only` join over the
authority object, resolving every relocation to the container that holds it), and **31 land in
`src/x509/v3_utl.rs`** while **20 are withheld by name**: nine because a callee is unlanded, and
eleven because their closure is complete but every caller is itself withheld (the D453 second
reason). The nine blockers:

| withheld | authority lines | blocker |
|---|---|---|
| `X509_get1_email` | `:449-458` | `X509_get_ext_d2i` (`x509_ext.c`, 10.14.5) |
| `X509_get1_ocsp` | `:460-480` | `X509_get_ext_d2i` and `AUTHORITY_INFO_ACCESS_free` (`v3_info.c`, 10.14.6) |
| `X509_REQ_get1_email` | `:482-494` | `X509_REQ_get_extensions`/`_subject_name` (`x509_req.c`, 10.14.11) and `X509V3_get_d2i` (`v3_lib.c`, 10.14.5) |
| `do_x509_check` and `X509_check_host`/`_email`/`_ip`/`_ip_asc` | `:869-1059` | `X509_get_ext_d2i` (`x509_ext.c`); the four callers reach only the withheld `do_x509_check` |
| `OSSL_GENERAL_NAMES_print` | `:1421-1432` | `GENERAL_NAME_print` (`v3_san.c`, 10.14.6) |

The hostname-matching cluster (`skip_prefix`, `equal_nocase`, `equal_case`, `equal_email`,
`wildcard_match`, `valid_star`, `equal_wildcard`, `do_check_string`) and the three email helpers
(`get_email`, `append_ia5`, `sk_strcmp`) have a **complete** closure but no reachable caller — every
one is reached only through a withheld function — so they are withheld under D453's second reason,
recorded rather than defined unreachable. `x509_local.h`'s `X509V3_conf_add_error_name_value`
expansion is modelled through `openssl_rs_err_add_data` with the authority's NULL-becomes-`<NULL>`
rule. `crypto/x509/v3_utl.c` has been in `gen_err_raise_sites.py`'s covered set since Phase 5, so no
generator input moved; the fifteen `V3_UTL_*` coordinates are all reachable now. `RT-STORE` moves
from **716 to 774 observations** (the parse-list state machine's four shapes and two refusals, the
value/`_uchar`/`_bool`/`_bool_nf` adders, the `get_value_bool`/`_int` pair, the `i2s_`/`s2i` sign and
radix order with the consumption refusal, `i2s_ASN1_ENUMERATED`, both `a2i_IPADDRESS` forms and
`X509V3_NAME_from_section`), all matching the authority on the first run.

**`v3_prn.c` is measured to yield one function, and is not started.** Its four containers' only
blocker is `X509V3_EXT_get` (`v3_lib.c`, withheld behind the `standard_exts[]` table), and
`X509V3_EXT_print`, `X509V3_extensions_print` and `X509V3_EXT_print_fp` all call it; only
`X509V3_EXT_val_prn`'s closure is complete, and `unknown_ext_print` has no reachable caller. The
unit is therefore deferred to the slice that lands the dispatch, rather than landed as a one-function
module whose other three names cannot be named.

**The whole-unit cascade re-measured, and the table units' closures are now satisfied but their
content is unnameable.** With `v3_utl.c`'s helpers in place the greedy cascade lands at step 1 the
`v3_*` table units that needed them (`v3_bitst.c`, `v3_extku.c`, `v3_pcons.c`, `v3_bcons.c`,
`v3_int.c`, `v3_sxnet.c`, `v3_tlsf.c`, `v3_enum.c`, `v3_asid.c`, `v3_battcons.c`, `v3_pmaps.c`,
`v3_akeya.c`). Every one of them is a **table-only leaf** whose sole content is an unexported
`ossl_v3_*` table that `nm -D` does not admit and no court can name — D455's two-part blocker — so
they remain withheld until `v3_lib.c`'s dispatch (`X509V3_EXT_get_nid`, which needs a complete
`standard_exts[]` over all 63 tables) lands with them. **`ossl_x509v3_cache_extensions` did not
become reachable**: `v3_purp.c`'s measured remaining-need is six names — the four `X509_get_ext`/
`_by_NID`/`_count`/`_get_ext_d2i` (`x509_ext.c`, 10.14.5), `ossl_x509_init_sig_info` (`x509_set.c`,
withheld) and `DIST_POINT_set_dpname` (`v3_crld.c`, 10.14.6) — and `x509_ext.c`'s only two callees
are `v3_lib.c`'s withheld lookup half, so the `x509_cmp ↔ v3_purp ↔ x509_vfy` SCC is still cut at
the function level and 10.14.5 is not ready. The table leaves the cascade "lands"
(`v3_bcons.c`, `v3_crld.c`, `v3_san.c`, …) are counted only by symbol closure; a table-only leaf
is still unnameable, so they do not close `v3_purp.c` in fact.

**One Phase-7 deferral was discharged as a consequence, and retiring it required landing the
export.** `EVP_add_alg_module`'s only blocker was `X509V3_get_value_bool`, which this slice landed,
so `blocker_liveness` fired on the now-stale hand-off. Rather than replace a blocker the authority
does not have, the pair landed: `crypto/evp/evp_cnf.c` is transcribed as `src/evp/evp_cnf.rs`
(`alg_module_init` and `EVP_add_alg_module`, whole), Phase 7 moves from `implemented 735 / deferred
215` to **`implemented 736 / deferred 214`**, and the `phase7_obligations.py` blocked-handoff row and
the `forensics/prerequisites.json` unit record are retired — the rule D453 and D454 used. Phase-10
counts are unchanged at **`296 implemented / 2 open`** exports and **`636 implemented / 0 open`**
provider rows, the expected shape for a dependency sub-subphase.

**10.14.5 and 10.14.6 land the chain's non-table half, and the wall is measured to be the tables
myself.** The slice's target was the call chain D461 named -- `PKCS12_parse` <-
`ossl_x509_add_cert_new` <- `X509_self_signed` <- `ossl_x509v3_cache_extensions`. Before landing
anything the same `nm --undefined-only` join was re-run over the authority's objects and one
correction to D461 came out of it: `ossl_x509v3_cache_extensions` needs **seven** names, not six --
the four `x509_ext.c` accessors, `ossl_x509_init_sig_info`, `DIST_POINT_set_dpname`, **and
`BASIC_CONSTRAINTS_free`** (`v3_bcons.c`, which the four-name list missed). Six of the seven land
here; the seventh is the wall:

* **`src/x509/x509_ext.rs` (10.14.5)** transcribes 21 of the 27 containers in
  `crypto/x509/x509_ext.c` (170 lines) -- the count/by-NID/by-OBJ/by-critical/get accessors and
  the add/delete mutators over `X509`, `X509_CRL` and `X509_REVOKED`. Its closure is 10.11's
  `x509_v3.rs` alone. **Six are withheld by name**, all behind `X509V3_get_d2i`/`X509V3_add1_i2d`
  in `v3_lib.rs`: `X509_CRL_get_ext_d2i` (`:62-65`), `X509_CRL_add1_ext_i2d` (`:67-72`),
  `X509_get_ext_d2i` (`:113-116`), `X509_add1_ext_i2d` (`:118-123`), `X509_REVOKED_get_ext_d2i`
  (`:161-164`), `X509_REVOKED_add1_ext_i2d` (`:166-169`). Nothing was stubbed.
* **`ossl_x509_init_sig_info` (`x509_set.c:305-309`) and its file-local `x509_sig_info_init`
  (`:217-302`) land** in `src/x509/x509_set.rs`, the third of the seven names. Its three
  `ERR_LIB_X509` sites (`:230` `X509_R_UNKNOWN_SIGID_ALGS`, `:252` `X509_R_ERROR_USING_SIGINF_SET`,
  `:284` `X509_R_ERROR_GETTING_MD_BY_NID`) join `gen_err_raise_sites.py` as stem `X509_SET` — the
  unit was previously unlisted — and the stale `forensics/prerequisites.json` row that covered the
  internal is retired (D453/D454's rule). Its `default:` branch keeps the authority's
  `EVP_get_digestbynid` call rather than substituting a fetched digest, so the Phase-13 legacy
  `OBJ_NAME` divergence (D333/D343) stays where the crate records it; the function is unreachable
  until the cache lands, so no court names it.
* **`DIST_POINT_set_dpname` (`v3_crld.c:526-552`) lands** in `src/x509/v3_crld.rs` (10.14.6) with
  the `DIST_POINT_NAME` layout; it is an export the admitted DSO carries, so the court drives it
  directly. **The unit's six `ossl_v3_*` tables are withheld by name** (`ossl_v3_crld`:26-35,
  `ossl_v3_freshest_crl`:36-45, `ossl_v3_idp`:360-370, `ossl_v3_crl_invdate`:487-495,
  `ossl_v3_crl_hold`:496-504, `ossl_v3_aa_issuing_dist_point`:715-724) with their section/printer
  behind the same `standard_exts[]`/`v3_conf`/`v3_san` blockers; the finding is a
  `forensics/prerequisites.json` divergence row (D452's mechanism), not a loosened gate.
* **`src/x509/v3_bcons.rs` (10.14.6) lands `BASIC_CONSTRAINTS` and its item group** -- the
  `ASN1_SEQUENCE` template (`:38-41`) and the `IMPLEMENT_ASN1_FUNCTIONS` group (`:43`), so
  `BASIC_CONSTRAINTS_free` (`crypto/x509/v3_bcons.c`), the seventh name the cache needs, is real.
  `ossl_v3_bcons` and the two callbacks (`i2v_BASIC_CONSTRAINTS`:45-54,
  `v2i_BASIC_CONSTRAINTS`:55-85) are **withheld by name** behind the same `standard_exts[]` /
  `v3_lib.c` dispatch, with their own divergence row.

**`standard_exts[]` is NOT complete, and is therefore not published.** `standard_exts.h:15-95`
names **73 entries over 63 distinct `ossl_v3_*` tables, defined by 44 authority units totalling
9,948 lines**, and their collective closure adds **24 unlanded names** from 17 further units
(`asn1_gen.c` 794, `t_x509.c` 559, the three CT units, `http_lib.c` 318 and `punycode.c`
316 among them). **`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`
stay withheld in `v3_lib.rs`**: a partial array would silently change `OBJ_bsearch_ext`'s answer
for every missing NID (D456), so it is not half-landed. **`ossl_x509v3_cache_extensions` did not
become reachable, but it is now one name from it**: all six of its other names are landed, and
its only remaining blocker is `X509_get_ext_d2i` -> `X509V3_get_d2i` -> the dispatch. `PKCS12_parse`
and `OSSL_STORE_load` therefore **stay open**; the ledger is unchanged at `296 implemented / 2 open`
and the provider rows at `636 / 0`. `RT-STORE` moves from **774 to 806 observations** (32: the
accessor/search arms over the fixed certificate and CRL, the add/delete pair and the empty-list
collapse, `DIST_POINT_set_dpname`'s NULL/`type 0`/`type 1` shapes, and the `BASIC_CONSTRAINTS`
item group's build/encode/decode/re-encode/free round trip). The remaining distance to the chain is
the **44-unit / 9,948-line table layer** plus that 24-name closure — still the whole `v3_lib` ↔
tables ↔ `v3_utl`/`v3_conf`/`v3_san` component, not a small loader.

**The table layer's first slice lands 14 of the 63 tables, and the array stays the claim.** The
owner accepted D463's option 1: land the table modules as real Rust, drive each through whatever
public surface reaches it, and withhold only the published `standard_exts[]` array and the six
lookup names in `v3_lib.rs` until all 63 tables exist. This slice is the first bite.

* **The measurement, run first.** The same `nm --undefined-only` join, with a unit closure-ready
  when every name its object leaves undefined is landed **and** crediting the crate's ordinary
  `pub fn` definitions (the D459 credit), finds **24 of the 44 units closure-ready** and **20
  blocked**, each with its named blocker. The smallest ready units landed first; the blocked 20 are
  the same component D463 named, dominated by the `v3_san.c` hub (`GENERAL_NAME_print`,
  `v2i_GENERAL_NAME_ex`, `i2v_GENERAL_NAME`, `i2v_GENERAL_NAMES`, `v2i_GENERAL_NAMES`), the
  `v3_conf.c` config layer (`X509V3_get_section`/`_section_free`) and `ossl_print_attribute_value`
  (`x_attrib.c`).
* **Twelve units transcribe whole — 612 authority lines — carrying 14 of the 63 tables**: `v3_int.c`
  (3 tables: `ossl_v3_crl_num`, `ossl_v3_delta_crl`, `ossl_v3_inhibit_anyp`), `v3_enum.c`
  (`ossl_v3_crl_reason`, with its exported printer `i2s_ASN1_ENUMERATED_TABLE`), `v3_audit_id.c`,
  `v3_no_ass.c`, `v3_single_use.c`, `v3_soa_id.c`, `v3_group_ac.c`, `v3_ind_iss.c`,
  `v3_no_rev_avail.c` (one `ASN1_NULL` table each), `v3_ia5.c` (`ossl_v3_ns_ia5_list`, eight rows),
  `v3_utf8.c` (`ossl_v3_utf8_list`, one row) and `v3_pku.c` (`ossl_v3_pkey_usage_period`, with its
  `i2r_PKEY_USAGE_PERIOD`). The first nine are Phase 10.12/10.13 leftovers the earlier slices
  withheld as "dead data with no court"; this slice lands them under the owner's option-1 decision.
* **Forty-nine tables remain withheld over 32 units (9,336 authority lines), and the split is
  recorded rather than blurred.** Sixteen tables over 12 units (2,714 lines) are
  **closure-ready but not attempted within this slice's budget** — the task's rule is that a
  withholding is a claim about the frontier, and for these the frontier is already past them, so
  they are named as budget, not as a closure gap. The other 33 tables over 20 units (6,622 lines)
  are **genuinely blocked**, each by a named unlanded callee (the table below).

| status | tables | units | authority lines |
|---|---:|---:|---:|
| landed whole (row's table(s) exist) | **14** | 12 | 612 |
| closure-ready, withheld for budget | 16 | 12 | 2,714 |
| withheld by name, with an unlanded blocker | 33 | 20 | 6,622 |
| **withheld, total** | **49** | **32** | **9,336** |

The budget-deferred 12 are `v3_asid.c` (871), `v3_sxnet.c` (259), `v3_ist.c` (144), `v3_tlsf.c`
(137), `v3_extku.c` (125, four tables), `v3_pmaps.c` (109), `v3_skid.c` (108), `v3_bitst.c` (100,
`two tables), `v3_pcons.c` (91), `v3_battcons.c` (86), `v3_bcons.c` (85) and `v3_timespec.c`
(599, whose item groups landed in 10.13 and whose table and twelve printers remain). The genuinely
blocked 20 are led by `v3_addr.c` (1,359), `v3_ncons.c` (862, three tables), `v3_crld.c` (724, six
tables), `v3_san.c` (689), `v3_cpols.c` (515) and `v3_admis.c` (355), whose common blockers are
`GENERAL_NAME_print`/`v2i_GENERAL_NAME_ex`/`i2v_GENERAL_NAME(S)` (`v3_san.c`),
`X509V3_get_section`/`_section_free` (`v3_conf.c`) and `ossl_print_attribute_value` (`x_attrib.c`).

* **The representation the slice chose, and why.** A table is a Rust `pub static` the eventual array
  references by path; it is **not** emitted as a `#[no_mangle]` C symbol. The authority's
  `ossl_v3_*` are global only because its translation-unit model gives them a symbol; the admitted
  DSO does not export them (`nm -D` shows none), so no court can name one either way. Keeping them
  Rust-only is the choice `evp::digest::StaticMd` already made, and it keeps the crate's C surface
  the ABI the project measures rather than a mirror of the authority's object-file symbol table.
* **A representation correction fell out of the first table, and it is recorded rather than
  smoothed over.** `struct v3_ext_method`'s `ASN1_ITEM_EXP *it` (`x509v3.h:69`) is a **function**
  pointer: `ASN1_ITEM_EXP` is `typedef const ASN1_ITEM *ASN1_ITEM_EXP(void)` (`asn1.h.in:378`), so
  `ASN1_ITEM_ref(i)` = `i##_it` is the getter function designator and `ASN1_ITEM_ptr(method->it)` =
  `((iptr)())` calls it. D456's first cut typed the field `*const Asn1Item`; `v3_lib.rs` now types
  it the function pointer the header declares, a pointer-sized change no landed code read.
* **Three `prerequisites.json` divergence rows were retired, not loosened.** The `v3_ia5.rs`,
  `v3_pku.rs` and `v3_utf8.rs` rows covered exactly the tables now built, so the gate's
  `divergence_record_does_not_match` finding fired and the rows were removed (the D453/D454 rule).
  No gate was weakened; `prerequisite_gate.py` is clean at 18 divergence rows.
* **The chain did not move.** `standard_exts[]` is not published (49 tables missing), so
  `X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d` stay withheld,
  `X509_get_ext_d2i` stays withheld, `ossl_x509v3_cache_extensions` stays unreachable, and
  `PKCS12_parse` and `OSSL_STORE_load` stay open. Phase-10 counts are unchanged at
  **`296 implemented / 2 open`** exports and **`636 implemented / 0 open`** provider rows.
* **The court grew where the surface did.** `RT-STORE` moves from **806 to 810 observations**: four
  arms driving the one newly nameable export, `i2s_ASN1_ENUMERATED_TABLE` (the row's `usr_data` hit
  and the fall-through miss to `i2s_ASN1_ENUMERATED`), each popping its own error queue first
  (D455). The 109-court total moves from **45,849 to 45,853**. The remaining tables add no arm: they
  are unnameable from the admitted DSO, and their drivable surface (the item groups) was already
  driven.
* **The D462 flake was not reproduced.** Five consecutive full `cargo test --lib` runs on the
  settled tree, each preserving full output and capturing `git --no-optional-locks status --short`
  at the moment of the run, all read **1114 passed, 0 failed** with a **clean** tree; no retry was
  added and no test skipped. That is five more green runs since the single D458 failure and still
  **not** a reproduction, so the defect stays open and unnamed rather than closed by absence.

**The three hubs land, and the wall they hid is `ASN1_generate_v3`.** The fourteenth pulled-forward
slice is task 2 of the D464 hand-off: `ossl_print_attribute_value` (`x_attrib.c`, hub 3),
`X509V3_get_section`/`_section_free` and the config-value layer (`v3_conf.c`, hub 2), and
`GENERAL_NAME_print`/`i2v_GENERAL_NAME`/`i2v_GENERAL_NAMES` (`v3_san.c`, hub 1).

* **`src/x509/x_attrib.rs` is now whole.** `ossl_print_attribute_value` (`:76-249`) and its
  `static print_oid` (`:61-74`) land; the blockers D464 recorded -- `d2i_X509_NAME`,
  `X509_NAME_print_ex`, `X509_NAME_free`, `ASN1_ENUMERATED_get_int64`, `ASN1_parse_dump`,
  `ossl_bio_print_hex` -- all landed by 10.14.2/10.14.3. `V_ASN1_VIDEOTEXSTRING` (`asn1/layout.rs`)
  and `XN_FLAG_ONELINE` (`a_strex.rs`) were added because the printer names them.
* **`src/x509/v3_conf.rs` lands the config-value layer.** `X509V3_get_string`/`X509V3_get_section`/
  `X509V3_string_free`/`X509V3_section_free` (`:396-432`), the `nconf`/`lhash` `X509V3_CONF_METHOD`
  tables and their callbacks, and the four setters `X509V3_set_nconf`/`set_ctx`/`set_issuer_pkey`/
  `set_conf_lhash`. The `X509V3_CTX` (`v3_ext_ctx`) and `X509V3_CONF_METHOD` layouts live here with
  their offsets asserted. **Fourteen names are withheld behind `X509V3_EXT_get_nid`** (`v3_lib.rs`,
  the withheld dispatch): `X509V3_EXT_i2d`, `do_ext_nconf`, `X509V3_EXT_nconf_int`,
  `X509V3_EXT_nconf`, `X509V3_EXT_nconf_nid`, `X509V3_EXT_add_nconf_sk`, `X509V3_EXT_add_nconf`,
  `X509V3_EXT_CRL_add_nconf`, `X509V3_EXT_conf`, `X509V3_EXT_conf_nid`, `X509V3_EXT_add_conf`,
  `X509V3_EXT_CRL_add_conf`, `X509V3_EXT_REQ_add_conf` and `X509V3_EXT_REQ_add_nconf` (the last also
  on `X509_REQ_add_extensions`, `x509_req.c`, 10.14.11). Six more -- `v3_check_critical`,
  `v3_check_generic`, `do_ext_i2d`, `v3_generic_extension`, `generic_asn1`, `delete_ext` -- have a
  landed closure but are withheld under D453's second reason (only withheld callers).
* **`src/x509/v3_san.rs` lands the printers**, and **withholds the whole `v2i` cluster behind
  `ASN1_generate_v3`** (`crypto/asn1/asn1_gen.c`): `a2i_GENERAL_NAME`, `v2i_GENERAL_NAME`,
  `v2i_GENERAL_NAME_ex`, `v2i_GENERAL_NAMES`, `do_othername`, `do_dirname`, `v2i_subject_alt`,
  `v2i_issuer_alt`, `copy_email`, `copy_issuer` and the `ossl_v3_alt` table (a `prerequisites.json`
  `owned_by_a_later_stratum` divergence row, D452/D455/D456's mechanism -- not a loosened gate).
  `a2i_GENERAL_NAME`'s `do_othername` calls `ASN1_generate_v3`, which is Phase 5's deferred pair
  `ASN1_generate_v3`/`ASN1_generate_nconf`; landing it is the next real move, because every other
  arrow in the cluster is a named caller of these ten.
* **`src/x509/v3_utl.rs` un-withholds `OSSL_GENERAL_NAMES_print`** (`:1421-1432`), the tenth name on
  its withhold table, now that `GENERAL_NAME_print` exists; the module lands 32 of its 51 functions.

**The readiness re-measurement, and the tables the hubs unblock.** The same `nm --undefined-only`
join (`court/table_units.py`) now reads **34 closure-ready table units** (from 24) and **10 blocked**
(from 20). The ten newly-ready units the hubs unblocked are `v3_aaa.c`, `v3_ac_tgt.c`, `v3_admis.c`,
`v3_attrdesc.c`, `v3_attrmap.c`, `v3_cpols.c`, `v3_iobo.c`, `v3_pci.c`, `v3_sda.c` and
`v3_usernotice.c`; the ten still blocked carry their named blocker (`v3_crld.c`/`v3_info.c`/`v3_san.c`
on the `v2i` cluster, `v3_ncons.c` on `http_lib.c`/`punycode.c` too, `v3_akid.c` on
`AUTHORITY_KEYID_*`, `v3_authattid.c` on `OSSL_ISSUER_SERIAL_it`, `v3_rolespec.c` on
`ossl_serial_number_print`, `v3_ocsp.c` on `ocsp_asn.c`, `ct_x509v3.c` on the CT units, and
`v3_addr.c` on `ossl_asn1_string_set_bits_left`, which the crate defines as
`asn1::bitstr::set_bits_left` under a different name). **No table unit was landed this slice** -- the
hubs are the bite, and the 22 now-closure-ready units are the next one; **14 of the 63 tables are
landed**.

**The court grew where the surface did.** `RT-STORE` moves from **810 to 865 observations**: a new
`drive_v3_hubs` block drives `GENERAL_NAME_print`/`i2v_GENERAL_NAME`/`i2v_GENERAL_NAMES`/
`OSSL_GENERAL_NAMES_print` over hand-built general names of every kind (an `ossl_v3_alt`-independent
surface), and the `X509V3_get_section`/`_get_string` layer over a real `NCONF` loaded from a memory
BIO, with the no-database, `lhash`-NULL and `set_issuer_pkey` refusals as the refusal arms; every
arm pops its error queue first (D455). The 109-court total moves from **45,853 to 45,908**.
`implemented_surface` moves from 3,684 to **3,741** symbols (its C-style internal population 478 to
479 -- `ossl_print_attribute_value` is now a crate `#[no_mangle]` internal, and `docs/CI.md` records
479). `dispatch_court` gains a `NOT_A_DISPATCH` exemption for the `X509V3_CONF_METHOD` callback
aliases, and one stale `prerequisites.json` row (`x_attrib.c`'s `ossl_print_attribute_value`) is
retired; `prerequisite_gate.py` is clean at 18 divergence rows.

**The D462 flake was not reproduced.** One full `cargo test --lib` run with `git status` captured at
the moment of the run read **1114 passed, 0 failed** on a clean tree; the pipeline's two runs read
**1114 passed, 0 failed** each (one serial, one parallel). No retry was added and no test skipped.

**The chain did not move.** `standard_exts[]` is not published (49 tables missing), so
`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d` stay withheld,
`X509_get_ext_d2i` stays withheld, `ossl_x509v3_cache_extensions` stays unreachable, and
`PKCS12_parse` and `OSSL_STORE_load` stay open. Phase-10 counts are unchanged at
**`296 implemented / 2 open`** exports and **`636 implemented / 0 open`** provider rows.

The remaining distance is therefore **49 tables over 32 units** -- 33 blocked over 20 units /
6,622 lines, now 10 blocked over the units above, and the 16 closure-ready-but-deferred over 12
units / 2,714 lines are now 22 closure-ready units -- plus the **24-name closure** D463 measured over
17 further units. The next real move is two-bite: land **`ASN1_generate_v3`/`ASN1_generate_nconf`**
(the `v2i` cluster's one blocker), then the now-closure-ready table units, then the array.

**`ASN1_generate_v3` lands, and it is the `v2i` cluster's one name.** The fifteenth pulled-forward
slice is task 1 of the D465 hand-off. `crypto/asn1/asn1_gen.c` (794 lines) now transcribes whole
into `src/asn1/asn1_gen.rs`: `ASN1_generate_v3` (`:90-97`) and `ASN1_generate_nconf`
(`:79-88`), the generator core `generate_v3` (`:99-247`), its parse callback `asn1_cb` (`:249-352`),
`parse_tagging` (`:354-402`), `asn1_multi` (`:406-467`), `append_exp` (`:469-503`),
`asn1_str2type` (`:583-748`) and `bitstr_cb` (`:750-768`), with the `ASN1_str2mask` table Phase 5
already landed. The `X509V3_CTX` the pair takes is `src/x509/v3_conf.rs`'s (10.14.4), which is why
Phase 5 could not land them and this slice can.

**The `v2i` cluster lands with it.** `src/x509/v3_san.rs` now transcribes `do_othername`
(`:631-662`), `do_dirname` (`:664-689`), `a2i_GENERAL_NAME` (`:503-590`), `v2i_GENERAL_NAME_ex`
(`:592-629`), `v2i_GENERAL_NAME` (`:497-501`) and `v2i_GENERAL_NAMES` (`:470-495`). **Four names
stay withheld**, each with its blocker, and `ossl_v3_alt` with them: `v2i_subject_alt` (`:377-413`)
and `copy_email` (`:419-468`) need `X509_REQ_get_subject_name` (`x509_req.c`, 10.14.11);
`v2i_issuer_alt` (`:301-332`) and `copy_issuer` (`:336-375`) need the withheld dispatch
`X509V3_EXT_d2i` (`v3_lib.rs`); the one table's two rows name two of those, so it is withheld whole
(`prerequisites.json` divergence row, unchanged). **The readiness re-measurement moves closure-ready
table units from 34 to 36** (`v3_crld.c` and `v3_info.c` are now READY) and blocked from 10 to 8.

**The differential court found the previous slice's declared reason codes were wrong, and they were
fixed at the root.** `crypto/x509/v3_san.c` is not in `gen_err_raise_sites.py`, so the `V3_SAN_*`
coordinates are declared locally. Their reason values had been transcribed against the wrong
header and were off by everything: `v2i_GENERAL_NAME_ex`'s missing-value raise read `109` where
`X509V3_R_MISSING_VALUE` is `124`, and its unsupported-option raise read `110` where
`X509V3_R_UNSUPPORTED_OPTION` is `117`, with `ERR_R_ASN1_LIB` typed `524557` against its own
`524301`. The first `RT-STORE` run of the new arms reported exactly those two coordinates as
residuals, so the constants were re-read from `x509v3err.h` and `err.h`, both reachable ones pinned
by new refusal arms (bad RID, bad IP, missing section, malformed othername, unsupported type, missing
value). `v3_info.c` did **not** land: its `i2v` callback's `BIO_snprintf` and its `v2i`'s
never-assigned `acc->location` make it a separate bite, and it is named withheld rather than half
landed.

**`v3_bitst.c` lands whole, the first table unit of the 22.** `src/x509/v3_bitst.rs` transcribes the
100-line unit: `ns_cert_type_table` (`:16-26`), `key_usage_type_table` (`:28-40`), the two
`EXT_BITSTRING` rows `ossl_v3_nscert`/`ossl_v3_key_usage` (`:42-43`) and the two exported callbacks
`i2v_ASN1_BIT_STRING` (`:45-65`) and `v2i_ASN1_BIT_STRING` (`:67-100`), each row's `usr_data`
pointing at its Rust table. `v3_bitst.c`'s three raise coordinates are declared locally. The
prototype court caught a `*const`/`*mut` mismatch on the two callbacks' method parameter against the
authority's own prototypes, so both are `*mut` and the rows cast through a `const fn`, the pattern
`v3_ia5.rs` set. **The crate now defines 16 of the 63 tables.**

**The D462 flake was REPRODUCED, and it is a real parallel-safety defect.** The second full
`cargo test --lib` of this slice's group-2 verification failed **1116 passed, 1 failed**:
`evp::algorithm::tests::a_refused_precondition_is_success_and_skips_the_map`, panicking at
`src/evp/algorithm.rs:576` with `assertion left == right failed  left: 2  right: 1`, on the
**parallel** run (the serial `--test-threads=1` run just before it passed 1117). The tree at the
moment of the run carried only this session's source edits and regenerated evidence -- no mid-edit
window, which is D462's leading explanation and is therefore **falsified**. The cause is on the
face of the test: five sibling tests in `evp::algorithm` share the process-global `SAW` array and
the `PRE_RESULT`/`PRE_ERRORS`/`POST_RESULT` statics with no `test_support::lock_global_state`, so
two of them interleaved and `pre` was counted twice. That is precisely the hazard the parallel gate
exists to catch (D462's stated policy: "a test that touches a global is supposed to take
`lock_global_state`"), so the five tests now take the crate lock; six parallel module runs and
three more full parallel suite runs are green. No test was skipped, deleted or weakened, and no
assertion was relaxed.

**The court grew where the surface did.** `RT-STORE` moves from **865 to 981 observations**: the
62 generator arms (twelve scalars, the tags, the config-backed `SEQUENCE`, the two refusals), the
`v2i` cluster (five `CONF_VALUE` types, `dirName`/`otherName` under a real `NCONF`, a two-entry
`v2i_GENERAL_NAMES`, and six per-type refusals) and the four `v3_bitst` arms, each popping its own
error queue first (D455). The 109-court total moves from **45,908 to 46,024**. `implemented_surface`
moves from 3,741 to **3,749** symbols (the eight new exports). Phase 5's ledger is **unchanged** at
`implemented 474 / deferred 91`: the two generator exports were never Phase-5 rows but Phase-11's
(`phase5-obligations.json` carries them at `owning_phase: 11`), so landing them moves the surface
and not that ledger -- and no Phase-11 row is created, which is why Phase 11 still derives
`not-started`.

**The chain did not move.** `standard_exts[]` is still not published (47 tables missing), so
`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d` stay withheld,
`X509_get_ext_d2i` stays withheld, `ossl_x509v3_cache_extensions` stays unreachable, and
`PKCS12_parse` and `OSSL_STORE_load` stay open. Phase-10 counts are unchanged at
**`296 implemented / 2 open`** exports and **`636 implemented / 0 open`** provider rows, and Phase 11
still derives `not-started`.

The remaining distance is **47 of the 63 tables** -- 16 are landed -- over the 8 blocked units and
the 36 closure-ready units (13 of which already carry landed tables), plus D463's 24-name closure
over 17 further units. The next real move is the closure-ready table units -- starting with
`v3_crld.c` and `v3_info.c`, now unblocked by the `v2i` cluster -- then the array, then
`PKCS12_parse` and `OSSL_STORE_load`.

**The closure-ready table units land; thirty of the sixty-three tables now exist, and the array is
still withheld.** The sixteenth pulled-forward slice took D466's list directly. The same
`nm --undefined-only` join was re-run first and reproduced D466 exactly: **36 closure-ready table
units, 8 blocked**, **16 of 63 tables landed**, 23 closure-ready units unlanded. **Nine units / 14
tables** then landed, each with its item group(s), its `i2s_`/`s2i_`/`i2v_`/`v2i_`/`i2r_`/`r2i_`
callbacks and its `OSSL_V3_EXT_METHOD` row(s), nothing stubbed:

* `v3_extku.c` (**4** tables: `ossl_v3_ext_ku`, `ossl_v3_ocsp_accresp`, `ossl_v3_acc_cert_policies`,
  `ossl_v3_acc_priv_policies`) -- `src/x509/v3_extku.rs`, the `EXTENDED_KEY_USAGE` `SEQUENCE OF`
  item group and the two callbacks.
* `v3_info.c` (**2**: `ossl_v3_info`, `ossl_v3_sinfo`) -- `src/x509/v3_info.rs`, the
  `ACCESS_DESCRIPTION`/`AUTHORITY_INFO_ACCESS` groups, the two callbacks and the exported
  `i2a_ACCESS_DESCRIPTION`.
* `v3_sda.c` (**2**: `ossl_v3_subj_dir_attrs`, `ossl_v3_associated_info`) -- `src/x509/v3_sda.rs`,
  the `OSSL_ATTRIBUTES_SYNTAX` `SEQUENCE OF X509_ATTRIBUTE` item group and its printer.
* `v3_pmaps.c` (1: `ossl_v3_policy_mappings`), `v3_pcons.c` (1: `ossl_v3_policy_constraints`),
  `v3_battcons.c` (1: `ossl_v3_battcons`), `v3_tlsf.c` (1: `ossl_v3_tls_feature`, whose item is the
  authority's `static` `TLS_FEATURE_it`, so only `_new`/`_free` are exported), `v3_iobo.c` (1:
  `ossl_v3_issued_on_behalf_of`) and the table half of `v3_bcons.c` (1: `ossl_v3_bcons`), whose item
  group had already landed -- the `forensics/prerequisites.json` divergence row that covered the
  withheld table was **retired** once it became real (D453/D454), taking the register from 18 rows
  to 17.

Each unit's raise coordinates are declared locally with the `err_sites::ErrSite` shape (none of
these files is in `gen_err_raise_sites.py`'s covered set), their reason values read from the
authority's `err.h`/`x509v3err.h`/`x509v3err.h` rather than typed: `v3_info`'s five, `v3_pcons`'s
three, `v3_pmaps`'s four, `v3_battcons`'s two, `v3_bcons`'s two and `v3_tlsf`'s three. `v3_sda.c`
and `v3_iobo.c` raise nothing. Nothing was courted over: the rows are unnameable from the admitted
DSO, so `RT-STORE` stays at **46,024** observations across 109 courts and `implemented_surface`
moves from 3,749 to **3,784** symbols (the thirty-five new exports: five `EXTENDED_KEY_USAGE_*`,
five `OSSL_BASIC_ATTR_CONSTRAINTS_*`, five `ACCESS_DESCRIPTION_*`, five
`AUTHORITY_INFO_ACCESS_*`, five `OSSL_ATTRIBUTES_SYNTAX_*`, three `POLICY_CONSTRAINTS_*`, three
`POLICY_MAPPING_*`, one `POLICY_MAPPINGS_it`, two `TLS_FEATURE_*` and the exported
`i2a_ACCESS_DESCRIPTION`).

**The array is not published and nothing closed.** **33 of 63 tables are still withheld** -- the 14
blocked tables over the 8 blocked units (`v3_addr`'s `ossl_v3_addr` a naming shim since
`ossl_asn1_string_set_bits_left` is landed as `asn1::bitstr::set_bits_left`; the rest blocked on
`ct_x509v3.c`, `ocsp_asn.c`, `AUTHORITY_KEYID_*` in `v3_akeya.c`, `OSSL_ISSUER_SERIAL_it` in
`x509_acert.c`, `http_lib.c`/`punycode.c`, `ossl_serial_number_print` in `t_x509.c`, and
`X509V3_EXT_d2i`/`X509_REQ_get_subject_name`) plus 19 over the 14 closure-ready units still
unlanded (`v3_crld.c`'s six, `v3_asid.c`, `v3_timespec.c`, `v3_cpols.c`, `v3_admis.c`, `v3_pci.c`,
`v3_sxnet.c`, `v3_skid.c`, `v3_ac_tgt.c`, `v3_attrdesc.c`, `v3_attrmap.c`, `v3_aaa.c`, `v3_ist.c`,
`v3_usernotice.c`, all closure-ready). So `standard_exts[]` (`standard_exts.h:15-95`) and the six `v3_lib.rs` lookup
names stay withheld (D456), `X509_get_ext_d2i` stays withheld, `ossl_x509v3_cache_extensions` stays
unreachable, and `PKCS12_parse` and `OSSL_STORE_load` stay open. Phase-10 counts are unchanged at
**`296 implemented / 2 open`** exports and **`636 implemented / 0 open`** provider rows, and Phase 11
still derives `not-started`.

**Verification, including the flake protocol and a measured environment flake.** D462's protocol was
followed first: `cargo test --lib` with `git --no-optional-locks status --short` captured at the
moment of the run read **1117 passed, 0 failed** on a **clean** tree -- D466's fix holds, and no test
was retried, skipped or weakened. `cargo fmt --all -- --check` and `cargo clippy --all-targets --
-D warnings` are clean; the 109-court pipeline reads **1117 passed, 0 failed** on both the serial and
the parallel half and prints `PIPELINE OK` exit 0 on two consecutive runs. One intermediate run
failed `probe_hygiene.py` with `rt_bio_resolve_probe.c` `UNSTABLE` -- its `getaddrinfo` failure
text differed between `-O0` (`Name or service not known`) and `-O1` (`No address associated with
hostname`) -- which is a **host DNS/environment** divergence in the container, not a source change:
the same probe read `clean` in the two runs either side of it, and neither this slice's source nor
its evidence touches `crypto/bio/b_addr.c`. It is recorded rather than smoothed: the probe's
`-O0`/`-O1` transcripts depend on the resolver's `EAI_*`-to-string mapping, which is the same class
of environment dependence the court's own stability plane exists to surface.

**The remaining distance is a number: 33 of the 63 tables** (14 blocked over 8 units, 19
closure-ready over 14 units), plus D463's 24-name closure over 17 further units; then the array,
then `X509_get_ext_d2i` -> `ossl_x509v3_cache_extensions` -> `PKCS12_parse` -> `store_result.c` /
`OSSL_STORE_load` -> the seal.

**The second table batch lands; forty-one of the sixty-three tables now exist.** The seventeenth
pulled-forward slice took the remaining closure-ready table units. **Six units / 11 tables** landed,
each with its item group(s), its callbacks and its `OSSL_V3_EXT_METHOD` row(s), nothing stubbed:

* `v3_crld.c` (**6** tables: `ossl_v3_crld`, `ossl_v3_freshest_crl`, `ossl_v3_idp`,
  `ossl_v3_crl_invdate`, `ossl_v3_crl_hold`, `ossl_v3_aa_issuing_dist_point`) -- `src/x509/v3_crld.rs`,
  the four item groups (`DIST_POINT_NAME`'s `CHOICE` with its `dpn_cb` `ASN1_AUX`, `DIST_POINT`,
  `CRL_DIST_POINTS`, `ISSUING_DIST_POINT`, `OSSL_AA_DIST_POINT`), the section callbacks and the six
  rows. This also un-withholds nothing: `DIST_POINT_set_dpname` and its type were already landed at
  function granularity (D455).
* `v3_asid.c` (**1**: `ossl_v3_asid`, `ext_nid` `NID_sbgp_autonomousSysNum`) -- `src/x509/v3_asid.rs`,
  the four RFC 3779 item groups and the canonicalisation routines. The IP-address half of RFC 3779
  lives in `v3_addr.c`, which this subphase does not own, so the unit rows one table, not two.
* `v3_timespec.c` (**1**: `ossl_v3_time_specification`) -- `src/x509/v3_timespec.rs`, which 10.13 had
  left as the item groups plus a by-name withdrawal of the row and its twelve printers (D455); this
  slice lands the row and the printers.
* `v3_cpols.c` (1: `ossl_v3_cpols`), `v3_skid.c` (1: `ossl_v3_skey_id`), `v3_sxnet.c` (1:
  `ossl_v3_sxnet`).

**What is withheld, by name, with its blocker.** `v3_asid.c`'s three path-validation names
(`asid_validate_path_internal`, `X509v3_asid_validate_path`, `X509v3_asid_validate_resource_set`) and
its `validation_err` macro are withheld whole: they read an `X509_STORE_CTX` (`ctx->chain`,
`ctx->error`, `ctx->error_depth`, `ctx->verify_cb`), and this crate has no layout for
`struct x509_store_ctx_st` -- inventing one in a table unit would be a stub of a Phase-11 type.
`v3_skid.c`'s `s2i_skey_id` is withheld because its `hash` arm reads
`ctx->subject_req->req_info.pubkey` and there is no `X509_REQ`/`X509_REQ_INFO` type (10.14.11), so the
row's `s2i` slot is `None` rather than filled with a hole; `ossl_x509_pubkey_hash` is withheld with
it, since its only in-unit caller is `s2i_skey_id` and its external callers are unlanded (D453's
second withholding reason). `v3_crld.c`, `v3_timespec.c`, `v3_cpols.c` and `v3_sxnet.c` withhold
nothing beyond the array.

**Three divergence rows move with the evidence, not against it.** `forensics/prerequisites.json`'s
`v3_timespec.c` and `v3_crld.c` rows are **retired** (their tables and printers now exist) and its
`v3_skid.c` row is **narrowed** to `ossl_x509_pubkey_hash` alone; the register goes from 17 rows to
15. The prerequisite gate is what forced the edit: it reported all three as
`divergence_record_does_not_match` on the first pipeline run of this slice, and a record that can keep
covering a name the crate has since built is a record that can hide the next one.

**`implemented_surface` moves from 3,784 to 3,878 symbols** (the ninety-four new exports: the
`DIST_POINT_NAME`/`DIST_POINT`/`CRL_DIST_POINTS`/`ISSUING_DIST_POINT`/`OSSL_AA_DIST_POINT` lifecycles,
the `ASRange`/`ASIdOrRange`/`ASIdentifierChoice`/`ASIdentifiers` lifecycles and the six
`X509v3_asid_*` routines, the `CERTIFICATEPOLICIES`/`POLICYINFO`/`POLICYQUALINFO`/`USERNOTICE`/
`NOTICEREF` lifecycles and `X509_POLICY_NODE_print`, the `SXNET`/`SXNETID` lifecycles and the seven
`SXNET_*` routines, `i2s_ASN1_OCTET_STRING`/`s2i_ASN1_OCTET_STRING`, and the eleven `OSSL_*`
time-specification lifecycles). `RT-STORE` stays at **46,024** observations across 109 courts: the
rows are internal data the admitted DSO does not name, so no arm was added that could not name its
subject.

**One defect was introduced by a rewrite and caught by reading the authority back.** The three
modules `v3_crld.rs`, `v3_skid.rs` and `v3_timespec.rs` already existed as tracked modules (the
function-granularity landings of 10.13/10.14.6/D455); the slice's setup truncated them before the
work began, and the transcriptions were then re-derived. `v3_skid.rs` and `v3_timespec.rs` came back
verbatim against the committed text (zero and one non-comment lines respectively), but the
`v3_crld.rs` re-derivation inverted `DIST_POINT_set_dpname`'s `set` argument -- it wrote
`c_int::from(i != 0)` where the authority's `X509_NAME_add_entry(dpn->dpname, ne, -1, i ? 0 : 1)`
(`v3_crld.c:541`) is `i == 0`. The differential court cannot name this row, so nothing but reading
the authority back would have found it; it was found that way and corrected. The lesson is recorded
rather than the mistake: the file was restored to a superset of its committed self with the one
inverted bit fixed, and the `gens = NULL` dead assignment the authority writes is kept under the
crate's existing `#[allow(unused_assignments)]` convention.

**The remaining distance is a number: 22 of the 63 tables** (14 blocked over 8 units, 8
closure-ready over 8 units -- `v3_admis.c`, `v3_pci.c`, `v3_ac_tgt.c`, `v3_attrdesc.c`,
`v3_attrmap.c`, `v3_aaa.c`, `v3_ist.c`, `v3_usernotice.c`), plus D463's 24-name closure over 17
further units; then the array, then `X509_get_ext_d2i` -> `ossl_x509v3_cache_extensions` ->
`PKCS12_parse` -> `store_result.c` / `OSSL_STORE_load` -> the seal.

**The closure-ready table set empties; forty-nine of the sixty-three tables now exist.** The
eighteenth pulled-forward slice took the last eight closure-ready units, one table each, and landed
them whole:

* `v3_admis.c` (`ossl_v3_ext_admission`) -- `src/x509/v3_admis.rs`, four item groups
  (`NAMING_AUTHORITY`, `PROFESSION_INFO`, `ADMISSIONS`, `ADMISSION_SYNTAX`), the two printers and the
  full `get0`/`set0` accessor surface.
* `v3_pci.c` (`ossl_v3_pci`) -- `src/x509/v3_pci.rs`, the `i2r_pci`/`r2i_pci` callbacks and the
  `process_pci_value` helper; the item it rows lives in `v3_pcia.rs`, already landed.
* `v3_ac_tgt.c` (`ossl_v3_targeting_information`) -- `src/x509/v3_ac_tgt.rs`, the six
  `OSSL_*` item groups and the five printers.
* `v3_attrdesc.c` (`ossl_v3_attribute_descriptor`) and `v3_attrmap.c`
  (`ossl_v3_attribute_mappings`) -- twenty-five exports each.
* `v3_aaa.c` (`ossl_v3_allowed_attribute_assignments`) and `v3_usernotice.c`
  (`ossl_v3_user_notice`).
* `v3_ist.c` (`ossl_v3_issuer_sign_tool`) -- an **extension** of the module 10.12 left as the item
  group plus a by-name withdrawal of the row and its two callbacks: this slice lands the row,
  `v2i_issuer_sign_tool` and `i2r_issuer_sign_tool`, and no pre-existing line is removed.

**Nothing beyond the array is withheld, and one divergence row is retired.** These units are
transcribed whole; the only withheld names are `standard_exts[]` and the six `v3_lib.rs` lookup
names (D456). The `v3_ist.c` divergence row in `forensics/prerequisites.json` is retired, taking the
register from 15 rows to **14** -- again the prerequisite gate forced the edit, reporting
`divergence_record_does_not_match` for `ossl_v3_issuer_sign_tool` on the first run.

**`implemented_surface` moves from 3,878 to 4,009 symbols** (+131: forty-six from `v3_admis`'s
accessors and lifecycles, twenty-five each from `v3_attrdesc` and `v3_attrmap`, fifteen each from
`v3_ac_tgt` and `v3_aaa`, five from `v3_usernotice`; `v3_pci` and `v3_ist` add none). `RT-STORE`
stays at **46,024** observations across 109 courts.

**Every closure-ready table unit is now landed, so the next move is the blocked eight.** The 14
remaining withheld tables are exactly the 14 blocked tables over the eight blocked units, and each
is blocked on a name outside the table layer: `v3_addr.c`'s `ossl_v3_addr` on the naming shim
`ossl_asn1_string_set_bits_left` (already landed as `asn1::bitstr::set_bits_left`); `v3_akid.c` on
`AUTHORITY_KEYID_*` (`v3_akeya.c`) and `X509V3_EXT_d2i`; `v3_san.c`'s `ossl_v3_alt` on
`X509V3_EXT_d2i`/`X509_REQ_get_subject_name`; `v3_authattid.c` on `OSSL_ISSUER_SERIAL_it`
(`x509_acert.c`); `v3_ncons.c`'s three on `OSSL_parse_url` (`http_lib.c`)/`ossl_a2ulabel`
(`punycode.c`); `v3_ocsp.c`'s five on `ocsp_asn.c`; and `v3_rolespec.c` on `ossl_serial_number_print`
(`t_x509.c`). The pivot to those dependencies is the remaining work before the array can be
published, and with it `X509_get_ext_d2i`, `PKCS12_parse` and `OSSL_STORE_load`.

**The blocked-unit pivots begin; fifty-seven of the sixty-three tables now exist and exactly six are
left.** The nineteenth pulled-forward slice took the two blocked units whose closure was one landed
name away, and the five-table OCSP unit `ocsp_asn.c` unblocked:

* `v3_addr.c` (`ossl_v3_addr`) -- `src/x509/v3_addr.rs`, the RFC 3779 IP-address unit: the four item
  groups (`IPAddressRange`, `IPAddressOrRange`, `IPAddressChoice`, `IPAddressFamily`), the
  canonicalisation routines and the `X509v3_addr_*` API. Its only measured blocker,
  `ossl_asn1_string_set_bits_left`, is a **naming difference only** -- it is landed as
  `crate::asn1::bitstr::set_bits_left`, and D463 named this shim. Its three path-validation names
  (`addr_validate_path_internal`, `X509v3_addr_validate_path`, `X509v3_addr_validate_resource_set`)
  are withheld whole with the same blocker `v3_asid.c`'s three have: no `X509_STORE_CTX` layout.
* `v3_rolespec.c` (`ossl_v3_role_spec_cert_identifier`) -- `src/x509/v3_rolespec.rs`, whose blocker
  `ossl_serial_number_print` (`t_x509.c:519-559`) landed alongside it in the existing
  `src/x509/t_x509.rs` (an extension: the file's `X509_signature_dump` is byte-for-byte unchanged).
  `v3_rolespec`'s printer `i2r_OSSL_ROLE_SPEC_CERT_ID` is that blocker's first caller, which is what
  turns the record from "no caller" into a landed function.
* `v3_ocsp.c` (**5** tables: `ossl_v3_ocsp_nonce`, `ossl_v3_ocsp_crlid`, `ossl_v3_ocsp_acutoff`,
  `ossl_v3_ocsp_serviceloc`, `ossl_v3_ocsp_nocheck`) -- `src/ocsp/v3_ocsp.rs`, in the new
  `src/ocsp/` tree whose first unit, `ocsp_asn.c`, landed in this slice too. That unit (135 lines,
  fifteen item groups, seventy-five exports) is the only reason `OCSP_CRLID_it`/`OCSP_SERVICELOC_it`
  exist, and it is what made `v3_ocsp.c` closure-ready.
* `v3_akeya.c` (`AUTHORITY_KEYID_*`) -- `src/x509/v3_akeya.rs`, the item group `v3_akid.c` names.
  Its `AUTHORITY_KEYID_dup` is **not** defined: the authority's `IMPLEMENT_ASN1_FUNCTIONS` emits
  only the `_it`/`_new`/`_free`/`d2i_`/`i2d_` quintet, and the admitted DSO exports no `_dup`.
* `v3_authattid.c` (`ossl_v3_authority_attribute_identifier`) -- `src/x509/v3_authattid.rs`, whose
  one blocker is `OSSL_ISSUER_SERIAL_it`. That accessor is the file-local one in `v3_ac_tgt.rs`
  (the authority's `static_ASN1_SEQUENCE_END`); it was made `pub(crate)` and reached by Rust path,
  which is the whole of the change to that file.

**`implemented_surface` moves from 4,009 to 4,133 symbols** (+124: the `ocsp_asn.c` seventy-five, the
`v3_addr` item groups and `X509v3_addr_*` API, the `AUTHORITY_KEYID_*` five, the
`OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX` five and the `v3_rolespec` ten). `RT-STORE` stays at **46,024**
observations across 109 courts; the new rows are internal data the admitted DSO does not name.

**One divergence row is narrowed, not retired.** `t_x509.rs`'s row covered
`ossl_serial_number_print` and `ossl_x509_print_ex_brief`; the first is now built, so the row is
narrowed to the second with its blocker (the Phase-11 object layer). The register stays at 14 rows.

**Exactly six tables are left, over four units**, and each is blocked on a unit rather than a table:
`v3_akid.c` and `v3_san.c`'s `ossl_v3_alt` on `X509V3_EXT_d2i` (the `v3_lib.c` dispatch, which needs
the published array) and, for `v3_san`, `X509_REQ_get_subject_name` (`x509_req.c`); `v3_ncons.c`'s
three on `OSSL_parse_url` (`http_lib.c`)/`ossl_a2ulabel` (`punycode.c`); and `ct_x509v3.c` on the
`SCT_LIST_*`/`SCT_set_source` CT units. The next slices are those dependencies; the array and
`X509_get_ext_d2i` come after them, and `PKCS12_parse`/`OSSL_STORE_load` after that.

**The last dependencies land and the name-constraint tables close; sixty-one of the sixty-three
tables now exist.** The twentieth pulled-forward slice took the units the last four unlanded tables
were blocked on, and three of those tables with them:

* `crypto/punycode.c` (316 lines) landed whole into `src/punycode.rs`
  (`ossl_punycode_decode`, `ossl_a2ulabel` and the four `static` helpers) -- the `ossl_a2ulabel`
  `v3_ncons.c` names.
* `crypto/http/http_lib.c`'s **`OSSL_parse_url`** landed into `src/http/http_lib.rs` with its four
  `static` helpers. The rest of the unit is withheld **by name** with its reason: `OSSL_HTTP_parse_url`
  (its only callers are the HTTP transport entry points this crate does not fabricate),
  `use_proxy` and `OSSL_HTTP_adapt_proxy` (a proxy resolved from the process environment for that
  same transport). This crate does not invent a network stack to make a table land.
* `crypto/ct/` -- the whole Certificate Transparency tree, nine units (2,053 lines), landed into the
  new `src/ct/`: `ct_b64.c`, `ct_log.c`, `ct_oct.c`, `ct_policy.c`, `ct_prn.c`, `ct_sct.c`,
  `ct_sct_ctx.c`, `ct_vfy.c` and `ct_x509v3.c` (the `ossl_v3_ct_scts` table, three rows). Fifty-nine
  exports, forty-four raise sites all read from `cterr.h`. One export is withheld with its blocker:
  `CTLOG_STORE_load_default_file`, whose default path is built from the admitted build's **forensic**
  `OPENSSLDIR` and so belongs to Phase 16, exactly as the four withheld `x509_def.c` names do.
* `crypto/x509/v3_ncons.c` (`ossl_v3_name_constraints`, `ossl_v3_holder_name_constraints`,
  `ossl_v3_delegated_name_constraints`) -- `src/x509/v3_ncons.rs`, transcribed whole now that
  `OSSL_parse_url` and `ossl_a2ulabel` exist. It has no `X509_STORE_CTX` surface, so nothing else
  waits.

**`implemented_surface` moves from 4,133 to 4,201 symbols** (+68) and the docs gate caught one stale
count: `docs/CI.md`'s `internal_symbols.c_style` figure was tied to the live atlas, so it moved from
479 to 481 and was corrected rather than exempted. `RT-STORE` stays at **46,024** observations across
109 courts.

**Exactly two tables are left, `ossl_v3_akey_id` (`v3_akid.c`) and `ossl_v3_alt` (`v3_san.c`)**, and
they are the two that need `X509V3_EXT_d2i` -- the `v3_lib.c` dispatch, which searches the
`standard_exts[]` array this whole layer exists to publish. `v3_san.c` additionally needs
`X509_REQ_get_subject_name`. The order is therefore forced and is the endgame: the array and the six
lookup names land with these two tables and the dispatch, and then `X509_get_ext_d2i`,
`ossl_x509v3_cache_extensions`, `PKCS12_parse` and `OSSL_STORE_load` follow.
