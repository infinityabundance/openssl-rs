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
