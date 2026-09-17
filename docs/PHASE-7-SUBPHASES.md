# Phase 7 — the EVP framework, as subphases

## 0. What this stratum is, and what it is not

Phase 7 is the **algorithm-independent** half of `libcrypto`'s public surface: the fetch
layer that turns a name and a property query into a method, the method stores and their
caches, the `EVP_*` object families that hold a method plus its parameters, and the
`EVP_PKEY` layer that is those objects bound to a key. Nine hundred and twenty-four exports
are assigned to it by `forensics/atlas/symbol-ownership.json`, plus twenty-six that Phase 5
handed over — nine hundred and fifty rows in total.

It is **not** the algorithms. AES, SHA, RSA, the KDFs' actual derivations, the MACs' actual
compressions and the signature schemes' arithmetic are Phase 8's, Phase 9's and Phase 13's.
What Phase 7 owns is the machinery every one of them is *reached through*, which is why it
comes first and why the plan's own phase order puts it here.

Two consequences are worth stating before the subphase table, because both are easy to get
wrong in a plan:

* **Phase 7 owns glue that lives in other directories.** `crypto/asn1/ameth_lib.c`'s
  twenty-six `EVP_PKEY_ASN1_METHOD` accessors, `crypto/asn1/i2d_evp.c`, `d2i_pr.c`,
  `d2i_param.c`, `d2i_pu.c` and `crypto/pem/pem_pkey.c`'s eight are declared in `evp.h`, so
  the atlas gives them to this stratum even though their translation units are Phase 5's and
  Phase 11's. That is the atlas's rule working: ownership follows the *header that promises
  the symbol*, not the directory it was written in. The subphase table says so per row rather
  than leaving a reader to be surprised by `src/evp/` holding ASN.1 glue.
* **Phase 7 owns wrappers whose primitives are later strata's.** `crypto/evp/e_des.c`,
  `e_rc4.c`, `e_rc2.c`, `e_idea.c`, `e_cast.c`, `e_seed.c`, `e_bf.c`, `e_sm4.c`,
  `legacy_md4.c`, `legacy_md5.c`, `legacy_sha.c`, `legacy_ripemd.c`, `legacy_blake2.c`,
  `legacy_mdc2.c`, `legacy_wp.c` are `EVP_des_cbc()`, `EVP_sha256()` and their siblings —
  declared in `evp.h`, so Phase 7's — while the ciphers and digests they name are Phase 13's.
  Those rows are **hand-offs with the dependency named**, in this ledger and not in a
  different one, because a stratum that owns a symbol and does not build it owes the reason.

## 1. The measurement this plan rests on

The authority's build tree holds one `.o` per translation unit per form
(`libcrypto-shlib-<stem>.o`), so which unit defines which export is a **measurement** and not
an inference. Listing every `libcrypto-shlib-*.o` under
`forensics/authorities/build/openssl-3.6.4-production` and intersecting each one's defined
externals with the atlas's Phase 7 set places **924 of 924** — no export in this stratum is
unaccounted for by a translation unit. The largest are:

| unit | Phase 7 exports | unit | Phase 7 exports |
|---|---|---|---|
| `crypto/evp/pmeth_lib.c` | 98 | `crypto/evp/kdf_lib.c` | 17 |
| `crypto/evp/evp_lib.c` | 97 | `crypto/evp/kem.c` | 17 |
| `crypto/evp/p_lib.c` | 74 | `crypto/evp/pmeth_gn.c` | 14 |
| `crypto/evp/evp_enc.c` | 45 | `crypto/evp/legacy_sha.c` | 13 |
| `crypto/evp/e_aes.c` | 38 | `crypto/evp/s_lib.c` | 13 |
| `crypto/evp/signature.c` | 30 | `crypto/evp/e_des3.c` | 13 |
| `crypto/evp/evp_rand.c` | 30 | `crypto/evp/keymgmt_meth.c` | 13 |
| `crypto/evp/digest.c` | 29 | `crypto/evp/encode.c` | 12 |
| `crypto/evp/e_aria.c` | 27 | `crypto/hmac/hmac.c` | 12 |
| `crypto/asn1/ameth_lib.c` | 26 | `crypto/evp/skeymgmt_meth.c` | 11 |
| `crypto/evp/e_camellia.c` | 21 | `crypto/evp/mac_meth.c` | 10 |
| `crypto/hpke/hpke.c` | 20 | `crypto/evp/m_sigver.c` | 10 |
| `crypto/evp/mac_lib.c` | 19 | `crypto/evp/kdf_meth.c` | 9 |
| `crypto/evp/cmeth_lib.c` | 18 | `crypto/cmac/cmac.c` | 9 |
| `crypto/evp/asymcipher.c` | 17 | `crypto/evp/names.c` | 8 |
| `crypto/evp/exchange.c` | 17 | `crypto/evp/evp_pbe.c` | 8 |
| | | `crypto/pem/pem_pkey.c` | 8 |

and the remainder is forty-odd units of one to seven exports each. **The count is a
measurement, not a plan:** the plan below groups them by *dependency*, and the subphase
boundaries are drawn where a build can be verified rather than where the file list happens
to break.

By declaring header the stratum is: `evp.h` 843, `kdf.h` 40, `hpke.h` 20, `hmac.h` 12,
`cmac.h` 9. By library: `libcrypto` 924, `libssl` 0 — Phase 7 adds nothing to `libssl`.

### The twenty-six hand-offs arriving from Phase 5

Three are `asn1.h`'s (`ASN1_item_sign_ex`, `ASN1_item_verify_ex` and one more) and
twenty-three are `pem.h`'s, each recorded by Phase 5 with its own reason: a PEM function that
tests a name against `EVP_PKEY_asn1_find_str`, or takes an `EVP_CIPHER` and derives a key
with `EVP_BytesToKey`, cannot be written before the EVP framework exists. Both strata's
ledgers carry the edge, and `ownership_audit.py` reconciles the two readings in both
directions, so an edge recorded on one side only fails the audit.

### The two deferrals this stratum discharges on arrival

`crypto/core_algorithm.c`'s `ossl_algorithm_do_all` and `crypto/core_fetch.c`'s
`ossl_method_construct` are in `forensics/prerequisites.json` as owed to Phase 7 (D132, D134).
They are **7.1's first work**, because nothing in this stratum can be written above them: the
fetch path is what every `EVP_*` object is built on, and they could not be written in Phase 6
because their only caller is Phase 7's own `evp_fetch.c`.

## 2. The subphases

Ordering is by dependency, and each row's dependency column was read from the authority's
calls rather than from the export list — the method D114, D118 and D122 established.

| # | Subphase | Owns | Depends on | Court | Exit criterion |
|---|---|---|---|---|---|
| 7.0 | **The ledger, and the stratum's wiring** | nothing in the crate — evidence | 6 | — | `forensics/phase7-obligations.py` exists and every one of the 950 rows (924 atlas-owned, 26 handed in) has a disposition; `ownership_audit.py` reads it; `phase_state.py` derives Phase 7's state from it; `docs/PHASE-7-SUBPHASES.md` is this file |
| 7.1 | **The fetch core** | `crypto/core_algorithm.c` whole (`ossl_algorithm_do_all`, `ossl_algorithm_get1_first_name`); `crypto/core_fetch.c` whole (`ossl_method_construct`); **`crypto/property/property.c`'s remainder** — the `OSSL_METHOD_STORE` object itself: `ossl_method_store_new`, `_free`, `ossl_method_lock_store`, `ossl_method_unlock_store`, `_add`, `_remove`, `_remove_all_provided`, `_fetch`, `_do_all`, `_cache_flush_all`, `_cache_get`, `_cache_set`, their twelve privates (`ossl_method_store_retrieve`/`_insert`, `ossl_method_cache_flush`/`_flush_alg`/`_flush_some`, `ossl_method_up_ref`/`_free`, `query_hash`/`query_cmp`, `impl_free`/`impl_cache_free`/`impl_cache_flush_alg`/`alg_cleanup`/`alg_cleanup_by_provider`/`alg_do_one`/`alg_copy`/`del_tmpalg`, and the property lock trio), the three types the store is made of (`ALGORITHM`, `IMPLEMENTATION`, `QUERY`) with their `DEFINE_LHASH_OF_EX`/`DEFINE_STACK_OF`/`DEFINE_SPARSE_ARRAY_OF` expansions, and the three global-properties functions 6.7a left (`ossl_ctx_global_properties`, `ossl_global_properties_no_mirrored`, `ossl_global_properties_stop_mirroring`) | 6 | `RT-FETCH` | **PARTLY LANDED (D139, D141).** `crypto/core_algorithm.c` is transcribed whole in `src/evp/algorithm.rs`: `ossl_algorithm_do_all`, `algorithm_do_this` and `algorithm_do_map`, with the three return conventions kept apart because two of them read like errors and are not, and with `OSSL_ALGORITHM` completed in `src/provider/activate.rs` where Phase 6 declared it. `crypto/core_fetch.c` is transcribed whole in `src/evp/method_store.rs` — `ossl_method_construct` and its five callbacks — and its two `ERR_raise` coordinates are registered. **D132's deferral is discharged and its row removed from `forensics/prerequisites.json`**, and so is `ossl_method_construct`'s, so the gate's blocking list goes 15 to 14 and then holds: the fifteen store names 6.7c's row promised were recorded against **Phase 6**, which is complete, and D141 retargets them here, which is why the list rises to 28 rather than falling to 13. **D142 then lands the store's object layer and retires eleven of the fifteen rows**, which takes the list to 17 with only the query path's four left. **The unit in this row was wrong until D141** and is corrected above: the `ossl_method_store_*` family is `crypto/property/property.c`'s and not `crypto/evp/evp_fetch.c`'s — that file *calls* them — and there is no `ossl_method_store_num`, nor any `opbits` in the store. Still open: `ossl_method_store_fetch`, the cache's `_cache_get`/`_cache_set`/stochastic flush, and `_do_all`. The court lands with them |
| 7.2 | **The fetch surface and the default properties** | `crypto/evp/evp_fetch.c`'s remaining ten internals and the eight names Phase 3 and 4 deferred here: `evp_generic_fetch`, `evp_generic_fetch_from_prov`, `evp_generic_do_all`, `evp_names_do_all`, `evp_is_a`, `evp_set_default_properties_int`, `evp_get_global_properties_str`, `evp_default_properties_enable_fips_int`; `crypto/evp/names.c` whole | 7.1 | `RT-FETCH` (extended) | **LANDED (D145, D146).** The default-property half and the fetch half are both transcribed: four exports, the six `mcm` callbacks, `inner_evp_generic_fetch`, `evp_generic_fetch`, `evp_generic_fetch_from_prov`, `evp_generic_do_all`, `evp_is_a`, `evp_names_do_all` and `ossl_lib_ctx_get_descriptor`. All five of this stratum's remaining deferrals are discharged, so the gate's blocking list is 15 -> 5 and **no Phase-7 name blocks anything**. **The exit criterion above cannot be met in 7.2, and the reason is a dependency rather than an omission.** "A property query selects and rejects algorithms through the real fetch path" needs a *class* to fetch through: `evp_generic_fetch` is internal, `libcrypto.ld` hides it, and a probe compiled against installed headers reaches the fetch path only through `EVP_MD_fetch` and its siblings — which are 7.3's, because they need the `EVP_MD` object. So the resolver (a provider publishing an algorithm, a query that selects it and a query that rejects it) lands with 7.3's first slice, in the same commit that makes `EVP_MD_fetch` exist, rather than as a claim this subphase cannot support. `RT-FETCH` already carries the part that *is* observable here: the store's shape in the index table, the two provider bridges that delegate into it, and the whole default-property surface — 38 observations, zero residuals
| 7.3 | **The symmetric method objects** | `crypto/evp/evp_enc.c`, `evp_lib.c`, `digest.c`, `cmeth_lib.c`, `mac_lib.c`, `mac_meth.c`, `kdf_lib.c`, `kdf_meth.c`, `skeymgmt_meth.c`, `evp_rand.c`, `e_old.c`, `c_allc.c`, `c_alld.c`, `evp_err.c`, `crypto/evp/names.c`; the legacy wrappers `crypto/evp/e_aes.c`, `e_aria.c`, `e_camellia.c`, `e_des3.c`, `e_sm4.c`, `e_des.c`, `e_rc2.c`, `e_rc4.c`, `e_idea.c`, `e_cast.c`, `e_seed.c`, `e_bf.c`, `e_null.c`, `e_xcbc_d.c`, `e_aes_cbc_hmac_sha1.c`, `e_aes_cbc_hmac_sha256.c`, `e_chacha20_poly1305.c`, `e_rc4_hmac_md5.c`, `legacy_md4.c`, `legacy_md5.c`, `legacy_sha.c`, `legacy_ripemd.c`, `legacy_blake2.c`, `legacy_mdc2.c`, `legacy_wp.c` — those whose primitives are Phase 13's are **handed on with the dependency named**, in this ledger | 7.2 | `RT-EVP-CIPHER`, `RT-EVP-MD` | **7.3a is the slice that unblocks the fetch court, and it is named here so it is not discovered.** `crypto/evp/digest.c`'s `evp_md_new`, `evp_md_from_algorithm` (the whole `OSSL_DISPATCH` walk, `set_legacy_nid` and `evp_md_cache_constants`), `evp_md_up_ref`, `evp_md_free`, `crypto/evp/evp_lib.c`'s `evp_md_free_int`, `crypto/evp/evp_utils.c`'s `evp_do_md_getparams`, the `EVP_MD` struct from `include/crypto/evp.h` with the fifteen `OSSL_FUNC_digest_*` types, and the three exports `EVP_MD_fetch`, `EVP_MD_free`, `EVP_MD_up_ref` — that is what makes the generic fetch path reachable from a probe, and with it the **negative-selection** observation 7.2's row names. `evp_md_cache_constants` is the reason the court's provider must publish `OSSL_FUNC_DIGEST_GET_PARAMS`: a digest whose `get_params` does not answer `OSSL_DIGEST_PARAM_BLOCK_SIZE` and `OSSL_DIGEST_PARAM_SIZE` fails the fetch with `EVP_R_CACHE_CONSTANTS_FAILED`, which is a contract fact rather than a probe detail. The rest of the row — the contexts, the ciphers, the legacy wrappers — follows 7.3a and is unchanged
| 7.4 | **The `EVP_PKEY` layer** | `crypto/evp/p_lib.c`, `pmeth_lib.c`, `pmeth_check.c`, `pmeth_gn.c`, `p_legacy.c`, `evp_pkey.c`, `evp_key.c`, `evp_pbe.c`, `p5_crpt.c`, `p5_crpt2.c`, `pbe_scrypt.c`, `p_seal.c`, `p_sign.c`, `p_verify.c`, `p_enc.c`, `p_dec.c`, `p_open.c`, `m_sigver.c`, `signature.c`, `asymcipher.c`, `kem.c`, `exchange.c`, `keymgmt_meth.c`, `keymgmt_lib.c`, `ec_support.c`, `dh_support.c`, `evp_pkey_type.c`, `evp_cnf.c`, `ctrl_params_translate.c`; and the `asn1.h` glue that lives outside the directory — `crypto/asn1/ameth_lib.c`, `i2d_evp.c`, `d2i_pr.c`, `d2i_param.c`, `d2i_pu.c` | 7.3 | `RT-EVP-PKEY` | `EVP_PKEY` holds a key from a provider, its `EVP_PKEY_ASN1_METHOD` glue is reachable, and the key's parameters round-trip through `ctrl_params_translate` |
| 7.5 | **The BIO, encoding and PEM bridges** | `crypto/evp/bio_enc.c`, `bio_b64.c`, `bio_md.c`, `bio_ok.c`, `encode.c`, `s_lib.c`; and the twenty-six hand-offs from Phase 5 — the twenty-three `pem.h` ones (`crypto/pem/pem_pkey.c`, `pem_pk8.c`) and the three `asn1.h` ones | 7.4 | `RT-EVP-BIO`, `RT-EVP-PEM` | the PEM and ASN.1 surface that deferred its EVP dependency to this stratum is implemented, and the hand-off edges on both sides are discharged. **LANDED (D194).** Twenty-six exports across `src/evp/encode.rs` (the twelve `EVP_Encode*`/`EVP_Decode*`/`EVP_ENCODE_CTX_*` names of `encode.c`), `src/evp/bio_enc.rs` (`BIO_f_base64`, `BIO_f_cipher`, `BIO_f_md`, `BIO_set_cipher` — the three single-export files `bio_b64.c`/`bio_md.c`/`bio_ok.c` land in the module their one shared `BIO_METHOD` struct belongs to) and `src/evp/pem_bridge.rs` (ten `PEM_*` names of `pem_lib.c`/`pem_sign.c`/`pem_oth.c`). Twenty-six do not and each names its blocker: `BIO_f_reliable` on `RAND_bytes` (Phase 9, `bio_ok.c:456`), and twenty-five `PEM_*` on `EVP_md5` (8, Phase 13), `OSSL_ENCODER_*`/`OSSL_DECODER_*` (15, Phase 10), `EVP_read_pw_string_min` (1, Phase 13 `UI`) and `evp_pkey_copy_downgraded` (1, Phase 8). `s_lib.c` is 7.3f's work and contributes nothing. Of the twenty-six hand-offs, nine land and seventeen are withheld with their blockers named; `ownership-audit.json` reads the Phase-5→7 edge with `mismatched: 0`, which is the exit criterion's "both sides" |
| 7.6 | **The MAC, KDF and HPKE header surfaces** | `crypto/hmac/hmac.c`'s twelve, `crypto/cmac/cmac.c`'s nine, `crypto/hpke/hpke.c`'s twenty, and the `kdf.h` remainder | 7.3 | `RT-HMAC`, `RT-CMAC`, `RT-HPKE` | the three header surfaces are implemented against the `EVP_MAC`/`EVP_KDF` objects 7.3 built, and each court observes its own surface rather than the shared machinery. **LANDED (D195).** Forty exports: twelve in `src/mac/hmac.rs`, nine plus the `include/crypto/cmac.h` internal `ossl_cmac_init` in `src/mac/cmac.rs`, and nineteen in `src/hpke/mod.rs`. One is withheld with its blocker named: `OSSL_HPKE_get_grease_value` on `RAND_bytes_ex` (Phase 9, `hpke.c:1433`). The `kdf.h` remainder contributes nothing — its forty names were already discharged and its `open` list is empty. The row's `EVP_AEAD` premise is false as measured, and D195 records the measurement. The three courts observe 32, 26 and 65 observations with zero residuals. |
| 7.7 | **The seal** | nothing in the crate — evidence | 7.0–7.6 | — | `docs/PHASE-7-EVP-SEAL.md`: zero open obligations, every court passing, the prototype court clean, **the dispatch plane clean** (`forensics/tools/dispatch_court.py`, D180 — it is not a stratum and has no row of its own, but it is the only instrument that reaches the `OSSL_FUNC_*` identities and callback signatures, and its first run found thirteen disagreeing declarations in landed code), the prerequisite gate and the plan reconciliation at zero findings, the FRF receipts and the Gemel checkpoint. **LANDED (D196).** The ledger reads zero open and the stratum derives `complete` in `forensics/phase-state.json`; the fifteen courts are `all_pass` with zero residuals; `prerequisite-gate.json`, `plan-reconciliation.json`, `prototype-court.json` and `dispatch-court.json` all read zero findings; the seal names the stratum's 244 deferrals by phase, its three registered divergences and D163–D196's entries. The plan's `crypto/evp/legacy_cipher.rs`, `legacy_digest.rs` and `params_translate.rs` were evidence-list entries for files that were never created, and D196 removes them from the phase-state evidence rather than creating empty modules to satisfy a list. The FRF half is vacuous by the convention `forensics/tools/gen_frf_courts.py`'s table records and `--check` enforces: it covers the Phase 3–6 runtime courts (43 declarations, `PEM_SignInit`'s three among them by their Phase-5 rows) and no Phase-7 court is declared, so this stratum has no FRF receipts; its evidence is `artifacts/phase7/COURTS.json`. |

Each row is a *dependency-ordered* boundary and not a size boundary. Three of them will
almost certainly split as they land — 7.3 and 7.4 are each over two hundred exports — and the
precedent from Phase 6 is that a split is recorded here with the reason it was needed rather
than performed silently.

### 7.4's dependency set was wrong, and it is the largest inversion found so far

**D163.** The row above says 7.4 depends on 7.3. Reading its calls says otherwise: **7.4's legacy
registry half depends on Phase 8**, and one unit of it on Phase 11. Nothing in the tooling could
have said so, and the reason is the blind spot `a2d_ASN1_OBJECT` exposed in the other direction —
the prerequisite gate fires on a name only when the crate has a module for the *defining* unit, so a
call into `crypto/rsa/rsa_pmeth.c` is invisible until `rsa_pmeth.c` itself is transcribed. The two
tables are where the dependency lives:

```text
crypto/evp/pmeth_lib.c      standard_methods[]  ->  ossl_rsa_pkey_method   (crypto/rsa/rsa_pmeth.c)
                                                    ossl_dh_pkey_method    (crypto/dh/dh_pmeth.c)
                                                    ossl_dsa_pkey_method   (crypto/dsa/dsa_pmeth.c)
                                                    ossl_ec_pkey_method    (crypto/ec/ec_pmeth.c)
                                                    ossl_rsa_pss_pkey_method
                                                    ossl_dhx_pkey_method
                                                    ossl_ecx25519_pkey_method   (crypto/ec/ecx_meth.c)
                                                    ossl_ecx448_pkey_method
                                                    ossl_ed25519_pkey_method
                                                    ossl_ed448_pkey_method
crypto/asn1/ameth_lib.c     standard_methods[]  ->  ossl_rsa_asn1_meths[0..1]   (crypto/rsa/rsa_ameth.c)
  (via crypto/asn1/standard_methods.h)             ossl_dh_asn1_meth            (crypto/dh/dh_ameth.c)
                                                   ossl_dsa_asn1_meths[0..3]    (crypto/dsa/dsa_ameth.c)
                                                   ossl_eckey_asn1_meth         (crypto/ec/ec_ameth.c)
                                                   ossl_rsa_pss_asn1_meth
                                                   ossl_dhx_asn1_meth
                                                   ossl_ecx/ed*_asn1_meth       (crypto/ec/ecx_meth.c)
                                                   ossl_sm2_asn1_meth
```

Both tables are **Phase 8's contents**: they *are* the algorithm strata's method objects, and the
plan already says as much in 7.3g's row for the legacy wrappers. So the subtree of 7.4 reachable only
through them — `evp_pkey_type.c` (`EVP_PKEY_type` → `EVP_PKEY_asn1_find`; the profile defines no
`OPENSSL_NO_DEPRECATED_3_6`, so the ameth branch is the one compiled), `p_lib.c`'s `pkey_set_type`
and `find_ameth`, `pmeth_lib.c`'s whole `EVP_PKEY_meth_*`/`EVP_PKEY_asn1_*` registry, `p_legacy.c`,
`ec_support.c`, `dh_support.c` (the last two need Phase 8's `EC_KEY`/`DH` *types*) — **cannot be
transcribed before Phase 8**. And `evp_cnf.c`, before Phase 11: its module callback reads the
configuration through `X509V3_get_value_bool`.

**The measurement that makes this actionable rather than blocking.** Implementing one export of a
unit makes the gate owe that unit's **header-declared internals** — not its file-local statics, which
is what I had assumed and which would have made every one of these units atomic. It is exactly seven
for `p_lib.c`, and they are the seven functions `include/crypto/evp.h` declares:

```text
evp_pkey_copy_downgraded   evp_pkey_export_to_provider   evp_pkey_free_legacy
evp_pkey_get0_DH_int       evp_pkey_get_legacy           evp_pkey_name2type
evp_pkey_type2name
```

Six of those seven are the legacy half and are Phase 8's at the granularity of their *callers*; the
seventh, `evp_pkey_export_to_provider`, is the provider half. **Executing that disposition is
D164**, and it came out at four rows naming Phase 8, one owed to 7.4c inside this stratum, and two
landed: `evp_pkey_type2name` is complete outright, and `evp_pkey_name2type` has its table half
landed with the `EVP_PKEY_type` fallback waiting on the same Phase-8 hand-off row 7.4l already
names. So the provider half of `p_lib.c` lands with the rows recorded, and the gate's blocking
census then *says* what is owed instead of hiding it. That is the disposition 7.3g used for its one
hundred and sixty-four legacy statics, at the granularity of the names a header promises.

**What this means for the order.** 7.4 lands provider-side first and in this order, each row a unit
or a named half of one:

| # | Land | Blocked half |
|---|---|---|
| 7.4a | the `EVP_PKEY` object's provider attributes and lifetime (`p_lib.c`'s provider paths), `keymgmt_lib.c` whole, the rows above | `pkey_set_type`/`find_ameth`, `evp_pkey_get_legacy`/`_free_legacy`/`_copy_downgraded`/`get0_DH_int`, `evp_pkey_export_to_provider` (7.4c), both registries |
| 7.4b | the five method-object families — `signature.c`, `asymcipher.c`, `kem.c`, `exchange.c`, `keymgmt_meth.c` — with their `EVP_PKEY_*` operations, minus `keymgmt_meth.c`'s `legacy_alg` fill | `keymgmt_meth.c`'s `get_legacy_alg_type_from_keymgmt` (→ `evp_pkey_name2type` → `EVP_PKEY_type`) |
| 7.4c | `pmeth_lib.c`'s `EVP_PKEY_CTX` object and its accessors, `pmeth_check.c`, `pmeth_gn.c`, `m_sigver.c` (**LANDED, D191**), `evp_pbe.c` and the five `p5_*`/`pbe_*` units (**LANDED, D192**) | `EVP_PKEY_meth_*`, `EVP_PKEY_asn1_*`, `EVP_PKEY_CTX_new`/`_new_id` (the legacy-typed constructors) |
| 7.4e | **`p_lib.c`'s provider half, the five `EVP_PKEY_CTX_*` accessors beside it, and `EVP_PKEY_Q_keygen`** — the four cache-backed getters, `missing_parameters`/`copy_parameters`/`can_sign`/`get_base_id`/`get0`, both type setters, `get_group_name`, both encoded-public-key halves, the four `EVP_PKEY_new_raw_*` constructors with the shared `new_raw_key_int` under them, `new_CMAC_key`, both default-digest accessors, the variadic generator with its C shim, and `evp_lib.c`'s `set_group_name`/`get_group_name`/`set_algor_params`/`get_algor_params` with `signature.c`'s `set_signature` (**LANDED, D190**) | `EVP_PKEY_digestsign_supports_digest` (→ `EVP_DigestSignInit_ex`, `m_sigver.c`, 7.4's own remaining work), `EVP_PKEY_type` (7.4l), the six `print_*` (→ `encoder.h`, Phase 10), the twenty legacy key accessors (→ Phase 8's key types), the two engine accessors (→ Phase 13), `EVP_PKEY_CTX_get_algor` (→ `d2i_X509_ALGOR`, Phase 11) |
| 7.4l | — **the two `standard_methods[]` tables and the exports that read them**, per symbol and not per unit (D165): `EVP_PKEY_type`, the six in `p_legacy.c`, the twelve in the `i2d_*`/`d2i_*` units, the `asn1_find`/`asn1_get0`/`asn1_get_count` half of `ameth_lib.c`, and `EVP_PKEY_meth_find`/`_get0`/`_get_count` in `pmeth_lib.c` (**PARTIAL, D193** — the *ten* that read no table land in `src/evp/p_legacy.rs`) | `EVP_PKEY_type`, `EVP_PKEY_meth_find`/`_get0`/`_get_count` (→ the two `standard_methods[]` tables, Phase 8); the twelve `d2i_*`/`i2d_*` (→ `OSSL_DECODER_*`/`OSSL_ENCODER_*`, Phase 10, and the ameth table, Phase 8); `ASN1_item_sign_ex`/`_verify_ex` (→ `ASN1_item_sign_ctx`/`_verify_ctx`, Phase 11); `EVP_SealInit` (→ `RAND_priv_bytes_ex`, Phase 9); `EVP_read_pw_string`/`_min` (→ `UI`, Phase 13) |
| 7.4n | `evp_cnf.c` — **held for Phase 11** (`X509V3_get_value_bool`) | — |

**`ctrl_params_translate.c` is one unit and it is sliced by its own structure, not by size (D187).**
The file is 2,959 lines and every export in it is in its last 400: the type layer and the ~40
`fixup_args` functions are dead weight until the two translation tables and the seven entry points
exist, and the tables reference the fix functions, so nothing in the file is observable until the whole
of it is. That is the opposite of the `EVP_PKEY_METHOD` registry, whose forty accessors each export on
their own, and it is why this row's remaining work is one commit and not five. The slices, in order,
for a reader who has to stop early: (1) the type layer — `enum state`'s ten values, `enum action`'s
three, `struct translation_ctx_st` and `struct translation_st`; (2) `default_check`,
`default_fixup_args` and `cleanup_translation_ctx`, which are the file's core and are called by every
table entry; (3) the ~40 `fix_*` / `get_payload_*` functions; (4) `evp_pkey_ctx_translations[]` and
`evp_pkey_translations[]`, which are ~520 lines of designated initialisers; (5) the seven entry points
and the exports. Every helper they need is already in the crate — the twelve `OSSL_PARAM_construct_*` /
`get_*` / `set_*` functions, `OSSL_PARAM_allocate_from_text`, `BN_bn2nativepad`, `BN_num_bytes`,
`EVP_PKEY_CTX_settable_params`, the six `EVP_PKEY_CTX_IS_*_OP` tests, and `raise_site_data` for the
`ERR_raise_data` sites — which is what makes the unit transcribable rather than blocked.

7.4a is not a size boundary either: it is the whole of `keymgmt_lib.c` plus the provider paths of
`p_lib.c`, and the rows above are what keep it honest while the rest of that unit waits. Its first
slice — `keymgmt_meth.c` whole and `p_lib.c`'s two name walkers — is landed and pushed to the
staging branch, awaiting its court (`RT-EVP-KEYMGMT`) and the `EVP_PKEY` object itself (D164).

**7.4b is sliced by the files' own two halves, and the split is named here rather than performed
silently (D189).** The row above is five method families whose files each contain a *method* half
(the object, its lifetime, the exports that reach it) and an *operation* half (the `EVP_PKEY_*`
entry points over it). The method halves land as **7.4b-i**; the operation halves are **7.4b-ii**
(`asymcipher.c`, landed), **7.4c-i** (`exchange.c` and `kem.c`, landed with the context) and
**7.4d** — `crypto/evp/signature.c`'s entry-point half, the eighteen `EVP_PKEY_sign*`/`verify*`/
`verify_recover*` exports, plus the replay half of the cached-data trio
(`evp_pkey_ctx_use_cached_data`) that is the only internal they owe. 7.4d is landed with its court
`RT-EVP-PKEY` (178 observations, zero residuals) and its finding recorded in D189: `legacy:` does
not reset `ctx->operation`, which is what makes the `algctx == NULL` arm of the three one-shot
entry points reachable from the public API. The remaining 7.4b work is `keymgmt_meth.c`'s
`legacy_alg` fill, which is blocked on `evp_pkey_name2type` and therefore on Phase 8.

**7.4e is the provider half of `p_lib.c` plus the six names that live outside it (D190).**
Twenty-four names were in its row; twenty-three landed in the first pass and the four
`EVP_PKEY_new_raw_*` constructors it had declined landed in the second, so **twenty-seven exports**
are in. The one name that does not land, `EVP_PKEY_digestsign_supports_digest`, is blocked on
`EVP_DigestSignInit_ex` (`m_sigver.c:371`), which is this stratum's own remaining work rather than
another stratum's, so it stays in the ledger's `open` list with no deferral row — a hand-off row
would misname its owner.

**The four declined constructors were declined on a wrong reading, and the correction is recorded
rather than folded away.** The first pass said they were blocked on `EVP_PKEY_asn1_find_str`
(`ameth_lib.c:114`, Phase 8). That is wrong as stated: `new_raw_key_int` (`p_lib.c:416`) calls that
lookup only inside its `#ifndef OPENSSL_NO_ENGINE` block, sets `*pe` from the **engine registry**,
and then **discards** the method the lookup may have returned via `if (tmpe == NULL) ameth = NULL;`.
No ENGINE can be obtained in this crate (`ENGINE` is Phase 13), so `tmpe` is NULL on every path and
`ameth` is NULL for every input — the provider branch is unconditional. The mechanism is Phase 8's;
its *answer* here is the one D181 already sanctions for `EVP_PKEY_get0_asn1`, and the transcription
names it at the site. What the first reading got wrong is the difference between a symbol being
absent and a symbol's answer being constant, and that is the class of finding this project collects.

The slice also found, and the court measured, that `int_ctx_new` rewrites a caller's `"EC"` to
`OBJ_nid2sn(EVP_PKEY_EC)` before fetching, which the authority resolves because its namemap is
pre-populated from the legacy method database (`standard_methods[]`, D109) and the candidate's is
not; the probe publishes its generation key types under the object spellings so that the
`EVP_PKEY_Q_keygen` arms exercise the `va_arg` walk rather than that gap. The same default-context
question decided the two entry points that hardcode `libctx = NULL` (`EVP_PKEY_new_CMAC_key` and the
legacy-type raw constructors): the probe registers its provider in the **default** library context as
well, and the measurement is that the authority's default provider never competes for those names.

**7.4c is closed by D192, and the five `p5_*`/`pbe_*` units are four files plus a whole table.** The
units are `crypto/evp/evp_pbe.c` (eight exports), `crypto/evp/p5_crpt.c` (three, one of them empty),
`crypto/evp/p5_crpt2.c` (six exports and two internals), `crypto/evp/pbe_scrypt.c` (two, landed in
7.4c-ii) and `crypto/asn1/p5_scrypt.c`'s two keygen exports — the fifth unit is not `pbe_scrypt.c`
as the row read, it is `p5_scrypt.c`, whose `PKCS5_v2_scrypt_keyivgen`/`_ex` are declared in `evp.h`
and therefore this stratum's while `PKCS5_pbe2_set_scrypt` and the `SCRYPT_PARAMS_*` accessors in the
same file are Phase 11's. Seventeen exports and two internals land in four new modules
(`src/evp/evp_pbe.rs`, `src/evp/p5_crpt.rs`, `src/evp/p5_crpt2.rs`, `src/evp/p5_scrypt.rs`), the
court is `RT-EVP-PBE` (420 observations, zero residuals), and the one row of the thirty-four-row
`builtin_pbe[]` that cannot name its keygen — the six `PKCS12_PBE_keyivgen` rows — is
`docs/SECURITY_DIVERGENCE_POLICY.md` **D-PBE-PKCS12-KEYGEN-1** rather than an approximation. The
same slice measured **D-EVP-CIPHER-LEGACY-NID-1**, a pre-existing contents boundary in
`EVP_CIPHER_get_nid`, and found a mis-recorded `ERR_raise` line in Phase 5's
`asn1_template_noexp_d2i` that it reports and did not repair.

**The ledger still owes 7.4l, and D165 measured why it is not a table yet.** `EVP_PKEY_type` sits in
`forensics/phase7-obligations.json`'s `open` list while this table hands `evp_pkey_type.c` to Phase 8:
the atlas decides ownership by the declaring header (`evp.h` is this stratum's) and this table decides
when the work can be done. D164 named the mechanical step as a second hand-off table beside
`LEGACY_HANDOFFS` whose rows are the eleven units above. D165 then measured three things that stop it:
the eleven units name **144** Phase-7-owned exports, most of which this stratum can implement (the
`EVP_PKEY_meth_*` accessors are field reads, and handing them to Phase 8 would defer work that belongs
here); a bag-of-identifiers scan over the C bodies flags **98 of 98** of one unit's exports, all of them
wrongly; and the measurement that does work — undefined symbols per object, then relocations paired
with function extents — needs three layers, because the tables' own references are in a data section
and `OSSL_NELEM(standard_methods)` leaves no relocation at all. The row above is therefore written per
symbol, and the tool that generalises it is the next step. A stratum with an `open` symbol it can never
build can never close; a stratum that *defers* what it can build never finishes either, and this is the
direction that would have been silent.

**7.4l executed that per-symbol reading, and ten of the twenty-three landed (D193).** The ten that
read no table are `crypto/evp/evp_key.c`'s three (`EVP_BytesToKey` and the two prompt accessors),
`p_sign.c`'s two, `p_verify.c`'s two, `p_open.c`'s two and `p_seal.c`'s `EVP_SealFinal`; they are in
`src/evp/p_legacy.rs`, which is the ledger's own module name for the eleven `EVP_Sign`/`EVP_Verify`/
`EVP_Open`/`EVP_Seal`/`EVP_BytesToKey`/`EVP_read_pw_string*`/`EVP_get_pw_prompt`/`EVP_set_pw_prompt`
symbols. The thirteen that did not are held with their blockers named, and the families are read
rather than assumed: the two `ASN1_item_*_ex` hand-offs from Phase 5 do not build **because their
delegates** `ASN1_item_sign_ctx`/`ASN1_item_verify_ctx` are `x509.h`'s and Phase 11's, not because
`EVP_DigestSignInit` was missing; the twelve `d2i_*`/`i2d_*` names take the `OSSL_DECODER_*`/
`OSSL_ENCODER_*` branch **first** for a provider key, so Phase 10 blocks them before Phase 8's ameth
table does; `EVP_read_pw_string` is withheld with its `_min` because its whole body is the call, while
`EVP_get_pw_prompt`/`EVP_set_pw_prompt` land because they touch the file's own static and no `UI` at
all. Each withheld name has a `forensics/prerequisites.json` row naming the stratum and the name that
blocks it, a `NOT_MEASURED_…` line in `RT-EVP-PKEY` or `RT-EVP-PBE`, and a paragraph in D193.


### 7.5's row names six units, and two of them are not its work

**D194.** The row above is a file list, and a file list is not a landing plan — `s_lib.c` is the
clearest case. Its exports are the `EVP_SKEY_*` family, 7.3f landed them in `src/evp/skeymgmt.rs`, and
`plan-reconciliation.json` does not census `crypto/evp/s_lib.c` as unreached: the row is
dependency-ordered and that dependency had already arrived. The other five units are `encode.c`'s
twelve names, `bio_enc.c`'s two, and the *three single-export files* `bio_b64.c` (`BIO_f_base64`),
`bio_md.c` (`BIO_f_md`) and `bio_ok.c` (`BIO_f_reliable`). They land in two modules — `src/evp/encode.rs`
and `src/evp/bio_enc.rs` — because a `BIO_METHOD` is a struct of function pointers rather than a set of
entry points, and the four filters share the dispatch kind. The dominant-unit rule then leaves
`bio_b64.c`, `bio_md.c` and `bio_ok.c` in `plan-reconciliation.json`'s `units_not_reached` census while
`encode.c` and `bio_enc.c` leave it, which is the `p_legacy.rs` reading D193 recorded.

**The twenty-six hand-offs are 23 `pem.h` and 3 `asn1.h`, and nine of them land.** The three `asn1.h`
ones are `ASN1_item_sign_ex`, `ASN1_item_verify_ex` (both withheld on Phase 11 by D193) and
`PEM_write_bio_ASN1_stream`, which the brief placed in `bio_asn1.c` and which is `crypto/asn1/asn_mime.c:128`'s
— it builds because everything under it (`BIO_f_base64`, `i2d_ASN1_bio_stream`, `BIO_printf`) is already
in the crate. The other eight that land are `PEM_SignInit`, `PEM_SignUpdate`, `PEM_SignFinal`,
`PEM_read`, `PEM_read_bio`, `PEM_read_bio_ex`, `PEM_write` and `PEM_write_bio`. The remaining seventeen
are withheld with their blockers named, in four families read rather than assumed: `EVP_md5`
(`legacy_md5.c:36`, Phase 13) is the hinge and takes eight names through `PEM_do_header`
(`pem_lib.c:479`); the `OSSL_ENCODER_*`/`OSSL_DECODER_*` branch is taken **first** by a provider key and
takes fifteen (`pem_pkey.c:49`, `pem_local.h:44`, `pem_pk8.c:75`); `EVP_read_pw_string_min`
(`evp_key.c:52`) takes `PEM_def_callback` because it is a `UI` program; and
`evp_pkey_copy_downgraded` (`pem_pkey.c:356`) takes `PEM_write_bio_PrivateKey_traditional`, which reads
the legacy `ameth` before it reads any encoder. `ownership-audit.json`'s `handoff_reconciliation` reads
the Phase-5 → 7 edge with a declared set of all twenty-six and `mismatched: 0`, which is both strata
agreeing and the row's "hand-off edges on both sides" criterion.

**Two arms of the plan's own sentence were false as measured, and the ledger settled both.**
`PKCS5_PBE_add` *is* landed (`src/evp/p5_crpt.rs:167`, by 7.4c) and `PEM_write_bio_PKCS8PrivateKey_nid`
*is not* — it is open, `git grep` finds no definition, and this slice withholds it on Phase 10 with a
`NOT_MEASURED` line. And the twenty-three `pem.h` hand-offs are not all `pem_pkey.c`'s and `pem_pk8.c`'s:
they span `pem_lib.c`, `pem_oth.c`, `pem_sign.c`, `pem_pkey.c` and `pem_pk8.c`.

**The row's court found a defect on its first run, and it is the kind a unit test alone would not
have.** `PEM_get_EVP_CIPHER_INFO` hands `EVP_get_cipherbyname` the `DEK-Info:` name *after* skipping the
whitespace that separates it from the label (`crypto/pem/pem_lib.c:561`, `:567`, `:571`); the
candidate had passed the un-skipped pointer, so `DEK-Info: UNDEF,...` resolved `" UNDEF"` and refused a
header the authority accepts. The fix is one saved pointer, and the arm is now identical on both sides.
The same court is what made the success path reachable at all: `EVP_get_cipherbyname` can only return a
method the legacy `OBJ_NAME` table holds (`crypto/evp/names.c:86`, and the namemap retry ends at the
same table at `:114`), so the probe registers a method of its own with `EVP_CIPHER_meth_new` +
`EVP_add_cipher` — and drives the contrast, because `EVP_CIPHER_fetch` *does* return its provider's
cipher and `EVP_get_cipherbyname` does not.

### 7.3, split — recorded when it was needed, not performed silently

7.3's row is a file list, and a file list is not a landing plan: it mixes four method *classes*
(`EVP_CIPHER`, `EVP_MD`, `EVP_MAC`/`EVP_KDF`, `EVP_RAND`/`EVP_SKEYMGMT`), the shared accessor
half of `evp_lib.c` that serves all of them, and one hundred and seventy-one legacy wrapper
statics whose primitives are Phase 13's. The split below is by *dependency*, so each slice can
be pushed on its own with a court that observes its own new surface, and the counts are the
ledger's own (`forensics/phase7-obligations.json`) on the day the split was made — a census of
what was open then, not a claim about the present.

| # | Subphase | Owns | Depends on | Court | Open at the split |
|---|---|---|---|---|---|
| 7.3a | **The `EVP_MD` object** | `digest.c`'s fetch half, `evp_md_from_algorithm`'s `OSSL_DISPATCH` walk, `evp_md_free_int`, `evp_do_md_getparams`, the struct; `EVP_MD_fetch`/`free`/`up_ref`/`get_type`/`get0_name`/`get_size`/`get_block_size` | 7.2 | `RT-FETCH` (extended) | **LANDED (D148, D149)** |
| 7.3b | **The `EVP_CIPHER` object** | `evp_enc.c`'s method half (`evp_cipher_new`, `evp_cipher_from_algorithm`, `evp_cipher_cache_constants`, `evp_cipher_free`/`_up_ref`), `evp_lib.c`'s `EVP_CIPHER_*` accessors, `cmeth_lib.c` whole; and `e_null.c`'s `EVP_enc_null`, which is the one legacy cipher with no Phase-13 primitive under it and the one a cipher court can resolve | 7.3a | `RT-EVP-CIPHER` | 42 |
| 7.3c | **The `EVP_CIPHER_CTX` and the `EVP_Encrypt`/`EVP_Decrypt` API** (`i` = the context, its parameters and initialisation; `ii` = the twelve exports that move data) | `evp_enc.c`'s remainder: the context, its flags, `EVP_CipherInit*`/`EVP_CipherUpdate`/`EVP_CipherFinal*`, the two `EVP_CipherPipeline*` families and the per-alias spellings of all of them | 7.3b | `RT-EVP-CIPHER` (extended) | 68 |
| 7.3d | **The `EVP_MD` remainder** — its first half (`i`: the accessors, the `meth_*` constructors, `EVP_md_null`) is landed; the `EVP_DigestSign*`/`EVP_DigestVerify*` names its row lists are `m_sigver.c`'s and go to 7.4, which already names that unit | `evp_lib.c`'s `EVP_MD_*` accessors and `EVP_MD_meth_*` constructors, `digest.c`'s context (`EVP_MD_CTX_*`), the one-shot `EVP_Digest*`/`EVP_DigestSign*`/`EVP_DigestVerify*`, `EVP_Q_digest`, `EVP_MD_do_all*`, `EVP_MD_xof`; and `m_null.c`'s `EVP_md_null`, for `EVP_enc_null`'s reason | 7.3a | `RT-EVP-MD` | 80 |
| 7.3e | **`EVP_MAC` and `EVP_KDF`** | `mac_lib.c`, `mac_meth.c`, `kdf_lib.c`, `kdf_meth.c` — the two symmetric method classes whose operations are supplied entirely by a provider. **LANDED (D157, D158).** Both classes are complete, and were written out separately rather than factored: they disagree on `CTX_dup`'s guard, on the structural check's arithmetic, on whether a `reset` exists, and on whether `CTX_new` refuses a NULL method. Their KDF twin found a **reference leak in `EVP_MAC_CTX_new`**, where the authority's `||` short-circuit means the up-ref must not run when `newctx` answers NULL; both copies were fixed and both carry the unit test. `EVP_MAC_init_SKEY` and `EVP_KDF_CTX_set_SKEY`/`_derive_SKEY` were handed forward for want of an `EVP_SKEY` and landed in 7.3f | 7.3d | `RT-EVP-MAC`, `RT-EVP-KDF` | 55 |
| 7.3f | **`EVP_RAND` and `EVP_SKEYMGMT`** | `evp_rand.c`, `skeymgmt_meth.c` **and `s_lib.c`** — the third provider-only class and the fourth, and `s_lib.c` is named here because the atlas assigns ownership by the header that promises a symbol rather than by the directory a file was written in: `EVP_SKEY`'s thirteen exports are `evp.h`'s and the file split is bookkeeping. **LANDED (D159, D160).** `EVP_RAND` is the class whose constructor takes three arguments, whose context is reference counted with a recursive release, and whose two locking counters are independent conditions; `EVP_SKEY` is the first object in this stratum that is not a context, and it owns a reference to its method. The four `*_SKEY` entry points handed forward by 7.3e landed here. `EVP_PKEY_derive_SKEY` is `pkey_derive.c`'s and is 7.4's, with its module named | 7.3e | `RT-EVP-RAND`, `RT-EVP-SKEY` | 54 |
| 7.3g | **`crypto/evp/names.c`, `evp_err.c`, `c_allc.c`, `c_alld.c`, and the legacy wrappers whose primitives are Phase 13's** | the four `EVP_MD_do_all*`/`EVP_CIPHER_do_all*` in `crypto/evp/names.c`, the generated reason table in `evp_err.c`, the three adders, and the one hundred and sixty-eight statics in `e_aes.c`, `e_aria.c`, `e_camellia.c`, `e_des3.c`, `e_sm4.c`, `e_des.c`, `e_rc2.c`, `e_rc4.c`, `e_idea.c`, `e_cast.c`, `e_seed.c`, `e_bf.c`, `e_xcbc_d.c`, `e_aes_cbc_hmac_sha1.c`, `e_aes_cbc_hmac_sha256.c`, `e_chacha20_poly1305.c`, `e_rc4_hmac_md5.c`, `e_old.c`, `legacy_md4.c`, `legacy_md5.c`, `legacy_md5_sha1.c`, `legacy_sha.c`, `legacy_ripemd.c`, `legacy_blake2.c`, `legacy_mdc2.c`, `legacy_wp.c` — **handed to Phase 13 with the dependency named in that stratum's ledger**, because `e_aes.c` calls `AES_encrypt` and its siblings, not a provider | 7.3f | — | 171 |

**LANDED (D161, D162).** The eight exports that need nothing from Phase 13 are implemented — the four `names.c` walkers, `EVP_add_cipher`, `EVP_add_digest`, `EVP_get_cipherbyname` and `EVP_get_digestbyname` with their two internal `_ex` halves — and the remaining **one hundred and sixty-four** rows are handed to Phase 13 with the primitive unit named per family (`crypto/aes/`, `crypto/sha/`, `crypto/md5/`, …), which is what this row always said would happen. `RT-EVP-NAMES` lands with 25 observations.

Two corrections came out of writing it, and both are recorded rather than quietly applied. **`EVP_get_cipherbyname` and `EVP_get_digestbyname` are not hand-offs** (D162): their bodies need nothing Phase 13 has, because the legacy lookup is only the first of three steps, and only their *input table* is another stratum's. **`OPENSSL_INIT_ADD_ALL_CIPHERS` was being refused** (D161), which made `OpenSSL_add_all_algorithms_noconf()` answer 0 where the authority answers 1 — the court found it by reading the error queue after `EVP_CIPHER_do_all`'s own first statement.

`evp_cleanup_int` was owed to **7.4** (`EVP_PBE_cleanup` is `evp_pbe.c`'s) and `EVP_add_alg_module` to **7.4** as well (`X509V3_get_value_bool` is Phase 11's); both were recorded in `forensics/prerequisites.json` rather than stubbed. **Both readings are superseded, and D196 is what settles them.** `EVP_PBE_cleanup` landed with 7.4c's PBE remainder (D192), so `evp_cleanup_int`'s only remaining dependency is its seventh call, `evp_app_cleanup_int`, which is Phase 8's -- the row is retargeted to Phase 8, and `src/evp/legacy_evp.rs`'s module doc says so. `EVP_add_alg_module` is one of the ledger's reasoned deferrals to Phase 11. And `evp_pkey_decrypt_alloc`, the one same-stratum name D193's row left unbuilt, **landed in 7.7** (`src/evp/asymcipher.rs`), so its `forensics/prerequisites.json` row is retired rather than carried.

Two consequences of the split that are worth stating rather than discovering:

* **7.3g is a hand-off, not a deferral of convenience.** Its ledger rows name Phase 13 and the
  primitive unit (`crypto/aes/`, `crypto/des/`, …), which is the same standard the 26 Phase-5
  hand-offs met when they arrived. What can be done here *is* done: the adders, the do-all
  walkers and the two null methods, each of which needs nothing from Phase 13.
* **`EVP_enc_null` and `EVP_md_null` are why the two courts above can exist at all.** A court for
  a method class needs something to resolve through a real provider; these two are the only
  legacy statics in 7.3 that can be built without a Phase-13 primitive, so they land with their
  class rather than with the wrappers they look like they belong to.
* **7.3c splits as *arming* versus *moving data*, and the first version of this note said
  otherwise.** The note first claimed the row does not split, on the argument that a context with
  no cipher answers only its own error paths. That argument is wrong: `EVP_CipherInit_ex` is the
  arming path, it is in the same half, and a context armed through it is observable by every
  accessor, by `dup` and `copy`, and by the parameter round trip. What *is* true, and what makes
  `ctrl` part of the first half rather than the second, is that `EVP_CIPHER_CTX_get_iv_length`
  reaches `EVP_CIPHER_CTX_ctrl` for a legacy cipher with `EVP_CIPH_CUSTOM_IV_LENGTH`. So:
  **7.3c-i** is the context, its parameters and initialisation, and **7.3c-ii** is the twelve
  exports that push bytes through an armed context. `docs/DECISIONS.md` D152 records the
  correction and the four dependencies the attempt measured.

### 7.6's brief names an `EVP_AEAD` that does not exist, and `hpke_util.c` is not a ledger unit

**D195.** The row above says `crypto/hpke/hpke.c` is "over `EVP_KEM`, `EVP_KDF` and, importantly,
`EVP_AEAD` (`crypto/evp/evp_aead.c`)". **There is no `EVP_AEAD` object in this authority.** No
`EVP_AEAD*` identifier appears anywhere in the pinned source, there is no `crypto/evp/evp_aead.c`
in the manifest, and `include/crypto/evp.h` declares neither. The AEAD half of `hpke.c` is an
`EVP_CIPHER` in GCM mode (`EVP_EncryptInit_ex`/`EVP_DecryptInit_ex` plus
`EVP_CTRL_AEAD_SET_IVLEN`/`GET_TAG`/`SET_TAG`), which is 7.3b/7.3c's own work, so no export is
withheld on the dependency the brief names. The one export that does not land is
`OSSL_HPKE_get_grease_value`, on `RAND_bytes_ex` (Phase 9, `hpke.c:1433`), and it has a
`forensics/prerequisites.json` row and a `NOT_MEASURED_…` line in `RT-HPKE`.

`crypto/hpke/hpke.c`'s helpers are `crypto/hpke/hpke_util.c`'s, declared in the **uninstalled**
`include/internal/hpke_util.h`, so the atlas does not census them as obligations and the ledger has
no module for them. They are transcribed as `pub(crate)` internals beside the exports they serve,
with one substitution that is a finding of its own: `ossl_hpke_labeled_extract`/`_expand` build
their labelled byte strings through `WPACKET`, which this crate does not have, and the
`WPACKET_*` calls there are an exactly-sized concatenation whose failure arm
(`hpke_util.c:329`, `:380`) cannot run. The concatenation is written directly and the unreachable
arm is named rather than stubbed. `find_random` and `hpke_random_suite` are omitted because their
only caller is the withheld function.

The `kdf.h` remainder the row names is **already discharged**: `owned_by_header['kdf.h']` is forty
names and its `open` list is empty, so the row contributes no work here.

### 7.7, the seal — what it settles, and the four readings that were wrong

**D196.** The seal is evidence rather than work, and closing the stratum turned out to require four
corrections to the readings the earlier rows left behind. They are listed here because each one is a
*reading* that a reader of this plan would otherwise still be following.

1. **Three of the evidence list's module paths never existed.** `src/evp/legacy_cipher.rs`,
   `src/evp/legacy_digest.rs` and `src/evp/params_translate.rs` were named as the modules the
   legacy cipher statics, the legacy digest statics and `ctrl_params_translate.c` would land in.
   7.3g handed the first two families to Phase 13 whole, so neither file was written; the ctrl
   plane landed in `src/evp/pkey_ctx.rs` (D188). `forensics/tools/phase_state.py`'s evidence list
   is what turned those into `evidence_absent`, and therefore into `in-progress`, so the entries
   are removed rather than satisfied with empty modules. The ledger's `MODULE_PREFIXES` labels for
   them stay: a label is not a claim about a file, which is D193's `p_legacy.rs` reading and D194's
   for the `PKCS5_` half of the `pem_bridge.rs` label.
2. **`evp_cleanup_int` was pinned to this stratum and belongs to Phase 8.** Its row named
   `EVP_PBE_cleanup` as the blocker, and that landed with 7.4c's PBE remainder (D192). What is left
   is the seventh call, `evp_app_cleanup_int`, which is Phase 8's; the row is retargeted rather
   than discharged.
3. **`evp_pkey_decrypt_alloc` was owed to this stratum and had never been written.** Its row said
   7.4b's operation half would land it "directly beside" `EVP_PKEY_decrypt`; that half landed and
   this did not. It landed in 7.7, and its prerequisite row is retired.
4. **`EVP_PKEY_new_mac_key` was not blocked at all.** D193's sweep put it in the twelve-name
   legacy-accessor group with the reason "all read a legacy key through `evp_pkey_get_legacy`",
   and its call list contains no such call: `crypto/evp/pmeth_gn.c:313` is `EVP_PKEY_CTX_new_id`,
   `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_mac_key`, `EVP_PKEY_keygen` and `EVP_PKEY_CTX_free`,
   and the first two of those blocked it only until 7.4c-ii and 7.4c-v landed them (D186, D188).
   It is implemented, in `src/evp/pmeth_gn.rs` with its thirteen siblings, and `RT-EVP-PKEY` drives
   it through a provider the probe publishes in the **default** library context, because
   `OBJ_nid2sn(EVP_PKEY_HMAC)` is `"HMAC"` and no other provider can answer it. This is the kind of
   finding the stratum's own seal is for: a name whose stated blocker had already landed and whose
   reason had been copied from its neighbours.

The stratum's own unreached-unit census is the other half of the same reconciliation. Fifty-six
units this plan names are reached or handed on but invisible to `plan_reconciliation.py`'s three
mechanical signals, and the file it reads for exactly that case -- `forensics/prerequisites.json`'s
`units` block, whose own rule is "an authority translation unit a subphase plan names, which no
transcription edge, no built internal function, no referenced identifier and no symbol record
reaches" -- now carries a record for each, with the class and the fields its class requires to prove.
D196 records the split: 42 `deferred_to_later_stratum` and 14 `reached_by_a_named_construct`.

## 3. What each subphase must honour — authority facts already established

Recorded so they are not re-derived per subphase.

1. **Tracing is compiled out.** `configdata.pm` records `no-trace`, so `OSSL_TRACE` and its
   family expand to nothing and are not a dependency. Phase 6 established this for
   `provider_core.c` and it holds for all of `crypto/evp/`.
2. **`OPENSSL_NO_ENGINE` is not defined.** `configdata.pm` records `engine` and
   `"engine" => "1"`, so the ENGINE paths in `pmeth_lib.c` and `ameth_lib.c` are live and
   their ENGINE dependencies are Phase 13's, recorded rather than stubbed.
3. **`OPENSSL_NO_DEPRECATED` is not defined and the legacy cipher wrappers are compiled.**
   `e_des.c`, `e_rc4.c` and their siblings are in the build; their primitives are Phase 13's.
4. **`OPENSSL_NO_FIPS` is set.** `evp_default_properties_enable_fips_int` exists and is
   deferred; this crate's FIPS claims are recorded separately in `docs/FIPS_CLAIMS.md`.
5. **Asm is *enabled*, and this row said the opposite until D143.** The row read "`no-asm` is set,
   so no `crypto/evp/*.s` or per-architecture `.pl` output is a dependency", and the authority's own
   build record says otherwise in three places a reader can check: `%disabled` in `configdata.pm`
   — the admitted profile's actual disable list — contains `trace`, `fips`, `md2`, `rc5`, `ktls`,
   `asan`, `ubsan`, `zlib` and thirty-five more, and **`asm` is not among them**; `"asm_arch" =>
   "x86_64"` and `"perlasm_scheme" => "elf"` are both recorded; and the build tree holds
   `crypto/x86_64cpuid.s` **and** `libcrypto-shlib-x86_64cpuid.o`, where the `.s` is perlasm output
   that a `no-asm` build does not produce. The consequence is not local: whatever `crypto/*.pl` and
   `crypto/*/*.pl` emit is part of the authority this crate reconstructs, it is hidden from the DSO
   by the version script so none of it is exported surface, and a Phase 8 or 9 transcription that
   reaches `aesni_encrypt` or `sha256_block_data_order` is reaching a perlasm implementation. This
   stratum's own instance is `OPENSSL_rdtsc` (`src/runtime/rdtsc.rs`), which 7.1's stochastic cache
   flush seeds from.
   dependency.
6. **The namemap is Phase 6's and is complete.** `ossl_namemap_doall_names`,
   `ossl_namemap_name2num*` and `ossl_namemap_add_names` are the vocabulary the fetch path
   uses, and their legacy pre-population was deferred whole to Phase 13 — which means an
   `EVP_get_digestbyname("md5")` that resolves through the *legacy* table is out of scope
   here and its disposition is named in that stratum's ledger.
7. **`ossl_provider_query_operation` and the operation bits are Phase 6's and are complete**,
   so 7.1's walk has a real provider to walk.

## 4. Constitutional gates this stratum must satisfy

1. **Every export is implemented or handed on with the dependency named.** The ledger is the
   arithmetic; `ownership_audit.py` is the cross-check.
2. **Every implemented export is observed by a differential court**, compiled twice and
   diffed on `key=value`.
3. **`ABI-PROTOTYPE` covers every declaration**, including the generated ones — D98's hole
   stays closed.
4. **`ABI-SYMBOL` and `ABI-DYNAMIC` stay clean** for the new surface, which means the
   `libcrypto.so.3` build must keep its `DT_NEEDED`, symbol types, bindings and versions.
5. **The prerequisite gate and the plan reconciliation stay at zero findings**, which for
   this stratum means `crypto/core_algorithm.c` and `crypto/core_fetch.c` stop being
   deferrals and start being reached.
6. **No authority fault is reproduced.** Where `crypto/evp/` dereferences a NULL or relies on
   an uninitialised field, the court does not call it and
   `docs/SECURITY_DIVERGENCE_POLICY.md` records the divergence.
7. **A commit may not undo an earlier commit's evidence**, and the version is an input to
   generated evidence — `docs/RELEASE_GATES.md` §8.

## 5. Process

One staging branch, `phase7-evp`, merged to `main` with `--no-ff` when the stratum is
complete and CI-green, and deleted afterwards. Work is pushed to the staging branch
frequently so that a long stratum survives any single session, and the branch is only merged
when its own seal exists and its ledger reads zero open.
