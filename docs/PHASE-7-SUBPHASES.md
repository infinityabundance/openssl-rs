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
| 7.2 | **The fetch surface and the default properties** | `crypto/evp/evp_fetch.c`'s remaining ten internals and the eight names Phase 3 and 4 deferred here: `evp_generic_fetch`, `evp_generic_fetch_from_prov`, `evp_generic_do_all`, `evp_names_do_all`, `evp_is_a`, `evp_set_default_properties_int`, `evp_get_global_properties_str`, `evp_default_properties_enable_fips_int`; `crypto/evp/names.c` whole | 7.1 | `RT-FETCH` (extended) | a property query selects and rejects algorithms through the real fetch path, including **negative** selection; the property-string step that `D-CHILD-REGISTER-PROPS-1` and `D-CHILD-PROPS-CB-1` recorded as unreachable becomes writable and both divergence rows are revised against measurement |
| 7.3 | **The symmetric method objects** | `crypto/evp/evp_enc.c`, `evp_lib.c`, `digest.c`, `cmeth_lib.c`, `mac_lib.c`, `mac_meth.c`, `kdf_lib.c`, `kdf_meth.c`, `skeymgmt_meth.c`, `evp_rand.c`, `e_old.c`, `c_allc.c`, `c_alld.c`, `evp_err.c`, `crypto/evp/names.c`; the legacy wrappers `crypto/evp/e_aes.c`, `e_aria.c`, `e_camellia.c`, `e_des3.c`, `e_sm4.c`, `e_des.c`, `e_rc2.c`, `e_rc4.c`, `e_idea.c`, `e_cast.c`, `e_seed.c`, `e_bf.c`, `e_null.c`, `e_xcbc_d.c`, `e_aes_cbc_hmac_sha1.c`, `e_aes_cbc_hmac_sha256.c`, `e_chacha20_poly1305.c`, `e_rc4_hmac_md5.c`, `legacy_md4.c`, `legacy_md5.c`, `legacy_sha.c`, `legacy_ripemd.c`, `legacy_blake2.c`, `legacy_mdc2.c`, `legacy_wp.c` — those whose primitives are Phase 13's are **handed on with the dependency named**, in this ledger | 7.2 | `RT-EVP-CIPHER`, `RT-EVP-MD` | the `EVP_CIPHER`/`EVP_MD`/`EVP_MAC`/`EVP_KDF`/`EVP_RAND` object families round-trip through the fetch path, and every wrapper whose primitive is Phase 13's is a recorded hand-off rather than a stub |
| 7.4 | **The `EVP_PKEY` layer** | `crypto/evp/p_lib.c`, `pmeth_lib.c`, `pmeth_check.c`, `pmeth_gn.c`, `p_legacy.c`, `evp_pkey.c`, `evp_key.c`, `evp_pbe.c`, `p5_crpt.c`, `p5_crpt2.c`, `pbe_scrypt.c`, `p_seal.c`, `p_sign.c`, `p_verify.c`, `p_enc.c`, `p_dec.c`, `p_open.c`, `m_sigver.c`, `signature.c`, `asymcipher.c`, `kem.c`, `exchange.c`, `keymgmt_meth.c`, `keymgmt_lib.c`, `ec_support.c`, `dh_support.c`, `evp_pkey_type.c`, `evp_cnf.c`, `ctrl_params_translate.c`; and the `asn1.h` glue that lives outside the directory — `crypto/asn1/ameth_lib.c`, `i2d_evp.c`, `d2i_pr.c`, `d2i_param.c`, `d2i_pu.c` | 7.3 | `RT-EVP-PKEY` | `EVP_PKEY` holds a key from a provider, its `EVP_PKEY_ASN1_METHOD` glue is reachable, and the key's parameters round-trip through `ctrl_params_translate` |
| 7.5 | **The BIO, encoding and PEM bridges** | `crypto/evp/bio_enc.c`, `bio_b64.c`, `bio_md.c`, `bio_ok.c`, `encode.c`, `s_lib.c`; and the twenty-six hand-offs from Phase 5 — the twenty-three `pem.h` ones (`crypto/pem/pem_pkey.c`, `pem_pk8.c`) and the three `asn1.h` ones | 7.4 | `RT-EVP-BIO`, `RT-EVP-PEM` | the PEM and ASN.1 surface that deferred its EVP dependency to this stratum is implemented, and the hand-off edges on both sides are discharged |
| 7.6 | **The MAC, KDF and HPKE header surfaces** | `crypto/hmac/hmac.c`'s twelve, `crypto/cmac/cmac.c`'s nine, `crypto/hpke/hpke.c`'s twenty, and the `kdf.h` remainder | 7.3 | `RT-HMAC`, `RT-CMAC`, `RT-HPKE` | the three header surfaces are implemented against the `EVP_MAC`/`EVP_KDF` objects 7.3 built, and each court observes its own surface rather than the shared machinery |
| 7.7 | **The seal** | nothing in the crate — evidence | 7.0–7.6 | — | `docs/PHASE-7-EVP-SEAL.md`: zero open obligations, every court passing, the prototype court clean, the prerequisite gate and the plan reconciliation at zero findings, the FRF receipts and the Gemel checkpoint |

Each row is a *dependency-ordered* boundary and not a size boundary. Three of them will
almost certainly split as they land — 7.3 and 7.4 are each over two hundred exports — and the
precedent from Phase 6 is that a split is recorded here with the reason it was needed rather
than performed silently.

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
5. **`no-asm` is set**, so no `crypto/evp/*.s` or per-architecture `.pl` output is a
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
