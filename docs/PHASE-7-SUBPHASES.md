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
| 7.5 | **The BIO, encoding and PEM bridges** | `crypto/evp/bio_enc.c`, `bio_b64.c`, `bio_md.c`, `bio_ok.c`, `encode.c`, `s_lib.c`; and the twenty-six hand-offs from Phase 5 — the twenty-three `pem.h` ones (`crypto/pem/pem_pkey.c`, `pem_pk8.c`) and the three `asn1.h` ones | 7.4 | `RT-EVP-BIO`, `RT-EVP-PEM` | the PEM and ASN.1 surface that deferred its EVP dependency to this stratum is implemented, and the hand-off edges on both sides are discharged |
| 7.6 | **The MAC, KDF and HPKE header surfaces** | `crypto/hmac/hmac.c`'s twelve, `crypto/cmac/cmac.c`'s nine, `crypto/hpke/hpke.c`'s twenty, and the `kdf.h` remainder | 7.3 | `RT-HMAC`, `RT-CMAC`, `RT-HPKE` | the three header surfaces are implemented against the `EVP_MAC`/`EVP_KDF` objects 7.3 built, and each court observes its own surface rather than the shared machinery |
| 7.7 | **The seal** | nothing in the crate — evidence | 7.0–7.6 | — | `docs/PHASE-7-EVP-SEAL.md`: zero open obligations, every court passing, the prototype court clean, the prerequisite gate and the plan reconciliation at zero findings, the FRF receipts and the Gemel checkpoint |

Each row is a *dependency-ordered* boundary and not a size boundary. Three of them will
almost certainly split as they land — 7.3 and 7.4 are each over two hundred exports — and the
precedent from Phase 6 is that a split is recorded here with the reason it was needed rather
than performed silently.

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
| 7.3c | **The `EVP_CIPHER_CTX` and the `EVP_Encrypt`/`EVP_Decrypt` API** | `evp_enc.c`'s remainder: the context, its flags, `EVP_CipherInit*`/`EVP_CipherUpdate`/`EVP_CipherFinal*`, the two `EVP_CipherPipeline*` families and the per-alias spellings of all of them | 7.3b | `RT-EVP-CIPHER` (extended) | 68 |
| 7.3d | **The `EVP_MD` remainder** | `evp_lib.c`'s `EVP_MD_*` accessors and `EVP_MD_meth_*` constructors, `digest.c`'s context (`EVP_MD_CTX_*`), the one-shot `EVP_Digest*`/`EVP_DigestSign*`/`EVP_DigestVerify*`, `EVP_Q_digest`, `EVP_MD_do_all*`, `EVP_MD_xof`; and `m_null.c`'s `EVP_md_null`, for `EVP_enc_null`'s reason | 7.3a | `RT-EVP-MD` | 80 |
| 7.3e | **`EVP_MAC` and `EVP_KDF`** | `mac_lib.c`, `mac_meth.c`, `kdf_lib.c`, `kdf_meth.c` — the two symmetric method classes whose operations are supplied entirely by a provider | 7.3d | `RT-EVP-MAC`, `RT-EVP-KDF` | 55 |
| 7.3f | **`EVP_RAND` and `EVP_SKEYMGMT`** | `evp_rand.c` and `skeymgmt_meth.c` | 7.3e | `RT-EVP-RAND` | 54 |
| 7.3g | **`names.c`, `evp_err.c`, `c_allc.c`, `c_alld.c`, and the legacy wrappers whose primitives are Phase 13's** | the four `EVP_MD_do_all*`/`EVP_CIPHER_do_all*` in `names.c`, the generated reason table in `evp_err.c`, the three adders, and the one hundred and sixty-eight statics in `e_aes.c`, `e_aria.c`, `e_camellia.c`, `e_des3.c`, `e_sm4.c`, `e_des.c`, `e_rc2.c`, `e_rc4.c`, `e_idea.c`, `e_cast.c`, `e_seed.c`, `e_bf.c`, `e_xcbc_d.c`, `e_aes_cbc_hmac_sha1.c`, `e_aes_cbc_hmac_sha256.c`, `e_chacha20_poly1305.c`, `e_rc4_hmac_md5.c`, `e_old.c`, `legacy_md4.c`, `legacy_md5.c`, `legacy_md5_sha1.c`, `legacy_sha.c`, `legacy_ripemd.c`, `legacy_blake2.c`, `legacy_mdc2.c`, `legacy_wp.c` — **handed to Phase 13 with the dependency named in that stratum's ledger**, because `e_aes.c` calls `AES_encrypt` and its siblings, not a provider | 7.3f | — | 171 |

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
