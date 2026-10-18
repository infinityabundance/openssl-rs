# OB-3 caller-precondition audit — `runtime::bio::owned::{OwnedCtx, RawCtx}`

**Source identity:** `integrate/safe-c33` at `2df614290` (working tree at audit time),
re-audited after the OB-3 fixes in the uncommitted working tree. Line numbers below are
from that fixed working tree.
**Authority:** OpenSSL 3.6.4, read from `forensics/authorities/src/openssl-3.6.4/`.
**Scope:** every call site in `src/` of the shared-owner transitions
`RawCtx::{malloc,malloc_at,assume_init,into_raw,set_release_line}` and
`OwnedCtx::{from_raw,from_raw_at,into_raw,set_release_line}` (plus the two
internal `assume_init` calls in the safe `OwnedCtx::zalloc{, _at}` constructors),
and the shared `CtxDestroy` implementations those owners run. Module-local
`OwnedCtx`/`RawCtx`/`CtxDestroy` copies (`ec/lib.rs`, `ssl/ssl_lib.rs`,
`evp/bio_ok.rs`, `provider/*`, etc.) are **out of OB-3** and are not counted.
The audit was read-only; the fixes in §6 are working-tree edits and no commit,
branch or push was made.

**Verdict semantics.** `ESTABLISHED` means a source witness was found for the
transition's obligation (initialisation, exclusive ownership, provenance and
release coordinates), as in `DESTRUCTOR-CONTRACTS.md`; it is **not**
independently checked and **not** `SAFETY_DISCHARGED`. `UNATTRIBUTED` means the
source either has no witness or the witness is contradicted. Counts separate
production, `cfg(test)`, and the two constructor-internal transitions.

---

## 0. Totals

| transition | production | `cfg(test)` | internal |
|---|---:|---:|---:|
| `RawCtx::assume_init` | 28 | 3 | 2 (`owned.rs:133,149`) |
| `OwnedCtx::from_raw` | 80 | 4 (`owned.rs:472` canary + `owned_ctx_model.rs:520,543,552`) | 0 |
| `OwnedCtx::from_raw_at` | 41 | 1 (`dso/mod.rs:1100`) | 0 |
| `RawCtx::malloc` | 9 | 3 (`eng_table.rs:628,688` + `owned_ctx_model.rs:479`) | 0 |
| `RawCtx::malloc_at` | 4 | 0 | 0 |
| `into_raw` (shared owners) | 132 | 7 (5 caller sites + `owned.rs:465` + `owned_ctx_model.rs:510,533`) | 0 |
| `set_release_line` (shared owners) | 10 | 0 | 0 |
| **total** | **304** | **18** | **2** |

**Status:** **304 of 304 production transitions `ESTABLISHED`; 0 `UNATTRIBUTED`.**
The fixes in §6 supply the missing `attributes` release, separate the
allocation/release coordinates of `EvpPkey`, `EvpPkeyCtx` and `EvpMd`, and turn
`OsslLibCtx`'s block-only publication into a validated `assume_init` transition
whose reclaim runs the same `CtxDestroy` body. All 18 test transitions remain
`ESTABLISHED` (source-witnessed test/negative-control/model paths). The sentence
does **not** claim that every release coordinate is verified: §9 marks 45 of the
121 production reclaims `UNVERIFIED` because the impl records a default/NULL
coordinate or because the pinned authority has only a generated `.c.in`
template. Those are retained coordinate gaps, not unreproduced transitions.

**CtxDestroy inventory:** 138 `unsafe impl CtxDestroy for` lines; 6 implement
module-local traits (`ec/lib.rs` 2, `ssl/ssl_lib.rs` 4) and 2 are the test-only
`ProbeCtx` impls (`runtime/bio/owned.rs`, `runtime/bio/owned_ctx_model.rs`). The remaining **130 production shared-trait impls** map by type
name onto the 136 `CtxDestroy` rows of `DESTRUCTOR-CONTRACTS.md` (199 rows
across all families, all `ESTABLISHED`, 0 `CONTRACTED`).

---

## 1. Transition inventory

### 1.1 `RawCtx::assume_init` — production (28)

```
src/asn1/x_pkey.rs:132                 src/cmp/cmp_server.rs:223
src/context/mod.rs:1099                src/context/thread_data.rs:151
src/decoder_lib.rs:456                 src/dh/object.rs:315
src/dsa/object.rs:253                  src/dsa/pmeth.rs:143
src/dso/mod.rs:261                     src/ec/ecdsa.rs:288
src/ec/ecx_key.rs:178                  src/engine/eng_table.rs:271
src/evp/cipher.rs:446                  src/provider/conf.rs:206
src/provider/decode_pvk2key.rs:153     src/provider/file_store_any2obj.rs:117
src/provider/ml_kem_kem.rs:128         src/provider/mlx_kem.rs:129
src/provider/sm2_enc.rs:284            src/rsa/mp.rs:184
src/rsa/object.rs:464                  src/selftest/mod.rs:242
src/x509/by_dir.rs:520                 src/x509/by_dir.rs:761
src/x509/pcy_cache.rs:307              src/x509/v3_lib.rs:589
src/x509/x_crl.rs:1293                 src/runtime/bio/bf_lbuf.rs:134
```

Test: `src/engine/eng_table.rs:639,699`, `src/runtime/bio/owned_ctx_model.rs:498`.

Internal: `src/runtime/bio/owned.rs:133,149` (the safe `OwnedCtx::zalloc`/`zalloc_at` bodies).

`into_raw` sites that publish a `RawCtx` **without** `assume_init` (7):
`encoder_pkey.rs:554` (`ConstructDataPkey`), `modes/ocb.rs:211` (`OcbCtx`),
`modes/siv128.rs:360` (`Siv128Context`), `runtime/bio/core_bio.rs:136`
(`OsslCoreBio`), `ui/ui_lib.rs:460,463` (`Ui`), `ui/ui_lib.rs:1696`
(`UiMethod`). Each is either an empty destructor body or writes/initialises every
destructor-visible field before publication. `OsslLibCtx` no longer belongs in
this list: `context/mod.rs:1099` now calls `assume_init` before `into_raw`, and
its reclaim runs the `CtxDestroy` body (§6, formerly unattributed item 4).

### 1.2 `OwnedCtx::from_raw` — production (80)

```
src/asn1/x_info.rs:126              src/asn1/x_pkey.rs:159
src/cmp/cmp_ctx.rs:606              src/cmp/cmp_server.rs:188
src/context/core_bio.rs:132         src/context/thread_data.rs:164
src/ct/ct_policy.rs:194             src/decoder_lib.rs:391
src/decoder_meth.rs:852             src/dh/object.rs:401
src/dh/pmeth.rs:205                 src/dsa/object.rs:339
src/dsa/pmeth.rs:191                src/ec/ecdsa.rs:304
src/ec/mult.rs:184                  src/ec/pmeth.rs:285
src/encoder_lib.rs:532              src/encoder_meth.rs:353
src/encoder_meth.rs:1351            src/engine/eng_table.rs:410
src/evp/cipher_ctx.rs:455           src/evp/cipher.rs:906
src/evp/encode.rs:278               src/evp/kem.rs:408
src/evp/keymgmt.rs:772              src/evp/rand.rs:712
src/evp/skeymgmt.rs:579             src/mac/hmac.rs:430
src/property/globals.rs:120         src/provider/child.rs:238
src/provider/ctx.rs:112             src/provider/decode_epki2pki.rs:133
src/provider/decode_pem2der.rs:324  src/provider/decode_pvk2key.rs:164
src/provider/decode_spki2typespki.rs:119
src/provider/ec_kem.rs:390          src/provider/ecx_kmgmt.rs:1550
src/provider/encode_key2any.rs:1903 src/provider/encode_key2ms.rs:123
src/provider/file_store_any2obj.rs:128
src/provider/file_store.rs:257      src/provider/mac_legacy_kmgmt.rs:328
src/provider/mac_legacy_kmgmt.rs:988
src/provider/ml_dsa_kmgmt.rs:1059   src/provider/ml_kem_kem.rs:141
src/provider/mlx_kem.rs:141         src/provider/rsa_kem.rs:199
src/provider/seed_src.rs:290        src/provider/seed_src.rs:774
src/provider/skeymgmt.rs:147        src/provider/slh_dsa_kmgmt.rs:844
src/rsa/mp.rs:99                    src/rsa/pmeth.rs:370
src/runtime/bio/bf_buff.rs:180      src/runtime/bio/bf_lbuf.rs:153
src/runtime/bio/bf_nbio.rs:173      src/runtime/bio/bf_prefix.rs:135
src/runtime/bio/bf_readbuff.rs:118  src/runtime/bio/bss_acpt.rs:220
src/runtime/bio/bss_bio.rs:182      src/runtime/bio/bss_conn.rs:232
src/runtime/bio/bss_dgram.rs:359    src/runtime/bio/bss_dgram_pair.rs:417
src/runtime/bio/bss_mem.rs:281      src/runtime/bio/bss_sock.rs:436
src/runtime/bio/comp.rs:346
src/runtime/bio/core_bio.rs:181     src/runtime/bio/method.rs:220
src/runtime/thread_arch.rs:559      src/selftest/indicator.rs:81
src/selftest/mod.rs:142             src/selftest/mod.rs:257
src/ssl/bio_ssl.rs:637              src/ssl/d1_lib.rs:152
src/store/store_lib.rs:1505         src/store/store_lib.rs:2251
src/store/store_lib.rs:2388         src/store/store_meth.rs:232
src/ts/ts_verify_ctx.rs:130         src/x509/pcy_cache.rs:451
```

Test: `src/runtime/bio/owned.rs:472` (negative-control canary) and the three
`OwnedCtx::<ProbeCtx>::from_raw` model calls at
`src/runtime/bio/owned_ctx_model.rs:520,543,552`.

### 1.3 `OwnedCtx::from_raw_at` — production (41)

```
src/async/async_wait.rs:195         src/context/mod.rs:1294
src/ct/ct_log.rs:332                  src/ct/ct_log.rs:599
src/ct/ct_sct_ctx.rs:154            src/ct/ct_sct.rs:228
src/dso/mod.rs:348                  src/ec/ecx_key.rs:205
src/engine/eng_dyn.rs:410           src/evp/asymcipher.rs:475
src/evp/digest.rs:805               src/evp/digest.rs:1969
src/evp/exchange.rs:505             src/evp/pkey_ctx.rs:1002
src/evp/pkey_ctx.rs:2192            src/evp/pkey.rs:669
src/hpke/mod.rs:2507                src/provider/conf.rs:228
src/provider/keymgmt.rs:253         src/provider/keymgmt.rs:1625
src/provider/sm2_enc.rs:242         src/rand/rand_lib.rs:465
src/ssl/ssl_sess.rs:459             src/ui/ui_lib.rs:479
src/ui/ui_lib.rs:499                src/ui/ui_lib.rs:1712
src/x509/by_dir.rs:330              src/x509/by_dir.rs:371
src/x509/by_dir.rs:428              src/x509/by_store.rs:343
src/x509/v3_lib.rs:384              src/x509/v3_purp.rs:671
src/x509/v3_utl.rs:349              src/x509/x509_lu.rs:974
src/x509/x509_lu.rs:1357             src/x509/x509_lu.rs:1630
src/x509/x509_lu.rs:1820             src/x509/x509_trust.rs:411
src/x509/x509_vfy.rs:1544            src/x509/x509_vpm.rs:350
src/x509/x_crl.rs:1314
```

Test: `src/dso/mod.rs:1100`.

### 1.4 `RawCtx::malloc` / `malloc_at`

`malloc` production (9): `dsa/pmeth.rs:126`, `engine/eng_table.rs:241`,
`modes/ocb.rs:207`, `provider/decode_pvk2key.rs:142`,
`provider/ml_kem_kem.rs:114`, `provider/mlx_kem.rs:118`,
`runtime/bio/bf_lbuf.rs:109`, `runtime/bio/core_bio.rs:123`,
`x509/pcy_cache.rs:293`.
Test: `engine/eng_table.rs:628,688`, `runtime/bio/owned_ctx_model.rs:479`.

`malloc_at` production (4): `x509/by_dir.rs:503`, `x509/by_dir.rs:743`,
`x509/v3_lib.rs:573`, `x509/x_crl.rs:1275`.

### 1.5 `into_raw` — production (132)

```
src/asn1/x_info.rs:110                         src/asn1/x_pkey.rs:143
src/async/async_wait.rs:182                    src/cmp/cmp_ctx.rs:595
src/cmp/cmp_server.rs:223                      src/context/core_bio.rs:121
src/context/mod.rs:1099                        src/context/thread_data.rs:151
src/ct/ct_log.rs:332                           src/ct/ct_log.rs:599
src/ct/ct_policy.rs:171                        src/ct/ct_sct.rs:215
src/ct/ct_sct_ctx.rs:143                       src/decoder_lib.rs:373
src/decoder_lib.rs:456                         src/decoder_meth.rs:780
src/dh/object.rs:318                           src/dh/pmeth.rs:188
src/dsa/object.rs:256                          src/dsa/pmeth.rs:143
src/dso/mod.rs:274                             src/dso/mod.rs:280
src/ec/ecdsa.rs:288                            src/ec/ecx_key.rs:178
src/ec/mult.rs:123                             src/ec/pmeth.rs:185
src/encoder_lib.rs:469                         src/encoder_meth.rs:282
src/encoder_meth.rs:1279                       src/encoder_pkey.rs:554
src/engine/eng_table.rs:288                    src/evp/asymcipher.rs:319
src/evp/cipher.rs:446                          src/evp/cipher_ctx.rs:346
src/evp/digest.rs:459                          src/evp/digest.rs:1899
src/evp/encode.rs:266                          src/evp/kem.rs:262
src/evp/keymgmt.rs:674                         src/evp/pkey_asn1.rs:641
src/evp/pkey_ctx.rs:689                        src/evp/pkey_ctx.rs:1165
src/evp/pkey_ctx.rs:1194                       src/evp/pkey_ctx.rs:1224
src/evp/pkey_ctx.rs:1253                       src/evp/pkey_ctx.rs:1297
src/evp/pkey_ctx.rs:1300                       src/evp/pkey_ctx.rs:2158
src/evp/rand.rs:473                            src/evp/signature.rs:899
src/evp/skeymgmt.rs:390                        src/hpke/mod.rs:2496
src/mac/hmac.rs:398                            src/modes/ocb.rs:211
src/modes/siv128.rs:360                        src/provider/child.rs:221
src/provider/conf.rs:206                       src/provider/ctx.rs:98
src/provider/decode_epki2pki.rs:123            src/provider/decode_pem2der.rs:314
src/provider/decode_pvk2key.rs:153             src/provider/decode_spki2typespki.rs:109
src/provider/ec_kem.rs:377                     src/provider/ecx_kmgmt.rs:1145
src/provider/encode_key2any.rs:1891            src/provider/encode_key2ms.rs:112
src/provider/file_store.rs:285                 src/provider/file_store_any2obj.rs:117
src/provider/keymgmt.rs:226                    src/provider/mac_legacy_kmgmt.rs:302
src/provider/mac_legacy_kmgmt.rs:789           src/provider/ml_dsa_kmgmt.rs:899
src/provider/ml_dsa_kmgmt.rs:904               src/provider/ml_kem_kem.rs:128
src/provider/mlx_kem.rs:129                    src/provider/rsa_kem.rs:188
src/provider/seed_src.rs:279                   src/provider/seed_src.rs:758
src/provider/skeymgmt.rs:214                   src/provider/slh_dsa_kmgmt.rs:679
src/property/globals.rs:133                    src/provider/sm2_enc.rs:116
src/provider/sm2_enc.rs:295                    src/rsa/mp.rs:184
src/rsa/object.rs:471                          src/rsa/pmeth.rs:252
src/runtime/bio/bf_buff.rs:162                  src/runtime/bio/bf_lbuf.rs:135
src/runtime/bio/bf_nbio.rs:158                  src/runtime/bio/bf_prefix.rs:124
src/runtime/bio/bf_readbuff.rs:100              src/runtime/bio/bss_acpt.rs:279
src/runtime/bio/bss_bio.rs:159                  src/runtime/bio/bss_conn.rs:277
src/runtime/bio/bss_dgram.rs:337                src/runtime/bio/bss_dgram_pair.rs:373
src/runtime/bio/bss_mem.rs:218                  src/runtime/bio/bss_sock.rs:408
src/runtime/bio/comp.rs:293                    src/runtime/bio/core_bio.rs:136
src/runtime/bio/method.rs:205
src/runtime/thread_arch.rs:422                 src/selftest/indicator.rs:69
src/selftest/mod.rs:130                        src/selftest/mod.rs:242
src/ssl/bio_ssl.rs:601                         src/ssl/d1_lib.rs:132
src/ssl/ssl_sess.rs:241                        src/ssl/ssl_sess.rs:406
src/store/store_lib.rs:920                     src/store/store_lib.rs:1731
src/store/store_lib.rs:1819                    src/store/store_lib.rs:2275
src/store/store_lib.rs:2299                    src/store/store_lib.rs:2354
src/store/store_lib.rs:2377                    src/store/store_meth.rs:258
src/store/store_register.rs:275                src/ts/ts_verify_ctx.rs:102
src/ui/ui_lib.rs:460                           src/ui/ui_lib.rs:463
src/ui/ui_lib.rs:1696                          src/x509/by_dir.rs:534
src/x509/by_dir.rs:778                         src/x509/by_store.rs:460
src/x509/pcy_cache.rs:307                      src/x509/v3_lib.rs:596
src/x509/x509_lu.rs:1322                       src/x509/x509_lu.rs:1647
src/x509/x509_vfy.rs:1522                      src/x509/x509_vpm.rs:332
src/x509/x_crl.rs:1294
```

Test (7): `engine/eng_table.rs:651,711`, `evp/pkey_ctx.rs:11728`,
`evp/signature.rs:2301`, `runtime/bio/owned.rs:465`,
`runtime/bio/owned_ctx_model.rs:510,533`.

**Reconciliation.** A fresh whole-tree grep for `into_raw`, `from_raw`,
`from_raw_at` and `take` was reconciled against this table. The shared
`OwnedCtx`/`RawCtx` API has no `take` transition. The four production sites that
the first inventory omitted are included (`async/async_wait.rs:182`,
`evp/digest.rs:1899`, `property/globals.rs:133`, `store/store_register.rs:275`),
as are the 13 shared-owner BIO caller modules listed in §1.7
(`bf_buff`, `bf_lbuf`, `bf_nbio`, `bf_prefix`, `bf_readbuff`, `bss_acpt`,
`bss_bio`, `bss_conn`, `bss_dgram`, `bss_dgram_pair`, `bss_mem`, `bss_sock`,
`comp`). Module-local owners with their own `into_raw`/`from_raw` (`OwnedRandCtx`,
`OwnedSkey`, `slh_dsa_sig::OwnedCtx`, `OwnedBuf`, `OwnedStr`, `OwnedBlock`) are
outside OB-3 and are not counted; the shared-owner count is **132**.

### 1.6 `set_release_line` — production (10)

```
src/dso/mod.rs:246        src/ec/ecx_key.rs:175
src/engine/eng_table.rs:259  src/engine/eng_table.rs:281
src/evp/pkey_ctx.rs:678  src/provider/conf.rs:202
src/provider/sm2_enc.rs:280  src/x509/by_dir.rs:767
src/x509/x509_lu.rs:1644  src/x509/x509_vfy.rs:1517
```

All ten re-point a still-unpublished block or a reclaimed record at the
authority's *alternate* release site (failed push / failed stack / failed lhash
insert / `propq`-dup or `pkey` up-ref failure); the handle has not been shared
and the single `Drop` remains the only release. `engine/eng_table.rs:259` is the
`EnginePile` `sk`-allocation refusal and `:281` the failed-lhash-insert refusal,
both re-pointing to `eng_table.c:113` (the pair the first inventory omitted);
`evp/pkey_ctx.rs:678` is `int_ctx_new`'s `EVP_PKEY_CTX_free` path
(`pmeth_lib.c:410`) after the propquery block-release site (`:312`);
`by_dir.rs:767` and `x509_lu.rs:1644` are on `OwnedCtx` after
`assume_init`/`from_raw_at`; the rest are on `RawCtx` before `assume_init`.

### 1.7 The 13 shared-owner BIO caller modules (second-round addendum)

These modules import the shared owners through `super::owned` (they are **not**
module-local copies). Each has one production `into_raw` and one production
`from_raw`; `bf_lbuf` additionally has the batch's only `RawCtx::malloc` and
`assume_init` pair. All 26 publication/reclaim sites (plus `bf_lbuf`'s
`malloc`/`assume_init` pair) are `ESTABLISHED` on the source witness
(constructor, initialisation, exclusive transfer, matching reclaim); their
release coordinates are `UNVERIFIED` because the shared impls leave
`CtxDestroy::FILE`/`LINE_FREE` at the trait default `(NULL, 0)` rather than the
authority's `OPENSSL_FILE`/`OPENSSL_LINE`. The authority block-release line is
recorded in the last column for auditability, not as a claimed crate coordinate.

| module / transitions | constructor and writes | release fn | impl coordinate | safety status |
|---|---|---|---|---|
| `bss_bio.rs:159` / `:182` | `bio_new`: `OwnedCtx::<BioBioSt>::zalloc` (`bss_bio.c:78`), writes `size`; zero rest | `bio_free` | `(NULL, 0)`; authority `bss_bio.c:104` `OPENSSL_free(b)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bf_prefix.rs:124` / `:135` | `prefix_create`: `zalloc` (`bf_prefix.c:54`), writes `prefix=NULL`, `indent=0`, `linestart=1` | `prefix_destroy` | `(NULL, 0)`; authority `bf_prefix.c:72` `OPENSSL_free(ctx)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_dgram.rs:337` / `:359` | `dgram_new`: `zalloc` (`bss_dgram.c:275`), no writes needed | `dgram_free` | `(NULL, 0)`; authority `bss_dgram.c:293` `OPENSSL_free(data)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_sock.rs:408` / `:436` | `sock_new`: `zalloc` (`bss_sock.c:83`), no writes needed | `sock_free` | `(NULL, 0)`; authority `bss_sock.c:100` `OPENSSL_free(a->ptr)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bf_lbuf.rs:135` / `:153` | `linebuffer_new`: `RawCtx::malloc` (`bf_lbuf.c:60`), writes `obuf` (`:62`), `obuf_size`, `obuf_len`; `assume_init` at `:134` only after all three | `linebuffer_free` | `(NULL, 0)`; authority `bf_lbuf.c:84` `OPENSSL_free(a->ptr)` (obuf `:83`) | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bf_nbio.rs:158` / `:173` | `nbiof_new`: `zalloc` (`bf_nbio.c:58`), writes `lrn=-1`, `lwn=-1` | `nbiof_free` | `(NULL, 0)`; authority `bf_nbio.c:71` `OPENSSL_free(a->ptr)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bf_readbuff.rs:100` / `:118` | `readbuffer_new`: `zalloc` (`bf_readbuff.c:55`), writes `ibuf_size`, `ibuf` | `readbuffer_free` | `(NULL, 0)`; authority `bf_readbuff.c:80` `OPENSSL_free(a->ptr)` (ibuf `:79`) | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_mem.rs:218` / `:281` | `mem_init`: `zalloc` (`bss_mem.c:111`), writes `buf`, `readp`; `mem_buf_free` releases `buf` separately first | `mem_free` | `(NULL, 0)`; authority `bss_mem.c:153` `OPENSSL_free(bb)` (readp `:152`) | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_acpt.rs:279` / `:220` | `accept_new`/`acpt_new`: `zalloc` (`bss_acpt.c:95`), writes `accept_family`, `accept_sock`, `state` | `BIO_ACCEPT_free` (`accept_free`) | `(NULL, 0)`; authority `bss_acpt.c:114` `OPENSSL_free(a)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bf_buff.rs:162` / `:180` | `buffer_new`: `zalloc` (`bf_buff.c:47`), writes `ibuf_size`, `ibuf`, `obuf_size`, `obuf` | `buffer_free` | `(NULL, 0)`; authority `bf_buff.c:80` `OPENSSL_free(a->ptr)` (ibuf `:78`, obuf `:79`) | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `comp.rs:293` / `:346` | `COMP_CTX_new`: `zalloc` (`comp_lib.c:25`), writes `meth`, then runs `meth->init` | `COMP_CTX_free` | `(NULL, 0)`; authority `comp_lib.c:61` `OPENSSL_free(ctx)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_dgram_pair.rs:373` / `:417` | `dgram_pair_init`: `zalloc` (`bss_dgram_pair.c:279`), writes `mtu`, `req_buf_len`, `lock`; refused lock returns as `OwnedCtx` over the zero-valid block | `dgram_pair_free` | `(NULL, 0)`; authority `bss_dgram_pair.c:334` `OPENSSL_free(b)` (lock `:333`) | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |
| `bss_conn.rs:277` / `:232` | `connect_new`/`conn_new`: `zalloc` (`bss_conn.c:289`), writes `state`, `connect_family`, `connect_sock_type` | `BIO_CONNECT_free` (`connect_free`) | `(NULL, 0)`; authority `bss_conn.c:304` `OPENSSL_free(a)` | `ESTABLISHED`; coordinate `UNVERIFIED` (trait default) |

#### Same-file zero-validity witnesses

All 12 distinct `CtxDestroy` impls below are already inside the executable
all-zero sweep of `OB3-CHECKS.md` §4 (130/130 passed), so these witnesses are
backed by an executed test as well as by field inspection. `bf_readbuff` shares
`bf_buff`'s `BioBufferCtx` impl and has no impl of its own.

| module | type | fields | all-zero valid? and why |
|---|---|---|---|
| `bss_bio` | `BioBioSt` | `peer:*mut Bio`, `closed:c_int`, `len/offset/size/request:usize`, `buf:*mut c_char` | **yes** — null pointers and zero integers; the body only takes a NULL `buf` |
| `bf_prefix` | `PrefixCtx` | `prefix:*mut c_char`, `indent:u32`, `linestart:c_int` | **yes** — NULL `prefix` is skipped by the `!is_null()` guard |
| `bss_dgram` | `BioDgramData` | `peer/local_addr:BioAddr` (`SockAddrStorage{ss_family:u16,__pad:[u8;126]}`), `connected/last_error/mtu/peekmode:c_uint`, `next_timeout/socket_timeout:OsslTime(u64)`, `local_addr_enabled:c_char` | **yes** — nested plain records of integers/bytes; empty body |
| `bss_sock` | `BssSockData` | `tfo_first:c_int`, `tfo_peer:[u8;28]` | **yes** — integers/bytes; empty body |
| `bf_lbuf` | `BioLineBufferCtx` | `obuf:*mut c_char`, `obuf_size:c_int`, `obuf_len:c_int` | **yes** — NULL buffer + zero lengths; body takes a NULL block as `None`. The constructor writes all three before `assume_init`; its `obuf` failure leaves only the NULL `obuf` written and returns as a `RawCtx`, so the destructor never sees the partial state |
| `bf_nbio` | `NbioTest` | `lrn:c_int`, `lwn:c_int` | **yes** — integers; empty body |
| `bf_readbuff` | `BioBufferCtx` (shared with `bf_buff`) | `ibuf_size/obuf_size:c_int`, `ibuf/obuf:*mut c_char`, `ibuf_len/ibuf_off/obuf_len/obuf_off:c_int` | **yes** — both buffers NULL, so both `OwnedBlock::take` calls are `None` |
| `bss_mem` | `BioBufMem` | `buf:*mut BufMem`, `readp:*mut BufMem` | **yes** — NULL `readp` is a `None` take; `buf` is released by `mem_buf_free`, not this body |
| `bss_acpt` | `BioAccept` | `state/accept_family/bind_mode/accepted_mode/accept_sock:c_int`, `param_addr/param_serv/cache_*_name/cache_*_serv:*mut c_char`, `addr_first:*mut BioAddrInfo`, `addr_iter:*const BioAddrInfo`, `cache_*_addr:BioAddr`, `bio_chain:*mut Bio` | **yes** — every member is an integer, a plain-byte `BioAddr`, or a NULL-able pointer; `OwnedBlock::take`, `BIO_ADDRINFO_free` and `BIO_free` all accept NULL |
| `bf_buff` | `BioBufferCtx` | as `bf_readbuff` | **yes** — both buffers NULL |
| `comp` | `CompCtx` | `meth:*mut CompMethod`, `compress_in/compress_out/expand_in/expand_out:c_ulong`, `data:*mut c_void` | **yes** — NULL `meth` skips the `finish` hook |
| `bss_dgram_pair` | `BioDgramPairSt` | `peer:*mut Bio`, `rbuf:RingBuf{start:*mut u8,len/count:usize,idx:[usize;2]}`, `req_buf_len/mtu:usize`, `cap:u32`, `local_addr:*mut BioAddr`, `lock:*mut CryptoRwlock`, `no_trunc/local_addr_enable/role/grows_on_write:bool` | **yes** — null pointers, zero integers, `false` booleans; `CRYPTO_THREAD_lock_free(NULL)` is a no-op |
| `bss_conn` | `BioConnect` | `state/connect_family/connect_sock_type/connect_mode/tfo_first:c_int`, `param_hostname/param_service:*mut c_char`, `addr_first:*mut BioAddrInfo`, `addr_iter:*const BioAddrInfo`, `info_callback:Option<BioInfoCb>`, `dgram_bio:*mut Bio` | **yes** — `Option<fn>` is `None` under the null-pointer niche; all pointers NULL; releasers accept NULL |

---

## 2. `assume_init` witnesses

The shared transition requires the storage to hold a fully initialised `T`
(every field `destroy_body` reads) and the handle to be the sole owner. There
are two constructor families.

### 2.1 Zeroed block + explicit writes (16 sites)

`RawCtx::zalloc`/`zalloc_at` leaves the whole block zero and the caller writes
the destructor-visible fields before `assume_init`. The zero remainder is the
authority's own constructed state, and the impl's zero-validity obligation
covers it.

| type / site | constructor and writes | destructor-visible fields |
|---|---|---|
| `X509Pkey` `x_pkey.rs:132` | `zalloc`; writes `enc_algor`, `enc_pkey` | both written; rest zero |
| `OsslCmpSrvCtx` `cmp_server.rs:223` | `zalloc`; writes `ctx`, `cert_req_id`, `polling`; `ctx` checked non-NULL before transition | `ctx` |
| `OsslLibCtxThreads` `thread_data.rs:151` | `zalloc`; writes `lock`, `cond_finished` | both |
| `OsslDecoderInstance` `decoder_lib.rs:456` | `zalloc`; `ptr::write(dest, ptr::read(src))`, then `decoderctx`; decoder up-ref taken | whole row copied + `decoderctx` |
| `Dh` `dh/object.rs:315` | `zalloc`; writes `lock`, `references`, `libctx`, `meth`, `flags`, `engine`; `params`/`ex_data` initialised; key slots zero | all, or authority zero state |
| `Dsa` `dsa/object.rs:253` | as `Dh` | all, or authority zero state |
| `Dso` `dso/mod.rs:261` | `zalloc_at`; writes `meth`, `references`; filename slots zero | `meth`, names (NULL) |
| `EcdsaSig` `ec/ecdsa.rs:288` | `zalloc`; no writes needed — zeroed block is the authority's two-NULL-scalar state | `r`, `s` (NULL) |
| `EcxKey` `ecx_key.rs:178` | `zalloc_at`; writes `libctx`, `haspubkey`, `keylen`, `type_`, `references`, optional `propq` | `propq`, `privkey`, `keylen` |
| `EvpCipher` `evp/cipher.rs:446` | `zalloc`; writes `refcnt`; rest is the valid zeroed method state | `type_name` (NULL), `prov` (NULL) |
| `ProviderConfGlobal` `conf.rs:206` | `zalloc_at`; writes `lock`; `activated_providers` zero | both |
| `Any2objCtx` `file_store_any2obj.rs:117` | `zalloc`; writes `provctx`; array zero | empty body (E) |
| `RsaPrimeInfo` `rsa/mp.rs:184` | `zalloc`; writes `r`,`d`,`t`,`pp`; failure path returns before transition | four BNs + zero `m` |
| `Rsa` `rsa/object.rs:464` | `zalloc`; writes `lock`, `blindings_sa`, `libctx`, `meth`, `flags`, `engine`, `ex_data`; keys/blinding zero; transition happens before the `built` test, and the failure path drops the zero-valid `OwnedCtx` | all, or authority zero state |
| `OsslSelfTest` `selftest/mod.rs:242` | `zalloc`; writes `cb`, `cb_arg`, `phase`, `type_`, `desc`, params | empty body (E) |
| `OsslLibCtx` `context/mod.rs:1099` | `zalloc`; `context_init` writes `lock` and every slot object it builds; slots whose strata have not landed remain zero | every slot pointer plus the two scalars; zero is the authority's empty state, and every slot release is NULL-tolerant |

### 2.2 Uninitialised (`malloc`) block + explicit writes (7 sites)

| type / site | constructor and writes | witness |
|---|---|---|
| `DsaPkeyCtx` `dsa/pmeth.rs:143` | `malloc`; writes `nbits`, `qbits`, `pmd`, `gentmp`, `md` | all five fields written; impl reads exactly these |
| `EnginePile` `eng_table.rs:271` | `malloc`; writes `uptodate`, `nid`, `sk`, then `funct = NULL` after the `sk`-failure arm | all four fields written before transition |
| `Pvk2keyCtx` `decode_pvk2key.rs:153` | `malloc`; `write_bytes(0)`, then `provctx`, `desc` | whole block zeroed + both fields; E body |
| `ProvMlKemCtx` `ml_kem_kem.rs:128` | `malloc`; `write_bytes(0)`, then `key`, `entropy`, `op` | whole block zeroed + all fields |
| `ProvMlxKemCtx` `mlx_kem.rs:129` | `malloc`; writes `libctx`, `key`, `op` | all three fields; E body |
| `X509PolicyCache` `pcy_cache.rs:307` | `malloc`; writes `anyPolicy`, `data`, `any_skip`, `explicit_skip`, `map_skip` | both destructor-read pointers + skip words |
| `BioLineBufferCtx` `bf_lbuf.rs:134` | `malloc`; writes `obuf`, `obuf_size`, `obuf_len`; the `obuf` failure returns while the block is still a `RawCtx` | all three fields written before `assume_init`; the body takes `obuf` (NULL or owned) |

### 2.3 `malloc_at` staged records (4 sites)

| type / site | constructor and writes | witness |
|---|---|---|
| `ByDirEntry` `by_dir.rs:520` | `malloc_at`; writes `dir_type`, `hashes`, `dir` | all three; `dir`/`hashes` NULL checked after transition before push |
| `ByDirHash` `by_dir.rs:761` | `malloc_at`; writes `hash`, `suffix` | both; failed push re-points release to `LINE_FREE_HASH_PUSH` |
| `X509V3ExtMethod` `v3_lib.rs:589` | `malloc_at`; `ptr::write(p, ptr::read(ext))`, then `ext_nid`, `ext_flags` | whole row copied + two fields; destroy body is empty (E) |
| `X509CrlMethod` `x_crl.rs:1293` | `malloc_at`; writes `flags`, four callbacks | all five fields |

### 2.4 Copy/duplication transition (1 site)

`ProvSm2Ctx` `sm2_enc.rs:284`: `zalloc_at`, `ptr::copy_nonoverlapping(srcctx,
dstctx, 1)`, `md` reset to the all-NULL digest, `EC_KEY_up_ref` taken on a
non-NULL borrowed key; only then `assume_init`. Failure of the up-ref returns
while the handle is still a `RawCtx` (block-only release). The later
`ossl_prov_digest_copy` runs on a fully valid `T`; a failure drops it through
the destructor, which releases the up-ref and the reset digest.

**No panic-window defect was found.** Every staged constructor either (a) keeps
the block as `RawCtx` until the last destructor-visible write, or (b) validates
a zeroed block whose impl has a zero-validity witness. The only post-
`assume_init` fallible steps (`by_dir` stack push, `v3_lib` `X509V3_EXT_add`,
`sm2_enc` digest copy) run on a fully valid `T` and drop through the normal
destructor. Test-only `assert!`s (`eng_table.rs:629,689`) are `cfg(test)`.

---

## 3. `from_raw` / `from_raw_at` witnesses

### 3.1 Matching `into_raw` round-trips (majority)

For the safe-constructor family the block is allocated and published in the
same module: `OwnedCtx::zalloc(/zalloc_at)` or `RawCtx::zalloc(/malloc)` →
writes/`assume_init` → `into_raw` → C ABI → `from_raw(_at)` in the destroy
function. The release coordinates are the impl's `LINE_FREE` for the generic
`from_raw` sites, and the explicit constants at the `zalloc_at`/`malloc_at`/
`set_release_line` sites. Examples checked against 3.6.4:

- `x509/x509_lu.rs` `X509Object`: alloc 481 / free 530; `LINE_FREE_OBJECT=530`
  and the dup-failure arm `LINE_FREE_OBJECT_DUP=595` match `x509_object_dup`.
- `x509/x509_lu.rs` `X509Lookup` and `X509Store`: free lines 39 and 253 match
  `LINE_FREE_LOOKUP`/`LINE_FREE_STORE`.
- `x509/by_dir.rs`: `ByDir` 110/163, `ByDirEntry` 153, `ByDirHash` 136 and the
  failed-push 399 all match `by_dir.c`.
- `x509/v3_purp.rs` `X509Purpose`: 205/271 match `v3_purp.c`.
- `x509/x509_trust.rs` `X509Trust`: 142/192 match `x509_trust.c`.
- `x509/v3_utl.rs` `ConfValue`: 57 allocation, 111 free match `v3_utl.c`.
- `engine/eng_dyn.rs` `DynamicDataCtx`: 159 allocation, 147 normal free, 193
  error free match `eng_dyn.c`.
- `provider/keymgmt.rs` `DhGenCtx`: 463 allocation, 485 error free, 828 normal
  free match `dh_kmgmt.c`.
- `rand/rand_lib.rs` `RandGlobal`: 513 allocation, 567 free match `rand_lib.c`.
- `ui/ui_lib.rs` `UiString` 68, `Ui`/`UiMethod` constructor and destroy sites
  match `ui_lib.c`.
- `ec/ecx_key.rs` `EcxKey`: 23 allocation, 60 error free, 83 normal free.
- `provider/sm2_enc.rs` `ProvSm2Ctx`: 57/135 and 143/152/135.
- `ssl/ssl_sess.rs` `SslSession`: 109/140 allocation, 930 free.
- `x509/x509_vfy.rs` `X509StoreCtx`: 2695/2704 constructor, 2726 free.
- `hpke/mod.rs` `OsslHpkeCtx`: 831/858 constructor, 878 free.

### 3.2 C-ABI / module-local-owner blocks

The following `from_raw(_at)` sites adopt a block whose construction is a
module-local owner or a direct `CRYPTO_*` call, not the shared `RawCtx`. The
`from_raw` contract explicitly permits a "C-ABI-owned block"; each source has
the provenance, initialisation and exclusive-ownership comment:

`DynamicDataCtx` (local `RawDynamicDataCtx`), `DhGenCtx` (local
`RawDhGenCtx`), `RandGlobal` (local `RawGlobal`), `EvpPkey` (local `RawPkey`),
`X509Lookup`/`X509Store` (local `RawLookup`/`RawStore`), `ByDir` (direct
`CRYPTO_malloc`), `X509Purpose`/`X509Trust` (direct `CRYPTO_malloc`),
`ConfValue` (module-local `OwnedBlock<u8>` then `into_raw`), `EvpKeyExch`
(direct `CRYPTO_zalloc` in `evp_keyexch_new`). These are `ESTABLISHED` as
`from_raw` sites but the construction transition is **outside OB-3**; the
shared boundary is only the reclaim.

### 3.3 Release coordinates — re-derived and `ESTABLISHED`

The three production `from_raw_at` sites that previously failed the coordinate
half of the witness now use the authority's own free sites, and each pointer is
the matching transfer:

| reclaim | published by | witness |
|---|---|---|
| `evp/pkey.rs:669` | `EVP_PKEY_new` → `RawPkey::finish` | §3.2 local owner; `down_ref` observes `Last`, so this is the one reclaim of the block; `p_lib.c:1851` |
| `evp/pkey_ctx.rs:1002` | `int_ctx_new` / `EVP_PKEY_CTX_dup` → `OwnedCtx::into_raw` | `EVP_PKEY_CTX_free` NULL-checks then reclaims; `pmeth_lib.c:410` |
| `evp/digest.rs:805` | `evp_md_new` → `OwnedCtx::into_raw` | `evp_md_free_int` runs only on the last `refcnt`; `evp_lib.c:866` |
| `context/mod.rs:1294` | `OSSL_LIB_CTX_new` → `assume_init` → `OwnedCtx::into_raw` | default contexts return early; `context.c:495` |

All other `from_raw(_at)` sites are `ESTABLISHED` on the source witness, not
independently re-derived; the remaining coordinate checks are a retained
evidence gap (§7).

---

## 4. `malloc` / `malloc_at` witnesses

| site | writes before `assume_init` | failure path |
|---|---|---|
| `dsa/pmeth.rs:126` | `nbits`, `qbits`, `pmd`, `gentmp`, `md` | `RawCtx::Drop` block-only; no `OwnedCtx` formed |
| `engine/eng_table.rs:241` | `uptodate`, `nid`, `sk`; `funct=NULL` after `sk` success | `sk` NULL → `drop(raw)` block-only |
| `modes/ocb.rs:207` | `CRYPTO_ocb128_init` fills the block | init false → `RawCtx` drops block-only |
| `decode_pvk2key.rs:142` | `write_bytes(0)`, `provctx`, `desc` | no fallible step between write and transition |
| `ml_kem_kem.rs:114` | `write_bytes(0)`, `key`, `entropy`, `op` | no fallible step |
| `mlx_kem.rs:118` | `libctx`, `key`, `op` | no fallible step |
| `runtime/bio/core_bio.rs:123` | `ref_cnt`; `bio` intentionally uninitialised until the C constructor | `into_raw` (no `assume_init`); E body |
| `x509/pcy_cache.rs:293` | `anyPolicy`, `data`, three skips | no fallible step between write and transition |
| `x509/by_dir.rs:503` | `dir_type`, `hashes`, `dir` | after transition; failure drops a valid record, fields may be NULL and the body accepts NULL |
| `x509/by_dir.rs:743` | `hash`, `suffix` | after transition; failed push sets the error release line then drops |
| `x509/v3_lib.rs:573` | whole row `ptr::write` + `ext_nid`/`ext_flags` | after transition; E body |
| `x509/x_crl.rs:1275` | `flags`, four callbacks | no fallible step |

No `malloc`/`malloc_at` failure path forms an `OwnedCtx` over uninitialised
storage: the staged handle is a `RawCtx` until the transition and its `Drop`
releases the block alone.

---

## 5. `CtxDestroy` cross-reference and zero-validity

`DESTRUCTOR-CONTRACTS.md` records **199 implementations, 0 `CONTRACTED`, 199
`ESTABLISHED`**, including 136 `CtxDestroy` rows. At HEAD the 130 production
shared-trait impls correspond one-for-one by type to those rows; the 6
module-local impls (`EcGroup`, `EcPoint`, `Cert`, `SslCtx`, `Ssl`,
`DanetlsRecord`) and the 2 test-only `ProbeCtx` impls are excluded from the shared
count. No shared impl is missing from the 199-row inventory.

**Zero-validity witness.** Every shared impl states that an all-zero `Self` is
valid and that its `destroy_body` is sound on it. The bodies were scanned for
unconditional member dereferences:

- The only unconditional member dereference is `Ui::destroy_body`'s
  `(*(*ptr).meth).ui_destroy_data`, which is behind
  `(*ptr).flags & UI_FLAG_DUPL_DATA`; an all-zero block has `flags == 0`, so the
  dereference is unreachable. `Ui` sets the flag only after `meth` is live.
- `MlDsaGenCtx`/`SlhDsaGenCtx` use `(*ptr).entropy.as_mut_ptr()` and
  `SslSession` uses `master_key`/`session_id` arrays; these are embedded arrays,
  valid at zero.
- `PropqSlot::of(&mut *ptr)` in `CachedStore`/`X509StoreCtx` forms a reference to
  a zeroed record of pointers/scalars; the records have no invalid zero state.
- All other bodies either pass NULL-able members to NULL-tolerant releasers or
  guard with `is_null()`.

**No zero-validity defect was found in the shared impls. One destructor-
completeness defect and three release-coordinate defects were found; all four
are fixed and re-audited in §6.**

---

## 6. Defects and unattributed boundary items

### D1 — `EvpPkey::destroy_body` omitted the `attributes` release (fixed)

**Authority:** `EVP_PKEY_free` (`p_lib.c:1830-1852`) runs `evp_pkey_free_it`,
`CRYPTO_free_ex_data`, `CRYPTO_THREAD_lock_free`, `CRYPTO_FREE_REF`, then
`sk_X509_ATTRIBUTE_pop_free(x->attributes, X509_ATTRIBUTE_free)` (`:1849`), then
`OPENSSL_free(x)` (`:1851`).

**Change:** `CtxDestroy for EvpPkey::destroy_body`
(`src/evp/pkey.rs:421-448`) now calls
`OPENSSL_sk_pop_free((*ptr).attributes, Some(free_x509_attribute))` after the
lock release, so the stack and each element are released exactly once, in the
authority's order and before `Drop`'s block release. `free_x509_attribute` calls
`X509_ATTRIBUTE_free`. The field is reachable through `EVP_PKEY_add1_attr*` in
`src/evp/evp_pkey.rs`; the module and field documentation now says so.

**Test:** `evp::pkey::tests::an_attribute_is_released_exactly_once_with_the_key`
adds one attribute with `EVP_PKEY_add1_attr_by_NID`, asserts the key reports one
attribute, frees the key, and observes exactly one element-destructor invocation
on the freeing thread. `DESTRUCTOR-CONTRACTS.md`'s `EvpPkey` rows now include the
member.

### D2 — `EvpPkey` release coordinates (fixed; allocator-seam divergence)

**Authority:** `EVP_PKEY_new`'s error label frees at `p_lib.c:1520`;
`EVP_PKEY_free` frees the block at `p_lib.c:1851`.

**Change:** `LINE_FREE_PKEY_CTOR = 1520` and `LINE_FREE_PKEY = 1851` are now
separate from `LINE_ZALLOC_PKEY = 1491`. `RawPkey::Drop` (constructor refusal)
uses 1520; `EVP_PKEY_free`'s `from_raw_at` (`src/evp/pkey.rs:669`) uses 1851.

### D3 — `EvpPkeyCtx` release/allocation coordinates (fixed; allocator-seam divergence)

**Authority:** `int_ctx_new` allocates at `pmeth_lib.c:297` and its propquery
`OPENSSL_strdup` at `:310`; the propquery-failure block free is `:312`.
`EVP_PKEY_CTX_free` frees `propquery` at `:403` and the block at `:410`.
`EVP_PKEY_CTX_dup` allocates the duplicate at `:463` and its propquery at `:476`,
releasing through `EVP_PKEY_CTX_free` (`:410`).
`evp_pkey_ctx_free_cached_data` frees the two cached members at `:1521`/`:1522`.

**Change:** `evp/pkey_ctx.rs` now uses `LINE_ZALLOC_CTX = 297`,
`LINE_ZALLOC_CTX_PROPQUERY = 310`, `LINE_FREE_CTX_CTOR = 312`,
`LINE_FREE_CTX = 410`, `LINE_FREE_CTX_PROPQUERY = 403`,
`LINE_ZALLOC_CTX_DUP = 463`, `LINE_ZALLOC_CTX_DUP_PROPQUERY = 476`, and
`LINE_FREE_CACHED_DIST_ID{,_NAME} = 1521/1522`. `int_ctx_new` keeps 312 for the
propquery refusal and calls `set_release_line(410)` before the `pkey` up-ref, the
first refusal that runs `EVP_PKEY_CTX_free`'s body. `EVP_PKEY_CTX_free`
(`:1002`) and every dup refusal use 410.

### D4 — `EvpMd` free-site file (fixed; allocator-seam divergence)

**Authority:** `evp_md_free_int` is in `crypto/evp/evp_lib.c`: `type_name` is
freed at `:863` and the block at `:866`. The allocation, `evp_md_new`'s
`OPENSSL_zalloc`, is `crypto/evp/digest.c:944`; its constructor-refusal
`OPENSSL_free(md)` is `digest.c:947`. The converted constructor has no fallible
step after the allocation (`CRYPTO_NEW_REF` is infallible), so that failure drop
is **unreachable**; `LINE_FREE_MD_ON_NEW = 947` records the authority's failure
site separately from the normal `LINE_FREE_MD = 866`.

**Change:** `evp/digest.rs` adds `FILE_EVP_LIB` / `FILE_EVP_LIB_SEAM` for the two
releases: `evp_md_free_int`'s `from_raw_at` (`:796`) and `destroy_body`'s
`type_name` free (`:816`) now report `evp_lib.c`. The allocation coordinates stay
`digest.c` / `LINE_ZALLOC_MD = 944`. (The crate's `evp_md_new` has no fallible
step after the allocation, so its `zalloc_at` release coordinates are not
observed; they point at the object's own release site, `evp_lib.c:866`.)

### UNATTRIBUTED transitions (0)

The four items recorded by the first audit are resolved:

1. `src/evp/pkey.rs:669` — D2 coordinate witness re-derived (`p_lib.c:1851`).
2. `src/evp/pkey_ctx.rs:1002` — D3 coordinate witness re-derived (`pmeth_lib.c:410`).
3. `src/evp/digest.rs:805` — D4 file witness re-derived (`evp_lib.c:866`).
4. `src/context/mod.rs:1094` — now `src/context/mod.rs:1099`: `OSSL_LIB_CTX_new`
   calls `RawCtx::assume_init` after `context_init` succeeds (the allocator zeroed
   the block and `context_init` wrote every slot it builds), then `into_raw`.
   `OSSL_LIB_CTX_free` (`:1294`) reclaims with
   `OwnedCtx::<OsslLibCtx>::from_raw_at(ctx, context.c, 495)`, so the
   `CtxDestroy for OsslLibCtx` body (child deregistration + `context_deinit`) is
   the same teardown the authority performs, followed by the block release. The
   block-only publication and the hand-written teardown are gone.

### Boundary bypasses (not transition counts; no UB identified)

- `evp/pkey_asn1.rs:711` (`EVP_PKEY_asn1_free`) calls
  `<EvpPkeyAsn1Method as CtxDestroy>::destroy_body` + `CRYPTO_free` by hand; the
  block was published by `OwnedCtx::into_raw` but never reclaimed through
  `from_raw`.
- `rsa/object.rs:705` (`RSA_free`) does the same for `Rsa` after the refcount
  gate.
- `modes/ocb.rs:211` publishes a `malloc`ed `OcbCtx` with `RawCtx::into_raw`
  after `CRYPTO_ocb128_init` success, and there is no in-crate `from_raw` free
  edge; the C caller owns the `CRYPTO_ocb128_cleanup` + free obligation. The
  publication witness is init-success + exclusive transfer, so it is counted
  `ESTABLISHED`, but the reclaim is external.
- `runtime/bio/core_bio.rs:136` publishes a `malloc`ed `OsslCoreBio` with
  `RawCtx::into_raw` leaving `bio` uninitialised; the destructor body is empty
  and `ossl_core_bio_free` runs `BIO_free(cb->bio)` explicitly, so the owner
  transition is not used to run the body.

---

## 7. Limits of this audit

- **This document itself is a static, source-witness audit.** No sanitizer, no
  differential court and no SMT/model check was run for it. The `ESTABLISHED`
  status is the same source-witness status used in `DESTRUCTOR-CONTRACTS.md`;
  nothing here is `SAFETY_DISCHARGED`. Executable zero-state, ASan and Miri
  evidence is recorded separately in `OB3-CHECKS.md` §4, §5 and §8.3.
- Release-coordinate witnesses are re-derived in §9: all **121** production
  `from_raw(_at)` sites are listed with their claimed authority file:line. **76**
  are `VERIFIED`; **45** are `UNVERIFIED` because the recorded coordinate is a
trait-default `(NULL, 0)` (or a template-only `.c.in` line), and each such row
  states the reason and the authority line that was found.
- The 130 shared `CtxDestroy` impls were mapped by type name to the 199-row
  inventory; the inventory's line numbers are from an earlier source identity
  and have shifted (for example `EvpMd` and `OsslEncoder`). The mapping is
  type-based, not line-based.
- `DESTRUCTOR-CONTRACTS.md`'s `EvpPkey` rows now include
  `sk_X509_ATTRIBUTE_pop_free(attributes)` and the shared impl's zero-validity
  claim; the omission and the stale "no zero-validity claim" note are fixed.
- The audit did not run the full Phase-25 forensic regeneration; that remains a
  seal-point activity.

---

## 8. ABI constructor/release pairings (re-audit addendum)

The independent ABI scan flagged three entries as lacking a *same-file*
structural witness. Re-derivation shows each has a matching constructor and
release; the scan predicate was too narrow (it looked only for a same-file
`from_raw`/`assume_init`, so it did not count `from_raw_at`, the direct
`CtxDestroy::destroy_body` + `CRYPTO_free` pairing, or a release in another
file). No source change was required.

| ABI entry | constructor / owner | publication | matching release | verdict |
|---|---|---|---|---|
| `EVP_KEYEXCH_free` (`src/evp/exchange.rs:490`) | `evp_keyexch_new` (`:339`) allocates `size_of::<EvpKeyExch>()` with `CRYPTO_zalloc(..., FILE, LINE_ZALLOC_KEYEXCH)` at `:341-345`; the constructor sets `refcnt = AtomicI32::new(1)` in the same block; the owner is the fetch framework's single reference | `evp_keyexch_from_algorithm` returns `exchange.cast::<c_void>()` at `:482` | `OwnedCtx::from_raw_at(exchange, FILE_SEAM, LINE_FREE_KEYEXCH)` at `:505`; the up-ref failure path uses `CRYPTO_free(..., LINE_FREE_KEYEXCH_UP_REF)` at `:359`, and the refusal paths call `EVP_KEYEXCH_free` at `:394,478` | matching allocation and release; `ESTABLISHED` |
| `EVP_PKEY_asn1_new` (`src/evp/pkey_asn1.rs:598`) | `OwnedCtx::<EvpPkeyAsn1Method>::zalloc()` at `:608`; owner `ameth` | `ameth.into_raw()` at `:641` | `EVP_PKEY_asn1_free` (`:699`) gates on `ASN1_PKEY_DYNAMIC`, then `<EvpPkeyAsn1Method as CtxDestroy>::destroy_body(ameth)` at `:711` and `CRYPTO_free(ameth, FILE, LINE_FREE_AMETH)` at `:712`; the impl's `LINE_ALLOC` is `LINE_ZALLOC_AMETH` and its `LINE_FREE` is `LINE_FREE_AMETH` | matching allocation and release; `ESTABLISHED` |
| `OSSL_STORE_LOADER_new` (`src/store/store_register.rs:251`) | `OwnedCtx::<OsslStoreLoader>::zalloc()` at `:265`; owner `res` | `res.into_raw()` at `:275` (the C caller then owns the loader) | `OSSL_STORE_LOADER_free` (`src/store/store_meth.rs:211`) calls `OwnedCtx::<OsslStoreLoader>::from_raw(loader)` at `:232`; the legacy loader has `prov == NULL`, so the refcount branch is skipped and this is the unique release | matching allocation and release; `ESTABLISHED` |

For the provider-created loader, `new_loader` (`store_meth.rs:243`) uses the
same `OwnedCtx::<OsslStoreLoader>::zalloc()` owner (`:244`), publishes with
`loader.into_raw()` (`:258`), and is reclaimed by the same
`OSSL_STORE_LOADER_free` release; only its `prov`/`refcnt` initialisation
differs.


---

## 9. Release-coordinate re-derivation (2026-10-18)

Every production reclaim site in §1.2/§1.3 was re-derived against
`forensics/authorities/src/openssl-3.6.4/` by reading the authority's
`OPENSSL_free` / `CRYPTO_free` / `OPENSSL_clear_free` line. The 121 rows below
are the 41 production `from_raw_at` and 80 production `from_raw` sites; the
test-only `src/dso/mod.rs:1100` is excluded. **76 rows are `VERIFIED`; 45 are
`UNVERIFIED` and state the reason.** A coordinate is `VERIFIED` only when the
claimed file:line contains the block release (not a member release).

`into_raw` is a publication, not a release, so it has no release coordinate of
its own: each of the **132** production `into_raw` sites (§1.5) pairs with the
same-type reclaim row below. Four publications were missing from the first
inventory and are now included: `src/async/async_wait.rs:182`,
`src/evp/digest.rs:1899`, `src/property/globals.rs:133` and
`src/store/store_register.rs:275`; the 13 shared-owner BIO caller modules of
§1.7 supply the remaining 13. The corrected production total is
**304** (28 + 80 + 41 + 9 + 4 + 132 + 10), not 274. The 10 `set_release_line`
sites include the two `EnginePile` refusal re-points at
`engine/eng_table.rs:259,281`, which the first pass counted as eight.

| Rust reclaim | release fn | type | claimed authority coordinate | verified authority text / status |
|---|---|---|---|---|
| `src/asn1/x_info.rs:126` | `from_raw` | `X509Info` | `crypto/asn1/x_info.c:36` | VERIFIED — `OPENSSL_free(x);` |
| `src/asn1/x_pkey.rs:159` | `from_raw` | `X509Pkey` | `crypto/asn1/x_pkey.c:45` | VERIFIED — `OPENSSL_free(x);` |
| `src/async/async_wait.rs:195` | `from_raw_at` | `AsyncWaitCtx` | `crypto/async/async_wait.c:41` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/cmp/cmp_ctx.rs:606` | `from_raw` | `OsslCmpCtx` | `crypto/cmp/cmp_ctx.c:244` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/cmp/cmp_server.rs:188` | `from_raw` | `OsslCmpSrvCtx` | `crypto/cmp/cmp_server.c:45` | VERIFIED — `OPENSSL_free(srv_ctx);` |
| `src/context/core_bio.rs:132` | `from_raw` | `BioCoreGlobals` | `crypto/bio/bss_core.c:27` | VERIFIED — `OPENSSL_free(vbcg);` |
| `src/context/mod.rs:1294` | `from_raw_at` | `OsslLibCtx` | `crypto/context.c:495` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/context/thread_data.rs:164` | `from_raw` | `OsslLibCtxThreads` | `crypto/thread/internal.c:156` | VERIFIED — `OPENSSL_free(t);` |
| `src/ct/ct_log.rs:352` | `from_raw_at` | `CtlogStore` | `NULL, 0` | UNVERIFIED — crate records `(NULL, 0)`; authority `CTLOG_STORE_free` frees at `crypto/ct/ct_log.c:136` (and failure path `:134`). |
| `src/ct/ct_log.rs:623` | `from_raw_at` | `Ctlog` | `NULL, 0` | UNVERIFIED — crate records `(NULL, 0)`; authority `CTLOG_free` frees at `crypto/ct/ct_log.c:297`. |
| `src/ct/ct_policy.rs:194` | `from_raw` | `CtPolicyEvalCtx` | none recorded | UNVERIFIED — impl leaves FILE/LINE_FREE at the trait default (NULL, 0); authority `CT_POLICY_EVAL_CTX_free` frees at `crypto/ct/ct_policy.c:65`. |
| `src/ct/ct_sct.rs:228` | `from_raw_at` | `Sct` | `NULL, 0` | UNVERIFIED — crate records `(NULL, 0)`; authority `SCT_free` frees at `crypto/ct/ct_sct.c:43`. |
| `src/ct/ct_sct_ctx.rs:154` | `from_raw_at` | `SctCtx` | `NULL, 0` | UNVERIFIED — crate records `(NULL, 0)`; authority `SCT_CTX_free` frees at `crypto/ct/ct_sct_ctx.c:52`. |
| `src/decoder_lib.rs:391` | `from_raw` | `OsslDecoderInstance` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `ossl_decoder_instance_free` frees at `crypto/encode_decode/decoder_lib.c:309`. |
| `src/decoder_meth.rs:852` | `from_raw` | `OsslDecoderCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `OSSL_DECODER_CTX_free` frees at `crypto/encode_decode/decoder_meth.c:673`. |
| `src/dh/object.rs:401` | `from_raw` | `Dh` | `crypto/dh/dh_lib.c, 0` | UNVERIFIED — impl records `(crypto/dh/dh_lib.c, 0)`; authority normal free `:164`, constructor-failure frees `:84`/`:90`; no single line is recorded. |
| `src/dh/pmeth.rs:205` | `from_raw` | `DhPkeyCtx` | `crypto/dh/dh_pmeth.c:79` | VERIFIED — `OPENSSL_free(dctx);` |
| `src/dsa/object.rs:339` | `from_raw` | `Dsa` | `crypto/dsa/dsa_lib.c, 0` | UNVERIFIED — impl records `(crypto/dsa/dsa_lib.c, 0)`; authority normal free `:241`, constructor-failure frees `:142`/`:148`; no single line is recorded. |
| `src/dsa/pmeth.rs:191` | `from_raw` | `DsaPkeyCtx` | `crypto/dsa/dsa_pmeth.c:74` | VERIFIED — `OPENSSL_free(dctx);` |
| `src/dso/mod.rs:348` | `from_raw_at` | `?` | `crypto/dso/dso_lib.c:78` | VERIFIED — `OPENSSL_free(dso);` |
| `src/ec/ecdsa.rs:304` | `from_raw` | `EcdsaSig` | `crypto/ec/ec_asn1.c:1200` | VERIFIED — `OPENSSL_free(sig);` |
| `src/ec/ecx_key.rs:205` | `from_raw_at` | `EcxKey` | `crypto/ec/ecx_key.c:83` | VERIFIED — `OPENSSL_free(key);` |
| `src/ec/mult.rs:184` | `from_raw` | `EcPreCompSt` | `crypto/ec/ec_mult.c:101` | VERIFIED — `OPENSSL_free(pre);` |
| `src/ec/pmeth.rs:285` | `from_raw` | `EcPkeyCtx` | `crypto/ec/ec_pmeth.c:99` | VERIFIED — `OPENSSL_free(dctx);` |
| `src/encoder_lib.rs:532` | `from_raw` | `?` | none recorded | UNVERIFIED — type `OsslEncoderInstance`, trait default (NULL, 0); authority free `crypto/encode_decode/encoder_lib.c:276`. |
| `src/encoder_meth.rs:353` | `from_raw` | `?` | none recorded | UNVERIFIED — type `OsslEncoder`, trait default (NULL, 0); authority free `crypto/encode_decode/encoder_meth.c:74`. |
| `src/encoder_meth.rs:1351` | `from_raw` | `?` | none recorded | UNVERIFIED — type `OsslEncoderCtx`, trait default (NULL, 0); authority free `crypto/encode_decode/encoder_meth.c:652`. |
| `src/engine/eng_dyn.rs:410` | `from_raw_at` | `DynamicDataCtx` | `crypto/engine/eng_dyn.c:147` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/engine/eng_table.rs:410` | `from_raw` | `EnginePile` | `crypto/engine/eng_table.c:184` | VERIFIED — `OPENSSL_free(p);` |
| `src/evp/asymcipher.rs:475` | `from_raw_at` | `EvpAsymCipher` | `crypto/evp/asymcipher.c:497` | VERIFIED — `OPENSSL_free(cipher);` |
| `src/evp/cipher.rs:906` | `from_raw` | `EvpCipher` | `crypto/evp/evp_enc.c:2118` | VERIFIED — `OPENSSL_free(cipher);` |
| `src/evp/cipher_ctx.rs:455` | `from_raw` | `EvpCipherCtx` | `crypto/evp/evp_enc.c:89` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/evp/digest.rs:805` | `from_raw_at` | `EvpMd` | `crypto/evp/evp_lib.c:866` | VERIFIED — `OPENSSL_free(md);` |
| `src/evp/digest.rs:1969` | `from_raw_at` | `EvpMdCtx` | `crypto/evp/digest.c:140` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/evp/encode.rs:278` | `from_raw` | `EvpEncodeCtx` | `crypto/evp/encode.c:125` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/evp/exchange.rs:505` | `from_raw_at` | `?` | `crypto/evp/exchange.c:173` | VERIFIED — `OPENSSL_free(exchange);` |
| `src/evp/kem.rs:408` | `from_raw` | `EvpKem` | `crypto/evp/kem.c:446` | VERIFIED — `OPENSSL_free(kem);` |
| `src/evp/keymgmt.rs:772` | `from_raw` | `EvpKeyMgmt` | `crypto/evp/keymgmt_meth.c:307` | VERIFIED — `OPENSSL_free(keymgmt);` |
| `src/evp/pkey.rs:669` | `from_raw_at` | `EvpPkey` | `crypto/evp/p_lib.c:1851` | VERIFIED — `OPENSSL_free(x);` |
| `src/evp/pkey_ctx.rs:1002` | `from_raw_at` | `EvpPkeyCtx` | `crypto/evp/pmeth_lib.c:410` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/evp/pkey_ctx.rs:2192` | `from_raw_at` | `EvpPkeyMethod` | `crypto/evp/pmeth_lib.c:439` | VERIFIED — `OPENSSL_free(pmeth);` |
| `src/evp/rand.rs:712` | `from_raw` | `EvpRand` | `crypto/evp/evp_rand.c:76` | VERIFIED — `OPENSSL_free(rand);` |
| `src/evp/skeymgmt.rs:579` | `from_raw` | `EvpSkeyMgmt` | `crypto/evp/skeymgmt_meth.c:172` | VERIFIED — `OPENSSL_free(skeymgmt);` |
| `src/hpke/mod.rs:2507` | `from_raw_at` | `OsslHpkeCtx` | `crypto/hpke/hpke.c:878` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/mac/hmac.rs:430` | `from_raw` | `HmacCtx` | `crypto/hmac/hmac.c:196` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/property/globals.rs:120` | `from_raw` | `OsslGlobalProperties` | `crypto/property/property.c:120` | VERIFIED — `OPENSSL_free(globp);` |
| `src/provider/child.rs:238` | `from_raw` | `ChildProvGlobals` | `crypto/provider_child.c:47` | VERIFIED — `OPENSSL_free(gbl);` |
| `src/provider/conf.rs:228` | `from_raw_at` | `ProviderConfGlobal` | `crypto/provider_conf.c:55` | VERIFIED — `OPENSSL_free(pcgbl);` |
| `src/provider/ctx.rs:112` | `from_raw` | `ProvCtx` | none recorded | UNVERIFIED — impl records `(providers/common/provider_ctx.c, 0)`; authority zalloc `:17`, free `:22`. |
| `src/provider/decode_epki2pki.rs:133` | `from_raw` | `Epki2pkiCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority free `decode_epki2pki.c.in:60`. |
| `src/provider/decode_pem2der.rs:324` | `from_raw` | `Pem2DerCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority free `decode_pem2der.c.in:80`. |
| `src/provider/decode_pvk2key.rs:164` | `from_raw` | `Pvk2keyCtx` | none recorded | UNVERIFIED — impl records `(NULL, 0)`; authority free `decode_pvk2key.c.in:90`. |
| `src/provider/decode_spki2typespki.rs:119` | `from_raw` | `Spki2TypespkiCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority free `decode_spki2typespki.c.in:59`. |
| `src/provider/ec_kem.rs:390` | `from_raw` | `ProvEcCtx` | `providers/implementations/kem/ec_kem.c.in:216` | UNVERIFIED — claimed `:216`; pinned authority has only `ec_kem.c.in`, whose block free is `:218`; the generated unit is absent. |
| `src/provider/ecx_kmgmt.rs:1550` | `from_raw` | `EcxGenCtx` | `providers/implementations/keymgmt/ecx_kmgmt.c.in:1413` | UNVERIFIED — claimed `:1413`; pinned authority has only `ecx_kmgmt.c.in`, whose `gctx` free is `:900`; the generated unit is absent. |
| `src/provider/encode_key2any.rs:1903` | `from_raw` | `?` | none recorded | UNVERIFIED — type `Key2anyCtx`, trait default (NULL, 0); authority free `encode_key2any.c.in:1130`. |
| `src/provider/encode_key2ms.rs:123` | `from_raw` | `Key2msCtx` | none recorded | UNVERIFIED — impl records `(NULL, 0)`; authority free `encode_key2ms.c.in:96`. |
| `src/provider/file_store.rs:257` | `from_raw` | `FileCtxSt` | none recorded | UNVERIFIED — impl records `(NULL, 0)`; authority free `file_store.c.in:127`. |
| `src/provider/file_store_any2obj.rs:128` | `from_raw` | `Any2objCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority free `file_store_any2obj.c.in:72`. |
| `src/provider/keymgmt.rs:253` | `from_raw_at` | `KdfData` | `providers/implementations/keymgmt/kdf_legacy_kmgmt.c:61` | VERIFIED — `OPENSSL_free(kdfdata);` |
| `src/provider/keymgmt.rs:1625` | `from_raw_at` | `DhGenCtx` | `providers/implementations/keymgmt/dh_kmgmt.c:828` | VERIFIED — `OPENSSL_free(gctx);` |
| `src/provider/mac_legacy_kmgmt.rs:328` | `from_raw` | `MacKey` | `providers/implementations/keymgmt/mac_legacy_kmgmt.c:100` | VERIFIED — `OPENSSL_free(mackey);` |
| `src/provider/mac_legacy_kmgmt.rs:988` | `from_raw` | `MacGenCtx` | `providers/implementations/keymgmt/mac_legacy_kmgmt.c:524` | VERIFIED — `OPENSSL_free(gctx);` |
| `src/provider/ml_dsa_kmgmt.rs:1059` | `from_raw` | `MlDsaGenCtx` | `providers/implementations/keymgmt/ml_dsa_kmgmt.c.in:867` | UNVERIFIED — claimed `:867`; pinned authority has only `ml_dsa_kmgmt.c.in`, whose `gctx` free is `:570`; the generated unit is absent. |
| `src/provider/ml_kem_kem.rs:141` | `from_raw` | `ProvMlKemCtx` | `providers/implementations/kem/ml_kem_kem.c.in:65` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/provider/mlx_kem.rs:141` | `from_raw` | `ProvMlxKemCtx` | `providers/implementations/kem/mlx_kem.c:53` | VERIFIED — `OPENSSL_free(vctx);` |
| `src/provider/rsa_kem.rs:199` | `from_raw` | `ProvRsaCtx` | `providers/implementations/kem/rsa_kem.c.in:112` | VERIFIED — `OPENSSL_free(prsactx);` |
| `src/provider/seed_src.rs:290` | `from_raw` | `ProvSeedSrc` | `providers/implementations/rands/seed_src.c.in:72` | VERIFIED — `OPENSSL_free(vseed);` |
| `src/provider/seed_src.rs:774` | `from_raw` | `ProvTestRng` | `providers/implementations/rands/test_rng.c.in:83` | UNVERIFIED — claimed `:83` (`OPENSSL_free(t->nonce)` in the template); pinned `.c.in` block free is `:85`; the generated unit is absent. |
| `src/provider/skeymgmt.rs:147` | `from_raw` | `ProvSkey` | `providers/implementations/skeymgmt/generic.c.in, 0` | UNVERIFIED — impl records `(NULL, 0)`; authority free `generic.c.in:35`. |
| `src/provider/slh_dsa_kmgmt.rs:844` | `from_raw` | `SlhDsaGenCtx` | `providers/implementations/keymgmt/slh_dsa_kmgmt.c.in:300` | VERIFIED — `OPENSSL_free(gctx);` |
| `src/provider/sm2_enc.rs:242` | `from_raw_at` | `ProvSm2Ctx` | `providers/implementations/asymciphers/sm2_enc.c.in:135` | VERIFIED — `OPENSSL_free(psm2ctx);` |
| `src/rand/rand_lib.rs:465` | `from_raw_at` | `RandGlobal` | `crypto/rand/rand_lib.c:567` | VERIFIED — `OPENSSL_free(dgbl);` |
| `src/rsa/mp.rs:99` | `from_raw` | `RsaPrimeInfo` | `crypto/rsa/rsa_mp.c, 0` | UNVERIFIED — impl records `(crypto/rsa/rsa_mp.c, 0)`; authority normal free `:54`, constructor-failure free `:19`. |
| `src/rsa/pmeth.rs:370` | `from_raw` | `RsaPkeyCtx` | `crypto/rsa/rsa_pmeth.c:130` | VERIFIED — `OPENSSL_free(rctx);` |
| `src/runtime/bio/bf_buff.rs:180` | `from_raw` | `BioBufferCtx` | `NULL, 0` | UNVERIFIED — impl leaves FILE/LINE_FREE at the trait default; authority `buffer_free` frees at `crypto/bio/bf_buff.c:80` (ibuf `:78`, obuf `:79`). |
| `src/runtime/bio/bf_lbuf.rs:153` | `from_raw` | `BioLineBufferCtx` | `NULL, 0` | UNVERIFIED — trait default; authority `linebuffer_free` frees at `crypto/bio/bf_lbuf.c:84` (obuf `:83`). |
| `src/runtime/bio/bf_nbio.rs:173` | `from_raw` | `NbioTest` | `NULL, 0` | UNVERIFIED — trait default; authority `nbiof_free` frees at `crypto/bio/bf_nbio.c:71`. |
| `src/runtime/bio/bf_prefix.rs:135` | `from_raw` | `PrefixCtx` | `NULL, 0` | UNVERIFIED — trait default; authority `prefix_destroy` frees at `crypto/bio/bf_prefix.c:72`. |
| `src/runtime/bio/bf_readbuff.rs:118` | `from_raw` | `BioBufferCtx` | `NULL, 0` | UNVERIFIED — trait default; authority `readbuffer_free` frees at `crypto/bio/bf_readbuff.c:80` (ibuf `:79`). |
| `src/runtime/bio/bss_acpt.rs:220` | `from_raw` | `BioAccept` | `NULL, 0` | UNVERIFIED — trait default; authority `BIO_ACCEPT_free` frees at `crypto/bio/bss_acpt.c:114`. |
| `src/runtime/bio/bss_bio.rs:182` | `from_raw` | `BioBioSt` | `NULL, 0` | UNVERIFIED — trait default; authority `bio_free` frees at `crypto/bio/bss_bio.c:104`. |
| `src/runtime/bio/bss_conn.rs:232` | `from_raw` | `BioConnect` | `NULL, 0` | UNVERIFIED — trait default; authority `BIO_CONNECT_free` frees at `crypto/bio/bss_conn.c:304`. |
| `src/runtime/bio/bss_dgram.rs:359` | `from_raw` | `BioDgramData` | `NULL, 0` | UNVERIFIED — trait default; authority `dgram_free` frees at `crypto/bio/bss_dgram.c:293`. |
| `src/runtime/bio/bss_dgram_pair.rs:417` | `from_raw` | `BioDgramPairSt` | `NULL, 0` | UNVERIFIED — trait default; authority `dgram_pair_free` frees at `crypto/bio/bss_dgram_pair.c:334` (lock `:333`). |
| `src/runtime/bio/bss_mem.rs:281` | `from_raw` | `BioBufMem` | `NULL, 0` | UNVERIFIED — trait default; authority `mem_free` frees at `crypto/bio/bss_mem.c:153` (readp `:152`). |
| `src/runtime/bio/bss_sock.rs:436` | `from_raw` | `BssSockData` | `NULL, 0` | UNVERIFIED — trait default; authority `sock_free` frees at `crypto/bio/bss_sock.c:100`. |
| `src/runtime/bio/comp.rs:346` | `from_raw` | `CompCtx` | `NULL, 0` | UNVERIFIED — trait default; authority `COMP_CTX_free` frees at `crypto/comp/comp_lib.c:61`. |
| `src/runtime/bio/core_bio.rs:181` | `from_raw` | `OsslCoreBio` | `crypto/bio/ossl_core_bio.c:50` | VERIFIED — `OPENSSL_free(cb);` |
| `src/runtime/bio/method.rs:220` | `from_raw` | `BioMethod` | `crypto/bio/bio_meth.c:54` | VERIFIED — `OPENSSL_free(biom);` |
| `src/runtime/thread_arch.rs:559` | `from_raw` | `CryptoThread` | `crypto/thread/arch.c:43` | VERIFIED — `OPENSSL_free(handle);` |
| `src/selftest/indicator.rs:81` | `from_raw` | `IndicatorCb` | `crypto/indicator_core.c:30` | VERIFIED — `OPENSSL_free(cb);` |
| `src/selftest/mod.rs:142` | `from_raw` | `SelfTestCb` | `crypto/self_test_core.c:44` | VERIFIED — `OPENSSL_free(stcb);` |
| `src/selftest/mod.rs:257` | `from_raw` | `OsslSelfTest` | `crypto/self_test_core.c:108` | VERIFIED — `OPENSSL_free(st);` |
| `src/ssl/bio_ssl.rs:637` | `from_raw` | `BioSsl` | `ssl/bio_ssl.c:91` | VERIFIED — `OPENSSL_free(bs);` |
| `src/ssl/d1_lib.rs:152` | `from_raw` | `Dtls1State` | `ssl/d1_lib.c:168` | VERIFIED — `OPENSSL_free(s->d1);` |
| `src/ssl/ssl_sess.rs:459` | `from_raw_at` | `SslSession` | `ssl/ssl_sess.c:930` | VERIFIED — `OPENSSL_clear_free(ss, sizeof(*ss));` |
| `src/store/store_lib.rs:1505` | `from_raw` | `OsslStoreCtx` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `OSSL_STORE_CTX_free` frees at `crypto/store/store_lib.c:603`. |
| `src/store/store_lib.rs:2251` | `from_raw` | `OsslStoreInfo` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `OSSL_STORE_INFO_free` frees at `crypto/store/store_lib.c:859`. |
| `src/store/store_lib.rs:2388` | `from_raw` | `OsslStoreSearch` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `OSSL_STORE_SEARCH_free` frees at `crypto/store/store_lib.c:990`. |
| `src/store/store_meth.rs:232` | `from_raw` | `OsslStoreLoader` | none recorded | UNVERIFIED — trait default (NULL, 0); authority `OSSL_STORE_LOADER_free` frees at `crypto/store/store_meth.c:39` (legacy) and `:55` (provider failure). |
| `src/ts/ts_verify_ctx.rs:130` | `from_raw` | `TsVerifyCtx` | `crypto/ts/ts_verify_ctx.c:34` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/ui/ui_lib.rs:479` | `from_raw_at` | `UiString` | `crypto/ui/ui_lib.c:68` | VERIFIED — `OPENSSL_free(uis);` |
| `src/ui/ui_lib.rs:499` | `from_raw_at` | `Ui` | `crypto/ui/ui_lib.c:81` | VERIFIED — `OPENSSL_free(ui);` |
| `src/ui/ui_lib.rs:1712` | `from_raw_at` | `UiMethod` | `crypto/ui/ui_lib.c:639` | VERIFIED — `OPENSSL_free(ui_method);` |
| `src/x509/by_dir.rs:330` | `from_raw_at` | `ByDirHash` | `crypto/x509/by_dir.c:136` | VERIFIED — `OPENSSL_free(hash);` |
| `src/x509/by_dir.rs:371` | `from_raw_at` | `ByDirEntry` | `crypto/x509/by_dir.c:153` | VERIFIED — `OPENSSL_free(ent);` |
| `src/x509/by_dir.rs:428` | `from_raw_at` | `ByDir` | `crypto/x509/by_dir.c:163` | VERIFIED — `OPENSSL_free(a);` |
| `src/x509/by_store.rs:343` | `from_raw_at` | `CachedStore` | `crypto/x509/by_store.c:117` | VERIFIED — `OPENSSL_free(store);` |
| `src/x509/pcy_cache.rs:451` | `from_raw` | `X509PolicyCache` | `crypto/x509/pcy_cache.c, 0` | UNVERIFIED — impl records `(crypto/x509/pcy_cache.c, 0)`; authority free `:186`. |
| `src/x509/v3_lib.rs:384` | `from_raw_at` | `X509V3ExtMethod` | `crypto/x509/v3_lib.c:119` | VERIFIED — `OPENSSL_free(ext);` |
| `src/x509/v3_purp.rs:671` | `from_raw_at` | `X509Purpose` | `crypto/x509/v3_purp.c:271` | VERIFIED — `OPENSSL_free(p);` |
| `src/x509/v3_utl.rs:349` | `from_raw_at` | `ConfValue` | `crypto/x509/v3_utl.c:111` | VERIFIED — `OPENSSL_free(conf);` |
| `src/x509/x509_lu.rs:974` | `from_raw_at` | `X509Lookup` | `crypto/x509/x509_lu.c:39` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/x509/x509_lu.rs:1357` | `from_raw_at` | `X509Object` | `crypto/x509/x509_lu.c:530` | VERIFIED — `OPENSSL_free(a);` |
| `src/x509/x509_lu.rs:1630` | `from_raw_at` | `X509Object` | `crypto/x509/x509_lu.c:530` | VERIFIED — `OPENSSL_free(a);` |
| `src/x509/x509_lu.rs:1820` | `from_raw_at` | `X509Store` | `crypto/x509/x509_lu.c:253` | VERIFIED — `OPENSSL_free(xs);` |
| `src/x509/x509_trust.rs:411` | `from_raw_at` | `X509Trust` | `crypto/x509/x509_trust.c:192` | VERIFIED — `OPENSSL_free(p);` |
| `src/x509/x509_vfy.rs:1544` | `from_raw_at` | `X509StoreCtx` | `crypto/x509/x509_vfy.c:2726` | VERIFIED — `OPENSSL_free(ctx);` |
| `src/x509/x509_vpm.rs:350` | `from_raw_at` | `X509VerifyParam` | `crypto/x509/x509_vpm.c:104` | VERIFIED — `OPENSSL_free(param);` |
| `src/x509/x_crl.rs:1314` | `from_raw_at` | `X509CrlMethod` | `crypto/x509/x_crl.c:515` | VERIFIED — `OPENSSL_free(m);` |

### 9.1 The four previously omitted `into_raw` publications

| publication | type | matching reclaim | authority release |
|---|---|---|---|
| `src/async/async_wait.rs:182` | `AsyncWaitCtx` | `OwnedCtx::from_raw_at` at `:195` | `crypto/async/async_wait.c:41` `OPENSSL_free(ctx);` |
| `src/evp/digest.rs:1899` | `EvpMdCtx` | `OwnedCtx::from_raw_at` at `:1969` | `crypto/evp/digest.c:140` `OPENSSL_free(ctx);` |
| `src/property/globals.rs:133` | `OsslGlobalProperties` | `OwnedCtx::from_raw` at `:120` | `crypto/property/property.c:120` `OPENSSL_free(globp);` |
| `src/store/store_register.rs:275` | `OsslStoreLoader` | `OwnedCtx::from_raw` at `store_meth.rs:232` | `crypto/store/store_meth.c:39` `OPENSSL_free(loader);` |

All four are one-for-one: the constructor allocates, `into_raw` gives up the
owner, and the named reclaim is the single release. The remaining 128
publications (119 original entries plus the 13 §1.7 modules, less these four)
pair with the same-type rows in the table above; no publication is left without
a reclaim row or an external-ownership note in §6.
