# Safe-33 unsafe→safe conversion — progress ledger

Authority: this file records *landed* conversion batches on `integrate/safe-c33`.
A batch is "landed" only when its local gate is green in the court container and
it is merged. The full Phase-25 forensic regeneration stays deferred until the
conversion campaign lands (see CLOSURE.md); the original Phase-25 site inventory
is retained only as the frozen baseline below.

Frozen atlas baseline (original inventory): **2420** allocation sites
(`artifacts/phase25/ownership-planes.json`).

## Current candidate-bound measurement

Regenerated at HEAD `0b56262523556a70babcb827fed9708dd28d28eb` by
`python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py` (see
`atlas-refresh/REPORT.md`; the generator is measurement-only and claims no
discharge):

- Safe-33 closure: **628** files; **313** have a recognised ownership seam
  (**49.8%**); **0** files have fully discharged obligations; **0/33**
  consumers are `SAFE_COMPATIBLE`.
- Whole tree: **865** `src/**/*.rs`; **374** files have a seam; **359** still
  contain raw allocator sites; **4,290** raw sites in total, which includes
  legitimate seam constructors and test-only probe helpers and is therefore
  **not** a residual count.
- Closure raw sites: **3,435** (upper bound; **143** in files with no seam).
  A seam is a file-level heuristic, not a per-site proof.

The residual conversion queue is re-derived from the frozen census and Git by
the snippet in the resume procedure; it is deliberately separate from this
file-level atlas metric.

Local gate for every batch (court container, 8 GB cap):
`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --lib` (must pass; the established baseline is **1214** passed
(one concurrent-refcount test added in subphase 39, eight
reference-count/re-entrancy tests added in subphase 40, and seven
alias/ownership tests added in subphase 41) and the adversarial
probes are `#[ignore]`d and run separately via `scripts/adv-probe.sh`; as of
sweep 35 there are **18** probes).

## Landed batches

| # | branch | files | notes |
|---|--------|-------|-------|
| 1 | stage/p25/cms-core | cms_kemri, cms_pwri, cms_dh | OwnedBuf seam; scratch buffers owned |
| 2 | stage/p25/cms-rest | cms_sd, cms_ec, cms_rsa | + closed a latent cms_ec leak (Drop frees `der`) |
| 3 | stage/p25/cms-finish | cms_kari, cms_enc, cms_ess | CMS module now fully seamed |
| — | fix/p25/sm2-flaky-bound | src/sm2/crypt.rs | pre-existing too-tight DER length bound (2 bytes, not 1) |
| 4 | stage/p25/pkcs7 | pk7_doit, pk7_smime | pk7_lib/pk7_asn1 ctx.propq retained → member-buffer unit |
| 5 | stage/p25/ssl-remainder | ssl_conf, t1_lib, ssl_asn1 | member C-string/array buffers retained |
| 6 | stage/p25/rsa-ec-keys | rsa/mod.rs, ec/ameth | rsa 9→4 interior, ameth 32→3 interior |
| 7 | stage/p25/pq-keys | ml_kem/key, ml_dsa/key, provider/mlx_kmgmt | PQ key material owned |
| 8 | stage/p25/provider-remainder | provider/mod.rs, provider/exchange.rs | provider metadata fields + DH ctx (frees 25→12/13→9) |
| 9 | stage/p25/srp-mac-http | srp/srp_vfy.rs, apps/mac.rs | srp interior free 20→0; mac 18→2; unsafe 140→137, 73→56 |
| 10 | stage/p25/http-decoder | decoder_pkey.rs, http/http_client.rs | decoder alloc+free 22→2; http_client 31→0 |
| 11 | stage/p25/asn1-remainder | asn1/bio_asn1.rs, text.rs, asn_mime.rs | interior alloc+free all → 0 |
| 12 | stage/p25/x509-remainder | x509/x_pubkey.rs, v3_ncons.rs, x_name.rs | frees 6→5, 13→1, 9→6 (helpers adopted) |
| 13 | stage/p25/runtime-remainder | runtime/conf/def.rs, confmod/mod.rs, async/async.rs | free 17→0, 24→0, 10→0 |
| 14 | stage/p25/provider-ops | provider/rsa_enc.rs, sm2_sig.rs, ml_kem_kmgmt.rs | interior 18→9, 14→9, 18→8 |
| 15 | stage/p25/cmp-crmf | cmp/cmp_protect.rs, crmf/crmf_pbm.rs, cmp/cmp_vfy.rs | free 16→1, 14→1, 13→1 |
| 16 | stage/p25/prop-ts-ct | ct/ct_oct.rs, property/store.rs, ts/ts_rsp_sign.rs | free 4→1, 9→7, 7→4 |
| 17 | stage/p25/evp-txtdb | txt_db/txt_db.rs, evp/mac.rs, evp/kdf.rs | txt_db free 11→1 |
| 18 | stage/p25/x509-lku | x509/by_dir.rs, x509_vpm.rs, x509_lu.rs | OwnedCtx + partial-construction Raw* owners; free 6→3,10→6,6→3 |
| 19 | stage/p25/ssl-rest2 | ssl/cert_comp, tls_srp, ssl_rsa, ssl_ciph | free 5→0,3→0,1→0; closes a dangling srp info pointer |
| -- | stage/p25/adopt-soundness | 16 files + AGENTS.md | **soundness**: every safe adoption ctor (`take`/`adopt`) → `unsafe fn` + real `# Safety` (AGENTS.md §1); A/B/C |
| 20 | stage/p25/x509-tail1 | x509spki, x509_trust, x_x509, x509_req, x_crl | OwnedCtx/OwnedStr/RawTrust; eliminated trtable_free pairing |
| 21 | stage/p25/x509-tail2 | x509_meth, v3_pci, v3_conf | RawMethod/OwnedMethod; policy_grow realloc contract; free 5→1 ×2 |
| 22 | stage/p25/x509-tail3 | v3_purp, v3_asid | OwnedCtx<X509Purpose>; RawPurpose/RawRange; free 8→5, 4→2 |
| 23 | stage/p25/x509-tail4 | v3_info, v3_akid, by_store, v3_lib, dane | interior frees 15→0 |
| 24 | stage/p25/rand-engine | rand/rand_lib.rs, engine/eng_dyn.rs, runtime/rcu.rs | free 18→7, 14→7, 13→3; rcu alloc/lifetime only |
| 25 | stage/p25/cms-final | cms/cms_smime.rs | OwnedChainArray (checked_mul); cms_asn1/lib are member-buffer residuals |
| 26 | stage/p25/dh-dsa-pkey | dh/mod.rs, dsa/mod.rs, rsa/sign.rs | Raw/OwnedMethod; rsa/sign free 7→1 (cleansed) |
| -- | stage/p25/p0-abstractions | asn1/owned.rs, x509/{pcy_lib,pcy_node,pcy_tree}.rs | **P0**: `checked_mul` in the alloc helper; owner-derived `tree_levels`; `parent_mut(&mut self)` |
| 27 | stage/p25/ct-module | ct/ct_sct_ctx, ct_log, ct_sct | OwnedCtx<CtxDestroy>; free 14→10, 8→6, 11→6 |
| 28 | stage/p25/provider-km | provider/ecdh_exch, ec_kmgmt, cipher_gcm | cleansed OwnedBuf seam; ec_kmgmt free 16→5 |
| 29 | stage/p25/provider-codecs | decode_msblob2key, mac_legacy_kmgmt, ml_kem_codecs, ecx_kmgmt, file_store | free 6→2, 7→6, 5→1, 7→5, 8→5 |
| 30 | stage/p25/km-p12-prop | asn1/a_sign, pkcs12/p12_utl, property/parse, provider/keymgmt | free 11→1, 5→3, 9→7; owner-lent slices |
| 31 | stage/p25/ec-dso-enc | dso/mod.rs, ec/asn1.rs, provider/encode_key2any.rs | free 7→2, 6→2 |
| 32 | stage/p25/pkey-crmf-addr | evp/pkey.rs, crmf/crmf_lib.rs, x509/v3_addr.rs | free 11→2, 6→4, 3→1; non-elidable cleanse improvement |
| 33 | stage/p25/pmeth | dh/ec/rsa pmeth, dsa/ameth, rsa/ossl | OwnedCtx<CtxDestroy>; rsa/ossl 23→15 |
| 34 | stage/p25/provider-sigs | legacyprov, dsa_kmgmt, dsa_sig, ecdsa_sig | free 2→1,7→5,6→3,6→3 (decode_der2key deferred) |
| 35 | stage/p25/tail1 | ct_b64, conf/conf_ssl, runtime/str, evp/exchange, evp/pem_bridge | OwnedStore/PemBuf; free 6→1,5→3,4→3,5→4,4→3 |
| 36 | stage/p25/tail2 | pkcs12/p12_decr, conf/api, dso/dlfcn, passphrase, decode_der2key | UiScratch; free 6→1,12→7,2→1,5→3 |
| 37 | stage/p25/tail3 | slh_dsa/key, rand/pool, params/build, ml_dsa_sig, dh/ameth, bio_enc | OwnedStr/OwnedBuf/OwnedDef/OwnedCtx |
| 38 | stage/p25/tail4 | ts_verify_ctx, ec/mult, ml_dsa/encoders, evp/skeymgmt, decoder_lib, evp/rand | RawCtx window; per-handle-line seams |
| 39 | stage/p25/tail5 | apps/kdf, mac_legacy_sig, bio/addr, packet, evp/fetch, params/mod | OwnedSub/OwnedAddr; kdf cleansing fix |
| -- | stage/p25/rawctx | runtime/bio/{owned,bf_lbuf,core_bio}.rs | **soundness**: `RawCtx<T>` (block-only release) + `unsafe assume_init -> OwnedCtx<T>` |
| -- | stage/p25/zeroval | ssl/ssl_lib.rs | **soundness**: initialise `Cert.custext` (zeroed `Vec`); crate-wide sibling scan clean |
| -- | integrate (docs/ci) | AGENTS.md, PROGRESS.md, .github/workflows/ci.yml | ledger reconciled; CI split into conversion vs seal modes |
| 40 | stage/p25/tail6 | async_wait, eng_lib, sm2/sign, slh_dsa_sig, asymcipher, seed_src | OwnedCtx/OwnedBuf; RawCtx windows; free 4→2,5→3,3→1,8→4 |
| 41 | stage/p25/tail7 | ec/print, asn1/string, slh_dsa_kmgmt, cmp_ctx, encode_key2text | body release sites 5→0,6→0,5→0 |
| 42 | stage/p25/tail8 | conf/modparse, thread_arch, decode_epki2pki, params/dup, ec/kmeth, ffc/params | 22 hand-written release sites → 0 |
| 43 | stage/p25/tail9 | prov_seed, ecx_key, async_posix, provider/conf, t_x509, asn1_gen | Raw*→OwnedCtx; asn1_gen 4→1 |
| 44 | stage/p25/tail10 | property/strings, slh_dsa/dsa, ml_dsa/sign, bn/blinding, bn/rand, evp/e_aria | 7 routine-body release sites → 0 |
| -- | stage/p25/ctor-soundness | ssl/ssl_lib.rs | **soundness**: `RawCtx`/`assume_init` staged init; `CtxDestroy` unsafe trait |
| -- | stage/p25/zerovalid | runtime/bio/owned.rs + 26 implementers | **soundness**: shared `CtxDestroy` unsafe trait (zero-validity + destructor contract) |
| -- | stage/p25/memberbuf-propq | pkcs7/{pk7_lib,pk7_asn1}.rs | **member-buffer model** (MEMBER-BUFFER-MODEL.md); PropqSlot proven on PKCS7 |
| -- | stage/p25/memberbuf-cms | cms/{cms_lib,cms_asn1}.rs, pkcs12/p12_asn.rs, pkcs7/pk7_mime.rs | CmsPropqSlot; **CmsCtx.propq now private** |
| -- | stage/p25/memberbuf-x509 | x509/{x_x509,x_crl,x509_req,x_pubkey,x_req,x_all,x509_vfy}.rs | X509_CRL/REQ/PUBKEY propq fields **private** |
| -- | stage/p25/memberbuf-sslstr | ssl/{ssl_asn1,ssl_lib,ssl_sess,ssl_txt}.rs | remaining `SslSession` C-strings + `Cert.psk_identity_hint` own their storage |
| -- | stage/p25/adv-tests | runtime/bio/owned.rs, ssl/{adv_alloc,ssl_lib}.rs, ssl/statem/{statem_clnt,statem_srvr}.rs | **adversarial**: ticket allocation-refusal regression + member-buffer/partial-init negative controls |
| -- | stage/p25/memberbuf-sslctx | ssl/{ssl_cert,ssl_ciph,ssl_lib}.rs, ssl/statem/extensions_clnt.rs | `SslCtx`/`Ssl` member buffers through the model |
| 45 | stage/p25/sweep1 | decoder_meth, evp/evp_lib, evp/pkey_asn1, provider/{ml_dsa_kmgmt,rsa_kem}, rsa/object | six files own their blocks |
| 46 | stage/p25/sweep2 | asn1/x_int64, provider/{ec_kem,ml_dsa_codecs,skeymgmt,sm2_enc}, srp/srp_lib | six files own their blocks |
| 47 | stage/p25/sweep3 | cmp/cmp_client, ec/{ecx_meth,key}, encoder_{lib,meth}, rsa/pss | six files own their blocks |
| 48 | stage/p25/sweep4 | asn1/tasn_prn, engine/eng_table, provider/ml_common_codecs, runtime/buffer, store/store_result, ts/ts_rsp_verify | six files own their blocks |
| 49 | stage/p25/sweep5 | asn1/a_digest, evp/keymgmt_lib, http/http_lib, pem/pem_lib, provider/ecx_kem, ui/ui_util | six files own their blocks |
| 50 | stage/p25/sweep6 | asn1/a_verify, ct/ct_policy, dsa/sign, provider/ecx_exch, runtime/bio/bss_mem | five files own their blocks |
| 51 | stage/p25/sweep7 | asn1/{a_i2d_fp,utl}, evp/kem, modes/ocb, x509/v3_san | five files own their blocks |
| -- | stage/p25/sslmb2 | 11 ssl files | complete `SslCtx`/`Ssl` member-buffer boundaries (propq readers, `serverinfo` realloc, handshake state) |
| 52 | stage/p25/sweep8 | bn/primes, cmp/cmp_asn, provider/decode_pem2der, store/store_meth | four files own their blocks |
| 53 | stage/p25/sweep9 | asn1/a_dup, evp/bio_ok, rsa/mp | three files own their blocks |
| -- | stage/p25/adv-harden | ssl/{adv_alloc,ssl_lib}.rs, ssl/statem/{statem_clnt,statem_srvr}.rs, AGENTS.md, scripts/adv-probe.sh | **assurance**: hard-failing one-process probes + §21 protocol |
| 54 | stage/p25/sweep10 | evp/signature, provider/decode_spki2typespki | two files own their blocks |
| 55 | stage/p25/sweep11 | asn1/{new,t_pkey,a_strex}, bn/intern, cmp/cmp_hdr, property/defn_cache | 13 interior alloc/release sites owned; 1 caller-side test release retained; two `checked_add` improvements; hidden 0 |
| 56 | stage/p25/sweep12 | provider/{rsa_kmgmt,eddsa_sig,init}, dsa/object, dh/object, ml_dsa/poly | staged `RawCtx`→`OwnedCtx` for DSA/DH; block-only owners for RSA gen + EdDSA; `OwnedStr`/`OwnedBuf` path temporaries; `VectorBuf` members; checked array products; hidden 0 |
| 57 | stage/p25/sweep13 | ec/depr, slh_dsa/hash_ctx, evp/evp_pbe, runtime/bio/bio_sock2, bn/bignum, asn1/fre | path-selected release lines; partial-init `OwnedHashCtx`; accepted-row ownership; socket-string order; ASN.1 embedded-free contracts retained; hidden 0 |
| 58 | stage/p25/sweep14 | encoder_pkey, modes/siv128, evp/keymgmt, provider/activate, dh/key, cmp/cmp_server | `RawCtx`→`OwnedCtx` contexts; `OwnedBlock` id array; `OpBitsSlot` realloc/clear under write lock; DH output transfer; hidden 0 |
| 59 | stage/p25/sweep15 | dsa/pmeth, ec/{ecx_backend,ecdh_ossl}, x509/pcy_cache, provider/file_store_any2obj, ffc/params_generate | staged contexts; ECX dup window; secret output transfer; FFC seed owners with caller-seed ownership encoded by owner presence; hidden 0 |
| 60 | stage/p25/sweep16 | provider/{child,mlx_kem}, ssl/d1_lib, dh/asn1, evp/algorithm, pkcs12/p12_key | `OwnedCtx` provider/DTLS states; DH decoded-block owners with transferred members retained; cleansed password owner; explicit `strndup` transfer; hidden 0 |
| 61 | stage/p25/sweep17 | runtime/bio/addr_info, params/from_text, provider/{encode_key2ms,decode_pvk2key}, ssl/bio_ssl, rsa/gen | `OwnedNode` addrinfo chain + `OwnedStr` out-params; param value buffer; provider contexts; BIO-SSL block owner; RSA plaintext owner. **Compatibility fix**: `BIO_parse_hostserv` now honours the authority's `h != NULL` guard before freeing `*host`; hidden 0 |
| 62 | stage/p25/sweep18 | provider/ml_kem_kem, context/thread_data, evp/e_chacha20_poly1305, asn1/a_strnid, runtime/bio/bss_log, modes/gcm | staged ML-KEM/thread contexts; cleansed AEAD local owners; registry-row owner; log buffer; staged GCM context with clear_free; hidden 0 |
| 63 | stage/p25/sweep19 | context/mod, rsa/ameth, evp/evp_pkey, asn1/p5_pbe, ec/oct, x509/v3_usernotice | staged libctx; plain/cleansed DER owners at setter edges; salt and point-buffer owners; notice conversion owner; hidden 0 |
| 64 | stage/p25/sweep20 | runtime/{threads_common,confmod/asn1}, x509/x509_obj, pem/pem_info, selftest/mod, mac/cmac | master-key owner; BUF_MEM data-transfer owner; PEM triple-buffer owners; staged self-test/CMAC contexts; checked conf length; hidden 0 |
| 65 | stage/p25/sweep21 | asn1/{time,a_mbstr}, mac/hmac, property/globals, x509/v3_utf8, dh/ctrl | shortened-time/mbstr/UTF8 owners with checked lengths; `OwnedCtx` HMAC/global-properties; ukm custody contract; hidden 0 |
| 66 | stage/p25/sweep22 | asn1/bitstr, cmp/cmp_genm, provider/{encode_key2blob,util}, x509/{v3_soa_id,v3_ind_iss} | bit-string owner + documented regrow; subject/blob owners; memdup transfer; returned strdup edges documented; hidden 0 |
| 67 | stage/p25/sweep23 | apps/{prime,configutl}, asn1/p5_pbev2, pem/key_legacy, provider/ctx, rsa/ctrl | output/helper owners; PBKDF2 salt owner with string-layer release; PEM name/data order; `OwnedCtx` provider context; OAEP label custody contract; hidden 0 |
| 68 | stage/p25/sweep24 | ec/{backend,curve}, rsa/backend, ts/ts_lib, store/store_register, provider/endecoder_common | EC key/array owners; RSA prime-info install owner; TS/store/endecoder owners; checked curve extents; hidden 0 |
| 69 | stage/p25/sweep25 | ec/ecdsa, evp/cipher, selftest/indicator, pkcs12/p12_p8e, x509/{v3_cpols,v3_ia5} | staged ECDSA/EVP contexts; indicator owner; PKCS#8 signature owner; policy/IA5 buffers with checked lengths; hidden 0 |
| 70 | stage/p25/sweep26 | x509/{x509_acert,v3_enum,v3_single_use,v3_no_rev_avail,v3_group_ac}, pem/pem_oth | ACERT/PEM local owners; returned extension strings documented as caller-owned transfers; hidden 0 |
| 71 | stage/p25/sweep27 | asn1/{x_info,x_pkey}, evp/encode, pem/pem_pkey, bn/gf2m, ec/ctrl | staged X509 info/pkey and encode contexts; secure-heap name/data owners with cleansing; test-local owner; UKM custody contract; hidden 0 |
| 72 | stage/p25/sweep28 | apps/{asn1parse,spkac}, provider/{cipher,cipher_tdes_wrap}, ec/{prn,ecdsa_ossl}, x509/x_attrib | PEM/app owners; TDES wrap reuses the engine `OwnedCtx` (visibility-only support change); EC DER/print owners; test-local owner; hidden 0 |
| 73 | stage/p25/sweep29 | runtime/bio/method, x509/{v3_prn,v3_sxnet}, ct/ct_x509v3, dsa/asn1, asn1/x_algor | **allocator-seam fix**: BIO_METHOD now zalloc/strdup/free through CRYPTO_* (no Box/libc bypass); extension/test owners; returned CT string documented; hidden 0 |
| -- | stage/p25/sweep30 | bn/ctx, runtime/sparse_array | structural/no-seam classification; four opaque objects retained Rust-owned because a seam allocation would report the wrong byte size (P1 hook-parity residual recorded) |
| 74 | stage/p25/sweep31 | rsa/asn1, bn/{mont,bn_srp}, x509/v3_no_ass | test-only owners; Rust-owned-opaque and no-seam classifications; returned strdup contract; hidden 0 |
| 75 | stage/p25/sweep32 | runtime/{thread,stack,lhash}, bn/recp | final opaque-representation classification; P1 allocator-hook byte-size residual stated; documentation only; hidden 0 |
| 76 | stage/p25/sweep33 | src/ssl/adv_alloc, dsa/object, dh/object, ec/ecx_backend, scripts/adv-probe.sh | **targeted court**: site-independent `arm_any`, cleansed-free detector + canary; DSA/DH/ECX allocation-refusal probes; 13/13 probes; hidden 0 |
| 77 | stage/p25/sweep34 | src/ssl/d1_lib, src/pkcs12/p12_key, src/provider/activate, scripts/adv-probe.sh | **targeted court**: DTLS state refusal/lifecycle, PKCS#12 `OwnedUniPass` cleansed release, provider operation-bits publication ordering; 16/16 probes; hidden 0 |
| 78 | stage/p25/sweep35 | src/dsa/object, src/dh/object, scripts/adv-probe.sh | **targeted court**: later initialisation failure (`meth->init` returns 0) runs the partial cleanup — method `finish` once, one forwarded context allocation, one release of the same block, default method restored and exercised; allocation-refusal arm already covered; lock-null (Box-based) and ex-data failure are unreachable/non-injectable and not claimed; 18/18 probes; hidden 0 |
| 79 | stage/p25/sweep37 | provider/cipher, ec/lib, ssl/ssl_lib | **destructor zero-validity**: D1/D2 `hw` null guard and D3/D4 `meth` null guard make the clear bodies no-ops on the all-zero block; constructed-path order, layouts, coordinates and cleansing unchanged; Ssl `session_ticket` comment reconciled with the authority's raw release; 2 new deterministic zero-state negative controls; 18/18 probes; hidden 0 |
| 80 | stage/p25/sweep38 | DESTRUCTOR-CONTRACTS.md, PROGRESS.md | **subphase 38 adjudication (docs only)**: 19 `CONTRACTED` `CtxDestroy` rows independently re-read against every constructor/publication path; **16 promoted to `ESTABLISHED`**, **3 retained `CONTRACTED`** (`SslCtx`, `Ssl`, `X509Store`), **0 STOP defects**; no `DISCHARGED`; residual callback/non-atomic-refcount obligations recorded |
| 81 | stage/p25/sweep39 | src/x509/x509_lu.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **runtime/alias adjudication**: `X509Store` last-ref gate moved from plain `c_int` to layout-compatible `AtomicI32` (size 160 / offset 144 / align 8 asserts; relaxed fetch-add, release fetch-sub + acquire fence); concurrent up-ref test added; `SslCtx`/`Ssl`/`X509Store` retained `CONTRACTED` for reachable callback re-entrancy (ex-data / lookup `free` hook / `BIO_free_all`); 0 STOP; 1199 passed, 18 ignored; 18/18 probes; hidden 0 |
| 82 | stage/p25/sweep40 | src/runtime/refcount.rs, src/runtime/mod.rs, src/ssl/ssl_lib.rs, src/ssl/ssl_sess.rs, src/x509/x509_lu.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **callback-reentrancy repair**: shared `REF_DESTROYING` sentinel CAS in the existing `AtomicI32`; `*_free` claims the last reference `1 -> destroying` and a re-entrant/over-free is a defined no-op; `*_up_ref` refuses zero/destroying without resurrecting; applied to `Ssl`, `SslCtx`, `SslSession`, `X509Store`; 8 deterministic tests (4 protocol + 4 real ex-data re-entry); no layout/ABI/allocator/free-order change; 0 STOP; 1207 passed, 18 ignored; 18/18 probes; hidden 0 |
| 83 | stage/p25/sweep41 | src/ssl/ssl_lib.rs, src/ssl/ssl_sess.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **`Ssl`/`SslCtx` alias/lifecycle closure**: field-by-field ownership audit; fixed S1 session-cache `owner` dangling (UAF), S2 missing `ENGINE_finish`, S3 missing `dane_final`, S4 missing `ssl_clear_bad_session`; 7 deterministic tests; both rows promoted to `ESTABLISHED` (not `DISCHARGED`); no layout/ABI/allocator coordinates; 1214 passed, 18 ignored; 18/18 probes; hidden 0 |

### Subphase 38 — destructor-contract adjudication (docs only)

- `ESTABLISHED` (16 of 19): `AsyncWaitCtx`, `OsslDecoderInstance`,
  `OsslDecoderCtx`, `Dh`, `Dsa`, `OsslEncoderInstance`, `OsslEncoderCtx`,
  `EvpPkey`, `EvpPkeyCtx`, `Rsa`, `CompCtx`, `SslSession`, `Ui`, `X509Lookup`,
  `EcGroup`, `EcPoint`.
- Retained `CONTRACTED` (3): `SslCtx`, `Ssl` (application ex-data/BIO callbacks
  and multi-member teardown analysis), `X509Store` (non-atomic `c_int`
  reference count + lookup `free` hooks).
- STOP defects: **0**. No production code changed; nothing promoted to
  `DISCHARGED`.
- Source witnesses and residual obligations are in
  `DESTRUCTOR-CONTRACTS.md` → “Adjudication (subphase 38)”.

### Subphase 39 — runtime/alias adjudication

- `X509Store`: the non-atomic `c_int` gate was a genuine concurrent-use defect
  (lost updates, premature free / use-after-free); fixed with `AtomicI32` and
  the authority's orderings. No layout, offset, allocator-coordinate or
  exported-signature change. One new concurrent-increment test.
- `SslCtx`/`Ssl`/`X509Store`: after the count reaches zero, application
  callbacks run by the destructor (`CRYPTO_free_ex_data`, the lookup `free`
  hook, `BIO_free_all`) can call the same `*_free` again. The `i > 0` gate does
  not reject the 0 → -1 transition, so a second `OwnedCtx` is created and the
  object is torn down twice. Recorded as a retained boundary, not redesigned;
  the minimal fix is a `DESTROYING` sentinel in the existing atomic refcount.
- No row promoted to `ESTABLISHED` or `DISCHARGED`; 0 STOP defects.
- Gate: `fmt` clean, clippy clean, **1199 passed / 18 ignored**, adv-probe
  **18/18**. Full evidence: `RUNTIME-ALIAS-EVIDENCE.md`.

### Subphase 40 — reference-count destroying sentinel (callback re-entrancy)

- Shared gate `src/runtime/refcount.rs`: `REF_DESTROYING = i32::MIN` lives in
  the existing `AtomicI32` (no field, layout or exported-signature change).
  `*_free` loads, treats zero/negative/sentinel as a defined no-op, releases a
  positive `n > 1` with `CAS(n, n-1)` (Release), and claims `1` with
  `CAS(1, REF_DESTROYING)` (AcqRel) before running the destructor body.
  `*_up_ref` CAS-increments only a positive count; zero/destroying returns 0
  without changing the count. `SSL_dup`'s quiescent path returns NULL if that
  guarded increment fails.
- Applied to `Ssl`, `SslCtx`, `SslSession` and `X509Store`. The authority's
  over-free UB becomes a defined no-op (a documented §17 safety divergence).
- Deterministic tests (no allocator hook, not ignored): one real ex-data
  `free_func` re-entry per type — `store_free_reentrancy_is_defined_noop`,
  `session_free_reentrancy_is_defined_noop`,
  `ctx_free_reentrancy_is_defined_noop`, `ssl_free_reentrancy_is_defined_noop`
  — plus four protocol tests in `runtime::refcount`.
- No row promoted to `SAFETY_DISCHARGED`; `SslCtx`/`Ssl`/`X509Store` remain
  `CONTRACTED` for the §7 independent-check package. 0 STOP defects.
- Gate: `fmt` clean, clippy clean, **1207 passed / 18 ignored**, adv-probe
  **18/18**. Full evidence: `RUNTIME-ALIAS-EVIDENCE.md` §§1–3.

### Subphase 41 — `Ssl`/`SslCtx` alias/lifecycle closure

- Field-by-field ownership audit of both objects against the authority's
  `SSL_free`/`ossl_ssl_connection_free` (`ssl_lib.c:1422-1547`) and
  `SSL_CTX_free` (`:4350-4468`). Full tables are in `DESTRUCTOR-CONTRACTS.md`
  → “Subphase 41”.
- Fixed four real defects: (S1) `SslSession.owner` was not cleared on cache
  removal/flush/context teardown, leaving a caller-held session pointing into a
  freed `SSL_CTX` (`SSL_SESSION_set_timeout` then read `owner->lock`); (S2)
  `SslCtx` never finished the structural `ENGINE_init` reference taken by
  `SSL_CTX_set_client_cert_engine`; (S3) `Ssl` never ran the authority's
  `dane_final`; (S4) `SSL_free` skipped the authority's `ssl_clear_bad_session`
  before releasing the session.
- Confirmed the alias rules: `SSL_new` takes two distinct `SSL_CTX` refs;
  `SSL_set_SSL_CTX` moves only `ctx`; `SSL_set_session` up-refs; chain
  accessors return borrowed owners; `SSL_dup`/`SSL_clear` create no shared
  owners.
- Seven deterministic tests added (no allocator hook, not ignored): four in
  `ssl::ssl_lib::alias_ownership_tests`, three in
  `ssl::ssl_sess::alias_ownership_tests`.
- `Ssl` and `SslCtx` promoted to `ESTABLISHED`; `X509Store` remains
  `CONTRACTED`; nothing is `SAFETY_DISCHARGED` (the §7 independent-check
  package is outstanding, and the currently-unset `waitctx`/`bbio`/`scts`/
  `shared_sigalgs`/`peer_sigalgs` members are an explicit future obligation).
- Gate: `fmt` clean, clippy clean, **1214 passed / 18 ignored**, adv-probe
  **18/18**. Full evidence: `RUNTIME-ALIAS-EVIDENCE.md` §4.

Converted files (union of stage/p25/* files): see the batch table above for the authoritative list. Allocation-site counts below are a **frozen-baseline** measure; the candidate-bound figure is in `atlas-refresh/` and MUST be regenerated (`atlas_refresh.py`) before quoting completion numbers. OOM guard: build with `CARGO_BUILD_JOBS=4`, test with `cargo test --lib -- --test-threads=4`.

## Standing conversion standard

`AGENTS.md` (tracked, repo root) is the standing engineering standard for every
conversion batch: adoption ctors are `unsafe fn` proof obligations; allocated
storage vs valid Rust values are separate states (MaybeUninit / partial
construction); checked arithmetic; panic safety; secrets as a distinct category;
and `SAFE_COMPATIBLE` requires the consumer's whole conservatively-established
dependency closure to be `SAFETY_DISCHARGED`.
Interior allocation-site reduction is larger than the atlas delta because each
converted module re-hosts several hand-written sites into one seam.

## Standing residuals (not yet addressed)

- **Member buffers**: `#[repr(C)]` struct fields with cross-function ownership
  whose remaining cases are named by the atlas, not by a frozen list.
- **Compound destructors**: objects freed by a multi-step body rather than one
  release (MlKemKey/MlDsaKey/MlxKey/ProvMlxKemGenCtx, RSA_METHOD).
- **Interior representation rewrites** (the deeper class, like
  `src/runtime/sparse_array.rs`): raw graph traversal replaced by owned nodes.
- **Discharge evidence**: no file has a proven per-site validity contract yet;
  `SAFETY_DISCHARGED` and `SAFE_COMPATIBLE` remain 0 pending the seal.

## Structural/no-seam tail (sweep-30 classification)

The last census files are **not** mechanical allocator-owner targets. Each has been
classified explicitly so the residual is auditable rather than implied:

- `bn/ctx.rs`, `bn/mont.rs`, `rsa/asn1.rs` — deliberately Rust-owned internal /
  test-layer representations; no exported C free contract. `bn/ctx` records the
  hook-invisibility consequence.
- `runtime/sparse_array.rs` — structural Rust-owned tree; header/nodes already use
  the CRYPTO seam; the remaining unsafe edge is the opaque-handle-to-reference
  conversion at each C entry point, stated there.
- `runtime/thread.rs` (`CRYPTO_RWLOCK`), `runtime/stack.rs` (`OPENSSL_STACK`),
  `runtime/lhash.rs` (`OPENSSL_LHASH`), `bn/recp.rs` (`BN_RECP_CTX`) — exported
  opaque objects whose Rust representation (`Box`/`Vec`) is **not** the authority's
  C struct size. Allocating them through `CRYPTO_zalloc(size_of::<Rust>())` would
  make a caller-installed `CRYPTO_set_mem_functions` hook observe the wrong byte
  count, violating §6's exact-size rule. They are retained as Rust-owned
  representations; **compatibility residual P1**: allocator-hook byte-size parity
  for these four opaque objects is not achieved. This is not hidden and does not
  claim discharge. A future representation decision (e.g. an authority-size block
  with an internal state pointer) must be made before claiming seam parity.
- `bn/bn_srp.rs` — no interior CRYPTO allocation site; arithmetic-only.
- `x509/v3_no_ass.rs` — returns a caller-owned `CRYPTO_strdup` block to the
  extension machinery; the transfer contract is the boundary.

## Next queue

**As of sweep 32 the residual census queue is fully classified: 0 unclassified
files.** Sweeps 11–29 converted or boundary-documented the mechanical tail;
sweeps 30–32 classified the structural/no-seam set. Four exported opaque objects
(`CRYPTO_RWLOCK`, `OPENSSL_STACK`, `OPENSSL_LHASH`, `BN_RECP_CTX`) remain
Rust-owned because converting them to a CRYPTO-seam allocation would allocate
`size_of::<Rust representation>()`, not the authority's C size, and would make a
caller's allocator hook observe the wrong byte count. That is the recorded **P1
hook-size residual**, not a discharge claim.

The queue is re-derived from Git + `artifacts/phase25/source-census.json` with
the snippet in the resume procedure; do not treat any list here as frozen. The
remaining work is **not** more mechanical conversion: it is per-site obligation
evidence, the P1 representation decision, and the seal (`SAFETY_DISCHARGED`
promotions and current-candidate consumer verification).

## Progress measurement (five dimensions — see AGENTS.md §19)

Not one percentage; report each axis honestly.

1. **Ownership reconstruction** — conversion batches plus the soundness,
   member-buffer, adversarial-test and destructor-trait batches (see the table);
   the reusable adoption-pattern set (OwnedBuf / OwnedCtx+`CtxDestroy` /
   partial-construction `Raw*` / staged `RawCtx`+`assume_init` / member-buffer
   `PropqSlot`/`MemberBufSlot`/`MemberCStrSlot`) is now sound, and **all 46
   module-local destructor traits are `unsafe trait`** with explicit contracts.
2. **Safe-interior coverage** — *not yet comprehensively measured*; the sparsest
   structural conversions so far are sparse_array and the X.509 policy tree.
3. **Discharged safety obligations** — local gate green per batch; three
   reusable-abstraction soundness fixes landed (adoption ctors are `unsafe fn`;
   `RawCtx`/`assume_init` staged init in `bio::owned` and `ssl_lib`; `CtxDestroy`
   is now an `unsafe trait` encoding the zero-validity + destructor contract for
   the shared seam). Counted separately from sites converted — a converted site
   is not a discharged obligation. Full `SAFETY_DISCHARGED` enumeration still
   awaits the seal-point regeneration.
4. **Cryptographic assurance** — bounded; no new vectors run in this campaign
   (WycHEproof/ACVP/constant-time remain at their Phase-25 evidence state).
5. **Safe-compatible consumers** — 0 new families graduated (per AGENTS.md §7 a
   family needs its whole dependency closure `SAFETY_DISCHARGED`).

Trust-boundary budget: the remaining raw boundaries are the C ABI edge, the
`CRYPTO_*` seam, `#[repr(C)]` member buffers with object-lifetime owners, and
structs crossing fn-pointer tables.

## P0/P1 source targets (from the world-class-standard review)

- **P0 done**: `src/runtime/bio/owned.rs` (and 15 sibling files) — safe raw
  ownership adoption removed; ctors are `unsafe fn` with a real `# Safety`.
  Since then the same abstraction's *uninitialised* `OwnedCtx::malloc` was split
  into `RawCtx<T>` (block-only release) + `unsafe assume_init -> OwnedCtx<T>`
  (batch `stage/p25/rawctx`), and `Cert.custext` (zeroed `Vec`) was fixed
  (`stage/p25/zeroval`).
- **P0 done**: `src/asn1/owned.rs` — allocation-size multiplication now uses
  `checked_mul` with the module's failure outcome (batch `stage/p25/p0-abstractions`).
- **P0 done**: `src/x509/pcy_lib.rs` `tree_levels` — now takes
  `&mut X509PolicyTree` and returns a borrow tied to the owner.
- **P0 done (residual recorded)**: `src/x509/pcy_node.rs` `Node::parent_mut` —
  now takes `&mut self`; `Node: Copy` leaves multi-`Node` aliasing of one parent
  a documented caller obligation.
- **P1 open**: `CipherDestroy`/`CtxDestroy` implementer contract — the
  *shared* `bio::owned::CtxDestroy` is now an `unsafe trait` (batch
  `zerovalid`); the ~39 module-local `CtxDestroy` copies still need the same
  audit/funnel. Also: `src/ffi/mod.rs` post-panic state rules; secret-bearing
  classification. `ssl_lib.rs`'s `OwnedCtx::new` was migrated to
  `RawCtx`/`assume_init` (batch `ctor-soundness`), so that item is done.

## Member-buffer unit (in progress)

Model: `MEMBER-BUFFER-MODEL.md`. Object-owned C buffers stay raw in
`#[repr(C)]`; a per-type borrow view (`unsafe of` / safe `clear` / `unsafe
store` / safe reader) funnels every write/read/release so the invariant lives
in one place, and the field becomes **private** once all accessors convert
(compile-time enforcement).

Landed: PKCS7 `propq` (private), CMS `propq` (private), PKCS12 nested release,
X.509 `X509`/`X509_CRL`/`X509_REQ`/`X509_PUBKEY` (all private),
`X509_STORE_CTX` + cached-store `propq` (private), the `SslSession` buffers
`ext_hostname`/`ext_tick`/`ext_alpn_selected`/`ticket_appdata` and the
`SslSession` C-strings `psk_identity_hint`/`psk_identity`/`srp_username`
(all private; a latent ticket double-free closed), and the `SslCtx`/`Ssl`
buffers `propq` (26 readers routed, private), `CertKey.serverinfo` (via the
new documented `realloc` model op, private), `ext_hostname`, `s3_alpn_selected`,
`s3_alpn_proposed`, `pha_context` (all private), `ext_alpn`/`ext_npn`,
`client/server_cert_type` (private).
Remaining: only `Ssl`/`SslCtx.supportedgroups` (element-counted, raw-pointer
writer — deliberately **not** forced into the byte-extent model; recorded as a
retained boundary), then the other member-buffer families the dependency atlas
names for the 33 consumers.

## Destructor-trait audit (complete)

All **46** module-local destructor traits (`CtxDestroy`/`CipherDestroy`/
`MacDestroy`/`KdfDestroy`/`GcmDestroy`/`DrbgCtx`/`FreeOnDrop`) are now
`unsafe trait` with an explicit `# Safety` implementer contract; **0 safe
ones remain** (batches `ctxtrait-x509`, `ctxtrait-provider`, `ctxtrait-rest`).
Contract (a) destructor always; (b) zero-validity only where a safe
zalloc-wrap constructor relies on it. Traits were **not** consolidated
(contracts kept module-local, as their construction/release semantics
differ).

### Destructor-contract obligation census

`DESTRUCTOR-CONTRACTS.md` audits every destructor-contract implementation and
the `Drop` owners that run them: **199** implementations (136 `CtxDestroy`,
27 `CipherDestroy`, 14 `KdfDestroy`, 7 `MacDestroy`, 7 `FreeOnDrop`,
5 `DrbgCtx`, 3 `GcmDestroy`) across **49 trait definitions** (46 `*Destroy`
including 42 `CtxDestroy`, plus `DrbgCtx` and 2 `FreeOnDrop`). Result: **21 `CONTRACTED`, 178 `ESTABLISHED`, 0 `DISCHARGED`**;
**4 STOP defect sites / 3 classes** (null `hw` dereference in
`ProvAesSivCtx`/`ProvAesGcmSivCtx`; null `meth` dereference in
`EcGroup`/`EcPoint::clear_destroy_body`). No mechanism is discharged by this
audit; the defects are reported, not fixed.

## Receipts

Each landed batch records a receipt (template `RECEIPT.template.md`) so a fresh
session can resume from Git + the receipt without reconstructing reasoning.

## Canonical next action — Safe-33 continuation

**Branch:** `integrate/safe-c33`
**Last observed HEAD:** `261e07ded32e97b192bef94bafc77accc17c5c04`
**Objective:** Advance memory safety for the 33 existing downstream consumers while preserving OpenSSL 3.6.4 compatibility.

### Resume procedure

1. Check the actual integration-branch HEAD and working-tree state. Read `AGENTS.md`, this ledger, `MEMBER-BUFFER-MODEL.md`. Treat Git and committed evidence as authoritative.
2. Reconcile the ledger with the landed sweep batches and the adversarial-test unit. The committed atlas may predate the most recent sweeps; regenerate the lightweight atlas (`python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py`) against the current candidate before publishing completion numbers. Do **not** run the full Phase-25 seal.
3. Reproduce the residual-file inventory from current source, recording the exact command and file list. Treat any reported count as a checkpoint, not a newly verified count.
4. Select the next coherent batch of at most six files, prioritizing Safe-33 dependency closure, ownership risk and reusable improvements. Continue the `stage/p25/sweepN` convention.
5. Apply the standing conversion contract: preserve ABI/layout, allocator-hook coordinates and event order, initialization validity, failure semantics, and secret-cleansing guarantees. Account for eliminated, relocated, retained and introduced unsafe obligations; `hidden = 0` is mandatory.
6. Independently verify in the court container, one heavy command at a time:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `CARGO_BUILD_JOBS=4 cargo test --lib -- --test-threads=4`
   The most recent reported library baseline is **1214** tests. Do not accept unexplained test loss. Check available memory before builds.
7. Commit and push the verified batch, merge it into `integrate/safe-c33`, and update this ledger with exact files, mechanisms, gate results and remaining obligations. Repeat with another bounded batch.

### Outstanding targeted work

SSL member buffers are **complete** except the deliberately retained
`Ssl`/`SslCtx.supportedgroups` boundary (element-counted, raw-pointer writer —
not forced into the byte-extent model). Do **not** re-do `SslCtx.propq`,
`CertKey.serverinfo`, or the `Ssl` handshake-state writers: those are converted
and their fields are private. The remaining campaign work is the residual
conversion queue plus the member-buffer families named by the atlas.

Preserve and expand the adversarial allocator-refusal tests as these ownership
paths change. The TLS ticket double-free regression must remain covered, and
any change touching a callback/allocator edge must keep `scripts/adv-probe.sh`
green. Reentrancy evidence is scoped: the `serverinfo` observer probe proves
**publication ordering** (the old pointer/len is visible during `realloc` and
the new pair after), not soundness under arbitrary application callbacks that
recurse back into the object — that remains a §21 boundary obligation to state
and discharge explicitly.

### Non-negotiable evidence distinction

- Ownership reconstruction does not establish memory safety.
- A successful test run does not discharge every unsafe obligation.
- `SAFETY_DISCHARGED` requires explicit per-site evidence.
- `SAFE_COMPATIBLE` remains **0/33** pending dependency-closure discharge and current-candidate functional verification.
- Miri is unavailable on the pinned toolchain; record this limitation without implying its checks were performed.

**Stop and escalate:** any plausible soundness defect, behavioural divergence, unaccounted unsafe obligation, failing gate, or ambiguous ownership transfer. Do not hide residuals to complete a batch.

**Final handoff:** actual HEAD, changed files, test results, updated Safe-33 file counts, remaining blockers, and the next executable batch.
