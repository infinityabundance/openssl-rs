# Safe-33 unsafe→safe conversion — progress ledger

Authority: this file records *landed* conversion batches on `integrate/safe-c33`.
A batch is "landed" only when its local gate is green in the court container and
it is merged. The full Phase-25 forensic regeneration stays deferred until the
conversion campaign lands (see CLOSURE.md); the original Phase-25 site inventory
is retained only as the frozen baseline below.

Frozen atlas baseline (original inventory): **2420** allocation sites
(`artifacts/phase25/ownership-planes.json`).

## Current candidate-bound measurement

Regenerated at HEAD `e48a1b519` (`measurement_revision: 2`) by
`python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py`;
`atlas-refresh/verify_measurement.py` independently reconciles the scan against
comment/literal-stripped source and exits 0. See `atlas-refresh/REPORT.md`; the
generator is measurement-only and claims no discharge.

- Safe-33 closure: **628** files; **315** have a recognised ownership seam
  (**50.2%**); **0** files have fully discharged obligations; **0/33**
  consumers are `SAFE_COMPATIBLE`.
- Whole tree: **866** `src/**/*.rs`; **376** files have a seam.
- Disjoint call-site classes: **806** production allocation calls in **282**
  files; **863** production release calls in **299** files; **110** test-only;
  **71** in the allocator-seam implementations (`src/runtime/mem.rs`,
  `src/runtime/secure.rs`). 806 + 863 + 110 + 71 = **1,850** call sites, all
  matched as call expressions only — comments, imports and function-pointer
  table entries are excluded, and allocations are no longer added to releases.
- **16** files have at least one production allocation call and no recognised
  seam. A seam is a file-level heuristic, not a per-site proof.
- `atlas-refresh/site-worklist.json` is the per-site evidence queue: **1,669**
  production allocation/release call sites, each with file, line, allocator
  family, enclosing function and closure membership.

**Unsafe-operation denominator** (`unsafe_census.py`, artifacts
`atlas-refresh/unsafe-census.json` + `UNSAFE-CENSUS.md`, candidate source
`af25dd2f0`; the census commit is `15157bc32` and changes only `forensics/`):
**65,207** production site operations — 42,729 `unsafe {}` blocks, 13,431
`unsafe fn` definitions, 331 `unsafe impl`, 49 `unsafe trait`, 10 `unsafe extern`
blocks, 274 high-risk calls (`transmute`, `assume_init`, raw-parts,
`set_len`, …), 836 safe-ABI `extern "C"` definitions and 7,547 non-allocator
FFI calls; 4,227 test-only and 185 seam. Raw-pointer type contexts (47,965) are
reported separately and are **not** counted as operations. The scan is lexical
(not a Rust parser), is byte-deterministic, and `--check` independently
reconciles 117,584 counted sites. **38 of the 628 closure files contain zero
production operations** (36 of them zero unsafe-language/high-risk constructs);
they are listed in `UNSAFE-CENSUS.md` and are complete with respect to unsafe
code, subject to their safe-call dependencies.

Measurement reproduction (court container):

```sh
bash docker/openssl-rs-court.sh exec bash -c \
  'cd /work && python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py'
bash docker/openssl-rs-court.sh exec bash -c \
  'cd /work && python3 forensics/memory-safety/campaign/safe-c33/atlas-refresh/verify_measurement.py'
```

The generator is byte-deterministic. Do not quote the deprecated
`raw_sites_total` / `closure_raw_sites` keys: they mix allocations with releases
and predate revision 2.

Residual conversion queue (file level), exact procedure:

```sh
git log --name-only --format= integrate/safe-c33 \
  --branches='stage/p25/*' \
  --not b5bbb457ec6a3fd57ab5f9890d1bae3bbe7fe491 -- src/
# then join artifacts/phase25/ownership-planes.json allocation_sites rows to
# artifacts/phase25/source-census.json sites by site_id (row[7]) and subtract
# the touched set above
```

At HEAD `e48a1b519` the only file with an allocation site outside the touched
set is `src/runtime/mem.rs` — the allocator seam itself, which the atlas
excludes by rule. The file-level conversion queue is therefore **empty**; the
remaining work is per-site obligation evidence, not mechanical conversion.

Local gate for every batch (court container, 8 GB cap):
`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --lib` (must pass; the established baseline is **1240** passed
(one concurrent-refcount test added in subphase 39, eight
reference-count/re-entrancy tests added in subphase 40, seven
alias/ownership tests added in subphase 41, one lookup-`free` re-entrancy
test added in subphase 42, one isolated allocator-hook size/release test
added in subphase 43, and one isolated `CRYPTO_RWLOCK` allocator-hook
size/release test added in subphase 44) and the adversarial
probes are `#[ignore]`d and run separately via `scripts/adv-probe.sh`; as of
sweep 35 there are **18** probes).

## Open STOP blockers

**None open.**

**Resolved: STOP-1 — `up_ref` could wrap a live count into the destroying
sentinel.** `src/runtime/refcount.rs` computed `n + 1`; at `n == i32::MAX` that
panicked under overflow checks and wrapped to `i32::MIN` (`REF_DESTROYING`) with
them disabled, which would silently retire a live object.

Fixed on `stage/p25/refcount-overflow` (merge `d722f3238`): `up_ref` now uses
`checked_add(1)` and returns `0` **before** any compare-exchange when the count
would overflow, so the count is unchanged. Counts below `i32::MAX` are
bit-for-bit unchanged. At `i32::MAX` the authority's signed addition is UB; the
defined refusal is recorded as a §17 divergence in the module contract.
Regression: `runtime::refcount::tests::up_ref_refuses_overflow_without_changing_count`.
Independent verification: fmt clean, clippy `-D warnings` clean, **1218 passed /
0 failed / 18 ignored**, **18/18** probes; `down_ref` verified free of the
analogous underflow (it special-cases `n == 1`). The reference-count boundaries
are now eligible for discharge work, subject to the §7 independent-check
package.

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
| 78 | stage/p25/sweep35 | src/dsa/object, src/dh/object, scripts/adv-probe.sh | **targeted court**: later initialisation failure (`meth->init` returns 0) runs the partial cleanup — method `finish` once, one forwarded context allocation, one release of the same block, default method restored and exercised; allocation-refusal arm already covered; lock-null (Box-based) and ex-data failure are unreachable/non-injectable and not claimed (superseded in subphase 44: the measured-target lock is option B and its allocation is seam-visible); 18/18 probes; hidden 0 |
| 79 | stage/p25/sweep37 | provider/cipher, ec/lib, ssl/ssl_lib | **destructor zero-validity**: D1/D2 `hw` null guard and D3/D4 `meth` null guard make the clear bodies no-ops on the all-zero block; constructed-path order, layouts, coordinates and cleansing unchanged; Ssl `session_ticket` comment reconciled with the authority's raw release; 2 new deterministic zero-state negative controls; 18/18 probes; hidden 0 |
| 80 | stage/p25/sweep38 | DESTRUCTOR-CONTRACTS.md, PROGRESS.md | **subphase 38 adjudication (docs only)**: 19 `CONTRACTED` `CtxDestroy` rows independently re-read against every constructor/publication path; **16 promoted to `ESTABLISHED`**, **3 retained `CONTRACTED`** (`SslCtx`, `Ssl`, `X509Store`), **0 STOP defects**; no `DISCHARGED`; residual callback/non-atomic-refcount obligations recorded |
| 81 | stage/p25/sweep39 | src/x509/x509_lu.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **runtime/alias adjudication**: `X509Store` last-ref gate moved from plain `c_int` to layout-compatible `AtomicI32` (size 160 / offset 144 / align 8 asserts; relaxed fetch-add, release fetch-sub + acquire fence); concurrent up-ref test added; `SslCtx`/`Ssl`/`X509Store` retained `CONTRACTED` for reachable callback re-entrancy (ex-data / lookup `free` hook / `BIO_free_all`); 0 STOP; 1199 passed, 18 ignored; 18/18 probes; hidden 0 |
| 82 | stage/p25/sweep40 | src/runtime/refcount.rs, src/runtime/mod.rs, src/ssl/ssl_lib.rs, src/ssl/ssl_sess.rs, src/x509/x509_lu.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **callback-reentrancy repair**: shared `REF_DESTROYING` sentinel CAS in the existing `AtomicI32`; `*_free` claims the last reference `1 -> destroying` and a re-entrant/over-free is a defined no-op; `*_up_ref` refuses zero/destroying without resurrecting; applied to `Ssl`, `SslCtx`, `SslSession`, `X509Store`; 8 deterministic tests (4 protocol + 4 real ex-data re-entry); no layout/ABI/allocator/free-order change; 0 STOP; 1207 passed, 18 ignored; 18/18 probes; hidden 0 |
| 83 | stage/p25/sweep41 | src/ssl/ssl_lib.rs, src/ssl/ssl_sess.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **`Ssl`/`SslCtx` alias/lifecycle closure**: field-by-field ownership audit; fixed S1 session-cache `owner` dangling (UAF), S2 missing `ENGINE_finish`, S3 missing `dane_final`, S4 missing `ssl_clear_bad_session`; 7 deterministic tests; both rows promoted to `ESTABLISHED` (not `DISCHARGED`); no layout/ABI/allocator coordinates; 1214 passed, 18 ignored; 18/18 probes; hidden 0 |
| 84 | stage/p25/sweep42 | src/x509/x509_lu.rs, DESTRUCTOR-CONTRACTS.md, RUNTIME-ALIAS-EVIDENCE.md, PROGRESS.md | **`X509Store` callback closure + D1/D2 re-adjudication**: deterministic lookup-`free` hook re-entry test (hook once, observes `REF_DESTROYING`, `up_ref` refused, sentinel survives); teardown order audited against `x509_lu.c:240-253`; ex-data partial-release path retained (authority parity) and cached-`sk_num` callback divergence recorded; `ProvAesSivCtx`/`ProvAesGcmSivCtx` promoted to `ESTABLISHED`; `X509Store` promoted to `ESTABLISHED`; nothing `DISCHARGED`; 1215 passed, 18 ignored; 18/18 probes; hidden 0 |
| 85 | stage/p25/sweep43 | src/bn/recp.rs, OPAQUE-REPRESENTATIONS.md, PROGRESS.md | **P1 representation decision**: authority sizes measured in the court container (RWLOCK 56, STACK 40, LHASH 104, RECP 64; Rust 48/48/136/64); `BN_RECP_CTX` converted to option B (authority-size `CRYPTO_zalloc` block, inline Rust state, target-gated compile-time size/align asserts, exact 24/40 coordinates, single release); RWLOCK B feasible but deferred; STACK/LHASH retain A (B impossible); one deterministic isolated hook test; nothing `DISCHARGED`; 1216 passed, 18 ignored; 18/18 probes; hidden 0 |
| 86 | stage/p25/sweep44 | src/runtime/thread.rs, src/dsa/object.rs, src/dh/object.rs, OPAQUE-REPRESENTATIONS.md, PROGRESS.md | **`CRYPTO_RWLOCK` option B**: 56-byte `CRYPTO_zalloc` block at `crypto/threads_pthread.c:910`, inline `RwlockInner`, `drop_in_place` and `CRYPTO_free` at `:1005`, NULL on seam refusal; target-gated compile-time pointer/int/size/align asserts; `Box` on unmeasured targets; one isolated child-process hook test (56 bytes, read/write/unlock, single release, no second allocation); DSA/DH partial-cleanup probes updated to the authority-parity second (lock) release without weakening the double-free check; STACK/LHASH remain option A; nothing `DISCHARGED`; 1217 passed, 18 ignored; 18/18 probes; hidden 0 |

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

### Subphase 42 — `X509Store` callback closure and D1/D2 re-adjudication

- Added `x509::x509_lu::tests::store_free_from_lookup_free_hook_is_defined_noop`:
  a minimal `X509_LOOKUP_METHOD` installs only the `free` hook, which re-enters
  `X509_STORE_free` on the store being torn down. It asserts the hook ran once,
  `references == REF_DESTROYING` before re-entry, `X509_STORE_up_ref` answers 0
  without resurrecting, and the sentinel survives the re-entrant call. The
  single block release is the outer `OwnedCtx::<X509Store>` `Drop`.
- Audited the body against the authority (`x509_lu.c:240-253`): lookups →
  stack → objects → ex-data → param → lock → block, unchanged. The ex-data
  `free_func` runs after `get_cert_methods`/`objs` are freed (authority order);
  a callback that calls a store mutator reading them would see the freed stack.
  Recorded as a retained caller-contract obligation, not a conversion defect.
- Recorded one callback-mutation divergence: the candidate caches
  `OPENSSL_sk_num` before the lookup loop, so a hook that pushes a new lookup is
  freed by the authority but left on the freed stack here (leak only).
- `X509Store` promoted to `ESTABLISHED`. Re-adjudicated D1/D2
  (`ProvAesSivCtx`/`ProvAesGcmSivCtx`): both implementer obligations are now
  source-witnessed and the zero-state control passes, so both are promoted to
  `ESTABLISHED`. Nothing is `SAFETY_DISCHARGED`; the §7 independent-check
  package remains outstanding.
- Gate: `fmt` clean, clippy clean, **1215 passed / 18 ignored**, adv-probe
  **18/18**. Full evidence: `RUNTIME-ALIAS-EVIDENCE.md` §5 and
  `DESTRUCTOR-CONTRACTS.md` → “Subphase 42”.

### Subphase 43 — opaque-representation decision (P1)

- Measured the authority and Rust representations on the admitted
  `x86_64-unknown-linux-gnu` target in the court container. Full table, options
  A/B/C, tradeoffs and recommendations: `OPAQUE-REPRESENTATIONS.md`.
- `CRYPTO_RWLOCK` 56/8 vs Rust 48/8 (B feasible, deferred);
  `OPENSSL_STACK` 40/8 vs 48/8 (B impossible); `OPENSSL_LHASH` 104/8 vs 136/8
  (B impossible); `BN_RECP_CTX` 64/8 vs 64/8 (B implemented).
- `BN_RECP_CTX` now allocates one authority-sized block through
  `CRYPTO_zalloc(64, c"crypto/bn/bn_recp.c", 24)`, writes `RecpCtx` inline, and
  releases it at line 40 after `drop_in_place`. Target-gated compile-time
  `size_of`/`align_of` asserts; other targets retain option A.
- Deterministic test
  `bn::recp::tests::hook_observes_authority_size_and_single_release` installs a
  recording allocator in an isolated child process and asserts one 64-byte
  allocation at the authority's coordinate, one release of the same pointer at
  line 40, and no second allocation.
- `CRYPTO_RWLOCK`, `OPENSSL_STACK`, `OPENSSL_LHASH` retain Rust-owned
  representations (P1 hook invisibility). The reciprocal's limb `Vec` storage is
  still Rust-owned, so total allocation parity is not claimed. Nothing is
  `SAFETY_DISCHARGED`.
- Gate: `fmt` clean, clippy clean, **1216 passed / 18 ignored**, adv-probe
  **18/18**.

### Subphase 44 — `CRYPTO_RWLOCK` option B (P1)

- `CRYPTO_THREAD_lock_new` now calls
  `CRYPTO_zalloc(56, c"crypto/threads_pthread.c", 910)` and writes
  `RwlockInner` inline; a seam refusal returns NULL with no error, matching the
  authority. `CRYPTO_THREAD_lock_free` runs `drop_in_place` and releases the
  same 56-byte block at line 1005 through a release guard; NULL is still a no-op.
- Target-gated compile-time asserts (`linux`/`x86_64`/64-bit) cover pointer
  width, pointer size, C `int` size, and `size_of`/`align_of::<RwlockInner>()`;
  unmeasured targets retain the `Box` representation.
- Lock/read/write/unlock operate unchanged on the inline `Mutex`+`Condvar`. No
  exported signature, layout, allocator coordinate or free order changed. A
  tree-wide audit found no `Box::from_raw` of `CryptoRwlock` outside
  `runtime/thread.rs`, so there is no second release path. There is no exported
  `CRYPTO_THREAD_trylock` in the administered authority or this crate; the
  try-lock primitive is `ossl_crypto_mutex_try_lock`, which this decision does
  not touch.
- Deterministic test
  `runtime::thread::tests::lock_hook::hook_observes_authority_size_and_single_release`
  (isolated child process) asserts one 56-byte allocation at line 910,
  successful read-lock/write-lock/unlock, one release of the same pointer at
  line 1005, and no second allocation.
- The DSA/DH method-init-failure and restored-success probes now observe the
  lock's `CRYPTO_free` in addition to the context block (two releases, as the
  authority does). Their assertions were scoped and updated, not weakened: the
  context block must still appear exactly once and `assert_no_double_free`
  still runs.
- `OPENSSL_STACK` and `OPENSSL_LHASH` remain **option A** (B impossible:
  48 > 40 and 136 > 104); their headers stay hook-invisible. `CRYPTO_RWLOCK`'s
  header now has authority-size hook parity. The reciprocal's limb storage and
  the stack/lhash element storage remain Rust-owned. Nothing is
  `SAFETY_DISCHARGED`.
- Gate: `fmt` clean, clippy clean, **1217 passed / 18 ignored**, adv-probe
  **18/18**.

### Subphase 45 — unsafe-operation census (measurement)

- `unsafe_census.py` (imports the atlas comment/literal stripper) emits a
  deterministic per-file census with disjoint production / test-only / seam
  classes and an independent `--check` reconciliation (117,584 counted sites).
- At source `af25dd2f0`: **65,207** production site operations — 42,729 unsafe
  blocks, 13,431 unsafe fn definitions, 331 unsafe impls, 49 unsafe traits, 10
  unsafe-extern blocks, 274 high-risk calls, 836 safe-ABI extern definitions,
  7,547 non-allocator FFI calls; 4,227 test-only, 185 seam. Raw-pointer type
  contexts (47,965) are a separate context metric, not operations.
- **38 of 628 closure files have zero production operations** (36 zero
  unsafe-language/high-risk constructs); listed in `UNSAFE-CENSUS.md`.

### Subphase 46 — RC-1 reference-count boundary evidence

- `REFCOUNT-BOUNDARY.md` (RC-1) records the contract for the shared protocol:
  liveness/non-retiring precondition, `up_ref` may act on behalf of an existing
  owner (as `SSL_dup` does), exactly one release per acquired reference, and the
  four converted callers (`Ssl`, `SslCtx`, `SslSession`, `X509Store`). Other
  refcount implementations (EVP, ENGINE, DSO, ASN.1, `store_meth`, `ml_dsa`) are
  explicitly out of scope.
- Four tests added: unique last release across N threads, concurrent up/down
  conservation, an `up_ref`/last-release race sampler (`up_ref` ∈ {0,1} plus the
  terminal invariant), and a deterministic outcome-class witness. 9 tests in the
  module.
- Independent adversarial review initially **FAILED** on four documentation/test
  defects (stale UB claim, overbroad inventory sentence, wrong precondition
  wording, one-branch race test); all four were fixed and the re-check is
  **PASS**. Status remains `ESTABLISHED`, not `SAFETY_DISCHARGED` (ownership is
  caller-enforced; no Loom/Miri/TSan).
- Gate: `fmt` clean, clippy clean, **1222 passed / 18 ignored**, adv-probe
  **18/18**.

### Subphase 47 — owner-helper inventory and adoption-contract repair

- `OWNER-DUPLICATES.md` inventories **329** `Owned*`/`Raw*` definitions: 4
  canonical and 325 module-local (**173 IDENTICAL**, 26 DIFFERENT, 126
  MUST-STAY-LOCAL). All 56 local `OwnedCtx` and 5 local `RawCtx` are bound to 41
  module-local `CtxDestroy` traits and cannot be unified before the trait
  migration.
- **STOP-2 fixed:** `OwnedCtx::new` in `ssl/statem/statem_clnt.rs` and
  `statem_srvr.rs` was a **safe** ownership-adoption constructor whose `Drop`
  calls `T::free_on_drop(ptr)`. It is now `unsafe fn` with a `# Safety` contract
  (provenance, whole-block extent, alignment, init validity for the destructor,
  exclusive ownership); all 11 call sites are unsafe-wrapped with
  justifications.
- **§3 fixed** at `property/strings.rs`, `property/parse.rs` (x2),
  `property/store.rs` and `ssl/ssl_sess.rs`: checked arithmetic with the
  existing failure tail, no allocation/partial write/panic, coordinates and
  free order unchanged.
- `SSL_set_session_ticket_ext` previously sized with `ext_len.max(0)` and then
  copied `ext_len as usize`; a negative length reached a huge `memcpy` (UB). It
  now refuses with `0` before allocating. The authority is undefined there, so
  this is a §17 UB-elimination divergence (comment corrected after review).
- Independent review: **PASS** (one comment correction applied). Gate: `fmt` 0,
  clippy 0, **1222 passed / 18 ignored**, adv-probe **18/18**.

### Subphase 48 — B-R1a cleansing-buffer consolidation

- The 13 identical `{ptr, release}` `OwnedBuf` copies now use one shared
  `src/runtime/owned_buf.rs`. Release representation is **private**; safe
  constructors derive the cleansing length from the allocation length, so no
  safe path can pass a length beyond the block to `CRYPTO_clear_free`.
  `adopt_plain`, `adopt_cleansed` and the distinct-length constructor are
  `unsafe fn` with explicit provenance/extent/alignment/initialization/
  exclusivity/`num <= extent` contracts.
- Allocator selection, stored coordinates, release order and NULL policy are
  unchanged (`num = zlen` in `dh/pmeth`, `num = ktmplen` in `ec/pmeth`).
  `http_client`'s `len + 1` allocation is now checked.
- Adversarial review **FAILED** the first version (safe `new_cleansed`/
  `set_release` could manufacture an out-of-bounds cleansing length) and
  **PASSED** after the redesign; the remaining `len + 1` §3 finding was fixed
  and re-gated.
- Gate: `fmt` 0, clippy 0, **1227 passed / 18 ignored**, adv-probe **18/18**.
  Progress: **13 of 173** identical helpers consolidated.

### Subphase 49 — B-R1b and B-R3 consolidation

- Eighteen more copies (`B-R1b` 14, `B-R3` 4) now use the shared type. It gained
  a `SecureCleansed` arm (`CRYPTO_secure_clear_free`), separate
  allocation/release coordinates for constant-file cleansing releases, and
  NULL-tolerant **unsafe** adopt variants.
- Provenance is explicit in both directions: plain adoption excludes secure-heap
  pointers (`CRYPTO_free`/`CRYPTO_clear_free` on an arena pointer is UB), and
  secure adoption names the secure allocator or its documented plain fallback,
  with `num <= extent`.
- Secure tests no longer skip on failed heap initialisation; they assert init
  success and verify the arena bytes are cleansed after release. A dead-code
  witness shows no CMS/RSA secure allocation was downgraded.
- Adversarial review **FAILED** the first version (silent-skip tests, no
  cleansing assertion, ambiguous provenance) and **PASSED** after the fixes.
- Gate: `fmt` 0, clippy 0, **1230 passed / 18 ignored**, adv-probe **18/18**.
  Progress: **31 of 173** identical helpers consolidated.

### Subphase 50 — B-P plain buffers, first half

- Twenty of the 52 `{ptr, file, line}` plain-free copies now use the shared
  type: asn1 (mime, bio), async, cmp (hdr, protect), ct (b64, log, oct, sct,
  sct_ctx), decoder_pkey, ec (key, print), evp_lib, hpke, pkcs7 smime, property
  store, provider (dsa_sig, ecdsa_sig, init).
- Allocator selection, separate allocation/release coordinates, NULL semantics,
  release order and `into_raw` hand-offs preserved; six files with
  `empty`/`realloc`/`clear_realloc`, path-dependent release-line setters or
  `memdup` were deliberately left unchanged.
- Adversarial review **PASS** on the inspected hunks. Gate: `fmt` 0, clippy 0,
  **1230 passed / 18 ignored**, adv-probe **18/18**. Progress: **51 of 173**.

### Subphase 51 — B-P plain buffers, second half

- Nineteen more copies migrated (provider ml_kem_codecs/mod/rsa_enc/seed_src/
  sm2_sig, rsa/pmeth, runtime conf/def + confmod/mod + str, sm2/sign,
  srp/srp_lib, ssl ssl_asn1/ssl_cert_comp/ssl_conf/t1_lib/tls_srp, x509
  x509_req/x509_vpm/x_pubkey); 95 adoption sites, each with a SAFETY note.
- `rsa_enc.oaep_label` and `sm2_sig.id` hand-offs keep the field as sole owner;
  every new `let-else` replaced an Option-returning adopt, so no NULL became a
  new error. Seven files needing dynamic release re-pointing, array allocation
  or realloc stay local.
- Adversarial review **PASS**. Gate: `fmt` 0, clippy 0, **1230 passed / 18
  ignored**, adv-probe **18/18**. Progress: **70 of 173**.

### Subphase 52 — B-Z and B-L constant-coordinate consolidation

- Seventeen copies migrated (`B-Z` 13, `B-L` 4 of 8). Constant coordinates
  use `new_plain_released`; `memdup`/`calloc` sites keep a local allocating
  wrapper returning the shared owner with the same seam coordinates;
  `v3_conf`'s `take_raw` is preserved as `into_raw` plus re-seeding an empty
  owner, so `free(NULL)` on tail/error paths is unchanged.
- Four `B-L` files with mutable/path-dependent release lines remain local.
- Adversarial review **PASS** (coverage caveat on 10 hunks checked by coordinate
  grep). Gate: `fmt` 0, clippy 0, **1230 passed / 18 ignored**, adv-probe
  **18/18**. Progress: **87 of 173**.

### Subphase 53 — always-cleanse groups consolidated

- Twelve copies (`B-CA-FL` 5, `B-CA-0` 5, `B-CF-FL` 2 of 3) now use the shared
  cleansing owner: asn1 a_sign/a_verify/t_pkey, dsa/sign, ec/ecx_meth, evp
  evp_pkey/pem_bridge, provider/keymgmt, rsa ameth/ossl/sign, slh_dsa/dsa.
  Release functions, both coordinate pairs, cleansing lengths and release order
  are unchanged. `bn/rand` stays local (owner-derived mutable slice).
- **§5 correction:** `evp_pkey` adopted PKCS#8 private-key DER with a plain
  free. It now cleanses the same extent (`num` = the encoder BUF_MEM length) at
  the authority's `(NULL, 0)` coordinates; the §17 divergence is recorded in
  code. Public-key DER remains a plain release.
- Adversarial review **FAILED** on that one point and **PASSED** after the fix.
  Gate: `fmt` 0, clippy 0, **1230 passed / 18 ignored**, adv-probe **18/18**.
  Progress: **99 of 173**.

### Subphase 54 — `OwnedStr` and the S-P string group

- New `src/runtime/owned_str.rs`: a possibly-NULL C string with stored release
  coordinates and plain NULL-tolerant `CRYPTO_free`. Constructors preserve each
  site's allocator (`strdup`/`strndup`/`malloc`) and separate allocation/release
  coordinates; `adopt` / `adopt_nullable` are `unsafe` with provenance,
  NUL/extent, alignment and exclusive-ownership contracts.
- Ten S-P copies migrated: cmp client/ctx/genm, ct log/sct_ctx, dso, provider
  init/keymgmt/ml_dsa_kmgmt/slh_dsa_kmgmt. Allocator, coordinates, NULL
  semantics, release order and `into_raw` hand-offs unchanged; dso's len-only
  malloc path keeps its `DSO_pathbyaddr` NUL contract.
- Adversarial review **PASS** (one overstated test name fixed). Gate: `fmt` 0,
  clippy 0, **1235 passed / 18 ignored**, adv-probe **18/18**. Progress: **109
  of 173**.

### Subphase 55 — S-L and S-Z string groups

- Twenty copies migrated (`S-L` 11, `S-Z` 9). Allocators, both coordinate
  pairs, NUL semantics, release order and NULL behavior unchanged; `ui_lib`'s
  const accessor keeps its exact pointer type; `conf/api`'s malloc keeps
  `(NULL,0)` coordinates.
- `http_lib` and `v3_akid` stay local because they re-point the release
  coordinate at live call sites (verified by quoting the setters and call
  sites); `bio_sock2` stays local because it needs `CRYPTO_zalloc`.
- Adversarial review **PASS**. Gate: `fmt` 0, clippy 0, **1235 passed / 18
  ignored**, adv-probe **18/18**. Progress: **129 of 173**.

### Subphase 56 — `OwnedBlock` groups

- Eleven of fifteen copies migrated: `OB-P` 7 (evp e_aes/e_aria, ec/smpl,
  property/parse, ssl ssl_lib + statem_clnt + statem_srvr), `OB-Z` 2
  (provider/file_store, store/store_lib), `OB-Cond` 2 (evp/digest,
  evp/pkey_ctx).
- New `Release::Conditional` + `unsafe adopt_conditional(ptr,num,clear,file,line)`;
  `clear` is fixed at construction, `num <= extent` is part of the contract, and
  `Drop` selects `CRYPTO_clear_free`/`CRYPTO_free` exactly as the old guards did.
  Every migrated `clear` value matches the old derivation.
- Four stay local: `x509/v3_utl` (mutable release line), `asn1/string`
  (`CRYPTO_realloc`), `evp/pkey` and `crmf/crmf_lib` (`set_clear` after
  construction).
- Adversarial review **PASS**. Gate: `fmt` 0, clippy 0, **1236 passed / 18
  ignored**, adv-probe **18/18**. Progress: **140 of 173**.

### Subphase 57 — small owner groups

- Eight copies migrated: `OwnedIkm` (ecx_kem) and `OwnedUniPass` (p12_key) to
  `adopt_cleansed` (stored length, coordinates and cleanse-before-free probe
  preserved); `OwnedScratch` (mac, rand), `OwnedLogBuf` (bss_log),
  `OwnedSlotBuf` (err, err_state), `OwnedExtValue` (v3_prn) and `OwnedI2s`
  (v3_sxnet) to the shared buffer/string owners.
- Added unsafe `OwnedBuf::new_strndup(str, max, file, line)` with a
  NULL/readable-for-`max` contract; no borrowed const string became an owner.
- Adversarial review **PASS**. Gate: `fmt` 0, clippy 0, **1236 passed / 18
  ignored**, adv-probe **18/18**. Progress: **148 of 173**.

### Subphase 58 — shared-owner API extensions and B-P exclusions

- Added metadata-only `set_release_line`, Conditional-only `set_clear` (preserves
  the construction-time `num <= extent` invariant), `new_zeroed_released`,
  unsafe `new_memdup` and unsafe `new_array` (checked product, overflow →
  `None`), with four focused tests.
- Twelve B-P exclusions migrated: cmp_vfy, crmf_pbm, evp/mac, p12_decr,
  ml_dsa_codecs, ts_rsp_sign, txt_db, v3_ncons, x_name, x509spki, ssl_rsa,
  x_x509. Allocator, coordinates, release mode/order and NULL policy unchanged
  (p12_decr's file was already the module constant; ssl_rsa keeps 818/827).
- `asn1/text` remains local: it needs `CRYPTO_realloc`/`CRYPTO_clear_realloc`
  with changing extents and a NULL-initialised empty handle.
- Adversarial review **PASS** (two hunks checked by diffstat only; gates green).
  Gate: `fmt` 0, clippy 0, **1240 passed / 18 ignored**, adv-probe **18/18**.
  Progress: **160 of 173**.

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
  opaque objects. Subphases 43–44 measured all four and recorded the decision in
  `OPAQUE-REPRESENTATIONS.md`: `BN_RECP_CTX` and `CRYPTO_RWLOCK` use **option B**
  (authority-sized `CRYPTO_*` block, inline Rust state, exact 64/56-byte hook
  events), while `OPENSSL_STACK` and `OPENSSL_LHASH` retain **option A** because
  B is impossible (`size_of::<Rust>() > size_of::<C>()`). The remaining
  **compatibility residual P1** is allocator-hook byte-size parity for those two
  remaining headers and for the reciprocal's limb storage; it is recorded, not
  hidden, and does not claim discharge.
- `bn/bn_srp.rs` — no interior CRYPTO allocation site; arithmetic-only.
- `x509/v3_no_ass.rs` — returns a caller-owned `CRYPTO_strdup` block to the
  extension machinery; the transfer contract is the boundary.

## Next queue

**As of subphase 44 the residual census queue is fully classified and the P1
representation decision is recorded and partly implemented.** Sweeps 11–29
converted or boundary-documented the mechanical tail; sweeps 30–32 classified
the structural/no-seam set; subphases 43–44 measured the four opaque objects.
`BN_RECP_CTX` and `CRYPTO_RWLOCK` now have authority-size hook parity for their
header blocks, while `OPENSSL_STACK` and `OPENSSL_LHASH` remain option A because
B is impossible (`OPAQUE-REPRESENTATIONS.md`). The reciprocal's limb storage and
the stack/lhash element storage remain hook-invisible; that is the remaining
**P1 hook-size residual**, not a discharge claim.

The queue is re-derived from Git + `artifacts/phase25/source-census.json` with
the exact snippet in “Current candidate-bound measurement”; do not treat any
list here as frozen. At `e48a1b519` the file-level queue is empty. The
remaining work is **not** more mechanical conversion: it is per-site obligation
evidence over `atlas-refresh/site-worklist.json` (1,669 production call sites),
the remaining P1 residuals, and the seal (`SAFETY_DISCHARGED` promotions and
current-candidate consumer verification).

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
including 42 `CtxDestroy`, plus `DrbgCtx` and 2 `FreeOnDrop`). `PROGRESS.md`
previously reported the subphase-37 checkpoint (178 `ESTABLISHED` / 21
`CONTRACTED`); **that figure is obsolete.** After subphases 38–43 the current
result is **199 `ESTABLISHED`, 0 `CONTRACTED`, 0 `DISCHARGED`** — authoritative
per-row detail is in `DESTRUCTOR-CONTRACTS.md`. Source-established is not
`SAFETY_DISCHARGED`: no row has the §7 independent-check package. The 4 STOP
defect sites found by the audit (null `hw` in `ProvAesSivCtx`/
`ProvAesGcmSivCtx`; null `meth` in `EcGroup`/`EcPoint::clear_destroy_body`)
were fixed in subphase 37 with deterministic zero-state controls.

## Receipts

Each landed batch records a receipt (template `RECEIPT.template.md`) so a fresh
session can resume from Git + the receipt without reconstructing reasoning.

## Canonical next action — Safe-33 continuation

**Branch:** `integrate/safe-c33`
**Last observed HEAD:** `9d645c7b3` (B-P exclusion semantics merged)
**Objective:** Advance memory safety for the 33 existing downstream consumers while preserving OpenSSL 3.6.4 compatibility.

### Resume procedure

1. Check the actual integration-branch HEAD and working-tree state. Read `AGENTS.md`, this ledger, `MEMBER-BUFFER-MODEL.md`. Treat Git and committed evidence as authoritative.
2. Reconcile the ledger with the landed sweep batches and the adversarial-test unit. The committed atlas may predate the most recent sweeps; regenerate the lightweight atlas (`python3 forensics/memory-safety/campaign/safe-c33/atlas_refresh.py`) against the current candidate before publishing completion numbers. Do **not** run the full Phase-25 seal.
3. Reproduce the residual-file inventory with the exact snippet in “Current candidate-bound measurement”. At `8bea24d49` it is empty apart from the allocator seam; do not invent new conversion work.
4. The remaining work is **obligation discharge**, not mechanical conversion. Execute the next subphase below (unsafe-operation census), then per-boundary evidence, one subagent at a time.
5. Apply the standing conversion contract to any change: preserve ABI/layout, allocator-hook coordinates and event order, initialization validity, failure semantics, and secret-cleansing guarantees. Account for eliminated, relocated, retained and introduced unsafe obligations; `hidden = 0` is mandatory.
6. Independently verify in the court container, one heavy command at a time:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `CARGO_BUILD_JOBS=4 cargo test --lib -- --test-threads=4`
   The most recent reported library baseline is **1218** tests (18 ignored; 18/18 adversarial probes via `scripts/adv-probe.sh`). Do not accept unexplained test loss. Check available memory before builds.
7. Commit and push the verified batch, merge it into `integrate/safe-c33`, and update this ledger with exact files, mechanisms, gate results and remaining obligations. Repeat with another bounded batch.

### Outstanding targeted work

SSL member buffers are **complete** except the deliberately retained
`Ssl`/`SslCtx.supportedgroups` boundary (element-counted, raw-pointer writer —
not forced into the byte-extent model). Do **not** re-do `SslCtx.propq`,
`CertKey.serverinfo`, or the `Ssl` handshake-state writers: those are converted
and their fields are private.

`BN_RECP_CTX` and `CRYPTO_RWLOCK` now have authority-size hook parity;
`OPENSSL_STACK` and `OPENSSL_LHASH` are deliberately option A
(`OPAQUE-REPRESENTATIONS.md`). The file-level conversion queue is **empty**; the
remaining work is per-site obligation evidence over
`atlas-refresh/site-worklist.json` (1,669 production allocation/release calls)
and the boundary families below.

Preserve and expand the adversarial allocator-refusal tests as these ownership
paths change. The TLS ticket double-free regression must remain covered, and
any change touching a callback/allocator edge must keep `scripts/adv-probe.sh`
green. Reentrancy evidence is scoped: the `serverinfo` observer probe proves
**publication ordering** (the old pointer/len is visible during `realloc` and
the new pair after), not soundness under arbitrary application callbacks that
recurse back into the object — that remains a §21 boundary obligation to state
and discharge explicitly.

### Next executable subphase — obligation denominator (unsafe-operation census)

**Status: done** (`15157bc32`; see “Unsafe-operation denominator” above and
`atlas-refresh/UNSAFE-CENSUS.md`). The file-level conversion queue is empty and
the unsafe-obligation denominator now exists.

**Next in sequence:** continue consolidating the IDENTICAL module-local owner
helpers in disjoint staged groups. Done: `B-R1a` (13), `B-R1b` (14), `B-R3` (4),
`B-P` (39 of 52; 13 need shared-API extensions), `B-Z` (13), `B-L` (4 of 8;
4 excluded), `B-CA-FL` (5), `B-CA-0` (5), `B-CF-FL` (2 of 3; `bn/rand` needs an
owner-derived slice accessor), `OwnedStr` (30 of 33; `http_lib`, `v3_akid`,
`bio_sock2` excluded pending mutable-release/zalloc API), `OwnedBlock` (11 of 15;
`v3_utl`, `asn1/string`, `evp/pkey`, `crmf/crmf_lib` excluded pending
mutable-release/realloc/set_clear API). Remaining: `B-P` exclusions (13), `B-L`
exclusions (4), `B-CF-FL` (`bn/rand`), `OwnedStr` exclusions (3), `OwnedBlock`
exclusions (4), plus the small OwnedIkm/OwnedUniPass/OwnedScratch/
constant-char* groups (8). Do not
touch the 26 DIFFERENT or 126 MUST-STAY-LOCAL copies. Each group needs a caller
inventory, adversarial review and a fresh gate. Afterwards, the
`CtxDestroy`/`CipherDestroy` shared-trait migration that unblocks the 61 local
`OwnedCtx`/`RawCtx` copies, then member-buffer slots, per-file audits by
consumer reachability, and seal evidence before any `SAFETY_DISCHARGED` /
`SAFE_COMPATIBLE` promotion.

**Why:** the campaign can count allocation sites but cannot state how many
unsafe obligations exist, nor which of the 628 closure files contain none. Until
that denominator exists, “file done” is not measurable.

**Deliverables (one subagent, no `src/` edits):**

1. `forensics/memory-safety/campaign/safe-c33/unsafe_census.py`, reusing the
   comment/string stripper from `atlas_refresh.py` (import it; do not diverge).
2. `atlas-refresh/unsafe-census.json` — deterministic; per file: closure
   membership, seam status, production/test-only/seam totals, and every site as
   `{line, kind, function}`.
3. `atlas-refresh/UNSAFE-CENSUS.md` — totals by kind, top 25 production files,
   and the count/list of closure files with **zero** production unsafe ops.
4. A `--check` mode that re-derives totals from stripped source and exits
   nonzero on mismatch.

Kinds: `unsafe {}` blocks; `unsafe fn`; `unsafe impl`; `unsafe trait`;
`unsafe extern`; high-risk calls (`transmute`, `assume_init`,
`from_raw_parts[_mut]`, `Box::from_raw`, `NonNull::new_unchecked`,
`get_unchecked[_mut]`, `unreachable_unchecked`, `set_len`); `extern "C"`
definitions and non-allocator `CRYPTO_*`/`OPENSSL_*`/`ossl_*` calls; raw-pointer
type declarations reported separately as a context metric, never as unsafe ops.
Allocator calls stay in `site-worklist.json` so the two counts never
overlap.

Acceptance: two runs byte-identical; `--check` exit 0; production + test-only +
seam counts reconcile with an independent stripped-source grep; residual
limitations (macro expansion, `#[path]`, per-field `cfg`) stated explicitly.

**Then, in order:** (a) boundary records and independent checks for
`OwnedBlock`/`OwnedBuf`/`OwnedStr`/`OwnedRaw` adoption and release, member-buffer
slots, and the `CtxDestroy`/`CipherDestroy` constructor contracts;
(b) per-file audits in consumer-reachability order, using the unsafe census as
the worklist; (c) seal evidence (ASan, loom, differential courts against
`forensics/authorities/src/openssl-3.6.4/`, the 8 L7-functional consumers) and
only then `SAFETY_DISCHARGED` / `SAFE_COMPATIBLE` promotions.

**Session note (2026-10-17):** this session ended when subagent spawning became
impossible — the conversation context (~822k tokens) plus the provider's 384k
completion reserve exceeds the 1,048,576-token limit, and OpenRouter fallbacks
have no credits. No project command was run on the host. Landed in this session:
subphase 44 (`CRYPTO_RWLOCK`, HEAD `c66812cb4`), atlas regeneration at
`893e4e6e2`, measurement revision 2 (`e48a1b519`), and this ledger
reconciliation. Resume in a fresh session; the state above is committed.

### Non-negotiable evidence distinction

- Ownership reconstruction does not establish memory safety.
- A successful test run does not discharge every unsafe obligation.
- `SAFETY_DISCHARGED` requires explicit per-site evidence.
- `SAFE_COMPATIBLE` remains **0/33** pending dependency-closure discharge and current-candidate functional verification.
- Miri is unavailable on the pinned toolchain; record this limitation without implying its checks were performed.

**Stop and escalate:** any plausible soundness defect, behavioural divergence, unaccounted unsafe obligation, failing gate, or ambiguous ownership transfer. Do not hide residuals to complete a batch.

**Final handoff:** actual HEAD, changed files, test results, updated Safe-33 file counts, remaining blockers, and the next executable batch.
