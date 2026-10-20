# OWNER-CALLERS — OB-1: `runtime::owned_buf::OwnedBuf`

**Source identity:** branch `integrate/safe-c33`, HEAD `a98fd53e901404395f8d6118878875f8bbe831ef`.
**Scope:** every call in `src/` to an `unsafe` constructor of the shared
`runtime::owned_buf::OwnedBuf` (`OB-1`). Safe allocating constructors are in
scope only as “no obligation beyond the length argument”; ordinary calls to
them are not audited. Module-local types also named `OwnedBuf`
(`apps/mac.rs`, `asn1/text.rs`, `bn/rand.rs`, `ml_dsa/{encoders,key,sign}.rs`,
`ml_kem/key.rs`, `pem/pvkfmt.rs`, `pkcs12/p12_utl.rs`, `provider/kdf.rs`,
`provider/mac_legacy_kmgmt.rs`, `rand/pool.rs`) are **different types** and are
excluded.

## Enumerated unsafe constructors on the shared type

| constructor | file:line | obligation |
|---|---|---|
| `new_array` | `runtime/owned_buf.rs:154` | `count*size` is the intended extent and all later accesses stay inside it |
| `new_memdup` | `:179` | `src` NULL or readable for `len` |
| `new_cleansed_num` | `:324` | `num <= len` |
| `new_strdup` | `:343` | NUL-terminated or NULL |
| `new_strndup` | `:366` | NULL or readable for `max` |
| `adopt_plain` | `:404` | plain `CRYPTO_*` seam provenance, whole-block identity, alignment, exclusive ownership, exact plain release coordinates |
| `adopt_conditional` | `:432` | as `adopt_cleansed`, plus `num <= extent` and the authority's `clear` decision fixed at construction |
| `adopt_cleansed` | `:476` | plain `CRYPTO_*` seam provenance (**secure heap excluded**), `num <= extent`, exact cleansing release coordinates |
| `adopt_plain_nullable` | `:502` | as `adopt_plain`; NULL is the authority's empty block |
| `adopt_cleansed_nullable` | `:525` | as `adopt_cleansed`; NULL accepted |
| `adopt_secure_cleansed` | `:562` | secure-heap provenance (or that allocator's documented plain fallback), `num <= extent`, exact secure cleansing release |

There are no other `unsafe` constructors on the shared type; the other
`impl OwnedBuf` blocks in the tree belong to the local types listed above.

## Method

Each call is recorded with a provenance witness, an extent/length witness and a
release witness. A comment, a `SAFETY:` line, or a contract claim is **not**
accepted as a witness. Accepted provenance facts are: (P1) the pointer is the
direct result of an allocating call in the argument; (P2) it is a local
out-parameter or local assigned from such a call in the same function; (P3) it
is a struct member whose only writes in the unit are from such a call (witness
line cited, including other files); (P4) it is a caller-supplied pointer under
an exported C-ABI / `# Safety` contract; (P5) it is NULL, the authority's
`free(NULL)` no-op. Test-only sites are marked `TEST`.

## Summary

| metric | count |
|---|---:|
| call expressions (production + test) | **458** |
| production | **455** |
| test-only | **3** |
| ESTABLISHED (production) | **455** |
| ESTABLISHED (test-only) | **3** |
| UNATTRIBUTED (production) | **0** |
| DEFECT | **0** |

By constructor (all 458): `adopt_plain_nullable` 212, `adopt_plain` 191,
`adopt_cleansed` 34, `adopt_conditional` 9, `adopt_cleansed_nullable` 4,
`new_strdup` 2, `adopt_secure_cleansed` 3, `new_cleansed_num` 1,
`new_memdup` 1, `new_strndup` 1. `new_array` no longer has a production
caller: `x509spki` now uses the safe `OwnedBuf::new` with the encoder's exact
extent. (The raw `grep` count for `adopt_cleansed` is 36; two matches are doc
comments.)

## Findings

**F1 — FIXED (was DEFECT; OB1-0262, `src/provider/ecx_kmgmt.rs:1010`).**
`ecx_set_params` released `ecxkey->privkey` through `OwnedBuf::adopt_cleansed`
(plain `CRYPTO_clear_free`). That field is allocated by
`ossl_ecx_key_allocate_privkey` with `CRYPTO_secure_zalloc(keylen)`
(`src/ec/ecx_key.rs:244`), and the authority's destructor releases it with
`OPENSSL_secure_clear_free` (`ecx_key.c:81`). Authority evidence also shows
this particular site (`ecx_kmgmt.c:930`) is a plain `OPENSSL_clear_free` of the
secure block — an authority invalid free once the secure heap is initialised;
per §17 it is not reproduced. The site now uses `adopt_secure_cleansed` at the
same extent (`keylen`) and coordinates; it also covers the secure allocator's
documented plain fallback when the heap is uninitialised. Tests exercise both
the live-heap and fallback arms.

**F2 — FIXED (was UNATTRIBUTED; OB1-0456, `src/x509/x509spki.rs:146`).**
`NETSCAPE_SPKI_b64_encode` allocated `new_array(der_len, 2)` (`2*der_len`
bytes), then called `EVP_EncodeBlock`, which writes `4*ceil(der_len/3)+1` bytes
(the terminator included). `2*n` under-sizes the encoder for `n = 1, 2 and 4`, and the
sizing `i2d_NETSCAPE_SPKI` only proves `der_len > 0`. The allocation is now the
encoder's exact extent, computed with checked arithmetic
(`4*((n+2)/3)+1`) and allocated with the safe `OwnedBuf::new`; allocation
failure answers NULL exactly as before. This is a deliberate §17 overrun
correction, not a compatibility change to the returned string.

**F3 — FIXED (OB1-0150, `src/evp/kdf.rs:1317`).**
The failure path converted a `new_zeroed_cleansed_at` block to `raw` and adopted
it with `adopt_plain`; `CRYPTO_free` was valid, but possibly secret-bearing
derived-key bytes were left uncleansed (§5). It now adopts with
`adopt_cleansed` over the known allocation length (`keylen`) at the authority's
failure-site coordinate. The authority's own plain failure free (`kdf_lib.c:250`)
is not reproduced; this is a recorded §17 safety divergence, unobservable in any
OpenSSL result. A canary test asserts the cleansing arm and length.

**F4 — contract-only sites (re-audited; no safe fn found).**

The `EVP_PKEY_CTRL_*_KDF_UKM` and `EVP_PKEY_CTRL_RSA_OAEP_LABEL` arms
(`ec/pmeth.rs:670`, `dh/pmeth.rs:388`, `rsa/pmeth.rs:1147`) release a block
that entered through a caller-supplied `p2` (a repeated set0 replaces, and
releases, the previous caller block). The `params/mod.rs:2987/3132/3159`
adoptions release the caller's `*out`/`*out_len` pair. These are ESTABLISHED as
trust-boundary obligations, but no in-crate type prevents a safe caller from
violating them.

Every named contract-only site was checked for the ABI boundary and for a
function-level `# Safety` that states provenance and extent:

| site | enclosing declaration | boundary evidence | `# Safety` provenance/extent | verdict |
|---|---|---|---|---|
| `src/ec/pmeth.rs:670` | `unsafe extern "C" fn pkey_ec_ctrl(` @525 | declared `unsafe extern "C"`; `# Safety` @519-524 | *“As [`crate::evp::pkey_ctx::PkeyMethCtrlFn`]”* plus the `EC_KDF_UKM` seam/length clause; the alias @`evp/pkey_ctx.rs:1751-1776` now documents the same obligation | **proven** |
| `src/dh/pmeth.rs:388` | `unsafe extern "C" fn pkey_dh_ctrl(` @278 | declared `unsafe extern "C"`; `# Safety` @272-277 | same alias plus the `DH_KDF_UKM` seam/length clause | **proven** |
| `src/rsa/pmeth.rs:1147` | `unsafe extern "C" fn pkey_rsa_ctrl(` @902 | declared `unsafe extern "C"`; `# Safety` @896-901 | same alias plus the `RSA_OAEP_LABEL` seam/length clause | **proven** |
| `src/params/mod.rs:2987` | `pub(crate) unsafe fn ossl_param_get1_octet_string_from_param(` @2964 | `unsafe fn`; every caller is an `unsafe fn`/`unsafe extern "C"` (see below) | *“`*out` must be NULL or a block of `*out_len` bytes from this allocator.”* @2960-2963 | **proven** |
| `src/params/mod.rs:3132` | `pub(crate) unsafe fn ossl_param_get1_concat_octet_string(` @3107 | as above | *“`*out` NULL or a block of `*out_len` bytes from this allocator”* @3102-3106 | **proven** |
| `src/params/mod.rs:3159` | same declaration @3107 | as above | same contract; `*out_len` is the prior success's length | **proven** |
| `src/asn1/asn_mime.rs:624` | `unsafe fn asn1_write_micalg(` @556; called @773 from `unsafe extern "C" fn SMIME_write_ASN1_ex(` @714 | unsafe fn reachable from one `unsafe extern "C"` | *“The `EVP_MD_CTRL_MICALG` arm … `md_ctrl` … NUL-terminated string … plain `CRYPTO_*` seam … extent is the string plus its terminator … ownership transfers … single release through `CRYPTO_free` — the authority's `OPENSSL_free(micstr)` at `crypto/asn1/asn_mime.c:189`”* @545-554 | **proven** |
| `src/cms/cms_env.rs:1163` | `unsafe fn adopt_decrypted_key(` @1160; chain `cms_RecipientInfo_ktri_decrypt` @1171 → `CMS_RecipientInfo_decrypt` `unsafe extern "C"` @2064 | unsafe fn reachable from one `unsafe extern "C"` | *“`ptr` is NULL or the whole, exclusively owned block `evp_pkey_decrypt_alloc` returned; `num` is the produced length … not larger than the allocation.”* @1157-1159 | **proven** |
| `src/ct/ct_sct.rs:336/463/536` | `pub unsafe extern "C" fn SCT_set0_log_id(` @321, `SCT_set0_extensions(` @459, `SCT_set0_signature(` @531 | declared `unsafe extern "C"` with `#[no_mangle]`; a public C entry, so the text states the obligation is the C caller's | *“a block obtained from this crate's **plain** `CRYPTO_*` allocator seam (`CRYPTO_malloc`, `CRYPTO_memdup` or `CRYPTO_strdup`) … allocation extent is at least `log_id_len` … ownership transfers … `SCT_free` releases it exactly once with `CRYPTO_free(ptr, NULL, 0)` (authority `ct_sct.c:85`/`:34-44`) … the V1 length refusal does not adopt”* @303-317; analogous @441-455 for `ext_len`, @513-527 for `sig_len` | **proven** |
| `src/provider/ecx_kmgmt.rs:1031` | `unsafe extern "C" fn ecx_set_params(` @1003 | declared `unsafe extern "C"` | *“`(*key).privkey` … `CRYPTO_secure_zalloc((*key).keylen, ...)` (`ec/ecx_key.rs:105`/`:244`) … allocation extent is exactly `keylen` … takes that ownership and releases it once through `CRYPTO_secure_clear_free(ptr, keylen, ...)` … at `ecx_kmgmt.c:930` … `params` … is **borrowed, not adopted** … `CRYPTO_strdup` (`ecx_kmgmt.c:851`)”* @990-1002 | **proven** |
| `src/provider/ml_kem_kmgmt.rs:1190` | `unsafe fn load_err(` @1181; called from `unsafe extern "C" fn ml_kem_load(` @1105 | unsafe fn reachable from one `unsafe extern "C"` | *“`encoded_dk` … `CRYPTO_secure_malloc((*p8fmt).priv_length, ...)` (`ml_kem_codecs.rs:696`) … extent equals `key->vinfo->prvkey_bytes` (the codec checks that equality at `ml_kem_codecs.rs:627-628`) … ownership transfers … releases it exactly once through `CRYPTO_secure_clear_free(encoded_dk, prvkey_bytes, ...)` (`ml_kem_kmgmt.c:535`)”* @1169-1180 | **proven** |
| `src/runtime/conf/def.rs:1649/1663/1689/1695/1701` | `unsafe fn finish_with_error(` @1630; called @1578 from `unsafe extern "C" fn def_load_bio(` @973 | unsafe fn reachable from one `unsafe extern "C"` | *“`section` … `CRYPTO_strdup(c"default", ...)` (`:1005`), extent `strlen + 1`; `dirpath` … `include_path` whose ownership `process_include` transfers (`:1432`, `:1786`) … `v` … `CRYPTO_malloc(size_of::<ConfValue>())` (`:1504`) … `v->name` … `CRYPTO_strdup` (`:1512`) … `v->value` … `BUF_MEM` data block `str_copy` installed (`:732`) … each released exactly once through `CRYPTO_free` (authority `conf_def.c:571`/`:584`/`:597-599`)”* @1606-1628 | **proven** |
| `src/ssl/ssl_cert_comp.rs:155` | `unsafe fn OSSL_COMP_CERT_new(` @144; chain `OSSL_COMP_CERT_from_compressed_data` @188 → `ssl_compress_one_cert` @310 → `ssl_compress_certs` @346 | all unsafe fns; the chain's top (`ssl_compress_certs`) has **no in-tree caller**, so it is not currently an extern-C edge | *“`data` … block returned by this crate's `CRYPTO_memdup(src, len, ...)` in `OSSL_COMP_CERT_from_compressed_data` (`ssl_cert_comp.rs:180`) … allocation extent is exactly `len` … ownership transfers … released exactly once with `CRYPTO_free` — authority `OPENSSL_free(data)` at `ssl_cert_comp.c:78`/`:145` … the authority compiles this only under `#ifndef OPENSSL_NO_COMP_ALG`”* @127-143 | **proven** |

**No safe fn was found** in this set: each site is inside an `unsafe fn`, and
the `params` adoptions are additionally `pub(crate) unsafe fn`, so safe Rust
cannot call them. The defects are contract-text defects, not unsafe-signature
defects:

1. ~~The three `pkey_*_ctrl` functions delegate to an undocumented
   `PkeyMethCtrlFn`.~~ **Closed:** the alias now documents provenance, extent
   and transfer for the UKM/OAEP-label arms, and each of the three `# Safety`
   blocks states the arm-specific obligation. The per-arm `SAFETY:` comments
   (`ec/pmeth.rs:666-668`, `dh/pmeth.rs:384-386`, `rsa/pmeth.rs:1143-1146`)
   remain corroboration, not the contract.
2. ~~`ecx_set_params` and `finish_with_error` state liveness only;
   `asn1_write_micalg` and `load_err` omit the adopted argument entirely;
   `SCT_set0_*` and `OSSL_COMP_CERT_new` state ownership but not the seam.~~
   **Closed (contract-completion batch).** Each site's enclosing `# Safety` now
   names the seam function, the extent and its bound, the ownership transfer
   (including the non-adopting refusal path in `SCT_set0_log_id`) and the exact
   release; the public C entries state that the obligation is the caller's.

The `params` call graph was checked site by site. Every call expression is in
an unsafe function:

- `src/provider/kdf.rs:1548/1558/1568` in `unsafe fn sskdf_common_set_ctx_params(` @1495, reached from `unsafe extern "C" fn sskdf_set_ctx_params(` @1593 and `unsafe extern "C" fn x963kdf_set_ctx_params(` @1693;
- `src/provider/kdf.rs:5260/5270/5281` in `unsafe fn hkdf_common_set_ctx_params(` @5207, reached from `unsafe extern "C" fn hkdf_ctx_set_ctx_params(` @5368, `hkdf_fixed_digest_set_ctx_params(` @5565 and `tls13_set_ctx_params(` @5662;
- `src/provider/kdf.rs:5684/5693/5702` directly in `unsafe extern "C" fn tls13_set_ctx_params(` @5662;
- `src/provider/kdf.rs:7272/7281/7290/7300` directly in `unsafe extern "C" fn kbkdf_set_ctx_params(` @7195.

These remain trust-boundary obligations; the function-level `# Safety` text at
`params/mod.rs:2960-2963` and `3102-3106` states both provenance and extent.

**Not a proof.** This audit is a source-level, per-caller precondition review.
It does not prove the release-mode invariant, does not model-check `Drop`, and
has not been run under Miri, a differential court, or a whole-library ASan run
(a focused ASan run of the model tests is recorded in `OWNER-CHECKS.md`). The `num <=
extent` facts for provider-supplied lengths were established by reading the
concrete allocation and its length writer; they are not machine-checked. The
three corrected sites above are **ESTABLISHED** as source-level caller
obligations with witnesses; that is not a `SAFETY_DISCHARGED` claim. The §7
discharge conditions (machine-checked aliasing/model checking, independent
review, and every retained/unknown obligation enumerated) remain open.

## Per-caller table

Legend: P1 direct allocation; P2 same-function assignment/out-parameter; P3
struct member assigned from an allocation (line cited, possibly another file);
P4 caller C-ABI contract; P5 NULL/empty. E0 plain release (no read); E1
cleansing length vs allocation extent; E2 conditional arm fixed at
construction; R1 plain `CRYPTO_free`; R2 `CRYPTO_clear_free(num)`; R3
conditional; R4 `CRYPTO_secure_clear_free(num)`.

| id | site | enclosing fn | ctor | provenance witness | extent/length witness | release witness | verdict |
|---|---|---|---|---|---|---|---|
| OB1-0001 | `src/apps/kdf.rs:420` | `main` | `adopt_plain` | P1: `OPENSSL_hexstr2buf` @418 allocates the decoded block | E0 plain | R1 `CRYPTO_free` (apps/kdf.c,211) | **ESTABLISHED** |
| OB1-0002 | `src/asn1/a_digest.rs:174` | `ossl_asn1_item_digest_ex` | `adopt_plain` | P2: out-param `let i = unsafe { ASN1_item_i2d(asn.cast::<c_void>(), &mut str_, it) };` @166 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0003 | `src/asn1/a_dup.rs:191` | `ASN1_item_dup` | `adopt_plain` | P2: out-param `let n = unsafe { ASN1_item_i2d(x, &mut b, it) };` @180 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0004 | `src/asn1/a_sign.rs:545` | `ASN1_item_sign_ctx` | `adopt_cleansed` | P2: out-param `let buf_len = unsafe { ASN1_item_i2d(data, &mut buf_in_raw, it) };` @533 | E1: `num = inl` | R2 `CRYPTO_clear_free(inl)` | **ESTABLISHED** |
| OB1-0005 | `src/asn1/a_verify.rs:439` | `ASN1_item_verify_ctx` | `adopt_cleansed` | P2: out-param `let inl = unsafe { ASN1_item_i2d(data, &mut buf_in, it) };` @422 | E1: `num = inll` | R2 `CRYPTO_clear_free(inll)` | **ESTABLISHED** |
| OB1-0006 | `src/asn1/asn1_gen.rs:1016` | `asn1_multi` | `adopt_plain` | P2: out-param `i2d_ASN1_SET_ANY(sk, &mut der_slot)` @1009 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0007 | `src/asn1/asn1_gen.rs:1132` | `generate_v3` | `adopt_plain` | P2: out-param `let cpy_len_raw = unsafe { i2d_ASN1_TYPE(ret, &mut orig_der_slot) };` @1125 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0008 | `src/asn1/asn1_gen.rs:1359` | `scalars_generate_and_re_encode` | `adopt_plain` | P2: out-param `let n = i2d_ASN1_TYPE(v, &mut out);` @1354 | E0 plain | R1 plain `CRYPTO_free` | **TEST** |
| OB1-0009 | `src/asn1/asn_mime.rs:624` | `asn1_write_micalg` | `adopt_plain_nullable` | P4: legacy `EVP_MD_CTRL_MICALG` callback @616 returns a NUL-terminated plain-`CRYPTO_*` block (authority frees it at `asn_mime.c:189`) | E0 plain; extent = string + terminator | R1 `CRYPTO_free` (FILE,LINE_MICALG_FREE) | **ESTABLISHED** |
| OB1-0010 | `src/asn1/asn_mime.rs:1734` | `mime_hdr_new` | `adopt_plain_nullable` | P1: `CRYPTO_strdup(name)` @1727 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_HDR_NEW_FREE_NAME) | **ESTABLISHED** |
| OB1-0011 | `src/asn1/asn_mime.rs:1761` | `mime_hdr_new` | `adopt_plain_nullable` | P1: `CRYPTO_strdup(value)` @1753 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_HDR_NEW_FREE_VALUE) | **ESTABLISHED** |
| OB1-0012 | `src/asn1/asn_mime.rs:1821` | `mime_hdr_new` | `adopt_plain_nullable` | P1: argument is `tmpname.map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0013 | `src/asn1/asn_mime.rs:1827` | `mime_hdr_new` | `adopt_plain_nullable` | P1: argument is `tmpval.map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0014 | `src/asn1/asn_mime.rs:1833` | `mime_hdr_new` | `adopt_plain_nullable` | P1: argument is `mhdr_buf.map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0015 | `src/asn1/asn_mime.rs:1870` | `mime_hdr_addparam` | `adopt_plain_nullable` | P1: `CRYPTO_strdup(name)` @1863 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_ADDPARAM_FREE_NAME) | **ESTABLISHED** |
| OB1-0016 | `src/asn1/asn_mime.rs:1897` | `mime_hdr_addparam` | `adopt_plain_nullable` | P1: `CRYPTO_strdup(value)` @1887 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_ADDPARAM_FREE_VALUE) | **ESTABLISHED** |
| OB1-0017 | `src/asn1/asn_mime.rs:1948` | `mime_hdr_addparam` | `adopt_plain_nullable` | P1: argument is `tmpname.map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0018 | `src/asn1/asn_mime.rs:1954` | `mime_hdr_addparam` | `adopt_plain_nullable` | P1: argument is `tmpval.map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0019 | `src/asn1/asn_mime.rs:1960` | `mime_hdr_addparam` | `adopt_plain_nullable` | P1: argument is `mparam_buf .map_or(ptr::null_mut(), OwnedBuf::into_raw)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0020 | `src/asn1/asn_mime.rs:2064` | `mime_hdr_free` | `adopt_plain_nullable` | P2: `let mut hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };` @1086 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0021 | `src/asn1/asn_mime.rs:2070` | `mime_hdr_free` | `adopt_plain_nullable` | P2: `let mut hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };` @1086 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0022 | `src/asn1/asn_mime.rs:2079` | `mime_hdr_free` | `adopt_plain_nullable` | P2: `let mut hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };` @1086 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0023 | `src/asn1/asn_mime.rs:2096` | `mime_param_free` | `adopt_plain_nullable` | P2: out-param `let idx = unsafe { OPENSSL_sk_find((*hdr).params, (&raw const param).cast::<c_vo` @2047 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0024 | `src/asn1/asn_mime.rs:2102` | `mime_param_free` | `adopt_plain_nullable` | P2: out-param `let idx = unsafe { OPENSSL_sk_find((*hdr).params, (&raw const param).cast::<c_vo` @2047 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0025 | `src/asn1/asn_mime.rs:2108` | `mime_param_free` | `adopt_plain_nullable` | P3: `param` from `OwnedBuf::new_plain_released(size_of::<MimeParam>())` @1907 in `mime_hdr_addparam` | E0 plain | R1 `CRYPTO_free` (FILE,LINE_PARAM_FREE) | **ESTABLISHED** |
| OB1-0026 | `src/asn1/bio_asn1.rs:271` | `asn1_bio_free` | `adopt_plain_nullable` | P3: `ctx.buf` from `OwnedBuf::new` @192 `into_raw`; `p` = `ctx` from `OwnedBuf::new_zeroed` @209 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILTER_FILE,LINE) | **ESTABLISHED** |
| OB1-0027 | `src/asn1/bio_asn1.rs:277` | `asn1_bio_free` | `adopt_plain_nullable` | P3: `ctx.buf` from `OwnedBuf::new` @192 `into_raw`; `p` = `ctx` from `OwnedBuf::new_zeroed` @209 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILTER_FILE,LINE) | **ESTABLISHED** |
| OB1-0028 | `src/asn1/bio_asn1.rs:858` | `BIO_new_NDEF` | `adopt_plain_nullable` | P2: `let raw = ndef_buf.map_or(core::ptr::null_mut(), OwnedBuf::into_raw);` @855 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0029 | `src/asn1/bio_asn1.rs:1026` | `ndef_prefix_free` | `adopt_plain_nullable` | P3: `aux.derbuf` from `OwnedBuf::new(derlen)` @978 `into_raw` | E0 plain | R1 `CRYPTO_free` (NDEF_FILE,LINE) | **ESTABLISHED** |
| OB1-0030 | `src/asn1/bio_asn1.rs:1067` | `ndef_suffix_free` | `adopt_plain_nullable` | P3: `block` from `OwnedBuf::new_zeroed` @833 in `BIO_new_NDEF`, `into_raw` | E0 plain | R1 `CRYPTO_free` (NDEF_FILE,LINE) | **ESTABLISHED** |
| OB1-0031 | `src/async/async.rs:229` | `async_ctx_free` | `adopt_plain_nullable` | P3: `ctx` from `OwnedBuf::new` @156 `into_raw` in `async_ctx_new` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_CTX_FREE) | **ESTABLISHED** |
| OB1-0032 | `src/async/async.rs:276` | `async_job_free` | `adopt_plain_nullable` | P3: `funcargs` from `OwnedBuf::new(size)` @530 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_JOB_FREEARGS) | **ESTABLISHED** |
| OB1-0033 | `src/async/async.rs:283` | `async_job_free` | `adopt_plain_nullable` | P3: `job` from `OwnedBuf::new_zeroed(size_of::<AsyncJob>())` @246 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_JOB_FREE) | **ESTABLISHED** |
| OB1-0034 | `src/async/async.rs:355` | `async_release_job` | `adopt_plain_nullable` | P3: `funcargs` from `OwnedBuf::new(size)` @530 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_JOB_FREEARGS) | **ESTABLISHED** |
| OB1-0035 | `src/async/async.rs:743` | `async_delete_thread_state` | `adopt_plain_nullable` | P3: `pool` from `OwnedBuf::new_zeroed` @667 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_POOL_FREE) | **ESTABLISHED** |
| OB1-0036 | `src/cmp/cmp_hdr.rs:487` | `ossl_cmp_hdr_set_transactionID` | `adopt_plain` | P1: argument is `i2s_ASN1_OCTET_STRING(ptr::null_mut(), (*ctx).transaction_id)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0037 | `src/cmp/cmp_protect.rs:149` | `ossl_cmp_calc_protection` | `adopt_plain_nullable` | P2: `protection` is the `ASN1_item_i2d` block (same function) | E0 plain | R1 `CRYPTO_free` (FILE,98) | **ESTABLISHED** |
| OB1-0038 | `src/cmp/cmp_protect.rs:193` | `ossl_cmp_calc_protection` | `adopt_plain_nullable` | P2: `protection` is the `ASN1_item_i2d` block (same function) | E0 plain | R1 `CRYPTO_free` (FILE,98) | **ESTABLISHED** |
| OB1-0039 | `src/cmp/cmp_protect.rs:441` | `pbmac_algor` | `adopt_plain_nullable` | P2: out-param `let pbm_der_len = unsafe { i2d_OSSL_CRMF_PBMPARAMETER(pbm, &mut pbm_der) };` @436 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0040 | `src/cmp/cmp_vfy.rs:412` | `check_name` | `adopt_plain_nullable` | P2: `let str_ = unsafe { X509_NAME_oneline(actual_name, ptr::null_mut(), 0) };` @408 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0041 | `src/cmp/cmp_vfy.rs:458` | `check_name` | `adopt_plain_nullable` | P2: `let str2 = unsafe { X509_NAME_oneline(expect_name, ptr::null_mut(), 0) };` @455 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0042 | `src/cmp/cmp_vfy.rs:511` | `check_kid` | `adopt_plain_nullable` | P1: `i2s_ASN1_OCTET_STRING(ckid)` @506 | E0 plain | R1 `CRYPTO_free` (FILE,208) | **ESTABLISHED** |
| OB1-0043 | `src/cmp/cmp_vfy.rs:555` | `check_kid` | `adopt_plain_nullable` | P1: `i2s_ASN1_OCTET_STRING(skid)` @551 | E0 plain | R1 `CRYPTO_free` (FILE,217) | **ESTABLISHED** |
| OB1-0044 | `src/cmp/cmp_vfy.rs:644` | `cert_acceptable` | `adopt_plain_nullable` | P2: `let sname = unsafe { X509_NAME_oneline(X509_get_subject_name(cert), ptr::null_mut(), 0) };` @638 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0045 | `src/cmp/cmp_vfy.rs:670` | `cert_acceptable` | `adopt_plain_nullable` | P2: `let iname = unsafe { X509_NAME_oneline(X509_get_issuer_name(cert), ptr::null_mut(), 0) };` @664 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0046 | `src/cmp/cmp_vfy.rs:1183` | `check_msg_find_cert` | `adopt_plain_nullable` | P1: `X509_NAME_oneline` @1180 | E0 plain | R1 `CRYPTO_free` (FILE,534) | **ESTABLISHED** |
| OB1-0047 | `src/cmp/cmp_vfy.rs:1186` | `check_msg_find_cert` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0048 | `src/cmp/cmp_vfy.rs:1194` | `check_msg_find_cert` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0049 | `src/cmp/cmp_vfy.rs:1492` | `check_transactionID_or_nonce` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0050 | `src/cmp/cmp_vfy.rs:1496` | `check_transactionID_or_nonce` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0051 | `src/cmp/cmp_vfy.rs:1504` | `check_transactionID_or_nonce` | `adopt_plain_nullable` | P1: `i2s_ASN1_OCTET_STRING(actual)` @1501 | E0 plain | R1 `CRYPTO_free` (FILE,669) | **ESTABLISHED** |
| OB1-0052 | `src/cmp/cmp_vfy.rs:1569` | `ossl_cmp_msg_check_update` | `adopt_plain_nullable` | P1: `X509_NAME_oneline(dname)` @1564 | E0 plain | R1 `CRYPTO_free` (FILE,730) | **ESTABLISHED** |
| OB1-0053 | `src/cms/cms_dh.rs:301` | `dh_cms_set_shared_info` | `adopt_plain_nullable` | P1: argument is `CRYPTO_memdup( ASN1_STRING_get0_data(ukm), dukmlen as usize, c"cms_dh.` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0054 | `src/cms/cms_dh.rs:478` | `dh_cms_encrypt` | `adopt_plain_nullable` | P2: out-param `penclen = unsafe { ASN1_item_i2d(pubk.cast(), &mut penc_raw, ASN1_INTEGER_it()) ` @473 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0055 | `src/cms/cms_dh.rs:593` | `dh_cms_encrypt` | `adopt_plain_nullable` | P1: argument is `CRYPTO_memdup( ASN1_STRING_get0_data(ukm), dukmlen as usize, c"cms_dh.` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0056 | `src/cms/cms_dh.rs:628` | `dh_cms_encrypt` | `adopt_plain_nullable` | P2: out-param `penclen = unsafe { ASN1_item_i2d(pubk.cast(), &mut penc_raw, ASN1_INTEGER_it()) ` @473 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0057 | `src/cms/cms_ec.rs:450` | `ecdh_cms_set_shared_info` | `adopt_plain_nullable` | P1: `CMS_SharedInfo_encode(&mut der_raw,...)` @445 | E0 plain | R1 `CRYPTO_free` (cms_ec.c,222) | **ESTABLISHED** |
| OB1-0058 | `src/cms/cms_ec.rs:604` | `ecdh_cms_encrypt` | `adopt_plain_nullable` | P2: out-param `let enckeylen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey, &mut penc2_raw) ` @599 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0059 | `src/cms/cms_ec.rs:724` | `ecdh_cms_encrypt` | `adopt_plain_nullable` | P1: `CMS_SharedInfo_encode(&mut penc_raw,...)` @738 | E0 plain | R1 `CRYPTO_free` (cms_ec.c,383) | **ESTABLISHED** |
| OB1-0060 | `src/cms/cms_ec.rs:749` | `ecdh_cms_encrypt` | `adopt_plain_nullable` | P2: out-param `penclen = unsafe { i2d_X509_ALGOR(wrap_alg, &mut penc_raw) };` @744 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0061 | `src/cms/cms_env.rs:1163` | `adopt_decrypted_key` | `adopt_cleansed_nullable` | P4: wrapper contract; prod caller @1326 passes `evp_pkey_decrypt_alloc` block | E1: `num` = produced length <= first-call capacity | R2 `CRYPTO_clear_free` (cms_asn1.c,88) | **ESTABLISHED** |
| OB1-0062 | `src/cms/cms_env.rs:2404` | `cms_AuthEnvelopedData_set_aad` | `adopt_plain_nullable` | P2: out-param `aadlen = unsafe { crate::asn1::i2d::ASN1_item_i2d(auth_attrs.cast(), &mut aad, i` @2400 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0063 | `src/cms/cms_ess.rs:380` | `CMS_add1_ReceiptRequest` | `adopt_plain_nullable` | P2: out-param `let rrderlen = unsafe { i2d_CMS_ReceiptRequest(rr, &mut rrder) };` @375 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0064 | `src/cms/cms_kari.rs:592` | `CMS_RecipientInfo_kari_decrypt` | `adopt_plain_nullable` | P1: `cek` from `cms_kek_cipher` @568 (CRYPTO_malloc) | E0 plain | R1 `CRYPTO_free` (cms_kari.c,281) | **ESTABLISHED** |
| OB1-0065 | `src/cms/cms_kari.rs:599` | `CMS_RecipientInfo_kari_decrypt` | `adopt_plain_nullable` | P1: `cek` from `cms_kek_cipher` @568 (CRYPTO_malloc) | E0 plain | R1 `CRYPTO_free` (cms_kari.c,281) | **ESTABLISHED** |
| OB1-0066 | `src/cms/cms_kemri.rs:463` | `kdf_derive` | `adopt_plain_nullable` | P1: `infoder` from `CMS_CMSORIforKEMOtherInfo_encode` @452 | E0 plain | R1 `CRYPTO_free` (cms_kemri.c,243) | **ESTABLISHED** |
| OB1-0067 | `src/cms/cms_rsa.rs:354` | `rsa_cms_decrypt` | `adopt_plain_nullable` | P1: `dup_label_raw` direct `CRYPTO_memdup` @350 | E0 plain | R1 `CRYPTO_free` (cms_rsa.c,109) | **ESTABLISHED** |
| OB1-0068 | `src/cms/cms_sd.rs:1558` | `CMS_SignerInfo_sign` | `adopt_plain_nullable` | P2: `abuf_raw` is the `ASN1_item_i2d` block @1546 | E0 plain | R1 `CRYPTO_free` (cms_sd.c,920) | **ESTABLISHED** |
| OB1-0069 | `src/cms/cms_sd.rs:1756` | `CMS_SignerInfo_verify` | `adopt_plain_nullable` | P2: `abuf_raw` is the `ASN1_item_i2d` block (same function) | E0 plain | R1 `CRYPTO_free` (cms_sd.c,996) | **ESTABLISHED** |
| OB1-0070 | `src/cms/cms_sd.rs:2085` | `CMS_add_smimecap` | `adopt_plain_nullable` | P2: out-param `let smderlen = unsafe { crate::asn1::x_algor::i2d_X509_ALGORS(algs, &mut smder_r` @2077 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0071 | `src/crmf/crmf_lib.rs:1608` | `OSSL_CRMF_ENCRYPTEDKEY_get1_pkey` | `adopt_plain` | P1: argument is `OSSL_CRMF_ENCRYPTEDVALUE_decrypt( (*encrypted_key).value.encrypted_val` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0072 | `src/crmf/crmf_lib.rs:1924` | `OSSL_CRMF_ENCRYPTEDVALUE_decrypt` | `adopt_conditional` | P1: argument is `CRYPTO_malloc(eksize, FILE.as_ptr(), 802)` | E2: `num = eksize`, `clear = false` fixed at construction | R3 `plain` arm, num `eksize` | **ESTABLISHED** |
| OB1-0073 | `src/crmf/crmf_lib.rs:2097` | `OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert` | `adopt_plain` | P1: argument is `OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ecert, libctx, propq, pkey, &mut len)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0074 | `src/ct/ct_b64.rs:193` | `SCT_new_from_base64` | `adopt_plain_nullable` | P1: `ct_base64_decode(logid_base64,&mut dec)` @184 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0075 | `src/ct/ct_b64.rs:217` | `SCT_new_from_base64` | `adopt_plain_nullable` | P2: `let dec = unsafe { OwnedBuf::adopt_plain_nullable(dec, SeamFile::NULL, 0) };` @193 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0076 | `src/ct/ct_b64.rs:235` | `SCT_new_from_base64` | `adopt_plain_nullable` | P2: `let dec = unsafe { OwnedBuf::adopt_plain_nullable(dec, SeamFile::NULL, 0) };` @193 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0077 | `src/ct/ct_b64.rs:293` | `CTLOG_new_from_base64_ex` | `adopt_plain_nullable` | P3: `pkey_der` from `ct_base64_decode` @111 `OwnedBuf::new` `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0078 | `src/ct/ct_log.rs:252` | `ct_v1_log_id_from_pkey` | `adopt_plain_nullable` | P2: out-param `let pkey_der_len = unsafe { i2d_PUBKEY(pkey, &mut pkey_der) };` @249 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0079 | `src/ct/ct_oct.rs:502` | `i2o_SCT` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0080 | `src/ct/ct_oct.rs:509` | `i2o_SCT` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0081 | `src/ct/ct_oct.rs:850` | `i2d_SCT_LIST` | `adopt_plain_nullable` | P2: `i2o_SCT_LIST(...,&mut (*octp).data)` @836 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0082 | `src/ct/ct_sct.rs:336` | `SCT_set0_log_id` | `adopt_plain_nullable` | P4: public C entry; caller's plain-`CRYPTO_*` block (`CRYPTO_malloc`/`CRYPTO_memdup`/`CRYPTO_strdup`), V1 length refusal does not adopt | E0 plain; extent >= `log_id_len` | R1 `CRYPTO_free` (NULL,0; authority `ct_sct.c:85`) | **ESTABLISHED** |
| OB1-0083 | `src/ct/ct_sct.rs:356` | `SCT_set1_log_id` | `adopt_plain_nullable` | P3: old `log_id` from `CRYPTO_memdup` @368 or a prior set0 transfer | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0084 | `src/ct/ct_sct.rs:463` | `SCT_set0_extensions` | `adopt_plain_nullable` | P4: public C entry; caller's plain-`CRYPTO_*` block; ownership transfers unconditionally | E0 plain; extent >= `ext_len` | R1 `CRYPTO_free` (NULL,0; authority `ct_sct.c:140`) | **ESTABLISHED** |
| OB1-0085 | `src/ct/ct_sct.rs:466` | `SCT_set1_extensions` | `adopt_plain_nullable` | P3: old `ext` from `CRYPTO_memdup` @478 or a prior set0 transfer | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0086 | `src/ct/ct_sct.rs:536` | `SCT_set0_signature` | `adopt_plain_nullable` | P4: public C entry; caller's plain-`CRYPTO_*` block; ownership transfers unconditionally | E0 plain; extent >= `sig_len` | R1 `CRYPTO_free` (NULL,0; authority `ct_sct.c:164`) | **ESTABLISHED** |
| OB1-0087 | `src/ct/ct_sct.rs:529` | `SCT_set1_signature` | `adopt_plain_nullable` | P3: old `sig` from `CRYPTO_memdup` @541 or a prior set0 transfer | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0088 | `src/ct/ct_sct_ctx.rs:291` | `SCT_CTX_set1_cert` | `adopt_plain_nullable` | P2: `i2d_X509(cert,&mut der)` @287 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0089 | `src/ct/ct_sct_ctx.rs:327` | `SCT_CTX_set1_cert` | `adopt_plain_nullable` | P2: `i2d_re_X509_tbs(pretmp,&mut der)` @323 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0090 | `src/ct/ct_sct_ctx.rs:343` | `SCT_CTX_set1_cert` | `adopt_plain_nullable` | P2: `der` is the `i2d_X509`/`i2d_re_X509_tbs` block @291/327 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0091 | `src/ct/ct_sct_ctx.rs:354` | `SCT_CTX_set1_cert` | `adopt_plain_nullable` | P2: `der` is the `i2d_X509`/`i2d_re_X509_tbs` block @291/327 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0092 | `src/ct/ct_sct_ctx.rs:433` | `ct_public_key_hash` | `adopt_plain_nullable` | P1: `i2d_X509_PUBKEY` @430 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0093 | `src/decoder_pkey.rs:221` | `decoder_cache_entry_free_fields` | `adopt_plain_nullable` | P3: fields `CRYPTO_strdup` @1594/1617/1640/1663 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0094 | `src/decoder_pkey.rs:227` | `decoder_cache_entry_free_fields` | `adopt_plain_nullable` | P3: fields `CRYPTO_strdup` @1594/1617/1640/1663 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0095 | `src/decoder_pkey.rs:233` | `decoder_cache_entry_free_fields` | `adopt_plain_nullable` | P3: fields `CRYPTO_strdup` @1594/1617/1640/1663 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0096 | `src/decoder_pkey.rs:239` | `decoder_cache_entry_free_fields` | `adopt_plain_nullable` | P3: fields `CRYPTO_strdup` @1594/1617/1640/1663 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0097 | `src/decoder_pkey.rs:266` | `decoder_cache_entry_free` | `adopt_plain_nullable` | P3: `entry` from `OwnedBuf::new_zeroed` @1580 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0098 | `src/decoder_pkey.rs:446` | `ossl_decoder_cache_free` | `adopt_plain_nullable` | P3: `cache` from `OwnedBuf::new` @397 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0099 | `src/decoder_pkey.rs:629` | `decoder_construct_pkey` | `adopt_plain_nullable` | P2: `object_type` from `OSSL_PARAM_get_utf8_string` @621; stored @636 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0100 | `src/decoder_pkey.rs:631` | `decoder_construct_pkey` | `adopt_plain_nullable` | P2: `object_type` from `OSSL_PARAM_get_utf8_string` @621; stored @636 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0101 | `src/decoder_pkey.rs:786` | `decoder_pkey_data_free_fields` | `adopt_plain_nullable` | P3: `propq` `CRYPTO_strdup` @1379; `object_type` @621 `into_raw` @636 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0102 | `src/decoder_pkey.rs:792` | `decoder_pkey_data_free_fields` | `adopt_plain_nullable` | P3: `propq` `CRYPTO_strdup` @1379; `object_type` @621 `into_raw` @636 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0103 | `src/decoder_pkey.rs:818` | `decoder_clean_pkey_construct_arg` | `adopt_plain_nullable` | P3: `construct_data` from `OwnedBuf::new_zeroed` @1107 `into_raw` | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0104 | `src/decoder_pkey.rs:1120` | `ossl_decoder_ctx_setup_for_pkey` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(propquery, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0105 | `src/decoder_pkey.rs:1378` | `ossl_decoder_ctx_for_pkey_dup` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup((*process_data_src).propq, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0106 | `src/decoder_pkey.rs:1593` | `OSSL_DECODER_CTX_new_for_pkey` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(input_type, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0107 | `src/decoder_pkey.rs:1616` | `OSSL_DECODER_CTX_new_for_pkey` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(input_structure, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0108 | `src/decoder_pkey.rs:1639` | `OSSL_DECODER_CTX_new_for_pkey` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(keytype, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0109 | `src/decoder_pkey.rs:1662` | `OSSL_DECODER_CTX_new_for_pkey` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(propquery, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0110 | `src/dh/ameth.rs:268` | `dh_pub_encode` | `adopt_plain` | P5: `penc` is still NULL (initialised @256; `i2d` is later @302) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0111 | `src/dh/ameth.rs:282` | `dh_pub_encode` | `adopt_plain` | P5: `penc` is still NULL (initialised @256; `i2d` is later @302) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0112 | `src/dh/ameth.rs:295` | `dh_pub_encode` | `adopt_plain` | P5: `penc` is still NULL (initialised @256; `i2d` is later @302) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0113 | `src/dh/ameth.rs:313` | `dh_pub_encode` | `adopt_plain` | P2: out-param `let penclen = unsafe { ASN1_item_i2d(pub_key.cast(), &mut penc, ASN1_INTEGER_it(` @302 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0114 | `src/dh/ameth.rs:337` | `dh_pub_encode` | `adopt_plain` | P2: out-param `let penclen = unsafe { ASN1_item_i2d(pub_key.cast(), &mut penc, ASN1_INTEGER_it(` @302 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0115 | `src/dh/ameth.rs:450` | `dh_priv_encode` | `adopt_cleansed` | P2: out-param `let dplen = unsafe { ASN1_item_i2d(prkey.cast(), &mut dp, ASN1_INTEGER_it()) };` @421 | E1: `num = dplen as usize` | R2 `CRYPTO_clear_free(dplen as usize)` | **ESTABLISHED** |
| OB1-0116 | `src/dh/pmeth.rs:388` | `pkey_dh_ctrl` | `adopt_plain` | P4: caller-owned `p2` for `EVP_PKEY_CTRL_DH_KDF_UKM` (set0 ABI); copied path `CRYPTO_memdup` @250 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_KDF_UKM_CTRL) | **ESTABLISHED** |
| OB1-0117 | `src/dsa/ameth.rs:247` | `dsa_pub_encode` | `adopt_plain` | P2: out-param `let penclen = unsafe { ASN1_item_i2d(pubint.cast(), &mut penc_raw, ASN1_INTEGER_` @242 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0118 | `src/dsa/ameth.rs:370` | `dsa_priv_encode` | `adopt_cleansed` | P2: out-param `let dplen = unsafe { ASN1_item_i2d(prkey.cast(), &mut dp_raw, ASN1_INTEGER_it())` @363 | E1: `num = dplen.max(0) as usize` | R2 `CRYPTO_clear_free(dplen.max(0) as usize)` | **ESTABLISHED** |
| OB1-0119 | `src/dsa/sign.rs:592` | `DSA_verify` | `adopt_cleansed` | P2: out-param `derlen = i2d_DSA_SIG(s.as_ptr(), &mut der);` @576 | E1: `num = derlen.max(0) as usize` | R2 `CRYPTO_clear_free(derlen.max(0) as usize)` | **ESTABLISHED** |
| OB1-0120 | `src/ec/ameth.rs:388` | `eckey_priv_encode` | `adopt_cleansed_nullable` | P2: out-param `let eplen = unsafe { i2d_ECPrivateKey(&raw const ec_key, &mut ep) };` @370 | E1: `num = eplen as usize` | R2 `CRYPTO_clear_free(eplen as usize)` | **ESTABLISHED** |
| OB1-0121 | `src/ec/ameth.rs:580` | `do_ec_key_print` | `adopt_plain_nullable` | P2: out-param `publen = EC_KEY_key2buf(x, EC_KEY_get_conv_form(x), &mut pub_buf, ptr::null_mut(` @577 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0122 | `src/ec/ameth.rs:592` | `do_ec_key_print` | `adopt_cleansed_nullable` | P2: out-param `privlen = EC_KEY_priv2buf(x, &mut priv_buf);` @589 | E1: `num = privlen` | R2 `CRYPTO_clear_free(privlen)` | **ESTABLISHED** |
| OB1-0123 | `src/ec/ameth.rs:969` | `ec_pkey_export_to` | `adopt_plain_nullable` | P1: `gen_buf`/`pub_key_buf` from `ossl_ec_group_todata`/`EC_POINT_point2buf` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,601/602) | **ESTABLISHED** |
| OB1-0124 | `src/ec/ameth.rs:1002` | `ec_pkey_export_to` | `adopt_plain_nullable` | P1: `gen_buf`/`pub_key_buf` from `ossl_ec_group_todata`/`EC_POINT_point2buf` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,601/602) | **ESTABLISHED** |
| OB1-0125 | `src/ec/asn1.rs:1573` | `EC_GROUP_get_ecparameters` | `adopt_plain` | P2: out-param `len = EC_POINT_point2buf(group, point, form, &mut buffer, ptr::null_mut());` @1566 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0126 | `src/ec/asn1.rs:1855` | `EC_GROUP_new_from_ecparameters` | `adopt_plain` | P2: `(*ret).seed = CRYPTO_malloc((*(*(*params).curve).seed).length as usize, FILE, 688)` @1860 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0127 | `src/ec/asn1.rs:2344` | `i2d_ECPrivateKey` | `adopt_cleansed` | P2: out-param `privlen = EC_KEY_priv2buf(a, &mut priv_);` @2293 | E1: `num = privlen` | R2 `CRYPTO_clear_free(privlen)` | **ESTABLISHED** |
| OB1-0128 | `src/ec/asn1.rs:2346` | `i2d_ECPrivateKey` | `adopt_plain` | P2: out-param `publen = EC_KEY_key2buf(a, (*a).conv_form, &mut pub_, ptr::null_mut());` @2320 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0129 | `src/ec/asn1.rs:2437` | `i2o_ECPublicKey` | `adopt_plain` | P2: `*out = buf;` @2421 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0130 | `src/ec/depr.rs:94` | `EC_POINT_point2bn` | `adopt_plain` | P2: out-param `let buf_len = EC_POINT_point2buf(group, point, form, &mut buf, ctx);` @83 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0131 | `src/ec/ecx_meth.rs:168` | `ecx_pub_encode` | `adopt_cleansed` | P2: `let penc = unsafe { CRYPTO_memdup((*ecxkey).pubkey.as_ptr().cast(), keylen(pkey), FILE, 42` @146 | E1: `num = keylen(pkey)` | R2 `CRYPTO_clear_free(keylen(pkey))` | **ESTABLISHED** |
| OB1-0132 | `src/ec/ecx_meth.rs:319` | `ecx_priv_encode` | `adopt_cleansed` | P1: `i2d_ASN1_OCTET_STRING` @296 | E1: `num = penclen` | R2 `CRYPTO_clear_free(penclen)` (FILE_SEAM,121) | **ESTABLISHED** |
| OB1-0133 | `src/ec/key.rs:283` | `EC_KEY_free` | `adopt_plain` | P3: `propq` set by `CRYPTO_strdup` at ec/kmeth.rs:374 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,101) | **ESTABLISHED** |
| OB1-0134 | `src/ec/pmeth.rs:670` | `pkey_ec_ctrl` | `adopt_plain` | P4: caller-owned `p2` for `EVP_PKEY_CTRL_EC_KDF_UKM` (set0 ABI); copied path `CRYPTO_memdup` @252 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_KDF_UKM_CTRL) | **ESTABLISHED** |
| OB1-0135 | `src/ec/print.rs:137` | `EC_POINT_point2hex` | `adopt_plain_nullable` | P2: `EC_POINT_point2buf(...,&mut buf)` @127 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,39) | **ESTABLISHED** |
| OB1-0136 | `src/ec/smpl.rs:1861` | `ossl_ec_GFp_simple_points_make_affine` | `adopt_plain_nullable` | P2: `prod_z = CRYPTO_malloc_array(` @1854 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0137 | `src/evp/digest.rs:1751` | `cleanup_old_md_data` | `adopt_conditional` | P3: `md_data` from `CRYPTO_zalloc(ctx_size)` @2287 or `CRYPTO_malloc(ctx_size)` @3153 | E1: `num`=`digest.ctx_size`, the allocation length | R3 conditional, clear=true (LINE_CLEAR_MD_DATA) | **ESTABLISHED** |
| OB1-0138 | `src/evp/digest.rs:2289` | `evp_md_init_legacy` | `adopt_conditional` | P1: argument is `CRYPTO_zalloc(ctx_size as usize, FILE, LINE_ZALLOC_MD_DATA)` | E2: `num = ctx_size as usize`, `clear = true` fixed at construction | R3 `clear` arm, num `ctx_size as usize` | **ESTABLISHED** |
| OB1-0139 | `src/evp/digest.rs:3162` | `evp_md_ctx_copy_legacy` | `adopt_conditional` | P1: argument is `CRYPTO_malloc(ctx_size as usize, FILE, LINE_COPY_MD_DATA)` | E2: `num = ctx_size as usize`, `clear = false` fixed at construction | R3 `plain` arm, num `ctx_size as usize` | **ESTABLISHED** |
| OB1-0140 | `src/evp/e_aes.rs:726` | `aes_gcm_cleanup` | `adopt_plain` | P3: field equals inline `(*c).iv` unless `SET_IVLEN` allocated it @783/934 (guard @725) | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0141 | `src/evp/e_aes.rs:778` | `aes_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @783/934; guard excludes inline buffer @777 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0142 | `src/evp/e_aes.rs:783` | `aes_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @783/934; guard excludes inline buffer @777 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0143 | `src/evp/e_aes.rs:934` | `aes_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @783/934; guard excludes inline buffer @777 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0144 | `src/evp/e_aria.rs:713` | `aria_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @718/884; guard excludes inline buffer @712 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0145 | `src/evp/e_aria.rs:718` | `aria_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @718/884; guard excludes inline buffer @712 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0146 | `src/evp/e_aria.rs:884` | `aria_gcm_ctrl` | `adopt_plain` | P3: old heap `iv` allocated @718/884; guard excludes inline buffer @712 | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0147 | `src/evp/e_aria.rs:919` | `aria_gcm_cleanup` | `adopt_plain` | P3: field equals inline `(*c).iv` unless `SET_IVLEN` allocated it @718/884 (guard @918) | E0 plain | R1 `CRYPTO_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0148 | `src/evp/evp_pkey.rs:222` | `ossl_evp_pkey2pkcs8` | `adopt_cleansed` | P2: out-param `\|\| unsafe { OSSL_ENCODER_to_data(ctx, &mut der, &mut derlen) } == 0` @208 | E1: `num = derlen` | R2 `CRYPTO_clear_free(derlen)` | **ESTABLISHED** |
| OB1-0149 | `src/evp/evp_pkey.rs:340` | `ossl_evp_pkcs82pkey_ex` | `adopt_cleansed` | P2: out-param `let encoded_len = unsafe { i2d_PKCS8_PRIV_KEY_INFO(p8, &mut encoded_data) };` @331 | E1: `num = encoded_len as usize` | R2 `CRYPTO_clear_free(encoded_len as usize)` | **ESTABLISHED** |
| OB1-0150 | `src/evp/kdf.rs:1317` | `EVP_KDF_derive_SKEY` | `adopt_cleansed` | P2: `raw` = `key.into_raw()` @1313 from `new_zeroed_cleansed_at` @1294 | E1: `num = keylen` = the allocation length | R2 `CRYPTO_clear_free(keylen)` (FILE_SEAM,LINE_FREE_DERIVE_SKEY_ON_FAIL); F3 fixed by §17 cleansing divergence | **ESTABLISHED** |
| OB1-0151 | `src/evp/pkey.rs:1189` | `EVP_PKEY_get_bn_param` | `adopt_conditional` | P1: argument is `CRYPTO_zalloc(buf_sz, FILE, LINE_ZALLOC_BN_BUFFER)` | E2: `num = buf_sz`, `clear = false` fixed at construction | R3 `plain` arm, num `buf_sz` | **ESTABLISHED** |
| OB1-0152 | `src/evp/pkey_ctx.rs:9896` | `evp_pkey_ctx_add1_octet_string` | `adopt_conditional` | P1: argument is `CRYPTO_zalloc(info_alloc, FILE, LINE_ZALLOC_XLAT_BN_BUF)` | E2: `num = info_alloc`, `clear = true` fixed at construction | R3 `clear` arm, num `info_alloc` | **ESTABLISHED** |
| OB1-0153 | `src/evp/pkey_ctx.rs:10925` | `EVP_PKEY_CTX_hex2ctrl` | `adopt_conditional` | P2: `let bin = unsafe { OPENSSL_hexstr2buf(hex, ptr::addr_of_mut!(binlen)) };` @10918 | E2: `num = 0`, `clear = false` fixed at construction | R3 `plain` arm, num `0` | **ESTABLISHED** |
| OB1-0154 | `src/evp/pkey_ctx.rs:11192` | `EVP_PKEY_CTX_set_algor_params` | `adopt_conditional` | P2: out-param `let derl = unsafe { i2d_ASN1_TYPE((*alg).parameter, &mut der) };` @11170 | E2: `num = 0`, `clear = false` fixed at construction | R3 `plain` arm, num `0` | **ESTABLISHED** |
| OB1-0155 | `src/evp/pkey_ctx.rs:11257` | `EVP_PKEY_CTX_get_algor_params` | `adopt_conditional` | P1: argument is `CRYPTO_malloc(derl, FILE_EVP_LIB, LINE_MALLOC_ALGOR_GET)` | E2: `num = 0`, `clear = false` fixed at construction | R3 `plain` arm, num `0` | **ESTABLISHED** |
| OB1-0156 | `src/ffc/params.rs:105` | `memdup` | `adopt_plain` | P2: `let raw = unsafe { CRYPTO_memdup(src.cast::<c_void>(), len, FILE_FFC_PARAMS, LINE) }` @101 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0157 | `src/ffc/params.rs:161` | `ossl_ffc_params_cleanup` | `adopt_plain` | P3: `seed` is the object's `CRYPTO_memdup` block | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0158 | `src/ffc/params.rs:291` | `ossl_ffc_params_set_seed` | `adopt_plain` | P3: old `seed` is the object's `CRYPTO_memdup` block | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0159 | `src/ffc/params.rs:567` | `ossl_ffc_params_copy` | `adopt_plain` | P3: `dst.seed` is the object's `CRYPTO_memdup` block | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0160 | `src/hpke/mod.rs:764` | `hpke_labeled_extract` | `adopt_plain` | P1: argument is `CRYPTO_malloc(labeled_ikmlen, FILE_HPKE_UTIL, 316)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0161 | `src/hpke/mod.rs:863` | `hpke_labeled_expand` | `adopt_plain` | P1: argument is `CRYPTO_malloc(labeled_infolen, FILE_HPKE_UTIL, 366)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0162 | `src/hpke/mod.rs:2796` | `OSSL_HPKE_CTX_set1_authpub` | `adopt_plain` | P1: argument is `CRYPTO_malloc(OSSL_HPKE_MAXSIZE, FILE_HPKE, 1018)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0163 | `src/http/http_client.rs:875` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0164 | `src/http/http_client.rs:880` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0165 | `src/http/http_client.rs:885` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0166 | `src/http/http_client.rs:890` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0167 | `src/http/http_client.rs:895` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0168 | `src/http/http_client.rs:900` | `OSSL_HTTP_REQ_CTX_free` | `adopt_plain` | P3: `buf` @835/842 `OwnedBuf::new` `into_raw`; `proxy`/`server`/`port` `CRYPTO_strdup`; `expected_ct` @1125/1130; `rctx` @820 `new_zeroed` `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,148-153) | **ESTABLISHED** |
| OB1-0169 | `src/http/http_client.rs:1116` | `OSSL_HTTP_REQ_CTX_set_expected` | `adopt_plain` | P3: `expected_ct` set only by `CRYPTO_strdup` @1125/1130 or NULL @1121 | E0 plain | R1 `CRYPTO_free` (FILE,152) | **ESTABLISHED** |
| OB1-0170 | `src/http/http_client.rs:1125` | `OSSL_HTTP_REQ_CTX_set_expected` | `adopt_plain` | P3: `expected_ct` set only by `CRYPTO_strdup` @1125/1130 or NULL @1121 | E0 plain | R1 `CRYPTO_free` (FILE,152) | **ESTABLISHED** |
| OB1-0171 | `src/http/http_client.rs:1353` | `http_req_ctx_new` | `adopt_plain` | P1: argument is `CRYPTO_strdup(proxy, FILE.as_ptr(), 428)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0172 | `src/http/http_client.rs:1369` | `http_req_ctx_new` | `adopt_plain` | P1: argument is `CRYPTO_strdup(server, FILE.as_ptr(), 431)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0173 | `src/http/http_client.rs:1385` | `http_req_ctx_new` | `adopt_plain` | P1: argument is `CRYPTO_strdup(port, FILE.as_ptr(), 434)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0174 | `src/http/http_client.rs:2143` | `explict_or_default_port` | `adopt_plain` | P2: out-param `if BIO_parse_hostserv(hostserv, ptr::null_mut(), &mut service, BIO_PARSE_PRIO_HO` @2131 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0175 | `src/http/http_client.rs:2320` | `OSSL_HTTP_open` | `adopt_plain` | P1: `proxy_host`/`proxy_port` from `OSSL_HTTP_parse_url` @2307 | E0 plain | R1 `CRYPTO_free` (FILE,1131/1132) | **ESTABLISHED** |
| OB1-0176 | `src/http/http_client.rs:2325` | `OSSL_HTTP_open` | `adopt_plain` | P1: `proxy_host`/`proxy_port` from `OSSL_HTTP_parse_url` @2307 | E0 plain | R1 `CRYPTO_free` (FILE,1131/1132) | **ESTABLISHED** |
| OB1-0177 | `src/http/http_client.rs:2472` | `OSSL_HTTP_exchange` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*rctx).redirection_url, FILE.as_ptr(), 1229)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0178 | `src/http/http_client.rs:2612` | `OSSL_HTTP_get` | `adopt_plain` | P1: argument is `CRYPTO_strdup(url, FILE.as_ptr(), 1303)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0179 | `src/http/http_client.rs:2676` | `OSSL_HTTP_get` | `adopt_plain` | P2: `OSSL_HTTP_parse_url(...,&mut path,...)` @2631 | E0 plain | R1 `CRYPTO_free` (FILE,1332) | **ESTABLISHED** |
| OB1-0180 | `src/http/http_client.rs:2687` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut current_url = current_url_blk` @2617 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0181 | `src/http/http_client.rs:2695` | `OSSL_HTTP_get` | `adopt_plain` | P1: argument is `CRYPTO_strdup(redirection_url, FILE.as_ptr(), 1340)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0182 | `src/http/http_client.rs:2705` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut host = server;` @2169 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0183 | `src/http/http_client.rs:2710` | `OSSL_HTTP_get` | `adopt_plain` | P2: `(*rctx).port = dup` @1390 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0184 | `src/http/http_client.rs:2717` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut current_url = current_url_blk` @2617 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0185 | `src/http/http_client.rs:2726` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut host = server;` @2169 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0186 | `src/http/http_client.rs:2731` | `OSSL_HTTP_get` | `adopt_plain` | P2: `(*rctx).port = dup` @1390 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0187 | `src/http/http_client.rs:2740` | `OSSL_HTTP_get` | `adopt_plain` | P2: `ctx.redirection_url = value;` @1871 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0188 | `src/http/http_client.rs:2746` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut host = server;` @2169 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0189 | `src/http/http_client.rs:2751` | `OSSL_HTTP_get` | `adopt_plain` | P2: `(*rctx).port = dup` @1390 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0190 | `src/http/http_client.rs:2763` | `OSSL_HTTP_get` | `adopt_plain` | P2: `let mut current_url = current_url_blk` @2617 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0191 | `src/http/http_client.rs:3020` | `OSSL_HTTP_proxy_connect` | `new_cleansed_num` | P1: `new_cleansed_num(alloc_len, len)` with `alloc_len = len+1` @3013 | E1: `num = len <= alloc_len` by construction | R2 `CRYPTO_clear_free(len)` (FILE,1508) | **ESTABLISHED** |
| OB1-0192 | `src/http/http_client.rs:3047` | `OSSL_HTTP_proxy_connect` | `adopt_cleansed` | P1: `proxyauthenc` from `base64encode` @3042; `base64encode` allocates `outl+1` | E1: `num = str_len(proxyauthenc) <= outl+1` | R2 `CRYPTO_clear_free(str_len)` (FILE,1518) | **ESTABLISHED** |
| OB1-0193 | `src/params/mod.rs:2987` | `ossl_param_get1_octet_string_from_param` | `adopt_cleansed` | P4: `# Safety` requires `*out` NULL or a block of `*out_len` bytes from this allocator | E1: caller's `*out_len` | R2 `CRYPTO_clear_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0194 | `src/params/mod.rs:3132` | `ossl_param_get1_concat_octet_string` | `adopt_cleansed` | P4: same `# Safety` contract | E1: caller's `*out_len` | R2 `CRYPTO_clear_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0195 | `src/params/mod.rs:3159` | `ossl_param_get1_concat_octet_string` | `adopt_cleansed` | P4: same `# Safety` contract | E1: caller's `*out_len` (set by prior success) | R2 `CRYPTO_clear_free` (FILE,LINE) | **ESTABLISHED** |
| OB1-0196 | `src/pkcs12/p12_decr.rs:344` | `PKCS12_item_decrypt_d2i_ex` | `adopt_plain_nullable` | P1: `crypted` from `PKCS12_pbe_crypt_ex` @326 | E0 plain | R1 `CRYPTO_free` (FILE,171) | **ESTABLISHED** |
| OB1-0197 | `src/pkcs12/p12_decr.rs:433` | `PKCS12_item_i2d_encrypt_ex` | `adopt_plain_nullable` | P2: out-param `let inlen = unsafe { ASN1_item_i2d(obj, &raw mut in_raw, it) };` @422 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0198 | `src/pkcs12/p12_key.rs:129` | `PKCS12_key_gen_asc_ex` | `adopt_cleansed` | P2: out-param `unsafe { OPENSSL_asc2uni(pass, passlen, &raw mut unipass, &raw mut uniplen) };` @119 | E1: `num = uniplen.max(0) as usize` | R2 `CRYPTO_clear_free(uniplen.max(0) as usize)` | **ESTABLISHED** |
| OB1-0199 | `src/pkcs12/p12_key.rs:228` | `PKCS12_key_gen_utf8_ex` | `adopt_cleansed` | P1: `OPENSSL_utf82uni` @217 | E1: `uniplen` = returned `ulen` | R2 `CRYPTO_clear_free(uniplen)` (FILE,67) | **ESTABLISHED** |
| OB1-0200 | `src/pkcs12/p12_key.rs:510` | `unipass_drop_cleanses_before_release` | `adopt_cleansed` | P2: `let p = CRYPTO_malloc(LEN, FILE.as_ptr(), 37).cast::<c_uchar>();` @499 | E1: `num = LEN` | R2 `CRYPTO_clear_free(LEN)` | **TEST** |
| OB1-0201 | `src/pkcs7/pk7_doit.rs:483` | `pkcs7_decrypt_rinfo` | `adopt_cleansed_nullable` | P1: `evp_pkey_decrypt_alloc` @457 | E1: `num = eklen` = produced length | R2 `CRYPTO_clear_free(eklen)` (NULL,0) | **ESTABLISHED** |
| OB1-0202 | `src/pkcs7/pk7_doit.rs:1669` | `PKCS7_SIGNER_INFO_sign` | `adopt_plain_nullable` | P2: out-param `let alen = unsafe { ASN1_item_i2d((*si).auth_attr.cast(), &mut abuf, PKCS7_ATTR_` @1665 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0203 | `src/pkcs7/pk7_doit.rs:1936` | `PKCS7_signatureVerify` | `adopt_plain_nullable` | P2: `ASN1_item_i2d` @1932 | E0 plain | R1 `CRYPTO_free` (FILE,1164) | **ESTABLISHED** |
| OB1-0204 | `src/property/parse.rs:792` | `stack_to_property_list` | `adopt_plain` | P1: argument is `CRYPTO_malloc(size, FILE, LINE_MALLOC_LIST)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0205 | `src/property/parse.rs:857` | `ossl_parse_property` | `adopt_plain` | P1: argument is `CRYPTO_malloc( core::mem::size_of::<OsslPropertyDefinition>(), FILE, L` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0206 | `src/property/parse.rs:943` | `ossl_parse_query` | `adopt_plain` | P1: argument is `CRYPTO_malloc( core::mem::size_of::<OsslPropertyDefinition>(), FILE, L` | E0 plain | R1 plain `CRYPTO_free` | **TEST** |
| OB1-0207 | `src/property/parse.rs:1213` | `ossl_property_merge` | `adopt_plain` | P1: argument is `CRYPTO_malloc(size, FILE, LINE_MALLOC_MERGED)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0208 | `src/property/store.rs:1171` | `ossl_method_store_cache_set` | `adopt_plain_nullable` | P5: NULL placeholders on the authority error tails | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0209 | `src/property/store.rs:1208` | `ossl_method_store_cache_set` | `adopt_plain_nullable` | P5: NULL placeholders on the authority error tails | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0210 | `src/property/store.rs:1223` | `ossl_method_store_cache_set` | `adopt_plain_nullable` | P5: NULL placeholders on the authority error tails | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0211 | `src/provider/decode_der2key.rs:647` | `der2key_decode` | `adopt_plain_nullable` | P1: `der_raw` from `ossl_read_der` (crate seam) | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0212 | `src/provider/dsa_kmgmt.rs:865` | `dsa_set_gen_seed` | `adopt_cleansed` | P3: old `seed` from `CRYPTO_memdup(seed,seedlen)` @874 | E1: `num = seedlen` | R2 `CRYPTO_clear_free(seedlen)` (FILE_SEAM,454) | **ESTABLISHED** |
| OB1-0213 | `src/provider/dsa_kmgmt.rs:874` | `dsa_set_gen_seed` | `adopt_cleansed` | P1: argument is `CRYPTO_memdup(seed, seedlen, FILE, 458)` | E1: `num = seedlen` | R2 `CRYPTO_clear_free(seedlen)` | **ESTABLISHED** |
| OB1-0214 | `src/provider/dsa_kmgmt.rs:965` | `dsa_gen_set_params` | `adopt_plain` | P3: old `mdname` from `CRYPTO_strdup` @970 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0215 | `src/provider/dsa_kmgmt.rs:970` | `dsa_gen_set_params` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*p).data, FILE, 514)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0216 | `src/provider/dsa_kmgmt.rs:986` | `dsa_gen_set_params` | `adopt_plain` | P3: old `mdprops` from `CRYPTO_strdup` @991 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0217 | `src/provider/dsa_kmgmt.rs:991` | `dsa_gen_set_params` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*p).data, FILE, 524)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0218 | `src/provider/dsa_kmgmt.rs:1266` | `dsa_gen_cleanup` | `adopt_plain` | P3: `mdname` from `CRYPTO_strdup` @970 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,706) | **ESTABLISHED** |
| OB1-0219 | `src/provider/dsa_kmgmt.rs:1271` | `dsa_gen_cleanup` | `adopt_plain` | P3: `mdprops` from `CRYPTO_strdup` @991 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,707) | **ESTABLISHED** |
| OB1-0220 | `src/provider/dsa_kmgmt.rs:1276` | `dsa_gen_cleanup` | `adopt_cleansed` | P3: `seed` from `CRYPTO_memdup` @874 | E1: `num = seedlen` | R2 `CRYPTO_clear_free(seedlen)` (FILE_SEAM,708) | **ESTABLISHED** |
| OB1-0221 | `src/provider/dsa_sig.rs:222` | `dsa_newctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup(propq, FILE, 147)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0222 | `src/provider/dsa_sig.rs:901` | `dsa_freectx` | `adopt_plain` | P3: `sig` `OSSL_PARAM_get_octet_string` @1633 or `CRYPTO_memdup` @978; `propq` `CRYPTO_strdup` @223/966 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0223 | `src/provider/dsa_sig.rs:907` | `dsa_freectx` | `adopt_plain` | P3: `sig` `OSSL_PARAM_get_octet_string` @1633 or `CRYPTO_memdup` @978; `propq` `CRYPTO_strdup` @223/966 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0224 | `src/provider/dsa_sig.rs:965` | `dsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*srcctx).propq, FILE, 663)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0225 | `src/provider/dsa_sig.rs:977` | `dsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_memdup((*srcctx).sig, (*srcctx).siglen, FILE, 666)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0226 | `src/provider/dsa_sig.rs:1619` | `dsa_sigalg_set_ctx_params` | `adopt_plain` | P2: `sig` from `OSSL_PARAM_get_octet_string` @1633 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,628) | **ESTABLISHED** |
| OB1-0227 | `src/provider/dsa_sig.rs:1633` | `dsa_sigalg_set_ctx_params` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p.sig, &mut sig, 0, ptr::addr_of_mut!((*pdsactx).` @1627 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0228 | `src/provider/dsa_sig.rs:1638` | `dsa_sigalg_set_ctx_params` | `adopt_plain` | P3: old `sig` from `OSSL_PARAM_get_octet_string` @1633 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,628) | **ESTABLISHED** |
| OB1-0229 | `src/provider/ec_kmgmt.rs:709` | `ec_export` | `adopt_plain` | P2: `key_to_params(...,&mut pub_key)` @698 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,503) | **ESTABLISHED** |
| OB1-0230 | `src/provider/ec_kmgmt.rs:710` | `ec_export` | `adopt_plain` | P2: `ossl_ec_group_todata(...,&mut genbuf)` @688 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,504) | **ESTABLISHED** |
| OB1-0231 | `src/provider/ec_kmgmt.rs:1161` | `common_get_params` | `adopt_plain` | P2: `ossl_ec_group_todata(...,&mut genbuf)` @1146 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,745) | **ESTABLISHED** |
| OB1-0232 | `src/provider/ec_kmgmt.rs:1166` | `common_get_params` | `adopt_plain` | P2: `key_to_params(...,&mut pub_key)` @1155 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,746) | **ESTABLISHED** |
| OB1-0233 | `src/provider/ec_kmgmt.rs:1529` | `sm2_gen_init` | `adopt_plain` | P1: argument is `CRYPTO_strdup(c"sm2".as_ptr(), FILE, 1005)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0234 | `src/provider/ec_kmgmt.rs:1622` | `ec_gen_set_params` | `adopt_plain` | P3: loop fields `CRYPTO_strdup` @1630 / `CRYPTO_memdup` @1686 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1063/1090) | **ESTABLISHED** |
| OB1-0235 | `src/provider/ec_kmgmt.rs:1627` | `ec_gen_set_params` | `adopt_plain` | P3: loop fields `CRYPTO_strdup` @1630 / `CRYPTO_memdup` @1686 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1063/1090) | **ESTABLISHED** |
| OB1-0236 | `src/provider/ec_kmgmt.rs:1680` | `ec_gen_set_params` | `adopt_plain` | P3: loop fields `CRYPTO_strdup` @1630 / `CRYPTO_memdup` @1686 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1063/1090) | **ESTABLISHED** |
| OB1-0237 | `src/provider/ec_kmgmt.rs:1686` | `ec_gen_set_params` | `adopt_plain` | P3: loop fields `CRYPTO_strdup` @1630 / `CRYPTO_memdup` @1686 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1063/1090) | **ESTABLISHED** |
| OB1-0238 | `src/provider/ec_kmgmt.rs:2076` | `ec_gen_cleanup` | `adopt_cleansed` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E1: `num = (*gctx).dhkem_ikmlen` | R2 `CRYPTO_clear_free((*gctx).dhkem_ikmlen)` | **ESTABLISHED** |
| OB1-0239 | `src/provider/ec_kmgmt.rs:2088` | `ec_gen_cleanup` | `adopt_plain` | P2: `(*gctx).group_name = OwnedBuf::adopt_plain(` @1529 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0240 | `src/provider/ec_kmgmt.rs:2093` | `ec_gen_cleanup` | `adopt_plain` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0241 | `src/provider/ec_kmgmt.rs:2098` | `ec_gen_cleanup` | `adopt_plain` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0242 | `src/provider/ec_kmgmt.rs:2103` | `ec_gen_cleanup` | `adopt_plain` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0243 | `src/provider/ec_kmgmt.rs:2108` | `ec_gen_cleanup` | `adopt_plain` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0244 | `src/provider/ec_kmgmt.rs:2113` | `ec_gen_cleanup` | `adopt_plain` | P2: `let gctx = CRYPTO_zalloc(core::mem::size_of::<EcGenCtx>(), FILE, 982).cast::<EcGenCtx>();` @1488 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0245 | `src/provider/ecdh_exch.rs:264` | `ecdh_freectx` | `adopt_cleansed` | P3: `kdf_ukm` from `OSSL_PARAM_get_octet_string` @548 or `CRYPTO_memdup` @334 | E1: `num = kdf_ukmlen` = helper length | R2 `CRYPTO_clear_free` (FILE_ECDH_EXCH_SEAM,189) | **ESTABLISHED** |
| OB1-0246 | `src/provider/ecdh_exch.rs:332` | `ecdh_dupctx` | `adopt_cleansed` | P1: argument is `CRYPTO_memdup( (*srcctx).kdf_ukm, (*srcctx).kdf_ukmlen, FILE_ECDH_EXCH` | E1: `num = (*srcctx).kdf_ukmlen` | R2 `CRYPTO_clear_free((*srcctx).kdf_ukmlen)` | **ESTABLISHED** |
| OB1-0247 | `src/provider/ecdh_exch.rs:555` | `ecdh_set_ctx_params` | `adopt_plain` | P2: `let pectx = CRYPTO_zalloc(core::mem::size_of::<ProvEcdhCtx>(), FILE_ECDH_EXCH, 97)` @143 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0248 | `src/provider/ecdh_exch.rs:561` | `ecdh_set_ctx_params` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p.ukm, &mut tmp_ukm, 0, &mut tmp_ukmlen) == 0 {` @550 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0249 | `src/provider/ecdsa_sig.rs:207` | `ecdsa_newctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup(propq, FILE, 147)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0250 | `src/provider/ecdsa_sig.rs:897` | `ecdsa_freectx` | `adopt_plain` | P2: `Some(buf) => (*ctx).propq = buf.into_raw().cast::<c_char>(),` @212 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0251 | `src/provider/ecdsa_sig.rs:903` | `ecdsa_freectx` | `adopt_plain` | P3: `sig` from `CRYPTO_memdup((*srcctx).sig,siglen)` @982 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0252 | `src/provider/ecdsa_sig.rs:970` | `ecdsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*srcctx).propq, FILE, 667)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0253 | `src/provider/ecdsa_sig.rs:982` | `ecdsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_memdup((*srcctx).sig, (*srcctx).siglen, FILE, 670)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0254 | `src/provider/ecdsa_sig.rs:1651` | `ecdsa_sigalg_set_ctx_params` | `adopt_plain` | P3: old `sig` from `CRYPTO_memdup` @982 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0255 | `src/provider/ecdsa_sig.rs:1665` | `ecdsa_sigalg_set_ctx_params` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p.sig, &mut sig, 0, ptr::addr_of_mut!((*ctx).sigl` @1659 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0256 | `src/provider/ecdsa_sig.rs:1670` | `ecdsa_sigalg_set_ctx_params` | `adopt_plain` | P3: old `sig` from `CRYPTO_memdup` @982 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0257 | `src/provider/ecx_kem.rs:312` | `ecxkem_freectx` | `adopt_cleansed` | P3: `ikm` from `OSSL_PARAM_get_octet_string` @560 (plain seam) | E1: `num = ikmlen` = helper length | R2 `CRYPTO_clear_free` (FILE_ECX_KEM_SEAM,177) | **ESTABLISHED** |
| OB1-0258 | `src/provider/ecx_kem.rs:565` | `ecxkem_set_ctx_params` | `adopt_cleansed` | P3: old/new `ikm` from `OSSL_PARAM_get_octet_string` @560 | E1: `num = tmplen` = helper length | R2 `CRYPTO_clear_free` (FILE_ECX_KEM_SEAM,321) | **ESTABLISHED** |
| OB1-0259 | `src/provider/ecx_kem.rs:572` | `ecxkem_set_ctx_params` | `adopt_cleansed` | P3: old/new `ikm` from `OSSL_PARAM_get_octet_string` @560 | E1: `num = tmplen` = helper length | R2 `CRYPTO_clear_free` (FILE_ECX_KEM_SEAM,321) | **ESTABLISHED** |
| OB1-0260 | `src/provider/ecx_kmgmt.rs:927` | `set_property_query` | `adopt_plain` | P3: old `propq` from `new_strdup(propq)` @935 | E0 plain | R1 `CRYPTO_free` (FILE_ECX_KMGMT_SEAM,848) | **ESTABLISHED** |
| OB1-0261 | `src/provider/ecx_kmgmt.rs:935` | `set_property_query` | `new_strdup` | P1: `new_strdup(propq)`; arg is NUL-terminated per the fn contract | E0 plain | R1 `CRYPTO_free` (FILE_ECX_KMGMT_SEAM,851) | **ESTABLISHED** |
| OB1-0262 | `src/provider/ecx_kmgmt.rs:1031` | `ecx_set_params` | `adopt_secure_cleansed` | P4: `privkey` is `CRYPTO_secure_zalloc(keylen)` from `ossl_ecx_key_allocate_privkey` (ec/ecx_key.rs:244); `params`' property-q is borrowed and copied by `CRYPTO_strdup` | E1: `num = keylen` = secure allocation length (plain fallback covered) | R4 `CRYPTO_secure_clear_free(keylen)` (FILE_ECX_KMGMT_SEAM,930); authority `:930` plain release is UB, not reproduced (§17) | **ESTABLISHED** |
| OB1-0263 | `src/provider/ecx_kmgmt.rs:1316` | `ecx_gen_set_params` | `adopt_plain` | P3: `propq` `new_strdup` @935; `dhkem_ikm` from `OSSL_PARAM_get_octet_string` @1340; `kdfpropq` UTF8_STRING data | E0 plain | R1 `CRYPTO_free` (FILE_ECX_KMGMT_SEAM,1152/1160) | **ESTABLISHED** |
| OB1-0264 | `src/provider/ecx_kmgmt.rs:1323` | `ecx_gen_set_params` | `new_strdup` | P1: `new_strdup((*p.kdfpropq).data)`; param checked `OSSL_PARAM_UTF8_STRING` @1313 | E0 plain | R1 `CRYPTO_free` (FILE_ECX_KMGMT_SEAM,1153) | **ESTABLISHED** |
| OB1-0265 | `src/provider/ecx_kmgmt.rs:1333` | `ecx_gen_set_params` | `adopt_plain` | P3: `propq` `new_strdup` @935; `dhkem_ikm` from `OSSL_PARAM_get_octet_string` @1340; `kdfpropq` UTF8_STRING data | E0 plain | R1 `CRYPTO_free` (FILE_ECX_KMGMT_SEAM,1152/1160) | **ESTABLISHED** |
| OB1-0266 | `src/provider/encode_key2any.rs:367` | `key_to_p8info` | `adopt_plain_nullable` | P2: `k2d(key,&mut der,...)` @364 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0267 | `src/provider/encode_key2any.rs:500` | `key_to_pubkey` | `adopt_plain_nullable` | P2: `k2d(key,&mut der,...)` @497 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0268 | `src/provider/encode_key2any.rs:824` | `key_to_type_specific_der_bio` | `adopt_plain_nullable` | P2: `k2d(key,&mut der,...)` @815 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0269 | `src/provider/encode_key2text.rs:688` | `ec_to_text` | `adopt_plain` | P2: out-param `priv_len = unsafe { EC_KEY_priv2buf(ec, &mut raw) };` @659 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0270 | `src/provider/exchange.rs:903` | `dh_freectx` | `adopt_plain` | P3: `kdf_cekalg` `CRYPTO_strdup` @990; `kdf_ukm` helper @1184 | E1: `num = kdf_ukmlen` = helper length | R2 `CRYPTO_clear_free` (FILE_DH_EXCH_SEAM,290) | **ESTABLISHED** |
| OB1-0271 | `src/provider/exchange.rs:911` | `dh_freectx` | `adopt_cleansed` | P3: `kdf_cekalg` `CRYPTO_strdup` @990; `kdf_ukm` helper @1184 | E1: `num = kdf_ukmlen` = helper length | R2 `CRYPTO_clear_free` (FILE_DH_EXCH_SEAM,290) | **ESTABLISHED** |
| OB1-0272 | `src/provider/exchange.rs:969` | `dh_dupctx` | `adopt_cleansed` | P1: argument is `CRYPTO_memdup( (*srcctx).kdf_ukm, (*srcctx).kdf_ukmlen, FILE_DH_EXCH, ` | E1: `num = (*srcctx).kdf_ukmlen` | R2 `CRYPTO_clear_free((*srcctx).kdf_ukmlen)` | **ESTABLISHED** |
| OB1-0273 | `src/provider/exchange.rs:989` | `dh_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*srcctx).kdf_cekalg, FILE_DH_EXCH, 338)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0274 | `src/provider/exchange.rs:1184` | `dh_set_ctx_params` | `adopt_plain` | P3: old `kdf_ukm` plain block; new from `OSSL_PARAM_get_octet_string` @1188 | E1: `num = tmp_ukmlen` = helper length | R1 old / R2 new (`CRYPTO_clear_free`, FILE_DH_EXCH_SEAM,435) | **ESTABLISHED** |
| OB1-0275 | `src/provider/exchange.rs:1198` | `dh_set_ctx_params` | `adopt_cleansed` | P3: old `kdf_ukm` plain block; new from `OSSL_PARAM_get_octet_string` @1188 | E1: `num = tmp_ukmlen` = helper length | R1 old / R2 new (`CRYPTO_clear_free`, FILE_DH_EXCH_SEAM,435) | **ESTABLISHED** |
| OB1-0276 | `src/provider/exchange.rs:1217` | `dh_set_ctx_params` | `adopt_plain` | P3: old `kdf_ukm` plain block; new from `OSSL_PARAM_get_octet_string` @1188 | E1: `num = tmp_ukmlen` = helper length | R1 old / R2 new (`CRYPTO_clear_free`, FILE_DH_EXCH_SEAM,435) | **ESTABLISHED** |
| OB1-0277 | `src/provider/exchange.rs:1228` | `dh_set_ctx_params` | `adopt_plain` | P3: old `kdf_ukm` plain block; new from `OSSL_PARAM_get_octet_string` @1188 | E1: `num = tmp_ukmlen` = helper length | R1 old / R2 new (`CRYPTO_clear_free`, FILE_DH_EXCH_SEAM,435) | **ESTABLISHED** |
| OB1-0278 | `src/provider/file_store.rs:637` | `file_set_ctx_params` | `adopt_plain` | P3: old `file.propq` from `OSSL_PARAM_get_utf8_string` @644 | E0 plain | R1 `CRYPTO_free` (NULL,0) | **ESTABLISHED** |
| OB1-0279 | `src/provider/file_store.rs:652` | `file_set_ctx_params` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_utf8_string(p.propq, &mut (*ctx).file.propq, 0) == 0 {` @644 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0280 | `src/provider/file_store.rs:715` | `file_set_ctx_params` | `adopt_plain` | P2: `let str_ = unsafe { X509_NAME_oneline(x509_name, ptr::null_mut(), 0) };` @700 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0281 | `src/provider/file_store.rs:1034` | `file_name_to_uri` | `adopt_plain` | P1: argument is `CRYPTO_zalloc(calculated_length, ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0282 | `src/provider/init.rs:406` | `provider_init` | `adopt_plain` | P2: `let strings = CRYPTO_calloc(` @396 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0283 | `src/provider/keymgmt.rs:1152` | `dh_set_gen_seed` | `adopt_cleansed` | P3: old `seed` from `CRYPTO_memdup(seed,seedlen)` @1164 | E1: `num = seedlen` = allocation length | R2 `CRYPTO_clear_free` (FILE_DH_KMGMT_SEAM,517) | **ESTABLISHED** |
| OB1-0284 | `src/provider/keymgmt.rs:1163` | `dh_set_gen_seed` | `adopt_cleansed` | P3: old `seed` from `CRYPTO_memdup(seed,seedlen)` @1164 | E1: `num = seedlen` = allocation length | R2 `CRYPTO_clear_free` (FILE_DH_KMGMT_SEAM,517) | **ESTABLISHED** |
| OB1-0285 | `src/provider/ml_dsa_codecs.rs:676` | `ossl_ml_dsa_d2i_PKCS8` | `adopt_plain` | P1: `slots` from `ossl_ml_common_pkcs8_fmt_order` (CRYPTO_calloc) | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_FREE_IN_SLOTS) | **ESTABLISHED** |
| OB1-0286 | `src/provider/ml_dsa_codecs.rs:717` | `ossl_ml_dsa_i2d_pubkey` | `new_memdup` | P1: `pk`/`pk_len` are the provider's public-key bytes (readable per encode contract) | E1: `len = (*params).pk_len` | R1 `CRYPTO_free` (FILE_SEAM,LINE_MEMDUP_PUB) | **ESTABLISHED** |
| OB1-0287 | `src/provider/ml_dsa_codecs.rs:911` | `ossl_ml_dsa_i2d_prvkey` | `adopt_plain` | P1: `fmt_slots` from `ossl_ml_common_pkcs8_fmt_order` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_FREE_OUT_SLOTS) | **ESTABLISHED** |
| OB1-0288 | `src/provider/ml_dsa_sig.rs:191` | `ml_dsa_freectx` | `adopt_plain` | P3: `sig` from `CRYPTO_memdup` @267 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0289 | `src/provider/ml_dsa_sig.rs:267` | `ml_dsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_memdup( (*srcctx).sig, (*srcctx).siglen, FILE, LINE_MEMDUP_SIG,` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0290 | `src/provider/ml_dsa_sig.rs:974` | `ml_dsa_set_ctx_params` | `adopt_plain` | P3: old `sig` from `CRYPTO_memdup` @267 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,972) | **ESTABLISHED** |
| OB1-0291 | `src/provider/ml_kem_codecs.rs:721` | `ossl_ml_kem_d2i_PKCS8` | `adopt_plain` | P1: `slots` from `ossl_ml_common_pkcs8_fmt_order` (CRYPTO_calloc) | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,400) | **ESTABLISHED** |
| OB1-0292 | `src/provider/ml_kem_codecs.rs:953` | `ossl_ml_kem_i2d_prvkey` | `adopt_plain` | P1: `fmt_slots` from `ossl_ml_common_pkcs8_fmt_order` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,552) | **ESTABLISHED** |
| OB1-0293 | `src/provider/ml_kem_kmgmt.rs:1154` | `ml_kem_load` | `adopt_secure_cleansed` | P2: `let encoded_dk = (*key).encoded_dk;` @1117 | E1: `num = prvkey_bytes` | R4 `CRYPTO_secure_clear_free(num)` | **ESTABLISHED** |
| OB1-0294 | `src/provider/ml_kem_kmgmt.rs:1190` | `load_err` | `adopt_secure_cleansed` | P2: `encoded_dk`, detached from `(*key).encoded_dk` @1117; allocated by `CRYPTO_secure_malloc((*p8fmt).priv_length)` (`ml_kem_codecs.rs:696`) | E1: `num = prvkey_bytes` = codec-verified `priv_length` (`ml_kem_codecs.rs:627-628`) | R4 `CRYPTO_secure_clear_free(num)` (`ml_kem_kmgmt.c:535`) | **ESTABLISHED** |
| OB1-0295 | `src/provider/ml_kem_kmgmt.rs:1432` | `ml_kem_gen_set_params` | `adopt_plain` | P3: old `propq` from `CRYPTO_strdup` @1437 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_GEN_FREE_PROPQ) | **ESTABLISHED** |
| OB1-0296 | `src/provider/ml_kem_kmgmt.rs:1437` | `ml_kem_gen_set_params` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*p.propq).data, FILE, LINE_GEN_FREE_PROPQ)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0297 | `src/provider/ml_kem_kmgmt.rs:1589` | `ml_kem_gen_cleanup` | `adopt_plain` | P2: `(*gctx).propq = OwnedBuf::adopt_plain(` @1437 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0298 | `src/provider/mlx_kmgmt.rs:291` | `mlx_kem_key_free` | `adopt_plain` | P2: `(*key).propq = propq.map_or(ptr::null_mut(), \|buf\| buf.into_raw().cast::<c_char>());` @331 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0299 | `src/provider/mlx_kmgmt.rs:312` | `mlx_kem_key_new` | `adopt_plain` | P2: `(*key).propq = propq.map_or(ptr::null_mut(), \|buf\| buf.into_raw().cast::<c_char>());` @331 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0300 | `src/provider/mlx_kmgmt.rs:1324` | `mlx_kem_set_params` | `adopt_plain` | P2: `(*key).propq = propq.map_or(ptr::null_mut(), \|buf\| buf.into_raw().cast::<c_char>());` @331 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0301 | `src/provider/mlx_kmgmt.rs:1379` | `mlx_kem_gen_set_params` | `adopt_plain` | P3: old `propq` from `CRYPTO_strdup` @1384 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_GEN_SET_PROPQ) | **ESTABLISHED** |
| OB1-0302 | `src/provider/mlx_kmgmt.rs:1384` | `mlx_kem_gen_set_params` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*p.propq).data, FILE, LINE_GEN_SET_PROPQ)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0303 | `src/provider/mlx_kmgmt.rs:1544` | `mlx_kem_gen_cleanup` | `adopt_plain` | P3: `propq` from `CRYPTO_strdup` @1384/@1578 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0304 | `src/provider/mlx_kmgmt.rs:1578` | `mlx_kem_dup` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*key).propq, FILE, LINE_DUP_MEMDUP)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0305 | `src/provider/mlx_kmgmt.rs:1597` | `mlx_kem_dup` | `adopt_plain` | P2: `Some(buf) => (*ret).propq = buf.into_raw().cast::<c_char>(),` @1583 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0306 | `src/provider/mod.rs:602` | `infopair_free` | `adopt_plain` | P2: `(*pair).name = name_buf.into_raw().cast::<c_char>();` @698 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0307 | `src/provider/mod.rs:608` | `infopair_free` | `adopt_plain` | P2: `(*pair).value = value_buf.into_raw().cast::<c_char>();` @720 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0308 | `src/provider/mod.rs:639` | `infopair_copy` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*src).name, FILE, lines::L_PAIR_COPY_NAME)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0309 | `src/provider/mod.rs:651` | `infopair_copy` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*src).value, FILE, lines::L_PAIR_COPY_VALUE)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0310 | `src/provider/mod.rs:690` | `infopair_add` | `adopt_plain` | P1: argument is `CRYPTO_strdup(name, FILE, lines::L_PAIR_ADD_NAME)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0311 | `src/provider/mod.rs:700` | `infopair_add` | `adopt_plain` | P1: argument is `CRYPTO_strdup(value, FILE, lines::L_PAIR_ADD_VALUE)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0312 | `src/provider/mod.rs:706` | `infopair_add` | `adopt_plain` | P2: `(*pair).name = name_buf.into_raw().cast::<c_char>();` @698 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0313 | `src/provider/mod.rs:712` | `infopair_add` | `adopt_plain` | P2: `(*pair).value = value_buf.into_raw().cast::<c_char>();` @720 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0314 | `src/provider/mod.rs:751` | `ossl_provider_info_clear` | `adopt_plain` | P3: `name`/`path` from `CRYPTO_strdup` @639/691/1421/2149 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0315 | `src/provider/mod.rs:757` | `ossl_provider_info_clear` | `adopt_plain` | P3: `name`/`path` from `CRYPTO_strdup` @639/691/1421/2149 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0316 | `src/provider/mod.rs:1066` | `ossl_provider_store_free` | `adopt_plain` | P3: `default_path` from `CRYPTO_strdup(path)` @2149 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_STORE_FREE_PATH) | **ESTABLISHED** |
| OB1-0317 | `src/provider/mod.rs:1420` | `ossl_provider_add_builtin` | `adopt_plain` | P1: argument is `CRYPTO_strdup(name, FILE_PROVIDER, lines::L_ADD_BUILTIN_DUP)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0318 | `src/provider/mod.rs:1858` | `provider_new` | `adopt_plain` | P1: argument is `CRYPTO_strdup(name, FILE, lines::L_PROV_NEW_NAME)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0319 | `src/provider/mod.rs:1951` | `ossl_provider_free` | `adopt_plain` | P3: `error_strings` from the registered-strings owner `src/provider/init.rs:427` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_PROV_FREE_ERROR_STRINGS) | **ESTABLISHED** |
| OB1-0320 | `src/provider/mod.rs:1958` | `ossl_provider_free` | `adopt_plain` | P3: `operation_bits` from the provider-activation block (`src/provider/activate.rs:325`) | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_PROV_FREE_OPERATION_BITS) | **ESTABLISHED** |
| OB1-0321 | `src/provider/mod.rs:1978` | `ossl_provider_free` | `adopt_plain` | P2: `(*prov).name = name_buf.into_raw().cast::<c_char>();` @1866 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0322 | `src/provider/mod.rs:1984` | `ossl_provider_free` | `adopt_plain` | P3: `name` from `OwnedBuf::new` @1866 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_PROV_FREE_NAME) | **ESTABLISHED** |
| OB1-0323 | `src/provider/mod.rs:2012` | `ossl_provider_set_module_path` | `adopt_plain` | P3: old `path` from `CRYPTO_strdup` @2029 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_SET_PATH_FREE) | **ESTABLISHED** |
| OB1-0324 | `src/provider/mod.rs:2022` | `ossl_provider_set_module_path` | `adopt_plain` | P1: argument is `CRYPTO_strdup(module_path, FILE, lines::L_SET_PATH_DUP)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0325 | `src/provider/mod.rs:2148` | `ossl_provider_set_default_search_path` | `adopt_plain` | P1: argument is `CRYPTO_strdup(path, FILE, lines::L_SET_SEARCH_PATH_DUP)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0326 | `src/provider/mod.rs:2168` | `ossl_provider_set_default_search_path` | `adopt_plain` | P3: old `default_path` from `CRYPTO_strdup(path)` @2149 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_SET_SEARCH_PATH_FREE) | **ESTABLISHED** |
| OB1-0327 | `src/provider/rand.rs:3135` | `drbg_ctr_set_ctx_params_locked` | `new_strndup` | P2: `let base = (*(*p).cipher).data.cast::<c_char>();` @3118 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0328 | `src/provider/rsa_enc.rs:547` | `rsa_freectx` | `adopt_plain` | P2: `let prsactx = CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 93).cast::<ProvRsaCt` @213 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0329 | `src/provider/rsa_enc.rs:604` | `rsa_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_memdup(src_label, src_labellen, FILE, 369)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0330 | `src/provider/rsa_enc.rs:1092` | `rsa_set_ctx_params` | `adopt_plain` | P2: `let prsactx = CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 93).cast::<ProvRsaCt` @213 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0331 | `src/provider/rsa_enc.rs:1099` | `rsa_set_ctx_params` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p.label, &mut tmp_label, 0, &mut tmp_labellen) ==` @1086 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0332 | `src/provider/seed_src.rs:234` | `destroy_body` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p, &mut ptr, 0, &mut size) == 0 {` @1090 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0333 | `src/provider/seed_src.rs:240` | `destroy_body` | `adopt_plain` | P2: out-param `if OSSL_PARAM_get_octet_string(p, &mut ptr, 0, &mut size) == 0 {` @1090 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0334 | `src/provider/seed_src.rs:1095` | `test_rng_set_ctx_params` | `adopt_plain` | P1: `entropy`/`nonce` from `OSSL_PARAM_get_octet_string` @1085/1105 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0335 | `src/provider/seed_src.rs:1113` | `test_rng_set_ctx_params` | `adopt_plain` | P1: `entropy`/`nonce` from `OSSL_PARAM_get_octet_string` @1085/1105 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0336 | `src/provider/sm2_sig.rs:204` | `sm2sig_newctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup(propq, FILE, 133)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0337 | `src/provider/sm2_sig.rs:583` | `sm2sig_freectx` | `adopt_plain` | P3: `propq` `CRYPTO_strdup` @205/631; `id` `OwnedBuf::new` @662 or adopt @923 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0338 | `src/provider/sm2_sig.rs:589` | `sm2sig_freectx` | `adopt_plain` | P3: `propq` `CRYPTO_strdup` @205/631; `id` `OwnedBuf::new` @662 or adopt @923 | E0 plain | R1 `CRYPTO_free` | **ESTABLISHED** |
| OB1-0339 | `src/provider/sm2_sig.rs:630` | `sm2sig_dupctx` | `adopt_plain` | P1: argument is `CRYPTO_strdup((*srcctx).propq, FILE, 377)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0340 | `src/provider/sm2_sig.rs:917` | `sm2sig_set_ctx_params` | `adopt_plain` | P2: `id` from `OSSL_PARAM_get_octet_string` @921; `mdname` from `OSSL_PARAM_get_utf8_string` @942 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,475) | **ESTABLISHED** |
| OB1-0341 | `src/provider/sm2_sig.rs:923` | `sm2sig_set_ctx_params` | `adopt_plain` | P2: `id` from `OSSL_PARAM_get_octet_string` @921; `mdname` from `OSSL_PARAM_get_utf8_string` @942 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,475) | **ESTABLISHED** |
| OB1-0342 | `src/provider/sm2_sig.rs:949` | `sm2sig_set_ctx_params` | `adopt_plain` | P2: `id` from `OSSL_PARAM_get_octet_string` @921; `mdname` from `OSSL_PARAM_get_utf8_string` @942 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,475) | **ESTABLISHED** |
| OB1-0343 | `src/provider/sm2_sig.rs:957` | `sm2sig_set_ctx_params` | `adopt_plain` | P2: `id` from `OSSL_PARAM_get_octet_string` @921; `mdname` from `OSSL_PARAM_get_utf8_string` @942 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,475) | **ESTABLISHED** |
| OB1-0344 | `src/provider/util.rs:686` | `ossl_prov_memdup` | `adopt_plain` | P2: `let copy = CRYPTO_memdup(src, src_len, FILE_PROVIDER_UTIL, 0).cast::<u8>();` @683 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0345 | `src/rsa/ameth.rs:200` | `rsa_pub_encode` | `adopt_plain` | P2: out-param `let penclen = unsafe { i2d_RSAPublicKey((*pkey).pkey.cast::<Rsa>(), &mut penc) }` @192 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0346 | `src/rsa/ameth.rs:382` | `rsa_priv_encode` | `adopt_cleansed` | P2: out-param `let rklen = unsafe { i2d_RSAPrivateKey((*pkey).pkey.cast::<Rsa>(), &mut rk) };` @369 | E1: `num = rklen as usize` | R2 `CRYPTO_clear_free(rklen as usize)` | **ESTABLISHED** |
| OB1-0347 | `src/rsa/gen.rs:118` | `calloc` | `adopt_plain` | P2: `let raw = CRYPTO_calloc(num, size, FILE_RSA_GEN, LINE).cast::<c_uchar>();` @115 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0348 | `src/rsa/pmeth.rs:301` | `pkey_rsa_copy` | `adopt_plain_nullable` | P3: old `oaep_label` from `CRYPTO_memdup` @306 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_FREE_OAEP_LABEL_COPY) | **ESTABLISHED** |
| OB1-0349 | `src/rsa/pmeth.rs:1147` | `pkey_rsa_ctrl` | `adopt_plain_nullable` | P4: caller-owned `p2` for `EVP_PKEY_CTRL_RSA_OAEP_LABEL` (set0 ABI) | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,LINE_FREE_OAEP_LABEL_CTRL) | **ESTABLISHED** |
| OB1-0350 | `src/rsa/pmeth.rs:1362` | `pkey_rsa_ctrl_str` | `adopt_plain_nullable` | P2: `let lab = unsafe { OPENSSL_hexstr2buf(value, &mut lablen) };` @1358 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0351 | `src/rsa/pss.rs:332` | `ossl_rsa_verify_PKCS1_PSS_mgf1` | `adopt_plain` | P2: `db = CRYPTO_malloc(masked_dblen as usize, FILE, LINE).cast::<c_uchar>();` @240 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0352 | `src/rsa/pss.rs:549` | `ossl_rsa_padding_add_PKCS1_PSS_mgf1` | `adopt_cleansed` | P2: `salt = CRYPTO_malloc(s_len as usize, FILE, LINE).cast::<c_uchar>();` @484 | E1: `num = s_len as usize` | R2 `CRYPTO_clear_free(s_len as usize)` | **ESTABLISHED** |
| OB1-0353 | `src/runtime/conf/def.rs:727` | `str_copy` | `adopt_plain_nullable` | P3: `*pto` is the previous `str_copy` value; `buf` is `BUF_MEM_new` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0354 | `src/runtime/conf/def.rs:735` | `str_copy` | `adopt_plain_nullable` | P3: `*pto` is the previous `str_copy` value; `buf` is `BUF_MEM_new` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0355 | `src/runtime/conf/def.rs:918` | `def_destroy` | `adopt_plain_nullable` | P2: `let conf = ret.as_ptr().cast::<Conf>();` @845 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0356 | `src/runtime/conf/def.rs:1104` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0357 | `src/runtime/conf/def.rs:1320` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0358 | `src/runtime/conf/def.rs:1381` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0359 | `src/runtime/conf/def.rs:1399` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0360 | `src/runtime/conf/def.rs:1421` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0361 | `src/runtime/conf/def.rs:1438` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0362 | `src/runtime/conf/def.rs:1565` | `def_load_bio` | `adopt_plain_nullable` | P2: `dirpath`/`include` from `str_copy`; `include_path` from `str_copy` or `OwnedBuf::new` @1369 `into_raw` | E0 plain | R1 `free(NULL,0)` | **ESTABLISHED** |
| OB1-0363 | `src/runtime/conf/def.rs:1649` | `finish_with_error` | `adopt_plain_nullable` | P4: `section` from `def_load_bio`'s `CRYPTO_strdup(c"default")` @1005 | E0 plain; extent `strlen+1` | R1 `CRYPTO_free` (NULL,0; authority `:571`) | **ESTABLISHED** |
| OB1-0364 | `src/runtime/conf/def.rs:1663` | `finish_with_error` | `adopt_plain_nullable` | P4: `dirpath` handed over by `process_include` @1432/:1786 (`str_copy` or `OwnedBuf::new` @1377) | E0 plain; extent = allocation | R1 `CRYPTO_free` (NULL,0; authority `:584`) | **ESTABLISHED** |
| OB1-0365 | `src/runtime/conf/def.rs:1689` | `finish_with_error` | `adopt_plain_nullable` | P4: `v->name` from `CRYPTO_strdup` @1512 (`v` from `OwnedBuf::new` @1504) | E0 plain; extent `strlen+1` | R1 `CRYPTO_free` (NULL,0; authority `:597`) | **ESTABLISHED** |
| OB1-0366 | `src/runtime/conf/def.rs:1695` | `finish_with_error` | `adopt_plain_nullable` | P4: `v->value`, the `BUF_MEM` data block installed by `str_copy` @732 | E0 plain; extent = `BUF_MEM` length | R1 `CRYPTO_free` (NULL,0; authority `:598`) | **ESTABLISHED** |
| OB1-0367 | `src/runtime/conf/def.rs:1701` | `finish_with_error` | `adopt_plain_nullable` | P4: `v` from `OwnedBuf::new(size_of::<ConfValue>())` @1504 | E0 plain; extent exactly `size_of::<ConfValue>()` | R1 `CRYPTO_free` (NULL,0; authority `:599`) | **ESTABLISHED** |
| OB1-0368 | `src/runtime/confmod/mod.rs:382` | `module_free` | `adopt_plain_nullable` | P3: `md.name` from `CRYPTO_strdup` @886 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_MODULE_FREE) | **ESTABLISHED** |
| OB1-0369 | `src/runtime/confmod/mod.rs:388` | `module_free` | `adopt_plain_nullable` | P3: `md` from `OwnedBuf::new_zeroed` @873 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_MODULE_FREE) | **ESTABLISHED** |
| OB1-0370 | `src/runtime/confmod/mod.rs:424` | `module_finish` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0371 | `src/runtime/confmod/mod.rs:430` | `module_finish` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0372 | `src/runtime/confmod/mod.rs:436` | `module_finish` | `adopt_plain_nullable` | P3: `imod` from `OwnedBuf::new(size_of::<ConfImodule>())` @1058 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,L_IMODULE_FREE) | **ESTABLISHED** |
| OB1-0373 | `src/runtime/confmod/mod.rs:911` | `module_add` | `adopt_plain_nullable` | P2: `(*tmod).name = CRYPTO_strdup(name, FILE, L_MODULE_NAME);` @890 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0374 | `src/runtime/confmod/mod.rs:1081` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0375 | `src/runtime/confmod/mod.rs:1087` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0376 | `src/runtime/confmod/mod.rs:1110` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0377 | `src/runtime/confmod/mod.rs:1116` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0378 | `src/runtime/confmod/mod.rs:1139` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0379 | `src/runtime/confmod/mod.rs:1145` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0380 | `src/runtime/confmod/mod.rs:1185` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0381 | `src/runtime/confmod/mod.rs:1191` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0382 | `src/runtime/confmod/mod.rs:1214` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).name = CRYPTO_strdup(name, FILE, L_IMODULE_NAME);` @1069 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0383 | `src/runtime/confmod/mod.rs:1220` | `module_init` | `adopt_plain_nullable` | P2: `(*imod).value = CRYPTO_strdup(value, FILE, L_IMODULE_VALUE);` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0384 | `src/runtime/confmod/mod.rs:1603` | `CONF_modules_load_file_ex` | `adopt_plain_nullable` | P3: `owned` from `CONF_get1_default_config_file` (CRYPTO_strdup) @1564 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,0) | **ESTABLISHED** |
| OB1-0385 | `src/sm2/sign.rs:688` | `ossl_sm2_internal_verify` | `adopt_plain` | P1: `der` from `i2d_ECDSA_SIG` @669 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,539) | **ESTABLISHED** |
| OB1-0386 | `src/srp/srp_vfy.rs:331` | `SRP_user_pwd_free` | `adopt_plain_nullable` | P3: `id`/`info` `CRYPTO_strdup` @424/437; `user_pwd` `OwnedBuf::new` @356 | E0 plain | R1 `CRYPTO_free` (FILE,184-186) | **ESTABLISHED** |
| OB1-0387 | `src/srp/srp_vfy.rs:336` | `SRP_user_pwd_free` | `adopt_plain_nullable` | P3: `id`/`info` `CRYPTO_strdup` @424/437; `user_pwd` `OwnedBuf::new` @356 | E0 plain | R1 `CRYPTO_free` (FILE,184-186) | **ESTABLISHED** |
| OB1-0388 | `src/srp/srp_vfy.rs:341` | `SRP_user_pwd_free` | `adopt_plain_nullable` | P3: `id`/`info` `CRYPTO_strdup` @424/437; `user_pwd` `OwnedBuf::new` @356 | E0 plain | R1 `CRYPTO_free` (FILE,184-186) | **ESTABLISHED** |
| OB1-0389 | `src/srp/srp_vfy.rs:408` | `SRP_user_pwd_set1_ids` | `adopt_plain_nullable` | P3: old `id`/`info` from `CRYPTO_strdup` @424/437 | E0 plain | R1 `CRYPTO_free` (FILE,214/215) | **ESTABLISHED** |
| OB1-0390 | `src/srp/srp_vfy.rs:413` | `SRP_user_pwd_set1_ids` | `adopt_plain_nullable` | P3: old `id`/`info` from `CRYPTO_strdup` @424/437 | E0 plain | R1 `CRYPTO_free` (FILE,214/215) | **ESTABLISHED** |
| OB1-0391 | `src/srp/srp_vfy.rs:423` | `SRP_user_pwd_set1_ids` | `adopt_plain_nullable` | P3: old `id`/`info` from `CRYPTO_strdup` @424/437 | E0 plain | R1 `CRYPTO_free` (FILE,214/215) | **ESTABLISHED** |
| OB1-0392 | `src/srp/srp_vfy.rs:436` | `SRP_user_pwd_set1_ids` | `adopt_plain_nullable` | P3: old `id`/`info` from `CRYPTO_strdup` @424/437 | E0 plain | R1 `CRYPTO_free` (FILE,214/215) | **ESTABLISHED** |
| OB1-0393 | `src/srp/srp_vfy.rs:577` | `SRP_VBASE_new` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(seed_key, FILE.as_ptr(), 292)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0394 | `src/srp/srp_vfy.rs:610` | `SRP_VBASE_free` | `adopt_plain_nullable` | P3: `seed_key` `CRYPTO_strdup` @578; `vb` `OwnedBuf::new` @556 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,307/308) | **ESTABLISHED** |
| OB1-0395 | `src/srp/srp_vfy.rs:615` | `SRP_VBASE_free` | `adopt_plain_nullable` | P3: `seed_key` `CRYPTO_strdup` @578; `vb` `OwnedBuf::new` @556 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,307/308) | **ESTABLISHED** |
| OB1-0396 | `src/srp/srp_vfy.rs:710` | `SRP_VBASE_init` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(*pp.add(DB_SRPID as usize), FILE.as_ptr(), 441)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0397 | `src/srp/srp_vfy.rs:853` | `SRP_gN_new_init` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup(ch, FILE.as_ptr(), 324)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0398 | `src/srp/srp_vfy.rs:892` | `SRP_gN_free` | `adopt_plain_nullable` | P2: `(*vb).gN_cache = OPENSSL_sk_new_null();` @566 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0399 | `src/srp/srp_vfy.rs:898` | `SRP_gN_free` | `adopt_plain_nullable` | P3: `gN_cache` from `OwnedBuf::new(size_of::<SrpGNCache>())` @839 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,342) | **ESTABLISHED** |
| OB1-0400 | `src/ssl/ssl_asn1.rs:664` | `i2d_SSL_SESSION` | `adopt_plain_nullable` | P2: `i2d_PUBKEY` @592 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,0) | **ESTABLISHED** |
| OB1-0401 | `src/ssl/ssl_cert_comp.rs:155` | `OSSL_COMP_CERT_new` | `adopt_plain_nullable` | P1: argument is the `CRYPTO_memdup(src, len)` result produced in `OSSL_COMP_CERT_from_compressed_data` @180 | E0 plain; extent exactly `len` (non-NULL implies `len >= 1`) | R1 `CRYPTO_free` (FILE_SEAM,0; authority `ssl_cert_comp.c:78`/`:145`) | **ESTABLISHED** |
| OB1-0402 | `src/ssl/ssl_cert_comp.rs:209` | `OSSL_COMP_CERT_free` | `adopt_plain_nullable` | P2: `(*cc).data = data.into_raw();` @158 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0403 | `src/ssl/ssl_cert_comp.rs:211` | `OSSL_COMP_CERT_free` | `adopt_plain_nullable` | P2: `let cc = ret.as_ptr().cast::<OsslCompCert>();` @156 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0404 | `src/ssl/ssl_cert_comp.rs:307` | `ssl_compress_one_cert` | `adopt_plain_nullable` | P2: `ssl_get_cert_to_compress(...,&mut cert_data)` @300 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,0) | **ESTABLISHED** |
| OB1-0405 | `src/ssl/ssl_conf.rs:1265` | `SSL_CONF_CTX_free` | `adopt_plain` | P3: `cctx` from `OwnedBuf::new_zeroed` @1221 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1120) | **ESTABLISHED** |
| OB1-0406 | `src/ssl/ssl_lib.rs:7946` | `SSL_add1_host` | `adopt_plain` | P1: `X509_VERIFY_PARAM_get1_ip_asc(param)` @7940 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,1175) | **ESTABLISHED** |
| OB1-0407 | `src/ssl/ssl_lib.rs:12122` | `SSL_add_expected_rpk` | `adopt_plain_nullable` | P1: `i2d_PUBKEY` @12115 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,8206) | **ESTABLISHED** |
| OB1-0408 | `src/ssl/statem/statem_clnt.rs:2622` | `tls12_construct_client_key_exchange` | `adopt_plain` | P2: out-param `let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey.as_ptr(), &mut pub_)` @2613 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0409 | `src/ssl/statem/statem_srvr.rs:2849` | `tls12_construct_server_key_exchange` | `adopt_plain` | P2: out-param `let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey.as_ptr(), &mut pub_)` @2840 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0410 | `src/ssl/statem/statem_srvr.rs:3043` | `construct_stateless_ticket` | `adopt_plain` | P1: argument is `CRYPTO_malloc(slen, core::ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0411 | `src/ssl/statem/statem_srvr.rs:3216` | `tls13_decrypt_ticket` | `adopt_plain` | P1: argument is `CRYPTO_malloc(ct_len + 16, core::ptr::null(), 0)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0412 | `src/ssl/t1_lib.rs:799` | `tls1_set_groups` | `adopt_plain_nullable` | P3: `*grpext` from `OwnedBuf::new` @789 `into_raw` in this function | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,0) | **ESTABLISHED** |
| OB1-0413 | `src/ssl/tls_srp.rs:68` | `srp_ctx_free` | `adopt_plain_nullable` | P3: `login`/`info` from `CRYPTO_strdup` @198/211 | E0 plain | R1 `CRYPTO_free` (ssl/tls_srp.c,37/38) | **ESTABLISHED** |
| OB1-0414 | `src/ssl/tls_srp.rs:74` | `srp_ctx_free` | `adopt_plain_nullable` | P3: `login`/`info` from `CRYPTO_strdup` @198/211 | E0 plain | R1 `CRYPTO_free` (ssl/tls_srp.c,37/38) | **ESTABLISHED** |
| OB1-0415 | `src/ssl/tls_srp.rs:197` | `ssl_srp_ctx_init_intern` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup((*src).login, c"ssl/tls_srp.c".as_ptr(), 115)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0416 | `src/ssl/tls_srp.rs:210` | `ssl_srp_ctx_init_intern` | `adopt_plain_nullable` | P1: argument is `CRYPTO_strdup((*src).info, c"ssl/tls_srp.c".as_ptr(), 119)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0417 | `src/ssl/tls_srp.rs:480` | `SSL_set_srp_server_param` | `adopt_plain_nullable` | P3: `info` from `CRYPTO_strdup` @492 | E0 plain | R1 `CRYPTO_free` (ssl/tls_srp.c,38) | **ESTABLISHED** |
| OB1-0418 | `src/ssl/tls_srp.rs:491` | `SSL_set_srp_server_param` | `adopt_plain_nullable` | P3: `info` from `CRYPTO_strdup` @492 | E0 plain | R1 `CRYPTO_free` (ssl/tls_srp.c,38) | **ESTABLISHED** |
| OB1-0419 | `src/store/store_lib.rs:887` | `OSSL_STORE_open_ex` | `adopt_plain` | P2: `let copy = CRYPTO_strdup(propq, ptr::null(), 0);` @886 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0420 | `src/store/store_lib.rs:1191` | `OSSL_STORE_find` | `adopt_plain` | P2: `// releases: `void *name_der = NULL` and `BIGNUM *number = NULL`.` @1077 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0421 | `src/txt_db/txt_db.rs:183` | `read_err` | `adopt_plain_nullable` | P3: `ret.index` from `CRYPTO_malloc_array` @258 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,FREE_INDEX) | **ESTABLISHED** |
| OB1-0422 | `src/txt_db/txt_db.rs:188` | `read_err` | `adopt_plain_nullable` | P3: `ret.qual` from `CRYPTO_malloc_array` @272 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,FREE_QUAL) | **ESTABLISHED** |
| OB1-0423 | `src/txt_db/txt_db.rs:193` | `read_err` | `adopt_plain_nullable` | P4: `ret` is `read_err`'s caller pointer from `CRYPTO_malloc` in `TXT_DB_read` @231 | E0 plain | R1 `CRYPTO_free` (FILE_SEAM,FREE_DB) | **ESTABLISHED** |
| OB1-0424 | `src/txt_db/txt_db.rs:769` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0425 | `src/txt_db/txt_db.rs:778` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0426 | `src/txt_db/txt_db.rs:800` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0427 | `src/txt_db/txt_db.rs:816` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0428 | `src/txt_db/txt_db.rs:827` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0429 | `src/txt_db/txt_db.rs:840` | `TXT_DB_free` | `adopt_plain_nullable` | P3: `index`/`qual` from `CRYPTO_malloc_array` @258/272; `db` from `CRYPTO_malloc` in TXT_DB_read; row fields caller-owned per the authority ABI | E0 plain | R1 `CRYPTO_free` (FILE_SEAM) | **ESTABLISHED** |
| OB1-0430 | `src/x509/dane.rs:481` | `dane_match_cert` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0431 | `src/x509/dane.rs:545` | `dane_match_cert` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0432 | `src/x509/dane.rs:788` | `dane_match_rpk` | `adopt_plain_nullable` | P2: `let mut i2dbuf = unsafe {` @480 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0433 | `src/x509/v3_conf.rs:605` | `do_ext_i2d` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0434 | `src/x509/v3_conf.rs:621` | `do_ext_i2d` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0435 | `src/x509/v3_conf.rs:657` | `do_ext_i2d` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0436 | `src/x509/v3_conf.rs:685` | `do_ext_i2d` | `adopt_plain_nullable` | P5: NULL placeholder; release is the authority no-op | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0437 | `src/x509/v3_conf.rs:882` | `v3_generic_extension` | `adopt_plain_nullable` | P5: NULL placeholders (the non-null arms are `OPENSSL_hexstr2buf`/`generic_asn1`) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0438 | `src/x509/v3_conf.rs:910` | `v3_generic_extension` | `adopt_plain_nullable` | P5: NULL placeholders (the non-null arms are `OPENSSL_hexstr2buf`/`generic_asn1`) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0439 | `src/x509/v3_conf.rs:920` | `v3_generic_extension` | `adopt_plain_nullable` | P5: NULL placeholders (the non-null arms are `OPENSSL_hexstr2buf`/`generic_asn1`) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0440 | `src/x509/v3_conf.rs:963` | `v3_generic_extension` | `adopt_plain_nullable` | P5: NULL placeholders (the non-null arms are `OPENSSL_hexstr2buf`/`generic_asn1`) | E0 plain | R1 `free(NULL)` | **ESTABLISHED** |
| OB1-0441 | `src/x509/v3_ncons.rs:563` | `print_nc_ipadd` | `adopt_plain_nullable` | P2: `let ip1 = unsafe { ossl_ipaddr_to_asc((*ip).data, len1) };` @557 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0442 | `src/x509/v3_ncons.rs:566` | `print_nc_ipadd` | `adopt_plain_nullable` | P2: `let ip2 = unsafe { ossl_ipaddr_to_asc((*ip).data.add(len1 as usize), len2) };` @559 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0443 | `src/x509/v3_ncons.rs:925` | `nc_email_eai` | `adopt_plain_nullable` | P2: `let baseptr = unsafe {` @911 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0444 | `src/x509/v3_ncons.rs:1086` | `nc_uri` | `adopt_plain_nullable` | P1: `CRYPTO_strndup((*uri).data,(*uri).length)` @1073 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_URI_COPY) | **ESTABLISHED** |
| OB1-0445 | `src/x509/v3_ncons.rs:1112` | `nc_uri` | `adopt_plain_nullable` | P1: `host` from `OSSL_parse_url` @1092 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_HOST) | **ESTABLISHED** |
| OB1-0446 | `src/x509/v3_ncons.rs:1116` | `nc_uri` | `adopt_plain_nullable` | P1: `host` from `OSSL_parse_url` @1092 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_HOST) | **ESTABLISHED** |
| OB1-0447 | `src/x509/v3_ncons.rs:1309` | `cn2dnsid` | `adopt_plain_nullable` | P1: `ASN1_STRING_to_UTF8(&mut utf8_value,cn)` @1298 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_UTF8_EMBEDDED) | **ESTABLISHED** |
| OB1-0448 | `src/x509/v3_ncons.rs:1499` | `NAME_CONSTRAINTS_check_CN` | `adopt_plain_nullable` | P2: `let idval = unsafe {` @1498 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0449 | `src/x509/v3_pci.rs:137` | `policy_grow` | `adopt_plain_nullable` | P3: `(*str_).data` from `CRYPTO_realloc` in this helper | E0 plain | R1 `CRYPTO_free` (FILE,free_line) | **ESTABLISHED** |
| OB1-0450 | `src/x509/v3_pci.rs:437` | `process_pci_value` | `adopt_plain_nullable` | P1: argument is `OPENSSL_hexstr2buf(valp, &raw mut val_len)` | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0451 | `src/x509/x509_req.rs:743` | `add_extensions_nid_tail` | `adopt_plain_nullable` | P2: `ASN1_item_i2d(...,&raw mut ext,...)` @733 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_EXT) | **ESTABLISHED** |
| OB1-0452 | `src/x509/x509_vpm.rs:543` | `int_x509_param_set1` | `adopt_plain_nullable` | P3: `*pdest` from previous `OwnedBuf::new_zeroed` @530 `into_raw` | E0 plain | R1 `CRYPTO_free` (FILE,0) | **ESTABLISHED** |
| OB1-0453 | `src/x509/x509_vpm.rs:571` | `X509_VERIFY_PARAM_set1_name` | `adopt_plain_nullable` | P3: old `name` from `CRYPTO_strdup` @576 | E0 plain | R1 `CRYPTO_free` (FILE,0) | **ESTABLISHED** |
| OB1-0454 | `src/x509/x509_vpm.rs:887` | `int_x509_param_set_hosts` | `adopt_plain_nullable` | P2: `let raw = CRYPTO_strndup(name, namelen, FILE.as_ptr(), 0);` @880 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0455 | `src/x509/x509_vpm.rs:1019` | `X509_VERIFY_PARAM_move_peername` | `adopt_plain_nullable` | P3: `to.peername` from `CRYPTO_strndup` at v3_utl.rs:2306/2347 | E0 plain | R1 `CRYPTO_free` (FILE,0) | **ESTABLISHED** |
| OB1-0456 | `src/x509/x509spki.rs:146` | `NETSCAPE_SPKI_b64_encode` | `new` (safe) | P1: DER block from the `i2d_NETSCAPE_SPKI` sizing pass @133 | E: checked `4*((der_len+2)/3)+1`, the encoder's exact extent; the old `2*der_len` under-sized `der_len = 1, 2, 4` | R1 `CRYPTO_free` (FILE_NAME,LINE); §17 overrun corrected | **ESTABLISHED** |
| OB1-0457 | `src/x509/x_name.rs:1023` | `X509_NAME_print` | `adopt_plain_nullable` | P2: `let b = unsafe { X509_NAME_oneline(name, ptr::null_mut(), 0) };` @1015 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |
| OB1-0458 | `src/x509/x_pubkey.rs:684` | `x509_pubkey_ex_d2i_ex` | `adopt_plain_nullable` | P1: `CRYPTO_memdup(in_saved,publen)` @669 | E0 plain | R1 `CRYPTO_free` (FILE,LINE_FREE_TMPBUF) | **ESTABLISHED** |
| OB1-0459 | `src/x509/x_pubkey.rs:1077` | `X509_PUBKEY_set` | `adopt_plain_nullable` | P2: out-param `let encoded = unsafe { OSSL_ENCODER_to_data(ectx, &raw mut der, &raw mut derlen)` @1070 | E0 plain | R1 plain `CRYPTO_free` | **ESTABLISHED** |