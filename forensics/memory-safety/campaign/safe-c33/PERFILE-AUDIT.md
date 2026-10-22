# Per-file obligation audit — pointer

**Purpose.** This file was the cumulative per-file obligation audit for the
`safe-c33` campaign. Its content has been split into one record per audited file
so the audit can grow without one unbounded document. The split preserved every
section, table row, residual and candidate-identity statement; only the
inter-section `---` separators and their surrounding blank padding were removed.

**Records live in [`per-file/`](per-file/).** Each record is named by replacing
`/` with `__`:

| File | Record |
|---|---|
| `src/evp/digest.rs` | [`per-file/src__evp__digest.rs.md`](per-file/src__evp__digest.rs.md) |
| `src/evp/pkey_ctx.rs` | [`per-file/src__evp__pkey_ctx.rs.md`](per-file/src__evp__pkey_ctx.rs.md) |
| `src/provider/cipher.rs` | [`per-file/src__provider__cipher.rs.md`](per-file/src__provider__cipher.rs.md) |
| `src/evp/cipher_ctx.rs` | [`per-file/src__evp__cipher_ctx.rs.md`](per-file/src__evp__cipher_ctx.rs.md) |
| `src/provider/kdf.rs` | [`per-file/src__provider__kdf.rs.md`](per-file/src__provider__kdf.rs.md) |
| `src/evp/pkey.rs` | [`per-file/src__evp__pkey.rs.md`](per-file/src__evp__pkey.rs.md) |

**Index.** The reusable template, the lifecycle/state definitions, the per-file
counts and the machine-readable pointer live in
[`PERFILE-INDEX.md`](PERFILE-INDEX.md) and
[`atlas-refresh/perfile-index.json`](atlas-refresh/perfile-index.json).

> **Non-discharge statement.** These records are file-level obligation audits,
> **not `SAFETY_DISCHARGED`**. A record enumerates and attributes a file's
> production unsafe sites; it does not establish whole-file safety, does not
> discharge its residual obligations, and is not an `INDEPENDENTLY_CHECKED`
> result. A file graduates only through the AGENTS.md §7 dependency-closure and
> independent-evidence gates. Campaign progress is **761 of 761 PARTIAL files
> audited (0 remaining)**; no file in this set has graduated.

The old cumulative content was split without modification. To compare against
the pre-split document, use the campaign commit that introduced this pointer; the
records are the authoritative copies of each section.

## Addendum — 2026-10-18, `integrate/safe-c33` (medium-severity sweep closures)

### Exported self-copy refusal (`EVP_CIPHER_CTX_copy`, `CMAC_CTX_copy`)

These are **AGENTS.md §17 UB-elimination divergences**. The authority's
`EVP_CIPHER_CTX_copy(out, out)` resets (and, in the provider arm, `memset`s) the
destination before `*out = *in`, then calls `in->cipher->dupctx`, which dereferences
the now-NULL `cipher`; `CMAC_CTX_copy(out, out)` reaches the same nested call. There
is no defined authority success to preserve. Both entries now return 0 at entry
when `out == in` and leave the source untouched. Tests:
`copying_a_context_onto_itself_is_refused` and
`copy_refuses_the_identity_and_leaves_the_source_alone`.

### `src/provider/cipher.rs` — legacy `CipherDestroy` zero-validity witness

All eight legacy implementers (`ProvCastCtx`, `ProvBlowfishCtx`, `ProvIdeaCtx`,
`ProvSeedCtx`, `ProvRc2Ctx`, `ProvRc4Ctx`, `ProvDesCtx`, `ProvRc4HmacMd5Ctx`)
have the same body: `ossl_cipher_generic_reset_ctx(ptr.cast())`, and nothing
else. The authority's eight `*_freectx` functions are likewise exactly
`ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx)` followed by
`OPENSSL_clear_free(ctx, sizeof(*ctx))` (e.g. `cipher_cast5.c:28-33`,
`cipher_rc4_hmac_md5.c:67-72`); `OwnedCtx::Drop` performs the block release.

The reset body is `if (ctx != NULL && ctx->alloced) { OPENSSL_free(ctx->tlsmac);
ctx->alloced = 0; ctx->tlsmac = NULL; }` (`ciphercommon.c.in:193-200`). On the
all-zero block that `OwnedCtx::new` can drop, `alloced == 0`, so the free is not
reached and `tlsmac` is never dereferenced; every releaser the body reaches on a
constructed context is NULL-tolerant. There is no unconditional dereference and
no path that releases the enclosing block. Executed witness:
`every_legacy_cipher_destroy_body_is_zero_valid` calls each body directly on the
zero state, asserts `alloced == 0` and `tlsmac == NULL`, then lets `Drop` run the
body a second time.

### `src/provider/cipher.rs` — `SyncCell` invariant witness

`SyncCell<[OsslAlgorithm; 140]>` stores the filtered `deflt_ciphers` table. The
sole writer is `fill_exported_ciphers`, reached only through
`EXPORTED_CIPHERS_INIT: Once`; `cache_exported_ciphers` and every reader
(`exported_ciphers`) enter the same `Once`, so the write is serialised and
publication carries a release/acquire edge. After completion the cell is never
written again; readers only read the static pointers. The `Sync` impl is now for
the concrete array rather than generic `T`, because only this module can witness
the discipline. This closes the previous comment-only claim: two concurrent
provider constructions can each reach the init function before either enters the
provider store, so provider ordering alone was not a memory-model guarantee.

### `src/provider/cipher.rs` — SIV failure injection

`aes_siv_dupctx` takes the CBC/CTR references before `ossl_siv128_copy_ctx`. The
new `siv_dupctx_failure_releases_only_the_refs_it_acquired` uses an unarmed
source `EVP_CIPHER_CTX` (`cipher == NULL`), which makes
`ossl_siv128_copy_ctx` return 0 at its `EVP_CIPHER_CTX_copy` step after both
references were taken. Dummy dynamic ciphers with refcount 1 are used as the
two fetched methods: the test asserts both counts return to 1 (not 0), so a
missing or duplicate release is observable without a process-global allocator
hook. The test reaches the arm through `siv_dupctx`, the real dispatch entry.

### `src/ec/pmeth.rs` — `pkey_ec_copy` failure release

The authority duplicates the group, key and UKM into `dst->data` and returns 0
at the first failure without releasing the earlier members; its caller
`EVP_PKEY_CTX_dup` clears `rctx->pmeth` before `EVP_PKEY_CTX_free` (`pmeth_lib.c:608-610`),
so the method cleanup is skipped and the partially built context leaks. The transcription now
calls `pkey_ec_cleanup(dst)` on each failure return, which releases exactly the
acquisitions made so far and clears `dst->data` (so a later cleanup is a no-op).
`copy_failure_releases_the_partially_built_destination` fails the UKM
`CRYPTO_memdup` with `i32::MAX` after the group duplicate, then asserts the slot
is NULL and that `pkey_ec_cleanup` is a no-op. This is a recorded divergence
from the authority's leak.

### Gate and probe status for this addendum

Court: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`
and `cargo test --lib -- --test-threads=4` (1320 passed, 22 ignored, 0 failed).
The committed Phase 8 probe binaries (not rebuilt for this batch) were executed:
`rt_cipher_mem_probe` produced 382 authority observations and **zero** diffs;
`rt_cipher_probe` produced 7291 observations and **one** residual,
`defltwrap.pad21` (authority hash vs candidate `0`). That residual is the
pre-existing D561 encrypt-extent refusal for a padded key-wrap update whose
provider `outsize` is the EVP-computed `inl + blocksize`; it is not touched by
this addendum and is recorded rather than silently re-baselined.

## Addendum — 2026-10-18, reference-count sentinel sweep (uncommitted review fix)

### Decision D562 — checked increments refuse instead of wrapping

The shared gate `runtime::refcount` now applied to `ENGINE` and the converted
families refuses a zero, negative, destroying, or `i32::MAX` count without
changing it. The authority increments first and answers failure (`zero -> 1`,
answer 0; `MAX -> MIN` on the atomic arm). Every positive live-count increment
keeps the authority's relaxed ordering and answer 1. This is a §17
UB-mechanism elimination recorded in `docs/DECISIONS.md` D562; the
`EVP_SKEY_up_ref` unit test now asserts the unchanged count.

### Families

Sentinel added where the last-reference body reaches a callback: `ENGINE`,
`EVP_PKEY`, `EVP_SKEY`, `DH`, `DSA`, `RSA`, `EC_KEY`, `BIO`, `DSO`, and the
provider methods (`EVP_CIPHER`/`MD`/`KDF`/`MAC`/`RAND`/`KEYMGMT`/`SKEYMGMT`/
`SIGNATURE`/`ASYM_CIPHER`/`KEYEXCH`/`KEM`, `OSSL_ENCODER`/`DECODER`,
`OSSL_STORE_LOADER`, `EVP_RAND_CTX`). `X509_STORE`, `SSL`, `SSL_CTX` and
`SSL_SESSION` already had it. No sentinel is added where the body has no
callback (`OsslCompCert`, `ECX_KEY`, `KDF_DATA`, `MAC_KEY`) or where the free
path is not refcount-gated (`Cert`, a unique owner); the provider's own
`refcnt` returns before teardown on any non-zero post-decrement, so a repeated
release cannot re-run teardown.

### Constructor counts

Every converted constructor publishes a count of 1 before the object escapes:
`ENGINE_new`, `EVP_PKEY_new`, `evp_skey_alloc`, `dh_new_intern`, `dsa_new_intern`,
`rsa_new_intern`, `ossl_ec_key_new_method_int`, `BIO_new_ex`, `new_method` (DSO),
and each provider-method constructor (`evp_cipher_new`, `evp_md_new`,
`evp_kdf_new`, `evp_mac_new`, `evp_rand_new`, `evp_rand_ctx_new`, `keymgmt_new`,
`skeymgmt_new`, `evp_signature_new`, `evp_asym_cipher_new`, `evp_keyexch_new`,
`evp_kem_new`, `ossl_encoder_new`, `ossl_decoder_new`, `new_loader`). No
converted object starts at 0.

### Evidence

Re-entrancy tests cover the ex-data path for `ENGINE`, `DH`, `DSA`, `RSA`,
`EC_KEY`, `EVP_PKEY` and `BIO`, the BIO `callback_ex` path, the DSO `finish`
hook, the `EVP_SKEY` provider key destructor, and an `EVP_CIPHER` provider
teardown re-entering its own free. `engine_list_add`'s refusal returns to
`ENGINE_add`, which owns and releases the engine lock on every path.

Court: fmt, clippy `-D warnings`, library tests and all 22 adversarial probes
are rerun for this addendum.

## Addendum — 2026-10-18, `integrate/safe-c33` (OB-4a contract-analyst fixes)

Rows are per changed file. **None is `SAFETY_DISCHARGED` or
`INDEPENDENTLY_CHECKED`**: each records a fixed defect and the witness that
now guards it. States use the §21 lifecycle; every row remains `CONTRACTED`.

| File | Defect | Authority | Fix / mechanism | Witness | State |
|---|---|---|---|---|---|
| `src/asn1/utl.rs` | `enc_save` freed the cached block, left the freed pointer in the field, and returned 0 on a refused replacement allocation, so a later `enc_free` double-freed and `enc_restore` copied from released memory. | `crypto/asn1/tasn_utl.c:172-178` assigns the allocation result; the crate publishes the post-free `(NULL, 0, modified=1)` state before the fallible allocation, avoiding the authority's stale-length restore path. | Failure-atomic field publication; release remains the same `OwnedBlock::from_raw` `Drop` at `(FILE, LINE)`. | `asn1::utl::adv_probe::refused_encoding_malloc_leaves_a_null_member_and_safe_restore` | CONTRACTED |
| `src/ssl/ssl_sess.rs` | `SSL_SESSION_set1_hostname` / `set1_alpn_selected` / `set1_ticket_appdata` released the member and then duplicated the caller's pointer; a caller passing the getter's own result read freed memory. | `ssl/ssl_sess.c:1083/1088`, `:1134/1140`, `:1484/1490` (authority UB). D563. | Duplicate before `clear`; release stays at the authority coordinates (1083/1134/1484); refused duplicate clears to the authority's post-failure state. | `ssl::ssl_sess::adv_probe::self_aliasing_session_setters_copy_before_clearing` | CONTRACTED |
| `src/ssl/s3_lib.rs` | The `SSL_CTRL_SET_TLSEXT_HOSTNAME` arm released the member, then called `strlen`/`CRYPTO_strdup` on the caller's pointer. | `ssl/s3_lib.c:4029/4043` (authority UB). D563. | Validate and duplicate before `clear`; the release stays at 4029 and the raise sites stay at 4040/4044. | `ssl::s3_lib::adv_probe::self_aliasing_sni_control_copies_before_clearing` | CONTRACTED |
| `src/ssl/ssl_rsa.rs` | `SSL_CTX_use_serverinfo_ex` reallocated the member and then copied/validated through a caller pointer that could name the released incumbent. | `ssl/ssl_rsa.c:839-844` (authority UB). D564. | Detect overlap with the live incumbent, tee the source before `realloc`, and use the tee for the copy and the second validation. | `ssl::ssl_rsa::adv_probe::self_aliasing_serverinfo_is_teed_before_realloc` | CONTRACTED |
| `src/ssl/ssl_rsa.rs` | `extension_length + 4` could wrap before an `extension_length`-byte copy. | `ssl/ssl_rsa.c:775-778` (unchecked C `+`). | `checked_add`; overflow answers the allocation-refusal outcome (0). | `ssl::ssl_rsa::checked_arithmetic_tests::extension_append_length_rejects_usize_max` | CONTRACTED |
| `src/asn1/d2i.rs` | `total + 1` for the joined error buffer could wrap. | `crypto/asn1/tasn_dec.c` error-text path (unchecked C `+`). | `checked_add`; overflow simply appends no text. | `asn1::d2i::tests::error_buffer_length_rejects_usize_max` | CONTRACTED |
| `src/asn1/tasn_prn.rs` | `strlen(tmp) + 3` for the radix prefix could wrap. | `crypto/asn1/tasn_prn.c` integer render path (unchecked C `+`). | `checked_add`; overflow returns NULL and releases `tmp`. | `asn1::tasn_prn::tests::radix_buffer_length_rejects_usize_max` | CONTRACTED |
| `src/ssl/ssl_asn1.rs`, `src/ssl/ssl_lib.rs` | `MemberBufSlot::store` claimed the allocation was exactly `len`, but the ASN.1 adoption sites transfer `ASN1_STRING::data`, allocated as `len + 1`; the precondition was false. | `ssl/ssl_asn1.c` adoption arms; `asn1/string.rs`, `asn1/d2i.rs`. | Contract weakened to "at least `len`, writable for `len`" with the free/realloc rationale; adoption now rejects `ASN1_STRING_FLAG_EMBED`, negative lengths, and NULL-with-nonzero-length (all unreachable). | `ssl::ssl_asn1::tests::adopt_octet_string_rejects_embed_and_negative_length` | CONTRACTED |

The OB-4a batch does **not** graduate any consumer family and does not touch the
OB-4b slot-unification/typestate work or the `PropqSlot` copies.
