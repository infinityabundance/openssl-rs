# Safe-33 unsafe→safe conversion — progress ledger

Authority: this file records *landed* conversion batches on `integrate/safe-c33`.
A batch is "landed" only when its local gate is green in the court container and
it is merged. The full Phase-25 forensic regeneration stays deferred until the
conversion campaign lands (see CLOSURE.md); the numbers below are the frozen
Phase-25 atlas baseline, so they are a *lower bound* on real progress (converted
modules still report their seam's `CRYPTO_*` sites).

Frozen atlas baseline: **2420** allocation sites (`artifacts/phase25/ownership-planes.json`).

Local gate for every batch (court container, 8 GB cap):
`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --lib` (must be 1183/1183).

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

Converted files (union of stage/p25/* files): ~64 of the ~1600-site remaining queue.
Interior allocation-site reduction is larger than the atlas delta because each
converted module re-hosts several hand-written sites into one seam.

## Standing residuals (not yet addressed)

- **Member buffers**: `#[repr(C)]` struct fields with cross-function ownership
  (e.g. `PKCS7.ctx.propq`, `SSL_CONF_CTX` prefix/cert_filename,
  `SslSession` ext_* buffers). These need a distinct owned handle type
  (a `strdup`-backed C-string handle) — the **member-buffer unit**.
- **Compound destructors**: objects freed by a multi-step body rather than one
  release (MlKemKey/MlDsaKey/MlxKey/ProvMlxKemGenCtx, RSA_METHOD).
- **Interior representation rewrites** (the deeper class, like
  `src/runtime/sparse_array.rs`): raw graph traversal replaced by owned nodes.

## Next queue (by remaining atlas sites)

provider/mod.rs, srp/srp_vfy.rs, apps/mac.rs, runtime/{conf/def.rs,mem.rs,
confmod/mod.rs,rcu.rs}, async/async.rs, http/http_client.rs, decoder_pkey.rs,
x509/{x_pubkey.rs,v3_ncons.rs}, asn1/{bio_asn1.rs,asn_mime.rs,text.rs},
provider/{exchange.rs,ml_kem_kmgmt.rs,encode_key2any.rs}, crmf/*, cmp/*, ts/*,
ct/*, txt_db/*, property/store.rs, rand/rand_lib.rs, engine/eng_dyn.rs,
ssl/{ssl_rsa.rs,tls_srp.rs,ssl_cert_comp.rs,ssl_ciph.rs,...},
then the member-buffer unit.
