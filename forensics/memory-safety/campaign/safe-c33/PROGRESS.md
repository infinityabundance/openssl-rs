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

Converted files (union of stage/p25/* files): ~51 files across 19 conversion batches plus the adoption-soundness fix.

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

## Progress measurement (five dimensions — see AGENTS.md §19)

Not one percentage; report each axis honestly.

1. **Ownership reconstruction** — 20 conversion batches across ~51 files; the
   reusable adoption-pattern set (OwnedBuf / OwnedCtx+`CtxDestroy` / partial-
   construction `Raw*` owners) is now sound (adoption ctors are `unsafe fn`).
2. **Safe-interior coverage** — *not yet comprehensively measured*; the sparsest
   structural conversions so far are sparse_array and the X.509 policy tree.
3. **Discharged safety obligations** — local gate green per batch; full
   `SAFETY_DISCHARGED` enumeration awaits the seal-point regeneration.
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
- **P0 open**: `src/asn1/owned.rs` — replace unchecked allocation-size
  multiplication with `checked_mul` + OpenSSL failure semantics.
- **P0 open**: `src/x509/pcy_lib.rs` `tree_levels` — tie the mutable level-array
  borrow to the tree owner, not a caller-chosen lifetime.
- **P0 open**: `src/x509/pcy_node.rs` `Node::parent_mut` — make exclusive parent
  access derivable from the graph's mutation model.
- **P1 open**: `CipherDestroy`/`CtxDestroy` implementer contract (make the trait
  obligation explicit/`unsafe`); `src/ffi/mod.rs` post-panic state rules;
  secret-bearing-context classification.

## Receipts

Each landed batch records a receipt (template `RECEIPT.template.md`) so a fresh
session can resume from Git + the receipt without reconstructing reasoning.
