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
`cargo test --lib` (must pass; the established baseline is **1196** passed
and the 9 adversarial probes are `#[ignore]`d and run separately via
`scripts/adv-probe.sh`).

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

## Receipts

Each landed batch records a receipt (template `RECEIPT.template.md`) so a fresh
session can resume from Git + the receipt without reconstructing reasoning.

## Canonical next action — Safe-33 continuation

**Branch:** `integrate/safe-c33`
**Last observed HEAD:** `d45c08a34aeda13b0307de579e94ae2cfc592b87`
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
   The most recent reported library baseline is **1196** tests. Do not accept unexplained test loss. Check available memory before builds.
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
