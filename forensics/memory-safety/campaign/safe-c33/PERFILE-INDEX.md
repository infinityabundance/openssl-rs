# Per-file obligation audit — index

**Purpose.** This is the entry point for the `safe-c33` per-file unsafe-site
audit. Each audited file has one record under `per-file/`, named by replacing
`/` with `__` (`src/evp/digest.rs` → `per-file/src__evp__digest.rs.md`). A record
contains the file's complete audit section — candidate identity, group table,
residual register, unclassified operations, highest-risk groups, and any
post-census delta — exactly as it appeared in the former cumulative
`PERFILE-AUDIT.md`.

> **Non-discharge statement.** Every record is a file-level obligation audit,
> **not `SAFETY_DISCHARGED`**. A record enumerates and attributes a file's
> production unsafe sites. It does not establish whole-file safety, does not
> discharge the residual obligations it lists, and is not an
> `INDEPENDENTLY_CHECKED` result. A file graduates only through the AGENTS.md §7
> dependency-closure and independent-evidence gates.

**Campaign progress: 9 of 761 PARTIAL files have full group records; the
mechanism-contract sweeps M1–M31 name 225 files in their structured `files`
arrays, and their union with the nine full records is 268 files. That leaves
600 of the 868 census files unaudited (`PARTIAL`); 92 files are `ZERO_UNSAFE`
and 15 are `BOUNDARY_COVERED`.** The 761 denominator is the `PARTIAL` file
population in `ATTRIBUTION.md`; it is not a count of files that have graduated.
The nine full records cover 6,252 production unsafe sites in 2,949 groups. The
sweeps are obligation checks over the known owner/slot/member-buffer mechanisms,
not the full `D###` enumeration.

**Reconciliation note (2026-10-19).** A free-text `src/...rs` extraction over
this file and every `atlas-refresh/*.json` returns 869 paths because
`next_batch`, `skipped`, `files_not_run` and NOT_RUN prose also name files. Only
each sweep's `.files` array (plus this file's audited record tables) counts as
audited. The naive extraction leaves only eight non-census runtime model/probe
files and no ordinary file, which is why the previous next-position lists were
stale. See §35 for the exact counts and the M31 set.

## 1. Reusable template

| Field | Meaning |
|---|---|
| `file` | Project-relative source path. |
| `candidate SHA` | The source identity the census was generated from, plus the audit HEAD if they differ. |
| `census counts` | Total operations, production operations, test-only operations, and the file hash from `atlas-refresh/unsafe-census.json`. |
| `group id` | Stable per-file identifier, `D001`-`Dnnn`. |
| `lines` | Every census line in the group, with the group count. |
| `kind` | Census kind code: `UF`, `UB`, `FC`, `HR`, `EC`, `UI`. |
| `ABI/export class` | `safe fn`, `unsafe fn`, or `unsafe extern "C"`, with `exported` or `not exported`. Only an exported FFI entry can carry a caller/ABI precondition. |
| `operation` | The actual raw/FFI operation(s) at those lines. |
| `contract` | The validity contract relied on: SAFETY comment, owner/slot type, FFI ABI, or `CtxDestroy` contract. |
| `establishment` | Who establishes the precondition: this code, an in-file caller, or an external C/ABI/provider contract. |
| `dependency group` | `D###` ids of groups whose obligations this row inherits, or `—` if none. |
| `state` | `CONTRACTED` (contract stated, not established), `ESTABLISHED` (precondition established by code or an identified caller/ABI contract), or `UNATTRIBUTED` (no caller-side establishment or boundary attribution). |
| `evidence needed` | Exactly what would be required before the group can become `INDEPENDENTLY_CHECKED`. |
| `residuals` | Obligations that remain after the group's current contract, including callback reentrancy, raw member pointers, and caller-asserted lengths. |

Group identifiers are per-file (`D###`, `C###`, `CC###`, `K###`, `P###`); the
same identifier can appear in different records for different files. Dependency
references are local to the record's file.

## 2. Lifecycle and state definitions

The state vocabulary maps onto the AGENTS.md §21 lifecycle:

```text
UNKNOWN -> CONTRACTED -> ESTABLISHED -> INDEPENDENTLY_CHECKED -> DISCHARGED
```

- **`CONTRACTED`** — a validity contract is stated, but the precondition is not
  established by this code or by an identified caller/ABI contract. A contract
  comment is not discharge.
- **`ESTABLISHED`** — the precondition is established in code, by an in-file
  caller, by a local owner/type invariant, or by a stated external ABI/provider
  contract. Establishment is not independent verification.
- **`UNATTRIBUTED`** — no caller-side establishment and no boundary attribution
  exists. This includes self-asserted `unsafe impl`/`unsafe trait` destructor
  obligations and safe functions that hide raw-pointer preconditions.
- **`INDEPENDENTLY_CHECKED`** — requires an independent reviewer, exact source
  and build identity, a contract witness per precondition, and a runtime/static
  check that fires on a deliberate violation. **No record claims this state.**
- **`DISCHARGED`** — the AGENTS.md §7 result: every remaining unsafe operation
  has an explicit validity contract, every precondition is established by a
  caller or external ABI contract, and no safe-Rust caller can cause UB through
  the safe interfaces. **No record claims this state.**

The `reviewer` column below records the adversarial-review outcome stated in the
campaign ledger (`PROGRESS.md`, subphases 67–78). A ledger `PASS` is a review of
the audit and its fixes, **not** an `INDEPENDENTLY_CHECKED` result and **not**
`SAFETY_DISCHARGED`.

## 3. Records

| File | Candidate source SHA-256 | Production sites | Groups | `ESTABLISHED` | `CONTRACTED` | `UNATTRIBUTED` | Record | Reviewer verdict |
|---|---|---:|---:|---:|---:|---:|---|---|
| `src/cms/cms_env.rs` | `07b9fccbf26c6a8726ae37244ee852d4c090b63cebe9f6d000c5d36ec0d84c56` | 549 | 127 | 0 | 123 | 4 | `per-file/src__cms__cms_env.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/evp/digest.rs` | `28af1f53701dac53e8ee08f1fcb15e3c0f6d1f5030006c91463966952d17c541` | 711 | 254 | 95 | 158 | 1 | `per-file/src__evp__digest.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/evp/pkey_ctx.rs` | `878af2a77b124f0293a506fa82222fdf270c3f7fae392228a7b02604c58d80c0` | 1,024 | 462 | 178 | 277 | 7 | `per-file/src__evp__pkey_ctx.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/provider/cipher.rs` | `098e33d4b766599d9b11760dfb9fdb41312ee07a2e797cb348ea293f42326c38` | 1,098 | 930 | 65 | 848 | 17 | `per-file/src__provider__cipher.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/evp/cipher_ctx.rs` | `9b8f322d2cfd65395ec585ae47978a9195e829cf175f8801e3e653dd3976b94b` | 672 | 181 | 35 | 129 | 17 | `per-file/src__evp__cipher_ctx.rs.md` | PASS (not `INDEPENDENTLY_CHECKED`) |
| `src/provider/kdf.rs` | `182b0b81dbf345f31b880ce824ae928bf92715909f153cf34560fc82cff22512` | 716 | 541 | 20 | 519 | 2 | `per-file/src__provider__kdf.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/evp/pkey.rs` | `b0d36d170c5ae823960c96d1d5b35c703c0306c222c4470f4202793cbbdccfd4` | 568 | 238 | 1 | 236 | 1 | `per-file/src__evp__pkey.rs.md` | PASS (not `INDEPENDENTLY_CHECKED`) |
| `src/x509/v3_addr.rs` | `fd18ebfe54c23b86747da6a0500f8f231508c0101d06d48cfbf9d29c52b046e2` | 498 | 123 | 38 | 80 | 5 | `per-file/src__x509__v3_addr.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| `src/hpke/mod.rs` | `14eb47fae70128bfd4bd96b77d086b5b28d29fea3e5c013b62ac600bc0747405` | 416 | 93 | 17 | 69 | 7 | `per-file/src__hpke__mod.rs.md` | PASS after correction (not `INDEPENDENTLY_CHECKED`) |
| **Total** | — | **6,252** | **2,949** | **449** | **2,439** | **61** | 9 records | — |

### Record notes

- The candidate SHA is the `Source SHA-256` recorded in each record's candidate
  identity. The census candidate for all nine is
  `c09eef8b94ce068c92557d9940decf50e8413c8c`; the per-record *audit HEAD* differs
  because the audits landed at different campaign commits. `src/evp/pkey.rs`,
  `src/cms/cms_env.rs` and `src/hpke/mod.rs` are the files whose audited source
  differs from the census (the `SeamFile` deltas recorded in their §1; `pkey.rs`
  also has a post-census section). For `src/hpke/mod.rs` the delta is 43
  insertions and 9 deletions (net +34 lines), including two failure-path
  `CRYPTO_free` → `CRYPTO_clear_free` changes; its candidate SHA is the audited
  source.
- `src/evp/digest.rs` carries the reusable template in its record (§1). The
  template is reproduced above so it remains discoverable without reading a
  record.
- `src/x509/v3_addr.rs` was audited at HEAD `7c4e8dde6`; its source hash matches
  the census exactly and `git diff c09eef8..HEAD` is empty, so its census lines
  are its HEAD lines.
- `src/provider/cipher.rs` and `src/evp/pkey.rs` include post-census source-delta
  sections. Those sections are part of their records and are not summarized
  away here.
- Counts in this table are transcribed from each record's own "Census totals"
  and "Group state summary"; they are checked against the group rows by
  `PERFILE-INDEX` verification (every row appears exactly once per file).
- `src/hpke/mod.rs` was audited at HEAD `2e7ac013c`; its source hash differs from
  the census because of the post-census `SeamFile` and cleanse changes recorded
  in its §7. It has 11 test-only operations, excluded from its 416 production
  sites.

## 3a. Mechanism-contract sweep M1 — 2026-10-18

**Source identity:** `integrate/safe-c33` at `258bcca51` plus the uncommitted
worktree state (test-only OB-4b lifecycle model and the §3 repairs listed below).
The census counts quoted in `ATTRIBUTION.md` remain bound to candidate
`c09eef8b94ce068c92557d9940decf50e8413c8c`; this sweep read HEAD source.

**Scope:** the mechanism-contract procedure for ordinary files — classify the
applicable RC-1 / OB-1 `OwnedBuf` / OB-2 `OwnedStr` / OB-3 `OwnedCtx`–`RawCtx` /
OB-4 member-slot mechanisms, check caller preconditions and unusual transitions,
repair genuine defects, run FAST for the changed units. This is **not** the full
per-file `D###` group record: every row remains `CONTRACTED` at file level, no
row is `INDEPENDENTLY_CHECKED` or `SAFETY_DISCHARGED`, and the full group census
for these twelve files is `NOT_RUN` (queued).

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/params/mod.rs` | OB-1 `OwnedBuf` (7 sites), extent accounting | **D1 fixed (STOP-class):** `written + data_size` could wrap past the capacity check and let `copy_nonoverlapping` write out of bounds; the helper is reachable from `provider/kdf.rs:1558/5281/7290`. Now `checked_add`. **D2 fixed:** `sz + terminator` allocation extent now `checked_add`. Two negative-control tests added. |
| `src/pkcs7/pk7_doit.rs` | OB-1 `OwnedBuf` new/adopt/into_raw, cleansing lengths | No defect: lengths come from EVP sizing/output calls; every failure path drops the owned block; adoption provenance is the seam. |
| `src/x509/v3_utl.rs` | OwnedBlock/OwnedCtx, `CRYPTO_strndup` adoption, parser bounds | **D6 fixed:** `strlen + 3` allocation extent now `checked_add` (§3). Parser bounds (`ipv6_cb` even-`total` invariant) verified against `v3_utl.c`. |
| `src/pem/pvkfmt.rs` | OB-1 `OwnedBuf::take`, extent sums | **D3–D5 fixed:** `keylen + 8`, `keylen + saltlen`, and the two `i2b_PVK` `outlen` sums now use `checked_add` and refuse on overflow. All were bounded at the call site; the bounds are now local, not hidden. |
| `src/cms/cms_sd.rs` | OB-1 `OwnedBuf` adopt/new/into_raw, two `from_raw_parts` | No defect: the `mlen != os->length` guard establishes both slice extents; every adopted block has one owner. |
| `src/x509/x509_vfy.rs` | OB-3 `OwnedCtx`, OB-4 `CStrSlot`, verify callbacks | No code defect. `X509_STORE_CTX_free`'s cleanup callback is a retained authority-compatible reentrancy edge (raw pointer, no `&mut` across the call); recorded, not discharged. |
| `src/evp/bio_enc.rs` | local unsafely-implemented `CtxDestroy`+`OwnedCtx`, BIO callbacks | No defect: allocation/release coordinates and the cleanse split match `bio_enc.c:68/73/97`; callbacks receive a raw BIO only. |
| `src/store/store_lib.rs` | OB-3 `OwnedCtx`/`CtxDestroy`, stack free thunk | **D7 (documentation):** the `OSSL_STORE_INFO_new*` safety contracts now state that ownership transfers only on success; the authority's allocation-refusal leak is preserved, not hidden. |
| `src/x509/x_pubkey.rs` | OB-4 `CStrSlot` (`propq`), OB-1 adoption, `OwnedCtx`-style new/free | No reachable defect. `x509_pubkey_set0_libctx` still clears before duplicating, but the member is private, has no getter, and every caller passes a different object's string; recorded as a latent pattern (copy-before-clear would change the allocator transcript). |
| `src/x509/v3_asid.rs` | OB-2 `OwnedStr::adopt` (4 sites) | No defect: `i2s_ASN1_INTEGER`/`CRYPTO_strdup` provenance is this crate's seam; each adopted string is released once at the authority line. |
| `src/asn1/asn_mime.rs` | OB-1 `OwnedBuf` new/adopt/into_raw (commit and `err:` tails) | No defect: commit transfers name/value/header exactly once; the shared error tail adopts each slot and frees even NULL. |
| `src/rsa/pmeth.rs` | OB-3 `OwnedCtx`/`CtxDestroy`, OB-1 OAEP label | No memory-safety defect. The authority's partial-copy leak on a refused `BN_dup`/`CRYPTO_memdup` is preserved and now recorded (not UB). |

**New unsafe assumptions: none.** The repairs are checked safe arithmetic and
documentation; no new `unsafe` operation, adoption, release site, allocator
coordinate, `#[repr(C)]` layout or exported symbol changed.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M1.json`](atlas-refresh/mechanism-sweep-M1.json).

## 3b. Mechanism-contract sweep M2 — 2026-10-18

**Source identity:** `integrate/safe-c33` at `d7265a503` plus the uncommitted
worktree state (the `crmf_lib.rs` repair and the `ts_rsp_sign.rs` contract
repair). The census counts quoted in `ATTRIBUTION.md` remain bound to candidate
`c09eef8b94ce068c92557d9940decf50e8413c8c`; this sweep read HEAD source.

**Scope:** the same mechanism-contract procedure as M1 — classify the applicable
RC-1 / OB-1 `OwnedBuf` / OB-2 `OwnedStr` / OB-3 `OwnedCtx`–`RawCtx` / OB-4
member-slot mechanisms, check caller preconditions and unusual transitions,
repair genuine defects, run FAST for the changed units — over the next ten
ordinary files in the queue (including two parser boundaries and one
secret-bearing decryption path). This is **not** the full per-file `D###` group
record: every row remains `CONTRACTED` at file level, no row is
`INDEPENDENTLY_CHECKED` or `SAFETY_DISCHARGED`, and the full group census for
these ten files is `NOT_RUN` (queued).

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/cmp/cmp_msg.rs` | OB-3 item-owned values, `OPENSSL_sk_push` ownership, `set0`/`set1` transfers, `X509_up_ref`/`X509_chain_up_ref` | No defect: every success/failure arm has one owner; `local_crm`/`rd`/`resp`/`cert_status` are nulled after a successful push and freed on the failure arms; `enc_privkey`'s recipient stack is up-ref'ed and released after `ossl_cms_sign_encrypt`. |
| `src/ssl/t1_trce.rs` | attacker-controlled trace cursor `(p,len)`, extension walk, per-message printers | No defect: every dereference is preceded by the authority's own bounds check; verified `ssl_print_hexbuf`, `ssl_print_version`, `ssl_print_random`, `ssl_print_signature`, the extension ADB arms, hello/keyex/certificate/cert-request/ticket printers and `SSL_trace`. Divergence retained: `trace_list` refuses `vlen == 0` (the C `% 0` is UB) and `ssl_print_raw_public_key` tolerates a NULL `sc->ctx`; the QUIC arm is unmodeled as the module records. |
| `src/cmp/cmp_asn.rs` | hand-expanded ASN.1 templates/ADB, `SyncAux` read-only aux, OB-2 `propq` | No defect: every template offset/size matches the in-file `#[repr(C)]` struct field order (0/8/16/… and the 8-byte union arm), including `CMP_ITAV`'s ADB at offset 8 and `CMP_PKIBODY`'s 27 choices. `SyncAux` is never written (same established pattern as `asn1/p8_pkey.rs`). `ossl_cmp_msg_set0_libctx` clears `propq` before duplicating, exactly as the authority (latent self-alias; no getter). |
| `src/ts/ts_rsp_sign.rs` | OB-3 `TS_RESP_CTX` zalloc/free, OB-1 ESS scratch encodings, `set1` duplicates, callbacks | **M2-D2 fixed (contract):** `ts_resp_set_gentime_with_precision` did not state that a non-NULL `asn1_time` is consumed (freed) on failure, matching the authority's `ASN1_GENERALIZEDTIME_free(asn1_time)`. The old wording let a caller double-free. Retained: `TS_RESP_CTX_set_def_policy` frees before `OBJ_dup` exactly as the authority (latent self-alias, no getter). |
| `src/cms/cms_smime.rs` | custom CAdES chain owner `OwnedChainArray`, stack ownership, BIO chain teardown | No defect: `checked_mul` allocation, index-checked `slot`/`chain`, one `sk_X509_pop_free` per filled slot and one `CRYPTO_free` at `:529`, ordered before the `untrusted`/`crls` releases exactly as the authority. |
| `src/crmf/crmf_lib.rs` | OB-1 `OwnedBuf` conditional cleansing, secret classification, error-path ownership | **M2-D1 fixed (high, secret):** three error paths released the decrypted symmetric key with a plain `CRYPTO_free` although the authority's `end:` calls `OPENSSL_clear_free(ek, eksize)` at `crmf_lib.c:846` — the decrypt-failure arm, the malformed-IV arm, and the output/context allocation-failure tail. All three now select the cleansing release. **M2-D3 fixed (medium, fidelity):** decrypt-init/sizing/allocation failures fell through into IV/output work instead of the authority's `goto end`; they now return through the tail. |
| `src/provider/encode_key2any.rs` | OB-1 new/adopt/`into_raw`, OB-3 `OwnedCtx`/`CtxDestroy`, `CRYPTO_memdup`, passphrase cleanse | No defect: `key_to_p8info`/`key_to_pubkey` transfer the DER block only on success and release it on every failure; `OPENSSL_cleanse(kstr, klen)` matches the authority; the context destroy body releases only the passphrase data and cipher. Retained: the authority-faithful `str` leak when `X509_PUBKEY_set0_param` refuses (a leak, not UB). |
| `src/cmp/cmp_client.rs` | OB-2 `OwnedStr`, callback storage `CbPtr`, `set0_newCert` | No defect: every `transmute` reverses a setter that stored the same function-pointer signature; `set0_newCert` refuses only on a NULL context and the caller then frees the certificate. Retained: transfer/certConf callbacks are application-controlled reentrancy edges under the authority's callback contract. |
| `src/cmp/cmp_vfy.rs` | OB-1 `adopt_plain_nullable`, constant-time PBMAC compare, release coordinates | No defect: `verify_PBMAC` compares lengths before the full-length `CRYPTO_memcmp`; each adopted `X509_NAME_oneline`/`i2s_ASN1_OCTET_STRING` block has one handle and the authority's own release line. |
| `src/asn1/d2i.rs` | `OwnedBlock`/`Collected`, realloc collector, parser cursor, checked sums, `ASN1_STRING_set0` handoff | No defect in the collector/`check_tlen`/`d2i_ex_primitive` paths: the resulting-length test matches the authority, `hdrlen + plen` is reached only after `ASN1_get_object` has cleared its error bit, the collect extent is checked, and `take_raw`/`adopt` leaves one owner across the content codec. |

**New unsafe assumptions: none.** The repairs are a secret-release selection, error-path returns
and one safety-contract statement; no new `unsafe` operation, adoption, release site, allocator
coordinate, `#[repr(C)]` layout or exported symbol changed.

**Defects:**

| id | file | severity | class | fix / witness |
|---|---|---|---|---|
| M2-D1 | `src/crmf/crmf_lib.rs` | high (secret cleansing) | three post-allocation error arms used plain `CRYPTO_free` for the decrypted symmetric key; authority uses `OPENSSL_clear_free(…, eksize)` at `:846` | `set_clear(true)` before each drop (post-fix lines 1984, 2030, 2051); witness: OB-1 conditional-cleanse model tests + `cms::cms_env` analogous probe; no fixture exercises these exact arms (`NOT_RUN`) |
| M2-D2 | `src/ts/ts_rsp_sign.rs` | low (contract) | `ts_resp_set_gentime_with_precision` omitted the authority's free-on-failure ownership transfer for a non-NULL `asn1_time` | safety contract now states the consumption (post-fix 1857); review only |
| M2-D3 | `src/crmf/crmf_lib.rs` | medium (error-path fidelity) | decrypt-init/sizing/`CRYPTO_malloc` failures fell through into later work instead of `goto end` | early returns through the authority's tail (post-fix 1904-1910, 1922-1932, 1949-1958); full library suite |

**Gates (final source):** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D warnings`
PASS; `cargo test --lib -- --test-threads=1` **1571 passed / 0 failed / 26 ignored**;
`cargo test --lib -- --test-threads=4` **1571 passed / 0 failed / 26 ignored**;
affected adversarial probes **2/2** (`cms::cms_env::tests::adv_probe_decrypted_key_release_cleanses_before_free`,
`ssl::adv_alloc::adv_probe::cleansed_free_instrument_detects_residue`). A first filtered
`ts::` invocation reported 17 failures; the identical rerun and both full runs passed, so it is
recorded as a non-reproducible environment observation, not a gate result.

**Deferred / NOT_RUN:** full `D###` records for these ten files; a direct runtime witness for the
three `crmf` error arms; targeted Miri/ASan (BOUNDARY/SEAL); dependency-graph regeneration against
the exact candidate (BATCH checkpoint after commit). `src/ssl/statem/statem_srvr.rs` (rank 31) is
**NOT_RUN**: deferred to its own callback/handshake boundary batch.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M2.json`](atlas-refresh/mechanism-sweep-M2.json).

## 3c. Mechanism-contract sweep M3 — 2026-10-18

**Source identity:** `integrate/safe-c33` at `d8153a349` plus the uncommitted
worktree state (the `conf/def.rs` extent-arithmetic repair and the
`cmp_server.rs` error-path cleanup). The census counts quoted in
`ATTRIBUTION.md` remain bound to candidate
`c09eef8b94ce068c92557d9940decf50e8413c8c`; this sweep read HEAD source.

**Scope:** the same mechanism-contract procedure as M1/M2 — classify the
applicable RC-1 / OB-1 `OwnedBuf` / OB-2 `OwnedStr` / OB-3 `OwnedCtx`–`RawCtx` /
OB-4 member-slot mechanisms, check caller preconditions and unusual transitions,
repair genuine defects, run FAST for the changed units — over the next eleven
ordinary files in the queue (CONF, the X.509 object/store/extension layer, ASN.1
primitives, the EVP signature method, the CMP server, UI and PKCS#7). This is
**not** the full per-file `D###` group record: every row remains `CONTRACTED` at
file level, no row is `INDEPENDENTLY_CHECKED` or `SAFETY_DISCHARGED`, and the
full group census for these eleven files is `NOT_RUN` (queued).

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/runtime/conf/def.rs` | OB-1 `OwnedBuf` new/adopt/into_raw, `BUF_MEM` ownership, allocator seam | **M3-D1 fixed (low):** four allocation extents now use checked arithmetic — `strlen(from)+1`, the expansion `newsize = strlen(p)+buf->length-(e-from)`, the joined include path `strlen+strlen+2`, and the directory entry `pathlen+namelen+2`. Ownership, release order and error sites unchanged. |
| `src/x509/x_all.rs` | ASN.1 stream forwarding, `simple_get_asn1` response BIO | No defect: every face forwards the caller contract; `simple_get_asn1` decodes then `BIO_free`s at `x_all.c:130`. |
| `src/asn1/prim.rs` | `OwnedBlock` PCTX/SCTX, `ASN1_OBJECT` reuse/free, integer sizing, `a2d_ASN1_OBJECT` heap slot | No defect: the reuse-vs-realloc arm, the conditional `object_free` on failed malloc, and the `ASN1_STRING_set0` handoff match `a_object.c`/`a_int.c`; no added unsafe operation. |
| `src/x509/x509_lu.rs` | OB-3 `OwnedCtx`/`RawLookup`/`RawStore`, three `CtxDestroy` bodies, RC-1 store refcount, stack ownership | No defect: partial-construction releases match `X509_LOOKUP_new`/`X509_STORE_new`; the destroy bodies never release the enclosing block; `x509_store_add` frees only on a failed push. |
| `src/evp/signature.rs` | OB-3 `OwnedCtx`/`CtxDestroy`, RC-1, provider callback dispatch | No defect: the zalloc/up-ref failure arm frees at the authority coordinate without assigning `prov`; `EVP_SIGNATURE_free` uses the shared sentinel; callbacks receive a raw object. |
| `src/x509/v3_crld.rs` | five `#[repr(C)]` item layouts, ADB/templates, `dpn_cb`, `v2i` ownership | No defect: assertion offsets and every template offset/tag/item match `v3_crld.c`; all error tails release `point`/`gen`/`gens` exactly once; `DIST_POINT_set_dpname` reproduces `i ? 0 : 1`. |
| `src/cmp/cmp_server.rs` | OB-3 `OwnedCtx`/`RawCtx`/`CtxDestroy`, application callback reentrancy | **M3-D2 fixed (low):** `process_cert_request` now runs the authority's `err:` tail on the callback-null and `set_option`-failure arms, releasing `si`, the certificate and the two stacks; the pre-callback badPOP return is unchanged. Callbacks remain raw-pointer reentrancy edges. |
| `src/x509/v3_cpols.rs` | ASN.1 item groups, `policy_section`/`notice_section`/`r2i_certpol` | No defect: every push-failure and parse-failure tail releases the partially built value once, matching `v3_cpols.c`. |
| `src/ui/ui_lib.rs` | OB-3 `OwnedCtx`/`RawCtx` for `UI`/`UI_STRING`/`UI_METHOD`, OB-2 `OwnedStr` dup prompts, callback phases | No defect: zero-state destroy bodies hold; dup-prompt ownership transfers only on a successful push and is released otherwise; `UI_process` calls the method hooks through raw pointers with no live borrow. |
| `src/pkcs7/pk7_lib.rs` | ownership transfers, `set0`/`set1`, up-refs, stack pushes, `OwnedCStr` propq | No defect in the checked paths: signer/digest/certificate/CRL/recipient adoption and up-ref-on-success match `pk7_lib.c`; failed pushes release the up-ref. |
| `src/x509/v3_purp.rs` | OB-2 `OwnedStr`, OB-3 `OwnedCtx`/`RawPurpose`/`CtxDestroy` | No defect in the purpose-row mechanisms: the strdup-into-existing-row error arm leaves the names installed exactly as the authority, and the fresh-row arm releases names and block. The full `ossl_x509v3_cache_extensions` path is not line-audited in this sweep. |

**New unsafe assumptions: none.** The repairs are checked safe arithmetic and an
error-path restructure; no new `unsafe` operation, adoption, release site,
allocator coordinate, `#[repr(C)]` layout or exported symbol changed.

**Defects:**

| id | file | severity | class | fix / witness |
|---|---|---|---|---|
| M3-D1 | `src/runtime/conf/def.rs` | low (defensive) | four unchecked length sums used as allocation extents (AGENTS.md §3) | `checked_add`/`checked_sub` with the authority's failure semantics (post-fix 563, 706, 1390, 1885); conf load tests + full suite |
| M3-D2 | `src/cmp/cmp_server.rs` | low (leak / fidelity, not UB) | two post-callback failure arms returned before the authority's `err:` cleanup | labelled reply block breaks to the shared tail (post-fix 607/649/675/703/738); full suite; error-injection witness `NOT_RUN` |

**Gates (final source):** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D warnings`
PASS; `cargo test --lib -- --test-threads=1` **1571 passed / 0 failed / 26 ignored**;
`cargo test --lib -- --test-threads=4` **1571 passed / 0 failed / 26 ignored**; no
affected adversarial probe is defined in the touched units (the `cmp_server`
zero-state sweep and the CONF load tests ran in the full suite).

**Deferred / NOT_RUN:** full `D###` records for these eleven files; the
callback-failure error-injection witness; targeted Miri/ASan (BOUNDARY/SEAL);
dependency-graph regeneration against the exact candidate (BATCH checkpoint after
commit); `src/ml_dsa/encoders.rs` (rank 43) is **NOT_RUN** because its file-local
secure-memory `OwnedBuf` (`CRYPTO_secure_malloc`/`CRYPTO_secure_clear_free`) and
secret-bearing key/signature serialisation are a genuinely new boundary, deferred
to its own boundary batch.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M3.json`](atlas-refresh/mechanism-sweep-M3.json).

## 3d. Mechanism-contract sweep M4 — 2026-10-18

**Source identity:** `integrate/safe-c33` at `38cf6d5a6` plus the uncommitted
worktree state (the two `rand_lib.rs` release-coordinate repairs and the
`provider/digest.rs` SHAKE get-parameter repair with its regression test). The
census counts quoted in `ATTRIBUTION.md` remain bound to candidate
`c09eef8b94ce068c92557d9940decf50e8413c8c`; this sweep read HEAD source.

**Scope:** the same mechanism-contract procedure as M1–M3 — classify the
applicable RC-1 / OB-1 `OwnedBuf` / OB-2 `OwnedStr` / OB-3 `OwnedCtx`–`RawCtx` /
OB-4 member-slot mechanisms, check caller preconditions and unusual transitions,
repair genuine defects, run FAST for the changed units — over the next twelve
ordinary files in the queue (X.509 extensions, RSA `ameth`, RNG, decoders, CMP
context and the provider DRBG/digest rows). This is **not** the full per-file
`D###` group record: every row remains `CONTRACTED` at file level, no row is
`INDEPENDENTLY_CHECKED` or `SAFETY_DISCHARGED`, and the full group census for
these twelve files is `NOT_RUN` (queued).

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/x509/v3_san.rs` | OB-2 `OwnedStr` for IP/OID scratch, stack reserved-push, `GENERAL_NAME` union arms, `v2i` ownership | No defect: `v2i_GENERAL_NAMES`'s reserved push and the `copy_issuer`/`copy_email` error tails match `v3_san.c`; `do_othername`/`do_dirname` release their partial values once. |
| `src/rsa/ameth.rs` | OB-1 `OwnedBuf` plain/cleansed, `X509_PUBKEY`/PKCS#8 `set0` handoff, PSS parameter ownership | No defect: `rsa_priv_encode` cleanses at `rklen`; every `ossl_rsa_pss_to_ctx` failure tail frees the decoded params; the import/export ownership arms match `rsa_ameth.c`. |
| `src/x509/v3_timespec.rs` | ASN.1 item lifecycle, `#[repr(C)]` layouts, printer pointer walks | No defect: layouts and offsets match `x509v3.h`; the authority's own duplicate `%.*s` print in the start-only arm is reproduced; the unit owns no allocation. |
| `src/rand/rand_lib.rs` | OB-3 `OwnedCtx`/`CtxDestroy`, OB-2 `OwnedStr`, `RawGlobal` partial init, thread-local DRBG references | **M4-D1 fixed (low):** two provider-name releases used the duplicate's line (`113`) where the authority's `OPENSSL_free` is at `112` (`set_random_provider_name`) and `1090` (`RAND_set1_random_provider`, NULL arm); both now release at the exact authority coordinates. The primary/public/private reference chains and `set0` slot displacement match. |
| `src/x509/v3_conf.rs` | OB-1 `OwnedBuf`, `v2i`/`s2i`/`r2i` ownership, `do_ext_i2d` error tail, extension stacks | No defect: the DER owner is emptied on the octet-string handoff and the error tail frees once; `X509V3_EXT_add_nconf_sk`'s SKID/AKID reorder, replace and push-failure arms match `v3_conf.c`. |
| `src/evp/rand.rs` | OB-3 `OwnedCtx` plus a context-local refcount, provider dispatch, lock/call/unlock | No defect: `EVP_RAND_CTX_new`'s failure arm releases the constructor's context, the block and the parent reference exactly once; the generate chunking and `get_ctx_params`/`nonce` asymmetric defaults match. |
| `src/decoder_lib.rs` | OB-3 `OwnedCtx`/`RawCtx`, decoder-instance reference chain, provider callbacks | No defect: the half-built instance destructor is per-field, the dup arms release only what they acquired, and `decoder_process` frees its mem BIO and restores `start_input_type` on every tail. |
| `src/cmp/cmp_ctx.rs` | OB-3 `OwnedCtx`/`CtxDestroy`, secret cleansing, up-refs and stacks | No defect: `secretValue` is cleansed at its actual extent on replacement and destruction; up-ref-then-replace and the `set1_certs`/`set0` arms match `cmp_ctx.c`. **Residual:** the generated setters record the allocator seam at line `0` and the short `crypto/cmp/cmp_ctx.c` path (the file's Phase-12.4 convention), not authority-exact; unchanged, no UB. |
| `src/x509/v3_ncons.rs` | OB-1 `OwnedBuf` (`ipadd`, `strndup`), ASN.1 item groups, matching loops | No defect: every adoption/free line matches `v3_ncons.c` (786/790/798/799/805/806/830, 678/728, 382/430, 247/248); the `permitted`/`excluded` prefix reads stay in bounds. |
| `src/ec/ecx_meth.rs` | OB-1 plain/cleansed, `EVP_PKEY_assign` transfers, key set/get buffers | No defect: the publication encoders cleanse at the exact extents, `validate_ecx_derive`'s NULL checks match, and the sign/verify lengths and ownership arms match `ecx_meth.c`. |
| `src/provider/rand.rs` | local unsafe `DrbgCtx`/`OwnedCtx`/`OwnedRaw`, secure allocations, DRBG state machine | No defect: secure clear-free sizes, `*_free` member order and the `dfree` error path match; generate chunking, reseed triggers and parent-chain locking match `drbg.c`/`drbg_{ctr,hash,hmac}.c.in`. |
| `src/provider/digest.rs` | OB-3-style local `OwnedCtx` (`zalloc`/`malloc`/`clear_free`), digest dispatch, SHA3/SHAKE ctx params | **M4-D2 fixed (low, compatibility):** `shake_get_ctx_params` refused a request naming both `xoflen` and `size`; the authority's generated get-decoder maps them to separate fields and sets both. It now fills every located alias; regression test `provider::digest::sha3::tests::shake_get_ctx_params_sets_both_aliases`. The set path still refuses both aliases (authority raises `PROV_R_REPEATED_PARAMETER`; this crate returns 0 without an error site, which is not generated for SHA3). |

**New unsafe assumptions: none.** The repairs are two release coordinates and one
compatibility branch; no new `unsafe` operation, adoption, release site,
`#[repr(C)]` layout or exported symbol changed. The only new test is inside the
`sha3` module and uses only already-public context fields.

**Defects:**

| id | file | severity | class | fix / witness |
|---|---|---|---|---|
| M4-D1 | `src/rand/rand_lib.rs` | low (allocator-seam fidelity; not UB) | two releases of `random_provider_name` recorded line 113 instead of the authority's free lines 112 / 1090 | `L_PROVIDER_NAME_SET_FREE`/`L_PROVIDER_NAME_SET1_FREE`; full suite |
| M4-D2 | `src/provider/digest.rs` | low (compatibility; not UB) | a SHAKE `get_ctx_params` request carrying both aliases was refused; the authority sets both | fill every located alias; `sha3::tests::shake_get_ctx_params_sets_both_aliases` + full suite |

**Gates (final source):** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D warnings`
PASS; `cargo test --lib -- --test-threads=1` **1572 passed / 0 failed / 26 ignored**;
`cargo test --lib -- --test-threads=4` **1572 passed / 0 failed / 26 ignored**. No
affected adversarial probe is defined in the two changed units (the seam
repair has no behaviour change; the SHAKE get repair is covered by the new
unit test); the non-affected probe suite is **NOT_RUN** at this level.

**Deferred / NOT_RUN:** full `D###` records for these twelve files; targeted
Miri/ASan (BOUNDARY/SEAL); dependency-graph regeneration against the exact
candidate (BATCH checkpoint after commit); a differential SHAKE `get_ctx_params`
court (BOUNDARY/SEAL). `src/runtime/bio/bss_dgram.rs` (rank 59) is skipped to its
own BIO-callback/reentrancy batch (with `bss_dgram_pair.rs`/`bss_conn.rs`), and
`src/ssl/ssl_sess.rs` (rank 61) is deferred to the SSL session ownership/
reference-count boundary batch; `src/ssl/statem/statem_clnt.rs` (rank 50) is the
TLS state-machine batch. `src/ml_dsa/encoders.rs`, `src/ssl/ssl_lib.rs` and
`src/ssl/statem/statem_srvr.rs` remain untouched (explicitly deferred).

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M4.json`](atlas-refresh/mechanism-sweep-M4.json).

## 3e. Mechanism-contract sweep M5 — 2026-10-18

**Candidate:** `integrate/safe-c33` source HEAD `a8d3661ba` (working tree; not
committed). **Level:** FAST, then **STOP**.

| file | rank | mechanisms | result |
|---|---:|---|---|
| `src/cms/cms_lib.rs` | 62 | OB-4 `CmsPropqSlot`, FFI ABI, stack/refcount ownership | no defect |
| `src/evp/cipher.rs` | 63 | OB-3 `OwnedCtx`/`RawCtx`, `CtxDestroy`, refcount, provider dispatch | no defect |
| `src/provider/mac.rs` | 64 | OB-3 `OwnedCtx`/`OwnedRaw`, unsafe `MacDestroy`, OB-1 `OwnedBuf`, secret cleansing | no defect; Poly1305/SipHash no-cleanse is the authority's documented asymmetry |
| `src/evp/pem_bridge.rs` | 67 | PemBuf seam owner, FFI ABI, C-string parsing, `EVP_CIPHER_INFO` | **M5-D1 (fixed): OOB write** |

**M5-D1 — `src/evp/pem_bridge.rs:578` (pre-fix `load_iv` call at `:586`).**
`PEM_get_EVP_CIPHER_INFO` took `ivlen` from `EVP_CIPHER_get_iv_length` and passed
it to `load_iv`, which zeroes and fills that many bytes into the fixed
`EVP_CIPHER_INFO::iv[EVP_MAX_IV_LENGTH]` array. A caller-registered method
(`EVP_CIPHER_meth_new` + `EVP_CIPHER_meth_set_iv_length` > 16 + `EVP_add_cipher`)
is reachable through `EVP_get_cipherbyname`, so the write could exceed 16 bytes.
Severity: **high (memory-safety, authority-inherited)**. Fix: refuse
`ivlen > EVP_MAX_IV_LENGTH` before `load_iv`; the resolved cipher remains in
place and the zeroed IV is untouched. This is a deliberate divergence from the
C authority's out-of-bounds write. Witness:
`evp::pem_bridge::tests::cipher_info_refuses_an_iv_longer_than_the_fixed_array`
(new) and the four existing `evp::pem_bridge::tests`; 5 passed / 0 failed.

**Skipped to a boundary batch (NOT_RUN):** `src/runtime/bio/bss_dgram_pair.rs`
(rank 65), `src/runtime/bio/bss_conn.rs` (66) — BIO callback/ownership
boundaries; `src/provider/file_store.rs` (69) — loader callback boundary.
`src/rsa/object.rs` (68) was queued next and is **NOT_RUN** because the STOP
condition halted the sweep.

**BATCH:** `cargo fmt` PASS; clippy `--all-targets -D warnings` PASS; library
serial 1573 passed / 0 failed / 26 ignored. Threaded run 1 was 1557 passed /
16 failed / 26 ignored, all `runtime::secure` global secure-heap init tests;
the rerun was 1573 passed / 0 failed / 26 ignored, and a run with only the new
test skipped was 1572 passed / 0 failed / 26 ignored. `runtime::secure::tests`
alone threaded was 15 passed / 0 failed. The first-run failures are a
pre-existing parallel secure-heap isolation race (other modules allocate secure
memory without the module's lock); record it as a test-isolation batch item,
not as an M5 regression.

**M5-D1 boundary control (ASan venue):** sensitivity canary diagnosed its
deliberate use-after-free; the temporary pre-fix revert produced
`stack-buffer-overflow` in `load_iv` (`src/evp/pem_bridge.rs:404`) and the test
aborted; the restored fixed source passed under ASan (1/1). Guard restoration
is byte-identical to the recorded fix and no temporary marker remains.

**Deferred / NOT_RUN:** deterministic threaded suite (secure-heap isolation),
independent boundary review and broader M5-D1 probes (BOUNDARY),
dependency-graph regeneration (BATCH checkpoint after commit). Full `D###`
records are also pending.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M5.json`](atlas-refresh/mechanism-sweep-M5.json).

## 3f. Mechanism-contract sweep M6 — 2026-10-18

**Candidate:** `integrate/safe-c33` source HEAD `b43570606` (working tree; not
committed). **Level:** FAST, then **BATCH** (including one targeted ASan
boundary control for M6-D2).

| file | rank | mechanisms | result |
|---|---:|---|---|
| `src/rsa/object.rs` | 68 | OB-3 `RawCtx`/`CtxDestroy`, refcount, member ownership, `set0` transactions | **M6-D1 (fixed): leak + stale reduction** |
| `src/pkcs7/pk7_smime.rs` | 70 | OB-1 `OwnedBuf`, BIO chains, PKCS7/X509 stack ownership, FFI ABI | no defect |
| `src/evp/kdf.rs` | 72 | OB-3 `OwnedCtx`, OB-1 `OwnedBuf` (cleansing), refcount, provider dispatch | no defect |
| `src/evp/mac.rs` | 73 | OB-3 `OwnedCtx`, OB-1 `OwnedBuf`, refcount, provider dispatch | no defect; `D-MAC-DUPCTX-NULL-1` is the recorded safe divergence |
| `src/ffc/params_generate.rs` | 75 | `SeedBuf`, `BN_CTX` pools, digest scratch extents, RNG paths, secret key material | **M6-D2 (fixed): stack-buffer-overflow** |
| `src/ec/lib.rs` | 76 | local `OwnedCtx`/unsafe `CtxDestroy`, `OwnedBlock`, ex_data, method dispatch | no defect |

**M6-D1 — `src/rsa/object.rs:638`, `:1513` (pre-fix).** The module
documentation and `RSA_free`/`ossl_rsa_set0_pss_params` carried a D348-era
reduction: `r->pss` was said to be unreachable because its only writer's only
authority caller was an unlanded unit. The writer's caller chain has since
landed (`src/rsa/backend.rs`'s `ossl_rsa_param_decode`, reached from the PKCS#8
decoder rows in `src/provider/decode_der2key.rs`), so a live PSS key can carry
`r->pss`. `RSA_free` then leaked the ASN.1 value, and `ossl_rsa_set0_pss_params`
leaked a replaced value. Severity: **medium (resource leak; ownership
obligation, not UB)**. Fix: restore both authority
`RSA_PSS_PARAMS_free` calls. Witness:
`rsa::object::tests::set0_pss_params_replaces_the_old_value_and_rsa_free_releases_it`
(new) plus the 14 existing tests (15 passed / 0 failed).

**M6-D2 — `src/ffc/params_generate.rs:791-792` (pre-fix).**
`generate_q_fips186_2` declared its two digest scratch arrays as
`[u8; SHA256_DIGEST_LENGTH]` (32 bytes), where the authority declares
`unsigned char buf2[EVP_MAX_MD_SIZE]` and `md[EVP_MAX_MD_SIZE]` (64). The digest
is caller-named through `OSSL_PKEY_PARAM_FFC_DIGEST` (including via
`EVP_PKEY_fromdata`/paramgen), so `EVP_Digest` writes `EVP_MD_get_size(evpmd)`
bytes — 64 for SHA-512 — into 32 bytes. Severity: **high (memory-safety; stack
out-of-bounds write introduced by the transcription, reachable on the legacy
186-2 generate/validate path)**. Fix: restore `EVP_MAX_MD_SIZE`, matching the
authority. Witness:
`ffc::params_generate::tests::the_186_2_q_generator_accepts_a_digest_wider_than_sha256`
(new).

**M6-D2 boundary control (ASan venue):** the new test passes on the fixed
source (1 passed / 0 failed; leak detection disabled because the provider/object
registries are deliberately process-lifetime allocations, not test residuals);
the temporary pre-fix revert produced `stack-buffer-overflow` (`WRITE of size
8`) in `generate_q_fips186_2` at `src/ffc/params_generate.rs:832` and the test
aborted. The restored source is byte-identical to the recorded fix and passes
again under ASan.

**Skipped to a boundary batch (NOT_RUN):** `src/runtime/bio/iolib.rs`
(rank 71) is the BIO callback/reentrancy dispatch layer; `src/runtime/obj.rs`
(rank 74) is the `OBJ_NAME` callback registry (destructor/comparator/do-all
callbacks, some invoked under the registry mutex). `src/provider/file_store.rs`
(rank 69), `src/runtime/bio/bss_dgram_pair.rs` (65) and
`src/runtime/bio/bss_conn.rs` (66) remain deferred from M5.

**BATCH:** `cargo fmt --all -- --check` PASS; clippy `--all-targets -D warnings`
PASS; library serial 1575 passed / 0 failed / 26 ignored; threaded run 1575
passed / 0 failed / 26 ignored (no secure-heap isolation failure this time).
Focused: `rsa::object::tests` 15/0, `ffc::params_generate::tests` 5/0.

**Deferred / NOT_RUN:** independent boundary review of the fixed ownership
sites and wider PSS-decoder replay (BOUNDARY); dependency-graph regeneration
(BATCH checkpoint after commit); deterministic repeat of the threaded suite.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M6.json`](atlas-refresh/mechanism-sweep-M6.json).

## 3g. Mechanism-contract sweep M7 — 2026-10-18

**Candidate:** `integrate/safe-c33` source HEAD `bbd0804f0` (working tree; not
committed). **Level:** FAST, then **BATCH**, plus a targeted ASan
out-pointer contract control for M7-D1.

| file | rank | mechanisms | result |
|---|---:|---|---|
| `src/ec/curve448.rs` | 77 | fixed-extent FFI buffer contracts, `EVP_MD_CTX`/`EVP_MD` ownership, scalar cleansing | no defect |
| `src/cmp/cmp_genm.rs` | 78 | `OPENSSL_sk_*` ownership, ITAV transfer, `OwnedStr`, X509 checks | **M7-D1 (fixed): type-confused out-pointer** |
| `src/srp/srp_vfy.rs` | 79 | OB-1 `OwnedBuf` adoption, SRP object/`BIGNUM` ownership, encode/decode extents | no defect |
| `src/evp/e_aes.rs` | 80 | `EVP_CIPHER` ctrl/do-cipher contract, GCM IV heap owner, mode copy repointing | no defect |
| `src/cms/cms_kari.rs` | 81 | OB-1 cleansed output, `EVP_PKEY_CTX` ownership, ASN.1 set1 transfers | no defect |
| `src/ts/ts_rsp_verify.rs` | 82 | `OwnedBlock`/`OwnedStr`, PKCS7/X509 stack and chain ownership | no defect |
| `src/pem/pem_pkey.rs` | 83 | `SecureName`/`SecureData`, decoder/legacy fallback, BIO push/pop | no defect |
| `src/ts/ts_conf.rs` | 84 | X509/BIO/`NCONF`/stack ownership, `X509V3_parse_list` rows | no defect |

**M7-D1 — `src/cmp/cmp_genm.rs:409-424` (pre-fix).**
`OSSL_CMP_get1_caCerts` called `ossl_x509_add_certs_new(out_stack as *mut
*mut OpenSslStack, ...)`, passing the fresh `OPENSSL_STACK` handle where the
helper's contract requires the address of a writable stack slot (`&out_stack`).
`ossl_x509_add_cert_new` then read the stack object's first field as a slot and
inserted through it, using the stack's element array as a second `OPENSSL_STACK`:
a type-confused write into the stack object. Severity: **high (memory-safety;
heap corruption / UB on every successful `caCerts` GENM reply)**. The authority
calls `X509_add_certs(*out, certs, flags)`, so the repair restores that exact
call (and drops the now-unused internal import).

**M7-D1 boundary control (ASan venue, `nightly-2026-10-05`,
`-Zsanitizer=address -Zbuild-std`):** a temporary test-only canary exercised
the helper with the correct slot and with the removed handle-as-slot shape. The
correct shape passes (`1 passed / 0 failed`); the removed shape faults under
ASan (`SEGV on unknown address 0xfffffffffffffff8`, `WRITE`, through
`OPENSSL_sk_free` after the corrupted stack object). The canary was removed
before the BATCH run. Replaying the production `OSSL_CMP_get1_caCerts` path
requires a live GENM exchange and is **NOT_RUN**.

**Skipped to a boundary batch (NOT_RUN):** none of the eight files presented a
new reusable unsafe boundary; the previously deferred callback/ownership files
remain deferred.

**BATCH:** `cargo fmt --all -- --check` PASS; clippy `--all-targets -D warnings`
PASS; library serial 1575 passed / 0 failed / 26 ignored; threaded run 1575
passed / 0 failed / 26 ignored. Focused: `ec::curve448` 2/0, `evp::e_aes` 1/0,
`pem::pem_pkey` 3/0.

**Deferred / NOT_RUN:** independent boundary review of M7-D1 and a real
GENM/caCerts differential replay (BOUNDARY); dependency-graph regeneration
(BATCH checkpoint after commit).

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M7.json`](atlas-refresh/mechanism-sweep-M7.json).

## 3h. Mechanism-contract sweep M8 — 2026-10-18

**Candidate:** `integrate/safe-c33` source HEAD `8fd9d3a79` (working tree; not
committed). **Level:** FAST, then **BATCH**, plus targeted ASan controls for
M8-D1 and M8-D2.

| file | rank | mechanisms | result |
|---|---:|---|---|
| `src/decoder_pkey.rs` | 85 | OB-1 `OwnedBuf`, `OwnedCtx`-style construct-data transfer, cache table ownership, stack/context ownership | no defect |
| `src/asn1/asn1_gen.rs` | 86 | OB-1 adoption, `ASN1_TYPE`/string ownership, `i2d` out-pointers, callback parsers | no defect |
| `src/dh/ameth.rs` | 87 | `EVP_PKEY_ASN1_METHOD` callbacks, `OwnedBuf` adoption/cleansed release, FFC parameter ownership | no defect |
| `src/ec/ameth.rs` | 88 | `EVP_PKEY_ASN1_METHOD` callbacks, `EcKey` by-value copy (no `Drop`), `OwnedBuf` adoption/cleansed release | no defect |
| `src/evp/skeymgmt.rs` | 89 | OB-3 `OwnedCtx`, local `OwnedSkey`, provider callback dispatch, refcount re-entry | **M8-D1 (fixed): provider destructor called with NULL** |
| `src/bn/bignum.rs` | 90 | `Box`-owned `BIGNUM`, `BN_FLG_STATIC_DATA`, byte-conversion extents, cleansing | **M8-D2 (fixed): `BN_copy(a, a)` aliasing** |
| `src/evp/asymcipher.rs` | 91 | OB-3 `OwnedCtx`, `OwnedBlock` cleansed release, provider fetch/export ownership | no defect |
| `src/evp/kem.rs` | 92 | OB-3 `OwnedCtx`, refcount dispatch, provider fetch/export ownership | no defect |

**M8-D1 — `src/evp/skeymgmt.rs:328-341` (pre-fix).**
`OwnedSkey::drop` called `evp_skeymgmt_freedata(skeymgmt, keydata)`
unconditionally, where the authority's `EVP_SKEY_free` guards
`skey->keydata != NULL`. The failure paths of `EVP_SKEY_import`,
`EVP_SKEY_import_SKEYMGMT` and `EVP_SKEY_generate` free a key whose
`keydata` was never produced, so the crate invoked a caller-supplied,
mandatory provider `free(NULL)` in a state the authority never invokes it.
Severity: **high (unsafe provider-callback invocation outside the
authority's contract; any provider whose `free` dereferences its key data
faults).** Fix: restore the authority's guard. The existing re-entrancy
test was updated to give its fixture non-NULL key data, and a new test
pins that a data-less key does not reach the provider destructor.

**M8-D2 — `src/bn/bignum.rs:496-509` (pre-fix).**
`BN_copy` formed `(as_mut(a), as_ref(b))` before testing identity; the
authority returns `a` for `a == b` (`bn_lib.c:341-342`). A C-valid
`BN_copy(a, a)` therefore created aliasing `&mut`/`&` borrows (UB) and,
because the destination was cleared before the copy, emptied the number.
Severity: **high (aliasing UB on a C-valid call, plus value corruption).**
Fix: the authority's early return, before any borrow is formed; a
regression test asserts identity and value preservation.

**Skipped to a boundary batch (NOT_RUN):** none of the eight files
presented a new reusable unsafe boundary; the previously deferred
callback/ownership files remain deferred.

**BATCH:** `cargo fmt --all -- --check` PASS; clippy `--all-targets -D warnings`
PASS; library serial 1577 passed / 0 failed / 26 ignored; threaded run
1577 passed / 0 failed / 26 ignored. Focused: `bn::bignum` 5/0,
`evp::skeymgmt` 11/0, `decoder_pkey` 3/0, `asn1_gen` 3/0, `dh::ameth` 5/0,
`evp::asymcipher` 5/0, `evp::kem` 4/0.

**ASan venue:** both repaired tests pass under
`-Zsanitizer=address -Zbuild-std` (nightly-2026-10-05; leak detection
disabled), with no sanitizer finding.

**Deferred / NOT_RUN:** independent boundary review of M8-D1/M8-D2, a
real third-party-provider NULL-free differential, and dependency-graph
regeneration (BATCH checkpoint after commit).

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M8.json`](atlas-refresh/mechanism-sweep-M8.json).

## 3i. Mechanism-contract sweep M9 — 2026-10-18

**Candidate:** `integrate/safe-c33` source HEAD `92f6bb672` (working tree; M9-D1
fix not committed). **Level:** FAST, then **BATCH**.

| file | rank | mechanisms | result |
|---|---:|---|---|
| `src/store/store_result.rs` | 93 | OB-1 adoption, object-abstraction `set0`/`new_*` ownership, PKCS#12 stack transfer, loader callback contract | no defect |
| `src/ec/pmeth.rs` | 94 | OB-3 `OwnedCtx<EcPkeyCtx>`, OB-1 cleansed KDF temp, partial-copy cleanup, ctrl ownership | no defect |
| `src/dsa/ameth.rs` | 95 | `EVP_PKEY_ASN1_METHOD` callbacks, OB-1 plain/cleansed DER owners, PKCS#8/X509 set0 transfer | no defect |
| `src/evp/keymgmt.rs` | 96 | OB-3 `OwnedCtx`, RC-1 refcount sentinel, provider up-ref order, 22 callback call-throughs | no defect |
| `src/evp/bio_ok.rs` | 97 | `RawCtx` -> `OwnedCtx` staged construction, plain/cleansed split, record parser bounds | no defect |
| `src/x509/x509_cmp.rs` | 98 | comparison/fingerprint extents, `X509_chain_up_ref` unwind, `X509_add_cert` ownership | no defect |
| `src/x509/v3_admis.rs` | 99 | ASN.1 item templates, `set0` replacement ownership, stack destructor thunks | no defect |
| `src/asn1/der.rs` | 100 | DER length/tag bounds, recursion depth, parser pointer extents, prefix-BIO ownership | **M9-D1 (fixed): prefix BIO leaked** |

**M9-D1 — `src/asn1/der.rs:604-615` (pre-fix, also `:653-656` and
`:713-718`).** When a sink did not accept `BIO_CTRL_SET_PREFIX`,
`asn1_print_info` pushed a fresh `BIO_f_prefix()` BIO and later detached it
with `BIO_pop`, but never released it. The authority's `asn1_print_info`
calls `BIO_free(bio)` after `BIO_pop` on every exit (`asn1_parse.c:75-85`).
Each printed ASN.1 element on a plain memory/file BIO therefore leaked one
BIO and its method reference, without bound under repeated
`ASN1_parse`/`ASN1_parse_dump`. Severity: **medium (resource leak; not
UB).** Fix: track the pushed BIO in a frame-local handle and free it after
the pop on both exits, and free the fresh BIO when `BIO_push` refuses it.
No allocation coordinate, layout, export or signature changed.

**Skipped to a boundary batch (NOT_RUN):** `src/x509/x509_vpm.rs` (rank 121)
was inspected and deferred: its writable `X509_VERIFY_PARAM` registry is an
`AtomicPtr<OpenSslStack>` with unsynchronized sort/find/delete/push
mutation plus a static `UnsafeCell` table, a shared-mutable-state and
concurrency boundary, not an ordinary file. The previously deferred
callback/ownership files remain deferred.

**BATCH:** `cargo fmt --all -- --check` PASS; clippy `--all-targets -D warnings`
PASS; library serial 1577 passed / 0 failed / 26 ignored; threaded run
1577 passed / 0 failed / 26 ignored. Focused: `store` 33/0, `ec::pmeth` 2/0,
`dsa` 35/0 (2 ignored), `evp::keymgmt` 10/0, `evp::bio_ok` 0 tests, `x509` 73/0,
`asn1` 36/0 (1 ignored).

**Deferred / NOT_RUN:** a targeted leak control for M9-D1 (the ASan venue
disables leak detection and no in-tree test drives `ASN1_parse_dump`); the
`x509_vpm` concurrency boundary; independent boundary review; and
dependency-graph regeneration (BATCH checkpoint after commit).

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M9.json`](atlas-refresh/mechanism-sweep-M9.json).

## 4. Machine-readable index

`atlas-refresh/perfile-index.json` mirrors table 3 as deterministic JSON:

```json
{
  "candidate_head": "d5255e262c602383645fcae2adc43e04faf9d4a3",
  "files": [ ],
  "totals": { "audited": 9, "partial_files": 9, "zero_unsafe": 0, "boundary_covered": 0 }
}
```

`files` is sorted by `file`. `totals.audited` is the number of audited files;
`partial_files`, `zero_unsafe` and `boundary_covered` are their status counts in
the `ATTRIBUTION.md` vocabulary (all nine are `PARTIAL`). Every entry carries
`not_discharged: true`.

## 5. Provenance

The former cumulative `PERFILE-AUDIT.md` was split into these records on
2026-10-18 without editing section content: each record is the corresponding
section verbatim, minus only the inter-section `---` separators and their
surrounding blank padding. The cumulative file is now a pointer to this index so
existing links continue to resolve.

## 6. Boundary sweep B1 — the four deferred callback/global-state files

**Source identity:** `integrate/safe-c33` at `9715fec62`, 2026-10-18. **STOP:**
none. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

| file | boundary IDs | disposition | defect repaired |
|---|---|---|---|
| `src/provider/file_store.rs` | `B1-FS-1..3` | `CONTRACTED` | none found |
| `src/runtime/bio/iolib.rs` | `B1-BIO-1..2` | `CONTRACTED` | `B1-D1` long-lived `&mut Bio` invalidated by the raw-pointer callback/method path (eight sites) |
| `src/runtime/obj.rs` | `B1-OBJ-1..3` | `CONTRACTED` | `B1-D2` caller destructor under the registry mutex; `B1-D3` `do_all` snapshot freed by a recursive removal; `B1-D4` intermediate read-lock self-deadlock, removed in-batch |
| `src/x509/x509_vpm.rs` | `B1-VPM-1..3` | `CONTRACTED` | `B1-D5` `UnsafeCell` over the const default table; `B1-D6` unsynchronised `PARAM_TABLE` stack mutation; `B1-D7` negative-id OOB pointer; `B1-D8` NULL key in `strcmp` |

`OBJ_NAME` iteration now takes a snapshot and defers the destructor of any
record removed during the walk to a RAII walk guard, so no lock is held across a
visitor and the snapshot's borrowed `name`/`data` remain valid. This is a
deliberate divergence from the authority, whose read lock makes re-entrant
mutation a deadlock. The `X509_VERIFY_PARAM` table is serialised by one mutex;
`get0`/`lookup` still return borrowed table pointers, so callers must not race
`table_cleanup` (authority parity, stated as an external precondition).

**Evidence.** FAST: fmt clean; 71 `runtime::bio`, 16 `runtime::obj`, 8
`x509::x509_vpm` tests. BATCH: clippy `--all-targets -D warnings` PASS; library
**1581 passed / 0 failed / 26 ignored** serially and with `--test-threads=4`;
**26/26** adversarial probes. Negative control `NC-B1-1`: the intermediate
read-lock design hung `bn::blinding:: --test-threads=4` (EXIT=124) and the final
design passed it (EXIT=0, 11 tests).

**Residuals and NOT_RUN.** ASan pre-fix canary for the `do_all` UAF, Miri
(no component; libc externs) and Loom/TSan are `NOT_RUN` at BOUNDARY/SEAL. The
remaining registry contracts (custom comparator purity, borrowed-data lifetime,
const default rows, BIO-callback non-invalidation) are external preconditions,
not hidden obligations. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B1.json`](atlas-refresh/boundary-sweep-B1.json).

**Next boundary position:** `src/runtime/bio/bss_dgram_pair.rs` (rank 65), then
`src/runtime/bio/bss_conn.rs` (rank 66). No fifth file was started.

## 7. Boundary sweep B2 — the three deferred BIO ownership/callback files

**Source identity:** `integrate/safe-c33` at `60c852eb0`; source blobs
`bss_dgram_pair.rs` `a9e7d54c3…`, `bss_conn.rs` `64234baaf…`,
`bss_dgram.rs` `7b9240577…`. **STOP:** none. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

| file | boundary IDs | disposition | defect repaired |
|---|---|---|---|
| `src/runtime/bio/bss_dgram_pair.rs` | `B2-DP-1..7` | `CONTRACTED` | `B2-D1` unchecked `req_buf_len + sz` ring-growth target (panic/lock-leak) |
| `src/runtime/bio/bss_conn.rs` | `B2-CN-1..7` | `CONTRACTED` | none found |
| `src/runtime/bio/bss_dgram.rs` | `B2-DG-1..7` | `CONTRACTED` | none found |

**B2-D1 — `bss_dgram_pair.rs` (pre-fix line 1257), low severity.**
`dgram_pair_write_inner` computed the resize target as `req_buf_len + sz`
without a checked add. The crate builds with `overflow-checks = true`, so a
caller-supplied `BIO_MSG.data_len` that overflows panics inside the write path
while the pair write lock is held; `guard_ffi` converts the panic to an error
but does not release the lock, leaving the BIO permanently blocked. Without
overflow checks the target wraps and can leave the growth loop spinning on an
unchanged ring. The fix maps an unrepresentable target to the existing
"no space" rollback path. The C authority has the same unchecked addition; this
is a deliberate divergence on a contract-violating length only.

**Contracts and residuals.** All three files were compared at their ownership,
callback and out-parameter seams against
`forensics/authorities/src/openssl-3.6.4`. Every boundary is `CONTRACTED`, with
37 residual obligations enumerated in the machine-readable receipt. The
load-bearing ones are external, not hidden: a BIO callback must not free or
invalidate the BIO (reused from B1); `BIO_MSG` arrays and their data/peer/local
pointers obey the documented layout; ctrl out-parameters are writable and
non-NULL where the authority writes; `SET0_LOCAL_ADDR` transfers ownership
once; borrowed `GET_CONNECT` pointers expire on the next mutation; and a
datagram BIO is not safe to free/control concurrently with an in-flight
data operation (ctrl fields are not ring-locked, authority parity). Self-pairing
is accepted as in the authority; the port's recursive-write detection makes the
read fail with 0 rather than deadlock, so no lock repair was retained.

**Evidence.** FAST: fmt clean; 71 `runtime::bio` tests (including the
`BioDgramPairSt`, `BioConnect` and `BioDgramData` zero-state sweeps). BATCH:
clippy `--all-targets -D warnings` PASS; library
**1581 passed / 0 failed / 26 ignored** serially (301.05 s) and with
`--test-threads=4` (87.18 s) on the recorded `a9e7d54c3…` blob. No affected
adversarial probe is defined for these three files. Ownership controls
`canary_destroy_instrument_is_live` and the five release-model mutants pass.

**Residuals and NOT_RUN.** ASan (the B2-D1 panic path and the free paths), Miri,
Loom/TSan, an executable authority differential and a pre-fix B2-D1 canary are
`NOT_RUN` at BOUNDARY/SEAL. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B2.json`](atlas-refresh/boundary-sweep-B2.json).

**Next boundary position:** `src/rsa/object.rs` (rank 68). Remaining deferred
families are the SSL session ownership batch (`ssl_sess`, rank 61), the TLS
state-machine batch (`statem_clnt`, rank 50), and the explicitly deferred
`ml_dsa/encoders.rs`, `ssl/ssl_lib.rs` and `ssl/statem/statem_srvr.rs`. No
fourth file was started in B2.

## 8. Boundary sweep B3 — the two deferred SSL lifecycle/state-machine files

**Source identity:** `integrate/safe-c33` at `4511ad3d3`; working-tree blobs
`ssl_lib.rs` `cdba5c9cb…` and `statem_srvr.rs` `ff22a0059…`.**STOP:** repaired —
two high-severity memory-safety defects were found and fixed. Nothing is
promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

| file | boundary IDs | disposition | defects repaired |
|---|---|---|---|
| `src/ssl/ssl_lib.rs` | `B3-SL-1..9` | `CONTRACTED` | `B3-D5` (DTLS `d1` leak on the ex_data refusal arm), `B3-D6` (unchecked supportedgroups extent) |
| `src/ssl/statem/statem_srvr.rs` | `B3-SS-1..9` | `CONTRACTED` | `B3-D1`/`B3-D2` (unbounded `i2d_X509` writes into 8192-byte stack buffers in both certificate flights), `B3-D3` (32-byte HMAC tail for the application-chosen ticket digest), `B3-D4` (unbounded callback IV length) |

**B3-D1/D2 — `statem_srvr.rs` (pre-fix 1910/2620/2651), high.** `i2d_X509` with
a non-NULL out-pointer writes the whole encoding and takes no capacity
argument, yet both flight writers encoded into `[u8; 8192]` stack buffers and
checked the length only afterwards. Any application certificate of 8192 bytes
or more overflowed the stack. Both now size first with `i2d_X509(cert, NULL)`,
compute the body with `checked_add`, allocate the exact body through `OwnedBuf`,
and encode into that reservation (the authority's WPACKET ordering).

**B3-D3 — `statem_srvr.rs` (pre-fix 2986), high.** The TLS1.3 stateless ticket
reserved only 32 bytes for the HMAC tail, but `ticket_key_cb` chooses the
digest; `HMAC_Final` writes up to `EVP_MAX_MD_SIZE` (64), so a SHA-384/512
callback produced a heap overflow. The tail now reserves `EVP_MAX_MD_SIZE`,
matching `statem_srvr.c:4314-4317`, and refuses a longer report.

**B3-D4/D5/D6 — low/informational.** The ticket path now refuses
`iv_len > EVP_MAX_IV_LENGTH` before slicing the 16-byte callback IV;
`SSL_new` releases its early-allocated DTLS state on the ex_data refusal arm
(the authority allocates it only after `ossl_ssl_init` succeeds); and the
`supportedgroups` copy uses `checked_mul` (the setter bounds it to 64, so the
overflow arm is unreachable).

**Contracts and residuals.** Nine boundaries per file, all `CONTRACTED`, with 42
residuals in the machine-readable receipt. The load-bearing ones are external:
the C caller owns the reference it releases; transferred objects carry one
reference; callback code must not free the SSL/SSL_CTX it receives; the
ClientHello readers are valid only during the callback; a destructor-time
reentrant free is a defined no-op while other reentrant use observes partial
teardown (authority ordering); and a ticket callback must initialise the
supplied cipher/HMAC contexts. Latent self-alias setters (`SSL_CTX_set_cert_store`,
`SSL_CTX_set0_ctlog_store`, `SSL_set0_tmp_dh_pkey`) and the `SSL_set_SSL_CTX`
free-before-assign window are authority parity, recorded not restructured.
Session internals (`ssl_sess`, rank 61) and the `ssl_rsa` chain loaders remain
delegated. Hidden obligations: 0.

**Evidence.** FAST: fmt clean; focused `ssl::ssl_lib` 21 passed / 4 ignored and
the new oversized controls. BATCH: clippy `--all-targets -D warnings` PASS;
library **1583 passed / 0 failed / 26 ignored** serially (233.10 s) and with
`--test-threads=4` (94.96 s). Affected probes: the srvr ticket probe and
double-release canary, the four `ssl_lib` realloc probes, the `ssl_sess`
self-alias probe and the cleansed-free canary all PASS. ASan: the venue canary
reports `heap-use-after-free` (exit 1), and the two new oversized-certificate
controls pass with no ASan report. The controls build a real self-signed EC
certificate whose DER exceeds 8192 bytes and drive each writer with a memory
BIO; pre-fix, the same DER was written into the fixed stack buffers.

**Residuals and NOT_RUN.** Miri, Loom/threaded state-machine interleavings, the
pre-fix binary under ASan, an authority differential for certificate bodies
above 16996 bytes (the reduced writer caps at 17000; the authority does not),
independent review and the full SEAL closure are `NOT_RUN` at BOUNDARY/SEAL.
The >16996-byte refusal is a recorded compatibility divergence of the reduced
writer. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B3.json`](atlas-refresh/boundary-sweep-B3.json).

**Next boundary position:** `src/rsa/object.rs` (rank 68), then
`src/ssl/ssl_sess.rs` (rank 61), `src/ssl/statem/statem_clnt.rs` (rank 50) and
`src/ml_dsa/encoders.rs`. No third file was started in B3.

## 9. Boundary sweep B4 — the deferred SSL session and client state-machine files

**Source identity:** `integrate/safe-c33` at `05457b479`; working-tree blobs
`ssl_sess.rs` `84ffa4649…` and `statem_clnt.rs` `65776490a…`. **STOP:** repaired —
one high-severity memory-safety defect and three lower-severity defects were
found and fixed. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

| file | boundary IDs | disposition | defects repaired |
|---|---|---|---|
| `src/ssl/ssl_sess.rs` | `B4-SL-1..5` | `CONTRACTED` | `B4-D3` (partially overlapping id sources used `copy_nonoverlapping`), `B4-D4` (refused cache push leaked its reference and reported success) |
| `src/ssl/statem/statem_clnt.rs` | `B4-SC-1..7` | `CONTRACTED` | `B4-D1` (unbounded TLS1.2 ServerHello session id written into the 32-byte session field), `B4-D2` (missing TLS1.3 bound / wrong alert-reason parity) |

**B4-D1 — `statem_clnt.rs` (pre-fix 2145), high.** The TLS1.2 ServerHello
session-id length is one wire byte (`0..=255`). It was published as
`session_id_length` and copied into `SslSession::session_id`, a 32-byte field
inside the heap session block. A hostile ServerHello with a 33–255-byte id
overran the field into `sid_ctx_length`/`sid_ctx`/the member pointers, and the
inflated length made later `session_cmp` reads run past the array. Both
ServerHello parsers now reject `sid_len > SSL_MAX_SSL_SESSION_ID_LENGTH` with
the authority's `SSL_AD_ILLEGAL_PARAMETER` / `SSL_R_SSL3_SESSION_ID_TOO_LONG`
(`statem_clnt.c:1519-1524`) before a session is created or mutated. The TLS1.3
parser was safe only by the `sid_len != tmp_len` short-circuit; the explicit
bound now supplies the authority's alert and reason (`B4-D2`).

**B4-D3 — `ssl_sess.rs` (pre-fix 1339/1756), low.** `SSL_SESSION_set1_id` and
`SSL_SESSION_set1_id_context` skip only the exact self-pointer and used
`copy_nonoverlapping`. Their stated contract accepts any source readable for
the length, including a pointer into the same array, so a partial overlap was
UB (as it is for the authority's `memcpy`). Both now use `ptr::copy`
(memmove), preserving the in-place result while eliminating the overlap UB per
AGENTS §17.

**B4-D4 — `ssl_sess.rs` (pre-fix 700), low.** `SSL_CTX_add_session` ignored
`OPENSSL_sk_push`. On a refused stack allocation it leaked the reference taken
for the cache, claimed `owner`, and returned 1 although the session was not
cached. It now checks the push, releases the cache reference on refusal, and
returns 0, matching the authority's OOM arm (`ssl_sess.c:756-765`); the
caller's own reference is untouched.

**Client analogues of B3.** The client uses no fixed certificate DER buffers:
both certificate flights parse directly from the message slice with `d2i_X509`,
and certificate/ticket bodies are dynamically allocated. The ticket path hashes
into a 32-byte digest and copies exactly 32 bytes into the 32-byte id, and the
ClientHello/public-key/signature bodies all carry explicit capacity checks. The
B3 stack-write classes have no reachable client equivalent.

**Contracts and residuals.** Twelve boundaries (five session, seven client),
all `CONTRACTED`, with 46 residuals in the machine-readable receipt. The
load-bearing external ones are: a C caller owns the reference it releases;
cache callbacks run under the context write lock during eviction (authority
parity) and must not re-enter the cache; `new_session_cb` owns its extra
reference when it returns nonzero; every application callback must not free the
SSL/SSL_CTX/SSL_SESSION it receives; and the reduced reader delivers exactly
one length-delimited message per call. Recorded divergences: eviction processes
insertion order, not timeout order; `SSL_CTX_free` releases the cache without
invoking `remove_session_cb` (the authority flushes and invokes it — wiring it
requires reordering `SslCtx::destroy_body`, outside this batch); the client
read/ticket cap is 16384 bytes; and the TLS1.2 ticket is the reduced stateful
form. Hidden obligations: 0.

**Evidence.** FAST: fmt clean; `ssl::ssl_sess` 6 passed / 1 ignored and the two
new ServerHello bounds controls. BATCH: clippy `--all-targets -D warnings`
PASS; library **1586 passed / 0 failed / 26 ignored** serially (287.31 s) and
with `--test-threads=4` (95.05 s). Affected probes, one process each: the two
`ssl_lib` realloc probes, the `ssl_sess` self-alias probe and the cleansed-free
canary all PASS. The 64-byte ServerHello controls assert refusal, a NULL
session and a poisoned state for both versions; the overlap control asserts the
deterministic memmove result.

**Residuals and NOT_RUN.** Miri, Loom/threaded handshake interleavings, the
pre-fix binary under ASan, an authority differential for the oversized
ServerHello, `SSL_CTX_free` callback parity and the full SEAL closure are
`NOT_RUN` at BOUNDARY/SEAL. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B4.json`](atlas-refresh/boundary-sweep-B4.json).

**Next boundary position:** `src/rsa/object.rs` (rank 68), then
`src/ml_dsa/encoders.rs`; the `ssl_lib` context-teardown ordering needed for
`remove_session_cb` parity is a recorded follow-up. No third file was started
in B4.

---
## 10. Boundary sweep B5 — ML-DSA key/signature encoders and the secure seam

**Candidate:** `integrate/safe-c33` source HEAD `c12d9915c` (working tree; not
committed). **Level:** FAST, BATCH and targeted ASan. **Scope:** exactly
`src/ml_dsa/encoders.rs`; no second file started.

Seven boundaries (`B5-ML-1`–`B5-ML-7`), all `CONTRACTED`: the file-local OB-1
`OwnedBuf` over the plain and secure allocator seams; pk encode/decode; sk
encode/decode (seed cleanse, secure scratch, `priv_encoding == in_` load path);
the twelve bit-packing primitives; hint/signature serialisation; the diagnostic
extent; `expand_mask`/`w1`.

**B5-D1 (fixed, medium, ASan-confirmed).** `hint_bits_encode` wrote each set
coefficient at `data[coeff_index++]` in the `omega + k`-byte packet while the
FIPS 204 weight bound (at most `omega` ones) was only an unstated caller
assumption. An over-weight in-memory hint overran the allocation. The encoder
now refuses the `(omega+1)`th set coefficient before writing; valid signatures
are unchanged. The pre-fix body was rebuilt in the ASan venue and the control
produced `stack-buffer-overflow` in `hint_bits_encode`; the fixed body passes.

**B5-D2 (fixed, low).** `hint_bits_decode` derived `end = p + k` and entered its
do/while unconditionally; for `k == 0` it read one byte past the limit span and
wrote through a possibly-NULL polynomial pointer. It now refuses `k == 0` (no
static parameter set produces it).

**B5-D3 (fixed, low, §3).** The hint packet extent (`omega + k`) and
`raise_with_alg`'s three-piece message capacity now use `checked_add`; both
operands are bounded statics, so reachable behaviour is identical.

**Contracts.** Every key-serialiser `# Safety` section now states the encoded
member ownership invariant it relies on (`pub_encoding` plain-owned,
`priv_encoding`/`seed` secure-owned at the parameter set's exact length), the
`priv_encoding == in_` alias path, and that a public-hash mismatch releases
`in_` when it is the key's own encoded block. The hint weight bound is stated
on both `hint_bits_encode` and `ossl_ml_dsa_sig_encode`.

**Secure seam (verified separately, not inferred from OB-1).** The secure arm is
sound on both provenances: with a secure heap the whole usable allocation is
cleansed on release; without one `CRYPTO_secure_malloc` falls back to the plain
seam and `CRYPTO_secure_clear_free` recognises that provenance, cleanses the
`len` bytes and releases through `CRYPTO_free`. `runtime::secure`'s
whole-allocation-cleanse, fallback and zero-length tests all pass.

**Secret cleaning.** `priv_encoding` and `seed` are `SECRET_DATA` +
`CLEANSING_REQUIRED`: the incumbent is secure-cleared at `:744`, the failed
scratch block at `:750`, and the seed at `:773`; decoded `s1/s2/t0` live in the
key's secure block and are cleansed by `key_reset`/`key_free`. `rho`, `tr`,
`c_tilde`, the hint and the signature bytes are public; `input_tr` is the public
key hash. Every secret allocation is cleansed on success, failure and
partial-initialisation paths that release it.

**Evidence.** FAST: fmt clean; `ml_dsa` 14 passed / 0 failed (12 existing + 2
new controls). BATCH: clippy `--all-targets -D warnings` PASS; library **1588
passed / 0 failed / 26 ignored** serially (268.13 s) and with
`--test-threads=4` (80.84 s); `runtime::secure` 15/0 as the affected seam probe.
ASan venue: the temporary pre-fix body fired `stack-buffer-overflow` at
`encoders.rs:1445`; the restored fixed body passes both controls. The file was
restored byte-identically (sha256 `61fb7560…`).

**Residuals and NOT_RUN.** Hidden obligations: 0; no safe caller can cause UB.
Miri over the hint paths, a paired authority differential for the impossible
`k == 0`/over-weight states, timing/dudect (the new branch tests public hint
coefficients; no timing claim is made), FRF-Fuzz replay, dependency-closure
audit, independent review and SEAL regeneration are `NOT_RUN`. Machine-readable
receipt: [`atlas-refresh/boundary-sweep-B5.json`](atlas-refresh/boundary-sweep-B5.json).

## Batch M11 — mechanism-contract sweep (attribution ranks 101–108)

**Audited (ordinary):** `src/pem/pem_lib.rs` (101, 136 sites),
`src/property/parse.rs` (102, 136), `src/x509/pcy_tree.rs` (103, 135),
`src/x509/x509_acert.rs` (104, 134), `src/ssl/ssl_ciph.rs` (107, 130),
`src/x509/x509_att.rs` (108, 129).
**NOT_RUN (BOUNDARY):** `src/ssl/bio_ssl.rs` (105, 133) and
`src/runtime/bio/bss_bio.rs` (106, 131) — BIO method/callback boundaries, deferred
without inspecting their interiors.

**M11-D1 (fixed, medium, STOP-and-clear).** `ossl_parse_query`'s `-name` override arm
left `OsslPropertyDefinition::type_` uninitialized. `stack_to_property_list` and
`ossl_property_merge` copy the definition as a whole, so the copy read an
uninitialized scalar (Rust UB even though every current reader tests `oper` first).
Both parsers now seed each fresh definition with a fully initialized zero
(`definition_zeroed()`); a focused assertion pins the override clause's `type_` to
`OSSL_PROPERTY_TYPE_STRING` (the zero the authority's `type`-ignoring readers
expect). Recorded divergence: deterministic zero replaces the authority's unset
field, which is unobservable to every reader.

**M11-D2 (fixed, medium).** `PEM_def_callback` stored `strlen(userdata)` in a
`c_int` and passed it to `memcpy`; a string longer than `INT_MAX`, or a negative
`num`, became an enormous `size_t`. The copy length is clamped to `num >= 0` and the
`strlen` result. Two controls cover truncation and the negative-`num` clamp.

**M11-D3/D4 (fixed, low).** `PEM_do_header` rejects a negative `*plen` instead of
passing it to `EVP_DecryptUpdate`; `PEM_ASN1_write_bio_internal` refuses a negative
second-pass encoder result instead of passing it to `EVP_EncryptUpdate` /
`PEM_write_bio`. Both are caller-contract violations, hardened rather than assumed.

**M11-D5 (fixed, low).** `X509_ACERT_add_attr_nconf`'s `c_strlen` now reports a
length that does not fit `c_int` instead of truncating it; `ciphersuite_cb` now
requires `len > 0`.

**M11-D6 (contract).** `tree_calculate_authority_set` and `tree_calculate_user_set`
now state the `nlevel >= 2` precondition `tree_init` establishes; their
`levels[len - 1]` index would otherwise underflow.

**Contracts reused.** OB-1 `OwnedBuf` (property definitions, `AttDataBuf`,
`OwnedBuf` in the SSL description path); the module-local `PemBuf`/`OwnedDer`
owners; the `OwnedTree`/`OwnedLevels`/`OwnedNode` policy-graph model with
`tree_levels`/`level_ptr` as the only level-address arithmetic; the category-B
BIO callback contracts (deferred files only); C-ABI getter/destructor contracts.
No new unsafe abstraction, no ABI/layout change, no allocator-coordinate change.

**Evidence.** FAST: fmt clean; focused `property::parse` 7/0, `pem::pem_lib` 2/0,
`pem::` 3/0, `pcy_tree`, `x509_acert`, `ssl_ciph` have no in-module tests. BATCH:
clippy `--all-targets -D warnings` PASS; library **1590 passed / 0 failed /
26 ignored** serially (256.43 s) and with `--test-threads=4` (97.04 s).
Hidden obligations: 0. Miri/ASan controls for D1/D2, an authority differential for
the override-clause `type_` divergence, the two deferred BIO boundaries, and SEAL
evidence are `NOT_RUN`.

**Next ordinary queue position:** `src/dh/pmeth.rs` (rank 109, 126), then
`src/runtime/confmod/mod.rs` (110, 126), `src/bn/gf2m.rs` (111, 125),
`src/decoder_meth.rs` (112, 125). `src/ssl/bio_ssl.rs` (105) and
`src/runtime/bio/bss_bio.rs` (106) remain queued for a boundary batch.
Machine-readable receipt: [`atlas-refresh/mechanism-sweep-M11.json`](atlas-refresh/mechanism-sweep-M11.json).

## Batch M12 — mechanism-contract sweep (attribution ranks 109, 111–117)

**Audited (ordinary):** `src/dh/pmeth.rs` (109, 126 sites), `src/bn/gf2m.rs`
(111, 125), `src/decoder_meth.rs` (112, 125), `src/asn1/time.rs` (113, 124),
`src/provider/encode_key2text.rs` (114, 124), `src/ts/ts_asn1.rs` (115, 124),
`src/x509/x_name.rs` (116, 124), `src/txt_db/txt_db.rs` (117, 122).
**NOT_RUN (BOUNDARY):** `src/runtime/confmod/mod.rs` (110, 126) — DSO module
init/finish callbacks plus global RCU module lists; deferred without inspecting its
interior.

**M12-D1 (fixed, medium).** `pkey_dh_ctrl`'s `EVP_PKEY_CTRL_DH_KDF_UKM` arm stored
`p1` directly in the `size_t` `kdf_ukmlen`; a negative length with a non-NULL `p2`
became a huge length that a later X9.42 derive read from `p2`. The arm now refuses
`p1 < 0` with `-2` before replacing the stored block. The authority stores the
wrapped value; the refusal is a recorded divergence on invalid input only. Control:
`dh::pmeth::tests::a_negative_ukm_length_is_refused`.

**M12-D2 (fixed, high).** `TXT_DB_read` computed `add = (num + 1) * sizeof(char *)`
in `c_int` and sized each row as `add + offset`. A large C-valid `num` wraps the
product; under overcommit the preceding index/qualifier arrays can succeed, after
which the row's pointer-array stores write outside a block sized from the wrapped
value. Both the product and the row extent are now `checked_*` + `usize::try_from`,
with overflow taking the existing `read_err` path. Valid inputs keep the same
allocation sizes, order and results.

**No defect found:** `src/bn/gf2m.rs` (all pointer reads bounded by the terminated
exponent array; every `BN_CTX_get` failure exits through `BN_CTX_end`),
`src/decoder_meth.rs` (OB-3 context destruction and dispatch scan at the authority
order), `src/asn1/time.rs` (parser index invariants: 12/14 bytes consumed against
minimum lengths 13/15, offset arm reads exactly the last four bytes),
`src/provider/encode_key2text.rs` (`OwnedClearBuf` adoption extents are the helper
return lengths; private/generator buffers released with `CRYPTO_clear_free`),
`src/ts/ts_asn1.rs` (AUX callback NEW/D2I/FREE_POST ownership), `src/x509/x_name.rs`
(canonicalisation stays inside the UTF-8 block; a negative first-pass i2d length
makes `BUF_MEM_grow(0)` return 0 and takes the failure path).

**Contracts reused.** OB-3 `OwnedCtx`/`CtxDestroy`, OB-1 `OwnedBuf`, OB-2
`OwnedStr`, the module-local `OwnedClearBuf`, decoder/encoder dispatch-table
contracts, ASN.1 item/AUX hooks, and the C-ABI getter/destructor contracts. No new
unsafe abstraction, ABI/layout change or allocator-coordinate change; the only new
unsafe operations are test-only calls in the pmeth control.

**Evidence.** FAST: fmt clean; focused `dh::pmeth` 2/0, `bn::gf2m` 5/0,
`decoder_meth` 5/0, `provider::encode_key2text` 2/0, `x509::x_name` 4/0; `txt_db`,
`asn1::time` and `ts::ts_asn1` have no in-module tests. BATCH: clippy
`--all-targets -D warnings` PASS; library **1591 passed / 0 failed / 26 ignored**
serially (208.15 s) and with `--test-threads=4` (92.77 s). Hidden obligations: 0.
ASan/Miri controls for D1/D2, an authority differential for the refusal, the
deferred `confmod` boundary and SEAL evidence are `NOT_RUN`.

**Next ordinary queue position:** `src/evp/fetch.rs` (rank 118, 121), then
`src/ssl/tls13_enc.rs` (119, 121), `src/ts/ts_rsp_utils.rs` (120, 121),
`src/x509/x509_vpm.rs` (121, 121). `src/runtime/confmod/mod.rs` (110) joins
`src/ssl/bio_ssl.rs` (105) and `src/runtime/bio/bss_bio.rs` (106) in the boundary
queue. Machine-readable receipt:
[`atlas-refresh/mechanism-sweep-M12.json`](atlas-refresh/mechanism-sweep-M12.json).

## 11. Boundary sweep B6 — confmod, BIO-SSL and the BIO pair

**Audited (boundary):** `src/runtime/confmod/mod.rs` (110, 126 sites),
`src/ssl/bio_ssl.rs` (105, 133), `src/runtime/bio/bss_bio.rs` (106, 131). The three
deferrals recorded by M11/M12 are closed; no boundary file remains in the B1–B6 queue.

**B6-D1 (fixed, high, STOP-and-clear).** `BIO_C_SET_SSL`'s re-creation arm called
`ssl_free`, which released the `BioSsl` block without clearing `BIO.ptr`, then returned 0
when `ssl_new`'s allocation was refused. The dangling slot caused a use-after-free in
later callbacks and a second release in `BIO_free`; the authority has the same release
build defect. The arm now clears the data slot and `init` before the fallible
`ssl_new`, every callback refuses a NULL slot, and SET_SSL can recover. Control:
`ssl::bio_ssl::adv_probe::set_ssl_allocation_refusal_clears_data_before_recreate`
(allocator-refusal probe; the recording allocator flags the pre-fix double release).

**B6-D2 (fixed, medium).** The four confmod diagnostic builders formatted into
`static mut BUF`, a cross-thread data race when `CONF_modules_load` runs concurrently on
different `CONF` objects. Each now takes caller-owned stack storage; the raise copies the
bytes synchronously. Message bytes and error coordinates are unchanged. The same class
remains in `src/provider/conf.rs` and `src/runtime/conf/conf_ssl.rs` (outside this batch).

**B6-D3 (fixed, low).** `BIO_read`/`bio_nread0` trusted `init` to imply a live peer and
`bio_write`/`bio_nwrite0` trusted it to imply a ring buffer. Both states are reachable
through the public `BIO_set_init`/`BIO_set_data` accessors. The paths now answer 0 on an
absent peer/buffer and `bio_destroy_pair` clears a live peer even when its data is
absent. Control: `bss_bio::tests::forced_initialised_state_without_a_pair_is_inert`.

**B6-D4 (fixed, low, parity).** `CONF_modules_unload` relied on `OPENSSL_sk_dup(NULL)`
answering NULL, which this crate's stack intentionally does not do. An explicit NULL test
now takes the authority's early return.

**Residuals.** No hidden obligations in the three files; no safe Rust caller can cause UB
through their interfaces. Retained and now stated: re-adopting the same SSL pointer with
`BIO_CLOSE`; `BIO_set_data`/`BIO_set_init` replacing a method's data; BIO pairs are not
concurrency-safe; `module_find` returns an unpinned entry, so unload/finish must not run
concurrently with load and a module callback must not unload its own module (the upstream
design has no per-module refcount, which blocks `SAFETY_DISCHARGED`); DSO symbol
signatures are the module's contract. Graduation: `CONTRACTED`.

**Evidence.** FAST: fmt and `cargo check --lib` clean; focused `bss_bio` 2/0, `bio_ssl`
1/0 + 1 ignored, `confmod` 2/0. BATCH: clippy `--all-targets -D warnings` PASS; library
**1592 passed / 0 failed / 27 ignored** serially (253.62 s) and with `--test-threads=4`
(94.65 s); the ignored allocator probe passes alone under `OPENSSL_RS_ADV_PROBE=1`.
ASan/Miri/TSan/Loom, the RT-SSL-BIO and RT-CONF-MOD differential courts (candidate shell
rebuild required), FRF-Fuzz replay, independent review and SEAL regeneration are
`NOT_RUN`. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B6.json`](atlas-refresh/boundary-sweep-B6.json).

**Next boundary position:** none from the B1–B6 queue. Next ordinary position remains
`src/evp/fetch.rs` (118), `src/ssl/tls13_enc.rs` (119), `src/ts/ts_rsp_utils.rs` (120),
`src/x509/x509_vpm.rs` (121).

## 12. Boundary sweep B7 — diagnostic-buffer races, SSL_CTX cache teardown, ssl_rsa loaders

**B7-D1/B7-D2 (fixed, medium, race).** `src/provider/conf.rs` and
`src/runtime/conf/conf_ssl.rs` still carried the B6-D2 class: four diagnostic builders
formatted into `static mut BUF`, although `provider_conf_load` and `ssl_module_init` run
concurrently from concurrent `OSSL_PROVIDER_load`/`CONF_modules_load` calls. All four now
take a caller-owned `&mut [c_char; ERR_MAX_DATA_SIZE]`; each raise copies the bytes
synchronously. Message bytes, truncation and site coordinates are unchanged.

**B7-D3 (fixed, medium, parity/UAF).** `SslCtx::destroy_body` released the session cache
through `ssl_ctx_session_cache_free` without invoking `remove_session_cb`; the authority
flushes the cache in `SSL_CTX_free` (`ssl_lib.c:4385-4389`, ticket #212). `destroy_body`
now calls `SSL_CTX_flush_sessions_ex(ctx, 0)` **first**, then frees `param`/`dane`, then
`ex_data` (authority order), then the container and the remaining members. The callback
therefore runs outside `ctx->lock` with the context, its `ex_data`, cache and lock still
live. Deliberate divergence: the authority frees `param`/`dane` before flushing, which
would expose freed members to a callback; flushing first is the stricter order.

**B7-D4 (fixed, low, parity).** The chain loader passed `None`/NULL to both PEM readers;
the authority forwards the context's default password callback (`ssl_rsa.c:479-490`).
`use_certificate_chain_file` now forwards it for both the leaf and the CA blocks. The
certificate-file loaders still omit the same forwarding and are the next recorded
follow-up, not part of this item.

**Residuals.** Hidden obligations: 0. No safe Rust caller can cause UB through these
interfaces. Retained: the `remove_session_cb` reentrancy contract (must not free the
context); a session re-added by a callback during the flush is released without a second
callback (the authority would leak it); the existing `ssl_security_cert` reduction; the
certificate-file callback omission. Graduation: `CONTRACTED`.

**Evidence.** FAST: fmt clean; focused `conf_ssl` 4/0, `provider::conf` 3/0, `ssl_sess`
7/0 + 1 ignored, `ssl_lib` 21/0 + 4 ignored, `ssl_rsa` 1/0 + 1 ignored. BATCH: clippy
`--all-targets -D warnings` PASS; library **1597 passed / 0 failed / 27 ignored**
serially (261.46 s) and with `--test-threads=4` (82.78 s); three affected SSL probes
pass under `OPENSSL_RS_ADV_PROBE=1`. ASan (nightly-2026-10-05, `-Zsanitizer=address`
`-Zbuild-std`): the four `ssl_sess::alias_ownership_tests` pass with no UAF/double-free.
Negative controls observed: restoring the `static mut` builder made the storage control
fail (`a == b`); freeing `ex_data` before the flush made the teardown control observe 0
instead of the sentinel. Miri/Loom/TSan, full-suite ASan, the encrypted-chain fixture,
the C teardown differential, FRF-Fuzz and SEAL regeneration are `NOT_RUN`. Machine-
readable receipt: [`atlas-refresh/boundary-sweep-B7.json`](atlas-refresh/boundary-sweep-B7.json).

**Next boundary position:** none from the B1–B7 queue. Next ordinary position remains
`src/evp/fetch.rs` (118), `src/ssl/tls13_enc.rs` (119), `src/ts/ts_rsp_utils.rs` (120),
`src/x509/x509_vpm.rs` (121).

## 13. Batch M13 — mechanism-contract sweep (attribution ranks 118–127)

**Audited (ordinary):** `src/evp/fetch.rs` (118, 121 unattributed),
`src/ssl/tls13_enc.rs` (119, 121), `src/ts/ts_rsp_utils.rs` (120, 121),
`src/evp/p_legacy.rs` (121, 120), `src/cms/cms_ess.rs` (122, 120),
`src/evp/pmeth_gn.rs` (125, 118), `src/provider/rsa_sig.rs` (126, 116),
`src/ssl/ssl_cert.rs` (127, 116).
**Skipped:** `src/x509/x509_vpm.rs` (121) — boundary-audited in B1, not re-opened.
**NOT_RUN (BOUNDARY):** `src/provider/mod.rs` (124) — provider lifecycle/refcount
edge. `src/rsa/mod.rs` (123) was not reached under the eight-file cap and is the
next large-file deferral.

**M13-D1 (fixed, high, STOP-and-clear).** `EVP_PKEY_CTX_get_keygen_info` accepted
`idx == keygen_info_count` as in range. `EVP_PKEY_generate` attaches a two-element
stack array with `count = 2`, so index 2 read one `int` past it; before a generation
the same test admitted index 0 with `keygen_info == NULL`, dereferencing NULL. Both
are C-valid calls (an application keygen callback can make them) and the authority
has the same off-by-one. The guard is now `idx >= count` and answers 0; indices
`0..count` are unchanged. Control:
`evp::pmeth_gn::tests::keygen_info_refuses_the_index_it_does_not_have`.

**M13-D2 (fixed, medium).** `hkdf_expand_label` copied an unbounded `context_len`
into a 512-byte `HkdfLabel` buffer after truncating the length to one byte, and
`hkdf_expand` built `T(i-1) | info | i` in a 512-byte scratch block with no
`info_len` bound. All current callers pass a transcript hash or an 8-byte ticket
nonce, so the paths were latent. The label builder now refuses `out_len > u16::MAX`,
label length `> u8::MAX` and `context_len > u8::MAX`; the expand refuses a hash
above `EVP_MAX_MD_SIZE` or an info that cannot fit. Control:
`ssl::tls13_enc::tests::hkdf_expand_label_refuses_a_context_that_does_not_fit_its_length_byte`.

**M13-D3 (fixed, medium).** `tls13_encrypt_record` copied `len` into a
`TLS13_HS_BUF_LEN + 1` inner buffer and wrote `len + 1 + tag_len` into a two-byte
record length with no bound on either; both record paths called `make_nonce` with
`iv_len` outside the `8..=16` range its indexing requires; `transcript_update` and
`write_handshake_message` used unchecked sums. The record layer already fragments at
16384 and fetches a 12-byte IV, so valid records are byte-identical; the guards are
checked-sum refusals. The pre-existing oversized-flight test and the SSL suite pass.

**M13-D4 (fixed, medium).** `ossl_cms_Receipt_verify` returned early on nine
post-decode refusals without releasing the `CMS_Receipt` that `ASN1_item_unpack` had
built; the authority's `err:` label frees it on every exit. The body is now a labelled
block that breaks to the shared cleanup, so repeatedly rejected receipts no longer
grow the process. Return codes and error sites are unchanged.

**M13-D5–D8 (fixed, low/medium).** `CMS_ReceiptRequest_create0_ex` refuses a negative
`idlen` (authority passes it to `ASN1_STRING_set0`); `EVP_BytesToKey` refuses a
negative `datal`, `EVP_OpenInit` a negative `ekl`, and `EVP_SealInit` checks the
context key length against the fixed 64-byte stack key before drawing it and refuses
`EVP_PKEY_get_size <= 0`; the RSA provider's sign/verify/recover paths refuse
`tbslen`/`siglen` above `c_int::MAX` instead of passing a negative `int` into the
padding routines; `SSL_add_dir_cert_subjects_to_stack` uses `checked_add` for its
path-length sum. Negative/overflowing inputs are recorded divergences; every valid
input keeps the authority's result.

**No defect found:** `src/evp/fetch.rs` (fetch half `allow(dead_code)` and matching
`evp_fetch.c`; default-property adoption/caller-free split and both render passes
correct, NULL store/name/list handled by callees) and `src/ts/ts_rsp_utils.rs`
(dup-and-replace setters, NULL-tolerant destructors, adopt/borrow edges match the
authority).

**Contracts reused.** OB-1 `OwnedBuf`, OB-3 `OwnedCtx`/destructor shape (module-local
`OwnedRsaCtx`), C-ABI exported-symbol/out-parameter/destructor contracts, provider
signature and keymgmt dispatch contracts, SSL stack ownership (`set0` adopts, `add0`
borrows, `add1` up-refs, `get1` duplicates), and ASN.1 item/`ASN1_STRING_set0`
ownership. No new unsafe abstraction, ABI/layout change or allocator-coordinate
change. New unsafe operations are test-only (three regression controls).

**Evidence.** FAST: fmt clean; focused `evp::fetch` 5/0, `ssl::tls13_enc` 2/0 + 1
ignored plus the new control, `evp::p_legacy` 4/0, `evp::pmeth_gn` 1/0, `ssl::ssl_cert`
3/0; `cms::cms_ess` and `provider::rsa_sig` have no in-module tests. BATCH: clippy
`--all-targets -D warnings` PASS; library **1600 passed / 0 failed / 27 ignored**
serially (212.44 s) and with `--test-threads=4` (87.21 s). Hidden obligations: 0.
No suite probe covers the changed units. ASan/Miri/Loom, the crafted CMS receipt
fixture, authority differentials for the refusals, the `provider/mod` boundary,
`rsa/mod`, FRF-Fuzz and SEAL regeneration are `NOT_RUN`. Machine-readable receipt:
[`atlas-refresh/mechanism-sweep-M13.json`](atlas-refresh/mechanism-sweep-M13.json).

**Next ordinary queue position:** `src/provider/mod.rs` (124) goes to the boundary
queue; the ordinary queue resumes at `src/cms/cms_pwri.rs` (128), then
`src/runtime/bio/mod.rs` (129), `src/x509/v3_pci.rs` (130). `src/rsa/mod.rs` (123)
remains the large-file deferral.

## 14. Boundary sweep B8 — provider lifecycle/registry and certificate-file callback forwarding

**STOP status: CLEAR.** No confirmed memory-safety defect, no ABI regression and no
new hidden obligation. Three `provider/mod.rs` findings (two unsafe contracts and one
safe-function raw dereference) and one B7 follow-up remained; all four are repaired.

**B8-D1 (fixed, low, contract).** `ossl_provider_store_free`'s documentation claimed
a second call on the same store is a no-op. The function clears each *field* (so a
partially built store is safe) but releases the `ProviderStore` block itself, so a
second call would be a use-after-free. The contract now requires exactly one release
per non-NULL store and names the two single-call sites; no code changed.

**B8-D2 (fixed, low, contract).** `OSSL_PROVIDER_available`'s `# Safety` allowed a
NULL `name`, but `name` is the search key passed to `ossl_provider_find`'s comparator,
which dereferences it. The contract now requires NUL termination and the forwarding
comment cites the real callee contract. Authority behaviour (a NULL name faults) is
is therefore documented rather than silently promised as supported.

**B8-D4 (fixed, low, soundness).** `predefined_row` was a **safe** function taking
`*const c_char` and dereferencing it through `c_strcmp`; the safe signature did not
require NUL termination, so safe crate code could hand it an invalid pointer. It now
takes `&CStr` and compares bytes directly; the single production caller performs the
`CStr::from_ptr` conversion inside its existing unsafe block. Behaviour is unchanged.

**B8-D3 (fixed, low, parity).** The B7 follow-up: `SSL_use_certificate_file` and
`SSL_CTX_use_certificate_file` passed `None`/NULL to `PEM_read_bio_X509`; the
authority forwards the connection's/context's default password callback
(`ssl_rsa.c:87-88`, `:338-339`). Both now forward it, matching the chain loader's
B7-D4 repair. Two regression controls load an encrypted PEM fixture and assert the
application callback was consulted (and observe 0 from the loader, since the fixture
body is not a certificate).

**Provider boundary result.** `B8-PROV-1..6` (store construction/teardown, lifecycle
and refcount, child-callback registration, find/insert race ownership, export
contracts) are `CONTRACTED`, not `SAFETY_DISCHARGED`: the retained authority
discipline includes callbacks invoked under the store lock (registration and
`create_provider_children`; the authority requires short, non-reentrant callbacks),
allocator-hook reentrancy while the store read lock is held during parameter copying,
and the store's teardown being single-call. `ossl_provider_up_ref` returning 0 after
incrementing, and the losing-race deactivate/free, match the authority; the only path
where `ossl_provider_add_to_store`'s post-insertion up-ref can fail is a child
provider, and child creation passes `actualprov = NULL`, so the dangling-store arm is
not reachable. Hidden obligations: 0. No safe Rust caller can cause UB through these
interfaces.

**Evidence.** FAST: fmt clean; focused `provider::tests` 10/0 and
`ssl::ssl_rsa::password_callback_tests` 2/0. BATCH: clippy `--all-targets -D warnings`
PASS; library **1602 passed / 0 failed / 27 ignored** serially (342.45 s) and with
`--test-threads=4` (95.04 s); affected adversarial probes
`ssl::ssl_rsa::adv_probe::self_aliasing_serverinfo_is_teed_before_realloc` and
`provider::activate::adv_probe::opbits_realloc_publishes_after_old_pair` pass under
`OPENSSL_RS_ADV_PROBE=1`. Negative control observed: reverting both PEM arguments to
`None`/NULL makes the two new controls fail with callback count 0. An extra default-
thread-count run (not a mandated gate) hit the pre-existing
`evp::method_store::tests::this_puts_only_into_a_temporary_store_and_always_destructs`
isolation failure; the mandated 1-thread and 4-thread runs are green. ASan/Miri/Loom,
full-suite sanitizers, FRF-Fuzz, independent review and SEAL regeneration are
`NOT_RUN`. Machine-readable receipt:
[`atlas-refresh/boundary-sweep-B8.json`](atlas-refresh/boundary-sweep-B8.json).

**Next ordinary position:** `src/cms/cms_pwri.rs` (128), then
`src/runtime/bio/mod.rs` (129), `src/x509/v3_pci.rs` (130). No B7 follow-up remains;
`src/rsa/mod.rs` (123) is still the large-file deferral.

## 15. Batch M14 — mechanism-contract sweep (rsa deferral, queued 128–130, four live-ranked files)

**STOP status: CLEAR after repair.** One confirmed STOP-class family: the exported RSA
padding entry points reproduced the authority's undefined behaviour for negative, wrapping
or sub-minimum lengths (`memcpy`/`memset` receiving a negated `int` as `size_t`). All nine
sites are repaired and a regression control now exercises each one. No other
memory-safety defect, ABI regression or new hidden obligation was found.

**Files audited (live attribution rank in parentheses).**

- `src/rsa/mod.rs` (134, large-file deferral) — **M14-D1–D9 (fixed, medium/low):**
  negative or `INT_MIN` lengths were passed to `memcpy`/`memset`/`EVP_Digest` by
  `RSA_padding_add_none` (:951), `RSA_padding_check_none` (:985),
  `RSA_padding_add_X931` (:1017), `RSA_padding_check_X931` (:1074, now also requires
  `flen >= 2`), `RSA_padding_add_PKCS1_type_1` (:1166),
  `ossl_rsa_padding_add_PKCS1_type_2_ex` (:1738, `tlen` wrap), `PKCS1_MGF1` (:1297,
  `seedlen`), both OAEP bodies (:1480, :2503, `plen`/`flen`) and `ossl_rsa_prf` (:2028,
  `llen`). Each guard is placed so every non-negative input keeps the authority's result
  and error coordinate; the deliberate UB divergence is recorded at the padding banner.
  No allocation/ownership defect: `RSA_meth_*` and the `OwnedBuf` scratch paths match
  `rsa_meth.c`/`rsa_oaep.c`/`rsa_pk1.c`.
- `src/cms/cms_pwri.rs` (147) — no defect. KEK wrap/unwrap length checks, the password
  arm, and the SKEY/ASN1 ownership transfers match `cms_pwri.c`.
- `src/runtime/bio/mod.rs` (154) — no defect. Creation/create-failure, free-veto reference
  consumption, `BIO_free_all`'s shared-element stop, push/pop and `BIO_dup_chain` teardown
  match `bio_lib.c` and the B1/B2 contracts.
- `src/x509/v3_pci.rs` (160) — no defect. `policy_grow`'s realloc ownership, the four
  failure releases, the file-read retry loop and the `r2i_pci` err cleanup match
  `v3_pci.c`; the freed slot is nulled so no double free is possible.
- `src/evp/exchange.rs` (74) — no defect. The raw derive buffer's plain/cleansed release
  split and the fetched SKEYMGMT release arms match `exchange.c`.
- `src/evp/e_aria.rs` (93) — no defect. GCM/CCM IV allocation, COPY re-pointing and
  cleanup match `e_aria.c`; the legacy `SET_IV_INV` ctrl arg remains the EVP_CIPHER ctrl
  contract's, as in the M7 `e_aes` result.
- `src/encoder_meth.rs` (104) — no defect. The four-clause provider-function test is
  transcribed exactly, and both `CtxDestroy` bodies release only their members.
- `src/crmf/crmf_asn.rs` (122) — no defect. Item templates and the thin
  new/free/dup/d2i/i2d wrappers forward the ASN.1 ownership contract.

**Contracts reused.** OB-1 `OwnedBuf`, OB-3 `OwnedCtx`/`CtxDestroy`, OB-4 member-buffer
slots, RC-1 refcount/destroying sentinel, B1/B2 BIO lifecycle/callback contracts, ASN.1
item/alloc/free/dup contracts, and the C-ABI exported-symbol/out-parameter/destructor
contracts. New unsafe abstractions: 0. Hidden obligations: 0.

**Evidence.** FAST: fmt clean; `rsa::` 82 passed / 0 failed / 1 ignored, including
`the_padding_entry_points_refuse_lengths_that_cannot_describe_a_block`. BATCH: clippy
`--all-targets -D warnings` PASS; library **1603 passed / 0 failed / 27 ignored** serially
(66.27 s) and with `--test-threads=4` (95.32 s). Negative-control mutation was not run
because it would inject the very `size_t::MAX` copy outside ASan; the controls are
load-bearing without it. ASan/Miri/Loom, full-suite sanitizers, FRF-Fuzz, the authority
differential for the refusal divergences and SEAL regeneration are `NOT_RUN`. Machine-
readable receipt:
[`atlas-refresh/mechanism-sweep-M14.json`](atlas-refresh/mechanism-sweep-M14.json).

**Next ordinary queue position:** `src/cms/cms_ec.rs` (168), then
`src/pkcs7/pk7_asn1.rs` and `src/x509/x_crl.rs`. The boundary queue is
`src/property/store.rs`, `src/provider/activate.rs`, `src/context/namemap.rs` and
`src/provider/ec_kmgmt.rs` (lock/callback/refcount edges), not re-opened here.

## 16. Boundary sweep B9 — property store, provider activation, namemap, EC keymgmt

**STOP status: CLEAR after repair.** One refcount/ownership defect, one OOM-path leak,
one short-circuit parity defect, one incomplete unsafe contract and five allocator-seam
coordinate defects were repaired. No memory-safety defect, ABI regression or new hidden
obligation remains; hidden = 0.

**Boundaries.** `B9-PROP-1..3` (store construction/teardown and add/remove, query cache,
do_all snapshot), `B9-ACT-1..3` (activation/deactivation and child/fallback edges, the
three-phase doall sweep, operation bitset/query surface), `B9-NAME-1..2` (map
construction/insertion/aliasing and the borrowed-name lookups) and `B9-EC-1..2` (EC/SM2
parameter import/export/get and generation/load/dup) are all `CONTRACTED`.

**Defects.**

- **B9-D7 (fixed, medium).** `ossl_provider_doall_activated` undid only from the
  callback-refusal index (leaking phase-1 raises for earlier providers) and from the
  failed index on the early-unlock path (down-refing a provider it never raised). It now
  restarts at 0 after phase 2 and at `curr + 1` after an early unlock, matching
  `provider_core.c`'s `curr = -1` / `for (curr++; ...)`. New control
  `doall_activated_undoes_every_raised_count_on_callback_refusal`; negative control
  observes 3 instead of 2 on the pre-fix shape.
- **B9-D1 (fixed, medium).** The property store's `add` error tail passed NULL to
  `alg_cleanup`, leaking the freshly allocated `ALGORITHM` (authority frees it).
- **B9-D9 (fixed, medium).** Eighteen `ok &= f()` sites in `ec_kmgmt.rs` evaluated import,
  export and validation steps the authority short-circuits; all now use
  `ok = ok && f()` semantics.
- **B9-D2/D3/D4/D6/D8 (fixed, low).** Allocator-seam corrections: store implementation
  malloc/free coordinates (337/344), `del_tmpalg` (575), namemap zalloc/free/name and
  strdup sites (554/583/51/240/257/325/329/388), provider opbits realloc (2035), and the
  EC COPY_UTF8/COPY_OCTET invocation lines (1091–1095, 1103/1104/1107).
- **B9-D5 (fixed, low).** `namemap::map_mut`'s unsafe contract now requires the write
  lock or sole pre-publication ownership and forbids retaining the reference after
  unlock; the doall callback's borrowed-name obligation is stated.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`property::store` 11/0, `context::namemap` 6/0, `provider::activate` 7/0/1 ignored.
BATCH: library **1604 passed / 0 failed / 27 ignored** serially (290.17 s) and with
`--test-threads=4` (91.96 s); `opbits_realloc_publishes_after_old_pair` passes under
`OPENSSL_RS_ADV_PROBE=1`. ASan/Miri/Loom/TSan, the B9-D1 allocation canary, early-unlock
injection, the EC authority differential, FRF-Fuzz, independent review and SEAL
generation are `NOT_RUN`. Receipt:
[`atlas-refresh/boundary-sweep-B9.json`](atlas-refresh/boundary-sweep-B9.json).

**Next ordinary position:** `src/cms/cms_ec.rs` (168), then `src/pkcs7/pk7_asn1.rs` and
`src/x509/x_crl.rs`. The B1–B9 boundary queue is closed; no known follow-up remains.

## 17. Mechanism sweep M15 — cms_ec, pk7_asn1, x_crl, x509name, cmp_protect, key_legacy, pem_pk8, ess_lib

**STOP status: CLEAR after repair.** Two error-path resource leaks and one non-faithful
`size_t` guard repaired. No memory-safety defect, ABI regression, layout change or
new hidden obligation remains; hidden = 0.

**Audited (ordinary).** `src/cms/cms_ec.rs` (168), `src/pkcs7/pk7_asn1.rs` (146),
`src/x509/x_crl.rs` (149), `src/x509/x509name.rs` (169), `src/cmp/cmp_protect.rs` (170),
`src/pem/key_legacy.rs` (173), `src/pem/pem_pk8.rs` (174), `src/ess/ess_lib.rs` (179);
ranks are production-site positions.

**Defects.**

- **M15-D1 (fixed, medium, `cms_ec.rs:137-145`).** `pkey_type2param`'s OID arm returned
  NULL when `EVP_PKEY_paramgen_init` failed without freeing the freshly created
  `EVP_PKEY_CTX`; `cms_ec.c` frees it at its single `err` label.
- **M15-D2 (fixed, low, `cms_ec.rs:611`).** The encoded-public-key length was cast to
  `c_long` before the `INT_MAX` test, so a value above `i64::MAX` would evade the
  authority's refusal and truncate at `ASN1_STRING_set0`; now compared in `usize`.
- **M15-D3 (fixed, low, `cmp_protect.rs:442-457`).** `pbmac_algor` leaked
  `OSSL_CRMF_PBMPARAMETER` on the `i2d < 0` and `ASN1_STRING_set` failure arms; both now
  free it, as `cmp_protect.c`'s `err` label does.

**No defect.** `pk7_asn1` templates/ADB/callbacks; `x_crl` layouts/templates/`crl_cb`/
`crl_inf_cb`/lookup/method surface (D2I_POST extension arm and cache frees remain
withheld as documented); `x509name` accessors/add/delete set fixup/create-by-*;
`key_legacy` shims/DHPARAMS readers/`pkey_get_*`; `pem_pk8` do_pk8pkey and readers;
`ess_lib` cert-id builders and lookup.

**Boundary-skipped (NOT_RUN).** `http/http_client.rs` (BIO callback), `params/build.rs`
(secure-heap ownership), `runtime/err.rs` (error queue), `provider/rsa_kmgmt.rs`
(provider callbacks), `evp/pkey_asn1.rs` (global method registry).

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`x_crl::` 4/0, `cms::cms_env::` 100/0/3 with `pem::`/`x509::x_name::`/`pkey_asn1::`,
and `cmp` 9/0. BATCH: library **1604 passed / 0 failed / 27 ignored** serially
(318.51 s) and with `--test-threads=4` (110.42 s). No affected `OPENSSL_RS_ADV_PROBE`
arm exists. ASan/Miri/Loom/TSan, full sanitizers, FRF-Fuzz, authority differential,
independent review and SEAL are `NOT_RUN`. Receipt:
[`atlas-refresh/mechanism-sweep-M15.json`](atlas-refresh/mechanism-sweep-M15.json).

**Next ordinary position:** `src/dsa/object.rs` (178), then `src/x509/v3_ac_tgt.rs`
(190) and down the production-site ranking.

## 18. Boundary sweep B10 — http_client, params/build, runtime/err, rsa_kmgmt, pkey_asn1

**STOP status: CLEAR after repair.** No memory-safety defect remains. One Rust data race (the global
ASN.1 method registry), one unchecked allocation-arithmetic class (parameter builder), three
allocator-seam coordinate divergences, one builder-block size divergence, one false `unsafe Sync`
marker, one RSA narrowing-cast parity defect and four contract/overflow repairs were made. Hidden
obligations = 0; no safe-Rust caller can cause UB through these modules. Receipt:
[`atlas-refresh/boundary-sweep-B10.json`](atlas-refresh/boundary-sweep-B10.json).

**Boundaries (all `CONTRACTED`, none promoted).** B10-HTTP-1/2/3 request-context ownership, nbio over
caller BIOs, and open/close callback ownership; B10-PARAM-1/2 builder lifecycle and
ordinary/secure block arithmetic; B10-ERR-1/2/3 `ERR_STATE` ownership, slot ownership and the
print/allocator-hook reentrancy edges; B10-RSA-1/2/3 object/import/export, generation context and
load/dup; B10-ASN1-1/2/3 the global method registry, method construction/copy/free and lookup/alias
tables.

**Defects.**

- **B10-D7 (fixed, medium, `pkey_asn1.rs:356`).** `app_methods` was a `static mut` pointer mutated and
  read with no synchronisation: concurrent `EVP_PKEY_asn1_add0`/lookup is a data race and therefore
  UB. It is now one `Mutex<AppMethods>` with locked count/get0/find helpers; no application callback
  runs under the lock. Loom/TSan control is `NOT_RUN`.
- **B10-D1 (fixed, medium, `params/build.rs:188`).** `size + 1`, `alloc_blocks * ALIGN`, the two block
  counters and `to_param`'s array/block sums were unchecked; an extreme caller-asserted extent could
  wrap, under-allocate and overrun in `param_bld_convert`. All are `checked_*` now. Negative control:
  disabling the push check fails `unrepresentable_value_extent_is_refused_at_push` (1 vs 0).
- **B10-D2/D4/D5 (fixed, low).** Seam coordinates: `param_build.c` and `http_client.c` are plain
  `.c` files, so their `__FILE__` carries `../../src/openssl-3.6.4/`; the builder also recorded
  line 0 at every site and the error queue recorded `NULL/0` for releases that the authority makes
  through `err_local.h:25/56/66/79/92/94` and `err.c:209`. Each site now carries its own coordinate.
- **B10-D3 (fixed, low, `params/build.rs:89`).** The inline `Vec` made the builder block 40 bytes;
  it is now `#[repr(C)]` with the `Vec` behind a pointer, matching the authority's 24 bytes. New
  size-parity test.
- **B10-D6 (fixed, low, `runtime/err.rs:453`).** `unsafe impl Sync for ErrState` was unnecessary and
  falsely claimed shareability (`thread_local!` needs only `'static`); removed.
- **B10-D8 (fixed, low, `rsa_kmgmt.rs:966`).** `nbits as c_int` was compared with 512 before the
  authority's `size_t` comparison, rejecting values `>= 2^31` the authority accepts at
  `gen_set_params`. The comparison now uses `usize`; the later `(int)` generation cast is unchanged.
- **B10-D9/D11/D12 (fixed, low).** Contracts now state `common_load`'s alignment requirement, the
  nbio rule that a custom BIO must not re-enter the same `rctx`, and `EVP_PKEY_asn1_add0`'s borrowed
  lifetime/no-unregister obligation. **B10-D10 (fixed, low)** adds `checked_add` to the four
  error-queue string sums.

**Retained residuals.** Custom BIOs must not re-enter the same request context; allocator hooks must
not re-enter the ERR API (or the ASN.1 registry, where it would deadlock); registered ASN.1 methods
and returned error strings are borrowed; `ERR_add_error_txt`'s length-bounded split is still absent;
`ERR_error_string(NULL)` keeps the authority's non-thread-safe static buffer; the builder's `Vec`
body is Rust-owned and invisible to the CRYPTO hook. These are stated at the boundaries, not hidden.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused `params::build::`
2/0, `evp::pkey_asn1::` 2/0, `runtime::err` 14/0. BATCH: library **1606 passed / 0 failed / 27
ignored** serially (227.09 s) and with `--test-threads=4` (97.95 s). No affected
`OPENSSL_RS_ADV_PROBE` arm exists. ASan/Miri/Loom/TSan, authority differentials, reentrancy
canaries, independent review and SEAL are `NOT_RUN`.

**Next ordinary position:** `src/dsa/object.rs` (178), then `src/x509/v3_ac_tgt.rs` (190). The
M15 boundary-skipped list is closed; no remaining B10 boundary item.

## 19. Mechanism sweep M16 — dsa/object, v3_ac_tgt, cmp_hdr, cms_dh, slh_dsa/dsa, dane, pcy_cache, bn/rand

**STOP status: CLEAR after repair.** One debug-build counter overflow and two too-weak
validity contracts repaired; two deliberate divergences recorded. No memory-safety defect, ABI
regression, layout change or new hidden obligation remains; hidden = 0.

**Audited (ordinary).** `src/dsa/object.rs` (178), `src/x509/v3_ac_tgt.rs` (190),
`src/cmp/cmp_hdr.rs` (191), `src/cms/cms_dh.rs` (192), `src/slh_dsa/dsa.rs` (193),
`src/x509/dane.rs` (194), `src/x509/pcy_cache.rs` (195), `src/bn/rand.rs` (196); ranks are
production-site positions. No file in this run was a new boundary.

**Defects.**

- **M16-D1 (fixed, low, `bn/rand.rs:1056`).** `ossl_bn_gen_dsa_nonce_fixed_top` incremented
  the authority's `unsigned char` digest counter with `i += 1`; a range above ~130k bits would
  panic a debug build (caught by `guard_ffi` as a spurious 0) where the authority wraps. Now
  `i.wrapping_add(1)`.
- **M16-D2/D3 (fixed, low, `pcy_cache.rs:459-461`, `:480-483`).** `ossl_policy_cache_set`'s and
  `ossl_policy_cache_find_data`'s `# Safety` sections admitted NULL for `x`/`id`, but both
  bodies (and the authority) dereference them. Contracts narrowed to live, non-NULL inputs.
- **M16-D4 (recorded, low, `dsa/object.rs:720-725`).** `DSA_set0_key` keeps `BN_clear_free` for
  the outgoing key where `dsa_lib.c:320/324` uses `BN_free`; a deliberate cleansing improvement,
  observable only to a reader of freed memory. The doc now records the divergence.
- **M16-D5 (recorded, low, `slh_dsa/dsa.rs:482-487`).** `msg_encode` clear-frees its internal
  `WPACKET`-failure block at `slh_dsa.c:309`, where the authority plain-frees it at `:278`; the
  block may hold part of a confidential message, so the cleansing improvement is kept and
  recorded.

**No defect.** `dsa/object` constructor/`DSA_free`/`DSA_dup_DH`/`set0_*`/FFC bridge; `v3_ac_tgt`
items/templates/printers/row; `cmp_hdr` getters, setters, nonces, implicitConfirm and `hdr_init`;
`cms_dh` peer key, shared info, decrypt/encrypt and envelope dispatch; `slh_dsa/dsa` sign/verify,
`msg_encode` and tree-id extraction; `dane` matrix and its cache releases; `pcy_cache` create/new/
free/find and the `pcy_map.c` transcription; `bn/rand` draw, range rejection, fixed-top and
DSA-nonce paths.

**Boundary-skipped (NOT_RUN).** None.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused `dsa::object`
2/0/2 ignored (allocator probes), `bn::rand` 7/0, `x509::pcy_cache` 1/0. BATCH: library **1606
passed / 0 failed / 27 ignored** serially (225.02 s) and with `--test-threads=4` (102.45 s). No
affected `OPENSSL_RS_ADV_PROBE` arm exists (the only probe-bearing file changed documentation
only). ASan/Miri/Loom/TSan, full sanitizers, FRF-Fuzz, authority differentials, independent review
and SEAL are `NOT_RUN`.

**Next ordinary position:** `src/rsa/ossl.rs` (197), then `src/srp/srp_lib.rs` (198) and down the
production-site ranking.

## 20. Mechanism sweep M17 — rsa/ossl, srp_lib, eng_list, ocsp_ext, ml_dsa_kmgmt, rsa/ctrl, cms_asn1, slh_dsa/key

**STOP status: CLEAR after repair.** One confirmed memory-safety defect class (dangling cached
Montgomery contexts released or used again after `RSA_set_method`) and one debug-build arithmetic
overflow were repaired; one internal contract was tightened. Hidden = 0.

**Audited (ordinary).** `src/rsa/ossl.rs` (197), `src/srp/srp_lib.rs` (198),
`src/engine/eng_list.rs` (199), `src/ocsp/ocsp_ext.rs` (200),
`src/provider/ml_dsa_kmgmt.rs` (201), `src/rsa/ctrl.rs` (202), `src/cms/cms_asn1.rs` (203),
`src/slh_dsa/key.rs` (204 cohort). No newly audited file was a new boundary.

**Defects.**

- **M17-D1 (fixed, high, `rsa/ossl.rs:2249-2270`).** `rsa_ossl_finish` released the extra-prime
  contexts and `_method_mod_{n,p,q}` but left the freed pointers in their slots. `RSA_set_method`
  calls that hook on every method transition, so a second `RSA_set_method` released the same blocks
  again, and the next private operation's `BN_MONT_CTX_set_locked` returned the dangling pointer
  from its non-NULL fast path (use-after-free). The authority has the same UB; §17 forbids
  reproducing it. Every released slot is now cleared, the deliberate divergence is recorded at the
  function, and `the_finish_hook_clears_every_slot_it_releases` is the regression/negative control.
- **M17-D2 (fixed, low, `srp/srp_lib.rs:105-119`).** `srp_Calc_xy` cast `BN_num_bytes(N)` to
  `usize` and doubled it without checking the sign; a live `BIGNUM` whose bit length overflowed the
  authority's `int` yields a negative width, whose cast and doubling panic a debug build across the
  C ABI. The function now answers the authority's allocation-failure result for a negative width,
  and its `# Safety` section requires a live (non-NULL) `N`, which is what `BN_num_bytes` reads.

**No defect.** `rsa/ossl`: method table, default-method store, blinding store/lock order, the four
crypt entry points, KDK, CRT/smooth path and lifecycle hooks. `srp_lib`: `xy`/`k` digests, client
and server key derivations, verification wrappers and the immutable `knowngN` table. `eng_list`:
list insertion/removal and RC-1 up/down pairs, dynamic-id linkage, iteration and `ENGINE_by_id`
copy/recursion arms, and the table-unregister-before-free improvement. `ocsp_ext`: the four
repeated extension families, nonce construction (DER header plus content), and the four
constructors' failure cleanup. `ml_dsa_kmgmt`: keymgmt dispatch, generated decoders, export/load,
seed-length bounded by the fixed entropy array, and the generator context's `CtxDestroy` body.
`rsa/ctrl`: named md setters/getters, padding/PSS/OAEP controls, keygen bits/pubexp/primes and the
OAEP label custody transfer. `cms_asn1`: the six item callbacks, streaming `cms_cb`, ADB/template
statics and the two shared-info encoders. `slh_dsa/key`: new/dup/free/reset, hash refcounts,
fromdata and its error cleansing, generation/entropy widths, accessors and text output.

**Boundary-skipped (NOT_RUN).** `src/runtime/thread.rs` (lock/once/TLS primitives),
`src/ssl/ssl_conf.rs` (`SSL_CONF` command dispatch), `src/pkcs12/p12_crt.rs`
(application-controlled `PKCS12_create_ex2` callback). The remaining 96-site tie-cohort file
`src/pem/pem_info.rs` is ordinary and is next in the queue.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused `rsa::ossl` 8/0
(new control included), `provider::ml_dsa_kmgmt` 1/0, `rsa::ctrl` 2/0; the other audited modules
have no test functions. BATCH (final candidate): library **1607 passed / 0 failed / 27 ignored**
serially (80.85 s) and with `--test-threads=4` (90.95 s). No affected `OPENSSL_RS_ADV_PROBE` arm
exists. ASan/Miri/Loom/TSan, full sanitizers, FRF-Fuzz, authority differentials, independent
review and SEAL are `NOT_RUN`.

**Next ordinary position:** `src/pem/pem_info.rs`, then `src/ml_kem/arith.rs`,
`src/pkcs12/p12_sbag.rs`, `src/asn1/new.rs` and `src/evp/encode.rs` in the 95/94 production-site
cohorts.

## 21. Boundary sweep B11 — thread, ssl_conf, p12_crt

**STOP status: CLEAR after repair.** Two confirmed memory-safety defect classes and one hidden
dangling-pointer obligation were repaired; p12_crt had no defect. Hidden = 0. Nothing is promoted
to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Audited (boundary).** `src/runtime/thread.rs` (B11-THR-1..4), `src/ssl/ssl_conf.rs`
(B11-SSL-1..3), `src/pkcs12/p12_crt.rs` (B11-P12-1..3).

**Defects.**

- **B11-D1 (fixed, high, `runtime/thread.rs`, condvar wait).** Both wait arms released the caller's
  mutex, waited, then set the parking flag without waiting for it to be clear. A second thread could
  take the mutex after the signal, leaving two threads believing they held it; the thread pool's
  join state and RCU's counters are mutated under that mutex. The wait now re-acquires through the
  same blocking loop as `ossl_crypto_mutex_lock`. New control
  `a_woken_waiter_waits_for_the_mutex_before_returning` fires on the pre-fix shape.
- **B11-D2 (fixed, medium, `ssl/ssl_conf.rs`, option parse).** `cmd_Protocol`/`cmd_Options`/
  `cmd_VerifyMode` stored a frame-local table's address in the long-lived `SSL_CONF_CTX` and left it
  dangling after the parse (the authority's tables are `static`). `parse_option_list` now clears
  `tbl`/`ntbl` before returning. New control
  `an_option_command_does_not_retain_its_frame_local_table` fires on the pre-fix shape.
- **B11-D3 (fixed, high, `ssl/ssl_conf.rs:183-199`, option words).** `ssl_set_option` cast the
  `c_long` cert-flag and `c_int` verify-mode pointers to `*mut u64` and wrote eight bytes; every
  VerifyMode option wrote four bytes past the `c_int`. Each class is now written through its own
  type. ASan negative control: the pre-fix widened write reported `heap-buffer-overflow` at
  `ssl_conf.rs:208`; the fixed candidate passes the same run.
- **B11-D4 (fixed, low, `runtime/thread.rs`).** `mutex_held` returned `&'static Mutex<bool>` and
  `rwlock_inner<'a>` returned a caller-chosen lifetime. Both are now higher-ranked closure helpers
  (`with_mutex_flag`, `with_rwlock_inner`), so the borrow cannot escape the call.
- **B11-D5 (fixed, low, `runtime/thread.rs`, unlock contract).** Reader ownership is not recorded,
  so a non-owner read unlock decrements the count; the documentation claimed a 0 return. The
  contract now requires the caller to hold the lock and records the authority-parity residual.

**No defect.** `thread.rs`: authority-sized rwlock block and coordinates, once/TLS/id/atomic
surface, gate-based condition variable and timed arm, sleep surface. `ssl_conf.rs`: table order and
switch indexing, prefix handling, context lifecycle and borrow capture, finish's unreachable
back-fill, cert-filename teardown. `p12_crt.rs`: bag adoption/removal, the `add_*` family's
ownership transfer, `PKCS12_create_ex2`'s callback calls (no borrow or lock held), and the
err-path release order.

**Retained.** Caller-held lock on unlock (reader attribution absent); atomic storage must not be
accessed non-atomically; `SSL_CONF_CTX` borrows the selected SSL/SSL_CTX; the unwired certificate
rows and the `SSL_PKEY_NUM`-only filename array remain for the certificate-loading subphase;
`PKCS12_create_cb` must not free the inputs or re-enter the build; a bag not found by
`pkcs12_remove_bag` stays with the caller.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; `runtime::thread` 31/0,
`ssl::ssl_conf` 2/0, `pkcs12::p12_crt` 2/0. BATCH: library **1610 passed / 0 failed / 27 ignored**
serially (61.17 s) and with `--test-threads=4` (93.90 s). ASan (pinned nightly, `-Zbuild-std`):
pre-fix overflow observed, post-fix controls clean. No affected `OPENSSL_RS_ADV_PROBE` arm exists.
Loom/TSan interleaving proof, Miri (nightly download failed on disk space), authority differentials,
FRF-Fuzz, independent review and SEAL are `NOT_RUN`.

**Next ordinary position:** `src/pem/pem_info.rs`, then `src/ml_kem/arith.rs`,
`src/pkcs12/p12_sbag.rs`, `src/asn1/new.rs` and `src/evp/encode.rs`. B1-B11 boundary queue closed;
next boundary item is the Loom/TSan control for the repaired condvar protocol at the next BOUNDARY
trigger.

## 22. Mechanism sweep M18 — pem_info, ml_kem/arith, p12_sbag, asn1/new, evp/encode, bn/arith, ml_dsa/key, p12_kiss

**STOP status: CLEAR after repair.** One confirmed aliasing/soundness defect (`BN_div` held two
live `&mut` to one object), two low-severity ASN.1-allocator fidelity/validity defects and one
CBD counted-loop divergence were repaired. Hidden = 0. Nothing is promoted to `SAFETY_DISCHARGED`
or `SAFE_COMPATIBLE`; the B1-B11 boundary queue remains closed and no boundary was audited here.

**Audited (ordinary, one line each).**

- `src/pem/pem_info.rs` (96): `PemBuf` adoption/single-release and err ordering; the
  classification loop and push/reclassify arms; the private-key `ptype` chop and raw selection; the
  `enc_data` custody transfer; the writer, including the authority's `PEM_write_bio_RSAPrivateKey`
  and `enc_len > 0` guards. No defect.
- `src/ml_kem/arith.rs` (95): hashes/sampling, scalar encode/decode, NTT, vector/matrix products,
  CBD samplers and the CPA pair. M18-D4 repaired. No memory-safety defect.
- `src/pkcs12/p12_sbag.rs` (95): selector-guarded `get0_*`, `nid`/`bag_*`, `get1_cert`/`crl`
  (plain and `_ex`), the six constructors and the PKCS8-encrypt fetch/legacy fallback. No defect.
- `src/asn1/new.rs` (95): item/template/primitive allocator, embed indirection, extern/choice/
  sequence arms, clear paths. M18-D2/D3 repaired. No defect after repair.
- `src/evp/encode.rs` (94): encode/decode state machines, the identity copy, line/padding bounds
  and every refusal arm (including `decoded_len == 0 && eof > 0`). No defect.
- `src/bn/arith.rs` (91): the add/sub/mul/div/mod/shift/inverse/gcd/exp/sqrt entry points.
  M18-D1 repaired, control added. No other defect.
- `src/ml_dsa/key.rs` (92): `OwnedBuf` and its four release modes; reset/free/dup; equality/has;
  `public_from_private`; pairwise check; keygen and the prekey comparison. No defect.
- `src/pkcs12/p12_kiss.rs` (92): `parse_pk12`/`parse_bags`/`parse_bag` ownership and the
  `PKCS12_parse` MAC/split/`ca`/err paths. No defect.

**Defects.**

- **M18-D1 (fixed, high, `bn/arith.rs:325-372`).** `BN_div` built `as_mut(dv)` and `as_mut(rem)` in
  one tuple. Its own documentation supports one object for both slots, which is two live `&mut` to
  one allocation (aliasing UB); the authority's aliased case is undefined. Inputs are now read
  through scoped shared borrows, and each output is borrowed and released in turn. The aliased
  case ends with the quotient (stored last), now documented. Control
  `div_accepts_one_object_for_both_outputs` (`17 / 5`, `dv == rem == out` -> 3).
- **M18-D2 (fixed, low, `asn1/new.rs:276-291`).** The SEQUENCE embed arm skipped
  `ossl_asn1_do_lock`, which `asn1_item_embed_new` calls for embedded values too. No in-tree item
  embeds a refcounted type (`X509`, `X509_CRL`, `X509_REQ` are pointed to), so the old shape was
  unobservable; the arm now calls it and raises `TASN_NEW_162` on refusal.
- **M18-D3 (fixed, low, `asn1/new.rs:417-427`).** `template_new` read `*pval` before the authority's
  address-only `tval = (ASN1_VALUE *)pval`; the read was unused and would be an uninitialised read
  if the slot were ever not zeroed. Removed.
- **M18-D4 (fixed, low, `ml_kem/arith.rs:1151-1163, 1192-1204`).** `gencbd_vector`/`_ntt` used a
  do-while shape: `rank == 0` sampled one scalar into an `out` documented live for zero, where the
  authority's counted loop samples none. Both now use the counted loop. Contracts for
  `inner_product`, `matrix_mult_*`, `hash_h_pubkey` and the CPA pair now state `rank >= 1` and their
  buffer widths.

**New unsafe assumptions (hidden must be 0).** None. The `BN_div` repair removes an aliasing
assumption; the CBD repair performs strictly fewer writes; the embed `do_lock` uses the contract
already exercised by the non-embed arm.

**Contracts reused.** Local `PemBuf` adoption/release; OB-1 `OwnedBuf` (four release modes);
OB-3 `OwnedCtx`/`CtxDestroy`; `OwnedBlock` ownership in `asn1/new`; the OpenSSL stack
pop-free/freefunc convention; ASN.1 item/template/ADB callback ordering; the BN null-or-live and
copy-before-store discipline; the PKCS12 selector/union and `create0_*` adoption contracts; the
ML-KEM `vinfo` rank/`du`/`dv` invariants; the `ERR` raise-coordinate and `CRYPTO_*` seam contracts.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused `evp::encode` 7/0,
`pkcs12::p12_sbag` 3/0, `bn` 83/0 plus the new `BN_div` control 1/0, `ml_dsa` 14/0, `ml_kem` 8/0;
`pem::pem_info`, `asn1::new` and `pkcs12::p12_kiss` have no test functions. BATCH (final candidate):
library **1611 passed / 0 failed / 27 ignored** serially (257.90 s) and with `--test-threads=4`
(95.72 s). No affected `OPENSSL_RS_ADV_PROBE` arm exists (only `src/asn1/utl.rs` in the ASN.1 tree
carries one, unchanged).

**NOT_RUN.** Miri (Stacked/Tree Borrows) for the `BN_div` repair and the retained read-before-write
`as_mut`+`as_ref` shape; ASan/Loom/TSan, full sanitizers, FRF-Fuzz, authority differentials for the
newly defined aliased case, independent review and SEAL. These are PENDING at the next BOUNDARY or
SEAL trigger; the boundary queue is closed.

**Retained.** The read-before-write pattern is sound under the SB/TB access order but has no Miri
witness; the same shape exists in `bn/{gf2m,mont,recp}.rs`, outside this batch. `compress`/
`decompress` require `bits` in `1..=12` (panic, not UB). `p12_sbag`'s readers require a well-formed
selector/value pair, as the authority does. No `CRYPTO_*` coordinate or `#[repr(C)]` layout changed.

**Next ordinary position:** `src/apps/smime.rs` (93), then `src/ssl/ssl_rsa.rs` (92),
`src/asn1/a_strex.rs` (91), `src/cms/cms_enc.rs` (91), `src/provider/dsa_sig.rs` (91).

---

## B12 — BN output-aliasing boundary (`gf2m`, `mont`, `recp`)

**Audited (boundary).** `src/bn/gf2m.rs` (B12-BN-GF2M-1/2), `src/bn/mont.rs`
(B12-BN-MONT-1/2/3) and `src/bn/recp.rs` (B12-BN-RECP-1/2/3). The M18-D1 class
(a tuple of `as_mut` and `as_ref` calls forming two live borrows of one allocation
when a caller aliases an output) was present in 13 production entry points and is
repaired: every operand is copied before the output is borrowed, each output is
borrowed only at store time, and every `# Safety` section now names the arguments
that may alias. Receipt: [`atlas-refresh/boundary-sweep-B12.json`](atlas-refresh/boundary-sweep-B12.json).

**Aliased-case contract.** `r` may alias `a`/`b` for the `BN_GF2m_*` arithmetic
entry points and `r` may alias `a`/`b`/`p`/`m` for `BN_to_montgomery`,
`BN_from_montgomery`, `BN_mod_mul_montgomery`, `BN_mod_exp_mont{,_consttime}` and
`BN_mod_exp_recp`. `BN_div_recp` allows `dv == rem` (remainder first, quotient
last) and either output aliasing the dividend. Context setters take type-distinct
objects; `BN_MONT_CTX_copy(to == from)` returns before forming any borrow.

**Controls.** `bn::gf2m::tests::aliased_outputs_match_the_distinct_form`,
`bn::mont::tests::aliased_outputs_match_the_distinct_form` and
`bn::recp::tests::aliased_outputs_match_the_distinct_form` compare each aliased
call with the distinct-output computation.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
controls 3/0; module filters `bn::gf2m` 6/0, `bn::mont` 1/0, `bn::recp` 2/0. BATCH:
library **1614 passed / 0 failed / 27 ignored** serially (290.33 s) and with
`--test-threads=4` (96.02 s). No affected `OPENSSL_RS_ADV_PROBE` arm exists.

**NOT_RUN.** Miri (Stacked/Tree Borrows): the court's only toolchain is
`1.98.1-x86_64-unknown-linux-gnu` and the `miri` component is unavailable (no
nightly installed). ASan/Loom/TSan, FRF-Fuzz and SEAL remain PENDING at the next
trigger. Nothing is promoted to `SAFETY_DISCHARGED`; hidden obligations in the
three audited files are 0.

**Residual (STOP for class closure).** The same tuple shape remains in
`src/bn/arith.rs` (14 sites: `BN_add`, `BN_sub`, `BN_uadd`, `BN_usub`, `BN_mul`,
`BN_sqr`, `BN_nnmod`, `BN_mod_inverse`, `BN_lshift`, `BN_rshift`, `BN_exp`,
`BN_mod_exp`, `BN_gcd`, `BN_mod_sqrt`) and was outside this batch's explicit
three-file scope. It must be the next boundary item (B13) before the class is
closed.

## B13 — BN output-aliasing boundary, remaining 14 sites (`arith`)

**Audited (boundary).** `src/bn/arith.rs` (B13-BN-ARITH-1), the 14 sites B12-R1
left open; `src/` was also swept for the same tuple shape. Receipt:
[`atlas-refresh/boundary-sweep-B13.json`](atlas-refresh/boundary-sweep-B13.json).

**Pre-fix defect.** `BN_add`, `BN_sub`, `BN_uadd`, `BN_usub`, `BN_mul`, `BN_sqr`,
`BN_nnmod`, `BN_mod_inverse`, `BN_lshift`, `BN_rshift`, `BN_exp`, `BN_mod_exp`,
`BN_gcd` and `BN_mod_sqrt` formed `(as_mut(r), as_ref(input))` in one tuple. The
authority supports those aliases, so a conforming caller created a live `&mut`
and `&` to one allocation.

**Repair.** Each operand is cloned through a shared borrow whose last use
precedes the write; the output is borrowed only at the store (`BN_mod_sqrt` at
each `finish_sqrt` exit). The module `Aliasing` section now names the exact
supported set and the preserved rejections (`BN_nnmod` `r == m`; `BN_mod_exp_simple`
`r == m`), and records the implementation-defined `BN_mod_inverse` `r == n`,
`BN_mod_exp` `r == m` and `BN_mod_sqrt` `in == p` cases.

**Controls.** `bn::arith::tests::aliased_outputs_match_the_distinct_form` covers
every repaired family (`r` aliasing each supported operand) and compares against
the distinct-output computation; `BN_nnmod` `r == m` is pinned as a rejection.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
2/0. BATCH: library **1615 passed / 0 failed / 27 ignored** with
`--test-threads=4` (91.86 s) and serially (243.70 s). No affected
`OPENSSL_RS_ADV_PROBE` arm exists.

**Escalations (no defect).** `src/bn/bignum.rs:506` (`BN_copy`, alias early
return) and `:862` (`BN_with_flags`, distinct-by-contract), and
`src/bn/mont.rs:273` (`BN_MONT_CTX_copy`, `to == from` early return), retain the
tuple shape with aliasing pre-excluded. `src/bn/blinding.rs` already reads before
the store.

**NOT_RUN.** Miri (Stacked/Tree Borrows): the pinned `1.98.1` toolchain has no
`miri` component. ASan/Loom/TSan, FRF-Fuzz and SEAL remain PENDING at the next
trigger.

**Graduation.** `CONTRACTED`; not `SAFETY_DISCHARGED` (Miri NOT_RUN, no
independent reviewer). Hidden obligations 0; no safe caller can cause UB through
the audited aliases.

---

## 23. Mechanism sweep M19 — smime, a_strex, cms_enc, dsa_sig, v3_lib, ecdsa_sig, v3_sxnet, v3_attrdesc

**STOP status: CLEAR after repair.** One confirmed memory-safety defect class (a
provider-controlled IV length overrunning the authority's `iv[EVP_MAX_IV_LENGTH]`
stack buffer) was repaired with a §17 refusal and a boundary control; four
ownership/leak divergences were repaired. Hidden = 0. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Audited (ordinary).** `src/apps/smime.rs` (93), `src/asn1/a_strex.rs` (91),
`src/cms/cms_enc.rs` (91), `src/provider/dsa_sig.rs` (91), `src/x509/v3_lib.rs`
(91), `src/provider/ecdsa_sig.rs` (90), `src/x509/v3_sxnet.rs` (89),
`src/x509/v3_attrdesc.rs` (89). `src/ssl/ssl_rsa.rs` (92) was skipped as already
audited (B7/B8). No newly audited file was a new boundary.

**Defects.**

- **M19-D1 (fixed, high, `cms/cms_enc.rs:218-235`).** `ossl_cms_EncryptedContent_init_bio`
  filled `unsigned char iv[EVP_MAX_IV_LENGTH]` with `ivlen = EVP_CIPHER_CTX_get_iv_length(ctx)`
  bytes and later copied `ivlen` bytes into `aparams.iv`, with no upper bound. A
  provider may advertise an `ivlen` above `EVP_MAX_IV_LENGTH`; the authority
  (`cms_enc.c:96-98,179`) overruns the stack buffer. The conversion now refuses
  with `ERR_R_EVP_LIB` at the authority's IV-length coordinate, recording the
  deliberate §17 divergence; `iv_length_guard_rejects_a_provider_iv_larger_than_the_buffer`
  is the positive/negative control. The end-to-end custom-provider reproducer is
  `NOT_RUN` (no overlong-IV provider harness).
- **M19-D2 (fixed, low, `apps/smime.rs:370-745`, nine sites).** The recipient
  stack was released with `OPENSSL_sk_free`, which frees only the stack array;
  `apps/smime.c:726` uses `OSSL_STACK_OF_X509_free` (pop-free with `X509_free`).
  Every certificate pushed for `-encrypt` was leaked. All sites now call
  `crate::x509::t_x509::OSSL_STACK_OF_X509_free`.
- **M19-D3 (fixed, low, `apps/smime.rs`, 17 cleanup sites).** `indata` — the
  content BIO `SMIME_read_PKCS7_ex` produces — was never freed; `apps/smime.c:744`
  releases it on every path. Each cleanup/return now frees it (NULL-safe).
- **M19-D4 (fixed, low, `apps/smime.rs:373-383`).** `OPENSSL_sk_push`'s result was
  ignored. On refusal the authority's `goto end` releases the unpushed
  certificate and the stack (`apps/smime.c:517-521,723-745`); the arm now does
  the same.
- **M19-D5 (fixed, low, `provider/ecdsa_sig.rs:926-935`).** `ecdsa_dupctx` omitted
  the authority's `kinv != NULL || r != NULL` refusal (`ecdsa_sig.c:634-638`).
  Those fields stay NULL without the ACVP arm, but a future assignment would
  make the `CRYPTO_memdup` alias two `BIGNUM`s and `freectx` release each twice.
  The refusal is restored.

**No defect.** `a_strex`: escape/width tables, counting-vs-writing passes, UTF-8
conversion, `ASN1_STRING_to_UTF8`'s reuse of the stack string, and the
`do_name_ex` separator/field-name ladder. `dsa_sig`: context create/dup/free,
digest setup and `aid_buf` copy, sign/verify paths, signature adoption and the
generated decoders. `v3_lib`: dynamic-row ownership, `ext_list` lifecycle,
search/sort, alias copy, `X509V3_get_d2i`, and `X509V3_add1_i2d`'s
replace/append/delete arms. `v3_sxnet`: add/get ownership transfer and the
partial-value cleanup. `v3_attrdesc`: the four printers and SELECTOR arms.

**Contracts reused.** RC-1, OB-1 `OwnedBuf`, OB-2 `OwnedStr`, OB-3
`OwnedCtx`/`CtxDestroy`, OB-4 member buffers, the `CRYPTO_*` seam coordinates,
the stack pop-free/element-destructor convention, the `i2s` callback ownership
contract, and the provider dispatch/ctx-dup contracts established in M7/M8.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`cms::cms_enc` 1/0 (new control), `x509::v3_lib` 1/0; the other six modules have
no test functions. BATCH (final candidate): library **1616 passed / 0 failed /
27 ignored** serially (260.36 s) and with `--test-threads=4` (110.53 s). No
audited file carries an `OPENSSL_RS_ADV_PROBE` arm, so no adversarial probe was
affected.

**NOT_RUN.** Miri (Stacked/Tree Borrows), ASan/Loom/TSan, the custom-provider
overlong-IV reproducer for M19-D1, curve25519/Wycheproof and other cryptographic
courts, FRF-Fuzz, authority differentials for the newly defined IV refusal,
independent review and SEAL. `src/property/store.rs` (93) and
`src/http/http_client.rs` (92) remain BOUNDARY and were not selected.

**Next ordinary position:** `src/ec/curve25519.rs` (90, security-sensitive
algorithm; vectors `NOT_RUN`), then `src/x509/x509_v3.rs` (89),
`src/runtime/conf/api.rs` (89) and `src/dso/mod.rs` (89).

## 24. Mechanism sweep M20 — curve25519, x509_v3, conf/api, dso, ec/asn1, d2i_pr, dsa/ossl, e_chacha20_poly1305

**STOP status: CLEAR after repair.** One confirmed double-free/use-after-free on the DSA
lifecycle pair and one confirmed caller-length truncation feeding an out-of-bounds
`strlen` were repaired. Hidden = 0. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`; no audited file was a newly discovered boundary.

**Audited (ordinary, one line each).** Rank values are production-site positions.

- `src/ec/curve25519.rs` (90): the ten perlasm field primitives and their pointer
  contracts; `fe64`/`fe51`/`fe` arithmetic ranges; `ge_*` group operations and the
  masked table select; the scalar reduction; and the six `ossl_*` exports with their
  cleanse and output-before-`CRYPTO_memcmp` order. No defect. Constant-time and RFC
  7748/8032 vectors are `NOT_RUN` (the in-module RFC vectors were not re-run as a
  cryptographic court).
- `src/x509/x509_v3.rs` (89): count/find/get/delete/add, the replace loop of
  `X509v3_add_extensions`, the two `X509_EXTENSION_create_by_*` ownership arms and the
  four accessors. No defect; a NULL stack element is outside the declared extension-stack
  contract and the authority dereferences it the same way.
- `src/runtime/conf/api.rs` (89): `OwnedValue`'s four release arms, `_CONF_add_string`'s
  push-then-insert/pop-replaced order, both free walks, `_CONF_new_section`'s partial
  construction, and the lookup/getenv ladder. No defect. Observation: `_CONF_free_data`
  releases `includedir` before the `data == NULL` early return, where the authority
  returns first; unreachable through the public API (only a successful load creates
  `includedir`, which has already created `data`), so not changed.
- `src/dso/mod.rs` (89): the `OwnedCtx<Dso>` destructor body, refcount-gated
  `DSO_free` (including finish-hook re-entry), the load refusal ladder, bind/ctrl/merge/
  filename and the two address lookups. No defect.
- `src/ec/asn1.rs` (87): `Packet`, DER integer/length/DSA-signature codecs, the
  ECDSA_SIG and ECPKPARAMETERS/ECPrivateKey i2d/d2i paths, the group `fieldid`/`curve`
  builders and the point codecs. No defect.
- `src/asn1/d2i_pr.rs` (86): the provider-first/legacy-second decode, the mark pair,
  `err_out`/`decoder_err_out` identity tests and the element-count fallback. M20-D1
  repaired.
- `src/dsa/ossl.rs` (86): the blinded sign loop, nonce setup, verify's range/zero
  refusals, the modexp dispatch and both lifecycle hooks. M20-D2 repaired.
- `src/evp/e_chacha20_poly1305.rs` (86): the two AEAD blocks, the TLS fast path's
  aligned scratch and zero-padding, the counter carry, the tag/AAD ctrls, copy and
  cleanup. No defect; AEAD vectors and timing are `NOT_RUN`.

**Defects.**

- **M20-D1 (fixed, medium, `asn1/d2i_pr.rs:78-91,220-232`).** `d2i_PrivateKey_ex`'s
  `long` length reached `OSSL_DECODER_from_data` as a `size_t` and then
  `BIO_new_mem_buf`'s `int`; a negative or not-`int`-sized length truncated to a
  negative `int`, whose BIO spelling is "strlen the buffer" (out-of-bounds read). The
  legacy callback also received `length as c_int`. Both entry points now refuse a
  length outside `0..=INT_MAX` before dereferencing the cursor, a deliberate divergence
  on invalid input. Control
  `asn1::d2i_pr::tests::a_length_outside_int_range_is_refused_before_any_read`.
- **M20-D2 (fixed, high, `dsa/ossl.rs:974-995`).** `dsa_finish` freed
  `dsa->method_mont_p` but left the freed pointer installed. `DSA_set_method` runs the
  outgoing table's `finish`, and `DSA_free` runs the table's `finish` again through
  `CtxDestroy::destroy_body`, so a cached Montgomery context was released twice
  (double free / use-after-free). The hook now clears the slot; the authority leaves it
  dangling, so this is a recorded §17 divergence (the M17-D1 class). Control
  `dsa::ossl::tests::the_finish_hook_clears_the_mont_cache_it_releases`.

**New unsafe assumptions (hidden must be 0).** None. M20-D2 removes an implicit
"the freed cache stays installed" assumption; M20-D1 removes an implicit "`long` fits
`int`" assumption at two call sites. No new unsafe abstraction, exported signature,
`#[repr(C)]` layout or `CRYPTO_*` coordinate changed.

**Contracts reused.** RC-1 reference-count gate; OB-1 `OwnedBuf` (plain and cleansed);
OB-2 `OwnedStr`; OB-3 `OwnedCtx`/`CtxDestroy` and `RawCtx` zeroed construction; OB-4
member-buffer slots; the ASN.1 `i2d`/`d2i` cursor and embedded-`value` conventions;
`EVP_CIPHER` `init`/`do_cipher`/`ctrl`/`cleanup` contracts; the `CRYPTO_*` seam
coordinates.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`asn1::d2i_pr` 1/0 (new control) and `dsa::ossl` 1/0 (new control); the other six
modules have no test functions. BATCH (final candidate): library **1618 passed / 0
failed / 27 ignored** serially (64.71 s) and with `--test-threads=4` (92.53 s). No
audited file carries an `OPENSSL_RS_ADV_PROBE` arm, so no adversarial probe was
affected.

**NOT_RUN.** Miri (Stacked/Tree Borrows), ASan/Loom/TSan, RFC 7748/8032 and AEAD
vector/Dudect courts for curve25519 and ChaCha20-Poly1305, FRF-Fuzz, authority
differentials for the M20-D1/M20-D2 divergences, independent review and SEAL.

**Next ordinary position:** `src/ml_dsa/poly.rs` (86), then
`src/asn1/a_mbstr.rs` (85), `src/asn1/string.rs` (85) and
`src/property/strings.rs` (85); `src/provider/mac_legacy_kmgmt.rs` (86) is a provider
callback boundary and was not selected.

## 24. Boundary sweep B14 — provider MAC callback boundary and the finish-hook class

Receipt: [`atlas-refresh/boundary-sweep-B14.json`](atlas-refresh/boundary-sweep-B14.json).
Candidate `13dcc552f`; two items, one repair.

**STOP status: CLEAR.** The freed-but-not-cleared finish-hook class is closed crate-wide.
`rsa_ossl_finish` (M17-D1) and `dsa_finish` (M20-D2) were already repaired; B14 found and
repaired the last instance, `dh_finish`.

| file | boundaries | disposition | defect / residual |
|---|---|---|---|
| `src/provider/mac_legacy_kmgmt.rs` | `B14-MK-1..4` (key refcount/ownership, member replacement, generator/transfer, export callback reentrancy) | `CONTRACTED` | **none (no UB)**. `B14-R1`: repeated `mac_gen_set_params` leaks the previous secure key, exactly as authority `:425` does; documented at the site, preserved, not a safety defect. |
| `src/dh/key.rs` | `B14-DH-1` (DH method finish cache) | `CONTRACTED` | **B14-D1 (fixed, high):** `dh_finish` freed `method_mont_p` without clearing it; `DH_set_method` and `DH_free` both run the hook, so a transition + free double-released and the next key operation used freed storage. The slot is now cleared after release. Control `dh::key::tests::the_finish_hook_clears_the_mont_cache_it_releases`; the control was observed to fail with the clear removed. |

**Sweep.** Every `*_finish` hook and every `finish:` table entry was examined. Only
RSA/DSA/DH release a reusable cached slot; RSA and DSA were already repaired and DH is
repaired here. EC group/point finish hooks free owned field elements without clearing them,
but are reached exactly once from the owning `OwnedCtx` destructor immediately before the
block is released (no reuse), so they are closed by exact-once proof. EC_KEY/DSO `finish`
hooks are application-owned and all built-in EC tables leave them `None`. Engine/conf/DSO
lifecycle hooks release through refcounts or free the enclosing record; `WPACKET_finish`
already clears its slot; the remaining `finish` symbols are AEAD finalisers, builder methods
or test fixtures.

**New unsafe assumptions (hidden must be 0).** None. One raw slot write (NULL) was added
inside `dh_finish`'s existing audited unsafe block. No export, signature, `#[repr(C)]`
layout, allocator-seam coordinate or unsafe lint attribute changed. No safe caller can cause
UB through the audited interfaces.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; DH control 1/0 and
provider zero-state sweeps 2/0. BATCH: library **1619 passed / 0 failed / 27 ignored**
serially (316.49 s) and threaded (99.38 s); 0 newly ignored, 0 removed, one test added.
No audited file carries an `OPENSSL_RS_ADV_PROBE` arm.

**NOT_RUN.** Miri (Stacked/Tree Borrows; `cargo miri` unavailable on the court's 1.98.1
toolchain), ASan/Loom/TSan, the authority differential for the DH slot-clear divergence,
independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next ordinary position:** no B14 follow-on; the file-level queue is empty at `e48a1b519`
(`PROGRESS.md:1520`). The last recorded ordinary list remains `src/ml_dsa/poly.rs` (86),
then `src/asn1/a_mbstr.rs` (85), `src/asn1/string.rs` (85) and
`src/property/strings.rs` (85).

## 25. Queue reconciliation and mechanism sweep M21 — 2026-10-19

**Reconciliation (corrects the “queue empty” reading of `PROGRESS.md:1520`).**

| measure | count |
|---|---:|
| Rust source files under `src/` | 877 |
| census files in `ATTRIBUTION.md` | 868 |
| `PARTIAL` files (the audit denominator) | 761 |
| `ZERO_UNSAFE` / `BOUNDARY_COVERED` | 92 / 15 |
| **files with a recorded audit** | **211** |
| — recorded as `PARTIAL` / `BOUNDARY_COVERED` | 208 / 3 |
| **total remaining** | **666** |
| **remaining `PARTIAL` files** | **553** |

`211` is the union of (a) the 199 distinct files named in structured receipt
fields — `.files` in `mechanism-sweep-M*.json` and `boundaries[].file` /
`sweep[].site` in `boundary-sweep-B*.json` — and (b) the 12 M1 files, whose
receipt `mechanism-sweep-M1.json` has an empty `files` array and whose audit
exists only in section 3a above. `unsafe-census.json` and `attribution.json`
name all 868 census files and are **not** audit records. The 20 index paths
absent from the structured receipts are next-queue and caller mentions, not
audits (for example `a_mbstr`, `string`, `property/strings`, `ml_dsa/poly`).

`PROGRESS.md:1520-1521` says the *file-level ownership conversion* queue is
empty; `:1523-1527` immediately names the next queue as the **761 `PARTIAL`
files** for per-file obligation audit. B14 quoted only the first sentence. The
conversion queue is empty; the obligation-audit queue is not.

**M21 audited files (8).**

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/digest/sha2.rs` | 32/64-bit counters, staging extents, Final padding, one-shot | No defect. |
| `src/digest/md32.rs` | shared `HASH_UPDATE`/`HASH_FINAL` collector | No defect. |
| `src/mac/cmac.rs` | staged allocation, cleanup/cleanse, copy, init arms, burst arithmetic, Final | No defect. |
| `src/evp/p5_crpt2.rs` | PBKDF2 params, NULL normalisations, error-tail cleanse, fetch releases | No defect. |
| `src/des/mod.rs` | key schedule, c2l/l2cn, string keys, all mode loops | No defect; the unsigned `l = length` is authority-faithful. |
| `src/asn1/string.rs` | `OwnedBlock`, embed/NDEF free, copy/dup/set0, joined UTF-8 text | **M21-D1 and M21-D2 fixed.** |
| `src/asn1/i2d.rs` | two-pass sizing, SET OF scratch/sort, template sums, primitive copy | **M21-D3 fixed.** |
| `src/x509/x509_req.rs` | `X509_to_X509_REQ`, extension decode/add/replace tails | No defect. |

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M21-D1 | `src/asn1/string.rs:264` | medium | negative length mistaken for a large capacity; resize skipped, copy overflows | negative arm reallocates; control `asn1::string::tests::a_negative_length_forces_the_set_to_reallocate` |
| M21-D2 | `src/asn1/string.rs:800-824` | low | unchecked joined-length sum/`+1` used for allocation (§3) | `checked_add` and `usize::try_from`; negative element length refuses |
| M21-D3 | `src/asn1/i2d.rs:724` | medium | negative content length copied as a huge extent | copy requires `len > 0`; authority's UB not reproduced (§17) |

**New unsafe assumptions (hidden must be 0).** None. No production `unsafe`
operation, adoption, release site, allocator coordinate, `#[repr(C)]` layout,
export or lint attribute changed. One test-only unsafe block was added for the
M21-D1 control.

**Gates.** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D
warnings` PASS; library **1620 passed / 0 failed / 27 ignored** serially
(228.44 s) and with `--test-threads=4` (92.72 s). Focused: `asn1::string` 2/0,
`x509::x509_req` 3/0, `des::` 28/0, `mac::cmac` 3/0, `digest::` 66/0,
`evp::p5_crpt2` 3/0; `asn1::i2d` has no test functions. No affected
`OPENSSL_RS_ADV_PROBE` arm exists.

**NOT_RUN.** Miri, ASan/Loom/TSan, a runtime witness for M21-D2, authority
differentials for the three §17 divergences, independent review and SEAL.
Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch (truthful remaining set).** `src/asn1/tasn_prn.rs`,
`src/cms/cms_kemri.rs`, `src/ct/ct_oct.rs`, `src/runtime/conf/lib.rs`,
`src/encoder_lib.rs`, `src/pem/pem_all.rs`, `src/bn/primes.rs`,
`src/ts/ts_rsp_print.rs`. Retained boundaries (NOT_RUN):
`src/asn1/bio_asn1.rs`, `src/provider/ecx_kmgmt.rs`,
`src/provider/cipher_gcm.rs`.

Receipt:
[`atlas-refresh/mechanism-sweep-M21.json`](atlas-refresh/mechanism-sweep-M21.json).

## 26. Mechanism sweep M22 — 2026-10-19

Source HEAD `5172780d9`; branch `integrate/safe-c33`; worktree dirty
(`src/ct/ct_oct.rs`, this section and the M22 receipt). Eight ordinary files from
the M21-named batch; no newly discovered boundary.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/asn1/tasn_prn.rs` | item/template walk, primitive dispatch, BN hex/decimal printer | No defect. |
| `src/cms/cms_kemri.rs` | KEM init/getters/set_ukm, KDF derive, `cms_kek_cipher`, encapsulate/decapsulate transfers | No defect. |
| `src/ct/ct_oct.rs` | cursor codecs, `o2i`/`i2o` SCT and signature bounds, SCT-list extents, OCTET STRING wrappers | **M22-D1 fixed.** |
| `src/runtime/conf/lib.rs` | `CONF_set_nconf`, NCONF new/free/data, get_string/number, stack `Conf` | No defect. |
| `src/encoder_lib.rs` | to_bio/fp/data, instance zalloc/free, recursive `encoder_process`, labeled printers | No defect. |
| `src/pem/pem_all.rs` | codec shims, plain PEM_ASN1 writers, provided-key encoder/legacy fallback | No defect. |
| `src/bn/primes.rs` | named-prime caches, Miller-Rabin, sieves, `OwnedMods`, prime/X9.31 generation | No defect. |
| `src/ts/ts_rsp_print.rs` | status/failure tables, TST info printers, GENERAL_NAME stack lifetime | No defect. |

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M22-D1 | `src/ct/ct_oct.rs:408,416,427,454,522,794` | low (defensive) | three unchecked length sums used as encoding/allocation extents: `4+sig_len`, `43+ext_len+4+sig_len`, `len2+2+sct_len` (§3) | `checked_add` helpers; overflow answers `-1`; control `ct::ct_oct::tests::encoded_length_sums_are_checked` |

**Contracts reused.** RC-1 (`raise_site`/`guard_ffi`), OB-1 `OwnedBuf`/
`OwnedBlock`, OB-3 `OwnedCtx`/`CtxDestroy`, OB-4 member-buffer slots, and the
established callback contracts for encoder construct/cleanup/encode/passphrase,
ASN1 item print/aux, and `CONF_METHOD` hooks (raw-pointer dispatch, no Rust
borrow across the call; retained, not newly modelled). Two pre-existing
observations are recorded rather than changed: `cms_kemri`'s failure-path output
buffer is cleansed (the 3.6.4/4.0.3 authority plain-frees it; the source comment
says `OPENSSL_clear_free`, which is inaccurate), and `i2d_SCT_LIST` relies on
`ASN1_OCTET_STRING_it`'s non-NDEF identity so only `data`/`length` are read from
its partially initialised stack value.

**New unsafe assumptions (hidden must be 0).** None. No production `unsafe`
operation, adoption, release site, allocator coordinate, `#[repr(C)]` layout,
export or lint attribute changed. Unsafe operations introduced/removed/relocated:
0/0/0. The only new code is three safe helpers and their test.

**Gates.** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D
warnings` PASS; library **1621 passed / 0 failed / 27 ignored** serially (211.28
s) and with `--test-threads=4` (128.84 s). Focused: `ct::ct_oct` 1/0,
`asn1::tasn_prn` 1/0, `bn::primes` 21/0, `encoder_lib` 4/0. No affected
`OPENSSL_RS_ADV_PROBE` arm exists.

**NOT_RUN.** Miri, ASan/Loom/TSan, the authority differential for M22-D1's
wraparound refusal, independent review and SEAL. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch (remaining ordinary set).** `src/rsa/gen.rs` (143),
`src/ocsp/ocsp_asn.rs` (135), `src/x509/by_dir.rs` (122), `src/packet.rs` (105),
`src/store/store_register.rs` (104), `src/passphrase.rs` (104),
`src/dh/object.rs` (103), `src/ml_dsa/poly.rs` (86). Excluded as retained
boundaries: `src/async/async.rs` (143), `src/evp/keymgmt_lib.rs` (140),
`src/provider/decode_der2key.rs` (121), `src/engine/eng_table.rs` (129),
`src/store/store_meth.rs` (127).

Receipt:
[`atlas-refresh/mechanism-sweep-M22.json`](atlas-refresh/mechanism-sweep-M22.json).

## 27. Mechanism sweep M23 — 2026-10-19

Source HEAD `42102cec4`; branch `integrate/safe-c33`; worktree dirty
(`src/packet.rs`, `src/passphrase.rs`, `src/ml_dsa/poly.rs`, this section and the
M23 receipt). Eight ordinary files from the M22-named batch; no newly discovered
boundary.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/rsa/gen.rs` | `OwnedBuf` calloc seam, `sk_BIGNUM` free thunks, multiprime keygen BIGNUM/stack lifetimes, pairwise self-test block, deprecated `RSA_generate_key` triple ownership | No defect. |
| `src/ocsp/ocsp_asn.rs` | static `ASN1_ITEM` templates and descriptors (sequence and choice), item new/d2i/i2d/free boilerplate | No defect. |
| `src/x509/by_dir.rs` | OB-3 `OwnedCtx`/`RawCtx` records and zero state, OB-4 stack slots, `sk` thunks, registry lock discipline, hashed lookup path | No defect. |
| `src/packet.rs` | `OwnedSub` zalloc/adopt, reserve/grow arithmetic, length encoding, QUIC vlint, `Packet` cursor | **M23-D1 fixed.** |
| `src/store/store_register.rs` | `RUN_ONCE` registry, atomic stack publication, rwlock, loader `OwnedCtx` zalloc, register/get/unregister/do-all | No defect. |
| `src/passphrase.rs` | `UiScratch` owned scratch, UI buffer extents, cache realloc/copy, callback dispatch order, clear/set transitions | **M23-D2 and M23-D3 fixed.** |
| `src/dh/object.rs` | OB-3 `RawCtx`/`OwnedCtx` `Dh`, refcount gate, clear-free member slots, FFC parameters, setters | No defect. |
| `src/ml_dsa/poly.rs` | safe-interior polynomial/vector/matrix ops, member-pair `VectorBuf`, checked allocation seams, slice views, expand-mask seed handling | **M23-D4 fixed.** |

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M23-D1 | `src/packet.rs:305` | low (defensive) | unchecked `lenbytes + len` used as the sub-packet reserve extent (§3) | `checked_add`; overflow answers 0; control `packet::tests::an_overflowing_sub_packet_extent_is_refused` |
| M23-D2 | `src/passphrase.rs:516` | low (defensive) | unchecked `pass_size + 1` used for both UI buffer allocations and their cleansing extents (§3) | `checked_add`; overflow refuses with the invalid-argument site; `UiScratch` stores the checked size |
| M23-D3 | `src/passphrase.rs:680` | medium | callback-reported `*pass_len` trusted as a copy/cleanse/allocation extent and `len + 1` unchecked, so a contract-breaking callback could read out of bounds and overflow the cache (§3, §21) | bound the reported length by `pass_size` and use `checked_add`; cleanse and refuse on violation; control `passphrase::tests::an_overlong_callback_length_is_refused` |
| M23-D4 | `src/ml_dsa/poly.rs:364` | low | `vector_copy` enforced shape equality only with `debug_assert!`, so the release `memcpy` could write past `dst` on a shape mismatch (§21.4) | release-level `assert_eq!`; authority's `NDEBUG` UB not reproduced (§17) |

**Contracts reused.** RC-1 (`raise_site`/`guard_ffi`), OB-1
`OwnedBuf`/`OwnedBlock`, OB-3 `OwnedCtx`/`RawCtx`/`CtxDestroy` and their
zero-state sweeps, OB-4 member-buffer slots, the ASN.1 item/template and
`i2d`/`d2i` conventions, the `BN_GENCB`/`OSSL_SELF_TEST` callback contract, the
`UI_METHOD` and `pem_password_cb` dispatch contracts, and the store-loader
do-all callback contract. No new model was introduced for a repeated pattern.

**Retained observations.** `rsa/gen.rs`'s pairwise test indexes
`plaintxt_len - 1` without a positivity check; the argument is only reachable
after a successful key generation and `pairwise_test` is never set on this
profile, so the existing precondition is recorded rather than changed.
`x509/by_dir.rs` keeps the authority's `int` path-length sum; `BIO_snprintf`
truncates safely and `BUF_MEM_grow` refuses the wrapped extent, so no
out-of-bounds access follows. `ml_dsa/poly.rs` keeps `k * l` in
`matrix_as_slice`; the matrix dimensions come from fixed parameter sets and a
wrapped length only shortens the slice, so it is not a memory-safety extent.

**New unsafe assumptions (hidden must be 0).** None. No production `unsafe`
operation, adoption, release site, allocator coordinate, `#[repr(C)]` layout,
export or lint attribute changed. Unsafe operations introduced/removed/relocated:
0/0/0. The two new controls are test-only safe code.

**Gates.** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D
warnings` PASS; library **1623 passed / 0 failed / 27 ignored** serially (62.32
s) and with `--test-threads=4` (83.87 s). Focused: `rsa::gen` 6/0, `ocsp` and
`store::store_register` have no test functions, `x509::by_dir` 3/0, `dh::object`
1/0 with 2 ignored allocator probes, `ml_dsa` 14/0, `passphrase` 10/0, `packet`
3/0; `ml_dsa::poly` has no test functions. No affected `OPENSSL_RS_ADV_PROBE`
arm exists for the three changed files.

**NOT_RUN.** Miri (Stacked/Tree Borrows), ASan/Loom/TSan, authority
differentials for the four §17 divergences, independent review and SEAL.
Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch (remaining ordinary set).** `src/property/strings.rs` (85),
`src/asn1/a_mbstr.rs` (85), `src/evp/e_des3.rs` (84), `src/ct/ct_log.rs` (83),
`src/cms/cms_rsa.rs` (82), `src/asn1/utl.rs` (81), `src/evp/e_camellia.rs` (80),
`src/asn1/text.rs` (79). Excluded as retained boundaries or shared callback
surfaces: `src/provider/mac_legacy_kmgmt.rs` (86), `src/engine/eng_lib.rs` (84),
`src/x509/x509_trust.rs` (84), `src/provider/slh_dsa_kmgmt.rs` (83),
`src/provider/ecx_kem.rs` (83), `src/ec/backend.rs` (82), `src/runtime/stack.rs`
(80), plus the five boundaries named in M22.

Receipt:
[`atlas-refresh/mechanism-sweep-M23.json`](atlas-refresh/mechanism-sweep-M23.json).

## 28. Mechanism sweep M24 — 2026-10-19

Source HEAD `8bad5f292`; branch `integrate/safe-c33`; worktree dirty
(`src/property/strings.rs`, `src/asn1/a_mbstr.rs`, `src/evp/e_des3.rs`,
`src/ct/ct_log.rs`, `src/cms/cms_rsa.rs`, `src/asn1/utl.rs`,
`src/evp/e_camellia.rs`, `src/asn1/text.rs`, this section and the M24 receipt).
Eight ordinary files from the M23-named batch; no newly discovered boundary.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/property/strings.rs` | `OwnedData`/`OwnedString` seams, self-referential `PROPERTY_STRING` layout, lhash hash/cmp/free thunks, rwlock intern race, reverse-lookup stack arithmetic | **M24-D5 fixed** (low). |
| `src/asn1/a_mbstr.rs` | `traverse_string` callback contract, `in_utf8`/`out_utf8`/`type_str`/`cpy_*` C callbacks, output extent arithmetic, `ASN1_STRING_set0` ownership | No defect; matches 3.6.4 (including `>=` and the `--*pidx` undo). |
| `src/evp/e_des3.rs` | `EVP_CIPHER` statics, `DesEdeKey` cipher-data block, CBC/OFB/CFB/ECB loops, CMS 3DES wrap/unwrap in-place path | **M24-D1 fixed** (high, UB). |
| `src/ct/ct_log.rs` | OB-3 `OwnedCtx`/`CtxDestroy` records and zero-state sweep, `OwnedBuf::adopt_plain_nullable`, `OwnedStr` adoption, CONF loader callback, log-ID lookup | **M24-D2 fixed** (high, OOB read). |
| `src/cms/cms_rsa.rs` | CMS signer/recipient dispatch, `X509_ALGOR` ownership, OAEP parameter pack/unpack, label `OwnedBuf`, provider `algorithm-id` stack buffer | **M24-D3 fixed** (medium, defensive bound). |
| `src/asn1/utl.rs` | choice selectors, refcount protocol (`REF_DESTROYING`), encoding-cache save/restore, ADB resolution, existing allocator negative control | No defect; `do_lock(op=0)` matches the authority's unconditional lock allocation. |
| `src/evp/e_camellia.rs` | provider-replaced legacy statics, block/stream callback views, CBC/ECB/OFB/CFB1/8/128/CTR callbacks | No defect; matches 3.6.4. |
| `src/asn1/text.rs` | `i2t`/`i2a` writers, `OwnedBuf` clear_realloc/realloc readers, line scanning and shift-or accumulation | **M24-D4 fixed** (medium, §3 overflow). |

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M24-D1 | `src/evp/e_des3.rs:604` | high (UB) | `des_ede3_unwrap`'s in-place arm reproduced the authority's `in -= 8` (`e_des3.c:335`), forming an out-of-bounds raw pointer before the later `+ 8` cancelled it; pointer arithmetic outside the allocation is UB in Rust (§2, §17) | compute `mid`/`last` directly: in-place `(in, in+inl-16)`, otherwise `(in+8, in+inl-8)`; same addresses, no out-of-bounds pointer; control `evp::e_des3::tests::in_place_unwrap_round_trips` |
| M24-D2 | `src/ct/ct_log.rs:687` | high (OOB read) | `CTLOG_STORE_get0_log_by_id` passed the caller's `log_id_len` to `memcmp` against the fixed 32-byte `log_id`, so a length above 32 read past the field (the authority's own UB at `ct_log.c:330`) (§1, §17) | refuse `log_id_len != CT_V1_HASHLEN` and compare 32 bytes; documented compatibility delta (NULL for a length the authority reads out of bounds); control `ct::ct_log::tests::an_over_long_log_id_is_refused_without_reading_past_the_field` |
| M24-D3 | `src/cms/cms_rsa.rs:140` | medium (defensive) | `EVP_PKEY_CTX_get_params` provider-reported `return_size` was trusted for a 128-byte stack `aid` buffer before `d2i_X509_ALGOR` (§21.1, provider trust boundary) | bound `aid_len` by `aid.len()`; a conforming provider is unchanged, a non-conforming one is refused |
| M24-D4 | `src/asn1/text.rs:500,690` | medium (defensive) | `a2i_ASN1_INTEGER`/`a2i_ASN1_STRING` used the authority's signed `num + i` and `num + i * 2` as a growth test and allocation extent; wrap on a multi-gigabyte input could skip growth and write past the block (§3) | `checked_add` for the new count and the growth extent; overflow answers `0` (the reader's failure outcome) |
| M24-D5 | `src/property/strings.rs:567` | low (defensive) | reverse lookup computed `idx - 1` on a caller-supplied `int`; `INT_MIN` panics in debug builds and is signed-overflow UB in the authority (§3) | `wrapping_sub(1)`; every non-minimum index is unchanged and index 0 still asks for `-1` |

**Contracts reused.** RC-1 (`raise_site`/`guard_ffi`), OB-1
`OwnedBuf`/`OwnedBlock`, OB-2 `OwnedStr`, OB-3
`OwnedCtx`/`RawCtx`/`CtxDestroy` and the zero-state sweep, OB-4 member-buffer
slots, the `ASN1_STRING` ownership convention, the `EVP_CIPHER` legacy callback
contract, and the CMS/`X509_ALGOR` ownership transitions. No new model was
introduced for a repeated pattern.

**New unsafe assumptions (hidden must be 0).** None. No production allocation
coordinate, `#[repr(C)]` layout, export or lint attribute changed. Unsafe
operations introduced/removed/relocated: 0/1 (the `in_.sub(8)` pointer
computation)/0. The new controls are test-only code; `Ctlog`/`CtlogStore` are
constructed from plain-data fields and never released by the test.

**Gates.** `cargo fmt --all -- --check` PASS; `cargo clippy --all-targets -- -D
warnings` PASS; library **1625 passed / 0 failed / 27 ignored** serially (230.23
s) and with `--test-threads=4` (87.75 s). Focused: `e_des3` 2/0 (new in-place
control), `ct_log` 4/0 (new over-long-ID control plus three zero-state sweeps),
`property::strings` 3/0, `e_camellia` 1/0, `asn1::utl` 0/1 ignored allocator
probe (unchanged); `a_mbstr`, `cms_rsa`, `asn1::text` have no test functions.

**NOT_RUN.** Miri (Stacked/Tree Borrows) on the new in-place control, ASan/Loom,
authority differentials for the two §17 divergences (in-place pointer spelling
is address-identical; the log-ID length guard changes only the out-of-bounds
case), independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED`
or `SAFE_COMPATIBLE`.

**Next 8-file batch (remaining ordinary set, descending production sites).**
`src/runtime/bio/bf_lbuf.rs` (78), `src/provider/seed_src.rs` (78),
`src/asn1/x_algor.rs` (77), `src/x509/x509_set.rs` (77),
`src/provider/ec_kem.rs` (77), `src/runtime/str.rs` (77),
`src/provider/mlx_kmgmt.rs` (75), `src/provider/ml_dsa_codecs.rs` (75). Triage the
four provider files first: if one is a genuinely new callback boundary, record it
`NOT_RUN` and substitute the next ranked ordinary file
(`src/provider/core_dispatch.rs` (75), then `src/provider/exchange.rs` (74)).
Skipped as already swept or retained boundaries: `src/ec/smpl2.rs` and
`src/mac/hmac.rs` (75, already covered), `src/provider/mac_legacy_kmgmt.rs`,
`src/engine/eng_lib.rs`, `src/x509/x509_trust.rs`,
`src/provider/slh_dsa_kmgmt.rs`, `src/provider/ecx_kem.rs`, `src/ec/backend.rs`,
`src/runtime/stack.rs`, `src/async/async.rs`, `src/evp/keymgmt_lib.rs`,
`src/provider/decode_der2key.rs`, `src/engine/eng_table.rs`,
`src/store/store_meth.rs`, plus the M1 cluster (`x509_vfy`, `pk7_doit`, `v3_utl`,
`cms_sd`, `params/mod`, `pvkfmt`, `store_lib`, `bio_enc`, `x_pubkey`, `v3_asid`,
`asn_mime`, `rsa/pmeth`).

Receipt:
[`atlas-refresh/mechanism-sweep-M24.json`](atlas-refresh/mechanism-sweep-M24.json).

## 29. Mechanism sweep M25 — 2026-10-19

Eight ordinary files from the M24-named batch; no newly discovered boundary.
Source identity `d8b4d82ca`; `src/runtime/str.rs` is the only source change.

**M25 audited files (8).** `src/runtime/bio/bf_lbuf.rs`, `src/provider/seed_src.rs`,
`src/asn1/x_algor.rs`, `src/x509/x509_set.rs`, `src/provider/ec_kem.rs`,
`src/runtime/str.rs`, `src/provider/mlx_kmgmt.rs`, `src/provider/ml_dsa_codecs.rs`.

**Defect.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M25-D1 | `src/runtime/str.rs:458` | high (one-byte OOB write; length divergence) | `buf2hexstr_sep` omitted the authority's `if (len == 0) ++len;`, so an empty separator-form `OPENSSL_buf2hexstr_ex` reported length 0, accepted `str_n == 0`, and wrote the NUL past the caller's extent (§3, §17) | restore the clamp before `*strlength`; control `runtime::str::tests::buf2hexstr_ex_empty_with_separator_requires_one_byte` |

**Contracts reused.** RC-1, OB-1, OB-2, OB-3 (+ zero-state sweep), OB-4,
ASN1 item/`ASN1_STRING` ownership, BIO control callbacks, provider
keymgmt import/export. No new unsafe assumption; hidden obligations 0;
unsafe ops introduced/removed/relocated 0/0/0.

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1626 passed / 0 failed / 27 ignored** serially (222.53 s) and with
`--test-threads=4` (89.13 s); focused `runtime::str::tests` 8/0.

**NOT_RUN.** Miri/ASan on the new bounds control (BOUNDARY), independent
review and SEAL. No downstream probe exercises the empty separator form: the
hostility corpus calls `OPENSSL_buf2hexstr` with non-empty input and the coverage
probe only resolves the `_ex` export. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/provider/core_dispatch.rs` (75),
`src/provider/exchange.rs` (74), `src/slh_dsa/wots.rs` (74),
`src/runtime/bio/addr.rs` (74), `src/runtime/bio/addr_info.rs` (74),
`src/evp/evp_pkey.rs` (74), `src/x509/v3_genn.rs` (73), `src/x509/v3_akid.rs` (73).
Deferred NOT_RUN as provider/callback boundaries: `provider/ml_kem_codecs.rs` (80),
`provider/file_store_any2obj.rs` (79), `ui/ui_openssl.rs` (84),
`provider/legacyprov.rs` (73); substitutions if triage changes:
`src/dsa/pmeth.rs` (73), `src/dh/ctrl.rs` (73).

Receipt:
[`atlas-refresh/mechanism-sweep-M25.json`](atlas-refresh/mechanism-sweep-M25.json).

## 30. Mechanism sweep M26 — 2026-10-19

Eight ordinary files from the M25-named batch; no newly discovered boundary.
Source identity `f479783f8`; `src/runtime/bio/addr.rs`,
`src/runtime/bio/addr_info.rs` and `src/runtime/bio/sys.rs` are the source changes.

**M26 audited files (8).** `src/provider/core_dispatch.rs`,
`src/provider/exchange.rs`, `src/slh_dsa/wots.rs`, `src/runtime/bio/addr.rs`,
`src/runtime/bio/addr_info.rs`, `src/evp/evp_pkey.rs`, `src/x509/v3_genn.rs`,
`src/x509/v3_akid.rs`.

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M26-D1 | `src/runtime/bio/addr_info.rs:321` | medium (compatibility divergence) | `addrinfo_wrap` ignored `BIO_ADDR_rawmake`'s refusal, returning success with an `AF_UNSPEC` address for an over-long `AF_UNIX` path; the allocation-failure arm also omitted the authority's `*bai = NULL` (§8, §17) | check the result, release the fresh address on refusal, and write NULL on node-allocation failure; control `runtime::bio::addr_info::tests::a_unix_path_that_cannot_be_terminated_is_refused` |
| M26-D2 | `src/runtime/bio/sys.rs:335` | high (alignment invariant; potential UB) | `SockAddrStorage` was 2-aligned while `addr.rs` derives 4-aligned `SockAddrIn`/`SockAddrIn6`/`SockAddrUn` references from it, so stack/embedded `BioAddr` values were not sound by construction (§2, §10, §21) | `#[repr(C, align(4))]` (size unchanged at 128) plus compile-time alignment assertions in `addr.rs` |

**Contracts reused.** RC-1, OB-1, OB-2, OB-3, OB-4, ASN1 item/union
ownership, BIO control callbacks and opaque `BIO_ADDR` storage, provider
keyexch/kdf dispatch, OSSL_PARAM decoders. No new unsafe assumption; hidden
obligations 0; unsafe ops introduced/removed/relocated 0/0/0.

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1627 passed / 0 failed / 27 ignored** serially (201.53 s) and with
`--test-threads=4` (126.99 s); focused `runtime::bio::addr` 13/0.

**NOT_RUN.** `RT-BIO-ADDR` differential probe (the phase-4 runner links the
committed `artifacts/phase2` distribution shell, which predates this worktree;
rebuilding it is a boundary action), Miri/ASan on the alignment change
(BOUNDARY), independent review and SEAL. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/dh/ctrl.rs` (73), `src/dsa/pmeth.rs` (73),
`src/provider/decode_msblob2key.rs` (72), `src/runtime/bio/bss_mem.rs` (72),
`src/x509/v3_attrmap.rs` (72), `src/runtime/bio/bio_sock2.rs` (70),
`src/x509/by_file.rs` (70), `src/runtime/bio/method.rs` (69).
Deferred NOT_RUN as boundaries: `provider/legacyprov.rs` (73),
`provider/child.rs` (71), `runtime/lhash.rs` (71, BOUNDARY_COVERED),
`ssl/record/rec_layer_s3.rs` (69); `src/dh/key.rs` is already covered by B14-D1.

Receipt:
[`atlas-refresh/mechanism-sweep-M26.json`](atlas-refresh/mechanism-sweep-M26.json).

## 31. Mechanism sweep M27 — 2026-10-19

Source HEAD `2b218351d`; branch `integrate/safe-c33`; worktree dirty
(`src/dh/ctrl.rs`, `src/runtime/bio/bss_mem.rs`, this index and the M27
receipt). Eight ordinary files from the M26-named batch; no newly discovered
boundary, so neither substitution (`src/x509/x_x509.rs`, `src/asn1/a_sign.rs`)
was used.

**M27 audited files (8).** `src/dh/ctrl.rs`, `src/dsa/pmeth.rs`,
`src/provider/decode_msblob2key.rs`, `src/runtime/bio/bss_mem.rs`,
`src/x509/v3_attrmap.rs`, `src/runtime/bio/bio_sock2.rs`,
`src/x509/by_file.rs`, `src/runtime/bio/method.rs`.

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M27-D1 | `src/runtime/bio/bss_mem.rs:583` | high (write through a C-valid NULL/zero-length buffer) | `mem_gets` wrote its terminator whenever `j <= 0`, so `BIO_gets(b, NULL, 0)` — admissible under the public `BIO_gets` contract — dereferenced NULL. The authority has the same defect; it is not reproduced (§17, §21.1) | write only when `size > 0` and `buf` is non-NULL, keeping the authority's `0` answer; control `runtime::bio::bss_mem::tests::a_zero_length_gets_does_not_write_through_a_null_buffer` |
| M27-D2 | `src/runtime/bio/bss_mem.rs:387` | medium (fallible arithmetic; no memory-safety impact observed) | `mem_write` computed `readp->length + inl` unchecked, so a negative or enormous `inl` panicked in debug (a panic boundary, §3) before `BUF_MEM_grow_clean` could refuse it | `checked_add`, translating overflow to the authority's `-1` refusal; the enormous wrapped lengths already fail the grow |
| M27-D3 | `src/dh/ctrl.rs:608` | low (contract accuracy; doc only) | `EVP_PKEY_CTX_get_dh_kdf_outlen` advertised `plen` as "NULL or a live `int`" while the body writes `*plen` on success, so the documented precondition did not establish validity | state that `plen` is a live, writable `int` on a `1` return |

**Contracts reused.** RC-1, OB-1, OB-2, OB-3 (+ zero-state sweep),
OB-4, ASN1 item/template/union ownership, BIO control/read/write callbacks,
provider decoder dispatch, OSSL_PARAM builders, `BUF_MEM` ownership. No new
unsafe assumption; hidden obligations 0; unsafe ops
introduced/removed/relocated 0/0/0.

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1628 passed / 0 failed / 27 ignored** serially (227.01 s) and with
`--test-threads=4` (102.25 s); focused `runtime::bio::bss_mem::tests` 1/0.

**NOT_RUN.** The phase-4 BIO differential probes still link the committed
`artifacts/phase2` distribution shell, which predates this worktree, so no
`RT-BIO` probe was run; Miri/ASan on M27-D1's NULL-write control (BOUNDARY),
independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/x509/x_x509.rs` (69), `src/asn1/a_sign.rs` (68),
`src/provider/eddsa_sig.rs` (68), `src/runtime/bio/bss_file.rs` (68),
`src/apps/crl2pkcs7.rs` (67), `src/asn1/fre.rs` (67),
`src/engine/eng_ctrl.rs` (67), `src/x509/x_ietfatt.rs` (67).
Deferred NOT_RUN as boundaries: `src/ssl/record/rec_layer_s3.rs` (69) and the
M26/M25-retained set. If `src/engine/eng_ctrl.rs` proves a new ENGINE ctrl
callback boundary, record it `NOT_RUN` and substitute the next ranked ordinary
file (`src/asn1/bitstr.rs` (65) after the already-covered `src/ec/smpl.rs`).

Receipt:
[`atlas-refresh/mechanism-sweep-M27.json`](atlas-refresh/mechanism-sweep-M27.json).

## 32. Mechanism sweep M28 — 2026-10-19

Source HEAD `485b9b847`; branch `integrate/safe-c33`; worktree dirty
(`src/asn1/bitstr.rs`, `src/asn1/fre.rs`, `src/runtime/bio/bss_file.rs`, this
index and the M28 receipt). Seven ordinary files from the M27-named batch;
`src/engine/eng_ctrl.rs` (67) proved a new ENGINE ctrl callback boundary and was
`NOT_RUN`, so the ranked substitute `src/asn1/bitstr.rs` (65) was audited.

**M28 audited files (8).** `src/x509/x_x509.rs`, `src/asn1/a_sign.rs`,
`src/provider/eddsa_sig.rs`, `src/runtime/bio/bss_file.rs`,
`src/apps/crl2pkcs7.rs`, `src/asn1/fre.rs`, `src/x509/x_ietfatt.rs`,
`src/asn1/bitstr.rs` (substitute). `NOT_RUN`: `src/engine/eng_ctrl.rs` (new
ENGINE ctrl callback boundary).

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M28-D1 | `src/runtime/bio/bss_file.rs:367` | high (write outside the caller's extent) | `file_gets` wrote `*buf = 0` before consulting `size`; a zero-length `BIO_gets` request has no writable byte, and the NULL case dereferenced NULL. The authority has the same defect (§17, §21.1; same class as M27-D1) | return the authority's `0` for `size <= 0` without touching `buf` or `bp`; control `runtime::bio::bss_file::tests::a_zero_length_gets_does_not_write_through_a_null_buffer` |
| M28-D2 | `src/runtime/bio/bss_file.rs:458` | high (NULL dereference inside libc) | `BIO_C_SET_FILENAME` called `fopen(ptr_, mode)` with no NULL check; `fopen(NULL, ...)` faults. OpenSSL 4.0.2 later added the same refusal | refuse a NULL filename after mode construction and before `fopen`, answering the authority's failure `0` with no new error coordinate; control `runtime::bio::bss_file::tests::set_filename_refuses_a_null_filename` |
| M28-D3 | `src/asn1/fre.rs:387/389` | low (out-of-authority read + redundant write; no observed behaviour change) | `template_free` read `*pval` unconditionally and wrote it back on the `ASN1_TFLG_EMBED` path; the authority never reads an embedded field's storage and instead uses the slot's address | assign `tval` from the slot's address only on the embed path; the read and write-back are gone |
| M28-D4 | `src/asn1/bitstr.rs:472` | low (fallible signed arithmetic; debug panic only for a hand-filled negative length) | `ASN1_BIT_STRING_set_bit` tested `w + 1 - s.length > 0` with the unclamped length and wrote the clamped count, so `INT_MIN` could overflow the test | compare and subtract in `usize` against the already-clamped `old_len`; conforming inputs are unchanged |

**Contracts reused.** RC-1, OB-1, OB-3 (incl. `CtxBlock`), OB-4
(`PropqSlot`), ASN1 item/template/union ownership and the item-layer
`D2I_PRE`/`NEW_POST`/`FREE_POST` callback contract, BIO method/ctrl/read/write
contract, provider dispatch and `OSSL_PARAM` builders, `X509_INFO` stack
consumption and PKCS7 ownership, WPACKET DER lifecycle. No new unsafe
assumption; hidden obligations 0; unsafe ops introduced/removed/relocated
0/2/0 (M28-D3 removed one raw read and one redundant write).

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1630 passed / 0 failed / 27 ignored** serially (238.37 s) and with
`--test-threads=4` (100.52 s); focused `runtime::bio::bss_file::tests` 2/0.

**NOT_RUN.** `src/engine/eng_ctrl.rs` (ENGINE ctrl callback boundary); the
phase-4 BIO and ASN.1 differential probes still link the committed
`artifacts/phase2` distribution shell, which predates this worktree; Miri/ASan
on the new controls and the EMBED free path (BOUNDARY); independent review and
SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/x509/v3_prn.rs` (65),
`src/runtime/thread_events.rs` (65), `src/runtime/init.rs` (65),
`src/ffc/dh.rs` (65), `src/cmp/cmp_util.rs` (65),
`src/cmp/cmp_status.rs` (65), `src/ts/ts_verify_ctx.rs` (64),
`src/rand/unix.rs` (64). Triage `runtime/thread_events.rs` and
`runtime/init.rs` first as possible callback/initialization boundaries; if
confirmed `NOT_RUN`, substitute `src/ocsp/ocsp_vfy.rs` (64), then
`src/bn/blinding.rs` (64), `src/x509/v3_info.rs` (63),
`src/ts/ts_req_utils.rs` (63). Deferred NOT_RUN: `engine/eng_ctrl.rs`,
`ssl/record/rec_layer_s3.rs` and the M26/M25-retained boundaries;
`src/ec/smpl.rs` is already covered.

Receipt:
[`atlas-refresh/mechanism-sweep-M28.json`](atlas-refresh/mechanism-sweep-M28.json).

## 33. Mechanism sweep M29 — 2026-10-19

Source HEAD `5f03632b9`; branch `integrate/safe-c33`; worktree dirty
(`src/rand/unix.rs`, `src/ts/ts_verify_ctx.rs`, this index and the M29
receipt). Eight ordinary files from the M28-named batch. Both triaged
boundaries were confirmed: `src/runtime/thread_events.rs` owns the thread-local
event-handler stack and its TLS-destructor callback, and `src/runtime/init.rs`
owns initialization ordering and caller-registered `OPENSSL_atexit` handlers.
Both are `NOT_RUN`; the first two ranked substitutes,
`src/ocsp/ocsp_vfy.rs` (64) and `src/bn/blinding.rs` (64), were audited.

**M29 audited files (8).** `src/x509/v3_prn.rs`, `src/ffc/dh.rs`,
`src/cmp/cmp_util.rs`, `src/cmp/cmp_status.rs`,
`src/ts/ts_verify_ctx.rs`, `src/rand/unix.rs`, `src/ocsp/ocsp_vfy.rs`
(substitute), `src/bn/blinding.rs` (substitute). `NOT_RUN`:
`src/runtime/thread_events.rs` (thread-event callback boundary),
`src/runtime/init.rs` (initialization/atexit callback boundary).

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M29-D1 | `src/ts/ts_verify_ctx.rs:407` | high (read through NULL from C-valid state; authority has the same fault) | `TS_REQ_to_TS_VERIFY_CTX` passed `ASN1_STRING_get0_data(msg)` to `memcpy` whenever the length was positive; length 5 with `data == NULL` is constructible through exported `ASN1_STRING_set0` | capture the data pointer once and take the existing `err:` arm when NULL; control `ts::ts_verify_ctx::tests::req_to_ctx_refuses_positive_length_with_null_data` |
| M29-D2 | `src/rand/unix.rs:120/124/127/131` | high (data race and aliasing UB from concurrent `RAND_bytes` / `RAND_keep_random_devices_open`; safe fns performed the access) | four `static mut` objects (`RANDOM_DEVICES`, `KEEP_RANDOM_DEVICES_OPEN`, `SHM_ADDR`, `SEEDED`) were mutated without synchronisation; two helpers dereferenced caller raw pointers under safe signatures | `Mutex` for the device cache (poison ignored), `AtomicI32`/`AtomicPtr` for the scalars, cache lock held only for the transition; `syscall_random` and `check_random_device` are now `unsafe fn` with stated contracts |
| M29-D3 | `src/cmp/cmp_util.rs:300` | low (diagnostic text only) | `OSSL_CMP_print_errors_cb` omits the authority's `ERR_SYSTEM_ERROR`/`openssl_strerror_r` arm and uses the unmasked code in the `reason(%lu)` fallback | recorded, not repaired; needs the ERR `strerror` helper or a duplicated arm. No memory-safety effect |
| M29-D4 | `src/x509/v3_prn.rs:146` | low (authority-parity NULL; needs a both-NULL `CONF_VALUE`) | `X509V3_EXT_val_prn` passes NULL to `BIO_puts` when both the entry's name and value are NULL; the authority and OpenSSL 4.0.2 have the same arm | recorded, not repaired; consistent later hardening batch |
| M29-D5 | `src/cmp/cmp_status.rs:337` | low (authority-parity NULL; needs positive length with NULL data) | `snprint_PKIStatusInfo_parts` passes a NULL `ASN1_STRING` data pointer with a positive `%.*s` precision; `cmp_status.c` has the same arm | recorded, not repaired; same hardening class as M29-D4 |

**Contracts reused.** RC-1, OB-1, OB-2, OB-3 (incl. the zero-state sweep),
`X509V3_EXT_METHOD` dispatch and result ownership, `STACK_OF`
CONF_VALUE/X509/OCSP_SINGLERESP/UTF8 ownership, ASN1 item ownership, the BIO
printf/puts/FP contract, BN blinding/arithmetic contracts, RAND pool
allocation/accounting. No new unsafe assumption; hidden obligations 0; unsafe
expressions introduced/removed/relocated 3/12/0 (the 12 are raw static-mut
accesses; two helper declarations were tightened to `unsafe fn` rather than
adding capability).

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1631 passed / 0 failed / 27 ignored** serially (67.03 s) and with
`--test-threads=4` (86.66 s). Focused: `ts::ts_verify_ctx` 2/0,
`rand::unix` 4/0, `x509::v3_prn` 1/0, `ffc::dh` 7/0, `bn::blinding` 11/0;
`cmp::cmp_util`, `cmp::cmp_status` and `ocsp::ocsp_vfy` have no module-local
tests.

**NOT_RUN.** The two triaged callback/initialization boundaries; the TS/CMP/
OCSP differential probes (their runner links the committed `artifacts/phase2`
shell); Miri on the FFI/syscall paths and TSan/ASan/Loom plus a static-mut
negative control (BOUNDARY); independent review and SEAL. Nothing is promoted
to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/x509/v3_info.rs` (63),
`src/ts/ts_req_utils.rs` (63), `src/evp/e_rc2.rs` (63),
`src/apps/pkeyutl.rs` (62), `src/asn1/a_verify.rs` (62), `src/dsa/mod.rs` (62),
`src/evp/evp_pbe.rs` (62), `src/ffc/params.rs` (62). Held for the following
batch: `src/ssl/tls_srp.rs` (62, protocol-adjacent). Inferred boundary
candidates skipped: `src/encoder_pkey.rs`, `src/engine/tb_asnmth.rs`,
`src/provider/decode_pvk2key.rs` (all 63, engine/provider dispatch surfaces).
Deferred NOT_RUN: `engine/eng_ctrl.rs`, `ssl/record/rec_layer_s3.rs`,
`provider/legacyprov.rs`, `provider/child.rs`, `runtime/lhash.rs` and the
M22-retained boundaries.

Receipt:
[`atlas-refresh/mechanism-sweep-M29.json`](atlas-refresh/mechanism-sweep-M29.json).

## 34. Mechanism sweep M30 — 2026-10-19

Source HEAD `aed68972c`; branch `integrate/safe-c33`; worktree dirty
(`src/evp/e_rc2.rs`, this index and the M30 receipt). Eight ordinary files
from the M29-named batch; `src/ssl/tls_srp.rs` (62) remains held and the three
inferred engine/provider dispatch candidates remain `NOT_RUN`.

**M30 audited files (8).** `src/x509/v3_info.rs`, `src/ts/ts_req_utils.rs`,
`src/evp/e_rc2.rs`, `src/apps/pkeyutl.rs`, `src/asn1/a_verify.rs`,
`src/dsa/mod.rs`, `src/evp/evp_pbe.rs`, `src/ffc/params.rs`.

**Defects.**

| id | file:line (post-fix) | severity | class | fix |
|---|---|---|---|---|
| M30-D1 | `src/evp/e_rc2.rs:369,378,387` | medium (compatibility; no memory-safety effect) | `rc2_get_asn1_type_and_iv` discarded the authority's return value: `let i: c_int = 0;` was never assigned, so a successful parameter decode answered 0 instead of the IV byte count. `EVP_CIPHER_asn1_to_param` callers test `<= 0`, so the legacy/engine RC2 path reported success as failure | assign the `ASN1_TYPE_get_int_octetstring` result to `i` and return it, matching `e_rc2.c:130-156`; failure arms stay `-1` |

**Retained obligations (recorded, not repaired).** M30-R1 `evp_pbe.rs:491`
`static mut PBE_ALGS` with the authority's own unsynchronised registration model
(BOUNDARY); M30-R2 `ffc/params.rs:251` `ossl_ffc_params_set0_j(d, d->j)`
authority-parity self-assignment use-after-free (documented, no landed caller);
M30-R3 `apps/pkeyutl.rs:110,738` module-private safe helpers over caller raw
BIO pointers.

**Contracts reused.** RC-1, OB-1 (plain and cleansed), OB-2, OB-3, OB-4 member
slots, ASN1 item ownership, STACK_OF + pop_free thunks, `X509V3_EXT_METHOD`
i2v/v2i, the legacy `EVP_CIPHER` callback contract, BIO, and the EVP_PBE row
registry. No new unsafe assumption; hidden obligations 0; unsafe expressions
introduced/removed/relocated 0/0/0. No allocator coordinate, export, signature
or `#[repr(C)]` layout changed.

**Gates.** fmt PASS; clippy `--all-targets -- -D warnings` PASS; library
**1635 passed / 0 failed / 27 ignored** serially (72.75 s) and with
`--test-threads=4` (109.48 s). Focused: `evp::e_rc2` 1/0.

**NOT_RUN.** `src/ssl/tls_srp.rs` and the three engine/provider dispatch
candidates; the RC2 get-asn1 return-value authority differential (the default
provider replaces these statics, so a legacy/engine driver is needed); Miri on
these FFI callbacks, and ASan/TSan/Loom for the retained PBE registry
(BOUNDARY); independent review and SEAL. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next 8-file batch.** `src/apps/cms.rs` (61), `src/provider/ml_dsa_sig.rs`
(61), `src/slh_dsa/fors.rs` (61), `src/x509/by_store.rs` (61),
`src/x509/x509_ext.rs` (61), `src/cms/cms_att.rs` (60),
`src/digest/blake2.rs` (60), `src/x509/v3_aaa.rs` (60). Skipped boundaries:
`src/ssl/tls_srp.rs` (62, held), `src/ssl/statem/extensions_clnt.rs` (60,
TLS protocol), `src/engine/eng_cnf.rs` (58, ENGINE config), and the three
engine/provider dispatch candidates.

Receipt:
[`atlas-refresh/mechanism-sweep-M30.json`](atlas-refresh/mechanism-sweep-M30.json).

## 25. Boundary sweep B15 — thread stop, initialisation/atexit, and ENGINE ctrl dispatch

Receipt: [`atlas-refresh/boundary-sweep-B15.json`](atlas-refresh/boundary-sweep-B15.json).
Candidate `2eef78548`; three files, four repairs.

**STOP status: CLEAR after repair.** Two confirmed memory-safety defects were stopped on
and repaired: `B15-D1` (heap-use-after-free when a handler calls `OPENSSL_thread_stop`
from a per-context stop) and `B15-D2` (NULL/one-past-the-array read in `ENGINE_ctrl` for
command number 0; authority-parity UB, not reproduced). Both negative controls were
observed on the pre-fix candidate (ASan heap-use-after-free; SIGSEGV) and pass after the
repair.

| file | boundaries | disposition | defects / residuals |
|---|---|---|---|
| `src/runtime/thread_events.rs` | `B15-TE-1..5` (head ownership, global register, stop walks, registration callback edge, key cell) | `CONTRACTED` | **B15-D1 (fixed, high):** the nested whole-thread stop released the head the enclosing context-stop walk still wrote. `init_thread_stop` now reports whether an enclosing walk owns the head; a refusal restores the slot and returns. Controls: `a_handler_that_stops_the_thread_during_a_context_stop_is_refused` (ASan pre-fix UAF at `thread_events.rs:781`, clean post-fix). `B15-R3/R4` retained. |
| `src/runtime/init.rs` | `B15-IN-1..5` (atexit node ownership, drain, init ordering, cleanup/terminal state, identity) | `CONTRACTED` | **B15-D3 (fixed, medium):** `OPENSSL_atexit`'s load+store lost concurrent registrations (149/512 survived); now a compare-exchange push. **B15-D4 (fixed, low):** the drain looped, so a self-registering handler could hang cleanup; now one snapshot and one walk, as the authority. Controls: `concurrent_atexit_registrations_all_survive`, `a_handler_registered_during_the_drain_is_not_run_by_it`. `B15-R1/R2` retained. |
| `src/engine/eng_ctrl.rs` | `B15-ENG-1..3` (caller-owned `cmd_defns`, ctrl dispatch, argument conversion) | `CONTRACTED` | **B15-D2 (fixed, high):** `int_ctrl_cmd_by_num` matched the `cmd_num == 0` terminator; on a valid empty list, `ENGINE_ctrl(e, GET_NAME_LEN, 0, …)` then called `strlen(NULL)` and `GET_NEXT` read one entry past the array. The authority has the same fault; the crate now fails closed at `ENGINE_R_INVALID_CMD_NUMBER` (`B15-R5`, recorded divergence). Control: `a_zero_command_number_does_not_match_the_terminator` (SIGSEGV pre-fix). |

**Sweep.** Each callback reentrancy edge was checked for a live Rust reference, a
non-reentrant lock and an owned buffer across the call. The thread-stop handlers do run
under the register lock (authority order); nested registration/deregistration is refused
by the non-recursive lock, and the one path that released shared storage is repaired.
`OPENSSL_cleanup` now states the authority's single-threaded requirement explicitly; only
cleanup-vs-cleanup is made safe. Every `cmd_defns` traversal step is bounded by the
terminator.

**New unsafe assumptions (hidden must be 0).** None. One new raw field write (the CAS
node's `next`) sits in a SAFETY-commented block over uniquely-owned storage. No export,
signature, `#[repr(C)]` layout, allocator-seam coordinate or unsafe lint attribute changed.
No safe caller can cause UB through the audited interfaces under the stated contracts.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused 22/0.
ASan (dedicated venue, `-Zsanitizer=address -Zbuild-std`): the B15-D1 control passes with
no report after the repair and reported the predicted heap-use-after-free before it.
BATCH: library **1635 passed / 0 failed / 27 ignored** serially (239.63 s) and with
`--test-threads=4` (100.94 s); 0 newly ignored, 0 removed, four tests added. None of the
three files carries an `OPENSSL_RS_ADV_PROBE` arm.

**NOT_RUN.** Miri (Stacked/Tree Borrows; the court's 1.98.1 toolchain has no miri),
Loom/TSan, the authority differentials for B15-D1/D2/D4, independent review and SEAL.
Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next ordinary position:** `src/x509/v3_info.rs` (63), then
`src/ts/ts_req_utils.rs` (63), `src/evp/e_rc2.rs` (63), `src/apps/pkeyutl.rs` (62),
`src/asn1/a_verify.rs` (62), `src/dsa/mod.rs` (62), `src/evp/evp_pbe.rs` (62),
`src/ffc/params.rs` (62). `src/engine/eng_ctrl.rs` was the last M29-deferred boundary
named in §24 and is audited here.

## 26. Boundary sweep B16 — SRP credentials, client extensions, ENGINE config, ASN.1 method table

Receipt: [`atlas-refresh/boundary-sweep-B16.json`](atlas-refresh/boundary-sweep-B16.json).
Candidate `8cfc56b38`; four files, five repairs.

**STOP status: CLEAR after repair.** Three confirmed memory-safety defects were stopped on
and repaired: `B16-D2` (heap-use-after-free when `SSL_set_srp_server_param` is passed the
pointer `SSL_get_srp_userinfo` returned), `B16-D3` (NULL dereference/abort on
`ENGINE_unregister_pkey_asn1_meths(NULL)`, a call the function itself documented as
NULL-tolerant), and `B16-D1` (a refused structural reference returned a borrowed
`EVP_PKEY_ASN1_METHOD` while owning no engine reference). Two further ownership defects
were repaired: `B16-D4` (displaced `s3.tmp.pkey` not released) and `B16-D5` (the
unsynchronised `initialized_engines` stack: finish-vs-init heap-use-after-free and
init-vs-init lost stack). Pre-fix controls were observed: ASan heap-use-after-free (D2),
SIGABRT null dereference (D3), and an assertion failure returning the borrowed method
(D1). D5's race is scheduler-dependent, so its deterministic pre-fix canary is NOT_RUN;
the serialised post-fix regression test passes.

| file | boundaries | disposition | defects / residuals |
|---|---|---|---|
| `src/ssl/tls_srp.rs` | `B16-SRP-1..4` (credential-block ownership, setters/accessors, callback edge, context installers) | `CONTRACTED` | **B16-D2 (fixed, high):** duplicate-then-release for `info`, so a self-aliased argument no longer reads freed memory. `B16-R1/R2` are the authority's own credential-reset leaks; `B16-R3` is the init-failure strength delta; `B16-R4` is the missing ERR raises. `B16-R8/E2` records the same alias class in `ssl_lib.rs` (out of scope). |
| `src/ssl/statem/extensions_clnt.rs` | `B16-EXT-1..3` (framework/builders, key-share transfer, message ownership) | `CONTRACTED` | **B16-D4 (fixed, low):** the previous `s3.tmp.pkey` is released before the new share is stored. Wire bytes unchanged; the non-HRR reduction still regenerates rather than reusing `ks_pkey[0]`. No callback runs in this file. |
| `src/engine/eng_cnf.rs` | `B16-CNF-1..3` (module stack, config walk/ctrl edge, registration) | `CONTRACTED` | **B16-D5 (fixed, high):** stack publication/push/pop/free now serialised by a module-local `Mutex`; `ENGINE_init`/`ENGINE_finish` hooks run outside it. `B16-R7` retains the authority's "do not mutate the walked CONF section" callback contract; `B16-R9` records reentrant-init ordering. |
| `src/engine/tb_asnmth.rs` | `B16-ASN1-1..3` (table registration, by-name lookup/refcount, method release) | `CONTRACTED` | **B16-D1 (fixed, high):** a refused up-ref now unlocks, raises `TB_ASNMTH_213` (`ERR_R_CRYPTO_LIB`) and returns NULL without writing `*pe`, as the authority does. **B16-D3 (fixed, high):** NULL unregistration is refused before the pile walk. NULL contracts on the register/get/set functions were corrected to non-NULL. `B16-R5` retains the callback-under-read-lock contract; `B16-R6` the borrowed method lifetime. |

**Sweep.** Every SRP credential field and every failure path was traced for partial init and
aliasing. The extension builders were compared with the fetched authority sources; only the
key-share transfer owns a pointer. The ENGINE stack's publication and mutation are now under
one lock, with no callback executed under it. The ASN.1 table walk takes exactly one
structural reference on a match and fails closed on refusal; its callback remains under the
engine read lock, as in the authority.

**New unsafe assumptions (hidden must be 0).** None. Two production `unsafe` blocks were
added in the refusal arm (unlock and the generated raise site), both SAFETY-commented; the
other repairs add no unsafe expression. No export, signature, `#[repr(C)]` layout,
allocator-seam coordinate or unsafe lint attribute changed. No safe caller can cause UB
through the audited interfaces under the stated contracts.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused 4/0. ASan
(dedicated venue, `-Zsanitizer=address -Zbuild-std`): the B16-D2 control reported the
predicted heap-use-after-free before the repair and passes after it. BATCH: library **1639
passed / 0 failed / 27 ignored** serially (209.80 s) and with `--test-threads=4` (90.40 s);
0 newly ignored, 0 removed, four tests added. None of the four files carries an
`OPENSSL_RS_ADV_PROBE` arm. E1 records an unrelated 84-byte ERR/EVP leak observed by the
ASan venue.

**NOT_RUN.** Miri (Stacked/Tree Borrows; the court's 1.98.1 toolchain has no miri),
Loom/TSan, the authority differentials for B16-D1/D2/D3/D5, the deterministic B16-D5 race
canary, independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next ordinary position:** `src/x509/v3_info.rs` (63), then
`src/ts/ts_req_utils.rs` (63), `src/evp/e_rc2.rs` (63), `src/apps/pkeyutl.rs` (62),
`src/asn1/a_verify.rs` (62), `src/dsa/mod.rs` (62), `src/evp/evp_pbe.rs` (62),
`src/ffc/params.rs` (62). This boundary sweep does not consume an ordinary queue position.

## 27. Boundary sweep B17 — setter aliasing, PBE registry, FFC cofactor, deferred codec edges

Receipt: [`atlas-refresh/boundary-sweep-B17.json`](atlas-refresh/boundary-sweep-B17.json).
Candidate `13b62ac3e`; four repaired files, two deferred boundaries audited.

**STOP status: CLEAR after repair. The B16-R8/E2 alias class is closed in `ssl_lib.rs`.**
Seven confirmed defects were stopped on and repaired: `B17-D1` (SRP username ctrl freed
`srp_ctx.login` before `CRYPTO_strdup(parg)`; `SSL_get_srp_username` can return that very
pointer through its context fallback), `B17-D2` (the password/info arm had the same UAF and
also left the member dangling on a refused duplicate), `B17-D3` (`SSL_set1_host` cleared the
parameter before reading a name `X509_VERIFY_PARAM_get0_host` returned), `B17-D6`
(`X509_VERIFY_PARAM_inherit` freed `dest->policies`/`dest->hosts` before copying them when
`dest == src`, reachable through `SSL_set1_param`/`SSL_CTX_set1_param`), `B17-D7`
(`int_x509_param_set_hosts` freed the host set before `strndup(name)`), `B17-D4`
(`ossl_ffc_params_set0_j(d, d->j)` freed then stored the same pointer), and `B17-D5`
(the unsynchronised `static mut PBE_ALGS` allowed a cleanup-vs-find/free UAF and an
init-vs-init lost stack). Pre-fix controls observed under ASan: D1, D2, D3 and D6 each
reported `heap-use-after-free` (in `strlen`, `strlen`, `strchr` and `Vec::len` respectively);
all five post-fix controls pass under ASan. D4's and D7's pre-fix ASan runs are NOT_RUN, but
their post-fix controls pass and the class control is the observed D1/D2/D3/D6 result. D5's
race is scheduler-dependent, so its deterministic pre-fix canary is NOT_RUN; the four-thread
registration control and the full suite pass.

| file | boundaries | disposition | defects / residuals |
|---|---|---|---|
| `src/ssl/ssl_lib.rs` | `B17-SSL-1..4` (SRP ctrl strings, `SSL_set1_host`, `SSL_set1_param` delegation, remaining copy/ownership setters) | `CONTRACTED` | **D1/D2 (fixed, high):** SRP username/info duplicate before release; the info failure path now clears the member. **D3 (fixed, high):** a parameter-owned host name is duplicated before the clear. **D6 (fixed, high):** self-inherit no longer releases the source set. `B17-R2` records the `set0` ownership-transfer setters (alias is contract-invalid, not a copy setter). |
| `src/x509/x509_vpm.rs` | `B17-XVPM-1` (host/policy inheritance and `set1_host`) | `CONTRACTED` | **D7 (fixed, high):** duplicate-then-release in `int_x509_param_set_hosts`. **D6 (fixed, high):** policies/hosts self-copy guards in `X509_VERIFY_PARAM_inherit`. `B17-R3` records the unexported-policy-set self-alias (unreachable without a getter). |
| `src/evp/evp_pbe.rs` | `B17-PBE-1` (application PBE registry publication, add/find/cleanup) | `CONTRACTED` | **D5 (fixed, high):** `PBE_ALGS` is now an `AtomicPtr` under a module-local `Mutex`; find copies the row under the guard, cleanup swaps then releases. No keygen or application callback runs under the lock. |
| `src/ffc/params.rs` | `B17-FFC-1` (cofactor ownership transfer) | `CONTRACTED` | **D4 (fixed, high):** self-assignment is a no-op retaining the single owner; the authority's UAF is a recorded §17 divergence. Null clears and distinct values are unchanged. |
| `src/encoder_pkey.rs` | `B17-ENC-1` (encoder collection, construct/import callbacks, pkey construction data) | `CONTRACTED` (deferred) | No defect found. `ConstructDataPkey` is zero-valid with an empty `CtxDestroy`; provider `does_selection`/`import_object`/`free_object` callbacks run with no Rust borrow or crate lock held; `B17-R4` records the borrowed `EVP_PKEY` lifetime. |
| `src/provider/decode_pvk2key.rs` | `B17-DEC-1` (decoder context, passphrase edge, decode/export ownership) | `CONTRACTED` (deferred) | No defect found. `Pvk2keyCtx` is zero-valid and `OwnedCtx` releases the block; `free_key` is the key's single release on every path; `B17-R5` records the framework's non-NULL/pointer-sized reference contract. |

**Sweep.** Every copy-setter in `ssl_lib` was classified: ALPN and certificate-type setters already
allocate before clearing; PSK identity hints and session-id context have no getter returning
the written member; the `set1`/`set0` BIO and store setters take an ownership reference rather
than copying, so a getter pointer does not satisfy their transfer contract (R2). The SRP
username/info getters fall back to the connection's context, which is what made the two ctrl
aliases reachable. The PBE registry's critical sections contain only stack/allocator work; the
keygen pointers are copied, never invoked, under the lock. The encoder and decoder were read
against their dispatch contracts and left unchanged (deferred).

**New unsafe assumptions (hidden must be 0).** None. The PBE repair replaces every
`static mut` access in add/find/cleanup with safe atomics; the alias repairs reorder existing
operations and add no unsafe expression. No export, signature, `#[repr(C)]` layout, allocator-seam coordinate or
unsafe lint attribute changed. No safe caller can cause UB through the audited interfaces under
the stated contracts.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused 5/0 (SSL
alias), 5/0 (PBE), 2/0 (FFC). ASan (dedicated venue, `-Zsanitizer=address -Zbuild-std`): the
pre-fix D1/D2/D3/D6 controls each reported the predicted heap-use-after-free; the post-fix
five-test suite passes with no ASan finding (leak detection disabled for the known E1 leak).
BATCH: library **1646 passed / 0 failed / 27 ignored** serially (195.53 s) and with
`--test-threads=4` (89.92 s); 0 newly ignored, 0 removed, seven tests added. E1 remains the
pre-existing ERR/EVP fetch leak (336 bytes in four allocations with leak detection on).

**NOT_RUN.** Miri (Stacked/Tree Borrows; the court toolchain has no miri), Loom/TSan, the
deterministic PBE race canary, pre-fix ASan for D4/D7 specifically, encoder/decoder adversarial
provider probes, the authority differentials, independent review and SEAL. Nothing is promoted
to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next ordinary position:** `src/x509/v3_info.rs` (63), then `src/ts/ts_req_utils.rs` (63),
`src/evp/e_rc2.rs` (63), `src/apps/pkeyutl.rs` (62), `src/asn1/a_verify.rs` (62),
`src/dsa/mod.rs` (62). `src/evp/evp_pbe.rs` and `src/ffc/params.rs` were swept here and leave
the queue. This boundary sweep does not consume an ordinary queue position.

## 35. Mechanism sweep M31 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `197f501dc` plus the worktree state
(the `src/ssl/bio_ssl.rs` repair below and this record).

**Reconciliation.** The census population is 868 source files: 92
`ZERO_UNSAFE`, 15 `BOUNDARY_COVERED`, 761 `PARTIAL`. Structured audit evidence
(each M-sweep's `.files` array plus this index's audited record tables) covers
**268** files, leaving **600** unaudited census files. A free-text extraction of
`src/...rs` from this file and every `atlas-refresh/*.json` instead yields 869
paths because prose fields (`next_batch`, `skipped`, `files_not_run`) name files
that were never audited. The eight paths that survive the naive subtraction are
test-only/model infrastructure modules (`owned_ctx_model`, `owned_buf_model`,
`owned_str_model`, `member_slot_model`, `zero_state`, `release_probe`,
`mem_coords`, `foreign`), not ordinary census files. All previous
"next position" lists were built from the naive set and are therefore stale.

**Scope:** the eight highest-ranked unaudited ordinary `PARTIAL` files excluded
from prior sweeps: `src/ml_dsa/encoders.rs` (225 unattributed sites),
`src/ssl/bio_ssl.rs` (133), `src/runtime/bio/bss_bio.rs` (131),
`src/runtime/confmod/mod.rs` (126), `src/asn1/bio_asn1.rs` (114),
`src/provider/ecx_kmgmt.rs` (113), `src/ec/key.rs` (111) and
`src/params/build.rs` (104). `src/provider/mod.rs` (118) was skipped as a
provider-dispatch boundary.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/ml_dsa/encoders.rs` | OB-1 local `OwnedBuf` (plain/secure), packet extents, hint-weight bounds | No defect. Every allocation has a checked/public extent, `Drop` is the single release, and `hint_bits_encode` refuses a hint above the `omega + k` packet extent instead of writing past it. |
| `src/ssl/bio_ssl.rs` | OB-3 `OwnedCtx<BioSsl>`, BIO callback contract, poisoned-data state | **M31-D1 fixed (medium, memory safety):** `BIO_ssl_shutdown` dereferenced the data slot that a refused `BIO_C_SET_SSL` re-creation deliberately leaves NULL; the pinned authority guards `bdata != NULL` (`bio_ssl.c:503`). **M31-D2 fixed (medium, memory safety):** `BIO_ssl_copy_session_id` had the same null-data dereference; the authority has the same UB, so the guard is a recorded §17 divergence. **M31-D3 fixed (medium, leak/compatibility):** the `BIO_C_SET_SSL` recovery arm recreated the block but never stored the caller's `SSL *`; the authority stores `bs->ssl = ptr`. |
| `src/runtime/bio/bss_bio.rs` | OB-3 `OwnedCtx<BioBioSt>`, ring extents, pair ownership | No defect. The ring invariants keep every copy inside `size`; a refused second pair allocation leaves the first block owned by its BIO and released once. |
| `src/runtime/confmod/mod.rs` | RCU lists, OB-1 entries (`OwnedBuf::new_zeroed`/`adopt`), DSO ownership, application init/finish callbacks | No defect. Publish/free order is synchronize-before-release; every failure arm releases only what it acquired; callbacks remain raw-pointer reentrancy edges (retained). |
| `src/asn1/bio_asn1.rs` | `BioAsn1BufCtx` ownership, prefix/suffix callbacks, NDEF support block | No defect. The support block transfers exactly once at `BIO_C_SET_EX_ARG`; failure before it drops the handle, and the suffix cleanup is the single release. |
| `src/provider/ecx_kmgmt.rs` | OB-3 `OwnedCtx<EcxGenCtx>`, secure/plain property ownership, keymgmt callbacks | No defect. `set_property_query` frees before duplicating exactly as the authority (latent self-alias retained, no getter); the secure private-key release uses the secure seam. |
| `src/ec/key.rs` | RC-1 refcount, key/group/point/BN ownership, method and ex-data callbacks | No defect. `down_ref` claims the last reference before any destructor; re-entrant `EC_KEY_free` is a no-op; `EC_KEY_copy` preserves the authority's partial-failure state. |
| `src/params/build.rs` | OB-1 `OwnedDef`, block-count arithmetic, secure/plain `to_param` | No defect. Push-time extents and the `to_param` sums are checked; a refused push drops the definition; `to_param` consumes and empties the builder as the authority does. |

**New unsafe assumptions (hidden must be 0).** None. The repairs add two NULL
guards and one pointer assignment; they add no unsafe operation, adoption,
allocator coordinate, `#[repr(C)]` layout, exported symbol or signature. The
poisoned-data state is now tolerated at every public chain-level entry point.

**Retained obligations.** `BIO_C_SET_SSL` re-creation and `ssl_free` remain
application-visible allocator-failure edges (now failure-atomic at the slot).
`confmod` module init/finish and `asn1` prefix/suffix callbacks remain
application-controlled reentrancy edges; no Rust borrow or crate lock is held
across them. `ecx_kmgmt`'s free-before-duplicate property setter is retained for
authority parity (no getter exposes the member).

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`ssl::bio_ssl` 1 passed / 1 ignored, and the ignored allocator probe
`set_ssl_allocation_refusal_clears_data_before_recreate` passes alone under
`OPENSSL_RS_ADV_PROBE=1` after the new shutdown/copy calls. BATCH: library
**1646 passed / 0 failed / 27 ignored** serially (308.67 s) and with
`--test-threads=4` (90.59 s). No test was removed or newly ignored.

**NOT_RUN.** Miri (Stacked/Tree Borrows; no miri in the court toolchain),
ASan/TSan/Loom, authority differentials for the repaired poisoned-state arms,
independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next eight unaudited ordinary files (reconciled set):**
`src/provider/ec_kmgmt.rs` (102 unattributed), `src/runtime/bio/bss_acpt.rs`
(102), `src/runtime/bio/bf_buff.rs` (101), `src/evp/keymgmt_lib.rs` (98),
`src/provider/decode_der2key.rs` (98), `src/ct/ct_sct.rs` (97),
`src/evp/pkey_asn1.rs` (96), `src/ssl/ssl_conf.rs` (94).
`src/provider/mod.rs` (118) stays skipped as a provider-dispatch boundary;
`src/ssl/record/rec_layer_s3.rs`, the `ssl/statem` modules and the ENGINE
dispatch files remain held.

## 36. Mechanism sweep M32 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `f5b42eef2` plus the worktree state
(the two repairs below, the canonical queue files and this record).

**Canonical structured queue.** `AUDITED-FILES.txt` is built only from
structured fields: each mechanism sweep's `.files` array (M2–M31, **233** unique),
the twelve M1 files in §3a, the nine records in `perfile-index.json`, and every
boundary sweep's `.boundaries[].file` (**48** unique, 9 overlapping a mechanism
sweep). The union is **293** audited census files. `PARTIAL-FILES.txt` is the
**761** `PARTIAL` rows of `attribution.json`; `REMAINING-AUDIT.txt` is
`comm -23`, **470** files before this batch and **462** after it. The census has
868 files (92 `ZERO_UNSAFE`, 15 `BOUNDARY_COVERED`, 761 `PARTIAL`) out of 877
`src/**/*.rs`. The old **268** figure omitted the 39 boundary-only files, predates
M31's 8 files, and was based on a 225-file mechanism union that the structured
arrays do not support.

**Scope:** the first eight security-relevant files in the stable remaining
order: AES modes, the ASN.1 read/dup/digest/write/print/type cluster, and
`BN_CTX`.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/aes.rs` | `AES_*` raw block/mode exports, `block128_f` callbacks, wrap/unwrap delegation | No defect. Every arm matches the pinned 3.6.4 `aes_ige.c`/`aes_wrap.c`, including the documented one-key `AES_bi_ige_encrypt` bug and the asserts-as-callers-preconditions (multiple of 16, 32/64-byte IV). |
| `src/asn1/a_d2i_fp.rs` | BIO read loop, `BUF_MEM_grow_clean` extents, ASN.1 header arithmetic | No defect. Checked adds guard every grown extent; the tag/length peeks stay inside `len`; the recoverable `ASN1_R_TOO_LONG` and clean-EOF branches match `a_d2i_fp.c`. |
| `src/asn1/a_dup.rs` | OB-1 `OwnedBuf` (`new_plain_released`/`adopt_plain`), `ASN1_AUX` callbacks | No defect. The `+10` slack, the encode/decode scratch release and the authority's aux-error leak are preserved; callbacks receive raw pointers only. |
| `src/asn1/a_digest.rs` | OB-1 `OwnedBuf`, engine/provider selection, fetched-method release | No defect. Every path releases the encoding; `fetched_md != md` drives the conditional release, as in `a_digest.c`. |
| `src/asn1/a_i2d_fp.rs` | OB-1 `OwnedBlock`, `from_raw` adoption, short-write loop | No defect. `write_all` is the authority's `j`/`n` loop; the memory-BIO failure path frees the BIO it made. |
| `src/asn1/a_print.rs` | `ASN1_STRING` extent, in-place compaction, signed-char classification | **M32-D1 fixed (medium, memory safety):** a negative `length` passed `% 4 == 0` and reached `from_raw_parts_mut(data, length as usize)`, forming an enormous slice (UB); the authority only writes one terminator. Now refused before any slice; safety contract states the nonnegative extent. Negative-control test added. |
| `src/asn1/a_type.rs` | OB-3 item ownership, `ASN1_TYPE_set` release-before-overwrite, pack/unpack octet ownership | No defect. The null-item `primitive_free` redirect and the three `t` cases match `a_type.c`; no borrow is held across a callback. |
| `src/bn/ctx.rs` | BN_CTX pool ownership, `BN_CTX_start`/`end` marks, `BN_GENCB` callback dispatch | **M32-D2 fixed (low, compatibility/security state):** `BN_CTX_get` now clears a leaked `BN_FLG_CONSTTIME` on a reused slot, matching `bn_ctx.c:237`. Test added. Box/Vec ownership, OOM-abort and the unmodelled `too_many` flag are recorded residuals, not UB. |

**New unsafe assumptions (hidden must be 0).** None. M32-D1 adds a refusal
before an existing slice formation; M32-D2 writes an existing flag field. No
unsafe operation, adoption, allocator coordinate, `#[repr(C)]` layout, exported
symbol or signature changed.

**Evidence.** FAST: fmt clean; focused `asn1::a_print` 1/1 and `bn::ctx` 1/1.
BATCH: clippy `--all-targets -D warnings` PASS; library **1648 passed / 0 failed
/ 27 ignored** serially (285.88 s) and with `--test-threads=4` (95.94 s). No test
removed or newly ignored.

**NOT_RUN.** Miri (Stacked/Tree Borrows), ASan/TSan/Loom, authority
differential for the invalid-extent refusal, independent adversarial review and
SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Next eight (stable order, library modules preferred).** `src/aria.rs`,
`src/asn1/asn1_item_list.rs`, `src/asn1/asn_mstbl.rs`, `src/asn1/asn_pack.rs`,
`src/asn1/a_strnid.rs`, `src/asn1/a_utf8.rs`, `src/asn1/d2i_param.rs`,
`src/asn1/d2i_pu.rs`. The literal first eight remaining lines are `src/apps/*`
CLI front-ends; they stay queued and are deferred, not excluded.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M32.json`](atlas-refresh/mechanism-sweep-M32.json).

## 37. Mechanism sweep M33 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `80a359d33` (no source change; the
batch is eight contract checks against OpenSSL 3.6.4 and adds only queue/record
edits).

**Scope:** the eight files M32 named as next: the ARIA compiled branch and an
ASN.1 reader/string-table/pack cluster.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/aria.rs` | `AriaU128` `#[repr(C)]` union views, `Key_RC`/`S1`/`S2`/`X1`/`X2` tables, round-key pointer arithmetic, both key schedules | No defect. The 147-row table check does not apply here; `KEY_RC` and the four word tables compare byte-for-byte with `crypto/aria/aria.c:60-66` and its `S1`..`X2` initialisers (unit test binds the `sb1`..`sb4` expansion). The `(bits + 256) / 32` count is computed only after the 128/192/256 check, which avoids the authority's signed-overflow UB without changing any valid-input result; `ARIA_GSRK`'s `Q`/`R` and the rotated `ARIA_DIFF_BYTE(T2,T3,T0,T1)` reproduce the macros. Decrypt is the same encrypt loop over the unwound schedule, matching `aria.c:601-683`. |
| `src/asn1/asn1_item_list.rs` | generated `asn1_item_list[]` order, `ASN1_ITEM_lookup` scan, `ASN1_ITEM_get` bound | No defect. Programmatic comparison of the Rust accessor list against `crypto/asn1/asn1_item_list.h` gives 147 entries in identical order; all guards are unset in the admitted profile. `i >= len` returns NULL as the authority does; a null `name` remains the authority's precondition (documented, not converted into a null answer). |
| `src/asn1/asn_mstbl.rs` | `CONF` section iteration, `X509V3_parse_list` ownership, `sk_CONF_VALUE_pop_free` callback, `strtoul` refusals | No defect. `min`/`max`/`mask`/`flags` acceptance and every refusal, the `cnf`-shaped versus `name`-shaped error record, the `STABLE_FLAGS_CLEAR` alias and the `ASN1_STRING_TABLE_add` call site match `asn_mstbl.c:57-117`. The 256-byte `BIO_snprintf` formatting buffer is the crate's established `ERR_raise_data` pattern (retained diagnostic truncation, not a safety obligation). |
| `src/asn1/asn_pack.rs` | `ASN1_STRING` in/out ownership slot, `ASN1_STRING_set0`, encode/decode scratch | No defect. The three `oct` cases, the `<= 0` encode test (the assignment happens before the test, as in C), the empty-`data` refusal and the shared `err:` release match `asn_pack.c`. `ASN1_item_unpack(_ex)` pass the string's extent and raise `ASN1_R_DECODE_ERROR` on null. |
| `src/asn1/a_strnid.rs` | `tbl_standard` NID order, runtime `stable` stack, `OwnedRow` zalloc/free ownership, mask intersection | No defect. All 28 rows, their bounds/masks/flags, the `nid <= 0` refusals, the sort-then-find over `stable`, the standard-table fallback and the owned-row copy match `a_strnid.c:118-234`. `ASN1_STRING_TABLE_cleanup` clears the atomic stack pointer before `OPENSSL_sk_pop_free`, exactly as the authority nulls `stable` first; `st_free` frees only `STABLE_FLAGS_MALLOC` rows. `table_cmp`'s null guard is a defensive no-UB path that valid stack contents never reach; `OwnedRow::from_raw` has an explicit single-release contract. |
| `src/asn1/a_utf8.rs` | `UTF8_getc` four refusal codes and length gating, `UTF8_putc` sizing convention and surrogate-before-length order | No defect. All four malformed forms (`-1`..`-4`), the `0xd800`-`0xdfff` refusal only in the three-byte arm, the non-minimal checks (`0x80`/`0x800`/`0x10000`) and the null-`str` width query match `a_utf8.c` exactly, including the observable `-2`-before-`-1` order in `UTF8_putc`. `val` is written only on success. |
| `src/asn1/d2i_param.rs` | `EVP_PKEY` slot ownership, `ameth->param_decode` callback dispatch, `BUF_MEM` read lifetime | No defect. The two refusals before the callback and the callback's own `0`, the `err:` identity test, and the `BUF_MEM_free` on both BIO-read paths match `d2i_param.c:18-65`. The `long`→`int` callback narrowing is reproduced deliberately. |
| `src/asn1/d2i_pu.rs` | type-switched `d2i_RSAPublicKey`/`d2i_DSAPublicKey`/`o2i_ECPublicKey`, downgraded-copy ownership, `err_out` identity test | No defect. The provided-EC downgrade, the `type != id || copy != NULL` set-type test, the RSA assignment-then-null-test (C assigns inside the condition), the DSA/EC member write-back and the `copy` release on both paths match `d2i_pu.c:28-98`. A caller-supplied key is not freed when `*a == ret`. |

**Defects.** None. No source file changed.

**New unsafe assumptions (hidden must be 0).** None. The batch adds no unsafe
operation, adoption, allocator coordinate, `#[repr(C)]` layout, exported symbol
or signature. Existing contracts were checked and reused: OB-1-style
zalloc/free ownership (`OwnedRow`), the typed-stack comparator/callback contract,
OB-4-style member-buffer slots in `d2i_pu`, the B-series no-Rust-borrow-across-a-
callback rule (`param_decode`, `sk_pop_free`), and the RC-1 refcount boundary
(no refcount transition in this batch; not applicable).

**Evidence.** FAST: fmt clean; focused `aria::` **6 passed / 0 failed**
(1,669 filtered). BATCH: clippy `--all-targets -D warnings` PASS; library
**1648 passed / 0 failed / 27 ignored** serially (222.92 s) and with
`--test-threads=4` (99.12 s). No test removed or newly ignored.

**NOT_RUN.** No file-specific adversarial probe exists for these units; Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay,
independent adversarial review and SEAL are `NOT_RUN`. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Queue.** `REMAINING-AUDIT.txt` 462 → **454**; `AUDITED-FILES.txt` 301 → **309**.

**Next eight (stable order).** `src/apps/asn1parse.rs`, `src/apps/ciphers.rs`,
`src/apps/cms.rs`, `src/apps/configutl.rs`, `src/apps/crl.rs`, `src/apps/dgst.rs`,
`src/apps/dhparam.rs`, `src/apps/dsa.rs`. These are CLI front-end boundaries and
remain deferred, not excluded.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M33.json`](atlas-refresh/mechanism-sweep-M33.json).

## 38. Mechanism sweep M34 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `85af84d93` plus the eight CLI
front-end repairs described below; contracts checked against OpenSSL 3.6.4.

**Scope:** the eight `src/apps/*` CLI front-ends M33 named as next. The audit
covered argument-string lifetimes (`Opts` copies argv, so no `&[String]` escapes),
file/BIO ownership on every exit, option-table bounds (`Opts::next`/`rest` are
bounds-checked), error tails, and every raw pointer returned by a getter.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/apps/asn1parse.rs` | `PEM_read_bio` name/header/data ownership, `BUF_MEM` adoption, DER read loop growth, offset/length bounds, `ASN1_parse_dump` | Repaired one compatibility defect: `length` was `c_long`, but the authority stores `strtol` in `unsigned int`, so `-length -1` stayed negative instead of becoming the clamped whole-buffer length. Now `c_uint` with `(int)length` comparisons. The DER loop's `checked_add` growth, the PEM block adoption (OB-1), and every exit's `BIO_free`/`BUF_MEM_free` are sound. |
| `src/apps/ciphers.rs` | `SSL_CTX_new_ex`/`SSL_new` ownership, `SSL_get1_supported_ciphers` stack ownership, callback registration, cipher-stack bounds | No defect. `sk` may be NULL, but `OPENSSL_sk_num(NULL)` is -1 and the loop is empty; the `use_supported` stack is freed once, `ctx`/`ssl` on every path, and the stdout/stderr BIOs are `BIO_NOCLOSE`. The `dummy_psk` callback has no state and cannot re-enter. |
| `src/apps/cms.rs` | `load_content_info` slot ownership, `CMS_sign_ex`/`CMS_add1_signer` refcounts, detached `bcont` BIO, `CMS_verify`, signer/key release | Repaired one leak: the detached-content BIO returned through `indata` was never freed (authority `BIO_free(indata)` at `apps/cms.c:1512`). It is now owned by `DetachedBio`, whose `Drop` releases it on every exit. `CMS_add1_signer` up-refs signer/key, so the post-call frees are correct and not double frees. |
| `src/apps/configutl.rs` | `NCONF_new`/`NCONF_load`/`NCONF_get_section_names`, `CONF_VALUE` borrowing, default-config block ownership | Repaired one leak: the `NCONF_get_section_names` stack was never freed (authority `sk_OPENSSL_CSTRING_free(sections)`). It is now released on both exits after the call; the stack holds borrowed names owned by `cnf` and has no element freefunc, which is what `OPENSSL_sk_free` models. |
| `src/apps/crl.rs` | `load_crl` ownership, `X509_CRL_get_ext_d2i` owned return, issuer/update getters, digest buffer, CRL writer | Repaired two compatibility defects: field prints went to the `-out` BIO instead of `bio_out` (the authority prints before opening `out`), and the `-hash` `<ERROR>` arm continued to write the CRL instead of bailing at `end:`. Prints now use a `BIO_NOCLOSE` stdout BIO opened first; `out` is opened after the print loop; all exits free `print_out`, `out` and `x` once. |
| `src/apps/dgst.rs` | `opt_md_silent` fetched-vs-legacy ownership, `BIO_new`/`BIO_push` chain, signature file BIO, `EVP_MD_CTX`, signer key | Repaired the authority-`end:` cleanup omissions: every early exit between the BIO allocations and the final release leaked the owned BIOs, digest, key and context. A single `dgst_cleanup` now performs the authority's exact release order (`BIO_free(in)`, `BIO_free_all(out)`, `EVP_MD_free(md)`, `EVP_PKEY_free(sigkey)`, `EVP_MD_CTX_free(signctx)`, `BIO_free(bmd)`); the free of `inb` before `bmd` matches `apps/dgst.c:506-512` and `BIO_free` does not traverse the filter chain. |
| `src/apps/dhparam.rs` | `load_keyparams` ownership, `EVP_PKEY_is_a`, `EVP_PKEY_param_check`, encoder context, numeric option parsing | Repaired one arithmetic defect: `strtol_base0` multiplied and added into `i128` unchecked, so a long numeric argument could panic in debug (or wrap in release) before the range check. It now uses `saturating_mul`/`saturating_add`, as `asn1parse` already did; overflow is still reported as an out-of-range value. |
| `src/apps/dsa.rs` | `load_key`/`load_pubkey` ownership, `EVP_PKEY_get_bn_param` owned BIGNUM, encoder context, output BIO | No memory-safety defect. All `pkey`/`out`/`ectx`/`pub_key` exits release once. Retained shared divergence: `bio_open_owner`'s owner-only permissions are not reconstructed, so a private-key `-out` uses `bio_open_default`/`fopen` semantics; `private` is computed but unused. This is the existing `apps/lib` boundary, not new to this batch. |

**Defects repaired (all low severity; none is UB).** `configutl` and `cms`
leaked one allocation per invocation; `dgst` leaked on its early failure paths;
`dhparam` could overflow `i128` on an over-long numeric option; `crl` misrouted
print fields and kept writing after the hash error; `asn1parse` mis-handled a
negative `-length`. No invalid free, double free, null dereference, alias or
uninitialised read was found.

**New unsafe assumptions (hidden must be 0).** Two documented ownership
contracts were added, both reusing established release mechanisms: `DetachedBio`
(one standalone MIME-split BIO, released once with `BIO_free`) and
`dgst_cleanup` (each pointer is NULL or the frame's one reference, released in
the authority's order). No new FFI symbol, allocator coordinate, `#[repr(C)]`
layout or signature; no hidden obligation. Contracts reused: OB-1 `OwnedBlock`
(asn1parse PEM names/header), OB-3 `OwnedCtx` release through
`OSSL_ENCODER_CTX_free`, the keyio load/BIO contract, the cipher-stack free
contract, and the B-series no-Rust-borrow-across-a-callback rule (`dummy_psk`).

**Evidence.** FAST: fmt clean; `cargo check --lib` PASS; `cargo test --lib --
apps::` **0 passed / 0 failed** (1,675 filtered — these front-ends have no unit
tests). BATCH: clippy `--all-targets -D warnings` PASS; library **1648 passed /
0 failed / 27 ignored** serially (253.62 s) and with `--test-threads=4`
(98.26 s). No test removed or newly ignored.

**NOT_RUN.** `courts/phase17/rt_cli_bodies_probe.sh` was not run: its candidate
shim points at the pre-batch `artifacts/phase2/openssl` (18 Oct) and the crate has
no CLI bin target to rebuild it, so a run would not exercise this candidate. Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay for these
eight units, independent adversarial review and SEAL are `NOT_RUN`. Nothing is
promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** `src/apps/dsa.rs` uses `bio_open_default` for
a `bio_open_owner` call site (shared `apps/lib` permission divergence); `cms` and
dsa omit the pointer-bearing `ERR_print_errors` tails; `crl` prints a repeated
option once per occurrence where the authority's per-option index prints once;
`asn1parse` keeps `offset` as `c_long` where the authority uses `int` (only
> `INT_MAX` values diverge); `configutl` writes `-out` at the end rather than
opening it before the config load.

**Queue.** `REMAINING-AUDIT.txt` 454 → **446**; `AUDITED-FILES.txt` 309 → **317**.

**Next eight (stable order).** `src/apps/ecparam.rs`, `src/apps/ec.rs`,
`src/apps/enc.rs`, `src/apps/engine.rs`, `src/apps/errstr.rs`,
`src/apps/genrsa.rs`, `src/apps/info.rs`, `src/apps/kdf.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M34.json`](atlas-refresh/mechanism-sweep-M34.json).

## 39. Mechanism sweep M35 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `cdaab4e27` plus the two CLI
front-end repairs described below; contracts checked against OpenSSL 3.6.4
(`apps/enc.c`, `apps/kdf.c` read at the pinned tag).

**Scope:** the eight `src/apps/*` CLI front-ends M34 named as next. The audit
covered argument-string lifetimes (`Opts` copies argv, so no `&[String]`
escapes), file/BIO ownership on every exit, option-array bounds, error tails,
allocation arithmetic, and every raw pointer returned by a getter.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/apps/ecparam.rs` | `EC_get_builtin_curves` count-then-fill, `BIO` ownership, fixed `[OSSL_PARAM; 4]`, keygen/load `EVP_PKEY` ownership, encoder context | No defect. Both curve calls use the table count as `nitems`, so `set_len(filled)` is exact; the parameter array holds at most three entries plus the terminator; every key/out/ctx exit releases once. `-no_seed`/`-check_named` reach `not_landed`. |
| `src/apps/ec.rs` | `load_key`/`load_pubkey`, output `BIO`, parameter setters with `CString`, print/check contexts, encoder context | No defect. Each `CString` outlives its parameter call; `eckey`/`out` are released once on every failure path. The encoder's NULL context is tolerated by `OSSL_ENCODER_to_bio`, producing the authority's same failure message. |
| `src/apps/enc.rs` | `set_hex` bounds, `-bufsize` conversion, base64/cipher `BIO` chain ownership, `EVP_CIPHER` ownership, cipher key/IV extents, opaque-key option routing | Repaired one medium option-routing defect: `-skeyopt` only set a flag and `-skeymgmt` was ignored, so with a cipher and no `-K` the body silently initialised the cipher with the all-zero key buffer. Both options now reach `not_landed` at parse time. `set_hex` cannot index past `out`; `-bufsize` reproduces the authority's `k`/`opt_long`/`LONG_MAX/1024` check; chain release order matches `apps/enc.c:801-821`. |
| `src/apps/engine.rs` | `ENGINE_by_id` functional ref vs `ENGINE_get_first/get_next` structural pointer, init/finish balance, id/name getters, BIO owners | No defect. Only the `ENGINE_by_id` reference is freed; the listing walk follows the authority and does not free structural pointers. Getter strings are NULL-checked; control command strings outlive the call; every early exit frees `out`. |
| `src/apps/errstr.rs` | 256-byte `ERR_error_string_n` buffer, `CStr`, `OPENSSL_init_ssl`, `%lx` conversion | No defect. The buffer is NUL-terminated within its given length and the borrow is scoped; the init settings pointer is NULL; the hex parser uses wrapping arithmetic only. |
| `src/apps/genrsa.rs` | `BN`/`BN_GENCB` single-owner release, base-0 conversion, `-primes`, `numbits` validation | No memory-safety defect. Both allocations are freed exactly once on every path. A negative magnitude beyond `LONG_MAX+1` is accepted as `LONG_MIN` and then rejected by `opt_int`; the authority rejects it as unparseable, both exit 1. |
| `src/apps/info.rs` | `OPENSSL_info` getter pointer, selector accounting | No defect. The one raw getter is NULL-checked before `CStr`; selector accounting has no indexing. |
| `src/apps/kdf.rs` | `app_params_new_from_opts` array allocation/free, `OSSL_PARAM_allocate_from_text`, cleansed derived key, hex rendering adoption, `EVP_KDF` ownership | Repaired one low arithmetic defect: the `OSSL_PARAM` array used `(opts.len()+1) * size_of` without checked arithmetic. It now uses `checked_add`/`checked_mul` and returns NULL (the existing malformed-option failure). Every exit releases params/out/ctx/kdf/key/hex once. |

**Defects repaired.** `enc`'s opaque symmetric-key options could silently degrade to
a zero raw key (`-skeyopt`) or be ignored (`-skeymgmt`); both now stop at the
documented `not_landed` boundary. `kdf` sized its parameter array with unchecked
arithmetic; the product is now checked, matching `OPENSSL_calloc`'s rejection.
Neither repair adds, removes or relocates an unsafe operation. No invalid free,
double free, null dereference, alias, uninitialised read or new hidden obligation
was found.

**New unsafe assumptions (hidden must be 0).** None. Both repairs are safe-code
changes (control flow and checked arithmetic). Contracts reused: the keyio
load/BIO contract, OB-1 `OwnedBuf` (`new_cleansed_at`, `adopt_plain`), OB-3
encoder-context release, the `ENGINE` structural/functional reference rule from
B16, and the `Opts` bounds contract.

**Evidence.** FAST: fmt clean; `cargo check --lib` PASS; `cargo test --lib --
apps::` **0 passed / 0 failed** (1,675 filtered — these front-ends have no unit
tests). BATCH: clippy `--all-targets -D warnings` PASS; library **1648 passed /
0 failed / 27 ignored** serially (64.66 s) and with `--test-threads=4`
(96.40 s). No test was removed or newly ignored.

**NOT_RUN.** `courts/phase17/rt_cli_bodies_probe.sh` needs a CLI executable; the
crate has no bin target and the probe's candidate shim points at the pre-batch
`artifacts/phase2/openssl`, so a run would not exercise this candidate. Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay for these
eight units, independent adversarial review and SEAL are `NOT_RUN`. Nothing is
promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** `ec` and `ecparam` use `bio_open_default` for
a `bio_open_owner` call site (shared `apps/lib` permission divergence); `enc`
does not reproduce `-v`'s byte reports, prints a zero-initialised `-P` salt where
the authority prints an indeterminate stack buffer, and leaves `-K`/`-iv`
argument copies and the key/IV buffers un-cleansed; `engine` renders a NULL
id/name as an empty string; `genrsa`'s negative-overflow message differs; `kdf`
omits the pointer-bearing `ERR_print_errors` tails.

**Queue.** `REMAINING-AUDIT.txt` 446 → **438**; `AUDITED-FILES.txt` 317 → **325**.

**Next eight (stable order).** `src/apps/keyio.rs`, `src/apps/mac.rs`,
`src/apps/nseq.rs`, `src/apps/ocsp.rs`, `src/apps/passwd.rs`,
`src/apps/pkcs12.rs`, `src/apps/pkcs7.rs`, `src/apps/pkcs8.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M35.json`](atlas-refresh/mechanism-sweep-M35.json).

## 40. Mechanism sweep M36 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `cbe7d2512` plus the three CLI
front-end repairs described below; contracts checked against OpenSSL 3.6.4
(`apps/{mac,ocsp,pkcs12}.c` read at the pinned tag).

**Scope:** the eight `src/apps/*` CLI front-ends M35 named as next. The audit
covered argument-string lifetimes (`Opts` copies argv, so no `&[String]` escapes),
file/BIO ownership on every exit, option-array bounds, error tails, allocation
arithmetic, and every raw pointer returned by a getter or owned by the body.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/apps/keyio.rs` | `bio_open_default`, `open_input` `CString` lifetime, `load_key`/`load_pubkey`/`load_cert`/`load_crl`/`load_keyparams` BIO ownership, public-then-private re-open fallback | No defect. Every `CString` outlives its `BIO_new_file`, each BIO is released once on every exit (including the `load_pubkey` failure re-open), and no getter pointer escapes the call. |
| `src/apps/mac.rs` | local `OwnedBuf` release, `app_params_new_from_opts` allocation/free, `OSSL_PARAM_allocate_from_text` extents, `EVP_MAC`/`EVP_MAC_CTX` ownership, read/final/output bounds, `CString` lifetimes | Repaired one low arithmetic defect: the `OSSL_PARAM` array used `(len + 1) * size_of` unchecked, so the product could wrap before `CRYPTO_zalloc` and later writes. It now uses `checked_add`/`checked_mul` and returns NULL, matching `OPENSSL_calloc`'s rejection. `app_params_free` stops at the calloc'ed terminator; `len <= BUFSIZE` bounds the hex loop and `BIO_write`. |
| `src/apps/nseq.rs` | `NETSCAPE_CERT_SEQUENCE`/`certs` stack ownership, `PEM_read_bio_X509` loop, `OPENSSL_sk_*` bounds, borrowed name getters, BIO cleanup order | No defect. `seq` is assigned on both arms before the common `end:`; the stack and its certificates are released once by `NETSCAPE_CERT_SEQUENCE_free`, and every exit frees `out` before `in` as the authority does. |
| `src/apps/ocsp.rs` | `OCSP_REQUEST_new`/`-free`, `load_cert` ownership for `-issuer`/`-cert`, `EVP_MD_fetch`/legacy method, `OCSP_cert_to_id`/`OCSP_request_add0_id`, nonce, request writer BIO | Repaired one low ownership defect: the loaded `issuer`/`cert` and fetched `cert_id_md` were never released (the authority frees all three at `end:`), and a replaced `-issuer`/`-cert` leaked its predecessor. A documented `OcspState` single-owner `Drop` now releases them on every exit; replacement frees the previous object as `apps/ocsp.c:481` does. |
| `src/apps/passwd.rs` | `Md` RAII over `EVP_MD_CTX_*`, digest buffer widths (16/64), salt truncation/clamping, output permutation indices, `-in` line reading and `pw_maxlen` truncation | No defect. Every digest write fits its fixed buffer; `passwd[..1]` is reached only when the length is non-zero; the md5 permutation indices stay below 16 and the SHA-256/512 tables below 32/64. Non-ASCII salts truncate by `char` rather than byte, and `-in -`/`-stdin` are unlanded — retained divergences, not memory-safety defects. |
| `src/apps/pkcs12.rs` | `load_cert`/`load_key` ownership, `PKCS12_create_ex2` argument extents, `-nomac`/`-iter` routing, `i2d_PKCS12_bio`, output BIO | Repaired one low compatibility defect: `-iter` fell back to `0` on a failed parse, silently selecting the default; `opt_int_arg` returns `-1` on failure, which is preserved now. `cert`/`key` are released once on every path and after `PKCS12_free`, never before. |
| `src/apps/pkcs7.rs` | `PKCS7_new_ex` + `d2i`/PEM out-slot reuse, `PKCS7_free`, borrowed `cert`/`crl` stacks, `OBJ_obj2nid` union selection, print/write paths, BIO ownership | No defect. A failed `d2i`/PEM decode clears the out-slot through `ASN1_item_ex_free`, so the later `PKCS7_free(p7)` is not a double free; the stack walk is bounds-checked by `OPENSSL_sk_num`, and all three resources are released once on every return. |
| `src/apps/pkcs8.rs` | `load_key`, `EVP_PKEY2PKCS8`/`EVP_PKCS82PKEY`, `PKCS8_PRIV_KEY_INFO_free`, PEM/DER writers, input/output BIO ownership | No defect. `pkey`, `p8inf`, `out` and `inbio` are released once on every branch; the conversion routines do not transfer ownership. `-iter`/`-saltlen` are parsed but unused in the landed `-nocrypt` arms and only feed the unlanded encrypted arms — retained divergence. |

**Defects repaired (all low severity; none is UB).** `mac` sized its parameter
array with unchecked multiplication; `ocsp` leaked the loaded issuer, certificate
and fetched digest (and a replaced issuer/certificate) on success and on every
failure after loading; `pkcs12` used the wrong fallback value for an invalid
`-iter`. No invalid free, double free, null dereference, alias, uninitialised
read or new hidden obligation was found.

**New unsafe assumptions (hidden must be 0).** One documented ownership contract
was added: `OcspState` (each field is NULL or the frame's single reference,
released once by `Drop` through `OCSP_REQUEST_free`/`X509_free`/`EVP_MD_free`,
all of which accept NULL; `EVP_MD_free` is the authority's no-op for a static
legacy method). No new FFI symbol, allocator coordinate, `#[repr(C)]` layout or
signature; no hidden obligation. Contracts reused: the keyio load/BIO contract,
OB-3-style single-owner release, the local `OwnedBuf` scratch-buffer contract in
`mac`, the `ASN1_item_ex_free` out-slot clearing rule, and the `Opts` bounds
contract.

**Evidence.** FAST: fmt clean; `cargo check --lib` PASS; `cargo test --lib --
apps::` **0 passed / 0 failed** (1,675 filtered — these front-ends have no unit
tests). BATCH: clippy `--all-targets -D warnings` PASS; library **1648 passed /
0 failed / 27 ignored** serially (202.25 s) and with `--test-threads=4`
(93.85 s). No test removed or newly ignored.

**NOT_RUN.** `courts/phase17/rt_cli_bodies_probe.sh` was not run: the crate has no
CLI bin target and the probe's candidate shim points at the pre-batch
`artifacts/phase2/openssl`, so a run would not exercise this candidate. Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay for these
eight units, independent adversarial review and SEAL are `NOT_RUN`. Nothing is
promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** `ocsp` still leaks a detached `OCSP_CERTID`
on the `OCSP_request_add0_id` failure arm (the authority's stack-only
`sk_OCSP_CERTID_free` does the same); `ocsp`/`pkcs12`/`pkcs8` omit the
pointer-bearing `ERR_print_errors`/`opt_int` diagnostics; `passwd` truncates a
non-ASCII salt by `char` where the authority truncates by byte and leaves `-in
-`/`-stdin` unlanded; `pkcs8` defers `-iter`/`-saltlen` to the unlanded encrypted
arms; the shared `bio_open_owner` permission divergence remains for the private
output paths.

**Queue.** `REMAINING-AUDIT.txt` 438 → **430**; `AUDITED-FILES.txt` 325 → **333**.

**Next eight (stable order).** `src/apps/pkeyparam.rs`, `src/apps/pkey.rs`,
`src/apps/prime.rs`, `src/apps/rand.rs`, `src/apps/req.rs`, `src/apps/rsa.rs`,
`src/apps/sess_id.rs`, `src/apps/skeyutl.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M36.json`](atlas-refresh/mechanism-sweep-M36.json).

## 41. Mechanism sweep M37 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `330816a1f` plus the three repairs
described below; contracts checked against OpenSSL 3.6.4
(`apps/{pkeyparam,pkey,prime,rand,req,rsa,sess_id,skeyutl}.c` and
`apps/lib/opt.c` read at the pinned tag).

**Scope:** the eight `src/apps/*` CLI front-ends M36 named as next. The audit
covered argument-string lifetimes (`Opts` copies argv, so no `&[String]`
escapes), file/BIO ownership on every exit, option-array bounds, error tails,
allocation arithmetic, getter-returned pointers and body-owned raw pointers.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/apps/pkeyparam.rs` | `bio_open` stdio/file split, `PEM_read_bio_Parameters_ex`, `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_param_check`, `PEM_write_bio_Parameters`/`EVP_PKEY_print_params`, `BIO_free`/`BIO_free_all` | No defect. `inbio` and `out` are released once on every return; the `-check` valid arm keeps the context live until after the write; `BIO_write`'s length is the 21-byte literal. |
| `src/apps/pkey.rs` | `load_key`/`load_pubkey`, `EVP_PKEY_CTX_new`/`EVP_PKEY_check`, `PEM_write_bio_PrivateKey`/`_traditional`/`PUBKEY`, `i2d_PKCS8PrivateKey_bio`/`i2d_PUBKEY_bio`/`i2d_PrivateKey_bio`, `EVP_PKEY_print_*`, output BIO | No defect. `pkey`/`out` are released once on every exit; the `-ec_conv_form`/`-ec_param_enc` arm frees both before refusing; `private` is retained only for the shared permission divergence below. |
| `src/apps/prime.rs` | `BN_hex2bn`/`BN_dec2bn` out-slot, `BN_print`/`BN_check_prime`, `BN_bn2hex`/`BN_bn2dec` adoption through `OwnedBlock`, `BIO_get_line`/`BUFSIZE` bounds, `hex_digit_prefix` | No defect. `BIO_get_line` writes at most `BUFSIZE-1` bytes and NUL-terminates, so `hex_digit_prefix` stops at index `BUFSIZE-1` and `buf[n] = 0` is in bounds; the `BN_bn2hex`/`BN_bn2dec` block is one adopted allocation with the `OPENSSL_free` seam at `(NULL, 0)`. |
| `src/apps/rand.rs` | `opt_long`/`strtol` suffix parse, `RAND_bytes_ex` chunking, `BIO_f_base64` push, `BIO_write`/`BIO_puts`/`BIO_ctrl` flush, output BIO | No defect. `chunk <= 1<<16` and `hex.len() <= 1<<17` fit the `c_int` write count; `scaled_num` is bounded by `UINT64_MAX >> 3` before the loop; the base64 chain is released once by `BIO_free_all`. Matches OpenSSL 3.6.4 (which has no `-n`). |
| `src/apps/req.rs` | `load_csr` BIO ownership/stdin arm, `X509_REQ_get0_pubkey`, `X509_REQ_verify`, `X509_REQ_print_ex`, `print_name`, `PEM_write_bio_PUBKEY`, request writers, output BIO | Repaired two defects: a NULL `X509_REQ_get0_pubkey` result skipped `-verify` and could exit 0; and `load_csr` refused a NULL filename instead of reading stdin as `load_csr_autofmt` does. `req`/`out` are released once on every return. |
| `src/apps/rsa.rs` | `load_key`/`load_pubkey`, `EVP_PKEY_is_a`, `EVP_PKEY_get_bn_param`/`BN_print`, `EVP_PKEY_CTX_new_from_pkey`/`EVP_PKEY_check`, `OSSL_ENCODER_CTX_new_for_pkey`/`to_bio`/`_free`, `try_legacy_encoding`, output BIO | Repaired one compatibility defect: `-RSAPublicKey_in` set `pubin = 2` but `keyio::load_pubkey` has no PKCS#1 public-key arm, so it decoded a different format; the arm now reaches `not_landed`. `pkey`, `out` and `ectx` are released once on every exit. |
| `src/apps/sess_id.rs` | `load_sess_id` BIO ownership, `PEM_read_bio_SSL_SESSION`, `SSL_SESSION_get0_peer`, `SSL_SESSION_set1_id_context`, `SSL_SESSION_print`/`_print_keylog`, `X509_print`, `i2d_X509_bio`, request writers, output BIO | No defect. `peer` is borrowed from `x` and used only while `x` is live; `out` is NULL when `-noout` suppresses printing and `BIO_free_all(NULL)` is the authority's no-op; `x`/`out` are released once on every return. |
| `src/apps/skeyutl.rs` | `EVP_SKEYMGMT_fetch`/`EVP_SKEY_generate`, `EVP_SKEY_get0_*` getters, `EVP_SKEY_free`/`EVP_SKEYMGMT_free`, `EVP_CIPHER_free`, `bio_err` BIO | No defect. `cstr` never retains a getter pointer past the call; `skey` is NULL-or-live before the single `EVP_SKEY_free`; `mgmt` is released after `skey`; the stderr BIO is NOCLOSE and freed once per arm. |

**Defects repaired (none is UB).** `req` silently skipped `-verify` when
`X509_REQ_get0_pubkey` answered NULL and could then return success (medium,
verification bypass by false success); `req` refused a NULL `-in` instead of
reading stdin (low, incomplete transcription); `rsa -RSAPublicKey_in` accepted
the flag but used the SubjectPublicKeyInfo decoder (low, wrong format accepted).
No invalid free, double free, null dereference, alias, uninitialised read or new
hidden obligation was found.

**New unsafe assumptions (hidden must be 0).** None. No unsafe operation was
added: the `req` guard reuses the existing `X509_REQ_get0_pubkey` and
`X509_REQ_free` calls, the stdin arm reuses `keyio::bio_open_default`, and the
`rsa` arm only returns `not_landed`. No new FFI symbol, allocator coordinate,
`#[repr(C)]` layout or signature. Contracts reused: the `Opts` copying/bounds
contract (`rest`/`num_rest`/`check_rest_arg`), the keyio `bio_open_default`
stdio/file contract, OB-3-style NULL-tolerant single release, the `OwnedBlock`
adoption contract for `BN_bn2hex`/`BN_bn2dec`, and the `BIO_NOCLOSE`
standard-stream contract.

**Evidence.** FAST: fmt clean; `cargo check --lib` PASS; `cargo test --lib --
apps::` **0 passed / 0 failed** (1,675 filtered — these front-ends have no unit
tests); `cargo test --lib -- x509_req` **3 passed**. Targeted control: a direct
`apps::req::main` probe on the court's `req.pem` returned 0 with `Certificate
request self-signature verify OK`; the same CSR with its SPKI algorithm OID
rewritten to unassigned `1.2.840.113549.1.1.99` (so `X509_REQ_get0_pubkey` is
NULL) returned **1** and printed no OK line. BATCH: clippy `--all-targets -D
warnings` PASS; library **1648 passed / 0 failed / 27 ignored** serially
(220.78 s) and with `--test-threads=4` (93.48 s). No test removed or newly
ignored.

**NOT_RUN.** `courts/phase17/rt_cli_bodies_probe.sh` was not run: the crate has no
CLI bin target and the probe's candidate shim points at the pre-batch
`artifacts/phase2/openssl`. The `-RSAPublicKey_in` decoder path is unlanded, so
its authority parity is untested. Miri (Stacked/Tree Borrows), ASan/TSan/Loom,
authority differential replay for all eight units, independent adversarial
review and SEAL are `NOT_RUN`. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** The shared `bio_open_owner` permission
divergence remains for `pkey`/`rsa` private-key output (and the other apps that
use `bio_open_default` for an owner-mode file); `req` parses `-days` with
`str::parse`/`unwrap_or(0)` where the authority uses `opt_int_arg` and
`UNSET_DAYS = -2` (only the unlanded `-x509` arm consumes it); `pkey`/`rsa`
accept only the PEM/DER input formats, not the authority's `OPT_FMT_ANY`
`P12`; every error tail omits the pointer-bearing `ERR_print_errors` lines;
`-RSAPublicKey_in` is now explicitly unlanded until a PKCS#1 public-key decoder
is added to `keyio`.

**Queue.** `REMAINING-AUDIT.txt` 430 → **422**; `AUDITED-FILES.txt` 333 → **341**.

**Next eight (stable order).** `src/apps/speed.rs`, `src/apps/spkac.rs`,
`src/apps/storeutl.rs`, `src/apps/ts.rs`, `src/apps/verify.rs`,
`src/apps/version.rs`, `src/apps/x509.rs`, `src/asn1_dsa.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M37.json`](atlas-refresh/mechanism-sweep-M37.json).

## 42. Mechanism sweep M38 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `23bd395c0` plus the five
resource/compatibility repairs across four files described below; contracts
checked against OpenSSL 3.6.4
(`apps/{speed,spkac,storeutl,ts,verify,version,x509}.c`, `crypto/asn1_dsa.c` and
`crypto/ts/ts_req_utils.c` at the pinned tag).

**Scope:** the eight files M37 named as next. The audit covered argument-string
lifetimes (`Opts` copies argv), file/BIO ownership on every exit including option
refusals, option-array bounds, error tails, allocation arithmetic, getter-returned
and body-owned raw pointers, and (for `asn1_dsa.rs`) the borrowed `Packet` cursor
contracts against their `dsa/sign.rs` callers.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/apps/speed.rs` | `EVP_MD_fetch`/legacy fallback, `EVP_DigestInit`, `EVP_MD_CTX_free`/`EVP_MD_free`, `Opts` arms | No defect. Fetched methods are released once; `EVP_MD_free` refuses the legacy/static origin, so the fallback is a no-op; every arm returns before the buffer. |
| `src/apps/spkac.rs` | `bio_open` stdio/file split, `NCONF_new`/`NCONF_load_bio`/`NCONF_get_string`, `NETSCAPE_SPKI_b64_decode`/`_print`/`_get_pubkey`/`_verify`, `PEM_write_bio_PUBKEY` | No defect. `inb`/`conf`/`spki`/`out`/`pkey` are released once on every return; a NULL `NETSCAPE_SPKI_get_pubkey` reaches the library's NULL-refusal arms exactly as the authority's unchecked use; `_passin` is the helper's NULL block. |
| `src/apps/storeutl.rs` | `OSSL_STORE_open`/`_expect`/`_load`/`_error`/`_eof`/`_close`, `OSSL_STORE_INFO_*` getters, `bio_out`/`bio_err`, output BIO | Repaired one compatibility defect: after the load loop the transcription reopened `out`, which `storeutl.c:507` does not; with zero loaded items it created the `-out` file and wrote `Total found: 0`, where the authority leaves `out` NULL and its `BIO_vprintf` refuses. The reopen is removed. |
| `src/apps/ts.rs` | `EVP_MD_fetch`/legacy `opt_md`, `NCONF_load`, `create_digest` chunking, `TS_REQ_new`/`TS_MSG_IMPRINT_new`/`X509_ALGOR_new`/`ASN1_TYPE_new`, setters' duplicate-on-set semantics, `d2i_TS_REQ_bio`/`i2d_TS_REQ_bio`/`TS_REQ_print_bio`, output BIO | Repaired three ownership leaks: `query_command` opened a data/stdin BIO before refusing the unlanded `-digest` hex arm (leak on every such run) and now checks the arm first, matching the authority's `digest == NULL && (data_bio = ...)`; `default_config_file` dropped the `CONF_get1_default_config_file` block and now adopts it with `OwnedBlock` at the (NULL, 0) seam; `main`'s two config-failure arms returned after `opt_md` fetched an `EVP_MD` without releasing it, and now free it. |
| `src/apps/verify.rs` | `X509_VERIFY_PARAM_new`/`_free`, `setup_verify` file arm, `X509_STORE_CTX_new`/`_init`/`_free`, verify callback, `X509_verify_cert`, output BIO | Repaired one ownership leak: `vpm` was allocated before the option loop but released only on the final arm, so every parse refusal/`not_landed` return leaked it. `VpmGuard` now gives every exit the authority's single `end:` release, in the authority's order (`vpm`, then `store`). Callback pointers (`current_cert`, `parent`) are borrowed only across the callback; `V_VERBOSE`/`VFLAGS` are process globals of a single-threaded CLI. |
| `src/apps/version.rs` | `OpenSSL_version` `'static` C string | No defect. `CStr::from_ptr` is used only on the documented never-NULL static string. |
| `src/apps/x509.rs` | `load_cert`, `X509_get0_pubkey`, `X509_get_issuer/subject_name`, `X509_get0_serialNumber`, `X509_get0_notBefore/After`, `X509_digest` into a 64-byte buffer, `X509_print_ex`, `i2d_X509_bio`/`PEM_write_bio_X509`, output BIO | No defect. `pkey` and the name/time/serial pointers are borrowed from live `x`; the SHA-1 digest length is bounded by `EVP_MAX_MD_SIZE` (64); `out`/`x` are released once on every return. |
| `src/asn1_dsa.rs` | borrowed `Packet` cursor (`get_1`, `get_net_2`, `get_bytes`, `get_sub`, length-prefixed 1/2), `WPACKET` encoder, `BN_bn2binpad`/`BN_bin2bn`, `offset_from` | No defect found. Every advance is guarded by `remaining`; `buf_init` refuses `len > SIZE_MAX/2`; the sub-packet borrow is a prefix of the parent; `ossl_decode_der_dsa_sig`'s `offset_from` stays within the caller's slice and `*ppin` advances by the consumed count. The `dsa/sign.rs` callers establish the documented precondition (`*ppin` readable for `len`, live `r`/`s`, live `WPACKET`). BOUNDARY closure is `NOT_RUN` (see below). |

**Defects repaired (none is UB).** Five resource/compatibility divergences: `ts` leaked a data/stdin BIO on the unlanded hex-digest
arm, leaked the default-config allocation, and leaked the fetched `EVP_MD` on two
config-failure arms (low); `verify` leaked its `X509_VERIFY_PARAM` on every
option-parse refusal (low); `storeutl` created an `-out` file and emitted
`Total found: 0` where the authority emits nothing when zero items load (low).
No invalid free, double free, null dereference, alias, uninitialised read or new
hidden obligation was found.

**New unsafe assumptions (hidden must be 0).** None. One new unsafe operation
was added, inside an established contract: `OwnedBlock::<c_char>::from_raw` in
`ts::default_config_file` reclaims the `CONF_get1_default_config_file` block
(configutl's identical adoption). `verify`'s `VpmGuard::drop` calls the existing
NULL-tolerant `X509_VERIFY_PARAM_free`; the pointer is produced in the same frame
and the guard is its exclusive owner. No new FFI symbol, allocator coordinate,
`#[repr(C)]` layout or signature. Contracts reused: `Opts` copying/bounds
(`rest`/`check_rest_arg`), keyio `bio_open_default` stdio/file, OB-1
`OwnedBlock` adoption with the (NULL, 0) release seam, OB-3-style NULL-tolerant
single release, `BIO_NOCLOSE` standard-stream, and the `Packet` borrowed-cursor
contracts.

**Evidence.** FAST: fmt clean; `cargo check --lib` PASS (9.34 s);
`cargo test --lib -- apps::` **0 passed / 0 failed** (1,675 filtered — these
front-ends have no unit tests); affected object tests
`ts_verify_ctx` **2 passed** and `x509_vpm` **7 passed**. BATCH: clippy
`--all-targets -D warnings` PASS; library **1648 passed / 0 failed / 27
ignored** serially (212.28 s) and with `--test-threads=4` (107.24 s). No test
removed or newly ignored.

**NOT_RUN.** No CLI bin target exists, so the app-level differential probes and
`courts/phase17/rt_cli_bodies_probe.sh` were not run. Allocator-hook
instrumentation for the repaired lifetimes, Miri (Stacked/Tree Borrows),
ASan/TSan/Loom, authority differential replay of the eight units, independent
adversarial review and SEAL are `NOT_RUN`. `asn1_dsa.rs`'s caller/dependency
closure is `NOT_RUN`; only its own contracts and the two `dsa/sign.rs` call sites
were checked. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** Every error tail still omits the
pointer-bearing `ERR_print_errors` lines; `verify`'s callback returns `ok`
without the authority's error-to-`ok` conversions (a failing chain is not
driven); `x509 -out` opens through `bio_open_default` without the
`outformat`-derived binary-mode flag (identical on Unix); `ts -reply`/`-verify`,
the `-digest` hex, `-policy` and nonce arms remain unlanded; `verify`'s
`V_VERBOSE`/`VFLAGS` are `static mut` process globals (single-threaded CLI, no
thread-safety claim); `spkac`'s unchecked `NETSCAPE_SPKI_get_pubkey` result is
NULL-refused by the library, matching the authority.

**Queue.** `REMAINING-AUDIT.txt` 422 → **414**; `AUDITED-FILES.txt` 341 → **349**.

**Next eight (stable order).** `src/asn1/evp_asn1.rs`, `src/asn1/i2d_evp.rs`,
`src/asn1/layout.rs`, `src/asn1/nsseq.rs`, `src/asn1/p5_pbe.rs`,
`src/asn1/p5_pbev2.rs`, `src/asn1/p5_scrypt.rs`, `src/asn1/p8_pkey.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M38.json`](atlas-refresh/mechanism-sweep-M38.json).

## 43. Mechanism sweep M39 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `e14d89768` plus the four repairs
described below; contracts checked against OpenSSL 3.6.4
(`crypto/asn1/{evp_asn1,i2d_evp,nsseq,p5_pbe,p5_pbev2,p5_scrypt,p8_pkey}.c` and
the generated `ASN1_ITEM`/`ASN1_TEMPLATE` descriptors).

**Scope:** the eight files M38 named as next. The audit covered the ASN.1 item
descriptors and their callbacks, allocated-block ownership in the PBE/PBKDF2/
scrypt builders, the fixed `EVP_MAX_IV_LENGTH` stack buffers, PKCS#8 private-key
cleansing and release, and the provided/legacy key DER writer hand-offs. Salt
and IV buffers were classified as public AlgorithmIdentifier contents; the
`PKCS8_PRIV_KEY_INFO.pkey` octets as secret and cleansing-required.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/asn1/evp_asn1.rs` | `asn1_int_oct`/`asn1_oct_int` items, borrowed local octet string over the caller's buffer, `ASN1_TYPE_pack_sequence`/`_unpack_sequence`, unpack-temporary free | No defect. The local string is a view and is never freed; the temporary is released once on every arm. The added `n > 0`/non-NULL guards only change the authority's C-invalid inputs (where it has UB). |
| `src/asn1/i2d_evp.rs` | `i2d_provided` chain walk, ENCODER context lifecycle, legacy `ameth` encoders, `ossl_evp_pkey2pkcs8` temporary | No defect. Each ENCODER context is released once; the temporary PKCS#8 is released once through the p8_pkey item (and now takes the repaired cleanse/release). Output buffers are caller-owned. |
| `src/asn1/layout.rs` | `repr(C)` item/template/AUX/ADB/TLC/PCTX/SCTX descriptors, four `unsafe impl Sync` claims | No defect. Definition-only unit; the Sync claims cover load-once statics of scalars, raw pointers and function pointers. |
| `src/asn1/nsseq.rs` | `NETSCAPE_CERT_SEQUENCE` item, `nsseq_cb` NEW_POST, shared `OBJ_nid2obj` static, item codecs | No defect. The callback borrows the static OID exactly as the authority; object free refuses the static origin. Certificates are public data. |
| `src/asn1/p5_pbe.rs` | `PBEPARAM` item, `SaltBuf`, `ASN1_STRING_set0` transfer, `X509_ALGOR_set0` adoption | Repaired one allocator-seam coordinate: the RAND-failure block is released at `p5_pbe.c:76` (the `OPENSSL_free` the `goto` reaches), not at the `:59` goto. Ownership and ordering already matched. |
| `src/asn1/p5_pbev2.rs` | `PBE2PARAM`/`PBKDF2PARAM`/`PBMAC1PARAM` items, `SaltBuf` at asn1_lib coordinates, 16-byte stack IV, cipher-context lifecycle | Repaired a latent stack overflow: the IV copy/draw trusted `EVP_CIPHER_get_iv_length` with no upper bound, reachable via `EVP_CIPHER_meth_set_iv_length`. Lengths above `EVP_MAX_IV_LENGTH` now take the bare `err:` tail (cms_enc/pem_bridge precedent). |
| `src/asn1/p5_scrypt.rs` | `SCRYPT_PARAMS` item, `ASN1_STRING_set` salt copy/grow, 16-byte stack IV, `EVP_PBE_scrypt` probe | Repaired the same unvalidated-IV-length overflow. Salt handling (copy, in-place draw, negative-length strlen semantics) matches the authority. |
| `src/asn1/p8_pkey.rs` | `PKCS8_PRIV_KEY_INFO` item, `pkey_cb` FREE_PRE/D2I_POST, `PKCS8_pkey_set0`/`_get0`, attributes | Repaired a private-key block leak: FREE_PRE cleansed the `ASN1_STRING` object itself, zeroing the `data`/`length` that `ASN1_STRING_free` reads next, so every PKCS#8 free leaked the octets. Only the contents are cleansed now (`length` clamped at zero), matching `p8_pkey.c:27`; a regression test pins that the owner stays releasable. |

**Defects repaired.** One resource/compatibility leak and two latent
memory-safety defects: `p8_pkey.rs:202` zeroed the octet string object in
`ASN1_OP_FREE_PRE`, leaking `pkey->data` on every `PKCS8_PRIV_KEY_INFO_free`
(medium, no UB) and on the `i2d_evp` temporary path; `p5_pbev2.rs:489` and
`p5_scrypt.rs:444` filled a 16-byte stack IV with an unbounded
`EVP_CIPHER_get_iv_length`, reachable from a caller-registered cipher (medium,
latent UB reproduced from the authority and now refused); `p5_pbe.rs:267`
released the salt block at the authority's `goto` line instead of its
`OPENSSL_free` line (low, allocator-seam compatibility). No invalid free,
double free, alias, uninitialised read or new hidden obligation was found.

**Secret-bearing buffers.** `PKCS8_PRIV_KEY_INFO.pkey->data` is
`SECRET_DATA`/`CLEANSING_REQUIRED`: its contents are cleansed in
`ASN1_OP_FREE_PRE` on every item-free path (`PKCS8_PRIV_KEY_INFO_free`, d2i
failure cleanup, the `ossl_evp_pkey2pkcs8` temporary) and then released plainly
by `ASN1_STRING_free`, matching the authority. A negative `penclen` (accepted by
the authority's `PKCS8_pkey_set0`) clamps the cleanse at zero rather than
reproducing the authority's implicit `size_t` overrun. PBE/PBKDF2/scrypt salts
and IVs are `PUBLIC_DATA`: they are neither cleansed nor clear-freed, and the
Drop/ownership-transfer release arms are unchanged.

**New unsafe assumptions (hidden must be 0).** None. No unsafe function, FFI
symbol, allocator coordinate (other than the corrected release line),
`#[repr(C)]` layout or exported signature was added. The invalid assumption that
`ASN1_OP_FREE_PRE` may destroy the member owner's metadata was removed rather
than relocated. Contracts reused: RC-1 descriptor layout, OB-1 release-seam
discipline for `SaltBuf`, OB-1/OB-4 `ASN1_STRING_set0` transfer, the ASN.1 item
lifecycle and `D2I_POST` version contract, the `EVP_MAX_IV_LENGTH` stack-buffer
contract, `X509_ALGOR_set0` adoption, and `ASN1_STRING_set`'s negative-length
semantics.

**Evidence.** FAST: `cargo fmt --all -- --check` clean; focused
`asn1::p8_pkey` **4 passed / 0 failed** (including the new FREE_PRE regression)
and `asn1::` **40 passed / 0 failed / 1 ignored**. BATCH: clippy
`--all-targets -D warnings` PASS; library **1649 passed / 0 failed / 27
ignored** serially (101.12 s) and with `--test-threads=4` (104.39 s). No test
removed or newly ignored.

**NOT_RUN.** The FRF runtime courts for this surface (`rt-evp-pbe`,
`rt-asn1`, `rt-asn1-template`) were not run: the FRF tooling container is not up
and the candidate probe artifacts predate this build, so they cannot observe
this change. The allocator-hook canary for the repaired PKCS#8 release event,
Miri (Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay,
the caller/dependency closure (BOUNDARY), independent adversarial review and
SEAL are `NOT_RUN`. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`; the two IV bounds are deliberate §17 divergences and the
leak repair is evidenced by a unit assertion rather than an allocator trace.

**Retained obligations (non-UB).** `p5_scrypt` keeps the authority's
negative-`saltlen` strlen semantics (a negative length with a non-NULL salt
requires a NUL-terminated string); `PKCS8_pkey_set0` still accepts a negative
`penclen`; `p8_pkey` cleanses only the private-key octets, not attribute values;
salts/IVs remain un-cleansed public data; error tails still omit the
pointer-bearing `ERR_print_errors` lines.

**Queue.** `REMAINING-AUDIT.txt` 414 → **406**; `AUDITED-FILES.txt` 349 → **357**.

**Next eight (stable order).** `src/asn1/t_pkey.rs`, `src/asn1/t_spki.rs`,
`src/asn1/typ.rs`, `src/asn1/x_bignum.rs`, `src/asn1/x_info.rs`,
`src/asn1/x_int64.rs`, `src/asn1/x_long.rs`, `src/asn1/x_pkey.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M39.json`](atlas-refresh/mechanism-sweep-M39.json).

## 44. Mechanism sweep M40 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `49933eef4` plus the two
contract-statement repairs below; contracts checked against OpenSSL 3.6.4
(`crypto/asn1/{t_pkey,t_spki,tasn_typ,x_bignum,x_info,x_int64,x_long,x_pkey}.c`).

**Scope:** the eight files M39 named as next. The audit covered the two number
printers, the SPKI printer, the generated `d2i_*`/`i2d_*` wrapper layer and the
`ASN1_NULL` sentinel, the `BIGNUM`/`CBIGNUM` primitive hooks, the `LONG`/`ZLONG`
slot-resident primitives, the eight fixed-width integer primitives, and the
`X509_INFO`/`X509_PKEY` lifecycles.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/asn1/t_pkey.rs` | `ASN1_buf_print`/`ASN1_bn_print`, `BIO_indent`/`BIO_printf`/`BIO_write`, `BN_is_negative`/`BN_is_zero`/`BN_bn2bin`, `OwnedBuf::new_cleansed` scratch | No defect. The wide-number buffer is `nbytes + 1` with a leading zero for the sign pad; `BN_bn2bin` writes exactly `nbytes` at `+1`, and the `buf[1] & 0x80` decision is the authority's. The scratch owner is the single `OPENSSL_clear_free` on both exits. Formats, signs, widths and failure tails match `t_pkey.c`. |
| `src/asn1/t_spki.rs` | `NETSCAPE_SPKI_print`, `X509_PUBKEY_get0_param`/`X509_PUBKEY_get`, `EVP_PKEY_print_public`/`EVP_PKEY_free`, `OBJ_obj2nid`/`OBJ_nid2ln`, challenge and signature printers | Repaired the `# Safety` contract: it named only `spkac`, while the body also reads the mandatory template fields `spkac->pubkey`, `spkac->challenge`, `sig_algor.algorithm` and `signature`. No behaviour change; the item templates make all five present on a valid value. |
| `src/asn1/typ.rs` | generated `d2i_*`/`i2d_*` wrappers for the string/multistring types, `ASN1_SEQUENCE_ANY`/`ASN1_SET_ANY`, `ASN1_NULL_new`/`_free`/`d2i`/`i2d` | No defect. Every wrapper is the authority's one-line forward; a null value slot is handled by the shared decoder, `pp` remains the caller's obligation, and the `ASN1_NULL` sentinel `(ASN1_VALUE *)1` is returned and never dereferenced, exactly as `tasn_typ.c`. |
| `src/asn1/x_bignum.rs` | `BIGNUM`/`CBIGNUM` primitive hook table, `bn_new`/`bn_secure_new`, `bn_free`, `bn_i2c`/`bn_c2i`, `bn_secure_c2i`, `bn_print` | No defect. `bn_free` reads `BN_SENSITIVE` from the item and takes `BN_clear_free`; a failed decode frees the value this call allocated and nulls the slot, matching `x_bignum.c`. The pad decision and magnitude write match. |
| `src/asn1/x_info.rs` | `X509_INFO` layout/offsets, `CtxDestroy` member body, `OwnedCtx::zalloc`/`from_raw`, `CRYPTO_free(enc_data)` | No defect. `_new` is the authority's zero-allocation; `_free` releases certificate, CRL, private key and `enc_data`, then the record, each once. The zeroed state is the authority's own constructed state, so the OB-3 zero-state sweep is sound. |
| `src/asn1/x_int64.rs` | eight fixed-width items and their `size`-as-flags hooks, `OwnedBlock` zalloc/from_raw, `ossl_c2i_uint64_int`/`ossl_i2c_uint64_int`, signed/zero-default rules | Repaired the `uint32_free` `SAFETY` contract: a decoded `UINT32` is allocated by `uint64_new` (eight bytes, the authority's own `uint32_c2i`), not by the four-byte `uint32_new`. `OwnedBlock`'s `Drop` releases the allocation's base pointer, so the wider block is released whole; the statement now says so instead of claiming a four-byte extent. No behaviour change. |
| `src/asn1/x_long.rs` | `LONG`/`ZLONG` slot-resident hooks, `long_new`/`long_free`, `long_i2c`/`long_c2i`, `long_print`, sentinel size | No defect. Reads and writes target the value slot itself (`read_unaligned`/`write_unaligned`), the negative encode is the authority's `0 - utmp - 1`, the padding/sign tests match, and the errors are the authority's coordinates. |
| `src/asn1/x_pkey.rs` | `X509_PKEY` layout/offsets, `RawCtx` publication window, `X509_ALGOR_new`/`ASN1_OCTET_STRING_new`, `CtxDestroy` member body, `OwnedCtx::from_raw`, `key_free` gate | No defect. The raw window releases only the block if initialisation is refused, the two members are written before `assume_init`, and the failure path drops the partially built value (members then block) and raises `X509_PKEY_28`. Member release order and the `key_free` test match `x_pkey.c`. |

**Defects repaired.** Two low-severity unsafe-contract statements, both
documentation-only and with no behaviour change: `x_int64.rs:242` claimed
`uint32_free` always reclaimed a four-byte block although the decode path
installs an eight-byte block through `uint64_new` (the release is
base-pointer-only, so no UB, but the stated extent was false); `t_spki.rs:32`
understated the printer's preconditions, omitting the mandatory template fields
it dereferences. No invalid free, double free, leak, alias, uninitialised read,
ABI change or allocator-seam change was found.

**New unsafe assumptions (hidden must be 0).** None. No unsafe function, FFI
symbol, allocator coordinate, `#[repr(C)]` layout or exported signature was
added or changed. Contracts reused: RC-1 item descriptor/template layout, OB-1
`OwnedBlock` allocation/release seam, OB-3 `OwnedCtx`/`CtxDestroy` (including
its zero-state obligation), the ASN.1 item lifecycle and primitive-hook
contract, `d2i`/`i2d` `a`/`pp`/`out` conventions, and the `CBIGNUM`
`BN_SENSITIVE` clear-free rule.

**Evidence.** FAST: `cargo fmt --all -- --check` clean; focused `asn1::` **40
passed / 0 failed / 1 ignored**. BATCH: clippy `--all-targets -D warnings` PASS;
library **1649 passed / 0 failed / 27 ignored** serially (254.34 s) and with
`--test-threads=4` (88.20 s). No test removed or newly ignored.

**NOT_RUN.** No runtime probe is affected: both repairs are contract statements
with no generated code change, so the FRF ASN.1 courts (`rt-asn1`,
`rt-asn1-str`, `rt-asn1-template`), the `rt-mem-*` allocator-hook courts, Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay, the
caller/dependency closure (BOUNDARY), independent adversarial review and SEAL
are `NOT_RUN`; the FRF tooling container is not up. Nothing is promoted to
`SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** `ASN1_bn_print` keeps the authority's
`number`-as-`%s` form: a null `number` is not part of the stated contract even
though the authority would hand it to `printf`. `t_spki` still dereferences the
item-mandatory fields exactly as the authority does. The allocator `file`/`line`
coordinates remain `0` (`OPENSSL_NO_CRYPTO_MDEBUG` convention), and error tails
still omit the pointer-bearing `ERR_print_errors` lines.

**Queue.** `REMAINING-AUDIT.txt` 406 → **398**; `AUDITED-FILES.txt` 357 → **365**.

**Next eight (stable order).** `src/asn1/x_sig.rs`, `src/asn1/x_spki.rs`,
`src/asn1/x_val.rs`, `src/async/arch/async_posix.rs`, `src/async/async.rs`,
`src/async/async_wait.rs`, `src/blowfish.rs`, `src/bn/bn_srp.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M40.json`](atlas-refresh/mechanism-sweep-M40.json).

## 45. Mechanism sweep M41 — 2026-10-19

**Source identity:** `integrate/safe-c33` at `f326c049f` plus the two
contract-statement repairs below; contracts checked against OpenSSL master
(`crypto/async/arch/async_posix.c`, `crypto/bf/*`, `crypto/bn/{bn_srp,bn_dh,bn_exp}.c`,
`crypto/asn1/x_{sig,spki,val}.c`).

**Scope:** the eight files M40 named as next. `src/async/async.rs` and
`src/async/async_wait.rs` are retained callback/fibre boundaries (the M22/M24
exclusion); they are recorded `NOT_RUN` and were replaced by the next two
ordinary files in the queue, `src/bn/dh.rs` and `src/bn/exp.rs`.

| File | Mechanisms exercised | Disposition |
|---|---|---|
| `src/asn1/x_sig.rs` | `X509_SIG` `#[repr(C)]` layout and offset/size assertions, `X509_SIG_it`, `IMPLEMENT_ASN1_FUNCTIONS` quartet, `X509_SIG_get0`/`getm` borrowed out-parameters | No defect. Both out-parameters are independently NULL-checked and the answers are borrowed, matching `x_sig.c`. The item layer is the established shared codec. |
| `src/asn1/x_spki.rs` | `NETSCAPE_SPKAC`/`NETSCAPE_SPKI` layouts (16/32 bytes), `ASN1_TFLG_EMBED` on the in-struct `X509_ALGOR` at offset 8, item lifecycle, generated `d2i_*`/`i2d_*` | No defect. The embedded field's own address is handed to the item machinery, so free releases the algorithm's members and never the enclosing block; the embedded offset and the 32-byte stride are asserted. |
| `src/asn1/x_val.rs` | `X509_VAL` layout, two `ASN1_TIME` templates, item lifecycle | No defect. Two mandatory pointer fields, one owner per item; no `_dup` is exported, matching `x_val.c`. |
| `src/async/arch/async_posix.rs` | `ucontext_t` C shim, `AtomicPtr` allocator slots and provenance-preserving recovery, `allow_customize` latch under `async_mem_lock`, caller stack alloc/free callbacks, `OwnedFibre` storage | No defect. Callbacks run with the lock released (reentrancy-safe), the latch and the unlock-before-store ordering match the authority exactly, and storage release is one `CRYPTO_free` at the authority's coordinate. Repaired a missing divergence record. |
| `src/blowfish.rs` | `n2l`/`l2n`/`n2ln`/`l2nn` byte extents, `BF_set_key` cyclic key XOR and self-encrypting schedule, ECB/CBC/CFB64/OFB64 loops | No defect. Every pointer walk is bounded by the caller's stated extent and the `length`/`num` arithmetic matches the authority. Repaired the CBC precondition statement. |
| `src/bn/bn_srp.rs` | limb-array transcription, `new_static_data` + `AtomicPtr` cache/CAS, `BN_FLG_STATIC_DATA` borrow semantics, ten accessors | No defect. A CAS loser releases its unpublished `Box` once; the cached object is process-lifetime and `BN_free` honours the static flag. Widths come from the declared array lengths. |
| `src/bn/dh.rs` | thirty-two `static_data_bignum` accessors, per-symbol function-local caches, width/flag/prime tests | No defect. Same static-`BIGNUM` idiom; every accessor returns the shared process-lifetime object and the table assertions cover all thirty-two widths and flags. |
| `src/bn/exp.rs` | the one internal `bn_mod_exp_mont_fixed_top`, null-or-live pointer contract, even-modulus refusal site | No defect. The substitution delegates to `BN_mod_exp_mont_consttime` with the same refusal and error coordinate; no new unsafe operation. |

**Defects repaired.** Two low-severity unsafe-contract statements, both
documentation-only with no behaviour change: `blowfish.rs:309` now states the
authority's multiple-of-8 precondition for `BF_cbc_encrypt` (the final whole-block
arm otherwise over-reads on decryption for a non-multiple length);
`async_posix.rs:101` records that `async_stack_alloc` zero-fills through
`CRYPTO_zalloc` where the authority uses `OPENSSL_malloc`, with the hook, request
size and `(FILE, LINE)` coordinate unchanged. No invalid free, double free, leak,
alias, uninitialised read, ABI change or allocator-seam change was found.

**New unsafe assumptions (hidden must be 0).** None. No unsafe function, FFI
symbol, allocator coordinate, `#[repr(C)]` layout or exported signature was
added or changed. Contracts reused: the ASN.1 item lifecycle/template/`EMBED`
contract, the generated `d2i`/`i2d` `a`/`pp`/`out` conventions, OB-1/OB-2
allocation seams, the static-`BIGNUM` cache idiom and `BN_FLG_STATIC_DATA`
borrow rule, and the B-series callback contract for the caller-supplied stack
allocator/free pair (invoked without the latch lock held).

**Evidence.** FAST: `cargo fmt --all -- --check` clean; focused `asn1::x_` 6
passed / 0 failed (the three wrapper files carry no tests of their own),
`blowfish` 2/0, `bn::dh` 7/0, `bn::exp` 2/0,
`crypto_async::arch::async_posix` 2/0; `bn::bn_srp` has no unit tests and is
covered through `srp_lib` and the full suite. BATCH: clippy
`--all-targets -D warnings` PASS; library **1649 passed / 0 failed / 27
ignored** serially (263.79 s) and with `--test-threads=4` (81.70 s). No test
removed or newly ignored.

**NOT_RUN.** `src/async/async.rs` and `src/async/async_wait.rs` are retained
callback/fibre boundaries and require a BOUNDARY-level audit; Miri
(Stacked/Tree Borrows), ASan/TSan/Loom, authority differential replay, the
caller/dependency closure, independent adversarial review and SEAL are also
`NOT_RUN`. No audited file carries an `OPENSSL_RS_ADV_PROBE` arm, so no probe
was affected. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Retained obligations (non-UB).** `BF_cbc_encrypt` keeps the authority's
partial-block arms; callers must supply the authority's multiple-of-8 length.
The SRP/DH constants remain process-lifetime leaks by construction (the cost of
`.rodata` in C), and the allocator `file`/`line` coordinates remain `0`
(`OPENSSL_NO_CRYPTO_MDEBUG` convention).

**Queue.** `REMAINING-AUDIT.txt` 398 → **390**; `AUDITED-FILES.txt` 365 → **373**.
The two `NOT_RUN` boundary files stay queued.

**Next eight (stable order).** `src/async/async.rs`, `src/async/async_wait.rs`
(both `NOT_RUN` carriers; substitute the next ordinary files), `src/bn/intern.rs`,
`src/bn/kron.rs`, `src/bn/nist.rs`, `src/bn/rsa_fips186_4.rs`, `src/camellia.rs`,
`src/cast.rs`.

**Machine-readable receipt:**
[`atlas-refresh/mechanism-sweep-M41.json`](atlas-refresh/mechanism-sweep-M41.json).

## 28. Boundary sweep B18 — async job/fibre lifecycle and the wait-context callback edge

Receipt: [`atlas-refresh/boundary-sweep-B18.json`](atlas-refresh/boundary-sweep-B18.json).
Candidate `7fc72ede5`; two files, one repair.

**STOP status: CLEAR after repair.** One confirmed memory-safety defect was stopped on and
repaired: `B18-D1` (heap-use-after-free in `AsyncWaitCtx::destroy_body` when a cleanup
callback removes another fd entry). Pre-fix ASan observed the predicted READ of size 4;
post-fix the same control and the full suite are clean. Hidden obligations 0; no safe Rust
caller can cause UB through the audited interfaces under the stated contracts.

| file | boundaries | disposition | defects / residuals |
|---|---|---|---|
| `src/async/async.rs` | `B18-ASY-1..5` (context, job/fibre/stack, pool, start/resume+err state machine, pause/block and thread-stop edge) | `CONTRACTED` | No defect. `B18-R1` records the authority's no-outstanding-job precondition for `ASYNC_cleanup_thread` (violation is a UAF in both implementations); `B18-R3` the authority-parity leaks; `B18-R4` the fail-closed NULL `func`/`wctx` arms; `B18-R6` hooks under the B15 register lock. |
| `src/async/async_wait.rs` | `B18-WAIT-1..3` (context/node ownership, fd-list surgery, callback/status and cleanup reentrancy) | `CONTRACTED` after repair | **B18-D1 (fixed, high):** `destroy_body` captured `curr->next` before the application cleanup callback; a callback calling `ASYNC_WAIT_CTX_clear_fd` for that next, still-added entry released it, and the loop continued through freed memory. The next link is now read after the callback, as the authority does. `B18-R2` retains the callback's self-removal/context-free prohibition. |

**Sweep.** Every constructor and failure arm was checked against the authority: context and
pool blocks are crate-allocator owned and published only after full initialisation; job
`funcargs` is a copied block with a single release; the fibre storage and stack are
released separately only where the Rust layout split requires it. The `ASYNC_start_job`
state machine and its `err` path release the job into the pool exactly on the authority's
arms, restoring the default libctx before release. No lock is held across the job function
or the thread-stop handler, and no Rust borrow spans a callback. The one reentrancy defect
was in the wait-context free walk.

**Evidence.** FAST: fmt clean; clippy `--all-targets -D warnings` PASS; focused
`crypto_async` 7/0 (1671 filtered). ASan (dedicated venue, `-Zsanitizer=address
-Zbuild-std`, nightly-2026-10-05): post-fix control passes; the pre-fix candidate reported
heap-use-after-free at `async_wait.rs:101`, freed through `ASYNC_WAIT_CTX_clear_fd`. BATCH:
library **1651 passed / 0 failed / 27 ignored** serially (233.04 s) and with
`--test-threads=4` (98.86 s); two tests added, none removed or newly ignored. Neither file
carries an `OPENSSL_RS_ADV_PROBE` arm.

**NOT_RUN.** Miri (Stacked/Tree Borrows; no miri component in the court toolchain),
Loom/TSan (per-thread state, no shared-memory change), authority differentials,
independent review and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or
`SAFE_COMPATIBLE`.

**Next ordinary position:** `src/bn/intern.rs`, then `src/bn/kron.rs`, `src/bn/nist.rs`,
`src/bn/rsa_fips186_4.rs`, `src/camellia.rs`, `src/cast.rs`. `src/async/async.rs` and
`src/async/async_wait.rs` were the two queued `NOT_RUN` boundary carriers and leave the
boundary queue; this sweep does not consume an ordinary queue position.

## 46. Mechanism sweep M42 — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M42.json`](atlas-refresh/mechanism-sweep-M42.json).
Candidate `a5a807ccb` plus this batch's source edits.

**STOP status: CLEAR after repair.** Three confirmed defects were stopped on and
repaired: `M42-D1` (aliasing UB in `bn_set_all_zero`), `M42-D2` (`CAST_set_key`
OOB read on a negative signed length), and `M42-D3` (`CAST_cbc_encrypt` OOB
read/write on a negative length). Three contract statements were made precise; no
behaviour other than the repaired bounds changed. Hidden obligations 0 for the
audited interfaces under their stated contracts.

| file | mechanisms | disposition | defects / residuals |
|---|---|---|---|
| `src/bn/intern.rs` | `bn_compute_wNAF`, `bn_get_dmax`/`bn_get_top`, `bn_set_all_zero`, `bn_copy_words`/`bn_get_words`/`bn_set_words` word bridges | `CONTRACTED` after repair | **M42-D1 (fixed, medium):** `bn_set_all_zero` called `bn_get_dmax(a)` while holding `as_mut(a)`, so a shared and a unique reference to the same `BIGNUM` were live together and the subsequent padding write used the invalidated unique borrow. `dmax` is now derived from `b` (they coincide in this representation). **Contract (low):** `bn_get_words` now forbids stores through its shared-derived pointer. |
| `src/bn/kron.rs` | `BN_kronecker` value/sign algorithm, `trailing_zeros`, `BN_CTX`-free temporaries | `CONTRACTED` | No defect. `parts()` copies both magnitudes, so no raw borrow escapes; every refusal is the authority's `-2`; `guard_ffi` wraps the export. |
| `src/bn/nist.rs` | five `BN_nist_mod_*` dispatchers, `BN_nist_mod_func` value-selection, static prime accessors | `CONTRACTED` | No defect. `BN_nist_mod_func` reads a copied magnitude and compares against the static getters; a NULL `p` selects nothing rather than dereferencing. |
| `src/bn/rsa_fips186_4.rs` | `ossl_bn_inv_sqrt_2` cache, auxiliary-prime search, `gen_prob_primes` pool/cleanup, `derive_prime` CRT+MR loop | `CONTRACTED` | No memory-safety defect. The cached constant is published once with a losing-thread release; every pool slot is checked before use; cleanup clears exactly the internally drawn slots and ends the `BN_CTX` frame. Residual `M42-R1` records the shared `BN_clear` cleansing gap (below). |
| `src/camellia.rs` | `CamelliaKey` layout, `get_u32`/`put_u32`, `Ekeygen`, `Feistel`/FL rounds, five mode entry points | `CONTRACTED` | No memory-safety defect. `Camellia_set_key` validates both pointers and all three key sizes. **Contract (low):** every mode entry now states the schedule must come from `Camellia_set_key` (`grand_rounds` 3 or 4); a zeroed key is a valid value but would index outside `rd_key`. |
| `src/cast.rs` | `CastKey` layout, `CAST_set_key` schedule, `E_CAST` rounds, ECB/CBC/CFB/OFB modes | `CONTRACTED` after repair | **M42-D2 (fixed, high):** a negative `len` was cast to `usize`, turning the authority's empty signed loop into a multi-gigabyte read of `data`. **M42-D3 (fixed, high):** for a negative CBC `length`, `l + 8` was cast to `c_uint` and passed to `n2ln`/`l2nn`, reading or writing far outside the caller's buffer; the partial arm now selects only a true 1..7-byte remainder. |
| `src/chacha.rs` | `CHACHA_U8TOU32`, `chacha20_core`, `ChaCha20_ctr32` counter/XOR loop | `CONTRACTED` | No defect. The key/counter reads are bounded by the contract; the in-place XOR preserves `out == inp`; the counter advance and zero-length no-op match the authority. |
| `src/cmp/cmp_http.rs` | `raise_cmp`, `keep_alive`, debug/log path, header stack, `OSSL_CMP_MSG_http_perform` transfer and decode | `CONTRACTED` | No memory-safety defect. `headers` is released on every early return; `req_mem`/`rsp` have single releases; a NULL `rsp` is handled by the item layer. **Contract (low):** the `req->body` non-NULL precondition the authority relies on is now stated. |

**Sweep.** Every raw access is bounded by a stated precondition or derived from an owner:
`bn_compute_wNAF`'s buffer is an `OwnedBuf` released on each refusal arm; the
word bridges are caller-sized; Kron/NIST copy their inputs; the RSA generator's pool
slots are checked and cleared exactly on the internally drawn arms; Camellia and CAST
render their `#[repr(C)]` layouts with compile-time offsets; ChaCha's loop is bounded
by `len`; and the CMP path's two BIOs and header stack each have one release.

**Evidence.** FAST: `cargo fmt --all -- --check` clean; clippy `--all-targets -D
warnings` PASS; focused tests `bn::intern` 7, `bn::rsa_fips186_4` 5, `camellia` 4, `cast`
5 (including two new negative-length controls), `chacha` 14 — all 0 failed. BATCH:
library **1653 passed / 0 failed / 27 ignored** serially (62.32 s) and with
`--test-threads=4` (84.88 s); two tests added, none removed or newly ignored. None of
the eight files carries an `OPENSSL_RS_ADV_PROBE` arm.

**Retained obligation (non-UB, shared mechanism).** `M42-R1`: `BN_clear`
(`src/bn/bignum.rs`) clears the `Vec` length without cleansing the limb storage,
while the authority `OPENSSL_cleanse`s `d[0..dmax]`. This is reachable from
`rsa_fips186_4`'s auxiliary-prime cleanup and from `BN_CTX_get`'s slot reset. It is a
secret-residue divergence, not a Rust soundness defect, and repairing the shared owner
invalidates the BIGNUM-dependent evidence closure, so it is deferred to a dedicated
BIGNUM shared-mechanism sweep rather than edited inside this batch.

**NOT_RUN.** Miri (no miri component in the court toolchain), targeted ASan control for
M42-D2/D3 (new plain tests are the FAST controls; sanitizer confirmation is a BOUNDARY
gate), Loom/TSan (no shared-memory change), authority differentials, independent review
and SEAL. Nothing is promoted to `SAFETY_DISCHARGED` or `SAFE_COMPATIBLE`.

**Queue.** `REMAINING-AUDIT.txt` 390 → **380**; `AUDITED-FILES.txt` 373 → **383**.
The ten moved entries are the eight audited files plus the two B18-audited async files
(`src/async/async.rs`, `src/async/async_wait.rs`) that B18 left in the queue for
bookkeeping.

**Next eight (stable order).** `src/cms/cms_att.rs`, `src/cms/cms_dd.rs`,
`src/cms/cms_io.rs`, `src/cms/cms_kem.rs`, `src/context/core_bio.rs`,
`src/context/dispatch.rs`, `src/context/mod.rs`, `src/context/thread_data.rs`.

## 47. Boundary sweep B19 — shared BIGNUM cleansing — 2026-10-19

Receipt: [`atlas-refresh/boundary-sweep-B19.json`](atlas-refresh/boundary-sweep-B19.json).
Candidate `1efef274c`; only `src/bn/bignum.rs` changed (`7eda5974`).

**M42-R1 closed.** `BN_clear` discarded the `Vec` length without cleansing the limb
storage. `cleanse_storage` now zeroes the whole allocation (`capacity()` limbs, the
analogue of the authority's `dmax`) with volatile writes and a compiler fence before
the length is cleared. `BN_clear_free` was widened from `len()` to `capacity()` for
the same reason. `BN_clear` now also clears `BN_FLG_FIXED_TOP` (`bn_lib.c:400`),
`BN_secure_new` carries `BN_FLG_SECURE`, and `BN_free` cleanses when that bit is set
(`bn_free_d`'s secure arm). `BN_copy`, `BN_with_flags` and `BN_set_word` reuse the
destination allocation instead of freeing a previously secret block un-cleansed.

| boundary | file | disposition |
|---|---|---|
| `B19-BN-1..4` (clear, clear-free, secure flag/free, allocation reuse) | `src/bn/bignum.rs` | `CONTRACTED` |

**Callers.** 38 `BN_clear` and 150 `BN_clear_free` sites across 34 files (RSA private
factors/CRT, DSA/ECDSA nonces, ECDH x-coordinate, DH private exponent, SRP
verifier/secret, `BN_CTX` pool reset, prime candidates, CBIGNUM). Every caller treats
these operations as a secret wipe; none relied on the old non-cleansing behaviour.
The only new observable value is `BN_get_flags(BN_secure_new(...), BN_FLG_SECURE)`,
which is the authority's value and makes `src/params/build.rs:814`'s secure arm match
`param_build.c`.

**Controls observed.** New positive test wipes eight sentinel limbs and reads every
limb up to `capacity()`; the negative control performs the old `Vec::clear`-only reset
and confirms the sentinel is still visible, so the inspection is not vacuous; a third
test checks the secure flag. FAST fmt/clippy clean; focused `bn::bignum` 8/8. BATCH
full library **1656 passed / 0 failed / 27 ignored** serially (273.86 s) and with
`--test-threads=4` (102.83 s); three tests added, none removed or newly ignored. ASan
venue (nightly-2026-10-05): `bn::bignum` 8/8 and `bn::` 90/90 excluding the
allocator-coordinate hook probe, which is ASan-incompatible for a FILE-pointer
identity reason unrelated to cleansing. Miri NOT_RUN (no component in the court
toolchain).

**Invalidated evidence.** M42-R1 is closed; re-adjudicate `M8` `src/bn/bignum.rs`,
`M32` `src/bn/ctx.rs`, `M42` `src/bn/rsa_fips186_4.rs`, `M37` `src/params/build.rs`
and the cleansing claims of the 34 caller files at the next BATCH/BOUNDARY gate. OB-1
and OB-4 evidence is **not** invalidated: limbs are `Vec<Limb>`, not `OwnedBuf`,
`OwnedBlock` or a member-buffer slot.

**Residual (disclosed, not hidden).** `B19-R1`: arithmetic `store()` assignments and
`parts()`/operation temporaries are still ordinary `Vec` allocations released by
`Drop` without cleansing. This is a secret-lifetime gap, not UB, and it is why the
mechanism is `CONTRACTED`, not `SAFETY_DISCHARGED`, alongside the unmodelled secure
heap (`OBL-BN-ALLOCATOR`) and the NOT_RUN authority differential/SEAL gates.

**Queue.** Unchanged (`REMAINING-AUDIT.txt` 380, `AUDITED-FILES.txt` 383): this sweep
audits an owner already counted. **Next ordinary position:** `src/cms/cms_att.rs`.

## 48. Mechanism sweep M43 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M43.json`](atlas-refresh/mechanism-sweep-M43.json).
Candidate `21e0ed4a9` plus the teardown repairs below in `src/context/mod.rs`.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/cms/cms_att.rs` | audited_no_change | 22 exported attribute wrappers, `cms_attrib_get`/`cms_check_attribute`, the seven-entry property table. The rule logic is line-for-line `cms_att.c:213-273`; no ownership is transferred, so no OB contract applies. |
| `src/cms/cms_dd.rs` | audited_no_change | `DigestedData` create/init/final. `EVP_MD_CTX_new`/`free` pair is single-owner; verify compares with `mdlen` validated against the decoded length (authority `memcmp`). No change. |
| `src/cms/cms_io.rs` | audited_no_change | `CMS_stream`, the d2i/i2d/PEM BIO codec, streaming wrappers and S/MIME delegates. The two `d2i_of_void`/`i2d_of_void` casts restate the typed callers; the extern delegates `SMIME_{write,read}_ASN1_ex` bind to the landed `asn1::asn_mime` exports. |
| `src/cms/cms_kem.rs` | audited_no_change | `kem_cms_{decrypt,encrypt}`: every acquisition (`EVP_CIPHER_fetch`, `ASN1_TYPE_new`, `d2i_X509_ALGOR`) has one release on every arm; `EVP_CIPHER_CTX_get_type` is the authority's own macro, so the expanded `EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(..))` is exact. |
| `src/context/core_bio.rs` | audited_no_change | OB-3 `BioCoreGlobals` (`CtxDestroy`, empty member body, `CRYPTO_zalloc` seam at `bss_core.c:32`/`:27`), seven method forwards. The NULL-`BIO_free`/`BIO_up_ref` guards are the already-recorded safety divergences; no new assumption. |
| `src/context/dispatch.rs` | audited_no_change | `OsslDispatch` `#[repr(C)]`, `Sync` justified by static tables, `entry_function` size-checked `transmute_copy`, NULL-table `lookup` divergence already recorded. |
| `src/context/mod.rs` | repaired_defects | `OsslLibCtx` OB-3 owner, `context_init` slot construction, `context_deinit_objs` ordering, default-context `RUN_ONCE` chain, index registry. Three defects repaired (below). |
| `src/context/thread_data.rs` | audited_no_change | OB-3 `OsslLibCtxThreads`, max/active counters under the slot mutex, pool start/join/clean. Wrapping subtraction and join-before-signal match `crypto/thread/internal.c`. |

**Defects repaired (all `src/context/mod.rs`).**

1. `context_deinit_objs:745` — `decoder_cache` was released before `decoder_store`; the authority releases the store first (`context.c:251-260`). Reordered to the authority. Severity **LOW** (teardown side-effect order, no reachable UB).
2. `context_deinit_objs:921` — the slot-18 child-provider globals were freed before the provider store, inverting the authority's P1 rule (`provider_store` before child data, `context.c:274`). `provider_deactivate_free` reaches these globals through `OSSL_LIB_CTX_CHILD_PROVIDER_INDEX`, so the early free silently skipped the parent up-ref/free callbacks. The slot was re-NULLed, so this was a behaviour/resource defect, not a UAF. Moved to the authority's low-priority position after the thread slot. Severity **HIGH** (P1 lifecycle invariant).
3. `release_default_drbg_ctx:1542` — cleared slot 5 without freeing it. The function is live via `rand_lib::ossl_rand_cleanup_int`, and Phase 9 had already filled the slot, so cleanup leaked the RAND global and its owned DRBGs. Restored the authority's free-then-clear. Severity **MEDIUM** (reachable leak, no UB).

The module-header statement that `ossl_ctx_thread_stop` was not yet called was stale and is corrected.

**Assumptions.** Unsafe assumptions eliminated: 0. Relocated: 0. New: 0. Contracts reused: OB-3
`OwnedCtx`/`RawCtx`/`CtxDestroy`, RC-1 seam coordinates, the `OsslDispatch` id/signature matched pair,
the BIO-method call contract, and the B1/B2/B6-B18 callback reentrancy contracts for the core-BIO
dispatch callbacks. No new FFI symbol, allocator coordinate, `#[repr(C)]` layout or signature.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused `context::` 21/21 and `cms::`
9 passed / 1 ignored. BATCH `cargo clippy --all-targets -- -D warnings` clean; full library
**1656 passed / 0 failed / 27 ignored** with `--test-threads=1` (263.38 s) and with
`--test-threads=4` (108.97 s); the affected cms allocator probe 1/1. A default-parallel
`cargo test --lib` run was flaky in `runtime::secure` (secure-heap init ordering); this is the
known isolation issue, it is outside this batch's files, and both required thread counts pass.

**NOT_RUN.** BOUNDARY independent closure audit of the `OsslLibCtx` destructor body (the body
changed, so its OB-3 evidence needs re-adjudication); Miri (no component in the court toolchain);
ASan; authority differential for teardown side effects (no harness reaches a child-provider
teardown); SEAL. The leak repair has no executable negative control: exercising it frees the
process-global default DRBG and would poison the rest of the suite.

**Queue.** `REMAINING-AUDIT.txt` 380 → **372**; `AUDITED-FILES.txt` 383 → **391**.
**Next eight (stable order).** `src/crmf/crmf_pbm.rs`, `src/ct/ct_b64.rs`, `src/ct/ct_policy.rs`,
`src/ct/ct_prn.rs`, `src/ct/ct_sct_ctx.rs`, `src/ct/ct_sct.rs`, `src/ct/ct_vfy.rs`,
`src/ct/ct_x509v3.rs`.

## 49. Mechanism sweep M44 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M44.json`](atlas-refresh/mechanism-sweep-M44.json).
Candidate `4452e95ac`; audit-only, no source change.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/crmf/crmf_pbm.rs` | audited_no_change | `OSSL_CRMF_{pbmp,pbm}_new`: salt and MAC-result `OwnedBuf`s at the authority coordinates, OWF iteration loop, and `basekey` cleansing before every free arm. `crmf_pbm.c:27-223` line-for-line; the `size_t`→`int`/`long` conversions are the authority's own. |
| `src/ct/ct_b64.rs` | audited_no_change | `ct_base64_decode` allocates `3*(inlen/4)` and hands the block over only after a setter accepts it; `EVP_DecodeBlock` guarantees a multiple-of-four group, so the padding walk cannot underflow. Key DER dropped after `d2i_PUBKEY_ex`; CTLOG failure frees the pkey reference. |
| `src/ct/ct_policy.rs` | audited_no_change | OB-3 `CtPolicyEvalCtx` (`CtxDestroy`, zero-state sweep), `propq` duplicate released by `OwnedBlock::take`, and the authority's gettimeofday/seconds/add/time2ms arithmetic. setters keep `X509_up_ref`-then-store. |
| `src/ct/ct_prn.rs` | audited_no_change | `timestamp_print` has one `ASN1_GENERALIZEDTIME_free` on every non-NULL arm and a bounded 20-byte `BIO_snprintf`; `SCT_print`/`SCT_LIST_print` field and stack arithmetic match `ct_prn.c:132-240`. |
| `src/ct/ct_sct_ctx.rs` | audited_no_change | OB-3 `SctCtx`, `OwnedStr` propq, `certder`/`preder` owner hand-off with the authority's err order, `pretmp` single free, and the key-hash allocator path. The authority's reused-`*hash` error-path free (`ct_public_key_hash`, site `:469`) is reproduced as documented (`:383-388`) and remains an unreachable, retained compatibility obligation. |
| `src/ct/ct_sct.rs` | audited_no_change | OB-3 `Sct`, `SCT_LIST_free` pop-free thunk, set0/set1 incumbent release and re-duplication, the completeness predicates, and `SCT_validate`'s single-context/two-wrapper lifetime with cleanup on every exit. Matches `ct_sct.c:22-385`. |
| `src/ct/ct_vfy.rs` | audited_no_change | `sct_ctx_update` writes exactly 12 bytes (`1+1+8+2`) and reuses the buffer for `l2n3`/`s2n`; `SCT_CTX_verify` checks completeness, version, log-id length/bytes and time before reading the signature, and frees the `EVP_MD_CTX` on every arm. |
| `src/ct/ct_x509v3.rs` | audited_no_change | Poison hooks, `i2r` adapter, the two `d2i_SCT_LIST` wrappers (one `SCT_LIST_free` on the tag-failure arm, `*a` cleared) and the three-row table. The four const-fn transmutes are the established v3-table ABI-compatible callback casts; no ownership crosses the table. |

**Defects repaired.** None. Every unit matches the pinned `openssl-3.6.4` authority; no source line changed.
The only retained obligation is the pre-existing, documented `ct_sct_ctx::ct_public_key_hash` error arm
(authority `ct_sct_ctx.c:200-242`) that frees a reused `*hash` block when `md` aliases it. It is not
reachable from any in-crate caller (both calls pass `sctx`'s NULL hash slot) and does not become a new
assumption.

**Assumptions.** Unsafe assumptions eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts reused:
OB-1 `OwnedBuf`, OB-2 `OwnedStr`, OB-3 `OwnedCtx`/`RawCtx`/`CtxDestroy` plus zero-state sweeps, OB-4
member-buffer slots, RC-1 seam coordinates, B19 cleansing, and the B1/B2/B6-B18 callback contracts for
the x509v3 table callbacks.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused `ct::` 27 passed / 0 failed /
4 ignored (the substring filter also matched `object::` names; all CT units pass); `crmf::` has no unit
tests. BATCH `cargo clippy --all-targets -- -D warnings` clean; full library **1656 passed / 0 failed /
27 ignored** with `--test-threads=1` (233.36 s) and with `--test-threads=4` (102.99 s). No dedicated
CT/CRMF adversarial probe or court exists; the three zero-state sweeps and the `ct_log` log-id boundary
test are the affected focused evidence and pass.

**NOT_RUN.** BOUNDARY (audit-only; no shared mechanism or trust boundary changed); Miri (no component in
the court toolchain); ASan; authority differential (no semantic change); SEAL.

**Queue.** `REMAINING-AUDIT.txt` 372 → **364**; `AUDITED-FILES.txt` 391 → **399**.
**Next eight (stable order).** `src/der_writer.rs`, `src/dh/asn1.rs`, `src/dh/backend.rs`,
`src/dh/check.rs`, `src/dh/depr.rs`, `src/dh/gen.rs`, `src/dh/group_params.rs`, `src/dh/kdf.rs`.

## 50. Mechanism sweep M45 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M45.json`](atlas-refresh/mechanism-sweep-M45.json).
Candidate `f59229e62`; source change confined to `src/der_writer.rs` (one dead-code control-flow
defect plus its focused test and `#[cfg(test)]`).

| file | disposition | mechanisms / note |
|---|---|---|
| `src/der_writer.rs` | defect_repaired | Nine `ossl_DER_w_*` writers and the `int_start/end_context`/`int_put_bytes_*` helpers. `ossl_DER_w_boolean` tested `WPACKET_close(pkt) == 0` (success is 1) and did not reproduce the authority's second inversion. Both callees are now tested for non-zero success and the divergence from `der_writer.c:60-68` is recorded in the function doc. New focused null-packet test; the test module is now `#[cfg(test)]`. The other eight functions and their tag/`BN_BYTES` constants match the authority, including `int_put_bytes_bn`'s top-limb probe through `bn_get_words`. |
| `src/dh/asn1.rs` | audited_no_change | `DHparams`/`DHvparams`/`DHxparams` templates, `DHparams_it`, `dh_cb` NEW/FREE/D2I_POST, and the X9.42 pair. `p/q/g/j` transfer to `DH_set0_pqg`/`ossl_ffc_params_set0_j`; `vparams` seed/counter are released before the vparams block (`OwnedBlock` at `:125`), and the decoded block is dropped at the authority's `:129` release site. The authority's uninitialised stack `ASN1_BIT_STRING.type` is zero-initialised and documented. |
| `src/dh/backend.rs` | audited_no_change | `params_fromdata/todata`, `key_fromdata/todata`, `is_foreign`, `dup`, `key_from_pkcs8`. The private import is `BN_clear_free`'d on every failure arm; PKCS#8 uses `BN_secure_new` and `ASN1_STRING_clear_free(privkey)` on all exits. `ossl_dh_dup`'s odd `||` domain-parameter guards and `DH_set0_key`'s leave-private-alone rule are the authority's and are codified by the unit tests. |
| `src/dh/check.rs` | audited_no_change | `DH_check_params[_ex]`, `DH_check[_ex]`, `DH_check_pub_key[_ex]`, partial/private/pairwise validators. Flag order, `|=` refinement, `DH_get_nid` fast path, BN_CTX cleanup on every arm and the self-test begin/end pairing match `dh_check.c`. The private key is borrowed for range checks; no local secret copy exists. |
| `src/dh/depr.rs` | audited_no_change | `DH_generate_parameters` matches `dh_depr.c:25-48`: `BN_GENCB` released before the object on the failure path and alone on success. |
| `src/dh/gen.rs` | audited_no_change | `ossl_dh_generate_ffc_parameters`, `ossl_dh_get_named_group_uid_from_size`, `DH_generate_parameters_ex` and `dh_builtin_genparams`. The generator bound is checked after `p`/`g` allocation, the `err:` label raises `ERR_R_BN_LIB` once, and `length`/`dirty_cnt` match `dh_gen.c:39-238`. |
| `src/dh/group_params.rs` | audited_no_change | `dh_param_init`, `ossl_dh_new_by_nid_ex`, `DH_new_by_nid`, `ossl_dh_cache_named_group`, `ossl_dh_is_named_safe_prime_group`, `DH_get_nid`. The cache flushes `params.nid`, installs only a missing `q`, and shares the `BN_FLG_STATIC_DATA` constants; the RFC 5114 uid 1..3 path is reproduced and tested. |
| `src/dh/kdf.rs` | audited_no_change | `ossl_dh_kdf_X9_42_asn1` (five-slot `OSSL_PARAM` array, digest/key/optional ukm/cekalg) and `DH_KDF_X9_42` (text-form OID, `OSSL_MAX_NAME_SIZE`). `Z`/`ukm` are borrowed and handed straight to `EVP_KDF_derive`; no copy or temporary secret exists in this unit, so no local cleansing is owed. Failure leaves `out` as the authority leaves it. |

**Defect repaired.** `src/der_writer.rs` (pre-edit `:131-132`, severity low/correctness, not
memory safety): `ossl_DER_w_boolean` returned failure on every successful close because the
close test was `== 0`; the authority's source inverts both that test and the following tag write
(`der_writer.c:60-68`), and the transcription had corrected only the second. The function has no
caller in the pinned authority or in this crate, so there is no compatibility surface; the
transcription now implements the documented behaviour and the divergence is recorded at the
function. A null-packet test exercises both boolean values.

**Secret-bearing buffers.** `dh_backend::ossl_dh_key_fromdata` clears an imported private key
with `BN_clear_free` on every refusal arm; `ossl_dh_key_from_pkcs8` allocates the private key
with `BN_secure_new`, clears it on conversion failure, and clear-frees the `ASN1_INTEGER` on
every exit. `dh_kdf` copies no secret: `Z` is passed by reference into the X9.42 KDF provider,
whose internal copies are outside this batch. `dh_check` borrows the private key for range and
pairwise checks without duplicating it. `p/q/g/j`, seeds and counters are public parameters.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. `int_put_bytes_uint32`'s
contract now states the alignment its `*const c_void` dereference requires, and
`int_der_w_integer`'s contract references the callback's own validity requirements; no new
precondition was introduced at any safe boundary. Contracts reused: RC-1 allocator seam, the
§1 `OwnedBlock`/`from_raw` block-ownership contract, OB-3-style partial-initialisation release
ordering (vparams members before their block), B19 cleansing discipline, and the existing
BN_CTX/self-test cleanup contracts. `ossl_DER_w_boolean` has no callers, so no dependency
closure was invalidated.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; `der_writer` 2 passed / 0 failed;
`dh::` 56 passed / 0 failed / 2 ignored. BATCH `cargo clippy --all-targets -- -D warnings`
clean; full library **1657 passed / 0 failed / 27 ignored** with `--test-threads=1` (212.39 s)
and with `--test-threads=4` (95.36 s). No der_writer or X9.42 adversarial probe exists; the
unaffected `dh::object::adv_probe` allocator probes remain ignored.

**NOT_RUN.** BOUNDARY (the changed function is private, dead, and holds no shared mechanism or
trust boundary; no safe caller can reach it); Miri (no component in the court toolchain); ASan;
authority differential for `ossl_DER_w_boolean` (no executable harness calls it; the semantic
comparison is source-level); SEAL.

**Queue.** `REMAINING-AUDIT.txt` 364 → **356**; `AUDITED-FILES.txt` 399 → **407**.
**Next eight (stable order).** `src/dh/mod.rs`, `src/dh/prn.rs`, `src/dh/rfc5114.rs`,
`src/digest/blake2.rs`, `src/digest/md4.rs`, `src/digest/md5.rs`, `src/digest/md5_sha1.rs`,
`src/digest/mdc2.rs`.

---

## 51. Mechanism sweep M46 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M46.json`](atlas-refresh/mechanism-sweep-M46.json).
Candidate `5845eca15` plus this batch's source edits; four files changed (`src/digest/blake2.rs`
is the only behavioural change; `src/dh/mod.rs`, `src/dh/rfc5114.rs` and `src/digest/mdc2.rs`
receive contract text only).

| file | disposition | mechanisms / note |
|---|---|---|
| `src/dh/mod.rs` | audited_no_change | The twenty-one `DH_meth_*` entries, `RawMethod` (partial construction, block-only `Drop`) and `OwnedMethod` (`DH_meth_free`'s name-then-table release), all through `CRYPTO_zalloc`/`CRYPTO_malloc`/`CRYPTO_strdup` with `FILE_DH_METH`. `DH_meth_new` stores `flags` before the name so the error path's plain block release is safe; `DH_meth_dup` copies the whole 72-byte table before the one deep field and drops only the block on a failed strdup. Contract text now names the caller's obligation for `DH_meth_free`/`DH_meth_set1_name`: a table this file created, never a built-in static table such as `DH_OpenSSL`'s. |
| `src/dh/prn.rs` | audited_no_change | `DHparams_print_fp`: `BIO_new(BIO_s_file())`, `BIO_ctrl(BIO_C_SET_FILE_PTR, BIO_NOCLOSE, fp)`, `DHparams_print`, then one `BIO_free`; the caller's `FILE *` is left open. The one refusal raises at `dh_prn.c:28` from reconstructed static strings. No allocation of its own, no ownership transfer, no change. |
| `src/dh/rfc5114.rs` | audited_no_change | The three `make_dh` expansions: `DH_new`, three `BN_dup`s assigned in the authority's `p,g,q` order, and `DH_free` on any NULL duplicate. The deprecated objects own their numbers while `DH_new_by_nid` shares the table's static constants; the tests pin that asymmetry and the `NID_undef` cache behaviour. Contract text now states that each `*_of` argument must return a live `BigNum`; the only callers are the three constant accessors. |
| `src/digest/blake2.rs` | defect_repaired | BLAKE2b/BLAKE2s parameter images, `init`/`init_key`/`update`/`final_`, the compressor and `load`/`store`. `init_key` read `key_length` from the public `Param.b[1]` and copied that many bytes into a stack block behind a `debug_assert!` only; a hostile parameter image could therefore write past `block` in a release build. It now refuses `0` and `> KEYBYTES` before the copy, and the test covers 0, 1, one-past and `u8::MAX` for both flavours. `compress`'s contract now states the whole-block read at each block start (the staging buffer is `BLOCKBYTES`); `init`/`final_` now state the `1..=OUTBYTES` digest-length invariant. |
| `src/digest/md4.rs` | audited_no_change | `Md4Ctx` layout (92 bytes, offsets pinned), the 48-invocation compression through the shared `md32` collector, the `Md32` impl, the four exports and the one-shot's static-NULL arm followed by a local cleanse. The MD4 round functions are the RFC's own spellings, not MD5's simplified forms; the three round bands match the generated table. |
| `src/digest/md5.rs` | audited_no_change | `Md5Ctx` layout (92 bytes), the 64-invocation compression with the authority's `A,D,C,B` destination cycle, the `Md32` impl, the exports and the one-shot's cleanse of its local context. `MD5_Init`'s zeroing is load-bearing because the first `update` reads `num`; the static-NULL answer is the authority's single shared buffer. |
| `src/digest/md5_sha1.rs` | audited_no_change | `Md5Sha1Ctx` is the two contexts side by side (92 + 96, offsets pinned), and the four `ossl_`-prefixed entry points match `md5_sha1.c`. `ossl_md5_sha1_ctrl` is the SSLv3 master-secret arm: md5 48-byte pads, SHA-1 40-byte pads, `md5tmp`/`sha1tmp` cleansed before returning, context re-initialised and re-updated so a later final answers the SSLv3 value. No export. |
| `src/digest/mdc2.rs` | audited_no_change | `Mdc2Ctx` layout (32 bytes, offsets pinned), `c2l`/`l2c`, `mdc2_body` over two DES lanes, `Init`/`Update`/`Final` and the one-shot. `Final`'s `data[i] = 0x80` arm is safe only while `num < MDC2_BLOCK`; that bound is now stated as a caller obligation on `Update`/`Final` because `num` is a public header field (the authority has the same C-level exposure). The two pad arms reproduce the published recipe values. |

**Defect repaired.** `src/digest/blake2.rs` (pre-edit `:263-270` BLAKE2b and `:593-600`
BLAKE2s, severity medium, latent memory safety): `init_key` took its copy length from
`(*p).b[1]`, a field of the public `Param` byte image, and only `debug_assert!`ed the bound.
In a release build a `key_length` above `KEYBYTES` would copy out of `block` and read past
`key`; `0` also fed a zero block instead of refusing a non-key. Both flavours now return 0
for `keylen == 0 || keylen > KEYBYTES` before touching the context or the key. The provider's
`setkey`/`set_ctx_params` already enforce `1..=KEYBYTES`, so the guard changes no valid
caller's result; the new focused test drives the invalid values directly.

**Contract repairs (no behaviour change).** `compress` in both flavours documents that the
compressor reads a whole block at every block start, which the callers satisfy by passing whole
blocks or the `BLOCKBYTES` staging buffer; `init`/`final_` document the digest-length bound that
`set_ctx_params` establishes; `make_dh` documents its function-pointer precondition; `DH_meth_free`
and `DH_meth_set1_name` document that the table must come from this file's allocator seam; and
`MDC2_Update`/`MDC2_Final` document the `num < MDC2_BLOCK` context invariant.

**Secret-bearing buffers.** Digest state is classified `SECRET_DEPENDENT_CONTROL`, not public
metadata. `MD5`/`MD4` cleanse their local context after `Final`; `init_key` cleanses the padded
key block on every arm including the new refusal (`block` is still zeroed on return because the
refusal happens before the copy, and no key byte was written). `md5_sha1` cleanses both
intermediates before re-initialising. MDC-2's `h`/`hh` are digest state and the authority does not
cleanse the caller-owned context; no local secret copy is added. No timing claim is made.

**Assumptions.** Eliminated: 1 (the stack-overflow path in `init_key` is now inexpressible for
any `Param`). Relocated: 0. New: 0. Hidden: 0. Contracts reused: OB-2 `OwnedStr` and the
`CRYPTO_*` seam for the method table, the `md32` collector's `block`/`make_string` contract for
MD4/MD5, and the existing provider `set_ctx_params` bounds for BLAKE2.

**Gates observed.** FAST `cargo fmt --all -- --check` clean. Focused: `digest::blake2` 2 passed /
0 failed (including the new refusal test); `dh::` 56 passed / 0 failed / 2 ignored; `digest::md`
10 passed / 0 failed. BATCH `cargo clippy --all-targets -- -D warnings` clean; full library
**1658 passed / 0 failed / 27 ignored** with `--test-threads=1` (216.09 s) and with
`--test-threads=4` (93.57 s). Affected probes: `dh::object::adv_probe::dh_new_refused_alloc_returns_null_without_free`
and `dh::object::adv_probe::dh_method_init_failure_runs_partial_cleanup` both 1 passed. No
BLAKE2 allocator probe exists; the key-length refusal is covered by the unit test above.

**NOT_RUN.** Constant-time/dudect for BLAKE2, MD4, MD5, MD5-SHA1 and MDC-2 (digest state is
`SECRET_DEPENDENT_CONTROL`; source inspection is not a timing result, and MDC-2's DES tables
are data-dependent by construction); Wycheproof/ACVP (the batch ran the crate's published
vectors only); authority differential `RT-DIGEST`/`RT-DH` (not built or replayed in this batch);
Miri (no component in the court toolchain); ASan (the invalid-length arm is a bounds refusal,
not a memory access); BOUNDARY (no shared mechanism changed: the repaired guard is local to
`init_key` and its valid-input behaviour is unchanged); SEAL.

**Queue.** `REMAINING-AUDIT.txt` 356 → **348**; `AUDITED-FILES.txt` 407 → **415**.
**Next eight (stable order).** `src/digest/ripemd.rs`, `src/digest/sha1.rs`, `src/digest/sha3.rs`,
`src/digest/sm3.rs`, `src/digest/wp.rs`, `src/dsa/asn1.rs`, `src/dsa/backend.rs`,
`src/dsa/check.rs`.

---

## 52. Mechanism sweep M47 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M47.json`](atlas-refresh/mechanism-sweep-M47.json).
Candidate `8e84cdfeb`; no source file changed. All eight files are transcriptions whose unsafe
operations are the collection's established seam patterns, and the audit found no defect that
justified an edit. FAST and BATCH were run on the unchanged candidate.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/digest/ripemd.rs` | audited_no_change | `crypto/ripemd/rmd_dgst.c`, `rmd_one.c`, `rmd_local.h`, `rmdconst.h`: the 96-byte `Ripemd160Ctx` (offsets asserted), the two independent 80-step lines over the shared `md32` collector, the five-assignment combine that reuses the first temporary, the `Md32` impl (little-endian `make_string`), the five exports and the one-shot's local-context cleanse. The block contract is the collector's `num * MD32_CBLOCK` readable. |
| `src/digest/sha1.rs` | audited_no_change | `crypto/sha/sha1dgst.c`, `sha1_one.c`, `sha_local.h`: the 96-byte `ShaCtx`, the ring-buffer `Xupdate` interleaved with the round that consumes it, `Md32` (big-endian `make_string`), the five exports, `ossl_sha1` (direct primitives, local cleanse) and `SHA1` (default-provider `EVP_Q_digest`, shared static NULL arm). `ossl_sha1_ctrl` is the SSLv3 master-secret arm: refuses a wrong cmd/NULL ctx/`mslen != 48` before touching state, cleanses the intermediate digest, leaves the context re-initialised for the caller's `Final`. |
| `src/digest/sha3.rs` | audited_no_change | `crypto/sha/sha3.c` and `keccak1600.c` (reference arm): `KeccakCtx` shape, the 25-lane permutation, `load_le64`/`store_le64`, `SHA3_absorb`/`SHA3_squeeze`, reset/init/update/final/squeeze. State-machine invariants are the authority's: update refuses `FINAL`/`SQUEEZE`, `bufsz < bsz` on every reachable path, `pad_and_absorb` writes `buf[num]` and `buf[bsz-1]` only under that invariant, and a repeated squeeze consumes buffered bytes before permuting. `sha3_blocksize` keeps the authority's `(1600 - bitlen*2)/8`; its callers pass the provider rows' fixed bit lengths or a legacy method's small `md_size*8`, so no hostile `bitlen` reaches the multiply. |
| `src/digest/sm3.rs` | audited_no_change | `crypto/sm3/sm3.c` and `sm3_local.h` over `md32`: the 108-byte `Sm3Ctx`, the loop-form 68-word schedule with the authority's XOR feed-forward, `P0`/`P1`/`FF`/`GG`/`T_j`, `Md32` (big-endian `make_string`), init/update/final and the unexported transform. The collector establishes the staging-block bound; no export is introduced. |
| `src/digest/wp.rs` | audited_no_change | `crypto/whrlpool/wp_block.c` (`OPENSSL_SMALL_FOOTPRINT` arm) and `wp_dgst.c`: the 168-byte `WhirlpoolCtx`, the `S`/`K` round loop, `WHIRLPOOL_Init/Update/BitUpdate/Final` and the one-shot. `Update` chunks at `1 << 60` before `BitUpdate` so `bits * 8` and `blocks * 64` stay inside `usize`; the 256-bit counter carry, the partial-byte staging bound and the `byteoff <= 64` padding arm are the authority's own invariants. `Final` returns 0 without copying for `md == NULL`, and cleanses the caller's context after a successful copy. |
| `src/dsa/asn1.rs` | audited_no_change | `crypto/dsa/dsa_asn1.c`: `dsa_cb` (`NEW_PRE` -> `DSA_new`, `FREE_PRE` -> `DSA_free` + null), one shared `DSA_AUX` behind a justified `unsafe impl Sync`, the three template arrays with `offset_of!`-derived offsets, and `d2i_`/`i2d_`/`DSAparams_dup` through the crate's ASN.1 machinery. `priv_key` is `CBIGNUM_it`, so a decoded private value is wiped by the item's own free path. |
| `src/dsa/backend.rs` | audited_no_change | `crypto/dsa/dsa_backend.c`: `ossl_dsa_key_fromdata` (neither-half success; private half only under `include_private`; `BN_clear_free` on the error path), `ossl_dsa_is_foreign`, `dsa_bn_dup_check`, `ossl_dsa_dup` (authority's `== 0` domain-parameter tests preserved, `DSA_free` on every failure) and `ossl_dsa_key_from_pkcs8` (negative-integer/sequence check, `BN_secure_new` + `BN_FLG_CONSTTIME`, `BN_mod_exp`, authority's `BN_free`/`DSA_free`/`BN_CTX_free`/`ASN1_STRING_clear_free` sequence). The apparent `BN_free` of the private value is secret-safe because `BN_secure_new` sets `BN_FLG_SECURE`, and this crate's `BN_free` cleanses that arm. |
| `src/dsa/check.rs` | audited_no_change | `crypto/dsa/dsa_check.c`: `dsa_precheck_params` (NULL p/q, modulus bound, `q < p`), the quick/full parameter validators, public/partial/private key checks with the authority's `&& *ret == 0` ledger test, and `ossl_dsa_check_pairwise` (`BN_CTX_new_ex`, `BN_new`, public-key recomputation, `BN_free`/`BN_CTX_free` on the shared `err:` path). Allocation failure and mismatch both answer 0, as the authority does. No test calls it directly; its provider callers compile and the full suite covers them. |

**Defects.** None confirmed. No source change was made, so no `#[repr(C)]`, allocator seam,
exported symbol, `# Safety` text or unsafe lint attribute was touched, and the evidence for the
shared mechanisms consumed by these files is not invalidated.

**Secret-bearing buffers.** Digest state is `SECRET_DEPENDENT_CONTROL`, not public metadata.
`RIPEMD160` and `ossl_sha1` cleanse their local contexts (authority behaviour); `md32::finalize`
zeroes the staging block on every construction, and `WHIRLPOOL_Final` cleanses the whole caller
context after copying the digest. `ossl_sha1_ctrl` cleanses its intermediate digest after the
outer-hash update; `padtmp` holds only the public 0x36/0x5c pad bytes. SM3/SHA-3 do not cleanse
caller-owned context state (authority behaviour; the provider's `freectx` owns release). For DSA,
the decoded private key goes through `CBIGNUM_it`, `ossl_dsa_key_fromdata` error paths use
`BN_clear_free` for the private half, and `ossl_dsa_key_from_pkcs8`'s private value is
`BN_secure_new` (so the authority's plain `BN_free` still wipes it). `ossl_dsa_dup` releases a
failed copy through `DSA_free`, which clears both halves.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts reused: RC-1 (raw
context entry points require a live initialized context and a readable input range); OB-2 where
the DSA error sites build authority strings; OB-3 `OwnedCtx` for the provider-side context
lifetime; the `md32` collector's `block`/`make_string` contract for RIPEMD-160/SHA-1/SM3; the
`CBIGNUM_it` cleansing free path; and B19's `BN_free`/`BN_clear_free`/`BN_FLG_SECURE` cleansing
rules.

**Gates observed.** FAST `cargo fmt --all -- --check` clean. Focused tests: `digest::ripemd::tests`
3 passed, `digest::sha1::tests` 5, `digest::sha3::tests` 3, `digest::sm3::tests` 2,
`digest::wp::tests` 3, `dsa::asn1::tests` 2, `dsa::backend::tests` 3 (all 0 failed).
BATCH `cargo clippy --all-targets -- -D warnings` clean; full library **1658 passed / 0 failed /
27 ignored** with `--test-threads=1` (236.50 s) and with `--test-threads=4` (91.21 s). Affected
adversarial probes in the suite: `dsa::object::adv_probe::dsa_new_refused_alloc_returns_null_without_free`
and `dsa::object::adv_probe::dsa_method_init_failure_runs_partial_cleanup` passed as part of the
full run; `dsa::check` has no direct unit test.

**NOT_RUN.** Constant-time/dudect for the five digests and for the DSA private-key paths
(`SECRET_DEPENDENT_CONTROL`; source inspection is not a timing result and no timing measurement
was taken); Wycheproof/ACVP (the batch ran the crate's published vectors only); authority
differential `RT-DIGEST`/`RT-DSA` (not built or replayed in this batch); Miri (no component in the
court toolchain); ASan (no memory access was added or exercised by a probe); BOUNDARY (no shared
mechanism changed; all eight files were audited without edit, so their existing evidence remains
valid); SEAL.

**Queue.** `REMAINING-AUDIT.txt` 348 → **340**; `AUDITED-FILES.txt` 415 → **423**.
**Next eight (stable order).** `src/dsa/ctrl.rs`, `src/dsa/depr.rs`, `src/dsa/gen.rs`,
`src/dsa/key.rs`, `src/dsa/prn.rs`, `src/dsa/sign.rs`, `src/dsa/vrf.rs`, `src/dso/dlfcn.rs`.

## 53. Mechanism sweep M48 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M48.json`](atlas-refresh/mechanism-sweep-M48.json).
Candidate `59c853fa4`. Five files were audited without edit; three carry repairs: two
compatibility residuals (a negative seed length answered the wrong way, and a DER-encoder
error path released its buffer in the wrong order for a recording allocator) and two
safety-contract tightenings. No reusable unsafe abstraction, allocator seam coordinate,
`#[repr(C)]` layout, export or unsafe lint attribute changed.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/dsa/ctrl.rs` | audited_no_change | `crypto/evp/dsa_ctrl.c`: the shared `dsa_paramgen_check` gate (NULL or non-generation op -> `-2` with `EVP_R_COMMAND_NOT_SUPPORTED`; the authority's `pmeth` key-type arm is unreachable because this crate's `EvpPkeyCtx` has no `pmeth`, and the `-1` branch is therefore never taken), six `OSSL_PARAM` builders through the non-strict `EVP_PKEY_CTX_set_params`, and the `EVP_PKEY_CTX_ctrl` wrapper. Contracts cover a NULL-or-live context, NUL-terminated strings, a seed readable for `seedlen`, and locals that outlive the set-params call. The seven NULL-context answers are pinned by the module's test. |
| `src/dsa/depr.rs` | audited_no_change | `crypto/dsa/dsa_depr.c`: `DSA_new` -> `BN_GENCB_new` (failure frees the DSA) -> `BN_GENCB_set_old` -> `DSA_generate_parameters_ex`; success returns the DSA and frees the callback, failure frees the callback then the DSA, matching the authority's `cb`-first order on both paths. The old-style callback is the caller's and is invoked through BN_GENCB under the B-series callback contract; no Rust borrow is held. |
| `src/dsa/gen.rs` | defect_repaired | `crypto/dsa/dsa_gen.c`: the 186-2/186-4 selector (`dirty_cnt` only when `ret > 0`) and the three-arm export (method `dsa_paramgen`, seed install, `bits < 2048 && seed_len <= 20`). **M48-D1** repaired: a negative `seed_len` was clamped to 0, which omitted the seed and then generated parameters, answering 1; the authority's implicit `int`→`size_t` conversion puts the length at or above `INT_MAX`, which `CRYPTO_memdup` refuses, so it answers 0. An explicit negative refusal now precedes the call; the invalid-input state artifact (the authority also drops a pre-existing seed and leaves `seedlen` stale) is recorded and not reproduced. A focused regression test was added. |
| `src/dsa/key.rs` | audited_no_change | `crypto/dsa/dsa_key.c`: method dispatch and the static `dsa_keygen` (partial validation, `BN_secure_new` private exponent, `ossl_ffc_generate_private_key`, `ossl_dsa_generate_public_key`, `dirty_cnt`) plus the `err:` release comparisons. The public-key scratch is `BN_FLG_CONSTTIME` and cleared on both exits; this crate's `BN_with_flags` copies limbs, so the scratch owns its storage. The fresh private key is `BN_secure_new`, and the failure path's `BN_free` is secret-safe through B19's `BN_FLG_SECURE` cleansing arm; a caller's pre-existing key is never released (`priv_key != dsa->priv_key`). |
| `src/dsa/prn.rs` | audited_no_change | `crypto/dsa/dsa_prn.c`: two `FILE`/BIO wrappers (`BIO_s_file`, `BIO_C_SET_FILE_PTR`/`BIO_NOCLOSE`, free on both paths) and the two BIO printers (throwaway `EVP_PKEY`, `EVP_PKEY_set1_DSA`, print gated on the assignment, free on both paths). Private-key printing is the API's purpose; no internal secret buffer is kept. |
| `src/dsa/sign.rs` | defect_repaired | `crypto/dsa/dsa_sign.c`: `OwnedSig` (`CRYPTO_zalloc`; `BN_clear_free` of both halves in `Drop`), `OwnedBufMem`/`BUF_MEM_free`, the two dispatch entry points, `DSA_SIG_get0`/`set0`, the DER pair's three call shapes, `DSA_size`, `ossl_dsa_sign_int`, `DSA_sign` and `DSA_verify` (canonical re-encode, `OwnedBuf::adopt_cleansed`). **M48-D2** repaired: the encoder error path dropped the `BUF_MEM` at scope exit *after* `WPACKET_cleanup`, while `dsa_sign.c:106-108` frees the buffer first; a recording allocator observes that order. The repair drops `buf` explicitly before cleanup (`WPACKET_cleanup` only walks `pkt.subs`). **M48-D3**: `DSA_SIG_set0`'s contract now requires distinct, exclusively owned `r`/`s`; a repeated pointer was permitted by the text but would double-release. |
| `src/dsa/vrf.rs` | audited_no_change | `crypto/dsa/dsa_vrf.c`: one dispatch to `dsa->meth->dsa_do_verify`. The authority calls the member unconditionally; this crate's nullable table entry is the reduction, and an absent member answers `-1`, the authority's "not verified for a reason other than a wrong signature". The `dgst`/`sig`/`dsa` contracts are the authority's. |
| `src/dso/dlfcn.rs` | defect_repaired | `crypto/dso/dso_dlfcn.c`: the dlfcn declarations, `dlfcn_load` (errno save/restore, `OwnedStr` adoption of the converted name, push failure frees the name before `dlclose` exactly as the authority's `err:` label, `loaded_filename` transfer), `dlfcn_unload` (empty stack = 1; a popped NULL is pushed back), `dlfcn_bind_func` (top entry, `dlsym` bits carried without a call), `dlfcn_merger` (four shapes, one trailing slash, `len + 2`), `dlfcn_name_converter` (no-slash rule, EXT_ONLY, `len + 1` write), `dlfcn_pathbyaddr`, `dlfcn_globallookup`, and the static table (`unsafe impl Sync`; NULL `ctrl`/`init`/`finish` are load-bearing) behind `guard_ffi`. **M48-D4**: the `dlfcn_pathbyaddr` contract allowed a NULL `path` unconditionally although the body writes `path[len]` when `sz > 0`; it now permits NULL only for the sizing call. The loader edge was audited: `dlopen`/`dlsym`/`dlclose` invoke no application callback while a Rust borrow is held (library constructors run inside `dlopen`, with no Rust object borrowed; the name handle is an owned value). |

**Secret-bearing buffers.** DSA private exponents are `SECRET_DATA`. `dsa_keygen` allocates a
fresh exponent with `BN_secure_new` (`BN_FLG_SECURE`); the failure path releases it with the
authority's `BN_free`, which B19 establishes cleanses that arm, and the caller's own key is
never released. `ossl_dsa_generate_public_key`'s `BN_FLG_CONSTTIME` scratch is `BN_clear_free`d
on both exits. The signature halves (`r`, `s`, k-derived and secret-adjacent) are
`BN_clear_free`d by `OwnedSig::Drop`/`DSA_SIG_free` and by `DSA_SIG_set0` when replacing them.
`DSA_sign_setup` hands the nonce inverse to its caller; this unit stores no nonce buffer.
`DSA_verify`'s DER re-encode is cleansed over `derlen.max(0)` bytes through
`OwnedBuf::adopt_cleansed` (the authority's `OPENSSL_clear_free`). `i2d_DSA_SIG`'s `BUF_MEM` is
released through `BUF_MEM_free`, which cleanses its data. The DSO unit holds only public
filenames, released with the plain `CRYPTO_free` seam.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. The three repairs remove two
latent behavioural divergences and two loose contracts; the negative-length guard narrows the
input contract rather than adding an assumption. Contracts reused: RC-1; OB-1 `OwnedBuf`
(`adopt_cleansed`); OB-2 `OwnedStr` (`adopt_nullable`, plain release); B19's
`BN_free`/`BN_clear_free`/`BN_FLG_SECURE` cleansing rules; the B-series callback contracts for
the BN_GENCB old-style callback and the method-table entry points; and the `DsoMethod`
static/`Sync` contract. The only added unsafe operation is the test-only block in
`dsa::gen::tests`, which carries its own `SAFETY:` contract; no production unsafe op was added.

**Gates observed.** FAST `cargo fmt --all -- --check` clean. Focused filters (0 failed each):
`dsa::ctrl` 1 passed, `dsa::depr` 0, `dsa::gen` 1, `dsa::key` 0, `dsa::prn` 0, `dsa::sign` 0,
`dsa::vrf` 0, `dso::dlfcn` 5. BATCH `cargo clippy --all-targets -- -D warnings` clean; full
library **1659 passed / 0 failed / 27 ignored** with `--test-threads=1` (284.91 s) and with
`--test-threads=4` (102.47 s); 1658 -> 1659 is the one added regression test. The two affected
DSA allocator probes were executed individually (`--ignored --exact`, `OPENSSL_RS_ADV_PROBE=1`):
`dsa_new_refused_alloc_returns_null_without_free` and
`dsa_method_init_failure_runs_partial_cleanup`, 1 passed each.

**NOT_RUN.** Constant-time/dudect for the DSA private-key and nonce paths
(`SECRET_DEPENDENT_CONTROL`; source inspection is not a timing result and no measurement was
taken); Wycheproof/ACVP (the crate's published vectors were exercised, no external suite was
replayed); `RT-DSA`/`RT-DSO` authority differential (not built or replayed); Miri (no component
in the court toolchain); ASan (the repairs change a refusal and an error-path release order, not
a memory access, and no sanitizer build was run); BOUNDARY (no reusable unsafe abstraction or
shared-mechanism contract changed; the DSO loader edge was audited and holds no Rust borrow
across `dlopen`/`dlsym`/`dlclose`, but a dedicated loader BOUNDARY pass was not run); SEAL.

**Queue.** `REMAINING-AUDIT.txt` 340 -> **332**; `AUDITED-FILES.txt` 423 -> **431**.
**Next eight (stable order).** `src/ec/backend.rs`, `src/ec/check.rs`, `src/ec/ctrl.rs`,
`src/ec/curve.rs`, `src/ec/cvt.rs`, `src/ec/depr.rs`, `src/ec/ecdh_ossl.rs`,
`src/ec/ecdsa_ossl.rs`.

## 54. Mechanism sweep M49 — 8-file ordinary batch — 2026-10-19

Candidate `24e7c2ac4`. All eight EC files were audited against `crypto/ec/ec_*.c`,
`crypto/evp/ec_ctrl.c` and the established contracts (RC-1, OB-1/OB-2/OB-3/OB-4,
B1/B2/B6–B18, B19). Five files needed no edit. Four repairs: one secret-cleansing
gap in the ECDH failure path (M49-D1), an `int`-overflow comparison on
caller-supplied digest lengths (M49-D2), and two `# Safety` contracts that
permitted a NULL out-slot on a path that writes it (M49-D3/D4). No reusable unsafe
abstraction, allocator coordinate (`file`/`line`/extent), `#[repr(C)]` layout,
export or unsafe lint attribute changed.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/ec/backend.rs` | audited_no_change | `crypto/ec/ec_backend.c`: the three `OSSL_ITEM` name/id maps (static, `unsafe impl Sync` over `'static` literals), `ec_group_explicit_todata`/`ossl_ec_group_todata` (optional parameters chosen by `tmpl`/located descriptor), the key/group `fromdata` family (`OwnedBlock` adoption of the getter's block at `:492`, `BN_secure_new` + `BN_FLG_CONSTTIME` private import, `BN_clear_free` on every tail), `ossl_ec_key_dup` (fresh group/point/`BN_new` private copy; failure `EC_KEY_free` cleanses through `BN_clear_free`), and the X.509/PKCS#8 tail (`d2i_ECParameters`/`d2i_ECPrivateKey` write-back slots, `ecerr` releases key then group). The X509-ALGOR parameter-type dispatch reads `ASN1_STRING` bytes only in the `V_ASN1_SEQUENCE` arm. |
| `src/ec/check.rs` | audited_no_change | `crypto/ec/ec_check.c`: `EC_GROUP_check_named_curve` (NULL/live group, optional `BN_CTX_new_ex`, `EC_curve_nid2nist` NULL test) and `EC_GROUP_check` (custom-curve early success, discriminant, generator on-curve, order non-zero, `order·G == ∞`). Every allocation (`new_ctx`, `point`) is released on each exit; the custom-curve return precedes both allocations. |
| `src/ec/ctrl.rs` | defect_repaired | `crypto/evp/ec_ctrl.c`: six strict `OSSL_PARAM` builders, the shared derivation gate (legacy/pkey-type arm unreachable by the `pmeth` reduction), the one custody transfer (`OPENSSL_free(ukm)` only on `1`) and six `EVP_PKEY_CTX_ctrl` wrappers. **M49-D3**: `EVP_PKEY_CTX_get_ecdh_kdf_outlen`'s contract admitted a NULL `plen` although the `1` arm writes it; now live/writable whenever the gate passes (NULL only with a refused context). **M49-D4**: `EVP_PKEY_CTX_get_ecdh_kdf_md` likewise; its fixer writes the resolved method through `p2` on the GET arm. `get0_ecdh_kdf_ukm` stays NULL-admissible because `set_octet_ptr` writes only a non-NULL `data`. |
| `src/ec/curve.rs` | audited_no_change | `crypto/ec/ec_curve.c`: generated table accessors (`EcCurveData`/`EcListElement`, `curve_list_method` D-EC-2), `EC_get_builtin_curves` (bounded `r.add(i)`, static comments), `ec_group_new_from_data` (seed/param slicing, `BN_bin2bn`, method/`group_set_curve` selection, generator/order/cofactor/seed install, ASN.1 flag adjustment, `BN_free` of public parameters only), and `ossl_ec_curve_nid_from_params` (`CRYPTO_malloc_array` checked extent, `OwnedBlock` plain release, `BN_CTX_get` slots, seed/parameter comparisons gated on equal widths). |
| `src/ec/cvt.rs` | audited_no_change | `crypto/ec/ec_cvt.c`: `EC_GROUP_new_curve_GFp`/`GF2m` select the profile's method (compile-time `OPENSSL_BN_ASM_MONT` arm), build via `ossl_ec_group_new_ex(ossl_bn_get_libctx(ctx), …)` and free the group when `EC_GROUP_set_curve` fails. No internal state. |
| `src/ec/depr.rs` | audited_no_change | `crypto/ec/ec_deprecated.c`: `EC_POINT_point2bn` (octet block `OwnedBuf::adopt_plain`, authority's leak-on-`buf_len > INT_MAX` path preserved and annotated) and `EC_POINT_bn2point` (`BN_num_bytes` macro expansion, zero-length widened to one, release-line-tagged `OwnedBuf`, caller's point never cleared, frame-owned point cleared on `oct2point` failure). |
| `src/ec/ecdh_ossl.rs` | defect_repaired | `crypto/ec/ecdh_ossl.c`: the method-column dispatcher and `ossl_ecdh_simple_compute_key` (cofactor arm in a `BN_CTX` temporary, affine x, field-width left padding, ownership transfer to `*pout`). **M49-D1**: the shared-secret block was plain-freed on every post-allocation failure, although it can already contain secret bytes; `OwnedSecretBuf` now stores its extent and cleanses with `CRYPTO_clear_free` at the same `(file, line 145)` coordinate. The success transfer remains uncleansed (authority behaviour; caller owns and clears). |
| `src/ec/ecdsa_ossl.rs` | defect_repaired | `crypto/ec/ecdsa_ossl.c`: three method-column dispatchers, `ossl_ecdsa_sign`/`deterministic_sign`/`verify`, the static nonce setup (`BN_secure_new` k, `BN_new` r/x, pre-growth, retry loops, inverse in place, transfer + `setup_err`), `ossl_ecdsa_simple_sign_sig` (digest truncation, Montgomery chain, retry cap, `sign_sig_err`) and `ossl_ecdsa_simple_verify_sig` (r/s range checks, `u1·G + u2·Q`). **M49-D2**: `8 * dgst_len` is now computed in `i64` at all four sites; the authority's signed `int` multiply is undefined for `|dlen| > INT_MAX/8`. The `ossl_ecdsa_sign_setup` contract now requires distinct `kinvp`/`rp` slots and distinct pointed-to `BIGNUM`s (the success arm clears and replaces both). |

**Secret-bearing buffers.** ECDH: the shared secret is the caller-owned `CRYPTO_malloc`
block (`SECRET_DATA`); the `BN_CTX` temporary `x` is `BN_clear`ed on every exit, the point
`tmp` is cleared, and the output block is now cleansed on every failure release; the
success edge transfers it uncleansed to the caller (authority contract). ECDSA: the nonce
`k` is `BN_secure_new` and reaches `BN_clear_free` on every failure and on both success
callers (`sign_sig_err`, `deterministic_sign`); `x` and the digest-derived `m` are
`BN_clear_free`d on every exit; signature halves are released by `ECDSA_SIG_free`, whose
`Drop` uses the `BN_clear_free` pair; the private scalar is only ever borrowed from the
`EC_KEY` (owned and cleansed by `EC_KEY_free`). `ec_backend`'s imported private scalar is
`BN_secure_new` and `BN_clear_free`d after `EC_KEY_set_private_key` copies it; the dup path
uses `BN_new`/`BN_copy` and is cleansed by `EC_KEY_free` on failure. Curve/check/cvt/depr
hold public parameter, point and seed data; their releases are plain `BN_free`/`CRYPTO_free`
matching the authority.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts reused: RC-1;
OB-1 `OwnedBuf` (`adopt_plain`, release-line tagging), OB-3 `OwnedCtx` via
`ECDSA_SIG_free`; B19's `BN_clear_free`/`BN_FLG_SECURE` rules; B1/B2/B6–B18 callback
contracts for the EC method-table columns and `EVP_PKEY_CTX_ctrl`; the `OsslItem` static
`Sync` contract. The D-EC-2 method substitution remains the recorded profile divergence.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused `cargo test --lib ec::`
47 passed / 0 failed / 1 ignored (1638 filtered). BATCH `cargo clippy --all-targets -- -D
warnings` clean; full library **1659 passed / 0 failed / 27 ignored** with
`--test-threads=4` (88.21 s) and with `--test-threads=1` (231.13 s). No ignored/`#[ignore]`
adversarial probe exists for the touched EC modules, so no EC allocator probe was affected
and none was replayed; the two changed behavioural sites (ECDH failure release, ECDSA
width compare) have no dedicated probe. Doc-only edits after the test run (ECDH owner
comment, `OWNER-DUPLICATES.md` §9.4) cannot change code identity.

**NOT_RUN.** Constant-time/dudect for ECDH and ECDSA private-scalar/nonce paths
(`SECRET_DEPENDENT_CONTROL`; source inspection is not a timing result and the generic
`BN_mul`/`BN_mod_mul` path is not the authority's fixed-top path); Wycheproof/ACVP (the
crate's published vectors ran, no external suite was replayed); `RT-EC` authority
differential (not rebuilt/replayed for this batch); Miri (no component in the court
toolchain); ASan (the repairs are a release-mode change and an arithmetic-width change, no
memory access); BOUNDARY (no reusable unsafe abstraction's contract changed — the ECDH
owner is module-local and its contract is unchanged except for the release mechanism);
SEAL.

**Queue.** `REMAINING-AUDIT.txt` 332 -> **324**; `AUDITED-FILES.txt` 431 -> **439**.
**Next eight (stable order).** `src/ec/ecdsa.rs`, `src/ec/ecx_backend.rs`,
`src/ec/ecx_key.rs`, `src/ec/kdf.rs`, `src/ec/kmeth.rs`, `src/ec/mod.rs`,
`src/ec/mont.rs`, `src/ec/mult.rs`.


## 55. Mechanism sweep M50 — 8-file ordinary batch — 2026-10-19

Candidate `adc3c4402`. All eight EC files were audited against the admitted
`openssl-3.6.4` sources and the established contracts (RC-1, OB-1/OB-2/OB-3/OB-4,
B1/B2/B6–B18, B19). Three files needed no edit. Five files carry repairs: one
secret-cleansing gap in the PKCS#8 ECX import (M50-D1), three allocator seam file
strings that lacked the admitted build record's `__FILE__` prefix
(M50-D2/D3/D4), one one-bit-field conversion that was not truncated to its C
storage width (M50-D5), and two stale free-site coordinates in comments
(M50-D6, documentation only). No `#[repr(C)]` layout, exported symbol/signature,
allocation extent/line, or unsafe lint attribute changed.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/ec/ecdsa.rs` | defect_repaired | `crypto/ec/ecdsa_sign.c`, `ecdsa_vrf.c` and `ec_asn1.c:1187-1300`: seven method-column dispatchers (`ECDSA_do_sign[_ex]`, `ECDSA_sign[_ex]`, `ECDSA_sign_setup`, `ECDSA_do_verify`, `ECDSA_verify`) and the `ECDSA_SIG` constructor/destructor/accessors (`OwnedCtx`/`RawCtx`, two `BN_clear_free` members). **M50-D2**: the allocator seam now reports `../../src/openssl-3.6.4/crypto/ec/ec_asn1.c`, the admitted authority's `__FILE__`, instead of the short path. **M50-D6**: the `OPENSSL_free(sig)` coordinate in two comments is line 1200, not 1198. `ECDSA_SIG_set0` replaces and clears the old pair only after both arguments are checked non-NULL. |
| `src/ec/ecx_backend.rs` | defect_repaired | `crypto/ec/ecx_backend.c`: `ossl_ecx_public_from_private` (four arms, no default), `ossl_ecx_key_fromdata` (private octets imported at `keylen`, mismatch cleared with the **received** length), `ossl_ecx_key_dup` (`RawDupKey`→`OwnedDupKey` staged construction, `CRYPTO_zalloc` at `:106`, private copy into a secure allocation, `dup_err`), `ossl_ecx_key_op` (algorithm-parameter checks, keygen clamping, silent `RAND_priv_bytes_ex` failure) and `ossl_ecx_key_from_pkcs8`. **M50-D1**: the decoded `ASN1_OCTET_STRING` is a copy of the raw private scalar; it is now released with `ASN1_STRING_clear_free`, not the authority's plain `ASN1_OCTET_STRING_free`. |
| `src/ec/ecx_key.rs` | defect_repaired | `crypto/ec/ecx_key.c`: the `ECX_KEY` shape, `CtxDestroy` (`propq` free at `:77`, secure clear at `:81`, block at `:83`), `ossl_ecx_key_new` (`RawCtx`), `ossl_ecx_key_free` (release/acquire refcount), `_set0_libctx`, `_up_ref`, `_allocate_privkey` and `ossl_ecx_compute_key` (X25519/X448 only, length query, output-length check). **M50-D5**: `haspubkey` is a one-bit C field; the storage-unit model now masks the assignment with `& 1`, where the previous `as c_uint` could store 2 or larger. |
| `src/ec/kdf.rs` | audited_no_change | `crypto/ec/ecdh_kdf.c`: the four-`OSSL_PARAM` X963 descriptor build, the single `EVP_KDF` fetch/`EVP_KDF_CTX` create/derive/release sequence (a refused context still frees the fetched method), and the deprecated `ECDH_KDF_X9_62` forwarder with NULL libctx/propq. The input `Z` and output `out` are caller-owned and not copied here. |
| `src/ec/kmeth.rs` | defect_repaired | `crypto/ec/ec_kmeth.c`: the static default `EC_KEY_METHOD`, `EC_KEY_OpenSSL`/`_get_default_method`/`_set_default_method` (`AtomicPtr`, NULL restores the built-in), `EC_KEY_get_method`/`_set_method`, `ossl_ec_key_new_method_int` (`OwnedEcKey` whose `Drop` is the authority's `err:` `EC_KEY_free`), `ECDH_compute_key` (`OwnedSecret` cleansing the method's buffer at `:172`), the `EC_KEY_METHOD_*` allocator/free and the twelve column setters/getters. **M50-D3**: the seam now reports `../../src/openssl-3.6.4/crypto/ec/ec_kmeth.c`, the authority's `__FILE__`. |
| `src/ec/mod.rs` | audited_no_change | `crypto/ec/ec_local.h`: `EC_FLAGS_*`, `point_conversion_form_t`, `Pct`, `EcMethod`/`EcGroup`/`EcPoint`/`EcKey`/`EcdsaSig`/`EcKeyMethod`, the `EcPreComp` union, all callback type aliases, and `ec_point_is_compat`. Layouts are the measured authority shapes; the only function is a field predicate whose contract requires live, initialised objects. |
| `src/ec/mont.rs` | audited_no_change | `crypto/ec/ecp_mont.c`: the `EC_GFp_mont_method` table, group init/finish/clear-finish/copy (cleansing `field_data2` on the clear paths), `group_set_curve` (replace-then-restore field data, release on `simple_group_set_curve` failure), field mul/sqr/inv/encode/decode/set-to-one. `field_inv` uses the public Fermat exponent in a secure `BN_CTX`; every `BN_*` temporary is released on each exit. No allocator seam of its own. |
| `src/ec/mult.rs` | defect_repaired | `crypto/ec/ec_mult.c`: `EcPreCompSt`/`CtxDestroy` (points array + points, refcounted release), `ec_pre_comp_new`/`_dup`/`EC_ec_pre_comp_free`, the three ladder inlines, `EC_POINT_CSWAP`, `ossl_ec_scalar_mul_ladder` (cardinality/lambda Montgomery ladder, `pbit` merge, affine input, `BN_FLG_CONSTTIME`), `ossl_ec_wNAF_mul` (precomputation reuse, wNAF splitting, per-scalar windows, `val`/`val_sub` ownership, single `err:` release) and `ossl_ec_wNAF_precompute_mult`/`_have_precompute_mult`. **M50-D4**: the seam now reports `../../src/openssl-3.6.4/crypto/ec/ec_mult.c`, the authority's `__FILE__`. Length sums mirror the authority and are bounded by the valid array/count contract; `CRYPTO_malloc_array` keeps its checked multiply. |

**Secret-bearing buffers.** `SECRET_DATA`: the ECX private scalar is allocated with
`CRYPTO_secure_zalloc`, copied into a secure allocation by the duplicate, cleansed at
`keylen` by `CRYPTO_secure_clear_free` on every destructor path, and cleansed at the
**received** length on the `fromdata` size-mismatch arm; the PKCS#8 decode's private
octet copy is now cleared before release (M50-D1); the `ECDH_compute_key` method buffer
is cleansed by `OwnedSecret` after both the raw-copy and KDF branches (and is not
released if the method itself failed, matching the authority's caller obligation);
`ECDSA_SIG`'s `r`/`s` reach `BN_clear_free` on replacement and destruction (M49's
nonce handling in `ecdsa_ossl` is unchanged). `SECRET_DEPENDENT_CONTROL`: scalar
bits drive the ladder's `BN_consttime_swap`; no constant-time claim is made from
source inspection, and dudect was not run. The wNAF digit arrays are plain-freed as
in the authority; the secret-scalar cases take the ladder path, so they are not
classified secret here. `kdf.rs` borrows `Z` and writes caller-owned `out`; any
provider-internal secret copies are `provider/kdf.rs`'s scope.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts reused:
RC-1 allocator seam; OB-1 `OwnedBuf`/`OwnedBlock` (through callees and the checked
getter); OB-3 `OwnedCtx`/`CtxDestroy` for `EcdsaSig`, `EcxKey`, `EcPreCompSt`;
B1/B2/B6–B18 callback and reentrancy contracts for the `EC_KEY_METHOD` columns,
`compute_key`/`KDF` and the method setters; B19 `BN_clear_free`/`BN_FLG_CONSTTIME`
rules. The ECX `haspubkey` bitfield is modelled as its storage unit (recorded
representation difference).

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`cargo test --lib ec::` 47 passed / 0 failed / 1 ignored (1638 filtered). BATCH
`cargo clippy --all-targets -- -D warnings` clean; full library **1659 passed /
0 failed / 27 ignored** with `--test-threads=1` (201.53 s) and with
`--test-threads=4` (92.24 s). The one affected allocator probe,
`ec::ecx_backend::adv_probe::ecx_key_dup_refused_alloc_returns_null_without_free`,
was replayed alone and passed (1 passed, 0 failed). All run in the court container
with `CARGO_BUILD_JOBS=4`.

**NOT_RUN.** Constant-time/dudect for the ECX private-scalar, ECDSA
private-scalar/nonce and ladder paths (`SECRET_DEPENDENT_CONTROL`; source
inspection is not a timing result); Wycheproof/ACVP (the crate's published vectors
ran, no external suite was replayed); `RT-EC` authority differential (not
rebuilt/replayed); Miri (no component in the court toolchain); ASan (the repairs
change a seam string, a one-bit mask and a release helper, not a memory access
pattern); BOUNDARY (no reusable unsafe abstraction's contract changed — the touched
contracts are the existing OB-3 owners and the ASN.1 clear-free helper);
SEAL.

**Queue.** `REMAINING-AUDIT.txt` 324 -> **316**; `AUDITED-FILES.txt` 439 -> **447**.
**Next eight (stable order).** `src/ec/nist.rs`, `src/ec/oct.rs`, `src/ec/print.rs`,
`src/ec/prn.rs`, `src/ec/sm2_key.rs`, `src/ec/smpl2.rs`, `src/ec/smpl.rs`,
`src/ec/support.rs`.


## 56. Mechanism sweep M51 — 8-file ordinary batch — 2026-10-19

Candidate `876100008`. All eight EC files were audited against the admitted
`openssl-3.6.4` sources and the established contracts (RC-1, OB-1, B1/B2/B6–B18,
B19). Three files needed no edit. Five files carry repairs: two allocator-seam
file strings without the admitted build record's `__FILE__` prefix (M51-D2/D3),
one unchecked allocation sum (M51-D4), one method-table content mismatch
(M51-D1), and one unsafe-API contract that described UB as an allowed input
(M51-D5, documentation only). No `#[repr(C)]` layout, exported symbol/signature,
allocation extent/line, or unsafe lint attribute changed. Every function body was
compared with its authority counterpart; the arithmetic and control flow match.

| file | disposition | mechanisms / note |
|---|---|---|
| `src/ec/nist.rs` | audited_no_change | `crypto/ec/ecp_nist.c`: the `EC_GFp_nist_method` table, the `EC_GFp_nist_method` export, `group_copy` (copies `field_mod_func` before the simple copy), `group_set_curve` (selects `BN_nist_mod_192`..`_521` by comparing `p`; a private `BN_CTX` is freed on both the refusal and success paths) and `field_mul`/`field_sqr` (private `BN_CTX` freed on every exit). No allocator seam of its own; no secret copy. |
| `src/ec/oct.rs` | defect_repaired | `crypto/ec/ecp_oct.c` and `crypto/ec/ec_oct.c`: the `PointBuf` owner (`CRYPTO_malloc` at `:147`, `Drop` `CRYPTO_free` at `:151`), GFp `set_compressed_coordinates`, `point2oct`/`oct2point` (length checks before every write, exact authority `skip`/`i` arithmetic), the three deprecated wrappers and `EC_POINT_point2buf` (`into_raw` is the single transfer edge, the refusal path frees). **M51-D2**: the seam now reports `../../src/openssl-3.6.4/crypto/ec/ec_oct.c`, the admitted authority's `__FILE__`, instead of the short path. |
| `src/ec/print.rs` | defect_repaired | `crypto/ec/ec_print.c`: `EC_POINT_point2hex` (`OwnedBuf` adoption of the point-encoding block, `OPENSSL_free` at `:39`; output rendered two uppercase digits per octet), `OwnedClearBuf` (`CRYPTO_malloc` at `:63`, cleansing `CRYPTO_clear_free` at `:72` over the decoder-written length) and `EC_POINT_hex2point`/`hex2point_tail` (the shared `err:` tail frees the octets and clears a point only when this call allocated it). **M51-D4**: `buf_len * 2 + 2` is now `checked_mul`/`checked_add`; an unrepresentable extent answers NULL (the authority's allocation-failure answer) instead of wrapping to a short block and overrunning it. |
| `src/ec/prn.rs` | audited_no_change | `crypto/ec/eck_prn.c` and `ec_ameth.c:717-720`: `GenBuf` adopts `EC_POINT_point2buf`'s `(ptr, len)` pair and its `Drop` is the authority's `OPENSSL_clear_free` at `:218`; `print_bin`'s fixed 133-byte buffer is safe because `off` is clamped to 128 before the `off + 1 + 4` write; `ECPKParameters_print`'s named/explicit arms, single `reason` tail and `p, a, b, gen_buf, ctx` release order match; the four `FILE *` wrappers and the `EC_KEY_PRINT_PARAM` arm are transcribed. |
| `src/ec/sm2_key.rs` | audited_no_change | `crypto/sm2/sm2_key.c`: `ossl_sm2_key_private_check` borrows the group, private scalar and order; only `max = BN_dup(order)` is allocated and it is `BN_free`d on every path (both `BN_sub_word` failure arms). The private scalar itself is never copied or buffered here. |
| `src/ec/smpl2.rs` | defect_repaired | `crypto/ec/ec2_smpl.c` and `crypto/ec/ec2_oct.c`: the binary method table, group init/finish/clear-finish/copy/set/get/discriminant, point init/finish/clear/copy/set-to-infinity/affine get-set, add/dbl/invert/is-on-curve/cmp/make-affine(s), field mul/sqr/div/inv, the Lopez-Dahab ladder pre/step/post, `ec_GF2m_simple_points_mul` and the three ec2_oct codecs. **M51-D1**: the table's `point_set_compressed_coordinates`, `point2oct` and `oct2point` slots are NULL again, as in `ec2_smpl.c:954-956`; `EC_FLAGS_DEFAULT_OCT` already dispatches those operations by field type in `ec_oct.c`, so behaviour is unchanged. |
| `src/ec/smpl.rs` | defect_repaired | `crypto/ec/ecp_smpl.c`: the prime method table, group init/finish/clear-finish/copy/set/get/discriminant, Jacobian/affine coordinate accessors, add/dbl/invert/is-on-curve/cmp/make-affine(s), field mul/sqr/inv, coordinate blinding and the ladder. `prod_z` is one `CRYPTO_malloc_array` block in an `OwnedBuf` (release at `:1357`) whose elements are `BN_clear_free`d in the authority's element loop; `field_inv` uses `BN_CTX_secure_new_ex` when the caller supplies no context. **M51-D3**: the array seam now reports `../../src/openssl-3.6.4/crypto/ec/ecp_smpl.c`, the admitted authority's `__FILE__`. |
| `src/ec/support.rs` | defect_repaired | `crypto/evp/ec_support.c`: the 82-row `curve_list` and 15-row `nist_curves` tables in authority order, `OSSL_EC_curve_nid2name`, `ossl_ec_curve_name2nid` (NIST table first, then case-folded search), `ossl_ec_curve_nid2nist_int` and `ossl_ec_curve_nist2nid_int` (`strcmp`). **M51-D5**: the last function's `# Safety` now states that `name` must be non-NULL; the previous text described a NULL dereference in `strcmp` as an expected fault rather than as an input outside the contract. |

**Secret-bearing buffers.** No secret copy is introduced in this batch. `SECRET_DATA`
and `SECRET_DEPENDENT_CONTROL` live in the callers (`mult.rs`, `ecdsa_ossl.rs`).
The authority's cleansing arms are preserved: `smpl.rs`/`smpl2.rs`
group/point `*_clear_finish` use `BN_clear_free`, and `prod_z`'s elements use
`BN_clear_free`; `smpl.rs::field_inv` uses a secure `BN_CTX` when it creates one;
`print.rs`'s point-octet buffer and `prn.rs`'s generator buffer are public-data
blocks that the authority nevertheless clear-frees, and both owners keep that
release (`ec_print.c:72`, `eck_prn.c:218`). `sm2_key.rs` reads the SM2 private
scalar only to compare it and frees no copy. `oct.rs` point encodings are
public and use the authority's plain release. No constant-time claim is made
from source inspection.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts
reused: RC-1 allocator seam; OB-1 `OwnedBuf` (`adopt_plain_nullable`, typed
plain/cleansed releases, `Drop` as the single release); B19's `BN_clear_free`
rule for group/point/`prod_z` elements; B1/B2/B6–B18 callback contracts for the
`EC_METHOD` tables and `ec_oct.c`'s `EC_FLAGS_DEFAULT_OCT` dispatch.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`cargo test --lib ec:: -- --test-threads=4` 47 passed / 0 failed / 1 ignored
(1638 filtered). BATCH `cargo clippy --all-targets -- -D warnings` clean; full
library **1659 passed / 0 failed / 27 ignored** with `--test-threads=1`
(312.63 s) and with `--test-threads=4` (90.68 s). No adversarial probe exists
for the four changed sites; the only EC probe (`ecx_backend::adv_probe`) is not
in this batch and was not replayed. All runs were in the court container with
`CARGO_BUILD_JOBS=4`.

**NOT_RUN.** Constant-time/dudect for the prime/binary field inversion,
blinding and ladder paths (`SECRET_DEPENDENT_CONTROL`; source inspection is not
a timing result); Wycheproof/ACVP (the crate's published vectors ran, no
external suite was replayed); `RT-EC` authority differential (not rebuilt or
replayed); Miri (no component in the court toolchain); ASan (the repairs change
seam strings, a table's NULL slots, a checked length and a doc comment, not a
memory-access pattern); BOUNDARY (no reusable unsafe abstraction's contract
changed — the owners and callbacks are the existing OB-1/B1/B2/B6–B18
contracts); SEAL.

**Retained observations.** (1) `print.rs`'s `OwnedClearBuf` trusts the
decoder-reported `oct_buf_len` not to exceed the buffer extent passed to
`OPENSSL_hexstr2buf_ex`; the authority has the same precondition, and the
decoder's contract establishes it. (2) The method table is consumed through
`EC_FLAGS_DEFAULT_OCT`; the M51-D1 change is not observably behavioural inside
the crate, but a direct observer of `EC_GF2m_simple_method()` now sees the
authority's NULL slots. (3) Out of this batch but the same seam-prefix class:
`src/ec/ecdh_ossl.rs:61` and `src/ec/ecdsa_ossl.rs:66` still use short
`crypto/ec/...` `FILE` constants for their `CRYPTO_*` calls. They were audited
in M49, are not in this batch, and are left unchanged; a later ledger pass
should decide whether M49's evidence remains valid or needs reissuing.

**Queue.** `REMAINING-AUDIT.txt` 316 -> **308**; `AUDITED-FILES.txt` 447 -> **455**.
**Next eight (stable order).** `src/engine/eng_all.rs`, `src/engine/eng_dyn.rs`,
`src/engine/eng_fat.rs`, `src/engine/eng_lib.rs`, `src/engine/eng_pkey.rs`,
`src/engine/eng_table.rs`, `src/engine/tb_cipher.rs`, `src/engine/tb_dh.rs`.

## 57. Mechanism sweep M52 — 8-file ordinary batch — 2026-10-19

**Batch.** `src/engine/eng_all.rs`, `eng_fat.rs`, `eng_lib.rs`, `eng_pkey.rs`,
`tb_cipher.rs`, `tb_dh.rs`, `tb_digest.rs`, `tb_dsa.rs`. `eng_dyn.rs` (DSO
loader and `bind_engine` callback) and `eng_table.rs` (lhash doall, engine
`init`/`finish` callbacks under the engine lock) were confirmed as
loader/callback boundaries and recorded **NOT_RUN**; `tb_digest.rs` and
`tb_dsa.rs` were substituted and remain in the queue. Metadata-only follow-up:
`src/ec/ecdh_ossl.rs:61` and `src/ec/ecdsa_ossl.rs:66` now carry the admitted
`../../src/openssl-3.6.4/` seam prefix.

| file | disposition | authority / mechanisms |
|---|---|---|
| `src/engine/eng_all.rs` | audited_no_change | `crypto/engine/eng_all.c`: `ENGINE_load_builtin_engines` transcribes the authority's `OPENSSL_init_crypto(ALL_BUILTIN, NULL)` inside `guard_ffi`; the still-unsupported init bit and the recorded divergence are unchanged. |
| `src/engine/eng_fat.rs` | defect_repaired | `crypto/engine/eng_fat.c`: method-mask dispatch, `int_def_cb`'s exact-length `strncmp` arms, `CONF_parse_list` error operand, complete registrars, and the deliberate `engine_unregister_from_all_tables` removal hardening. **M52-D3**. |
| `src/engine/eng_lib.rs` | defect_repaired | `crypto/engine/eng_lib.c`: `ENGINE_new`/`engine_free_util`/`ENGINE_free`, the checked refcount sentinel, the cleanup stack, ex-data and element accessors. `engine_set_all_null`'s field inventory matches the authority exactly (it deliberately does not clear the EC/pkey-method/SSL-loader slots). **M52-D2**. |
| `src/engine/eng_pkey.rs` | defect_repaired | `crypto/engine/eng_pkey.c`: three loader setters/getters and the three entry points; NULL/`funct_ref`/no-loader refusal order matches. **M52-D2**. |
| `src/engine/tb_cipher.rs` | defect_repaired | `crypto/engine/tb_cipher.c`: cipher table, registration/default selection and the two callback accessors. **M52-D1**. |
| `src/engine/tb_dh.rs` | defect_repaired | `crypto/engine/tb_dh.c`: single `dummy_nid` table. **M52-D1**. |
| `src/engine/tb_digest.rs` | defect_repaired | `crypto/engine/tb_digest.c`: digest table selected by `ossl_asn1_item_digest_ex`. **M52-D1**. |
| `src/engine/tb_dsa.rs` | defect_repaired | `crypto/engine/tb_dsa.c`: single `dummy_nid` table. **M52-D1**. |

**Defects repaired.** M52-D1 (low, six `tb_*` files): `# Safety` said `e` "must
be NULL or point to a live `Engine`" for functions whose body dereferences `e`
unconditionally (`ENGINE_register_*`, `ENGINE_set_default_*`, the getters and
setters); a permitted input that is UB is not a sound contract. Now requires a
non-NULL live `Engine`. M52-D2 (low, `eng_lib`/`eng_pkey`): same class for the
nine non-null-tolerant element/getter accessors and the six loader
setters/getters; the `ENGINE_free`, ex-data and `ENGINE_load_*` functions that do
test NULL keep the NULL-tolerant wording. M52-D3 (low, `eng_fat`):
`ENGINE_set_default`, `ENGINE_set_default_string` and
`ENGINE_register_complete` now require a non-NULL `Engine`. M52-D4 (none,
metadata): the two short EC seam strings are restored to the admitted prefix.
No production code path, signature, layout or exported symbol changed.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts
reused: RC-1 allocator seam (exact size/file/line preserved); OB-3 owner shape
for `RawEngine`/`OwnedEngine` and the cleanup `OwnedItem` (partial allocation
releases only the block; the last-reference owner runs the authority's member
destructor body once); B1/B2/B6–B18 callback contracts for the engine method
tables and loader callbacks; B15/B16 engine ctrl/registration contracts.
`eng_dyn`/`eng_table` remain queued for a BOUNDARY pass.

**Recorded deviation.** `ENGINE_set_ex_data`/`ENGINE_get_ex_data` answer 0/NULL
for a NULL engine, where the authority dereferences it (C UB). This is the
existing in-crate safety improvement; it is recorded here rather than silently
inherited.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`cargo test --lib engine:: -- --test-threads=4` 19 passed / 0 failed /
0 ignored (1667 filtered). BATCH `cargo clippy --all-targets -- -D warnings`
clean; full library **1659 passed / 0 failed / 27 ignored** with
`--test-threads=1` (230.71 s) and with `--test-threads=4` (94.92 s). All runs in
the court container with `CARGO_BUILD_JOBS=4`.

**NOT_RUN.** `RT-ENGINE` phase-13/phase-16 authority differential (not rebuilt
or replayed); no allocator-transcript probe was re-executed for the two seam
strings; Miri (no component in the court toolchain); ASan (documentation and seam
metadata only, no memory-access-pattern change); BOUNDARY for `eng_dyn` and
`eng_table` (deferred to their own pass — they remain in the queue); SEAL.

**Retained observations.** (1) The same NULL-permissive wording remains in the
still-unaudited `tb_eckey`, `tb_pkmeth`, `tb_rand` and `tb_rsa` siblings; the
repair applies when those files are audited. (2) The M49 ownership evidence for
`ecdh_ossl`/`ecdsa_ossl` is unaffected by the metadata repair; only the reported
allocator coordinate changes, and it now matches the admitted build record.
(3) `engine_set_all_null` intentionally leaves `ec_meth`, `pkey_meths`,
`pkey_asn1_meths` and `load_ssl_client_cert` uncleared, exactly as
`eng_lib.c:56-75` does; this is not an omission.

**Queue.** `REMAINING-AUDIT.txt` 308 -> **300**; `AUDITED-FILES.txt` 455 -> **463**.
**Next eight (stable order).** `src/engine/eng_dyn.rs`, `src/engine/eng_table.rs`,
`src/engine/tb_eckey.rs`, `src/engine/tb_pkmeth.rs`, `src/engine/tb_rand.rs`,
`src/engine/tb_rsa.rs`, `src/ess/ess_asn1.rs`, `src/evp/algorithm.rs`.

## 58. Boundary sweep B20 — dynamic ENGINE loader and ENGINE operation tables — 2026-10-19

Receipt: [`atlas-refresh/boundary-sweep-B20.json`](atlas-refresh/boundary-sweep-B20.json).

**STOP status: CLEAR after repair.** One Rust data race was confirmed and repaired:
`ossl_engine_table_select` read the `ENGINE_TABLE *` slot without the engine lock on
the authority's `*table == NULL` fast path while `engine_table_cleanup` /
`engine_table_register` wrote it under the lock. ThreadSanitizer reports the race at
`eng_table.rs:472` on the pre-repair shape and is clean on the repair; the new
`concurrent_select_and_cleanup_serialise_on_the_engine_lock` test is the witness. The
authority has the same C data race; the fast path is deliberately not reproduced
(§17). One overflow panic across an `extern "C"` comparison was removed. Register,
select-walk, pile-destructor and dynamic-loader preconditions that were implicit are
now stated (non-NULL register target, borrowed-entry lifetime, doall lock, the
per-ENGINE exclusivity of control/load, and the loaded library's `dynamic_fns`
lifetime). A `dynamic_fns` C-layout guard was added. No export, signature,
`#[repr(C)]` layout, allocator-seam coordinate or unsafe-lint attribute changed.

| file | boundaries | disposition | defects |
|---|---|---|---|
| `src/engine/eng_dyn.rs` | `B20-DYN-1..4` (ex_data context ownership/construction, ctrl string+`dirs` ownership, DSO load/version/bind rollback, built-in registration) | `CONTRACTED` | none; **B20-D6 (fixed, low)** states the per-ENGINE exclusivity and loaded-library callback obligations the authority leaves implicit. |
| `src/engine/eng_table.rs` | `B20-TBL-1..5` (pile ownership/destructor, register, unregister/cleanup, select, doall) | `CONTRACTED` | **B20-D1 (fixed, medium):** unlocked slot read in select (TSan-confirmed data race). **B20-D2 (fixed, low):** `engine_pile_cmp` could overflow-panic across `extern "C"`; now `wrapping_sub`. **B20-D3 (fixed, low):** register contract allowed NULL while `setdefault` dereferences it, and omitted the borrowed-entry lifetime. **B20-D4 (fixed, low):** doall omitted the engine-lock/no-mutation precondition. **B20-D5 (fixed, low):** the pile destructor's engine-lock precondition is now explicit. |

**Ownership before/after.** `DynamicDataCtx` keeps its staged `RawDataCtx` ->
`OwnedCtx` construction, single `CRYPTO_free` at `eng_dyn.c:147`/`:193`, and
`dirs`/`int_free_str` ownership; `EnginePile` keeps `RawCtx::malloc` ->
`assume_init` -> lhash ownership with block-only failure releases at `:113` and the
normal release at `:184`. Both files' `CtxDestroy` bodies were re-read against the
authority; the only change is the stated destructor-lock precondition.

**Assumptions.** Eliminated: 1 (the unlocked slot read). Relocated: 0. New: 0.
Hidden: 0. Contract corrections make the remaining external obligations explicit:
per-ENGINE control/load exclusivity; the loaded library may not retain `dynamic_fns`;
registered entries borrow `e` until unregistered; `engine_table_doall` callers hold
the engine lock and do not mutate the table; a non-NULL cached `funct` is finished
only under the lock. Reused: RC-1/OB-1..OB-4 allocator and owner shapes;
B1/B2/B6–B18 callback contracts; B15/B16 engine ctrl/registration contracts.

**Residuals (disclosed, not hidden).** `B20-R1` the authority's `uptodate` arm can
return the cached default without an acquired functional reference when `init`
fails (pinned by two tests). `B20-R2` table entries are borrowed `ENGINE *`; the
global-list removal path retires them before dropping its reference (a deliberate
improvement), but an engine registered without being in the list must be kept alive
by its registrant. `B20-R3` engine `init`/`finish`/`destroy` hooks run under the
engine write lock in register/select/unregister/cleanup (authority parity; a
recursive write is refused, a read lock can block). `B20-R4` allocations occur under
that lock, so allocator hooks must not re-enter engine APIs. `B20-R5` per-ENGINE
control/load is not serialised (authority parity; now an external contract).
`B20-R6` `v_check`/`bind_engine` are arbitrary unlocked library code. `B20-R7` a
lock failure while lazily registering the dynamic ex_data index leaks that index
(bounded; authority parity). `B20-R8` the authority's mandatory list-add failure
leaves the failed engine bound and the DSO loaded (poisoned, later ctrl refused;
authority parity).

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`engine::eng_dyn` + `engine::eng_table` 5 passed / 0 failed. BATCH clippy
`--all-targets -D warnings` clean; full library **1660 passed / 0 failed / 27
ignored** with `--test-threads=4` (93.68 s) and with `--test-threads=1`
(277.26 s). One test added, none removed, none newly ignored (1687 collected).
**TSan** (`nightly-2026-10-05`, `-Zsanitizer=thread -Zbuild-std`, dedicated
`.tsan-target`, one test, `--test-threads=1`): positive run clean; the pre-repair
negative control reported `WARNING: ThreadSanitizer: data race` at
`eng_table.rs:472` (`ossl_engine_table_select` vs `engine_table_cleanup`).

**NOT_RUN.** Miri (no `miri` component in either venue; the path uses allocator and
pthread FFI); ASan (not the instrument for the slot-ordering defect and no extent or
ownership change; TSan covered the class); Loom (the C ABI statics are not a Loom
model); `RT-ENGINE` authority differential for the exact candidate; FRF/probe suite;
SEAL.

**Queue.** `REMAINING-AUDIT.txt` 300 -> **298**; `AUDITED-FILES.txt` 463 -> **465**.
**Next eight (stable order).** `src/engine/tb_eckey.rs`, `src/engine/tb_pkmeth.rs`,
`src/engine/tb_rand.rs`, `src/engine/tb_rsa.rs`, `src/ess/ess_asn1.rs`,
`src/evp/algorithm.rs`, `src/evp/c_allc.rs`, `src/evp/c_alld.rs`.

## 59. Mechanism sweep M53 — 8-file ordinary batch — 2026-10-19

Receipt: [`atlas-refresh/mechanism-sweep-M53.json`](atlas-refresh/mechanism-sweep-M53.json).

**Batch.** `src/engine/tb_eckey.rs`, `tb_pkmeth.rs`, `tb_rand.rs`, `tb_rsa.rs`,
`src/ess/ess_asn1.rs`, `src/evp/c_allc.rs`, `c_alld.rs`, and substituted
`src/evp/e_aes_cbc_hmac_sha1.rs`. `src/evp/algorithm.rs` was confirmed as a
provider-dispatch/registry boundary (`reserve_store`/`fn_`/`unreserve_store`
function pointers and `ossl_provider_doall_activated`) and left **NOT_RUN** for a
BOUNDARY pass; the next ordinary entry was substituted.

| file | disposition | authority / mechanisms |
|---|---|---|
| `src/engine/tb_eckey.rs` | defect_repaired | `crypto/engine/tb_eckey.c`: EC method table (authority's `dh_table` spelling), `dummy_nid`, register/unregister/set-default and the opaque method accessors. **M53-D1**. |
| `src/engine/tb_pkmeth.rs` | defect_repaired | `crypto/engine/tb_pkmeth.c`: NID-set callback registration, `ENGINE_get_pkey_meth`, and `engine_pkey_meths_free` over the engine's own callback. **M53-D1**. |
| `src/engine/tb_rand.rs` | defect_repaired | `crypto/engine/tb_rand.c`: single-`dummy_nid` RAND table and accessors. **M53-D1**. |
| `src/engine/tb_rsa.rs` | defect_repaired | `crypto/engine/tb_rsa.c`: single-`dummy_nid` RSA table and accessors. **M53-D1**. |
| `src/ess/ess_asn1.rs` | audited_no_change | `crypto/ess/ess_asn1.c`: five `ASN1_SEQUENCE` templates, 16/16/24/16/16-byte layouts and the generated new/free/dup/d2i/i2d exports. Template flags, offsets, `static_` vs exported `_it` split and `#ifndef` profile arms match the authority. |
| `src/evp/c_allc.rs` | audited_no_change | `crypto/evp/c_allc.c`: `openssl_add_all_ciphers_int` registration order, aliases and the `no-rc5` omissions match the authority. |
| `src/evp/c_alld.rs` | audited_no_change | `crypto/evp/c_alld.c`: `openssl_add_all_digests_int` order, three explicit aliases and the `no-md2` omission match the authority. |
| `src/evp/e_aes_cbc_hmac_sha1.rs` | audited_no_change | `crypto/evp/e_aes_cbc_hmac_sha1.c`: the two deprecated statics, `init`/`do_cipher`/`ctrl`/ASN.1 callbacks over the provider context, TLS 1.1 AAD pad arithmetic and the AES-NI-gated NULL answer. AAD writes are bounded by the 13-byte check and the 16-byte `aux`; `SHA1_Update`/state copies use owner-derived slots. |

**Defects repaired.** M53-D1 (low, four `tb_*` files, 21 clauses): `# Safety`
said `e` "must be NULL or point to a live `Engine`" for functions whose bodies
dereference `e` unconditionally. Each now requires a non-NULL live `Engine`,
completing the M52-D1 class. `engine_pkey_meths_free` keeps its NULL-tolerant
wording because it tests NULL; `ENGINE_set_pkey_meths` now names `e` explicitly
instead of the generic "pointer arguments" sentence. No production code,
signature, layout or exported symbol changed.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. Contracts
reused: RC-1 allocator seam (no allocation in the batch changed); B1/B2/B6–B18
engine callback contracts, including the `ENGINE_PKEY_METHS_PTR` count-and-`nids`
obligation also used by `tb_cipher.rs`; B15/B16/B20 engine table selection;
the ASN.1 item/template and generated-wrapper contracts; the legacy EVP
`OBJ_NAME` registration contract.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`cargo test --lib -- --test-threads=4 engine::` 20 passed / 0 failed /
0 ignored (1667 filtered); `legacy_evp::` 5 passed / 0 failed. BATCH
`cargo clippy --all-targets -- -D warnings` clean; full library **1660 passed /
0 failed / 27 ignored** with `--test-threads=1` (228.46 s) and with
`--test-threads=4` (82.14 s). All runs in the court container with
`CARGO_BUILD_JOBS=4`.

**NOT_RUN.** BOUNDARY for `src/evp/algorithm.rs` (provider-dispatch/registry
callback boundary; remains queued); Miri (no component in the court toolchain);
ASan (contract wording only, no memory-access-pattern change); `RT-ENGINE` /
`RT-EVP` authority differentials for the exact candidate; FRF/probe suite; SEAL.

**Retained observations.** (1) `algorithm.rs` is not a registry *table* like the
`tb_*` units but the provider algorithm walk; its function-pointer callbacks mean
it needs the BOUNDARY treatment, not a contract-wording pass. (2) The
`ENGINE_PKEY_METHS_PTR` callback must set `nids` to `num_nids` integers whenever
it answers a positive count; this is the established engine callback obligation,
inherited unchanged from the authority. (3) No secret copy or constant-time
claim is involved in this batch; the method tables and name registration are
public data.

**Queue.** `REMAINING-AUDIT.txt` 298 -> **290**; `AUDITED-FILES.txt` 465 -> **473**.
**Next eight (stable order).** `src/evp/algorithm.rs`, `src/evp/e_aes_cbc_hmac_sha256.rs`,
`src/evp/e_bf.rs`, `src/evp/e_cast.rs`, `src/evp/e_des.rs`, `src/evp/e_idea.rs`,
`src/evp/e_rc4_hmac_md5.rs`, `src/evp/e_rc4.rs`.

## 60. Boundary sweep B21 — EVP algorithm walk, provider callbacks and the first-name seam

**Candidate.** `integrate/safe-c33` at `f1daf09bb`; `src/evp/algorithm.rs`
(blob `5f886ca7b`). Authority: `crypto/core_algorithm.c` (sha256
`182f4a8d…`, 6,246 bytes) in the pinned 3.6.4 manifest.

**Disposition.** CONTRACTED, not `SAFETY_DISCHARGED`. Five boundaries
(B21-EVP-1..5) re-use the B9/B10 registry serialization contract:
`ossl_provider_doall_activated` takes a provider reference and raises its
activation count before invoking `algorithm_do_this` **outside every lock**,
and `query_operation`/`unquery_operation` bracket the map walk.

**Defects repaired.**
- B21-D1 (low, allocator-seam coordinate): `L_STRNDUP` said 175; the pinned
  authority's `OPENSSL_strndup` call is `core_algorithm.c:197`. Fixed.
- B21-D2 (low, panic/overflow): `cur_operation += 1` overflowed for an
  out-of-contract `operation_id == INT_MAX` (authority C UB; debug panic
  across `unsafe extern "C"`). Replaced with `checked_add` and a defined stop.
- B21-D3 (doc): the `libctx` rewrite comment claimed a reader/callback
  visibility that does not exist; `cbdata.libctx` is written and never read
  (authority parity). Corrected.

**Gates observed.** FAST fmt clean; focused `evp::algorithm` **7 passed / 0
failed** (1,680 filtered). BATCH clippy clean; full library **1660 passed /
0 failed / 27 ignored** serial (281.28 s) and threaded (90.54 s), in the court
with `CARGO_BUILD_JOBS=4`.

**NOT_RUN.** Miri (no component in stable 1.98.1/nightly-2026-10-05); ASan on
the exact candidate (no memory-access-pattern change; the allocation remains
the audited `CRYPTO_strndup` seam and no production test reaches the walk);
Loom/TSan (no lock or atomic in this file; the callback refcount discipline is
B9/B10's and was not edited); `RT-FETCH` named-provider/sweep differential;
FRF/probe suite; SEAL.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. No new
production unsafe operation; no safe Rust interface changed. Residuals are the
provider-table termination/NUL contract, the reserve/unreserve callback pairing
(a caller lock is held across pre/fn/post), and the non-fatal context assertion
— all authority parity and recorded in `boundary-sweep-B21.json`.

**Queue.** `REMAINING-AUDIT.txt` 290 -> **289**; `AUDITED-FILES.txt` 473 -> **474**.
**Next eight (stable order).** `src/evp/e_aes_cbc_hmac_sha256.rs`,
`src/evp/e_bf.rs`, `src/evp/e_cast.rs`, `src/evp/e_des.rs`, `src/evp/e_idea.rs`,
`src/evp/e_rc4_hmac_md5.rs`, `src/evp/e_rc4.rs`, `src/evp/e_seed.rs`.

## 61. Per-file audit M54 — legacy EVP cipher carriers (eight files)

**Candidate.** `integrate/safe-c33` at `e686b3642` plus this batch's worktree edits.
Files: `src/evp/e_aes_cbc_hmac_sha256.rs`, `src/evp/e_bf.rs`,
`src/evp/e_cast.rs`, `src/evp/e_des.rs`, `src/evp/e_idea.rs`,
`src/evp/e_rc4_hmac_md5.rs`, `src/evp/e_rc4.rs`, `src/evp/e_seed.rs`.
Authority: the pinned 3.6.4 `crypto/evp/e_*.c` files (cross-checked against
3.5.9, 3.4.8, 3.0.0 and 1.1.1w where an expression was in doubt).

**Disposition.** Seven files are clean transcriptions whose statics, mode
loops, key lengths, block sizes, flags, ASN.1 views and ctx sizes match the
authority field for field. Two genuine defects were found and repaired in the
stitched AES-CBC-HMAC-SHA256 carrier, and one authority-UB reproduction was
closed in the RC4-HMAC-MD5 control.

**Defects repaired.**
- M54-D1 (high, compatibility / caller buffer sizing):
  `src/evp/e_aes_cbc_hmac_sha256.rs:220` answered
  `EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE` with the SHA-1 digest constant
  (`arg + 20 + 16`) instead of the SHA-256 one (`arg + 32 + 16`; authority
  `e_aes_cbc_hmac_sha256.c:807-808` in every checked release). For a
  representative TLS fragment of 16384 the answer was 16437 instead of 16453;
  a caller sizing a multiblock output buffer from the control answer could be
  sixteen bytes short. The value is now computed by
  `tls11_multiblock_max_bufsize`, which uses `SHA256_DIGEST_LENGTH` and
  refuses an overflowing fragment size with `-1` (the authority's signed
  addition is undefined there). Controls:
  `evp::e_aes_cbc_hmac_sha256::tests::the_tls11_max_bufsize_reserves_a_sha256_digest`
  and `..._refuses_overflow` (2 passed).
- M54-D2 (medium, authority-UB reproduction):
  `src/evp/e_rc4_hmac_md5.rs:228` passed a negative
  `EVP_CTRL_AEAD_SET_MAC_KEY` length through `arg as usize`, i.e. a
  `SIZE_MAX`-byte read from the caller's pointer. The authority converts the
  same `int` to `size_t` and faults; a negative key length is never valid, so
  the callback now answers `-1` instead of reproducing the fault (§17).
- M54-D3 (medium, authority-UB reproduction): the same command in
  `src/evp/e_aes_cbc_hmac_sha256.rs:181` now refuses a negative length, and
  its `EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT` arm now refuses an `arg` smaller
  than `EvpCtrlTls11MultiblockParam` before dereferencing `ptr_`, matching the
  provider arm's recorded deliberate divergence and the `_AAD` sibling's
  existing test.

**Adjacent observation (not edited).** The already-audited sibling
`src/evp/e_aes_cbc_hmac_sha1.rs` (AUDITED-FILES.txt:282) carries the same two
negative/undersized legacy-control patterns at `:191` and `:255`. It was not
in this batch and was not re-audited; queue it for a small follow-up repair
with the same two guards (its `MAX_BUFSIZE` constant is already the correct
SHA-1 `20`).

**Secret-bearing storage and cleansing.** Every key schedule
(`ProvAesHmacSha256Ctx.ks`, `head/tail/md`, `Rc4Key`, `BfKey`, `CastKey`,
`DesKeySchedule`, `IdeaKeySchedule`, `SeedKeySchedule`) lives in the legacy
`cipher_data` block and is cleansed by the shared
`EVP_CIPHER_CTX_reset`/`OwnedCtx` path with `OPENSSL_cleanse(cipher_data,
ctx_size)` before `CRYPTO_free`; no per-file `cleanup` callback is needed and
none is installed, matching the authority's NULL `cleanup`. The scratch
`hmac_key[64]` in RC4-HMAC-MD5 and in the provider's
`aesni_cbc_hmac_sha256_set_mac_key` is cleansed before return. IDEA's decryption
schedule temporary is `MaybeUninit`, filled by `IDEA_set_encrypt_key`, and
cleansed after use. `aux`/`payload_length` hold TLS AAD and length metadata
(public), and are not cleansed. The RC4-HMAC-MD5 local `mac` holds the wire
MAC (public) and is not cleansed. No constant-time claim is made anywhere in
this batch.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`evp::e_` **18 passed / 0 failed** (including the two new formula controls).
BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1662 passed / 0 failed / 27 ignored** serial (64.31 s) and with
`--test-threads=4` (98.74 s; 1689 total), in the court with
`CARGO_BUILD_JOBS=4`. No newly ignored test and no unexplained removal
(previous batch: 1660 passed / 27 ignored; +2 are this batch's controls).

**NOT_RUN.** Miri (no component in the pinned toolchain); ASan/valgrind on the
negative-length arms (no in-tree fixture constructs a legacy cipher context
for these private controls; the guards are compile- and review-verified);
constant-time/dudect analysis (no secret-dependent branch was introduced; the
authority parity claim is not a timing result); `RT-CIPHER` differential for
the MAX_BUFSIZE answer; FRF/probe suite; SEAL.

**Assumptions.** Eliminated: 1 (the wrong size answer no longer exists).
Relocated: 0. New: 0. Hidden: 0. No new production unsafe operation was
introduced; no exported symbol, signature, `#[repr(C)]` layout, or allocator
coordinate changed. The legacy `EVP_CIPHER` objects remain carriers whose
`ctrl` callbacks are reachable only through an engine; their caller contract
is unchanged, and the three new refusals only reject calls that were invalid
or undefined in the authority.

**Queue.** `REMAINING-AUDIT.txt` 289 -> **281**; `AUDITED-FILES.txt` 474 -> **482**.
**Next eight (stable order).** `src/evp/e_sm4.rs`, `src/evp/evp_cnf.rs`,
`src/evp/evp_lib.rs`, `src/evp/e_xcbc_d.rs`, `src/evp/keymgmt_lib.rs`,
`src/evp/legacy_blake2.rs`, `src/evp/legacy_evp.rs`, `src/evp/legacy_md4.rs`.

## 62. Per-file audit M55 — legacy EVP statics, CNF and ALGOR hand-offs (eight files)

**Candidate.** `integrate/safe-c33` at `03ef9b1fd` plus this batch's worktree
edits. Files: `src/evp/e_sm4.rs`, `src/evp/evp_cnf.rs`, `src/evp/evp_lib.rs`,
`src/evp/e_xcbc_d.rs`, `src/evp/legacy_blake2.rs`, `src/evp/legacy_evp.rs`,
`src/evp/legacy_md4.rs`, `src/evp/legacy_md5.rs`. `src/evp/keymgmt_lib.rs`
was the fifth queued file but is a provider export/import dispatch boundary
(operation cache, two-lock protocol, provider callbacks), so it was **not**
audited here and remains queued; `src/evp/legacy_md5.rs` was substituted from
the next stable slot. Authority: the pinned 3.6.4 `crypto/evp/` units
(`e_sm4.c`, `evp_cnf.c`, `evp_lib.c`, `e_xcbc_d.c`, `legacy_blake2.c`,
`names.c`, `legacy_md4.c`, `legacy_md5.c`, `legacy_md5_sha1.c`).

**Disposition.** All eight audited files are clean transcriptions. Their
statics match the authority field for field (NID, pkey NID, size, block size,
flags, origin, ASN.1 views, `ctx_size`), their callback triples forward the
context and data pointers unchanged, and their NULL/ownership contracts are
stated at every raw boundary. No ownership, initialisation, aliasing or
secret-lifetime defect was found in them.

**Queued follow-up repaired (already-audited file, metadata only).**
`src/evp/e_aes_cbc_hmac_sha1.rs` carried the same legacy-control patterns M54
repaired in the SHA-256 sibling:
- M55-D1 (medium, authority-UB reproduction): the `SET_MAC_KEY` arm at `:191`
  forwarded a negative `arg` to the provider's `size_t` length, a
  `SIZE_MAX`-byte read. It now refuses `arg < 0` with `-1` (§17).
- M55-D2 (medium, authority-UB reproduction): the
  `MULTIBLOCK_ENCRYPT` arm at `:255` dereferenced `ptr_` without the size test
  its `_AAD` sibling makes. It now refuses
  `arg < size_of::<EvpCtrlTls11MultiblockParam>()` with `-1`, matching the
  provider arm's recorded divergence.
- M55-D3 (low, signed overflow): the `MAX_BUFSIZE` answer at `:238` computed
  `arg + 20 + 16` in `c_int` and would panic (debug) or wrap (release) for a
  fragment size near `INT_MAX`. The SHA-1 digest constant (`20`) is correct;
  the arithmetic is now the checked helper `tls11_multiblock_max_bufsize`,
  which refuses overflow with `-1`. Two controls added:
  `evp::e_aes_cbc_hmac_sha1::tests::the_tls11_max_bufsize_reserves_a_sha1_digest`
  and `..._refuses_overflow` (both pass).

**Secret-bearing storage and cleansing.** `e_sm4.rs`'s `EvpSm4Key` (SM4 round
keys) and `e_xcbc_d.rs`'s `DesxCbcKey` (DES key schedule plus the two
whitening blocks) are secret and live in the legacy `cipher_data` block. Both
are cleansed by the shared `EVP_CIPHER_CTX_reset` path with
`OPENSSL_cleanse(cipher_data, ctx_size)` before `CRYPTO_free` (and by the
`CRYPTO_clear_free` arms on the init-failure paths); `cleanup` is `None`,
matching the authority. The digest statics keep `ctx_size` zero, so they own
no `md_data` block and no secret state in this crate; the provider fetch
replaces them before any callback reads `md_data`. `evp_lib.rs`'s `aid`
buffer holds the public `algorithm-id` DER and is owned by `OwnedBuf` at the
authority's malloc/free coordinates. `evp_cnf.rs`'s formatted error string is
public configuration text. No constant-time claim is made in this batch.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`cargo test --lib` per unit — `e_sm4` 1, `evp_cnf` 1, `evp_lib` 0,
`e_xcbc_d` 1, `legacy_blake2` 2, `legacy_evp` 5, `legacy_md4` 2,
`legacy_md5` 3, `e_aes_cbc_hmac_sha1` 2 — **17 passed / 0 failed**. BATCH:
`cargo clippy --all-targets -- -D warnings` clean; full library
**1664 passed / 0 failed / 27 ignored** serial (66.20 s) and with
`--test-threads=4` (82.67 s; 1691 total), in the court with
`CARGO_BUILD_JOBS=4`. No newly ignored test and no unexplained removal
(previous batch: 1662 passed / 27 ignored; +2 are this batch's controls).

**NOT_RUN.** Miri (no component in the pinned toolchain); ASan/valgrind and a
runtime control for M55-D1/D2 (no in-tree fixture constructs a legacy
CBC-HMAC-SHA1 context for these private control arms; the guards are compile-
and review-verified); constant-time/dudect (no secret-dependent branch was
introduced); `RT-CIPHER` differential for the MAX_BUFSIZE answer; FRF/probe
suite; dependency-graph regeneration; SEAL.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: 0. No new
production unsafe operation, exported symbol, signature, `#[repr(C)]` layout
or allocator coordinate changed. The changed helper is safe Rust.

**Queue.** `REMAINING-AUDIT.txt` 281 -> **273**; `AUDITED-FILES.txt` 482 ->
**490**. **Next eight (stable order).** `src/evp/keymgmt_lib.rs`,
`src/evp/legacy_mdc2.rs`, `src/evp/legacy_ripemd.rs`,
`src/evp/legacy_sha3.rs`, `src/evp/legacy_sha.rs`, `src/evp/legacy_wp.rs`,
`src/evp/method_store.rs`, `src/evp/p5_crpt.rs`.

## M56 — per-file contract sweep (keymgmt utilities and PBES units)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`4f340911c` (dirty worktree; no commit was made by the audit subagent). Census
identity is unchanged from the M55 receipt. The eight records below are
file-level obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/evp/keymgmt_lib.rs` | operation-cache `OP_CACHE_ELEM` ownership (`OwnedCacheElem`), provider export/import round trip, read/write lock protocol, origin identity `(name_id, prov)`, callback re-entry | 1 defect (M56-D1) repaired; cache/ownership contracts reused |
| `src/evp/legacy_mdc2.rs` | legacy `EVP_MD` static carrier (`EVP_ORIG_GLOBAL`, `ctx_size` 0, callback triple) | no defect; M55 legacy-static contract reused |
| `src/evp/legacy_ripemd.rs` | same carrier pattern | no defect; same contract |
| `src/evp/legacy_sha3.rs` | same carrier pattern plus `sha3_int_init`'s `ctx->digest->md_size` read and `shake_ctrl`'s XOF length write | no defect; the callbacks are unreachable on the zero-`ctx_size` statics through the legacy arm (provider fetch or `NO_INIT` early return) |
| `src/evp/legacy_sha.rs` | seven carriers plus `sha1_int_ctrl`'s NULL-context guard and `ossl_sha1_ctrl` extent contract | no defect; same reachability argument |
| `src/evp/legacy_wp.rs` | same carrier pattern (`pkey_type` literal 0, `WHIRLPOOL_BBLOCK / 8`) | no defect; same contract |
| `src/evp/p5_crpt.rs` | ASN.1 `PBEPARAM`, PBKDF1 fetch/derive, key/IV split, secret buffers | 2 defects (M56-D2 fixed-buffer bound, M56-D3 failure-path cleansing) repaired |
| `src/evp/p5_scrypt.rs` | `SCRYPT_PARAMS` decode, length/probe validation, `err_cleanup` cleansing on every post-decode failure | no defect; existing `err_cleanup` contract reused |

**Deferred boundary.** `src/evp/method_store.rs` was not audited: it is the
method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary.
It remains in `REMAINING-AUDIT.txt` at the head of the queue. `keymgmt_lib.rs`
was audited rather than deferred because its production body is the portable
key export/import ownership helper; its provider round trip and lock protocol
were read in full and M56-D1 was repaired.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M56-D1 | `src/evp/keymgmt_lib.rs:377` (pre-fix call at 371) | high | authority-UB reproduction: NULL `pk->keymgmt` dereference | `evp_keymgmt_util_export` refuses an unassigned key before `evp_keymgmt_export` (§17 divergence; authority crashes on a fresh `EVP_PKEY_new()` passed to `EVP_PKEY_export`/`EVP_PKEY_todata`) |
| M56-D2 | `src/evp/p5_crpt.rs:285` (pre-fix check at 262) | high | unbounded provider digest size writes past a 64-byte stack buffer | refuse `EVP_MD_get_size(md) > EVP_MAX_MD_SIZE` before `EVP_KDF_derive` (§17 divergence) |
| M56-D3 | `src/evp/p5_crpt.rs:409` (pre-fix `err:` label at 343) | medium | secret-bearing stack buffers not cleansed on failure paths | `finish_err` now cleanses `md_tmp`/`key`/`iv` before every failure return (§5 divergence; the authority cleanses only on success) |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0.
Hidden obligations: 0. No production unsafe operation, exported symbol,
signature, `#[repr(C)]` layout or allocator coordinate changed. The M56-D1
guard, the M56-D2 bound and the M56-D3 cleansing add no `unsafe fn`; M56-D3
extends the existing private `finish_err` contract with three caller-owned
buffer extents.

**Contracts reused.** Legacy `EVP_MD` static carrier contract (M55: global
origin, zero `ctx_size`, provider fetch replacement); provider
callback/reentrancy contract; `OSSL_PARAM` terminated-array contract; RC-1
allocator-seam coordinates; PBES/`err_cleanup` cleansing pattern from
`p5_scrypt.rs`; ASN.1 private-item shape transposition.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`evp::keymgmt_lib` 5 passed / 0 failed, `evp::p5_crpt` 6 passed / 0 failed,
`legacy_` (all legacy units) 42 passed / 0 failed, and `p5_scrypt` 2 passed /
0 failed.
BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1665 passed / 0 failed / 27 ignored** (1692 total) serial in 60.81 s and
with `--test-threads=4` in 97.95 s, in the court with `CARGO_BUILD_JOBS=4`.
No unexplained removal and no newly ignored test (M55: 1664 passed / 27
ignored; +1 is M56-D1's regression control).

**NOT_RUN.** Miri, ASan/valgrind, dudect/constant-time (no secret-dependent
branch introduced); a runtime witness for M56-D3 cleansing (stack residue is
not externally observable; review-only) and an oversized-digest control for
M56-D2 (no fixture builds a provider method reporting `size > 64`);
affected adversarial probes (the `scripts/adv-probe.sh` set has no probe for
these boundaries); authority differential for the three §17/§5 divergences;
FRF suite; dependency-graph regeneration; SEAL.

**Queue.** `REMAINING-AUDIT.txt` 273 -> **265**; `AUDITED-FILES.txt` 490 ->
**498**. **Next eight.** `src/evp/method_store.rs` (registry boundary —
defer again), `src/evp/pbe.rs`, `src/evp/p_dec.rs`, `src/evp/p_enc.rs`,
`src/evp/p_legacy_assign.rs`, `src/evp/p_lib.rs`, `src/evp/pmeth_check.rs`,
`src/ffc/backend.rs`.

## M57 — per-file contract sweep (legacy PKEY wrappers, method checks, FFC backend and keygen)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`526fa34db` (dirty worktree; no commit was made by the audit subagent). Census
identity is unchanged from the M56 receipt. The eight records below are
file-level obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/evp/pbe.rs` | `EVP_PBE_scrypt[_ex]` descriptor build, NULL normalisation, `r`/`p` bound, KDF fetch/context lifetime, caller-owned key extent | 1 defect (M57-D1) repaired; OSSL_PARAM and KDF contracts reused |
| `src/evp/p_dec.rs` | `EVP_PKEY_decrypt_old`: type test, legacy RSA accessor, PKCS#1 v1.5 decrypt, caller-owned plaintext | no defect |
| `src/evp/p_enc.rs` | `EVP_PKEY_encrypt_old`: type test, legacy RSA accessor, PKCS#1 v1.5 encrypt, caller-owned ciphertext | no defect |
| `src/evp/p_legacy_assign.rs` | six set1/get0/get1 exports, `RSA`/`EC_KEY` up_ref and failure release, base-id test for SM2 | no defect; refcount contract reused |
| `src/evp/p_lib.rs` | `EVP_PKEY_set1_engine` / `get0_engine`: functional reference, method probe, previous engine release, two distinct fields | no defect; engine callback contract reused |
| `src/evp/pmeth_check.rs` | `try_provided_check` -1/0/1 protocol, keymgmt copy and export substitution, six selections, legacy-arm reachability | no defect; one residual error-reason note (see below) |
| `src/ffc/backend.rs` | `ossl_ffc_params_fromdata`: named-group arm, BN/int/seed/flag/digest imports, error-label release order, set0 transfers | 1 contract defect (M57-D2) corrected; ownership contract reused |
| `src/ffc/key_generate.rs` | `ossl_ffc_generate_private_key`: N/s defaults, range check, `2^N`/`q` bound, rejection loop, caller-owned private key | 1 defect (M57-D3) repaired; BIGNUM contract reused |

**Deferred boundary.** `src/evp/method_store.rs` was not audited: it is the
method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary. It
remains in `REMAINING-AUDIT.txt` at the head of the queue. `ffc/key_generate.rs`
was substituted from the head of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M57-D1 | `src/evp/pbe.rs:156` (pre-fix cast at 151) | medium | `*mut` descriptor published from immutable storage | four scalars are `mut` parameters; descriptors use `addr_of_mut!` (no ABI change) |
| M57-D2 | `src/ffc/backend.rs:82` | low | `# Safety` admitted NULL for a pointer the body dereferences; digest strings borrowed but unstated | contract now requires non-NULL `ffc` and states the DIGEST/DIGEST_PROPS lifetime |
| M57-D3 | `src/ffc/key_generate.rs:87` (pre-fix `2 * s`) | low | signed strength doubling can overflow (debug panic; release wrap can hang the rejection loop) | `checked_mul(2)` with refusal before allocation (§17 divergence; callers bounded) |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0.
Hidden obligations: 0. No production unsafe operation, exported symbol,
signature, `#[repr(C)]` layout or allocator coordinate changed. M57-D1 removes
a mutable-pointer-from-`&T` capability inside an existing unsafe block; M57-D2
is documentation; M57-D3 is safe arithmetic plus one new unit test.

**Secret-bearing storage.** `pbe.rs` holds no internal secret: password/salt
are only pointed at by descriptors (the provider copies them into its own
`CRYPTO_clear_free`-owned buffers), and `key` remains the caller's. `p_dec.rs`
writes caller-owned plaintext; `p_enc.rs` reads caller-owned plaintext.
`p_lib.rs`/`pmeth_check.rs` borrow keydata without copying. `ffc/backend.rs`
handles public FFC parameters. `ffc/key_generate.rs` writes the private key
directly into the caller's BIGNUM, so cleansing remains the caller's obligation
(DH uses `BN_clear_free`; `dsa/key.rs` uses `BN_free`, the authority's own
ordering, noted as a follow-up outside this batch).

**Contracts reused.** OSSL_PARAM terminated-array and caller-owned output
contract; KDF input-parameter read-only convention; `EVP_PKEY_CTX`
provider/legacy `-1` fall-through contract; refcount set1 contract; FFC_PARAMS
`set0_pqg`/`set0_j` ownership plus err-label release order; B19 BIGNUM
secret-output convention; RC-1 seam and `#[repr(C)]` layouts untouched.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused tests
(ffc::backend 4, ffc::key_generate 3, evp::p_lib 1, evp::evp_pbe 5,
evp::p5_scrypt 2, evp::p5_crpt 6) **21 passed / 0 failed**.
BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1666 passed / 0 failed / 27 ignored** (1693 total) serial in 62.08 s and
with `--test-threads=4` in 94.83 s, in the court with `CARGO_BUILD_JOBS=4`.
No unexplained removal and no newly ignored test (M56: 1665 passed / 27
ignored; +1 is M57-D3's regression control).

**NOT_RUN.** Miri, ASan/valgrind, dudect/constant-time (no secret-dependent
branch introduced); a runtime control for M57-D1 (no in-tree provider writes
an input parameter) and for M57-D2 (documentation-only); authority
differential for the `pmeth_check.rs` NONE-branch error reason and the M57-D3
divergence; affected adversarial probes (`scripts/adv-probe.sh` has no probe
for these boundaries); FRF suite; dependency-graph regeneration; SEAL.

**Residual.** `pmeth_check.rs` raises `PMETH_CHECK_78`
(`OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`) at both the `EVP_PKEY_NONE` test
and the `not_supported` label, where the authority raises `NO_KEY_SET` at the
former. Both statements are in the legacy arm, unreachable here because
`try_provided_check` returns -1 only for a NULL `keymgmt` and no legacy context
can be built; no site constant was invented without the pinned authority
coordinates.

**Queue.** `REMAINING-AUDIT.txt` 265 -> **257**; `AUDITED-FILES.txt` 498 ->
**506**. **Next eight.** `src/evp/method_store.rs` (registry boundary —
defer again), `src/ffc/key_validate.rs`, `src/ffc/params_validate.rs`,
`src/http/http_lib.rs`, `src/idea.rs`, `src/mac/hmac.rs`,
`src/mac/poly1305.rs`, `src/mac/siphash.rs`.

---

## M58 — per-file contract sweep (FFC key/param validation, HTTP URL parser, IDEA, legacy HMAC, Poly1305, SipHash, TLS CBC MAC)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`cfe1798ec` (dirty worktree; no commit was made by the audit subagent).
Census identity is unchanged from the M57 receipt. The eight records below are
file-level obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/ffc/key_validate.rs` | SP800-56A partial/full public-key and private-key range checks; `ret` write-before-test protocol; `BN_CTX` lifetime and authority failure returns; NULL `params`/`pub_key` arms | no defect |
| `src/ffc/params_validate.rs` | FIPS 186-2/4 validators over a copied `FFC_PARAMS`; `simple_validate`'s zeroed destination, forced flags, `res` substitution and cleanup; `full_validate` seed/primality arms | no defect |
| `src/http/http_lib.rs` | `OSSL_parse_url` component scan and bounds, `OSSL_HTTP_parse_url` `OwnedStr` handoff/release lines, `use_proxy` bracket stripping, `OSSL_HTTP_adapt_proxy` borrowed return | no defect |
| `src/idea.rs` | 54-word `#[repr(C)]` schedule, key expansion/inversion, ECB/CBC/CFB64/OFB64, `num < 0` poison arm, wrapping 64-bit arithmetic | no defect |
| `src/mac/hmac.rs` | `HMAC_Init[_ex]` re-key/NULL-key protocol, `keytmp`/`pad` cleanse arms, `HMAC_Final` opad fold, `CTX_new/reset/copy/free`, OB-3 `CtxDestroy` body | no defect; OB-3 and cleanse contracts reused |
| `src/mac/poly1305.rs` | `#[repr(C)]` 248-byte context, u128 block arithmetic, partial-block carry, key load, `Final` cleanse of the whole context, layout size test | no defect |
| `src/mac/siphash.rs` | `Init`/`Update`/`Final`, zero-means-maximum sizes, `set_hash_size` v1 compensation, tail buffer, two output constructions | 1 contract defect (M58-D1) corrected |
| `src/mac/ssl3_cbc.rs` | constant-time TLS/SSLv3 record MAC over four digest contexts; `MdState` alignment, `num_starting_blocks`/variance loop bounds, length-byte construction, pad2 fold, `err` cleanup | 1 UB-risk hardening (M58-D2); no arithmetic defect |

**Deferred boundary.** `src/evp/method_store.rs` was not audited: it is the
method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It
remains in `REMAINING-AUDIT.txt` at the head of the queue. `src/mac/ssl3_cbc.rs`
was substituted from the head of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M58-D1 | `src/mac/siphash.rs:180`, `:204` | low | `# Safety` admitted a NULL `ctx` for two functions whose bodies dereference it | both contracts now require a live, non-NULL context; body unchanged (upstream `crypto/siphash/siphash.c` has no NULL test either) |
| M58-D2 | `src/mac/ssl3_cbc.rs:469` (pre-fix copy at `:465`) | low | `copy_nonoverlapping` with a NULL `mac_secret` and `mac_secret_length == 0` is UB under Rust's pointer rules (the authority's `memcpy(..., 0)` performs no access) | the copy is skipped when the secret is empty; the `# Safety` section now allows NULL only for the empty secret. No observable change. |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0.
Hidden obligations: 0. No exported symbol, signature, `#[repr(C)]` layout or
allocator coordinate changed. M58-D1 is documentation-only; M58-D2 wraps an
existing copy in an existing unsafe block in a zero-length guard. No unsafe
operation was added or removed.

**Secret-bearing storage.** `hmac.rs` is the only unit here that both holds
MAC-key material and cleanses it: `keytmp` (key or `H(key)` when the key is
longer than a block) and `pad` (the ipad/opad image) are cleansed on the
`goto err` arms and on the success path whenever `reset` is set -- exactly the
authority's `err:` cleanse. The four early returns that skip it in the
authority (`j > 144`, `j < 0`, a failed `j < len` digest, and
`len < 0 || len > 144`) skip it here too, and no secret is present in the
buffers on those arms because `keytmp` is written only by a successful
`EVP_DigestFinal_ex`. The keyed digest states live in `i_ctx`/`o_ctx`, whose
`EVP_MD_CTX_reset`/`free` run their own cleanses. `HMAC_Final`'s `buf` (the
inner digest) is not cleansed, matching the authority; it is classified as a
keyed intermediate, not a key. `poly1305.rs` cleanses the whole 248-byte
context on `Final` (multiplier, nonce, accumulator and tail). `ssl3_cbc.rs`
does **not** cleanse `hmac_pad` (the secret XOR pad constant, a directly
recoverable key copy) or the keyed `md_state`/`mac_out`/`first_block`/`block`
images; the authority does not either. Following the recorded
`provider/mac.rs` precedent (Poly1305's provider free is a bare free because
the authority's is), this batch classifies rather than diverges; adding the
cleanses is the first hardening candidate for a security batch. `siphash.rs`
has no cleanse in the authority (key mixed into `v0..v3` and `leavings`
persisting in the caller's context); cleansing belongs to the provider's free
path. `ffc/*` handles public parameters and caller-owned BIGNUMs; `http_lib.rs`
handles public URL/proxy text; `idea.rs` writes a key schedule that the
authority never cleanses and that this crate has no release path for.

**Contracts reused.** OB-2 `OwnedStr` adoption/release at authority
coordinates (`http_lib.rs`); OB-3 `OwnedCtx`/`CtxDestroy` with the zero-state
sweep (`hmac.rs`); the caller-owned BIGNUM private-key and FFC copy/cleanup
protocols (`ffc/*`); the authority's `# Safety`-documented pointer extents for
the digest dispatch and constant-time selection helpers (`ssl3_cbc.rs`); the
wrapping-arithmetic convention for `unsigned long` transcriptions (`idea.rs`).

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused tests
(ffc::key_validate 3, ffc::params_validate 6, idea::tests 2, mac::hmac 4,
mac::poly1305 3, mac::siphash 5, mac::ssl3_cbc 4) **27 passed / 0 failed**.
`http_lib.rs` has no unit test in-tree, so it has no focused count.
BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1666 passed / 0 failed / 27 ignored** (1693 total) serial in 272.50 s and
with `--test-threads=4` in 97.95 s, in the court with `CARGO_BUILD_JOBS=4`.
No unexplained removal and no newly ignored test.

**NOT_RUN.** Miri, ASan/valgrind, dudect/constant-time (the only `ssl3_cbc`
change is the zero-length guard; no constant-time claim is made from source
inspection); a runtime control for M58-D1 (documentation-only) and M58-D2 (no
in-tree caller yet; the focused tests all pass non-empty secrets); authority
differential for the pinned `ssl3_cbc` SSLv3 arm (no in-tree authority tree;
current upstream has removed `is_sslv3`, so only the TLS arm and the helper
serialisers were cross-checked); affected adversarial probes
(`scripts/adv-probe.sh` has no probe for these boundaries); FRF suite;
dependency-graph regeneration; negative controls for the secret-residue
classification; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `hmac.rs` forwards `impl` to `EVP_DigestInit_ex`; current upstream
3.6-dev adds an early `if (impl != NULL) return 0`, while the 3.0 source (and
the port's own doc) forwards it. The pinned 3.6.4 tree is not in this
checkout, so the version question is recorded rather than changed; forwarding
is memory-safe because `evp_md_init_internal` refuses a non-NULL `impl`
before any dereference, but a non-NULL `impl` mutates `ctx->md` before that
refusal, a compatibility difference if the pin has the early check.
(3) The `ssl3_cbc` secret residue noted above. (4) SipHash/Poly1305 provider
free paths are outside this batch and are where those contexts' cleansing is
recorded.

**Queue.** `REMAINING-AUDIT.txt` 257 -> **249**; `AUDITED-FILES.txt` 506 ->
**514**. **Next eight.** `src/evp/method_store.rs` (registry boundary —
defer again), `src/ml_dsa/hash.rs`, `src/ml_dsa/mod.rs`, `src/ml_dsa/ntt.rs`,
`src/ml_dsa/sample.rs`, `src/ml_dsa/sign.rs`, `src/ml_kem/key.rs`,
`src/ml_kem/mod.rs`.

---

## M59 — per-file contract sweep (ML-DSA core, ML-KEM key/verification core, CCM)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`fb4d7d3b7` (dirty worktree: the six `src/ml_kem/key.rs` repairs below; no
commit was made by the audit subagent). The eight records are file-level
obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/ml_dsa/hash.rs` | `shake_xof`/`_2`/`_3` short-circuit `&&` chains over `EVP_DigestInit_ex2`/`Update`/`Squeeze`; multi-part update order; zero-length updates; caller extents | no defect |
| `src/ml_dsa/mod.rs` | parameter table and `MlDsaParams` layout, `unsafe impl Sync` over a `'static` C-string pointer, `MlDsaKey`/`MlDsaSig` `#[repr(C)]` layouts, constant-time scalar helpers | no defect |
| `src/ml_dsa/ntt.rs` | Montgomery reduction, forward/inverse NTT index bounds, `matrix_as_slice`/vector slice extents, in-place accumulation, `product` cleanse | no defect |
| `src/ml_dsa/sample.rs` | rejection samplers and nibble/three-byte coefficient bounds, `derived_seed` construction and cleanse arms, public `A` material classification, mask/challenge buffer cleanse | no defect |
| `src/ml_dsa/sign.rs` | `OwnedBuf` scratch ownership/release arm, `mu` init/update/finalize, sign/verify drivers, temporary pointer partitioning, stack-secret cleanse paths | no defect |
| `src/ml_kem/key.rs` | `OwnedBuf` plain/secure/cleansed release arms, `add_storage` member layout, key new/dup/reset/free, parse/encode/genkey/encap/decap, secret-buffer cleanse paths | 6 defects (M59-D1..D6) repaired |
| `src/ml_kem/mod.rs` | `*Alloc` layout `offset_of!` assertions, `VinfoMap` `Sync`, vinfo accessors, size formulas | no defect |
| `src/modes/ccm.rs` | `CRYPTO_ccm128_*` state machine, B0 length reconstruction, AAD length encodings, `blocks` budget, counter helpers, block/stream callbacks, length refusals | no memory-safety defect; secret residue classified |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It stays
at the head of `REMAINING-AUDIT.txt`. `src/modes/ccm.rs` was substituted from
the head of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M59-D1 | `src/ml_kem/key.rs:682` (pre-fix doc at `:679`) | low | `# Safety` admitted NULL for `ossl_ml_kem_key_reset`, whose body dereferences `key`; the authority has no NULL test | contract now requires a live, non-NULL key and states that NULL is a caller violation, not a refusal. No code change. |
| M59-D2 | `src/ml_kem/key.rs:1048` (pre-fix alloc at `:1044`) | medium | `ossl_ml_kem_parse_public_key` allocated `EVP_MD_CTX` before the length check, leaking it whenever `len != pubkey_bytes`; the authority's short-circuiting `||` never allocates on that arm | length is checked first; the context is allocated only on the accepting arm. Observable return unchanged. |
| M59-D3 | `src/ml_kem/key.rs:1094` (pre-fix alloc at `:1086`) | medium | same leak in `ossl_ml_kem_parse_private_key` on `len != prvkey_bytes` | same ordering repair. |
| M59-D4 | `src/ml_kem/key.rs:1219` (pre-fix alloc at `:1201`) | medium | `ossl_ml_kem_encap_seed` allocated `EVP_MD_CTX` before validating `ctext`/`clen`/`shared_secret`/`slen`/`entropy`/`elen`, leaking it on every rejected argument | arguments are validated first, then the context is allocated, matching the authority's short-circuit order. |
| M59-D5 | `src/ml_kem/key.rs:1326` (pre-fix alloc at `:1302`) | medium | `ossl_ml_kem_decap` allocated `EVP_MD_CTX` before the length/ciphertext checks; an invalid argument returned after the RNG fallback with the context still live | the context is created only on the accepting arm; the RNG fallback still runs both for a rejected argument and for an allocation failure, as the authority's single condition does. |
| M59-D6 | `src/ml_kem/key.rs:1149`, `:1162`, `:1169` (pre-fix early returns at `:1137`, `:1141`, `:1151`) | medium | `ossl_ml_kem_genkey` returned on `encode_seed` failure, `RAND_priv_bytes_ex` failure and `EVP_MD_CTX_new` failure without cleansing the 64-byte `seed`; the last arm leaves a fully generated private seed on the stack | each early return now cleanses `seed` (§5 failure-path cleansing, a deliberate divergence from the authority, which has the same residue). No observable behaviour change. |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0.
Hidden obligations: 0. No exported symbol, signature, `#[repr(C)]` layout or
allocator coordinate changed. No unsafe operation was added or removed; the
repairs sit inside existing unsafe bodies. `src/ml_kem/key.rs` additionally now
states the liveness contract for `ossl_ml_kem_encap_seed`, `ossl_ml_kem_decap`
and `ossl_ml_kem_pubkey_cmp` (documentation only).

**Secret-bearing storage.** ML-DSA sign: `rho_prime` (masking seed), `c_tilde`
and the caller-side `mu` are cleansed on the success and failure paths; the
scratch blob (`w1_encoded`, `c_ntt`, NTT vectors) is released through
`CRYPTO_clear_free` in the signing driver and through the plain authority free
in the verifying driver (the verify temporaries are public signature data).
ML-DSA sampling: `derived_seed` in `ossl_ml_dsa_vector_expand_S` and the
`rej_bounded_poly` block buffer are cleansed on both arms; the expand-mask
buffer is always cleansed; the public matrix `A` seed/blocks are deliberately
not cleansed (FIPS 204 §3.6.3, as the authority comments). The NTT accumulator
`product` is cleansed. ML-KEM: `seed` (genkey) is cleansed on success,
`add_storage` failure, and now on the three early failures; `augmented_seed` and
`hashed` are cleansed in `genkey`; `input`/`Kr`/`r` are cleansed in
encapsulation; `decrypted`/`Kr`/`failure_key` are cleansed on every decapsulation
arm; `s`/`z`/`d` and `seedbuf` are released through
`CRYPTO_secure_clear_free`, while the public `t` block uses `CRYPTO_free`.
CCM cleanses nothing: `cmac`/`nonce` persist in the caller's context and the
authority has no cleanse arm there; classed as a keyed intermediate residue
(not a key schedule) and recorded, not diverged.

**Contracts reused.** Authority allocation boundaries and release arms through
the `CRYPTO_*` seam (`OwnedBuf` in sign/key); the `Vector`/`Matrix`
`(ptr,len)` member-extent model and `#[repr(C)]` layout assertions; CCM's
caller-supplied block/stream callback and context-ownership contract; FIPS
203/204 pointer-extent and length-refusal contracts. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused tests
`ml_kem` **8 passed / 0 failed**, `ml_dsa` **14 passed / 0 failed**,
`modes::ccm` **4 passed / 0 failed**. BATCH: `cargo clippy --all-targets -- -D
warnings` clean; full library **1666 passed / 0 failed / 27 ignored** (1693
total) serial in 216.08 s and with `--test-threads=4` in 96.71 s, in the court
with `CARGO_BUILD_JOBS=4`. Matches the M58 baseline exactly: no unexplained
removal and no newly ignored test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; `scripts/adv-probe.sh` has no probe for
ML-DSA, ML-KEM or CCM (affected probes NOT_RUN); dudect/ctgrind/constant-time
(no constant-time claim is made for any file in this batch from source
inspection); FRF suite; pinned-authority differential beyond the 3.6.4 source
comparison performed for `ml_kem.c` and `ccm128.c`; dependency-graph
regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `MlKemKey::rho_pkhash` is not initialised by `key_new`; the authority also
leaves it untouched after `OPENSSL_malloc`, and `add_storage` zeroes it when
`dup == 0`, so no path reads it uninitialised. (3) `poly.rs`
`Vector::as_slice`/`matrix_as_slice` would form a slice from NULL when the
count is zero; every reachable constructor uses a positive rank and `poly.rs`
is outside this batch — hardening candidate, no reachable path. (4) The ML-DSA
scratch-size arithmetic in `sign.rs` uses unchecked products/additions, but
`k`/`l`/`gamma2` come from the immutable parameter table; checked arithmetic is
a hardening candidate. (5) CCM's keyed intermediate residue is recorded above.
(6) No constant-time claim is made for ML-DSA, ML-KEM or CCM.

**Queue.** `REMAINING-AUDIT.txt` 249 -> **241**; `AUDITED-FILES.txt` 514 ->
**522**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/modes/gcm.rs`, `src/modes/mod.rs`, `src/modes/ocb.rs`,
`src/modes/siv128.rs`, `src/modes/wrap.rs`, `src/modes/xts.rs`,
`src/ocsp/ocsp_cl.rs`.

## M60 — per-file contract sweep (GCM, non-AEAD mode helpers, OCB, AES-SIV, key wrap, XTS, OCSP client/HTTP)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`b12ba246b` (dirty worktree: the seven repairs below; no commit was made by the
audit subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/modes/gcm.rs` | `GCM128_CONTEXT` layout/alignment, `H`/`Xi` half-word accessors, `GcmRawCtx`→`GcmCtxOwner` initialisation transition, cleansing release at the authority coordinate, nonce/AAD/message length accounting, `num`-style partial-block continuity, `CRYPTO_memcmp` tag answer | no defect |
| `src/modes/mod.rs` | CBC enc/dec (in-place and out-of-place), OFB, CFB-128/-8/-1, `cfbr_encrypt_block`'s `ovec` slack byte, CTR/CTR-32 counter increments, all four CTS families' straddling copies and return lengths | 2 defects (M60-D1) repaired |
| `src/modes/ocb.rs` | `OcbCtx` layout, `CtxDestroy` body (L-table release + whole-context cleanse), `ocb_lookup_l` growth, `copy_ctx` identity case, setiv stretch indexing, AAD/data full-block and partial-block arms, stream callback contract, tag compare | 1 defect (M60-D2) repaired |
| `src/modes/siv128.rs` | `SIV_BLOCK` union views, S2V duplicate/free arms, zeroed-context requirement, `cipher_ctx`/`mac`/`mac_ctx_init` ownership across init/copy/cleanup, tag compare, failure cleanse | no defect |
| `src/modes/wrap.rs` | RFC 3394/5649 wrap/unwrap, `memmove` overlap arms, range tests before arithmetic, IV/AIV compare, failure-path `OPENSSL_cleanse(out, inlen)` | 3 defects (M60-D3..D5) repaired |
| `src/modes/xts.rs` | caller-populated `#[repr(C)]` context, tweak doubling (LE arm), ciphertext stealing forward/backward, `len < 16` refusal, unaligned `u64_a1` loads, GB variant | no defect |
| `src/ocsp/ocsp_cl.rs` | response accessors, `OCSP_resp_find` scan bounds, single/response status out-pointers, validity time arithmetic, request builder ownership (add0_id, set1_name, add1_cert, sign), responder-id selectors | 2 defects (M60-D6..D7) repaired |
| `src/ocsp/ocsp_http.rs` | HTTP request-context configuration, every failure arm frees the context, exchange + `ASN1_item_d2i_bio` NULL-BIO arm | no defect |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It stays
at the head of `REMAINING-AUDIT.txt`. `src/ocsp/ocsp_http.rs` was substituted
from the head of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M60-D1 | `src/modes/mod.rs:118`, `:139` | medium | `ctr128_inc`/`ctr96_inc` were safe `fn`s that dereferenced a caller-supplied raw pointer: safe Rust could pass NULL and cause UB (unsafe-safe-Rust API) | both are now `unsafe fn` with a `# Safety` contract; the four in-file call sites carry SAFETY comments. No code or ABI change. |
| M60-D2 | `src/modes/ocb.rs:557`, `:674` | medium | the partial-block arms formed `from_raw_parts(inp, last_len)` and `from_raw_parts_mut(outp, last_len)` over the same range when `in == out`, which EVP's block update may pass — overlapping `&`/`&mut` is UB | the input tail is copied to a local before `out` is mutably borrowed; the authority's byte result is preserved for the non-overlapping case and correctness is restored for in-place (see residual 4). New in-place regression test. |
| M60-D3 | `src/modes/wrap.rs:110` | low | `crypto_128_unwrap_raw` evaluated `inlen - 8` before the range test; a caller-supplied `inlen < 8` panicked in a debug build (abort across the C ABI) where the authority answers 0 | `checked_sub(8)` with a false answer; observable release behaviour unchanged. |
| M60-D4 | `src/modes/wrap.rs:203` | low | `CRYPTO_128_wrap_pad` computed `div_ceil(8) * 8` before the `inlen == 0`/`max` test; a huge caller length overflowed in a debug build | the authority's range test now runs before the ceiling arithmetic. |
| M60-D5 | `src/modes/wrap.rs:260` | low | `CRYPTO_128_unwrap_pad` evaluated `inlen / 8 - 1` before the range test; `inlen < 8` underflowed in a debug build | the range test now precedes the block count. |
| M60-D6 | `src/ocsp/ocsp_cl.rs:550` | medium | `OCSP_request_sign`'s key-mismatch arm returned with the freshly created `OCSP_SIGNATURE` still installed: leak plus a half-built request, whereas the authority's `goto err` frees it and clears the pointer | free and null on that arm, matching the authority's error path. |
| M60-D7 | `src/ocsp/ocsp_cl.rs:243` | low | `OCSP_resp_find` computed `last + 1`; `last == INT_MAX` overflowed in a debug build (abort) where the authority's undefined addition effectively wraps | `saturating_add(1)`: an empty scan and `-1`, the same answer the release build produced. New regression test. |

**Unsafe accounting.** Eliminated: the two safe raw-pointer helpers can no longer
be called from safe Rust with an invalid pointer (M60-D1). Relocated: 0. New
assumptions: 0. Hidden obligations: 0. No exported symbol, signature,
`#[repr(C)]` layout or allocator coordinate changed. The repairs sit inside
existing unsafe bodies or replace an overlapping reference pair with a local
copy; no unsafe operation was added or removed.

**Secret-bearing storage.** GCM: the context carries `H`, the keystream `eki`,
the tag mask `ek0`, the GHASH accumulator and the pending AAD/message bytes; the
single release is `CRYPTO_clear_free(ctx, sizeof(GcmCtx))` in
`GcmCtxOwner::drop`, so the whole context is cleansed on the normal release. The
`CRYPTO_gcm128_new` allocation-failure path frees the not-yet-initialised block
with plain `CRYPTO_free` (nothing secret has been written). OCB: `destroy_body`
releases the L table with `CRYPTO_clear_free` and cleanses the whole `OcbCtx`
(`offset`, `offset_aad`, `sum`, `checksum`, `l_star`, `l_dollar`) on cleanup;
the key schedules and block/stream callbacks are caller-owned and never copied.
AES-SIV: `ossl_siv128_cleanup` cleanses `d` and `tag`; the CMAC and cipher
state lives in their own contexts and is released by their destructors.
RFC 5649 unwrap cleanses `out` (unwrapped key material) on every refusal arm;
RFC 3394 unwrap cleanses `out` on IV mismatch. XTS carries no long-lived
secret: the tweak and `scratch` are IV/ciphertext-derived and the key schedules
remain the caller's. OCSP: none of these functions copies a secret; the private
key is handled as an `EVP_PKEY` handle and the signature/ASN.1 payloads are
public data. Per the authority, the wrap/OCB/SIV local keyed intermediates are
not cleansed (residual 5); no constant-time claim is made for any file here
from source inspection.

**Contracts reused.** The validated-initialisation owner transition and single
cleansing release (`GcmRawCtx`→`GcmCtxOwner`); `RawCtx`/`CtxDestroy` member
release plus whole-context cleanse for OCB and SIV (the enclosing block is never
released by `destroy_body`); the OCB L-table member extent (`max_l_index * 16`,
with `l_index + 1` entries populated); the caller-populated `#[repr(C)]` XTS
context; the C ABI caller contracts for `in`/`out`/`iv`/`key` extents and
in-place operation; and the `CRYPTO_*` allocator seam at the authority's
translation-unit coordinates. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; `cargo check
--lib` clean; focused `modes::` **25 passed / 0 failed** (including the two new
regression tests) and `ocsp::` **1 passed / 0 failed**; name-filtered `wrap`
**19 passed / 0 failed**. BATCH: `cargo clippy --all-targets -- -D warnings`
clean; full library **1669 passed / 0 failed / 27 ignored** (1696 total) serial
in 246.82 s and with `--test-threads=4` in 85.30 s, in the court with
`CARGO_BUILD_JOBS=4`. That is the M59 baseline plus the three new tests: no
unexplained removal and no newly ignored test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; `scripts/adv-probe.sh` has no probe for
the modes or OCSP families (affected adversarial probes NOT_RUN); dudect/ctgrind
(no constant-time claim is made); FRF suite; pinned-authority differential
beyond the 3.6.4 source comparison of `gcm128.c`, `ctr128.c`, `cfb128.c`,
`cts128.c`, `ocb128.c`, `siv128.c`, `wrap128.c`, `xts128.c` and `ocsp_cl.c`;
dependency-graph regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `OCSP_request_sign`'s `set1_name`-failure arm returns without freeing a
pre-existing `optionalSignature`, whereas the authority's `goto err` frees it
and clears the pointer; the Rust arm is the safer one and is only reachable on
an allocation failure, but it is a recorded divergence. (3) `OCSP_check_validity`
still evaluates `t_now ± nsec/maxsec` without checked arithmetic; `nsec` and
`maxsec` are caller configuration rather than network data and the authority's
signed overflow is undefined. Hardening candidate. (4) The in-place OCB
partial-block tag now checksums the original plaintext; the authority's C reads
`in` after writing `out`, so an exactly-overlapping caller would checksum
ciphertext and produce a different tag. The safe result is retained and pinned
by the new test; non-overlapping behaviour is identical. (5) `wrap.rs`'s `a`/`b`
intermediates, OCB's `pad`/`tail` and SIV's local `t`/`q` are not cleansed, as
the authority also leaves them; they are keyed intermediates, not key stores.
(6) No constant-time claim is made for GCM, OCB, SIV, wrap or XTS.

**Queue.** `REMAINING-AUDIT.txt` 241 -> **233**; `AUDITED-FILES.txt` 522 ->
**530**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/ocsp/ocsp_lib.rs`, `src/ocsp/ocsp_prn.rs`, `src/ocsp/ocsp_srv.rs`,
`src/ocsp/v3_ocsp.rs`, `src/param_build_set.rs`, `src/params/dup.rs`,
`src/params/from_text.rs`.


## M61 — per-file contract sweep (OCSP lib/prn/srv/v3, param_build_set, params dup/from_text, PEM other)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`954ab90d0` (dirty worktree: the repairs below; no commit was made by the audit
subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/ocsp/ocsp_lib.rs` | `OCSP_CERTID` builder (algorithm install, issuer-name/key digests, serial copy), every failure arm, the two id comparators, the ASN.1 duplicate | 2 contract defects (M61-D1) repaired |
| `src/ocsp/ocsp_prn.rs` | status/cert/reason tables, `ocsp_certid_print`, request and response transcripts, per-entry stack walks, optional signature block | no defect |
| `src/ocsp/ocsp_srv.rs` | request accessors, `OCSP_id_get0_info`, response create/pack, `add1_status` ownership and choice arms, add-cert, sign/sign_ctx, RESPID setters and matchers, SHA-1 fetch/release | no defect |
| `src/ocsp/v3_ocsp.rs` | five extension rows, ten static callbacks, nonce raw `i2d`/`d2i` with the owning slot, serviceloc stack walk | no defect |
| `src/param_build_set.rs` | the seven builder-or-in-place writes, `bn_pad` size probe and range refusal, multi-key name/stack walk | no defect |
| `src/params/dup.rs` | single-block duplicate with secure-block terminator, block arithmetic, `_PTR` value copy, shallow case-insensitive merge, free walk | 1 contract defect (M61-D2) and the allocator seam (M61-D5) repaired |
| `src/params/from_text.rs` | hex-prefix key rewrite, integer two's-complement halves, size probe, UTF8/OCTET writes, print-to-bio walk | 2 contract defects (M61-D3..D4) and the allocator seam (M61-D5) repaired |
| `src/pem/pem_oth.rs` | `PEM_bytes_read_bio` result ownership, `DataBuf` single release, `d2i` cursor, ASN.1 refusal reason | no defect |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It stays
at the head of `REMAINING-AUDIT.txt`. `src/pem/pem_oth.rs` was substituted from
the head of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M61-D1 | `src/ocsp/ocsp_lib.rs:93`, `:126` | low | the `# Safety` contracts allowed NULL for `issuer`, `issuerName` and `issuerKey`, all of which the bodies dereference (the key bit-string unconditionally); a caller following the documented contract could pass NULL and cause UB | contracts now require `issuer` to be live with a public-key bit string and `issuerName`/`issuerKey` to be live; `serialNumber`/`subject`/`dgst` remain the only NULL-allowed arguments. No code or ABI change. |
| M61-D2 | `src/params/dup.rs:299` | low | `ossl_param_dup`'s contract required only `data_size` readable bytes, but `OSSL_PARAM_OCTET_PTR`/`OSSL_PARAM_UTF8_PTR` entries read one full pointer from `data` regardless of `data_size` | the contract now states the `_PTR` arm's alignment and one-pointer readability. No code change. |
| M61-D3 | `src/params/from_text.rs:62` | low | `has_hex_prefix`'s contract said `s` may be NULL while the body dereferences it immediately | contract now requires non-NULL and NUL-terminated. No code change. |
| M61-D4 | `src/params/from_text.rs:309` | low | `OSSL_PARAM_allocate_from_text`'s contract omitted that the non-hex octet-string arm reads `value_n` bytes, not just a NUL-terminated string | contract now states the `value_n` readability requirement. No code change. |
| M61-D5 | `src/params/dup.rs:50`, `:53-57`; `src/params/from_text.rs:50`, `:53-54` | low | both allocator seams used the bare translation-unit path and line `0`, while the authority's plain `.c` `__FILE__` carries the source-tree prefix and each allocation/release has its own line; the strings are observable to a caller-installed `CRYPTO_set_mem_functions` hook | `FILE` now carries the admitted build's `../../src/openssl-3.6.4/...` spelling and each seam call uses its authority line: dup alloc `:46`, failed-duplicate free `:133`, merge alloc `:191`, secure free `:240`, array free `:241`; from_text alloc `:325`, failure free `:332`. `OwnedParamBlock` carries the release line and `OwnedBuf::new_zeroed_released` separates the two from_text coordinates. |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0.
Hidden obligations: 0 (the four repaired contracts were the only ones that
admitted an argument the body dereferenced). No exported symbol, signature,
`#[repr(C)]` layout or excluded symbol changed. The two seam repairs change only
the `file`/`line` metadata a `CRYPTO_set_mem_functions` hook observes.

**Secret-bearing storage.** OCSP copies no secret: the private key stays an
`EVP_PKEY` handle and the signed payloads are public. `from_text`'s temporary
`BIGNUM` and value buffer can carry parameter material (including private-key
components); the authority releases them with plain `BN_free`/`OPENSSL_free`
and the conversion preserves that (residual 2). `dup` preserves the secure
block's cleansing `CRYPTO_secure_clear_free` and the public array's plain
`CRYPTO_free`, exactly as the authority; values that came from the secure heap
are cleansed through the terminator block. `pem_oth` frees the DER block with
the authority's plain `CRYPTO_free`. No constant-time claim is made for any file
here from source inspection.

**Contracts reused.** `OB-1` `OwnedBuf` (including the split allocation/release
coordinates); `OB-4` secure-block terminator (`OSSL_PARAM_ALLOCATED_END` == 127,
size carried as the secure block's); the C ABI caller contracts for NULL-or-live
optional pointers and caller-sized buffers; BIGNUM ownership through
`BN_asc2bn`/`BN_hex2bn` -> `BN_free`; ASN.1 item ownership (`*_new`/`*_free`);
and the `CRYPTO_*` allocator seam at the authority's `FILE`/`LINE`. No new model
was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; `cargo check
--lib` clean; focused `params` **53 passed / 0 failed**, `ocsp` **1 / 0**,
`pem` **19 / 0**, `rsa::backend` **4 / 0**; `cargo clippy --all-targets -- -D
warnings` clean. BATCH: full library **1669 passed / 0 failed / 27 ignored**
(1696 total) serial in 268.56 s and with `--test-threads=4` in 97.51 s, in the
court with `CARGO_BUILD_JOBS=4`, after the seam repair. No unexplained removal
and no newly ignored test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; `scripts/adv-probe.sh` has no probe for
the params, OCSP or PEM-other families (affected adversarial probes NOT_RUN);
an allocator-coordinate differential over `OSSL_PARAM_dup`/`_merge`/
`allocate_from_text` (no harness observes the file/line strings for these
units) NOT_RUN; dudect/ctgrind (no constant-time claim is made); FRF suite;
dependency-graph regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `OSSL_PARAM_allocate_from_text`'s failure path frees a buffer that
`OPENSSL_hexstr2buf_ex` may have partially filled with parameter text, using the
authority's plain free; switching it to a cleansing release would be a recorded
deliberate improvement and is a hardening candidate. (3) The same function's
`q.data_size * 8` range test can overflow on a hostile descriptor: a debug build
panics (caught by `guard_ffi`) where the release build wraps; the authority has
the same wrap, so this is a hardening candidate, not a reachable memory-safety
defect. (4) `OSSL_PARAM_print_to_bio` does not free the `BIGNUM` that
`OSSL_PARAM_get_BN` allocates for a wide integer, matching the authority's own
leak; recorded rather than silently fixed. (5) The OCSP printers and builders
retain the authority's unconditional dereference of mandatory decoded members
(`certStatus`, `thisUpdate`, `requestList` entries), which a successful ASN.1
decode establishes. (6) No constant-time claim is made for the OCSP or PEM
units.

**Queue.** `REMAINING-AUDIT.txt` 233 -> **225**; `AUDITED-FILES.txt` 530 ->
**538**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/pem/pem_x509.rs`, `src/pem/pem_xaux.rs`, `src/pkcs12/p12_add.rs`,
`src/pkcs12/p12_asn.rs`, `src/pkcs12/p12_attr.rs`, `src/pkcs12/p12_crpt.rs`,
`src/pkcs12/p12_decr.rs`.

## M62 — per-file contract sweep (PEM X509 pairs, PKCS#12 ASN.1, attributes, PBE key/IV, buffer crypt, init)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`6749fc638` (dirty worktree: the repairs below; no commit was made by the audit
subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results. The authority sources were read from
`forensics/authorities/src/openssl-3.6.4/`.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/pem/pem_x509.rs` | the two `(d2i/i2d_of_void)` shims, four `IMPLEMENT_PEM_rw` expansions, header constants, result ownership | no defect |
| `src/pem/pem_xaux.rs` | the `X509_AUX` shims and four expansions, `PEM_STRING_X509_TRUSTED`, result ownership | no defect |
| `src/pkcs12/p12_add.rs` | `PKCS12_item_pack_safebag` union out-slot, two `PKCS12_decrypt_skey` spellings, `PKCS7` type guards, pack/unpack `p7data`/`p7encdata`/`authsafes`, fetched-cipher release | 1 defect (M62-D6) repaired |
| `src/pkcs12/p12_asn.rs` | four item descriptors, two ADB tables, `SyncAdb`, the `PKCS12_free` `propq` member slot, `d2i`/`i2d` codecs | 1 seam-coordinate defect (M62-D8) repaired |
| `src/pkcs12/p12_attr.rs` | ten thin add/read helpers, `set0_attrs` shallow release, `friendlyname` BMP decode | 1 contract defect (M62-D7) repaired |
| `src/pkcs12/p12_crpt.rs` | private `PBEPARAM` descriptor, `PKCS12_PBE_keyivgen_ex` key/IV derivation, both failure arms, cipher init, stack cleansing | 2 defects (M62-D4, M62-D5) repaired |
| `src/pkcs12/p12_decr.rs` | `PKCS12_pbe_crypt_ex` allocation/length/failure arms, MAC-carrying arm, four item decrypt/encrypt spellings, `OwnedBuf` adoption coordinates | 3 defects (M62-D1, M62-D2, M62-D3) repaired |
| `src/pkcs12/p12_init.rs` | `PKCS12_init_ex` failure ladder, `version`/`authsafes` slots, `_get0_pkcs7ctx` borrow | no defect |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It stays
at the head of `REMAINING-AUDIT.txt`. `src/pkcs12/p12_init.rs` was substituted
from position 9 of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M62-D1 | `src/pkcs12/p12_decr.rs:134`, `:161` | low | `max_out_len = inlen + block_size` and `max_out_len += mac_len` were unchecked `c_int` sums sizing the output allocation; an overflow or a negative sum could size the block below the bytes `EVP_CipherUpdate` writes (authority wraps; §17 forbids reproducing it) | both sums now use `checked_add` with a non-negative filter and refuse (free the context, answer NULL) before allocating. |
| M62-D2 | `src/pkcs12/p12_decr.rs:55`, `:228`, `:260` | low | allocator seam used the short `crypto/...` spelling and the authority's `OPENSSL_free(out)` lines were reported as `92` and `105`, but the admitted build's `__FILE__` is `../../src/openssl-3.6.4/...` and the frees are at `p12_decr.c:93` and `:108`; observable through `CRYPTO_set_mem_functions` | `FILE` now carries the admitted spelling; the two failure releases use `:93` and `:108`. The `:85`, `:171`, `:211`, `:216` coordinates already matched and are unchanged. |
| M62-D3 | `src/pkcs12/p12_decr.rs:209`, `:226`, `:258`, `:484` | medium | on every PBE failure after `EVP_CipherUpdate` the authority frees the output block without cleansing even though the decrypt arm's prefix is plaintext; `PKCS12_item_i2d_encrypt_ex` likewise frees the encoded plaintext without cleansing when `zbuf != 0` and the crypt fails | `OPENSSL_cleanse` of the full allocation (or `inlen`) runs before each plain release. Deliberate failure-path improvement over `p12_decr.c:85/93/108/211`; no release coordinate changed. |
| M62-D4 | `src/pkcs12/p12_crpt.rs:185` | low | `key`/`iv` are `EVP_MAX_KEY_LENGTH`/`EVP_MAX_IV_LENGTH` stack arrays filled with `EVP_CIPHER_get_key_length`/`_iv_length` bytes; a cipher advertising more overruns them in the authority (reachable only with a caller-supplied cipher whose lengths exceed the built-in PBE table), so the documented contract hid a precondition | lengths are read once and a cipher with `klen > 64` or `ivlen > 16` is refused after the parameter is decoded and freed, before deriving. No raise is invented. |
| M62-D5 | `src/pkcs12/p12_crpt.rs:213`, `:247` | medium | both derivation-failure returns left the secret `key` (and `iv`) uncleansed on the stack; the authority does the same | both failure arms cleanse both fixed arrays before returning; the success path keeps the authority's two cleanses. |
| M62-D6 | `src/pkcs12/p12_add.rs:299` | low | `PKCS12_unpack_p7encdata` checked `d.encrypted` for NULL and then dereferenced `enc_data`; a live `PKCS7` with a NULL content object satisfied the documented contract and would fault (the authority has the same gap) | a NULL `enc_data` is refused at the existing decode-error coordinate `PKCS12_ADD_162` (`PKCS12_R_DECODE_ERROR`); no new error site. |
| M62-D7 | `src/pkcs12/p12_attr.rs:76`, `:117`, `:142`, `:166`, `:190`, `:254` | low | the five add helpers documented `name` as readable for `namelen` bytes, but `namelen == -1` makes `ASN1_STRING_set_by_NID` measure the string, so the contract permitted a non-NUL-terminated buffer; `PKCS12_get_friendlyname` likewise did not state the `V_ASN1_BMPSTRING` value's validity | contracts now state the NUL-termination requirement for `namelen == -1` and the well-formed-attribute precondition. No code or ABI change. |
| M62-D8 | `src/pkcs12/p12_asn.rs:638` | low | the `PKCS12_free` `propq` member-slot seam reported the short `crypto/...` spelling rather than the admitted build's `__FILE__` | `FILE` now carries `../../src/openssl-3.6.4/crypto/pkcs12/p12_asn.c`; the release line `35` already matched. |

**Unsafe accounting.** Eliminated: 0. Relocated: 0. New assumptions: 0 (the
four repaired arguments/coordinates were the only ones that admitted an input
the body would dereference wrongly). Hidden obligations: 0. No exported
symbol, signature, `#[repr(C)]` layout or excluded symbol changed. The seam
repairs change only `file`/`line` strings a `CRYPTO_set_mem_functions` hook
observes.

**Secret-bearing storage.** PKCS#12 passwords, derived keys and the DER
encodings of private-key bags are `SECRET_DATA`; the PBE salt/iteration count,
the algorithm identifiers and the ciphertext are `PUBLIC_DATA`. Cleansed paths:
`p12_crpt` derives into fixed stack arrays and cleanses both on the success
tail (authority behaviour) and now on both failure returns (M62-D5);
`p12_decr`'s output block holds plaintext on the decrypt arm and is now
cleansed before each failure release (M62-D3); `PKCS12_item_decrypt_d2i_ex`
cleanses its decrypted buffer when `zbuf` is set (authority) and
`PKCS12_item_i2d_encrypt_ex` does the same on success and now also on a failed
crypt (M62-D3). The converted password lives in `p12_key`'s `OwnedBuf` with a
cleansing release; this batch does not alter it. `p12_attr`/`p12_asn`/`p12_add`
copy no password or key plaintext: they manipulate borrowed ASN.1 objects, and
the `SafeBag`/`PKCS7` layers release through the item layer. No constant-time
claim is made for any file here from source inspection.

**Contracts reused.** `OB-1` `OwnedBuf` (adopt/adopt_plain at the authority's
allocation and release coordinates); `OB-4` member-buffer slot
(`PropqSlot::clear` for `p7->ctx.propq`); the ASN.1 item ownership contracts
for the four PKCS#12 groups and `PBEPARAM`; the C ABI contracts for
NULL-or-live optional pointers and caller-sized buffers; the `EVP_PBE` key/IV
generator callback contract; and the `CRYPTO_*` allocator seam at the
authority's exact `FILE`/`LINE`. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; `cargo check
--lib` clean; focused `pkcs12` **20 passed / 0 failed / 1 ignored** (the
`p12_key` allocator probe) and `pem` **19 / 0**. BATCH: `cargo clippy
--all-targets -- -D warnings` clean; full library **1669 passed / 0 failed /
27 ignored** (1696 total) serial in 63.59 s and with `--test-threads=4` in
265.50 s, in the court with `CARGO_BUILD_JOBS=4`. Affected probe
`pkcs12::p12_key::adv_probe::unipass_drop_cleanses_before_release` **1 / 0**
with `OPENSSL_RS_ADV_PROBE=1`. No unexplained removal and no newly ignored
test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; a targeted allocator-hook control for
the p12 seam coordinates (no harness observes `CRYPTO_*` file/line strings for
these units) NOT_RUN; a synthetic-cipher control for the M62-D4 refusal (the
crate has no public way to build an `EVP_CIPHER` with `key_len > 64`; the
built-in PBE table cannot reach it) NOT_RUN; a checked-overflow control for
M62-D1 (needs `inlen` near `INT_MAX`) NOT_RUN; dudect/ctgrind (no constant-time
claim); FRF suite; dependency-graph regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `PKCS12_item_decrypt_d2i_ex` still frees a decrypted plaintext without
cleansing when the caller passes `zbuf == 0`; that is the authority's
contractual choice and is preserved. (3) `PKCS12_pbe_crypt_ex`'s plaintext is
handed to the caller without a length-attached cleansing release; that is the
exported ABI contract (the caller owns the buffer), not a hidden obligation.
(4) The `p12_add` pack paths trust the item layer's union invariants
(`PKCS7_set_type` establishes `d.encrypted`); the added NULL test covers the
one content pointer a C caller can tamper with. (5) The PKCS#12 KDF and the
provider `PKCS12KDF` row are outside this batch. (6) No constant-time claim is
made for the PKCS#12 units.

**Queue.** `REMAINING-AUDIT.txt` 225 -> **217**; `AUDITED-FILES.txt` 538 ->
**546**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/pkcs12/p12_key.rs`, `src/pkcs12/p12_mutl.rs`,
`src/pkcs12/p12_npas.rs`, `src/pkcs12/p12_p8d.rs`, `src/pkcs12/p12_p8e.rs`,
`src/pkcs12/p12_utl.rs`, `src/pkcs7/bio_pk7.rs`.

## M63 — per-file contract sweep (PKCS#12 key/MAC/newpass, PKCS7 attribute helpers and BIO)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`6f128a871` (dirty worktree: the repairs below; no commit was made by the audit
subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results. The authority sources were read from
`forensics/authorities/src/openssl-3.6.4/` and confirmed byte-identical to the
pinned 3.6.4 tag for the units compared.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/pkcs12/p12_key.rs` | four `PKCS12_key_gen_asc/utf8` spellings over `OwnedBuf` (cleansed adoption), `PKCS12_key_gen_uni_ex` KDF fetch/params/derive, length and NULL arms, five PBE parameters | no defect |
| `src/pkcs12/p12_mutl.rs` | `PKCS12_mac_present`/`_get0_mac`, `pkcs12_setup_mac` salt/iteration allocation, PBMAC1 parameter unpack, PBKDF2/GOST key derivation, `pkcs12_gen_mac` digest/key/HMAC ladder and cleanses, `PKCS12_verify_mac` constant-time compare, `PKCS12_set_mac`, `PKCS12_set_pbmac1_pbkdf2` | 1 defect (M63-D3) repaired |
| `src/pkcs12/p12_npas.rs` | `alg_get` PBE tuple decode, `newpass_bag` decrypt/re-encrypt/union replacement, `newpass_bags`, `newpass_p12` safe restore, three raise sites | no defect |
| `src/pkcs12/p12_p8d.rs` | both `PKCS8_decrypt` spellings; `zbuf == 1` cleansed plaintext release | no defect |
| `src/pkcs12/p12_p8e.rs` | both `PKCS8_encrypt` spellings, PRF/v1.5 ladder, `PKCS8_set0_pbe_ex` adoption and partial-init release | no defect |
| `src/pkcs12/p12_utl.rs` | `OPENSSL_asc2uni`/`_uni2asc`/`_utf82uni`/`_uni2utf8`, `bmp_to_utf8`, the four PKCS12 BIO/`FILE` wrappers, local `OwnedBuf` | 2 defects (M63-D1, M63-D2) repaired |
| `src/pkcs7/bio_pk7.rs` | one `BIO_new_NDEF` forward | no defect |
| `src/pkcs7/pk7_attr.rs` | SMIMECapabilities encode/decode, `PKCS7_simple_smimecap` parameter ownership, content-type/signing-time/digest attributes | no defect |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary.
It stays at the head of `REMAINING-AUDIT.txt`. `src/pkcs7/pk7_attr.rs` was
substituted from position 9 of the stable queue.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M63-D1 | `src/pkcs12/p12_utl.rs:142`, `:270`, `:278`, `:402`, `:413` | low | the allocation-size accumulators `asclen * 2 + 2` (asc2uni), `ulen += 2/4` (utf82uni) and `asclen += j/+1` (uni2utf8) were unchecked `c_int` arithmetic; overflow panics in debug and wraps in release, turning the allocation size into a bogus value instead of returning the ordinary failure answer (§3/§17) | every sizing step now uses `checked_mul`/`checked_add` and refuses with the ordinary NULL answer before allocating. No exported signature changed. |
| M63-D2 | `src/pkcs12/p12_utl.rs:201` | medium | `OPENSSL_uni2asc` executed `uni.add(1)` unconditionally, but its documented contract permitted `(NULL, 0)`; pointer arithmetic on null is Rust UB even though the authority's `uni++` is never dereferenced for an empty input | the skip is conditional on `unilen != 0`, preserving the one-byte `""` result for `(NULL, 0)` while removing the UB; contracts for the four conversions now state that NULL is permitted only for the empty input. |
| M63-D3 | `src/pkcs12/p12_mutl.rs:464` | low | a failed `PKCS5_PBKDF2_HMAC` in the GOST keygen left the 96-byte scratch, which can hold partial derived key material, uncleansed on the failure path; the authority `p12_mutl.c:73-76` does the same | the failure arm now `OPENSSL_cleanse`s the whole scratch before returning false. Deliberate secret-residue improvement; no observable behaviour, release seam or coordinate changed. |

**Unsafe accounting.** Eliminated: 0 (no unsafe operation removed). Relocated:
0. New assumptions: 0 — the three repairs only refuse or cleanse inputs the
body previously accepted. Hidden obligations: 0 after the repair. No exported
symbol, signature, `#[repr(C)]` layout, excluded symbol or allocator seam
coordinate changed; no new `unsafe fn`.

**Secret-bearing storage.** PKCS#12 passwords, the converted UTF-16 form, PBKDF2
keys, the GOST key, HMAC keys and decrypted private-key encodings are
`SECRET_DATA`; salts, iteration counts, algorithm identifiers, MAC values and
ciphertext are `PUBLIC_DATA`. Cleansed paths: `p12_key`'s converted password is
an `OwnedBuf` with a cleansing release on success and every KDF failure;
`p12_mutl`'s MAC `key` array is cleansed on every exit, and the GOST scratch is
now cleansed on both paths (M63-D3); `p12_p8d`/`p12_p8e` use `zbuf == 1`, so
the DER plaintext is cleansed by the item layer on decrypt and encrypt, and
`PKCS8_set0_pbe_ex` releases its partial initialization without running a
destructor. Retained authority behaviour: the parsed `PKCS8_PRIV_KEY_INFO`
returned by `PKCS8_decrypt_ex` is released with the item destructor, which does
not cleanse the decoded key fields, and an unencrypted `keyBag` in
`newpass_p12` is released the same way. `p12_utl` returns password conversions
to the C caller, which owns the cleansing release. No constant-time claim is
made for any unit from source inspection.

**Contracts reused.** OB-1 `OwnedBuf` (`adopt_cleansed` for the converted
password, local plain `OwnedBuf` for the conversion result seam); ASN.1 item
ownership for `PKCS8_PRIV_KEY_INFO`, `PBE2PARAM`, `PBKDF2PARAM`, `PBMAC1PARAM`,
`X509_SIG`, `PKCS12_SAFEBAG` and `PKCS12_MAC_DATA`; C ABI contracts for
NULL-or-live optional pointers, caller-sized buffers and caller-owned results;
the `EVP_KDF`/`EVP_MD` fetch contracts; the B19 BIGNUM/secret cleansing rule
applied to the MAC and GOST scratch; the `CRYPTO_*` allocator seam at the
authority's exact `FILE`/`LINE`. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`pkcs12::p12_utl` **4 / 0**, `pkcs12::p12_key` **2 / 0 / 1 ignored**,
`pkcs12::p12_mutl` **2 / 0**, `pkcs12::p12_npas` **1 / 0**; the substituted
`pkcs7` units contain no unit tests. BATCH: `cargo clippy --all-targets -- -D
warnings` clean; full library **1670 passed / 0 failed / 27 ignored** (1697
total) serial in 248.98 s and with `--test-threads=4` in 95.56 s, in the court
with `CARGO_BUILD_JOBS=4`. Affected probe
`pkcs12::p12_key::adv_probe::unipass_drop_cleanses_before_release` **1 / 0**
with `OPENSSL_RS_ADV_PROBE=1`. No unexplained removal and no newly ignored
test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; a direct failure-path residue control
for M63-D3 (the GOST scratch is a function-local array and no harness observes
it) NOT_RUN; an allocator-seam differential for the `p12_utl` conversion blocks
NOT_RUN; dudect/ctgrind (no constant-time claim); FRF suite; dependency-graph
regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) The decoded-key structures released by `PKCS8_PRIV_KEY_INFO_free` (and the
unencrypted `keyBag` path in `newpass_p12`) are not cleansed; that is the
authority's item-destructor contract and is preserved, not reclassified as
safe. (3) `p12_key`'s `out` is caller-owned key material; the ABI has no
length-attached cleansing release. (4) `OPENSSL_asc2uni`/`utf82uni` return
password material that the C caller must release with `OPENSSL_clear_free`;
that ownership is the exported contract. (5) No constant-time claim is made
for the PKCS#12 or PKCS#7 units.

**Queue.** `REMAINING-AUDIT.txt` 217 -> **209**; `AUDITED-FILES.txt` 546 ->
**554**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/pkcs7/pk7_mime.rs`, `src/property/defn_cache.rs`,
`src/property/globals.rs`, `src/property/list.rs`, `src/property/query.rs`,
`src/provider/base.rs`, `src/provider/capabilities.rs`.

---

## M64 — per-file contract sweep (property vocabulary/definition cache, provider base/capabilities/child, PKCS7 MIME)

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`13574d0cf` (dirty worktree: the M64-D1 repair below; no commit was made by the
audit subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results. The authority sources were read from
`forensics/authorities/src/openssl-3.6.4/` for every unit compared.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/pkcs7/pk7_mime.rs` | `i2d_PKCS7_bio_stream`, `PEM_write_bio_PKCS7_stream`, `SMIME_write_PKCS7` (signed arm, `md_algs`, `SMIME_OLDMIME`), `SMIME_read_PKCS7_ex`/`SMIME_read_PKCS7` (live `*p7` probe, libctx/propq read, `resolve_libctx`) | no safety defect; thin C ABI delegation |
| `src/property/defn_cache.rs` | slot-2 lhash constructor/releaser, `OwnedElem` alloc/adopt/into_raw, hash/cmp/free thunks, `ossl_prop_defn_get` read-lock lookup, `ossl_prop_defn_set` hit/insert/delete arms, checked size and allocator seam | no safety defect; one authority-faithful delete leak and unreachable assertion arm noted |
| `src/property/globals.rs` | slot-14 `OsslGlobalProperties`, OB-3 `CtxDestroy`, zeroed-holder validity, `ossl_ctx_global_properties` loadconfig arm, two mirroring flag accessors, zero-state sweep | no defect |
| `src/property/list.rs` | `#[repr(C)]` definition/list layout (union and `has_optional` bitfield), `properties_ptr`, `num_properties`, `properties` tail view | no UB; returned-slice lifetime/aliasing obligation was implicit and is now stated in the `# Safety` contract (M64-D2, documentation) |
| `src/property/query.rs` | sorted-array binary search and comparator, NULL/absent-name arms, `get_type`/`get_string_value`/`get_number_value`, `has_optional`, `is_enabled` override-before-union read | 1 defect (M64-D1) repaired |
| `src/provider/base.rs` | `BASE_PARAM_TYPES` descriptors, `base_get_params` locate/set arms, `base_query` four operation rows, `BASE_DISPATCH_TABLE`, `ossl_base_provider_init` dispatch walk/handle/libctx/ctx storage | no defect; provider dispatch boundary under the established `ProviderInitFn` contract, not the method-store registry |
| `src/provider/capabilities.rs` | 44-row/59-row/3-row/3-row capability tables, literal and row-field `OSSL_PARAM` aliasing, both walkers and callback refusal, `ossl_prov_get_capabilities` name dispatch | no defect; NULL-`cb`/NULL-name guards are the recorded safer divergence |
| `src/provider/child.rs` | slot-18 `ChildProvGlobals` and OB-3 destructor, child init dispatch walk, create/remove/global-props callbacks under the write lock, `init_as_child` seven-pointer validation, deregister NULL guard, parent up-ref/free, handle/ischild accessors | no defect; lock-across-parent-upcall reentrancy is authority-identical and recorded as a retained contract |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary
(store locking, construct/reserve/unreserve callbacks, method cache). It stays
at the head of `REMAINING-AUDIT.txt`. `src/provider/child.rs` was substituted
from position 9 of the stable queue. `src/provider/base.rs` was **audited**
rather than deferred: its handle use is the borrowed opaque handle of the
already-contracted `ProviderInitFn` dispatch table, not an ownership-adoption
or registry boundary.

**Defects.**

| ID | File:line | Severity | Class | Repair |
|---|---|---|---|---|
| M64-D1 | `src/property/query.rs:173` (post-fix) | low (compatibility, not UB in-reach) | `ossl_property_get_number_value` dereferenced `prop` unconditionally, while the authority tests `prop != NULL` and answers 0; a NULL definition was UB here and a defined 0 there | added the authority's NULL arm and a NULL assertion to the existing focused test. The contract now reads "NULL or live". No signature change. |
| M64-D2 | `src/property/list.rs:201` (post-fix) | low (contract documentation) | `properties<'len>` returns a caller-chosen lifetime from a raw list pointer; the `# Safety` stated only the length obligation, leaving the borrow-lifetime and alias-exclusivity requirements implicit | the contract now names both obligations. No code or signature change; the type cannot express them because the owner is a raw pointer. |

**Unsafe accounting.** Eliminated: 0 (no unsafe operation removed). Relocated:
0. New assumptions: 0. Hidden obligations: 0 after M64-D2's contract
statement; the remaining obligations are explicit and retained. No exported
symbol, signature, `#[repr(C)]` layout, excluded symbol or allocator seam
coordinate changed; no new `unsafe fn`.

**Secret-bearing storage.** These units carry `PUBLIC_DATA`: property names and
values, algorithm and capability tables, provider metadata, and the PKCS#7 MIME
envelope. No `SECRET_DATA` buffer is allocated, copied or released here. No
constant-time claim is made for any unit from source inspection.

**Contracts reused.** RC-1 context read/write locking for the definition cache;
OB-3 `OwnedCtx`/`CtxDestroy` for the global-properties and child-provider
slots, including the zero-state sweep; lhash element ownership and the
`CRYPTO_*` allocator seam at the authority's exact `FILE`/`LINE` in
`defn_cache`; C ABI contracts for NULL-or-live optional pointers, terminated
dispatch tables, writable out-parameters and caller-owned results; the provider
callback/dispatch contracts established in B1/B2/B6–B20 and M4 (including the
safer NULL-callback and NULL-name refusals); the `OsslParam` static Sync and
immutable-literal/row-field aliasing contract. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`property` **29 / 0**, `property::query` **3 / 0**, `provider::child`
**1 / 0**; `pkcs7::pk7_mime`, `provider::base` and `provider::capabilities`
contain no unit tests. BATCH after the repair: `cargo clippy --all-targets -- -D
warnings` clean; full library **1670 passed / 0 failed / 27 ignored** (1697
total) serial in 256.82 s and with `--test-threads=4` in 136.75 s, in the court
with `CARGO_BUILD_JOBS=4`. No unexplained removal and no newly ignored test.

**NOT_RUN.** Miri, ASan/valgrind, Loom; affected adversarial probes NOT_RUN
(`scripts/adv-probe.sh` has no property, provider base/capabilities/child or
PKCS7-MIME probe); a Miri or Tree-Borrows run of the `properties` tail view;
dudect/ctgrind (no constant-time claim); FRF suite; dependency-graph
regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) `ossl_prop_defn_set`'s delete arm leaves the removed element unreleased,
exactly as the authority does; the cache leaks until context teardown, and this
is preserved rather than reclassified. (3) A cached definition list is shared
by the cache and by every `Implementation.properties` that found it; the cache
owns the single release, and no caller may free it. (4) `properties<'len>`'s
lifetime and alias exclusivity remain caller obligations that the type system
cannot express from a raw list pointer. (5) `provider_create_child_cb` holds
the child write lock across parent upcalls (`c_prov_get0_provider_ctx`,
`c_prov_get0_dispatch`) exactly as the authority does; a parent that re-enters
the create path from those callbacks would deadlock, not race, and this
reentrancy contract is recorded rather than changed.

**Queue.** `REMAINING-AUDIT.txt` 209 -> **201**; `AUDITED-FILES.txt` 554 ->
**562**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/provider/cipher_gcm.rs`, `src/provider/cipher_tdes_wrap.rs`,
`src/provider/ctx.rs`, `src/provider/decode_der2key.rs`,
`src/provider/decode_epki2pki.rs`, `src/provider/decode_pem2der.rs`,
`src/provider/decode_spki2typespki.rs`.

## M65 — per-file contract sweep (provider decoder front doors, shared provider context, GCM and DES3-WRAP, DSA DER writer)

Receipt: [`atlas-refresh/mechanism-sweep-M65.json`](atlas-refresh/mechanism-sweep-M65.json).

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`46badefba` (dirty worktree: the repairs below; no commit was made by the audit
subagent). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results. Authority sources were read from
`forensics/authorities/src/openssl-3.6.4/` and
`forensics/authorities/build/openssl-3.6.4-production/` for every unit compared.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/cipher_gcm.rs` | `ossl_gcm_initctx`, the shared engine (`getivgen`, `setivinv`, `gcm_tls_init`, `gcm_tls_iv_set_fixed`, `gcm_tls_cipher`, `gcm_cipher_internal`, `gcm_iv_generate`), get/set ctx params, one-shot and the GCM/TLS AAD path, the `GcmDestroy`/`OwnedCtx`/`OwnedRaw` ownership model, AES/ARIA/SM4 `newctx`/`dupctx`/`freectx` and `initkey`, layout assertions | 3 defects (M65-D1..D3) repaired |
| `src/provider/cipher_tdes_wrap.rs` | `des_ede3_wrap`/`des_ede3_unwrap` (including the in-place shift), `tdes_wrap_cipher_internal`, both dispatch entries, `required_write_extent`, `tdes_wrap_newctx`, the DES3-WRAP table | 2 defects (M65-D4, M65-D5) repaired |
| `src/provider/ctx.rs` | OB-3 `ProvCtx`/`CtxDestroy`, `zalloc` constructor, setters/getters (NULL-live), `PROV_LIBCTX_OF`, both core-parameter accessors, zero-state sweep | no defect |
| `src/provider/decode_der2key.rs` | `BARE_ALGOR`/`BARE_PUBKEY` templates and destructor, the `KeytypeDesc` function table, selection rule, `der2key_newctx`/`freectx`, `der2key_decode` mark/fatal/label flow, `export_object`, the ML-KEM/ML-DSA/SLH-DSA d2i forwarders, both 77-row tables | 1 cleansing repair (M65-D8) |
| `src/provider/decode_epki2pki.rs` | OB-3 context and destructor, generated parser, `ossl_epki2pki_der_decode` (`d2i_X509_SIG`/PBE/`PKCS8_pkey_get0`/callback), decode bridge and BUF_MEM split, dispatch table | 1 secret-cleansing repair (M65-D6) |
| `src/provider/decode_pem2der.rs` | 18-row PEM map and its `Sync` argument, OB-3 context, `read_pem`, `PEM_do_header` pass shim, both engine dispatches and the generic params build, `'end` release order | 1 secret-cleansing repair (M65-D7) |
| `src/provider/decode_spki2typespki.rs` | OB-3 context, generated parser, `ossl_spki2typespki_der_decode` (SPKI read, SM2 special case, callback params), decode bridge, dispatch table | no defect (SPKI is `PUBLIC_DATA`; plain release retained) |
| `src/provider/der_dsa_sig.rs` | the nine OID literals and `ossl_DER_w_algorithmIdentifier_DSA_with_MD` over `WPACKET` | no defect |

**Deferred boundary.** `src/evp/method_store.rs` was again not audited: it is
the method-store/`OSSL_METHOD_CONSTRUCT_METHOD` registry and dispatch boundary.
It stays at the head of `REMAINING-AUDIT.txt`. `src/provider/der_dsa_sig.rs`
was substituted from position 9 of the stable queue.

**Defects.**

| ID | File:line (post-fix) | Severity | Class | Repair |
|---|---|---|---|---|
| M65-D1 | `src/provider/cipher_gcm.rs:844` | high | `getivgen` incremented at `iv + ivlen - 8`; the whole-IV restore arm can set `iv_gen` with `ivlen < 8`, so the wrapping subtraction wrote outside `iv` (authority UB, reachable from `tlsivgen`) | refuse with 0 when `ivlen < 8`; legitimate 12-byte IVs are unaffected |
| M65-D2 | `src/provider/cipher_gcm.rs:881` | high | `setivinv` copied `inl` bytes at `iv + ivlen - inl` with an application-supplied `data_size`; `inl > ivlen` wraps (authority UB, reachable from `tlsivinv`) | refuse with 0 when `inl > ivlen` |
| M65-D3 | `src/provider/cipher_gcm.rs:1352` | high | `gcm_tls_iv_set_fixed`'s `(ivlen - len) < 8` guard wraps for `len > ivlen`, after which `memcpy`/`RAND_bytes_ex` run with an underflowed length (authority UB, reachable from `tlsivfixed`) | add `len > ivlen` to the refusal guard |
| M65-D4 | `src/provider/cipher_tdes_wrap.rs:246` | medium | the in-place shift used `ptr::copy(out, out.add(8), …)`, i.e. source first; the authority's `memmove(out, out + 8, …)` shifts left. Every in-place unwrap decrypted the wrong blocks and read the wrong final IV | swap to `ptr::copy(out.add(8), out, …)`; new read-sequence test fails pre-repair and passes post-repair |
| M65-D5 | `src/provider/cipher_tdes_wrap.rs:253` | medium | the authority's `in -= 8` was transcribed literally; `in - 8` is outside the caller's block (Rust UB) even though it is immediately added back | compute the central and final offsets directly from the original pointer |
| M65-D6 | `src/provider/decode_epki2pki.rs:311,393,463` | low | passphrase `pbuf`, decrypted `new_der` and the input DER were left/released without cleansing (authority plain releases) | cleanse `pbuf` on both arms, cleanse `new_der` over its plaintext length, cleanse the decode block over `der_len`; release sites and seam unchanged |
| M65-D7 | `src/provider/decode_pem2der.rs:706` | low | `PEM_do_header` decrypts private-key material into `der`; the authority releases it plainly | cleanse `der` over `der_len` before the existing release |
| M65-D8 | `src/provider/decode_der2key.rs:536` | low | the read block carries private-key DER; both authority tails release it plainly | `cleanse_der(der, der_len)` before the single `OwnedBuf` release on both tails |

**Unsafe accounting.** Eliminated: 0 expressions (no `unsafe fn` removed or
added). Relocated: 0. New assumptions: 0 — the length guards only refuse
inputs that reached out-of-bounds writes, and `cleanse_der`'s contract names
provenance, ownership and the length bound. Hidden obligations: 0 after the
repairs. No exported symbol, signature, `#[repr(C)]` layout, excluded symbol or
allocator-seam coordinate changed. The three GCM refusals are deliberate
divergences from authority UB, in the §17 direction.

**Secret-bearing storage.** GCM/TDES IVs, tags, AAD, the fixed wrap IV,
`sha1tmp`, algorithm names/OIDs and SubjectPublicKeyInfo DER are `PUBLIC_DATA`;
passphrases, decrypted `PrivateKeyInfo` bytes and private-key DER are
`SECRET_DATA`. Cleansed paths: GCM contexts and every key schedule via
`CRYPTO_clear_free`; TDES `icv`/`iv`/`ctx->iv`/`sha1tmp` on every unwrap exit,
`out` on an ICV mismatch, and the TDES context via `tdes_freectx`; epki
`pbuf`/`new_der`/input DER; pem2der `der`; der2key `der`. Retained authority
behaviour: decoded key objects and the `PKCS8_PRIV_KEY_INFO` item are released
by their item destructors without cleansing. No constant-time claim is made.

**Contracts reused.** OB-1 `OwnedBuf`/`OwnedBlock` adoption and the `CRYPTO_*`
seam at the authority's exact `FILE`/`LINE`; OB-3 `OwnedCtx`/`CtxDestroy` and
the all-zero sweep; OB-4 member-buffer slots and caller-sized UTF-8 writes; the
provider decoder dispatch contracts from B1/B2/B6–B20; the GCM `OwnedCtx` /
`OwnedRaw` cleansing-vs-plain distinction; C ABI contracts for NULL-or-live
optional pointers, key-terminated `OSSL_PARAM` arrays, writable out-parameters
and caller-owned results. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`provider::cipher_gcm` **2 / 0**, `provider::cipher_tdes_wrap` **2 / 0**,
`provider::decode_der2key` **5 / 0**, `provider::decode_epki2pki` **2 / 0**,
`provider::decode_pem2der` **3 / 0**, `provider::decode_spki2typespki`
**2 / 0**, `provider::ctx` **3 / 0**; `provider::der_dsa_sig` contains no unit
tests. BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1672 passed / 0 failed / 27 ignored** (1699 total) with
`--test-threads=1` in 248.20 s and with `--test-threads=4` in 94.07 s, in the
court with `CARGO_BUILD_JOBS=4`. No unexplained removal and no newly ignored
test.

**NOT_RUN.** Miri/ASan/valgrind over the GCM length guards and the in-place
TDES unwrap; a differential compatibility court for in-place DES3-WRAP against
the pinned authority binary; Loom; affected adversarial probes (none exists for
these units); dudect/ctgrind (no constant-time claim); FRF suite;
dependency-graph regeneration; SEAL.

**Residual.** (1) `method_store.rs` remains the deferred registry boundary.
(2) Decoded key objects released by the row free functions and the
`PKCS8_PRIV_KEY_INFO` item destructor are not cleansed; that is the authority's
item contract and is preserved. (3) Keys are expanded into the context
schedule; the caller's key buffer is not owned or released here. (4) The GCM
refusals change behaviour only for inputs the authority turns into memory
corruption; a court probing overlength TLS-IV parameters observes the refusal.
(5) `decode_spki2typespki` keeps a plain release because SPKI is public.

**Queue.** `REMAINING-AUDIT.txt` 201 -> **193**; `AUDITED-FILES.txt` 562 ->
**570**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/provider/der_ec_sig.rs`, `src/provider/der_ecx_key.rs`,
`src/provider/der_ml_dsa_key.rs`, `src/provider/der_rsa_key.rs`,
`src/provider/der_rsa_sig.rs`, `src/provider/der_slh_dsa_key.rs`,
`src/provider/der_sm2_sig.rs`; `src/provider/digest_to_nid.rs` is the
substitute ordinary entry.

## M66 — per-file contract sweep (provider DER AlgorithmIdentifier writers and the digest-to-NID table)

Receipt: [`atlas-refresh/mechanism-sweep-M66.json`](atlas-refresh/mechanism-sweep-M66.json).

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`ca22e7d4b` (clean source tree; no repair was required and no source edit was
made). The eight records are file-level obligation checks, not
`SAFETY_DISCHARGED` results. Authority sources were read from
`forensics/authorities/src/openssl-3.6.4/` for every unit compared.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/der_ec_sig.rs` | the nine ECDSA-with-MD OID literals, `ossl_DER_w_algorithmIdentifier_ECDSA_with_MD` over `WPACKET` (`begin_sequence`/`precompiled`/`end_sequence`), unknown-`mdnid` refusal | no defect |
| `src/provider/der_ecx_key.rs` | the four ECX/Ed OID literals, the shared `write_identifier` body, the X25519/X448/ED25519/ED448 writers and their unused `ECX_KEY *` argument | no defect |
| `src/provider/der_ml_dsa_key.rs` | the three ML-DSA OID literals, `ossl_ml_dsa_key_get_name` precondition, `OPENSSL_strcasecmp` NUL-termination, the three-name dispatch, unknown-name refusal | no defect |
| `src/provider/der_rsa_key.rs` | the thirteen precompiled identifiers, `der_w_maskgen_algorithm` (`NID_sha1` default omission), `ossl_DER_w_RSASSA_PSS_params` (NULL/unrestricted refusal, salt/trailer checks), the RSA/RSA-PSS AlgorithmIdentifier writers, `ossl_rsa_get0_pss_params_30` lifetime | no defect |
| `src/provider/der_rsa_sig.rs` | the sixteen MD-with-RSA OID literals, the explicit `NULL` PARAMETERS write, the `-1` unlisted-`mdnid` answer | no defect |
| `src/provider/der_slh_dsa_key.rs` | the twelve SLH-DSA OID literals, `ossl_slh_dsa_key_get_type` precondition, the twelve-NID dispatch, unknown-NID refusal | no defect |
| `src/provider/der_sm2_sig.rs` | the single `sm2-with-SM3` OID literal, the one-case dispatch, unused `EC_KEY *` argument | no defect |
| `src/provider/digest_to_nid.rs` | the eleven-row `OSSL_ITEM` table, `unsafe impl Sync for OsslItem`, `ossl_digest_md_to_nid` (`it`/`it_len` and NUL-terminated `ptr` contract), `ossl_digest_get_approved_nid` | no defect; one retained documented invariant (see below) |

**Defects.** None. Every writer matches its authority's case set, refusal
value, write order and unused-argument behaviour. The `RSASSA-PSS` params/OID
order was exercised with a temporary local probe and produces
`SEQUENCE { id-RSASSA-PSS, RSASSA-PSS-params }`, matching the authority's
`asn1parse` output; the probe was removed and the worktree is clean.

**Unsafe accounting.** Eliminated: 0. Relocated: 0. Introduced: 0. No
`unsafe fn` signature, `#[repr(C)]` layout, exported symbol or allocator-seam
coordinate changed. Every remaining unsafe operation has an explicit contract
at its declaration: `*mut Wpacket` live (reused from the `packet` unit),
`*mut`/`*const` key or PSS object live-or-NULL as declared, `it` readable for
`it_len` entries with NUL-terminated `ptr`s, and `md` NULL-or-live. Callers
(`rsa_sig.rs`, `ecdsa_sig.rs`, `dsa_sig.rs`, `eddsa_sig.rs`, `sm2_sig.rs`,
`ml_dsa_sig.rs`, `slh_dsa_sig.rs`, `encode_key2any.rs`,
`securitycheck_default.rs`) establish those preconditions from their own
live-context contracts. Hidden obligations: 0. Retained documented invariant:
`OsslItem`'s `Sync` relies on every instance's `ptr` naming a `'static`
NUL-terminated literal — true for both tables (`digest_to_nid.rs` and
`securitycheck_default.rs`), and dereference still occurs only inside an
`unsafe fn` whose contract requires NUL termination, so no safe caller can
reach UB through the safe surface.

**Secret-bearing storage.** All eight units handle `PUBLIC_DATA` only: DER
OID/algorithm-identifier literals, the `WPACKET` output that carries them, and
public key metadata (`params->alg`, the SLH-DSA type NID). No private
encoding, seed, scalar or signature-secret buffer is read, copied, stored or
released here, so there is no secret-bearing buffer and no cleansing path to
review. The key-argument reads are limited to the accessors named above; the
callers' private-key bodies and signature buffers are outside these units.
No constant-time claim is made.

**Contracts reused.** `WPACKET` live-packet and DER-mode write discipline from
the `packet` unit (`WPACKET_init_der`, `WPACKET_memcpy`,
`WPACKET_get_total_written`, `WPACKET_cleanup`); the `der_writer`
`begin_sequence`/`precompiled`/`end_sequence`/`null`/`uint32` contracts; the
`OPENSSL_strcasecmp` NUL-terminated-string contract; the RSA-PSS accessors'
NULL-or-live contract and `ossl_rsa_pss_params_30_is_unrestricted`'s documented
NULL answer; C ABI contracts for unused key arguments, caller-owned `WPACKET`
buffers and caller-owned result pointers. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`provider::der_*` **12 passed / 0 failed**; `provider::securitycheck_default`
**2 / 0** (the `digest_to_nid` consumers; the module itself has no unit
tests). BATCH: `cargo clippy --all-targets -- -D warnings` clean; full library
**1672 passed / 0 failed / 27 ignored** (1699 total) with
`--test-threads=1` in 260.48 s and with `--test-threads=4` in 105.73 s, in the
court with `CARGO_BUILD_JOBS=4`. No unexplained removal and no newly ignored
test.

**NOT_RUN.** Miri/Tree Borrows/ASan (no allocation, aliasing or lifetime
claim was changed); Loom; affected adversarial probes (none exists for these
units); dudect/ctgrind (no constant-time claim); authority differential courts
(the unit tests compare against the authority's generated bytes, not against
the pinned binary); FRF suite; dependency-graph regeneration; SEAL.

**Residual.** (1) `src/evp/method_store.rs` remains the deferred registry
boundary at the head of the queue. (2) The `OsslItem` `Sync` invariant is
documented but not type-enforced (see above); it is not a hidden obligation
because it is stated here and its only dereference site is unsafe-contracted.
(3) The key accessors read public metadata only; no secret buffer is owned by
these units. (4) The callers' `WPACKET` backings are caller-owned and are not
cleansed here, correctly, because their contents are algorithm identifiers.

**Queue.** `REMAINING-AUDIT.txt` 193 -> **185**; `AUDITED-FILES.txt` 570 ->
**578**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/provider/dsa_kmgmt.rs`, `src/provider/ecdh_exch.rs`,
`src/provider/ecx_exch.rs`, `src/provider/ecx_kem.rs`,
`src/provider/encode_key2blob.rs`, `src/provider/encode_key2ms.rs`,
`src/provider/endecoder_common.rs`; `src/provider/file_store_any2obj.rs` is the
substitute ordinary entry if `method_store.rs` is deferred again.

---

## M67 — per-file contract sweep (DSA keymgmt, ECDH/ECX exchange, ECX DHKEM, key encoders and endecoder helpers)

Receipt: [`atlas-refresh/mechanism-sweep-M67.json`](atlas-refresh/mechanism-sweep-M67.json).

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`1d5186002`. One documentation-accuracy repair in `src/provider/ecx_kem.rs` (a
SAFETY comment claimed `ecx_key_check` tolerated a NULL key while its body
dereferences it); behaviour, layout, symbols and allocator coordinates are
unchanged. Authority sources were read from
`forensics/authorities/src/openssl-3.5.9/` and, for the generated
`ecdh_exch` unit, the `3.6.4` `.c.in`, for every unit compared. The eight
records are file-level obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/file_store_any2obj.rs` | OB-3 `OwnedCtx`/`RawCtx` for `Any2objCtx`, the DER/MSBLOB/PVK decoders' `BUF_MEM` ownership and empty-handed paths, callback parameter lifetimes, `data_structure` bounds | no defect |
| `src/provider/dsa_kmgmt.rs` | `DsaGenCtx` ownership (`seed`/`mdname`/`mdprops`), generation callback, `dsa_export` builder/parameter release, `ossl_dsa_*`/`DSA_free` object lifetime | no defect |
| `src/provider/ecdh_exch.rs` | `ProvEcdhCtx` keys and `kdf_md` up-ref/free, UKM replacement (plain) vs final release (cleansed), `dupctx` failure paths, X9.63 staging and `derive_skey` output cleansing | no defect |
| `src/provider/ecx_exch.rs` | local `OwnedCtx`/`RawCtx` context ownership, key/peerkey up-ref balance in `dupctx`, block-vs-member release split | no defect |
| `src/provider/ecx_kem.rs` | `ProvEcxCtx` ownership, `ikm` replacement/final cleansing, `derivekey` temp seed, `dhkm`/`prk` cleansing, encapsulate/decapsulate output and error paths | no functional defect; one SAFETY-comment correction |
| `src/provider/encode_key2blob.rs` | `i2o_ECPublicKey` block adoption, core-BIO bridge lifetime, six-slot tables and selection rule | no defect |
| `src/provider/encode_key2ms.rs` | `Key2msCtx` via `OwnedCtx`/`CtxDestroy`, `pwdata` clear, `EVP_PKEY` lifetime, PVK/MSBLOB selection and passphrase callback | no defect |
| `src/provider/endecoder_common.rs` | dispatch pilfers, `ossl_prov_import_key`/`free_key` failure path, `ossl_read_der` header-vs-data ownership split | no defect |

**Defects.** No memory-safety, ownership, aliasing, ABI or secret-lifetime
defect. The only source edit corrects the `ecx_key_check`/`ecxkem_init`
contract to say what the code and the KEM dispatch already require (a live
`ECX_KEY`), removing a misleading claim that NULL was tolerated.

**Unsafe accounting.** Eliminated: 0. Relocated: 0. Introduced: 0. No
`unsafe fn` signature, `#[repr(C)]` layout, exported symbol or allocator-seam
coordinate changed. Hidden obligations: 0. Retained documented preconditions
are the keyexch/KEM dispatch contracts (live non-NULL context and key), the
authority-identical inert `ProvEcxCtx::propq` field (never assigned, always
NULL), and the authority-faithful plain release of private-key copies in
`dsa_export`'s `OSSL_PARAM` block and `ossl_read_der`'s DER block.

**Secret-bearing storage.** `ecx_kem` cleanses `ikm`, `dhkm`, `prk` and the
temporary random seed on every replacement, failure and teardown path;
`ecdh_exch` cleanses the UKM final release, the secure X9.63 staging buffer and
the `derive_skey` output, while replacing the old UKM with the authority's
plain free; `dsa_kmgmt` cleanses the generation seed; `file_store_any2obj`
releases every DER/MSBLOB/PVK `BUF_MEM` through `BUF_MEM_free`, whose data
block is cleansed over the block capacity; `encode_key2ms` clears `pwdata` and
lets `EVP_PKEY_free` cleanse the imported key's BIGNUMs. Private-key copies
handed to callers (`dsa_export`, `ossl_read_der`) use the authority's plain
releases and are recorded as such. `encode_key2blob` handles public points
only. No constant-time claim is made.

**Contracts reused.** OB-1 `OwnedBuf`; OB-3 `OwnedCtx`/`RawCtx`/`CtxDestroy`;
OB-4 in-place member replacement; RC-1 reference-count pairs; B19 BIGNUM
cleansing through the key destructors; the `BUF_MEM_free` cleansing-release
contract; the B1/B2/B6–B20 callback contracts; the core-BIO bridge and C ABI
buffer/key contracts; and the provider encoder NULL/0 allocator-coordinate
convention established in M27. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`provider::file_store_any2obj` **2 / 0** (including the zero-state sweep) and
`provider::encode_key2blob` **2 / 0**; the other six units have no name-filtered
unit tests and are covered by the full suite. BATCH:
`cargo clippy --all-targets -- -D warnings` clean; full library **1672 passed /
0 failed / 27 ignored** (1699 total) with `--test-threads=1` in 243.24 s and
with `--test-threads=4` in 86.54 s, in the court with `CARGO_BUILD_JOBS=4`. No
unexplained removal and no newly ignored test.

**NOT_RUN.** Miri/Tree Borrows/ASan (no ownership or aliasing claim changed);
Loom; affected adversarial probes (none exists for these units); dudect/ctgrind
(no constant-time claim); authority differential courts for derived secrets and
PVK/MSBLOB bytes; FRF suite; dependency-graph regeneration; SEAL.

**Residual.** (1) `src/evp/method_store.rs` remains the deferred registry
boundary at the head of the queue. (2) `ProvEcxCtx::propq` is documented as an
inert owned-typed field, not an allocation; the authority never assigns it.
(3) The dispatch functions that dereference their context/key state the C
ABI's non-NULL precondition at each declaration; no safe-Rust caller can reach
them. (4) Private-key copies handed to callbacks are released plainly exactly
as the authority releases them.

**Queue.** `REMAINING-AUDIT.txt` 185 -> **177**; `AUDITED-FILES.txt` 578 ->
**586**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/provider/init.rs`, `src/provider/kem_util.rs`,
`src/provider/keymgmt.rs`, `src/provider/legacyprov.rs`,
`src/provider/mac_legacy_sig.rs`, `src/provider/ml_common_codecs.rs`,
`src/provider/ml_dsa_sig.rs`.

## M68 — per-file contract sweep (provider KDF/DH keymgmt, legacy provider, legacy MAC, ML common/ML-DSA/ML-KEM codecs and ML-KEM KEM)

Receipt: [`atlas-refresh/mechanism-sweep-M68.json`](atlas-refresh/mechanism-sweep-M68.json).

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`f6357d2ef`. Three files carry worktree repairs (four findings): a failure-path
state difference in `dh_gen_common_set_params`, allocator release coordinates and
secret residue in the ML-KEM codecs, and secret residue in the ML-DSA signature
context. Behaviour on success, layout, symbols, exported signatures and every
allocation coordinate are unchanged; the changes are failure-path state, release
coordinates and cleansing. Authority sources were read from
`forensics/authorities/src/openssl-3.6.4/` for every unit compared. The eight
records are file-level obligation checks, not `SAFETY_DISCHARGED` results.
`src/evp/method_store.rs` and `src/provider/init.rs` were inspected and deferred
as trust boundaries (see below); the two next ordinary queue entries were taken
in their place so the batch still covers eight files.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/kem_util.rs` | the one-entry `DHKEM` mode table, NULL/`NUL`-terminated `name` contract, `OPENSSL_strcasecmp` comparison, sentinel-as-loop-stop vs stored terminator | no defect |
| `src/provider/keymgmt.rs` | `KdfData` refcount/Drop, `DhGenCtx` field-order/all-zero validity, `RawDhGenCtx` pre-publication block-only release, seed replacement (`adopt_cleansed` → `CRYPTO_memdup`), `mdname`/`mdprops` replacement, `dh_gen` callback/`gencb` lifetime and `dh_gen_end`, `dh_load` reference detach, `dh_export` builder/parameter release | 1 low-severity failure-path divergence repaired (M68-D1) |
| `src/provider/legacyprov.rs` | local `OwnedCtx<T>` allocation/copy/copyctx/cleansing release for the mandatory POD digest contexts, MDC2 `pad_type` setter, provider table walk/query/teardown, libctx child ownership | no defect |
| `src/provider/mac_legacy_sig.rs` | `ProvMacCtx` ownership split (propq plain, macctx/key refs), `newctx`/`dupctx` partial-init and error paths, dispatch-context NULL preconditions, settable/fetch lifetimes | no defect |
| `src/provider/ml_common_codecs.rs` | six-format preference selection, case-insensitive prefix matching, zero-sorts-last total order, terminator slot, `OwnedBlock` calloc/free, four big-endian helpers, `Sync` tables | no defect |
| `src/provider/ml_dsa_sig.rs` | `ProvMlDsaCtx` field order/dup ownership, `sig`/`md_ctx`/`test_entropy` release and cleansing, `set_alg_id_buffer` `WPACKET` discipline, three randomness modes, `mu`/`rand_tmp` cleansing on every return, generated decoder duplicate-key refusal, dispatch tables | 1 low-severity secret-residue finding repaired (M68-D4) |
| `src/provider/ml_kem_codecs.rs` | SPKI prefix check and PKCS#8 format/bounds walk, `CRYPTO_secure_malloc` DK ownership, `i2d` buffer sizing/encoding, key-to-text seed/DK handling, allocator release coordinates | 2 low-severity findings repaired (M68-D2, M68-D3) |
| `src/provider/ml_kem_kem.rs` | `RawCtx`→`OwnedCtx` construction and zero-state sweep, borrowed key, entropy buffer lifetime (one-shot, `ctext == NULL` exception), encapsulate/decapsulate length and NULL-pointer arms | no defect |

**Defects.**

| ID | Location (pre-fix) | Severity | Class | Repair |
|---|---|---|---|---|
| M68-D1 | `src/provider/keymgmt.rs:1220-1224` | low | failure-path compatibility divergence | `dh_gen_common_set_params` tested the named group's UID before storing it, so a rejected group left the previous `group_nid`; the authority assigns `NID_undef` first. The assignment now precedes the test, so an ignored set-params failure feeds `dh_gen` the authority's value. |
| M68-D2 | `src/provider/ml_kem_codecs.rs:758, 871, 1004, 1025` | low | allocator-seam release coordinate | the four `OwnedBuf`s recorded the allocation line as their release line; the authority frees at `ml_kem_codecs.c:427` (pub failure), `:554` (prv failure), `:616` (pubenc) and `:617` (prvenc). `new_plain_released`/`new_cleansed_released` now carry both pairs; allocation coordinates and sizes are unchanged. |
| M68-D3 | `src/provider/ml_kem_codecs.rs:560, 871-... , 1004-...` | low | secret residue on failure/teardown | the `key_to_text` stack copy of the private seed was never cleared, and the private-key DER buffers (`prvenc`, and the `i2d_prvkey` output on failure) were released plainly, leaving seed/DK bytes in freed or reused storage. The seed is now cleansed at function exit and both private DER buffers use a cleansing release; on success the caller still takes the block exactly as the authority hands it over. |
| M68-D4 | `src/provider/ml_dsa_sig.rs:183-196, 940-975` | low | secret residue on failure paths | `freectx` cleansed only `test_entropy_len` bytes, and a refused or wrong-length `test-entropy` set resets that length to 0 after writing into the buffer, leaving earlier entropy bytes. `freectx` now cleanses the whole array and each `set-entropy` attempt clears the array before the copy and on every refusal. Deliberate deviation from `ml_dsa_sig.c:79/420-427`; not observable through the API. |

No memory-safety defect (UB, invalid free, aliasing conflict, uninitialised
read, or safe caller reachable through a safe interface) was found. The D3/D4
repairs are deliberate safety improvements over the authority's own residue; they
change no successful-path output, error code or allocation.

**Unsafe accounting.** Eliminated: 0. Relocated: 0. Introduced: 0. No `unsafe fn`,
`#[repr(C)]` layout, exported symbol or signature changed; no `SAFETY` comment was
weakened. Every remaining unsafe operation in the eight files has an explicit
contract at its declaration or at the enclosing block: C dispatch contexts are
non-NULL and live; borrowed keys are owned by `EVP_PKEY`/`ML_KEM_KEY`; `DhGenCtx`
and `ProvMlDsaCtx`/`ProvMlKemCtx` match the authority's field order and all-zero
validity; `WPACKET` is live; the PKCS#8 walk stays inside `len`; `data`/`msg` are
readable for their lengths. Hidden obligations: 0. Retained documented
invariants: (1) `ml_dsa_sig`'s `set_alg_id_buffer` passes a fixed 256-byte
`aid_buf` to `WPACKET_init_der`, so the init's NULL/zero refusal cannot occur and
`WPACKET_cleanup` always sees an initialised packet (the same shape the already
audited DSA/SLH-DSA signature units carry); (2) `ProvMlKemCtx::entropy` is NULL or
`entropy_buf`; (3) the ML-KEM/ML-DSA format tables are internally consistent with
`p8_bytes`, which is the bound the encoding walk relies on.

**Secret-bearing storage.** `ml_dsa_sig`: `test_entropy` is `SECRET_DATA` /
`CLEANSING_REQUIRED` — cleansed over the full array in `freectx` and before every
replacement attempt (success, refusal and wrong length); `rand_tmp` is cleansed on
every path where it, not `test_entropy`, supplied the value; `mu` is cleansed on
every return; the key is a borrow and the context's `context_string`, `sig` and
`aid_buf` are public. `ml_kem_codecs`: `encoded_dk` is allocated with
`CRYPTO_secure_malloc` and owned by the key, whose destructor secure-clears it; the
decoded seed is copied into key-owned storage; the `i2d_prvkey` output and
`key_to_text`'s `prvenc` are `SECRET_DATA` and now use cleansing releases on every
path where the unit still owns them (success hands the former to the caller, as
the authority does), and the to-text stack seed is cleansed. `ml_kem_kem`:
`entropy_buf` is cleansed after each encapsulation and in `destroy_body`; the
`ctext == NULL` size-query path deliberately retains it for the next call, which
is the authority's one-shot semantics and is documented in the unit.
`keymgmt`: the FIPS 186-4 seed uses `OwnedBuf::adopt_cleansed` on replacement and
release; `mdname`/`mdprops` are public. `legacyprov`: the digest contexts carry
chaining state and are released with `CRYPTO_clear_free`; `mac_legacy_sig` owns
only a public property query and a key reference. No constant-time claim is made.

**Contracts reused.** `OB-1` `OwnedBuf` (`new_plain_released`, `new_cleansed`,
`new_cleansed_released`, `adopt_plain`, `adopt_cleansed`, `into_raw`) for seed,
signature, DER and entropy buffers; `OB-2` `OwnedStr` for provider names and paths;
`OB-3` `OwnedCtx`/`RawCtx`/`CtxDestroy` and the block-vs-member split for
`KdfData`, `DhGenCtx`, `ProvMlKemCtx` and the legacy digest contexts; `OB-4`
member-buffer slots for `seed`/`mdname`/`mdprops`/`sig`; `RC-1` refcount ownership
for `KdfData`, `MacKey` and `EVP_MD_CTX` duplicates; `B19` BIGNUM/key cleansing
through the primitive key destructors; the per-path allocator-coordinate contract
established by M61/M62; the `WPACKET` DER write/finish/cleanup contract; the
`OSSL_PARAM` key-terminated array and descriptor contracts; and the C ABI
dispatch contracts for every `extern "C"` entry point. No new model was created.

**Gates observed.** FAST: `cargo fmt --all -- --check` clean; focused
`provider::ml_*` **10 passed / 0 failed** (including both ML-KEM codec tests and
the ML-KEM KEM zero-state sweep), `provider::keymgmt` **2 / 0** (both zero-state
sweeps), `provider::legacyprov` **1 / 0**; `provider::mac_legacy_sig` and
`provider::kem_util` have no unit tests and are covered by the full suite. An
initial `provider::` sweep showed two `ec_kem` failures; both pass when rerun in
isolation, the known global-state isolation issue, not a regression. BATCH:
`cargo clippy --all-targets -- -D warnings` clean; full library **1672 passed /
0 failed / 27 ignored** (1699 total) with `--test-threads=1` in 262.92 s and with
`--test-threads=4` in 90.63 s. Counts are identical to M67: no unexplained removal
and no newly ignored test.

**NOT_RUN.** `src/evp/method_store.rs` and `src/provider/init.rs` are deferred
boundary work: method_store is the `OSSL_METHOD_CONSTRUCT_METHOD` registry /
temporary-store dispatch host (caller-supplied function table, global method
store, refcount balance across `construct`/`put`/`destruct`), and init invokes a
provider-supplied `OSSL_provider_init` callback and walks a provider-supplied,
unbounded dispatch table (reentrancy, partial initialisation and teardown
obligations). Affected adversarial probes: none observes these units' release
coordinates or post-free contents, and no allocator-hook differential exists, so
the probes are `NOT_RUN` rather than `PASS`. Miri/Stacked+Tree Borrows/ASan/Loom,
authority differential courts for ML-DSA/ML-KEM encodings and DH generation,
constant-time measurement, dependency-graph regeneration and the FRF suite/SEAL
are `NOT_RUN` at their scheduled levels.

**Residual.** (1) `src/evp/method_store.rs` and `src/provider/init.rs` remain the
deferred registry/initialisation boundaries at the head of the queue. (2) The
ML-KEM `ctext == NULL` size-query path retains one-shot `ikmE` entropy for the
next call, deliberately matching the authority. (3) A private-key DER block handed
to a caller by `ossl_ml_kem_i2d_prvkey` is caller-owned and freed plainly by the
authority's contract; the unit cleanses only the blocks it still owns. (4) The
legacy provider keeps a child library context alive across teardown, the
documented default/base-provider shape rather than `legacyprov.c`'s own
`OSSL_LIB_CTX_free`.

**Queue.** `REMAINING-AUDIT.txt` 177 -> **169**; `AUDITED-FILES.txt` 586 ->
**594**. **Next eight.** `src/evp/method_store.rs` (registry boundary — defer
again), `src/provider/init.rs` (provider-init boundary — defer again),
`src/provider/ml_kem_kmgmt.rs`, `src/provider/mlx_kem.rs`,
`src/provider/rsa_enc.rs`, `src/provider/rsa_kem.rs`,
`src/provider/securitycheck_default.rs`, `src/provider/securitycheck.rs`.

## M69 — boundary sweep B22 (method-store constructing dispatch and provider initialisation)

Receipt: [`atlas-refresh/boundary-sweep-B22.json`](atlas-refresh/boundary-sweep-B22.json).

**Candidate identity.** `integrate/safe-c33` at source HEAD `ff2595b4e`.
Worktree blobs: `src/evp/method_store.rs` `2695423fc`, `src/provider/init.rs`
`faad135a1`. Authority: `crypto/core_fetch.c` (sha256 `f8900fd6b…`, 5,661
bytes) and `crypto/provider_core.c` (sha256 `da796e074…`, 85,492 bytes), read
whole from `forensics/authorities/src/openssl-3.6.4/`.

**Disposition.** CONTRACTED for both files, not `SAFETY_DISCHARGED`.
Four method-store boundaries (B22-MCM-1..4) reuse the B9/B10/B21 registry
serialization contract: `reserve_store` takes the method-store lock and holds
it across pre, every construct/put/destruct and post, giving the order
method-store -> provider opbits. Five provider-init boundaries (B22-PINIT-1..5)
cover path resolution, the `OSSL_provider_init` callback and partial-init state,
the unbounded provider dispatch walk, the reason-strings copy, and teardown.
The mcm callback contract (put increments the refcount; a NULL store names the
global store; the temporary store belongs to the mcm owner; no callback may
re-enter the held store lock) and the provider ABI contracts remain caller
obligations, which is why neither file is discharged.

**Defects repaired.**
- B22-D1 (medium, `provider/init.rs:359-366` pre-fix, now `:372`): the
dispatch walk transmuted a NULL `GET_REASON_STRINGS` function straight into a
non-Option `fn`; the authority's accessor macro answers NULL and its caller
guards it. The arm is now a match guard, so a NULL entry stays absent.
- B22-D2 (low, `provider/init.rs:265` pre-fix, now `:269`): a failed
`DSO_merge` still called `DSO_load(dso, NULL, …)`, raising
`DSO_R_NO_FILENAME` where the authority short-circuits. The load is now skipped
when the merge answer is NULL; the release path is unchanged.
- B22-D3 (low, test-only, `evp/method_store.rs` fixtures): the seven tests share
one `SAW` counter set and raced `reset()` under `--test-threads=4` (observed
once as 7 passed / 1 failed). A test-only `Mutex` now serialises them; poison is
recovered and no production code changed.

**New control.** `provider_init::tests::a_null_reason_strings_entry_is_ignored_like_the_authority`
publishes an id-1029 entry with a NULL function and asserts that initialisation,
publication and free all succeed. Honest limitation: restoring the unguarded
transmute does **not** make this test fail, because `Option<fn>` uses the null
niche and `Some(NULL)` is representationally `None`; the test is a parity
control, not a detector for the invalid-value class. Miri is that detector and
is `NOT_RUN`.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`provider::init::tests` + `evp::method_store` **8 passed / 0 failed** (1,692
filtered) threaded; `cargo clippy --all-targets -- -D warnings` clean (the first
guard form was rejected as `collapsible_match` and rewritten as a match guard).
BATCH full library **1673 passed / 0 failed / 27 ignored** (1,700 total) serial
in 267.45 s and threaded in 110.07 s, in the court with `CARGO_BUILD_JOBS=4`.
The single new test accounts for the 1,699 -> 1,700 total; no test was removed
or newly ignored.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: **0**. No
production unsafe operation added or removed; one operation (the typed
dispatch-slot transmute) was narrowed by a validity guard and one FFI call is
skipped on an allocation-failure path. No safe caller can reach either walk:
`ossl_method_construct` is `pub(crate) unsafe` with no caller until 7.2.
Residuals are the provider table/termination/reason-string lifetime contracts,
the mcm refcount/temporary-store ownership contract, the store-lock re-entry
ban, the late-init failure state, the NULL reason-string table safety
improvement, and the unlocked init flag (B22-R1..R6).

**NOT_RUN.** Miri/Stacked+Tree Borrows (`cargo miri` reports the component is
not available for the court's stable 1.98.1); ASan (no allocation, ownership or
access-pattern change; the invalid-value class is Miri's); Loom/TSan (neither
file declares a lock or atomic — the new `Mutex` is test-only and the
cross-mechanism order is B9/B10/B21's, unchanged); `RT-FETCH` named-provider and
temporary-store differential (no caller yet); authority provider-load
differential (no harness loads a real module provider under this unit); the FRF
suite and SEAL.

**Residuals.** (1) `provider/init.rs` and `evp/method_store.rs` are now audited;
their external contracts are recorded, not discharged. (2) The method-store
lock is held across caller callbacks and they must not re-enter it. (3) The
provider dispatch and reason-strings tables are terminated and kept alive by
the provider. (4) A late init failure leaves `provctx` published with the flag
clear, so free performs no teardown — authority parity. (5) A NULL
reason-strings table is refused here where the authority dereferences it
(deliberate section 17 improvement); `ERR_load_strings` remains a no-op in this
crate. (6) Init exclusivity is the caller's, stated in the `# Safety` contract.

**Queue.** `REMAINING-AUDIT.txt` 169 -> **167**; `AUDITED-FILES.txt` 594 ->
**596**. **Next ordinary position.** `src/provider/ml_kem_kmgmt.rs`. **Next
eight.** `src/provider/ml_kem_kmgmt.rs`, `src/provider/mlx_kem.rs`,
`src/provider/rsa_enc.rs`, `src/provider/rsa_kem.rs`,
`src/provider/securitycheck_default.rs`, `src/provider/securitycheck.rs`,
`src/provider/seeding.rs`, `src/provider/skeymgmt.rs`.

## M69 (mechanism) — per-file contract sweep (ML-KEM keymgmt, MLX KEM, RSA cipher/RSASVE, security checks, seeding and symmetric-key management)

Receipt: [`atlas-refresh/mechanism-sweep-M69.json`](atlas-refresh/mechanism-sweep-M69.json).
Numbering note: the preceding section is the boundary sweep B22, which this file
headed `M69`; this entry keeps the orchestrator-assigned mechanism receipt name.

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`2d24ba8f5`. Three files carry worktree repairs (three findings): one failure-path
allocation guard in `mlx_kem_decapsulate`, cleansing plus release-coordinate
separation for the two RSA OAEP/TLS scratch buffers, and release-coordinate
separation for the ML-KEM keymgmt scratch buffers. Layouts, symbols, exported
signatures, allocation sizes and `FILE` values are unchanged; the only release
change beyond the line metadata is `CRYPTO_clear_free` instead of `CRYPTO_free`
for two internally owned scratch blocks. The eight records are file-level
obligation checks, not `SAFETY_DISCHARGED` results.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/ml_kem_kmgmt.rs` | `ProvMlKemGenCtx` seed/seedbuf ownership, `ml_kem_pairwise_test` scratch and cleanses, export public/seed/private/DK provenance and secure-heap release, generated decoder walks and repeated-key sites, `check_seed`/`check_prvenc`, `load`/`load_err` detached-DK ownership, gen/gen_set_params/gen_cleanup | 1 low-severity allocator-coordinate class repaired (M69-D3) |
| `src/provider/mlx_kem.rs` | `ProvMlxKemCtx` borrowed key, `newctx` field-by-field init, ML-KEM plus ECDHE encapsulate/decapsulate ladders, shared-secret cleanse arms, size-query returns, dispatch table | 1 low-severity failure-path allocation divergence repaired (M69-D1) |
| `src/provider/rsa_enc.rs` | `ProvRsaCtx` key/md/label refcounts, OAEP encrypt/decrypt scratch, TLS padding ladder, constant-time selection, get/set decoders, dup/free partial-init arms | 1 low-severity secret-residue plus coordinate class repaired (M69-D2) |
| `src/provider/rsa_kem.rs` | `ProvRsaCtx` zalloc/dup/free, RSASVE generate/recover, degenerate-ciphertext guard, BN_CTX temporaries, operation-name map | no defect |
| `src/provider/securitycheck_default.rs` | seven-row RSA digest map, NULL `EVP_MD` contract, approved-NID fall-through | no defect |
| `src/provider/securitycheck.rs` | protect/allow classification and PSS refusal, RSA/EC/DSA/DH size checks | no defect |
| `src/provider/seeding.rs` | eight dispatch ids, `set_func` identity refusal, user-before-plain precedence, forwarding up-calls | no defect |
| `src/provider/skeymgmt.rs` | `ProvSkey` zalloc/member cleanse, generic import/export, AES length/type subclass, dispatch rows | no defect |

**Defects.**

| ID | Location (pre-fix) | Severity | Class | Repair |
|---|---|---|---|---|
| M69-D1 | `src/provider/mlx_kem.rs:514-518` | low | failure-path allocation divergence | the ECDH peer key was allocated before testing the just-created `EVP_PKEY_CTX`; the authority guards the context first, so an allocator failure now skips the peer allocation exactly as the authority does. |
| M69-D2 | `src/provider/rsa_enc.rs:362-395, 462-519` | low | secret residue plus allocator-seam coordinate | both OAEP/TLS scratch buffers recorded the allocation line as the release line and were freed plainly while holding padded plaintext / decrypted EM. They now use `new_cleansed_released` at the authority's allocation and early/late release coordinates and are cleansed before release (a deliberate improvement over the authority's `OPENSSL_free`, not observable through the API). |
| M69-D3 | `src/provider/ml_kem_kmgmt.rs:154-177, 269-280, 501-553, 922-927, 1166-1195, 1432-1440` | low | allocator-seam release coordinate | eight scratch handles recorded their allocation site as their release site (pairwise ctext, export public/seed/private/DK, `check_prvenc`, replacement `propq`), and `ml_kem_load` shared `LINE_LOAD_CLEAR=535` between the success and error arms although 535 is not a free site. Separate allocation/release pairs now name 115/158, 269/339, 283/337, 289/338, 294/338, 377/383, 558/565, 734/735 and 839. |

No memory-safety defect (UB, invalid free, aliasing conflict, uninitialised read,
or safe caller reachable through a safe interface) was found. The D2/D3 repairs
are allocator-coordinate and secret-residue improvements; D1 is a failure-path
compatibility repair.

**Secret-bearing buffers.** RSA OAEP encrypt/decrypt scratch is now cleansed on
every arm; the RSA key itself is released through `RSA_free` and B19's BIGNUM
cleansing. ML-KEM pairwise `secret`/`out`/`entropy` and the stack seed are
cleansed on every exit, the pairwise ciphertext and `check_prvenc` scratch are
clear-freed, export seed/private/DK copies are secure-clear-freed, the
`OSSL_PARAM` copies are cleansed before `OSSL_PARAM_free`, and the detached
`encoded_dk` is secure-clear-freed on both load arms. `ProvSkey.data` is
clear-freed on the destructor and on the rejected-import paths. MLX's combined
shared secret is cleansed on failure after the length checks; its size-query
returns are deliberately cleanse-free, matching the authority. `seeding` and the
two security-check units store no secrets.

**Assumptions.** Eliminated: 0. Relocated: 0. New: 0. Hidden: **0**. No unsafe
operation was added or removed; the new calls are safe constructors and setters.
Contracts reused: OB-1 `OwnedBuf`, OB-3 `OwnedCtx`/`CtxDestroy`, OB-4 member
slots, RC-1 refcounts, B19 BIGNUM cleansing, the provider `OSSL_CALLBACK`
lifetime contract and the `CRYPTO_*` seam.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; focused
`provider::mlx_kem` 1/0, `provider::skeymgmt` 1/0, `provider::securitycheck` 3/0,
`provider::rsa_kem` 1/0, `runtime::owned_buf` 30/0, `runtime::bio::owned` 19/0.
The `provider::` subset reported 174 passed / 1 failed once
(`provider::ec_kem::tests::the_dhkem_round_trip_agrees_in_crate`); rerun alone it
passes, so it is the known test-isolation issue, not a regression. BATCH
`cargo clippy --all-targets -- -D warnings` clean; full library **1673 passed /
0 failed / 27 ignored** serial in 201.74 s and threaded in 93.39 s, in the court
with `CARGO_BUILD_JOBS=4`.

**NOT_RUN.** Miri/Stacked+Tree Borrows and ASan (no ownership mechanism changed;
the repaired class is allocator metadata and residue); allocator-hook
differential observing the corrected `file`/`line` events; authority
differential for RSA OAEP/TLS, RSASVE and ML-KEM export/load; constant-time
measurement (no secret-dependent control flow changed, no claim made);
dependency-graph regeneration; FRF suite and SEAL.

**Residuals.** (1) The eight files are audited, not `SAFETY_DISCHARGED`. (2)
Provider-up-call statics assume the core serialises initialisation. (3)
`ProvMlxKemCtx.key` and `ProvRsaCtx.rsa` lifetimes are EVP caller obligations.
(4) The RSA padding ladders use the authority's constant-time helpers but no new
timing evidence was produced.

**Queue.** `REMAINING-AUDIT.txt` 167 -> **159**; `AUDITED-FILES.txt` 596 ->
**604**. **Next ordinary position.** `src/provider/slh_dsa_kmgmt.rs`. **Next
eight.** `src/provider/slh_dsa_kmgmt.rs`, `src/provider/slh_dsa_sig.rs`,
`src/provider/sm2_enc.rs`, `src/provider/sm2_sig.rs`,
`src/provider/stores.rs`, `src/provider/util.rs`, `src/punycode.rs`,
`src/quic_vlint.rs`.

## M70 (mechanism) — per-file contract sweep (SLH-DSA keymgmt/signature, SM2 asymmetric cipher/signature, provider store bridges, provider utility helpers, punycode, QUIC varint)

Receipt: [`atlas-refresh/mechanism-sweep-M70.json`](atlas-refresh/mechanism-sweep-M70.json).

**Candidate identity.** Worktree audit on `integrate/safe-c33` at source HEAD
`44e389df3`. Three files carry worktree repairs (two findings, one of them
class-wide): the SLH-DSA and
SM2 signature AlgorithmIdentifier builders now hand `WPACKET_cleanup` a zeroed
packet image, so the authority's unconditional cleanup is defined when
`WPACKET_init_der` refuses (its node-allocation refusal returns before writing
`subs`); and `ossl_quic_vlint_decode`'s `# Safety` contract no longer offers
NULL for a pointer the body unconditionally writes. One test-only negative
control was added. Layouts, exported symbols, signatures, allocation sizes and
`FILE` values are unchanged; no unsafe operation was removed, and the only
new production unsafe expressions are the two `core::mem::zeroed` calls that
replace the `MaybeUninit` declarations.

**Files audited (8).**

| File | Mechanisms checked | Result |
|---|---|---|
| `src/provider/slh_dsa_kmgmt.rs` | `SlhDsaGenCtx` zalloc/cleanup (`OwnedCtx`/`OwnedStr`), seed `entropy` copy and cleanse, export param-builder key copies and their cleanse, generated import/get/gen-set decoders, `load` detachment, twelve dispatch tables | no defect |
| `src/provider/slh_dsa_sig.rs` | `ProvSlhDsaCtx` zalloc/memdup/dup/free, `RawCtx`→`OwnedCtx` transition, `add_random` cleanse, stack `add_rand` cleanse, AlgorithmIdentifier builder, generated set/get decoders, borrowed key/alg | 1 medium-severity uninitialised-read/free class repaired (M70-D1) |
| `src/provider/sm2_enc.rs` | `ProvSm2Ctx` zalloc/dup/free split, borrowed `EC_KEY` refcount, `PROV_DIGEST` reset/copy, size-query returns, generated set/get decoders | no defect |
| `src/provider/sm2_sig.rs` | `ProvSm2SigCtx` zalloc/dup/free, `id`/`propq` ownership, `Z`-digest scratch, md/mdctx refcounts, AlgorithmIdentifier builder, distid and digest setters, md-params rows | 1 medium-severity uninitialised-read/free class repaired (M70-D1) |
| `src/provider/stores.rs` | nine method-store/cache bridges, slot read plus NULL test, absent-store return values, provider-context lookup | no defect |
| `src/provider/util.rs` | `PROV_CIPHER`/`PROV_DIGEST` reset/copy/fetch/load, engine narrowing, MAC context load, `ossl_prov_memdup` | no defect |
| `src/punycode.rs` | `ossl_punycode_decode` bounds/overflow refusals and `memmove` insert, `ossl_a2ulabel` label walk, WPACKET output, UTF-8 encoder buffer contract | no defect |
| `src/quic_vlint.rs` | encode length/body bounds, decode length and truncation refusal, pointer contracts | 1 low-severity unsafe-contract understatement repaired (M70-D2) |

**Defects.**

| ID | Location (pre-fix) | Severity | Class | Repair |
|---|---|---|---|---|
| M70-D1 | `src/provider/slh_dsa_sig.rs:389-402`, `src/provider/sm2_sig.rs:392-402` | medium | uninitialised read / invalid free on an allocation-failure path | both bodies build the packet with `MaybeUninit` but call `WPACKET_cleanup` unconditionally, exactly as the authority does. `WPACKET_init_der` also refuses when its `WPACKET_SUB` allocation fails, and on that arm it has written `curr`/`written` but not `subs`, so cleanup walked an uninitialised pointer. Each packet is now the all-zero `Wpacket` image (`subs` NULL, a valid value for every field), which `init_der` overwrites completely on success; a refusal now cleans up as an empty chain. No reachable success-path behaviour changes. |
| M70-D2 | `src/quic_vlint.rs:163-166` | low | unsafe-contract understatement | the `# Safety` text said `v` may be NULL, but the body dereferences it unconditionally (the authority does the same). It now requires `v` to be non-NULL and writable; the inline `SAFETY:` note matches. |

**Class finding outside this batch (not repaired here).** The same
failed-initialisation cleanup is present wherever the authority cleans up a
non-zeroed packet after a possibly-refused initialisation:
`src/provider/ecdsa_sig.rs:288-300`, `src/provider/dsa_sig.rs:259-311`,
`src/provider/eddsa_sig.rs:348-376`, `src/provider/ml_dsa_sig.rs:313-325`,
`src/provider/ml_kem_kmgmt.rs:1355-1373`, and `src/provider/kdf.rs:2114-2150`
(first-arm cleanup; the second `der_encode_sharedinfo` reuses a packet already
cleared) and `:4905-4923`. `rsa_sig.rs` and the `der_*` helpers are already
guarded. The root-cause repair is one line in
`src/packet.rs`'s `wpacket_intern_init_len` (clear `subs` before the node
allocation), which would cover every caller; because that is a shared
ownership mechanism it needs its own BOUNDARY sweep and independent review,
so it is queued rather than folded into this batch.

**Secret-bearing buffers.** SLH-DSA generation `entropy` (the caller-supplied
seed) is cleansed by `SlhDsaGenCtx::destroy_body` on `gen_cleanup` and on the
`gen_init` failure path; the export builder's private-key copy is cleansed
before `OSSL_PARAM_free` on the callback path. SLH-DSA signature contexts hold
`add_random` (cleansed in `destroy_body`) and the stack `add_rand` (cleansed
only when the provider drew it, which is the authority's own rule; the caller's
`test-entropy` is borrowed). The SLH-DSA private key is borrowed through
`EVP_PKEY` and released by its owner. SM2 contexts borrow the `EC_KEY`
(`EC_KEY_up_ref`/`EC_KEY_free`); the SM2 user ID and property query are public
metadata, released plainly. `sm2_enc`, `stores`, `util`, `punycode` and
`quic_vlint` hold no secret-bearing storage (`ossl_prov_memdup` copies a
caller's bucket, and its KDF callers own the cleanse).

**Assumptions.** Eliminated: 1 (the hidden "init_der cannot fail" precondition
on the cleanup). Relocated: 0. New: 0. Hidden: **0**. Unsafe expressions: two
production `core::mem::zeroed` calls replacing the `MaybeUninit` declarations
and one test-only `zeroed` in the control; no unsafe operation was removed. Contracts reused: OB-1
`OwnedBuf`, OB-2 `OwnedStr`, OB-3 `OwnedCtx`/`RawCtx`/`CtxDestroy` with the
zero-validity sweep, OB-4 member slots, RC-1 refcounts, the provider
`OSSL_CALLBACK` lifetime contract, the `WPACKET` init/cleanup contract and the
`CRYPTO_*` seam.

**Gates observed.** FAST `cargo fmt --all -- --check` clean; `cargo check --lib`
clean; focused `slh_dsa` 8/0, `sm2` 10/0, control
`provider::slh_dsa_sig::tests::a_refused_der_init_leaves_a_cleanable_packet`
1/0. BATCH `cargo clippy --all-targets -- -D warnings` clean; full library
**1674 passed / 0 failed / 27 ignored** threaded (`--test-threads=4`) in
102.23 s and serial (`--test-threads=1`) in 223.14 s, in the court with
`CARGO_BUILD_JOBS=4`. Targeted Miri on the control passed under both Stacked
Borrows and Tree Borrows (`nightly-2026-10-01`).

**NOT_RUN.** Allocator-failure injection exercising the repaired arm end to
end (no injection harness exists for `WPACKET_SUB`; the control reaches the
same early-return state through the argument refusal); authority differential
for the twelve SLH-DSA rows and the SM2 cipher/signature rows; ASan; constant-
time measurement (no secret-dependent control flow changed, no claim made);
dependency-graph regeneration; FRF suite and SEAL. The shared-callee repair
noted above is deliberately not attempted here and needs a BOUNDARY gate.

**Residuals.** (1) The eight files are audited, not `SAFETY_DISCHARGED`. (2)
`slh_dsa_signverify_msg_init` replaces `ctx->hash_ctx` without releasing the
previous one when an init with a key runs twice; that is the authority's own
leak, not UB, and is left for compatibility. (3) The class finding above
remains in six other files until the shared-callee repair is scheduled. (4)
`ossl_prov_memdup` leaves `*dest` untouched on allocation failure where the
authority writes NULL; no in-crate caller reads `*dest` after a 0 answer. (5)
The borrowed key and `alg`/`id` lifetimes are EVP caller obligations.

**Queue.** `REMAINING-AUDIT.txt` 159 -> **151**; `AUDITED-FILES.txt` 604 ->
**612**. **Next ordinary position.** `src/rand/pool.rs`. **Next eight.**
`src/rand/pool.rs`, `src/rand/prov_seed.rs`, `src/rand/rand_uniform.rs`,
`src/rand/sys.rs`, `src/rc2.rs`, `src/rc4.rs`, `src/rsa/asn1.rs`,
`src/rsa/backend.rs`.
