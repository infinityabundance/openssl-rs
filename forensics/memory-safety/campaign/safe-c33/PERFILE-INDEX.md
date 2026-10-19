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

**Campaign progress: 9 of 761 PARTIAL files have full group records; a further
12 files have mechanism-contract sweeps (batch M1), 10 files have
mechanism-contract sweeps (batch M2), 11 files have mechanism-contract
sweeps (batch M3) and 12 files have mechanism-contract sweeps (batch M4),
none with full group records.** The 761 denominator is the
`PARTIAL` file population in `ATTRIBUTION.md`; it is not a
count of files that have graduated. The nine full records cover 6,252 production
unsafe sites in 2,949 groups. The M1–M4 sweeps are obligation checks over the
known owner/slot/member-buffer mechanisms, not the full `D###` enumeration.

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
