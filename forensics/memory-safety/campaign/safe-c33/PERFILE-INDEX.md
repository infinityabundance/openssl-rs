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
