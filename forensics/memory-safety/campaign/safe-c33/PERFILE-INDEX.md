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
12 files have mechanism-contract sweeps (batch M1) and 10 files have
mechanism-contract sweeps (batch M2), neither with full group records.** The
761 denominator is the `PARTIAL` file population in `ATTRIBUTION.md`; it is not a
count of files that have graduated. The nine full records cover 6,252 production
unsafe sites in 2,949 groups. The M1 and M2 sweeps are obligation checks over the
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
