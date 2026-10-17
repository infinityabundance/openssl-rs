# Module-local ownership-owner duplicates in `src/`

**Status:** inventory and duplicate analysis only. **No consolidation performed.**
**Source identity:** `integrate/safe-c33` at `7771a1c4f` (working tree at audit time).
**Scope:** every `struct Owned*` / `struct Raw*` definition in `src/` (329 definitions).
Read-only audit: no `src/` edit, no build, no test run. All figures come from
`grep`/`sed`/`awk` over the working tree.

This document answers one question: *which of the many per-module owner types are
the same ownership mechanism copied into different files, and which only look
alike?* It does **not** claim any mechanism is `SAFETY_DISCHARGED` or that a
consumer family is `SAFE_COMPATIBLE`. Consolidation is a separate, reviewed change.

---

## 0. Summary

| family | definitions | shared/canonical | local | IDENTICAL | DIFFERENT | MUST-STAY-LOCAL |
|---|---:|---:|---:|---:|---:|---:|
| `OwnedBuf` | 127 | 0 | 127 | 117 | 10 | 0 |
| `OwnedStr` | 34 | 0 | 34 | 33 | 1 | 0 |
| `OwnedBlock` | 19 | 2 | 17 | 15 | 2 | 0 |
| `OwnedCtx` | 57 | 1 | 56 | 0 | 0 | 56 |
| `OwnedRaw` | 5 | 0 | 5 | 0 | 0 | 5 |
| `RawCtx` | 6 | 1 | 5 | 0 | 0 | 5 |
| other `Owned*`/`Raw*` | 81 | 0 | 81 | 8 | 13 | 60 |
| **total** | **329** | **4** | **325** | **173** | **26** | **126** |

* The 4 shared/canonical definitions are `runtime/bio/owned.rs` (`OwnedCtx`,
  `RawCtx`, `OwnedBlock`) and `asn1/owned.rs` (`OwnedBlock<T>`). They are the
  funnel targets, not duplicates, and are excluded from the class counts.
* 2 of the 81 "other" definitions (`RawKeyDetails`, `evp/pkey.rs:2333` and
  `evp/skeymgmt.rs:1111`) are **not owners**: they are borrowed pointer bundles
  with no `Drop`. They are classed `MUST-STAY-LOCAL` (and are not consolidation
  targets).
* Counts are of **definitions**, not files or unsafe blocks. A mechanism is one
  type's constructors + `Drop`, regardless of how many call sites use it.

### Classification rubric

* **IDENTICAL** — same field shape (including pointer class, stored-vs-constant
  coordinates, and cleansing length), same allocation seam, and same release
  semantics. Safe to funnel into one shared type; caller-visible API variance is
  called out in the group.
* **DIFFERENT** — same rough purpose but a semantic difference blocks pooling:
  cleansing/length, ownership transfer, NULL policy, coordinate mechanism, or a
  module-specific release call. The difference is listed.
* **MUST-STAY-LOCAL** — the type depends on a module-specific representation,
  destructor body/trait, ABI object, or an uninitialised-construction window. A
  shared type cannot express it without an abstraction the module does not have.

**Coordinate rule.** Owners store coordinates in one of three mechanisms:
`(file,line)` per instance, `line` per instance + module-constant file, or
compile-time constants. Two owners with the same mechanism are grouped even when
their literal authority `file`/`line` values differ (otherwise no two owners
could ever be pooled). Where pooling would change the coordinates a
caller-installed `CRYPTO_set_mem_functions` hook observes, that is recorded in
the group notes as a compatibility prerequisite (normally a per-module
`const FILE`/`const LINE` carrier).

Release abbreviations: `P` = `CRYPTO_free` (plain), `C` = `CRYPTO_clear_free`,
`SC` = `CRYPTO_secure_clear_free`, `SF` = `CRYPTO_secure_free`.

### Flagged findings (details in §9)

1. **Unsound safe adoption constructor (2 copies).**
   `ssl/statem/statem_clnt.rs:209` and `ssl/statem/statem_srvr.rs:238` define
   `fn new(ptr: *mut T) -> Option<OwnedCtx<T>>` as a **safe** ownership-adoption
   constructor with no `# Safety` contract. `Drop` calls
   `T::free_on_drop(ptr)`. Safe code in the module can pass an arbitrary,
   aliased, or already-freed pointer and cause an invalid free. Current call
   sites pass `*_new()` answers, so no observed UB — but the safe interface is
   unsound by AGENTS §1. **This is also the only "Drop can free memory it does
   not exclusively own" case found.**
2. All `take`/`adopt`/`adopt_cleansed`/`from_raw` constructors on owner types
   are `unsafe fn` and carry a `# Safety` section (scanned across `src/`; no
   exception found). One `unsafe fn new` (allocation, not adoption) exists at
   `property/strings.rs:187` and is correctly documented.
3. Arithmetic hardening (not an ownership defect): several safe sites compute
   `size_of::<T>() + len` without `checked_add` (`property/strings.rs:191`,
   `property/parse.rs:833,1244`, `property/store.rs:1266`,
   `ssl/ssl_sess.rs:1940`). AGENTS §3 requires checked arithmetic for
   allocation sizes; these should be hardened in a separate batch.

---

## 1. Canonical shared types (not counted as duplicates)

| file:line | type | fields | constructors | Drop | secret | notes |
|---|---|---|---|---|---|---|
| `runtime/bio/owned.rs:86` | `OwnedCtx<T: CtxDestroy>` | `NonNull<T>` | `zalloc() -> Option` (safe) | `destroy_body` + `P` at `T::FILE`,`T::LINE_FREE` | trait-defined | shared destructor trait (unsafe); no stored coordinates |
| `runtime/bio/owned.rs:147` | `RawCtx<T: CtxDestroy>` | `NonNull<MaybeUninit<T>>` | `malloc`/`zalloc -> Option`; `assume_init` unsafe | block-only `P` | no | uninitialised-construction window |
| `runtime/bio/owned.rs:217` | `OwnedBlock` | `*mut c_void` | `take` unsafe -> `Option` | `P(NULL,0)` | no | plain seam block |
| `asn1/owned.rs:36` | `OwnedBlock<T>` | `NonNull<T>`, `file`, `line` | `malloc`/`zalloc` (`checked_mul`), `from_raw` unsafe | `P(file,line)` | no | generic, checked arithmetic |

`runtime::bio::owned::{CtxDestroy, OwnedCtx, RawCtx, OwnedBlock}` is already
imported by ~70 files; the `OwnedCtx` copies in §5 are the files that did not
migrate to it (or need extra state).

---

## 2. `OwnedBuf` — 127 definitions

All are byte buffers allocated through `CRYPTO_malloc`/`CRYPTO_zalloc`
(`new` returns `Option`, NULL→`None`), and all adopt through an `unsafe fn`
(`take`/`adopt`/`adopt_cleansed`, all with `# Safety`). `Drop` is
`CRYPTO_free`/`CRYPTO_clear_free`/`CRYPTO_secure_*`. No `OwnedBuf` uses a
destructor body other than the allocator release.

### 2.1 `B-P` — `{ptr, file, line}` plain free — **IDENTICAL (52)**

* **Fields:** `ptr: *mut c_uchar` (or `*mut u8`; layout-identical), `file:
  *const c_char`, `line: c_int`. `cmp_hdr` names the stored line `release_line`
  and `provider/init` uses `*mut c_void`; same mechanism.
* **Constructors:** `new(len,file,line) -> Option` = `CRYPTO_malloc`; `take`/
  `adopt` unsafe. 15 of the 52 have an **infallible** `adopt -> Self` (the
  caller's `# Safety` says non-NULL) rather than `-> Option`; the owner still
  never needs to represent NULL and `Drop` tolerates it. Signature variance, not
  an ownership difference.
* **Drop:** `CRYPTO_free(self.ptr, self.file, self.line)`.
* **Secret:** no. **Cleansing length stored:** no.
* **Members (calls in same file):**
  `asn1/asn_mime.rs:185` (38), `asn1/bio_asn1.rs:100` (20), `asn1/text.rs:72`
  (13), `async/async.rs:87` (18), `cmp/cmp_hdr.rs:129` (10),
  `cmp/cmp_protect.rs:97` (8), `cmp/cmp_vfy.rs:122` (18),
  `crmf/crmf_pbm.rs:87` (7), `ct/ct_b64.rs:98` (12), `ct/ct_log.rs:359` (6),
  `ct/ct_oct.rs:117` (15), `ct/ct_sct_ctx.rs:242` (15), `ct/ct_sct.rs:288`
  (11), `decoder_pkey.rs:215` (31), `ec/key.rs:102` (9), `ec/print.rs:56` (9),
  `evp/evp_lib.rs:69` (7), `evp/mac.rs:149` (7), `hpke/mod.rs:1269` (9),
  `pkcs12/p12_decr.rs:78` (10), `pkcs7/pk7_smime.rs:130` (7),
  `property/store.rs:139` (10), `provider/dsa_sig.rs:187` (13),
  `provider/ecdsa_sig.rs:191` (13), `provider/init.rs:172` (6),
  `provider/ml_dsa_codecs.rs:411` (14), `provider/ml_kem_codecs.rs:444` (15),
  `provider/mod.rs:596` (27), `provider/rsa_enc.rs:211` (13),
  `provider/seed_src.rs:302` (9), `provider/sm2_sig.rs:149` (19),
  `rsa/pmeth.rs:219` (11), `runtime/conf/def.rs:167` (28),
  `runtime/confmod/mod.rs:179` (28), `runtime/str.rs:60` (7),
  `sm2/sign.rs:72` (12), `srp/srp_lib.rs:77` (9), `ssl/ssl_asn1.rs:95` (6),
  `ssl/ssl_cert_comp.rs:104` (12), `ssl/ssl_conf.rs:125` (9),
  `ssl/ssl_rsa.rs:876` (6), `ssl/t1_lib.rs:105` (11),
  `ssl/tls_srp.rs:65` (11), `ts/ts_rsp_sign.rs:168` (7),
  `txt_db/txt_db.rs:155` (17), `x509/v3_ncons.rs:186` (13),
  `x509/x509_req.rs:399` (9), `x509/x509spki.rs:45` (11),
  `x509/x509_vpm.rs:365` (13), `x509/x_name.rs:120` (6),
  `x509/x_pubkey.rs:206` (8), `x509/x_x509.rs:105` (6).

### 2.2 `B-L` — `{ptr, line}` plain free, constant file — **IDENTICAL (8)**

* **Fields:** `ptr: *mut c_uchar`/`*mut u8`/`*mut c_void`, `line: c_int`;
  file is a module constant.
* **Constructors:** `new(len,file,line) -> Option`; `adopt` unsafe.
* **Drop:** `P(self.ptr, FILE_CONST, self.line)`.
* **Secret:** no. **Length stored:** no.
* **Members:** `asn1/a_digest.rs:76` (10), `asn1/asn1_gen.rs:135` (13),
  `ec/depr.rs:55` (11), `provider/ml_dsa_sig.rs:174` (8),
  `ssl/ssl_ciph.rs:1204` (10), `x509/dane.rs:384` (9),
  `x509/v3_conf.rs:165` (14), `x509/v3_pci.rs:116` (8).

### 2.3 `B-Z` — `{ptr}` plain free, constant coordinates — **IDENTICAL (13)**

* **Fields:** `ptr` only (`*mut c_uchar`, `*mut u8`, `*mut c_char`, or
  `NonNull<u8>`/`NonNull<c_uchar>`); coordinates are compile-time constants.
* **Constructors:** `new` (`CRYPTO_malloc`) where present; `adopt`/`take` unsafe.
* **Drop:** `P(ptr, CONST_FILE, CONST_LINE)`.
* **Secret:** no. **Length stored:** no.
* **Note:** 5 members release at `(NULL, 0)`
  (`provider/decode_der2key`, `encode_key2any`, `encode_key2text`,
  `provider/util`, `decode_msblob2key`); 8 use a module constant
  `FILE`/`LINE`. A shared type must carry the constant (e.g. associated consts);
  hardcoding `(NULL,0)` would change the site observed by an allocator hook.
* **Members:** `asn1/a_dup.rs:52` (10), `bn/intern.rs:113` (7),
  `dh/key.rs:119` (8), `evp/fetch.rs:121` (8), `ffc/params.rs:95` (17),
  `provider/decode_der2key.rs:500` (6), `provider/encode_key2any.rs:324` (13),
  `provider/encode_key2text.rs:131` (8), `provider/util.rs:665` (6),
  `rand/prov_seed.rs:68` (6), `params/from_text.rs:57` (6),
  `rsa/gen.rs:112` (6), `provider/decode_msblob2key.rs:168` (6).

### 2.4 `B-CA-FL` — `{ptr, len, file, line}`, always cleanse — **IDENTICAL (5)**

* **Fields:** `ptr`, `len`/`num: usize`, `file`, `line`.
* **Constructors:** `new` (`CRYPTO_malloc`), `adopt_cleansed`/`take` unsafe.
* **Drop:** `C(ptr, len, file, line)` unconditionally.
* **Secret:** yes (always cleansed). **Cleansing length stored:** yes.
* **Members:** `asn1/a_sign.rs:111` (17), `asn1/a_verify.rs:90` (9),
  `ec/ecx_meth.rs:109` (7 — field named `num`), `provider/keymgmt.rs:625` (7),
  `rsa/sign.rs:81` (14).

### 2.5 `B-CA-0` — `{ptr, len}`, always cleanse, constant coordinates — **IDENTICAL (5)**

* **Fields:** `ptr`, `len`/`num`; coordinates constant.
* **Drop:** `C(ptr, len, CONST_FILE, CONST_LINE)`.
* **Secret:** yes. **Length stored:** yes.
* **Members:** `asn1/t_pkey.rs:51` (6), `bn/rand.rs:149` (8),
  `dsa/sign.rs:149` (6), `rsa/ossl.rs:177` (9 — `num`),
  `slh_dsa/dsa.rs:537` (8).

### 2.6 `B-CF-FL` — `{ptr, len, file, line, bool}`, conditional cleanse — **IDENTICAL (3)**

* **Fields:** `ptr`, `len`, `file`, `line`, and a `clear`/`cleanse: bool`
  selecting plain vs cleansing release.
* **Constructors:** `new` (`CRYPTO_malloc`), `adopt`/`take` unsafe; a setter or
  constructor flag turns cleansing on after the buffer is filled.
* **Drop:** `C(ptr,len,file,line)` if flag else `P(ptr,file,line)`.
* **Secret:** yes, when the flag is set. **Length stored:** yes.
* **Members:** `evp/evp_pkey.rs:71` (7), `evp/pem_bridge.rs:280` (10),
  `rsa/ameth.rs:115` (9).

### 2.7 `B-R1a` — `{ptr, release}` enum `Plain{file,line} | Cleansed{num,file,line}` — **IDENTICAL (13)**

* **Fields:** `ptr`, `release: BufRelease`.
* **Constructors:** `new` (`CRYPTO_malloc`) defaults `Plain`; `take`/`adopt`
  unsafe, often `-> Option`; cleansing enabled by constructing the `Cleansed`
  variant.
* **Drop:** match: `P(file,line)` / `C(num,file,line)`. NULL tolerated.
* **Secret:** yes (variant-selected). **Length stored:** yes (in `Cleansed`).
* **Members:** `apps/kdf.rs:107` (9), `dh/ameth.rs:114` (13),
  `dh/pmeth.rs:165` (10), `dsa/ameth.rs:86` (10), `ec/asn1.rs:138` (18),
  `ec/pmeth.rs:165` (10), `evp/kdf.rs:120` (9), `http/http_client.rs:779` (49),
  `params/mod.rs:97` (15), `provider/dsa_kmgmt.rs:174` (16),
  `provider/ec_kmgmt.rs:222` (23), `provider/ecx_kmgmt.rs:256` (15),
  `rsa/pss.rs:96` (9).

### 2.8 `B-R1b` — `{ptr, release}` enum `Plain{file,line} | Cleansed{num}` — **IDENTICAL (14)**

* Same as `B-R1a`, except the `Cleansed` variant stores only `num`; the file is
  a module constant (the authority's `OPENSSL_clear_free(ptr,num)` wrapper).
* **Drop:** `P(file,line)` / `C(ptr,num,CONST_FILE,CONST_LINE)`.
* **Members:** `cms/cms_dh.rs:77` (19), `cms/cms_ec.rs:83` (16),
  `cms/cms_enc.rs:65` (14), `cms/cms_env.rs:111` (15),
  `cms/cms_ess.rs:65` (10), `cms/cms_kari.rs:55` (12),
  `cms/cms_kemri.rs:60` (14), `cms/cms_pwri.rs:53` (13),
  `cms/cms_rsa.rs:72` (10), `cms/cms_sd.rs:127` (17),
  `ec/ameth.rs:97` (20), `pkcs7/pk7_doit.rs:117` (23),
  `rsa/mod.rs:1336` (12), `srp/srp_vfy.rs:140` (29).

### 2.9 `B-R3` — `{ptr, release}` with `SecureCleansed` — **IDENTICAL (4)**

* **Fields/enum:** `Plain{file,line} | Cleansed{num,file,line} |
  SecureCleansed{num,file,line}`.
* **Drop:** `P` / `C` / `SC`.
* **Secret:** yes. **Length stored:** yes.
* **Members:** `provider/ecdh_exch.rs:145` (17), `provider/exchange.rs:90` (18),
  `provider/ml_kem_kmgmt.rs:195` (26), `provider/mlx_kmgmt.rs:277` (21).

### 2.10 `OwnedBuf` definitions classed **DIFFERENT** (10)

| file:line | calls | fields | difference |
|---|---:|---|---|
| `apps/mac.rs:84` | 6 | `{ptr, release}` `Plain` only | release enum has no cleansing arm; singleton variant |
| `ml_dsa/key.rs:150` | 32 | `{ptr, release}` `Plain`/`Cleansed`/`Secure`/`SecureCleansed`, all with file+line | superset of `B-R3`; singleton |
| `ml_kem/key.rs:106` | 27 | `{ptr, release}` `Plain`/`Secure`/`SecureCleansed` | no `Cleansed` arm; singleton |
| `provider/mac_legacy_kmgmt.rs:215` | 17 | `{ptr, release}` `Plain{file,line}`/`Secure{num,file,line}` | the `Secure` arm calls `SC`, not `SF`; singleton |
| `rand/pool.rs:169` | 11 | `{ptr, release}` `SecureCleansed`/`Cleansed` | no plain arm (pool blocks are always secret); singleton |
| `ml_dsa/sign.rs:108` | 7 | `{ptr, len, line_free, release: Release{Cleansed,Plain}}` | length in a field, release enum carries no payload; coordinates constant; singleton |
| `ml_dsa/encoders.rs:97` | 11 | `{NonNull<u8>, len, file, line, secure: bool}` | `NonNull` + a `secure` flag selecting secure vs plain heap; duplicates `B-CF` only if extended |
| `pem/pvkfmt.rs:146` | 17 | `{ptr, len, clear: bool}` | constant coordinates; conditional cleanse |
| `provider/kdf.rs:418` | 12 | `{ptr, len, file, clear: bool}` | no per-instance line (constant); conditional cleanse |
| `pkcs12/p12_utl.rs:62` | 9 | `{ptr, len, file, line}` | stores `len` but `Drop` is plain `P`; the length is not a cleansing length |

---

## 3. `OwnedStr` — 34 definitions

All release with plain `CRYPTO_free` and store **no** cleansing length. All are
non-secret string blocks. `take`/`adopt` are `unsafe fn` with `# Safety`; most
return `Option`, `dso/dlfcn.rs:135` returns `Self` (NULL tolerated by `Drop`).

### 3.1 `S-P` — `{ptr, file, line}` — **IDENTICAL (10)**

* `ptr: *mut c_char`; `Drop: P(ptr,file,line)`.
* Members: `cmp/cmp_client.rs:81` (7), `cmp/cmp_ctx.rs:54` (11),
  `cmp/cmp_genm.rs:60` (6), `ct/ct_log.rs:314` (9),
  `ct/ct_sct_ctx.rs:201` (6), `dso/mod.rs:330` (10),
  `provider/init.rs:136` (12), `provider/keymgmt.rs:585` (11),
  `provider/ml_dsa_kmgmt.rs:155` (8), `provider/slh_dsa_kmgmt.rs:126` (8).

### 3.2 `S-L` — `{ptr, line}`, constant file — **IDENTICAL (13)**

* `Drop: P(ptr, CONST_FILE, line)`.
* Members: `cmp/cmp_asn.rs:1610` (8), `engine/eng_dyn.rs:309` (19),
  `http/http_lib.rs:142` (8), `rand/rand_lib.rs:318` (21),
  `runtime/conf/conf_ssl.rs:140` (9), `ui/ui_lib.rs:426` (33),
  `x509/t_x509.rs:275` (6), `x509/v3_akid.rs:186` (7),
  `x509/v3_asid.rs:136` (9), `x509/v3_info.rs:122` (7),
  `x509/v3_purp.rs:550` (9), `x509/v3_san.rs:98` (8),
  `x509/x509_trust.rs:284` (7).

### 3.3 `S-Z` — `{ptr}`, constant coordinates — **IDENTICAL (10)**

* `Drop: P(ptr, CONST_FILE, CONST_LINE)`.
* Members: `decoder_meth.rs:731` (7), `dh/mod.rs:463` (9),
  `dsa/mod.rs:471` (9), `dso/dlfcn.rs:126` (6),
  `runtime/bio/addr_info.rs:170` (8), `runtime/bio/addr.rs:210` (9),
  `runtime/bio/bio_sock2.rs:78` (16), `runtime/conf/api.rs:271` (9),
  `runtime/conf/modparse.rs:90` (13), `slh_dsa/key.rs:117` (8).

### 3.4 `S-NL` — **DIFFERENT (1)**

`x509/v3_addr.rs:2120` (9): `{ptr: NonNull<c_char>, line}`. `NonNull` is the
difference (no NULL state); `Drop: P(ptr, CONST_FILE, line)`. Otherwise the same
mechanism as `S-L`.

---

## 4. `OwnedBlock` — 19 definitions (17 local)

### 4.1 `OB-P` — `{ptr, file, line}` plain free — **IDENTICAL (8)**

* `ptr: *mut c_void`/`*mut u8`; `new`/`take` (unsafe) or `from_raw` (unsafe);
  `Drop: P(ptr,file,line)`.
* Members: `evp/e_aes.rs:110` (11), `evp/e_aria.rs:96` (11),
  `ec/smpl.rs:86` (7), `property/parse.rs:762` (14), `ssl/ssl_lib.rs:702` (10),
  `ssl/statem/statem_clnt.rs:279` (6), `ssl/statem/statem_srvr.rs:321` (10),
  `x509/v3_utl.rs:196` (24).

### 4.2 `OB-Cond` — `{ptr, len, clear, file, line}` — **IDENTICAL (4)**

* `take`/`from_raw` unsafe; `Drop` selects `C(ptr,len,file,line)` vs
  `P(ptr,file,line)` from `clear`. Secret when `clear`; length stored.
* Members: `evp/digest.rs:304` (11), `evp/pkey_ctx.rs:343` (10),
  `evp/pkey.rs:517` (11), `crmf/crmf_lib.rs:1579` (21).

### 4.3 `OB-Z` — `{ptr}` plain free, constant coordinates — **IDENTICAL (3)**

* `Drop: P(ptr, CONST_FILE, CONST_LINE)`; `take` unsafe.
* Members: `asn1/string.rs:49` (15), `provider/file_store.rs:313` (12),
  `store/store_lib.rs:220` (11).
* Note: `provider/file_store` and `store_lib` release at `(NULL,0)` and are
  directly compatible with `runtime::bio::owned::OwnedBlock`; `asn1/string`
  uses a module `FILE`/`LINE` constant and needs that coordinate preserved.

### 4.4 DIFFERENT (2)

| file:line | calls | fields | difference |
|---|---:|---|---|
| `evp/asymcipher.rs:305` | 6 | `{ptr, len, file, line}` | always `C` (no plain arm), so `len` is mandatory — not the conditional `OB-Cond` |
| `runtime/rcu.rs:269` | 22 | `OwnedBlock<T> {NonNull<T>, line}` | generic element type + only `line`; `Drop: P(ptr, CONST_FILE, line)` |

---

## 5. `OwnedCtx` — 57 definitions (56 local, 1 shared)

Every local copy is bound to a **module-local** `unsafe trait CtxDestroy` (or
`FreeOnDrop`/`GcmDestroy`/…). `DESTRUCTOR-CONTRACTS.md` records 42 `CtxDestroy`
definitions (1 shared + 41 local). The structs are structurally near-identical,
but the *trait identity* is module-specific, so none can be pooled into the
shared type without unifying the trait first. They are therefore
**MUST-STAY-LOCAL** here; they are **not** listed as consolidation candidates.

### 5.1 `CO-FL` — `{NonNull<T>, file, line}`, local `CtxDestroy` (25)

Constructors: `new`/`new_zeroed`/`zalloc` (`CRYPTO_zalloc -> Option`);
`from_raw` unsafe → `Option`; `Drop: T::destroy_body(ptr)` then
`P(ptr,file,line)`. Secret/cleansing: the trait body owns member cleansing; the
owner itself stores no length.

`async/async_wait.rs:118` (15), `ct/ct_log.rs:212` (22),
`ct/ct_sct_ctx.rs:130` (14), `ct/ct_sct.rs:219` (14), `dso/mod.rs:225` (14),
`engine/eng_dyn.rs:385` (9), `evp/asymcipher.rs:228` (15),
`evp/digest.rs:251` (21), `evp/exchange.rs:127` (12),
`evp/pkey_ctx.rs:285` (23), `evp/pkey.rs:417` (10),
`provider/keymgmt.rs:460` (20), `rand/rand_lib.rs:388` (9),
`ssl/ssl_lib.rs:582` (35), `ssl/ssl_sess.rs:201` (19),
`x509/by_dir.rs:252` (25), `x509/by_store.rs:223` (20),
`x509/v3_lib.rs:221` (15), `x509/v3_purp.rs:435` (12),
`x509/v3_utl.rs:159` (11), `x509/x509_lu.rs:584` (24),
`x509/x509_trust.rs:175` (12), `x509/x509_vfy.rs:257` (16),
`x509/x509_vpm.rs:282` (16), `x509/x_crl.rs:215` (16).

### 5.2 `CO-0` — `{NonNull<T>}`, local `CtxDestroy`, constant coords (12)

Constructors `new`/`zalloc` -> `Option`, `from_raw` unsafe; `Drop` =
`destroy_body` then `P(ptr, CONST_FILE, CONST_LINE)`.

`ec/ecx_key.rs:150` (13), `provider/conf.rs:198` (14),
`provider/decode_der2key.rs:557` (11), `provider/ec_kem.rs:200` (13),
`provider/ecx_kmgmt.rs:203` (15), `provider/encode_key2any.rs:403` (14),
`provider/file_store.rs:260` (15), `provider/mac_legacy_kmgmt.rs:162` (18),
`provider/seed_src.rs:247` (18), `provider/skeymgmt.rs:136` (13),
`provider/slh_dsa_sig.rs:179` (18), `store/store_lib.rs:165` (30).

### 5.3 `CO-other-generic` — module-specific trait bound/extra state (13)

| file:line | calls | fields / bound | difference from shared |
|---|---:|---|---|
| `ec/lib.rs:148` | 34 | `{NonNull<T>, file, line, cleansing: bool}`, local `CtxDestroy` | runtime cleansing flag |
| `evp/bio_enc.rs:189` | 18 | `{NonNull<T>, file, line, cleansed: bool}`, local `CtxDestroy` | runtime cleansing flag |
| `provider/cipher_gcm.rs:1718` | 25 | `{NonNull<T>}`, `GcmDestroy` | module trait, constant coords |
| `provider/cipher.rs:481` | 96 | `{NonNull<T>}`, `CipherDestroy` | module trait, constant coords |
| `provider/digest.rs:321` | 27 | `{NonNull<T>}` — **no trait bound** | destructor supplied by free-function pointer at use site |
| `provider/kdf.rs:363` | 59 | `{NonNull<T>}`, `KdfDestroy` | module trait |
| `provider/legacyprov.rs:212` | 15 | `{NonNull<T>}` — **no trait bound** | free-function destructor |
| `provider/mac.rs:247` | 43 | `{NonNull<T>}`, `MacDestroy` | module trait |
| `provider/rand.rs:269` | 26 | `{NonNull<T>}`, `DrbgCtx` | module trait |
| `provider/sm2_enc.rs:118` | 16 | `{NonNull<T>, line_free}`, local `CtxDestroy` | release line per handle |
| `ssl/statem/statem_clnt.rs:203` | 10 | `{NonNull<T>}`, `FreeOnDrop` | wraps a `*_new` object, not a zalloc block |
| `ssl/statem/statem_srvr.rs:232` | 15 | `{NonNull<T>}`, `FreeOnDrop` | same |
| `ui/ui_lib.rs:320` | 25 | `{NonNull<T>, line}`, local `CtxDestroy` | release line per handle |

### 5.4 `CO-concrete` — non-generic context owners (6)

| file:line | calls | fields | Drop |
|---|---:|---|---|
| `bn/blinding.rs:163` | 9 | `{ptr: *mut Blinding}` | frees members + `P` (constant) |
| `evp/bio_ok.rs:253` | 12 | `{ptr: *mut BioOkCtx}` | `EVP_MD_CTX_free` + `C` |
| `hpke/mod.rs:1205` | 11 | `{NonNull<OsslHpkeCtx>, line}` | `destroy_ctx_body` + `C` |
| `provider/decode_msblob2key.rs:114` | 9 | `{NonNull<Msblob2keyCtx>}` | `P(NULL,0)` |
| `provider/ecx_exch.rs:94` | 12 | `{NonNull<ProvEcxCtx>}` | frees key/peerkey + `P` |
| `provider/mac_legacy_sig.rs:109` | 12 | `{NonNull<ProvMacCtx>, propq_line, block_line}` | frees members + `P` at two sites |

---

## 6. `OwnedRaw` — 5 definitions — **MUST-STAY-LOCAL**

Raw (possibly not-yet-valid) context storage; `Drop` releases the block only or
runs a module-specific destroy body.

| file:line | calls | fields | constructor / Drop |
|---|---:|---|---|
| `provider/cipher_gcm.rs:1777` | 8 | `{NonNull<T>}`, `GcmDestroy` | `adopt` unsafe → `Option`; module destroy |
| `provider/cipher.rs:546` | 12 | `{NonNull<T>}`, `CipherDestroy` | `adopt` unsafe → `Option`; module destroy |
| `provider/mac.rs:318` | 9 | `{NonNull<T>}`, `MacDestroy` | `adopt` unsafe → `Option`; module destroy |
| `provider/rand.rs:322` | 7 | `{NonNull<T>}`, `DrbgCtx` | `adopt` unsafe → `Option`; module destroy |
| `ui/ui_lib.rs:382` | 10 | `{NonNull<T>, line}` | `new` (`zalloc`) / `from_raw` unsafe; block + line |

---

## 7. `RawCtx` — 6 definitions (5 local, 1 shared) — **MUST-STAY-LOCAL**

The uninitialised-construction window (`NonNull<MaybeUninit<T>>` or
`NonNull<T>` held without field reads), `Drop` releases the block **alone** and
never runs a destructor body. This is a semantic difference from `OwnedCtx`
that must not be erased.

| file:line | calls | fields | notes |
|---|---:|---|---|
| `runtime/bio/owned.rs:147` | — | `{NonNull<MaybeUninit<T>>}` | shared canonical; `assume_init` unsafe |
| `ssl/ssl_lib.rs:647` | 22 | `{NonNull<MaybeUninit<T>>, file, line}` | local; same transition |
| `evp/bio_ok.rs:206` | 8 | `{ptr: *mut BioOkCtx}` | concrete; block-only |
| `provider/ecx_exch.rs:157` | 7 | `{NonNull<ProvEcxCtx>, line}` | concrete; block-only |
| `provider/slh_dsa_sig.rs:258` | 7 | `{NonNull<T>}`, local `CtxDestroy` | block-only |
| `provider/sm2_enc.rs:175` | 7 | `{NonNull<T>, line_free}`, local `CtxDestroy` | block-only |

---

## 8. Other `Owned*`/`Raw*` owners — 81 definitions

`I` = IDENTICAL, `D` = DIFFERENT, `M` = MUST-STAY-LOCAL. Fields are abbreviated.
"Drop" names the release call; all release once.

| file:line | type | fields | Drop | calls | class |
|---|---|---|---:|---:|---|
| `asn1/a_strnid.rs:76` | `OwnedRow` | `*mut Asn1StringTable` | `P` const | 5 | M |
| `async/arch/async_posix.rs:260` | `OwnedFibre` | `*mut c_void` | `P` const | 5 | M |
| `async/async_wait.rs:204` | `OwnedFdLookup` | `*mut FdLookup,file,line` | `P` | 6 | M |
| `bn/primes.rs:1326` | `OwnedMods` | `NonNull<PrimeT>,file,line` | `P` | 4 | M |
| `cms/cms_smime.rs:817` | `OwnedChainArray` | `*mut *mut Stack,count` | pop-free + `P` | 4 | M |
| `dh/backend.rs:546` | `OwnedDh` | `*mut Dh` (test) | `DH_free` | 8 | M |
| `dh/mod.rs:374` | `RawMethod` | `NonNull<DhMethod>` | `P` const | 5 | M |
| `dh/mod.rs:425` | `OwnedMethod` | `NonNull<DhMethod>` | name + `P` | 4 | M |
| `dsa/backend.rs:447` | `OwnedDsa` | `*mut Dsa` (test) | `DSA_free` | 8 | M |
| `dsa/mod.rs:382` | `RawMethod` | `NonNull<DsaMethod>` | `P` const | 5 | M |
| `dsa/mod.rs:433` | `OwnedMethod` | `NonNull<DsaMethod>` | name + `P` | 4 | M |
| `dsa/object.rs:857` | `OwnedDsa` | `*mut Dsa` (test) | `DSA_free` | 5 | M |
| `dsa/sign.rs:119` | `OwnedBufMem` | `NonNull<BufMem>` | `BUF_MEM_free` | 4 | D |
| `dsa/sign.rs:70` | `OwnedSig` | `NonNull<DsaSig>` | r,s + `P` | 5 | M |
| `ec/ecdh_ossl.rs:59` | `OwnedSecretBuf` | `*mut c_uchar` | `P` const | 4 | D |
| `ec/ecx_backend.rs:123` | `OwnedDupKey` | `NonNull<EcxKey>` | `ossl_ecx_key_free` | 5 | M |
| `ec/ecx_backend.rs:76` | `RawDupKey` | `NonNull<EcxKey>` | `P` const | 4 | M |
| `ec/ecx_key.rs:191` | `RawEcxKey` | `NonNull<EcxKey>` | `P` const (propq) | 4 | M |
| `ec/kmeth.rs:118` | `OwnedEcKeyMethod` | `NonNull<EcKeyMethod>` | `P` const | 5 | M |
| `ec/kmeth.rs:171` | `OwnedSecret` | `*mut u8,len` | `C` const | 4 | D |
| `ec/kmeth.rs:75` | `OwnedEcKey` | `NonNull<EcKey>` | `EC_KEY_free` | 4 | M |
| `ec/print.rs:112` | `OwnedClearBuf` | `*mut c_uchar,len,file,line` | `C` | 4 | D |
| `engine/eng_dyn.rs:440` | `RawDataCtx` | `NonNull<DynamicDataCtx>` | dirs + `P` | 4 | M |
| `engine/eng_lib.rs:248` | `RawEngine` | `NonNull<Engine>` | `P` const | 4 | M |
| `engine/eng_lib.rs:292` | `OwnedEngine` | `NonNull<Engine>,not_locked` | full destructor | 4 | M |
| `engine/eng_lib.rs:547` | `OwnedItem` | `NonNull<EngineCleanupItem>` | `P` const | 5 | M |
| `evp/e_chacha20_poly1305.rs:152` | `OwnedAeadBlock` | `*mut Ctx,len` | `C` | 5 | D |
| `evp/evp_pbe.rs:444` | `OwnedPbeCtl` | `*mut EvpPbeCtl` | `P` const | 4 | M |
| `evp/exchange.rs:191` | `OwnedKey` | `*mut u8,len,KeyRelease` | `P`/`C` (line only) | 4 | D |
| `evp/keymgmt_lib.rs:133` | `OwnedCacheElem` | `*mut OpCacheElem,line` | `P` | 5 | M |
| `evp/pkey.rs:2333` | `RawKeyDetails` | borrowed out-params | **none** | 3 | M |
| `evp/pkey.rs:474` | `RawPkey` | `NonNull<EvpPkey>` | `P` alloc site | 4 | M |
| `evp/rand.rs:363` | `OwnedRandCtx` | `NonNull<EvpRandCtx>,line,destruct` | destruct body + `P` | 5 | M |
| `evp/skeymgmt.rs:1111` | `RawKeyDetails` | borrowed out-params | **none** | 3 | M |
| `evp/skeymgmt.rs:276` | `OwnedSkey` | `NonNull<EvpSkey>,line,destruct` | destruct body + `P` | 5 | M |
| `packet.rs:107` | `OwnedSub` | `*mut WpacketSub` | `P` const | 6 | M |
| `params/build.rs:114` | `OwnedDef` | `*mut ParamBldDef` | `P` const | 6 | M |
| `params/dup.rs:111` | `OwnedParamBlock` | `*mut u8,sz,secure` | `SC`/`P` | 5 | D |
| `pem/pem_lib.rs:392` | `OwnedDer` | `*mut c_uchar,num,line` | `C` | 4 | D |
| `pkcs12/p12_key.rs:87` | `OwnedUniPass` | `*mut c_uchar,len,line` | `C` const file | 4 | I |
| `property/defn_cache.rs:95` | `OwnedElem` | `*mut Elem,release_line` | `P` | 5 | M |
| `property/strings.rs:120` | `OwnedData` | `*mut PropertyStringData` | dedicated free | 4 | M |
| `property/strings.rs:175` | `OwnedString` | `*mut PropertyString` | `P` const | 4 | D |
| `provider/conf.rs:240` | `RawProviderConf` | `NonNull<ProviderConfGlobal>` | `P` err | 4 | M |
| `provider/ec_kem.rs:249` | `OwnedSecret` | `*mut u8,len,line` | `C` const file | 4 | D |
| `provider/ecx_kem.rs:126` | `OwnedIkm` | `*mut u8,len,line` | `C` const file | 4 | I |
| `provider/encode_key2text.rs:167` | `OwnedClearBuf` | `*mut c_uchar,len` | `C` const | 5 | D |
| `provider/keymgmt.rs:549` | `RawDhGenCtx` | `NonNull<DhGenCtx>` | `P` err | 4 | M |
| `provider/mac.rs:356` | `OwnedScratch` | `NonNull<c_uchar>,file` | `P` const line | 4 | I |
| `provider/rand.rs:359` | `OwnedScratch` | `NonNull<c_char>,file` | `P` const line | 4 | I |
| `provider/rsa_sig.rs:365` | `OwnedRsaCtx` | `NonNull<ProvRsaCtx>` | member body + `C` | 5 | M |
| `rand/rand_lib.rs:451` | `RawGlobal` | `NonNull<RandGlobal>` | `P` err | 4 | M |
| `rsa/backend.rs:1379` | `OwnedRsa` | `*mut Rsa` (test) | `RSA_free` | 5 | M |
| `rsa/backend.rs:870` | `OwnedPrimeInfo` | `*mut RsaPrimeInfo` | multip_info_free | 4 | M |
| `runtime/bio/addr_info.rs:99` | `OwnedNode` | `NonNull<BioAddrInfo>` | addr + `P` | 5 | M |
| `runtime/bio/addr.rs:147` | `OwnedAddr` | `NonNull<BioAddr>` | `P` const | 5 | M |
| `runtime/bio/bss_log.rs:40` | `OwnedLogBuf` | `*mut c_char` | `P` const | 4 | I |
| `runtime/buffer.rs:72` | `OwnedData` | `*mut c_char,num,secure` | `SC`/`C` | 4 | D |
| `runtime/conf/api.rs:198` | `OwnedValue` | `NonNull<ConfValue>,ValueRelease` | member body + `P` | 5 | M |
| `runtime/conf/conf_ssl.rs:179` | `OwnedStore` | `*mut SslConfName,count` | two arrays + `P` | 5 | M |
| `runtime/err.rs:531` | `OwnedSlotBuf` | `*mut c_char` | `P` const | 5 | I |
| `runtime/err.rs:621` | `OwnedErrState` | `NonNull<ErrState>` | members + `P` | 5 | M |
| `runtime/init.rs:907` | `OwnedInitStop` | `NonNull<OpenSslInitStop>` | `P` const | 10 | M |
| `runtime/sparse_array.rs:156` | `OwnedNode` | `NonNull<Node>` | `P` const | 17 | M |
| `runtime/thread_arch.rs:191` | `OwnedThreadHandle` | `NonNull<c_ulong>` | `P` const | 5 | M |
| `slh_dsa/hash_ctx.rs:47` | `OwnedHashCtx` | `*mut SlhDsaHashCtx` | dedicated free | 4 | M |
| `ui/ui_util.rs:80` | `OwnedPwData` | `NonNull<PemPasswordCbData>` | `P(NULL,0)` | 5 | M |
| `x509/by_dir.rs:317` | `RawDir` | `NonNull<ByDir>` | `P` err | 4 | M |
| `x509/pcy_node.rs:166` | `OwnedNode` | `NonNull<X509PolicyNode>` | `P` const | 5 | M |
| `x509/pcy_tree.rs:191` | `OwnedLevels` | `NonNull<X509PolicyLevel>` | `P` const | 5 | M |
| `x509/pcy_tree.rs:247` | `OwnedTree` | `NonNull<X509PolicyTree>` | members + `P` | 5 | M |
| `x509/t_x509.rs:228` | `OwnedDerBuf` | `*mut c_void,line` | `P` const | 4 | D |
| `x509/v3_asid.rs:178` | `RawRange` | `NonNull<AsRange>` | `P` err | 4 | M |
| `x509/v3_prn.rs:69` | `OwnedExtValue` | `*mut c_char` | `P` const | 4 | I |
| `x509/v3_purp.rs:502` | `RawPurpose` | `NonNull<X509Purpose>` | `P` err | 4 | M |
| `x509/v3_sxnet.rs:73` | `OwnedI2s` | `*mut c_char` | `P` const | 4 | I |
| `x509/x509_lu.rs:649` | `RawLookup` | `NonNull<X509Lookup>` | `P` err | 4 | M |
| `x509/x509_lu.rs:698` | `RawStore` | `NonNull<X509Store>` | members + `P` | 4 | M |
| `x509/x509_meth.rs:114` | `OwnedMethod` | `NonNull<X509LookupMethod>` | members + `P` | 4 | M |
| `x509/x509_meth.rs:64` | `RawMethod` | `NonNull<X509LookupMethod>` | `P` err | 4 | M |
| `x509/x509_trust.rs:237` | `RawTrust` | `NonNull<X509Trust>` | `P` err | 4 | M |

### 8.1 IDENTICAL sub-groups inside §8

* **`OwnedSecret`-with-line / `OwnedUniPass`** (2): `provider/ecx_kem.rs:126`,
  `pkcs12/p12_key.rs:87` — `{ptr,len,line}`, `C` with constant file. Both store
  the exact cleansing length. (Distinct from `ec/kmeth::OwnedSecret`, which has
  no line and a constant site.)
* **`OwnedScratch`** (2): `provider/mac.rs:356`, `provider/rand.rs:359` —
  `{NonNull, ptr, file}`, plain `P` with a constant line. One allocates via
  `CRYPTO_malloc`, the other via `CRYPTO_strndup`; both are the same seam and
  release.
* **constant-`char*` block owners** (4): `runtime/bio/bss_log.rs:40`,
  `runtime/err.rs:531`, `x509/v3_prn.rs:69`, `x509/v3_sxnet.rs:73` —
  `{ptr: *mut c_char}`, plain `P` at a module constant. Pooling requires
  preserving each release site.

---

## 9. Flagged findings

### 9.1 Unsound safe adoption constructor (must fix)

**Locations:** `src/ssl/statem/statem_clnt.rs:209`,
`src/ssl/statem/statem_srvr.rs:238`.

```rust
impl<T: FreeOnDrop> OwnedCtx<T> {
    /// Own a `*_new` answer, or `None` when it answered NULL.
    fn new(ptr: *mut T) -> Option<OwnedCtx<T>> {      // SAFE, no # Safety
        core::ptr::NonNull::new(ptr).map(|ptr| OwnedCtx { ptr })
    }
}
impl<T: FreeOnDrop> Drop for OwnedCtx<T> {
    fn drop(&mut self) { unsafe { T::free_on_drop(self.ptr.as_ptr()) } }
}
```

* This is an **ownership-adoption constructor** (raw pointer → owning handle)
  with a **safe** signature. AGENTS §1 requires `unsafe fn` + a `# Safety`
  contract establishing provenance, allocation identity/extent, exclusive
  ownership and the exact release. None is present.
* Reachability: the type and method are module-private, so only safe code in the
  same module can call it today. That is still a soundness bug: a safe caller
  can pass any `*mut T` (including an aliased, interior, or already-freed
  pointer) and `Drop` will run `T::free_on_drop` on it. “All current call sites
  are correct” does not discharge it.
* Current call sites pass `EVP_MD_CTX_new()` / `SSL_SESSION_new()` /
  `EVP_PKEY_new()` / `EVP_CIPHER_CTX_new()` / `HMAC_CTX_new()` answers
  (`statem_clnt.rs:1870,2016,2609`; `statem_srvr.rs:2169,2594,2653,2849,3073-3074,3165-3169`),
  so no UB is observed.
* **Recommended:** make it `unsafe fn new` with a `# Safety` section (live
  `*_new` object, one reference owned here, not released elsewhere; NULL
  allowed). Same for the server copy.
* This is also the concrete instance of “a `Drop` that can free memory it does
  not exclusively own”: the safe constructor lets `Drop` free an unowned block.

### 9.2 Adoption constructors otherwise well-formed

* Every `take` / `adopt` / `adopt_cleansed` / `from_raw` on an owner type is
  `unsafe fn` and has a `# Safety` section. No exception found in `src/`.
* `property/strings.rs:187` is an `unsafe fn new(l)` (allocating, not adopting)
  and carries a `# Safety`; the `size_of + l` addition is unchecked (see 9.3).
* `dso/dlfcn.rs:135` and the infallible `adopt -> Self` copies accept a pointer
  the caller must prove non-NULL; NULL is nevertheless tolerated by `Drop`
  (a no-op), so the type remains sound. Signature variance only.

### 9.3 Arithmetic hardening (AGENTS §3, separate batch)

Safe allocation-size expressions without `checked_add`:
`property/strings.rs:191`, `property/parse.rs:833,1244`,
`property/store.rs:1266`, `ssl/ssl_sess.rs:1940`. These are not ownership-adoption
defects, but AGENTS §3 requires checked arithmetic for any
`size_of::<T>() + len` used for allocation. `asn1/owned.rs` does this correctly
with `checked_mul`.

### 9.4 Secret-classification observations

* `ec/ecdh_ossl.rs:59 OwnedSecretBuf` is secret-bearing but has **no stored
  cleansing length** and `Drop` is plain `CRYPTO_free`. The module documents
  that the authority deliberately hands the shared secret to the caller without
  cleansing here, and the caller owns and clears it. This is preserved
  authority behaviour, not a conversion defect, but it means the type must
  **not** be treated as a secret-safe destructor. Classed DIFFERENT.
* `rand/pool.rs:169` has no plain-release arm (only `SecureCleansed`/`Cleansed`),
  which is correct for pool blocks but makes it structurally distinct.
* All `C`/`SC` owners that store a cleansing length do so in the struct
  (`len`/`num` or a `release` variant); none recomputes it at `Drop` from a
  length that could have changed. This matches AGENTS §5.1.

### 9.5 Destructor bodies do not free the enclosing block

Scanned all 235 `unsafe fn destroy_body` implementations: no body calls
`CRYPTO_free` on the enclosing `ptr`/`ctx`; all `CRYPTO_free` calls are on
members (`(*ptr).field`) or on a local member pointer. The block release is
confined to `OwnedCtx`'s `Drop`, as the trait contract requires.

---

## 10. Consolidation candidates (IDENTICAL groups only)

Listed by expected value. Each requires a reviewed, separately gated change; do
not treat this list as authorization to merge.

1. **`OwnedBuf` plain `{ptr,file,line}` → 52 copies** (`B-P`). Highest value:
   same allocation (`CRYPTO_malloc`), same `Drop` (`P(ptr,file,line)`), same
   NULL policy. A shared type already exists in spirit
   (`runtime/bio/owned::OwnedBlock` is `{ptr}` only); the right target is a new
   `pub(crate) OwnedBuf` with `new` + `unsafe adopt -> Option` in
   `runtime/mem` or `runtime/bio/owned`. The 15 infallible-`adopt` callers need
   only `let Some(x) = ... else` (they already guard non-NULL).
2. **`OwnedBuf` release-enum family → 27 copies** (`B-R1a` 13 + `B-R1b` 14).
   One `BufRelease` with `Plain{file,line}` and
   `Cleansed{num,file,line}` covers both; `B-R1b` can pass a module constant
   file. `B-R3` (4) adds `SecureCleansed`; a single enum with an optional
   secure arm covers all 31.
3. **`OwnedStr` → 33 copies** (`S-P` 10 + `S-L` 13 + `S-Z` 10). One
   `{ptr,file,line}` type with a `const FILE`/stored line suffices; no cleansing
   and no length. `S-NL` stays local (NonNull).
4. **`OwnedBlock` → 15 copies** (`OB-P` 8 + `OB-Cond` 4 + `OB-Z` 3). One type
   `{ptr, len: Option<usize>, file, line}` can serve plain, always-cleanse and
   conditional-cleanse; the `clear` flag is only needed by `OB-Cond`. Note
   `evp/asymcipher` (always cleanse) is one field away from `OB-Cond` and could
   join with `len: usize` + `clear: true` default.
5. **`OwnedBuf` always-cleanse → 10 copies** (`B-CA-FL` 5 + `B-CA-0` 5). One
   `{ptr,len,file,line}` type; the constant-coordinate members pass module
   constants.
6. **`OwnedBuf` conditional-cleanse `OB-CF-FL` → 3 copies.**
7. **Small groups:** `OwnedSecret`-with-line/`OwnedUniPass` (2),
   `OwnedScratch` (2), constant-`char*` block owners (4).

### Explicit non-candidates

* All 56 module-local `OwnedCtx` and 5 local `RawCtx`: structurally similar but
  bound to **41 distinct local `CtxDestroy` traits** (plus `FreeOnDrop`,
  `DrbgCtx`, `GcmDestroy`, `KdfDestroy`, `MacDestroy`, `CipherDestroy`). They
  become candidates only after a single shared destructor trait (with the
  `FILE`/`LINE_ALLOC`/`LINE_FREE` consts already present in
  `runtime/bio/owned::CtxDestroy`) replaces the copies. That trait migration is
  itself a reusable-unsafe-abstraction change under AGENTS §9/§21, not part of
  this inventory.
* All `Raw*` uninitialised-construction windows: the block-only `Drop` and the
  `assume_init` transition are the semantic content; pooling them with
  `OwnedCtx` would erase the partially-initialised-state guarantee.
* Module-specific object owners (`OwnedDh/Dsa/Rsa/Sig/Method/Engine/Skey/
  Tree/Node/Store/...`) and record owners with custom destructor bodies
  (`OwnedValue`, `OwnedStore`, `OwnedTree`, `OwnedEngine`, `OwnedSkey`, …).

---

## 11. Residuals and limits

* This is a **static inventory**, not a safety proof. Class counts are audit
  classifications; the per-group member lists make each one checkable.
* Call counts are `grep -cw <Type> <file>` occurrences (definition + impls +
  uses), as requested; they are not a precise call-graph count.
* The `# Safety` scan looked for the token within 30 lines before each
  `unsafe fn` constructor. No exception was found, but this is a textual check,
  not a contract review; `DESTRUCTOR-CONTRACTS.md` remains the contract-level
  audit.
* No consolidation was performed, no `src/` file was modified, and no build or
  test was run. A consolidation batch must re-run the local gate in the court
  container (`cargo fmt --check`, `clippy -D warnings`, library tests) and
  record a receipt per AGENTS §14.
* The two safe `OwnedCtx::new` constructors are the only finding that blocks a
  soundness claim for the `FreeOnDrop` owner family. They should be fixed
  before any `SAFE_COMPATIBLE` argument that relies on those modules.
