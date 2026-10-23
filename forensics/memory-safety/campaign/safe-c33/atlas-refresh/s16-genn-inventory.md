# S16 — `GENERAL_NAME` union-arm access inventory

Source identity: `integrate/safe-c33` @ `febfd3f3d` (pre-conversion; working tree clean).
Scope: every direct access to a `GeneralName::d` arm across `src/**`. Line numbers are
pre-conversion (`HEAD`) line numbers. Hits on `PKCS7`/`CMS`/`SIV` `d` unions are listed in
the "excluded" section because they are different structs that merely share the field name.

Classification: **(a)** inside `v3_genn.rs`; **(b)** read; **(c)** write (assigns the arm);
**(d)** raw-pointer-only (no Rust reference formed over the arm); **(e)** forms a Rust
reference / place over the arm (`&T`, `&mut T`, or a dereferenced place).

## 1. Access sites (pre-conversion)

| # | file:line | location | nature | repr | selector guard before access | disposition |
|---|---|---|---|---|---|---|
| 1 | `src/x509/v3_genn.rs:147` | a | read | e | `match self.type_` arm | kept; now the single reader (`as_ref`) |
| 2 | `src/x509/v3_genn.rs:148` | a | read | e | same | kept |
| 3 | `src/x509/v3_genn.rs:149` | a | read | e | same | kept |
| 4 | `src/x509/v3_genn.rs:150-154` | a | read | e | same | kept |
| 5 | `src/x509/v3_genn.rs:155-159` | a | read | e | same | kept |
| 6 | `src/x509/v3_genn.rs:160` | a | read | e | same | kept |
| 7 | `src/x509/v3_genn.rs:161-165` | a | read | e | same | kept |
| 8 | `src/x509/v3_genn.rs:83-134` | a | write | c | `install` switch | kept; the single writer |
| 9 | `src/x509/v3_genn.rs:1074` (test) | a | read | d | test owns selector | kept (test-only) |
| 10 | `src/cmp/cmp_hdr.rs:199` | b | read | d | `(*name).type_ == GEN_DIRNAME` | retained; selector-checked + SAFETY |
| 11 | `src/cmp/cmp_server.rs:1305` | b | read | d | `(*sender).type_ == GEN_DIRNAME` | retained; selector-checked + SAFETY |
| 12 | `src/cmp/cmp_vfy.rs:740-742` | b | read | d | **none** (`g.d.directoryName`) | **converted** to `directory_name()` |
| 13 | `src/cmp/cmp_vfy.rs:1180` | b | read | d | **none** (`(*sender).d.directoryName`) | **converted** to `directory_name()` |
| 14 | `src/cmp/cmp_vfy.rs:1550` | b | read | d | `(*actual_sender).type_ == GEN_DIRNAME` | retained |
| 15 | `src/crmf/crmf_lib.rs:764` | b | **write** | **e** (`&mut d.directoryName`) | none (fresh item) | **routed**: `X509_NAME_dup` + `set_directory_name` |
| 16 | `src/crmf/crmf_lib.rs:1452` | b | read | d | `(*gn).type_ == GEN_DIRNAME` | retained |
| 17 | `src/ess/ess_lib.rs:169-170` | b | **write** | c/d | none (fresh item) | **routed**: `set_directory_name` |
| 18 | `src/ess/ess_lib.rs:296-297` | b | **write** | c/d | none (fresh item) | **routed**: `set_directory_name` |
| 19 | `src/ess/ess_lib.rs:474` | b | read | d | `(*issuer).type_ == GEN_DIRNAME` | retained |
| 20 | `src/ocsp/ocsp_cl.rs:471` | b | **write** | d (`addr_of_mut!`) | none (fresh item) | **routed**: `X509_NAME_dup` + `set_directory_name` |
| 21 | `src/ocsp/ocsp_ext.rs:1004-1005` | b | **write** | c/d | none (`ACCESS_DESCRIPTION_new`) | **routed**: `set_ia5(GEN_URI, …)` |
| 22 | `src/ocsp/ocsp_vfy.rs:871` | b | read | d | `(*gen).type_ == GEN_DIRNAME` | retained |
| 23 | `src/ts/ts_rsp_sign.rs:1396-1397` | b | **write** | c/d | none (fresh item) | **routed**: `set_directory_name` |
| 24 | `src/ts/ts_rsp_verify.rs:1024` | b | read | d | `(*tsa_name).type_ == GEN_DIRNAME` | retained |
| 25 | `src/x509/v3_akid.rs:556-557` | b | **write** | c/d | none (fresh item) | **routed**: `set_directory_name` |
| 26 | `src/x509/v3_ncons.rs:528` | b | read | d | `(*(*tree).base).type_ == GEN_IPADD` | retained |
| 27 | `src/x509/v3_ncons.rs:1383-1385` | b | **write** | c/d | stack temporary | **routed**: `set_directory_name` |
| 28 | `src/x509/v3_ncons.rs:1403` | b | **write** | c/d | loop, selector set to `GEN_EMAIL` | **routed**: `set_ia5(GEN_EMAIL, …)` |
| 29 | `src/x509/v3_ncons.rs:1405` | b | read | **e** (`(*gntmp.d.ia5).type_`) | `GEN_EMAIL` set above | **converted** to `as_ref` → `GeneralNameRef::Ia5` |
| 30 | `src/x509/v3_ncons.rs:1450-1452` | b | **write** | c/d | stack temporary | **routed**: `set_ia5(GEN_DNS, …)` |
| 31 | `src/x509/v3_ncons.rs:1483-1484` | b | read+write | **e** (`(*gntmp.d.ia5)…`) | `GEN_DNS` set above | **converted** to `arm_ptr()` |
| 32 | `src/x509/v3_purp.rs:1268` | b | read | d | `(*gen).type_ == GEN_DIRNAME` | retained |
| 33 | `src/x509/v3_purp.rs:2289` | b | read | d | `(*gen).type_ == GEN_DIRNAME` | retained |
| 34 | `src/x509/v3_san.rs:205-207` | b | read | d | **caller contract only** | **hardened**: self-guarding `other_name()` |
| 35 | `src/x509/v3_san.rs:214-216` | b | read | d | **caller contract only** | **hardened**: self-guarding `ia5()` |
| 36 | `src/x509/v3_san.rs:223-225` | b | read | d | **caller contract only** | **hardened**: self-guarding `directory_name()` |
| 37 | `src/x509/v3_san.rs:232-234` | b | read | d | **caller contract only** | **hardened**: self-guarding `ip_address()` |
| 38 | `src/x509/v3_san.rs:241-243` | b | read | d | **caller contract only** | **hardened**: self-guarding `registered_id()` |
| 39 | `src/x509/v3_san.rs:787` | b | **write** | c/d | none | **routed**: build-local + `install` |
| 40 | `src/x509/v3_san.rs:839` | b | **write** | c/d | none | **removed**: error tail now frees the local |
| 41 | `src/x509/v3_san.rs:872` | b | **write** | c/d | none | **routed**: build-local + `install` |
| 42 | `src/x509/v3_san.rs:936` | b | **write** | c/d | none | **routed**: build-local + `install` |
| 43 | `src/x509/v3_san.rs:949` | b | **write** | c/d | none | **routed**: build-local + `install` |
| 44 | `src/x509/v3_san.rs:985` | b | **write** | c/d | none | **routed**: build-local + `install` |
| 45 | `src/x509/v3_san.rs:991-992` | b | read+write | **e** (`(*gen).d.ia5`) | none | **routed**: local `ia5` |
| 46 | `src/x509/v3_san.rs:1463-1465` | b | **write** | c/d | none | **routed**: `set_ia5(GEN_EMAIL, …)` |
| 47 | `src/x509/v3_utl.rs:1786` | b | read | d | `(*gen).type_ == GEN_EMAIL` | retained |
| 48 | `src/x509/v3_utl.rs:1840` | b | read | d | `(*loc).type_ == GEN_URI` | retained |
| 49 | `src/x509/v3_utl.rs:2438` | b | read | d | `match (*gen).type_` `GEN_OTHERNAME` | retained |
| 50 | `src/x509/v3_utl.rs:2461` | b | read | d | `GEN_EMAIL` arm | retained |
| 51 | `src/x509/v3_utl.rs:2468` | b | read | d | `GEN_DNS` arm | retained |
| 52 | `src/x509/v3_utl.rs:2475` | b | read | d | `GEN_IPADD` arm | retained |
| 53 | `src/x509/x509_acert.rs:934` | b | read | d | `(*dirName).type_ == GEN_DIRNAME` | retained |
| 54 | `src/x509/x509_vfy.rs:4454` | b | read | d | `(*gena).type_ == GEN_DIRNAME` | retained |
| 55 | `src/x509/x509_vfy.rs:4502` | b | read | d | `(*gen).type_ == GEN_DIRNAME` | retained |
| 56 | `src/x509/x_crl.rs:1114` | b | read | d | `(*gen).type_ == GEN_DIRNAME` | retained |

### `addr_of`/`addr_of_mut` on a `GENERAL_NAME` arm

| file:line | form | disposition |
|---|---|---|
| `src/ocsp/ocsp_cl.rs:471` | `addr_of_mut!((*gen).d.directoryName)` | routed (site 20) |
| `src/x509/v3_ncons.rs:1405,1483` | dereferenced place via `gntmp.d.ia5` | converted (sites 29, 31) |

No other `addr_of!`/`addr_of_mut!` names a `GeneralName` arm.

## 2. Summary counts

| class | pre-conversion | post-conversion |
|---|---|---|
| (a) inside `v3_genn.rs` — reads via `as_ref` | 7 | 7 (single reader) |
| (a) inside `v3_genn.rs` — the `install` writer | 1 | 1 |
| (a) test-only direct reads | 1 | 1 |
| outside `v3_genn.rs` — **writes** | **19** | **0** |
| outside `v3_genn.rs` — reads forming a reference/place (e) | 3 | 0 |
| outside `v3_genn.rs` — raw-pointer-only reads (d) | 24 | 20 (all selector-checked + SAFETY) |
| outside `v3_genn.rs` — unguarded reads | 2 | 0 |
| outside `v3_genn.rs` — caller-contract-only accessors | 5 | 0 |

Post-conversion, the only direct arm accesses outside `v3_genn.rs` are 20 raw-pointer
reads, each immediately preceded by an explicit `type_ == GEN_*` / `match type_` check and a
`// SAFETY:` comment naming the discriminant and pointee contract. Every write, every
reference-forming read, and every accessor now goes through the audited family in
`v3_genn.rs`.

## 3. Excluded hits (different `d` unions)

`src/pkcs7/pk7_doit.rs:203,239`, `src/pkcs7/pk7_lib.rs:413`, `src/ts/ts_asn1.rs:1120`,
`src/ts/ts_rsp_sign.rs:1815,1838` — `PKCS7::d.other` (a different struct).
`src/cms/cms_*.rs` `d` fields and `src/modes/siv128.rs` `ctx->d` — different structs.
