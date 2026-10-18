# OB-2 caller-precondition audit — `runtime::owned_str::OwnedStr`

**Source identity:** `integrate/safe-c33` at `a0c8a01e7`, plus this batch's
contract-doc and test-only edits in `src/` (no production behaviour change).
Site line numbers were re-read from that edited working tree; the candidate
source pin remains `a0c8a01e7`. **Boundary:** `OB-2`, `OwnedStr` unsafe adoption/transfer
operations. **Purpose:** per-caller precondition inventory for the adjudicator.
This document does **not** change `OWNER-CALLERS.md` or any other ledger, does
not claim a graduation state, and is **not a proof**. The adjudicator decides.

## 0. Method and verdict semantics

The implementation was read first. It has exactly two unsafe constructors:

- `unsafe fn adopt(ptr, file, line) -> Option<Self>` — non-NULL transfers
  ownership; NULL answers `None` (authority's no-op `free(NULL)`).
- `unsafe fn adopt_nullable(ptr, file, line) -> Self` — non-NULL transfers
  ownership exactly once; NULL is kept and `Drop` performs `CRYPTO_free(NULL)`.

Safe constructors (`new`, `new_zeroed`) and the safe transitions `into_raw`,
`set_release_line`, `as_ptr` carry no adoption precondition. **No
`new_strdup`/`new_strndup` exists in the impl.** The duplicate-group members
call `adopt` on `CRYPTO_strdup`/`CRYPTO_strndup` results (or on a helper that
allocates through them).

Exhaustive search over `src/` for `OwnedStr::{adopt,adopt_nullable,new,new_zeroed,into_raw}`;
imports were checked for aliases (none) and fully-qualified hidden uses (none).
Production and `#[cfg(test)]` sites are separated. **131** code call sites of
`adopt`/`adopt_nullable` (the four extra test-only sites are the
`owned_str_model.rs` correspondence tests added with this batch):

| constructor | production | test-only | total |
|---|---:|---:|---:|
| `adopt` | 117 | 9 | 126 |
| `adopt_nullable` | 3 | 2 | 5 |
| **total** | **120** | **11** | **131** |

Safe constructor sites: **5 production** (`OwnedStr::new` at
`dso/mod.rs:768`, `runtime/err.rs:538`, `runtime/conf/api.rs:524`,
`runtime/bio/bss_log.rs:169`; `new_zeroed` at `runtime/bio/bio_sock2.rs:691`)
and 3 test sites. Their only obligation is the requested length; the documented
"write the terminator before a C-string read" is a consumer obligation, not an
unsafe one.

**Verdict rule.** `ESTABLISHED` requires a concrete witness, in the caller
frame, for all of: (1) provenance from a named `CRYPTO_*` allocation or a
documented C-ABI allocation seam; (2) NUL-termination within the allocated
extent whenever a C-string consumer reads the block; (3) exclusive ownership
with a single release at the named coordinate. A comment that merely asserts
one of these without an enforcing contract or a traceable producer is
`UNATTRIBUTED`. So is an application callback whose allocation contract is not
stated at the API that accepts it. `DUP` = `CRYPTO_strdup` (extent
`strlen+1`, NUL-terminated); `NDUP` = `CRYPTO_strndup` (extent
`min(strnlen,max)+1`, NUL-terminated); `FIELD(x)` = object field whose only
installers are the cited seam sites; `HELP(x)` = named helper verified to
allocate through the seam.

## 1. `adopt` call sites

### `src/cmp/cmp_asn.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-001 | 1622 | `ossl_cmp_msg_set0_libctx` | FIELD(msg->propq): DUP at 1630/`into_raw` 1638, or `ASN1_OP_DUP_POST` set0 | yes (DUP) | sole field owner; replaced at 1638 | Drop → `CRYPTO_free(FILE,46)` | ESTABLISHED |
| OS-002 | 1629 | `ossl_cmp_msg_set0_libctx` | DUP(propq) | yes | fresh, `into_raw` 1638 | Drop → `CRYPTO_free(FILE,49)` | ESTABLISHED |
| OS-003 | 1662 | `ossl_cmp_msg_cb` | FIELD(msg->propq) as OS-001 | yes | free-hook owner | Drop → `CRYPTO_free(FILE,854)` | ESTABLISHED |

### `src/cmp/cmp_client.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-004 | 670 | `send_receive_check` | HELP(`ossl_sk_ASN1_UTF8STRING2text`): `CRYPTO_malloc(len+1)`, NUL at `asn1/string.rs:810` | yes, len+1 | fresh, single | Drop → `CRYPTO_free(FILE,243)` | ESTABLISHED |
| OS-005 | 1195 | `cert_response` | HELP(`X509_NAME_oneline`, NULL buffer): `BUF_MEM` data via seam, NUL written | yes | fresh, single | Drop → `CRYPTO_free(FILE,801)` | ESTABLISHED |

### `src/cmp/cmp_ctx.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-006 | 308 | `ctx_set1_char!` expansion (`OSSL_CMP_CTX_set1_{proxy,server,no_proxy,serverPath}`) | FIELD($field): DUP at 298–309, or NULL | yes (DUP) | incumbent replaced under one owner | Drop → `CRYPTO_free(FILE,0)` | ESTABLISHED |
| OS-007 | 482 | `OsslCmpCtx::destroy_body` | FIELD(propq): DUP at 550 | yes | unique context owner | Drop → `CRYPTO_free(FILE_C,196)` | ESTABLISHED |
| OS-008 | 483 | `OsslCmpCtx::destroy_body` | FIELD(server_path): DUP via `ctx_set1_char!` | yes | unique | Drop → `(FILE_C,197)` | ESTABLISHED |
| OS-009 | 484 | `OsslCmpCtx::destroy_body` | FIELD(server): DUP via `ctx_set1_char!` | yes | unique | Drop → `(FILE_C,198)` | ESTABLISHED |
| OS-010 | 485 | `OsslCmpCtx::destroy_body` | FIELD(proxy): DUP via `ctx_set1_char!` | yes | unique | Drop → `(FILE_C,199)` | ESTABLISHED |
| OS-011 | 486 | `OsslCmpCtx::destroy_body` | FIELD(no_proxy): DUP via `ctx_set1_char!` | yes | unique | Drop → `(FILE_C,200)` | ESTABLISHED |

### `src/cmp/cmp_genm.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-012 | 130 | `cert_msg` | HELP(`X509_NAME_oneline`) | yes | fresh, single | Drop → `CRYPTO_free(FILE,31)` | ESTABLISHED |

### `src/ct/ct_log.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-013 | 312 | `CTLOG_STORE_new_ex` | DUP(propq), checked at 315 | yes | `into_raw` 319 into store | Drop → `CRYPTO_free(NULL,0)` | ESTABLISHED |
| OS-014 | 418 | `ctlog_store_load_log` | NDUP(log_name, log_name_len) | yes, `strnlen+1` | fresh, single | Drop → `CRYPTO_free(NULL,0)` | ESTABLISHED |
| OS-015 | 573 | `CTLOG_new_ex` | DUP(propq), checked at 576 | yes | `into_raw` 580 | Drop → `(NULL,0)` | ESTABLISHED |
| OS-016 | 585 | `CTLOG_new_ex` | DUP(name), checked at 586 | yes | `into_raw` 590 | Drop → `(NULL,0)` | ESTABLISHED |

### `src/ct/ct_sct_ctx.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-017 | 133 | `SCT_CTX_new` | DUP(propq), checked at 136 | yes | `into_raw` 141 | Drop → `(NULL,0)` | ESTABLISHED |

### `src/decoder_meth.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-018 | 285 | `OSSL_DECODER_free` | FIELD(base.name) installed at 333 from OS-019 | yes | last reference; reentrancy gate | Drop → `(NULL,0)` | ESTABLISHED |
| OS-019 | 327 | `ossl_decoder_from_algorithm` | HELP(`ossl_algorithm_get1_first_name`): NDUP | yes | fresh; `into_raw` 333 | Drop → `(NULL,0)` | ESTABLISHED |

### `src/dh/mod.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-020 | 479 | `DH_meth_new` | DUP(name), checked at 484 | yes | `into_raw` into row | Drop → `(FILE_DH_METH_SEAM,LINE)` | ESTABLISHED |
| OS-021 | 531 | `DH_meth_dup` | DUP((*dhm).name) | yes | fresh; raw copy owned separately | Drop → `(FILE_DH_METH_SEAM,LINE)` | ESTABLISHED |
| OS-022 | 569 | `DH_meth_set1_name` | DUP(name) before old release | yes | fresh, `into_raw` 582 | Drop → `(FILE_DH_METH_SEAM,LINE)` | ESTABLISHED |
| OS-023 | 581 | `DH_meth_set1_name` | FIELD(dhm->name) from OS-020/021/022 | yes | sole row owner | Drop → `(FILE_DH_METH_SEAM,LINE)` | ESTABLISHED |

### `src/dsa/mod.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-024 | 488 | `DSA_meth_new` | DUP(name), checked at 493 | yes | `into_raw` into row | Drop → `(FILE_DSA_METH_SEAM,LINE)` | ESTABLISHED |
| OS-025 | 536 | `DSA_meth_dup` | DUP((*dsam).name) | yes | fresh; separate raw row | Drop → `(FILE_DSA_METH_SEAM,LINE)` | ESTABLISHED |
| OS-026 | 574 | `DSA_meth_set1_name` | DUP(name) before old release | yes | fresh, `into_raw` 587 | Drop → `(FILE_DSA_METH_SEAM,LINE)` | ESTABLISHED |
| OS-027 | 586 | `DSA_meth_set1_name` | FIELD(dsam->name) from OS-024/025/026 | yes | sole row owner | Drop → `(FILE_DSA_METH_SEAM,LINE)` | ESTABLISHED |

### `src/engine/eng_dyn.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-028 | 320 | `DynamicDataCtx::destroy_body` | FIELD(DYNAMIC_LIBNAME): DUP at 623 → raw 629 | yes | unique context | Drop → `(FILE_SEAM,LINE_FREE_LIBNAME)` | ESTABLISHED |
| OS-029 | 325 | `DynamicDataCtx::destroy_body` | FIELD(engine_id): DUP at 657 → raw 663 | yes | unique | Drop → `(FILE_SEAM,LINE_FREE_ENGINE_ID)` | ESTABLISHED |
| OS-030 | 391 | `int_free_str` | FIELD(dirs element): DUP at 703 → stack 711 → raw 720 | yes | stack element destructor owns it | Drop → `(FILE_SEAM,LINE_INT_FREE_STR)` | ESTABLISHED |
| OS-031 | 613 | `dynamic_ctrl` | FIELD(DYNAMIC_LIBNAME) | yes | replaced once | Drop → `(FILE_SEAM,LINE_FREE_SO_PATH)` | ESTABLISHED |
| OS-032 | 622 | `dynamic_ctrl` | DUP(p) at 623, checked | yes | fresh; raw 629 | Drop → `(FILE_SEAM,LINE_FREE_SO_PATH)` | ESTABLISHED |
| OS-033 | 648 | `dynamic_ctrl` | FIELD(engine_id) | yes | replaced once | Drop → `(FILE_SEAM,LINE_FREE_ID)` | ESTABLISHED |
| OS-034 | 656 | `dynamic_ctrl` | DUP(p) at 657, checked | yes | fresh; raw 663 | Drop → `(FILE_SEAM,LINE_FREE_ID)` | ESTABLISHED |
| OS-035 | 702 | `dynamic_ctrl` | DUP(p) at 703, checked | yes | fresh; `into_raw` 720 after push | Drop → `(FILE_SEAM,LINE_STRDUP_DIR)` | ESTABLISHED |
| OS-036 | 773 | `int_load` | HELP(`DSO_merge` → `dlfcn_merger`): DUP or `CRYPTO_malloc(len+2)`, NUL at 300 | yes | fresh; single | Drop → `(FILE_SEAM,LINE_FREE_MERGE_FOUND)` | ESTABLISHED |
| OS-037 | 777 | `int_load` | HELP(`DSO_merge`) as OS-036 | yes | fresh; single | Drop → `(FILE_SEAM,LINE_FREE_MERGE_MISS)` | ESTABLISHED |

### `src/http/http_lib.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-038 | 199 | `free_pstring` | EXT(*pstr): `# Safety` names `CRYPTO_strndup`/`CRYPTO_malloc`; all 12 callers pass this call's own parse outputs | yes | slot cleared at 201 | Drop → `CRYPTO_free(FILE,49)` | ESTABLISHED |
| OS-039 | 521 | `OSSL_HTTP_parse_url` | HELP(`OSSL_parse_url`): `CRYPTO_strndup` (`copy_substring` 183) | yes | fresh, local handle | Drop → `(FILE,229)` | ESTABLISHED |
| OS-040 | 522 | `OSSL_HTTP_parse_url` | HELP(`OSSL_parse_url`): NDUP or DUP (port at 571) | yes | fresh, local handle | Drop → `(FILE,233)` | ESTABLISHED |

### `src/provider/init.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-041 | 201 | `provider_init` | DUP(default_path) at 196 under read lock, checked 198 | yes | fresh, local handle | Drop → `(FILE_SEAM,LINE_LOAD_DIR_FREE)` | ESTABLISHED |
| OS-042 | 242 | `provider_init` | HELP(`DSO_convert_filename` → built-in converter): DUP or `CRYPTO_malloc(rsize)`, NUL at `dlfcn.rs:356` | yes | fresh, local handle | Drop → `(FILE_SEAM,LINE_ALLOCATED_PATH_FREE)` | ESTABLISHED |
| OS-043 | 258 | `provider_init` | HELP(`DSO_merge`) as OS-036 | yes | fresh, local handle | Drop → `(FILE_SEAM,LINE_MERGED_PATH_FREE)` | ESTABLISHED |

### `src/provider/keymgmt.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-044 | 1332 | `dh_gen_common_set_params` | FIELD(mdname): DUP 1334 → raw 1338, or NULL at 1072 | yes | unique gen-ctx | Drop → `(FILE_DH_KMGMT_SEAM,635)` | ESTABLISHED |
| OS-045 | 1333 | `dh_gen_common_set_params` | DUP(param data), checked | yes | fresh; raw 1338 | Drop → `(FILE_DH_KMGMT_SEAM,636)` | ESTABLISHED |
| OS-046 | 1348 | `dh_gen_common_set_params` | FIELD(mdprops): DUP 1350 → raw 1354, or NULL | yes | unique | Drop → `(FILE_DH_KMGMT_SEAM,644)` | ESTABLISHED |
| OS-047 | 1349 | `dh_gen_common_set_params` | DUP(param data), checked | yes | fresh; raw 1354 | Drop → `(FILE_DH_KMGMT_SEAM,645)` | ESTABLISHED |

### `src/provider/ml_dsa_kmgmt.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-048 | 169 | `MlDsaGenCtx::destroy_body` | FIELD(propq): `OSSL_PARAM_get_utf8_string` → `OwnedBuf`/`CRYPTO_malloc`, NUL at `params/mod.rs:2537`; or NULL | yes | unique gen-ctx | Drop → `(FILE_SEAM,LINE_GEN_CLEANUP_PROPQ)` | ESTABLISHED |
| OS-049 | 1023 | `ml_dsa_gen_set_params` | FIELD(propq) as OS-048 | yes | replaced once | Drop → `(FILE_SEAM,LINE_GEN_SET_FREE_PROPQ)` | ESTABLISHED |

### `src/provider/slh_dsa_kmgmt.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-050 | 141 | `SlhDsaGenCtx::destroy_body` | FIELD(propq): DUP 813, or NULL | yes | unique gen-ctx | Drop → `(FILE_SEAM,LINE_FREE_PROPQ)` | ESTABLISHED |
| OS-051 | 811 | `slh_dsa_gen_set_params` | FIELD(propq): DUP 813 | yes | replaced once | Drop → `(FILE_SEAM,LINE_FREE_PROPQ)` | ESTABLISHED |

### `src/rand/rand_lib.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-052 | 330 | `RandGlobal::destroy_body` | FIELD(random_provider_name): DUP 1882 → raw 1887 | yes | unique record | Drop → `(FILE_SEAM,L_CTX_FREE_PROVIDER_NAME)` | ESTABLISHED |
| OS-053 | 335 | `RandGlobal::destroy_body` | FIELD(rng_name): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_RNG_NAME)` | ESTABLISHED |
| OS-054 | 340 | `RandGlobal::destroy_body` | FIELD(rng_cipher): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_RNG_CIPHER)` | ESTABLISHED |
| OS-055 | 345 | `RandGlobal::destroy_body` | FIELD(rng_digest): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_RNG_DIGEST)` | ESTABLISHED |
| OS-056 | 350 | `RandGlobal::destroy_body` | FIELD(rng_propq): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_RNG_PROPQ)` | ESTABLISHED |
| OS-057 | 355 | `RandGlobal::destroy_body` | FIELD(seed_name): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_SEED_NAME)` | ESTABLISHED |
| OS-058 | 360 | `RandGlobal::destroy_body` | FIELD(seed_propq): DUP 1620 → raw 1632 | yes | unique | Drop → `(FILE_SEAM,L_CTX_FREE_SEED_PROPQ)` | ESTABLISHED |
| OS-059 | 431 | `ossl_rand_ctx_new` | DUP(literal) | yes | fresh; `into_raw` into record | Drop → `(FILE_SEAM,L_CTX_ERR_PROVIDER_NAME)` | ESTABLISHED |
| OS-060 | 1622 | `random_set_string` | DUP(s), checked; allocation extent `strlen(s)+1` | yes | fresh; `into_raw` 1632 | Drop → `(FILE_SEAM,L_RANDOM_SET_STRING_FREE)` | ESTABLISHED |
| OS-061 | 1630 | `random_set_string` | FIELD(*p): every caller passes a `RandGlobal` field installed by OS-060/063; the helper's `# Safety` states NULL-or-whole-`CRYPTO_strdup`-block with extent exactly `strlen(*p)+1` | yes, exact block extent | slot cleared at 1632 | Drop → `(FILE_SEAM,L_RANDOM_SET_STRING_FREE)` | ESTABLISHED |
| OS-062 | 1878 | `set_random_provider_name` | FIELD(random_provider_name) | yes | replaced once | Drop → `(FILE_SEAM,L_PROVIDER_NAME_DUP)` | ESTABLISHED |
| OS-063 | 1881 | `set_random_provider_name` | DUP(name) | yes | fresh; raw 1887 | Drop → `(FILE_SEAM,L_PROVIDER_NAME_DUP)` | ESTABLISHED |
| OS-064 | 1910 | `RAND_set1_random_provider` | FIELD(random_provider_name) | yes | cleared at 1916 | Drop → `(FILE_SEAM,L_PROVIDER_NAME_DUP)` | ESTABLISHED |

### `src/runtime/bio/addr.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-065 | 813 | `addr_strings` | DUP(host buffer), NUL after `getnameinfo`/fallback | yes | fresh; `into_raw` 843 | Drop → `(ALLOC_FILE,ALLOC_LINE)` | ESTABLISHED |
| OS-066 | 825 | `addr_strings` | DUP(service buffer) | yes | fresh; `into_raw` 844 | Drop → `(ALLOC_FILE,ALLOC_LINE)` | ESTABLISHED |

### `src/runtime/bio/addr_info.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-067 | 683 | `BIO_parse_hostserv` | NDUP(h, hl) | yes | fresh; `into_raw` 692 | Drop → `(ALLOC_FILE,ALLOC_LINE)` | ESTABLISHED |
| OS-068 | 707 | `BIO_parse_hostserv` | NDUP(p, pl) | yes | fresh; `into_raw` 739 | Drop → `(ALLOC_FILE,ALLOC_LINE)` | ESTABLISHED |
| OS-069 | 727 | `BIO_parse_hostserv` | FIELD(*host) written at 692 from OS-067 (rollback path) | yes | released once, slot NULLed 733 | Drop → `(ALLOC_FILE,ALLOC_LINE)` | ESTABLISHED |

### `src/runtime/bio/bio_sock2.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-070 | 556 | `BIO_get_accept_socket` | HELP(`BIO_parse_hostserv`): NDUP | yes | fresh, local handle | Drop → `(NULL,0)` | ESTABLISHED |
| OS-071 | 558 | `BIO_get_accept_socket` | HELP(`BIO_parse_hostserv`): NDUP | yes | fresh, local handle | Drop → `(NULL,0)` | ESTABLISHED |
| OS-072 | 668 | `BIO_accept` | HELP(`BIO_ADDR_hostname_string` → `addr_strings`): DUP | yes | fresh, local handle | Drop → `(NULL,0)` | ESTABLISHED |
| OS-073 | 676 | `BIO_accept` | HELP(`BIO_ADDR_service_string`): DUP | yes | fresh, local handle | Drop → `(NULL,0)` | ESTABLISHED |

### `src/runtime/conf/api.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-074 | 479 | `_CONF_free_data` | FIELD(conf->includedir): DUP at `def.rs:1325`, or NULL | yes | CONFIG owns; documented single free | Drop → `(NULL,0)` | ESTABLISHED |

### `src/runtime/conf/conf_ssl.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-075 | 203 | `OwnedStore::drop` | FIELD(name): DUP at 431 | yes | store array entry | Drop → `(FILE_SEAM,L_FREE_NAME)` | ESTABLISHED |
| OS-076 | 206 | `OwnedStore::drop` | FIELD(cmd): DUP at 469 | yes | store entry | Drop → `(FILE_SEAM,L_FREE_CMD)` | ESTABLISHED |
| OS-077 | 207 | `OwnedStore::drop` | FIELD(arg): DUP at 470, or NULL | yes | store entry | Drop → `(FILE_SEAM,L_FREE_ARG)` | ESTABLISHED |

### `src/runtime/conf/modparse.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-078 | 208 | `CONF_get1_default_config_file` | DUP(from_env), `into_raw` 210 to caller | yes | fresh; single transfer | Drop → `(NULL,0)` | ESTABLISHED |
| OS-079 | 225 | `CONF_get1_default_config_file` | DUP(c""), `into_raw` 231 | yes | fresh; single transfer | Drop → `(NULL,0)` | ESTABLISHED |
| OS-080 | 353 | test `the_default_path_is_not_the_authority_forensic_directory` | FIELD(p): caller-owned result of OS-078/079 | yes | test frame owner | Drop → `(NULL,0)` | ESTABLISHED (test-only) |
| OS-081 | 366 | test `default_config_file_follows_the_environment_...` | FIELD(p) as OS-080 | yes | test frame | Drop → `(NULL,0)` | ESTABLISHED (test-only) |
| OS-082 | 374 | test `default_config_file_follows_the_environment_...` | FIELD(p) as OS-080 | yes | test frame | Drop → `(NULL,0)` | ESTABLISHED (test-only) |

### `src/runtime/err.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-083 | 323 | `ErrorState::clear_data` | FIELD/C(err_data): internal `slot_buf_alloc` (`OwnedStr::new`) or external `ERR_set_error_data`; that entry's `# Safety` now states the seam/whole-block/`strlen+1`/exclusive-owner/release-once contract when `ERR_TXT_MALLOCED` is set | yes, `strlen+1` within the block | `MALLOCED` flag claims ownership; exported entry states exclusivity and single release | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |
| OS-084 | 350 | `ErrorState::clear` | FIELD(err_file): `dup_c` → `OwnedStr::new`, `into_raw` | yes (`len+1`) | unique slot | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |
| OS-085 | 352 | `ErrorState::clear` | FIELD(err_func): `dup_c` | yes | unique slot | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |
| OS-086 | 386 | `ErrorState::set_debug` | FIELD(err_file) from OS-084 installer | yes | replaced once | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |
| OS-087 | 391 | `ErrorState::set_debug` | FIELD(err_func) | yes | replaced once | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |
| OS-088 | 414 | `ErrorState::set_data` | FIELD/C(err_data): same two sources as OS-083; this slot setter documents the same contract | yes, `strlen+1` within the block | `MALLOCED` claims ownership; setter states exclusive single release | Drop → `(NULL,ERR_LINE)` | ESTABLISHED |

### `src/runtime/owned_str.rs` (tests only)

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-089 | 260 | test `adopt_keeps_the_nul_terminated_contents` | DUP(literal), NULL allowed | yes | fresh, test frame | Drop → `CRYPTO_free(FILE,14)` | ESTABLISHED (test-only) |
| OS-090 | 270 | test `adopt_null_is_none` | NULL | n/a | none | `None`, no free | ESTABLISHED (test-only) |
| OS-091 | 289 | test `into_raw_suppresses_release` | DUP(literal) | yes | `into_raw`, explicit free at 296 exactly once | `CRYPTO_free(FILE,18)` | ESTABLISHED (test-only) |

### `src/runtime/owned_str_model.rs` (tests only)

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-128 | 359 | test `production_adopt_null_matches_the_model` | NULL | n/a | none | `None`, no free | ESTABLISHED (test-only) |
| OS-129 | 367 | test `production_nullable_adopt_null_matches_the_model` | NULL | n/a | handle retained; `Drop` is `free(NULL)` | `CRYPTO_free(NULL)` | ESTABLISHED (test-only) |
| OS-130 | 392 | test `production_non_null_adoption_and_drop_match_the_model` | DUP(literal) at 388 | yes | fresh, test frame | Drop → `CRYPTO_free(FILE,4)` | ESTABLISHED (test-only) |
| OS-131 | 419 | test `production_into_raw_matches_the_model` | DUP(literal) at 415 | yes | `into_raw`, explicit free at 435 exactly once | `CRYPTO_free(FILE,6)` | ESTABLISHED (test-only) |

### `src/slh_dsa/key.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-092 | 97 | `slh_dsa_key_hash_cleanup` | FIELD(propq): DUP 180/249 → raw, or NULL | yes | unique key | Drop → `(FILE_SEAM,LINE_FREE_PROPQ)` | ESTABLISHED |
| OS-093 | 179 | `ossl_slh_dsa_key_new` | DUP(propq) | yes | fresh; raw 187 | Drop → `(FILE_SEAM,LINE_FREE_PROPQ)` | ESTABLISHED |
| OS-094 | 248 | `ossl_slh_dsa_key_dup` | DUP((*src).propq) | yes | fresh; raw 256 | Drop → `(FILE_SEAM,LINE_FREE_PROPQ)` | ESTABLISHED |

### `src/ui/ui_lib.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-095 | 763 | `UI_dup_input_string` | DUP(prompt), checked | yes | `into_raw` 789 iff add adopted | Drop → `(FILE_SEAM,LINE_DUP_INPUT_FREE)` | ESTABLISHED |
| OS-096 | 846 | `UI_dup_verify_string` | DUP(prompt), checked | yes | raw 872 iff adopted | Drop → `(FILE_SEAM,LINE_DUP_VERIFY_FREE)` | ESTABLISHED |
| OS-097 | 940 | `UI_dup_bool_string` | DUP(prompt), checked | yes | raw 1017 iff adopted | Drop → `(FILE_SEAM,LINE_DUP_BOOL_ERR)` | ESTABLISHED |
| OS-098 | 954 | `UI_dup_bool_string` | DUP(action_desc) | yes | raw 1020 iff adopted | Drop → same | ESTABLISHED |
| OS-099 | 968 | `UI_dup_bool_string` | DUP(ok_chars) | yes | raw 1023 iff adopted | Drop → same | ESTABLISHED |
| OS-100 | 982 | `UI_dup_bool_string` | DUP(cancel_chars) | yes | raw 1026 iff adopted | Drop → same | ESTABLISHED |
| OS-101 | 1059 | `UI_dup_info_string` | DUP(text) | yes | raw iff adopted | Drop → `(FILE_SEAM,LINE_DUP_INFO_FREE)` | ESTABLISHED |
| OS-102 | 1132 | `UI_dup_error_string` | DUP(text) | yes | raw iff adopted | Drop → `(FILE_SEAM,LINE_DUP_ERROR_FREE)` | ESTABLISHED |
| OS-103 | 1664 | `UI_create_method` | DUP(name) | yes | raw 1694 iff success | Drop → `(FILE_SEAM,LINE_CREATE_METHOD_FREE_NAME)` | ESTABLISHED |

### `src/x509/t_x509.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-104 | 1258 | `X509_STORE_CTX_print_verify_cb` | HELP(`X509_VERIFY_PARAM_get1_ip_asc` → `ossl_ipaddr_to_asc` → DUP at `v3_utl.rs:1547`) | yes | fresh, local handle | Drop → `(FILE,LINE_FREE_IP_ASC)` | ESTABLISHED |

### `src/x509/v3_akid.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-105 | 288 | `i2v_AUTHORITY_KEYID` | HELP(`i2s_ASN1_OCTET_STRING` → `OPENSSL_buf2hexstr` → seam, NUL) | yes | fresh, single | Drop → `(FILE,58)` | ESTABLISHED |
| OS-106 | 336 | `i2v_AUTHORITY_KEYID` | HELP(`i2s_ASN1_OCTET_STRING`) | yes | fresh, single | Drop → `(FILE,78)` | ESTABLISHED |

### `src/x509/v3_asid.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-107 | 717 | `i2r_ASIdentifierChoice` | HELP(`i2s_ASN1_INTEGER` → `BN_bn2dec`/hex, seam, NUL) | yes | fresh, single | Drop → `(FILE,LINE_FREE_ID)` | ESTABLISHED |
| OS-108 | 744 | `i2r_ASIdentifierChoice` | HELP(`i2s_ASN1_INTEGER`) | yes | fresh, single | Drop → `(FILE,LINE_FREE_RANGE_MIN)` | ESTABLISHED |
| OS-109 | 768 | `i2r_ASIdentifierChoice` | HELP(`i2s_ASN1_INTEGER`) | yes | fresh, single | Drop → `(FILE,LINE_FREE_RANGE_MAX)` | ESTABLISHED |
| OS-110 | 1518 | `v2i_ASIdentifiers` | DUP(value) | yes | fresh; handle alive for split | Drop → `(FILE,LINE_V2I_FREE)` | ESTABLISHED |

### `src/x509/v3_info.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-111 | 370 | `i2v_AUTHORITY_INFO_ACCESS` | FIELD(vtmp->name): `x509v3_add_len_value` DUP (`v3_utl.rs:181`), replaced by `ntmp` | yes | CONF_VALUE owns the replacement | Drop → `(FILE,LINE_FREE_NAME)` | ESTABLISHED |
| OS-112 | 469 | `v2i_AUTHORITY_INFO_ACCESS` | NDUP((*cnf).name, prefix length) | yes | fresh, local handle | Drop → `(FILE,LINE_FREE_OBJ)` | ESTABLISHED |

### `src/x509/v3_prn.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-113 | 270 | `X509V3_EXT_print` | EXT: application-supplied `X509V3_EXT_METHOD.i2s` callback result; the `X509V3ExtI2s` alias and `X509V3_EXT_add`'s `# Safety` now state the seam/whole-block/`strlen+1`/single-release contract | yes, `strlen+1` within the block | callback transfers ownership once; print path's `Drop` is the sole release | Drop → `(FILE,LINE_FREE_VALUE)` | ESTABLISHED |

### `src/x509/v3_purp.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-114 | 936 | `X509_PURPOSE_add` | FIELD(ptmp->name) installed 1036/1039 (DUP 952) under `DYNAMIC_NAME` | yes | row owns; replaced here | Drop → `(FILE,LINE_ADD_FREE_NAME)` | ESTABLISHED |
| OS-115 | 941 | `X509_PURPOSE_add` | FIELD(ptmp->sname): DUP 960 | yes | row owns | Drop → `(FILE,LINE_ADD_FREE_SNAME)` | ESTABLISHED |
| OS-116 | 951 | `X509_PURPOSE_add` | DUP(name), checked at 972 | yes | raw 1036 on success | Drop → `(FILE,LINE_ADD_ERR_NAME)` | ESTABLISHED |
| OS-117 | 959 | `X509_PURPOSE_add` | DUP(sname), checked at 972 | yes | raw 1039 on success | Drop → `(FILE,LINE_ADD_ERR_SNAME)` | ESTABLISHED |

### `src/x509/v3_san.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-118 | 574 | `i2v_GENERAL_NAME` | HELP(`ossl_ipaddr_to_asc` → DUP) | yes | fresh, local handle | Drop → `(FILE,195)` | ESTABLISHED |
| OS-119 | 716 | `GENERAL_NAME_print` | HELP(`ossl_ipaddr_to_asc` → DUP) | yes | fresh, local handle | Drop → `(FILE,290)` | ESTABLISHED |
| OS-120 | 805 | `do_othername` | NDUP(value, objlen) | yes | fresh, local handle | Drop → `(FILE,653)` | ESTABLISHED |

### `src/x509/v3_sxnet.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-121 | 375 | `sxnet_i2r` | HELP(`i2s_ASN1_INTEGER`) | yes | fresh, single | Drop → `(FILE,LINE_FREE_TMP)` | ESTABLISHED |

### `src/x509/x509_trust.rs`

| ID | site | enclosing fn | provenance | NUL / extent | ownership | release | verdict |
|---|---|---|---|---|---|---|---|
| OS-122 | 630 | `X509_TRUST_add` | FIELD(trtmp->name) installed 690 (DUP 635) under `DYNAMIC_NAME` | yes | row owns; replaced here | Drop → `(FILE,LINE_FREE_STD_NAME)` | ESTABLISHED |
| OS-123 | 634 | `X509_TRUST_add` | DUP(name), checked at 642 | yes | raw 690 on success | Drop → `(FILE,LINE_FREE_ERR_NAME)` | ESTABLISHED |

## 2. `adopt_nullable` call sites

| ID | site | enclosing fn | provenance | NUL / extent | NULL behaviour | ownership | release | verdict |
|---|---|---|---|---|---|---|---|---|
| OS-124 | `src/dso/dlfcn.rs:143` | `dlfcn_load` | HELP(`DSO_convert_filename` → built-in `dlfcn_name_converter`: `CRYPTO_malloc(rsize)`, NUL at 356) | yes | NULL checked at 134 before adoption, so this call is non-NULL | `into_raw` 173 into `loaded_filename` on success, else Drop; exactly once | Drop → `(FILE_SEAM,LINE_FREE_TRANSLATED)` | ESTABLISHED |
| OS-125 | `src/dso/mod.rs:623` | `DSO_set_filename` | DUP(filename) at 618, checked non-NULL 619 | yes | copy is non-NULL here | raw 633 into `dso->filename`; exactly once | Drop → `(FILE_LIB_SEAM,LINE_FREE_FILENAME)` | ESTABLISHED |
| OS-126 | `src/dso/mod.rs:627` | `DSO_set_filename` | FIELD(dso->filename): installed 633 (OS-125) or initial NULL | yes | NULL is a no-op release | released here then field replaced 633; exactly once | Drop → `(FILE_LIB_SEAM,LINE_FREE_FILENAME)` | ESTABLISHED |
| OS-127 | `src/runtime/owned_str.rs:277` | test `null_handle_drop_is_the_noop_release` | NULL | n/a | retained; `Drop` performs `CRYPTO_free(NULL)` | no pointer transferred | `CRYPTO_free(NULL)` | ESTABLISHED (test-only) |

## 3. Verdict summary and closed evidence

- **131** `adopt`/`adopt_nullable` sites: **131 ESTABLISHED, 0
  UNATTRIBUTED**. Production: 120 sites = **120 ESTABLISHED, 0
  UNATTRIBUTED**. Test-only: 11, all ESTABLISHED.
- By constructor: `adopt` 126 = 126 ESTABLISHED; `adopt_nullable` 5 = 5
  ESTABLISHED.
- `adopt_nullable` NULL semantics: confirmed at all five sites — NULL maps to
  `CRYPTO_free(NULL)`, never to a release of another block; every non-NULL
  transfer is followed by exactly one `into_raw` or `Drop`. No double release
  found on `into_raw` paths (all `into_raw` sites pair with exactly one later
  adoption of the same field).

**Previously UNATTRIBUTED, now attributed by contract text** (the adjudicator
still decides; this document does not claim a graduation state):

1. `src/runtime/err.rs:323` (`ErrorState::clear_data`) — the slot's
   `ERR_TXT_MALLOCED` arm releases through `CRYPTO_free`. `ErrorState::clear_data`,
   `ErrorState::set_data`, and the exported `ERR_set_error_data` now state the
   matching caller guarantee: with the flag, a whole `CRYPTO_malloc`/
   `CRYPTO_strdup` block, NUL-terminated with a `strlen+1` C-string extent,
   exclusively owned and released once by ERR; without it, a borrowed pointer
   that must outlive the entry. The authority's `ERR_set_error_data` comment
   ("takes over ownership of the allocated memory", `err.c:803-806`) and its
   `err_clear_data`/`err_set_data` `OPENSSL_free` arms (`err_local.h:25,79`)
   are quoted at those sites.
2. `src/runtime/err.rs:414` (`ErrorState::set_data`) — the same slot contract is
   documented on the setter that replaces an incumbent `err_data` block.
3. `src/x509/v3_prn.rs:270` (`X509V3_EXT_print`) — the `X509V3ExtI2s` type alias
   now carries the callback ABI contract (whole `OPENSSL_malloc`/
   `CRYPTO_strdup` block, NUL-terminated, `strlen+1` C-string extent, ownership
   transferred), and `X509V3_EXT_add`'s `# Safety` states that registering an
   `i2s` row accepts the same obligation. Authority: `X509V3_EXT_print` frees
   `value` at `v3_prn.c:130`; the `i2s_ASN1_*` docs say "It is the caller's
   responsibility to free the returned string"
   (`doc/man3/s2i_ASN1_IA5STRING.pod`).

**Residual assumptions (now explicit, not hidden):**

- The three boundary contracts are C-ABI obligations. A C caller that passes a
  stack/static or already-owned pointer with `ERR_TXT_MALLOCED`, or registers
  an `i2s` returning borrowed storage, violates the documented contract; the C
  ABI cannot enforce it. The in-tree writers were checked and install only seam
  blocks (`ERR_set_error_data` callers in-tree are absent; all standard and
  custom `i2s` implementations return `CRYPTO_strdup`/`CRYPTO_malloc`).
- `random_set_string`'s `# Safety` now states the `*p` NULL-or-seam-block rule;
  all twelve call sites pass `RandGlobal` fields installed by OS-060/OS-063 or
  zero-initialised.
- Retained external-ABI assumptions (not counted against individual adopt
  sites): `X509_TRUST_get0`/`X509_PURPOSE_get0` return mutable row pointers and
  `DSO_METHOD_openssl` returns a mutable pointer to a shared method table, so a
  C caller can in principle install a borrowed `name`/converter result that a
  later release frees. This is the authority's own ABI hazard; the in-tree
  writers install only seam blocks.

## 4. Limits

This inventory is source-level and **not** a proof. The separate `OB2-CHECKS.md`
records the bounded `OwnedStr` transition model, its three negative controls, the
focused ASan run over the production paths, and the ordinary gate. Neither
document runs Miri, and neither tests a hostile C caller against the exported
boundaries. `src/` was changed only by contract/documentation comments and
test-only code; nothing was committed.
