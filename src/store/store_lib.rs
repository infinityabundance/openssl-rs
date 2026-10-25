//! `crypto/store/store_lib.c` — the `OSSL_STORE_CTX` state machine and the
//! `OSSL_STORE_INFO`/`OSSL_STORE_SEARCH` object model. Phase 10 (10.5), part two.
//!
//! The unit is 1,102 lines and **49 exports**, and D448 withheld all of them as one
//! block. This module is the correction that record asked for: the blockage is
//! **per-function**, and measurement (`nm --undefined-only` over the authority's
//! `libcrypto-lib-store_lib.o`, joined function by function against `store_lib.c`)
//! says which function reaches which unlanded name.
//!
//! # What lands, and what the measurement says about each
//!
//! **All forty-nine land.** Every one of their closures is inside the crate:
//! the `OSSL_STORE_CTX` state machine (`open`/`open_ex`/`eof`/`error`/`expect`/
//! `close`/`attach`/`delete`/`supports_search`/`find`), the `OSSL_STORE_INFO`
//! constructor and accessor family (`new`, `new_NAME`/`new_PARAMS`/`new_PUBKEY`/
//! `new_PKEY`/`new_CERT`/`new_CRL`/`set0_NAME_description`, the `get_type`/
//! `get0_*`/`get1_NAME`/`get1_NAME_description`/`get1_PARAMS`/`get1_PUBKEY`/
//! `get1_PKEY`/`get1_CERT`/`get1_CRL` accessors, `get0_CERT`/`get0_CRL` and `free`),
//! the whole `OSSL_STORE_SEARCH` object, and the two deprecated control entry points
//! (`ctrl`/`vctrl`, whose only `va_arg` walk is the one `int *` of
//! `OSSL_STORE_C_USE_SECMEM`; that lives in [`crate::store::store_lib_variadic`]).
//!
//! **Phase 10.8 landed the five names D448 named as the blockers**, and with them the
//! three functions and two arms this module had withheld: `X509_up_ref` and
//! `X509_CRL_up_ref` close [`OSSL_STORE_INFO_get1_CERT`]/[`OSSL_STORE_INFO_get1_CRL`],
//! `X509_free`/`X509_CRL_free` close the CERT and CRL arms of
//! [`OSSL_STORE_INFO_free`], and `i2d_X509_NAME` closes the `BY_NAME` and
//! `BY_ISSUER_SERIAL` arms of [`OSSL_STORE_find`].
//!
//! # The last export lands, with its result handler
//!
//! [`OSSL_STORE_load`] was the one name left open: its fetched branch calls
//! `store_result.c`'s `ossl_store_handle_load_result`, whose `try_cert`/`try_crl`/`try_pkcs12`
//! reach `d2i_X509`/`d2i_X509_AUX`/`d2i_X509_CRL` and `PKCS12_parse`. `d2i_X509`/`d2i_X509_CRL`
//! landed in 10.8, `d2i_X509_AUX` in 10.12 (with the `X509_CERT_AUX` item), and `PKCS12_parse`
//! in 10.3, so the whole `store_result.c` unit now lands in [`super::store_result`] and this
//! function lands with it. **All forty-nine exports are landed.**
//!
//! # The `file` provider rows are published, and this module now reaches them
//!
//! 10.16 publishes both `file` `OSSL_OP_STORE` rows (`src/provider/file_store.rs`), so
//! `OSSL_STORE_LOADER_fetch`/`do_all_provided` resolve a loader and `RT-STORE` calls them.
//! [`OSSL_STORE_load`]'s fetched branch now drives that loader through
//! `store_result.c`'s `ossl_store_handle_load_result`, landed in [`super::store_result`];
//! the row that resolves is exactly the loader this function consumes.
//!
//! # Ownership: the three objects are owned Rust, the two plain blocks with them
//!
//! Every `OSSL_STORE_CTX`, `OSSL_STORE_INFO` and `OSSL_STORE_SEARCH` this unit allocates for
//! itself is an [`OwnedCtx`]: it stays a `CRYPTO_zalloc` at the authority's own size on the
//! crate's allocator seam (`__FILE__`/`__LINE__` NULL/0, as the authority writes them), so a
//! caller-installed `CRYPTO_set_mem_functions` hook observes the allocation and its release, and
//! `Drop` is the only release. A constructor returns through [`OwnedCtx::into_raw`] rather than a
//! bare pointer, a refusal path returns rather than freeing what it half-built, and
//! `OSSL_STORE_close`/`OSSL_STORE_INFO_free`/`OSSL_STORE_SEARCH_free` reclaim through
//! [`OwnedCtx::from_raw`] so [`CtxDestroy::destroy_body`] runs the authority's own free body
//! before the block release. `OSSL_STORE_SEARCH`'s destructor body is empty; the other two are not.
//!
//! The name buffer `i2d_X509_NAME` fills in `OSSL_STORE_find` and the `CRYPTO_strdup` property
//! copy `OSSL_STORE_open_ex` keeps are [`OwnedBuf`]s: `Drop` releases them at the authority's
//! own (NULL, 0) site, and the property copy is handed to the context with
//! [`OwnedBuf::into_raw`] at the moment its `properties` member takes it over.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::bn::bignum::{BN_free, BigNum};
use crate::evp::digest::{EVP_MD_get0_name, EVP_MD_get_size, EvpMd};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_locate_const, OsslParam,
};
use crate::passphrase::{
    ossl_pw_clear_passphrase_cache, ossl_pw_clear_passphrase_data,
    ossl_pw_enable_passphrase_caching, ossl_pw_passphrase_callback_dec, ossl_pw_set_ui_method,
    OsslPassphraseData,
};
use crate::provider::{ossl_provider_ctx, OSSL_PROVIDER_get0_provider_ctx};
use crate::runtime::bio::core_bio::{ossl_core_bio_free, ossl_core_bio_new_from_bio};
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::Bio;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_shift, OpenSslStack,
};
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strlcpy};
use crate::ui::ui_lib::UiMethod;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_crl::{X509Crl, X509_CRL_free, X509_CRL_up_ref};
use crate::x509::x_name::{i2d_X509_NAME, X509Name};
use crate::x509::x_x509::{X509_free, X509};

use super::store_meth::{
    OSSL_STORE_LOADER_fetch, OSSL_STORE_LOADER_free, OSSL_STORE_LOADER_get0_provider,
};
use super::store_register::ossl_store_get0_loader_int;
use super::store_result::{ossl_store_handle_load_result, OsslStoreLoadResultData};
use super::{
    OsslStoreLoader, OsslStoreLoaderCtx, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_CRL,
    OSSL_STORE_INFO_NAME, OSSL_STORE_INFO_PARAMS, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY,
};
use crate::runtime::mem_coords::SeamFile;

extern "C" {
    /// Pull one general-purpose argument from a live `va_list`.
    ///
    /// Defined in `src/runtime/bio/bio_va.c`. The `OSSL_STORE_C_USE_SECMEM` arm of
    /// `OSSL_STORE_vctrl` is the only reader; it needs the caller's `int *`, and a
    /// `va_arg` walk cannot be written in stable Rust.
    fn openssl_rs_va_gp(ap: *mut c_void) -> u64;
}

// ---------------------------------------------------------------------------
// Ownership of the three objects and the two plain blocks
// ---------------------------------------------------------------------------

// The shared [`OwnedBuf`] owns a `CRYPTO_*`-seam block that is not one of the file's objects
// (here the `CRYPTO_strdup` property copy and the `i2d_X509_NAME` name buffer), released at the
// authority's own (NULL, 0) site, so a caller-installed `CRYPTO_set_mem_functions` hook observes
// it. `into_raw` hands the property copy to the context `properties` member that takes it over.

// The three object destructors: each is exactly what its unit's `*_free` performed by hand, minus
// the block release `OwnedCtx`'s `Drop` now owns.

// SAFETY: (a) holds: `destroy_body` is empty -- `OSSL_STORE_CTX` has no destructor body beyond
// `ossl_store_close_it`, which is run explicitly at close, so no member is released here and never
// the enclosing block. (b) holds trivially: the body touches nothing, so an all-zero context is
// valid -- what the safe `OwnedCtx::zalloc` leans on.
unsafe impl CtxDestroy for OsslStoreCtx {
    /// Empty: `OSSL_STORE_CTX` has no destructor body beyond `ossl_store_close_it`, which
    /// `OSSL_STORE_close` runs explicitly to return its answer, so the block release is the only
    /// work `Drop` has left here.
    unsafe fn destroy_body(_ptr: *mut OsslStoreCtx) {}
}

// SAFETY: (a) holds: `destroy_body` is empty -- `OSSL_STORE_SEARCH_free` is a bare block free, so no
// member is released here and never the enclosing block. (b) holds trivially: the body touches
// nothing, so an all-zero search is valid -- what the safe `OwnedCtx::zalloc` leans on.
unsafe impl CtxDestroy for OsslStoreSearch {
    /// Empty: `OSSL_STORE_SEARCH_free` is a bare block free.
    unsafe fn destroy_body(_ptr: *mut OsslStoreSearch) {}
}

// SAFETY: (a) holds: `destroy_body` is `OSSL_STORE_INFO_free` minus the block -- the member
// selected by `type_`, each releaser NULL-tolerant, never the enclosing block. (b) holds: an
// all-zero info has `type_` unset, so the `_ => {}` arm releases nothing -- what the safe
// `OwnedCtx::zalloc` leans on.
unsafe impl CtxDestroy for OsslStoreInfo {
    unsafe fn destroy_body(ptr: *mut OsslStoreInfo) {
        // SAFETY: `ptr` is a live object per the trait contract.
        unsafe {
            match (*ptr).type_ {
                OSSL_STORE_INFO_NAME => {
                    // SAFETY: the type is NAME, so `name`/`desc` are live and owned.
                    CRYPTO_free((*ptr).data.name.name.cast::<c_void>(), ptr::null(), 0);
                    CRYPTO_free((*ptr).data.name.desc.cast::<c_void>(), ptr::null(), 0);
                }
                OSSL_STORE_INFO_PARAMS => {
                    // SAFETY: the type is PARAMS, so `params` is live and owned.
                    EVP_PKEY_free((*ptr).data.params);
                }
                OSSL_STORE_INFO_PUBKEY => {
                    // SAFETY: the type is PUBKEY, so `pubkey` is live and owned.
                    EVP_PKEY_free((*ptr).data.pubkey);
                }
                OSSL_STORE_INFO_PKEY => {
                    // SAFETY: the type is PKEY, so `pkey` is live and owned.
                    EVP_PKEY_free((*ptr).data.pkey);
                }
                OSSL_STORE_INFO_CERT => {
                    // SAFETY: the type is CERT, so `x509` is live and owned as an `X509`.
                    X509_free((*ptr).data.x509.cast::<X509>());
                }
                OSSL_STORE_INFO_CRL => {
                    // SAFETY: the type is CRL, so `crl` is live and owned as an `X509_CRL`.
                    X509_CRL_free((*ptr).data.crl.cast::<X509Crl>());
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Constants — the `store.h`/`storeerr.h`/`core_names.h` numbers and literals
// ---------------------------------------------------------------------------

/// `ERR_LIB_OSSL_STORE` — `include/openssl/err.h:158`.
const ERR_LIB_OSSL_STORE: c_int = 44;

/// `OSSL_STORE_R_NOT_A_PRIVATE_KEY` — `include/openssl/storeerr.h:33`.
const OSSL_STORE_R_NOT_A_PRIVATE_KEY: c_int = 102;
/// `OSSL_STORE_R_NOT_A_NAME` — `include/openssl/storeerr.h:32`.
const OSSL_STORE_R_NOT_A_NAME: c_int = 103;
/// `OSSL_STORE_R_NOT_PARAMETERS` — `include/openssl/storeerr.h:35`.
const OSSL_STORE_R_NOT_PARAMETERS: c_int = 104;
/// `OSSL_STORE_R_LOADING_STARTED` — `include/openssl/storeerr.h:29`.
const OSSL_STORE_R_LOADING_STARTED: c_int = 117;
/// `OSSL_STORE_R_UNSUPPORTED_OPERATION` — `include/openssl/storeerr.h:43`.
const OSSL_STORE_R_UNSUPPORTED_OPERATION: c_int = 118;
/// `OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST` — `storeerr.h:25`.
const OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST: c_int = 121;
/// `OSSL_STORE_R_NOT_A_PUBLIC_KEY` — `include/openssl/storeerr.h:34`.
const OSSL_STORE_R_NOT_A_PUBLIC_KEY: c_int = 122;
/// `OSSL_STORE_R_NOT_A_CERTIFICATE` — `include/openssl/storeerr.h`.
const OSSL_STORE_R_NOT_A_CERTIFICATE: c_int = 100;
/// `OSSL_STORE_R_NOT_A_CRL` — `include/openssl/storeerr.h`.
const OSSL_STORE_R_NOT_A_CRL: c_int = 101;

/// `ERR_R_OSSL_STORE_LIB` — `err.h:342`, `44 | ERR_RFLAG_COMMON`.
const ERR_R_OSSL_STORE_LIB: c_int = 524332;
/// `ERR_R_CRYPTO_LIB` — `err.h:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// `OSSL_STORE_C_USE_SECMEM` — `include/openssl/store.h:85`.
pub(crate) const OSSL_STORE_C_USE_SECMEM: c_int = 1;

/// `OSSL_STORE_SEARCH_BY_NAME` — `include/openssl/store.h:213`.
const OSSL_STORE_SEARCH_BY_NAME: c_int = 1;
/// `OSSL_STORE_SEARCH_BY_ISSUER_SERIAL` — `include/openssl/store.h:214`.
const OSSL_STORE_SEARCH_BY_ISSUER_SERIAL: c_int = 2;
/// `OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT` — `include/openssl/store.h:215`.
const OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT: c_int = 3;
/// `OSSL_STORE_SEARCH_BY_ALIAS` — `include/openssl/store.h:216`.
const OSSL_STORE_SEARCH_BY_ALIAS: c_int = 4;

/// `OSSL_STORE_PARAM_EXPECT` — `core_names.h:575`.
const OSSL_STORE_PARAM_EXPECT: &CStr = c"expect";
/// `OSSL_STORE_PARAM_PROPERTIES` — `core_names.h:579`.
const OSSL_STORE_PARAM_PROPERTIES: &CStr = c"properties";
/// `OSSL_STORE_PARAM_SUBJECT` — `core_names.h:581`.
const OSSL_STORE_PARAM_SUBJECT: &CStr = c"subject";
/// `OSSL_STORE_PARAM_ISSUER` — `core_names.h:578`.
const OSSL_STORE_PARAM_ISSUER: &CStr = c"name";
/// `OSSL_STORE_PARAM_SERIAL` — `core_names.h:580`.
const OSSL_STORE_PARAM_SERIAL: &CStr = c"serial";
/// `OSSL_STORE_PARAM_DIGEST` — `core_names.h:574`.
const OSSL_STORE_PARAM_DIGEST: &CStr = c"digest";
/// `OSSL_STORE_PARAM_FINGERPRINT` — `core_names.h:576`.
const OSSL_STORE_PARAM_FINGERPRINT: &CStr = c"fingerprint";
/// `OSSL_STORE_PARAM_ALIAS` — `core_names.h:573`.
const OSSL_STORE_PARAM_ALIAS: &CStr = c"alias";
/// `"use_secmem"` — the `OSSL_STORE_vctrl` `OSSL_STORE_C_USE_SECMEM` entry.
const OSSL_STORE_PARAM_USE_SECMEM: &CStr = c"use_secmem";

// ---------------------------------------------------------------------------
// The raise coordinates
//
// `crypto/store/store_lib.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`,
// so its coordinates are declared here under the generator's own naming, the way
// `store_meth.rs` declares its six. Each is the authority's own file/line/function.
// ---------------------------------------------------------------------------

/// One `store_lib.c` raise coordinate. `line` and `func` are the authority file's own.
const fn store_lib_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
    dynamic_reason: bool,
) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/store/store_lib.c",
        line,
        func,
        lib: ERR_LIB_OSSL_STORE,
        reason,
        dynamic_reason,
    }
}

/// `OSSL_STORE_open_ex` at `store_lib.c:82` (a NULL URI).
const STORE_LIB_82: err_sites::ErrSite = store_lib_site(
    82,
    c"OSSL_STORE_open_ex",
    ERR_R_PASSED_NULL_PARAMETER,
    false,
);
/// `OSSL_STORE_open_ex` at `store_lib.c:115`.
const STORE_LIB_115: err_sites::ErrSite =
    store_lib_site(115, c"OSSL_STORE_open_ex", ERR_R_CRYPTO_LIB, false);
/// `OSSL_STORE_expect` at `store_lib.c:299`.
const STORE_LIB_299: err_sites::ErrSite = store_lib_site(
    299,
    c"OSSL_STORE_expect",
    ERR_R_PASSED_INVALID_ARGUMENT,
    false,
);
/// `OSSL_STORE_expect` at `store_lib.c:303`.
const STORE_LIB_303: err_sites::ErrSite = store_lib_site(
    303,
    c"OSSL_STORE_expect",
    OSSL_STORE_R_LOADING_STARTED,
    false,
);
/// `OSSL_STORE_find` at `store_lib.c:329`.
const STORE_LIB_329: err_sites::ErrSite =
    store_lib_site(329, c"OSSL_STORE_find", OSSL_STORE_R_LOADING_STARTED, false);
/// `OSSL_STORE_find` at `store_lib.c:333` (a NULL search).
const STORE_LIB_333: err_sites::ErrSite =
    store_lib_site(333, c"OSSL_STORE_find", ERR_R_PASSED_NULL_PARAMETER, false);
/// `OSSL_STORE_find` at `store_lib.c:347`.
const STORE_LIB_347: err_sites::ErrSite = store_lib_site(
    347,
    c"OSSL_STORE_find",
    OSSL_STORE_R_UNSUPPORTED_OPERATION,
    false,
);
/// `OSSL_STORE_find` at `store_lib.c:352`.
const STORE_LIB_352: err_sites::ErrSite =
    store_lib_site(352, c"OSSL_STORE_find", ERR_R_CRYPTO_LIB, false);
/// `OSSL_STORE_find` at `store_lib.c:410` (the legacy branch).
const STORE_LIB_410: err_sites::ErrSite = store_lib_site(
    410,
    c"OSSL_STORE_find",
    OSSL_STORE_R_UNSUPPORTED_OPERATION,
    false,
);
/// `OSSL_STORE_delete` at `store_lib.c:502` (a NULL URI).
const STORE_LIB_502: err_sites::ErrSite = store_lib_site(
    502,
    c"OSSL_STORE_delete",
    ERR_R_PASSED_NULL_PARAMETER,
    false,
);
/// `OSSL_STORE_delete` at `store_lib.c:514`.
const STORE_LIB_514: err_sites::ErrSite =
    store_lib_site(514, c"OSSL_STORE_delete", ERR_R_CRYPTO_LIB, false);
/// `OSSL_STORE_INFO_new_NAME` at `store_lib.c:631`.
const STORE_LIB_631: err_sites::ErrSite = store_lib_site(
    631,
    c"OSSL_STORE_INFO_new_NAME",
    ERR_R_OSSL_STORE_LIB,
    false,
);
/// `OSSL_STORE_INFO_set0_NAME_description` at `store_lib.c:644`.
const STORE_LIB_644: err_sites::ErrSite = store_lib_site(
    644,
    c"OSSL_STORE_INFO_set0_NAME_description",
    ERR_R_PASSED_INVALID_ARGUMENT,
    false,
);
/// `OSSL_STORE_INFO_new_PARAMS` at `store_lib.c:657`.
const STORE_LIB_657: err_sites::ErrSite = store_lib_site(
    657,
    c"OSSL_STORE_INFO_new_PARAMS",
    ERR_R_OSSL_STORE_LIB,
    false,
);
/// `OSSL_STORE_INFO_new_PUBKEY` at `store_lib.c:666`.
const STORE_LIB_666: err_sites::ErrSite = store_lib_site(
    666,
    c"OSSL_STORE_INFO_new_PUBKEY",
    ERR_R_OSSL_STORE_LIB,
    false,
);
/// `OSSL_STORE_INFO_new_PKEY` at `store_lib.c:675`.
const STORE_LIB_675: err_sites::ErrSite = store_lib_site(
    675,
    c"OSSL_STORE_INFO_new_PKEY",
    ERR_R_OSSL_STORE_LIB,
    false,
);
/// `OSSL_STORE_INFO_new_CERT` at `store_lib.c:684`.
const STORE_LIB_684: err_sites::ErrSite = store_lib_site(
    684,
    c"OSSL_STORE_INFO_new_CERT",
    ERR_R_OSSL_STORE_LIB,
    false,
);
/// `OSSL_STORE_INFO_new_CRL` at `store_lib.c:693`.
const STORE_LIB_693: err_sites::ErrSite =
    store_lib_site(693, c"OSSL_STORE_INFO_new_CRL", ERR_R_OSSL_STORE_LIB, false);
/// `OSSL_STORE_INFO_get1_NAME` at `store_lib.c:723`.
const STORE_LIB_723: err_sites::ErrSite = store_lib_site(
    723,
    c"OSSL_STORE_INFO_get1_NAME",
    OSSL_STORE_R_NOT_A_NAME,
    false,
);
/// `OSSL_STORE_INFO_get1_NAME_description` at `store_lib.c:738`.
const STORE_LIB_738: err_sites::ErrSite = store_lib_site(
    738,
    c"OSSL_STORE_INFO_get1_NAME_description",
    OSSL_STORE_R_NOT_A_NAME,
    false,
);
/// `OSSL_STORE_INFO_get1_PARAMS` at `store_lib.c:756`.
const STORE_LIB_756: err_sites::ErrSite = store_lib_site(
    756,
    c"OSSL_STORE_INFO_get1_PARAMS",
    OSSL_STORE_R_NOT_PARAMETERS,
    false,
);
/// `OSSL_STORE_INFO_get1_PUBKEY` at `store_lib.c:774`.
const STORE_LIB_774: err_sites::ErrSite = store_lib_site(
    774,
    c"OSSL_STORE_INFO_get1_PUBKEY",
    OSSL_STORE_R_NOT_A_PUBLIC_KEY,
    false,
);
/// `OSSL_STORE_INFO_get1_PKEY` at `store_lib.c:792`.
const STORE_LIB_792: err_sites::ErrSite = store_lib_site(
    792,
    c"OSSL_STORE_INFO_get1_PKEY",
    OSSL_STORE_R_NOT_A_PRIVATE_KEY,
    false,
);
/// `OSSL_STORE_INFO_get1_CERT` at `store_lib.c:810` (10.8 closes it).
const STORE_LIB_810: err_sites::ErrSite = store_lib_site(
    810,
    c"OSSL_STORE_INFO_get1_CERT",
    OSSL_STORE_R_NOT_A_CERTIFICATE,
    false,
);
/// `OSSL_STORE_INFO_get1_CRL` at `store_lib.c:828` (10.8 closes it).
const STORE_LIB_828: err_sites::ErrSite = store_lib_site(
    828,
    c"OSSL_STORE_INFO_get1_CRL",
    OSSL_STORE_R_NOT_A_CRL,
    false,
);
/// `OSSL_STORE_SEARCH_by_key_fingerprint` at `store_lib.c:959` — the one site whose
/// message data is formatted at run time, so `dynamic_reason` is unused and the text
/// is supplied by the caller.
const STORE_LIB_959: err_sites::ErrSite = store_lib_site(
    959,
    c"OSSL_STORE_SEARCH_by_key_fingerprint",
    OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST,
    false,
);

// ---------------------------------------------------------------------------
// The object model — `store_local.h`'s three structs
// ---------------------------------------------------------------------------

/// `struct { char *name; char *desc; } name` — the `OSSL_STORE_INFO_NAME` member.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OsslStoreInfoName {
    /// `char *name` — the borrowed-then-owned name; freed by `OSSL_STORE_INFO_free`.
    pub(crate) name: *mut c_char,
    /// `char *desc` — the optional description.
    pub(crate) desc: *mut c_char,
}

/// The authority's unnamed `union { ... } _` of `struct ossl_store_info_st`.
///
/// Rust reserves `_`, so the struct's field is named `data` here. Every member is a
/// pointer (or the two-pointer `name` pair), so the union is sixteen bytes and
/// eight-aligned whichever member is live.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union OsslStoreInfoData {
    /// `void *data` — the generic pointer `OSSL_STORE_INFO_get0_data` reports.
    pub(crate) data: *mut c_void,
    /// The `OSSL_STORE_INFO_NAME` member.
    pub(crate) name: OsslStoreInfoName,
    /// `EVP_PKEY *params` — the `OSSL_STORE_INFO_PARAMS` member.
    pub(crate) params: *mut EvpPkey,
    /// `EVP_PKEY *pubkey` — the `OSSL_STORE_INFO_PUBKEY` member.
    pub(crate) pubkey: *mut EvpPkey,
    /// `EVP_PKEY *pkey` — the `OSSL_STORE_INFO_PKEY` member.
    pub(crate) pkey: *mut EvpPkey,
    /// `X509 *x509` — the `OSSL_STORE_INFO_CERT` member, opaque here (Phase 11's).
    pub(crate) x509: *mut c_void,
    /// `X509_CRL *crl` — the `OSSL_STORE_INFO_CRL` member, opaque here (Phase 11's).
    pub(crate) crl: *mut c_void,
}

/// `struct ossl_store_info_st` — `store_local.h:26-42`.
#[repr(C)]
pub struct OsslStoreInfo {
    /// `int type` — one of the public `OSSL_STORE_INFO_*` numbers.
    pub(crate) type_: c_int,
    /// The authority's unnamed `union { ... } _`, named `data` here.
    pub(crate) data: OsslStoreInfoData,
}

/// `struct ossl_store_search_st` — `store_local.h:50-71`.
#[repr(C)]
pub(crate) struct OsslStoreSearch {
    /// `int search_type` — one of the public `OSSL_STORE_SEARCH_BY_*` numbers.
    pub(crate) search_type: c_int,
    /// `X509_NAME *name` — borrowed; used by BY_NAME and BY_ISSUER_SERIAL.
    pub(crate) name: *mut c_void,
    /// `const ASN1_INTEGER *serial` — borrowed; used by BY_ISSUER_SERIAL.
    pub(crate) serial: *const c_void,
    /// `const EVP_MD *digest` — borrowed; used by BY_KEY_FINGERPRINT.
    pub(crate) digest: *const EvpMd,
    /// `const unsigned char *string` — borrowed; BY_KEY_FINGERPRINT and BY_ALIAS.
    pub(crate) string: *const c_uchar,
    /// `size_t stringlength` — the length of `string`.
    pub(crate) stringlength: usize,
}

/// `OSSL_STORE_post_process_info_fn` — `store.h:44-45`.
///
/// `OSSL_STORE_INFO *(*)(OSSL_STORE_INFO *, void *)`. A NULL callback is
/// `Option::None`, which has the same layout as the authority's pointer.
pub(crate) type OsslStorePostProcessInfoFn =
    unsafe extern "C" fn(*mut OsslStoreInfo, *mut c_void) -> *mut OsslStoreInfo;

/// `struct ossl_store_ctx_st` — `store_local.h:133-155`.
#[repr(C)]
pub struct OsslStoreCtx {
    /// `const OSSL_STORE_LOADER *loader` — the legacy loader (or the fetched one).
    pub(crate) loader: *const OsslStoreLoader,
    /// `OSSL_STORE_LOADER *fetched_loader` — non-NULL only for a provider loader.
    pub(crate) fetched_loader: *mut OsslStoreLoader,
    /// `OSSL_STORE_LOADER_CTX *loader_ctx`.
    pub(crate) loader_ctx: *mut OsslStoreLoaderCtx,
    /// `OSSL_STORE_post_process_info_fn post_process`.
    // written by `OSSL_STORE_open_ex`; read by `OSSL_STORE_load`
    pub(crate) post_process: Option<OsslStorePostProcessInfoFn>,
    /// `void *post_process_data`.
    // written by `OSSL_STORE_open_ex`; read by `OSSL_STORE_load`
    pub(crate) post_process_data: *mut c_void,
    /// `int expected_type` — written by `OSSL_STORE_expect`.
    // written by `OSSL_STORE_expect`; read by `OSSL_STORE_load`
    pub(crate) expected_type: c_int,
    /// `char *properties` — the owned copy of the property query.
    pub(crate) properties: *mut c_char,
    /// `int loading` — 0 before the first `OSSL_STORE_load`, 1 otherwise.
    pub(crate) loading: c_int,
    /// `int error_flag` — 1 on a fetched-loader load error.
    pub(crate) error_flag: c_int,
    /// `STACK_OF(OSSL_STORE_INFO) *cached_info` — the PKCS#12 one-object-at-a-time cache.
    pub(crate) cached_info: *mut OpenSslStack,
    /// `struct ossl_passphrase_data_st pwdata`.
    pub(crate) pwdata: OsslPassphraseData,
}

/// `OSSL_STORE_INFO_free` as an `OPENSSL_sk_freefunc`.
///
/// `OPENSSL_sk_pop_free` takes `void (*)(void *)` and `OSSL_STORE_INFO_free` takes
/// `OSSL_STORE_INFO *`; this is the typed bridge the stack frees through.
///
/// # Safety
/// `p` must be NULL, or the base pointer of an allocation produced by this crate's
/// `OSSL_STORE_INFO_new*` constructors: it must come from the `CRYPTO_*` allocator seam
/// at the authority's size/`file`/`line`, be suitably aligned for `OsslStoreInfo`, be
/// fully initialised as an `OSSL_STORE_INFO`, and be exclusively owned by the stack that
/// is freeing it (no other owner, not already released). Ownership transfers to
/// `OSSL_STORE_INFO_free`, which releases the block; `p` must not be used afterwards.
/// A pointer that is not such an allocation, or one still owned elsewhere, is undefined
/// behaviour. ABI: this is the `OPENSSL_sk_freefunc` (`void (*)(void *)`) form, invoked
/// exactly once per stack element.
unsafe extern "C" fn store_info_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `OSSL_STORE_INFO *` values, per its declaration.
    unsafe { OSSL_STORE_INFO_free(p.cast::<OsslStoreInfo>()) };
}

/// A local `strlen`, the way the crate's other modules carry one.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract, so the walk stops.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `static int loader_set_params(OSSL_STORE_LOADER *loader, OSSL_STORE_LOADER_CTX
/// *loader_ctx, const OSSL_PARAM params[], const char *propq)` — `store_lib.c:35-61`.
///
/// `loader->p_set_ctx_params` is dereferenced unconditionally by the authority when
/// `params != NULL`; the crate spells that as a skip, because both callers are in the
/// fetched branch and a provider loader may legitimately leave `p_set_ctx_params` NULL
/// (`store_meth.rs` treats it as optional), where `OSSL_STORE_ctrl`'s own convention is
/// that a loader without one ignores the parameters and answers 1.
///
/// # Safety
/// `loader` must be live; `params` NULL or a terminated array; `propq` NULL or
/// NUL-terminated.
unsafe fn loader_set_params(
    loader: *const OsslStoreLoader,
    loader_ctx: *mut c_void,
    params: *const OsslParam,
    propq: *const c_char,
) -> c_int {
    if !params.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(set_ctx_params) = unsafe { (*loader).p_set_ctx_params } {
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if unsafe { set_ctx_params(loader_ctx, params) } == 0 {
                return 0;
            }
        }
    }

    if !propq.is_null() {
        // SAFETY: `params` is NULL or terminated; `locate_const` handles both.
        if !unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES.as_ptr()) }
            .is_null()
        {
            return 1;
        }

        let propp = [
            // SAFETY: the key is a static literal; `propq` is NUL-terminated.
            unsafe {
                crate::params::OSSL_PARAM_construct_utf8_string(
                    OSSL_STORE_PARAM_PROPERTIES.as_ptr(),
                    propq.cast_mut(),
                    0,
                )
            },
            OSSL_PARAM_construct_end(),
        ];

        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(set_ctx_params) = unsafe { (*loader).p_set_ctx_params } {
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if unsafe { set_ctx_params(loader_ctx, propp.as_ptr()) } == 0 {
                return 0;
            }
        }
    }
    1
}

/// `static int ossl_store_close_it(OSSL_STORE_CTX *ctx)` — `store_lib.c:577-597`.
///
/// # Safety
/// `ctx` must be NULL or a live `OsslStoreCtx`.
unsafe fn ossl_store_close_it(ctx: *mut OsslStoreCtx) -> c_int {
    let mut ret = 0;
    if ctx.is_null() {
        return 1;
    }

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if !unsafe { (*ctx).fetched_loader }.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(p_close) = unsafe { (*(*ctx).loader).p_close } {
            // SAFETY: `loader_ctx` is the fetched loader's own context.
            ret = unsafe { p_close((*ctx).loader_ctx.cast::<c_void>()) };
        }
    }
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if unsafe { (*ctx).fetched_loader }.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(closefn) = unsafe { (*(*ctx).loader).closefn } {
            // SAFETY: `loader_ctx` is the legacy loader's own context.
            ret = unsafe { closefn((*ctx).loader_ctx) };
        }
    }

    // SAFETY: `cached_info` is NULL or the stack `OSSL_STORE_load` fills; the thunk
    // frees each `OSSL_STORE_INFO`.
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    unsafe { OPENSSL_sk_pop_free((*ctx).cached_info, Some(store_info_free_thunk)) };
    // SAFETY: `fetched_loader` is NULL or a loader this context holds one reference to.
    unsafe { OSSL_STORE_LOADER_free((*ctx).fetched_loader) };
    // SAFETY: `properties` is NULL or the `CRYPTO_strdup` this context owns.
    unsafe { CRYPTO_free((*ctx).properties.cast::<c_void>(), ptr::null(), 0) };
    // SAFETY: `pwdata` is live and owned by `ctx`.
    unsafe { ossl_pw_clear_passphrase_data(&mut (*ctx).pwdata) };
    ret
}

// ---------------------------------------------------------------------------
// The `OSSL_STORE_CTX` entry points
// ---------------------------------------------------------------------------

/// `OSSL_STORE_CTX *OSSL_STORE_open_ex(const char *uri, OSSL_LIB_CTX *libctx,
/// const char *propq, const UI_METHOD *ui_method, void *ui_data,
/// const OSSL_PARAM params[], OSSL_STORE_post_process_info_fn post_process,
/// void *post_process_data)` — `store_lib.c:63-238`.
///
/// # Safety
/// `uri`/`propq` NULL or NUL-terminated; `libctx` NULL or live; `ui_method` NULL or
/// live; `params` NULL or a terminated array; `post_process` NULL or a valid
/// callback; `post_process_data` opaque.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // the authority's own eight-parameter arity
pub unsafe extern "C" fn OSSL_STORE_open_ex(
    uri: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
    params: *const OsslParam,
    post_process: Option<OsslStorePostProcessInfoFn>,
    post_process_data: *mut c_void,
) -> *mut OsslStoreCtx {
    // SAFETY: an all-zero `ossl_passphrase_data_st` is its own initialiser (`{ 0 }`).
    let mut pwdata: OsslPassphraseData = unsafe { core::mem::zeroed() };
    let mut loader: *const OsslStoreLoader = ptr::null();
    let mut fetched_loader: *mut OsslStoreLoader = ptr::null_mut();
    let mut loader_ctx: *mut OsslStoreLoaderCtx = ptr::null_mut();
    let mut no_loader_found: c_int = 1;
    let mut scheme_copy = [0 as c_char; 256];
    let mut schemes: [*const c_char; 2] = [ptr::null(); 2];
    let mut schemes_n: usize = 0;
    let mut scheme: *const c_char;

    if uri.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_82) };
        return ptr::null_mut();
    }

    /*
     * Put the file scheme first.  If the uri does represent an existing file, possible
     * device name and all, then it should be loaded.  Only a failed attempt at loading a
     * local file should have us try something else.
     */
    schemes[schemes_n] = c"file".as_ptr();
    schemes_n += 1;

    // SAFETY: `scheme_copy` is a 256-byte buffer and `uri` is NUL-terminated.
    unsafe { OPENSSL_strlcpy(scheme_copy.as_mut_ptr(), uri, scheme_copy.len()) };
    // `strchr(scheme_copy, ':')`, without libc's `strchr`.
    let mut scheme_end: Option<usize> = None;
    {
        let mut i = 0usize;
        while i < scheme_copy.len() {
            let ch = scheme_copy[i];
            if ch == 0 {
                break;
            }
            if ch == b':' as c_char {
                scheme_end = Some(i);
                break;
            }
            i += 1;
        }
    }
    if let Some(i) = scheme_end {
        scheme_copy[i] = 0;
        // SAFETY: `i < len`, so `i + 1 <= len`; the `CAS_PREFIX` read is bounded below.
        let p = unsafe { scheme_copy.as_ptr().add(i + 1) };
        // SAFETY: both strings are NUL-terminated.
        if unsafe { OPENSSL_strcasecmp(scheme_copy.as_ptr(), c"file".as_ptr()) } != 0 {
            // `HAS_PREFIX(p, "//")`.
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if unsafe { *p == b'/' as c_char && *p.add(1) == b'/' as c_char } {
                schemes_n -= 1; /* Invalidate the file scheme */
            }
            schemes[schemes_n] = scheme_copy.as_ptr();
            schemes_n += 1;
        }
    }

    // SAFETY: the error queue is available.
    ERR_set_mark();

    'err: {
        // The property-query copy this attempt keeps, owned until it is handed to the context's
        // `properties` member below or released by `Drop` on a refusal.
        let mut propq_copy: Option<OwnedBuf> = None;

        if !ui_method.is_null()
            // SAFETY: `pwdata` is live; the two calls set and enable caching.
            && (unsafe { ossl_pw_set_ui_method(&mut pwdata, ui_method, ui_data) } == 0
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                || unsafe { ossl_pw_enable_passphrase_caching(&mut pwdata) } == 0)
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&STORE_LIB_115) };
            break 'err;
        }

        let mut i = 0usize;
        while loader_ctx.is_null() && i < schemes_n {
            scheme = schemes[i];
            // SAFETY: a compile-time-constant site.
            ERR_set_mark();
            // SAFETY: `scheme` is NUL-terminated.
            loader = unsafe { ossl_store_get0_loader_int(scheme) };
            if !loader.is_null() {
                // SAFETY: the mark was set above.
                ERR_clear_last_mark();
                no_loader_found = 0;
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                if let Some(open_ex) = unsafe { (*loader).open_ex } {
                    // SAFETY: `loader`, `uri`, `ui_method` and `ui_data` are per the contract.
                    loader_ctx = unsafe {
                        open_ex(
                            loader,
                            uri,
                            libctx,
                            propq,
                            ui_method.cast::<c_void>(),
                            ui_data,
                        )
                    };
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                } else if let Some(open) = unsafe { (*loader).open } {
                    // SAFETY: as above.
                    loader_ctx = unsafe { open(loader, uri, ui_method.cast::<c_void>(), ui_data) };
                }
            } else {
                // SAFETY: the mark was set above.
                ERR_pop_to_mark();
            }

            if loader.is_null() {
                // SAFETY: `libctx`, `scheme` and `propq` are per the contract.
                fetched_loader = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme, propq) };
                if !fetched_loader.is_null() {
                    // SAFETY: `fetched_loader` is a provider loader, so its provider is live.
                    let provider = unsafe { OSSL_STORE_LOADER_get0_provider(fetched_loader) };
                    // SAFETY: `provider` is live.
                    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(provider) };
                    no_loader_found = 0;
                    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                    if let Some(p_open_ex) = unsafe { (*fetched_loader).p_open_ex } {
                        // SAFETY: the provider callbacks take the passed context and params.
                        loader_ctx = unsafe {
                            p_open_ex(
                                provctx,
                                uri,
                                params,
                                Some(ossl_pw_passphrase_callback_dec),
                                (&mut pwdata as *mut OsslPassphraseData).cast::<c_void>(),
                            )
                        }
                        .cast::<OsslStoreLoaderCtx>();
                    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                    } else if let Some(p_open) = unsafe { (*fetched_loader).p_open } {
                        // SAFETY: as above.
                        let opened = unsafe { p_open(provctx, uri) };
                        if !opened.is_null()
                            // SAFETY: `opened` is the provider's context; `params`/`propq` per contract.
                            && unsafe {
                                loader_set_params(fetched_loader, opened, params, propq)
                            } == 0
                        {
                            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                            if let Some(p_close) = unsafe { (*fetched_loader).p_close } {
                                // SAFETY: `opened` is the provider's own context.
                                unsafe { p_close(opened) };
                            }
                        } else {
                            loader_ctx = opened.cast::<OsslStoreLoaderCtx>();
                        }
                    }
                    if loader_ctx.is_null() {
                        // SAFETY: `fetched_loader` is live and this context is not keeping it.
                        unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                        fetched_loader = ptr::null_mut();
                    }
                    loader = fetched_loader;

                    /* Clear any internally cached passphrase */
                    // SAFETY: `pwdata` is live.
                    unsafe { ossl_pw_clear_passphrase_cache(&mut pwdata) };
                }
            }
            i += 1;
        }

        if no_loader_found != 0 {
            /*
             * It's assumed that ossl_store_get0_loader_int() and
             * OSSL_STORE_LOADER_fetch() report their own errors
             */
            break 'err;
        }

        if loader_ctx.is_null() {
            /*
             * It's assumed that the loader's open() method reports its own errors
             */
            break 'err;
        }

        if !propq.is_null() {
            // SAFETY: `propq` is NUL-terminated per the contract, so `CRYPTO_strdup` answers this
            // crate's own property copy; that block is owned here until `Drop` releases it or the
            // context's `properties` member takes it over, and no other owner holds it.
            propq_copy = unsafe {
                let copy = CRYPTO_strdup(propq, ptr::null(), 0);
                OwnedBuf::adopt_plain(copy.cast::<u8>(), SeamFile::NULL, 0)
            };
            if propq_copy.is_none() {
                break 'err;
            }
        }
        // The context block, allocated through the crate's allocator seam; `Drop` is its single
        // release on every refusal below and `into_raw` hands it out on success.
        let Some(ctx) = OwnedCtx::<OsslStoreCtx>::zalloc() else {
            break 'err;
        };

        // SAFETY: `ctx` is a fresh zeroed allocation and every pointer stored is live.
        unsafe {
            (*ctx.as_ptr()).properties = propq_copy
                .take()
                .map_or(ptr::null_mut(), |b| b.into_raw().cast::<c_char>());
            (*ctx.as_ptr()).fetched_loader = fetched_loader;
            (*ctx.as_ptr()).loader = loader;
            (*ctx.as_ptr()).loader_ctx = loader_ctx;
            (*ctx.as_ptr()).post_process = post_process;
            (*ctx.as_ptr()).post_process_data = post_process_data;
            ptr::write(&mut (*ctx.as_ptr()).pwdata, pwdata);
        }

        /*
         * If the attempt to open with the 'file' scheme loader failed and the other scheme
         * loader succeeded, the failure to open with the 'file' scheme loader leaves an
         * error on the error stack.  Let's remove it.
         */
        // SAFETY: a mark was set at entry.
        ERR_pop_to_mark();

        return ctx.into_raw();
    }

    // err:
    // SAFETY: a mark was set at entry.
    ERR_clear_last_mark();
    if !loader_ctx.is_null() {
        /*
         * Temporary structure so OSSL_STORE_close() can work even when |ctx| couldn't be
         * allocated properly
         */
        // SAFETY: an all-zero context is the authority's `{ NULL, }`.
        let mut tmpctx: OsslStoreCtx = unsafe { core::mem::zeroed() };
        tmpctx.fetched_loader = fetched_loader;
        tmpctx.loader = loader;
        tmpctx.loader_ctx = loader_ctx;

        // SAFETY: the three fields above are the context's live ones.
        unsafe { ossl_store_close_it(&mut tmpctx) };
        // `ossl_store_close_it` releases the one reference this frame's `OSSL_STORE_LOADER_fetch`
        // acquired and it was handed over through `tmpctx.fetched_loader`; the local carries no
        // second release. The authority frees it again at `store_lib.c:234` (the Coverity-
        // suppressed OOM double release this repair does not reproduce, §17).
    } else {
        // SAFETY: no `loader_ctx` exists, so no temporary context took the fetch reference. Every
        // loop path that fetched a loader and failed to open one already released and nulled it,
        // so this is either NULL (the authority's no-op) or the single release of the reference
        // this frame still owns.
        unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
    }
    // `propq_copy` and `ctx` were scoped to the block above and released by their `Drop` there.
    ptr::null_mut()
}

/// `OSSL_STORE_CTX *OSSL_STORE_open(const char *uri, const UI_METHOD *ui_method,
/// void *ui_data, OSSL_STORE_post_process_info_fn post_process,
/// void *post_process_data)` — `store_lib.c:240-247`.
///
/// # Safety
/// As [`OSSL_STORE_open_ex`], with `libctx`, `propq` and `params` defaulted to NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_open(
    uri: *const c_char,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
    post_process: Option<OsslStorePostProcessInfoFn>,
    post_process_data: *mut c_void,
) -> *mut OsslStoreCtx {
    // SAFETY: NULL `libctx`/`propq`/`params` are the authority's own defaults here.
    unsafe {
        OSSL_STORE_open_ex(
            uri,
            ptr::null_mut(),
            ptr::null(),
            ui_method,
            ui_data,
            ptr::null(),
            post_process,
            post_process_data,
        )
    }
}

/// `int OSSL_STORE_expect(OSSL_STORE_CTX *ctx, int expected_type)` — `store_lib.c:293-322`.
///
/// # Safety
/// `ctx` must be NULL or live; the loader's `expect` callback, if reached, must
/// tolerate the context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_expect(ctx: *mut OsslStoreCtx, expected_type: c_int) -> c_int {
    let mut ret = 1;

    if ctx.is_null() || !(0..=OSSL_STORE_INFO_CRL).contains(&expected_type) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_299) };
        return 0;
    }
    // SAFETY: `ctx` is non-NULL per the guard above.
    if unsafe { (*ctx).loading } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_303) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe { (*ctx).expected_type = expected_type };
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    let fetched = unsafe { (*ctx).fetched_loader };
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if !fetched.is_null() && unsafe { (*fetched).p_set_ctx_params }.is_some() {
        // The parameter's own address is what the authority constructs from.
        let mut local = expected_type;
        let params = [
            // SAFETY: `local` is a live `int`.
            unsafe { OSSL_PARAM_construct_int(OSSL_STORE_PARAM_EXPECT.as_ptr(), &mut local) },
            OSSL_PARAM_construct_end(),
        ];
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(set_ctx_params) = unsafe { (*fetched).p_set_ctx_params } {
            // SAFETY: `loader_ctx` is the fetched loader's own context.
            ret = unsafe { set_ctx_params((*ctx).loader_ctx.cast::<c_void>(), params.as_ptr()) };
        }
    }
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if unsafe { (*ctx).fetched_loader }.is_null() && unsafe { (*(*ctx).loader).expect }.is_some() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(expect) = unsafe { (*(*ctx).loader).expect } {
            // SAFETY: `loader_ctx` is the legacy loader's own context.
            ret = unsafe { expect((*ctx).loader_ctx, expected_type) };
        }
    }
    ret
}

/// `int OSSL_STORE_find(OSSL_STORE_CTX *ctx, const OSSL_STORE_SEARCH *search)` —
/// `store_lib.c:324-418`.
///
/// All four fetched arms and the legacy branch are transcribed. The `BY_NAME` and
/// `BY_ISSUER_SERIAL` arms, which the 10.5 slice carved out for `i2d_X509_NAME`, are
/// closed by 10.8: the name is encoded with `i2d_X509_NAME` and, for the issuer/serial
/// search, the serial with `ASN1_INTEGER_to_BN`.
///
/// # Safety
/// `ctx` must be NULL or live; `search` must be NULL or a live `OsslStoreSearch`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_find(
    ctx: *mut OsslStoreCtx,
    search: *const OsslStoreSearch,
) -> c_int {
    let mut ret = 1;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).loading } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_329) };
        return 0;
    }
    if search.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_333) };
        return 0;
    }

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    let fetched = unsafe { (*ctx).fetched_loader };
    if !fetched.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if unsafe { (*fetched).p_set_ctx_params }.is_none() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&STORE_LIB_347) };
            return 0;
        }

        // SAFETY: a fresh builder with no arguments.
        let bld = OSSL_PARAM_BLD_new();
        if bld.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&STORE_LIB_352) };
            return 0;
        }

        ret = 0; /* Assume the worst */

        // The two locals the `BY_NAME`/`BY_ISSUER_SERIAL` arms fill and the cleanup below
        // releases: `void *name_der = NULL` and `BIGNUM *number = NULL`.
        let mut name_der: *mut c_void = ptr::null_mut();
        let mut number: *mut BigNum = ptr::null_mut();

        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        match unsafe { (*search).search_type } {
            OSSL_STORE_SEARCH_BY_NAME => {
                // SAFETY: `search` owns the borrowed name; `name_der` is a live out-slot, and
                // `i2d_X509_NAME` allocates into it because it is NULL.
                let name_der_sz = unsafe {
                    i2d_X509_NAME(
                        (*search).name.cast::<X509Name>(),
                        (&raw mut name_der).cast::<*mut c_uchar>(),
                    )
                };
                if name_der_sz > 0 {
                    // SAFETY: `bld` is live and `name_der` holds `name_der_sz` bytes.
                    let pushed = unsafe {
                        OSSL_PARAM_BLD_push_octet_string(
                            bld,
                            OSSL_STORE_PARAM_SUBJECT.as_ptr(),
                            name_der,
                            name_der_sz as usize,
                        )
                    };
                    ret = c_int::from(pushed != 0);
                }
            }
            OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT => {
                // SAFETY: `bld` is live; the digest and bytes belong to `search`.
                let digest_ok = unsafe {
                    OSSL_PARAM_BLD_push_utf8_string(
                        bld,
                        OSSL_STORE_PARAM_DIGEST.as_ptr(),
                        EVP_MD_get0_name((*search).digest),
                        0,
                    )
                };
                // SAFETY: `bld` is live; `search` owns the borrowed fingerprint bytes.
                let fingerprint_ok = digest_ok != 0
                    && unsafe {
                        OSSL_PARAM_BLD_push_octet_string(
                            bld,
                            OSSL_STORE_PARAM_FINGERPRINT.as_ptr(),
                            (*search).string.cast::<c_void>(),
                            (*search).stringlength,
                        )
                    } != 0;
                ret = c_int::from(fingerprint_ok);
            }
            OSSL_STORE_SEARCH_BY_ALIAS => {
                // SAFETY: `bld` is live; `search` owns the borrowed alias bytes.
                let pushed = unsafe {
                    OSSL_PARAM_BLD_push_utf8_string(
                        bld,
                        OSSL_STORE_PARAM_ALIAS.as_ptr(),
                        (*search).string.cast::<c_char>(),
                        (*search).stringlength,
                    )
                };
                ret = c_int::from(pushed != 0);
            }
            OSSL_STORE_SEARCH_BY_ISSUER_SERIAL => {
                // SAFETY: `search` owns the borrowed name and serial; `name_der` is a live
                // out-slot, and `i2d_X509_NAME` allocates into it because it is NULL.
                let name_der_sz = unsafe {
                    i2d_X509_NAME(
                        (*search).name.cast::<X509Name>(),
                        (&raw mut name_der).cast::<*mut c_uchar>(),
                    )
                };
                if name_der_sz > 0 {
                    // SAFETY: `search->serial` is a borrowed `ASN1_INTEGER`; `ASN1_INTEGER_to_BN`
                    // with a NULL `bn` allocates a fresh `BIGNUM`.
                    number = unsafe {
                        ASN1_INTEGER_to_BN((*search).serial.cast::<Asn1String>(), ptr::null_mut())
                    };
                }
                if name_der_sz > 0 && !number.is_null() {
                    // SAFETY: `bld` is live, `name_der` holds `name_der_sz` bytes and `number` is
                    // the allocated BIGNUM.
                    let pushed = unsafe {
                        OSSL_PARAM_BLD_push_octet_string(
                            bld,
                            OSSL_STORE_PARAM_ISSUER.as_ptr(),
                            name_der,
                            name_der_sz as usize,
                        ) != 0
                            && OSSL_PARAM_BLD_push_BN(bld, OSSL_STORE_PARAM_SERIAL.as_ptr(), number)
                                != 0
                    };
                    ret = c_int::from(pushed);
                }
            }
            _ => {}
        }
        if ret != 0 {
            // SAFETY: `bld` is live and non-NULL.
            let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if let Some(set_ctx_params) = unsafe { (*fetched).p_set_ctx_params } {
                // SAFETY: `loader_ctx` is the fetched loader's own context.
                ret = unsafe { set_ctx_params((*ctx).loader_ctx.cast::<c_void>(), params) };
            }
            // SAFETY: `params` is the descriptor block the builder produced.
            unsafe { OSSL_PARAM_free(params) };
        }
        // SAFETY: `bld` is live and non-NULL.
        unsafe { OSSL_PARAM_BLD_free(bld) };
        // The `name_der` buffer `i2d_X509_NAME` filled is adopted by an owner whose `Drop` is its
        // release; `number` is NULL or the BIGNUM `ASN1_INTEGER_to_BN` allocated, released by
        // `BN_free`.
        // SAFETY: `name_der` is NULL or the `i2d_X509_NAME` block this frame allocated on the
        // crate's allocator seam and owns; no other owner holds it.
        let _name_der = unsafe { OwnedBuf::adopt_plain(name_der.cast::<u8>(), SeamFile::NULL, 0) };
        // SAFETY: `number` is NULL or the BIGNUM `ASN1_INTEGER_to_BN` allocated.
        unsafe { BN_free(number) };
    } else {
        /* legacy loader section */
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if unsafe { (*(*ctx).loader).find }.is_none() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&STORE_LIB_410) };
            return 0;
        }
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(find) = unsafe { (*(*ctx).loader).find } {
            // SAFETY: `loader_ctx` and `search` are the legacy loader's own.
            ret = unsafe { find((*ctx).loader_ctx, search.cast::<c_void>()) };
        }
    }

    ret
}

/// `OSSL_STORE_INFO *OSSL_STORE_load(OSSL_STORE_CTX *ctx)` — `store_lib.c:420-490`.
///
/// The unit's last export, and the crate's `src/store/mod.rs` doc named it as the one name
/// withheld. Its fetched branch hands `store_result.c`'s `ossl_store_handle_load_result` — now
/// landed in [`super::store_result`] — to the loader's `p_load`, and its legacy branch calls
/// the loader's own `load`. Both branches then run the context's post-process callback, clear
/// the internally cached passphrase, and drop any object whose type the caller did not expect.
///
/// # Safety
/// `ctx` must be NULL or a live `OsslStoreCtx`; the loader's `p_load`/`load` and the
/// post-process callback must tolerate the arguments supplied here.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_load(ctx: *mut OsslStoreCtx) -> *mut OsslStoreInfo {
    let mut v: *mut OsslStoreInfo = ptr::null_mut();

    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).loading = 1 };
    'again: loop {
        // SAFETY: `ctx` is live per the contract.
        if unsafe { OSSL_STORE_eof(ctx) } != 0 {
            return ptr::null_mut();
        }

        // SAFETY: `ctx` is live per the contract; `cached_info` is NULL or a live stack.
        if !unsafe { (*ctx).cached_info }.is_null() {
            // SAFETY: `cached_info` is a live stack of `OSSL_STORE_INFO`.
            v = unsafe { OPENSSL_sk_shift((*ctx).cached_info) }.cast::<OsslStoreInfo>();
        } else {
            // SAFETY: `ctx` is live per the contract.
            if !unsafe { (*ctx).fetched_loader }.is_null() {
                let mut load_data = OsslStoreLoadResultData {
                    v: ptr::null_mut(),
                    ctx,
                };
                // SAFETY: `ctx` is live per the contract.
                unsafe { (*ctx).error_flag = 0 };

                // SAFETY: `loader_ctx` is the fetched loader's own context; the object callback
                // and its argument are this frame's, and the passphrase callback and the context's
                // passphrase data are live and owned here.
                let loaded = unsafe {
                    if let Some(p_load) = (*(*ctx).fetched_loader).p_load {
                        p_load(
                            (*ctx).loader_ctx.cast::<c_void>(),
                            Some(ossl_store_handle_load_result),
                            ptr::addr_of_mut!(load_data).cast::<c_void>(),
                            Some(ossl_pw_passphrase_callback_dec),
                            ptr::addr_of_mut!((*ctx).pwdata).cast::<c_void>(),
                        )
                    } else {
                        0
                    }
                };
                if loaded == 0 {
                    // SAFETY: `ctx` is live per the contract.
                    unsafe { (*ctx).error_flag = 1 };
                    return ptr::null_mut();
                }
                v = load_data.v;
            }
            // SAFETY: `ctx` is live per the contract.
            if unsafe { (*ctx).fetched_loader }.is_null() {
                // SAFETY: `loader_ctx` is the legacy loader's own context; the UI method and its
                // data are the passphrase data's own union member.
                v = unsafe {
                    if let Some(load) = (*(*ctx).loader).load {
                        load(
                            (*ctx).loader_ctx,
                            (*ctx).pwdata.payload.ui_method.ui_method.cast::<c_void>(),
                            (*ctx).pwdata.payload.ui_method.ui_method_data,
                        )
                        .cast::<OsslStoreInfo>()
                    } else {
                        ptr::null_mut()
                    }
                };
            }
        }

        // SAFETY: `ctx` is live per the contract.
        if let Some(post_process) = unsafe { (*ctx).post_process } {
            if !v.is_null() {
                // SAFETY: `v` is a live object; the callback and its data are the caller's.
                v = unsafe { post_process(v, (*ctx).post_process_data) };

                /*
                 * By returning NULL, the callback decides that this object should
                 * be ignored.
                 */
                if v.is_null() {
                    continue 'again;
                }
            }
        }

        /* Clear any internally cached passphrase */
        // SAFETY: `ctx` is live per the contract.
        unsafe { ossl_pw_clear_passphrase_cache(&mut (*ctx).pwdata) };

        // SAFETY: `ctx` is live per the contract; `expected_type` is its own.
        if !v.is_null() && unsafe { (*ctx).expected_type } != 0 {
            // SAFETY: `v` is live per the guard above.
            let returned_type = unsafe { OSSL_STORE_INFO_get_type(v) };

            if returned_type != OSSL_STORE_INFO_NAME && returned_type != 0 {
                // SAFETY: `ctx` is live per the contract.
                if unsafe { (*ctx).expected_type } != returned_type {
                    // SAFETY: `v` is a live object this frame owns.
                    unsafe { OSSL_STORE_INFO_free(v) };
                    continue 'again;
                }
            }
        }

        return v;
    }
}

/// `int OSSL_STORE_delete(const char *uri, OSSL_LIB_CTX *libctx, const char *propq,
/// const UI_METHOD *ui_method, void *ui_data, const OSSL_PARAM params[])` —
/// `store_lib.c:492-540`.
///
/// # Safety
/// `uri`/`propq` NULL or NUL-terminated; `libctx` NULL or live; `ui_method` NULL or
/// live; `params` NULL or a terminated array.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // the authority's own six-parameter arity
pub unsafe extern "C" fn OSSL_STORE_delete(
    uri: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let mut scheme = [0 as c_char; 256];
    let mut res = 0;
    // SAFETY: an all-zero `ossl_passphrase_data_st` is its own initialiser.
    let mut pwdata: OsslPassphraseData = unsafe { core::mem::zeroed() };

    if uri.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_502) };
        return 0;
    }
    // SAFETY: `scheme` is a 256-byte buffer and `uri` is NUL-terminated.
    unsafe { OPENSSL_strlcpy(scheme.as_mut_ptr(), uri, scheme.len()) };

    // `strchr(scheme, ':')`; without an explicit scheme, this does not work.
    let mut colon: Option<usize> = None;
    {
        let mut i = 0usize;
        while i < scheme.len() {
            let ch = scheme[i];
            if ch == 0 {
                break;
            }
            if ch == b':' as c_char {
                colon = Some(i);
                break;
            }
            i += 1;
        }
    }
    match colon {
        Some(i) => scheme[i] = 0,
        None => return 0,
    }

    if !ui_method.is_null()
        // SAFETY: `pwdata` is live.
        && (unsafe { ossl_pw_set_ui_method(&mut pwdata, ui_method, ui_data) } == 0
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            || unsafe { ossl_pw_enable_passphrase_caching(&mut pwdata) } == 0)
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_514) };
        return 0;
    }

    // SAFETY: `libctx`, `scheme` and `propq` are per the contract.
    let fetched_loader = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme.as_ptr(), propq) };

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if !fetched_loader.is_null() && unsafe { (*fetched_loader).p_delete }.is_some() {
        // SAFETY: the provider is live for a fetched loader.
        let provider = unsafe { OSSL_STORE_LOADER_get0_provider(fetched_loader) };
        // SAFETY: `provider` is live.
        let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(provider) };
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(p_delete) = unsafe { (*fetched_loader).p_delete } {
            // SAFETY: the provider's own context and parameters.
            res = unsafe {
                p_delete(
                    provctx,
                    uri,
                    params,
                    Some(ossl_pw_passphrase_callback_dec),
                    (&mut pwdata as *mut OsslPassphraseData).cast::<c_void>(),
                )
            };
        }
    }

    /* Clear any internally cached passphrase */
    // SAFETY: `pwdata` is live.
    unsafe { ossl_pw_clear_passphrase_cache(&mut pwdata) };
    // SAFETY: `fetched_loader` is NULL or a loader this function holds.
    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };

    res
}

/// `int OSSL_STORE_error(OSSL_STORE_CTX *ctx)` — `store_lib.c:542-553`.
///
/// # Safety
/// `ctx` must be live; the legacy loader's `error` callback must tolerate the context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_error(ctx: *mut OsslStoreCtx) -> c_int {
    let mut ret = 1;

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if !unsafe { (*ctx).fetched_loader }.is_null() {
        // SAFETY: `ctx` is live.
        ret = unsafe { (*ctx).error_flag };
    }
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if unsafe { (*ctx).fetched_loader }.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(error) = unsafe { (*(*ctx).loader).error } {
            // SAFETY: `loader_ctx` is the legacy loader's own context.
            ret = unsafe { error((*ctx).loader_ctx) };
        }
    }
    ret
}

/// `int OSSL_STORE_eof(OSSL_STORE_CTX *ctx)` — `store_lib.c:555-575`.
///
/// # Safety
/// `ctx` must be live; the loader's `eof`/`p_eof` callback must tolerate the context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_eof(ctx: *mut OsslStoreCtx) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    let mut cached = unsafe { (*ctx).cached_info };
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if !cached.is_null() && unsafe { OPENSSL_sk_num(cached) } == 0 {
        // SAFETY: `cached` is the stack the context owns.
        unsafe { OPENSSL_sk_free(cached) };
        cached = ptr::null_mut();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).cached_info = ptr::null_mut() };
    }

    if cached.is_null() {
        ret = 1;
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if !unsafe { (*ctx).fetched_loader }.is_null() {
            // The authority spells this `ctx->loader->p_eof`, which is the fetched
            // loader here because `OSSL_STORE_open_ex` sets `loader = fetched_loader`.
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if let Some(p_eof) = unsafe { (*(*ctx).loader).p_eof } {
                // SAFETY: `loader_ctx` is the fetched loader's own context.
                ret = unsafe { p_eof((*ctx).loader_ctx.cast::<c_void>()) };
            }
        }
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if unsafe { (*ctx).fetched_loader }.is_null() {
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if let Some(eof) = unsafe { (*(*ctx).loader).eof } {
                // SAFETY: `loader_ctx` is the legacy loader's own context.
                ret = unsafe { eof((*ctx).loader_ctx) };
            }
        }
    }
    c_int::from(ret != 0)
}

/// `int OSSL_STORE_close(OSSL_STORE_CTX *ctx)` — `store_lib.c:599-605`.
///
/// # Safety
/// `ctx` must be NULL or a live, fully-owned `OsslStoreCtx`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_close(ctx: *mut OsslStoreCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract.
    let ret = unsafe { ossl_store_close_it(ctx) };

    // The block is this call's own (NULL is a no-op); `OwnedCtx`'s `Drop` is its single release.
    // `OSSL_STORE_CTX`'s destructor body is empty because `ossl_store_close_it` above is it, run
    // here to return its answer.
    // SAFETY: `ctx` is NULL or the context this call owns and has not released.
    unsafe { drop(OwnedCtx::<OsslStoreCtx>::from_raw(ctx)) };
    ret
}

/// `int OSSL_STORE_supports_search(OSSL_STORE_CTX *ctx, int search_type)` —
/// `store_lib.c:863-912`.
///
/// # Safety
/// `ctx` must be live; the loader's `find`/`p_settable_ctx_params` callbacks must
/// tolerate the arguments.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_supports_search(
    ctx: *mut OsslStoreCtx,
    search_type: c_int,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    let fetched = unsafe { (*ctx).fetched_loader };
    if !fetched.is_null() {
        // SAFETY: the provider is live for a fetched loader.
        let provider = unsafe { OSSL_STORE_LOADER_get0_provider(fetched) };
        // SAFETY: `provider` is live.
        let provctx = unsafe { ossl_provider_ctx(provider) };

        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if unsafe { (*fetched).p_settable_ctx_params }.is_none() {
            return 0;
        }
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        let params = if let Some(p_settable) = unsafe { (*fetched).p_settable_ctx_params } {
            // SAFETY: the provider's own context.
            unsafe { p_settable(provctx) }
        } else {
            ptr::null()
        };
        // SAFETY: `params` is the provider's settable table; each key is a literal.
        let p_subject =
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT.as_ptr()) };
        // SAFETY: as above.
        let p_issuer = unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ISSUER.as_ptr()) };
        // SAFETY: as above.
        let p_serial = unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SERIAL.as_ptr()) };
        // SAFETY: as above.
        let p_fingerprint =
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_FINGERPRINT.as_ptr()) };
        // SAFETY: as above.
        let p_alias = unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ALIAS.as_ptr()) };

        match search_type {
            OSSL_STORE_SEARCH_BY_NAME => ret = c_int::from(!p_subject.is_null()),
            OSSL_STORE_SEARCH_BY_ISSUER_SERIAL => {
                ret = c_int::from(!p_issuer.is_null() && !p_serial.is_null())
            }
            OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT => ret = c_int::from(!p_fingerprint.is_null()),
            OSSL_STORE_SEARCH_BY_ALIAS => ret = c_int::from(!p_alias.is_null()),
            _ => {}
        }
    }
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    if unsafe { (*ctx).fetched_loader }.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if unsafe { (*(*ctx).loader).find }.is_none() {
            return 0;
        }
        // SAFETY: an all-zero search is what the authority passes as a criteria stub.
        let mut tmp_search: OsslStoreSearch = unsafe { core::mem::zeroed() };
        tmp_search.search_type = search_type;
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(find) = unsafe { (*(*ctx).loader).find } {
            // SAFETY: the legacy loader's own `find` contract.
            ret = unsafe {
                find(
                    ptr::null_mut(),
                    (&tmp_search as *const OsslStoreSearch).cast::<c_void>(),
                )
            };
        }
    }
    ret
}

/// `OSSL_STORE_CTX *OSSL_STORE_attach(BIO *bp, const char *scheme,
/// OSSL_LIB_CTX *libctx, const char *propq, const UI_METHOD *ui_method, void *ui_data,
/// const OSSL_PARAM params[], OSSL_STORE_post_process_info_fn post_process,
/// void *post_process_data)` — `store_lib.c:1028-1102`.
///
/// # Safety
/// `bp` NULL or live; `scheme`/`propq` NULL or NUL-terminated; `libctx` NULL or
/// live; `ui_method` NULL or live; `params` NULL or terminated; `post_process` NULL
/// or valid.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // the authority's own nine-parameter arity
pub unsafe extern "C" fn OSSL_STORE_attach(
    bp: *mut Bio,
    scheme: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
    params: *const OsslParam,
    post_process: Option<OsslStorePostProcessInfoFn>,
    post_process_data: *mut c_void,
) -> *mut OsslStoreCtx {
    let mut fetched_loader: *mut OsslStoreLoader = ptr::null_mut();
    let mut loader_ctx: *mut OsslStoreLoaderCtx = ptr::null_mut();
    let mut scheme = scheme;

    if scheme.is_null() {
        scheme = c"file".as_ptr();
    }

    // SAFETY: a mark on the error queue.
    ERR_set_mark();
    // SAFETY: `scheme` is NUL-terminated.
    let mut loader = unsafe { ossl_store_get0_loader_int(scheme) };
    if !loader.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(attach) = unsafe { (*loader).attach } {
            // SAFETY: `loader`, `bp`, `ui_method` and `ui_data` are per the contract.
            loader_ctx = unsafe {
                attach(
                    loader,
                    bp.cast::<c_void>(),
                    libctx,
                    propq,
                    ui_method.cast::<c_void>(),
                    ui_data,
                )
            };
        }
    }

    if loader.is_null() {
        // SAFETY: `libctx`, `scheme` and `propq` are per the contract.
        fetched_loader = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme, propq) };
        if !fetched_loader.is_null() {
            // SAFETY: the provider is live for a fetched loader.
            let provider = unsafe { OSSL_STORE_LOADER_get0_provider(fetched_loader) };
            // SAFETY: `provider` is live.
            let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(provider) };
            // SAFETY: `bp` is live per the contract.
            let raw_cbio = unsafe { ossl_core_bio_new_from_bio(bp) };
            // SAFETY: a NULL or live core BIO is the opaque handle the provider takes.
            let cbio = raw_cbio.cast::<c_void>();

            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            if raw_cbio.is_null() || unsafe { (*fetched_loader).p_attach }.is_none() {
                // SAFETY: `fetched_loader` is live and not kept.
                unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                fetched_loader = ptr::null_mut();
            } else {
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                let attached = if let Some(p_attach) = unsafe { (*fetched_loader).p_attach } {
                    // SAFETY: the provider's own context and core BIO.
                    unsafe { p_attach(provctx, cbio) }
                } else {
                    ptr::null_mut()
                };
                if attached.is_null() {
                    // SAFETY: `fetched_loader` is live and not kept.
                    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                    fetched_loader = ptr::null_mut();
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                } else if unsafe { loader_set_params(fetched_loader, attached, params, propq) } == 0
                {
                    // A refused params set closes the context and refuses the attach: publishing a
                    // store whose loader is NULL would make `OSSL_STORE_close`/`OSSL_STORE_load`
                    // dereference that NULL loader (B27-X2). `loader_ctx` is assigned only on the
                    // accepted-params path below, so this refusal leaves it NULL and the guard at
                    // the end of this function returns NULL. The authority publishes the closed
                    // context with `loader = NULL` (store_lib.c:1093-1098); that UB is not
                    // reproduced (§17).
                    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                    if let Some(p_close) = unsafe { (*fetched_loader).p_close } {
                        // SAFETY: `attached` is the provider's own context and this is its close.
                        unsafe { p_close(attached) };
                    }
                    // SAFETY: `fetched_loader` is live and not kept.
                    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                    fetched_loader = ptr::null_mut();
                } else {
                    loader_ctx = attached.cast::<OsslStoreLoaderCtx>();
                }
            }
            loader = fetched_loader;
            // SAFETY: `cbio` is NULL or the core BIO just created.
            unsafe { ossl_core_bio_free(raw_cbio) };
        }
    }

    if loader_ctx.is_null() {
        // SAFETY: the mark was set above.
        ERR_clear_last_mark();
        return ptr::null_mut();
    }

    // The context block, allocated through the crate's allocator seam; `Drop` is its single
    // release on the refusal below and `into_raw` hands it out on success.
    let Some(ctx) = OwnedCtx::<OsslStoreCtx>::zalloc() else {
        // SAFETY: the mark was set above.
        ERR_clear_last_mark();
        return ptr::null_mut();
    };

    if !ui_method.is_null()
        // SAFETY: `ctx` is a fresh zeroed allocation; `pwdata` is live.
        && unsafe { ossl_pw_set_ui_method(&mut (*ctx.as_ptr()).pwdata, ui_method, ui_data) } == 0
    {
        // SAFETY: the mark was set above.
        ERR_clear_last_mark();
        // `ctx` is released by its `Drop` as this frame returns.
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live and every pointer stored is live.
    unsafe {
        (*ctx.as_ptr()).fetched_loader = fetched_loader;
        (*ctx.as_ptr()).loader = loader;
        (*ctx.as_ptr()).loader_ctx = loader_ctx;
        (*ctx.as_ptr()).post_process = post_process;
        (*ctx.as_ptr()).post_process_data = post_process_data;
    }

    /*
     * ossl_store_get0_loader_int will raise an error if the loader for the scheme
     * cannot be retrieved. But if a loader was successfully fetched then we remove
     * this error from the error stack.
     */
    // SAFETY: the mark was set above.
    ERR_pop_to_mark();

    ctx.into_raw()
}

// ---------------------------------------------------------------------------
// `OSSL_STORE_vctrl` / `OSSL_STORE_ctrl`
//
// `OSSL_STORE_vctrl` itself is **not** here: a `va_list` can cross into Rust only as
// an opaque pointer, and the authority's `OSSL_STORE_ctrl` is C-variadic, which
// stable Rust cannot define. Both public entry points are therefore the argument
// marshalling in `src/store/store_lib_variadic.c`, and every decision lives in
// `openssl_rs_store_vctrl` below. The `OSSL_STORE_C_USE_SECMEM` arm is the only one
// that reads an argument (`va_arg(args, int *)`), and it does so only in the fetched
// branch, which is why the read is here rather than in the C shim.
// ---------------------------------------------------------------------------

/// The Rust half of `OSSL_STORE_vctrl`, called by `src/store/store_lib_variadic.c`.
///
/// # Safety
/// `ctx` must be NULL or live; `args` must be the live `va_list` of the caller's
/// variadic function (`OSSL_STORE_ctrl`) or of `OSSL_STORE_vctrl`.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_store_vctrl(
    ctx: *mut OsslStoreCtx,
    cmd: c_int,
    args: *mut c_void,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
    let fetched = unsafe { (*ctx).fetched_loader };
    if !fetched.is_null() {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(set_ctx_params) = unsafe { (*fetched).p_set_ctx_params } {
            let mut params = [OSSL_PARAM_construct_end(); 2];

            // SAFETY: the authority's `switch` has this one case and a `default` that
            // leaves `params[0]` as the terminator.
            if cmd == OSSL_STORE_C_USE_SECMEM {
                // SAFETY: the caller supplied one `int *` for this command.
                let on = unsafe { openssl_rs_va_gp(args) } as *mut c_int;
                // SAFETY: `on` is the caller's `int *`.
                params[0] =
                    unsafe { OSSL_PARAM_construct_int(OSSL_STORE_PARAM_USE_SECMEM.as_ptr(), on) };
            }

            // SAFETY: `loader_ctx` is the fetched loader's own context.
            return unsafe { set_ctx_params((*ctx).loader_ctx.cast::<c_void>(), params.as_ptr()) };
        }
    } else {
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        let loader = unsafe { (*ctx).loader };
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        if let Some(ctrl) = unsafe { (*loader).ctrl } {
            // SAFETY: the legacy loader's own `ctrl` contract; the `va_list` is
            // forwarded exactly as the authority forwards it.
            // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
            return unsafe { ctrl((*ctx).loader_ctx, cmd, args) };
        }
    }

    /*
     * If the fetched loader doesn't have a set_ctx_params or a ctrl, it's as if there
     * was one that ignored our params, which usually returns 1.
     */
    1
}

// ---------------------------------------------------------------------------
// The `OSSL_STORE_INFO` constructors
// ---------------------------------------------------------------------------

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new(int type, void *data)` — `store_lib.c:614-624`.
///
/// # Safety
///
/// `data` is stored as-is. On success its ownership transfers to the returned object;
/// on a refused allocation no object exists and the caller retains it (the authority's
/// own `:619-621` failure arm leaks it, and that behaviour is preserved).
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new(
    type_: c_int,
    data: *mut c_void,
) -> *mut OsslStoreInfo {
    // The object block, allocated through the crate's allocator seam; `into_raw` hands it out.
    let Some(info) = OwnedCtx::<OsslStoreInfo>::zalloc() else {
        return ptr::null_mut();
    };

    // SAFETY: `info` is a fresh zeroed allocation.
    unsafe {
        (*info.as_ptr()).type_ = type_;
        (*info.as_ptr()).data.data = data;
    }
    info.into_raw()
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_NAME(char *name)` — `store_lib.c:626-639`.
///
/// # Safety
///
/// `name` is NULL or an allocation whose ownership transfers to the returned object.
/// On a refused allocation no object exists and the caller retains `name`; the
/// authority's `:631-633` arm returns without releasing it, which is preserved.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_NAME(name: *mut c_char) -> *mut OsslStoreInfo {
    // SAFETY: `OSSL_STORE_INFO_new` stores a NULL union member.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_NAME, ptr::null_mut()) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_631) };
        return ptr::null_mut();
    }

    // SAFETY: `info` is live and of type NAME, so the `name` member is the live one.
    unsafe {
        (*info).data.name = OsslStoreInfoName {
            name,
            desc: ptr::null_mut(),
        };
    }
    info
}

/// `int OSSL_STORE_INFO_set0_NAME_description(OSSL_STORE_INFO *info, char *desc)` —
/// `store_lib.c:641-651`.
///
/// # Safety
/// `info` must be live; `desc` NULL or an allocation whose ownership transfers.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_set0_NAME_description(
    info: *mut OsslStoreInfo,
    desc: *mut c_char,
) -> c_int {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } != OSSL_STORE_INFO_NAME {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_644) };
        return 0;
    }

    // SAFETY: `info` is of type NAME, so the `name` member is live.
    unsafe { (*info).data.name.desc = desc };

    1
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_PARAMS(EVP_PKEY *params)` —
/// `store_lib.c:652-659`.
///
/// # Safety
/// `params` is NULL or an object whose ownership transfers to the returned info.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_PARAMS(params: *mut EvpPkey) -> *mut OsslStoreInfo {
    // SAFETY: the generic constructor stores the pointer as-is.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_PARAMS, params.cast::<c_void>()) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_657) };
    }
    info
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_PUBKEY(EVP_PKEY *pkey)` —
/// `store_lib.c:661-668`.
///
/// # Safety
/// `pkey` is NULL or an object whose ownership transfers to the returned info.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_PUBKEY(pkey: *mut EvpPkey) -> *mut OsslStoreInfo {
    // SAFETY: the generic constructor stores the pointer as-is.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_PUBKEY, pkey.cast::<c_void>()) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_666) };
    }
    info
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_PKEY(EVP_PKEY *pkey)` —
/// `store_lib.c:670-677`.
///
/// # Safety
/// `pkey` is NULL or an object whose ownership transfers to the returned info.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_PKEY(pkey: *mut EvpPkey) -> *mut OsslStoreInfo {
    // SAFETY: the generic constructor stores the pointer as-is.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_PKEY, pkey.cast::<c_void>()) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_675) };
    }
    info
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_CERT(X509 *x509)` — `store_lib.c:679-686`.
///
/// # Safety
/// `x509` is NULL or an object whose ownership transfers to the returned info.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_CERT(x509: *mut c_void) -> *mut OsslStoreInfo {
    // SAFETY: the generic constructor stores the pointer as-is.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_CERT, x509) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_684) };
    }
    info
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_CRL(X509_CRL *crl)` — `store_lib.c:688-695`.
///
/// # Safety
/// `crl` is NULL or an object whose ownership transfers to the returned info.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new_CRL(crl: *mut c_void) -> *mut OsslStoreInfo {
    // SAFETY: the generic constructor stores the pointer as-is.
    let info = unsafe { OSSL_STORE_INFO_new(OSSL_STORE_INFO_CRL, crl) };

    if info.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_LIB_693) };
    }
    info
}

// ---------------------------------------------------------------------------
// The `OSSL_STORE_INFO` accessors
// ---------------------------------------------------------------------------

/// `int OSSL_STORE_INFO_get_type(const OSSL_STORE_INFO *info)` — `store_lib.c:700-703`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get_type(info: *const OsslStoreInfo) -> c_int {
    // SAFETY: `info` is live per the contract.
    unsafe { (*info).type_ }
}

/// `void *OSSL_STORE_INFO_get0_data(int type, const OSSL_STORE_INFO *info)` —
/// `store_lib.c:705-710`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_data(
    type_: c_int,
    info: *const OsslStoreInfo,
) -> *mut c_void {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == type_ {
        // SAFETY: the generic `data` member aliases every arm.
        return unsafe { (*info).data.data };
    }
    ptr::null_mut()
}

/// `const char *OSSL_STORE_INFO_get0_NAME(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:712-717`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_NAME(info: *const OsslStoreInfo) -> *const c_char {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_NAME {
        // SAFETY: the type is NAME, so the `name` member is live.
        return unsafe { (*info).data.name.name };
    }
    ptr::null()
}

/// `char *OSSL_STORE_INFO_get1_NAME(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:719-725`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_NAME(info: *const OsslStoreInfo) -> *mut c_char {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_NAME {
        // SAFETY: the type is NAME, so `name` is live and NUL-terminated.
        return unsafe { CRYPTO_strdup((*info).data.name.name, ptr::null(), 0) };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_723) };
    ptr::null_mut()
}

/// `const char *OSSL_STORE_INFO_get0_NAME_description(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:727-732`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_NAME_description(
    info: *const OsslStoreInfo,
) -> *const c_char {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_NAME {
        // SAFETY: the type is NAME, so the `name` member is live.
        return unsafe { (*info).data.name.desc };
    }
    ptr::null()
}

/// `char *OSSL_STORE_INFO_get1_NAME_description(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:734-740`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_NAME_description(
    info: *const OsslStoreInfo,
) -> *mut c_char {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_NAME {
        // SAFETY: the type is NAME, so `desc` is live; a NULL desc is the empty string.
        let desc = unsafe { (*info).data.name.desc };
        let src = if desc.is_null() { c"".as_ptr() } else { desc };
        // SAFETY: `src` is NUL-terminated.
        return unsafe { CRYPTO_strdup(src, ptr::null(), 0) };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_738) };
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get0_PARAMS(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:742-747`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PARAMS(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PARAMS {
        // SAFETY: the type is PARAMS, so the `params` member is live.
        return unsafe { (*info).data.params };
    }
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get1_PARAMS(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:749-758`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PARAMS(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PARAMS {
        // SAFETY: the type is PARAMS, so `params` is live; `up_ref` handles its refcount.
        if unsafe { EVP_PKEY_up_ref((*info).data.params) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the type is PARAMS, so the `params` member is live.
        return unsafe { (*info).data.params };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_756) };
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get0_PUBKEY(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:760-765`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PUBKEY(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PUBKEY {
        // SAFETY: the type is PUBKEY, so the `pubkey` member is live.
        return unsafe { (*info).data.pubkey };
    }
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get1_PUBKEY(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:767-776`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PUBKEY(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PUBKEY {
        // SAFETY: the type is PUBKEY, so `pubkey` is live.
        if unsafe { EVP_PKEY_up_ref((*info).data.pubkey) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the type is PUBKEY, so the `pubkey` member is live.
        return unsafe { (*info).data.pubkey };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_774) };
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get0_PKEY(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:778-783`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_PKEY(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PKEY {
        // SAFETY: the type is PKEY, so the `pkey` member is live.
        return unsafe { (*info).data.pkey };
    }
    ptr::null_mut()
}

/// `EVP_PKEY *OSSL_STORE_INFO_get1_PKEY(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:785-794`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_PKEY(info: *const OsslStoreInfo) -> *mut EvpPkey {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_PKEY {
        // SAFETY: the type is PKEY, so `pkey` is live.
        if unsafe { EVP_PKEY_up_ref((*info).data.pkey) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the type is PKEY, so the `pkey` member is live.
        return unsafe { (*info).data.pkey };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_792) };
    ptr::null_mut()
}

/// `X509 *OSSL_STORE_INFO_get0_CERT(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:796-801`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_CERT(info: *const OsslStoreInfo) -> *mut c_void {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_CERT {
        // SAFETY: the type is CERT, so the `x509` member is live (opaque here).
        return unsafe { (*info).data.x509 };
    }
    ptr::null_mut()
}

/// `X509_CRL *OSSL_STORE_INFO_get0_CRL(const OSSL_STORE_INFO *info)` —
/// `store_lib.c:814-819`.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get0_CRL(info: *const OsslStoreInfo) -> *mut c_void {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_CRL {
        // SAFETY: the type is CRL, so the `crl` member is live (opaque here).
        return unsafe { (*info).data.crl };
    }
    ptr::null_mut()
}

/// `X509 *OSSL_STORE_INFO_get1_CERT(const OSSL_STORE_INFO *info)` — `store_lib.c:803-812`.
///
/// Closed by 10.8: `X509_up_ref` is now landed.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_CERT(info: *const OsslStoreInfo) -> *mut X509 {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_CERT {
        // SAFETY: the type is CERT, so `x509` is live as an `X509`.
        let x = unsafe { (*info).data.x509.cast::<X509>() };
        // SAFETY: `x` is the object the CERT arm holds.
        if unsafe { X509_up_ref(x) } == 0 {
            return ptr::null_mut();
        }
        return x;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_810) };
    ptr::null_mut()
}

/// `X509_CRL *OSSL_STORE_INFO_get1_CRL(const OSSL_STORE_INFO *info)` — `store_lib.c:821-830`.
///
/// Closed by 10.8: `X509_CRL_up_ref` is now landed.
///
/// # Safety
/// `info` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_get1_CRL(info: *const OsslStoreInfo) -> *mut X509Crl {
    // SAFETY: `info` is live per the contract.
    if unsafe { (*info).type_ } == OSSL_STORE_INFO_CRL {
        // SAFETY: the type is CRL, so `crl` is live as an `X509_CRL`.
        let crl = unsafe { (*info).data.crl.cast::<X509Crl>() };
        // SAFETY: `crl` is the object the CRL arm holds.
        if unsafe { X509_CRL_up_ref(crl) } == 0 {
            return ptr::null_mut();
        }
        return crl;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&STORE_LIB_828) };
    ptr::null_mut()
}

/// `void OSSL_STORE_INFO_free(OSSL_STORE_INFO *info)` — `store_lib.c:835-861`.
///
/// Every arm is transcribed, including the `CERT` and `CRL` arms 10.8 closed with
/// `X509_free`/`X509_CRL_free`, and the object itself is always released.
///
/// # Safety
/// `info` must be NULL or a live object not already freed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_free(info: *mut OsslStoreInfo) {
    // SAFETY: `info` is NULL or a live object not already freed; `from_raw` reclaims it (NULL is
    // a no-op) and `Drop` runs the authority's own union-member releases and the block release.
    unsafe { drop(OwnedCtx::<OsslStoreInfo>::from_raw(info)) };
}

// ---------------------------------------------------------------------------
// The `OSSL_STORE_SEARCH` object
// ---------------------------------------------------------------------------

/// `OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_name(X509_NAME *name)` —
/// `store_lib.c:915-925`.
///
/// # Safety
/// `name` is borrowed; the caller must keep it alive for the search's lifetime.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_name(name: *mut c_void) -> *mut OsslStoreSearch {
    // The object block, allocated through the crate's allocator seam; `into_raw` hands it out.
    let Some(search) = OwnedCtx::<OsslStoreSearch>::zalloc() else {
        return ptr::null_mut();
    };

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search.as_ptr()).search_type = OSSL_STORE_SEARCH_BY_NAME;
        (*search.as_ptr()).name = name;
    }
    search.into_raw()
}

/// `OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_issuer_serial(X509_NAME *name,
/// const ASN1_INTEGER *serial)` — `store_lib.c:927-939`.
///
/// # Safety
/// `name`/`serial` are borrowed; the caller must keep them alive.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_issuer_serial(
    name: *mut c_void,
    serial: *const c_void,
) -> *mut OsslStoreSearch {
    // The object block, allocated through the crate's allocator seam; `into_raw` hands it out.
    let Some(search) = OwnedCtx::<OsslStoreSearch>::zalloc() else {
        return ptr::null_mut();
    };

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search.as_ptr()).search_type = OSSL_STORE_SEARCH_BY_ISSUER_SERIAL;
        (*search.as_ptr()).name = name;
        (*search.as_ptr()).serial = serial;
    }
    search.into_raw()
}

/// `OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_key_fingerprint(const EVP_MD *digest,
/// const unsigned char *bytes, size_t len)` — `store_lib.c:941-972`.
///
/// # Safety
/// `digest` is borrowed; `bytes` is borrowed for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_key_fingerprint(
    digest: *const EvpMd,
    bytes: *const c_uchar,
    len: usize,
) -> *mut OsslStoreSearch {
    // The object block, allocated through the crate's allocator seam; `Drop` releases it on the
    // two refusals below and `into_raw` hands it out on success.
    let Some(search) = OwnedCtx::<OsslStoreSearch>::zalloc() else {
        return ptr::null_mut();
    };

    // SAFETY: `digest` is NULL or live; a NULL is the authority's own refusal.
    let md_size = unsafe { EVP_MD_get_size(digest) };
    if md_size <= 0 {
        // `search` is released by its `Drop` as this frame returns.
        return ptr::null_mut();
    }

    if !digest.is_null() && len != md_size as usize {
        let mut msg = [0 as c_char; 512];
        // SAFETY: `msg` is writable for its own length; the format arguments are as
        // the authority's own `ERR_raise_data` supplies them.
        // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s size is %d, fingerprint size is %zu".as_ptr(),
                EVP_MD_get0_name(digest),
                md_size,
                len,
            );
        }
        // SAFETY: `msg` is a NUL-terminated stack buffer.
        unsafe { raise_site_data(&STORE_LIB_959, msg.as_ptr()) };
        // `search` is released by its `Drop` as this frame returns.
        return ptr::null_mut();
    }

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search.as_ptr()).search_type = OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT;
        (*search.as_ptr()).digest = digest;
        (*search.as_ptr()).string = bytes;
        (*search.as_ptr()).stringlength = len;
    }
    search.into_raw()
}

/// `OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_alias(const char *alias)` —
/// `store_lib.c:974-985`.
///
/// # Safety
/// `alias` must be NUL-terminated and outlive the search.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_alias(alias: *const c_char) -> *mut OsslStoreSearch {
    // The object block, allocated through the crate's allocator seam; `into_raw` hands it out.
    let Some(search) = OwnedCtx::<OsslStoreSearch>::zalloc() else {
        return ptr::null_mut();
    };

    // SAFETY: `alias` is NUL-terminated per the contract.
    let len = unsafe { c_strlen(alias) };
    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search.as_ptr()).search_type = OSSL_STORE_SEARCH_BY_ALIAS;
        (*search.as_ptr()).string = alias.cast::<c_uchar>();
        (*search.as_ptr()).stringlength = len;
    }
    search.into_raw()
}

/// `void OSSL_STORE_SEARCH_free(OSSL_STORE_SEARCH *search)` — `store_lib.c:988-991`.
///
/// # Safety
/// `search` must be NULL or an object from one of the constructors, not already freed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_free(search: *mut OsslStoreSearch) {
    // SAFETY: `search` is NULL or the allocation a constructor made; it is reclaimed (NULL is a
    // no-op) and its `Drop` runs the bare block release `OSSL_STORE_SEARCH_free` performed.
    unsafe { drop(OwnedCtx::<OsslStoreSearch>::from_raw(search)) };
}

/// `int OSSL_STORE_SEARCH_get_type(const OSSL_STORE_SEARCH *criterion)` —
/// `store_lib.c:994-997`.
///
/// # Safety
/// `criterion` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get_type(criterion: *const OsslStoreSearch) -> c_int {
    // SAFETY: `criterion` is live per the contract.
    unsafe { (*criterion).search_type }
}

/// `X509_NAME *OSSL_STORE_SEARCH_get0_name(const OSSL_STORE_SEARCH *criterion)` —
/// `store_lib.c:999-1002`.
///
/// # Safety
/// `criterion` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_name(
    criterion: *const OsslStoreSearch,
) -> *mut c_void {
    // SAFETY: `criterion` is live per the contract.
    unsafe { (*criterion).name }
}

/// `const ASN1_INTEGER *OSSL_STORE_SEARCH_get0_serial(const OSSL_STORE_SEARCH
/// *criterion)` — `store_lib.c:1004-1008`.
///
/// # Safety
/// `criterion` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_serial(
    criterion: *const OsslStoreSearch,
) -> *const c_void {
    // SAFETY: `criterion` is live per the contract.
    unsafe { (*criterion).serial }
}

/// `const unsigned char *OSSL_STORE_SEARCH_get0_bytes(const OSSL_STORE_SEARCH
/// *criterion, size_t *length)` — `store_lib.c:1010-1016`.
///
/// # Safety
/// `criterion` and `length` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_bytes(
    criterion: *const OsslStoreSearch,
    length: *mut usize,
) -> *const c_uchar {
    // SAFETY: `length` is writable and `criterion` is live per the contract.
    unsafe {
        *length = (*criterion).stringlength;
        (*criterion).string
    }
}

/// `const char *OSSL_STORE_SEARCH_get0_string(const OSSL_STORE_SEARCH *criterion)` —
/// `store_lib.c:1018-1021`.
///
/// # Safety
/// `criterion` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_string(
    criterion: *const OsslStoreSearch,
) -> *const c_char {
    // SAFETY: `criterion` is live per the contract.
    unsafe { (*criterion).string.cast::<c_char>() }
}

/// `const EVP_MD *OSSL_STORE_SEARCH_get0_digest(const OSSL_STORE_SEARCH *criterion)` —
/// `store_lib.c:1023-1026`.
///
/// # Safety
/// `criterion` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_get0_digest(
    criterion: *const OsslStoreSearch,
) -> *const EvpMd {
    // SAFETY: `criterion` is live per the contract.
    unsafe { (*criterion).digest }
}

#[cfg(test)]
// Test-side `unsafe` blocks are direct calls to the API under test, with pointers to
// values this test owns and whose validity it just established. The invariant is
// identical in every case, so it is stated once here rather than repeated at each
// call site. Product code keeps the crate-wide denial.
#[allow(clippy::undocumented_unsafe_blocks)]
mod tests {
    use super::*;
    use crate::test_support::lock_global_state;

    /// The `OSSL_STORE_INFO` NAME arm round-trips through its constructors and
    /// accessors, and the accessors of the other types refuse it.
    ///
    /// `lock_global_state` because the object model allocates through the crate's
    /// memory functions and the refusal arms touch the process-global error queue
    /// (`docs/CONCURRENCY_MODEL.md` section 7).
    #[test]
    fn info_name_round_trips_and_other_accessors_refuse() {
        let _guard = lock_global_state();
        crate::runtime::err::ERR_clear_error();

        // SAFETY: every pointer below is a live allocation from the crate's allocator.
        unsafe {
            let name = CRYPTO_strdup(c"a-name".as_ptr(), ptr::null(), 0);
            let info = OSSL_STORE_INFO_new_NAME(name);
            assert!(!info.is_null());
            assert_eq!(OSSL_STORE_INFO_get_type(info), OSSL_STORE_INFO_NAME);
            assert_eq!(
                core::ffi::CStr::from_ptr(OSSL_STORE_INFO_get0_NAME(info)).to_bytes(),
                b"a-name"
            );
            assert!(OSSL_STORE_INFO_get0_data(OSSL_STORE_INFO_NAME, info) == name.cast());
            assert!(OSSL_STORE_INFO_get0_NAME_description(info).is_null());

            let desc = CRYPTO_strdup(c"a description".as_ptr(), ptr::null(), 0);
            assert_eq!(OSSL_STORE_INFO_set0_NAME_description(info, desc), 1);
            assert_eq!(
                core::ffi::CStr::from_ptr(OSSL_STORE_INFO_get0_NAME_description(info)).to_bytes(),
                b"a description"
            );

            // The `get1` form answers a fresh copy, not the borrowed pointer.
            let copy = OSSL_STORE_INFO_get1_NAME(info);
            assert!(!copy.is_null() && copy != name);
            CRYPTO_free(copy.cast::<c_void>(), ptr::null(), 0);

            // Every other typed accessor refuses a NAME and raises.
            assert!(OSSL_STORE_INFO_get0_PARAMS(info).is_null());
            assert!(OSSL_STORE_INFO_get1_PARAMS(info).is_null());
            assert_eq!(
                crate::runtime::err::peek_first_reason() as c_int,
                OSSL_STORE_R_NOT_PARAMETERS
            );

            OSSL_STORE_INFO_free(info);
        }
        crate::runtime::err::ERR_clear_error();
    }

    /// The generic constructor and the CERT/CRL arms take an opaque pointer, so a
    /// NULL object can be driven end to end.
    #[test]
    fn info_cert_and_crl_arms_hold_opaque_pointers() {
        let _guard = lock_global_state();
        crate::runtime::err::ERR_clear_error();

        // SAFETY: every pointer below is a live allocation from the crate's allocator.
        unsafe {
            let cert = OSSL_STORE_INFO_new_CERT(ptr::null_mut());
            assert!(!cert.is_null());
            assert_eq!(OSSL_STORE_INFO_get_type(cert), OSSL_STORE_INFO_CERT);
            assert!(OSSL_STORE_INFO_get0_CERT(cert).is_null());
            assert!(OSSL_STORE_INFO_get0_CRL(cert).is_null());
            OSSL_STORE_INFO_free(cert);

            let crl = OSSL_STORE_INFO_new_CRL(ptr::null_mut());
            assert_eq!(OSSL_STORE_INFO_get_type(crl), OSSL_STORE_INFO_CRL);
            OSSL_STORE_INFO_free(crl);

            // A NULL is a no-op, as in the authority.
            OSSL_STORE_INFO_free(ptr::null_mut());
        }
        crate::runtime::err::ERR_clear_error();
    }

    /// The `OSSL_STORE_SEARCH` constructors store their borrowed inputs and the
    /// accessors report them back; the fingerprint length is checked.
    #[test]
    fn search_object_stores_and_reports_its_criterion() {
        let _guard = lock_global_state();
        crate::runtime::err::ERR_clear_error();

        // SAFETY: every pointer below is a live allocation from the crate's allocator,
        // except the borrowed digest, which is a static method object.
        unsafe {
            let alias = OSSL_STORE_SEARCH_by_alias(c"an-alias".as_ptr());
            assert!(!alias.is_null());
            assert_eq!(
                OSSL_STORE_SEARCH_get_type(alias),
                OSSL_STORE_SEARCH_BY_ALIAS
            );
            assert_eq!(
                core::ffi::CStr::from_ptr(OSSL_STORE_SEARCH_get0_string(alias)).to_bytes(),
                b"an-alias"
            );
            let mut len = 0usize;
            let bytes = OSSL_STORE_SEARCH_get0_bytes(alias, &mut len);
            assert_eq!(len, 8);
            assert!(!bytes.is_null());
            assert!(OSSL_STORE_SEARCH_get0_name(alias).is_null());
            assert!(OSSL_STORE_SEARCH_get0_digest(alias).is_null());
            OSSL_STORE_SEARCH_free(alias);

            let name = OSSL_STORE_SEARCH_by_name(ptr::null_mut());
            assert_eq!(OSSL_STORE_SEARCH_get_type(name), OSSL_STORE_SEARCH_BY_NAME);
            assert!(OSSL_STORE_SEARCH_get0_name(name).is_null());
            OSSL_STORE_SEARCH_free(name);

            let issuer = OSSL_STORE_SEARCH_by_issuer_serial(ptr::null_mut(), ptr::null());
            assert_eq!(
                OSSL_STORE_SEARCH_get_type(issuer),
                OSSL_STORE_SEARCH_BY_ISSUER_SERIAL
            );
            assert!(OSSL_STORE_SEARCH_get0_serial(issuer).is_null());
            OSSL_STORE_SEARCH_free(issuer);

            // SHA-256 is 32 bytes; a 3-byte fingerprint is the length refusal.
            let md = crate::evp::legacy_sha::EVP_sha256();
            let fp = b"abc";
            let bad = OSSL_STORE_SEARCH_by_key_fingerprint(md, fp.as_ptr(), fp.len());
            assert!(bad.is_null());
            assert_eq!(
                crate::runtime::err::peek_first_reason() as c_int,
                OSSL_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST
            );
            crate::runtime::err::ERR_clear_error();

            let good = OSSL_STORE_SEARCH_by_key_fingerprint(md, fp.as_ptr(), 32);
            assert!(!good.is_null());
            assert_eq!(
                OSSL_STORE_SEARCH_get_type(good),
                OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT
            );
            assert_eq!(OSSL_STORE_SEARCH_get0_digest(good), md);
            OSSL_STORE_SEARCH_free(good);
        }
        crate::runtime::err::ERR_clear_error();
    }

    /// `OSSL_STORE_expect`'s NULL-context and range refusals are the authority's own.
    #[test]
    fn expect_refuses_a_null_context_and_a_bad_type() {
        let _guard = lock_global_state();
        crate::runtime::err::ERR_clear_error();

        // SAFETY: a NULL context is exactly the refusal arm.
        unsafe {
            assert_eq!(OSSL_STORE_expect(ptr::null_mut(), 0), 0);
            assert_eq!(
                crate::runtime::err::peek_first_reason() as c_int,
                ERR_R_PASSED_INVALID_ARGUMENT
            );
            assert_eq!(
                OSSL_STORE_expect(ptr::null_mut(), OSSL_STORE_INFO_CRL + 1),
                0
            );
            crate::runtime::err::ERR_clear_error();
        }
    }
}

// ---------------------------------------------------------------------------
// OOM-refusal probe (`scripts/adv-probe.sh`, §16 negative control)
// ---------------------------------------------------------------------------
// The allocator hook is process-global, so the probes are `#[ignore]`d and run one process per
// probe. This one drives the `OSSL_STORE_open_ex` refusal window that B26-X1 names: the provider's
// loader has opened successfully, then the `OSSL_STORE_CTX` block allocation is refused.
#[cfg(test)]
mod adv_probe {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::ssl::adv_alloc;

    /// Load the two providers whose published `OSSL_OP_STORE` rows resolve the `file` loader.
    ///
    /// # Safety
    /// The caller serialises with the rest of the process-global provider-state tests.
    unsafe fn load_providers() {
        // SAFETY: both names are static NUL-terminated literals, and the caller holds the global
        // state lock that the provider store requires.
        unsafe {
            assert!(
                !crate::provider::OSSL_PROVIDER_load(ptr::null_mut(), c"default".as_ptr())
                    .is_null(),
                "the default provider loads"
            );
            assert!(
                !crate::provider::OSSL_PROVIDER_load(ptr::null_mut(), c"base".as_ptr()).is_null(),
                "the base provider loads"
            );
        }
    }

    /// A real file the published `file` loader can open, and its `file:` URI.
    fn temporary_store_file() -> (std::path::PathBuf, std::ffi::CString) {
        let path =
            std::env::temp_dir().join(format!("openssl-rs-b26x1-{}-store.pem", std::process::id()));
        std::fs::write(
            &path,
            b"-----BEGIN B26X1 PROBE-----\n-----END B26X1 PROBE-----\n",
        )
        .expect("the probe writes its own temporary store file");
        let uri = std::ffi::CString::new(format!("file:{}", path.display()))
            .expect("the temporary path has no interior NUL");
        (path, uri)
    }

    /// A refused `OSSL_STORE_CTX` allocation *after* a successful provider open must leave the
    /// loader store's cache entry owning a live loader.
    ///
    /// Pre-fix (`store_lib.rs:942`), the error path released the fetched loader twice: once through
    /// `ossl_store_close_it`, once directly. The second release stole the reference the method
    /// store's cache entry owned, so the cache flush below freed the loader block while the
    /// implementation entry still pointed at it. Post-fix only `ossl_store_close_it` releases the
    /// fetched reference, and the flush releases the cache entry's own reference.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn refused_store_ctx_alloc_after_provider_open_preserves_the_cached_loader() {
        let _guard = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        let (path, uri) = temporary_store_file();
        // SAFETY: the caller holds the process-global state lock.
        unsafe { load_providers() };

        let propq = c"provider=default";
        // Warm the loader store's result cache so the probe knows the loader object's address and
        // can watch its releases. The fetch returns one reference; releasing it leaves the
        // implementation entry and the cache entry (two references) owning the object.
        // SAFETY: `scheme`/`propq` are NUL-terminated literals, and `OSSL_STORE_LOADER_fetch`
        // returns a reference this frame owns.
        let loader = unsafe {
            crate::store::store_meth::OSSL_STORE_LOADER_fetch(
                ptr::null_mut(),
                c"file".as_ptr(),
                propq.as_ptr(),
            )
        };
        assert!(!loader.is_null(), "the published `file` row resolves");
        // SAFETY: `loader` is live and the accessor only reads its provider pointer.
        let provider = unsafe { crate::store::store_meth::OSSL_STORE_LOADER_get0_provider(loader) };
        // SAFETY: this releases exactly the reference the fetch above returned.
        unsafe { crate::store::store_meth::OSSL_STORE_LOADER_free(loader) };

        // Refuse exactly the `OSSL_STORE_CTX` block `OwnedCtx::zalloc` requests at `(NULL, 0)`.
        // That request is made after the provider's `open` has answered a live loader context and
        // after `propq_copy` has succeeded -- the B26-X1 OOM window.
        let ctx_size = core::mem::size_of::<OsslStoreCtx>();
        let copy_size = propq.to_bytes().len() + 1;
        adv_alloc::reset();
        adv_alloc::arm(ctx_size);
        // SAFETY: every pointer is NULL or NUL-terminated per `OSSL_STORE_open_ex`'s contract.
        let ctx = unsafe {
            OSSL_STORE_open_ex(
                uri.as_ptr(),
                ptr::null_mut(),
                propq.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                None,
                ptr::null_mut(),
            )
        };
        adv_alloc::disarm();
        assert!(
            ctx.is_null(),
            "the refused context allocation must fail the open"
        );

        // Self-verify the refusal reached the intended window: the `propq_copy` allocation (the
        // statement immediately before the context allocation) must be observed *before* the
        // refused request. An arm consumed inside the provider open cannot satisfy this.
        let ev = adv_alloc::events();
        let refused = ev
            .iter()
            .position(
                |e| matches!(e, adv_alloc::Ev::Malloc { n, site: true, refused: true } if *n == ctx_size),
            )
            .expect("the armed `OSSL_STORE_CTX` allocation was not the request refused");
        let copy = ev
            .iter()
            .position(
                |e| matches!(e, adv_alloc::Ev::Malloc { n, site: true, refused: false } if *n == copy_size),
            )
            .expect("the property-query copy was not allocated, so the open did not reach the OOM window");
        assert!(
            copy < refused,
            "the refused allocation preceded the property copy, so it was not the context allocation"
        );

        // Pre-fix, the flush frees the loader block because the stolen reference had already taken
        // the count to one; post-fix the cache entry still holds its own reference and no allocator
        // release may be observed here.
        adv_alloc::assert_no_double_free();
        // SAFETY: NULL selects the default library context's store loader store; the flush releases
        // only the cached results' own references.
        unsafe {
            crate::store::store_meth::ossl_store_loader_store_cache_flush(ptr::null_mut());
        }
        let freed_by_flush = adv_alloc::events()
            .iter()
            .any(|e| matches!(e, adv_alloc::Ev::Free { p } if *p == loader as usize));
        assert!(
            !freed_by_flush,
            "B26-X1: the loader store cache released a loader it no longer owned after a refused context allocation"
        );

        // Release the implementation entry's reference: post-fix this is the loader block's single
        // allocator release, and the double-release detector must stay quiet.
        // SAFETY: `provider` is live (both providers remain loaded) and this is the store that holds
        // the `file` loader's implementation entry.
        unsafe {
            crate::store::store_meth::ossl_store_loader_store_remove_all_provided(provider);
        }
        let releases = adv_alloc::events()
            .iter()
            .filter(|e| matches!(e, adv_alloc::Ev::Free { p } if *p == loader as usize))
            .count();
        assert_eq!(
            releases, 1,
            "the loader block must be released exactly once across the refused open, the cache flush and the store removal"
        );
        adv_alloc::assert_no_double_free();

        let _ = std::fs::remove_file(path);
    }

    /// A refused `loader_set_params` must refuse the attach, not publish a store whose
    /// `loader` is NULL and whose `loader_ctx` is already closed.
    ///
    /// **Pre-fix (`store_lib.rs:1672-1687`).** The fetched branch assigned `loader_ctx`
    /// before calling `loader_set_params`. On refusal it closed that context, freed and
    /// nulled `fetched_loader`, and left the local `loader_ctx` non-NULL, so the
    /// `loader_ctx.is_null()` guard did not fire: the function published a store with
    /// `loader = NULL`, `fetched_loader = NULL` and a closed `loader_ctx`. Both
    /// `OSSL_STORE_close` (through `ossl_store_close_it`) and `OSSL_STORE_load` then
    /// dereferenced `(*ctx).loader` (NULL).
    ///
    /// **Post-fix.** `loader_ctx` is assigned only on the accepted-params path, so the
    /// refusal leaves it NULL and the attach returns NULL. The provider's `close` still ran:
    /// the file loader's context holds one reference on the probe's BIO, so after attach the
    /// BIO's public reference count is 1 (the probe's own). A missing `p_close` would leave it
    /// at 2; a second `p_close` would release the probe's reference and make the explicit
    /// `BIO_free` below a double release.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn refused_loader_params_refuses_the_attach_without_publishing_a_null_loader() {
        use crate::runtime::bio::bss_mem::BIO_new_mem_buf;
        use crate::runtime::bio::BIO_free;

        let _guard = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        // SAFETY: the caller holds the process-global state lock.
        unsafe { load_providers() };

        let propq = c"provider=default";
        // Warm the loader store's cache so the loader block has independent cache and
        // implementation references; the probe then watches the fetch reference's release.
        // SAFETY: `scheme`/`propq` are NUL-terminated literals, and this fetch returns a
        // reference this frame owns.
        let loader = unsafe {
            crate::store::store_meth::OSSL_STORE_LOADER_fetch(
                ptr::null_mut(),
                c"file".as_ptr(),
                propq.as_ptr(),
            )
        };
        assert!(!loader.is_null(), "the published `file` row resolves");
        // SAFETY: `loader` is live and the accessor only reads its provider pointer.
        let provider = unsafe { crate::store::store_meth::OSSL_STORE_LOADER_get0_provider(loader) };
        // SAFETY: this releases exactly the reference the warm-up fetch returned.
        unsafe { crate::store::store_meth::OSSL_STORE_LOADER_free(loader) };

        // A memory BIO the file loader can attach to. The probe keeps one reference; the
        // file loader's context takes another, and `OSSL_STORE_attach`'s core-BIO wrapper a
        // third. The reference accounting below depends on all three.
        // SAFETY: the literal is live for the call and `BIO_new_mem_buf` copies no ownership
        // of a read-only buffer; the returned BIO carries this frame's reference.
        let bio = unsafe { BIO_new_mem_buf(c"b27x2-probe".as_ptr().cast(), 11) };
        assert!(!bio.is_null(), "the probe's memory BIO is created");

        // `file_set_ctx_params_decoder` refuses a repeated key, so `file_set_ctx_params`
        // answers 0 and `loader_set_params` answers 0. This is a C-valid params array and a
        // defined provider refusal, not a malformed call.
        let mut expect: c_int = 0;
        // SAFETY: the key is a static literal and `expect` is writable for an `int`.
        let duplicated =
            unsafe { OSSL_PARAM_construct_int(OSSL_STORE_PARAM_EXPECT.as_ptr(), &mut expect) };
        let params = [duplicated, duplicated, OSSL_PARAM_construct_end()];

        adv_alloc::reset();
        // SAFETY: every pointer is NULL or live per `OSSL_STORE_attach`'s contract; `params` is
        // a terminated array with a duplicated key, which the provider legitimately refuses.
        let ctx = unsafe {
            OSSL_STORE_attach(
                bio,
                c"file".as_ptr(),
                ptr::null_mut(),
                propq.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                params.as_ptr(),
                None,
                ptr::null_mut(),
            )
        };
        assert!(
            ctx.is_null(),
            "B27-X2: a refused loader_set_params must refuse the attach, not publish a store with loader = NULL"
        );

        // Drop the probe's BIO reference. If the provider's `close` ran, the attach left
        // exactly this one reference on the BIO (its core-BIO wrapper took and released one,
        // and the file context took one that `file_close` released); if `p_close` did not run,
        // the count is still 2 here and the context's reference leaks. The BIO is a `Box`, so
        // the CRYPTO-seam transcript cannot observe it: its public reference count is the
        // witness.
        // SAFETY: `bio` is this frame's live reference (the attach released the other two),
        // so its public reference count is readable.
        let references = unsafe { (*bio).references.load(core::sync::atomic::Ordering::SeqCst) };
        assert_eq!(
            references, 1,
            "B27-X2: the refused attach must close the loader context exactly once (the BIO must be left with only the probe's reference)"
        );
        // SAFETY: `bio` is the live reference this frame owns and this is its single release.
        let freed = unsafe { BIO_free(bio) };
        assert_eq!(freed, 1, "the probe's BIO free succeeds");
        adv_alloc::assert_no_double_free();

        // `OSSL_STORE_close` accepts NULL and answers 1. `OSSL_STORE_load` requires a live
        // context; the refusal publishes none, so there is no store through which it could
        // reach a NULL loader. The negative control below drives the pre-fix published shape
        // through both call sites in isolated child processes.
        // SAFETY: NULL is the documented no-op input.
        assert_eq!(unsafe { OSSL_STORE_close(ptr::null_mut()) }, 1);

        // The fetched loader reference the attach acquired was released by the refusal: after
        // flushing the cache entry's own reference the block is not freed, and after removing
        // the implementation entry's reference it is freed exactly once. A leaked fetch
        // reference would leave the count at one and produce no release.
        // SAFETY: NULL selects the default library context's loader store.
        unsafe {
            crate::store::store_meth::ossl_store_loader_store_cache_flush(ptr::null_mut());
        }
        let freed_by_flush = adv_alloc::events()
            .iter()
            .any(|e| matches!(e, adv_alloc::Ev::Free { p } if *p == loader as usize));
        assert!(
            !freed_by_flush,
            "the loader store cache released a loader the implementation entry still owns"
        );
        // SAFETY: `provider` is live (both providers remain loaded) and this is the store that
        // holds the `file` loader's implementation entry.
        unsafe {
            crate::store::store_meth::ossl_store_loader_store_remove_all_provided(provider);
        }
        let loader_releases = adv_alloc::events()
            .iter()
            .filter(|e| matches!(e, adv_alloc::Ev::Free { p } if *p == loader as usize))
            .count();
        assert_eq!(
            loader_releases, 1,
            "the loader block must be released exactly once across the refused attach, the cache flush and the store removal"
        );
        adv_alloc::assert_no_double_free();
    }

    /// Negative control (§16): the pre-fix published shape faults at both call sites.
    ///
    /// A zeroed `OsslStoreCtx` with `loader = NULL`, `fetched_loader = NULL` and a non-NULL
    /// (already closed) `loader_ctx` is exactly what the pre-fix attach published. `close`
    /// reaches `(*(*ctx).loader).closefn` and `load` reaches `OSSL_STORE_eof`'s
    /// `(*(*ctx).loader).eof`; both dereference the NULL loader. Each call runs in its own
    /// child process so the fault is contained and the parent can observe it. This control
    /// proves the shipped probe's NULL assertion is not vacuous.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn canary_published_null_loader_store_faults_on_close_and_load() {
        const CHILD_ENV: &str = "OPENSSL_RS_B27X2_CANARY";
        const THIS: &str = "store::store_lib::adv_probe::canary_published_null_loader_store_faults_on_close_and_load";

        if let Ok(mode) = std::env::var(CHILD_ENV) {
            // SAFETY: this is the pre-fix published shape: no live loader, so both call sites
            // dereference NULL. The fault is the control's expected outcome.
            unsafe {
                let mut ctx: OsslStoreCtx = core::mem::zeroed();
                ctx.loader = ptr::null();
                ctx.fetched_loader = ptr::null_mut();
                ctx.loader_ctx = core::ptr::dangling_mut::<OsslStoreLoaderCtx>();
                if mode == "close" {
                    let _ = ossl_store_close_it(&mut ctx);
                } else {
                    let _ = OSSL_STORE_load(&mut ctx);
                }
            }
            // Reaching here means the pre-fix shape did not fault, so the control is dead.
            std::process::exit(1);
        }

        use std::os::unix::process::ExitStatusExt;

        let exe = std::env::current_exe().expect("the test binary has a path");
        let run = |mode: &str| {
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    THIS,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, mode)
                // Under ASan, let the kernel deliver the fault so the parent observes SIGSEGV
                // rather than ASan's intercepted exit code.
                .env("ASAN_OPTIONS", "handle_segv=0")
                .status()
                .expect("the canary child starts")
        };

        for mode in ["close", "load"] {
            let status = run(mode);
            let signal = status.signal();
            // The pre-fix shape has no loader, so the call dereferences NULL. In a debug court
            // Rust's own null check turns that into a non-unwinding panic (SIGABRT); an
            // optimised or sanitised venue may deliver SIGSEGV instead. Either is the fault
            // this control exists to observe; a normal exit is not.
            assert!(
                matches!(signal, Some(6) | Some(11)),
                "the pre-fix published shape must fault on {mode} (observed signal {signal:?})"
            );
        }
    }

    /// Negative control (§16): the recording allocator's double-release detector must fire on a
    /// deliberate second release, so a quiet [`adv_alloc::double_free`] above means something.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn canary_double_release_is_detected() {
        let _guard = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        adv_alloc::reset();
        // SAFETY: `b` is a fresh block; the second release is the deliberate test-only defect.
        unsafe {
            let b = CRYPTO_malloc(16, ptr::null(), 0).cast::<u8>();
            assert!(!b.is_null());
            CRYPTO_free(b.cast(), ptr::null(), 0);
            CRYPTO_free(b.cast(), ptr::null(), 0);
        }
        assert!(
            adv_alloc::double_free(),
            "the instrument must flag a double release (negative control)"
        );
    }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(OsslStoreCtx => zero_state_sweep_ossl_store_ctx, OsslStoreSearch => zero_state_sweep_ossl_store_search, OsslStoreInfo => zero_state_sweep_ossl_store_info);
