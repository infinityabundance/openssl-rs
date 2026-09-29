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
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::Bio;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
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

extern "C" {
    /// Pull one general-purpose argument from a live `va_list`.
    ///
    /// Defined in `src/runtime/bio/bio_va.c`. The `OSSL_STORE_C_USE_SECMEM` arm of
    /// `OSSL_STORE_vctrl` is the only reader; it needs the caller's `int *`, and a
    /// `va_arg` walk cannot be written in stable Rust.
    fn openssl_rs_va_gp(ap: *mut c_void) -> u64;
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
/// `params != NULL`; the crate spells that as a skip, because the only callers are in
/// the fetched branch, which no candidate transcript reaches while no store row is
/// published (see the module doc).
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
    let mut ctx: *mut OsslStoreCtx = ptr::null_mut();
    let mut propq_copy: *mut c_char = ptr::null_mut();
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
            // SAFETY: `propq` is NUL-terminated.
            propq_copy = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
            if propq_copy.is_null() {
                break 'err;
            }
        }
        // SAFETY: `size_of::<OsslStoreCtx>()` is the context the authority allocates.
        ctx = CRYPTO_zalloc(core::mem::size_of::<OsslStoreCtx>(), ptr::null(), 0)
            .cast::<OsslStoreCtx>();
        if ctx.is_null() {
            break 'err;
        }

        // SAFETY: `ctx` is a fresh zeroed allocation and every pointer stored is live.
        unsafe {
            (*ctx).properties = propq_copy;
            (*ctx).fetched_loader = fetched_loader;
            (*ctx).loader = loader;
            (*ctx).loader_ctx = loader_ctx;
            (*ctx).post_process = post_process;
            (*ctx).post_process_data = post_process_data;
            ptr::write(&mut (*ctx).pwdata, pwdata);
        }

        /*
         * If the attempt to open with the 'file' scheme loader failed and the other scheme
         * loader succeeded, the failure to open with the 'file' scheme loader leaves an
         * error on the error stack.  Let's remove it.
         */
        // SAFETY: a mark was set at entry.
        ERR_pop_to_mark();

        return ctx;
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
    }
    // SAFETY: `fetched_loader` is NULL or a freed-by-the-line-above loader, matching the
    // authority's own double release on this unreachable-in-candidate path.
    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
    if !propq_copy.is_null() {
        // SAFETY: `propq_copy` is the `CRYPTO_strdup` this function owns.
        unsafe { CRYPTO_free(propq_copy.cast::<c_void>(), ptr::null(), 0) };
    }
    if !ctx.is_null() {
        // SAFETY: `ctx` is the `CRYPTO_zalloc` this function owns.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0) };
    }
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
        // SAFETY: `name_der` is NULL or the buffer `i2d_X509_NAME` allocated; `number` is NULL or
        // the BIGNUM `ASN1_INTEGER_to_BN` allocated.
        unsafe {
            CRYPTO_free(name_der, ptr::null(), 0);
            BN_free(number);
        }
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

    // SAFETY: `ctx` is the context this call owns.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0) };
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
                loader_ctx = attached.cast::<OsslStoreLoaderCtx>();
                if loader_ctx.is_null() {
                    // SAFETY: `fetched_loader` is live and not kept.
                    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                    fetched_loader = ptr::null_mut();
                // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                } else if unsafe { loader_set_params(fetched_loader, attached, params, propq) } == 0
                {
                    // SAFETY: the enclosing function's `# Safety` contract makes every pointer used here valid.
                    if let Some(p_close) = unsafe { (*fetched_loader).p_close } {
                        // SAFETY: `attached` is the provider's own context.
                        unsafe { p_close(attached) };
                    }
                    // SAFETY: `fetched_loader` is live and not kept.
                    unsafe { OSSL_STORE_LOADER_free(fetched_loader) };
                    fetched_loader = ptr::null_mut();
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

    // SAFETY: `size_of::<OsslStoreCtx>()` is the context the authority allocates.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<OsslStoreCtx>(), ptr::null(), 0).cast::<OsslStoreCtx>();
    if ctx.is_null() {
        // SAFETY: the mark was set above.
        ERR_clear_last_mark();
        return ptr::null_mut();
    }

    if !ui_method.is_null()
        // SAFETY: `ctx` is a fresh zeroed allocation; `pwdata` is live.
        && unsafe { ossl_pw_set_ui_method(&mut (*ctx).pwdata, ui_method, ui_data) } == 0
    {
        // SAFETY: the mark was set above.
        ERR_clear_last_mark();
        // SAFETY: `ctx` is the allocation just made.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live and every pointer stored is live.
    unsafe {
        (*ctx).fetched_loader = fetched_loader;
        (*ctx).loader = loader;
        (*ctx).loader_ctx = loader_ctx;
        (*ctx).post_process = post_process;
        (*ctx).post_process_data = post_process_data;
    }

    /*
     * ossl_store_get0_loader_int will raise an error if the loader for the scheme
     * cannot be retrieved. But if a loader was successfully fetched then we remove
     * this error from the error stack.
     */
    // SAFETY: the mark was set above.
    ERR_pop_to_mark();

    ctx
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
/// `data` is stored as-is; ownership is transferred to the returned object.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_INFO_new(
    type_: c_int,
    data: *mut c_void,
) -> *mut OsslStoreInfo {
    // SAFETY: `size_of::<OsslStoreInfo>()` is the allocation the authority makes.
    let info = CRYPTO_zalloc(core::mem::size_of::<OsslStoreInfo>(), ptr::null(), 0)
        .cast::<OsslStoreInfo>();

    if info.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `info` is a fresh zeroed allocation.
    unsafe {
        (*info).type_ = type_;
        (*info).data.data = data;
    }
    info
}

/// `OSSL_STORE_INFO *OSSL_STORE_INFO_new_NAME(char *name)` — `store_lib.c:626-639`.
///
/// # Safety
/// `name` is NULL or an allocation whose ownership transfers to the object.
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
    if info.is_null() {
        return;
    }

    // SAFETY: `info` is live per the contract.
    match unsafe { (*info).type_ } {
        OSSL_STORE_INFO_NAME => {
            // SAFETY: the type is NAME, so `name`/`desc` are live and owned.
            unsafe {
                CRYPTO_free((*info).data.name.name.cast::<c_void>(), ptr::null(), 0);
                CRYPTO_free((*info).data.name.desc.cast::<c_void>(), ptr::null(), 0);
            }
        }
        OSSL_STORE_INFO_PARAMS => {
            // SAFETY: the type is PARAMS, so `params` is live and owned.
            unsafe { EVP_PKEY_free((*info).data.params) };
        }
        OSSL_STORE_INFO_PUBKEY => {
            // SAFETY: the type is PUBKEY, so `pubkey` is live and owned.
            unsafe { EVP_PKEY_free((*info).data.pubkey) };
        }
        OSSL_STORE_INFO_PKEY => {
            // SAFETY: the type is PKEY, so `pkey` is live and owned.
            unsafe { EVP_PKEY_free((*info).data.pkey) };
        }
        OSSL_STORE_INFO_CERT => {
            // SAFETY: the type is CERT, so `x509` is live and owned as an `X509`.
            unsafe { X509_free((*info).data.x509.cast::<X509>()) };
        }
        OSSL_STORE_INFO_CRL => {
            // SAFETY: the type is CRL, so `crl` is live and owned as an `X509_CRL`.
            unsafe { X509_CRL_free((*info).data.crl.cast::<X509Crl>()) };
        }
        _ => {}
    }
    // SAFETY: `info` is the allocation `OSSL_STORE_INFO_new` made.
    unsafe { CRYPTO_free(info.cast::<c_void>(), ptr::null(), 0) };
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
    // SAFETY: `size_of::<OsslStoreSearch>()` is the allocation the authority makes.
    let search = CRYPTO_zalloc(core::mem::size_of::<OsslStoreSearch>(), ptr::null(), 0)
        .cast::<OsslStoreSearch>();

    if search.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search).search_type = OSSL_STORE_SEARCH_BY_NAME;
        (*search).name = name;
    }
    search
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
    // SAFETY: `size_of::<OsslStoreSearch>()` is the allocation the authority makes.
    let search = CRYPTO_zalloc(core::mem::size_of::<OsslStoreSearch>(), ptr::null(), 0)
        .cast::<OsslStoreSearch>();

    if search.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search).search_type = OSSL_STORE_SEARCH_BY_ISSUER_SERIAL;
        (*search).name = name;
        (*search).serial = serial;
    }
    search
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
    // SAFETY: `size_of::<OsslStoreSearch>()` is the allocation the authority makes.
    let search = CRYPTO_zalloc(core::mem::size_of::<OsslStoreSearch>(), ptr::null(), 0)
        .cast::<OsslStoreSearch>();

    if search.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `digest` is NULL or live; a NULL is the authority's own refusal.
    let md_size = unsafe { EVP_MD_get_size(digest) };
    if md_size <= 0 {
        // SAFETY: `search` is the allocation just made.
        unsafe { CRYPTO_free(search.cast::<c_void>(), ptr::null(), 0) };
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
        // SAFETY: `search` is the allocation just made.
        unsafe { CRYPTO_free(search.cast::<c_void>(), ptr::null(), 0) };
        return ptr::null_mut();
    }

    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search).search_type = OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT;
        (*search).digest = digest;
        (*search).string = bytes;
        (*search).stringlength = len;
    }
    search
}

/// `OSSL_STORE_SEARCH *OSSL_STORE_SEARCH_by_alias(const char *alias)` —
/// `store_lib.c:974-985`.
///
/// # Safety
/// `alias` must be NUL-terminated and outlive the search.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_by_alias(alias: *const c_char) -> *mut OsslStoreSearch {
    // SAFETY: `size_of::<OsslStoreSearch>()` is the allocation the authority makes.
    let search = CRYPTO_zalloc(core::mem::size_of::<OsslStoreSearch>(), ptr::null(), 0)
        .cast::<OsslStoreSearch>();

    if search.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `alias` is NUL-terminated per the contract.
    let len = unsafe { c_strlen(alias) };
    // SAFETY: `search` is a fresh zeroed allocation.
    unsafe {
        (*search).search_type = OSSL_STORE_SEARCH_BY_ALIAS;
        (*search).string = alias.cast::<c_uchar>();
        (*search).stringlength = len;
    }
    search
}

/// `void OSSL_STORE_SEARCH_free(OSSL_STORE_SEARCH *search)` — `store_lib.c:988-991`.
///
/// # Safety
/// `search` must be NULL or an object from one of the constructors, not already freed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_SEARCH_free(search: *mut OsslStoreSearch) {
    // SAFETY: `search` is NULL or the allocation a constructor made.
    unsafe { CRYPTO_free(search.cast::<c_void>(), ptr::null(), 0) };
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
