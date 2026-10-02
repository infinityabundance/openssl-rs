//! `crypto/ts/` — the RFC 3161 timestamping surface. Phase 12.5.
//!
//! Phase 12.5 lands the timestamping surface `ts.h` declares, transcribed from the authority's
//! `crypto/ts/` units. The units and what each is:
//!
//! * [`ts_asn1`] — the six item groups (`TS_MSG_IMPRINT`, `TS_REQ`, `TS_ACCURACY`, `TS_TST_INFO`,
//!   `TS_STATUS_INFO`, `TS_RESP`), the accessors `IMPLEMENT_ASN1_FUNCTIONS` generates, the
//!   BIO/`FILE` stream wrappers, and `PKCS7_to_TS_TST_INFO`.
//! * [`ts_req_utils`] — the `TS_REQ` accessors and its extension stack.
//! * [`ts_rsp_utils`] — the `TS_RESP`/`TS_TST_INFO`/`TS_STATUS_INFO`/`TS_ACCURACY` accessors and
//!   the `TS_TST_INFO` extension stack.
//! * [`ts_lib`] — the printing helpers `ts_req_print`/`ts_rsp_print` compose.
//! * [`ts_req_print`] — `TS_REQ_print_bio`.
//! * [`ts_rsp_print`] — `TS_RESP_print_bio`, `TS_STATUS_INFO_print_bio`, `TS_TST_INFO_print_bio`.
//! * [`ts_rsp_sign`] — the `TS_RESP_CTX_*` authority engine: the context object model, the
//!   response-generation entry point `TS_RESP_create_response` and every static it reaches
//!   (`ts_RESP_sign`, the ESS signing-certificate attachment, `ts_TST_INFO_content_new` and
//!   `TS_RESP_set_genTime_with_precision`).
//! * [`ts_rsp_verify`] — the response verifier: `TS_RESP_verify_signature`,
//!   `TS_RESP_verify_response`, `TS_RESP_verify_token` and the statics they reach.
//! * [`ts_verify_ctx`] — `TS_VERIFY_CTX_new`/`init`/`free`/`cleanup`, the setter family and
//!   `TS_REQ_to_TS_VERIFY_CTX`.
//!
//! ## What is withheld, and why
//!
//! One pair of `crypto/ts/`'s entry points is **not** landed here, and it is not ts-local:
//!
//! * `TS_CONF_set_crypto_device` and `TS_CONF_set_default_engine` (`ts_conf.c`) reach
//!   `ENGINE_by_id`/`ENGINE_set_default`, which are Phase **13**'s; `src/engine/eng_list.rs`
//!   records `ENGINE_by_id` as withheld on `crypto/engine/eng_dyn.c`. The non-engine
//!   `TS_CONF_*` readers land as [`ts_conf`].
//!
//! `ts_rsp_sign.c`'s response builder and `ts_rsp_verify.c` waited on 12.7's ESS item group and
//! its `OSSL_ESS_*` helpers (`crypto/ess/ess_asn1.c`, `crypto/ess/ess_lib.c`), and 12.5b lands
//! them now that 12.7 has closed.
//!
//! ## The bytes are the contract
//!
//! Every item group is the authority's own `ASN1_*` template in its own order, and the differential
//! court `RT-TS` compares the container's DER byte for byte and the print text line for line
//! against the authority's. `docs/PHASE-12-SUBPHASES.md` §3.1 is why a self-consistent round trip
//! is not enough.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, CStr};

use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;

pub(crate) mod ts_asn1;
pub(crate) mod ts_conf;
pub(crate) mod ts_lib;
pub(crate) mod ts_req_print;
pub(crate) mod ts_req_utils;
pub(crate) mod ts_rsp_print;
pub(crate) mod ts_rsp_sign;
pub(crate) mod ts_rsp_utils;
pub(crate) mod ts_rsp_verify;
pub(crate) mod ts_verify_ctx;

/// `ERR_LIB_TS` — `include/openssl/err.h.in:112`.
pub(crate) const ERR_LIB_TS: c_int = 47;

/// `ERR_R_ASN1_LIB` — `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_OBJ_LIB` — `(ERR_LIB_OBJ | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_OBJ_LIB: c_int = 524296;
/// `ERR_R_CRYPTO_LIB` — `(ERR_LIB_CRYPTO | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_TS_LIB` — `(ERR_LIB_TS | ERR_RFLAG_COMMON)`.
pub(crate) const ERR_R_TS_LIB: c_int = 524335;
/// `ERR_R_EVP_LIB` — `(ERR_LIB_EVP | ERR_RFLAG_COMMON)`, `include/openssl/err.h.in:322`.
pub(crate) const ERR_R_EVP_LIB: c_int = 524294;
/// `ERR_R_X509_LIB` — `(ERR_LIB_X509 | ERR_RFLAG_COMMON)`, `include/openssl/err.h.in:327`.
pub(crate) const ERR_R_X509_LIB: c_int = 524299;
/// `ERR_R_PKCS7_LIB` — `(ERR_LIB_PKCS7 | ERR_RFLAG_COMMON)`, `include/openssl/err.h.in:334`.
pub(crate) const ERR_R_PKCS7_LIB: c_int = 524321;

/// One `ERR_raise(ERR_LIB_TS, reason)` coordinate of a `crypto/ts/` translation unit.
///
/// The file, line and function are the authority's own, so the error's debug strings match the
/// authority's for any caller that reads them back through `ERR_get_error_all`.
///
/// # Safety
/// The coordinate is a compile-time constant.
pub(crate) unsafe fn raise_ts(
    file: &'static CStr,
    line: c_int,
    func: &'static CStr,
    reason: c_int,
) {
    let site = ErrSite {
        file,
        line,
        func,
        lib: ERR_LIB_TS,
        reason,
        dynamic_reason: false,
    };
    // SAFETY: the site is a live local for the duration of the call.
    unsafe { raise_site(&site) };
}

/// One `ERR_raise_data(ERR_LIB_TS, reason, ...)` coordinate of a `crypto/ts/` translation unit.
///
/// The message is the authority's already-formatted data argument; the coordinate is the
/// authority's own file, line and function, so the data string matches the authority's for a
/// caller that reads it back through `ERR_get_error_all`.
///
/// # Safety
/// The coordinate is a compile-time constant and `msg` is NULL or NUL-terminated.
pub(crate) unsafe fn raise_ts_data(
    file: &'static CStr,
    line: c_int,
    func: &'static CStr,
    reason: c_int,
    msg: *const core::ffi::c_char,
) {
    let site = ErrSite {
        file,
        line,
        func,
        lib: ERR_LIB_TS,
        reason,
        dynamic_reason: false,
    };
    // SAFETY: the site is a live local and `msg` is NUL-terminated per the contract.
    unsafe { crate::runtime::err::raise_site_data(&site, msg) };
}
