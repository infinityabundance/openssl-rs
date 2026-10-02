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
//! * [`ts_verify_ctx`] — `TS_VERIFY_CTX_new`/`init`/`free`/`cleanup`, the setter family and
//!   `TS_REQ_to_TS_VERIFY_CTX`.
//!
//! ## What is withheld, and why
//!
//! Two of `crypto/ts/`'s units are **not** landed here, and neither is withheld for a ts-local
//! reason:
//!
//! * `ts_rsp_sign.c`'s `TS_RESP_create_response` and `ts_rsp_verify.c` are blocked on the ESS
//!   item group and the `OSSL_ESS_*` helpers (`crypto/ess/ess_asn1.c`, `crypto/ess/ess_lib.c`),
//!   which are Phase **12.7**'s by their `ess.h` declaration. `ts_RESP_sign` attaches the
//!   `SigningCertificate` signed attribute through `OSSL_ESS_signing_cert_new_init` and
//!   `ts_check_signing_certs` reads it back through `OSSL_ESS_check_signing_certs`; neither has a
//!   landed counterpart, and ESS is not ts-local, so the sign/verify entry points wait for 12.7
//!   rather than reaching across the subphase boundary. (The remainder of `ts_rsp_sign.c`'s
//!   context-management surface lands as [`ts_rsp_sign`].)
//! * `TS_CONF_set_crypto_device` and `TS_CONF_set_default_engine` (`ts_conf.c`) reach
//!   `ENGINE_by_id`/`ENGINE_set_default`, which are Phase **13**'s; `src/engine/eng_list.rs`
//!   records `ENGINE_by_id` as withheld on `crypto/engine/eng_dyn.c`. The non-engine
//!   `TS_CONF_*` readers land as [`ts_conf`].
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
