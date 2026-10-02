//! `crypto/cmp/cmp_ctx.c` — the `OSSL_CMP_CTX` object and its accessors. Phase 12.4.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces, non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_free};
use crate::cmp::cmp_asn::{CmpItav, CmpMsg, OSSL_CMP_ITAV_free};
use crate::cmp::cmp_util::{
    ossl_cmp_asn1_octet_string_set1, ossl_cmp_asn1_octet_string_set1_bytes, OSSL_CMP_log_cb_t,
    OSSL_CMP_print_errors_cb, OSSL_CMP_LOG_DEBUG, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_INFO,
    OSSL_CMP_LOG_MAX,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_type, EvpMd};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_hmac_sha1, NID_sha256, NID_subject_alt_name, OBJ_nid2sn};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_cpols::{CERTIFICATEPOLICIES_new, POLICYINFO_free, PolicyInfo};
use crate::x509::v3_genn::{GENERAL_NAME_dup, GENERAL_NAME_free};
use crate::x509::v3_purp::ossl_x509v3_cache_extensions;
use crate::x509::x509_cmp::{ossl_x509_add_certs_new, X509_chain_up_ref, X509_get0_pubkey};
use crate::x509::x509_lu::{X509Store, X509_STORE_free};
use crate::x509::x509_req::X509_REQ_get0_pubkey;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x509_v3::X509v3_get_ext_by_NID;
use crate::x509::x509_vfy::X509_build_chain;
use crate::x509::x_exten::X509_EXTENSION_free;
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};
use crate::x509::x_req::{X509_REQ_dup, X509_REQ_free};
use crate::x509::x_x509::{X509_free, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_ctx.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;

/// The choice selectors of `OSSL_CRMF_POPO` — `include/openssl/crmf.h.in:160-164`.
const OSSL_CRMF_POPO_NONE: c_int = -1;
const OSSL_CRMF_POPO_SIGNATURE: c_int = 1;
const OSSL_CRMF_POPO_KEYAGREE: c_int = 3;
/// `CRL_REASON_NONE`.
const CRL_REASON_NONE: c_int = 0;
/// `OCSP_REVOKED_STATUS_NOSTATUS` / `_AACOMPROMISE` — `include/openssl/ocsp.h`.
const OCSP_REVOKED_STATUS_NOSTATUS: c_int = -1;
const OCSP_REVOKED_STATUS_AACOMPROMISE: c_int = 10;

/// The `OSSL_CMP_OPT_*` option selectors — `include/openssl/cmp.h.in:355-378`.
const OSSL_CMP_OPT_LOG_VERBOSITY: c_int = 0;
const OSSL_CMP_OPT_KEEP_ALIVE: c_int = 10;
const OSSL_CMP_OPT_MSG_TIMEOUT: c_int = 11;
const OSSL_CMP_OPT_TOTAL_TIMEOUT: c_int = 12;
const OSSL_CMP_OPT_USE_TLS: c_int = 13;
const OSSL_CMP_OPT_VALIDITY_DAYS: c_int = 20;
const OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT: c_int = 21;
const OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL: c_int = 22;
const OSSL_CMP_OPT_POLICIES_CRITICAL: c_int = 23;
const OSSL_CMP_OPT_POPO_METHOD: c_int = 24;
const OSSL_CMP_OPT_IMPLICIT_CONFIRM: c_int = 25;
const OSSL_CMP_OPT_DISABLE_CONFIRM: c_int = 26;
const OSSL_CMP_OPT_REVOCATION_REASON: c_int = 27;
const OSSL_CMP_OPT_UNPROTECTED_SEND: c_int = 30;
const OSSL_CMP_OPT_UNPROTECTED_ERRORS: c_int = 31;
const OSSL_CMP_OPT_OWF_ALGNID: c_int = 32;
const OSSL_CMP_OPT_MAC_ALGNID: c_int = 33;
const OSSL_CMP_OPT_DIGEST_ALGNID: c_int = 34;
const OSSL_CMP_OPT_IGNORE_KEYUSAGE: c_int = 35;
const OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR: c_int = 36;
const OSSL_CMP_OPT_NO_CACHE_EXTRACERTS: c_int = 37;

/// `X509_ADD_FLAG_UP_REF`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_NO_DUP`.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;

/// `OSSL_HTTP_REQ_CTX` — opaque here.
type OSSL_HTTP_REQ_CTX = c_void;
/// `OSSL_CMP_transfer_cb_t`/`OSSL_CMP_certConf_cb_t`/`OSSL_HTTP_bio_cb_t` — pointer-sized.
type CbPtr = *mut c_void;

/// `OSSL_CMP_transfer_cb_t` — `include/openssl/cmp.h.in:397-398`.
pub type OSSL_CMP_transfer_cb_t =
    Option<unsafe extern "C" fn(*mut OsslCmpCtx, *const CmpMsg) -> *mut CmpMsg>;
/// `OSSL_CMP_certConf_cb_t` — `include/openssl/cmp.h.in:444-445`.
pub type OSSL_CMP_certConf_cb_t =
    Option<unsafe extern "C" fn(*mut OsslCmpCtx, *mut X509, c_int, *mut *const c_char) -> c_int>;
/// `OSSL_HTTP_bio_cb_t` — `include/openssl/http.h`.
pub type OSSL_HTTP_bio_cb_t =
    Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_int, c_int) -> *mut c_void>;

/// `struct ossl_cmp_ctx_st` — `cmp_local.h:24-130`. Every pointer is stored untyped: the exported
/// accessors' ABI is a pointer either way, and the typed views live in the units that read a field.
#[repr(C)]
pub(crate) struct OsslCmpCtx {
    pub(crate) libctx: *mut c_void,
    pub(crate) propq: *mut c_char,
    log_cb: Option<OSSL_CMP_log_cb_t>,
    log_verbosity: c_int,
    transfer_cb: CbPtr,
    transfer_cb_arg: *mut c_void,
    pub(crate) http_ctx: *mut OSSL_HTTP_REQ_CTX,
    pub(crate) server_path: *mut c_char,
    pub(crate) server: *mut c_char,
    pub(crate) server_port: c_int,
    pub(crate) proxy: *mut c_char,
    pub(crate) no_proxy: *mut c_char,
    pub(crate) keep_alive: c_int,
    pub(crate) msg_timeout: c_int,
    total_timeout: c_int,
    pub(crate) tls_used: c_int,
    end_time: i64,
    pub(crate) http_cb: CbPtr,
    http_cb_arg: *mut c_void,
    unprotected_errors: c_int,
    no_cache_extra_certs: c_int,
    srv_cert: *mut X509,
    validated_srv_cert: *mut X509,
    expected_sender: *mut X509Name,
    trusted: *mut X509Store,
    pub(crate) untrusted: *mut OpenSslStack,
    ignore_keyusage: c_int,
    permit_ta_in_extra_certs_for_ir: c_int,
    unprotected_send: c_int,
    cert: *mut X509,
    chain: *mut OpenSslStack,
    pkey: *mut EvpPkey,
    reference_value: *mut Asn1String,
    secret_value: *mut Asn1String,
    pbm_slen: usize,
    pbm_owf: *mut EvpMd,
    pbm_itercnt: c_int,
    pbm_mac: c_int,
    recipient: *mut X509Name,
    digest: *mut EvpMd,
    transaction_id: *mut Asn1String,
    sender_nonce: *mut Asn1String,
    recip_nonce: *mut Asn1String,
    first_sender_nonce: *mut Asn1String,
    free_text: *mut Asn1String,
    geninfo_itavs: *mut OpenSslStack,
    implicit_confirm: c_int,
    disable_confirm: c_int,
    extra_certs_out: *mut OpenSslStack,
    new_pkey: *mut EvpPkey,
    new_pkey_priv: c_int,
    issuer: *mut X509Name,
    serial_number: *mut Asn1String,
    days: c_int,
    subject_name: *mut X509Name,
    subject_alt_names: *mut OpenSslStack,
    subject_alt_name_nodefault: c_int,
    set_subject_alt_name_critical: c_int,
    req_extensions: *mut OpenSslStack,
    policies: *mut OpenSslStack,
    set_policies_critical: c_int,
    popo_method: c_int,
    old_cert: *mut X509,
    p10_csr: *mut c_void,
    revocation_reason: c_int,
    genm_itavs: *mut OpenSslStack,
    pub(crate) status: c_int,
    pub(crate) status_string: *mut OpenSslStack,
    pub(crate) fail_info_code: c_int,
    new_cert: *mut X509,
    new_chain: *mut OpenSslStack,
    ca_pubs: *mut OpenSslStack,
    extra_certs_in: *mut OpenSslStack,
    cert_conf_cb: CbPtr,
    cert_conf_cb_arg: *mut c_void,
}

/// `ERR_raise(ERR_LIB_CMP, reason)` for this unit's NULL-argument arms.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_ctx(reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        crate::runtime::err::raise_site(&crate::runtime::err::err_sites::ErrSite {
            file: FILE,
            line: 0,
            func: c"OSSL_CMP_CTX",
            lib: ERR_LIB_CMP,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `CMP_R_NULL_ARGUMENT`.
const CMP_R_NULL_ARGUMENT: c_int = 103;

macro_rules! ctx_get0_ptr {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or a live `OSSL_CMP_CTX`."]
        pub unsafe extern "C" fn $f(ctx: *const OsslCmpCtx) -> *mut c_void {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return ptr::null_mut();
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).$field.cast() }
        }
    };
}

macro_rules! ctx_get_int {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or a live `OSSL_CMP_CTX`."]
        pub unsafe extern "C" fn $f(ctx: *const OsslCmpCtx) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return -1;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).$field }
        }
    };
}

macro_rules! ctx_set0_ptr {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or live; `val` is NULL or transfers ownership."]
        pub unsafe extern "C" fn $f(ctx: *mut OsslCmpCtx, val: *mut c_void) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).$field = val };
            1
        }
    };
}

macro_rules! ctx_set_int {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or live."]
        pub unsafe extern "C" fn $f(ctx: *mut OsslCmpCtx, val: c_int) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).$field = val };
            1
        }
    };
}

macro_rules! ctx_set1_char {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or live; `val` is NULL or NUL-terminated."]
        pub unsafe extern "C" fn $f(ctx: *mut OsslCmpCtx, val: *const c_char) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return 0;
            }
            let dup = if !val.is_null() {
                // SAFETY: `val` is NUL-terminated.
                unsafe { CRYPTO_strdup(val, FILE.as_ptr(), 0) }
            } else {
                ptr::null_mut()
            };
            if !val.is_null() && dup.is_null() {
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe {
                CRYPTO_free((*ctx).$field.cast(), FILE.as_ptr(), 0);
                (*ctx).$field = dup;
            }
            1
        }
    };
}

macro_rules! ctx_set1_dup {
    ($f:ident, $field:ident, $dup:path, $free:path) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or live; `val` is NULL or live."]
        pub unsafe extern "C" fn $f(ctx: *mut OsslCmpCtx, val: *const c_void) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return 0;
            }
            // SAFETY: `val` is live and the thunk duplicates it.
            let dup = if !val.is_null() {
                // SAFETY: `val` is live and the thunk duplicates it.
                unsafe { $dup(val) }
            } else {
                ptr::null_mut()
            };
            if !val.is_null() && dup.is_null() {
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe {
                $free((*ctx).$field.cast());
                (*ctx).$field = dup.cast();
            }
            1
        }
    };
}

// --- void-typed free/dup thunks for the macro-generated setters ---

unsafe extern "C" fn x509_name_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { X509_NAME_dup(p.cast()) }.cast()
}
unsafe extern "C" fn x509_name_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_NAME_free(p.cast()) };
}
unsafe extern "C" fn asn1_integer_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { ASN1_item_dup(ASN1_INTEGER_it(), p) }.cast()
}
unsafe extern "C" fn asn1_integer_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { ASN1_INTEGER_free(p.cast()) };
}
unsafe extern "C" fn x509_req_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { X509_REQ_dup(p.cast()) }.cast()
}
unsafe extern "C" fn x509_req_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_REQ_free(p.cast()) };
}

/// `TYPE _free(...)` thunks for `OSSL_CMP_CTX_free`.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast()) };
}
unsafe extern "C" fn evp_pkey_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { EVP_PKEY_free(p.cast()) };
}
unsafe extern "C" fn evp_md_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { EVP_MD_free(p.cast()) };
}
unsafe extern "C" fn octet_string_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { ASN1_OCTET_STRING_free(p.cast()) };
}
unsafe extern "C" fn general_name_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { GENERAL_NAME_free(p.cast()) };
}
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_EXTENSION_free(p.cast()) };
}
unsafe extern "C" fn utf8_string_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { crate::asn1::string::ASN1_UTF8STRING_free(p.cast()) };
}
unsafe extern "C" fn x509_store_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_STORE_free(p.cast()) };
}
unsafe extern "C" fn itav_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { OSSL_CMP_ITAV_free(p.cast()) };
}
unsafe extern "C" fn policy_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { POLICYINFO_free(p.cast()) };
}

/// Frees a stack of `OSSL_CMP_ITAV`, as the authority's `OSSL_CMP_ITAVs_free` macro does.
///
/// # Safety
/// `sk` is NULL or a live stack of `OSSL_CMP_ITAV`.
unsafe fn itavs_free(sk: *mut OpenSslStack) {
    // SAFETY: `sk` is NULL or live.
    unsafe { OPENSSL_sk_pop_free(sk, Some(itav_free_void)) };
}

/// `static int cmp_ctx_set_md(OSSL_CMP_CTX *ctx, EVP_MD **pmd, int nid)` — `cmp_ctx.c:82-94`.
unsafe fn cmp_ctx_set_md(ctx: *mut OsslCmpCtx, pmd: *mut *mut EvpMd, nid: c_int) -> c_int {
    // SAFETY: `ctx` is live; the object table answers a name for a known NID.
    let md = unsafe { EVP_MD_fetch((*ctx).libctx, OBJ_nid2sn(nid), (*ctx).propq.cast_const()) };
    if md.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(136) };
        return 0;
    }
    // SAFETY: `pmd` is a live out-pointer.
    unsafe {
        EVP_MD_free(*pmd);
        *pmd = md;
    }
    1
}

/// `OSSL_CMP_CTX *OSSL_CMP_CTX_new(OSSL_LIB_CTX *libctx, const char *propq)` — `cmp_ctx.c:100-142`.
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_new(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OsslCmpCtx {
    // SAFETY: `CRYPTO_zalloc` returns zeroed memory or NULL.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<OsslCmpCtx>(), FILE.as_ptr(), 102) as *mut OsslCmpCtx;
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live and zeroed.
    unsafe {
        (*ctx).libctx = libctx;
    }
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated.
        let dup = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 108) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).propq = dup };
        if dup.is_null() {
            // SAFETY: `ctx` is live.
            unsafe { OSSL_CMP_CTX_free(ctx) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).log_verbosity = OSSL_CMP_LOG_INFO;
        (*ctx).status = crate::cmp::cmp_status::OSSL_CMP_PKISTATUS_unspecified;
        (*ctx).fail_info_code = -1;
        (*ctx).keep_alive = 1;
        (*ctx).msg_timeout = -1;
        (*ctx).tls_used = -1;
    }
    let untrusted = OPENSSL_sk_new_null();
    if untrusted.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { OSSL_CMP_CTX_free(ctx) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).untrusted = untrusted;
        (*ctx).pbm_slen = 16;
    }
    // SAFETY: `ctx` is live.
    if unsafe { cmp_ctx_set_md(ctx, ptr::addr_of_mut!((*ctx).pbm_owf), NID_sha256) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe { OSSL_CMP_CTX_free(ctx) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).pbm_itercnt = 500;
        (*ctx).pbm_mac = NID_hmac_sha1;
    }
    // SAFETY: `ctx` is live.
    if unsafe { cmp_ctx_set_md(ctx, ptr::addr_of_mut!((*ctx).digest), NID_sha256) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe { OSSL_CMP_CTX_free(ctx) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe {
        (*ctx).popo_method = OSSL_CRMF_POPO_SIGNATURE;
        (*ctx).revocation_reason = CRL_REASON_NONE;
    }
    ctx
}

/// `void OSSL_CMP_CTX_free(OSSL_CMP_CTX *ctx)` — `cmp_ctx.c:185-245`.
///
/// # Safety
/// `ctx` is NULL or a live `OSSL_CMP_CTX` returned by [`OSSL_CMP_CTX_new`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_free(ctx: *mut OsslCmpCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live; each field is NULL or owned by the context.
    unsafe {
        CRYPTO_free((*ctx).propq.cast(), FILE.as_ptr(), 196);
        CRYPTO_free((*ctx).server_path.cast(), FILE.as_ptr(), 197);
        CRYPTO_free((*ctx).server.cast(), FILE.as_ptr(), 198);
        CRYPTO_free((*ctx).proxy.cast(), FILE.as_ptr(), 199);
        CRYPTO_free((*ctx).no_proxy.cast(), FILE.as_ptr(), 200);

        X509_free((*ctx).srv_cert);
        X509_free((*ctx).validated_srv_cert);
        X509_NAME_free((*ctx).expected_sender);
        X509_STORE_free((*ctx).trusted);
        OSSL_STACK_OF_X509_free((*ctx).untrusted);

        X509_free((*ctx).cert);
        OSSL_STACK_OF_X509_free((*ctx).chain);
        EVP_PKEY_free((*ctx).pkey);
        ASN1_OCTET_STRING_free((*ctx).reference_value);
        if !(*ctx).secret_value.is_null() {
            let len = (*(*ctx).secret_value).length as usize;
            if len > 0 && !(*(*ctx).secret_value).data.is_null() {
                ptr::write_bytes((*(*ctx).secret_value).data, 0, len);
            }
        }
        ASN1_OCTET_STRING_free((*ctx).secret_value);
        EVP_MD_free((*ctx).pbm_owf);

        X509_NAME_free((*ctx).recipient);
        EVP_MD_free((*ctx).digest);
        ASN1_OCTET_STRING_free((*ctx).transaction_id);
        ASN1_OCTET_STRING_free((*ctx).sender_nonce);
        ASN1_OCTET_STRING_free((*ctx).recip_nonce);
        ASN1_OCTET_STRING_free((*ctx).first_sender_nonce);
        itavs_free((*ctx).geninfo_itavs);
        OSSL_STACK_OF_X509_free((*ctx).extra_certs_out);

        EVP_PKEY_free((*ctx).new_pkey);
        X509_NAME_free((*ctx).issuer);
        ASN1_INTEGER_free((*ctx).serial_number);
        X509_NAME_free((*ctx).subject_name);
        OPENSSL_sk_pop_free((*ctx).subject_alt_names, Some(general_name_free_void));
        OPENSSL_sk_pop_free((*ctx).req_extensions, Some(x509_extension_free_void));
        OPENSSL_sk_pop_free((*ctx).policies, Some(policy_free_void));
        X509_free((*ctx).old_cert);
        X509_REQ_free((*ctx).p10_csr.cast());

        itavs_free((*ctx).genm_itavs);

        OPENSSL_sk_pop_free((*ctx).status_string, Some(utf8_string_free_void));
        X509_free((*ctx).new_cert);
        OSSL_STACK_OF_X509_free((*ctx).new_chain);
        OSSL_STACK_OF_X509_free((*ctx).ca_pubs);
        OSSL_STACK_OF_X509_free((*ctx).extra_certs_in);

        CRYPTO_free(ctx.cast(), FILE.as_ptr(), 244);
    }
}

/// `int OSSL_CMP_CTX_reinit(OSSL_CMP_CTX *ctx)` — `cmp_ctx.c:152-182`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_reinit(ctx: *mut OsslCmpCtx) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        if !(*ctx).http_ctx.is_null() {
            crate::http::http_client::OSSL_HTTP_close((*ctx).http_ctx.cast(), 1);
            (*ctx).http_ctx = ptr::null_mut();
        }
        (*ctx).status = crate::cmp::cmp_status::OSSL_CMP_PKISTATUS_unspecified;
        (*ctx).fail_info_code = -1;
        itavs_free((*ctx).genm_itavs);
        (*ctx).genm_itavs = ptr::null_mut();
    }
    // SAFETY: `ctx` is live; each helper accepts NULL and the pointers are valid.
    let ok = unsafe {
        ossl_cmp_ctx_set0_statusString(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set0_newCert(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set1_newChain(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set1_caPubs(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set1_extraCertsIn(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set1_validatedSrvCert(ctx, ptr::null_mut()) != 0
            && ossl_cmp_ctx_set1_first_senderNonce(ctx, ptr::null_mut()) != 0
            && OSSL_CMP_CTX_set1_transactionID(ctx, ptr::null()) != 0
            && OSSL_CMP_CTX_set1_senderNonce(ctx, ptr::null()) != 0
            && ossl_cmp_ctx_set1_recipNonce(ctx, ptr::null()) != 0
    };
    ok as c_int
}

// --- the generated accessors ---

ctx_get0_ptr!(OSSL_CMP_CTX_get0_libctx, libctx);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_trustedStore, trusted);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_untrusted, untrusted);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_statusString, status_string);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_geninfo_ITAVs, geninfo_itavs);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_validatedSrvCert, validated_srv_cert);
ctx_get0_ptr!(OSSL_CMP_CTX_get0_newCert, new_cert);
ctx_get0_ptr!(OSSL_CMP_CTX_get_certConf_cb_arg, cert_conf_cb_arg);
ctx_get0_ptr!(OSSL_CMP_CTX_get_http_cb_arg, http_cb_arg);
ctx_get0_ptr!(OSSL_CMP_CTX_get_transfer_cb_arg, transfer_cb_arg);
ctx_get_int!(OSSL_CMP_CTX_get_status, status);
ctx_get_int!(OSSL_CMP_CTX_get_failInfoCode, fail_info_code);

ctx_set_int!(ossl_cmp_ctx_set_status, status);
ctx_set_int!(ossl_cmp_ctx_set_failInfoCode, fail_info_code);
ctx_set_int!(OSSL_CMP_CTX_set_serverPort, server_port);
ctx_set0_ptr!(OSSL_CMP_CTX_set_certConf_cb_arg, cert_conf_cb_arg);
ctx_set0_ptr!(OSSL_CMP_CTX_set_http_cb_arg, http_cb_arg);
ctx_set0_ptr!(OSSL_CMP_CTX_set_transfer_cb_arg, transfer_cb_arg);

/// `const char *OSSL_CMP_CTX_get0_propq(const OSSL_CMP_CTX *ctx)`.
///
/// # Safety
/// `ctx` is NULL or a live `OSSL_CMP_CTX`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_get0_propq(ctx: *const OsslCmpCtx) -> *const c_char {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return ptr::null();
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).propq }
}

/// Stores a raw callback address in a `CbPtr` field.
macro_rules! cb_to_ptr {
    ($cb:expr) => {
        match $cb {
            Some(f) => f as *const () as *mut c_void,
            None => ptr::null_mut(),
        }
    };
}

/// `int OSSL_CMP_CTX_set_certConf_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_certConf_cb_t cb)`.
///
/// # Safety
/// `ctx` is NULL or live; `cb` is NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set_certConf_cb(
    ctx: *mut OsslCmpCtx,
    cb: OSSL_CMP_certConf_cb_t,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cert_conf_cb = cb_to_ptr!(cb) };
    1
}

/// `int OSSL_CMP_CTX_set_http_cb(OSSL_CMP_CTX *ctx, OSSL_HTTP_bio_cb_t cb)`.
///
/// # Safety
/// `ctx` is NULL or live; `cb` is NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set_http_cb(
    ctx: *mut OsslCmpCtx,
    cb: OSSL_HTTP_bio_cb_t,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).http_cb = cb_to_ptr!(cb) };
    1
}

/// `int OSSL_CMP_CTX_set_transfer_cb(OSSL_CMP_CTX *ctx, OSSL_CMP_transfer_cb_t cb)`.
///
/// # Safety
/// `ctx` is NULL or live; `cb` is NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set_transfer_cb(
    ctx: *mut OsslCmpCtx,
    cb: OSSL_CMP_transfer_cb_t,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).transfer_cb = cb_to_ptr!(cb) };
    1
}

ctx_set1_char!(OSSL_CMP_CTX_set1_proxy, proxy);
ctx_set1_char!(OSSL_CMP_CTX_set1_server, server);
ctx_set1_char!(OSSL_CMP_CTX_set1_no_proxy, no_proxy);
ctx_set1_char!(OSSL_CMP_CTX_set1_serverPath, server_path);

ctx_set1_dup!(
    OSSL_CMP_CTX_set1_recipient,
    recipient,
    x509_name_dup_void,
    x509_name_free_void
);
ctx_set1_dup!(
    OSSL_CMP_CTX_set1_expected_sender,
    expected_sender,
    x509_name_dup_void,
    x509_name_free_void
);
ctx_set1_dup!(
    OSSL_CMP_CTX_set1_issuer,
    issuer,
    x509_name_dup_void,
    x509_name_free_void
);
ctx_set1_dup!(
    OSSL_CMP_CTX_set1_subjectName,
    subject_name,
    x509_name_dup_void,
    x509_name_free_void
);
ctx_set1_dup!(
    OSSL_CMP_CTX_set1_serialNumber,
    serial_number,
    asn1_integer_dup_void,
    asn1_integer_free_void
);
ctx_set1_dup!(
    OSSL_CMP_CTX_set1_p10CSR,
    p10_csr,
    x509_req_dup_void,
    x509_req_free_void
);

/// `OSSL_CMP_CTX_set0_trustedStore` — `DEFINE_OSSL_set0(OSSL_CMP_CTX, trusted, X509_STORE)`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set0_trustedStore(
    ctx: *mut OsslCmpCtx,
    val: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        X509_STORE_free((*ctx).trusted);
        (*ctx).trusted = val.cast();
    }
    1
}

/// `ossl_cmp_ctx_set0_statusString` — `DEFINE_OSSL_set0(ossl_cmp_ctx, statusString,
/// OSSL_CMP_PKIFREETEXT)`, crate-internal because `cmp.h` does not declare it.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or transfers ownership.
pub(crate) unsafe extern "C" fn OSSL_CMP_CTX_set0_statusString(
    ctx: *mut OsslCmpCtx,
    val: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        OPENSSL_sk_pop_free((*ctx).status_string, Some(utf8_string_free_void));
        (*ctx).status_string = val.cast();
    }
    1
}

/// `ossl_cmp_ctx_set0_statusString`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or transfers ownership.
pub unsafe extern "C" fn ossl_cmp_ctx_set0_statusString(
    ctx: *mut OsslCmpCtx,
    val: *mut c_void,
) -> c_int {
    // SAFETY: forwards.
    unsafe { OSSL_CMP_CTX_set0_statusString(ctx, val) }
}

/// `ossl_cmp_ctx_set0_newCert` — `DEFINE_OSSL_set0(ossl_cmp_ctx, newCert, X509)`,
/// crate-internal because `cmp.h` does not declare it.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set0_newCert(
    ctx: *mut OsslCmpCtx,
    val: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        X509_free((*ctx).new_cert);
        (*ctx).new_cert = val.cast();
    }
    1
}
/// `ossl_cmp_ctx_set0_newCert`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or transfers ownership.
pub unsafe extern "C" fn ossl_cmp_ctx_set0_newCert(
    ctx: *mut OsslCmpCtx,
    val: *mut c_void,
) -> c_int {
    // SAFETY: forwards.
    unsafe { OSSL_CMP_CTX_set0_newCert(ctx, val) }
}

/// `TYPE _set1_FIELD` for the three X509 stacks — `cmp_ctx.c:460-471`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
unsafe fn set1_certs(
    ctx: *mut OsslCmpCtx,
    field: *mut *mut OpenSslStack,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `field` points at a live field.
    unsafe {
        OSSL_STACK_OF_X509_free(*field);
        *field = ptr::null_mut();
    }
    if !certs.is_null() {
        // SAFETY: `certs` is a live stack.
        let up = unsafe { X509_chain_up_ref(certs) };
        if up.is_null() {
            return 0;
        }
        // SAFETY: `field` is a live out-pointer.
        unsafe { *field = up };
    }
    1
}

/// `ossl_cmp_ctx_set1_newChain`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
pub unsafe extern "C" fn ossl_cmp_ctx_set1_newChain(
    ctx: *mut OsslCmpCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_certs(ctx, ptr::addr_of_mut!((*ctx).new_chain), certs) }
}
/// `ossl_cmp_ctx_set1_extraCertsIn`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
pub unsafe extern "C" fn ossl_cmp_ctx_set1_extraCertsIn(
    ctx: *mut OsslCmpCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_certs(ctx, ptr::addr_of_mut!((*ctx).extra_certs_in), certs) }
}
/// `ossl_cmp_ctx_set1_caPubs`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
pub unsafe extern "C" fn ossl_cmp_ctx_set1_caPubs(
    ctx: *mut OsslCmpCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_certs(ctx, ptr::addr_of_mut!((*ctx).ca_pubs), certs) }
}

/// `OSSL_CMP_CTX_set1_extraCertsOut`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_extraCertsOut(
    ctx: *mut OsslCmpCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_certs(ctx, ptr::addr_of_mut!((*ctx).extra_certs_out), certs) }
}

/// `STACK_OF(X509) *OSSL_CMP_CTX_get1_<FIELD>` — `DEFINE_OSSL_CMP_CTX_get1_certs`.
macro_rules! ctx_get1_certs {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or a live `OSSL_CMP_CTX`."]
        pub unsafe extern "C" fn $f(ctx: *const OsslCmpCtx) -> *mut OpenSslStack {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return ptr::null_mut();
            }
            // SAFETY: `ctx` is live.
            unsafe { X509_chain_up_ref((*ctx).$field) }
        }
    };
}
ctx_get1_certs!(OSSL_CMP_CTX_get1_newChain, new_chain);
ctx_get1_certs!(OSSL_CMP_CTX_get1_extraCertsIn, extra_certs_in);
ctx_get1_certs!(OSSL_CMP_CTX_get1_caPubs, ca_pubs);

/// `OSSL_CMP_CTX_set1_untrusted` — `cmp_ctx.c:63-80`.
///
/// # Safety
/// `ctx` is NULL or live; `certs` is NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_untrusted(
    ctx: *mut OsslCmpCtx,
    certs: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut untrusted: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: the out-pointer and input are valid.
    if unsafe {
        ossl_x509_add_certs_new(
            &mut untrusted,
            certs,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
        )
    } == 0
    {
        // SAFETY: `untrusted` is NULL or a fresh stack.
        unsafe { OSSL_STACK_OF_X509_free(untrusted) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        OSSL_STACK_OF_X509_free((*ctx).untrusted);
        (*ctx).untrusted = untrusted;
    }
    1
}

/// `OSSL_CMP_CTX_set1_referenceValue` — `cmp_ctx.c:417-425`.
///
/// # Safety
/// `ctx` is NULL or live; `ref_` is NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_referenceValue(
    ctx: *mut OsslCmpCtx,
    ref_: *const u8,
    len: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        ossl_cmp_asn1_octet_string_set1_bytes(ptr::addr_of_mut!((*ctx).reference_value), ref_, len)
    }
}

/// `OSSL_CMP_CTX_set1_secretValue` — `cmp_ctx.c:428-445`.
///
/// # Safety
/// `ctx` is NULL or live; `sec` is NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_secretValue(
    ctx: *mut OsslCmpCtx,
    sec: *const u8,
    len: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut secret_value: *mut Asn1String = ptr::null_mut();
    // SAFETY: the out-pointer and input are valid.
    if unsafe { ossl_cmp_asn1_octet_string_set1_bytes(&mut secret_value, sec, len) } != 1 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        if !(*ctx).secret_value.is_null() {
            let l = (*(*ctx).secret_value).length as usize;
            if l > 0 && !(*(*ctx).secret_value).data.is_null() {
                ptr::write_bytes((*(*ctx).secret_value).data, 0, l);
            }
            ASN1_OCTET_STRING_free((*ctx).secret_value);
        }
        (*ctx).secret_value = secret_value;
    }
    1
}

/// `OSSL_CMP_CTX_push0_geninfo_ITAV` — `cmp_ctx.c:512-519`.
///
/// # Safety
/// `ctx` is NULL or live; `itav` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_push0_geninfo_ITAV(
    ctx: *mut OsslCmpCtx,
    itav: *mut CmpItav,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        crate::cmp::cmp_asn::OSSL_CMP_ITAV_push0_stack_item(
            ptr::addr_of_mut!((*ctx).geninfo_itavs),
            itav,
        )
    }
}

/// `OSSL_CMP_CTX_reset_geninfo_ITAVs` — `cmp_ctx.c:521-530`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_reset_geninfo_ITAVs(ctx: *mut OsslCmpCtx) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        itavs_free((*ctx).geninfo_itavs);
        (*ctx).geninfo_itavs = ptr::null_mut();
    }
    1
}

/// `OSSL_CMP_CTX_push0_genm_ITAV` — `cmp_ctx.c:535-542`.
///
/// # Safety
/// `ctx` is NULL or live; `itav` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_push0_genm_ITAV(
    ctx: *mut OsslCmpCtx,
    itav: *mut CmpItav,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        crate::cmp::cmp_asn::OSSL_CMP_ITAV_push0_stack_item(
            ptr::addr_of_mut!((*ctx).genm_itavs),
            itav,
        )
    }
}

/// `OSSL_CMP_CTX_push0_policy` — `cmp_ctx.c:497-509`.
///
/// # Safety
/// `ctx` is NULL or live; `pinfo` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_push0_policy(
    ctx: *mut OsslCmpCtx,
    pinfo: *mut PolicyInfo,
) -> c_int {
    if ctx.is_null() || pinfo.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).policies }.is_null() {
        let pol = CERTIFICATEPOLICIES_new();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).policies = pol };
        if pol.is_null() {
            return 0;
        }
    }
    // SAFETY: `ctx` is live and the stack is live.
    unsafe { OPENSSL_sk_push((*ctx).policies, pinfo.cast()) }
}

/// `OSSL_CMP_CTX_set0_reqExtensions` — `cmp_ctx.c:626-641`.
///
/// # Safety
/// `ctx` is NULL or live; `exts` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set0_reqExtensions(
    ctx: *mut OsslCmpCtx,
    exts: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let nsan = unsafe { OPENSSL_sk_num((*ctx).subject_alt_names) };
    if nsan > 0 && !exts.is_null()
        // SAFETY: `exts` is live.
        && unsafe { X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) } >= 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(102) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        OPENSSL_sk_pop_free((*ctx).req_extensions, Some(x509_extension_free_void));
        (*ctx).req_extensions = exts;
    }
    1
}

/// `OSSL_CMP_CTX_reqExtensions_have_SAN` — `cmp_ctx.c:644-655`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_reqExtensions_have_SAN(ctx: *mut OsslCmpCtx) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return -1;
    }
    // SAFETY: `ctx` is live.
    let exts = unsafe { (*ctx).req_extensions };
    if !exts.is_null()
        // SAFETY: `exts` is live.
        && unsafe { X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1) } >= 0
    {
        1
    } else {
        0
    }
}

/// `OSSL_CMP_CTX_push1_subjectAltName` — `cmp_ctx.c:661-686`.
///
/// # Safety
/// `ctx` is NULL or live; `name` is NULL or live and is duplicated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_push1_subjectAltName(
    ctx: *mut OsslCmpCtx,
    name: *const c_void,
) -> c_int {
    if ctx.is_null() || name.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { OSSL_CMP_CTX_reqExtensions_have_SAN(ctx) } == 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(102) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).subject_alt_names }.is_null() {
        let sk = OPENSSL_sk_new_null();
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).subject_alt_names = sk };
        if sk.is_null() {
            return 0;
        }
    }
    // SAFETY: `name` is live.
    let dup = unsafe { GENERAL_NAME_dup(name.cast()) };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live and the stack is live.
    if unsafe { OPENSSL_sk_push((*ctx).subject_alt_names, dup.cast()) } == 0 {
        // SAFETY: `dup` is live.
        unsafe { GENERAL_NAME_free(dup) };
        return 0;
    }
    1
}

/// `OSSL_CMP_CTX_build_cert_chain` — `cmp_ctx.c:694-718`.
///
/// # Safety
/// `ctx` is NULL or live; `own_trusted` and `candidates` are NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_build_cert_chain(
    ctx: *mut OsslCmpCtx,
    own_trusted: *mut X509Store,
    candidates: *mut OpenSslStack,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe {
        ossl_x509_add_certs_new(
            ptr::addr_of_mut!((*ctx).untrusted),
            candidates,
            X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let chain = unsafe {
        X509_build_chain(
            (*ctx).cert,
            (*ctx).untrusted,
            own_trusted,
            0,
            (*ctx).libctx,
            (*ctx).propq,
        )
    };
    if chain.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(164) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).chain = chain };
    1
}

/// `OSSL_CMP_CTX_set0_newPkey` — `cmp_ctx.c:750-761`.
///
/// # Safety
/// `ctx` is NULL or live; `pkey` is NULL or transfers ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set0_newPkey(
    ctx: *mut OsslCmpCtx,
    priv_: c_int,
    pkey: *mut EvpPkey,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        EVP_PKEY_free((*ctx).new_pkey);
        (*ctx).new_pkey = pkey;
        (*ctx).new_pkey_priv = priv_;
    }
    1
}

/// `OSSL_CMP_CTX_get0_newPkey` — `cmp_ctx.c:765-777`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_get0_newPkey(
    ctx: *const OsslCmpCtx,
    priv_: c_int,
) -> *mut c_void {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe {
        if !(*ctx).new_pkey.is_null() {
            return if priv_ != 0 && (*ctx).new_pkey_priv == 0 {
                ptr::null_mut()
            } else {
                (*ctx).new_pkey.cast()
            };
        }
        if !(*ctx).p10_csr.is_null() {
            return if priv_ != 0 {
                ptr::null_mut()
            } else {
                X509_REQ_get0_pubkey((*ctx).p10_csr.cast()).cast()
            };
        }
        (*ctx).pkey.cast()
    }
}

/// `EVP_PKEY *ossl_cmp_ctx_get0_newPubkey(const OSSL_CMP_CTX *ctx)` — `cmp_ctx.c:779-792`. Internal.
///
/// # Safety
/// `ctx` is NULL or live.
pub unsafe extern "C" fn ossl_cmp_ctx_get0_newPubkey(ctx: *const OsslCmpCtx) -> *mut c_void {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe {
        if !(*ctx).new_pkey.is_null() {
            return (*ctx).new_pkey.cast();
        }
        if !(*ctx).p10_csr.is_null() {
            return X509_REQ_get0_pubkey((*ctx).p10_csr.cast()).cast();
        }
        if !(*ctx).old_cert.is_null() {
            return X509_get0_pubkey((*ctx).old_cert).cast();
        }
        if !(*ctx).cert.is_null() {
            return X509_get0_pubkey((*ctx).cert).cast();
        }
        (*ctx).pkey.cast()
    }
}

/// `DEFINE_OSSL_set1_up_ref(OSSL_CMP_CTX, cert, X509)` — `cmp_ctx.c:579-597,692`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
unsafe fn set1_up_ref_x509(ctx: *mut OsslCmpCtx, field: *mut *mut X509, val: *mut X509) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    if !val.is_null() {
        // SAFETY: `val` is live.
        if unsafe { ossl_x509v3_cache_extensions(val) } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_ctx(147) };
            return 0;
        }
        // SAFETY: `val` is live.
        if unsafe { X509_up_ref(val) } == 0 {
            return 0;
        }
    }
    // SAFETY: `field` is a live out-pointer.
    unsafe {
        X509_free(*field);
        *field = val;
    }
    1
}

/// `OSSL_CMP_CTX_set1_cert`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_cert(ctx: *mut OsslCmpCtx, val: *mut X509) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_up_ref_x509(ctx, ptr::addr_of_mut!((*ctx).cert), val) }
}
/// `OSSL_CMP_CTX_set1_oldCert`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_oldCert(ctx: *mut OsslCmpCtx, val: *mut X509) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_up_ref_x509(ctx, ptr::addr_of_mut!((*ctx).old_cert), val) }
}
/// `OSSL_CMP_CTX_set1_srvCert`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_srvCert(ctx: *mut OsslCmpCtx, val: *mut X509) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_up_ref_x509(ctx, ptr::addr_of_mut!((*ctx).srv_cert), val) }
}
/// `ossl_cmp_ctx_set1_validatedSrvCert`.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
pub unsafe extern "C" fn ossl_cmp_ctx_set1_validatedSrvCert(
    ctx: *mut OsslCmpCtx,
    val: *mut X509,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { set1_up_ref_x509(ctx, ptr::addr_of_mut!((*ctx).validated_srv_cert), val) }
}

/// `OSSL_CMP_CTX_set1_pkey` — the `EVP_PKEY` arm, whose `_invalid` predicate is constant 0.
///
/// # Safety
/// `ctx` is NULL or live; `val` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set1_pkey(ctx: *mut OsslCmpCtx, val: *mut EvpPkey) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    if !val.is_null()
        // SAFETY: `val` is live.
        && unsafe { EVP_PKEY_up_ref(val) } == 0
    {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        EVP_PKEY_free((*ctx).pkey);
        (*ctx).pkey = val;
    }
    1
}

/// `DEFINE_set1_ASN1_OCTET_STRING`.
macro_rules! ctx_set1_octet {
    ($f:ident, $field:ident) => {
        #[no_mangle]
        #[doc = ""]
        #[doc = "# Safety"]
        #[doc = "`ctx` is NULL or live; `val` is NULL or live."]
        pub unsafe extern "C" fn $f(ctx: *mut OsslCmpCtx, val: *const Asn1String) -> c_int {
            if ctx.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe { ossl_cmp_asn1_octet_string_set1(ptr::addr_of_mut!((*ctx).$field), val) }
        }
    };
}
ctx_set1_octet!(OSSL_CMP_CTX_set1_transactionID, transaction_id);
ctx_set1_octet!(OSSL_CMP_CTX_set1_senderNonce, sender_nonce);
ctx_set1_octet!(ossl_cmp_ctx_set1_recipNonce, recip_nonce);
ctx_set1_octet!(ossl_cmp_ctx_set1_first_senderNonce, first_sender_nonce);

/// `int OSSL_CMP_CTX_set_option(OSSL_CMP_CTX *ctx, int opt, int val)` — `cmp_ctx.c:867-976`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set_option(
    ctx: *mut OsslCmpCtx,
    opt: c_int,
    val: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    let min_val = match opt {
        OSSL_CMP_OPT_REVOCATION_REASON => OCSP_REVOKED_STATUS_NOSTATUS,
        OSSL_CMP_OPT_POPO_METHOD => OSSL_CRMF_POPO_NONE,
        _ => 0,
    };
    if val < min_val {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(177) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        match opt {
            OSSL_CMP_OPT_LOG_VERBOSITY => {
                if val > OSSL_CMP_LOG_MAX {
                    raise_ctx(175);
                    return 0;
                }
                (*ctx).log_verbosity = val;
            }
            OSSL_CMP_OPT_IMPLICIT_CONFIRM => (*ctx).implicit_confirm = val,
            OSSL_CMP_OPT_DISABLE_CONFIRM => (*ctx).disable_confirm = val,
            OSSL_CMP_OPT_UNPROTECTED_SEND => (*ctx).unprotected_send = val,
            OSSL_CMP_OPT_UNPROTECTED_ERRORS => (*ctx).unprotected_errors = val,
            OSSL_CMP_OPT_NO_CACHE_EXTRACERTS => (*ctx).no_cache_extra_certs = val,
            OSSL_CMP_OPT_VALIDITY_DAYS => (*ctx).days = val,
            OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT => (*ctx).subject_alt_name_nodefault = val,
            OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL => (*ctx).set_subject_alt_name_critical = val,
            OSSL_CMP_OPT_POLICIES_CRITICAL => (*ctx).set_policies_critical = val,
            OSSL_CMP_OPT_IGNORE_KEYUSAGE => (*ctx).ignore_keyusage = val,
            OSSL_CMP_OPT_POPO_METHOD => {
                if val > OSSL_CRMF_POPO_KEYAGREE {
                    raise_ctx(175);
                    return 0;
                }
                (*ctx).popo_method = val;
            }
            OSSL_CMP_OPT_DIGEST_ALGNID => {
                if cmp_ctx_set_md(ctx, ptr::addr_of_mut!((*ctx).digest), val) == 0 {
                    return 0;
                }
            }
            OSSL_CMP_OPT_OWF_ALGNID => {
                if cmp_ctx_set_md(ctx, ptr::addr_of_mut!((*ctx).pbm_owf), val) == 0 {
                    return 0;
                }
            }
            OSSL_CMP_OPT_MAC_ALGNID => (*ctx).pbm_mac = val,
            OSSL_CMP_OPT_KEEP_ALIVE => (*ctx).keep_alive = val,
            OSSL_CMP_OPT_MSG_TIMEOUT => (*ctx).msg_timeout = val,
            OSSL_CMP_OPT_TOTAL_TIMEOUT => (*ctx).total_timeout = val,
            OSSL_CMP_OPT_USE_TLS => (*ctx).tls_used = val,
            OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR => {
                (*ctx).permit_ta_in_extra_certs_for_ir = val
            }
            OSSL_CMP_OPT_REVOCATION_REASON => {
                if val > OCSP_REVOKED_STATUS_AACOMPROMISE {
                    raise_ctx(175);
                    return 0;
                }
                (*ctx).revocation_reason = val;
            }
            _ => {
                raise_ctx(174);
                return 0;
            }
        }
    }
    1
}

/// `int OSSL_CMP_CTX_get_option(const OSSL_CMP_CTX *ctx, int opt)` — `cmp_ctx.c:982-1036`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_get_option(ctx: *const OsslCmpCtx, opt: c_int) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return -1;
    }
    // SAFETY: `ctx` is live.
    unsafe {
        match opt {
            OSSL_CMP_OPT_LOG_VERBOSITY => (*ctx).log_verbosity,
            OSSL_CMP_OPT_IMPLICIT_CONFIRM => (*ctx).implicit_confirm,
            OSSL_CMP_OPT_DISABLE_CONFIRM => (*ctx).disable_confirm,
            OSSL_CMP_OPT_UNPROTECTED_SEND => (*ctx).unprotected_send,
            OSSL_CMP_OPT_UNPROTECTED_ERRORS => (*ctx).unprotected_errors,
            OSSL_CMP_OPT_NO_CACHE_EXTRACERTS => (*ctx).no_cache_extra_certs,
            OSSL_CMP_OPT_VALIDITY_DAYS => (*ctx).days,
            OSSL_CMP_OPT_SUBJECTALTNAME_NODEFAULT => (*ctx).subject_alt_name_nodefault,
            OSSL_CMP_OPT_SUBJECTALTNAME_CRITICAL => (*ctx).set_subject_alt_name_critical,
            OSSL_CMP_OPT_POLICIES_CRITICAL => (*ctx).set_policies_critical,
            OSSL_CMP_OPT_IGNORE_KEYUSAGE => (*ctx).ignore_keyusage,
            OSSL_CMP_OPT_POPO_METHOD => (*ctx).popo_method,
            OSSL_CMP_OPT_DIGEST_ALGNID => EVP_MD_get_type((*ctx).digest),
            OSSL_CMP_OPT_OWF_ALGNID => EVP_MD_get_type((*ctx).pbm_owf),
            OSSL_CMP_OPT_MAC_ALGNID => (*ctx).pbm_mac,
            OSSL_CMP_OPT_KEEP_ALIVE => (*ctx).keep_alive,
            OSSL_CMP_OPT_MSG_TIMEOUT => (*ctx).msg_timeout,
            OSSL_CMP_OPT_TOTAL_TIMEOUT => (*ctx).total_timeout,
            OSSL_CMP_OPT_USE_TLS => (*ctx).tls_used,
            OSSL_CMP_OPT_PERMIT_TA_IN_EXTRACERTS_FOR_IR => (*ctx).permit_ta_in_extra_certs_for_ir,
            OSSL_CMP_OPT_REVOCATION_REASON => (*ctx).revocation_reason,
            _ => {
                raise_ctx(174);
                -1
            }
        }
    }
}

/// `OSSL_CMP_CTX_set_log_cb` — `cmp_ctx.c:387-403`. Under `OPENSSL_NO_TRACE` the trace-callback
/// registration is compiled out, so this only stores the callback and answers 1.
///
/// # Safety
/// `ctx` is NULL or live; `cb` is NULL or a valid callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_set_log_cb(
    ctx: *mut OsslCmpCtx,
    cb: Option<OSSL_CMP_log_cb_t>,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_ctx(CMP_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).log_cb = cb };
    1
}

/// `void OSSL_CMP_CTX_print_errors(const OSSL_CMP_CTX *ctx)` — `cmp_ctx.c:406-411`.
///
/// # Safety
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CTX_print_errors(ctx: *const OsslCmpCtx) {
    if !ctx.is_null()
        // SAFETY: `ctx` is live.
        && OSSL_CMP_LOG_ERR > unsafe { (*ctx).log_verbosity }
    {
        return;
    }
    // SAFETY: `ctx` is NULL or live.
    let cb = if ctx.is_null() {
        None
    } else {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).log_cb }
    };
    // SAFETY: `cb` is the caller's callback or NULL.
    unsafe { OSSL_CMP_print_errors_cb(cb) };
}

/// `int ossl_cmp_print_log(...)` — `cmp_ctx.c:334-384`, reduced to a single-message helper because
/// the no-trace arm formats through `BIO_vsnprintf` and calls the callback with the result.
///
/// # Safety
/// `ctx` is NULL or live; `msg` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_cmp_print_log(
    level: c_int,
    ctx: *const OsslCmpCtx,
    func: *const c_char,
    file: *const c_char,
    line: c_int,
    msg: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is NULL or live.
    if ctx.is_null() || unsafe { (*ctx).log_cb }.is_none() {
        return 1;
    }
    // SAFETY: `ctx` is live.
    if level > unsafe { (*ctx).log_verbosity } {
        return 1;
    }
    if msg.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live; the callback is the caller's.
    match unsafe { (*ctx).log_cb } {
        Some(cb) => {
            // SAFETY: the arguments are valid.
            unsafe { cb(func, file, line, level, msg) }
        }
        None => 1,
    }
}

/// Keeps the message-engine severity names reachable.
#[allow(dead_code)]
const _LOG_DEBUG: c_int = OSSL_CMP_LOG_DEBUG;
