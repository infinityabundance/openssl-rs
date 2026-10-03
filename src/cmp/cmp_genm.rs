//! `crypto/cmp/cmp_genm.c` — the CMP general-message readers. Phase 12.4b.
//!
//! The four `OSSL_CMP_get1_*` readers issue a `genm` request through the client engine and
//! validate the `genp` reply: `caCerts`, `rootCaKeyUpdate` (with its two self-signed-transition
//! checks), `crlUpdate` and `certReqTemplate`. Its `ossl_X509_check[_all]` helpers validate a
//! received certificate's time frame and CA/EE role.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces, non_camel_case_types)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::ptr;

use crate::cmp::cmp_asn::*;
use crate::cmp::cmp_client::OSSL_CMP_exec_GENM_ses;
use crate::cmp::cmp_ctx::{
    OSSL_CMP_CTX_get0_libctx, OSSL_CMP_CTX_get0_propq, OSSL_CMP_CTX_get0_trustedStore,
    OSSL_CMP_CTX_get_status, OSSL_CMP_CTX_push0_genm_ITAV, OsslCmpCtx,
};
use crate::cmp::cmp_util::{ossl_cmp_log_str, OSSL_CMP_LOG_ERR, OSSL_CMP_LOG_WARNING};
use crate::crmf::crmf_asn::CrmfCertTemplate;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_shift,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_purp::X509_get_extension_flags;
use crate::x509::x509_cmp::{
    ossl_x509_add_cert_new, ossl_x509_add_certs_new, X509_add_cert, X509_get_subject_name,
};
use crate::x509::x509_lu::{
    X509Store, X509StoreCtx, X509_STORE_CTX_get0_store, X509_STORE_add_cert, X509_STORE_free,
    X509_STORE_get0_param, X509_STORE_get1_all_certs, X509_STORE_get_verify_cb, X509_STORE_new,
    X509_STORE_set1_param,
};
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x509_set::{X509_get0_notAfter, X509_get0_notBefore, X509_up_ref};
use crate::x509::x509_vfy::{
    X509_STORE_CTX_free, X509_STORE_CTX_get0_chain, X509_STORE_CTX_get0_untrusted,
    X509_STORE_CTX_get_check_issued, X509_STORE_CTX_get_error, X509_STORE_CTX_get_error_depth,
    X509_STORE_CTX_init, X509_STORE_CTX_new_ex, X509_STORE_CTX_set_flags,
    X509_STORE_CTX_set_verify_cb, X509_cmp_timeframe, X509_verify_cert,
};
use crate::x509::x509_vpm::X509VerifyParam;
use crate::x509::x_x509::{X509_dup, X509_free, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_genm.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// `NID_id_it_caCerts`/`_rootCaKeyUpdate`/`_certReqTemplate`/`_crls` — `include/openssl/obj_mac.h`.
const NID_id_it_CACERTS: c_int = 1223;
const NID_id_it_ROOTCAKEYUPDATE: c_int = 1224;
const NID_id_it_CERTREQTEMPLATE: c_int = 1225;
const NID_id_it_CRLS: c_int = 1257;
/// `OSSL_CMP_PKISTATUS_unspecified`/`_request` — `include/openssl/cmp.h.in:205,202`.
const OSSL_CMP_PKISTATUS_UNSPECIFIED: c_int = -1;
const OSSL_CMP_PKISTATUS_REQUEST: c_int = -3;
/// `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` — `include/openssl/x509_vfy.h.in:233`.
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
/// `X509_V_FLAG_CHECK_SS_SIGNATURE` — `include/openssl/x509_vfy.h.in:367`.
const X509_V_FLAG_CHECK_SS_SIGNATURE: c_ulong = 0x4000;
/// `X509_ADD_FLAG_UP_REF`/`_NO_DUP` — `include/openssl/x509.h.in:801,803`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;
/// `EXFLAG_CA`/`EXFLAG_V1` — `include/openssl/x509v3.h`.
const EXFLAG_CA: c_uint = 0x10;
const EXFLAG_V1: c_uint = 0x40;

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CMP,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `static const X509_VERIFY_PARAM *get0_trustedStore_vpm(const OSSL_CMP_CTX *ctx)` —
/// `cmp_genm.c:14-19`.
///
/// # Safety
/// `ctx` is live.
unsafe fn get0_trustedStore_vpm(ctx: *const OsslCmpCtx) -> *const X509VerifyParam {
    // SAFETY: `ctx` is live.
    let ts = unsafe { OSSL_CMP_CTX_get0_trustedStore(ctx) }.cast::<X509Store>();
    if ts.is_null() {
        ptr::null()
    } else {
        // SAFETY: `ts` is live.
        unsafe { X509_STORE_get0_param(ts).cast_const() }
    }
}

/// `static void cert_msg(...)` — `cmp_genm.c:21-32`.
///
/// # Safety
/// `ctx` is live; `cert`/`msg` are live.
unsafe fn cert_msg(
    source: &'static core::ffi::CStr,
    level: c_int,
    ctx: *mut OsslCmpCtx,
    cert: *mut X509,
    msg: &'static core::ffi::CStr,
) {
    // SAFETY: `cert` is live.
    let subj = unsafe { X509_NAME_oneline(X509_get_subject_name(cert), ptr::null_mut(), 0) };
    // SAFETY: `ctx` is live.
    let level_name = if level == OSSL_CMP_LOG_WARNING {
        c"WARN".as_ptr()
    } else {
        c"ERR".as_ptr()
    };
    // SAFETY: `ctx` is live. The two names are NUL-terminated or the empty substitute.
    unsafe {
        ossl_cmp_log_str(
            level,
            ctx,
            c"cert_msg",
            FILE,
            27,
            format_args!(
                "{}:certificate from '{}' with subject '{}' {}",
                std::ffi::CStr::from_ptr(level_name).to_string_lossy(),
                source.to_string_lossy(),
                if subj.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(subj)
                        .to_string_lossy()
                        .into_owned()
                },
                msg.to_string_lossy(),
            ),
        )
    };
    // SAFETY: `subj` is NULL or this call's own.
    unsafe { crate::runtime::mem::CRYPTO_free(subj.cast(), FILE.as_ptr(), 31) };
}

/// `static int ossl_X509_check(OSSL_CMP_CTX *ctx, const char *source, X509 *cert, int type_CA,`
/// `const X509_VERIFY_PARAM *vpm)` — `cmp_genm.c:35-58`.
///
/// # Safety
/// `ctx`/`cert` are live; `vpm` is NULL or live.
unsafe fn ossl_X509_check(
    ctx: *mut OsslCmpCtx,
    source: &'static core::ffi::CStr,
    cert: *mut X509,
    type_ca: c_int,
    vpm: *const X509VerifyParam,
) -> c_int {
    // SAFETY: `cert` is live.
    let ex_flags = unsafe { X509_get_extension_flags(cert) };
    // SAFETY: `cert` is live; `vpm` is NULL or live.
    let res =
        unsafe { X509_cmp_timeframe(vpm, X509_get0_notBefore(cert), X509_get0_notAfter(cert)) };
    let mut ret = c_int::from(res == 0);
    let level = if vpm.is_null() {
        OSSL_CMP_LOG_WARNING
    } else {
        OSSL_CMP_LOG_ERR
    };
    if ret == 0 {
        // SAFETY: `ctx`/`cert` are live.
        unsafe {
            cert_msg(
                source,
                level,
                ctx,
                cert,
                if res > 0 {
                    c"has expired"
                } else {
                    c"not yet valid"
                },
            )
        };
    }
    if type_ca >= 0 && (ex_flags & EXFLAG_V1) == 0 {
        let is_ca = (ex_flags & EXFLAG_CA) != 0;
        if (type_ca != 0) != is_ca {
            // SAFETY: `ctx`/`cert` are live.
            unsafe {
                cert_msg(
                    source,
                    level,
                    ctx,
                    cert,
                    if is_ca {
                        c"is not an EE cert"
                    } else {
                        c"is not a CA cert"
                    },
                )
            };
            ret = 0;
        }
    }
    ret
}

/// `static int ossl_X509_check_all(OSSL_CMP_CTX *ctx, const char *source, STACK_OF(X509) *certs,`
/// `int type_CA, const X509_VERIFY_PARAM *vpm)` — `cmp_genm.c:60-72`.
///
/// # Safety
/// `ctx` is live; `certs` is NULL or a live stack; `vpm` is NULL or live.
unsafe fn ossl_X509_check_all(
    ctx: *mut OsslCmpCtx,
    source: &'static core::ffi::CStr,
    certs: *mut OpenSslStack,
    type_ca: c_int,
    vpm: *const X509VerifyParam,
) -> c_int {
    let mut ret = 1;
    // SAFETY: `certs` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let cert = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `ctx`/`cert` are live.
        let ok = unsafe { ossl_X509_check(ctx, source, cert, type_ca, vpm) };
        ret = c_int::from(ok != 0 && ret != 0);
        i += 1;
    }
    ret
}

/// `static OSSL_CMP_ITAV *get_genm_itav(OSSL_CMP_CTX *ctx, OSSL_CMP_ITAV *req, int expected,`
/// `const char *desc)` — `cmp_genm.c:74-139`.
///
/// # Safety
/// `ctx` is NULL or live; `req` is live and consumed; `desc` is NUL-terminated.
unsafe fn get_genm_itav(
    ctx: *mut OsslCmpCtx,
    req: *mut CmpItav,
    expected: c_int,
    desc: &'static core::ffi::CStr,
) -> *mut CmpItav {
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(82, c"get_genm_itav", CMP_R_NULL_ARGUMENT_R) };
        // SAFETY: `req` is live and owned here.
        unsafe { OSSL_CMP_ITAV_free(req) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    if unsafe { OSSL_CMP_CTX_get_status(ctx) } != OSSL_CMP_PKISTATUS_UNSPECIFIED {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(86, c"get_genm_itav", 191) };
        // SAFETY: `req` is live and owned here.
        unsafe { OSSL_CMP_ITAV_free(req) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx`/`req` are live; ownership of `req` moves into the context.
    if unsafe { OSSL_CMP_CTX_push0_genm_ITAV(ctx, req) } == 0 {
        // SAFETY: `req` is live and owned here.
        unsafe { OSSL_CMP_ITAV_free(req) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    let itavs = unsafe { OSSL_CMP_exec_GENM_ses(ctx) };
    if itavs.is_null() {
        // SAFETY: `ctx` is live.
        if unsafe { OSSL_CMP_CTX_get_status(ctx) } != OSSL_CMP_PKISTATUS_REQUEST {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(97, c"get_genm_itav", 192) };
        }
        return ptr::null_mut();
    }
    // SAFETY: `itavs` is live.
    let n = unsafe { OPENSSL_sk_num(itavs) };
    if n <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(103, c"get_genm_itav", 193) };
        // SAFETY: `itavs` is live and owned here.
        unsafe { OPENSSL_sk_free(itavs) };
        return ptr::null_mut();
    }

    let mut i = 0;
    while i < n {
        // SAFETY: `itavs` is live.
        let itav = unsafe { OPENSSL_sk_shift(itavs) }.cast::<CmpItav>();
        // SAFETY: `itav` is live.
        let obj = unsafe { OSSL_CMP_ITAV_get0_type(itav) };
        // SAFETY: `obj` is live.
        if unsafe { OBJ_obj2nid(obj) } == expected {
            let mut j = i + 1;
            while j < n {
                // SAFETY: `itavs` is live.
                let extra = unsafe { OPENSSL_sk_shift(itavs) }.cast::<CmpItav>();
                // SAFETY: `extra` is live.
                unsafe { OSSL_CMP_ITAV_free(extra) };
                j += 1;
            }
            // SAFETY: `itavs` is live.
            unsafe { OPENSSL_sk_free(itavs) };
            return itav;
        }
        let mut name = [0 as c_char; 128];
        // SAFETY: `obj` is live; `name` is writable.
        if unsafe { OBJ_obj2txt(name.as_mut_ptr(), name.len() as c_int, obj, 0) } < 0 {
            name[0] = 0;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_WARNING,
                ctx,
                c"get_genm_itav",
                FILE,
                127,
                format_args!(
                    "genp contains InfoType '{}' while expecting 'id-it-{}'",
                    if name[0] == 0 {
                        "<unknown>".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(name.as_ptr())
                            .to_string_lossy()
                            .into_owned()
                    },
                    desc.to_string_lossy(),
                ),
            )
        };
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        i += 1;
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cmp(132, c"get_genm_itav", 193) };
    // SAFETY: `itavs` is live and owned here.
    unsafe { OPENSSL_sk_free(itavs) };
    ptr::null_mut()
}

/// `int OSSL_CMP_get1_caCerts(OSSL_CMP_CTX *ctx, STACK_OF(X509) **out)` — `cmp_genm.c:141-179`.
///
/// # Safety
/// `ctx` is NULL or live; `out` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_get1_caCerts(
    ctx: *mut OsslCmpCtx,
    out: *mut *mut OpenSslStack,
) -> c_int {
    if out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(148, c"OSSL_CMP_get1_caCerts", CMP_R_NULL_ARGUMENT_R) };
        return 0;
    }
    // SAFETY: `out` is a writable slot.
    unsafe { *out = ptr::null_mut() };

    // SAFETY: `OSSL_CMP_ITAV_new_caCerts` returns a fresh ITAV or NULL.
    let req = unsafe { OSSL_CMP_ITAV_new_caCerts(ptr::null()) };
    if req.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`req` are live.
    let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_CACERTS, c"caCerts") };
    if itav.is_null() {
        return 0;
    }
    let mut certs: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `itav` is live; `certs` is a writable slot.
    if unsafe { OSSL_CMP_ITAV_get0_caCerts(itav, &mut certs) } == 0 {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    let mut ret = 1;
    if certs.is_null() {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return ret;
    }
    // SAFETY: `ctx` is live; `certs` is live; `vpm` is NULL or live.
    if unsafe { ossl_X509_check_all(ctx, c"genp", certs, 1, get0_trustedStore_vpm(ctx)) } == 0 {
        ret = 0;
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return ret;
    }
    // SAFETY: no preconditions.
    let out_stack = OPENSSL_sk_new_reserve(None, unsafe { OPENSSL_sk_num(certs) });
    // SAFETY: `out` is writable.
    unsafe { *out = out_stack };
    // SAFETY: `out_stack` is NULL or a fresh stack; `certs` is live.
    if out_stack.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        || unsafe {
            ossl_x509_add_certs_new(
                out_stack as *mut *mut OpenSslStack,
                certs,
                X509_ADD_FLAG_UP_REF | X509_ADD_FLAG_NO_DUP,
            )
        } == 0
    {
        // SAFETY: `out_stack` is NULL or a fresh stack.
        unsafe { OSSL_STACK_OF_X509_free(out_stack) };
        // SAFETY: `out` is writable.
        unsafe { *out = ptr::null_mut() };
        ret = 0;
    }
    // SAFETY: `itav` is live.
    unsafe { OSSL_CMP_ITAV_free(itav) };
    ret
}

/// `static int selfsigned_verify_cb(int ok, X509_STORE_CTX *store_ctx)` — `cmp_genm.c:181-221`.
///
/// # Safety
/// `store_ctx` is live.
unsafe extern "C" fn selfsigned_verify_cb(ok: c_int, store_ctx: *mut c_void) -> c_int {
    let store_ctx = store_ctx.cast::<X509StoreCtx>();
    // SAFETY: `store_ctx` is live.
    if ok == 0
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        && unsafe { X509_STORE_CTX_get_error_depth(store_ctx) } == 0
        // SAFETY: `store_ctx` is live.
        && unsafe { X509_STORE_CTX_get_error(store_ctx) } == X509_V_ERROR_DEPTH_ZERO_SELF_SIGNED
    {
        /* in this case, custom chain building */
        // SAFETY: `store_ctx` is live.
        let chain = unsafe { X509_STORE_CTX_get0_chain(store_ctx) };
        // SAFETY: `store_ctx` is live.
        let untrusted = unsafe { X509_STORE_CTX_get0_untrusted(store_ctx) };
        // SAFETY: `store_ctx` is live.
        let check_issued = unsafe { X509_STORE_CTX_get_check_issued(store_ctx) };
        // SAFETY: the gate above ensures the callback is set.
        let check_issued = match check_issued {
            Some(f) => f,
            None => return ok,
        };
        // SAFETY: `chain` is live.
        let mut cert = unsafe { OPENSSL_sk_value(chain, 0) }.cast::<X509>(); /* target cert */
        let mut ok = ok;

        // SAFETY: `untrusted` is NULL or a live stack.
        let n = unsafe { OPENSSL_sk_num(untrusted) };
        let mut i = 0;
        while i < n {
            // SAFETY: `i` is in range.
            cert = unsafe { OPENSSL_sk_value(untrusted, i) }.cast::<X509>();
            // SAFETY: `chain`/`cert` are live.
            if unsafe { X509_add_cert(chain, cert, X509_ADD_FLAG_UP_REF) } == 0 {
                return 0;
            }
            i += 1;
        }

        // SAFETY: `store_ctx` is live.
        let store = unsafe { X509_STORE_CTX_get0_store(store_ctx) };
        // SAFETY: `store` is live.
        let trust = unsafe { X509_STORE_get1_all_certs(store) };
        // SAFETY: `trust` is NULL or a live stack.
        let nt = unsafe { OPENSSL_sk_num(trust) };
        let mut i = 0;
        while i < nt {
            // SAFETY: `i` is in range.
            let issuer = unsafe { OPENSSL_sk_value(trust, i) }.cast::<X509>();
            // SAFETY: `store_ctx`/`cert`/`issuer` are live per the callback's contract.
            if unsafe { check_issued(store_ctx.cast(), cert, issuer) } != 0 {
                // SAFETY: `chain`/`issuer` are live.
                if unsafe { X509_add_cert(chain, issuer, X509_ADD_FLAG_UP_REF) } != 0 {
                    ok = 1;
                }
                break;
            }
            i += 1;
        }
        // SAFETY: `trust` is NULL or this call's own.
        unsafe { OSSL_STACK_OF_X509_free(trust) };
        return ok;
    }
    // SAFETY: `store_ctx` is live.
    let ts = unsafe { X509_STORE_CTX_get0_store(store_ctx) };
    if ts.is_null() {
        return ok;
    }
    // SAFETY: `ts` is live.
    let verify_cb = unsafe { X509_STORE_get_verify_cb(ts) };
    match verify_cb {
        // SAFETY: the callback is the store's own.
        Some(cb) => unsafe { cb(ok, store_ctx.cast()) },
        None => ok,
    }
}

/// `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` — `include/openssl/x509_vfy.h.in:233` (`18`).
const X509_V_ERROR_DEPTH_ZERO_SELF_SIGNED: c_int = 18;

/// `static int verify_ss_cert(OSSL_LIB_CTX *libctx, const char *propq, X509_STORE *ts,`
/// `STACK_OF(X509) *untrusted, X509 *target)` — `cmp_genm.c:224-246`.
///
/// # Safety
/// `ts`/`target` are live; `untrusted` NULL or live.
unsafe fn verify_ss_cert(
    libctx: *mut c_void,
    propq: *const c_char,
    ts: *mut X509Store,
    untrusted: *mut OpenSslStack,
    target: *mut X509,
) -> c_int {
    if ts.is_null() || target.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(232, c"verify_ss_cert", ERR_R_PASSED_NULL_PARAMETER) };
        return 0;
    }
    // SAFETY: `libctx`/`propq` are the caller's.
    let csc = unsafe { X509_STORE_CTX_new_ex(libctx, propq) };
    // SAFETY: `csc` is NULL or live.
    if csc.is_null() || unsafe { X509_STORE_CTX_init(csc, ts, target, untrusted) } == 0 {
        // SAFETY: `csc` is NULL or this call's own.
        unsafe { X509_STORE_CTX_free(csc) };
        return 0;
    }
    // SAFETY: `csc` is live.
    unsafe {
        X509_STORE_CTX_set_flags(csc, X509_V_FLAG_CHECK_SS_SIGNATURE);
        X509_STORE_CTX_set_verify_cb(csc, Some(selfsigned_verify_cb));
    }
    // SAFETY: `csc` is live.
    let ok = unsafe { X509_verify_cert(csc) } > 0;
    // SAFETY: `csc` is this call's own.
    unsafe { X509_STORE_CTX_free(csc) };
    c_int::from(ok)
}

/// `static int verify_ss_cert_trans(...)` — `cmp_genm.c:248-285`.
///
/// # Safety
/// `ctx` is live; the other pointers are NULL or live as described.
unsafe fn verify_ss_cert_trans(
    ctx: *mut OsslCmpCtx,
    trusted: *mut X509,
    trans: *mut X509,
    target: *mut X509,
    desc: &'static core::ffi::CStr,
) -> c_int {
    // SAFETY: `ctx` is live.
    let mut ts = unsafe { OSSL_CMP_CTX_get0_trustedStore(ctx) }.cast::<X509Store>();
    let mut untrusted: *mut OpenSslStack = ptr::null_mut();
    let mut res = 0;

    if !trusted.is_null() {
        // SAFETY: `ts` is NULL or live.
        let vpm: *mut X509VerifyParam = if ts.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
            unsafe { X509_STORE_get0_param(ts) }
        };
        // SAFETY: `X509_STORE_new` returns a fresh store or NULL.
        ts = unsafe { X509_STORE_new() };
        if ts.is_null() {
            return 0;
        }
        // SAFETY: `ts` is live.
        if unsafe { X509_STORE_set1_param(ts, vpm) } == 0
            // SAFETY: `ts`/`trusted` are live.
            || unsafe { X509_STORE_add_cert(ts, trusted) } == 0
        {
            // SAFETY: `ts` is this call's own.
            unsafe { X509_STORE_free(ts) };
            return 0;
        }
    }

    if !trans.is_null()
        // SAFETY: `untrusted` is a writable slot; `trans` is live.
        && unsafe { ossl_x509_add_cert_new(&mut untrusted, trans, X509_ADD_FLAG_UP_REF) } == 0
    {
        // SAFETY: `untrusted` is NULL or this call's own.
        unsafe { OSSL_STACK_OF_X509_free(untrusted) };
        if !trusted.is_null() {
            // SAFETY: `ts` is live.
            unsafe { X509_STORE_free(ts) };
        }
        return 0;
    }

    // SAFETY: `ctx` is live; the others are NULL or live.
    res = unsafe {
        verify_ss_cert(
            OSSL_CMP_CTX_get0_libctx(ctx),
            OSSL_CMP_CTX_get0_propq(ctx),
            ts,
            untrusted,
            target,
        )
    };
    if res == 0 {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_cmp_log_str(
                OSSL_CMP_LOG_ERR,
                ctx,
                c"verify_ss_cert_trans",
                FILE,
                276,
                format_args!(
                    "failed to validate {} certificate received in genp {}",
                    desc.to_string_lossy(),
                    if trusted.is_null() {
                        "using trust store"
                    } else {
                        "with given certificate as trust anchor"
                    },
                ),
            )
        };
    }
    // SAFETY: `untrusted` is NULL or this call's own.
    unsafe { OSSL_STACK_OF_X509_free(untrusted) };
    if !trusted.is_null() {
        // SAFETY: `ts` is live.
        unsafe { X509_STORE_free(ts) };
    }
    res
}

/// `int OSSL_CMP_get1_rootCaKeyUpdate(...)` — `cmp_genm.c:287-346`.
///
/// # Safety
/// `ctx` is NULL or live; `old_with_old` NULL or live; the output slots are writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_get1_rootCaKeyUpdate(
    ctx: *mut OsslCmpCtx,
    old_with_old: *const X509,
    new_with_new: *mut *mut X509,
    new_with_old: *mut *mut X509,
    old_with_new: *mut *mut X509,
) -> c_int {
    if new_with_new.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                296,
                c"OSSL_CMP_get1_rootCaKeyUpdate",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `new_with_new` is a writable slot.
    unsafe { *new_with_new = ptr::null_mut() };

    // SAFETY: `old_with_old` is NULL or live.
    let req = unsafe { OSSL_CMP_ITAV_new_rootCaCert(old_with_old) };
    if req.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`req` are live.
    let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_ROOTCAKEYUPDATE, c"rootCaKeyUpdate") };
    if itav.is_null() {
        return 0;
    }

    let mut old_with_old_copy: *mut X509 = ptr::null_mut();
    let mut my_new_with_old: *mut X509 = ptr::null_mut();
    let mut my_old_with_new: *mut X509 = ptr::null_mut();
    // SAFETY: `itav` is live; the slots are writable.
    if unsafe {
        OSSL_CMP_ITAV_get0_rootCaKeyUpdate(
            itav,
            new_with_new,
            &mut my_new_with_old,
            &mut my_old_with_new,
        )
    } == 0
    {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    /* no root CA cert update available */
    // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
    if unsafe { *new_with_new }.is_null() {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 1;
    }
    // SAFETY: `old_with_old` is NULL or live.
    if !old_with_old.is_null() {
        // SAFETY: `old_with_old` is live.
        old_with_old_copy = unsafe { X509_dup(old_with_old) };
        if old_with_old_copy.is_null() {
            // SAFETY: `itav` is live.
            unsafe { OSSL_CMP_ITAV_free(itav) };
            return 0;
        }
    }
    // SAFETY: `ctx` is live; the certs are NULL or live.
    if unsafe {
        verify_ss_cert_trans(
            ctx,
            old_with_old_copy,
            my_new_with_old,
            *new_with_new,
            c"newWithNew",
        )
    } == 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(319, c"OSSL_CMP_get1_rootCaKeyUpdate", 195) };
        // SAFETY: `itav`/`old_with_old_copy` are NULL or this call's own.
        unsafe {
            OSSL_CMP_ITAV_free(itav);
            X509_free(old_with_old_copy);
        }
        return 0;
    }
    if !old_with_old.is_null()
        && !my_old_with_new.is_null()
        // SAFETY: `ctx` is live.
        && unsafe {
            verify_ss_cert_trans(ctx, *new_with_new, my_old_with_new, old_with_old_copy, c"oldWithOld")
        } == 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(325, c"OSSL_CMP_get1_rootCaKeyUpdate", 195) };
        // SAFETY: the three are NULL or this call's own.
        unsafe {
            OSSL_CMP_ITAV_free(itav);
            X509_free(old_with_old_copy);
        }
        return 0;
    }

    let mut res = 0;
    // SAFETY: `*new_with_new` is live.
    if unsafe { X509_up_ref(*new_with_new) } == 0 {
        // SAFETY: the two are NULL or this call's own.
        unsafe {
            OSSL_CMP_ITAV_free(itav);
            X509_free(old_with_old_copy);
        }
        return 0;
    }
    let mut free_new_with_new = true;
    if !new_with_old.is_null() {
        // SAFETY: `new_with_old` is a writable slot.
        unsafe { *new_with_old = my_new_with_old };
        // SAFETY: `*new_with_old` is NULL or live.
        if !unsafe { *new_with_old }.is_null() {
            // SAFETY: `*new_with_old` is live.
            if unsafe { X509_up_ref(*new_with_old) } == 0 {
                // fall through to the failure tail
            } else {
                free_new_with_new = false;
            }
        }
    }
    let ok_old_with_new = if old_with_new.is_null() {
        true
    } else {
        // SAFETY: `old_with_new` is a writable slot.
        unsafe { *old_with_new = my_old_with_new };
        // SAFETY: `*old_with_new` is NULL or live.
        unsafe { *old_with_new }.is_null() || unsafe { X509_up_ref(*old_with_new) } != 0
    };
    if !ok_old_with_new || free_new_with_new {
        // SAFETY: the enclosing function's `# Safety` section is the contract for these raw pointers.
        if !new_with_old.is_null() && !unsafe { *new_with_old }.is_null() {
            // SAFETY: `*new_with_old` is live.
            unsafe { X509_free(*new_with_old) };
        }
        // SAFETY: `*new_with_new` is live.
        unsafe { X509_free(*new_with_new) };
        res = 0;
    } else {
        res = 1;
    }
    // SAFETY: the two are NULL or this call's own.
    unsafe {
        OSSL_CMP_ITAV_free(itav);
        X509_free(old_with_old_copy);
    }
    res
}

/// `int OSSL_CMP_get1_crlUpdate(OSSL_CMP_CTX *ctx, const X509 *crlcert, const X509_CRL *last_crl,`
/// `X509_CRL **crl)` — `cmp_genm.c:348-406`.
///
/// # Safety
/// `ctx` is NULL or live; `crlcert`/`last_crl` NULL or live; `crl` writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_get1_crlUpdate(
    ctx: *mut OsslCmpCtx,
    crlcert: *const X509,
    last_crl: *const crate::x509::x_crl::X509Crl,
    crl: *mut *mut crate::x509::x_crl::X509Crl,
) -> c_int {
    if crl.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(359, c"OSSL_CMP_get1_crlUpdate", CMP_R_NULL_ARGUMENT_R) };
        return 0;
    }
    // SAFETY: `crl` is a writable slot.
    unsafe { *crl = ptr::null_mut() };

    // SAFETY: `last_crl`/`crlcert` are NULL or live.
    let mut status = unsafe { OSSL_CMP_CRLSTATUS_create(last_crl, crlcert, 1) };
    if status.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(365, c"OSSL_CMP_get1_crlUpdate", 198) };
        return 0;
    }
    // SAFETY: no preconditions.
    let mut list = OPENSSL_sk_new_reserve(None, 1);
    if list.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(369, c"OSSL_CMP_get1_crlUpdate", 198);
            OSSL_CMP_CRLSTATUS_free(status);
        }
        return 0;
    }
    // SAFETY: `list` is live; `status` transfers in.
    if unsafe { OPENSSL_sk_push(list, status.cast()) } == 0 {
        // SAFETY: `status`/`list` are live and owned here.
        unsafe {
            raise_cmp(369, c"OSSL_CMP_get1_crlUpdate", 198);
            OSSL_CMP_CRLSTATUS_free(status);
            OPENSSL_sk_free(list);
        }
        return 0;
    }
    status = ptr::null_mut();

    // SAFETY: `list` transfers into the request.
    let req = unsafe { OSSL_CMP_ITAV_new0_crlStatusList(list) };
    if req.is_null() {
        // SAFETY: `list` is live.
        unsafe { OPENSSL_sk_free(list) };
        return 0;
    }
    list = ptr::null_mut();

    // SAFETY: `ctx`/`req` are live.
    let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_CRLS, c"crl") };
    if itav.is_null() {
        return 0;
    }
    let mut crls: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `itav` is live; `crls` is a writable slot.
    if unsafe { OSSL_CMP_ITAV_get0_crls(itav, &mut crls) } == 0 {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    if crls.is_null() {
        /* no CRL update available */
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 1;
    }
    // SAFETY: `crls` is live.
    if unsafe { OPENSSL_sk_num(crls) } != 1 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(391, c"OSSL_CMP_get1_crlUpdate", 193) };
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    // SAFETY: `crls` is live.
    let first = unsafe { OPENSSL_sk_value(crls, 0) }.cast::<crate::x509::x_crl::X509Crl>();
    // SAFETY: `first` is live.
    if first.is_null() || unsafe { crate::x509::x_crl::X509_CRL_up_ref(first) } == 0 {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    // SAFETY: `crl` is a writable slot.
    unsafe { *crl = first };
    // SAFETY: `itav` is live.
    unsafe { OSSL_CMP_ITAV_free(itav) };
    1
}

/// `int OSSL_CMP_get1_certReqTemplate(...)` — `cmp_genm.c:408-440`.
///
/// # Safety
/// `ctx` is NULL or live; `cert_template` writable; `key_spec` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_get1_certReqTemplate(
    ctx: *mut OsslCmpCtx,
    cert_template: *mut *mut CrmfCertTemplate,
    key_spec: *mut *mut OpenSslStack,
) -> c_int {
    if !key_spec.is_null() {
        // SAFETY: `key_spec` is a writable slot.
        unsafe { *key_spec = ptr::null_mut() };
    }
    if cert_template.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(418, c"OSSL_CMP_get1_certReqTemplate", CMP_R_NULL_ARGUMENT_R) };
        return 0;
    }
    // SAFETY: `cert_template` is a writable slot.
    unsafe { *cert_template = ptr::null_mut() };

    // SAFETY: `OSSL_CMP_ITAV_new0_certReqTemplate` returns a fresh ITAV or NULL.
    let req = unsafe { OSSL_CMP_ITAV_new0_certReqTemplate(ptr::null_mut(), ptr::null_mut()) };
    if req.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(424, c"OSSL_CMP_get1_certReqTemplate", 197) };
        return 0;
    }
    // SAFETY: `ctx`/`req` are live.
    let itav = unsafe { get_genm_itav(ctx, req, NID_id_it_CERTREQTEMPLATE, c"certReqTemplate") };
    if itav.is_null() {
        return 0;
    }
    // SAFETY: `itav` is live; the slots are writable.
    if unsafe { OSSL_CMP_ITAV_get1_certReqTemplate(itav, cert_template, key_spec) } == 0 {
        // SAFETY: `itav` is live.
        unsafe { OSSL_CMP_ITAV_free(itav) };
        return 0;
    }
    // SAFETY: `itav` is live.
    unsafe { OSSL_CMP_ITAV_free(itav) };
    1
}

/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h:91` (`103`).
const CMP_R_NULL_ARGUMENT_R: c_int = 103;
