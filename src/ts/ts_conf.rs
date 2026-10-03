//! `crypto/ts/ts_conf.c` — the `tsa` configuration readers. Phase 12.5.
//!
//! The certificate/key loaders and the sixteen `TS_CONF_set_*` readers that build a `TS_RESP_CTX`
//! from a `CONF` section. `TS_CONF_set_crypto_device` and `TS_CONF_set_default_engine` are the
//! `#ifndef OPENSSL_NO_ENGINE` pair 12.5 withheld and 13.8 transcribes: their body is the
//! `ENGINE_by_id`/`ENGINE_set_default` lookup and installation, landed by 13.1 and 13.2.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::x_info::{X509Info, X509_INFO_free};
use crate::engine::eng_ctrl::ENGINE_ctrl;
use crate::engine::eng_fat::ENGINE_set_default;
use crate::engine::eng_lib::{ENGINE_free, Engine};
use crate::engine::eng_list::ENGINE_by_id;
use crate::evp::digest::EvpMd;
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::pem::pem_info::PEM_X509_INFO_read_bio;
use crate::pem::pem_pkey::PEM_read_bio_PrivateKey;
use crate::pem::pem_xaux::PEM_read_bio_X509_AUX;
use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::sys::{strcmp, strtol};
use crate::runtime::bio::BIO_free;
use crate::runtime::conf::api::_CONF_get_number;
use crate::runtime::conf::lib::NCONF_get_string;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::obj::OBJ_txt2obj;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_utl::{X509V3_conf_free, X509V3_parse_list};
use crate::x509::x509_cmp::X509_add_cert;
use crate::x509::x_x509::X509;

use super::ts_rsp_sign::{
    TS_RESP_CTX_add_flags, TS_RESP_CTX_add_md, TS_RESP_CTX_add_policy, TS_RESP_CTX_set_accuracy,
    TS_RESP_CTX_set_certs, TS_RESP_CTX_set_clock_precision_digits, TS_RESP_CTX_set_def_policy,
    TS_RESP_CTX_set_ess_cert_id_digest, TS_RESP_CTX_set_serial_cb, TS_RESP_CTX_set_signer_cert,
    TS_RESP_CTX_set_signer_digest, TS_RESP_CTX_set_signer_key, TsRespCtx, TsSerialCb,
};
use super::{raise_ts, raise_ts_data};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_conf.c";

/// `BASE_SECTION` — `ts_conf.c:23`.
const BASE_SECTION: &core::ffi::CStr = c"tsa";
/// `ENV_DEFAULT_TSA` — `ts_conf.c:24`.
const ENV_DEFAULT_TSA: &core::ffi::CStr = c"default_tsa";
/// `ENV_SERIAL` — `ts_conf.c:25`.
const ENV_SERIAL: &core::ffi::CStr = c"serial";
/// `ENV_CRYPTO_DEVICE` — `ts_conf.c:26`.
const ENV_CRYPTO_DEVICE: &core::ffi::CStr = c"crypto_device";
/// `ENV_SIGNER_CERT` — `ts_conf.c:27`.
const ENV_SIGNER_CERT: &core::ffi::CStr = c"signer_cert";
/// `ENV_CERTS` — `ts_conf.c:28`.
const ENV_CERTS: &core::ffi::CStr = c"certs";
/// `ENV_SIGNER_KEY` — `ts_conf.c:29`.
const ENV_SIGNER_KEY: &core::ffi::CStr = c"signer_key";
/// `ENV_SIGNER_DIGEST` — `ts_conf.c:30`.
const ENV_SIGNER_DIGEST: &core::ffi::CStr = c"signer_digest";
/// `ENV_DEFAULT_POLICY` — `ts_conf.c:31`.
const ENV_DEFAULT_POLICY: &core::ffi::CStr = c"default_policy";
/// `ENV_OTHER_POLICIES` — `ts_conf.c:32`.
const ENV_OTHER_POLICIES: &core::ffi::CStr = c"other_policies";
/// `ENV_DIGESTS` — `ts_conf.c:33`.
const ENV_DIGESTS: &core::ffi::CStr = c"digests";
/// `ENV_ACCURACY` — `ts_conf.c:34`.
const ENV_ACCURACY: &core::ffi::CStr = c"accuracy";
/// `ENV_ORDERING` — `ts_conf.c:35`.
const ENV_ORDERING: &core::ffi::CStr = c"ordering";
/// `ENV_TSA_NAME` — `ts_conf.c:36`.
const ENV_TSA_NAME: &core::ffi::CStr = c"tsa_name";
/// `ENV_ESS_CERT_ID_CHAIN` — `ts_conf.c:37`.
const ENV_ESS_CERT_ID_CHAIN: &core::ffi::CStr = c"ess_cert_id_chain";
/// `ENV_VALUE_SECS` — `ts_conf.c:38`.
const ENV_VALUE_SECS: &core::ffi::CStr = c"secs";
/// `ENV_VALUE_MILLISECS` — `ts_conf.c:39`.
const ENV_VALUE_MILLISECS: &core::ffi::CStr = c"millisecs";
/// `ENV_VALUE_MICROSECS` — `ts_conf.c:40`.
const ENV_VALUE_MICROSECS: &core::ffi::CStr = c"microsecs";
/// `ENV_CLOCK_PRECISION_DIGITS` — `ts_conf.c:41`.
const ENV_CLOCK_PRECISION_DIGITS: &core::ffi::CStr = c"clock_precision_digits";
/// `ENV_VALUE_YES` — `ts_conf.c:42`.
const ENV_VALUE_YES: &core::ffi::CStr = c"yes";
/// `ENV_VALUE_NO` — `ts_conf.c:43`.
const ENV_VALUE_NO: &core::ffi::CStr = c"no";
/// `ENV_ESS_CERT_ID_ALG` — `ts_conf.c:44`.
const ENV_ESS_CERT_ID_ALG: &core::ffi::CStr = c"ess_cert_id_alg";

/// `TS_TSA_NAME` — `include/openssl/ts.h:232`.
const TS_TSA_NAME: c_int = 0x01;
/// `TS_ORDERING` — `include/openssl/ts.h:235`.
const TS_ORDERING: c_int = 0x02;
/// `TS_ESS_CERT_ID_CHAIN` — `include/openssl/ts.h:242`.
const TS_ESS_CERT_ID_CHAIN: c_int = 0x04;
/// `TS_MAX_CLOCK_PRECISION_DIGITS` — `include/openssl/ts.h:312`.
const TS_MAX_CLOCK_PRECISION_DIGITS: c_long = 6;

/// `ENGINE_METHOD_ALL` — `include/openssl/engine.h:55`, `(unsigned int)0xFFFF`.
const ENGINE_METHOD_ALL: c_uint = 0xFFFF;
/// `ENGINE_CTRL_CHIL_SET_FORKCHECK` — `include/openssl/engine.h:235`, `100`.
const ENGINE_CTRL_CHIL_SET_FORKCHECK: c_int = 100;

/// `TS_R_CANNOT_LOAD_CERT` — `include/openssl/tserr.h`.
const TS_R_CANNOT_LOAD_CERT: c_int = 137;
/// `TS_R_CANNOT_LOAD_KEY` — `include/openssl/tserr.h`.
const TS_R_CANNOT_LOAD_KEY: c_int = 138;
/// `TS_R_VAR_BAD_VALUE` — `include/openssl/tserr.h`.
const TS_R_VAR_BAD_VALUE: c_int = 135;
/// `TS_R_VAR_LOOKUP_FAILURE` — `include/openssl/tserr.h`.
const TS_R_VAR_LOOKUP_FAILURE: c_int = 136;
/// `TS_R_COULD_NOT_SET_ENGINE` — `include/openssl/tserr.h`.
const TS_R_COULD_NOT_SET_ENGINE: c_int = 127;

/// `ts_CONF_lookup_fail(name, tag)` — `ts_conf.c:125-128`.
///
/// # Safety
/// The coordinate is a compile-time constant.
unsafe fn ts_conf_lookup_fail() {
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 127, c"ts_CONF_lookup_fail", TS_R_VAR_LOOKUP_FAILURE) };
}

/// `ts_CONF_invalid(name, tag)` — `ts_conf.c:130-133`.
///
/// # Safety
/// The coordinate is a compile-time constant.
unsafe fn ts_conf_invalid() {
    // SAFETY: a compile-time coordinate.
    unsafe { raise_ts(FILE, 132, c"ts_CONF_invalid", TS_R_VAR_BAD_VALUE) };
}

/// `atoi(s)` — the C library conversion, via the crate's `strtol` shim.
///
/// # Safety
/// `s` is NULL or NUL-terminated.
unsafe fn atoi(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is NUL-terminated.
    unsafe { strtol(s, ptr::null_mut(), 10) as c_int }
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509_INFO_free`.
///
/// # Safety
/// `p` is an `X509_INFO` per the stack's element type.
unsafe extern "C" fn x509_info_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_INFO_free(p.cast()) };
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509V3_conf_free`.
///
/// # Safety
/// `p` is a `CONF_VALUE` per the stack's element type.
unsafe extern "C" fn conf_value_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509V3_conf_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// Certificate and key loading
// ---------------------------------------------------------------------------------------------

/// `X509 *TS_CONF_load_cert(const char *file)` — `ts_conf.c:48-65`.
///
/// # Safety
/// `file` is NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_load_cert(file: *const c_char) -> *mut X509 {
    let mut x: *mut X509 = ptr::null_mut();

    // SAFETY: `file` is NUL-terminated.
    let cert = unsafe { BIO_new_file(file, c"r".as_ptr()) };
    if !cert.is_null() {
        // SAFETY: `cert` is live.
        x = unsafe { PEM_read_bio_X509_AUX(cert, ptr::null_mut(), None, ptr::null_mut()) };
    }
    if x.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 62, c"TS_CONF_load_cert", TS_R_CANNOT_LOAD_CERT) };
    }
    // SAFETY: `cert` is NULL or live.
    unsafe { BIO_free(cert) };
    x
}

/// `STACK_OF(X509) *TS_CONF_load_certs(const char *file)` — `ts_conf.c:67-102`.
///
/// # Safety
/// `file` is NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_load_certs(file: *const c_char) -> *mut OpenSslStack {
    let mut othercerts: *mut OpenSslStack = ptr::null_mut();
    let mut allcerts: *mut OpenSslStack = ptr::null_mut();

    // SAFETY: `file` is NUL-terminated.
    let certs = unsafe { BIO_new_file(file, c"r".as_ptr()) };
    if !certs.is_null() {
        // SAFETY: no preconditions.
        othercerts = OPENSSL_sk_new_null();
        if !othercerts.is_null() {
            // SAFETY: `certs` is live.
            allcerts =
                unsafe { PEM_X509_INFO_read_bio(certs, ptr::null_mut(), None, ptr::null_mut()) };
            // SAFETY: `allcerts` is NULL or live.
            let n = unsafe { OPENSSL_sk_num(allcerts) };
            for i in 0..n {
                // SAFETY: `allcerts` is live and `i` in range.
                let xi = unsafe { OPENSSL_sk_value(allcerts, i) }.cast::<X509Info>();
                // SAFETY: `xi` is live.
                if !unsafe { (*xi).x509 }.is_null() {
                    // SAFETY: `othercerts` and `xi->x509` are live.
                    if unsafe { X509_add_cert(othercerts, (*xi).x509, 0) } == 0 {
                        // SAFETY: `othercerts` is live.
                        unsafe { OSSL_STACK_OF_X509_free(othercerts) };
                        othercerts = ptr::null_mut();
                        break;
                    }
                    // SAFETY: `xi` is live; ownership passes to `othercerts`.
                    unsafe { (*xi).x509 = ptr::null_mut() };
                }
            }
        }
    }
    if othercerts.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 98, c"TS_CONF_load_certs", TS_R_CANNOT_LOAD_CERT) };
    }
    // SAFETY: `allcerts` is NULL or a stack of `X509_INFO`.
    unsafe { OPENSSL_sk_pop_free(allcerts, Some(x509_info_free_void)) };
    // SAFETY: `certs` is NULL or live.
    unsafe { BIO_free(certs) };
    othercerts
}

/// `EVP_PKEY *TS_CONF_load_key(const char *file, const char *pass)` — `ts_conf.c:104-121`.
///
/// # Safety
/// `file`/`pass` are NUL-terminated or `pass` NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_load_key(
    file: *const c_char,
    pass: *const c_char,
) -> *mut crate::evp::pkey::EvpPkey {
    let mut pkey: *mut crate::evp::pkey::EvpPkey = ptr::null_mut();

    // SAFETY: `file` is NUL-terminated.
    let key = unsafe { BIO_new_file(file, c"r".as_ptr()) };
    if !key.is_null() {
        // SAFETY: `key` is live; `pass` is the caller's.
        pkey =
            unsafe { PEM_read_bio_PrivateKey(key, ptr::null_mut(), None, pass.cast_mut().cast()) };
    }
    if pkey.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 118, c"TS_CONF_load_key", TS_R_CANNOT_LOAD_KEY) };
    }
    // SAFETY: `key` is NULL or live.
    unsafe { BIO_free(key) };
    pkey
}

// ---------------------------------------------------------------------------------------------
// Configuration options
// ---------------------------------------------------------------------------------------------

/// `const char *TS_CONF_get_tsa_section(CONF *conf, const char *section)` — `ts_conf.c:135-143`.
///
/// # Safety
/// `conf` is live; `section` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_get_tsa_section(
    conf: *mut Conf,
    section: *const c_char,
) -> *const c_char {
    if section.is_null() {
        // SAFETY: `conf` is live and the two names are static.
        let s = unsafe { NCONF_get_string(conf, BASE_SECTION.as_ptr(), ENV_DEFAULT_TSA.as_ptr()) };
        if s.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_lookup_fail() };
        }
        return s;
    }
    section
}

/// `int TS_CONF_set_serial(CONF *conf, const char *section, TS_serial_cb cb, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:145-159`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_serial(
    conf: *mut Conf,
    section: *const c_char,
    cb: Option<TsSerialCb>,
    ctx: *mut TsRespCtx,
) -> c_int {
    // SAFETY: `conf` and `section` are live.
    let serial = unsafe { NCONF_get_string(conf, section, ENV_SERIAL.as_ptr()) };
    if serial.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_lookup_fail() };
        return 0;
    }
    // SAFETY: `ctx` is live; the CONF string is the callback's data.
    unsafe { TS_RESP_CTX_set_serial_cb(ctx, cb, serial.cast()) };
    1
}

/// `int TS_CONF_set_crypto_device(CONF *conf, const char *section, const char *device)` —
/// `ts_conf.c:163-178`.
///
/// A NULL `device` is read from the section's `crypto_device` entry; when neither is present no
/// engine is installed and the call succeeds. A non-NULL device is handed to
/// [`TS_CONF_set_default_engine`], and a refusal there raises `TS_R_VAR_BAD_VALUE`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `device` is NULL or NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_crypto_device(
    conf: *mut Conf,
    section: *const c_char,
    device: *const c_char,
) -> c_int {
    let mut device = device;

    if device.is_null() {
        // SAFETY: `conf` and `section` are live.
        device = unsafe { NCONF_get_string(conf, section, ENV_CRYPTO_DEVICE.as_ptr()) };
    }

    if !device.is_null()
        // SAFETY: `device` is NUL-terminated.
        && unsafe { TS_CONF_set_default_engine(device) } == 0
    {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        return 0;
    }
    1
}

/// `int TS_CONF_set_default_engine(const char *name)` — `ts_conf.c:180-202`.
///
/// `"builtin"` is accepted without touching the registry. Any other name is looked up with
/// `ENGINE_by_id`; a miss, or an `ENGINE_set_default(e, ENGINE_METHOD_ALL)` refusal, raises
/// `TS_R_COULD_NOT_SET_ENGINE` and answers 0. The `"chil"` arm sets the fork-check control
/// before installing the engine.
///
/// # Safety
/// `name` is NUL-terminated.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_default_engine(name: *const c_char) -> c_int {
    // SAFETY: `name` is NUL-terminated.
    if unsafe { strcmp(name, c"builtin".as_ptr()) } == 0 {
        return 1;
    }

    let mut ret = 0;
    // SAFETY: `name` is NUL-terminated.
    let e: *mut Engine = unsafe { ENGINE_by_id(name) };
    if !e.is_null() {
        // SAFETY: `name` is NUL-terminated.
        if unsafe { strcmp(name, c"chil".as_ptr()) } == 0 {
            // SAFETY: `e` is live; the control takes a scalar and no pointer argument.
            unsafe { ENGINE_ctrl(e, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, ptr::null_mut(), None) };
        }
        // SAFETY: `e` is live.
        if unsafe { ENGINE_set_default(e, ENGINE_METHOD_ALL) } != 0 {
            ret = 1;
        }
    }

    if ret == 0 {
        let mut msg: Vec<u8> = b"engine:".to_vec();
        // SAFETY: `name` is NUL-terminated, as the `strcmp`s above established.
        msg.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes());
        msg.push(0);
        // SAFETY: the coordinate is a compile-time constant and `msg` is NUL-terminated.
        unsafe {
            raise_ts_data(
                FILE,
                198,
                c"TS_CONF_set_default_engine",
                TS_R_COULD_NOT_SET_ENGINE,
                msg.as_ptr().cast(),
            )
        };
    }
    // SAFETY: `e` is NULL or live.
    unsafe { ENGINE_free(e) };
    ret
}

/// `int TS_CONF_set_signer_cert(CONF *conf, const char *section, const char *cert,
/// TS_RESP_CTX *ctx)` — `ts_conf.c:206-228`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `cert` is NULL or NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_signer_cert(
    conf: *mut Conf,
    section: *const c_char,
    cert: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut cert = cert;
    let mut ret = 0;

    if cert.is_null() {
        // SAFETY: `conf` and `section` are live.
        cert = unsafe { NCONF_get_string(conf, section, ENV_SIGNER_CERT.as_ptr()) };
        if cert.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_lookup_fail() };
            return ret;
        }
    }
    // SAFETY: `cert` is NUL-terminated.
    let cert_obj = unsafe { TS_CONF_load_cert(cert) };
    if !cert_obj.is_null() {
        // SAFETY: `ctx` is live and `cert_obj` is live.
        if unsafe { TS_RESP_CTX_set_signer_cert(ctx, cert_obj) } != 0 {
            ret = 1;
        }
    }
    // SAFETY: `cert_obj` is NULL or live.
    unsafe { crate::x509::x_x509::X509_free(cert_obj) };
    ret
}

/// `int TS_CONF_set_certs(CONF *conf, const char *section, const char *certs, TS_RESP_CTX *ctx)`
/// — `ts_conf.c:230-250`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `certs` is NULL or NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_certs(
    conf: *mut Conf,
    section: *const c_char,
    certs: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut certs = certs;
    let mut ret = 0;

    if certs.is_null() {
        // Certificate chain is optional.
        // SAFETY: `conf` and `section` are live.
        certs = unsafe { NCONF_get_string(conf, section, ENV_CERTS.as_ptr()) };
        if certs.is_null() {
            // SAFETY: nothing was allocated.
            return 1;
        }
    }
    // SAFETY: `certs` is NUL-terminated.
    let certs_obj = unsafe { TS_CONF_load_certs(certs) };
    if !certs_obj.is_null() {
        // SAFETY: `ctx` is live and `certs_obj` is live.
        if unsafe { TS_RESP_CTX_set_certs(ctx, certs_obj) } != 0 {
            ret = 1;
        }
    }
    // SAFETY: `certs_obj` is NULL or live.
    unsafe { OSSL_STACK_OF_X509_free(certs_obj) };
    ret
}

/// `int TS_CONF_set_signer_key(CONF *conf, const char *section, const char *key,
/// const char *pass, TS_RESP_CTX *ctx)` — `ts_conf.c:252-273`.
///
/// # Safety
/// `conf` is live; `section`/`pass` are NUL-terminated or NULL; `key` is NULL or NUL-terminated;
/// `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_signer_key(
    conf: *mut Conf,
    section: *const c_char,
    key: *const c_char,
    pass: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut key = key;
    let mut ret = 0;

    if key.is_null() {
        // SAFETY: `conf` and `section` are live.
        key = unsafe { NCONF_get_string(conf, section, ENV_SIGNER_KEY.as_ptr()) };
    }
    if key.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_lookup_fail() };
        return ret;
    }
    // SAFETY: `key`/`pass` are the caller's.
    let key_obj = unsafe { TS_CONF_load_key(key, pass) };
    if !key_obj.is_null() {
        // SAFETY: `ctx` is live and `key_obj` is live.
        if unsafe { TS_RESP_CTX_set_signer_key(ctx, key_obj) } != 0 {
            ret = 1;
        }
    }
    // SAFETY: `key_obj` is NULL or live.
    unsafe { crate::evp::pkey::EVP_PKEY_free(key_obj) };
    ret
}

/// `int TS_CONF_set_signer_digest(CONF *conf, const char *section, const char *md,
/// TS_RESP_CTX *ctx)` — `ts_conf.c:275-297`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `md` is NULL or NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_signer_digest(
    conf: *mut Conf,
    section: *const c_char,
    md: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut md = md;
    let mut ret = 0;

    if md.is_null() {
        // SAFETY: `conf` and `section` are live.
        md = unsafe { NCONF_get_string(conf, section, ENV_SIGNER_DIGEST.as_ptr()) };
    }
    if md.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_lookup_fail() };
        return ret;
    }
    // SAFETY: `md` is NUL-terminated.
    let sign_md = unsafe { EVP_get_digestbyname(md) };
    if sign_md.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        return ret;
    }
    // SAFETY: `ctx` is live.
    if unsafe { TS_RESP_CTX_set_signer_digest(ctx, sign_md) } != 0 {
        ret = 1;
    }
    ret
}

/// `int TS_CONF_set_def_policy(CONF *conf, const char *section, const char *policy,
/// TS_RESP_CTX *ctx)` — `ts_conf.c:299-322`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `policy` is NULL or NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_def_policy(
    conf: *mut Conf,
    section: *const c_char,
    policy: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut policy = policy;
    let mut ret = 0;

    if policy.is_null() {
        // SAFETY: `conf` and `section` are live.
        policy = unsafe { NCONF_get_string(conf, section, ENV_DEFAULT_POLICY.as_ptr()) };
    }
    if policy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_lookup_fail() };
        return ret;
    }
    // SAFETY: `policy` is NUL-terminated.
    let policy_obj = unsafe { OBJ_txt2obj(policy, 0) };
    if policy_obj.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        return ret;
    }
    // SAFETY: `ctx` is live and `policy_obj` is live.
    if unsafe { TS_RESP_CTX_set_def_policy(ctx, policy_obj) } != 0 {
        ret = 1;
    }
    // SAFETY: `policy_obj` is NULL or live.
    unsafe { ASN1_OBJECT_free(policy_obj) };
    ret
}

/// `int TS_CONF_set_policies(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:324-356`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_policies(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut list: *mut OpenSslStack = ptr::null_mut();
    let mut ret = 0;

    // SAFETY: `conf` and `section` are live.
    let policies = unsafe { NCONF_get_string(conf, section, ENV_OTHER_POLICIES.as_ptr()) };

    // If no other policy is specified, that's fine.
    if !policies.is_null() {
        // SAFETY: `policies` is NUL-terminated.
        list = unsafe { X509V3_parse_list(policies) };
        if list.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            // SAFETY: `list` is NULL.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
    }
    // SAFETY: `list` is NULL or live.
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: `list` is live and `i` in range.
        let val = unsafe { OPENSSL_sk_value(list, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live.
        let extval = unsafe {
            if (*val).value.is_null() {
                (*val).name
            } else {
                (*val).value
            }
        };
        // SAFETY: `extval` is NUL-terminated.
        let objtmp = unsafe { OBJ_txt2obj(extval, 0) };
        if objtmp.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            // SAFETY: `list` is NULL or live.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
        // SAFETY: `ctx` is live and `objtmp` is live.
        if unsafe { TS_RESP_CTX_add_policy(ctx, objtmp) } == 0 {
            // SAFETY: `objtmp` is live.
            unsafe { ASN1_OBJECT_free(objtmp) };
            // SAFETY: `list` is NULL or live.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
        // SAFETY: `objtmp` is live.
        unsafe { ASN1_OBJECT_free(objtmp) };
    }

    ret = 1;
    // SAFETY: `list` is NULL or live.
    unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
    ret
}

/// `int TS_CONF_set_digests(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:358-394`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_digests(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut list: *mut OpenSslStack = ptr::null_mut();
    let mut ret = 0;

    // SAFETY: `conf` and `section` are live.
    let digests = unsafe { NCONF_get_string(conf, section, ENV_DIGESTS.as_ptr()) };

    if digests.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_lookup_fail() };
        // SAFETY: `list` is NULL.
        unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
        return ret;
    }
    // SAFETY: `digests` is NUL-terminated.
    list = unsafe { X509V3_parse_list(digests) };
    if list.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        // SAFETY: `list` is NULL.
        unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
        return ret;
    }
    // SAFETY: `list` is live.
    if unsafe { OPENSSL_sk_num(list) } == 0 {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        // SAFETY: `list` is live.
        unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
        return ret;
    }
    // SAFETY: `list` is live.
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: `list` is live and `i` in range.
        let val = unsafe { OPENSSL_sk_value(list, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live.
        let extval = unsafe {
            if (*val).value.is_null() {
                (*val).name
            } else {
                (*val).value
            }
        };
        // SAFETY: `extval` is NUL-terminated.
        let md = unsafe { EVP_get_digestbyname(extval) };
        if md.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            // SAFETY: `list` is live.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
        // SAFETY: `ctx` is live and `md` is live.
        if unsafe { TS_RESP_CTX_add_md(ctx, md) } == 0 {
            // SAFETY: `list` is live.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
    }

    ret = 1;
    // SAFETY: `list` is live.
    unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
    ret
}

/// `int TS_CONF_set_accuracy(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:396-431`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_accuracy(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut list: *mut OpenSslStack = ptr::null_mut();
    let mut ret = 0;
    let mut secs = 0;
    let mut millis = 0;
    let mut micros = 0;

    // SAFETY: `conf` and `section` are live.
    let accuracy = unsafe { NCONF_get_string(conf, section, ENV_ACCURACY.as_ptr()) };

    if !accuracy.is_null() {
        // SAFETY: `accuracy` is NUL-terminated.
        list = unsafe { X509V3_parse_list(accuracy) };
        if list.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            // SAFETY: `list` is NULL.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
    }
    // SAFETY: `list` is NULL or live.
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: `list` is live and `i` in range.
        let val = unsafe { OPENSSL_sk_value(list, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live and its `name` is a static comparison string.
        let is_secs = unsafe { strcmp((*val).name, ENV_VALUE_SECS.as_ptr()) } == 0;
        // SAFETY: as above.
        let is_millis = unsafe { strcmp((*val).name, ENV_VALUE_MILLISECS.as_ptr()) } == 0;
        // SAFETY: as above.
        let is_micros = unsafe { strcmp((*val).name, ENV_VALUE_MICROSECS.as_ptr()) } == 0;
        // SAFETY: `val` is live.
        let value = unsafe { (*val).value };
        if is_secs {
            if !value.is_null() {
                // SAFETY: `value` is NUL-terminated.
                secs = unsafe { atoi(value) };
            }
        } else if is_millis {
            if !value.is_null() {
                // SAFETY: `value` is NUL-terminated.
                millis = unsafe { atoi(value) };
            }
        } else if is_micros {
            if !value.is_null() {
                // SAFETY: `value` is NUL-terminated.
                micros = unsafe { atoi(value) };
            }
        } else {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            // SAFETY: `list` is NULL or live.
            unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
            return ret;
        }
    }
    // SAFETY: `ctx` is live.
    if unsafe { TS_RESP_CTX_set_accuracy(ctx, secs, millis, micros) } != 0 {
        ret = 1;
    }
    // SAFETY: `list` is NULL or live.
    unsafe { OPENSSL_sk_pop_free(list, Some(conf_value_free_void)) };
    ret
}

/// `int TS_CONF_set_clock_precision_digits(const CONF *conf, const char *section,
/// TS_RESP_CTX *ctx)` — `ts_conf.c:433-454`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_clock_precision_digits(
    conf: *const Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: `conf` and `section` are live.
    let digits = unsafe { _CONF_get_number(conf, section, ENV_CLOCK_PRECISION_DIGITS.as_ptr()) };
    if !(0..=TS_MAX_CLOCK_PRECISION_DIGITS).contains(&digits) {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        return ret;
    }

    // SAFETY: `ctx` is live.
    if unsafe { TS_RESP_CTX_set_clock_precision_digits(ctx, digits as u32) } != 0 {
        ret = 1;
    }
    ret
}

/// `ts_CONF_add_flag(CONF *conf, const char *section, const char *field, int flag,
/// TS_RESP_CTX *ctx)` — `ts_conf.c:456-471`.
///
/// # Safety
/// `conf` is live; `section`/`field` are NUL-terminated; `ctx` is live.
unsafe fn ts_conf_add_flag(
    conf: *mut Conf,
    section: *const c_char,
    field: *const c_char,
    flag: c_int,
    ctx: *mut TsRespCtx,
) -> c_int {
    // SAFETY: `conf` and `section`/`field` are live.
    let value = unsafe { NCONF_get_string(conf, section, field) };

    if !value.is_null() {
        // SAFETY: `value` is NUL-terminated and the two names are static.
        let is_yes = unsafe { strcmp(value, ENV_VALUE_YES.as_ptr()) } == 0;
        // SAFETY: as above.
        let is_no = unsafe { strcmp(value, ENV_VALUE_NO.as_ptr()) } == 0;
        if is_yes {
            // SAFETY: `ctx` is live.
            unsafe { TS_RESP_CTX_add_flags(ctx, flag) };
        } else if !is_no {
            // SAFETY: a compile-time coordinate.
            unsafe { ts_conf_invalid() };
            return 0;
        }
    }

    1
}

/// `int TS_CONF_set_ordering(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:473-476`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_ordering(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ts_conf_add_flag(conf, section, ENV_ORDERING.as_ptr(), TS_ORDERING, ctx) }
}

/// `int TS_CONF_set_tsa_name(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:478-481`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_tsa_name(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ts_conf_add_flag(conf, section, ENV_TSA_NAME.as_ptr(), TS_TSA_NAME, ctx) }
}

/// `int TS_CONF_set_ess_cert_id_chain(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:483-488`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_ess_cert_id_chain(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ts_conf_add_flag(
            conf,
            section,
            ENV_ESS_CERT_ID_CHAIN.as_ptr(),
            TS_ESS_CERT_ID_CHAIN,
            ctx,
        )
    }
}

/// `int TS_CONF_set_ess_cert_id_digest(CONF *conf, const char *section, TS_RESP_CTX *ctx)` —
/// `ts_conf.c:490-512`.
///
/// # Safety
/// `conf` is live; `section` is NUL-terminated; `ctx` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_CONF_set_ess_cert_id_digest(
    conf: *mut Conf,
    section: *const c_char,
    ctx: *mut TsRespCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: `conf` and `section` are live.
    let mut md = unsafe { NCONF_get_string(conf, section, ENV_ESS_CERT_ID_ALG.as_ptr()) };

    if md.is_null() {
        md = c"sha256".as_ptr().cast_mut();
    }

    // SAFETY: `md` is NUL-terminated.
    let cert_md: *const EvpMd = unsafe { EVP_get_digestbyname(md) };
    if cert_md.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { ts_conf_invalid() };
        return ret;
    }

    // SAFETY: `ctx` is live.
    if unsafe { TS_RESP_CTX_set_ess_cert_id_digest(ctx, cert_md) } != 0 {
        ret = 1;
    }
    ret
}
