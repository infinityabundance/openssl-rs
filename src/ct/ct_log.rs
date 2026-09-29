//! `crypto/ct/ct_log.c` — the `CTLOG` object and the `CTLOG_STORE` that holds a log list. Phase
//! 10.14.15's CT layer.
//!
//! `crypto/ct/ct_log.c` is 335 lines and transcribes whole except for one withheld name. It owns
//! the `CTLOG` structure (`crypto/ct/ct_local.h`-adjacent, spelled in `ct_log.c:24-30`), the
//! `CTLOG_STORE` (`:36-40`), the load context `CTLOG_STORE_LOAD_CTX` (`:43-47`), and every
//! lifecycle, accessor and CONF loader.
//!
//! **Withheld by name**: `CTLOG_STORE_load_default_file` (`:161-169`). It consults the
//! `CTLOG_FILE` environment variable and, when that is unset, falls back to `CTLOG_FILE` —
//! `OPENSSLDIR "/ct_log_list.cnf"` (`include/internal/common.h:87`), a compile-time path built from
//! the admitted build's **forensic** `OPENSSLDIR`. The candidate reports `OPENSSLDIR: N/A`
//! (`src/runtime/init.rs:1133`) and the whole directory plane is Phase 16's (`ossl_get_openssldir`,
//! `src/runtime/defaults.rs`), so a transcription would diverge on the default branch — the same
//! class as the four withheld `crypto/x509/x509_def.c` names (`src/x509/x509_def.rs`). The env-only
//! branch is not separately landable without inventing the other.
//!
//! ## The raise sites
//!
//! `crypto/ct/ct_log.c` is not an entry in `gen_err_raise_sites.py`, so its nine coordinates are
//! **declared locally**, their reason values read from `include/openssl/cterr.h` and
//! `include/openssl/err.h.in`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::ct::ct_b64::CTLOG_new_from_base64_ex;
use crate::ct::ct_sct::CT_V1_HASHLEN;
use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::runtime::bio::sys;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::conf::lib::{NCONF_free, NCONF_get_string, NCONF_load, NCONF_new};
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::conf::types::{Conf, ConfMethod};
use crate::runtime::err::err_reasons::{
    CT_R_LOG_CONF_INVALID, CT_R_LOG_CONF_MISSING_DESCRIPTION, CT_R_LOG_CONF_MISSING_KEY,
    CT_R_LOG_KEY_INVALID,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_strndup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::x509::x_pubkey::i2d_PUBKEY;

/// `ERR_LIB_CT` — `include/openssl/err.h.in:115`.
const ERR_LIB_CT: c_int = 50;
/// `ERR_R_EVP_LIB` — `include/openssl/err.h.in:322`, `(ERR_LIB_EVP /* 6 */ | ERR_RFLAG_COMMON)`.
const ERR_R_EVP_LIB: c_int = 6 | (0x2 << 18);

/// One `ct_log.c` raise coordinate, declared locally (see the module doc).
const fn ct_log_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ct/ct_log.c",
        line,
        func,
        lib: ERR_LIB_CT,
        reason,
        dynamic_reason: false,
    }
}

/// `ct_v1_log_id_from_pkey` at `crypto/ct/ct_log.c:83`.
const CT_LOG_83: ErrSite = ct_log_site(83, c"ct_v1_log_id_from_pkey", CT_R_LOG_KEY_INVALID);
/// `ct_v1_log_id_from_pkey` at `crypto/ct/ct_log.c:88`.
const CT_LOG_88: ErrSite = ct_log_site(88, c"ct_v1_log_id_from_pkey", ERR_R_EVP_LIB);
/// `CTLOG_STORE_new_ex` at `crypto/ct/ct_log.c:116`.
const CT_LOG_116: ErrSite = ct_log_site(116, c"CTLOG_STORE_new_ex", ERR_R_CRYPTO_LIB);
/// `ctlog_new_from_conf` at `crypto/ct/ct_log.c:147`.
const CT_LOG_147: ErrSite = ct_log_site(
    147,
    c"ctlog_new_from_conf",
    CT_R_LOG_CONF_MISSING_DESCRIPTION,
);
/// `ctlog_new_from_conf` at `crypto/ct/ct_log.c:153`.
const CT_LOG_153: ErrSite = ct_log_site(153, c"ctlog_new_from_conf", CT_R_LOG_CONF_MISSING_KEY);
/// `ctlog_store_load_log` at `crypto/ct/ct_log.c:209`.
const CT_LOG_209: ErrSite = ct_log_site(209, c"ctlog_store_load_log", ERR_R_CRYPTO_LIB);
/// `CTLOG_STORE_load_file` at `crypto/ct/ct_log.c:229`.
const CT_LOG_229: ErrSite = ct_log_site(229, c"CTLOG_STORE_load_file", CT_R_LOG_CONF_INVALID);
/// `CTLOG_STORE_load_file` at `crypto/ct/ct_log.c:235`.
const CT_LOG_235: ErrSite = ct_log_site(235, c"CTLOG_STORE_load_file", CT_R_LOG_CONF_INVALID);
/// `CTLOG_STORE_load_file` at `crypto/ct/ct_log.c:240`.
const CT_LOG_240: ErrSite = ct_log_site(240, c"CTLOG_STORE_load_file", CT_R_LOG_CONF_INVALID);

/// `struct ctlog_st` — `CTLOG`, from `crypto/ct/ct_log.c:24-30`.
#[repr(C)]
pub struct Ctlog {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
    /// `char *name`.
    pub(crate) name: *mut c_char,
    /// `uint8_t log_id[CT_V1_HASHLEN]`.
    pub(crate) log_id: [u8; CT_V1_HASHLEN],
    /// `EVP_PKEY *public_key`.
    pub(crate) public_key: *mut EvpPkey,
}

const _: () = {
    assert!(core::mem::size_of::<Ctlog>() == 64);
    assert!(core::mem::offset_of!(Ctlog, libctx) == 0);
    assert!(core::mem::offset_of!(Ctlog, propq) == 8);
    assert!(core::mem::offset_of!(Ctlog, name) == 16);
    assert!(core::mem::offset_of!(Ctlog, log_id) == 24);
    assert!(core::mem::offset_of!(Ctlog, public_key) == 56);
};

/// `struct ctlog_store_st` — `CTLOG_STORE`, from `crypto/ct/ct_log.c:36-40`.
#[repr(C)]
pub struct CtlogStore {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
    /// `STACK_OF(CTLOG) *logs`.
    pub(crate) logs: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<CtlogStore>() == 24);
    assert!(core::mem::offset_of!(CtlogStore, libctx) == 0);
    assert!(core::mem::offset_of!(CtlogStore, propq) == 8);
    assert!(core::mem::offset_of!(CtlogStore, logs) == 16);
};

/// `CTLOG_STORE_LOAD_CTX` — `crypto/ct/ct_log.c:43-47`.
#[repr(C)]
struct CtlogStoreLoadCtx {
    /// `CTLOG_STORE *log_store`.
    log_store: *mut CtlogStore,
    /// `CONF *conf`.
    conf: *mut Conf,
    /// `size_t invalid_log_entries`.
    invalid_log_entries: usize,
}

/// `static CTLOG_STORE_LOAD_CTX *ctlog_store_load_ctx_new(void)` — `crypto/ct/ct_log.c:61-66`.
fn ctlog_store_load_ctx_new() -> *mut CtlogStoreLoadCtx {
    CRYPTO_zalloc(core::mem::size_of::<CtlogStoreLoadCtx>(), ptr::null(), 0)
        .cast::<CtlogStoreLoadCtx>()
}

/// `static void ctlog_store_load_ctx_free(CTLOG_STORE_LOAD_CTX *ctx)` — `crypto/ct/ct_log.c:68-71`.
///
/// # Safety
///
/// `ctx` is NULL or a value [`ctlog_store_load_ctx_new`] returned.
unsafe fn ctlog_store_load_ctx_free(ctx: *mut CtlogStoreLoadCtx) {
    // SAFETY: `ctx` is NULL or this unit's own allocation per the contract.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0) };
}

/// `void ctlog_free_void(void *p)` — the `FreeFn` thunk `CTLOG_STORE_free` installs.
///
/// # Safety
///
/// `p` is NULL or a live `CTLOG` the stack owns.
unsafe extern "C" fn ctlog_free_void(p: *mut c_void) {
    // SAFETY: the stack holds `CTLOG *` elements per the contract.
    unsafe { CTLOG_free(p.cast::<Ctlog>()) };
}

/// `static int ct_v1_log_id_from_pkey(CTLOG *log, EVP_PKEY *pkey)` — `crypto/ct/ct_log.c:74-98`.
///
/// # Safety
///
/// `log` is a live `CTLOG`; `pkey` is a live `EVP_PKEY`.
unsafe fn ct_v1_log_id_from_pkey(log: *mut Ctlog, pkey: *mut EvpPkey) -> c_int {
    let mut ret: c_int = 0;
    let mut pkey_der: *mut c_uchar = ptr::null_mut();
    // SAFETY: `pkey` is live per the contract; `pkey_der` is an out-slot.
    let pkey_der_len = unsafe { i2d_PUBKEY(pkey, &mut pkey_der) };
    let mut len: c_uint = 0;
    let mut sha256: *mut EvpMd = ptr::null_mut();

    'blk: {
        if pkey_der_len <= 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_LOG_83) };
            break 'blk;
        }
        // SAFETY: `log` is live per the contract.
        sha256 = unsafe { EVP_MD_fetch((*log).libctx, c"SHA2-256".as_ptr(), (*log).propq) };
        if sha256.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_LOG_88) };
            break 'blk;
        }

        // SAFETY: `pkey_der` is readable for `pkey_der_len` bytes; `log->log_id` is a 32-byte
        // buffer the digest writes exactly.
        ret = unsafe {
            EVP_Digest(
                pkey_der.cast::<c_void>(),
                pkey_der_len as usize,
                (*log).log_id.as_mut_ptr(),
                &mut len,
                sha256,
                ptr::null_mut(),
            )
        };
    }

    // SAFETY: `sha256` is NULL or the fetched digest this call owns.
    unsafe { EVP_MD_free(sha256) };
    // SAFETY: `pkey_der` is NULL or the encoder's block.
    unsafe { CRYPTO_free(pkey_der.cast::<c_void>(), ptr::null(), 0) };
    ret
}

/// `CTLOG_STORE *CTLOG_STORE_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ct/ct_log.c:100-124`.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_STORE_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CtlogStore {
    let ret =
        CRYPTO_zalloc(core::mem::size_of::<CtlogStore>(), ptr::null(), 0).cast::<CtlogStore>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` is a fresh zeroed allocation; `libctx` is a pointer value.
    unsafe { (*ret).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
        if propq_copy.is_null() {
            // SAFETY: `ret` is the allocation this call owns.
            unsafe { CTLOG_STORE_free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: `ret` is live; `propq_copy` is the copy this call owns.
        unsafe { (*ret).propq = propq_copy };
    }

    // `OPENSSL_sk_new_null` answers NULL or a live stack.
    let logs = OPENSSL_sk_new_null();
    // SAFETY: `ret` is live and its `logs` field is a writable slot.
    unsafe { (*ret).logs = logs };
    if logs.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_116) };
        // SAFETY: `ret` is the allocation this call owns.
        unsafe { CTLOG_STORE_free(ret) };
        return ptr::null_mut();
    }

    ret
}

/// `CTLOG_STORE *CTLOG_STORE_new(void)` — `crypto/ct/ct_log.c:126-129`.
#[no_mangle]
pub extern "C" fn CTLOG_STORE_new() -> *mut CtlogStore {
    // SAFETY: both arguments are NULL, which the constructor accepts.
    unsafe { CTLOG_STORE_new_ex(ptr::null_mut(), ptr::null()) }
}

/// `void CTLOG_STORE_free(CTLOG_STORE *store)` — `crypto/ct/ct_log.c:131-138`.
///
/// # Safety
///
/// `store` is NULL or a live `CTLOG_STORE` this crate owns and that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_STORE_free(store: *mut CtlogStore) {
    if store.is_null() {
        return;
    }
    // SAFETY: `store` is live per the contract; each field is NULL or owned.
    unsafe {
        CRYPTO_free((*store).propq.cast::<c_void>(), ptr::null(), 0);
        OPENSSL_sk_pop_free((*store).logs, Some(ctlog_free_void));
        CRYPTO_free(store.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `static int ctlog_new_from_conf(CTLOG_STORE *store, CTLOG **ct_log, const CONF *conf, const char
/// *section)` — `crypto/ct/ct_log.c:140-159`.
///
/// # Safety
///
/// `store` is a live `CTLOG_STORE`; `ct_log` is a writable slot; `conf` is a live `CONF`; `section`
/// is NUL-terminated.
unsafe fn ctlog_new_from_conf(
    store: *mut CtlogStore,
    ct_log: *mut *mut Ctlog,
    conf: *const Conf,
    section: *const c_char,
) -> c_int {
    // SAFETY: `conf` and `section` are live per the contract.
    let description = unsafe { NCONF_get_string(conf, section, c"description".as_ptr()) };
    if description.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_147) };
        return 0;
    }

    // SAFETY: `conf` and `section` are live per the contract.
    let pkey_base64 = unsafe { NCONF_get_string(conf, section, c"key".as_ptr()) };
    if pkey_base64.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_153) };
        return 0;
    }

    // SAFETY: `store` is live; the three strings are NUL-terminated; `ct_log` is a writable slot.
    unsafe {
        CTLOG_new_from_base64_ex(
            ct_log,
            pkey_base64,
            description,
            (*store).libctx,
            (*store).propq,
        )
    }
}

/// `static int ctlog_store_load_log(const char *log_name, int log_name_len, void *arg)` —
/// `crypto/ct/ct_log.c:177-213`.
///
/// # Safety
///
/// `log_name` is NULL or readable for `log_name_len` bytes; `arg` is a live
/// [`CtlogStoreLoadCtx`].
unsafe extern "C" fn ctlog_store_load_log(
    log_name: *const c_char,
    log_name_len: c_int,
    arg: *mut c_void,
) -> c_int {
    let load_ctx = arg.cast::<CtlogStoreLoadCtx>();
    let mut ct_log: *mut Ctlog = ptr::null_mut();

    // log_name will be NULL for empty list entries.
    if log_name.is_null() {
        return 1;
    }

    // SAFETY: `log_name` is readable for `log_name_len` bytes per the contract.
    let tmp = unsafe { CRYPTO_strndup(log_name, log_name_len as usize, ptr::null(), 0) };
    if tmp.is_null() {
        return -1;
    }

    // SAFETY: `load_ctx` is live per the contract; `tmp` is NUL-terminated.
    let ret =
        unsafe { ctlog_new_from_conf((*load_ctx).log_store, &mut ct_log, (*load_ctx).conf, tmp) };
    // SAFETY: `tmp` is the `CRYPTO_strndup` this call owns.
    unsafe { CRYPTO_free(tmp.cast::<c_void>(), ptr::null(), 0) };

    if ret < 0 {
        return ret;
    }
    if ret == 0 {
        // SAFETY: `load_ctx` is live per the contract.
        unsafe { (*load_ctx).invalid_log_entries += 1 };
        return 1;
    }

    // SAFETY: `load_ctx` is live; its `log_store` is live; `ct_log` is live.
    if unsafe { OPENSSL_sk_push((*(*load_ctx).log_store).logs, ct_log.cast::<c_void>()) } == 0 {
        // SAFETY: `ct_log` is the value this call owns until the push succeeds.
        unsafe { CTLOG_free(ct_log) };
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_209) };
        return -1;
    }
    1
}

/// `int CTLOG_STORE_load_file(CTLOG_STORE *store, const char *file)` —
/// `crypto/ct/ct_log.c:215-249`.
///
/// # Safety
///
/// `store` is a live `CTLOG_STORE`; `file` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_STORE_load_file(
    store: *mut CtlogStore,
    file: *const c_char,
) -> c_int {
    let mut ret: c_int = 0;
    let load_ctx = ctlog_store_load_ctx_new();

    if load_ctx.is_null() {
        return 0;
    }
    // SAFETY: `load_ctx` is live per the constructor.
    unsafe {
        (*load_ctx).log_store = store;
        (*load_ctx).conf = NCONF_new(ptr::null_mut::<ConfMethod>());
    }
    // SAFETY: `load_ctx` is live.
    if unsafe { (*load_ctx).conf }.is_null() {
        // SAFETY: `load_ctx` is live; `conf` is NULL.
        unsafe { NCONF_free((*load_ctx).conf) };
        // SAFETY: `load_ctx` is this call's allocation.
        unsafe { ctlog_store_load_ctx_free(load_ctx) };
        return ret;
    }

    // SAFETY: `load_ctx` is live; `file` is NUL-terminated.
    if unsafe { NCONF_load((*load_ctx).conf, file, ptr::null_mut()) } <= 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_229) };
        // SAFETY: `load_ctx` is live; `conf` is live.
        unsafe { NCONF_free((*load_ctx).conf) };
        // SAFETY: `load_ctx` is this call's allocation.
        unsafe { ctlog_store_load_ctx_free(load_ctx) };
        return ret;
    }

    // SAFETY: `load_ctx` is live; its `conf` is live.
    let enabled_logs =
        unsafe { NCONF_get_string((*load_ctx).conf, ptr::null(), c"enabled_logs".as_ptr()) };
    if enabled_logs.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_235) };
        // SAFETY: `load_ctx` is live; `conf` is live.
        unsafe { NCONF_free((*load_ctx).conf) };
        // SAFETY: `load_ctx` is this call's allocation.
        unsafe { ctlog_store_load_ctx_free(load_ctx) };
        return ret;
    }

    // SAFETY: `enabled_logs` is NUL-terminated; the callback is this unit's; `load_ctx` is live.
    let parsed = unsafe {
        CONF_parse_list(
            enabled_logs,
            b',' as c_int,
            1,
            Some(ctlog_store_load_log),
            load_ctx.cast::<c_void>(),
        )
    };
    // SAFETY: `load_ctx` is live.
    if parsed == 0 || unsafe { (*load_ctx).invalid_log_entries } > 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_240) };
        // SAFETY: `load_ctx` is live; `conf` is live.
        unsafe { NCONF_free((*load_ctx).conf) };
        // SAFETY: `load_ctx` is this call's allocation.
        unsafe { ctlog_store_load_ctx_free(load_ctx) };
        return ret;
    }

    ret = 1;
    // SAFETY: `load_ctx` is live; `conf` is live.
    unsafe { NCONF_free((*load_ctx).conf) };
    // SAFETY: `load_ctx` is this call's allocation.
    unsafe { ctlog_store_load_ctx_free(load_ctx) };
    ret
}

/// `CTLOG *CTLOG_new_ex(EVP_PKEY *public_key, const char *name, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/ct/ct_log.c:256-283`.
///
/// # Safety
///
/// `public_key` is a live `EVP_PKEY` whose ownership passes to the answer; `name` is
/// NUL-terminated; `libctx` is NULL or live; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_new_ex(
    public_key: *mut EvpPkey,
    name: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Ctlog {
    let ret = CRYPTO_zalloc(core::mem::size_of::<Ctlog>(), ptr::null(), 0).cast::<Ctlog>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ret` is a fresh zeroed allocation; `libctx` is a pointer value.
    unsafe { (*ret).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
        if propq_copy.is_null() {
            // SAFETY: `ret` is the allocation this call owns.
            unsafe { CTLOG_free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: `ret` is live; `propq_copy` is the copy this call owns.
        unsafe { (*ret).propq = propq_copy };
    }

    // SAFETY: `name` is NUL-terminated per the contract.
    let name_copy = unsafe { CRYPTO_strdup(name, ptr::null(), 0) };
    if name_copy.is_null() {
        // SAFETY: `ret` is the allocation this call owns.
        unsafe { CTLOG_free(ret) };
        return ptr::null_mut();
    }
    // SAFETY: `ret` is live; `name_copy` is the copy this call owns.
    unsafe { (*ret).name = name_copy };

    // SAFETY: `ret` is live; `public_key` is live per the contract.
    if unsafe { ct_v1_log_id_from_pkey(ret, public_key) } != 1 {
        // SAFETY: `ret` is the allocation this call owns.
        unsafe { CTLOG_free(ret) };
        return ptr::null_mut();
    }

    // SAFETY: `ret` is live; `public_key`'s ownership passes here.
    unsafe { (*ret).public_key = public_key };
    ret
}

/// `CTLOG *CTLOG_new(EVP_PKEY *public_key, const char *name)` — `crypto/ct/ct_log.c:285-288`.
///
/// # Safety
///
/// `public_key` is a live `EVP_PKEY` whose ownership passes to the answer; `name` is
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_new(public_key: *mut EvpPkey, name: *const c_char) -> *mut Ctlog {
    // SAFETY: `public_key` and `name` are live per the contract; the optional args are NULL.
    unsafe { CTLOG_new_ex(public_key, name, ptr::null_mut(), ptr::null()) }
}

/// `void CTLOG_free(CTLOG *log)` — `crypto/ct/ct_log.c:291-299`.
///
/// # Safety
///
/// `log` is NULL or a live `CTLOG` this crate owns and that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_free(log: *mut Ctlog) {
    if log.is_null() {
        return;
    }
    // SAFETY: `log` is live per the contract; each field is NULL or owned.
    unsafe {
        CRYPTO_free((*log).name.cast::<c_void>(), ptr::null(), 0);
        EVP_PKEY_free((*log).public_key);
        CRYPTO_free((*log).propq.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(log.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `const char *CTLOG_get0_name(const CTLOG *log)` — `crypto/ct/ct_log.c:301-304`.
///
/// # Safety
///
/// `log` is a live `CTLOG`.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_get0_name(log: *const Ctlog) -> *const c_char {
    // SAFETY: `log` is live per the contract.
    unsafe { (*log).name }
}

/// `void CTLOG_get0_log_id(const CTLOG *log, const uint8_t **log_id, size_t *log_id_len)` —
/// `crypto/ct/ct_log.c:306-311`.
///
/// # Safety
///
/// `log` is a live `CTLOG`; `log_id` and `log_id_len` are writable.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_get0_log_id(
    log: *const Ctlog,
    log_id: *mut *const u8,
    log_id_len: *mut usize,
) {
    // SAFETY: `log` is live and both out-slots are writable per the contract.
    unsafe {
        *log_id = (*log).log_id.as_ptr();
        *log_id_len = CT_V1_HASHLEN;
    }
}

/// `EVP_PKEY *CTLOG_get0_public_key(const CTLOG *log)` — `crypto/ct/ct_log.c:313-316`.
///
/// # Safety
///
/// `log` is a live `CTLOG`.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_get0_public_key(log: *const Ctlog) -> *mut EvpPkey {
    // SAFETY: `log` is live per the contract.
    unsafe { (*log).public_key }
}

/// `const CTLOG *CTLOG_STORE_get0_log_by_id(const CTLOG_STORE *store, const uint8_t *log_id, size_t
/// log_id_len)` — `crypto/ct/ct_log.c:322-335`.
///
/// # Safety
///
/// `store` is a live `CTLOG_STORE`; `log_id` is readable for `log_id_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_STORE_get0_log_by_id(
    store: *const CtlogStore,
    log_id: *const u8,
    log_id_len: usize,
) -> *const Ctlog {
    // SAFETY: `store` is live per the contract.
    let num = unsafe { OPENSSL_sk_num((*store).logs) };
    let mut i = 0;
    while i < num {
        // SAFETY: `store->logs` is live and `i` is in bounds.
        let log = unsafe { OPENSSL_sk_value((*store).logs, i) }.cast::<Ctlog>();
        // SAFETY: `log` is a live element; both buffers are readable for `log_id_len` bytes.
        if unsafe {
            sys::memcmp(
                (*log).log_id.as_ptr().cast::<c_void>(),
                log_id.cast::<c_void>(),
                log_id_len,
            )
        } == 0
        {
            return log;
        }
        i += 1;
    }
    ptr::null()
}
