//! `crypto/ct/ct_log.c` — the `CTLOG` object and the `CTLOG_STORE` that holds a log list. Phase
//! 10.14.15's CT layer.
//!
//! `crypto/ct/ct_log.c` is 335 lines and **transcribes whole**. It owns
//! the `CTLOG` structure (`crypto/ct/ct_local.h`-adjacent, spelled in `ct_log.c:24-30`), the
//! `CTLOG_STORE` (`:36-40`), the load context `CTLOG_STORE_LOAD_CTX` (`:43-47`), and every
//! lifecycle, accessor and CONF loader.
//!
//! **`CTLOG_STORE_load_default_file`** (`:161-169`) landed with 12.9. It consults the
//! `CTLOG_FILE` environment variable through `ossl_safe_getenv` and, when that is unset, falls
//! back to `CTLOG_FILE` — `OPENSSLDIR "/ct_log_list.cnf"` (`include/internal/common.h:87`). That
//! path is built exactly as `src/x509/x509_def.rs` builds the certificate-area paths: from the
//! build-time `OPENSSL_RS_OPENSSLDIR`, with the empty sentinel when the build configured none, so
//! the default branch answers a path this distribution did not fabricate rather than the admitted
//! build's forensic `OPENSSLDIR`. `ossl_get_openssldir` and the directory plane proper remain
//! Phase 16's.
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

use crate::runtime::owned_buf::OwnedBuf;
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
use crate::runtime::getenv::ossl_safe_getenv;
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

/// `CTLOG_FILE_EVP` — `include/internal/common.h:98`, the environment variable
/// `CTLOG_STORE_load_default_file` reads first (`"CTLOG_FILE"`).
const CTLOG_FILE_EVP: &CStr = c"CTLOG_FILE";

/// `CTLOG_FILE` — `include/internal/common.h:87`, `OPENSSLDIR "/ct_log_list.cnf"`, the default
/// the environment variable overrides.
///
/// Built like `src/x509/x509_def.rs`: the build's `OPENSSL_RS_OPENSSLDIR` appears exactly once
/// and the terminator is appended at compile time, so no allocation is involved and the address
/// is stable. An unset `OPENSSL_RS_OPENSSLDIR` answers the same empty sentinel
/// `X509_get_default_cert_area` does rather than a fabricated path.
fn ctlog_file_c() -> *const c_char {
    match env!("OPENSSL_RS_OPENSSLDIR") {
        "" => c"".as_ptr(),
        _ => match CStr::from_bytes_with_nul(
            concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/ct_log_list.cnf\0").as_bytes(),
        ) {
            Ok(s) => s.as_ptr(),
            Err(_) => c"".as_ptr(),
        },
    }
}

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

// ---------------------------------------------------------------------------------------------
// Ownership of the `CTLOG`/`CTLOG_STORE` records, the load context, the duplicated strings and the
// encoder scratch block
// ---------------------------------------------------------------------------------------------

/// The authority's `*_free` body for one of this file's heap records, without the block release
/// [`OwnedCtx`]'s `Drop` performs. One impl per record type, so the owner runs the right destructor
/// from `Drop` without a `CRYPTO_free` written at any call site.
///
/// # Safety
///
/// An implementer takes on both halves of the contract, because the safe [`OwnedCtx::new_zeroed`]
/// builds the owner and its `Drop` runs the implementer's body through a safe interface:
///
/// * (a) **destructor** -- `destroy_body(ptr)` runs the authority's `*_free` member body **exactly
///   once** for that object; it releases **exactly** the members the object owns (every releaser is
///   the authority's own and accepts the not-yet-set NULL/zero state) and **never** releases the
///   enclosing block, which [`OwnedCtx`]'s `Drop` releases; and
/// * (b) **zero-validity** -- an all-zero block of `Self` is a valid `Self` for which `destroy_body`
///   and every operation the owner performs are sound. This is the obligation the safe
///   [`OwnedCtx::new_zeroed`] leans on: it validates a `CRYPTO_zalloc` block with no caller
///   assertion.
///
/// Breaking (a) lets safe Rust double-release or release the enclosing block; breaking (b) runs
/// `destroy_body` on a value that is not a valid `Self`.
unsafe trait CtxDestroy: Sized {
    /// The authority's `*_free` body, without the block release `Drop` performs.
    ///
    /// # Safety
    ///
    /// `ptr` is a live record this file allocated and has not released.
    unsafe fn destroy_body(ptr: *mut Self);
}

/// An owned one of the file's heap records.
///
/// The block keeps the authority's `#[repr(C)]` layout and its exact `CRYPTO_zalloc` size, but its
/// *ownership* is this type: [`Self::new_zeroed`] allocates it, [`Self::from_raw`] takes back the
/// block the C ABI hands to `CTLOG_free`/`CTLOG_STORE_free`, and `Drop` runs the authority's own free
/// body ([`CtxDestroy::destroy_body`]) followed by its single block release. A Rust `Box` would hide
/// both the release and the caller-installed `CRYPTO_set_mem_functions` hook.
struct OwnedCtx<T: CtxDestroy> {
    ptr: ptr::NonNull<T>,
    file: *const c_char,
    line: c_int,
}

impl<T: CtxDestroy> OwnedCtx<T> {
    /// `CRYPTO_zalloc(size_of::<T>(), file, line)`, or `None` when it answers NULL. The zeroed image
    /// is the authority's own starting state -- every owned member is NULL -- so
    /// [`CtxDestroy::destroy_body`] on it is the authority's own all-empty free.
    fn new_zeroed(file: *const c_char, line: c_int) -> Option<OwnedCtx<T>> {
        let raw = CRYPTO_zalloc(core::mem::size_of::<T>(), file, line).cast::<T>();
        ptr::NonNull::new(raw).map(|ptr| OwnedCtx { ptr, file, line })
    }

    /// The block's address, the C ABI's `CTLOG *`/`CTLOG_STORE *`/`CTLOG_STORE_LOAD_CTX *`.
    fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Reclaim the block the C ABI hands to a `*_free`, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live record this file allocated that `Drop` has not released.
    unsafe fn from_raw(ptr: *mut T, file: *const c_char, line: c_int) -> Option<OwnedCtx<T>> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedCtx { ptr, file, line })
    }

    /// Give up ownership of the record to the C ABI's answer.
    fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl<T: CtxDestroy> Drop for OwnedCtx<T> {
    /// The record's destructor: the authority's own free body followed by its single block release,
    /// through the same allocator seam.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released; `destroy_body` is
        // the authority's own free body and this is the block's single release.
        unsafe {
            T::destroy_body(self.ptr.as_ptr());
            CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), self.file, self.line);
        }
    }
}

/// The authority's `CTLOG_STORE_free` body (`crypto/ct/ct_log.c:131-138`), without the block release
/// [`OwnedCtx`]'s `Drop` performs: the property query and the log stack.
// SAFETY: (a) holds: `destroy_body` is the authority's `CTLOG_STORE_free` body minus the block --
// the property query and the log stack, each releaser NULL-tolerant, never the enclosing block.
// (b) holds: an all-zero store has both members NULL, so the body is the authority's own all-empty
// teardown -- what the safe `OwnedCtx::new_zeroed` leans on.
unsafe impl CtxDestroy for CtlogStore {
    unsafe fn destroy_body(ptr: *mut CtlogStore) {
        // SAFETY: `ptr` is a live record per the trait contract; its `propq` is NULL or this file's
        // `CRYPTO_strdup` block and its `logs` is NULL or a live stack of `CTLOG`.
        unsafe {
            CRYPTO_free((*ptr).propq.cast::<c_void>(), ptr::null(), 0);
            OPENSSL_sk_pop_free((*ptr).logs, Some(ctlog_free_void));
        }
    }
}

/// The authority's `CTLOG_free` body (`crypto/ct/ct_log.c:291-299`), without the block release
/// [`OwnedCtx`]'s `Drop` performs: the name, the key reference and the property query.
// SAFETY: (a) holds: `destroy_body` is the authority's `CTLOG_free` body minus the block -- the
// name, the key reference and the property query, each releaser NULL-tolerant, never the enclosing
// block. (b) holds: an all-zero log has every member NULL, so the body is the authority's own
// all-empty teardown -- what the safe `OwnedCtx::new_zeroed` leans on.
unsafe impl CtxDestroy for Ctlog {
    unsafe fn destroy_body(ptr: *mut Ctlog) {
        // SAFETY: `ptr` is a live record per the trait contract; `name`/`propq` are NULL or this
        // file's `CRYPTO_strdup` blocks and `public_key` is NULL or an owned key.
        unsafe {
            CRYPTO_free((*ptr).name.cast::<c_void>(), ptr::null(), 0);
            EVP_PKEY_free((*ptr).public_key);
            CRYPTO_free((*ptr).propq.cast::<c_void>(), ptr::null(), 0);
        }
    }
}

/// The authority's `ctlog_store_load_ctx_free` body (`crypto/ct/ct_log.c:68-71`) plus the separate
/// `NCONF_free(conf)` every exit of [`CTLOG_STORE_load_file`] performs, without the block release
/// [`OwnedCtx`]'s `Drop` performs.
// SAFETY: (a) holds: `destroy_body` is `ctlog_store_load_ctx_free`'s body (`NCONF_free(conf)`) minus
// the block -- NULL-tolerant, never the enclosing block. (b) holds: an all-zero load context has a
// NULL `conf`, so the body is the authority's own all-empty teardown -- what the safe
// `OwnedCtx::new_zeroed` leans on.
unsafe impl CtxDestroy for CtlogStoreLoadCtx {
    unsafe fn destroy_body(ptr: *mut CtlogStoreLoadCtx) {
        // SAFETY: `ptr` is a live load context per the trait contract; its `conf` is NULL or a live
        // `CONF`.
        unsafe { NCONF_free((*ptr).conf) };
    }
}

/// An owned `char *` allocated through the crate's `CRYPTO_strdup`/`CRYPTO_strndup` seam: a
/// property query, a `CTLOG` name, and the temporary section name.
struct OwnedStr {
    ptr: *mut c_char,
    file: *const c_char,
    line: c_int,
}

impl OwnedStr {
    /// Adopt a `CRYPTO_strdup`/`CRYPTO_strndup` result, or `None` for NULL; `file`/`line` are the
    /// authority's release site for the string.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a NUL-terminated string this unit allocated through the crate's
    /// `CRYPTO_strdup`/`CRYPTO_strndup` seam; the caller owns it and no other owner will release it.
    unsafe fn take(ptr: *mut c_char, file: *const c_char, line: c_int) -> Option<OwnedStr> {
        if ptr.is_null() {
            None
        } else {
            Some(OwnedStr { ptr, file, line })
        }
    }

    /// The string's address, for the consumer that reads it.
    fn as_ptr(&self) -> *const c_char {
        self.ptr
    }

    /// Give up ownership of the string to the record that takes it over.
    fn into_raw(self) -> *mut c_char {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedStr {
    /// The string's single release, through the same seam.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block the seam answered and has not handed out; its single
        // release is the authority's own plain `CRYPTO_free`.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file, self.line) };
    }
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
    // The encoder's block is owned from here; `Drop` is the authority's own tail release.
    // SAFETY: `pkey_der` is NULL or a live block this crate allocated that no one else owns.
    let pkey_der_owner = unsafe { OwnedBuf::adopt_plain_nullable(pkey_der, ptr::null(), 0) };
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
    // `pkey_der_owner`'s `Drop` is the authority's own `OPENSSL_free(pkey_der)`, after `sha256`.
    drop(pkey_der_owner);
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
    let Some(store) = OwnedCtx::<CtlogStore>::new_zeroed(ptr::null(), 0) else {
        return ptr::null_mut();
    };

    // SAFETY: `store.as_ptr()` is a fresh zeroed record; `libctx` is a pointer value.
    unsafe { (*store.as_ptr()).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy =
            unsafe { OwnedStr::take(CRYPTO_strdup(propq, ptr::null(), 0), ptr::null(), 0) };
        // The authority's failure path runs the whole `CTLOG_STORE_free`; the handle's `Drop` is
        // that same release over the partially built record.
        let Some(propq_copy) = propq_copy else {
            return ptr::null_mut();
        };
        // SAFETY: `store` is live.
        unsafe { (*store.as_ptr()).propq = propq_copy.into_raw() };
    }

    // `OPENSSL_sk_new_null` answers NULL or a live stack.
    let logs = OPENSSL_sk_new_null();
    // SAFETY: `store` is live and its `logs` field is a writable slot.
    unsafe { (*store.as_ptr()).logs = logs };
    if logs.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_116) };
        return ptr::null_mut();
    }

    store.into_raw()
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
    // SAFETY: `store` is NULL or a live `CTLOG_STORE` this crate owns and that is not used
    // afterwards; `from_raw` reclaims it and `Drop` runs the authority's own free body and block
    // release.
    drop(unsafe { OwnedCtx::<CtlogStore>::from_raw(store, ptr::null(), 0) });
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
    let tmp = unsafe {
        OwnedStr::take(
            CRYPTO_strndup(log_name, log_name_len as usize, ptr::null(), 0),
            ptr::null(),
            0,
        )
    };
    let Some(tmp) = tmp else {
        return -1;
    };

    // SAFETY: `load_ctx` is live per the contract; `tmp` is NUL-terminated.
    let ret = unsafe {
        ctlog_new_from_conf(
            (*load_ctx).log_store,
            &mut ct_log,
            (*load_ctx).conf,
            tmp.as_ptr(),
        )
    };
    // The authority releases `tmp` right after the lookup; `Drop` is that release.
    drop(tmp);

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
    let ret: c_int = 0;
    // The load context owns its `CONF` and its block; `Drop` is the authority's own
    // `NCONF_free(conf)` + `ctlog_store_load_ctx_free` at every exit, in that order.
    let Some(load_ctx) = OwnedCtx::<CtlogStoreLoadCtx>::new_zeroed(ptr::null(), 0) else {
        return ret;
    };
    // SAFETY: `load_ctx.as_ptr()` is a fresh zeroed load context.
    unsafe {
        (*load_ctx.as_ptr()).log_store = store;
        (*load_ctx.as_ptr()).conf = NCONF_new(ptr::null_mut::<ConfMethod>());
    }
    // SAFETY: `load_ctx` is live.
    if unsafe { (*load_ctx.as_ptr()).conf }.is_null() {
        return ret;
    }

    // SAFETY: `load_ctx` is live; `file` is NUL-terminated.
    if unsafe { NCONF_load((*load_ctx.as_ptr()).conf, file, ptr::null_mut()) } <= 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_229) };
        return ret;
    }

    // SAFETY: `load_ctx` is live; its `conf` is live.
    let enabled_logs = unsafe {
        NCONF_get_string(
            (*load_ctx.as_ptr()).conf,
            ptr::null(),
            c"enabled_logs".as_ptr(),
        )
    };
    if enabled_logs.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_235) };
        return ret;
    }

    // SAFETY: `enabled_logs` is NUL-terminated; the callback is this unit's; `load_ctx` is live.
    let parsed = unsafe {
        CONF_parse_list(
            enabled_logs,
            b',' as c_int,
            1,
            Some(ctlog_store_load_log),
            load_ctx.as_ptr().cast::<c_void>(),
        )
    };
    // SAFETY: `load_ctx` is live.
    if parsed == 0 || unsafe { (*load_ctx.as_ptr()).invalid_log_entries } > 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_LOG_240) };
        return ret;
    }

    1
}

/// `int CTLOG_STORE_load_default_file(CTLOG_STORE *store)` — `crypto/ct/ct_log.c:161-169`.
///
/// The `CTLOG_FILE` environment variable is consulted first, through the secure lookup every
/// `libcrypto` environment read uses; when it is unset the compile-time `CTLOG_FILE`
/// (`OPENSSLDIR "/ct_log_list.cnf"`) is the fallback.
///
/// # Safety
///
/// `store` is a live `CTLOG_STORE`.
#[no_mangle]
pub unsafe extern "C" fn CTLOG_STORE_load_default_file(store: *mut CtlogStore) -> c_int {
    // SAFETY: the literal is NUL-terminated.
    let mut fpath: *const c_char = unsafe { ossl_safe_getenv(CTLOG_FILE_EVP.as_ptr()) };
    if fpath.is_null() {
        fpath = ctlog_file_c();
    }
    // SAFETY: `store` is live per the contract; `fpath` is NUL-terminated.
    unsafe { CTLOG_STORE_load_file(store, fpath) }
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
    let Some(ctlog) = OwnedCtx::<Ctlog>::new_zeroed(ptr::null(), 0) else {
        return ptr::null_mut();
    };

    // SAFETY: `ctlog.as_ptr()` is a fresh zeroed record; `libctx` is a pointer value.
    unsafe { (*ctlog.as_ptr()).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy =
            unsafe { OwnedStr::take(CRYPTO_strdup(propq, ptr::null(), 0), ptr::null(), 0) };
        // The authority's failure path runs the whole `CTLOG_free`; the handle's `Drop` is that
        // same release over the partially built record.
        let Some(propq_copy) = propq_copy else {
            return ptr::null_mut();
        };
        // SAFETY: `ctlog` is live.
        unsafe { (*ctlog.as_ptr()).propq = propq_copy.into_raw() };
    }

    // SAFETY: `name` is NUL-terminated per the contract.
    let name_copy = unsafe { OwnedStr::take(CRYPTO_strdup(name, ptr::null(), 0), ptr::null(), 0) };
    let Some(name_copy) = name_copy else {
        return ptr::null_mut();
    };
    // SAFETY: `ctlog` is live.
    unsafe { (*ctlog.as_ptr()).name = name_copy.into_raw() };

    // SAFETY: `ctlog` is live; `public_key` is live per the contract.
    if unsafe { ct_v1_log_id_from_pkey(ctlog.as_ptr(), public_key) } != 1 {
        return ptr::null_mut();
    }

    // SAFETY: `ctlog` is live; `public_key`'s ownership passes here.
    unsafe { (*ctlog.as_ptr()).public_key = public_key };
    ctlog.into_raw()
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
    // SAFETY: `log` is NULL or a live `CTLOG` this crate owns and that is not used afterwards;
    // `from_raw` reclaims it and `Drop` runs the authority's own free body and block release.
    drop(unsafe { OwnedCtx::<Ctlog>::from_raw(log, ptr::null(), 0) });
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
