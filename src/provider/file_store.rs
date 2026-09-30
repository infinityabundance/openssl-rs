//! Phase 10.16 — `providers/implementations/storemgmt/file_store.c`: the `file:` STORE LOADER
//! the `default` and `base` providers publish as their one `OSSL_OP_STORE` row, plus the two
//! `OSSL_ALGORITHM` tables (`DEFLT_STORES`, `BASE_STORES`) those providers' query arms return.
//!
//! ## What lands, and what is withheld
//!
//! **The whole unit lands; nothing is withheld by name.** Every callee its object leaves
//! undefined is provided by a landed unit: the decoder front doors and chain
//! (`src/decoder_lib.rs`, `src/decoder_meth.rs`, 8.8/8.9 and 10.6), the digest substrate
//! `X509_NAME_hash_ex` reads (`src/x509/x509_cmp.rs`, 10.14.1), the `X509_NAME` object and its
//! printer (`src/x509/x_name.rs` 10.8, `src/x509/x509_obj.rs` 10.10), the directory walk
//! (`src/runtime/dir.rs`), the core-BIO bridge (`src/runtime/bio/core_bio.rs`, the
//! D-PROV-BIO-METHOD-1 divergence the crate already records) and the parameter layer. The
//! `file:` engine's own private last-resort decoder is
//! [`crate::provider::file_store_any2obj`]'s `ossl_any_to_obj_algorithm`, transcribed in the
//! same slice because the two units are one engine: `file_setup_decoders` is the table's only
//! reader.
//!
//! **The engine is real, not a row in front of a stub.** `file_open`/`file_attach` build a
//! `file_ctx_st`, `file_load` drives the decoder chain and hands each object abstraction to the
//! store's callback, `file_eof` reads the BIO, and `file_close` releases the context. The row
//! therefore satisfies `loader_from_algorithm`'s four-clause sanity check (`store_meth.c:241`)
//! with its `open`/`attach`, `load`, `eof` and `close` callbacks, which is what makes
//! `OSSL_STORE_LOADER_fetch`/`do_all_provided` resolve it (D455/D459's refused piece).
//!
//! ## The one divergence, and why it is not the engine's
//!
//! `ossl_bio_new_from_core_bio` is this crate's one-argument bridge
//! (`src/runtime/bio/core_bio.rs:363`): the `OSSL_CORE_BIO` the core hands a provider already
//! wraps the real `BIO`, so the `provctx` first argument the authority's signature takes is not
//! read here either. That is the pre-existing `D-PROV-BIO-METHOD-1` divergence, not this unit's.
//!
//! ## Error coordinates
//!
//! Every `ERR_raise*` below goes through the `err_sites` convention (D442/D444): the generator
//! entry `("providers/implementations/storemgmt/file_store.c", "PROV_FILE_STORE")` derives each
//! coordinate from the authority's own text, and the three `ERR_LIB_SYS` errno sites are
//! `raise_site_dynamic*`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_lib::{
    ossl_decoder_ctx_add_decoder_inst, ossl_decoder_instance_free,
    ossl_decoder_instance_new_forprov, OSSL_DECODER_CTX_add_extra, OSSL_DECODER_CTX_set_cleanup,
    OSSL_DECODER_CTX_set_construct, OSSL_DECODER_CTX_set_construct_data,
    OSSL_DECODER_CTX_set_input_structure, OSSL_DECODER_CTX_set_input_type,
    OSSL_DECODER_INSTANCE_get_input_type, OSSL_DECODER_from_bio,
};
use crate::decoder_meth::{
    ossl_decoder_from_algorithm, DecoderCleanupFn, DecoderConstructFn, OSSL_DECODER_CTX_free,
    OSSL_DECODER_CTX_new, OSSL_DECODER_free, OsslDecoderCtx, OsslDecoderInstance,
};
use crate::decoder_pkey::OSSL_DECODER_CTX_set_passphrase_cb;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string, OsslParam,
    END,
};
use crate::passphrase::OsslPassphraseCallback;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::{ossl_prov_ctx_get0_libctx, ProvCtx};
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys;
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_new_file, Bio, BIO_CTRL_EOF, BIO_CTRL_PENDING,
};
use crate::runtime::dir::{ossl_ends_with_dirsep, stat_is_dir, OpenSslDirCtx};
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, raise_site_dynamic, raise_site_dynamic_data,
    ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strlcat, OPENSSL_strncasecmp};
use crate::selftest::OsslCallback;
use crate::x509::x509_cmp::X509_NAME_hash_ex;
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x_name::{d2i_X509_NAME, X509Name, X509_NAME_free};

// ---------------------------------------------------------------------------
// Constants — `file_store.c`'s own literals and the store/item identities
// ---------------------------------------------------------------------------

/// `#define OSSL_OP_STORE 22` — `include/openssl/core_dispatch.h:297`. The operation id both
/// providers' query arms are keyed on; the final path segment is what the census resolves.
pub(crate) const OSSL_OP_STORE: c_int = 22;

/// `IS_FILE` — `file_store.c:72`. Read file and pass results.
const IS_FILE: c_int = 0;
/// `IS_DIR` — `file_store.c:73`. Pass directory entry names.
const IS_DIR: c_int = 1;

/// `OSSL_STORE_INFO_PUBKEY` — `include/openssl/store.h:159`.
const OSSL_STORE_INFO_PUBKEY: c_int = 3;
/// `OSSL_STORE_INFO_PKEY` — `store.h:160`.
const OSSL_STORE_INFO_PKEY: c_int = 4;
/// `OSSL_STORE_INFO_CERT` — `store.h:161`.
const OSSL_STORE_INFO_CERT: c_int = 5;
/// `OSSL_STORE_INFO_CRL` — `store.h:162`.
const OSSL_STORE_INFO_CRL: c_int = 6;

/// `OSSL_OBJECT_NAME` — `include/openssl/core_object.h:28`.
const OSSL_OBJECT_NAME: c_int = 1;

/// `OSSL_OBJECT_PARAM_TYPE` — `core_names.h:362`, the string `"type"`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();

/// `OSSL_STORE_PARAM_PROPERTIES` — `core_names.h:579`.
const OSSL_STORE_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_STORE_PARAM_EXPECT` — `core_names.h:575`.
const OSSL_STORE_PARAM_EXPECT: *const c_char = c"expect".as_ptr();
/// `OSSL_STORE_PARAM_SUBJECT` — `core_names.h:581`.
const OSSL_STORE_PARAM_SUBJECT: *const c_char = c"subject".as_ptr();
/// `OSSL_STORE_PARAM_INPUT_TYPE` — `core_names.h:577`.
const OSSL_STORE_PARAM_INPUT_TYPE: *const c_char = c"input-type".as_ptr();

/// `ERR_LIB_OSSL_DECODER` — `include/openssl/err.h:123`.
const ERR_LIB_OSSL_DECODER: c_ulong = 60;
/// `ERR_R_UNSUPPORTED` — `err.h:364`: `(268 | ERR_RFLAG_COMMON)`.
const ERR_R_UNSUPPORTED: c_ulong = 268 | (0x2 << 18);

/// `ERR_GET_LIB(r)` — `err.h`. The shift and mask the macro applies.
fn err_get_lib(r: c_ulong) -> c_ulong {
    (r >> 23) & 0xFF
}
/// `ERR_GET_REASON(r)` — `err.h`, the low `ERR_REASON_MASK` bits.
fn err_get_reason(r: c_ulong) -> c_ulong {
    r & 0x7F_FFFF
}

/// The `ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER, "param %s is repeated", s)` the
/// `paramnames.pm` decoders share at each repeated key.
///
/// # Safety
/// `s` must be the NUL-terminated key of a live descriptor.
unsafe fn raise_repeated_param(site: &err_sites::ErrSite, s: *const c_char) {
    let mut msg = [0 as c_char; 256];
    // SAFETY: `msg` is writable for its size and `s` is NUL-terminated.
    unsafe {
        BIO_snprintf(
            msg.as_mut_ptr(),
            msg.len(),
            c"param %s is repeated".as_ptr(),
            s,
        )
    };
    // SAFETY: `site` is a compile-time constant and `msg` is NUL-terminated.
    unsafe { raise_site_data(site, msg.as_ptr()) };
}

// ---------------------------------------------------------------------------
// The context object — `file_store.c:68-126`
// ---------------------------------------------------------------------------

/// The `IS_FILE` arm of the authority's union — `file_store.c:78-84`.
struct FileCtxFile {
    /// `BIO *file`.
    file: *mut Bio,
    /// `OSSL_DECODER_CTX *decoderctx`.
    decoderctx: *mut OsslDecoderCtx,
    /// `char *input_type`.
    input_type: *mut c_char,
    /// `char *propq`.
    propq: *mut c_char,
}

/// The `IS_DIR` arm of the authority's union — `file_store.c:87-105`.
struct FileCtxDir {
    /// `OPENSSL_DIR_CTX *ctx`.
    ctx: *mut OpenSslDirCtx,
    /// `int end_reached`.
    end_reached: c_int,
    /// `char search_name[9]`.
    search_name: [c_char; 9],
    /// `const char *last_entry` — points into the directory context's own buffer.
    last_entry: *const c_char,
    /// `int last_errno`.
    last_errno: c_int,
}

/// `struct file_ctx_st` — `file_store.c:68-112`.
///
/// **The authority's union is a pair of structs here.** The union is an internal layout choice
/// (its `type` tag selects the arm and the object never crosses the ABI), so the two arms are
/// separate fields rather than a `union`; every read and write in this unit goes through the
/// `type_` test exactly as the authority's `ctx->type != IS_DIR` does. Nothing else observes the
/// shape.
struct FileCtxSt {
    /// `void *provctx`.
    provctx: *mut c_void,
    /// `char *uri` — the URI we currently try to load.
    uri: *mut c_char,
    /// `enum { IS_FILE, IS_DIR } type`.
    type_: c_int,
    /// The `IS_FILE` arm.
    file: FileCtxFile,
    /// The `IS_DIR` arm.
    dir: FileCtxDir,
    /// `int expected_type` — may be unspecified.
    expected_type: c_int,
    /// `int fatal_error` — we should indicate EOF.
    fatal_error: c_int,
}

/// `static void free_file_ctx(struct file_ctx_st *ctx)` — `file_store.c:114-126`.
///
/// # Safety
/// `ctx` must be NULL or a context this unit allocated, and must not be used again.
unsafe fn free_file_ctx(ctx: *mut FileCtxSt) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the guard above and owns these allocations.
    unsafe {
        CRYPTO_free((*ctx).uri.cast::<c_void>(), ptr::null(), 0);
        if (*ctx).type_ != IS_DIR {
            OSSL_DECODER_CTX_free((*ctx).file.decoderctx);
            CRYPTO_free((*ctx).file.propq.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*ctx).file.input_type.cast::<c_void>(), ptr::null(), 0);
        }
        CRYPTO_free(ctx.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `static struct file_ctx_st *new_file_ctx(int type, const char *uri, void *provctx)` —
/// `file_store.c:128-141`.
///
/// # Safety
/// `uri` must be NULL or NUL-terminated.
unsafe fn new_file_ctx(type_: c_int, uri: *const c_char, provctx: *mut c_void) -> *mut FileCtxSt {
    // SAFETY: the constructor asks only for a zeroed block of the object's size.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<FileCtxSt>(), ptr::null(), 0).cast::<FileCtxSt>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is this call's fresh allocation; `uri` is NULL or NUL-terminated.
        let uri_ok = uri.is_null() || {
            // SAFETY: `uri` is NULL or NUL-terminated per the contract.
            let copy = unsafe { CRYPTO_strdup(uri, ptr::null(), 0) };
            // SAFETY: `ctx` is this call's fresh, uniquely-owned allocation.
            unsafe { (*ctx).uri = copy };
            !copy.is_null()
        };
        if uri_ok {
            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).type_ = type_;
                (*ctx).provctx = provctx;
            }
            return ctx;
        }
    }
    // SAFETY: `ctx` is NULL or this call's allocation, live or partly initialised.
    unsafe { free_file_ctx(ctx) };
    ptr::null_mut()
}

// ---------------------------------------------------------------------------
// Opening / attaching — `file_store.c:146-290`
// ---------------------------------------------------------------------------

/// `static struct file_ctx_st *file_open_stream(BIO *source, const char *uri, void *provctx)` —
/// `file_store.c:156-172`.
///
/// # Safety
/// `source` must be a live BIO this context takes ownership of; `uri` NULL or NUL-terminated.
unsafe fn file_open_stream(
    source: *mut Bio,
    uri: *const c_char,
    provctx: *mut c_void,
) -> *mut FileCtxSt {
    // SAFETY: `uri` is NULL or NUL-terminated per the contract.
    let ctx = unsafe { new_file_ctx(IS_FILE, uri, provctx) };
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_FILE_STORE_162) };
        // SAFETY: `ctx` is NULL, which `free_file_ctx` accepts.
        unsafe { free_file_ctx(ctx) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).file.file = source };
    ctx
}

/// `HAS_CASE_PREFIX`/`CHECK_AND_SKIP_CASE_PREFIX` — `include/internal/common.h:62-66`. Returns
/// true when `pre` is a case-insensitive prefix of `*s`, and on success advances `*s` past it.
///
/// # Safety
/// `*s` must be NUL-terminated.
unsafe fn check_and_skip_case_prefix(s: &mut *const c_char, pre: &[u8]) -> bool {
    // `OPENSSL_strncasecmp(*s, pre, sizeof(pre) - 1) == 0`; the slice is exactly the prefix.
    // SAFETY: `*s` is NUL-terminated and the comparison reads at most `pre.len()` bytes of it.
    if unsafe { OPENSSL_strncasecmp(*s, pre.as_ptr().cast::<c_char>(), pre.len()) } == 0 {
        // SAFETY: the prefix matched, so `*s` has at least `pre.len()` bytes before its NUL.
        *s = unsafe { (*s).add(pre.len()) };
        true
    } else {
        false
    }
}

/// `static void *file_open_dir(const char *path, const char *uri, void *provctx)` —
/// `file_store.c:174-197`.
///
/// # Safety
/// `path` and `uri` must be NUL-terminated; `provctx` is the provider's own.
unsafe fn file_open_dir(
    path: *const c_char,
    uri: *const c_char,
    provctx: *mut c_void,
) -> *mut c_void {
    // SAFETY: `uri` is NUL-terminated per the contract.
    let ctx = unsafe { new_file_ctx(IS_DIR, uri, provctx) };
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_FILE_STORE_179) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live; the read fills the directory context's own buffer.
    unsafe {
        (*ctx).dir.last_entry = crate::runtime::dir::OPENSSL_DIR_read(&mut (*ctx).dir.ctx, path);
    }
    // SAFETY: the read above may have set errno.
    unsafe { (*ctx).dir.last_errno = sys::errno() };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).dir.last_entry }.is_null() {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).dir.last_errno } != 0 {
            let mut msg = [0 as c_char; 512];
            // SAFETY: `msg` is a writable buffer of the size passed; `path` is NUL-terminated.
            unsafe {
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"Calling OPENSSL_DIR_read(\"%s\")".as_ptr(),
                    path,
                )
            };
            // SAFETY: the site is a compile-time constant marked dynamic; `msg` is NUL-terminated.
            unsafe {
                raise_site_dynamic_data(
                    &err_sites::PROV_FILE_STORE_187,
                    (*ctx).dir.last_errno,
                    msg.as_ptr(),
                )
            };
            // SAFETY: `ctx` is live and this call owns it.
            unsafe { file_close(ctx.cast::<c_void>()) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).dir.end_reached = 1 };
    }
    ctx.cast::<c_void>()
}

/// `static void *file_open(void *provctx, const char *uri)` — `file_store.c:199-276`.
///
/// # Safety
/// `uri` must be NUL-terminated; `provctx` is the provider's own.
unsafe extern "C" fn file_open(provctx: *mut c_void, uri: *const c_char) -> *mut c_void {
    let mut ctx: *mut FileCtxSt = ptr::null_mut();
    let mut path_data: [*const c_char; 2] = [ptr::null(); 2];
    let mut path_data_n: usize = 0;
    let mut p = uri;
    let mut q;
    let mut path: *const c_char = ptr::null();
    let mut path_is_dir = false;

    // SAFETY: no preconditions.
    ERR_set_mark();

    // First step, just take the URI as is.
    path_data[path_data_n] = uri;
    path_data_n += 1;

    // Second step: if the URI appears to start with the "file" scheme, extract the path and
    // make that the second path to check.
    // SAFETY: `p` is NUL-terminated and `check_and_skip_case_prefix`'s contract is met.
    if unsafe { check_and_skip_case_prefix(&mut p, b"file:") } {
        q = p;
        // SAFETY: `q` is NUL-terminated.
        if unsafe { check_and_skip_case_prefix(&mut q, b"//") } {
            path_data_n -= 1; // Invalidate using the full URI.
                              // SAFETY: `q` is NUL-terminated.
            if unsafe { check_and_skip_case_prefix(&mut q, b"localhost/") }
                // SAFETY: `q` is NUL-terminated.
                || unsafe { check_and_skip_case_prefix(&mut q, b"/") }
            {
                // Step back one char to preserve the first slash, so the path is absolute.
                // SAFETY: at least one character preceded `q`, because `//` was skipped.
                p = unsafe { q.sub(1) };
            } else {
                // SAFETY: no preconditions for either.
                ERR_clear_last_mark();
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PROV_FILE_STORE_234) };
                return ptr::null_mut();
            }
        }
        path_data[path_data_n] = p;
        path_data_n += 1;
    }

    let mut i = 0usize;
    while path.is_null() && i < path_data_n {
        // SAFETY: `path_data[i]` is NUL-terminated.
        match unsafe { stat_is_dir(path_data[i]) } {
            Ok(is_dir) => {
                path = path_data[i];
                path_is_dir = is_dir;
            }
            Err(e) => {
                let mut msg = [0 as c_char; 512];
                // SAFETY: `msg` is writable and `path_data[i]` is NUL-terminated.
                unsafe {
                    BIO_snprintf(
                        msg.as_mut_ptr(),
                        msg.len(),
                        c"calling stat(%s)".as_ptr(),
                        path_data[i],
                    )
                };
                // SAFETY: the site is marked dynamic and `msg` is NUL-terminated.
                unsafe {
                    raise_site_dynamic_data(&err_sites::PROV_FILE_STORE_254, e, msg.as_ptr())
                };
            }
        }
        i += 1;
    }
    if path.is_null() {
        // SAFETY: no preconditions.
        ERR_clear_last_mark();
        return ptr::null_mut();
    }

    // Successfully found a working path; clear the errors collected on the way.
    // SAFETY: no preconditions.
    ERR_pop_to_mark();

    if path_is_dir {
        // SAFETY: `path`/`uri` are NUL-terminated.
        ctx = unsafe { file_open_dir(path, uri, provctx).cast::<FileCtxSt>() };
    } else {
        // SAFETY: `path` is NUL-terminated and the mode literal is static.
        let bio = unsafe { BIO_new_file(path, c"rb".as_ptr()) };
        if bio.is_null() {
            // SAFETY: NULL is accepted.
            unsafe { BIO_free_all(bio) };
        } else {
            // SAFETY: `bio` is live and this context takes it over on success.
            ctx = unsafe { file_open_stream(bio, uri, provctx) };
            if ctx.is_null() {
                // SAFETY: `bio` is live and this call still owns its reference.
                unsafe { BIO_free_all(bio) };
            }
        }
    }
    ctx.cast::<c_void>()
}

/// `void *file_attach(void *provctx, OSSL_CORE_BIO *cin)` — `file_store.c:278-290`.
///
/// # Safety
/// `cin` must be a live core BIO; `provctx` is the provider's own.
unsafe extern "C" fn file_attach(provctx: *mut c_void, cin: *mut c_void) -> *mut c_void {
    // SAFETY: `cin` is a live handle and `ossl_bio_new_from_core_bio` takes its own reference.
    let new_bio = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if new_bio.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `new_bio` is live; `uri` is NULL here, as the authority passes.
    let ctx = unsafe { file_open_stream(new_bio, ptr::null(), provctx) };
    if ctx.is_null() {
        // SAFETY: `new_bio` is live and this call still owns its reference.
        unsafe { BIO_free(new_bio) };
    }
    ctx.cast::<c_void>()
}

// ---------------------------------------------------------------------------
// Setting parameters — `file_store.c:292-443`
// ---------------------------------------------------------------------------

/// `file_set_ctx_params_list[]` — `file_store.c:300-306`.
static FILE_SET_CTX_PARAMS_LIST: [OsslParam; 5] = [
    param_utf8_string(OSSL_STORE_PARAM_PROPERTIES),
    param_int(OSSL_STORE_PARAM_EXPECT),
    param_octet_string(OSSL_STORE_PARAM_SUBJECT),
    param_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE),
    END,
];

/// `struct file_set_ctx_params_st` — `file_store.c:310-315`, the `paramnames.pm` expansion.
struct FileSetCtxParams {
    /// `OSSL_PARAM *expect`.
    expect: *const OsslParam,
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
    /// `OSSL_PARAM *sub`.
    sub: *const OsslParam,
    /// `OSSL_PARAM *type`.
    type_: *const OsslParam,
}

/// `static int file_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// file_set_ctx_params_st *r)` — `file_store.c:319-375`.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array.
unsafe fn file_set_ctx_params_decoder(params: *const OsslParam) -> Option<FileSetCtxParams> {
    let mut r = FileSetCtxParams {
        expect: ptr::null(),
        propq: ptr::null(),
        sub: ptr::null(),
        type_: ptr::null(),
    };
    if params.is_null() {
        return Some(r);
    }
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let key = core::ffi::CStr::from_ptr((*p).key).to_bytes();
            match key.first().copied() {
                Some(b'e') if &key[1..] == b"xpect" => {
                    if !r.expect.is_null() {
                        // SAFETY: `(*p).key` is the repeated key of a live descriptor.
                        raise_repeated_param(&err_sites::PROV_FILE_STORE_334, (*p).key);
                        return None;
                    }
                    r.expect = p;
                }
                Some(b'i') if &key[1..] == b"nput-type" => {
                    if !r.type_.is_null() {
                        // SAFETY: as above.
                        raise_repeated_param(&err_sites::PROV_FILE_STORE_345, (*p).key);
                        return None;
                    }
                    r.type_ = p;
                }
                Some(b'p') if &key[1..] == b"roperties" => {
                    if !r.propq.is_null() {
                        // SAFETY: as above.
                        raise_repeated_param(&err_sites::PROV_FILE_STORE_356, (*p).key);
                        return None;
                    }
                    r.propq = p;
                }
                Some(b's') if &key[1..] == b"ubject" => {
                    if !r.sub.is_null() {
                        // SAFETY: as above.
                        raise_repeated_param(&err_sites::PROV_FILE_STORE_367, (*p).key);
                        return None;
                    }
                    r.sub = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }
    Some(r)
}

/// `static const OSSL_PARAM *file_settable_ctx_params(void *provctx)` —
/// `file_store.c:380-383`.
///
/// # Safety
/// The store `settable_ctx_params` dispatch contract.
unsafe extern "C" fn file_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    FILE_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int file_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])` —
/// `file_store.c:385-443`.
///
/// # Safety
/// The store `set_ctx_params` dispatch contract.
unsafe extern "C" fn file_set_ctx_params(
    loaderctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = loaderctx.cast::<FileCtxSt>();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `params` is the contract's array.
    let Some(p) = (unsafe { file_set_ctx_params_decoder(params) }) else {
        return 0;
    };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).type_ } != IS_DIR {
        // These parameters are ignored for directories.
        if !p.propq.is_null() {
            // SAFETY: `ctx` is live and owns `propq`.
            unsafe {
                CRYPTO_free((*ctx).file.propq.cast::<c_void>(), ptr::null(), 0);
                (*ctx).file.propq = ptr::null_mut();
                // SAFETY: `p.propq` is a live descriptor; `propq` is this row's out-slot.
                if OSSL_PARAM_get_utf8_string(p.propq, &mut (*ctx).file.propq, 0) == 0 {
                    return 0;
                }
            }
        }
        if !p.type_.is_null() {
            // SAFETY: `ctx` is live and owns `input_type`.
            unsafe {
                CRYPTO_free((*ctx).file.input_type.cast::<c_void>(), ptr::null(), 0);
                (*ctx).file.input_type = ptr::null_mut();
                // SAFETY: `p.type_` is a live descriptor; `input_type` is this row's out-slot.
                if OSSL_PARAM_get_utf8_string(p.type_, &mut (*ctx).file.input_type, 0) == 0 {
                    return 0;
                }
            }
        }
    }

    // SAFETY: `ctx` is live; `p.expect` is a live descriptor or NULL.
    if !p.expect.is_null()
        // SAFETY: `p.expect` is a live integer descriptor and `expected_type` is this context's.
        && unsafe { OSSL_PARAM_get_int(p.expect, &mut (*ctx).expected_type) } == 0
    {
        return 0;
    }

    if !p.sub.is_null() {
        let mut der: *const c_uchar = ptr::null();
        let mut der_len: usize = 0;
        let mut ok: c_int = 0;
        // SAFETY: `p.sub` is a live octet-string descriptor; `der`/`der_len` are out-slots.
        unsafe {
            if OSSL_PARAM_get_octet_string_ptr(
                p.sub,
                (&mut der as *mut *const c_uchar).cast(),
                &mut der_len,
            ) == 0
                || der_len > c_long::MAX as usize
            {
                return 0;
            }
        }
        // SAFETY: `der`/`der_len` describe the descriptor's octet string; `d2i_X509_NAME`
        // advances `der` and answers a new object or NULL.
        let x509_name: *mut X509Name =
            unsafe { d2i_X509_NAME(ptr::null_mut(), &mut der, der_len as c_long) };
        if x509_name.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).type_ } != IS_DIR {
            // SAFETY: `x509_name` is live; the printer allocates.
            let str_ = unsafe { X509_NAME_oneline(x509_name, ptr::null_mut(), 0) };
            let mut msg = [0 as c_char; 1024];
            // SAFETY: all arguments are NUL-terminated strings.
            unsafe {
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"uri=%s:subject=%s".as_ptr(),
                    (*ctx).uri,
                    str_,
                )
            };
            // SAFETY: the site is a compile-time constant; `msg` is NUL-terminated.
            unsafe { raise_site_data(&err_sites::PROV_FILE_STORE_426, msg.as_ptr()) };
            // SAFETY: `str_` was allocated by the printer above.
            unsafe { CRYPTO_free(str_.cast::<c_void>(), ptr::null(), 0) };
            // SAFETY: `x509_name` is live and this call owns it.
            unsafe { X509_NAME_free(x509_name) };
            return 0;
        }
        // SAFETY: `ctx`/`x509_name` are live; `ok` is this frame's out-slot.
        let hash = unsafe {
            X509_NAME_hash_ex(
                x509_name,
                ossl_prov_ctx_get0_libctx((*ctx).provctx.cast::<ProvCtx>()),
                ptr::null(),
                &mut ok,
            )
        };
        // SAFETY: `ctx` is live and `search_name` is its own 9-byte buffer.
        unsafe {
            BIO_snprintf(
                (*ctx).dir.search_name.as_mut_ptr(),
                (*ctx).dir.search_name.len(),
                c"%08lx".as_ptr(),
                hash,
            );
        }
        // SAFETY: `x509_name` is live and this call owns it.
        unsafe { X509_NAME_free(x509_name) };
        if ok == 0 {
            return 0;
        }
    }
    1
}

// ---------------------------------------------------------------------------
// Loading — `file_store.c:445-822`
// ---------------------------------------------------------------------------

/// `struct file_load_data_st` — `file_store.c:450-453`.
struct FileLoadDataSt {
    /// `OSSL_CALLBACK *object_cb`.
    object_cb: Option<OsslCallback>,
    /// `void *object_cbarg`.
    object_cbarg: *mut c_void,
}

/// `static int file_load_construct(OSSL_DECODER_INSTANCE *decoder_inst, const OSSL_PARAM *params,
/// void *construct_data)` — `file_store.c:455-477`.
///
/// # Safety
/// The decoder `construct` dispatch contract; `construct_data` must be a live `FileLoadDataSt`.
unsafe extern "C" fn file_load_construct(
    _decoder_inst: *mut OsslDecoderInstance,
    params: *const OsslParam,
    construct_data: *mut c_void,
) -> c_int {
    let data = construct_data.cast::<FileLoadDataSt>();
    // SAFETY: `data` is live per the contract.
    match unsafe { (*data).object_cb } {
        // SAFETY: `params` is the decoder chain's; `object_cbarg` is the caller's.
        Some(cb) => unsafe { cb(params, (*data).object_cbarg) },
        None => 0,
    }
}

/// `void file_load_cleanup(void *construct_data)` — `file_store.c:479-482`. Nothing to do.
///
/// # Safety
/// The decoder `cleanup` dispatch contract.
unsafe extern "C" fn file_load_cleanup(_construct_data: *mut c_void) {}

/// `static int file_setup_decoders(struct file_ctx_st *ctx)` — `file_store.c:484-621`.
///
/// # Safety
/// `ctx` must be a live context whose `type_` is `IS_FILE`.
unsafe fn file_setup_decoders(ctx: *mut FileCtxSt) -> c_int {
    // SAFETY: `ctx` is live.
    if !unsafe { (*ctx).file.decoderctx }.is_null() {
        return 1;
    }
    // SAFETY: `ctx` is live per the contract.
    c_int::from(unsafe { file_setup_decoders_once(ctx) })
}

/// The one-shot body of [`file_setup_decoders`] — `file_store.c:492-618`. Returns whether the
/// chain was built; every refusal raises its own site and answers `false`.
///
/// # Safety
/// `ctx` must be a live `IS_FILE` context whose `decoderctx` is NULL.
unsafe fn file_setup_decoders_once(ctx: *mut FileCtxSt) -> bool {
    // SAFETY: `ctx` is live and its `provctx` is the provider's own.
    let libctx = unsafe { ossl_prov_ctx_get0_libctx((*ctx).provctx.cast::<ProvCtx>()) };
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).file.decoderctx }.is_null() {
        // SAFETY: the constructor takes no arguments and answers NULL or a live object.
        let fresh = unsafe { OSSL_DECODER_CTX_new() };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).file.decoderctx = fresh };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).file.decoderctx }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_FILE_STORE_494) };
            return false;
        }
        // SAFETY: `ctx` is live; `input_type` may be NULL.
        if unsafe {
            OSSL_DECODER_CTX_set_input_type((*ctx).file.decoderctx, (*ctx).file.input_type)
        } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_FILE_STORE_501) };
            return false;
        }

        // Where applicable, set the outermost structure name, and hand the same string to the
        // last-resort decoder instances below. Each case raises its own authority coordinate
        // (`516`/`533`/`541`/`549`), which is why they are not collapsed into one check.
        // SAFETY: `ctx` is live.
        let input_structure: *const c_char = match unsafe { (*ctx).expected_type } {
            OSSL_STORE_INFO_PUBKEY => {
                let s = c"SubjectPublicKeyInfo".as_ptr();
                // SAFETY: `ctx` is live and the string is static.
                if unsafe { OSSL_DECODER_CTX_set_input_structure((*ctx).file.decoderctx, s) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PROV_FILE_STORE_516) };
                    return false;
                }
                s
            }
            OSSL_STORE_INFO_PKEY => {
                let s = c"EncryptedPrivateKeyInfo".as_ptr();
                // SAFETY: as above.
                if unsafe { OSSL_DECODER_CTX_set_input_structure((*ctx).file.decoderctx, s) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PROV_FILE_STORE_533) };
                    return false;
                }
                s
            }
            OSSL_STORE_INFO_CERT => {
                let s = c"Certificate".as_ptr();
                // SAFETY: as above.
                if unsafe { OSSL_DECODER_CTX_set_input_structure((*ctx).file.decoderctx, s) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PROV_FILE_STORE_541) };
                    return false;
                }
                s
            }
            OSSL_STORE_INFO_CRL => {
                let s = c"CertificateList".as_ptr();
                // SAFETY: as above.
                if unsafe { OSSL_DECODER_CTX_set_input_structure((*ctx).file.decoderctx, s) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PROV_FILE_STORE_549) };
                    return false;
                }
                s
            }
            _ => ptr::null(),
        };

        // SAFETY: `ossl_any_to_obj_algorithm` is this stratum's own terminated table; `addr_of!`
        // does not create a reference to the mutable static.
        let mut to_algo =
            core::ptr::addr_of!(crate::provider::file_store_any2obj::ossl_any_to_obj_algorithm)
                .cast::<OsslAlgorithm>();
        // SAFETY: the table is terminated by a NULL name.
        while !unsafe { (*to_algo).algorithm_names }.is_null() {
            // SAFETY: `to_algo` is a live row; the provider is NULL by design here.
            let to_obj = unsafe { ossl_decoder_from_algorithm(0, to_algo, ptr::null_mut()) };
            let to_obj_inst = if to_obj.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `to_obj` is live and `ctx.provctx` is the provider's own.
                unsafe {
                    ossl_decoder_instance_new_forprov(to_obj, (*ctx).provctx, input_structure)
                }
            };
            // SAFETY: `to_obj` is live or NULL.
            unsafe { OSSL_DECODER_free(to_obj) };
            if to_obj_inst.is_null() {
                return false;
            }
            // SAFETY: `to_obj_inst` is live.
            let input_type = unsafe { OSSL_DECODER_INSTANCE_get_input_type(to_obj_inst) };
            // SAFETY: `ctx` is live; the four string pointers are NUL-terminated or NULL.
            let mismatched = unsafe {
                !(*ctx).file.input_type.is_null()
                    && OPENSSL_strcasecmp(input_type, (*ctx).file.input_type) != 0
                    && (OPENSSL_strcasecmp((*ctx).file.input_type, c"PEM".as_ptr()) != 0
                        || OPENSSL_strcasecmp(input_type, c"der".as_ptr()) != 0)
            };
            if mismatched {
                // SAFETY: `to_obj_inst` is live and this call owns it.
                unsafe { ossl_decoder_instance_free(to_obj_inst) };
                // SAFETY: the loop stays within the terminated table.
                to_algo = unsafe { to_algo.add(1) };
                continue;
            }
            // SAFETY: `ctx` is live; `to_obj_inst` is live and handed over on success.
            if unsafe { ossl_decoder_ctx_add_decoder_inst((*ctx).file.decoderctx, to_obj_inst) }
                == 0
            {
                // SAFETY: `to_obj_inst` is live and this call still owns it.
                unsafe { ossl_decoder_instance_free(to_obj_inst) };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PROV_FILE_STORE_594) };
                return false;
            }
            // SAFETY: the loop stays within the terminated table.
            to_algo = unsafe { to_algo.add(1) };
        }

        // Add on the usual extra decoders.
        // SAFETY: `ctx` is live; `libctx` and `propq` are NULL or live.
        if unsafe { OSSL_DECODER_CTX_add_extra((*ctx).file.decoderctx, libctx, (*ctx).file.propq) }
            == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_FILE_STORE_601) };
            return false;
        }

        // Then install the constructor hooks.
        // SAFETY: `ctx` is live; the two callbacks are this unit's own.
        if unsafe {
            OSSL_DECODER_CTX_set_construct(
                (*ctx).file.decoderctx,
                Some(file_load_construct as DecoderConstructFn),
            )
        } == 0
            // SAFETY: as above; the second hook is set only when the first succeeded.
            || unsafe {
                OSSL_DECODER_CTX_set_cleanup(
                    (*ctx).file.decoderctx,
                    Some(file_load_cleanup as DecoderCleanupFn),
                )
            } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_FILE_STORE_613) };
            return false;
        }
    }
    true
}

/// `static int file_load_file(struct file_ctx_st *ctx, OSSL_CALLBACK *object_cb,
/// void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `file_store.c:623-656`.
///
/// # Safety
/// `ctx` must be a live `IS_FILE` context.
unsafe fn file_load_file(
    ctx: *mut FileCtxSt,
    object_cb: Option<OsslCallback>,
    object_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { file_setup_decoders(ctx) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).fatal_error = 1 };
        return 0;
    }

    let mut data = FileLoadDataSt {
        object_cb,
        object_cbarg,
    };
    // SAFETY: `ctx` is live; `data` outlives the decode call below.
    unsafe {
        OSSL_DECODER_CTX_set_construct_data(
            (*ctx).file.decoderctx,
            (&mut data as *mut FileLoadDataSt).cast::<c_void>(),
        );
        OSSL_DECODER_CTX_set_passphrase_cb((*ctx).file.decoderctx, pw_cb, pw_cbarg);
    }

    // SAFETY: no preconditions.
    ERR_set_mark();
    // SAFETY: `ctx` is live and the decoder chain was just set up.
    let ret = unsafe { OSSL_DECODER_from_bio((*ctx).file.decoderctx, (*ctx).file.file) };
    // SAFETY: `ctx` is live.
    if unsafe { bio_eof((*ctx).file.file) } != 0 && {
        // SAFETY: the ERR queue is thread-local and queryable here.
        let err = ERR_peek_last_error();
        err != 0
            && err_get_lib(err) == ERR_LIB_OSSL_DECODER
            && err_get_reason(err) == ERR_R_UNSUPPORTED
    } {
        // SAFETY: no preconditions.
        ERR_pop_to_mark();
    } else {
        // SAFETY: no preconditions.
        ERR_clear_last_mark();
    }
    ret
}

/// `static char *file_name_to_uri(struct file_ctx_st *ctx, const char *name)` —
/// `file_store.c:663-682`.
///
/// # Safety
/// `ctx` must be a live context with a non-NULL `uri`; `name` must be non-NULL and
/// NUL-terminated.
unsafe fn file_name_to_uri(ctx: *mut FileCtxSt, name: *const c_char) -> *mut c_char {
    // SAFETY: `ctx.uri` is NUL-terminated per the contract.
    let pathsep: *const c_char = if unsafe { ossl_ends_with_dirsep((*ctx).uri) } != 0 {
        c"".as_ptr()
    } else {
        c"/".as_ptr()
    };
    // SAFETY: every argument is NUL-terminated.
    let calculated_length =
        unsafe { sys::strlen((*ctx).uri) + sys::strlen(pathsep) + sys::strlen(name) + 1 };
    // SAFETY: the allocation asks for a zeroed block of the computed size.
    let data = CRYPTO_zalloc(calculated_length, ptr::null(), 0).cast::<c_char>();
    if data.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `data` is a live buffer of `calculated_length` bytes; the three sources are
    // NUL-terminated, so `OPENSSL_strlcat` writes within it.
    unsafe {
        OPENSSL_strlcat(data, (*ctx).uri, calculated_length);
        OPENSSL_strlcat(data, pathsep, calculated_length);
        OPENSSL_strlcat(data, name, calculated_length);
    }
    data
}

/// `static int file_name_check(struct file_ctx_st *ctx, const char *name)` —
/// `file_store.c:684-744`.
///
/// # Safety
/// `ctx` must be a live `IS_DIR` context; `name` must be NUL-terminated.
unsafe fn file_name_check(ctx: *mut FileCtxSt, name: *const c_char) -> c_int {
    // SAFETY: `search_name` is a NUL-terminated 9-byte buffer of `ctx`.
    let len = unsafe { sys::strlen((*ctx).dir.search_name.as_ptr()) };
    // SAFETY: `ctx` is live per the contract.
    let expected_type = unsafe { (*ctx).expected_type };

    // If there are no search criteria, all names are accepted.
    // SAFETY: `ctx` is live.
    if unsafe { *(*ctx).dir.search_name.as_ptr() } == 0 {
        return 1;
    }

    // If the expected type isn't supported, no name is accepted.
    if expected_type != 0
        && expected_type != OSSL_STORE_INFO_CERT
        && expected_type != OSSL_STORE_INFO_CRL
    {
        return 0;
    }

    // First, check the basename. A matching prefix proves `name` has `len` bytes before its NUL.
    // SAFETY: `name` and `search_name` are NUL-terminated.
    if unsafe {
        OPENSSL_strncasecmp(name, (*ctx).dir.search_name.as_ptr(), len) != 0
            || *name.add(len) != b'.' as c_char
    } {
        return 0;
    }
    // SAFETY: `name[len]` was just proven a `.`, so `name[len + 1]` is within the string.
    let mut p = unsafe { name.add(len + 1) };

    // Then, if the expected type is a CRL, check that the extension starts with 'r'.
    // SAFETY: `p` is within `name`.
    if unsafe { *p } == b'r' as c_char {
        // SAFETY: `p` is within `name`.
        p = unsafe { p.add(1) };
        if expected_type != 0 && expected_type != OSSL_STORE_INFO_CRL {
            return 0;
        }
    } else if expected_type == OSSL_STORE_INFO_CRL {
        return 0;
    }

    // Last, check that the rest of the extension is a decimal number, at least one digit long.
    // SAFETY: `p` is within `name`.
    if !unsafe { crate::runtime::ctype::ossl_isdigit((*p as u8) as c_int) } {
        return 0;
    }
    // SAFETY: `p` walks toward the NUL terminator.
    while unsafe { crate::runtime::ctype::ossl_isdigit((*p as u8) as c_int) } {
        // SAFETY: `p` is within `name`.
        p = unsafe { p.add(1) };
    }

    // If we've reached the end of the string, we've found a fitting file name.
    // SAFETY: `p` is within `name`.
    c_int::from(unsafe { *p } == 0)
}

/// `static int file_load_dir_entry(struct file_ctx_st *ctx, OSSL_CALLBACK *object_cb,
/// void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `file_store.c:746-797`.
///
/// # Safety
/// `ctx` must be a live `IS_DIR` context.
unsafe fn file_load_dir_entry(
    ctx: *mut FileCtxSt,
    object_cb: Option<OsslCallback>,
    object_cbarg: *mut c_void,
    _pw_cb: Option<OsslPassphraseCallback>,
    _pw_cbarg: *mut c_void,
) -> c_int {
    // `static const int object_type = OSSL_OBJECT_NAME`.
    let object_type: c_int = OSSL_OBJECT_NAME;
    // SAFETY: `object_type` outlives the descriptor; the two constructors take a key.
    let mut object = [
        unsafe {
            OSSL_PARAM_construct_int(
                OSSL_OBJECT_PARAM_TYPE,
                (&object_type as *const c_int).cast_mut(),
            )
        },
        unsafe { OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA, ptr::null_mut(), 0) },
        OSSL_PARAM_construct_end(),
    ];
    let mut newname: *mut c_char = ptr::null_mut();

    loop {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).dir.last_entry }.is_null() {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).dir.end_reached } == 0 {
                // `assert(ctx->_.dir.last_errno != 0)` is compiled out under NDEBUG.
                // SAFETY: the site is marked dynamic; the reason is the cached errno.
                unsafe {
                    raise_site_dynamic(&err_sites::PROV_FILE_STORE_765, (*ctx).dir.last_errno)
                };
            }
            return 0;
        }

        // Flag acceptable names.
        // SAFETY: `ctx` is live and `last_entry` is a NUL-terminated entry name.
        if unsafe { *(*ctx).dir.last_entry } != b'.' as c_char
            // SAFETY: `ctx` is live and `last_entry` is NUL-terminated.
            && unsafe { file_name_check(ctx, (*ctx).dir.last_entry) } != 0
        {
            // SAFETY: `ctx` is live and `last_entry` is NUL-terminated.
            newname = unsafe { file_name_to_uri(ctx, (*ctx).dir.last_entry) };
            if newname.is_null() {
                return 0;
            }
        }

        // SAFETY: `ctx` is live; the URI is NUL-terminated.
        unsafe {
            (*ctx).dir.last_entry =
                crate::runtime::dir::OPENSSL_DIR_read(&mut (*ctx).dir.ctx, (*ctx).uri);
        }
        // SAFETY: the read above may have set errno.
        unsafe { (*ctx).dir.last_errno = sys::errno() };
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).dir.last_entry }.is_null() && unsafe { (*ctx).dir.last_errno } == 0 {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).dir.end_reached = 1 };
        }
        if !newname.is_null() {
            break;
        }
    }

    object[1].data = newname.cast::<c_void>();
    // SAFETY: `newname` is NUL-terminated.
    object[1].data_size = unsafe { sys::strlen(newname) };
    let ok = match object_cb {
        // SAFETY: `object` is a terminator-ended array live across the call.
        Some(cb) => unsafe { cb(object.as_ptr(), object_cbarg) },
        None => 0,
    };
    // SAFETY: `newname` was allocated above and this call owns it.
    unsafe { CRYPTO_free(newname.cast::<c_void>(), ptr::null(), 0) };
    ok
}

/// `static int file_load(void *loaderctx, OSSL_CALLBACK *object_cb, void *object_cbarg,
/// OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` — `file_store.c:804-822`.
///
/// # Safety
/// The store `load` dispatch contract; `loaderctx` must be a live context.
unsafe extern "C" fn file_load(
    loaderctx: *mut c_void,
    object_cb: Option<OsslCallback>,
    object_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = loaderctx.cast::<FileCtxSt>();
    // SAFETY: `ctx` is live per the contract.
    let type_ = unsafe { (*ctx).type_ };
    match type_ {
        // SAFETY: `ctx` is live and the two functions take it plus the caller's callbacks.
        IS_FILE => unsafe { file_load_file(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg) },
        // SAFETY: as above.
        IS_DIR => unsafe { file_load_dir_entry(ctx, object_cb, object_cbarg, pw_cb, pw_cbarg) },
        // `assert(0)` is compiled out under NDEBUG.
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Eof detection and closing — `file_store.c:824-888`
// ---------------------------------------------------------------------------

/// `BIO_eof(b)` — `include/openssl/bio.h`, `BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL)`.
///
/// # Safety
/// `b` must be a live BIO.
unsafe fn bio_eof(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_EOF, 0, ptr::null_mut()) as c_int }
}

/// `BIO_pending(b)` — `include/openssl/bio.h`, `BIO_ctrl(b, BIO_CTRL_PENDING, 0, NULL)`.
///
/// # Safety
/// `b` must be a live BIO.
unsafe fn bio_pending(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_PENDING, 0, ptr::null_mut()) as c_int }
}

/// `static int file_eof(void *loaderctx)` — `file_store.c:829-851`.
///
/// # Safety
/// The store `eof` dispatch contract; `loaderctx` must be a live context.
unsafe extern "C" fn file_eof(loaderctx: *mut c_void) -> c_int {
    let ctx = loaderctx.cast::<FileCtxSt>();
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).fatal_error } != 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let type_ = unsafe { (*ctx).type_ };
    match type_ {
        // SAFETY: `ctx` is live.
        IS_DIR => unsafe { (*ctx).dir.end_reached },
        IS_FILE => {
            // SAFETY: `ctx` is live and `file.file` is a live BIO.
            unsafe {
                c_int::from(bio_pending((*ctx).file.file) == 0 && bio_eof((*ctx).file.file) != 0)
            }
        }
        // `assert(0)` is compiled out under NDEBUG.
        _ => 1,
    }
}

/// `static int file_close_dir(struct file_ctx_st *ctx)` — `file_store.c:853-859`.
///
/// # Safety
/// `ctx` must be a live `IS_DIR` context.
unsafe fn file_close_dir(ctx: *mut FileCtxSt) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).dir.ctx }.is_null() {
        // Nothing to close.
    } else {
        // SAFETY: `ctx.dir.ctx` is live; the end releases it and clears the slot.
        unsafe { crate::runtime::dir::OPENSSL_DIR_end(&mut (*ctx).dir.ctx) };
    }
    // SAFETY: `ctx` is live and this call owns it.
    unsafe { free_file_ctx(ctx) };
    1
}

/// `static int file_close_stream(struct file_ctx_st *ctx)` — `file_store.c:861-872`.
///
/// # Safety
/// `ctx` must be a live `IS_FILE` context.
unsafe fn file_close_stream(ctx: *mut FileCtxSt) -> c_int {
    // SAFETY: `ctx` is live; `file.file` is a live BIO or NULL.
    unsafe {
        BIO_free((*ctx).file.file);
        (*ctx).file.file = ptr::null_mut();
    }
    // SAFETY: `ctx` is live and this call owns it.
    unsafe { free_file_ctx(ctx) };
    1
}

/// `static int file_close(void *loaderctx)` — `file_store.c:874-888`.
///
/// # Safety
/// The store `close` dispatch contract; `loaderctx` must be a live context.
unsafe extern "C" fn file_close(loaderctx: *mut c_void) -> c_int {
    let ctx = loaderctx.cast::<FileCtxSt>();
    // SAFETY: `ctx` is live per the contract.
    let type_ = unsafe { (*ctx).type_ };
    match type_ {
        // SAFETY: `ctx` is live and the closer takes it.
        IS_DIR => unsafe { file_close_dir(ctx) },
        // SAFETY: as above.
        IS_FILE => unsafe { file_close_stream(ctx) },
        // `assert(0)` is compiled out under NDEBUG.
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// The published dispatch table and the two provider rows — `file_store.c:890-900`
// ---------------------------------------------------------------------------

/// `const OSSL_DISPATCH ossl_file_store_functions[]` — `file_store.c:890-900`.
///
/// The seven callbacks `loader_from_algorithm` scans for, and the reason the `file` row
/// survives its four-clause sanity check: `open`, `attach`, `settable_ctx_params`,
/// `set_ctx_params`, `load`, `eof` and `close`.
#[no_mangle]
pub static ossl_file_store_functions: [OsslDispatch; 8] = [
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_OPEN,
        function: file_open as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_ATTACH,
        function: file_attach as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
        function: file_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_SET_CTX_PARAMS,
        function: file_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_LOAD,
        function: file_load as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_EOF,
        function: file_eof as *mut c_void,
    },
    OsslDispatch {
        function_id: crate::store::OSSL_FUNC_STORE_CLOSE,
        function: file_close as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `deflt_store[]` — `providers/defltprov.c:689-696` over `stores.inc`'s one Linux row:
/// `{"file", "provider=default,fips=yes", ossl_file_store_functions}`.
///
/// `winstore_store.c`'s `org.openssl.winstore` row is behind `OPENSSL_NO_WINSTORE`, which the
/// admitted Linux profile defines, so the table is the one row and the terminator.
pub(crate) static DEFLT_STORES: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"file".as_ptr(),
        property_definition: c"provider=default,fips=yes".as_ptr(),
        implementation: ossl_file_store_functions.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `base_store[]` — `providers/baseprov.c:81-88` over the same `stores.inc` row with the base
/// provider's property string `"provider=base,fips=yes"`.
pub(crate) static BASE_STORES: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"file".as_ptr(),
        property_definition: c"provider=base,fips=yes".as_ptr(),
        implementation: ossl_file_store_functions.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The published dispatch table is the authority's seven rows and the terminator, in order,
    /// and it carries the four callbacks the fetch's sanity check requires.
    #[test]
    fn the_dispatch_table_is_the_authoritys_seven_rows() {
        // SAFETY: the table is a `'static` value terminated by `OSSL_DISPATCH_END`.
        unsafe {
            let base = ossl_file_store_functions.as_ptr();
            let want = [
                crate::store::OSSL_FUNC_STORE_OPEN,
                crate::store::OSSL_FUNC_STORE_ATTACH,
                crate::store::OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
                crate::store::OSSL_FUNC_STORE_SET_CTX_PARAMS,
                crate::store::OSSL_FUNC_STORE_LOAD,
                crate::store::OSSL_FUNC_STORE_EOF,
                crate::store::OSSL_FUNC_STORE_CLOSE,
            ];
            for (i, id) in want.iter().enumerate() {
                let row = &*base.add(i);
                assert_eq!(row.function_id, *id, "row {i}");
                assert!(!row.function.is_null(), "row {i} has no callback");
            }
            assert_eq!((*base.add(7)).function_id, OSSL_DISPATCH_END);
        }
    }

    /// Both provider rows name `file` and point at the one dispatch table.
    #[test]
    fn the_two_rows_are_the_file_scheme() {
        // SAFETY: both tables are `'static` values terminated by a NULL name.
        unsafe {
            for (table, prop) in [
                (DEFLT_STORES.as_ptr(), "provider=default,fips=yes"),
                (BASE_STORES.as_ptr(), "provider=base,fips=yes"),
            ] {
                let row = &*table;
                assert!(core::ffi::CStr::from_ptr(row.algorithm_names).to_bytes() == b"file");
                assert_eq!(
                    core::ffi::CStr::from_ptr(row.property_definition).to_bytes(),
                    prop.as_bytes()
                );
                assert_eq!(
                    row.implementation,
                    ossl_file_store_functions.as_ptr().cast()
                );
                assert!((*table.add(1)).algorithm_names.is_null());
            }
        }
    }

    /// **The defect the reverted slice met, now regression-locked.** `OSSL_STORE_LOADER_fetch`
    /// reaches `deflt_query`/`base_query` for `OSSL_OP_STORE`, runs `construct_loader`, and
    /// resolves the `file` row through its dispatch table's four mandatory callbacks. With the
    /// default and base providers loaded, the fetch answers the default provider's loader.
    #[test]
    fn the_file_fetch_resolves_through_the_published_row() {
        // SAFETY: this test touches the process-global provider store, so it serialises with the
        // rest of the global-state tests.
        let _lock = crate::test_support::lock_global_state();
        // SAFETY: the provider names are static NUL-terminated literals.
        let default =
            unsafe { crate::provider::OSSL_PROVIDER_load(ptr::null_mut(), c"default".as_ptr()) };
        // SAFETY: as above.
        let base =
            unsafe { crate::provider::OSSL_PROVIDER_load(ptr::null_mut(), c"base".as_ptr()) };
        assert!(!default.is_null(), "the default provider loads");
        assert!(!base.is_null(), "the base provider loads");
        // SAFETY: the ERR queue is this thread's; clear anything a previous test left.
        crate::runtime::err::ERR_clear_error();
        // SAFETY: `scheme` is a static NUL-terminated literal and `properties` is NULL.
        let loader = unsafe {
            crate::store::store_meth::OSSL_STORE_LOADER_fetch(
                ptr::null_mut(),
                c"file".as_ptr(),
                ptr::null(),
            )
        };
        assert!(
            !loader.is_null(),
            "the published `file` OSSL_OP_STORE row resolves"
        );
        // SAFETY: `loader` is live and `name` is a static NUL-terminated literal; `is_a`
        // compares the loader's `scheme_id` against the namemap's number for the name.
        let is_file =
            unsafe { crate::store::store_meth::OSSL_STORE_LOADER_is_a(loader, c"file".as_ptr()) };
        assert_eq!(
            is_file, 1,
            "the resolved loader answers to the `file` scheme"
        );
        // SAFETY: `loader` is live and this call releases the reference the fetch returned.
        unsafe { crate::store::store_meth::OSSL_STORE_LOADER_free(loader) };
    }
}
