//! Phase 10.1/10.6 — `providers/implementations/encode_decode/decode_pvk2key.c`: the provider's
//! **PVK decoders**, one `OSSL_OP_DECODER` table for `DSA` and one for `RSA`, published by both the
//! `default` and the `base` provider.
//!
//! One of §1a's eleven row-publishing units (`2 tables`, `4 rows`). D435 held it `pending` for
//! `b2i_{DSA,RSA}_PVK_bio_ex`, which `crypto/pem/pvkfmt.c` publishes internally and 10.6 lands.
//!
//! ## The fatal/ignorable split is the error queue, and that is the subtlety
//!
//! `b2i_*_PVK_bio_ex` has no separate decrypt call, so a wrong passphrase and a malformed file both
//! surface as a NULL return. The unit distinguishes them by peeking the queue's **last** entry:
//! `ERR_LIB_PEM` with `PEM_R_BAD_PASSWORD_READ` or `PEM_R_BAD_DECRYPT` is fatal (the errors are
//! passed through), anything else is a "this decoder did not match" that gets discarded and the
//! next decoder is tried. `RT-CODEC` drives the readable PVK (level 0) and the malformed-header
//! refusal, because the encrypted arms need the `legacy` provider's `PVKKDF`/`RC4` rows.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_DOES_SELECTION, OSSL_FUNC_DECODER_EXPORT_OBJECT,
    OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX, OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DECODER_SET_CTX_PARAMS,
};
use crate::dsa::object::DSA_free;
use crate::dsa::Dsa;
use crate::evp::keymgmt::KeymgmtExportFn;
use crate::evp::pem_bridge::PemPasswordCb;
use crate::evp::pkey::OSSL_KEYMGMT_SELECT_ALL;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_utf8_string, OsslParam,
};
use crate::passphrase::{
    ossl_pw_pvk_password, ossl_pw_set_ossl_passphrase_cb, OsslPassphraseCallback,
    OsslPassphraseData,
};
use crate::pem::pvkfmt::{b2i_DSA_PVK_bio_ex, b2i_RSA_PVK_bio_ex};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::endecoder_common::ossl_prov_get_keymgmt_export;
use crate::rsa::object::{ossl_rsa_set0_libctx, RSA_free};
use crate::rsa::Rsa;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::{BIO_free, Bio};
use crate::runtime::err::{peek_last_lib, peek_last_reason, ERR_clear_last_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::selftest::OsslCallback;

unsafe extern "C" {
    /// The C library's `strcmp`, the generated parameter decoder's own comparison.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// `EVP_PKEY_RSA`/`EVP_PKEY_DSA` — the two ids the descriptors name.
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_DSA: c_int = 116;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_MAX_PROPQUERY_SIZE` — `internal/sizes.h`, the `propq` buffer's length.
const OSSL_MAX_PROPQUERY_SIZE: usize = 50;
/// `OSSL_OBJECT_PKEY` and the `OSSL_OBJECT_PARAM_*` names — `core_object.h`.
const OSSL_OBJECT_PKEY: c_int = 1;
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
const OSSL_OBJECT_PARAM_REFERENCE: *const c_char = c"reference".as_ptr();
/// `OSSL_DECODER_PARAM_PROPERTIES` — `core_names.h`.
const OSSL_DECODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `ERR_LIB_PEM`, `PEM_R_BAD_DECRYPT` and `PEM_R_BAD_PASSWORD_READ` — `pemerr.h:23,26`.
const ERR_LIB_PEM: u64 = 13;
const PEM_R_BAD_DECRYPT: u64 = 101;
const PEM_R_BAD_PASSWORD_READ: u64 = 104;

/// `typedef void *b2i_PVK_of_bio_pw_fn(BIO *in, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `decode_pvk2key.c:44-45`.
type B2iPvkOfBioPwFn = unsafe extern "C" fn(
    *mut Bio,
    Option<PemPasswordCb>,
    *mut c_void,
    *mut c_void,
    *const c_char,
) -> *mut c_void;
/// `typedef int check_key_fn(void *, struct pvk2key_ctx_st *ctx)` — `:42` (unused by both rows).
#[allow(dead_code)]
type CheckKeyFn = unsafe extern "C" fn(*mut c_void, *mut Pvk2keyCtx) -> c_int;
/// `typedef void adjust_key_fn(void *, struct pvk2key_ctx_st *ctx)` — `:43`.
type AdjustKeyFn = unsafe extern "C" fn(*mut c_void, *mut Pvk2keyCtx);
/// `typedef void free_key_fn(void *)` — `:46`.
type FreeKeyFn = unsafe extern "C" fn(*mut c_void);

/// `struct keytype_desc_st` — `decode_pvk2key.c:47-55`.
#[repr(C)]
struct KeytypeDesc {
    type_: c_int,
    name: *const c_char,
    fns: *const OsslDispatch,
    read_private_key: Option<B2iPvkOfBioPwFn>,
    adjust_key: Option<AdjustKeyFn>,
    free_key: Option<FreeKeyFn>,
}

// SAFETY: a descriptor is a C value whose raw pointers are `'static` tables or `'static` literals;
// every entry point that reads it is a framework callback that never mutates it.
unsafe impl Sync for KeytypeDesc {}

/// `struct pvk2key_ctx_st` — `decode_pvk2key.c:66-72`.
#[repr(C)]
pub(crate) struct Pvk2keyCtx {
    provctx: *mut c_void,
    propq: [c_char; OSSL_MAX_PROPQUERY_SIZE],
    desc: *const KeytypeDesc,
    selection: c_int,
}

/// `static struct pvk2key_ctx_st *pvk2key_newctx(void *provctx,
/// const struct keytype_desc_st *desc)` — `decode_pvk2key.c:74-84`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe fn pvk2key_newctx(provctx: *mut c_void, desc: *const KeytypeDesc) -> *mut Pvk2keyCtx {
    // SAFETY: `CRYPTO_malloc` answers a block of the struct's size or NULL.
    let ctx =
        CRYPTO_malloc(core::mem::size_of::<Pvk2keyCtx>(), ptr::null(), 0).cast::<Pvk2keyCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is this call's fresh allocation; zero it as the authority's zalloc does.
    unsafe {
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<Pvk2keyCtx>());
        (*ctx).provctx = provctx;
        (*ctx).desc = desc;
    }
    ctx
}

/// `static void pvk2key_freectx(void *vctx)` — `decode_pvk2key.c:86-91`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn pvk2key_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is this call's own allocation.
    unsafe { CRYPTO_free(vctx, ptr::null(), 0) };
}

/// `pvk2key_set_ctx_params_list[]` — the generated settable list, one `properties` string.
static PVK2KEY_SET_CTX_PARAMS_LIST: [OsslParam; 2] = [
    OsslParam {
        key: OSSL_DECODER_PARAM_PROPERTIES,
        data_type: crate::params::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: crate::params::OSSL_PARAM_UNMODIFIED,
    },
    crate::params::END,
];

/// `static const OSSL_PARAM *pvk2key_settable_ctx_params(void *provctx)` —
/// `decode_pvk2key.c:99-102`.
///
/// # Safety
/// The decoder `settable_ctx_params` dispatch contract.
unsafe extern "C" fn pvk2key_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    PVK2KEY_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int pvk2key_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `decode_pvk2key.c:104-119`.
///
/// # Safety
/// The decoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn pvk2key_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Pvk2keyCtx>();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live; `str_` borrows its buffer.
    let mut propq: *mut c_char = unsafe { (*ctx).propq.as_mut_ptr() };
    let mut p = params;
    if !p.is_null() {
        // SAFETY: `p` walks a `key == NULL`-terminated array.
        while !unsafe { (*p).key }.is_null() {
            // SAFETY: each key is NUL-terminated and the literal is too.
            if unsafe { strcmp((*p).key, OSSL_DECODER_PARAM_PROPERTIES) } == 0 {
                // SAFETY: `p` is live and `propq`/`ctx` are this frame's.
                if unsafe {
                    OSSL_PARAM_get_utf8_string(
                        p,
                        &raw mut propq,
                        core::mem::size_of_val(&(*ctx).propq),
                    )
                } == 0
                {
                    return 0;
                }
            }
            // SAFETY: the array is terminated, so the step stays within it.
            p = unsafe { p.add(1) };
        }
    }
    1
}

/// `static int pvk2key_does_selection(void *provctx, int selection)` — `decode_pvk2key.c:121-130`.
///
/// # Safety
/// The decoder `does_selection` dispatch contract.
unsafe extern "C" fn pvk2key_does_selection(_provctx: *mut c_void, selection: c_int) -> c_int {
    if selection == 0 {
        return 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        return 1;
    }
    0
}

/// `static int pvk2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `decode_pvk2key.c:132-218`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn pvk2key_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Pvk2keyCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let mut in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }
    let mut key: *mut c_void = ptr::null_mut();
    let mut ok = 0;

    // SAFETY: `ctx` is live.
    unsafe { (*ctx).selection = selection };
    // SAFETY: `ctx` is live.
    let desc = unsafe { (*ctx).desc };

    if (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        // SAFETY: `desc` is live.
        && unsafe { (*desc).read_private_key }.is_some()
    {
        // SAFETY: every bit pattern of the C struct is a valid value; the authority's `memset`.
        let mut pwdata: OsslPassphraseData = unsafe { core::mem::zeroed() };
        // SAFETY: `pwdata` is this frame's and the callback arguments are the caller's.
        if unsafe { ossl_pw_set_ossl_passphrase_cb(&raw mut pwdata, pw_cb, pw_cbarg) } == 0 {
            // SAFETY: `in_` is this decode's own.
            unsafe { BIO_free(in_) };
            // SAFETY: `desc` is live and `key` is NULL.
            unsafe { free_key(desc, key) };
            return ok;
        }

        // SAFETY: the callback was read from the live descriptor; `in_`, `pwdata` and the context
        // are this call's.
        key = unsafe {
            ((*desc).read_private_key.unwrap_unchecked())(
                in_,
                Some(ossl_pw_pvk_password),
                (&raw mut pwdata).cast::<c_void>(),
                prov_libctx_of((*ctx).provctx),
                (*ctx).propq.as_ptr(),
            )
        };

        /* Fatal errors pass through; everything else is discarded. */
        let lib = peek_last_lib();
        let reason = peek_last_reason();
        if lib == ERR_LIB_PEM && (reason == PEM_R_BAD_PASSWORD_READ || reason == PEM_R_BAD_DECRYPT)
        {
            ERR_clear_last_mark();
            // SAFETY: `in_` is this decode's own.
            unsafe { BIO_free(in_) };
            // SAFETY: `desc` is live and `key` is NULL.
            unsafe { free_key(desc, key) };
            return ok;
        }

        if selection != 0 && key.is_null() {
            // SAFETY: `in_` is this decode's own.
            unsafe { BIO_free(in_) };
            // SAFETY: `desc` is live and `key` is NULL.
            unsafe { free_key(desc, key) };
            return 1;
        }
    }

    // SAFETY: `desc` is live.
    if !key.is_null() {
        // SAFETY: `desc` is live.
        if let Some(adjust) = unsafe { (*desc).adjust_key } {
            // SAFETY: the callback was read from the live descriptor and `key` is its object.
            unsafe { adjust(key, ctx) };
        }
    }

    /* Ending up "empty handed" is not an error. */
    ok = 1;
    // SAFETY: `in_` is this decode's own.
    unsafe { BIO_free(in_) };
    in_ = ptr::null_mut();

    if !key.is_null() {
        let mut object_type = OSSL_OBJECT_PKEY;
        let mut params: [OsslParam; 4] = [crate::params::END; 4];
        // SAFETY: every constructor is called with this frame's buffers.
        unsafe {
            params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &raw mut object_type);
            params[1] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE,
                (*desc).name.cast_mut(),
                0,
            );
            /* The address of the key becomes the octet string */
            params[2] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_REFERENCE,
                (&raw mut key).cast::<c_void>(),
                core::mem::size_of::<*mut c_void>(),
            );
            params[3] = crate::params::END;
        }
        // SAFETY: `params` is terminated and `data_cbarg` is the caller's.
        ok = match data_cb {
            // SAFETY: `cb` is the framework's callback and `params` is this frame's.
            Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
            None => 0,
        };
    }

    // SAFETY: `in_` is NULL or this decode's own.
    unsafe { BIO_free(in_) };
    // SAFETY: `desc` is live and `key` is its object or NULL.
    unsafe { free_key(desc, key) };
    ok
}

/// `static void free_key(...)` as the descriptor's own destructor.
///
/// # Safety
/// `desc` live; `key` NULL or its object.
unsafe fn free_key(desc: *const KeytypeDesc, key: *mut c_void) {
    // SAFETY: `desc` is live.
    if let Some(f) = unsafe { (*desc).free_key } {
        // SAFETY: the callback was read from the live descriptor and `key` is its object.
        unsafe { f(key) };
    }
}

/// `static int pvk2key_export_object(void *vctx, const void *reference, size_t reference_sz,
/// OSSL_CALLBACK *export_cb, void *export_cbarg)` — `decode_pvk2key.c:220-239`.
///
/// # Safety
/// The decoder `export_object` dispatch contract.
unsafe extern "C" fn pvk2key_export_object(
    vctx: *mut c_void,
    reference: *const c_void,
    reference_sz: usize,
    export_cb: Option<OsslCallback>,
    export_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Pvk2keyCtx>();
    // SAFETY: `ctx`/`ctx.desc` are live.
    let desc = unsafe { (*ctx).desc };
    // SAFETY: `desc` is live.
    let export: Option<KeymgmtExportFn> = unsafe { ossl_prov_get_keymgmt_export((*desc).fns) };
    if reference_sz == core::mem::size_of::<*mut c_void>() {
        if let Some(f) = export {
            // SAFETY: `ctx` is live.
            let mut selection = unsafe { (*ctx).selection };
            if selection == 0 {
                selection = OSSL_KEYMGMT_SELECT_ALL;
            }
            // SAFETY: the reference is a `void *`; its contents are the object's address.
            let keydata = unsafe { *(reference.cast::<*mut c_void>()) };
            // SAFETY: the callback was read from the live descriptor's table and every argument is
            // the framework's.
            return unsafe { f(keydata, selection, export_cb, export_cbarg) };
        }
    }
    0
}

/// `#define dsa_private_key_bio (b2i_PVK_of_bio_pw_fn *)b2i_DSA_PVK_bio_ex`.
///
/// # Safety
/// As `b2i_DSA_PVK_bio_ex`.
unsafe extern "C" fn dsa_pvk_void(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed reader's terms.
    unsafe { b2i_DSA_PVK_bio_ex(in_, cb, u, libctx, propq).cast::<c_void>() }
}

/// `#define rsa_private_key_bio (b2i_PVK_of_bio_pw_fn *)b2i_RSA_PVK_bio_ex`.
///
/// # Safety
/// As `b2i_RSA_PVK_bio_ex`.
unsafe extern "C" fn rsa_pvk_void(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed reader's terms.
    unsafe { b2i_RSA_PVK_bio_ex(in_, cb, u, libctx, propq).cast::<c_void>() }
}

/// `static void rsa_adjust(void *key, struct pvk2key_ctx_st *ctx)` — `decode_pvk2key.c:251-254`.
///
/// # Safety
/// `key` must be a live `RSA *`; `ctx` the live context.
unsafe extern "C" fn rsa_adjust(key: *mut c_void, ctx: *mut Pvk2keyCtx) {
    // SAFETY: `ctx` is live.
    let libctx = unsafe { prov_libctx_of((*ctx).provctx) };
    // SAFETY: `key` is the RSA the decoder built.
    unsafe { ossl_rsa_set0_libctx(key.cast::<Rsa>(), libctx) };
}

/// `#define dsa_free (void (*)(void *)) DSA_free`.
///
/// # Safety
/// `key` NULL or a live `DSA *`.
unsafe extern "C" fn dsa_free_void(key: *mut c_void) {
    // SAFETY: the caller's contract, restated in the typed destructor's terms.
    unsafe { DSA_free(key.cast::<Dsa>()) };
}

/// `#define rsa_free (void (*)(void *)) RSA_free`.
///
/// # Safety
/// `key` NULL or a live `RSA *`.
unsafe extern "C" fn rsa_free_void(key: *mut c_void) {
    // SAFETY: the caller's contract, restated in the typed destructor's terms.
    unsafe { RSA_free(key.cast::<Rsa>()) };
}

/// One `IMPLEMENT_MS(KEYTYPE, keytype)` expansion (`decode_pvk2key.c:260-293`).
macro_rules! implement_ms {
    ($newctx:ident, $table:ident, $desc:ident, $ty:expr, $name:expr, $keymgmt:path, $read:ident, $adjust:expr, $free:ident) => {
        static $desc: KeytypeDesc = KeytypeDesc {
            type_: $ty,
            name: $name,
            fns: $keymgmt.as_ptr(),
            read_private_key: Some($read),
            adjust_key: $adjust,
            free_key: Some($free),
        };

        /// `pvk2<keytype>_newctx`.
        ///
        /// # Safety
        /// The decoder `newctx` dispatch contract.
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: `$desc` is a static descriptor and `provctx` is the caller's.
            unsafe { pvk2key_newctx(provctx, &$desc).cast::<c_void>() }
        }

        pub(crate) static $table: [OsslDispatch; 8] = [
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_FREECTX,
                function: pvk2key_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DOES_SELECTION,
                function: pvk2key_does_selection as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DECODE,
                function: pvk2key_decode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_EXPORT_OBJECT,
                function: pvk2key_export_object as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
                function: pvk2key_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
                function: pvk2key_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

implement_ms!(
    pvk2dsa_newctx,
    PVK_TO_DSA_DECODER_FUNCTIONS,
    PVK2DSA_DESC,
    EVP_PKEY_DSA,
    c"DSA".as_ptr(),
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    dsa_pvk_void,
    None,
    dsa_free_void
);
implement_ms!(
    pvk2rsa_newctx,
    PVK_TO_RSA_DECODER_FUNCTIONS,
    PVK2RSA_DESC,
    EVP_PKEY_RSA,
    c"RSA".as_ptr(),
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    rsa_pvk_void,
    Some(rsa_adjust),
    rsa_free_void
);
