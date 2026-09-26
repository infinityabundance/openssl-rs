//! Phase 10.1/10.6 — `providers/implementations/encode_decode/decode_msblob2key.c`: the provider's
//! **MSBLOB decoders**, one `OSSL_OP_DECODER` table for `DSA` and one for `RSA`, published by both
//! the `default` and the `base` provider.
//!
//! One of §1a's eleven row-publishing units (`2 tables`, `4 rows`). D435 held it `pending` for
//! `ossl_do_blob_header`/`ossl_blob_length`/`ossl_b2i_{DSA,RSA}_after_header`, all of which live in
//! `crypto/pem/pvkfmt.c` and 10.6 now lands.
//!
//! ## The decode is the blob header plus the type's own reader
//!
//! `msblob2key_decode` reads 16 bytes, validates them with `ossl_do_blob_header` and discards that
//! probe's errors (`ERR_set_mark`/`ERR_pop_to_mark`), checks the header's key type against the
//! table's own, computes the body's length with `ossl_blob_length`, reads it, and hands it to the
//! descriptor's `read_private_key`/`read_public_key` — `ossl_b2i_{DSA,RSA}_after_header`. `RSA`'s
//! descriptor additionally pins the resulting key's library context with `ossl_rsa_set0_libctx` in
//! its `adjust_key`. A blob whose header does not match answers "empty handed" (a successful
//! decode that yields no object), which the framework treats as "this decoder did not match".
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_DOES_SELECTION, OSSL_FUNC_DECODER_EXPORT_OBJECT,
    OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
};
use crate::dsa::object::DSA_free;
use crate::dsa::Dsa;
use crate::evp::keymgmt::KeymgmtExportFn;
use crate::evp::pkey::OSSL_KEYMGMT_SELECT_ALL;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OsslParam,
};
use crate::passphrase::{ossl_pw_set_ossl_passphrase_cb, OsslPassphraseCallback};
use crate::pem::pvkfmt::{
    ossl_b2i_DSA_after_header, ossl_b2i_RSA_after_header, ossl_blob_length, ossl_do_blob_header,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::endecoder_common::ossl_prov_get_keymgmt_export;
use crate::rsa::object::{ossl_rsa_set0_libctx, RSA_free};
use crate::rsa::Rsa;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::{BIO_free, BIO_read};
use crate::runtime::err::{err_sites, raise_site, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::selftest::OsslCallback;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY`/`_PUBLIC_KEY` — `core_dispatch.h:640-641`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `BLOB_MAX_LENGTH` — `include/crypto/pem.h:20`.
const BLOB_MAX_LENGTH: c_uint = 102400;
/// `OSSL_OBJECT_PKEY` — `core_object.h`, the object class the callback is told about.
const OSSL_OBJECT_PKEY: c_int = 1;
/// The `OSSL_OBJECT_PARAM_*` names — `core_object.h`, also spelled in `decode_epki2pki.rs`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
const OSSL_OBJECT_PARAM_REFERENCE: *const c_char = c"reference".as_ptr();

/// `typedef void *b2i_of_void_fn(const unsigned char **in, unsigned int bitlen, int ispub)` —
/// `decode_msblob2key.c:34-35`.
type B2iOfVoidFn = unsafe extern "C" fn(*mut *const u8, c_uint, c_int) -> *mut c_void;
/// `typedef void adjust_key_fn(void *, struct msblob2key_ctx_st *ctx)` — `:36`.
type AdjustKeyFn = unsafe extern "C" fn(*mut c_void, *mut Msblob2keyCtx);
/// `typedef void free_key_fn(void *)` — `:37`.
type FreeKeyFn = unsafe extern "C" fn(*mut c_void);

/// `struct keytype_desc_st` — `decode_msblob2key.c:38-47`.
#[repr(C)]
struct KeytypeDesc {
    type_: c_int,
    name: *const c_char,
    fns: *const OsslDispatch,
    read_private_key: Option<B2iOfVoidFn>,
    read_public_key: Option<B2iOfVoidFn>,
    adjust_key: Option<AdjustKeyFn>,
    free_key: Option<FreeKeyFn>,
}

// SAFETY: a descriptor is a C value whose raw pointers are `'static` tables or `'static` literals;
// every entry point that reads it is a framework callback that never mutates it.
unsafe impl Sync for KeytypeDesc {}

/// `EVP_PKEY_RSA`/`EVP_PKEY_DSA` — the two ids the descriptors name.
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_DSA: c_int = 116;

/// `struct msblob2key_ctx_st` — `decode_msblob2key.c:56-61`.
#[repr(C)]
pub(crate) struct Msblob2keyCtx {
    provctx: *mut c_void,
    desc: *const KeytypeDesc,
    selection: c_int,
}

/// `static struct msblob2key_ctx_st *msblob2key_newctx(void *provctx,
/// const struct keytype_desc_st *desc)` — `decode_msblob2key.c:63-73`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe fn msblob2key_newctx(provctx: *mut c_void, desc: *const KeytypeDesc) -> *mut Msblob2keyCtx {
    // SAFETY: `CRYPTO_zalloc` answers a zeroed block of the struct's size or NULL.
    let ctx = CRYPTO_malloc(core::mem::size_of::<Msblob2keyCtx>(), ptr::null(), 0)
        .cast::<Msblob2keyCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is this call's fresh allocation; zero it as the authority's zalloc does.
    unsafe {
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<Msblob2keyCtx>());
        (*ctx).provctx = provctx;
        (*ctx).desc = desc;
    }
    ctx
}

/// `static void msblob2key_freectx(void *vctx)` — `decode_msblob2key.c:75-80`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn msblob2key_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is this call's own allocation.
    unsafe { CRYPTO_free(vctx, ptr::null(), 0) };
}

/// `static int msblob2key_does_selection(void *provctx, int selection)` —
/// `decode_msblob2key.c:82-91`.
///
/// # Safety
/// The decoder `does_selection` dispatch contract.
unsafe extern "C" fn msblob2key_does_selection(_provctx: *mut c_void, selection: c_int) -> c_int {
    if selection == 0 {
        return 1;
    }
    if (selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) != 0 {
        return 1;
    }
    0
}

/// `static int msblob2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `decode_msblob2key.c:93-206`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn msblob2key_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Msblob2keyCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }
    let mut hdr_buf = [0u8; 16];
    let mut bitlen: c_uint = 0;
    let mut magic: c_uint = 0;
    let mut isdss: c_int = -1;
    let mut ispub: c_int = -1;
    let mut key: *mut c_void = ptr::null_mut();

    // SAFETY: `in_` is live and `hdr_buf` is 16 bytes.
    if unsafe { BIO_read(in_, hdr_buf.as_mut_ptr().cast::<c_void>(), 16) } != 16 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_DECODE_MSBLOB2KEY_111) };
        // SAFETY: `in_` is this decode's own reference.
        unsafe { BIO_free(in_) };
        return 1;
    }
    ERR_set_mark();
    let mut p: *const u8 = hdr_buf.as_ptr();
    // SAFETY: `p`/`ispub`/`isdss`/`magic`/`bitlen` are this frame's.
    let blob_ok = unsafe {
        ossl_do_blob_header(
            &raw mut p,
            16,
            &raw mut magic,
            &raw mut bitlen,
            &raw mut isdss,
            &raw mut ispub,
        )
    } > 0;
    ERR_pop_to_mark();
    if !blob_ok {
        // SAFETY: `in_` is this decode's own reference.
        unsafe { BIO_free(in_) };
        return 1;
    }

    // SAFETY: `ctx` is the caller's live context.
    unsafe { (*ctx).selection = selection };

    // SAFETY: `ctx`/`ctx.desc` are live.
    let desc = unsafe { (*ctx).desc };
    // SAFETY: `desc` is the table's own descriptor.
    let desc_type = unsafe { (*desc).type_ };
    if (isdss != 0 && desc_type != EVP_PKEY_DSA) || (isdss == 0 && desc_type != EVP_PKEY_RSA) {
        // SAFETY: `in_` is this decode's own reference.
        unsafe { BIO_free(in_) };
        return 1;
    }

    let length = ossl_blob_length(bitlen, isdss, ispub);
    if length > BLOB_MAX_LENGTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_DECODE_MSBLOB2KEY_130) };
        // SAFETY: `in_` is this decode's own reference.
        unsafe { BIO_free(in_) };
        return 1;
    }
    // SAFETY: `length` bytes as a raw allocation.
    let buf = CRYPTO_malloc(length as usize, ptr::null(), 0).cast::<u8>();
    if buf.is_null() {
        // SAFETY: `in_` is this decode's own reference.
        unsafe { BIO_free(in_) };
        return 0;
    }
    // SAFETY: `buf` holds `length` bytes and `in_` is live.
    if unsafe { BIO_read(in_, buf.cast::<c_void>(), length as c_int) } != length as c_int {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_DECODE_MSBLOB2KEY_138) };
        // SAFETY: `in_`/`buf` are this decode's own.
        unsafe {
            BIO_free(in_);
            CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0);
        }
        return 1;
    }

    if (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        && ispub == 0
        // SAFETY: `desc` is live.
        && unsafe { (*desc).read_private_key }.is_some()
    {
        // SAFETY: every bit pattern of the C struct is a valid value; the authority's `memset`.
        let mut pwdata: crate::passphrase::OsslPassphraseData = unsafe { core::mem::zeroed() };
        // SAFETY: `pwdata` is this frame's and the callback arguments are the caller's.
        if unsafe { ossl_pw_set_ossl_passphrase_cb(&raw mut pwdata, pw_cb, pw_cbarg) } == 0 {
            // SAFETY: `in_`/`buf` are this decode's own.
            unsafe {
                BIO_free(in_);
                CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0);
            }
            // SAFETY: `key` is NULL here.
            unsafe { free_key(desc, key) };
            return 0;
        }
        p = buf;
        // SAFETY: the callback was read from the live descriptor and `p`/`bitlen` are this frame's.
        key = unsafe { ((*desc).read_private_key.unwrap_unchecked())(&raw mut p, bitlen, ispub) };
        if selection != 0 && key.is_null() {
            // SAFETY: `in_`/`buf` are this decode's own.
            unsafe {
                BIO_free(in_);
                CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0);
            }
            // SAFETY: `key` is NULL.
            unsafe { free_key(desc, key) };
            return 1;
        }
    }
    if key.is_null()
        && (selection == 0 || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        && ispub != 0
        // SAFETY: `desc` is live.
        && unsafe { (*desc).read_public_key }.is_some()
    {
        p = buf;
        // SAFETY: the callback was read from the live descriptor and `p`/`bitlen` are this frame's.
        key = unsafe { ((*desc).read_public_key.unwrap_unchecked())(&raw mut p, bitlen, ispub) };
        if selection != 0 && key.is_null() {
            // SAFETY: `in_`/`buf` are this decode's own.
            unsafe {
                BIO_free(in_);
                CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0);
            }
            // SAFETY: `key` is NULL.
            unsafe { free_key(desc, key) };
            return 1;
        }
    }

    // SAFETY: `desc` is live and `key` is its object or NULL.
    if !key.is_null() {
        // SAFETY: `desc` is live.
        if let Some(adjust) = unsafe { (*desc).adjust_key } {
            // SAFETY: the callback was read from the live descriptor and `key` is its object.
            unsafe { adjust(key, ctx) };
        }
    }

    /* Ending up "empty handed" is not an error. */
    let mut ok = 1;
    // SAFETY: `in_`/`buf` are this decode's own.
    unsafe {
        BIO_free(in_);
        CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0);
    }

    if !key.is_null() {
        let mut object_type = OSSL_OBJECT_PKEY;
        let mut params: [OsslParam; 4] = [OSSL_PARAM_construct_end(); 4];
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
            params[3] = OSSL_PARAM_construct_end();
        }
        // SAFETY: `params` is terminated and `data_cbarg` is the caller's.
        ok = match data_cb {
            // SAFETY: `cb` is the framework's callback and `params` is this frame's.
            Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
            None => 0,
        };
        // The ownership of `key` moved into the callback's exported copy; release ours.
        // SAFETY: `key` is this decode's object and `desc` its destructor.
        unsafe { free_key(desc, key) };
    }
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

/// `static void free_key(...)` as the descriptor's own destructor.
/// `static int msblob2key_export_object(void *vctx, const void *reference, size_t reference_sz,
/// OSSL_CALLBACK *export_cb, void *export_cbarg)` — `decode_msblob2key.c:208-228`.
///
/// # Safety
/// The decoder `export_object` dispatch contract.
unsafe extern "C" fn msblob2key_export_object(
    vctx: *mut c_void,
    reference: *const c_void,
    reference_sz: usize,
    export_cb: Option<OsslCallback>,
    export_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Msblob2keyCtx>();
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
            // SAFETY: the reference is a `void *`; the contents are the address of the object.
            let keydata = unsafe { *(reference.cast::<*mut c_void>()) };
            // SAFETY: the callback was read from the live descriptor's table and every argument is
            // the framework's.
            return unsafe { f(keydata, selection, export_cb, export_cbarg) };
        }
    }
    0
}

/// `static void rsa_adjust(void *key, struct msblob2key_ctx_st *ctx)` —
/// `decode_msblob2key.c:242-245`.
///
/// # Safety
/// `key` must be a live `RSA *`; `ctx` the live context.
unsafe extern "C" fn rsa_adjust(key: *mut c_void, ctx: *mut Msblob2keyCtx) {
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

/// `#define dsa_decode_private_key (b2i_of_void_fn *)ossl_b2i_DSA_after_header`.
///
/// # Safety
/// As `ossl_b2i_DSA_after_header`.
unsafe extern "C" fn dsa_decode_void(
    in_: *mut *const u8,
    bitlen: c_uint,
    ispub: c_int,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed reader's terms.
    unsafe { ossl_b2i_DSA_after_header(in_, bitlen, ispub).cast::<c_void>() }
}

/// `#define rsa_decode_private_key (b2i_of_void_fn *)ossl_b2i_RSA_after_header`.
///
/// # Safety
/// As `ossl_b2i_RSA_after_header`.
unsafe extern "C" fn rsa_decode_void(
    in_: *mut *const u8,
    bitlen: c_uint,
    ispub: c_int,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed reader's terms.
    unsafe { ossl_b2i_RSA_after_header(in_, bitlen, ispub).cast::<c_void>() }
}

/// One `IMPLEMENT_MSBLOB(KEYTYPE, keytype)` expansion (`decode_msblob2key.c:251-279`).
macro_rules! implement_msblob {
    ($newctx:ident, $table:ident, $desc:ident, $ty:expr, $name:expr, $keymgmt:path, $read:ident, $adjust:expr, $free:ident) => {
        static $desc: KeytypeDesc = KeytypeDesc {
            type_: $ty,
            name: $name,
            fns: $keymgmt.as_ptr(),
            read_private_key: Some($read),
            read_public_key: Some($read),
            adjust_key: $adjust,
            free_key: Some($free),
        };

        /// `msblob2<keytype>_newctx`.
        ///
        /// # Safety
        /// The decoder `newctx` dispatch contract.
        unsafe extern "C" fn $newctx(provctx: *mut c_void) -> *mut c_void {
            // SAFETY: `$desc` is a static descriptor and `provctx` is the caller's.
            unsafe { msblob2key_newctx(provctx, &$desc).cast::<c_void>() }
        }

        pub(crate) static $table: [OsslDispatch; 6] = [
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_NEWCTX,
                function: $newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_FREECTX,
                function: msblob2key_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DOES_SELECTION,
                function: msblob2key_does_selection as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DECODE,
                function: msblob2key_decode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_EXPORT_OBJECT,
                function: msblob2key_export_object as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

implement_msblob!(
    msblob2dsa_newctx,
    MSBLOB_TO_DSA_DECODER_FUNCTIONS,
    MSTYPE2DSA_DESC,
    EVP_PKEY_DSA,
    c"DSA".as_ptr(),
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    dsa_decode_void,
    None,
    dsa_free_void
);
implement_msblob!(
    msblob2rsa_newctx,
    MSBLOB_TO_RSA_DECODER_FUNCTIONS,
    MSTYPE2RSA_DESC,
    EVP_PKEY_RSA,
    c"RSA".as_ptr(),
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    rsa_decode_void,
    Some(rsa_adjust),
    rsa_free_void
);
