//! Phase 10.16 — `providers/implementations/storemgmt/file_store_any2obj.c`: the `file:` store's
//! **private last-resort decoder**. Three `OSSL_OP_DECODER` rows collected into one table,
//! `ossl_any_to_obj_algorithm[]`: `obj` under `input=DER`, `input=MSBLOB` and `input=PVK`.
//!
//! This unit has no `store.h` export and publishes no provider row of its own; it is the decoder
//! `file_store.c`'s `file_setup_decoders` registers as the **last** entry of its chain, so that a
//! DER (or MSBLOB/PVK) blob no other decoder recognises is still handed on as an *object
//! abstraction* (`OSSL_OBJECT_PARAM_TYPE`/`DATA`) for `store_result.c` to classify. `file_store.c`
//! reaches `ossl_any_to_obj_algorithm` directly, which is why the two units are one slice: this
//! table is unwired without the store engine that walks it.
//!
//! **Its whole closure is landed**, which is what makes it landable at all: `asn1_d2i_read_bio`
//! (`src/asn1/a_d2i_fp.rs`), `ossl_do_blob_header`/`ossl_blob_length`/`ossl_do_PVK_header` and
//! `BLOB_MAX_LENGTH`'s check (`src/pem/pvkfmt.rs`, D354/D355), `ossl_bio_new_from_core_bio`
//! (`src/runtime/bio/core_bio.rs`), the `BUF_MEM_*` layer (`src/runtime/buffer.rs`) and the
//! `OSSL_PARAM_construct_*` family (`src/params/`).
//!
//! **The three decoders differ only in their framing.** `der2obj_decode` reads one top-level DER
//! object; `msblob2obj_decode` and `pvk2obj_decode` read a fixed 16-/24-byte header, call the
//! `pvkfmt.c` header parser to learn whether the blob is DSS or RSA and how many key bytes follow,
//! and read exactly that much. All three end in `any2obj_decode_final`, which builds the parameter
//! set and calls the store's `data_cb`; the decoder **frees the `BUF_MEM` it was handed**, so the
//! three engines hand off ownership rather than leaking it.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::asn1_d2i_read_bio;
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string, OsslParam, END,
};
use crate::pem::pvkfmt::{ossl_blob_length, ossl_do_PVK_header, ossl_do_blob_header};
use crate::provider::activate::OsslAlgorithm;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::{BIO_free, BIO_read};
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new, BufMem};
use crate::runtime::err::{
    err_sites, raise_site, raise_site_dynamic, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::selftest::OsslCallback;

/// `OSSL_MAX_CODEC_STRUCT_SIZE` — `include/internal/sizes.h`, the fixed capacity of the
/// `data_structure` buffer every codec context carries.
const OSSL_MAX_CODEC_STRUCT_SIZE: usize = 32;

/// `BLOB_MAX_LENGTH` — `include/crypto/pem.h:20`, the largest MSBLOB body `msblob2obj_decode`
/// will read. The authority's `pvkfmt.c` defines its own copy for the same bound; this unit
/// re-declares it because it is the check's owner here (`file_store_any2obj.c:238`).
const BLOB_MAX_LENGTH: c_uint = 102400;

/// `OSSL_OBJECT_UNKNOWN` — `include/openssl/core_object.h:27`. `der2obj_decode` announces the
/// bytes as an unknown object and leaves classification to the store's result handler.
const OSSL_OBJECT_UNKNOWN: c_int = 0;
/// `OSSL_OBJECT_PKEY` — `include/openssl/core_object.h:29`. The MSBLOB and PVK engines announce a
/// key object.
const OSSL_OBJECT_PKEY: c_int = 2;

/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `include/openssl/core_names.h`, the string
/// `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_INPUT_TYPE` — the string `"input-type"`.
const OSSL_OBJECT_PARAM_INPUT_TYPE: *const c_char = c"input-type".as_ptr();
/// `OSSL_OBJECT_PARAM_TYPE` — the string `"type"`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();

/// `struct any2obj_ctx_st` — `file_store_any2obj.c:54-57`.
#[repr(C)]
struct Any2objCtx {
    /// `PROV_CTX *provctx`.
    provctx: *mut c_void,
    /// `char data_structure[OSSL_MAX_CODEC_STRUCT_SIZE]`.
    data_structure: [c_char; OSSL_MAX_CODEC_STRUCT_SIZE],
}

/// `static void *any2obj_newctx(void *provctx)` — `file_store_any2obj.c:59-66`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe extern "C" fn any2obj_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the constructor asks only for a zeroed block of the object's size.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<Any2objCtx>(), ptr::null(), 0).cast::<Any2objCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is this call's fresh allocation.
        unsafe { (*ctx).provctx = provctx };
    }
    ctx.cast::<c_void>()
}

/// `static void any2obj_freectx(void *ctx)` — `file_store_any2obj.c:68-71`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn any2obj_freectx(ctx: *mut c_void) {
    // SAFETY: `ctx` is this unit's own allocation.
    unsafe { CRYPTO_free(ctx, ptr::null(), 0) };
}

/// `struct any2obj_set_ctx_params_st` — `file_store_any2obj.c:82-86`, the `paramnames.pm`
/// expansion.
struct Any2objSetCtxParams {
    /// `OSSL_PARAM *datastruct` — the located `data-structure` descriptor.
    datastruct: *const OsslParam,
}

/// `any2obj_set_ctx_params_list[]` — `file_store_any2obj.c:75-80`: one `data-structure` string.
static ANY2OBJ_SET_CTX_PARAMS_LIST: [OsslParam; 2] = [
    OsslParam {
        key: OSSL_OBJECT_PARAM_DATA_STRUCTURE,
        data_type: crate::params::OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: crate::params::OSSL_PARAM_UNMODIFIED,
    },
    END,
];

/// `static int any2obj_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// any2obj_set_ctx_params_st *r)` — `file_store_any2obj.c:89-107`.
///
/// The `paramnames.pm` expansion for the one name this decoder knows. A repeated
/// `data-structure` raises `PROV_R_REPEATED_PARAMETER` at the second occurrence and refuses.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array.
unsafe fn any2obj_set_ctx_params_decoder(params: *const OsslParam) -> Option<Any2objSetCtxParams> {
    let mut r = Any2objSetCtxParams {
        datastruct: ptr::null(),
    };
    if params.is_null() {
        return Some(r);
    }
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            if core::ffi::CStr::from_ptr((*p).key).to_bytes() == b"data-structure" {
                if !r.datastruct.is_null() {
                    raise_site(&err_sites::PROV_FILE_STORE_ANY2OBJ_100);
                    return None;
                }
                r.datastruct = p;
            }
            p = p.add(1);
        }
    }
    Some(r)
}

/// `static int any2obj_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `file_store_any2obj.c:112-128`.
///
/// # Safety
/// The decoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn any2obj_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Any2objCtx>();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `params` is the contract's array.
    let Some(p) = (unsafe { any2obj_set_ctx_params_decoder(params) }) else {
        return 0;
    };
    // SAFETY: `ctx` is live; `str_` borrows its `data_structure` buffer.
    let mut str_: *mut c_char = unsafe { (*ctx).data_structure.as_mut_ptr() };
    if !p.datastruct.is_null() {
        // SAFETY: `p.datastruct` is a live descriptor in `params`; `str_` is this context's.
        let ok = unsafe {
            OSSL_PARAM_get_utf8_string(
                p.datastruct,
                &mut str_,
                core::mem::size_of::<[c_char; OSSL_MAX_CODEC_STRUCT_SIZE]>(),
            )
        };
        if ok == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *any2obj_settable_ctx_params(void *provctx)` —
/// `file_store_any2obj.c:130-133`.
///
/// # Safety
/// The decoder `settable_ctx_params` dispatch contract.
unsafe extern "C" fn any2obj_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    ANY2OBJ_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int any2obj_decode_final(void *vctx, int objtype, const char *input_type, const char
/// *data_type, BUF_MEM *mem, OSSL_CALLBACK *data_cb, void *data_cbarg)` —
/// `file_store_any2obj.c:135-167`.
///
/// Builds up to six parameter descriptors and hands them to the store's callback. It **frees
/// `mem`** — the three engines above hand off ownership — and an "empty handed" call (a NULL
/// `mem`) is success, not an error.
///
/// # Safety
/// `vctx` is a live `Any2objCtx` or the callback contract permits its absence; the string
/// pointers are NULL or NUL-terminated; `mem` is NULL or a `BUF_MEM` this call may free.
unsafe fn any2obj_decode_final(
    vctx: *mut c_void,
    objtype: c_int,
    input_type: *const c_char,
    data_type: *const c_char,
    mem: *mut BufMem,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Any2objCtx>();
    // "1 indicates that we successfully decoded something, or not at all."
    let mut ok: c_int = 1;
    if !mem.is_null() {
        // Five payload descriptors plus the terminator, exactly as the authority's `[6]` is.
        let mut params = [END; 6];
        let mut p = 0usize;
        if !data_type.is_null() {
            // SAFETY: `data_type` is NUL-terminated per the contract.
            params[p] = unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_TYPE,
                    data_type.cast_mut(),
                    0,
                )
            };
            p += 1;
        }
        if !input_type.is_null() {
            // SAFETY: `input_type` is NUL-terminated per the contract.
            params[p] = unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_OBJECT_PARAM_INPUT_TYPE,
                    input_type.cast_mut(),
                    0,
                )
            };
            p += 1;
        }
        // SAFETY: `ctx` is live; `data_structure` is NUL-terminated or empty.
        if unsafe { *(*ctx).data_structure.as_ptr() != 0 } {
            // SAFETY: `ctx`'s buffer is NUL-terminated if non-empty.
            params[p] = unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                    (*ctx).data_structure.as_mut_ptr(),
                    0,
                )
            };
            p += 1;
        }
        // The authority's descriptor points at its own `objtype` parameter; the local keeps it
        // live across the callback.
        let mut objtype_holder = objtype;
        // SAFETY: `objtype_holder` is a live local for the descriptor's lifetime.
        params[p] =
            unsafe { OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &mut objtype_holder) };
        p += 1;
        // SAFETY: `mem` is live and its data is readable for `length`.
        params[p] = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_DATA,
                (*mem).data.cast(),
                (*mem).length,
            )
        };
        p += 1;
        params[p] = OSSL_PARAM_construct_end();
        if let Some(cb) = data_cb {
            // SAFETY: `params` is a `key`-terminated array live across the call; `data_cbarg` is
            // the caller's.
            ok = unsafe { cb(params.as_ptr(), data_cbarg) };
        }
        // SAFETY: the engines above transferred `mem` to this call.
        unsafe { BUF_MEM_free(mem) };
    }
    ok
}

/// `static int der2obj_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `file_store_any2obj.c:170-194`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn der2obj_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    _selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    _pw_cb: *mut c_void,
    _pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Any2objCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }
    let mut mem: *mut BufMem = ptr::null_mut();
    // SAFETY: `in_` is live and `mem` is this frame's out-parameter.
    ERR_set_mark();
    // SAFETY: `in_` is live; the read owns nothing on failure.
    let ok = unsafe { asn1_d2i_read_bio(in_, &mut mem) } >= 0;
    // SAFETY: the mark above is this frame's.
    ERR_pop_to_mark();
    if !ok && !mem.is_null() {
        // SAFETY: `mem` was allocated by the failed read and is this call's to free.
        unsafe { BUF_MEM_free(mem) };
        mem = ptr::null_mut();
    }
    // SAFETY: `in_` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(in_) };

    // "any2obj_decode_final() frees |mem| for us"
    // SAFETY: `ctx` is live; the strings are NULL; `mem` is this call's.
    unsafe {
        any2obj_decode_final(
            ctx.cast(),
            OSSL_OBJECT_UNKNOWN,
            ptr::null(),
            ptr::null(),
            mem,
            data_cb,
            data_cbarg,
        )
    }
}

/// `static int msblob2obj_decode(...)` — `file_store_any2obj.c:196-268`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
// The authority's two dead `ok = 0` stores and its second `mem_len += mem_want` are kept
// verbatim; they are unreachable reads, so the compiler would otherwise refuse the build.
#[allow(unused_assignments)]
unsafe extern "C" fn msblob2obj_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    _selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    _pw_cb: *mut c_void,
    _pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Any2objCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    let mut mem: *mut BufMem = ptr::null_mut();
    let mut mem_len: usize = 0;
    let mut mem_want: usize;
    let mut p: *const c_uchar;
    let mut bitlen: c_uint = 0;
    let mut magic: c_uint = 0;
    let mut isdss: c_int = -1;
    let mut ispub: c_int = -1;
    let mut ok = false;

    if in_.is_null() {
        // SAFETY: `in_` is NULL and `mem` is NULL.
        return unsafe { msblob2obj_err(in_, mem) };
    }

    mem_want = 16; /* The size of the MSBLOB header */
    // SAFETY: `CRYPTO_*` allocate `mem_want` bytes; `mem` owns the result.
    unsafe {
        mem = BUF_MEM_new();
        if mem.is_null() || BUF_MEM_grow(mem, mem_want) == 0 {
            raise_site(&err_sites::PROV_FILE_STORE_ANY2OBJ_217);
            return msblob2obj_err(in_, mem);
        }
    }

    // SAFETY: `in_` is live; `mem` has `mem_want` writable bytes; the mark is this frame's.
    unsafe {
        ERR_set_mark();
        ok = BIO_read(in_, (*mem).data.cast(), mem_want as c_int) == mem_want as c_int;
        mem_len += mem_want;
        ERR_pop_to_mark();
    }
    if !ok {
        // SAFETY: `in_`/`mem` are this call's; `ok == false` frees `mem`.
        unsafe { BIO_free(in_) };
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        mem = ptr::null_mut();
        // SAFETY: `ctx` is live; a NULL `mem` is "empty handed".
        return unsafe {
            any2obj_decode_final(
                ctx.cast(),
                OSSL_OBJECT_PKEY,
                c"msblob".as_ptr(),
                if isdss != 0 {
                    c"DSA".as_ptr()
                } else {
                    c"RSA".as_ptr()
                },
                mem,
                data_cb,
                data_cbarg,
            )
        };
    }

    // SAFETY: `mem` has 16 readable bytes; `p` walks them; the removes are out-parameters.
    unsafe {
        ERR_set_mark();
        p = (*mem).data.cast::<c_uchar>();
        ok = ossl_do_blob_header(&mut p, 16, &mut magic, &mut bitlen, &mut isdss, &mut ispub) > 0;
        ERR_pop_to_mark();
    }
    if !ok {
        // SAFETY: `in_`/`mem` are this call's.
        unsafe { BIO_free(in_) };
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        // SAFETY: `ctx` is live; a NULL `mem` is "empty handed".
        return unsafe {
            any2obj_decode_final(
                ctx.cast(),
                OSSL_OBJECT_PKEY,
                c"msblob".as_ptr(),
                if isdss != 0 {
                    c"DSA".as_ptr()
                } else {
                    c"RSA".as_ptr()
                },
                ptr::null_mut(),
                data_cb,
                data_cbarg,
            )
        };
    }

    ok = false;
    // SAFETY: pure arithmetic.
    mem_want = ossl_blob_length(bitlen, isdss, ispub) as usize;

    if mem_want as c_uint > BLOB_MAX_LENGTH {
        // SAFETY: `in_`/`mem` are this call's.
        unsafe { BIO_free(in_) };
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        // SAFETY: `ctx` is live; a NULL `mem` is "empty handed".
        return unsafe {
            any2obj_decode_final(
                ctx.cast(),
                OSSL_OBJECT_PKEY,
                c"msblob".as_ptr(),
                if isdss != 0 {
                    c"DSA".as_ptr()
                } else {
                    c"RSA".as_ptr()
                },
                ptr::null_mut(),
                data_cb,
                data_cbarg,
            )
        };
    }
    // SAFETY: `mem` is live; growing preserves its contents and reports failure with 0.
    if unsafe { BUF_MEM_grow(mem, mem_len + mem_want) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_FILE_STORE_ANY2OBJ_242) };
        // SAFETY: `in_`/`mem` are this call's.
        return unsafe { msblob2obj_err(in_, mem) };
    }

    // SAFETY: `mem` has room for `mem_want` bytes at `mem_len`; `in_` is live.
    unsafe {
        ERR_set_mark();
        ok = BIO_read(in_, (*mem).data.add(mem_len).cast(), mem_want as c_int) == mem_want as c_int;
        mem_len += mem_want;
        ERR_pop_to_mark();
    }

    // SAFETY: `in_` is this call's.
    unsafe { BIO_free(in_) };
    if !ok {
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        mem = ptr::null_mut();
    }
    // SAFETY: `ctx` is live; `mem` is this call's or NULL.
    unsafe {
        any2obj_decode_final(
            ctx.cast(),
            OSSL_OBJECT_PKEY,
            c"msblob".as_ptr(),
            if isdss != 0 {
                c"DSA".as_ptr()
            } else {
                c"RSA".as_ptr()
            },
            mem,
            data_cb,
            data_cbarg,
        )
    }
}

/// The `err:` arm of `msblob2obj_decode` (`file_store_any2obj.c:264-267`): free both and fail.
///
/// # Safety
/// `in_` and `mem` are NULL or owned by this call.
unsafe fn msblob2obj_err(in_: *mut crate::runtime::bio::Bio, mem: *mut BufMem) -> c_int {
    // SAFETY: the two resources are this call's.
    unsafe {
        BIO_free(in_);
        BUF_MEM_free(mem);
    }
    0
}

/// `static int pvk2obj_decode(...)` — `file_store_any2obj.c:270-336`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
// The authority's dead `ok = 0` store and second `mem_len += mem_want` are kept verbatim; see the
// sibling above.
#[allow(unused_assignments)]
unsafe extern "C" fn pvk2obj_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    _selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    _pw_cb: *mut c_void,
    _pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Any2objCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    let mut mem: *mut BufMem = ptr::null_mut();
    let mut mem_len: usize = 0;
    let mut mem_want: usize;
    let mut p: *const c_uchar;
    let mut saltlen: c_uint = 0;
    let mut keylen: c_uint = 0;
    let mut ok = false;
    let mut isdss: c_int = -1;

    if in_.is_null() {
        // SAFETY: `in_` is NULL and `mem` is NULL.
        return unsafe { msblob2obj_err(in_, mem) };
    }

    mem_want = 24; /* The size of the PVK header */
    // SAFETY: `mem` owns its allocation.
    unsafe {
        mem = BUF_MEM_new();
        if mem.is_null() || BUF_MEM_grow(mem, mem_want) == 0 {
            raise_site(&err_sites::PROV_FILE_STORE_ANY2OBJ_289);
            return msblob2obj_err(in_, mem);
        }
    }

    // SAFETY: `in_` is live; `mem` has 24 writable bytes.
    unsafe {
        ERR_set_mark();
        ok = BIO_read(in_, (*mem).data.cast(), mem_want as c_int) == mem_want as c_int;
        mem_len += mem_want;
        ERR_pop_to_mark();
    }
    if !ok {
        // SAFETY: `in_` and `mem` are this call's.
        unsafe { BIO_free(in_) };
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        // SAFETY: `ctx` is live; NULL `mem` is "empty handed".
        return unsafe {
            any2obj_decode_final(
                ctx.cast(),
                OSSL_OBJECT_PKEY,
                c"pvk".as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                data_cb,
                data_cbarg,
            )
        };
    }

    // SAFETY: `mem` has 24 readable bytes; the out-parameters are this frame's.
    unsafe {
        ERR_set_mark();
        p = (*mem).data.cast::<c_uchar>();
        ok = ossl_do_PVK_header(&mut p, 24, 0, &mut isdss, &mut saltlen, &mut keylen) > 0;
        ERR_pop_to_mark();
    }
    if !ok {
        // SAFETY: `in_`/`mem` are this call's.
        unsafe { BIO_free(in_) };
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        // SAFETY: `ctx` is live; NULL `mem` is "empty handed".
        return unsafe {
            any2obj_decode_final(
                ctx.cast(),
                OSSL_OBJECT_PKEY,
                c"pvk".as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                data_cb,
                data_cbarg,
            )
        };
    }

    ok = false;
    // SAFETY: pure arithmetic.
    mem_want = saltlen as usize + keylen as usize;
    // SAFETY: `mem` is live.
    if unsafe { BUF_MEM_grow(mem, mem_len + mem_want) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_FILE_STORE_ANY2OBJ_310) };
        // SAFETY: `in_`/`mem` are this call's.
        return unsafe { msblob2obj_err(in_, mem) };
    }

    // SAFETY: `mem` has room for `mem_want` bytes at `mem_len`; `in_` is live.
    unsafe {
        ERR_set_mark();
        ok = BIO_read(in_, (*mem).data.add(mem_len).cast(), mem_want as c_int) == mem_want as c_int;
        mem_len += mem_want;
        ERR_pop_to_mark();
    }

    // SAFETY: `in_` is this call's.
    unsafe { BIO_free(in_) };
    if !ok {
        // SAFETY: `mem` is this call's.
        unsafe { BUF_MEM_free(mem) };
        mem = ptr::null_mut();
    }
    // SAFETY: `ctx` is live; `mem` is this call's or NULL. A failed read passes "pvk" with NULL
    // data type, exactly as the authority's `ok ? (isdss ? "DSA" : "RSA") : NULL` does.
    unsafe {
        any2obj_decode_final(
            ctx.cast(),
            OSSL_OBJECT_PKEY,
            c"pvk".as_ptr(),
            if ok {
                if isdss != 0 {
                    c"DSA".as_ptr()
                } else {
                    c"RSA".as_ptr()
                }
            } else {
                ptr::null()
            },
            mem,
            data_cb,
            data_cbarg,
        )
    }
}

/// `der_to_obj_decoder_functions[]` — `file_store_any2obj.c:338-350`'s `MAKE_DECODER(der, …)`.
pub(crate) static DER_TO_OBJ_DECODER_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: any2obj_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: any2obj_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: der2obj_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: any2obj_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: any2obj_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `msblob_to_obj_decoder_functions[]` — `file_store_any2obj.c:351`'s `MAKE_DECODER(msblob, …)`.
pub(crate) static MSBLOB_TO_OBJ_DECODER_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: any2obj_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: any2obj_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: msblob2obj_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: any2obj_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: any2obj_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `pvk_to_obj_decoder_functions[]` — `file_store_any2obj.c:352`'s `MAKE_DECODER(pvk, …)`.
pub(crate) static PVK_TO_OBJ_DECODER_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: any2obj_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: any2obj_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: pvk2obj_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: any2obj_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: any2obj_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_ALGORITHM ossl_any_to_obj_algorithm[]` — `file_store_any2obj.c:354-361`.
///
/// Three rows and the terminator; the property strings are the authority's (`input=DER`,
/// `input=MSBLOB`, `input=PVK`). `file_store.c`'s `file_setup_decoders` walks this table to build
/// its chain, which is why the symbol keeps its authority name.
#[no_mangle]
pub static mut ossl_any_to_obj_algorithm: [OsslAlgorithm; 4] = [
    OsslAlgorithm {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=DER".as_ptr(),
        implementation: DER_TO_OBJ_DECODER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=MSBLOB".as_ptr(),
        implementation: MSBLOB_TO_OBJ_DECODER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"obj".as_ptr(),
        property_definition: c"input=PVK".as_ptr(),
        implementation: PVK_TO_OBJ_DECODER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

// The two dynamic-reason helpers are imported for symmetry with the units that compute an errno
// reason; this unit's `ERR_LIB_SYS` sites are `file_store.c`'s, not its own.
#[allow(unused_imports)]
use raise_site_dynamic as _raise_site_dynamic_used;

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the authority's three-row shape with the terminator, and each row carries the
    /// `input=` property the authority's `input=DER`/`input=MSBLOB`/`input=PVK` literals spell.
    #[test]
    fn the_algorithm_table_is_the_authoritys_three_rows() {
        // SAFETY: the table is a `'static` value terminated by a NULL name; `addr_of!` does not
        // create a reference to the mutable static.
        unsafe {
            let base = core::ptr::addr_of!(ossl_any_to_obj_algorithm).cast::<OsslAlgorithm>();
            let props = ["input=DER", "input=MSBLOB", "input=PVK"];
            for (i, want) in props.iter().enumerate() {
                let row = &*base.add(i);
                assert!(
                    core::ffi::CStr::from_ptr(row.algorithm_names).to_bytes() == b"obj",
                    "row {i} does not name `obj`"
                );
                assert_eq!(
                    core::ffi::CStr::from_ptr(row.property_definition).to_bytes(),
                    want.as_bytes()
                );
                assert!(
                    !row.implementation.is_null(),
                    "row {i} has no dispatch table"
                );
            }
            assert!(
                (*base.add(3)).algorithm_names.is_null(),
                "the array is not terminated"
            );
        }
    }
}
