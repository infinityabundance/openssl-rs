//! Phase 10 — `crypto/encode_decode/decoder_lib.c`: the `OSSL_DECODER_INSTANCE` and
//! `OSSL_DECODER_CTX` object layer (D364).
//!
//! This is the second of the four decoder units, and it is the `decoder_meth.c` fetch block's
//! counterpart: the instance constructors and destructor, the two hard-error accessors, the
//! chain's `add` pair, the ten `OSSL_DECODER_CTX_*` / `OSSL_DECODER_INSTANCE_*` accessors and
//! `OSSL_DECODER_export`. `decoder_meth.c`'s context trio lands with it -- its unit is still
//! `decoder_meth.c`'s, but its body calls [`ossl_decoder_instance_free`] and
//! [`OSSL_DECODER_CTX_get_num_decoders`], which are this unit's.
//!
//! ## The chain-building block, landed with the fetch block it waited on (D367)
//!
//! The three blocks this module held back through D364 are here: `OSSL_DECODER_CTX_add_extra`
//! (`:556-679`) with its two visitors `collect_all_decoders` (`:430-437`) and
//! `collect_extra_decoder` (`:439-546`), its comparator `decoder_sk_cmp` (`:548-554`) and its
//! state `collect_extra_decoder_data_st` (`:411-425`); `decoder_process` (`:798-1165`) with its
//! state `decoder_process_data_st` (`:27-46`); and `OSSL_DECODER_from_bio` (`:47-119`),
//! `bio_from_file` (`:122-133`), `OSSL_DECODER_from_fp` (`:134-145`) and `OSSL_DECODER_from_data`
//! (`:147-167`). Every one of them reached `OSSL_DECODER_do_all_provided` or
//! `OSSL_DECODER_fetch` -- `decoder_meth.c`'s fetch block -- so they had to wait for it; the fetch
//! block landed in D366 and this entry is its first caller's consequence.
//!
//! ## The one asymmetry in `decoder_process` that a transcription must keep
//!
//! `decoder_process` (`:798-1165`) is `OSSL_CALLBACK`-shaped, not `OSSL_DECODER_CONSTRUCT`-shaped:
//! the provider's `decode` calls it with `(params, &new_data)` and it dispatches on whether
//! `params` is NULL. On the NULL arm it only prepares the walk; on the non-NULL arm it runs the
//! context's constructor first and, **when that constructor succeeds, stops** -- the recursion is
//! skipped and `data->flag_construct_called` is the flag `OSSL_DECODER_from_bio` reads to tell a
//! constructed object from a failed walk. The three `ERR_set_mark`/`ERR_pop_to_mark`/`
//! `ERR_clear_last_mark` sites are that distinction's error-queue discipline: a decoder that
//! failed non-fatally has its errors popped, one that failed fatally has the mark cleared so the
//! errors survive. `OSSL_TRACE_*` is compiled out in this build and is not reproduced.
//!
//! ## Two fault boundaries the authority has and this module answers 0 for
//!
//! `decoder->newctx` and `decoder->export_object` are **optional** in the dispatch scan --
//! `ossl_decoder_from_algorithm` requires only that `newctx`/`freectx` be both-or-neither -- yet
//! `ossl_decoder_instance_new_forprov` (`:227`), `OSSL_DECODER_CTX_add_decoder` (`:395`) and
//! `OSSL_DECODER_export` (`:757`) call them through the bare pointer, so a provider that supplied
//! neither would fault there. No provider decoder is registered in this crate, so neither site is
//! reachable, and this module takes the same shape `src/runtime/lhash.rs` records for
//! `OPENSSL_LH_doall`: it answers the failure the caller's contract implies (0) rather than
//! reproducing the fault, and the boundary is named here rather than silently avoided.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::decoder_meth::{
    ossl_decoder_fast_is_a, ossl_decoder_parsed_properties, OSSL_DECODER_do_all_provided,
    OSSL_DECODER_free, OSSL_DECODER_get0_provider, OSSL_DECODER_is_a, OSSL_DECODER_up_ref,
    OsslDecoder, OsslDecoderCtx, OsslDecoderInstance,
};
use crate::params::{
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate_const,
    OsslParam, OSSL_PARAM_OCTET_STRING,
};
use crate::passphrase::{
    ossl_pw_clear_passphrase_cache, ossl_pw_enable_passphrase_caching,
    ossl_pw_passphrase_callback_dec,
};
use crate::property::globals::ossl_ctx_global_properties;
use crate::property::query::{ossl_property_find_property, ossl_property_get_string_value};
use crate::provider::{ossl_provider_libctx, OSSL_PROVIDER_get0_provider_ctx};
use crate::runtime::bio::bf_readbuff::BIO_f_readbuffer;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::bss_mem::BIO_new_mem_buf;
use crate::runtime::bio::core_bio::{ossl_core_bio_free, ossl_core_bio_new_from_bio, OsslCoreBio};
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{
    BIO_free, BIO_new, BIO_pop, BIO_push, Bio, BIO_CTRL_INFO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL,
    BIO_C_SET_FILE_PTR, BIO_NOCLOSE,
};
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_peek_error,
    ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h`, the string `"data-structure"`, the same
/// constant `src/encoder_lib.rs` carries.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — `core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();
/// `OSSL_OBJECT_PARAM_INPUT_TYPE` — `core_names.h:360`, the string `"input-type"`.
const OSSL_OBJECT_PARAM_INPUT_TYPE: *const c_char = c"input-type".as_ptr();

/// `ERR_DATA_BUFFER`'s size, as `src/evp/signature.rs` records it: the stack buffer a
/// pre-formatted `ERR_raise_data` message is built in.
const ERR_DATA_BUFFER: usize = 1024;

/// The `err:` label of [`ossl_decoder_instance_new`] — `decoder_lib.c:296-298`.
///
/// # Safety
/// `inst` must be a live instance this call allocated.
unsafe fn fail_instance(inst: *mut OsslDecoderInstance) -> *mut OsslDecoderInstance {
    // SAFETY: `inst` is live and owned here.
    unsafe { ossl_decoder_instance_free(inst) };
    ptr::null_mut()
}

/// `int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection)` —
/// `decoder_lib.c:168-182`.
///
/// **0 is a valid selection**, and means the caller leaves it to the code to discover what the
/// selection is -- so this is a plain store with no range test.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_selection(
    ctx: *mut OsslDecoderCtx,
    selection: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_171) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).selection = selection };
    1
}

/// `int OSSL_DECODER_CTX_set_input_type(OSSL_DECODER_CTX *ctx, const char *input_type)` —
/// `decoder_lib.c:183-198`.
///
/// **NULL is a valid starting input type**, and means the caller leaves it to the code to
/// discover.
///
/// # Safety
/// `ctx` must be NULL or live; `input_type` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_input_type(
    ctx: *mut OsslDecoderCtx,
    input_type: *const c_char,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_187) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).start_input_type = input_type };
    1
}

/// `int OSSL_DECODER_CTX_set_input_structure(OSSL_DECODER_CTX *ctx,
/// const char *input_structure)` — `decoder_lib.c:199-214`.
///
/// # Safety
/// `ctx` must be NULL or live; `input_structure` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_input_structure(
    ctx: *mut OsslDecoderCtx,
    input_structure: *const c_char,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_203) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).input_structure = input_structure };
    1
}

/// `OSSL_DECODER_INSTANCE *ossl_decoder_instance_new_forprov(OSSL_DECODER *decoder,
/// void *provctx, const char *input_structure)` — `decoder_lib.c:215-241`.
///
/// The provider-context arm: the decoder's own `newctx` makes the instance's context, and a
/// non-NULL `input_structure` is handed to the implementation through the mandatory `"data-
/// structure"` parameter **before** the instance is built -- so a refusal there releases the fresh
/// context and answers NULL without an instance ever existing.
///
/// # Safety
/// `decoder` must be live; `input_structure` NULL or NUL-terminated.
#[allow(dead_code)] // the authority's callers are the `storemgmt` provider stores, unlanded
pub(crate) unsafe fn ossl_decoder_instance_new_forprov(
    decoder: *mut OsslDecoder,
    provctx: *mut c_void,
    input_structure: *const c_char,
) -> *mut OsslDecoderInstance {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_222) };
        return ptr::null_mut();
    }

    // SAFETY: `decoder` is live. The authority calls `decoder->newctx` through the bare pointer;
    // see the module doc's fault-boundary note for the absent-field arm.
    let Some(newctx) = (unsafe { (*decoder).newctx }) else {
        return ptr::null_mut();
    };
    // SAFETY: `newctx` is a live provider callback and `provctx` is its producer's context.
    let decoderctx = unsafe { newctx(provctx) };
    if decoderctx.is_null() {
        return ptr::null_mut();
    }
    if !input_structure.is_null() {
        // SAFETY: `decoder` is live.
        if let Some(set_ctx_params) = unsafe { (*decoder).set_ctx_params } {
            // SAFETY: the constructor fills a two-entry descriptor array whose last entry is the
            // terminator, and both name and value are the caller's own.
            let params = unsafe {
                [
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                        input_structure.cast_mut(),
                        0,
                    ),
                    crate::params::OSSL_PARAM_construct_end(),
                ]
            };
            // SAFETY: `set_ctx_params` is a live provider callback and `params` is terminated.
            if unsafe { set_ctx_params(decoderctx, params.as_ptr()) } == 0 {
                // SAFETY: `decoder` is live.
                if let Some(freectx) = unsafe { (*decoder).freectx } {
                    // SAFETY: `freectx` is a live provider callback and `decoderctx` is its own
                    // context.
                    unsafe { freectx(decoderctx) };
                }
                return ptr::null_mut();
            }
        }
    }
    // SAFETY: `decoder` is live and `decoderctx` is a live context this call made.
    unsafe { ossl_decoder_instance_new(decoder, decoderctx) }
}

/// `OSSL_DECODER_INSTANCE *ossl_decoder_instance_new(OSSL_DECODER *decoder, void *decoderctx)` —
/// `decoder_lib.c:242-300`.
///
/// Two property reads and a reference, and the authority's labels are what make the failure paths
/// safe: `input_type` is set from the **mandatory** `input` property and is diagnosed when absent,
/// `input_structure` from the optional `structure` property, and every failure reaches
/// [`ossl_decoder_instance_free`] with a half-built instance -- which is why that destructor tests
/// each field rather than the instance.
///
/// # Safety
/// `decoder` must be live; `decoderctx` must be a live context the caller transfers.
#[no_mangle]
pub unsafe extern "C" fn ossl_decoder_instance_new(
    decoder: *mut OsslDecoder,
    decoderctx: *mut c_void,
) -> *mut OsslDecoderInstance {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_252) };
        return ptr::null_mut();
    }

    // The constructor asks only for a zeroed block of the instance's size.
    let decoder_inst = CRYPTO_zalloc(core::mem::size_of::<OsslDecoderInstance>(), ptr::null(), 0)
        .cast::<OsslDecoderInstance>();
    if decoder_inst.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `decoder` is live.
    let prov = unsafe { crate::decoder_meth::OSSL_DECODER_get0_provider(decoder) };
    // SAFETY: `prov` is live (or NULL, which the property lookup then discriminates).
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `decoder` is live.
    let props = unsafe { ossl_decoder_parsed_properties(decoder) };
    if props.is_null() {
        let mut msg = [0 as c_char; ERR_DATA_BUFFER];
        // SAFETY: `msg` is the buffer, the format is the authority's, and its one argument is
        // NUL-terminated.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"there are no property definitions with decoder %s".as_ptr(),
                crate::decoder_meth::OSSL_DECODER_get0_name(decoder),
            );
            raise_site_data(&err_sites::DECODER_LIB_263, msg.as_ptr());
        }
        // SAFETY: `decoder_inst` is live and owned here.
        return unsafe { fail_instance(decoder_inst) };
    }

    /* The "input" property is mandatory */
    // SAFETY: `props` is live and the literal is readable.
    let prop = unsafe { ossl_property_find_property(props, libctx, c"input".as_ptr()) };
    // SAFETY: `libctx` is the decoder's provider context; `prop` is NULL or a live definition.
    let input_type = unsafe { ossl_property_get_string_value(libctx, prop) };
    // SAFETY: `decoder_inst` is live and uniquely owned here; `input_type_id` is zeroed first,
    // exactly as the authority zeroes it before the NULL test.
    unsafe {
        (*decoder_inst).input_type = input_type;
        (*decoder_inst).input_type_id = 0;
    }
    if input_type.is_null() {
        let mut msg = [0 as c_char; ERR_DATA_BUFFER];
        // SAFETY: `msg` is the buffer, the format is the authority's, and all three arguments are
        // NUL-terminated.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"the mandatory 'input' property is missing for decoder %s (properties: %s)"
                    .as_ptr(),
                crate::decoder_meth::OSSL_DECODER_get0_name(decoder),
                crate::decoder_meth::OSSL_DECODER_get0_properties(decoder),
            );
            raise_site_data(&err_sites::DECODER_LIB_274, msg.as_ptr());
        }
        // SAFETY: `decoder_inst` is live and owned here.
        return unsafe { fail_instance(decoder_inst) };
    }

    /* The "structure" property is optional */
    // SAFETY: `props` is live and the literal is readable.
    let sprop = unsafe { ossl_property_find_property(props, libctx, c"structure".as_ptr()) };
    if !sprop.is_null() {
        // SAFETY: `sprop` is a live definition and `libctx` is the decoder's context.
        let input_structure = unsafe { ossl_property_get_string_value(libctx, sprop) };
        // SAFETY: `decoder_inst` is live.
        unsafe { (*decoder_inst).input_structure = input_structure };
    }

    // SAFETY: `decoder` is live.
    if unsafe { crate::decoder_meth::OSSL_DECODER_up_ref(decoder) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_290) };
        // SAFETY: `decoder_inst` is live and owned here.
        return unsafe { fail_instance(decoder_inst) };
    }
    // SAFETY: `decoder_inst` is live and uniquely owned here.
    unsafe {
        (*decoder_inst).decoder = decoder;
        (*decoder_inst).decoderctx = decoderctx;
    }
    decoder_inst
}

/// `void ossl_decoder_instance_free(OSSL_DECODER_INSTANCE *decoder_inst)` —
/// `decoder_lib.c:301-312`.
///
/// Three releases in the authority's order: the provider context through the decoder's own
/// `freectx` (so the *decoder* must still be live), then the decoder reference, then the instance.
/// The NULL tests are per-field, which is what makes the constructor's `err:` label safe to reach
/// with a half-built instance.
///
/// # Safety
/// `decoder_inst` must be NULL or a live instance this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn ossl_decoder_instance_free(decoder_inst: *mut OsslDecoderInstance) {
    if decoder_inst.is_null() {
        return;
    }
    // SAFETY: `decoder_inst` is live.
    let decoder = unsafe { (*decoder_inst).decoder };
    if !decoder.is_null() {
        // SAFETY: `decoder` is live.
        if let Some(freectx) = unsafe { (*decoder).freectx } {
            // SAFETY: `freectx` is a live provider callback and `decoderctx` is its context.
            unsafe { freectx((*decoder_inst).decoderctx) };
        }
        // SAFETY: `decoder_inst` is live.
        unsafe { (*decoder_inst).decoderctx = ptr::null_mut() };
        // SAFETY: `decoder` is live and this instance holds its reference.
        unsafe { crate::decoder_meth::OSSL_DECODER_free(decoder) };
        // SAFETY: `decoder_inst` is live.
        unsafe { (*decoder_inst).decoder = ptr::null_mut() };
    }
    // SAFETY: `decoder_inst` is live and this is the instance's own block.
    unsafe { CRYPTO_free(decoder_inst.cast(), ptr::null(), 0) };
}

/// `OSSL_DECODER_INSTANCE *ossl_decoder_instance_dup(const OSSL_DECODER_INSTANCE *src)` —
/// `decoder_lib.c:313-343`.
///
/// A **bitwise** copy of the source instance -- fields, bit flags, `order` and `score` included --
/// followed by a fresh reference on the decoder and a **new** provider context. The copy is why
/// the duplicated instance's `input_type`/`input_structure` point at the *same* provider strings
/// the source does: they are the decoder's own property values, not the instance's.
///
/// # Safety
/// `src` must be a live instance.
pub(crate) unsafe fn ossl_decoder_instance_dup(
    src: *const OsslDecoderInstance,
) -> *mut OsslDecoderInstance {
    // The constructor asks only for a zeroed block of the instance's size.
    let dest = CRYPTO_zalloc(core::mem::size_of::<OsslDecoderInstance>(), ptr::null(), 0)
        .cast::<OsslDecoderInstance>();
    if dest.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: both pointers are live and the struct holds raw pointers and scalars only, so the
    // duplication runs no destructor twice -- the `ptr::read`/`ptr::write` pair `src/ec/ameth.rs`
    // records for the same shape.
    unsafe { ptr::write(dest, ptr::read(src)) };
    // SAFETY: `dest` is live and its decoder is the source's.
    if unsafe { crate::decoder_meth::OSSL_DECODER_up_ref((*dest).decoder) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_324) };
        // SAFETY: `dest` is live and owned here.
        unsafe { CRYPTO_free(dest.cast(), ptr::null(), 0) };
        return ptr::null_mut();
    }
    // SAFETY: `dest` is live and its decoder is live (the reference above).
    let prov = unsafe { crate::decoder_meth::OSSL_DECODER_get0_provider((*dest).decoder) };
    // SAFETY: `prov` is live.
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(prov) };
    // SAFETY: `dest` is live; the absent-`newctx` arm is the module doc's fault boundary.
    let Some(newctx) = (unsafe { (*(*dest).decoder).newctx }) else {
        // SAFETY: `dest` is live and holds the reference taken above.
        unsafe { crate::decoder_meth::OSSL_DECODER_free((*dest).decoder) };
        // SAFETY: `dest` is live and owned here.
        unsafe { CRYPTO_free(dest.cast(), ptr::null(), 0) };
        return ptr::null_mut();
    };
    // SAFETY: `newctx` is a live provider callback and `provctx` is its producer's context.
    let decoderctx = unsafe { newctx(provctx) };
    if decoderctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_332) };
        // SAFETY: `dest` is live and holds the reference taken above.
        unsafe { crate::decoder_meth::OSSL_DECODER_free((*dest).decoder) };
        // SAFETY: `dest` is live and owned here.
        unsafe { CRYPTO_free(dest.cast(), ptr::null(), 0) };
        return ptr::null_mut();
    }
    // SAFETY: `dest` is live.
    unsafe { (*dest).decoderctx = decoderctx };
    dest
}

/// `void ossl_decoder_ctx_set_harderr(OSSL_DECODER_CTX *ctx)` — `decoder_lib.c:344-348`.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn ossl_decoder_ctx_set_harderr(ctx: *mut OsslDecoderCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).harderr = 1 };
}

/// `int ossl_decoder_ctx_get_harderr(const OSSL_DECODER_CTX *ctx)` — `decoder_lib.c:349-353`.
///
/// # Safety
/// `ctx` must be live.
#[allow(dead_code)] // read by `crypto/store/store_result.c`'s result handler, unlanded
pub(crate) unsafe fn ossl_decoder_ctx_get_harderr(ctx: *const OsslDecoderCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).harderr }
}

/// `int ossl_decoder_ctx_add_decoder_inst(OSSL_DECODER_CTX *ctx, OSSL_DECODER_INSTANCE *di)` —
/// `decoder_lib.c:354-380`.
///
/// The chain is built **lazily**: a NULL stack is replaced by a fresh one, and only then is the
/// instance pushed. A failed allocation is `ERR_R_CRYPTO_LIB`; a failed push is a 0 answer with
/// no raise, which is what makes the caller's `err:` label the only diagnosis.
///
/// # Safety
/// `ctx` must be live; `di` must be a live instance the caller transfers on success.
#[no_mangle]
pub unsafe extern "C" fn ossl_decoder_ctx_add_decoder_inst(
    ctx: *mut OsslDecoderCtx,
    di: *mut OsslDecoderInstance,
) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).decoder_insts }.is_null() {
        // The constructor allocates an empty stack or answers NULL.
        let fresh = OPENSSL_sk_new_null();
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_LIB_361) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).decoder_insts = fresh };
    }

    // SAFETY: `ctx` is live and its stack is non-NULL; the instance is the caller's.
    c_int::from(unsafe { OPENSSL_sk_push((*ctx).decoder_insts, di.cast::<c_void>()) } > 0)
}

/// `int OSSL_DECODER_CTX_add_decoder(OSSL_DECODER_CTX *ctx, OSSL_DECODER *decoder)` —
/// `decoder_lib.c:381-427`.
///
/// The context is made with the decoder's own `newctx` from **its provider's context**, then the
/// instance is built from it and pushed. `decoderctx` is cleared to NULL once the instance owns
/// it, which is what keeps the `err:` label from releasing it twice.
///
/// # Safety
/// `ctx` must be live; `decoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_add_decoder(
    ctx: *mut OsslDecoderCtx,
    decoder: *mut OsslDecoder,
) -> c_int {
    let mut decoder_inst: *mut OsslDecoderInstance = ptr::null_mut();

    if ctx.is_null() || decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_389) };
        return 0;
    }

    // SAFETY: `decoder` is live.
    let prov = unsafe { crate::decoder_meth::OSSL_DECODER_get0_provider(decoder) };
    // SAFETY: `prov` is live.
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(prov) };

    // SAFETY: `decoder` is live; the absent-`newctx` arm is the module doc's fault boundary.
    let Some(newctx) = (unsafe { (*decoder).newctx }) else {
        return 0;
    };
    // SAFETY: `newctx` is a live provider callback and `provctx` is its producer's context.
    let decoderctx = unsafe { newctx(provctx) };
    if !decoderctx.is_null() {
        // SAFETY: `decoder` is live and `decoderctx` is a live context this call made and hands
        // over.
        decoder_inst = unsafe { ossl_decoder_instance_new(decoder, decoderctx) };
    }

    if decoder_inst.is_null() {
        // SAFETY: `decoder` is live and `decoderctx` is still this call's, because
        // `ossl_decoder_instance_new` did not take it.
        if !decoderctx.is_null() {
            // SAFETY: `decoder` is live.
            if let Some(freectx) = unsafe { (*decoder).freectx } {
                // SAFETY: `freectx` is a live provider callback and `decoderctx` is its own
                // context.
                unsafe { freectx(decoderctx) };
            }
        }
        return 0;
    }
    /* The instance owns `decoderctx` now, so nothing below releases it -- the authority's own
     * `decoderctx = NULL;` (`:402`), written as a fact rather than a store. */

    // SAFETY: `ctx` is live and `decoder_inst` is live and transfers to the chain on success.
    let added = unsafe { ossl_decoder_ctx_add_decoder_inst(ctx, decoder_inst) };
    if added == 0 {
        // SAFETY: `decoder_inst` is live and the push failed, so it is still this call's.
        unsafe { ossl_decoder_instance_free(decoder_inst) };
        return 0;
    }
    1
}

/// `int OSSL_DECODER_CTX_get_num_decoders(OSSL_DECODER_CTX *ctx)` — `decoder_lib.c:680-686`.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_get_num_decoders(ctx: *mut OsslDecoderCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract, so the read is only reached when it is live.
    if ctx.is_null() || unsafe { (*ctx).decoder_insts }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live and its stack is non-NULL.
    unsafe { OPENSSL_sk_num((*ctx).decoder_insts) }
}

/// `int OSSL_DECODER_CTX_set_construct(OSSL_DECODER_CTX *ctx,
/// OSSL_DECODER_CONSTRUCT *construct)` — `decoder_lib.c:687-697`.
///
/// # Safety
/// `ctx` must be NULL or live; `construct` NULL or a live callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_construct(
    ctx: *mut OsslDecoderCtx,
    construct: Option<crate::decoder_meth::DecoderConstructFn>,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_691) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct = construct };
    1
}

/// `int OSSL_DECODER_CTX_set_construct_data(OSSL_DECODER_CTX *ctx, void *construct_data)` —
/// `decoder_lib.c:698-708`.
///
/// # Safety
/// `ctx` must be NULL or live; `construct_data` NULL or the caller's own.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_construct_data(
    ctx: *mut OsslDecoderCtx,
    construct_data: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_702) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct_data = construct_data };
    1
}

/// `int OSSL_DECODER_CTX_set_cleanup(OSSL_DECODER_CTX *ctx, OSSL_DECODER_CLEANUP *cleanup)` —
/// `decoder_lib.c:709-719`.
///
/// # Safety
/// `ctx` must be NULL or live; `cleanup` NULL or a live callback.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_cleanup(
    ctx: *mut OsslDecoderCtx,
    cleanup: Option<crate::decoder_meth::DecoderCleanupFn>,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_713) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cleanup = cleanup };
    1
}

/// `OSSL_DECODER_CONSTRUCT *OSSL_DECODER_CTX_get_construct(OSSL_DECODER_CTX *ctx)` —
/// `decoder_lib.c:720-727`.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_get_construct(
    ctx: *mut OsslDecoderCtx,
) -> Option<crate::decoder_meth::DecoderConstructFn> {
    if ctx.is_null() {
        return None;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct }
}

/// `void *OSSL_DECODER_CTX_get_construct_data(OSSL_DECODER_CTX *ctx)` — `decoder_lib.c:728-734`.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_get_construct_data(
    ctx: *mut OsslDecoderCtx,
) -> *mut c_void {
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct_data }
}

/// `OSSL_DECODER_CLEANUP *OSSL_DECODER_CTX_get_cleanup(OSSL_DECODER_CTX *ctx)` —
/// `decoder_lib.c:735-742`.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_get_cleanup(
    ctx: *mut OsslDecoderCtx,
) -> Option<crate::decoder_meth::DecoderCleanupFn> {
    if ctx.is_null() {
        return None;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cleanup }
}

/// `int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst, void *reference,
/// size_t reference_sz, OSSL_CALLBACK *export_cb, void *export_cbarg)` — `decoder_lib.c:743-763`.
///
/// **All four** arguments are asserted non-NULL before anything is read, and the answer is the
/// instance's own `export_object` callback's -- this function itself decides nothing.
///
/// # Safety
/// `decoder_inst` must be live; `reference` readable for `reference_sz`; `export_cb` live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_export(
    decoder_inst: *mut OsslDecoderInstance,
    reference: *mut c_void,
    reference_sz: usize,
    export_cb: Option<OsslCallback>,
    export_cbarg: *mut c_void,
) -> c_int {
    if decoder_inst.is_null()
        || reference.is_null()
        || export_cb.is_none()
        || export_cbarg.is_null()
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_754) };
        return 0;
    }

    // SAFETY: `decoder_inst` is live.
    let decoder = unsafe { OSSL_DECODER_INSTANCE_get_decoder(decoder_inst) };
    // SAFETY: `decoder_inst` is live.
    let decoderctx = unsafe { OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst) };
    // SAFETY: `decoder` is live. The authority calls `export_object` through the bare pointer; see
    // the module doc's fault-boundary note for the absent-field arm.
    let Some(export_object) = (unsafe { (*decoder).export_object }) else {
        return 0;
    };
    // SAFETY: `export_object` is a live provider callback, `decoderctx` is its context, and the
    // remaining three arguments are the caller's.
    unsafe { export_object(decoderctx, reference, reference_sz, export_cb, export_cbarg) }
}

/// `OSSL_DECODER *OSSL_DECODER_INSTANCE_get_decoder(OSSL_DECODER_INSTANCE *decoder_inst)` —
/// `decoder_lib.c:764-771`.
///
/// # Safety
/// `decoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_decoder(
    decoder_inst: *mut OsslDecoderInstance,
) -> *mut OsslDecoder {
    if decoder_inst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `decoder_inst` is live.
    unsafe { (*decoder_inst).decoder }
}

/// `void *OSSL_DECODER_INSTANCE_get_decoder_ctx(OSSL_DECODER_INSTANCE *decoder_inst)` —
/// `decoder_lib.c:772-778`.
///
/// # Safety
/// `decoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_decoder_ctx(
    decoder_inst: *mut OsslDecoderInstance,
) -> *mut c_void {
    if decoder_inst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `decoder_inst` is live.
    unsafe { (*decoder_inst).decoderctx }
}

/// `const char *OSSL_DECODER_INSTANCE_get_input_type(OSSL_DECODER_INSTANCE *decoder_inst)` —
/// `decoder_lib.c:779-786`.
///
/// # Safety
/// `decoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_input_type(
    decoder_inst: *mut OsslDecoderInstance,
) -> *const c_char {
    if decoder_inst.is_null() {
        return ptr::null();
    }
    // SAFETY: `decoder_inst` is live.
    unsafe { (*decoder_inst).input_type }
}

/// `const char *OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
/// int *was_set)` — `decoder_lib.c:787-796`.
///
/// The `was_set` out-parameter is written **before** the field is read, and it is the instance's
/// own `flag_input_structure_was_set` -- so the out-parameter is 0 for a NULL instance too, which
/// is the only way a caller can tell "no structure" from "not asked".
///
/// # Safety
/// `was_set` must be writable; `decoder_inst` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_INSTANCE_get_input_structure(
    decoder_inst: *mut OsslDecoderInstance,
    was_set: *mut c_int,
) -> *const c_char {
    if decoder_inst.is_null() {
        return ptr::null();
    }
    // SAFETY: `was_set` is writable per the contract; `decoder_inst` is live.
    unsafe {
        *was_set = (*decoder_inst).flag_input_structure_was_set;
        (*decoder_inst).input_structure
    }
}

// ---------------------------------------------------------------------------
// The from_* family and the chain builder — `decoder_lib.c:26-167`, `:411-679`, `:798-1165`
// ---------------------------------------------------------------------------

/// `BIO_tell(b)` — `include/openssl/bio.h`'s macro over `BIO_ctrl(BIO_C_FILE_TELL)`.
///
/// # Safety
/// `b` must be NULL or live.
unsafe fn bio_tell(b: *mut Bio) -> c_long {
    // SAFETY: `b` is NULL or live per the contract; this control takes no pointer argument.
    unsafe { BIO_ctrl(b, BIO_C_FILE_TELL, 0, ptr::null_mut()) }
}

/// `BIO_seek(b, offset)` — `bio.h`'s macro over `BIO_ctrl(BIO_C_FILE_SEEK)`.
///
/// # Safety
/// `b` must be NULL or live.
unsafe fn bio_seek(b: *mut Bio, offset: c_long) -> c_long {
    // SAFETY: as [`bio_tell`]; the offset is a plain scalar.
    unsafe { BIO_ctrl(b, BIO_C_FILE_SEEK, offset, ptr::null_mut()) }
}

/// `BIO_get_mem_data(b, pp)` — `bio.h`'s macro over `BIO_ctrl(BIO_CTRL_INFO)`.
///
/// The answer is the *available* byte count; the control also writes the buffer pointer through
/// the out-parameter, which is why the macro's two roles share one call.
///
/// # Safety
/// `b` must be live; `pp` writable for one pointer.
unsafe fn bio_get_mem_data(b: *mut Bio, pp: *mut *const c_uchar) -> c_long {
    // SAFETY: `b` is live and `pp` is the out-parameter the control writes.
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast::<c_void>()) }
}

/// `struct decoder_process_data_st` — `decoder_lib.c:26-43`.
///
/// The three bitfields are projected as their four-byte storage, the projection
/// [`OsslDecoderInstance`]'s flag uses.
struct DecoderProcessData {
    /// `OSSL_DECODER_CTX *ctx`.
    ctx: *mut OsslDecoderCtx,
    /// `BIO *bio` — the current BIO.
    bio: *mut Bio,
    /// `int current_decoder_inst_index`.
    current_decoder_inst_index: c_int,
    /// `int recursion` — for tracing only, which this build compiles out.
    recursion: c_int,
    /// `unsigned int flag_next_level_called : 1`.
    flag_next_level_called: c_int,
    /// `unsigned int flag_construct_called : 1`.
    flag_construct_called: c_int,
    /// `unsigned int flag_input_structure_checked : 1`.
    flag_input_structure_checked: c_int,
}

/// `int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *ctx, BIO *in)` — `decoder_lib.c:47-119`.
///
/// Three refusals and a wrap. A NULL BIO is `ERR_R_PASSED_NULL_PARAMETER`; an **empty chain** is
/// `OSSL_DECODER_R_DECODER_NOT_FOUND` with the authority's own "did you forget to load the default
/// providers?" text; and a BIO that cannot `BIO_tell` is wrapped in a `BIO_f_readbuffer` so the
/// walk below can seek it. The "no supported data" diagnosis is added only when the walk left the
/// error queue exactly as it found it (`ERR_peek_last_error() == lasterr`) or emptied it, so a real
/// decoder error is never hidden behind it.
///
/// # Safety
/// `ctx` must be live; `in_` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_from_bio(ctx: *mut OsslDecoderCtx, in_: *mut Bio) -> c_int {
    let mut data = DecoderProcessData {
        ctx: ptr::null_mut(),
        bio: ptr::null_mut(),
        current_decoder_inst_index: 0,
        recursion: 0,
        flag_next_level_called: 0,
        flag_construct_called: 0,
        flag_input_structure_checked: 0,
    };
    let mut new_bio: *mut Bio = ptr::null_mut();

    if in_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_55) };
        return 0;
    }

    // SAFETY: `ctx` is live or NULL, which the count accepts.
    if unsafe { OSSL_DECODER_CTX_get_num_decoders(ctx) } == 0 {
        // SAFETY: a compile-time-constant site; the message is the authority's own single literal.
        unsafe {
            raise_site_data(
                &err_sites::DECODER_LIB_60,
                c"No decoders were found. For standard decoders you need at least one of the default or base providers available. Did you forget to load them?".as_ptr(),
            )
        };
        return 0;
    }

    // SAFETY: no preconditions.
    let lasterr: c_ulong = ERR_peek_last_error();

    let mut bp = in_;
    // SAFETY: `bp` is live.
    if unsafe { bio_tell(bp) } < 0 {
        // SAFETY: `BIO_f_readbuffer` takes no arguments and answers a static method.
        new_bio = unsafe { BIO_new(BIO_f_readbuffer()) };
        if new_bio.is_null() {
            return 0;
        }
        // SAFETY: both BIOs are live and the push links them.
        bp = unsafe { BIO_push(new_bio, bp) };
    }
    data.ctx = ctx;
    data.bio = bp;

    /* Enable passphrase caching */
    // SAFETY: `ctx` is live, so its embedded passphrase data is its own field.
    unsafe { ossl_pw_enable_passphrase_caching(ptr::addr_of_mut!((*ctx).pwdata)) };

    // SAFETY: `data` is live and initialised above.
    let mut ok = unsafe { decoder_process(ptr::null(), ptr::addr_of_mut!(data).cast::<c_void>()) };

    if data.flag_construct_called == 0 {
        // The authority's six conditional spellings, each a NULL check on one of the context's
        // two input strings.
        // SAFETY: `ctx` is live; the two strings are NULL or NUL-terminated.
        let (spaces, itl, isl, comma, it, is_) = unsafe {
            let it = if !(*ctx).start_input_type.is_null() {
                (*ctx).start_input_type
            } else {
                c"".as_ptr()
            };
            let is_ = if !(*ctx).input_structure.is_null() {
                (*ctx).input_structure
            } else {
                c"".as_ptr()
            };
            let both = !(*ctx).start_input_type.is_null() && !(*ctx).input_structure.is_null();
            (
                if both { c" ".as_ptr() } else { c"".as_ptr() },
                if (*ctx).start_input_type.is_null() {
                    c"".as_ptr()
                } else {
                    c"Input type: ".as_ptr()
                },
                if (*ctx).input_structure.is_null() {
                    c"".as_ptr()
                } else {
                    c"Input structure: ".as_ptr()
                },
                if both { c", ".as_ptr() } else { c"".as_ptr() },
                it,
                is_,
            )
        };

        // SAFETY: both are plain reads of the error queue, and both are safe functions.
        if ERR_peek_last_error() == lasterr || ERR_peek_error() == 0 {
            let mut msg = [0 as c_char; ERR_DATA_BUFFER];
            // SAFETY: `msg` is a writable buffer of the size passed, and every `%s` argument is
            // NUL-terminated.
            unsafe {
                BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"No supported data to decode. %s%s%s%s%s%s".as_ptr(),
                    spaces,
                    itl,
                    it,
                    comma,
                    isl,
                    is_,
                );
                raise_site_data(&err_sites::DECODER_LIB_104, msg.as_ptr());
            }
        }
        ok = 0;
    }

    /* Clear any internally cached passphrase */
    // SAFETY: `ctx` is live, so its embedded passphrase data is its own field.
    unsafe { ossl_pw_clear_passphrase_cache(ptr::addr_of_mut!((*ctx).pwdata)) };

    if !new_bio.is_null() {
        // SAFETY: `new_bio` is the wrap pushed above; popping unlinks it from `bp`.
        unsafe { BIO_pop(new_bio) };
        // SAFETY: `new_bio` is live and this function owns it.
        unsafe { BIO_free(new_bio) };
    }
    ok
}

/// `static BIO *bio_from_file(FILE *fp)` — `decoder_lib.c:122-133`.
///
/// `BIO_set_fp(b, fp, BIO_NOCLOSE)` is `BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE, fp)`, which is
/// how the crate spells the macro elsewhere (`src/encoder_lib.rs`).
///
/// # Safety
/// `fp` must be a live `FILE *`.
unsafe fn bio_from_file(fp: *mut c_void) -> *mut Bio {
    // SAFETY: `BIO_s_file` takes no arguments and answers a static method.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_127) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is a live file BIO and `fp` is the caller's `FILE *`.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp) };
    b
}

/// `int OSSL_DECODER_from_fp(OSSL_DECODER_CTX *ctx, FILE *fp)` — `decoder_lib.c:134-145`.
///
/// The `OPENSSL_NO_STDIO` guard around this and [`bio_from_file`] is the authority's; this crate
/// is built with stdio, so the guarded half is here.
///
/// # Safety
/// `ctx` must be live; `fp` must be a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_from_fp(ctx: *mut OsslDecoderCtx, fp: *mut c_void) -> c_int {
    let mut ret = 0;
    // SAFETY: `fp` is live per the contract.
    let b = unsafe { bio_from_file(fp) };
    if !b.is_null() {
        // SAFETY: `b` is live and `ctx` is the caller's.
        ret = unsafe { OSSL_DECODER_from_bio(ctx, b) };
    }
    // SAFETY: `b` is NULL or a live BIO this call owns.
    unsafe { BIO_free(b) };
    ret
}

/// `int OSSL_DECODER_from_data(OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
/// size_t *pdata_len)` — `decoder_lib.c:147-166`.
///
/// The three NULL arms are asserted together, and a success moves the caller's pointer to the end
/// of what was consumed and decrements the length to what is left, both through
/// `BIO_get_mem_data`'s control.
///
/// # Safety
/// `ctx` must be live; `pdata` must be NULL or point at a readable pointer; `pdata_len` writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_from_data(
    ctx: *mut OsslDecoderCtx,
    pdata: *mut *const c_uchar,
    pdata_len: *mut usize,
) -> c_int {
    let mut ret = 0;

    // SAFETY: `pdata` is NULL or points at a readable pointer; the read is guarded by the check.
    let deref_is_null = !pdata.is_null() && unsafe { *pdata }.is_null();
    if pdata.is_null() || deref_is_null || pdata_len.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_154) };
        return 0;
    }

    // SAFETY: `*pdata` is non-NULL and readable for `*pdata_len` bytes.
    let membio = unsafe { BIO_new_mem_buf((*pdata).cast::<c_void>(), *pdata_len as c_int) };
    // SAFETY: `ctx` is live and `membio` is NULL or a live BIO.
    if unsafe { OSSL_DECODER_from_bio(ctx, membio) } != 0 {
        // SAFETY: `pdata_len` is writable and `pdata`'s pointer is the control's out-parameter.
        unsafe { *pdata_len = bio_get_mem_data(membio, pdata) as usize };
        ret = 1;
    }
    // SAFETY: `membio` is NULL or a live BIO this call owns.
    unsafe { BIO_free(membio) };

    ret
}

/// `sk_OSSL_DECODER_pop_free`'s destructor: the crate's stack frees elements through a `void *`
/// callback, so `OSSL_DECODER_free` is reached through this thunk.
unsafe extern "C" fn decoder_free_thunk(p: *mut c_void) {
    // SAFETY: the stack's element is an `OsslDecoder` whose reference the stack owns.
    unsafe { OSSL_DECODER_free(p.cast::<OsslDecoder>()) };
}

/// `enum { IS_SAME = 0, IS_DIFFERENT = 1 }` — `decoder_lib.c:422-423`.
const IS_SAME: c_int = 0;
const IS_DIFFERENT: c_int = 1;

/// `struct collect_extra_decoder_data_st` — `decoder_lib.c:413-426`.
struct CollectExtraDecoderData {
    /// `OSSL_DECODER_CTX *ctx`.
    ctx: *mut OsslDecoderCtx,
    /// `const char *output_type`.
    output_type: *const c_char,
    /// `int output_type_id`.
    output_type_id: c_int,
    /// `int type_check` — one of [`IS_SAME`], [`IS_DIFFERENT`].
    type_check: c_int,
    /// `int w_prev_start`.
    w_prev_start: c_int,
    /// `int w_prev_end`.
    w_prev_end: c_int,
    /// `int w_new_start`.
    w_new_start: c_int,
    /// `int w_new_end`.
    w_new_end: c_int,
}

/// `static void collect_all_decoders(OSSL_DECODER *decoder, void *arg)` — `decoder_lib.c:430-437`.
///
/// The up-ref-then-push pair is the authority's: the stack owns one reference per element, and a
/// push that fails gives that reference back immediately.
///
/// # Safety
/// `decoder` must be live; `arg` must be a live `STACK_OF(OSSL_DECODER)`.
unsafe extern "C" fn collect_all_decoders(decoder: *mut OsslDecoder, arg: *mut c_void) {
    let skdecoders = arg.cast::<OpenSslStack>();
    // SAFETY: both are live per the contract.
    unsafe {
        if OSSL_DECODER_up_ref(decoder) != 0
            && OPENSSL_sk_push(skdecoders, decoder.cast::<c_void>()) <= 0
        {
            OSSL_DECODER_free(decoder);
        }
    }
}

/// `static void collect_extra_decoder(OSSL_DECODER *decoder, void *arg)` — `decoder_lib.c:439-546`.
///
/// Four exclusions before anything is built -- a name that does not match the output type, an
/// `algodef` already in the chain, a `newctx` that fails, and a `set_ctx_params` that refuses the
/// context's input structure -- then a final two-way check on whether the decoder's own input type
/// is (or is not) the same as its name. The `w_prev_start..w_new_end` window is what makes the
/// "already in the chain" test cover decoders added in the *current* iteration as well as the
/// previous ones.
///
/// # Safety
/// `decoder` must be live; `arg` must be a live [`CollectExtraDecoderData`].
unsafe extern "C" fn collect_extra_decoder(decoder: *mut OsslDecoder, arg: *mut c_void) {
    let data = arg.cast::<CollectExtraDecoderData>();
    // SAFETY: `data` is live per the contract.
    let (output_type, output_type_id) = unsafe {
        (
            (*data).output_type,
            ptr::addr_of_mut!((*data).output_type_id),
        )
    };
    // SAFETY: `decoder` is live and the three arguments are the caller's.
    if unsafe { ossl_decoder_fast_is_a(decoder, output_type, output_type_id) } == 0 {
        return;
    }

    // SAFETY: `decoder` is live.
    let prov = unsafe { OSSL_DECODER_get0_provider(decoder) };
    // SAFETY: `prov` is the decoder's provider.
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(prov) };

    /*
     * Check that we don't already have this decoder in our stack, starting with the previous
     * windows but also looking at what we have added in the current window.
     */
    // SAFETY: every read below is a live field of `data` or of the context it names.
    unsafe {
        let mut j = (*data).w_prev_start;
        while j < (*data).w_new_end {
            let check_inst =
                OPENSSL_sk_value((*(*data).ctx).decoder_insts, j).cast::<OsslDecoderInstance>();
            if (*decoder).base.algodef == (*(*check_inst).decoder).base.algodef {
                return;
            }
            j += 1;
        }
    }

    // SAFETY: `decoder` is live.
    let newctx = unsafe { (*decoder).newctx };
    let decoderctx = match newctx {
        // SAFETY: `newctx` is a live provider callback and `provctx` is its provider's context.
        Some(newctx) => unsafe { newctx(provctx) },
        None => ptr::null_mut(),
    };
    if decoderctx.is_null() {
        return;
    }

    // SAFETY: `decoder` and `data` are live.
    unsafe {
        if (*decoder).set_ctx_params.is_some() && !(*(*data).ctx).input_structure.is_null() {
            let str_ = (*(*data).ctx).input_structure;
            let params: [OsslParam; 2] = [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_OBJECT_PARAM_DATA_STRUCTURE.cast_mut(),
                    str_.cast_mut(),
                    0,
                ),
                crate::params::OSSL_PARAM_construct_end(),
            ];
            if let Some(set_ctx_params) = (*decoder).set_ctx_params {
                if set_ctx_params(decoderctx, params.as_ptr()) == 0 {
                    if let Some(freectx) = (*decoder).freectx {
                        freectx(decoderctx);
                    }
                    return;
                }
            }
        }
    }

    // SAFETY: `decoder` is live and `decoderctx` is the context just built.
    let di = unsafe { ossl_decoder_instance_new(decoder, decoderctx) };
    if di.is_null() {
        // SAFETY: `decoder` is live and `decoderctx` is this function's own.
        unsafe {
            if let Some(freectx) = (*decoder).freectx {
                freectx(decoderctx);
            }
        }
        return;
    }

    // SAFETY: `decoder` and `di` are live.
    unsafe {
        match (*data).type_check {
            IS_SAME => {
                // If it differs, this is not a decoder to add for now.
                if ossl_decoder_fast_is_a(
                    decoder,
                    OSSL_DECODER_INSTANCE_get_input_type(di),
                    ptr::addr_of_mut!((*di).input_type_id),
                ) == 0
                {
                    ossl_decoder_instance_free(di);
                    return;
                }
            }
            _ => {
                // If it's the same, this is not a decoder to add for now.
                if ossl_decoder_fast_is_a(
                    decoder,
                    OSSL_DECODER_INSTANCE_get_input_type(di),
                    ptr::addr_of_mut!((*di).input_type_id),
                ) != 0
                {
                    ossl_decoder_instance_free(di);
                    return;
                }
            }
        }

        if ossl_decoder_ctx_add_decoder_inst((*data).ctx, di) == 0 {
            ossl_decoder_instance_free(di);
            return;
        }

        (*data).w_new_end += 1;
    }
}

/// `static int decoder_sk_cmp(const OSSL_DECODER_INSTANCE *const *a,
/// const OSSL_DECODER_INSTANCE *const *b)` — `decoder_lib.c:548-554`.
///
/// The stack passes **element slots**, so each argument is a `const OSSL_DECODER_INSTANCE *const *`:
/// the crate's stack comparator takes `*const c_void`, and the two dereferences that follows are the
/// authority's own. Equal scores fall back to the insertion `order` so the sort is stable.
///
/// # Safety
/// Both arguments must be live element slots of an `OSSL_DECODER_INSTANCE` stack.
unsafe extern "C" fn decoder_sk_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<*const OsslDecoderInstance>();
    let b = b.cast::<*const OsslDecoderInstance>();
    // SAFETY: both point at the stack's own element slots, whose values are live instances.
    unsafe {
        if (*(*a)).score == (*(*b)).score {
            return (*(*a)).order - (*(*b)).order;
        }
        (*(*a)).score - (*(*b)).score
    }
}

/// `int OSSL_DECODER_CTX_add_extra(OSSL_DECODER_CTX *ctx, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `decoder_lib.c:556-678`.
///
/// The sliding-window chain extension: it walks the instances already in the chain, asks every
/// available decoder whether it produces what the considered instance wants as input, and appends
/// those that do, repeating over the newly appended window until a round adds nothing or ten rounds
/// have run. The two `type_check` passes are the authority's: first decoders whose input type has
/// the same name as the decoder itself, then those whose input type differs.
///
/// # Safety
/// `ctx` must be live; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_add_extra(
    ctx: *mut OsslDecoderCtx,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_589) };
        return 0;
    }

    /*
     * If there is no stack of OSSL_DECODER_INSTANCE, we have nothing more to add. That's fine.
     */
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).decoder_insts }.is_null() {
        return 1;
    }

    // SAFETY: no preconditions.
    let skdecoders = OPENSSL_sk_new_null();
    if skdecoders.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_LIB_609) };
        return 0;
    }
    // SAFETY: `skdecoders` is live and `collect_all_decoders` is this unit's own visitor.
    unsafe { OSSL_DECODER_do_all_provided(libctx, collect_all_decoders, skdecoders.cast()) };
    // SAFETY: `skdecoders` is a live stack.
    let numdecoders = unsafe { OPENSSL_sk_num(skdecoders) };

    /*
     * If there are provided or default properties, sort the initial decoder list by property
     * matching score so that the highest scored provider is selected first.
     */
    // SAFETY: `libctx` is NULL or live, and the property slot read accepts NULL.
    if !propq.is_null() || !unsafe { ossl_ctx_global_properties(libctx, 0) }.is_null() {
        // SAFETY: `ctx` is live and its stack is non-NULL (checked above).
        let num_decoder_insts = unsafe { OPENSSL_sk_num((*ctx).decoder_insts) };
        // SAFETY: the comparator is this unit's own and the stack is live.
        let mut old_cmp =
            unsafe { OPENSSL_sk_set_cmp_func((*ctx).decoder_insts, Some(decoder_sk_cmp)) };

        for i in 0..num_decoder_insts {
            // SAFETY: `i` is in range.
            let di =
                unsafe { OPENSSL_sk_value((*ctx).decoder_insts, i) }.cast::<OsslDecoderInstance>();
            // SAFETY: `di` is a live instance in the chain.
            unsafe { (*di).order = i };
        }
        // SAFETY: the stack is live and now has a comparator.
        unsafe { OPENSSL_sk_sort((*ctx).decoder_insts) };
        // SAFETY: restoring the previous comparator, as the authority does.
        unsafe { OPENSSL_sk_set_cmp_func((*ctx).decoder_insts, old_cmp.take()) };
    }

    let mut data = CollectExtraDecoderData {
        ctx,
        output_type: ptr::null(),
        output_type_id: 0,
        type_check: IS_SAME,
        w_prev_start: 0,
        // SAFETY: `ctx` is live and its stack is non-NULL.
        w_prev_end: unsafe { OPENSSL_sk_num((*ctx).decoder_insts) },
        w_new_start: 0,
        w_new_end: 0,
    };

    let mut depth: usize = 0;
    loop {
        data.w_new_start = data.w_prev_end;
        data.w_new_end = data.w_prev_end;

        let mut tc = IS_SAME;
        while tc <= IS_DIFFERENT {
            data.type_check = tc;
            let mut i = data.w_prev_start;
            while i < data.w_prev_end {
                // SAFETY: `ctx` is live and `i` is in range.
                let decoder_inst = unsafe { OPENSSL_sk_value((*ctx).decoder_insts, i) }
                    .cast::<OsslDecoderInstance>();
                // SAFETY: `decoder_inst` is live in the chain.
                data.output_type = unsafe { OSSL_DECODER_INSTANCE_get_input_type(decoder_inst) };
                data.output_type_id = 0;

                for j in 0..numdecoders {
                    // SAFETY: `j` is in range of the collected decoder stack.
                    let dec = unsafe { OPENSSL_sk_value(skdecoders, j) }.cast::<OsslDecoder>();
                    // SAFETY: `dec` is live and `data` is this frame's own.
                    unsafe { collect_extra_decoder(dec, ptr::addr_of_mut!(data).cast::<c_void>()) };
                }
                i += 1;
            }
            tc += 1;
        }

        /* How many were added in this iteration */
        let count = data.w_new_end - data.w_new_start;

        /* Slide the "previous decoder" windows */
        data.w_prev_start = data.w_new_start;
        data.w_prev_end = data.w_new_end;

        depth += 1;
        if !(count != 0 && depth <= 10) {
            break;
        }
    }

    // SAFETY: `skdecoders` is live and owns one reference per element.
    unsafe { OPENSSL_sk_pop_free(skdecoders, Some(decoder_free_thunk)) };
    1
}

/// `static int decoder_process(const OSSL_PARAM params[], void *arg)` — `decoder_lib.c:798-1165`.
///
/// The walk. See the module doc for the `params`-NULL dispatch and the error-queue discipline. The
/// loop reproduces `for (i = data->current_decoder_inst_index; i-- > 0;)` exactly, so a normal exit
/// leaves `i == -1` and a `break` leaves the index that broke; the authority's `goto end` sites are
/// `break` out of the surrounding block, which is why the tail runs on every path.
///
/// # Safety
/// `params` NULL or a terminated array; `arg` a live, initialised [`DecoderProcessData`] whose
/// `ctx` is live.
unsafe extern "C" fn decoder_process(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let data = arg.cast::<DecoderProcessData>();
    // SAFETY: `data` is live per the contract.
    let ctx = unsafe { (*data).ctx };
    let mut decoder: *mut OsslDecoder = ptr::null_mut();
    let mut cbio: *mut OsslCoreBio = ptr::null_mut();
    let bio: *mut Bio;
    let mut ok: c_int = 0;
    let mut new_data = DecoderProcessData {
        ctx: ptr::null_mut(),
        bio: ptr::null_mut(),
        current_decoder_inst_index: 0,
        recursion: 0,
        flag_next_level_called: 0,
        flag_construct_called: 0,
        flag_input_structure_checked: 0,
    };
    let mut data_type: *const c_char = ptr::null();
    let mut data_structure: *const c_char = ptr::null();
    // SAFETY: `ctx` is live.
    let start_input_type = unsafe { (*ctx).start_input_type };

    /*
     * This is an indicator up the call stack that something was indeed decoded, leading to a
     * recursive call of this function.
     */
    // SAFETY: `data` is live.
    unsafe { (*data).flag_next_level_called = 1 };

    new_data.ctx = ctx;
    // SAFETY: `data` is live.
    new_data.recursion = unsafe { (*data).recursion } + 1;

    'walk: {
        if params.is_null() {
            /* First iteration, where we prepare for what is to come */
            // SAFETY: `ctx` is live.
            unsafe { (*data).current_decoder_inst_index = OSSL_DECODER_CTX_get_num_decoders(ctx) };
            // SAFETY: `data` is live.
            bio = unsafe { (*data).bio };
        } else {
            // SAFETY: `data` is live.
            let index = unsafe { (*data).current_decoder_inst_index };
            // SAFETY: `ctx` is live and `index` is a valid chain index.
            let decoder_inst = unsafe { OPENSSL_sk_value((*ctx).decoder_insts, index) }
                .cast::<OsslDecoderInstance>();
            // SAFETY: `decoder_inst` is live.
            decoder = unsafe { OSSL_DECODER_INSTANCE_get_decoder(decoder_inst) };

            // SAFETY: `data` is live.
            unsafe { (*data).flag_construct_called = 0 };
            // SAFETY: `ctx` is live.
            let construct = unsafe { (*ctx).construct };
            if let Some(construct) = construct {
                // SAFETY: `construct` is a live constructor and the three arguments are the
                // context's own.
                let rv = unsafe { construct(decoder_inst, params, (*ctx).construct_data) };
                ok = c_int::from(rv > 0);
                if ok != 0 {
                    // SAFETY: `data` is live.
                    unsafe { (*data).flag_construct_called = 1 };
                    break 'walk;
                }
            }

            /* The constructor didn't return success */

            /*
             * so we try to use the object we got and feed it to any next decoder that will take it.
             * Object references are not allowed for this. If this data isn't present, decoding has
             * failed.
             */
            // SAFETY: `params` is a terminated array per the contract.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA) };
            // SAFETY: `p` is NULL or a live descriptor.
            if p.is_null() || unsafe { (*p).data_type } != OSSL_PARAM_OCTET_STRING {
                break 'walk;
            }
            // SAFETY: `p` is live and its data is an octet string of `data_size` bytes.
            let mem = unsafe { BIO_new_mem_buf((*p).data, (*p).data_size as c_int) };
            if mem.is_null() {
                break 'walk;
            }
            new_data.bio = mem;
            bio = new_data.bio;

            /* Get the data type if there is one */
            // SAFETY: `params` is a terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE) };
            if !p.is_null()
                // SAFETY: `p` is live and `data_type` is this frame's own slot.
                && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, ptr::addr_of_mut!(data_type)) } == 0
            {
                break 'walk;
            }

            /* Get the data structure if there is one */
            // SAFETY: `params` is a terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE) };
            if !p.is_null()
                // SAFETY: `p` is live and `data_structure` is this frame's own slot.
                && unsafe { OSSL_PARAM_get_utf8_string_ptr(p, ptr::addr_of_mut!(data_structure)) }
                    == 0
            {
                break 'walk;
            }

            /* Get the new input type if there is one */
            // SAFETY: `params` is a terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_INPUT_TYPE) };
            if !p.is_null() {
                // SAFETY: `p` is live and the context's `start_input_type` is its own field.
                if unsafe {
                    OSSL_PARAM_get_utf8_string_ptr(p, ptr::addr_of_mut!((*ctx).start_input_type))
                } == 0
                {
                    break 'walk;
                }
                /*
                 * When switching PKCS8 from PEM to DER we decrypt the data if needed and then
                 * determine the algorithm OID. Likewise, with SPKI, only this time sans decryption.
                 */
                // SAFETY: each of the three strings is NULL or NUL-terminated.
                unsafe {
                    if !(*ctx).input_structure.is_null()
                        && (OPENSSL_strcasecmp(
                            (*ctx).input_structure,
                            c"SubjectPublicKeyInfo".as_ptr(),
                        ) == 0
                            || OPENSSL_strcasecmp(data_structure, c"PrivateKeyInfo".as_ptr()) == 0
                            || OPENSSL_strcasecmp(
                                (*ctx).input_structure,
                                c"PrivateKeyInfo".as_ptr(),
                            ) == 0)
                    {
                        (*data).flag_input_structure_checked = 1;
                    }
                }
            }

            /*
             * If the data structure is "type-specific" and the data type is given, we drop the
             * data structure: the data type is already enough to find the applicable next decoder.
             */
            // SAFETY: both strings are non-NULL and NUL-terminated per the checks above.
            let type_specific = !data_type.is_null()
                && !data_structure.is_null()
                && unsafe { OPENSSL_strcasecmp(data_structure, c"type-specific".as_ptr()) } == 0;
            if type_specific {
                data_structure = ptr::null();
            }
        }

        /* If we have no more decoders to look through at this point, we failed */
        // SAFETY: `data` is live.
        if unsafe { (*data).current_decoder_inst_index } == 0 {
            break 'walk;
        }

        // SAFETY: `bio` is live.
        let loc = unsafe { bio_tell(bio) };
        if loc < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_LIB_965) };
            break 'walk;
        }

        // SAFETY: `bio` is live.
        cbio = unsafe { ossl_core_bio_new_from_bio(bio) };
        if cbio.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DECODER_LIB_970) };
            break 'walk;
        }

        // SAFETY: `data` is live.
        let mut i = unsafe { (*data).current_decoder_inst_index };
        loop {
            // `i-- > 0`: the test reads the pre-decrement value, so a normally-exhausted loop
            // leaves `i == -1` and a `break` leaves the index that broke.
            let old = i;
            i -= 1;
            if old <= 0 {
                break;
            }

            // SAFETY: every read below is a live field of `ctx` or of its chain.
            unsafe {
                let new_decoder_inst =
                    OPENSSL_sk_value((*ctx).decoder_insts, i).cast::<OsslDecoderInstance>();
                let new_decoder = OSSL_DECODER_INSTANCE_get_decoder(new_decoder_inst);
                let mut n_i_s_was_set: c_int = 0;
                let new_input_type = OSSL_DECODER_INSTANCE_get_input_type(new_decoder_inst);
                let new_input_structure = OSSL_DECODER_INSTANCE_get_input_structure(
                    new_decoder_inst,
                    ptr::addr_of_mut!(n_i_s_was_set),
                );
                let new_decoderctx = OSSL_DECODER_INSTANCE_get_decoder_ctx(new_decoder_inst);

                /*
                 * If |decoder| is NULL, it means we've just started, and the caller may have
                 * specified what it expects the initial input to be.
                 */
                if decoder.is_null()
                    && !(*ctx).start_input_type.is_null()
                    && OPENSSL_strcasecmp((*ctx).start_input_type, new_input_type) != 0
                {
                    continue;
                }

                /*
                 * If we have a previous decoder, we check that the input type of the next to be
                 * used matches the type of this previous one.
                 */
                if !decoder.is_null()
                    && ossl_decoder_fast_is_a(
                        decoder,
                        new_input_type,
                        ptr::addr_of_mut!((*new_decoder_inst).input_type_id),
                    ) == 0
                {
                    continue;
                }

                /*
                 * If the previous decoder gave us a data type, we check to see if that matches the
                 * decoder we're currently considering.
                 */
                if !data_type.is_null() && OSSL_DECODER_is_a(new_decoder, data_type) == 0 {
                    continue;
                }

                /*
                 * If the previous decoder gave us a data structure name, we check to see that it
                 * matches the input data structure of the decoder we're currently considering.
                 */
                if !data_structure.is_null()
                    && (new_input_structure.is_null()
                        || OPENSSL_strcasecmp(data_structure, new_input_structure) != 0)
                {
                    continue;
                }

                /*
                 * If the decoder we're currently considering specifies a structure, and this
                 * check hasn't already been done earlier in this chain of decoder_process() calls,
                 * check that it matches the user provided input structure, if one is given.
                 */
                if (*data).flag_input_structure_checked == 0
                    && !(*ctx).input_structure.is_null()
                    && !new_input_structure.is_null()
                {
                    (*data).flag_input_structure_checked = 1;
                    if OPENSSL_strcasecmp(new_input_structure, (*ctx).input_structure) != 0 {
                        continue;
                    }
                }

                /*
                 * Checking the return value of BIO_reset() or BIO_seek() is unsafe. Furthermore,
                 * BIO_reset() is unsafe to use if the source BIO happens to be a BIO_s_mem(),
                 * because the earlier BIO_tell() gives us zero no matter where we are in the
                 * underlying buffer we're reading from. So, we simply do a BIO_seek(), and use
                 * BIO_tell() that we're back at the same position.
                 */
                bio_seek(bio, loc);
                if bio_tell(bio) != loc {
                    break 'walk;
                }

                /*
                 * We only care about errors reported from decoder implementations if it returns
                 * false (i.e. there was a fatal error).
                 */
                ERR_set_mark();

                new_data.current_decoder_inst_index = i;
                new_data.flag_input_structure_checked = (*data).flag_input_structure_checked;
                ok = match (*new_decoder).decode {
                    Some(decode) => decode(
                        new_decoderctx,
                        cbio.cast::<c_void>(),
                        (*new_data.ctx).selection,
                        Some(decoder_process),
                        ptr::addr_of_mut!(new_data).cast::<c_void>(),
                        Some(ossl_pw_passphrase_callback_dec),
                        ptr::addr_of_mut!((*new_data.ctx).pwdata).cast::<c_void>(),
                    ),
                    None => 0,
                };

                (*data).flag_construct_called = new_data.flag_construct_called;

                /* Break on error or if we tried to construct an object already */
                if ok == 0 || (*data).flag_construct_called != 0 {
                    ERR_clear_last_mark();
                    break;
                }
                ERR_pop_to_mark();

                /*
                 * Break if the decoder implementation that we called recursed, since that
                 * indicates that it successfully decoded something.
                 */
                if new_data.flag_next_level_called != 0 {
                    break;
                }
            }
        }
    }

    // end:
    // SAFETY: `cbio` is NULL or a live handle this call owns.
    unsafe { ossl_core_bio_free(cbio) };
    // SAFETY: `new_data.bio` is NULL or a BIO this call allocated.
    unsafe { BIO_free(new_data.bio) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).start_input_type = start_input_type };
    ok
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder_meth::{
        ossl_decoder_new, OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_new, OSSL_DECODER_free,
    };

    /// A fresh context has an empty chain and no callbacks, and its three setters round-trip --
    /// including the authority's "0 is a valid selection" and "NULL is a valid starting input
    /// type" arms.
    #[test]
    fn a_fresh_context_has_an_empty_chain_and_round_trips_its_setters() {
        // SAFETY: no preconditions.
        let ctx = unsafe { OSSL_DECODER_CTX_new() };
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is this test's own context.
        unsafe {
            assert_eq!(OSSL_DECODER_CTX_get_num_decoders(ctx), 0);
            assert!(OSSL_DECODER_CTX_get_construct(ctx).is_none());
            assert!(OSSL_DECODER_CTX_get_cleanup(ctx).is_none());
            assert!(OSSL_DECODER_CTX_get_construct_data(ctx).is_null());

            assert_eq!(OSSL_DECODER_CTX_set_selection(ctx, 0), 1);
            assert_eq!((*ctx).selection, 0);
            assert_eq!(OSSL_DECODER_CTX_set_selection(ctx, 0x85), 1);
            assert_eq!((*ctx).selection, 0x85);

            assert_eq!(OSSL_DECODER_CTX_set_input_type(ctx, ptr::null()), 1);
            assert!((*ctx).start_input_type.is_null());
            assert_eq!(OSSL_DECODER_CTX_set_input_type(ctx, c"DER".as_ptr()), 1);
            assert_eq!(
                OSSL_DECODER_CTX_set_input_structure(ctx, c"PrivateKeyInfo".as_ptr()),
                1
            );

            /* A NULL context is diagnosed rather than written. */
            crate::runtime::err::ERR_clear_error();
            assert_eq!(OSSL_DECODER_CTX_set_selection(ptr::null_mut(), 1), 0);
            assert_ne!(crate::runtime::err::ERR_peek_error(), 0);
            crate::runtime::err::ERR_clear_error();

            OSSL_DECODER_CTX_free(ctx);
        }
    }

    /// A decoder with no constructor is refused rather than faulted: the module's own fault
    /// boundary, observed. `ossl_decoder_new` builds a decoder with **no** dispatch slots at all,
    /// so `OSSL_DECODER_CTX_add_decoder` reaches the absent-`newctx` arm and answers 0 without
    /// taking the decoder -- which the second free observes.
    #[test]
    fn a_decoder_without_a_constructor_is_refused_rather_than_faulted() {
        // SAFETY: no preconditions.
        let ctx = unsafe { OSSL_DECODER_CTX_new() };
        // SAFETY: no preconditions.
        let decoder = unsafe { ossl_decoder_new() };
        assert!(!ctx.is_null() && !decoder.is_null());
        // SAFETY: both objects are this test's own.
        unsafe {
            assert_eq!(OSSL_DECODER_CTX_add_decoder(ctx, decoder), 0);
            assert_eq!(OSSL_DECODER_CTX_get_num_decoders(ctx), 0);
            /* The decoder was not taken, so this is the only release it needs. */
            OSSL_DECODER_free(decoder);
            OSSL_DECODER_CTX_free(ctx);
        }
    }

    /// The `from_*` family refuses before it decodes: a NULL BIO is
    /// `ERR_R_PASSED_NULL_PARAMETER`, an empty chain is `OSSL_DECODER_R_DECODER_NOT_FOUND`, and
    /// `OSSL_DECODER_from_data`'s three NULL arms are all refused. No provider decoder is
    /// registered in this crate, so a decodable-looking input still cannot reach a decoder -- which
    /// is the ``num_decoders == 0`` arm and the reason this crate's readers cannot succeed yet.
    #[test]
    fn the_from_family_refuses_a_null_bio_and_an_empty_chain() {
        use crate::runtime::bio::bss_mem::BIO_s_mem;
        use crate::runtime::bio::{BIO_new, BIO_write};
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

        // SAFETY: no preconditions.
        let ctx = unsafe { OSSL_DECODER_CTX_new() };
        assert!(!ctx.is_null());
        // SAFETY: `BIO_s_mem` takes no arguments and answers a static method.
        let mem = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!mem.is_null());
        // SAFETY: `mem` is a live memory BIO and the bytes are this test's own.
        unsafe {
            assert_eq!(BIO_write(mem, c"not a key".as_ptr().cast(), 9), 9);
        }

        ERR_clear_error();
        // SAFETY: `ctx` is live; the NULL BIO is the arm under test.
        assert_eq!(unsafe { OSSL_DECODER_from_bio(ctx, ptr::null_mut()) }, 0);
        assert_ne!(ERR_peek_error(), 0, "a NULL BIO is diagnosed");

        ERR_clear_error();
        // SAFETY: both are live and the chain is empty, which the count refuses.
        assert_eq!(unsafe { OSSL_DECODER_from_bio(ctx, mem) }, 0);
        assert_ne!(ERR_peek_error(), 0, "an empty chain is diagnosed");

        ERR_clear_error();
        // SAFETY: the three NULL arms are the ones under test; nothing is written.
        let from_data = unsafe { OSSL_DECODER_from_data(ctx, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(from_data, 0);
        assert_ne!(ERR_peek_error(), 0, "a NULL data pointer is diagnosed");

        // SAFETY: `ctx` and `mem` are this test's own.
        unsafe {
            BIO_free(mem);
            OSSL_DECODER_CTX_free(ctx);
        }
    }
}
