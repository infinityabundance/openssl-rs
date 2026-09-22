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
//! ## What is withheld, as one named block, and why it is one block
//!
//! * `OSSL_DECODER_CTX_add_extra` (`:556-679`) and its two visitors `collect_all_decoders`
//!   (`:430-437`) and `collect_extra_decoder` (`:439-546`), its comparator `decoder_sk_cmp`
//!   (`:548-554`) and its state `collect_extra_decoder_data_st` (`:411-425`);
//! * `decoder_process` (`:798-1165`) and its state `decoder_process_data_st` (`:27-46`);
//! * `OSSL_DECODER_from_bio` (`:47-118`), `bio_from_file` (`:122-133`), `OSSL_DECODER_from_fp`
//!   (`:134-145`) and `OSSL_DECODER_from_data` (`:147-167`).
//!
//! Every one of them reaches `OSSL_DECODER_do_all_provided` or `OSSL_DECODER_fetch` --
//! `decoder_meth.c`'s fetch block, which is still withheld because its own first caller is
//! `decoder_pkey.c`, the next unit. `add_extra` calls `do_all_provided` directly; `decoder_process`
//! calls `add_extra` (`:1103`); `from_bio` calls `decoder_process` (`:88`) and
//! `OSSL_DECODER_CTX_get_num_decoders`; `from_fp` and `from_data` wrap `from_bio`. So they land
//! together, with that block, rather than one at a time.
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

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::decoder_meth::{
    ossl_decoder_parsed_properties, OsslDecoder, OsslDecoderCtx, OsslDecoderInstance,
};
use crate::params::OSSL_PARAM_construct_utf8_string;
use crate::property::query::{ossl_property_find_property, ossl_property_get_string_value};
use crate::provider::{ossl_provider_libctx, OSSL_PROVIDER_get0_provider_ctx};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push};
use crate::selftest::OsslCallback;

/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h`, the string `"data-structure"`, the same
/// constant `src/encoder_lib.rs` carries.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();

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
#[allow(dead_code)] // read by decoder_pkey.c's `decoder_construct_pkey`, next unit
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
#[allow(dead_code)] // read by decoder_pkey.c's cache, next unit
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
#[allow(dead_code)] // read by decoder_process, withheld with the fetch block
pub(crate) unsafe fn ossl_decoder_ctx_set_harderr(ctx: *mut OsslDecoderCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).harderr = 1 };
}

/// `int ossl_decoder_ctx_get_harderr(const OSSL_DECODER_CTX *ctx)` — `decoder_lib.c:349-353`.
///
/// # Safety
/// `ctx` must be live.
#[allow(dead_code)] // read by decoder_process, withheld with the fetch block
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
}
