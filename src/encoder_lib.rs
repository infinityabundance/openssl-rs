//! Phase 10 — `crypto/encode_decode/encoder_lib.c`: the `OSSL_ENCODER_CTX` chain and its runner.
//!
//! The second of the three encoder units (D361). Where `src/encoder_meth.rs` is the method object
//! and the dispatch scan, this unit is the **context**: the chain of `OSSL_ENCODER_INSTANCE`s the
//! method objects are instantiated into, the setters that describe what to encode, and
//! `encoder_process` -- the mutually recursive walk that tries each instance from the end of the
//! chain and, when one succeeds, feeds its output to the next. `OSSL_ENCODER_CTX_new` and its
//! `_set_params`/`_free` siblings live in the *other* unit but land with this one, because they
//! call this unit's `ossl_encoder_instance_free`, `OSSL_ENCODER_INSTANCE_get_encoder` and
//! `OSSL_ENCODER_INSTANCE_get_encoder_ctx`; that is the measurement D360 recorded and this entry
//! discharges.
//!
//! ## The walk, and the three things about it that a transcription gets wrong
//!
//! `encoder_process` (`:417-704`) is the whole reason this file is not mechanical.
//!
//! * **It recurses on an index, and the loop is a reverse walk.**
//!   `for (i = data->current_encoder_inst_index; i-- > 0;)` visits the instances from the *last* to
//!   the *first*, and each iteration recurses with `i` as the next index. The chain is therefore
//!   built by the **deepest** call first, which is why `ossl_encoder_ctx_setup_for_pkey` places the
//!   same-provider encoders *last*: the chain is processed in reverse order. Only the top call sets
//!   `top = 1`, and `top` decides whether the output type is compared against the *caller's* desired
//!   type or against the **name of the next encoder** (`OSSL_ENCODER_is_a`).
//! * **`ok` is three-valued and the recursion's answer is read as three cases.** `-1` means the
//!   recursion found nothing and *this* level should be tried; `0` means the recursion failed and
//!   this level should be skipped; `1` means the recursion succeeded and this level should use the
//!   result. The loop breaks on `ok != 0`, which is *not* "on success": a `-1` also breaks it.
//! * **`count_output_structure` counts matches, and `-1` and `0` are different states.** A context
//!   with no desired structure starts at `-1`; one with a desired structure starts at `0` and is
//!   incremented only by a matching instance, so `0` at the top of a `case -1:` means "a structure
//!   was asked for and nothing matched" and is a hard `return 0`.
//!
//! The authority's `for` loop plus its post-loop `if (i < 0) ... else switch (ok)` is a `goto`
//! pattern; Rust has none, so the loop is a `loop` whose test reproduces `i-- > 0` exactly -- the
//! decrement happens **before** the test can fail, so a normally-exhausted loop leaves `i == -1`
//! while a `break` leaves the index that broke -- and the post-loop half is one `if`. The three
//! `continue`s inside the body are Rust `continue`s, which reach the same decrement.
//!
//! ## What is now landed at the tail
//!
//! The three `ossl_bio_print_*` helpers -- `ossl_bio_print_labeled_bignum` (`:706`),
//! `ossl_bio_print_labeled_buf` (`:785`) and `ossl_bio_print_ffc_params` (`:813`) -- are the tail of
//! the file and are called by **provider encoder implementations**. They landed with the first of
//! them, `src/provider/encode_key2text.rs` (10.1), which is the caller the `prerequisites.json`
//! `divergences` row that withheld them named as their landing condition. They are transcribed
//! whole; the `LABELED_BUF_PRINT_WIDTH`-octet layout, the one-word decimal-with-hex form and the
//! `X9.42` parameter layout are all observable in `RT-CODEC`'s transcript.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::bn::bignum::{BN_bn2hex, BN_is_negative, BN_is_zero, BN_num_bits, BigNum};
use crate::bn::intern::bn_get_words;
use crate::encoder_meth::{
    ossl_encoder_parsed_properties, EncoderCleanupFn, EncoderConstructFn, OSSL_ENCODER_free,
    OSSL_ENCODER_get0_name, OSSL_ENCODER_get0_properties, OSSL_ENCODER_get0_provider,
    OSSL_ENCODER_is_a, OSSL_ENCODER_up_ref, OsslEncoder, OsslEncoderCtx, OsslEncoderInstance,
};
use crate::ffc::dh::{ossl_ffc_named_group_get_name, ossl_ffc_uid_to_dh_named_group};
use crate::ffc::FfcParams;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OsslParam,
};
use crate::passphrase::ossl_pw_passphrase_callback_enc;
use crate::property::query::{ossl_property_find_property, ossl_property_get_string_value};
use crate::provider::{ossl_provider_libctx, OSSL_PROVIDER_get0_provider_ctx};
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::core_bio::{ossl_core_bio_free, ossl_core_bio_new_from_bio, OsslCoreBio};
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::{
    BIO_free, BIO_new, Bio, BIO_C_GET_BUF_MEM_PTR, BIO_C_SET_FILE_PTR, BIO_NOCLOSE,
};
use crate::runtime::buffer::BufMem;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::NID_undef;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::runtime::str::OPENSSL_strcasecmp;

/// `ERR_DATA_BUFFER`'s size, as `src/evp/signature.rs` records it: the stack buffer a
/// pre-formatted `ERR_raise_data` message is built in.
const ERR_DATA_BUFFER: usize = 1024;

/// `OSSL_OBJECT_PARAM_DATA_TYPE` -- `include/openssl/core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` -- `core_names.h:357`, the string `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` -- `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();

/// `struct encoder_process_data_st` -- `encoder_lib.c:44-64`.
///
/// Fields the recursion passes **down** (`level`, `next_encoder_inst`, `count_output_structure`)
/// and fields it passes **up** (`prev_encoder_inst`, `running_output`, `data_type`) are interleaved
/// in the authority's order; the order is kept.
struct EncoderProcessData {
    /// `OSSL_ENCODER_CTX *ctx`.
    ctx: *mut OsslEncoderCtx,
    /// `BIO *bio` -- the current output.
    bio: *mut Bio,
    /// `int current_encoder_inst_index`.
    current_encoder_inst_index: c_int,
    /// `int level` -- the recursion depth.
    level: c_int,
    /// `OSSL_ENCODER_INSTANCE *next_encoder_inst`.
    next_encoder_inst: *mut OsslEncoderInstance,
    /// `int count_output_structure`.
    count_output_structure: c_int,
    /// `OSSL_ENCODER_INSTANCE *prev_encoder_inst`.
    prev_encoder_inst: *mut OsslEncoderInstance,
    /// `unsigned char *running_output`.
    running_output: *mut c_uchar,
    /// `size_t running_output_length`.
    running_output_length: usize,
    /// `const char *data_type` -- the name of the first succeeding implementation.
    data_type: *const c_char,
}

/// The instance at index `i` of `data`'s chain -- the authority spells this inline three times.
///
/// # Safety
/// `data` must be live and `i` a valid index into its chain.
unsafe fn instance_at(data: *mut EncoderProcessData, i: c_int) -> *mut OsslEncoderInstance {
    // SAFETY: `data` is live per the contract, so its context and chain are too.
    unsafe { OPENSSL_sk_value((*(*data).ctx).encoder_insts, i).cast::<OsslEncoderInstance>() }
}

/// `static BIO *bio_from_file(FILE *fp)` -- `encoder_lib.c:94-104`.
///
/// `BIO_set_fp(b, fp, BIO_NOCLOSE)` is `BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE, fp)`, which is
/// how the crate spells the macro everywhere else (`src/evp/pem_bridge.rs:1183`).
///
/// # Safety
/// `fp` must be a live `FILE *`.
unsafe fn bio_from_file(fp: *mut c_void) -> *mut Bio {
    // SAFETY: `BIO_s_file` takes no arguments and answers a static method.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_99) };
        return ptr::null_mut();
    }
    // SAFETY: `b` is a live file BIO and `fp` is the caller's `FILE *`.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp) };
    b
}

/// `int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out)` -- `encoder_lib.c:68-91`.
///
/// The two refusals mean different things: **no encoders at all** is
/// `OSSL_ENCODER_R_ENCODER_NOT_FOUND` with the long "did you forget to load the default providers?"
/// message, and a context with encoders but no constructor or destructor is `ERR_R_INIT_FAIL`. The
/// second is unreachable from `OSSL_ENCODER_CTX_new_for_pkey`, which sets both.
///
/// # Safety
/// `ctx` must be live or NULL; `out` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_to_bio(ctx: *mut OsslEncoderCtx, out: *mut Bio) -> c_int {
    let mut data = EncoderProcessData {
        ctx,
        bio: out,
        current_encoder_inst_index: 0,
        level: 0,
        next_encoder_inst: ptr::null_mut(),
        count_output_structure: 0,
        prev_encoder_inst: ptr::null_mut(),
        running_output: ptr::null_mut(),
        running_output_length: 0,
        data_type: ptr::null(),
    };
    // SAFETY: `ctx` is live or NULL, which `OSSL_ENCODER_CTX_get_num_encoders` accepts.
    data.current_encoder_inst_index = unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) };

    if data.current_encoder_inst_index == 0 {
        // SAFETY: a compile-time-constant site; the message is the authority's own single literal.
        unsafe {
            raise_site_data(
                &err_sites::ENCODER_LIB_78,
                c"No encoders were found. For standard encoders you need at least one of the default or base providers available. Did you forget to load them?".as_ptr(),
            )
        };
        return 0;
    }

    // SAFETY: the count is non-zero, so `ctx` is live and non-NULL here.
    unsafe {
        if (*ctx).cleanup.is_none() || (*ctx).construct.is_none() {
            raise_site(&err_sites::ENCODER_LIB_86);
            return 0;
        }
    }

    // SAFETY: every field of `data` is set above and the walk's contract is met.
    c_int::from(unsafe { encoder_process(&mut data) } > 0)
}

/// `int OSSL_ENCODER_to_fp(OSSL_ENCODER_CTX *ctx, FILE *fp)` -- `encoder_lib.c:106-116`.
///
/// # Safety
/// `ctx` must be live; `fp` must be a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_to_fp(ctx: *mut OsslEncoderCtx, fp: *mut c_void) -> c_int {
    let mut ret = 0;
    // SAFETY: `fp` is live per the contract.
    let b = unsafe { bio_from_file(fp) };
    if !b.is_null() {
        // SAFETY: `b` is live and `ctx` is the caller's.
        ret = unsafe { OSSL_ENCODER_to_bio(ctx, b) };
    }
    // SAFETY: `b` is NULL or a live BIO this call owns.
    unsafe { BIO_free(b) };
    ret
}

/// `int OSSL_ENCODER_to_data(OSSL_ENCODER_CTX *ctx, unsigned char **pdata,
/// size_t *pdata_len)` -- `encoder_lib.c:119-168`.
///
/// Three arms, and the middle is the subtlety the authority's own comment flags: when the caller's
/// buffer is **too small**, `ret` is cleared but `*pdata_len` is *not* updated, because the
/// authority deliberately leaves the caller's length alone rather than confusingly reporting a size
/// it did not fill. A buffer that fits has its length **decremented** by what was written; a NULL
/// buffer receives the memory BIO's own allocation, **stolen** by setting `buf->data` to NULL.
///
/// # Safety
/// `ctx` must be live; `pdata_len` must be writable; `pdata` must be NULL or point at a writable
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_to_data(
    ctx: *mut OsslEncoderCtx,
    pdata: *mut *mut c_uchar,
    pdata_len: *mut usize,
) -> c_int {
    let mut ret = 0;

    if pdata_len.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_127) };
        return 0;
    }

    // SAFETY: `BIO_s_mem` takes no arguments and answers a static method.
    let out = unsafe { BIO_new(BIO_s_mem()) };

    if !out.is_null() {
        // SAFETY: `out` is live and `ctx` is the caller's.
        let wrote = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
        let mut buf: *mut BufMem = ptr::null_mut();
        // SAFETY: `out` is a live memory BIO and `buf` is this frame's own slot.
        let got = unsafe {
            BIO_ctrl(
                out,
                BIO_C_GET_BUF_MEM_PTR,
                0,
                ptr::addr_of_mut!(buf).cast::<c_void>(),
            )
        };
        if wrote != 0 && got > 0 {
            ret = 1; /* Hope for the best. A too small buffer will clear this. */

            // SAFETY: `pdata` is NULL or the caller's pointer-to-pointer and `buf` is live.
            unsafe {
                if !pdata.is_null() && !(*pdata).is_null() {
                    if *pdata_len < (*buf).length {
                        ret = 0;
                    } else {
                        *pdata_len -= (*buf).length;
                    }
                } else {
                    *pdata_len = (*buf).length;
                }

                if ret != 0 && !pdata.is_null() {
                    if !(*pdata).is_null() {
                        ptr::copy_nonoverlapping(
                            (*buf).data.cast::<c_uchar>(),
                            *pdata,
                            (*buf).length,
                        );
                        *pdata = (*pdata).add((*buf).length);
                    } else {
                        *pdata = (*buf).data.cast::<c_uchar>();
                        (*buf).data = ptr::null_mut();
                    }
                }
            }
        }
    }
    // SAFETY: `out` is NULL or a live BIO this call owns.
    unsafe { BIO_free(out) };
    ret
}

/// `int OSSL_ENCODER_CTX_set_selection(OSSL_ENCODER_CTX *ctx, int selection)` --
/// `encoder_lib.c:170-184`.
///
/// Both refusals are live: a NULL context is `ERR_R_PASSED_NULL_PARAMETER` and a **zero** selection
/// is `ERR_R_PASSED_INVALID_ARGUMENT`, so a caller who passes `0` gets a diagnosis rather than a
/// context that encodes nothing.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_selection(
    ctx: *mut OsslEncoderCtx,
    selection: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_173) };
        return 0;
    }
    if selection == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_178) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).selection = selection };
    1
}

/// `int OSSL_ENCODER_CTX_set_output_type(OSSL_ENCODER_CTX *ctx, const char *output_type)` --
/// `encoder_lib.c:186-196`.
///
/// # Safety
/// `ctx` must be live; `output_type` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_output_type(
    ctx: *mut OsslEncoderCtx,
    output_type: *const c_char,
) -> c_int {
    if ctx.is_null() || output_type.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_190) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).output_type = output_type };
    1
}

/// `int OSSL_ENCODER_CTX_set_output_structure(OSSL_ENCODER_CTX *ctx,
/// const char *output_structure)` -- `encoder_lib.c:198-208`.
///
/// # Safety
/// `ctx` must be live; `output_structure` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_output_structure(
    ctx: *mut OsslEncoderCtx,
    output_structure: *const c_char,
) -> c_int {
    if ctx.is_null() || output_structure.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_202) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).output_structure = output_structure };
    1
}

/// `static OSSL_ENCODER_INSTANCE *ossl_encoder_instance_new(OSSL_ENCODER *encoder,
/// void *encoderctx)` -- `encoder_lib.c:210-266`.
///
/// The two mandatory-once properties are read here and nowhere else: `output_type` comes from the
/// `"output"` property and a missing one is a **hard failure** with
/// `ERR_R_INVALID_PROPERTY_DEFINITION`, while `"structure"` is optional. A missing property *list*
/// is the same failure before either lookup.
///
/// # Safety
/// `encoder` must be live; `encoderctx` is the provider's own context, possibly NULL.
unsafe fn ossl_encoder_instance_new(
    encoder: *mut OsslEncoder,
    encoderctx: *mut c_void,
) -> *mut OsslEncoderInstance {
    if encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_220) };
        return ptr::null_mut();
    }

    // SAFETY: the constructor only asks for a zeroed block of the object's size.
    let inst = CRYPTO_zalloc(core::mem::size_of::<OsslEncoderInstance>(), ptr::null(), 0)
        .cast::<OsslEncoderInstance>();
    if inst.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `encoder` is live; the reference is released by `ossl_encoder_instance_free`.
    if unsafe { OSSL_ENCODER_up_ref(encoder) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_228) };
        // SAFETY: `inst` is live and owned here.
        return unsafe { fail_instance(inst) };
    }

    // SAFETY: `encoder` is live.
    let prov = unsafe { OSSL_ENCODER_get0_provider(encoder) };
    // SAFETY: `prov` is a live provider (the encoder holds a reference to it).
    let libctx = unsafe { ossl_provider_libctx(prov) };
    // SAFETY: `encoder` is live.
    let props = unsafe { ossl_encoder_parsed_properties(encoder) };
    if props.is_null() {
        let mut msg = [0 as c_char; ERR_DATA_BUFFER];
        // SAFETY: `msg` is the buffer, the format is the authority's, and its one argument is
        // NUL-terminated.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"there are no property definitions with encoder %s".as_ptr(),
                OSSL_ENCODER_get0_name(encoder),
            );
            raise_site_data(&err_sites::ENCODER_LIB_236, msg.as_ptr());
        }
        // SAFETY: `inst` is live and owned here.
        return unsafe { fail_instance(inst) };
    }

    /* The "output" property is mandatory */
    // SAFETY: `props` is live and the literal is readable.
    let prop = unsafe { ossl_property_find_property(props, libctx, c"output".as_ptr()) };
    // SAFETY: `libctx` is the encoder's provider context; `prop` is NULL or a live definition.
    let output_type = unsafe { ossl_property_get_string_value(libctx, prop) };
    if output_type.is_null() {
        let mut msg = [0 as c_char; ERR_DATA_BUFFER];
        // SAFETY: `msg` is the buffer, the format is the authority's, and all three arguments are
        // NUL-terminated.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"the mandatory 'output' property is missing for encoder %s (properties: %s)"
                    .as_ptr(),
                OSSL_ENCODER_get0_name(encoder),
                OSSL_ENCODER_get0_properties(encoder),
            );
            raise_site_data(&err_sites::ENCODER_LIB_246, msg.as_ptr());
        }
        // SAFETY: `inst` is live and owned here.
        return unsafe { fail_instance(inst) };
    }

    /* The "structure" property is optional */
    let mut output_structure: *const c_char = ptr::null();
    // SAFETY: `props` is live and the literal is readable.
    let sprop = unsafe { ossl_property_find_property(props, libctx, c"structure".as_ptr()) };
    if !sprop.is_null() {
        // SAFETY: `sprop` is a live definition and `libctx` is the encoder's context.
        output_structure = unsafe { ossl_property_get_string_value(libctx, sprop) };
    }

    // SAFETY: `inst` is live and uniquely owned here.
    unsafe {
        (*inst).encoder = encoder;
        (*inst).encoderctx = encoderctx;
        (*inst).output_type = output_type;
        (*inst).output_structure = output_structure;
    }
    inst
}

/// The `err:` label of [`ossl_encoder_instance_new`] -- `encoder_lib.c:263-265`.
///
/// # Safety
/// `inst` must be a live instance this call allocated.
unsafe fn fail_instance(inst: *mut OsslEncoderInstance) -> *mut OsslEncoderInstance {
    // SAFETY: `inst` is live and owned here.
    unsafe { ossl_encoder_instance_free(inst) };
    ptr::null_mut()
}

/// `void ossl_encoder_instance_free(OSSL_ENCODER_INSTANCE *encoder_inst)` --
/// `encoder_lib.c:268-278`.
///
/// Three releases in the authority's order: the provider context through the encoder's own
/// `freectx` (so the *encoder* must still be live), then the encoder reference, then the instance.
/// The NULL tests are per-field, which is what makes the constructor's `err:` label safe to reach
/// with a half-built instance.
///
/// # Safety
/// `encoder_inst` must be NULL or a live instance this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn ossl_encoder_instance_free(encoder_inst: *mut OsslEncoderInstance) {
    if encoder_inst.is_null() {
        return;
    }
    // SAFETY: `encoder_inst` is live.
    let encoder = unsafe { (*encoder_inst).encoder };
    if !encoder.is_null() {
        // SAFETY: `encoder` is live.
        if let Some(freectx) = unsafe { (*encoder).freectx } {
            // SAFETY: `freectx` is a live provider callback and `encoderctx` is its context.
            unsafe { freectx((*encoder_inst).encoderctx) };
        }
        // SAFETY: `encoder_inst` is live.
        unsafe { (*encoder_inst).encoderctx = ptr::null_mut() };
        // SAFETY: `encoder` is live; this releases the reference `ossl_encoder_instance_new` took.
        unsafe { OSSL_ENCODER_free(encoder) };
        // SAFETY: `encoder_inst` is live.
        unsafe { (*encoder_inst).encoder = ptr::null_mut() };
    }
    // SAFETY: `encoder_inst` is this call's own allocation.
    unsafe { CRYPTO_free(encoder_inst.cast(), ptr::null(), 0) };
}

/// `static int ossl_encoder_ctx_add_encoder_inst(OSSL_ENCODER_CTX *ctx,
/// OSSL_ENCODER_INSTANCE *ei)` -- `encoder_lib.c:280-305`.
///
/// The stack is created lazily on the first push, which is why `OSSL_ENCODER_CTX_get_num_encoders`
/// can answer 0 for a context that has never had an instance.
///
/// # Safety
/// `ctx` must be live; `ei` must be a live instance whose ownership is handed over.
unsafe fn ossl_encoder_ctx_add_encoder_inst(
    ctx: *mut OsslEncoderCtx,
    ei: *mut OsslEncoderInstance,
) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe {
        if (*ctx).encoder_insts.is_null() {
            (*ctx).encoder_insts = OPENSSL_sk_new_null();
            if (*ctx).encoder_insts.is_null() {
                raise_site(&err_sites::ENCODER_LIB_287);
                return 0;
            }
        }
        c_int::from(OPENSSL_sk_push((*ctx).encoder_insts, ei.cast::<c_void>()) > 0)
    }
}

/// `int OSSL_ENCODER_CTX_add_encoder(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER *encoder)` --
/// `encoder_lib.c:307-337`.
///
/// The provider context and the encoder context are two different objects: the authority takes the
/// first from the provider and gives it to the encoder's `newctx`. The `encoderctx = NULL` after the
/// instance is built is deliberate -- from that point the *instance* owns it, and the `err:` label
/// would otherwise free it twice.
///
/// # Safety
/// `ctx` must be live; `encoder` must be live and is referenced, not adopted.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_add_encoder(
    ctx: *mut OsslEncoderCtx,
    encoder: *mut OsslEncoder,
) -> c_int {
    if ctx.is_null() || encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_315) };
        return 0;
    }

    // SAFETY: `encoder` is live.
    let prov = unsafe { OSSL_ENCODER_get0_provider(encoder) };
    // SAFETY: `prov` is live (the encoder holds a reference).
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(prov) };

    // SAFETY: `encoder` is live and `newctx` is a live provider callback when present.
    let encoderctx = match unsafe { (*encoder).newctx } {
        // SAFETY: `newctx` is a live callback from the provider's dispatch table and `provctx` is
        // the context `OSSL_PROVIDER_get0_provider_ctx` answered for the same provider.
        Some(newctx) => unsafe { newctx(provctx) },
        None => ptr::null_mut(),
    };
    if encoderctx.is_null() {
        // SAFETY: no instance and no context exist, so the label frees nothing.
        return unsafe { add_encoder_fail(ptr::null_mut(), encoder, ptr::null_mut()) };
    }

    // SAFETY: `encoder` is live and `encoderctx` is the context the provider just built.
    let inst = unsafe { ossl_encoder_instance_new(encoder, encoderctx) };
    if inst.is_null() {
        // SAFETY: `encoderctx` is still owned here; no instance took it.
        return unsafe { add_encoder_fail(ptr::null_mut(), encoder, encoderctx) };
    }

    // SAFETY: `ctx` is live and `inst` is live and handed over.
    if unsafe { ossl_encoder_ctx_add_encoder_inst(ctx, inst) } == 0 {
        // SAFETY: `inst` is live and still owned here, so the label releases it.
        return unsafe { add_encoder_fail(inst, encoder, ptr::null_mut()) };
    }

    1
}

/// The `err:` label of [`OSSL_ENCODER_CTX_add_encoder`] -- `encoder_lib.c:332-336`.
///
/// # Safety
/// Each pointer must be NULL or live and not owned by anything else.
unsafe fn add_encoder_fail(
    inst: *mut OsslEncoderInstance,
    encoder: *mut OsslEncoder,
    encoderctx: *mut c_void,
) -> c_int {
    // SAFETY: each pointer is NULL or live per the contract.
    unsafe {
        ossl_encoder_instance_free(inst);
        if !encoderctx.is_null() {
            if let Some(freectx) = (*encoder).freectx {
                freectx(encoderctx);
            }
        }
    }
    0
}

/// `int OSSL_ENCODER_CTX_add_extra(OSSL_ENCODER_CTX *ctx, OSSL_LIB_CTX *libctx,
/// const char *propq)` -- `encoder_lib.c:339-343`.
///
/// **A `return 1;` and nothing else** in this authority revision: the "extra" encoders the name
/// refers to are not looked up at all. The signature is kept because callers pass all three
/// arguments and a transcription that dropped them would be the wrong function.
///
/// # Safety
/// The arguments are unused; no pointer is read.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_add_extra(
    _ctx: *mut OsslEncoderCtx,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    1
}

/// `int OSSL_ENCODER_CTX_get_num_encoders(OSSL_ENCODER_CTX *ctx)` -- `encoder_lib.c:345-350`.
///
/// The `ctx == NULL || ctx->encoder_insts == NULL` pair is the arm `print_pkey` reaches for a
/// legacy key: its context has no instances, so this answers **0** and the encoder path is skipped.
/// It is also why `print_pkey` may hand this function a NULL context.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_get_num_encoders(ctx: *mut OsslEncoderCtx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let insts = unsafe { (*ctx).encoder_insts };
    if insts.is_null() {
        return 0;
    }
    // SAFETY: `insts` is a live stack.
    unsafe { OPENSSL_sk_num(insts) }
}

/// `int OSSL_ENCODER_CTX_set_construct(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER_CONSTRUCT *construct)`
/// -- `encoder_lib.c:352-361`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_construct(
    ctx: *mut OsslEncoderCtx,
    construct: Option<EncoderConstructFn>,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_356) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct = construct };
    1
}

/// `int OSSL_ENCODER_CTX_set_construct_data(OSSL_ENCODER_CTX *ctx, void *construct_data)` --
/// `encoder_lib.c:363-372`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_construct_data(
    ctx: *mut OsslEncoderCtx,
    construct_data: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_367) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).construct_data = construct_data };
    1
}

/// `int OSSL_ENCODER_CTX_set_cleanup(OSSL_ENCODER_CTX *ctx, OSSL_ENCODER_CLEANUP *cleanup)` --
/// `encoder_lib.c:374-383`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_cleanup(
    ctx: *mut OsslEncoderCtx,
    cleanup: Option<EncoderCleanupFn>,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_LIB_378) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cleanup = cleanup };
    1
}

/// `OSSL_ENCODER *OSSL_ENCODER_INSTANCE_get_encoder(OSSL_ENCODER_INSTANCE *encoder_inst)` --
/// `encoder_lib.c:385-391`.
///
/// # Safety
/// `encoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_encoder(
    encoder_inst: *mut OsslEncoderInstance,
) -> *mut OsslEncoder {
    if encoder_inst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `encoder_inst` is live.
    unsafe { (*encoder_inst).encoder }
}

/// `void *OSSL_ENCODER_INSTANCE_get_encoder_ctx(OSSL_ENCODER_INSTANCE *encoder_inst)` --
/// `encoder_lib.c:393-399`.
///
/// # Safety
/// `encoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_encoder_ctx(
    encoder_inst: *mut OsslEncoderInstance,
) -> *mut c_void {
    if encoder_inst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `encoder_inst` is live.
    unsafe { (*encoder_inst).encoderctx }
}

/// `const char *OSSL_ENCODER_INSTANCE_get_output_type(OSSL_ENCODER_INSTANCE *encoder_inst)` --
/// `encoder_lib.c:401-407`.
///
/// # Safety
/// `encoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_output_type(
    encoder_inst: *mut OsslEncoderInstance,
) -> *const c_char {
    if encoder_inst.is_null() {
        return ptr::null();
    }
    // SAFETY: `encoder_inst` is live.
    unsafe { (*encoder_inst).output_type }
}

/// `const char *OSSL_ENCODER_INSTANCE_get_output_structure(OSSL_ENCODER_INSTANCE *encoder_inst)`
/// -- `encoder_lib.c:409-415`.
///
/// # Safety
/// `encoder_inst` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_INSTANCE_get_output_structure(
    encoder_inst: *mut OsslEncoderInstance,
) -> *const c_char {
    if encoder_inst.is_null() {
        return ptr::null();
    }
    // SAFETY: `encoder_inst` is live.
    unsafe { (*encoder_inst).output_structure }
}

/// `static int encoder_process(struct encoder_process_data_st *data)` --
/// `encoder_lib.c:417-704`.
///
/// See the module doc for the three properties of the walk. The structure: a `loop` reproducing
/// `for (i = n; i-- > 0;)` exactly, whose body recurses **before** this level decides anything; then
/// the authority's `if (i < 0) ok = -1; else { switch (ok) ... ; if (ok) { ...encode... } }`, with
/// `i == -1` meaning the loop was exhausted; then the tail, which runs on **every** path and is why
/// `running_output` is freed even when the walk found nothing. `OSSL_TRACE_*` is a no-op in this
/// build and is not reproduced.
///
/// # Safety
/// `data` must point at a live, initialised [`EncoderProcessData`] whose `ctx` is live.
unsafe fn encoder_process(data: *mut EncoderProcessData) -> c_int {
    let mut allocated_out: *mut Bio = ptr::null_mut();
    let mut original_data: *const c_void = ptr::null();
    let mut abstract_: [OsslParam; 10] = [OSSL_PARAM_construct_end(); 10];
    let mut current_abstract: *const OsslParam = ptr::null();

    let mut ok: c_int = -1; /* -1 signifies that the lookup loop gave nothing */
    let mut top = 0;

    // SAFETY: `data` is live per the contract.
    let n = unsafe {
        if (*data).next_encoder_inst.is_null() {
            let desired = !(*data).ctx.is_null() && !(*(*data).ctx).output_structure.is_null();
            (*data).count_output_structure = if desired { 0 } else { -1 };
            top = 1;
        }
        (*data).current_encoder_inst_index
    };

    let mut i = n;
    loop {
        // `i-- > 0`: the test reads the pre-decrement value, so the decrement happens even on the
        // iteration that leaves the loop, and a normal exit leaves `i == -1`.
        let old = i;
        i -= 1;
        if old <= 0 {
            break;
        }

        // SAFETY: every read below is a live field of `data` or of the context it names.
        unsafe {
            let mut next_encoder: *mut OsslEncoder = ptr::null_mut();
            if top == 0 {
                next_encoder = OSSL_ENCODER_INSTANCE_get_encoder((*data).next_encoder_inst);
            }

            let current_encoder_inst = instance_at(data, i);
            let current_encoder = OSSL_ENCODER_INSTANCE_get_encoder(current_encoder_inst);
            let current_encoder_ctx = OSSL_ENCODER_INSTANCE_get_encoder_ctx(current_encoder_inst);
            let current_output_type = OSSL_ENCODER_INSTANCE_get_output_type(current_encoder_inst);
            let current_output_structure =
                OSSL_ENCODER_INSTANCE_get_output_structure(current_encoder_inst);

            let mut new_data = EncoderProcessData {
                ctx: (*data).ctx,
                bio: ptr::null_mut(),
                current_encoder_inst_index: i,
                level: (*data).level + 1,
                next_encoder_inst: current_encoder_inst,
                count_output_structure: (*data).count_output_structure,
                prev_encoder_inst: ptr::null_mut(),
                running_output: ptr::null_mut(),
                running_output_length: 0,
                data_type: ptr::null(),
            };
            let _ = current_encoder;
            let _ = current_encoder_ctx;

            if top != 0 {
                if !(*(*data).ctx).output_type.is_null()
                    && OPENSSL_strcasecmp(current_output_type, (*(*data).ctx).output_type) != 0
                {
                    continue;
                }
            } else if OSSL_ENCODER_is_a(next_encoder, current_output_type) == 0 {
                continue;
            }

            if !(*(*data).ctx).output_structure.is_null() && !current_output_structure.is_null() {
                if OPENSSL_strcasecmp((*(*data).ctx).output_structure, current_output_structure)
                    != 0
                {
                    continue;
                }
                (*data).count_output_structure += 1;
            }

            ok = encoder_process(&mut new_data);

            (*data).prev_encoder_inst = new_data.prev_encoder_inst;
            (*data).running_output = new_data.running_output;
            (*data).running_output_length = new_data.running_output_length;

            if ok != 0 {
                break;
            }
        }
    }

    // SAFETY: `data` is live and every pointer read below is NULL or the caller's.
    unsafe {
        if i < 0 {
            ok = -1;
        } else {
            match ok {
                0 => {}
                -1 => {
                    if (*data).count_output_structure == 0 {
                        return 0;
                    }
                    let current_encoder_inst = instance_at(data, i);
                    let current_encoder = OSSL_ENCODER_INSTANCE_get_encoder(current_encoder_inst);
                    original_data = match (*(*data).ctx).construct {
                        Some(construct) => {
                            construct(current_encoder_inst, (*(*data).ctx).construct_data)
                        }
                        None => ptr::null(),
                    };
                    (*data).data_type = OSSL_ENCODER_get0_name(current_encoder);
                    ok = if !original_data.is_null() { 1 } else { 0 };
                }
                1 => {
                    if (*data).running_output.is_null() {
                        raise_site(&err_sites::ENCODER_LIB_614);
                        ok = 0;
                    } else {
                        let prev_output_structure =
                            OSSL_ENCODER_INSTANCE_get_output_structure((*data).prev_encoder_inst);
                        let mut p = abstract_.as_mut_ptr();
                        *p = OSSL_PARAM_construct_utf8_string(
                            OSSL_OBJECT_PARAM_DATA_TYPE.cast_mut(),
                            (*data).data_type.cast_mut(),
                            0,
                        );
                        p = p.add(1);
                        if !prev_output_structure.is_null() {
                            *p = OSSL_PARAM_construct_utf8_string(
                                OSSL_OBJECT_PARAM_DATA_STRUCTURE.cast_mut(),
                                prev_output_structure.cast_mut(),
                                0,
                            );
                            p = p.add(1);
                        }
                        *p = OSSL_PARAM_construct_octet_string(
                            OSSL_OBJECT_PARAM_DATA.cast_mut(),
                            (*data).running_output.cast::<c_void>(),
                            (*data).running_output_length,
                        );
                        p = p.add(1);
                        *p = OSSL_PARAM_construct_end();
                        current_abstract = abstract_.as_ptr();
                    }
                }
                _ => {}
            }

            if ok != 0 {
                let mut cbio: *mut OsslCoreBio = ptr::null_mut();
                let current_out: *mut Bio;

                if top != 0 {
                    current_out = (*data).bio;
                } else {
                    allocated_out = BIO_new(BIO_s_mem());
                    current_out = allocated_out;
                    if current_out.is_null() {
                        ok = 0; /* Assume BIO_new() recorded an error */
                    }
                }

                if ok != 0 {
                    cbio = ossl_core_bio_new_from_bio(current_out);
                    ok = c_int::from(!cbio.is_null());
                }
                if ok != 0 {
                    let current_encoder_inst = instance_at(data, i);
                    let current_encoder = OSSL_ENCODER_INSTANCE_get_encoder(current_encoder_inst);
                    let current_encoder_ctx =
                        OSSL_ENCODER_INSTANCE_get_encoder_ctx(current_encoder_inst);
                    ok = match (*current_encoder).encode {
                        Some(encode) => encode(
                            current_encoder_ctx,
                            cbio.cast::<c_void>(),
                            original_data,
                            current_abstract,
                            (*(*data).ctx).selection,
                            Some(ossl_pw_passphrase_callback_enc),
                            ptr::addr_of_mut!((*(*data).ctx).pwdata).cast::<c_void>(),
                        ),
                        None => 0,
                    };
                }

                ossl_core_bio_free(cbio);
                (*data).prev_encoder_inst = instance_at(data, i);
            }
        }

        // The tail, on every path.
        CRYPTO_free((*data).running_output.cast(), ptr::null(), 0);
        (*data).running_output = ptr::null_mut();

        if !allocated_out.is_null() {
            let mut buf: *mut BufMem = ptr::null_mut();
            BIO_ctrl(
                allocated_out,
                BIO_C_GET_BUF_MEM_PTR,
                0,
                ptr::addr_of_mut!(buf).cast::<c_void>(),
            );
            (*data).running_output = (*buf).data.cast::<c_uchar>();
            (*data).running_output_length = (*buf).length;
            ptr::write_bytes(buf, 0, 1);
        }

        BIO_free(allocated_out);
        if !original_data.is_null() {
            if let Some(cleanup) = (*(*data).ctx).cleanup {
                cleanup((*(*data).ctx).construct_data);
            }
        }
    }
    ok
}

/// `LABELED_BUF_PRINT_WIDTH` — `crypto/encode_decode/encoder_lib.c:27`.
const LABELED_BUF_PRINT_WIDTH: usize = 15;

/// `BN_BYTES` — `include/openssl/bn.h:38` for a 64-bit `BN_ULONG`.
const BN_BYTES: c_int = 8;

/// `int ossl_bio_print_labeled_bignum(BIO *out, const char *label, const BIGNUM *bn)` —
/// `crypto/encode_decode/encoder_lib.c:706-783`.
///
/// The three-part shape is the contract: a small value (at most one word) prints as decimal with
/// its hex in parentheses on one line; a larger one prints the label alone, then the magnitude in
/// lower-case hex, 15 bytes per line, with a leading `00` when the top bit is set and `:` between
/// bytes. A `%s%c%c` call carries the separator so the first byte of a line has none.
///
/// # Safety
/// `out` must be a live BIO; `bn` NULL or live; `label` NULL or NUL-terminated.
pub(crate) unsafe fn ossl_bio_print_labeled_bignum(
    out: *mut Bio,
    label_in: *const c_char,
    bn: *const BigNum,
) -> c_int {
    let spaces = c"    ";
    let mut use_sep = 0;
    let mut label = label_in;
    let mut post_label_spc: *const c_char = c" ".as_ptr();

    if bn.is_null() {
        return 0;
    }
    if label.is_null() {
        label = c"".as_ptr();
        post_label_spc = c"".as_ptr();
    }

    // SAFETY: `bn` is live per the contract.
    if unsafe { BN_is_zero(bn) } != 0 {
        // SAFETY: `out` is live; the format and its two `%s` arguments agree.
        return unsafe { BIO_printf(out, c"%s%s0\n".as_ptr(), label, post_label_spc) };
    }

    // `BN_num_bytes(a)` is the authority's macro `((BN_num_bits(a)+7)/8)`.
    // SAFETY: `bn` is live.
    if (unsafe { BN_num_bits(bn) } + 7) / 8 <= BN_BYTES {
        // SAFETY: `bn` is live and non-zero, so it has at least one word.
        let words = unsafe { bn_get_words(bn) };
        let mut neg: *const c_char = c"".as_ptr();
        // SAFETY: `bn` is live.
        if unsafe { BN_is_negative(bn) } != 0 {
            neg = c"-".as_ptr();
        }
        // SAFETY: `words` points at `bn`'s live magnitude; the format's `%lu`/`%lx` take a
        // `c_ulong` and `BN_ULONG` is `unsigned long` on this build.
        let word = unsafe { *words } as c_ulong;
        // SAFETY: `out` is live and every argument matches its conversion.
        return unsafe {
            BIO_printf(
                out,
                c"%s%s%s%lu (%s0x%lx)\n".as_ptr(),
                label,
                post_label_spc,
                neg,
                word,
                neg,
                word,
            )
        };
    }

    // SAFETY: `bn` is live.
    let hex_str: *mut c_char = unsafe { BN_bn2hex(bn) };
    if hex_str.is_null() {
        return 0;
    }

    // SAFETY: `hex_str` is a live NUL-terminated NUL-terminated buffer from `BN_bn2hex`.
    let ret = unsafe {
        let mut p = hex_str;
        let mut neg: *const c_char = c"".as_ptr();
        if *p == b'-' as c_char {
            p = p.add(1);
            neg = c" (Negative)".as_ptr();
        }
        if BIO_printf(out, c"%s%s\n".as_ptr(), label, neg) <= 0 {
            0
        } else {
            'blk: {
                let mut bytes: c_int = 0;
                if BIO_printf(out, c"%s".as_ptr(), spaces.as_ptr()) <= 0 {
                    break 'blk 0;
                }
                if *p >= b'8' as c_char {
                    if BIO_printf(out, c"%02x".as_ptr(), 0) <= 0 {
                        break 'blk 0;
                    }
                    bytes += 1;
                    use_sep = 1;
                }
                while *p != 0 {
                    if (bytes % 15) == 0 && bytes > 0 {
                        if BIO_printf(out, c":\n%s".as_ptr(), spaces.as_ptr()) <= 0 {
                            break 'blk 0;
                        }
                        use_sep = 0;
                    }
                    let c0 = (*p as u8).to_ascii_lowercase() as c_int;
                    let c1 = (*p.add(1) as u8).to_ascii_lowercase() as c_int;
                    let sep = if use_sep == 1 { c":" } else { c"" };
                    if BIO_printf(out, c"%s%c%c".as_ptr(), sep.as_ptr(), c0, c1) <= 0 {
                        break 'blk 0;
                    }
                    bytes += 1;
                    p = p.add(2);
                    use_sep = 1;
                }
                if BIO_printf(out, c"\n".as_ptr()) <= 0 {
                    break 'blk 0;
                }
                1
            }
        }
    };
    // SAFETY: `hex_str` is the buffer `BN_bn2hex` returned and this call owns it.
    unsafe { CRYPTO_free(hex_str.cast(), ptr::null(), 0) };
    ret
}

/// `int ossl_bio_print_labeled_buf(BIO *out, const char *label, const unsigned char *buf,
/// size_t buflen)` — `crypto/encode_decode/encoder_lib.c:785-810`.
///
/// # Safety
/// `out` must be a live BIO; `label` NUL-terminated; `buf` valid for `buflen` bytes.
pub(crate) unsafe fn ossl_bio_print_labeled_buf(
    out: *mut Bio,
    label: *const c_char,
    buf: *const c_uchar,
    buflen: usize,
) -> c_int {
    // SAFETY: `out` is live and `label` matches the `%s`.
    if unsafe { BIO_printf(out, c"%s\n".as_ptr(), label) } <= 0 {
        return 0;
    }
    let mut i: usize = 0;
    while i < buflen {
        if i.is_multiple_of(LABELED_BUF_PRINT_WIDTH) {
            // SAFETY: `out` is live; the two writes are the authority's line break and indent.
            unsafe {
                if i > 0 && BIO_printf(out, c"\n".as_ptr()) <= 0 {
                    return 0;
                }
                if BIO_printf(out, c"    ".as_ptr()) <= 0 {
                    return 0;
                }
            }
        }
        let sep = if i == buflen - 1 { c"" } else { c":" };
        // SAFETY: `out` is live; `buf` is valid for `buflen` bytes so `i < buflen` is in range.
        if unsafe { BIO_printf(out, c"%02x%s".as_ptr(), *buf.add(i) as c_int, sep.as_ptr()) } <= 0 {
            return 0;
        }
        i += 1;
    }
    // SAFETY: `out` is live.
    if unsafe { BIO_printf(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    1
}

/// `int ossl_bio_print_ffc_params(BIO *out, const FFC_PARAMS *ffc)` —
/// `crypto/encode_decode/encoder_lib.c:813-864`.
///
/// A named group prints one `GROUP:` line; otherwise the parameters print in the `X9.42` layout.
///
/// # Safety
/// `out` must be a live BIO and `ffc` live.
pub(crate) unsafe fn ossl_bio_print_ffc_params(out: *mut Bio, ffc: *const FfcParams) -> c_int {
    // SAFETY: `ffc` is live per the contract.
    if unsafe { (*ffc).nid } != NID_undef {
        // SAFETY: `ffc` is live; the uid lookup answers NULL or a static named group.
        let group = unsafe { ossl_ffc_uid_to_dh_named_group((*ffc).nid) };
        // SAFETY: `group` is NULL or live; the accessor answers NULL or a static name.
        let name = unsafe { ossl_ffc_named_group_get_name(group) };
        if name.is_null() {
            return 0;
        }
        // SAFETY: `out` is live and `name` matches the `%s`.
        if unsafe { BIO_printf(out, c"GROUP: %s\n".as_ptr(), name) } <= 0 {
            return 0;
        }
        return 1;
    }
    // SAFETY: `ffc` is live and each field is NULL or a live object it owns; `out` is live.
    unsafe {
        if ossl_bio_print_labeled_bignum(out, c"P:   ".as_ptr(), (*ffc).p) == 0 {
            return 0;
        }
        if !(*ffc).q.is_null()
            && ossl_bio_print_labeled_bignum(out, c"Q:   ".as_ptr(), (*ffc).q) == 0
        {
            return 0;
        }
        if ossl_bio_print_labeled_bignum(out, c"G:   ".as_ptr(), (*ffc).g) == 0 {
            return 0;
        }
        if !(*ffc).j.is_null()
            && ossl_bio_print_labeled_bignum(out, c"J:   ".as_ptr(), (*ffc).j) == 0
        {
            return 0;
        }
        if !(*ffc).seed.is_null()
            && ossl_bio_print_labeled_buf(out, c"SEED:".as_ptr(), (*ffc).seed, (*ffc).seedlen) == 0
        {
            return 0;
        }
        if (*ffc).gindex != -1 && BIO_printf(out, c"gindex: %d\n".as_ptr(), (*ffc).gindex) <= 0 {
            return 0;
        }
        if (*ffc).pcounter != -1
            && BIO_printf(out, c"pcounter: %d\n".as_ptr(), (*ffc).pcounter) <= 0
        {
            return 0;
        }
        if (*ffc).h != 0 && BIO_printf(out, c"h: %d\n".as_ptr(), (*ffc).h) <= 0 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A context with no chain answers **0** encoders, and that is the arm `print_pkey` takes for a
    /// legacy key: `ctx->encoder_insts == NULL`, so no lookup happens.
    #[test]
    fn a_fresh_context_has_no_encoders() {
        // SAFETY: no preconditions.
        let ctx = unsafe { crate::encoder_meth::OSSL_ENCODER_CTX_new() };
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(OSSL_ENCODER_CTX_get_num_encoders(ctx), 0);
            crate::encoder_meth::OSSL_ENCODER_CTX_free(ctx);
        }
        // SAFETY: the NULL argument is the other arm of the same test.
        let null_ctx_count = unsafe { OSSL_ENCODER_CTX_get_num_encoders(ptr::null_mut()) };
        assert_eq!(null_ctx_count, 0);
    }

    /// A zero selection is refused with a diagnosis rather than accepted as "encode nothing", and
    /// a NULL output structure is refused while a real one is stored.
    #[test]
    fn the_setters_keep_the_authoritys_refusals() {
        // SAFETY: no preconditions.
        let ctx = unsafe { crate::encoder_meth::OSSL_ENCODER_CTX_new() };
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(OSSL_ENCODER_CTX_set_selection(ctx, 0), 0);
            assert_eq!(OSSL_ENCODER_CTX_set_selection(ctx, 1), 1);
            assert_eq!(OSSL_ENCODER_CTX_set_output_type(ctx, c"TEXT".as_ptr()), 1);
            assert_eq!(OSSL_ENCODER_CTX_set_output_structure(ctx, ptr::null()), 0);
            assert_eq!(OSSL_ENCODER_CTX_set_output_structure(ctx, c"x".as_ptr()), 1);
            assert_eq!(OSSL_ENCODER_CTX_set_construct(ctx, None), 1);
            assert_eq!(OSSL_ENCODER_CTX_set_cleanup(ctx, None), 1);
            assert_eq!(
                OSSL_ENCODER_CTX_add_extra(ctx, ptr::null_mut(), ptr::null()),
                1
            );
            crate::encoder_meth::OSSL_ENCODER_CTX_free(ctx);
        }
    }

    /// `to_bio` on an encoder-less context is the refusal whose message names the missing
    /// providers; `print_pkey` never sees it because it tests the count first.
    #[test]
    fn to_bio_without_encoders_refuses() {
        // SAFETY: no preconditions.
        let ctx = unsafe { crate::encoder_meth::OSSL_ENCODER_CTX_new() };
        // SAFETY: `BIO_s_mem` takes no arguments.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null());
        // SAFETY: both are live.
        unsafe {
            assert_eq!(OSSL_ENCODER_to_bio(ctx, bio), 0);
            BIO_free(bio);
            crate::encoder_meth::OSSL_ENCODER_CTX_free(ctx);
        }
    }
}
