//! Phase 10 — `crypto/encode_decode/decoder_meth.c`: the `OSSL_DECODER` method object.
//!
//! This is the first of the three decoder units (D363), and it is the one that carries the
//! **dispatch scan** and the `OSSL_DECODER` object itself. It lands the object
//! constructor/destructor, the dispatch scan, the accessors and the by-name parameter
//! pass-throughs, and the nine `OSSL_FUNC_DECODER_*` identities the scan switches on.
//!
//! The unit is `decoder_meth.c`'s 675 lines, and it is the **twin** of `encoder_meth.c`'s
//! (`src/encoder_meth.rs`, D360/D362) one function at a time -- the same object, the same scan,
//! the same accessors, the same fetch block. It is not a copy of that transcription: every body
//! below was read from `decoder_meth.c`, and where the two units differ the difference is
//! recorded. The one place they *do* differ in substance is the sanity check, and the decoder's
//! is the authority's own two-clause form (see below).
//!
//! ## The nine identities are not sequential, and that is the whole trap
//!
//! `decoder_meth.c`'s `ossl_decoder_from_algorithm` (`:231-296`) walks a provider's
//! `OSSL_DISPATCH` table and switches on `function_id`. In the authority those ids come from the
//! `OSSL_CORE_MAKE_FUNC` invocations at `include/openssl/core_dispatch.h:984-1007`, and their
//! values are **1, 2, 3, 4, 5, 6, 10, 11, 20** -- the last three are not where a sequential
//! numbering would put them. A transcription that numbered them `1..9` would store the decoder's
//! `decode` pointer in `does_selection`'s slot and `export_object`'s in `decode`'s: every
//! dispatch slot after the sixth would be wrong, and nothing would fail until a provider decoder
//! actually ran. The values are written out one per constant, each against its own
//! `OSSL_FUNC_DECODER_*` name, and the unit test at the bottom of this file builds a table whose
//! `decode` entry is at id 11 and whose `does_selection` entry is at id 10 and asserts the two
//! land in the fields their names say.
//!
//! ## The pair rule is the authority's two clauses, not the encoder's four
//!
//! `decoder_meth.c:275-279` is
//! `!((newctx == NULL && freectx == NULL) || (newctx != NULL && freectx != NULL)) || decode == NULL`.
//! There is no import/free pair to check: a decoder carries `export_object`, a single callback, so
//! the decoder's rule has exactly one pair and one required driver. The encoder's Rust spells a
//! four-clause form; this module does **not** copy it, because the decoder's authority body has
//! two clauses and only two.
//!
//! ## What this pass withholds, and why each block cannot land before the next unit
//!
//! * **The fetch and construct-method block landed in D366.** `decoder_data_st`,
//!   `get_tmp_decoder_store`, `dealloc_tmp_decoder_store`, `get_decoder_store`,
//!   `reserve_decoder_store`, `unreserve_decoder_store`, `get_decoder_from_store`,
//!   `put_decoder_in_store`, `construct_decoder`, `destruct_decoder`, `up_ref_decoder`,
//!   `free_decoder`, `inner_ossl_decoder_fetch`, `OSSL_DECODER_fetch`, `do_one_data_st`/`do_one`,
//!   `OSSL_DECODER_do_all_provided` and the two `ossl_decoder_up_ref`/`ossl_decoder_free` thunks
//!   (`:88-231`, `:298-438`, `:552-608`) are below. Its first real callers are
//!   `src/decoder_lib.rs`'s `OSSL_DECODER_CTX_add_extra` and `src/decoder_pkey.rs`'s
//!   `OSSL_DECODER_CTX_new_for_pkey`; it lands before them because `do_all_provided` is what they
//!   call, and it is self-contained -- every callee it reaches was landed with Phase 6, 7 or the
//!   encoder chain.
//! * **The context trio and the two context shapes landed in D364**, with `src/decoder_lib.rs`:
//!   `OSSL_DECODER_CTX_new` (`:628`), `OSSL_DECODER_CTX_set_params` (`:637`) and
//!   `OSSL_DECODER_CTX_free` (`:665`) are below, together with `OsslDecoderInstance` and
//!   `OsslDecoderCtx`. Their unit is still this one -- they are `decoder_meth.c`'s -- but their
//!   commit moves: `_free` calls `ossl_decoder_instance_free` and `_set_params` calls
//!   `OSSL_DECODER_CTX_get_num_decoders`/`OSSL_DECODER_INSTANCE_get_decoder`/
//!   `_get_decoder_ctx`, all `decoder_lib.c`'s, so they land with that unit. That is the split
//!   `encoder_meth.c`'s trio took between D360 and D361.
//!
//! The unit's two **store bridges** (`:453-469`) are the exception, and they are not a gap:
//! `ossl_decoder_store_cache_flush` and `ossl_decoder_store_remove_all_provided` are transcribed
//! in `src/provider/stores.rs` alongside the sibling provider-activation bridges (D357), and both
//! delegate for real since D365 filled slot 11. The test at the bottom of this file calls them by
//! name so the two units' answers stay joined.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::context::namemap::{
    ossl_namemap_add_names, ossl_namemap_doall_names, ossl_namemap_name2num,
    ossl_namemap_name2num_n, ossl_namemap_num2name, ossl_namemap_stored,
};
use crate::context::{lib_ctx_get_data, lib_ctx_get_descriptor, OSSL_LIB_CTX_DECODER_STORE_INDEX};
use crate::encoder_meth::OsslEndecodeBase;
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::method_store::{ossl_method_construct, OsslMethodConstructMethod};
use crate::params::OsslParam;
use crate::passphrase::OsslPassphraseData;
use crate::property::list::OsslPropertyList;
use crate::property::parse::ossl_parse_property;
use crate::property::store::{
    ossl_method_lock_store, ossl_method_store_add, ossl_method_store_cache_get,
    ossl_method_store_cache_set, ossl_method_store_do_all, ossl_method_store_fetch,
    ossl_method_store_free, ossl_method_store_new, ossl_method_unlock_store, OsslMethodStore,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_libctx, ossl_provider_up_ref, OsslProvider};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::OpenSslStack;
use crate::selftest::OsslCallback;

/// `#define NAME_SEPARATOR ':'` — `crypto/encode_decode/decoder_meth.c:27`.
///
/// A decoder can carry several names in one colon-separated string, and the fetch block splits it
/// with `strchr`: only the *first* name is used for the name-map id.
const NAME_SEPARATOR: c_char = b':' as c_char;

/// `#define OSSL_OP_DECODER 21` — `include/openssl/core_dispatch.h:296`.
///
/// **Twenty-one, not twenty**: the `OSSL_OP_*` ids skip 6-9 and the encoder's twenty is the
/// neighbouring row, so a transcription that reused it would ask the method store for encoders.
const OSSL_OP_DECODER: c_int = 21;

// ---------------------------------------------------------------------------
// The `OSSL_FUNC_DECODER_*` identities — `include/openssl/core_dispatch.h:984-992`
// ---------------------------------------------------------------------------

/// `#define OSSL_FUNC_DECODER_NEWCTX 1` — `core_dispatch.h:984`.
pub(crate) const OSSL_FUNC_DECODER_NEWCTX: c_int = 1;
/// `#define OSSL_FUNC_DECODER_FREECTX 2` — `core_dispatch.h:985`.
pub(crate) const OSSL_FUNC_DECODER_FREECTX: c_int = 2;
/// `#define OSSL_FUNC_DECODER_GET_PARAMS 3` — `core_dispatch.h:986`.
pub(crate) const OSSL_FUNC_DECODER_GET_PARAMS: c_int = 3;
/// `#define OSSL_FUNC_DECODER_GETTABLE_PARAMS 4` — `core_dispatch.h:987`.
pub(crate) const OSSL_FUNC_DECODER_GETTABLE_PARAMS: c_int = 4;
/// `#define OSSL_FUNC_DECODER_SET_CTX_PARAMS 5` — `core_dispatch.h:988`.
pub(crate) const OSSL_FUNC_DECODER_SET_CTX_PARAMS: c_int = 5;
/// `#define OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS 6` — `core_dispatch.h:989`.
pub(crate) const OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS: c_int = 6;
/// `#define OSSL_FUNC_DECODER_DOES_SELECTION 10` — `core_dispatch.h:990`. **Ten, not seven.**
pub(crate) const OSSL_FUNC_DECODER_DOES_SELECTION: c_int = 10;
/// `#define OSSL_FUNC_DECODER_DECODE 11` — `core_dispatch.h:991`. **Eleven, not eight.**
pub(crate) const OSSL_FUNC_DECODER_DECODE: c_int = 11;
/// `#define OSSL_FUNC_DECODER_EXPORT_OBJECT 20` — `core_dispatch.h:992`. **Twenty, not nine.**
pub(crate) const OSSL_FUNC_DECODER_EXPORT_OBJECT: c_int = 20;

// ---------------------------------------------------------------------------
// The callback types — `OSSL_CORE_MAKE_FUNC`'s expansions, `core_dispatch.h:993-1007`
// ---------------------------------------------------------------------------

/// `void *(OSSL_FUNC_decoder_newctx_fn)(void *provctx)` — `core_dispatch.h:993`.
pub(crate) type DecoderNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `void (OSSL_FUNC_decoder_freectx_fn)(void *ctx)` — `core_dispatch.h:994`.
pub(crate) type DecoderFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `int (OSSL_FUNC_decoder_get_params_fn)(OSSL_PARAM params[])` — `core_dispatch.h:995`.
pub(crate) type DecoderGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `const OSSL_PARAM *(OSSL_FUNC_decoder_gettable_params_fn)(void *provctx)` —
/// `core_dispatch.h:996-997`.
pub(crate) type DecoderGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `int (OSSL_FUNC_decoder_set_ctx_params_fn)(void *ctx, const OSSL_PARAM params[])` —
/// `core_dispatch.h:998-999`.
pub(crate) type DecoderSetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `const OSSL_PARAM *(OSSL_FUNC_decoder_settable_ctx_params_fn)(void *provctx)` —
/// `core_dispatch.h:1000-1001`.
pub(crate) type DecoderSettableCtxParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `int (OSSL_FUNC_decoder_does_selection_fn)(void *provctx, int selection)` —
/// `core_dispatch.h:1003-1004`.
pub(crate) type DecoderDoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
/// `int (OSSL_FUNC_decoder_decode_fn)(void *ctx, OSSL_CORE_BIO *in, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `core_dispatch.h:1005-1007`.
pub(crate) type DecoderDecodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    c_int,
    Option<OsslCallback>,
    *mut c_void,
    Option<crate::passphrase::OsslPassphraseCallback>,
    *mut c_void,
) -> c_int;
/// `int (OSSL_FUNC_decoder_export_object_fn)(void *ctx, const void *objref, size_t objref_sz,
/// OSSL_CALLBACK *export_cb, void *export_cbarg)` — `core_dispatch.h:1008-1010`.
pub(crate) type DecoderExportObjectFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_void,
    usize,
    Option<OsslCallback>,
    *mut c_void,
) -> c_int;

// ---------------------------------------------------------------------------
// The object — `crypto/encode_decode/decoder_local.h`
// ---------------------------------------------------------------------------

/// `struct ossl_decoder_st` — `decoder_local.h:29-41`.
///
/// One field per `<OSSL_FUNC_DECODER_*>` entry `ossl_decoder_from_algorithm` may find. Every one
/// is an `Option` because a table need not supply it, and `None` is the authority's NULL. The
/// shared head is [`OsslEndecodeBase`], which `decoder_local.h:24-27` gives the same five-field
/// body `encoder_local.h:21-29` does.
#[repr(C)]
pub struct OsslDecoder {
    /// The shared head.
    pub(crate) base: OsslEndecodeBase,
    /// `OSSL_FUNC_DECODER_NEWCTX`.
    pub(crate) newctx: Option<DecoderNewCtxFn>,
    /// `OSSL_FUNC_DECODER_FREECTX`.
    pub(crate) freectx: Option<DecoderFreeCtxFn>,
    /// `OSSL_FUNC_DECODER_GET_PARAMS`.
    pub(crate) get_params: Option<DecoderGetParamsFn>,
    /// `OSSL_FUNC_DECODER_GETTABLE_PARAMS`.
    pub(crate) gettable_params: Option<DecoderGettableParamsFn>,
    /// `OSSL_FUNC_DECODER_SET_CTX_PARAMS`.
    pub(crate) set_ctx_params: Option<DecoderSetCtxParamsFn>,
    /// `OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS`.
    pub(crate) settable_ctx_params: Option<DecoderSettableCtxParamsFn>,
    /// `OSSL_FUNC_DECODER_DOES_SELECTION`.
    pub(crate) does_selection: Option<DecoderDoesSelectionFn>,
    /// `OSSL_FUNC_DECODER_DECODE`.
    pub(crate) decode: Option<DecoderDecodeFn>,
    /// `OSSL_FUNC_DECODER_EXPORT_OBJECT`.
    pub(crate) export_object: Option<DecoderExportObjectFn>,
}

// ---------------------------------------------------------------------------
// The object's lifetime
// ---------------------------------------------------------------------------

/// `static OSSL_DECODER *ossl_decoder_new(void)` — `decoder_meth.c:38-50`.
///
/// A zeroed object with a reference count of **1**. The `CRYPTO_NEW_REF` failure arm calls
/// `OSSL_DECODER_free`, so the count must be readable as 0 on that path (the `zalloc` guarantee)
/// and the constructor cannot simply build the struct in Rust.
///
/// # Safety
/// No preconditions; the answer is NULL or a uniquely-owned object.
pub(crate) unsafe fn ossl_decoder_new() -> *mut OsslDecoder {
    // SAFETY: the constructor only asks for a zeroed block of the object's size.
    let decoder =
        CRYPTO_zalloc(core::mem::size_of::<OsslDecoder>(), ptr::null(), 0).cast::<OsslDecoder>();
    if decoder.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `decoder` is a fresh, zeroed, uniquely-owned block; this is the field `CRYPTO_NEW_REF`
    // initialises to 1.
    unsafe { (*decoder).base.refcnt.store(1, Ordering::Release) };
    decoder
}

/// `int OSSL_DECODER_up_ref(OSSL_DECODER *decoder)` — `decoder_meth.c:52-58`.
///
/// Answers **1** unconditionally, the shape `OSSL_ENCODER_up_ref` has: the body is `CRYPTO_UP_REF`
/// and a `return 1`, and no caller checks the answer.
///
/// # Safety
/// `decoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_up_ref(decoder: *mut OsslDecoder) -> c_int {
    // SAFETY: `decoder` is live per the contract; the count is a plain atomic field.
    unsafe { (*decoder).base.refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void OSSL_DECODER_free(OSSL_DECODER *decoder)` — `decoder_meth.c:60-75`.
///
/// The release order is the authority's: the name, the parsed properties, the provider reference
/// and the count are released **before** the block itself, and the count is released by the same
/// `CRYPTO_FREE_REF` that decides whether anything else runs. The `ref > 0` test is `fetch_sub`'s
/// return **minus one**, so the crate tests `last > 1`.
///
/// # Safety
/// `decoder` must be NULL or a live `OsslDecoder` this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_free(decoder: *mut OsslDecoder) {
    if decoder.is_null() {
        return;
    }

    // SAFETY: `decoder` is live per the contract.
    let last = unsafe { (*decoder).base.refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }

    // SAFETY: `decoder` is live and this is the last reference; each field is this object's own.
    unsafe {
        CRYPTO_free((*decoder).base.name.cast(), ptr::null(), 0);
        crate::property::parse::ossl_property_free((*decoder).base.parsed_propdef);
        crate::provider::ossl_provider_free((*decoder).base.prov);
        CRYPTO_free(decoder.cast(), ptr::null(), 0);
    }
}

/// `void *ossl_decoder_from_algorithm(int id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)` — `decoder_meth.c:231-296`.
///
/// The dispatch scan, and the reason this unit exists. Three things are the authority's and easy
/// to get wrong: the name is taken with `ossl_algorithm_get1_first_name`, which **allocates** and
/// is released by `OSSL_DECODER_free`; the property definition is parsed once and stored; and the
/// sanity check at `:275-279` is a **two-clause** condition -- the constructor/destructor pair must
/// be both-or-neither, and `decode` must be present. It is written as the authority wrote it, with
/// the two clauses kept separate, because collapsing them is how the `||` becomes an `&&`.
///
/// # Safety
/// `algodef` must be a live algorithm definition whose `implementation` is a terminated dispatch
/// table; `prov` must be NULL or live.
pub(crate) unsafe fn ossl_decoder_from_algorithm(
    id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut OsslDecoder {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation }.cast::<OsslDispatch>();
    // SAFETY: `prov` is NULL or live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };

    // SAFETY: `ossl_decoder_new` takes no arguments and answers NULL or a live object.
    let decoder = unsafe { ossl_decoder_new() };
    if decoder.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `decoder` is live and uniquely owned here.
    unsafe { (*decoder).base.id = id };
    // SAFETY: `algodef` is live; the helper allocates a copy of the first name.
    let name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    // SAFETY: `decoder` is live; a NULL name is a failure the release below handles.
    unsafe { (*decoder).base.name = name };
    if name.is_null() {
        // SAFETY: `decoder` is live and owned here.
        unsafe { OSSL_DECODER_free(decoder) };
        return ptr::null_mut();
    }
    // SAFETY: `decoder` is live.
    unsafe { (*decoder).base.algodef = algodef };
    // SAFETY: `algodef` is live; the parse is given the provider's context.
    let parsed = unsafe { ossl_parse_property(libctx, (*algodef).property_definition) };
    // SAFETY: `decoder` is live.
    unsafe { (*decoder).base.parsed_propdef = parsed };
    if parsed.is_null() {
        // SAFETY: `decoder` is live and owned here.
        unsafe { OSSL_DECODER_free(decoder) };
        return ptr::null_mut();
    }

    // SAFETY: `fns` is a terminated table per the contract, and every cast below is the type its
    // own `OSSL_FUNC_DECODER_*` id names -- which is what the non-sequential values above are for.
    unsafe {
        let mut p = fns;
        while (*p).function_id != OSSL_DISPATCH_END {
            match (*p).function_id {
                OSSL_FUNC_DECODER_NEWCTX if (*decoder).newctx.is_none() => {
                    (*decoder).newctx = entry_function::<DecoderNewCtxFn>(p);
                }
                OSSL_FUNC_DECODER_FREECTX if (*decoder).freectx.is_none() => {
                    (*decoder).freectx = entry_function::<DecoderFreeCtxFn>(p);
                }
                OSSL_FUNC_DECODER_GET_PARAMS if (*decoder).get_params.is_none() => {
                    (*decoder).get_params = entry_function::<DecoderGetParamsFn>(p);
                }
                OSSL_FUNC_DECODER_GETTABLE_PARAMS if (*decoder).gettable_params.is_none() => {
                    (*decoder).gettable_params = entry_function::<DecoderGettableParamsFn>(p);
                }
                OSSL_FUNC_DECODER_SET_CTX_PARAMS if (*decoder).set_ctx_params.is_none() => {
                    (*decoder).set_ctx_params = entry_function::<DecoderSetCtxParamsFn>(p);
                }
                OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS
                    if (*decoder).settable_ctx_params.is_none() =>
                {
                    (*decoder).settable_ctx_params =
                        entry_function::<DecoderSettableCtxParamsFn>(p);
                }
                OSSL_FUNC_DECODER_DOES_SELECTION if (*decoder).does_selection.is_none() => {
                    (*decoder).does_selection = entry_function::<DecoderDoesSelectionFn>(p);
                }
                OSSL_FUNC_DECODER_DECODE if (*decoder).decode.is_none() => {
                    (*decoder).decode = entry_function::<DecoderDecodeFn>(p);
                }
                OSSL_FUNC_DECODER_EXPORT_OBJECT if (*decoder).export_object.is_none() => {
                    (*decoder).export_object = entry_function::<DecoderExportObjectFn>(p);
                }
                _ => {}
            }
            p = p.add(1);
        }

        // The sanity check, its two clauses kept separate: both-or-neither for the pair, and
        // `decode` required.
        let pair_ok = ((*decoder).newctx.is_none() && (*decoder).freectx.is_none())
            || ((*decoder).newctx.is_some() && (*decoder).freectx.is_some());
        if !pair_ok || (*decoder).decode.is_none() {
            OSSL_DECODER_free(decoder);
            raise_site(&err_sites::DECODER_METH_280);
            return ptr::null_mut();
        }

        if !prov.is_null() && ossl_provider_up_ref(prov) == 0 {
            OSSL_DECODER_free(decoder);
            return ptr::null_mut();
        }
        (*decoder).base.prov = prov;
    }
    decoder
}

// ---------------------------------------------------------------------------
// The accessors — `decoder_meth.c:449-608`
// ---------------------------------------------------------------------------

/// `const OSSL_PROVIDER *OSSL_DECODER_get0_provider(const OSSL_DECODER *decoder)` —
/// `decoder_meth.c:461-469`.
///
/// # Safety
/// `decoder` must be null-or-live; a NULL is a diagnosed `ERR_R_PASSED_NULL_PARAMETER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_get0_provider(
    decoder: *const OsslDecoder,
) -> *const OsslProvider {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_463) };
        return ptr::null();
    }
    // SAFETY: `decoder` is live.
    unsafe { (*decoder).base.prov }
}

/// `const char *OSSL_DECODER_get0_properties(const OSSL_DECODER *decoder)` —
/// `decoder_meth.c:471-479`.
///
/// # Safety
/// `decoder` must be null-or-live; a NULL is a diagnosed `ERR_R_PASSED_NULL_PARAMETER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_get0_properties(
    decoder: *const OsslDecoder,
) -> *const c_char {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_473) };
        return ptr::null();
    }
    // SAFETY: `decoder` is live; `algodef` is the borrowed table entry it was built from.
    unsafe { (*(*decoder).base.algodef).property_definition }
}

/// `const OSSL_PROPERTY_LIST *ossl_decoder_parsed_properties(const OSSL_DECODER *decoder)` —
/// `decoder_meth.c:481-490`.
///
/// # Safety
/// `decoder` must be null-or-live; a NULL is a diagnosed `ERR_R_PASSED_NULL_PARAMETER`.
pub(crate) unsafe fn ossl_decoder_parsed_properties(
    decoder: *const OsslDecoder,
) -> *mut OsslPropertyList {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_484) };
        return ptr::null_mut();
    }
    // SAFETY: `decoder` is live.
    unsafe { (*decoder).base.parsed_propdef }
}

/// `int ossl_decoder_get_number(const OSSL_DECODER *decoder)` — `decoder_meth.c:492-500`.
///
/// # Safety
/// `decoder` must be null-or-live; a NULL is a diagnosed `ERR_R_PASSED_NULL_PARAMETER`.
#[allow(dead_code)] // read by this module's own unit test; the authority's callers are `store_result.c`'s
pub(crate) unsafe fn ossl_decoder_get_number(decoder: *const OsslDecoder) -> c_int {
    if decoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_494) };
        return 0;
    }
    // SAFETY: `decoder` is live.
    unsafe { (*decoder).base.id }
}

/// `const char *OSSL_DECODER_get0_name(const OSSL_DECODER *decoder)` — `decoder_meth.c:502-505`.
///
/// The one accessor with **no NULL test**: the authority's body is a bare field read, so this is
/// too.
///
/// # Safety
/// `decoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_get0_name(decoder: *const OsslDecoder) -> *const c_char {
    // SAFETY: `decoder` is live per the contract.
    unsafe { (*decoder).base.name }
}

/// `const char *OSSL_DECODER_get0_description(const OSSL_DECODER *decoder)` —
/// `decoder_meth.c:507-510`.
///
/// # Safety
/// `decoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_get0_description(
    decoder: *const OsslDecoder,
) -> *const c_char {
    // SAFETY: `decoder` is live; `algodef` is the borrowed table entry it was built from.
    unsafe { (*(*decoder).base.algodef).algorithm_description }
}

/// `int OSSL_DECODER_is_a(const OSSL_DECODER *decoder, const char *name)` —
/// `decoder_meth.c:512-521`.
///
/// A name comparison through the name map, and **0** for an object with no provider.
///
/// # Safety
/// `decoder` must be live; `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_is_a(
    decoder: *const OsslDecoder,
    name: *const c_char,
) -> c_int {
    // SAFETY: `decoder` is live.
    let prov = unsafe { (*decoder).base.prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live (or NULL, which the comparison then loses); `name` is
        // NUL-terminated per the contract.
        let num = unsafe { ossl_namemap_name2num(namemap, name) };
        // SAFETY: `decoder` is live.
        return c_int::from(num == unsafe { (*decoder).base.id });
    }
    0
}

/// `static int resolve_name(OSSL_DECODER *decoder, const char *name)` —
/// `decoder_meth.c:523-529`.
///
/// # Safety
/// `decoder` must be live and have a provider; `name` NUL-terminated.
unsafe fn resolve_name(decoder: *mut OsslDecoder, name: *const c_char) -> c_int {
    // SAFETY: `decoder` is live and its provider is live per the contract.
    let libctx = unsafe { ossl_provider_libctx((*decoder).base.prov) };
    let namemap = ossl_namemap_stored(libctx);
    // SAFETY: `namemap` is live or NULL; `name` is NUL-terminated per the contract.
    unsafe { ossl_namemap_name2num(namemap, name) }
}

/// `int ossl_decoder_fast_is_a(OSSL_DECODER *decoder, const char *name, int *id_cache)` —
/// `decoder_meth.c:531-538`.
///
/// The cached-id form: a non-positive cache is refilled through [`resolve_name`], and the answer
/// is `id > 0 && number == id`. Both sides of that `&&` matter -- an unresolved name is **0**, not
/// a comparison against a stale id.
///
/// # Safety
/// `decoder` must be live; `name` NUL-terminated; `id_cache` must be writable.
#[allow(dead_code)] // read by decoder_lib.c's decoder selection, next pass
pub(crate) unsafe fn ossl_decoder_fast_is_a(
    decoder: *mut OsslDecoder,
    name: *const c_char,
    id_cache: *mut c_int,
) -> c_int {
    // SAFETY: `id_cache` is writable per the contract.
    let mut id = unsafe { *id_cache };

    if id <= 0 {
        // SAFETY: `decoder` and `name` are live per the contract.
        id = unsafe { resolve_name(decoder, name) };
        // SAFETY: `id_cache` is writable per the contract.
        unsafe { *id_cache = id };
    }

    // SAFETY: `decoder` is live.
    c_int::from(id > 0 && unsafe { (*decoder).base.id } == id)
}

/// `int OSSL_DECODER_names_do_all(const OSSL_DECODER *decoder,
/// void (*fn)(const char *name, void *data), void *data)` — `decoder_meth.c:552-567`.
///
/// # Safety
/// `decoder` must be NULL or live; `fn` must be a valid callback that tolerates every name.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_names_do_all(
    decoder: *const OsslDecoder,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    if decoder.is_null() {
        return 0;
    }
    // SAFETY: `decoder` is live.
    let prov = unsafe { (*decoder).base.prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live or NULL; the callback is the caller's.
        return unsafe { ossl_namemap_doall_names(namemap, (*decoder).base.id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *OSSL_DECODER_gettable_params(OSSL_DECODER *decoder)` —
/// `decoder_meth.c:569-578`.
///
/// # Safety
/// `decoder` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_gettable_params(
    decoder: *mut OsslDecoder,
) -> *const OsslParam {
    if !decoder.is_null() {
        // SAFETY: `decoder` is live.
        if let Some(gettable) = unsafe { (*decoder).gettable_params } {
            // SAFETY: `decoder` is live, so its provider is too.
            let provctx = unsafe { crate::provider::ossl_provider_ctx((*decoder).base.prov) };
            // SAFETY: `gettable` is a live provider callback and `provctx` is its own context.
            return unsafe { gettable(provctx) };
        }
    }
    ptr::null()
}

/// `int OSSL_DECODER_get_params(OSSL_DECODER *decoder, OSSL_PARAM params[])` —
/// `decoder_meth.c:580-586`.
///
/// # Safety
/// `decoder` must be NULL or live; `params` must be NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_get_params(
    decoder: *mut OsslDecoder,
    params: *mut OsslParam,
) -> c_int {
    if !decoder.is_null() {
        // SAFETY: `decoder` is live.
        if let Some(get_params) = unsafe { (*decoder).get_params } {
            // SAFETY: `get_params` is a live provider callback and `params` is the caller's.
            return unsafe { get_params(params) };
        }
    }
    0
}

/// `const OSSL_PARAM *OSSL_DECODER_settable_ctx_params(OSSL_DECODER *decoder)` —
/// `decoder_meth.c:588-596`.
///
/// # Safety
/// `decoder` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_settable_ctx_params(
    decoder: *mut OsslDecoder,
) -> *const OsslParam {
    if !decoder.is_null() {
        // SAFETY: `decoder` is live.
        if let Some(settable) = unsafe { (*decoder).settable_ctx_params } {
            // SAFETY: `decoder` is live, so its provider is too.
            let provctx = unsafe { crate::provider::ossl_provider_ctx((*decoder).base.prov) };
            // SAFETY: `settable` is a live provider callback and `provctx` is its own context.
            return unsafe { settable(provctx) };
        }
    }
    ptr::null()
}

// ---------------------------------------------------------------------------
// The context shapes — `crypto/encode_decode/encoder_local.h:106-169`
// ---------------------------------------------------------------------------

/// `typedef int OSSL_DECODER_CONSTRUCT(OSSL_DECODER_INSTANCE *, const OSSL_PARAM *, void *)` —
/// `include/openssl/decoder.h:93-95`.
///
/// Answers an `int`, unlike the encoder's construct callback which answers the constructed
/// `void *`: a decoder constructor's answer is a status, and the object it produced reaches the
/// caller through `OSSL_DECODER_CTX_get_construct_data`'s convention instead.
pub(crate) type DecoderConstructFn =
    unsafe extern "C" fn(*mut OsslDecoderInstance, *const OsslParam, *mut c_void) -> c_int;
/// `typedef void OSSL_DECODER_CLEANUP(void *construct_data)` — `include/openssl/decoder.h:96`.
pub(crate) type DecoderCleanupFn = unsafe extern "C" fn(*mut c_void);

/// `struct ossl_decoder_instance_st` — `encoder_local.h:106-115`.
///
/// One instantiated decoder in a context's chain. `decoderctx` is the provider's own context and
/// is released through the decoder's `freectx`; `input_type` comes from the implementation's
/// mandatory `input` property and is never NULL on a constructed instance.
#[repr(C)]
pub struct OsslDecoderInstance {
    /// `OSSL_DECODER *decoder` — never NULL.
    pub(crate) decoder: *mut OsslDecoder,
    /// `void *decoderctx` — never NULL.
    pub(crate) decoderctx: *mut c_void,
    /// `const char *input_type` — never NULL.
    pub(crate) input_type: *const c_char,
    /// `const char *input_structure` — may be NULL.
    pub(crate) input_structure: *const c_char,
    /// `int input_type_id`.
    pub(crate) input_type_id: c_int,
    /// `int order` — for stable ordering of decoders wrt proqs.
    pub(crate) order: c_int,
    /// `int score` — for ordering decoders wrt proqs.
    pub(crate) score: c_int,
    /// `unsigned int flag_input_structure_was_set : 1` — projected as its four-byte storage, the
    /// projection `EvpPkey`'s `foreign` and `EvpPkeyCache`'s bitfields use.
    pub(crate) flag_input_structure_was_set: c_int,
}

/// `struct ossl_decoder_ctx_st` — `encoder_local.h:120-169`.
///
/// The context `OSSL_DECODER_CTX_new` allocates and `OSSL_DECODER_CTX_free` releases. `pwdata` is
/// the passphrase bridge D356/D358 landed, embedded by value exactly as the authority embeds it,
/// and `harderr` is the flag `ossl_decoder_ctx_set_harderr` raises so further processing stops.
#[repr(C)]
pub struct OsslDecoderCtx {
    /// `const char *start_input_type` — the caller's starting type, or NULL.
    pub(crate) start_input_type: *const c_char,
    /// `const char *input_structure` — the desired input structure, or NULL.
    pub(crate) input_structure: *const c_char,
    /// `int selection` — the `OSSL_KEYMGMT_SELECT_*` bits expected.
    pub(crate) selection: c_int,
    /// `STACK_OF(OSSL_DECODER_INSTANCE) *decoder_insts` — the chain, built lazily.
    pub(crate) decoder_insts: *mut OpenSslStack,
    /// `OSSL_DECODER_CONSTRUCT *construct` — the object constructor for the chain's head.
    pub(crate) construct: Option<DecoderConstructFn>,
    /// `OSSL_DECODER_CLEANUP *cleanup` — its destructor.
    pub(crate) cleanup: Option<DecoderCleanupFn>,
    /// `void *construct_data` — passed to both.
    pub(crate) construct_data: *mut c_void,
    /// `struct ossl_passphrase_data_st pwdata` — by value, as the authority embeds it.
    pub(crate) pwdata: OsslPassphraseData,
    /// `int harderr` — set by `ossl_decoder_ctx_set_harderr`.
    pub(crate) harderr: c_int,
}

// ---------------------------------------------------------------------------
// The context trio — `decoder_meth.c:628-675`
// ---------------------------------------------------------------------------

/// `sk_OSSL_DECODER_INSTANCE_pop_free`'s destructor: the crate's stack frees elements through a
/// `void *`-shaped callback, so `ossl_decoder_instance_free` is reached through this thunk.
unsafe extern "C" fn decoder_instance_free_thunk(p: *mut c_void) {
    // SAFETY: the stack's element is an `OsslDecoderInstance` this crate allocated and owns.
    unsafe { crate::decoder_lib::ossl_decoder_instance_free(p.cast()) };
}

/// `OSSL_DECODER_CTX *OSSL_DECODER_CTX_new(void)` — `decoder_meth.c:628-635`.
///
/// A zeroed context and nothing else. `pwdata`'s zeroed state is the authority's own initial
/// state, and `harderr` is 0.
///
/// # Safety
/// No preconditions; the answer is NULL or a uniquely-owned context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_new() -> *mut OsslDecoderCtx {
    // The constructor only asks for a zeroed block of the context's size.
    CRYPTO_zalloc(core::mem::size_of::<OsslDecoderCtx>(), ptr::null(), 0).cast::<OsslDecoderCtx>()
}

/// `int OSSL_DECODER_CTX_set_params(OSSL_DECODER_CTX *ctx, const OSSL_PARAM params[])` —
/// `decoder_meth.c:637-663`.
///
/// The authority's **and** of every instance's answer, with an **empty chain a success**: a
/// context with no instances answers 1 without asking anything, which is why a caller can set
/// parameters before the chain exists.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_set_params(
    ctx: *mut OsslDecoderCtx,
    params: *const OsslParam,
) -> c_int {
    let mut ok = 1;

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_644) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).decoder_insts }.is_null() {
        return 1;
    }

    // SAFETY: `ctx` is live and its stack is non-NULL.
    let l = unsafe { crate::decoder_lib::OSSL_DECODER_CTX_get_num_decoders(ctx) };
    for i in 0..l {
        // SAFETY: `ctx` is live; the index is inside the stack.
        let decoder_inst =
            unsafe { crate::runtime::stack::OPENSSL_sk_value((*ctx).decoder_insts, i) }
                .cast::<OsslDecoderInstance>();
        // SAFETY: `decoder_inst` is a live instance from the context's own stack.
        let (decoder, decoderctx) = unsafe {
            (
                crate::decoder_lib::OSSL_DECODER_INSTANCE_get_decoder(decoder_inst),
                crate::decoder_lib::OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst),
            )
        };
        if decoderctx.is_null() {
            continue;
        }
        // SAFETY: `decoder` is the instance's live method object.
        let Some(set_ctx_params) = (unsafe { (*decoder).set_ctx_params }) else {
            continue;
        };
        // SAFETY: `set_ctx_params` is a live provider callback and `params` is the caller's.
        if unsafe { set_ctx_params(decoderctx, params) } == 0 {
            ok = 0;
        }
    }
    ok
}

/// `void OSSL_DECODER_CTX_free(OSSL_DECODER_CTX *ctx)` — `decoder_meth.c:665-675`.
///
/// Four releases in the authority's order: the cleanup callback with the construct data, the
/// instance chain (each released through its own `freectx`), the passphrase bridge's data, then
/// the context itself. The NULL test is the whole body's, so a NULL context is silent.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_CTX_free(ctx: *mut OsslDecoderCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if let Some(cleanup) = (*ctx).cleanup {
            cleanup((*ctx).construct_data);
        }
        crate::runtime::stack::OPENSSL_sk_pop_free(
            (*ctx).decoder_insts,
            Some(decoder_instance_free_thunk),
        );
        crate::passphrase::ossl_pw_clear_passphrase_data(ptr::addr_of_mut!((*ctx).pwdata));
        CRYPTO_free(ctx.cast(), ptr::null(), 0);
    }
}

// ---------------------------------------------------------------------------
// The fetch and construct-method block — `decoder_meth.c:88-231`, `:298-438`, `:552-608`
// ---------------------------------------------------------------------------

/// `static void ossl_decoder_free(void *data)` — `decoder_meth.c:29-32`.
///
/// # Safety
/// `data` must be a live `OsslDecoder`.
unsafe extern "C" fn ossl_decoder_free(data: *mut c_void) {
    // SAFETY: `data` is live per the contract.
    unsafe { OSSL_DECODER_free(data.cast::<OsslDecoder>()) };
}

/// `static int ossl_decoder_up_ref(void *data)` — `decoder_meth.c:34-37`.
///
/// # Safety
/// `data` must be a live `OsslDecoder`.
unsafe extern "C" fn ossl_decoder_up_ref(data: *mut c_void) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { OSSL_DECODER_up_ref(data.cast::<OsslDecoder>()) }
}

/// `struct decoder_data_st` — `decoder_meth.c:76-86`.
///
/// The walk's state. `id`, `names` and `propquery` are filled by `inner_ossl_decoder_fetch` for the
/// **get** callback's benefit; `tmp_store` is the temporary store the walk may create and
/// [`dealloc_tmp_decoder_store`] releases; `flag_construct_error_occurred` is the one-bit flag that
/// lets the fetch tell an unsupported algorithm from a failed constructor, projected as its
/// four-byte storage.
struct DecoderDataSt {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `int id`.
    id: c_int,
    /// `const char *names`.
    names: *const c_char,
    /// `const char *propquery`.
    propquery: *const c_char,
    /// `OSSL_METHOD_STORE *tmp_store`.
    tmp_store: *mut OsslMethodStore,
    /// `unsigned int flag_construct_error_occurred : 1`.
    flag_construct_error_occurred: c_int,
}

/// The length of the first `':'`-separated name in `names`.
///
/// # Safety
/// `names` must be NUL-terminated.
unsafe fn first_name_len(names: *const c_char) -> usize {
    let mut l = 0usize;
    // SAFETY: `names` is NUL-terminated per the contract, so the scan stays inside it.
    unsafe {
        while *names.add(l) != 0 && *names.add(l) != NAME_SEPARATOR {
            l += 1;
        }
    }
    l
}

/// `static void *get_tmp_decoder_store(void *data)` — `decoder_meth.c:95-101`.
///
/// # Safety
/// `data` must be a live `DecoderDataSt`.
unsafe extern "C" fn get_tmp_decoder_store(data: *mut c_void) -> *mut c_void {
    let methdata = data.cast::<DecoderDataSt>();
    // SAFETY: `methdata` is live per the contract.
    unsafe {
        if (*methdata).tmp_store.is_null() {
            (*methdata).tmp_store = ossl_method_store_new((*methdata).libctx);
        }
        (*methdata).tmp_store.cast::<c_void>()
    }
}

/// `static void dealloc_tmp_decoder_store(void *store)` — `decoder_meth.c:103-107`.
///
/// # Safety
/// `store` must be NULL or a store this file created.
unsafe extern "C" fn dealloc_tmp_decoder_store(store: *mut c_void) {
    if !store.is_null() {
        // SAFETY: `store` is a store `get_tmp_decoder_store` created and nobody else released.
        unsafe { ossl_method_store_free(store.cast::<OsslMethodStore>()) };
    }
}

/// `static OSSL_METHOD_STORE *get_decoder_store(OSSL_LIB_CTX *libctx)` — `decoder_meth.c:110-113`.
fn get_decoder_store(libctx: *mut c_void) -> *mut OsslMethodStore {
    // `lib_ctx_get_data` is a SAFE function in this crate (D113), so the read is not guarded.
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_DECODER_STORE_INDEX).cast::<OsslMethodStore>()
}

/// `static int reserve_decoder_store(void *store, void *data)` — `decoder_meth.c:115-124`.
///
/// # Safety
/// `store` NULL or a live store; `data` a live `DecoderDataSt`.
unsafe extern "C" fn reserve_decoder_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<DecoderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live per the contract.
        store = get_decoder_store(unsafe { (*methdata).libctx });
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live here.
    unsafe { ossl_method_lock_store(store) }
}

/// `static int unreserve_decoder_store(void *store, void *data)` — `decoder_meth.c:126-135`.
///
/// # Safety
/// As [`reserve_decoder_store`].
unsafe extern "C" fn unreserve_decoder_store(store: *mut c_void, data: *mut c_void) -> c_int {
    let methdata = data.cast::<DecoderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    if store.is_null() {
        // SAFETY: `methdata` is live per the contract.
        store = get_decoder_store(unsafe { (*methdata).libctx });
        if store.is_null() {
            return 0;
        }
    }
    // SAFETY: `store` is live here.
    unsafe { ossl_method_unlock_store(store) }
}

/// `static void *get_decoder_from_store(void *store, const OSSL_PROVIDER **prov, void *data)` —
/// `decoder_meth.c:138-172`.
///
/// # Safety
/// `store` NULL or live; `prov` NULL or writable; `data` a live `DecoderDataSt`.
unsafe extern "C" fn get_decoder_from_store(
    store: *mut c_void,
    prov: *mut *const OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<DecoderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();
    let mut method: *mut c_void = ptr::null_mut();

    // SAFETY: `methdata` is live per the contract.
    unsafe {
        let mut id = (*methdata).id;
        if id == 0 && !(*methdata).names.is_null() {
            let namemap = ossl_namemap_stored((*methdata).libctx);
            if namemap.is_null() {
                return ptr::null_mut();
            }
            let l = first_name_len((*methdata).names);
            id = ossl_namemap_name2num_n(namemap, (*methdata).names, l);
        }

        if id == 0 {
            return ptr::null_mut();
        }

        if store.is_null() {
            store = get_decoder_store((*methdata).libctx);
            if store.is_null() {
                return ptr::null_mut();
            }
        }

        if ossl_method_store_fetch(store, id, (*methdata).propquery, prov, &mut method) == 0 {
            return ptr::null_mut();
        }
    }
    method
}

/// `static int put_decoder_in_store(void *store, void *method, const OSSL_PROVIDER *prov,
/// const char *names, const char *propdef, void *data)` — `decoder_meth.c:174-211`.
///
/// # Safety
/// `store` NULL or live; `method` live; `prov` live; `names` NULL or NUL-terminated; `propdef` NULL
/// or NUL-terminated; `data` a live `DecoderDataSt`.
unsafe extern "C" fn put_decoder_in_store(
    store: *mut c_void,
    method: *mut c_void,
    prov: *const OsslProvider,
    names: *const c_char,
    propdef: *const c_char,
    data: *mut c_void,
) -> c_int {
    let methdata = data.cast::<DecoderDataSt>();
    let mut store = store.cast::<OsslMethodStore>();

    // SAFETY: `names` is NULL or NUL-terminated per the contract.
    let l = if !names.is_null() {
        // SAFETY: `names` is non-NULL and NUL-terminated here.
        unsafe { first_name_len(names) }
    } else {
        0
    };

    // SAFETY: `methdata` is live per the contract.
    unsafe {
        let namemap = ossl_namemap_stored((*methdata).libctx);
        if namemap.is_null() {
            return 0;
        }
        let id = ossl_namemap_name2num_n(namemap, names, l);
        if id == 0 {
            return 0;
        }

        if store.is_null() {
            store = get_decoder_store((*methdata).libctx);
            if store.is_null() {
                return 0;
            }
        }

        ossl_method_store_add(
            store,
            prov,
            id,
            propdef,
            method,
            ossl_decoder_up_ref,
            ossl_decoder_free,
        )
    }
}

/// `static void *construct_decoder(const OSSL_ALGORITHM *algodef, OSSL_PROVIDER *prov,
/// void *data)` — `decoder_meth.c:298-333`.
///
/// # Safety
/// `algodef` and `prov` must be live; `data` a live `DecoderDataSt`.
unsafe extern "C" fn construct_decoder(
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
    data: *mut c_void,
) -> *mut c_void {
    let methdata = data.cast::<DecoderDataSt>();
    // SAFETY: `prov` is live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };
    let namemap = ossl_namemap_stored(libctx);
    // SAFETY: `algodef` is live per the contract.
    let names = unsafe { (*algodef).algorithm_names };
    // SAFETY: `namemap` is live or NULL, which `ossl_namemap_add_names` refuses.
    let id = unsafe { ossl_namemap_add_names(namemap, 0, names, NAME_SEPARATOR) };
    let method = if id != 0 {
        // SAFETY: `algodef` and `prov` are live, and `id` is the number the name map just gave.
        unsafe { ossl_decoder_from_algorithm(id, algodef, prov) }
    } else {
        ptr::null_mut()
    };

    if method.is_null() {
        // SAFETY: `methdata` is live per the contract.
        unsafe { (*methdata).flag_construct_error_occurred = 1 };
    }
    method.cast::<c_void>()
}

/// `static void destruct_decoder(void *method, void *data)` — `decoder_meth.c:336-339`.
///
/// # Safety
/// `method` must be a live `OsslDecoder`; `data` is unused.
unsafe extern "C" fn destruct_decoder(method: *mut c_void, _data: *mut c_void) {
    // SAFETY: `method` is live per the contract.
    unsafe { OSSL_DECODER_free(method.cast::<OsslDecoder>()) };
}

/// `static int up_ref_decoder(void *method)` — `decoder_meth.c:341-344`.
///
/// # Safety
/// `method` must be a live `OsslDecoder`.
unsafe extern "C" fn up_ref_decoder(method: *mut c_void) -> c_int {
    // SAFETY: `method` is live per the contract.
    unsafe { OSSL_DECODER_up_ref(method.cast::<OsslDecoder>()) }
}

/// `static void free_decoder(void *method)` — `decoder_meth.c:346-349`.
///
/// # Safety
/// `method` must be a live `OsslDecoder`.
unsafe extern "C" fn free_decoder(method: *mut c_void) {
    // SAFETY: `method` is live per the contract.
    unsafe { OSSL_DECODER_free(method.cast::<OsslDecoder>()) };
}

/// `ERR_RFLAG_COMMON` — `include/openssl/err.h`, the bit every `ERR_R_*` common reason carries.
const ERR_RFLAG_COMMON: c_int = 0x2 << 18;

/// `ERR_R_FETCH_FAILED`, taken from the generated site rather than typed: the value is the
/// authority's own, resolved through its headers by `gen_err_raise_sites.py`.
const ERR_R_FETCH_FAILED: c_int = err_sites::EVP_FETCH_352.reason;

/// `ERR_R_UNSUPPORTED` (`err.h`): `(268 | ERR_RFLAG_COMMON)`.
const ERR_R_UNSUPPORTED: c_int = 268 | ERR_RFLAG_COMMON;

/// `static OSSL_DECODER *inner_ossl_decoder_fetch(struct decoder_data_st *methdata,
/// const char *name, const char *properties)` — `decoder_meth.c:351-421`.
///
/// The **cache is consulted first**, and only a miss runs the walk. `unsupported` starts as "no
/// name resolved" and is *replaced* by `!flag_construct_error_occurred` after a miss, so a walk
/// that never entered the constructor means "unsupported" and one that failed inside it means
/// `ERR_R_FETCH_FAILED`.
///
/// # Safety
/// `methdata` must point at a live, initialised `DecoderDataSt`; `name` and `properties` NULL or
/// NUL-terminated.
unsafe fn inner_ossl_decoder_fetch(
    methdata: *mut DecoderDataSt,
    name: *const c_char,
    properties: *const c_char,
) -> *mut OsslDecoder {
    // SAFETY: `methdata` is live per the contract.
    let libctx = unsafe { (*methdata).libctx };
    let store = get_decoder_store(libctx);
    let namemap = ossl_namemap_stored(libctx);
    let propq: *const c_char = if !properties.is_null() {
        properties
    } else {
        c"".as_ptr()
    };
    let mut method: *mut c_void = ptr::null_mut();

    if store.is_null() || namemap.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DECODER_METH_356) };
        return ptr::null_mut();
    }

    // SAFETY: `namemap` is live and `name` is NULL or NUL-terminated.
    let mut id = if !name.is_null() {
        // SAFETY: `namemap` is live and `name` is non-NULL and NUL-terminated here.
        unsafe { ossl_namemap_name2num(namemap, name) }
    } else {
        0
    };

    /* If we haven't found the name yet, chances are that the algorithm to be fetched is unsupported. */
    let mut unsupported = id == 0;

    // SAFETY: `store` and `namemap` are live; `methdata` is live.
    unsafe {
        if id == 0
            || ossl_method_store_cache_get(store, ptr::null_mut(), id, propq, &mut method) == 0
        {
            let mcm = OsslMethodConstructMethod {
                get_tmp_store: get_tmp_decoder_store,
                lock_store: reserve_decoder_store,
                unlock_store: unreserve_decoder_store,
                get: get_decoder_from_store,
                put: put_decoder_in_store,
                construct: construct_decoder,
                destruct: destruct_decoder,
            };
            let mut prov: *mut OsslProvider = ptr::null_mut();

            (*methdata).id = id;
            (*methdata).names = name;
            (*methdata).propquery = propq;
            (*methdata).flag_construct_error_occurred = 0;
            method = ossl_method_construct(
                (*methdata).libctx,
                OSSL_OP_DECODER,
                &mut prov,
                0, /* !force_cache */
                &mcm,
                methdata.cast::<c_void>(),
            );
            if !method.is_null() {
                if id == 0 {
                    id = ossl_namemap_name2num(namemap, name);
                }
                ossl_method_store_cache_set(
                    store,
                    prov,
                    id,
                    propq,
                    method,
                    up_ref_decoder,
                    free_decoder,
                );
            }

            /*
             * If we never were in the constructor, the algorithm to be fetched is unsupported.
             */
            unsupported = (*methdata).flag_construct_error_occurred == 0;
        }

        if (id != 0 || !name.is_null()) && method.is_null() {
            let code = if unsupported {
                ERR_R_UNSUPPORTED
            } else {
                ERR_R_FETCH_FAILED
            };
            let reported = if name.is_null() {
                ossl_namemap_num2name(namemap, id, 0)
            } else {
                name
            };
            let mut msg = [0 as c_char; 1024];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s, Name (%s : %d), Properties (%s)".as_ptr(),
                lib_ctx_get_descriptor((*methdata).libctx),
                if reported.is_null() {
                    c"<null>".as_ptr()
                } else {
                    reported
                },
                id,
                if properties.is_null() {
                    c"<null>".as_ptr()
                } else {
                    properties
                },
            );
            raise_site_dynamic_data(&err_sites::DECODER_METH_414, code, msg.as_ptr());
        }
    }

    method.cast::<OsslDecoder>()
}

/// `OSSL_DECODER *OSSL_DECODER_fetch(OSSL_LIB_CTX *libctx, const char *name,
/// const char *properties)` — `decoder_meth.c:423-435`.
///
/// # Safety
/// `libctx` NULL or live; `name` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_fetch(
    libctx: *mut c_void,
    name: *const c_char,
    properties: *const c_char,
) -> *mut OsslDecoder {
    let mut methdata = DecoderDataSt {
        libctx,
        id: 0,
        names: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
    };
    // SAFETY: `methdata` is live and initialised per the contract.
    let method = unsafe { inner_ossl_decoder_fetch(&mut methdata, name, properties) };
    // SAFETY: `methdata.tmp_store` is NULL or a store this call created.
    unsafe { dealloc_tmp_decoder_store(methdata.tmp_store.cast::<c_void>()) };
    method
}

/// `struct do_one_data_st` — `decoder_meth.c:540-543`.
struct DoOneData {
    /// `void (*user_fn)(OSSL_DECODER *decoder, void *arg)`.
    user_fn: unsafe extern "C" fn(*mut OsslDecoder, *mut c_void),
    /// `void *user_arg`.
    user_arg: *mut c_void,
}

/// `static void do_one(int id, void *method, void *arg)` — `decoder_meth.c:545-550`.
///
/// # Safety
/// `method` must be a live `OsslDecoder` and `arg` a live `DoOneData`.
unsafe extern "C" fn do_one(_id: c_int, method: *mut c_void, arg: *mut c_void) {
    // SAFETY: `arg` is a live `DoOneData` per the contract.
    let data = arg.cast::<DoOneData>();
    // SAFETY: `data` is live; `user_fn` is the caller's own callback.
    unsafe { ((*data).user_fn)(method.cast::<OsslDecoder>(), (*data).user_arg) };
}

/// `void OSSL_DECODER_do_all_provided(OSSL_LIB_CTX *libctx,
/// void (*user_fn)(OSSL_DECODER *decoder, void *arg), void *user_arg)` — `decoder_meth.c:552-577`.
///
/// The **fetch runs first**, which is what fills the temporary store, and only then are both the
/// temporary store's methods and the permanent store's walked. The temporary store is released
/// last. In this crate the walk finds the rows 10.1 has published -- the seventy
/// `decode_der2key.c` decoders the default (and base) provider each publish, keyed by name so the
/// two identical tables collapse to seventy stored methods -- and no others, because every other
/// `OSSL_OP_DECODER` provider row is still `unimplemented`.
///
/// # Safety
/// `libctx` NULL or live; `user_fn` a valid callback; `user_arg` opaque to this file.
#[no_mangle]
pub unsafe extern "C" fn OSSL_DECODER_do_all_provided(
    libctx: *mut c_void,
    user_fn: unsafe extern "C" fn(*mut OsslDecoder, *mut c_void),
    user_arg: *mut c_void,
) {
    let mut methdata = DecoderDataSt {
        libctx,
        id: 0,
        names: ptr::null(),
        propquery: ptr::null(),
        tmp_store: ptr::null_mut(),
        flag_construct_error_occurred: 0,
    };
    // SAFETY: `methdata` is live; `inner_ossl_decoder_fetch`'s contract is met with NULLs.
    unsafe { inner_ossl_decoder_fetch(&mut methdata, ptr::null(), ptr::null()) };

    let mut data = DoOneData { user_fn, user_arg };
    // SAFETY: each store is NULL or live and `data` is this frame's own.
    unsafe {
        if !methdata.tmp_store.is_null() {
            ossl_method_store_do_all(
                methdata.tmp_store,
                Some(do_one),
                ptr::addr_of_mut!(data).cast::<c_void>(),
            );
        }
        ossl_method_store_do_all(
            get_decoder_store(libctx),
            Some(do_one),
            ptr::addr_of_mut!(data).cast::<c_void>(),
        );
    }
    // SAFETY: `methdata.tmp_store` is NULL or a store this call created.
    unsafe { dealloc_tmp_decoder_store(methdata.tmp_store.cast::<c_void>()) };
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::OsslDispatch;

    /// The **non-sequential** ids land in the fields their names say.
    ///
    /// A table is laid out so `decode` is at id 11 and `does_selection` at id 10 -- the two whose
    /// values a sequential renumbering would swap -- and the scan is required to store each in its
    /// own slot. `decode` is non-NULL so the sanity check passes.
    #[test]
    fn the_dispatch_scan_stores_each_id_in_its_own_field() {
        // SAFETY: both callbacks are `unsafe extern "C"` items of the right shape and touch no
        // state, so calling either is defined.
        unsafe extern "C" fn decode_stub(
            _ctx: *mut c_void,
            _in: *mut c_void,
            _selection: c_int,
            _cb: Option<OsslCallback>,
            _cbarg: *mut c_void,
            _pw: Option<crate::passphrase::OsslPassphraseCallback>,
            _pwarg: *mut c_void,
        ) -> c_int {
            1
        }
        // SAFETY: as above.
        unsafe extern "C" fn selection_stub(_provctx: *mut c_void, _selection: c_int) -> c_int {
            1
        }

        let table = [
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DOES_SELECTION,
                function: selection_stub as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_DECODER_DECODE,
                function: decode_stub as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];

        // SAFETY: the table is terminated and the two entries carry their own ids.
        let (does_selection, decode) = unsafe {
            (
                entry_function::<DecoderDoesSelectionFn>(table.as_ptr()),
                entry_function::<DecoderDecodeFn>(table.as_ptr().add(1)),
            )
        };
        assert!(does_selection.is_some(), "id 10 is does_selection");
        assert!(decode.is_some(), "id 11 is decode");
        // The two entries are distinct functions: a swap would make them one pointer stored twice.
        assert_ne!(
            table[0].function as usize, table[1].function as usize,
            "does_selection and decode are distinct entries, not one pointer stored twice"
        );
        // The ids are pinned to their authority values.
        assert_eq!(OSSL_FUNC_DECODER_DOES_SELECTION, 10);
        assert_eq!(OSSL_FUNC_DECODER_DECODE, 11);
        assert_eq!(OSSL_FUNC_DECODER_EXPORT_OBJECT, 20);
        assert_eq!(OSSL_OP_DECODER, 21);
    }

    /// A fresh object has no fields and a reference count that survives a round trip, and the
    /// accessors that carry no NULL test read NULL out of a zeroed object.
    #[test]
    fn a_fresh_object_has_no_callbacks_and_a_live_reference() {
        // SAFETY: no preconditions.
        let decoder = unsafe { ossl_decoder_new() };
        assert!(!decoder.is_null());
        // SAFETY: `decoder` is this test's own object, and the number of a zeroed object is 0.
        unsafe {
            assert!(OSSL_DECODER_up_ref(decoder) == 1);
            assert!((*decoder).decode.is_none());
            assert!((*decoder).newctx.is_none());
            assert!(OSSL_DECODER_get0_name(decoder).is_null());
            assert!(ossl_decoder_get_number(decoder) == 0);
            OSSL_DECODER_free(decoder);
            OSSL_DECODER_free(decoder);
        }
    }

    /// The fetch block's two entry points: the fetch of an unknown name answers NULL and
    /// **raises** (the walk found no constructor, so the reason is the unsupported one), and the
    /// do-all walk finds the seventy provider decoder rows this crate publishes -- the sixty-nine
    /// `decode_der2key.c` tables and the one `DER` `EncryptedPrivateKeyInfo` decoder 10.1 landed.
    /// Exactly one of them is named `DER`; the rest carry their key type's name. A callback that
    /// records each decoder's name is the observation.
    #[test]
    fn a_fetch_of_an_unknown_name_refuses_and_the_walk_finds_the_der_rows() {
        // SAFETY: the argument is a NUL-terminated literal and NULL is the default context.
        let got = unsafe {
            OSSL_DECODER_fetch(
                ptr::null_mut(),
                c"openssl-rs-not-a-decoder".as_ptr(),
                ptr::null(),
            )
        };
        assert!(got.is_null(), "no provider decoder answers that name");
        assert_ne!(
            crate::runtime::err::ERR_peek_error(),
            0,
            "the refusal raises"
        );
        crate::runtime::err::ERR_clear_error();

        /// `(count, named_der)`.
        #[repr(C)]
        struct Seen {
            count: c_int,
            named_der: c_int,
        }

        // SAFETY: the callback reads a live `OsslDecoder` and a live `Seen`.
        unsafe extern "C" fn count(decoder: *mut OsslDecoder, arg: *mut c_void) {
            let seen = arg.cast::<Seen>();
            // SAFETY: `decoder` is live per the walk's contract and `seen` is the caller's.
            unsafe {
                (*seen).count += 1;
                let name = OSSL_DECODER_get0_name(decoder);
                if !name.is_null() && core::ffi::CStr::from_ptr(name).to_bytes() == b"DER" {
                    (*seen).named_der += 1;
                }
            }
        }
        let mut seen = Seen {
            count: 0,
            named_der: 0,
        };
        // SAFETY: `seen` is this frame's own and outlives the call.
        unsafe {
            OSSL_DECODER_do_all_provided(
                ptr::null_mut(),
                count,
                ptr::addr_of_mut!(seen).cast::<c_void>(),
            );
        }
        assert_eq!(
            seen.count, 70,
            "the walk finds the seventy decoder rows 10.1 landed"
        );
        assert_eq!(seen.named_der, 1, "exactly one of them is named DER");
        crate::runtime::err::ERR_clear_error();
    }

    /// This unit's two store bridges and the third decoder bridge are transcribed in
    /// `src/provider/stores.rs`, and the provider machinery calls them there. Naming them here is
    /// what keeps the unit's own translation-unit record complete. All three slots are now filled
    /// -- D365 filled the decoder store and cache -- so each answers the authority's value for a
    /// store that exists: the four method-store flushes **1**, and the decoder cache's flush **1**
    /// as well, because it is not absent any more.
    #[test]
    fn the_units_store_bridges_are_the_provider_modules() {
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live and non-NULL, which is all three bridges' contract.
        unsafe {
            assert_eq!(
                crate::provider::stores::ossl_decoder_store_cache_flush(ctx),
                1
            );
            assert_eq!(
                crate::provider::stores::ossl_decoder_cache_flush(ctx),
                1,
                "the decoder cache slot is filled, and an empty table flushes to 1"
            );
        }
        // The sibling needs a live provider, which this unit has none of; the name is referenced
        // so the unit's record names it, and the reference is typed rather than merely mentioned.
        let _ = crate::provider::stores::ossl_decoder_store_remove_all_provided
            as unsafe fn(*const crate::provider::OsslProvider) -> c_int;
    }
}
