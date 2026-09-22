//! Phase 10 — `crypto/encode_decode/encoder_meth.c`: the `OSSL_ENCODER` method object and its
//! context constructor.
//!
//! This is the first of the three encoder units (D360), and it is the one that carries the
//! **dispatch scan** and the `OSSL_ENCODER` object itself. It lands the store-bridge work D357
//! already put in `src/provider/stores.rs`, the object constructor/destructor, the accessors, the
//! by-name parameter pass-throughs, and the ten `OSSL_FUNC_ENCODER_*` identities the scan switches
//! on.
//!
//! ## The ten identities are not sequential, and that is the whole trap
//!
//! `crypto/encode_decode/encoder_meth.c`'s `encoder_from_algorithm` (`:231-274`) walks a provider's
//! `OSSL_DISPATCH` table and switches on `function_id`. In the authority those ids come from the
//! `OSSL_CORE_MAKE_FUNC` invocations at `include/openssl/core_dispatch.h:962-983`, and their values
//! are **1, 2, 3, 4, 5, 6, 10, 11, 20, 21** -- the four at 10, 11, 20 and 21 are not where a
//! sequential numbering would put them. A transcription that numbered them `1..10` would store the
//! encoder's `encode` pointer in `does_selection`'s slot and `import_object`'s in `encode`'s: every
//! dispatch slot after the sixth would be wrong, and nothing would fail until a provider encoder
//! actually ran. The values are therefore written out one per constant, each against its own
//! `OSSL_FUNC_ENCODER_*` name, and the unit test at the bottom of this file builds a table whose
//! `encode` entry is at id 11 and whose `does_selection` entry is at id 10 and asserts the two land
//! in the fields their names say -- so a future sequential renumbering fails a test rather than a
//! provider.
//!
//! ## What is withheld, and it is one named block rather than a scattered list
//!
//! Every function that is *not* here is named, with its authority coordinate: **the fetch and
//! construct-method block** -- `encoder_data_st` (`:78-87`), `get_tmp_encoder_store` (`:95`),
//! `dealloc_tmp_encoder_store` (`:104`), `get_encoder_store` (`:111`), `reserve_encoder_store`
//! (`:116`), `unreserve_encoder_store` (`:127`), `get_encoder_from_store` (`:139`),
//! `put_encoder_in_store` (`:174`), `construct_encoder` (`:304`), `destruct_encoder` (`:335`),
//! `up_ref_encoder` (`:340`), `free_encoder` (`:345`), `inner_ossl_encoder_fetch` (`:351`),
//! `OSSL_ENCODER_fetch` (`:429`), `do_one` (`:532`) and `OSSL_ENCODER_do_all_provided` (`:539`).
//! These are one block because `do_all_provided` calls `inner_ossl_encoder_fetch` **first** (`:549`)
//! and the fetch is the only caller of the seven `ossl_method_construct` callbacks, so none of the
//! seventeen can link without the rest. Sixteen of the seventeen are `static` or non-exported and
//! the seventeenth is an export, so the prerequisite gate does not see them as a transcribed unit's
//! unwired internals -- but the omission is a *narrowing* and is recorded here rather than left
//! implicit. They land with `src/encoder_pkey.rs`, whose `OSSL_ENCODER_CTX_new_for_pkey` is the
//! first caller of `do_all_provided`.
//!
//! The **context trio** (`OSSL_ENCODER_CTX_new` `:608`, `_set_params` `:616`, `_free` `:645`) is
//! here, even though it needs `src/encoder_lib.rs`'s `ossl_encoder_instance_free` and its two
//! `OSSL_ENCODER_INSTANCE_get_*` -- the two units landed together in D361 for exactly that reason,
//! which is the measurement D360 recorded.
//!
//! The two store bridges `ossl_encoder_store_cache_flush` and
//! `ossl_encoder_store_remove_all_provided` are this unit's (`:442-459`) but are **already
//! transcribed** in `src/provider/stores.rs`, by D357, alongside the seven sibling bridges of the
//! provider activation path; this module does not define them a second time, and the test at the
//! bottom of this file calls them by name so the two units' answers stay joined.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::context::namemap::{ossl_namemap_doall_names, ossl_namemap_stored};
use crate::encoder_lib::{
    ossl_encoder_instance_free, OSSL_ENCODER_CTX_get_num_encoders,
    OSSL_ENCODER_INSTANCE_get_encoder, OSSL_ENCODER_INSTANCE_get_encoder_ctx,
};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::params::OsslParam;
use crate::passphrase::{
    ossl_pw_clear_passphrase_data, OsslPassphraseCallback, OsslPassphraseData,
};
use crate::property::list::OsslPropertyList;
use crate::property::parse::ossl_parse_property;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_libctx, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};

/// `#define NAME_SEPARATOR ':'` — `crypto/encode_decode/encoder_meth.c:25`.
///
/// An encoder can carry several names in one colon-separated string; the fetch block (withheld)
/// is what splits it, so this constant is unused until that lands.
#[allow(dead_code)] // read by the withheld fetch block, which splits the name list
const NAME_SEPARATOR: c_char = b':' as c_char;

// ---------------------------------------------------------------------------
// The `OSSL_FUNC_ENCODER_*` identities — `include/openssl/core_dispatch.h:952-961`
// ---------------------------------------------------------------------------

/// `#define OSSL_FUNC_ENCODER_NEWCTX 1` — `core_dispatch.h:952`.
pub(crate) const OSSL_FUNC_ENCODER_NEWCTX: c_int = 1;
/// `#define OSSL_FUNC_ENCODER_FREECTX 2` — `core_dispatch.h:953`.
pub(crate) const OSSL_FUNC_ENCODER_FREECTX: c_int = 2;
/// `#define OSSL_FUNC_ENCODER_GET_PARAMS 3` — `core_dispatch.h:954`.
pub(crate) const OSSL_FUNC_ENCODER_GET_PARAMS: c_int = 3;
/// `#define OSSL_FUNC_ENCODER_GETTABLE_PARAMS 4` — `core_dispatch.h:955`.
pub(crate) const OSSL_FUNC_ENCODER_GETTABLE_PARAMS: c_int = 4;
/// `#define OSSL_FUNC_ENCODER_SET_CTX_PARAMS 5` — `core_dispatch.h:956`.
pub(crate) const OSSL_FUNC_ENCODER_SET_CTX_PARAMS: c_int = 5;
/// `#define OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS 6` — `core_dispatch.h:957`.
pub(crate) const OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS: c_int = 6;
/// `#define OSSL_FUNC_ENCODER_DOES_SELECTION 10` — `core_dispatch.h:958`. **Ten, not seven.**
pub(crate) const OSSL_FUNC_ENCODER_DOES_SELECTION: c_int = 10;
/// `#define OSSL_FUNC_ENCODER_ENCODE 11` — `core_dispatch.h:959`. **Eleven, not eight.**
pub(crate) const OSSL_FUNC_ENCODER_ENCODE: c_int = 11;
/// `#define OSSL_FUNC_ENCODER_IMPORT_OBJECT 20` — `core_dispatch.h:960`. **Twenty, not nine.**
pub(crate) const OSSL_FUNC_ENCODER_IMPORT_OBJECT: c_int = 20;
/// `#define OSSL_FUNC_ENCODER_FREE_OBJECT 21` — `core_dispatch.h:961`. **Twenty-one, not ten.**
pub(crate) const OSSL_FUNC_ENCODER_FREE_OBJECT: c_int = 21;

/// `void *(OSSL_FUNC_encoder_newctx_fn)(void *provctx)` — `core_dispatch.h:962`.
pub(crate) type EncoderNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `void (OSSL_FUNC_encoder_freectx_fn)(void *ctx)` — `core_dispatch.h:963`.
pub(crate) type EncoderFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `int (OSSL_FUNC_encoder_get_params_fn)(OSSL_PARAM params[])` — `core_dispatch.h:964`.
pub(crate) type EncoderGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `const OSSL_PARAM *(OSSL_FUNC_encoder_gettable_params_fn)(void *provctx)` — `core_dispatch.h:965`.
pub(crate) type EncoderGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `int (OSSL_FUNC_encoder_set_ctx_params_fn)(void *ctx, const OSSL_PARAM params[])`.
pub(crate) type EncoderSetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `const OSSL_PARAM *(OSSL_FUNC_encoder_settable_ctx_params_fn)(void *provctx)`.
pub(crate) type EncoderSettableCtxParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `int (OSSL_FUNC_encoder_does_selection_fn)(void *provctx, int selection)`.
pub(crate) type EncoderDoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
/// `int (OSSL_FUNC_encoder_encode_fn)(void *ctx, OSSL_CORE_BIO *out, const void *obj_raw,
/// const OSSL_PARAM obj_abstract[], int selection, OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)`.
pub(crate) type EncoderEncodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_void,
    *const c_void,
    *const OsslParam,
    c_int,
    Option<OsslPassphraseCallback>,
    *mut c_void,
) -> c_int;
/// `void *(OSSL_FUNC_encoder_import_object_fn)(void *ctx, int selection,
/// const OSSL_PARAM params[])`.
pub(crate) type EncoderImportObjectFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const OsslParam) -> *mut c_void;
/// `void (OSSL_FUNC_encoder_free_object_fn)(void *obj)` — `core_dispatch.h:983`.
pub(crate) type EncoderFreeObjectFn = unsafe extern "C" fn(*mut c_void);

// ---------------------------------------------------------------------------
// The shapes — `crypto/encode_decode/encoder_local.h`
// ---------------------------------------------------------------------------

/// `struct ossl_endecode_base_st` — `encoder_local.h:21-29`.
///
/// The common head of `OSSL_ENCODER` and `OSSL_DECODER`, and the only part either has in common:
/// the provider, the name-map id, the algorithm-definition the object was built from, and the
/// reference count. `algo_def` is borrowed from the provider's table and never freed; `name` and
/// `parsed_propdef` are this object's.
#[repr(C)]
pub struct OsslEndecodeBase {
    /// `OSSL_PROVIDER *prov` — holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `int id` — the name-map number the object answers to.
    pub(crate) id: c_int,
    /// `char *name` — the first name from the algorithm definition.
    pub(crate) name: *mut c_char,
    /// `const OSSL_ALGORITHM *algodef` — borrowed from the provider's table.
    pub(crate) algodef: *const OsslAlgorithm,
    /// `OSSL_PROPERTY_LIST *parsed_propdef` — this object's own parsed properties.
    pub(crate) parsed_propdef: *mut OsslPropertyList,
    /// `CRYPTO_REF_COUNT refcnt` — a plain `_Atomic int` in the authority, modelled as `AtomicI32`.
    pub(crate) refcnt: AtomicI32,
}

/// `struct ossl_encoder_st` — `encoder_local.h:31-43`.
///
/// One field per `<OSSL_FUNC_ENCODER_*>` entry `encoder_from_algorithm` may find. Every one is an
/// `Option` because a table need not supply it, and `None` is the authority's NULL.
#[repr(C)]
pub struct OsslEncoder {
    /// The shared head.
    pub(crate) base: OsslEndecodeBase,
    /// `OSSL_FUNC_ENCODER_NEWCTX`.
    pub(crate) newctx: Option<EncoderNewCtxFn>,
    /// `OSSL_FUNC_ENCODER_FREECTX`.
    pub(crate) freectx: Option<EncoderFreeCtxFn>,
    /// `OSSL_FUNC_ENCODER_GET_PARAMS`.
    pub(crate) get_params: Option<EncoderGetParamsFn>,
    /// `OSSL_FUNC_ENCODER_GETTABLE_PARAMS`.
    pub(crate) gettable_params: Option<EncoderGettableParamsFn>,
    /// `OSSL_FUNC_ENCODER_SET_CTX_PARAMS`.
    pub(crate) set_ctx_params: Option<EncoderSetCtxParamsFn>,
    /// `OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS`.
    pub(crate) settable_ctx_params: Option<EncoderSettableCtxParamsFn>,
    /// `OSSL_FUNC_ENCODER_DOES_SELECTION`.
    pub(crate) does_selection: Option<EncoderDoesSelectionFn>,
    /// `OSSL_FUNC_ENCODER_ENCODE`.
    pub(crate) encode: Option<EncoderEncodeFn>,
    /// `OSSL_FUNC_ENCODER_IMPORT_OBJECT`.
    pub(crate) import_object: Option<EncoderImportObjectFn>,
    /// `OSSL_FUNC_ENCODER_FREE_OBJECT`.
    pub(crate) free_object: Option<EncoderFreeObjectFn>,
}

/// `struct ossl_encoder_instance_st` — `encoder_local.h:58-63`.
///
/// One instantiated encoder in a context's chain. `encoderctx` is the provider's own context and
/// is released through the encoder's `freectx`; `output_type` comes from the implementation's
/// `output` property and is never NULL on a constructed instance.
#[repr(C)]
pub struct OsslEncoderInstance {
    /// `OSSL_ENCODER *encoder` — never NULL.
    pub(crate) encoder: *mut OsslEncoder,
    /// `void *encoderctx` — never NULL.
    pub(crate) encoderctx: *mut c_void,
    /// `const char *output_type` — never NULL.
    pub(crate) output_type: *const c_char,
    /// `const char *output_structure` — may be NULL.
    pub(crate) output_structure: *const c_char,
}

/// `typedef const void *OSSL_ENCODER_CONSTRUCT(OSSL_ENCODER_INSTANCE *, void *)` —
/// `encoder.h:91-92`.
pub(crate) type EncoderConstructFn =
    unsafe extern "C" fn(*mut OsslEncoderInstance, *mut c_void) -> *const c_void;
/// `typedef void OSSL_ENCODER_CLEANUP(void *construct_data)` — `encoder.h:93`.
pub(crate) type EncoderCleanupFn = unsafe extern "C" fn(*mut c_void);

/// `struct ossl_encoder_ctx_st` — `encoder_local.h:69-104`.
///
/// The context `OSSL_ENCODER_CTX_new` allocates and `OSSL_ENCODER_CTX_free` releases. `pwdata` is
/// the passphrase bridge D356/D358 landed, embedded by value exactly as the authority embeds it.
#[repr(C)]
pub struct OsslEncoderCtx {
    /// `int selection` — the `OSSL_KEYMGMT_SELECT_*` bits to encode.
    pub(crate) selection: c_int,
    /// `const char *output_type` — the desired output type, matched against the `output` property.
    pub(crate) output_type: *const c_char,
    /// `const char *output_structure` — the desired output structure, or NULL.
    pub(crate) output_structure: *const c_char,
    /// `STACK_OF(OSSL_ENCODER_INSTANCE) *encoder_insts` — the chain, built lazily.
    pub(crate) encoder_insts: *mut OpenSslStack,
    /// `OSSL_ENCODER_CONSTRUCT *construct` — the object constructor for the chain's head.
    pub(crate) construct: Option<EncoderConstructFn>,
    /// `OSSL_ENCODER_CLEANUP *cleanup` — its destructor.
    pub(crate) cleanup: Option<EncoderCleanupFn>,
    /// `void *construct_data` — passed to both.
    pub(crate) construct_data: *mut c_void,
    /// `struct ossl_passphrase_data_st pwdata` — by value, as the authority embeds it.
    pub(crate) pwdata: OsslPassphraseData,
}

// ---------------------------------------------------------------------------
// The object
// ---------------------------------------------------------------------------

/// `static OSSL_ENCODER *ossl_encoder_new(void)` — `encoder_meth.c:38-50`.
///
/// A zeroed object with a reference count of **1**. The `CRYPTO_NEW_REF` failure arm calls
/// `OSSL_ENCODER_free`, which is why the `refcnt` field must be readable as 0 on that path (the
/// `zalloc` guarantee) and why the constructor does not simply build the struct in Rust: the
/// failure arm's release goes through the public destructor.
#[allow(dead_code)] // read by the withheld fetch block, next pass
pub(crate) unsafe fn ossl_encoder_new() -> *mut OsslEncoder {
    // SAFETY: the constructor only asks for a zeroed block of the object's size.
    let encoder =
        CRYPTO_zalloc(core::mem::size_of::<OsslEncoder>(), ptr::null(), 0).cast::<OsslEncoder>();
    if encoder.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `encoder` is a fresh, zeroed, uniquely-owned block; this is the field `CRYPTO_NEW_REF`
    // initialises to 1. A zeroed `refcnt` would make the release below free an object another
    // reference still holds.
    unsafe { (*encoder).base.refcnt.store(1, Ordering::Release) };
    encoder
}

/// `int OSSL_ENCODER_up_ref(OSSL_ENCODER *encoder)` — `encoder_meth.c:52-58`.
///
/// Answers **1** unconditionally, including for the NULL the authority would fault on: the body is
/// `CRYPTO_UP_REF` and a `return 1`, and no caller checks the answer.
///
/// # Safety
/// `encoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_up_ref(encoder: *mut OsslEncoder) -> c_int {
    // SAFETY: `encoder` is live per the contract; the count is a plain atomic field.
    unsafe { (*encoder).base.refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void OSSL_ENCODER_free(OSSL_ENCODER *encoder)` — `encoder_meth.c:60-75`.
///
/// The release order is the authority's: the name, the parsed properties, the provider reference
/// and the count are released **before** the block itself, and the count is released by the same
/// `CRYPTO_FREE_REF` that decides whether anything else runs. The `ref > 0` test is
/// `fetch_sub`'s return **minus one**, which is why the crate's other reference-counted objects
/// test `last > 1` rather than `last > 0`.
///
/// # Safety
/// `encoder` must be NULL or a live `OsslEncoder` this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_free(encoder: *mut OsslEncoder) {
    if encoder.is_null() {
        return;
    }

    // SAFETY: `encoder` is live per the contract.
    let last = unsafe { (*encoder).base.refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }

    // SAFETY: `encoder` is live and this is the last reference; each field is this object's own.
    unsafe {
        CRYPTO_free((*encoder).base.name.cast(), ptr::null(), 0);
        crate::property::parse::ossl_property_free((*encoder).base.parsed_propdef);
        crate::provider::ossl_provider_free((*encoder).base.prov);
        CRYPTO_free(encoder.cast(), ptr::null(), 0);
    }
}

/// `static void *encoder_from_algorithm(int id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)` — `encoder_meth.c:209-297`.
///
/// The dispatch scan, and the reason this unit exists. Three things are the authority's and easy
/// to get wrong: the name is taken with `ossl_algorithm_get1_first_name`, which **allocates** and
/// is released by `OSSL_ENCODER_free`; the property definition is parsed once and stored; and the
/// sanity check at `:280-288` is a **four-way** condition whose first three clauses are pairwise
/// and only the fourth is singular -- `encode` must be present, and the constructor/destructor pair
/// and the import/free pair must each be both-or-neither. It is written as the authority wrote it,
/// with the four clauses kept separate, because collapsing them is how the `||` becomes an `&&`.
///
/// # Safety
/// `algodef` must be a live algorithm definition whose `implementation` is a terminated dispatch
/// table; `prov` must be NULL or live.
#[allow(dead_code)] // read by the withheld fetch block and by `src/encoder_lib.rs`, next pass
pub(crate) unsafe fn encoder_from_algorithm(
    id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut OsslEncoder {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation }.cast::<OsslDispatch>();
    // SAFETY: `prov` is NULL or live per the contract.
    let libctx = unsafe { ossl_provider_libctx(prov) };

    // SAFETY: `ossl_encoder_new` takes no arguments and answers NULL or a live object.
    let encoder = unsafe { ossl_encoder_new() };
    if encoder.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `encoder` is live and uniquely owned here.
    unsafe { (*encoder).base.id = id };
    // SAFETY: `algodef` is live; the helper allocates a copy of the first name.
    let name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.name = name };
    if name.is_null() {
        // SAFETY: `encoder` is live and owned here.
        unsafe { OSSL_ENCODER_free(encoder) };
        return ptr::null_mut();
    }
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.algodef = algodef };
    // SAFETY: `algodef` is live; the parse is given the provider's context.
    let parsed = unsafe { ossl_parse_property(libctx, (*algodef).property_definition) };
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.parsed_propdef = parsed };
    if parsed.is_null() {
        // SAFETY: `encoder` is live and owned here.
        unsafe { OSSL_ENCODER_free(encoder) };
        return ptr::null_mut();
    }

    // SAFETY: `fns` is a terminated table per the contract, and every cast below is the type its
    // own `OSSL_FUNC_ENCODER_*` id names -- which is what the non-sequential values above are for.
    unsafe {
        let mut p = fns;
        while (*p).function_id != OSSL_DISPATCH_END {
            match (*p).function_id {
                OSSL_FUNC_ENCODER_NEWCTX if (*encoder).newctx.is_none() => {
                    (*encoder).newctx = entry_function::<EncoderNewCtxFn>(p);
                }
                OSSL_FUNC_ENCODER_FREECTX if (*encoder).freectx.is_none() => {
                    (*encoder).freectx = entry_function::<EncoderFreeCtxFn>(p);
                }
                OSSL_FUNC_ENCODER_GET_PARAMS if (*encoder).get_params.is_none() => {
                    (*encoder).get_params = entry_function::<EncoderGetParamsFn>(p);
                }
                OSSL_FUNC_ENCODER_GETTABLE_PARAMS if (*encoder).gettable_params.is_none() => {
                    (*encoder).gettable_params = entry_function::<EncoderGettableParamsFn>(p);
                }
                OSSL_FUNC_ENCODER_SET_CTX_PARAMS if (*encoder).set_ctx_params.is_none() => {
                    (*encoder).set_ctx_params = entry_function::<EncoderSetCtxParamsFn>(p);
                }
                OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS
                    if (*encoder).settable_ctx_params.is_none() =>
                {
                    (*encoder).settable_ctx_params =
                        entry_function::<EncoderSettableCtxParamsFn>(p);
                }
                OSSL_FUNC_ENCODER_DOES_SELECTION if (*encoder).does_selection.is_none() => {
                    (*encoder).does_selection = entry_function::<EncoderDoesSelectionFn>(p);
                }
                OSSL_FUNC_ENCODER_ENCODE if (*encoder).encode.is_none() => {
                    (*encoder).encode = entry_function::<EncoderEncodeFn>(p);
                }
                OSSL_FUNC_ENCODER_IMPORT_OBJECT if (*encoder).import_object.is_none() => {
                    (*encoder).import_object = entry_function::<EncoderImportObjectFn>(p);
                }
                OSSL_FUNC_ENCODER_FREE_OBJECT if (*encoder).free_object.is_none() => {
                    (*encoder).free_object = entry_function::<EncoderFreeObjectFn>(p);
                }
                _ => {}
            }
            p = p.add(1);
        }

        // The sanity check, its four clauses kept separate: both-or-neither for the two pairs, and
        // `encode` required.
        let pairs_ok = ((*encoder).newctx.is_none() && (*encoder).freectx.is_none())
            || ((*encoder).newctx.is_some() && (*encoder).freectx.is_some())
            || ((*encoder).import_object.is_some() && (*encoder).free_object.is_some())
            || ((*encoder).import_object.is_none() && (*encoder).free_object.is_none());
        if !pairs_ok || (*encoder).encode.is_none() {
            OSSL_ENCODER_free(encoder);
            raise_site(&err_sites::ENCODER_METH_286);
            return ptr::null_mut();
        }

        if !prov.is_null() && ossl_provider_up_ref(prov) == 0 {
            OSSL_ENCODER_free(encoder);
            return ptr::null_mut();
        }
        (*encoder).base.prov = prov;
    }
    encoder
}

/// `const OSSL_PROVIDER *OSSL_ENCODER_get0_provider(const OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:465-473`.
///
/// # Safety
/// `encoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_get0_provider(
    encoder: *const OsslEncoder,
) -> *const OsslProvider {
    if encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_METH_468) };
        return ptr::null();
    }
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.prov }
}

/// `const char *OSSL_ENCODER_get0_properties(const OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:475-483`.
///
/// # Safety
/// `encoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_get0_properties(
    encoder: *const OsslEncoder,
) -> *const c_char {
    if encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_METH_478) };
        return ptr::null();
    }
    // SAFETY: `encoder` is live; `algodef` is the borrowed table entry it was built from.
    unsafe { (*(*encoder).base.algodef).property_definition }
}

/// `const OSSL_PROPERTY_LIST *ossl_encoder_parsed_properties(const OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:485-494`.
///
/// # Safety
/// `encoder` must be live.
#[allow(dead_code)] // read by encoder_lib.c's `ossl_encoder_instance_new`, next pass
pub(crate) unsafe fn ossl_encoder_parsed_properties(
    encoder: *const OsslEncoder,
) -> *mut OsslPropertyList {
    if encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_METH_489) };
        return ptr::null_mut();
    }
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.parsed_propdef }
}

/// `int ossl_encoder_get_number(const OSSL_ENCODER *encoder)` — `encoder_meth.c:496-504`.
///
/// # Safety
/// `encoder` must be live.
#[allow(dead_code)] // read by encoder_lib.c's accessors, next pass
pub(crate) unsafe fn ossl_encoder_get_number(encoder: *const OsslEncoder) -> c_int {
    if encoder.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_METH_499) };
        return 0;
    }
    // SAFETY: `encoder` is live.
    unsafe { (*encoder).base.id }
}

/// `const char *OSSL_ENCODER_get0_name(const OSSL_ENCODER *encoder)` — `encoder_meth.c:506-509`.
///
/// The one accessor with **no NULL test**: the authority's body is a bare field read, so this is
/// too. A NULL encoder is the caller's fault and reads as a fault, not as a diagnosed 0.
///
/// # Safety
/// `encoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_get0_name(encoder: *const OsslEncoder) -> *const c_char {
    // SAFETY: `encoder` is live per the contract.
    unsafe { (*encoder).base.name }
}

/// `const char *OSSL_ENCODER_get0_description(const OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:511-514`.
///
/// # Safety
/// `encoder` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_get0_description(
    encoder: *const OsslEncoder,
) -> *const c_char {
    // SAFETY: `encoder` is live; `algodef` is the borrowed table entry it was built from.
    unsafe { (*(*encoder).base.algodef).algorithm_description }
}

/// `int OSSL_ENCODER_is_a(const OSSL_ENCODER *encoder, const char *name)` —
/// `encoder_meth.c:516-525`.
///
/// A name comparison through the name map, and **0** for an object with no provider: an encoder
/// built without one has no name map to ask, and the authority answers 0 rather than dereferencing
/// the NULL.
///
/// # Safety
/// `encoder` must be live; `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_is_a(
    encoder: *const OsslEncoder,
    name: *const c_char,
) -> c_int {
    // SAFETY: `encoder` is live.
    let prov = unsafe { (*encoder).base.prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live (or NULL, which the comparison then loses); `name` is
        // NUL-terminated per the contract.
        let num = unsafe { crate::context::namemap::ossl_namemap_name2num(namemap, name) };
        // SAFETY: `encoder` is live.
        return c_int::from(num == unsafe { (*encoder).base.id });
    }
    0
}

/// `int OSSL_ENCODER_names_do_all(const OSSL_ENCODER *encoder,
/// void (*fn)(const char *name, void *data), void *data)` — `encoder_meth.c:559-574`.
///
/// # Safety
/// `encoder` must be live; `fn` must be a valid callback that tolerates every name.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_names_do_all(
    encoder: *const OsslEncoder,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    if encoder.is_null() {
        return 0;
    }
    // SAFETY: `encoder` is live.
    let prov = unsafe { (*encoder).base.prov };
    if !prov.is_null() {
        // SAFETY: `prov` is live.
        let libctx = unsafe { ossl_provider_libctx(prov) };
        let namemap = ossl_namemap_stored(libctx);
        // SAFETY: `namemap` is live or NULL; the callback is the caller's.
        return unsafe { ossl_namemap_doall_names(namemap, (*encoder).base.id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *OSSL_ENCODER_gettable_params(OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:576-585`.
///
/// # Safety
/// `encoder` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_gettable_params(
    encoder: *mut OsslEncoder,
) -> *const OsslParam {
    if !encoder.is_null() {
        // SAFETY: `encoder` is live.
        if let Some(gettable) = unsafe { (*encoder).gettable_params } {
            // SAFETY: `encoder` is live, so its provider is too.
            let provctx = unsafe { crate::provider::ossl_provider_ctx((*encoder).base.prov) };
            // SAFETY: `gettable` is a live provider callback and `provctx` is its own context.
            return unsafe { gettable(provctx) };
        }
    }
    ptr::null()
}

/// `int OSSL_ENCODER_get_params(OSSL_ENCODER *encoder, OSSL_PARAM params[])` —
/// `encoder_meth.c:587-592`.
///
/// # Safety
/// `encoder` must be NULL or live; `params` must be NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_get_params(
    encoder: *mut OsslEncoder,
    params: *mut OsslParam,
) -> c_int {
    if !encoder.is_null() {
        // SAFETY: `encoder` is live.
        if let Some(get_params) = unsafe { (*encoder).get_params } {
            // SAFETY: `get_params` is a live provider callback and `params` is the caller's.
            return unsafe { get_params(params) };
        }
    }
    0
}

/// `const OSSL_PARAM *OSSL_ENCODER_settable_ctx_params(OSSL_ENCODER *encoder)` —
/// `encoder_meth.c:594-602`.
///
/// # Safety
/// `encoder` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_settable_ctx_params(
    encoder: *mut OsslEncoder,
) -> *const OsslParam {
    if !encoder.is_null() {
        // SAFETY: `encoder` is live.
        if let Some(settable) = unsafe { (*encoder).settable_ctx_params } {
            // SAFETY: `encoder` is live, so its provider is too.
            let provctx = unsafe { crate::provider::ossl_provider_ctx((*encoder).base.prov) };
            // SAFETY: `settable` is a live provider callback and `provctx` is its own context.
            return unsafe { settable(provctx) };
        }
    }
    ptr::null()
}

/// `sk_OSSL_ENCODER_INSTANCE_pop_free`'s destructor: the crate's stack frees elements through a
/// `void *`-shaped callback, so `ossl_encoder_instance_free` is reached through this thunk.
unsafe extern "C" fn encoder_instance_free_thunk(p: *mut c_void) {
    // SAFETY: the stack's element is an `OsslEncoderInstance` this crate allocated and owns.
    unsafe { ossl_encoder_instance_free(p.cast()) };
}

/// `OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new(void)` -- `encoder_meth.c:608-614`.
///
/// One zeroed allocation and nothing else: no lock, no reference count, no failure diagnosis. The
/// embedded `pwdata` is therefore `type_ == 0`, which is no member of the passphrase enum -- the
/// state `ossl_pw_get_passphrase` would refuse if it were ever called, and which the passphrase
/// setters overwrite.
///
/// # Safety
/// No preconditions.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_new() -> *mut OsslEncoderCtx {
    // SAFETY: the constructor only asks for a zeroed block of the object's size.
    CRYPTO_zalloc(core::mem::size_of::<OsslEncoderCtx>(), ptr::null(), 0).cast::<OsslEncoderCtx>()
}

/// `int OSSL_ENCODER_CTX_set_params(OSSL_ENCODER_CTX *ctx, const OSSL_PARAM params[])` --
/// `encoder_meth.c:616-643`.
///
/// An **empty chain is a success**: `ctx->encoder_insts == NULL` answers 1 without touching
/// `params`, which is the arm `OSSL_ENCODER_CTX_new_for_pkey` reaches for a legacy key. With a
/// chain, every instance that has a context *and* a `set_ctx_params` is asked, and the answer is
/// the **and** of their answers rather than the first refusal -- a later instance still gets the
/// call after an earlier one fails.
///
/// # Safety
/// `ctx` must be live; `params` must be NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_params(
    ctx: *mut OsslEncoderCtx,
    params: *const OsslParam,
) -> c_int {
    let mut ok = 1;

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_METH_624) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let insts = unsafe { (*ctx).encoder_insts };
    if insts.is_null() {
        return 1;
    }

    // SAFETY: `ctx` is live, so the count and the stack agree.
    let l = unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) };
    for i in 0..l {
        // SAFETY: `insts` is a live stack and `i` is within its count.
        unsafe {
            let encoder_inst = OPENSSL_sk_value(insts, i).cast::<OsslEncoderInstance>();
            let encoder = OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
            let encoderctx = OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);

            if encoderctx.is_null() {
                continue;
            }
            if let Some(set_ctx_params) = (*encoder).set_ctx_params {
                if set_ctx_params(encoderctx, params) == 0 {
                    ok = 0;
                }
            }
        }
    }
    ok
}

/// `void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *ctx)` -- `encoder_meth.c:645-654`.
///
/// Four releases in the authority's order: the instance chain through
/// `ossl_encoder_instance_free` (which is what releases each instance's encoder reference and its
/// provider context), the constructor data, the **passphrase bridge** -- D356/D358's
/// `ossl_pw_clear_passphrase_data`, which frees an explicit phrase and the cache -- and the context
/// itself. A NULL context is a no-op.
///
/// # Safety
/// `ctx` must be NULL or a live `OsslEncoderCtx` this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_free(ctx: *mut OsslEncoderCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live; the stack is NULL or a live stack of instances this crate made, and
    // the thunk frees each one.
    unsafe {
        OPENSSL_sk_pop_free((*ctx).encoder_insts, Some(encoder_instance_free_thunk));
        CRYPTO_free((*ctx).construct_data, ptr::null(), 0);
        ossl_pw_clear_passphrase_data(ptr::addr_of_mut!((*ctx).pwdata));
        CRYPTO_free(ctx.cast(), ptr::null(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `int (OSSL_FUNC_encoder_encode_fn)(...)` — a real encode callback for the scan test.
    unsafe extern "C" fn example_encode(
        _ctx: *mut c_void,
        _out: *mut c_void,
        _obj: *const c_void,
        _abstract: *const OsslParam,
        _selection: c_int,
        _cb: Option<OsslPassphraseCallback>,
        _cbarg: *mut c_void,
    ) -> c_int {
        11
    }

    /// `int (OSSL_FUNC_encoder_does_selection_fn)(...)` — a real selection callback.
    unsafe extern "C" fn example_does_selection(_provctx: *mut c_void, _selection: c_int) -> c_int {
        10
    }

    /// A provider's dispatch table with **only** the two ids whose values are not sequential, in
    /// the order a provider would write them.
    static TABLE: [OsslDispatch; 3] = [
        OsslDispatch {
            function_id: OSSL_FUNC_ENCODER_ENCODE,
            function: example_encode as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_FUNC_ENCODER_DOES_SELECTION,
            function: example_does_selection as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        },
    ];

    /// A provider algorithm definition whose implementation is [`TABLE`].
    static ALGO: OsslAlgorithm = OsslAlgorithm {
        algorithm_names: c"TEST".as_ptr(),
        property_definition: c"".as_ptr(),
        implementation: TABLE.as_ptr().cast::<c_void>(),
        algorithm_description: c"test".as_ptr(),
    };

    /// **The trap, pinned.** `ENCODE` is 11 and `DOES_SELECTION` is 10, so a table that lists
    /// `encode` first must still land it in `encode` and the selection callback in
    /// `does_selection` -- never the other way round. This is the test a sequential renumbering
    /// fails.
    #[test]
    fn the_scan_lands_each_callback_in_the_field_its_id_names() {
        // SAFETY: `ALGO` is a live definition over a terminated table, and a NULL provider is the
        // contract's other arm.
        let encoder = unsafe { encoder_from_algorithm(1, &ALGO, ptr::null_mut()) };
        assert!(!encoder.is_null());
        // SAFETY: `encoder` is live.
        unsafe {
            assert!((*encoder).encode.is_some());
            assert!((*encoder).does_selection.is_some());
            // The two are distinct functions and are *not* swapped.
            assert_eq!(
                (*encoder).encode.map(|f| f as *const () as usize),
                Some(example_encode as *const () as usize)
            );
            assert_eq!(
                (*encoder).does_selection.map(|f| f as *const () as usize),
                Some(example_does_selection as *const () as usize)
            );
            assert_eq!((*encoder).base.id, 1);
            OSSL_ENCODER_free(encoder);
        }
    }

    /// The count is not part of the ids, and the four constants that break the sequence are the
    /// values the authority's header gives. Named individually so a wrong one is a named failure.
    #[test]
    fn the_identities_are_the_authoritys_values() {
        assert_eq!(OSSL_FUNC_ENCODER_NEWCTX, 1);
        assert_eq!(OSSL_FUNC_ENCODER_FREECTX, 2);
        assert_eq!(OSSL_FUNC_ENCODER_GET_PARAMS, 3);
        assert_eq!(OSSL_FUNC_ENCODER_GETTABLE_PARAMS, 4);
        assert_eq!(OSSL_FUNC_ENCODER_SET_CTX_PARAMS, 5);
        assert_eq!(OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, 6);
        assert_eq!(OSSL_FUNC_ENCODER_DOES_SELECTION, 10);
        assert_eq!(OSSL_FUNC_ENCODER_ENCODE, 11);
        assert_eq!(OSSL_FUNC_ENCODER_IMPORT_OBJECT, 20);
        assert_eq!(OSSL_FUNC_ENCODER_FREE_OBJECT, 21);
    }

    /// This unit's two store bridges are transcribed in `src/provider/stores.rs` (D357), and the
    /// provider machinery calls them there. Naming them here is what keeps the unit's own
    /// translation-unit record complete, and the call observes the authority's answer for a context
    /// whose encoder store exists: **1**.
    #[test]
    fn the_units_store_bridges_are_the_provider_modules() {
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live and non-NULL, which is the flush's contract.
        unsafe {
            assert_eq!(
                crate::provider::stores::ossl_encoder_store_cache_flush(ctx),
                1
            )
        };
        // The sibling needs a live provider, which this unit has none of; the name is referenced
        // so the unit's record names it, and the reference is typed rather than merely mentioned.
        let _ = crate::provider::stores::ossl_encoder_store_remove_all_provided
            as unsafe fn(*const crate::provider::OsslProvider) -> c_int;
    }
}
