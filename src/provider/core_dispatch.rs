//! Phase 6.8b-ii — the `core_dispatch` table: what the core offers a provider.
//!
//! `core_dispatch` is the **only** way a provider reaches the library. A provider module's
//! `init` is handed `OSSL_DISPATCH *in`, and every `OSSL_FUNC_CORE_*`, `OSSL_FUNC_BIO_*` and
//! `OSSL_FUNC_CRYPTO_*` it can call comes from this table. So the table *is* the core/provider
//! ABI, and its shape is a compatibility surface in a way that a static function pointer
//! usually is not: a provider compiled against another 3.x will look up the ids it knows and
//! be answered NULL for the ones this build does not publish.
//!
//! That last point is why the table is assembled **only from entries whose function exists**,
//! with the absent ones named below rather than stubbed. A NULL entry and a wrong entry are
//! different failures and only one of them is honest.
//!
//! ## What is absent, and why each one is
//!
//! | id | function | owner |
//! |---|---|---|
//! | `OSSL_FUNC_CORE_THREAD_START` (3) | `ossl_init_thread_start` | **6.6e-ii** — the per-thread event-handler table |
//! | `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB` (105), `DEREGISTER_CHILD_CB` (106) | the child callback pair | **6.8e** |
//! | `OSSL_FUNC_PROVIDER_UP_REF` (110), `PROVIDER_FREE` (111) | `provider_up_ref_intern`, `provider_free_intern` | **6.8c** — the `activate` arm is `ossl_provider_activate` |
//! | `OSSL_FUNC_GET_ENTROPY` (101), `GET_USER_ENTROPY` (98), `CLEANUP_ENTROPY` (102), `CLEANUP_USER_ENTROPY` (96), `GET_NONCE` (103), `GET_USER_NONCE` (99), `CLEANUP_NONCE` (104), `CLEANUP_USER_NONCE` (97) | the eight `rand_*` callbacks | **Phase 9** — they wrap `ossl_rand_get_entropy` and friends |
//! | `OSSL_FUNC_CORE_OBJ_ADD_SIGID` (121), `CORE_OBJ_CREATE` (122) | `core_obj_add_sigid`, `core_obj_create` | **landed** — `OBJ_txt2nid`, `OBJ_find_sigid_algs`, `OBJ_add_sigid` and `OBJ_create` are all in `src/runtime/obj.rs` |
//!
//! The first three groups are gaps; the fourth is not, and is included. The distinction is
//! worth stating because "not in the table yet" reads as one condition and is three.
//!
//! ## `core_get_params` has a fall-through that is easy to miss
//!
//! Three parameters are answered from the core itself — the version, the provider's name and
//! the module filename — and then, **unconditionally**, the provider's own configuration
//! parameters are written over the caller's array by
//! [`crate::provider::ossl_provider_get_conf_parameters`]. So a caller asking for
//! `"provider-name"` gets the core's answer *and* a config parameter of the same name would
//! overwrite it, because the two writes go to the same array and the second wins. That is the
//! authority's order and it is reproduced rather than tidied.
//!
//! ## `core_gettable_params` answers a `static`
//!
//! The three descriptors are a `static const` array with NULL `data` pointers, and the
//! function answers its address — so a caller must not write through them. `return_size` is
//! `OSSL_PARAM_UNMODIFIED` on all three, which is what `OSSL_PARAM_DEFN` expands to.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::context::dispatch::OsslDispatch;
use crate::params::{OsslParam, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UTF8_PTR};
use crate::provider::{
    ossl_provider_ctx, ossl_provider_get0_dispatch, ossl_provider_get_conf_parameters,
    ossl_provider_name, OsslProvider,
};
use crate::runtime::err::{
    ERR_clear_last_mark, ERR_count_to_mark, ERR_new, ERR_pop_to_mark, ERR_set_debug, ERR_set_mark,
};
use crate::runtime::init::VERSION_STRING;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_clear_realloc, CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc,
    CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::runtime::obj::{OBJ_add_sigid, OBJ_create, OBJ_find_sigid_algs, OBJ_txt2nid};
use crate::runtime::secure::{
    CRYPTO_secure_allocated, CRYPTO_secure_clear_free, CRYPTO_secure_free, CRYPTO_secure_malloc,
    CRYPTO_secure_zalloc,
};

extern "C" {
    /// `int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list ap)`.
    ///
    /// Defined in `src/runtime/bio/bio_variadic.c`. The dispatch table publishes it directly,
    /// as the authority does, because a provider that writes a formatted message wants the
    /// core's `_dopr` rather than the platform's `vsnprintf` — the two disagree on `%s` of a
    /// NULL pointer and on the return value of a truncated write.
    #[allow(dead_code)] // published by `CORE_DISPATCH`, which nothing reads until 6.8c
    fn BIO_vsnprintf(buf: *mut c_char, n: usize, format: *const c_char, args: *mut c_void)
        -> c_int;
}

/// `ERR_LIB_OFFSET` — the shift `ERR_GET_LIB` applies.
const ERR_LIB_OFFSET: c_uint = 23;
/// `ERR_LIB_MASK` — the width of the library field.
const ERR_LIB_MASK: c_uint = 0xFF;
/// `ERR_REASON_MASK` — the width of the reason field.
const ERR_REASON_MASK: c_uint = 0x7F_FFFF;

/// `ERR_GET_LIB(r)`.
fn err_get_lib(r: c_uint) -> c_int {
    ((r >> ERR_LIB_OFFSET) & ERR_LIB_MASK) as c_int
}

/// `ERR_GET_REASON(r)`.
fn err_get_reason(r: c_uint) -> c_int {
    (r & ERR_REASON_MASK) as c_int
}

// The `OSSL_FUNC_*` ids this table publishes, from `include/openssl/core_dispatch.h`.
/// `OSSL_FUNC_CORE_GETTABLE_PARAMS`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_GETTABLE_PARAMS: c_int = 1;
/// `OSSL_FUNC_CORE_GET_PARAMS`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_GET_PARAMS: c_int = 2;
/// `OSSL_FUNC_CORE_GET_LIBCTX`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_GET_LIBCTX: c_int = 4;
/// `OSSL_FUNC_CORE_NEW_ERROR`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_NEW_ERROR: c_int = 5;
/// `OSSL_FUNC_CORE_SET_ERROR_DEBUG`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_SET_ERROR_DEBUG: c_int = 6;
/// `OSSL_FUNC_CORE_VSET_ERROR`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_VSET_ERROR: c_int = 7;
/// `OSSL_FUNC_CORE_SET_ERROR_MARK`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_SET_ERROR_MARK: c_int = 8;
/// `OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_CLEAR_LAST_ERROR_MARK: c_int = 9;
/// `OSSL_FUNC_CORE_POP_ERROR_TO_MARK`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_POP_ERROR_TO_MARK: c_int = 10;
/// `OSSL_FUNC_CRYPTO_MALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_MALLOC: c_int = 20;
/// `OSSL_FUNC_CRYPTO_ZALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_ZALLOC: c_int = 21;
/// `OSSL_FUNC_CRYPTO_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_FREE: c_int = 22;
/// `OSSL_FUNC_CRYPTO_CLEAR_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_CLEAR_FREE: c_int = 23;
/// `OSSL_FUNC_CRYPTO_REALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_REALLOC: c_int = 24;
/// `OSSL_FUNC_CRYPTO_CLEAR_REALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_CLEAR_REALLOC: c_int = 25;
/// `OSSL_FUNC_CRYPTO_SECURE_MALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_SECURE_MALLOC: c_int = 26;
/// `OSSL_FUNC_CRYPTO_SECURE_ZALLOC`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_SECURE_ZALLOC: c_int = 27;
/// `OSSL_FUNC_CRYPTO_SECURE_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_SECURE_FREE: c_int = 28;
/// `OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_SECURE_CLEAR_FREE: c_int = 29;
/// `OSSL_FUNC_CRYPTO_SECURE_ALLOCATED`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CRYPTO_SECURE_ALLOCATED: c_int = 30;
/// `OSSL_FUNC_OPENSSL_CLEANSE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_OPENSSL_CLEANSE: c_int = 31;
/// `OSSL_FUNC_BIO_NEW_FILE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_NEW_FILE: c_int = 40;
/// `OSSL_FUNC_BIO_NEW_MEMBUF`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_NEW_MEMBUF: c_int = 41;
/// `OSSL_FUNC_BIO_READ_EX`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_READ_EX: c_int = 42;
/// `OSSL_FUNC_BIO_WRITE_EX`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_WRITE_EX: c_int = 43;
/// `OSSL_FUNC_BIO_UP_REF`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_UP_REF: c_int = 44;
/// `OSSL_FUNC_BIO_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_FREE: c_int = 45;
/// `OSSL_FUNC_BIO_VPRINTF`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_VPRINTF: c_int = 46;
/// `OSSL_FUNC_BIO_VSNPRINTF`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_VSNPRINTF: c_int = 47;
/// `OSSL_FUNC_BIO_PUTS`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_PUTS: c_int = 48;
/// `OSSL_FUNC_BIO_GETS`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_GETS: c_int = 49;
/// `OSSL_FUNC_BIO_CTRL`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_BIO_CTRL: c_int = 50;
/// `OSSL_FUNC_INDICATOR_CB`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_INDICATOR_CB: c_int = 95;
/// `OSSL_FUNC_SELF_TEST_CB`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_SELF_TEST_CB: c_int = 100;
/// `OSSL_FUNC_CORE_COUNT_TO_MARK`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_COUNT_TO_MARK: c_int = 120;
/// `OSSL_FUNC_CORE_OBJ_ADD_SIGID`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_OBJ_ADD_SIGID: c_int = 121;
/// `OSSL_FUNC_CORE_OBJ_CREATE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_OBJ_CREATE: c_int = 122;
/// `OSSL_FUNC_PROVIDER_NAME`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_NAME: c_int = 107;
/// `OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_GET0_PROVIDER_CTX: c_int = 108;
/// `OSSL_FUNC_PROVIDER_GET0_DISPATCH`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_GET0_DISPATCH: c_int = 109;
/// `OSSL_FUNC_CORE_THREAD_START`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_CORE_THREAD_START: c_int = 3;
/// `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_REGISTER_CHILD_CB: c_int = 105;
/// `OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_DEREGISTER_CHILD_CB: c_int = 106;
/// `OSSL_FUNC_PROVIDER_UP_REF`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_UP_REF: c_int = 110;
/// `OSSL_FUNC_PROVIDER_FREE`.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) const FUNC_PROVIDER_FREE: c_int = 111;

/// `OSSL_PROV_PARAM_CORE_VERSION` — `"openssl-version"`.
const PROV_PARAM_CORE_VERSION: *const c_char = c"openssl-version".as_ptr();
/// `OSSL_PROV_PARAM_CORE_PROV_NAME` — `"provider-name"`.
const PROV_PARAM_CORE_PROV_NAME: *const c_char = c"provider-name".as_ptr();
/// `OSSL_PROV_PARAM_CORE_MODULE_FILENAME` — `"module-filename"`.
const PROV_PARAM_CORE_MODULE_FILENAME: *const c_char = c"module-filename".as_ptr();

/// A descriptor of the three parameters `core_get_params` answers from the core.
///
/// `OSSL_PARAM_DEFN(key, type, addr, sz)` expands to a `data` of NULL and a `return_size` of
/// `OSSL_PARAM_UNMODIFIED`, which is what a *descriptor* carries: the caller supplies the
/// buffer, and this array only says what may be asked for.
const fn param_defn(key: *const c_char) -> OsslParam {
    OsslParam {
        key,
        data_type: OSSL_PARAM_UTF8_PTR,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `static const OSSL_PARAM param_types[]` — answered by `core_gettable_params`.
pub(crate) static PARAM_TYPES: ParamTypes = ParamTypes([
    param_defn(PROV_PARAM_CORE_VERSION),
    param_defn(PROV_PARAM_CORE_PROV_NAME),
    param_defn(PROV_PARAM_CORE_MODULE_FILENAME),
    // The authority's `OSSL_PARAM_END`.
    OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
]);

/// The descriptor array, in a wrapper that can carry a `Sync` claim.
///
/// `OsslParam` holds raw pointers, so `[OsslParam; 4]` is not `Sync` and cannot be a
/// `static` without one. The claim is true for *this* array and not for `OsslParam` in
/// general, which is why it is made on a wrapper here rather than as a blanket impl in
/// `src/params` — a blanket impl would be a claim about every descriptor in the crate.
pub(crate) struct ParamTypes(pub(crate) [OsslParam; 4]);

// SAFETY: every `key` in this array is a `'static` C-string literal, every `data` is NULL,
// and the array is never mutated. Nothing can reach it except through the `*const` the
// dispatch table publishes, and `OSSL_PARAM` descriptors are defined to be shared read-only
// (`OSSL_PARAM_DEFN` produces exactly this shape in C, where it is `const`).
unsafe impl Sync for ParamTypes {}

/// `static const OSSL_PARAM *core_gettable_params(const OSSL_CORE_HANDLE *handle)`.
///
/// The handle is ignored: the answer is the same three descriptors for every provider.
///
/// # Safety
/// None: `handle` is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_gettable_params(_handle: *const c_void) -> *const OsslParam {
    PARAM_TYPES.0.as_ptr()
}

/// `static int core_get_params(const OSSL_CORE_HANDLE *handle, OSSL_PARAM params[])`.
///
/// Three writes from the core and then the provider's own configuration parameters over the
/// same array, in that order — see the module doc for why the order matters.
///
/// # Safety
/// `handle` must be the `OSSL_PROVIDER *` this provider was created as, and `params` a
/// terminated array of writable descriptors.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_get_params(
    handle: *const c_void,
    params: *mut OsslParam,
) -> c_int {
    let prov = handle.cast::<OsslProvider>();
    // SAFETY: each `OSSL_PARAM_locate` call walks a terminated array and answers NULL when
    // the key is absent, so no dereference is unguarded; `prov` is the handle's own object.
    unsafe {
        let p = crate::params::OSSL_PARAM_locate(params, PROV_PARAM_CORE_VERSION);
        if !p.is_null() {
            crate::params::OSSL_PARAM_set_utf8_ptr(p, VERSION_STRING.as_ptr());
        }
        let p = crate::params::OSSL_PARAM_locate(params, PROV_PARAM_CORE_PROV_NAME);
        if !p.is_null() {
            crate::params::OSSL_PARAM_set_utf8_ptr(p, ossl_provider_name(prov));
        }
        let p = crate::params::OSSL_PARAM_locate(params, PROV_PARAM_CORE_MODULE_FILENAME);
        if !p.is_null() {
            crate::params::OSSL_PARAM_set_utf8_ptr(
                p,
                crate::provider::ossl_provider_module_path(prov),
            );
        }
        // Unconditional, and last: the provider's configuration parameters win over the
        // three above where a name collides.
        ossl_provider_get_conf_parameters(prov, params)
    }
}

/// `static int core_thread_start(const OSSL_CORE_HANDLE *handle,
/// OSSL_thread_stop_handler_fn handfn, void *arg)`.
///
/// The provider-facing spelling of `ossl_init_thread_start`: a provider that has per-thread
/// state asks the core to be told when that thread stops, and the core registers the
/// provider's own handler against the **handle**, which is the `OSSL_PROVIDER *` the loader
/// created. The authority's comment says exactly that, and it is why the cast is safe: the
/// handle a provider receives through `OSSL_provider_init` is the provider object.
///
/// Note the argument order. The dispatch entry is `(handle, handfn, arg)` and
/// `ossl_init_thread_start` is `(index, arg, handfn)` — the handler is the *third* parameter
/// there and the *second* here. Transposing them compiles, because both are pointer-sized,
/// and would register the argument as a function and call it at thread exit. That is why this
/// body is a named call rather than an inline cast.
///
/// 6.6e-ii, and the entry it publishes is id 3 in the 1024-series table.
pub(crate) unsafe extern "C" fn core_thread_start(
    handle: *const c_void,
    handfn: Option<crate::runtime::thread_events::ThreadStopHandlerFn>,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the handle is the `OSSL_PROVIDER *` the loader passed to `OSSL_provider_init`,
    // per the authority's own comment, and it is used only as an opaque deregistration key.
    unsafe { crate::runtime::thread_events::ossl_init_thread_start(handle, arg, handfn) }
}

/// `static OPENSSL_CORE_CTX *core_get_libctx(const OSSL_CORE_HANDLE *handle)`.
///
/// Reads `prov->libctx` **directly** rather than through `ossl_provider_libctx`, and the
/// authority says why: `ossl_provider_libctx` answers NULL for a NULL provider, and a NULL
/// library context has a special meaning that does not apply here — the authority's own
/// comment calls a NULL provider at this point a coding error.
///
/// # Safety
/// `handle` must be the `OSSL_PROVIDER *` this provider was created as.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_get_libctx(handle: *const c_void) -> *mut c_void {
    let prov = handle.cast::<OsslProvider>();
    // SAFETY: `prov` is the live provider the handle names.
    unsafe { (*prov).libctx }
}

/// `static void core_new_error(const OSSL_CORE_HANDLE *handle)`.
///
/// The handle is ignored: OpenSSL's error queue is thread-local and not per-provider, which
/// the authority's own comment says is a limitation rather than a design.
///
/// # Safety
/// None: the handle is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_new_error(_handle: *const c_void) {
    ERR_new();
}

/// `static void core_set_error_debug(const OSSL_CORE_HANDLE *handle, const char *file,
/// int line, const char *func)`.
///
/// # Safety
/// `file` and `func` must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_set_error_debug(
    _handle: *const c_void,
    file: *const c_char,
    line: c_int,
    func: *const c_char,
) {
    // SAFETY: both strings are NULL or NUL-terminated per the contract.
    unsafe { ERR_set_debug(file, line, func) };
}

/// `static void core_vset_error(const OSSL_CORE_HANDLE *handle, uint32_t reason,
/// const char *fmt, va_list args)`.
///
/// The provider may raise either an OpenSSL library error or its own: if the uppermost eight
/// bits of `reason` are non-zero it is a library error and the library and reason are taken
/// from it; otherwise it is a new-style provider error and the provider's own error library
/// number is used. `VERSION_STRING`'s sibling — the provider's `error_lib` — comes from
/// [`crate::provider::ossl_provider_new`], which assigned it from
/// `ERR_get_next_error_library`.
///
/// # Safety
/// `handle` must be the `OSSL_PROVIDER *` this provider was created as; `fmt` NUL-terminated
/// or NULL; `args` the `va_list` of the caller's own variadic function.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_vset_error(
    handle: *const c_void,
    reason: c_uint,
    fmt: *const c_char,
    args: *mut c_void,
) {
    let prov = handle.cast::<OsslProvider>();
    let lib = err_get_lib(reason);
    // SAFETY: `fmt`/`args` follow `ERR_vset_error`'s contract, and `prov` is live.
    unsafe {
        if lib != 0 {
            ERR_vset_error(lib, err_get_reason(reason), fmt, args);
        } else {
            ERR_vset_error((*prov).error_lib, reason as c_int, fmt, args);
        }
    }
}

/// `static int core_set_error_mark(const OSSL_CORE_HANDLE *handle)`.
///
/// # Safety
/// None: the handle is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_set_error_mark(_handle: *const c_void) -> c_int {
    ERR_set_mark()
}

/// `static int core_clear_last_error_mark(const OSSL_CORE_HANDLE *handle)`.
///
/// # Safety
/// None: the handle is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_clear_last_error_mark(_handle: *const c_void) -> c_int {
    ERR_clear_last_mark()
}

/// `static int core_pop_error_to_mark(const OSSL_CORE_HANDLE *handle)`.
///
/// # Safety
/// None: the handle is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_pop_error_to_mark(_handle: *const c_void) -> c_int {
    ERR_pop_to_mark()
}

/// `static int core_count_to_mark(const OSSL_CORE_HANDLE *handle)`.
///
/// # Safety
/// None: the handle is unused.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the table
pub(crate) unsafe extern "C" fn core_count_to_mark(_handle: *const c_void) -> c_int {
    ERR_count_to_mark()
}

/// `static void core_indicator_get_callback(OPENSSL_CORE_CTX *libctx,
/// OSSL_INDICATOR_CALLBACK **cb)`.
///
/// The first parameter is a **library context**, not a provider handle, which is the one
/// callback in the table whose first argument is not the handle: the callback is per-context,
/// and the provider is not part of the question.
///
/// # Safety
/// `ctx` must be the `OSSL_LIB_CTX *` this provider belongs to; `cb` NULL or writable for a
/// function pointer.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_indicator_get_callback(
    ctx: *mut c_void,
    cb: *mut *mut c_void,
) {
    // SAFETY: the cast is between two pointer-to-function-pointer representations, which
    // `OSSL_INDICATOR_get_callback` treats as opaque; `ctx` is the context per the contract.
    unsafe {
        crate::selftest::indicator::OSSL_INDICATOR_get_callback(
            ctx,
            cb.cast::<Option<crate::selftest::OsslIndicatorCallback>>(),
        )
    };
}

/// `static void core_self_test_get_callback(OPENSSL_CORE_CTX *libctx, OSSL_CALLBACK **cb,
/// void **cbarg)`.
///
/// Two outputs, not one: the self-test callback carries an argument with it, and both are
/// written from the same slot. A NULL `cb` or `cbarg` is skipped rather than refused.
///
/// # Safety
/// `ctx` must be the `OSSL_LIB_CTX *` this provider belongs to; `cb`/`cbarg` NULL or writable.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_self_test_get_callback(
    ctx: *mut c_void,
    cb: *mut *mut c_void,
    cbarg: *mut *mut c_void,
) {
    // SAFETY: as `core_indicator_get_callback`; `cbarg` is already the right shape.
    unsafe {
        crate::selftest::OSSL_SELF_TEST_get_callback(
            ctx,
            cb.cast::<Option<crate::selftest::OsslCallback>>(),
            cbarg,
        )
    };
}

/// `static int core_obj_add_sigid(const OSSL_CORE_HANDLE *prov, const char *sign_name,
/// const char *digest_name, const char *pkey_name)`.
///
/// Three names in, NIDs resolved by `OBJ_txt2nid`, and the digest is optional: a NULL or
/// **empty** digest name is allowed and becomes the undefined NID, but any *other*
/// unresolvable digest is a refusal. An existing triple is a **success without doing
/// anything**, which is why the presence check comes before the pkey check — the authority's
/// comment says so, and it is the difference between "already there" and "cannot be added".
///
/// # Safety
/// `prov` is accepted and unused; the three names must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_obj_add_sigid(
    _prov: *const c_void,
    sign_name: *const c_char,
    digest_name: *const c_char,
    pkey_name: *const c_char,
) -> c_int {
    const NID_UNDEF: c_int = 0;
    // SAFETY: `sign_name`/`pkey_name` are NULL or NUL-terminated; `OBJ_txt2nid` answers the
    // undefined NID for NULL.
    unsafe {
        let sign_nid = OBJ_txt2nid(sign_name);
        let pkey_nid = OBJ_txt2nid(pkey_name);
        let mut digest_nid = NID_UNDEF;
        if !digest_name.is_null() && *digest_name != 0 {
            digest_nid = OBJ_txt2nid(digest_name);
            if digest_nid == NID_UNDEF {
                return 0;
            }
        }
        if sign_nid == NID_UNDEF {
            return 0;
        }
        // Already present: a success, even though no NIDs were supplied for it.
        if OBJ_find_sigid_algs(sign_nid, ptr::null_mut(), ptr::null_mut()) != 0 {
            return 1;
        }
        if pkey_nid == NID_UNDEF {
            return 0;
        }
        OBJ_add_sigid(sign_nid, digest_nid, pkey_nid)
    }
}

/// `static int core_obj_create(const OSSL_CORE_HANDLE *prov, const char *oid,
/// const char *sn, const char *ln)`.
///
/// Create-if-absent, in one expression: an OID that already resolves answers 1 without
/// calling `OBJ_create`, and otherwise the answer is `OBJ_create`'s being not-undefined.
///
/// # Safety
/// `prov` is accepted and unused; the three names must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_obj_create(
    _prov: *const c_void,
    oid: *const c_char,
    sn: *const c_char,
    ln: *const c_char,
) -> c_int {
    const NID_UNDEF: c_int = 0;
    // SAFETY: all three names are NULL or NUL-terminated per the contract.
    unsafe {
        if OBJ_txt2nid(oid) != NID_UNDEF {
            return 1;
        }
        c_int::from(OBJ_create(oid, sn, ln) != NID_UNDEF)
    }
}

/// `static const char *core_provider_get0_name(const OSSL_CORE_HANDLE *prov)`.
///
/// # Safety
/// `prov` must be the `OSSL_PROVIDER *` the handle names.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_provider_get0_name(prov: *const c_void) -> *const c_char {
    // SAFETY: `prov` is the live provider the handle names.
    unsafe { ossl_provider_name(prov.cast::<OsslProvider>()) }
}

/// `static void *core_provider_get0_provider_ctx(const OSSL_CORE_HANDLE *prov)`.
///
/// # Safety
/// `prov` must be the `OSSL_PROVIDER *` the handle names.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_provider_get0_provider_ctx(
    prov: *const c_void,
) -> *mut c_void {
    // SAFETY: `prov` is the live provider the handle names.
    unsafe { ossl_provider_ctx(prov.cast::<OsslProvider>()) }
}

/// `static const OSSL_DISPATCH *core_provider_get0_dispatch(const OSSL_CORE_HANDLE *prov)`.
///
/// # Safety
/// `prov` must be the `OSSL_PROVIDER *` the handle names.
#[allow(dead_code)] // unreachable until 6.8b-iii publishes the dispatch table
pub(crate) unsafe extern "C" fn core_provider_get0_dispatch(
    prov: *const c_void,
) -> *const crate::context::dispatch::OsslDispatch {
    // SAFETY: `prov` is the live provider the handle names.
    unsafe { ossl_provider_get0_dispatch(prov.cast::<OsslProvider>()) }
}

extern "C" {
    /// `void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)`.
    ///
    /// Defined in `src/runtime/err_variadic.c`, where the `va_arg` walk has to live: a
    /// C-variadic function cannot be defined in stable Rust. A `va_list` is opaque here in
    /// both directions, which is how every `va_list` boundary in this crate is declared.
    fn ERR_vset_error(lib: c_int, reason: c_int, fmt: *const c_char, args: *mut c_void);
}

/// The `OSSL_DISPATCH_END` terminator's `function_id`.
#[allow(dead_code)] // unreachable until 6.8c publishes it through `get0_dispatch`
const DISPATCH_END: c_int = 0;

/// One entry of the core dispatch table.
#[allow(dead_code)] // the table below is its only user, and nothing reads that until 6.8c
const fn e(function_id: c_int, function: *mut c_void) -> OsslDispatch {
    OsslDispatch {
        function_id,
        function,
    }
}

/// `static const OSSL_DISPATCH core_dispatch_[]` — the core's half of the provider ABI.
///
/// Assembled **only from entries whose function exists**, in the authority's order, with the
/// absent ids named in the module doc. A provider that asks for an absent id is answered NULL,
/// which is the same answer it would get from an older build — so the gap is visible to a
/// provider rather than hidden behind a stub.
///
/// Three groups are absent and each for its own reason: `CORE_THREAD_START` (6.6e-ii), the
/// eight `rand_*` callbacks (Phase 9), and the two child-callback and two provider-accessor
/// pairs (6.8e and 6.8c). The module doc's table is the record, and the test below asserts the
/// published set so that adding an entry or dropping one cannot happen quietly.
// SAFETY: every `function` here is a `'static` function item or a `'static` function in
// another module of this crate, and every `function_id` is a compile-time constant. The array
// is never mutated. Nothing is ever written through the pointers it publishes except by a
// provider calling the function whose signature that entry declares.
unsafe impl Sync for CoreDispatchTable {}

/// A wrapper carrying the table's `Sync` claim.
#[allow(dead_code)] // unreachable until 6.8c publishes it through `get0_dispatch`
pub(crate) struct CoreDispatchTable(pub(crate) [OsslDispatch; 42]);

/// The table itself.
#[allow(dead_code)] // unreachable until 6.8c publishes it through `get0_dispatch`
pub(crate) static CORE_DISPATCH: CoreDispatchTable = CoreDispatchTable([
    e(
        FUNC_CORE_GETTABLE_PARAMS,
        core_gettable_params as *mut c_void,
    ),
    e(FUNC_CORE_GET_PARAMS, core_get_params as *mut c_void),
    e(FUNC_CORE_GET_LIBCTX, core_get_libctx as *mut c_void),
    e(FUNC_CORE_THREAD_START, core_thread_start as *mut c_void),
    e(FUNC_CORE_NEW_ERROR, core_new_error as *mut c_void),
    e(
        FUNC_CORE_SET_ERROR_DEBUG,
        core_set_error_debug as *mut c_void,
    ),
    e(FUNC_CORE_VSET_ERROR, core_vset_error as *mut c_void),
    e(FUNC_CORE_SET_ERROR_MARK, core_set_error_mark as *mut c_void),
    e(
        FUNC_CORE_CLEAR_LAST_ERROR_MARK,
        core_clear_last_error_mark as *mut c_void,
    ),
    e(
        FUNC_CORE_POP_ERROR_TO_MARK,
        core_pop_error_to_mark as *mut c_void,
    ),
    e(FUNC_CORE_COUNT_TO_MARK, core_count_to_mark as *mut c_void),
    e(
        FUNC_BIO_NEW_FILE,
        crate::runtime::bio::core_bio::ossl_core_bio_new_file as *mut c_void,
    ),
    e(
        FUNC_BIO_NEW_MEMBUF,
        crate::runtime::bio::core_bio::ossl_core_bio_new_mem_buf as *mut c_void,
    ),
    e(
        FUNC_BIO_READ_EX,
        crate::runtime::bio::core_bio::ossl_core_bio_read_ex as *mut c_void,
    ),
    e(
        FUNC_BIO_WRITE_EX,
        crate::runtime::bio::core_bio::ossl_core_bio_write_ex as *mut c_void,
    ),
    e(
        FUNC_BIO_UP_REF,
        crate::runtime::bio::core_bio::ossl_core_bio_up_ref as *mut c_void,
    ),
    e(
        FUNC_BIO_FREE,
        crate::runtime::bio::core_bio::ossl_core_bio_free as *mut c_void,
    ),
    e(
        FUNC_BIO_VPRINTF,
        crate::runtime::bio::core_bio::ossl_core_bio_vprintf as *mut c_void,
    ),
    e(FUNC_BIO_VSNPRINTF, BIO_vsnprintf as *mut c_void),
    e(
        FUNC_BIO_PUTS,
        crate::runtime::bio::core_bio::ossl_core_bio_puts as *mut c_void,
    ),
    e(
        FUNC_BIO_GETS,
        crate::runtime::bio::core_bio::ossl_core_bio_gets as *mut c_void,
    ),
    e(
        FUNC_BIO_CTRL,
        crate::runtime::bio::core_bio::ossl_core_bio_ctrl as *mut c_void,
    ),
    e(
        FUNC_INDICATOR_CB,
        core_indicator_get_callback as *mut c_void,
    ),
    e(
        FUNC_SELF_TEST_CB,
        core_self_test_get_callback as *mut c_void,
    ),
    // 96-104: the eight `rand_*` callbacks — absent, Phase 9.
    // 105, 106: the child-callback pair — absent, 6.8e.
    e(FUNC_PROVIDER_NAME, core_provider_get0_name as *mut c_void),
    e(
        FUNC_PROVIDER_GET0_PROVIDER_CTX,
        core_provider_get0_provider_ctx as *mut c_void,
    ),
    e(
        FUNC_PROVIDER_GET0_DISPATCH,
        core_provider_get0_dispatch as *mut c_void,
    ),
    // 110, 111: `PROVIDER_UP_REF` and `PROVIDER_FREE` — absent, 6.8c.
    e(FUNC_CORE_OBJ_ADD_SIGID, core_obj_add_sigid as *mut c_void),
    e(FUNC_CORE_OBJ_CREATE, core_obj_create as *mut c_void),
    e(FUNC_CRYPTO_MALLOC, CRYPTO_malloc as *mut c_void),
    e(FUNC_CRYPTO_ZALLOC, CRYPTO_zalloc as *mut c_void),
    e(FUNC_CRYPTO_FREE, CRYPTO_free as *mut c_void),
    e(FUNC_CRYPTO_CLEAR_FREE, CRYPTO_clear_free as *mut c_void),
    e(FUNC_CRYPTO_REALLOC, CRYPTO_realloc as *mut c_void),
    e(
        FUNC_CRYPTO_CLEAR_REALLOC,
        CRYPTO_clear_realloc as *mut c_void,
    ),
    e(
        FUNC_CRYPTO_SECURE_MALLOC,
        CRYPTO_secure_malloc as *mut c_void,
    ),
    e(
        FUNC_CRYPTO_SECURE_ZALLOC,
        CRYPTO_secure_zalloc as *mut c_void,
    ),
    e(FUNC_CRYPTO_SECURE_FREE, CRYPTO_secure_free as *mut c_void),
    e(
        FUNC_CRYPTO_SECURE_CLEAR_FREE,
        CRYPTO_secure_clear_free as *mut c_void,
    ),
    e(
        FUNC_CRYPTO_SECURE_ALLOCATED,
        CRYPTO_secure_allocated as *mut c_void,
    ),
    e(FUNC_OPENSSL_CLEANSE, OPENSSL_cleanse as *mut c_void),
    OsslDispatch {
        function_id: DISPATCH_END,
        function: ptr::null_mut(),
    },
]);

#[cfg(test)]
mod tests {
    //! The parameter descriptors, the error-library split, and the ids themselves.
    //!
    //! The dispatch *table* is not assembled yet, so what these tests can establish is the
    //! callbacks' own arithmetic: which library a provider error is attributed to, and what
    //! the descriptor array says a caller may ask for.

    use super::*;

    #[test]
    fn the_descriptor_array_names_the_three_core_parameters_and_terminates() {
        assert_eq!(PARAM_TYPES.0.len(), 4);
        let keys: &[&core::ffi::CStr] = &[c"openssl-version", c"provider-name", c"module-filename"];
        for (i, want) in keys.iter().enumerate() {
            // SAFETY: `PARAM_TYPES.0[i].key` is a `'static` literal with a terminator.
            let got = unsafe { core::ffi::CStr::from_ptr(PARAM_TYPES.0[i].key) };
            assert_eq!(got.to_bytes(), want.to_bytes(), "descriptor {i}");
            assert_eq!(PARAM_TYPES.0[i].data_type, OSSL_PARAM_UTF8_PTR);
            // A descriptor carries no buffer and claims nothing has been written.
            assert!(PARAM_TYPES.0[i].data.is_null());
            assert_eq!(PARAM_TYPES.0[i].data_size, 0);
            assert_eq!(PARAM_TYPES.0[i].return_size, OSSL_PARAM_UNMODIFIED);
        }
        // The terminator has a NULL key and a zero type.
        assert!(PARAM_TYPES.0[3].key.is_null());
        assert_eq!(PARAM_TYPES.0[3].data_type, 0);
    }

    #[test]
    fn gettable_params_answers_the_static_array_for_any_handle() {
        // SAFETY: the function ignores its argument, so any handle is acceptable -- which is
        // asserted by passing two different ones and requiring the same answer back.
        let p = unsafe { core_gettable_params(ptr::null()) };
        // SAFETY: as above.
        let p2 = unsafe { core_gettable_params(ptr::null::<c_void>()) };
        assert_eq!(
            p,
            PARAM_TYPES.0.as_ptr(),
            "the answer is the static's address"
        );
        assert!(p == p2, "and the same address however it is asked");
    }

    #[test]
    fn an_error_code_splits_into_a_library_and_a_reason() {
        // A library error: `ERR_LIB_CRYPTO` is 15, so the packed code has 15 in the top eight
        // bits and the reason in the low 23.
        let lib = 15u32;
        let reason = 0x1234u32;
        let packed = (lib << ERR_LIB_OFFSET) | reason;
        assert_eq!(err_get_lib(packed), 15);
        assert_eq!(err_get_reason(packed), 0x1234);
        // A provider error has a zero library, which is what `core_vset_error` tests for.
        let prov_reason = 7u32;
        assert_eq!(err_get_lib(prov_reason), 0);
        assert_eq!(err_get_reason(prov_reason), 7);
        // The library field is eight bits wide, so a code with bit 31 set still yields a
        // library rather than a negative number.
        assert_eq!(err_get_lib(0xFFFF_FFFF), 0xFF);
        assert_eq!(err_get_reason(0xFFFF_FFFF), ERR_REASON_MASK as c_int);
    }

    #[test]
    fn the_published_ids_are_the_headers_numbers_and_are_distinct() {
        // These are the numbers a provider compiled against another 3.x will look up, so a
        // transcription slip would be silent: the provider would find a different function
        // than it asked for. The values are asserted rather than merely used.
        let table: &[(c_int, &str)] = &[
            (FUNC_CORE_GETTABLE_PARAMS, "CORE_GETTABLE_PARAMS"),
            (FUNC_CORE_GET_PARAMS, "CORE_GET_PARAMS"),
            (FUNC_CORE_GET_LIBCTX, "CORE_GET_LIBCTX"),
            (FUNC_CORE_NEW_ERROR, "CORE_NEW_ERROR"),
            (FUNC_CORE_SET_ERROR_DEBUG, "CORE_SET_ERROR_DEBUG"),
            (FUNC_CORE_VSET_ERROR, "CORE_VSET_ERROR"),
            (FUNC_CORE_SET_ERROR_MARK, "CORE_SET_ERROR_MARK"),
            (
                FUNC_CORE_CLEAR_LAST_ERROR_MARK,
                "CORE_CLEAR_LAST_ERROR_MARK",
            ),
            (FUNC_CORE_POP_ERROR_TO_MARK, "CORE_POP_ERROR_TO_MARK"),
            (FUNC_CRYPTO_MALLOC, "CRYPTO_MALLOC"),
            (FUNC_CRYPTO_ZALLOC, "CRYPTO_ZALLOC"),
            (FUNC_CRYPTO_FREE, "CRYPTO_FREE"),
            (FUNC_CRYPTO_CLEAR_FREE, "CRYPTO_CLEAR_FREE"),
            (FUNC_CRYPTO_REALLOC, "CRYPTO_REALLOC"),
            (FUNC_CRYPTO_CLEAR_REALLOC, "CRYPTO_CLEAR_REALLOC"),
            (FUNC_CRYPTO_SECURE_MALLOC, "CRYPTO_SECURE_MALLOC"),
            (FUNC_CRYPTO_SECURE_ZALLOC, "CRYPTO_SECURE_ZALLOC"),
            (FUNC_CRYPTO_SECURE_FREE, "CRYPTO_SECURE_FREE"),
            (FUNC_CRYPTO_SECURE_CLEAR_FREE, "CRYPTO_SECURE_CLEAR_FREE"),
            (FUNC_CRYPTO_SECURE_ALLOCATED, "CRYPTO_SECURE_ALLOCATED"),
            (FUNC_OPENSSL_CLEANSE, "OPENSSL_CLEANSE"),
            (FUNC_BIO_NEW_FILE, "BIO_NEW_FILE"),
            (FUNC_BIO_NEW_MEMBUF, "BIO_NEW_MEMBUF"),
            (FUNC_BIO_READ_EX, "BIO_READ_EX"),
            (FUNC_BIO_WRITE_EX, "BIO_WRITE_EX"),
            (FUNC_BIO_UP_REF, "BIO_UP_REF"),
            (FUNC_BIO_FREE, "BIO_FREE"),
            (FUNC_BIO_VPRINTF, "BIO_VPRINTF"),
            (FUNC_BIO_VSNPRINTF, "BIO_VSNPRINTF"),
            (FUNC_BIO_PUTS, "BIO_PUTS"),
            (FUNC_BIO_GETS, "BIO_GETS"),
            (FUNC_BIO_CTRL, "BIO_CTRL"),
            (FUNC_INDICATOR_CB, "INDICATOR_CB"),
            (FUNC_SELF_TEST_CB, "SELF_TEST_CB"),
            (FUNC_CORE_COUNT_TO_MARK, "CORE_COUNT_TO_MARK"),
            (FUNC_CORE_OBJ_ADD_SIGID, "CORE_OBJ_ADD_SIGID"),
            (FUNC_CORE_OBJ_CREATE, "CORE_OBJ_CREATE"),
        ];
        // Distinct: two ids mapping to one function would make one of them unreachable.
        for i in 0..table.len() {
            for j in (i + 1)..table.len() {
                assert_ne!(
                    table[i].0, table[j].0,
                    "{} and {} share an id",
                    table[i].1, table[j].1
                );
            }
        }
        // Spot checks against the header, including the two that are far from their
        // neighbours and would be easy to mistype.
        assert_eq!(FUNC_CORE_GETTABLE_PARAMS, 1);
        assert_eq!(FUNC_BIO_NEW_FILE, 40);
        assert_eq!(FUNC_INDICATOR_CB, 95);
        assert_eq!(FUNC_SELF_TEST_CB, 100);
        assert_eq!(FUNC_CORE_COUNT_TO_MARK, 120);
        assert_eq!(FUNC_CORE_OBJ_CREATE, 122);
        // Each family is contiguous in the header, and a gap is the failure worth catching:
        // a mistyped id would silently hand a provider a different function than it asked
        // for. The BIO family runs 40..50 and the CRYPTO family 20..31, which the constants
        // above are checked against here.
        let bio_run = [
            FUNC_BIO_NEW_FILE,
            FUNC_BIO_NEW_MEMBUF,
            FUNC_BIO_READ_EX,
            FUNC_BIO_WRITE_EX,
            FUNC_BIO_UP_REF,
            FUNC_BIO_FREE,
            FUNC_BIO_VPRINTF,
            FUNC_BIO_VSNPRINTF,
            FUNC_BIO_PUTS,
            FUNC_BIO_GETS,
            FUNC_BIO_CTRL,
        ];
        for (k, id) in bio_run.iter().enumerate() {
            assert_eq!(*id, FUNC_BIO_NEW_FILE + k as c_int, "BIO id at offset {k}");
        }
        let crypto_run = [
            FUNC_CRYPTO_MALLOC,
            FUNC_CRYPTO_ZALLOC,
            FUNC_CRYPTO_FREE,
            FUNC_CRYPTO_CLEAR_FREE,
            FUNC_CRYPTO_REALLOC,
            FUNC_CRYPTO_CLEAR_REALLOC,
            FUNC_CRYPTO_SECURE_MALLOC,
            FUNC_CRYPTO_SECURE_ZALLOC,
            FUNC_CRYPTO_SECURE_FREE,
            FUNC_CRYPTO_SECURE_CLEAR_FREE,
            FUNC_CRYPTO_SECURE_ALLOCATED,
            FUNC_OPENSSL_CLEANSE,
        ];
        for (k, id) in crypto_run.iter().enumerate() {
            assert_eq!(
                *id,
                FUNC_CRYPTO_MALLOC + k as c_int,
                "CRYPTO id at offset {k}"
            );
        }
    }
    #[test]
    fn the_table_publishes_exactly_the_ids_whose_functions_exist() {
        // The published set, and the absent set, are both asserted. A provider compiled
        // against another 3.x looks up the ids it knows and is answered NULL for the ones
        // this build does not publish, so **which ids are absent is a compatibility fact**,
        // not an internal detail -- and one that would otherwise be invisible, because a
        // missing entry and a wrongly-typed entry both produce a provider that misbehaves
        // rather than a build failure.
        let published: &[c_int] = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 120, // the core, error, thread and mark group
            20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, // CRYPTO_* and OPENSSL_cleanse
            40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, // the BIO group
            95, 100, // the indicator and self-test callbacks
            107, 108, 109, // the three provider accessors
            121, 122, // the two object callbacks
        ];
        // The terminator is not an id; it ends the walk.
        assert_eq!(CORE_DISPATCH.0.len(), published.len() + 1);
        assert_eq!(CORE_DISPATCH.0[published.len()].function_id, DISPATCH_END);
        assert!(
            CORE_DISPATCH.0[published.len()].function.is_null(),
            "the terminator publishes no function"
        );
        let mut seen = [0usize; 200];
        for entry in CORE_DISPATCH.0.iter().take(published.len()) {
            assert!(
                !entry.function.is_null(),
                "id {} publishes a function",
                entry.function_id
            );
            assert!(
                published.contains(&entry.function_id),
                "id {} is published but not in the expected set",
                entry.function_id
            );
            let idx = entry.function_id as usize;
            assert!(idx < seen.len(), "id {idx} is outside the checked range");
            seen[idx] += 1;
            assert_eq!(seen[idx], 1, "id {idx} appears twice");
        }
        for id in published {
            assert_eq!(
                seen[*id as usize], 1,
                "id {id} is expected but {} times present",
                seen[*id as usize]
            );
        }
        // Every other id below 200 must be absent, and these are the ones that are absent on
        // purpose: 96-106 needs Phase 9 and 6.8e, and
        // 110/111 need 6.8c's activate. A test that only listed the published set would let
        // an id be *added* without anyone deciding it was ready.
        for id in 0..200i32 {
            if published.contains(&id) {
                continue;
            }
            assert_eq!(
                seen[id as usize], 0,
                "id {id} is published but is not in the expected set"
            );
        }
    }

    #[test]
    fn the_absent_ids_are_the_ones_the_module_doc_names() {
        // The doc table and the code cannot drift: each named absence is checked against the
        // table. `CORE_THREAD_START` left this list when 6.6e-ii landed
        // `ossl_init_thread_start`, and its entry is now published as id 3, so the remaining
        // names are the eight `rand_*` ids, which are Phase 9's, the
        // child-callback pair is 6.8e's and the two provider refcount entries are 6.8c's.
        let absent: &[(c_int, &str)] = &[
            (96, "CLEANUP_USER_ENTROPY -- Phase 9"),
            (97, "CLEANUP_USER_NONCE -- Phase 9"),
            (98, "GET_USER_ENTROPY -- Phase 9"),
            (99, "GET_USER_NONCE -- Phase 9"),
            (101, "GET_ENTROPY -- Phase 9"),
            (102, "CLEANUP_ENTROPY -- Phase 9"),
            (103, "GET_NONCE -- Phase 9"),
            (104, "CLEANUP_NONCE -- Phase 9"),
            (105, "PROVIDER_REGISTER_CHILD_CB -- 6.8e"),
            (106, "PROVIDER_DEREGISTER_CHILD_CB -- 6.8e"),
            (110, "PROVIDER_UP_REF -- 6.8c"),
            (111, "PROVIDER_FREE -- 6.8c"),
        ];
        for (id, why) in absent {
            for entry in CORE_DISPATCH.0.iter() {
                assert_ne!(
                    entry.function_id, *id,
                    "id {id} is recorded absent ({why}) but the table publishes it"
                );
            }
        }
        // And the named constants exist with the header's values, so the doc's numbers are
        // checked rather than prose.
        assert_eq!(FUNC_CORE_THREAD_START, 3);
        assert_eq!(FUNC_PROVIDER_REGISTER_CHILD_CB, 105);
        assert_eq!(FUNC_PROVIDER_DEREGISTER_CHILD_CB, 106);
        assert_eq!(FUNC_PROVIDER_UP_REF, 110);
        assert_eq!(FUNC_PROVIDER_FREE, 111);
        assert_eq!(FUNC_PROVIDER_NAME, 107);
        assert_eq!(FUNC_PROVIDER_GET0_PROVIDER_CTX, 108);
        assert_eq!(FUNC_PROVIDER_GET0_DISPATCH, 109);
        // The two ids the doc used to state wrongly: the "new seeding" series is 96-99 and
        // the original series is 101-104, so the absent run is 96..106 with a hole at 100
        // where `SELF_TEST_CB` sits -- which is published.
        assert_eq!(FUNC_SELF_TEST_CB, 100);
        assert_eq!(FUNC_INDICATOR_CB, 95);
    }
}
