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
//! | `OSSL_FUNC_GET_ENTROPY` (104) … `CLEANUP_USER_NONCE` (112) | the nine `rand_*` callbacks | **Phase 9** — they wrap `ossl_rand_get_entropy` and friends |
//! | `OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB` (102), `DEREGISTER_CHILD_CB` (103) | the child callback pair | **6.8e** |
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

use crate::params::{OsslParam, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UTF8_PTR};
use crate::provider::{ossl_provider_get_conf_parameters, ossl_provider_name, OsslProvider};
use crate::runtime::err::{
    ERR_clear_last_mark, ERR_count_to_mark, ERR_new, ERR_pop_to_mark, ERR_set_debug, ERR_set_mark,
};
use crate::runtime::init::VERSION_STRING;

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

extern "C" {
    /// `void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)`.
    ///
    /// Defined in `src/runtime/err_variadic.c`, where the `va_arg` walk has to live: a
    /// C-variadic function cannot be defined in stable Rust. A `va_list` is opaque here in
    /// both directions, which is how every `va_list` boundary in this crate is declared.
    fn ERR_vset_error(lib: c_int, reason: c_int, fmt: *const c_char, args: *mut c_void);
}

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
}
