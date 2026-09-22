//! Phase 8 — the default provider's `OSSL_OP_SKEYMGMT` rows, and the algorithm units behind them.
//!
//! Two registration rows of `providers/defltprov.c`'s `deflt_skeymgmt[]` are published here, in the
//! authority's order: `AES` (with its OID alias `2.16.840.1.101.3.4.1`), whose unit is
//! `providers/implementations/skeymgmt/aes_skmgmt.c`; and `GENERIC-SECRET`, whose unit is
//! `providers/implementations/skeymgmt/generic.c`. Each unit is transcribed **whole** (D327's
//! rule).
//!
//! ## The two units, and why the AES one is four functions
//!
//! `generic.c` is the base: `generic_import` decodes a `raw-bytes` record into a freshly allocated
//! `PROV_SKEY`, `generic_free` releases it, `generic_export` hands the bytes back through the
//! caller's `OSSL_CALLBACK`, and `generic_imp_settable_params` publishes the one-key import list.
//! `aes_skmgmt.c` is a **subclass** built on those four: its `aes_import` calls `generic_import` and
//! then refuses any key whose length is not 16, 24 or 32, stamping `SKEY_TYPE_AES`; its `aes_export`
//! refuses a keydata that is not already stamped `SKEY_TYPE_AES` and otherwise defers to
//! `generic_export`. The two dispatch tables therefore differ in exactly the two slots, and the
//! free/settable slots are the *same function pointers*.
//!
//! ## The one raise, and where it comes from
//!
//! `generic.c` raises once, in the generated import decoder: a second `raw-bytes` record is
//! `PROV_R_REPEATED_PARAMETER`. `aes_skmgmt.c` raises nothing at all — every refusal in it is a
//! bare `return NULL`/`return 0` — so it is deliberately absent from `gen_err_raise_sites.py`, the
//! same way `mdc2_prov.c` and `rsa_meth.c` are.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::skeymgmt::{
    OSSL_FUNC_SKEYMGMT_EXPORT, OSSL_FUNC_SKEYMGMT_FREE, OSSL_FUNC_SKEYMGMT_IMPORT,
    OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam, END,
    OSSL_PARAM_OCTET_STRING,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::param_octet_string;
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc};
use crate::selftest::OsslCallback;

/// `FILE_GENERIC_SKEYMGMT` — the generated unit's own `__FILE__`.
const FILE_GENERIC_SKEYMGMT: *const c_char =
    c"providers/implementations/skeymgmt/generic.c".as_ptr();

/// `OSSL_SKEY_PARAM_RAW_BYTES` — `include/openssl/core_names.h:572`.
const OSSL_SKEY_PARAM_RAW_BYTES: *const c_char = c"raw-bytes".as_ptr();

/// `OSSL_SKEYMGMT_SELECT_SECRET_KEY` — `include/openssl/core_dispatch.h:472`.
const OSSL_SKEYMGMT_SELECT_SECRET_KEY: c_int = 0x02;

/// `SKEY_TYPE_GENERIC` — `include/internal/skey.h:14`.
const SKEY_TYPE_GENERIC: c_int = 1;

/// `SKEY_TYPE_AES` — `include/internal/skey.h:15`.
const SKEY_TYPE_AES: c_int = 2;

/// `struct prov_skey_st` — `include/internal/skey.h:17-31`. A symmetric key is a byte buffer, its
/// length, the library context it was imported in, and the type that says what it is for.
#[repr(C)]
pub(crate) struct ProvSkey {
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `int type` — `SKEY_TYPE_GENERIC` or `SKEY_TYPE_AES`.
    pub type_: c_int,
    /// `unsigned char *data` / `size_t length`.
    pub data: *mut u8,
    pub length: usize,
}

/// `SKEYMGMT` rows live in the default provider, which is always in a happy state on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static const OSSL_PARAM generic_skey_import_list[]` — `generic.c:37-40`.
static GENERIC_SKEY_IMPORT_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SKEY_PARAM_RAW_BYTES), END];

/// `static int generic_skey_import_decoder(const OSSL_PARAM *p, struct generic_skey_import_st *r)` —
/// `generic.c:48-67`. One key, and a second occurrence of it is `PROV_R_REPEATED_PARAMETER` at
/// `:63`. It returns the single field rather than filling a struct, because the struct has one.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn generic_skey_import_decode(params: *const OsslParam) -> Result<*const OsslParam, ()> {
    let mut raw_bytes: *const OsslParam = ptr::null();
    if params.is_null() {
        return Ok(raw_bytes);
    }
    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            if CStr::from_ptr((*p).key).to_bytes()
                == CStr::from_ptr(OSSL_SKEY_PARAM_RAW_BYTES).to_bytes()
            {
                if !raw_bytes.is_null() {
                    raise_site(&err_sites::PROV_GENERIC_SKEYMGMT_63);
                    return Err(());
                }
                raw_bytes = p;
            }
            p = p.add(1);
        }
    }
    Ok(raw_bytes)
}

/// `void generic_free(void *keydata)` — `generic.c:25-34`.
///
/// # Safety
/// `keydata` is NULL or a `PROV_SKEY` this module allocated.
pub(crate) unsafe extern "C" fn generic_free(keydata: *mut c_void) {
    // SAFETY: `keydata` is NULL or a live key per the contract.
    unsafe {
        let generic = keydata.cast::<ProvSkey>();

        if generic.is_null() {
            return;
        }

        CRYPTO_clear_free(
            (*generic).data.cast(),
            (*generic).length,
            FILE_GENERIC_SKEYMGMT,
            0,
        );
        CRYPTO_free(generic.cast(), FILE_GENERIC_SKEYMGMT, 0);
    }
}

/// `void *generic_import(void *provctx, int selection, const OSSL_PARAM params[])` — `generic.c:70-115`.
/// The `goto end` is a labelled block whose single exit releases the half-built key when `ok` is 0.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn generic_import(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let libctx = prov_libctx_of(provctx);
        let mut ok = 0;

        if is_running() == 0 {
            return ptr::null_mut();
        }

        if (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0 {
            return ptr::null_mut();
        }

        let raw_bytes = match generic_skey_import_decode(params) {
            Ok(r) => r,
            Err(()) => return ptr::null_mut(),
        };

        if raw_bytes.is_null() || (*raw_bytes).data_type != OSSL_PARAM_OCTET_STRING {
            return ptr::null_mut();
        }

        let mut generic = CRYPTO_zalloc(core::mem::size_of::<ProvSkey>(), FILE_GENERIC_SKEYMGMT, 0)
            .cast::<ProvSkey>();
        if generic.is_null() {
            return ptr::null_mut();
        }

        (*generic).libctx = libctx;

        (*generic).type_ = SKEY_TYPE_GENERIC;

        'end: {
            (*generic).data = CRYPTO_memdup(
                (*raw_bytes).data,
                (*raw_bytes).data_size,
                FILE_GENERIC_SKEYMGMT,
                0,
            )
            .cast::<u8>();
            if (*generic).data.is_null() {
                break 'end;
            }
            (*generic).length = (*raw_bytes).data_size;
            ok = 1;
        }

        if ok == 0 {
            generic_free(generic.cast());
            generic = ptr::null_mut();
        }
        generic.cast()
    }
}

/// `const OSSL_PARAM *generic_imp_settable_params(void *provctx)` — `generic.c:117-120`.
///
/// # Safety
/// The dispatch contract; `provctx` is unused.
pub(crate) unsafe extern "C" fn generic_imp_settable_params(
    _provctx: *mut c_void,
) -> *const OsslParam {
    GENERIC_SKEY_IMPORT_LIST.as_ptr()
}

/// `int generic_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void *cbarg)` —
/// `generic.c:122-145`. The bytes leave through the caller's callback, which is the whole reason
/// `export` returns a status rather than a buffer.
///
/// # Safety
/// The dispatch contract.
pub(crate) unsafe extern "C" fn generic_export(
    keydata: *mut c_void,
    selection: c_int,
    param_callback: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let gen = keydata.cast::<ProvSkey>();

        if is_running() == 0 || gen.is_null() {
            return 0;
        }

        /* If we use generic SKEYMGMT as a "base class", we shouldn't check the type */
        if (selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY) == 0 {
            return 0;
        }

        let mut params = [END, END];
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SKEY_PARAM_RAW_BYTES,
            (*gen).data.cast(),
            (*gen).length,
        );
        params[1] = OSSL_PARAM_construct_end();

        match param_callback {
            Some(cb) => cb(params.as_ptr(), cbarg),
            None => 0,
        }
    }
}

/// `static void *aes_import(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `aes_skmgmt.c:20-35`. The generic import, then the AES length rule, then the type stamp.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_import(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let aes = generic_import(provctx, selection, params).cast::<ProvSkey>();

        if aes.is_null() {
            return ptr::null_mut();
        }

        if (*aes).length != 16 && (*aes).length != 24 && (*aes).length != 32 {
            generic_free(aes.cast());
            return ptr::null_mut();
        }
        (*aes).type_ = SKEY_TYPE_AES;

        aes.cast()
    }
}

/// `static int aes_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void
/// *cbarg)` — `aes_skmgmt.c:37-46`. A keydata that is not stamped `SKEY_TYPE_AES` is refused
/// outright rather than exported as generic bytes.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn aes_export(
    keydata: *mut c_void,
    selection: c_int,
    param_callback: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let aes = keydata.cast::<ProvSkey>();

        if aes.is_null() || (*aes).type_ != SKEY_TYPE_AES {
            return 0;
        }

        generic_export(keydata, selection, param_callback, cbarg)
    }
}

/// `const OSSL_DISPATCH ossl_generic_skeymgmt_functions[]` — `generic.c:147-155`.
pub(crate) static GENERIC_SKEYMGMT_FUNCTIONS: [OsslDispatch; 5] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_FREE,
        function: generic_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_IMPORT,
        function: generic_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_EXPORT,
        function: generic_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
        function: generic_imp_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_aes_skeymgmt_functions[]` — `aes_skmgmt.c:48-57`. The free and
/// settable slots are `generic.c`'s own function pointers; only the import and export slots differ.
pub(crate) static AES_SKEYMGMT_FUNCTIONS: [OsslDispatch; 5] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_FREE,
        function: generic_free as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_IMPORT,
        function: aes_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_EXPORT,
        function: aes_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
        function: generic_imp_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_skeymgmt[]` — `providers/defltprov.c:667-673`, in the
/// authority's order: `AES` first, `GENERIC-SECRET` second.
///
/// **The property definition is `"provider=default"` on both rows**, which is `defltprov.c`'s `ALG`
/// macro (D247).
pub(crate) static DEFLT_SKEYMGMT: [OsslAlgorithm; 3] = [
    OsslAlgorithm {
        // `PROV_NAMES_AES` — the OID alias is part of the row.
        algorithm_names: c"AES:2.16.840.1.101.3.4.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: AES_SKEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_GENERIC` — the primary name alone.
        algorithm_names: c"GENERIC-SECRET".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: GENERIC_SKEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
