//! `crypto/store/store_result.c` — the provider object-abstraction result handler that
//! [`crate::store::store_lib::OSSL_STORE_load`] hands to a fetched loader's `load`. Phase 10
//! (10.5), the unit 10.16 named as the engine's remaining result path.
//!
//! The authority unit is 667 lines and **no export**: its one externally-named entry,
//! `ossl_store_handle_load_result` (`store_local.h:178`, an `OSSL_CALLBACK`), is threaded
//! through the provider's `p_load` as a function pointer, so nothing here is `#[no_mangle]`.
//! Every other function is `static`. The unit is the "do the best it can with it" reader the
//! file's own header describes: given an object abstraction (a terminated parameter array),
//! it tries, in order, a name, a key, a certificate, a CRL and a PKCS#12 blob, and answers the
//! first `OSSL_STORE_INFO` it can build.
//!
//! # The whole unit lands here
//!
//! Every callee is landed. `d2i_X509`/`d2i_X509_AUX`/`X509_new_ex` (Phase 11's `X509` graph,
//! landed in 10.8/10.12), `d2i_X509_CRL`/`ossl_x509_crl_set0_libctx` (10.8), `PKCS12_parse`
//! and its four container readers (10.3, and the parallel `p12_kiss.c` slice that landed with
//! it), the `OSSL_DECODER` context family (`OSS_DECODER_CTX_new_for_pkey`/`_set_passphrase_cb`/
//! `_free`, `OSSL_DECODER_from_data`, `ossl_decoder_ctx_get_harderr`), the key management
//! fetch/load/import family (`EVP_KEYMGMT_fetch`/`_free`/`_get0_provider`,
//! `evp_keymgmt_fetch_from_prov`, `evp_keymgmt_load`, `evp_keymgmt_util_try_import`/
//! `_make_pkey`/`_has`), and the `OSSL_STORE_INFO` constructors this crate already publishes
//! are one and all in the crate. `EVP_PKCS82PKEY_ex` is reached through the crate's internal
//! spelling `ossl_evp_pkcs82pkey_ex` (10.11), the same posture `crypto/pem/pem_pk8.c` and
//! `p12_kiss.rs` take: the export row is Phase 11's, the behaviour is landed.
//!
//! # What is withheld
//!
//! Nothing. The last blocker the 10.5 module doc named for this unit — `d2i_X509_AUX` and
//! `PKCS12_parse` — closed with 10.12 and 10.3 respectively, so the handler lands whole and
//! [`crate::store::store_lib::OSSL_STORE_load`]'s fetched branch lands with it.
//!
//! # The raise sites are declared locally
//!
//! `crypto/store/store_result.c` is **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES` (as `store_lib.rs` and `store_meth.rs` also are not), so its six
//! coordinates are declared here under the generator's own naming. Each reason value is read
//! from the installed headers: the `OSSL_STORE_R_BAD_PASSWORD_READ` /
//! `OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR` / `OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC` from
//! `include/openssl/storeerr.h:23,37,24`, `ERR_LIB_OSSL_STORE` from `err.h.in:109`, and
//! `ERR_R_UNSUPPORTED` from `err.h.in:366` (`268 | ERR_RFLAG_COMMON`, `ERR_RFLAG_COMMON =
//! 0x2 << ERR_RFLAGS_OFFSET` with `ERR_RFLAGS_OFFSET = 18`, `err.h.in:232,241`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::p8_pkey::{d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free};
use crate::asn1::x_algor::X509Algor;
use crate::asn1::x_sig::{d2i_X509_SIG, X509_SIG_free, X509_SIG_get0};
use crate::decoder_lib::{ossl_decoder_ctx_get_harderr, OSSL_DECODER_from_data};
use crate::decoder_meth::OSSL_DECODER_CTX_free;
use crate::decoder_pkey::{OSSL_DECODER_CTX_new_for_pkey, OSSL_DECODER_CTX_set_passphrase_cb};
use crate::evp::evp_pkey::ossl_evp_pkcs82pkey_ex;
use crate::evp::keymgmt::{
    evp_keymgmt_fetch_from_prov, evp_keymgmt_load, EVP_KEYMGMT_fetch, EVP_KEYMGMT_free,
    EVP_KEYMGMT_get0_provider,
};
use crate::evp::keymgmt_lib::{
    evp_keymgmt_util_has, evp_keymgmt_util_make_pkey, evp_keymgmt_util_try_import, TryImportData,
};
use crate::evp::pkey::{
    EVP_PKEY_free, EvpPkey, OSSL_KEYMGMT_SELECT_ALL, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate_const,
    OsslParam,
};
use crate::passphrase::{
    ossl_pw_get_passphrase, OsslPassphraseCallback, OSSL_PASSPHRASE_PARAM_INFO,
};
use crate::pem::pem_lib::{PEM_BUFSIZE, PEM_STRING_X509_TRUSTED};
use crate::pkcs12::p12_asn::{d2i_PKCS12, PKCS12_free};
use crate::pkcs12::p12_decr::PKCS12_pbe_crypt;
use crate::pkcs12::p12_kiss::PKCS12_parse;
use crate::pkcs12::p12_mutl::{PKCS12_mac_present, PKCS12_verify_mac};
use crate::provider::{
    ossl_provider_libctx, OSSL_PROVIDER_available, OSSL_PROVIDER_get0_name, OsslProvider,
};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, OPENSSL_cleanse};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_shift,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::x509::x_crl::{d2i_X509_CRL, ossl_x509_crl_set0_libctx, X509_CRL_free};
use crate::x509::x_pubkey::d2i_PUBKEY_ex;
use crate::x509::x_x509::{d2i_X509, d2i_X509_AUX, X509_free, X509_new_ex, X509};

use super::store_lib::{OsslStoreCtx, OsslStoreInfo};
use super::store_meth::OSSL_STORE_LOADER_get0_provider;
use super::{OSSL_STORE_INFO_PARAMS, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY};

// ---------------------------------------------------------------------------
// The `core_object.h` object-type numbers and the `core_names.h` parameter names
// ---------------------------------------------------------------------------

/// `OSSL_OBJECT_UNKNOWN` — `include/openssl/core_object.h:27`.
const OSSL_OBJECT_UNKNOWN: c_int = 0;
/// `OSSL_OBJECT_NAME` — `include/openssl/core_object.h:28`.
const OSSL_OBJECT_NAME: c_int = 1;
/// `OSSL_OBJECT_PKEY` — `include/openssl/core_object.h:29`.
const OSSL_OBJECT_PKEY: c_int = 2;
/// `OSSL_OBJECT_CERT` — `include/openssl/core_object.h:30`.
const OSSL_OBJECT_CERT: c_int = 3;
/// `OSSL_OBJECT_CRL` — `include/openssl/core_object.h:31`.
const OSSL_OBJECT_CRL: c_int = 4;
/// `OSSL_OBJECT_PKCS12` — `store_result.c:35`'s private `#define`, a value outside the public
/// positive range so it can never slip out of this translation unit.
const OSSL_OBJECT_PKCS12: c_int = -1;

/// `OSSL_OBJECT_PARAM_TYPE` — `core_names.h:362`, the string `"type"`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — `core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h:357`, the string `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_INPUT_TYPE` — `core_names.h:360`, the string `"input-type"`.
const OSSL_OBJECT_PARAM_INPUT_TYPE: *const c_char = c"input-type".as_ptr();
/// `OSSL_OBJECT_PARAM_REFERENCE` — `core_names.h:361`, the string `"reference"`.
const OSSL_OBJECT_PARAM_REFERENCE: *const c_char = c"reference".as_ptr();
/// `OSSL_OBJECT_PARAM_DESC` — `core_names.h:359`, the string `"desc"`.
const OSSL_OBJECT_PARAM_DESC: *const c_char = c"desc".as_ptr();

/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `core_dispatch.h:646-648`, the authority's
/// `DOMAIN_PARAMETERS | OTHER_PARAMETERS`. Restated here as the crate's other consumers of the
/// macro restate it (`src/evp/pmeth_check.rs`, `src/provider/keymgmt.rs`) because it has no
/// single `pub(crate)` home.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int = 0x04 | 0x80;

// ---------------------------------------------------------------------------
// The raise coordinates
//
// `crypto/store/store_result.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
// coordinates are declared here under the generator's own naming, the way `store_lib.rs` and
// `store_meth.rs` declare theirs. Each is the authority's own file/line/function.
// ---------------------------------------------------------------------------

/// `ERR_LIB_OSSL_STORE` — `include/openssl/err.h.in:109`.
const ERR_LIB_OSSL_STORE: c_int = 44;
/// `OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC` — `include/openssl/storeerr.h:24`.
const OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC: c_int = 113;
/// `OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR` — `include/openssl/storeerr.h:37`.
const OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR: c_int = 114;
/// `OSSL_STORE_R_BAD_PASSWORD_READ` — `include/openssl/storeerr.h:23`.
const OSSL_STORE_R_BAD_PASSWORD_READ: c_int = 115;
/// `ERR_R_UNSUPPORTED` — `include/openssl/err.h.in:366`, `268 | ERR_RFLAG_COMMON` with
/// `ERR_RFLAG_COMMON = 0x2 << ERR_RFLAGS_OFFSET`, `ERR_RFLAGS_OFFSET = 18`
/// (`err.h.in:232,241`), so `268 | (0x2 << 18) == 524556`.
const ERR_R_UNSUPPORTED: c_int = 268 | (0x2 << 18);

/// One `store_result.c` raise coordinate. `line` and `func` are the authority file's own.
const fn store_result_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
    dynamic_reason: bool,
) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/store/store_result.c",
        line,
        func,
        lib: ERR_LIB_OSSL_STORE,
        reason,
        dynamic_reason,
    }
}

/// `ossl_store_handle_load_result` at `store_result.c:160` — the `provider=%s%s` arm.
const STORE_RESULT_160: err_sites::ErrSite = store_result_site(
    160,
    c"ossl_store_handle_load_result",
    ERR_R_UNSUPPORTED,
    false,
);
/// `ossl_store_handle_load_result` at `store_result.c:163` — the `%s` hint arm.
const STORE_RESULT_163: err_sites::ErrSite = store_result_site(
    163,
    c"ossl_store_handle_load_result",
    ERR_R_UNSUPPORTED,
    false,
);
/// `ossl_store_handle_load_result` at `store_result.c:165` — the bare `ERR_raise`.
const STORE_RESULT_165: err_sites::ErrSite = store_result_site(
    165,
    c"ossl_store_handle_load_result",
    ERR_R_UNSUPPORTED,
    false,
);
/// `try_key_value_legacy` at `store_result.c:356`.
const STORE_RESULT_356: err_sites::ErrSite = store_result_site(
    356,
    c"try_key_value_legacy",
    OSSL_STORE_R_BAD_PASSWORD_READ,
    false,
);
/// `try_pkcs12` at `store_result.c:591`.
const STORE_RESULT_591: err_sites::ErrSite = store_result_site(
    591,
    c"try_pkcs12",
    OSSL_STORE_R_PASSPHRASE_CALLBACK_ERROR,
    false,
);
/// `try_pkcs12` at `store_result.c:602` — the MAC-verify refusal, whose message is one of two
/// compile-time strings.
const STORE_RESULT_602: err_sites::ErrSite = store_result_site(
    602,
    c"try_pkcs12",
    OSSL_STORE_R_ERROR_VERIFYING_PKCS12_MAC,
    false,
);

// ---------------------------------------------------------------------------
// `struct ossl_load_result_data_st` (`store_local.h:174-177`) and the extracted-parameter
// scratch struct (`store_result.c:63-74`)
// ---------------------------------------------------------------------------

/// `struct ossl_load_result_data_st` — `store_local.h:174-177`. The `arg` the provider's
/// `p_load` forwards to [`ossl_store_handle_load_result`].
#[repr(C)]
pub(crate) struct OsslStoreLoadResultData {
    /// `OSSL_STORE_INFO *v` — the object the handler fills in, or NULL.
    pub(crate) v: *mut OsslStoreInfo,
    /// `OSSL_STORE_CTX *ctx` — the loader context the handler reads.
    pub(crate) ctx: *mut OsslStoreCtx,
}

/// `struct extracted_param_data_st` — `store_result.c:63-74`.
///
/// The authority's `ref` member is spelled `reference` here, because `ref` is a Rust keyword.
/// It is the object abstraction's `OSSL_OBJECT_PARAM_REFERENCE` payload.
struct ExtractedParamData {
    /// `int object_type` — one of `OSSL_OBJECT_*`; written by every `try_*` that recognises
    /// its own type.
    object_type: c_int,
    /// `const char *data_type` — the PEM name, or NULL.
    data_type: *const c_char,
    /// `const char *input_type` — the decoder-chained input type, or NULL.
    input_type: *const c_char,
    /// `const char *data_structure` — the decoder-chained structure, or NULL.
    data_structure: *const c_char,
    /// `const char *utf8_data` — the object payload when it is a name.
    utf8_data: *const c_char,
    /// `const void *octet_data` — the object payload when it is DER.
    octet_data: *const c_void,
    /// `size_t octet_data_size` — the DER length.
    octet_data_size: usize,
    /// `const void *ref` — the object reference for a by-reference key.
    reference: *const c_void,
    /// `size_t ref_size` — the reference's length.
    reference_size: usize,
    /// `const char *desc` — the object's optional description.
    desc: *const c_char,
}

/// `typedef OSSL_STORE_INFO *store_info_new_fn(EVP_PKEY *)` — `store_result.c:317`. The
/// constructor `try_key` settles on once it has decided whether the key it built is a private
/// key, a public key or parameters alone.
pub(crate) type StoreInfoNewFn = unsafe extern "C" fn(*mut EvpPkey) -> *mut OsslStoreInfo;

/// The `X509_free` destructor shape `OPENSSL_sk_pop_free` takes, for the `chain` stack the
/// authority releases through `OSSL_STACK_OF_X509_free`.
///
/// # Safety
/// `p` is null or an `X509` this item layer owns.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast::<X509>()) };
}

/// The `OSSL_STORE_INFO_free` destructor shape for `sk_OSSL_STORE_INFO_pop_free`.
///
/// # Safety
/// `p` is null or an `OSSL_STORE_INFO` this object layer owns.
unsafe extern "C" fn store_info_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { super::store_lib::OSSL_STORE_INFO_free(p.cast::<OsslStoreInfo>()) };
}

/// The `const unsigned char **` cursor address the `d2i_*` readers advance: the address of the
/// scratch struct's `octet_data` member, exactly as the authority spells
/// `(const unsigned char **)&data->octet_data`.
///
/// # Safety
/// `data` must be a live `ExtractedParamData`.
unsafe fn octet_cursor(data: *mut ExtractedParamData) -> *mut *const c_uchar {
    // SAFETY: `data` is live per the contract; the field's address is a valid cursor slot.
    unsafe { ptr::addr_of_mut!((*data).octet_data).cast::<*const c_uchar>() }
}

/// `static int try_name(struct extracted_param_data_st *data, OSSL_STORE_INFO **v)` —
/// `store_result.c:174-192`.
///
/// # Safety
/// `data` and `v` must be live.
unsafe fn try_name(data: *mut ExtractedParamData, v: *mut *mut OsslStoreInfo) -> c_int {
    // SAFETY: `data` is live per the contract.
    if unsafe { (*data).object_type } == OSSL_OBJECT_NAME {
        // SAFETY: `data` is live per the contract.
        let utf8 = unsafe { (*data).utf8_data };
        if utf8.is_null() {
            return 0;
        }
        // SAFETY: `utf8` is NUL-terminated per the object abstraction.
        let newname = unsafe { CRYPTO_strdup(utf8, ptr::null(), 0) };
        let mut newdesc: *mut c_char = ptr::null_mut();
        let mut ok = !newname.is_null();
        if ok {
            // SAFETY: `data` is live per the contract.
            let desc = unsafe { (*data).desc };
            if !desc.is_null() {
                // SAFETY: `desc` is NUL-terminated per the object abstraction.
                newdesc = unsafe { CRYPTO_strdup(desc, ptr::null(), 0) };
                ok = !newdesc.is_null();
            }
        }
        if ok {
            // SAFETY: the constructor takes ownership of `newname`.
            let info = unsafe { super::store_lib::OSSL_STORE_INFO_new_NAME(newname) };
            // SAFETY: `v` is a live out-slot per the contract.
            unsafe { *v = info };
            ok = !info.is_null();
        }
        if !ok {
            // SAFETY: both are NULL or the allocations this frame owns.
            unsafe {
                CRYPTO_free(newname.cast::<c_void>(), ptr::null(), 0);
                CRYPTO_free(newdesc.cast::<c_void>(), ptr::null(), 0);
            }
            return 0;
        }
        // SAFETY: `*v` is the NAME object just built; `newdesc` transfers to it (NULL allowed).
        unsafe { super::store_lib::OSSL_STORE_INFO_set0_NAME_description(*v, newdesc) };
    }
    1
}

/// `static EVP_PKEY *try_key_ref(struct extracted_param_data_st *data, OSSL_STORE_CTX *ctx,
/// const OSSL_PROVIDER *provider, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `store_result.c:201-271`.
///
/// # Safety
/// `data` and `ctx` must be live; `provider` must be the fetched loader's provider.
unsafe fn try_key_ref(
    data: *mut ExtractedParamData,
    ctx: *mut OsslStoreCtx,
    provider: *const OsslProvider,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut pk: *mut EvpPkey = ptr::null_mut();
    let mut keydata: *mut c_void = ptr::null_mut();
    let mut try_fallback = 2;

    // SAFETY: `data` is live per the contract.
    let data_type = unsafe { (*data).data_type };
    if data_type.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `libctx`/`propq` are the caller's; `data_type` is NUL-terminated.
    let mut keymgmt = unsafe { EVP_KEYMGMT_fetch(libctx, data_type, propq) };
    // SAFETY: a mark on the error queue.
    ERR_set_mark();
    loop {
        if keymgmt.is_null() || !keydata.is_null() {
            break;
        }
        // The authority's `try_fallback-- > 0`: test the old value, then decrement.
        let old = try_fallback;
        try_fallback -= 1;
        if old <= 0 {
            break;
        }

        // SAFETY: `keymgmt` is live per the loop guard.
        let same_provider = unsafe { EVP_KEYMGMT_get0_provider(keymgmt) } == provider;
        if same_provider {
            /* no point trying fallback here */
            try_fallback = 0;
            // SAFETY: `keymgmt` is live; `data`'s reference/`ref_size` describe the blob.
            keydata =
                unsafe { evp_keymgmt_load(keymgmt, (*data).reference, (*data).reference_size) };
        } else {
            let mut import_data = TryImportData {
                keymgmt,
                keydata: ptr::null_mut(),
                selection: OSSL_KEYMGMT_SELECT_ALL,
            };
            // SAFETY: `ctx` is live per the contract.
            let export_object = unsafe { (*(*ctx).fetched_loader).p_export_object };
            if let Some(export_object) = export_object {
                // SAFETY: `loader_ctx` is the fetched loader's own context; the reference and
                // its length are `data`'s; the callback and its argument are this frame's.
                unsafe {
                    export_object(
                        (*ctx).loader_ctx.cast::<c_void>(),
                        (*data).reference,
                        (*data).reference_size,
                        Some(evp_keymgmt_util_try_import),
                        ptr::addr_of_mut!(import_data).cast::<c_void>(),
                    );
                }
            }
            keydata = import_data.keydata;
        }

        if keydata.is_null() && try_fallback > 0 {
            // SAFETY: `keymgmt` is live.
            unsafe { EVP_KEYMGMT_free(keymgmt) };
            // SAFETY: `provider` is live; `data_type` is NUL-terminated.
            keymgmt = unsafe { evp_keymgmt_fetch_from_prov(provider.cast_mut(), data_type, propq) };
            if !keymgmt.is_null() {
                // SAFETY: a mark was set before the fetch.
                ERR_pop_to_mark();
                ERR_set_mark();
            }
        }
    }
    if !keydata.is_null() {
        // SAFETY: a mark was set before the loop.
        ERR_pop_to_mark();
        // SAFETY: `keymgmt` and `keydata` are live and belong together.
        pk = unsafe { evp_keymgmt_util_make_pkey(keymgmt, keydata) };
    } else {
        // SAFETY: a mark was set before the loop.
        ERR_clear_last_mark();
    }
    // SAFETY: `keymgmt` is NULL or a live method this frame holds.
    unsafe { EVP_KEYMGMT_free(keymgmt) };

    pk
}

/// `static EVP_PKEY *try_key_value(struct extracted_param_data_st *data, OSSL_STORE_CTX *ctx,
/// OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg, OSSL_LIB_CTX *libctx, const char *propq,
/// int *harderr)` — `store_result.c:273-315`.
///
/// # Safety
/// `data` and `ctx` must be live; `harderr` must be a live out-slot.
unsafe fn try_key_value(
    data: *mut ExtractedParamData,
    ctx: *mut OsslStoreCtx,
    cb: OsslPassphraseCallback,
    cbarg: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
    harderr: *mut c_int,
) -> *mut EvpPkey {
    let mut pk: *mut EvpPkey = ptr::null_mut();
    // SAFETY: `data` is live per the contract.
    let mut pdata = unsafe { (*data).octet_data.cast::<c_uchar>() };
    // SAFETY: `data` is live per the contract.
    let mut pdatalen = unsafe { (*data).octet_data_size };

    // SAFETY: `ctx` is live per the contract.
    let selection: c_int = match unsafe { (*ctx).expected_type } {
        0 => 0,
        OSSL_STORE_INFO_PARAMS => OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
        OSSL_STORE_INFO_PUBKEY => {
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
        }
        OSSL_STORE_INFO_PKEY => OSSL_KEYMGMT_SELECT_ALL,
        _ => return ptr::null_mut(),
    };

    // SAFETY: `pk` is a live out-slot; the three strings are `data`'s; `libctx`/`propq` are the
    // caller's.
    let decoderctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &raw mut pk,
            (*data).input_type,
            (*data).data_structure,
            (*data).data_type,
            selection,
            libctx,
            propq,
        )
    };
    // SAFETY: `decoderctx` is NULL or a fresh context; the callback and its argument are the
    // caller's.
    unsafe { OSSL_DECODER_CTX_set_passphrase_cb(decoderctx, Some(cb), cbarg) };

    /* No error if this couldn't be decoded */
    // SAFETY: `decoderctx` is NULL or live; the two cursors are this frame's.
    unsafe { OSSL_DECODER_from_data(decoderctx, &raw mut pdata, &raw mut pdatalen) };

    /* Save the hard error state. */
    // SAFETY: `decoderctx` is NULL or live; `harderr` is a live out-slot.
    unsafe { *harderr = ossl_decoder_ctx_get_harderr(decoderctx) };
    // SAFETY: `decoderctx` is NULL or the context just built.
    unsafe { OSSL_DECODER_CTX_free(decoderctx) };

    pk
}

/// `static EVP_PKEY *try_key_value_legacy(struct extracted_param_data_st *data,
/// store_info_new_fn **store_info_new, OSSL_STORE_CTX *ctx, OSSL_PASSPHRASE_CALLBACK *cb,
/// void *cbarg, OSSL_LIB_CTX *libctx, const char *propq)` — `store_result.c:319-399`.
///
/// # Safety
/// `data` and `ctx` must be live; `store_info_new` must be a live out-slot.
unsafe fn try_key_value_legacy(
    data: *mut ExtractedParamData,
    store_info_new: *mut Option<StoreInfoNewFn>,
    ctx: *mut OsslStoreCtx,
    cb: OsslPassphraseCallback,
    cbarg: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    let mut pk: *mut EvpPkey = ptr::null_mut();
    // SAFETY: `data` is live per the contract.
    let mut der: *const c_uchar = unsafe { (*data).octet_data.cast::<c_uchar>() };
    let mut derp: *const c_uchar;
    // SAFETY: `data` is live per the contract.
    let mut der_len: c_long = unsafe { (*data).octet_data_size } as c_long;

    /* Try PUBKEY first, that's a real easy target */
    // SAFETY: `ctx` is live per the contract.
    let expected = unsafe { (*ctx).expected_type };
    if expected == 0 || expected == OSSL_STORE_INFO_PUBKEY {
        derp = der;
        // SAFETY: `derp` is this frame's cursor; `libctx`/`propq` are the caller's.
        pk = unsafe { d2i_PUBKEY_ex(ptr::null_mut(), &raw mut derp, der_len, libctx, propq) };

        if !pk.is_null() {
            // SAFETY: `store_info_new` is a live out-slot per the contract.
            unsafe { *store_info_new = Some(super::store_lib::OSSL_STORE_INFO_new_PUBKEY) };
        }
    }

    /* Try private keys next */
    if pk.is_null() && (expected == 0 || expected == OSSL_STORE_INFO_PKEY) {
        let mut new_der: *mut c_uchar = ptr::null_mut();

        /* See if it's an encrypted PKCS#8 and decrypt it. */
        derp = der;
        // SAFETY: `derp` is this frame's cursor.
        let p8 = unsafe { d2i_X509_SIG(ptr::null_mut(), &raw mut derp, der_len) };

        if !p8.is_null() {
            let mut pbuf = [0 as c_char; PEM_BUFSIZE as usize];
            let mut plen: usize = 0;

            // SAFETY: `pbuf` is this frame's buffer of the size passed; `cbarg` is the caller's.
            if unsafe {
                cb(
                    pbuf.as_mut_ptr(),
                    PEM_BUFSIZE as usize,
                    &raw mut plen,
                    ptr::null(),
                    cbarg,
                )
            } == 0
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&STORE_RESULT_356) };
            } else {
                let mut alg: *const X509Algor = ptr::null();
                let mut oct: *const Asn1String = ptr::null();
                let mut len: c_int = 0;

                // SAFETY: `p8` is live; the two out-slots are this frame's.
                unsafe { X509_SIG_get0(p8, &raw mut alg, &raw mut oct) };

                /*
                 * No need to check the returned value, |new_der|
                 * will be NULL on error anyway.
                 */
                // SAFETY: `alg` is live; the passphrase buffer and `oct`'s octets are readable for
                // their lengths; `new_der`/`len` are this frame's out-slots.
                unsafe {
                    PKCS12_pbe_crypt(
                        alg,
                        pbuf.as_ptr(),
                        plen as c_int,
                        (*oct).data,
                        (*oct).length,
                        &raw mut new_der,
                        &raw mut len,
                        0,
                    );
                }
                der_len = len as c_long;
                der = new_der;
            }
            // SAFETY: `p8` is NULL or this frame's own object.
            unsafe { X509_SIG_free(p8) };
        }

        /*
         * If the encrypted PKCS#8 couldn't be decrypted,
         * |der| is NULL
         */
        if !der.is_null() {
            /* Try to unpack an unencrypted PKCS#8, that's easy */
            derp = der;
            // SAFETY: `derp` is this frame's cursor.
            let p8info =
                unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut derp, der_len) };

            if !p8info.is_null() {
                // SAFETY: `p8info` is live; `libctx`/`propq` are the caller's.
                pk = unsafe { ossl_evp_pkcs82pkey_ex(p8info, libctx, propq) };
                // SAFETY: `p8info` is this frame's own object.
                unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
            }
        }

        if !pk.is_null() {
            // SAFETY: `store_info_new` is a live out-slot per the contract.
            unsafe { *store_info_new = Some(super::store_lib::OSSL_STORE_INFO_new_PKEY) };
        }

        // SAFETY: `new_der` is NULL or the buffer `PKCS12_pbe_crypt` allocated.
        unsafe { CRYPTO_free(new_der.cast::<c_void>(), ptr::null(), 0) };
    }

    pk
}

/// `static int try_key(struct extracted_param_data_st *data, OSSL_STORE_INFO **v,
/// OSSL_STORE_CTX *ctx, const OSSL_PROVIDER *provider, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `store_result.c:401-470`.
///
/// # Safety
/// `data`, `v` and `ctx` must be live; `provider` must be the fetched loader's provider.
unsafe fn try_key(
    data: *mut ExtractedParamData,
    v: *mut *mut OsslStoreInfo,
    ctx: *mut OsslStoreCtx,
    provider: *const OsslProvider,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut store_info_new: Option<StoreInfoNewFn> = None;
    let mut harderr: c_int = 0;

    // SAFETY: `data` is live per the contract.
    let object_type = unsafe { (*data).object_type };
    if object_type == OSSL_OBJECT_UNKNOWN || object_type == OSSL_OBJECT_PKEY {
        let mut pk: *mut EvpPkey = ptr::null_mut();

        /* Prefer key by reference than key by value */
        // SAFETY: `data` is live per the contract.
        if object_type == OSSL_OBJECT_PKEY && !unsafe { (*data).reference }.is_null() {
            // SAFETY: `data` and `ctx` are live; `provider`/`libctx`/`propq` are the caller's.
            pk = unsafe { try_key_ref(data, ctx, provider, libctx, propq) };

            /*
             * If for some reason we couldn't get a key, it's an error.
             * It indicates that while decoders could make a key reference,
             * the keymgmt somehow couldn't handle it, or doesn't have a
             * OSSL_FUNC_keymgmt_load function.
             */
            if pk.is_null() {
                return 0;
            }
        // SAFETY: `data` is live per the contract.
        } else if !unsafe { (*data).octet_data }.is_null() {
            let cb = crate::passphrase::ossl_pw_passphrase_callback_dec;
            // SAFETY: `ctx` is live per the contract.
            let cbarg = unsafe { ptr::addr_of_mut!((*ctx).pwdata).cast::<c_void>() };

            // SAFETY: `data` and `ctx` are live; `harderr` is this frame's out-slot.
            pk = unsafe { try_key_value(data, ctx, cb, cbarg, libctx, propq, &raw mut harderr) };

            /*
             * Desperate last maneuver, in case the decoders don't support
             * the data we have, then we try on our own to at least get an
             * engine provided legacy key.
             * This is the same as der2key_decode() does, but in a limited
             * way and within the walls of libcrypto.
             */
            if pk.is_null() && harderr == 0 {
                // SAFETY: `data`, `ctx` and the out-slot are live; `cb`/`cbarg` are this frame's.
                pk = unsafe {
                    try_key_value_legacy(
                        data,
                        &raw mut store_info_new,
                        ctx,
                        cb,
                        cbarg,
                        libctx,
                        propq,
                    )
                };
            }
        }

        if !pk.is_null() {
            // SAFETY: `data` is live per the contract.
            unsafe { (*data).object_type = OSSL_OBJECT_PKEY };

            let ctor = match store_info_new {
                Some(ctor) => ctor,
                None => {
                    /*
                     * We determined the object type for OSSL_STORE_INFO, which
                     * makes an explicit difference between an EVP_PKEY with just
                     * (domain) parameters and an EVP_PKEY with actual key
                     * material.
                     * The logic is that an EVP_PKEY with actual key material
                     * always has the public half.
                     */
                    // SAFETY: `pk` is live.
                    if unsafe { evp_keymgmt_util_has(pk, OSSL_KEYMGMT_SELECT_PRIVATE_KEY) } != 0 {
                        super::store_lib::OSSL_STORE_INFO_new_PKEY
                    // SAFETY: `pk` is live.
                    } else if unsafe { evp_keymgmt_util_has(pk, OSSL_KEYMGMT_SELECT_PUBLIC_KEY) }
                        != 0
                    {
                        super::store_lib::OSSL_STORE_INFO_new_PUBKEY
                    } else {
                        super::store_lib::OSSL_STORE_INFO_new_PARAMS
                    }
                }
            };
            // SAFETY: `pk` is a live key whose ownership transfers to the object.
            let info = unsafe { ctor(pk) };
            // SAFETY: `v` is a live out-slot per the contract.
            unsafe { *v = info };
        }

        // SAFETY: `v` is a live out-slot per the contract.
        if unsafe { *v }.is_null() {
            // SAFETY: `pk` is NULL or a key this frame owns.
            unsafe { EVP_PKEY_free(pk) };
        }
    }

    c_int::from(harderr == 0)
}

/// `static int try_cert(struct extracted_param_data_st *data, OSSL_STORE_INFO **v,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `store_result.c:472-518`.
///
/// # Safety
/// `data` and `v` must be live.
unsafe fn try_cert(
    data: *mut ExtractedParamData,
    v: *mut *mut OsslStoreInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `data` is live per the contract.
    let object_type = unsafe { (*data).object_type };
    if object_type == OSSL_OBJECT_UNKNOWN || object_type == OSSL_OBJECT_CERT {
        /*
         * In most cases, we can try to interpret the serialized
         * data as a trusted cert (X509 + X509_AUX) and fall back
         * to reading it as a normal cert (just X509), but if
         * |data_type| (the PEM name) specifically declares it as a
         * trusted cert, then no fallback should be engaged.
         * |ignore_trusted| tells if the fallback can be used (1)
         * or not (0).
         */
        let mut ignore_trusted = 1;
        // SAFETY: `libctx` and `propq` are the caller's.
        let mut cert = unsafe { X509_new_ex(libctx, propq) };

        if cert.is_null() {
            return 0;
        }

        /* If we have a data type, it should be a PEM name */
        // SAFETY: `data` is live per the contract.
        let data_type = unsafe { (*data).data_type };
        if !data_type.is_null()
            // SAFETY: both strings are NUL-terminated.
            && unsafe { OPENSSL_strcasecmp(data_type, PEM_STRING_X509_TRUSTED) } == 0
        {
            ignore_trusted = 0;
        }

        // SAFETY: `cert` is live; the cursor addresses the scratch struct's DER fields.
        let aux_ok = unsafe {
            !d2i_X509_AUX(
                &raw mut cert,
                octet_cursor(data),
                (*data).octet_data_size as c_long,
            )
            .is_null()
        };
        let plain_ok = if aux_ok {
            true
        } else if ignore_trusted == 0 {
            false
        } else {
            // SAFETY: as above.
            unsafe {
                !d2i_X509(
                    &raw mut cert,
                    octet_cursor(data),
                    (*data).octet_data_size as c_long,
                )
                .is_null()
            }
        };
        if !aux_ok && !plain_ok {
            // SAFETY: `cert` is NULL or a live object this frame owns.
            unsafe { X509_free(cert) };
            cert = ptr::null_mut();
        }

        if !cert.is_null() {
            /* We determined the object type */
            // SAFETY: `data` is live per the contract.
            unsafe { (*data).object_type = OSSL_OBJECT_CERT };
            // SAFETY: `cert` transfers to the object.
            let info = unsafe { super::store_lib::OSSL_STORE_INFO_new_CERT(cert.cast::<c_void>()) };
            // SAFETY: `v` is a live out-slot per the contract.
            unsafe { *v = info };
            // SAFETY: `v` is a live out-slot per the contract.
            if unsafe { *v }.is_null() {
                // SAFETY: `cert` is live and the constructor refused it.
                unsafe { X509_free(cert) };
            }
        }
    }

    1
}

/// `static int try_crl(struct extracted_param_data_st *data, OSSL_STORE_INFO **v,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `store_result.c:520-546`.
///
/// # Safety
/// `data` and `v` must be live.
unsafe fn try_crl(
    data: *mut ExtractedParamData,
    v: *mut *mut OsslStoreInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `data` is live per the contract.
    let object_type = unsafe { (*data).object_type };
    if object_type == OSSL_OBJECT_UNKNOWN || object_type == OSSL_OBJECT_CRL {
        // SAFETY: the cursor addresses the scratch struct's DER field.
        let mut crl = unsafe {
            d2i_X509_CRL(
                ptr::null_mut(),
                octet_cursor(data),
                (*data).octet_data_size as c_long,
            )
        };

        if !crl.is_null() {
            /* We determined the object type */
            // SAFETY: `data` is live per the contract.
            unsafe { (*data).object_type = OSSL_OBJECT_CRL };
        }

        // SAFETY: `crl` is NULL or live; `libctx`/`propq` are the caller's.
        if !crl.is_null() && unsafe { ossl_x509_crl_set0_libctx(crl, libctx, propq) } == 0 {
            // SAFETY: `crl` is live and this frame owns it.
            unsafe { X509_CRL_free(crl) };
            crl = ptr::null_mut();
        }

        if !crl.is_null() {
            // SAFETY: `crl` transfers to the object.
            let info = unsafe { super::store_lib::OSSL_STORE_INFO_new_CRL(crl.cast::<c_void>()) };
            // SAFETY: `v` is a live out-slot per the contract.
            unsafe { *v = info };
        }
        // SAFETY: `v` is a live out-slot per the contract.
        if unsafe { *v }.is_null() {
            // SAFETY: `crl` is NULL or a CRL this frame owns.
            unsafe { X509_CRL_free(crl) };
        }
    }

    1
}

/// `static int try_pkcs12(struct extracted_param_data_st *data, OSSL_STORE_INFO **v,
/// OSSL_STORE_CTX *ctx, OSSL_LIB_CTX *libctx, const char *propq)` — `store_result.c:548-667`.
///
/// # Safety
/// `data`, `v` and `ctx` must be live.
unsafe fn try_pkcs12(
    data: *mut ExtractedParamData,
    v: *mut *mut OsslStoreInfo,
    ctx: *mut OsslStoreCtx,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let _ = (libctx, propq);
    let mut ok: c_int = 1;

    /* There is no specific object type for PKCS12 */
    // SAFETY: `data` is live per the contract.
    if unsafe { (*data).object_type } == OSSL_OBJECT_UNKNOWN {
        /* Initial parsing */
        // SAFETY: the cursor addresses the scratch struct's DER field.
        let p12 = unsafe {
            d2i_PKCS12(
                ptr::null_mut(),
                octet_cursor(data),
                (*data).octet_data_size as c_long,
            )
        };

        if !p12.is_null() {
            let pass: *const c_char;
            let mut tpass = [0 as c_char; (PEM_BUFSIZE + 1) as usize];
            let mut tpass_len: usize = 0;
            let mut pkey: *mut EvpPkey = ptr::null_mut();
            let mut cert: *mut X509 = ptr::null_mut();
            let mut chain: *mut OpenSslStack = ptr::null_mut();

            // SAFETY: `data` is live per the contract.
            unsafe { (*data).object_type = OSSL_OBJECT_PKCS12 };

            ok = 0; /* Assume decryption or parse error */

            'parse: {
                // SAFETY: `p12` is live; a NULL passphrase and length 0 are the no-password probe.
                if unsafe { PKCS12_mac_present(p12) } == 0
                    // SAFETY: `p12` is live; the NULL-passphrase probe is read-only.
                    || unsafe { PKCS12_verify_mac(p12, ptr::null(), 0) } != 0
                {
                    pass = ptr::null();
                // SAFETY: `p12` is live; the empty-string passphrase is the empty-password probe.
                } else if unsafe { PKCS12_verify_mac(p12, c"".as_ptr(), 0) } != 0 {
                    pass = c"".as_ptr();
                } else {
                    const PROMPT: &CStr = c"PKCS12 import pass phrase";
                    let pw_params = [
                        // SAFETY: the key is a literal and the prompt buffer is this frame's.
                        unsafe {
                            OSSL_PARAM_construct_utf8_string(
                                OSSL_PASSPHRASE_PARAM_INFO,
                                PROMPT.as_ptr().cast_mut(),
                                PROMPT.to_bytes().len(),
                            )
                        },
                        OSSL_PARAM_construct_end(),
                    ];

                    // SAFETY: `tpass` is this frame's buffer of the size passed; `tpass_len` is
                    // this frame's out-slot; `ctx`'s passphrase data is live.
                    if unsafe {
                        ossl_pw_get_passphrase(
                            tpass.as_mut_ptr(),
                            PEM_BUFSIZE as usize,
                            &raw mut tpass_len,
                            pw_params.as_ptr(),
                            0,
                            ptr::addr_of_mut!((*ctx).pwdata),
                        )
                    } == 0
                    {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&STORE_RESULT_591) };
                        break 'parse;
                    }
                    pass = tpass.as_ptr();
                    /*
                     * ossl_pw_get_passphrase() does not NUL terminate but
                     * we must do it for PKCS12_parse()
                     */
                    tpass[tpass_len] = 0;
                    // SAFETY: `p12` is live; `pass` points at `tpass`, NUL-terminated above.
                    if unsafe { PKCS12_verify_mac(p12, pass, tpass_len as c_int) } == 0 {
                        let msg = if tpass_len == 0 {
                            c"empty password"
                        } else {
                            c"maybe wrong password"
                        };
                        // SAFETY: a compile-time-constant site with NUL-terminated message text.
                        unsafe { raise_site_data(&STORE_RESULT_602, msg.as_ptr()) };
                        break 'parse;
                    }
                }

                // SAFETY: `p12` is live; `pass` is NULL or NUL-terminated; the three out-slots are
                // this frame's.
                if unsafe { PKCS12_parse(p12, pass, &raw mut pkey, &raw mut cert, &raw mut chain) }
                    != 0
                {
                    let mut infos: *mut OpenSslStack = OPENSSL_sk_new_null();
                    let mut osi_pkey: *mut OsslStoreInfo = ptr::null_mut();
                    let mut osi_cert: *mut OsslStoreInfo = ptr::null_mut();
                    let mut osi_ca: *mut OsslStoreInfo = ptr::null_mut();

                    ok = 1; /* Parsing went through correctly! */

                    if !infos.is_null() {
                        if !pkey.is_null() {
                            // SAFETY: `pkey` transfers to the object.
                            osi_pkey = unsafe { super::store_lib::OSSL_STORE_INFO_new_PKEY(pkey) };
                            // SAFETY: `infos` is a fresh stack; `osi_pkey` is the object built.
                            let pushed = !osi_pkey.is_null()
                                && {
                                    pkey = ptr::null_mut();
                                    true
                                }
                                && unsafe { OPENSSL_sk_push(infos, osi_pkey.cast::<c_void>()) }
                                    != 0;
                            if pushed {
                                osi_pkey = ptr::null_mut();
                            } else {
                                ok = 0;
                            }
                        }
                        if ok != 0 && !cert.is_null() {
                            // SAFETY: `cert` transfers to the object.
                            osi_cert = unsafe {
                                super::store_lib::OSSL_STORE_INFO_new_CERT(cert.cast::<c_void>())
                            };
                            // SAFETY: `infos` is a live stack; `osi_cert` is the object built.
                            let pushed = !osi_cert.is_null()
                                && {
                                    cert = ptr::null_mut();
                                    true
                                }
                                && unsafe { OPENSSL_sk_push(infos, osi_cert.cast::<c_void>()) }
                                    != 0;
                            if pushed {
                                osi_cert = ptr::null_mut();
                            } else {
                                ok = 0;
                            }
                        }
                        // SAFETY: `chain` is a live stack.
                        while ok != 0 && unsafe { OPENSSL_sk_num(chain) } > 0 {
                            // SAFETY: `chain` is live and non-empty.
                            let ca = unsafe { OPENSSL_sk_value(chain, 0) }.cast::<X509>();

                            // SAFETY: `ca` is the borrowed chain element; `OSSL_STORE_INFO_new_CERT`
                            // takes ownership of a fresh reference the shift hands over.
                            osi_ca = unsafe {
                                super::store_lib::OSSL_STORE_INFO_new_CERT(ca.cast::<c_void>())
                            };
                            // SAFETY: `chain` is live; `osi_ca` is the object built.
                            let good = !osi_ca.is_null()
                                && !unsafe { OPENSSL_sk_shift(chain) }.is_null()
                                && unsafe { OPENSSL_sk_push(infos, osi_ca.cast::<c_void>()) } != 0;
                            if good {
                                osi_ca = ptr::null_mut();
                            } else {
                                ok = 0;
                            }
                        }
                    }
                    // SAFETY: `pkey` is NULL or a key this frame owns.
                    unsafe { EVP_PKEY_free(pkey) };
                    // SAFETY: `cert` is NULL or a cert this frame owns.
                    unsafe { X509_free(cert) };
                    // SAFETY: `chain` is NULL or a stack of `X509`; the thunk frees each element
                    // and the container.
                    unsafe { OPENSSL_sk_pop_free(chain, Some(x509_free_void)) };
                    // SAFETY: each is NULL or an object this frame holds.
                    unsafe {
                        super::store_lib::OSSL_STORE_INFO_free(osi_pkey);
                        super::store_lib::OSSL_STORE_INFO_free(osi_cert);
                        super::store_lib::OSSL_STORE_INFO_free(osi_ca);
                    }
                    if ok == 0 {
                        // SAFETY: `infos` is NULL or a stack of `OSSL_STORE_INFO`; the thunk frees
                        // each element and the container.
                        unsafe { OPENSSL_sk_pop_free(infos, Some(store_info_free_void)) };
                        infos = ptr::null_mut();
                    }
                    // SAFETY: `ctx` is live per the contract.
                    unsafe { (*ctx).cached_info = infos };
                }
            }

            // SAFETY: `tpass` is this frame's buffer.
            unsafe { OPENSSL_cleanse(tpass.as_mut_ptr().cast::<c_void>(), tpass.len()) };
            // SAFETY: `p12` is NULL or this frame's own object.
            unsafe { PKCS12_free(p12) };
        }
        // SAFETY: `ctx` is live per the contract; the shift may answer NULL.
        let shifted = unsafe { OPENSSL_sk_shift((*ctx).cached_info) }.cast::<OsslStoreInfo>();
        // SAFETY: `v` is a live out-slot per the contract.
        unsafe { *v = shifted };
    }

    ok
}

/// `int ossl_store_handle_load_result(const OSSL_PARAM params[], void *arg)` —
/// `store_result.c:87-172`, declared `OSSL_CALLBACK` at `store_local.h:178`.
///
/// This is the object-abstraction reader [`crate::store::store_lib::OSSL_STORE_load`] hands to a
/// fetched loader's `p_load`. It is internal — no `#[no_mangle]`, exactly as the authority
/// reaches it by callback pointer rather than by symbol.
///
/// # Safety
/// `params` must be a terminated parameter array and `arg` a live `OsslStoreLoadResultData`
/// whose `ctx` is a live fetched-loader context.
pub(crate) unsafe extern "C" fn ossl_store_handle_load_result(
    params: *const OsslParam,
    arg: *mut c_void,
) -> c_int {
    let cbdata = arg.cast::<OsslStoreLoadResultData>();
    // SAFETY: `cbdata` is live per the contract.
    let v = unsafe { ptr::addr_of_mut!((*cbdata).v) };
    // SAFETY: `cbdata` is live per the contract.
    let ctx = unsafe { (*cbdata).ctx };
    // SAFETY: `ctx` is live and its fetched loader is a provider loader.
    let provider = unsafe { OSSL_STORE_LOADER_get0_provider((*ctx).fetched_loader) };
    // SAFETY: `provider` is live.
    let libctx = unsafe { ossl_provider_libctx(provider) };
    // SAFETY: `ctx` is live per the contract.
    let propq = unsafe { (*ctx).properties };
    let mut helper_data = ExtractedParamData {
        object_type: OSSL_OBJECT_UNKNOWN,
        data_type: ptr::null(),
        input_type: ptr::null(),
        data_structure: ptr::null(),
        utf8_data: ptr::null(),
        octet_data: ptr::null(),
        octet_data_size: 0,
        reference: ptr::null(),
        reference_size: 0,
        desc: ptr::null(),
    };

    // SAFETY: each `locate` reads a terminated array; each `get_*` writes one live field.
    unsafe {
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_TYPE);
        if !p.is_null() && OSSL_PARAM_get_int(p, &raw mut helper_data.object_type) == 0 {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
        if !p.is_null() && OSSL_PARAM_get_utf8_string_ptr(p, &raw mut helper_data.data_type) == 0 {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA);
        if !p.is_null()
            && OSSL_PARAM_get_octet_string_ptr(
                p,
                &raw mut helper_data.octet_data,
                &raw mut helper_data.octet_data_size,
            ) == 0
            && OSSL_PARAM_get_utf8_string_ptr(p, &raw mut helper_data.utf8_data) == 0
        {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE);
        if !p.is_null()
            && OSSL_PARAM_get_utf8_string_ptr(p, &raw mut helper_data.data_structure) == 0
        {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_INPUT_TYPE);
        if !p.is_null() && OSSL_PARAM_get_utf8_string_ptr(p, &raw mut helper_data.input_type) == 0 {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
        if !p.is_null()
            && OSSL_PARAM_get_octet_string_ptr(
                p,
                &raw mut helper_data.reference,
                &raw mut helper_data.reference_size,
            ) == 0
        {
            return 0;
        }
        let p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DESC);
        if !p.is_null() && OSSL_PARAM_get_utf8_string_ptr(p, &raw mut helper_data.desc) == 0 {
            return 0;
        }
    }

    /*
     * The helper functions return 0 on actual errors, otherwise 1, even if
     * they didn't fill out |*v|.
     */
    'err: {
        // SAFETY: a mark on the error queue.
        ERR_set_mark();
        // SAFETY: `v` is a live out-slot in `cbdata`.
        if unsafe { *v }.is_null()
            // SAFETY: `v` and `helper_data` are this frame's live slots.
            && unsafe { try_name(&raw mut helper_data, v) } == 0
        {
            break 'err;
        }
        // SAFETY: a mark was set above.
        ERR_pop_to_mark();
        // SAFETY: a mark on the error queue.
        ERR_set_mark();
        // SAFETY: `v` is a live out-slot in `cbdata`.
        if unsafe { *v }.is_null()
            // SAFETY: `v`, `helper_data` and `ctx` are this frame's live slots; `provider`,
            // `libctx` and `propq` are the caller's.
            && unsafe { try_key(&raw mut helper_data, v, ctx, provider, libctx, propq) } == 0
        {
            break 'err;
        }
        // SAFETY: a mark was set above.
        ERR_pop_to_mark();
        // SAFETY: a mark on the error queue.
        ERR_set_mark();
        // SAFETY: `v` is a live out-slot in `cbdata`.
        if unsafe { *v }.is_null()
            // SAFETY: `v` and `helper_data` are this frame's live slots; `libctx` and `propq`
            // are the caller's.
            && unsafe { try_cert(&raw mut helper_data, v, libctx, propq) } == 0
        {
            break 'err;
        }
        // SAFETY: a mark was set above.
        ERR_pop_to_mark();
        // SAFETY: a mark on the error queue.
        ERR_set_mark();
        // SAFETY: `v` is a live out-slot in `cbdata`.
        if unsafe { *v }.is_null()
            // SAFETY: `v` and `helper_data` are this frame's live slots; `libctx` and `propq`
            // are the caller's.
            && unsafe { try_crl(&raw mut helper_data, v, libctx, propq) } == 0
        {
            break 'err;
        }
        // SAFETY: a mark was set above.
        ERR_pop_to_mark();
        // SAFETY: a mark on the error queue.
        ERR_set_mark();
        // SAFETY: `v` is a live out-slot in `cbdata`.
        if unsafe { *v }.is_null()
            // SAFETY: `v`, `helper_data` and `ctx` are this frame's live slots; `libctx` and
            // `propq` are the caller's.
            && unsafe { try_pkcs12(&raw mut helper_data, v, ctx, libctx, propq) } == 0
        {
            break 'err;
        }
        // SAFETY: a mark was set above.
        ERR_pop_to_mark();

        // SAFETY: `v` is a live out-slot per the contract.
        if unsafe { *v }.is_null() {
            let mut hint: *const c_char = c"".as_ptr();

            // SAFETY: `libctx` and the literal name are per the API's contract.
            if unsafe { OSSL_PROVIDER_available(libctx, c"default".as_ptr()) } == 0 {
                hint = c":maybe need to load the default provider?".as_ptr();
            }
            if !provider.is_null() {
                let mut msg = [0 as c_char; 1024];
                // SAFETY: `msg` is writable for its length; `provider` is live and `hint` is
                // NUL-terminated.
                unsafe {
                    BIO_snprintf(
                        msg.as_mut_ptr(),
                        msg.len(),
                        c"provider=%s%s".as_ptr(),
                        OSSL_PROVIDER_get0_name(provider),
                        hint,
                    );
                    raise_site_data(&STORE_RESULT_160, msg.as_ptr());
                }
            // SAFETY: `hint` is NUL-terminated, so the first byte is readable.
            } else if unsafe { *hint } != 0 {
                // SAFETY: a compile-time-constant site; `hint` is NUL-terminated.
                unsafe { raise_site_data(&STORE_RESULT_163, hint) };
            } else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&STORE_RESULT_165) };
            }
        }

        // SAFETY: `v` is a live out-slot per the contract.
        return c_int::from(!unsafe { *v }.is_null());
    }

    // err:
    // SAFETY: a mark was set above.
    ERR_clear_last_mark();
    0
}
