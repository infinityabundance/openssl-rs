//! Phase 10 — `providers/implementations/encode_decode/endecoder_common.c`: the two shared
//! helpers the provider codec units stand on, plus the `OSSL_DISPATCH` pilfers behind them.
//!
//! `endecoder_common.c` is 103 lines and defines six functions: four `ossl_prov_get_keymgmt_*`
//! pilfers, `ossl_prov_import_key`, `ossl_prov_free_key` and `ossl_read_der`. It is the *shared
//! base* of every provider codec unit — `encode_key2any.c`, `encode_key2text.c`,
//! `encode_key2blob.c`, `decode_der2key.c`, `decode_epki2pki.c` and the rest all call
//! `ossl_prov_import_key`/`ossl_prov_free_key` from their `import_object`/`free_object` slots and
//! `ossl_read_der` from their decode arm — so it lands with the first of them rather than being
//! written twice.
//!
//! ## The pilfers read the crate's own keymgmt tables
//!
//! The authority walks a provider's `OSSL_DISPATCH` table looking for `OSSL_FUNC_KEYMGMT_*` ids and
//! returns the matching function. That is exactly what this module does over the crate's keymgmt
//! tables (`src/provider/rsa_kmgmt.rs`, `ecx_kmgmt.rs`, …): an id is a number, not a symbol, so the
//! four ids are spelled out one per constant against `include/openssl/core_dispatch.h`.
//!
//! ## `ossl_read_der` is a decoder-only reach
//!
//! It reads exactly one top-level DER object out of a core BIO through `asn1_d2i_read_bio`. The
//! text encoder never calls it; it is transcribed here because the unit is whole, and the decoder
//! unit that does call it is not yet landed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::asn1_d2i_read_bio;
use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::keymgmt::{
    KeymgmtExportFn, KeymgmtFreeFn, KeymgmtImportFn, KeymgmtNewFn, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_NEW,
};
use crate::params::OsslParam;
use crate::runtime::buffer::BufMem;
use crate::runtime::mem::CRYPTO_free;

/// `OSSL_FUNC_keymgmt_new_fn *ossl_prov_get_keymgmt_new(const OSSL_DISPATCH *fns)` —
/// `endecoder_common.c:16-25`.
///
/// # Safety
/// `fns` must be a terminated `OSSL_DISPATCH` table.
pub(crate) unsafe fn ossl_prov_get_keymgmt_new(fns: *const OsslDispatch) -> Option<KeymgmtNewFn> {
    // SAFETY: `fns` is a terminated table per the contract; the walk stops at the end entry.
    unsafe { pilfer::<KeymgmtNewFn>(fns, OSSL_FUNC_KEYMGMT_NEW) }
}

/// `OSSL_FUNC_keymgmt_free_fn *ossl_prov_get_keymgmt_free(const OSSL_DISPATCH *fns)` —
/// `endecoder_common.c:27-36`.
///
/// # Safety
/// `fns` must be a terminated `OSSL_DISPATCH` table.
pub(crate) unsafe fn ossl_prov_get_keymgmt_free(fns: *const OsslDispatch) -> Option<KeymgmtFreeFn> {
    // SAFETY: as above.
    unsafe { pilfer::<KeymgmtFreeFn>(fns, OSSL_FUNC_KEYMGMT_FREE) }
}

/// `OSSL_FUNC_keymgmt_import_fn *ossl_prov_get_keymgmt_import(const OSSL_DISPATCH *fns)` —
/// `endecoder_common.c:38-47`.
///
/// # Safety
/// `fns` must be a terminated `OSSL_DISPATCH` table.
pub(crate) unsafe fn ossl_prov_get_keymgmt_import(
    fns: *const OsslDispatch,
) -> Option<KeymgmtImportFn> {
    // SAFETY: as above.
    unsafe { pilfer::<KeymgmtImportFn>(fns, OSSL_FUNC_KEYMGMT_IMPORT) }
}

/// `OSSL_FUNC_keymgmt_export_fn *ossl_prov_get_keymgmt_export(const OSSL_DISPATCH *fns)` —
/// `endecoder_common.c:49-58`.
///
/// `#[allow(dead_code)]`'s reason: **its caller is the decoder half.** `decode_der2key.c`'s
/// `der2key_export_object` is the only reader, and that unit is not landed; the pilfer is here
/// because the unit is whole, the same way `ossl_read_der` is.
///
/// # Safety
/// `fns` must be a terminated `OSSL_DISPATCH` table.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_prov_get_keymgmt_export(
    fns: *const OsslDispatch,
) -> Option<KeymgmtExportFn> {
    // SAFETY: as above.
    unsafe { pilfer::<KeymgmtExportFn>(fns, OSSL_FUNC_KEYMGMT_EXPORT) }
}

/// The walk the four pilfers share: return the function of the first entry whose `function_id` is
/// `id`, or `None` at the table's end. `entry_function` is the crate's one reader of a dispatch
/// slot, so the id-to-type correspondence stays in one place.
///
/// # Safety
/// `fns` must be a terminated `OSSL_DISPATCH` table and the entry named by `id` must carry a
/// function of type `T`.
unsafe fn pilfer<T: Copy>(fns: *const OsslDispatch, id: c_int) -> Option<T> {
    if fns.is_null() {
        return None;
    }
    let mut entry = fns;
    // SAFETY: `entry` walks a terminated table; each read is within it.
    unsafe {
        while (*entry).function_id != OSSL_DISPATCH_END {
            if (*entry).function_id == id {
                return entry_function::<T>(entry);
            }
            entry = entry.add(1);
        }
    }
    None
}

/// `void *ossl_prov_import_key(const OSSL_DISPATCH *fns, void *provctx, int selection,
/// const OSSL_PARAM params[])` — `endecoder_common.c:60-76`.
///
/// A new keydata is built through the keymgmt's own `new`, filled through its `import`, and freed
/// through its `free` if either step fails. All three must be present or nothing is attempted.
///
/// # Safety
/// `fns` must be a terminated keymgmt dispatch table; `provctx` the provider context; `params` a
/// live, `key`-terminated array.
pub(crate) unsafe fn ossl_prov_import_key(
    fns: *const OsslDispatch,
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: `fns` is a keymgmt table per the contract.
    let kmgmt_new = unsafe { ossl_prov_get_keymgmt_new(fns) };
    // SAFETY: as above.
    let kmgmt_free = unsafe { ossl_prov_get_keymgmt_free(fns) };
    // SAFETY: as above.
    let kmgmt_import = unsafe { ossl_prov_get_keymgmt_import(fns) };
    let mut key: *mut c_void = ptr::null_mut();

    if let (Some(new), Some(import), Some(free)) = (kmgmt_new, kmgmt_import, kmgmt_free) {
        // SAFETY: each callback is the keymgmt's own, called with the arguments its contract names.
        unsafe {
            key = new(provctx);
            if key.is_null() || import(key, selection, params) == 0 {
                free(key);
                key = ptr::null_mut();
            }
        }
    }
    key
}

/// `void ossl_prov_free_key(const OSSL_DISPATCH *fns, void *key)` — `endecoder_common.c:78-84`.
///
/// # Safety
/// `fns` must be a terminated keymgmt dispatch table; `key` its own keydata or NULL.
pub(crate) unsafe fn ossl_prov_free_key(fns: *const OsslDispatch, key: *mut c_void) {
    // SAFETY: `fns` is a keymgmt table per the contract.
    if let Some(free) = unsafe { ossl_prov_get_keymgmt_free(fns) } {
        // SAFETY: `free` is the keymgmt's own and `key` is its object.
        unsafe { free(key) };
    }
}

/// `int ossl_read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin, unsigned char **data, long *len)` —
/// `endecoder_common.c:86-103`.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the decoder units.** Every `*2key` decoder's
/// `decode` arm reads its DER through this function, and none of them is landed; it is transcribed
/// because the unit is whole. `provctx` is unused by this crate's core-BIO bridge (`prov/bio_prov.c`
/// is absent), which is why it is `_provctx` here.
///
/// The DER buffer handed back is the `BUF_MEM`'s own data, which the caller frees with
/// `OPENSSL_free`; the `BUF_MEM` header itself is released here.
///
/// # Safety
/// `_provctx` must be a live provider context, `cin` a live core BIO, and `data`/`len` writable.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_read_der(
    _provctx: *mut c_void,
    cin: *mut c_void,
    data: *mut *mut c_uchar,
    len: *mut c_long,
) -> c_int {
    let mut mem: *mut BufMem = ptr::null_mut();
    // SAFETY: `cin` is the core BIO the caller handed over; the bridge takes its own reference.
    let in_ = unsafe { crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }
    // SAFETY: `in_` is a live BIO and `mem` is this frame's out-parameter.
    let ok = unsafe { asn1_d2i_read_bio(in_, &mut mem) } >= 0;
    if ok {
        // SAFETY: `mem` is a live BUF_MEM from the read; its data and length are the caller's now.
        unsafe {
            *data = (*mem).data.cast::<c_uchar>();
            *len = (*mem).length as c_long;
            CRYPTO_free(mem.cast::<c_void>(), ptr::null(), 0);
        }
    }
    // SAFETY: `in_` is live and this call owns the reference the bridge took.
    unsafe { crate::runtime::bio::BIO_free(in_) };
    c_int::from(ok)
}
