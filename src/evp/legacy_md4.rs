//! `crypto/evp/legacy_md4.c` — the static `EVP_MD` object `EVP_md4()` returns.
//!
//! # The same `flags`-is-zero shape as MD5 and RIPEMD-160
//!
//! `md4_md` (`legacy_md4.c:22-29`) writes a bare **`0`** in its `flags` field, not
//! `EVP_MD_FLAG_DIGALGID_ABSENT`, which [`crate::evp::legacy_sha`]'s helper supplies for all seven of
//! its objects. The helper below therefore takes `flags` as an argument and the call site states the
//! authority's `0` rather than inheriting a bit the MD4 object does not carry.
//!
//! Everything else is the sibling files' shape: the callback triple
//! `IMPLEMENT_LEGACY_EVP_MD_METH(md4, MD4)` (`legacy_meth.h:10-22`) over the crate's
//! `MD4_Init`/`_Update`/`_Final`, a `NULL` `md_ctrl`, and `ctx_size` zero for the reason the SHA
//! file records — a legacy method is replaced by its provider counterpart before any callback reads
//! `md_data`, so the zero is never a read of unallocated storage.
//!
//! The pkey NID is `NID_md4WithRSAEncryption` (`legacy_md4.c:24`), which is **not** `NID_md4`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::md4::{MD4_Final, MD4_Init, MD4_Update, Md4Ctx};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::{NID_md4, NID_md4WithRSAEncryption};

/// `MD4_DIGEST_LENGTH` — `include/openssl/md4.h:28`.
const MD4_DIGEST_LENGTH: c_int = 16;
/// `MD4_CBLOCK` — `include/openssl/md4.h:39`.
const MD4_CBLOCK: c_int = 64;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h:255`. A global method is not reference counted and not
/// freed, which is why the mutating arms of `EVP_MD_up_ref`/`EVP_MD_free` both refuse it.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_MD_CTX_get0_md_data(ctx)` — `crypto/evp/evp_lib.c:1087`, which the authority's legacy macro
/// calls. A bare `return ctx->md_data;`, factored out because all three callbacks below open with
/// it.
///
/// # Safety
/// `ctx` must be a live `EVP_MD_CTX`.
unsafe fn md_data(ctx: *mut EvpMdCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).md_data }
}

/// A `static` `EVP_MD`. The wrapper claims `Sync` for a value that is only ever read: a heap
/// `EvpMd` is mutable and synchronised by its reference count, while a compile-time constant one is
/// neither.
///
/// **A private copy per file, not an import**, chosen to keep each legacy file independent; see the
/// identical note in `court/legacy_md5.rs`.
struct StaticMd(EvpMd);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every mutating
// arm in the digest module is guarded by `origin`, and `EVP_ORIG_GLOBAL` is not `EVP_ORIG_DYNAMIC`,
// so `EVP_MD_up_ref` and `EVP_MD_free` both refuse these objects.
unsafe impl Sync for StaticMd {}

/// `LEGACY_EVP_MD_METH_TABLE`'s shape, as a `const fn`. `flags` is an argument because the
/// authority's object writes `0` there and the SHA file's shared value would be wrong; the rest of
/// the legacy half is the macro's six values and the provider half stays zero.
#[allow(clippy::too_many_arguments)]
const fn legacy_md(
    type_: c_int,
    pkey_type: c_int,
    md_size: c_int,
    flags: c_ulong,
    block_size: c_int,
    init: Option<MdLegacyInitFn>,
    update: Option<MdLegacyUpdateFn>,
    final_: Option<MdLegacyFinalFn>,
    md_ctrl: Option<MdLegacyCtrlFn>,
) -> StaticMd {
    StaticMd(EvpMd {
        type_,
        pkey_type,
        md_size,
        flags,
        origin: EVP_ORIG_GLOBAL,
        init,
        update,
        final_,
        // The authority's table writes `NULL, NULL` for `copy` and `cleanup`.
        copy: None,
        cleanup: None,
        block_size,
        // **Zero, and that is the authority's value rather than an omission**; the fetch-replacement
        // arm replaces this method before any callback would read `md_data`.
        ctx_size: 0,
        md_ctrl,
        name_id: 0,
        type_name: core::ptr::null_mut(),
        description: core::ptr::null(),
        prov: core::ptr::null_mut(),
        refcnt: AtomicI32::new(0),
        newctx: None,
        dinit: None,
        dupdate: None,
        dfinal: None,
        dsqueeze: None,
        digest: None,
        freectx: None,
        copyctx: None,
        dupctx: None,
        get_params: None,
        set_ctx_params: None,
        get_ctx_params: None,
        gettable_params: None,
        settable_ctx_params: None,
        gettable_ctx_params: None,
    })
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_LEGACY_EVP_MD_METH(md4, MD4)` — `legacy_meth.h:10-22`, written out.
// ---------------------------------------------------------------------------------------------

/// `md4_init` — `legacy_meth.h:11-14`, with `fn` = `MD4`.
unsafe extern "C" fn md4_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract; `md_data` reads a field of a live context and `MD4_Init`
    // writes the block it points at.
    unsafe { MD4_Init(md_data(ctx).cast::<Md4Ctx>()) }
}

/// `md4_update` — `legacy_meth.h:15-18`.
unsafe extern "C" fn md4_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { MD4_Update(md_data(ctx).cast::<Md4Ctx>(), data, count) }
}

/// `md4_final` — `legacy_meth.h:19-22`. The authority's macro is
/// `fn##_Final(md, EVP_MD_CTX_get0_md_data(ctx))`, and `MD4_Final` takes the digest first.
unsafe extern "C" fn md4_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { MD4_Final(md, md_data(ctx).cast::<Md4Ctx>()) }
}

/// `md4_md` — `legacy_md4.c:22-29`. `flags` is **0** and `md_ctrl` is **NULL**, both the authority's
/// literals.
static MD4_MD: StaticMd = legacy_md(
    NID_md4,
    NID_md4WithRSAEncryption,
    MD4_DIGEST_LENGTH,
    0,
    MD4_CBLOCK,
    Some(md4_init),
    Some(md4_update),
    Some(md4_final),
    None,
);

/// `const EVP_MD *EVP_md4(void)` — `legacy_md4.c:31-34`.
///
/// The answer is a constant, so this is not an `unsafe` function: the authority's own body reads
/// nothing. Handing the pointer to `EVP_DigestInit_ex` still digests, because the library fetches
/// the provider implementation by NID and replaces this object before any of its callbacks would
/// run (`src/evp/digest.rs:124-145`).
#[no_mangle]
pub extern "C" fn EVP_md4() -> *const EvpMd {
    core::ptr::addr_of!(MD4_MD.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object against the authority's own fields, read from `legacy_md4.c:22-29`.
    ///
    /// `flags` is checked to be **zero** rather than `EVP_MD_FLAG_DIGALGID_ABSENT`: the SHA file's
    /// helper would have supplied the latter, and this is an object that would expose the copy.
    #[test]
    fn the_object_is_the_authoritys_fields() {
        let md = &MD4_MD.0;
        assert_eq!(md.type_, NID_md4);
        assert_eq!(md.pkey_type, NID_md4WithRSAEncryption);
        assert_eq!(md.md_size, 16);
        assert_eq!(md.block_size, 64);
        assert_eq!(md.flags, 0);
        assert_eq!(md.origin, EVP_ORIG_GLOBAL);
        assert_eq!(md.ctx_size, 0);
        assert_eq!(md.name_id, 0);
        assert!(md.type_name.is_null());
        assert!(md.prov.is_null());
        assert!(md.copy.is_none());
        assert!(md.cleanup.is_none());
        assert!(md.md_ctrl.is_none());
        assert!(md.init.is_some());
        assert!(md.update.is_some());
        assert!(md.final_.is_some());
    }

    /// The entry point answers the address of its own object and is not NULL.
    #[test]
    fn the_entry_point_answers_its_own_object() {
        assert!(!EVP_md4().is_null());
        assert_eq!(EVP_md4(), core::ptr::addr_of!(MD4_MD.0));
    }
}
