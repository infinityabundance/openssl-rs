//! `crypto/evp/legacy_wp.c` — the static `EVP_MD` object `EVP_whirlpool()` returns.
//!
//! # A pkey type of **zero**, and the only block size that is a division
//!
//! `whirlpool_md` (`legacy_wp.c:22-30`) writes a bare **`0`** in its `flags` field, not
//! `EVP_MD_FLAG_DIGALGID_ABSENT`, so the helper below takes `flags` as an argument and the call site
//! states the authority's `0`.
//!
//! Its `pkey_type` is also a literal **`0`** (`legacy_wp.c:24`) — alone among the legacy digest
//! objects in this crate, which all name a `NID_*WithRSA*`. That is transcribed literally rather
//! than "corrected" to `NID_whirlpool`.
//!
//! The block size is `WHIRLPOOL_BBLOCK / 8` (`legacy_wp.c:29`) — 512 bits over 8, i.e. 64 — and it
//! is the one object whose block-size initialiser is an expression rather than a `*_CBLOCK` name.
//!
//! The callbacks are `IMPLEMENT_LEGACY_EVP_MD_METH(wp, WHIRLPOOL)` (`legacy_meth.h:10-22`) over the
//! crate's `WHIRLPOOL_Init`/`_Update`/`_Final`, with a `NULL` `md_ctrl` and `ctx_size` zero for the
//! reason the SHA file records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::wp::{WHIRLPOOL_Final, WHIRLPOOL_Init, WHIRLPOOL_Update, WhirlpoolCtx};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::NID_whirlpool;

/// `WHIRLPOOL_DIGEST_LENGTH` — `include/openssl/whrlpool.h:28`, which is `512 / 8`.
const WHIRLPOOL_DIGEST_LENGTH: c_int = 64;
/// `WHIRLPOOL_BBLOCK` — `include/openssl/whrlpool.h:32`. The authority's block size is this over
/// eight.
const WHIRLPOOL_BBLOCK: c_int = 512;

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
// `IMPLEMENT_LEGACY_EVP_MD_METH(wp, WHIRLPOOL)` — `legacy_meth.h:10-22`, written out.
// ---------------------------------------------------------------------------------------------

/// `wp_init` — `legacy_meth.h:11-14`, with `fn` = `WHIRLPOOL`.
unsafe extern "C" fn wp_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract; `md_data` reads a field of a live context and `WHIRLPOOL_Init`
    // writes the block it points at.
    unsafe { WHIRLPOOL_Init(md_data(ctx).cast::<WhirlpoolCtx>()) }
}

/// `wp_update` — `legacy_meth.h:15-18`.
unsafe extern "C" fn wp_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { WHIRLPOOL_Update(md_data(ctx).cast::<WhirlpoolCtx>(), data, count) }
}

/// `wp_final` — `legacy_meth.h:19-22`. The authority's macro is
/// `fn##_Final(md, EVP_MD_CTX_get0_md_data(ctx))`, and `WHIRLPOOL_Final` takes the digest first.
unsafe extern "C" fn wp_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { WHIRLPOOL_Final(md, md_data(ctx).cast::<WhirlpoolCtx>()) }
}

/// `whirlpool_md` — `legacy_wp.c:22-30`. `flags` is **0**, `pkey_type` is the authority's literal
/// **0**, and `md_ctrl` is **NULL**; `block_size` is the authority's `WHIRLPOOL_BBLOCK / 8`.
static WHIRLPOOL_MD: StaticMd = legacy_md(
    NID_whirlpool,
    0,
    WHIRLPOOL_DIGEST_LENGTH,
    0,
    WHIRLPOOL_BBLOCK / 8,
    Some(wp_init),
    Some(wp_update),
    Some(wp_final),
    None,
);

/// `const EVP_MD *EVP_whirlpool(void)` — `legacy_wp.c:32-35`.
///
/// The answer is a constant, so this is not an `unsafe` function: the authority's own body reads
/// nothing. Handing the pointer to `EVP_DigestInit_ex` still digests, because the library fetches
/// the provider implementation by NID and replaces this object before any of its callbacks would
/// run (`src/evp/digest.rs:124-145`).
#[no_mangle]
pub extern "C" fn EVP_whirlpool() -> *const EvpMd {
    core::ptr::addr_of!(WHIRLPOOL_MD.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The object against the authority's own fields, read from `legacy_wp.c:22-30`.
    ///
    /// The things this catches that a name-and-size test would not: `flags` is **zero**, the
    /// `pkey_type` is the authority's literal **0** rather than `NID_whirlpool`, and `block_size` is
    /// the authority's `WHIRLPOOL_BBLOCK / 8`.
    #[test]
    fn the_object_is_the_authoritys_fields() {
        let md = &WHIRLPOOL_MD.0;
        assert_eq!(md.type_, NID_whirlpool);
        assert_eq!(md.pkey_type, 0);
        assert_eq!(md.md_size, 64);
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
        assert!(!EVP_whirlpool().is_null());
        assert_eq!(EVP_whirlpool(), core::ptr::addr_of!(WHIRLPOOL_MD.0));
    }
}
