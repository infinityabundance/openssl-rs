//! `crypto/sm3/legacy_sm3.c` — the static `EVP_MD` object `EVP_sm3()` returns.
//!
//! # The lower-case macro, because the construction's entry points are `ossl_*`
//!
//! SM3's internal API is `ossl_sm3_init`/`_update`/`_final` (`include/internal/sm3.h`), so the
//! authority uses `IMPLEMENT_LEGACY_EVP_MD_METH_LC(sm3_int, ossl_sm3)` (`legacy_sm3.c:15`,
//! `legacy_meth.h:24-36`), which lower-cases its callee rather than upper-casing it. The callbacks
//! below are that macro written out over the crate's [`crate::digest::sm3`] functions; the naming
//! `sm3_int_*` is the authority's and distinguishes them from the `EVP_sm3` entry point.
//!
//! `sm3_md` (`legacy_sm3.c:17-25`) writes a bare **`0`** in its `flags` field, not
//! `EVP_MD_FLAG_DIGALGID_ABSENT`, so the helper below takes `flags` as an argument and the call site
//! states the authority's `0`. Its `md_ctrl` is **NULL** and its `ctx_size` is zero for the reason
//! the SHA file records. The pkey NID is `NID_sm3WithRSAEncryption` (`legacy_sm3.c:19`), which is
//! **not** `NID_sm3`.
//!
//! The module sits at `src/sm3/` because the authority's translation unit is `crypto/sm3/`, even
//! though the SM3 primitive itself is transcribed under [`crate::digest::sm3`] — the module layout
//! follows the defining unit, which is the crate's rule for the legacy statics.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::sm3::{ossl_sm3_final, ossl_sm3_init, ossl_sm3_update, Sm3Ctx};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::{NID_sm3, NID_sm3WithRSAEncryption};

/// `SM3_DIGEST_LENGTH` — `include/internal/sm3.h:22`.
const SM3_DIGEST_LENGTH: c_int = 32;
/// `SM3_CBLOCK` — `include/internal/sm3.h:25`.
const SM3_CBLOCK: c_int = 64;

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

/// The authority's `sm3_int_init` writes through `EVP_MD_CTX_get0_md_data(ctx)` without testing
/// it. That is sound only when the EVP layer supplied the block; the exported
/// `EVP_MD_meth_get_init` also hands this callback to any C caller, and `EVP_MD_CTX_new()`
/// zero-fills the context, so `md_data` is NULL. The crate refuses that shape with the C
/// initialise failure value `0` instead of reproducing the authority's NULL write
/// (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-LEGACY-MD-INIT-MD-DATA-1`).
///
/// A context establishes a writable block in exactly two ways:
///
/// * `digest` is this very table object (`owner`) — the transcribed legacy-table shape; or
/// * `digest` is another live method whose `ctx_size` is at least `size` — the block
///   `evp_md_init_legacy` allocated for that method.
///
/// A NULL context, a NULL `md_data`, a NULL method and a too-small `app_datasize` all refuse.
///
/// # Safety
/// `ctx` must be NULL or point to a live `EvpMdCtx`; `owner` must be a live `EvpMd`, the table
/// object that installs this callback.
unsafe fn init_md_data(
    ctx: *mut EvpMdCtx,
    owner: *const EvpMd,
    size: usize,
) -> Option<*mut c_void> {
    if ctx.is_null() {
        return None;
    }
    // SAFETY: `ctx` is NULL or live per the contract.
    let md_data = unsafe { (*ctx).md_data };
    // SAFETY: as above.
    let digest = unsafe { (*ctx).digest };
    if md_data.is_null() || digest.is_null() {
        return None;
    }
    if core::ptr::eq(digest, owner) {
        return Some(md_data);
    }
    // SAFETY: `digest` is a live method: a context's method is only ever installed from a method
    // the library owns, and a NULL or dangling method is not a C-valid context state.
    let ctx_size = unsafe { (*digest).ctx_size };
    if ctx_size >= 0 && ctx_size as usize >= size {
        Some(md_data)
    } else {
        None
    }
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
// `IMPLEMENT_LEGACY_EVP_MD_METH_LC(sm3_int, ossl_sm3)` — `legacy_meth.h:24-36`, written out.
// ---------------------------------------------------------------------------------------------

/// `sm3_int_init` — `legacy_meth.h:25-28`, with `fn` = `ossl_sm3`.
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`. The callback checks the context's method
/// and block before writing: a fresh `EVP_MD_CTX_new()` (`md_data == NULL`), a NULL context, a
/// context with no method and a method whose `app_datasize` is too small all answer `0`, the C
/// initialise failure value, instead of performing the authority's NULL write. The normal table
/// shape — a writable `SM3_CTX` behind a context bound to this method — still initialises and
/// returns `1`. The refusal is recorded as `docs/SECURITY_DIVERGENCE_POLICY.md`
/// `D-LEGACY-MD-INIT-MD-DATA-1`.
unsafe extern "C" fn sm3_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SM3_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SM3_MD.0),
            core::mem::size_of::<Sm3Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SM3_CTX`.
    unsafe { ossl_sm3_init(block.cast::<Sm3Ctx>()) }
}

/// `sm3_int_update` — `legacy_meth.h:29-32`.
unsafe extern "C" fn sm3_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { ossl_sm3_update(md_data(ctx).cast::<Sm3Ctx>(), data, count) }
}

/// `sm3_int_final` — `legacy_meth.h:33-36`. The authority's macro is
/// `fn##_final(md, EVP_MD_CTX_get0_md_data(ctx))`, and `ossl_sm3_final` takes the digest first.
unsafe extern "C" fn sm3_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { ossl_sm3_final(md, md_data(ctx).cast::<Sm3Ctx>()) }
}

/// `sm3_md` — `legacy_sm3.c:17-25`. `flags` is **0** and `md_ctrl` is **NULL**, both the authority's
/// literals.
static SM3_MD: StaticMd = legacy_md(
    NID_sm3,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    SM3_CBLOCK,
    Some(sm3_int_init),
    Some(sm3_int_update),
    Some(sm3_int_final),
    None,
);

/// `const EVP_MD *EVP_sm3(void)` — `legacy_sm3.c:27-30`.
///
/// The answer is a constant, so this is not an `unsafe` function: the authority's own body reads
/// nothing. Handing the pointer to `EVP_DigestInit_ex` still digests, because the library fetches
/// the provider implementation by NID and replaces this object before any of its callbacks would
/// run (`src/evp/digest.rs:124-145`).
#[no_mangle]
pub extern "C" fn EVP_sm3() -> *const EvpMd {
    core::ptr::addr_of!(SM3_MD.0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// The object against the authority's own fields, read from `legacy_sm3.c:17-25`.
    ///
    /// `flags` is checked to be **zero** rather than `EVP_MD_FLAG_DIGALGID_ABSENT`: the SHA file's
    /// helper would have supplied the latter, and this is an object that would expose the copy.
    #[test]
    fn the_object_is_the_authoritys_fields() {
        let md = &SM3_MD.0;
        assert_eq!(md.type_, NID_sm3);
        assert_eq!(md.pkey_type, NID_sm3WithRSAEncryption);
        assert_eq!(md.md_size, 32);
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
        assert!(!EVP_sm3().is_null());
        assert_eq!(EVP_sm3(), core::ptr::addr_of!(SM3_MD.0));
    }

    /// An `EVP_MD_CTX` bound to `md` and a writable digest block, with no provider state.
    fn bound_context(md: *const EvpMd, block: *mut c_void) -> EvpMdCtx {
        EvpMdCtx {
            reqdigest: md,
            digest: md,
            engine: core::ptr::null_mut(),
            flags: 0,
            md_data: block,
            pctx: core::ptr::null_mut(),
            update: None,
            algctx: core::ptr::null_mut(),
            fetched_digest: core::ptr::null_mut(),
        }
    }

    /// `EVP_MD_meth_get_init(EVP_sm3())` handed to a C caller, then called with a fresh
    /// `EVP_MD_CTX_new()` (`md_data == NULL`) and with a NULL context. The authority's
    /// `sm3_int_init` writes through `EVP_MD_CTX_get0_md_data(ctx)`, so both are a NULL write; the
    /// crate refuses both with `0`. The table's own path still produces SM3("abc").
    #[test]
    fn legacy_sm3_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_get_final, EVP_MD_meth_get_init,
            EVP_MD_meth_get_update,
        };

        // SAFETY: `EVP_sm3()` answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sm3()) }.expect("sm3_md has an init");
        // SAFETY: as above.
        let update = unsafe { EVP_MD_meth_get_update(EVP_sm3()) }.expect("sm3_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sm3()) }.expect("sm3_md has a final");

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        assert_eq!(unsafe { init(fresh) }, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        assert_eq!(unsafe { init(core::ptr::null_mut()) }, 0);

        let mut store = core::mem::MaybeUninit::<Sm3Ctx>::uninit();
        let mut ctx = bound_context(EVP_sm3(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sm3_md`, and `store` is a writable `SM3_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 32];
        // SAFETY: `output` is writable for the SM3 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
                0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
                0x8f, 0x4b, 0xa8, 0xe0,
            ],
            "SM3(\"abc\") changed"
        );
    }
}
