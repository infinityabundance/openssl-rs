//! `crypto/evp/legacy_md5.c` and `crypto/evp/legacy_md5_sha1.c` — the static `EVP_MD` objects
//! `EVP_md5()` and `EVP_md5_sha1()` return.
//!
//! # What is different from the seven SHA objects, and why that is the whole point of this file
//!
//! [`crate::evp::legacy_sha`]'s `legacy_md` hard-codes `flags` to
//! `EVP_MD_FLAG_DIGALGID_ABSENT`, because all seven of those objects carry that bit and only that
//! bit. **Neither object here carries any flag at all.** `legacy_md5.c:26` and
//! `legacy_md5_sha1.c:31` both write a bare `0` in the `flags` field, so the helper in this file
//! takes `flags` as an argument and each initialiser below states the authority's own value rather
//! than inheriting the SHA file's. A transcription that copied the SHA helper unchanged would put
//! `EVP_MD_FLAG_DIGALGID_ABSENT` on both objects and be wrong; the field test at the bottom is what
//! catches that.
//!
//! The other difference is `md_ctrl`. `md5_md` writes `NULL` (`legacy_md5.c:28`), while
//! `md5_sha1_md` writes `md5_sha1_int_ctrl` (`legacy_md5_sha1.c:34`), the SSLv3 master-secret arm
//! that forwards to `ossl_md5_sha1_ctrl`. That crate function already exists
//! (`src/digest/md5_sha1.rs:104`) and is what the callback calls.
//!
//! # `md5_sha1_md`'s two NIDs are the same number
//!
//! `legacy_md5_sha1.c:28-29` writes `NID_md5_sha1` in **both** the `type` and `pkey_type` slots —
//! the only object in this family whose two identity NIDs coincide. That is transcribed literally
//! below rather than "corrected".
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::md5::{MD5_Final, MD5_Init, MD5_Update, Md5Ctx};
use crate::digest::md5_sha1::{
    ossl_md5_sha1_ctrl, ossl_md5_sha1_final, ossl_md5_sha1_init, ossl_md5_sha1_update, Md5Sha1Ctx,
};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::{NID_md5, NID_md5WithRSAEncryption, NID_md5_sha1};

/// `MD5_DIGEST_LENGTH` — `include/openssl/md5.h:28`.
const MD5_DIGEST_LENGTH: c_int = 16;
/// `MD5_CBLOCK` — `include/openssl/md5.h:38`.
const MD5_CBLOCK: c_int = 64;
/// `MD5_SHA1_DIGEST_LENGTH` — `prov/md5_sha1.h:21`, which is `MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH`
/// = 16 + 20.
const MD5_SHA1_DIGEST_LENGTH: c_int = 36;
/// `MD5_SHA1_CBLOCK` — `prov/md5_sha1.h:22`, which is `MD5_CBLOCK`.
const MD5_SHA1_CBLOCK: c_int = 64;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h:255`. The origin that makes every mutating arm of
/// `EVP_MD_up_ref`/`EVP_MD_free` refuse: a global method is not reference counted and not freed.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_MD_CTX_get0_md_data(ctx)` — `crypto/evp/evp_lib.c:1087`, which the authority's legacy macros
/// call. It is a bare `return ctx->md_data;` and is factored out here for the same reason
/// [`crate::evp::legacy_sha`] factors it: every callback below opens with it.
///
/// # Safety
/// `ctx` must be a live `EVP_MD_CTX`.
unsafe fn md_data(ctx: *mut EvpMdCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).md_data }
}

/// A `static` `EVP_MD`. The wrapper claims `Sync` for a value that is only ever read, for the same
/// reason [`crate::evp::digest`]'s own `StaticMd` does: a heap `EvpMd` is mutable and synchronised
/// by its reference count, while a compile-time constant one is neither.
///
/// **This is a private copy per file, not an import**, chosen to keep each legacy file independent
/// of the others; the SHA file's copy is private to it and the task's convention is to duplicate
/// rather than widen that helper's visibility.
struct StaticMd(EvpMd);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every mutating
// arm in the digest module is guarded by `origin`, and `EVP_ORIG_GLOBAL` is not `EVP_ORIG_DYNAMIC`,
// so `EVP_MD_up_ref` and `EVP_MD_free` both refuse these objects.
unsafe impl Sync for StaticMd {}

/// `LEGACY_EVP_MD_METH_TABLE`'s shape, as a `const fn`, with `flags` passed through because the two
/// objects in this file disagree with the seven SHA objects and with each other about it.
///
/// The legacy half is the six values the macro supplies (`init`, `update`, `final`, `copy`,
/// `cleanup`, `block_size`, `ctx_size`, `md_ctrl`); the provider half plus the identity fields are
/// all zero, which is what a `static const` initialiser leaves them as, and `EVP_ORIG_GLOBAL` means
/// they stay that way for the life of the process.
///
/// `#[allow(clippy::too_many_arguments)]`'s reason is the authority's arity: `LEGACY_EVP_MD_METH_TABLE`
/// takes five arguments and `struct evp_md_st`'s legacy run is eight fields, so grouping them into a
/// helper struct would make these initialisers stop reading like the C they transcribe.
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
        // **Zero, and that is the authority's value rather than an omission.** A legacy method is
        // replaced by its provider counterpart before any callback reads `md_data`.
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
// `IMPLEMENT_LEGACY_EVP_MD_METH(md5, MD5)` — `legacy_meth.h:10-22`, written out.
// ---------------------------------------------------------------------------------------------

/// `md5_init` — `legacy_meth.h:11-14`, with `fn` = `MD5`.
unsafe extern "C" fn md5_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract; `md_data` reads a field of a live context and `MD5_Init`
    // writes the block it points at.
    unsafe { MD5_Init(md_data(ctx).cast::<Md5Ctx>()) }
}

/// `md5_update` — `legacy_meth.h:15-18`.
unsafe extern "C" fn md5_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { MD5_Update(md_data(ctx).cast::<Md5Ctx>(), data, count) }
}

/// `md5_final` — `legacy_meth.h:19-22`. Note the argument order: the authority's macro is
/// `fn##_Final(md, EVP_MD_CTX_get0_md_data(ctx))`, and `MD5_Final` takes the digest first.
unsafe extern "C" fn md5_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { MD5_Final(md, md_data(ctx).cast::<Md5Ctx>()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_LEGACY_EVP_MD_METH_LC(md5_sha1_int, ossl_md5_sha1)` — `legacy_meth.h:24-36`, the
// lower-case variant, plus the control function `legacy_md5_sha1.c:22-25`.
// ---------------------------------------------------------------------------------------------

/// `md5_sha1_int_init` — `legacy_md5_sha1.c:21` over `ossl_md5_sha1_init`.
unsafe extern "C" fn md5_sha1_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract; `md_data` is a live context's block.
    unsafe { ossl_md5_sha1_init(md_data(ctx).cast::<Md5Sha1Ctx>()) }
}

/// `md5_sha1_int_update` — the same macro over `ossl_md5_sha1_update`.
unsafe extern "C" fn md5_sha1_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { ossl_md5_sha1_update(md_data(ctx).cast::<Md5Sha1Ctx>(), data, count) }
}

/// `md5_sha1_int_final` — the same macro over `ossl_md5_sha1_final`.
unsafe extern "C" fn md5_sha1_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { ossl_md5_sha1_final(md, md_data(ctx).cast::<Md5Sha1Ctx>()) }
}

/// `md5_sha1_int_ctrl` — `legacy_md5_sha1.c:22-25`. Forwards the context's `md_data` and the four
/// control arguments straight to `ossl_md5_sha1_ctrl`, which answers `-2` for any command but
/// `EVP_CTRL_SSL3_MASTER_SECRET`.
unsafe extern "C" fn md5_sha1_int_ctrl(
    ctx: *mut EvpMdCtx,
    cmd: c_int,
    mslen: c_int,
    ms: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract; every argument is passed through unchanged.
    unsafe { ossl_md5_sha1_ctrl(md_data(ctx).cast::<Md5Sha1Ctx>(), cmd, mslen, ms) }
}

// ---------------------------------------------------------------------------------------------
// The two objects, in the authority's own order.
// ---------------------------------------------------------------------------------------------

/// `md5_md` — `legacy_md5.c:22-29`. `flags` is **0** and `md_ctrl` is **NULL**; both facts are the
/// authority's literals, not defaults.
static MD5_MD: StaticMd = legacy_md(
    NID_md5,
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,
    0,
    MD5_CBLOCK,
    Some(md5_init),
    Some(md5_update),
    Some(md5_final),
    None,
);

/// `md5_sha1_md` — `legacy_md5_sha1.c:27-36`. `flags` is **0** here too, and the two NIDs are the
/// same number; only the control function distinguishes the legacy half from `md5_md`.
static MD5_SHA1_MD: StaticMd = legacy_md(
    NID_md5_sha1,
    NID_md5_sha1,
    MD5_SHA1_DIGEST_LENGTH,
    0,
    MD5_SHA1_CBLOCK,
    Some(md5_sha1_int_init),
    Some(md5_sha1_int_update),
    Some(md5_sha1_int_final),
    Some(md5_sha1_int_ctrl),
);

/// `const EVP_MD *EVP_md5(void)` — `legacy_md5.c:31-34`.
///
/// The answer is a constant, so this is not an `unsafe` function: the authority's own body reads
/// nothing. What a caller does with the pointer is another matter, and the fetch-replacement arm
/// (`src/evp/digest.rs:124-145`) is why handing it to `EVP_DigestInit_ex` still produces a working
/// digest — the library fetches the provider implementation by NID and replaces this object before
/// any of its callbacks would run.
#[no_mangle]
pub extern "C" fn EVP_md5() -> *const EvpMd {
    core::ptr::addr_of!(MD5_MD.0)
}

/// `const EVP_MD *EVP_md5_sha1(void)` — `legacy_md5_sha1.c:38-41`.
#[no_mangle]
pub extern "C" fn EVP_md5_sha1() -> *const EvpMd {
    core::ptr::addr_of!(MD5_SHA1_MD.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two objects against the authority's own fields, read from `legacy_md5.c:22-29` and
    /// `legacy_md5_sha1.c:27-36`.
    ///
    /// The things this catches that a name-and-size test would not: `flags` is **zero** for both
    /// (not `EVP_MD_FLAG_DIGALGID_ABSENT`, which the SHA file's helper would have supplied), and
    /// `md5_sha1_md`'s `type` and `pkey_type` are the same NID.
    #[test]
    fn the_two_objects_are_the_authoritys_fields() {
        let cases: [(&EvpMd, c_int, c_int, c_int, c_int); 2] = [
            (&MD5_MD.0, NID_md5, NID_md5WithRSAEncryption, 16, 64),
            (&MD5_SHA1_MD.0, NID_md5_sha1, NID_md5_sha1, 36, 64),
        ];

        for (md, type_, pkey_type, md_size, block_size) in cases {
            assert_eq!(md.type_, type_);
            assert_eq!(md.pkey_type, pkey_type);
            assert_eq!(md.md_size, md_size);
            assert_eq!(md.block_size, block_size);
            assert_eq!(md.flags, 0);
            assert_eq!(md.origin, EVP_ORIG_GLOBAL);
            assert_eq!(md.ctx_size, 0);
            assert_eq!(md.name_id, 0);
            assert!(md.type_name.is_null());
            assert!(md.prov.is_null());
            assert!(md.copy.is_none());
            assert!(md.cleanup.is_none());
            assert!(md.init.is_some());
            assert!(md.update.is_some());
            assert!(md.final_.is_some());
        }
    }

    /// Only `md5_sha1_md` carries a control function; `md5_md` writes `NULL` there.
    #[test]
    fn only_md5_sha1_carries_a_control_function() {
        assert!(MD5_MD.0.md_ctrl.is_none());
        assert!(MD5_SHA1_MD.0.md_ctrl.is_some());
    }

    /// The entry points answer the address of their own object, and the two are distinct. A
    /// transcription that returned one object for both names would satisfy every field test above.
    #[test]
    fn each_entry_point_answers_its_own_object() {
        let pointers = [EVP_md5() as usize, EVP_md5_sha1() as usize];

        for (i, a) in pointers.iter().enumerate() {
            assert!(*a != 0, "entry point {i} answered NULL");
            for b in pointers.iter().skip(i + 1) {
                assert_ne!(a, b, "two entry points answered the same object");
            }
        }
        assert_eq!(EVP_md5(), core::ptr::addr_of!(MD5_MD.0));
        assert_eq!(EVP_md5_sha1(), core::ptr::addr_of!(MD5_SHA1_MD.0));
    }
}
