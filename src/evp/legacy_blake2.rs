//! `crypto/evp/legacy_blake2.c` — the static `EVP_MD` objects `EVP_blake2b512()` and
//! `EVP_blake2s256()` return.
//!
//! # Two adapters the authority writes by hand, and what they become here
//!
//! The authority's `legacy_blake2.c:18-31` cannot hand the provider's init functions to the legacy
//! macro directly, because `ossl_blake2b_init`/`ossl_blake2s_init` take a parameter block while the
//! legacy signature takes only the context. It therefore defines local `blake2b_init`/`blake2s_init`
//! wrappers that build a default `BLAKE2B_PARAM`/`BLAKE2S_PARAM` and call through, and then
//! `#define`s the update and final names onto the `ossl_` spellings (`legacy_blake2.c:32-35`). The
//! `IMPLEMENT_LEGACY_EVP_MD_METH_LC` macro (`legacy_meth.h:24-36`) then turns those into
//! `blake2b_int_init/_update/_final` and `blake2s_int_init/_update/_final`.
//!
//! The crate's provider row is a module rather than a set of `ossl_`-prefixed functions
//! (`src/digest/blake2.rs`), so the three callbacks below call `blake2b::init`/`update`/`final_` and
//! `blake2s::…` directly. The local parameter block is built with [`crate::digest::blake2::blake2b::param_init`]
//! and [`crate::digest::blake2::blake2s::param_init`], which are the crate's
//! `ossl_blake2b_param_init`/`ossl_blake2s_param_init`.
//!
//! # The init callback returns a constant one
//!
//! The authority's `ossl_blake2b_init` is `blake2b_init_param(c, P); return 1;`
//! (`providers/implementations/digests/blake2b_prov.c:125-129`), and `ossl_blake2s_init` is the
//! same (`blake2s_prov.c:118-123`): neither can fail. The crate's corresponding functions return
//! `()` for that reason, so the callbacks below answer the authority's constant `1` after the call
//! rather than propagating a result the authority never produces. This is a transcription of the
//! observable return value, not a substitute for a missing internal.
//!
//! # `flags`, again
//!
//! Both objects write **`0`** in `flags` (`legacy_blake2.c:44`, `:59`) and **`0`** as the pkey NID
//! (`:42`, `:57`), so the helper takes `flags` as an argument and the call sites state the
//! authority's value rather than the SHA file's `EVP_MD_FLAG_DIGALGID_ABSENT`.
//!
//! # Which context the callbacks cast `md_data` to
//!
//! `legacy_blake2.c:18`/`:25` take a bare `BLAKE2S_CTX *`/`BLAKE2B_CTX *`, not the
//! `blake2s_md_data_st`/`blake2b_md_data_st` that wraps a context and its parameters. So the casts
//! below are to [`crate::digest::blake2::blake2b::Ctx`] and
//! [`crate::digest::blake2::blake2s::Ctx`], the crate's `BLAKE2B_CTX`/`BLAKE2S_CTX`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::blake2::{blake2b, blake2s};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::{NID_blake2b512, NID_blake2s256};

/// `BLAKE2B_DIGEST_LENGTH` — `prov/blake2.h:80`.
const BLAKE2B_DIGEST_LENGTH: c_int = 64;
/// `BLAKE2B_BLOCKBYTES` — `prov/blake2.h:25`.
const BLAKE2B_BLOCKBYTES: c_int = 128;
/// `BLAKE2S_DIGEST_LENGTH` — `prov/blake2.h:81`.
const BLAKE2S_DIGEST_LENGTH: c_int = 32;
/// `BLAKE2S_BLOCKBYTES` — `prov/blake2.h:19`.
const BLAKE2S_BLOCKBYTES: c_int = 64;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h:255`. A global method is not reference counted and not
/// freed, which is why the mutating arms of `EVP_MD_up_ref`/`EVP_MD_free` both refuse it.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_MD_CTX_get0_md_data(ctx)` — `crypto/evp/evp_lib.c:1087`, which the authority's legacy macro
/// calls. A bare `return ctx->md_data;`, factored out because all six callbacks below open with it.
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

/// `LEGACY_EVP_MD_METH_TABLE`'s shape, as a `const fn`. `flags` is an argument because the authority
/// writes `0` into both of these objects and the SHA file's shared value would be wrong; the rest of
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
// The BLAKE2b triple — `legacy_blake2.c:25-31` plus
// `IMPLEMENT_LEGACY_EVP_MD_METH_LC(blake2b_int, blake2b)` at `:37-38`.
// ---------------------------------------------------------------------------------------------

/// `blake2b_int_init` — the lower-case macro over the authority's local `blake2b_init`. The
/// authority's `BLAKE2B_PARAM P;` is uninitialised and then fully overwritten by
/// `ossl_blake2b_param_init`, so a zeroed local here is byte-for-byte equivalent.
unsafe extern "C" fn blake2b_int_init(ctx: *mut EvpMdCtx) -> c_int {
    let mut p = blake2b::Param { b: [0u8; 64] };
    blake2b::param_init(&mut p);
    // SAFETY: `md_data(ctx)` is the live context's block, which this object's `ctx_size`/method
    // makes a `BLAKE2B_CTX`, and `p` is a live local.
    unsafe { blake2b::init(md_data(ctx).cast::<blake2b::Ctx>(), &p) };
    // `ossl_blake2b_init` returns 1 unconditionally (`blake2b_prov.c:125-129`).
    1
}

/// `blake2b_int_update` — the same macro over `ossl_blake2b_update`.
unsafe extern "C" fn blake2b_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe {
        blake2b::update(
            md_data(ctx).cast::<blake2b::Ctx>(),
            data.cast::<u8>(),
            count,
        )
    }
}

/// `blake2b_int_final` — the same macro over `ossl_blake2b_final`. The authority's macro is
/// `fn##_final(md, EVP_MD_CTX_get0_md_data(ctx))`, so the digest comes first.
unsafe extern "C" fn blake2b_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { blake2b::final_(md, md_data(ctx).cast::<blake2b::Ctx>()) }
}

// ---------------------------------------------------------------------------------------------
// The BLAKE2s triple — `legacy_blake2.c:18-24` plus
// `IMPLEMENT_LEGACY_EVP_MD_METH_LC(blake2s_int, blake2s)` at `:37`.
// ---------------------------------------------------------------------------------------------

/// `blake2s_int_init` — the lower-case macro over the authority's local `blake2s_init`.
unsafe extern "C" fn blake2s_int_init(ctx: *mut EvpMdCtx) -> c_int {
    let mut p = blake2s::Param { b: [0u8; 32] };
    blake2s::param_init(&mut p);
    // SAFETY: `md_data(ctx)` is the live context's block, which this object's method makes a
    // `BLAKE2S_CTX`, and `p` is a live local.
    unsafe { blake2s::init(md_data(ctx).cast::<blake2s::Ctx>(), &p) };
    // `ossl_blake2s_init` returns 1 unconditionally (`blake2s_prov.c:118-123`).
    1
}

/// `blake2s_int_update` — the same macro over `ossl_blake2s_update`.
unsafe extern "C" fn blake2s_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe {
        blake2s::update(
            md_data(ctx).cast::<blake2s::Ctx>(),
            data.cast::<u8>(),
            count,
        )
    }
}

/// `blake2s_int_final` — the same macro over `ossl_blake2s_final`.
unsafe extern "C" fn blake2s_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { blake2s::final_(md, md_data(ctx).cast::<blake2s::Ctx>()) }
}

// ---------------------------------------------------------------------------------------------
// The two objects, in the authority's own order.
// ---------------------------------------------------------------------------------------------

/// `blake2b_md` — `legacy_blake2.c:40-48`. `flags` and the pkey NID are both **0**, and `md_ctrl`
/// is **NULL**.
static BLAKE2B_MD: StaticMd = legacy_md(
    NID_blake2b512,
    0,
    BLAKE2B_DIGEST_LENGTH,
    0,
    BLAKE2B_BLOCKBYTES,
    Some(blake2b_int_init),
    Some(blake2b_int_update),
    Some(blake2b_int_final),
    None,
);

/// `blake2s_md` — `legacy_blake2.c:55-63`. The same shape with the 32/64 widths.
static BLAKE2S_MD: StaticMd = legacy_md(
    NID_blake2s256,
    0,
    BLAKE2S_DIGEST_LENGTH,
    0,
    BLAKE2S_BLOCKBYTES,
    Some(blake2s_int_init),
    Some(blake2s_int_update),
    Some(blake2s_int_final),
    None,
);

/// `const EVP_MD *EVP_blake2b512(void)` — `legacy_blake2.c:50-53`.
///
/// The answer is a constant, so this is not an `unsafe` function: the authority's own body reads
/// nothing. Handing the pointer to `EVP_DigestInit_ex` still digests, because the library fetches
/// the provider implementation by NID and replaces this object before any of its callbacks would
/// run (`src/evp/digest.rs:124-145`).
#[no_mangle]
pub extern "C" fn EVP_blake2b512() -> *const EvpMd {
    core::ptr::addr_of!(BLAKE2B_MD.0)
}

/// `const EVP_MD *EVP_blake2s256(void)` — `legacy_blake2.c:65-68`.
#[no_mangle]
pub extern "C" fn EVP_blake2s256() -> *const EvpMd {
    core::ptr::addr_of!(BLAKE2S_MD.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two objects against the authority's own fields, read from `legacy_blake2.c:40-48` and
    /// `:55-63`. `flags` and `pkey_type` are both **zero**, which is what the SHA file's helper
    /// would have gotten wrong had it been copied unchanged.
    #[test]
    fn the_two_objects_are_the_authoritys_fields() {
        let cases: [(&EvpMd, c_int, c_int, c_int); 2] = [
            (&BLAKE2B_MD.0, NID_blake2b512, 64, 128),
            (&BLAKE2S_MD.0, NID_blake2s256, 32, 64),
        ];

        for (md, type_, md_size, block_size) in cases {
            assert_eq!(md.type_, type_);
            assert_eq!(md.pkey_type, 0);
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
            assert!(md.md_ctrl.is_none());
            assert!(md.init.is_some());
            assert!(md.update.is_some());
            assert!(md.final_.is_some());
        }
    }

    /// The entry points answer the addresses of their own objects, and the two are distinct. A
    /// transcription that returned one object for both names would satisfy every field test above.
    #[test]
    fn each_entry_point_answers_its_own_object() {
        let pointers = [EVP_blake2b512() as usize, EVP_blake2s256() as usize];

        for (i, a) in pointers.iter().enumerate() {
            assert!(*a != 0, "entry point {i} answered NULL");
            for b in pointers.iter().skip(i + 1) {
                assert_ne!(a, b, "two entry points answered the same object");
            }
        }
        assert_eq!(EVP_blake2b512(), core::ptr::addr_of!(BLAKE2B_MD.0));
        assert_eq!(EVP_blake2s256(), core::ptr::addr_of!(BLAKE2S_MD.0));
    }
}
