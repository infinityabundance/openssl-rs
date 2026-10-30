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
//! # The initialisers refuse a context without a writable block
//!
//! The authority's local `blake2b_init`/`blake2s_init` wrappers call
//! `ossl_blake2b_init`/`ossl_blake2s_init` on `EVP_MD_CTX_get0_md_data(ctx)` with no test on the
//! block. The exported `EVP_MD_meth_get_init` hands that callback to any C caller, and a fresh
//! `EVP_MD_CTX_new()` is zero-filled, so `md_data` is NULL. The crate validates the context first
//! and answers the C initialise failure value `0` where the authority performs the NULL write
//! (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-LEGACY-BLAKE2-INIT-MD-DATA-1`), exactly as the
//! audited SHA-1/SHA-224/MD5 siblings do under `D-LEGACY-MD-INIT-MD-DATA-1`.
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

/// The writable digest block an initialiser may write, or `None` when the context does not
/// establish one.
///
/// The authority's `IMPLEMENT_LEGACY_EVP_MD_METH_LC` calls its local `blake2b_init`/`blake2s_init`
/// on `EVP_MD_CTX_get0_md_data(ctx)` without testing it. That is sound only when the EVP layer
/// supplied the block; the exported `EVP_MD_meth_get_init` also hands this callback to any C
/// caller, and `EVP_MD_CTX_new()` zero-fills the block, so `md_data` is NULL. The crate refuses
/// that shape with the C initialise failure value `0` instead of reproducing the authority's
/// NULL write (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-LEGACY-BLAKE2-INIT-MD-DATA-1`).
///
/// A context establishes a writable block in exactly two ways:
///
/// * `digest` is this very table object (`owner`) — the transcribed legacy-table shape; or
/// * `digest` is another live method whose `ctx_size` is at least `size` — the block the EVP layer
///   allocated for that method, which is the shape a caller produces when it installs this
///   exported callback on its own method with a sufficient `app_datasize`.
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
    // SAFETY: `ctx` is non-NULL and live per the contract.
    let md_data = unsafe { md_data(ctx) };
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
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`. The callback checks the context's method
/// and block before writing: a fresh `EVP_MD_CTX_new()` (`md_data == NULL`), a NULL context, a
/// context with no method and a method whose `app_datasize` is too small all answer `0`, the C
/// initialise failure value, instead of performing the authority's NULL write. The normal table
/// shape — a writable `BLAKE2B_CTX` behind a context bound to this method — still initialises and
/// returns `1`. The refusal is recorded as `docs/SECURITY_DIVERGENCE_POLICY.md`
/// `D-LEGACY-BLAKE2-INIT-MD-DATA-1`.
unsafe extern "C" fn blake2b_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2B_MD` is a live
    // static method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2B_MD.0),
            core::mem::size_of::<blake2b::Ctx>(),
        )
    }) else {
        return 0;
    };
    let mut p = blake2b::Param { b: [0u8; 64] };
    blake2b::param_init(&mut p);
    // SAFETY: `init_md_data` established a writable `BLAKE2B_CTX`, and `p` is a live local.
    unsafe { blake2b::init(block.cast::<blake2b::Ctx>(), &p) };
    // `ossl_blake2b_init` returns 1 unconditionally (`blake2b_prov.c:125-129`).
    1
}

/// `blake2b_int_update` — the same macro over `ossl_blake2b_update`.
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`; `count` may be zero, in which case `data`
/// may be NULL and the callback answers `1` without touching either pointer. The callback refuses
/// a context that does not establish a writable `BLAKE2B_CTX` — NULL, a fresh `EVP_MD_CTX_new()`,
/// a NULL method, or a method with a smaller `ctx_size` — with `0` before any dereference
/// (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-LEGACY-MD-CALLBACK-MD-DATA-1`). The context is
/// borrowed exclusively for the duration of the call and no pointer is retained.
unsafe extern "C" fn blake2b_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2B_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2B_MD.0),
            core::mem::size_of::<blake2b::Ctx>(),
        )
    }) else {
        return 0;
    };
    // The authority's `ossl_blake2b_update` reaches `copy_nonoverlapping` even for a zero length;
    // answer the zero-length update before the pointer is used so a NULL `data` is accepted here.
    if count == 0 {
        return 1;
    }
    // SAFETY: `init_md_data` established a writable `BLAKE2B_CTX`; `data`/`count` are the caller's.
    unsafe { blake2b::update(block.cast::<blake2b::Ctx>(), data.cast::<u8>(), count) }
}

/// `blake2b_int_final` — the same macro over `ossl_blake2b_final`. The authority's macro is
/// `fn##_final(md, EVP_MD_CTX_get0_md_data(ctx))`, so the digest comes first.
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`; `md` must be writable for
/// `BLAKE2B_DIGEST_LENGTH` (64) bytes. The context precondition is the one
/// [`blake2b_int_update`] states, and a context without a writable block is refused with `0`
/// before `md` is touched.
unsafe extern "C" fn blake2b_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2B_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2B_MD.0),
            core::mem::size_of::<blake2b::Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `BLAKE2B_CTX`; `md` is writable per the
    // contract.
    unsafe { blake2b::final_(md, block.cast::<blake2b::Ctx>()) }
}

// ---------------------------------------------------------------------------------------------
// The BLAKE2s triple — `legacy_blake2.c:18-24` plus
// `IMPLEMENT_LEGACY_EVP_MD_METH_LC(blake2s_int, blake2s)` at `:37`.
// ---------------------------------------------------------------------------------------------

/// `blake2s_int_init` — the lower-case macro over the authority's local `blake2s_init`.
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`. The same validation as
/// [`blake2b_int_init`] applies over a `BLAKE2S_CTX`: a context without a writable block answers
/// `0` instead of performing the authority's NULL write, and the bound table path still
/// initialises and returns `1`. Recorded as `D-LEGACY-BLAKE2-INIT-MD-DATA-1`.
unsafe extern "C" fn blake2s_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2S_MD` is a live
    // static method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2S_MD.0),
            core::mem::size_of::<blake2s::Ctx>(),
        )
    }) else {
        return 0;
    };
    let mut p = blake2s::Param { b: [0u8; 32] };
    blake2s::param_init(&mut p);
    // SAFETY: `init_md_data` established a writable `BLAKE2S_CTX`, and `p` is a live local.
    unsafe { blake2s::init(block.cast::<blake2s::Ctx>(), &p) };
    // `ossl_blake2s_init` returns 1 unconditionally (`blake2s_prov.c:118-123`).
    1
}

/// `blake2s_int_update` — the same macro over `ossl_blake2s_update`.
///
/// # Safety
///
/// As [`blake2b_int_update`], over a writable `BLAKE2S_CTX` (`BLAKE2S_MD` is the owner): `ctx`
/// NULL or live, `count` zero allowed with `data` NULL, and a context without a writable block
/// refused with `0` before any dereference.
unsafe extern "C" fn blake2s_int_update(
    ctx: *mut EvpMdCtx,
    data: *const c_void,
    count: usize,
) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2S_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2S_MD.0),
            core::mem::size_of::<blake2s::Ctx>(),
        )
    }) else {
        return 0;
    };
    // As in the BLAKE2b arm: a zero-length update is answered before the pointer is used.
    if count == 0 {
        return 1;
    }
    // SAFETY: `init_md_data` established a writable `BLAKE2S_CTX`; `data`/`count` are the caller's.
    unsafe { blake2s::update(block.cast::<blake2s::Ctx>(), data.cast::<u8>(), count) }
}

/// `blake2s_int_final` — the same macro over `ossl_blake2s_final`.
///
/// # Safety
///
/// As [`blake2b_int_final`], over a writable `BLAKE2S_CTX`: `ctx` NULL or live, `md` writable for
/// `BLAKE2S_DIGEST_LENGTH` (32) bytes, and a context without a writable block refused with `0`.
unsafe extern "C" fn blake2s_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `BLAKE2S_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(BLAKE2S_MD.0),
            core::mem::size_of::<blake2s::Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `BLAKE2S_CTX`; `md` is writable per the
    // contract.
    unsafe { blake2s::final_(md, block.cast::<blake2s::Ctx>()) }
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// A context with the fields the legacy callbacks read: `digest`/`reqdigest` bound to `md` and
    /// a writable `md_data` block. Every other field is the zero `EVP_MD_CTX_new` leaves behind.
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

    /// `EVP_MD_meth_get_init(EVP_blake2b512())` handed to a C caller, then called with a fresh
    /// `EVP_MD_CTX_new()` (`md_data == NULL`) and with a NULL context. The authority's local
    /// `blake2b_init` calls `ossl_blake2b_init(EVP_MD_CTX_get0_md_data(ctx), &P)`, so both are a
    /// NULL write; the crate refuses both with `0`. The table's own path — a context bound to
    /// `blake2b_md` with a writable `BLAKE2B_CTX` — must still produce the standard
    /// BLAKE2b-512("abc") digest.
    #[test]
    fn legacy_blake2b_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_get_final, EVP_MD_meth_get_init,
            EVP_MD_meth_get_update,
        };

        // SAFETY: `EVP_blake2b512()` answers a live static method.
        let init =
            unsafe { EVP_MD_meth_get_init(EVP_blake2b512()) }.expect("blake2b_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_blake2b512()) }.expect("blake2b_md has an update");
        // SAFETY: as above.
        let final_ =
            unsafe { EVP_MD_meth_get_final(EVP_blake2b512()) }.expect("blake2b_md has a final");

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        let refused_fresh = unsafe { init(fresh) };
        assert_eq!(refused_fresh, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        let refused_null = unsafe { init(core::ptr::null_mut()) };
        assert_eq!(refused_null, 0);

        let mut store = core::mem::MaybeUninit::<blake2b::Ctx>::uninit();
        let mut ctx = bound_context(EVP_blake2b512(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `blake2b_md`, and `store` is a writable `BLAKE2B_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 64];
        // SAFETY: `output` is writable for the BLAKE2b-512 digest length.
        let finalised = unsafe { final_(&mut ctx, output.as_mut_ptr()) };
        assert_eq!(finalised, 1);
        assert_eq!(
            output,
            [
                0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12,
                0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f,
                0xdb, 0xff, 0xa2, 0xd1, 0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52,
                0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
                0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
            ],
            "BLAKE2b-512(\"abc\") changed"
        );
    }

    /// As [`legacy_blake2b_init_refuses_context_without_md_data_and_inits_bound_context`], over
    /// the `blake2s_md` table entry and `ossl_blake2s_init`'s `BLAKE2S_CTX` block.
    #[test]
    fn legacy_blake2s_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_get_final, EVP_MD_meth_get_init,
            EVP_MD_meth_get_update,
        };

        // SAFETY: `EVP_blake2s256()` answers a live static method.
        let init =
            unsafe { EVP_MD_meth_get_init(EVP_blake2s256()) }.expect("blake2s_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_blake2s256()) }.expect("blake2s_md has an update");
        // SAFETY: as above.
        let final_ =
            unsafe { EVP_MD_meth_get_final(EVP_blake2s256()) }.expect("blake2s_md has a final");

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        let refused_fresh = unsafe { init(fresh) };
        assert_eq!(refused_fresh, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        let refused_null = unsafe { init(core::ptr::null_mut()) };
        assert_eq!(refused_null, 0);

        let mut store = core::mem::MaybeUninit::<blake2s::Ctx>::uninit();
        let mut ctx = bound_context(EVP_blake2s256(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `blake2s_md`, and `store` is a writable `BLAKE2S_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 32];
        // SAFETY: `output` is writable for the BLAKE2s-256 digest length.
        let finalised = unsafe { final_(&mut ctx, output.as_mut_ptr()) };
        assert_eq!(finalised, 1);
        assert_eq!(
            output,
            [
                0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb,
                0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c,
                0x86, 0x67, 0x59, 0x82,
            ],
            "BLAKE2s-256(\"abc\") changed"
        );
    }
}
