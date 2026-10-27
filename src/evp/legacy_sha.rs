//! `crypto/evp/legacy_sha.c` — the static `EVP_MD` objects the seven `EVP_sha*()` entry points
//! return.
//!
//! # What these objects are, and the one thing about them that is not obvious
//!
//! `EVP_sha1()` is `return &sha1_md;` (`legacy_sha.c:100`) — one line, no allocation, no fetch. Each
//! `shaN_md` is a `static const EVP_MD` whose legacy half is
//! `LEGACY_EVP_MD_METH_TABLE(shaN_init, shaN_update, shaN_final, ctrl, block)`, which
//! `legacy_meth.h:38-39` expands to `init, update, final, NULL, NULL, block, 0, ctrl`. Read against
//! `struct evp_md_st` that puts the digest's block size in `block_size` and **zero in `ctx_size`**,
//! and the measurement agrees: `courts/layout/oracle-legacy-sha.c` reads `block_size` 64,
//! `ctx_size` 0, `copy` and `cleanup` NULL for `sha1_md`.
//!
//! `ctx_size` zero means `evp_md_init_internal` does **not** allocate `ctx->md_data` and does not set
//! `ctx->update` (`crypto/evp/digest.c:342`) — which looks fatal for a legacy callback that reads
//! `md_data`. It is not, and D289/D290 record the four measurements and the resolution: **a legacy
//! method is never used to digest anything.** `evp_md_init_internal` opens with
//! `if (type->prov == NULL)` and, for such a method, fetches the provider implementation by
//! `OBJ_nid2sn(type->type)` with the empty property query and **rebinds `type` to it** before
//! `ctx->digest = type` (`digest.c:258-280`). The digest therefore runs through the provider
//! method's `newctx`/`dinit`/`dupdate`/`dfinal` on `ctx->algctx` — which is 8.1's provider SHA rows —
//! and these objects are carriers whose callbacks an engine may reach and the library does not.
//!
//! **So the callbacks below are transcribed for faithfulness, not because the digest path reaches
//! them**, and this module's job is to make the seven objects field-for-field the authority's. The
//! crate's own `evp_md_init_internal` equivalent already carries the fetch-replacement arm
//! (`src/evp/digest.rs:124-145`), so nothing here needs the digest path changed.
//!
//! # `IMPLEMENT_LEGACY_EVP_MD_METH` is written out rather than expanded
//!
//! The authority's macro emits three functions per digest. The crate forbids `macro_rules!` for
//! *exports* because the ownership and prototype courts read source text and a name that exists only
//! after expansion is invisible to them; these callbacks are internal, but they are still spelled
//! out, because a reader comparing this file with `legacy_meth.h` should be able to do it line by
//! line. The shared shape (`EVP_MD_CTX_get0_md_data(ctx)` and nothing else) is factored into
//! [`md_data`] for the update, final and control callbacks. The initialisers go through
//! [`init_md_data`] instead, because a C caller can reach them through the exported
//! `EVP_MD_meth_get_init` with a context that has no writable block; that helper validates the
//! context and refuses the shape the authority writes through.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};
use core::sync::atomic::AtomicI32;

use crate::digest::sha1::{ossl_sha1_ctrl, SHA1_Final, SHA1_Init, SHA1_Update, ShaCtx};
use crate::digest::sha2::{
    sha512_224_init, sha512_256_init, SHA224_Init, SHA256_Final, SHA256_Init, SHA256_Update,
    SHA384_Init, SHA512_Final, SHA512_Init, SHA512_Update, Sha256Ctx, Sha512Ctx,
};
use crate::evp::digest::{
    EvpMd, EvpMdCtx, MdLegacyCtrlFn, MdLegacyFinalFn, MdLegacyInitFn, MdLegacyUpdateFn,
};
use crate::runtime::obj::{
    NID_sha1, NID_sha1WithRSAEncryption, NID_sha224, NID_sha224WithRSAEncryption, NID_sha256,
    NID_sha256WithRSAEncryption, NID_sha384, NID_sha384WithRSAEncryption, NID_sha512,
    NID_sha512WithRSAEncryption, NID_sha512_224, NID_sha512_224WithRSAEncryption, NID_sha512_256,
    NID_sha512_256WithRSAEncryption,
};

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA_DIGEST_LENGTH: c_int = 20;
/// `SHA224_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA224_DIGEST_LENGTH: c_int = 28;
/// `SHA256_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA256_DIGEST_LENGTH: c_int = 32;
/// `SHA384_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA384_DIGEST_LENGTH: c_int = 48;
/// `SHA512_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA512_DIGEST_LENGTH: c_int = 64;
/// `SHA_CBLOCK` — `include/openssl/sha.h`.
const SHA_CBLOCK: c_int = 64;
/// `SHA256_CBLOCK` — `include/openssl/sha.h`.
const SHA256_CBLOCK: c_int = 64;
/// `SHA512_CBLOCK` — `include/openssl/sha.h`.
const SHA512_CBLOCK: c_int = 128;

/// `EVP_MD_FLAG_DIGALGID_ABSENT` — `include/openssl/evp.h`. **Eight, and it is the only flag these
/// objects carry**; the oracle reads `flags` `8` off `EVP_sha1()` rather than trusting this constant,
/// which is why the value is stated with its measurement beside it.
const EVP_MD_FLAG_DIGALGID_ABSENT: c_ulong = 0x0008;

/// `EVP_ORIG_GLOBAL` — `include/crypto/evp.h:255`. The origin that makes every mutating arm of
/// `EVP_MD_up_ref`/`EVP_MD_free` refuse: a global method is not reference counted and not freed.
const EVP_ORIG_GLOBAL: c_int = 1;

/// `EVP_MD_CTX_get0_md_data(ctx)` — `crypto/evp/evp_lib.c:1087`, which the authority's legacy macros
/// call. It is a bare `return ctx->md_data;`, and it is factored out here because the update, final
/// and control callbacks below open with it. The initialisers use [`init_md_data`] instead, because
/// their exported function pointer can be called with a context that has no block.
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
/// The authority's `IMPLEMENT_LEGACY_EVP_MD_METH` writes through
/// `EVP_MD_CTX_get0_md_data(ctx)` without testing it. That is sound only when the EVP layer
/// supplied the block; the exported `EVP_MD_meth_get_init` also hands this callback to any C
/// caller, and `EVP_MD_CTX_new()` zero-fills the block, so `md_data` is NULL. The crate refuses
/// that shape with the C initialise failure value `0` instead of reproducing the authority's
/// NULL write (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-LEGACY-MD-INIT-MD-DATA-1`).
///
/// A context establishes a writable block in exactly two ways:
///
/// * `digest` is this very table object (`owner`) — the transcribed legacy-table shape; or
/// * `digest` is another live method whose `ctx_size` is at least `size` — the block
///   `evp_md_init_legacy` allocated for that method, which is the shape a caller produces when
///   it installs this exported callback on its own method with a sufficient `app_datasize`.
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

/// A `static` `EVP_MD`. The wrapper exists for the same reason `src/evp/digest.rs`'s own
/// `StaticMd` does: claiming `Sync` for a bare `EvpMd` would be a lie, because a heap `EvpMd` is
/// mutable and synchronised by its reference count, while a compile-time constant one is neither.
struct StaticMd(EvpMd);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every mutating
// arm in the digest module is guarded by `origin`, and `EVP_ORIG_GLOBAL` is not `EVP_ORIG_DYNAMIC`,
// so `EVP_MD_up_ref` and `EVP_MD_free` both refuse these objects.
unsafe impl Sync for StaticMd {}

/// `LEGACY_EVP_MD_METH_TABLE`'s shape, as a `const fn` so the seven objects below differ only in
/// the fields that distinguish them.
///
/// The two halves are worth naming because the compiler needs both spelled out: the **legacy half**
/// is the six values the macro supplies (`init`, `update`, `final`, `copy`, `cleanup`, `block_size`,
/// `ctx_size`, `md_ctrl`), and the **provider half** plus the identity fields are all zero, which is
/// what a `static const` initialiser leaves them as. Nothing sets them later: `EVP_ORIG_GLOBAL`
/// means the object is never fetched, so `name_id`, `type_name`, `prov` and the twelve `OSSL_FUNC_*`
/// members stay null for the life of the process.
///
/// `#[allow(clippy::too_many_arguments)]`'s reason: **the arity is the authority's.**
/// `LEGACY_EVP_MD_METH_TABLE` takes five arguments and `struct evp_md_st`'s legacy run is eight
/// fields; grouping them into a helper struct here would make the seven initialisers below stop
/// reading like the C they transcribe, which is the whole point of this file.
#[allow(clippy::too_many_arguments)]
const fn legacy_md(
    type_: c_int,
    pkey_type: c_int,
    md_size: c_int,
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
        flags: EVP_MD_FLAG_DIGALGID_ABSENT,
        origin: EVP_ORIG_GLOBAL,
        init,
        update,
        final_,
        // The authority's table writes `NULL, NULL` for `copy` and `cleanup`, and the oracle reads
        // both back as NULL.
        copy: None,
        cleanup: None,
        block_size,
        // **Zero, and that is the authority's value rather than an omission.** D290 explains why the
        // zero is harmless: the library replaces this method before any callback reads `md_data`.
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
// `IMPLEMENT_LEGACY_EVP_MD_METH(sha1, SHA1)` and its siblings, written out.
//
// Each triple is the authority's macro body verbatim: `fn##_Init(md_data(ctx))`,
// `fn##_Update(md_data(ctx), data, count)`, `fn##_Final(md, md_data(ctx))`. `SHA224_Update` and
// `SHA384_Update` are `#define`s for the SHA-256 and SHA-512 ones in `sha.h`, which is why only
// three update and three final functions are named below.
// ---------------------------------------------------------------------------------------------

/// `sha1_init` — `legacy_meth.h:11-14`.
///
/// # Safety
///
/// `ctx` must be NULL or point to a live `EVP_MD_CTX`. The callback checks the context's method
/// and block before writing: a fresh `EVP_MD_CTX_new()` (`md_data == NULL`), a NULL context, a
/// context with no method and a method whose `app_datasize` is too small all answer `0`, the C
/// initialise failure value, instead of performing the authority's NULL write. The normal table
/// shape — a writable `SHA_CTX` behind a context bound to this method — still initialises and
/// returns `1`. The refusal is recorded as `docs/SECURITY_DIVERGENCE_POLICY.md`
/// `D-LEGACY-MD-INIT-MD-DATA-1`; no path the crate's own initialiser takes reaches it.
unsafe extern "C" fn sha1_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA1_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA1_MD.0),
            core::mem::size_of::<ShaCtx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA_CTX`.
    unsafe { SHA1_Init(block.cast::<ShaCtx>()) }
}

/// `sha1_update` — `legacy_meth.h:15-18`.
unsafe extern "C" fn sha1_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above, and `data`/`count` are forwarded unchanged.
    unsafe { SHA1_Update(md_data(ctx).cast::<ShaCtx>(), data, count) }
}

/// `sha1_final` — `legacy_meth.h:19-22`. Note the argument order: the authority's macro is
/// `fn##_Final(md, EVP_MD_CTX_get0_md_data(ctx))`, and `SHA1_Final` takes the digest first.
unsafe extern "C" fn sha1_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA1_Final(md, md_data(ctx).cast::<ShaCtx>()) }
}

/// `sha1_int_ctrl` — `legacy_sha.c:70-74`. The authority passes NULL rather than reading a field of a
/// NULL context, and `ossl_sha1_ctrl` answers `-2` for any command but
/// `EVP_CTRL_SSL3_MASTER_SECRET`.
unsafe extern "C" fn sha1_int_ctrl(
    ctx: *mut EvpMdCtx,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract; the NULL branch is the authority's own guard.
    unsafe {
        ossl_sha1_ctrl(
            if ctx.is_null() {
                core::ptr::null_mut()
            } else {
                md_data(ctx).cast::<ShaCtx>()
            },
            cmd,
            p1,
            p2,
        )
    }
}

/// `sha224_init` — `IMPLEMENT_LEGACY_EVP_MD_METH(sha224, SHA224)`.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA256_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha224_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha224_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA224_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA224_MD.0),
            core::mem::size_of::<Sha256Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA256_CTX`.
    unsafe { SHA224_Init(block.cast::<Sha256Ctx>()) }
}

/// `sha224_update` — `IMPLEMENT_LEGACY_EVP_MD_METH(sha224, SHA224)`, where `SHA224_Update` is
/// `sha.h`'s `#define` for `SHA256_Update`.
unsafe extern "C" fn sha224_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above.
    unsafe { SHA256_Update(md_data(ctx).cast::<Sha256Ctx>(), data, count) }
}

/// `sha224_final` — as above, over `SHA256_Final`.
unsafe extern "C" fn sha224_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA256_Final(md, md_data(ctx).cast::<Sha256Ctx>()) }
}

/// `sha256_init`.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA256_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha256_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha256_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA256_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA256_MD.0),
            core::mem::size_of::<Sha256Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA256_CTX`.
    unsafe { SHA256_Init(block.cast::<Sha256Ctx>()) }
}

/// `sha256_update`.
unsafe extern "C" fn sha256_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above.
    unsafe { SHA256_Update(md_data(ctx).cast::<Sha256Ctx>(), data, count) }
}

/// `sha256_final`.
unsafe extern "C" fn sha256_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA256_Final(md, md_data(ctx).cast::<Sha256Ctx>()) }
}

/// `sha384_init` — `IMPLEMENT_LEGACY_EVP_MD_METH(sha384, SHA384)`.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA512_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha384_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha384_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA384_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA384_MD.0),
            core::mem::size_of::<Sha512Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA512_CTX`.
    unsafe { SHA384_Init(block.cast::<Sha512Ctx>()) }
}

/// `sha384_update` — `SHA384_Update` is `sha.h`'s `#define` for `SHA512_Update`.
unsafe extern "C" fn sha384_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Update(md_data(ctx).cast::<Sha512Ctx>(), data, count) }
}

/// `sha384_final` — as above, over `SHA512_Final`.
unsafe extern "C" fn sha384_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Final(md, md_data(ctx).cast::<Sha512Ctx>()) }
}

/// `sha512_init`.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA512_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha512_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha512_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA512_MD` is a live static
    // method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA512_MD.0),
            core::mem::size_of::<Sha512Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA512_CTX`.
    unsafe { SHA512_Init(block.cast::<Sha512Ctx>()) }
}

/// `sha512_update`.
unsafe extern "C" fn sha512_update(ctx: *mut EvpMdCtx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Update(md_data(ctx).cast::<Sha512Ctx>(), data, count) }
}

/// `sha512_final`.
unsafe extern "C" fn sha512_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Final(md, md_data(ctx).cast::<Sha512Ctx>()) }
}

/// `sha512_224_int_init` — `IMPLEMENT_LEGACY_EVP_MD_METH(sha512_224_int, sha512_224)`, where
/// `legacy_sha.c:46-47` `#define`s `sha512_224_Init` to `sha512_224_init`. So this calls the
/// **lower-case** `sha512_224_init`, which is the truncated-initialisation the crate already has,
/// and not `SHA512_Init`.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA512_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha512_224_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha512_224_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA512_224_MD` is a live
    // static method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA512_224_MD.0),
            core::mem::size_of::<Sha512Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA512_CTX`.
    unsafe { sha512_224_init(block.cast::<Sha512Ctx>()) }
}

/// `sha512_224_int_final` — the same table's final, over `SHA512_Final`.
unsafe extern "C" fn sha512_224_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Final(md, md_data(ctx).cast::<Sha512Ctx>()) }
}

/// `sha512_256_int_init` — `sha512_256_init`, for the reason `sha512_224_int_init` gives.
///
/// # Safety
///
/// As [`sha1_init`]: `ctx` must be NULL or point to a live `EVP_MD_CTX`; the callback establishes
/// its own writable `SHA512_CTX` from the context's method and block, and answers `0` when the
/// caller supplied a shape that does not contain one. The table's own path (a context bound to
/// `sha512_256_md` with a writable block) is unchanged and returns `1`.
unsafe extern "C" fn sha512_256_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the callback's contract, and `SHA512_256_MD` is a live
    // static method.
    let Some(block) = (unsafe {
        init_md_data(
            ctx,
            core::ptr::addr_of!(SHA512_256_MD.0),
            core::mem::size_of::<Sha512Ctx>(),
        )
    }) else {
        return 0;
    };
    // SAFETY: `init_md_data` established a writable `SHA512_CTX`.
    unsafe { sha512_256_init(block.cast::<Sha512Ctx>()) }
}

/// `sha512_256_int_final`.
unsafe extern "C" fn sha512_256_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Final(md, md_data(ctx).cast::<Sha512Ctx>()) }
}

// ---------------------------------------------------------------------------------------------
// The seven objects, in `legacy_sha.c`'s own order.
// ---------------------------------------------------------------------------------------------

/// `sha1_md` — `legacy_sha.c:87-95`, the only one of the seven with a non-NULL `md_ctrl`.
static SHA1_MD: StaticMd = legacy_md(
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    SHA_CBLOCK,
    Some(sha1_init),
    Some(sha1_update),
    Some(sha1_final),
    Some(sha1_int_ctrl),
);

/// `sha224_md` — `legacy_sha.c:97-106`.
static SHA224_MD: StaticMd = legacy_md(
    NID_sha224,
    NID_sha224WithRSAEncryption,
    SHA224_DIGEST_LENGTH,
    SHA256_CBLOCK,
    Some(sha224_init),
    Some(sha224_update),
    Some(sha224_final),
    None,
);

/// `sha256_md` — `legacy_sha.c:108-117`.
static SHA256_MD: StaticMd = legacy_md(
    NID_sha256,
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    SHA256_CBLOCK,
    Some(sha256_init),
    Some(sha256_update),
    Some(sha256_final),
    None,
);

/// `sha384_md` — `legacy_sha.c:150-159`.
static SHA384_MD: StaticMd = legacy_md(
    NID_sha384,
    NID_sha384WithRSAEncryption,
    SHA384_DIGEST_LENGTH,
    SHA512_CBLOCK,
    Some(sha384_init),
    Some(sha384_update),
    Some(sha384_final),
    None,
);

/// `sha512_md` — `legacy_sha.c:161-170`.
static SHA512_MD: StaticMd = legacy_md(
    NID_sha512,
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,
    SHA512_CBLOCK,
    Some(sha512_init),
    Some(sha512_update),
    Some(sha512_final),
    None,
);

/// `sha512_224_md` — `legacy_sha.c:119-128`. Note the sizes: the **digest** is 28 octets
/// (`SHA224_DIGEST_LENGTH`) while the **block** is 128 (`SHA512_CBLOCK`), because the width and the
/// truncation are independent.
static SHA512_224_MD: StaticMd = legacy_md(
    NID_sha512_224,
    NID_sha512_224WithRSAEncryption,
    SHA224_DIGEST_LENGTH,
    SHA512_CBLOCK,
    Some(sha512_224_int_init),
    Some(sha384_update),
    Some(sha512_224_int_final),
    None,
);

/// `sha512_256_md` — `legacy_sha.c:130-139`. The mirror of its sibling: 32 octets of digest over a
/// 128-octet block.
static SHA512_256_MD: StaticMd = legacy_md(
    NID_sha512_256,
    NID_sha512_256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,
    SHA512_CBLOCK,
    Some(sha512_256_int_init),
    Some(sha384_update),
    Some(sha512_256_int_final),
    None,
);

/// `const EVP_MD *EVP_sha1(void)` — `legacy_sha.c:100-103`.
///
/// **The answer is a constant, so this is not an `unsafe` function** — the authority's own body
/// reads nothing. What a caller does with the pointer is another matter, and D290 explains why
/// handing it to `EVP_DigestInit_ex` produces a working digest: the library fetches the provider
/// implementation by NID and replaces this object before any of its callbacks would run.
#[no_mangle]
pub extern "C" fn EVP_sha1() -> *const EvpMd {
    core::ptr::addr_of!(SHA1_MD.0)
}

/// `const EVP_MD *EVP_sha224(void)` — `legacy_sha.c:105-108`.
#[no_mangle]
pub extern "C" fn EVP_sha224() -> *const EvpMd {
    core::ptr::addr_of!(SHA224_MD.0)
}

/// `const EVP_MD *EVP_sha256(void)` — `legacy_sha.c:116-119`.
#[no_mangle]
pub extern "C" fn EVP_sha256() -> *const EvpMd {
    core::ptr::addr_of!(SHA256_MD.0)
}

/// `const EVP_MD *EVP_sha384(void)` — `legacy_sha.c:158-161`.
#[no_mangle]
pub extern "C" fn EVP_sha384() -> *const EvpMd {
    core::ptr::addr_of!(SHA384_MD.0)
}

/// `const EVP_MD *EVP_sha512(void)` — `legacy_sha.c:169-172`.
#[no_mangle]
pub extern "C" fn EVP_sha512() -> *const EvpMd {
    core::ptr::addr_of!(SHA512_MD.0)
}

/// `const EVP_MD *EVP_sha512_224(void)` — `legacy_sha.c:127-130`.
#[no_mangle]
pub extern "C" fn EVP_sha512_224() -> *const EvpMd {
    core::ptr::addr_of!(SHA512_224_MD.0)
}

/// `const EVP_MD *EVP_sha512_256(void)` — `legacy_sha.c:138-141`.
#[no_mangle]
pub extern "C" fn EVP_sha512_256() -> *const EvpMd {
    core::ptr::addr_of!(SHA512_256_MD.0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// The seven objects against the authority's own fields, measured by
    /// `courts/layout/oracle-legacy-sha.c` for `sha1_md` and read from `legacy_sha.c` for the rest.
    ///
    /// The two things this catches that a name-and-size test would not: `flags` is
    /// `EVP_MD_FLAG_DIGALGID_ABSENT` and only that, and `ctx_size` is **zero** — a transcription that
    /// "fixed" the zero because `md_data` looks unallocated would fail here rather than at the first
    /// digest call, and D290 is the reason not to fix it.
    #[test]
    fn the_seven_objects_are_the_authoritys_fields() {
        let cases: [(&EvpMd, c_int, c_int, c_int, c_int); 7] = [
            (&SHA1_MD.0, NID_sha1, NID_sha1WithRSAEncryption, 20, 64),
            (
                &SHA224_MD.0,
                NID_sha224,
                NID_sha224WithRSAEncryption,
                28,
                64,
            ),
            (
                &SHA256_MD.0,
                NID_sha256,
                NID_sha256WithRSAEncryption,
                32,
                64,
            ),
            (
                &SHA384_MD.0,
                NID_sha384,
                NID_sha384WithRSAEncryption,
                48,
                128,
            ),
            (
                &SHA512_MD.0,
                NID_sha512,
                NID_sha512WithRSAEncryption,
                64,
                128,
            ),
            (
                &SHA512_224_MD.0,
                NID_sha512_224,
                NID_sha512_224WithRSAEncryption,
                28,
                128,
            ),
            (
                &SHA512_256_MD.0,
                NID_sha512_256,
                NID_sha512_256WithRSAEncryption,
                32,
                128,
            ),
        ];

        for (md, type_, pkey_type, md_size, block_size) in cases {
            assert_eq!(md.type_, type_);
            assert_eq!(md.pkey_type, pkey_type);
            assert_eq!(md.md_size, md_size);
            assert_eq!(md.block_size, block_size);
            assert_eq!(md.flags, EVP_MD_FLAG_DIGALGID_ABSENT);
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

    /// Only `sha1_md` carries a `md_ctrl`, and it is the authority's `sha1_int_ctrl`. The other six
    /// write `NULL` there, which `LEGACY_EVP_MD_METH_TABLE`'s fourth argument spells out per call.
    #[test]
    fn only_sha1_carries_a_control_function() {
        assert!(SHA1_MD.0.md_ctrl.is_some());
        assert!(SHA224_MD.0.md_ctrl.is_none());
        assert!(SHA256_MD.0.md_ctrl.is_none());
        assert!(SHA384_MD.0.md_ctrl.is_none());
        assert!(SHA512_MD.0.md_ctrl.is_none());
        assert!(SHA512_224_MD.0.md_ctrl.is_none());
        assert!(SHA512_256_MD.0.md_ctrl.is_none());
    }

    /// The entry points answer the address of their own object, and the seven are distinct. A
    /// transcription that returned one object for two names would satisfy every field test above.
    #[test]
    fn each_entry_point_answers_its_own_object() {
        let pointers = [
            EVP_sha1() as usize,
            EVP_sha224() as usize,
            EVP_sha256() as usize,
            EVP_sha384() as usize,
            EVP_sha512() as usize,
            EVP_sha512_224() as usize,
            EVP_sha512_256() as usize,
        ];

        for (i, a) in pointers.iter().enumerate() {
            assert!(*a != 0, "entry point {i} answered NULL");
            for b in pointers.iter().skip(i + 1) {
                assert_ne!(a, b, "two entry points answered the same object");
            }
        }
        assert_eq!(EVP_sha1(), core::ptr::addr_of!(SHA1_MD.0));
        assert_eq!(EVP_sha256(), core::ptr::addr_of!(SHA256_MD.0));
    }

    /// An `EVP_MD_CTX` bound to `md` and a writable digest block, with no provider state. The
    /// legacy callbacks read only `digest` and `md_data`; every other field is the zero
    /// `EVP_MD_CTX_new` leaves behind.
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

    /// The two shapes a C caller can hand an exported legacy initialiser that do not contain a
    /// writable digest block: a fresh `EVP_MD_CTX_new()` (`md_data == NULL`) and a NULL context.
    /// Both must answer the C initialise failure value `0` without dereferencing anything.
    fn assert_init_refuses_contexts_without_md_data(init: MdLegacyInitFn) {
        use crate::evp::digest::{EVP_MD_CTX_free, EVP_MD_CTX_new};

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        assert_eq!(unsafe { init(fresh) }, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        assert_eq!(unsafe { init(core::ptr::null_mut()) }, 0);
    }

    /// `EVP_MD_meth_get_init(EVP_sha1())` handed to a C caller, then called with the two context
    /// shapes the getter's documented contract does not exclude: a fresh `EVP_MD_CTX_new()`
    /// (`md_data == NULL`) and a NULL context. The authority's `sha1_init` writes through
    /// `EVP_MD_CTX_get0_md_data(ctx)`, so both are a NULL write; the crate refuses both with `0`.
    /// The same test drives the table's own path — a context bound to `sha1_md` with a writable
    /// `SHA_CTX` — and checks that the result is still the standard SHA1("abc") digest.
    #[test]
    fn legacy_sha1_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_get_final, EVP_MD_meth_get_init,
            EVP_MD_meth_get_update,
        };

        // SAFETY: `EVP_sha1()` answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sha1()) }.expect("sha1_md has an init");
        // SAFETY: as above.
        let update = unsafe { EVP_MD_meth_get_update(EVP_sha1()) }.expect("sha1_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sha1()) }.expect("sha1_md has a final");

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        assert_eq!(unsafe { init(fresh) }, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        assert_eq!(unsafe { init(core::ptr::null_mut()) }, 0);

        let mut store = core::mem::MaybeUninit::<ShaCtx>::uninit();
        let mut ctx = bound_context(EVP_sha1(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha1_md`, and `store` is a writable `SHA_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 20];
        // SAFETY: `output` is writable for the SHA-1 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ],
            "SHA1(\"abc\") changed"
        );
    }

    /// As [`legacy_sha1_init_refuses_context_without_md_data_and_inits_bound_context`], over the
    /// `sha224_md` table entry and `SHA224_Init`'s `SHA256_CTX` block.
    #[test]
    fn legacy_sha224_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_get_final, EVP_MD_meth_get_init,
            EVP_MD_meth_get_update,
        };

        // SAFETY: `EVP_sha224()` answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sha224()) }.expect("sha224_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_sha224()) }.expect("sha224_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sha224()) }.expect("sha224_md has a final");

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is a live context and the callback accepts any live context.
        assert_eq!(unsafe { init(fresh) }, 0, "init accepted a NULL md_data");
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };

        // SAFETY: a NULL context is the input under test; the callback's contract permits it.
        assert_eq!(unsafe { init(core::ptr::null_mut()) }, 0);

        let mut store = core::mem::MaybeUninit::<Sha256Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha224(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha224_md`, and `store` is a writable `SHA256_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 28];
        // SAFETY: `output` is writable for the SHA-224 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
            ],
            "SHA224(\"abc\") changed"
        );
    }

    /// As [`legacy_sha1_init_refuses_context_without_md_data_and_inits_bound_context`], over the
    /// `sha256_md` table entry and `SHA256_Init`'s `SHA256_CTX` block.
    #[test]
    fn legacy_sha256_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update,
        };

        // SAFETY: each accessor answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sha256()) }.expect("sha256_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_sha256()) }.expect("sha256_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sha256()) }.expect("sha256_md has a final");

        assert_init_refuses_contexts_without_md_data(init);

        let mut store = core::mem::MaybeUninit::<Sha256Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha256(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha256_md`, and `store` is a writable `SHA256_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 32];
        // SAFETY: `output` is writable for the SHA-256 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ],
            "SHA256(\"abc\") changed"
        );
    }

    /// As above, over the `sha384_md` table entry and `SHA384_Init`'s `SHA512_CTX` block.
    #[test]
    fn legacy_sha384_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update,
        };

        // SAFETY: each accessor answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sha384()) }.expect("sha384_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_sha384()) }.expect("sha384_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sha384()) }.expect("sha384_md has a final");

        assert_init_refuses_contexts_without_md_data(init);

        let mut store = core::mem::MaybeUninit::<Sha512Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha384(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha384_md`, and `store` is a writable `SHA512_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 48];
        // SAFETY: `output` is writable for the SHA-384 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
                0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
                0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
                0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
            ],
            "SHA384(\"abc\") changed"
        );
    }

    /// As above, over the `sha512_md` table entry and `SHA512_Init`'s `SHA512_CTX` block.
    #[test]
    fn legacy_sha512_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update,
        };

        // SAFETY: each accessor answers a live static method.
        let init = unsafe { EVP_MD_meth_get_init(EVP_sha512()) }.expect("sha512_md has an init");
        // SAFETY: as above.
        let update =
            unsafe { EVP_MD_meth_get_update(EVP_sha512()) }.expect("sha512_md has an update");
        // SAFETY: as above.
        let final_ = unsafe { EVP_MD_meth_get_final(EVP_sha512()) }.expect("sha512_md has a final");

        assert_init_refuses_contexts_without_md_data(init);

        let mut store = core::mem::MaybeUninit::<Sha512Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha512(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha512_md`, and `store` is a writable `SHA512_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 64];
        // SAFETY: `output` is writable for the SHA-512 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ],
            "SHA512(\"abc\") changed"
        );
    }

    /// As above, over the `sha512_224_md` table entry and its truncated `SHA512_CTX`
    /// initialisation.
    #[test]
    fn legacy_sha512_224_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update,
        };

        // SAFETY: each accessor answers a live static method.
        let init =
            unsafe { EVP_MD_meth_get_init(EVP_sha512_224()) }.expect("sha512_224_md has an init");
        // SAFETY: as above.
        let update = unsafe { EVP_MD_meth_get_update(EVP_sha512_224()) }
            .expect("sha512_224_md has an update");
        // SAFETY: as above.
        let final_ =
            unsafe { EVP_MD_meth_get_final(EVP_sha512_224()) }.expect("sha512_224_md has a final");

        assert_init_refuses_contexts_without_md_data(init);

        let mut store = core::mem::MaybeUninit::<Sha512Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha512_224(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha512_224_md`, and `store` is a writable `SHA512_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 28];
        // SAFETY: `output` is writable for the SHA-512/224 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, 0xda, 0xae, 0x75, 0x30, 0x46, 0x08,
                0x42, 0xe2, 0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4, 0x3e, 0x89, 0x24, 0xaa,
            ],
            "SHA512/224(\"abc\") changed"
        );
    }

    /// As above, over the `sha512_256_md` table entry and its truncated `SHA512_CTX`
    /// initialisation.
    #[test]
    fn legacy_sha512_256_init_refuses_context_without_md_data_and_inits_bound_context() {
        use crate::evp::digest::{
            EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update,
        };

        // SAFETY: each accessor answers a live static method.
        let init =
            unsafe { EVP_MD_meth_get_init(EVP_sha512_256()) }.expect("sha512_256_md has an init");
        // SAFETY: as above.
        let update = unsafe { EVP_MD_meth_get_update(EVP_sha512_256()) }
            .expect("sha512_256_md has an update");
        // SAFETY: as above.
        let final_ =
            unsafe { EVP_MD_meth_get_final(EVP_sha512_256()) }.expect("sha512_256_md has a final");

        assert_init_refuses_contexts_without_md_data(init);

        let mut store = core::mem::MaybeUninit::<Sha512Ctx>::uninit();
        let mut ctx = bound_context(EVP_sha512_256(), store.as_mut_ptr().cast());
        // SAFETY: `ctx` is live, bound to `sha512_256_md`, and `store` is a writable `SHA512_CTX`.
        let initialised = unsafe { init(&mut ctx) };
        assert_eq!(initialised, 1, "init refused a writable md_data");

        let message = b"abc";
        // SAFETY: `ctx` was just initialised and `message` is readable for its length.
        let updated = unsafe { update(&mut ctx, message.as_ptr().cast(), message.len()) };
        assert_eq!(updated, 1);
        let mut output = [0u8; 32];
        // SAFETY: `output` is writable for the SHA-512/256 digest length.
        assert_eq!(unsafe { final_(&mut ctx, output.as_mut_ptr()) }, 1);
        assert_eq!(
            output,
            [
                0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c,
                0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31,
                0x07, 0xe7, 0xaf, 0x23,
            ],
            "SHA512/256(\"abc\") changed"
        );
    }
}
