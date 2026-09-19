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
//! [`md_data`] so the fifteen functions read as the three-line macros they replace.
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
/// call. It is a bare `return ctx->md_data;`, and it is factored out here because all fifteen
/// callbacks below open with it.
///
/// # Safety
/// `ctx` must be a live `EVP_MD_CTX`.
unsafe fn md_data(ctx: *mut EvpMdCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).md_data }
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
unsafe extern "C" fn sha1_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract; `md_data` reads a field of a live context.
    unsafe { SHA1_Init(md_data(ctx).cast::<ShaCtx>()) }
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
unsafe extern "C" fn sha224_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA224_Init(md_data(ctx).cast::<Sha256Ctx>()) }
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
unsafe extern "C" fn sha256_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA256_Init(md_data(ctx).cast::<Sha256Ctx>()) }
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
unsafe extern "C" fn sha384_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA384_Init(md_data(ctx).cast::<Sha512Ctx>()) }
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
unsafe extern "C" fn sha512_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA512_Init(md_data(ctx).cast::<Sha512Ctx>()) }
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
unsafe extern "C" fn sha512_224_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { sha512_224_init(md_data(ctx).cast::<Sha512Ctx>()) }
}

/// `sha512_224_int_final` — the same table's final, over `SHA512_Final`.
unsafe extern "C" fn sha512_224_int_final(ctx: *mut EvpMdCtx, md: *mut c_uchar) -> c_int {
    // SAFETY: as above.
    unsafe { SHA512_Final(md, md_data(ctx).cast::<Sha512Ctx>()) }
}

/// `sha512_256_int_init` — `sha512_256_init`, for the reason `sha512_224_int_init` gives.
unsafe extern "C" fn sha512_256_int_init(ctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { sha512_256_init(md_data(ctx).cast::<Sha512Ctx>()) }
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
}
