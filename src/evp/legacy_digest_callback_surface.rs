//! Adversarial coverage for the **entire** exported legacy digest callback surface.
//!
//! B48 was rejected because it contracted 36 census sites while the exported surface is wider:
//! every `EVP_MD_meth_get_init/update/final/ctrl` getter hands out one of these callbacks, and
//! `EVP_MD_meth_new` + `EVP_MD_meth_set_app_datasize` lets a C caller put an arbitrary context
//! behind it. This module drives every callback installed by the 22 legacy `EVP_MD` tables
//! through the exported getters and the context shapes a caller can construct:
//!
//! * an undersized `md_data` (8 bytes) and a wrong-typed block whose extent passes;
//! * a NULL context block (`EVP_MD_CTX_new`-shaped) and a NULL `data` with `count != 0`;
//! * a `METH`-origin method whose `ctx_size` is 0, which allocates no block;
//! * a positive control proving the table's own bound context still digests.
//!
//! Each caller-created method installs the table's own exported callbacks with
//! `EVP_MD_meth_set_init/update/final/ctrl`, so `EVP_MD_meth_get_*` answers them and the test
//! observes a real invocation rather than an absent callback. `EVP_DigestInit_ex` is also driven
//! once per table: it allocates exactly `app_datasize` bytes, the extent the callback's guard
//! then compares against `size_of`.
//!
//! The extent of a caller-created block is mechanically checked by `init_md_data`/`init_keccak`.
//! The concrete **type** is not: `app_datasize` declares a size, not a type, so a correctly-sized
//! block of the wrong type is a caller contract violation.
//! `wrong_typed_block_is_admitted_when_extent_passes` and `extent_is_not_type` record that
//! boundary explicitly rather than claiming more than the guard establishes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::evp::digest::{
    EVP_DigestInit_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_free, EVP_MD_meth_get_ctrl,
    EVP_MD_meth_get_final, EVP_MD_meth_get_init, EVP_MD_meth_get_update, EVP_MD_meth_new,
    EVP_MD_meth_set_app_datasize, EVP_MD_meth_set_ctrl, EVP_MD_meth_set_final,
    EVP_MD_meth_set_init, EVP_MD_meth_set_result_size, EVP_MD_meth_set_update, EVP_md_null, EvpMd,
    EvpMdCtx,
};
use crate::evp::legacy_blake2::{EVP_blake2b512, EVP_blake2s256};
use crate::evp::legacy_md4::EVP_md4;
use crate::evp::legacy_md5::{EVP_md5, EVP_md5_sha1};
use crate::evp::legacy_mdc2::EVP_mdc2;
use crate::evp::legacy_ripemd::EVP_ripemd160;
use crate::evp::legacy_sha::{
    EVP_sha1, EVP_sha224, EVP_sha256, EVP_sha384, EVP_sha512, EVP_sha512_224, EVP_sha512_256,
};
use crate::evp::legacy_sha3::{
    EVP_sha3_224, EVP_sha3_256, EVP_sha3_384, EVP_sha3_512, EVP_shake128, EVP_shake256,
};
use crate::evp::legacy_wp::EVP_whirlpool;
use crate::legacy_sm3::EVP_sm3;

/// `EVP_CTRL_SSL3_MASTER_SECRET` — `include/openssl/evp.h:1221`.
const EVP_CTRL_SSL3_MASTER_SECRET: c_int = 0x1d;
/// `EVP_MD_CTRL_XOF_LEN` — `include/openssl/evp.h`.
const EVP_MD_CTRL_XOF_LEN: c_int = 0x3;
/// `NID_undef` — the type a caller-created `METH` method starts with.
const NID_UNDEF: c_int = 0;

/// The 22 `EVP_MD` objects the legacy digest modules export.
fn tables() -> [(&'static str, *const EvpMd); 22] {
    // Every entry point is a safe function that answers a live static method.
    [
        ("md4", EVP_md4()),
        ("md5", EVP_md5()),
        ("md5_sha1", EVP_md5_sha1()),
        ("sha1", EVP_sha1()),
        ("sha224", EVP_sha224()),
        ("sha256", EVP_sha256()),
        ("sha384", EVP_sha384()),
        ("sha512", EVP_sha512()),
        ("sha512_224", EVP_sha512_224()),
        ("sha512_256", EVP_sha512_256()),
        ("mdc2", EVP_mdc2()),
        ("ripemd160", EVP_ripemd160()),
        ("whirlpool", EVP_whirlpool()),
        ("sm3", EVP_sm3()),
        ("blake2b512", EVP_blake2b512()),
        ("blake2s256", EVP_blake2s256()),
        ("sha3_224", EVP_sha3_224()),
        ("sha3_256", EVP_sha3_256()),
        ("sha3_384", EVP_sha3_384()),
        ("sha3_512", EVP_sha3_512()),
        ("shake128", EVP_shake128()),
        ("shake256", EVP_shake256()),
    ]
}

/// A fresh `METH`-origin method with a caller-declared block size and result size.
fn custom_method(ctx_size: c_int, md_size: c_int) -> *mut EvpMd {
    // SAFETY: `EVP_MD_meth_new` allocates a fresh method this test owns.
    let md = unsafe { EVP_MD_meth_new(NID_UNDEF, 0) };
    assert!(!md.is_null(), "EVP_MD_meth_new answered NULL");
    // SAFETY: `md` is the fresh method above; each setter writes one still-zero field.
    unsafe {
        assert_eq!(EVP_MD_meth_set_app_datasize(md, ctx_size), 1);
        if md_size != 0 {
            assert_eq!(EVP_MD_meth_set_result_size(md, md_size), 1);
        }
    }
    md
}

/// A fresh `METH`-origin method that installs `table`'s callbacks, so the method answers the same
/// exported pointers a legacy table does while the test declares the caller-sized block.
fn method_with_table_callbacks(ctx_size: c_int, table: *const EvpMd) -> *mut EvpMd {
    let md = custom_method(ctx_size, 32);
    // SAFETY: `md` is the fresh method this test owns and `table` is a live static method; each
    // setter fills one still-NULL slot and answers 1.
    unsafe {
        assert_eq!(EVP_MD_meth_set_init(md, EVP_MD_meth_get_init(table)), 1);
        assert_eq!(EVP_MD_meth_set_update(md, EVP_MD_meth_get_update(table)), 1);
        assert_eq!(EVP_MD_meth_set_final(md, EVP_MD_meth_get_final(table)), 1);
        assert_eq!(EVP_MD_meth_set_ctrl(md, EVP_MD_meth_get_ctrl(table)), 1);
    }
    md
}

/// How many of the four callbacks `md` answers. Comparing this against the table is what proves
/// the install above happened and that the test is not driving an all-`None` method.
fn installed_callbacks(md: *const EvpMd) -> usize {
    // SAFETY: `md` is a live method this test owns or a live static method.
    unsafe {
        [
            EVP_MD_meth_get_init(md).is_some(),
            EVP_MD_meth_get_update(md).is_some(),
            EVP_MD_meth_get_final(md).is_some(),
            EVP_MD_meth_get_ctrl(md).is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
    }
}

/// A context with no provider state, as `EVP_MD_CTX_new` leaves it, but bound to `digest` and a
/// caller-supplied block.
fn ctx(digest: *const EvpMd, md_data: *mut c_void) -> EvpMdCtx {
    EvpMdCtx {
        reqdigest: digest,
        digest,
        engine: core::ptr::null_mut(),
        flags: 0,
        md_data,
        pctx: core::ptr::null_mut(),
        update: None,
        algctx: core::ptr::null_mut(),
        fetched_digest: core::ptr::null_mut(),
    }
}

/// Ask every callback installed on `md` to operate on `ctx`, which must not establish the
/// callback's concrete block. Each must answer the failure value without touching `md_data`.
/// Answers how many callbacks were invoked, so a caller can prove the method was not empty.
fn assert_callbacks_refuse(md: *const EvpMd, ctx_ptr: &mut EvpMdCtx, label: &str) -> usize {
    // SAFETY: `md` is a live static method or a live `METH` method this test owns.
    let (init, update, final_, ctrl) = unsafe {
        (
            EVP_MD_meth_get_init(md),
            EVP_MD_meth_get_update(md),
            EVP_MD_meth_get_final(md),
            EVP_MD_meth_get_ctrl(md),
        )
    };
    let message = b"abc";
    let mut invoked = 0;

    if let Some(init) = init {
        invoked += 1;
        // SAFETY: `ctx_ptr` is live and the callback accepts any live context.
        assert_eq!(
            // SAFETY: `ctx_ptr` is live and the callback accepts any live context.
            unsafe { init(ctx_ptr) },
            0,
            "{label}: init accepted the block"
        );
    }
    if let Some(update) = update {
        invoked += 1;
        // SAFETY: `ctx_ptr` is live and `message` is readable for its length.
        assert_eq!(
            // SAFETY: `ctx_ptr` is live and `message` is readable for its length.
            unsafe { update(ctx_ptr, message.as_ptr().cast(), message.len()) },
            0,
            "{label}: update accepted the block"
        );
        // SAFETY: a NULL `data` with a non-zero length is the input under test; the callback's
        // contract refuses it before the primitive is reached.
        assert_eq!(
            // SAFETY: a NULL `data` with a non-zero length is the input under test; the
            // callback's contract refuses it before the primitive is reached.
            unsafe { update(ctx_ptr, core::ptr::null(), 1) },
            0,
            "{label}: update accepted a NULL data with count 1"
        );
    }
    if let Some(final_) = final_ {
        invoked += 1;
        let mut output = [0u8; 64];
        // SAFETY: `ctx_ptr` is live and `output` is writable for the longest legacy digest.
        assert_eq!(
            // SAFETY: `ctx_ptr` is live and `output` is writable for the longest legacy digest.
            unsafe { final_(ctx_ptr, output.as_mut_ptr()) },
            0,
            "{label}: final accepted the block"
        );
    }
    if let Some(ctrl) = ctrl {
        invoked += 1;
        // SAFETY: `ctx_ptr` is live; neither command reads a `p2` on the refusals under test.
        let master = unsafe {
            ctrl(
                ctx_ptr,
                EVP_CTRL_SSL3_MASTER_SECRET,
                48,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        let xof = unsafe { ctrl(ctx_ptr, EVP_MD_CTRL_XOF_LEN, 32, core::ptr::null_mut()) };
        assert!(
            master != 1 && xof != 1,
            "{label}: ctrl wrote through the block (master {master}, xof {xof})"
        );
    }

    invoked
}

/// An undersized block (eight bytes) is refused by every callback, before any write.
///
/// The methods below carry the tables' **real** callbacks (the getter comparison proves the
/// install), and `EVP_DigestInit_ex` allocates exactly the declared eight bytes and reaches the
/// installed initialiser, which refuses that block.
#[test]
fn undersized_block_is_refused_for_every_callback() {
    let mut block = [0xa5u8; 8];
    for (name, table) in tables() {
        let md = method_with_table_callbacks(8, table);
        let expected = installed_callbacks(table);
        assert_eq!(
            installed_callbacks(md),
            expected,
            "{name}: the table's callbacks were not installed"
        );
        let mut c = ctx(md, block.as_mut_ptr().cast());
        assert_eq!(
            assert_callbacks_refuse(md, &mut c, name),
            expected,
            "{name}: a callback was not invoked"
        );
        assert_eq!(
            block, [0xa5u8; 8],
            "{name}: a refused callback modified md_data"
        );

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is live and `md` is this test's live method; the initialiser installed
        // above is reached with the eight-byte block `ctx_size` produces.
        assert_eq!(
            // SAFETY: `fresh` is live and `md` is this test's live method; the initialiser
            // installed above is reached with the eight-byte block `ctx_size` produces.
            unsafe { EVP_DigestInit_ex(fresh, md, core::ptr::null_mut()) },
            0,
            "{name}: EVP_DigestInit_ex accepted an eight-byte context"
        );
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
    }
}

/// A block whose **extent passes** but whose concrete type is wrong is admitted, not refused.
///
/// `app_datasize` is 1024 and the block is a `[u64; 128]`, a valid object of a different type
/// than any digest context and at least `size_of::<T>()` for every `T` the tables cast to. The
/// guard therefore compares extent only: each initialiser writes its own `size_of::<T>()` inside
/// the admitted block and answers 1. Refusal here would mean the guard checked a type it does
/// not have; admission is the measured residual (`extent_is_not_type`, B48-R5).
#[test]
fn wrong_typed_block_is_admitted_when_extent_passes() {
    // Every concrete context `T` the 22 tables cast to is smaller than this block, so writing a
    // `T` into its prefix below is in bounds.
    const _: () = {
        use crate::digest::blake2::{blake2b, blake2s};
        use crate::digest::md4::Md4Ctx;
        use crate::digest::md5::Md5Ctx;
        use crate::digest::md5_sha1::Md5Sha1Ctx;
        use crate::digest::mdc2::Mdc2Ctx;
        use crate::digest::ripemd::Ripemd160Ctx;
        use crate::digest::sha1::ShaCtx;
        use crate::digest::sha2::{Sha256Ctx, Sha512Ctx};
        use crate::digest::sha3::KeccakCtx;
        use crate::digest::sm3::Sm3Ctx;
        use crate::digest::wp::WhirlpoolCtx;
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<ShaCtx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Sha256Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Sha512Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Md4Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Md5Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Md5Sha1Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Mdc2Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Ripemd160Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<WhirlpoolCtx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<Sm3Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<KeccakCtx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<blake2b::Ctx>());
        assert!(core::mem::size_of::<[u64; 128]>() >= core::mem::size_of::<blake2s::Ctx>());
    };

    let mut block = [0x5au64; 128];
    for (name, table) in tables() {
        let md = method_with_table_callbacks(1024, table);
        let expected = installed_callbacks(table);
        assert_eq!(
            installed_callbacks(md),
            expected,
            "{name}: the table's callbacks were not installed"
        );
        let mut c = ctx(md, block.as_mut_ptr().cast());
        // SAFETY: `md` is this test's live method.
        let (init, update, final_) = unsafe {
            (
                EVP_MD_meth_get_init(md),
                EVP_MD_meth_get_update(md),
                EVP_MD_meth_get_final(md),
            )
        };
        assert!(
            init.is_some() && update.is_some() && final_.is_some(),
            "{name}: the table is missing one of its callbacks"
        );
        if let (Some(init), Some(update), Some(final_)) = (init, update, final_) {
            // SAFETY: `c` is live, the block is 1024 bytes, and the method declares that extent.
            assert_eq!(
                // SAFETY: `c` is live, the block is 1024 bytes, and the method declares that
                // extent.
                unsafe { init(&mut c) },
                1,
                "{name}: init refused a block whose extent passed"
            );
            let message = b"abc";
            // SAFETY: `init` above wrote the concrete context into the block's prefix and
            // `message` is readable for its length.
            assert_eq!(
                // SAFETY: `init` above wrote the concrete context into the block's prefix and
                // `message` is readable for its length.
                unsafe { update(&mut c, message.as_ptr().cast(), message.len()) },
                1,
                "{name}: update failed on the admitted block"
            );
            let mut output = [0u8; 64];
            // SAFETY: the block holds the concrete context and `output` is writable for 64 bytes.
            assert_eq!(
                // SAFETY: the block holds the concrete context and `output` is writable for 64
                // bytes.
                unsafe { final_(&mut c, output.as_mut_ptr()) },
                1,
                "{name}: final failed on the admitted block"
            );
        }
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
        block = [0x5au64; 128];
    }
}

/// A NULL `md_data` is refused by every callback, including after a refused init has left a fresh
/// `EVP_MD_CTX_new()` context with no block.
#[test]
fn null_md_data_is_refused_for_every_callback() {
    for (name, table) in tables() {
        let mut c = ctx(table, core::ptr::null_mut());
        assert_callbacks_refuse(table, &mut c, name);
    }

    // The library-shaped fresh context, not a hand-built one.
    let fresh = EVP_MD_CTX_new();
    assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
    for (name, table) in tables() {
        // SAFETY: `fresh` is live and `md` is a live static method.
        let (init, update, final_) = unsafe {
            (
                EVP_MD_meth_get_init(table),
                EVP_MD_meth_get_update(table),
                EVP_MD_meth_get_final(table),
            )
        };
        if let Some(init) = init {
            // SAFETY: `fresh` is live.
            assert_eq!(
                // SAFETY: `fresh` is live.
                unsafe { init(fresh) },
                0,
                "{name}: init accepted a fresh context"
            );
        }
        if let Some(update) = update {
            let message = b"abc";
            // SAFETY: `fresh` is live and `message` is readable.
            assert_eq!(
                // SAFETY: `fresh` is live and `message` is readable.
                unsafe { update(fresh, message.as_ptr().cast(), message.len()) },
                0,
                "{name}: update accepted a fresh context"
            );
        }
        if let Some(final_) = final_ {
            let mut output = [0u8; 64];
            // SAFETY: `fresh` is live and `output` is writable.
            assert_eq!(
                // SAFETY: `fresh` is live and `output` is writable.
                unsafe { final_(fresh, output.as_mut_ptr()) },
                0,
                "{name}: final accepted a fresh context"
            );
        }
    }
    // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
    unsafe { EVP_MD_CTX_free(fresh) };
}

/// A NULL `data` with `count != 0` is refused by every update callback **after** the block guard
/// has passed. The context is bound to the owner table with a large block, so only the new
/// `data` guard can stop the primitive.
#[test]
fn null_data_with_nonzero_count_is_refused_for_every_update_callback() {
    let mut block = [0u64; 128];
    for (name, table) in tables() {
        // SAFETY: `table` is a live static method.
        let update = unsafe { EVP_MD_meth_get_update(table) };
        let Some(update) = update else { continue };
        let mut c = ctx(table, block.as_mut_ptr().cast());
        // SAFETY: `c` is live and its owner-identity block is large enough for every legacy
        // context; the callback must refuse the NULL `data` before the primitive reads it.
        assert_eq!(
            // SAFETY: `c` is live and its owner-identity block is large enough for every legacy
            // context; the callback must refuse the NULL `data` before the primitive reads it.
            unsafe { update(&mut c, core::ptr::null(), 1) },
            0,
            "{name}: update accepted a NULL data with count 1"
        );
        assert_eq!(
            block, [0u64; 128],
            "{name}: a refused update modified md_data"
        );
    }
}

/// A `METH`-origin method whose declared `ctx_size` is zero allocates no block, so every callback
/// refuses the non-NULL block a caller might still attach.
#[test]
fn zero_ctx_size_legacy_method_is_refused_for_every_callback() {
    let mut block = [0u64; 128];
    for (name, table) in tables() {
        let md = method_with_table_callbacks(0, table);
        let expected = installed_callbacks(table);
        assert_eq!(
            installed_callbacks(md),
            expected,
            "{name}: the table's callbacks were not installed"
        );
        let mut c = ctx(md, block.as_mut_ptr().cast());
        assert_eq!(
            assert_callbacks_refuse(md, &mut c, name),
            expected,
            "{name}: a callback was not invoked"
        );
        assert_eq!(
            block, [0u64; 128],
            "{name}: a refused callback modified md_data"
        );

        let fresh = EVP_MD_CTX_new();
        assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
        // SAFETY: `fresh` is live and `md` is this test's live method; `ctx_size == 0` allocates
        // no block, so the installed initialiser is reached with a NULL `md_data` and refuses.
        assert_eq!(
            // SAFETY: `fresh` is live and `md` is this test's live method; `ctx_size == 0`
            // allocates no block, so the installed initialiser sees a NULL `md_data`.
            unsafe { EVP_DigestInit_ex(fresh, md, core::ptr::null_mut()) },
            0,
            "{name}: EVP_DigestInit_ex accepted a context with no block"
        );
        // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
        unsafe { EVP_MD_CTX_free(fresh) };
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
    }
}

/// The extent guard is not a type guard. A `METH` method that declares a large enough
/// `app_datasize` gets its callback called with a block of that size even when the block is not
/// the callback's concrete context. This is the residual the receipt names: the caller chooses
/// the callback and the size, so the type is the caller's obligation, not a mechanically checked
/// property. Every init answers `1` here, proving the boundary is exactly extent.
#[test]
fn extent_is_not_type() {
    let mut block = [0u64; 128];
    for (name, table) in tables() {
        let md = custom_method(1024, 32);
        let mut c = ctx(md, block.as_mut_ptr().cast());
        // SAFETY: `table` is a live static method.
        let init = unsafe { EVP_MD_meth_get_init(table) };
        assert!(init.is_some(), "{name}: the table has no init");
        if let Some(init) = init {
            assert_eq!(
                // SAFETY: `c` is live and the block is 1024 bytes, the extent the method declared.
                unsafe { init(&mut c) },
                1,
                "{name}: init refused a block whose extent matched the declaration"
            );
        }
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
        block = [0u64; 128];
    }
}

/// `shake_ctrl` refuses a negative `EVP_MD_CTRL_XOF_LEN` before it stores the length, while a
/// non-negative length on the same valid context still succeeds.
#[test]
fn shake_ctrl_refuses_a_negative_xof_length() {
    // SAFETY: `EVP_shake128()` answers a live static method.
    let ctrl = unsafe { EVP_MD_meth_get_ctrl(EVP_shake128()) };
    assert!(ctrl.is_some(), "shake128_md has no ctrl");
    let Some(ctrl) = ctrl else { return };

    let md = custom_method(1024, 32);
    let mut block = [0u64; 128];
    let mut c = ctx(md, block.as_mut_ptr().cast());
    assert_eq!(
        // SAFETY: `c` is live and declares a 1024-byte block with a positive method `md_size`;
        // the negative length must be refused before the write.
        unsafe { ctrl(&mut c, EVP_MD_CTRL_XOF_LEN, -1, core::ptr::null_mut()) },
        0,
        "shake_ctrl accepted a negative XOF length"
    );
    assert_eq!(
        block, [0u64; 128],
        "a refused negative length modified md_data"
    );
    assert_eq!(
        // SAFETY: the same live context; a non-negative length is the valid shape.
        unsafe { ctrl(&mut c, EVP_MD_CTRL_XOF_LEN, 32, core::ptr::null_mut()) },
        1,
        "shake_ctrl refused a valid XOF length"
    );
    // SAFETY: `md` is this test's own method, released exactly once here.
    unsafe { EVP_MD_meth_free(md) };
}

/// `EVP_md_null` is the sibling legacy method in `src/evp/digest.rs`. Its three callbacks read no
/// argument at all, so a fresh context (and even a NULL one) still succeeds and needs no block.
#[test]
fn md_null_callbacks_need_no_block() {
    // SAFETY: `EVP_md_null()` answers a live static method.
    let (init, update, final_) = unsafe {
        (
            EVP_MD_meth_get_init(EVP_md_null()),
            EVP_MD_meth_get_update(EVP_md_null()),
            EVP_MD_meth_get_final(EVP_md_null()),
        )
    };
    assert!(
        init.is_some() && update.is_some() && final_.is_some(),
        "EVP_md_null is missing one of its callbacks"
    );
    let fresh = EVP_MD_CTX_new();
    assert!(!fresh.is_null(), "EVP_MD_CTX_new answered NULL");
    let message = b"abc";
    let mut output = [0u8; 64];
    if let (Some(init), Some(update), Some(final_)) = (init, update, final_) {
        assert_eq!(
            // SAFETY: `fresh` is live; the null callback reads nothing.
            unsafe { init(fresh) },
            1
        );
        assert_eq!(
            // SAFETY: `fresh` is live and `message` is readable.
            unsafe { update(fresh, message.as_ptr().cast(), message.len()) },
            1
        );
        assert_eq!(
            // SAFETY: `fresh` is live and `output` is writable.
            unsafe { final_(fresh, output.as_mut_ptr()) },
            1
        );
    }
    // SAFETY: `fresh` came from `EVP_MD_CTX_new` and is released exactly once here.
    unsafe { EVP_MD_CTX_free(fresh) };
}

/// Positive control: a context bound to `sha1_md` with a writable block still digests, so the
/// guards narrow only the invalid shapes.
#[test]
fn valid_sha1_call_still_succeeds() {
    // SAFETY: `EVP_sha1()` answers a live static method.
    let (init, update, final_) = unsafe {
        (
            EVP_MD_meth_get_init(EVP_sha1()),
            EVP_MD_meth_get_update(EVP_sha1()),
            EVP_MD_meth_get_final(EVP_sha1()),
        )
    };
    assert!(
        init.is_some() && update.is_some() && final_.is_some(),
        "sha1_md is missing one of its callbacks"
    );

    if let (Some(init), Some(update), Some(final_)) = (init, update, final_) {
        let mut store = [0u64; 128];
        let mut c = ctx(EVP_sha1(), store.as_mut_ptr().cast());
        assert_eq!(
            // SAFETY: `c` is live, bound to `sha1_md`, and `store` is writable for a `SHA_CTX`.
            unsafe { init(&mut c) },
            1,
            "init refused a valid SHA_CTX"
        );
        let message = b"abc";
        assert_eq!(
            // SAFETY: `c` was just initialised and `message` is readable for its length.
            unsafe { update(&mut c, message.as_ptr().cast(), message.len()) },
            1
        );
        let mut output = [0u8; 20];
        assert_eq!(
            // SAFETY: `output` is writable for the SHA-1 digest length.
            unsafe { final_(&mut c, output.as_mut_ptr()) },
            1
        );
        assert_eq!(
            output,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ],
            "SHA1(\"abc\") changed"
        );
    }
}

/// A caller-built method that declares `app_datasize == size_of::<KeccakCtx>()` passes
/// `init_keccak`'s extent check (`legacy_sha3.rs:156`), so a `result_size` of `0` or `-1` is
/// refused **only** by the `md_size <= 0` check at `legacy_sha3.rs:162`. All six SHA-3/SHAKE
/// tables are driven through the exported getters, with `final` first and a byte-identical block
/// asserted after every call.
///
/// **Mutation-sensitive: deleting `md_size <= 0` at `legacy_sha3.rs:162` makes the `final`
/// assertion fail** for every table and both result sizes (`ossl_sha3_final` answers `1` for the
/// zeroed block, whose `KeccakCtx::md_size` is 0). The positive control at the end proves the
/// same declared extent is admitted when `md_size` is positive, i.e. that this test does not fail
/// on the extent check.
#[test]
fn nonpositive_result_size_is_refused_for_every_sha3_and_shake_surface() {
    use crate::digest::sha3::KeccakCtx;

    let keccak_size = core::mem::size_of::<KeccakCtx>();
    let mut block = [0u64; 64];
    assert!(core::mem::size_of_val(&block) >= keccak_size);

    for (name, table) in [
        ("sha3_224", EVP_sha3_224()),
        ("sha3_256", EVP_sha3_256()),
        ("sha3_384", EVP_sha3_384()),
        ("sha3_512", EVP_sha3_512()),
        ("shake128", EVP_shake128()),
        ("shake256", EVP_shake256()),
    ] {
        // SAFETY: each getter answers `table`'s own live callbacks.
        let (init, final_, ctrl) = unsafe {
            (
                EVP_MD_meth_get_init(table),
                EVP_MD_meth_get_final(table),
                EVP_MD_meth_get_ctrl(table),
            )
        };
        let Some((init, final_)) = init.zip(final_) else {
            panic!("{name}: the table is missing init/final");
        };

        for result_size in [0, -1] {
            // SAFETY: `EVP_MD_meth_new` allocates a fresh method this test owns.
            let md = unsafe { EVP_MD_meth_new(NID_UNDEF, 0) };
            assert!(!md.is_null(), "{name}: EVP_MD_meth_new answered NULL");
            // SAFETY: `md` is the fresh method above; each setter writes one still-zero field.
            unsafe {
                assert_eq!(EVP_MD_meth_set_app_datasize(md, keccak_size as c_int), 1);
                assert_eq!(EVP_MD_meth_set_result_size(md, result_size), 1);
                assert_eq!(EVP_MD_meth_set_init(md, Some(init)), 1);
                assert_eq!(EVP_MD_meth_set_final(md, Some(final_)), 1);
                assert_eq!(EVP_MD_meth_set_ctrl(md, ctrl), 1);
            }
            let mut c = ctx(md, block.as_mut_ptr().cast());
            let mut output = [0u8; 64];

            // SAFETY: `c` is live and its method declares exactly the block's extent, so only the
            // `md_size <= 0` guard can refuse.
            assert_eq!(
                unsafe { final_(&mut c, output.as_mut_ptr()) },
                0,
                "{name}: final accepted result_size {result_size}"
            );
            assert_eq!(
                block, [0u64; 64],
                "{name}: a refused final modified md_data"
            );

            // SAFETY: as above, for the initialiser.
            assert_eq!(
                unsafe { init(&mut c) },
                0,
                "{name}: init accepted result_size {result_size}"
            );
            assert_eq!(block, [0u64; 64], "{name}: a refused init modified md_data");

            if let Some(ctrl) = ctrl {
                // SAFETY: `c` is live and the command reads no argument buffer.
                assert_eq!(
                    unsafe { ctrl(&mut c, EVP_MD_CTRL_XOF_LEN, 32, core::ptr::null_mut()) },
                    0,
                    "{name}: ctrl accepted result_size {result_size}"
                );
                assert_eq!(block, [0u64; 64], "{name}: a refused ctrl modified md_data");
            }

            // SAFETY: `md` is this test's own method, released exactly once here.
            unsafe { EVP_MD_meth_free(md) };
        }

        // Positive control: the same extent with a positive `result_size` is admitted.
        // SAFETY: `EVP_MD_meth_new` allocates a fresh method this test owns.
        let md = unsafe { EVP_MD_meth_new(NID_UNDEF, 0) };
        assert!(!md.is_null(), "{name}: EVP_MD_meth_new answered NULL");
        // SAFETY: `md` is the fresh method above.
        unsafe {
            assert_eq!(EVP_MD_meth_set_app_datasize(md, keccak_size as c_int), 1);
            assert_eq!(EVP_MD_meth_set_result_size(md, 32), 1);
            assert_eq!(EVP_MD_meth_set_init(md, Some(init)), 1);
        }
        let mut c = ctx(md, block.as_mut_ptr().cast());
        // SAFETY: `c` is live and the block is at least a `KeccakCtx` long.
        assert_eq!(
            unsafe { init(&mut c) },
            1,
            "{name}: the matching extent was refused"
        );
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
        block = [0u64; 64];
    }
}
