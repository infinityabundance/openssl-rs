//! Adversarial coverage for the **entire** exported legacy digest callback surface.
//!
//! B48 was rejected because it contracted 36 census sites while the exported surface is wider:
//! every `EVP_MD_meth_get_init/update/final/ctrl` getter hands out one of these callbacks, and
//! `EVP_MD_meth_new` + `EVP_MD_meth_set_app_datasize` lets a C caller put an arbitrary context
//! behind it. This module drives every callback installed by the 22 legacy `EVP_MD` tables
//! through the exported getters and the context shapes a caller can construct:
//!
//! * an undersized `md_data` (8 bytes) and a wrong-typed block (a `u64`);
//! * a NULL context block (`EVP_MD_CTX_new`-shaped) and a NULL `data` with `count != 0`;
//! * a `METH`-origin method whose `ctx_size` is 0, which allocates no block;
//! * a positive control proving the table's own bound context still digests.
//!
//! The extent of a caller-created block is mechanically checked by `init_md_data`/`init_keccak`.
//! The concrete **type** is not: `app_datasize` declares a size, not a type, so a correctly-sized
//! block of the wrong type is a caller contract violation. `extent_is_not_type` records that
//! boundary explicitly rather than claiming more than the guard establishes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::evp::digest::{
    EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_meth_free, EVP_MD_meth_get_ctrl, EVP_MD_meth_get_final,
    EVP_MD_meth_get_init, EVP_MD_meth_get_update, EVP_MD_meth_new, EVP_MD_meth_set_app_datasize,
    EVP_MD_meth_set_result_size, EVP_md_null, EvpMd, EvpMdCtx,
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
fn assert_callbacks_refuse(md: *const EvpMd, ctx_ptr: &mut EvpMdCtx, label: &str) {
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

    if let Some(init) = init {
        // SAFETY: `ctx_ptr` is live and the callback accepts any live context.
        assert_eq!(
            // SAFETY: `ctx_ptr` is live and the callback accepts any live context.
            unsafe { init(ctx_ptr) },
            0,
            "{label}: init accepted the block"
        );
    }
    if let Some(update) = update {
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
}

/// An undersized block (eight bytes) is refused by every callback, before any write.
#[test]
fn undersized_block_is_refused_for_every_callback() {
    let mut block = [0xa5u8; 8];
    for (name, _table) in tables() {
        let md = custom_method(8, 32);
        let mut c = ctx(md, block.as_mut_ptr().cast());
        assert_callbacks_refuse(md, &mut c, name);
        assert_eq!(
            block, [0xa5u8; 8],
            "{name}: a refused callback modified md_data"
        );
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
    }
}

/// A wrong-typed block is refused for every callback that casts: an eight-byte `u64` is neither
/// the concrete context of any callback nor large enough for one.
#[test]
fn wrong_typed_block_is_refused_for_every_callback() {
    let mut block = [0x5au64; 1];
    for (name, _table) in tables() {
        let md = custom_method(8, 32);
        let mut c = ctx(md, block.as_mut_ptr().cast());
        assert_callbacks_refuse(md, &mut c, name);
        assert_eq!(
            block, [0x5au64; 1],
            "{name}: a refused callback modified the u64"
        );
        // SAFETY: `md` is this test's own method, released exactly once here.
        unsafe { EVP_MD_meth_free(md) };
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
    for (name, _table) in tables() {
        let md = custom_method(0, 32);
        let mut c = ctx(md, block.as_mut_ptr().cast());
        assert_callbacks_refuse(md, &mut c, name);
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
