//! Phase 25.12 — committed Kani proof harnesses for `openssl-rs`.
//!
//! The memory-safety stratum (`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` 25.12) records the Kani
//! harness results over the harnesses that actually exist. These are those harnesses: bounded
//! model-checking proofs over **pure, public** functions of the crate that Kani can express
//! exactly. They are compiled only under Kani (`--cfg kani`); under a normal `cargo test` this
//! file is empty and the `kani` crate is never required, so the crate's ordinary test suite is
//! unaffected.
//!
//! ## Why the exported FFI surface is not proved here
//!
//! Every exported `extern "C"` entry point runs its body inside `ffi::guard_ffi`, which wraps it in
//! `std::panic::catch_unwind` so a Rust panic can never cross the C ABI. Kani 0.68.0 aborts with an
//! internal compiler error while lowering the `catch_unwind` intrinsic on its own pinned toolchain
//! (`kani-compiler/src/intrinsics.rs`: it asserts the intrinsic output is `i32`, and this nightly's
//! `catch_unwind` intrinsic no longer is), so **no** harness that reaches a crate FFI entry point
//! can even be compiled by this Kani. The plane records that as a per-target `UNSUPPORTED` with the
//! exact command and compiler message; it is never a pass. The harnesses here therefore target the
//! pure public surface (the BLAKE2 provider parameter block, `src/digest/blake2.rs`), which does not
//! cross the panic guard.

#![cfg(kani)]

use openssl_rs::asn1::der::ASN1_object_size;
use openssl_rs::digest::blake2::blake2b::{
    param_init, param_set_personal, Param, DIGEST_LENGTH, PERSONALBYTES,
};

/// The `personal` field's byte offset inside `BLAKE2B_PARAM` (`prov/blake2.h:63`); the module keeps
/// it private, so this proof pins the layout it was written against.
const PERSONAL_OFFSET: usize = 48;

/// `blake2b::param_init` must always produce the documented parameter prefix and nothing else: the
/// digest-length byte (`DIGEST_LENGTH`), a zero key-length, and the `fanout == 1`, `depth == 1`
/// bytes, with the whole 64-byte block zero elsewhere. This is the initialization every BLAKE2b
/// context depends on, so it must hold for an arbitrary starting block.
#[kani::proof]
#[kani::unwind(61)]
fn blake2b_param_init_sets_the_documented_prefix() {
    let mut p = Param { b: kani::any() };
    param_init(&mut p);
    assert_eq!(p.b[0], DIGEST_LENGTH, "digest_length byte");
    assert_eq!(p.b[1], 0, "key_length byte");
    assert_eq!(p.b[2], 1, "fanout byte");
    assert_eq!(p.b[3], 1, "depth byte");
    let mut i = 4;
    while i < 64 {
        assert_eq!(p.b[i], 0, "reserved/padding byte must be zero");
        i += 1;
    }
}

/// `blake2b::param_set_personal` must be **bounded** and **zero-filling**: for every caller length
/// `n <= PERSONALBYTES` it writes exactly `n` bytes of the given slice followed by `PERSONALBYTES - n`
/// zero bytes, and never touches any other byte of the block. Kani checks the slice bounds and the
/// `PERSONAL_OFFSET + n .. PERSONAL_OFFSET + PERSONALBYTES` arithmetic, so this proves the routine
/// cannot panic, underflow or overrun the parameter block for any admissible length — the bound the
/// caller's length check is supposed to make safe.
#[kani::proof]
#[kani::unwind(65)]
fn blake2b_param_set_personal_is_bounded_and_zero_filled() {
    let before: [u8; 64] = kani::any();
    let mut p = Param { b: before };
    let input: [u8; PERSONALBYTES] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= PERSONALBYTES);
    param_set_personal(&mut p, &input[..n]);
    let mut i = 0;
    while i < PERSONALBYTES {
        if i < n {
            assert_eq!(
                p.b[PERSONAL_OFFSET + i],
                input[i],
                "the input bytes are copied verbatim"
            );
        } else {
            assert_eq!(
                p.b[PERSONAL_OFFSET + i],
                0,
                "the remainder of the field is zero"
            );
        }
        i += 1;
    }
    // No byte outside the personal field may move: everything before the field and everything after
    // it is unchanged from the starting block.
    let mut j = 0;
    while j < PERSONAL_OFFSET {
        assert_eq!(
            p.b[j], before[j],
            "bytes before the personal field are untouched"
        );
        j += 1;
    }
    let mut k = PERSONAL_OFFSET + PERSONALBYTES;
    while k < 64 {
        assert_eq!(
            p.b[k], before[k],
            "bytes after the personal field are untouched"
        );
        k += 1;
    }
}

/// `ASN1_object_size` (`src/asn1/der.rs`) must, for every non-negative content length it accepts,
/// answer a size that strictly exceeds the content by at least a tag octet and a length octet.
///
/// **This harness is a stated target Kani 0.68.0 cannot express.** `ASN1_object_size` runs inside
/// `ffi::guard_ffi`, whose `std::panic::catch_unwind` triggers a Kani compiler internal error on
/// this toolchain; the plane records it `UNSUPPORTED` with the exact message, never a pass. It is
/// kept in the tree so the target is a fact rather than a claim, and `kani --harness` filtering
/// keeps it out of the codegen of the other harnesses.
#[kani::proof]
fn asn1_object_size_always_has_encoding_overhead() {
    let constructed: core::ffi::c_int = kani::any();
    let length: core::ffi::c_int = kani::any();
    let tag: core::ffi::c_int = kani::any();
    let r = ASN1_object_size(constructed, length, tag);
    if length >= 0 && r != -1 {
        assert!(
            r >= length + 2,
            "ASN1_object_size must exceed the content length by at least a tag and a length octet"
        );
    }
}

/// `ASN1_object_size` must reject a negative content length with `-1` for every `constructed` and
/// `tag`. Like the harness above, this reaches `guard_ffi` and is a stated target Kani 0.68.0
/// cannot compile; the plane records it `UNSUPPORTED`.
#[kani::proof]
fn asn1_object_size_rejects_negative_length() {
    let constructed: core::ffi::c_int = kani::any();
    let tag: core::ffi::c_int = kani::any();
    let r = ASN1_object_size(constructed, -1, tag);
    assert_eq!(r, -1, "a negative length must be rejected with -1");
}

/// The positive control. Kani must be known to *detect* a violation in this venue before any proof
/// it reports is trusted: this harness asserts something false for every symbolic input, so Kani
/// must report it `FAILED`. The plane records the control's outcome and refuses a passing result if
/// the control did not fire.
#[kani::proof]
fn kani_positive_control_deliberate_failure() {
    let x: u8 = kani::any();
    assert!(
        x != x,
        "deliberate false assertion: Kani must report this harness FAILED"
    );
}
