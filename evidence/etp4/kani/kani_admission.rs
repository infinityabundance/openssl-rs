//! Kani admission controls for ETP-4.
//!
//! These harnesses qualify the verifier, not the production code. The positive
//! harness must verify; the negative harness must fail with a counterexample.
//! Neither result says anything about `openssl-rs`.
//!
//! Run (inside the court, after `kani setup`):
//!
//! ```text
//! kani evidence/etp4/kani/kani_admission.rs --harness admission_positive
//! kani evidence/etp4/kani/kani_admission.rs --harness admission_negative_must_fail
//! ```

#[kani::proof]
fn admission_positive() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    kani::assume(a < 100);
    kani::assume(b < 100);
    assert!((a as u16) + (b as u16) < 200);
}

#[kani::proof]
fn admission_negative_must_fail() {
    let a: u8 = kani::any();
    // False at a == 128: doubling wraps to zero. Kani must produce a
    // counterexample rather than report success.
    assert!(a.wrapping_mul(2) != 0 || a != 128);
}
