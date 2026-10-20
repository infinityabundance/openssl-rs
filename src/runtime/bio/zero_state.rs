//! Executable zero-state sweep for the shared `CtxDestroy` implementations.
//!
//! [`CtxDestroy`](crate::runtime::bio::owned::CtxDestroy)'s implementer
//! obligation (b) states that an all-zero block is a valid `Self` and that
//! `destroy_body` is sound on it. `DESTRUCTOR-CONTRACTS.md` records that
//! obligation as source evidence for every impl; this module executes it.
//!
//! [`zero_state_sweep!`] is invoked at the bottom of each source file that owns
//! shared impls, so the generated test lives next to the type and can name even
//! a private one. It expands to one test function per type, making each test
//! path name the type it covers. Every test does exactly obligation (b) and
//! nothing else:
//!
//! 1. allocate `size_of::<T>()` zeroed bytes through the crate's allocator seam
//!    (`CRYPTO_zalloc`);
//! 2. call `T::destroy_body` on that all-zero value;
//! 3. release the block with `CRYPTO_free`.
//!
//! No constructor and no owner `Drop` runs, so the test cannot pass by way of
//! the `OwnedCtx`/`RawCtx` machinery. A type whose destructor needs a non-NULL
//! lock or method is still expected to be zero-valid by contract; if it is not,
//! the generated test fails and names it.
//!
//! Out of scope: the module-local `CtxDestroy` copies (`ec`, `ssl`,
//! `x509::dane`) implement a *different* trait, and the `ProbeCtx` impls are
//! already test-only.
//!
//! SPDX-License-Identifier: Apache-2.0

/// Expand to one all-zero-block destructor test per `Type => test_fn` pair.
///
/// Each type must be nameable as `$t` from the invocation site (the file that
/// owns its `runtime::bio::owned::CtxDestroy` impl). The test function name is
/// supplied by the caller because a generated module named after the type would
/// collide with the type itself in the module's type namespace.
macro_rules! zero_state_sweep {
    ($($t:ident => $f:ident),+ $(,)?) => {
        $(
            #[test]
            fn $f() {
                let size = core::mem::size_of::<$t>();
                let raw = unsafe {
                    // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
                    crate::runtime::mem::CRYPTO_zalloc(size, core::ptr::null(), 0)
                };
                assert!(
                    !raw.is_null(),
                    "CRYPTO_zalloc refused the zero-state block for {}",
                    stringify!($t),
                );

                // SAFETY: `raw` is a fresh zeroed block of exactly `size_of::<T>()` bytes from
                // this crate's allocator; obligation (b) states that an all-zero block is a valid
                // `T` for which `destroy_body` is sound. `destroy_body` releases only owned
                // members and never the enclosing block (obligation (a)), so the block stays
                // live for the release below.
                unsafe {
                    <$t as crate::runtime::bio::owned::CtxDestroy>::destroy_body(
                        raw.cast::<$t>(),
                    );
                }

                // SAFETY: the block above is still live and this is its single release.
                unsafe { crate::runtime::mem::CRYPTO_free(raw, core::ptr::null(), 0) };
            }
        )+
    };
}

pub(crate) use zero_state_sweep;
