//! Fallible allocation for the constant-time BN path.
//!
//! Every heap request that can grow with a modulus or an exponent on the
//! constant-time ladder goes through here, so an allocation failure becomes an
//! ordinary `None`/error return instead of `handle_alloc_error`'s process abort.
//! The helpers are deliberately small and total: the amount is reserved with
//! [`Vec::try_reserve_exact`], which also reports capacity overflow, and only
//! then is the vector filled.
//!
//! This module does not close `OBL-BN-ALLOCATOR`. The variable-time public path
//! and the C-ABI argument copies in [`crate::bn::bignum::parts`] still use
//! infallible `Vec` operations; those residuals are named in the batch receipt.

/// A zeroed vector of exactly `n` elements, or `None` when the allocator
/// refuses (including when `n * size_of::<T>()` overflows the allocation
/// limits).
pub(crate) fn try_zeroed<T: Clone>(n: usize, zero: T) -> Option<Vec<T>> {
    #[cfg(test)]
    if test_fail::should_fail() {
        return None;
    }
    let mut v: Vec<T> = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, zero);
    Some(v)
}

/// Copy `src` into a fresh vector, or `None` when the allocation fails.
pub(crate) fn try_clone_slice<T: Clone>(src: &[T]) -> Option<Vec<T>> {
    #[cfg(test)]
    if test_fail::should_fail() {
        return None;
    }
    let mut v = Vec::new();
    v.try_reserve_exact(src.len()).ok()?;
    v.extend_from_slice(src);
    Some(v)
}

/// Test-only allocation-failure seam.
///
/// A unit test can arm a budget on its own thread and then exercise the real
/// code path while each fallible allocation in turn is forced to fail. This
/// proves that the path *reports* failure rather than aborting; it does not
/// prove that no allocation exists outside these helpers (a request made by an
/// infallible `Vec` operation never consults this seam).
#[cfg(test)]
pub(crate) mod test_fail {
    use core::cell::Cell;

    thread_local! {
        /// Successful allocations still allowed on this thread, or `None` when
        /// the seam is not armed. `Some(0)` fails the next allocation.
        static BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// Fail the allocation that follows `successes` successful ones.
    pub(crate) fn fail_after(successes: usize) -> Guard {
        BUDGET.with(|b| b.set(Some(successes)));
        Guard
    }

    /// Disarms the seam when the test leaves scope, including on a panic.
    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            BUDGET.with(|b| b.set(None));
        }
    }

    /// Consume one allocation from the budget; true when this one must fail.
    pub(crate) fn should_fail() -> bool {
        BUDGET.with(|b| match b.get() {
            None => false,
            Some(0) => true,
            Some(n) => {
                b.set(Some(n - 1));
                false
            }
        })
    }
}
