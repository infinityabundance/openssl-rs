//! Fallible allocation for the runtime's secret-bearing paths.
//!
//! Every heap request that can grow with a modulus or an exponent on the
//! constant-time ladder goes through here, so an allocation failure becomes an
//! ordinary `None`/error return instead of `handle_alloc_error`'s process abort.
//! This module lives in `runtime` because [`crate::runtime::secret`]'s heap owner
//! allocates through it; `crate::bn::alloc` re-exports the same items, so the
//! BN subsystem depends on the runtime rather than the reverse (T26).
//! The helpers are deliberately small and total: the amount is reserved with
//! [`Vec::try_reserve_exact`], which also reports capacity overflow, and only
//! then is the vector filled.
//!
//! This module does not close `OBL-BN-ALLOCATOR`. The variable-time public path
//! and the `BIGNUM` object boxes still have infallible sites; those residuals are
//! named in the batch receipt.

/// A zeroed vector of exactly `n` elements, or `None` when the allocator
/// refuses (including when `n * size_of::<T>()` overflows the allocation
/// limits).
#[track_caller]
pub(crate) fn try_zeroed<T: Clone>(n: usize, zero: T) -> Option<Vec<T>> {
    // An empty vector asks the allocator for nothing; it is not a failure site.
    if n == 0 {
        return Some(Vec::new());
    }
    #[cfg(test)]
    if test_fail::should_fail(core::panic::Location::caller()) {
        return None;
    }
    let mut v: Vec<T> = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, zero);
    Some(v)
}

/// Copy `src` into a fresh vector, or `None` when the allocation fails.
#[track_caller]
pub(crate) fn try_clone_slice<T: Clone>(src: &[T]) -> Option<Vec<T>> {
    // Copying nothing asks the allocator for nothing; it is not a failure site.
    if src.is_empty() {
        return Some(Vec::new());
    }
    #[cfg(test)]
    if test_fail::should_fail(core::panic::Location::caller()) {
        return None;
    }
    let mut v = Vec::new();
    v.try_reserve_exact(src.len()).ok()?;
    v.extend_from_slice(src);
    Some(v)
}

/// Reserve `additional` more elements, reporting failure instead of aborting.
///
/// The test seam sees this request too, so a sweep covers the in-place growth
/// sites (`bn_wexpand`, the `BN_CTX` pool, `BN_set_bit`) and not only fresh
/// vectors.
#[track_caller]
pub(crate) fn try_reserve<T>(v: &mut Vec<T>, additional: usize) -> bool {
    let Some(need) = v.len().checked_add(additional) else {
        return false;
    };
    // A request that the existing capacity already satisfies does not reach the
    // allocator, so it is not a failure site and the seam must not treat it as one.
    if v.capacity() >= need {
        return true;
    }
    #[cfg(test)]
    if test_fail::should_fail(core::panic::Location::caller()) {
        return false;
    }
    v.try_reserve(additional).is_ok()
}

/// Box `value` on the heap, or give it back when the allocator refuses.
///
/// This is the fallible form of `Box::new` for the `BIGNUM`, `BN_CTX` and
/// `BN_MONT_CTX` objects the secret-bearing entry points allocate. A `Box` built
/// this way is released with `Box::from_raw` exactly like one built with
/// `Box::new`, because both use the `Global` allocator. The layout is a single
/// `T`, so no size arithmetic can overflow.
///
/// On failure the value is returned rather than dropped here. A value such as a
/// `BIGNUM` owns a limb vector that may contain secret material, and dropping it
/// normally would free that block uncleansed; the caller must cleanse the value
/// before releasing it.
#[track_caller]
pub(crate) fn try_boxed<T>(value: T) -> Result<*mut T, T> {
    #[cfg(test)]
    if test_fail::should_fail(core::panic::Location::caller()) {
        return Err(value);
    }
    let layout = core::alloc::Layout::new::<T>();
    // SAFETY: `layout` has non-zero size (`T` is a struct, never a ZST here) and
    // is correctly aligned, which are `alloc`'s preconditions. A null result is
    // reported as the refused value instead of aborting.
    let p = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if p.is_null() {
        return Err(value);
    }
    // SAFETY: `p` is a fresh, sufficiently large, correctly aligned allocation for
    // one `T`, and `value` has not been moved or dropped.
    unsafe { p.write(value) };
    Ok(p)
}

/// Test-only allocation-failure seam.
///
/// Three modes, all thread-local:
///
/// * a **budget** ([`fail_after`]) fails the allocation that follows `n`
///   successful ones — cheap, for short paths;
/// * a **site sweep** ([`sweep_sites`]) records every distinct allocation site a
///   path reaches and then fails each site in turn. This is what makes a sweep of
///   ECDSA signing tractable: the scalar ladder has tens of thousands of
///   allocation *occurrences* but only a few dozen distinct source sites;
/// * a **counter** ([`count_start`]/[`counted`]) for the T29 measurement.
///
/// The seam intercepts only the helpers above. A request made by an infallible
/// `Vec` operation never consults it, so a clean sweep says nothing about a site
/// that does not appear here.
#[cfg(test)]
pub(crate) mod test_fail {
    use core::cell::{Cell, RefCell};
    use core::panic::Location;

    thread_local! {
        /// Successful allocations still allowed on this thread, or `None` when
        /// the budget is not armed. `Some(0)` fails the next allocation.
        static BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
        /// The one allocation site that must fail, when a site sweep is armed.
        static TARGET: Cell<Option<&'static Location<'static>>> = const { Cell::new(None) };
        /// Whether the armed site was actually reached in the last run.
        static HIT: Cell<bool> = const { Cell::new(false) };
        /// Distinct sites seen by the recording run, or `None` when not recording.
        static RECORD: RefCell<Option<Vec<&'static Location<'static>>>> = const { RefCell::new(None) };
        /// Allocation occurrences seen while the counter is armed.
        static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
        /// Per-site occurrence counts while a census is armed.
        static TALLY: RefCell<Option<Vec<(&'static Location<'static>, usize)>>> =
            const { RefCell::new(None) };
    }

    /// Fail the allocation that follows `successes` successful ones.
    pub(crate) fn fail_after(successes: usize) -> Guard {
        BUDGET.with(|b| b.set(Some(successes)));
        Guard
    }

    /// Disarms the budget when the test leaves scope, including on a panic.
    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            BUDGET.with(|b| b.set(None));
        }
    }

    /// Record every distinct allocation site `op` reaches, then fail each one in
    /// turn and require `op` to report an error.
    ///
    /// Returns the number of distinct sites. The operation must succeed once the
    /// seam is disarmed; that final success is asserted here.
    pub(crate) fn sweep_sites(mut op: impl FnMut() -> bool) -> usize {
        let sites = record_sites(&mut op);
        assert!(!sites.is_empty(), "the path must reach the seam");
        for site in &sites {
            let guard = fail_at_site(site);
            let ok = op();
            let hit = TARGET.with(|t| t.get()).is_some() && HIT.with(|h| h.get());
            drop(guard);
            // A stateful site (a cache or pool that the recording run already grew)
            // may not be reached again from this state. That is not a swallowed
            // failure: when it *is* reached, it must be reported.
            if hit {
                assert!(
                    !ok,
                    "allocation failure at {site} must be reported, not abort"
                );
            }
        }
        assert!(op(), "the operation must succeed once the seam is disarmed");
        sites.len()
    }

    /// Distinct allocation sites reached by one successful `op` run.
    fn record_sites(op: &mut impl FnMut() -> bool) -> Vec<&'static Location<'static>> {
        RECORD.with(|r| *r.borrow_mut() = Some(Vec::new()));
        let _guard = RecordGuard;
        let ok = op();
        let sites = RECORD.with(|r| r.borrow_mut().take().unwrap_or_default());
        assert!(ok, "the recording run must succeed");
        sites
    }

    struct RecordGuard;

    impl Drop for RecordGuard {
        fn drop(&mut self) {
            RECORD.with(|r| *r.borrow_mut() = None);
        }
    }

    /// Fail exactly the allocations reported at `site` until the guard drops.
    pub(crate) fn fail_at_site(site: &'static Location<'static>) -> SiteGuard {
        TARGET.with(|t| t.set(Some(site)));
        HIT.with(|h| h.set(false));
        SiteGuard
    }

    /// Disarms the site target when the test leaves scope.
    pub(crate) struct SiteGuard;

    impl Drop for SiteGuard {
        fn drop(&mut self) {
            TARGET.with(|t| t.set(None));
        }
    }

    /// Count every allocation the seam sees on this thread until the guard drops.
    pub(crate) fn count_start() -> CountGuard {
        COUNT.with(|c| c.set(Some(0)));
        CountGuard
    }

    /// The number of seam-visible allocations since [`count_start`].
    pub(crate) fn counted() -> usize {
        COUNT.with(|c| c.get().unwrap_or(0))
    }

    /// Disarms the counter when the test leaves scope.
    pub(crate) struct CountGuard;

    impl Drop for CountGuard {
        fn drop(&mut self) {
            COUNT.with(|c| c.set(None));
        }
    }

    /// Count every seam-visible allocation **per source site** until the guard drops.
    ///
    /// This answers the question a total cannot: which site to attack. The T29
    /// census uses it to order one P-256 signature's allocations by count instead of
    /// guessing from the code shape.
    pub(crate) fn tally_start() -> TallyGuard {
        TALLY.with(|t| *t.borrow_mut() = Some(Vec::new()));
        TallyGuard
    }

    /// The per-site counts collected since [`tally_start`], most frequent first.
    /// Taking them disarms the census.
    pub(crate) fn tally_take() -> Vec<(&'static Location<'static>, usize)> {
        let mut sites = TALLY.with(|t| t.borrow_mut().take().unwrap_or_default());
        sites.sort_by_key(|a| core::cmp::Reverse(a.1));
        sites
    }

    /// Disarms the census when the test leaves scope, including on a panic.
    pub(crate) struct TallyGuard;

    impl Drop for TallyGuard {
        fn drop(&mut self) {
            TALLY.with(|t| *t.borrow_mut() = None);
        }
    }

    /// Consume one allocation from the armed mode; true when this one must fail.
    pub(crate) fn should_fail(site: &'static Location<'static>) -> bool {
        COUNT.with(|c| {
            if let Some(n) = c.get() {
                c.set(Some(n + 1));
            }
        });
        TALLY.with(|t| {
            if let Some(sites) = t.borrow_mut().as_mut() {
                match sites.iter_mut().find(|(s, _)| *s == site) {
                    Some((_, n)) => *n += 1,
                    None => sites.push((site, 1)),
                }
            }
        });
        RECORD.with(|r| {
            if let Some(sites) = r.borrow_mut().as_mut() {
                if !sites.contains(&site) {
                    sites.push(site);
                }
            }
        });
        if TARGET.with(|t| t.get()) == Some(site) {
            HIT.with(|h| h.set(true));
            return true;
        }
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
