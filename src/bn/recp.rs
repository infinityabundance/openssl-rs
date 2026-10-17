//! Phase 5 — `BN_RECP_CTX` and the reciprocal division built on it.
//!
//! `BN_RECP_CTX` is opaque to a consumer (`types.h` forward-declares it and
//! `crypto/bn/bn_local.h` holds the definition), so the representation is ours.
//!
//! ## What the reciprocal is, and what it is not
//!
//! The reciprocal is a *speed* device: `BN_div_recp` converges on the same truncated
//! quotient and remainder that `BN_div` computes, which is why its correction loop
//! exists and why it reports `BN_R_BAD_RECIPROCAL` when it does not converge in two
//! steps. Its **sign rules** are stated at the end of the authority's function and are
//! the ones reproduced here: the remainder takes the dividend's sign, and the quotient
//! takes `dividend.neg ^ divisor.neg`.
//!
//! One consequence is worth stating because it is easy to get wrong by "improving"
//! it: `BN_mod_mul_reciprocal` is **not** `BN_nnmod` of the product. It is a
//! truncated-division remainder, so a negative product yields a negative result.
//!
//! ## The zero modulus
//!
//! `BN_RECP_CTX_set` refuses a zero modulus without raising. `BN_div_recp` on a
//! context that was never set therefore reaches `BN_div` with a zero divisor — and
//! reaches it through `BN_reciprocal`, so the raise is `BN_div`'s own coordinate,
//! not a new one.
//!
//! ## Ownership classification and representation decision
//!
//! On the admitted `x86_64-unknown-linux-gnu` target the authority's
//! `struct bn_recp_ctx_st` is **64 bytes / 8-align**: two `BIGNUM` members
//! (24 bytes each) plus three `int`s. The Rust [`RecpCtx`] is also 64 / 8 on
//! this target, so the context block uses **option B** of
//! `OPAQUE-REPRESENTATIONS.md`: `BN_RECP_CTX_new` asks the `CRYPTO_*` seam for
//! the authority's 64 bytes and writes the Rust state inline, and
//! `BN_RECP_CTX_free` drops that state and releases the same block through the
//! seam. A caller-installed `CRYPTO_set_mem_functions` hook therefore observes
//! one allocation of exactly `sizeof(BN_RECP_CTX)` and its single release, at
//! the authority's `crypto/bn/bn_recp.c` coordinates.
//!
//! Two limits remain explicit rather than hidden:
//!
//! * the `n`/`nr` limb `Vec`s are still Rust-owned, so the hook does not observe
//!   their storage. Only the context block's event has authority-size parity;
//!   this is **not** a total-memory-parity or `SAFETY_DISCHARGED` claim.
//! * the layout constants are target-gated and compile-time checked. On a target
//!   whose authority layout has not been measured, the module keeps option A (a
//!   Rust `Box`) rather than guessing. The former `Box` statement that
//!   `size_of::<RecpCtx>()` differed from the C size was not measured and is
//!   corrected by the 64-byte equality above.

use core::ffi::c_int;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use core::ffi::c_void;

use crate::bn::arith::{mod_exp_core, BN_div};
use crate::bn::bignum::{as_mut, as_ref, new_owned, parts, store, BN_free, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BN_DIV_217, BN_EXP_183};
use crate::runtime::err::raise_site;

/// `BN_FLG_CONSTTIME`, as the authority's `bn.h` defines it.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// The authority's `sizeof(struct bn_recp_ctx_st)` on the measured target:
/// two `BIGNUM` (8-byte pointer + four `int` = 24 bytes, align 8) plus three
/// `int` = 64 bytes, align 8. Checked against the Rust type at compile time
/// below; a target this has not been measured for falls back to option A.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const AUTHORITY_BN_RECP_CTX_SIZE: usize = 64;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const AUTHORITY_BN_RECP_CTX_ALIGN: usize = 8;

// The 64-byte derivation `2 * (8 + 4 * 4) + 3 * 4` assumes an 8-byte pointer
// and a 4-byte C `int`; both are checked here rather than trusted.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const _: () = assert!(core::mem::size_of::<usize>() == 8);
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const _: () = assert!(core::mem::size_of::<c_int>() == 4);

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const _: () = assert!(
    core::mem::size_of::<RecpCtx>() <= AUTHORITY_BN_RECP_CTX_SIZE,
    "RecpCtx no longer fits the authority-sized BN_RECP_CTX block"
);
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const _: () = assert!(
    core::mem::align_of::<RecpCtx>() <= AUTHORITY_BN_RECP_CTX_ALIGN,
    "RecpCtx alignment exceeds what the C allocator guarantees"
);

/// The authority's allocation coordinate (`OPENSSL_zalloc(sizeof(*ret))`).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const FILE: &core::ffi::CStr = c"crypto/bn/bn_recp.c";
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const LINE_ALLOC: c_int = 24;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const LINE_FREE: c_int = 40;

/// The authority's `BN_RECP_CTX`.
pub struct RecpCtx {
    /// `N` — the divisor, held as a magnitude.
    n: Vec<Limb>,
    /// `N`'s sign, which `BN_div_recp` folds into the quotient's sign rule.
    neg: bool,
    /// `Nr` — the reciprocal, recomputed when `shift` changes.
    nr: Vec<Limb>,
    /// `num_bits` — `BN_num_bits(N)` as it stood when the context was set.
    num_bits: c_int,
    /// `shift` — the `len` the cached reciprocal was computed for, or a negative
    /// sentinel when `BN_reciprocal` failed.
    shift: c_int,
}

/// Read a `*mut RecpCtx` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `RecpCtx`.
unsafe fn as_mut_recp<'a>(p: *mut RecpCtx) -> Option<&'a mut RecpCtx> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// The authority's `BN_RECP_CTX_init`: an empty divisor, reciprocal and signs.
fn recp_init() -> RecpCtx {
    RecpCtx {
        n: Vec::new(),
        neg: false,
        nr: Vec::new(),
        num_bits: 0,
        shift: 0,
    }
}

/// Option B: one `CRYPTO_zalloc` block of the authority's exact size, with the
/// Rust state written into it. The compile-time asserts above establish both
/// the extent and the alignment obligation.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn alloc_recp() -> *mut RecpCtx {
    let block =
        CRYPTO_zalloc(AUTHORITY_BN_RECP_CTX_SIZE, FILE.as_ptr(), LINE_ALLOC).cast::<RecpCtx>();
    if block.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `CRYPTO_zalloc` returned a fresh, exclusively-owned, writable block
    // of `AUTHORITY_BN_RECP_CTX_SIZE` bytes. The compile-time asserts prove that
    // is at least `size_of::<RecpCtx>()`; the C allocator contract guarantees an
    // alignment at least as strict as `AUTHORITY_BN_RECP_CTX_ALIGN`. No other
    // reference to the block exists, so one `write` initialises the whole value.
    unsafe { block.write(recp_init()) };
    block
}

/// Option A, retained for targets whose authority layout has not been measured.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn alloc_recp() -> *mut RecpCtx {
    Box::into_raw(Box::new(recp_init()))
}

/// Releases the C block after the Rust state has been dropped. The guard makes
/// the block release happen exactly once even if a destructor ever unwinds.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
struct BlockRelease(*mut RecpCtx);

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl Drop for BlockRelease {
    fn drop(&mut self) {
        // SAFETY: the block came from `CRYPTO_zalloc` at `FILE`/`LINE_ALLOC` in
        // `alloc_recp`, and this guard is its single release at the authority's
        // freeing coordinate.
        unsafe { CRYPTO_free(self.0.cast::<c_void>(), FILE.as_ptr(), LINE_FREE) };
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
unsafe fn free_recp(p: *mut RecpCtx) {
    let _release = BlockRelease(p);
    // SAFETY: `p` is a live, initialized `RecpCtx` from `alloc_recp`, exclusively
    // owned by the caller, and this is its single destructor.
    unsafe { core::ptr::drop_in_place(p) };
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
unsafe fn free_recp(p: *mut RecpCtx) {
    // SAFETY: `p` came from `Box::into_raw` in `alloc_recp` and is not freed
    // elsewhere.
    unsafe { drop(Box::from_raw(p)) };
}

/// `BN_RECP_CTX *BN_RECP_CTX_new(void)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_RECP_CTX_new() -> *mut RecpCtx {
    guard_ffi(core::ptr::null_mut(), alloc_recp)
}

/// `void BN_RECP_CTX_free(BN_RECP_CTX *recp)`
///
/// A null pointer is a no-op.
///
/// # Safety
///
/// `recp` must be null or a pointer returned by `BN_RECP_CTX_new`, and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn BN_RECP_CTX_free(recp: *mut RecpCtx) {
    guard_ffi((), || {
        if !recp.is_null() {
            // SAFETY: the caller's contract is exactly that `recp` came from
            // `BN_RECP_CTX_new` and has not been freed.
            unsafe { free_recp(recp) };
        }
    });
}

/// `int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)`
///
/// A zero divisor is refused without raising; everything else is accepted, including
/// a negative one, whose sign is carried into the quotient by `BN_div_recp`.
///
/// # Safety
///
/// `recp` must be null or a live, uniquely-owned `BN_RECP_CTX`; `d` must be null or
/// live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_RECP_CTX_set(
    recp: *mut RecpCtx,
    d: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut_recp(recp), as_ref(d)) };
        let (dd, dn) = parts(x);
        let Some(dst) = dst else {
            return 0;
        };
        if dd.is_empty() {
            return 0;
        }
        dst.n = dd;
        dst.neg = dn;
        dst.nr = Vec::new();
        dst.num_bits = limbs::bit_len(&dst.n) as c_int;
        dst.shift = 0;
        1
    })
}

/// `BN_RECP_CTX` with the sign of `N`, as the authority's `BN_div_recp` sees it: the
/// magnitude drives the arithmetic and the sign reaches the quotient's sign rule.
fn divisor_as_bignum(recp: &RecpCtx, neg: bool) -> *mut BigNum {
    new_owned(recp.n.clone(), c_int::from(neg))
}

/// `int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, BN_RECP_CTX *recp,`
/// `BN_CTX *ctx)`
///
/// # Safety
///
/// `dv` and `rem` must each be null or a live, uniquely-owned `BIGNUM`; `m` must be
/// null or live; `recp` must be null or a live `BN_RECP_CTX`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_div_recp(
    dv: *mut BigNum,
    rem: *mut BigNum,
    m: *const BigNum,
    recp: *mut RecpCtx,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let mc = unsafe { as_mut_recp(recp) };
        let Some(mc) = mc else {
            return 0;
        };
        let neg = mc.neg;
        if mc.n.is_empty() {
            // The authority reaches `BN_div` with a zero divisor through
            // `BN_reciprocal`, so the raise is `BN_div`'s.
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_DIV_217) };
            return 0;
        }
        let divisor = divisor_as_bignum(mc, neg);
        // SAFETY: `divisor` is live and uniquely owned here; `BN_div`'s contract on
        // the remaining arguments is this function's contract.
        let out = unsafe { BN_div(dv, rem, m, divisor, ctx) };
        // SAFETY: `divisor` is the object this call allocated.
        unsafe { BN_free(divisor) };
        out
    })
}

/// `int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)` — `2^len / m`
/// truncated, answering `len` on success and `-1` on failure.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `m` must be null or live;
/// `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_reciprocal(
    r: *mut BigNum,
    m: *const BigNum,
    len: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(-1, || {
        // `BN_set_bit` refuses a negative index, and the authority's failure to set
        // the bit leaves the -1 it returns rather than raising anything.
        if len < 0 {
            return -1;
        }
        let num = new_owned(limbs::shl(&[1u64], len as usize), 0);
        // SAFETY: `num` is live and uniquely owned here; `BN_div`'s contract on the
        // remaining arguments is this function's contract.
        let ok = unsafe { BN_div(r, core::ptr::null_mut(), num, m, ctx) };
        // SAFETY: `num` is the object this call allocated.
        unsafe { BN_free(num) };
        if ok == 0 {
            -1
        } else {
            len
        }
    })
}

/// `int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,`
/// `BN_RECP_CTX *recp, BN_CTX *ctx)`
///
/// A null `y` means "reduce `x` and nothing else", which is how the authority spells
/// a plain modular reduction with this context.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `x` and `y` must each be null
/// or live; `recp` must be null or a live `BN_RECP_CTX`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_mul_reciprocal(
    r: *mut BigNum,
    x: *const BigNum,
    y: *const BigNum,
    recp: *mut RecpCtx,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        if y.is_null() {
            // SAFETY: `BN_div_recp`'s contract is this function's contract.
            return unsafe { BN_div_recp(core::ptr::null_mut(), r, x, recp, ctx) };
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (xx, yy) = unsafe { (as_ref(x), as_ref(y)) };
        let (xd, xn) = parts(xx);
        let (yd, yn) = parts(yy);
        let product = limbs::mul(&xd, &yd);
        let neg = xn != yn;
        let num = new_owned(product, c_int::from(neg));
        // SAFETY: `num` is live and uniquely owned here; `BN_div_recp`'s contract on
        // the remaining arguments is this function's contract.
        let out = unsafe { BN_div_recp(core::ptr::null_mut(), r, num, recp, ctx) };
        // SAFETY: `num` is the object this call allocated.
        unsafe { BN_free(num) };
        out
    })
}

/// `int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx)`
///
/// This is the path `BN_mod_exp` takes for an even modulus. A constant-time exponent,
/// base or modulus is refused, because only `BN_mod_exp_mont` has a constant-time
/// ladder.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `p` and `m` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_recp(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y, z) = unsafe { (as_mut(r), as_ref(a), as_ref(p), as_ref(m)) };
        let (ad, _) = parts(x);
        let (pd, _) = parts(y);
        let (md, _) = parts(z);
        // SAFETY: the null checks are `BN_get_flags`'s own contract, and the site is
        // a compile-time constant.
        unsafe {
            if gets_consttime(p) || gets_consttime(a) || gets_consttime(m) {
                raise_site(&BN_EXP_183);
                return 0;
            }
        }
        // The zero-exponent rule is checked before the modulus is looked at, which is
        // why `0^0 mod 0` answers one here rather than failing.
        if limbs::bit_len(&pd) == 0 {
            let zero = md.len() == 1 && md[0] == 1;
            return c_int::from(store(dst, if zero { Vec::new() } else { vec![1] }, false));
        }
        match mod_exp_core(&ad, &pd, &md) {
            Some(v) => c_int::from(store(dst, v, false)),
            None => 0,
        }
    })
}

/// `int BN_get_flags(const BIGNUM *b, int n)` read for `BN_FLG_CONSTTIME`.
///
/// # Safety
///
/// `b` must be null or a live `BIGNUM`.
unsafe fn gets_consttime(b: *const BigNum) -> bool {
    // SAFETY: the caller guarantees `b` is null or live, which is `BN_get_flags`'s
    // own contract.
    unsafe { crate::bn::bignum::BN_get_flags(b, BN_FLG_CONSTTIME) != 0 }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_set_mem_functions;
    use core::ffi::{c_char, c_int, c_void};
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    extern "C" {
        fn malloc(n: usize) -> *mut c_void;
        fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
        fn free(p: *mut c_void);
    }

    static MALLOCS: AtomicUsize = AtomicUsize::new(0);
    static MALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static MALLOC_FILE: AtomicUsize = AtomicUsize::new(0);
    static MALLOC_LINE: AtomicI32 = AtomicI32::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static FREED_PTR: AtomicUsize = AtomicUsize::new(0);
    static FREE_FILE: AtomicUsize = AtomicUsize::new(0);
    static FREE_LINE: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn hook_malloc(n: usize, file: *const c_char, line: c_int) -> *mut c_void {
        MALLOCS.fetch_add(1, Ordering::SeqCst);
        MALLOC_SIZE.store(n, Ordering::SeqCst);
        MALLOC_FILE.store(file as usize, Ordering::SeqCst);
        MALLOC_LINE.store(line, Ordering::SeqCst);
        // SAFETY: `malloc` has no preconditions.
        unsafe { malloc(n) }
    }

    unsafe extern "C" fn hook_realloc(
        p: *mut c_void,
        n: usize,
        _file: *const c_char,
        _line: c_int,
    ) -> *mut c_void {
        // SAFETY: `p` is NULL or a block from `hook_malloc`.
        unsafe { realloc(p, n) }
    }

    unsafe extern "C" fn hook_free(p: *mut c_void, file: *const c_char, line: c_int) {
        FREES.fetch_add(1, Ordering::SeqCst);
        FREED_PTR.store(p as usize, Ordering::SeqCst);
        FREE_FILE.store(file as usize, Ordering::SeqCst);
        FREE_LINE.store(line, Ordering::SeqCst);
        // SAFETY: `p` is NULL or a block from `hook_malloc`.
        unsafe { free(p) }
    }

    const CHILD_ENV: &str = "OPENSSL_RS_RECP_HOOK_CHILD";

    /// The allocator seam latches shut after a process's first `CRYPTO_*`
    /// allocation, so the observation is made in a fresh process in which this is
    /// the only test that runs. That is what makes it deterministic: no other test
    /// can allocate first or race the counters.
    #[test]
    fn hook_observes_authority_size_and_single_release() {
        if std::env::var_os(CHILD_ENV).is_some() {
            run_probe();
            return;
        }

        let exe = std::env::current_exe().unwrap_or_default();
        assert!(!exe.as_os_str().is_empty(), "the test binary has no path");
        let ran_and_passed = std::process::Command::new(exe)
            .args([
                "--exact",
                "bn::recp::tests::hook_observes_authority_size_and_single_release",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(ran_and_passed, "the isolated hook probe failed");
    }

    fn run_probe() {
        // SAFETY: the hooks forward to libc and stay valid for the process; this
        // process runs exactly this test, so the seam has not latched shut.
        let installed = unsafe {
            CRYPTO_set_mem_functions(Some(hook_malloc), Some(hook_realloc), Some(hook_free))
        };
        assert_eq!(installed, 1, "the allocator seam refused installation");

        // SAFETY: `BN_RECP_CTX_new` takes no pointers.
        let recp = unsafe { BN_RECP_CTX_new() };
        assert!(!recp.is_null(), "BN_RECP_CTX_new returned NULL");

        assert_eq!(MALLOCS.load(Ordering::SeqCst), 1, "one block allocation");
        assert_eq!(
            MALLOC_SIZE.load(Ordering::SeqCst),
            AUTHORITY_BN_RECP_CTX_SIZE,
            "the hook must observe the authority's sizeof(BN_RECP_CTX)"
        );
        assert_eq!(
            MALLOC_FILE.load(Ordering::SeqCst),
            FILE.as_ptr() as usize,
            "the allocation reports the authority's file"
        );
        assert_eq!(MALLOC_LINE.load(Ordering::SeqCst), LINE_ALLOC);

        // SAFETY: `recp` is live and this is its single release.
        unsafe { BN_RECP_CTX_free(recp) };

        assert_eq!(FREES.load(Ordering::SeqCst), 1, "exactly one release");
        assert_eq!(FREED_PTR.load(Ordering::SeqCst), recp as usize);
        assert_eq!(FREE_FILE.load(Ordering::SeqCst), FILE.as_ptr() as usize);
        assert_eq!(FREE_LINE.load(Ordering::SeqCst), LINE_FREE);
        assert_eq!(MALLOCS.load(Ordering::SeqCst), 1, "no second allocation");
    }
}
