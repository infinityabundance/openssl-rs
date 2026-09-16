//! `crypto/uid.c` and `crypto/cryptlib.c`'s `OPENSSL_isservice` — the two
//! privilege-query exports.
//!
//! ## Why these are two one-line functions in their own module
//!
//! Both are **platform predicates**, not utilities: each answers a question whose
//! answer is decided entirely by which `#if` arm the platform selects, and the
//! admitted profile selects one arm out of five. Writing them out with the arm
//! named is the only way a reader can check that the right arm was taken, and a
//! single wrong arm is a silent security difference rather than a crash.
//!
//! ## `OPENSSL_issetugid`
//!
//! `uid.c` has five arms. The admitted profile (glibc, x86-64 Linux) takes the
//! last one — *not* the OpenBSD/FreeBSD `issetugid()` arm — and inside it the
//! glibc branch, because glibc provides `getauxval` and
//! `__GLIBC_PREREQ(2, 16)` holds:
//!
//! ```c
//! int OPENSSL_issetugid(void)
//! {
//!     return getauxval(AT_SECURE) != 0;
//! }
//! ```
//!
//! The `getuid() != geteuid()` fallback in the same `#else` is what runs on a
//! libc without `getauxval`; it is **not** transcribed, because a literal written
//! from the source would be an unmeasured claim about a libc this crate has not
//! observed. On this profile the two happen to agree for a setuid binary but not
//! for a program that was merely given a group it did not ask for, and that
//! difference is exactly why the arm matters.
//!
//! The value is not cosmetic. `ossl_safe_getenv` (see `runtime::getenv`) is the
//! *other* half of the same question: `secure_getenv` uses `AT_SECURE` internally,
//! and `OPENSSL_issetugid` is the public way to ask the same thing.
//!
//! ## `OPENSSL_isservice`
//!
//! Every non-Windows arm of `cryptlib.c`'s definition is the same:
//!
//! ```c
//! int OPENSSL_isservice(void) { return 0; }
//! ```
//!
//! The interesting arms are the Win32 ones, which ask whether the process is
//! attached to `WinSta0`. The admitted profile compiles the last arm, so the
//! answer is unconditionally `0` and there is nothing to approximate.

use core::ffi::{c_int, c_ulong};

/// `AT_SECURE`, from `<elf.h>` / `<sys/auxv.h>` on Linux.
const AT_SECURE: c_ulong = 23;

unsafe extern "C" {
    /// `unsigned long getauxval(unsigned long type)`, from `<sys/auxv.h>`.
    fn getauxval(type_: c_ulong) -> c_ulong;
}

/// `int OPENSSL_issetugid(void)`
///
/// Non-zero when the process is running with elevated privilege — a setuid or
/// setgid binary, or one whose capabilities were raised at exec — as reported by
/// the kernel through the auxiliary vector. `0` otherwise. Never fails: an
/// `AT_SECURE` entry that is absent reads as `0`, which is the same answer
/// `getauxval` gives on success for a normal process.
#[no_mangle]
pub extern "C" fn OPENSSL_issetugid() -> c_int {
    // SAFETY: `getauxval` takes an integer and cannot fail in a way that matters
    // here; it sets `errno` to ENOENT and returns 0 for an absent entry, which is
    // the value `AT_SECURE` has for every ordinary process.
    (unsafe { getauxval(AT_SECURE) } != 0) as c_int
}

/// `int OPENSSL_isservice(void)`
///
/// Unconditionally `0` on this profile: the function exists to distinguish a
/// Windows service from an interactive process, and none of the Win32 arms is
/// compiled. Kept as a real function rather than elided because a caller can and
/// does call it.
#[no_mangle]
pub extern "C" fn OPENSSL_isservice() -> c_int {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_test_process_is_not_privileged() {
        // `cargo test` runs as an ordinary process, so `AT_SECURE` is zero. If
        // this ever fails, the test suite is running setuid and every other
        // environment-dependent expectation in the crate becomes suspect.
        assert_eq!(OPENSSL_issetugid(), 0);
        assert_eq!(OPENSSL_isservice(), 0);
    }
}
