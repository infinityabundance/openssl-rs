//! Phase 5 — the `BIGNUM` object: lifetime, predicates, flags and conversions.
//!
//! `BIGNUM` is opaque to callers of the authority (`include/openssl/bn.h` declares
//! `typedef struct bignum_st BIGNUM;` and defines nothing), so the representation
//! here is ours: sign-magnitude, the magnitude a normalised little-endian limb
//! vector (`limbs.rs`). Two fields survive from the authority's struct because they
//! are **observable through the API** rather than private layout:
//!
//! * `neg` — `BN_is_negative`, `BN_set_negative`, the sign `BN_div` gives its
//!   remainder, and the byte order `BN_bn2mpi` writes all read it.
//! * `flags` — `BN_get_flags` exists so a caller can inspect them, and
//!   `BN_FLG_CONSTTIME` changes what several operations promise.
//!
//! ## The discipline this module follows
//!
//! Every entry point takes raw pointers and dereferences them, so every entry
//! point is `unsafe` with a `# Safety` section, and each one reads those pointers
//! in **exactly one** `unsafe` block whose comment states the invariant. After that
//! block the body works with `Option<&BigNum>` / `Option<&mut BigNum>` and owned
//! vectors, so there is no second place where a pointer could be misused.
//!
//! ## Allocation, and a recorded narrowing
//!
//! Strings returned by `BN_bn2hex` and `BN_bn2dec` are allocated through
//! `CRYPTO_malloc`, because that is the authority's contract: `OPENSSL_free` is a
//! *macro* over `CRYPTO_free(ptr, file, line)` in this profile — neither
//! `OPENSSL_free` nor `OPENSSL_malloc` is an exported symbol, which was checked
//! rather than assumed — so a caller frees the string through the same allocator
//! hooks a program can install with `CRYPTO_set_mem_functions`.
//!
//! The `BIGNUM` object and its limb vector are allocated through Rust's allocator,
//! so a program that installs those hooks does **not** see them, and an allocation
//! failure aborts rather than returning `NULL`. That difference is real, it is
//! recorded as `OBL-BN-ALLOCATOR` in `forensics/phase5-obligations.json`, and it is
//! *not* claimed as parity.

use core::ffi::{c_char, c_int, c_ulong};

use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;

/// The allocating site reported to `CRYPTO_malloc`.
const FILE: &core::ffi::CStr = c"crypto/bn/bn_lib.c";
/// The authority passes `__LINE__`; the line is inert in this profile because
/// `OPENSSL_NO_CRYPTO_MDEBUG` is defined, but it still has to be a number.
const LINE: c_int = 0;

/// `BN_FLG_MALLOCED` — set on a `BIGNUM` this library allocated.
pub(crate) const BN_FLG_MALLOCED: c_int = 0x01;

/// The authority's `BIGNUM`.
#[repr(C)]
pub struct BigNum {
    /// Little-endian magnitude with no trailing zero limbs.
    pub(crate) d: Vec<Limb>,
    /// Non-zero when the value is negative. Never set on zero.
    pub(crate) neg: c_int,
    /// The `BN_FLG_*` bits `BN_get_flags` reports.
    pub(crate) flags: c_int,
}

/// Read a `*const BigNum` as a reference.
///
/// # Safety
///
/// `p` must be null or point to a live `BigNum` that is not mutated for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn as_ref<'a>(p: *const BigNum) -> Option<&'a BigNum> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // unmutated.
        Some(unsafe { &*p })
    }
}

/// Read a `*mut BigNum` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `BigNum`.
pub(crate) unsafe fn as_mut<'a>(p: *mut BigNum) -> Option<&'a mut BigNum> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// A fresh heap `BIGNUM`, with the magnitude normalised and `neg` cleared on zero.
pub(crate) fn new_owned(mut d: Vec<Limb>, neg: c_int) -> *mut BigNum {
    limbs::normalise(&mut d);
    let zero = d.is_empty();
    Box::into_raw(Box::new(BigNum {
        d,
        // The authority never leaves `neg` set on zero, and neither may we:
        // `BN_is_negative(BN_new())` is 0, and a negative zero would print a sign
        // no authority path prints.
        neg: if zero { 0 } else { neg },
        flags: BN_FLG_MALLOCED,
    }))
}

/// The magnitude and sign of an optional object; `(empty, false)` for null.
pub(crate) fn parts(b: Option<&BigNum>) -> (Vec<Limb>, bool) {
    match b {
        Some(b) => (b.d.clone(), b.neg != 0),
        None => (Vec::new(), false),
    }
}

/// Store a magnitude and sign into an optional destination.
///
/// Answers `false` only for a null destination, which is how the entry points
/// report "no `r` to write to".
pub(crate) fn store(r: Option<&mut BigNum>, mut d: Vec<Limb>, neg: bool) -> bool {
    limbs::normalise(&mut d);
    match r {
        None => false,
        Some(dst) => {
            let zero = d.is_empty();
            dst.d = d;
            dst.neg = if zero { 0 } else { c_int::from(neg) };
            true
        }
    }
}

/// Copy `s` into memory the caller can release with `OPENSSL_free`.
pub(crate) fn dup_cstring(s: &str) -> *mut c_char {
    let bytes = s.as_bytes();
    let n = bytes.len() + 1;
    let p = crate::runtime::mem::CRYPTO_malloc(n, FILE.as_ptr(), LINE);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `p` came from `CRYPTO_malloc(n, ..)`, so it owns at least `n`
    // writable bytes and `bytes.len() + 1 == n`.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), p.cast::<u8>(), bytes.len());
        *p.cast::<u8>().add(bytes.len()) = 0;
    }
    p.cast()
}

/// Read a NUL-terminated string, replacing invalid UTF-8 rather than failing.
///
/// # Safety
///
/// `p` must be null or point to a NUL-terminated string that stays valid for the
/// call.
pub(crate) unsafe fn from_cstr_lossy(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `p` is NUL-terminated and readable for the
    // length of the string.
    Some(
        unsafe { core::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Hex of the magnitude, with a leading `-` when negative and no leading zero
/// *bytes*; `"0"` for zero. `BN_bn2hex`'s format.
///
/// The authority writes its limbs out byte by byte, so it suppresses leading zero
/// bytes but emits both digits of every byte it keeps: `2` is `"02"` and
/// `0x30000000000000000` is `"030000000000000000"`. A nibble-oriented encoder —
/// the obvious way to write this — drops the leading zero and is a divergence the
/// `RT-BN` court detects on almost every other line.
fn hex_of(b: &BigNum, upper: bool) -> String {
    const UPPER: [u8; 16] = *b"0123456789ABCDEF";
    const LOWER: [u8; 16] = *b"0123456789abcdef";
    let digits = if upper { &UPPER } else { &LOWER };

    let mut out: Vec<u8> = Vec::with_capacity(b.d.len() * 16 + 1);
    if b.neg != 0 {
        out.push(b'-');
    }
    let mut started = false;
    // Limbs high to low, and within a limb the high byte first: the authority's
    // nesting order, which is what the `z` flag advances through.
    for limb in b.d.iter().rev() {
        for shift in (0..8).rev() {
            let byte = ((limb >> (shift * 8)) & 0xff) as u8;
            if !started && byte == 0 {
                continue;
            }
            started = true;
            out.push(digits[(byte >> 4) as usize]);
            out.push(digits[(byte & 0x0f) as usize]);
        }
    }
    if !started {
        out.push(b'0');
    }
    // Every byte pushed is an ASCII hex digit or `-`, so this cannot fail; the
    // fallback keeps the function total rather than unwrapping.
    String::from_utf8(out).unwrap_or_default()
}

/// Decimal digits of the magnitude, by repeated division by `10^19` (the largest
/// power of ten that fits in a limb, so the largest chunk one division can yield).
fn dec_of(b: &BigNum) -> String {
    const CHUNK: u64 = 10_000_000_000_000_000_000;
    let mut s = String::new();
    if b.neg != 0 {
        s.push('-');
    }
    let mut work = b.d.clone();
    let mut parts: Vec<u64> = Vec::new();
    while !work.is_empty() {
        let (q, r) = limbs::div_rem_small(&work, CHUNK);
        parts.push(r);
        work = q;
    }
    match parts.pop() {
        None => s.push('0'),
        Some(top) => {
            s.push_str(&top.to_string());
            for part in parts.iter().rev() {
                s.push_str(&format!("{part:019}"));
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

/// `BIGNUM *BN_new(void)`
///
/// # Safety
///
/// This entry point takes no pointers; it is `unsafe` only because the rest of the
/// `BN_*` surface it belongs to is, and libc-ABI consistency matters more than a
/// per-function exception.
#[no_mangle]
pub unsafe extern "C" fn BN_new() -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || new_owned(Vec::new(), 0))
}

/// `BIGNUM *BN_secure_new(void)`
///
/// # Safety
///
/// Takes no pointers; see `BN_new`.
#[no_mangle]
pub unsafe extern "C" fn BN_secure_new() -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || new_owned(Vec::new(), 0))
}

/// `void BN_free(BIGNUM *a)`
///
/// A null pointer is explicitly allowed and does nothing.
///
/// # Safety
///
/// `a` must be null or a `BIGNUM` this library allocated and has not freed.
#[no_mangle]
pub unsafe extern "C" fn BN_free(a: *mut BigNum) {
    guard_ffi((), || {
        if a.is_null() {
            return;
        }
        // SAFETY: by this function's `# Safety` section `a` came from
        // `Box::into_raw` in this module and is not yet freed, so reclaiming the
        // box is exactly what is owed; this is the only read of the pointer.
        drop(unsafe { Box::from_raw(a) });
    });
}

/// `void BN_clear_free(BIGNUM *a)`
///
/// The authority zeroises the limbs first. That is observable only to a program
/// reading freed memory — not a contract — but `BN_clear_free` exists to make the
/// promise, and a custodian does not quietly drop a security promise it can keep.
///
/// # Safety
///
/// As `BN_free`.
#[no_mangle]
pub unsafe extern "C" fn BN_clear_free(a: *mut BigNum) {
    guard_ffi((), || {
        if a.is_null() {
            return;
        }
        // SAFETY: as `BN_free` — `a` is a live box this module allocated.
        let mut b = unsafe { Box::from_raw(a) };
        for limb in b.d.iter_mut() {
            // SAFETY: `limb` is a valid, aligned, uniquely-owned `u64`, and
            // `write_volatile` is what stops the optimiser eliding the clear,
            // which is the entire point of this function.
            unsafe { core::ptr::write_volatile(limb, 0) };
        }
        drop(b);
    });
}

/// `void BN_clear(BIGNUM *a)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_clear(a: *mut BigNum) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section, and the only
        // read of the pointer.
        if let Some(b) = unsafe { as_mut(a) } {
            b.d.clear();
            b.neg = 0;
        }
    });
}

/// `void BN_zero_ex(BIGNUM *a)` — the function behind the `BN_zero` macro.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_zero_ex(a: *mut BigNum) {
    // SAFETY: `BN_clear`'s contract is this function's contract.
    unsafe { BN_clear(a) };
}

/// `const BIGNUM *BN_value_one(void)`
///
/// The authority returns a pointer to a process-wide constant. This returns a
/// fresh object, which differs in that a caller must not free the authority's and
/// must free this one. The difference is recorded as
/// `OBL-BN-VALUE-ONE-IDENTITY` rather than claimed as parity: making it a true
/// static would mean an object with no owner and no way to free it, which is a
/// worse contract than the one the authority is trying to express.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_value_one() -> *const BigNum {
    guard_ffi(core::ptr::null(), || new_owned(vec![1], 0))
}

/// `BIGNUM *BN_dup(const BIGNUM *a)`
///
/// Returns `NULL` for a null input, as the authority does.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_dup(a: *const BigNum) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section; the only
        // read of the pointer.
        match unsafe { as_ref(a) } {
            None => core::ptr::null_mut(),
            Some(b) => new_owned(b.d.clone(), b.neg),
        }
    })
}

/// `BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// `a` and `b` must each be null or live, and must not be the same object when
/// both are non-null.
#[no_mangle]
pub unsafe extern "C" fn BN_copy(a: *mut BigNum, b: *const BigNum) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `a` and `b` are null or live and distinct, which is this
        // function's `# Safety` section; the only read of either pointer.
        let (dst, src) = unsafe { (as_mut(a), as_ref(b)) };
        match (dst, src) {
            (Some(dst), Some(src)) => {
                dst.d.clear();
                dst.d.extend_from_slice(&src.d);
                dst.neg = src.neg;
                a
            }
            _ => core::ptr::null_mut(),
        }
    })
}

/// `void BN_swap(BIGNUM *a, BIGNUM *b)`
///
/// # Safety
///
/// `a` and `b` must each be null or live, and distinct when both are non-null.
#[no_mangle]
pub unsafe extern "C" fn BN_swap(a: *mut BigNum, b: *mut BigNum) {
    guard_ffi((), || {
        if a == b {
            return;
        }
        // SAFETY: two distinct, live, uniquely-owned objects, so the two mutable
        // borrows cannot alias; the only read of either pointer.
        let (x, y) = unsafe { (as_mut(a), as_mut(b)) };
        if let (Some(x), Some(y)) = (x, y) {
            // Flags travel with the object rather than the value: the authority
            // swaps only the limbs, the top and the sign.
            core::mem::swap(&mut x.d, &mut y.d);
            core::mem::swap(&mut x.neg, &mut y.neg);
        }
    });
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// `int BN_num_bits(const BIGNUM *a)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_num_bits(a: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => limbs::bit_len(&b.d) as c_int,
            None => 0,
        }
    })
}

/// `int BN_num_bits_word(BN_ULONG w)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_num_bits_word(w: c_ulong) -> c_int {
    guard_ffi(0, || limbs::bit_len_word(w as Limb) as c_int)
}

/// `int BN_is_zero(const BIGNUM *a)`
///
/// The authority dereferences without a null check, so a null argument faults
/// there and answers `1` here. That is a recorded safety divergence, not a
/// reproduced fault.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_zero(a: *const BigNum) -> c_int {
    guard_ffi(1, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => c_int::from(limbs::is_zero(&b.d)),
            None => 1,
        }
    })
}

/// `int BN_is_one(const BIGNUM *a)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_one(a: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => c_int::from(b.d.len() == 1 && b.d[0] == 1),
            None => 0,
        }
    })
}

/// `int BN_is_word(const BIGNUM *a, const BN_ULONG w)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_word(a: *const BigNum, w: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => c_int::from(b.d == limbs::from_u64(w as Limb)),
            None => 0,
        }
    })
}

/// `int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_abs_is_word(a: *const BigNum, w: c_ulong) -> c_int {
    // The magnitude word test is the value word test on a value whose sign has
    // been cleared, so it is `BN_is_word` and the name is about intent.
    // SAFETY: `BN_is_word` requires exactly this function's contract.
    unsafe { BN_is_word(a, w) }
}

/// `int BN_is_odd(const BIGNUM *a)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_odd(a: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => c_int::from(!limbs::is_even(&b.d)),
            None => 0,
        }
    })
}

/// `int BN_is_negative(const BIGNUM *a)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_negative(a: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => b.neg,
            None => 0,
        }
    })
}

/// `int BN_is_bit_set(const BIGNUM *a, int n)`
///
/// A negative `n` answers `0` rather than reading out of bounds, which is why the
/// parameter is signed in the first place.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_is_bit_set(a: *const BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => c_int::from(limbs::bit(&b.d, n as usize)),
            None => 0,
        }
    })
}

// ---------------------------------------------------------------------------
// Setters and flags
// ---------------------------------------------------------------------------

/// `int BN_set_word(BIGNUM *a, BN_ULONG w)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_set_word(a: *mut BigNum, w: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_mut(a) } {
            Some(b) => {
                b.d = limbs::from_u64(w as Limb);
                b.neg = 0;
                1
            }
            None => 0,
        }
    })
}

/// `unsigned long BN_get_word(const BIGNUM *a)`
///
/// Answers `(unsigned long)-1` when the value does not fit, the authority's
/// documented "too large" sentinel.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_get_word(a: *const BigNum) -> c_ulong {
    guard_ffi(c_ulong::MAX, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return 0,
        };
        // The authority's test is on the *limb count*, not the value.
        if b.d.len() > 1 {
            return c_ulong::MAX;
        }
        limbs::low_u64(&b.d) as c_ulong
    })
}

/// `int BN_set_bit(BIGNUM *a, int n)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_set_bit(a: *mut BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_mut(a) } {
            Some(b) => {
                limbs::set_bit(&mut b.d, n as usize);
                1
            }
            None => 0,
        }
    })
}

/// `int BN_clear_bit(BIGNUM *a, int n)`
///
/// Clearing a bit above the value is a no-op that reports success.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_clear_bit(a: *mut BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_mut(a) } {
            Some(b) => {
                limbs::clear_bit(&mut b.d, n as usize);
                if b.d.is_empty() {
                    b.neg = 0;
                }
                1
            }
            None => 0,
        }
    })
}

/// `void BN_set_negative(BIGNUM *a, int n)`
///
/// The authority refuses to mark zero negative, and neither does this.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_set_negative(a: *mut BigNum, n: c_int) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(b) = unsafe { as_mut(a) } {
            b.neg = if n != 0 && !b.d.is_empty() { 1 } else { 0 };
        }
    });
}

/// `void BN_set_flags(BIGNUM *a, int n)`
///
/// The flag word is opaque here: the bits a caller sets are the bits
/// `BN_get_flags` reads back. The ones this profile can observe are
/// `BN_FLG_CONSTTIME` (`0x04`), which asks constant-time behaviour from several
/// operations, and the internal markers `BN_FLG_STATIC_DATA` (`0x02`) and
/// `BN_FLG_FIXED_TOP` (`0x10`) the authority sets on its NIST prime constants. No
/// behaviour here branches on them yet, which the ledger records rather than
/// implies.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_set_flags(a: *mut BigNum, n: c_int) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(b) = unsafe { as_mut(a) } {
            b.flags |= n;
        }
    });
}

/// `int BN_get_flags(const BIGNUM *a, int n)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_get_flags(a: *const BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => b.flags & n,
            None => 0,
        }
    })
}

/// `void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags)`
///
/// **Recorded narrowing.** The authority makes `dest` *alias* `b`'s limb array, so
/// a later write through `dest` is visible through `b`. That trick exists for
/// internal constant-time temporaries; reproducing it needs the limb array owned
/// as a raw pointer with an aliasing flag, and getting that wrong turns a temporary
/// into a double free. This copies the value instead, so `dest` and `b` are
/// independent. Recorded as `OBL-BN-WITH-FLAGS-ALIASING` rather than claimed as
/// parity.
///
/// # Safety
///
/// `dest` and `b` must each be null or live; when both are non-null they must be
/// distinct, or the caller must not rely on the authority's aliasing.
#[no_mangle]
pub unsafe extern "C" fn BN_with_flags(dest: *mut BigNum, b: *const BigNum, flags: c_int) {
    guard_ffi((), || {
        // SAFETY: null-or-live and distinct per this function's `# Safety` section.
        let (dst, src) = unsafe { (as_mut(dest), as_ref(b)) };
        if let (Some(dst), Some(src)) = (dst, src) {
            dst.d.clear();
            dst.d.extend_from_slice(&src.d);
            dst.neg = src.neg;
            dst.flags = src.flags | flags;
        }
    });
}

/// `int BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, unsigned int nwords)`
///
/// Swaps `a` and `b` when `condition` is non-zero, in time independent of it: the
/// loop touches `nwords` limbs of both operands either way and the mask is derived
/// from `condition` without branching.
///
/// # Safety
///
/// `a` and `b` must each be null or live, and distinct when both are non-null.
#[no_mangle]
pub unsafe extern "C" fn BN_consttime_swap(
    condition: c_ulong,
    a: *mut BigNum,
    b: *mut BigNum,
    nwords: c_int,
) {
    guard_ffi((), || {
        if a == b {
            return;
        }
        // SAFETY: two distinct live objects, so the borrows cannot alias; the only
        // read of either pointer.
        let (x, y) = unsafe { (as_mut(a), as_mut(b)) };
        let (x, y) = match (x, y) {
            (Some(x), Some(y)) => (x, y),
            _ => return,
        };
        let mask = 0u64.wrapping_sub((condition != 0) as u64);
        let n = nwords.max(0) as usize;
        x.d.resize(x.d.len().max(n), 0);
        y.d.resize(y.d.len().max(n), 0);
        for i in 0..n {
            let t = (x.d[i] ^ y.d[i]) & mask;
            x.d[i] ^= t;
            y.d[i] ^= t;
        }
        limbs::normalise(&mut x.d);
        limbs::normalise(&mut y.d);
        let t = ((x.neg as u64) ^ (y.neg as u64)) & mask;
        x.neg = ((x.neg as u64) ^ t) as c_int;
        y.neg = ((y.neg as u64) ^ t) as c_int;
    });
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// Decode big- or little-endian bytes into an optional destination, clearing the
/// sign because a byte string is a magnitude.
fn from_bytes(bytes: &[u8], bn: Option<&mut BigNum>, little: bool) -> bool {
    let ordered: Vec<u8> = if little {
        bytes.to_vec()
    } else {
        bytes.iter().rev().copied().collect()
    };
    let mut d: Vec<Limb> = Vec::with_capacity(ordered.len() / 8 + 1);
    let mut acc: u128 = 0;
    let mut have = 0usize;
    for &byte in &ordered {
        acc |= (byte as u128) << (8 * have);
        have += 1;
        if have == 8 {
            d.push(acc as Limb);
            acc = 0;
            have = 0;
        }
    }
    if have != 0 {
        d.push(acc as Limb);
    }
    store(bn, d, false)
}

/// Write the magnitude as `out.len()` bytes, most significant first unless
/// `little`, zero padded on the insignificant side.
fn to_bytes(v: &[Limb], out: &mut [u8], little: bool) {
    let n = out.len();
    for (i, byte) in out.iter_mut().enumerate() {
        let bitpos = if little { i * 8 } else { (n - 1 - i) * 8 };
        *byte = match v.get(bitpos / 64) {
            Some(&l) => (l >> (bitpos % 64)) as u8,
            None => 0,
        };
    }
}

/// The optional object an `int len` byte string names, or `None` when the arguments
/// cannot describe one.
///
/// # Safety
///
/// `s` must point to at least `len` readable bytes when `len` is positive.
unsafe fn bytes_arg<'a>(s: *const u8, len: c_int) -> Option<&'a [u8]> {
    if len < 0 || (s.is_null() && len != 0) {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: the caller's contract is exactly that `s` covers `len` bytes, and
    // `len` is positive here.
    Some(unsafe { core::slice::from_raw_parts(s, len as usize) })
}

/// `BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)`
///
/// # Safety
///
/// `s` must point to at least `len` readable bytes when `len` is positive; `ret`
/// must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_bin2bn(s: *const u8, len: c_int, ret: *mut BigNum) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        let (bytes, dst) = unsafe { (bytes_arg(s, len), as_mut(ret)) };
        let bytes = match bytes {
            Some(b) => b,
            None => return core::ptr::null_mut(),
        };
        if ret.is_null() {
            let fresh = new_owned(Vec::new(), 0);
            // SAFETY: `fresh` is a live object this function owns.
            if !unsafe { as_mut(fresh) }.is_some_and(|d| from_bytes(bytes, Some(d), false)) {
                return core::ptr::null_mut();
            }
            return fresh;
        }
        if from_bytes(bytes, dst, false) {
            ret
        } else {
            core::ptr::null_mut()
        }
    })
}

/// `BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)`
///
/// # Safety
///
/// As `BN_bin2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_lebin2bn(s: *const u8, len: c_int, ret: *mut BigNum) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        let (bytes, dst) = unsafe { (bytes_arg(s, len), as_mut(ret)) };
        let bytes = match bytes {
            Some(b) => b,
            None => return core::ptr::null_mut(),
        };
        if ret.is_null() {
            let fresh = new_owned(Vec::new(), 0);
            // SAFETY: `fresh` is a live object this function owns.
            if !unsafe { as_mut(fresh) }.is_some_and(|d| from_bytes(bytes, Some(d), true)) {
                return core::ptr::null_mut();
            }
            return fresh;
        }
        if from_bytes(bytes, dst, true) {
            ret
        } else {
            core::ptr::null_mut()
        }
    })
}

/// Decompose a two's-complement byte string as `(magnitude, negative)`, with the
/// magnitude in big-endian order and no sign extension.
///
/// `little` selects where the sign lives: the authority reads a little-endian string
/// most-significant byte last, so the sign is the top bit of the *final* byte.
fn signed_magnitude(bytes: &[u8], little: bool) -> (Vec<u8>, bool) {
    let mut ordered: Vec<u8> = bytes.to_vec();
    if little {
        ordered.reverse();
    }
    // `ordered` is big-endian from here, so its first byte carries the sign.
    let negative = ordered.first().is_some_and(|b| b & 0x80 != 0);
    if negative {
        for byte in ordered.iter_mut() {
            *byte = !*byte;
        }
        let mut carry = 1u16;
        for byte in ordered.iter_mut().rev() {
            let t = *byte as u16 + carry;
            *byte = t as u8;
            carry = t >> 8;
        }
    }
    (ordered, negative)
}

/// Place a two's-complement decode into a fresh object when `ret` is null, or into
/// `ret` otherwise — the allocation contract `BN_bin2bn` and its signed relatives
/// share, and the reason a null `ret` is not an error.
///
/// # Safety
///
/// `ret` must be null or a live, uniquely-owned `BIGNUM`.
unsafe fn signed_store(magnitude: &[u8], negative: bool, ret: *mut BigNum) -> *mut BigNum {
    let target = if ret.is_null() {
        new_owned(Vec::new(), 0)
    } else {
        ret
    };
    // SAFETY: the caller guarantees `ret` is null or live and uniquely owned, and
    // `target` is `ret` when it is not null and a fresh object otherwise.
    let Some(d) = (unsafe { as_mut(target) }) else {
        return core::ptr::null_mut();
    };
    if !from_bytes(magnitude, Some(d), false) {
        if ret.is_null() {
            // SAFETY: `target` is the fresh object this call allocated.
            unsafe { BN_free(target) };
        }
        return core::ptr::null_mut();
    }
    if negative && !d.d.is_empty() {
        d.neg = 1;
    }
    target
}

/// `BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret)`
///
/// The native byte order of this target is little-endian, which is what the
/// authority's own `BN_native2bn` compiles to here.
///
/// # Safety
///
/// As `BN_bin2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_native2bn(s: *const u8, len: c_int, ret: *mut BigNum) -> *mut BigNum {
    // SAFETY: `BN_lebin2bn`'s contract is this function's contract on this target.
    unsafe { BN_lebin2bn(s, len, ret) }
}

/// `int BN_bn2bin(const BIGNUM *a, unsigned char *to)`
///
/// Writes the **magnitude** in big-endian order, exactly `BN_num_bytes`
/// (= `(BN_num_bits + 7) / 8`) bytes; the caller must have sized `to` for that.
///
/// # Safety
///
/// `a` must be null or live; `to` must point to at least `(BN_num_bits(a) + 7) / 8`
/// writable bytes when that count is non-zero, and may be null when it is zero.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2bin(a: *const BigNum, to: *mut u8) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return -1,
        };
        let n = limbs::bit_len(&b.d).div_ceil(8);
        if n == 0 {
            return 0;
        }
        if to.is_null() {
            return -1;
        }
        // SAFETY: the caller guarantees `to` holds `n` writable bytes and
        // `n > 0`, so the slice is non-empty and valid.
        let out = unsafe { core::slice::from_raw_parts_mut(to, n) };
        to_bytes(&b.d, out, false);
        n as c_int
    })
}

/// Write the magnitude into `tolen` bytes, big-endian unless `little`, zero padded.
/// `None` when the value does not fit, which the entry points report as `-1`.
///
/// # Safety
///
/// `to` must point to at least `tolen` writable bytes when `tolen` is positive.
unsafe fn padded_bytes(a: *const BigNum, to: *mut u8, tolen: c_int, little: bool) -> Option<c_int> {
    if tolen < 0 {
        return None;
    }
    // SAFETY: null-or-live per the caller's contract.
    let b = unsafe { as_ref(a) }?;
    if limbs::bit_len(&b.d).div_ceil(8) > tolen as usize {
        return None;
    }
    if tolen > 0 {
        if to.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `to` holds `tolen` writable bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(to, tolen as usize) };
        to_bytes(&b.d, out, little);
    }
    Some(tolen)
}

/// `int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// `a` must be null or live; `to` must point to at least `tolen` writable bytes
/// when `tolen` is positive.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2binpad(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        unsafe { padded_bytes(a, to, tolen, false) }.unwrap_or(-1)
    })
}

/// `int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// As `BN_bn2binpad`.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2lebinpad(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        unsafe { padded_bytes(a, to, tolen, true) }.unwrap_or(-1)
    })
}

/// `int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// As `BN_bn2binpad`.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2nativepad(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    // SAFETY: `BN_bn2lebinpad`'s contract is this function's contract on this
    // little-endian target.
    unsafe { BN_bn2lebinpad(a, to, tolen) }
}

/// `char *BN_bn2hex(const BIGNUM *a)` — uppercase hex, allocated by
/// `CRYPTO_malloc` so a caller frees it with `OPENSSL_free`.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2hex(a: *const BigNum) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => dup_cstring(&hex_of(b, true)),
            None => core::ptr::null_mut(),
        }
    })
}

/// `char *BN_bn2dec(const BIGNUM *a)` — decimal, allocated by `CRYPTO_malloc`.
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2dec(a: *const BigNum) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref(a) } {
            Some(b) => dup_cstring(&dec_of(b)),
            None => core::ptr::null_mut(),
        }
    })
}

/// Parse `digits` in `radix` into the object `*a` names, allocating when it is
/// null. Answers the number of characters consumed, or `0`, which is the
/// authority's contract and what lets a caller walk a concatenated string.
fn parse_into(a: *mut *mut BigNum, text: &str, radix: u32) -> c_int {
    let bytes = text.as_bytes();
    let neg = bytes.first() == Some(&b'-');
    let mut end = usize::from(neg);
    let start = end;
    while end < bytes.len() && (bytes[end] as char).is_digit(radix) {
        end += 1;
    }
    if end == start {
        return 0;
    }
    let mut d: Vec<Limb> = Vec::new();
    for c in text[start..end].chars() {
        let Some(v) = c.to_digit(radix) else {
            return 0;
        };
        if radix == 16 {
            // Four bits per digit, so the limbs can be filled by a shift rather
            // than by a general multiply-and-add.
            let mut carry = v as u64;
            for limb in d.iter_mut() {
                let t = ((*limb as u128) << 4) | (carry as u128);
                *limb = t as u64;
                carry = (t >> 64) as u64;
            }
            if carry != 0 {
                d.push(carry);
            }
        } else {
            d = limbs::add(&limbs::mul(&d, &[radix as u64]), &[v as u64]);
        }
    }
    // SAFETY: the caller guarantees `a` is a writable out-parameter, which the
    // `# Safety` section of the entry point that calls this states.
    let slot = match unsafe { a.as_mut() } {
        Some(slot) => slot,
        None => return 0,
    };
    if slot.is_null() {
        *slot = new_owned(d, c_int::from(neg));
    } else {
        // SAFETY: `*slot` is a live object the caller owns, so filling it in is
        // the documented "reuse this object" behaviour of `BN_hex2bn`/`BN_dec2bn`.
        let Some(dst) = (unsafe { as_mut(*slot) }) else {
            return 0;
        };
        if !store(Some(dst), d, neg) {
            return 0;
        }
    }
    end as c_int
}

/// `int BN_hex2bn(BIGNUM **a, const char *str)`
///
/// # Safety
///
/// `str` must be a NUL-terminated C string; `a` must point to a writable
/// `*mut BIGNUM` whose current value is null or a live object.
#[no_mangle]
pub unsafe extern "C" fn BN_hex2bn(a: *mut *mut BigNum, str: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `str` is a NUL-terminated string.
        match unsafe { from_cstr_lossy(str) } {
            Some(t) => parse_into(a, &t, 16),
            None => 0,
        }
    })
}

/// `int BN_dec2bn(BIGNUM **a, const char *str)`
///
/// # Safety
///
/// As `BN_hex2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_dec2bn(a: *mut *mut BigNum, str: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `str` is a NUL-terminated string.
        match unsafe { from_cstr_lossy(str) } {
            Some(t) => parse_into(a, &t, 10),
            None => 0,
        }
    })
}

/// `int BN_asc2bn(BIGNUM **a, const char *str)`
///
/// Accepts `0x`/`0X` hex or decimal; that prefix is the only difference from the
/// two radix-specific parsers.
///
/// # Safety
///
/// As `BN_hex2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_asc2bn(a: *mut *mut BigNum, str: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `str` is a NUL-terminated string.
        let text = match unsafe { from_cstr_lossy(str) } {
            Some(t) => t,
            None => return 0,
        };
        let sign = if text.starts_with('-') { "-" } else { "" };
        let body = text.strip_prefix('-').unwrap_or(&text);
        // The authority tests the first two characters after an optional sign —
        // `p[0] == '0' && (p[1] == 'x' || p[1] == 'X')` — so `"0x"` alone is a hex
        // parse of the empty string, which fails, rather than a decimal parse of
        // `"0x"`. Matching that test rather than a length check keeps the edge
        // cases identical.
        let radix = if body.starts_with("0x") || body.starts_with("0X") {
            16
        } else {
            10
        };
        let parsed = if radix == 16 {
            parse_into(a, &format!("{sign}{}", &body[2..]), 16)
        } else {
            parse_into(a, &text, 10)
        };
        // `BN_asc2bn` answers 1 or 0, unlike `BN_hex2bn`/`BN_dec2bn`, which answer
        // the number of digits consumed. Returning that count is a divergence the
        // court sees on every successful call.
        if parsed == 0 {
            0
        } else {
            1
        }
    })
}

/// The authority's MPI wire form: a four-byte big-endian byte count, the magnitude
/// bytes (with a leading zero byte when the top bit is set), then a sign byte when
/// the value is negative.
fn mpi_encode(b: &BigNum) -> Vec<u8> {
    let bits = limbs::bit_len(&b.d);
    let nbytes = bits.div_ceil(8);
    let pad = usize::from(bits > 0 && bits.is_multiple_of(8));
    let neg = b.neg != 0;
    let mut out = Vec::with_capacity(4 + nbytes + pad + usize::from(neg));
    out.extend_from_slice(&((nbytes + pad) as u32).to_be_bytes());
    out.resize(4 + pad, 0);
    if nbytes > 0 {
        let at = out.len();
        out.resize(at + nbytes, 0);
        to_bytes(&b.d, &mut out[at..], false);
    }
    if neg {
        out.push(0xFF);
    }
    out
}

/// `int BN_bn2mpi(const BIGNUM *a, unsigned char *to)`
///
/// With a null `to` this answers the number of bytes a write would take, which is
/// the authority's size-query protocol.
///
/// # Safety
///
/// `a` must be null or live; `to` must be null or point to at least as many
/// writable bytes as the size query reports.
#[no_mangle]
pub unsafe extern "C" fn BN_bn2mpi(a: *const BigNum, to: *mut u8) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return -1,
        };
        let encoded = mpi_encode(b);
        if to.is_null() {
            return encoded.len() as c_int;
        }
        // SAFETY: the caller guarantees `to` covers the size query's answer, which
        // is `encoded.len()`.
        let out = unsafe { core::slice::from_raw_parts_mut(to, encoded.len()) };
        out.copy_from_slice(&encoded);
        encoded.len() as c_int
    })
}

/// `BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret)`
///
/// # Safety
///
/// `s` must point to at least `len` readable bytes when `len` is positive; `ret`
/// must be null or live and uniquely owned.
#[no_mangle]
pub unsafe extern "C" fn BN_mpi2bn(s: *const u8, len: c_int, ret: *mut BigNum) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        let bytes = match unsafe { bytes_arg(s, len) } {
            Some(b) => b,
            None => return core::ptr::null_mut(),
        };
        if bytes.len() < 4 {
            return core::ptr::null_mut();
        }
        let nbytes = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if 4 + nbytes > bytes.len() {
            return core::ptr::null_mut();
        }
        let neg = 4 + nbytes < bytes.len() && bytes[bytes.len() - 1] != 0;
        let fresh = new_owned(Vec::new(), 0);
        // SAFETY: `fresh` is a live object this function owns.
        let Some(dst) = (unsafe { as_mut(fresh) }) else {
            return core::ptr::null_mut();
        };
        if !from_bytes(&bytes[4..4 + nbytes], Some(dst), false) {
            // SAFETY: `fresh` is live and this function is dropping it.
            unsafe { BN_free(fresh) };
            return core::ptr::null_mut();
        }
        if neg && !dst.d.is_empty() {
            dst.neg = 1;
        }
        if ret.is_null() {
            fresh
        } else {
            // SAFETY: `ret` is null or live and uniquely owned per the contract.
            let moved = unsafe { as_mut(ret) };
            let ok = moved.is_some_and(|m| store(Some(m), dst.d.clone(), dst.neg != 0));
            // SAFETY: `fresh` is live and this function is dropping it.
            unsafe { BN_free(fresh) };
            if ok {
                ret
            } else {
                core::ptr::null_mut()
            }
        }
    })
}

/// `BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret)` — the
/// input is read as a two's-complement big-endian integer.
///
/// # Safety
///
/// As `BN_bin2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_bin2bn(
    s: *const u8,
    len: c_int,
    ret: *mut BigNum,
) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        let bytes = match unsafe { bytes_arg(s, len) } {
            Some(b) => b,
            None => return core::ptr::null_mut(),
        };
        let (magnitude, negative) = signed_magnitude(bytes, false);
        // SAFETY: `ret` is null or live and uniquely owned per this function's
        // `# Safety` section.
        unsafe { signed_store(&magnitude, negative, ret) }
    })
}

/// `BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)` — the
/// bytes are a two's-complement integer with the **most significant byte last**.
///
/// # Safety
///
/// As `BN_bin2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_lebin2bn(
    s: *const u8,
    len: c_int,
    ret: *mut BigNum,
) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: both arguments' contracts are this function's `# Safety` section.
        let bytes = match unsafe { bytes_arg(s, len) } {
            Some(b) => b,
            None => return core::ptr::null_mut(),
        };
        let (magnitude, negative) = signed_magnitude(bytes, true);
        // SAFETY: `ret` is null or live and uniquely owned per this function's
        // `# Safety` section.
        unsafe { signed_store(&magnitude, negative, ret) }
    })
}

/// `BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret)`
///
/// # Safety
///
/// As `BN_bin2bn`.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_native2bn(
    s: *const u8,
    len: c_int,
    ret: *mut BigNum,
) -> *mut BigNum {
    // SAFETY: `BN_signed_lebin2bn`'s contract is this function's contract on this
    // little-endian target.
    unsafe { BN_signed_lebin2bn(s, len, ret) }
}

/// Write the two's-complement form of `b` into `tolen` bytes, big-endian unless
/// `little`. `None` when the value cannot fit.
///
/// # Safety
///
/// `to` must point to at least `tolen` writable bytes when `tolen` is positive.
unsafe fn signed_bytes(b: &BigNum, to: *mut u8, tolen: c_int, little: bool) -> Option<c_int> {
    if tolen < 0 {
        return None;
    }
    let need = limbs::bit_len(&b.d).div_ceil(8);
    if need > tolen as usize {
        return None;
    }
    if tolen > 0 {
        if to.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees `tolen` writable bytes at `to`.
        let out = unsafe { core::slice::from_raw_parts_mut(to, tolen as usize) };
        to_bytes(&b.d, out, little);
        if b.neg != 0 {
            // Negate in place: invert every byte of the representation, then add
            // one, propagating the carry from the least significant byte.
            for byte in out.iter_mut() {
                *byte = !*byte;
            }
            let order: Vec<usize> = if little {
                (0..out.len()).collect()
            } else {
                (0..out.len()).rev().collect()
            };
            let mut carry = 1u16;
            for i in order {
                let t = out[i] as u16 + carry;
                out[i] = t as u8;
                carry = t >> 8;
            }
        }
    }
    Some(tolen)
}

/// `int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// `a` must be null or live; `to` must point to at least `tolen` writable bytes
/// when `tolen` is positive.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_bn2bin(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return -1,
        };
        // SAFETY: the caller guarantees `tolen` writable bytes at `to`.
        unsafe { signed_bytes(b, to, tolen, false) }.unwrap_or(-1)
    })
}

/// `int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// As `BN_signed_bn2bin`.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_bn2lebin(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return -1,
        };
        // SAFETY: the caller guarantees `tolen` writable bytes at `to`.
        unsafe { signed_bytes(b, to, tolen, true) }.unwrap_or(-1)
    })
}

/// `int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen)`
///
/// # Safety
///
/// As `BN_signed_bn2bin`.
#[no_mangle]
pub unsafe extern "C" fn BN_signed_bn2native(a: *const BigNum, to: *mut u8, tolen: c_int) -> c_int {
    // SAFETY: `BN_signed_bn2lebin`'s contract is this function's contract here.
    unsafe { BN_signed_bn2lebin(a, to, tolen) }
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

/// `int BN_print(BIO *fp, const BIGNUM *a)` — lowercase hex through the BIO layer,
/// so it inherits the BIO's retry and error behaviour rather than writing to a
/// descriptor directly.
///
/// # Safety
///
/// `fp` must be null or a live `BIO`; `a` must be null or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_print(fp: *mut crate::runtime::bio::Bio, a: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return 0,
        };
        let s = hex_of(b, false);
        // SAFETY: `fp` is null or a live BIO, and `s` outlives the call.
        let n = unsafe { crate::runtime::bio::BIO_write(fp, s.as_ptr().cast(), s.len() as c_int) };
        c_int::from(n == s.len() as c_int)
    })
}

/// `int BN_print_fp(FILE *fp, const BIGNUM *a)`
///
/// # Safety
///
/// `fp` must be null or a live `FILE`; `a` must be null or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_print_fp(
    fp: *mut crate::runtime::bio::sys::FILE,
    a: *const BigNum,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let b = match unsafe { as_ref(a) } {
            Some(b) => b,
            None => return 0,
        };
        if fp.is_null() {
            return 0;
        }
        let s = hex_of(b, false);
        // SAFETY: `fp` is non-null and the caller guarantees it is a live `FILE`;
        // `s` outlives the call. The authority writes with `fputs`.
        let n = unsafe { crate::runtime::bio::sys::fwrite(s.as_ptr().cast(), 1, s.len(), fp) };
        c_int::from(n == s.len())
    })
}

/// `char *BN_options(void)` — a build-configuration string. The authority answers
///
/// # Safety
///
/// Takes no pointers.
///
/// a `BN_LLONG`-style description of how it was compiled. This answers the same
/// kind of description of *this* implementation's limb width, because a caller
/// using it to pick a code path must be told the truth about the build in front of
/// it, not about the build it would have been linked against otherwise.
#[no_mangle]
pub unsafe extern "C" fn BN_options() -> *const c_char {
    guard_ffi(core::ptr::null(), || c"bn(64,64)".as_ptr())
}

/// `int BN_security_bits(int L, int N)` — the security strength the authority
/// attributes to a modulus of `L` bits with `N`-bit subgroups. These thresholds are
/// contract: a caller uses the answer to decide whether a key is strong enough.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_security_bits(l: c_int, n: c_int) -> c_int {
    guard_ffi(0, || {
        for (bits, strength) in [
            (15_360, 256),
            (7_680, 192),
            (3_072, 128),
            (2_048, 112),
            (1_024, 80),
        ] {
            if l >= bits {
                return strength;
            }
        }
        match n {
            160 => 80,
            224 => 112,
            256 => 128,
            _ => 0,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_decimal_round_trip_through_the_parsers() {
        // Verified against an independent bignum: this test's first version
        // asserted a decimal value that was simply typed wrong, and the
        // implementation was right. That is the fourth time in this stratum that
        // the expectation was the suspect rather than the code.
        let hex = "deadbeefcafebabe0123456789abcdef";
        let decimal = "295990755076957304698161171062762229231";
        let mut p: *mut BigNum = core::ptr::null_mut();
        assert_eq!(
            // SAFETY: `p` is a writable slot this test owns, and the string is a
            // NUL-terminated literal.
            unsafe { BN_hex2bn(&mut p, c"deadbeefcafebabe0123456789abcdef".as_ptr()) },
            32
        );
        assert_eq!(
            // SAFETY: `p` is live and `BN_bn2dec` allocates the answer.
            unsafe { std::ffi::CStr::from_ptr(BN_bn2dec(p)) }.to_str(),
            Ok(decimal)
        );
        let mut q: *mut BigNum = core::ptr::null_mut();
        assert_eq!(
            // SAFETY: `q` is a writable slot and the string is NUL-terminated.
            unsafe { BN_dec2bn(&mut q, c"295990755076957304698161171062762229231".as_ptr()) },
            39
        );
        assert!(
            // SAFETY: both objects are live.
            unsafe { same_value(p, q) },
            "the hex and decimal parsers agree on {hex}"
        );
        // SAFETY: both objects are live and were allocated here.
        unsafe {
            BN_free(p);
            BN_free(q);
        }
    }

    /// Test-only equality, so this test does not have to reach for `BN_cmp` in
    /// another module to say what it means.
    ///
    /// # Safety
    ///
    /// Both arguments must be live.
    unsafe fn same_value(a: *const BigNum, b: *const BigNum) -> bool {
        // SAFETY: the caller guarantees both are live.
        match unsafe { (as_ref(a), as_ref(b)) } {
            (Some(x), Some(y)) => x.d == y.d && x.neg == y.neg,
            _ => false,
        }
    }

    #[test]
    fn mpi_encoding_matches_the_documented_layout() {
        let mut p: *mut BigNum = core::ptr::null_mut();
        // SAFETY: `p` is a writable slot and the string is NUL-terminated.
        unsafe { BN_hex2bn(&mut p, c"80".as_ptr()) };
        // SAFETY: `p` is live; a null `to` asks for the size.
        let n = unsafe { BN_bn2mpi(p, core::ptr::null_mut()) };
        assert_eq!(n, 6, "4-byte count + a padding byte + the value byte");
        let mut buf = [0u8; 6];
        // SAFETY: `buf` is exactly the size the query reported.
        unsafe { BN_bn2mpi(p, buf.as_mut_ptr()) };
        assert_eq!(&buf[..4], &[0, 0, 0, 2]);
        assert_eq!(&buf[4..], &[0, 0x80]);
        // SAFETY: `p` is live.
        unsafe { BN_free(p) };
    }

    #[test]
    fn predicates_and_flags_behave_at_the_boundaries() {
        // SAFETY: every object here is allocated by this test and live.
        unsafe {
            let a = BN_new();
            assert_eq!(BN_is_zero(a), 1);
            assert_eq!(BN_is_negative(a), 0);
            BN_set_negative(a, 1);
            assert_eq!(BN_is_negative(a), 0, "zero is never negative");
            let big = new_owned(limbs::from_u64(1 << 20), 0);
            BN_set_bit(big, 200);
            assert_eq!(BN_num_bits(big), 201);
            assert_eq!(BN_is_bit_set(big, 200), 1);
            assert_eq!(BN_is_bit_set(big, -1), 0, "a negative bit is not an error");
            BN_clear_bit(big, 200);
            assert_eq!(BN_num_bits(big), 21);
            BN_set_flags(big, 0x04);
            assert_eq!(BN_get_flags(big, 0x04), 0x04);
            assert_eq!(BN_get_flags(big, 0x01), 0x01);
            assert_eq!(BN_get_word(big), 1 << 20);
            assert_eq!(BN_security_bits(2048, 0), 112);
            assert_eq!(BN_security_bits(256, 0), 0);
            BN_free(a);
            BN_free(big);
        }
    }
}
