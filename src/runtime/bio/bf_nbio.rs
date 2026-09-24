//! Phase 9 — the non-blocking-IO test filter (`BIO_f_nbio_test`).
//!
//! `crypto/bio/bf_nbio.c` whole. It is a *test* filter — nothing in the library
//! pushes it — but `bio.h` declares it, so it is an export, and it is the one
//! `crypto/bio/` filter whose body reaches the random layer: `nbiof_read` and
//! `nbiof_write` each draw one byte with `RAND_priv_bytes` and use its low three
//! bits as the number of bytes to pass through. That is why it is this stratum's
//! rather than Phase 4's, which landed every other filter beside it.
//!
//! # What it does, and what is observable
//!
//! A zero draw (one chance in eight) short-circuits the transfer: the filter
//! answers `-1` and raises the retry flag for the direction it was called in,
//! without touching `next_bio` at all. A non-zero draw forwards *at most* that
//! many bytes, so a write larger than the draw is truncated and the remainder is
//! lost — not buffered. `nbiof_write` keeps the truncated length in `lwn` so the
//! next call resumes with the same cap instead of drawing again, and clears it as
//! soon as it is read.
//!
//! # What a differential court can measure here, and what it cannot
//!
//! The draw itself is unobservable, and so is the truncation: two builds draw
//! different bytes. What *is* deterministic and is measured by `RT-BIO-FILTER`'s
//! arm is the contract around the draw — that the filter constructs (`BIO_new`
//! answers non-NULL), that its method reports `BIO_TYPE_NBIO_TEST` and its name,
//! that `nbiof_new` set `lrn`/`lwn` to `-1` (visible through the first write's
//! cap behaviour only once a draw has happened), that `BIO_ctrl(BIO_CTRL_DUP)`
//! answers 0 without forwarding, that every entry point with a NULL `next_bio`
//! answers 0 rather than dereferencing, and that the free path releases the
//! context. The filter's own `BIO_f_nbio_test()` answering a non-NULL method
//! pointer — not its contents — is the export's observation.
//!
//! `bio_local.h`'s `NBIO_TEST` is two `int`s; `b->ptr` is the allocation and the
//! authority's `nbiof_free` frees it without reading it, so the struct's only
//! observable is `lwn`, and only through the second write's cap.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::rand::rand_lib::RAND_priv_bytes;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioInfoCb, BioMethod, BIO_CTRL_DUP, BIO_C_DO_STATE_MACHINE, BIO_FLAGS_READ, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_TYPE_NBIO_TEST,
};

/// `typedef struct nbio_test_st { int lrn; int lwn; } NBIO_TEST` — `bf_nbio.c:36-40`.
///
/// `lrn` is the read-side cap and `lwn` the write-side one; both start at `-1`,
/// which is not a cap (the branch tests `> 0`) but is what the authority stores.
#[repr(C)]
struct NbioTest {
    lrn: c_int,
    lwn: c_int,
}

/// The authority's method name, `bf_nbio.c:41`.
const NBIOF_NAME: &[u8] = b"non-blocking IO test filter\0";

/// `static const BIO_METHOD methods_nbiof` — `bf_nbio.c:41-56`.
static NBIOF_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_NBIO_TEST,
    name: NBIOF_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(nbiof_write),
    bread: Some(bread_conv),
    bread_old: Some(nbiof_read),
    bputs: Some(nbiof_puts),
    bgets: Some(nbiof_gets),
    ctrl: Some(nbiof_ctrl),
    create: Some(nbiof_new),
    destroy: Some(nbiof_free),
    callback_ctrl: Some(nbiof_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_nbio_test(void)` — `bf_nbio.c:58-61`.
#[no_mangle]
pub extern "C" fn BIO_f_nbio_test() -> *const BioMethod {
    guard_ffi(ptr::null(), || &NBIOF_METHOD)
}

/// The context of a live non-blocking-test BIO.
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe fn ctx(b: *mut Bio) -> *mut NbioTest {
    // SAFETY: the caller guarantees the BIO came from this method.
    unsafe { (*b).ptr.cast() }
}

/// `BIO_clear_retry_flags(b)` — `bio.h`'s macro over `BIO_clear_flags`.
///
/// # Safety
/// `b` must be a live BIO.
#[inline]
unsafe fn clear_retry_flags(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
}

/// `BIO_set_retry_read(b)` — `bio.h`'s macro over `BIO_set_flags`.
///
/// # Safety
/// `b` must be a live BIO.
#[inline]
unsafe fn set_retry_read(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe { super::BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) };
}

/// `BIO_set_retry_write(b)` — `bio.h`'s macro over `BIO_set_flags`.
///
/// # Safety
/// `b` must be a live BIO.
#[inline]
unsafe fn set_retry_write(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe { super::BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
}

/// `static int nbiof_new(BIO *bi)` — `bf_nbio.c:63-75`.
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn nbiof_new(bi: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns a fresh zeroed allocation of the requested size, or NULL.
    let nt = CRYPTO_zalloc(core::mem::size_of::<NbioTest>(), ptr::null(), 0).cast::<NbioTest>();
    if nt.is_null() {
        return 0;
    }
    // SAFETY: `nt` is a fresh zeroed allocation; `bi` is live.
    unsafe {
        (*nt).lrn = -1;
        (*nt).lwn = -1;
        (*bi).ptr = nt.cast();
        (*bi).init = 1;
    }
    1
}

/// `static int nbiof_free(BIO *a)` — `bf_nbio.c:77-86`.
///
/// # Safety
/// `a` must be NULL or a live BIO created from this method.
unsafe extern "C" fn nbiof_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live and holds a `NbioTest`.
    unsafe {
        CRYPTO_free((*a).ptr.cast(), ptr::null(), 0);
        (*a).ptr = ptr::null_mut();
        (*a).init = 0;
        (*a).flags = 0;
    }
    1
}

/// `static int nbiof_read(BIO *b, char *out, int outl)` — `bf_nbio.c:88-111`.
///
/// # Safety
/// `b` must be a live filter BIO; `out` must be valid for `outl` bytes.
unsafe extern "C" fn nbiof_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }

    // SAFETY: `b` is live.
    unsafe { clear_retry_flags(b) };
    let mut n: c_uchar = 0;
    // SAFETY: the draw contract; `n` is one writable byte.
    if unsafe { RAND_priv_bytes(&mut n, 1) } <= 0 {
        return -1;
    }
    let num = (n & 0x07) as c_int;
    let outl = if outl > num { num } else { outl };

    if num == 0 {
        // SAFETY: `b` is live.
        unsafe { set_retry_read(b) };
        -1
    } else {
        // SAFETY: `next` is a live BIO in the chain; `out` is valid for `outl` bytes.
        let ret = unsafe { super::BIO_read(next, out.cast(), outl) };
        if ret < 0 {
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
        }
        ret
    }
}

/// `static int nbiof_write(BIO *b, const char *in, int inl)` — `bf_nbio.c:113-149`.
///
/// # Safety
/// `b` must be a live filter BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn nbiof_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    if in_.is_null() || inl <= 0 {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `b` is live and holds a `NbioTest`.
    let nt = unsafe { ctx(b) };

    // SAFETY: `b` is live.
    unsafe { clear_retry_flags(b) };

    // SAFETY: `nt` is this BIO's own context.
    let num = unsafe {
        if (*nt).lwn > 0 {
            let n = (*nt).lwn;
            (*nt).lwn = 0;
            n
        } else {
            let mut n: c_uchar = 0;
            // SAFETY: the draw contract; `n` is one writable byte.
            if RAND_priv_bytes(&mut n, 1) <= 0 {
                return -1;
            }
            (n & 7) as c_int
        }
    };
    let inl = if inl > num { num } else { inl };

    if num == 0 {
        // SAFETY: `b` is live.
        unsafe { set_retry_write(b) };
        -1
    } else {
        // SAFETY: `next` is a live BIO in the chain; `in_` is valid for `inl` bytes.
        let ret = unsafe { super::BIO_write(next, in_.cast(), inl) };
        if ret < 0 {
            // SAFETY: `b` is live; `nt` is this BIO's own context.
            unsafe {
                super::BIO_copy_next_retry(b);
                (*nt).lwn = inl;
            }
        }
        ret
    }
}

/// `static long nbiof_ctrl(BIO *b, int cmd, long num, void *ptr)` — `bf_nbio.c:151-172`.
///
/// # Safety
/// `b` must be a live filter BIO; `arg` must be as the command requires.
unsafe extern "C" fn nbiof_ctrl(b: *mut Bio, cmd: c_int, num: c_long, arg: *mut c_void) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    match cmd {
        BIO_C_DO_STATE_MACHINE => {
            // SAFETY: `b` is live.
            unsafe { clear_retry_flags(b) };
            // SAFETY: `next` is live.
            let ret = unsafe { super::BIO_ctrl(next, cmd, num, arg) };
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
            ret
        }
        // The filter refuses `DUP` rather than forwarding it, like every other
        // filter in this module: duplicating the downstream BIO's private state
        // into itself is not what the command means.
        BIO_CTRL_DUP => 0,
        _ => {
            // SAFETY: `next` is live.
            unsafe { super::BIO_ctrl(next, cmd, num, arg) }
        }
    }
}

/// `static long nbiof_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)` — `bf_nbio.c:174-179`.
///
/// # Safety
/// `b` must be a live filter BIO.
unsafe extern "C" fn nbiof_callback_ctrl(b: *mut Bio, cmd: c_int, fp: Option<BioInfoCb>) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live.
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// `static int nbiof_gets(BIO *bp, char *buf, int size)` — `bf_nbio.c:181-185`.
///
/// # Safety
/// `bp` must be a live filter BIO; `buf` must be valid for `size` bytes.
unsafe extern "C" fn nbiof_gets(bp: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `bp` is live.
    let next = unsafe { (*bp).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live; `buf` is valid for `size` bytes.
    unsafe { super::BIO_gets(next, buf, size) }
}

/// `static int nbiof_puts(BIO *bp, const char *str)` — `bf_nbio.c:187-191`.
///
/// # Safety
/// `bp` must be a live filter BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn nbiof_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `bp` is live.
    let next = unsafe { (*bp).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live; `str_` is NUL-terminated.
    unsafe { super::BIO_puts(next, str_) }
}
