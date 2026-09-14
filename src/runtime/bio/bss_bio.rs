//! Phase 4 — the BIO pair (`BIO_s_bio`, `BIO_new_bio_pair`).
//!
//! A BIO pair is two BIOs wired back to back inside one process, used when the
//! caller has an I/O channel that has no BIO method of its own. Each endpoint
//! owns a **ring buffer** for what it writes, and reads from its peer's ring
//! buffer, so a read and a write on opposite endpoints move the same bytes.
//!
//! The observable contract is mostly about the retry protocol, and it is not
//! symmetric in the way one might expect:
//!
//! * a read on an empty, unclosed peer buffer returns `-1` with the **read**
//!   retry flag set, and records the number of bytes the reader wanted in the
//!   peer's `request` field — clamped to the peer's buffer size, because the peer
//!   could not deliver more than that in one write anyway;
//! * a write to a full buffer returns `-1` with the **write** retry flag set;
//! * a write to a buffer whose peer has shut down its write side raises
//!   `BIO_R_BROKEN_PIPE` and returns `-1`, while a **read** on a closed-and-empty
//!   peer returns `0` without raising at all;
//! * `BIO_CTRL_EOF` is 1 only when the peer is closed **and** empty, and 1 for an
//!   unpaired BIO;
//! * `BIO_CTRL_PENDING` reports the *peer's* length (what this endpoint can read)
//!   while `BIO_CTRL_WPENDING` reports its own (what it has written);
//! * the ring buffer wraps, so the write path advances a computed write offset
//!   and splits the copy in two.
//!
//! `rt_bio_pair_probe.c` drives all of that through the public controls, and
//! separately through the non-copying `BIO_nread`/`BIO_nwrite` interface, which
//! is what `BIO_ctrl_get_write_guarantee` is a promise about.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_BIO_286, BSS_BIO_361, BSS_BIO_426, BSS_BIO_429, BSS_BIO_617,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING,
    BIO_C_DESTROY_BIO_PAIR, BIO_C_GET_READ_REQUEST, BIO_C_GET_WRITE_BUF_SIZE,
    BIO_C_GET_WRITE_GUARANTEE, BIO_C_MAKE_BIO_PAIR, BIO_C_NREAD, BIO_C_NREAD0, BIO_C_NWRITE,
    BIO_C_NWRITE0, BIO_C_RESET_READ_REQUEST, BIO_C_SET_WRITE_BUF_SIZE, BIO_C_SHUTDOWN_WR,
    BIO_FLAGS_READ, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_TYPE_BIO,
};

/// The method name the authority reports for a BIO pair endpoint.
const PAIR_NAME: &[u8] = b"BIO pair\0";

/// The default write-buffer size: "enough for one TLS record (just a default)".
const DEFAULT_PAIR_SIZE: usize = 17 * 1024;

/// The authority's `struct bio_bio_st`.
///
/// `peer` is a `BIO *`, not a context pointer: the code reads and writes the
/// peer's `init` and `ptr` through it, so the BIO has to be reachable from here.
#[repr(C)]
pub struct BioBioSt {
    /// The other endpoint, or NULL when this one is not paired.
    pub peer: *mut Bio,
    /// Non-zero once the peer's write side has been shut down.
    pub closed: c_int,
    /// Bytes written and not yet read by the peer.
    pub len: usize,
    /// Where those bytes start in `buf`.
    pub offset: usize,
    /// Capacity of `buf`.
    pub size: usize,
    /// The ring buffer.
    pub buf: *mut c_char,
    /// Bytes the peer last asked for and did not get.
    pub request: usize,
}

/// A compiled-in method table. `BIO_s_bio()` returns its address.
static PAIR_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_BIO,
    name: PAIR_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(bio_write),
    bread: Some(bread_conv),
    bread_old: Some(bio_read),
    bputs: Some(bio_puts),
    bgets: None,
    ctrl: Some(bio_ctrl),
    create: Some(bio_new),
    destroy: Some(bio_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_bio(void)`
#[no_mangle]
pub extern "C" fn BIO_s_bio() -> *const BioMethod {
    guard_ffi(ptr::null(), || &PAIR_METHOD)
}

/// This endpoint's context.
///
/// # Safety
/// `bio` must be a live BIO created from this method.
unsafe fn ctx(bio: *mut Bio) -> *mut BioBioSt {
    // SAFETY: the caller guarantees the BIO came from this method.
    unsafe { (*bio).ptr.cast() }
}

/// The peer's context.
///
/// # Safety
/// `b` must be a live context; the peer may be NULL, which yields NULL here.
unsafe fn peer_ctx(b: *mut BioBioSt) -> *mut BioBioSt {
    // SAFETY: `b` is live.
    let peer = unsafe { (*b).peer };
    if peer.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `peer` is a live paired BIO whose `ptr` is a `BioBioSt`.
    unsafe { (*peer).ptr.cast() }
}

/// `bio_new`
///
/// # Safety
/// `bio` must be a live BIO. Note this sets the capacity but **not** `init`, so
/// an unpaired endpoint reads as uninitialised until it is paired.
unsafe extern "C" fn bio_new(bio: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let b: *mut BioBioSt = CRYPTO_zalloc(core::mem::size_of::<BioBioSt>(), ptr::null(), 0).cast();
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a fresh allocation and `bio` is live.
    unsafe {
        (*b).size = DEFAULT_PAIR_SIZE;
        (*bio).ptr = b.cast();
    }
    1
}

/// `bio_free` — tears the pair down first, which clears the peer's `init`.
///
/// # Safety
/// `bio` must be NULL or a live BIO created from this method.
unsafe extern "C" fn bio_free(bio: *mut Bio) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: `bio` is live and holds a `BioBioSt`.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    if unsafe { !(*b).peer.is_null() } {
        // SAFETY: `bio` is live and paired.
        unsafe { bio_destroy_pair(bio) };
    }
    // SAFETY: `buf` is NULL or owned here.
    unsafe {
        CRYPTO_free((*b).buf.cast(), ptr::null(), 0);
        CRYPTO_free(b.cast(), ptr::null(), 0);
    }
    1
}

/// `bio_read` — takes from the **peer's** ring buffer.
///
/// # Safety
/// `bio` must be a live paired BIO; `out` writable for `size_` bytes or NULL.
unsafe extern "C" fn bio_read(bio: *mut Bio, out: *mut c_char, size_: c_int) -> c_int {
    // SAFETY: `bio` is live.
    unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return 0;
    }
    let mut size = size_ as usize;
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is a live paired context and `peer_ctx` tolerates a NULL peer.
    let pb = unsafe { peer_ctx(b) };
    // SAFETY: `pb` is live.
    unsafe { (*pb).request = 0 };

    if out.is_null() || size == 0 {
        return 0;
    }

    // SAFETY: `pb` is live.
    if unsafe { (*pb).len } == 0 {
        // SAFETY: `pb` is live.
        if unsafe { (*pb).closed } != 0 {
            // The writer has closed and nothing is left.
            return 0;
        }
        // SAFETY: `bio` and `pb` are live.
        unsafe {
            super::BIO_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
            (*pb).request = if size <= (*pb).size { size } else { (*pb).size };
        }
        return -1;
    }

    // SAFETY: `pb` is live.
    if unsafe { (*pb).len } < size {
        // SAFETY: `pb` is the peer's context, non-NULL for a paired endpoint.
        size = unsafe { (*pb).len };
    }

    let mut rest = size;
    let mut out = out;
    while rest > 0 {
        // SAFETY: `pb` is live.
        let chunk = unsafe {
            if (*pb).offset + rest <= (*pb).size {
                rest
            } else {
                // The ring buffer wraps.
                (*pb).size - (*pb).offset
            }
        };
        // SAFETY: `pb` holds `offset + chunk <= size` valid bytes and `out` is
        // writable for `chunk`.
        unsafe {
            ptr::copy_nonoverlapping((*pb).buf.add((*pb).offset), out, chunk);
            (*pb).len -= chunk;
            if (*pb).len != 0 {
                (*pb).offset += chunk;
                if (*pb).offset == (*pb).size {
                    (*pb).offset = 0;
                }
                out = out.add(chunk);
            } else {
                // The buffer is empty now, so the offset restarts.
                (*pb).offset = 0;
            }
        }
        rest -= chunk;
    }
    size as c_int
}

/// `bio_write` — appends to this endpoint's own ring buffer.
///
/// # Safety
/// `bio` must be a live paired BIO; `in_` readable for `num_` bytes.
unsafe extern "C" fn bio_write(bio: *mut Bio, in_: *const c_char, num_: c_int) -> c_int {
    // SAFETY: `bio` is live.
    unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 || in_.is_null() || num_ <= 0 {
        return 0;
    }
    let mut num = num_ as usize;
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };

    // SAFETY: `b` is live.
    unsafe { (*b).request = 0 };
    // SAFETY: `b` is live.
    if unsafe { (*b).closed } != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_BIO_286) };
        return -1;
    }
    // SAFETY: `b` is live.
    if unsafe { (*b).len } == unsafe { (*b).size } {
        // SAFETY: `bio` is live.
        unsafe { super::BIO_set_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
        return -1;
    }

    // SAFETY: `b` is live.
    unsafe {
        if num > (*b).size - (*b).len {
            num = (*b).size - (*b).len;
        }
    }

    let mut rest = num;
    let mut in_ = in_;
    while rest > 0 {
        // SAFETY: `b` is live.
        let write_offset = unsafe {
            let mut wo = (*b).offset + (*b).len;
            if wo >= (*b).size {
                wo -= (*b).size;
            }
            wo
        };
        // SAFETY: `b` is live.
        let chunk = unsafe {
            if write_offset + rest <= (*b).size {
                rest
            } else {
                (*b).size - write_offset
            }
        };
        // SAFETY: `b->buf` has room for `chunk` bytes at `write_offset` and `in_`
        // is readable for `chunk`.
        unsafe {
            ptr::copy_nonoverlapping(in_, (*b).buf.add(write_offset), chunk);
            (*b).len += chunk;
            in_ = in_.add(chunk);
        }
        rest -= chunk;
    }
    num as c_int
}

/// `bio_nread0` — the non-copying read preparation.
///
/// # Safety
/// `bio` must be a live paired BIO; `buf` NULL or writable.
unsafe fn bio_nread0(bio: *mut Bio, buf: *mut *mut c_char) -> isize {
    // SAFETY: `bio` is live.
    unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is a live paired context and `peer_ctx` tolerates a NULL peer.
    let pb = unsafe { peer_ctx(b) };
    // SAFETY: `pb` is live.
    unsafe { (*pb).request = 0 };

    // SAFETY: `pb` is live.
    if unsafe { (*pb).len } == 0 {
        // Nothing available: the ordinary read reports 0 or -1 for this case.
        let mut dummy = 0 as c_char;
        // SAFETY: `bio` is live and `dummy` is writable.
        return unsafe { bio_read(bio, &mut dummy, 1) } as isize;
    }

    // SAFETY: `pb` is live.
    let mut num = unsafe { (*pb).len };
    // SAFETY: as above. The non-copying interface never wraps.
    if unsafe { (*pb).size < (*pb).offset + num } {
        // SAFETY: `pb` is the peer's context, non-NULL for a paired endpoint.
        num = unsafe { (*pb).size - (*pb).offset };
    }
    if !buf.is_null() {
        // SAFETY: `buf` is writable; the pointer stays inside the ring buffer.
        unsafe { *buf = (*pb).buf.add((*pb).offset) };
    }
    num as isize
}

/// `bio_nread` — the non-copying read, which also advances.
///
/// # Safety
/// `bio` must be a live paired BIO; `buf` NULL or writable.
unsafe fn bio_nread(bio: *mut Bio, buf: *mut *mut c_char, num_: usize) -> isize {
    let mut num = if num_ > isize::MAX as usize {
        isize::MAX
    } else {
        num_ as isize
    };
    // SAFETY: `bio` is live and paired.
    let available = unsafe { bio_nread0(bio, buf) };
    if num > available {
        num = available;
    }
    if num <= 0 {
        return num;
    }
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is a live paired context and `peer_ctx` tolerates a NULL peer.
    let pb = unsafe { peer_ctx(b) };
    // SAFETY: `pb` is live.
    unsafe {
        (*pb).len -= num as usize;
        if (*pb).len != 0 {
            (*pb).offset += num as usize;
            if (*pb).offset == (*pb).size {
                (*pb).offset = 0;
            }
        } else {
            (*pb).offset = 0;
        }
    }
    num
}

/// `bio_nwrite0` — the non-copying write preparation.
///
/// # Safety
/// `bio` must be a live paired BIO; `buf` NULL or writable.
unsafe fn bio_nwrite0(bio: *mut Bio, buf: *mut *mut c_char) -> isize {
    // SAFETY: `bio` is live.
    unsafe { super::BIO_clear_flags(bio, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    // SAFETY: `bio` is live.
    if unsafe { (*bio).init } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    unsafe { (*b).request = 0 };
    // SAFETY: `b` is live.
    if unsafe { (*b).closed } != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_BIO_361) };
        return -1;
    }
    // SAFETY: `b` is live.
    if unsafe { (*b).len } == unsafe { (*b).size } {
        // SAFETY: `bio` is live.
        unsafe { super::BIO_set_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
        return -1;
    }

    // SAFETY: `b` is live.
    let mut num = unsafe { (*b).size - (*b).len };
    // SAFETY: `b` is live.
    let write_offset = unsafe {
        let mut wo = (*b).offset + (*b).len;
        if wo >= (*b).size {
            wo -= (*b).size;
        }
        wo
    };
    // SAFETY: `b` is this endpoint's live context.
    if write_offset + num > unsafe { (*b).size } {
        // The non-copying interface must never wrap, so that the guarantee
        // `BIO_ctrl_get_write_guarantee` makes is honest.
        // SAFETY: `b` is this endpoint's live context.
        num = unsafe { (*b).size } - write_offset;
    }
    if !buf.is_null() {
        // SAFETY: `buf` is writable and the pointer stays inside the buffer.
        unsafe { *buf = (*b).buf.add(write_offset) };
    }
    num as isize
}

/// `bio_nwrite` — the non-copying write, which also increases the length.
///
/// # Safety
/// `bio` must be a live paired BIO; `buf` NULL or writable.
unsafe fn bio_nwrite(bio: *mut Bio, buf: *mut *mut c_char, num_: usize) -> isize {
    let mut num = if num_ > isize::MAX as usize {
        isize::MAX
    } else {
        num_ as isize
    };
    // SAFETY: `bio` is live and paired.
    let space = unsafe { bio_nwrite0(bio, buf) };
    if num > space {
        num = space;
    }
    if num <= 0 {
        return num;
    }
    // SAFETY: `bio` is live and paired.
    let b = unsafe { ctx(bio) };
    // SAFETY: `b` is live.
    unsafe { (*b).len += num as usize };
    num
}

/// `bio_ctrl`
///
/// # Safety
/// `bio` must be a live BIO created from this method; `ptr` must match the
/// control's contract.
unsafe extern "C" fn bio_ctrl(bio: *mut Bio, cmd: c_int, num: c_long, ptr_: *mut c_void) -> c_long {
    // SAFETY: `bio` is live and holds a `BioBioSt`.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return 0;
    }

    match cmd {
        BIO_C_SET_WRITE_BUF_SIZE => {
            // SAFETY: `b` is live.
            if unsafe { !(*b).peer.is_null() } {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BSS_BIO_426) };
                return 0;
            }
            if num == 0 {
                // SAFETY: as above.
                unsafe { raise_site(&BSS_BIO_429) };
                return 0;
            }
            // SAFETY: `b` is live.
            unsafe {
                let new_size = num as usize;
                if (*b).size != new_size {
                    CRYPTO_free((*b).buf.cast(), ptr::null(), 0);
                    (*b).buf = ptr::null_mut();
                    (*b).size = new_size;
                }
            }
            1
        }
        BIO_C_GET_WRITE_BUF_SIZE => {
            // SAFETY: `b` is live.
            (unsafe { (*b).size }) as c_long
        }
        BIO_C_MAKE_BIO_PAIR => {
            let other = ptr_.cast::<Bio>();
            // SAFETY: the control's contract says `ptr_` is a BIO.
            c_long::from(unsafe { bio_make_pair(bio, other) })
        }
        BIO_C_DESTROY_BIO_PAIR => {
            // SAFETY: `bio` is live.
            unsafe { bio_destroy_pair(bio) };
            1
        }
        BIO_C_GET_WRITE_GUARANTEE => {
            // SAFETY: `b` is live.
            if unsafe { (*b).peer.is_null() || (*b).closed != 0 } {
                0
            } else {
                // SAFETY: `b` is live.
                unsafe { ((*b).size - (*b).len) as c_long }
            }
        }
        BIO_C_GET_READ_REQUEST => {
            // SAFETY: `b` is live.
            (unsafe { (*b).request }) as c_long
        }
        BIO_C_RESET_READ_REQUEST => {
            // SAFETY: `b` is live.
            unsafe { (*b).request = 0 };
            1
        }
        BIO_C_SHUTDOWN_WR => {
            // SAFETY: `b` is live.
            unsafe { (*b).closed = 1 };
            1
        }
        BIO_C_NREAD0 => {
            // SAFETY: `bio` is live and `ptr_` is the caller's out-parameter.
            unsafe { bio_nread0(bio, ptr_.cast()) as c_long }
        }
        BIO_C_NREAD => {
            // SAFETY: `bio` is live and `ptr_` is the caller's out-parameter.
            unsafe { bio_nread(bio, ptr_.cast(), num as usize) as c_long }
        }
        BIO_C_NWRITE0 => {
            // SAFETY: `bio` is live and `ptr_` is the caller's out-parameter.
            unsafe { bio_nwrite0(bio, ptr_.cast()) as c_long }
        }
        BIO_C_NWRITE => {
            // SAFETY: `bio` is live and `ptr_` is the caller's out-parameter.
            unsafe { bio_nwrite(bio, ptr_.cast(), num as usize) as c_long }
        }
        BIO_CTRL_RESET => {
            // SAFETY: `b` is live.
            unsafe {
                if !(*b).buf.is_null() {
                    (*b).len = 0;
                    (*b).offset = 0;
                }
            }
            0
        }
        BIO_CTRL_GET_CLOSE => {
            // SAFETY: `bio` is live.
            (unsafe { (*bio).shutdown }) as c_long
        }
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: `bio` is live.
            unsafe { (*bio).shutdown = num as c_int };
            1
        }
        BIO_CTRL_PENDING => {
            // SAFETY: `b` is live.
            if unsafe { !(*b).peer.is_null() } {
                // SAFETY: `b` is live and paired.
                let pb = unsafe { peer_ctx(b) };
                // SAFETY: `pb` is live.
                (unsafe { (*pb).len }) as c_long
            } else {
                0
            }
        }
        BIO_CTRL_WPENDING => {
            // SAFETY: `b` is live.
            unsafe {
                if !(*b).buf.is_null() {
                    (*b).len as c_long
                } else {
                    0
                }
            }
        }
        BIO_CTRL_DUP => {
            let other = ptr_.cast::<Bio>();
            // SAFETY: the control's contract says `ptr_` is a fresh BIO.
            let ob = unsafe { ctx(other) };
            if !ob.is_null() {
                // SAFETY: `b` and `ob` are live. The authority asserts the target
                // is fresh, so its buffer is NULL and only the size is copied.
                unsafe { (*ob).size = (*b).size };
            }
            1
        }
        BIO_CTRL_FLUSH => 1,
        BIO_CTRL_EOF => {
            // SAFETY: `b` is live.
            if unsafe { !(*b).peer.is_null() } {
                // SAFETY: `b` is live and paired.
                let pb = unsafe { peer_ctx(b) };
                // SAFETY: `pb` is live.
                unsafe { c_long::from((*pb).len == 0 && (*pb).closed != 0) }
            } else {
                1
            }
        }
        _ => 0,
    }
}

/// `bio_puts`
///
/// # Safety
/// `bio` must be a live paired BIO and `str_` NUL-terminated.
unsafe extern "C" fn bio_puts(bio: *mut Bio, str_: *const c_char) -> c_int {
    if str_.is_null() {
        // The authority calls `strlen`, which faults; total by policy.
        return -1;
    }
    // SAFETY: `str_` is NUL-terminated.
    let len = unsafe { super::sys::strlen(str_) };
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bio` is live and `str_` is readable for `len` bytes.
    unsafe { bio_write(bio, str_, len as c_int) }
}

/// `bio_make_pair` — allocates both ring buffers and wires the endpoints.
///
/// # Safety
/// `bio1` and `bio2` must each be a live BIO created from this method.
unsafe fn bio_make_pair(bio1: *mut Bio, bio2: *mut Bio) -> bool {
    if bio1.is_null() || bio2.is_null() {
        return false;
    }
    // SAFETY: both are live.
    let (b1, b2) = unsafe { (ctx(bio1), ctx(bio2)) };

    // SAFETY: `b1`/`b2` are live.
    if unsafe { !(*b1).peer.is_null() || !(*b2).peer.is_null() } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_BIO_617) };
        return false;
    }

    // SAFETY: `b1` is live.
    if unsafe { (*b1).buf.is_null() } {
        // SAFETY: `b1` is live.
        unsafe {
            (*b1).buf = CRYPTO_malloc((*b1).size, ptr::null(), 0).cast();
            if (*b1).buf.is_null() {
                return false;
            }
            (*b1).len = 0;
            (*b1).offset = 0;
        }
    }
    // SAFETY: `b2` is live.
    if unsafe { (*b2).buf.is_null() } {
        // SAFETY: `b2` is live.
        unsafe {
            (*b2).buf = CRYPTO_malloc((*b2).size, ptr::null(), 0).cast();
            if (*b2).buf.is_null() {
                return false;
            }
            (*b2).len = 0;
            (*b2).offset = 0;
        }
    }

    // SAFETY: all pointers are live.
    unsafe {
        (*b1).peer = bio2;
        (*b1).closed = 0;
        (*b1).request = 0;
        (*b2).peer = bio1;
        (*b2).closed = 0;
        (*b2).request = 0;
        (*bio1).init = 1;
        (*bio2).init = 1;
    }
    true
}

/// `bio_destroy_pair` — unpairs both endpoints and clears their buffers.
///
/// # Safety
/// `bio` must be a live BIO created from this method.
unsafe fn bio_destroy_pair(bio: *mut Bio) {
    // SAFETY: `bio` is live.
    let b = unsafe { ctx(bio) };
    if b.is_null() {
        return;
    }
    // SAFETY: `b` is live.
    let peer_bio = unsafe { (*b).peer };
    if peer_bio.is_null() {
        return;
    }
    // SAFETY: `peer_bio` is live and paired back to `bio`.
    let pb = unsafe { peer_ctx(b) };
    // SAFETY: all live.
    unsafe {
        (*pb).peer = ptr::null_mut();
        (*peer_bio).init = 0;
        (*pb).len = 0;
        (*pb).offset = 0;
        (*b).peer = ptr::null_mut();
        (*bio).init = 0;
        (*b).len = 0;
        (*b).offset = 0;
    }
}

/// `int BIO_new_bio_pair(BIO **bio1_p, size_t writebuf1, BIO **bio2_p, size_t writebuf2)`
///
/// The outputs are written **even on failure**, with NULLs, which is why the
/// early error path clears them.
///
/// # Safety
/// `bio1_p` and `bio2_p` must each be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_bio_pair(
    bio1_p: *mut *mut Bio,
    writebuf1: usize,
    bio2_p: *mut *mut Bio,
    writebuf2: usize,
) -> c_int {
    guard_ffi(0, || {
        let mut bio1: *mut Bio = ptr::null_mut();
        let mut bio2: *mut Bio = ptr::null_mut();
        let mut ret = 0;

        'build: {
            if writebuf1 > c_long::MAX as usize || writebuf2 > c_long::MAX as usize {
                break 'build;
            }
            // SAFETY: `BIO_s_bio` returns a static method table.
            bio1 = unsafe { super::BIO_new(BIO_s_bio()) };
            if bio1.is_null() {
                break 'build;
            }
            // SAFETY: as above.
            bio2 = unsafe { super::BIO_new(BIO_s_bio()) };
            if bio2.is_null() {
                break 'build;
            }
            if writebuf1 != 0 {
                // SAFETY: `bio1` is live.
                if unsafe {
                    super::BIO_ctrl(
                        bio1,
                        BIO_C_SET_WRITE_BUF_SIZE,
                        writebuf1 as c_long,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    break 'build;
                }
            }
            if writebuf2 != 0 {
                // SAFETY: `bio2` is live.
                if unsafe {
                    super::BIO_ctrl(
                        bio2,
                        BIO_C_SET_WRITE_BUF_SIZE,
                        writebuf2 as c_long,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    break 'build;
                }
            }
            // SAFETY: both are live.
            if !unsafe { bio_make_pair(bio1, bio2) } {
                break 'build;
            }
            ret = 1;
            break 'build;
        }

        if ret == 0 {
            // SAFETY: each is NULL or owned here.
            unsafe {
                super::BIO_free(bio1);
                bio1 = ptr::null_mut();
                super::BIO_free(bio2);
                bio2 = ptr::null_mut();
            }
        }

        if !bio1_p.is_null() {
            // SAFETY: `bio1_p` is writable per the caller's contract.
            unsafe { *bio1_p = bio1 };
        }
        if !bio2_p.is_null() {
            // SAFETY: `bio2_p` is writable per the caller's contract.
            unsafe { *bio2_p = bio2 };
        }
        ret
    })
}
