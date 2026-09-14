//! Phase 4 — the caching read filter (`BIO_f_readbuffer`).
//!
//! `BIO_f_readbuffer` adds `BIO_tell` and `BIO_seek` to a source that has
//! neither, by **caching everything it has read** into a growable buffer. Unlike
//! `BIO_f_buffer`, which keeps only what has not been consumed, this one keeps
//! the whole history and moves an offset through it, so:
//!
//! * `BIO_C_FILE_TELL` and `BIO_CTRL_INFO` report `ibuf_off` — the number of
//!   bytes consumed — rather than anything about the underlying BIO;
//! * `BIO_C_FILE_SEEK` and `BIO_CTRL_RESET` accept only a position inside what has
//!   been cached (`0 <= num <= ibuf_off + ibuf_len`) and refuse the rest, because
//!   seeking forward would need data that has not been read;
//! * `BIO_CTRL_EOF` is 0 while cached bytes remain, and reports **1** (not the
//!   next BIO's answer) when there is no next BIO;
//! * the growable buffers are sized in whole `DEFAULT_BUFFER_SIZE` blocks, and the
//!   input block is rounded up to include the offset;
//! * `BIO_gets` reads **one byte at a time** from the next BIO, deliberately, so
//!   that it works on a binary stream containing NUL and on a re-opened `stdin`.
//!
//! `RT-BIO-FILTER` observes the tell/seek/EOF relations around cached reads.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc, CRYPTO_zalloc};

use super::bf_buff::{BioBufferCtx, DEFAULT_BUFFER_SIZE};
use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_PENDING,
    BIO_CTRL_RESET, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY,
    BIO_TYPE_BUFFER,
};

/// The method name the authority reports for this filter.
const READBUFFER_NAME: &[u8] = b"readbuffer\0";

/// A compiled-in method table. `BIO_f_readbuffer()` returns its address.
///
/// The type is `BIO_TYPE_BUFFER`, as in the authority — the readbuffer shares the
/// buffer's type rather than having one of its own.
static READBUFFER_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_BUFFER,
    name: READBUFFER_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(readbuffer_write),
    bread: Some(bread_conv),
    bread_old: Some(readbuffer_read),
    bputs: Some(readbuffer_puts),
    bgets: Some(readbuffer_gets),
    ctrl: Some(readbuffer_ctrl),
    create: Some(readbuffer_new),
    destroy: Some(readbuffer_free),
    callback_ctrl: Some(readbuffer_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_readbuffer(void)`
#[no_mangle]
pub extern "C" fn BIO_f_readbuffer() -> *const BioMethod {
    guard_ffi(ptr::null(), || &READBUFFER_METHOD)
}

/// The context of a live readbuffer BIO.
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe fn ctx(b: *mut Bio) -> *mut BioBufferCtx {
    // SAFETY: the caller guarantees the BIO came from this method.
    unsafe { (*b).ptr.cast() }
}

/// `readbuffer_new` — note the input buffer is **zeroed**, unlike the buffer
/// filter's.
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn readbuffer_new(bi: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let c: *mut BioBufferCtx =
        CRYPTO_zalloc(core::mem::size_of::<BioBufferCtx>(), ptr::null(), 0).cast();
    if c.is_null() {
        return 0;
    }
    // SAFETY: `c` is a fresh allocation.
    unsafe {
        (*c).ibuf_size = DEFAULT_BUFFER_SIZE;
        (*c).ibuf = CRYPTO_zalloc(DEFAULT_BUFFER_SIZE as usize, ptr::null(), 0).cast();
        if (*c).ibuf.is_null() {
            CRYPTO_free(c.cast(), ptr::null(), 0);
            return 0;
        }
        (*bi).init = 1;
        (*bi).ptr = c.cast();
        (*bi).flags = 0;
    }
    1
}

/// `readbuffer_free`
///
/// # Safety
/// `a` must be NULL or a live BIO created from this method.
unsafe extern "C" fn readbuffer_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live and holds a `BioBufferCtx`.
    let c = unsafe { ctx(a) };
    if !c.is_null() {
        // SAFETY: the buffer was allocated by `readbuffer_new`.
        unsafe {
            CRYPTO_free((*c).ibuf.cast(), ptr::null(), 0);
            CRYPTO_free(c.cast(), ptr::null(), 0);
            (*a).ptr = ptr::null_mut();
            (*a).init = 0;
            (*a).flags = 0;
        }
    }
    1
}

/// `readbuffer_resize` — round the requirement up to whole blocks, counting the
/// bytes already consumed.
///
/// # Safety
/// `c` must be a live readbuffer context.
unsafe fn readbuffer_resize(c: *mut BioBufferCtx, sz: c_int) -> bool {
    // SAFETY: `c` is live.
    let mut sz = unsafe { (*c).ibuf_off } + DEFAULT_BUFFER_SIZE - 1 + sz;
    sz = DEFAULT_BUFFER_SIZE * (sz / DEFAULT_BUFFER_SIZE);
    // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
    if sz > unsafe { (*c).ibuf_size } {
        // SAFETY: `ibuf` is owned here and `sz > 0`.
        let tmp = unsafe { CRYPTO_realloc((*c).ibuf.cast(), sz as usize, ptr::null(), 0) }
            .cast::<c_char>();
        if tmp.is_null() {
            return false;
        }
        // SAFETY: `c` is live.
        unsafe {
            (*c).ibuf = tmp;
            (*c).ibuf_size = sz;
        }
    }
    true
}

/// `readbuffer_read`
///
/// # Safety
/// `b` must be a live readbuffer BIO and `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn readbuffer_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() || outl == 0 {
        return 0;
    }
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    if c.is_null() || next.is_null() {
        return 0;
    }
    let mut num = 0i32;
    let mut out = out;
    let mut outl = outl;
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };

    loop {
        // Drain what is already cached.
        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        let mut i = unsafe { (*c).ibuf_len };
        if i != 0 {
            if i > outl {
                i = outl;
            }
            // SAFETY: the cache holds `ibuf_off + ibuf_len` bytes and `out` is
            // writable for `i <= outl`.
            unsafe {
                ptr::copy_nonoverlapping((*c).ibuf.add((*c).ibuf_off as usize), out, i as usize);
                (*c).ibuf_off += i;
                (*c).ibuf_len -= i;
            }
            num += i;
            if outl == i {
                return num;
            }
            // SAFETY: `i <= outl`.
            unsafe { out = out.add(i as usize) };
            outl -= i;
        }

        // SAFETY: `c` is live.
        if !(unsafe { readbuffer_resize(c, outl) }) {
            return 0;
        }

        // Buffer one read directly at the cache's tail, so the cache only grows
        // past what has been consumed.
        // SAFETY: `next` is live and the cache has room for `outl` more bytes.
        let r =
            unsafe { super::BIO_read(next, (*c).ibuf.add((*c).ibuf_off as usize).cast(), outl) };
        if r <= 0 {
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
            if r < 0 {
                return if num > 0 { num } else { r };
            }
            return num;
        }
        // SAFETY: `c` is live.
        unsafe { (*c).ibuf_len = r };
    }
}

/// `readbuffer_write` — this filter is read-only and always reports 0.
#[allow(clippy::missing_safety_doc)]
unsafe extern "C" fn readbuffer_write(_b: *mut Bio, _in: *const c_char, _inl: c_int) -> c_int {
    0
}

/// `readbuffer_puts` — always reports 0, like the write.
#[allow(clippy::missing_safety_doc)]
unsafe extern "C" fn readbuffer_puts(_b: *mut Bio, _str_: *const c_char) -> c_int {
    0
}

/// `readbuffer_ctrl`
///
/// # Safety
/// `b` must be a live readbuffer BIO and `ptr_` must match the control's contract.
unsafe extern "C" fn readbuffer_ctrl(
    b: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    let mut ret: c_long = 1;

    match cmd {
        BIO_CTRL_EOF => {
            // SAFETY: `c` is live.
            if unsafe { (*c).ibuf_len } > 0 {
                return 0;
            }
            if next.is_null() {
                return 1;
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
        }
        BIO_C_FILE_SEEK | BIO_CTRL_RESET => {
            // SAFETY: `c` is live.
            let sz = unsafe { (*c).ibuf_off + (*c).ibuf_len } as c_long;
            if num < 0 || num > sz {
                return 0;
            }
            // SAFETY: `c` is live.
            unsafe {
                (*c).ibuf_off = num as c_int;
                (*c).ibuf_len = (sz - num) as c_int;
            }
        }
        BIO_C_FILE_TELL | BIO_CTRL_INFO => {
            // SAFETY: `c` is live.
            ret = unsafe { (*c).ibuf_off } as c_long;
        }
        BIO_CTRL_PENDING => {
            // SAFETY: `c` is live.
            ret = unsafe { (*c).ibuf_len } as c_long;
            if ret == 0 {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            }
        }
        BIO_CTRL_DUP | BIO_CTRL_FLUSH => {
            ret = 1;
        }
        _ => {
            ret = 0;
        }
    }
    ret
}

/// `readbuffer_callback_ctrl`
///
/// # Safety
/// `b` must be a live readbuffer BIO.
unsafe extern "C" fn readbuffer_callback_ctrl(
    b: *mut Bio,
    cmd: c_int,
    fp: Option<super::BioInfoCb>,
) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live.
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// `readbuffer_gets`
///
/// The next-BIO read is one byte at a time on purpose; the authority's comment
/// says why (NUL bytes in a binary stream, and a re-opened `stdin`).
///
/// # Safety
/// `b` must be a live readbuffer BIO and `buf` writable for `size` bytes.
unsafe extern "C" fn readbuffer_gets(b: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    if buf.is_null() || size == 0 {
        return 0;
    }
    let size = size - 1;
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    if c.is_null() || next.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };

    let mut num = 0i32;
    let mut size = size;
    let mut out = buf;

    // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
    if unsafe { (*c).ibuf_len } > 0 {
        // SAFETY: `ibuf` holds `ibuf_off + ibuf_len` valid bytes, so this stays inside the allocation.
        let p = unsafe { (*c).ibuf.add((*c).ibuf_off as usize) };
        let mut found_newline = false;
        let mut num_chars = 0i32;
        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        while num_chars < unsafe { (*c).ibuf_len } && num_chars < size {
            // SAFETY: `p` holds `ibuf_len` bytes.
            let ch = unsafe { *p.add(num_chars as usize) };
            // SAFETY: `out` is writable.
            unsafe { *out = ch };
            // SAFETY: `out` advances within the caller's `size + 1` byte buffer.
            out = unsafe { out.add(1) };
            num_chars += 1;
            if ch == b'\n' as c_char {
                found_newline = true;
                break;
            }
        }
        num += num_chars;
        size -= num_chars;
        // SAFETY: `c` is live.
        unsafe {
            (*c).ibuf_len -= num_chars;
            (*c).ibuf_off += num_chars;
        }
        if found_newline || size == 0 {
            // SAFETY: `out` is inside the caller's buffer.
            unsafe { *out = 0 };
            return num;
        }
    }

    // SAFETY: `c` is live.
    if !(unsafe { readbuffer_resize(c, 1 + size) }) {
        return 0;
    }

    // SAFETY: `c` is live.
    let mut p = unsafe { (*c).ibuf.add((*c).ibuf_off as usize) };
    for _ in 0..size {
        // SAFETY: `next` is live and `p` is writable for one byte.
        let j = unsafe { super::BIO_read(next, p.cast(), 1) };
        if j <= 0 {
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
            // SAFETY: `out` is inside the caller's buffer.
            unsafe { *out = 0 };
            return if num > 0 { num } else { j };
        }
        // SAFETY: `p` holds the byte just read and `out` is writable.
        unsafe {
            let ch = *p;
            *out = ch;
            out = out.add(1);
            (*c).ibuf_off += 1;
        }
        num += 1;
        // SAFETY: `p` was one byte inside the cache.
        let ch = unsafe { *p };
        if ch == b'\n' as c_char {
            break;
        }
        // SAFETY: `p` advances within the cache, which was resized for this loop.
        p = unsafe { p.add(1) };
    }
    // SAFETY: `out` is inside the caller's buffer.
    unsafe { *out = 0 };
    num
}
