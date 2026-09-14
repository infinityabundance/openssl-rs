//! Phase 4 — the line-buffering filter (`BIO_f_linebuffer`).
//!
//! `BIO_f_linebuffer` holds output until a newline appears, so a caller can
//! produce a line at a time without a syscall per fragment. On the read side it
//! is transparent — it forwards and copies the retry state — so all of its
//! behaviour is on the write path, and the parts that are observable are the
//! ones a "buffer until newline" description would not predict:
//!
//! * a fragment that fills the buffer is flushed even without a newline, so a
//!   write of more than `obuf_size` bytes never overflows;
//! * after the loop, any remainder that has no newline is copied into the buffer
//!   **without flushing**, which is what makes the newline boundary visible
//!   through `BIO_ctrl(BIO_CTRL_INFO)` and `BIO_CTRL_WPENDING`;
//! * a failed flush **restores `obuf_len` to its pre-flush value**, so the data
//!   is not lost when the next BIO reports a retry;
//! * `BIO_C_SET_BUFF_SIZE` copies the retained bytes into the new allocation and
//!   truncates `obuf_len` to the new size.
//!
//! `RT-BIO-FILTER` observes the retained-byte counts around each of those.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_RESET, BIO_CTRL_WPENDING,
    BIO_C_DO_STATE_MACHINE, BIO_C_SET_BUFF_SIZE, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY,
    BIO_TYPE_LINEBUFFER,
};

/// `DEFAULT_LINEBUFFER_SIZE` in the authority.
const DEFAULT_LINEBUFFER_SIZE: i32 = 1024 * 10;

/// The authority's `BIO_LINEBUFFER_CTX`.
#[repr(C)]
struct BioLineBufferCtx {
    /// The output buffer.
    obuf: *mut c_char,
    /// Capacity.
    obuf_size: c_int,
    /// Retained bytes.
    obuf_len: c_int,
}

/// The method name the authority reports for this filter.
const LINEBUFFER_NAME: &[u8] = b"linebuffer\0";

/// A compiled-in method table. `BIO_f_linebuffer()` returns its address.
static LINEBUFFER_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_LINEBUFFER,
    name: LINEBUFFER_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(linebuffer_write),
    bread: Some(bread_conv),
    bread_old: Some(linebuffer_read),
    bputs: Some(linebuffer_puts),
    bgets: Some(linebuffer_gets),
    ctrl: Some(linebuffer_ctrl),
    create: Some(linebuffer_new),
    destroy: Some(linebuffer_free),
    callback_ctrl: Some(linebuffer_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_linebuffer(void)`
#[no_mangle]
pub extern "C" fn BIO_f_linebuffer() -> *const BioMethod {
    guard_ffi(ptr::null(), || &LINEBUFFER_METHOD)
}

/// The context of a live line-buffer BIO.
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe fn ctx(b: *mut Bio) -> *mut BioLineBufferCtx {
    // SAFETY: the caller guarantees the BIO came from this method.
    unsafe { (*b).ptr.cast() }
}

/// `linebuffer_new`
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn linebuffer_new(bi: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_malloc` returns a fresh allocation of the requested size.
    let c = CRYPTO_malloc(core::mem::size_of::<BioLineBufferCtx>(), ptr::null(), 0)
        .cast::<BioLineBufferCtx>();
    if c.is_null() {
        return 0;
    }
    // SAFETY: `c` is a fresh allocation.
    unsafe {
        (*c).obuf = CRYPTO_malloc(DEFAULT_LINEBUFFER_SIZE as usize, ptr::null(), 0).cast();
        if (*c).obuf.is_null() {
            CRYPTO_free(c.cast(), ptr::null(), 0);
            return 0;
        }
        (*c).obuf_size = DEFAULT_LINEBUFFER_SIZE;
        (*c).obuf_len = 0;
        (*bi).init = 1;
        (*bi).ptr = c.cast();
        (*bi).flags = 0;
    }
    1
}

/// `linebuffer_free`
///
/// # Safety
/// `a` must be NULL or a live BIO created from this method.
unsafe extern "C" fn linebuffer_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live and holds a `BioLineBufferCtx`.
    let c = unsafe { ctx(a) };
    if !c.is_null() {
        // SAFETY: the buffer was allocated by `linebuffer_new`.
        unsafe {
            CRYPTO_free((*c).obuf.cast(), ptr::null(), 0);
            CRYPTO_free(c.cast(), ptr::null(), 0);
            (*a).ptr = ptr::null_mut();
            (*a).init = 0;
            (*a).flags = 0;
        }
    }
    1
}

/// `linebuffer_read` — transparent, but the retry state is still cleared and
/// re-copied, so the flags a caller reads are the next BIO's.
///
/// # Safety
/// `b` must be a live line-buffer BIO and `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn linebuffer_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live and `out` is writable for `outl` bytes.
    let ret = unsafe { super::BIO_read(next, out.cast(), outl) };
    // SAFETY: `b` is live.
    unsafe {
        super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        super::BIO_copy_next_retry(b);
    }
    ret
}

/// `linebuffer_write`
///
/// The authority tracks a single pointer `p` that marks the end of the segment it
/// is currently working on (just past a newline, or the end of the input), and the
/// quantities that drive the two loops are `p - in` and the free space. Both
/// change as `in` advances, so this reproduces the two as `pdist` rather than
/// re-scanning — a re-scan would give the same first answer and the wrong second.
///
/// # Safety
/// `b` must be a live line-buffer BIO and `in_` readable for `inl` bytes.
unsafe extern "C" fn linebuffer_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    if in_.is_null() || inl <= 0 {
        return 0;
    }
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    if c.is_null() || next.is_null() {
        return 0;
    }
    let mut num = 0i32;
    let mut in_ = in_;
    let mut inl = inl;
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };

    loop {
        // Find the segment that ends at the next newline (inclusive), or at the
        // end of the input.
        let mut pdist = inl;
        let mut found_nl = false;
        {
            let mut i = 0i32;
            while i < inl {
                // SAFETY: `in_` is readable for `inl` bytes.
                if unsafe { *in_.add(i as usize) } == b'\n' as c_char {
                    pdist = i + 1;
                    found_nl = true;
                    break;
                }
                i += 1;
            }
        }

        // While there is retained text and either a newline was found or the
        // segment no longer fits, concatenate and flush.
        while (found_nl || pdist > unsafe { (*c).obuf_size } - unsafe { (*c).obuf_len })
            && unsafe { (*c).obuf_len } > 0
        {
            let orig_olen = unsafe { (*c).obuf_len };
            let llen = pdist;
            let i = unsafe { (*c).obuf_size - (*c).obuf_len };
            if llen > 0 {
                if i >= llen {
                    // SAFETY: the buffer has room for `llen` bytes and `in_` is
                    // readable for at least that many.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            in_,
                            (*c).obuf.add((*c).obuf_len as usize),
                            llen as usize,
                        );
                        (*c).obuf_len += llen;
                        in_ = in_.add(llen as usize);
                    }
                    inl -= llen;
                    num += llen;
                    // `in = p` in the authority, so the remaining distance is 0.
                    pdist = 0;
                } else {
                    // SAFETY: the buffer has room for `i` bytes.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            in_,
                            (*c).obuf.add((*c).obuf_len as usize),
                            i as usize,
                        );
                        (*c).obuf_len += i;
                        in_ = in_.add(i as usize);
                    }
                    inl -= i;
                    num += i;
                    pdist -= i;
                }
            }
            // SAFETY: `next` is live and the buffer holds `obuf_len` bytes.
            let w = unsafe { super::BIO_write(next, (*c).obuf.cast(), (*c).obuf_len) };
            if w <= 0 {
                // The authority restores the retained length before reporting, so
                // the concatenated bytes are not lost to a retry.
                // SAFETY: `c` is live.
                unsafe { (*c).obuf_len = orig_olen };
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                if w < 0 {
                    return if num > 0 { num } else { w };
                }
                return num;
            }
            // SAFETY: `c` is live.
            unsafe {
                if w < (*c).obuf_len {
                    let remaining = (*c).obuf_len - w;
                    ptr::copy((*c).obuf.add(w as usize), (*c).obuf, remaining as usize);
                }
                (*c).obuf_len -= w;
            }
        }

        // With nothing retained, write the segment straight through when a
        // newline was found or it exceeds one buffer.
        if (found_nl || pdist > unsafe { (*c).obuf_size }) && pdist > 0 {
            // SAFETY: `next` is live and `in_` is readable for `pdist` bytes.
            let w = unsafe { super::BIO_write(next, in_.cast(), pdist) };
            if w <= 0 {
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                if w < 0 {
                    return if num > 0 { num } else { w };
                }
                return num;
            }
            num += w;
            // SAFETY: `w <= pdist <= inl`.
            unsafe { in_ = in_.add(w as usize) };
            inl -= w;
            // No adjustment to `pdist` is needed: the next iteration of the outer
            // loop rescans and recomputes it, exactly as the authority's `p` is
            // recomputed from the advanced `in` pointer.
        }

        if !found_nl || inl <= 0 {
            break;
        }
    }

    // Retain the remainder: text with no newline, kept for the next call.
    while inl > 0 {
        // SAFETY: `c` is a live context.
        let avail = (unsafe { (*c).obuf_size } - unsafe { (*c).obuf_len }) as usize;
        if avail == 0 {
            // Flush to make room.
            // SAFETY: `next` is live and the buffer holds `obuf_len` bytes.
            let w = unsafe { super::BIO_write(next, (*c).obuf.cast(), (*c).obuf_len) };
            if w <= 0 {
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                return if num > 0 { num } else { w };
            }
            // SAFETY: `c` is live.
            unsafe {
                if w < (*c).obuf_len {
                    let remaining = (*c).obuf_len - w;
                    ptr::copy((*c).obuf.add(w as usize), (*c).obuf, remaining as usize);
                }
                (*c).obuf_len -= w;
            }
            continue;
        }
        let to_copy = if inl as usize > avail {
            avail
        } else {
            inl as usize
        };
        // SAFETY: `avail` bytes are free in the buffer and `in_` is readable for
        // `to_copy <= inl`.
        unsafe {
            ptr::copy_nonoverlapping(in_, (*c).obuf.add((*c).obuf_len as usize), to_copy);
            (*c).obuf_len += to_copy as c_int;
            in_ = in_.add(to_copy);
        }
        inl -= to_copy as c_int;
        num += to_copy as c_int;
    }

    num
}

/// `linebuffer_ctrl`
///
/// # Safety
/// `b` must be a live line-buffer BIO and `ptr_` must match the control's contract.
unsafe extern "C" fn linebuffer_ctrl(
    b: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    let mut ret: c_long = 1;

    match cmd {
        BIO_CTRL_RESET => {
            // SAFETY: `c` is live.
            unsafe { (*c).obuf_len = 0 };
            if next.is_null() {
                return 0;
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
        }
        BIO_CTRL_INFO => {
            // SAFETY: `c` is live.
            ret = unsafe { (*c).obuf_len } as c_long;
        }
        BIO_CTRL_WPENDING => {
            // SAFETY: `c` is live.
            ret = unsafe { (*c).obuf_len } as c_long;
            if ret == 0 {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            }
        }
        BIO_C_SET_BUFF_SIZE => {
            if num > c_int::MAX as c_long {
                return 0;
            }
            let obs = num as c_int;
            // SAFETY: `c` is live.
            let current = unsafe { (*c).obuf };
            let mut p = current;
            if obs > DEFAULT_LINEBUFFER_SIZE && obs != unsafe { (*c).obuf_size } {
                p = CRYPTO_malloc(obs as usize, ptr::null(), 0).cast();
                if p.is_null() {
                    return 0;
                }
            }
            // SAFETY: `c` is live.
            unsafe {
                if (*c).obuf != p {
                    if (*c).obuf_len > obs {
                        (*c).obuf_len = obs;
                    }
                    ptr::copy_nonoverlapping((*c).obuf, p, (*c).obuf_len as usize);
                    CRYPTO_free((*c).obuf.cast(), ptr::null(), 0);
                    (*c).obuf = p;
                    (*c).obuf_size = obs;
                }
            }
        }
        BIO_C_DO_STATE_MACHINE => {
            if next.is_null() {
                return 0;
            }
            // SAFETY: `b` is live.
            unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
        }
        BIO_CTRL_FLUSH => {
            if next.is_null() {
                return 0;
            }
            if unsafe { (*c).obuf_len } <= 0 {
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                return ret;
            }
            loop {
                // SAFETY: `b` is live.
                unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
                if unsafe { (*c).obuf_len } > 0 {
                    // SAFETY: `next` is live and the buffer holds `obuf_len` bytes.
                    let r = unsafe { super::BIO_write(next, (*c).obuf.cast(), (*c).obuf_len) };
                    // SAFETY: `b` is live.
                    unsafe { super::BIO_copy_next_retry(b) };
                    if r <= 0 {
                        return r as c_long;
                    }
                    // SAFETY: `c` is live.
                    unsafe {
                        if r < (*c).obuf_len {
                            let remaining = (*c).obuf_len - r;
                            ptr::copy((*c).obuf.add(r as usize), (*c).obuf, remaining as usize);
                        }
                        (*c).obuf_len -= r;
                    }
                } else {
                    // SAFETY: `c` is live.
                    unsafe { (*c).obuf_len = 0 };
                    break;
                }
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
        }
        BIO_CTRL_DUP => {
            let dbio = ptr_.cast::<Bio>();
            // SAFETY: `c` is live.
            let obs = unsafe { (*c).obuf_size };
            let mut which: c_int = 1;
            // SAFETY: `dbio` is live per the control's contract.
            let r = unsafe {
                super::BIO_ctrl(
                    dbio,
                    BIO_C_SET_BUFF_SIZE,
                    obs as c_long,
                    ptr::addr_of_mut!(which).cast(),
                )
            };
            if r <= 0 {
                ret = 0;
            }
        }
        _ => {
            if next.is_null() {
                return 0;
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
        }
    }
    ret
}

/// `linebuffer_callback_ctrl`
///
/// # Safety
/// `b` must be a live line-buffer BIO.
unsafe extern "C" fn linebuffer_callback_ctrl(
    b: *mut Bio,
    cmd: c_int,
    fp: *mut super::BioInfoCb,
) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live.
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// `linebuffer_gets`
///
/// # Safety
/// `b` must be a live line-buffer BIO and `buf` writable for `size` bytes.
unsafe extern "C" fn linebuffer_gets(b: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live and `buf` is writable for `size` bytes.
    unsafe { super::BIO_gets(next, buf, size) }
}

/// `linebuffer_puts`
///
/// # Safety
/// `b` must be a live line-buffer BIO and `str_` NUL-terminated.
unsafe extern "C" fn linebuffer_puts(b: *mut Bio, str_: *const c_char) -> c_int {
    if str_.is_null() {
        // The authority calls `strlen`, which faults; total by policy.
        return -1;
    }
    // SAFETY: `str_` is NUL-terminated.
    let len = unsafe { super::sys::strlen(str_) };
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `b` is live and `str_` is readable for `len` bytes.
    unsafe { linebuffer_write(b, str_, len as c_int) }
}
