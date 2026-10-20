//! Phase 4 — the buffering filter (`BIO_f_buffer`).
//!
//! `BIO_f_buffer` is the filter `PEM_read_bio` and the ASN.1 machinery put in
//! front of an I/O BIO, and its contract is a pair of independent cursors over a
//! pair of fixed allocations. The observable surface is larger than "fewer
//! syscalls":
//!
//! * `BIO_read` first drains what the input buffer already holds, and only when
//!   the *request* is larger than the buffer does it pass reads straight through
//!   to the next BIO;
//! * `BIO_write` fills the output buffer, flushes it, and then writes
//!   whole-buffer-sized chunks directly — so the number of calls the next BIO
//!   sees depends on the sizes, not just the byte count;
//! * `BIO_gets` caps the line at `size - 1` bytes and NUL-terminates, and returns
//!   0 for an empty read;
//! * `BIO_ctrl(BIO_CTRL_EOF)` answers 0 while buffered input remains, even if the
//!   underlying BIO is at end of file;
//! * `BIO_ctrl(BIO_C_SET_BUFF_SIZE)` only reallocates when the requested size
//!   exceeds `DEFAULT_BUFFER_SIZE` **and** differs from the current one, and the
//!   request is directed at the read or the write buffer by whether the `int`
//!   argument is 0 or 1;
//! * `BIO_ctrl(BIO_CTRL_PEEK)` first forces a read into the input buffer, then
//!   copies at most `num` bytes **without consuming them**;
//! * `BIO_CTRL_DUP` copies both buffer sizes onto the target BIO through its own
//!   control, so a duplicated chain keeps the sizes.
//!
//! Everything above is measured by `RT-BIO-FILTER` rather than inferred from the
//! header, and the sizes are observed through `BIO_ctrl(BIO_CTRL_INFO)` and the
//! pending counts rather than by reading the private structure.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

use super::method::{bread_conv, bwrite_conv};
use super::owned::{CtxDestroy, OwnedBlock, OwnedCtx};
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_PEEK,
    BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_WPENDING, BIO_C_DO_STATE_MACHINE,
    BIO_C_GET_BUFF_NUM_LINES, BIO_C_SET_BUFF_READ_DATA, BIO_C_SET_BUFF_SIZE, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_TYPE_BUFFER,
};

/// `DEFAULT_BUFFER_SIZE` in the authority.
pub(crate) const DEFAULT_BUFFER_SIZE: i32 = 4096;

/// The authority's `BIO_F_BUFFER_CTX` (`bio_local.h`).
///
/// `BIO_f_readbuffer` shares the layout, so it lives here and both filters use
/// it; the field order is the authority's, which matters for nothing except
/// keeping the two implementations literally identical.
#[repr(C)]
pub(crate) struct BioBufferCtx {
    /// Input buffer capacity.
    pub ibuf_size: c_int,
    /// Output buffer capacity.
    pub obuf_size: c_int,
    /// Input buffer.
    pub ibuf: *mut c_char,
    /// Bytes currently in the input buffer.
    pub ibuf_len: c_int,
    /// Read offset into the input buffer.
    pub ibuf_off: c_int,
    /// Output buffer.
    pub obuf: *mut c_char,
    /// Bytes currently in the output buffer.
    pub obuf_len: c_int,
    /// Write offset into the output buffer.
    pub obuf_off: c_int,
}

/// The authority's `buffer_free` body *minus* the block release [`OwnedCtx`]'s `Drop` performs.
///
/// `BIO_f_readbuffer` shares this layout but allocates only its input buffer, so its `obuf` stays a
/// NULL `#[repr(C)]` member; `CRYPTO_free(NULL)` is the authority's own no-op, which is why the
/// one destructor serves both filters. The two buffers stay plain `#[repr(C)]` members the
/// authority owns and resizes by hand in `buffer_ctrl`; only the context block's ownership moves
/// to the handle.
// SAFETY: (a) `destroy_body` is the authority's `buffer_free` member body, releasing exactly this
// context's two buffers once (each `OwnedBlock::take` accepts the unset NULL) and never the
// enclosing block, which `OwnedCtx` releases; (b) `BioBufferCtx` is a `#[repr(C)]` record of raw
// pointers and integers, so an all-zero block is a valid `BioBufferCtx` the body is sound on.
unsafe impl CtxDestroy for BioBufferCtx {
    unsafe fn destroy_body(ptr: *mut BioBufferCtx) {
        // SAFETY: `ptr` is a live context per the trait contract; both members are NULL or owned
        // seam blocks whose single release is the block handle's `Drop`.
        unsafe {
            drop(OwnedBlock::take((*ptr).ibuf.cast()));
            drop(OwnedBlock::take((*ptr).obuf.cast()));
        }
    }
}

/// The method name the authority reports for this filter.
const BUFFER_NAME: &[u8] = b"buffer\0";

/// A compiled-in method table. `BIO_f_buffer()` returns its address.
static BUFFER_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_BUFFER,
    name: BUFFER_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(buffer_write),
    bread: Some(bread_conv),
    bread_old: Some(buffer_read),
    bputs: Some(buffer_puts),
    bgets: Some(buffer_gets),
    ctrl: Some(buffer_ctrl),
    create: Some(buffer_new),
    destroy: Some(buffer_free),
    callback_ctrl: Some(buffer_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_buffer(void)`
#[no_mangle]
pub extern "C" fn BIO_f_buffer() -> *const BioMethod {
    guard_ffi(ptr::null(), || &BUFFER_METHOD)
}

/// The context of a live buffer BIO.
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe fn ctx(b: *mut Bio) -> *mut BioBufferCtx {
    // SAFETY: the caller guarantees the BIO was created from this method, whose
    // `create` stores a `BioBufferCtx`.
    unsafe { (*b).ptr.cast() }
}

/// `buffer_new`
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn buffer_new(bi: *mut Bio) -> c_int {
    // SAFETY: `OwnedCtx::zalloc` returns nulled memory of the requested size, or NULL.
    let Some(ctx) = OwnedCtx::<BioBufferCtx>::zalloc() else {
        return 0;
    };
    let c = ctx.as_ptr();
    // SAFETY: `c` is a fresh allocation.
    unsafe {
        (*c).ibuf_size = DEFAULT_BUFFER_SIZE;
        (*c).ibuf = CRYPTO_malloc(DEFAULT_BUFFER_SIZE as usize, ptr::null(), 0).cast();
        if (*c).ibuf.is_null() {
            // The context never escaped; the handle's `Drop` releases it (and the NULL members).
            return 0;
        }
        (*c).obuf_size = DEFAULT_BUFFER_SIZE;
        (*c).obuf = CRYPTO_malloc(DEFAULT_BUFFER_SIZE as usize, ptr::null(), 0).cast();
        if (*c).obuf.is_null() {
            // As above: the context, and the input buffer it now owns, are released by `Drop`.
            return 0;
        }
        (*bi).init = 1;
        (*bi).ptr = c.cast();
        (*bi).flags = 0;
    }
    // The context is now the BIO's; `buffer_free` reclaims it through `OwnedCtx::from_raw`.
    let _ = ctx.into_raw();
    1
}

/// `buffer_free`
///
/// # Safety
/// `a` must be NULL or a live BIO created from this method.
unsafe extern "C" fn buffer_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live and holds a `BioBufferCtx`.
    let c = unsafe { ctx(a) };
    if !c.is_null() {
        // SAFETY: the context is the BIO's own; `Drop` frees the two buffers it owns and then the
        // block, exactly as `buffer_free` frees them by hand.
        unsafe {
            drop(OwnedCtx::<BioBufferCtx>::from_raw(c));
            (*a).ptr = ptr::null_mut();
            (*a).init = 0;
            (*a).flags = 0;
        }
    }
    1
}

/// `buffer_read`
///
/// # Safety
/// `b` must be a live buffer BIO and `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn buffer_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() {
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
        // If there is stuff left over, grab it.
        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        let mut i = unsafe { (*c).ibuf_len };
        if i != 0 {
            if i > outl {
                i = outl;
            }
            // SAFETY: the buffer holds `ibuf_off + ibuf_len` valid bytes and `out`
            // is writable for `i <= outl`.
            unsafe {
                ptr::copy_nonoverlapping((*c).ibuf.add((*c).ibuf_off as usize), out, i as usize);
                (*c).ibuf_off += i;
                (*c).ibuf_len -= i;
            }
            num += i;
            if outl == i {
                return num;
            }
            // SAFETY: `i <= outl`, so the advanced pointers stay in range.
            unsafe { out = out.add(i as usize) };
            outl -= i;
        }

        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        if outl > unsafe { (*c).ibuf_size } {
            // Read straight through to the caller's buffer.
            loop {
                // SAFETY: `b` is live, `out` writable for `outl`, `next` live.
                let r = unsafe { super::BIO_read(next, out.cast(), outl) };
                if r <= 0 {
                    // SAFETY: `b` is live.
                    unsafe { super::BIO_copy_next_retry(b) };
                    if r < 0 {
                        return if num > 0 { num } else { r };
                    }
                    return num;
                }
                num += r;
                if outl == r {
                    return num;
                }
                // SAFETY: `r <= outl` bytes were written.
                unsafe { out = out.add(r as usize) };
                outl -= r;
            }
        }

        // Buffer one read.
        // SAFETY: `next` is live and `ibuf` is writable for `ibuf_size`.
        let r = unsafe { super::BIO_read(next, (*c).ibuf.cast(), (*c).ibuf_size) };
        if r <= 0 {
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
            if r < 0 {
                return if num > 0 { num } else { r };
            }
            return num;
        }
        // SAFETY: `c` is a live context.
        unsafe {
            (*c).ibuf_off = 0;
            (*c).ibuf_len = r;
        }
        // Loop back and re-read through the buffer.
    }
}

/// `buffer_write`
///
/// # Safety
/// `b` must be a live buffer BIO and `in_` readable for `inl` bytes.
unsafe extern "C" fn buffer_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
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
        // SAFETY: `c` is a live context.
        let i = unsafe { (*c).obuf_size - ((*c).obuf_len + (*c).obuf_off) };
        if i >= inl {
            // SAFETY: `obuf` has room for `inl` more bytes and `in_` is readable.
            unsafe {
                ptr::copy_nonoverlapping(
                    in_,
                    (*c).obuf.add(((*c).obuf_off + (*c).obuf_len) as usize),
                    inl as usize,
                );
                (*c).obuf_len += inl;
            }
            return num + inl;
        }

        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        if unsafe { (*c).obuf_len } != 0 {
            if i > 0 {
                // SAFETY: as above, for `i` bytes.
                unsafe {
                    ptr::copy_nonoverlapping(
                        in_,
                        (*c).obuf.add(((*c).obuf_off + (*c).obuf_len) as usize),
                        i as usize,
                    );
                    in_ = in_.add(i as usize);
                    inl -= i;
                    num += i;
                    (*c).obuf_len += i;
                }
            }
            // The buffer is now full; drain it.
            loop {
                // SAFETY: `next` is live; the buffer holds `obuf_len` bytes.
                let w = unsafe {
                    super::BIO_write(
                        next,
                        (*c).obuf.add((*c).obuf_off as usize).cast(),
                        (*c).obuf_len,
                    )
                };
                if w <= 0 {
                    // SAFETY: `b` is live.
                    unsafe { super::BIO_copy_next_retry(b) };
                    if w < 0 {
                        return if num > 0 { num } else { w };
                    }
                    return num;
                }
                // SAFETY: `w <= obuf_len`.
                unsafe {
                    (*c).obuf_off += w;
                    (*c).obuf_len -= w;
                }
                // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
                if unsafe { (*c).obuf_len } == 0 {
                    break;
                }
            }
        }
        // SAFETY: `c` is a live context.
        unsafe { (*c).obuf_off = 0 };

        // Write whole buffers directly while several remain.
        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        while inl >= unsafe { (*c).obuf_size } {
            // SAFETY: `in_` is readable for `inl` bytes.
            let w = unsafe { super::BIO_write(next, in_.cast(), inl) };
            if w <= 0 {
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                if w < 0 {
                    return if num > 0 { num } else { w };
                }
                return num;
            }
            num += w;
            // SAFETY: `w <= inl`.
            unsafe { in_ = in_.add(w as usize) };
            inl -= w;
            if inl == 0 {
                return num;
            }
        }
        // Loop back: the remainder is copied into the buffer.
    }
}

/// `buffer_ctrl`
///
/// # Safety
/// `b` must be a live buffer BIO and `ptr_` must match the control's contract.
unsafe extern "C" fn buffer_ctrl(
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
            // SAFETY: `c` is a live context.
            unsafe {
                (*c).ibuf_off = 0;
                (*c).ibuf_len = 0;
                (*c).obuf_off = 0;
                (*c).obuf_len = 0;
            }
            if next.is_null() {
                return 0;
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
        }
        BIO_CTRL_EOF => {
            // SAFETY: `c` is a live context.
            if unsafe { (*c).ibuf_len } > 0 {
                return 0;
            }
            if next.is_null() {
                return 0;
            }
            // SAFETY: `next` is live.
            ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
        }
        BIO_CTRL_INFO => {
            // SAFETY: `c` is a live context.
            ret = unsafe { (*c).obuf_len } as c_long;
        }
        BIO_C_GET_BUFF_NUM_LINES => {
            ret = 0;
            // SAFETY: `c` is a live context and `ibuf` holds `ibuf_len` bytes
            // from `ibuf_off`.
            unsafe {
                for i in 0..(*c).ibuf_len {
                    if *(*c).ibuf.add(((*c).ibuf_off + i) as usize) == b'\n' as c_char {
                        ret += 1;
                    }
                }
            }
        }
        BIO_CTRL_WPENDING => {
            // SAFETY: `c` is a live context.
            ret = unsafe { (*c).obuf_len } as c_long;
            if ret == 0 {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            }
        }
        BIO_CTRL_PENDING => {
            // SAFETY: `c` is a live context.
            ret = unsafe { (*c).ibuf_len } as c_long;
            if ret == 0 {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            }
        }
        BIO_C_SET_BUFF_READ_DATA => {
            // The length becomes the `int` `ibuf_len` and is also used as a
            // `usize` copy count, so a negative or above-`INT_MAX` request is
            // outside the control's contract. The authority truncates `num`
            // to `int` and hands the truncated value to `memcpy`, which is
            // undefined behaviour for those inputs; refuse them instead.
            if num < 0 || num > c_int::MAX as c_long {
                return 0;
            }
            // A positive count requires the caller's data pointer.
            if num > 0 && ptr_.is_null() {
                return 0;
            }
            // SAFETY: `c` is a live context.
            if num > unsafe { (*c).ibuf_size } as c_long {
                // SAFETY: `num > 0` bytes are requested and fit in `c_int`.
                let p1 = CRYPTO_malloc(num as usize, ptr::null(), 0).cast::<c_char>();
                if p1.is_null() {
                    return 0;
                }
                // SAFETY: `c` is live and `ibuf` is owned here.
                unsafe {
                    CRYPTO_free((*c).ibuf.cast(), ptr::null(), 0);
                    (*c).ibuf = p1;
                }
            }
            // SAFETY: `c` is live; `ptr_` is readable for `num` bytes when
            // `num > 0`. A zero-length copy is skipped so a NULL `ptr_` is
            // never handed to `copy_nonoverlapping`.
            unsafe {
                (*c).ibuf_off = 0;
                (*c).ibuf_len = num as c_int;
                if num > 0 {
                    ptr::copy_nonoverlapping(ptr_.cast::<c_char>(), (*c).ibuf, num as usize);
                }
            }
            ret = 1;
        }
        BIO_C_SET_BUFF_SIZE => {
            // SAFETY: `c` is a live context.
            let ctx_ibuf_size = unsafe { (*c).ibuf_size };
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
            let ctx_obuf_size = unsafe { (*c).obuf_size };
            let (ibs, obs) = if !ptr_.is_null() {
                // SAFETY: the control's contract says `ptr_` is an `int *`.
                let which = unsafe { *(ptr_ as *const c_int) };
                if which == 0 {
                    (num as c_int, ctx_obuf_size)
                } else {
                    (ctx_ibuf_size, num as c_int)
                }
            } else {
                (num as c_int, num as c_int)
            };
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
            let mut p1 = unsafe { (*c).ibuf };
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
            let mut p2 = unsafe { (*c).obuf };
            if ibs > DEFAULT_BUFFER_SIZE && ibs != ctx_ibuf_size {
                if num <= 0 {
                    return 0;
                }
                p1 = CRYPTO_malloc(num as usize, ptr::null(), 0).cast();
                if p1.is_null() {
                    return 0;
                }
            }
            if obs > DEFAULT_BUFFER_SIZE && obs != ctx_obuf_size {
                p2 = CRYPTO_malloc(num as usize, ptr::null(), 0).cast();
                if p2.is_null() {
                    // SAFETY: `p1` was just allocated here when it differs from
                    // the context's own buffer.
                    unsafe {
                        if p1 != (*c).ibuf {
                            CRYPTO_free(p1.cast(), ptr::null(), 0);
                        }
                    }
                    return 0;
                }
            }
            // SAFETY: `c` is live.
            unsafe {
                if (*c).ibuf != p1 {
                    CRYPTO_free((*c).ibuf.cast(), ptr::null(), 0);
                    (*c).ibuf = p1;
                    (*c).ibuf_off = 0;
                    (*c).ibuf_len = 0;
                    (*c).ibuf_size = ibs;
                }
                if (*c).obuf != p2 {
                    CRYPTO_free((*c).obuf.cast(), ptr::null(), 0);
                    (*c).obuf = p2;
                    (*c).obuf_off = 0;
                    (*c).obuf_len = 0;
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
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
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
                // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
                if unsafe { (*c).obuf_len } > 0 {
                    // SAFETY: `next` is live and the buffer holds `obuf_len` bytes.
                    let r = unsafe {
                        super::BIO_write(
                            next,
                            (*c).obuf.add((*c).obuf_off as usize).cast(),
                            (*c).obuf_len,
                        )
                    };
                    // SAFETY: `b` is live.
                    unsafe { super::BIO_copy_next_retry(b) };
                    if r <= 0 {
                        return r as c_long;
                    }
                    // SAFETY: `r <= obuf_len`.
                    unsafe {
                        (*c).obuf_off += r;
                        (*c).obuf_len -= r;
                    }
                } else {
                    // SAFETY: `c` is live.
                    unsafe {
                        (*c).obuf_len = 0;
                        (*c).obuf_off = 0;
                    }
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
            // SAFETY: the control's contract says `ptr_` is a BIO; `c` is live.
            let (ibs, obs) = unsafe { ((*c).ibuf_size, (*c).obuf_size) };
            // `BIO_set_read_buffer_size` / `BIO_set_write_buffer_size`.
            let mut which: c_int = 0;
            // SAFETY: `dbio` is live per the contract; `which` is readable.
            let r1 = unsafe {
                super::BIO_ctrl(
                    dbio,
                    BIO_C_SET_BUFF_SIZE,
                    ibs as c_long,
                    ptr::addr_of_mut!(which).cast(),
                )
            };
            which = 1;
            // SAFETY: as above.
            let r2 = unsafe {
                super::BIO_ctrl(
                    dbio,
                    BIO_C_SET_BUFF_SIZE,
                    obs as c_long,
                    ptr::addr_of_mut!(which).cast(),
                )
            };
            if r1 <= 0 || r2 <= 0 {
                ret = 0;
            }
        }
        BIO_CTRL_PEEK => {
            let fake_buf = [0 as c_char; 1];
            // "Ensure there's stuff in the input buffer": a zero-length read
            // still triggers the buffering path.
            // SAFETY: `b` is live and the fake buffer is a writable 1-byte array.
            unsafe { buffer_read(b, fake_buf.as_ptr().cast_mut(), 0) };
            // SAFETY: `c` is a live context.
            let mut n = num;
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
            if n > unsafe { (*c).ibuf_len } as c_long {
                // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
                n = unsafe { (*c).ibuf_len } as c_long;
            }
            // A negative length is outside the control's contract; the
            // authority's `memcpy` takes it as a huge `size_t`. Refuse it, and
            // skip the zero-length copy so a NULL `ptr_` is legal there.
            if n < 0 {
                return 0;
            }
            if n > 0 {
                if ptr_.is_null() {
                    return 0;
                }
                // SAFETY: `ptr_` is writable for `n` bytes and the buffer holds
                // `ibuf_len >= n` bytes from `ibuf_off`.
                unsafe {
                    ptr::copy_nonoverlapping(
                        (*c).ibuf.add((*c).ibuf_off as usize),
                        ptr_.cast::<c_char>(),
                        n as usize,
                    );
                }
            }
            ret = n;
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

/// `buffer_callback_ctrl`
///
/// # Safety
/// `b` must be a live buffer BIO.
unsafe extern "C" fn buffer_callback_ctrl(
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

/// `buffer_gets`
///
/// # Safety
/// `b` must be a live buffer BIO and `buf` writable for `size` bytes.
unsafe extern "C" fn buffer_gets(b: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `b` is live.
    let (c, next) = unsafe { (ctx(b), (*b).next_bio) };
    if c.is_null() || next.is_null() || buf.is_null() {
        return 0;
    }
    let mut num = 0i32;
    let mut size = size - 1; // reserve space for a '\0'
    let mut out = buf;
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };

    loop {
        // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
        if unsafe { (*c).ibuf_len } > 0 {
            // SAFETY: `ibuf` holds `ibuf_off + ibuf_len` valid bytes, so this stays inside the allocation.
            let p = unsafe { (*c).ibuf.add((*c).ibuf_off as usize) };
            let mut flag = false;
            let mut i = 0i32;
            // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
            while i < unsafe { (*c).ibuf_len } && i < size {
                // SAFETY: `p` holds `ibuf_len` bytes.
                let ch = unsafe { *p.add(i as usize) };
                // SAFETY: `out` is writable for `size + 1` bytes overall.
                unsafe { *out = ch };
                // SAFETY: `out` advances within the caller's `size + 1` byte buffer.
                out = unsafe { out.add(1) };
                i += 1;
                if ch == b'\n' as c_char {
                    flag = true;
                    break;
                }
            }
            num += i;
            size -= i;
            // SAFETY: `c` is live.
            unsafe {
                (*c).ibuf_len -= i;
                (*c).ibuf_off += i;
            }
            if flag || size == 0 {
                // SAFETY: `out` is inside the caller's buffer.
                unsafe { *out = 0 };
                return num;
            }
        } else {
            // SAFETY: `next` is live and `ibuf` is writable for `ibuf_size`.
            let i = unsafe { super::BIO_read(next, (*c).ibuf.cast(), (*c).ibuf_size) };
            if i <= 0 {
                // SAFETY: `b` is live.
                unsafe { super::BIO_copy_next_retry(b) };
                // SAFETY: `out` is inside the caller's buffer.
                unsafe { *out = 0 };
                if i < 0 {
                    return if num > 0 { num } else { i };
                }
                return num;
            }
            // SAFETY: `c` is live.
            unsafe {
                (*c).ibuf_len = i;
                (*c).ibuf_off = 0;
            }
        }
    }
}

/// `buffer_puts`
///
/// # Safety
/// `b` must be a live buffer BIO and `str_` NUL-terminated.
unsafe extern "C" fn buffer_puts(b: *mut Bio, str_: *const c_char) -> c_int {
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
    unsafe { buffer_write(b, str_, len as c_int) }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(BioBufferCtx => zero_state_sweep_bio_buffer_ctx);

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_push, BIO_read};

    fn new_buffer() -> *mut Bio {
        // SAFETY: `BIO_f_buffer` answers the static buffer method.
        let b = unsafe { BIO_new(BIO_f_buffer()) };
        assert!(!b.is_null());
        b
    }

    fn new_buffer_with_mem_next() -> *mut Bio {
        let b = new_buffer();
        // SAFETY: `BIO_s_mem` answers the static memory method.
        let next = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!next.is_null());
        // SAFETY: `b` is live and owns the chain it is pushed onto.
        assert!(!unsafe { BIO_push(b, next) }.is_null());
        b
    }

    #[test]
    fn set_buffer_read_data_accepts_a_bounded_copy() {
        let b = new_buffer_with_mem_next();
        let data = *b"pre!";
        // SAFETY: `b` is live and `data` is readable for four bytes.
        let set = unsafe {
            BIO_ctrl(
                b,
                BIO_C_SET_BUFF_READ_DATA,
                4,
                data.as_ptr().cast_mut().cast(),
            )
        };
        assert_eq!(set, 1);
        let mut out = [0u8; 4];
        // SAFETY: `b` is live and `out` is writable for four bytes.
        let n = unsafe { BIO_read(b, out.as_mut_ptr().cast(), 4) };
        assert_eq!(n, 4);
        assert_eq!(&out, b"pre!");
        // SAFETY: this is the BIO's single release.
        unsafe { BIO_free(b) };
    }

    #[test]
    fn set_buffer_read_data_refuses_a_negative_length() {
        let b = new_buffer();
        let byte = 0u8;
        // SAFETY: `b` is live and the control refuses the negative length
        // without reading the pointer.
        let ret = unsafe {
            BIO_ctrl(
                b,
                BIO_C_SET_BUFF_READ_DATA,
                -1,
                ptr::from_ref(&byte).cast_mut().cast(),
            )
        };
        assert_eq!(ret, 0);
        // SAFETY: this is the BIO's single release.
        unsafe { BIO_free(b) };
    }

    #[test]
    fn set_buffer_read_data_accepts_a_zero_length_null_pointer() {
        let b = new_buffer();
        // SAFETY: `b` is live; a zero count is not copied.
        let ret = unsafe { BIO_ctrl(b, BIO_C_SET_BUFF_READ_DATA, 0, ptr::null_mut()) };
        assert_eq!(ret, 1);
        // SAFETY: this is the BIO's single release.
        unsafe { BIO_free(b) };
    }

    #[test]
    fn peek_refuses_a_negative_length() {
        let b = new_buffer();
        let mut out = [0u8; 1];
        // SAFETY: `b` is live; the control refuses the negative length.
        let ret = unsafe { BIO_ctrl(b, BIO_CTRL_PEEK, -1, out.as_mut_ptr().cast()) };
        assert_eq!(ret, 0);
        // SAFETY: this is the BIO's single release.
        unsafe { BIO_free(b) };
    }
}
