//! Phase 5 — the ASN.1 filter BIO bridge: `crypto/asn1/bio_asn1.c` and
//! `bio_ndef.c`.
//!
//! This is the subphase-5.8 pair, and the two files are one mechanism seen from
//! two sides. `bio_asn1.c` is a *filter* BIO that wraps everything written through
//! it in a single ASN.1 primitive header — by default an `OCTET STRING` — with
//! optional prefix and suffix byte runs either side. `bio_ndef.c` is the caller that
//! uses those runs: it installs a prefix and a suffix that encode an `ASN1_ITEM`
//! around the stream in two passes, so a structure can be written out without
//! holding its content in memory.
//!
//! ## The state machine, and why it is a state machine
//!
//! `asn1_bio_write` is not a wrapper over one `BIO_write`. It is a loop over seven
//! states because each write may have to emit a prefix, then a header, then some
//! content, then more content on the next call, then a suffix at flush — and
//! because every one of those `BIO_write`s can return short. The `bufpos`/`buflen`
//! pair is the partial-write cursor for the *header*, which is the only piece that
//! is not the caller's buffer: a header that half-writes must resume inside the
//! header, not re-emit it.
//!
//! The `copylen` field is the other half: the header declares a length, so the
//! filter must pass through exactly that many content bytes before it can start
//! another header. A caller that writes 100 bytes into a filter configured for a
//! 40-byte object gets a 40-byte object followed by a fresh header — not an error.
//! That is observable and is courted.
//!
//! ## `ex_arg` is a `void *` the caller owns
//!
//! `BIO_C_SET_EX_ARG` stores it and `BIO_C_GET_EX_ARG` reads it back; the filter
//! never dereferences it and never frees it. The prefix and suffix callbacks are
//! handed `&ctx->ex_arg`, which is why their `parg` is an `NDEF_SUPPORT **` rather
//! than an `NDEF_SUPPORT *`: the argument is the *address of the slot*, so the
//! callback may either read the pointer or replace it. `ndef_suffix_free` does the
//! latter, which is how the support block is released exactly once.
//!
//! ## What is deliberately not reproduced
//!
//! `asn1_bio_write` returns `-1` from two paths that the authority's own
//! `ossl_assert` guards — a header larger than the 20-byte buffer. The header can
//! only exceed the buffer for a content length above `2^14 - 1`, because the
//! header's own size is `ASN1_object_size`'s and the buffer is sized for the
//! largest short-form tag plus length. Nothing here reaches that state; the check is
//! reproduced as the same assertion, so a caller that somehow did would see the
//! process stop rather than a truncated object.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::der::{ASN1_object_size, ASN1_put_object};
use crate::asn1::i2d::ASN1_item_ndef_i2d;
use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::bio::method::{bread_conv, bwrite_conv};
use crate::runtime::bio::{
    BIO_callback_ctrl, BIO_clear_flags, BIO_copy_next_retry, BIO_ctrl, BIO_free, BIO_get_data,
    BIO_gets, BIO_new, BIO_next, BIO_pop, BIO_push, BIO_read, BIO_set_data, BIO_set_init,
    BIO_write,
};
use crate::runtime::bio::{
    Bio, BioInfoCb, BioMethod, BIO_CTRL_FLUSH, BIO_C_GET_EX_ARG, BIO_C_GET_PREFIX,
    BIO_C_GET_SUFFIX, BIO_C_SET_EX_ARG, BIO_C_SET_PREFIX, BIO_C_SET_SUFFIX, BIO_TYPE_ASN1,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_strnlen;

/// The authority translation unit for the filter BIO.
pub(crate) const FILTER_FILE: &core::ffi::CStr = c"crypto/asn1/bio_asn1.c";
/// The authority translation unit for the NDEF bridge.
pub(crate) const NDEF_FILE: &core::ffi::CStr = c"crypto/asn1/bio_ndef.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `DEFAULT_ASN1_BUF_SIZE` — "large enough for biggest tag+length".
const DEFAULT_ASN1_BUF_SIZE: c_int = 20;

/// `BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY` — what `BIO_clear_retry_flags` clears.
const BIO_FLAGS_RWS: c_int = 0x01 | 0x04;
/// `BIO_FLAGS_SHOULD_RETRY`.
const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;

/// `asn1_bio_state_t`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
enum Asn1BioState {
    Start = 0,
    PreCopy,
    Header,
    HeaderCopy,
    DataCopy,
    PostCopy,
    Done,
}

/// `asn1_ps_func` — `int (*)(BIO *, unsigned char **, int *, void *)`.
///
/// The `void *` is the address of the context's `ex_arg` slot, so a callback may
/// read or replace it; see the module documentation.
pub type Asn1PsFunc =
    unsafe extern "C" fn(*mut Bio, *mut *mut u8, *mut c_int, *mut c_void) -> c_int;

/// `BIO_ASN1_EX_FUNCS` — the pair the two setters and the two getters move.
#[repr(C)]
pub struct BioAsn1ExFuncs {
    /// The callback.
    pub ex_func: Option<Asn1PsFunc>,
    /// Its cleanup, called once the data it produced has been written.
    pub ex_free_func: Option<Asn1PsFunc>,
}

/// `BIO_ASN1_BUF_CTX` — one filter BIO's whole state.
struct BioAsn1BufCtx {
    state: Asn1BioState,
    buf: *mut u8,
    bufsize: c_int,
    bufpos: c_int,
    buflen: c_int,
    copylen: c_int,
    asn1_class: c_int,
    asn1_tag: c_int,
    prefix: Option<Asn1PsFunc>,
    prefix_free: Option<Asn1PsFunc>,
    suffix: Option<Asn1PsFunc>,
    suffix_free: Option<Asn1PsFunc>,
    ex_buf: *mut u8,
    ex_len: c_int,
    ex_pos: c_int,
    ex_arg: *mut c_void,
}

/// `const BIO_METHOD *BIO_f_asn1(void)`
///
/// The method is a compiled-in table; the context is per-BIO and created by
/// `asn1_bio_new`.
static ASN1_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_ASN1,
    name: c"asn1".as_ptr(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(asn1_bio_write),
    bread: Some(bread_conv),
    bread_old: Some(asn1_bio_read),
    bputs: Some(asn1_bio_puts),
    bgets: Some(asn1_bio_gets),
    ctrl: Some(asn1_bio_ctrl),
    create: Some(asn1_bio_new),
    destroy: Some(asn1_bio_free),
    callback_ctrl: Some(asn1_bio_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_asn1(void)`
#[no_mangle]
pub extern "C" fn BIO_f_asn1() -> *const BioMethod {
    guard_ffi(core::ptr::null(), || &ASN1_METHOD)
}

/// The context of a BIO this method created.
///
/// # Safety
///
/// `b` must be a live BIO whose method is [`ASN1_METHOD`].
unsafe fn ctx_of<'a>(b: *mut Bio) -> Option<&'a mut BioAsn1BufCtx> {
    // SAFETY: the caller's contract is this function's; `BIO_get_data` is a
    // pointer read.
    let p = unsafe { BIO_get_data(b) } as *mut BioAsn1BufCtx;
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees `b` is a filter BIO of this method, so the
        // data pointer is a context this module allocated and no other reference
        // to it exists for the borrow.
        Some(unsafe { &mut *p })
    }
}

/// `static int asn1_bio_init(BIO_ASN1_BUF_CTX *ctx, int size)`
fn asn1_bio_init(ctx: &mut BioAsn1BufCtx, size: c_int) -> c_int {
    if size <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::BIO_ASN1_118) };
        return 0;
    }
    // SAFETY: `CRYPTO_malloc` answers null or `size` bytes.
    let buf = CRYPTO_malloc(size as usize, FILTER_FILE.as_ptr(), LINE).cast::<u8>();
    if buf.is_null() {
        return 0;
    }
    ctx.buf = buf;
    ctx.bufsize = size;
    ctx.asn1_class = V_ASN1_UNIVERSAL;
    ctx.asn1_tag = V_ASN1_OCTET_STRING;
    ctx.state = Asn1BioState::Start;
    1
}

/// `static int asn1_bio_new(BIO *b)`
///
/// # Safety
///
/// `b` must be a live BIO being created.
unsafe extern "C" fn asn1_bio_new(b: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` answers null or a zeroed context.
    let p = CRYPTO_zalloc(
        core::mem::size_of::<BioAsn1BufCtx>(),
        FILTER_FILE.as_ptr(),
        LINE,
    )
    .cast::<BioAsn1BufCtx>();
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is a fresh, uniquely-owned context.
    let ctx = unsafe { &mut *p };
    if asn1_bio_init(ctx, DEFAULT_ASN1_BUF_SIZE) == 0 {
        // SAFETY: `p` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(p.cast(), FILTER_FILE.as_ptr(), LINE) };
        return 0;
    }
    // SAFETY: `b` is a live BIO and `p` is not owned elsewhere.
    unsafe {
        BIO_set_data(b, p.cast());
        BIO_set_init(b, 1);
    }
    1
}

/// `static int asn1_bio_free(BIO *b)`
///
/// # Safety
///
/// `b` must be null or a live filter BIO of this method.
unsafe extern "C" fn asn1_bio_free(b: *mut Bio) -> c_int {
    if b.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract is `ctx_of`'s.
    let Some(ctx) = (unsafe { ctx_of(b) }) else {
        return 0;
    };
    if let Some(f) = ctx.prefix_free {
        // SAFETY: the callback's contract is the filter's own; `ex_*` are live
        // fields of `ctx` and `ex_arg` is the caller's slot.
        unsafe {
            f(
                b,
                &raw mut ctx.ex_buf,
                &raw mut ctx.ex_len,
                (&raw mut ctx.ex_arg).cast(),
            )
        };
    }
    if let Some(f) = ctx.suffix_free {
        // SAFETY: as above.
        unsafe {
            f(
                b,
                &raw mut ctx.ex_buf,
                &raw mut ctx.ex_len,
                (&raw mut ctx.ex_arg).cast(),
            )
        };
    }
    // SAFETY: `buf` came from this allocator and is not owned elsewhere.
    unsafe { CRYPTO_free(ctx.buf.cast(), FILTER_FILE.as_ptr(), LINE) };
    let p: *mut BioAsn1BufCtx = ctx;
    // SAFETY: the context came from this allocator, is not owned elsewhere, and
    // the BIO is about to forget it.
    unsafe {
        CRYPTO_free(p.cast(), FILTER_FILE.as_ptr(), LINE);
        BIO_set_data(b, core::ptr::null_mut());
        BIO_set_init(b, 0);
    }
    1
}

/// `static int asn1_bio_flush_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
/// asn1_ps_func *cleanup, asn1_bio_state_t next)`
///
/// # Safety
///
/// `b` must be a live filter BIO and `ctx` its context.
unsafe fn asn1_bio_flush_ex(
    b: *mut Bio,
    ctx: &mut BioAsn1BufCtx,
    cleanup: Option<Asn1PsFunc>,
    next: Asn1BioState,
) -> c_int {
    if ctx.ex_len <= 0 {
        return 1;
    }
    loop {
        // SAFETY: `b` is live and `BIO_next` reads its next pointer.
        let n = unsafe { BIO_next(b) };
        if n.is_null() {
            return 0;
        }
        // SAFETY: `ctx.ex_buf` owns `ctx.ex_len + ctx.ex_pos` bytes and the run to
        // write starts at `ex_pos`; `n` is live.
        let ret = unsafe { BIO_write(n, ctx.ex_buf.add(ctx.ex_pos as usize).cast(), ctx.ex_len) };
        if ret <= 0 {
            return ret;
        }
        ctx.ex_len -= ret;
        if ctx.ex_len > 0 {
            ctx.ex_pos += ret;
        } else {
            if let Some(f) = cleanup {
                // SAFETY: the callback's contract is the filter's own.
                unsafe {
                    f(
                        b,
                        &raw mut ctx.ex_buf,
                        &raw mut ctx.ex_len,
                        (&raw mut ctx.ex_arg).cast(),
                    )
                };
            }
            ctx.state = next;
            ctx.ex_pos = 0;
            return ret;
        }
    }
}

/// `static int asn1_bio_setup_ex(BIO *b, BIO_ASN1_BUF_CTX *ctx,
/// asn1_ps_func *setup, asn1_bio_state_t ex_state,
/// asn1_bio_state_t other_state)`
///
/// # Safety
///
/// `b` must be a live filter BIO and `ctx` its context.
unsafe fn asn1_bio_setup_ex(
    b: *mut Bio,
    ctx: &mut BioAsn1BufCtx,
    setup: Option<Asn1PsFunc>,
    ex_state: Asn1BioState,
    other_state: Asn1BioState,
) -> c_int {
    if let Some(f) = setup {
        // SAFETY: the callback's contract is the filter's own.
        let ok = unsafe {
            f(
                b,
                &raw mut ctx.ex_buf,
                &raw mut ctx.ex_len,
                (&raw mut ctx.ex_arg).cast(),
            )
        };
        if ok == 0 {
            // SAFETY: `b` is a live BIO.
            unsafe { BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
            return 0;
        }
    }
    ctx.state = if ctx.ex_len > 0 {
        ex_state
    } else {
        other_state
    };
    1
}

/// `static int asn1_bio_write(BIO *b, const char *in, int inl)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `in` must be readable for `inl` bytes.
#[allow(unused_assignments)]
// The authority initialises `ret` to `-1` and every path that reaches the end of
// the loop assigns it first, so the initialiser is never read. It is kept because
// it is the authority's own line and because a future state added to the machine
// would want it.
unsafe extern "C" fn asn1_bio_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    // SAFETY: the caller's contract is `ctx_of`'s.
    let Some(ctx) = (unsafe { ctx_of(b) }) else {
        return 0;
    };
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    if in_.is_null() || inl < 0 || next.is_null() {
        return 0;
    }
    let mut in_ = in_;
    let mut inl = inl;
    let mut wrlen: c_int = 0;
    let mut ret: c_int = -1;

    loop {
        match ctx.state {
            Asn1BioState::Start => {
                // SAFETY: `b` is live and `ctx` is its context.
                if unsafe {
                    asn1_bio_setup_ex(
                        b,
                        ctx,
                        ctx.prefix,
                        Asn1BioState::PreCopy,
                        Asn1BioState::Header,
                    )
                } == 0
                {
                    return -1;
                }
            }
            Asn1BioState::PreCopy => {
                // SAFETY: as above.
                ret = unsafe { asn1_bio_flush_ex(b, ctx, ctx.prefix_free, Asn1BioState::Header) };
                if ret <= 0 {
                    break;
                }
            }
            Asn1BioState::Header => {
                ctx.buflen = ASN1_object_size(0, inl, ctx.asn1_tag) - inl;
                if ctx.buflen > ctx.bufsize {
                    // Upstream's `ossl_assert`, reproduced: the state is
                    // unreachable for any content that fits a 20-byte header, and
                    // stopping is the authority's answer if it were reached.
                    return -1;
                }
                let mut p = ctx.buf;
                // SAFETY: `p` points into `ctx.buf`, which owns `bufsize` bytes and
                // `buflen <= bufsize`.
                unsafe { ASN1_put_object(&mut p, 0, inl, ctx.asn1_tag, ctx.asn1_class) };
                ctx.copylen = inl;
                ctx.state = Asn1BioState::HeaderCopy;
            }
            Asn1BioState::HeaderCopy => {
                // SAFETY: `ctx.buf` owns `bufsize >= buflen` bytes and the write
                // starts at `bufpos`; `next` is live.
                ret =
                    unsafe { BIO_write(next, ctx.buf.add(ctx.bufpos as usize).cast(), ctx.buflen) };
                if ret <= 0 {
                    break;
                }
                ctx.buflen -= ret;
                if ctx.buflen != 0 {
                    ctx.bufpos += ret;
                } else {
                    ctx.bufpos = 0;
                    ctx.state = Asn1BioState::DataCopy;
                }
            }
            Asn1BioState::DataCopy => {
                let wrmax = if inl > ctx.copylen { ctx.copylen } else { inl };
                // SAFETY: `in_` is readable for `inl >= wrmax` bytes and `next` is
                // live.
                ret = unsafe { BIO_write(next, in_.cast(), wrmax) };
                if ret <= 0 {
                    break;
                }
                wrlen += ret;
                ctx.copylen -= ret;
                // SAFETY: `ret <= inl`, so advancing by `ret` stays inside the
                // caller's buffer.
                in_ = unsafe { in_.add(ret as usize) };
                inl -= ret;

                if ctx.copylen == 0 {
                    ctx.state = Asn1BioState::Header;
                }
                if inl == 0 {
                    break;
                }
            }
            Asn1BioState::PostCopy | Asn1BioState::Done => {
                // SAFETY: `b` is a live BIO.
                unsafe { BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
                return 0;
            }
        }
    }

    // SAFETY: `b` is a live BIO.
    unsafe {
        BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        BIO_copy_next_retry(b);
    }
    if wrlen > 0 {
        wrlen
    } else {
        ret
    }
}

/// `static int asn1_bio_read(BIO *b, char *in, int inl)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `in` must be writable for `inl` bytes.
unsafe extern "C" fn asn1_bio_read(b: *mut Bio, in_: *mut c_char, inl: c_int) -> c_int {
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live and `in_` is writable for `inl` bytes.
    unsafe { BIO_read(next, in_.cast(), inl) }
}

/// `static int asn1_bio_puts(BIO *b, const char *str)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `str` must be a NUL-terminated string.
unsafe extern "C" fn asn1_bio_puts(b: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: the caller's contract makes `str_` NUL-terminated.
    let len = unsafe { OPENSSL_strnlen(str_, usize::MAX) };
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `b` is live and `str_` is readable for `len` bytes.
    unsafe { asn1_bio_write(b, str_, len as c_int) }
}

/// `static int asn1_bio_gets(BIO *b, char *str, int size)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `str` must be writable for `size` bytes.
unsafe extern "C" fn asn1_bio_gets(b: *mut Bio, str_: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live and `str_` is writable for `size` bytes.
    unsafe { BIO_gets(next, str_, size) }
}

/// `static long asn1_bio_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `fp` must be null or the callback `cmd` expects.
unsafe extern "C" fn asn1_bio_callback_ctrl(
    b: *mut Bio,
    cmd: c_int,
    fp: Option<BioInfoCb>,
) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live and `fp` is the caller's.
    unsafe { BIO_callback_ctrl(next, cmd, fp) }
}

/// `static long asn1_bio_ctrl(BIO *b, int cmd, long arg1, void *arg2)`
///
/// The four `BIO_C_*_PREFIX`/`_SUFFIX` commands move the callback pair; the two
/// `EX_ARG` commands move the caller's pointer; `BIO_CTRL_FLUSH` is what drives the
/// state machine to `DONE` and emits the suffix.
///
/// # Safety
///
/// `b` must be a live filter BIO and `arg2` whatever `cmd` expects.
unsafe extern "C" fn asn1_bio_ctrl(
    b: *mut Bio,
    cmd: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_long {
    // SAFETY: the caller's contract is `ctx_of`'s.
    let Some(ctx) = (unsafe { ctx_of(b) }) else {
        return 0;
    };
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    let mut ret: c_long = 1;

    match cmd {
        BIO_C_SET_PREFIX => {
            // SAFETY: the command's contract makes `arg2` a `BIO_ASN1_EX_FUNCS *`.
            let ex_func = unsafe { &*(arg2 as *const BioAsn1ExFuncs) };
            ctx.prefix = ex_func.ex_func;
            ctx.prefix_free = ex_func.ex_free_func;
        }
        BIO_C_GET_PREFIX => {
            // SAFETY: as above; the getter writes through it.
            let ex_func = unsafe { &mut *(arg2 as *mut BioAsn1ExFuncs) };
            ex_func.ex_func = ctx.prefix;
            ex_func.ex_free_func = ctx.prefix_free;
        }
        BIO_C_SET_SUFFIX => {
            // SAFETY: as `BIO_C_SET_PREFIX`.
            let ex_func = unsafe { &*(arg2 as *const BioAsn1ExFuncs) };
            ctx.suffix = ex_func.ex_func;
            ctx.suffix_free = ex_func.ex_free_func;
        }
        BIO_C_GET_SUFFIX => {
            // SAFETY: as `BIO_C_GET_PREFIX`.
            let ex_func = unsafe { &mut *(arg2 as *mut BioAsn1ExFuncs) };
            ex_func.ex_func = ctx.suffix;
            ex_func.ex_free_func = ctx.suffix_free;
        }
        BIO_C_SET_EX_ARG => ctx.ex_arg = arg2,
        BIO_C_GET_EX_ARG => {
            // SAFETY: the command's contract makes `arg2` a `void **`.
            unsafe { *(arg2 as *mut *mut c_void) = ctx.ex_arg };
        }
        BIO_CTRL_FLUSH => {
            if next.is_null() {
                return 0;
            }
            if ctx.state == Asn1BioState::Header {
                // SAFETY: `b` is live and `ctx` its context.
                if unsafe {
                    asn1_bio_setup_ex(
                        b,
                        ctx,
                        ctx.suffix,
                        Asn1BioState::PostCopy,
                        Asn1BioState::Done,
                    )
                } == 0
                {
                    return 0;
                }
            }
            if ctx.state == Asn1BioState::PostCopy {
                // SAFETY: as above.
                ret = c_long::from(unsafe {
                    asn1_bio_flush_ex(b, ctx, ctx.suffix_free, Asn1BioState::Done)
                });
                if ret <= 0 {
                    return ret;
                }
            }
            if ctx.state == Asn1BioState::Done {
                // SAFETY: `next` is live and non-null on this path.
                return unsafe { BIO_ctrl(next, cmd, arg1, arg2) };
            }
            // SAFETY: `b` is a live BIO.
            unsafe { BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
            return 0;
        }
        _ => {
            if next.is_null() {
                return 0;
            }
            // SAFETY: `next` is live and the arguments are the caller's.
            return unsafe { BIO_ctrl(next, cmd, arg1, arg2) };
        }
    }

    let _ = ret;
    ret
}

/// `static int asn1_bio_set_ex(BIO *b, int cmd, asn1_ps_func *ex_func,
/// asn1_ps_func *ex_free_func)`
///
/// # Safety
///
/// `b` must be a live filter BIO.
unsafe fn asn1_bio_set_ex(
    b: *mut Bio,
    cmd: c_int,
    ex_func: Option<Asn1PsFunc>,
    ex_free_func: Option<Asn1PsFunc>,
) -> c_int {
    let mut extmp = BioAsn1ExFuncs {
        ex_func,
        ex_free_func,
    };
    // SAFETY: `b` is live and `extmp` is a live local of the shape `cmd` expects.
    unsafe { BIO_ctrl(b, cmd, 0, (&raw mut extmp).cast()) as c_int }
}

/// `static int asn1_bio_get_ex(BIO *b, int cmd, asn1_ps_func **ex_func,
/// asn1_ps_func **ex_free_func)`
///
/// # Safety
///
/// `b` must be a live filter BIO; both outputs must be writable.
unsafe fn asn1_bio_get_ex(
    b: *mut Bio,
    cmd: c_int,
    ex_func: *mut Option<Asn1PsFunc>,
    ex_free_func: *mut Option<Asn1PsFunc>,
) -> c_int {
    let mut extmp = BioAsn1ExFuncs {
        ex_func: None,
        ex_free_func: None,
    };
    // SAFETY: `b` is live and `extmp` is a live local of the shape `cmd` expects.
    let ret = unsafe { BIO_ctrl(b, cmd, 0, (&raw mut extmp).cast()) };
    if ret > 0 {
        // SAFETY: the caller's contract makes both outputs writable.
        unsafe {
            *ex_func = extmp.ex_func;
            *ex_free_func = extmp.ex_free_func;
        }
    }
    ret as c_int
}

/// `int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
/// asn1_ps_func *prefix_free)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `prefix` and `prefix_free` must be null or
/// `asn1_ps_func` values.
#[no_mangle]
pub unsafe extern "C" fn BIO_asn1_set_prefix(
    b: *mut Bio,
    prefix: Option<Asn1PsFunc>,
    prefix_free: Option<Asn1PsFunc>,
) -> c_int {
    // SAFETY: the caller's contract is `asn1_bio_set_ex`'s.
    unsafe { asn1_bio_set_ex(b, BIO_C_SET_PREFIX, prefix, prefix_free) }
}

/// `int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
/// asn1_ps_func **pprefix_free)`
///
/// # Safety
///
/// `b` must be a live filter BIO; both outputs must be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_asn1_get_prefix(
    b: *mut Bio,
    pprefix: *mut Option<Asn1PsFunc>,
    pprefix_free: *mut Option<Asn1PsFunc>,
) -> c_int {
    // SAFETY: the caller's contract is `asn1_bio_get_ex`'s.
    unsafe { asn1_bio_get_ex(b, BIO_C_GET_PREFIX, pprefix, pprefix_free) }
}

/// `int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
/// asn1_ps_func *suffix_free)`
///
/// # Safety
///
/// `b` must be a live filter BIO; `suffix` and `suffix_free` must be null or
/// `asn1_ps_func` values.
#[no_mangle]
pub unsafe extern "C" fn BIO_asn1_set_suffix(
    b: *mut Bio,
    suffix: Option<Asn1PsFunc>,
    suffix_free: Option<Asn1PsFunc>,
) -> c_int {
    // SAFETY: the caller's contract is `asn1_bio_set_ex`'s.
    unsafe { asn1_bio_set_ex(b, BIO_C_SET_SUFFIX, suffix, suffix_free) }
}

/// `int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
/// asn1_ps_func **psuffix_free)`
///
/// # Safety
///
/// `b` must be a live filter BIO; both outputs must be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_asn1_get_suffix(
    b: *mut Bio,
    psuffix: *mut Option<Asn1PsFunc>,
    psuffix_free: *mut Option<Asn1PsFunc>,
) -> c_int {
    // SAFETY: the caller's contract is `asn1_bio_get_ex`'s.
    unsafe { asn1_bio_get_ex(b, BIO_C_GET_SUFFIX, psuffix, psuffix_free) }
}

// ---------------------------------------------------------------------------
// bio_ndef.c — the caller that uses the prefix and the suffix
// ---------------------------------------------------------------------------

/// `NDEF_SUPPORT` — the support block `BIO_new_NDEF` stores in `ex_arg`.
#[repr(C)]
pub struct NdefSupport {
    /// The `ASN1_VALUE` being streamed.
    pub val: *mut c_void,
    /// Its item.
    pub it: *const Asn1Item,
    /// The BIO the caller writes to.
    pub ndef_bio: *mut Bio,
    /// The output BIO at the bottom of the chain.
    pub out: *mut Bio,
    /// Where the content is inserted, as the callback set it.
    pub boundary: *mut *mut u8,
    /// The DER buffer the prefix or suffix pass allocated.
    pub derbuf: *mut u8,
}

/// `BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it)`
///
/// On success the returned BIO owns `out` as part of its chain; on failure the
/// caller still owns it. That asymmetry is the authority's and is why the cleanup
/// path pops before freeing.
///
/// # Safety
///
/// `out` must be a live BIO; `val` must be a live value of `it`'s type; `it` must be
/// a live item.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_NDEF(
    out: *mut Bio,
    mut val: *mut c_void,
    it: *const Asn1Item,
) -> *mut Bio {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract makes `it` live.
        let Some(item) = (unsafe { it.as_ref() }) else {
            return core::ptr::null_mut();
        };
        let aux = item.funcs as *const Asn1Aux;
        if aux.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::BIO_NDEF_67) };
            return core::ptr::null_mut();
        }
        // SAFETY: `aux` is the item's `funcs`, which for a templated item is an
        // `ASN1_AUX`.
        let Some(cb) = (unsafe { (*aux).asn1_cb }) else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::BIO_NDEF_67) };
            return core::ptr::null_mut();
        };

        // SAFETY: `CRYPTO_zalloc` answers null or a zeroed support block.
        let ndef_aux = CRYPTO_zalloc(
            core::mem::size_of::<NdefSupport>(),
            NDEF_FILE.as_ptr(),
            LINE,
        )
        .cast::<NdefSupport>();
        // SAFETY: the method table is a compiled-in static.
        let asn_bio = unsafe { BIO_new(BIO_f_asn1()) };

        let mut out = out;
        let mut pop_bio: *mut Bio = core::ptr::null_mut();
        if ndef_aux.is_null() || asn_bio.is_null() {
            // SAFETY: `pop_bio` is null, which `BIO_pop` accepts, and either
            // `ndef_aux` or `asn_bio` may be null, which both free paths accept.
            unsafe {
                BIO_pop(pop_bio);
                BIO_free(asn_bio);
                CRYPTO_free(ndef_aux.cast(), NDEF_FILE.as_ptr(), LINE);
            }
            return core::ptr::null_mut();
        }

        // "ASN1 bio needs to be next to output BIO."
        // SAFETY: both are live BIOs.
        out = unsafe { BIO_push(asn_bio, out) };
        if out.is_null() {
            // SAFETY: `asn_bio` is live and `ndef_aux` is not owned by anything.
            unsafe {
                BIO_free(asn_bio);
                CRYPTO_free(ndef_aux.cast(), NDEF_FILE.as_ptr(), LINE);
            }
            return core::ptr::null_mut();
        }
        pop_bio = asn_bio;

        // SAFETY: `asn_bio` is live and each control's argument is the shape it
        // expects; the two callbacks are this module's.
        // The authority's test is `A <= 0 || B <= 0 || C <= 0` and the three calls
        // are made in that order, short-circuiting. Each answers 1 on success.
        // SAFETY: `asn_bio` is live and each control's argument is the shape it
        // expects; the two callbacks are this module's, and the third stores the
        // support block without reading it.
        let setup = unsafe {
            BIO_asn1_set_prefix(asn_bio, Some(ndef_prefix), Some(ndef_prefix_free)) > 0
                && BIO_asn1_set_suffix(asn_bio, Some(ndef_suffix), Some(ndef_suffix_free)) > 0
                && BIO_ctrl(asn_bio, BIO_C_SET_EX_ARG, 0, ndef_aux.cast()) > 0
        };
        if !setup {
            // SAFETY: `pop_bio` is live; the block is not yet owned by the BIO.
            unsafe {
                BIO_pop(pop_bio);
                BIO_free(asn_bio);
                CRYPTO_free(ndef_aux.cast(), NDEF_FILE.as_ptr(), LINE);
            }
            return core::ptr::null_mut();
        }

        let mut sarg = Asn1StreamArg {
            out,
            ndef_bio: core::ptr::null_mut(),
            boundary: core::ptr::null_mut(),
        };

        // SAFETY: the callback's contract is the authority's `ASN1_OP_STREAM_PRE`;
        // `val` and `sarg` are live locals and `it` is the caller's item.
        let ok = unsafe { cb(ASN1_OP_STREAM_PRE, &raw mut val, it, (&raw mut sarg).cast()) };
        if ok <= 0 {
            // After `ASN1_OP_STREAM_PRE` the block is owned by `asn_bio`, so it is
            // not freed here.
            // SAFETY: `pop_bio` is live and `asn_bio` is still owned here.
            unsafe {
                BIO_pop(pop_bio);
                BIO_free(asn_bio);
            }
            return core::ptr::null_mut();
        }

        // SAFETY: `ndef_aux` is live and no other reference to it exists.
        unsafe {
            (*ndef_aux).val = val;
            (*ndef_aux).it = it;
            (*ndef_aux).ndef_bio = sarg.ndef_bio;
            (*ndef_aux).boundary = sarg.boundary;
            (*ndef_aux).out = out;
        }
        sarg.ndef_bio
    })
}

/// `ASN1_STREAM_ARG` — what a streaming callback is handed.
#[repr(C)]
pub struct Asn1StreamArg {
    /// The BIO to stream through.
    pub out: *mut Bio,
    /// The BIO with the filters appended.
    pub ndef_bio: *mut Bio,
    /// The streaming boundary, as `ASN1_item_ndef_i2d` leaves it.
    pub boundary: *mut *mut u8,
}

/// `static int ndef_prefix(BIO *b, unsigned char **pbuf, int *plen, void *parg)`
///
/// Encodes the value with `ASN1_item_ndef_i2d` twice — once to size, once to fill —
/// and hands back only the bytes *before* the boundary the encode left behind, so
/// the stream's content lands where the header expects it.
///
/// # Safety
///
/// The filter's contract: `pbuf` and `plen` are the filter's fields, `parg` the
/// address of its `ex_arg`.
unsafe extern "C" fn ndef_prefix(
    _b: *mut Bio,
    pbuf: *mut *mut u8,
    plen: *mut c_int,
    parg: *mut c_void,
) -> c_int {
    if parg.is_null() {
        return 0;
    }
    // SAFETY: the filter passes the address of its `ex_arg`, which holds an
    // `NDEF_SUPPORT *`.
    let ndef_aux = unsafe { *(parg as *mut *mut NdefSupport) };
    // SAFETY: `BIO_new_NDEF` allocated the support block and the filter owns it
    // until the suffix's cleanup releases it; a non-null pointer is live.
    let Some(aux) = (unsafe { ndef_aux.as_ref() }) else {
        return 0;
    };
    // SAFETY: `aux` is live and its item is the caller's.
    let derlen = unsafe { ASN1_item_ndef_i2d(aux.val, core::ptr::null_mut(), aux.it) };
    if derlen < 0 {
        return 0;
    }
    // SAFETY: `CRYPTO_malloc` answers null or `derlen` bytes.
    let p = CRYPTO_malloc(derlen as usize, NDEF_FILE.as_ptr(), LINE).cast::<u8>();
    if p.is_null() {
        return 0;
    }
    // SAFETY: `ndef_aux` is live and uniquely owned.
    unsafe { (*ndef_aux).derbuf = p };
    // SAFETY: the filter's contract makes `pbuf` writable.
    unsafe { *pbuf = p };
    let mut p = p;
    // SAFETY: `p` owns `derlen` bytes and advances within them.
    unsafe { ASN1_item_ndef_i2d(aux.val, &mut p, aux.it) };

    // SAFETY: the callback's contract makes `boundary` readable and the filter set
    // it during the encode.
    let boundary = unsafe { *aux.boundary };
    if boundary.is_null() {
        return 0;
    }
    // SAFETY: the filter's contract makes `plen` writable; `boundary` is inside
    // the buffer `*pbuf` points at.
    unsafe { *plen = (boundary as isize - p as isize) as c_int };
    1
}

/// `static int ndef_prefix_free(BIO *b, unsigned char **pbuf, int *plen,
/// void *parg)`
///
/// # Safety
///
/// As [`ndef_prefix`], with the filter's `ex_arg` on its cleanup path.
unsafe extern "C" fn ndef_prefix_free(
    _b: *mut Bio,
    pbuf: *mut *mut u8,
    plen: *mut c_int,
    parg: *mut c_void,
) -> c_int {
    if parg.is_null() {
        return 0;
    }
    // SAFETY: the filter's contract.
    let ndef_aux = unsafe { *(parg as *mut *mut NdefSupport) };
    if ndef_aux.is_null() {
        return 0;
    }
    // SAFETY: `ndef_aux` is live and uniquely owned.
    unsafe {
        let aux = &mut *ndef_aux;
        CRYPTO_free(aux.derbuf.cast(), NDEF_FILE.as_ptr(), LINE);
        aux.derbuf = core::ptr::null_mut();
        *pbuf = core::ptr::null_mut();
        *plen = 0;
    }
    1
}

/// `static int ndef_suffix_free(BIO *b, unsigned char **pbuf, int *plen,
/// void *parg)`
///
/// Frees the prefix's buffer and then the support block, clearing the caller's
/// pointer — which is why the suffix's `parg` is passed on unchanged and the block
/// is released exactly once.
///
/// # Safety
///
/// As [`ndef_prefix_free`].
unsafe extern "C" fn ndef_suffix_free(
    b: *mut Bio,
    pbuf: *mut *mut u8,
    plen: *mut c_int,
    parg: *mut c_void,
) -> c_int {
    // SAFETY: the filter's contract is `ndef_prefix_free`'s.
    if unsafe { ndef_prefix_free(b, pbuf, plen, parg) } == 0 {
        return 0;
    }
    // SAFETY: the filter's contract makes `parg` the address of its `ex_arg`.
    let slot = parg as *mut *mut NdefSupport;
    // SAFETY: the slot is live.
    let block = unsafe { *slot };
    if !block.is_null() {
        // SAFETY: `block` came from `CRYPTO_zalloc` in `BIO_new_NDEF` and is not
        // owned elsewhere once the pointer is cleared.
        unsafe {
            CRYPTO_free(block.cast(), NDEF_FILE.as_ptr(), LINE);
            *slot = core::ptr::null_mut();
        }
    }
    1
}

/// `static int ndef_suffix(BIO *b, unsigned char **pbuf, int *plen, void *parg)`
///
/// Runs `ASN1_OP_STREAM_POST` to finalise the structure, re-encodes it, and hands
/// back only the bytes *from* the boundary onward.
///
/// # Safety
///
/// As [`ndef_prefix`].
unsafe extern "C" fn ndef_suffix(
    _b: *mut Bio,
    pbuf: *mut *mut u8,
    plen: *mut c_int,
    parg: *mut c_void,
) -> c_int {
    if parg.is_null() {
        return 0;
    }
    // SAFETY: the filter's contract.
    let ndef_aux = unsafe { *(parg as *mut *mut NdefSupport) };
    // SAFETY: `BIO_new_NDEF` allocated the support block and the filter owns it
    // until the suffix's cleanup releases it; a non-null pointer is live.
    let Some(aux) = (unsafe { ndef_aux.as_ref() }) else {
        return 0;
    };
    // SAFETY: `aux.it` is the caller's live item.
    let Some(item) = (unsafe { aux.it.as_ref() }) else {
        return 0;
    };
    let aux_ptr = item.funcs as *const Asn1Aux;
    if aux_ptr.is_null() {
        return 0;
    }
    // SAFETY: `aux_ptr` is the item's `funcs`.
    let Some(cb) = (unsafe { (*aux_ptr).asn1_cb }) else {
        return 0;
    };

    let mut sarg = Asn1StreamArg {
        out: aux.out,
        ndef_bio: aux.ndef_bio,
        boundary: aux.boundary,
    };
    // SAFETY: the callback's contract is `ASN1_OP_STREAM_POST`; the value slot and
    // `sarg` are live locals.
    if unsafe {
        cb(
            ASN1_OP_STREAM_POST,
            (&raw mut (*ndef_aux).val),
            aux.it,
            (&raw mut sarg).cast(),
        )
    } <= 0
    {
        return 0;
    }

    // SAFETY: `aux` is live and its item is the caller's.
    let derlen = unsafe { ASN1_item_ndef_i2d(aux.val, core::ptr::null_mut(), aux.it) };
    if derlen < 0 {
        return 0;
    }
    // SAFETY: `CRYPTO_malloc` answers null or `derlen` bytes.
    let p = CRYPTO_malloc(derlen as usize, NDEF_FILE.as_ptr(), LINE).cast::<u8>();
    if p.is_null() {
        return 0;
    }
    // SAFETY: `ndef_aux` is live and uniquely owned.
    unsafe { (*ndef_aux).derbuf = p };
    // SAFETY: the filter's contract makes `pbuf` writable.
    unsafe { *pbuf = p };
    let mut p = p;
    // SAFETY: `p` owns `derlen` bytes and advances within them.
    let derlen = unsafe { ASN1_item_ndef_i2d(aux.val, &mut p, aux.it) };

    // SAFETY: `aux.boundary` is readable and the encode set it.
    let boundary = unsafe { *aux.boundary };
    if boundary.is_null() {
        return 0;
    }
    // SAFETY: `pbuf` and `plen` are writable and `boundary` is inside the buffer.
    unsafe {
        *pbuf = boundary;
        *plen = derlen - (boundary as isize - aux.derbuf as isize) as c_int;
    }
    1
}
