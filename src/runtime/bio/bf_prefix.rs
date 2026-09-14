//! Phase 4 — the prefix filter (`BIO_f_prefix`).
//!
//! `BIO_f_prefix` inserts text at the start of every line that passes through it:
//! `openssl`'s `-prefix`/`-indent` output options and the CLI's text output both
//! use it. Its state is one flag — "am I at the start of a line" — and the
//! contract is entirely in how that flag is maintained:
//!
//! * with no prefix **and** no indent the filter is a passthrough that still
//!   *notes* whether the next byte starts a line, so a prefix set later applies
//!   from the right place;
//! * a prefix is emitted only when the flag is set, and the indent is emitted as
//!   a `"%*s"` field through the ordinary printf path, so an indent of 0 emits
//!   **nothing** (a zero-width field);
//! * writes are broken at newlines and each segment is written to the next BIO
//!   in full or not at all, so a partial write by the next BIO makes the whole
//!   call fail rather than silently dropping bytes;
//! * `BIO_ctrl(BIO_CTRL_SET_PREFIX)` **frees the old prefix even when it then
//!   fails**, and duplicates the new one;
//! * seeking or resetting sets the flag, so a rewind re-emits the prefix.
//!
//! `RT-BIO-FILTER` drives the flag through the passthrough case, the mixed case
//! and the rewind, and reads the indent back through `BIO_CTRL_GET_INDENT`.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::{
    Bio, BioMethod, BIO_CTRL_GET_INDENT, BIO_CTRL_RESET, BIO_CTRL_SET_INDENT, BIO_CTRL_SET_PREFIX,
    BIO_C_FILE_SEEK, BIO_TYPE_BUFFER,
};

/// The method name the authority reports for this filter.
const PREFIX_NAME: &[u8] = b"prefix\0";

/// The authority's `PREFIX_CTX`.
#[repr(C)]
struct PrefixCtx {
    /// The user's prefix text, or NULL.
    prefix: *mut c_char,
    /// Indentation amount.
    indent: u32,
    /// Non-zero while the next output begins a line.
    linestart: c_int,
}

/// A compiled-in method table. `BIO_f_prefix()` returns its address.
///
/// The write and read slots are the modern (`_ex`) forms and the legacy slots are
/// NULL, exactly as the authority's table is.
static PREFIX_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_BUFFER,
    name: PREFIX_NAME.as_ptr().cast(),
    bwrite: Some(prefix_write),
    bwrite_old: None,
    bread: Some(prefix_read),
    bread_old: None,
    bputs: Some(prefix_puts),
    bgets: Some(prefix_gets),
    ctrl: Some(prefix_ctrl),
    create: Some(prefix_create),
    destroy: Some(prefix_destroy),
    callback_ctrl: Some(prefix_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_prefix(void)`
#[no_mangle]
pub extern "C" fn BIO_f_prefix() -> *const BioMethod {
    guard_ffi(ptr::null(), || &PREFIX_METHOD)
}

/// The context of a live prefix BIO.
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe fn ctx(b: *mut Bio) -> *mut PrefixCtx {
    // SAFETY: the caller guarantees the BIO came from this method, whose
    // `create` stores a `PrefixCtx`.
    unsafe { (*b).ptr.cast() }
}

/// `prefix_create`
///
/// # Safety
/// `b` must be a live BIO.
unsafe extern "C" fn prefix_create(b: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let c: *mut PrefixCtx = CRYPTO_zalloc(core::mem::size_of::<PrefixCtx>(), ptr::null(), 0).cast();
    if c.is_null() {
        return 0;
    }
    // SAFETY: `c` is a fresh allocation and `b` is live.
    unsafe {
        (*c).prefix = ptr::null_mut();
        (*c).indent = 0;
        (*c).linestart = 1;
        (*b).ptr = c.cast();
        (*b).init = 1;
    }
    1
}

/// `prefix_destroy`
///
/// # Safety
/// `b` must be a live BIO created from this method.
unsafe extern "C" fn prefix_destroy(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live and holds a `PrefixCtx`.
    let c = unsafe { ctx(b) };
    if !c.is_null() {
        // SAFETY: `prefix` is NULL or an owned duplicate.
        unsafe {
            if !(*c).prefix.is_null() {
                CRYPTO_free((*c).prefix.cast(), ptr::null(), 0);
            }
            CRYPTO_free(c.cast(), ptr::null(), 0);
        }
    }
    1
}

/// `prefix_read` — a pure forward.
///
/// # Safety
/// `b` must be a live prefix BIO; `buf` writable for `size` bytes.
unsafe extern "C" fn prefix_read(
    b: *mut Bio,
    buf: *mut c_char,
    size: usize,
    numread: *mut usize,
) -> c_int {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    // SAFETY: `next` is live (or NULL, which `BIO_read_ex` answers for).
    unsafe { super::BIO_read_ex(next, buf.cast(), size, numread) }
}

/// `prefix_write`
///
/// # Safety
/// `b` must be a live prefix BIO; `out` readable for `outl` bytes; `numwritten`
/// writable.
unsafe extern "C" fn prefix_write(
    b: *mut Bio,
    out: *const c_char,
    outl: usize,
    numwritten: *mut usize,
) -> c_int {
    // SAFETY: `b` is live.
    let c = unsafe { ctx(b) };
    if c.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };

    // With neither a prefix nor an indent there is nothing to insert, but the
    // line-start flag is still maintained for a prefix set later.
    // SAFETY: `c` is live.
    let no_prefix = unsafe { (*c).prefix.is_null() || *(*c).prefix == 0 };
    // SAFETY: `c` is this BIO's context, allocated by its `create` and freed only by its `destroy`.
    if no_prefix && unsafe { (*c).indent } == 0 {
        if outl > 0 {
            // SAFETY: `out` is readable for `outl` bytes.
            let last = unsafe { *out.add(outl - 1) };
            // SAFETY: `c` is live.
            unsafe { (*c).linestart = c_int::from(last == b'\n' as c_char) };
        }
        // SAFETY: `next` is live.
        return unsafe { super::BIO_write_ex(next, out.cast(), outl, numwritten) };
    }

    // SAFETY: `numwritten` is writable per the caller's contract.
    unsafe { *numwritten = 0 };

    let mut out = out;
    let mut outl = outl;
    while outl > 0 {
        // SAFETY: `c` is live.
        if unsafe { (*c).linestart } != 0 {
            // SAFETY: `c` is live.
            let (prefix, indent) = unsafe { ((*c).prefix, (*c).indent) };
            if !prefix.is_null() {
                // SAFETY: `prefix` is NUL-terminated.
                let plen = unsafe { super::sys::strlen(prefix) };
                let mut dontcare: usize = 0;
                // SAFETY: `next` is live and `prefix` is readable for `plen`.
                if unsafe { super::BIO_write_ex(next, prefix.cast(), plen, &mut dontcare) } == 0 {
                    return 0;
                }
            }
            // The authority emits the indent through `BIO_printf(next, "%*s", …)`,
            // so an indent of 0 emits nothing at all.
            // SAFETY: `next` is live; the format and its two arguments match.
            unsafe { super::print::BIO_printf(next, c"%*s".as_ptr(), indent, c"".as_ptr()) };
            // SAFETY: `c` is live.
            unsafe { (*c).linestart = 0 };
        }

        // Find the next newline, or the end of the input.
        let mut i = 0usize;
        let mut ch = 0u8;
        while i < outl {
            // SAFETY: `out` is readable for `outl` bytes.
            ch = unsafe { *out.add(i) } as u8;
            if ch == b'\n' {
                break;
            }
            i += 1;
        }
        if ch == b'\n' {
            i += 1;
        }

        // Write what was found, in full each time.
        while i > 0 {
            let mut n: usize = 0;
            // SAFETY: `next` is live and `out` is readable for `i` bytes.
            if unsafe { super::BIO_write_ex(next, out.cast(), i, &mut n) } == 0 {
                return 0;
            }
            // SAFETY: `out` is readable for `i` bytes and `n <= i`.
            unsafe { out = out.add(n) };
            outl -= n;
            // SAFETY: `numwritten` is the caller's out-parameter.
            unsafe { *numwritten += n };
            i -= n;
        }

        if ch == b'\n' {
            // SAFETY: `c` is live.
            unsafe { (*c).linestart = 1 };
        }
    }

    1
}

/// `prefix_ctrl`
///
/// # Safety
/// `b` must be a live prefix BIO; `ptr` must match the control's contract.
unsafe extern "C" fn prefix_ctrl(
    b: *mut Bio,
    cmd: c_int,
    num: c_long,
    ptr_: *mut c_void,
) -> c_long {
    if b.is_null() {
        return -1;
    }
    // SAFETY: `b` is live.
    let c = unsafe { ctx(b) };
    if c.is_null() {
        return -1;
    }
    let mut ret: c_long = 0;

    match cmd {
        BIO_CTRL_SET_PREFIX => {
            // SAFETY: `prefix` is NULL or an owned duplicate.
            unsafe {
                if !(*c).prefix.is_null() {
                    CRYPTO_free((*c).prefix.cast(), ptr::null(), 0);
                }
            }
            if ptr_.is_null() {
                // SAFETY: `c` is live.
                unsafe { (*c).prefix = ptr::null_mut() };
                ret = 1;
            } else {
                // SAFETY: `ptr_` is a NUL-terminated string.
                let dup = unsafe { super::sys::strdup(ptr_.cast()) };
                // SAFETY: `c` is live.
                unsafe { (*c).prefix = dup };
                ret = c_long::from(!dup.is_null());
            }
        }
        BIO_CTRL_SET_INDENT => {
            if num >= 0 {
                // SAFETY: `c` is live.
                unsafe { (*c).indent = num as u32 };
                ret = 1;
            }
        }
        BIO_CTRL_GET_INDENT => {
            // SAFETY: `c` is live.
            ret = unsafe { (*c).indent } as c_long;
        }
        _ => {
            // Seeking and resetting re-arm the flag.
            if cmd == BIO_C_FILE_SEEK || cmd == BIO_CTRL_RESET {
                // SAFETY: `c` is live.
                unsafe { (*c).linestart = 1 };
            }
            // SAFETY: `b` is live.
            let next = unsafe { (*b).next_bio };
            if !next.is_null() {
                // SAFETY: `next` is live.
                ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr_) };
            }
        }
    }
    ret
}

/// `prefix_callback_ctrl`
///
/// # Safety
/// `b` must be a live prefix BIO.
unsafe extern "C" fn prefix_callback_ctrl(
    b: *mut Bio,
    cmd: c_int,
    fp: *mut super::BioInfoCb,
) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    // SAFETY: `next` is live (or NULL, which `BIO_callback_ctrl` answers for).
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// `prefix_gets`
///
/// # Safety
/// `b` must be a live prefix BIO; `buf` writable for `size` bytes.
unsafe extern "C" fn prefix_gets(b: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    // SAFETY: `next` is live.
    unsafe { super::BIO_gets(next, buf, size) }
}

/// `prefix_puts`
///
/// # Safety
/// `b` must be a live prefix BIO; `str_` NUL-terminated.
unsafe extern "C" fn prefix_puts(b: *mut Bio, str_: *const c_char) -> c_int {
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
    unsafe { super::BIO_write(b, str_.cast(), len as c_int) }
}
