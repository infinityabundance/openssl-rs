//! Phase 4 — the `FILE`-pointer BIO (`BIO_s_file`, `BIO_new_file`, `BIO_new_fp`).
//!
//! This is the BIO an application gets when it hands the library a `FILE *`, and
//! the one `openssl` uses for `-in`/`-out`. Its observable surface is wider than
//! "read and write":
//!
//! * `BIO_new_file` chooses `BIO_FP_TEXT` from the **absence** of a `b` in the
//!   mode string, and folds that into the close flag it passes to `BIO_set_fp`;
//! * a failed `fopen` raises a *system* error whose data string is
//!   `calling fopen(<name>, <mode>)` **formatted by the library's own printing
//!   engine**, which substitutes `<NULL>` for a NULL `%s` — so the data text is
//!   not what the C library would produce;
//! * a failed read raises only when `fread` returned 0 *and* `ferror` is set, so
//!   an end-of-file read is silent;
//! * `BIO_C_SET_FILE_PTR` calls the destroy hook first, so replacing the file of
//!   an open BIO closes the old one if `shutdown` was set;
//! * `BIO_C_SET_FILENAME` maps a flag word to a mode string and raises
//!   `BIO_R_BAD_FOPEN_MODE` for an empty flag word before it touches the file
//!   system.
//!
//! ## The UPLINK branches are compiled out
//!
//! The authority's `bss_file.c` is full of `b->flags & BIO_FLAGS_UPLINK_INTERNAL`
//! tests, which exist for platforms that route stdio through a userland shim.
//! `BIO_FLAGS_UPLINK_INTERNAL` is **0** on this platform (`internal/cryptlib.h`,
//! `#else` of `OPENSSL_USE_APPLINK`), so every one of those tests is a constant
//! false, `file_new`'s "default to UPLINK" assignment is a no-op, and the
//! `#if BIO_FLAGS_UPLINK_INTERNAL != 0` block in `BIO_C_SET_FILE_PTR` is not
//! compiled. Reproducing the *tests* would be reproducing code that cannot run;
//! the observable consequence — plain stdio — is what is implemented, and the
//! field is still set to the same value so a caller reading `BIO_get_flags` sees
//! what the authority leaves there.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_FILE_149, BSS_FILE_151, BSS_FILE_284, BSS_FILE_299, BSS_FILE_302, BSS_FILE_335,
    BSS_FILE_337, BSS_FILE_67, BSS_FILE_75, BSS_FILE_77,
};
use crate::runtime::err::{raise_site, raise_site_dynamic_data};

use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{
    Bio, BioMethod, BIO_CLOSE, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_INFO, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_C_FILE_SEEK, BIO_C_FILE_TELL,
    BIO_C_GET_FILE_PTR, BIO_C_SET_FILENAME, BIO_C_SET_FILE_PTR, BIO_FLAGS_UPLINK_INTERNAL,
    BIO_FP_APPEND, BIO_FP_READ, BIO_FP_TEXT, BIO_FP_WRITE, BIO_TYPE_FILE,
};

/// The method name the authority reports for a `FILE` BIO.
const FILE_NAME: &[u8] = b"FILE pointer\0";

/// `EOF` from `<stdio.h>`.
const EOF: c_int = -1;

/// The authority's error-data buffer size (`ERR_MAX_DATA_SIZE`, `err.h`).
const ERR_MAX_DATA_SIZE: usize = 1024;

/// A compiled-in method table. `BIO_s_file()` returns its address.
static FILE_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_FILE,
    name: FILE_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(file_write),
    bread: Some(bread_conv),
    bread_old: Some(file_read),
    bputs: Some(file_puts),
    bgets: Some(file_gets),
    ctrl: Some(file_ctrl),
    create: Some(file_new),
    destroy: Some(file_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_file(void)`
#[no_mangle]
pub extern "C" fn BIO_s_file() -> *const BioMethod {
    guard_ffi(ptr::null(), || &FILE_METHOD)
}

/// Whether a NUL-terminated byte string contains `needle`.
///
/// # Safety
/// `s` must be NULL or NUL-terminated.
unsafe fn has_byte(s: *const c_char, needle: u8) -> bool {
    if s.is_null() {
        return false;
    }
    let mut i = 0isize;
    loop {
        // SAFETY: `s` is NUL-terminated.
        let c = unsafe { *s.offset(i) } as u8;
        if c == 0 {
            return false;
        }
        if c == needle {
            return true;
        }
        i += 1;
    }
}

/// Build the authority's `ERR_raise_data` text `calling fopen(%s, %s)`.
///
/// The authority formats this with its own printing engine
/// (`ERR_vset_error` → `BIO_vsnprintf` → `_dopr`), whose `%s` substitutes the
/// literal `<NULL>` for a NULL pointer. Calling libc's `snprintf` here would
/// print `(null)` instead, so the substitution is done explicitly.
///
/// `ERR_vset_error` first grows the slot to `ERR_MAX_DATA_SIZE` bytes and the
/// formatter reports truncation as failure; a message that does not fit
/// therefore leaves the data **empty** rather than truncated, and that is
/// reproduced too.
///
/// # Safety
/// `filename` and `mode` must each be NULL or NUL-terminated.
unsafe fn fopen_message(buf: &mut [c_char], filename: *const c_char, mode: *const c_char) -> usize {
    let mut n = 0usize;
    let mut push = |b: u8| {
        if n + 1 < buf.len() {
            buf[n] = b as c_char;
            n += 1;
            true
        } else {
            false
        }
    };
    let mut fits = true;
    for &b in b"calling fopen(" {
        fits &= push(b);
    }
    for p in [filename, mode] {
        if !fits {
            break;
        }
        if p.is_null() {
            for &b in b"<NULL>" {
                fits &= push(b);
            }
        } else {
            let mut i = 0isize;
            loop {
                // SAFETY: `p` is NUL-terminated.
                let c = unsafe { *p.offset(i) } as u8;
                if c == 0 {
                    break;
                }
                fits &= push(c);
                i += 1;
            }
        }
        if ptr::eq(p, filename) {
            for &b in b", " {
                fits &= push(b);
            }
        }
    }
    for &b in b")" {
        fits &= push(b);
    }
    if !fits {
        // Truncation: the engine reports -1 and `ERR_vset_error` stores "".
        buf[0] = 0;
        return 0;
    }
    buf[n] = 0;
    n
}

/// `int BIO_new_file(const char *filename, const char *mode)`
///
/// # Safety
/// `filename` and `mode` must be NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        if filename.is_null() || mode.is_null() {
            // The authority hands both to `fopen` and faults inside libc; total
            // by policy (docs/SECURITY_DIVERGENCE_POLICY.md).
            return ptr::null_mut();
        }
        // SAFETY: both are NUL-terminated per the caller's contract.
        let file = unsafe { sys::fopen(filename, mode) };
        let mut fp_flags = BIO_CLOSE;
        // SAFETY: `mode` is NUL-terminated.
        if !unsafe { has_byte(mode, b'b') } {
            fp_flags |= BIO_FP_TEXT;
        }
        if file.is_null() {
            // The authority reads errno once for the raised reason and again for
            // the follow-up test, and the intervening allocation may change it;
            // both reads are reproduced.
            // SAFETY: `errno` is thread-local.
            let err = unsafe { sys::errno() };
            let mut buf = [0 as c_char; ERR_MAX_DATA_SIZE];
            // SAFETY: both strings are NUL-terminated.
            unsafe { fopen_message(&mut buf, filename, mode) };
            // SAFETY: the site is a compile-time constant and `buf` is
            // NUL-terminated (or starts with NUL after truncation).
            unsafe { raise_site_dynamic_data(&BSS_FILE_67, err, buf.as_ptr()) };
            // SAFETY: `errno` is thread-local.
            let err2 = unsafe { sys::errno() };
            if err2 == sys::ENOENT || err2 == sys::ENXIO {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BSS_FILE_75) };
            } else {
                // SAFETY: as above.
                unsafe { raise_site(&BSS_FILE_77) };
            }
            return ptr::null_mut();
        }
        // SAFETY: `BIO_s_file` returns a static method table.
        let ret = unsafe { super::BIO_new(BIO_s_file()) };
        if ret.is_null() {
            // SAFETY: `file` came from `fopen` and is owned here.
            unsafe { sys::fclose(file) };
            return ptr::null_mut();
        }
        // `BIO_set_fp(b, fp, c)` is `BIO_ctrl(b, BIO_C_SET_FILE_PTR, c, fp)`.
        // SAFETY: `ret` is a fresh FILE BIO.
        unsafe { super::BIO_ctrl(ret, BIO_C_SET_FILE_PTR, fp_flags as c_long, file.cast()) };
        ret
    })
}

/// `BIO *BIO_new_fp(FILE *stream, int close_flag)`
///
/// # Safety
/// `stream` must be a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_fp(stream: *mut c_void, close_flag: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_s_file` returns a static method table.
        let ret = unsafe { super::BIO_new(BIO_s_file()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // The authority sets `BIO_FLAGS_UPLINK_INTERNAL`, which is 0 here.
        // SAFETY: `ret` is live; the flag constant is the authority's.
        unsafe { super::BIO_set_flags(ret, BIO_FLAGS_UPLINK_INTERNAL) };
        // SAFETY: `ret` is a fresh FILE BIO.
        unsafe { super::BIO_ctrl(ret, BIO_C_SET_FILE_PTR, close_flag as c_long, stream) };
        ret
    })
}

/// `file_new` — `bi->init = 0; bi->num = 0; bi->ptr = NULL; bi->flags = UPLINK`.
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn file_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 0;
        (*bi).num = 0;
        (*bi).ptr = ptr::null_mut();
        (*bi).flags = BIO_FLAGS_UPLINK_INTERNAL;
    }
    1
}

/// `file_free` — closes the stream only when `shutdown` and `init` and the
/// pointer are all set.
///
/// # Safety
/// `a` must be NULL or a live BIO.
unsafe extern "C" fn file_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live.
    if unsafe { (*a).shutdown != 0 } {
        // SAFETY: as above.
        let (init, p) = unsafe { ((*a).init, (*a).ptr) };
        if init != 0 && !p.is_null() {
            // SAFETY: `p` is a `FILE *` this BIO owns.
            unsafe { sys::fclose(p.cast()) };
            // SAFETY: as above.
            unsafe {
                (*a).ptr = ptr::null_mut();
                (*a).flags = BIO_FLAGS_UPLINK_INTERNAL;
            }
        }
        // SAFETY: as above.
        unsafe { (*a).init = 0 };
    }
    1
}

/// `file_read`
///
/// # Safety
/// `b` must be a live FILE BIO and `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn file_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    let mut ret = 0;
    // SAFETY: `b` is live.
    let (init, p) = unsafe { ((*b).init, (*b).ptr) };
    if init != 0 && !out.is_null() {
        // SAFETY: `out` is writable for `outl` bytes and `p` is a `FILE *`.
        ret = unsafe { sys::fread(out.cast(), 1, outl as usize, p.cast()) as c_int };
        if ret == 0 {
            // SAFETY: `p` is a `FILE *`.
            if unsafe { sys::ferror(p.cast()) } != 0 {
                // SAFETY: `errno` is thread-local.
                let e = unsafe { sys::errno() };
                // SAFETY: the sites are compile-time constants and the message a
                // static NUL-terminated string.
                unsafe {
                    raise_site_dynamic_data(&BSS_FILE_149, e, c"calling fread()".as_ptr());
                    raise_site(&BSS_FILE_151);
                }
                ret = -1;
            }
        }
    }
    ret
}

/// `file_write` — note the authority's inverted `fwrite` arguments: it writes
/// one item of `inl` bytes and only then converts the item count back to a byte
/// count, so a short write reports 0.
///
/// # Safety
/// `b` must be a live FILE BIO and `in_` readable for `inl` bytes or NULL.
unsafe extern "C" fn file_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    let mut ret = 0;
    // SAFETY: `b` is live.
    let (init, p) = unsafe { ((*b).init, (*b).ptr) };
    if init != 0 && !in_.is_null() {
        // SAFETY: `in_` is readable for `inl` bytes and `p` is a `FILE *`.
        ret = unsafe { sys::fwrite(in_.cast(), inl as usize, 1, p.cast()) as c_int };
        if ret != 0 {
            ret = inl;
        }
    }
    ret
}

/// `file_puts`
///
/// # Safety
/// `bp` must be a live FILE BIO and `s` NUL-terminated.
unsafe extern "C" fn file_puts(bp: *mut Bio, s: *const c_char) -> c_int {
    if s.is_null() {
        // The authority calls `strlen`, which faults; total by policy.
        return -1;
    }
    // SAFETY: `s` is NUL-terminated.
    let n = unsafe { sys::strlen(s) };
    if n > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `s` is readable for `n` bytes.
    unsafe { file_write(bp, s, n as c_int) }
}

/// `file_gets`
///
/// # Safety
/// `bp` must be a live FILE BIO and `buf` writable for `size` bytes.
unsafe extern "C" fn file_gets(bp: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    if buf.is_null() {
        // The authority stores `buf[0]`, which faults; total by policy.
        return 0;
    }
    // SAFETY: `buf` is writable for `size` bytes.
    unsafe { *buf = 0 };
    // SAFETY: `bp` is live and holds a `FILE *`.
    let p = unsafe { (*bp).ptr };
    // SAFETY: `buf` is writable for `size` and `p` is a `FILE *`.
    if unsafe { sys::fgets(buf, size, p.cast()) }.is_null() {
        return 0;
    }
    // SAFETY: `buf` is now NUL-terminated by `fgets`.
    let first = unsafe { *buf };
    if first != 0 {
        // SAFETY: as above.
        return unsafe { sys::strlen(buf) as c_int };
    }
    0
}

/// `file_ctrl`
///
/// # Safety
/// `b` must be a live FILE BIO and `ptr_` must match the control's contract.
unsafe extern "C" fn file_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr_: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    // SAFETY: `b` is live.
    let fp = unsafe { (*b).ptr };

    match cmd {
        BIO_C_FILE_SEEK | BIO_CTRL_RESET => {
            // SAFETY: `fp` is a `FILE *` for a BIO created by this method.
            ret = unsafe { sys::fseek(fp.cast(), num, sys::SEEK_SET) as c_long };
        }
        BIO_CTRL_EOF => {
            // SAFETY: as above.
            ret = unsafe { sys::feof(fp.cast()) as c_long };
        }
        BIO_C_FILE_TELL | BIO_CTRL_INFO => {
            // SAFETY: as above.
            ret = unsafe { sys::ftell(fp.cast()) as c_long };
        }
        BIO_C_SET_FILE_PTR => {
            // The destroy hook runs first, which closes the previous stream when
            // `shutdown` was set.
            // SAFETY: `b` is live.
            unsafe { file_free(b) };
            // SAFETY: `b` is live.
            unsafe {
                (*b).shutdown = (num & BIO_CLOSE as c_long) as c_int;
                (*b).ptr = ptr_;
                (*b).init = 1;
            }
        }
        BIO_C_SET_FILENAME => {
            // SAFETY: `b` is live.
            unsafe { file_free(b) };
            // SAFETY: as above.
            unsafe { (*b).shutdown = (num & BIO_CLOSE as c_long) as c_int };

            // The mode string is built from the flag word; the authority's buffer
            // is four bytes and no `b`/`t` suffix is appended off Windows.
            let mode: &[u8] = if num & BIO_FP_APPEND as c_long != 0 {
                if num & BIO_FP_READ as c_long != 0 {
                    b"a+\0"
                } else {
                    b"a\0"
                }
            } else if num & BIO_FP_READ as c_long != 0 && num & BIO_FP_WRITE as c_long != 0 {
                b"r+\0"
            } else if num & BIO_FP_WRITE as c_long != 0 {
                b"w\0"
            } else if num & BIO_FP_READ as c_long != 0 {
                b"r\0"
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BSS_FILE_284) };
                return 0;
            };

            // SAFETY: `ptr_` is the filename per the control's contract; `mode`
            // is a static NUL-terminated string.
            let fp = unsafe { sys::fopen(ptr_.cast(), mode.as_ptr().cast()) };
            if fp.is_null() {
                // SAFETY: `errno` is thread-local.
                let e = unsafe { sys::errno() };
                let mut buf = [0 as c_char; ERR_MAX_DATA_SIZE];
                // SAFETY: `ptr_` is NUL-terminated and `mode` is static.
                unsafe { fopen_message(&mut buf, ptr_.cast(), mode.as_ptr().cast()) };
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_site_dynamic_data(&BSS_FILE_299, e, buf.as_ptr());
                    raise_site(&BSS_FILE_302);
                }
                return 0;
            }
            // SAFETY: `b` is live.
            unsafe {
                (*b).ptr = fp.cast();
                (*b).init = 1;
            }
        }
        BIO_C_GET_FILE_PTR => {
            // The authority's UPLINK test is `0 == 0` here, so the pointer is
            // always handed out.
            if !ptr_.is_null() {
                // SAFETY: the control's contract says `ptr_` is a `FILE **`.
                unsafe { *(ptr_ as *mut *mut c_void) = fp };
            }
        }
        BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).shutdown as c_long };
        }
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` is live.
            unsafe { (*b).shutdown = num as c_int };
        }
        BIO_CTRL_FLUSH => {
            // SAFETY: `fp` is a `FILE *`.
            let st = unsafe { sys::fflush(fp.cast()) };
            if st == EOF {
                // SAFETY: `errno` is thread-local.
                let e = unsafe { sys::errno() };
                // SAFETY: the sites are compile-time constants and the message a
                // static string.
                unsafe {
                    raise_site_dynamic_data(&BSS_FILE_335, e, c"calling fflush()".as_ptr());
                    raise_site(&BSS_FILE_337);
                }
                ret = 0;
            }
        }
        BIO_CTRL_DUP => {
            ret = 1;
        }
        _ => {
            // BIO_CTRL_WPENDING, BIO_CTRL_PENDING, BIO_CTRL_PUSH, BIO_CTRL_POP
            // and everything unknown.
            ret = 0;
        }
    }
    ret
}
