//! Phase 4 — the syslog BIO (`BIO_s_log`).
//!
//! `BIO_s_log` is a **write-only sink**: it has a write and a puts, no read and
//! no gets. Its contract is a small priority mapping in front of `syslog(3)`:
//! a line whose first characters match one of the authority's prefixes is logged
//! at that level and the *prefix is removed* before the message is sent, and a
//! line that matches nothing is logged at `LOG_ERR` with no prefix stripped.
//!
//! Two details matter for compatibility:
//!
//! * the table is terminated by an entry with length **0**, so the scan always
//!   stops there — an unmatched line is not an error, it is the default level;
//! * `BIO_s_log`'s method type is `BIO_TYPE_MEM`, not a dedicated log type. A
//!   caller that classifies BIOs by type sees the same value the authority gives
//!   it, which is why the constant is reused here rather than "corrected".
//!
//! The system log itself is not part of the comparison surface — it leaves the
//! process — but the return values, the method table, the `init`/`shutdown`
//! state and the control's return are, and `RT-BIO-FILE` observes those.
//!
//! On a platform without `syslog` the authority's `BIO_s_log` returns NULL
//! (`NO_SYSLOG`); this build has it, and a build without it would be a different
//! profile with a different obligation, not an edit here.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

use super::method::bwrite_conv;
use super::sys;
use super::{Bio, BioMethod, BIO_CTRL_SET, BIO_TYPE_MEM};

/// The method name the authority reports for the syslog BIO.
const LOG_NAME: &[u8] = b"syslog\0";

/// The identity passed to `openlog` by `slg_new`.
const LOG_IDENT: &[u8] = b"application\0";

/// `LOG_PID | LOG_CONS` — the options the authority passes to `openlog`.
const LOG_OPTIONS: c_int = 0x01 | 0x02;
/// `LOG_DAEMON`.
const LOG_DAEMON: c_int = 3 << 3;

const LOG_EMERG: c_int = 0;
const LOG_ALERT: c_int = 1;
const LOG_CRIT: c_int = 2;
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_NOTICE: c_int = 5;
const LOG_INFO: c_int = 6;
const LOG_DEBUG: c_int = 7;

/// The authority's prefix table, in its order. The final entry has length 0 and
/// is the default: an unmatched line keeps its whole text and logs at `LOG_ERR`.
const MAPPING: [(&[u8], c_int); 20] = [
    (b"PANIC ", LOG_EMERG),
    (b"EMERG ", LOG_EMERG),
    (b"EMR ", LOG_EMERG),
    (b"ALERT ", LOG_ALERT),
    (b"ALR ", LOG_ALERT),
    (b"CRIT ", LOG_CRIT),
    (b"CRI ", LOG_CRIT),
    (b"ERROR ", LOG_ERR),
    (b"ERR ", LOG_ERR),
    (b"WARNING ", LOG_WARNING),
    (b"WARN ", LOG_WARNING),
    (b"WAR ", LOG_WARNING),
    (b"NOTICE ", LOG_NOTICE),
    (b"NOTE ", LOG_NOTICE),
    (b"NOT ", LOG_NOTICE),
    (b"INFO ", LOG_INFO),
    (b"INF ", LOG_INFO),
    (b"DEBUG ", LOG_DEBUG),
    (b"DBG ", LOG_DEBUG),
    (b"", LOG_ERR),
];

/// A compiled-in method table. `BIO_s_log()` returns its address.
static LOG_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_MEM,
    name: LOG_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(slg_write),
    bread: None,
    bread_old: None,
    bputs: Some(slg_puts),
    bgets: None,
    ctrl: Some(slg_ctrl),
    create: Some(slg_new),
    destroy: Some(slg_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_log(void)`
#[no_mangle]
pub extern "C" fn BIO_s_log() -> *const BioMethod {
    guard_ffi(ptr::null(), || &LOG_METHOD)
}

/// `xopenlog`
///
/// # Safety
/// `name` must be NULL or NUL-terminated.
unsafe fn xopenlog(name: *const c_char, level: c_int) {
    // SAFETY: `name` is NULL or NUL-terminated per the caller's contract.
    unsafe { sys::openlog(name, LOG_OPTIONS, level) };
}

/// `xcloselog`
fn xcloselog() {
    // SAFETY: `closelog` takes no arguments and cannot fail.
    unsafe { sys::closelog() };
}

/// `slg_new` — opens the log with the authority's identity and facility.
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn slg_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 1;
        (*bi).num = 0;
        (*bi).ptr = ptr::null_mut();
    }
    // SAFETY: the ident is a static NUL-terminated string.
    unsafe { xopenlog(LOG_IDENT.as_ptr().cast(), LOG_DAEMON) };
    1
}

/// `slg_free`
///
/// # Safety
/// `a` must be NULL or a live BIO.
unsafe extern "C" fn slg_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    xcloselog();
    1
}

/// `slg_write` — pick the level from the prefix, strip it, and log.
///
/// # Safety
/// `b` must be a live log BIO and `in_` readable for `inl` bytes.
unsafe extern "C" fn slg_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    let _ = b;
    let ret = inl;
    if inl < 0 {
        return 0;
    }
    // The authority copies the input into a heap buffer and NUL-terminates it so
    // the prefix comparison and the logged text are NUL-safe.
    // SAFETY: the size is `inl + 1` and the allocation is freed below.
    let buf = CRYPTO_malloc((inl as usize) + 1, ptr::null(), 0).cast::<c_char>();
    if buf.is_null() {
        return 0;
    }
    // SAFETY: `in_` is readable for `inl` bytes and `buf` has `inl + 1`.
    unsafe {
        ptr::copy_nonoverlapping(in_, buf, inl as usize);
        *buf.add(inl as usize) = 0;
    }

    // The scan always terminates: the last entry's length is zero.
    let mut priority = LOG_ERR;
    let mut prefix_len = 0usize;
    for (prefix, level) in MAPPING.iter() {
        // SAFETY: `buf` is NUL-terminated; `prefix` may be empty (length 0), for
        // which the comparison is vacuously equal.
        let matched = unsafe {
            prefix.is_empty() || sys::strncmp(buf, prefix.as_ptr().cast(), prefix.len()) == 0
        };
        if matched {
            priority = *level;
            prefix_len = prefix.len();
            break;
        }
    }

    // SAFETY: `prefix_len <= inl`, so the pointer stays inside the allocation;
    // the format is a static string.
    unsafe {
        sys::syslog(priority, c"%s".as_ptr(), buf.add(prefix_len));
    }
    // SAFETY: `buf` came from `CRYPTO_malloc`.
    unsafe { CRYPTO_free(buf.cast(), ptr::null(), 0) };
    ret
}

/// `slg_ctrl` — always answers 0; `BIO_CTRL_SET` re-opens the log.
///
/// # Safety
/// `b` must be a live log BIO and `ptr` must be NULL or a NUL-terminated ident.
unsafe extern "C" fn slg_ctrl(_b: *mut Bio, cmd: c_int, num: c_long, ptr_: *mut c_void) -> c_long {
    if cmd == BIO_CTRL_SET {
        xcloselog();
        // SAFETY: `ptr_` is the ident per the control's contract.
        unsafe { xopenlog(ptr_.cast(), num as c_int) };
    }
    0
}

/// `slg_puts`
///
/// # Safety
/// `bp` must be a live log BIO and `s` NUL-terminated.
unsafe extern "C" fn slg_puts(bp: *mut Bio, s: *const c_char) -> c_int {
    if s.is_null() {
        // The authority calls `strlen`, which faults; total by policy.
        return -1;
    }
    // SAFETY: `s` is NUL-terminated.
    let n = unsafe { sys::strlen(s) };
    // SAFETY: `bp` is live and `s` is readable for `n` bytes.
    unsafe { slg_write(bp, s, n as c_int) }
}
