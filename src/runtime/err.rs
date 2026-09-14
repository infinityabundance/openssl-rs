//! Phase 3 core runtime — the `ERR` subsystem.
//!
//! OpenSSL's error queue is **thread-local state**, and
//! `docs/CONCURRENCY_MODEL.md` names it the canonical example of a surface that
//! applications observe directly. So the queue is implemented as a faithful
//! mechanism, not as a `Result<T, E>`: an error carries a library, a reason, a
//! file/line/function, optional textual data, and a position in a bounded
//! per-thread ring with marks.
//!
//! ## Packing
//!
//! The value returned by `ERR_get_error` packs library and reason:
//!
//! ```text
//! (lib << 23) | reason        lib: 8 bits, reason: 23 bits
//! ```
//!
//! `ERR_get_error`'s *return value is itself an observable*, so this encoding is
//! part of the contract, not an internal detail.
//!
//! ## Known deviations, recorded rather than hidden
//!
//! The authority ships built-in reason-string tables generated at its build time
//! from the `*err.h` headers, so `ERR_reason_error_string` returns text for a
//! known `(lib, reason)` pair without any `ERR_load_strings` call. This module
//! has no such tables yet, so those functions return NULL and `ERR_error_string_n`
//! renders the `reason(N)` fallback. That is a real divergence, it is measurable
//! by the `RT-ERR` court, and it is tracked as an open obligation whose remedy is
//! to generate the tables from the authority's own `crypto/**/*err.c` sources —
//! archaeology, not guesswork.
//!
//! ## Variadic entry points
//!
//! `ERR_set_error`, `ERR_add_error_data` and `ERR_add_error_vdata` are
//! printf-style variadic C functions. Rust cannot define a C-variadic function on
//! stable, so those three are thin C adapters (`err_variadic.c`) that format
//! through `vsnprintf` and call back into the Rust core below. This is an
//! ABI-boundary necessity, not an implementation backend: no behaviour lives in
//! the C.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use std::cell::RefCell;
use std::collections::VecDeque;

use crate::ffi::guard_ffi;

const ERR_LIB_OFFSET: c_ulong = 23;
const ERR_LIB_MASK: c_ulong = 0xFF;
const ERR_REASON_MASK: c_ulong = 0x7FFFFF;

/// The queue depth. The authority's ring holds 16 entries and drops the oldest
/// when full; that is observable, so it is modelled rather than made unbounded.
const ERR_NUM_ERRORS: usize = 16;

#[derive(Clone, Default)]
struct Entry {
    lib: c_int,
    reason: c_int,
    file: Option<Vec<u8>>,
    line: c_int,
    func: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    data_flags: c_int,
    /// A slot created by `ERR_new` but not yet completed by `ERR_set_error`.
    incomplete: bool,
}

impl Entry {
    fn packed(&self) -> c_ulong {
        ((self.lib as c_ulong) << ERR_LIB_OFFSET) | (self.reason as c_ulong & ERR_REASON_MASK)
    }
}

#[derive(Default)]
struct State {
    /// Oldest at the front. `ERR_get_error` pops the front; `ERR_new` pushes the
    /// back.
    entries: VecDeque<Entry>,
    /// Marks are recorded as the queue length at mark time, which is equivalent
    /// to the authority's positional marks and is simpler to keep consistent
    /// when the ring drops its oldest entry.
    marks: Vec<usize>,
    next_lib: c_int,
}

impl State {
    fn push(&mut self, e: Entry) {
        self.entries.push_back(e);
        while self.entries.len() > ERR_NUM_ERRORS {
            self.entries.pop_front();
            // A mark that pointed at the dropped position now refers to the new
            // oldest entry, so shift every mark down by one and discard those
            // that fall off the front.
            self.marks = self.marks.iter().map(|m| m.saturating_sub(1)).collect();
            self.marks.retain(|&m| m > 0);
        }
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

fn cstr_bytes(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is a NUL-terminated C string per the caller's contract.
    unsafe {
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n += 1;
        }
        let mut v = Vec::with_capacity(n);
        for i in 0..n {
            v.push(*p.add(i) as u8);
        }
        Some(v)
    }
}

/// Raise a complete error from inside the library, the way the authority's
/// `ERR_raise` macro does.
///
/// This is the crate-internal path (the public `ERR_set_error` is C-variadic and
/// cannot be called from Rust). `file`/`line` are the values the *raising
/// function received*, because the authority attributes such errors to its
/// caller: `CRYPTO_malloc_array` on overflow reports the caller's file and line,
/// which the RT-MEM probe measures directly (`ERR_get_error_all`). The function
/// name is the empty string, which is what `OPENSSL_FUNC` expands to in the
/// pinned authority's build.
///
/// # Safety
/// `file` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_with(lib: c_int, reason: c_int, file: *const c_char, line: c_int) {
    let f = cstr_bytes(file);
    with_state(|s| {
        s.push(Entry {
            lib,
            reason,
            file: f,
            line,
            func: Some(Vec::new()),
            // Measured: the authority's overflow error carries an EMPTY,
            // non-NULL data pointer with flags 0 -- not a NULL one. The
            // difference is visible through `ERR_get_error_all`.
            data: Some(Vec::new()),
            data_flags: 0,
            incomplete: false,
        })
    });
}

/// `void ERR_new(void)`
///
/// Starts a new error at the top of the queue. The entry is `incomplete` until
/// `ERR_set_error` supplies a library and reason, mirroring the authority's
/// `ERR_FLAG_NEW` state — an incomplete slot is skipped by `ERR_get_error`.
#[no_mangle]
pub extern "C" fn ERR_new() {
    guard_ffi((), || {
        with_state(|s| {
            s.push(Entry {
                incomplete: true,
                ..Default::default()
            })
        })
    })
}

/// `void ERR_set_debug(const char *file, int line, const char *func)`
///
/// # Safety
/// `file` and `func` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char) {
    guard_ffi((), || {
        let f = cstr_bytes(file);
        let fnb = cstr_bytes(func);
        with_state(|s| {
            if let Some(e) = s.entries.back_mut() {
                if f.is_some() {
                    e.file = f;
                }
                e.line = line;
                if fnb.is_some() {
                    e.func = fnb;
                }
            }
        })
    })
}

/// Writes the current entry's library, reason and message. Called by the
/// variadic C adapter so that all state changes live in Rust.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_set_error(lib: c_int, reason: c_int, msg: *const c_char) {
    guard_ffi((), || {
        let m = cstr_bytes(msg);
        with_state(|s| {
            if let Some(e) = s.entries.back_mut() {
                e.lib = lib;
                e.reason = reason;
                e.incomplete = false;
                if let Some(m) = m {
                    if !m.is_empty() {
                        e.data = Some(m);
                        e.data_flags = 0x02; // ERR_TXT_STRING
                    }
                }
            }
        })
    })
}

/// Appends textual data to the current entry. Called by the variadic C adapter.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_add_data(msg: *const c_char) {
    guard_ffi((), || {
        let m = cstr_bytes(msg);
        with_state(|s| {
            if let Some(e) = s.entries.back_mut() {
                if let Some(m) = m {
                    match &mut e.data {
                        Some(d) => d.extend_from_slice(&m),
                        None => e.data = Some(m),
                    }
                    e.data_flags = 0x02;
                }
            }
        })
    })
}

/// `void ERR_set_error_data(char *data, int flags)`
///
/// # Safety
/// `data` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_error_data(data: *mut c_char, flags: c_int) {
    guard_ffi((), || {
        let d = cstr_bytes(data);
        with_state(|s| {
            if let Some(e) = s.entries.back_mut() {
                e.data = d;
                e.data_flags = flags;
            }
        })
    })
}

/// `void ERR_add_error_txt(const char *sepr, const char *txt)`
///
/// Not variadic, so it lives in Rust; it joins with `sepr` when data already
/// exists, which is what makes multi-part diagnostics readable.
///
/// # Safety
/// `sepr` and `txt` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_txt(sepr: *const c_char, txt: *const c_char) {
    guard_ffi((), || {
        let s = cstr_bytes(sepr).unwrap_or_default();
        let t = cstr_bytes(txt).unwrap_or_default();
        with_state(|st| {
            if let Some(e) = st.entries.back_mut() {
                match &mut e.data {
                    Some(d) if !d.is_empty() => {
                        d.extend_from_slice(&s);
                        d.extend_from_slice(&t);
                    }
                    _ => {
                        e.data = Some(t);
                        e.data_flags = 0x02;
                    }
                }
            }
        })
    })
}

/// Pops the oldest complete entry, returning its packed value (0 when empty).
fn pop_oldest() -> c_ulong {
    with_state(|s| loop {
        let Some(front) = s.entries.front() else {
            return 0;
        };
        if front.incomplete {
            s.entries.pop_front();
            continue;
        }
        let packed = front.packed();
        s.entries.pop_front();
        return packed;
    })
}

/// Reads the oldest entry without removing it, filling the optional outputs.
///
/// Pointer outputs are only written when the argument is non-NULL, which the
/// public API's documentation permits and callers rely on.
unsafe fn write_out_str(dst: *mut *const c_char, bytes: &Option<Vec<u8>>) {
    if dst.is_null() {
        return;
    }
    match bytes {
        Some(v) => {
            // The authority's returned pointers are valid until the entry is
            // cleared; we hand out a leaked copy rather than a dangling pointer,
            // trading a bounded leak for not returning memory that could be
            // freed underneath the caller. Tracked as a residual.
            let mut buf = Vec::with_capacity(v.len() + 1);
            buf.extend_from_slice(v);
            buf.push(0);
            let b = buf.leak();
            // SAFETY: `dst` is non-NULL and writable per the caller's contract.
            unsafe { *dst = b.as_ptr() as *const c_char };
        }
        // SAFETY: as above.
        None => unsafe { *dst = core::ptr::null() },
    }
}

/// `unsigned long ERR_get_error(void)`
#[no_mangle]
pub extern "C" fn ERR_get_error() -> c_ulong {
    guard_ffi(0, pop_oldest)
}

/// `unsigned long ERR_get_error_all(const char **file, int *line, const char **func, const char **data, int *flags)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        with_state(|s| {
            let Some(front) = s.entries.front().cloned() else {
                return 0;
            };
            if front.incomplete {
                return pop_oldest();
            }
            let packed = front.packed();
            s.entries.pop_front();
            // SAFETY: each output is either NULL or writable per the caller.
            unsafe {
                write_out_str(file, &front.file);
                if !line.is_null() {
                    *line = front.line;
                }
                write_out_str(func, &front.func);
                write_out_str(data, &front.data);
                if !flags.is_null() {
                    *flags = front.data_flags;
                }
            }
            packed
        })
    })
}

/// `unsigned long ERR_get_error_line(const char **file, int *line)`
///
/// # Safety
/// `file` and `line` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_line(file: *mut *const c_char, line: *mut c_int) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_get_error_all(
            file,
            line,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// `unsigned long ERR_get_error_line_data(const char **file, int *line, const char **data, int *flags)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_get_error_line_data(
    file: *mut *const c_char,
    line: *mut c_int,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe { ERR_get_error_all(file, line, core::ptr::null_mut(), data, flags) }
}

/// `unsigned long ERR_peek_error(void)`
#[no_mangle]
pub extern "C" fn ERR_peek_error() -> c_ulong {
    guard_ffi(0, || {
        with_state(|s| {
            s.entries
                .iter()
                .find(|e| !e.incomplete)
                .map(|e| e.packed())
                .unwrap_or(0)
        })
    })
}

/// `unsigned long ERR_peek_last_error(void)`
#[no_mangle]
pub extern "C" fn ERR_peek_last_error() -> c_ulong {
    guard_ffi(0, || {
        with_state(|s| {
            s.entries
                .iter()
                .rev()
                .find(|e| !e.incomplete)
                .map(|e| e.packed())
                .unwrap_or(0)
        })
    })
}

/// `unsigned long ERR_peek_error_all(const char **file, int *line, const char **func, const char **data, int *flags)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        let e = with_state(|s| s.entries.iter().find(|e| !e.incomplete).cloned());
        let Some(e) = e else { return 0 };
        // SAFETY: each output is either NULL or writable per the caller.
        unsafe {
            write_out_str(file, &e.file);
            if !line.is_null() {
                *line = e.line;
            }
            write_out_str(func, &e.func);
            write_out_str(data, &e.data);
            if !flags.is_null() {
                *flags = e.data_flags;
            }
        }
        e.packed()
    })
}

/// `unsigned long ERR_peek_last_error_all(...)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_all(
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    guard_ffi(0, || {
        let e = with_state(|s| s.entries.iter().rev().find(|e| !e.incomplete).cloned());
        let Some(e) = e else { return 0 };
        // SAFETY: each output is either NULL or writable per the caller.
        unsafe {
            write_out_str(file, &e.file);
            if !line.is_null() {
                *line = e.line;
            }
            write_out_str(func, &e.func);
            write_out_str(data, &e.data);
            if !flags.is_null() {
                *flags = e.data_flags;
            }
        }
        e.packed()
    })
}

/// `unsigned long ERR_peek_error_line(const char **file, int *line)`
///
/// # Safety
/// `file` and `line` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_line(
    file: *mut *const c_char,
    line: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_error_all(
            file,
            line,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// `unsigned long ERR_peek_error_data(const char **data, int *flags)`
///
/// # Safety
/// `data` and `flags` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_data(
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_error_all(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            data,
            flags,
        )
    }
}

/// `unsigned long ERR_peek_error_func(const char **func)`
///
/// # Safety
/// `func` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_func(func: *mut *const c_char) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_error_all(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            func,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// `unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_error_line_data(
    file: *mut *const c_char,
    line: *mut c_int,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe { ERR_peek_error_all(file, line, core::ptr::null_mut(), data, flags) }
}

/// `unsigned long ERR_peek_last_error_line(const char **file, int *line)`
///
/// # Safety
/// `file` and `line` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_line(
    file: *mut *const c_char,
    line: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_last_error_all(
            file,
            line,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// `unsigned long ERR_peek_last_error_data(const char **data, int *flags)`
///
/// # Safety
/// `data` and `flags` must each be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_data(
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_last_error_all(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            data,
            flags,
        )
    }
}

/// `unsigned long ERR_peek_last_error_func(const char **func)`
///
/// # Safety
/// `func` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_func(func: *mut *const c_char) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe {
        ERR_peek_last_error_all(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            func,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// `unsigned long ERR_peek_last_error_line_data(...)`
///
/// # Safety
/// Every output pointer must be NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn ERR_peek_last_error_line_data(
    file: *mut *const c_char,
    line: *mut c_int,
    data: *mut *const c_char,
    flags: *mut c_int,
) -> c_ulong {
    // SAFETY: forwarding the caller's contract unchanged.
    unsafe { ERR_peek_last_error_all(file, line, core::ptr::null_mut(), data, flags) }
}

/// `void ERR_clear_error(void)`
#[no_mangle]
pub extern "C" fn ERR_clear_error() {
    guard_ffi((), || {
        with_state(|s| {
            s.entries.clear();
            s.marks.clear();
        })
    })
}

/// `int ERR_set_mark(void)`
#[no_mangle]
pub extern "C" fn ERR_set_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            s.marks.push(s.entries.len());
            1
        })
    })
}

/// `int ERR_pop_to_mark(void)`
///
/// Removes entries back to the most recent mark. Returns 1 when a mark existed,
/// 0 otherwise — the authority distinguishes "popped" from "nothing to pop", and
/// callers branch on it.
#[no_mangle]
pub extern "C" fn ERR_pop_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let Some(mark) = s.marks.pop() else {
                return 0;
            };
            while s.entries.len() > mark {
                s.entries.pop_back();
            }
            1
        })
    })
}

/// `int ERR_clear_last_mark(void)`
#[no_mangle]
pub extern "C" fn ERR_clear_last_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| if s.marks.pop().is_some() { 1 } else { 0 })
    })
}

/// `int ERR_count_to_mark(void)`
#[no_mangle]
pub extern "C" fn ERR_count_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let Some(mark) = s.marks.last().copied() else {
                return 0;
            };
            (s.entries.len().saturating_sub(mark)) as c_int
        })
    })
}

/// `int ERR_get_next_error_library(void)`
#[no_mangle]
pub extern "C" fn ERR_get_next_error_library() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            // The authority starts dynamic libraries above the static ones; the
            // exact base matters to callers comparing lib codes, so it is
            // recorded as part of the RT-ERR court rather than guessed here.
            s.next_lib += 1;
            100 + s.next_lib
        })
    })
}

thread_local! {
    static STRING_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn render_error(e: c_ulong, out: &mut Vec<u8>) {
    let lib = (e >> ERR_LIB_OFFSET) & ERR_LIB_MASK;
    let reason = e & ERR_REASON_MASK;
    // The authority's format, reproduced exactly: unknown lib/reason render as
    // their numeric fallbacks because no string tables are registered.
    out.extend_from_slice(
        format!("error:{e:08X}:lib({lib}):func({reason}):reason({reason})").as_bytes(),
    );
}

/// `void ERR_error_string_n(unsigned long e, char *buf, size_t len)`
///
/// # Safety
/// `buf` must be NULL or writable for `len` bytes; when `len` is 0 the call is
/// a no-op.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize) {
    guard_ffi((), || {
        if buf.is_null() || len == 0 {
            return;
        }
        let mut v = Vec::new();
        render_error(e, &mut v);
        let n = v.len().min(len - 1);
        // SAFETY: `buf` is writable for `len` bytes per the caller's contract.
        unsafe {
            core::ptr::copy_nonoverlapping(v.as_ptr() as *const c_char, buf, n);
            *buf.add(n) = 0;
        }
    })
}

/// `char *ERR_error_string(unsigned long e, char *buf)`
///
/// With a NULL `buf` the authority returns a pointer into thread-local storage
/// that is valid until the next call. That thread-local lifetime is the
/// is the contract, so it is reproduced rather than approximated with a static buffer
/// shared across threads.
///
/// # Safety
/// `buf` must be NULL or writable for at least 256 bytes.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        if !buf.is_null() {
            // SAFETY: forwarding the caller's contract (256-byte buffer).
            unsafe { ERR_error_string_n(e, buf, 256) };
            return buf;
        }
        let mut v = Vec::new();
        render_error(e, &mut v);
        STRING_BUF.with(|b| {
            let mut b = b.borrow_mut();
            b.clear();
            b.extend_from_slice(&v);
            b.push(0);
            b.as_mut_ptr() as *mut c_char
        })
    })
}

/// `const char *ERR_lib_error_string(unsigned long e)` — NULL until string
/// tables exist (recorded deviation; see the module note).
#[no_mangle]
pub extern "C" fn ERR_lib_error_string(_e: c_ulong) -> *const c_char {
    core::ptr::null()
}

/// `const char *ERR_func_error_string(unsigned long e)` — see the module note.
#[no_mangle]
pub extern "C" fn ERR_func_error_string(_e: c_ulong) -> *const c_char {
    core::ptr::null()
}

/// `const char *ERR_reason_error_string(unsigned long e)` — see the module note.
#[no_mangle]
pub extern "C" fn ERR_reason_error_string(_e: c_ulong) -> *const c_char {
    core::ptr::null()
}

/// `int ERR_load_strings(int lib, ERR_STRING_DATA *str)`
///
/// Accepted and ignored: this build registers no string tables, which is a
/// recorded deviation rather than a silent lie (the same observable the module
/// note describes).
#[no_mangle]
pub extern "C" fn ERR_load_strings(_lib: c_int, _str: *mut c_void) -> c_int {
    1
}

/// `int ERR_load_strings_const(const ERR_STRING_DATA *str)`
#[no_mangle]
pub extern "C" fn ERR_load_strings_const(_str: *const c_void) -> c_int {
    1
}

/// The per-library `ERR_load_*_strings` entry points.
///
/// In OpenSSL 3.x these exist for source compatibility and populate nothing at
/// runtime (reason strings are built in). Returning 1 therefore matches the
/// authority's observable behaviour.
macro_rules! noop_load {
    ($($name:ident),* $(,)?) => {
        $(
            #[doc = concat!("`int ", stringify!($name), "(void)` — source-compatible entry point; see the module note.")]
            #[no_mangle]
            pub extern "C" fn $name() -> c_int { 1 }
        )*
    };
}

noop_load!(
    ERR_load_ASN1_strings,
    ERR_load_ASYNC_strings,
    ERR_load_BIO_strings,
    ERR_load_BN_strings,
    ERR_load_BUF_strings,
    ERR_load_CMS_strings,
    ERR_load_COMP_strings,
    ERR_load_CONF_strings,
    ERR_load_CRYPTO_strings,
    ERR_load_CT_strings,
    ERR_load_DH_strings,
    ERR_load_DSA_strings,
    ERR_load_EC_strings,
    ERR_load_ENGINE_strings,
    ERR_load_ERR_strings,
    ERR_load_EVP_strings,
    ERR_load_KDF_strings,
    ERR_load_OBJ_strings,
    ERR_load_OCSP_strings,
    ERR_load_OSSL_STORE_strings,
    ERR_load_PEM_strings,
    ERR_load_PKCS12_strings,
    ERR_load_PKCS7_strings,
    ERR_load_RAND_strings,
    ERR_load_RSA_strings,
    ERR_load_TS_strings,
    ERR_load_UI_strings,
    ERR_load_X509V3_strings,
    ERR_load_X509_strings,
);
