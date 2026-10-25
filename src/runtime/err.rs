//! Phase 3 core runtime — the `ERR` subsystem.
//!
//! OpenSSL's error queue is **thread-local state**, and
//! `docs/CONCURRENCY_MODEL.md` names it the canonical example of a surface that
//! applications observe directly. So the queue is implemented as a faithful
//! mechanism, not as a `Result<T, E>`: an error carries a library, a reason, a
//! file/line/function, optional textual data, and a position in a bounded
//! per-thread ring with marks.
//!
//! ## The ring is the public layout, so the ring is the store
//!
//! `ERR_STATE` is a **public structure** in `err.h` (guarded only by
//! `OPENSSL_NO_DEPRECATED_3_0`, which this profile does not define) and
//! `ERR_get_state` returns a pointer to it. A caller can therefore read
//! `es->top`, `es->bottom`, `es->err_buffer[i]`, `es->err_flags[i]` and so on
//! directly. That rules out keeping the queue in some private Rust collection
//! with a mirrored view: the ring *is* the representation here, matching the
//! authority slot for slot.
//!
//! ```text
//! ERR_new:  top = (top + 1) % 16 ; if top == bottom { bottom = (bottom + 1) % 16 }
//! ```
//!
//! The oldest error is at `(bottom + 1) % 16`, the newest at `top`, and a slot is
//! complete exactly when its `err_buffer` is non-zero. Sixteen slots therefore
//! hold fifteen usable errors, which is a real capacity detail rather than an
//! off-by-one to be "fixed".
//!
//! ## Packing
//!
//! `ERR_PACK(lib, func, reason)` discards `func` in 3.x and evaluates to
//! `(lib & 0xff) << 23 | (reason & 0x7fffff)`, so the value `ERR_get_error`
//! returns encodes only library and reason. `ERR_LIB_SYS` is special-cased to
//! `ERR_SYSTEM_FLAG | reason`. All of that is caller-observable and is
//! reproduced exactly.
//!
//! ## Strings
//!
//! The library and reason tables are compiled into the authority, but they are
//! **not** always visible: the registry starts empty and is populated by loaders
//! driven by initialisation (`docs/DECISIONS.md` D19). They are rebuilt from the
//! authority's own inputs by `forensics/tools/gen_err_strings.py` — the compiled
//! `*_err.c` arrays for the text, the headers for the codes — and verified
//! exhaustively by the RT-ERR court: every `(library, reason)` pair in the crypto
//! load set, every generic reason, all 357 SSL reasons on both sides of their
//! load flag, and the six reasons no loader loads. `ERR_func_error_string` is
//! unconditionally NULL in 3.x, and the rendered form is
//! `error:%08lX:lib:func:reason` with an `err:...` fallback when the pretty form
//! exactly fills the buffer, which is what `ERR_error_string_n` produces.
//!
//! ## Where a raise happened
//!
//! `ERR_raise` is a macro that records `OPENSSL_FILE`, `OPENSSL_LINE` and
//! `OPENSSL_FUNC` as well, and `ERR_get_error_all` hands them to the caller. They
//! are part of the observed contract and are reproduced exactly, from the
//! generated [`err_sites`] table
//! (`forensics/tools/gen_err_raise_sites.py`; `docs/DECISIONS.md` D20).
//!
//! ## Variadic entry points
//!
//! `ERR_set_error`, `ERR_vset_error` and `ERR_add_error_data` are printf-style
//! variadic C functions. Rust cannot *define* a C-variadic function on stable, so
//! those are thin C adapters (`err_variadic.c`) that format through `vsnprintf`
//! and call back into the Rust core below. All behaviour lives in Rust.
//!
//! ## Locking
//!
//! The state is reached through `UnsafeCell`, not a `RefCell`. That is not a
//! shortcut: the authority re-enters its own state from inside these operations
//! (a `CRYPTO_malloc` inside `err_set_debug`, for example), and a runtime borrow
//! check would turn that into a panic where the authority simply proceeds.
//!
//! Reentry is instead **refused** by a thread-local guard: while one `with_state`
//! closure holds `&mut ErrState`, a nested ERR call on the same thread returns
//! the "no state" outcome without touching the state. That covers the one
//! reentry edge this module cannot exclude by construction — a caller-installed
//! `CRYPTO_set_mem_functions` hook that calls back into ERR while the closure is
//! live — and turns what would be two aliasing `&mut` references into a defined
//! failure (the nested raise is dropped; the outer operation completes).

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::dso_shared;
use crate::runtime::init;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::mem_coords::SeamFile;

#[path = "err_strings.rs"]
mod err_strings;

#[path = "err_sites.rs"]
pub(crate) mod err_sites;

#[path = "err_reasons.rs"]
pub(crate) mod err_reasons;

#[path = "err_loaders.rs"]
mod err_loaders;

/// `ERR_NUM_ERRORS`. The ring depth. The authority's ring holds this many slots,
/// one of which is always the gap between `bottom` and `top`, so the usable
/// depth is one less.
const ERR_NUM_ERRORS: usize = 16;

/// `ERR_NUM_ERRORS` as the ring depth, for the sibling module that implements
/// `OSSL_ERR_STATE_*` — `crypto/err/err_save.c`'s Rust home. The two are in
/// different source files, as they are in the authority, so the constant is
/// re-exported rather than duplicated.
pub(crate) const ERR_STATE_SLOTS: usize = ERR_NUM_ERRORS;

/// `ERR_FLAG_MARK` — historical; marks live in `err_marks` in 3.x.
#[allow(dead_code)]
const ERR_FLAG_MARK: c_int = 0x01;
/// `ERR_TXT_MALLOCED` — the data buffer is owned by this state.
const ERR_TXT_MALLOCED: c_int = 0x01;
/// `ERR_TXT_STRING` — the data is a C string.
const ERR_TXT_STRING: c_int = 0x02;
/// `ERR_FLAG_CLEAR` — a slot marked for lazy clearing by the next read.
const ERR_FLAG_CLEAR: c_int = 0x02;

/// `ERR_TXT_MALLOCED` as a re-export, and `ERR_FLAG_CLEAR` with it, for the
/// sibling module that implements `OSSL_ERR_STATE_*` — `crypto/err/err_save.c`'s
/// Rust home. It reads both: `ERR_FLAG_CLEAR` to decide whether to skip a
/// lazily-cleared slot on `restore`, and `ERR_TXT_MALLOCED` to mark the copy it
/// makes of an attached buffer as owned.
pub(crate) const ERR_TXT_MALLOCED_FLAG: c_int = ERR_TXT_MALLOCED;
/// See [`ERR_TXT_MALLOCED_FLAG`].
pub(crate) const ERR_FLAG_CLEAR_FLAG: c_int = ERR_FLAG_CLEAR;

/// `void err_clear_last_constant_time(int clear)` — `crypto/err/err.c:875-891`.
///
/// **The flag is ORed in, and the operand is selected in constant time**, because the alternative —
/// an `if (clear)` — is a branch that an attacker measuring the OAEP decrypt path could observe.
/// The authority's own comment says why the record is *flagged* rather than removed here: removing
/// it would let a later error occupy the same slot and reveal timing information. `clear` is an
/// `int` that is `0` or `1`, and the authority reinterprets it through `constant_time_eq_int`, so
/// the mask is all-ones exactly when `clear` is zero.
///
/// The bounds check is a **transcription addition**, recorded as one: the authority indexes
/// `err_flags[top]` unguarded, and `top` is maintained in `0..ERR_NUM_ERRORS` by the state's own
/// code. A Rust index would panic rather than read adjacent memory if that invariant were ever
/// broken, and this crate forbids a panic on a published path, so an out-of-range `top` does
/// nothing instead of doing something undefined.
///
/// The caller is `RSA_padding_check_PKCS1_OAEP_mgf1`, which calls it **unconditionally after
/// raising** — a transcription that guarded it on `good` would get exactly the case the flag exists
/// for wrong. The type-2 check and the OAEP check both call it, so the `#[allow(dead_code)]` this
/// carried until D323's landing has been removed rather than left to outlive its reason.
pub(crate) fn err_clear_last_constant_time(clear: c_int) {
    use crate::runtime::constant_time::{constant_time_eq_int, constant_time_select_int};

    // The closure's return value is discarded: this function reports nothing, and the state is
    // absent only before the thread's first error, where the authority also returns early.
    let _ = with_state(|es| {
        let top = es.top;

        if top < 0 || top as usize >= ERR_NUM_ERRORS {
            return;
        }
        let mask = constant_time_select_int(constant_time_eq_int(clear, 0), 0, ERR_FLAG_CLEAR);

        es.err_flags[top as usize] |= mask;
    });
}

/// `ERR_LIB_SYS`, the one library whose errors are packed as system codes.
const ERR_LIB_SYS: c_int = 2;

/// `ERR_SYSTEM_MASK` (`err.h`): the low bits of a system error.
const ERR_SYSTEM_MASK: c_ulong = 0x7FFF_FFFF;

/// `ERR_SYSTEM_FLAG`.
const ERR_SYSTEM_FLAG: c_ulong = 0x8000_0000;
/// `ERR_RFLAGS_MASK` / `ERR_RFLAGS_OFFSET`, used to strip the flag bits from a
/// reason when rendering the numeric fallback.
const ERR_RFLAGS_MASK: c_ulong = 0x1F;
const ERR_RFLAGS_OFFSET: c_ulong = 18;

const ERR_LIB_OFFSET: c_ulong = 23;
const ERR_LIB_MASK: c_ulong = 0xFF;
const ERR_REASON_MASK: c_ulong = 0x7FFFFF;

/// The layout-compatible representation of C's `ERR_STATE`.
///
/// Public and documented in `err.h`, so every field offset matters. Field names
/// and order are taken from that header rather than chosen.
#[repr(C)]
pub struct ErrState {
    /// `int err_flags[ERR_NUM_ERRORS]`
    pub err_flags: [c_int; ERR_NUM_ERRORS],
    /// `int err_marks[ERR_NUM_ERRORS]` — per-slot mark counters.
    pub err_marks: [c_int; ERR_NUM_ERRORS],
    /// `unsigned long err_buffer[ERR_NUM_ERRORS]` — the packed error, 0 if the
    /// slot is incomplete.
    pub err_buffer: [c_ulong; ERR_NUM_ERRORS],
    /// `char *err_data[ERR_NUM_ERRORS]`
    pub err_data: [*mut c_char; ERR_NUM_ERRORS],
    /// `size_t err_data_size[ERR_NUM_ERRORS]`
    pub err_data_size: [usize; ERR_NUM_ERRORS],
    /// `int err_data_flags[ERR_NUM_ERRORS]`
    pub err_data_flags: [c_int; ERR_NUM_ERRORS],
    /// `char *err_file[ERR_NUM_ERRORS]`
    pub err_file: [*mut c_char; ERR_NUM_ERRORS],
    /// `int err_line[ERR_NUM_ERRORS]`
    pub err_line: [c_int; ERR_NUM_ERRORS],
    /// `char *err_func[ERR_NUM_ERRORS]`
    pub err_func: [*mut c_char; ERR_NUM_ERRORS],
    /// `int top` — where the next error goes.
    pub top: c_int,
    /// `int bottom` — the gap behind the oldest error.
    pub bottom: c_int,
}

impl ErrState {
    const fn new() -> Self {
        ErrState {
            err_flags: [0; ERR_NUM_ERRORS],
            err_marks: [0; ERR_NUM_ERRORS],
            err_buffer: [0; ERR_NUM_ERRORS],
            err_data: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            err_data_size: [0; ERR_NUM_ERRORS],
            err_data_flags: [0; ERR_NUM_ERRORS],
            err_file: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            err_line: [0; ERR_NUM_ERRORS],
            err_func: [core::ptr::null_mut(); ERR_NUM_ERRORS],
            top: 0,
            bottom: 0,
        }
    }

    /// `err_clear` over every slot. The opening move of `OSSL_ERR_STATE_free`
    /// (with `deall`), of `OSSL_ERR_STATE_save` (with `deall`) and of
    /// `OSSL_ERR_STATE_save_to_mark`'s no-thread-state arm (`crypto/err/err_save.c`).
    pub(crate) fn clear_all(&mut self, deall: bool) {
        for i in 0..ERR_NUM_ERRORS {
            self.clear(i, deall);
        }
    }

    /// A state with every field zero, the shape `memset(s, 0, sizeof(*s))` gives.
    ///
    /// Needed by `OSSL_ERR_STATE_save`, whose second step is exactly that `memset`
    /// over the thread's state after the ownership of its buffers has moved into
    /// the destination. `clear_all(false)` would **not** do: its documented
    /// behaviour for an owned buffer is to keep the pointer and truncate in place,
    /// which leaves the same buffer owned by two states — a double free, and one
    /// the RT-RUNTIME-EXT court found on a state reused across a clear. The
    /// authority's own comment says "just clear the thread state" while its code
    /// zeroes it, and the code is what a caller observes.
    ///
    /// `err_line` is therefore 0 here rather than the `-1` a cleared slot carries,
    /// which is also what the `memset` gives.
    pub(crate) fn zeroed() -> ErrState {
        ErrState::new()
    }

    /// The authority's `memcpy(es, thread_es, sizeof(*es))` in
    /// `OSSL_ERR_STATE_save`, written structurally so that the ownership of the
    /// attached data buffers moves with the slots instead of being duplicated.
    ///
    /// Written out field by field rather than derived, because a `Clone` would be
    /// the wrong operation here: the source is about to be zeroed, so exactly one
    /// state owns each buffer afterwards, and a derived `Clone` would make the
    /// operation look like a copy of an owned value when it is a transfer.
    pub(crate) fn copy_of(other: &ErrState) -> ErrState {
        ErrState {
            err_flags: other.err_flags,
            err_marks: other.err_marks,
            err_buffer: other.err_buffer,
            err_data: other.err_data,
            err_data_size: other.err_data_size,
            err_data_flags: other.err_data_flags,
            err_file: other.err_file,
            err_line: other.err_line,
            err_func: other.err_func,
            top: other.top,
            bottom: other.bottom,
        }
    }

    /// `err_get_slot`: advance `top`, and drag `bottom` forward once the ring is
    /// full. That one-slot gap is why fifteen errors survive, not sixteen.
    pub(crate) fn get_slot(&mut self) {
        let n = ERR_NUM_ERRORS as c_int;
        self.top = (self.top + 1) % n;
        if self.top == self.bottom {
            self.bottom = (self.bottom + 1) % n;
        }
    }

    /// `err_clear_data`. With `deall` the buffer is released; without it a
    /// malloced buffer is kept but truncated, which is how the authority reuses
    /// data buffers across clears.
    ///
    /// ## The `MALLOCED` slot contract
    ///
    /// The authority's `ERR_TXT_MALLOCED` (`include/openssl/err.h.in:52`) is the
    /// flag that selects `OPENSSL_free(es->err_data[i])` here
    /// (`crypto/err/err_local.h:25`); `err_set_data` selects the same release for
    /// the incumbent buffer at `:79`. That release is only sound when every
    /// writer establishes the matching precondition:
    ///
    /// * with `ERR_TXT_MALLOCED` set, a non-NULL pointer is the base of one whole block
    ///   from the crate's `CRYPTO_*` allocator seam (`CRYPTO_malloc`,
    ///   `CRYPTO_strdup`, or an authority helper that allocates through one of
    ///   them), its NUL-terminated contents fit within the allocated extent
    ///   (`strlen + 1` for the `ERR_set_error_data` path, which is also the exact
    ///   extent of a `CRYPTO_strdup` block), this state is its exclusive owner,
    ///   and the release below is its single `CRYPTO_free`;
    /// * without the flag the pointer is **borrowed**: it is never released here
    ///   and must remain valid and NUL-terminated until the entry is cleared or
    ///   replaced.
    ///
    /// Internal buffers are built by [`slot_buf_alloc`]. The only external
    /// writer is [`ERR_set_error_data`], whose `# Safety` states the same
    /// contract. The authority's own comment on that function records the
    /// ownership transfer: "callers should be advised that this function takes
    /// over ownership of the allocated memory" (`crypto/err/err.c:803-804`).
    pub(crate) fn clear_data(&mut self, i: usize, deall: bool) {
        if (self.err_data_flags[i] & ERR_TXT_MALLOCED) != 0 {
            if deall {
                // Release the buffer this slot owns; the handle's `Drop` is the release.
                // SAFETY: the MALLOCED flag says this state owns the pointer, and no other
                // handle has released it.
                unsafe {
                    drop(SlotStr::adopt(
                        self.err_data[i],
                        SeamFile::new(ERR_LOCAL_FILE),
                        L_FREE_DATA_DEALL,
                    ))
                };
                self.err_data[i] = core::ptr::null_mut();
                self.err_data_size[i] = 0;
                self.err_data_flags[i] = 0;
            } else if !self.err_data[i].is_null() {
                // SAFETY: as above; the buffer is at least one byte and is kept (not
                // released), so writing its first byte truncates it in place.
                unsafe { *self.err_data[i] = 0 };
                self.err_data_flags[i] = ERR_TXT_MALLOCED;
            }
        } else {
            self.err_data[i] = core::ptr::null_mut();
            self.err_data_size[i] = 0;
            self.err_data_flags[i] = 0;
        }
    }

    /// `err_clear`.
    pub(crate) fn clear(&mut self, i: usize, deall: bool) {
        self.clear_data(i, deall);
        self.err_marks[i] = 0;
        self.err_flags[i] = 0;
        self.err_buffer[i] = 0;
        self.err_line[i] = -1;
        // SAFETY: these pointers are always either NULL or owned by this state, and no
        // other handle has released them.
        unsafe {
            drop(SlotStr::adopt(
                self.err_file[i],
                SeamFile::new(ERR_LOCAL_FILE),
                L_FREE_FILE_CLEAR,
            ));
            self.err_file[i] = core::ptr::null_mut();
            drop(SlotStr::adopt(
                self.err_func[i],
                SeamFile::new(ERR_LOCAL_FILE),
                L_FREE_FUNC_CLEAR,
            ));
            self.err_func[i] = core::ptr::null_mut();
        }
    }

    /// `err_set_error`. System errors carry `ERR_SYSTEM_FLAG` instead of a
    /// packed library, and that difference is visible through `ERR_get_error`.
    ///
    /// The authority narrows to `unsigned int` here rather than masking to
    /// `ERR_REASON_MASK`, so a reason wider than the mask keeps its high bits.
    fn set_error(&mut self, i: usize, lib: c_int, reason: c_int) {
        self.err_buffer[i] = if lib == ERR_LIB_SYS {
            ((reason as u32) | (ERR_SYSTEM_FLAG as u32)) as c_ulong
        } else {
            pack(lib as c_ulong, reason as c_ulong)
        };
    }

    /// `err_set_debug`, the **install** half: the strings are already duplicated by the
    /// caller (see [`DebugParts`]), and the incumbent buffers are detached for release.
    ///
    /// Splitting the operation this way is what keeps every allocation out of the state
    /// borrow. The authority frees the incumbent before it allocates the replacement; here the
    /// allocation must precede the borrow, so it precedes the queued release too. Only the
    /// allocator-hook *order* differs, and only for the buffered strings.
    pub(crate) fn install_debug(&mut self, i: usize, line: c_int, parts: DebugParts) {
        // The slot's previous buffers are queued by `SlotStr::drop` (no seam call under the
        // borrow); each fresh duplicate was allocated before the borrow was taken.
        // SAFETY: these pointers are those `install_debug`/`clear` left in the slot: NULL or
        // owned by this state, and no other handle has released them.
        unsafe {
            drop(SlotStr::adopt(
                self.err_file[i],
                SeamFile::new(ERR_LOCAL_FILE),
                L_FREE_FILE_SET_DEBUG,
            ));
        }
        self.err_file[i] = match parts.file {
            Some(buf) => buf.into_raw(),
            None => core::ptr::null_mut(),
        };
        // SAFETY: as above, for the function slot.
        unsafe {
            drop(SlotStr::adopt(
                self.err_func[i],
                SeamFile::new(ERR_LOCAL_FILE),
                L_FREE_FUNC_SET_DEBUG,
            ));
        }
        self.err_func[i] = match parts.func {
            Some(buf) => buf.into_raw(),
            None => core::ptr::null_mut(),
        };
        self.err_line[i] = line;
    }

    /// `err_set_data`.
    ///
    /// Replacing a slot that already carries `ERR_TXT_MALLOCED` releases the
    /// incumbent block first, then installs `data`/`size`/`flags`. The new value
    /// must satisfy the slot contract documented on [`Self::clear_data`]: with
    /// `ERR_TXT_MALLOCED`, a non-NULL `data` is the base of one whole seam block with
    /// `strlen + 1` bytes of NUL-terminated contents, exclusively owned by this
    /// state and released exactly once by this state; without the flag, `data` is
    /// borrowed and must outlive the entry.
    pub(crate) fn set_data(&mut self, i: usize, data: *mut c_char, size: usize, flags: c_int) {
        if (self.err_data_flags[i] & ERR_TXT_MALLOCED) != 0 {
            // Release the buffer this slot already owned before adopting the new one.
            // SAFETY: the MALLOCED flag says this state owns the pointer and no other
            // handle has released it; the new `data` is adopted raw below.
            unsafe {
                drop(SlotStr::adopt(
                    self.err_data[i],
                    SeamFile::new(ERR_LOCAL_FILE),
                    L_FREE_DATA_REPLACE,
                ))
            };
        }
        self.err_data[i] = data;
        self.err_data_size[i] = size;
        self.err_data_flags[i] = flags;
    }

    /// The oldest index, `(bottom + 1) % 16`.
    fn oldest(&self) -> usize {
        ((self.bottom as usize) + 1) % ERR_NUM_ERRORS
    }

    /// Apply the pending `ERR_FLAG_CLEAR` slots, as `get_error_values` does
    /// before answering any read.
    fn settle_clears(&mut self) {
        let n = ERR_NUM_ERRORS as c_int;
        while self.bottom != self.top {
            if (self.err_flags[self.top as usize] & ERR_FLAG_CLEAR) != 0 {
                let t = self.top as usize;
                self.clear(t, false);
                self.top = if self.top > 0 { self.top - 1 } else { n - 1 };
                continue;
            }
            let i = (self.bottom + 1) % n;
            if (self.err_flags[i as usize] & ERR_FLAG_CLEAR) != 0 {
                self.bottom = i;
                let b = self.bottom as usize;
                self.clear(b, false);
                continue;
            }
            break;
        }
    }
}

// The state is only ever reached through the thread-local `STATE` (or the authority's
// per-thread `ERR_get_state`), so no `Sync` marker is claimed for it: the struct contains raw
// pointers and is deliberately not shareable. `thread_local!` needs only `'static`, and
// `StateCell` is `!Sync` (it holds an `UnsafeCell`), which is the correct shape for
// per-thread mutable state.

/// The empty C string stored in place of NULL so the read side can hand back a
/// non-NULL `""` without allocating, exactly as the authority does.
const EMPTY_C: *const c_char = c"".as_ptr();

/// `ERR_PACK(lib, 0, reason)`. The function field is discarded in 3.x.
fn pack(lib: c_ulong, reason: c_ulong) -> c_ulong {
    ((lib & ERR_LIB_MASK) << ERR_LIB_OFFSET) | (reason & ERR_REASON_MASK)
}

/// `ERR_GET_LIB`.
///
/// A system error does not carry a packed library; the authority answers
/// `ERR_LIB_SYS` for it, which is why `ERR_lib_error_string(0x80000002)` renders
/// as "system library" rather than as library 0.
fn get_lib(e: c_ulong) -> c_ulong {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        ERR_LIB_SYS as c_ulong
    } else {
        (e >> ERR_LIB_OFFSET) & ERR_LIB_MASK
    }
}

/// `ERR_GET_REASON`.
fn get_reason(e: c_ulong) -> c_ulong {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        e & ERR_SYSTEM_MASK
    } else {
        e & ERR_REASON_MASK
    }
}

/// `ERR_GET_REASON(ERR_peek_error())` — the reason code of the queue's **first** entry.
///
/// The first-entry twin of [`peek_last_reason`], and the one `crypto/pem/pem_lib.c`'s
/// `pem_bytes_read_bio_flags` needs: it asks whether the reader's *oldest* queued error is
/// `PEM_R_NO_START_LINE` — meaning it scanned to end-of-input without finding a BEGIN line —
/// and, when it is, appends the name it was looking for. Reading the newest entry instead
/// would answer a different question on a queue holding more than one record.
///
/// # Safety
///
/// There is no precondition: the function takes no arguments and touches only the
/// calling thread's own queue.
pub(crate) fn peek_first_reason() -> c_ulong {
    let e = ERR_peek_error();
    if e == 0 {
        0
    } else {
        get_reason(e)
    }
}

/// `ERR_GET_REASON(ERR_peek_last_error())` — the reason code of the queue's last entry.
///
/// Exists because one caller has to *branch* on a reason rather than report it:
/// `asn1_d2i_read_bio` asks whether a header `ASN1_get_object` rejected was merely
/// `ASN1_R_TOO_LONG` — recoverable, because the buffer has not received the whole length
/// yet — or a genuinely malformed header.
///
/// # Safety
///
/// There is no precondition: the function takes no arguments and touches only the
/// calling thread's own queue.
pub(crate) fn peek_last_reason() -> c_ulong {
    let e = ERR_peek_last_error();
    if e == 0 {
        0
    } else {
        get_reason(e)
    }
}

/// `ERR_GET_LIB(ERR_peek_last_error())` — the library code of the queue's last entry.
///
/// The companion of [`peek_last_reason`], for the same kind of caller: `crypto/rsa/
/// rsa_gen.c`'s multi-prime generator has to distinguish "this prime has no inverse
/// modulo `e`, so draw another" from any other failure, and the authority spells that
/// test `ERR_GET_LIB(error) == ERR_LIB_BN && ERR_GET_REASON(error) == BN_R_NO_INVERSE`.
///
/// # Safety
///
/// There is no precondition: the function takes no arguments and touches only the
/// calling thread's own queue.
pub(crate) fn peek_last_lib() -> c_ulong {
    let e = ERR_peek_last_error();
    if e == 0 {
        0
    } else {
        get_lib(e)
    }
}

/// The `__FILE__`/`__LINE__` the error-state **allocations** record.
///
/// The authority allocates every per-slot buffer and the `ERR_STATE` block by calling
/// `CRYPTO_malloc`/`CRYPTO_zalloc` with the literal `NULL, 0` (the header's
/// `CRYPTO_malloc(..., NULL, 0)` in `err_local.h` and the explicit `NULL, 0` in `err_save.c`),
/// so those allocations record the inert coordinates. **Releases are not symmetric**: they go
/// through `OPENSSL_free`, which records `OPENSSL_FILE`/`OPENSSL_LINE` at the `err_local.h` or
/// `err.c` site that performs them. The release coordinates are therefore separate constants
/// below; one `NULL`/`0` pair is not the contract for both halves.
const ERR_FILE: *const c_char = core::ptr::null();
const ERR_LINE: c_int = 0;

/// `err_local.h` and `err.c` are the files whose `OPENSSL_free`/`CRYPTO_free` calls release a
/// slot buffer and the state block. Both are plain source-tree files, so `__FILE__` carries the
/// admitted build's prefix.
const ERR_LOCAL_FILE: &core::ffi::CStr = c"../../src/openssl-3.6.4/crypto/err/err_local.h";
const ERR_C_FILE: &core::ffi::CStr = c"../../src/openssl-3.6.4/crypto/err/err.c";

/// `err_clear_data`'s `OPENSSL_free(es->err_data[i])` — `err_local.h:25`.
const L_FREE_DATA_DEALL: c_int = 25;
/// `err_set_debug`'s `OPENSSL_free(es->err_file[i])` — `err_local.h:56`.
const L_FREE_FILE_SET_DEBUG: c_int = 56;
/// `err_set_debug`'s `OPENSSL_free(es->err_func[i])` — `err_local.h:66`.
const L_FREE_FUNC_SET_DEBUG: c_int = 66;
/// `err_set_data`'s replacement release — `err_local.h:79`.
const L_FREE_DATA_REPLACE: c_int = 79;
/// `err_clear`'s `OPENSSL_free(es->err_file[i])` — `err_local.h:92`.
const L_FREE_FILE_CLEAR: c_int = 92;
/// `err_clear`'s `OPENSSL_free(es->err_func[i])` — `err_local.h:94`.
const L_FREE_FUNC_CLEAR: c_int = 94;
/// `OSSL_ERR_STATE_free`'s `CRYPTO_free(state, OPENSSL_FILE, OPENSSL_LINE)` — `err.c:209`.
const L_FREE_STATE: c_int = 209;

// A per-slot buffer: the allocation a ring slot keeps in `err_data` (when
// `ERR_TXT_MALLOCED`), `err_file` or `err_func`, owned by `SlotStr`.
//
// The slot keeps the authority's `#[repr(C)]` raw `*mut c_char` — that layout is public and
// cannot change — so ownership crosses the slot as a raw pointer. `SlotStr` allocates and
// releases through the **process-global** `CRYPTO_*` seam (libcrypto's exported entry points,
// resolved once) rather than this DSO's private copy: the ring is shared across DSOs, so a
// buffer written by libssl can be released by libcrypto's `ERR_clear_error` and must come from
// the same allocator table the application's `CRYPTO_set_mem_functions` hook writes. Using the
// local copy made that release an invalid free under an installed hook. `slot_buf_alloc` and
// `dup_c` are the only allocating constructors; `SlotStr::into_raw` stores one into a slot and
// `SlotStr::adopt` reclaims a slot's pointer for release. The recorded `__FILE__`/`__LINE__`
// are unchanged, so the hook observes the same file and line as it observes for the
// authority's own `err_*` helpers: `NULL`/`0` for allocations and the `err_local.h` site for
// each release.

/// A per-slot buffer owned by the process-wide error ring.
///
/// The release is `CRYPTO_free` at the authority's `err_local.h` site for the operation that
/// dropped the slot; both halves are the process-global seam, so the block is always
/// `OPENSSL_free`-able by whichever DSO's `clear`/`set_debug`/`set_data` runs.
pub(crate) struct SlotStr {
    ptr: *mut c_char,
    file: SeamFile,
    line: c_int,
}

impl SlotStr {
    /// `CRYPTO_malloc(len, NULL, 0)`, or `None` when the seam answers NULL (the authority's
    /// refused allocation).
    fn new(len: usize) -> Option<SlotStr> {
        // SAFETY: the allocation coordinate is NULL per this constructor's contract.
        let raw = unsafe { dso_shared::crypto_malloc(len, SeamFile::NULL.as_ptr(), ERR_LINE) }
            .cast::<c_char>();
        if raw.is_null() {
            return None;
        }
        Some(SlotStr {
            ptr: raw,
            file: SeamFile::NULL,
            line: ERR_LINE,
        })
    }

    /// Adopt a slot pointer for release, or `None` for NULL (the authority's no-op
    /// `free(NULL)`).
    ///
    /// # Safety
    /// `ptr` is NULL or the base of one whole block the process-global `CRYPTO_*` seam
    /// allocated, exclusively owned by the calling state, and `file`/`line` name the
    /// authority's own plain `CRYPTO_free` site for it.
    unsafe fn adopt(ptr: *mut c_char, file: SeamFile, line: c_int) -> Option<SlotStr> {
        if ptr.is_null() {
            None
        } else {
            Some(SlotStr { ptr, file, line })
        }
    }

    /// The writable block, for the constructor that fills it.
    pub(crate) fn as_ptr(&self) -> *mut c_char {
        self.ptr
    }

    /// Give the block to a ring slot; the slot's later `adopt` is its single release.
    pub(crate) fn into_raw(self) -> *mut c_char {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl SlotStr {
    /// Release this block now. Called either when no state borrow is live, or by the deferred
    /// flush, which runs after the borrow has ended.
    fn release_now(mut self) {
        let p = core::mem::replace(&mut self.ptr, core::ptr::null_mut());
        if !p.is_null() {
            // SAFETY: `p` is a live seam block this handle exclusively owns, and `file`/`line`
            // are the authority's release coordinates for the dropping operation.
            unsafe { dso_shared::crypto_free(p.cast(), self.file.as_ptr(), self.line) };
        }
    }
}

impl Drop for SlotStr {
    fn drop(&mut self) {
        if state_borrowed() {
            // A `&mut ErrState` is live in this DSO. Releasing here would run the process-global
            // `CRYPTO_free` (and an application's installed `free` hook) under that borrow; the
            // hook could re-enter ERR and form a second borrow. Queue instead: `with_state`
            // flushes the queue after the borrow ends.
            let queued = PENDING_RELEASES
                .try_with(|q| match q.try_borrow_mut() {
                    Ok(mut q) => {
                        q.push(SlotStr {
                            ptr: self.ptr,
                            file: self.file,
                            line: self.line,
                        });
                        true
                    }
                    Err(_) => false,
                })
                .unwrap_or(false);
            if queued {
                self.ptr = core::ptr::null_mut();
                return;
            }
        }
        let p = self.ptr;
        if !p.is_null() {
            // SAFETY: `p` is a live seam block this handle exclusively owns, and `file`/`line`
            // are the authority's release coordinates for the dropping operation.
            unsafe { dso_shared::crypto_free(p.cast(), self.file.as_ptr(), self.line) };
        }
        self.ptr = core::ptr::null_mut();
    }
}

/// The duplicated strings `install_debug` needs, built **before** the state borrow is taken.
///
/// `err_set_debug` duplicates both strings. Doing that through [`dup_c`] can allocate through
/// the process-global seam, whose failure path may raise another error; that must happen while
/// no `&mut ErrState` is live, or the nested raise would form a second borrow (in the other DSO
/// has no guard for this one).
pub(crate) struct DebugParts {
    pub(crate) file: Option<SlotStr>,
    pub(crate) func: Option<SlotStr>,
}

/// Duplicate the file/function strings for a raise, before entering `with_state`.
///
/// # Safety
/// `file`/`func` are NULL or NUL-terminated C strings.
pub(crate) unsafe fn debug_parts(file: *const c_char, func: *const c_char) -> DebugParts {
    DebugParts {
        // SAFETY: each pointer is NULL or NUL-terminated per the caller's contract.
        file: unsafe { dup_c(file) },
        // SAFETY: as above.
        func: unsafe { dup_c(func) },
    }
}

/// An owned copy of an error message, built before entering `with_state`.
///
/// Returns the buffer and its extent (`strlen + 1`), or `None` for NULL/empty/refused/overflow.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
pub(crate) unsafe fn message_copy(msg: *const c_char) -> Option<(SlotStr, usize)> {
    if msg.is_null() {
        return None;
    }
    // SAFETY: `msg` is NUL-terminated per the caller's contract.
    let len = unsafe { c_strlen(msg) };
    let alloc = len.checked_add(1)?;
    let buf = slot_buf_alloc(alloc)?;
    // SAFETY: `buf` is `len + 1` fresh bytes and `msg` is valid for `len`.
    unsafe {
        core::ptr::copy_nonoverlapping(msg, buf.as_ptr(), len);
        *buf.as_ptr().add(len) = 0;
    }
    Some((buf, len + 1))
}

/// Allocate a fresh slot buffer of `len` bytes through the process-global allocator at the
/// inert `NULL`/`0` coordinates, or `None` when it answers NULL (the authority's refused
/// `CRYPTO_malloc`).
pub(crate) fn slot_buf_alloc(len: usize) -> Option<SlotStr> {
    SlotStr::new(len)
}

/// A NUL-terminated duplicate of `s`, or `None` for NULL or empty input — the rule
/// `err_set_debug` applies to the file and function strings.
///
/// # Safety
/// `s` must be NULL or a NUL-terminated C string.
unsafe fn dup_c(s: *const c_char) -> Option<SlotStr> {
    if s.is_null() {
        return None;
    }
    // SAFETY: `s` is NUL-terminated per the caller's contract.
    let len = unsafe { c_strlen(s) };
    if len == 0 {
        return None;
    }
    let buf = slot_buf_alloc(len + 1)?;
    // SAFETY: `buf` is `len + 1` fresh bytes and `s` is valid for `len`.
    unsafe {
        core::ptr::copy_nonoverlapping(s, buf.as_ptr(), len);
        *buf.as_ptr().add(len) = 0;
    }
    Some(buf)
}

/// An owned heap `ERR_STATE`.
///
/// The authority's `OSSL_ERR_STATE_new` allocates the block with
/// `CRYPTO_zalloc(sizeof(ERR_STATE), NULL, 0)` and `OSSL_ERR_STATE_free` releases every owned
/// per-slot buffer and then the block. Ownership is this type: `new` allocates through the
/// crate's allocator seam and `Drop` runs the authority's own free body ([`ErrState::clear_all`]
/// with `deall`) followed by the block release, through the same seam. The `#[repr(C)]` layout,
/// the stable address the C ABI hands out and takes back, and the recorded `__FILE__`/`__LINE__`
/// of both the allocation and the release are unchanged, so a caller's
/// `CRYPTO_set_mem_functions` hook observes the same size, file and sequence.
///
/// The **thread-local** state is not governed by this type: it is a [`StateCell`] whose
/// `Drop` releases the per-slot buffers the ring still owns at thread exit, without
/// releasing the enclosing block (which lives in thread-local storage). Keeping the two
/// releases separate is what preserves the authority's `OSSL_ERR_STATE_free` sequence —
/// buffers first, then the block — while the block itself is never heap-allocated here.
pub(crate) struct OwnedErrState {
    ptr: ptr::NonNull<ErrState>,
}

impl OwnedErrState {
    /// Allocate a fresh, zeroed state through the installed allocator, or `None` when it answers
    /// NULL (the authority's refused `CRYPTO_zalloc`).
    pub(crate) fn new() -> Option<OwnedErrState> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block
        // of `size_of::<ErrState>()` bytes, which is exactly the layout the C ABI expects.
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_zalloc(core::mem::size_of::<ErrState>(), ERR_FILE, ERR_LINE)
        }
        .cast::<ErrState>();
        ptr::NonNull::new(raw).map(|ptr| OwnedErrState { ptr })
    }

    /// Give up ownership of the block to the C caller's state pointer.
    pub(crate) fn into_raw(self) -> *mut ErrState {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim a block a previous `into_raw` handed to the C caller, for release by `Drop`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live block a previous `into_raw` gave up and `Drop` has not released.
    pub(crate) unsafe fn from_raw(ptr: *mut ErrState) -> Option<OwnedErrState> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedErrState { ptr })
    }
}

impl Drop for OwnedErrState {
    /// The authority's `OSSL_ERR_STATE_free` body: every slot is cleared with `deall` — its
    /// owned buffers released — and then the block is released, through the same allocator seam
    /// it was allocated on.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `new` allocated (or `from_raw` reclaimed) and this is
        // its single release; `clear_all(true)` is the authority's own free body, releasing each
        // owned per-slot buffer first.
        unsafe {
            (*self.ptr.as_ptr()).clear_all(true);
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                ERR_C_FILE.as_ptr(),
                L_FREE_STATE,
            );
        }
    }
}

/// # Safety
/// `s` must be a NUL-terminated C string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: NUL-terminated, so the loop leaves the allocation.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// The per-thread error state storage.
///
/// `UnsafeCell` rather than `RefCell` because these operations legitimately re-enter the
/// state (see the module note). The wrapper exists for its `Drop`: the authority's
/// per-thread state is released when the thread ends, and an unwrapped `UnsafeCell<ErrState>`
/// needs no drop, so `thread_local!` registered **no** destructor and the buffers the ring
/// still owned at exit were never released (V3's ASan leak of the last queued entry from
/// `raise_site_dynamic_data`).
///
/// The destructor runs the authority's own `OSSL_ERR_STATE_free` opening move,
/// [`ErrState::clear_all`]`(true)`, which releases every owned `err_data`/`err_file`/`err_func`
/// buffer and NULLs the slot. It deliberately does **not** release the enclosing block: that
/// block *is* this thread-local and is reclaimed by the TLS machinery. Because every release
/// NULLs its slot, a later thread-exit clear after an explicit `ERR_clear_error` (which keeps
/// a malloced data buffer by truncating it in place) frees each block exactly once.
struct StateCell(UnsafeCell<ErrState>);

impl StateCell {
    const fn new() -> StateCell {
        StateCell(UnsafeCell::new(ErrState::new()))
    }
}

impl Drop for StateCell {
    fn drop(&mut self) {
        // SAFETY: thread exit gives this thread exclusive access to its own state, and this
        // is its single teardown. `clear_all(true)` releases each owned buffer exactly once
        // and leaves the slot NULL; `crypto_free` cannot re-enter this state because the TLS
        // key is already `Destroyed`, so `ERR_get_state` answers NULL and `with_state`
        // refuses. The enclosing block is thread-local storage and is not released here.
        unsafe { (*self.0.get()).clear_all(true) };
    }
}

thread_local! {
    /// The per-thread error state. See [`StateCell`] for the teardown obligation.
    static STATE: StateCell = const { StateCell::new() };
    /// Whether this thread has already performed the authority's per-thread
    /// state creation, which is what loads the crypto error strings.
    static STATE_READY: Cell<bool> = const { Cell::new(false) };
    /// Whether this thread currently holds the `&mut ErrState` that `with_state`
    /// hands its closure. A nested ERR call sees `true` and is refused instead
    /// of forming a second `&mut` (NEO-ERR-7).
    static STATE_IN_USE: Cell<bool> = const { Cell::new(false) };
    /// Slot buffers detached while a `with_state` borrow is live. Their release is deferred to
    /// the end of the borrow, so no process-global `CRYPTO_free` (and no application free hook)
    /// runs while `&mut ErrState` is held. The `Vec` is an ordinary Rust allocation: it cannot
    /// re-enter ERR.
    static PENDING_RELEASES: RefCell<Vec<SlotStr>> = const { RefCell::new(Vec::new()) };
}

/// Whether this DSO currently holds the `&mut ErrState` that `with_state` hands its closure.
pub(crate) fn state_borrowed() -> bool {
    STATE_IN_USE.try_with(|b| b.get()).unwrap_or(false)
}

/// Release every queued slot buffer. Runs with the borrow already ended (normally from
/// `with_state`'s exit guard, or explicitly after `f` returns).
fn flush_pending_releases() {
    let pending = PENDING_RELEASES
        .try_with(|q| core::mem::take(&mut *q.borrow_mut()))
        .ok();
    if let Some(queued) = pending {
        for handle in queued {
            handle.release_now();
        }
    }
}

/// Flushes [`PENDING_RELEASES`] on every exit path, including an unwinding closure. Declared
/// **before** [`StateAccessGuard`] in `with_state`, so it drops after the guard has cleared the
/// borrow flag.
struct PendingReleaseGuard;

impl Drop for PendingReleaseGuard {
    fn drop(&mut self) {
        flush_pending_releases();
    }
}

/// Clears [`STATE_IN_USE`] on every exit path, including an unwinding closure.
struct StateAccessGuard;

impl StateAccessGuard {
    /// Take the thread's state-access slot, or `None` when this thread already
    /// holds it (a reentrant call) or the thread-local is being destroyed.
    fn enter() -> Option<StateAccessGuard> {
        STATE_IN_USE
            .try_with(|in_use| {
                if in_use.replace(true) {
                    None
                } else {
                    Some(StateAccessGuard)
                }
            })
            .ok()
            .flatten()
    }
}

impl Drop for StateAccessGuard {
    fn drop(&mut self) {
        let _ = STATE_IN_USE.try_with(|in_use| in_use.set(false));
    }
}

// ---------------------------------------------------------------------------
// The string registry is loaded, not compiled in
// ---------------------------------------------------------------------------
//
// The authority's `int_error_hash` starts empty. `ossl_err_get_state_int`
// creates a thread's `ERR_STATE` and then runs
// `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS)` -- "ignore failures
// from these" -- which loads the generic tables and every library in
// `ossl_err_load_crypto_strings`. SSL is deliberately not in that set; its
// strings appear only when `OPENSSL_INIT_LOAD_SSL_STRINGS` is processed. Both
// facts are observable through `ERR_reason_error_string`, and the RT-ERR probe
// measures them, including the window before any ERR call has run at all.

/// The generic tables (`ERR_str_libraries`, `ERR_str_reasons`) have been loaded.
static GENERIC_LOADED: AtomicBool = AtomicBool::new(false);
/// Bit `lib` set means that library's reason table has been loaded.
static LIB_LOADED: AtomicU64 = AtomicU64::new(0);

/// `ERR_LIB_SSL`. Its table arrives through a different initialisation flag.
const ERR_LIB_SSL: u32 = 20;

/// Load the generic tables. `ossl_err_load_ERR_strings`. Idempotent.
pub(crate) fn load_generic() {
    GENERIC_LOADED.store(true, Ordering::Release);
}

/// Load one library's reason table. Idempotent.
pub(crate) fn load_lib(lib: u32) {
    load_generic();
    if lib < 64 {
        LIB_LOADED.fetch_or(1u64 << lib, Ordering::AcqRel);
    }
}

/// `ossl_err_load_crypto_strings` — the generic tables plus the crypto set.
pub(crate) fn load_crypto_strings() {
    load_generic();
    let mut mask = 0u64;
    for &lib in err_strings::CRYPTO_LIBS {
        if (lib as u32) < 64 {
            mask |= 1u64 << lib;
        }
    }
    LIB_LOADED.fetch_or(mask, Ordering::AcqRel);
}

/// `ossl_err_load_SSL_strings` — the generic tables plus library 20.
pub(crate) fn load_ssl_strings() {
    load_lib(ERR_LIB_SSL);
}

/// `err_cleanup` — the registry is torn down, so nothing is visible afterwards.
pub(crate) fn unload_strings() {
    GENERIC_LOADED.store(false, Ordering::Release);
    LIB_LOADED.store(0, Ordering::Release);
}

fn generic_loaded() -> bool {
    GENERIC_LOADED.load(Ordering::Acquire)
}

fn lib_loaded(lib: u32) -> bool {
    lib < 64 && (LIB_LOADED.load(Ordering::Acquire) & (1u64 << lib)) != 0
}

/// Run `f` with this thread's error state. `None` during thread teardown and
/// after `OPENSSL_cleanup`, both of which the authority treats as "no state":
/// `ossl_err_get_state_int` returns NULL once `OPENSSL_init_crypto` refuses.
/// `void err_free_strings_int(void)`
///
/// The authority's body is a comment:
///
/// ```c
/// void err_free_strings_int(void)
/// {
///     /* obsolete */
/// }
/// ```
///
/// It is exported because a precompiled binary may resolve it, and its
/// *behaviour* is that it does nothing — including doing nothing to the string
/// registry, which `ERR_clear_error`-adjacent callers might otherwise expect it
/// to release. Reproduced as an empty body rather than removed, because the
/// symbol's presence is part of the ABI and its emptiness is part of the
/// contract.
#[no_mangle]
pub extern "C" fn err_free_strings_int() {}

/// Run `f` with this thread's error state.
///
/// ## Reentrancy
///
/// The closure runs with `&mut ErrState`. No seam call — allocation, reallocation or release —
/// may run under that borrow: a `CRYPTO_malloc` failure raises, and a release runs an
/// application's installed `free` hook, and either could re-enter this DSO's ERR code or, worse,
/// the *other* DSO's copy, where this guard is not held, forming a second `&mut` on the shared
/// state. The discipline is therefore:
///
/// * **allocations** are hoisted above the borrow: every allocating helper (`debug_parts`,
///   `message_copy`, `slot_buf_alloc` in the append paths) runs first, and the closure only
///   installs what it was handed;
/// * **releases** are queued by [`SlotStr::drop`] into [`PENDING_RELEASES`] while the flag is
///   set, and [`PendingReleaseGuard`] frees them once the borrow has ended.
///
/// A hook that still re-enters ERR during the queued flush is refused by [`StateAccessGuard`]
/// when it reaches this DSO (the borrow flag has not been cleared yet) and, when it reaches the
/// other DSO through an exported entry point, sees no live `&mut` because `f` has returned.
pub(crate) fn with_state<R>(f: impl FnOnce(&mut ErrState) -> R) -> Option<R> {
    if init::stopped() {
        return None;
    }
    // Declared before the access guard so it drops after the borrow flag is cleared.
    let _pending = PendingReleaseGuard;
    // Refuse a nested access before loading strings or touching the state: those
    // steps may themselves allocate, and a hook that re-enters ERR must not see a
    // second `&mut`. The guard resets even if `f` unwinds.
    let _access = StateAccessGuard::enter()?;
    // First ERR call on this thread: the authority creates the `ERR_STATE` and
    // that creation is what loads the crypto error strings.
    let _ = STATE_READY.try_with(|r| {
        if !r.replace(true) {
            load_crypto_strings();
        }
    });
    // The state is the **shared** one. Both DSOs link the crate archive `--whole-archive`,
    // so each carries its own `STATE`; the authority shares one `libcrypto.so.3`. Resolving
    // libcrypto's exported `ERR_get_state` here makes a libssl-raised error land in the queue
    // `ERR_peek_error` reads through libcrypto -- the authority's binding, measured by
    // `RT-CROSS-DSO-STATE`. A static link falls back to this DSO's own `STATE` (see
    // `runtime::dso_shared`).
    let state = crate::runtime::dso_shared::err_state_ptr();
    if state.is_null() {
        return None;
    }
    // SAFETY: `state` is the live per-thread `ERR_STATE` the authority's `ERR_get_state`
    // returns (or this DSO's, on the fallback path), so the only reachable `&mut` is on this
    // thread. `f` must not retain the reference; every caller uses it for the call.
    Some(f(unsafe { &mut *state }))
}

/// Raise a complete error from inside the library, the way the authority's
/// `ERR_raise` macro does.
///
/// This is the crate-internal path (the public `ERR_set_error` is C-variadic and
/// cannot be called from Rust). `file`/`line` are the values the *raising
/// function received*, because the authority attributes such errors to its
/// caller: `CRYPTO_malloc_array` on overflow reports the caller's file and line,
/// which the RT-MEM probe measures directly through `ERR_peek_error_all`. The
/// function name is the empty string, which `err_set_debug` stores as NULL and
/// the read side renders as `""`; no data is attached, so the flags read as 0.
///
/// # Safety
/// `file` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_with(lib: c_int, reason: c_int, file: *const c_char, line: c_int) {
    // SAFETY: `file` is NULL or NUL-terminated per this function's contract; `EMPTY_C` is the
    // authority's empty function name (stored as NULL).
    let parts = unsafe { debug_parts(file, EMPTY_C) };
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.install_debug(t, line, parts);
        s.set_error(t, lib, reason);
    });
}

/// `ERR_raise(lib, reason)` at a recorded authority site.
///
/// The three debug strings are not invented: they are the authority's own
/// `OPENSSL_FILE`/`OPENSSL_LINE`/`OPENSSL_FUNC` values for the site this code
/// path is reconstructing, derived by `forensics/tools/gen_err_raise_sites.py`
/// from the pinned source and the admitted build record. `ERR_get_error_all` and
/// `ERR_print_errors` hand them to the caller, so they are observed contract.
///
/// # Safety
/// The `ErrSite` is a compile-time constant whose pointers are static.
pub(crate) unsafe fn raise_site(site: &err_sites::ErrSite) {
    // SAFETY: the site's pointers are static NUL-terminated C strings.
    let parts = unsafe { debug_parts(site.file.as_ptr(), site.func.as_ptr()) };
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.install_debug(t, site.line, parts);
        s.set_error(t, site.lib, site.reason);
    });
}

/// `ERR_raise(lib, reason)` at a recorded authority site whose *reason* the
/// authority computes at run time.
///
/// Several authority sites raise `ERR_LIB_SYS` with the current `errno` (or a
/// negated return value) instead of a header constant. The file, line and
/// function are still the authority's own, so they come from the recorded site;
/// only the reason is supplied by the caller. `gen_err_raise_sites.py` marks
/// those sites with `dynamic_reason` so this function is used for exactly them.
///
/// # Safety
/// The `ErrSite` is a compile-time constant whose pointers are static.
pub(crate) unsafe fn raise_site_dynamic(site: &err_sites::ErrSite, reason: c_int) {
    // The generated table marks which sites compute their reason at run time. This
    // assertion is the only reader of that flag, and it exists so the distinction
    // cannot rot: if a future edit routes a constant-reason site through here, the
    // mistake shows up in tests rather than as a wrong reason code in production.
    debug_assert!(
        site.dynamic_reason,
        "raise_site_dynamic used with a constant-reason site"
    );
    // SAFETY: the site's pointers are static NUL-terminated C strings.
    let parts = unsafe { debug_parts(site.file.as_ptr(), site.func.as_ptr()) };
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.install_debug(t, site.line, parts);
        s.set_error(t, site.lib, reason);
    });
}

/// `ERR_raise_data(lib, reason, "...")` at a recorded authority site.
///
/// The authority's `ERR_vset_error` formats the message into an allocated
/// buffer, marks it `ERR_TXT_MALLOCED | ERR_TXT_STRING`, and stores its length
/// including the terminator. `msg` is that already-formatted buffer's content.
///
/// # Safety
/// `msg` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_site_data(site: &err_sites::ErrSite, msg: *const c_char) {
    // SAFETY: the site's pointers are static NUL-terminated C strings, and `msg` is NULL or
    // NUL-terminated per this function's contract.
    let parts = unsafe { debug_parts(site.file.as_ptr(), site.func.as_ptr()) };
    // SAFETY: as above.
    let data = unsafe { message_copy(msg) };
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.install_debug(t, site.line, parts);
        s.set_error(t, site.lib, site.reason);
        if let Some((buf, len)) = data {
            s.set_data(t, buf.into_raw(), len, ERR_TXT_MALLOCED | ERR_TXT_STRING);
        }
    });
}

/// `ERR_raise_data(lib, reason, "...")` at a recorded authority site whose
/// *reason* the authority computes at run time **and** which carries fixed text.
///
/// `raise_site_dynamic` covers a run-time reason with no data and
/// `raise_site_data` a constant reason with data; this is the combination the
/// socket helpers need, where the authority raises a system error with a
/// constant "calling ...()" message.
///
/// # Safety
/// The `ErrSite` is a compile-time constant whose pointers are static, and `msg`
/// must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn raise_site_dynamic_data(
    site: &err_sites::ErrSite,
    reason: c_int,
    msg: *const c_char,
) {
    debug_assert!(
        site.dynamic_reason,
        "raise_site_dynamic_data used with a constant-reason site"
    );
    // SAFETY: the site's pointers are static NUL-terminated C strings, and `msg` is NULL or
    // NUL-terminated per this function's contract.
    let parts = unsafe { debug_parts(site.file.as_ptr(), site.func.as_ptr()) };
    // SAFETY: as above.
    let data = unsafe { message_copy(msg) };
    with_state(|s| {
        s.get_slot();
        let t = s.top as usize;
        s.clear(t, false);
        s.install_debug(t, site.line, parts);
        s.set_error(t, site.lib, reason);
        if let Some((buf, len)) = data {
            s.set_data(t, buf.into_raw(), len, ERR_TXT_MALLOCED | ERR_TXT_STRING);
        }
    });
}

/// `ERR_STATE *ERR_get_state(void)`
///
/// The pointer is into thread-local storage, exactly as in the authority, and
/// stays valid until the thread exits.
#[no_mangle]
pub extern "C" fn ERR_get_state() -> *mut ErrState {
    guard_ffi(core::ptr::null_mut(), || {
        STATE
            .try_with(|s| s.0.get())
            .unwrap_or(core::ptr::null_mut())
    })
}

/// `void ERR_new(void)`
///
/// Claims a slot and clears it. The slot is *incomplete* — `err_buffer` is zero —
/// until `ERR_set_error` supplies a library and reason, which is what makes an
/// interrupted `ERR_raise` invisible to `ERR_get_error`.
#[no_mangle]
pub extern "C" fn ERR_new() {
    guard_ffi((), || {
        with_state(|s| {
            s.get_slot();
            let t = s.top as usize;
            s.clear(t, false);
        });
    })
}

/// `void ERR_set_debug(const char *file, int line, const char *func)`
///
/// # Safety
/// `file` and `func` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_debug(file: *const c_char, line: c_int, func: *const c_char) {
    guard_ffi((), || {
        // SAFETY: `file`/`func` are NULL or NUL-terminated per this function's contract.
        let parts = unsafe { debug_parts(file, func) };
        with_state(|s| {
            let t = s.top as usize;
            s.install_debug(t, line, parts);
        });
    })
}

/// Writes library, reason and message into the current slot. Called by the
/// variadic C adapters so that all state changes live in Rust.
///
/// A NULL `msg` clears any data, matching the authority: `ERR_raise(lib, reason)`
/// is `ERR_set_error(lib, reason, NULL)`, and that resets the data rather than
/// leaving whatever was there.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_set_error(lib: c_int, reason: c_int, msg: *const c_char) {
    guard_ffi((), || {
        // SAFETY: `msg` is NULL or NUL-terminated per this function's contract.
        let data = unsafe { message_copy(msg) };
        with_state(|s| {
            let t = s.top as usize;
            s.clear_data(t, false);
            s.set_error(t, lib, reason);
            if let Some((buf, len)) = data {
                s.set_data(t, buf.into_raw(), len, ERR_TXT_MALLOCED | ERR_TXT_STRING);
            }
        });
    })
}

/// Detaches the current slot's error data, for the variadic formatter.
///
/// This is the step `ERR_vset_error` performs directly in the authority: the
/// slot's `err_data` and `err_data_size` are handed to the caller and the slot is
/// left with a NULL pointer and no flags, so that the formatter may `realloc` the
/// buffer without anything else freeing it in the meantime.
///
/// Returns the buffer (which the caller now owns) and writes its size through
/// `size`.
///
/// ## The return value is always owned
///
/// The pointer is `NULL` or the base of one whole block from the crate's
/// `CRYPTO_*` allocator seam, and the caller owns it. That holds even when the
/// slot held **borrowed** data (`ERR_set_error_data` without
/// `ERR_TXT_MALLOCED`): the borrowed bytes are copied into a fresh seam block
/// and the borrowed original is left untouched, because the queue never owned
/// it. The slot is detached in every case (`err_data` becomes NULL and the flags
/// become 0).
///
/// This is the ownership invariant `ERR_vset_error` relies on: the variadic
/// adapter passes the result to `CRYPTO_realloc` unconditionally, so a borrowed
/// pointer must never escape this function. Reporting the slot's flag instead
/// would make the adapter's correctness depend on a branch it could get wrong;
/// copying here keeps the invariant local to the owner.
///
/// # Safety
/// `size` must be NULL or writable for a `usize`.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_take_data(size: *mut usize) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        // Phase 1, under the borrow: detach the slot and remember what it held. No seam call
        // happens here.
        let detached = with_state(|s| {
            let t = s.top as usize;
            let p = s.err_data[t];
            let p_size = s.err_data_size[t];
            let p_flags = s.err_data_flags[t];
            s.err_data[t] = core::ptr::null_mut();
            s.err_data_size[t] = 0;
            s.err_data_flags[t] = 0;
            (p, p_size, p_flags)
        });
        let (p, p_size, p_flags) = match detached {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        // Phase 2, outside the borrow: the only allocation is the copy a borrowed slot needs.
        let owned = if p.is_null() {
            core::ptr::null_mut()
        } else if (p_flags & ERR_TXT_MALLOCED) != 0 {
            // The queue owned this block; ownership transfers to the caller.
            p
        } else if p_size == 0 {
            // A borrowed slot with no recorded extent cannot be copied and
            // owns nothing; the adapter's NULL arm is the authority's
            // no-message path.
            core::ptr::null_mut()
        } else {
            // Borrowed slot: copy into a fresh seam block so the caller's
            // `CRYPTO_realloc` never receives a pointer the queue did not
            // allocate. `ERR_set_error_data` recorded `strlen + 1` as the
            // extent, so `p_size` bytes are readable and NUL-terminated.
            let Some(buf) = slot_buf_alloc(p_size) else {
                return core::ptr::null_mut();
            };
            // SAFETY: `buf` is `p_size` fresh bytes and the borrowed slot is
            // readable for `p_size` bytes per its `ERR_set_error_data`
            // contract. The blocks cannot overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(p.cast::<u8>(), buf.as_ptr().cast::<u8>(), p_size)
            };
            buf.into_raw()
        };
        if !size.is_null() {
            // SAFETY: writable per the caller's contract.
            unsafe {
                *size = if owned.is_null() { 0 } else { p_size };
            }
        }
        owned
    })
}

/// `CRYPTO_realloc` for the variadic adapter, through the same process-global seam the ring
/// uses for its slot buffers.
///
/// The adapter grows and shrinks the block `openssl_rs_err_take_data` handed it. That block may
/// come from this DSO's ring or from the other DSO's (the queue is shared) and is owned by the
/// process-global allocator, so the realloc must be that allocator's too: this DSO's private
/// `CRYPTO_realloc` would be a foreign realloc whenever an application installed memory
/// functions.
///
/// # Safety
/// `addr` is NULL or a live block the process-global `CRYPTO_*` seam allocated; `file` is NULL
/// or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_realloc(
    addr: *mut c_char,
    num: usize,
    file: *const c_char,
    line: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `addr`/`file` are per the caller's contract.
        unsafe { dso_shared::crypto_realloc(addr.cast(), num, file, line).cast::<c_char>() }
    })
}

/// Installs the result of the variadic formatter.
///
/// The authority's `ERR_vset_error` ends with `err_clear_data(es, top, 0)`, an
/// `err_set_error`, and — only when there was a format string — an
/// `err_set_data(es, top, buf, buf_size, flags)`. Splitting it this way lets the
/// formatting itself happen in C, where `va_list` exists, while the queue's state
/// stays in Rust.
///
/// # Safety
/// `data` must be NULL or a `CRYPTO_malloc` block this call takes ownership of.
///
/// When `flags & ERR_TXT_MALLOCED` is set and `data` is non-NULL, the caller
/// additionally guarantees that `size >= 1`, that `size` is no larger than the
/// block's allocation extent, and that a NUL byte occurs within the first
/// `size` bytes. `OSSL_ERR_STATE_save`/`restore` later copy exactly `size` bytes
/// out of this slot, so an overstated extent is an out-of-bounds read; the size
/// must stay valid for as long as the error state owns the block. A zero extent
/// with a MALLOCED block is refused and the block is released rather than stored.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_finish_data(
    lib: c_int,
    reason: c_int,
    data: *mut c_char,
    size: usize,
    flags: c_int,
) {
    guard_ffi((), || {
        with_state(|s| {
            let t = s.top as usize;
            s.clear_data(t, false);
            s.set_error(t, lib, reason);
            // A NULL buffer is the `fmt == NULL` case: the slot keeps no data at
            // all, which is different from keeping an empty string.
            if !data.is_null() {
                if (flags & ERR_TXT_MALLOCED) != 0 && size == 0 {
                    // Violates the extent contract above. The block was handed to
                    // this call and must not leak, but a zero-byte owned slot
                    // cannot be represented (the restore copy is size-driven), so
                    // release it and keep the slot data-free.
                    // SAFETY: `data` is one whole seam block owned by this call.
                    unsafe {
                        drop(SlotStr::adopt(
                            data,
                            SeamFile::new(ERR_LOCAL_FILE),
                            L_FREE_DATA_DEALL,
                        ))
                    };
                } else {
                    s.set_data(t, data, size, flags);
                }
            }
        });
    })
}

/// Appends textual data to the current slot. Called by the variadic C adapter,
/// which has already concatenated the arguments.
///
/// # Safety
/// `msg` is NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn openssl_rs_err_add_data(msg: *const c_char) {
    guard_ffi((), || {
        if msg.is_null() {
            return;
        }
        // SAFETY: `msg` is NUL-terminated per the caller's contract.
        let add_len = unsafe { c_strlen(msg) };
        if add_len == 0 {
            return;
        }
        // SAFETY: `msg` is NUL-terminated per the caller's contract; no separator.
        unsafe { append_current(core::ptr::null(), msg) };
    })
}

/// Append `sep` and `suffix` to the current slot's data without any seam call under the state
/// borrow.
///
/// The old data is **detached** under a short borrow, the replacement is allocated while no
/// borrow is live, and the new block is installed under a second short borrow. A re-entrant raise
/// during the allocation advances the ring's `top`; it cannot write this already-detached slot,
/// so the install still targets the slot this call started with. On allocation failure the old
/// value is put back, which is the authority's behaviour (its `err_set_data` is not reached).
///
/// # Safety
/// `sep` and `suffix` are NULL or NUL-terminated C strings.
unsafe fn append_current(sep: *const c_char, suffix: *const c_char) {
    // Phase 1, under the borrow: detach the current data. No seam call.
    let Some((t, old_p, old_size, old_flags)) = with_state(|s| {
        let t = s.top as usize;
        let p = s.err_data[t];
        let size = s.err_data_size[t];
        let flags = s.err_data_flags[t];
        s.err_data[t] = core::ptr::null_mut();
        s.err_data_size[t] = 0;
        s.err_data_flags[t] = 0;
        (t, p, size, flags)
    }) else {
        return;
    };
    // The queue owned the detached block when the MALLOCED flag is set; this handle is now its
    // single owner and releases it after the install (outside every borrow).
    let old_owned = if (old_flags & ERR_TXT_MALLOCED) != 0 {
        // SAFETY: the flag says the slot owned this block and phase 1 detached it.
        unsafe { SlotStr::adopt(old_p, SeamFile::new(ERR_LOCAL_FILE), L_FREE_DATA_REPLACE) }
    } else {
        None
    };
    // Only an owned, string-flagged block is reused: the authority appends to a borrowed slot's
    // text by starting a fresh buffer, and a MALLOCED slot without `ERR_TXT_STRING` is replaced.
    let old_len = if (old_flags & ERR_TXT_MALLOCED) != 0 && !old_p.is_null() {
        // SAFETY: MALLOCED means the detached block is a NUL-terminated seam block.
        unsafe { c_strlen(old_p) }
    } else {
        0
    };
    // SAFETY: `sep` is non-NULL on this arm and NUL-terminated per the contract.
    let sepr_present = !sep.is_null() && unsafe { *sep != 0 };
    // The separator is suppressed when there is no existing *string* data.
    let sep_len = if sepr_present && (old_flags & ERR_TXT_STRING) != 0 {
        // SAFETY: `sep` is non-empty here and NUL-terminated per the contract.
        unsafe { c_strlen(sep) }
    } else {
        0
    };
    // SAFETY: `suffix` is NUL-terminated per the contract.
    let add_len = unsafe { c_strlen(suffix) };
    let total = old_len
        .checked_add(sep_len)
        .and_then(|n| n.checked_add(add_len));
    let alloc = total.and_then(|n| n.checked_add(1));
    let buf = match alloc.and_then(slot_buf_alloc) {
        Some(buf) => buf,
        None => {
            // Put the old value back: the authority's failure path leaves the slot unchanged.
            with_state(|s| {
                s.err_data[t] = old_p;
                s.err_data_size[t] = old_size;
                s.err_data_flags[t] = old_flags;
            });
            core::mem::forget(old_owned);
            return;
        }
    };
    let total = total.unwrap_or(0);
    // SAFETY: `buf` is `total + 1` fresh bytes; the old buffer (when non-NULL) is valid for
    // `old_len`, `sep` for `sep_len` and `suffix` for `add_len`.
    unsafe {
        let p = buf.as_ptr();
        if old_len > 0 {
            core::ptr::copy_nonoverlapping(old_p, p, old_len);
        }
        if sep_len > 0 {
            core::ptr::copy_nonoverlapping(sep, p.add(old_len), sep_len);
        }
        core::ptr::copy_nonoverlapping(suffix, p.add(old_len + sep_len), add_len);
        *p.add(total) = 0;
    }
    // Phase 2, under a short borrow: install. `set_data` queues the incumbent's release, but the
    // slot is empty here.
    with_state(|s| {
        s.set_data(
            t,
            buf.into_raw(),
            total + 1,
            ERR_TXT_MALLOCED | ERR_TXT_STRING,
        )
    });
    // Outside the borrow: release the block the slot used to own.
    drop(old_owned);
}

/// `void ERR_set_error_data(char *data, int flags)`
///
/// Takes ownership of `data`, which is the documented and slightly surprising
/// part of this API: the caller must not free it afterwards. The authority's own
/// comment says "callers should be advised that this function takes over
/// ownership of the allocated memory, i.e. they can't count on the pointer to
/// remain valid" (`crypto/err/err.c:803-806`), and it stores the caller's `flags`
/// unchanged after estimating the extent as `strlen(data) + 1`
/// (`crypto/err/err.c:807`).
///
/// # Safety
///
/// `data` must be NULL or NUL-terminated within a readable allocation. The
/// caller must not use or release the pointer after this call.
///
/// When `flags & ERR_TXT_MALLOCED` is set and `data` is non-NULL, the caller
/// additionally guarantees:
///
/// * `data` is the base of one whole allocation from the process's active
///   `CRYPTO_malloc`/`CRYPTO_strdup` seam (not an interior pointer, stack
///   buffer, literal, or unrelated allocator block);
/// * its extent is at least `strlen(data) + 1` bytes (exactly that for a
///   `CRYPTO_strdup` block), so the cached size is valid for the allocation;
/// * this call receives exclusive ownership: no other owner will release it, and
///   the error queue's `CRYPTO_free` is its single release, now or when the slot
///   is later cleared/replaced.
///
/// A NULL `data` with `ERR_TXT_MALLOCED` owns nothing: the slot stores NULL and
/// the later release is the authority's no-op `free(NULL)`.
///
/// Without `ERR_TXT_MALLOCED`, the pointer is borrowed rather than owned: it is
/// never released by the error queue and must remain valid and NUL-terminated
/// until the entry is cleared or replaced. Passing a non-seam pointer *with* the
/// flag, or releasing a MALLOCED pointer after this call, violates the C ABI
/// contract and is not made safe by the Rust type system.
#[no_mangle]
pub unsafe extern "C" fn ERR_set_error_data(data: *mut c_char, flags: c_int) {
    guard_ffi((), || {
        // SAFETY: `data` is NUL-terminated per the caller's contract.
        let len = if data.is_null() {
            0
        } else {
            // SAFETY: `data` is NUL-terminated per the caller's contract.
            unsafe { c_strlen(data) + 1 }
        };
        with_state(|s| {
            let t = s.top as usize;
            s.clear_data(t, true);
            s.set_data(t, data, len, flags);
        });
    })
}

/// `void ERR_add_error_txt(const char *sepr, const char *txt)`
///
/// The authority routes this through `ERR_add_error_data`, but with one rule that
/// is easy to miss and is directly observable through `ERR_get_error_all`: the
/// **separator is dropped when the current slot carries no string data**. A slot
/// raised with `ERR_set_error(lib, reason, NULL)` has no `ERR_TXT_STRING`, so
/// appending `"ab"` with separator `" | "` yields `ab`, not `" | ab"`. The
/// separator only separates existing text from new text.
///
/// ## Open obligation: the length-bounded split is not implemented
///
/// The authority also splits `txt` when the combined data would exceed
/// `ERR_PRINT_BUF_SIZE - 100`, emitting several queue entries so that
/// `ERR_print_errors_cb`'s fixed buffer cannot truncate the report. That path is
/// not implemented here: it only manifests for error data of roughly four
/// kilobytes or more, no court probes it, and no claim is made about it. It is
/// recorded rather than left implicit, and a court for it is the obligation.
///
/// # Safety
/// `sepr` and `txt` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_txt(sepr: *const c_char, txt: *const c_char) {
    guard_ffi((), || {
        if txt.is_null() {
            return;
        }
        // SAFETY: `sepr`/`txt` are NULL or NUL-terminated per this function's contract.
        unsafe { append_current(sepr, txt) };
    })
}

/// Which error `get_error_values` is being asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Pop,
    PeekFirst,
    PeekLast,
}

/// The outputs `get_error_values` can fill in; only the non-NULL ones are
/// written, exactly as in the authority.
struct Outputs {
    file: *mut *const c_char,
    line: *mut c_int,
    func: *mut *const c_char,
    data: *mut *const c_char,
    flags: *mut c_int,
}

/// The shared body of `ERR_get_error*` and `ERR_peek_error*`, reproducing
/// `get_error_values` including its NULL-as-empty-string conversions.
///
/// # Safety
/// Every non-NULL output pointer must be writable for its type.
unsafe fn get_error_values(action: Action, out: Outputs) -> c_ulong {
    with_state(|s| {
        s.settle_clears();
        if s.bottom == s.top {
            return 0;
        }
        let i = match action {
            Action::PeekLast => s.top as usize,
            _ => s.oldest(),
        };
        let ret = s.err_buffer[i];
        if action == Action::Pop {
            s.bottom = i as c_int;
            s.err_buffer[i] = 0;
        }
        // SAFETY: each output is NULL or writable per the caller's contract, and
        // the values written are either ring-owned pointers or static empties.
        unsafe {
            if !out.file.is_null() {
                *out.file = if s.err_file[i].is_null() {
                    EMPTY_C
                } else {
                    s.err_file[i]
                };
            }
            if !out.line.is_null() {
                *out.line = s.err_line[i];
            }
            if !out.func.is_null() {
                *out.func = if s.err_func[i].is_null() {
                    EMPTY_C
                } else {
                    s.err_func[i]
                };
            }
            if !out.flags.is_null() {
                *out.flags = s.err_data_flags[i];
            }
            if out.data.is_null() {
                if action == Action::Pop {
                    let t = i;
                    s.clear_data(t, false);
                }
            } else {
                *out.data = if s.err_data[i].is_null() {
                    // The authority reports an empty string and zeroes the flags
                    // in this case, so a caller never sees a non-NULL flags value
                    // describing data that is not there.
                    if !out.flags.is_null() {
                        *out.flags = 0;
                    }
                    EMPTY_C
                } else {
                    s.err_data[i]
                };
            }
        }
        ret
    })
    .unwrap_or(0)
}

macro_rules! get_error {
    ($name:ident, $action:expr, $doc:expr) => {
        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $name() -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: all output pointers are NULL, so nothing is written.
                unsafe {
                    get_error_values(
                        $action,
                        Outputs {
                            file: core::ptr::null_mut(),
                            line: core::ptr::null_mut(),
                            func: core::ptr::null_mut(),
                            data: core::ptr::null_mut(),
                            flags: core::ptr::null_mut(),
                        },
                    )
                }
            })
        }
    };
}

get_error!(
    ERR_get_error,
    Action::Pop,
    "`unsigned long ERR_get_error(void)`"
);
get_error!(
    ERR_peek_error,
    Action::PeekFirst,
    "`unsigned long ERR_peek_error(void)`"
);
get_error!(
    ERR_peek_last_error,
    Action::PeekLast,
    "`unsigned long ERR_peek_last_error(void)`"
);

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
        // SAFETY: forwarded; see this function's contract.
        unsafe {
            get_error_values(
                Action::Pop,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

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
        // SAFETY: forwarded.
        unsafe {
            get_error_values(
                Action::PeekFirst,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

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
        // SAFETY: forwarded.
        unsafe {
            get_error_values(
                Action::PeekLast,
                Outputs {
                    file,
                    line,
                    func,
                    data,
                    flags,
                },
            )
        }
    })
}

// The legacy accessors are NOT uniform in arity: `_func` takes one output,
// `_line` two, `_line_data` four, `_data` two *different* ones. Defining them
// through a single five-parameter macro produced exports whose ABI did not match
// the declarations — a defect the RT-ERR probe found by calling them the way the
// header says to. Each arity now has its own macro, so the signature is a
// compile-time fact rather than an argument list of booleans.
macro_rules! forwarding_get_line {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `file` and `line` must each be NULL or writable for its type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(file: *mut *const c_char, line: *mut c_int) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the absent out-parameters are NULL.
                unsafe {
                    $inner(
                        file,
                        line,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
            })
        }
    };
}

macro_rules! forwarding_get_line_data {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// Every output pointer must be NULL or writable for its type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            file: *mut *const c_char,
            line: *mut c_int,
            data: *mut *const c_char,
            flags: *mut c_int,
        ) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; `func` is not an output here.
                unsafe { $inner(file, line, core::ptr::null_mut(), data, flags) }
            })
        }
    };
}

macro_rules! forwarding_get_func {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `func` must be NULL or writable.
        #[no_mangle]
        pub unsafe extern "C" fn $name(func: *mut *const c_char) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the other outputs are NULL.
                unsafe {
                    $inner(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        func,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                }
            })
        }
    };
}

macro_rules! forwarding_get_data {
    ($name:ident, $inner:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// # Safety
        /// `data` and `flags` must each be NULL or writable for their type.
        #[no_mangle]
        pub unsafe extern "C" fn $name(data: *mut *const c_char, flags: *mut c_int) -> c_ulong {
            guard_ffi(0, || {
                // SAFETY: forwarded unchanged; the other outputs are NULL.
                unsafe {
                    $inner(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        data,
                        flags,
                    )
                }
            })
        }
    };
}

forwarding_get_line!(
    ERR_get_error_line,
    ERR_get_error_all,
    "`unsigned long ERR_get_error_line(const char **file, int *line)`"
);
forwarding_get_line_data!(
    ERR_get_error_line_data,
    ERR_get_error_all,
    "`unsigned long ERR_get_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);
forwarding_get_line!(
    ERR_peek_error_line,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_line(const char **file, int *line)`"
);
forwarding_get_data!(
    ERR_peek_error_data,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_data(const char **data, int *flags)`"
);
forwarding_get_func!(
    ERR_peek_error_func,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_func(const char **func)`"
);
forwarding_get_line_data!(
    ERR_peek_error_line_data,
    ERR_peek_error_all,
    "`unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);
forwarding_get_line!(
    ERR_peek_last_error_line,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_line(const char **file, int *line)`"
);
forwarding_get_data!(
    ERR_peek_last_error_data,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_data(const char **data, int *flags)`"
);
forwarding_get_func!(
    ERR_peek_last_error_func,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_func(const char **func)`"
);
forwarding_get_line_data!(
    ERR_peek_last_error_line_data,
    ERR_peek_last_error_all,
    "`unsigned long ERR_peek_last_error_line_data(const char **file, int *line, const char **data, int *flags)`"
);

/// `void ERR_clear_error(void)`
///
/// Clears every slot. Data buffers that this state owns are truncated rather
/// than released, because the authority reuses them.
#[no_mangle]
pub extern "C" fn ERR_clear_error() {
    guard_ffi((), || {
        with_state(|s| {
            for i in 0..ERR_NUM_ERRORS {
                s.clear(i, false);
            }
            s.top = 0;
            s.bottom = 0;
        });
    })
}

/// `int ERR_set_mark(void)`
///
/// Returns 0 on an empty queue — there is nothing to mark — and increments the
/// mark counter of the *newest* slot otherwise.
#[no_mangle]
pub extern "C" fn ERR_set_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            if s.bottom == s.top {
                return 0;
            }
            s.err_marks[s.top as usize] += 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_pop(void)`
///
/// Discards the newest error without returning it.
#[no_mangle]
pub extern "C" fn ERR_pop() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            if s.bottom == s.top {
                return 0;
            }
            let t = s.top as usize;
            s.clear(t, false);
            let n = ERR_NUM_ERRORS as c_int;
            s.top = if s.top > 0 { s.top - 1 } else { n - 1 };
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_pop_to_mark(void)`
///
/// Discards errors until a marked slot is reached, then consumes one mark from
/// it. The marked error itself is *kept*: the mark denotes a point in the queue,
/// not an error to remove.
#[no_mangle]
pub extern "C" fn ERR_pop_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            while s.bottom != s.top && s.err_marks[s.top as usize] == 0 {
                let t = s.top as usize;
                s.clear(t, false);
                s.top = if s.top > 0 { s.top - 1 } else { n - 1 };
            }
            if s.bottom == s.top {
                return 0;
            }
            s.err_marks[s.top as usize] -= 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_count_to_mark(void)`
///
/// The number of errors above the most recent mark, excluding the marked one.
#[no_mangle]
pub extern "C" fn ERR_count_to_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            let mut count = 0;
            let mut top = s.top;
            while s.bottom != top && s.err_marks[top as usize] == 0 {
                count += 1;
                top = if top > 0 { top - 1 } else { n - 1 };
            }
            count
        })
        .unwrap_or(0)
    })
}

/// `int ERR_clear_last_mark(void)`
#[no_mangle]
pub extern "C" fn ERR_clear_last_mark() -> c_int {
    guard_ffi(0, || {
        with_state(|s| {
            let n = ERR_NUM_ERRORS as c_int;
            let mut top = s.top;
            while s.bottom != top && s.err_marks[top as usize] == 0 {
                top = if top > 0 { top - 1 } else { n - 1 };
            }
            if s.bottom == top {
                return 0;
            }
            s.err_marks[top as usize] -= 1;
            1
        })
        .unwrap_or(0)
    })
}

/// `int ERR_get_next_error_library(void)`
#[no_mangle]
pub extern "C" fn ERR_get_next_error_library() -> c_int {
    guard_ffi(0, || {
        // The authority hands out codes above `ERR_LIB_USER` (128); the exact
        // sequence is a per-process allocation and is measured by RT-ERR.
        NEXT_LIB.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as c_int + 128
    })
}

/// The next dynamic library code to hand out. `ERR_LIB_USER` is 128 and the
/// authority starts there, unlike the earlier `100 + n` guess this replaces.
static NEXT_LIB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A deliberately shared buffer, matching the authority's `static char buf[256]`
/// inside `ERR_error_string`. It is not thread-safe there either, and pretending
/// otherwise would be a divergence rather than an improvement.
struct SharedBuf(UnsafeCell<[u8; 256]>);
// SAFETY: mirrors the authority's own static buffer, which is also shared across
// threads without synchronisation. Callers already accept that contract.
unsafe impl Sync for SharedBuf {}
static ERR_STRING_BUF: SharedBuf = SharedBuf(UnsafeCell::new([0u8; 256]));

extern "C" {
    /// The GNU `strerror_r`, returning a pointer that may or may not be `buf`.
    /// This is the variant the authority's `_GNU_SOURCE` build calls from
    /// `openssl_strerror_r`, and therefore the one whose text a caller sees.
    fn strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> *mut c_char;
}

/// `openssl_strerror_r` reduced to what `ossl_err_string_int` needs: fill `buf`
/// with the platform's text for `errnum`, and report whether it succeeded.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes.
unsafe fn strerror_into(errnum: c_int, buf: *mut c_char, buflen: usize) -> bool {
    if buf.is_null() || buflen == 0 {
        return false;
    }
    // SAFETY: `buf` is writable for `buflen` bytes per the caller's contract.
    let p = unsafe { strerror_r(errnum, buf, buflen) };
    if p.is_null() {
        return false;
    }
    if !core::ptr::eq(p, buf) {
        // The GNU variant may hand back a pointer to a static string instead of
        // using `buf`; copy it in, exactly as `OPENSSL_strlcpy` does in the
        // authority.
        // SAFETY: `p` is NUL-terminated, `buf` has `buflen` non-zero bytes.
        unsafe {
            let n = c_strlen(p).min(buflen - 1);
            core::ptr::copy_nonoverlapping(p, buf, n);
            *buf.add(n) = 0;
        }
    }
    true
}

/// `ossl_err_string_int(e, "", buf, len)`.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is non-zero.
unsafe fn error_string_body(e: c_ulong, buf: *mut c_char, len: usize) {
    // SAFETY: forwarded; the authority passes the empty string for the function
    // name when formatting a standalone error string.
    unsafe { error_string_body_func(e, EMPTY_C, buf, len) }
}

/// `ossl_err_string_int(e, func, buf, len)`.
///
/// The `func` is carried through because `ERR_print_errors_cb` prints the
/// *recorded* function name from the error's debug information, not an empty
/// field, so the same formatter produces
/// `error:<code>:<lib>:<func>:<reason>` for it and
/// `error:<code>:<lib>::<reason>` for `ERR_error_string`.
///
/// # Safety
/// `buf` must be writable for `len` bytes when `len` is non-zero; `func` must be
/// NULL or a NUL-terminated C string.
unsafe fn error_string_body_func(e: c_ulong, func: *const c_char, buf: *mut c_char, len: usize) {
    if len == 0 || buf.is_null() {
        return;
    }
    let lib = get_lib(e);
    let system_error = (e & ERR_SYSTEM_FLAG) != 0;
    let mut lib_fallback = [0u8; 64];
    let lib_ptr = {
        let p = ERR_lib_error_string(e);
        if p.is_null() {
            // `lib(%lu)` — the whole field, not just a number.
            let s = format!("lib({lib})");
            let n = s.len().min(lib_fallback.len() - 1);
            lib_fallback[..n].copy_from_slice(&s.as_bytes()[..n]);
            lib_fallback[n] = 0;
            lib_fallback.as_ptr().cast::<c_char>()
        } else {
            p
        }
    };
    let reason = get_reason(e);
    let mut reason_fallback = [0u8; 256];
    let reason_ptr = {
        // A system error is rendered through the platform's `strerror_r`, never
        // through the reason table: the authority cannot put a per-thread
        // `strerror` buffer into a library-wide table lookup.
        let p = if system_error {
            // SAFETY: the buffer is 256 writable bytes.
            if unsafe {
                strerror_into(
                    reason as c_int,
                    reason_fallback.as_mut_ptr().cast::<c_char>(),
                    reason_fallback.len(),
                )
            } {
                reason_fallback.as_ptr().cast::<c_char>()
            } else {
                core::ptr::null()
            }
        } else {
            ERR_reason_error_string(e)
        };
        if p.is_null() {
            // The flag bits are stripped from the numeric fallback, so a code
            // carrying ERR_RFLAG_* renders as its base reason.
            let bare = reason & !(ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
            let s = format!("reason({bare})");
            let n = s.len().min(reason_fallback.len() - 1);
            reason_fallback[..n].copy_from_slice(&s.as_bytes()[..n]);
            reason_fallback[n] = 0;
            reason_fallback.as_ptr().cast::<c_char>()
        } else {
            p
        }
    };
    // SAFETY: all three pointers are valid NUL-terminated strings.
    let (ls, rs) = unsafe {
        (
            core::slice::from_raw_parts(lib_ptr.cast::<u8>(), c_strlen(lib_ptr)),
            core::slice::from_raw_parts(reason_ptr.cast::<u8>(), c_strlen(reason_ptr)),
        )
    };
    let mut v = Vec::new();
    v.extend_from_slice(format!("error:{e:08X}:").as_bytes());
    v.extend_from_slice(ls);
    v.push(b':');
    if !func.is_null() {
        // SAFETY: `func` is NUL-terminated per this function's contract.
        let f = unsafe { core::slice::from_raw_parts(func.cast::<u8>(), c_strlen(func)) };
        v.extend_from_slice(f);
    }
    v.push(b':');
    v.extend_from_slice(rs);
    // The authority substitutes a compact form when the pretty one exactly fills
    // the buffer. Its test is `strlen(buf) == len - 1` *after* the bounded write,
    // so a string that had to be truncated also triggers it — which is what makes
    // the substitution observable through a short buffer.
    let wrote = v.len();
    let n = wrote.min(len - 1);
    // SAFETY: `buf` is writable for `len` bytes and `n <= len - 1`.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr().cast::<c_char>(), buf, n);
        *buf.add(n) = 0;
    }
    if n == len - 1 {
        let compact = format!("err:{e:x}:{lib:x}:0:{reason:x}");
        let bytes = compact.as_bytes();
        let n = bytes.len().min(len - 1);
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, n);
            *buf.add(n) = 0;
        }
    }
}

/// `void ERR_error_string_n(unsigned long e, char *buf, size_t len)`
///
/// # Safety
/// `buf` must be NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize) {
    guard_ffi((), || {
        // SAFETY: forwarded unchanged.
        unsafe { error_string_body(e, buf, len) }
    })
}

/// `char *ERR_error_string(unsigned long e, char *buf)`
///
/// With a NULL `buf` the authority answers with a pointer into a **static**
/// buffer, shared across threads. That is its contract, and it is reproduced
/// rather than quietly "improved" into thread-local storage — a caller that
/// relied on comparing pointers, or that saw the value overwritten by another
/// thread, would observe the difference.
///
/// # Safety
///
/// `buf` must be NULL or writable for at least 256 bytes.
///
/// With a NULL `buf` the returned pointer aliases the process-global
/// `ERR_STRING_BUF`, exactly as the authority's `static char buf[256]` does.
/// Writing it and reading the returned pointer are **not** synchronized by this
/// function: concurrent calls (or a read concurrent with a call) on different
/// threads are a data race and therefore undefined behaviour in Rust. A caller
/// that uses the NULL-buffer form must serialize it externally — one lock or one
/// thread — and must treat the returned pointer as valid only until the next
/// `ERR_error_string` call on any thread. The buffer is reproduced as shared
/// rather than moved to thread-local storage so pointer-comparison and
/// overwrite-observation behaviour matches the authority; see the note above.
#[no_mangle]
pub unsafe extern "C" fn ERR_error_string(e: c_ulong, buf: *mut c_char) -> *mut c_char {
    guard_ffi(core::ptr::null_mut(), || {
        if !buf.is_null() {
            // SAFETY: the caller guarantees 256 writable bytes.
            unsafe { error_string_body(e, buf, 256) };
            return buf;
        }
        let p = ERR_STRING_BUF.0.get().cast::<c_char>();
        // SAFETY: the static buffer is 256 bytes; see the type's note on why
        // sharing it matches the authority.
        unsafe { error_string_body(e, p, 256) };
        p
    })
}

/// `const char *ERR_lib_error_string(unsigned long e)`
///
/// NULL until the generic tables have been loaded. Before the first ERR-state
/// creation on any thread the authority's hash is empty, so a lookup answers
/// NULL even for a library whose array is compiled in; the probe measures that
/// window explicitly.
#[no_mangle]
pub extern "C" fn ERR_lib_error_string(e: c_ulong) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        if !generic_loaded() {
            return core::ptr::null();
        }
        let lib = get_lib(e);
        if lib > u8::MAX as c_ulong {
            return core::ptr::null();
        }
        lookup_lib(lib as u32)
    })
}

/// `const char *ERR_func_error_string(unsigned long e)`
///
/// Always NULL. In 3.x `ERR_PACK` discards the function field, so there is
/// nothing to look up; the authority's implementation is a bare `return NULL`.
#[no_mangle]
pub extern "C" fn ERR_func_error_string(_e: c_ulong) -> *const c_char {
    core::ptr::null()
}

/// `const char *ERR_reason_error_string(unsigned long e)`
///
/// Tries the library-qualified key first, then the bare reason, and refuses
/// system errors — which the authority does because it cannot render a platform
/// error string through a shared buffer.
///
/// Visibility follows the load state. A library-qualified key is only reachable
/// once *that library* has been loaded, so an SSL reason stays NULL until
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` has run; the generic fallback needs the
/// generic tables, which any load supplies.
#[no_mangle]
pub extern "C" fn ERR_reason_error_string(e: c_ulong) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        if (e & ERR_SYSTEM_FLAG) != 0 {
            return core::ptr::null();
        }
        let lib = get_lib(e) as u32;
        let reason = get_reason(e) as u32;
        if lib_loaded(lib) {
            let qualified = ((lib & 0xFF) << ERR_LIB_OFFSET as u32) | (reason & 0x7F_FFFF);
            let p = lookup(err_strings::REASONS, qualified);
            if !p.is_null() {
                return p;
            }
        }
        if !generic_loaded() {
            return core::ptr::null();
        }
        lookup(err_strings::REASONS, reason)
    })
}

/// Look up a `(key, NUL-terminated text)` table by key.
fn lookup(table: &[(u32, &[u8])], key: u32) -> *const c_char {
    match table.binary_search_by_key(&key, |&(k, _)| k) {
        // SAFETY: every entry is a static byte string ending in NUL, so the
        // pointer is a valid C string for the life of the process.
        Ok(i) => table[i].1.as_ptr().cast::<c_char>(),
        Err(_) => core::ptr::null(),
    }
}

/// Look up a library name, whose keys are single bytes.
fn lookup_lib(key: u32) -> *const c_char {
    match err_strings::LIBS.binary_search_by_key(&(key as u8), |&(k, _)| k) {
        // SAFETY: as `lookup`.
        Ok(i) => err_strings::LIBS[i].1.as_ptr().cast::<c_char>(),
        Err(_) => core::ptr::null(),
    }
}

/// `int ERR_load_strings(int lib, ERR_STRING_DATA *str)`
///
/// The authority's tables are compiled in, so this legacy entry point exists for
/// source compatibility. Its observable behaviour is measured by the RT-ERR
/// probe rather than asserted here.
#[no_mangle]
pub extern "C" fn ERR_load_strings(_lib: c_int, _str: *mut c_void) -> c_int {
    1
}

/// `int ERR_load_strings_const(const ERR_STRING_DATA *str)`
#[no_mangle]
pub extern "C" fn ERR_load_strings_const(_str: *const c_void) -> c_int {
    1
}

/// `int ERR_unload_strings(int lib, ERR_STRING_DATA *str)`
#[no_mangle]
pub extern "C" fn ERR_unload_strings(_lib: c_int, _str: *mut c_void) -> c_int {
    1
}

/// `void ERR_remove_thread_state(void *dummy)`
///
/// Deprecated and, in the authority, a no-op that does not even synchronise the
/// internal buffer. Reproduced as such rather than given meaning it does not
/// have.
///
/// # Safety
/// `_dummy` is ignored; any value, including NULL, is accepted.
#[no_mangle]
pub unsafe extern "C" fn ERR_remove_thread_state(_dummy: *mut c_void) {}

/// `void ERR_remove_state(unsigned long pid)`
///
/// Deprecated. The authority ignores `pid` entirely; the name suggests it once
/// removed another thread's state, which it no longer does.
#[no_mangle]
pub extern "C" fn ERR_remove_state(_pid: c_ulong) {}

/// The per-library `ERR_load_*_strings` entry points live in the generated
/// `err_loaders` module. They are **not** no-ops: each one loads the generic
/// tables plus that library, which `ERR_reason_error_string` makes observable.
/// The authority's own versions do the same through `ERR_load_strings_const`
/// and `ossl_err_load_ERR_strings`.
/// `int (*)(const char *str, size_t len, void *u)` — the `ERR_print_errors_cb`
/// callback.
pub type ErrPrintCb = unsafe extern "C" fn(*const c_char, usize, *mut c_void) -> c_int;

/// `ossl_buf2hexstr_sep(buf, buflen, 0)` — upper-case hex, no separator.
///
/// The separator argument of the authority's helper is `CH_ZERO` here, which means
/// "no separator" rather than "NUL-separated", and it is why the thread id renders
/// as one unbroken hex run.
fn buf2hexstr_plain(buf: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut v = Vec::with_capacity(buf.len() * 2);
    for &b in buf {
        v.push(HEX[(b >> 4) as usize]);
        v.push(HEX[(b & 0x0f) as usize]);
    }
    v
}

/// `void ERR_print_errors_cb(int (*cb)(const char *, size_t, void *), void *u)`
///
/// Drains the whole thread-local queue, oldest first, printing one line per error:
///
/// ```text
/// <thread-id-as-hex>:<error string>:<file>:<line>:<data>
/// ```
///
/// A callback that returns `<= 0` stops the report **and leaves the remaining
/// errors on the queue**, which is the authority's behaviour and is why an
/// aborting callback is not the same as clearing the queue.
///
/// # Safety
/// `cb` must be the caller's printing callback; `u` is passed through untouched.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_cb(cb: Option<ErrPrintCb>, u: *mut c_void) {
    guard_ffi((), || {
        let Some(cb) = cb else {
            return;
        };
        loop {
            let mut file: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut func: *const c_char = ptr::null();
            let mut data: *const c_char = ptr::null();
            let mut flags: c_int = 0;
            // SAFETY: all five are live locals of the types the function writes.
            let l = unsafe {
                ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
            };
            if l == 0 {
                break;
            }
            // A slot with no string data prints an empty field rather than whatever
            // the pointer happens to hold.
            let data = if flags & ERR_TXT_STRING == 0 {
                EMPTY_C
            } else {
                data
            };

            let mut out: Vec<u8> = Vec::with_capacity(256);
            // SAFETY: `pthread_self` takes no arguments and always succeeds.
            let tid = crate::runtime::thread::CRYPTO_THREAD_get_current_id();
            out.extend_from_slice(&buf2hexstr_plain(&tid.to_ne_bytes()));
            out.push(b':');

            let mut tmp = [0u8; 4096];
            // SAFETY: `tmp` is 4096 writable bytes; `func` is NUL-terminated or
            // NULL, per the error's own recorded debug information.
            unsafe {
                error_string_body_func(l, func, tmp.as_mut_ptr().cast(), tmp.len());
                let n = c_strlen(tmp.as_ptr().cast());
                out.extend_from_slice(&tmp[..n]);
            }
            out.push(b':');
            // SAFETY: `file` and `data` are each NULL or NUL-terminated strings.
            unsafe {
                if !file.is_null() {
                    let n = c_strlen(file);
                    out.extend_from_slice(core::slice::from_raw_parts(file.cast::<u8>(), n));
                }
                out.push(b':');
                out.extend_from_slice(format!("{line}").as_bytes());
                out.push(b':');
                if !data.is_null() {
                    let n = c_strlen(data);
                    out.extend_from_slice(core::slice::from_raw_parts(data.cast::<u8>(), n));
                }
                out.push(b'\n');
            }
            // SAFETY: `cb` is the caller's callback; `out` is a live slice and `u`
            // is the caller's opaque pointer.
            if unsafe { cb(out.as_ptr().cast(), out.len(), u) } <= 0 {
                break;
            }
        }
    })
}

/// `static int print_bio(const char *str, size_t len, void *bp)`
///
/// # Safety
/// `bp` must be a live BIO.
unsafe extern "C" fn print_bio(str_: *const c_char, len: usize, bp: *mut c_void) -> c_int {
    if len > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is a live BIO and `str_` is valid for `len` bytes.
    unsafe { crate::runtime::bio::BIO_write(bp.cast(), str_.cast(), len as c_int) }
}

/// `void ERR_print_errors(BIO *bp)`
///
/// # Safety
/// `bp` must be NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors(bp: *mut crate::runtime::bio::Bio) {
    guard_ffi((), || {
        // SAFETY: forwarded; `ERR_print_errors_cb` accepts a NULL callback and the
        // BIO belongs to the caller.
        unsafe { ERR_print_errors_cb(Some(print_bio), bp.cast()) };
    })
}

/// `void ERR_print_errors_fp(FILE *fp)`
///
/// The authority builds a `BIO_new_fp(fp, BIO_NOCLOSE)` and prints into that.
/// `BIO_s_file` is an open obligation of this stratum, so this writes the same
/// bytes to the stream directly — a file BIO's only effect on a write is `fwrite`
/// to that stream. The mechanism difference is recorded rather than hidden.
///
/// # Safety
/// `fp` must be NULL or a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn ERR_print_errors_fp(fp: *mut crate::runtime::bio::sys::FILE) {
    guard_ffi((), || {
        /// Writes an already-formatted report line to the caller's stream.
        ///
        /// # Safety
        /// `fp` must be NULL or a live `FILE *`.
        unsafe extern "C" fn print_fp(str_: *const c_char, len: usize, fp: *mut c_void) -> c_int {
            if fp.is_null() {
                return -1;
            }
            // SAFETY: `fp` is the caller's stream and `str_` is valid for `len`
            // bytes.
            unsafe { crate::runtime::bio::sys::fwrite(str_.cast(), 1, len, fp.cast()) as c_int }
        }
        // SAFETY: forwarded; `print_fp` writes to the caller's stream.
        unsafe { ERR_print_errors_cb(Some(print_fp), fp.cast()) };
    })
}

/// `void ERR_add_error_mem_bio(const char *separator, BIO *bio)`
///
/// Appends the contents of a memory BIO to the current error's data, separated by
/// `separator`. Two details are deliberate: a non-empty buffer whose last byte is
/// not NUL gets one written first, so the text is a C string; and a buffer of
/// exactly one byte is treated as empty because the guard is `len > 1`. Both are
/// the authority's, and both are observable through `ERR_get_error_all`.
///
/// # Safety
/// `bio` must be NULL or a live BIO; `separator` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ERR_add_error_mem_bio(
    separator: *const c_char,
    bio: *mut crate::runtime::bio::Bio,
) {
    guard_ffi((), || {
        if bio.is_null() {
            return;
        }
        // `BIO_get_mem_data(bio, &str)` is `BIO_ctrl(bio, BIO_CTRL_INFO, 0, &str)`.
        let mut str_ptr: *mut c_char = ptr::null_mut();
        // SAFETY: `bio` is live and `str_ptr` is a live local the control writes.
        let mut len = unsafe {
            crate::runtime::bio::BIO_ctrl(
                bio,
                crate::runtime::bio::BIO_CTRL_INFO,
                0,
                (&mut str_ptr as *mut *mut c_char).cast(),
            )
        };
        if len <= 0 {
            return;
        }
        // SAFETY: `str_ptr` addresses the BIO's buffer and `len` bytes are valid.
        unsafe {
            if *str_ptr.add((len - 1) as usize) != 0 {
                // SAFETY: writing one NUL byte through a live BIO.
                if crate::runtime::bio::BIO_write(bio, c"".as_ptr().cast(), 1) <= 0 {
                    return;
                }
                let mut p2: *mut c_char = ptr::null_mut();
                len = crate::runtime::bio::BIO_ctrl(
                    bio,
                    crate::runtime::bio::BIO_CTRL_INFO,
                    0,
                    (&mut p2 as *mut *mut c_char).cast(),
                );
                str_ptr = p2;
            }
            if len > 1 {
                ERR_add_error_txt(separator, str_ptr);
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Takes the crate-wide global-state lock. The error registry is
    /// process-global (`GENERIC_LOADED`/`LIB_LOADED`, `NEXT_LIB` and the shared
    /// `ERR_error_string` buffer), and every queue call reads the crate-wide init
    /// flag (`init::stopped`), so a test here must not run concurrently with any
    /// test that initialises or tears down the library:
    /// [`crate::test_support::lock_global_state`] is the one lock every
    /// global-touching test shares, not a lock local to this module.
    ///
    /// `generated_tables_are_complete_and_sorted` is deliberately **not** locked:
    /// it reads only the immutable generated `err_strings` tables.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::lock_global_state()
    }

    #[test]
    fn a_reentrant_state_access_is_refused_and_the_guard_resets() {
        let _g = lock();
        let outer = with_state(|s| {
            // A nested ERR call on this thread must not form a second `&mut`:
            // it is refused with the same "no state" outcome as a stopped
            // library, and it does not mutate the slot the outer call holds.
            let nested = with_state(|inner| {
                inner.top += 1;
            });
            assert!(nested.is_none(), "reentrant access must be refused");
            s.top
        });
        assert!(outer.is_some(), "the outer access still succeeds");
        // The guard resets on exit, so the next unrelated ERR call works.
        assert!(with_state(|_| ()).is_some());
    }

    /// Read a static C string returned by the tables.
    fn cstr(p: *const c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: the tables hold static NUL-terminated byte strings.
        unsafe {
            Some(
                String::from_utf8_lossy(core::slice::from_raw_parts(p.cast::<u8>(), c_strlen(p)))
                    .into_owned(),
            )
        }
    }

    fn drain() {
        ERR_clear_error();
    }

    /// A refused error-string allocation must happen **before** the `&mut ErrState` borrow is
    /// taken. Under the borrow it would call the process-global `CRYPTO_malloc`, whose failure
    /// path raises through libcrypto's own ERR code — where this DSO's reentrancy guard is not
    /// held — forming a second `&mut` on the shared state.
    ///
    /// The seam probe counts every allocation/release made while [`state_borrowed`] is true; the
    /// assertion is that the count stays zero. Reintroducing an allocation inside a
    /// `with_state` closure (or an eager release instead of the deferred queue) makes it fail.
    #[test]
    fn a_failed_error_string_allocation_runs_before_the_state_borrow() {
        let _g = lock();
        drain();
        let _ = dso_shared::take_seam_probe();
        let _ = dso_shared::take_in_borrow_probe();
        // Arm exactly one refusal: the file-string duplicate cannot be allocated.
        dso_shared::arm_malloc_failure(1);
        // SAFETY: a static NUL-terminated string.
        unsafe { raise_with(15, 42, c"ssl/ssl_rsa.c".as_ptr(), 515) };
        let (mallocs, _) = dso_shared::take_seam_probe();
        assert!(mallocs >= 1, "the armed allocation attempt must have run");
        assert_eq!(
            dso_shared::take_in_borrow_probe(),
            0,
            "no seam call (and so no allocator callback) may run while the ErrState borrow is live"
        );
        // The raise still completed; the refused duplicate is stored as NULL, which the read side
        // renders as `""`, and the line is the site's own.
        let mut file: *const c_char = ptr::null();
        let mut line = 0;
        let mut func: *const c_char = ptr::null();
        let mut data: *const c_char = ptr::null();
        let mut flags = 0;
        // SAFETY: every output pointer is this frame's own variable.
        let e = unsafe {
            get_error_values(
                Action::Pop,
                Outputs {
                    file: &mut file,
                    line: &mut line,
                    func: &mut func,
                    data: &mut data,
                    flags: &mut flags,
                },
            )
        };
        assert_ne!(e, 0, "the raise must still be recorded");
        assert_eq!(
            file, EMPTY_C,
            "a refused duplicate reads as the empty string"
        );
        assert_eq!(func, EMPTY_C);
        assert_eq!(line, 515);

        // A successful raise allocates both strings before the borrow and releases them after it.
        // SAFETY: a static NUL-terminated string.
        unsafe { raise_with(15, 43, c"ssl/ssl_rsa.c".as_ptr(), 516) };
        ERR_clear_error();
        assert_eq!(
            dso_shared::take_in_borrow_probe(),
            0,
            "releases are deferred to after the borrow"
        );
        let (_, frees) = dso_shared::take_seam_probe();
        assert!(
            frees >= 1,
            "clear must release the strings through the seam"
        );
    }

    /// The stunnel 5.73 path: `SSL_CTX_use_certificate_chain_file` on an empty file fails,
    /// the PEM/libssl raises queue `err_file`/`err_func` strings, and the application calls
    /// `ERR_clear_error`.
    ///
    /// The defect was that those strings were allocated through the raising DSO's private
    /// `CRYPTO_malloc` while the clear released them through the other DSO's table; once an
    /// application installed memory functions the release was an invalid free. The error ring
    /// now allocates and releases through the process-global seam on both halves, which the
    /// probe observes. Reverting either half (the writer to a local `CRYPTO_malloc`, the reader
    /// to a local `CRYPTO_free`) makes one of the assertions below fail.
    #[test]
    fn certificate_chain_parse_failure_then_clear_error_uses_one_allocator_seam() {
        let _g = lock();
        drain();
        let path = std::env::temp_dir().join(format!(
            "openssl-rs-empty-cert-chain-{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, b"").expect("an empty temporary certificate file");
        let cpath = std::ffi::CString::new(path.to_str().expect("utf-8 temp path"))
            .expect("no interior NUL");
        let _ = dso_shared::take_seam_probe();
        // SAFETY: the method table is a static; the context is this frame's own object and is
        // released below. The path is a live NUL-terminated C string.
        let ctx = unsafe { crate::ssl::ssl_lib::SSL_CTX_new(crate::ssl::methods::TLS_method()) };
        assert!(!ctx.is_null(), "SSL_CTX_new must succeed");
        // SAFETY: both pointers are live per the comment above.
        let loaded =
            unsafe { crate::ssl::ssl_rsa::SSL_CTX_use_certificate_chain_file(ctx, cpath.as_ptr()) };
        assert_eq!(loaded, 0, "an empty certificate chain file must not load");
        assert_ne!(ERR_peek_error(), 0, "the parse failure must be queued");
        let (mallocs, _) = dso_shared::take_seam_probe();
        assert!(
            mallocs > 0,
            "the queued error strings must be allocated through the process-global seam"
        );
        ERR_clear_error();
        let (_, frees) = dso_shared::take_seam_probe();
        assert!(
            frees > 0,
            "ERR_clear_error must release them through the same process-global seam"
        );
        // SAFETY: `ctx` is this frame's own live context and this is its single release.
        unsafe { crate::ssl::ssl_lib::SSL_CTX_free(ctx) };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn generated_tables_are_complete_and_sorted() {
        // The lookup is a binary search, so an unsorted table would silently fail
        // to find entries rather than fail to compile. Assert it here.
        assert_eq!(err_strings::LIBS.len(), err_strings::LIB_COUNT);
        assert_eq!(err_strings::REASONS.len(), err_strings::REASON_COUNT);
        assert!(err_strings::LIBS.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(err_strings::REASONS.windows(2).all(|w| w[0].0 < w[1].0));
        for (_, text) in err_strings::LIBS.iter() {
            assert_eq!(*text.last().expect("non-empty"), 0, "missing terminator");
        }
        for (_, text) in err_strings::REASONS.iter() {
            assert_eq!(*text.last().expect("non-empty"), 0, "missing terminator");
        }
    }

    #[test]
    fn string_lookups_match_the_measured_authority_values() {
        let _g = lock();
        // `0x0780007F` is the overflow error the RT-MEM probe measured: library
        // 15 (`ERR_LIB_CRYPTO`), reason 127 (`CRYPTO_R_INTEGER_OVERFLOW`).
        assert_eq!(
            cstr(ERR_lib_error_string(0x0780_007F)).as_deref(),
            Some("common libcrypto routines")
        );
        assert_eq!(
            cstr(ERR_reason_error_string(0x0780_007F)).as_deref(),
            Some("integer overflow")
        );
        assert!(cstr(ERR_lib_error_string(200 << 23)).is_none());
        assert!(cstr(ERR_reason_error_string((15 << 23) | 0x007F_FFFF)).is_none());
        // `ERR_SYSTEM_FLAG` suppresses reason lookup entirely.
        assert!(cstr(ERR_reason_error_string(ERR_SYSTEM_FLAG | 15)).is_none());
        // `ERR_func_error_string` is unconditionally NULL in 3.x.
        assert!(ERR_func_error_string(0x0780_007F).is_null());
    }

    #[test]
    fn ring_keeps_fifteen_errors_and_evicts_the_oldest() {
        let _g = lock();
        drain();
        for i in 1..=20u32 {
            ERR_new();
            // SAFETY: a NUL-terminated literal.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        // The authority's ring has one slot of headroom, so 20 pushes retain 15.
        let mut seen = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            seen.push(get_reason(e));
        }
        assert_eq!(seen.len(), 15, "usable ring depth");
        // The survivors are the newest fifteen: reasons 6..=20.
        assert_eq!(seen.first().copied(), Some(6));
        assert_eq!(seen.last().copied(), Some(20));
    }

    #[test]
    fn get_is_fifo_and_peek_last_is_the_newest() {
        let _g = lock();
        drain();
        for i in 1..=3u32 {
            ERR_new();
            // SAFETY: NULL message is accepted.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        assert_eq!(get_reason(ERR_peek_error()), 1);
        assert_eq!(get_reason(ERR_peek_last_error()), 3);
        assert_eq!(get_reason(ERR_get_error()), 1);
        assert_eq!(get_reason(ERR_get_error()), 2);
        assert_eq!(get_reason(ERR_get_error()), 3);
        assert_eq!(ERR_get_error(), 0);
    }

    #[test]
    fn an_incomplete_slot_is_invisible() {
        let _g = lock();
        drain();
        ERR_new(); // never completed
        assert_eq!(ERR_peek_error(), 0);
        assert_eq!(ERR_get_error(), 0);
        ERR_new();
        // SAFETY: NULL message is accepted.
        unsafe { openssl_rs_err_set_error(15, 42, core::ptr::null()) };
        assert_eq!(get_reason(ERR_get_error()), 42);
    }

    #[test]
    fn marks_behave_as_measured() {
        let _g = lock();
        drain();
        // An empty queue has nothing to mark.
        assert_eq!(ERR_set_mark(), 0);
        for i in 1..=3u32 {
            ERR_new();
            // SAFETY: NULL message is accepted.
            unsafe { openssl_rs_err_set_error(15, i as c_int, core::ptr::null()) };
        }
        assert_eq!(ERR_set_mark(), 1);
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 4, core::ptr::null()) };
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 5, core::ptr::null()) };
        assert_eq!(ERR_count_to_mark(), 2);
        // Popping to the mark keeps the marked error itself.
        assert_eq!(ERR_pop_to_mark(), 1);
        assert_eq!(get_reason(ERR_peek_last_error()), 3);
        assert_eq!(ERR_pop_to_mark(), 0, "the mark was consumed");
    }

    #[test]
    fn error_string_uses_the_authority_format() {
        let _g = lock();
        let mut buf = [0i8; 256];
        // SAFETY: 256 writable bytes.
        unsafe { ERR_error_string_n(0x0780_007F, buf.as_mut_ptr(), 256) };
        let s = cstr(buf.as_ptr()).expect("non-null");
        assert_eq!(
            s,
            "error:0780007F:common libcrypto routines::integer overflow"
        );
        // A NULL buffer still works, through the shared static.
        // SAFETY: NULL is accepted and handled.
        let p = unsafe { ERR_error_string(0x0780_007F, core::ptr::null_mut()) };
        assert_eq!(cstr(p).as_deref(), Some(s.as_str()));
        // len == 0 is a no-op rather than a panic.
        // SAFETY: NULL with len 0.
        unsafe { ERR_error_string_n(1, core::ptr::null_mut(), 0) };
    }

    #[test]
    fn error_string_falls_back_to_numeric_fields() {
        let _g = lock();
        let mut buf = [0i8; 256];
        // SAFETY: 256 writable bytes.
        unsafe { ERR_error_string_n(0x7F80_0001, buf.as_mut_ptr(), 256) };
        let s = cstr(buf.as_ptr()).expect("non-null");
        // `ERR_error_string_n` always passes an empty `func` field, so the
        // pretty form contains two adjacent colons there.
        assert_eq!(s, "error:7F800001:lib(255)::reason(1)");
    }

    #[test]
    fn get_state_exposes_the_ring() {
        let _g = lock();
        drain();
        let es = ERR_get_state();
        assert!(!es.is_null());
        // SAFETY: `es` points into this thread's state for its lifetime.
        unsafe {
            assert_eq!((*es).top, 0);
            assert_eq!((*es).bottom, 0);
        }
        ERR_new();
        // SAFETY: as above.
        unsafe { openssl_rs_err_set_error(15, 7, core::ptr::null()) };
        // SAFETY: as above.
        unsafe {
            assert_eq!((*es).top, 1);
            assert_eq!((*es).bottom, 0);
            assert_eq!((*es).err_buffer[1], (15 << 23) | 7);
        }
        assert_eq!(ERR_pop(), 1);
        // SAFETY: as above.
        unsafe { assert_eq!((*es).top, 0) };
        assert_eq!(ERR_pop(), 0);
    }

    #[test]
    fn data_flags_and_ownership() {
        let _g = lock();
        drain();
        ERR_new();
        // SAFETY: NV is NUL-terminated.
        unsafe { openssl_rs_err_set_error(15, 1, c"a message".as_ptr()) };
        let mut data: *const c_char = core::ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: all out-parameters are NULL or point at live locals.
        let e = unsafe {
            ERR_peek_error_all(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut data,
                &mut flags,
            )
        };
        assert_eq!(get_reason(e), 1);
        assert_eq!(cstr(data).as_deref(), Some("a message"));
        assert_eq!(flags, ERR_TXT_MALLOCED | ERR_TXT_STRING);
        // A NULL message clears the data rather than leaving the previous text.
        ERR_new();
        // SAFETY: NULL is accepted and clears.
        unsafe { openssl_rs_err_set_error(15, 2, core::ptr::null()) };
        let mut flags2: c_int = 7;
        // SAFETY: as above.
        let _ = unsafe {
            ERR_peek_last_error_all(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut data,
                &mut flags2,
            )
        };
        assert_eq!(cstr(data).as_deref(), Some(""));
        assert_eq!(flags2, 0);
        drain();
    }

    /// NEO-ERR-1 probe: a borrowed slot must not escape `take_data` as the
    /// ``owned`` block the C variadic adapter passes to `CRYPTO_realloc`.
    ///
    /// The second half performs the adapter's exact realloc sequence on the
    /// returned pointer, which is where the pre-fix code reallocated the
    /// caller's borrowed storage.
    #[test]
    fn take_data_copies_borrowed_data_before_the_adapter_reallocs() {
        let _g = lock();
        drain();
        ERR_new();
        static BORROWED: &[u8] = b"borrowed message\0";
        let borrowed = BORROWED.as_ptr().cast::<c_char>() as *mut c_char;
        // SAFETY: static NUL-terminated storage; flags 0 means borrowed, so the
        // queue never owns it.
        unsafe { ERR_set_error_data(borrowed, 0) };

        let mut size: usize = 0;
        // SAFETY: `size` is writable.
        let taken = unsafe { openssl_rs_err_take_data(&mut size) };
        assert!(!taken.is_null(), "take_data must return an owned copy");
        assert_ne!(
            taken, borrowed,
            "borrowed storage must not be returned as the owned block"
        );
        assert_eq!(size, BORROWED.len());

        // Exactly what ERR_vset_error does: grow to ERR_MAX_DATA_SIZE, then
        // shrink to the formatted length plus its terminator.
        // SAFETY: `taken` is one whole block from the crate allocator.
        let grown = unsafe {
            crate::runtime::mem::CRYPTO_realloc(taken.cast(), 1024, core::ptr::null(), 0)
        };
        assert!(!grown.is_null(), "realloc of the owned copy must succeed");
        // SAFETY: `grown` is at least 1024 bytes and NUL-terminated.
        unsafe {
            assert_eq!(
                cstr(grown.cast::<c_char>()).as_deref(),
                Some("borrowed message")
            );
            crate::runtime::mem::CRYPTO_free(grown, core::ptr::null(), 0);
        }
        // The borrowed original is untouched and still readable.
        assert_eq!(
            cstr(borrowed.cast_const()).as_deref(),
            Some("borrowed message")
        );
        drain();
    }

    /// Negative control for NEO-ERR-1: the pre-fix adapter shape passed the
    /// detached slot pointer to `CRYPTO_realloc` without establishing that the
    /// slot owned it. On a borrowed slot that is an invalid realloc.
    ///
    /// Guarded so the normal suite never executes it. Run under ASan with
    /// `OPENSSL_RS_ERR_NEGATIVE_CONTROL=1`; the sanitizer must reject the
    /// realloc of static storage, which is what the pre-fix code did.
    #[test]
    fn borrowed_realloc_negative_control_fires_only_when_enabled() {
        if std::env::var_os("OPENSSL_RS_ERR_NEGATIVE_CONTROL").is_none() {
            return;
        }
        let _g = lock();
        drain();
        ERR_new();
        static BORROWED: &[u8] = b"pre-fix borrowed slot\0";
        let borrowed = BORROWED.as_ptr().cast::<c_char>() as *mut c_char;
        // SAFETY: static NUL-terminated storage; flags 0 means borrowed.
        unsafe { ERR_set_error_data(borrowed, 0) };
        // SAFETY: deliberately violates the block contract. This is the canary,
        // not a supported call, and ASan must report it.
        unsafe { crate::runtime::mem::CRYPTO_realloc(borrowed.cast(), 1024, core::ptr::null(), 0) };
        drain();
    }

    /// NEO-ERR-2: an owned slot with a zero extent is refused and the block is
    /// released instead of being stored for a later size-driven copy.
    #[test]
    fn finish_data_rejects_a_zero_extent_malloced_block() {
        let _g = lock();
        drain();
        ERR_new();
        // SAFETY: one fresh seam block, written as a NUL-terminated string.
        let p = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            crate::runtime::mem::CRYPTO_malloc(4, core::ptr::null(), 0)
        };
        assert!(!p.is_null());
        // SAFETY: `p` is four writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(b"abc".as_ptr(), p.cast::<u8>(), 3) };
        // SAFETY: `p` is a wholly owned seam block; size 0 violates the extent
        // contract, so the call must release it rather than store it.
        unsafe {
            openssl_rs_err_finish_data(
                15,
                42,
                p.cast::<c_char>(),
                0,
                ERR_TXT_MALLOCED | ERR_TXT_STRING,
            )
        };
        let mut data: *const c_char = core::ptr::null();
        let mut flags: c_int = -1;
        // SAFETY: NULL or writable out-parameters.
        let e = unsafe {
            ERR_peek_last_error_all(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut data,
                &mut flags,
            )
        };
        assert_eq!(get_reason(e), 42);
        // The read side renders an absent value as "" (EMPTY_C), so the flags
        // are what prove the slot stored nothing.
        assert_eq!(cstr(data).as_deref(), Some(""));
        assert_eq!(flags, 0, "a zero-extent owned slot must not be stored");
        drain();
    }

    /// Reports the end of a thread's own thread-local teardown.
    ///
    /// Initialized **before** the thread's first `ERR` call, so its destructor is registered
    /// before the state's and therefore runs after it (thread-local destructors run LIFO).
    /// Sending from the destructor is how the test learns that the state destructor has
    /// already run, rather than racing `thread::join` against TLS teardown.
    struct ExitReporter(RefCell<Option<std::sync::mpsc::Sender<()>>>);

    impl Drop for ExitReporter {
        fn drop(&mut self) {
            if let Some(tx) = self.0.get_mut().take() {
                let _ = tx.send(());
            }
        }
    }

    thread_local! {
        static EXIT_REPORTER: ExitReporter = const { ExitReporter(RefCell::new(None)) };
    }

    /// V3b: thread exit releases the buffers the per-thread error ring still owns.
    ///
    /// The ring is public `#[repr(C)]` layout, so the test reads the **address** of the data
    /// buffer its raise attached from the live state inside the thread. It then observes a
    /// `CRYPTO_free` of that exact address after the state's destructor has run. Before the
    /// state had a destructor nothing released the buffer at exit; that is the leak V3's ASan
    /// run reported as 84 bytes from `raise_site_dynamic_data`.
    #[test]
    fn err_thread_exit_releases_the_queued_data_buffer() {
        let _g = lock();
        drain();

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            // Registered before the first ERR call, so it is destroyed after the state.
            EXIT_REPORTER.with(|r| *r.0.borrow_mut() = Some(tx));
            // SAFETY: the site's pointers are static and `msg` is NUL-terminated.
            unsafe {
                raise_site_dynamic_data(
                    &err_sites::EVP_FETCH_376,
                    1,
                    c"provider=default, Algorithm (SHA256 : 5)".as_ptr(),
                )
            };
            // The same accessor `with_state` uses, so the address is read from the state the
            // raise actually wrote to.
            let state = dso_shared::err_state_ptr();
            assert!(!state.is_null(), "the thread must have a live error state");
            // SAFETY: `state` is this thread's live state; the read happens before the thread
            // returns, and no other handle can release the buffer.
            let addr = unsafe {
                let top = (*state).top as usize;
                assert_ne!(
                    (*state).err_data_flags[top] & ERR_TXT_MALLOCED,
                    0,
                    "the raise must attach an owned data buffer"
                );
                (*state).err_data[top] as usize
            };
            assert_ne!(addr, 0, "the raise must attach a non-NULL data buffer");
            dso_shared::arm_free_observation(addr);
            addr
        });

        let addr = handle
            .join()
            .expect("the error-raising thread must not panic");
        // The state's destructor is registered after the reporter's, so its teardown has
        // completed by the time this message arrives.
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the thread-local teardown did not complete");
        assert!(
            dso_shared::take_free_observation(),
            "the per-thread error state must release the buffer at {addr:#x} it still owned at \
             thread exit"
        );
    }
}
