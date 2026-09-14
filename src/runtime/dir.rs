//! `crypto/o_dir.c` — `OPENSSL_DIR_read` and `OPENSSL_DIR_end`, the directory
//! walk that `.include` of a *directory* is built on, plus the two internal path
//! predicates the include logic asks about.
//!
//! ## Why this module is in Phase 3's family
//!
//! It was in **no** phase's family until the ownership audit
//! (`forensics/tools/ownership_audit.py`) looked for the exports that no ledger
//! claims. `src/runtime/conf/` needed `OPENSSL_DIR_read` to read an include
//! directory, which is how the gap surfaced; the module itself is core runtime,
//! which is Phase 3. See `docs/DECISIONS.md` D51.
//!
//! ## What the authority's context object is, and what it is not
//!
//! `OPENSSL_DIR_CTX` is opaque in the public header (`internal/o_dir.h`) and the
//! authority allocates it with the **C library's** `malloc`, not `CRYPTO_malloc`
//! — the file's own comment says the routines "really come from the Levitte
//! Programming" and were only renamed into OpenSSL's namespace. That choice is
//! reproduced: the context is a `malloc`/`free` object, so a caller who replaces
//! the OpenSSL allocator does not have to be able to free this one.
//!
//! The authority's `struct LP_dir_context_st` is `{ DIR *dir; char
//! entry_name[LP_ENTRY_SIZE + 1]; }` with `LP_ENTRY_SIZE` = `PATH_MAX` where
//! `PATH_MAX` is defined (4096 on the admitted Linux profile). The returned
//! pointer is the *interior* `entry_name` buffer, valid until the next call on
//! the same context — so the buffer is part of the struct here too, rather than
//! a Rust `Vec` whose reallocation could move it.
//!
//! ## The two path predicates
//!
//! `ossl_ends_with_dirsep` and `ossl_is_absolute_path` are `static inline` in
//! `include/internal/common.h`, so no symbol is exported for them; they are
//! internal helpers with exactly one consumer in this stratum
//! (`conf_def.c`'s `.include` handling). They are kept here, next to the
//! directory walk they serve, rather than in a module of their own. Their
//! platform-conditional arms (`__VMS`, `_WIN32`) are not transcribed: the
//! admitted authority profile is Linux, and a Windows arm written from a
//! literal would be an unmeasured claim about a platform this crate has never
//! observed.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::str::OPENSSL_strlcpy;

use crate::runtime::bio::sys;

/// `LP_ENTRY_SIZE` — `PATH_MAX` on the admitted profile.
const LP_ENTRY_SIZE: usize = 4096;

/// `struct LP_dir_context_st`, as far as its size and its `entry_name` interior
/// pointer are concerned. The `DIR *` is kept as an opaque `*mut c_void` because
/// only the C shim ever dereferences it.
#[repr(C)]
pub struct OpenSslDirCtx {
    /// The platform's `DIR *`, from `openssl_rs_dir_open`.
    dir: *mut c_void,
    /// `char entry_name[LP_ENTRY_SIZE + 1]`.
    entry_name: [c_char; LP_ENTRY_SIZE + 1],
}

extern "C" {
    /// `opendir(3)`, wrapped so the `DIR` type never escapes C.
    fn openssl_rs_dir_open(path: *const c_char) -> *mut c_void;
    /// One `readdir(3)` step; NULL at end of directory or on error, with the
    /// error reported through `err`.
    fn openssl_rs_dir_next(dir: *mut c_void, err: *mut c_int) -> *const c_char;
    /// `closedir(3)`.
    fn openssl_rs_dir_close(dir: *mut c_void) -> c_int;
    /// `stat(3)` restricted to the one question the include logic asks:
    /// -1 error (in `*err`), 0 not a directory, 1 a directory.
    fn openssl_rs_stat_is_dir(path: *const c_char, err: *mut c_int) -> c_int;
}

/// Sets the thread's `errno`, as the authority's `LP_find_file` does directly.
fn set_errno(value: c_int) {
    // SAFETY: `errno_location` returns a valid pointer to the thread's own slot.
    unsafe { sys::set_errno(value) };
}

/// The thread's `errno`.
fn errno() -> c_int {
    // SAFETY: `errno_location` returns a valid pointer to the thread's own slot.
    unsafe { sys::errno() }
}

/// `const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx, const char *directory)`
///
/// Opens the directory on the first call (`*ctx == NULL`) and returns one entry
/// name per call thereafter, including `.` and `..`, exactly as `readdir` does.
/// A NULL `ctx` or `directory` is `EINVAL`; a failed `opendir` leaves the context
/// NULL and `errno` set to the failure; end of directory is a NULL return with
/// `errno == 0`, which is the documented way to tell it apart from an error.
///
/// The returned pointer is the context's own buffer: it is invalidated by the
/// next call and by [`OPENSSL_DIR_end`].
///
/// # Safety
/// `ctx` must be NULL or point to a NULL-or-live context; `directory` must be
/// NULL or a NUL-terminated path.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_DIR_read(
    ctx: *mut *mut OpenSslDirCtx,
    directory: *const c_char,
) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if ctx.is_null() || directory.is_null() {
            set_errno(sys::EINVAL);
            return ptr::null();
        }
        set_errno(0);
        // SAFETY: `ctx` is non-NULL (rejected above) and the caller's contract
        // makes it a readable pointer to an `OPENSSL_DIR_CTX *` slot.
        if unsafe { *ctx }.is_null() {
            // SAFETY: a plain C-library allocation of a known size, matching the
            // authority's own choice of allocator for this object.
            let fresh = unsafe { sys::malloc(core::mem::size_of::<OpenSslDirCtx>()) }
                .cast::<OpenSslDirCtx>();
            if fresh.is_null() {
                set_errno(sys::ENOMEM);
                return ptr::null();
            }
            // SAFETY: `fresh` is a fresh block of exactly this type.
            unsafe {
                sys::memset(
                    fresh.cast::<c_void>(),
                    0,
                    core::mem::size_of::<OpenSslDirCtx>(),
                );
                (*fresh).dir = openssl_rs_dir_open(directory);
            }
            // SAFETY: `fresh` is the non-NULL block allocated above and zeroed
            // by the `memset`, so its `dir` field is readable.
            if unsafe { (*fresh).dir }.is_null() {
                let saved = errno();
                // SAFETY: `fresh` came from `malloc` above; `free` is its match.
                unsafe { sys::free(fresh.cast::<c_void>()) };
                set_errno(saved);
                return ptr::null();
            }
            // SAFETY: `ctx` is a live out-parameter per the caller's contract.
            unsafe { *ctx = fresh };
        }
        let mut read_err: c_int = 0;
        // SAFETY: `*ctx` is non-NULL and live (its contract), so `dir` is an
        // open stream; `read_err` is a live local this step may write.
        let name = unsafe { openssl_rs_dir_next((**ctx).dir, &mut read_err) };
        if name.is_null() {
            // `readdir` returns NULL both at end of directory and on error; the
            // authority deliberately does *not* touch `errno` here, so the
            // caller's `errno == 0` test distinguishes them. Reproduced by
            // leaving `errno` alone.
            return ptr::null();
        }
        // SAFETY: `name` is a readdir-owned string valid until the next step.
        let entry = unsafe { &mut (**ctx).entry_name };
        // SAFETY: `name` is NUL-terminated and `entry` is `LP_ENTRY_SIZE + 1`
        // bytes; `OPENSSL_strlcpy` writes at most that many bytes.
        unsafe { OPENSSL_strlcpy(entry.as_mut_ptr(), name, entry.len()) };
        entry.as_ptr()
    })
}

/// `int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx)`
///
/// Closes the stream and frees the context. A NULL `ctx`, or a context that was
/// never opened, is `EINVAL` and reports failure. The authority's `switch` has
/// the same effect as `ret == 0`; a `closedir` that returned anything else still
/// frees the context and falls through to `EINVAL`, which is reproduced.
///
/// # Safety
/// `ctx` must be NULL or point to a NULL-or-live context; the context must not
/// be used again afterwards.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_DIR_end(ctx: *mut *mut OpenSslDirCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or, per the caller's contract, points to a
        // readable `OPENSSL_DIR_CTX *` slot; the short-circuit guards the read.
        if !ctx.is_null() && !unsafe { *ctx }.is_null() {
            // SAFETY: `*ctx` is live per the caller's contract, so it owns an
            // open stream and a `malloc`'d block.
            let ret = unsafe {
                let c = *ctx;
                let r = openssl_rs_dir_close((*c).dir);
                sys::free(c.cast::<c_void>());
                r
            };
            if ret == 0 {
                return 1;
            }
            if ret == -1 {
                return 0;
            }
        }
        set_errno(sys::EINVAL);
        0
    })
}

/// The three-state answer `stat` gives about a path, for the include logic.
///
///  * `Err(errno)` — `stat` failed
///  * `Ok(false)` — the path exists and is not a directory
///  * `Ok(true)`  — the path exists and is a directory
///
/// The decision itself (`S_ISDIR`) is made in C, by the platform's own header;
/// see `src/runtime/dir_posix.c` for why no field offset is assumed here.
///
/// # Safety
/// `path` must be a NUL-terminated C string.
pub(crate) unsafe fn stat_is_dir(path: *const c_char) -> Result<bool, c_int> {
    let mut err: c_int = 0;
    // SAFETY: `path` is NUL-terminated and `err` is writable.
    match unsafe { openssl_rs_stat_is_dir(path, &mut err) } {
        -1 => Err(err),
        0 => Ok(false),
        _ => Ok(true),
    }
}

/// `int ossl_ends_with_dirsep(const char *path)`
///
/// True when the last character is `/`. An empty string is not a separator:
/// the authority only looks at the last byte when the string is non-empty.
///
/// # Safety
/// `path` must be a NUL-terminated C string.
pub unsafe fn ossl_ends_with_dirsep(path: *const c_char) -> c_int {
    // SAFETY: `path` is NUL-terminated per the caller's contract.
    let len = unsafe { sys::strlen(path) };
    if len == 0 {
        return 0;
    }
    // SAFETY: byte `len - 1` is inside the string, since `len >= 1`.
    c_int::from(unsafe { *path.add(len - 1) } == b'/' as c_char)
}

/// `int ossl_is_absolute_path(const char *path)`
///
/// On the admitted profile this is `path[0] == '/'`, including for the empty
/// string (which is not absolute).
///
/// # Safety
/// `path` must be a NUL-terminated C string.
pub unsafe fn ossl_is_absolute_path(path: *const c_char) -> c_int {
    // SAFETY: byte 0 of a NUL-terminated string is always readable.
    c_int::from(unsafe { *path } == b'/' as c_char)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn path_predicates_match_the_authority() {
        for (input, ends, abs) in [
            ("/tmp/x", 0, 1),
            ("/tmp/", 1, 1),
            ("tmp/x", 0, 0),
            ("", 0, 0),
            ("/", 1, 1),
            ("//", 1, 1),
        ] {
            let Ok(c) = CString::new(input) else {
                unreachable!("the test inputs contain no interior NUL");
            };
            // SAFETY: `c` is a live NUL-terminated string.
            let (e, a) = unsafe {
                (
                    ossl_ends_with_dirsep(c.as_ptr()),
                    ossl_is_absolute_path(c.as_ptr()),
                )
            };
            assert_eq!(e, ends, "ossl_ends_with_dirsep({input:?})");
            assert_eq!(a, abs, "ossl_is_absolute_path({input:?})");
        }
    }

    /// A NULL context and a NULL path are `EINVAL`, and end-of-directory is a
    /// NULL return with the *unchanged* `errno` that distinguishes it from a
    /// failure. Both are what the authority's `LP_find_file` documents.
    #[test]
    fn null_arguments_and_end_of_directory_are_distinguishable() {
        let mut ctx: *mut OpenSslDirCtx = ptr::null_mut();
        // SAFETY: explicitly NULL arguments are defined behaviour here.
        unsafe {
            assert!(OPENSSL_DIR_read(ptr::null_mut(), ptr::null()).is_null());
            assert_eq!(errno(), sys::EINVAL);
            assert!(OPENSSL_DIR_read(&mut ctx, ptr::null()).is_null());
            assert_eq!(errno(), sys::EINVAL);
            assert_eq!(OPENSSL_DIR_end(&mut ctx), 0);
            assert_eq!(errno(), sys::EINVAL);
        }

        // An empty directory: the first call opens it, the second reports the end.
        let dir = std::env::temp_dir().join(format!("openssl-rs-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let Ok(()) = std::fs::create_dir_all(&dir) else {
            unreachable!("the temp directory can be created");
        };
        let Some(dir_str) = dir.to_str() else {
            unreachable!("the temp dir path is valid UTF-8");
        };
        let Ok(path) = CString::new(dir_str) else {
            unreachable!("the temp dir path has no interior NUL");
        };
        // SAFETY: `ctx` is NULL and `path` is a live NUL-terminated string.
        unsafe {
            set_errno(0);
            let first = OPENSSL_DIR_read(&mut ctx, path.as_ptr());
            assert!(!ctx.is_null());
            assert!(!first.is_null(), "a fresh directory has at least `.`");
            // Walk to the end; the authority leaves `errno` untouched there, so
            // it is the caller's job to have zeroed it (as `LP_find_file` does).
            let mut n = 1;
            loop {
                set_errno(0);
                let next = OPENSSL_DIR_read(&mut ctx, path.as_ptr());
                if next.is_null() {
                    assert_eq!(errno(), 0, "end of directory, not an error");
                    break;
                }
                n += 1;
                assert!(n < 1000, "a fresh directory cannot have 1000 entries");
            }
            // `.` and `..` are both returned.
            assert_eq!(n, 2);
            assert_eq!(OPENSSL_DIR_end(&mut ctx), 1);
            // The authority's `LP_find_file_end` frees the context and does
            // **not** clear the caller's pointer, so a caller that reuses the
            // context without resetting it to NULL has `OPENSSL_DIR_read` treat
            // it as already open and `readdir` a freed `DIR`. That hazard is the
            // authority's and is reproduced rather than quietly repaired; the
            // pointer is only *compared* here, never followed.
            assert!(!ctx.is_null(), "end does not clear the caller's pointer");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
