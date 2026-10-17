//! `crypto/x509/by_dir.c` — the `X509_LOOKUP_hash_dir` method: the hashed-directory lookup.
//! **This slice lands the unit whole**: its one open export, `X509_LOOKUP_hash_dir` (`:77-80`), and
//! the `static` callbacks, helpers and layouts it is built on.
//!
//! `crypto/x509/by_dir.c` is 448 lines. Its closure is now complete. The two loaders its
//! `get_cert_by_subject_ex` reaches are landed
//! ([`X509_load_cert_file_ex`](crate::x509::by_file::X509_load_cert_file_ex) and
//! [`X509_load_crl_file`](crate::x509::by_file::X509_load_crl_file), 11.6); `X509_get_default_cert_dir`
//! (`crypto/x509/x509_def.c:88-96`) and its env-var name (`:108-111`) are landed in
//! [`crate::x509::x509_def`]; and the `#ifndef OPENSSL_NO_POSIX_IO` existence probe (`:321-337`)
//! is served by the new existence-only `lstat`/`stat` shims (`src/runtime/dir_posix.c`, declared in
//! [`crate::runtime::dir`]). The one name `court/unit_ready.py` lists besides
//! `X509_get_default_cert_dir`, `ossl_safe_getenv`, is landed in `src/runtime/getenv.rs` (the tool
//! reports it only because it is not an exported `libcrypto` symbol, not because it is missing).
//!
//! ## The former D453 withholding is discharged
//!
//! This unit was once withheld by name, and `get_cert_by_subject_ex`/`get_cert_by_subject` under a
//! second reason that `docs/DECISIONS.md` D453 names ("a function whose closure is complete is still
//! withheld when no reachable caller exists"): their only authority callers are `x509_dir_lookup`'s
//! `get_by_subject`/`get_by_subject_ex` slots, and that row was withheld for `dir_ctrl`. That reason
//! **dissolves exactly when the row lands** — the row's `ctrl` slot is `dir_ctrl`, whose
//! `X509_FILETYPE_DEFAULT` arm now reaches the landed `X509_get_default_cert_dir`, and its two
//! `get_by_subject*` slots now reach the landed loaders and the new existence shims. With the row
//! landed, every one of the names below has a reachable caller, so the whole unit lands.
//!
//! ## The landed surface
//!
//! * The three layouts `BY_DIR_HASH` (`:34-37`), `BY_DIR_ENTRY` (`:39-43`) and `BY_DIR` (`:45-49`),
//!   and the four `static`s that serve them: `by_dir_hash_free` (`:134-137`), `by_dir_hash_cmp`
//!   (`:139-147`), `by_dir_entry_free` (`:149-154`), `new_dir` (`:108-132`) and `free_dir`
//!   (`:156-164`).
//! * `add_cert_dir` (`:166-220`) — the directory-list parser. `dir` is a `LIST_SEPARATOR_CHAR`
//!   (`:` on this profile, `include/internal/e_os.h:213`) separated list; each non-empty element
//!   that is not already present is duplicated into a `BY_DIR_ENTRY` with its own sorted hash stack.
//! * `get_cert_by_subject_ex` (`:222-442`) and its wrapper `get_cert_by_subject` (`:444-448`) — the
//!   subject lookup. For each directory it formats `dir/<hash>.<suffix>` (or `dir/<hash>r.<suffix>`
//!   for a CRL), probes existence through the new `lstat`/`stat` shims, loads the file with the
//!   landed loaders, then pulls the cached object back out of the store. The `#ifndef
//!   OPENSSL_NO_POSIX_IO` arm reprobes with `stat` so a dangling symlink advances the suffix rather
//!   than stopping the scan.
//! * `dir_ctrl` (`:82-106`) — the method's control door. `X509_L_ADD_DIR` parses `argp`, or the
//!   environment's directory (or the compiled-in default) when `argl` is `X509_FILETYPE_DEFAULT`.
//! * The row `x509_dir_lookup` (`:62-75`) and its constructor `X509_LOOKUP_hash_dir` (`:77-80`).
//!
//! ## The raise sites
//!
//! `crypto/x509/by_dir.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the ten
//! coordinates the unit reaches are **declared locally** in the `err_sites::ErrSite` shape (as
//! `v3_addr.rs` does). The reasons are read from `include/openssl/err.h.in` — `ERR_R_BN_LIB`
//! (`ERR_LIB_BN (3) | ERR_RFLAG_COMMON`) and `ERR_R_BUF_LIB` (`ERR_LIB_BUF (7) | ERR_RFLAG_COMMON`)
//! — and the generated `x509err.h` (`X509_R_INVALID_DIRECTORY`, `X509_R_LOADING_CERT_DIR`,
//! `X509_R_WRONG_LOOKUP_TYPE`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void, CStr};
use core::mem::{size_of, MaybeUninit};
use core::ptr;

use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx, RawCtx};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys;
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new, BufMem};
use crate::runtime::dir::{openssl_rs_lstat_exists, openssl_rs_stat_exists};
use crate::runtime::err::err_reasons::{
    X509_R_INVALID_DIRECTORY, X509_R_LOADING_CERT_DIR, X509_R_WRONG_LOOKUP_TYPE,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_clear_error, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strndup};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_is_sorted, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};
use crate::x509::by_file::{X509_load_cert_file_ex, X509_load_crl_file};
use crate::x509::x509_cmp::X509_NAME_hash_ex;
use crate::x509::x509_def::{X509_get_default_cert_dir, X509_get_default_cert_dir_env};
use crate::x509::x509_lu::{
    X509Lookup, X509LookupMethod, X509Object, X509_STORE_lock, X509_STORE_unlock, X509_LOOKUP_TYPE,
    X509_LU_CRL, X509_LU_X509,
};
use crate::x509::x_crl::X509Crl;
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::X509;

// ---------------------------------------------------------------------------------------------
// Constants and raise coordinates — see the module doc.
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BN_LIB` — `include/openssl/err.h.in:319`, `ERR_LIB_BN (3) | ERR_RFLAG_COMMON`.
const ERR_R_BN_LIB: c_int = 524291;
/// `ERR_R_BUF_LIB` — `include/openssl/err.h.in:323`, `ERR_LIB_BUF (7) | ERR_RFLAG_COMMON`.
const ERR_R_BUF_LIB: c_int = 524295;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO (15) | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;

/// `X509_FILETYPE_PEM` — `include/openssl/x509.h.in:70`.
const X509_FILETYPE_PEM: c_int = 1;
/// `X509_FILETYPE_DEFAULT` — `include/openssl/x509.h:170`.
const X509_FILETYPE_DEFAULT: c_int = 3;
/// `X509_L_ADD_DIR` — `include/openssl/x509_vfy.h:284`, the command behind `X509_LOOKUP_add_dir`.
const X509_L_ADD_DIR: c_int = 2;

/// `LIST_SEPARATOR_CHAR` — `include/internal/e_os.h:213`, `:` on the admitted (non-VMS,
/// non-Windows) profile.
const LIST_SEPARATOR_CHAR: c_char = b':' as c_char;

/// The `OPENSSL_FILE` string for this unit's `CRYPTO_malloc`/`CRYPTO_strndup`/`CRYPTO_free`
/// expansions.
const FILE: &CStr = c"crypto/x509/by_dir.c";
/// `new_dir`'s `OPENSSL_malloc(sizeof(*a))` (`:110`).
const LINE_MALLOC_DIR: c_int = 110;
/// `new_dir`'s error-path `OPENSSL_free(a)` (`:130`).
const LINE_FREE_DIR_NEW: c_int = 130;
/// `by_dir_hash_free`'s `OPENSSL_free(hash)` (`:136`).
const LINE_FREE_HASH: c_int = 136;
/// `by_dir_entry_free`'s `OPENSSL_free(ent->dir)` (`:151`).
const LINE_FREE_ENTRY_DIR: c_int = 151;
/// `by_dir_entry_free`'s `OPENSSL_free(ent)` (`:153`).
const LINE_FREE_ENTRY: c_int = 153;
/// `free_dir`'s `OPENSSL_free(a)` (`:163`).
const LINE_FREE_DIR: c_int = 163;
/// `add_cert_dir`'s `OPENSSL_malloc(sizeof(*ent))` (`:202`).
const LINE_MALLOC_ENTRY: c_int = 202;
/// `add_cert_dir`'s `OPENSSL_strndup(ss, len)` (`:207`).
const LINE_STRNDUP_ENTRY_DIR: c_int = 207;
/// `get_cert_by_subject_ex`'s `OPENSSL_malloc(sizeof(*hent))` (`:389`).
const LINE_MALLOC_HASH: c_int = 389;
/// `get_cert_by_subject_ex`'s error-path `OPENSSL_free(hent)` (`:399`).
const LINE_FREE_HASH_PUSH: c_int = 399;

/// One `by_dir.c` raise coordinate, declared locally (see the module doc).
const fn by_dir_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/by_dir.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `dir_ctrl`'s failed default-directory add at `by_dir.c:99` (`X509_R_LOADING_CERT_DIR`).
const BY_DIR_99: ErrSite = by_dir_site(99, c"dir_ctrl", X509_R_LOADING_CERT_DIR);
/// `new_dir`'s failed `BUF_MEM_new` at `by_dir.c:116` (`ERR_R_BN_LIB`).
const BY_DIR_116: ErrSite = by_dir_site(116, c"new_dir", ERR_R_BN_LIB);
/// `new_dir`'s failed `CRYPTO_THREAD_lock_new` at `by_dir.c:123` (`ERR_R_CRYPTO_LIB`).
const BY_DIR_123: ErrSite = by_dir_site(123, c"new_dir", ERR_R_CRYPTO_LIB);
/// `add_cert_dir`'s NULL or empty `dir` at `by_dir.c:173` (`X509_R_INVALID_DIRECTORY`).
const BY_DIR_173: ErrSite = by_dir_site(173, c"add_cert_dir", X509_R_INVALID_DIRECTORY);
/// `add_cert_dir`'s failed `sk_BY_DIR_ENTRY_new_null` at `by_dir.c:198` (`ERR_R_CRYPTO_LIB`).
const BY_DIR_198: ErrSite = by_dir_site(198, c"add_cert_dir", ERR_R_CRYPTO_LIB);
/// `add_cert_dir`'s failed `sk_BY_DIR_ENTRY_push` at `by_dir.c:214` (`ERR_R_CRYPTO_LIB`).
const BY_DIR_214: ErrSite = by_dir_site(214, c"add_cert_dir", ERR_R_CRYPTO_LIB);
/// `get_cert_by_subject_ex`'s unknown `type` at `by_dir.c:250` (`X509_R_WRONG_LOOKUP_TYPE`).
const BY_DIR_250: ErrSite = by_dir_site(250, c"get_cert_by_subject_ex", X509_R_WRONG_LOOKUP_TYPE);
/// `get_cert_by_subject_ex`'s failed `BUF_MEM_new` at `by_dir.c:255` (`ERR_R_BUF_LIB`).
const BY_DIR_255: ErrSite = by_dir_site(255, c"get_cert_by_subject_ex", ERR_R_BUF_LIB);
/// `get_cert_by_subject_ex`'s failed `BUF_MEM_grow` at `by_dir.c:271` (`ERR_R_BUF_LIB`).
const BY_DIR_271: ErrSite = by_dir_site(271, c"get_cert_by_subject_ex", ERR_R_BUF_LIB);
/// `get_cert_by_subject_ex`'s failed `sk_BY_DIR_HASH_push` at `by_dir.c:400` (`ERR_R_CRYPTO_LIB`).
const BY_DIR_400: ErrSite = by_dir_site(400, c"get_cert_by_subject_ex", ERR_R_CRYPTO_LIB);

// ---------------------------------------------------------------------------------------------
// The layouts — `crypto/x509/by_dir.c:34-49`.
// ---------------------------------------------------------------------------------------------

/// `struct lookup_dir_hashes_st` — `BY_DIR_HASH`, from `crypto/x509/by_dir.c:34-37`.
///
/// One subject-hash value a directory has served a CRL for, and the largest suffix seen for it.
#[repr(C)]
struct ByDirHash {
    /// `unsigned long hash` — the `X509_NAME_hash_ex` value.
    hash: c_ulong,
    /// `int suffix` — the largest `<hash>r<suffix>` file index seen.
    suffix: c_int,
}

/// `struct lookup_dir_entry_st` — `BY_DIR_ENTRY`, from `crypto/x509/by_dir.c:39-43`.
///
/// One directory in the lookup's list, with its file type and its sorted hash records.
#[repr(C)]
struct ByDirEntry {
    /// `char *dir` — the directory path, owned.
    dir: *mut c_char,
    /// `int dir_type` — the `X509_FILETYPE_*` word the directory's files use.
    dir_type: c_int,
    /// `STACK_OF(BY_DIR_HASH) *hashes` — the CRL suffix records, ordered by [`by_dir_hash_cmp`].
    hashes: *mut OpenSslStack,
}

/// `struct lookup_dir_st` — `BY_DIR`, from `crypto/x509/by_dir.c:45-49`.
///
/// The method's private data: the shared path buffer, the directory list and the lock guarding
/// each entry's hash stack.
#[repr(C)]
struct ByDir {
    /// `BUF_MEM *buffer` — the scratch buffer the candidate paths are formatted into.
    buffer: *mut BufMem,
    /// `STACK_OF(BY_DIR_ENTRY) *dirs` — the directories added so far.
    dirs: *mut OpenSslStack,
    /// `CRYPTO_RWLOCK *lock` — guards each entry's `hashes` stack.
    lock: *mut CryptoRwlock,
}

// ---------------------------------------------------------------------------------------------
// Ownership of the file's heap records
// ---------------------------------------------------------------------------------------------

/// An owned `BY_DIR` block still under construction.
///
/// `new_dir` allocates the record and fills its members one at a time; until the last is set the
/// bytes are not a valid `BY_DIR`, so the authority's error path (`by_dir.c:130`) releases the block
/// *alone* -- running `free_dir`'s destructor over members it has not initialised would read them.
/// This handle is that block-only release; [`Self::finish`] hands the block to the lookup's
/// `method_data`, where [`OwnedCtx`] later releases it through `free_dir`'s own destructor.
struct RawDir {
    ptr: ptr::NonNull<ByDir>,
}

impl RawDir {
    /// `CRYPTO_malloc(sizeof(*a), FILE, 110)`, or `None` when it answers NULL.
    fn new() -> Option<RawDir> {
        // `CRYPTO_malloc` is a safe function: it answers NULL or a fresh, writable block of
        // `size_of::<ByDir>()` bytes, which is exactly `BY_DIR`'s layout.
        let raw = CRYPTO_malloc(size_of::<ByDir>(), FILE.as_ptr(), LINE_MALLOC_DIR).cast::<ByDir>();
        ptr::NonNull::new(raw).map(|ptr| RawDir { ptr })
    }

    /// The writable start of the block.
    fn as_ptr(&self) -> *mut ByDir {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the lookup's `method_data`.
    fn finish(self) -> *mut ByDir {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for RawDir {
    /// The authority's `new_dir` error-path release (`by_dir.c:130`): the block alone.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `new` allocated and has not been handed out; its single
        // release is the authority's own plain `CRYPTO_free` at the `err:` label.
        unsafe {
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_DIR_NEW,
            )
        };
    }
}

/// The authority's `by_dir_hash_free` body: a `BY_DIR_HASH` owns no sub-resources, so only the
/// block release [`OwnedCtx`]'s `Drop` performs is left.
// SAFETY: (a) holds: `destroy_body` is the authority's no-op `by_dir_hash_free` body -- the record
// owns no releasable members -- and it never releases the enclosing block, which `OwnedCtx`'s
// `Drop` owns. (b) holds: `ByDirHash` is a `#[repr(C)]` record of two integers, so an all-zero block
// is a valid value and the empty body is sound on it.
unsafe impl CtxDestroy for ByDirHash {
    unsafe fn destroy_body(_ptr: *mut ByDirHash) {}
}

/// The authority's `by_dir_entry_free` body, without the block release [`OwnedCtx`]'s `Drop`
/// performs: the owned directory path and the stack of hash records.
// SAFETY: (a) holds: `destroy_body` is `by_dir_entry_free` -- it releases exactly the record's own
// `dir` string and `hashes` stack (each NULL-tolerant) and never the enclosing block. (b) holds:
// `ByDirEntry` is a `#[repr(C)]` record of a pointer, an integer and a stack pointer, so an
// all-zero block is a valid value and both releases accept NULL.
unsafe impl CtxDestroy for ByDirEntry {
    unsafe fn destroy_body(ptr: *mut ByDirEntry) {
        // SAFETY: `ptr` is a live record per the trait contract; `dir` is NULL or this file's
        // `CRYPTO_strndup` block, and `hashes` is NULL or this file's own stack.
        unsafe {
            CRYPTO_free((*ptr).dir.cast(), FILE.as_ptr(), LINE_FREE_ENTRY_DIR);
            OPENSSL_sk_pop_free((*ptr).hashes, Some(by_dir_hash_free_thunk));
        }
    }
}

/// The authority's `free_dir` body, without the block release [`OwnedCtx`]'s `Drop` performs: the
/// directory list, the scratch buffer and the lock.
// SAFETY: (a) holds: `destroy_body` is `by_dir_free` -- it releases exactly the record's own
// `dirs` stack, `buffer` and `lock` (each NULL-tolerant) and never the enclosing block. (b) holds:
// `ByDir` is a `#[repr(C)]` record of three raw pointers, so an all-zero block is a valid value and
// `OPENSSL_sk_pop_free(NULL)`/`BUF_MEM_free(NULL)`/`CRYPTO_THREAD_lock_free(NULL)` are no-ops.
unsafe impl CtxDestroy for ByDir {
    unsafe fn destroy_body(ptr: *mut ByDir) {
        // SAFETY: `ptr` is a live record per the trait contract; each member is NULL or owned by it.
        unsafe {
            OPENSSL_sk_pop_free((*ptr).dirs, Some(by_dir_entry_free_thunk));
            BUF_MEM_free((*ptr).buffer);
            CRYPTO_THREAD_lock_free((*ptr).lock);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The hash records — `crypto/x509/by_dir.c:134-164`.
// ---------------------------------------------------------------------------------------------

/// The `OPENSSL_sk_pop_free` adapter for the `BY_DIR_HASH` record.
///
/// Takes the raw element the stack hands back and reclaims it as an [`OwnedCtx`], whose `Drop` is
/// the record's single release at the authority's own `by_dir_hash_free` site.
///
/// # Safety
///
/// `elem` must be NULL or a `BY_DIR_HASH` record this module's `CRYPTO_malloc` allocated.
unsafe extern "C" fn by_dir_hash_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a `BY_DIR_HASH` this module allocated; `from_raw` reclaims it and
    // `Drop` runs the authority's own release.
    drop(unsafe { OwnedCtx::<ByDirHash>::from_raw_at(elem.cast(), FILE.as_ptr(), LINE_FREE_HASH) });
}

/// `static int by_dir_hash_cmp(const BY_DIR_HASH *const *a, const BY_DIR_HASH *const *b)` —
/// `crypto/x509/by_dir.c:139-147`.
///
/// Orders two hash records by their `hash` value alone. The stack passes element slots, so both
/// arguments are pointers to the `BY_DIR_HASH *` to compare.
///
/// # Safety
///
/// `a`/`b` must each be a live slot holding a live `BY_DIR_HASH`.
unsafe extern "C" fn by_dir_hash_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's comparator contract supplies two element slots.
    unsafe {
        let a = a.cast::<*const ByDirHash>();
        let b = b.cast::<*const ByDirHash>();
        if (**a).hash > (**b).hash {
            1
        } else if (**a).hash < (**b).hash {
            -1
        } else {
            0
        }
    }
}

/// The `OPENSSL_sk_pop_free` adapter for the `BY_DIR_ENTRY` record.
///
/// Takes the raw element the stack hands back and reclaims it as an [`OwnedCtx`], whose `Drop`
/// releases its directory path, its hash stack and the block itself at the authority's own
/// `by_dir_entry_free` sites.
///
/// # Safety
///
/// `elem` must be NULL or a `BY_DIR_ENTRY` this module's `CRYPTO_malloc` allocated.
unsafe extern "C" fn by_dir_entry_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a `BY_DIR_ENTRY` this module allocated; `from_raw` reclaims it and
    // `Drop` runs the authority's own free body.
    drop(unsafe {
        OwnedCtx::<ByDirEntry>::from_raw_at(elem.cast(), FILE.as_ptr(), LINE_FREE_ENTRY)
    });
}

// ---------------------------------------------------------------------------------------------
// The lifecycle — `crypto/x509/by_dir.c:108-164`.
// ---------------------------------------------------------------------------------------------

/// `static int new_dir(X509_LOOKUP *lu)` — `crypto/x509/by_dir.c:108-132`.
///
/// Allocates the method's `BY_DIR`, its scratch buffer and its lock, and attaches it to `lu`. A
/// failed allocation answers 0.
///
/// # Safety
///
/// `lu` must be a live `X509_LOOKUP` whose method data is not yet set by this method.
unsafe extern "C" fn new_dir(lu: *mut X509Lookup) -> c_int {
    // `RawDir` owns the fresh block; until the last member is set its release is the block alone,
    // exactly the authority's `err:` label (`by_dir.c:130`).
    let Some(a) = RawDir::new() else {
        return 0;
    };
    // SAFETY: `a` is this call's own fresh block; the writes below initialise its members, and each
    // early return drops `a` (the block-only release) because it is never installed.
    unsafe {
        (*a.as_ptr()).buffer = BUF_MEM_new();
        if (*a.as_ptr()).buffer.is_null() {
            // SAFETY: a compile-time-constant site.
            raise_site(&BY_DIR_116);
            return 0;
        }
        (*a.as_ptr()).dirs = ptr::null_mut();
        (*a.as_ptr()).lock = CRYPTO_THREAD_lock_new();
        if (*a.as_ptr()).lock.is_null() {
            BUF_MEM_free((*a.as_ptr()).buffer);
            // SAFETY: a compile-time-constant site.
            raise_site(&BY_DIR_123);
            return 0;
        }
        (*lu).method_data = a.finish().cast::<c_void>();
    }
    1
}

/// `static void free_dir(X509_LOOKUP *lu)` — `crypto/x509/by_dir.c:156-164`.
///
/// Releases the method's directory list, scratch buffer and lock, then the `BY_DIR` itself.
///
/// # Safety
///
/// `lu` must be a live `X509_LOOKUP` whose method data is this method's own `BY_DIR`.
unsafe extern "C" fn free_dir(lu: *mut X509Lookup) {
    // SAFETY: `lu` is live with this method's own record per the contract.
    let a = unsafe { (*lu).method_data }.cast::<ByDir>();
    // SAFETY: `a` is this method's own record; reclaiming it runs `free_dir`'s destructor (the
    // directory list, the scratch buffer and the lock) and releases the block at the authority's own
    // `by_dir.c:163` site.
    drop(unsafe { OwnedCtx::<ByDir>::from_raw_at(a, FILE.as_ptr(), LINE_FREE_DIR) });
}

// ---------------------------------------------------------------------------------------------
// The directory-list parser — `crypto/x509/by_dir.c:166-220`.
// ---------------------------------------------------------------------------------------------

/// `static int add_cert_dir(BY_DIR *ctx, const char *dir, int type)` —
/// `crypto/x509/by_dir.c:166-220`.
///
/// Splits `dir` on `LIST_SEPARATOR_CHAR` and appends each non-empty element not already in
/// `ctx->dirs` as a fresh `BY_DIR_ENTRY` of file `type`. A NULL or empty `dir` answers 0 with
/// `X509_R_INVALID_DIRECTORY`; an allocated-but-unpushable entry is released.
///
/// # Safety
///
/// `ctx` must be a live `BY_DIR`; `dir` NULL or NUL-terminated.
unsafe fn add_cert_dir(ctx: *mut ByDir, dir: *const c_char, type_: c_int) -> c_int {
    // SAFETY: `dir` is NULL or NUL-terminated per the contract.
    if dir.is_null() || unsafe { *dir } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&BY_DIR_173) };
        return 0;
    }

    let mut s = dir;
    let mut p = dir;
    loop {
        'iter: {
            // SAFETY: `p` walks the NUL-terminated `dir`, so every byte read is inside it.
            if unsafe { *p } == LIST_SEPARATOR_CHAR || unsafe { *p } == 0 {
                let ss = s;
                // SAFETY: `p` is at a byte of `dir`, so `p + 1` is inside or one past it.
                s = unsafe { p.add(1) };
                // SAFETY: `ss` and `p` both point into `dir`, with `ss <= p`.
                let len = unsafe { p.offset_from(ss) } as usize;
                if len == 0 {
                    break 'iter;
                }
                let mut j: c_int = 0;
                // SAFETY: `ctx` is live; a NULL stack answers -1, so the test is false.
                while j < unsafe { OPENSSL_sk_num((*ctx).dirs) } {
                    // SAFETY: `j` is in range.
                    let ent = unsafe { OPENSSL_sk_value((*ctx).dirs, j) }.cast::<ByDirEntry>();
                    // SAFETY: `ent` is a live entry whose `dir` is NUL-terminated, and `ss` is
                    // the start of a `len`-byte path, so both reads stay inside their strings.
                    if unsafe {
                        sys::strlen((*ent).dir) == len && sys::strncmp((*ent).dir, ss, len) == 0
                    } {
                        break;
                    }
                    j += 1;
                }
                // SAFETY: `ctx` is live; a NULL stack answers -1, so the test is false.
                if j < unsafe { OPENSSL_sk_num((*ctx).dirs) } {
                    break 'iter;
                }
                // SAFETY: `ctx` is this method's own live record.
                if unsafe { (*ctx).dirs }.is_null() {
                    let dirs = OPENSSL_sk_new_null();
                    // SAFETY: `ctx` is live and `dirs` is the new stack.
                    unsafe { (*ctx).dirs = dirs };
                    if dirs.is_null() {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&BY_DIR_198) };
                        return 0;
                    }
                }
                // The block is a `RawCtx` (`RawCtx::malloc_at` is the authority's own
                // `OPENSSL_malloc(sizeof(*ent))`): every field is written before `assume_init`
                // makes it a valid record whose `Drop` releases the path, the hash stack and the
                // block itself at the authority's own sites. Only a successful push gives the
                // block up to `ctx->dirs`.
                // SAFETY: the allocator answers NULL or a fresh block; every field is written
                // before the validated transition below.
                let Some(raw) = RawCtx::<ByDirEntry>::malloc_at(
                    FILE.as_ptr(),
                    LINE_MALLOC_ENTRY,
                    FILE.as_ptr(),
                    LINE_FREE_ENTRY,
                ) else {
                    return 0;
                };
                let p = raw.as_ptr();
                // SAFETY: `p` is this call's own fresh record.
                unsafe {
                    (*p).dir_type = type_;
                    (*p).hashes = OPENSSL_sk_new(Some(by_dir_hash_cmp));
                    // SAFETY: `ss` is the start of a `len`-byte path inside `dir`.
                    (*p).dir = CRYPTO_strndup(ss, len, FILE.as_ptr(), LINE_STRNDUP_ENTRY_DIR);
                }
                // SAFETY: every field of the record has been written above.
                let ent = unsafe { raw.assume_init() };
                // SAFETY: `ent` is this call's own fresh record.
                unsafe {
                    if (*ent.as_ptr()).dir.is_null() || (*ent.as_ptr()).hashes.is_null() {
                        return 0;
                    }
                    // SAFETY: `ctx`'s stack is live; the record is the element to push.
                    if OPENSSL_sk_push((*ctx).dirs, ent.as_ptr().cast::<c_void>()) == 0 {
                        drop(ent);
                        raise_site(&BY_DIR_214);
                        return 0;
                    }
                }
                // The push succeeded, so `ctx->dirs` owns the record now.
                let _ = ent.into_raw();
            }
        }
        // The `while (*p++ != '\0')` condition of the authority's `do`/`while`.
        // SAFETY: `p` is at a byte of `dir` after the body.
        let last = unsafe { *p } == 0;
        // SAFETY: `p` advances within (or one past) `dir`.
        p = unsafe { p.add(1) };
        if last {
            break;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The subject lookup — `crypto/x509/by_dir.c:222-448`.
// ---------------------------------------------------------------------------------------------

/// `static int get_cert_by_subject_ex(X509_LOOKUP *xl, X509_LOOKUP_TYPE type, const X509_NAME
/// *name, X509_OBJECT *ret, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/by_dir.c:222-442`.
///
/// Searches every added directory for a certificate or CRL whose name hashes to the same value,
/// loading the matching file with [`X509_load_cert_file_ex`]/[`X509_load_crl_file`] and then
/// pulling the cached object out of `xl`'s store. Answers 1 (with `ret` filled) when an object was
/// found, 0 otherwise. A NULL `name` or an unknown `type` answers 0.
///
/// # Safety
///
/// `xl` must be a live `X509_LOOKUP` whose method data is this method's own `BY_DIR` and whose
/// store is live; `name` NULL or live; `ret` NULL or writable; `libctx` NULL or live; `propq` NULL
/// or NUL-terminated.
unsafe extern "C" fn get_cert_by_subject_ex(
    xl: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut ok: c_int = 0;
    let mut j: c_int;
    let h: c_ulong;
    let mut b: *mut BufMem = ptr::null_mut();
    let mut tmp: *mut X509Object;
    let mut postfix: *const c_char = c"".as_ptr();

    // The authority's stack-local union holds an `X509` or an `X509_CRL`; only the name the
    // comparator reads is ever written (see `x509_object_cmp`), so the two stay separate here.
    let mut x509_s = MaybeUninit::<X509>::uninit();
    let mut crl_s = MaybeUninit::<X509Crl>::uninit();
    let mut stmp = MaybeUninit::<X509Object>::uninit();

    if name.is_null() {
        return 0;
    }

    'finish: {
        // SAFETY: `stmp`, `x509_s` and `crl_s` are this frame's locals; the fields are written
        // before the key is used.
        unsafe {
            (*stmp.as_mut_ptr()).type_ = type_;
            if type_ == X509_LU_X509 {
                (*x509_s.as_mut_ptr()).cert_info.subject = name.cast_mut();
                (*stmp.as_mut_ptr()).data.x509 = x509_s.as_mut_ptr();
            } else if type_ == X509_LU_CRL {
                (*crl_s.as_mut_ptr()).crl.issuer = name.cast_mut();
                (*stmp.as_mut_ptr()).data.crl = crl_s.as_mut_ptr();
                postfix = c"r".as_ptr();
            } else {
                raise_site(&BY_DIR_250);
                break 'finish;
            }
        }

        b = BUF_MEM_new();
        if b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&BY_DIR_255) };
            break 'finish;
        }

        // SAFETY: `xl` is live with this method's own `BY_DIR` per the contract.
        let ctx = unsafe { (*xl).method_data }.cast::<ByDir>();
        let mut hash_ok: c_int = 0;
        // SAFETY: `name` is live; `libctx`/`propq` are the caller's; `hash_ok` is writable.
        h = unsafe { X509_NAME_hash_ex(name, libctx, propq, &mut hash_ok) };
        if hash_ok == 0 {
            break 'finish;
        }
        // SAFETY: `ctx` is live; a NULL `dirs` answers -1, so the body is skipped.
        for i in 0..unsafe { OPENSSL_sk_num((*ctx).dirs) } {
            // SAFETY: `i` is in range.
            let ent = unsafe { OPENSSL_sk_value((*ctx).dirs, i) }.cast::<ByDirEntry>();
            // SAFETY: `ent->dir` is NUL-terminated.
            j = unsafe { sys::strlen((*ent).dir) } as c_int + 1 + 8 + 6 + 1 + 1;
            // SAFETY: `b` is this call's own live buffer.
            if unsafe { BUF_MEM_grow(b, j as usize) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BY_DIR_271) };
                break 'finish;
            }
            let mut hent: *mut ByDirHash;
            let mut k: c_int;
            // SAFETY: `ent->hashes` is this method's own stack or NULL.
            if type_ == X509_LU_CRL && !unsafe { (*ent).hashes }.is_null() {
                let htmp = ByDirHash { hash: h, suffix: 0 };
                // SAFETY: `ctx->lock` is this method's own lock.
                if unsafe { CRYPTO_THREAD_read_lock((*ctx).lock) } == 0 {
                    break 'finish;
                }
                // SAFETY: `ent->hashes` is live; `htmp` is a live key.
                let idx = unsafe { OPENSSL_sk_find((*ent).hashes, (&raw const htmp).cast()) };
                if idx >= 0 {
                    // SAFETY: `idx` is in range.
                    hent = unsafe { OPENSSL_sk_value((*ent).hashes, idx) }.cast::<ByDirHash>();
                    // SAFETY: `hent` is a live hash record.
                    k = unsafe { (*hent).suffix };
                } else {
                    hent = ptr::null_mut();
                    k = 0;
                }
                // SAFETY: `ctx->lock` was read-locked just above.
                unsafe { CRYPTO_THREAD_unlock((*ctx).lock) };
            } else {
                k = 0;
                hent = ptr::null_mut();
            }
            loop {
                // The non-VMS arm uses a literal `/` separator.
                let sep = c_int::from(b'/' as c_char);
                // SAFETY: `b` is a live buffer grown to hold the formatted path; `ent->dir` and
                // `postfix` are NUL-terminated, and the variadic arguments match the format.
                unsafe {
                    BIO_snprintf(
                        (*b).data,
                        (*b).max,
                        c"%s%c%08lx.%s%d".as_ptr(),
                        (*ent).dir,
                        sep,
                        h,
                        postfix,
                        k,
                    );
                }
                // SAFETY: `b->data` is a NUL-terminated path.
                if unsafe { openssl_rs_lstat_exists((*b).data) } < 0 {
                    break; // the file does not exist, not even as a symlink
                }
                // SAFETY: `b->data` is a NUL-terminated path.
                if unsafe { openssl_rs_stat_exists((*b).data) } < 0 {
                    k += 1;
                    continue; // the symlink is broken: following it went wrong
                }
                ERR_set_mark();
                // SAFETY: `xl` is a live lookup with a live store; `b->data` is NUL-terminated;
                // `ent->dir_type` is the directory's own file type; `libctx`/`propq` are the
                // caller's. The `#ifndef OPENSSL_NO_POSIX_IO` arm below discards the answer.
                unsafe {
                    if type_ == X509_LU_X509 {
                        X509_load_cert_file_ex(xl, (*b).data, (*ent).dir_type, libctx, propq);
                    } else if type_ == X509_LU_CRL {
                        X509_load_crl_file(xl, (*b).data, (*ent).dir_type);
                    }
                }
                ERR_pop_to_mark();
                // `#ifndef OPENSSL_NO_POSIX_IO`: `res = 1`, so a found file whose load failed is
                // skipped gracefully rather than stopping the scan.
                k += 1;
            }

            // We have added it to the cache, so now pull it out again.
            if k > 0 {
                // SAFETY: `xl->store_ctx` is live with a live lock.
                if unsafe { X509_STORE_lock((*xl).store_ctx) } == 0 {
                    break 'finish;
                }
                // SAFETY: `xl->store_ctx->objs` is live; `stmp` is the key, holding only the name.
                j = unsafe { OPENSSL_sk_find((*(*xl).store_ctx).objs, stmp.as_ptr().cast()) };
                // SAFETY: `j` is -1 or in range, and `_value` answers NULL for -1.
                tmp = unsafe { OPENSSL_sk_value((*(*xl).store_ctx).objs, j) }.cast::<X509Object>();
                // SAFETY: the store lock was just taken.
                unsafe { X509_STORE_unlock((*xl).store_ctx) };
            } else {
                tmp = ptr::null_mut();
            }

            // If a CRL, update the last file suffix added for this hash. No record is added when
            // `k` is 0, so the simple no-CRL case needs no write lock.
            if type_ == X509_LU_CRL && k > 0 {
                // SAFETY: `ctx->lock` is this method's own lock.
                if unsafe { CRYPTO_THREAD_write_lock((*ctx).lock) } == 0 {
                    break 'finish;
                }
                if hent.is_null() {
                    let htmp = ByDirHash { hash: h, suffix: 0 };
                    // SAFETY: `ent->hashes` is live; `htmp` is a live key.
                    let idx = unsafe { OPENSSL_sk_find((*ent).hashes, (&raw const htmp).cast()) };
                    // SAFETY: `idx` is -1 or in range; `_value` answers NULL for -1.
                    hent = unsafe { OPENSSL_sk_value((*ent).hashes, idx) }.cast::<ByDirHash>();
                }
                if hent.is_null() {
                    // The block is a `RawCtx` (`RawCtx::malloc_at` is the authority's own
                    // `OPENSSL_malloc(sizeof(*hent))`): both fields are written before
                    // `assume_init`. A failed push re-points its release at the authority's
                    // `:399` site, and only a successful push gives it up to `ent->hashes`.
                    // SAFETY: the allocator answers NULL or a fresh block; both fields are
                    // written before the validated transition below.
                    let Some(raw) = RawCtx::<ByDirHash>::malloc_at(
                        FILE.as_ptr(),
                        LINE_MALLOC_HASH,
                        FILE.as_ptr(),
                        LINE_FREE_HASH,
                    ) else {
                        // SAFETY: `ctx->lock` is write-locked.
                        unsafe { CRYPTO_THREAD_unlock((*ctx).lock) };
                        ok = 0;
                        break 'finish;
                    };
                    let p = raw.as_ptr();
                    // SAFETY: `p` is this call's own fresh record.
                    unsafe {
                        (*p).hash = h;
                        (*p).suffix = k;
                    }
                    // SAFETY: both fields of the record have been written above.
                    let mut rec = unsafe { raw.assume_init() };
                    // SAFETY: `rec` is this call's own fresh record; `ent->hashes` is live.
                    unsafe {
                        // SAFETY: `ent->hashes` is live; the record is the element to push.
                        if OPENSSL_sk_push((*ent).hashes, rec.as_ptr().cast::<c_void>()) == 0 {
                            CRYPTO_THREAD_unlock((*ctx).lock);
                            rec.set_release_line(LINE_FREE_HASH_PUSH);
                            drop(rec);
                            raise_site(&BY_DIR_400);
                            ok = 0;
                            break 'finish;
                        }
                        // Ensure the stack is sorted so a later find does not mutate it and so
                        // does not need a write lock.
                        OPENSSL_sk_sort((*ent).hashes);
                    }
                    // The push succeeded, so `ent->hashes` owns the record now.
                    let _ = rec.into_raw();
                } else {
                    // SAFETY: `hent` is a live hash record.
                    if unsafe { (*hent).suffix } < k {
                        // SAFETY: as above.
                        unsafe { (*hent).suffix = k };
                    }
                }
                // SAFETY: `ctx->lock` is write-locked.
                unsafe { CRYPTO_THREAD_unlock((*ctx).lock) };
            }

            if !tmp.is_null() {
                ok = 1;
                // SAFETY: `ret` is the caller's writable slot; `tmp` is a live object.
                unsafe {
                    (*ret).type_ = (*tmp).type_;
                    (*ret).data = (*tmp).data;
                }
                ERR_clear_error();
                break 'finish;
            }
        }
    }

    // finish: if we changed anything, resort the objects for faster lookup.
    // SAFETY: `xl->store_ctx` is live with a live lock.
    if unsafe { X509_STORE_lock((*xl).store_ctx) } != 0 {
        // SAFETY: the store lock is held.
        let objs = unsafe { (*(*xl).store_ctx).objs };
        // SAFETY: `objs` is the store's own live object stack.
        if unsafe { OPENSSL_sk_is_sorted(objs) } == 0 {
            // SAFETY: `objs` is live.
            unsafe { OPENSSL_sk_sort(objs) };
        }
        // SAFETY: the store lock is held.
        unsafe { X509_STORE_unlock((*xl).store_ctx) };
    }
    // SAFETY: `b` is NULL or this call's own buffer.
    unsafe { BUF_MEM_free(b) };
    ok
}

/// `static int get_cert_by_subject(X509_LOOKUP *xl, X509_LOOKUP_TYPE type, const X509_NAME *name,
/// X509_OBJECT *ret)` — `crypto/x509/by_dir.c:444-448`.
///
/// [`get_cert_by_subject_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`get_cert_by_subject_ex`], without `libctx`/`propq`.
unsafe extern "C" fn get_cert_by_subject(
    xl: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: the contract is `get_cert_by_subject_ex`'s with NULL libctx/propq.
    unsafe { get_cert_by_subject_ex(xl, type_, name, ret, ptr::null_mut(), ptr::null()) }
}

// ---------------------------------------------------------------------------------------------
// The control door — `crypto/x509/by_dir.c:82-106`.
// ---------------------------------------------------------------------------------------------

/// `static int dir_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **retp)` —
/// `crypto/x509/by_dir.c:82-106`.
///
/// The method's `ctrl` door. `X509_L_ADD_DIR` appends `argp` to the directory list, or the
/// environment's directory (or the compiled-in default) when `argl` is `X509_FILETYPE_DEFAULT`,
/// with `X509_FILETYPE_PEM` files. Any other command answers 0. A failed default add raises
/// `X509_R_LOADING_CERT_DIR`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP` whose method data is this method's own `BY_DIR`; `argp` NULL
/// or NUL-terminated.
unsafe extern "C" fn dir_ctrl(
    ctx: *mut X509Lookup,
    cmd: c_int,
    argp: *const c_char,
    argl: c_long,
    _retp: *mut *mut c_char,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `ctx` is live with this method's own `BY_DIR` per the contract.
    let ld = unsafe { (*ctx).method_data }.cast::<ByDir>();
    if cmd == X509_L_ADD_DIR {
        if argl == c_long::from(X509_FILETYPE_DEFAULT) {
            // SAFETY: the env-var name is a fixed `'static` C string, so reading the
            // environment is defined.
            let dir = unsafe { ossl_safe_getenv(X509_get_default_cert_dir_env()) };
            if !dir.is_null() {
                // SAFETY: `ld` is this method's own record; `dir` is NUL-terminated.
                ret = unsafe { add_cert_dir(ld, dir, X509_FILETYPE_PEM) };
            } else {
                // SAFETY: `ld` is this method's record; the default answers a `'static` string.
                ret = unsafe { add_cert_dir(ld, X509_get_default_cert_dir(), X509_FILETYPE_PEM) };
            }
            if ret == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&BY_DIR_99) };
            }
        } else {
            // SAFETY: `ld` is this method's record; `argp` is NUL-terminated per the contract.
            // The cast is the authority's `(int)argl`.
            ret = unsafe { add_cert_dir(ld, argp, argl as c_int) };
        }
    }
    ret
}

// ---------------------------------------------------------------------------------------------
// The method table and its constructor — `crypto/x509/by_dir.c:62-80`.
// ---------------------------------------------------------------------------------------------

/// A `Sync` newtype over the method row, so it can be a `static`.
///
/// A `static` of raw pointers is not `Sync` (the same reason [`crate::x509::by_store`]'s method row
/// claims it), so the table is wrapped.
#[repr(transparent)]
struct DirLookupMethod(X509LookupMethod);

// SAFETY: the row is fully initialised at compile time and never written. Its pointer fields borrow
// the crate's own `static` string, function addresses and NULL; the authority's `x509_dir_lookup`
// is exactly this -- an immutable table of immutable fields.
unsafe impl Sync for DirLookupMethod {}

/// `static X509_LOOKUP_METHOD x509_dir_lookup` — `crypto/x509/by_dir.c:62-75`.
///
/// The method row [`X509_LOOKUP_hash_dir`] hands out. Its `init`, `shutdown`,
/// `get_by_issuer_serial`, `get_by_fingerprint`, `get_by_alias` and `ctrl_ex` slots are NULL;
/// `new_item`, `free`, `ctrl`, `get_by_subject` and `get_by_subject_ex` are this unit's callbacks.
static X509_DIR_LOOKUP: DirLookupMethod = DirLookupMethod(X509LookupMethod {
    name: c"Load certs from files in a directory".as_ptr().cast_mut(),
    new_item: Some(new_dir),
    free: Some(free_dir),
    init: None,
    shutdown: None,
    ctrl: Some(dir_ctrl),
    get_by_subject: Some(get_cert_by_subject),
    get_by_issuer_serial: None,
    get_by_fingerprint: None,
    get_by_alias: None,
    get_by_subject_ex: Some(get_cert_by_subject_ex),
    ctrl_ex: None,
});

/// `X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void)` — `crypto/x509/by_dir.c:77-80`.
///
/// The hashed-directory lookup method. The answer is a `'static` row the caller must not free.
///
/// # Safety
///
/// The answer is a module-owned `static`; no argument is read.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_hash_dir() -> *mut X509LookupMethod {
    (&raw const X509_DIR_LOOKUP.0).cast_mut()
}
