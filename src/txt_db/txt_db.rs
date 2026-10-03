//! Phase 13.5 — `crypto/txt_db/txt_db.c`: the `TXT_DB` two-dimensional text database.
//!
//! `include/openssl/txt_db.h` declares six exports and one public structure, and this
//! module is the whole of it: [`TXT_DB_read`] (`crypto/txt_db/txt_db.c:20-125`) parses a
//! tab-separated database from a `BIO` through a `BUF_MEM`, [`TXT_DB_write`] (`:187-232`)
//! is its inverse, [`TXT_DB_insert`] (`:234-277`) adds a row, [`TXT_DB_create_index`]
//! (`:147-185`) builds an `LHASH_OF(OPENSSL_STRING)` over one field, [`TXT_DB_get_by_index`]
//! (`:127-145`) looks a row up through one, and [`TXT_DB_free`] (`:279-314`) releases the
//! whole object.
//!
//! ## The structure, and the two collections it holds
//!
//! `TXT_DB` (`include/openssl/txt_db.h:39-48`) is `#[repr(C)]` here with the header's own
//! field order, because the header is public: a consumer that includes it reads
//! `num_fields`, `data`, `index`, `qual`, `error`, `arg1`, `arg2` and `arg_row` at the
//! authority's offsets. `data` is the `STACK_OF(OPENSSL_PSTRING)` the rows live on — a
//! plain `OPENSSL_STACK` of `char **` rows (`src/runtime/stack.rs`), because
//! `DEFINE_SPECIAL_STACK_OF(OPENSSL_PSTRING, OPENSSL_STRING)` makes every
//! `sk_OPENSSL_PSTRING_*` call a macro over `OPENSSL_sk_*` — and `index` is an array of
//! `num_fields` `OPENSSL_LHASH *`, one per indexed field, each built over the *row*
//! pointers with the caller's hash and comparison functions (so a lookup's key is a row,
//! and the comparator reads whichever field the index was made on).
//!
//! A row is **one** allocation: `(num_fields + 1)` `char *` slots followed by the
//! NUL-terminated fields packed contiguously, with `row[num_fields]` a sentinel pointing
//! one past the last field. [`TXT_DB_free`] uses that sentinel to decide whether a field
//! pointer belongs to the row's own block (do not free) or was allocated elsewhere (free),
//! which is why a row this module's [`TXT_DB_read`] built and one a caller built are both
//! releasable by the same code.
//!
//! ## `SRP_VBASE_init`'s blocker is now removable
//!
//! Phase 12.8 withheld `SRP_VBASE_init` (`crypto/srp/srp_vfy.c:394-510`) by name because
//! its body reads a verifier file through `TXT_DB_read` (`:423`) and releases it through
//! `TXT_DB_free` (`:504`), and no crate module defined either. This subphase lands exactly
//! those two names, so the dependency that held the row is gone and 13.8 can transcribe the
//! body. **The row is not landed here** — `docs/PHASE-13-SUBPHASES.md` §2 assigns it to
//! 13.8 — and `src/srp/srp_vfy.rs`'s `#[allow(dead_code)]` markers stay until then.
//!
//! ## Divergences, recorded rather than hidden
//!
//! * **A successful `TXT_DB_read` zeroes `error`/`arg1`/`arg2`/`arg_row`.** The authority
//!   allocates the object with `OPENSSL_malloc` and initialises only `num_fields`, `data`,
//!   `index` and `qual` on the success path, so those four fields hold indeterminate bytes
//!   there and reading them is undefined behaviour. This crate writes defined zeroes; no
//!   well-defined caller can observe the difference, and the court does not read them.
//! * **A negative `idx`/`field` is refused rather than indexed.** The authority's checks
//!   are only `idx >= db->num_fields` and `field >= db->num_fields`, so a negative index
//!   reaches `db->index[idx]` and reads or writes out of bounds. This crate answers
//!   `DB_ERROR_INDEX_OUT_OF_RANGE` for the negative arm, the safer answer
//!   `docs/SECURITY_DIVERGENCE_POLICY.md` permits; the court does not drive it, because the
//!   authority's behaviour there is not well defined.
//! * **`TXT_DB_read`'s wrong-field-count path leaks the rows already pushed.** The
//!   authority's `err:` label calls `sk_OPENSSL_PSTRING_free` (the array — **not**
//!   `_pop_free`) on `data`, so every row parsed before the malformed line is abandoned.
//!   This transcription reproduces the leak rather than silently fixing it; it is
//!   observable through no return value or transcript.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::mem::size_of;
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::bio::iolib::{BIO_gets, BIO_write};
use crate::runtime::bio::sys::strlen;
use crate::runtime::bio::Bio;
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_grow_clean, BUF_MEM_new, BufMem};
use crate::runtime::lhash::{
    OPENSSL_LH_delete, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new, OPENSSL_LH_retrieve,
    OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_malloc_array};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};

/// The authority's `OPENSSL_FILE` for this unit, so an allocation a caller's
/// `CRYPTO_set_mem_functions` sees carries the authority's coordinate.
const FILE: *const c_char = c"crypto/txt_db/txt_db.c".as_ptr();

/// `BUFSIZE` — `crypto/txt_db/txt_db.c:18`.
const BUFSIZE: c_int = 512;

/// `OPENSSL_LINE` of `TXT_DB_read`'s `OPENSSL_malloc(sizeof(*ret))` (`:36`).
const MALLOC_DB: c_int = 36;
/// `OPENSSL_LINE` of `TXT_DB_read`'s index-array allocation (`:43`).
const MALLOC_INDEX: c_int = 43;
/// `OPENSSL_LINE` of `TXT_DB_read`'s qualifier-array allocation (`:45`).
const MALLOC_QUAL: c_int = 45;
/// `OPENSSL_LINE` of `TXT_DB_read`'s row-block allocation (`:73`).
const MALLOC_ROW: c_int = 73;
/// `OPENSSL_LINE` of the wrong-field-count row free (`:104`).
const READ_FREE_ROW_BAD: c_int = 104;
/// `OPENSSL_LINE` of the failed-push row free (`:110`).
const READ_FREE_ROW_PUSH: c_int = 110;
/// `OPENSSL_LINE` of `TXT_DB_read`'s error-path index free (`:120`).
const READ_FREE_INDEX: c_int = 120;
/// `OPENSSL_LINE` of `TXT_DB_read`'s error-path qualifier free (`:121`).
const READ_FREE_QUAL: c_int = 121;
/// `OPENSSL_LINE` of `TXT_DB_read`'s error-path object free (`:122`).
const READ_FREE_DB: c_int = 122;
/// `OPENSSL_LINE` of `TXT_DB_free`'s index-array free (`:289`).
const FREE_INDEX: c_int = 289;
/// `OPENSSL_LINE` of `TXT_DB_free`'s qualifier-array free (`:291`).
const FREE_QUAL: c_int = 291;
/// `OPENSSL_LINE` of `TXT_DB_free`'s "new row" field free (`:302`).
const FREE_FIELD_NEW: c_int = 302;
/// `OPENSSL_LINE` of `TXT_DB_free`'s "outside the block" field free (`:306`).
const FREE_FIELD_EXT: c_int = 306;
/// `OPENSSL_LINE` of `TXT_DB_free`'s row-block free (`:309`).
const FREE_ROW: c_int = 309;
/// `OPENSSL_LINE` of `TXT_DB_free`'s object free (`:313`).
const FREE_DB: c_int = 313;

/// `DB_ERROR_OK` — `include/openssl/txt_db.h:24`.
const DB_ERROR_OK: c_long = 0;
/// `DB_ERROR_MALLOC` — `include/openssl/txt_db.h:25`.
const DB_ERROR_MALLOC: c_long = 1;
/// `DB_ERROR_INDEX_CLASH` — `include/openssl/txt_db.h:26`.
const DB_ERROR_INDEX_CLASH: c_long = 2;
/// `DB_ERROR_INDEX_OUT_OF_RANGE` — `include/openssl/txt_db.h:27`.
const DB_ERROR_INDEX_OUT_OF_RANGE: c_long = 3;
/// `DB_ERROR_NO_INDEX` — `include/openssl/txt_db.h:28`.
const DB_ERROR_NO_INDEX: c_long = 4;
/// `DB_ERROR_WRONG_NUM_FIELDS` — `include/openssl/txt_db.h:30`.
const DB_ERROR_WRONG_NUM_FIELDS: c_long = 6;

/// `OPENSSL_STRING *` — one row: `num_fields` field pointers plus the sentinel slot.
type OpenSslPString = *mut *mut c_char;
/// `int (*)(OPENSSL_STRING *)` — a per-field index qualifier (`txt_db.h:52`).
type QualFn = unsafe extern "C" fn(*mut *mut c_char) -> c_int;
/// `unsigned long (*)(const void *)` — `OPENSSL_LH_HASHFUNC` (`lhash.h`).
type HashFn = unsafe extern "C" fn(*const c_void) -> c_ulong;
/// `int (*)(const void *, const void *)` — `OPENSSL_LH_COMPFUNC` (`lhash.h`).
type CompFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// `TXT_DB` — `include/openssl/txt_db.h:39-48`.
///
/// The header defines the structure in full, so the layout is ABI and is reproduced field
/// for field rather than hidden behind an opaque handle.
#[repr(C)]
pub struct TxtDb {
    /// `int num_fields`.
    pub num_fields: c_int,
    /// `STACK_OF(OPENSSL_PSTRING) *data`.
    pub data: *mut OpenSslStack,
    /// `LHASH_OF(OPENSSL_STRING) **index` — one lhash per indexed field, or NULL.
    pub index: *mut *mut OpenSslLhash,
    /// `int (**qual)(OPENSSL_STRING *)` — the qualifier paired with each index, or NULL.
    pub qual: *mut Option<QualFn>,
    /// `long error` — the last `DB_ERROR_*` this object recorded.
    pub error: c_long,
    /// `long arg1` — the field index a clash reported.
    pub arg1: c_long,
    /// `long arg2` — the row index a create-index clash reported.
    pub arg2: c_long,
    /// `OPENSSL_STRING *arg_row` — the row an insert clash collided with.
    pub arg_row: OpenSslPString,
}

/// The authority's `err:` label of `TXT_DB_read` — `crypto/txt_db/txt_db.c:116-124`.
///
/// # Safety
///
/// `buf` must be NULL or a `BUF_MEM` from `BUF_MEM_new`; `ret` must be NULL or a `TXT_DB`
/// whose `data`/`index`/`qual` fields are exactly what `TXT_DB_read` set them to (`data` a
/// live stack or NULL, `index`/`qual` arrays or NULL). Ownership of both transfers here.
unsafe fn read_err(buf: *mut BufMem, ret: *mut TxtDb) -> *mut TxtDb {
    // SAFETY: `buf` is NULL or this call's own `BUF_MEM`.
    unsafe { BUF_MEM_free(buf) };
    if !ret.is_null() {
        // SAFETY: `ret` is live and its three fields are as `TXT_DB_read` set them; the
        // authority's `sk_OPENSSL_PSTRING_free` is `OPENSSL_sk_free` (the array only).
        unsafe {
            OPENSSL_sk_free((*ret).data);
            CRYPTO_free((*ret).index.cast(), FILE, READ_FREE_INDEX);
            CRYPTO_free((*ret).qual.cast(), FILE, READ_FREE_QUAL);
            CRYPTO_free(ret.cast(), FILE, READ_FREE_DB);
        }
    }
    ptr::null_mut()
}

/// `TXT_DB *TXT_DB_read(BIO *in, int num)` — `crypto/txt_db/txt_db.c:20-125`.
///
/// Reads `num`-field records until EOF, one line at a time through a `BUF_MEM`. A line
/// whose first character is `#` is skipped; a line is a record only when it ends in a
/// newline (a short read is continued); fields are separated by unescaped tabs and a
/// backslash before a tab makes it literal. A record that does not yield exactly `num`
/// fields fails the whole read, which answers NULL (and, in the authority, leaks the rows
/// already pushed — see the module header).
///
/// # Safety
///
/// `in_` must be NULL or a live `BIO` with a `gets` method. The caller owns the returned
/// object and must release it with [`TXT_DB_free`]; on failure NULL is returned.
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_read(in_: *mut Bio, num: c_int) -> *mut TxtDb {
    guard_ffi(ptr::null_mut(), || 'err: {
        // `BUF_MEM_new` is the safe constructor and answers NULL on failure.
        let buf = BUF_MEM_new();
        if buf.is_null() {
            break 'err ptr::null_mut();
        }
        let mut size: c_int = BUFSIZE;
        // SAFETY: `buf` is live.
        if unsafe { BUF_MEM_grow(buf, size as usize) } == 0 {
            // SAFETY: `buf` is live and the grow failed.
            break 'err unsafe { read_err(buf, ptr::null_mut()) };
        }
        // `CRYPTO_malloc` is the safe allocator and answers NULL on failure.
        let ret = CRYPTO_malloc(size_of::<TxtDb>(), FILE, MALLOC_DB).cast::<TxtDb>();
        if ret.is_null() {
            // SAFETY: `buf` is live and there is no `ret` yet.
            break 'err unsafe { read_err(buf, ret) };
        }
        // SAFETY: `ret` is a fresh allocation; `index`/`qual` are set to NULL before the
        // allocations that the error path frees, exactly as the authority does.
        unsafe {
            (*ret).num_fields = num;
            (*ret).index = ptr::null_mut();
            (*ret).qual = ptr::null_mut();
            // The authority leaves these four indeterminate on the success path; defined
            // zeroes cannot be observed by a well-defined caller (module header).
            (*ret).error = DB_ERROR_OK;
            (*ret).arg1 = 0;
            (*ret).arg2 = 0;
            (*ret).arg_row = ptr::null_mut();
        }
        // `OPENSSL_sk_new_null` is the safe constructor and answers NULL on failure.
        let data = OPENSSL_sk_new_null();
        // SAFETY: `ret` is live.
        unsafe { (*ret).data = data };
        if data.is_null() {
            // SAFETY: `buf` and `ret` are live; `ret`'s arrays are still NULL.
            break 'err unsafe { read_err(buf, ret) };
        }
        // An array of `num` lhash pointers; `CRYPTO_malloc_array` is safe.
        let index = CRYPTO_malloc_array(
            num as usize,
            size_of::<*mut OpenSslLhash>(),
            FILE,
            MALLOC_INDEX,
        )
        .cast::<*mut OpenSslLhash>();
        // SAFETY: `ret` is live.
        unsafe { (*ret).index = index };
        if index.is_null() {
            // SAFETY: `buf` and `ret` are live; `ret`'s qualifier array is still NULL.
            break 'err unsafe { read_err(buf, ret) };
        }
        // An array of `num` qualifier slots; `CRYPTO_malloc_array` is safe.
        let qual =
            CRYPTO_malloc_array(num as usize, size_of::<Option<QualFn>>(), FILE, MALLOC_QUAL)
                .cast::<Option<QualFn>>();
        // SAFETY: `ret` is live.
        unsafe { (*ret).qual = qual };
        if qual.is_null() {
            // SAFETY: `buf` and `ret` are live and fully initialised.
            break 'err unsafe { read_err(buf, ret) };
        }
        for i in 0..num {
            // SAFETY: both arrays have `num` slots and `i` is in `[0, num)`.
            unsafe {
                *(*ret).index.add(i as usize) = ptr::null_mut();
                *(*ret).qual.add(i as usize) = None;
            }
        }

        // `add = (num + 1) * sizeof(char *)`: the pointer array each row begins with.
        let add: c_int = (num + 1) * size_of::<*mut c_char>() as c_int;
        // SAFETY: `buf` holds `size` bytes.
        unsafe { *(*buf).data.add((size - 1) as usize) = 0 };
        let mut offset: c_int = 0;
        loop {
            if offset != 0 {
                size += BUFSIZE;
                // SAFETY: `buf` is live; the grow may fail and the authority fails then.
                if unsafe { BUF_MEM_grow_clean(buf, size as usize) } == 0 {
                    // SAFETY: `buf` and `ret` are live.
                    break 'err unsafe { read_err(buf, ret) };
                }
            }
            // SAFETY: `buf` holds `size` bytes and `offset < size`.
            unsafe { *(*buf).data.add(offset as usize) = 0 };
            // SAFETY: `in_` is the caller's BIO; the destination has `size - offset` bytes.
            unsafe { BIO_gets(in_, (*buf).data.add(offset as usize), size - offset) };
            // SAFETY: as above; a NUL first byte means end of input.
            if unsafe { *(*buf).data.add(offset as usize) } == 0 {
                break;
            }
            // SAFETY: `buf->data` is the line's start when `offset == 0`.
            if offset == 0 && unsafe { *(*buf).data } == b'#' as c_char {
                continue;
            }
            // SAFETY: the line is NUL-terminated.
            let i = unsafe { strlen((*buf).data.add(offset as usize)) } as c_int;
            offset += i;
            // SAFETY: `offset >= 1` after a non-empty read.
            if unsafe { *(*buf).data.add((offset - 1) as usize) } != b'\n' as c_char {
                continue;
            }
            // SAFETY: `offset >= 1`; the newline becomes the field terminator.
            unsafe { *(*buf).data.add((offset - 1) as usize) = 0 };
            // A fresh block of `add + offset` bytes: the pointer array and the
            // NUL-terminated line packed after it; `CRYPTO_malloc` is safe.
            let row = CRYPTO_malloc((add + offset) as usize, FILE, MALLOC_ROW).cast::<c_char>();
            if row.is_null() {
                // SAFETY: `buf` and `ret` are live.
                break 'err unsafe { read_err(buf, ret) };
            }
            offset = 0;

            // `pp` is the row's pointer array; the cursor `p` starts at the data region.
            let pp = row.cast::<*mut c_char>();
            // SAFETY: `row` has `add` bytes for the pointer array before that region.
            let mut p = unsafe { row.add(add as usize) };
            let mut n: c_int = 0;
            // SAFETY: `pp` has `num + 1` slots and `n == 0`.
            unsafe { *pp.add(n as usize) = p };
            n += 1;
            // SAFETY: `buf` is live.
            let mut f = unsafe { (*buf).data };
            let mut esc: c_int = 0;
            loop {
                // SAFETY: `f` walks the line's NUL-terminated bytes.
                if unsafe { *f } == 0 {
                    break;
                }
                // SAFETY: `f` is readable.
                if unsafe { *f } == b'\t' as c_char {
                    if esc != 0 {
                        // An escaped tab: drop the backslash just written and fall through
                        // so the tab itself is copied literally.
                        // SAFETY: `p` is inside `row`'s data region.
                        p = unsafe { p.sub(1) };
                    } else {
                        // SAFETY: `p` is inside `row`'s data region.
                        unsafe { *p = 0 };
                        // SAFETY: the cursor advances within the row's block.
                        unsafe {
                            p = p.add(1);
                            f = f.add(1);
                        }
                        if n >= num {
                            break;
                        }
                        // SAFETY: `pp` has `num + 1` slots and `n < num`.
                        unsafe { *pp.add(n as usize) = p };
                        n += 1;
                        continue;
                    }
                }
                // SAFETY: `f` is readable.
                esc = c_int::from(unsafe { *f } == b'\\' as c_char);
                // SAFETY: both pointers are valid for this byte.
                unsafe {
                    *p = *f;
                    p = p.add(1);
                    f = f.add(1);
                }
            }
            // SAFETY: the last field is terminated in place and the cursor advances.
            unsafe {
                *p = 0;
                p = p.add(1);
            }
            // SAFETY: `f` is readable.
            if n != num || unsafe { *f } != 0 {
                // SAFETY: `pp` is the row's own pointer array.
                unsafe { CRYPTO_free(pp.cast(), FILE, READ_FREE_ROW_BAD) };
                // SAFETY: `ret` is live.
                unsafe { (*ret).error = DB_ERROR_WRONG_NUM_FIELDS };
                // SAFETY: `buf` and `ret` are live.
                break 'err unsafe { read_err(buf, ret) };
            }
            // SAFETY: the sentinel slot `pp[num]`; `p` is one past the last field's NUL.
            unsafe { *pp.add(n as usize) = p };
            // SAFETY: `ret` is live and `pp` is the row handed over to the stack.
            if unsafe { OPENSSL_sk_push((*ret).data, pp.cast()) } == 0 {
                // SAFETY: `pp` is the row's own pointer array.
                unsafe { CRYPTO_free(pp.cast(), FILE, READ_FREE_ROW_PUSH) };
                // SAFETY: `buf` and `ret` are live.
                break 'err unsafe { read_err(buf, ret) };
            }
        }
        // SAFETY: `buf` is live.
        unsafe { BUF_MEM_free(buf) };
        ret
    })
}

/// `long TXT_DB_write(BIO *out, TXT_DB *db)` — `crypto/txt_db/txt_db.c:187-232`.
///
/// The inverse of [`TXT_DB_read`]: every field of every row is written, with a literal tab
/// escaped as backslash-tab, fields separated by tabs and the record terminated by a
/// newline. Returns the number of bytes written, or -1 if the `BUF_MEM` could not grow or a
/// `BIO_write` did not take the whole row.
///
/// # Safety
///
/// `out` must be NULL or a live `BIO` with a `write` method; `db` must be a live `TXT_DB`.
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_write(out: *mut Bio, db: *mut TxtDb) -> c_long {
    guard_ffi(-1, || {
        // `BUF_MEM_new` is the safe constructor and answers NULL on failure.
        let buf = BUF_MEM_new();
        if buf.is_null() {
            return -1;
        }
        let mut ret: c_long = -1;
        'work: {
            // SAFETY: `db` is the caller's live object.
            let n = unsafe { OPENSSL_sk_num((*db).data) } as c_long;
            // SAFETY: `db` is live.
            let nn = unsafe { (*db).num_fields } as c_long;
            let mut tot: c_long = 0;
            for i in 0..n {
                // SAFETY: `i` is a valid row index.
                let pp = unsafe { OPENSSL_sk_value((*db).data, i as c_int) }.cast::<*mut c_char>();
                let mut l: c_long = 0;
                for j in 0..nn {
                    // SAFETY: `pp` has `nn` field slots and `j` is in `[0, nn)`.
                    let fj = unsafe { *pp.add(j as usize) };
                    if !fj.is_null() {
                        // SAFETY: `fj` is NUL-terminated.
                        l += unsafe { strlen(fj) } as c_long;
                    }
                }
                // SAFETY: `buf` is live; `2 * l + nn` is the authority's own bound.
                if unsafe { BUF_MEM_grow_clean(buf, (l * 2 + nn) as usize) } == 0 {
                    break 'work;
                }
                // SAFETY: `buf` is live and its block has the grown size.
                let mut p = unsafe { (*buf).data };
                for j in 0..nn {
                    // SAFETY: `pp` has `nn` field slots and `j` is in `[0, nn)`.
                    let mut f = unsafe { *pp.add(j as usize) };
                    if !f.is_null() {
                        loop {
                            // SAFETY: `f` is NUL-terminated.
                            if unsafe { *f } == 0 {
                                break;
                            }
                            // SAFETY: `f` is NUL-terminated.
                            if unsafe { *f } == b'\t' as c_char {
                                // SAFETY: the block is at least `2 * l + nn` bytes; the
                                // escape byte and the cursor's advance are one step.
                                unsafe {
                                    *p = b'\\' as c_char;
                                    p = p.add(1);
                                }
                            }
                            // SAFETY: both pointers are valid for this byte.
                            unsafe {
                                *p = *f;
                                p = p.add(1);
                                f = f.add(1);
                            }
                        }
                    }
                    // SAFETY: room remains for the separator.
                    unsafe {
                        *p = b'\t' as c_char;
                        p = p.add(1);
                    }
                }
                // SAFETY: at least one byte was written, the final separator.
                unsafe { *p.sub(1) = b'\n' as c_char };
                // SAFETY: both pointers are in `buf`'s own allocation.
                let j = unsafe { p.offset_from((*buf).data) } as c_long;
                // SAFETY: `out` is the caller's BIO and the block holds `j` bytes.
                if unsafe { BIO_write(out, (*buf).data.cast(), j as c_int) } as c_long != j {
                    break 'work;
                }
                tot += j;
            }
            ret = tot;
        }
        // SAFETY: `buf` is live.
        unsafe { BUF_MEM_free(buf) };
        ret
    })
}

/// `OPENSSL_STRING *TXT_DB_get_by_index(TXT_DB *db, int idx, OPENSSL_STRING *value)`
/// — `crypto/txt_db/txt_db.c:127-145`.
///
/// Looks `value` up in the index for field `idx`. Answers NULL and records a
/// `DB_ERROR_*` when `idx` is out of range or has no index; on a lookup it records
/// `DB_ERROR_OK` whether or not a row was found.
///
/// # Safety
///
/// `db` must be a live `TXT_DB`; `value` must be a row the index's comparator can read.
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_get_by_index(
    db: *mut TxtDb,
    idx: c_int,
    value: OpenSslPString,
) -> OpenSslPString {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `db` is the caller's live object.
        let nf = unsafe { (*db).num_fields };
        // A negative index is the recorded safer divergence: the authority would read
        // `db->index[idx]` out of bounds.
        if idx >= nf || idx < 0 {
            // SAFETY: `db` is live.
            unsafe { (*db).error = DB_ERROR_INDEX_OUT_OF_RANGE };
            return ptr::null_mut();
        }
        // SAFETY: `idx` is in `[0, nf)`.
        let lh = unsafe { *(*db).index.add(idx as usize) };
        if lh.is_null() {
            // SAFETY: `db` is live.
            unsafe { (*db).error = DB_ERROR_NO_INDEX };
            return ptr::null_mut();
        }
        // SAFETY: `lh` is a live index and `value` is the caller's lookup row.
        let ret = unsafe { OPENSSL_LH_retrieve(lh, value.cast()) }.cast::<*mut c_char>();
        // SAFETY: `db` is live.
        unsafe { (*db).error = DB_ERROR_OK };
        ret
    })
}

/// `int TXT_DB_create_index(TXT_DB *db, int field, int (*qual)(OPENSSL_STRING *),
/// OPENSSL_LH_HASHFUNC hash, OPENSSL_LH_COMPFUNC cmp)` — `crypto/txt_db/txt_db.c:147-185`.
///
/// Builds an lhash over field `field` from every row `qual` accepts (all rows when `qual`
/// is NULL), refusing with `DB_ERROR_INDEX_CLASH` and filling `arg1`/`arg2` when two rows
/// collide. On success the previous index for `field`, if any, is released and replaced.
///
/// # Safety
///
/// `db` must be a live `TXT_DB`; `qual`, `hash` and `cmp` must be valid callbacks for the
/// row shape the object holds (`hash` and `cmp` may be NULL, which selects the lhash
/// defaults).
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_create_index(
    db: *mut TxtDb,
    field: c_int,
    qual: Option<QualFn>,
    hash: Option<HashFn>,
    cmp: Option<CompFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `db` is the caller's live object.
        let nf = unsafe { (*db).num_fields };
        // The negative arm is the recorded safer divergence.
        if field >= nf || field < 0 {
            // SAFETY: `db` is live.
            unsafe { (*db).error = DB_ERROR_INDEX_OUT_OF_RANGE };
            return 0;
        }
        let idx = OPENSSL_LH_new(hash, cmp);
        if idx.is_null() {
            // SAFETY: `db` is live.
            unsafe { (*db).error = DB_ERROR_MALLOC };
            return 0;
        }
        // SAFETY: `db` is live.
        let n = unsafe { OPENSSL_sk_num((*db).data) };
        for i in 0..n {
            // SAFETY: `i` is a valid row index.
            let r = unsafe { OPENSSL_sk_value((*db).data, i) }.cast::<*mut c_char>();
            if let Some(q) = qual {
                // SAFETY: `r` is a row and `q` is the caller's qualifier for it.
                if unsafe { q(r) } == 0 {
                    continue;
                }
            }
            // SAFETY: `idx` is live and `r` is a row pointer.
            let k = unsafe { OPENSSL_LH_insert(idx, r.cast()) }.cast::<*mut c_char>();
            if !k.is_null() {
                // SAFETY: `db`, its data stack and `k` are live.
                unsafe {
                    (*db).error = DB_ERROR_INDEX_CLASH;
                    (*db).arg1 = OPENSSL_sk_find((*db).data, k.cast()) as c_long;
                    (*db).arg2 = i as c_long;
                }
                // SAFETY: `idx` is live and is not kept on this path.
                unsafe { OPENSSL_LH_free(idx) };
                return 0;
            }
            // SAFETY: `idx` is live and `r` is the row just inserted.
            if unsafe { OPENSSL_LH_retrieve(idx, r.cast()) }.is_null() {
                // SAFETY: `db` is live.
                unsafe { (*db).error = DB_ERROR_MALLOC };
                // SAFETY: `idx` is live and is not kept on this path.
                unsafe { OPENSSL_LH_free(idx) };
                return 0;
            }
        }
        // SAFETY: `field` is in `[0, nf)`; replace the stored index and qualifier.
        unsafe {
            OPENSSL_LH_free(*(*db).index.add(field as usize));
            *(*db).index.add(field as usize) = idx;
            *(*db).qual.add(field as usize) = qual;
        }
        1
    })
}

/// The authority's `err1:` label of `TXT_DB_insert` — `crypto/txt_db/txt_db.c:266-274`.
///
/// # Safety
///
/// `db` must be a live `TXT_DB`; `row` must be the row the caller passed to
/// [`TXT_DB_insert`]; `i` must be the loop cursor the authority's cleanup walks down from.
unsafe fn insert_err1(db: *mut TxtDb, row: OpenSslPString, mut i: c_int) -> c_int {
    // SAFETY: `db` is live.
    unsafe { (*db).error = DB_ERROR_MALLOC };
    while i > 0 {
        i -= 1;
        // SAFETY: `i` is in `[0, num_fields)`.
        let idx = unsafe { *(*db).index.add(i as usize) };
        if idx.is_null() {
            continue;
        }
        // SAFETY: `i` is in `[0, num_fields)`.
        let qual = unsafe { *(*db).qual.add(i as usize) };
        if let Some(q) = qual {
            // SAFETY: `row` is the caller's row and `q` its qualifier.
            if unsafe { q(row) } == 0 {
                continue;
            }
        }
        // SAFETY: `idx` is live and holds `row`.
        unsafe { OPENSSL_LH_delete(idx, row.cast()) };
    }
    0
}

/// `int TXT_DB_insert(TXT_DB *db, OPENSSL_STRING *row)` — `crypto/txt_db/txt_db.c:234-277`.
///
/// Checks every index for a key clash first, then inserts `row` into each index and appends
/// it to `data`. A clash refuses *before* any mutation and records `DB_ERROR_INDEX_CLASH`
/// with `arg1` the field and `arg_row` the row it collided with; an allocation or insertion
/// failure records `DB_ERROR_MALLOC` and undoes the indexes it had already updated.
///
/// # Safety
///
/// `db` must be a live `TXT_DB`; `row` must be a row of the object's own shape owned by the
/// caller, whose ownership transfers to `db` on success.
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_insert(db: *mut TxtDb, row: OpenSslPString) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `db` is the caller's live object.
        let nf = unsafe { (*db).num_fields };
        for i in 0..nf {
            // SAFETY: `i` is in `[0, nf)`.
            let idx = unsafe { *(*db).index.add(i as usize) };
            if idx.is_null() {
                continue;
            }
            // SAFETY: `i` is in `[0, nf)`.
            let qual = unsafe { *(*db).qual.add(i as usize) };
            if let Some(q) = qual {
                // SAFETY: `row` is the caller's row and `q` its qualifier.
                if unsafe { q(row) } == 0 {
                    continue;
                }
            }
            // SAFETY: `idx` is live and `row` is the lookup key.
            let r = unsafe { OPENSSL_LH_retrieve(idx, row.cast()) }.cast::<*mut c_char>();
            if !r.is_null() {
                // SAFETY: `db` is live.
                unsafe {
                    (*db).error = DB_ERROR_INDEX_CLASH;
                    (*db).arg1 = i as c_long;
                    (*db).arg_row = r;
                }
                return 0;
            }
        }

        let mut i: c_int = 0;
        while i < nf {
            // SAFETY: `i` is in `[0, nf)`.
            let idx = unsafe { *(*db).index.add(i as usize) };
            if !idx.is_null() {
                // SAFETY: `i` is in `[0, nf)`.
                let qual = unsafe { *(*db).qual.add(i as usize) };
                let mut skip = false;
                if let Some(q) = qual {
                    // SAFETY: `row` is the caller's row and `q` its qualifier.
                    if unsafe { q(row) } == 0 {
                        skip = true;
                    }
                }
                if !skip {
                    // SAFETY: `idx` is live and `row` the item to store.
                    unsafe { OPENSSL_LH_insert(idx, row.cast()) };
                    // SAFETY: `idx` is live.
                    if unsafe { OPENSSL_LH_retrieve(idx, row.cast()) }.is_null() {
                        // SAFETY: `db` is live and `i` is the failed index.
                        return unsafe { insert_err1(db, row, i) };
                    }
                }
            }
            i += 1;
        }
        // SAFETY: `db` is live and `row` the item to append; `i == nf` here.
        if unsafe { OPENSSL_sk_push((*db).data, row.cast()) } == 0 {
            // SAFETY: `db` is live and `i == nf`.
            return unsafe { insert_err1(db, row, i) };
        }
        1
    })
}

/// `void TXT_DB_free(TXT_DB *db)` — `crypto/txt_db/txt_db.c:279-314`.
///
/// Releases the indexes, the qualifier array, every row and the object. A row built by
/// [`TXT_DB_read`] has its fields inside its own block and they are released with it; a row
/// a caller built with a NULL sentinel has its field pointers released individually. NULL is
/// accepted and ignored.
///
/// # Safety
///
/// `db` must be NULL or an object from this module that is not used again afterwards.
#[no_mangle]
pub unsafe extern "C" fn TXT_DB_free(db: *mut TxtDb) {
    guard_ffi((), || {
        if db.is_null() {
            return;
        }
        // SAFETY: `db` is live.
        let nf = unsafe { (*db).num_fields };
        // SAFETY: `db` is live.
        if !unsafe { (*db).index }.is_null() {
            let mut i = nf - 1;
            while i >= 0 {
                // SAFETY: `i` is in `[0, nf)`.
                let lh = unsafe { *(*db).index.add(i as usize) };
                // SAFETY: `lh` is NULL or a live index.
                unsafe { OPENSSL_LH_free(lh) };
                i -= 1;
            }
            // SAFETY: the array came from `CRYPTO_malloc_array` in `TXT_DB_read`.
            unsafe { CRYPTO_free((*db).index.cast(), FILE, FREE_INDEX) };
        }
        // SAFETY: the array came from `CRYPTO_malloc_array` or is NULL.
        unsafe { CRYPTO_free((*db).qual.cast(), FILE, FREE_QUAL) };
        // SAFETY: `db` is live.
        if !unsafe { (*db).data }.is_null() {
            // SAFETY: `data` is a live stack.
            let mut i = unsafe { OPENSSL_sk_num((*db).data) } - 1;
            while i >= 0 {
                // SAFETY: `i` is a valid row index.
                let p = unsafe { OPENSSL_sk_value((*db).data, i) }.cast::<*mut c_char>();
                // SAFETY: `p` is a row with `nf` fields plus the sentinel at `p[nf]`.
                let max = unsafe { *p.add(nf as usize) };
                if max.is_null() {
                    // A row the caller built with a NULL sentinel: each field is its own
                    // allocation.
                    for n in 0..nf {
                        // SAFETY: `n` is in `[0, nf)`.
                        unsafe { CRYPTO_free((*p.add(n as usize)).cast(), FILE, FREE_FIELD_NEW) };
                    }
                } else {
                    // A row this module built: fields inside the block are not freed, the
                    // ones a caller allocated from outside it are.
                    for n in 0..nf {
                        // SAFETY: `n` is in `[0, nf)`.
                        let field = unsafe { *p.add(n as usize) };
                        if (field as usize) < (p as usize) || (field as usize) > (max as usize) {
                            // SAFETY: `field` lies outside the row's own block.
                            unsafe { CRYPTO_free(field.cast(), FILE, FREE_FIELD_EXT) };
                        }
                    }
                }
                // SAFETY: the row block is this object's own allocation.
                unsafe { CRYPTO_free(p.cast(), FILE, FREE_ROW) };
                i -= 1;
            }
            // SAFETY: `data` is a live stack whose elements are released above.
            unsafe { OPENSSL_sk_free((*db).data) };
        }
        // SAFETY: `db` was allocated by `CRYPTO_malloc` in `TXT_DB_read`.
        unsafe { CRYPTO_free(db.cast(), FILE, FREE_DB) };
    });
}
