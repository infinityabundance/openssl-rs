//! Phase 6.8b-i — `crypto/bio/ossl_core_bio.c`: the core's BIO handle for providers.
//!
//! A provider that wants to read or write a file is not handed a `BIO`. It is handed an
//! `OSSL_CORE_BIO`, which is **deliberately a distinct type** — the authority's own comment
//! says so: *"This is distinct from a BIO to prevent casting between the two which could lead
//! to versioning problems."* So a provider author cannot reach into the `BIO` and is confined
//! to the eleven functions the core publishes through `core_dispatch`'s `OSSL_FUNC_BIO_*`
//! entries.
//!
//! That makes this file the *entire* surface a provider has for I/O, and it is why it belongs
//! to the core-dispatch work rather than to the BIO stratum: nothing here has its own logic.
//! Every function is a reference-counted handle plus a forward to an exported `BIO_*`, which
//! is a property worth stating because it means the interesting behaviour is in which
//! forward fails how, not in the forwards themselves.
//!
//! ## The two constructors differ in who frees the BIO on failure
//!
//! `ossl_core_bio_new_from_bio` is given a BIO the **caller already owns**, so it takes its
//! own reference and, on failure, frees only the handle — the caller's BIO is untouched.
//! `core_bio_new_from_new_bio` is given a BIO the call has **already transferred ownership
//! of**, so on failure it frees the BIO as well. Confusing the two leaks a BIO or releases
//! the caller's; the pair is written as two functions for exactly that reason rather than
//! one with a flag.
//!
//! ## `ossl_core_bio_up_ref` does not test its argument
//!
//! The authority's body is `return CRYPTO_UP_REF(&cb->ref_cnt, &ref);` with no NULL test, so
//! a NULL handle dereferences NULL. `ossl_core_bio_free` *is* NULL-tolerant and answers 1.
//! The asymmetry is the authority's, and the NULL case is a fault there rather than a
//! defined answer, so it is **guarded here and recorded** rather than reproduced — see
//! `docs/SECURITY_DIVERGENCE_POLICY.md`, D-OSSL-CORE-BIO-1.
//!
//! ## Why these were missing
//!
//! They are `ossl_`-prefixed internals, so they are in no version script and in no header the
//! atlas reconciles. Phase 4 owns `crypto/bio/`, and Phase 4 closed at zero open — because
//! **an export-based ledger cannot see an internal function**. That is a blind spot of the
//! same family as the one D49/D51/D97 record for exports, one level down, and it is worth
//! naming here: the ledger's universe is the 6,499 exports, and a file whose contents are all
//! internal contributes nothing to it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::runtime::bio::bss_file::BIO_new_file;
use crate::runtime::bio::bss_mem::BIO_new_mem_buf;
use crate::runtime::bio::iolib::{BIO_ctrl, BIO_gets, BIO_puts, BIO_read_ex, BIO_write_ex};
use crate::runtime::bio::{BIO_free, BIO_up_ref, Bio};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The authority's translation unit, for the allocation-tracking `file` argument.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) const FILE: *const c_char =
    c"../../src/openssl-3.6.4/crypto/bio/ossl_core_bio.c".as_ptr();

/// `core_bio_new`'s `OPENSSL_malloc(sizeof(*cb))`.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
const L_CORE_BIO_NEW: c_int = 25;
/// `ossl_core_bio_free`'s `OPENSSL_free(cb)`.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
const L_CORE_BIO_FREE: c_int = 50;

extern "C" {
    /// `int BIO_vprintf(BIO *bio, const char *format, va_list args)`.
    ///
    /// Defined in `src/runtime/bio/bio_variadic.c`, which is where the `va_arg` walk has to
    /// live: a C-variadic function cannot be defined in stable Rust. A `va_list` is opaque
    /// here in both directions, which is exactly how this crate's other `va_list`
    /// boundaries are declared.
    fn BIO_vprintf(bio: *mut Bio, format: *const c_char, args: *mut c_void) -> c_int;
}

/// `struct ossl_core_bio_st` — `OSSL_CORE_BIO` as the core sees it.
///
/// `CRYPTO_REF_COUNT ref_cnt` is an inline atomic in this build, so it is an `AtomicI32` with
/// no allocation of its own — which is the same reading D115 took for `DSO`'s count.
#[repr(C)]
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) struct OsslCoreBio {
    /// `CRYPTO_REF_COUNT ref_cnt`.
    pub(crate) ref_cnt: AtomicI32,
    /// The wrapped BIO, owned by this handle.
    pub(crate) bio: *mut Bio,
}

/// `static OSSL_CORE_BIO *core_bio_new(void)`.
///
/// `OPENSSL_malloc` and **not** `zalloc`, so the BIO field is uninitialised until the caller
/// sets it. Both callers set it on every success path, and both free the handle on every
/// failure path, so the uninitialised field is never read — but it is the reason this cannot
/// be a `zalloc` "for safety" without changing the allocation the authority makes.
///
/// # Safety
/// None: the answer is a new handle or NULL.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
unsafe fn core_bio_new() -> *mut OsslCoreBio {
    // SAFETY: a fresh block of exactly this type; `CRYPTO_malloc` is a safe function in this
    // crate, so no block is needed for the call itself.
    let cb = CRYPTO_malloc(core::mem::size_of::<OsslCoreBio>(), FILE, L_CORE_BIO_NEW)
        .cast::<OsslCoreBio>();
    if cb.is_null() {
        return ptr::null_mut();
    }
    // The authority's `CRYPTO_NEW_REF` cannot fail for an inline atomic, so its failure arm
    // -- `OPENSSL_free(cb)` at line 28 and `return NULL` -- is unreachable here. The
    // reference count is therefore *set* rather than *created*.
    // SAFETY: `cb` is a fresh block this function owns, so the field write is to
    // uninitialised-owned storage.
    unsafe { (*cb).ref_cnt = AtomicI32::new(1) };
    cb
}

/// `int ossl_core_bio_up_ref(OSSL_CORE_BIO *cb)`.
///
/// Answers `CRYPTO_UP_REF`'s result, which is 1 for every successful call because the count
/// was at least 1 already. The authority does **not** test `cb` here; the NULL guard is this
/// crate's and the divergence is recorded.
///
/// # Safety
/// `cb` must be NULL or a live handle from `core_bio_new`.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_up_ref(cb: *mut OsslCoreBio) -> c_int {
    if cb.is_null() {
        // See D-OSSL-CORE-BIO-1: the authority dereferences NULL here.
        return 0;
    }
    // SAFETY: `cb` is live.
    let ref_ = unsafe { (*cb).ref_cnt.fetch_add(1, Ordering::AcqRel) } + 1;
    c_int::from(ref_ > 1)
}

/// `int ossl_core_bio_free(OSSL_CORE_BIO *cb)`.
///
/// NULL-tolerant, answering 1, so a caller may free unconditionally. The answer is
/// **`BIO_free`'s** on the releasing path, not a constant: a BIO whose destroy hook reports
/// failure makes this answer 0, which is a fact a provider author can depend on.
///
/// # Safety
/// `cb` must be NULL or a live handle, released at most once past its last reference.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_free(cb: *mut OsslCoreBio) -> c_int {
    if cb.is_null() {
        return 1;
    }
    // SAFETY: `cb` is live.
    let ref_ = unsafe { (*cb).ref_cnt.fetch_sub(1, Ordering::AcqRel) } - 1;
    if ref_ > 0 {
        return 1;
    }
    // SAFETY: this is the last reference, so nothing else can reach the handle; the BIO is
    // the one this handle owns.
    unsafe {
        let res = BIO_free((*cb).bio);
        CRYPTO_free(cb.cast::<c_void>(), FILE, L_CORE_BIO_FREE);
        res
    }
}

/// `OSSL_CORE_BIO *ossl_core_bio_new_from_bio(BIO *bio)`.
///
/// The caller keeps its BIO: a reference is taken, so the two owners are independent and a
/// failure frees only the handle.
///
/// # Safety
/// `bio` must be a live `BIO`.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_new_from_bio(bio: *mut Bio) -> *mut OsslCoreBio {
    // SAFETY: the construct takes no arguments and only allocates.
    let cb = unsafe { core_bio_new() };
    if cb.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `bio` is live per the contract.
    if unsafe { BIO_up_ref(bio) } == 0 {
        // The caller's BIO keeps its own reference, so the handle is all that is released.
        // SAFETY: `cb` has one reference (this function's) and a NULL BIO field at this
        // point; the free takes the last reference and releases the handle.
        unsafe {
            (*cb).bio = ptr::null_mut();
            ossl_core_bio_free(cb);
        }
        return ptr::null_mut();
    }
    // SAFETY: `cb` is live and `bio` is now owned by it as well as by the caller.
    unsafe { (*cb).bio = bio };
    cb
}

/// `static OSSL_CORE_BIO *core_bio_new_from_new_bio(BIO *bio)`.
///
/// The call has **already transferred** the BIO, so a failure here frees it: a `BIO_new_file`
/// whose handle cannot be built must not leave a descriptor open. A NULL `bio` is NULL out,
/// not an error, and no error is raised — the caller sees a NULL handle either way.
///
/// # Safety
/// `bio` must be NULL or a live `BIO` whose ownership is being transferred.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
unsafe fn core_bio_new_from_new_bio(bio: *mut Bio) -> *mut OsslCoreBio {
    if bio.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the construct takes no arguments and only allocates.
    let cb = unsafe { core_bio_new() };
    if cb.is_null() {
        // SAFETY: the BIO was transferred to this call, so releasing it is this call's
        // obligation.
        unsafe { BIO_free(bio) };
        return ptr::null_mut();
    }
    // SAFETY: `cb` is live and now owns `bio`.
    unsafe { (*cb).bio = bio };
    cb
}

/// `OSSL_CORE_BIO *ossl_core_bio_new_file(const char *filename, const char *mode)`.
///
/// # Safety
/// `filename` and `mode` must be NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_new_file(
    filename: *const c_char,
    mode: *const c_char,
) -> *mut OsslCoreBio {
    // SAFETY: both strings are NUL-terminated per the contract.
    let bio = unsafe { BIO_new_file(filename, mode) };
    // SAFETY: `bio` is NULL or a freshly created BIO whose ownership passes to the handle.
    unsafe { core_bio_new_from_new_bio(bio) }
}

/// `OSSL_CORE_BIO *ossl_core_bio_new_mem_buf(const void *buf, int len)`.
///
/// # Safety
/// `buf` must be valid for `len` bytes, or `len` must be -1 for a NUL-terminated string.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_new_mem_buf(buf: *const c_void, len: c_int) -> *mut OsslCoreBio {
    // SAFETY: `buf`/`len` follow `BIO_new_mem_buf`'s contract, which is the caller's.
    let bio = unsafe { BIO_new_mem_buf(buf, len) };
    // SAFETY: the BIO's ownership passes to the handle; `core_bio_new_from_new_bio` frees a
    // non-NULL BIO when the handle cannot be built.
    unsafe { core_bio_new_from_new_bio(bio) }
}

/// `int ossl_core_bio_read_ex(OSSL_CORE_BIO *cb, void *data, size_t dlen,
/// size_t *readbytes)`.
///
/// # Safety
/// `cb` must be live and `data`/`readbytes` writable as `BIO_read_ex` requires.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_read_ex(
    cb: *mut OsslCoreBio,
    data: *mut c_void,
    dlen: usize,
    readbytes: *mut usize,
) -> c_int {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and the buffers follow `BIO_read_ex`'s contract.
    unsafe { BIO_read_ex(bio, data, dlen, readbytes) }
}

/// `int ossl_core_bio_write_ex(OSSL_CORE_BIO *cb, const void *data, size_t dlen,
/// size_t *written)`.
///
/// # Safety
/// `cb` must be live and `data`/`written` as `BIO_write_ex` requires.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_write_ex(
    cb: *mut OsslCoreBio,
    data: *const c_void,
    dlen: usize,
    written: *mut usize,
) -> c_int {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and the buffers follow `BIO_write_ex`'s contract.
    unsafe { BIO_write_ex(bio, data, dlen, written) }
}

/// `int ossl_core_bio_gets(OSSL_CORE_BIO *cb, char *buf, int size)`.
///
/// # Safety
/// `cb` must be live and `buf` writable for `size` bytes.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_gets(
    cb: *mut OsslCoreBio,
    buf: *mut c_char,
    size: c_int,
) -> c_int {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and `buf` follows `BIO_gets`'s contract.
    unsafe { BIO_gets(bio, buf, size) }
}

/// `int ossl_core_bio_puts(OSSL_CORE_BIO *cb, const char *buf)`.
///
/// # Safety
/// `cb` must be live and `buf` NUL-terminated.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_puts(cb: *mut OsslCoreBio, buf: *const c_char) -> c_int {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and `buf` is NUL-terminated per the contract.
    unsafe { BIO_puts(bio, buf) }
}

/// `long ossl_core_bio_ctrl(OSSL_CORE_BIO *cb, int cmd, long larg, void *parg)`.
///
/// # Safety
/// `cb` must be live and `parg` must match the command.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_ctrl(
    cb: *mut OsslCoreBio,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and `cmd`/`parg` follow `BIO_ctrl`'s contract.
    unsafe { BIO_ctrl(bio, cmd, larg, parg) }
}

/// `int ossl_core_bio_vprintf(OSSL_CORE_BIO *cb, const char *format, va_list args)`.
///
/// The `va_list` is opaque here, which is how every `va_list` boundary in this crate is
/// declared: it is a pointer to the caller's argument cursor and this function only forwards
/// it. The walk itself is `bio_variadic.c`'s, because `va_arg` needs the argument list of the
/// function that owns it.
///
/// # Safety
/// `cb` must be live, `format` NUL-terminated, and `args` must be the `va_list` of the
/// caller's own variadic function.
#[allow(dead_code)] // unreachable until 6.8b-i publishes the core dispatch table
pub(crate) unsafe fn ossl_core_bio_vprintf(
    cb: *mut OsslCoreBio,
    format: *const c_char,
    args: *mut c_void,
) -> c_int {
    // SAFETY: `cb` is live.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and `format`/`args` follow `BIO_vprintf`'s contract.
    unsafe { BIO_vprintf(bio, format, args) }
}

/// `BIO *ossl_bio_new_from_core_bio(PROV_CTX *provctx, OSSL_CORE_BIO *corebio)` —
/// `providers/common/bio_prov.c`.
///
/// **The provider-BIO method is why this is a bridge and not a copy.** The authority's version
/// builds a new `BIO` over the provider's core-BIO method and stores the `OSSL_CORE_BIO` as its
/// data; that method is installed by `ossl_prov_bio_from_dispatch`, which this crate does not
/// build (see `ossl_default_provider_init`). Here the `OSSL_CORE_BIO` the core hands a provider
/// **already wraps the real `BIO`** (`ossl_core_bio_new_from_bio`), so the bridge is the wrapped
/// BIO with its own reference taken and released by the caller's `BIO_free` — the same reads and
/// writes an authority provider performs, through the one handle this crate has. It is recorded
/// as a divergence (`docs/SECURITY_DIVERGENCE_POLICY.md`, D-PROV-BIO-METHOD-1).
///
/// # Safety
/// `cb` must be NULL or a live handle from `core_bio_new`, and its wrapped BIO must be live.
pub(crate) unsafe fn ossl_bio_new_from_core_bio(cb: *mut OsslCoreBio) -> *mut Bio {
    if cb.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cb` is live per the contract.
    let bio = unsafe { (*cb).bio };
    // SAFETY: the BIO is live and this call takes its own reference on success.
    if unsafe { BIO_up_ref(bio) } == 0 {
        return ptr::null_mut();
    }
    bio
}

#[cfg(test)]
mod tests {
    //! The reference count, the two constructors' differing ownership, and the forwards.
    //!
    //! `alloc` is not linked for unit tests, so no `String` appears below. Every BIO here is
    //! a memory BIO built from a literal.

    use super::*;
    use crate::runtime::bio::iolib::BIO_read_ex as read_ex;

    #[test]
    fn a_memory_handle_reads_the_bytes_it_was_built_from() {
        // SAFETY: a NUL-terminated literal, which is `len == -1`'s contract.
        let cb = unsafe { ossl_core_bio_new_mem_buf(c"hello world".as_ptr().cast::<c_void>(), -1) };
        assert!(!cb.is_null(), "a memo BUF handle must be constructible");
        let mut buf = [0u8; 5];
        let mut got = 0usize;
        // SAFETY: `cb` is live and `buf`/`got` are writable.
        let ok = unsafe {
            ossl_core_bio_read_ex(
                cb,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                ptr::addr_of_mut!(got),
            )
        };
        assert_eq!(ok, 1, "the read succeeds");
        assert_eq!(got, 5, "five bytes were asked for and five came back");
        assert_eq!(&buf, b"hello");
        // SAFETY: `cb` is live and holds the only reference.
        let freed = unsafe { ossl_core_bio_free(cb) };
        assert_eq!(
            freed, 1,
            "releasing the last reference answers BIO_free's result"
        );
    }

    #[test]
    fn the_reference_count_is_observable_through_free_and_only_the_last_one_releases() {
        // SAFETY: a memory handle over a literal.
        let cb = unsafe { ossl_core_bio_new_mem_buf(c"x".as_ptr().cast::<c_void>(), 1) };
        assert!(!cb.is_null());
        // `undocumented_unsafe_blocks` wants the comment *directly* above the block, and
        // inside a macro invocation the block is what the macro expands to, so the comment
        // has to sit within the macro rather than above it.
        assert_eq!(
            // SAFETY: `cb` is live.
            unsafe { ossl_core_bio_up_ref(cb) },
            1,
            "the first up_ref answers 1"
        );
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_core_bio_up_ref(cb) },
            1,
            "and so does the second"
        );
        // SAFETY: as above. Two releases leave the handle alive.
        assert_eq!(unsafe { ossl_core_bio_free(cb) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { ossl_core_bio_free(cb) }, 1);
        // The handle is still usable: its count is 1, not 0.
        let mut b = [0u8; 1];
        let mut got = 0usize;
        // SAFETY: `cb` is live.
        let ok = unsafe {
            ossl_core_bio_read_ex(
                cb,
                b.as_mut_ptr().cast::<c_void>(),
                1,
                ptr::addr_of_mut!(got),
            )
        };
        assert_eq!(ok, 1, "readable after three up_refs and two frees");
        assert_eq!(got, 1);
        // SAFETY: `cb` is live and this is its last reference.
        assert_eq!(unsafe { ossl_core_bio_free(cb) }, 1);
    }

    #[test]
    fn free_is_null_tolerant_and_answers_one() {
        // SAFETY: `ossl_core_bio_free` accepts NULL by its contract.
        assert_eq!(unsafe { ossl_core_bio_free(ptr::null_mut()) }, 1);
        // `up_ref` is NOT: the authority dereferences NULL, so the guard here answers 0 and
        // the divergence is recorded rather than reproduced.
        // SAFETY: `ossl_core_bio_up_ref` accepts NULL in this crate's version.
        assert_eq!(unsafe { ossl_core_bio_up_ref(ptr::null_mut()) }, 0);
    }

    #[test]
    fn new_from_bio_takes_its_own_reference_so_the_callers_bio_survives() {
        // SAFETY: a fresh memory BIO over a literal.
        let bio = unsafe { BIO_new_mem_buf(c"abc".as_ptr().cast::<c_void>(), 3) };
        assert!(!bio.is_null());
        // SAFETY: `bio` is live.
        let cb = unsafe { ossl_core_bio_new_from_bio(bio) };
        assert!(!cb.is_null(), "the handle is built around the caller's BIO");
        // Releasing the *handle* must leave the caller's BIO alive, because the handle took
        // its own reference rather than adopting the caller's.
        // SAFETY: `cb` is live and holds one of the two references.
        assert_eq!(unsafe { ossl_core_bio_free(cb) }, 1);
        let mut b = [0u8; 3];
        let mut got = 0usize;
        // SAFETY: `bio` is still live: only the handle's reference was released.
        let ok = unsafe {
            read_ex(
                bio,
                b.as_mut_ptr().cast::<c_void>(),
                3,
                ptr::addr_of_mut!(got),
            )
        };
        assert_eq!(ok, 1, "the caller's BIO is still readable");
        assert_eq!(got, 3);
        assert_eq!(&b, b"abc");
        // SAFETY: `bio` is live and this releases the caller's reference.
        assert_eq!(unsafe { BIO_free(bio) }, 1);
    }

    #[test]
    fn a_null_memo_buf_answers_null_without_raising() {
        // `core_bio_new_from_new_bio` returns NULL for a NULL BIO and deliberately does not
        // raise: the caller sees a NULL handle either way, so an error would be noise.
        // SAFETY: a zero-length Buffer at NULL is not a valid request, so this uses an
        // explicit NULL with length 0, which `BIO_new_mem_buf` refuses and answers NULL for.
        let cb = unsafe { ossl_core_bio_new_mem_buf(ptr::null(), 0) };
        assert!(cb.is_null(), "a NULL buffer yields no handle");
    }

    #[test]
    fn the_ctrl_and_puts_forwards_reach_the_wrapped_bio() {
        // SAFETY: a fresh memory write BIO.
        let cb = unsafe { ossl_core_bio_new_mem_buf(c"".as_ptr().cast::<c_void>(), 0) };
        assert!(!cb.is_null());
        // SAFETY: `cb` is live and the string is a literal.
        let put = unsafe { ossl_core_bio_puts(cb, c"plus".as_ptr()) };
        // A read-only memory BIO cannot be written to; the *forward* is what is being
        // observed here, and its failure is the wrapped BIO's answer rather than a NULL
        // handle. Either answer is acceptable, but the call must not fault.
        assert!(put <= 0, "a read-only memo BIO refuses a write, got {put}");
        // `BIO_CTRL_INFO` (3) on a memory BIO answers the data pointer; `BIO_CTRL_PENDING`
        // (10) answers the remaining count. The forward must not fault on either.
        // SAFETY: `cb` is live and `BIO_CTRL_PENDING` takes no argument.
        let pending = unsafe { ossl_core_bio_ctrl(cb, 10, 0, ptr::null_mut()) };
        assert!(
            pending >= 0,
            "the ctrl forward reaches the BIO, got {pending}"
        );
        // SAFETY: `cb` is live and holds the only reference.
        assert_eq!(unsafe { ossl_core_bio_free(cb) }, 1);
    }
}
