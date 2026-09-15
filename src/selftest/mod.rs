//! Phase 6.11 — the self-test callback surface.
//!
//! Two things share this module because they share a shape: a per-context
//! callback holder stored in a library context slot, and an object that invokes a
//! callback at a moment of interest. `crypto/self_test_core.c` is 160 lines and
//! `crypto/indicator_core.c` is 54, and neither has a dependency the other does
//! not.
//!
//! ## The self-test object aliases its own fields
//!
//! `struct ossl_self_test_st` holds `phase`, `type` and `desc` as `const char *`
//! and a four-element `OSSL_PARAM` array **whose entries point back at those
//! three fields**. That aliasing is the whole design and it is observable:
//!
//! * `self_test_setparams` builds `st-phase`/`st-type`/`st-desc` pointing at
//!   `st->phase`/`st->type`/`st->desc`, so a caller that holds the array after the
//!   call sees whatever the fields say *then*, not what they said when the array
//!   was built;
//! * `OSSL_SELF_TEST_onend` reassigns all three to the string `"None"` **after**
//!   invoking the callback and **without** rebuilding the array. So an array
//!   captured during `onend` reports phase `Pass` when read inside the callback
//!   and `None` when read afterwards. A transcription that rebuilt the array, or
//!   that copied the strings, would lose that.
//! * the array has four entries only when a callback is set. With a NULL callback
//!   it is a bare terminator — which is what `OSSL_SELF_TEST_new` builds — so a
//!   fresh object's array is "empty" rather than "phase/type/desc with empty
//!   values".
//!
//! `RT-SELFTEST` observes all three, because a callback receives the array and can
//! print it: the court's probe *is* the callback.
//!
//! ## Two safety divergences, both recorded
//!
//! * `OSSL_SELF_TEST_oncorrupt_byte` dereferences `bytes` only when its callback
//!   refuses the corruption. The authority faults on a NULL `bytes` in that case;
//!   this answers 0, because nothing was corrupted.
//! * a context whose callback slot cannot be read stores nothing and answers
//!   NULL, where the authority's own NULL guards do the same.
//!
//! Both are in `docs/SECURITY_DIVERGENCE_POLICY.md` with the authority behaviour
//! they stand in for.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_SELF_TEST_CB_INDEX};
use crate::ffi::guard_ffi;
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string, OsslParam};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

pub mod indicator;

/// `OSSL_CALLBACK`, from `openssl/core.h`:
/// `int (*)(const OSSL_PARAM params[], void *arg)`.
///
/// A bare function pointer, so a C caller's NULL is representable: the parameter
/// is `Option<OsslCallback>` everywhere it appears.
pub type OsslCallback = unsafe extern "C" fn(*const OsslParam, *mut c_void) -> c_int;

/// `OSSL_INDICATOR_CALLBACK`, from `openssl/indicator.h`:
/// `int (*)(const char *type, const char *desc, const OSSL_PARAM params[])`.
pub type OsslIndicatorCallback =
    unsafe extern "C" fn(*const c_char, *const c_char, *const OsslParam) -> c_int;

/// The authority's translation unit, so an allocation that fails records the
/// coordinates a consumer would see from the authority.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/self_test_core.c".as_ptr();
/// `OPENSSL_zalloc(sizeof(*stcb))` is at `crypto/self_test_core.c:40`,
/// `OPENSSL_free(stcb)` at 45, `OPENSSL_zalloc(sizeof(*ret))` at 88 and
/// `OPENSSL_free(st)` at 103.
const LINE_ZALLOC_CB: c_int = 40;
const LINE_FREE_CB: c_int = 45;
const LINE_ZALLOC_ST: c_int = 88;
const LINE_FREE_ST: c_int = 103;

/// `OSSL_SELF_TEST_PHASE_*` and `OSSL_SELF_TEST_TYPE_NONE` / `_DESC_NONE`, from
/// `openssl/self_test.h`. The `NONE` spellings really are the string `"None"` for
/// all three fields rather than the empty string, which is why `onend` leaves the
/// object reporting `None` rather than blank.
const PHASE_NONE: &core::ffi::CStr = c"None";
const PHASE_START: &core::ffi::CStr = c"Start";
const PHASE_CORRUPT: &core::ffi::CStr = c"Corrupt";
const PHASE_PASS: &core::ffi::CStr = c"Pass";
const PHASE_FAIL: &core::ffi::CStr = c"Fail";
const EMPTY: &core::ffi::CStr = c"";

/// The `OSSL_PARAM` keys, from `openssl/core_names.h`.
const KEY_PHASE: &core::ffi::CStr = c"st-phase";
const KEY_TYPE: &core::ffi::CStr = c"st-type";
const KEY_DESC: &core::ffi::CStr = c"st-desc";

// ---------------------------------------------------------------------------
// The per-context slot (index 12)
// ---------------------------------------------------------------------------

/// `struct self_test_cb_st` — two pointers, `OPENSSL_zalloc`ed.
#[repr(C)]
pub(crate) struct SelfTestCb {
    /// `OSSL_CALLBACK *cb`.
    cb: Option<OsslCallback>,
    /// `void *cbarg`.
    cbarg: *mut c_void,
}

/// `void *ossl_self_test_set_callback_new(OSSL_LIB_CTX *ctx)`
///
/// The `ctx` argument is accepted and unused, as in the authority.
pub(crate) fn ossl_self_test_set_callback_new(_ctx: *mut c_void) -> *mut SelfTestCb {
    CRYPTO_zalloc(core::mem::size_of::<SelfTestCb>(), FILE, LINE_ZALLOC_CB).cast::<SelfTestCb>()
}

/// `void ossl_self_test_set_callback_free(void *stcb)` — accepts NULL.
///
/// # Safety
/// `stcb` must be NULL or a pointer returned by
/// [`ossl_self_test_set_callback_new`] and not already released.
pub(crate) unsafe fn ossl_self_test_set_callback_free(stcb: *mut SelfTestCb) {
    if stcb.is_null() {
        return;
    }
    // SAFETY: the block came from `CRYPTO_zalloc` in the constructor and is
    // released exactly once here.
    unsafe { CRYPTO_free(stcb.cast::<c_void>(), FILE, LINE_FREE_CB) };
}

/// `get_self_test_callback(libctx)` — the slot lookup, through the context
/// module's own accessor rather than through the exported forward, because this
/// is the internal caller the authority's static function represents.
fn slot(ctx: *mut c_void) -> *mut SelfTestCb {
    lib_ctx_get_data(ctx, OSSL_LIB_CTX_SELF_TEST_CB_INDEX).cast::<SelfTestCb>()
}

// ---------------------------------------------------------------------------
// The self-test object
// ---------------------------------------------------------------------------

/// `struct ossl_self_test_st`.
///
/// `phase`, `type_` and `desc` are `const char *` in the authority and the
/// `params` array aliases them. `params` is four entries because the authority
/// declares `OSSL_PARAM params[4]` regardless of how many it fills.
#[repr(C)]
pub struct OsslSelfTest {
    phase: *const c_char,
    type_: *const c_char,
    desc: *const c_char,
    cb: Option<OsslCallback>,
    params: [OsslParam; 4],
    cb_arg: *mut c_void,
}

/// `static void self_test_setparams(OSSL_SELF_TEST *st)`
///
/// Rebuilds the array in place. The three entries are built **only when a
/// callback is set**, and each stores the address of the field rather than a copy
/// of the string — see the module documentation for why that is observable.
///
/// # Safety
/// `st` must be a live object from [`OSSL_SELF_TEST_new`].
unsafe fn self_test_setparams(st: *mut OsslSelfTest) {
    let mut n = 0;
    // SAFETY: `st` is live per the caller's contract; every write is to the
    // object's own array, bounded by its four entries, and `n` reaches at most 3
    // before the terminator.
    unsafe {
        if (*st).cb.is_some() {
            (*st).params[n] =
                OSSL_PARAM_construct_utf8_string(KEY_PHASE.as_ptr(), (*st).phase.cast_mut(), 0);
            n += 1;
            (*st).params[n] =
                OSSL_PARAM_construct_utf8_string(KEY_TYPE.as_ptr(), (*st).type_.cast_mut(), 0);
            n += 1;
            (*st).params[n] =
                OSSL_PARAM_construct_utf8_string(KEY_DESC.as_ptr(), (*st).desc.cast_mut(), 0);
            n += 1;
        }
        (*st).params[n] = OSSL_PARAM_construct_end();
    }
}

/// `OSSL_SELF_TEST *OSSL_SELF_TEST_new(OSSL_CALLBACK *cb, void *cbarg)`
///
/// `cb` is a nullable function pointer and `cbarg` is stored verbatim; the object
/// owns neither. Returns NULL only when the allocation fails.
#[no_mangle]
pub extern "C" fn OSSL_SELF_TEST_new(cb: Option<OsslCallback>, cbarg: *mut c_void) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let st = CRYPTO_zalloc(core::mem::size_of::<OsslSelfTest>(), FILE, LINE_ZALLOC_ST)
            .cast::<OsslSelfTest>();
        if st.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `st` is a fresh block of exactly this struct's size that no
        // other thread can observe yet; these are its only writes before it is
        // published.
        unsafe {
            (*st).cb = cb;
            (*st).cb_arg = cbarg;
            (*st).phase = EMPTY.as_ptr();
            (*st).type_ = EMPTY.as_ptr();
            (*st).desc = EMPTY.as_ptr();
            self_test_setparams(st);
        }
        st.cast::<c_void>()
    })
}

/// `void OSSL_SELF_TEST_free(OSSL_SELF_TEST *st)` — accepts NULL.
///
/// # Safety
/// `st` must be NULL or a value returned by [`OSSL_SELF_TEST_new`] and not
/// already released.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_free(st: *mut c_void) {
    guard_ffi((), || {
        if st.is_null() {
            return;
        }
        // SAFETY: the block came from `CRYPTO_zalloc` in the constructor and is
        // released exactly once here. The object owns neither the callback nor
        // its argument, so nothing else is released.
        unsafe { CRYPTO_free(st, FILE, LINE_FREE_ST) };
    })
}

/// `void OSSL_SELF_TEST_onbegin(OSSL_SELF_TEST *st, const char *type, const char *desc)`
///
/// A no-op for a NULL object **or** a NULL callback: the authority guards both, so
/// an object created without a callback never calls anything.
///
/// # Safety
/// `st` must be NULL or a live object; `type` and `desc` must be NULL or
/// NUL-terminated strings that outlive the object's use of them — they are stored
/// by reference, not copied.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_onbegin(
    st: *mut c_void,
    type_: *const c_char,
    desc: *const c_char,
) {
    guard_ffi((), || {
        if st.is_null() {
            return;
        }
        let st = st.cast::<OsslSelfTest>();
        // SAFETY: `st` is live per the caller's contract. The callback is invoked
        // with the object's own array, which is why the array's address is taken
        // rather than the entries copied.
        unsafe {
            if (*st).cb.is_none() {
                return;
            }
            (*st).phase = PHASE_START.as_ptr();
            (*st).type_ = type_;
            (*st).desc = desc;
            self_test_setparams(st);
            if let Some(cb) = (*st).cb {
                let _ = cb(
                    ptr::addr_of!((*st).params).cast::<OsslParam>(),
                    (*st).cb_arg,
                );
            }
        }
    })
}

/// `void OSSL_SELF_TEST_onend(OSSL_SELF_TEST *st, int ret)`
///
/// The phase is `Pass` when `ret == 1` and `Fail` for **every** other value,
/// including 0 and negative ones — an important detail, because "failed" and "did
/// not answer 1" are the same thing to the authority.
///
/// The three fields are reset to `"None"` *after* the callback and *without*
/// rebuilding the array, so the array a caller captured during the call reports
/// the phase it had then and the strings it has now.
///
/// # Safety
/// `st` must be NULL or a live object.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_onend(st: *mut c_void, ret: c_int) {
    guard_ffi((), || {
        if st.is_null() {
            return;
        }
        let st = st.cast::<OsslSelfTest>();
        // SAFETY: `st` is live per the caller's contract.
        unsafe {
            if (*st).cb.is_none() {
                return;
            }
            (*st).phase = if ret == 1 {
                PHASE_PASS.as_ptr()
            } else {
                PHASE_FAIL.as_ptr()
            };
            self_test_setparams(st);
            if let Some(cb) = (*st).cb {
                let _ = cb(
                    ptr::addr_of!((*st).params).cast::<OsslParam>(),
                    (*st).cb_arg,
                );
            }
            (*st).phase = PHASE_NONE.as_ptr();
            (*st).type_ = PHASE_NONE.as_ptr();
            (*st).desc = PHASE_NONE.as_ptr();
        }
    })
}

/// `int OSSL_SELF_TEST_oncorrupt_byte(OSSL_SELF_TEST *st, unsigned char *bytes)`
///
/// The callback decides: if it answers **0** the first byte is flipped and this
/// answers 1; otherwise the byte is untouched and this answers 0. The phase is
/// `Corrupt`, and `type`/`desc` are *not* changed — so a caller that never called
/// `onbegin` passes the object's initial empty strings through to the callback.
///
/// A NULL `bytes` with a refusing callback is the authority's fault; this answers
/// 0 because nothing was corrupted. See the module documentation.
///
/// # Safety
/// `st` must be NULL or a live object; `bytes` must be NULL or point to one
/// writable byte.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_oncorrupt_byte(st: *mut c_void, bytes: *mut u8) -> c_int {
    guard_ffi(0, || {
        if st.is_null() {
            return 0;
        }
        let st = st.cast::<OsslSelfTest>();
        // SAFETY: `st` is live per the caller's contract.
        unsafe {
            if (*st).cb.is_none() {
                return 0;
            }
            (*st).phase = PHASE_CORRUPT.as_ptr();
            self_test_setparams(st);
            let Some(cb) = (*st).cb else {
                return 0;
            };
            if cb(
                ptr::addr_of!((*st).params).cast::<OsslParam>(),
                (*st).cb_arg,
            ) != 0
            {
                return 0;
            }
            if bytes.is_null() {
                // The authority writes through the NULL here. Recorded divergence.
                return 0;
            }
            // `bytes` is non-NULL and points to one writable byte per the
            // caller's contract; the write is part of the enclosing block, which
            // is where its SAFETY comment is.
            *bytes ^= 1;
            1
        }
    })
}

/// `void OSSL_SELF_TEST_set_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK *cb, void *cbarg)`
///
/// Stores the pair in the **context's** slot rather than in any object, so every
/// self-test object created afterwards on that context uses it. A context whose
/// slot cannot be read stores nothing, silently — the authority's own behaviour.
///
/// # Safety
/// `libctx` must be NULL or a live context. The pair is stored, not owned: the
/// caller must keep `cbarg` alive for as long as the context may invoke it.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_set_callback(
    libctx: *mut c_void,
    cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) {
    guard_ffi((), || {
        let stcb = slot(libctx);
        if stcb.is_null() {
            return;
        }
        // SAFETY: `stcb` is a live callback holder owned by the context.
        unsafe {
            (*stcb).cb = cb;
            (*stcb).cbarg = cbarg;
        }
    })
}

/// `void OSSL_SELF_TEST_get_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK **cb, void **cbarg)`
///
/// Each output pointer is optional: a NULL one is skipped rather than written
/// through, so a caller can ask for either half alone. Both answer NULL when the
/// context has no slot.
///
/// The first out-parameter is a `OSSL_CALLBACK **` — a pointer to a **function
/// pointer**, not a `void **`. An earlier revision of this file wrote it as
/// `*mut *mut c_void`, which is the same to a probe that passes correctly sized
/// storage and a different prototype to every compiler; the prototype court
/// found it (`OSSL_SELF_TEST_get_callback` was one of two type mismatches at the
/// 6.11 landing), and no runtime observation could have.
///
/// # Safety
/// `libctx` must be NULL or a live context; `cb` and `cbarg` must each be NULL or
/// point to writable storage.
#[no_mangle]
pub unsafe extern "C" fn OSSL_SELF_TEST_get_callback(
    libctx: *mut c_void,
    cb: *mut Option<OsslCallback>,
    cbarg: *mut *mut c_void,
) {
    guard_ffi((), || {
        let stcb = slot(libctx);
        // SAFETY: `cb` and `cbarg` are NULL or writable per the caller's
        // contract; the writes are of a stored function pointer and a stored
        // argument, either of which may legitimately be NULL.
        unsafe {
            if !cb.is_null() {
                *cb = if stcb.is_null() { None } else { (*stcb).cb };
            }
            if !cbarg.is_null() {
                *cbarg = if stcb.is_null() {
                    ptr::null_mut()
                } else {
                    (*stcb).cbarg
                };
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new, OSSL_LIB_CTX_set0_default};

    /// What a callback invocation saw. The array is probed through
    /// `OSSL_PARAM_locate`, so the assertion is about the keys and values the
    /// authority would pass rather than merely that a call happened.
    struct Call {
        phase: [u8; 16],
        type_: [u8; 16],
        desc: [u8; 16],
        calls: c_int,
        refuse: bool,
    }

    /// Copies a UTF-8 parameter's value into a fixed buffer, NUL-terminated, or
    /// writes `-` when the key is absent.
    ///
    /// # Safety
    /// `params` must be the array the callback was given; `dst` must be non-empty.
    unsafe fn copy_utf8(params: *const OsslParam, key: &core::ffi::CStr, dst: &mut [u8]) {
        dst.fill(0);
        // SAFETY: `params` is the callback's array per the contract, and `key` is
        // a literal.
        // `OSSL_PARAM_locate` takes a mutable pointer because a located
        // parameter may be written through; locating does not write.
        let found = unsafe {
            crate::params::OSSL_PARAM_locate(params.cast_mut().cast::<OsslParam>(), key.as_ptr())
        };
        if found.is_null() {
            dst[0] = b'-';
            return;
        }
        // SAFETY: `found` is a live parameter of the array just built.
        let p = unsafe { &*found };
        let len = core::cmp::min(p.data_size, dst.len() - 1);
        // SAFETY: `p.data` points to a NUL-terminated string for a UTF8_STRING
        // parameter, and `len` is bounded by the destination buffer.
        unsafe { ptr::copy_nonoverlapping(p.data.cast::<u8>(), dst.as_mut_ptr(), len) };
    }

    unsafe extern "C" fn record(params: *const OsslParam, arg: *mut c_void) -> c_int {
        // SAFETY: `arg` is the `Call` this test passed as the callback argument,
        // and `params` is the object's array per the caller contract.
        unsafe {
            let arg = arg.cast::<Call>();
            (*arg).calls += 1;
            copy_utf8(params, c"st-phase", &mut (*arg).phase);
            copy_utf8(params, c"st-type", &mut (*arg).type_);
            copy_utf8(params, c"st-desc", &mut (*arg).desc);
            if (*arg).refuse {
                0
            } else {
                1
            }
        }
    }

    /// The NUL-terminated prefix of a fixed buffer, as text. Invalid UTF-8 is
    /// impossible here -- every value written is an ASCII literal from the
    /// authority's headers -- so a failure is reported as a marker rather than
    /// panicking inside an `extern "C"` callback's test.
    fn as_str(b: &[u8]) -> &str {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        core::str::from_utf8(&b[..end]).unwrap_or("<invalid-utf8>")
    }

    fn new_call() -> Call {
        Call {
            phase: [0; 16],
            type_: [0; 16],
            desc: [0; 16],
            calls: 0,
            refuse: false,
        }
    }

    #[test]
    fn the_phases_a_callback_sees() {
        let mut call = new_call();
        let st = OSSL_SELF_TEST_new(Some(record), ptr::addr_of_mut!(call).cast::<c_void>());
        assert!(!st.is_null());
        // SAFETY: `st` is live and `call` outlives every use of it.
        unsafe {
            OSSL_SELF_TEST_onbegin(st, c"KAT_Digest".as_ptr(), c"SHA2".as_ptr());
            assert_eq!(call.calls, 1);
            assert_eq!(as_str(&call.phase), "Start");
            assert_eq!(as_str(&call.type_), "KAT_Digest");
            assert_eq!(as_str(&call.desc), "SHA2");

            // `onend` treats anything other than 1 as a failure.
            OSSL_SELF_TEST_onend(st, 1);
            assert_eq!(as_str(&call.phase), "Pass");
            assert_eq!(as_str(&call.type_), "KAT_Digest");
            OSSL_SELF_TEST_onend(st, 0);
            assert_eq!(as_str(&call.phase), "Fail");
            OSSL_SELF_TEST_onend(st, -1);
            assert_eq!(as_str(&call.phase), "Fail");
            assert_eq!(call.calls, 4);
            // `onend` reset the fields after the last call and did not rebuild
            // the array. The entries point at those fields, so reading through
            // the array now reports "None" -- the aliasing the module
            // documentation describes, observed from outside.
            let array = ptr::addr_of!((*st.cast::<OsslSelfTest>()).params).cast::<OsslParam>();
            let mut buf = [0u8; 16];
            copy_utf8(array, c"st-type", &mut buf);
            assert_eq!(as_str(&buf), "None");
            copy_utf8(array, c"st-desc", &mut buf);
            assert_eq!(as_str(&buf), "None");
            OSSL_SELF_TEST_free(st);
        }
    }

    #[test]
    fn oncorrupt_byte_flips_only_when_the_callback_refuses() {
        let mut call = new_call();
        let st = OSSL_SELF_TEST_new(Some(record), ptr::addr_of_mut!(call).cast::<c_void>());
        assert!(!st.is_null());
        let mut byte = 0xa5u8;
        // SAFETY: `st` is live, `byte` is writable, and `call` outlives its use.
        unsafe {
            // The callback answers 1, so the byte is untouched and the answer is 0.
            assert_eq!(
                OSSL_SELF_TEST_oncorrupt_byte(st, ptr::addr_of_mut!(byte)),
                0
            );
            assert_eq!(byte, 0xa5);
            assert_eq!(as_str(&call.phase), "Corrupt");
            // A fresh object's `type`/`desc` are empty and `oncorrupt_byte` does
            // not change them.
            assert_eq!(as_str(&call.type_), "");
            assert_eq!(as_str(&call.desc), "");
            // Now it refuses. The assignment is read by the callback through the
            // pointer the object holds, which is why the linter has to be told
            // that it is not dead.
            call.refuse = true;
            let refused = call.refuse;
            assert!(refused);
            assert_eq!(
                OSSL_SELF_TEST_oncorrupt_byte(st, ptr::addr_of_mut!(byte)),
                1
            );
            assert_eq!(byte, 0xa4);
            OSSL_SELF_TEST_free(st);
        }
    }

    #[test]
    fn an_object_without_a_callback_calls_nothing() {
        let st = OSSL_SELF_TEST_new(None, ptr::null_mut());
        assert!(!st.is_null());
        let mut byte = 0x01u8;
        // SAFETY: `st` is live and `byte` is writable.
        unsafe {
            OSSL_SELF_TEST_onbegin(st, c"x".as_ptr(), c"y".as_ptr());
            OSSL_SELF_TEST_onend(st, 1);
            assert_eq!(
                OSSL_SELF_TEST_oncorrupt_byte(st, ptr::addr_of_mut!(byte)),
                0
            );
            assert_eq!(byte, 0x01);
            OSSL_SELF_TEST_free(st);
            // Freeing NULL is a no-op.
            OSSL_SELF_TEST_free(ptr::null_mut());
        }
    }

    #[test]
    fn the_callback_pair_is_per_context() {
        let a = OSSL_LIB_CTX_new();
        let b = OSSL_LIB_CTX_new();
        assert!(!a.is_null() && !b.is_null());
        let mut arg = 7i32;
        let mut got_cb: Option<OsslCallback> = None;
        let mut got_arg: *mut c_void = ptr::null_mut();
        // SAFETY: both contexts are live; the out-parameters are writable.
        unsafe {
            // A fresh context has no callback.
            OSSL_SELF_TEST_get_callback(a, ptr::addr_of_mut!(got_cb), ptr::addr_of_mut!(got_arg));
            assert!(got_cb.is_none() && got_arg.is_null());

            OSSL_SELF_TEST_set_callback(a, Some(record), ptr::addr_of_mut!(arg).cast::<c_void>());
            OSSL_SELF_TEST_get_callback(a, ptr::addr_of_mut!(got_cb), ptr::addr_of_mut!(got_arg));
            assert!(got_cb.is_some_and(|f| f as *const () == record as *const ()));
            assert_eq!(got_arg, ptr::addr_of_mut!(arg).cast::<c_void>());

            // `b` did not move.
            OSSL_SELF_TEST_get_callback(b, ptr::addr_of_mut!(got_cb), ptr::addr_of_mut!(got_arg));
            assert!(got_cb.is_none() && got_arg.is_null());

            // Each output pointer is optional.
            got_cb = None;
            OSSL_SELF_TEST_get_callback(a, ptr::addr_of_mut!(got_cb), ptr::null_mut());
            assert!(got_cb.is_some_and(|f| f as *const () == record as *const ()));

            // A NULL context reads the default context's slot.
            let previous = OSSL_LIB_CTX_set0_default(a);
            OSSL_SELF_TEST_get_callback(
                ptr::null_mut(),
                ptr::addr_of_mut!(got_cb),
                ptr::addr_of_mut!(got_arg),
            );
            assert!(got_cb.is_some_and(|f| f as *const () == record as *const ()));
            OSSL_LIB_CTX_set0_default(previous);

            OSSL_LIB_CTX_free(b);
            OSSL_LIB_CTX_free(a);
        }
    }
}
