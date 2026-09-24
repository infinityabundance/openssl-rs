//! Phase 13 staging — `crypto/ui/ui_util.c`: the `UI_UTIL_*` bridge to a legacy callback.
//!
//! Landed ahead of its stratum, as `ui_lib.rs` was under D350, because it is the last thing
//! between `crypto/passphrase.c`'s dispatcher and a compilable encoder: `ossl_pw_get_passphrase`'s
//! `is_pem_password` arm calls [`UI_UTIL_wrap_read_pem_callback`] to turn a `pem_password_cb` into
//! a `UI_METHOD`, and `crypto/encode_decode/encoder_lib.c`'s `encoder_process` needs that
//! dispatcher for its passphrase callback. So this unit is the **head** of the chain D357 measured
//! (`ossl_pw_passphrase_callback_enc` -> `ossl_pw_get_passphrase` ->
//! `UI_UTIL_wrap_read_pem_callback`), and it is the reason the encoder work could not proceed
//! without it.
//!
//! ## The `RUN_ONCE` is the only interesting machinery
//!
//! The wrapper stores its `struct pem_password_cb_data` in the *method's* ex-data rather than in a
//! global, so the ex-data index it uses must be allocated exactly once per process --
//! `RUN_ONCE(&get_index_once, ui_method_data_index_init)`. The crate has no `RUN_ONCE` macro, and
//! the authority's expands to `CRYPTO_THREAD_run_once(once, init##_ossl_) && init##_ossl_ret_`, so
//! the sequence here is the same one `src/runtime/init.rs` uses for `ossl_init_base`: an
//! `AtomicI32` for the once, a second for the cached answer, and a wrapper that stores the body's
//! return value so every later caller reads it rather than re-running the body.
//!
//! The index itself is `-1` until the once runs, which is the authority's own initialiser and the
//! reason `UI_method_set_ex_data(ui_method, ui_method_data_index, data)` is inside the `RUN_ONCE`
//! short-circuit: a wrapper built before the index exists would attach its data at index `-1`.
//!
//! ## `ui_read` dereferences the ex-data without a NULL test, and so does this
//!
//! `ui_read` casts the method's ex-data to a `struct pem_password_cb_data *` and calls
//! `data->cb` immediately. The authority does not test it, because the only `UI_METHOD` that
//! installs `ui_read` as its reader is the one this file builds, and that one always attaches the
//! data. Reproducing the untested dereference is deliberate: a NULL test here would be a
//! divergence that hides a real mis-wiring.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::evp::pem_bridge::PemPasswordCb;
use crate::pem::pem_lib::{PEM_def_callback, PEM_BUFSIZE};
use crate::runtime::ex_data::{CRYPTO_get_ex_new_index, CryptoExData, CRYPTO_EX_INDEX_UI_METHOD};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::runtime::thread::CRYPTO_THREAD_run_once;
use crate::ui::ui_lib::{
    UI_add_input_string, UI_add_verify_string, UI_create_method, UI_destroy_method, UI_free,
    UI_get0_user_data, UI_get_method, UI_get_result_maxsize, UI_get_string_type,
    UI_method_get_ex_data, UI_method_set_closer, UI_method_set_ex_data, UI_method_set_opener,
    UI_method_set_reader, UI_method_set_writer, UI_new, UI_process, UI_set_result_ex, Ui, UiMethod,
    UiString, UIT_BOOLEAN, UIT_ERROR, UIT_INFO, UIT_NONE, UIT_PROMPT, UIT_VERIFY,
};

/// `BUFSIZ` — `<stdio.h>` on this platform, as `src/evp/p_legacy.rs` records for
/// `EVP_read_pw_string_min`'s identical local buffer. The authority guards it with
/// `#ifndef BUFSIZ`, so the value is glibc's and not the fallback `256` the file names.
const BUFSIZ: usize = 8192;

/// `struct pem_password_cb_data` — `crypto/ui/ui_util.c:48-51`.
///
/// `cb` is a plain function pointer and not an `Option`, because by the time this struct is
/// readable the wrapper has set it: `UI_UTIL_wrap_read_pem_callback` substitutes
/// `PEM_def_callback` for a NULL argument rather than storing one.
#[repr(C)]
struct PemPasswordCbData {
    /// `pem_password_cb *cb` — the caller's callback, or `PEM_def_callback`.
    cb: PemPasswordCb,
    /// `int rwflag` — passed straight through to `cb`.
    rwflag: c_int,
}

/// `static int ui_method_data_index = -1;` — `crypto/ui/ui_util.c:81`.
///
/// An `AtomicI32` rather than a `static mut`, for the reason the crate gives everywhere it needs
/// addressable mutable storage: the object is written under the `RUN_ONCE` and read by a caller
/// that synchronised on it, so the atomic is the storage and not a claim about locking.
static UI_METHOD_DATA_INDEX: AtomicI32 = AtomicI32::new(-1);

/// `static CRYPTO_ONCE get_index_once = CRYPTO_ONCE_STATIC_INIT;` — the once storage.
static GET_INDEX_ONCE: AtomicI32 = AtomicI32::new(0);

/// `get_index_once_ossl_ret_` — the `RUN_ONCE` macro's cached answer, see the module doc.
static GET_INDEX_ONCE_RET: AtomicI32 = AtomicI32::new(0);

/// `static void ui_new_method_data(...)` — `crypto/ui/ui_util.c:53-60`.
///
/// A no-op `CRYPTO_EX_new`: the data is allocated externally and attached with
/// `UI_method_set_ex_data`, so there is nothing for the constructor to do.
unsafe extern "C" fn ui_new_method_data(
    _parent: *mut c_void,
    _ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
}

/// `static int ui_dup_method_data(...)` — `crypto/ui/ui_util.c:62-71`.
///
/// The `CRYPTO_EX_dup` callback: a duplicated `UI_METHOD` gets its **own** copy of the
/// `pem_password_cb_data`, so freeing one does not free the other's. Answers 0 when the memdup
/// fails, which makes the whole duplication fail rather than leaving two methods sharing a
/// pointer.
unsafe extern "C" fn ui_dup_method_data(
    _to: *mut CryptoExData,
    _from: *const CryptoExData,
    pptr: *mut *mut c_void,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) -> c_int {
    // SAFETY: `pptr` is the slot the ex-data machinery hands a dup callback.
    if !unsafe { *pptr }.is_null() {
        // SAFETY: `*pptr` is the live data this callback is asked to copy.
        let copy = unsafe { CRYPTO_memdup(*pptr, size_of::<PemPasswordCbData>(), ptr::null(), 0) };
        // SAFETY: `pptr` is writable per the callback's contract.
        unsafe { *pptr = copy };
        if !copy.is_null() {
            return 1;
        }
    }
    0
}

/// `static void ui_free_method_data(...)` — `crypto/ui/ui_util.c:73-76`.
///
/// The `CRYPTO_EX_free` callback. `OPENSSL_free` and not a clear-free: the data holds a function
/// pointer and an `int`, not a passphrase.
unsafe extern "C" fn ui_free_method_data(
    _parent: *mut c_void,
    data: *mut c_void,
    _ad: *mut CryptoExData,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    // SAFETY: `data` is the slot's data, allocated by `ui_dup_method_data` or the wrapper.
    unsafe { CRYPTO_free(data, ptr::null(), 0) };
}

/// `DEFINE_RUN_ONCE_STATIC(ui_method_data_index_init)` — the once body,
/// `crypto/ui/ui_util.c:83-89`.
///
/// Reserves the ex-data index on `CRYPTO_EX_INDEX_UI_METHOD` with the three callbacks above, and
/// answers 1 unconditionally: `CRYPTO_get_ex_new_index` answers `-1` only for an invalid class,
/// and the class here is the constant the authority names.
unsafe extern "C" fn ui_method_data_index_init() -> c_int {
    let idx = CRYPTO_get_ex_new_index(
        CRYPTO_EX_INDEX_UI_METHOD,
        0,
        ptr::null_mut(),
        Some(ui_new_method_data),
        Some(ui_dup_method_data),
        Some(ui_free_method_data),
    );
    UI_METHOD_DATA_INDEX.store(idx, Ordering::Release);
    1
}

/// The `RUN_ONCE` macro's wrapper for [`ui_method_data_index_init`]: run the body once, cache its
/// answer, and answer the cache thereafter.
///
/// This is the authority's `init##_ossl_`, generated by `DEFINE_RUN_ONCE_STATIC`.
extern "C" fn get_index_once_body() {
    // SAFETY: the body only calls `CRYPTO_get_ex_new_index`, whose contract is satisfied by the
    // constants and callbacks above.
    let ret = unsafe { ui_method_data_index_init() };
    GET_INDEX_ONCE_RET.store(ret, Ordering::Release);
}

/// `RUN_ONCE(&get_index_once, ui_method_data_index_init)` — `crypto/ui/ui_util.c:154`.
fn run_once_get_index() -> bool {
    // SAFETY: `GET_INDEX_ONCE` is a `CRYPTO_ONCE`-shaped `AtomicI32` at its initial value, and
    // `get_index_once_body` is a valid `extern "C" fn()`.
    let ran = unsafe { CRYPTO_THREAD_run_once(GET_INDEX_ONCE.as_ptr(), Some(get_index_once_body)) };
    ran != 0 && GET_INDEX_ONCE_RET.load(Ordering::Acquire) != 0
}

/// `static int ui_open(UI *ui)` — `crypto/ui/ui_util.c:91-94`.
unsafe extern "C" fn ui_open(_ui: *mut Ui) -> c_int {
    1
}

/// `static int ui_read(UI *ui, UI_STRING *uis)` — `crypto/ui/ui_util.c:95-133`.
///
/// The reader the wrapper installs. Only `UIT_PROMPT` does anything: it asks the stored callback
/// for a password, clamps `maxsize` to `PEM_BUFSIZE` **before** the call so the callback cannot
/// overrun the local buffer, and then hands the answer to `UI_set_result_ex`. The five other
/// string types fall through and answer 1, which is what stops `UI_process` treating an info or
/// error string as a prompt.
///
/// # Safety
/// `ui` and `uis` must be live, and `ui`'s method must be the one
/// [`UI_UTIL_wrap_read_pem_callback`] built -- the ex-data read below is untested for the reason
/// the module doc gives.
unsafe extern "C" fn ui_read(ui: *mut Ui, uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live per the contract.
    match unsafe { UI_get_string_type(uis) } {
        UIT_PROMPT => {
            let mut result = [0 as c_char; PEM_BUFSIZE as usize + 1];
            // SAFETY: `ui` is live and its method is the wrapper's, so the ex-data at the index
            // the once reserved is a `PemPasswordCbData` this file allocated.
            let data = unsafe {
                UI_method_get_ex_data(
                    UI_get_method(ui),
                    UI_METHOD_DATA_INDEX.load(Ordering::Acquire),
                )
                .cast::<PemPasswordCbData>()
            };
            // SAFETY: as above; `data` is non-NULL for the wrapper's method.
            let mut maxsize = unsafe { UI_get_result_maxsize(uis) };
            if maxsize > PEM_BUFSIZE {
                maxsize = PEM_BUFSIZE;
            }
            // SAFETY: `data` is the wrapper's data and `cb` is a live function pointer; the buffer
            // is `maxsize <= PEM_BUFSIZE` bytes as just clamped.
            let len = unsafe {
                ((*data).cb)(
                    result.as_mut_ptr(),
                    maxsize,
                    (*data).rwflag,
                    UI_get0_user_data(ui),
                )
            };
            if len > maxsize {
                return -1;
            }
            if len >= 0 {
                result[len as usize] = 0;
            }
            if len < 0 {
                return len;
            }
            // SAFETY: `ui` and `uis` are live; `result` is NUL-terminated by the line above.
            if unsafe { UI_set_result_ex(ui, uis, result.as_ptr(), len) } >= 0 {
                return 1;
            }
            0
        }
        UIT_VERIFY | UIT_NONE | UIT_BOOLEAN | UIT_INFO | UIT_ERROR => 1,
        _ => 1,
    }
}

/// `static int ui_write(UI *ui, UI_STRING *uis)` — `crypto/ui/ui_util.c:134-137`.
unsafe extern "C" fn ui_write(_ui: *mut Ui, _uis: *mut UiString) -> c_int {
    1
}

/// `static int ui_close(UI *ui)` — `crypto/ui/ui_util.c:138-141`.
unsafe extern "C" fn ui_close(_ui: *mut Ui) -> c_int {
    1
}

/// `int UI_UTIL_read_pw_string(char *buf, int length, const char *prompt, int verify)` —
/// `crypto/ui/ui_util.c:20-31`.
///
/// The wrapper whose only job is the local buffer: it clamps the length to `BUFSIZ`, delegates,
/// and cleanses the buffer it allocated. The cleanse runs whether or not the delegate succeeded,
/// which is the authority's own order.
///
/// # Safety
/// `buf` must be writable for `min(length, BUFSIZ)` bytes; `prompt` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn UI_UTIL_read_pw_string(
    buf: *mut c_char,
    length: c_int,
    prompt: *const c_char,
    verify: c_int,
) -> c_int {
    let mut buff = [0 as c_char; BUFSIZ];
    // SAFETY: `buff` is `BUFSIZ` bytes and the size passed is at most `BUFSIZ`.
    let ret = unsafe {
        UI_UTIL_read_pw(
            buf,
            buff.as_mut_ptr(),
            if length > BUFSIZ as c_int {
                BUFSIZ as c_int
            } else {
                length
            },
            prompt,
            verify,
        )
    };
    // SAFETY: `buff` is the `BUFSIZ`-byte array just allocated.
    unsafe { OPENSSL_cleanse(buff.as_mut_ptr().cast::<c_void>(), BUFSIZ) };
    ret
}

/// `int UI_UTIL_read_pw(char *buf, char *buff, int size, const char *prompt, int verify)` —
/// `crypto/ui/ui_util.c:33-52`.
///
/// `-2` is the "no `UI`" answer and `-1` the "size too small one"; both are the authority's
/// initialisers. `verify` adds the second string with `buf` as its test buffer, which is what makes
/// `UI_process` compare the two.
///
/// # Safety
/// `buf` must be writable for `size - 1` bytes, `buff` likewise when `verify` is non-zero;
/// `prompt` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn UI_UTIL_read_pw(
    buf: *mut c_char,
    buff: *mut c_char,
    size: c_int,
    prompt: *const c_char,
    verify: c_int,
) -> c_int {
    let mut ok: c_int = -2;

    if size < 1 {
        return -1;
    }

    // SAFETY: no preconditions.
    let ui = unsafe { UI_new() };
    if !ui.is_null() {
        // SAFETY: `ui` is live; `buf` is writable for `size - 1` bytes per the contract.
        ok = unsafe { UI_add_input_string(ui, prompt, 0, buf, 0, size - 1) };
        if ok >= 0 && verify != 0 {
            // SAFETY: `ui` is live; `buff` is writable and `buf` is the test buffer.
            ok = unsafe { UI_add_verify_string(ui, prompt, 0, buff, 0, size - 1, buf) };
        }
        if ok >= 0 {
            // SAFETY: `ui` is live and holds the strings just added.
            ok = unsafe { UI_process(ui) };
        }
        // SAFETY: `ui` is live and no longer used.
        unsafe { UI_free(ui) };
    }
    ok
}

/// `UI_METHOD *UI_UTIL_wrap_read_pem_callback(pem_password_cb *cb, int rwflag)` —
/// `crypto/ui/ui_util.c:143-164`.
///
/// Builds a `UI_METHOD` around a legacy callback. The `||` chain is a single failure path in the
/// authority and is one here: any arm that fails destroys the partially built method and frees the
/// data, so a caller never sees a half-initialised wrapper. The ex-data attach is **after** the
/// `RUN_ONCE` for the reason the module doc gives.
///
/// # Safety
/// `cb` must be NULL or a live `pem_password_cb` that stays valid for the method's lifetime.
#[no_mangle]
pub unsafe extern "C" fn UI_UTIL_wrap_read_pem_callback(
    cb: Option<PemPasswordCb>,
    rwflag: c_int,
) -> *mut UiMethod {
    let mut ui_method: *mut UiMethod = ptr::null_mut();

    // SAFETY: the constructor takes a size and the file/line pair; it reads nothing else.
    let data =
        CRYPTO_zalloc(size_of::<PemPasswordCbData>(), ptr::null(), 0).cast::<PemPasswordCbData>();
    let ok = !data.is_null();
    if ok {
        // SAFETY: the literal is readable and NUL-terminated.
        ui_method = unsafe { UI_create_method(c"PEM password callback wrapper".as_ptr()) };
        if ui_method.is_null()
            // SAFETY: `ui_method` is live and each callback has the method's own signature.
            || unsafe {
                UI_method_set_opener(ui_method, Some(ui_open))
                    | UI_method_set_reader(ui_method, Some(ui_read))
                    | UI_method_set_writer(ui_method, Some(ui_write))
                    | UI_method_set_closer(ui_method, Some(ui_close))
            } < 0
            || !run_once_get_index()
            // SAFETY: `ui_method` is live and `data` is the allocation made above.
            || unsafe {
                UI_method_set_ex_data(
                    ui_method,
                    UI_METHOD_DATA_INDEX.load(Ordering::Acquire),
                    data.cast::<c_void>(),
                )
            } == 0
        {
            // SAFETY: both are NULL or live; `UI_destroy_method` accepts NULL.
            unsafe {
                UI_destroy_method(ui_method);
                CRYPTO_free(data.cast::<c_void>(), ptr::null(), 0);
            }
            return ptr::null_mut();
        }
    }

    if data.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `data` is the live allocation made above and not yet handed to anyone else.
    unsafe {
        (*data).rwflag = rwflag;
        (*data).cb = cb.unwrap_or(PEM_def_callback);
    }
    ui_method
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `pem_password_cb` that copies a fixed phrase into the caller's buffer and reports its
    /// length, so a round trip through the wrapper is observable without any interactive read.
    unsafe extern "C" fn fixed_phrase_cb(
        buf: *mut c_char,
        size: c_int,
        _rwflag: c_int,
        _u: *mut c_void,
    ) -> c_int {
        let phrase = b"swordfish";
        if (size as usize) < phrase.len() {
            return -1;
        }
        // SAFETY: `buf` is writable for `size` bytes and `size >= phrase.len()`.
        unsafe { ptr::copy_nonoverlapping(phrase.as_ptr().cast::<c_char>(), buf, phrase.len()) };
        phrase.len() as c_int
    }

    /// The wrapper builds a method with all four callbacks and its data attached at the reserved
    /// index -- the whole of what it promises before anything is read.
    #[test]
    fn the_wrapper_builds_a_method_and_attaches_its_data() {
        // SAFETY: a live callback, and the wrapper's contract is satisfied.
        let method = unsafe { UI_UTIL_wrap_read_pem_callback(Some(fixed_phrase_cb), 0) };
        assert!(!method.is_null());
        // SAFETY: `method` is live.
        let data = unsafe {
            UI_method_get_ex_data(method, UI_METHOD_DATA_INDEX.load(Ordering::Acquire))
                .cast::<PemPasswordCbData>()
        };
        assert!(!data.is_null());
        // SAFETY: `data` is the wrapper's own allocation.
        unsafe {
            assert_eq!((*data).rwflag, 0);
            assert_eq!(
                (*data).cb as *const () as usize,
                fixed_phrase_cb as *const () as usize
            );
        }
        // SAFETY: `method` is live and released exactly once; the ex-data destructor frees `data`.
        unsafe { UI_destroy_method(method) };
    }

    /// A NULL callback is replaced by `PEM_def_callback` rather than stored as NULL, which is what
    /// makes `ui_read`'s untested dereference safe.
    #[test]
    fn a_null_callback_becomes_the_default() {
        // SAFETY: the NULL argument is the case under test.
        let method = unsafe { UI_UTIL_wrap_read_pem_callback(None, 1) };
        assert!(!method.is_null());
        // SAFETY: `method` is live.
        let data = unsafe {
            UI_method_get_ex_data(method, UI_METHOD_DATA_INDEX.load(Ordering::Acquire))
                .cast::<PemPasswordCbData>()
        };
        assert!(!data.is_null());
        // SAFETY: `data` is the wrapper's own allocation.
        unsafe {
            assert_eq!((*data).rwflag, 1);
            assert_eq!(
                (*data).cb as *const () as usize,
                PEM_def_callback as *const () as usize
            );
            UI_destroy_method(method);
        }
    }

    /// `UI_UTIL_read_pw` refuses a size below one **before** building anything, which is the one
    /// observable that needs no UI at all.
    #[test]
    fn read_pw_refuses_a_size_below_one() {
        let mut buf = [0 as c_char; 8];
        // SAFETY: `buf` is writable for 8 bytes; a size of 0 returns before any is touched.
        let ret = unsafe {
            UI_UTIL_read_pw(buf.as_mut_ptr(), buf.as_mut_ptr(), 0, c"prompt".as_ptr(), 0)
        };
        assert_eq!(ret, -1);
    }
}
