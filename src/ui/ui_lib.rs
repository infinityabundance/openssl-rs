//! Phase 13 staging — `crypto/ui/ui_lib.c`: the `UI` program, its `UI_STRING` queue and its
//! `UI_METHOD` vtable.
//!
//! This unit is transcribed **whole** (949 lines, 57 exports) because it is the object layer the
//! password path stands on: `EVP_read_pw_string_min` (`crypto/evp/evp_key.c:52`) is `UI_new`,
//! two `UI_add_*_string` calls, `UI_process` and `UI_free`, and nothing else. It lands here, one
//! stratum before the `pem.h` helpers that call it, because the chain
//! `EVP_read_pw_string_min -> PEM_def_callback -> PEM_do_header -> PEM_ASN1_*` is what opens the
//! PEM hinge; landing the top of the chain alone would be a module no caller could reach.
//!
//! ## The three objects, and which fields are ABI
//!
//! `UI`, `UI_STRING` and `UI_METHOD` are declared in `crypto/ui/ui_local.h:20-107`, an internal
//! header, so the atlas records no body for them and the crate defines them. Callers obtain a
//! `UI` only from `UI_new`/`UI_new_method` and read it only through the accessors below except
//! where they take its address, so the field order is this module's — but it is still written as
//! the authority's, with the offsets asserted by `core::mem::offset_of!`, because
//! `UI_process` reaches *through* `ui->meth` into a table whose layout the `ui_openssl.c` method
//! object shares. The union `_` is the one place the layout is not merely a Rust struct: a
//! `UI_STRING`'s `string_data` and `boolean_data` overlap, and `free_string` reads
//! `boolean_data`'s three pointers only when the type says so.
//!
//! ## The return codes are the contract, and one of them is not a failure
//!
//! Every `UI_add_*`/`UI_dup_*` answers the index of the added string (the `sk_push` return, which
//! is the new count), or a negative value. The `-1` and `-2` differ: `UI_process` answers `-2`
//! when a session was *cancelled* or interrupted — `ui->meth->ui_flush`/`ui_read_string`
//! answering `-1`, or a read with no reader installed — and clears `UI_FLAG_REDOABLE` in that
//! case, while `-1` is an error that leaves the flag alone. `EVP_read_pw_string_min` passes
//! `UI_process`'s answer straight through, so the distinction is observable from the PEM path.
//!
//! ## The raise sites are generated
//!
//! `crypto/ui/ui_lib.c` joins `gen_err_raise_sites.py`'s `COVERED_FILES`, so every `ERR_raise*`
//! below is a `err_sites::UI_LIB_<line>` constant whose file, line, function and `ERR_LIB_UI`
//! value are read from the authority rather than typed. The two `ERR_raise_data` sites
//! (`UI_process`'s `"while %s"` and `UI_set_result_ex`'s `"You must type in %d to %d
//! characters"`) carry their formatted message through `raise_site_data`, as `src/asn1/a_mbstr.rs`
//! does for the same shape.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{memcpy, strchr, strlen};
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_print_errors_cb, ErrPrintCb,
};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_UI, CRYPTO_EX_INDEX_UI_METHOD,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::str::{OPENSSL_strlcat, OPENSSL_strlcpy};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};
use crate::ui::ui_null::UI_null;
use crate::ui::ui_openssl::UI_get_default_method;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ui/ui_lib.c".as_ptr();

/// `UI_METHOD` — `include/openssl/ui.h:294`'s `struct ui_method_st` (`crypto/ui/ui_local.h:20-59`).
///
/// The seven callbacks are `Option<...>`, so a NULL member and an absent callback are the same
/// state, which is how the authority reads them (`if (ui->meth->ui_write_string != NULL)`).
#[repr(C)]
pub struct UiMethod {
    /// `char *name` — owned by the object; `UI_destroy_method` frees it.
    pub(crate) name: *mut c_char,
    /// `int (*ui_open_session)(UI *ui)`.
    pub(crate) ui_open_session: Option<UiOpenSessionFn>,
    /// `int (*ui_write_string)(UI *ui, UI_STRING *uis)`.
    pub(crate) ui_write_string: Option<UiWriteStringFn>,
    /// `int (*ui_flush)(UI *ui)`.
    pub(crate) ui_flush: Option<UiFlushFn>,
    /// `int (*ui_read_string)(UI *ui, UI_STRING *uis)`.
    pub(crate) ui_read_string: Option<UiReadStringFn>,
    /// `int (*ui_close_session)(UI *ui)`.
    pub(crate) ui_close_session: Option<UiCloseSessionFn>,
    /// `void *(*ui_duplicate_data)(UI *ui, void *ui_data)`.
    pub(crate) ui_duplicate_data: Option<UiDuplicateDataFn>,
    /// `void (*ui_destroy_data)(UI *ui, void *ui_data)`.
    pub(crate) ui_destroy_data: Option<UiDestroyDataFn>,
    /// `char *(*ui_construct_prompt)(UI *ui, const char *object_desc, const char *object_name)`.
    pub(crate) ui_construct_prompt: Option<UiConstructPromptFn>,
    /// `CRYPTO_EX_DATA ex_data`.
    pub(crate) ex_data: CryptoExData,
}

/// `int (*)(UI *ui)` — `ui.h`'s `ui_open_session`/`ui_flush`/`ui_close_session`.
pub type UiOpenSessionFn = unsafe extern "C" fn(*mut Ui) -> c_int;
/// `int (*)(UI *ui, UI_STRING *uis)` — `ui.h`'s `ui_write_string`/`ui_read_string`.
pub type UiWriteStringFn = unsafe extern "C" fn(*mut Ui, *mut UiString) -> c_int;
/// `int (*)(UI *ui)` — the flusher.
pub type UiFlushFn = UiOpenSessionFn;
/// `int (*)(UI *ui, UI_STRING *uis)` — the reader.
pub type UiReadStringFn = UiWriteStringFn;
/// `int (*)(UI *ui)` — the closer.
pub type UiCloseSessionFn = UiOpenSessionFn;
/// `void *(*)(UI *ui, void *ui_data)` — the data duplicator.
pub type UiDuplicateDataFn = unsafe extern "C" fn(*mut Ui, *mut c_void) -> *mut c_void;
/// `void (*)(UI *ui, void *ui_data)` — the data destructor.
pub type UiDestroyDataFn = unsafe extern "C" fn(*mut Ui, *mut c_void);
/// `char *(*)(UI *ui, const char *, const char *)` — the prompt constructor.
pub type UiConstructPromptFn =
    unsafe extern "C" fn(*mut Ui, *const c_char, *const c_char) -> *mut c_char;

/// `string_data` — the `UIT_PROMPT`/`UIT_VERIFY` arm of `struct ui_string_st`'s union.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UiStringData {
    /// `int result_minsize` — the minimum the result may be.
    pub(crate) result_minsize: c_int,
    /// `int result_maxsize` — the maximum the result may be.
    pub(crate) result_maxsize: c_int,
    /// `const char *test_buf` — the string a `UIT_VERIFY` result is compared with.
    pub(crate) test_buf: *const c_char,
}

/// `boolean_data` — the `UIT_BOOLEAN` arm of `struct ui_string_st`'s union.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UiBooleanData {
    /// `const char *action_desc` — the yes/no instruction.
    pub(crate) action_desc: *const c_char,
    /// `const char *ok_chars` — the characters that mean "yes"; `[0]` is the stored answer.
    pub(crate) ok_chars: *const c_char,
    /// `const char *cancel_chars` — the characters that mean "no".
    pub(crate) cancel_chars: *const c_char,
}

/// `union { ... } _` — the overlapping `string_data`/`boolean_data` half of a `UI_STRING`.
///
/// The authority declares it as a C union because the object is one type with six
/// `UI_string_types` and only two shapes of payload. Modelling it as a union keeps the struct the
/// authority's size (24 bytes, set by `boolean_data`'s three pointers) and keeps
/// `free_string`'s `switch (uis->type)` the only reader of `boolean_data`.
#[repr(C)]
pub union UiStringPayload {
    /// The `UIT_PROMPT`/`UIT_VERIFY` payload.
    pub string_data: UiStringData,
    /// The `UIT_BOOLEAN` payload.
    pub boolean_data: UiBooleanData,
}

/// `UI_STRING` — `include/openssl/ui.h:294`'s `struct ui_string_st` (`crypto/ui/ui_local.h:61-92`).
#[repr(C)]
pub struct UiString {
    /// `enum UI_string_types type` — the six-way selector the accessors switch on.
    pub(crate) type_: c_int,
    /// `const char *out_string` — the text to print; may be owned when `OUT_STRING_FREEABLE`.
    pub(crate) out_string: *const c_char,
    /// `int input_flags` — the caller's flags, passed to the method's reader.
    pub(crate) input_flags: c_int,
    /// `char *result_buf` — where `UI_set_result_ex` writes the answer.
    pub(crate) result_buf: *mut c_char,
    /// `size_t result_len` — the answer's length, set by `UI_set_result_ex`.
    pub(crate) result_len: usize,
    /// `union { string_data; boolean_data; }` — the payload.
    pub(crate) payload: UiStringPayload,
    /// `int flags` — `OUT_STRING_FREEABLE` or 0.
    pub(crate) flags: c_int,
}

/// `UI` — `include/openssl/ui.h`'s opaque `struct ui_st` (`crypto/ui/ui_local.h:94-107`).
#[repr(C)]
pub struct Ui {
    /// `const UI_METHOD *meth` — the vtable `UI_process` drives.
    pub(crate) meth: *const UiMethod,
    /// `STACK_OF(UI_STRING) *strings` — the queue, `NULL` until the first `UI_add_*`.
    pub(crate) strings: *mut OpenSslStack,
    /// `void *user_data` — the caller's context, passed to the method.
    pub(crate) user_data: *mut c_void,
    /// `CRYPTO_EX_DATA ex_data`.
    pub(crate) ex_data: CryptoExData,
    /// `int flags` — `UI_FLAG_REDOABLE`, `UI_FLAG_DUPL_DATA` and `UI_FLAG_PRINT_ERRORS`.
    pub(crate) flags: c_int,
    /// `CRYPTO_RWLOCK *lock` — held for the length of a console session.
    pub(crate) lock: *mut CryptoRwlock,
}

const _: () = {
    assert!(core::mem::size_of::<UiMethod>() == 88);
    assert!(core::mem::offset_of!(UiMethod, name) == 0);
    assert!(core::mem::offset_of!(UiMethod, ui_open_session) == 8);
    assert!(core::mem::offset_of!(UiMethod, ui_write_string) == 16);
    assert!(core::mem::offset_of!(UiMethod, ui_flush) == 24);
    assert!(core::mem::offset_of!(UiMethod, ui_read_string) == 32);
    assert!(core::mem::offset_of!(UiMethod, ui_close_session) == 40);
    assert!(core::mem::offset_of!(UiMethod, ui_duplicate_data) == 48);
    assert!(core::mem::offset_of!(UiMethod, ui_destroy_data) == 56);
    assert!(core::mem::offset_of!(UiMethod, ui_construct_prompt) == 64);
    assert!(core::mem::offset_of!(UiMethod, ex_data) == 72);

    assert!(core::mem::size_of::<UiString>() == 72);
    assert!(core::mem::offset_of!(UiString, type_) == 0);
    assert!(core::mem::offset_of!(UiString, out_string) == 8);
    assert!(core::mem::offset_of!(UiString, input_flags) == 16);
    assert!(core::mem::offset_of!(UiString, result_buf) == 24);
    assert!(core::mem::offset_of!(UiString, result_len) == 32);
    assert!(core::mem::offset_of!(UiString, payload) == 40);
    assert!(core::mem::offset_of!(UiString, flags) == 64);

    assert!(core::mem::size_of::<Ui>() == 56);
    assert!(core::mem::offset_of!(Ui, meth) == 0);
    assert!(core::mem::offset_of!(Ui, strings) == 8);
    assert!(core::mem::offset_of!(Ui, user_data) == 16);
    assert!(core::mem::offset_of!(Ui, ex_data) == 24);
    assert!(core::mem::offset_of!(Ui, flags) == 40);
    assert!(core::mem::offset_of!(Ui, lock) == 48);
};

// SAFETY: a `UiMethod` is a name pointer, function pointers and a zeroed `CRYPTO_EX_DATA`; the
// one shared instance (`ui_openssl.c`'s `ui_openssl` object) is fully initialised before its
// address is published and is never mutated afterwards. Sharing `&UiMethod` across threads
// therefore introduces no data race, which is what lets `UI_null` keep its object in a non-`mut`
// `static`.
unsafe impl Sync for UiMethod {}

/// `UIT_NONE` — `ui.h:307`. Not a prompt: `UI_write_string` and the accessors ignore it.
pub const UIT_NONE: c_int = 0;
/// `UIT_PROMPT` — a string prompt whose answer `UI_set_result_ex` writes.
pub const UIT_PROMPT: c_int = 1;
/// `UIT_VERIFY` — a prompt read twice and compared.
pub const UIT_VERIFY: c_int = 2;
/// `UIT_BOOLEAN` — a yes/no prompt.
pub const UIT_BOOLEAN: c_int = 3;
/// `UIT_INFO` — informational output.
pub const UIT_INFO: c_int = 4;
/// `UIT_ERROR` — error output.
pub const UIT_ERROR: c_int = 5;

/// `UI_INPUT_FLAG_ECHO` — `ui.h:126`. Passed through to the method's reader; the console method
/// echoes the input when it is set.
pub const UI_INPUT_FLAG_ECHO: c_int = 0x01;

/// `OUT_STRING_FREEABLE` — `ui_local.h:90`. The `out_string` and the `boolean_data` strings are
/// the object's to free.
pub(crate) const OUT_STRING_FREEABLE: c_int = 0x01;

/// `UI_FLAG_REDOABLE` — `ui_local.h:101`. Cleared by `UI_process` on a cancel and by
/// `UI_set_result_ex` on entry; set again by a too-short or too-long result.
pub(crate) const UI_FLAG_REDOABLE: c_int = 0x0001;
/// `UI_FLAG_DUPL_DATA` — `ui_local.h:102`. `user_data` was produced by the method's duplicator
/// and must be released by its destructor.
pub(crate) const UI_FLAG_DUPL_DATA: c_int = 0x0002;
/// `UI_FLAG_PRINT_ERRORS` — `ui_local.h:103`. `UI_process` drains the error queue first.
pub(crate) const UI_FLAG_PRINT_ERRORS: c_int = 0x0100;

/// `UI_CTRL_PRINT_ERRORS` — `ui.h:211`.
const UI_CTRL_PRINT_ERRORS: c_int = 1;
/// `UI_CTRL_IS_REDOABLE` — `ui.h:217`.
const UI_CTRL_IS_REDOABLE: c_int = 2;

/// `UI_new` reads `UI_get_default_method`, which is `ui_openssl.c`'s; a method object's
/// `ui_destroy_data` is called with two arguments and answers nothing.
///
/// `UI_new`'s body is `UI_new_method(NULL)` and nothing else — `crypto/ui/ui_lib.c:18-21`.
///
/// # Safety
///
/// `UI_new` takes no arguments and allocates its own object, so it has no preconditions.
#[no_mangle]
pub unsafe extern "C" fn UI_new() -> *mut Ui {
    // SAFETY: the callee takes no argument it did not allocate.
    unsafe { UI_new_method(ptr::null()) }
}

/// `UI *UI_new_method(const UI_METHOD *method)` — `crypto/ui/ui_lib.c:23-48`.
///
/// The method resolution is a three-step fall-through: the caller's method, else the default
/// method, else `UI_null()`. The lock is taken first and a lock failure raises
/// `ERR_R_CRYPTO_LIB` and frees the half-built object; an `ex_data` failure frees it through
/// `UI_free`, which is why `lock` and `meth` are assigned before `CRYPTO_new_ex_data` runs.
///
/// # Safety
///
/// `method` is NULL or a live `UI_METHOD` that outlives the returned `UI`.
#[no_mangle]
pub unsafe extern "C" fn UI_new_method(method: *const UiMethod) -> *mut Ui {
    // SAFETY: no preconditions.
    let ret = CRYPTO_zalloc(core::mem::size_of::<Ui>(), FILE, LINE_NEW_METHOD_ZALLOC).cast::<Ui>();

    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let lock = CRYPTO_THREAD_lock_new();
    // SAFETY: `ret` is the object just allocated and is ours alone.
    unsafe { (*ret).lock = lock };
    if lock.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_32) };
        // SAFETY: `ret` is ours and fully ours to free (no `ex_data` yet).
        unsafe { CRYPTO_free(ret.cast::<c_void>(), FILE, LINE_NEW_METHOD_FREE) };
        return ptr::null_mut();
    }

    let mut method = method;
    if method.is_null() {
        // SAFETY: no preconditions.
        method = unsafe { UI_get_default_method() };
    }
    if method.is_null() {
        // SAFETY: `UI_null` answers a `'static` object and takes no argument.
        method = UI_null();
    }
    // SAFETY: `ret` is ours; `method` is a live method object.
    unsafe { (*ret).meth = method };

    // SAFETY: `ret` is live and `(*ret).ex_data` is a field of it, zeroed by `CRYPTO_zalloc`.
    if unsafe {
        CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_UI,
            ret.cast::<c_void>(),
            ptr::addr_of_mut!((*ret).ex_data),
        )
    } == 0
    {
        // SAFETY: `ret` is a live object this call created.
        unsafe { UI_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `static void free_string(UI_STRING *uis)` — `crypto/ui/ui_lib.c:50-69`.
///
/// Frees the payload strings only when `OUT_STRING_FREEABLE` is set, and the three
/// `boolean_data` strings only for a `UIT_BOOLEAN`. The `switch` deliberately has no `default`:
/// a type outside the enum frees nothing but the object.
///
/// # Safety
///
/// `uis` is NULL or a heap `UI_STRING` whose owning stack is being torn down.
unsafe extern "C" fn free_string(uis: *mut c_void) {
    let uis = uis.cast::<UiString>();
    if uis.is_null() {
        return;
    }
    // SAFETY: `uis` is a live object.
    if unsafe { (*uis).flags } & OUT_STRING_FREEABLE != 0 {
        // SAFETY: `out_string` is owned when the flag says so.
        unsafe {
            CRYPTO_free(
                (*uis).out_string.cast_mut().cast::<c_void>(),
                FILE,
                LINE_FREE_STRING_OUT,
            )
        };
        // SAFETY: `uis` is live; the type selector decides which union arm is live.
        if unsafe { (*uis).type_ } == UIT_BOOLEAN {
            // SAFETY: a boolean string's three strings are owned with it; copying the arm out of
            // the union is a plain read of three pointers.
            let b = unsafe { (*uis).payload.boolean_data };
            // SAFETY: each is owned by this object.
            unsafe {
                CRYPTO_free(
                    b.action_desc.cast_mut().cast::<c_void>(),
                    FILE,
                    LINE_FREE_STRING_ACTION,
                );
                CRYPTO_free(
                    b.ok_chars.cast_mut().cast::<c_void>(),
                    FILE,
                    LINE_FREE_STRING_OK,
                );
                CRYPTO_free(
                    b.cancel_chars.cast_mut().cast::<c_void>(),
                    FILE,
                    LINE_FREE_STRING_CANCEL,
                );
            }
        }
    }
    // SAFETY: `uis` was allocated by `CRYPTO_zalloc` and is not referenced again.
    unsafe { CRYPTO_free(uis.cast::<c_void>(), FILE, LINE_FREE_STRING_FREE) };
}

/// `void UI_free(UI *ui)` — `crypto/ui/ui_lib.c:71-82`.
///
/// A NULL `ui` is accepted and ignored. The `user_data` is released through the method's
/// destructor only when `UI_add_user_data` marked it duplicated.
///
/// # Safety
///
/// `ui` is NULL or a live object from `UI_new`/`UI_new_method` that is not referenced afterwards.
#[no_mangle]
pub unsafe extern "C" fn UI_free(ui: *mut Ui) {
    if ui.is_null() {
        return;
    }
    // SAFETY: `ui` is live.
    if unsafe { (*ui).flags } & UI_FLAG_DUPL_DATA != 0 {
        // SAFETY: `ui->meth` is a live method (set by `UI_new_method`) and `user_data` is the
        // value the duplicator produced.
        unsafe {
            if let Some(destroy) = (*(*ui).meth).ui_destroy_data {
                destroy(ui, (*ui).user_data);
            }
        }
    }
    // SAFETY: `strings` is NULL or the queue this object owns; `free_string` frees its elements.
    unsafe { OPENSSL_sk_pop_free((*ui).strings, Some(free_string)) };
    // SAFETY: `ui` is live and `ex_data` is its own.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_UI,
            ui.cast::<c_void>(),
            ptr::addr_of_mut!((*ui).ex_data),
        )
    };
    // SAFETY: `lock` was created by `UI_new_method` and is not used again.
    unsafe { CRYPTO_THREAD_lock_free((*ui).lock) };
    // SAFETY: `ui` is the object allocated by `UI_new_method`.
    unsafe { CRYPTO_free(ui.cast::<c_void>(), FILE, LINE_FREE_UI) };
}

/// `static int allocate_string_stack(UI *ui)` — `crypto/ui/ui_lib.c:84-93`.
///
/// Lazily creates the queue; answers `-1` only when the stack cannot be allocated.
///
/// # Safety
///
/// `ui` must be live.
unsafe fn allocate_string_stack(ui: *mut Ui) -> c_int {
    // SAFETY: `ui` is live.
    if unsafe { (*ui).strings }.is_null() {
        // SAFETY: `OPENSSL_sk_new_null` allocates its own object.
        let st = OPENSSL_sk_new_null();
        // SAFETY: `ui` is live and ours.
        unsafe { (*ui).strings = st };
        if st.is_null() {
            return -1;
        }
    }
    0
}

/// `static UI_STRING *general_allocate_prompt(...)` — `crypto/ui/ui_lib.c:95-116`.
///
/// The three-way guard is the whole contract: a NULL prompt raises `ERR_R_PASSED_NULL_PARAMETER`,
/// a prompt type with a NULL `result_buf` raises `UI_R_NO_RESULT_BUFFER`, and otherwise the
/// object is allocated. It answers NULL on every refusal and never otherwise.
///
/// # Safety
///
/// `ui` live; `prompt` NULL or readable; `result_buf` NULL or writable by the caller contract.
unsafe fn general_allocate_prompt(
    ui: *mut Ui,
    prompt: *const c_char,
    prompt_freeable: c_int,
    type_: c_int,
    input_flags: c_int,
    result_buf: *mut c_char,
) -> *mut UiString {
    let mut ret: *mut UiString = ptr::null_mut();

    if prompt.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_103) };
    } else if (type_ == UIT_PROMPT || type_ == UIT_VERIFY || type_ == UIT_BOOLEAN)
        && result_buf.is_null()
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_107) };
    } else {
        // SAFETY: `CRYPTO_zalloc` takes the size, file and line and zeroes its own allocation.
        ret = CRYPTO_zalloc(core::mem::size_of::<UiString>(), FILE, LINE_ALLOCATE_PROMPT)
            .cast::<UiString>();
        if !ret.is_null() {
            // SAFETY: `ret` is the object just allocated and is ours alone.
            unsafe {
                (*ret).out_string = prompt;
                (*ret).flags = if prompt_freeable != 0 {
                    OUT_STRING_FREEABLE
                } else {
                    0
                };
                (*ret).input_flags = input_flags;
                (*ret).type_ = type_;
                (*ret).result_buf = result_buf;
            }
        }
    }
    let _ = ui;
    ret
}

/// `static int general_allocate_string(...)` — `crypto/ui/ui_lib.c:118-143`.
///
/// Pushes a non-boolean string and answers the index, or `-1`. The `ret--` on a failed push is
/// the authority's "adapt `sk_push`'s 0 to -1" and is copied rather than tidied.
///
/// # Safety
///
/// As [`general_allocate_prompt`], plus `test_buf` NULL or a readable NUL-terminated string.
#[allow(clippy::too_many_arguments)]
unsafe fn general_allocate_string(
    ui: *mut Ui,
    prompt: *const c_char,
    prompt_freeable: c_int,
    type_: c_int,
    input_flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
) -> c_int {
    let mut ret: c_int = -1;
    // SAFETY: the caller's contract.
    let s = unsafe {
        general_allocate_prompt(ui, prompt, prompt_freeable, type_, input_flags, result_buf)
    };

    if !s.is_null() {
        // SAFETY: `ui` is live per the contract.
        if unsafe { allocate_string_stack(ui) } >= 0 {
            // SAFETY: `s` is the object just allocated and `ui` is live.
            unsafe {
                (*s).payload.string_data.result_minsize = minsize;
                (*s).payload.string_data.result_maxsize = maxsize;
                (*s).payload.string_data.test_buf = test_buf;
            }
            // SAFETY: `ui->strings` is a live stack and `s` is transferred to it.
            ret = unsafe { OPENSSL_sk_push((*ui).strings, s.cast::<c_void>()) };
            if ret <= 0 {
                ret -= 1;
                // SAFETY: the push did not adopt `s`, so this call still owns it.
                unsafe { free_string(s.cast::<c_void>()) };
            }
        } else {
            // SAFETY: `s` was not adopted by a stack.
            unsafe { free_string(s.cast::<c_void>()) };
        }
    }
    ret
}

/// `static int general_allocate_boolean(...)` — `crypto/ui/ui_lib.c:145-190`.
///
/// The one validation the file does for booleans: `ok_chars` and `cancel_chars` must be non-NULL,
/// and no character may appear in both — a collision raises
/// `UI_R_COMMON_OK_AND_CANCEL_CHARACTERS` but, notably, does **not** refuse: the authority's
/// `for` loop has no `break`, and allocation continues after the raise. The transcription copies
/// that, because a caller that ignores the error queue sees the object either way.
///
/// # Safety
///
/// `ui` live; `ok_chars`/`cancel_chars` NULL or readable NUL-terminated strings (the authority
/// dereferences them without a NULL test once the two NULL guards pass).
#[allow(clippy::too_many_arguments)]
unsafe fn general_allocate_boolean(
    ui: *mut Ui,
    prompt: *const c_char,
    action_desc: *const c_char,
    ok_chars: *const c_char,
    cancel_chars: *const c_char,
    prompt_freeable: c_int,
    type_: c_int,
    input_flags: c_int,
    result_buf: *mut c_char,
) -> c_int {
    let mut ret: c_int = -1;

    if ok_chars.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_159) };
    } else if cancel_chars.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_161) };
    } else {
        let mut p = ok_chars;
        // SAFETY: `ok_chars` is NUL-terminated per the contract.
        while unsafe { *p } != 0 {
            // SAFETY: both strings are readable and NUL-terminated.
            if !unsafe { strchr(cancel_chars, (*p) as c_int) }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::UI_LIB_165) };
            }
            // SAFETY: advancing within the NUL-terminated `ok_chars`.
            p = unsafe { p.add(1) };
        }

        // SAFETY: the caller's contract.
        let s = unsafe {
            general_allocate_prompt(ui, prompt, prompt_freeable, type_, input_flags, result_buf)
        };

        if !s.is_null() {
            // SAFETY: `ui` is live per the contract.
            if unsafe { allocate_string_stack(ui) } >= 0 {
                // SAFETY: `s` is the object just allocated.
                unsafe {
                    (*s).payload.boolean_data.action_desc = action_desc;
                    (*s).payload.boolean_data.ok_chars = ok_chars;
                    (*s).payload.boolean_data.cancel_chars = cancel_chars;
                }
                // SAFETY: `ui->strings` is a live stack and `s` is transferred to it.
                ret = unsafe { OPENSSL_sk_push((*ui).strings, s.cast::<c_void>()) };
                if ret <= 0 {
                    ret -= 1;
                    // SAFETY: the push did not adopt `s`.
                    unsafe { free_string(s.cast::<c_void>()) };
                }
            } else {
                // SAFETY: `s` was not adopted by a stack.
                unsafe { free_string(s.cast::<c_void>()) };
            }
        }
    }
    ret
}

/// `int UI_add_input_string(UI *ui, const char *prompt, int flags, char *result_buf, int minsize,
/// int maxsize)` — `crypto/ui/ui_lib.c:196-202`.
///
/// # Safety
///
/// `ui` live; `prompt` readable; `result_buf` writable for `maxsize` bytes plus a NUL.
#[no_mangle]
pub unsafe extern "C" fn UI_add_input_string(
    ui: *mut Ui,
    prompt: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        general_allocate_string(
            ui,
            prompt,
            0,
            UIT_PROMPT,
            flags,
            result_buf,
            minsize,
            maxsize,
            ptr::null(),
        )
    }
}

/// `int UI_dup_input_string(UI *ui, ...)` — `crypto/ui/ui_lib.c:205-224`.
///
/// The difference from `UI_add_input_string` is the `OPENSSL_strdup` of the prompt and the
/// `prompt_freeable` flag; a failed dup answers **0** here (the `_verify` twin answers `-1`).
///
/// # Safety
///
/// As [`UI_add_input_string`].
#[no_mangle]
pub unsafe extern "C" fn UI_dup_input_string(
    ui: *mut Ui,
    prompt: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
) -> c_int {
    let mut prompt_copy: *mut c_char = ptr::null_mut();

    if !prompt.is_null() {
        // SAFETY: `prompt` is NUL-terminated per the contract.
        prompt_copy = unsafe { CRYPTO_strdup(prompt, FILE, LINE_DUP_INPUT_PROMPT) };
        if prompt_copy.is_null() {
            return 0;
        }
    }

    // SAFETY: the caller's contract; `prompt_copy` is ours.
    let ret = unsafe {
        general_allocate_string(
            ui,
            prompt_copy,
            1,
            UIT_PROMPT,
            flags,
            result_buf,
            minsize,
            maxsize,
            ptr::null(),
        )
    };
    if ret <= 0 {
        // SAFETY: the failed add did not adopt `prompt_copy`.
        unsafe { CRYPTO_free(prompt_copy.cast::<c_void>(), FILE, LINE_DUP_INPUT_FREE) };
    }
    ret
}

/// `int UI_add_verify_string(UI *ui, ..., const char *test_buf)` —
/// `crypto/ui/ui_lib.c:226-233`.
///
/// # Safety
///
/// As [`UI_add_input_string`], plus `test_buf` readable.
#[no_mangle]
pub unsafe extern "C" fn UI_add_verify_string(
    ui: *mut Ui,
    prompt: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        general_allocate_string(
            ui, prompt, 0, UIT_VERIFY, flags, result_buf, minsize, maxsize, test_buf,
        )
    }
}

/// `int UI_dup_verify_string(UI *ui, ..., const char *test_buf)` —
/// `crypto/ui/ui_lib.c:235-254`.
///
/// # Safety
///
/// As [`UI_add_verify_string`].
#[no_mangle]
pub unsafe extern "C" fn UI_dup_verify_string(
    ui: *mut Ui,
    prompt: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
    minsize: c_int,
    maxsize: c_int,
    test_buf: *const c_char,
) -> c_int {
    let mut prompt_copy: *mut c_char = ptr::null_mut();

    if !prompt.is_null() {
        // SAFETY: `prompt` is NUL-terminated per the contract.
        prompt_copy = unsafe { CRYPTO_strdup(prompt, FILE, LINE_DUP_VERIFY_PROMPT) };
        if prompt_copy.is_null() {
            return -1;
        }
    }

    // SAFETY: the caller's contract; `prompt_copy` is ours.
    let ret = unsafe {
        general_allocate_string(
            ui,
            prompt_copy,
            1,
            UIT_VERIFY,
            flags,
            result_buf,
            minsize,
            maxsize,
            test_buf,
        )
    };
    if ret <= 0 {
        // SAFETY: the failed add did not adopt `prompt_copy`.
        unsafe { CRYPTO_free(prompt_copy.cast::<c_void>(), FILE, LINE_DUP_VERIFY_FREE) };
    }
    ret
}

/// `int UI_add_input_boolean(UI *ui, ...)` — `crypto/ui/ui_lib.c:256-263`.
///
/// # Safety
///
/// `ui` live; `prompt`/`action_desc`/`ok_chars`/`cancel_chars` readable; `result_buf` writable
/// for at least one byte.
#[no_mangle]
pub unsafe extern "C" fn UI_add_input_boolean(
    ui: *mut Ui,
    prompt: *const c_char,
    action_desc: *const c_char,
    ok_chars: *const c_char,
    cancel_chars: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        general_allocate_boolean(
            ui,
            prompt,
            action_desc,
            ok_chars,
            cancel_chars,
            0,
            UIT_BOOLEAN,
            flags,
            result_buf,
        )
    }
}

/// `int UI_dup_input_boolean(UI *ui, ...)` — `crypto/ui/ui_lib.c:265-313`.
///
/// Duplicates each of the four strings, and any failed dup jumps to `err:` where all four are
/// freed — including the ones not yet duplicated, which are still NULL and so a no-op.
///
/// # Safety
///
/// As [`UI_add_input_boolean`].
#[no_mangle]
pub unsafe extern "C" fn UI_dup_input_boolean(
    ui: *mut Ui,
    prompt: *const c_char,
    action_desc: *const c_char,
    ok_chars: *const c_char,
    cancel_chars: *const c_char,
    flags: c_int,
    result_buf: *mut c_char,
) -> c_int {
    let mut prompt_copy: *mut c_char = ptr::null_mut();
    let mut action_desc_copy: *mut c_char = ptr::null_mut();
    let mut ok_chars_copy: *mut c_char = ptr::null_mut();
    let mut cancel_chars_copy: *mut c_char = ptr::null_mut();

    if !prompt.is_null() {
        // SAFETY: `prompt` is NUL-terminated per the contract.
        prompt_copy = unsafe { CRYPTO_strdup(prompt, FILE, LINE_DUP_BOOL_PROMPT) };
        if prompt_copy.is_null() {
            // SAFETY: everything copied so far is NULL.
            unsafe {
                dup_bool_err(
                    prompt_copy,
                    action_desc_copy,
                    ok_chars_copy,
                    cancel_chars_copy,
                )
            };
            return -1;
        }
    }
    if !action_desc.is_null() {
        // SAFETY: `action_desc` is NUL-terminated per the contract.
        action_desc_copy = unsafe { CRYPTO_strdup(action_desc, FILE, LINE_DUP_BOOL_ACTION) };
        if action_desc_copy.is_null() {
            // SAFETY: the non-NULL copies are ours and freed here.
            unsafe {
                dup_bool_err(
                    prompt_copy,
                    action_desc_copy,
                    ok_chars_copy,
                    cancel_chars_copy,
                )
            };
            return -1;
        }
    }
    if !ok_chars.is_null() {
        // SAFETY: `ok_chars` is NUL-terminated per the contract.
        ok_chars_copy = unsafe { CRYPTO_strdup(ok_chars, FILE, LINE_DUP_BOOL_OK) };
        if ok_chars_copy.is_null() {
            // SAFETY: the non-NULL copies are ours and freed here.
            unsafe {
                dup_bool_err(
                    prompt_copy,
                    action_desc_copy,
                    ok_chars_copy,
                    cancel_chars_copy,
                )
            };
            return -1;
        }
    }
    if !cancel_chars.is_null() {
        // SAFETY: `cancel_chars` is NUL-terminated per the contract.
        cancel_chars_copy = unsafe { CRYPTO_strdup(cancel_chars, FILE, LINE_DUP_BOOL_CANCEL) };
        if cancel_chars_copy.is_null() {
            // SAFETY: the non-NULL copies are ours and freed here.
            unsafe {
                dup_bool_err(
                    prompt_copy,
                    action_desc_copy,
                    ok_chars_copy,
                    cancel_chars_copy,
                )
            };
            return -1;
        }
    }

    // SAFETY: the caller's contract; the four copies are ours.
    let ret = unsafe {
        general_allocate_boolean(
            ui,
            prompt_copy,
            action_desc_copy,
            ok_chars_copy,
            cancel_chars_copy,
            1,
            UIT_BOOLEAN,
            flags,
            result_buf,
        )
    };
    if ret <= 0 {
        // SAFETY: the failed add did not adopt the four copies.
        unsafe {
            dup_bool_err(
                prompt_copy,
                action_desc_copy,
                ok_chars_copy,
                cancel_chars_copy,
            )
        };
        return -1;
    }
    ret
}

/// `err:` of `UI_dup_input_boolean` — `crypto/ui/ui_lib.c:307-312`. Frees all four copies.
///
/// # Safety
///
/// Each argument is NULL or a string produced by `CRYPTO_strdup`.
unsafe fn dup_bool_err(
    prompt_copy: *mut c_char,
    action_desc_copy: *mut c_char,
    ok_chars_copy: *mut c_char,
    cancel_chars_copy: *mut c_char,
) {
    // SAFETY: each pointer is NULL or ours; `CRYPTO_free` ignores NULL.
    unsafe {
        CRYPTO_free(prompt_copy.cast::<c_void>(), FILE, LINE_DUP_BOOL_ERR);
        CRYPTO_free(action_desc_copy.cast::<c_void>(), FILE, LINE_DUP_BOOL_ERR);
        CRYPTO_free(ok_chars_copy.cast::<c_void>(), FILE, LINE_DUP_BOOL_ERR);
        CRYPTO_free(cancel_chars_copy.cast::<c_void>(), FILE, LINE_DUP_BOOL_ERR);
    }
}

/// `int UI_add_info_string(UI *ui, const char *text)` — `crypto/ui/ui_lib.c:315-319`.
///
/// # Safety
///
/// `ui` live; `text` readable.
#[no_mangle]
pub unsafe extern "C" fn UI_add_info_string(ui: *mut Ui, text: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { general_allocate_string(ui, text, 0, UIT_INFO, 0, ptr::null_mut(), 0, 0, ptr::null()) }
}

/// `int UI_dup_info_string(UI *ui, const char *text)` — `crypto/ui/ui_lib.c:321-337`.
///
/// # Safety
///
/// `ui` live; `text` readable.
#[no_mangle]
pub unsafe extern "C" fn UI_dup_info_string(ui: *mut Ui, text: *const c_char) -> c_int {
    let mut text_copy: *mut c_char = ptr::null_mut();

    if !text.is_null() {
        // SAFETY: `text` is NUL-terminated per the contract.
        text_copy = unsafe { CRYPTO_strdup(text, FILE, LINE_DUP_INFO_PROMPT) };
        if text_copy.is_null() {
            return -1;
        }
    }

    // SAFETY: the caller's contract; `text_copy` is ours.
    let ret = unsafe {
        general_allocate_string(
            ui,
            text_copy,
            1,
            UIT_INFO,
            0,
            ptr::null_mut(),
            0,
            0,
            ptr::null(),
        )
    };
    if ret <= 0 {
        // SAFETY: the failed add did not adopt `text_copy`.
        unsafe { CRYPTO_free(text_copy.cast::<c_void>(), FILE, LINE_DUP_INFO_FREE) };
    }
    ret
}

/// `int UI_add_error_string(UI *ui, const char *text)` — `crypto/ui/ui_lib.c:339-343`.
///
/// # Safety
///
/// `ui` live; `text` readable.
#[no_mangle]
pub unsafe extern "C" fn UI_add_error_string(ui: *mut Ui, text: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        general_allocate_string(
            ui,
            text,
            0,
            UIT_ERROR,
            0,
            ptr::null_mut(),
            0,
            0,
            ptr::null(),
        )
    }
}

/// `int UI_dup_error_string(UI *ui, const char *text)` — `crypto/ui/ui_lib.c:345-361`.
///
/// # Safety
///
/// `ui` live; `text` readable.
#[no_mangle]
pub unsafe extern "C" fn UI_dup_error_string(ui: *mut Ui, text: *const c_char) -> c_int {
    let mut text_copy: *mut c_char = ptr::null_mut();

    if !text.is_null() {
        // SAFETY: `text` is NUL-terminated per the contract.
        text_copy = unsafe { CRYPTO_strdup(text, FILE, LINE_DUP_ERROR_PROMPT) };
        if text_copy.is_null() {
            return -1;
        }
    }

    // SAFETY: the caller's contract; `text_copy` is ours.
    let ret = unsafe {
        general_allocate_string(
            ui,
            text_copy,
            1,
            UIT_ERROR,
            0,
            ptr::null_mut(),
            0,
            0,
            ptr::null(),
        )
    };
    if ret <= 0 {
        // SAFETY: the failed add did not adopt `text_copy`.
        unsafe { CRYPTO_free(text_copy.cast::<c_void>(), FILE, LINE_DUP_ERROR_FREE) };
    }
    ret
}

/// `char *UI_construct_prompt(UI *ui, const char *phrase_desc, const char *object_name)` —
/// `crypto/ui/ui_lib.c:363-394`.
///
/// The method's own constructor wins when present; otherwise the default
/// `"Enter <phrase_desc> for <object_name>:"` is built with `OPENSSL_malloc`,
/// `OPENSSL_strlcpy` and `OPENSSL_strlcat`, and the caller owns it. A NULL `phrase_desc` answers
/// NULL before anything is allocated.
///
/// # Safety
///
/// `ui` NULL or live; `phrase_desc`/`object_name` NULL or readable.
#[no_mangle]
pub unsafe extern "C" fn UI_construct_prompt(
    ui: *mut Ui,
    phrase_desc: *const c_char,
    object_name: *const c_char,
) -> *mut c_char {
    // SAFETY: `ui` is NULL or live; when live, `meth` is a live method object.
    let method_ctor = unsafe {
        if !ui.is_null() && !(*ui).meth.is_null() {
            (*(*ui).meth).ui_construct_prompt
        } else {
            None
        }
    };
    if let Some(ctor) = method_ctor {
        // SAFETY: `ui` is live (the branch required it) and the strings are readable.
        return unsafe { ctor(ui, phrase_desc, object_name) };
    }
    if phrase_desc.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `phrase_desc` is NUL-terminated per the contract.
    let mut len = c"Enter ".to_bytes().len() as c_int + unsafe { strlen(phrase_desc) as c_int };
    if !object_name.is_null() {
        // SAFETY: `object_name` is NUL-terminated per the contract.
        len += c" for ".to_bytes().len() as c_int + unsafe { strlen(object_name) as c_int };
    }
    len += c":".to_bytes().len() as c_int;

    // SAFETY: `CRYPTO_malloc` validates its own allocation.
    let prompt = CRYPTO_malloc((len + 1) as usize, FILE, LINE_CONSTRUCT_PROMPT).cast::<c_char>();
    if prompt.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prompt` is `len + 1` writable bytes and the strings are readable.
    unsafe {
        OPENSSL_strlcpy(prompt, c"Enter ".as_ptr(), (len + 1) as usize);
        OPENSSL_strlcat(prompt, phrase_desc, (len + 1) as usize);
        if !object_name.is_null() {
            OPENSSL_strlcat(prompt, c" for ".as_ptr(), (len + 1) as usize);
            OPENSSL_strlcat(prompt, object_name, (len + 1) as usize);
        }
        OPENSSL_strlcat(prompt, c":".as_ptr(), (len + 1) as usize);
    }
    prompt
}

/// `void *UI_add_user_data(UI *ui, void *user_data)` — `crypto/ui/ui_lib.c:396-407`.
///
/// Returns the previous value. A `UI_FLAG_DUPL_DATA` flag means the old value is the method's to
/// destroy, so the method's destructor runs and NULL is returned instead.
///
/// # Safety
///
/// `ui` live; `user_data` is the caller's and stays valid for the `UI`'s lifetime.
#[no_mangle]
pub unsafe extern "C" fn UI_add_user_data(ui: *mut Ui, user_data: *mut c_void) -> *mut c_void {
    // SAFETY: `ui` is live.
    let mut old_data = unsafe { (*ui).user_data };

    // SAFETY: `ui` is live; `meth` is set by `UI_new_method`.
    if unsafe { (*ui).flags } & UI_FLAG_DUPL_DATA != 0 {
        // SAFETY: the flag says the method duplicated the old value, so its destructor owns it.
        unsafe {
            if let Some(destroy) = (*(*ui).meth).ui_destroy_data {
                destroy(ui, old_data);
            }
        }
        old_data = ptr::null_mut();
    }
    // SAFETY: `ui` is live and ours.
    unsafe {
        (*ui).user_data = user_data;
        (*ui).flags &= !UI_FLAG_DUPL_DATA;
    }
    old_data
}

/// `int UI_dup_user_data(UI *ui, void *user_data)` — `crypto/ui/ui_lib.c:409-429`.
///
/// Requires both a duplicator and a destructor; a NULL duplicate raises `ERR_R_UI_LIB`. The
/// re-stored value goes through `UI_add_user_data` — which clears the flag — and the flag is set
/// again afterwards, so the destructor runs exactly once for this value.
///
/// # Safety
///
/// `ui` live; `user_data` readable as the method's duplicator expects.
#[no_mangle]
pub unsafe extern "C" fn UI_dup_user_data(ui: *mut Ui, user_data: *mut c_void) -> c_int {
    // SAFETY: `ui` is live and `meth` is set.
    let (dup, has_destroy) = unsafe {
        let m = (*ui).meth;
        ((*m).ui_duplicate_data, (*m).ui_destroy_data.is_some())
    };
    if dup.is_none() || !has_destroy {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_415) };
        return -1;
    }

    // SAFETY: the duplicator is present (checked above) and `user_data` is the caller's.
    let duplicate = match dup {
        // SAFETY: the duplicator is present (checked above) and `user_data` is the caller's.
        Some(duplicate) => unsafe { duplicate(ui, user_data) },
        None => ptr::null_mut(),
    };
    if duplicate.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_421) };
        return -1;
    }

    // SAFETY: `ui` is live and the duplicate is the caller's to hand over.
    unsafe { UI_add_user_data(ui, duplicate) };
    // SAFETY: `ui` is live.
    unsafe { (*ui).flags |= UI_FLAG_DUPL_DATA };

    0
}

/// `void *UI_get0_user_data(UI *ui)` — `crypto/ui/ui_lib.c:431-434`.
///
/// # Safety
///
/// `ui` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_user_data(ui: *mut Ui) -> *mut c_void {
    // SAFETY: `ui` is live.
    unsafe { (*ui).user_data }
}

/// `const char *UI_get0_result(UI *ui, int i)` — `crypto/ui/ui_lib.c:436-447`.
///
/// A negative index raises `UI_R_INDEX_TOO_SMALL` and one past the end raises
/// `UI_R_INDEX_TOO_LARGE`; both answer NULL. A valid index is the string form of the result.
///
/// # Safety
///
/// `ui` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_result(ui: *mut Ui, i: c_int) -> *const c_char {
    if i < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_439) };
        return ptr::null();
    }
    // SAFETY: `ui` is live and `strings` is NULL or a live stack.
    if i >= unsafe { OPENSSL_sk_num((*ui).strings) } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_443) };
        return ptr::null();
    }
    // SAFETY: `i` is a valid index into `ui->strings`.
    let uis = unsafe { OPENSSL_sk_value((*ui).strings, i) }.cast::<UiString>();
    // SAFETY: `uis` is a live queue element.
    unsafe { UI_get0_result_string(uis) }
}

/// `int UI_get_result_length(UI *ui, int i)` — `crypto/ui/ui_lib.c:449-460`.
///
/// The `int` twin of [`UI_get0_result`], with the same two raise sites and `-1` as its refusal.
///
/// # Safety
///
/// `ui` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_result_length(ui: *mut Ui, i: c_int) -> c_int {
    if i < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_452) };
        return -1;
    }
    // SAFETY: `ui` is live and `strings` is NULL or a live stack.
    if i >= unsafe { OPENSSL_sk_num((*ui).strings) } {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_456) };
        return -1;
    }
    // SAFETY: `i` is a valid index into `ui->strings`.
    let uis = unsafe { OPENSSL_sk_value((*ui).strings, i) }.cast::<UiString>();
    // SAFETY: `uis` is a live queue element.
    unsafe { UI_get_result_string_length(uis) }
}

/// `static int print_error(const char *str, size_t len, UI *ui)` —
/// `crypto/ui/ui_lib.c:462-474`.
///
/// The `ERR_print_errors_cb` callback `UI_process` installs. The authority casts a
/// three-argument function to the callback type, so the signature is written as the callback's
/// here; `ui` is the `void *` the callback receives and `len` is unused.
///
/// # Safety
///
/// `str_` NULL or a readable `len`-byte string; `ui` is the live `UI` the callback was given.
unsafe extern "C" fn print_error(str_: *const c_char, _len: usize, ui: *mut c_void) -> c_int {
    let ui = ui.cast::<Ui>();
    // SAFETY: the all-zero `UI_STRING` is a valid value (a zeroed pointer, zeroed union and a
    // zeroed int), which is what the authority's `memset` produces.
    let mut uis: UiString = unsafe { core::mem::zeroed() };
    uis.type_ = UIT_ERROR;
    uis.out_string = str_;

    // SAFETY: `ui` is the live object the callback was handed; `meth` is set.
    let writer = unsafe { (*(*ui).meth).ui_write_string };
    if let Some(write) = writer {
        // SAFETY: `ui` and `uis` are live.
        if unsafe { write(ui, &mut uis) } <= 0 {
            return -1;
        }
    }
    0
}

/// `int UI_process(UI *ui)` — `crypto/ui/ui_lib.c:476-555`.
///
/// The five phases in order: open, drain the error queue when asked, write every string, flush,
/// read every string, close. The answers `0`, `-1` and `-2` are three different states — see the
/// module doc — and the `state` string that names the failing phase is what the final
/// `ERR_raise_data` interpolates. `UI_FLAG_REDOABLE` is cleared by either `-1` arm of the flush
/// and the read.
///
/// # Safety
///
/// `ui` is a live object whose method table may be driven, which for the default method means
/// the process's controlling terminal.
#[no_mangle]
pub unsafe extern "C" fn UI_process(ui: *mut Ui) -> c_int {
    let mut ok: c_int = 0;
    let mut state: *const c_char = c"processing".as_ptr();

    // SAFETY: `ui` is live and `meth` is set by `UI_new_method`.
    let opener = unsafe { (*(*ui).meth).ui_open_session };
    if let Some(open) = opener {
        // SAFETY: `ui` is live.
        if unsafe { open(ui) } <= 0 {
            state = c"opening session".as_ptr();
            ok = -1;
            // SAFETY: `ui` is live and `state` is a static string.
            return unsafe { ui_process_err(ui, ok, state) };
        }
    }

    // SAFETY: `ui` is live.
    if unsafe { (*ui).flags } & UI_FLAG_PRINT_ERRORS != 0 {
        let cb: Option<ErrPrintCb> = Some(print_error);
        // SAFETY: `print_error` matches `ErrPrintCb` and `ui` is the context it expects.
        unsafe { ERR_print_errors_cb(cb, ui.cast::<c_void>()) };
    }

    let mut i: c_int = 0;
    // SAFETY: `ui` is live; `strings` is NULL or a live stack.
    while i < unsafe { OPENSSL_sk_num((*ui).strings) } {
        // SAFETY: `ui` is live; `meth` is set.
        let writer = unsafe { (*(*ui).meth).ui_write_string };
        if let Some(write) = writer {
            // SAFETY: `i` is a valid index into `ui->strings`.
            let uis = unsafe { OPENSSL_sk_value((*ui).strings, i) }.cast::<UiString>();
            // SAFETY: `ui` and `uis` are live.
            if unsafe { write(ui, uis) } <= 0 {
                state = c"writing strings".as_ptr();
                ok = -1;
                // SAFETY: `ui` is live and `state` is a static string.
                return unsafe { ui_process_err(ui, ok, state) };
            }
        }
        i += 1;
    }

    // SAFETY: `ui` is live; `meth` is set.
    let flusher = unsafe { (*(*ui).meth).ui_flush };
    if let Some(flush) = flusher {
        // SAFETY: `ui` is live.
        let r = unsafe { flush(ui) };
        if r == -1 {
            // SAFETY: `ui` is live.
            unsafe { (*ui).flags &= !UI_FLAG_REDOABLE };
            ok = -2;
            // SAFETY: `ui` is live and `state` is a static string.
            return unsafe { ui_process_err(ui, ok, state) };
        } else if r == 0 {
            state = c"flushing".as_ptr();
            ok = -1;
            // SAFETY: `ui` is live and `state` is a static string.
            return unsafe { ui_process_err(ui, ok, state) };
        }
        ok = 0;
    }

    i = 0;
    // SAFETY: `ui` is live; `strings` is NULL or a live stack.
    while i < unsafe { OPENSSL_sk_num((*ui).strings) } {
        // SAFETY: `ui` is live; `meth` is set.
        let reader = unsafe { (*(*ui).meth).ui_read_string };
        if let Some(read) = reader {
            // SAFETY: `i` is a valid index into `ui->strings`.
            let uis = unsafe { OPENSSL_sk_value((*ui).strings, i) }.cast::<UiString>();
            // SAFETY: `ui` and `uis` are live.
            match unsafe { read(ui, uis) } {
                -1 => {
                    // SAFETY: `ui` is live.
                    unsafe { (*ui).flags &= !UI_FLAG_REDOABLE };
                    ok = -2;
                    // SAFETY: `ui` is live and `state` is a static string.
                    return unsafe { ui_process_err(ui, ok, state) };
                }
                0 => {
                    state = c"reading strings".as_ptr();
                    ok = -1;
                    // SAFETY: `ui` is live and `state` is a static string.
                    return unsafe { ui_process_err(ui, ok, state) };
                }
                _ => ok = 0,
            }
        } else {
            // SAFETY: `ui` is live.
            unsafe { (*ui).flags &= !UI_FLAG_REDOABLE };
            ok = -2;
            // SAFETY: `ui` is live and `state` is a static string.
            return unsafe { ui_process_err(ui, ok, state) };
        }
        i += 1;
    }

    state = ptr::null();
    // SAFETY: `ui` is live for the whole call.
    unsafe { ui_process_err(ui, ok, state) }
}

/// `err:` of `UI_process` — `crypto/ui/ui_lib.c:544-554`.
///
/// Closes the session, which may downgrade a `0` to a `-1`; then raises
/// `UI_R_PROCESSING_ERROR` with the phase name when the answer is `-1`. `state` is non-NULL on
/// every `-1` path, which is what makes the `%s` well-defined.
///
/// # Safety
///
/// `ui` live; `state` is NULL or a NUL-terminated static string.
unsafe fn ui_process_err(ui: *mut Ui, mut ok: c_int, mut state: *const c_char) -> c_int {
    // SAFETY: `ui` is live; `meth` is set.
    let closer = unsafe { (*(*ui).meth).ui_close_session };
    if let Some(close) = closer {
        // SAFETY: `ui` is live.
        if unsafe { close(ui) } <= 0 {
            if state.is_null() {
                state = c"closing session".as_ptr();
            }
            ok = -1;
        }
    }

    if ok == -1 {
        let mut msg = [0 as c_char; 48];
        // SAFETY: `msg` is a 48-byte buffer; the format and argument match.
        unsafe { BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"while %s".as_ptr(), state) };
        // SAFETY: the site is a compile-time constant and `msg` is NUL-terminated.
        unsafe { raise_site_data(&err_sites::UI_LIB_553, msg.as_ptr()) };
    }
    ok
}

/// `int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void))` —
/// `crypto/ui/ui_lib.c:557-579`.
///
/// Two commands are implemented; the third branch raises `UI_R_UNKNOWN_CONTROL_COMMAND` and
/// answers `-1`. `UI_CTRL_PRINT_ERRORS` **returns the previous state** rather than 0, which is
/// why its return is compared against 1 and 0 rather than truthiness.
///
/// # Safety
///
/// `ui` NULL or live; `p`/`f` are unused by both commands.
#[no_mangle]
pub unsafe extern "C" fn UI_ctrl(
    ui: *mut Ui,
    cmd: c_int,
    i: c_long,
    _p: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    if ui.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::UI_LIB_560) };
        return -1;
    }
    match cmd {
        UI_CTRL_PRINT_ERRORS => {
            // SAFETY: `ui` is live.
            let save_flag = c_int::from(unsafe { (*ui).flags } & UI_FLAG_PRINT_ERRORS != 0);
            // SAFETY: `ui` is live.
            unsafe {
                if i != 0 {
                    (*ui).flags |= UI_FLAG_PRINT_ERRORS;
                } else {
                    (*ui).flags &= !UI_FLAG_PRINT_ERRORS;
                }
            }
            return save_flag;
        }
        UI_CTRL_IS_REDOABLE => {
            // SAFETY: `ui` is live.
            return c_int::from(unsafe { (*ui).flags } & UI_FLAG_REDOABLE != 0);
        }
        _ => {}
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_site(&err_sites::UI_LIB_577) };
    -1
}

/// `int UI_set_ex_data(UI *r, int idx, void *arg)` — `crypto/ui/ui_lib.c:581-584`.
///
/// # Safety
///
/// `r` live and `idx` a registered index.
#[no_mangle]
pub unsafe extern "C" fn UI_set_ex_data(r: *mut Ui, idx: c_int, arg: *mut c_void) -> c_int {
    // SAFETY: `r` is live per the contract; `ex_data` is its own.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*r).ex_data), idx, arg) }
}

/// `void *UI_get_ex_data(const UI *r, int idx)` — `crypto/ui/ui_lib.c:586-589`.
///
/// # Safety
///
/// `r` live and `idx` a registered index.
#[no_mangle]
pub unsafe extern "C" fn UI_get_ex_data(r: *const Ui, idx: c_int) -> *mut c_void {
    // SAFETY: `r` is live per the contract; `ex_data` is its own.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*r).ex_data), idx) }
}

/// `const UI_METHOD *UI_get_method(UI *ui)` — `crypto/ui/ui_lib.c:591-594`.
///
/// # Safety
///
/// `ui` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_method(ui: *mut Ui) -> *const UiMethod {
    // SAFETY: `ui` is live.
    unsafe { (*ui).meth }
}

/// `const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth)` —
/// `crypto/ui/ui_lib.c:596-600`.
///
/// # Safety
///
/// `ui` live; `meth` a live method that outlives the `UI`.
#[no_mangle]
pub unsafe extern "C" fn UI_set_method(ui: *mut Ui, meth: *const UiMethod) -> *const UiMethod {
    // SAFETY: `ui` is live and ours.
    unsafe { (*ui).meth = meth };
    // SAFETY: `ui` is live.
    unsafe { (*ui).meth }
}

/// `UI_METHOD *UI_create_method(const char *name)` — `crypto/ui/ui_lib.c:602-624`.
///
/// Allocates a zeroed method, dups the name and registers its `ex_data`. The refusal path frees
/// the name only when it was allocated (`ui_method->name != NULL`), which distinguishes the
/// `ex_data` failure — which raises `ERR_R_CRYPTO_LIB` — from the two allocation failures.
///
/// # Safety
///
/// `name` must be a readable NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn UI_create_method(name: *const c_char) -> *mut UiMethod {
    // SAFETY: `CRYPTO_zalloc` validates its own allocation.
    let ui_method = CRYPTO_zalloc(
        core::mem::size_of::<UiMethod>(),
        FILE,
        LINE_CREATE_METHOD_ZALLOC,
    )
    .cast::<UiMethod>();

    // SAFETY: `ui_method` is NULL or ours; `name` is NUL-terminated per the contract.
    let name_copy = if ui_method.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `name` is NUL-terminated per the contract.
        unsafe { CRYPTO_strdup(name, FILE, LINE_CREATE_METHOD_DUP) }
    };

    // SAFETY: `ui_method` is ours when non-NULL; the field assignment is ours to make.
    let ex_ok = if !ui_method.is_null() && !name_copy.is_null() {
        // SAFETY: `ui_method` is ours and `name_copy` is the dup just made.
        unsafe {
            (*ui_method).name = name_copy;
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_UI_METHOD,
                ui_method.cast::<c_void>(),
                ptr::addr_of_mut!((*ui_method).ex_data),
            ) != 0
        }
    } else {
        false
    };

    if ui_method.is_null() || name_copy.is_null() || !ex_ok {
        if !ui_method.is_null() {
            // SAFETY: `ui_method` is ours; `name` is non-NULL exactly on the `ex_data` failure.
            if !unsafe { (*ui_method).name }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::UI_LIB_617) };
            }
            // SAFETY: the name is ours and was allocated by `CRYPTO_strdup`.
            unsafe {
                CRYPTO_free(
                    (*ui_method).name.cast::<c_void>(),
                    FILE,
                    LINE_CREATE_METHOD_FREE_NAME,
                )
            };
        }
        // SAFETY: `ui_method` is NULL or ours.
        unsafe { CRYPTO_free(ui_method.cast::<c_void>(), FILE, LINE_CREATE_METHOD_FREE) };
        return ptr::null_mut();
    }
    ui_method
}

/// `void UI_destroy_method(UI_METHOD *ui_method)` — `crypto/ui/ui_lib.c:631-640`.
///
/// The authority's warning — *do not* use this on a statically allocated method — is part of the
/// contract: the object and its name are freed unconditionally. A NULL `ui_method` is ignored.
///
/// # Safety
///
/// `ui_method` is NULL or a heap object from `UI_create_method`.
#[no_mangle]
pub unsafe extern "C" fn UI_destroy_method(ui_method: *mut UiMethod) {
    if ui_method.is_null() {
        return;
    }
    // SAFETY: `ui_method` is ours and `ex_data` is its own.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_UI_METHOD,
            ui_method.cast::<c_void>(),
            ptr::addr_of_mut!((*ui_method).ex_data),
        )
    };
    // SAFETY: the name was allocated by `CRYPTO_strdup` (or is NULL).
    unsafe {
        CRYPTO_free(
            (*ui_method).name.cast::<c_void>(),
            FILE,
            LINE_DESTROY_METHOD_NAME,
        )
    };
    // SAFETY: `ui_method` is ours.
    unsafe { (*ui_method).name = ptr::null_mut() };
    // SAFETY: `ui_method` is the heap object.
    unsafe { CRYPTO_free(ui_method.cast::<c_void>(), FILE, LINE_DESTROY_METHOD) };
}

/// `int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui))` —
/// `crypto/ui/ui_lib.c:642-649`.
///
/// # Safety
///
/// `method` NULL or live; `open` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_opener(
    method: *mut UiMethod,
    open: Option<UiOpenSessionFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_open_session = open };
        return 0;
    }
    -1
}

/// `int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis))` —
/// `crypto/ui/ui_lib.c:651-659`.
///
/// # Safety
///
/// `method` NULL or live; `write` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_writer(
    method: *mut UiMethod,
    write: Option<UiWriteStringFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_write_string = write };
        return 0;
    }
    -1
}

/// `int UI_method_set_flusher(UI_METHOD *method, int (*flusher)(UI *ui))` —
/// `crypto/ui/ui_lib.c:661-668`.
///
/// # Safety
///
/// `method` NULL or live; `flush` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_flusher(
    method: *mut UiMethod,
    flush: Option<UiFlushFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_flush = flush };
        return 0;
    }
    -1
}

/// `int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis))` —
/// `crypto/ui/ui_lib.c:670-678`.
///
/// # Safety
///
/// `method` NULL or live; `read` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_reader(
    method: *mut UiMethod,
    read: Option<UiReadStringFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_read_string = read };
        return 0;
    }
    -1
}

/// `int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui))` —
/// `crypto/ui/ui_lib.c:680-687`.
///
/// # Safety
///
/// `method` NULL or live; `close` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_closer(
    method: *mut UiMethod,
    close: Option<UiCloseSessionFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_close_session = close };
        return 0;
    }
    -1
}

/// `int UI_method_set_data_duplicator(UI_METHOD *method, void *(*duplicator)(UI *ui, void
/// *ui_data), void (*destructor)(UI *ui, void *ui_data))` — `crypto/ui/ui_lib.c:689-699`.
///
/// Sets both callbacks at once: `UI_dup_user_data` requires the pair, so a method that could set
/// only one would be a half-configured object.
///
/// # Safety
///
/// `method` NULL or live; `duplicator`/`destructor` callbacks the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_data_duplicator(
    method: *mut UiMethod,
    duplicator: Option<UiDuplicateDataFn>,
    destructor: Option<UiDestroyDataFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe {
            (*method).ui_duplicate_data = duplicator;
            (*method).ui_destroy_data = destructor;
        }
        return 0;
    }
    -1
}

/// `int UI_method_set_prompt_constructor(UI_METHOD *method, char *(*prompt_constructor)(UI *ui,
/// const char *, const char *))` — `crypto/ui/ui_lib.c:701-711`.
///
/// # Safety
///
/// `method` NULL or live; `ctor` a callback the method may call.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_prompt_constructor(
    method: *mut UiMethod,
    ctor: Option<UiConstructPromptFn>,
) -> c_int {
    if !method.is_null() {
        // SAFETY: `method` is live and ours.
        unsafe { (*method).ui_construct_prompt = ctor };
        return 0;
    }
    -1
}

/// `int UI_method_set_ex_data(UI_METHOD *method, int idx, void *data)` —
/// `crypto/ui/ui_lib.c:713-716`.
///
/// # Safety
///
/// `method` live and `idx` a registered `CRYPTO_EX_INDEX_UI_METHOD` index.
#[no_mangle]
pub unsafe extern "C" fn UI_method_set_ex_data(
    method: *mut UiMethod,
    idx: c_int,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `method` is live per the contract; `ex_data` is its own.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*method).ex_data), idx, data) }
}

/// `int (*UI_method_get_opener(const UI_METHOD *method))(UI *)` —
/// `crypto/ui/ui_lib.c:718-723`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_opener(method: *const UiMethod) -> Option<UiOpenSessionFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_open_session };
    }
    None
}

/// `int (*UI_method_get_writer(const UI_METHOD *method))(UI *, UI_STRING *)` —
/// `crypto/ui/ui_lib.c:725-730`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_writer(method: *const UiMethod) -> Option<UiWriteStringFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_write_string };
    }
    None
}

/// `int (*UI_method_get_flusher(const UI_METHOD *method))(UI *)` —
/// `crypto/ui/ui_lib.c:732-737`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_flusher(method: *const UiMethod) -> Option<UiFlushFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_flush };
    }
    None
}

/// `int (*UI_method_get_reader(const UI_METHOD *method))(UI *, UI_STRING *)` —
/// `crypto/ui/ui_lib.c:739-744`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_reader(method: *const UiMethod) -> Option<UiReadStringFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_read_string };
    }
    None
}

/// `int (*UI_method_get_closer(const UI_METHOD *method))(UI *)` —
/// `crypto/ui/ui_lib.c:746-751`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_closer(method: *const UiMethod) -> Option<UiCloseSessionFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_close_session };
    }
    None
}

/// `char *(*UI_method_get_prompt_constructor(const UI_METHOD *method))(UI *, const char *, const
/// char *)` — `crypto/ui/ui_lib.c:753-758`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_prompt_constructor(
    method: *const UiMethod,
) -> Option<UiConstructPromptFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_construct_prompt };
    }
    None
}

/// `void *(*UI_method_get_data_duplicator(const UI_METHOD *method))(UI *, void *)` —
/// `crypto/ui/ui_lib.c:760-765`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_data_duplicator(
    method: *const UiMethod,
) -> Option<UiDuplicateDataFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_duplicate_data };
    }
    None
}

/// `void (*UI_method_get_data_destructor(const UI_METHOD *method))(UI *, void *)` —
/// `crypto/ui/ui_lib.c:767-772`.
///
/// # Safety
///
/// `method` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_data_destructor(
    method: *const UiMethod,
) -> Option<UiDestroyDataFn> {
    if !method.is_null() {
        // SAFETY: `method` is live per the contract.
        return unsafe { (*method).ui_destroy_data };
    }
    None
}

/// `const void *UI_method_get_ex_data(const UI_METHOD *method, int idx)` —
/// `crypto/ui/ui_lib.c:774-777`.
///
/// # Safety
///
/// `method` live and `idx` a registered index.
#[no_mangle]
pub unsafe extern "C" fn UI_method_get_ex_data(
    method: *const UiMethod,
    idx: c_int,
) -> *const c_void {
    // SAFETY: `method` is live per the contract; `ex_data` is its own.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*method).ex_data), idx).cast_const() }
}

/// `enum UI_string_types UI_get_string_type(UI_STRING *uis)` — `crypto/ui/ui_lib.c:779-782`.
///
/// The return type is the authority's `enum UI_string_types`, which the ABI makes an `int`.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_string_type(uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live.
    unsafe { (*uis).type_ }
}

/// `int UI_get_input_flags(UI_STRING *uis)` — `crypto/ui/ui_lib.c:784-787`.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_input_flags(uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live.
    unsafe { (*uis).input_flags }
}

/// `const char *UI_get0_output_string(UI_STRING *uis)` — `crypto/ui/ui_lib.c:789-792`.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_output_string(uis: *mut UiString) -> *const c_char {
    // SAFETY: `uis` is live.
    unsafe { (*uis).out_string }
}

/// `const char *UI_get0_action_string(UI_STRING *uis)` — `crypto/ui/ui_lib.c:794-807`.
///
/// Only a `UIT_BOOLEAN` has one; every other type answers NULL.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_action_string(uis: *mut UiString) -> *const c_char {
    // SAFETY: `uis` is live.
    if unsafe { (*uis).type_ } == UIT_BOOLEAN {
        // SAFETY: a boolean string's payload is `boolean_data`.
        return unsafe { (*uis).payload.boolean_data.action_desc };
    }
    ptr::null()
}

/// `const char *UI_get0_result_string(UI_STRING *uis)` — `crypto/ui/ui_lib.c:809-822`.
///
/// Only `UIT_PROMPT` and `UIT_VERIFY` hold a result.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_result_string(uis: *mut UiString) -> *const c_char {
    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        // SAFETY: `uis` is live and the result buffer is the caller's.
        UIT_PROMPT | UIT_VERIFY => unsafe { (*uis).result_buf.cast_const() },
        _ => ptr::null(),
    }
}

/// `int UI_get_result_string_length(UI_STRING *uis)` — `crypto/ui/ui_lib.c:824-837`.
///
/// `-1` for every type that has no result, including `UIT_BOOLEAN`, whose answer is a single
/// byte stored in `result_buf[0]` rather than a string.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_result_string_length(uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        // SAFETY: `uis` is live.
        UIT_PROMPT | UIT_VERIFY => unsafe { (*uis).result_len as c_int },
        _ => -1,
    }
}

/// `const char *UI_get0_test_string(UI_STRING *uis)` — `crypto/ui/ui_lib.c:839-852`.
///
/// The verify-only companion to [`UI_get0_result_string`].
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get0_test_string(uis: *mut UiString) -> *const c_char {
    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        // SAFETY: a verify string's payload is `string_data`.
        UIT_VERIFY => unsafe { (*uis).payload.string_data.test_buf },
        _ => ptr::null(),
    }
}

/// `int UI_get_result_minsize(UI_STRING *uis)` — `crypto/ui/ui_lib.c:854-867`.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_result_minsize(uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        // SAFETY: a prompt/verify string's payload is `string_data`.
        UIT_PROMPT | UIT_VERIFY => unsafe { (*uis).payload.string_data.result_minsize },
        _ => -1,
    }
}

/// `int UI_get_result_maxsize(UI_STRING *uis)` — `crypto/ui/ui_lib.c:869-882`.
///
/// # Safety
///
/// `uis` live.
#[no_mangle]
pub unsafe extern "C" fn UI_get_result_maxsize(uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        // SAFETY: a prompt/verify string's payload is `string_data`.
        UIT_PROMPT | UIT_VERIFY => unsafe { (*uis).payload.string_data.result_maxsize },
        _ => -1,
    }
}

/// `int UI_set_result(UI *ui, UI_STRING *uis, const char *result)` —
/// `crypto/ui/ui_lib.c:884-887`.
///
/// # Safety
///
/// `ui`/`uis` live; `result` a readable NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn UI_set_result(
    ui: *mut Ui,
    uis: *mut UiString,
    result: *const c_char,
) -> c_int {
    // SAFETY: `result` is NUL-terminated per the contract.
    let len = unsafe { strlen(result) } as c_int;
    // SAFETY: the caller's contract.
    unsafe { UI_set_result_ex(ui, uis, result, len) }
}

/// `int UI_set_result_ex(UI *ui, UI_STRING *uis, const char *result, int len)` —
/// `crypto/ui/ui_lib.c:889-949`.
///
/// Clears `UI_FLAG_REDOABLE` on entry, then branches on the string type. A result outside
/// `[result_minsize, result_maxsize]` re-sets the flag and raises with the two bounds in the
/// message; a NULL `result_buf` raises `UI_R_NO_RESULT_BUFFER`. The `UIT_BOOLEAN` arm takes the
/// **first** character that appears in `ok_chars` or `cancel_chars`, storing that string's own
/// first character — so the answer is normalised to the canonical yes/no byte. It falls through
/// to the `UIT_NONE` arm, which is a `break`.
///
/// # Safety
///
/// `ui`/`uis` live; `result` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn UI_set_result_ex(
    ui: *mut Ui,
    uis: *mut UiString,
    result: *const c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `ui` is live.
    unsafe { (*ui).flags &= !UI_FLAG_REDOABLE };

    // SAFETY: `uis` is live.
    match unsafe { (*uis).type_ } {
        UIT_PROMPT | UIT_VERIFY => {
            // SAFETY: `uis` is live; the payload is `string_data` for these two types.
            let (minsize, maxsize) = unsafe {
                (
                    (*uis).payload.string_data.result_minsize,
                    (*uis).payload.string_data.result_maxsize,
                )
            };
            if len < minsize {
                // SAFETY: `ui` is live.
                unsafe { (*ui).flags |= UI_FLAG_REDOABLE };
                let mut msg = [0 as c_char; 64];
                // SAFETY: `msg` is a 64-byte buffer and the format and arguments match.
                unsafe {
                    BIO_snprintf(
                        msg.as_mut_ptr(),
                        msg.len(),
                        c"You must type in %d to %d characters".as_ptr(),
                        minsize,
                        maxsize,
                    )
                };
                // SAFETY: the site is a compile-time constant and `msg` is NUL-terminated.
                unsafe { raise_site_data(&err_sites::UI_LIB_898, msg.as_ptr()) };
                return -1;
            }
            if len > maxsize {
                // SAFETY: `ui` is live.
                unsafe { (*ui).flags |= UI_FLAG_REDOABLE };
                let mut msg = [0 as c_char; 64];
                // SAFETY: `msg` is a 64-byte buffer and the format and arguments match.
                unsafe {
                    BIO_snprintf(
                        msg.as_mut_ptr(),
                        msg.len(),
                        c"You must type in %d to %d characters".as_ptr(),
                        minsize,
                        maxsize,
                    )
                };
                // SAFETY: the site is a compile-time constant and `msg` is NUL-terminated.
                unsafe { raise_site_data(&err_sites::UI_LIB_906, msg.as_ptr()) };
                return -1;
            }

            // SAFETY: `uis` is live.
            if unsafe { (*uis).result_buf }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::UI_LIB_914) };
                return -1;
            }

            // SAFETY: `result` is `len` readable bytes and `result_buf` is writable for
            // `maxsize` bytes plus a NUL, per the caller's contract.
            unsafe {
                memcpy(
                    (*uis).result_buf.cast::<c_void>(),
                    result.cast::<c_void>(),
                    len as usize,
                )
            };
            if len <= maxsize {
                // SAFETY: the contract gives `result_buf` room for the terminator.
                unsafe { *(*uis).result_buf.add(len as usize) = 0 };
            }
            // SAFETY: `uis` is live.
            unsafe { (*uis).result_len = len as usize };
        }
        UIT_BOOLEAN => {
            // SAFETY: `uis` is live.
            if unsafe { (*uis).result_buf }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::UI_LIB_927) };
                return -1;
            }

            // SAFETY: `uis` is live and the caller contract gives `result_buf` one byte.
            unsafe { *(*uis).result_buf = 0 };
            // SAFETY: `uis` is live; the payload is `boolean_data` for a boolean string.
            let b = unsafe { (*uis).payload.boolean_data };
            let mut p = result;
            // SAFETY: `result` is readable for `len` bytes and the loop stops at either NUL or
            // `len`, both inside the caller's buffer.
            while unsafe { *p } != 0 && (p as usize - result as usize) < len as usize {
                // SAFETY: both strings are readable and NUL-terminated.
                if !unsafe { strchr(b.ok_chars, (*p) as c_int) }.is_null() {
                    // SAFETY: `ok_chars` is non-empty when the loop matched; `result_buf` holds
                    // one byte.
                    unsafe { *(*uis).result_buf = *b.ok_chars };
                    break;
                }
                // SAFETY: both strings are readable and NUL-terminated.
                if !unsafe { strchr(b.cancel_chars, (*p) as c_int) }.is_null() {
                    // SAFETY: as above.
                    unsafe { *(*uis).result_buf = *b.cancel_chars };
                    break;
                }
                // SAFETY: still inside `result`.
                p = unsafe { p.add(1) };
            }
        }
        // The authority's `case UIT_NONE: case UIT_INFO: case UIT_ERROR: break;` — reached by
        // fall-through from `UIT_BOOLEAN` as well as directly, and a no-op either way.
        _ => {}
    }
    0
}

// ---------------------------------------------------------------------------------------------
// `OPENSSL_FILE`/`OPENSSL_LINE` for the allocations whose coordinates a caller can read back
// through `CRYPTO_set_mem_functions`. Kept per site rather than shared, because the line is the
// authority's.
// ---------------------------------------------------------------------------------------------

/// `UI_new_method`'s `OPENSSL_zalloc(sizeof(*ret))` (`ui_lib.c:25`).
const LINE_NEW_METHOD_ZALLOC: c_int = 25;
/// `UI_new_method`'s `OPENSSL_free(ret)` on the lock failure (`ui_lib.c:33`).
const LINE_NEW_METHOD_FREE: c_int = 33;
/// `free_string`'s `OPENSSL_free((char *)uis->out_string)` (`ui_lib.c:53`).
const LINE_FREE_STRING_OUT: c_int = 53;
/// `free_string`'s `action_desc` free (`ui_lib.c:56`).
const LINE_FREE_STRING_ACTION: c_int = 56;
/// `free_string`'s `ok_chars` free (`ui_lib.c:57`).
const LINE_FREE_STRING_OK: c_int = 57;
/// `free_string`'s `cancel_chars` free (`ui_lib.c:58`).
const LINE_FREE_STRING_CANCEL: c_int = 58;
/// `free_string`'s `OPENSSL_free(uis)` (`ui_lib.c:68`).
const LINE_FREE_STRING_FREE: c_int = 68;
/// `UI_free`'s `OPENSSL_free(ui)` (`ui_lib.c:81`).
const LINE_FREE_UI: c_int = 81;
/// `general_allocate_prompt`'s `OPENSSL_zalloc(sizeof(*ret))` (`ui_lib.c:108`).
const LINE_ALLOCATE_PROMPT: c_int = 108;
/// `UI_dup_input_string`'s `OPENSSL_strdup(prompt)` (`ui_lib.c:212`).
const LINE_DUP_INPUT_PROMPT: c_int = 212;
/// `UI_dup_input_string`'s `OPENSSL_free(prompt_copy)` (`ui_lib.c:221`).
const LINE_DUP_INPUT_FREE: c_int = 221;
/// `UI_dup_verify_string`'s `OPENSSL_strdup(prompt)` (`ui_lib.c:243`).
const LINE_DUP_VERIFY_PROMPT: c_int = 243;
/// `UI_dup_verify_string`'s `OPENSSL_free(prompt_copy)` (`ui_lib.c:252`).
const LINE_DUP_VERIFY_FREE: c_int = 252;
/// `UI_dup_input_boolean`'s `OPENSSL_strdup(prompt)` (`ui_lib.c:276`).
const LINE_DUP_BOOL_PROMPT: c_int = 276;
/// `UI_dup_input_boolean`'s `OPENSSL_strdup(action_desc)` (`ui_lib.c:282`).
const LINE_DUP_BOOL_ACTION: c_int = 282;
/// `UI_dup_input_boolean`'s `OPENSSL_strdup(ok_chars)` (`ui_lib.c:288`).
const LINE_DUP_BOOL_OK: c_int = 288;
/// `UI_dup_input_boolean`'s `OPENSSL_strdup(cancel_chars)` (`ui_lib.c:294`).
const LINE_DUP_BOOL_CANCEL: c_int = 294;
/// `UI_dup_input_boolean`'s `err:` frees (`ui_lib.c:308-311`).
const LINE_DUP_BOOL_ERR: c_int = 308;
/// `UI_dup_info_string`'s `OPENSSL_strdup(text)` (`ui_lib.c:327`).
const LINE_DUP_INFO_PROMPT: c_int = 327;
/// `UI_dup_info_string`'s `OPENSSL_free(text_copy)` (`ui_lib.c:335`).
const LINE_DUP_INFO_FREE: c_int = 335;
/// `UI_dup_error_string`'s `OPENSSL_strdup(text)` (`ui_lib.c:351`).
const LINE_DUP_ERROR_PROMPT: c_int = 351;
/// `UI_dup_error_string`'s `OPENSSL_free(text_copy)` (`ui_lib.c:359`).
const LINE_DUP_ERROR_FREE: c_int = 359;
/// `UI_construct_prompt`'s `OPENSSL_malloc(len + 1)` (`ui_lib.c:383`).
const LINE_CONSTRUCT_PROMPT: c_int = 383;
/// `UI_create_method`'s `OPENSSL_zalloc(sizeof(*ui_method))` (`ui_lib.c:606`).
const LINE_CREATE_METHOD_ZALLOC: c_int = 606;
/// `UI_create_method`'s `OPENSSL_strdup(name)` (`ui_lib.c:607`).
const LINE_CREATE_METHOD_DUP: c_int = 607;
/// `UI_create_method`'s `OPENSSL_free(ui_method->name)` (`ui_lib.c:618`).
const LINE_CREATE_METHOD_FREE_NAME: c_int = 618;
/// `UI_create_method`'s `OPENSSL_free(ui_method)` (`ui_lib.c:620`).
const LINE_CREATE_METHOD_FREE: c_int = 620;
/// `UI_destroy_method`'s `OPENSSL_free(ui_method->name)` (`ui_lib.c:637`).
const LINE_DESTROY_METHOD_NAME: c_int = 637;
/// `UI_destroy_method`'s `OPENSSL_free(ui_method)` (`ui_lib.c:639`).
const LINE_DESTROY_METHOD: c_int = 639;

#[cfg(test)]
mod tests {
    use super::*;

    /// `UI_new` with the built-in method object, the two accessors and `UI_free`. The default
    /// method is `ui_openssl.c`'s object; nothing here drives it, so no terminal is touched.
    #[test]
    fn a_new_ui_holds_the_default_method_and_frees() {
        // SAFETY: `UI_new` allocates its own object.
        let ui = unsafe { UI_new() };
        assert!(!ui.is_null());
        // SAFETY: `ui` is live.
        let meth = unsafe { UI_get_method(ui) };
        assert!(!meth.is_null());
        // SAFETY: `ui` is live and its method object is a `'static` one.
        unsafe { assert!((*meth).ui_write_string.is_some()) };
        // SAFETY: `ui` is a live object this call created.
        unsafe { UI_free(ui) };
    }

    /// `UI_new_method(UI_null())` builds the do-nothing method. With an input string queued,
    /// `UI_process` answers `-2` because the null method has no reader — the cancellation code
    /// the module doc describes — and clears `UI_FLAG_REDOABLE`. Nothing is prompted.
    #[test]
    fn the_null_method_cancels_without_a_reader() {
        // SAFETY: `UI_null` returns a `'static` method object.
        let meth = UI_null();
        // SAFETY: `meth` is a live method.
        let ui = unsafe { UI_new_method(meth) };
        assert!(!ui.is_null());
        let mut buf = [0 as c_char; 16];
        // SAFETY: `ui` is live and `buf` outlives the call.
        let idx = unsafe { UI_add_input_string(ui, c"p".as_ptr(), 0, buf.as_mut_ptr(), 0, 8) };
        assert!(idx > 0);
        // SAFETY: `ui` is live and valid for the call.
        let rc = unsafe { UI_process(ui) };
        assert_eq!(rc, -2);
        // SAFETY: the flag was cleared by the cancel.
        unsafe { assert_eq!((*ui).flags & UI_FLAG_REDOABLE, 0) };
        // SAFETY: `ui` is a live object this call created.
        unsafe { UI_free(ui) };
    }

    /// An added prompt reports its index, its minimum and maximum and its test string, and a
    /// result inside the bounds lands in the caller's buffer with its length.
    #[test]
    fn an_added_prompt_round_trips_its_bounds_and_result() {
        // SAFETY: `UI_null` returns a `'static` method object.
        let meth = UI_null();
        // SAFETY: `meth` is a live method.
        let ui = unsafe { UI_new_method(meth) };
        let mut buf = [0 as c_char; 16];
        let test = c"test";
        // SAFETY: the buffers outlive the call.
        let idx = unsafe {
            UI_add_verify_string(
                ui,
                c"prompt".as_ptr(),
                0,
                buf.as_mut_ptr(),
                2,
                8,
                test.as_ptr(),
            )
        };
        assert!(idx > 0);
        // SAFETY: `ui` is live.
        let uis = unsafe { OPENSSL_sk_value((*ui).strings, 0) }.cast::<UiString>();
        // SAFETY: `uis` is a live queue element.
        unsafe {
            assert_eq!(UI_get_result_minsize(uis), 2);
            assert_eq!(UI_get_result_maxsize(uis), 8);
            assert_eq!(UI_get_string_type(uis), UIT_VERIFY);
            assert_eq!(UI_get0_test_string(uis), test.as_ptr());
        }
        // SAFETY: `result` is three bytes and the bounds allow it; `buf` is 16 bytes.
        let rc = unsafe { UI_set_result_ex(ui, uis, c"abc".as_ptr(), 3) };
        assert_eq!(rc, 0);
        // SAFETY: `uis` is live and the result is three bytes plus the terminator.
        unsafe {
            assert_eq!(UI_get_result_string_length(uis), 3);
            assert_eq!((*uis).result_buf.read(), b'a' as c_char);
        }
        // SAFETY: `ui` is a live object this call created.
        unsafe { UI_free(ui) };
    }

    /// A result shorter than the minimum is refused with `-1` and re-sets `UI_FLAG_REDOABLE`.
    #[test]
    fn a_short_result_is_refused_and_redoable() {
        // SAFETY: `UI_null` returns a `'static` method object.
        let meth = UI_null();
        // SAFETY: `meth` is a live method.
        let ui = unsafe { UI_new_method(meth) };
        let mut buf = [0 as c_char; 16];
        // SAFETY: the buffers outlive the call.
        let idx = unsafe { UI_add_input_string(ui, c"p".as_ptr(), 0, buf.as_mut_ptr(), 4, 8) };
        assert!(idx > 0);
        // SAFETY: `ui` is live.
        let uis = unsafe { OPENSSL_sk_value((*ui).strings, 0) }.cast::<UiString>();
        // SAFETY: `uis` is a live queue element and one byte is inside the buffer.
        let rc = unsafe { UI_set_result_ex(ui, uis, c"ab".as_ptr(), 2) };
        assert_eq!(rc, -1);
        // SAFETY: `ui` is live.
        unsafe { assert_ne!((*ui).flags & UI_FLAG_REDOABLE, 0) };
        // SAFETY: `ui` is a live object this call created.
        unsafe { UI_free(ui) };
    }
}
