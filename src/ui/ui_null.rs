//! Phase 13 staging — `crypto/ui/ui_null.c`: the do-nothing `UI_METHOD`.
//!
//! `ui_null.c` is 26 lines and one export, and it lands with `ui_lib.c` because `UI_new_method`
//! falls back to it: `if (method == NULL) method = UI_get_default_method(); if (method == NULL)
//! method = UI_null();` (`crypto/ui/ui_lib.c:37-40`). The default method is never NULL on this
//! platform — `ui_openssl.c` installs `ui_openssl` as `default_UI_meth` — so the fall-through is
//! unreachable at run time, but the *call* is compiled in and the symbol has to exist for
//! `ui_lib.c` to link. That is the whole reason it is transcribed here rather than deferred with
//! the rest of `ui_util.c`, which nothing in the chain reaches.
//!
//! The object is `static const UI_METHOD ui_null` with a name and six NULL callbacks. A `UI`
//! built over it has no opener, writer, flusher, reader or closer, so `UI_process` answers `-2`
//! (a cancel) on its first reader-less string rather than prompting — which is what makes it a
//! safe method to drive from a unit test.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

use crate::runtime::ex_data::CryptoExData;
use crate::ui::ui_lib::UiMethod;

/// `static const UI_METHOD ui_null` — `crypto/ui/ui_null.c:12-20`.
///
/// The `ex_data` field is the zero `CRYPTO_EX_DATA`, which is a NULL `ctx` and a NULL `sk`.
static UI_NULL: UiMethod = UiMethod {
    name: c"OpenSSL NULL UI".as_ptr().cast_mut(),
    ui_open_session: None,
    ui_write_string: None,
    ui_flush: None,
    ui_read_string: None,
    ui_close_session: None,
    ui_duplicate_data: None,
    ui_destroy_data: None,
    ui_construct_prompt: None,
    ex_data: CryptoExData {
        ctx: ptr::null_mut(),
        sk: ptr::null_mut(),
    },
};

/// `const UI_METHOD *UI_null(void)` — `crypto/ui/ui_null.c:23-26`.
///
/// Answers the address of the one `'static` object. The authority's comment above it calls the
/// function "the method with all the built-in thingies"; it has none, and the name is the
/// authority's typo carried through.
///
/// # Safety
///
/// Takes no arguments and touches no pointer.
#[no_mangle]
pub extern "C" fn UI_null() -> *const UiMethod {
    core::ptr::addr_of!(UI_NULL)
}
