//! Phase 10 — `crypto/passphrase.c`: the passphrase bridge the encode/decode framework stands on.
//!
//! This file is the **floor** of the encoder/decoder framework (D356). `OSSL_ENCODER_CTX` and
//! `OSSL_DECODER_CTX` each embed one `struct ossl_passphrase_data_st` and hand it to a provider
//! through the four `ossl_pw_set_*` helpers, so nothing in `crypto/encode_decode/` links until
//! those helpers exist. They are the authority's own bridge between the three caller-facing
//! passphrase forms (`EVP_PKEY`-style `pem_password_cb`, the provider-facing
//! `OSSL_PASSPHRASE_CALLBACK`, and a `UI_METHOD`) and the single provider-facing callback form.
//!
//! ## What is here, and what is withheld — and why the line falls where it does
//!
//! **Nine of the fifteen functions are here.** Every one whose body's closure is complete is
//! transcribed: `ossl_pw_clear_passphrase_data`, `ossl_pw_clear_passphrase_cache`, the four
//! `ossl_pw_set_*` setters, the two caching-flag toggles, and the `static do_ui_passphrase`
//! processor. The six that are **withheld** all wait on one name:
//!
//! * `ossl_pw_get_passphrase` (`crypto/passphrase.c:204-305`) is the central dispatcher. Its
//!   `is_pem_password` arm calls `UI_UTIL_wrap_read_pem_callback`
//!   (`crypto/ui/ui_util.c`, declared `include/openssl/ui.h:...`), which is **Phase 13's and
//!   unlanded** — the crate's `src/ui/mod.rs` records that the three `UI_UTIL_*` names are not on
//!   its working set. A body whose own text calls a function no module defines cannot be written,
//!   and it is not stubbed: the four remaining `ossl_pw_get_password`, `ossl_pw_pem_password`,
//!   `ossl_pw_pvk_password`, `ossl_pw_passphrase_callback_enc` and `ossl_pw_passphrase_callback_dec`
//!   are each a single call into `ossl_pw_get_passphrase` and are withheld with it.
//! * the `static do_ui_passphrase` is **not** withheld, even though its only caller is: its own
//!   body reaches only landed `UI_*` functions, and the project's convention is to transcribe a
//!   function whole when its closure is complete. It therefore carries an item-level
//!   `#[allow(dead_code)]` naming the caller that is waiting.
//!
//! The withholding is a **narrowing, not a divergence**: no crate name stands in for an authority
//! name, so no `divergences` row is required. The next thing that needs `ossl_pw_get_passphrase` is
//! `OSSL_ENCODER_CTX_set_passphrase`'s callback registration, which is on no path the eight
//! Phase-8 printers take — `print_pkey` falls through to `ameth->priv_print` with no passphrase
//! read at all — so this half blocks nothing the printers wait on.
//!
//! ## The struct's layout is measured, not read
//!
//! `courts/layout/measure-ossl-passphrase-data.c` compiles the authority's own
//! `struct ossl_passphrase_data_st` against the admitted build's headers and prints its size and
//! the offsets below; the numbers in the `const _` block are those and not a reading of the
//! declaration. The two facts a reading gets wrong are that the `type` enum is a four-byte `int`
//! followed by four bytes of padding, and that the one-bit `unsigned int flag_cache_passphrase`
//! occupies four bytes at 24 with four more of padding before the pointer at 32.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::evp::pem_bridge::PemPasswordCb;
use crate::params::OsslParam;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc,
};
use crate::ui::ui_lib::{
    UI_add_input_string, UI_add_user_data, UI_add_verify_string, UI_construct_prompt, UI_free,
    UI_get_result_length, UI_new, UI_process, UI_set_method, Ui, UiMethod,
};

/// `int(OSSL_PASSPHRASE_CALLBACK)(char *pass, size_t pass_size, size_t *pass_len,
/// const OSSL_PARAM params[], void *arg)` — `include/openssl/core.h:227`.
///
/// The provider-facing passphrase callback. Declared here because this is the first unit that
/// stores one; `crypto/encode_decode/` re-exports it through the `encoder.h`/`decoder.h`
/// setters when that stratum lands. A NULL callback is `Option::None`, which has the same
/// layout as the pointer the authority writes.
pub type OsslPassphraseCallback =
    unsafe extern "C" fn(*mut c_char, usize, *mut usize, *const OsslParam, *mut c_void) -> c_int;

/// `UI_INPUT_FLAG_DEFAULT_PWD` — `include/openssl/ui.h:133`.
///
/// The authority spells the flag as a `#define`; the value is its own.
pub(crate) const UI_INPUT_FLAG_DEFAULT_PWD: c_int = 0x02;

/// `enum { is_expl_passphrase = 1, is_pem_password, is_ossl_passphrase, is_ui_method }` —
/// `include/internal/passphrase.h:41-46`.
///
/// The members are consecutive from an explicit `1`, which is why the first is written out and
/// the other three follow rather than repeating the numbers.
pub(crate) const IS_EXPL_PASSPHRASE: c_int = 1;
/// See [`IS_EXPL_PASSPHRASE`].
pub(crate) const IS_PEM_PASSWORD: c_int = IS_EXPL_PASSPHRASE + 1;
/// See [`IS_EXPL_PASSPHRASE`].
pub(crate) const IS_OSSL_PASSPHRASE: c_int = IS_EXPL_PASSPHRASE + 2;
/// See [`IS_EXPL_PASSPHRASE`].
pub(crate) const IS_UI_METHOD: c_int = IS_EXPL_PASSPHRASE + 3;

/// `struct { char *passphrase_copy; size_t passphrase_len; } expl_passphrase` —
/// `include/internal/passphrase.h:49-52`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ExplPassphrase {
    /// `char *passphrase_copy` — an owned copy, or a one-byte allocation for an empty phrase.
    pub(crate) passphrase_copy: *mut c_char,
    /// `size_t passphrase_len` — the copy's length, which for the empty phrase is zero.
    pub(crate) passphrase_len: usize,
}

/// `struct { pem_password_cb *password_cb; void *password_cbarg; } pem_password` —
/// `include/internal/passphrase.h:54-57`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PemPassword {
    /// `pem_password_cb *password_cb` — the caller's legacy callback.
    pub(crate) password_cb: Option<PemPasswordCb>,
    /// `void *password_cbarg` — its argument, passed through untouched.
    pub(crate) password_cbarg: *mut c_void,
}

/// `struct { OSSL_PASSPHRASE_CALLBACK *passphrase_cb; void *passphrase_cbarg; } ossl_passphrase` —
/// `include/internal/passphrase.h:59-62`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OsslPassphrase {
    /// `OSSL_PASSPHRASE_CALLBACK *passphrase_cb` — the provider-facing callback.
    pub(crate) passphrase_cb: Option<OsslPassphraseCallback>,
    /// `void *passphrase_cbarg` — its argument, passed through untouched.
    pub(crate) passphrase_cbarg: *mut c_void,
}

/// `struct { const UI_METHOD *ui_method; void *ui_method_data; } ui_method` —
/// `include/internal/passphrase.h:64-67`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UiMethodChoice {
    /// `const UI_METHOD *ui_method` — the caller's UI method.
    pub(crate) ui_method: *const UiMethod,
    /// `void *ui_method_data` — the UI's user data.
    pub(crate) ui_method_data: *mut c_void,
}

/// The unnamed `union { ... } _` of `struct ossl_passphrase_data_st` —
/// `include/internal/passphrase.h:48-68`.
///
/// The authority spells the member `_`; Rust reserves that identifier, so the field is named
/// `payload` here and the authority's spelling is recorded in this comment rather than in the
/// code. Exactly one member is live, chosen by `type_`. Both members are two pointers, so the
/// union is sixteen bytes and eight-aligned whichever is live, which is what makes the offsets
/// below independent of the branch taken.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union PassphraseUnion {
    /// The `is_expl_passphrase` member.
    pub(crate) expl_passphrase: ExplPassphrase,
    /// The `is_pem_password` member.
    pub(crate) pem_password: PemPassword,
    /// The `is_ossl_passphrase` member.
    pub(crate) ossl_passphrase: OsslPassphrase,
    /// The `is_ui_method` member.
    pub(crate) ui_method: UiMethodChoice,
}

/// `struct ossl_passphrase_data_st` — `include/internal/passphrase.h:40-80`.
///
/// A local, on-stack-with-its-owner type: the authority offers no allocator for it, and the
/// encoder and decoder contexts embed it. Modelled in the authority's member order, with the
/// one-bit `flag_cache_passphrase` projected as its four-byte storage — the same projection
/// `EvpPkey`'s `foreign` uses, because a bitfield has no address to pin.
#[repr(C)]
pub struct OsslPassphraseData {
    /// The `enum { ... } type` selector, spelled without a name in the authority.
    pub(crate) type_: c_int,
    /// The authority's unnamed `union { ... } _` member, named `payload` here because Rust
    /// reserves `_`.
    pub(crate) payload: PassphraseUnion,
    /// `unsigned int flag_cache_passphrase : 1` — projected as its four-byte storage.
    pub(crate) flag_cache_passphrase: c_uint,
    /// `char *cached_passphrase` — the cached copy, or NULL.
    pub(crate) cached_passphrase: *mut c_char,
    /// `size_t cached_passphrase_len` — the cached copy's length.
    pub(crate) cached_passphrase_len: usize,
}

/// The measured layout, pinned member by member.
///
/// `courts/layout/measure-ossl-passphrase-data.c` prints these numbers from the authority's own
/// struct; the union member is unnamed in the authority, so its offset is asserted through the
/// struct's own field order — `flag_cache_passphrase` at 24 following `type_` at 0.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<OsslPassphraseData>() == 48);
    assert!(align_of::<OsslPassphraseData>() == 8);
    assert!(offset_of!(OsslPassphraseData, type_) == 0);
    assert!(offset_of!(OsslPassphraseData, payload) == 8);
    assert!(offset_of!(OsslPassphraseData, flag_cache_passphrase) == 24);
    assert!(offset_of!(OsslPassphraseData, cached_passphrase) == 32);
    assert!(offset_of!(OsslPassphraseData, cached_passphrase_len) == 40);
};

/// `void ossl_pw_clear_passphrase_data(struct ossl_passphrase_data_st *data)` —
/// `crypto/passphrase.c:16-25`.
///
/// The release order is the authority's and matters: the explicit-passphrase member is cleansed
/// and freed **before** the cache is cleared, so the two allocations the struct can own are both
/// released, and the whole struct is then zeroed so the next `type_` read is `0`.
///
/// # Safety
/// `data` must be NULL or a live `OsslPassphraseData`.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_clear_passphrase_data(data: *mut OsslPassphraseData) {
    if !data.is_null() {
        // SAFETY: `data` is non-NULL and live per the contract.
        if unsafe { (*data).type_ } == IS_EXPL_PASSPHRASE {
            // SAFETY: `type_` selects the union's `expl_passphrase` member, so that member is the
            // live one and its `passphrase_copy` is the allocation `ossl_pw_set_passphrase` made.
            unsafe {
                CRYPTO_clear_free(
                    (*data).payload.expl_passphrase.passphrase_copy.cast(),
                    (*data).payload.expl_passphrase.passphrase_len,
                    ptr::null(),
                    0,
                );
            }
        }
        // SAFETY: `data` is live and was not released above.
        unsafe { ossl_pw_clear_passphrase_cache(data) };
        // SAFETY: `data` is a live, writable, correctly-sized `OsslPassphraseData`; this is the
        // authority's `memset(data, 0, sizeof(*data))`.
        unsafe { ptr::write_bytes(data, 0, 1) };
    }
}

/// `void ossl_pw_clear_passphrase_cache(struct ossl_passphrase_data_st *data)` —
/// `crypto/passphrase.c:27-31`.
///
/// `data` is **not** guarded, and the authority does not guard it either: both its callers hold a
/// non-NULL struct. The pointer is set to NULL after the free so the next
/// `ossl_pw_get_passphrase` does not read a dangling cache through the
/// `cached_passphrase != NULL` test.
///
/// # Safety
/// `data` must be live; it is dereferenced without a NULL test, as the authority's body is.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_clear_passphrase_cache(data: *mut OsslPassphraseData) {
    // SAFETY: `data` is live per the contract.
    unsafe {
        CRYPTO_clear_free(
            (*data).cached_passphrase.cast(),
            (*data).cached_passphrase_len,
            ptr::null(),
            0,
        );
        (*data).cached_passphrase = ptr::null_mut();
    }
}

/// `int ossl_pw_set_passphrase(struct ossl_passphrase_data_st *data,
/// const unsigned char *passphrase, size_t passphrase_len)` — `crypto/passphrase.c:33-49`.
///
/// The `passphrase_len != 0` choice of allocation is deliberate and observable: an empty phrase
/// gets a **one-byte** block rather than NULL, so `ossl_pw_get_passphrase`'s
/// `source != NULL` test takes the explicit-phrase path and answers an empty password instead of
/// falling through to the callbacks. Answers 1 on success and 0 on a NULL argument or an
/// allocation failure, the latter leaving the caller's struct cleared with `type_` set but no
/// copy — which is why the failure path is after the assignment rather than before it.
///
/// # Safety
/// `data` must be a live `OsslPassphraseData`; `passphrase` must be NULL or readable for
/// `passphrase_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_set_passphrase(
    data: *mut OsslPassphraseData,
    passphrase: *const u8,
    passphrase_len: usize,
) -> c_int {
    if data.is_null() || passphrase.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_38) };
        return 0;
    }
    // SAFETY: `data` is live.
    unsafe { ossl_pw_clear_passphrase_data(data) };
    // SAFETY: `data` is live and writable.
    unsafe { (*data).type_ = IS_EXPL_PASSPHRASE };
    // SAFETY: `data` is live; the member is written through the same pointer it was read from.
    let copy = if passphrase_len != 0 {
        // SAFETY: `passphrase` is readable for `passphrase_len` bytes per the contract.
        unsafe { CRYPTO_memdup(passphrase.cast(), passphrase_len, ptr::null(), 0) }
    } else {
        CRYPTO_malloc(1, ptr::null(), 0)
    };
    // SAFETY: `data` is live and the union member is the one `type_` selects.
    unsafe {
        (*data).payload.expl_passphrase.passphrase_copy = copy.cast();
    }
    if copy.is_null() {
        return 0;
    }
    // SAFETY: `data` is live; only the length member remains to be written.
    unsafe {
        (*data).payload.expl_passphrase.passphrase_len = passphrase_len;
    }
    1
}

/// `int ossl_pw_set_pem_password_cb(struct ossl_passphrase_data_st *data,
/// pem_password_cb *cb, void *cbarg)` — `crypto/passphrase.c:51-63`.
///
/// The legacy `pem_password_cb` form. Both the struct and the callback are refused when NULL,
/// because a `type_` of `is_pem_password` with no callback would reach the UI wrapper with
/// nothing to wrap.
///
/// # Safety
/// `data` must be a live `OsslPassphraseData`; `cb` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_set_pem_password_cb(
    data: *mut OsslPassphraseData,
    cb: Option<PemPasswordCb>,
    cbarg: *mut c_void,
) -> c_int {
    if data.is_null() || cb.is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_55) };
        return 0;
    }
    // SAFETY: `data` is live.
    unsafe { ossl_pw_clear_passphrase_data(data) };
    // SAFETY: `data` is live and writable; `type_` selects the member written next.
    unsafe {
        (*data).type_ = IS_PEM_PASSWORD;
        (*data).payload.pem_password.password_cb = cb;
        (*data).payload.pem_password.password_cbarg = cbarg;
    }
    1
}

/// `int ossl_pw_set_ossl_passphrase_cb(struct ossl_passphrase_data_st *data,
/// OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)` — `crypto/passphrase.c:65-77`.
///
/// The provider-facing callback form, and the one `crypto/encode_decode/`'s own setters reach.
///
/// # Safety
/// `data` must be a live `OsslPassphraseData`; `cb` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_set_ossl_passphrase_cb(
    data: *mut OsslPassphraseData,
    cb: Option<OsslPassphraseCallback>,
    cbarg: *mut c_void,
) -> c_int {
    if data.is_null() || cb.is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_69) };
        return 0;
    }
    // SAFETY: `data` is live.
    unsafe { ossl_pw_clear_passphrase_data(data) };
    // SAFETY: `data` is live and writable; `type_` selects the member written next.
    unsafe {
        (*data).type_ = IS_OSSL_PASSPHRASE;
        (*data).payload.ossl_passphrase.passphrase_cb = cb;
        (*data).payload.ossl_passphrase.passphrase_cbarg = cbarg;
    }
    1
}

/// `int ossl_pw_set_ui_method(struct ossl_passphrase_data_st *data,
/// const UI_METHOD *ui_method, void *ui_data)` — `crypto/passphrase.c:79-91`.
///
/// The `UI_METHOD` form, which `do_ui_passphrase` drives directly rather than through the
/// `UI_UTIL` wrapper the `is_pem_password` arm needs.
///
/// # Safety
/// `data` must be a live `OsslPassphraseData`; `ui_method` must be non-NULL and live.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_set_ui_method(
    data: *mut OsslPassphraseData,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
) -> c_int {
    if data.is_null() || ui_method.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_83) };
        return 0;
    }
    // SAFETY: `data` is live.
    unsafe { ossl_pw_clear_passphrase_data(data) };
    // SAFETY: `data` is live and writable; `type_` selects the member written next.
    unsafe {
        (*data).type_ = IS_UI_METHOD;
        (*data).payload.ui_method.ui_method = ui_method;
        (*data).payload.ui_method.ui_method_data = ui_data;
    }
    1
}

/// `int ossl_pw_enable_passphrase_caching(struct ossl_passphrase_data_st *data)` —
/// `crypto/passphrase.c:93-97`.
///
/// The authority answers 1 unconditionally and does not test `data`; the caller holds it. That is
/// why `crypto/encode_decode/`'s callers all set the flag on a context they own.
///
/// # Safety
/// `data` must be live; it is dereferenced without a NULL test, as the authority's body is.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_enable_passphrase_caching(data: *mut OsslPassphraseData) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { (*data).flag_cache_passphrase = 1 };
    1
}

/// `int ossl_pw_disable_passphrase_caching(struct ossl_passphrase_data_st *data)` —
/// `crypto/passphrase.c:99-103`.
///
/// The write is a plain `0`, not a bit clear, because the field is one bit wide.
///
/// # Safety
/// `data` must be live; it is dereferenced without a NULL test, as the authority's body is.
#[no_mangle]
pub unsafe extern "C" fn ossl_pw_disable_passphrase_caching(
    data: *mut OsslPassphraseData,
) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { (*data).flag_cache_passphrase = 0 };
    1
}

/// `static int do_ui_passphrase(char *pass, size_t pass_size, size_t *pass_len,
/// const char *prompt_info, int verify, const UI_METHOD *ui_method, void *ui_data)` —
/// `crypto/passphrase.c:114-201`.
///
/// The UI processor, and the authority's comment above it names the four ways it differs from
/// `UI_UTIL_read_pw` — it builds its own prompt, allocates its own buffers to compensate for the
/// terminator a UI password string carries, raises errors, and reports the length back. All four
/// are in the body below.
///
/// `verify` selects the second prompt, and its buffer is a **separate** allocation passed as the
/// `test_buf` argument, which is what makes `UI_process` compare the two rather than accept one.
/// The `end:` label frees in the authority's order (verify buffer, then input buffer, then the
/// prompt, then the `UI`) and neither buffer is NULL-tested for the reasons
/// `CRYPTO_clear_free`'s contract gives.
#[allow(dead_code)] // read by `ossl_pw_get_passphrase`, withheld on `UI_UTIL_wrap_read_pem_callback`
unsafe fn do_ui_passphrase(
    pass: *mut c_char,
    pass_size: usize,
    pass_len: *mut usize,
    prompt_info: *const c_char,
    verify: c_int,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
) -> c_int {
    // `ipass` and `vpass` are declared before `prompt` because the authority's `end:` label
    // frees them on the `UI_construct_prompt` failure path, where they are still NULL.
    let mut ipass: *mut c_char = ptr::null_mut();
    let mut vpass: *mut c_char = ptr::null_mut();
    let mut ret: c_int = 0;

    if pass.is_null() || pass_size == 0 || pass_len.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_124) };
        return 0;
    }

    // SAFETY: no preconditions.
    let ui = unsafe { UI_new() };
    if ui.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_129) };
        return 0;
    }

    if !ui_method.is_null() {
        // SAFETY: `ui` is live and `ui_method` is non-NULL per the contract.
        unsafe {
            UI_set_method(ui, ui_method);
            if !ui_data.is_null() {
                UI_add_user_data(ui, ui_data);
            }
        }
    }

    // SAFETY: `ui` is live; the two literals are the authority's own and readable.
    let prompt = unsafe { UI_construct_prompt(ui, c"pass phrase".as_ptr(), prompt_info) };
    if prompt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_142) };
        // SAFETY: the `end` label's contract, with its four pointers the locals above.
        return unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) };
    }

    // SAFETY: `CRYPTO_zalloc` takes a size and answers NULL or a zeroed block; a positive
    // `pass_size + 1` is a valid size and `pass_size`'s range is the caller's contract.
    ipass = CRYPTO_zalloc(pass_size + 1, ptr::null(), 0).cast();
    if ipass.is_null() {
        // SAFETY: the `end` label's contract, with its four pointers the locals above.
        return unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) };
    }

    // SAFETY: `ui`, `prompt` and `ipass` are live; `ipass` is writable for `pass_size` bytes and
    // `prompt` is NUL-terminated, both per the constructor's contract.
    let prompt_idx = unsafe {
        UI_add_input_string(
            ui,
            prompt,
            UI_INPUT_FLAG_DEFAULT_PWD,
            ipass,
            0,
            pass_size as c_int,
        )
    } - 1;
    if prompt_idx < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PASSPHRASE_156) };
        // SAFETY: the `end` label's contract, with its four pointers the locals above.
        return unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) };
    }

    if verify != 0 {
        // SAFETY: as for `ipass`.
        vpass = CRYPTO_zalloc(pass_size + 1, ptr::null(), 0).cast();
        if vpass.is_null() {
            // SAFETY: the `end` label's contract, with its four pointers the locals above.
            return unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) };
        }
        // SAFETY: `ui` and `prompt` are live; `vpass` is writable and `ipass` is the test buffer
        // `UI_process` compares against.
        let verify_idx = unsafe {
            UI_add_verify_string(
                ui,
                prompt,
                UI_INPUT_FLAG_DEFAULT_PWD,
                vpass,
                0,
                pass_size as c_int,
                ipass,
            )
        } - 1;
        if verify_idx < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PASSPHRASE_171) };
            // SAFETY: the `end` label's contract, with its four pointers the locals above.
            return unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) };
        }
    }

    // SAFETY: `ui` is live.
    match unsafe { UI_process(ui) } {
        -2 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PASSPHRASE_178) };
        }
        -1 => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PASSPHRASE_181) };
        }
        _ => {
            // SAFETY: `ui` is live and `prompt_idx` indexes a string it holds.
            let res = unsafe { UI_get_result_length(ui, prompt_idx) };
            if res < 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PASSPHRASE_186) };
            } else {
                // SAFETY: `pass` is writable for `pass_size` bytes and `ipass` holds at least
                // `res` bytes, `res` being bounded by the string's maxsize.
                unsafe {
                    *pass_len = res as usize;
                    ptr::copy_nonoverlapping(ipass, pass, *pass_len);
                }
                ret = 1;
            }
        }
    }

    // SAFETY: the `end` label's contract, with its four pointers the locals above.
    unsafe { end(ui, prompt, ipass, vpass, pass_size, ret) }
}

/// The authority's `end:` label of [`do_ui_passphrase`] — `crypto/passphrase.c:195-200`.
///
/// Split out because the label has eight incoming jumps in the authority and Rust has no `goto`;
/// a call is the same thing with the same arguments.
///
/// # Safety
/// `ui`, `prompt`, `ipass` and `vpass` must each be NULL or a pointer this function's caller
/// owns, `pass_size + 1` must be the size `ipass`/`vpass` were allocated with.
unsafe fn end(
    ui: *mut Ui,
    prompt: *mut c_char,
    ipass: *mut c_char,
    vpass: *mut c_char,
    pass_size: usize,
    ret: c_int,
) -> c_int {
    // SAFETY: each pointer is NULL or owned by the caller, and the two buffers are `pass_size + 1`
    // bytes as allocated above.
    unsafe {
        CRYPTO_clear_free(vpass.cast(), pass_size + 1, ptr::null(), 0);
        CRYPTO_clear_free(ipass.cast(), pass_size + 1, ptr::null(), 0);
        if !prompt.is_null() {
            CRYPTO_free(prompt.cast(), ptr::null(), 0);
        }
        UI_free(ui);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed struct, as `ossl_pw_clear_passphrase_data` leaves one: `type_` is 0, which is no
    /// member of the authority's enum, so a stray read is a test failure rather than a branch.
    fn blank() -> OsslPassphraseData {
        OsslPassphraseData {
            type_: 0,
            payload: PassphraseUnion {
                expl_passphrase: ExplPassphrase {
                    passphrase_copy: ptr::null_mut(),
                    passphrase_len: 0,
                },
            },
            flag_cache_passphrase: 0,
            cached_passphrase: ptr::null_mut(),
            cached_passphrase_len: 0,
        }
    }

    /// A `pem_password_cb` that always refuses; only its address is observed here.
    unsafe extern "C" fn rejecting_cb(
        _buf: *mut c_char,
        _size: c_int,
        _rwflag: c_int,
        _u: *mut c_void,
    ) -> c_int {
        -1
    }

    /// The round trip `osl_pw_set_passphrase` promises: a copy is owned, the type selects it,
    /// and `osl_pw_clear_passphrase_data` releases it and zeroes the selector.
    #[test]
    fn set_passphrase_owns_a_copy_and_clear_releases_it() {
        let mut d = blank();
        let phrase = b"hunter2";
        // SAFETY: `d` is live and `phrase` is readable for its length.
        let ok = unsafe { ossl_pw_set_passphrase(&mut d, phrase.as_ptr(), phrase.len()) };
        assert_eq!(ok, 1);
        // SAFETY: `type_` selects the union member read.
        unsafe {
            assert_eq!(d.type_, IS_EXPL_PASSPHRASE);
            assert_eq!(d.payload.expl_passphrase.passphrase_len, phrase.len());
            let copy = core::slice::from_raw_parts(
                d.payload.expl_passphrase.passphrase_copy.cast::<u8>(),
                phrase.len(),
            );
            assert_eq!(copy, phrase);
            // The copy is the crate's, not the caller's: a different pointer holds the bytes.
            assert_ne!(
                d.payload
                    .expl_passphrase
                    .passphrase_copy
                    .cast::<u8>()
                    .cast_const(),
                phrase.as_ptr()
            );
            ossl_pw_clear_passphrase_data(&mut d);
            assert_eq!(d.type_, 0);
            assert!(d.payload.expl_passphrase.passphrase_copy.is_null());
        }
    }

    /// An empty phrase gets a one-byte block, not NULL, so the `source != NULL` test in the
    /// withheld dispatcher would take the explicit arm; the length is zero either way.
    #[test]
    fn an_empty_passphrase_still_gets_an_allocation() {
        let mut d = blank();
        // SAFETY: `d` is live and a zero length reads no bytes of `passphrase`.
        let ok = unsafe { ossl_pw_set_passphrase(&mut d, b"".as_ptr(), 0) };
        assert_eq!(ok, 1);
        // SAFETY: `type_` selects the union member read, and the pointer is non-NULL.
        unsafe {
            assert_eq!(d.payload.expl_passphrase.passphrase_len, 0);
            assert!(!d.payload.expl_passphrase.passphrase_copy.is_null());
            ossl_pw_clear_passphrase_data(&mut d);
        }
    }

    /// Each setter clears what came before: a struct set to one type and then to another must
    /// hold only the second, which is the authority's `osl_pw_clear_passphrase_data` call at the
    /// head of every setter.
    #[test]
    fn setting_a_second_form_replaces_the_first() {
        let mut d = blank();
        // SAFETY: `d` is live and the phrase is readable for its length.
        unsafe {
            assert_eq!(ossl_pw_set_passphrase(&mut d, b"first".as_ptr(), 5), 1);
            assert_eq!(d.type_, IS_EXPL_PASSPHRASE);
            assert_eq!(
                ossl_pw_set_pem_password_cb(&mut d, Some(rejecting_cb), ptr::null_mut()),
                1
            );
            assert_eq!(d.type_, IS_PEM_PASSWORD);
            assert_eq!(
                d.payload
                    .pem_password
                    .password_cb
                    .map(|f| f as *const () as usize),
                Some(rejecting_cb as *const () as usize)
            );
            ossl_pw_clear_passphrase_data(&mut d);
        }
    }

    /// The two caching toggles write the one-bit field as a whole word, and each answers 1.
    #[test]
    fn the_caching_toggles_write_the_flag() {
        let mut d = blank();
        // SAFETY: `d` is live.
        unsafe {
            assert_eq!(ossl_pw_enable_passphrase_caching(&mut d), 1);
            assert_eq!(d.flag_cache_passphrase, 1);
            assert_eq!(ossl_pw_disable_passphrase_caching(&mut d), 1);
            assert_eq!(d.flag_cache_passphrase, 0);
        }
    }

    /// A NULL argument is refused **before** any pointer is dereferenced, for both the phrase
    /// setter and the callback setter.
    #[test]
    fn a_null_argument_is_refused() {
        // SAFETY: the NULL argument is the case under test; nothing is dereferenced on the
        // refusal path.
        unsafe {
            assert_eq!(ossl_pw_set_passphrase(ptr::null_mut(), b"x".as_ptr(), 1), 0);
            assert_eq!(ossl_pw_set_passphrase(&mut blank(), ptr::null(), 1), 0);
            assert_eq!(
                ossl_pw_set_pem_password_cb(ptr::null_mut(), Some(rejecting_cb), ptr::null_mut()),
                0
            );
            assert_eq!(
                ossl_pw_set_ossl_passphrase_cb(ptr::null_mut(), None, ptr::null_mut()),
                0
            );
        }
    }
}
