//! Phase 10 — `crypto/encode_decode/encoder_pkey.c`: building a context for an `EVP_PKEY`.
//!
//! The third and last encoder unit (D362). It is the file the whole chain exists for:
//! `OSSL_ENCODER_CTX_new_for_pkey` is what `print_pkey` (`crypto/evp/p_lib.c:1211`) calls, and its
//! result is the context whose `OSSL_ENCODER_CTX_get_num_encoders` answers **0** for every key this
//! crate can build — because no provider encoder implementation is registered here — which is what
//! sends `print_pkey` to `ameth->priv_print`. It is also the first caller of
//! `OSSL_ENCODER_do_all_provided`, which is why the fetch block that waited through D360 and D361
//! landed in this commit rather than before it.
//!
//! ## The two-pass collection, and why the ids are cached
//!
//! `ossl_encoder_ctx_setup_for_pkey` (`:227-340`) collects encoders in **two passes**
//! (`flag_find_same_provider` 0 then 1) because the chain is processed in reverse: encoders from a
//! *different* provider than the key management are added first so that same-provider encoders end
//! up **last** in the stack, and the walk in `src/encoder_lib.rs` then reaches the same-provider ones
//! first. The two passes match differently: the same-provider pass compares the encoder's name-map
//! `id` against the ids of the key management's names, and the other pass asks
//! `OSSL_ENCODER_is_a` by name. The ids are computed **once** into `id_names` because the authority's
//! own comment says why: `collect_encoder` is called many times and every call would otherwise
//! convert all the names to ids.
//!
//! ## The one arm a legacy key takes
//!
//! `pkey->keymgmt == NULL` means the whole `if` is skipped, so no encoder is ever looked up, no
//! `id_names` is allocated, and `ok` is **1** with a context that holds nothing. That is the arm
//! every Phase-8 printer takes, because each builds its `EVP_PKEY` with `EVP_PKEY_set1_*`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr;

use crate::context::namemap::{ossl_namemap_name2num, ossl_namemap_stored};
use crate::encoder_lib::{
    OSSL_ENCODER_CTX_add_extra, OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_CTX_set_cleanup,
    OSSL_ENCODER_CTX_set_construct, OSSL_ENCODER_CTX_set_construct_data,
    OSSL_ENCODER_CTX_set_output_structure, OSSL_ENCODER_CTX_set_output_type,
    OSSL_ENCODER_CTX_set_selection,
};
use crate::encoder_meth::{
    OSSL_ENCODER_CTX_new, OSSL_ENCODER_CTX_set_params, OSSL_ENCODER_do_all_provided,
    OSSL_ENCODER_get0_provider, OSSL_ENCODER_is_a, OsslEncoder, OsslEncoderCtx,
    OsslEncoderInstance,
};
use crate::evp::keymgmt::{
    evp_keymgmt_export, EVP_KEYMGMT_get0_provider, EVP_KEYMGMT_names_do_all,
};
use crate::evp::pkey::{evp_pkey_is_provided, EvpPkey};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OsslParam};
use crate::passphrase::{
    ossl_pw_set_ossl_passphrase_cb, ossl_pw_set_passphrase, ossl_pw_set_pem_password_cb,
    ossl_pw_set_ui_method, OsslPassphraseCallback,
};
use crate::provider::{ossl_provider_libctx, OsslProvider};
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc_array, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::ui::ui_lib::UiMethod;

/// `OSSL_ENCODER_PARAM_CIPHER` — `core_names.h:256`, which is `OSSL_ALG_PARAM_CIPHER`'s `"cipher"`.
const OSSL_ENCODER_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();
/// `OSSL_ENCODER_PARAM_PROPERTIES` — `core_names.h:258`, `OSSL_ALG_PARAM_PROPERTIES`' `"properties"`.
const OSSL_ENCODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_ENCODER_PARAM_SAVE_PARAMETERS` — `core_names.h:259`, the string `"save-parameters"`.
const OSSL_ENCODER_PARAM_SAVE_PARAMETERS: *const c_char = c"save-parameters".as_ptr();

/// `evp_pkey_is_assigned(pk)` — the authority's macro, `(pk)->keymgmt != NULL || (pk)->pkey.ptr != NULL`.
///
/// # Safety
/// `pk` must be live.
unsafe fn pkey_is_assigned(pk: *const EvpPkey) -> bool {
    // SAFETY: `pk` is live per the contract; both reads are plain fields.
    unsafe { !(*pk).keymgmt.is_null() || !(*pk).pkey.is_null() }
}

/// `int OSSL_ENCODER_CTX_set_cipher(OSSL_ENCODER_CTX *ctx, const char *cipher_name,
/// const char *propquery)` — `encoder_pkey.c:26-38`.
///
/// Two `utf8_string` parameters in a three-element array whose last entry is the terminator; both
/// strings are passed with a size of 0, which is the descriptor's "NUL-terminated" spelling.
///
/// # Safety
/// `ctx` must be live; the two names NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_cipher(
    ctx: *mut OsslEncoderCtx,
    cipher_name: *const c_char,
    propquery: *const c_char,
) -> c_int {
    // SAFETY: the constructor only fills a descriptor; both arguments are the caller's.
    let mut params: [OsslParam; 3] = unsafe {
        [
            crate::params::OSSL_PARAM_construct_utf8_string(
                OSSL_ENCODER_PARAM_CIPHER,
                cipher_name.cast_mut(),
                0,
            ),
            crate::params::OSSL_PARAM_construct_utf8_string(
                OSSL_ENCODER_PARAM_PROPERTIES,
                propquery.cast_mut(),
                0,
            ),
            OSSL_PARAM_construct_end(),
        ]
    };
    let _ = &mut params;
    // SAFETY: `ctx` is live and `params` is terminated.
    unsafe { OSSL_ENCODER_CTX_set_params(ctx, params.as_ptr()) }
}

/// `int OSSL_ENCODER_CTX_set_passphrase(OSSL_ENCODER_CTX *ctx, const unsigned char *kstr,
/// size_t klen)` — `encoder_pkey.c:40-45`.
///
/// # Safety
/// `ctx` must be live; `kstr` readable for `klen` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase(
    ctx: *mut OsslEncoderCtx,
    kstr: *const u8,
    klen: usize,
) -> c_int {
    // SAFETY: `ctx` is live, so its embedded `pwdata` is this object's own field.
    unsafe { ossl_pw_set_passphrase(ptr::addr_of_mut!((*ctx).pwdata), kstr, klen) }
}

/// `int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx, const UI_METHOD *ui_method,
/// void *ui_data)` — `encoder_pkey.c:47-52`.
///
/// # Safety
/// `ctx` must be live; `ui_method` live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase_ui(
    ctx: *mut OsslEncoderCtx,
    ui_method: *const UiMethod,
    ui_data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live, so its `pwdata` field is.
    unsafe { ossl_pw_set_ui_method(ptr::addr_of_mut!((*ctx).pwdata), ui_method, ui_data) }
}

/// `int OSSL_ENCODER_CTX_set_pem_password_cb(OSSL_ENCODER_CTX *ctx, pem_password_cb *cb,
/// void *cbarg)` — `encoder_pkey.c:54-58`.
///
/// # Safety
/// `ctx` must be live; `cb` non-NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_pem_password_cb(
    ctx: *mut OsslEncoderCtx,
    cb: Option<crate::evp::pem_bridge::PemPasswordCb>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live, so its `pwdata` field is.
    unsafe { ossl_pw_set_pem_password_cb(ptr::addr_of_mut!((*ctx).pwdata), cb, cbarg) }
}

/// `int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx, OSSL_PASSPHRASE_CALLBACK *cb,
/// void *cbarg)` — `encoder_pkey.c:60-65`.
///
/// # Safety
/// `ctx` must be live; `cb` non-NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_set_passphrase_cb(
    ctx: *mut OsslEncoderCtx,
    cb: Option<OsslPassphraseCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live, so its `pwdata` field is.
    unsafe { ossl_pw_set_ossl_passphrase_cb(ptr::addr_of_mut!((*ctx).pwdata), cb, cbarg) }
}

/// `struct collected_encoder_st` — `encoder_pkey.c:72-83`.
#[repr(C)]
struct CollectedEncoder {
    /// `STACK_OF(OPENSSL_CSTRING) *names` — the key management's names, borrowed.
    names: *mut OpenSslStack,
    /// `int *id_names` — each name's name-map id, or NULL.
    id_names: *mut c_int,
    /// `const char *output_structure` — the context's desired structure, or NULL.
    output_structure: *const c_char,
    /// `const char *output_type` — the context's desired type.
    output_type: *const c_char,
    /// `const OSSL_PROVIDER *keymgmt_prov` — the key management's provider, or NULL.
    keymgmt_prov: *const OsslProvider,
    /// `OSSL_ENCODER_CTX *ctx`.
    ctx: *mut OsslEncoderCtx,
    /// `unsigned int flag_find_same_provider : 1` — projected as its four-byte storage.
    flag_find_same_provider: c_int,
    /// `int error_occurred`.
    error_occurred: c_int,
}

/// `struct collected_names_st` — `encoder_pkey.c:129-132`.
#[repr(C)]
struct CollectedNames {
    /// `STACK_OF(OPENSSL_CSTRING) *names`.
    names: *mut OpenSslStack,
    /// `unsigned int error_occurred : 1` — projected as its four-byte storage.
    error_occurred: c_int,
}

/// `static void collect_encoder(OSSL_ENCODER *encoder, void *arg)` — `encoder_pkey.c:85-127`.
///
/// The four-way `continue` is the authority's and each clause is a different exclusion: the wrong
/// pass, a `does_selection` that refuses this selection, and -- only for a **different** provider --
/// an encoder that cannot `import_object` the key. The `break` on a successful add is what makes the
/// "only add each encoder implementation once" comment true.
///
/// # Safety
/// `encoder` must be live; `arg` a live `CollectedEncoder`.
unsafe extern "C" fn collect_encoder(encoder: *mut OsslEncoder, arg: *mut c_void) {
    // SAFETY: `arg` is a live `CollectedEncoder` per the contract.
    unsafe {
        let data = arg.cast::<CollectedEncoder>();
        if (*data).error_occurred != 0 {
            return;
        }
        (*data).error_occurred = 1; /* Assume the worst */

        let prov = OSSL_ENCODER_get0_provider(encoder);
        if c_int::from((*data).keymgmt_prov == prov) == (*data).flag_find_same_provider {
            let provctx = crate::provider::OSSL_PROVIDER_get0_provider_ctx(prov);
            let end_i = OPENSSL_sk_num((*data).names);

            for i in 0..end_i {
                let match_ = if (*data).flag_find_same_provider != 0 {
                    c_int::from(*(*data).id_names.add(i as usize) == (*encoder).base.id)
                } else {
                    OSSL_ENCODER_is_a(encoder, OPENSSL_sk_value((*data).names, i).cast::<c_char>())
                };
                let does_selection = (*encoder).does_selection;
                let refuses = match does_selection {
                    Some(does_selection) => does_selection(provctx, (*(*data).ctx).selection) == 0,
                    None => false,
                };
                if match_ == 0
                    || refuses
                    || ((*data).keymgmt_prov != prov && (*encoder).import_object.is_none())
                {
                    continue;
                }

                /* Only add each encoder implementation once */
                if crate::encoder_lib::OSSL_ENCODER_CTX_add_encoder((*data).ctx, encoder) != 0 {
                    break;
                }
            }
        }

        (*data).error_occurred = 0; /* All is good now */
    }
}

/// `static void collect_name(const char *name, void *arg)` — `encoder_pkey.c:134-147`.
///
/// # Safety
/// `name` must be NUL-terminated; `arg` a live `CollectedNames`.
unsafe extern "C" fn collect_name(name: *const c_char, arg: *mut c_void) {
    // SAFETY: `arg` is a live `CollectedNames` per the contract.
    unsafe {
        let data = arg.cast::<CollectedNames>();
        if (*data).error_occurred != 0 {
            return;
        }
        (*data).error_occurred = 1; /* Assume the worst */

        if OPENSSL_sk_push((*data).names, name.cast::<c_void>()) <= 0 {
            return;
        }

        (*data).error_occurred = 0; /* All is good now */
    }
}

/// `struct construct_data_st` — `encoder_pkey.c:155-162`.
#[repr(C)]
struct ConstructDataPkey {
    /// `const EVP_PKEY *pk`.
    pk: *const EvpPkey,
    /// `int selection`.
    selection: c_int,
    /// `OSSL_ENCODER_INSTANCE *encoder_inst`.
    encoder_inst: *mut OsslEncoderInstance,
    /// `const void *obj`.
    obj: *const c_void,
    /// `void *constructed_obj`.
    constructed_obj: *mut c_void,
}

/// `static int encoder_import_cb(const OSSL_PARAM params[], void *arg)` —
/// `encoder_pkey.c:164-174`.
///
/// # Safety
/// `params` must be a live array; `arg` a live `ConstructDataPkey`.
unsafe extern "C" fn encoder_import_cb(params: *const OsslParam, arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is a live `ConstructDataPkey` per the contract.
    unsafe {
        let construct_data = arg.cast::<ConstructDataPkey>();
        let encoder_inst = (*construct_data).encoder_inst;
        let encoder = crate::encoder_lib::OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
        let encoderctx = crate::encoder_lib::OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);

        (*construct_data).constructed_obj = match (*encoder).import_object {
            Some(import_object) => import_object(encoderctx, (*construct_data).selection, params),
            None => ptr::null_mut(),
        };

        c_int::from(!(*construct_data).constructed_obj.is_null())
    }
}

/// `static const void *encoder_construct_pkey(OSSL_ENCODER_INSTANCE *encoder_inst, void *arg)` —
/// `encoder_pkey.c:176-204`.
///
/// The **provider identity test** is the point: when the encoder's provider is the key management's,
/// the key data is handed over directly (`data->obj = pk->keydata`); otherwise the key is
/// **exported** into the encoder's own object through `evp_keymgmt_export`, and a private-key
/// selection is widened to include the public half first. Both facts are the authority's.
///
/// # Safety
/// `encoder_inst` must be live; `arg` a live `ConstructDataPkey`.
unsafe extern "C" fn encoder_construct_pkey(
    encoder_inst: *mut OsslEncoderInstance,
    arg: *mut c_void,
) -> *const c_void {
    // SAFETY: `arg` is a live `ConstructDataPkey` per the contract.
    unsafe {
        let data = arg.cast::<ConstructDataPkey>();
        if (*data).obj.is_null() {
            let encoder = crate::encoder_lib::OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
            let pk = (*data).pk;
            let k_prov = EVP_KEYMGMT_get0_provider((*pk).keymgmt);
            let e_prov = OSSL_ENCODER_get0_provider(encoder);

            if k_prov != e_prov {
                let mut selection = (*data).selection;

                if selection & crate::evp::pkey::OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
                    selection |= crate::evp::pkey::OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
                }
                (*data).encoder_inst = encoder_inst;

                if evp_keymgmt_export(
                    (*pk).keymgmt,
                    (*pk).keydata,
                    selection,
                    Some(encoder_import_cb),
                    data.cast::<c_void>(),
                ) == 0
                {
                    return ptr::null();
                }
                (*data).obj = (*data).constructed_obj;
            } else {
                (*data).obj = (*pk).keydata;
            }
        }

        (*data).obj
    }
}

/// `static void encoder_destruct_pkey(void *arg)` — `encoder_pkey.c:206-219`.
///
/// # Safety
/// `arg` must be a live `ConstructDataPkey`.
unsafe extern "C" fn encoder_destruct_pkey(arg: *mut c_void) {
    // SAFETY: `arg` is a live `ConstructDataPkey` per the contract.
    unsafe {
        let data = arg.cast::<ConstructDataPkey>();
        let match_ = (*data).obj == (*data).constructed_obj;

        if !(*data).encoder_inst.is_null() {
            let encoder =
                crate::encoder_lib::OSSL_ENCODER_INSTANCE_get_encoder((*data).encoder_inst);
            if let Some(free_object) = (*encoder).free_object {
                free_object((*data).constructed_obj);
            }
        }
        (*data).constructed_obj = ptr::null_mut();
        if match_ {
            (*data).obj = ptr::null();
        }
    }
}

/// `static int ossl_encoder_ctx_setup_for_pkey(OSSL_ENCODER_CTX *ctx, const EVP_PKEY *pkey,
/// int selection, const char *propquery)` — `encoder_pkey.c:227-340`.
///
/// The two-pass collection, the cached ids, and the legacy-key short arm. `data` is the
/// `ConstructDataPkey` that is handed to the context (and not freed) when at least one encoder was
/// added; on **every** other path the authority's `err:` label frees it after clearing the
/// context's `construct_data`, which is what keeps a half-built context safe to release.
///
/// # Safety
/// `ctx` must be live; `pkey` must be live; `propquery` NULL or NUL-terminated.
unsafe fn ossl_encoder_ctx_setup_for_pkey(
    ctx: *mut OsslEncoderCtx,
    pkey: *const EvpPkey,
    selection: c_int,
    // The authority's `ossl_encoder_ctx_setup_for_pkey` declares `propquery` and never reads it
    // (it is threaded on to `OSSL_ENCODER_CTX_add_extra` by the *caller*, `encoder_pkey.c:388`);
    // the parameter is kept for signature fidelity.
    _propquery: *const c_char,
) -> c_int {
    let mut data: *mut ConstructDataPkey = ptr::null_mut();
    let mut prov: *const OsslProvider = ptr::null();
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut ok = 0;

    if ctx.is_null() || pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_PKEY_239) };
        return 0;
    }

    // SAFETY: `pkey` is live.
    unsafe {
        if evp_pkey_is_provided(pkey) != 0 {
            prov = EVP_KEYMGMT_get0_provider((*pkey).keymgmt);
            libctx = ossl_provider_libctx(prov);
        }

        if !(*pkey).keymgmt.is_null() {
            let mut encoder_data = CollectedEncoder {
                names: ptr::null_mut(),
                id_names: ptr::null_mut(),
                output_structure: (*ctx).output_structure,
                output_type: (*ctx).output_type,
                keymgmt_prov: prov,
                ctx,
                flag_find_same_provider: 0,
                error_occurred: 0,
            };

            data = CRYPTO_zalloc(size_of::<ConstructDataPkey>(), ptr::null(), 0)
                .cast::<ConstructDataPkey>();
            if data.is_null() {
                return setup_fail(ctx, data, ok);
            }

            /* First, collect the keymgmt names, then the encoders that match. */
            let mut keymgmt_data = CollectedNames {
                names: OPENSSL_sk_new_null(),
                error_occurred: 0,
            };
            if keymgmt_data.names.is_null() {
                raise_site(&err_sites::ENCODER_PKEY_261);
                return setup_fail(ctx, data, ok);
            }

            EVP_KEYMGMT_names_do_all(
                (*pkey).keymgmt,
                Some(collect_name),
                (&mut keymgmt_data as *mut CollectedNames).cast(),
            );
            if keymgmt_data.error_occurred != 0 {
                OPENSSL_sk_free(keymgmt_data.names);
                return setup_fail(ctx, data, ok);
            }

            encoder_data.names = keymgmt_data.names;

            /*
             * collect_encoder() is called many times, and for every call it converts all
             * encoder_data.names into namemap ids if it calls OSSL_ENCODER_is_a(). We cache the
             * ids here instead, and can use them for encoders with the same provider as the
             * keymgmt.
             */
            let namemap = ossl_namemap_stored(libctx);
            let end = OPENSSL_sk_num(encoder_data.names);
            if end > 0 {
                encoder_data.id_names =
                    CRYPTO_malloc_array(end as usize, size_of::<c_int>(), ptr::null(), 0)
                        .cast::<c_int>();
                if encoder_data.id_names.is_null() {
                    OPENSSL_sk_free(keymgmt_data.names);
                    return setup_fail(ctx, data, ok);
                }
                for i in 0..end {
                    let name = OPENSSL_sk_value(keymgmt_data.names, i).cast::<c_char>();
                    *encoder_data.id_names.add(i as usize) = ossl_namemap_name2num(namemap, name);
                }
            }
            /*
             * Place the encoders with a different provider as the keymgmt last (the chain is
             * processed in reverse order).
             */
            encoder_data.flag_find_same_provider = 0;
            OSSL_ENCODER_do_all_provided(
                libctx,
                collect_encoder_thunk,
                (&mut encoder_data as *mut CollectedEncoder).cast::<c_void>(),
            );

            /*
             * Place the encoders with the same provider as the keymgmt first (the chain is
             * processed in reverse order).
             */
            encoder_data.flag_find_same_provider = 1;
            OSSL_ENCODER_do_all_provided(
                libctx,
                collect_encoder_thunk,
                (&mut encoder_data as *mut CollectedEncoder).cast::<c_void>(),
            );

            CRYPTO_free(encoder_data.id_names.cast(), ptr::null(), 0);
            OPENSSL_sk_free(keymgmt_data.names);
            if encoder_data.error_occurred != 0 {
                raise_site(&err_sites::ENCODER_PKEY_316);
                return setup_fail(ctx, data, ok);
            }
        }

        if !data.is_null() && OSSL_ENCODER_CTX_get_num_encoders(ctx) != 0 {
            if OSSL_ENCODER_CTX_set_construct(ctx, Some(encoder_construct_pkey)) == 0
                || OSSL_ENCODER_CTX_set_construct_data(ctx, data.cast::<c_void>()) == 0
                || OSSL_ENCODER_CTX_set_cleanup(ctx, Some(encoder_destruct_pkey)) == 0
            {
                return setup_fail(ctx, data, ok);
            }

            (*data).pk = pkey;
            (*data).selection = selection;

            data = ptr::null_mut(); /* Avoid it being freed */
        }

        ok = 1;
    }

    // SAFETY: `ctx` is live and `data` is NULL or this call's own allocation.
    unsafe { setup_fail(ctx, data, ok) }
}

/// The `err:` label of [`ossl_encoder_ctx_setup_for_pkey`] — `encoder_pkey.c:334-339`.
///
/// # Safety
/// `ctx` live; `data` NULL or a live `ConstructDataPkey` this call allocated.
unsafe fn setup_fail(ctx: *mut OsslEncoderCtx, data: *mut ConstructDataPkey, ok: c_int) -> c_int {
    if !data.is_null() {
        // SAFETY: `ctx` is live and `data` is this call's own allocation.
        unsafe {
            OSSL_ENCODER_CTX_set_construct_data(ctx, ptr::null_mut());
            CRYPTO_free(data.cast(), ptr::null(), 0);
        }
    }
    ok
}

/// The `void (*)(OSSL_ENCODER *, void *)` shape `OSSL_ENCODER_do_all_provided` takes, wrapping
/// [`collect_encoder`]'s `void *` argument.
///
/// # Safety
/// `encoder` live; `arg` a live `CollectedEncoder`.
unsafe extern "C" fn collect_encoder_thunk(encoder: *mut OsslEncoder, arg: *mut c_void) {
    // SAFETY: as `collect_encoder`.
    unsafe { collect_encoder(encoder, arg) };
}

/// `OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_for_pkey(const EVP_PKEY *pkey, int selection,
/// const char *output_type, const char *output_struct, const char *propquery)` —
/// `encoder_pkey.c:342-408`.
///
/// **Two refusals before anything is built**: a NULL key and a key that is not assigned. The
/// assigned test is what makes `print_pkey` safe to call on a key built by `EVP_PKEY_set1_*` --
/// those are assigned (they have a legacy `pkey`), so the context is built and its count is 0.
///
/// # Safety
/// `pkey` must be live; the three strings NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ENCODER_CTX_new_for_pkey(
    pkey: *const EvpPkey,
    selection: c_int,
    output_type: *const c_char,
    output_struct: *const c_char,
    propquery: *const c_char,
) -> *mut OsslEncoderCtx {
    let mut libctx: *mut c_void = ptr::null_mut();

    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_PKEY_352) };
        return ptr::null_mut();
    }

    // SAFETY: `pkey` is live.
    if !unsafe { pkey_is_assigned(pkey) } {
        // SAFETY: a compile-time-constant site, with the authority's own message text.
        unsafe {
            raise_site_data(
                &err_sites::ENCODER_PKEY_357,
                c"The passed EVP_PKEY must be assigned a key".as_ptr(),
            )
        };
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let ctx = unsafe { OSSL_ENCODER_CTX_new() };
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ENCODER_PKEY_363) };
        return ptr::null_mut();
    }

    // SAFETY: `pkey` is live.
    unsafe {
        if evp_pkey_is_provided(pkey) != 0 {
            let prov = EVP_KEYMGMT_get0_provider((*pkey).keymgmt);
            libctx = ossl_provider_libctx(prov);
        }
    }

    // SAFETY: `ctx` is live; every call below takes the caller's own strings.
    let built = unsafe {
        OSSL_ENCODER_CTX_set_output_type(ctx, output_type) != 0
            && (output_struct.is_null()
                || OSSL_ENCODER_CTX_set_output_structure(ctx, output_struct) != 0)
            && OSSL_ENCODER_CTX_set_selection(ctx, selection) != 0
            && ossl_encoder_ctx_setup_for_pkey(ctx, pkey, selection, propquery) != 0
            && OSSL_ENCODER_CTX_add_extra(ctx, libctx, propquery) != 0
    };
    if built {
        // SAFETY: `pkey` is live (checked at the top of the function).
        let mut save_parameters = unsafe { (*pkey).save_parameters };
        // SAFETY: the constructor fills a descriptor over this frame's `save_parameters`.
        let params: [OsslParam; 2] = unsafe {
            [
                OSSL_PARAM_construct_int(OSSL_ENCODER_PARAM_SAVE_PARAMETERS, &mut save_parameters),
                OSSL_PARAM_construct_end(),
            ]
        };
        /* ignoring error as this is only auxiliary parameter */
        // SAFETY: `ctx` is live and `params` is terminated.
        unsafe { OSSL_ENCODER_CTX_set_params(ctx, params.as_ptr()) };
        return ctx;
    }

    // SAFETY: `ctx` is live and this call owns it.
    unsafe { crate::encoder_meth::OSSL_ENCODER_CTX_free(ctx) };
    ptr::null_mut()
}
