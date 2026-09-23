//! Phase 8 — `providers/implementations/asymciphers/rsa_enc.c`: the `RSA`
//! `OSSL_OP_ASYM_CIPHER` row.
//!
//! The unit is the *encryption* face of the `RSA` key object `src/provider/rsa_kmgmt.rs`
//! publishes (D391): `PROV_RSA_CTX` holds an `RSA` borrow, the pad mode, an OAEP digest and an
//! MGF1 digest, an OAEP label, and the TLS client/negotiated versions for the one padding mode
//! that has no `RSA_METHOD` member. `rsa_encrypt`/`rsa_decrypt` route on the pad mode, and the two
//! `RSA_PKCS1_WITH_TLS_PADDING` arms are the only readers of `client_version`/`alt_version`.
//!
//! ## The one prerequisite, and it is not the pair this stratum already had
//!
//! `rsa_init` calls `ossl_rsa_key_op_get_protect` (`:111`, landed with D395), and `rsa_decrypt`'s
//! TLS arm calls `crypto/rsa/rsa_pk1.c`'s `ossl_rsa_padding_check_PKCS1_type_2_TLS` (`:307`). That
//! fourth `rsa_pk1.c` padding function is **not** one of the fifteen this stratum transcribed: D285
//! recorded it as a Phase 9 hand-off on `RAND_priv_bytes_ex`, D323 corrected the coordinate, and
//! it lands here with the provider row that is its only caller. Everything else the unit reaches is
//! already landed (`ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex`, `RSA_padding_check_PKCS1_OAEP_mgf1`,
//! `RSA_public_encrypt`/`RSA_private_decrypt`, the constant-time helpers).
//!
//! ## The three arms that are absent, and why
//!
//! The `FIPS_MODULE` PKCS#1 v1.5 refusal in `rsa_encrypt` (`:166-176`) and `rsa_init`'s
//! `ossl_fips_ind_rsa_key_check` (`:133-138`) are not this profile's arm (D235), so `rsa_encrypt`
//! has no padding refusal on this profile and the `ind`/`ind_k`/`ind_pad` keys are absent from the
//! generated decoders and lists. `OSSL_FIPS_IND_SET_APPROVED` is a no-op.
//!
//! ## The `OPENSSL_*` allocation family
//!
//! `rsa_encrypt`/`rsa_decrypt` use `OPENSSL_malloc`/`OPENSSL_free` for their temporary buffers and
//! `rsa_dupctx` uses `OPENSSL_memdup`; each is the `CRYPTO_*` form with this unit's own `__FILE__`
//! and the authority's line, exactly as `rsa_sig.c.in`'s allocations are.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::asymcipher::{
    OSSL_FUNC_ASYM_CIPHER_DECRYPT, OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
    OSSL_FUNC_ASYM_CIPHER_DUPCTX, OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
    OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, OSSL_FUNC_ASYM_CIPHER_FREECTX,
    OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_NEWCTX, OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_up_ref, EvpMd};
use crate::evp::pkey_ctx::{
    EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCRYPT, RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING,
    RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PKCS1_WITH_TLS_PADDING,
};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr, OSSL_PARAM_set_uint,
    OSSL_PARAM_set_utf8_string, OsslParam, END, OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{
    param_int, param_octet_ptr, param_octet_string, param_uint, param_utf8_string,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::securitycheck::ossl_rsa_key_op_get_protect;
use crate::rsa::object::{
    RSA_free, RSA_private_decrypt, RSA_public_encrypt, RSA_size, RSA_test_flags, RSA_up_ref,
    RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA,
};
use crate::rsa::ossl::RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING;
use crate::rsa::Rsa;
use crate::rsa::{
    ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex, ossl_rsa_padding_check_PKCS1_type_2_TLS,
    RSA_padding_check_PKCS1_OAEP_mgf1,
};
use crate::runtime::constant_time::{
    constant_time_msb_s, constant_time_msb_u32, constant_time_select, constant_time_select_int,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc};

/// The unit's own `__FILE__`. `rsa_enc.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path (D235's finding).
const FILE: *const c_char = c"providers/implementations/asymciphers/rsa_enc.c".as_ptr();

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_MAX_PROPQUERY_SIZE` — `include/internal/sizes.h:19`.
const OSSL_MAX_PROPQUERY_SIZE: usize = 256;

/// `SSL_MAX_MASTER_KEY_LENGTH` — `include/openssl/prov_ssl.h:20`.
const SSL_MAX_MASTER_KEY_LENGTH: usize = 48;

/// `OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST` — `core_names.h:142`, which is `OSSL_ALG_PARAM_DIGEST`.
const OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST: *const c_char = c"digest".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS` — `core_names.h:143`.
const OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS: *const c_char = c"digest-props".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_PAD_MODE` — `core_names.h:145`, which is `OSSL_PKEY_PARAM_PAD_MODE`.
const OSSL_ASYM_CIPHER_PARAM_PAD_MODE: *const c_char = c"pad-mode".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST` — `core_names.h:140`.
const OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST: *const c_char = c"mgf1-digest".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS` — `core_names.h:141`.
const OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS: *const c_char = c"mgf1-properties".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL` — `core_names.h:144`.
const OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL: *const c_char = c"oaep-label".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION` — `core_names.h:147`.
const OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION: *const c_char = c"tls-client-version".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION` — `core_names.h:148`.
const OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION: *const c_char =
    c"tls-negotiated-version".as_ptr();

/// `OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION` — `core_names.h:139`.
const OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION: *const c_char = c"implicit-rejection".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_PKCSV15` — `core_names.h:89`.
const OSSL_PKEY_RSA_PAD_MODE_PKCSV15: *const c_char = c"pkcs1".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_NONE` — `core_names.h:88`.
const OSSL_PKEY_RSA_PAD_MODE_NONE: *const c_char = c"none".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_OAEP` — `core_names.h:90`.
const OSSL_PKEY_RSA_PAD_MODE_OAEP: *const c_char = c"oaep".as_ptr();

/// `PROV_RSA_CTX` — `rsa_enc.c.in:67-85`. The `OSSL_FIPS_IND_DECLARE` at the foot is empty on this
/// profile.
#[repr(C)]
struct ProvRsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `RSA *rsa` — a borrow carrying a reference.
    rsa: *mut Rsa,
    /// `int pad_mode`.
    pad_mode: c_int,
    /// `int operation` — reuses `EVP_PKEY_OP_*`.
    operation: c_int,
    /// `EVP_MD *oaep_md` — the OAEP message digest.
    oaep_md: *mut EvpMd,
    /// `EVP_MD *mgf1_md`.
    mgf1_md: *mut EvpMd,
    /// `unsigned char *oaep_label` — owned.
    oaep_label: *mut u8,
    /// `size_t oaep_labellen`.
    oaep_labellen: usize,
    /// `unsigned int client_version` — TLS padding.
    client_version: c_uint,
    /// `unsigned int alt_version` — TLS padding.
    alt_version: c_uint,
    /// `unsigned int implicit_rejection` — PKCS#1 v1.5 decryption mode.
    implicit_rejection: c_uint,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static int name2id(...)`/`padding_item[]` — `rsa_enc.c.in:53-59`, the pad-mode number/name map
/// both directions walk. The fourth entry is the authority's own `"oeap"` misspelling, kept first
/// as a second alias for `RSA_PKCS1_OAEP_PADDING`: the comment "Correct spelling first" is why the
/// exact spelling wins the linear search.
struct PaddingItem {
    id: c_int,
    ptr: *const c_char,
}

// SAFETY: every `ptr` is a `'static` literal and nothing mutates the table.
unsafe impl Sync for PaddingItem {}

static PADDING_ITEM: [PaddingItem; 5] = [
    PaddingItem {
        id: RSA_PKCS1_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_PKCSV15,
    },
    PaddingItem {
        id: RSA_NO_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_NONE,
    },
    PaddingItem {
        id: RSA_PKCS1_OAEP_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_OAEP,
    },
    PaddingItem {
        id: RSA_PKCS1_OAEP_PADDING,
        ptr: c"oeap".as_ptr(),
    },
    PaddingItem {
        id: 0,
        ptr: ptr::null(),
    },
];

/// `static void *rsa_newctx(void *provctx)` — `rsa_enc.c.in:87-100`.
///
/// # Safety
/// The asym_cipher `newctx` dispatch contract.
unsafe extern "C" fn rsa_newctx(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let prsactx = CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 93).cast::<ProvRsaCtx>();
    if prsactx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prsactx` is this call's own allocation.
    unsafe {
        (*prsactx).libctx = prov_libctx_of(provctx);
    }
    prsactx.cast()
}

/// `static int rsa_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation, const
/// char *desc)` — `rsa_enc.c.in:102-140`, without the `FIPS_MODULE` tail (`:133-138`).
///
/// # Safety
/// The asym_cipher `encrypt_init`/`decrypt_init` dispatch contract.
unsafe fn rsa_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut protect: c_int = 0;

    if is_running() == 0 || prsactx.is_null() || vrsa.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context and `vrsa` is the caller's key.
    unsafe {
        if ossl_rsa_key_op_get_protect(vrsa.cast::<Rsa>(), operation, &mut protect) == 0 {
            return 0;
        }
        if RSA_up_ref(vrsa.cast::<Rsa>()) == 0 {
            return 0;
        }
        RSA_free((*prsactx).rsa);
        (*prsactx).rsa = vrsa.cast::<Rsa>();
        (*prsactx).operation = operation;
        (*prsactx).implicit_rejection = 1;

        match RSA_test_flags((*prsactx).rsa, RSA_FLAG_TYPE_MASK) {
            RSA_FLAG_TYPE_RSA => {
                (*prsactx).pad_mode = RSA_PKCS1_PADDING;
            }
            _ => {
                /* This should not happen due to the check above */
                raise_site(&err_sites::PROV_RSA_ENC_124);
                return 0;
            }
        }

        if rsa_set_ctx_params(vprsactx, params) == 0 {
            return 0;
        }
    }

    1
}

/// `static int rsa_encrypt_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_enc.c.in:142-147`.
///
/// # Safety
/// The asym_cipher `encrypt_init` dispatch contract.
unsafe extern "C" fn rsa_encrypt_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_init(
            vprsactx,
            vrsa,
            params,
            EVP_PKEY_OP_ENCRYPT,
            c"RSA Encrypt Init".as_ptr(),
        )
    }
}

/// `static int rsa_decrypt_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_enc.c.in:149-154`.
///
/// # Safety
/// The asym_cipher `decrypt_init` dispatch contract.
unsafe extern "C" fn rsa_decrypt_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_init(
            vprsactx,
            vrsa,
            params,
            EVP_PKEY_OP_DECRYPT,
            c"RSA Decrypt Init".as_ptr(),
        )
    }
}

/// `static int rsa_encrypt(void *vprsactx, unsigned char *out, size_t *outlen, size_t outsize,
/// const unsigned char *in, size_t inlen)` — `rsa_enc.c.in:156-230`, without the `FIPS_MODULE`
/// PKCS#1 v1.5 refusal (`:166-176`).
///
/// # Safety
/// The asym_cipher `encrypt` dispatch contract.
unsafe extern "C" fn rsa_encrypt(
    vprsactx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    outsize: usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        let len = RSA_size((*prsactx).rsa) as usize;

        if len == 0 {
            raise_site(&err_sites::PROV_RSA_ENC_177);
            return 0;
        }

        if out.is_null() {
            *outlen = len;
            return 1;
        }

        if outsize < len {
            raise_site(&err_sites::PROV_RSA_ENC_187);
            return 0;
        }

        let mut ret: c_int;
        if (*prsactx).pad_mode == RSA_PKCS1_OAEP_PADDING {
            let rsasize = RSA_size((*prsactx).rsa);

            let tbuf = CRYPTO_malloc(rsasize as usize, FILE, 197).cast::<u8>();
            if tbuf.is_null() {
                return 0;
            }
            if (*prsactx).oaep_md.is_null() {
                (*prsactx).oaep_md =
                    EVP_MD_fetch((*prsactx).libctx, c"SHA-1".as_ptr(), ptr::null());
                if (*prsactx).oaep_md.is_null() {
                    CRYPTO_free(tbuf.cast(), FILE, 202);
                    raise_site(&err_sites::PROV_RSA_ENC_201);
                    return 0;
                }
            }
            ret = ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(
                (*prsactx).libctx,
                tbuf,
                rsasize,
                input,
                inlen as c_int,
                (*prsactx).oaep_label,
                (*prsactx).oaep_labellen as c_int,
                (*prsactx).oaep_md,
                (*prsactx).mgf1_md,
            );

            if ret == 0 {
                CRYPTO_free(tbuf.cast(), FILE, 215);
                return 0;
            }
            ret = RSA_public_encrypt(rsasize, tbuf, out, (*prsactx).rsa, RSA_NO_PADDING);
            CRYPTO_free(tbuf.cast(), FILE, 220);
        } else {
            ret = RSA_public_encrypt(
                inlen as c_int,
                input,
                out,
                (*prsactx).rsa,
                (*prsactx).pad_mode,
            );
        }
        /* A ret value of 0 is not an error */
        if ret < 0 {
            return ret;
        }
        *outlen = ret as usize;
    }
    1
}

/// `static int rsa_decrypt(void *vprsactx, unsigned char *out, size_t *outlen, size_t outsize,
/// const unsigned char *in, size_t inlen)` — `rsa_enc.c.in:232-322`.
///
/// # Safety
/// The asym_cipher `decrypt` dispatch contract.
unsafe extern "C" fn rsa_decrypt(
    vprsactx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    outsize: usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        let len = RSA_size((*prsactx).rsa) as usize;
        let pad_mode: c_int;

        if (*prsactx).pad_mode == RSA_PKCS1_WITH_TLS_PADDING {
            if out.is_null() {
                *outlen = SSL_MAX_MASTER_KEY_LENGTH;
                return 1;
            }
            if outsize < SSL_MAX_MASTER_KEY_LENGTH {
                raise_site(&err_sites::PROV_RSA_ENC_247);
                return 0;
            }
        } else {
            if out.is_null() {
                if len == 0 {
                    raise_site(&err_sites::PROV_RSA_ENC_253);
                    return 0;
                }
                *outlen = len;
                return 1;
            }

            if outsize < len {
                raise_site(&err_sites::PROV_RSA_ENC_261);
                return 0;
            }
        }

        let mut ret: c_int;
        if (*prsactx).pad_mode == RSA_PKCS1_OAEP_PADDING
            || (*prsactx).pad_mode == RSA_PKCS1_WITH_TLS_PADDING
        {
            let tbuf = CRYPTO_malloc(len, FILE, 272).cast::<u8>();
            if tbuf.is_null() {
                return 0;
            }
            ret = RSA_private_decrypt(inlen as c_int, input, tbuf, (*prsactx).rsa, RSA_NO_PADDING);
            /*
             * With no padding then, on success ret should be len, otherwise an
             * error occurred (non-constant time)
             */
            if ret != len as c_int {
                CRYPTO_free(tbuf.cast(), FILE, 281);
                raise_site(&err_sites::PROV_RSA_ENC_280);
                return 0;
            }
            if (*prsactx).pad_mode == RSA_PKCS1_OAEP_PADDING {
                if (*prsactx).oaep_md.is_null() {
                    (*prsactx).oaep_md =
                        EVP_MD_fetch((*prsactx).libctx, c"SHA-1".as_ptr(), ptr::null());
                    if (*prsactx).oaep_md.is_null() {
                        CRYPTO_free(tbuf.cast(), FILE, 289);
                        raise_site(&err_sites::PROV_RSA_ENC_288);
                        return 0;
                    }
                }
                ret = RSA_padding_check_PKCS1_OAEP_mgf1(
                    out,
                    outsize as c_int,
                    tbuf,
                    len as c_int,
                    len as c_int,
                    (*prsactx).oaep_label,
                    (*prsactx).oaep_labellen as c_int,
                    (*prsactx).oaep_md,
                    (*prsactx).mgf1_md,
                );
            } else {
                /* RSA_PKCS1_WITH_TLS_PADDING */
                if (*prsactx).client_version == 0 {
                    raise_site(&err_sites::PROV_RSA_ENC_301);
                    CRYPTO_free(tbuf.cast(), FILE, 304);
                    return 0;
                }
                ret = ossl_rsa_padding_check_PKCS1_type_2_TLS(
                    (*prsactx).libctx,
                    out,
                    outsize,
                    tbuf,
                    len,
                    (*prsactx).client_version as c_int,
                    (*prsactx).alt_version as c_int,
                );
            }
            CRYPTO_free(tbuf.cast(), FILE, 311);
        } else {
            if (*prsactx).implicit_rejection == 0 && (*prsactx).pad_mode == RSA_PKCS1_PADDING {
                pad_mode = RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING;
            } else {
                pad_mode = (*prsactx).pad_mode;
            }
            ret = RSA_private_decrypt(inlen as c_int, input, out, (*prsactx).rsa, pad_mode);
        }
        *outlen = constant_time_select(constant_time_msb_s(ret as usize), *outlen, ret as usize);
        ret = constant_time_select_int(constant_time_msb_u32(ret as u32), 0, 1);
        ret
    }
}

/// `static void rsa_freectx(void *vprsactx)` — `rsa_enc.c.in:324-335`.
///
/// # Safety
/// The asym_cipher `freectx` dispatch contract.
unsafe extern "C" fn rsa_freectx(vprsactx: *mut c_void) {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is this call's context.
    unsafe {
        RSA_free((*prsactx).rsa);
        EVP_MD_free((*prsactx).oaep_md);
        EVP_MD_free((*prsactx).mgf1_md);
        CRYPTO_free((*prsactx).oaep_label.cast(), FILE, 332);
        CRYPTO_free(prsactx.cast(), FILE, 334);
    }
}

/// `static void *rsa_dupctx(void *vprsactx)` — `rsa_enc.c.in:337-375`.
///
/// # Safety
/// The asym_cipher `dupctx` dispatch contract.
unsafe extern "C" fn rsa_dupctx(vprsactx: *mut c_void) -> *mut c_void {
    let srcctx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's context.
    unsafe {
        let dstctx =
            CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 345).cast::<ProvRsaCtx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        // The authority's `*dstctx = *srcctx` is a whole-struct assignment; the pointer copy is
        // that assignment, and each borrowed member is then up-ref'd in place.
        core::ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        if !(*dstctx).rsa.is_null() && RSA_up_ref((*dstctx).rsa) == 0 {
            CRYPTO_free(dstctx.cast(), FILE, 351);
            return ptr::null_mut();
        }

        if !(*dstctx).oaep_md.is_null() && EVP_MD_up_ref((*dstctx).oaep_md) == 0 {
            RSA_free((*dstctx).rsa);
            CRYPTO_free(dstctx.cast(), FILE, 357);
            return ptr::null_mut();
        }

        if !(*dstctx).mgf1_md.is_null() && EVP_MD_up_ref((*dstctx).mgf1_md) == 0 {
            RSA_free((*dstctx).rsa);
            EVP_MD_free((*dstctx).oaep_md);
            CRYPTO_free(dstctx.cast(), FILE, 364);
            return ptr::null_mut();
        }

        if !(*dstctx).oaep_label.is_null() {
            let dup = CRYPTO_memdup(
                (*dstctx).oaep_label.cast(),
                (*dstctx).oaep_labellen,
                FILE,
                369,
            )
            .cast::<u8>();
            if dup.is_null() {
                rsa_freectx(dstctx.cast());
                return ptr::null_mut();
            }
            (*dstctx).oaep_label = dup;
        }

        dstctx.cast()
    }
}

/// `struct rsa_get_ctx_params_st` — the `produce_param_decoder` expansion at `rsa_enc.c:394-402`,
/// without its `fips` field.
#[derive(Clone, Copy)]
struct GetCtxParams {
    oaep: *const OsslParam,
    imrej: *const OsslParam,
    mgf1: *const OsslParam,
    label: *const OsslParam,
    pad: *const OsslParam,
    tlsver: *const OsslParam,
    negver: *const OsslParam,
}

/// `rsa_get_ctx_params_decoder` — the generated get decoder.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        oaep: ptr::null(),
        imrej: ptr::null(),
        mgf1: ptr::null(),
        label: ptr::null(),
        pad: ptr::null(),
        tlsver: ptr::null(),
        negver: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"digest" => {
                    if !r.oaep.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_425);
                        return None;
                    }
                    r.oaep = p;
                }
                b"implicit-rejection" => {
                    if !r.imrej.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_449);
                        return None;
                    }
                    r.imrej = p;
                }
                b"mgf1-digest" => {
                    if !r.mgf1.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_460);
                        return None;
                    }
                    r.mgf1 = p;
                }
                b"oaep-label" => {
                    if !r.label.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_471);
                        return None;
                    }
                    r.label = p;
                }
                b"pad-mode" => {
                    if !r.pad.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_482);
                        return None;
                    }
                    r.pad = p;
                }
                b"tls-client-version" => {
                    if !r.tlsver.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_509);
                        return None;
                    }
                    r.tlsver = p;
                }
                b"tls-negotiated-version" => {
                    if !r.negver.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_520);
                        return None;
                    }
                    r.negver = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsa_get_ctx_params_list[]` — `rsa_enc.c:378-391`, without the
/// `FIPS_MODULE` entry.
static RSA_GET_CTX_PARAMS_LIST: [OsslParam; 9] = [
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE),
    param_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST),
    param_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL),
    param_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION),
    param_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION),
    param_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION),
    END,
];

/// `static int rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)` —
/// `rsa_enc.c:605-670`.
///
/// # Safety
/// The asym_cipher `get_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_get_ctx_params(vprsactx: *mut c_void, params: *mut OsslParam) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        let Some(p) = rsa_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.pad.is_null() {
            if (*p.pad).data_type != OSSL_PARAM_UTF8_STRING {
                /* Support for legacy pad mode number */
                if OSSL_PARAM_set_int(p.pad.cast_mut(), (*prsactx).pad_mode) == 0 {
                    return 0;
                }
            } else {
                let mut word: *const c_char = ptr::null();

                let mut i = 0usize;
                while PADDING_ITEM[i].id != 0 {
                    if (*prsactx).pad_mode == PADDING_ITEM[i].id {
                        word = PADDING_ITEM[i].ptr;
                        break;
                    }
                    i += 1;
                }

                if !word.is_null() {
                    if OSSL_PARAM_set_utf8_string(p.pad.cast_mut(), word) == 0 {
                        return 0;
                    }
                } else {
                    raise_site(&err_sites::PROV_RSA_ENC_565);
                }
            }
        }

        if !p.oaep.is_null() {
            let name = if (*prsactx).oaep_md.is_null() {
                c"".as_ptr()
            } else {
                EVP_MD_get0_name((*prsactx).oaep_md)
            };
            if OSSL_PARAM_set_utf8_string(p.oaep.cast_mut(), name) == 0 {
                return 0;
            }
        }

        if !p.mgf1.is_null() {
            let mgf1_md = if (*prsactx).mgf1_md.is_null() {
                (*prsactx).oaep_md
            } else {
                (*prsactx).mgf1_md
            };
            let name = if mgf1_md.is_null() {
                c"".as_ptr()
            } else {
                EVP_MD_get0_name(mgf1_md)
            };
            if OSSL_PARAM_set_utf8_string(p.mgf1.cast_mut(), name) == 0 {
                return 0;
            }
        }

        if !p.label.is_null()
            && OSSL_PARAM_set_octet_ptr(
                p.label.cast_mut(),
                (*prsactx).oaep_label.cast(),
                (*prsactx).oaep_labellen,
            ) == 0
        {
            return 0;
        }

        if !p.tlsver.is_null()
            && OSSL_PARAM_set_uint(p.tlsver.cast_mut(), (*prsactx).client_version) == 0
        {
            return 0;
        }

        if !p.negver.is_null()
            && OSSL_PARAM_set_uint(p.negver.cast_mut(), (*prsactx).alt_version) == 0
        {
            return 0;
        }

        if !p.imrej.is_null()
            && OSSL_PARAM_set_uint(p.imrej.cast_mut(), (*prsactx).implicit_rejection) == 0
        {
            return 0;
        }
    }

    1
}

/// `static const OSSL_PARAM *rsa_gettable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_enc.c:458-462`.
///
/// # Safety
/// The asym_cipher `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_gettable_ctx_params(
    _vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct rsa_set_ctx_params_st` — `rsa_enc.c:383-...`, without its two `fips` fields.
#[derive(Clone, Copy)]
struct SetCtxParams {
    oaep: *const OsslParam,
    oaep_pq: *const OsslParam,
    pad: *const OsslParam,
    mgf1: *const OsslParam,
    mgf1_pq: *const OsslParam,
    label: *const OsslParam,
    tlsver: *const OsslParam,
    negver: *const OsslParam,
    imrej: *const OsslParam,
}

/// `rsa_set_ctx_params_decoder` — the generated set decoder.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        oaep: ptr::null(),
        oaep_pq: ptr::null(),
        pad: ptr::null(),
        mgf1: ptr::null(),
        mgf1_pq: ptr::null(),
        label: ptr::null(),
        tlsver: ptr::null(),
        negver: ptr::null(),
        imrej: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"digest" => {
                    if !r.oaep.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_703);
                        return None;
                    }
                    r.oaep = p;
                }
                b"digest-props" => {
                    if !r.oaep_pq.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_694);
                        return None;
                    }
                    r.oaep_pq = p;
                }
                b"implicit-rejection" => {
                    if !r.imrej.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_719);
                        return None;
                    }
                    r.imrej = p;
                }
                b"mgf1-digest" => {
                    if !r.mgf1.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_763);
                        return None;
                    }
                    r.mgf1 = p;
                }
                b"mgf1-properties" => {
                    if !r.mgf1_pq.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_774);
                        return None;
                    }
                    r.mgf1_pq = p;
                }
                b"oaep-label" => {
                    if !r.label.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_790);
                        return None;
                    }
                    r.label = p;
                }
                b"pad-mode" => {
                    if !r.pad.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_801);
                        return None;
                    }
                    r.pad = p;
                }
                b"tls-client-version" => {
                    if !r.tlsver.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_841);
                        return None;
                    }
                    r.tlsver = p;
                }
                b"tls-negotiated-version" => {
                    if !r.negver.is_null() {
                        raise_site(&err_sites::PROV_RSA_ENC_852);
                        return None;
                    }
                    r.negver = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsa_set_ctx_params_list[]` — `rsa_enc.c:613-630`, without the two
/// `FIPS_MODULE` entries.
static RSA_SET_CTX_PARAMS_LIST: [OsslParam; 11] = [
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE),
    param_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST),
    param_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS),
    param_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL),
    param_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION),
    param_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION),
    param_uint(OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION),
    END,
];

/// `static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])` —
/// `rsa_enc.c:481-605`, without the two `OSSL_FIPS_IND_SET_CTX_FROM_PARAM` calls (literals here).
///
/// # Safety
/// The asym_cipher `set_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_set_ctx_params(vprsactx: *mut c_void, params: *const OsslParam) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        let Some(p) = rsa_set_ctx_params_decoder(params) else {
            return 0;
        };

        let mut mdname = [0 as c_char; OSSL_MAX_NAME_SIZE];
        let mut mdprops = [0 as c_char; OSSL_MAX_PROPQUERY_SIZE];
        let mut str_ptr: *mut c_char;

        if !p.oaep.is_null() {
            str_ptr = mdname.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.oaep, &mut str_ptr, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }

            if !p.oaep_pq.is_null() {
                str_ptr = mdprops.as_mut_ptr();
                if OSSL_PARAM_get_utf8_string(p.oaep_pq, &mut str_ptr, OSSL_MAX_PROPQUERY_SIZE) == 0
                {
                    return 0;
                }
            }

            EVP_MD_free((*prsactx).oaep_md);
            (*prsactx).oaep_md = EVP_MD_fetch((*prsactx).libctx, mdname.as_ptr(), mdprops.as_ptr());

            if (*prsactx).oaep_md.is_null() {
                return 0;
            }
        }

        if !p.pad.is_null() {
            let mut pad_mode: c_int = 0;

            if (*p.pad).data_type != OSSL_PARAM_UTF8_STRING {
                /* Support for legacy pad mode as a number */
                if OSSL_PARAM_get_int(p.pad, &mut pad_mode) == 0 {
                    return 0;
                }
            } else {
                if (*p.pad).data.is_null() {
                    return 0;
                }

                let data = CStr::from_ptr((*p.pad).data.cast()).to_bytes();
                let mut i = 0usize;
                while PADDING_ITEM[i].id != 0 {
                    if CStr::from_ptr(PADDING_ITEM[i].ptr).to_bytes() == data {
                        pad_mode = PADDING_ITEM[i].id;
                        break;
                    }
                    i += 1;
                }
            }

            /*
             * PSS padding is for signatures only so is not compatible with
             * asymmetric cipher use.
             */
            if pad_mode == RSA_PKCS1_PSS_PADDING {
                return 0;
            }
            if pad_mode == RSA_PKCS1_OAEP_PADDING && (*prsactx).oaep_md.is_null() {
                (*prsactx).oaep_md =
                    EVP_MD_fetch((*prsactx).libctx, c"SHA1".as_ptr(), mdprops.as_ptr());
                if (*prsactx).oaep_md.is_null() {
                    return 0;
                }
            }
            (*prsactx).pad_mode = pad_mode;
        }

        if !p.mgf1.is_null() {
            str_ptr = mdname.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.mgf1, &mut str_ptr, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }

            if !p.mgf1_pq.is_null() {
                str_ptr = mdprops.as_mut_ptr();
                if OSSL_PARAM_get_utf8_string(p.mgf1_pq, &mut str_ptr, OSSL_MAX_PROPQUERY_SIZE) == 0
                {
                    return 0;
                }
            } else {
                str_ptr = ptr::null_mut();
            }

            EVP_MD_free((*prsactx).mgf1_md);
            (*prsactx).mgf1_md = EVP_MD_fetch((*prsactx).libctx, mdname.as_ptr(), str_ptr);

            if (*prsactx).mgf1_md.is_null() {
                return 0;
            }
        }

        if !p.label.is_null() {
            let mut tmp_label: *mut c_void = ptr::null_mut();
            let mut tmp_labellen: usize = 0;

            if OSSL_PARAM_get_octet_string(p.label, &mut tmp_label, 0, &mut tmp_labellen) == 0 {
                return 0;
            }
            CRYPTO_free((*prsactx).oaep_label.cast(), FILE, 576);
            (*prsactx).oaep_label = tmp_label.cast::<u8>();
            (*prsactx).oaep_labellen = tmp_labellen;
        }

        if !p.tlsver.is_null() {
            let mut client_version: c_uint = 0;

            if OSSL_PARAM_get_uint(p.tlsver, &mut client_version) == 0 {
                return 0;
            }
            (*prsactx).client_version = client_version;
        }

        if !p.negver.is_null() {
            let mut alt_version: c_uint = 0;

            if OSSL_PARAM_get_uint(p.negver, &mut alt_version) == 0 {
                return 0;
            }
            (*prsactx).alt_version = alt_version;
        }

        if !p.imrej.is_null() {
            let mut implicit_rejection: c_uint = 0;

            if OSSL_PARAM_get_uint(p.imrej, &mut implicit_rejection) == 0 {
                return 0;
            }
            (*prsactx).implicit_rejection = implicit_rejection;
        }
    }
    1
}

/// `static const OSSL_PARAM *rsa_settable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_enc.c:607-611`.
///
/// # Safety
/// The asym_cipher `settable_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_settable_ctx_params(
    _vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `const OSSL_DISPATCH ossl_rsa_asym_cipher_functions[]` — `rsa_enc.c:613-630`.
pub(crate) static RSA_ASYM_CIPHER_FUNCTIONS: [OsslDispatch; 12] = [
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_NEWCTX,
        function: rsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
        function: rsa_encrypt_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
        function: rsa_encrypt as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
        function: rsa_decrypt_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DECRYPT,
        function: rsa_decrypt as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_FREECTX,
        function: rsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_DUPCTX,
        function: rsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
        function: rsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
        function: rsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
        function: rsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
        function: rsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
