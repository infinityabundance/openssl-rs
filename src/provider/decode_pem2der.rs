//! Phase 10.5 — `providers/implementations/encode_decode/decode_pem2der.c`: the provider's
//! **PEM-to-DER decoder** — one `OSSL_OP_DECODER` table published by both the `default` and the
//! `base` provider.
//!
//! It is the front of the whole decoder chain: it reads a PEM block, names it against a fixed
//! `pem_name_map[]` of the eighteen blocks OpenSSL writes, and then either hands the DER to one of
//! the two engines beside it — [`ossl_epki2pki_der_decode`] for the `PKCS#8` arms and
//! [`ossl_spki2typespki_der_decode`](crate::provider::decode_spki2typespki::ossl_spki2typespki_der_decode)
//! for the `PUBLIC KEY` arms — or announces a type-specific structure for the DER-to-key chain.
//!
//! ## Provenance and closure
//!
//! `nm --undefined-only` over the authority's `libdefault-lib-decode_pem2der.o` names no name this
//! crate did not already have once this slice's sibling `decode_spki2typespki.c` lands:
//! `ossl_spki2typespki_der_decode` is the only one, and it is the unit next door. The PEM machinery
//! (`PEM_read_bio`, `PEM_get_EVP_CIPHER_INFO`, `PEM_do_header`, `EVP_BytesToKey`) was landed by
//! Phases 4 and 9, and `ossl_epki2pki_der_decode` by D445's `decode_epki2pki.rs`. The unit is
//! transcribed whole; there is no withheld arm.
//!
//! ## The `pem_name_map[]` constants
//!
//! Seven of the eighteen `PEM_STRING_*` blocks in the table — `X509`, `X509_TRUSTED`, `X509_OLD`,
//! `X509_CRL`, `DSA_PUBLIC`, `SM2PRIVATEKEY` and `SM2PARAMETERS` — are named here for the first
//! time by a landed path, so they are added to [`crate::pem::pem_lib`] (their authority home)
//! rather than typed into this module. The other eleven were already there.
//!
//! ## Error coordinates
//!
//! This is a generated `.c.in` (`decode_pem2der.c.in`), so its `__FILE__` is the build-relative
//! `providers/implementations/encode_decode/decode_pem2der.c`. Its two `ERR_raise*` sites are the
//! machine-generated `set_ctx_params` parser's `PROV_R_REPEATED_PARAMETER`, one for `data-structure`
//! (`:114`) and one for `properties` (`:125`); `forensics/tools/gen_err_raise_sites.py` now carries
//! both, so they are not local declarations.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
};
use crate::evp::pem_bridge::{EvpCipherInfo, PEM_get_EVP_CIPHER_INFO, PEM_read_bio, PemPasswordCb};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string, OsslParam, END,
};
use crate::passphrase::OsslPassphraseCallback;
use crate::pem::pem_lib::{
    PEM_do_header, PEM_STRING_DHPARAMS, PEM_STRING_DHXPARAMS, PEM_STRING_DSA, PEM_STRING_DSAPARAMS,
    PEM_STRING_DSA_PUBLIC, PEM_STRING_ECPARAMETERS, PEM_STRING_ECPRIVATEKEY, PEM_STRING_PKCS8,
    PEM_STRING_PKCS8INF, PEM_STRING_PUBLIC, PEM_STRING_RSA, PEM_STRING_RSA_PUBLIC,
    PEM_STRING_SM2PARAMETERS, PEM_STRING_SM2PRIVATEKEY, PEM_STRING_X509, PEM_STRING_X509_CRL,
    PEM_STRING_X509_OLD, PEM_STRING_X509_TRUSTED,
};
use crate::provider::cipher::param_utf8_string;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::decode_epki2pki::ossl_epki2pki_der_decode;
use crate::provider::decode_spki2typespki::ossl_spki2typespki_der_decode;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::sys::{strcmp, strlen};
use crate::runtime::bio::BIO_free;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

/// `OSSL_MAX_PROPQUERY_SIZE` — `include/internal/sizes.h:19`.
const OSSL_MAX_PROPQUERY_SIZE: usize = 256;
/// `OSSL_MAX_CODEC_STRUCT_SIZE` — `include/internal/sizes.h:21`, the `DATA_STRUCTURE` name width.
const OSSL_MAX_CODEC_STRUCT_SIZE: usize = 32;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `include/openssl/core_dispatch.h`, `0x01`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY` — `include/openssl/core_dispatch.h`, `0x02`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;

/// `OSSL_DECODER_PARAM_PROPERTIES` — `core_names.h`, the string `"properties"`.
const OSSL_DECODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_OBJECT_PARAM_TYPE` — `core_names.h:362`, the string `"type"`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — `core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h:357`, the string `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();

/// `OSSL_OBJECT_PKEY` — `include/openssl/core_object.h:29`.
const OSSL_OBJECT_PKEY: c_int = 2;
/// `OSSL_OBJECT_CERT` — `include/openssl/core_object.h:30`.
const OSSL_OBJECT_CERT: c_int = 3;
/// `OSSL_OBJECT_CRL` — `include/openssl/core_object.h:31`.
const OSSL_OBJECT_CRL: c_int = 4;

/// `PKCS8_LAST_IDX` — `decode_pem2der.c:200`, the last `pem_name_map[]` index in the `PKCS#8` block.
const PKCS8_LAST_IDX: usize = 1;
/// `SPKI_LAST_IDX` — `decode_pem2der.c:202`, the last index in the `SubjectPublicKeyInfo` block.
const SPKI_LAST_IDX: usize = 2;

/// `struct pem_name_map_st` — `decode_pem2der.c:191-196`.
#[repr(C)]
struct PemNameMap {
    /// `const char *pem_name`.
    pem_name: *const c_char,
    /// `int object_type`.
    object_type: c_int,
    /// `const char *data_type`.
    data_type: *const c_char,
    /// `const char *data_structure`.
    data_structure: *const c_char,
}

// SAFETY: [`PEM_NAME_MAP`] is a compile-time constant whose four pointer fields are `'static`
// string literals, and it is never written; a shared reference to it is therefore safe to share
// between threads. This is the same argument `src/ec/backend.rs`'s `unsafe impl Sync for OsslItem`
// makes for its constant tables.
unsafe impl Sync for PemNameMap {}

/// `pem_name_map[]` — `decode_pem2der.c:196-225`, the eighteen PEM blocks this decoder recognises.
///
/// The order is load-bearing: [`PKCS8_LAST_IDX`] and [`SPKI_LAST_IDX`] are indices into it, and the
/// two engine dispatches below test `i <=` those. The `NULL` `data_type`/`data_structure` fields are
/// the authority's own and are what the two `!= NULL` guards in the params build read.
static PEM_NAME_MAP: [PemNameMap; 18] = [
    // PKCS#8 and SubjectPublicKeyInfo
    PemNameMap {
        pem_name: PEM_STRING_PKCS8,
        object_type: OSSL_OBJECT_PKEY,
        data_type: ptr::null(),
        data_structure: c"EncryptedPrivateKeyInfo".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_PKCS8INF,
        object_type: OSSL_OBJECT_PKEY,
        data_type: ptr::null(),
        data_structure: c"PrivateKeyInfo".as_ptr(),
    },
    // PKCS8_LAST_IDX == 1
    PemNameMap {
        pem_name: PEM_STRING_PUBLIC,
        object_type: OSSL_OBJECT_PKEY,
        data_type: ptr::null(),
        data_structure: c"SubjectPublicKeyInfo".as_ptr(),
    },
    // SPKI_LAST_IDX == 2
    // Our set of type specific PEM types
    PemNameMap {
        pem_name: PEM_STRING_DHPARAMS,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"DH".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_DHXPARAMS,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"X9.42 DH".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_DSA,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"DSA".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_DSA_PUBLIC,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"DSA".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_DSAPARAMS,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"DSA".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_ECPRIVATEKEY,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"EC".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_ECPARAMETERS,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"EC".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_SM2PRIVATEKEY,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"SM2".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_SM2PARAMETERS,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"SM2".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_RSA,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"RSA".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_RSA_PUBLIC,
        object_type: OSSL_OBJECT_PKEY,
        data_type: c"RSA".as_ptr(),
        data_structure: c"type-specific".as_ptr(),
    },
    // A few others that there is at least have an object type for, even though there is no provider
    // interface to handle such objects, yet. However, this is beneficial for the OSSL_STORE result
    // handler.
    PemNameMap {
        pem_name: PEM_STRING_X509,
        object_type: OSSL_OBJECT_CERT,
        data_type: ptr::null(),
        data_structure: c"Certificate".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_X509_TRUSTED,
        object_type: OSSL_OBJECT_CERT,
        data_type: ptr::null(),
        data_structure: c"Certificate".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_X509_OLD,
        object_type: OSSL_OBJECT_CERT,
        data_type: ptr::null(),
        data_structure: c"Certificate".as_ptr(),
    },
    PemNameMap {
        pem_name: PEM_STRING_X509_CRL,
        object_type: OSSL_OBJECT_CRL,
        data_type: ptr::null(),
        data_structure: c"CertificateList".as_ptr(),
    },
];

/// `struct pem2der_ctx_st` — `decode_pem2der.c:59-63`.
#[repr(C)]
struct Pem2DerCtx {
    /// `PROV_CTX *provctx`.
    provctx: *mut c_void,
    /// `char data_structure[OSSL_MAX_CODEC_STRUCT_SIZE]`.
    data_structure: [c_char; OSSL_MAX_CODEC_STRUCT_SIZE],
    /// `char propq[OSSL_MAX_PROPQUERY_SIZE]`.
    propq: [c_char; OSSL_MAX_PROPQUERY_SIZE],
}

/// `struct pem2der_pass_data_st` — `decode_pem2der.c:166-169`.
#[repr(C)]
struct Pem2DerPassData {
    /// `OSSL_PASSPHRASE_CALLBACK *cb`.
    cb: Option<OsslPassphraseCallback>,
    /// `void *cbarg`.
    cbarg: *mut c_void,
}

/// `static int read_pem(PROV_CTX *provctx, OSSL_CORE_BIO *cin, char **pem_name, char **pem_header,
/// unsigned char **data, long *len)` — `decode_pem2der.c:37-50`.
///
/// # Safety
/// `cin` is a live core BIO; the four out-parameters are NULL or writable.
unsafe fn read_pem(
    _provctx: *mut c_void,
    cin: *mut c_void,
    pem_name: *mut *mut c_char,
    pem_header: *mut *mut c_char,
    data: *mut *mut c_uchar,
    len: *mut c_long,
) -> c_int {
    // SAFETY: `provctx`/`cin` are the caller's and the bridge takes its own reference on success.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live and the four out-parameters are the caller's.
    let ok = unsafe { PEM_read_bio(in_, pem_name, pem_header, data, len) } > 0;
    // SAFETY: `in_` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(in_) };
    c_int::from(ok)
}

/// `static void *pem2der_newctx(void *provctx)` — `decode_pem2der.c:65-72`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe extern "C" fn pem2der_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<Pem2DerCtx>(), ptr::null(), 0).cast::<Pem2DerCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh zeroed allocation this frame owns.
        unsafe { (*ctx).provctx = provctx };
    }
    ctx.cast::<c_void>()
}

/// `static void pem2der_freectx(void *vctx)` — `decode_pem2der.c:74-79`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn pem2der_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or the context `pem2der_newctx` allocated.
    unsafe { CRYPTO_free(vctx.cast::<c_void>(), ptr::null(), 0) };
}

/// `struct pem2der_set_ctx_params_st` — `decode_pem2der.c:92-95`, the two fields the
/// machine-generated parser fills.
struct Pem2DerSetCtxParams {
    /// `OSSL_PARAM *ds`.
    ds: *const OsslParam,
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
}

/// `static int pem2der_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// pem2der_set_ctx_params_st *r)` — `decode_pem2der.c:99-133`, the `paramnames.pm` expansion.
///
/// A repeated `data-structure` (`:114`) or `properties` (`:125`) raises
/// `PROV_R_REPEATED_PARAMETER` at the second occurrence and refuses. The authority's parser
/// dispatches on the key's first byte (`'d'` then `'p'`); this walk reads the same two keys by
/// name, which is the crate's idiom for a generated parser.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array.
unsafe fn pem2der_set_ctx_params_decoder(params: *const OsslParam) -> Option<Pem2DerSetCtxParams> {
    let mut r = Pem2DerSetCtxParams {
        ds: ptr::null(),
        propq: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            match core::ffi::CStr::from_ptr((*p).key).to_bytes() {
                b"data-structure" => {
                    if !r.ds.is_null() {
                        raise_site(&err_sites::PROV_DECODE_PEM2DER_114);
                        return None;
                    }
                    r.ds = p;
                }
                b"properties" => {
                    if !r.propq.is_null() {
                        raise_site(&err_sites::PROV_DECODE_PEM2DER_125);
                        return None;
                    }
                    r.propq = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM pem2der_set_ctx_params_list[]` — `decode_pem2der.c:84-88`.
static PEM2DER_SET_CTX_PARAMS_LIST: [OsslParam; 3] = [
    param_utf8_string(OSSL_DECODER_PARAM_PROPERTIES),
    param_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE),
    END,
];

/// `static const OSSL_PARAM *pem2der_settable_ctx_params(void *provctx)` —
/// `decode_pem2der.c:138-141`.
///
/// # Safety
/// The decoder `settable_ctx_params` dispatch contract; `_provctx` is ignored.
unsafe extern "C" fn pem2der_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    PEM2DER_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int pem2der_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `decode_pem2der.c:143-163`.
///
/// # Safety
/// The decoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn pem2der_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Pem2DerCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = pem2der_set_ctx_params_decoder(params) else {
            return 0;
        };

        let mut str_ = (*ctx).propq.as_mut_ptr();
        if !p.propq.is_null()
            && OSSL_PARAM_get_utf8_string(p.propq, &mut str_, OSSL_MAX_PROPQUERY_SIZE) == 0
        {
            return 0;
        }

        let mut str_ = (*ctx).data_structure.as_mut_ptr();
        if !p.ds.is_null()
            && OSSL_PARAM_get_utf8_string(p.ds, &mut str_, OSSL_MAX_CODEC_STRUCT_SIZE) == 0
        {
            return 0;
        }
    }
    1
}

/// `static int pem2der_pass_helper(char *buf, int num, int w, void *data)` —
/// `decode_pem2der.c:171-181`.
///
/// A `pem_password_cb`-compatible shim over the framework's `OSSL_PASSPHRASE_CALLBACK`: it calls
/// through and answers the pass phrase length, or `-1` when there is no callback to call.
///
/// # Safety
/// A `pem_password_cb` per `include/openssl/pem.h:57`.
unsafe extern "C" fn pem2der_pass_helper(
    buf: *mut c_char,
    num: c_int,
    _w: c_int,
    data: *mut c_void,
) -> c_int {
    let pass_data = data.cast::<Pem2DerPassData>();
    let mut plen: usize = 0;

    // SAFETY: `pass_data` is the `PEM_do_header` caller's `&pass_data`; a NULL one is refused.
    unsafe {
        if pass_data.is_null() {
            return -1;
        }
        let Some(cb) = (*pass_data).cb else {
            return -1;
        };
        // SAFETY: `cb` is the framework's callback and each argument is this frame's.
        if cb(
            buf,
            num as usize,
            &mut plen,
            ptr::null(),
            (*pass_data).cbarg,
        ) == 0
        {
            return -1;
        }
    }
    plen as c_int
}

/// `static int pem2der_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `decode_pem2der.c:183-325`.
///
/// The unit's engine. The three ownership points are the authority's: `read_pem` allocates
/// `pem_name`/`pem_header`/`der`, all three are released at `end:` on every path, and the two
/// engines are handed the DER buffer rather than a copy.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn pem2der_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Pem2DerCtx>();
    let mut pem_name: *mut c_char = ptr::null_mut();
    let mut pem_header: *mut c_char = ptr::null_mut();
    let mut der: *mut c_uchar = ptr::null_mut();
    let mut der_len: c_long = 0;

    // SAFETY: `ctx` is the caller's context and the four out-parameters are this frame's.
    let read = unsafe {
        read_pem(
            (*ctx).provctx,
            cin,
            &mut pem_name,
            &mut pem_header,
            &mut der,
            &mut der_len,
        )
    };
    let mut ok = c_int::from(read > 0);
    // We return "empty handed". This is not an error.
    if ok == 0 {
        return 1;
    }

    let result = 'end: {
        // 10 is the number of characters in "Proc-Type:", which `PEM_get_EVP_CIPHER_INFO()
        // requires to be present. If the PEM header has fewer characters than that, it's not worth
        // spending cycles on it.
        // SAFETY: `pem_header` is a NUL-terminated string `PEM_read_bio` returned.
        if unsafe { strlen(pem_header) } > 10 {
            // SAFETY: the all-zero `EvpCipherInfo` is a valid value and `PEM_get_EVP_CIPHER_INFO`
            // initialises both fields before anything reads them.
            let mut cipher: EvpCipherInfo = unsafe { core::mem::zeroed() };
            let mut pass_data = Pem2DerPassData {
                cb: pw_cb,
                cbarg: pw_cbarg,
            };

            ok = 0; // Assume that we fail
                    // SAFETY: `pem_header` is a writable NUL-terminated string and `cipher` is this frame's.
            if unsafe { PEM_get_EVP_CIPHER_INFO(pem_header, &mut cipher) } == 0
                // SAFETY: `cipher` was filled in above and `der`/`der_len` are `read_pem`'s.
                || unsafe {
                    PEM_do_header(
                        &mut cipher,
                        der,
                        &mut der_len,
                        Some(pem2der_pass_helper as PemPasswordCb),
                        (&mut pass_data as *mut Pem2DerPassData).cast::<c_void>(),
                    )
                } == 0
            {
                break 'end ok;
            }
        }

        // Indicated that we successfully decoded something, or not at all. Ending up "empty handed"
        // is not an error.
        ok = 1;

        // Have a look to see if we recognise anything.
        let mut i = 0usize;
        // SAFETY: `pem_name` is a NUL-terminated string and each entry's `pem_name` is one too.
        while i < PEM_NAME_MAP.len() && unsafe { strcmp(pem_name, PEM_NAME_MAP[i].pem_name) } != 0 {
            i += 1;
        }

        if i < PEM_NAME_MAP.len() {
            let entry = &PEM_NAME_MAP[i];
            // We expect these to be read only so casting away the const is ok.
            let data_type = entry.data_type.cast_mut();
            let data_structure = entry.data_structure.cast_mut();

            // Since this may perform decryption, we need to check the selection to avoid password
            // prompts for objects of no interest.
            // SAFETY: `ctx` is the caller's context, `der` is `read_pem`'s buffer, and the
            // callbacks are the framework's.
            let is_pkcs8 = i <= PKCS8_LAST_IDX
                && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                    // SAFETY: both strings are NUL-terminated.
                    || unsafe {
                        OPENSSL_strcasecmp(
                            (*ctx).data_structure.as_ptr(),
                            c"EncryptedPrivateKeyInfo".as_ptr(),
                        )
                    } == 0
                    // SAFETY: as above.
                    || unsafe {
                        OPENSSL_strcasecmp(
                            (*ctx).data_structure.as_ptr(),
                            c"PrivateKeyInfo".as_ptr(),
                        )
                    } == 0);
            if is_pkcs8 {
                // SAFETY: the engine's contract; every argument is `read_pem`'s or the caller's.
                ok = unsafe {
                    ossl_epki2pki_der_decode(
                        der,
                        der_len,
                        selection,
                        data_cb,
                        data_cbarg,
                        pw_cb,
                        pw_cbarg,
                        prov_libctx_of((*ctx).provctx),
                        (*ctx).propq.as_ptr(),
                    )
                };
                break 'end ok;
            }

            // SAFETY: as above.
            let is_spki = i <= SPKI_LAST_IDX
                && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                    // SAFETY: both strings are NUL-terminated.
                    || unsafe {
                        OPENSSL_strcasecmp(
                            (*ctx).data_structure.as_ptr(),
                            c"SubjectPublicKeyInfo".as_ptr(),
                        )
                    } == 0);
            if is_spki {
                // SAFETY: the engine's contract; every argument is `read_pem`'s or the caller's.
                ok = unsafe {
                    ossl_spki2typespki_der_decode(
                        der,
                        der_len,
                        selection,
                        data_cb,
                        data_cbarg,
                        pw_cb,
                        pw_cbarg,
                        prov_libctx_of((*ctx).provctx),
                        (*ctx).propq.as_ptr(),
                    )
                };
                break 'end ok;
            }

            let mut objtype: c_int = entry.object_type;
            let mut params: [OsslParam; 5] = [END; 5];
            let mut n = 0usize;

            // SAFETY: every constructor is called with a buffer this frame owns.
            unsafe {
                if !data_type.is_null() {
                    params[n] =
                        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, data_type, 0);
                    n += 1;
                }

                // We expect this to be read only so casting away the const is ok.
                if !data_structure.is_null() {
                    params[n] = OSSL_PARAM_construct_utf8_string(
                        OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                        data_structure,
                        0,
                    );
                    n += 1;
                }
                params[n] = OSSL_PARAM_construct_octet_string(
                    OSSL_OBJECT_PARAM_DATA,
                    der.cast(),
                    der_len as usize,
                );
                n += 1;
                params[n] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &mut objtype);
                n += 1;

                params[n] = OSSL_PARAM_construct_end();
            }

            // SAFETY: `params` is a terminated array and `data_cbarg` is the caller's.
            ok = match data_cb {
                // SAFETY: `cb` is the framework's callback and every argument is this frame's.
                Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
                None => 0,
            };
        }

        ok
    };

    // SAFETY: each is NULL or the allocation `read_pem` made; this call owns them all.
    unsafe {
        CRYPTO_free(pem_name.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(pem_header.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0);
    }
    result
}

/// `ossl_pem_to_der_decoder_functions[]` — `decode_pem2der.c:327-336`. Five named slots and the
/// terminator. It is `pub(crate)` because `decode_der2key.rs`'s combined
/// `deflt_decoder[]`/`base_decoder[]` carries it as a row.
pub(crate) static PEM_TO_DER_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: pem2der_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: pem2der_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: pem2der_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: pem2der_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: pem2der_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the authority's five-slot shape — `newctx`, `freectx`, `decode`,
    /// `settable_ctx_params`, `set_ctx_params` — and the terminator.
    #[test]
    fn the_table_is_the_authoritys_five_slot_shape() {
        let fns = PEM_TO_DER_FUNCTIONS.as_ptr();
        let mut i = 0;
        let mut seen = [false; 5];
        let mut unexpected = 0;
        // SAFETY: the table is terminated and each read is within it.
        unsafe {
            while (*fns.add(i)).function_id != OSSL_DISPATCH_END {
                match (*fns.add(i)).function_id {
                    OSSL_FUNC_DECODER_NEWCTX => seen[0] = true,
                    OSSL_FUNC_DECODER_FREECTX => seen[1] = true,
                    OSSL_FUNC_DECODER_DECODE => seen[2] = true,
                    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS => seen[3] = true,
                    OSSL_FUNC_DECODER_SET_CTX_PARAMS => seen[4] = true,
                    _ => unexpected += 1,
                }
                i += 1;
            }
        }
        assert_eq!(
            unexpected, 0,
            "the decoder table carries an unexpected slot"
        );
        assert!(
            seen.iter().all(|&s| s),
            "the decoder table is missing a slot"
        );
        assert_eq!(i, 5);
    }

    /// The `pem_name_map[]` is the authority's eighteen rows, and the two engine-dispatch indices
    /// (`PKCS8_LAST_IDX`, `SPKI_LAST_IDX`) point at the `PrivateKeyInfo` and `SubjectPublicKeyInfo`
    /// rows as `decode_pem2der.c:200-202` asserts.
    #[test]
    fn the_pem_name_map_is_the_authoritys_eighteen_rows() {
        assert_eq!(PEM_NAME_MAP.len(), 18);
        // SAFETY: every `pem_name` is a `'static` C string literal.
        unsafe {
            assert_eq!(
                core::ffi::CStr::from_ptr(PEM_NAME_MAP[PKCS8_LAST_IDX].pem_name).to_bytes(),
                b"PRIVATE KEY"
            );
            assert_eq!(
                core::ffi::CStr::from_ptr(PEM_NAME_MAP[SPKI_LAST_IDX].pem_name).to_bytes(),
                b"PUBLIC KEY"
            );
        }
    }
}
