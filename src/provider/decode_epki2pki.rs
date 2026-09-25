//! Phase 10.1 — `providers/implementations/encode_decode/decode_epki2pki.c`: the provider's
//! **`EncryptedPrivateKeyInfo`-to-`PrivateKeyInfo` DER decoder**, one `OSSL_OP_DECODER` table
//! published by both the `default` and the `base` provider.
//!
//! This is one of the eleven row-publishing units of `docs/PHASE-10-SUBPHASES.md` §1a (`1 table`,
//! `2 rows`), and the third to land. Its closure is entirely landed: `asn1_d2i_read_bio`,
//! `d2i_X509_SIG`/`X509_SIG_get0`/`X509_SIG_free` (D348's `src/asn1/x_sig.rs`),
//! `d2i_PKCS8_PRIV_KEY_INFO`/`PKCS8_pkey_get0`/`PKCS8_PRIV_KEY_INFO_free` (D349,
//! `src/asn1/p8_pkey.rs`), `PKCS12_pbe_crypt_ex` (D368), and `OBJ_obj2txt`. It is the first
//! *decoder* row this stratum publishes, so it is also what makes the `OSSL_OP_DECODER` arm of
//! both provider queries non-NULL.
//!
//! ## The engine is `ossl_epki2pki_der_decode`, and it is shared
//!
//! `epki2pki_decode` reads one top-level DER object through `asn1_d2i_read_bio` and hands it to
//! `ossl_epki2pki_der_decode`, which is the unit's real engine: it tries `d2i_X509_SIG` first and,
//! if that parses, decrypts the ciphertext with `PKCS12_pbe_crypt_ex`; then it parses the result as
//! a `PKCS8_PRIV_KEY_INFO` and passes its OID and octets to the framework's callback.
//! `decode_pem2der.c` reaches the same engine for the `PKCS#8` PEM arm, which is why it is
//! `pub(crate)` here and not an inline body of the decode arm.
//!
//! ## The bytes are the contract
//!
//! `RT-CODEC` fetches these rows through `OSSL_DECODER_fetch(NULL, "DER",
//! "input=der,structure=EncryptedPrivateKeyInfo,provider=…")`, feeds a fixed PKCS#8
//! `EncryptedPrivateKeyInfo` (a published vector, not a generated key) and compares the transcript
//! byte for byte against the authority's, together with the passphrase-refusal arm's error queue.
//! A transcription that round-trips its own output is not this (`docs/PHASE-10-SUBPHASES.md`
//! §3.1).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_d2i_fp::asn1_d2i_read_bio;
use crate::asn1::p8_pkey::{d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, PKCS8_pkey_get0};
use crate::asn1::x_algor::X509Algor;
use crate::asn1::x_sig::{d2i_X509_SIG, X509_SIG_free, X509_SIG_get0};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string, OsslParam, END,
};
use crate::passphrase::OsslPassphraseCallback;
use crate::pkcs12::p12_decr::PKCS12_pbe_crypt_ex;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::param_utf8_string;
use crate::provider::ctx::prov_libctx_of;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::BIO_free;
use crate::runtime::buffer::BufMem;
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::OBJ_obj2txt;
use crate::selftest::OsslCallback;

/// `OSSL_OP_DECODER` — `include/openssl/core_dispatch.h:296`. The provider queries name it, and
/// the census resolves the arm's constant by this final path segment.
pub(crate) const OSSL_OP_DECODER: c_int = 21;

/// `OSSL_MAX_PROPQUERY_SIZE` — `include/internal/sizes.h:19`.
const OSSL_MAX_PROPQUERY_SIZE: usize = 256;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_DECODER_PARAM_PROPERTIES` — `core_names.h`, the string `"properties"`.
const OSSL_DECODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_OBJECT_PARAM_TYPE` — `core_names.h:362`, the string `"type"`.
const OSSL_OBJECT_PARAM_TYPE: *const c_char = c"type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_TYPE` — `core_names.h:358`, the string `"data-type"`.
const OSSL_OBJECT_PARAM_DATA_TYPE: *const c_char = c"data-type".as_ptr();
/// `OSSL_OBJECT_PARAM_INPUT_TYPE` — `core_names.h:360`, the string `"input-type"`.
const OSSL_OBJECT_PARAM_INPUT_TYPE: *const c_char = c"input-type".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA_STRUCTURE` — `core_names.h:357`, the string `"data-structure"`.
const OSSL_OBJECT_PARAM_DATA_STRUCTURE: *const c_char = c"data-structure".as_ptr();
/// `OSSL_OBJECT_PARAM_DATA` — `core_names.h:356`, the string `"data"`.
const OSSL_OBJECT_PARAM_DATA: *const c_char = c"data".as_ptr();
/// `OSSL_OBJECT_PKEY` — `core_object.h:29`. The engine announces the decoded `PrivateKeyInfo` as
/// a key object for the next decoder in the chain.
const OSSL_OBJECT_PKEY: c_int = 2;

/// `struct epki2pki_ctx_st` — `decode_epki2pki.c:40-43`.
#[repr(C)]
struct Epki2pkiCtx {
    /// `PROV_CTX *provctx`.
    provctx: *mut c_void,
    /// `char propq[OSSL_MAX_PROPQUERY_SIZE]`.
    propq: [c_char; OSSL_MAX_PROPQUERY_SIZE],
}

/// `static void *epki2pki_newctx(void *provctx)` — `decode_epki2pki.c:45-52`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe extern "C" fn epki2pki_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<Epki2pkiCtx>(), ptr::null(), 0).cast::<Epki2pkiCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh zeroed allocation this frame owns.
        unsafe { (*ctx).provctx = provctx };
    }
    ctx.cast::<c_void>()
}

/// `static void epki2pki_freectx(void *vctx)` — `decode_epki2pki.c:54-58`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn epki2pki_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or the context `epki2pki_newctx` allocated.
    unsafe { CRYPTO_free(vctx.cast::<c_void>(), ptr::null(), 0) };
}

/// `struct epki2pki_set_ctx_params_st` — `decode_epki2pki.c:71-73`, the one field the
/// machine-generated parser fills.
struct Epki2pkiSetCtxParams {
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
}

/// `static int epki2pki_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// epki2pki_set_ctx_params_st *r)` — `decode_epki2pki.c:77-95`, the `paramnames.pm` expansion.
///
/// A repeated `properties` raises `PROV_R_REPEATED_PARAMETER` at the second occurrence and refuses.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array.
unsafe fn epki2pki_set_ctx_params_decoder(
    params: *const OsslParam,
) -> Option<Epki2pkiSetCtxParams> {
    let mut r = Epki2pkiSetCtxParams { propq: ptr::null() };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            if core::ffi::CStr::from_ptr((*p).key).to_bytes() == b"properties" {
                if !r.propq.is_null() {
                    raise_site(&err_sites::PROV_DECODE_EPKI2PKI_88);
                    return None;
                }
                r.propq = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM epki2pki_set_ctx_params_list[]` — `decode_epki2pki.c:64-67`.
static EPKI2PKI_SET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_utf8_string(OSSL_DECODER_PARAM_PROPERTIES), END];

/// `static const OSSL_PARAM *epki2pki_settable_ctx_params(void *provctx)` —
/// `decode_epki2pki.c:100-103`.
///
/// # Safety
/// The decoder `settable_ctx_params` dispatch contract; `_provctx` is ignored.
unsafe extern "C" fn epki2pki_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    EPKI2PKI_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int epki2pki_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `decode_epki2pki.c:105-120`.
///
/// # Safety
/// The decoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn epki2pki_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Epki2pkiCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = epki2pki_set_ctx_params_decoder(params) else {
            return 0;
        };

        let mut str_ = (*ctx).propq.as_mut_ptr();
        if !p.propq.is_null()
            && OSSL_PARAM_get_utf8_string(p.propq, &mut str_, OSSL_MAX_PROPQUERY_SIZE) == 0
        {
            return 0;
        }
    }
    1
}

/// `int ossl_epki2pki_der_decode(unsigned char *der, long der_len, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `decode_epki2pki.c:159-234`.
///
/// The unit's engine: decrypt a `d2i_X509_SIG` if the input parses as one, then announce the
/// resulting `PKCS8_PRIV_KEY_INFO` to the callback. `selection` is the authority's and is unused.
///
/// # Safety
/// `der` must be readable for `der_len` bytes; `data_cb`/`pw_cb` the framework's callbacks.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_epki2pki_der_decode(
    der: *mut c_uchar,
    der_len: c_long,
    _selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut pder: *const c_uchar = der;
    let mut new_der: *mut c_uchar = ptr::null_mut();
    let mut der_cur = der;
    let mut der_len_cur = der_len;
    let mut alg: *const X509Algor = ptr::null();
    let mut ok = 1;

    // SAFETY: no preconditions.
    ERR_set_mark();
    // SAFETY: `pder` is the caller's readable cursor and `der_len` its length.
    let p8 = unsafe { d2i_X509_SIG(ptr::null_mut(), &mut pder, der_len) };
    if !p8.is_null() {
        let mut pbuf = [0 as c_char; 1024];
        let mut plen: usize = 0;

        // SAFETY: no preconditions.
        ERR_clear_last_mark();

        // SAFETY: `pw_cb` is the framework's callback; a NULL one is the authority's undefined
        // behaviour and is treated as a refusal here rather than dereferenced.
        let got = match pw_cb {
            // SAFETY: `cb` is the framework's callback and every argument is this frame's.
            Some(cb) => unsafe {
                cb(
                    pbuf.as_mut_ptr(),
                    pbuf.len(),
                    &mut plen,
                    ptr::null(),
                    pw_cbarg,
                )
            },
            None => 0,
        };
        if got == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_DECODE_EPKI2PKI_179) };
            ok = 0;
        } else {
            let mut oct: *const crate::asn1::layout::Asn1String = ptr::null();
            let mut new_der_len: c_int = 0;

            // SAFETY: `p8` is live; `alg`/`oct` are this frame's out-parameters.
            unsafe { X509_SIG_get0(p8, &mut alg, &mut oct) };
            // SAFETY: `oct` is a live ASN1_OCTET_STRING; `new_der`/`new_der_len` are this frame's.
            let pbe = unsafe {
                PKCS12_pbe_crypt_ex(
                    alg,
                    pbuf.as_ptr(),
                    plen as c_int,
                    (*oct).data,
                    (*oct).length,
                    &mut new_der,
                    &mut new_der_len,
                    0,
                    libctx,
                    propq,
                )
            };
            if pbe.is_null() {
                ok = 0;
            } else {
                der_cur = new_der;
                der_len_cur = new_der_len as c_long;
            }
            alg = ptr::null();
        }
        // SAFETY: `p8` is live and this call owns it.
        unsafe { X509_SIG_free(p8) };
    } else {
        // SAFETY: no preconditions.
        ERR_pop_to_mark();
    }

    // SAFETY: no preconditions.
    ERR_set_mark();
    let mut pder2: *const c_uchar = der_cur;
    // SAFETY: `pder2` is a readable cursor and `der_len_cur` its length.
    let p8inf = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut pder2, der_len_cur) };
    // SAFETY: no preconditions.
    ERR_pop_to_mark();

    if !p8inf.is_null()
        // SAFETY: `p8inf` is live and `alg` is this frame's out-parameter.
        && unsafe {
            PKCS8_pkey_get0(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut alg,
                p8inf,
            )
        } != 0
    {
        let mut keytype = [0 as c_char; OSSL_MAX_NAME_SIZE];
        let mut params: [OsslParam; 6] = [END; 6];
        let mut objtype: c_int = OSSL_OBJECT_PKEY;

        // SAFETY: `keytype` is a live buffer of the size passed and `alg` is live.
        unsafe {
            OBJ_obj2txt(
                keytype.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                (*alg).algorithm,
                0,
            );
        }

        // SAFETY: every constructor is called with the buffer this frame owns.
        unsafe {
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE,
                keytype.as_mut_ptr(),
                0,
            );
            params[1] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_INPUT_TYPE,
                c"DER".as_ptr().cast_mut(),
                0,
            );
            params[2] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                c"PrivateKeyInfo".as_ptr().cast_mut(),
                0,
            );
            params[3] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_DATA,
                der_cur.cast(),
                der_len_cur as usize,
            );
            params[4] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &mut objtype);
            params[5] = OSSL_PARAM_construct_end();
        }

        // SAFETY: `params` is a terminated array and `data_cbarg` is the caller's.
        ok = match data_cb {
            // SAFETY: `cb` is the framework's callback and every argument is this frame's.
            Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
            None => 0,
        };
    }
    // SAFETY: `p8inf` is NULL or live and this call owns it.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8inf) };
    // SAFETY: `new_der` is NULL or the allocation `PKCS12_pbe_crypt_ex` made.
    unsafe { CRYPTO_free(new_der.cast::<c_void>(), ptr::null(), 0) };
    ok
}

/// `static int epki2pki_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `decode_epki2pki.c:127-157`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn epki2pki_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Epki2pkiCtx>();
    // SAFETY: `cin` is the core BIO this decode owns.
    let in_ = unsafe { ossl_bio_new_from_core_bio(cin.cast()) };
    if in_.is_null() {
        return 0;
    }

    let mut mem: *mut BufMem = ptr::null_mut();
    // SAFETY: `in_` is live and `mem` is this frame's out-parameter.
    let read = unsafe { asn1_d2i_read_bio(in_, &mut mem) } >= 0;
    // SAFETY: `in_` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(in_) };

    if !read {
        // "Empty handed" is not an error, as the authority's comment says.
        return 1;
    }

    // SAFETY: `mem` is the live BUF_MEM `asn1_d2i_read_bio` filled.
    let der = unsafe { (*mem).data.cast::<c_uchar>() };
    // SAFETY: as above.
    let der_len = unsafe { (*mem).length as c_long };
    // SAFETY: `mem` is the allocation the read made; its header is released here and its `data`
    // buffer by the free below, exactly as the authority's `OPENSSL_free(mem)`/`OPENSSL_free(der)`
    // pair does.
    unsafe { CRYPTO_free(mem.cast::<c_void>(), ptr::null(), 0) };

    // SAFETY: `der` is a live buffer of `der_len` bytes and `ctx` is the caller's context.
    let ok = unsafe {
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
    // SAFETY: `der` is the buffer the read allocated and this call owns it.
    unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
    ok
}

/// `ossl_EncryptedPrivateKeyInfo_der_to_der_decoder_functions[]` —
/// `decode_epki2pki.c:236-245`. Five named slots and the terminator.
static ENCRYPTED_PRIVATE_KEY_INFO_DER_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: epki2pki_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: epki2pki_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: epki2pki_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: epki2pki_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: epki2pki_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// The `output=input` property each row carries, with its provider's own prefix.
const DEFAULT_DECODER_PROPERTY: *const c_char =
    c"provider=default,fips=yes,input=der,structure=EncryptedPrivateKeyInfo".as_ptr();
/// The base provider's copy.
const BASE_DECODER_PROPERTY: *const c_char =
    c"provider=base,fips=yes,input=der,structure=EncryptedPrivateKeyInfo".as_ptr();

/// `deflt_decoder[]`'s rows this unit publishes — `providers/decoders.inc`'s
/// `DECODER_w_structure("DER", der, yes, der, EncryptedPrivateKeyInfo)` as `defltprov.c` expands
/// it. The `DER` name and its property are the row's identity; the census joins on both.
pub(crate) static DEFLT_DECODERS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"DER".as_ptr(),
        property_definition: DEFAULT_DECODER_PROPERTY,
        implementation: ENCRYPTED_PRIVATE_KEY_INFO_DER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `base_decoder[]`'s copy of the same row, with the base provider's property.
pub(crate) static BASE_DECODERS: [OsslAlgorithm; 2] = [
    OsslAlgorithm {
        algorithm_names: c"DER".as_ptr(),
        property_definition: BASE_DECODER_PROPERTY,
        implementation: ENCRYPTED_PRIVATE_KEY_INFO_DER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the authority's five-slot shape — `newctx`, `freectx`, `decode`,
    /// `settable_ctx_params`, `set_ctx_params` — and the terminator. The two ids that are *not*
    /// sequential (`decode` 11, `export_object` 20) are the reason the values are named.
    #[test]
    fn the_table_is_the_authoritys_five_slot_shape() {
        let fns = ENCRYPTED_PRIVATE_KEY_INFO_DER_FUNCTIONS.as_ptr();
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

    /// The two provider rows carry the same `DER` name and dispatch, and differ only in the
    /// provider prefix of the property — the base provider's copy of the `default` row.
    #[test]
    fn the_two_provider_rows_differ_only_in_their_prefix() {
        // SAFETY: both pointers are static C strings this module wrote.
        unsafe {
            let d = core::ffi::CStr::from_ptr(DEFLT_DECODERS[0].property_definition).to_bytes();
            let b = core::ffi::CStr::from_ptr(BASE_DECODERS[0].property_definition).to_bytes();
            assert!(d.starts_with(b"provider=default,"));
            assert!(b.starts_with(b"provider=base,"));
            assert_eq!(
                &d[b"provider=default".len()..],
                &b[b"provider=base".len()..]
            );
            assert_eq!(
                core::ffi::CStr::from_ptr(DEFLT_DECODERS[0].algorithm_names).to_bytes(),
                b"DER"
            );
        }
        assert_eq!(
            DEFLT_DECODERS[0].implementation,
            BASE_DECODERS[0].implementation
        );
    }
}
