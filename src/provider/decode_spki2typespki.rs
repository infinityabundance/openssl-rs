//! Phase 10.5 — `providers/implementations/encode_decode/decode_spki2typespki.c`: the provider's
//! **`SubjectPublicKeyInfo`-to-type-specific-`SubjectPublicKeyInfo` DER decoder** — one
//! `OSSL_OP_DECODER` table published by both the `default` and the `base` provider.
//!
//! This is the unit that feeds the `decode_der2key.c` chain (D434's order): the DER-to-key decoder
//! knows how to read an `RSAPublicKey`, an `ECPoint` or a PQC public key out of a type-specific
//! structure, so something must first take a `SubjectPublicKeyInfo` and announce *which* type-specific
//! structure its `BIT STRING` holds. That something is this table. `decode_pem2der.c` reaches the
//! same engine for the `PUBLIC KEY` PEM arm, which is why [`ossl_spki2typespki_der_decode`] is
//! `pub(crate)` and not an inline body of the decode arm.
//!
//! ## Provenance and closure
//!
//! `nm --undefined-only` over the authority's `libdefault-lib-decode_spki2typespki.o` names exactly
//! one name this crate did not have when 10.5 began: `ossl_x509_algor_is_sm2`, in
//! `crypto/ec/ec_backend.c`. Everything else — `ossl_d2i_X509_PUBKEY_INTERNAL`,
//! `X509_PUBKEY_get0_param`, `X509_ALGOR_get0`, `OBJ_obj2nid`/`OBJ_obj2txt`, `ossl_read_der` —
//! was landed. That one name lands with this unit ([`crate::ec::backend::ossl_x509_algor_is_sm2`])
//! and the `forensics/prerequisites.json` divergence row that withheld it is retired. The unit is
//! under 350 authority lines and is transcribed whole; there is no withheld arm.
//!
//! ## `doc`/`ctx` provenance
//!
//! This is a generated `.c.in` (`decode_spki2typespki.c.in`), so its `__FILE__` is the
//! build-relative `providers/implementations/encode_decode/decode_spki2typespki.c` — the same
//! spelling `decode_epki2pki.c` carries. Its one `ERR_raise*` is the machine-generated
//! `set_ctx_params` parser's `PROV_R_REPEATED_PARAMETER` at `:87`, which
//! `forensics/tools/gen_err_raise_sites.py` now carries (it is not a local declaration).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::decoder_meth::{
    OSSL_FUNC_DECODER_DECODE, OSSL_FUNC_DECODER_FREECTX, OSSL_FUNC_DECODER_NEWCTX,
    OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_DECODER_SET_CTX_PARAMS,
};
use crate::ec::backend::ossl_x509_algor_is_sm2;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_utf8_string, OsslParam, END,
};
use crate::passphrase::OsslPassphraseCallback;
use crate::provider::cipher::param_utf8_string;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::endecoder_common::ossl_read_der;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, NID_X9_62_id_ecPublicKey, OBJ_obj2nid, OBJ_obj2txt};
use crate::selftest::OsslCallback;
use crate::x509::x_pubkey::{
    ossl_X509_PUBKEY_INTERNAL_free, ossl_d2i_X509_PUBKEY_INTERNAL, X509Pubkey,
    X509_PUBKEY_get0_param,
};

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
/// `OSSL_OBJECT_PKEY` — `core_object.h:29`. The engine announces the decoded public key as a key
/// object for the next decoder in the chain.
const OSSL_OBJECT_PKEY: c_int = 2;

/// `struct spki2typespki_ctx_st` — `decode_spki2typespki.c:39-42`.
#[repr(C)]
struct Spki2TypespkiCtx {
    /// `PROV_CTX *provctx`.
    provctx: *mut c_void,
    /// `char propq[OSSL_MAX_PROPQUERY_SIZE]`.
    propq: [c_char; OSSL_MAX_PROPQUERY_SIZE],
}

/// `static void *spki2typespki_newctx(void *provctx)` — `decode_spki2typespki.c:44-51`.
///
/// # Safety
/// The decoder `newctx` dispatch contract.
unsafe extern "C" fn spki2typespki_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<Spki2TypespkiCtx>(), ptr::null(), 0)
        .cast::<Spki2TypespkiCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh zeroed allocation this frame owns.
        unsafe { (*ctx).provctx = provctx };
    }
    ctx.cast::<c_void>()
}

/// `static void spki2typespki_freectx(void *vctx)` — `decode_spki2typespki.c:53-58`.
///
/// # Safety
/// The decoder `freectx` dispatch contract.
unsafe extern "C" fn spki2typespki_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is NULL or the context `spki2typespki_newctx` allocated.
    unsafe { CRYPTO_free(vctx.cast::<c_void>(), ptr::null(), 0) };
}

/// `struct spki2typespki_set_ctx_params_st` — `decode_spki2typespki.c:70-72`, the one field the
/// machine-generated parser fills.
struct Spki2TypespkiSetCtxParams {
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
}

/// `static int spki2typespki_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// spki2typespki_set_ctx_params_st *r)` — `decode_spki2typespki.c:75-94`, the `paramnames.pm`
/// expansion.
///
/// A repeated `properties` raises `PROV_R_REPEATED_PARAMETER` at the second occurrence and refuses.
///
/// # Safety
/// `params` must be NULL or a `key`-terminated array.
unsafe fn spki2typespki_set_ctx_params_decoder(
    params: *const OsslParam,
) -> Option<Spki2TypespkiSetCtxParams> {
    let mut r = Spki2TypespkiSetCtxParams { propq: ptr::null() };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            if core::ffi::CStr::from_ptr((*p).key).to_bytes() == b"properties" {
                if !r.propq.is_null() {
                    raise_site(&err_sites::PROV_DECODE_SPKI2TYPESPKI_87);
                    return None;
                }
                r.propq = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM spki2typespki_set_ctx_params_list[]` —
/// `decode_spki2typespki.c:63-66`.
static SPKI2TYPESPKI_SET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_utf8_string(OSSL_DECODER_PARAM_PROPERTIES), END];

/// `static const OSSL_PARAM *spki2typespki_settable_ctx_params(void *provctx)` —
/// `decode_spki2typespki.c:99-102`.
///
/// # Safety
/// The decoder `settable_ctx_params` dispatch contract; `_provctx` is ignored.
unsafe extern "C" fn spki2typespki_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    SPKI2TYPESPKI_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int spki2typespki_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `decode_spki2typespki.c:104-119`.
///
/// # Safety
/// The decoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn spki2typespki_set_ctx_params(
    vctx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<Spki2TypespkiCtx>();

    // SAFETY: `ctx` is the caller's context and `params` is NULL or a terminated array.
    unsafe {
        if ctx.is_null() {
            return 0;
        }
        let Some(p) = spki2typespki_set_ctx_params_decoder(params) else {
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

/// `int ossl_spki2typespki_der_decode(unsigned char *der, long len, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `decode_spki2typespki.c:140-198`.
///
/// The unit's engine: decode the SPKI, read its algorithm identifier, and announce the
/// type-specific structure name. **The `SM2` special case is the reason
/// [`ossl_x509_algor_is_sm2`] exists**: SM2 reuses `id-ecPublicKey`, so when the OID is the EC one
/// and the *parameter* says SM2 the name is `"SM2"`; otherwise `OBJ_obj2txt` names the OID.
///
/// `selection`, `pw_cb` and `pw_cbarg` are the authority's and are unused by this engine (the
/// public-key structure is never encrypted); they are kept in the signature because both callers
/// pass them.
///
/// # Safety
/// `der` must be readable for `len` bytes; `data_cb` the framework's callback.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_spki2typespki_der_decode(
    der: *mut c_uchar,
    len: c_long,
    _selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    _pw_cb: Option<OsslPassphraseCallback>,
    _pw_cbarg: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut derp: *const c_uchar = der;
    let mut algor: *mut X509Algor = ptr::null_mut();
    let mut oid: *const Asn1Object = ptr::null();
    let mut dataname = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut objtype: c_int = OSSL_OBJECT_PKEY;
    let mut ok = 0;

    // SAFETY: `derp` is the caller's readable cursor and `len` its length.
    let mut xpub: *mut X509Pubkey =
        unsafe { ossl_d2i_X509_PUBKEY_INTERNAL(&mut derp, len, libctx, propq) };

    if xpub.is_null() {
        // We return "empty handed". This is not an error.
        return 1;
    }

    // SAFETY: `xpub` is live; `algor` is this frame's out-parameter.
    if unsafe {
        X509_PUBKEY_get0_param(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut algor,
            xpub,
        )
    } == 0
    {
        // SAFETY: `xpub` is live and this call owns it (`goto end:`).
        unsafe { ossl_X509_PUBKEY_INTERNAL_free(xpub) };
        return ok;
    }
    // SAFETY: `algor` is live and borrowed from `xpub`; `oid` is this frame's out-parameter.
    unsafe { X509_ALGOR_get0(&mut oid, ptr::null_mut(), ptr::null_mut(), algor) };

    // `#ifndef OPENSSL_NO_EC`: SM2 abuses the EC oid, so this could actually be SM2.
    // SAFETY: `oid` is live and `algor` is live.
    let is_sm2 = unsafe { OBJ_obj2nid(oid) } == NID_X9_62_id_ecPublicKey
        && unsafe { ossl_x509_algor_is_sm2(algor) } != 0;
    if is_sm2 {
        // SAFETY: `dataname` is a 50-byte buffer and `c"SM2"` is 4 bytes including its NUL.
        unsafe { ptr::copy_nonoverlapping(c"SM2".as_ptr(), dataname.as_mut_ptr(), 4) };
    } else {
        // SAFETY: `dataname` is a writable buffer of the size passed and `oid` is live.
        if unsafe { OBJ_obj2txt(dataname.as_mut_ptr(), OSSL_MAX_NAME_SIZE as c_int, oid, 0) } <= 0 {
            // SAFETY: `xpub` is live and this call owns it (`goto end:`).
            unsafe { ossl_X509_PUBKEY_INTERNAL_free(xpub) };
            return ok;
        }
    }

    // SAFETY: `xpub` is live and this call owns it; the column is set to NULL so the `end:` free
    // below is a no-op, exactly as the authority's assignment is.
    unsafe { ossl_X509_PUBKEY_INTERNAL_free(xpub) };
    xpub = ptr::null_mut();

    let mut params: [OsslParam; 6] = [END; 6];

    // SAFETY: every constructor is called with the buffer this frame owns.
    unsafe {
        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE, dataname.as_mut_ptr(), 0);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_INPUT_TYPE,
            c"DER".as_ptr().cast_mut(),
            0,
        );
        params[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE,
            c"SubjectPublicKeyInfo".as_ptr().cast_mut(),
            0,
        );
        params[3] =
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA, der.cast(), len as usize);
        params[4] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &mut objtype);
        params[5] = OSSL_PARAM_construct_end();
    }

    // SAFETY: `params` is a terminated array and `data_cbarg` is the caller's.
    ok = match data_cb {
        // SAFETY: `cb` is the framework's callback and every argument is this frame's.
        Some(cb) => unsafe { cb(params.as_ptr(), data_cbarg) },
        None => 0,
    };

    // SAFETY: `xpub` is NULL here (the column was cleared above), which this call tolerates.
    unsafe { ossl_X509_PUBKEY_INTERNAL_free(xpub) };
    ok
}

/// `static int spki2typespki_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
/// OSSL_CALLBACK *data_cb, void *data_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)` —
/// `decode_spki2typespki.c:121-138`.
///
/// # Safety
/// The decoder `decode` dispatch contract.
unsafe extern "C" fn spki2typespki_decode(
    vctx: *mut c_void,
    cin: *mut c_void,
    selection: c_int,
    data_cb: Option<OsslCallback>,
    data_cbarg: *mut c_void,
    pw_cb: Option<OsslPassphraseCallback>,
    pw_cbarg: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Spki2TypespkiCtx>();
    let mut der: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;

    // SAFETY: `ctx` is the caller's context, `cin` the core BIO, and `der`/`len` this frame's.
    let read = unsafe { ossl_read_der((*ctx).provctx, cin, &mut der, &mut len) };
    if read == 0 {
        // "Empty handed" is not an error, as the authority's comment says.
        return 1;
    }

    // SAFETY: `der` is a live buffer of `len` bytes, `ctx` the caller's context, and the callbacks
    // are the framework's.
    let ok = unsafe {
        ossl_spki2typespki_der_decode(
            der,
            len,
            selection,
            data_cb,
            data_cbarg,
            pw_cb,
            pw_cbarg,
            prov_libctx_of((*ctx).provctx),
            (*ctx).propq.as_ptr(),
        )
    };
    // SAFETY: `der` is the buffer `ossl_read_der` allocated and this call owns it.
    unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
    ok
}

/// `ossl_SubjectPublicKeyInfo_der_to_der_decoder_functions[]` — `decode_spki2typespki.c:200-209`.
/// Five named slots and the terminator. It is `pub(crate)` because `decode_der2key.rs`'s combined
/// `deflt_decoder[]`/`base_decoder[]` carries it as a row.
pub(crate) static SPKI_TO_TYPESPKI_FUNCTIONS: [OsslDispatch; 6] = [
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_NEWCTX,
        function: spki2typespki_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_FREECTX,
        function: spki2typespki_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_DECODE,
        function: spki2typespki_decode as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS,
        function: spki2typespki_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_DECODER_SET_CTX_PARAMS,
        function: spki2typespki_set_ctx_params as *mut c_void,
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
        let fns = SPKI_TO_TYPESPKI_FUNCTIONS.as_ptr();
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
}
