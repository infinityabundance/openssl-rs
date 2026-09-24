//! `crypto/ec/ecx_meth.c` — the four X25519/X448/Ed25519/Ed448 `EVP_PKEY` methods, both halves,
//! Phase 8.8.
//!
//! One thousand four hundred and sixty-eight lines, fifty-five functions, **eight internals**: four
//! `const EVP_PKEY_ASN1_METHOD` objects (`ossl_ecx25519_asn1_meth`, `ossl_ecx448_asn1_meth`,
//! `ossl_ed25519_asn1_meth`, `ossl_ed448_asn1_meth`) and four `EVP_PKEY_METHOD` accessors
//! (`ossl_ecx25519_pkey_method`, `ossl_ecx448_pkey_method`, `ossl_ed25519_pkey_method`,
//! `ossl_ed448_pkey_method`). D353 withheld the ameth rows and D355 the pmeth rows from the crate's
//! two `standard_methods[]` tables under `docs/SECURITY_DIVERGENCE_POLICY.md`'s `D-PKEY-AMETH-3`;
//! **D372 lands this unit and retires that divergence.**
//!
//! ## What the objects need, and where each piece came from
//!
//! A `const EVP_PKEY_ASN1_METHOD` names its callbacks by address, so the rows could not exist until
//! every callback did. The chain is: this unit's own fifty-five bodies; [`crate::ec::ecx_key`]'s
//! object (`crypto/ec/ecx_key.c`, D372); [`crate::ec::ecx_backend`]'s four functions
//! (`crypto/ec/ecx_backend.c`, D372) including the `ossl_ecx_key_op` both halves call;
//! [`crate::ec::curve25519`] (D370) and [`crate::ec::curve448`] (D371) for the arithmetic; and the
//! four `ossl_evp_pkey_get1_*` accessors of `crypto/evp/p_lib.c:926-955`, which `src/evp/pkey.rs`
//! carries because that is the translation unit the internal-symbol atlas attributes them to.
//!
//! ## The `#ifdef S390X_EC_ASM` arms, which are 24 of the 55 functions and are not here
//!
//! The unit's largest block is the s390x hardware path: `s390x_pkey_ecx_keygen25519/448`,
//! `s390x_pkey_ecd_keygen25519/448`, `s390x_pkey_ecx_derive25519/448`,
//! `s390x_pkey_ecd_digest{sig,verify}{25519,448}` and the four `*_s390x_pkey_meth` objects. On this
//! profile `S390X_EC_ASM` is undefined, so none is compiled, none raises on a reachable path, and
//! the four accessors' `#ifdef` guards are dead. Their 10 `ERR_raise` sites are still generated
//! (`err_sites.rs`'s `ECX_METH_955` … `ECX_METH_1365`) because the generator records the whole file,
//! and they are **not** referenced here — only the seventeen portable sites are.
//!
//! ## The two header macros this unit is the second user of
//!
//! `KEYLENID`/`KEYNID2TYPE` are [`crate::ec::ecx_backend`]'s (`crypto/ec/ecx_backend.h`), and
//! `KEYTYPE2NID` (`include/crypto/ecx.h:51`) is defined here because this unit is its only caller.
//! `KEYLEN(p)` is the header's one-line `KEYLENID((p)->ameth->pkey_id)` and is written out at each
//! of its use sites rather than as a function, exactly as the header expands it.
//!
//! ## Where the Rust deliberately differs, each recorded at its site
//!
//! * `ecx_priv_encode` builds a stack `ASN1_OCTET_STRING` and **leaves `oct.type` uninitialised**
//!   (the authority does too). The crate's `Asn1String` has a `type_` field with no default, so the
//!   local sets `V_ASN1_OCTET_STRING`: the plain-octet encoder reads the item's type, not the
//!   string's, so the two agree, and the alternative — `MaybeUninit` — would make an unread field
//!   look like a hazard.
//! * `ecx_key_print`'s `BIO_printf` calls are the C varargs; the crate declares `BIO_printf` in
//!   `runtime/bio/print.rs` and each call passes the same argument shapes.
//! * `EVP_PKEY_FLAG_SIGCTX_CUSTOM` (4) is added to [`crate::evp::pkey_ctx`] by this entry: the two
//!   EdDSA methods are its only setters on the portable path.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1Item, Asn1Pctx, Asn1String, V_ASN1_UNDEF};
use crate::asn1::p8_pkey::{PKCS8_pkey_set0, Pkcs8PrivKeyInfo};
use crate::asn1::t_pkey::ASN1_buf_print;
use crate::asn1::typ::i2d_ASN1_OCTET_STRING;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0, X509_ALGOR_set0};
use crate::ec::curve25519::{ossl_ed25519_sign, ossl_ed25519_verify, ossl_x25519};
use crate::ec::curve448::{ossl_ed448_sign, ossl_ed448_verify, ossl_x448};
use crate::ec::ecx_backend::{
    is25519, isx448, keylenid, keynid2type, ossl_ecx_key_dup, ossl_ecx_key_fromdata,
    ossl_ecx_key_op, KEY_OP_KEYGEN, KEY_OP_PRIVATE, KEY_OP_PUBLIC,
};
use crate::ec::ecx_key::{ossl_ecx_key_free, ossl_ecx_key_new, EcxKey, X25519_KEYLEN, X448_KEYLEN};
use crate::evp::digest::{EVP_DigestVerifyInit, EVP_MD_CTX_get_pkey_ctx, EVP_md_null, EvpMdCtx};
use crate::evp::keymgmt::{EVP_KEYMGMT_get0_provider, KeymgmtImportFn};
use crate::evp::pkey::{
    evp_pkey_get_legacy, EVP_PKEY_assign, EvpPkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID,
    ASN1_PKEY_CTRL_GET1_TLS_ENCPT, ASN1_PKEY_CTRL_SET1_TLS_ENCPT, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY,
};
use crate::evp::pkey_asn1::{Asn1BitString, EvpPkeyAsn1Method};
use crate::evp::pkey_ctx::{
    EvpPkeyCtx, EvpPkeyMethod, EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY,
    EVP_PKEY_ED25519, EVP_PKEY_ED448, EVP_PKEY_FLAG_SIGCTX_CUSTOM, EVP_PKEY_X25519, EVP_PKEY_X448,
};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{OSSL_PARAM_locate_const, OsslParam};
use crate::provider::ossl_provider_libctx;
use crate::rsa::ameth::X509_SIG_INFO_TLS;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_memcmp, CRYPTO_memdup};
use crate::runtime::obj::{Asn1Object, NID_undef, OBJ_nid2ln, OBJ_nid2obj, NID_ED25519, NID_ED448};
use crate::x509::x509_set::{X509SigInfo, X509_SIG_INFO_set};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get0_param, X509_PUBKEY_set0_param};

const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ecx_meth.c".as_ptr();

/// `X25519_BITS` — `include/crypto/ecx.h:32`.
const X25519_BITS: c_int = 253;
/// `X25519_SECURITY_BITS` — `include/crypto/ecx.h:33`.
const X25519_SECURITY_BITS: c_int = 128;
/// `X448_BITS` — `include/crypto/ecx.h:35`.
const X448_BITS: c_int = 448;
/// `X448_SECURITY_BITS` — `include/crypto/ecx.h:36`.
const X448_SECURITY_BITS: c_int = 224;
/// `ED448_BITS` — `include/crypto/ecx.h:41`.
const ED448_BITS: c_int = 456;
/// `ED25519_SIGSIZE` — `include/crypto/ecx.h:38`.
const ED25519_SIGSIZE: usize = 64;
/// `ED448_SIGSIZE` — `include/crypto/ecx.h:44`.
const ED448_SIGSIZE: usize = 114;

/// `KEYLEN(p)` — `crypto/ec/ecx_backend.h:19`: a key's length from the method it was decoded with.
///
/// **`KEYTYPE2NID` is not transcribed, and that is a measurement rather than an omission:**
/// `include/crypto/ecx.h:51` defines it and **nothing in the whole authority calls it**
/// (`grep -rn KEYTYPE2NID` answers the definition and nothing else), so a Rust transcription would
/// be a function no landed path reaches. The name is named here rather than left as a silent gap.
fn keylen(pkey: *const EvpPkey) -> usize {
    // SAFETY: `pkey` is live and its `ameth` is the method it was assigned with.
    let id = unsafe { (*(*pkey).ameth).pkey_id };
    keylenid(id)
}

/// `static int ecx_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)` —
/// `crypto/ec/ecx_meth.c:28`.
///
/// # Safety
/// `pk` is live; `pkey` is live and holds a live `ECX_KEY`.
unsafe extern "C" fn ecx_pub_encode(pk: *mut X509Pubkey, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let ecxkey = unsafe { (*pkey).pkey.cast::<EcxKey>() };
    if ecxkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:37`).
        unsafe { raise_site(&err_sites::ECX_METH_37) };
        return 0;
    }

    // `OPENSSL_memdup(ecxkey->pubkey, KEYLEN(pkey))`.
    // SAFETY: `ecxkey` is live and its `pubkey` is `MAX_KEYLEN` bytes.
    let penc = unsafe { CRYPTO_memdup((*ecxkey).pubkey.as_ptr().cast(), keylen(pkey), FILE, 42) }
        .cast::<u8>();
    if penc.is_null() {
        return 0;
    }

    // SAFETY: `pk` is live; `penc` is the fresh copy this call owns.
    let ok = unsafe {
        X509_PUBKEY_set0_param(
            pk,
            OBJ_nid2obj((*(*pkey).ameth).pkey_id),
            V_ASN1_UNDEF,
            ptr::null_mut(),
            penc,
            keylen(pkey) as c_int,
        )
    };
    if ok == 0 {
        // SAFETY: `penc` is live and still owned here.
        unsafe { CRYPTO_clear_free(penc.cast(), keylen(pkey), FILE, 46) };
        // SAFETY: a compile-time-constant site (`ecx_meth.c:48`).
        unsafe { raise_site(&err_sites::ECX_METH_48) };
        return 0;
    }
    1
}

/// `static int ecx_pub_decode(EVP_PKEY *pkey, const X509_PUBKEY *pubkey)` —
/// `crypto/ec/ecx_meth.c:52`.
///
/// # Safety
/// `pkey` is live; `pubkey` is live.
unsafe extern "C" fn ecx_pub_decode(pkey: *mut EvpPkey, pubkey: *const X509Pubkey) -> c_int {
    let mut p: *const u8 = ptr::null();
    let mut pklen: c_int = 0;
    let mut palg: *mut X509Algor = ptr::null_mut();

    // SAFETY: `pubkey` is live and the three out-slots are this frame's.
    if unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &mut p, &mut pklen, &mut palg, pubkey) }
        == 0
    {
        return 0;
    }
    // SAFETY: `pkey` is live; `palg`/`p`/`pklen` are the decoded triple.
    let ecx = unsafe {
        ossl_ecx_key_op(
            palg,
            p,
            pklen,
            (*(*pkey).ameth).pkey_id,
            KEY_OP_PUBLIC,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    if !ecx.is_null() {
        // SAFETY: `pkey` is live and `ecx` is the key this call transfers to it.
        unsafe { EVP_PKEY_assign(pkey, (*(*pkey).ameth).pkey_id, ecx.cast()) };
        return 1;
    }
    0
}

/// `static int ecx_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)` — `crypto/ec/ecx_meth.c:71`.
///
/// A negative answer is `-2`, the authority's "cannot compare" answer, and only a NULL key
/// produces it.
///
/// # Safety
/// `a` and `b` are live.
unsafe extern "C" fn ecx_pub_cmp(a: *const EvpPkey, b: *const EvpPkey) -> c_int {
    // SAFETY: both keys are live per the contract.
    let akey = unsafe { (*a).pkey.cast::<EcxKey>() };
    // SAFETY: both keys are live.
    let bkey = unsafe { (*b).pkey.cast::<EcxKey>() };

    if akey.is_null() || bkey.is_null() {
        return -2;
    }

    // SAFETY: both keys are live and their `pubkey` arrays are `MAX_KEYLEN` bytes; the length read
    // is the method's own key length, which is at most `MAX_KEYLEN`.
    c_int::from(
        unsafe {
            CRYPTO_memcmp(
                (*akey).pubkey.as_ptr().cast(),
                (*bkey).pubkey.as_ptr().cast(),
                keylen(a),
            )
        } == 0,
    )
}

/// `static int ecx_priv_decode_ex(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ec/ecx_meth.c:83`.
///
/// # Safety
/// `pkey` is live; `p8` is live; `libctx`/`propq` are NULL or live.
unsafe extern "C" fn ecx_priv_decode_ex(
    pkey: *mut EvpPkey,
    p8: *const Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: every argument is the caller's.
    let ecx = unsafe { crate::ec::ecx_backend::ossl_ecx_key_from_pkcs8(p8, libctx, propq) };
    if !ecx.is_null() {
        // SAFETY: `pkey` is live and `ecx` is the key this call transfers to it.
        unsafe { EVP_PKEY_assign(pkey, (*(*pkey).ameth).pkey_id, ecx.cast()) };
        return 1;
    }
    0
}

/// `static int ecx_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)` —
/// `crypto/ec/ecx_meth.c:95`.
///
/// The `ASN1_OCTET_STRING` is a stack object that **borrows** the key's private scalar: `oct.data`
/// points into the secure allocation and `oct.flags` is 0, so the encoder copies and never frees
/// it. The authority leaves `oct.type` unset; this transcription sets it (see the module doc).
///
/// # Safety
/// `p8` is live; `pkey` is live and holds a live `ECX_KEY`.
unsafe extern "C" fn ecx_priv_encode(p8: *mut Pkcs8PrivKeyInfo, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let ecxkey = unsafe { (*pkey).pkey.cast::<EcxKey>() };
    // SAFETY: `ecxkey` may be NULL; the check below is the authority's.
    if ecxkey.is_null() || unsafe { (*ecxkey).privkey }.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:106`).
        unsafe { raise_site(&err_sites::ECX_METH_106) };
        return 0;
    }

    // SAFETY: `ecxkey` is live and its `privkey` is `KEYLEN(pkey)` bytes.
    let oct = Asn1String {
        length: keylen(pkey) as c_int,
        // `oct.type` is left unset by the authority; the plain-octet encoder reads the item's
        // type, not this field, so the two agree (see the module doc).
        type_: crate::asn1::layout::V_ASN1_OCTET_STRING,
        // SAFETY: `ecxkey` is live and its private scalar is `KEYLEN(pkey)` bytes.
        data: unsafe { (*ecxkey).privkey }.cast::<c_uchar>(),
        flags: 0,
    };
    let mut penc: *mut u8 = ptr::null_mut();

    // SAFETY: `oct` is live for `oct.length` bytes and `penc` is this frame's slot.
    let penclen = unsafe { i2d_ASN1_OCTET_STRING(&raw const oct, &mut penc) };
    if penclen < 0 {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:116`).
        unsafe { raise_site(&err_sites::ECX_METH_116) };
        return 0;
    }

    // SAFETY: `p8` is live; `penc` is the fresh encoding this call transfers on success.
    let ok = unsafe {
        PKCS8_pkey_set0(
            p8,
            OBJ_nid2obj((*(*pkey).ameth).pkey_id),
            0,
            V_ASN1_UNDEF,
            ptr::null_mut(),
            penc,
            penclen,
        )
    };
    if ok == 0 {
        // SAFETY: `penc` is live and still owned here.
        unsafe { CRYPTO_clear_free(penc.cast(), penclen as usize, FILE, 121) };
        // SAFETY: a compile-time-constant site (`ecx_meth.c:123`).
        unsafe { raise_site(&err_sites::ECX_METH_123) };
        return 0;
    }
    1
}

/// `static int ecx_size(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:130`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ecx_size(pkey: *const EvpPkey) -> c_int {
    keylen(pkey) as c_int
}

/// `static int ecx_bits(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:135`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ecx_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let id = unsafe { (*(*pkey).ameth).pkey_id };
    if is25519(id) {
        X25519_BITS
    } else if isx448(id) {
        X448_BITS
    } else {
        ED448_BITS
    }
}

/// `static int ecx_security_bits(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:146`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ecx_security_bits(pkey: *const EvpPkey) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let id = unsafe { (*(*pkey).ameth).pkey_id };
    if is25519(id) {
        X25519_SECURITY_BITS
    } else {
        X448_SECURITY_BITS
    }
}

/// `static void ecx_free(EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:156`.
///
/// # Safety
/// `pkey` is live.
unsafe extern "C" fn ecx_free(pkey: *mut EvpPkey) {
    // SAFETY: `pkey` is live per the contract.
    unsafe { ossl_ecx_key_free((*pkey).pkey.cast::<EcxKey>()) };
}

/// `static int ecx_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)` —
/// `crypto/ec/ecx_meth.c:161`. "parameters" are always equal.
///
/// # Safety
/// The two arguments are live; they are unread.
unsafe extern "C" fn ecx_cmp_parameters(_a: *const EvpPkey, _b: *const EvpPkey) -> c_int {
    1
}

/// `static int ecx_key_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx,
/// ecx_key_op_t op)` — `crypto/ec/ecx_meth.c:167`.
///
/// # Safety
/// `bp` is live; `pkey` is live; `ctx` is unread.
unsafe extern "C" fn ecx_key_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
    op: c_int,
) -> c_int {
    // SAFETY: `pkey` is live per the contract.
    let ecxkey = unsafe { (*pkey).pkey.cast::<EcxKey>() };
    // SAFETY: `pkey` is live and its method's `pkey_id` names the long name.
    let nm = OBJ_nid2ln(unsafe { (*(*pkey).ameth).pkey_id });

    if op == KEY_OP_PRIVATE {
        // SAFETY: `ecxkey` may be NULL; the check is the authority's.
        if ecxkey.is_null() || unsafe { (*ecxkey).privkey }.is_null() {
            // SAFETY: the `%*s` shape is `BIO_printf`'s, and `bp` is live.
            if unsafe {
                BIO_printf(
                    bp,
                    c"%*s<INVALID PRIVATE KEY>\n".as_ptr(),
                    indent,
                    c"".as_ptr(),
                )
            } <= 0
            {
                return 0;
            }
            return 1;
        }
        // SAFETY: the same contract.
        if unsafe { BIO_printf(bp, c"%*s%s Private-Key:\n".as_ptr(), indent, nm) } <= 0 {
            return 0;
        }
        // SAFETY: the same contract.
        if unsafe { BIO_printf(bp, c"%*spriv:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `ecxkey` is live and its private scalar is `KEYLEN(pkey)` bytes.
        if unsafe {
            ASN1_buf_print(
                bp,
                (*ecxkey).privkey.cast::<c_uchar>(),
                keylen(pkey),
                indent + 4,
            )
        } == 0
        {
            return 0;
        }
    } else {
        if ecxkey.is_null() {
            // SAFETY: the `%*s` shape is `BIO_printf`'s, and `bp` is live.
            if unsafe {
                BIO_printf(
                    bp,
                    c"%*s<INVALID PUBLIC KEY>\n".as_ptr(),
                    indent,
                    c"".as_ptr(),
                )
            } <= 0
            {
                return 0;
            }
            return 1;
        }
        // SAFETY: the same contract.
        if unsafe { BIO_printf(bp, c"%*s%s Public-Key:\n".as_ptr(), indent, nm) } <= 0 {
            return 0;
        }
    }
    // SAFETY: the same contract.
    if unsafe { BIO_printf(bp, c"%*spub:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }

    // SAFETY: `ecxkey` is non-NULL on every path that reaches here and its `pubkey` is
    // `KEYLEN(pkey)` bytes.
    if unsafe {
        ASN1_buf_print(
            bp,
            (*ecxkey).pubkey.as_ptr().cast::<c_uchar>(),
            keylen(pkey),
            indent + 4,
        )
    } == 0
    {
        return 0;
    }
    1
}

/// `static int ecx_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/ec/ecx_meth.c:207`.
///
/// # Safety
/// `bp`/`pkey` are live; `ctx` is unread.
unsafe extern "C" fn ecx_priv_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: the arguments match `ecx_key_print`'s contract.
    unsafe { ecx_key_print(bp, pkey, indent, _ctx, KEY_OP_PRIVATE) }
}

/// `static int ecx_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)` —
/// `crypto/ec/ecx_meth.c:213`.
///
/// # Safety
/// `bp`/`pkey` are live; `ctx` is unread.
unsafe extern "C" fn ecx_pub_print(
    bp: *mut Bio,
    pkey: *const EvpPkey,
    indent: c_int,
    _ctx: *mut Asn1Pctx,
) -> c_int {
    // SAFETY: the arguments match `ecx_key_print`'s contract.
    unsafe { ecx_key_print(bp, pkey, indent, _ctx, KEY_OP_PUBLIC) }
}

/// `static int ecx_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/ec/ecx_meth.c:219`.
///
/// # Safety
/// `pkey` is live; `arg2` is the argument the `op` names.
unsafe extern "C" fn ecx_ctrl(
    pkey: *mut EvpPkey,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
            // SAFETY: `pkey` is live; `arg2` is the encoded public key of `arg1` bytes.
            let ecx = unsafe {
                ossl_ecx_key_op(
                    ptr::null(),
                    arg2.cast::<u8>(),
                    arg1 as c_int,
                    (*(*pkey).ameth).pkey_id,
                    KEY_OP_PUBLIC,
                    ptr::null_mut(),
                    ptr::null(),
                )
            };
            if !ecx.is_null() {
                // SAFETY: `pkey` is live and `ecx` is the key this call transfers to it.
                unsafe { EVP_PKEY_assign(pkey, (*(*pkey).ameth).pkey_id, ecx.cast()) };
                return 1;
            }
            0
        }
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
            // SAFETY: `pkey` is live.
            if unsafe { (*pkey).pkey }.is_null() {
                return 0;
            }
            let ppt = arg2.cast::<*mut u8>();
            // SAFETY: `pkey` is live and its union holds this method's live `ECX_KEY`.
            let ecxkey = unsafe { (*pkey).pkey }.cast::<EcxKey>();
            // SAFETY: `ppt` is the caller's output slot and the key's `pubkey` is `KEYLEN(pkey)`
            // bytes.
            let p =
                unsafe { CRYPTO_memdup((*ecxkey).pubkey.as_ptr().cast(), keylen(pkey), FILE, 244) }
                    .cast::<u8>();
            // SAFETY: `ppt` is the caller's writable slot.
            unsafe { *ppt = p };
            if !p.is_null() {
                return keylen(pkey) as c_int;
            }
            0
        }
        _ => -2,
    }
}

/// `static int ecd_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)` —
/// `crypto/ec/ecx_meth.c:251`. We currently only support Pure EdDSA which takes no digest.
///
/// # Safety
/// `arg2` is a writable `int` for `ASN1_PKEY_CTRL_DEFAULT_MD_NID`.
unsafe extern "C" fn ecd_ctrl(
    _pkey: *mut EvpPkey,
    op: c_int,
    _arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    if op == ASN1_PKEY_CTRL_DEFAULT_MD_NID {
        // SAFETY: `arg2` is the caller's writable `int` slot per the callback contract.
        unsafe { *arg2.cast::<c_int>() = NID_undef };
        return 2;
    }
    -2
}

/// `static int ecx_set_priv_key(EVP_PKEY *pkey, const unsigned char *priv, size_t len)` —
/// `crypto/ec/ecx_meth.c:262`.
///
/// # Safety
/// `pkey` is live; `priv` is readable for `len` bytes.
unsafe extern "C" fn ecx_set_priv_key(pkey: *mut EvpPkey, priv_: *const u8, len: usize) -> c_int {
    let mut libctx: *mut c_void = ptr::null_mut();

    // SAFETY: `pkey` is live.
    if !unsafe { (*pkey).keymgmt }.is_null() {
        // SAFETY: `pkey` is live and its `keymgmt` is live.
        libctx = unsafe { ossl_provider_libctx(EVP_KEYMGMT_get0_provider((*pkey).keymgmt)) };
    }

    // SAFETY: `priv_` is readable for `len` bytes; `libctx` is as computed.
    let ecx = unsafe {
        ossl_ecx_key_op(
            ptr::null(),
            priv_,
            len as c_int,
            (*(*pkey).ameth).pkey_id,
            KEY_OP_PRIVATE,
            libctx,
            ptr::null(),
        )
    };
    if !ecx.is_null() {
        // SAFETY: `pkey` is live and `ecx` is the key this call transfers to it.
        unsafe { EVP_PKEY_assign(pkey, (*(*pkey).ameth).pkey_id, ecx.cast()) };
        return 1;
    }
    0
}

/// `static int ecx_set_pub_key(EVP_PKEY *pkey, const unsigned char *pub, size_t len)` —
/// `crypto/ec/ecx_meth.c:280`.
///
/// # Safety
/// `pkey` is live; `pub` is readable for `len` bytes.
unsafe extern "C" fn ecx_set_pub_key(pkey: *mut EvpPkey, pub_: *const u8, len: usize) -> c_int {
    let mut libctx: *mut c_void = ptr::null_mut();

    // SAFETY: `pkey` is live.
    if !unsafe { (*pkey).keymgmt }.is_null() {
        // SAFETY: `pkey` is live and its `keymgmt` is live.
        libctx = unsafe { ossl_provider_libctx(EVP_KEYMGMT_get0_provider((*pkey).keymgmt)) };
    }

    // SAFETY: `pub_` is readable for `len` bytes; `libctx` is as computed.
    let ecx = unsafe {
        ossl_ecx_key_op(
            ptr::null(),
            pub_,
            len as c_int,
            (*(*pkey).ameth).pkey_id,
            KEY_OP_PUBLIC,
            libctx,
            ptr::null(),
        )
    };
    if !ecx.is_null() {
        // SAFETY: `pkey` is live and `ecx` is the key this call transfers to it.
        unsafe { EVP_PKEY_assign(pkey, (*(*pkey).ameth).pkey_id, ecx.cast()) };
        return 1;
    }
    0
}

/// `static int ecx_get_priv_key(const EVP_PKEY *pkey, unsigned char *priv, size_t *len)` —
/// `crypto/ec/ecx_meth.c:298`.
///
/// # Safety
/// `pkey` is live; `len` is writable for one `size_t`; `priv` is NULL or writable for `*len`.
unsafe extern "C" fn ecx_get_priv_key(
    pkey: *const EvpPkey,
    priv_: *mut u8,
    len: *mut usize,
) -> c_int {
    // SAFETY: `pkey` is live.
    let key = unsafe { (*pkey).pkey.cast::<EcxKey>() };
    // SAFETY: `pkey` is live and its method names the key length.
    let klen = keylenid(unsafe { (*(*pkey).ameth).pkey_id });

    if priv_.is_null() {
        // SAFETY: `len` is writable per the contract.
        unsafe { *len = klen };
        return 1;
    }

    // SAFETY: `key` may be NULL; `len` is readable.
    if key.is_null() || unsafe { (*key).privkey }.is_null() || unsafe { *len } < klen {
        return 0;
    }

    // SAFETY: `len` is writable.
    unsafe { *len = klen };
    // SAFETY: `priv_` is writable for `klen` bytes and `key`'s private scalar is `klen` long.
    unsafe { ptr::copy_nonoverlapping((*key).privkey, priv_, klen) };

    1
}

/// `static int ecx_get_pub_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len)` —
/// `crypto/ec/ecx_meth.c:322`.
///
/// # Safety
/// `pkey` is live; `len` is writable for one `size_t`; `pub` is NULL or writable for `*len`.
unsafe extern "C" fn ecx_get_pub_key(
    pkey: *const EvpPkey,
    pub_: *mut u8,
    len: *mut usize,
) -> c_int {
    // SAFETY: `pkey` is live.
    let key = unsafe { (*pkey).pkey.cast::<EcxKey>() };
    // SAFETY: `pkey` is live and its method names the key length.
    let klen = keylenid(unsafe { (*(*pkey).ameth).pkey_id });

    if pub_.is_null() {
        // SAFETY: `len` is writable per the contract.
        unsafe { *len = klen };
        return 1;
    }

    // SAFETY: `key` may be NULL; `len` is readable.
    if key.is_null() || unsafe { *len } < klen {
        return 0;
    }

    // SAFETY: `len` is writable.
    unsafe { *len = klen };
    // SAFETY: `pub_` is writable for `klen` bytes and `key`'s `pubkey` is at least that long.
    unsafe { ptr::copy_nonoverlapping((*key).pubkey.as_ptr(), pub_, klen) };

    1
}

/// `static size_t ecx_pkey_dirty_cnt(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:344`.
///
/// The authority provides no way to update an ECX key once set, so the count is the constant 1.
///
/// # Safety
/// `pkey` is live; it is unread.
unsafe extern "C" fn ecx_pkey_dirty_cnt(_pkey: *const EvpPkey) -> usize {
    1
}

/// `static int ecx_pkey_export_to(const EVP_PKEY *from, void *to_keydata,
/// OSSL_FUNC_keymgmt_import_fn *importer, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ec/ecx_meth.c:352`.
///
/// The authority dereferences `from->pkey.ecx` without a NULL test — this is only reached for a key
/// this method already accepted — and `libctx`/`propq` are unused on the C path too.
///
/// # Safety
/// `from` is live and holds a live `ECX_KEY`; `importer` is the destination's own function.
unsafe extern "C" fn ecx_pkey_export_to(
    from: *const EvpPkey,
    to_keydata: *mut c_void,
    importer: Option<KeymgmtImportFn>,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    // SAFETY: `from` is live per the contract.
    let key = unsafe { (*from).pkey.cast::<EcxKey>() };

    let tmpl = OSSL_PARAM_BLD_new();
    let mut params: *mut OsslParam = ptr::null_mut();
    let mut selection: c_int = 0;
    let mut rv: c_int = 0;

    if tmpl.is_null() {
        return 0;
    }

    /* A key must at least have a public part. */
    // SAFETY: `tmpl` is live and `key`'s `pubkey` is `keylen` bytes.
    if unsafe {
        OSSL_PARAM_BLD_push_octet_string(
            tmpl,
            OSSL_PKEY_PARAM_PUB_KEY,
            (*key).pubkey.as_ptr().cast(),
            (*key).keylen,
        )
    } == 0
    {
        // goto err
        // SAFETY: `tmpl` is live.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        // SAFETY: `params` is NULL.
        unsafe { OSSL_PARAM_free(params) };
        return rv;
    }
    selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    // SAFETY: `key` is live.
    if !unsafe { (*key).privkey }.is_null() {
        // SAFETY: `tmpl` is live and `key`'s private scalar is `keylen` bytes.
        if unsafe {
            OSSL_PARAM_BLD_push_octet_string(
                tmpl,
                OSSL_PKEY_PARAM_PRIV_KEY,
                (*key).privkey.cast(),
                (*key).keylen,
            )
        } == 0
        {
            // goto err
            // SAFETY: `tmpl` is live.
            unsafe { OSSL_PARAM_BLD_free(tmpl) };
            // SAFETY: `params` is NULL.
            unsafe { OSSL_PARAM_free(params) };
            return rv;
        }
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }

    // SAFETY: `tmpl` is live.
    params = unsafe { OSSL_PARAM_BLD_to_param(tmpl) };

    /* We export, the provider imports. */
    // SAFETY: `importer` is the destination's own function.
    rv = unsafe { importer.map_or(0, |f| f(to_keydata, selection, params)) };

    // SAFETY: both pointers are live (or NULL) and this call owns them.
    unsafe {
        OSSL_PARAM_BLD_free(tmpl);
        OSSL_PARAM_free(params);
    }
    rv
}

/// `static int ecx_generic_import_from(const OSSL_PARAM params[], void *vpctx, int keytype)` —
/// `crypto/ec/ecx_meth.c:385`.
///
/// The `ERR_raise` is **`ERR_LIB_DH`**, not `ERR_LIB_EC`: the authority's own slip, and
/// `err_sites.rs`'s `ECX_METH_395` records it as lib 5.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn ecx_generic_import_from(
    params: *const OsslParam,
    vpctx: *mut c_void,
    keytype: c_int,
) -> c_int {
    let pctx = vpctx.cast::<EvpPkeyCtx>();
    // SAFETY: `pctx` is live per the contract.
    let pkey = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey(pctx) };
    // SAFETY: `pctx` is live and its `libctx`/`propquery` are its own.
    let ecx =
        unsafe { ossl_ecx_key_new((*pctx).libctx, keynid2type(keytype), 0, (*pctx).propquery) };
    // SAFETY: `params` is a live array.
    let pub_ = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY) };
    // SAFETY: `params` is a live array.
    let priv_ = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY) };

    if ecx.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:395`, `ERR_LIB_DH`).
        unsafe { raise_site(&err_sites::ECX_METH_395) };
        return 0;
    }

    // SAFETY: `ecx` is live; `pkey` is live; `pub_`/`priv_` are NULL or live; `keytype` is the
    // method's own id.
    if unsafe { ossl_ecx_key_fromdata(ecx, pub_, priv_, 1) } == 0
        // SAFETY: `pkey` is live and `ecx` is this function's own key.
        || unsafe { EVP_PKEY_assign(pkey, keytype, ecx.cast()) } == 0
    {
        // SAFETY: `ecx` is live and not yet owned by `pkey`.
        unsafe { ossl_ecx_key_free(ecx) };
        return 0;
    }
    1
}

/// `static int ecx_pkey_copy(EVP_PKEY *to, EVP_PKEY *from)` — `crypto/ec/ecx_meth.c:409`.
///
/// # Safety
/// `to` and `from` are live.
unsafe extern "C" fn ecx_pkey_copy(to: *mut EvpPkey, from: *mut EvpPkey) -> c_int {
    // SAFETY: `from` is live per the contract.
    let ecx = unsafe { (*from).pkey.cast::<EcxKey>() };
    let mut dupkey: *mut EcxKey = ptr::null_mut();

    if !ecx.is_null() {
        // SAFETY: `ecx` is live.
        dupkey = unsafe { ossl_ecx_key_dup(ecx, OSSL_KEYMGMT_SELECT_ALL) };
        if dupkey.is_null() {
            return 0;
        }
    }

    // SAFETY: `to` is live and `dupkey` is the fresh copy this call transfers on success.
    let ret = unsafe { EVP_PKEY_assign(to, (*from).type_, dupkey.cast()) };
    if ret == 0 {
        // SAFETY: `dupkey` is live and still owned here.
        unsafe { ossl_ecx_key_free(dupkey) };
    }
    ret
}

/// `static int x25519_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/ec/ecx_meth.c:425`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn x25519_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecx_generic_import_from(params, vpctx, EVP_PKEY_X25519) }
}

/// `static int x448_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/ec/ecx_meth.c:475`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn x448_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecx_generic_import_from(params, vpctx, EVP_PKEY_X448) }
}

/// `static int ecd_size25519(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:533`.
///
/// # Safety
/// `pkey` is live; it is unread.
unsafe extern "C" fn ecd_size25519(_pkey: *const EvpPkey) -> c_int {
    ED25519_SIGSIZE as c_int
}

/// `static int ecd_size448(const EVP_PKEY *pkey)` — `crypto/ec/ecx_meth.c:538`.
///
/// # Safety
/// `pkey` is live; it is unread.
unsafe extern "C" fn ecd_size448(_pkey: *const EvpPkey) -> c_int {
    ED448_SIGSIZE as c_int
}

/// `static int ecd_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *asn,
/// const X509_ALGOR *sigalg, const ASN1_BIT_STRING *str, EVP_PKEY *pkey)` —
/// `crypto/ec/ecx_meth.c:543`.
///
/// # Safety
/// `ctx`/`sigalg`/`pkey` are live; `it` and `str` are unread.
unsafe extern "C" fn ecd_item_verify(
    ctx: *mut EvpMdCtx,
    _it: *const Asn1Item,
    _asn: *const c_void,
    sigalg: *const X509Algor,
    _str: *const Asn1BitString,
    pkey: *mut EvpPkey,
) -> c_int {
    let mut obj: *const Asn1Object = ptr::null();
    let mut ptype: c_int = 0;

    /* Sanity check: make sure it is ED25519/ED448 with absent parameters. */
    // SAFETY: `sigalg` is live and `obj`/`ptype` are this frame's slots.
    unsafe { X509_ALGOR_get0(&mut obj, &mut ptype, ptr::null_mut(), sigalg) };
    // SAFETY: `obj` is the algorithm object `sigalg` owns.
    let nid = unsafe { crate::runtime::obj::OBJ_obj2nid(obj) };
    if (nid != NID_ED25519 && nid != NID_ED448) || ptype != V_ASN1_UNDEF {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:554`).
        unsafe { raise_site(&err_sites::ECX_METH_554) };
        return 0;
    }

    // SAFETY: `ctx` and `pkey` are live; the three NULLs are the authority's own.
    if unsafe { EVP_DigestVerifyInit(ctx, ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey) }
        == 0
    {
        return 0;
    }

    2
}

/// `static int ecd_item_sign(X509_ALGOR *alg1, X509_ALGOR *alg2, int nid)` —
/// `crypto/ec/ecx_meth.c:564`.
///
/// # Safety
/// `alg1` is live; `alg2` is NULL or live.
unsafe extern "C" fn ecd_item_sign(
    alg1: *mut X509Algor,
    alg2: *mut X509Algor,
    nid: c_int,
) -> c_int {
    /* Note that X509_ALGOR_set0(..., ..., V_ASN1_UNDEF, ...) cannot fail. */
    // SAFETY: `alg1` is live and its parameter slot takes `V_ASN1_UNDEF`.
    unsafe { X509_ALGOR_set0(alg1, OBJ_nid2obj(nid), V_ASN1_UNDEF, ptr::null_mut()) };
    if !alg2.is_null() {
        // SAFETY: `alg2` is live and its parameter slot takes `V_ASN1_UNDEF`.
        unsafe { X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_UNDEF, ptr::null_mut()) };
    }
    3
}

/// `static int ecd_item_sign25519(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *asn,
/// X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *str)` —
/// `crypto/ec/ecx_meth.c:576`.
///
/// # Safety
/// `alg1` is live; `alg2` is NULL or live; the other three are unread.
unsafe extern "C" fn ecd_item_sign25519(
    _ctx: *mut EvpMdCtx,
    _it: *const Asn1Item,
    _asn: *const c_void,
    alg1: *mut X509Algor,
    alg2: *mut X509Algor,
    _str: *mut Asn1BitString,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecd_item_sign(alg1, alg2, NID_ED25519) }
}

/// `static int ecd_sig_info_set25519(X509_SIG_INFO *siginf, const X509_ALGOR *alg,
/// const ASN1_STRING *sig)` — `crypto/ec/ecx_meth.c:583`.
///
/// # Safety
/// `siginf` is writable; `alg`/`sig` are live and unread.
unsafe extern "C" fn ecd_sig_info_set25519(
    siginf: *mut X509SigInfo,
    _alg: *const X509Algor,
    _sig: *const Asn1String,
) -> c_int {
    // SAFETY: `siginf` is writable per the contract.
    unsafe {
        X509_SIG_INFO_set(
            siginf,
            NID_undef,
            NID_ED25519,
            X25519_SECURITY_BITS,
            X509_SIG_INFO_TLS,
        )
    };
    1
}

/// `static int ecd_item_sign448(EVP_MD_CTX *ctx, const ASN1_ITEM *it, const void *asn,
/// X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *str)` —
/// `crypto/ec/ecx_meth.c:590`.
///
/// # Safety
/// `alg1` is live; `alg2` is NULL or live; the other three are unread.
unsafe extern "C" fn ecd_item_sign448(
    _ctx: *mut EvpMdCtx,
    _it: *const Asn1Item,
    _asn: *const c_void,
    alg1: *mut X509Algor,
    alg2: *mut X509Algor,
    _str: *mut Asn1BitString,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecd_item_sign(alg1, alg2, NID_ED448) }
}

/// `static int ecd_sig_info_set448(X509_SIG_INFO *siginf, const X509_ALGOR *alg,
/// const ASN1_STRING *sig)` — `crypto/ec/ecx_meth.c:597`.
///
/// # Safety
/// `siginf` is writable; `alg`/`sig` are live and unread.
unsafe extern "C" fn ecd_sig_info_set448(
    siginf: *mut X509SigInfo,
    _alg: *const X509Algor,
    _sig: *const Asn1String,
) -> c_int {
    // SAFETY: `siginf` is writable per the contract.
    unsafe {
        X509_SIG_INFO_set(
            siginf,
            NID_undef,
            NID_ED448,
            X448_SECURITY_BITS,
            X509_SIG_INFO_TLS,
        )
    };
    1
}

/// `static int ed25519_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/ec/ecx_meth.c:604`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn ed25519_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecx_generic_import_from(params, vpctx, EVP_PKEY_ED25519) }
}

/// `static int ed448_import_from(const OSSL_PARAM params[], void *vpctx)` —
/// `crypto/ec/ecx_meth.c:654`.
///
/// # Safety
/// `params` is a live parameter array; `vpctx` is a live `EVP_PKEY_CTX`.
unsafe extern "C" fn ed448_import_from(params: *const OsslParam, vpctx: *mut c_void) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { ecx_generic_import_from(params, vpctx, EVP_PKEY_ED448) }
}

/// `const EVP_PKEY_ASN1_METHOD ossl_ecx25519_asn1_meth` — `crypto/ec/ecx_meth.c:429-472`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_ecx25519_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_X25519,
    pkey_base_id: EVP_PKEY_X25519,
    pkey_flags: 0,
    pem_str: c"X25519".as_ptr() as *mut c_char,
    info: c"OpenSSL X25519 algorithm".as_ptr() as *mut c_char,
    pub_decode: Some(ecx_pub_decode),
    pub_encode: Some(ecx_pub_encode),
    pub_cmp: Some(ecx_pub_cmp),
    pub_print: Some(ecx_pub_print),
    priv_decode: None,
    priv_encode: Some(ecx_priv_encode),
    priv_print: Some(ecx_priv_print),
    pkey_size: Some(ecx_size),
    pkey_bits: Some(ecx_bits),
    pkey_security_bits: Some(ecx_security_bits),
    param_decode: None,
    param_encode: None,
    param_missing: None,
    param_copy: None,
    param_cmp: Some(ecx_cmp_parameters),
    param_print: None,
    sig_print: None,
    pkey_free: Some(ecx_free),
    pkey_ctrl: Some(ecx_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: None,
    item_sign: None,
    siginf_set: None,
    pkey_check: None,
    pkey_public_check: None,
    pkey_param_check: None,
    set_priv_key: Some(ecx_set_priv_key),
    set_pub_key: Some(ecx_set_pub_key),
    get_priv_key: Some(ecx_get_priv_key),
    get_pub_key: Some(ecx_get_pub_key),
    dirty_cnt: Some(ecx_pkey_dirty_cnt),
    export_to: Some(ecx_pkey_export_to),
    import_from: Some(x25519_import_from),
    copy: Some(ecx_pkey_copy),
    priv_decode_ex: Some(ecx_priv_decode_ex),
};

/// `const EVP_PKEY_ASN1_METHOD ossl_ecx448_asn1_meth` — `crypto/ec/ecx_meth.c:479-522`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_ecx448_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_X448,
    pkey_base_id: EVP_PKEY_X448,
    pkey_flags: 0,
    pem_str: c"X448".as_ptr() as *mut c_char,
    info: c"OpenSSL X448 algorithm".as_ptr() as *mut c_char,
    pub_decode: Some(ecx_pub_decode),
    pub_encode: Some(ecx_pub_encode),
    pub_cmp: Some(ecx_pub_cmp),
    pub_print: Some(ecx_pub_print),
    priv_decode: None,
    priv_encode: Some(ecx_priv_encode),
    priv_print: Some(ecx_priv_print),
    pkey_size: Some(ecx_size),
    pkey_bits: Some(ecx_bits),
    pkey_security_bits: Some(ecx_security_bits),
    param_decode: None,
    param_encode: None,
    param_missing: None,
    param_copy: None,
    param_cmp: Some(ecx_cmp_parameters),
    param_print: None,
    sig_print: None,
    pkey_free: Some(ecx_free),
    pkey_ctrl: Some(ecx_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: None,
    item_sign: None,
    siginf_set: None,
    pkey_check: None,
    pkey_public_check: None,
    pkey_param_check: None,
    set_priv_key: Some(ecx_set_priv_key),
    set_pub_key: Some(ecx_set_pub_key),
    get_priv_key: Some(ecx_get_priv_key),
    get_pub_key: Some(ecx_get_pub_key),
    dirty_cnt: Some(ecx_pkey_dirty_cnt),
    export_to: Some(ecx_pkey_export_to),
    import_from: Some(x448_import_from),
    copy: Some(ecx_pkey_copy),
    priv_decode_ex: Some(ecx_priv_decode_ex),
};

/// `const EVP_PKEY_ASN1_METHOD ossl_ed25519_asn1_meth` — `crypto/ec/ecx_meth.c:608-651`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_ed25519_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_ED25519,
    pkey_base_id: EVP_PKEY_ED25519,
    pkey_flags: 0,
    pem_str: c"ED25519".as_ptr() as *mut c_char,
    info: c"OpenSSL ED25519 algorithm".as_ptr() as *mut c_char,
    pub_decode: Some(ecx_pub_decode),
    pub_encode: Some(ecx_pub_encode),
    pub_cmp: Some(ecx_pub_cmp),
    pub_print: Some(ecx_pub_print),
    priv_decode: None,
    priv_encode: Some(ecx_priv_encode),
    priv_print: Some(ecx_priv_print),
    pkey_size: Some(ecd_size25519),
    pkey_bits: Some(ecx_bits),
    pkey_security_bits: Some(ecx_security_bits),
    param_decode: None,
    param_encode: None,
    param_missing: None,
    param_copy: None,
    param_cmp: Some(ecx_cmp_parameters),
    param_print: None,
    sig_print: None,
    pkey_free: Some(ecx_free),
    pkey_ctrl: Some(ecd_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: Some(ecd_item_verify),
    item_sign: Some(ecd_item_sign25519),
    siginf_set: Some(ecd_sig_info_set25519),
    pkey_check: None,
    pkey_public_check: None,
    pkey_param_check: None,
    set_priv_key: Some(ecx_set_priv_key),
    set_pub_key: Some(ecx_set_pub_key),
    get_priv_key: Some(ecx_get_priv_key),
    get_pub_key: Some(ecx_get_pub_key),
    dirty_cnt: Some(ecx_pkey_dirty_cnt),
    export_to: Some(ecx_pkey_export_to),
    import_from: Some(ed25519_import_from),
    copy: Some(ecx_pkey_copy),
    priv_decode_ex: Some(ecx_priv_decode_ex),
};

/// `const EVP_PKEY_ASN1_METHOD ossl_ed448_asn1_meth` — `crypto/ec/ecx_meth.c:658-701`.
#[allow(non_upper_case_globals)] // the authority's own object name
pub static ossl_ed448_asn1_meth: EvpPkeyAsn1Method = EvpPkeyAsn1Method {
    pkey_id: EVP_PKEY_ED448,
    pkey_base_id: EVP_PKEY_ED448,
    pkey_flags: 0,
    pem_str: c"ED448".as_ptr() as *mut c_char,
    info: c"OpenSSL ED448 algorithm".as_ptr() as *mut c_char,
    pub_decode: Some(ecx_pub_decode),
    pub_encode: Some(ecx_pub_encode),
    pub_cmp: Some(ecx_pub_cmp),
    pub_print: Some(ecx_pub_print),
    priv_decode: None,
    priv_encode: Some(ecx_priv_encode),
    priv_print: Some(ecx_priv_print),
    pkey_size: Some(ecd_size448),
    pkey_bits: Some(ecx_bits),
    pkey_security_bits: Some(ecx_security_bits),
    param_decode: None,
    param_encode: None,
    param_missing: None,
    param_copy: None,
    param_cmp: Some(ecx_cmp_parameters),
    param_print: None,
    sig_print: None,
    pkey_free: Some(ecx_free),
    pkey_ctrl: Some(ecd_ctrl),
    old_priv_decode: None,
    old_priv_encode: None,
    item_verify: Some(ecd_item_verify),
    item_sign: Some(ecd_item_sign448),
    siginf_set: Some(ecd_sig_info_set448),
    pkey_check: None,
    pkey_public_check: None,
    pkey_param_check: None,
    set_priv_key: Some(ecx_set_priv_key),
    set_pub_key: Some(ecx_set_pub_key),
    get_priv_key: Some(ecx_get_priv_key),
    get_pub_key: Some(ecx_get_pub_key),
    dirty_cnt: Some(ecx_pkey_dirty_cnt),
    export_to: Some(ecx_pkey_export_to),
    import_from: Some(ed448_import_from),
    copy: Some(ecx_pkey_copy),
    priv_decode_ex: Some(ecx_priv_decode_ex),
};

/// `static int pkey_ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)` —
/// `crypto/ec/ecx_meth.c:705`.
///
/// # Safety
/// `ctx` and `pkey` are live.
unsafe extern "C" fn pkey_ecx_keygen(ctx: *mut EvpPkeyCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live and its `pmeth` is the method that reached this callback.
    let ecx = unsafe {
        ossl_ecx_key_op(
            ptr::null(),
            ptr::null(),
            0,
            (*(*ctx).pmeth).pkey_id,
            KEY_OP_KEYGEN,
            ptr::null_mut(),
            ptr::null(),
        )
    };

    if !ecx.is_null() {
        // SAFETY: `ctx`/`pkey` are live and `ecx` is the key this call transfers to `pkey`.
        unsafe { EVP_PKEY_assign(pkey, (*(*ctx).pmeth).pkey_id, ecx.cast()) };
        return 1;
    }
    0
}

/// `static int validate_ecx_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen,
/// const unsigned char **privkey, const unsigned char **pubkey)` —
/// `crypto/ec/ecx_meth.c:725`.
///
/// # Safety
/// `ctx` is live; `key`/`keylen` are unread; each output pointer is a writable slot.
unsafe extern "C" fn validate_ecx_derive(
    ctx: *mut EvpPkeyCtx,
    _key: *mut u8,
    _keylen: *mut usize,
    privkey: *mut *const u8,
    pubkey: *mut *const u8,
) -> c_int {
    // SAFETY: `ctx` is live and its `pkey`/`peerkey` are NULL or live.
    if unsafe { (*ctx).pkey }.is_null() || unsafe { (*ctx).peerkey }.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:733`).
        unsafe { raise_site(&err_sites::ECX_METH_733) };
        return 0;
    }
    // SAFETY: both keys are live.
    let ecxkey = unsafe { evp_pkey_get_legacy((*ctx).pkey) }.cast::<EcxKey>();
    // SAFETY: both keys are live.
    let peerkey = unsafe { evp_pkey_get_legacy((*ctx).peerkey) }.cast::<EcxKey>();
    // SAFETY: `ecxkey` may be NULL.
    if ecxkey.is_null() || unsafe { (*ecxkey).privkey }.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:739`).
        unsafe { raise_site(&err_sites::ECX_METH_739) };
        return 0;
    }
    if peerkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:743`).
        unsafe { raise_site(&err_sites::ECX_METH_743) };
        return 0;
    }
    // SAFETY: both slots are writable per the contract.
    unsafe {
        *privkey = (*ecxkey).privkey;
        *pubkey = (*peerkey).pubkey.as_ptr();
    }

    1
}

/// `static int pkey_ecx_derive25519(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)` —
/// `crypto/ec/ecx_meth.c:751`.
///
/// # Safety
/// `ctx` is live; `key` is NULL or writable for 32 bytes; `keylen` is writable.
unsafe extern "C" fn pkey_ecx_derive25519(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    let mut privkey: *const u8 = ptr::null();
    let mut pubkey: *const u8 = ptr::null();

    // SAFETY: the arguments match `validate_ecx_derive`'s contract.
    if unsafe { validate_ecx_derive(ctx, key, keylen, &mut privkey, &mut pubkey) } == 0
        || (!key.is_null()
            // SAFETY: `key` is writable for 32 bytes; `privkey`/`pubkey` are live 32-byte keys.
            && unsafe { ossl_x25519(key, privkey, pubkey) } == 0)
    {
        return 0;
    }
    // SAFETY: `keylen` is writable per the contract.
    unsafe { *keylen = X25519_KEYLEN };
    1
}

/// `static int pkey_ecx_derive448(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)` —
/// `crypto/ec/ecx_meth.c:765`.
///
/// # Safety
/// `ctx` is live; `key` is NULL or writable for 56 bytes; `keylen` is writable.
unsafe extern "C" fn pkey_ecx_derive448(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    keylen: *mut usize,
) -> c_int {
    let mut privkey: *const u8 = ptr::null();
    let mut pubkey: *const u8 = ptr::null();

    // SAFETY: the arguments match `validate_ecx_derive`'s contract.
    if unsafe { validate_ecx_derive(ctx, key, keylen, &mut privkey, &mut pubkey) } == 0
        || (!key.is_null()
            // SAFETY: `key` is writable for 56 bytes; `privkey`/`pubkey` are live 56-byte keys.
            && unsafe { ossl_x448(key, privkey, pubkey) } == 0)
    {
        return 0;
    }
    // SAFETY: `keylen` is writable per the contract.
    unsafe { *keylen = X448_KEYLEN };
    1
}

/// `static int pkey_ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` —
/// `crypto/ec/ecx_meth.c:779`. Only the peer key matters for derivation.
///
/// # Safety
/// The arguments are live; `type` alone is read.
unsafe extern "C" fn pkey_ecx_ctrl(
    _ctx: *mut EvpPkeyCtx,
    type_: c_int,
    _p1: c_int,
    _p2: *mut c_void,
) -> c_int {
    if type_ == EVP_PKEY_CTRL_PEER_KEY {
        return 1;
    }
    -2
}

/// `static const EVP_PKEY_METHOD ecx25519_pkey_meth` — `crypto/ec/ecx_meth.c:786-796`.
///
/// Flags are **0** and the keygen column is `pkey_ecx_keygen`; the encode is
/// `ossl_ecx_key_op(..., KEY_OP_KEYGEN, ...)`, which randomises and clamps in the authority's own
/// `ossl_ecx_key_op`.
static ECX25519_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_X25519,
    flags: 0,
    init: None,
    copy: None,
    cleanup: None,
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_ecx_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: Some(pkey_ecx_derive25519),
    ctrl: Some(pkey_ecx_ctrl),
    ctrl_str: None,
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `static const EVP_PKEY_METHOD ecx448_pkey_meth` — `crypto/ec/ecx_meth.c:798-808`.
static ECX448_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_X448,
    flags: 0,
    init: None,
    copy: None,
    cleanup: None,
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_ecx_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: Some(pkey_ecx_derive448),
    ctrl: Some(pkey_ecx_ctrl),
    ctrl_str: None,
    digestsign: None,
    digestverify: None,
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `static int pkey_ecd_digestsign25519(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
/// const unsigned char *tbs, size_t tbslen)` — `crypto/ec/ecx_meth.c:810`.
///
/// # Safety
/// `ctx` is live; `sig` is NULL or writable for 64 bytes; `siglen` is writable; `tbs` is readable
/// for `tbslen`.
unsafe extern "C" fn pkey_ecd_digestsign25519(
    ctx: *mut EvpMdCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its pkey context holds the signing key.
    let edkey =
        unsafe { evp_pkey_get_legacy((*EVP_MD_CTX_get_pkey_ctx(ctx)).pkey) }.cast::<EcxKey>();

    if edkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:813`).
        unsafe { raise_site(&err_sites::ECX_METH_813) };
        return 0;
    }

    if sig.is_null() {
        // SAFETY: `siglen` is writable per the contract.
        unsafe { *siglen = ED25519_SIGSIZE };
        return 1;
    }
    // SAFETY: `siglen` is readable.
    if unsafe { *siglen } < ED25519_SIGSIZE {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:822`).
        unsafe { raise_site(&err_sites::ECX_METH_822) };
        return 0;
    }

    // SAFETY: `sig` is writable for 64 bytes; `tbs` is readable for `tbslen`; the key's
    // `pubkey`/`privkey` are 32 bytes; the four trailing NULLs are the authority's own.
    if unsafe {
        ossl_ed25519_sign(
            sig,
            tbs,
            tbslen,
            (*edkey).pubkey.as_ptr(),
            (*edkey).privkey,
            0,
            0,
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `siglen` is writable.
    unsafe { *siglen = ED25519_SIGSIZE };
    1
}

/// `static int pkey_ecd_digestsign448(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
/// const unsigned char *tbs, size_t tbslen)` — `crypto/ec/ecx_meth.c:840`.
///
/// # Safety
/// `ctx` is live; `sig` is NULL or writable for 114 bytes; `siglen` is writable; `tbs` is readable
/// for `tbslen`.
unsafe extern "C" fn pkey_ecd_digestsign448(
    ctx: *mut EvpMdCtx,
    sig: *mut u8,
    siglen: *mut usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its pkey context holds the signing key.
    let edkey =
        unsafe { evp_pkey_get_legacy((*EVP_MD_CTX_get_pkey_ctx(ctx)).pkey) }.cast::<EcxKey>();

    if edkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:843`).
        unsafe { raise_site(&err_sites::ECX_METH_843) };
        return 0;
    }

    if sig.is_null() {
        // SAFETY: `siglen` is writable per the contract.
        unsafe { *siglen = ED448_SIGSIZE };
        return 1;
    }
    // SAFETY: `siglen` is readable.
    if unsafe { *siglen } < ED448_SIGSIZE {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:852`).
        unsafe { raise_site(&err_sites::ECX_METH_852) };
        return 0;
    }

    // SAFETY: `sig` is writable for 114 bytes; `tbs` is readable for `tbslen`; the key's
    // fields are 57 bytes; the two trailing arguments are the key's own context and propq.
    if unsafe {
        ossl_ed448_sign(
            (*edkey).libctx,
            sig,
            tbs,
            tbslen,
            (*edkey).pubkey.as_ptr(),
            (*edkey).privkey,
            ptr::null(),
            0,
            0,
            (*edkey).propq,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `siglen` is writable.
    unsafe { *siglen = ED448_SIGSIZE };
    1
}

/// `static int pkey_ecd_digestverify25519(EVP_MD_CTX *ctx, const unsigned char *sig,
/// size_t siglen, const unsigned char *tbs, size_t tbslen)` — `crypto/ec/ecx_meth.c:864`.
///
/// # Safety
/// `ctx` is live; `sig` is readable for `siglen`; `tbs` is readable for `tbslen`.
unsafe extern "C" fn pkey_ecd_digestverify25519(
    ctx: *mut EvpMdCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its pkey context holds the verifying key.
    let edkey =
        unsafe { evp_pkey_get_legacy((*EVP_MD_CTX_get_pkey_ctx(ctx)).pkey) }.cast::<EcxKey>();

    if edkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:871`).
        unsafe { raise_site(&err_sites::ECX_METH_871) };
        return 0;
    }

    if siglen != ED25519_SIGSIZE {
        return 0;
    }

    // SAFETY: `sig` is readable for 64 bytes; `tbs` for `tbslen`; the key's `pubkey` is 32; the
    // four trailing NULLs are the authority's own; the last two are the key's own context.
    unsafe {
        ossl_ed25519_verify(
            tbs,
            tbslen,
            sig,
            (*edkey).pubkey.as_ptr(),
            0,
            0,
            0,
            ptr::null(),
            0,
            (*edkey).libctx,
            (*edkey).propq,
        )
    }
}

/// `static int pkey_ecd_digestverify448(EVP_MD_CTX *ctx, const unsigned char *sig,
/// size_t siglen, const unsigned char *tbs, size_t tbslen)` — `crypto/ec/ecx_meth.c:884`.
///
/// # Safety
/// `ctx` is live; `sig` is readable for `siglen`; `tbs` is readable for `tbslen`.
unsafe extern "C" fn pkey_ecd_digestverify448(
    ctx: *mut EvpMdCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    // SAFETY: `ctx` is live and its pkey context holds the verifying key.
    let edkey =
        unsafe { evp_pkey_get_legacy((*EVP_MD_CTX_get_pkey_ctx(ctx)).pkey) }.cast::<EcxKey>();

    if edkey.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_meth.c:891`).
        unsafe { raise_site(&err_sites::ECX_METH_891) };
        return 0;
    }

    if siglen != ED448_SIGSIZE {
        return 0;
    }

    // SAFETY: `sig` is readable for 114 bytes; `tbs` for `tbslen`; the key's `pubkey` is 57; the
    // two trailing arguments are the key's own context and propq.
    unsafe {
        ossl_ed448_verify(
            (*edkey).libctx,
            tbs,
            tbslen,
            sig,
            (*edkey).pubkey.as_ptr(),
            ptr::null(),
            0,
            0,
            (*edkey).propq,
        )
    }
}

/// `static int pkey_ecd_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)` —
/// `crypto/ec/ecx_meth.c:901`.
///
/// # Safety
/// `p2` is NULL or a live `EVP_MD`.
unsafe extern "C" fn pkey_ecd_ctrl(
    _ctx: *mut EvpPkeyCtx,
    type_: c_int,
    _p1: c_int,
    p2: *mut c_void,
) -> c_int {
    match type_ {
        EVP_PKEY_CTRL_MD => {
            /* Only NULL allowed as digest. */
            if p2.is_null() || p2.cast_const() == EVP_md_null().cast::<c_void>() {
                return 1;
            }
            // SAFETY: a compile-time-constant site (`ecx_meth.c:909`).
            unsafe { raise_site(&err_sites::ECX_METH_909) };
            0
        }
        EVP_PKEY_CTRL_DIGESTINIT => 1,
        _ => -2,
    }
}

/// `static const EVP_PKEY_METHOD ed25519_pkey_meth` — `crypto/ec/ecx_meth.c:914-926`.
///
/// `EVP_PKEY_FLAG_SIGCTX_CUSTOM` is the flag: the `digestsign`/`digestverify` pair drives the
/// signature itself rather than a digest-then-sign pair.
static ED25519_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_ED25519,
    flags: EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    init: None,
    copy: None,
    cleanup: None,
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_ecx_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: None,
    ctrl: Some(pkey_ecd_ctrl),
    ctrl_str: None,
    digestsign: Some(pkey_ecd_digestsign25519),
    digestverify: Some(pkey_ecd_digestverify25519),
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `static const EVP_PKEY_METHOD ed448_pkey_meth` — `crypto/ec/ecx_meth.c:928-940`.
static ED448_PKEY_METH: EvpPkeyMethod = EvpPkeyMethod {
    pkey_id: EVP_PKEY_ED448,
    flags: EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    init: None,
    copy: None,
    cleanup: None,
    paramgen_init: None,
    paramgen: None,
    keygen_init: None,
    keygen: Some(pkey_ecx_keygen),
    sign_init: None,
    sign: None,
    verify_init: None,
    verify: None,
    verify_recover_init: None,
    verify_recover: None,
    signctx_init: None,
    signctx: None,
    verifyctx_init: None,
    verifyctx: None,
    encrypt_init: None,
    encrypt: None,
    decrypt_init: None,
    decrypt: None,
    derive_init: None,
    derive: None,
    ctrl: Some(pkey_ecd_ctrl),
    ctrl_str: None,
    digestsign: Some(pkey_ecd_digestsign448),
    digestverify: Some(pkey_ecd_digestverify448),
    check: None,
    public_check: None,
    param_check: None,
    digest_custom: None,
};

/// `const EVP_PKEY_METHOD *ossl_ecx25519_pkey_method(void)` — `crypto/ec/ecx_meth.c:1391`.
///
/// The `#ifdef S390X_EC_ASM` arm is not compiled on this profile, so the portable table is the
/// answer unconditionally.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
pub(crate) unsafe extern "C" fn ossl_ecx25519_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(ECX25519_PKEY_METH)
}

/// `const EVP_PKEY_METHOD *ossl_ecx448_pkey_method(void)` — `crypto/ec/ecx_meth.c:1400`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
pub(crate) unsafe extern "C" fn ossl_ecx448_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(ECX448_PKEY_METH)
}

/// `const EVP_PKEY_METHOD *ossl_ed25519_pkey_method(void)` — `crypto/ec/ecx_meth.c:1409`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
pub(crate) unsafe extern "C" fn ossl_ed25519_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(ED25519_PKEY_METH)
}

/// `const EVP_PKEY_METHOD *ossl_ed448_pkey_method(void)` — `crypto/ec/ecx_meth.c:1421`.
///
/// # Safety
/// Nothing: the answer is a `static` of this module.
pub(crate) unsafe extern "C" fn ossl_ed448_pkey_method() -> *const EvpPkeyMethod {
    ptr::addr_of!(ED448_PKEY_METH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four `EVP_PKEY_ASN1_METHOD` objects by identity: the ids and both owned strings, which
    /// is what `EVP_PKEY_asn1_get0_info` and the two `find` functions read.
    #[test]
    fn ameth_objects_are_the_four_ecx_types() {
        let rows: [(_, c_int, &str); 4] = [
            (
                &ossl_ecx25519_asn1_meth,
                crate::runtime::obj::NID_X25519,
                "X25519",
            ),
            (
                &ossl_ecx448_asn1_meth,
                crate::runtime::obj::NID_X448,
                "X448",
            ),
            (
                &ossl_ed25519_asn1_meth,
                crate::runtime::obj::NID_ED25519,
                "ED25519",
            ),
            (
                &ossl_ed448_asn1_meth,
                crate::runtime::obj::NID_ED448,
                "ED448",
            ),
        ];
        for (row, id, pem) in rows {
            assert_eq!(row.pkey_id, id);
            assert_eq!(row.pkey_base_id, id);
            assert_eq!(row.pkey_flags, 0);
            // SAFETY: `pem_str` is a NUL-terminated literal this crate owns.
            let seen = unsafe { core::ffi::CStr::from_ptr(row.pem_str) };
            assert_eq!(seen.to_str().unwrap_or(""), pem);
            // The two EdDSA rows carry the sigctx pair; the two Montgomery rows do not.
            let is_eddsa =
                id == crate::runtime::obj::NID_ED25519 || id == crate::runtime::obj::NID_ED448;
            assert_eq!(row.item_sign.is_some(), is_eddsa);
            assert!(row.pub_decode.is_some() && row.priv_encode.is_some());
        }
    }

    /// The four `EVP_PKEY_METHOD` accessors: `pkey_id` and the flags word, which is what
    /// `EVP_PKEY_meth_get0_info` publishes and the only field difference between the rows.
    #[test]
    fn pmeth_accessors_are_the_four_ecx_types() {
        // SAFETY: each accessor answers a `static` of this module.
        let rows: [(*const EvpPkeyMethod, c_int, c_int); 4] = unsafe {
            [
                (
                    ossl_ecx25519_pkey_method(),
                    crate::runtime::obj::NID_X25519,
                    0,
                ),
                (ossl_ecx448_pkey_method(), crate::runtime::obj::NID_X448, 0),
                (
                    ossl_ed25519_pkey_method(),
                    crate::runtime::obj::NID_ED25519,
                    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
                ),
                (
                    ossl_ed448_pkey_method(),
                    crate::runtime::obj::NID_ED448,
                    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
                ),
            ]
        };
        for (meth, id, flags) in rows {
            // SAFETY: `meth` is a live `static`.
            unsafe {
                assert_eq!((*meth).pkey_id, id);
                assert_eq!((*meth).flags, flags);
                assert!((*meth).keygen.is_some());
            }
        }
    }
}
