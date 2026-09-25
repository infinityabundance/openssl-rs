//! Phase 10.1 — `providers/implementations/encode_decode/encode_key2text.c`: the provider's
//! **text encoders**, one `OSSL_OP_ENCODER` table per key type whose object layer is landed.
//!
//! This is the first unit of the encode/decode family to land (10.1). The framework that
//! *dispatches* to it — `src/encoder_meth.rs`, `src/encoder_lib.rs`, `src/encoder_pkey.rs` — is
//! Phase 8's 8.8 chain (D362), so this unit adds rows rather than symbols: 11 tables, one per key
//! type, published by both the `default` and the `base` provider.
//!
//! ## The row is a table over one shared engine
//!
//! Every table's dispatch is the authority's `MAKE_TEXT_ENCODER` expansion (`:652-696`): `newctx`
//! and `freectx` are the unit's two, shared by all eleven; `import_object`/`free_object` pilfer the
//! key type's own `ossl_*_keymgmt_functions`; and `encode` calls one of the five `*_to_text`
//! printers. So the "eleven implementations" are one engine and eleven table rows, which is the
//! measurement this stratum is for (`docs/PHASE-10-SUBPHASES.md` §1a).
//!
//! ## Why only eleven of the twenty-nine tables
//!
//! The authority's `MAKE_TEXT_ENCODER` list (`:698-744`) is twenty-nine tables. Eighteen of them are
//! `ML-KEM`/`ML-DSA`/`SLH-DSA`, whose `*_to_text` is not in this file at all: `ml_kem_to_text` calls
//! `ossl_ml_kem_key_to_text` (`providers/implementations/encode_decode/ml_kem_codecs.c`),
//! `ml_dsa_to_text` calls `ossl_ml_dsa_key_to_text` (`ml_dsa_codecs.c`) and `slh_dsa_to_text` calls
//! `ossl_slh_dsa_key_to_text` (`crypto/slh_dsa/slh_dsa_key.c:488-526`), and none of those three
//! units is landed. A table with no printable body would answer the wrong bytes for every key, so
//! the eighteen are **not published** rather than published empty; they are the `pending` rows
//! `docs/PHASE-10-SUBPHASES.md` §3.5 names, and the census leaves them `unimplemented`.
//!
//! ## The bytes are the contract
//!
//! `RT-CODEC` drives these rows through `OSSL_ENCODER_CTX_new_for_pkey(pkey, sel, "TEXT", …)` and
//! compares the transcript byte for byte against the authority's. The label layout, the
//! decimal-with-parenthesised-hex small-value form, the 15-byte-per-line hex blocks and the `X9.42`
//! parameter order are all observable; a transcription that round-trips a parse is not this.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::bn::bignum::{BN_num_bits, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dh::object::{
    ossl_dh_get0_params, DH_get0_p, DH_get0_priv_key, DH_get0_pub_key, DH_get_length,
};
use crate::dh::Dh;
use crate::dsa::object::{ossl_dsa_get0_params, DSA_get0_p, DSA_get0_priv_key, DSA_get0_pub_key};
use crate::dsa::Dsa;
use crate::ec::curve::EC_curve_nid2nist;
use crate::ec::ecx_key::{
    EcxKey, ECX_KEY_TYPE_ED25519, ECX_KEY_TYPE_ED448, ECX_KEY_TYPE_X25519, ECX_KEY_TYPE_X448,
};
use crate::ec::key::{
    ossl_ec_key_get_libctx, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
    EC_KEY_get_conv_form, EC_KEY_key2buf, EC_KEY_priv2buf,
};
use crate::ec::lib::{
    EC_GROUP_get0_cofactor, EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed,
    EC_GROUP_get_asn1_flag, EC_GROUP_get_basis_type, EC_GROUP_get_curve, EC_GROUP_get_curve_name,
    EC_GROUP_get_field_type, EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len,
    EC_GROUP_order_bits,
};
use crate::ec::oct::EC_POINT_point2buf;
use crate::ec::{
    EcGroup, EcKey, PointConversionForm, POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_HYBRID,
    POINT_CONVERSION_UNCOMPRESSED,
};
use crate::encoder_lib::{
    ossl_bio_print_ffc_params, ossl_bio_print_labeled_bignum, ossl_bio_print_labeled_buf,
};
use crate::encoder_meth::{
    OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREECTX, OSSL_FUNC_ENCODER_FREE_OBJECT,
    OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX,
};
use crate::evp::pkey::{
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::ffc::FfcParams;
use crate::params::OsslParam;
use crate::passphrase::OsslPassphraseCallback;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::endecoder_common::{ossl_prov_free_key, ossl_prov_import_key};
use crate::rsa::object::{
    ossl_rsa_get0_all_params, ossl_rsa_get0_pss_params_30, RSA_get0_key, RSA_test_flags,
    RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::{
    ossl_rsa_pss_params_30_hashalg, ossl_rsa_pss_params_30_is_unrestricted,
    ossl_rsa_pss_params_30_maskgenalg, ossl_rsa_pss_params_30_maskgenhashalg,
    ossl_rsa_pss_params_30_saltlen, ossl_rsa_pss_params_30_trailerfield,
};
use crate::rsa::schemes::{ossl_rsa_mgf_nid2name, ossl_rsa_oaeppss_nid2name};
use crate::rsa::Rsa;
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::{BIO_free, Bio};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free};
use crate::runtime::obj::{
    NID_X9_62_characteristic_two_field, NID_mgf1, NID_sha1, NID_undef, OBJ_nid2sn,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack,
};

/// `OPENSSL_EC_NAMED_CURVE` — `include/openssl/ec.h:1033`, read by `ec_param_to_text`.
const OPENSSL_EC_NAMED_CURVE: c_int = crate::evp::pkey_ctx::OPENSSL_EC_NAMED_CURVE;

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `include/openssl/evp.h:106`, the private-or-public pair. The
/// crate's `src/evp/pkey.rs` keeps it module-private, so it is spelled here from the two public
/// halves rather than widening that module's surface.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `static void *key2text_newctx(void *provctx)` — `encode_key2text.c:625-628`.
///
/// The authority returns `provctx` itself and allocates nothing, so `freectx` has nothing to free.
/// The encoder's `encode` therefore receives the provider context as `vctx`, which is what
/// `ossl_bio_new_from_core_bio(vctx, cout)` reads.
unsafe extern "C" fn key2text_newctx(provctx: *mut c_void) -> *mut c_void {
    provctx
}

/// `static void key2text_freectx(void *vctx)` — `encode_key2text.c:630-632`. Empty, as the
/// authority's is.
unsafe extern "C" fn key2text_freectx(_vctx: *mut c_void) {}

/// The five per-key-type printers share one signature. It is spelled inline rather than as a
/// `type` alias because it is not an authority `OSSL_FUNC_*` type: `dispatch_court.py` reads a
/// named `type ... = unsafe extern "C" fn` as a dispatch alias to be linked to an authority name,
/// and this shape has none.
///
/// `static int key2text_encode(void *vctx, const void *key, int selection, OSSL_CORE_BIO *cout,
/// int (*key2text)(BIO *out, const void *key, int selection), OSSL_PASSPHRASE_CALLBACK *cb,
/// void *cbarg)` — `encode_key2text.c:634-650`.
///
/// # Safety
/// `cout` must be the core BIO the framework wrapped around the caller's output; `key` the
/// provider key object the type's keymgmt built; `key2text` a live printer.
unsafe fn key2text_encode(
    vctx: *mut c_void,
    cout: *mut c_void,
    key: *const c_void,
    selection: c_int,
    key2text: unsafe extern "C" fn(*mut Bio, *const c_void, c_int) -> c_int,
    _cb: Option<OsslPassphraseCallback>,
    _cbarg: *mut c_void,
) -> c_int {
    let _ = vctx;
    // SAFETY: `cout` is the core BIO the framework built for this encode.
    let out = unsafe { ossl_bio_new_from_core_bio(cout.cast()) };
    if out.is_null() {
        return 0;
    }
    // SAFETY: `out` is live; `key` and `key2text` are the caller's per its own contract.
    let ret = unsafe { key2text(out, key, selection) };
    // SAFETY: `out` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(out) };
    ret
}

// ---------------------------------------------------------------------------
// The DH printer — `encode_key2text.c:41-111`
// ---------------------------------------------------------------------------

/// `static int dh_to_text(BIO *out, const void *key, int selection)` — `encode_key2text.c:42-110`.
///
/// # Safety
/// `out` NULL or live; `key` NULL or a `DH *` the provider's `DH`/`DHX` keymgmt built.
unsafe extern "C" fn dh_to_text(out: *mut Bio, key: *const c_void, selection: c_int) -> c_int {
    let dh = key.cast::<Dh>();
    let mut type_label: *const c_char = ptr::null();
    let mut priv_key: *const BigNum = ptr::null();
    let mut pub_key: *const BigNum = ptr::null();
    let mut params: *const FfcParams = ptr::null();

    if out.is_null() || dh.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_52) };
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        type_label = c"DH Private-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        type_label = c"DH Public-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        type_label = c"DH Parameters".as_ptr();
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        // SAFETY: `dh` is live.
        priv_key = unsafe { DH_get0_priv_key(dh) };
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_66) };
            return 0;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        // SAFETY: `dh` is live.
        pub_key = unsafe { DH_get0_pub_key(dh) };
        if pub_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_73) };
            return 0;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        // SAFETY: `dh` is live and the accessor returns its interior params pointer.
        let got = unsafe { ossl_dh_get0_params(dh.cast_mut()) };
        if got.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_80) };
            return 0;
        }
        params = got;
    }

    // SAFETY: `dh` is live.
    let p = unsafe { DH_get0_p(dh) };
    if p.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_87) };
        return 0;
    }

    // SAFETY: `out` is live; `type_label`/`p` match the conversions. `BIO_printf` is the authority's.
    unsafe {
        if BIO_printf(out, c"%s: (%d bit)\n".as_ptr(), type_label, BN_num_bits(p)) <= 0 {
            return 0;
        }
        if !priv_key.is_null()
            && ossl_bio_print_labeled_bignum(out, c"private-key:".as_ptr(), priv_key) == 0
        {
            return 0;
        }
        if !pub_key.is_null()
            && ossl_bio_print_labeled_bignum(out, c"public-key:".as_ptr(), pub_key) == 0
        {
            return 0;
        }
        if !params.is_null() && ossl_bio_print_ffc_params(out, params) == 0 {
            return 0;
        }
        let length: c_long = DH_get_length(dh);
        if length > 0
            && BIO_printf(
                out,
                c"recommended-private-length: %ld bits\n".as_ptr(),
                length,
            ) <= 0
        {
            return 0;
        }
    }

    1
}

// ---------------------------------------------------------------------------
// The DSA printer — `encode_key2text.c:115-177`
// ---------------------------------------------------------------------------

/// `static int dsa_to_text(BIO *out, const void *key, int selection)` — `encode_key2text.c:116-176`.
///
/// # Safety
/// `out` NULL or live; `key` NULL or a `DSA *` the provider's `DSA` keymgmt built.
unsafe extern "C" fn dsa_to_text(out: *mut Bio, key: *const c_void, selection: c_int) -> c_int {
    let dsa = key.cast::<Dsa>();
    let mut type_label: *const c_char = ptr::null();
    let mut priv_key: *const BigNum = ptr::null();
    let mut pub_key: *const BigNum = ptr::null();
    let mut params: *const FfcParams = ptr::null();

    if out.is_null() || dsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_125) };
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        type_label = c"Private-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        type_label = c"Public-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        type_label = c"DSA-Parameters".as_ptr();
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        // SAFETY: `dsa` is live.
        priv_key = unsafe { DSA_get0_priv_key(dsa) };
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_139) };
            return 0;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        // SAFETY: `dsa` is live.
        pub_key = unsafe { DSA_get0_pub_key(dsa) };
        if pub_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_146) };
            return 0;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        // SAFETY: `dsa` is live and the accessor returns its interior params pointer.
        let got = unsafe { ossl_dsa_get0_params(dsa.cast_mut()) };
        if got.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_153) };
            return 0;
        }
        params = got;
    }

    // SAFETY: `dsa` is live.
    let p = unsafe { DSA_get0_p(dsa) };
    if p.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_160) };
        return 0;
    }

    // SAFETY: `out` is live; every argument matches its conversion.
    unsafe {
        if BIO_printf(out, c"%s: (%d bit)\n".as_ptr(), type_label, BN_num_bits(p)) <= 0 {
            return 0;
        }
        if !priv_key.is_null()
            && ossl_bio_print_labeled_bignum(out, c"priv:".as_ptr(), priv_key) == 0
        {
            return 0;
        }
        if !pub_key.is_null() && ossl_bio_print_labeled_bignum(out, c"pub: ".as_ptr(), pub_key) == 0
        {
            return 0;
        }
        if !params.is_null() && ossl_bio_print_ffc_params(out, params) == 0 {
            return 0;
        }
    }

    1
}

// ---------------------------------------------------------------------------
// The EC printer — `encode_key2text.c:182-382`
// ---------------------------------------------------------------------------

/// `static int ec_param_explicit_curve_to_text(BIO *out, const EC_GROUP *group, BN_CTX *ctx)` —
/// `encode_key2text.c:183-208`.
///
/// # Safety
/// `out` live; `group` live; `ctx` live with three `BN_CTX_get` slots available.
unsafe fn ec_param_explicit_curve_to_text(
    out: *mut Bio,
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    let mut plabel: *const c_char = c"Prime:".as_ptr();
    // SAFETY: `ctx` is live per the contract.
    let p = unsafe { BN_CTX_get(ctx) };
    // SAFETY: as above.
    let a = unsafe { BN_CTX_get(ctx) };
    // SAFETY: as above.
    let b = unsafe { BN_CTX_get(ctx) };
    if b.is_null()
        // SAFETY: `group` is live and the three slots are this frame's.
        || unsafe { EC_GROUP_get_curve(group, p, a, b, ctx) } == 0
    {
        return 0;
    }

    // SAFETY: `group` is live.
    if unsafe { EC_GROUP_get_field_type(group) } == NID_X9_62_characteristic_two_field {
        // SAFETY: `group` is live.
        let basis_type = unsafe { EC_GROUP_get_basis_type(group) };
        // SAFETY: `out` is live and the `%s` argument is `OBJ_nid2sn`'s answer.
        unsafe {
            if basis_type == NID_undef
                || BIO_printf(out, c"Basis Type: %s\n".as_ptr(), OBJ_nid2sn(basis_type)) <= 0
            {
                return 0;
            }
        }
        plabel = c"Polynomial:".as_ptr();
    }
    // SAFETY: `out` is live and each `bn` is a live slot of `ctx`.
    unsafe {
        c_int::from(
            ossl_bio_print_labeled_bignum(out, plabel, p) != 0
                && ossl_bio_print_labeled_bignum(out, c"A:   ".as_ptr(), a) != 0
                && ossl_bio_print_labeled_bignum(out, c"B:   ".as_ptr(), b) != 0,
        )
    }
}

/// `static int ec_param_explicit_gen_to_text(BIO *out, const EC_GROUP *group, BN_CTX *ctx)` —
/// `encode_key2text.c:210-247`.
///
/// # Safety
/// `out` live; `group` live; `ctx` live.
unsafe fn ec_param_explicit_gen_to_text(
    out: *mut Bio,
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    let mut buf: *mut c_uchar = ptr::null_mut();

    // SAFETY: `group` is live.
    let form: PointConversionForm = unsafe { EC_GROUP_get_point_conversion_form(group) };
    // SAFETY: `group` is live.
    let point = unsafe { EC_GROUP_get0_generator(group) };

    if point.is_null() {
        return 0;
    }

    let glabel: *const c_char = match form {
        POINT_CONVERSION_COMPRESSED => c"Generator (compressed):".as_ptr(),
        POINT_CONVERSION_UNCOMPRESSED => c"Generator (uncompressed):".as_ptr(),
        POINT_CONVERSION_HYBRID => c"Generator (hybrid):".as_ptr(),
        _ => return 0,
    };

    // SAFETY: `group`/`point` are live and `buf` is this frame's out-parameter.
    let buflen = unsafe { EC_POINT_point2buf(group, point, form, &mut buf, ctx) };
    if buflen == 0 {
        return 0;
    }

    // SAFETY: `out` is live and `buf` is valid for `buflen` bytes.
    let ret = unsafe { ossl_bio_print_labeled_buf(out, glabel, buf, buflen) };
    // SAFETY: `buf` is the allocation `EC_POINT_point2buf` returned; `buflen` its length.
    unsafe { CRYPTO_clear_free(buf.cast(), buflen, ptr::null(), 0) };
    ret
}

/// `static int ec_param_explicit_to_text(BIO *out, const EC_GROUP *group, OSSL_LIB_CTX *libctx)` —
/// `encode_key2text.c:250-289`.
///
/// # Safety
/// `out` live; `group` live; `libctx` NULL or live.
unsafe fn ec_param_explicit_to_text(
    out: *mut Bio,
    group: *const EcGroup,
    libctx: *mut c_void,
) -> c_int {
    // SAFETY: `libctx` is NULL or live per the contract.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    unsafe { BN_CTX_start(ctx) };

    // SAFETY: `group` is live.
    let tmp_nid = unsafe { EC_GROUP_get_field_type(group) };
    // SAFETY: `group` is live.
    let order = unsafe { EC_GROUP_get0_order(group) };
    if order.is_null() {
        // SAFETY: `ctx` is live and `BN_CTX_start` was called on it.
        unsafe {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
        return 0;
    }

    // SAFETY: `group` is live.
    let seed = unsafe { EC_GROUP_get0_seed(group) };
    let mut seed_len: usize = 0;
    if !seed.is_null() {
        // SAFETY: `group` is live.
        seed_len = unsafe { EC_GROUP_get_seed_len(group) };
    }
    // SAFETY: `group` is live.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };

    // SAFETY: every pointer is live and every argument matches its conversion.
    let ok = unsafe {
        BIO_printf(out, c"Field Type: %s\n".as_ptr(), OBJ_nid2sn(tmp_nid)) > 0
            && ec_param_explicit_curve_to_text(out, group, ctx) != 0
            && ec_param_explicit_gen_to_text(out, group, ctx) != 0
            && ossl_bio_print_labeled_bignum(out, c"Order: ".as_ptr(), order) != 0
            && (cofactor.is_null()
                || ossl_bio_print_labeled_bignum(out, c"Cofactor: ".as_ptr(), cofactor) != 0)
            && (seed.is_null()
                || ossl_bio_print_labeled_buf(out, c"Seed:".as_ptr(), seed, seed_len) != 0)
    };

    // SAFETY: `ctx` is live and `BN_CTX_start` was called on it.
    unsafe {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    c_int::from(ok)
}

/// `static int ec_param_to_text(BIO *out, const EC_GROUP *group, OSSL_LIB_CTX *libctx)` —
/// `encode_key2text.c:291-311`.
///
/// # Safety
/// `out` live; `group` live; `libctx` NULL or live.
unsafe fn ec_param_to_text(out: *mut Bio, group: *const EcGroup, libctx: *mut c_void) -> c_int {
    // SAFETY: `group` is live.
    if (unsafe { EC_GROUP_get_asn1_flag(group) } & OPENSSL_EC_NAMED_CURVE) != 0 {
        // SAFETY: `group` is live.
        let curve_nid = unsafe { EC_GROUP_get_curve_name(group) };

        if curve_nid == NID_undef {
            return 0;
        }

        // SAFETY: `out` is live and the `%s` argument is `OBJ_nid2sn`'s answer.
        if unsafe {
            BIO_printf(
                out,
                c"%s: %s\n".as_ptr(),
                c"ASN1 OID".as_ptr(),
                OBJ_nid2sn(curve_nid),
            )
        } <= 0
        {
            return 0;
        }

        // SAFETY: `curve_nid` is a curve the group named.
        let curve_name = EC_curve_nid2nist(curve_nid);
        // SAFETY: `out` is live and `curve_name` matches the `%s`.
        return c_int::from(
            curve_name.is_null()
                || unsafe {
                    BIO_printf(
                        out,
                        c"%s: %s\n".as_ptr(),
                        c"NIST CURVE".as_ptr(),
                        curve_name,
                    )
                } > 0,
        );
    }
    // SAFETY: `group`/`libctx` are live per this function's contract.
    unsafe { ec_param_explicit_to_text(out, group, libctx) }
}

/// `static int ec_to_text(BIO *out, const void *key, int selection)` — `encode_key2text.c:313-381`.
///
/// # Safety
/// `out` NULL or live; `key` NULL or an `EC_KEY *` the provider's `EC`/`SM2` keymgmt built.
unsafe extern "C" fn ec_to_text(out: *mut Bio, key: *const c_void, selection: c_int) -> c_int {
    let ec = key.cast::<EcKey>();
    let mut type_label: *const c_char = ptr::null();
    let mut priv_buf: *mut c_uchar = ptr::null_mut();
    let mut priv_len: usize = 0;
    let mut pub_buf: *mut c_uchar = ptr::null_mut();
    let mut pub_len: usize = 0;

    if out.is_null() || ec.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_323) };
        return 0;
    }

    // SAFETY: `ec` is live.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_328) };
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        type_label = c"Private-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        type_label = c"Public-Key".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
        // SAFETY: `group` is live.
        if unsafe { EC_GROUP_get_curve_name(group) } != crate::runtime::obj::NID_sm2 {
            type_label = c"EC-Parameters".as_ptr();
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        // SAFETY: `ec` is live.
        let priv_key = unsafe { EC_KEY_get0_private_key(ec) };
        if priv_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_344) };
            return 0;
        }
        // SAFETY: `ec` is live and `priv_buf` is this frame's out-parameter.
        priv_len = unsafe { EC_KEY_priv2buf(ec, &mut priv_buf) };
        if priv_len == 0 {
            return 0;
        }
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        // SAFETY: `ec` is live.
        let pub_pt = unsafe { EC_KEY_get0_public_key(ec) };
        if pub_pt.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_355) };
            // SAFETY: `priv_buf` is NULL or the allocation `EC_KEY_priv2buf` returned.
            unsafe { CRYPTO_clear_free(priv_buf.cast(), priv_len, ptr::null(), 0) };
            return 0;
        }
        // SAFETY: `ec` is live; `pub_buf` is this frame's out-parameter.
        pub_len =
            unsafe { EC_KEY_key2buf(ec, EC_KEY_get_conv_form(ec), &mut pub_buf, ptr::null_mut()) };
        if pub_len == 0 {
            // SAFETY: `priv_buf` is NULL or the allocation `EC_KEY_priv2buf` returned.
            unsafe { CRYPTO_clear_free(priv_buf.cast(), priv_len, ptr::null(), 0) };
            return 0;
        }
    }

    let mut ret = 1;
    // SAFETY: `out` is live; every pointer argument is live and matches its conversion. The three
    // checks are separate statements because the authority's are, and each is skipped once an
    // earlier one has failed.
    unsafe {
        if !type_label.is_null()
            && BIO_printf(
                out,
                c"%s: (%d bit)\n".as_ptr(),
                type_label,
                EC_GROUP_order_bits(group),
            ) <= 0
        {
            ret = 0;
        }
        if ret != 0
            && !priv_buf.is_null()
            && ossl_bio_print_labeled_buf(out, c"priv:".as_ptr(), priv_buf, priv_len) == 0
        {
            ret = 0;
        }
        if ret != 0
            && !pub_buf.is_null()
            && ossl_bio_print_labeled_buf(out, c"pub:".as_ptr(), pub_buf, pub_len) == 0
        {
            ret = 0;
        }
        if ret != 0 && (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ret = ec_param_to_text(out, group, ossl_ec_key_get_libctx(ec));
        }
    }

    // SAFETY: both buffers are NULL or the allocations their producers returned.
    unsafe {
        CRYPTO_clear_free(priv_buf.cast(), priv_len, ptr::null(), 0);
        CRYPTO_free(pub_buf.cast(), ptr::null(), 0);
    }
    ret
}

// ---------------------------------------------------------------------------
// The ECX printer — `encode_key2text.c:386-438`
// ---------------------------------------------------------------------------

/// `static int ecx_to_text(BIO *out, const void *key, int selection)` — `encode_key2text.c:387-437`.
///
/// # Safety
/// `out` NULL or live; `key` NULL or an `ECX_KEY *` one of the four ECX keymgmt built.
unsafe extern "C" fn ecx_to_text(out: *mut Bio, key: *const c_void, selection: c_int) -> c_int {
    let ecx = key.cast::<EcxKey>();
    let mut type_label: *const c_char = ptr::null();

    if out.is_null() || ecx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_393) };
        return 0;
    }

    // SAFETY: `ecx` is live.
    match unsafe { (*ecx).type_ } {
        ECX_KEY_TYPE_X25519 => type_label = c"X25519".as_ptr(),
        ECX_KEY_TYPE_X448 => type_label = c"X448".as_ptr(),
        ECX_KEY_TYPE_ED25519 => type_label = c"ED25519".as_ptr(),
        ECX_KEY_TYPE_ED448 => type_label = c"ED448".as_ptr(),
        _ => {}
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        // SAFETY: `ecx` is live.
        let privkey = unsafe { (*ecx).privkey };
        if privkey.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_414) };
            return 0;
        }

        // SAFETY: `out` is live and `type_label` matches the `%s`.
        if unsafe { BIO_printf(out, c"%s Private-Key:\n".as_ptr(), type_label) } <= 0 {
            return 0;
        }
        // SAFETY: `privkey` is live for `keylen` bytes.
        if unsafe { ossl_bio_print_labeled_buf(out, c"priv:".as_ptr(), privkey, (*ecx).keylen) }
            == 0
        {
            return 0;
        }
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        // SAFETY: `ecx` is live.
        if unsafe { (*ecx).haspubkey } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_425) };
            return 0;
        }

        // SAFETY: `out` is live and `type_label` matches the `%s`.
        if unsafe { BIO_printf(out, c"%s Public-Key:\n".as_ptr(), type_label) } <= 0 {
            return 0;
        }
    }

    // SAFETY: `ecx` is live and `pubkey` is its inline array of `keylen` valid bytes.
    unsafe {
        c_int::from(
            ossl_bio_print_labeled_buf(
                out,
                c"pub:".as_ptr(),
                (*ecx).pubkey.as_ptr(),
                (*ecx).keylen,
            ) != 0,
        )
    }
}

// ---------------------------------------------------------------------------
// The RSA printer — `encode_key2text.c:458-613`
// ---------------------------------------------------------------------------

/// `static int rsa_to_text(BIO *out, const void *key, int selection)` — `encode_key2text.c:458-613`.
///
/// # Safety
/// `out` NULL or live; `key` NULL or an `RSA *` the provider's `RSA`/`RSA-PSS` keymgmt built.
unsafe extern "C" fn rsa_to_text(out: *mut Bio, key: *const c_void, selection: c_int) -> c_int {
    let rsa = key.cast::<Rsa>();
    let mut type_label: *const c_char = c"RSA key".as_ptr();
    let mut modulus_label: *const c_char = ptr::null();
    let mut exponent_label: *const c_char = ptr::null();
    let mut rsa_d: *const BigNum = ptr::null();
    let mut rsa_n: *const BigNum = ptr::null();
    let mut rsa_e: *const BigNum = ptr::null();

    // SAFETY: `rsa` is NULL or live; the accessor tolerates NULL and returns the default params.
    let pss_params = unsafe { ossl_rsa_get0_pss_params_30(rsa.cast_mut()) };

    if out.is_null() || rsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_473) };
        return 0;
    }

    // SAFETY: the three stacks are freshly created or NULL.
    let factors: *mut OpenSslStack = OPENSSL_sk_new_null();
    // SAFETY: as above.
    let exps: *mut OpenSslStack = OPENSSL_sk_new_null();
    // SAFETY: as above.
    let coeffs: *mut OpenSslStack = OPENSSL_sk_new_null();

    if factors.is_null() || exps.is_null() || coeffs.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROV_ENCODE_KEY2TEXT_482) };
        // SAFETY: each stack is NULL or a stack this frame owns.
        unsafe { free_stacks(factors, exps, coeffs) };
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
        type_label = c"Private-Key".as_ptr();
        modulus_label = c"modulus:".as_ptr();
        exponent_label = c"publicExponent:".as_ptr();
    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
        type_label = c"Public-Key".as_ptr();
        modulus_label = c"Modulus:".as_ptr();
        exponent_label = c"Exponent:".as_ptr();
    }

    // SAFETY: `rsa` is live and the three out-parameters are this frame's.
    unsafe { RSA_get0_key(rsa, &mut rsa_n, &mut rsa_e, &mut rsa_d) };
    // SAFETY: `rsa` is live and each stack is this frame's.
    unsafe { ossl_rsa_get0_all_params(rsa.cast_mut(), factors, exps, coeffs) };
    // SAFETY: `factors` is live.
    let primes = unsafe { OPENSSL_sk_num(factors) };

    // SAFETY: `out` is live; every argument matches its conversion.
    let ret = unsafe {
        let header = if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            BIO_printf(
                out,
                c"%s: (%d bit, %d primes)\n".as_ptr(),
                type_label,
                BN_num_bits(rsa_n),
                primes,
            )
        } else {
            BIO_printf(
                out,
                c"%s: (%d bit)\n".as_ptr(),
                type_label,
                BN_num_bits(rsa_n),
            )
        };
        let mut ret = 0;
        if header > 0
            && ossl_bio_print_labeled_bignum(out, modulus_label, rsa_n) != 0
            && ossl_bio_print_labeled_bignum(out, exponent_label, rsa_e) != 0
        {
            ret = 1;
        }
        if ret != 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ret = 0;
            if ossl_bio_print_labeled_bignum(out, c"privateExponent:".as_ptr(), rsa_d) != 0
                && ossl_bio_print_labeled_bignum(out, c"prime1:".as_ptr(), sk_value(factors, 0))
                    != 0
                && ossl_bio_print_labeled_bignum(out, c"prime2:".as_ptr(), sk_value(factors, 1))
                    != 0
                && ossl_bio_print_labeled_bignum(out, c"exponent1:".as_ptr(), sk_value(exps, 0))
                    != 0
                && ossl_bio_print_labeled_bignum(out, c"exponent2:".as_ptr(), sk_value(exps, 1))
                    != 0
                && ossl_bio_print_labeled_bignum(out, c"coefficient:".as_ptr(), sk_value(coeffs, 0))
                    != 0
            {
                ret = 1;
                let mut i: c_int = 2;
                while i < OPENSSL_sk_num(factors) {
                    if BIO_printf(out, c"prime%d:".as_ptr(), i + 1) <= 0
                        || ossl_bio_print_labeled_bignum(out, ptr::null(), sk_value(factors, i))
                            == 0
                        || BIO_printf(out, c"exponent%d:".as_ptr(), i + 1) <= 0
                        || ossl_bio_print_labeled_bignum(out, ptr::null(), sk_value(exps, i)) == 0
                        || BIO_printf(out, c"coefficient%d:".as_ptr(), i + 1) <= 0
                        || ossl_bio_print_labeled_bignum(out, ptr::null(), sk_value(coeffs, i - 1))
                            == 0
                    {
                        ret = 0;
                        break;
                    }
                    i += 1;
                }
            }
        }
        ret
    };

    if ret != 0 && (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0 {
        // SAFETY: `pss_params` is NULL or the RSA's own params; `out` is live.
        let pss_ok = unsafe { rsa_pss_to_text(out, rsa, pss_params) };
        if pss_ok == 0 {
            // SAFETY: each stack is NULL or a stack this frame owns.
            unsafe { free_stacks(factors, exps, coeffs) };
            return 0;
        }
    }

    // SAFETY: each stack is NULL or a stack this frame owns.
    unsafe { free_stacks(factors, exps, coeffs) };
    ret
}

/// The `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS` tail of `rsa_to_text` — `encode_key2text.c:555-605`.
///
/// # Safety
/// `out` live; `rsa` live; `pss_params` NULL or `rsa`'s own.
unsafe fn rsa_pss_to_text(
    out: *mut Bio,
    rsa: *const Rsa,
    pss_params: *const crate::rsa::RsaPssParams30,
) -> c_int {
    // SAFETY: `rsa` is live.
    match unsafe { RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK) } {
        RSA_FLAG_TYPE_RSA => {
            // SAFETY: `pss_params` is NULL or live.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(pss_params) } == 0 {
                // SAFETY: `out` is live and the format has no conversions.
                if unsafe { BIO_printf(out, c"(INVALID PSS PARAMETERS)\n".as_ptr()) } <= 0 {
                    return 0;
                }
            }
        }
        RSA_FLAG_TYPE_RSASSAPSS => {
            // SAFETY: `pss_params` is NULL or live.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(pss_params) } != 0 {
                // SAFETY: `out` is live and the format has no conversions.
                if unsafe { BIO_printf(out, c"No PSS parameter restrictions\n".as_ptr()) } <= 0 {
                    return 0;
                }
            } else {
                // SAFETY: `pss_params` is live here (a non-NULL restricted object).
                let hashalg_nid = unsafe { ossl_rsa_pss_params_30_hashalg(pss_params) };
                // SAFETY: as above.
                let maskgenalg_nid = unsafe { ossl_rsa_pss_params_30_maskgenalg(pss_params) };
                // SAFETY: as above.
                let maskgenhashalg_nid =
                    unsafe { ossl_rsa_pss_params_30_maskgenhashalg(pss_params) };
                // SAFETY: as above.
                let saltlen = unsafe { ossl_rsa_pss_params_30_saltlen(pss_params) };
                // SAFETY: as above.
                let trailerfield = unsafe { ossl_rsa_pss_params_30_trailerfield(pss_params) };

                // SAFETY: `out` is live and each argument matches its conversion; the two name
                // lookups answer static strings or NULL, exactly as the authority's do.
                let ok = unsafe {
                    BIO_printf(out, c"PSS parameter restrictions:\n".as_ptr()) > 0
                        && BIO_printf(
                            out,
                            c"  Hash Algorithm: %s%s\n".as_ptr(),
                            ossl_rsa_oaeppss_nid2name(hashalg_nid),
                            if hashalg_nid == NID_sha1 {
                                c" (default)".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                        ) > 0
                        && BIO_printf(
                            out,
                            c"  Mask Algorithm: %s with %s%s\n".as_ptr(),
                            ossl_rsa_mgf_nid2name(maskgenalg_nid),
                            ossl_rsa_oaeppss_nid2name(maskgenhashalg_nid),
                            if maskgenalg_nid == NID_mgf1 && maskgenhashalg_nid == NID_sha1 {
                                c" (default)".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                        ) > 0
                        && BIO_printf(
                            out,
                            c"  Minimum Salt Length: %d%s\n".as_ptr(),
                            saltlen,
                            if saltlen == 20 {
                                c" (default)".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                        ) > 0
                        && BIO_printf(
                            out,
                            c"  Trailer Field: 0x%x%s\n".as_ptr(),
                            trailerfield,
                            if trailerfield == 1 {
                                c" (default)".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                        ) > 0
                };
                if !ok {
                    return 0;
                }
            }
        }
        _ => {}
    }
    1
}

/// `sk_BIGNUM_const_value(factors, i)` — the one `OPENSSL_sk_value` read the RSA printer makes.
///
/// # Safety
/// `stack` live with `i` in range.
unsafe fn sk_value(stack: *const OpenSslStack, i: c_int) -> *const BigNum {
    // SAFETY: `stack`/`i` are in range per the caller's contract.
    unsafe { OPENSSL_sk_value(stack, i).cast() }
}

/// `sk_BIGNUM_const_free(f)` over the three stacks — NULL-tolerant, as the authority's is.
///
/// # Safety
/// Each argument NULL or a stack this frame owns.
unsafe fn free_stacks(
    factors: *mut OpenSslStack,
    exps: *mut OpenSslStack,
    coeffs: *mut OpenSslStack,
) {
    // SAFETY: each stack is NULL or this frame's; `OPENSSL_sk_free` takes NULL.
    unsafe {
        OPENSSL_sk_free(factors);
        OPENSSL_sk_free(exps);
        OPENSSL_sk_free(coeffs);
    }
}

// ---------------------------------------------------------------------------
// The eleven tables — the authority's `MAKE_TEXT_ENCODER` expansions `:698-744`
// ---------------------------------------------------------------------------

/// One `MAKE_TEXT_ENCODER(impl, type)` expansion (`encode_key2text.c:652-696`), for the key types
/// whose `*_to_text` is in this unit. `$keymgmt` is the key type's own `ossl_*_keymgmt_functions`,
/// `$text` its `*_to_text`, and `$raise` the site the `key_abstract != NULL` refusal records.
///
/// The generated names follow the macro's own substitution (`impl##2text_*`), and the table symbol
/// is `ossl_##impl##_to_text_encoder_functions[]` in the authority spelled as a Rust `static`.
macro_rules! make_text_encoder {
    ($encode:ident, $import:ident, $free:ident, $table:ident, $text:path, $keymgmt:path, $raise:path) => {
        /// `import_object` — `ossl_prov_import_key(<keymgmt>, ctx, selection, params)`. Unreached
        /// when the encoder's provider is the keymgmt's (the same-provider arm hands the keydata
        /// straight over), but transcribed because the authority's table carries it.
        ///
        /// # Safety
        /// The encoder `import_object` dispatch contract.
        unsafe extern "C" fn $import(
            ctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            // SAFETY: the table is the key type's own and the arguments are the caller's.
            unsafe { ossl_prov_import_key($keymgmt.as_ptr(), ctx, selection, params) }
        }

        /// `free_object` — `ossl_prov_free_key(<keymgmt>, key)`.
        ///
        /// # Safety
        /// The encoder `free_object` dispatch contract.
        unsafe extern "C" fn $free(key: *mut c_void) {
            // SAFETY: the table is the key type's own and `key` is its object.
            unsafe { ossl_prov_free_key($keymgmt.as_ptr(), key) }
        }

        /// `encode` — `encode_key2text.c`'s generated body: refuse an abstract object, else run the
        /// type's printer through the shared engine.
        ///
        /// # Safety
        /// The encoder `encode` dispatch contract.
        unsafe extern "C" fn $encode(
            vctx: *mut c_void,
            cout: *mut c_void,
            key: *const c_void,
            key_abstract: *const OsslParam,
            selection: c_int,
            cb: Option<OsslPassphraseCallback>,
            cbarg: *mut c_void,
        ) -> c_int {
            if !key_abstract.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&$raise) };
                return 0;
            }
            // SAFETY: the encoder contract is the caller's; the printer is this unit's own.
            unsafe { key2text_encode(vctx, cout, key, selection, $text, cb, cbarg) }
        }

        static $table: [OsslDispatch; 6] = [
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_NEWCTX,
                function: key2text_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREECTX,
                function: key2text_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                function: $import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREE_OBJECT,
                function: $free as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_ENCODE,
                function: $encode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

// The eleven expansions, in the authority's order (`:698-744`). The eighteen PQC tables are not
// published: their `*_to_text` helpers live in unlanded units (module doc).
make_text_encoder!(
    dh2text_encode,
    dh2text_import_object,
    dh2text_free_object,
    DH_TO_TEXT_FUNCTIONS,
    dh_to_text,
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_699
);
make_text_encoder!(
    dhx2text_encode,
    dhx2text_import_object,
    dhx2text_free_object,
    DHX_TO_TEXT_FUNCTIONS,
    dh_to_text,
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_700
);
make_text_encoder!(
    dsa2text_encode,
    dsa2text_import_object,
    dsa2text_free_object,
    DSA_TO_TEXT_FUNCTIONS,
    dsa_to_text,
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_703
);
make_text_encoder!(
    ec2text_encode,
    ec2text_import_object,
    ec2text_free_object,
    EC_TO_TEXT_FUNCTIONS,
    ec_to_text,
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_706
);
make_text_encoder!(
    sm22text_encode,
    sm22text_import_object,
    sm22text_free_object,
    SM2_TO_TEXT_FUNCTIONS,
    ec_to_text,
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_708
);
make_text_encoder!(
    ed255192text_encode,
    ed255192text_import_object,
    ed255192text_free_object,
    ED25519_TO_TEXT_FUNCTIONS,
    ecx_to_text,
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_711
);
make_text_encoder!(
    ed4482text_encode,
    ed4482text_import_object,
    ed4482text_free_object,
    ED448_TO_TEXT_FUNCTIONS,
    ecx_to_text,
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_712
);
make_text_encoder!(
    x255192text_encode,
    x255192text_import_object,
    x255192text_free_object,
    X25519_TO_TEXT_FUNCTIONS,
    ecx_to_text,
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_713
);
make_text_encoder!(
    x4482text_encode,
    x4482text_import_object,
    x4482text_free_object,
    X448_TO_TEXT_FUNCTIONS,
    ecx_to_text,
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_714
);
make_text_encoder!(
    rsa2text_encode,
    rsa2text_import_object,
    rsa2text_free_object,
    RSA_TO_TEXT_FUNCTIONS,
    rsa_to_text,
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_722
);
make_text_encoder!(
    rsapss2text_encode,
    rsapss2text_import_object,
    rsapss2text_free_object,
    RSAPSS_TO_TEXT_FUNCTIONS,
    rsa_to_text,
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2TEXT_723
);

// ---------------------------------------------------------------------------
// The provider tables — `providers/defltprov.c`'s `deflt_encoder[]` and `providers/baseprov.c`'s
// `base_encoder[]`, restricted to the eleven rows this unit publishes, in the authority's order.
// ---------------------------------------------------------------------------

/// `OSSL_OP_ENCODER` — `include/openssl/core_dispatch.h:295`. The provider queries name it, and
/// the census resolves the arm's constant by this final path segment.
pub(crate) const OSSL_OP_ENCODER: c_int = 20;

/// The `output=text` property each row carries, with its provider's own prefix and the row's
/// `fips` flag exactly as `providers/encoders.inc`'s `ENCODER_TEXT` expands it.
const DEFAULT_TEXT_PROPERTY: *const c_char = c"provider=default,fips=yes,output=text".as_ptr();
/// `SM2` is the one non-FIPS text row (`encoders.inc:56`, `fips=no`).
const DEFAULT_SM2_TEXT_PROPERTY: *const c_char = c"provider=default,fips=no,output=text".as_ptr();
/// The base provider's `fips=yes` property.
const BASE_TEXT_PROPERTY: *const c_char = c"provider=base,fips=yes,output=text".as_ptr();
/// The base provider's `SM2` property.
const BASE_SM2_TEXT_PROPERTY: *const c_char = c"provider=base,fips=no,output=text".as_ptr();

/// `deflt_encoder[]`'s rows this unit publishes — `providers/defltprov.c:675-680` over
/// `providers/encoders.inc`, restricted to the eleven text rows, in the authority's order.
///
/// Each row is the authority's `ENCODER_TEXT(name, sym, fips)` expansion, and each is written as
/// the same struct literal the census's reader parses (`algorithm_names` then `implementation`) so
/// that a row and its dispatch symbol cannot drift apart.
pub(crate) static DEFLT_ENCODERS: [OsslAlgorithm; 12] = [
    OsslAlgorithm {
        algorithm_names: c"RSA".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: RSA_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"RSA-PSS".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: RSAPSS_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DH".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: DH_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DHX".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: DHX_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DSA".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: DSA_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"EC".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: EC_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"ED25519".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: ED25519_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"ED448".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: ED448_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"X25519".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: X25519_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"X448".as_ptr(),
        property_definition: DEFAULT_TEXT_PROPERTY,
        implementation: X448_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SM2".as_ptr(),
        property_definition: DEFAULT_SM2_TEXT_PROPERTY,
        implementation: SM2_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

/// `base_encoder[]`'s rows this unit publishes — `providers/baseprov.c:67-72`, the same eleven rows
/// with the base provider's property.
pub(crate) static BASE_ENCODERS: [OsslAlgorithm; 12] = [
    OsslAlgorithm {
        algorithm_names: c"RSA".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: RSA_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"RSA-PSS".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: RSAPSS_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DH".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: DH_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DHX".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: DHX_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"DSA".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: DSA_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"EC".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: EC_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"ED25519".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: ED25519_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"ED448".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: ED448_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"X25519".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: X25519_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"X448".as_ptr(),
        property_definition: BASE_TEXT_PROPERTY,
        implementation: X448_TO_TEXT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SM2".as_ptr(),
        property_definition: BASE_SM2_TEXT_PROPERTY,
        implementation: SM2_TO_TEXT_FUNCTIONS.as_ptr().cast(),
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

    /// Every published row's dispatch table is the authority's shape: `newctx`, `freectx`,
    /// `import_object`, `free_object`, `encode`, terminator — five named slots and the end.
    #[test]
    fn each_table_is_the_authoritys_five_slot_shape() {
        for table in [&DEFLT_ENCODERS[..], &BASE_ENCODERS[..]] {
            for row in table.iter() {
                if row.algorithm_names.is_null() {
                    continue;
                }
                let fns = row.implementation.cast::<OsslDispatch>();
                let mut i = 0;
                let mut seen = [false; 5];
                let mut unexpected = 0;
                // SAFETY: the table is terminated, and each read is within it.
                unsafe {
                    while (*fns.add(i)).function_id != OSSL_DISPATCH_END {
                        match (*fns.add(i)).function_id {
                            OSSL_FUNC_ENCODER_NEWCTX => seen[0] = true,
                            OSSL_FUNC_ENCODER_FREECTX => seen[1] = true,
                            OSSL_FUNC_ENCODER_IMPORT_OBJECT => seen[2] = true,
                            OSSL_FUNC_ENCODER_FREE_OBJECT => seen[3] = true,
                            OSSL_FUNC_ENCODER_ENCODE => seen[4] = true,
                            _ => unexpected += 1,
                        }
                        i += 1;
                    }
                }
                assert_eq!(unexpected, 0, "a text table carries an unexpected slot");
                assert!(seen.iter().all(|&s| s), "a text table is missing a slot");
                assert_eq!(i, 5);
            }
        }
    }

    /// The one property difference the authority's `encoders.inc` carries: `SM2` is `fips=no`, the
    /// other ten `fips=yes`; both providers spell their own name.
    #[test]
    fn sm2_is_the_only_non_fips_row() {
        for table in [&DEFLT_ENCODERS[..], &BASE_ENCODERS[..]] {
            for row in table.iter() {
                if row.algorithm_names.is_null() {
                    continue;
                }
                // SAFETY: both pointers are static C strings this module wrote.
                let (prop, is_sm2) = unsafe {
                    let prop = core::ffi::CStr::from_ptr(row.property_definition).to_bytes();
                    let name = core::ffi::CStr::from_ptr(row.algorithm_names).to_bytes();
                    (prop, name == b"SM2")
                };
                let mentions = |needle: &[u8]| prop.windows(needle.len()).any(|w| w == needle);
                if is_sm2 {
                    assert!(mentions(b"fips=no"), "SM2 must be fips=no");
                } else {
                    assert!(mentions(b"fips=yes"), "every other row is fips=yes");
                }
            }
        }
    }
}
