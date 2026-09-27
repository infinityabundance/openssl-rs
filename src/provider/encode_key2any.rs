//! Phase 10.3 — `providers/implementations/encode_decode/encode_key2any.c`: the provider's
//! **DER and PEM key encoders**, one `OSSL_OP_ENCODER` table per `(key type, structure, output)`
//! triple, published by both the `default` and the `base` provider.
//!
//! This is the largest unit of the key-format stratum: the authority's `MAKE_ENCODER` list
//! (`:1538-1819`) is 208 expansions, of which the provider's own `providers/encoders.inc`
//! registers **206** as rows — the two `MAKE_ENCODER(sm2, ec, SM2, der/pem)` expansions exist as
//! globals (`nm` shows `ossl_sm2_to_SM2_der_encoder_functions` as a defined symbol) but
//! `encoders.inc` publishes no `SM2`-structure row, so no table of either provider references
//! them. They are transcribed here with the rest and left unregistered, which is what the
//! authority's own tables do.
//!
//! ## The row is a table over one shared engine
//!
//! Every table's dispatch is the authority's `MAKE_ENCODER` expansion (`:1467-1532`): `newctx`,
//! `freectx`, `settable_ctx_params` and `set_ctx_params` are the unit's shared four; each table
//! gets its own `does_selection`, `import_object`, `free_object` and `encode`, the last calling
//! the shared `key2any_encode` engine over the same `KEY2ANY_CTX`. So the "206 implementations"
//! are one engine and 206 table rows, which is the measurement this stratum is for
//! (`docs/PHASE-10-SUBPHASES.md` §1a).
//!
//! ## What the engine publishes
//!
//! The output structures are the three PKCS#8/X.509 envelopes (`PrivateKeyInfo`,
//! `EncryptedPrivateKeyInfo`, `SubjectPublicKeyInfo`) plus the type-specific forms
//! (`type-specific`, `RSA`/`PKCS1`, `DH`/`PKCS3`, `DHX`/`X9.42`, `DSA`, `EC`/`X9.62`,
//! `SM2`), for both `der` and `pem`. The `PrivateKeyInfo` writer silently upgrades to
//! `EncryptedPrivateKeyInfo` when a cipher is set (`cipher_intent`), which is the authority's
//! flexibility note at `:1354-1362`.
//!
//! ## The two pulled-forward exports
//!
//! `nm --undefined-only` over the authority's `libdefault-lib-encode_key2any.o` names only two
//! symbols this crate did not implement that the `SubjectPublicKeyInfo` arms reach:
//! `i2d_X509_PUBKEY_bio` (`:329`) and `PEM_write_bio_X509_PUBKEY` (`:354`). Both are now landed
//! beside their landed siblings (`src/x509/x_pubkey.rs`, `src/pem/pem_lib.rs`); everything else
//! the unit calls was already published.
//!
//! ## The bytes are the contract
//!
//! `RT-CODEC` drives these rows through `OSSL_ENCODER_CTX_new_for_pkey(pkey, selection,
//! "DER"/"PEM", structure, …)` and compares the transcript byte for byte against the authority's.
//! A transcription that round-trips a parse is not this (`docs/PHASE-10-SUBPHASES.md` §3.1).
//!
//! ## The raise coordinates are declared here
//!
//! `src/runtime/err_sites.rs` is generated from a per-phase file list that does not yet carry
//! `encode_key2any.c`, so this unit's `ERR_raise*` coordinates are declared under the generator's
//! own naming here, exactly as `src/provider/cipher_gcm.rs`'s are, and move into `err_sites.rs`
//! when that generator next runs.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)] // the authority's function and table names are the contract
#![allow(non_upper_case_globals)] // the authority's table names, e.g. `ossl_rsa_to_...`
#![allow(unreachable_pub)]
#![allow(clippy::too_many_arguments)] // every signature mirrors the authority's

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::mem::size_of;
use core::ptr;

use crate::asn1::a_i2d_fp::ASN1_i2d_bio;
use crate::asn1::layout::V_ASN1_UNDEF;
use crate::asn1::layout::{Asn1String, I2dOfVoid, V_ASN1_NULL, V_ASN1_OBJECT, V_ASN1_SEQUENCE};
use crate::asn1::p8_pkey::{
    i2d_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, PKCS8_PRIV_KEY_INFO_new, PKCS8_pkey_set0,
    Pkcs8PrivKeyInfo,
};
use crate::asn1::prim::{ASN1_OBJECT_free, BN_to_ASN1_INTEGER};
use crate::asn1::string::{
    ASN1_STRING_clear_free, ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set0,
};
use crate::asn1::typ::{i2d_ASN1_INTEGER, i2d_ASN1_OCTET_STRING};
use crate::asn1::x_sig::{i2d_X509_SIG, X509Sig, X509_SIG_free};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dh::asn1::{i2d_DHparams, i2d_DHxparams, DH_FLAG_TYPE_DHX};
use crate::dh::object::{DH_get0_priv_key, DH_get0_pub_key, DH_test_flags};
use crate::dh::Dh;
use crate::dsa::asn1::{i2d_DSAPrivateKey, i2d_DSAPublicKey, i2d_DSAparams};
use crate::dsa::object::{DSA_get0_g, DSA_get0_p, DSA_get0_priv_key, DSA_get0_pub_key, DSA_get0_q};
use crate::dsa::Dsa;
use crate::ec::asn1::{i2d_ECParameters, i2d_ECPrivateKey, i2o_ECPublicKey};
use crate::ec::ecx_key::EcxKey;
use crate::ec::key::{
    EC_KEY_get0_group, EC_KEY_get0_public_key, EC_KEY_get_enc_flags, EC_KEY_set_enc_flags,
};
use crate::ec::lib::{EC_GROUP_get_asn1_flag, EC_GROUP_get_curve_name};
use crate::ec::EcKey;
use crate::encoder_meth::{
    OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREECTX,
    OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX,
    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::evp::pkey::{
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_DH, EVP_PKEY_DHX, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519, EVP_PKEY_ED448,
    EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_X25519, EVP_PKEY_X448, OPENSSL_EC_NAMED_CURVE,
};
use crate::ml_dsa::{MlDsaKey, EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65, EVP_PKEY_ML_DSA_87};
use crate::ml_kem::{MlKemKey, EVP_PKEY_ML_KEM_1024, EVP_PKEY_ML_KEM_512, EVP_PKEY_ML_KEM_768};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_total_written, WPACKET_init_der,
    WPACKET_init_null_der, Wpacket,
};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_utf8_string_ptr, OsslParam, END, OSSL_PARAM_INTEGER,
    OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UTF8_STRING,
};
use crate::passphrase::{
    ossl_pw_clear_passphrase_data, ossl_pw_get_passphrase, ossl_pw_pem_password,
    ossl_pw_set_ossl_passphrase_cb, OsslPassphraseCallback, OsslPassphraseData,
};
use crate::pem::pem_lib::{
    OsslI2dOfVoidCtx, PEM_ASN1_write_bio, PEM_ASN1_write_bio_ctx, PEM_write_bio_X509_PUBKEY,
    PEM_BUFSIZE, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF,
};
use crate::pkcs12::p12_p8e::PKCS8_encrypt_ex;
use crate::provider::ctx::{ossl_prov_ctx_get0_libctx, ProvCtx};
use crate::provider::der_rsa_key::ossl_DER_w_RSASSA_PSS_params;
use crate::provider::endecoder_common::{ossl_prov_free_key, ossl_prov_import_key};
use crate::provider::ml_dsa_codecs::{ossl_ml_dsa_i2d_prvkey, ossl_ml_dsa_i2d_pubkey};
use crate::provider::ml_kem_codecs::{ossl_ml_kem_i2d_prvkey, ossl_ml_kem_i2d_pubkey};
use crate::rsa::asn1::{i2d_RSAPrivateKey, i2d_RSAPublicKey};
use crate::rsa::object::{
    ossl_rsa_get0_pss_params_30, RSA_test_flags, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA,
    RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::ossl_rsa_pss_params_30_is_unrestricted;
use crate::rsa::{Rsa, RsaPssParams30};
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::{BIO_free, BIO_write, Bio};
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_zalloc, OPENSSL_cleanse,
};
use crate::runtime::obj::{Asn1Object, NID_undef, OBJ_length, OBJ_nid2obj};
use crate::slh_dsa::key::{
    ossl_slh_dsa_key_get_priv, ossl_slh_dsa_key_get_priv_len, ossl_slh_dsa_key_get_pub,
    ossl_slh_dsa_key_get_pub_len,
};
use crate::slh_dsa::SlhDsaKey;
use crate::x509::x_pubkey::{
    i2d_X509_PUBKEY_bio, X509Pubkey, X509_PUBKEY_free, X509_PUBKEY_new, X509_PUBKEY_set0_param,
};

/// `key_to_paramstring_fn` — `encode_key2any.c:67-68`'s typedef: a key type's parameter-blob
/// producer.
type KeyToParamstringFn =
    unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int;

/// `key_to_der_fn` — `encode_key2any.c:69-72`'s typedef: one writer's own signature.
type KeyToDerFn = unsafe extern "C" fn(
    *mut Bio,
    *const c_void,
    c_int,
    *const c_char,
    Option<KeyToParamstringFn>,
    OsslI2dOfVoidCtx,
    *mut Key2anyCtx,
) -> c_int;

// The C library's `strcmp`, the generated parameter decoder's own comparison.
unsafe extern "C" {
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

// ---------------------------------------------------------------------------------------------
// The unit's recorded raise coordinates (`encode_key2any.c`'s 31 `ERR_raise*` call sites)
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_PROV` — `include/openssl/err.h:120`.
const ERR_LIB_PROV: c_int = 57;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h:326`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509_LIB` — `include/openssl/err.h:325`.
const ERR_R_X509_LIB: c_int = 524299;
/// `ERR_R_PROV_LIB` — `include/openssl/err.h:344`.
const ERR_R_PROV_LIB: c_int = 524345;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h:358`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h:354`, carrying `ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `PROV_R_UNABLE_TO_GET_PASSPHRASE` — `include/openssl/proverr.h:159`.
const PROV_R_UNABLE_TO_GET_PASSPHRASE: c_int = 159;
/// `PROV_R_BN_ERROR` — `include/openssl/proverr.h:160`.
const PROV_R_BN_ERROR: c_int = 160;
/// `PROV_R_MISSING_OID` — `include/openssl/proverr.h:209`.
const PROV_R_MISSING_OID: c_int = 209;
/// `PROV_R_NOT_A_PUBLIC_KEY` — `include/openssl/proverr.h:220`.
const PROV_R_NOT_A_PUBLIC_KEY: c_int = 220;
/// `PROV_R_NOT_A_PRIVATE_KEY` — `include/openssl/proverr.h:221`.
const PROV_R_NOT_A_PRIVATE_KEY: c_int = 221;
/// `PROV_R_REPEATED_PARAMETER` — `include/openssl/proverr.h:252`.
const PROV_R_REPEATED_PARAMETER: c_int = 252;

/// One `encode_key2any.c` raise coordinate. `line` and `func` are the authority file's own.
const fn key2any_site(line: c_int, func: &'static CStr, reason: c_int) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/providers/implementations/encode_decode/encode_key2any.c",
        line,
        func,
        lib: ERR_LIB_PROV,
        reason,
        dynamic_reason: false,
    }
}

/// `key_to_p8info` at `encode_key2any.c:103`.
const KEY2ANY_103: err_sites::ErrSite = key2any_site(103, c"key_to_p8info", ERR_R_ASN1_LIB);
/// `p8info_to_encp8` at `encode_key2any.c:125`.
const KEY2ANY_125: err_sites::ErrSite =
    key2any_site(125, c"p8info_to_encp8", PROV_R_UNABLE_TO_GET_PASSPHRASE);
/// `key_to_pubkey` at `encode_key2any.c:167`.
const KEY2ANY_167: err_sites::ErrSite = key2any_site(167, c"key_to_pubkey", ERR_R_X509_LIB);
/// `key_to_type_specific_der_bio` at `encode_key2any.c:387`.
const KEY2ANY_387: err_sites::ErrSite =
    key2any_site(387, c"key_to_type_specific_der_bio", ERR_R_PROV_LIB);
/// `prepare_dh_params` at `encode_key2any.c:463`.
const KEY2ANY_463: err_sites::ErrSite = key2any_site(463, c"prepare_dh_params", ERR_R_ASN1_LIB);
/// `prepare_dh_params` at `encode_key2any.c:473`.
const KEY2ANY_473: err_sites::ErrSite = key2any_site(473, c"prepare_dh_params", ERR_R_ASN1_LIB);
/// `dh_spki_pub_to_der` at `encode_key2any.c:492`.
const KEY2ANY_492: err_sites::ErrSite =
    key2any_site(492, c"dh_spki_pub_to_der", PROV_R_NOT_A_PUBLIC_KEY);
/// `dh_spki_pub_to_der` at `encode_key2any.c:496`.
const KEY2ANY_496: err_sites::ErrSite = key2any_site(496, c"dh_spki_pub_to_der", PROV_R_BN_ERROR);
/// `dh_pki_priv_to_der` at `encode_key2any.c:514`.
const KEY2ANY_514: err_sites::ErrSite =
    key2any_site(514, c"dh_pki_priv_to_der", PROV_R_NOT_A_PRIVATE_KEY);
/// `dh_pki_priv_to_der` at `encode_key2any.c:518`.
const KEY2ANY_518: err_sites::ErrSite = key2any_site(518, c"dh_pki_priv_to_der", PROV_R_BN_ERROR);
/// `encode_dsa_params` at `encode_key2any.c:568`.
const KEY2ANY_568: err_sites::ErrSite = key2any_site(568, c"encode_dsa_params", ERR_R_ASN1_LIB);
/// `encode_dsa_params` at `encode_key2any.c:575`.
const KEY2ANY_575: err_sites::ErrSite = key2any_site(575, c"encode_dsa_params", ERR_R_ASN1_LIB);
/// `dsa_spki_pub_to_der` at `encode_key2any.c:608`.
const KEY2ANY_608: err_sites::ErrSite =
    key2any_site(608, c"dsa_spki_pub_to_der", PROV_R_NOT_A_PUBLIC_KEY);
/// `dsa_spki_pub_to_der` at `encode_key2any.c:612`.
const KEY2ANY_612: err_sites::ErrSite = key2any_site(612, c"dsa_spki_pub_to_der", PROV_R_BN_ERROR);
/// `dsa_pki_priv_to_der` at `encode_key2any.c:630`.
const KEY2ANY_630: err_sites::ErrSite =
    key2any_site(630, c"dsa_pki_priv_to_der", PROV_R_NOT_A_PRIVATE_KEY);
/// `dsa_pki_priv_to_der` at `encode_key2any.c:634`.
const KEY2ANY_634: err_sites::ErrSite = key2any_site(634, c"dsa_pki_priv_to_der", PROV_R_BN_ERROR);
/// `prepare_ec_explicit_params` at `encode_key2any.c:668`.
const KEY2ANY_668: err_sites::ErrSite =
    key2any_site(668, c"prepare_ec_explicit_params", ERR_R_ASN1_LIB);
/// `prepare_ec_explicit_params` at `encode_key2any.c:674`.
const KEY2ANY_674: err_sites::ErrSite =
    key2any_site(674, c"prepare_ec_explicit_params", ERR_R_ASN1_LIB);
/// `prepare_ec_params` at `encode_key2any.c:709`.
const KEY2ANY_709: err_sites::ErrSite = key2any_site(709, c"prepare_ec_params", PROV_R_MISSING_OID);
/// `ec_spki_pub_to_der` at `encode_key2any.c:726`.
const KEY2ANY_726: err_sites::ErrSite =
    key2any_site(726, c"ec_spki_pub_to_der", PROV_R_NOT_A_PUBLIC_KEY);
/// `ecx_spki_pub_to_der` at `encode_key2any.c:792`.
const KEY2ANY_792: err_sites::ErrSite =
    key2any_site(792, c"ecx_spki_pub_to_der", ERR_R_PASSED_NULL_PARAMETER);
/// `ecx_pki_priv_to_der` at `encode_key2any.c:812`.
const KEY2ANY_812: err_sites::ErrSite =
    key2any_site(812, c"ecx_pki_priv_to_der", ERR_R_PASSED_NULL_PARAMETER);
/// `ecx_pki_priv_to_der` at `encode_key2any.c:822`.
const KEY2ANY_822: err_sites::ErrSite = key2any_site(822, c"ecx_pki_priv_to_der", ERR_R_ASN1_LIB);
/// `slh_dsa_spki_pub_to_der` at `encode_key2any.c:1032`.
const KEY2ANY_1032: err_sites::ErrSite = key2any_site(
    1032,
    c"slh_dsa_spki_pub_to_der",
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `slh_dsa_pki_priv_to_der` at `encode_key2any.c:1051`.
const KEY2ANY_1051: err_sites::ErrSite = key2any_site(
    1051,
    c"slh_dsa_pki_priv_to_der",
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `key2any_encode` at `encode_key2any.c:1283`.
const KEY2ANY_1283: err_sites::ErrSite =
    key2any_site(1283, c"key2any_encode", ERR_R_PASSED_NULL_PARAMETER);
/// `key2any_encode` at `encode_key2any.c:1295`.
const KEY2ANY_1295: err_sites::ErrSite =
    key2any_site(1295, c"key2any_encode", ERR_R_PASSED_INVALID_ARGUMENT);

// ---------------------------------------------------------------------------------------------
// The context — `encode_key2any.c:52-64`
// ---------------------------------------------------------------------------------------------

/// `typedef struct key2any_ctx_st` — `encode_key2any.c:52-64`.
///
/// The one allocation `key2any_newctx` makes; every table's `encode` receives it as `vctx`.
#[repr(C)]
pub(crate) struct Key2anyCtx {
    /// `PROV_CTX *provctx`.
    provctx: *mut ProvCtx,
    /// `int save_parameters` — set to 0 if parameters should not be saved (dsa only).
    save_parameters: c_int,
    /// `int cipher_intent` — 1 if intending to encrypt/decrypt, otherwise 0.
    cipher_intent: c_int,
    /// `EVP_CIPHER *cipher`.
    cipher: *mut EvpCipher,
    /// `struct ossl_passphrase_data_st pwdata`.
    pwdata: OsslPassphraseData,
}

/// `static void free_asn1_data(int type, void *data)` — `encode_key2any.c:76-86`.
///
/// # Safety
/// `data` is NULL or a live value of the kind `type` selects.
unsafe fn free_asn1_data(type_: c_int, data: *mut c_void) {
    match type_ {
        // SAFETY: `type_` selects the `ASN1_OBJECT` arm.
        V_ASN1_OBJECT => unsafe { ASN1_OBJECT_free(data.cast::<Asn1Object>()) },
        // SAFETY: `type_` selects the `ASN1_STRING` arm.
        V_ASN1_SEQUENCE => unsafe { ASN1_STRING_free(data.cast::<Asn1String>()) },
        _ => {}
    }
}

/// `static PKCS8_PRIV_KEY_INFO *key_to_p8info(...)` — `encode_key2any.c:88-110`.
///
/// # Safety
/// `key` is the caller's object; `k2d` its matching DER producer; `ctx` a live `Key2anyCtx`.
unsafe fn key_to_p8info(
    key: *const c_void,
    key_nid: c_int,
    params: *mut c_void,
    params_type: c_int,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> *mut Pkcs8PrivKeyInfo {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: no preconditions.
    let p8info = PKCS8_PRIV_KEY_INFO_new();

    if !p8info.is_null() {
        // SAFETY: `key` and `k2d` are the caller's per the contract; `der` is this frame's.
        let derlen = unsafe { k2d(key, &mut der, ctx.cast()) };
        // SAFETY: `p8info` is live, `der` is `derlen` readable bytes this call owns.
        if derlen > 0
            // SAFETY: `p8info` is live, `der` is `derlen` readable bytes this call owns.
            && unsafe {
                PKCS8_pkey_set0(
                    p8info,
                    OBJ_nid2obj(key_nid),
                    0,
                    params_type,
                    params,
                    der,
                    derlen,
                )
            } != 0
        {
            return p8info;
        }
    }

    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&KEY2ANY_103) };
    // SAFETY: `p8info` is NULL or this call's object.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
    // SAFETY: `der` is NULL or this call's allocation.
    unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
    ptr::null_mut()
}

/// `static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info, KEY2ANY_CTX *ctx)` —
/// `encode_key2any.c:112-133`.
///
/// # Safety
/// `p8info` is live; `ctx` a live `Key2anyCtx` whose `cipher` may be NULL.
unsafe fn p8info_to_encp8(p8info: *mut Pkcs8PrivKeyInfo, ctx: *mut Key2anyCtx) -> *mut X509Sig {
    let mut kstr = [0 as c_char; PEM_BUFSIZE as usize];
    let mut klen: usize = 0;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).cipher.is_null() } {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live and `provctx` is its provider's context.
    let libctx = unsafe { ossl_prov_ctx_get0_libctx((*ctx).provctx) };
    // SAFETY: `kstr` is writable for `PEM_BUFSIZE` bytes, `klen` is this frame's, and `pwdata` is
    // the live passphrase data the context embeds.
    if unsafe {
        ossl_pw_get_passphrase(
            kstr.as_mut_ptr(),
            kstr.len(),
            &mut klen,
            ptr::null(),
            1,
            ptr::addr_of_mut!((*ctx).pwdata),
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_125) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx`'s cipher and libctx are live, `kstr` is `klen` readable bytes, `p8info` is
    // live. First argument == -1 means "standard", as the authority's comment records.
    let p8 = unsafe {
        PKCS8_encrypt_ex(
            -1,
            (*ctx).cipher,
            kstr.as_ptr(),
            klen as c_int,
            ptr::null_mut(),
            0,
            0,
            p8info,
            libctx,
            ptr::null(),
        )
    };
    // SAFETY: `kstr` is this frame's buffer.
    unsafe { OPENSSL_cleanse(kstr.as_mut_ptr().cast::<c_void>(), klen) };
    p8
}

/// `static X509_SIG *key_to_encp8(...)` — `encode_key2any.c:135-150`.
///
/// # Safety
/// As [`key_to_p8info`].
unsafe fn key_to_encp8(
    key: *const c_void,
    key_nid: c_int,
    params: *mut c_void,
    params_type: c_int,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> *mut X509Sig {
    // SAFETY: the arguments are forwarded under this function's contract.
    let p8info = unsafe { key_to_p8info(key, key_nid, params, params_type, k2d, ctx) };

    if p8info.is_null() {
        // SAFETY: `params` is the caller's value for `params_type`.
        unsafe { free_asn1_data(params_type, params) };
        ptr::null_mut()
    } else {
        // SAFETY: `p8info` is this call's live object and `ctx` is live.
        let p8 = unsafe { p8info_to_encp8(p8info, ctx) };
        // SAFETY: `p8info` is this call's object.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
        p8
    }
}

/// `static X509_PUBKEY *key_to_pubkey(...)` — `encode_key2any.c:152-174`.
///
/// # Safety
/// `key` is the caller's object; `k2d` its matching DER producer; `ctx` a live `Key2anyCtx`.
unsafe fn key_to_pubkey(
    key: *const c_void,
    key_nid: c_int,
    params: *mut c_void,
    params_type: c_int,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> *mut X509Pubkey {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: no preconditions.
    let xpk = X509_PUBKEY_new();

    if !xpk.is_null() {
        // SAFETY: `key`/`k2d` are the caller's; `der` is this frame's.
        let derlen = unsafe { k2d(key, &mut der, ctx.cast()) };
        // SAFETY: `xpk` is live and `der` is `derlen` readable bytes this call owns.
        if derlen > 0
            // SAFETY: `xpk` is live and `der` is `derlen` readable bytes this call owns.
            && unsafe {
                X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid), params_type, params, der, derlen)
            } != 0
        {
            return xpk;
        }
    }

    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&KEY2ANY_167) };
    // SAFETY: `xpk` is NULL or this call's object.
    unsafe { X509_PUBKEY_free(xpk) };
    // SAFETY: `der` is NULL or this call's allocation.
    unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
    ptr::null_mut()
}

// ---------------------------------------------------------------------------------------------
// The four writers `key_to_*_*_priv_bio`/`_pub_bio`/`_param_bio` — `encode_key2any.c:195-441`
// ---------------------------------------------------------------------------------------------

/// `static int key_to_epki_der_priv_bio(...)` — `encode_key2any.c:195-220`.
///
/// # Safety
/// The `key_to_der_fn` contract: `out` a live BIO; `key` the caller's object; `k2d`/`ctx` live.
unsafe extern "C" fn key_to_epki_der_priv_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    _pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).cipher_intent } == 0 {
        return 0;
    }

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract; `str`/`strtype` are this frame's.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let p8 = unsafe { key_to_encp8(key, key_nid, str, strtype, k2d, ctx) };
    let ret = if !p8.is_null() {
        // SAFETY: `out` is live and `p8` is this call's live object.
        unsafe { i2d_PKCS8_bio(out, p8) }
    } else {
        0
    };
    // SAFETY: `p8` is NULL or this call's object.
    unsafe { X509_SIG_free(p8) };
    ret
}

/// `static int key_to_epki_pem_priv_bio(...)` — `encode_key2any.c:222-247`.
///
/// # Safety
/// As [`key_to_epki_der_priv_bio`].
unsafe extern "C" fn key_to_epki_pem_priv_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    _pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).cipher_intent } == 0 {
        return 0;
    }

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract; `str`/`strtype` are this frame's.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let p8 = unsafe { key_to_encp8(key, key_nid, str, strtype, k2d, ctx) };
    let ret = if !p8.is_null() {
        // SAFETY: `out` is live and `p8` is this call's live object.
        unsafe { PEM_write_bio_PKCS8(out, p8) }
    } else {
        0
    };
    // SAFETY: `p8` is NULL or this call's object.
    unsafe { X509_SIG_free(p8) };
    ret
}

/// `static int key_to_pki_der_priv_bio(...)` — `encode_key2any.c:249-278`.
///
/// # Safety
/// As [`key_to_epki_der_priv_bio`].
unsafe extern "C" fn key_to_pki_der_priv_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).cipher_intent } != 0 {
        // SAFETY: the private arm's contract.
        return unsafe { key_to_epki_der_priv_bio(out, key, key_nid, pemname, p2s, k2d, ctx) };
    }

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let p8info = unsafe { key_to_p8info(key, key_nid, str, strtype, k2d, ctx) };

    let ret = if !p8info.is_null() {
        // SAFETY: `out` is live and `p8info` is this call's live object.
        unsafe { i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info) }
    } else {
        // SAFETY: `str` is the caller's value for `strtype`.
        unsafe { free_asn1_data(strtype, str) };
        0
    };

    // SAFETY: `p8info` is NULL or this call's object.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
    ret
}

/// `static int key_to_pki_pem_priv_bio(...)` — `encode_key2any.c:280-309`.
///
/// # Safety
/// As [`key_to_pki_der_priv_bio`].
unsafe extern "C" fn key_to_pki_pem_priv_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).cipher_intent } != 0 {
        // SAFETY: the private arm's contract.
        return unsafe { key_to_epki_pem_priv_bio(out, key, key_nid, pemname, p2s, k2d, ctx) };
    }

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let p8info = unsafe { key_to_p8info(key, key_nid, str, strtype, k2d, ctx) };

    let ret = if !p8info.is_null() {
        // SAFETY: `out` is live and `p8info` is this call's live object.
        unsafe { PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info) }
    } else {
        // SAFETY: `str` is the caller's value for `strtype`.
        unsafe { free_asn1_data(strtype, str) };
        0
    };

    // SAFETY: `p8info` is NULL or this call's object.
    unsafe { PKCS8_PRIV_KEY_INFO_free(p8info) };
    ret
}

/// `static int key_to_spki_der_pub_bio(...)` — `encode_key2any.c:311-334`.
///
/// # Safety
/// As [`key_to_epki_der_priv_bio`].
unsafe extern "C" fn key_to_spki_der_pub_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    _pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let xpk = unsafe { key_to_pubkey(key, key_nid, str, strtype, k2d, ctx) };

    let ret = if !xpk.is_null() {
        // SAFETY: `out` is live and `xpk` is this call's live object.
        unsafe { i2d_X509_PUBKEY_bio(out, xpk) }
    } else {
        0
    };

    // SAFETY: `xpk` is NULL or this call's object; it also frees `str`.
    unsafe { X509_PUBKEY_free(xpk) };
    ret
}

/// `static int key_to_spki_pem_pub_bio(...)` — `encode_key2any.c:336-361`.
///
/// # Safety
/// As [`key_to_spki_der_pub_bio`].
unsafe extern "C" fn key_to_spki_pem_pub_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    _pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut str: *mut c_void = ptr::null_mut();
    let mut strtype = V_ASN1_UNDEF;

    if let Some(f) = p2s {
        // SAFETY: the callback's own contract.
        if unsafe { f(key, key_nid, (*ctx).save_parameters, &mut str, &mut strtype) } == 0 {
            return 0;
        }
    }

    // SAFETY: the arguments are forwarded under this function's contract.
    let xpk = unsafe { key_to_pubkey(key, key_nid, str, strtype, k2d, ctx) };

    let ret = if !xpk.is_null() {
        // SAFETY: `out` is live and `xpk` is this call's live object.
        unsafe { PEM_write_bio_X509_PUBKEY(out, xpk) }
    } else {
        // SAFETY: `str` is the caller's value for `strtype`.
        unsafe { free_asn1_data(strtype, str) };
        0
    };

    // SAFETY: `xpk` is NULL or this call's object; it also frees `str`.
    unsafe { X509_PUBKEY_free(xpk) };
    ret
}

/// `static int key_to_type_specific_der_bio(...)` — `encode_key2any.c:375-397`, the shared body
/// of the three `key_to_type_specific_der_{priv,pub,param}_bio` aliases.
///
/// # Safety
/// As [`key_to_epki_der_priv_bio`].
unsafe extern "C" fn key_to_type_specific_der_bio(
    out: *mut Bio,
    key: *const c_void,
    _key_nid: c_int,
    _pemname: *const c_char,
    _p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    let mut der: *mut c_uchar = ptr::null_mut();

    // SAFETY: `key`/`k2d` are the caller's; `der` is this frame's.
    let derlen = unsafe { k2d(key, &mut der, ctx.cast()) };
    if derlen <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_387) };
        return 0;
    }

    // SAFETY: `out` is live and `der` is `derlen` readable bytes.
    let ret = unsafe { BIO_write(out, der.cast::<c_void>(), derlen) };
    // SAFETY: `der` is this call's allocation.
    unsafe { CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0) };
    c_int::from(ret > 0)
}

/// `static int key_to_type_specific_pem_bio_cb(...)` — `encode_key2any.c:399-409`.
///
/// # Safety
/// As [`key_to_epki_der_priv_bio`], plus the PEM callback's own contract.
unsafe extern "C" fn key_to_type_specific_pem_bio_cb(
    out: *mut Bio,
    key: *const c_void,
    _key_nid: c_int,
    pemname: *const c_char,
    _p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
    cb: Option<crate::evp::pem_bridge::PemPasswordCb>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: every argument is live per this function's contract; `ctx` carries the cipher.
    c_int::from(
        unsafe {
            PEM_ASN1_write_bio_ctx(
                Some(k2d),
                ctx.cast(),
                pemname,
                out,
                key,
                (*ctx).cipher,
                ptr::null(),
                0,
                cb,
                cbarg,
            )
        } > 0,
    )
}

/// `static int key_to_type_specific_pem_priv_bio(...)` — `encode_key2any.c:411-420`.
///
/// # Safety
/// As [`key_to_type_specific_pem_bio_cb`].
unsafe extern "C" fn key_to_type_specific_pem_priv_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    // SAFETY: the shared body's contract, with the unit's own PEM callback.
    unsafe {
        key_to_type_specific_pem_bio_cb(
            out,
            key,
            key_nid,
            pemname,
            p2s,
            k2d,
            ctx,
            Some(ossl_pw_pem_password),
            ptr::addr_of_mut!((*ctx).pwdata).cast(),
        )
    }
}

/// `static int key_to_type_specific_pem_pub_bio(...)` — `encode_key2any.c:422-430`.
///
/// # Safety
/// As [`key_to_type_specific_pem_bio_cb`].
unsafe extern "C" fn key_to_type_specific_pem_pub_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    // SAFETY: the shared body's contract, with no callback.
    unsafe {
        key_to_type_specific_pem_bio_cb(
            out,
            key,
            key_nid,
            pemname,
            p2s,
            k2d,
            ctx,
            None,
            ptr::null_mut(),
        )
    }
}

/// `static int key_to_type_specific_pem_param_bio(...)` — `encode_key2any.c:432-442`.
///
/// # Safety
/// As [`key_to_type_specific_pem_bio_cb`].
unsafe extern "C" fn key_to_type_specific_pem_param_bio(
    out: *mut Bio,
    key: *const c_void,
    key_nid: c_int,
    pemname: *const c_char,
    p2s: Option<
        unsafe extern "C" fn(*const c_void, c_int, c_int, *mut *mut c_void, *mut c_int) -> c_int,
    >,
    k2d: OsslI2dOfVoidCtx,
    ctx: *mut Key2anyCtx,
) -> c_int {
    // SAFETY: the shared body's contract, with no callback.
    unsafe {
        key_to_type_specific_pem_bio_cb(
            out,
            key,
            key_nid,
            pemname,
            p2s,
            k2d,
            ctx,
            None,
            ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The four PKCS#8/PKCS#1 `ASN1_i2d_bio`/`PEM_ASN1_write_bio` helpers the writers reach. These are
// the `IMPLEMENT_PEM_{i2d,write}_*` expansions `crypto/pem/pem_pk8.c` builds internally (see that
// module's doc), transcribed under the authority's call names.
// ---------------------------------------------------------------------------------------------

/// `i2d_PKCS8_bio` — the `IMPLEMENT_PEM_i2d_bio(PKCS8, X509_SIG, …)` body.
///
/// # Safety
/// `bp` a live BIO; `p8` live.
unsafe fn i2d_PKCS8_bio(bp: *mut Bio, p8: *const X509Sig) -> c_int {
    // SAFETY: this wrapper restates `i2d_X509_SIG`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { i2d_X509_SIG(x.cast::<X509Sig>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bp` is live, `i2d` is the encoder above, `p8` is live.
    unsafe { ASN1_i2d_bio(i2d, bp, p8.cast::<c_void>()) }
}

/// `i2d_PKCS8_PRIV_KEY_INFO_bio` — the `IMPLEMENT_PEM_i2d_bio(PKCS8_PRIV_KEY_INFO, …)` body.
///
/// # Safety
/// `bp` a live BIO; `p8inf` live.
unsafe fn i2d_PKCS8_PRIV_KEY_INFO_bio(bp: *mut Bio, p8inf: *const Pkcs8PrivKeyInfo) -> c_int {
    // SAFETY: this wrapper restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { i2d_PKCS8_PRIV_KEY_INFO(x.cast::<Pkcs8PrivKeyInfo>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: `bp` is live, `i2d` is the encoder above, `p8inf` is live.
    unsafe { ASN1_i2d_bio(i2d, bp, p8inf.cast::<c_void>()) }
}

/// `PEM_write_bio_PKCS8` — the `IMPLEMENT_PEM_write_bio(PKCS8, X509_SIG, …)` body.
///
/// # Safety
/// `bp` a live BIO; `p8` live.
unsafe fn PEM_write_bio_PKCS8(bp: *mut Bio, p8: *const X509Sig) -> c_int {
    // SAFETY: this wrapper restates `i2d_X509_SIG`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { i2d_X509_SIG(x.cast::<X509Sig>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: every argument is live; the two NULLs are the authority's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            PEM_STRING_PKCS8,
            bp,
            p8.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `PEM_write_bio_PKCS8_PRIV_KEY_INFO` — the `IMPLEMENT_PEM_write_bio(PKCS8_PRIV_KEY_INFO, …)`
/// body.
///
/// # Safety
/// `bp` a live BIO; `p8inf` live.
unsafe fn PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp: *mut Bio, p8inf: *const Pkcs8PrivKeyInfo) -> c_int {
    // SAFETY: this wrapper restates `i2d_PKCS8_PRIV_KEY_INFO`'s contract in `I2dOfVoid`'s terms.
    unsafe extern "C" fn i2d_void(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { i2d_PKCS8_PRIV_KEY_INFO(x.cast::<Pkcs8PrivKeyInfo>(), out) }
    }
    let i2d: I2dOfVoid = i2d_void;
    // SAFETY: every argument is live; the two NULLs are the authority's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            PEM_STRING_PKCS8INF,
            bp,
            p8inf.cast::<c_void>(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The per-type DER producers — `encode_key2any.c:456-1103`
// ---------------------------------------------------------------------------------------------

/// `PKEY_EC_NO_PARAMETERS`' cousin: `EC_PKEY_NO_PARAMETERS` — `include/openssl/ec.h:950`, read by
/// `ec_pki_priv_to_der`.
const EC_PKEY_NO_PARAMETERS: c_int = 0x001;

/// `EVP_PKEY_SLH_DSA_SHA2_128S` — `crypto/slh_dsa.h`, `NID_SLH_DSA_SHA2_128s`.
const EVP_PKEY_SLH_DSA_SHA2_128S: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_128s;
/// `EVP_PKEY_SLH_DSA_SHA2_128F`.
const EVP_PKEY_SLH_DSA_SHA2_128F: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_128f;
/// `EVP_PKEY_SLH_DSA_SHA2_192S`.
const EVP_PKEY_SLH_DSA_SHA2_192S: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_192s;
/// `EVP_PKEY_SLH_DSA_SHA2_192F`.
const EVP_PKEY_SLH_DSA_SHA2_192F: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_192f;
/// `EVP_PKEY_SLH_DSA_SHA2_256S`.
const EVP_PKEY_SLH_DSA_SHA2_256S: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_256s;
/// `EVP_PKEY_SLH_DSA_SHA2_256F`.
const EVP_PKEY_SLH_DSA_SHA2_256F: c_int = crate::runtime::obj::NID_SLH_DSA_SHA2_256f;
/// `EVP_PKEY_SLH_DSA_SHAKE_128S`.
const EVP_PKEY_SLH_DSA_SHAKE_128S: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_128s;
/// `EVP_PKEY_SLH_DSA_SHAKE_128F`.
const EVP_PKEY_SLH_DSA_SHAKE_128F: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_128f;
/// `EVP_PKEY_SLH_DSA_SHAKE_192S`.
const EVP_PKEY_SLH_DSA_SHAKE_192S: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_192s;
/// `EVP_PKEY_SLH_DSA_SHAKE_192F`.
const EVP_PKEY_SLH_DSA_SHAKE_192F: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_192f;
/// `EVP_PKEY_SLH_DSA_SHAKE_256S`.
const EVP_PKEY_SLH_DSA_SHAKE_256S: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_256s;
/// `EVP_PKEY_SLH_DSA_SHAKE_256F`.
const EVP_PKEY_SLH_DSA_SHAKE_256F: c_int = crate::runtime::obj::NID_SLH_DSA_SHAKE_256f;

/// `static int prepare_dh_params(const void *dh, int nid, int save, void **pstr, int *pstrtype)`
/// — `encode_key2any.c:457-482`.
///
/// # Safety
/// `dh` a live `DH *`; `pstr`/`pstrtype` writable.
unsafe extern "C" fn prepare_dh_params(
    dh: *const c_void,
    nid: c_int,
    _save: c_int,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let params = ASN1_STRING_new();
    if params.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_463) };
        return 0;
    }

    // SAFETY: `params` is live; `dh` is the caller's object and `params.data` this frame's slot.
    let len = if nid == EVP_PKEY_DHX {
        // SAFETY: `dh` is the caller's object and `params`'s data slot is this frame's.
        unsafe { i2d_DHxparams(dh.cast::<Dh>(), ptr::addr_of_mut!((*params).data)) }
    } else {
        // SAFETY: as above, through the PKCS#3 encoder.
        unsafe { i2d_DHparams(dh.cast::<Dh>(), ptr::addr_of_mut!((*params).data)) }
    };
    // SAFETY: `params` is live.
    unsafe { (*params).length = len };

    if len <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_473) };
        // SAFETY: `params` is this frame's object.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    // SAFETY: `params` is live and the out-parameters are this frame's.
    unsafe {
        (*params).type_ = V_ASN1_SEQUENCE;
        *pstr = params.cast::<c_void>();
        *pstrtype = V_ASN1_SEQUENCE;
    }
    1
}

/// `static int dh_spki_pub_to_der(const void *dh, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:484-504`.
///
/// # Safety
/// `dh` a live `DH *`; `pder` writable.
unsafe extern "C" fn dh_spki_pub_to_der(
    dh: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let bn = unsafe { DH_get0_pub_key(dh.cast::<Dh>()) };
    if bn.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_492) };
        return 0;
    }
    // SAFETY: `bn` is live and NULL selects a fresh integer.
    let pub_key = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if pub_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_496) };
        return 0;
    }
    // SAFETY: `pub_key` is live and `pder` is the caller's cursor.
    let ret = unsafe { i2d_ASN1_INTEGER(pub_key, pder) };
    // SAFETY: `pub_key` is this call's object.
    unsafe { ASN1_STRING_clear_free(pub_key) };
    ret
}

/// `static int dh_pki_priv_to_der(const void *dh, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:506-526` (also `dh_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`dh_spki_pub_to_der`].
unsafe extern "C" fn dh_pki_priv_to_der(
    dh: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let bn = unsafe { DH_get0_priv_key(dh.cast::<Dh>()) };
    if bn.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_514) };
        return 0;
    }
    // SAFETY: `bn` is live and NULL selects a fresh integer.
    let priv_key = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if priv_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_518) };
        return 0;
    }
    // SAFETY: `priv_key` is live and `pder` is the caller's cursor.
    let ret = unsafe { i2d_ASN1_INTEGER(priv_key, pder) };
    // SAFETY: `priv_key` is this call's object.
    unsafe { ASN1_STRING_clear_free(priv_key) };
    ret
}

/// `static int dh_type_specific_params_to_der(const void *dh, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:530-537`.
///
/// # Safety
/// As [`dh_spki_pub_to_der`].
unsafe extern "C" fn dh_type_specific_params_to_der(
    dh: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    if unsafe { DH_test_flags(dh.cast::<Dh>(), DH_FLAG_TYPE_DHX) } != 0 {
        // SAFETY: `dh` is live and `pder` is the caller's cursor.
        unsafe { i2d_DHxparams(dh.cast::<Dh>(), pder) }
    } else {
        // SAFETY: as above.
        unsafe { i2d_DHparams(dh.cast::<Dh>(), pder) }
    }
}

/// `static int dh_check_key_type(const void *dh, int expected_type)` — `encode_key2any.c:546-551`.
///
/// # Safety
/// `dh` a live `DH *`.
unsafe extern "C" fn dh_check_key_type(dh: *const c_void, expected_type: c_int) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let type_ = if unsafe { DH_test_flags(dh.cast::<Dh>(), DH_FLAG_TYPE_DHX) } != 0 {
        EVP_PKEY_DHX
    } else {
        EVP_PKEY_DH
    };
    c_int::from(type_ == expected_type)
}

/// `static int encode_dsa_params(const void *dsa, int nid, void **pstr, int *pstrtype)` —
/// `encode_key2any.c:562-583`.
///
/// # Safety
/// `dsa` a live `DSA *`; `pstr`/`pstrtype` writable.
unsafe fn encode_dsa_params(
    dsa: *const c_void,
    _nid: c_int,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let params = ASN1_STRING_new();
    if params.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_568) };
        return 0;
    }
    // SAFETY: `params` is live and its `data` slot is this frame's.
    unsafe {
        (*params).length = i2d_DSAparams(dsa.cast::<Dsa>(), ptr::addr_of_mut!((*params).data));
    }
    // SAFETY: `params` is live.
    if unsafe { (*params).length } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_575) };
        // SAFETY: `params` is this frame's object.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    // SAFETY: the out-parameters are this frame's.
    unsafe {
        *pstrtype = V_ASN1_SEQUENCE;
        *pstr = params.cast::<c_void>();
    }
    1
}

/// `static int prepare_dsa_params(const void *dsa, int nid, int save, void **pstr,
/// int *pstrtype)` — `encode_key2any.c:585-598`.
///
/// # Safety
/// As [`encode_dsa_params`].
unsafe extern "C" fn prepare_dsa_params(
    dsa: *const c_void,
    nid: c_int,
    save: c_int,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let p = unsafe { DSA_get0_p(dsa.cast::<Dsa>()) };
    // SAFETY: as above.
    let q = unsafe { DSA_get0_q(dsa.cast::<Dsa>()) };
    // SAFETY: as above.
    let g = unsafe { DSA_get0_g(dsa.cast::<Dsa>()) };

    if save != 0 && !p.is_null() && !q.is_null() && !g.is_null() {
        // SAFETY: the arguments are forwarded under this function's contract.
        return unsafe { encode_dsa_params(dsa, nid, pstr, pstrtype) };
    }
    // SAFETY: the out-parameters are this frame's.
    unsafe {
        *pstr = ptr::null_mut();
        *pstrtype = V_ASN1_UNDEF;
    }
    1
}

/// `static int dsa_spki_pub_to_der(const void *dsa, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:600-620`.
///
/// # Safety
/// `dsa` a live `DSA *`; `pder` writable.
unsafe extern "C" fn dsa_spki_pub_to_der(
    dsa: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let bn = unsafe { DSA_get0_pub_key(dsa.cast::<Dsa>()) };
    if bn.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_608) };
        return 0;
    }
    // SAFETY: `bn` is live and NULL selects a fresh integer.
    let pub_key = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if pub_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_612) };
        return 0;
    }
    // SAFETY: `pub_key` is live and `pder` is the caller's cursor.
    let ret = unsafe { i2d_ASN1_INTEGER(pub_key, pder) };
    // SAFETY: `pub_key` is this call's object.
    unsafe { ASN1_STRING_clear_free(pub_key) };
    ret
}

/// `static int dsa_pki_priv_to_der(const void *dsa, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:622-642` (also `dsa_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`dsa_spki_pub_to_der`].
unsafe extern "C" fn dsa_pki_priv_to_der(
    dsa: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let bn = unsafe { DSA_get0_priv_key(dsa.cast::<Dsa>()) };
    if bn.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_630) };
        return 0;
    }
    // SAFETY: `bn` is live and NULL selects a fresh integer.
    let priv_key = unsafe { BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if priv_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_634) };
        return 0;
    }
    // SAFETY: `priv_key` is live and `pder` is the caller's cursor.
    let ret = unsafe { i2d_ASN1_INTEGER(priv_key, pder) };
    // SAFETY: `priv_key` is this call's object.
    unsafe { ASN1_STRING_clear_free(priv_key) };
    ret
}

/// One `k2d_NOCTX(n, f)` expansion (`encode_key2any.c:446-452`): a `ctx`-taking forwarder to the
/// no-context `i2d` function `$f`.
macro_rules! k2d_noctx {
    ($name:ident, $f:path) => {
        /// The `k2d_NOCTX` forwarder.
        ///
        /// # Safety
        /// `key` is the `i2d` function's object; `pder` its cursor.
        unsafe extern "C" fn $name(
            key: *const c_void,
            pder: *mut *mut c_uchar,
            _ctx: *mut c_void,
        ) -> c_int {
            // SAFETY: the contract is forwarded.
            unsafe { $f(key.cast(), pder) }
        }
    };
}

k2d_noctx!(dsa_prv_k2d, i2d_DSAPrivateKey);
k2d_noctx!(dsa_pub_k2d, i2d_DSAPublicKey);
k2d_noctx!(dsa_param_k2d, i2d_DSAparams);

/// `static int prepare_ec_explicit_params(const void *eckey, void **pstr, int *pstrtype)` —
/// `encode_key2any.c:662-682`.
///
/// # Safety
/// `eckey` a live `EC_KEY *`; `pstr`/`pstrtype` writable.
unsafe fn prepare_ec_explicit_params(
    eckey: *const c_void,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let params = ASN1_STRING_new();
    if params.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_668) };
        return 0;
    }
    // SAFETY: `params` is live and its `data` slot is this frame's.
    unsafe {
        (*params).length =
            i2d_ECParameters(eckey.cast::<EcKey>(), ptr::addr_of_mut!((*params).data));
    }
    // SAFETY: `params` is live.
    if unsafe { (*params).length } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_674) };
        // SAFETY: `params` is this frame's object.
        unsafe { ASN1_STRING_free(params) };
        return 0;
    }
    // SAFETY: the out-parameters are this frame's.
    unsafe {
        *pstrtype = V_ASN1_SEQUENCE;
        *pstr = params.cast::<c_void>();
    }
    1
}

/// `static int prepare_ec_params(const void *eckey, int nid, int save, void **pstr,
/// int *pstrtype)` — `encode_key2any.c:688-720`.
///
/// # Safety
/// As [`prepare_ec_explicit_params`].
unsafe extern "C" fn prepare_ec_params(
    eckey: *const c_void,
    _nid: c_int,
    _save: c_int,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: `eckey` is live per the contract.
    let group = unsafe { EC_KEY_get0_group(eckey.cast::<EcKey>()) };
    if group.is_null() {
        return 0;
    }
    // SAFETY: `group` is live.
    let curve_nid = unsafe { EC_GROUP_get_curve_name(group) };
    let mut params: *mut Asn1Object = ptr::null_mut();
    if curve_nid != NID_undef {
        params = OBJ_nid2obj(curve_nid);
        if params.is_null() {
            return 0;
        }
    }

    // SAFETY: `group` is live.
    if curve_nid != NID_undef
        // SAFETY: `group` is live.
        && (unsafe { EC_GROUP_get_asn1_flag(group) } & OPENSSL_EC_NAMED_CURVE) != 0
    {
        // The CHOICE came to namedCurve.
        // SAFETY: `params` is non-NULL here (curve_nid != NID_undef).
        if unsafe { OBJ_length(params) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&KEY2ANY_709) };
            // SAFETY: `params` is this call's object.
            unsafe { ASN1_OBJECT_free(params) };
            return 0;
        }
        // SAFETY: the out-parameters are this frame's.
        unsafe {
            *pstr = params.cast::<c_void>();
            *pstrtype = V_ASN1_OBJECT;
        }
        1
    } else {
        // The CHOICE came to ecParameters.
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { prepare_ec_explicit_params(eckey, pstr, pstrtype) }
    }
}

/// `static int ec_spki_pub_to_der(const void *eckey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:722-730`.
///
/// # Safety
/// `eckey` a live `EC_KEY *`; `pder` writable.
unsafe extern "C" fn ec_spki_pub_to_der(
    eckey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `eckey` is live per the contract.
    if unsafe { EC_KEY_get0_public_key(eckey.cast::<EcKey>()) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_726) };
        return 0;
    }
    // SAFETY: `eckey` is live and `pder` is the caller's cursor.
    unsafe { i2o_ECPublicKey(eckey.cast::<EcKey>(), pder) }
}

/// `static int ec_pki_priv_to_der(const void *veckey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:732-751` (also `ec_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`ec_spki_pub_to_der`].
unsafe extern "C" fn ec_pki_priv_to_der(
    veckey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: the authority writes the flags through this pointer (`encode_key2any.c:732-751`),
    // so the object is mutable despite the `const void *` parameter.
    let eckey = veckey.cast_mut().cast::<EcKey>();
    // SAFETY: `eckey` is live per the contract.
    let old_flags = unsafe { EC_KEY_get_enc_flags(eckey) };
    // SAFETY: `eckey` is live and the flag write is the authority's.
    unsafe {
        EC_KEY_set_enc_flags(
            eckey,
            (old_flags | EC_PKEY_NO_PARAMETERS as c_uint) as c_uint,
        )
    };
    // SAFETY: `eckey` is live and `pder` is the caller's cursor.
    let ret = unsafe { i2d_ECPrivateKey(eckey, pder) };
    // SAFETY: `eckey` is live; the flags are restored.
    unsafe { EC_KEY_set_enc_flags(eckey, old_flags) };
    ret
}

k2d_noctx!(ec_param_k2d, i2d_ECParameters);
k2d_noctx!(ec_prv_k2d, i2d_ECPrivateKey);

/// `static int ecx_spki_pub_to_der(const void *vecxkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:785-802`.
///
/// # Safety
/// `vecxkey` a live `ECX_KEY *`; `pder` writable.
unsafe extern "C" fn ecx_spki_pub_to_der(
    vecxkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    let ecxkey = vecxkey.cast::<EcxKey>();
    if ecxkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_792) };
        return 0;
    }
    // SAFETY: `ecxkey` is live; the source is `keylen` readable bytes.
    let keyblob = unsafe {
        CRYPTO_memdup(
            (*ecxkey).pubkey.as_ptr().cast::<c_void>(),
            (*ecxkey).keylen,
            ptr::null(),
            0,
        )
    }
    .cast::<c_uchar>();
    if keyblob.is_null() {
        return 0;
    }
    // SAFETY: `pder` is the caller's cursor.
    unsafe { *pder = keyblob };
    // SAFETY: `ecxkey` is live per the contract.
    unsafe { (*ecxkey).keylen as c_int }
}

/// `static int ecx_pki_priv_to_der(const void *vecxkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:804-827` (also `ecx_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`ecx_spki_pub_to_der`].
unsafe extern "C" fn ecx_pki_priv_to_der(
    vecxkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    let ecxkey = vecxkey.cast::<EcxKey>();
    // SAFETY: `ecxkey` is live per the contract.
    if ecxkey.is_null() || unsafe { (*ecxkey).privkey }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_812) };
        return 0;
    }
    // The authority builds a stack `ASN1_OCTET_STRING` holding the private bytes; the crate
    // builds the same value to hand to `i2d_ASN1_OCTET_STRING`.
    // SAFETY: `ecxkey` is live; the octet string borrows its private key.
    let oct = unsafe {
        let mut oct: Asn1String = core::mem::zeroed();
        oct.data = (*ecxkey).privkey;
        oct.length = (*ecxkey).keylen as c_int;
        oct.flags = 0;
        oct
    };
    // SAFETY: `oct` is a live value and `pder` is the caller's cursor.
    let keybloblen = unsafe { i2d_ASN1_OCTET_STRING(&oct, pder) };
    if keybloblen < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_822) };
        return 0;
    }
    keybloblen
}

/// `static int ml_dsa_spki_pub_to_der(const void *vkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:851-855`.
///
/// # Safety
/// `vkey` a live `ML_DSA_KEY *`; `pder` writable.
unsafe extern "C" fn ml_dsa_spki_pub_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `vkey` is live per the contract.
    unsafe { ossl_ml_dsa_i2d_pubkey(vkey.cast::<MlDsaKey>(), pder) }
}

/// `static int ml_dsa_pki_priv_to_der(const void *vkey, unsigned char **pder, void *vctx)` —
/// `encode_key2any.c:857-863` (also `ml_dsa_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`ml_dsa_spki_pub_to_der`], with `vctx` the live `Key2anyCtx`.
unsafe extern "C" fn ml_dsa_pki_priv_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    vctx: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Key2anyCtx>();
    // SAFETY: `vkey` is live; `ctx` carries the provider context the codec needs.
    unsafe { ossl_ml_dsa_i2d_prvkey(vkey.cast::<MlDsaKey>(), pder, (*ctx).provctx) }
}

/// `static int ml_kem_spki_pub_to_der(const void *vkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:881-885`.
///
/// # Safety
/// `vkey` a live `ML_KEM_KEY *`; `pder` writable.
unsafe extern "C" fn ml_kem_spki_pub_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    // SAFETY: `vkey` is live per the contract.
    unsafe { ossl_ml_kem_i2d_pubkey(vkey.cast::<MlKemKey>(), pder) }
}

/// `static int ml_kem_pki_priv_to_der(const void *vkey, unsigned char **pder, void *vctx)` —
/// `encode_key2any.c:887-893` (also `ml_kem_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`ml_kem_spki_pub_to_der`], with `vctx` the live `Key2anyCtx`.
unsafe extern "C" fn ml_kem_pki_priv_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    vctx: *mut c_void,
) -> c_int {
    let ctx = vctx.cast::<Key2anyCtx>();
    // SAFETY: `vkey` is live; `ctx` carries the provider context the codec needs.
    unsafe { ossl_ml_kem_i2d_prvkey(vkey.cast::<MlKemKey>(), pder, (*ctx).provctx) }
}

/// `static int prepare_rsa_params(const void *rsa, int nid, int save, void **pstr,
/// int *pstrtype)` — `encode_key2any.c:915-985`.
///
/// # Safety
/// `rsa` a live `RSA *`; `pstr`/`pstrtype` writable.
unsafe extern "C" fn prepare_rsa_params(
    rsa: *const c_void,
    _nid: c_int,
    _save: c_int,
    pstr: *mut *mut c_void,
    pstrtype: *mut c_int,
) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    let pss: *mut RsaPssParams30 =
        unsafe { ossl_rsa_get0_pss_params_30(rsa.cast_mut().cast::<Rsa>()) };

    // SAFETY: `pstr` is the caller's out-parameter.
    unsafe { *pstr = ptr::null_mut() };

    // SAFETY: `rsa` is live per the contract.
    match unsafe { RSA_test_flags(rsa.cast::<Rsa>(), RSA_FLAG_TYPE_MASK) } {
        RSA_FLAG_TYPE_RSA => {
            // If plain RSA, the parameters shall be NULL.
            // SAFETY: `pstrtype` is the caller's out-parameter.
            unsafe { *pstrtype = V_ASN1_NULL };
            1
        }
        RSA_FLAG_TYPE_RSASSAPSS => {
            // SAFETY: `pss` is the key's own params object.
            if unsafe { ossl_rsa_pss_params_30_is_unrestricted(pss) } != 0 {
                // SAFETY: `pstrtype` is the caller's out-parameter.
                unsafe { *pstrtype = V_ASN1_UNDEF };
                return 1;
            }
            // The two-pass WPACKET build; `str` is freed on every failure path.
            let mut str: *mut c_uchar = ptr::null_mut();
            let mut str_sz: usize = 0;
            let mut failed = false;

            for i in 0..2 {
                // SAFETY: all-zero is a valid bit pattern for a `Wpacket`; the two init functions
                // initialise every field before it is read.
                let mut pkt: Wpacket = unsafe { core::mem::zeroed() };
                if i == 0 {
                    // SAFETY: `pkt` is live.
                    if unsafe { WPACKET_init_null_der(&mut pkt) } == 0 {
                        failed = true;
                        break;
                    }
                } else {
                    // SAFETY: `str_sz` is the length the first pass measured.
                    str = CRYPTO_malloc(str_sz, ptr::null(), 0).cast::<c_uchar>();
                    if str.is_null()
                        // SAFETY: `pkt` is live, `str` is `str_sz` writable bytes.
                        || unsafe { WPACKET_init_der(&mut pkt, str, str_sz) } == 0
                    {
                        // SAFETY: `pkt` is live or partially initialised.
                        unsafe { WPACKET_cleanup(&mut pkt) };
                        failed = true;
                        break;
                    }
                }
                // SAFETY: `pkt` is live and `pss` is the key's own.
                if unsafe { ossl_DER_w_RSASSA_PSS_params(&mut pkt, -1, pss) } == 0
                    // SAFETY: `pkt` is live.
                    || unsafe { WPACKET_finish(&mut pkt) } == 0
                    // SAFETY: `pkt` is live and `str_sz` is this frame's.
                    || unsafe { WPACKET_get_total_written(&mut pkt, &mut str_sz) } == 0
                {
                    // SAFETY: `pkt` is live.
                    unsafe { WPACKET_cleanup(&mut pkt) };
                    failed = true;
                    break;
                }
                // SAFETY: `pkt` is live.
                unsafe { WPACKET_cleanup(&mut pkt) };

                if str_sz == 0 {
                    break;
                }
            }

            if failed {
                // SAFETY: `str` is NULL or this frame's allocation.
                unsafe { CRYPTO_free(str.cast::<c_void>(), ptr::null(), 0) };
                return 0;
            }

            // SAFETY: no preconditions.
            let astr = ASN1_STRING_new();
            if astr.is_null() {
                // SAFETY: `str` is NULL or this frame's allocation.
                unsafe { CRYPTO_free(str.cast::<c_void>(), ptr::null(), 0) };
                return 0;
            }
            // SAFETY: `astr` is live; `str` is this call's allocation of `str_sz` bytes, adopted.
            unsafe {
                *pstrtype = V_ASN1_SEQUENCE;
                ASN1_STRING_set0(astr, str.cast::<c_void>(), str_sz as c_int);
                *pstr = astr.cast::<c_void>();
            }
            1
        }
        // Currently unsupported RSA key type.
        _ => 0,
    }
}

k2d_noctx!(rsa_prv_k2d, i2d_RSAPrivateKey);
k2d_noctx!(rsa_pub_k2d, i2d_RSAPublicKey);

/// `static int rsa_check_key_type(const void *rsa, int expected_type)` —
/// `encode_key2any.c:1001-1012`.
///
/// # Safety
/// `rsa` a live `RSA *`.
unsafe extern "C" fn rsa_check_key_type(rsa: *const c_void, expected_type: c_int) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    match unsafe { RSA_test_flags(rsa.cast::<Rsa>(), RSA_FLAG_TYPE_MASK) } {
        RSA_FLAG_TYPE_RSA => c_int::from(expected_type == EVP_PKEY_RSA),
        RSA_FLAG_TYPE_RSASSAPSS => c_int::from(expected_type == EVP_PKEY_RSA_PSS),
        // Currently unsupported RSA key type.
        _ => EVP_PKEY_NONE,
    }
}

/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, the "no type" answer `rsa_check_key_type`'s
/// unsupported arm produces.
const EVP_PKEY_NONE: c_int = 0;

/// `static int slh_dsa_spki_pub_to_der(const void *vkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:1024-1042`.
///
/// # Safety
/// `vkey` a live `SLH_DSA_KEY *`; `pder` writable.
unsafe extern "C" fn slh_dsa_spki_pub_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    let key = vkey.cast::<SlhDsaKey>();
    if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_1032) };
        return 0;
    }
    // SAFETY: `key` is live with params set.
    let key_len = unsafe { ossl_slh_dsa_key_get_pub_len(key) };
    // SAFETY: `key` is live; the source is `key_len` readable bytes.
    let key_blob = unsafe {
        CRYPTO_memdup(
            ossl_slh_dsa_key_get_pub(key).cast::<c_void>(),
            key_len,
            ptr::null(),
            0,
        )
    }
    .cast::<c_uchar>();
    if key_blob.is_null() {
        return 0;
    }
    // SAFETY: `pder` is the caller's cursor.
    unsafe { *pder = key_blob };
    key_len as c_int
}

/// `static int slh_dsa_pki_priv_to_der(const void *vkey, unsigned char **pder, void *ctx)` —
/// `encode_key2any.c:1044-1061` (also `slh_dsa_epki_priv_to_der`'s alias).
///
/// # Safety
/// As [`slh_dsa_spki_pub_to_der`].
unsafe extern "C" fn slh_dsa_pki_priv_to_der(
    vkey: *const c_void,
    pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    let key = vkey.cast::<SlhDsaKey>();
    // SAFETY: `key` is live.
    if unsafe { ossl_slh_dsa_key_get_priv(key) }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_1051) };
        return 0;
    }
    // SAFETY: `key` is live with params set.
    let len = unsafe { ossl_slh_dsa_key_get_priv_len(key) };

    if !pder.is_null() {
        // SAFETY: `key` is live; the source is `len` readable bytes.
        let p = unsafe {
            CRYPTO_memdup(
                ossl_slh_dsa_key_get_priv(key).cast::<c_void>(),
                len,
                ptr::null(),
                0,
            )
        }
        .cast::<c_uchar>();
        if p.is_null() {
            return 0;
        }
        // SAFETY: `pder` is the caller's cursor.
        unsafe { *pder = p };
    }
    len as c_int
}

// ---------------------------------------------------------------------------------------------
// The shared context functions — `encode_key2any.c:1107-1298`
// ---------------------------------------------------------------------------------------------

/// `static void *key2any_newctx(void *provctx)` — `encode_key2any.c:1110-1120`.
///
/// # Safety
/// The encoder `newctx` dispatch contract.
unsafe extern "C" fn key2any_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `CRYPTO_zalloc` validates its own allocation.
    let ctx = CRYPTO_zalloc(size_of::<Key2anyCtx>(), ptr::null(), 0).cast::<Key2anyCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh, writable, correctly-sized allocation.
        unsafe {
            (*ctx).provctx = provctx.cast::<ProvCtx>();
            (*ctx).save_parameters = 1;
        }
    }
    ctx.cast::<c_void>()
}

/// `static void key2any_freectx(void *vctx)` — `encode_key2any.c:1122-1129`.
///
/// # Safety
/// The encoder `freectx` dispatch contract.
unsafe extern "C" fn key2any_freectx(vctx: *mut c_void) {
    if vctx.is_null() {
        return;
    }
    let ctx = vctx.cast::<Key2anyCtx>();
    // SAFETY: `ctx` is the live context this call owns.
    unsafe {
        ossl_pw_clear_passphrase_data(ptr::addr_of_mut!((*ctx).pwdata));
        EVP_CIPHER_free((*ctx).cipher);
    }
    // SAFETY: `vctx` is this call's allocation.
    unsafe { CRYPTO_free(vctx, ptr::null(), 0) };
}

/// `OSSL_ENCODER_PARAM_CIPHER` — `core_names.h`, `"cipher"`.
const OSSL_ENCODER_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();
/// `OSSL_ENCODER_PARAM_PROPERTIES` — `core_names.h`, `"properties"`.
const OSSL_ENCODER_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `OSSL_ENCODER_PARAM_SAVE_PARAMETERS` — `core_names.h`, `"save-parameters"`.
const OSSL_ENCODER_PARAM_SAVE_PARAMETERS: *const c_char = c"save-parameters".as_ptr();

/// `key2any_set_ctx_params_list[]` — the generated settable list (`encode_key2any.c:1134-1139`).
static KEY2ANY_SET_CTX_PARAMS_LIST: [OsslParam; 4] = [
    OsslParam {
        key: OSSL_ENCODER_PARAM_CIPHER,
        data_type: OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    OsslParam {
        key: OSSL_ENCODER_PARAM_PROPERTIES,
        data_type: OSSL_PARAM_UTF8_STRING,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    OsslParam {
        key: OSSL_ENCODER_PARAM_SAVE_PARAMETERS,
        data_type: OSSL_PARAM_INTEGER,
        data: ptr::null_mut(),
        data_size: size_of::<c_int>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    },
    END,
];

/// `struct key2any_set_ctx_params_st` — `encode_key2any.c:1142-1148`.
#[repr(C)]
struct Key2anySetCtxParams {
    /// `OSSL_PARAM *cipher`.
    cipher: *const OsslParam,
    /// `OSSL_PARAM *propq`.
    propq: *const OsslParam,
    /// `OSSL_PARAM *svprm`.
    svprm: *const OsslParam,
}

/// `ERR_raise_data(ERR_LIB_PROV, PROV_R_REPEATED_PARAMETER, "param %s is repeated", s)` — the
/// generated decoder's repeated-parameter refusal (`encode_key2any.c:1166-1190`).
///
/// # Safety
/// `s` is the NUL-terminated parameter key.
unsafe fn repeated_parameter(line: c_int, s: *const c_char) {
    let mut buf = [0 as c_char; 256];
    // SAFETY: `buf` is 256 bytes, the format is NUL-terminated, and `s` is NUL-terminated.
    unsafe {
        BIO_snprintf(
            buf.as_mut_ptr(),
            buf.len(),
            c"param %s is repeated".as_ptr(),
            s,
        )
    };
    // SAFETY: a compile-time-constant site and NUL-terminated message.
    unsafe {
        raise_site_data(
            &key2any_site(
                line,
                c"key2any_set_ctx_params_decoder",
                PROV_R_REPEATED_PARAMETER,
            ),
            buf.as_ptr(),
        )
    };
}

/// `static int key2any_set_ctx_params_decoder(const OSSL_PARAM *p, struct
/// key2any_set_ctx_params_st *r)` — `encode_key2any.c:1150-1197`, the machine-generated parser.
///
/// # Safety
/// `p` NULL or a `key == NULL`-terminated array; `r` writable.
unsafe fn key2any_set_ctx_params_decoder(
    p: *const OsslParam,
    r: *mut Key2anySetCtxParams,
) -> c_int {
    // SAFETY: `r` is writable per the contract; this is the authority's `memset`.
    unsafe { ptr::write_bytes(r, 0, 1) };

    if !p.is_null() {
        let mut q = p;
        // SAFETY: `q` walks a `key == NULL`-terminated array.
        while !unsafe { (*q).key }.is_null() {
            // SAFETY: `q`'s key is NUL-terminated per the array's contract.
            let s = unsafe { (*q).key };
            // The authority's `switch (s[0])` over the three parameters.
            // SAFETY: `s` is NUL-terminated per the array's contract.
            let first = unsafe { *s } as u8;
            // SAFETY: the two arguments are NUL-terminated.
            let matched = |rest: &CStr| unsafe { strcmp(s.add(1), rest.as_ptr()) } == 0;
            match first {
                b'c' if matched(c"ipher") => {
                    // SAFETY: `r` is writable.
                    if !unsafe { (*r).cipher }.is_null() {
                        // SAFETY: `s` is NUL-terminated.
                        unsafe { repeated_parameter(1166, s) };
                        return 0;
                    }
                    // SAFETY: `r` is writable.
                    unsafe { (*r).cipher = q };
                }
                b'p' if matched(c"roperties") => {
                    // SAFETY: `r` is writable.
                    if !unsafe { (*r).propq }.is_null() {
                        // SAFETY: `s` is NUL-terminated.
                        unsafe { repeated_parameter(1177, s) };
                        return 0;
                    }
                    // SAFETY: `r` is writable.
                    unsafe { (*r).propq = q };
                }
                b's' if matched(c"ave-parameters") => {
                    // SAFETY: `r` is writable.
                    if !unsafe { (*r).svprm }.is_null() {
                        // SAFETY: `s` is NUL-terminated.
                        unsafe { repeated_parameter(1188, s) };
                        return 0;
                    }
                    // SAFETY: `r` is writable.
                    unsafe { (*r).svprm = q };
                }
                _ => {}
            }
            // SAFETY: the array is terminated, so the step stays within it.
            q = unsafe { q.add(1) };
        }
    }
    1
}

/// `static const OSSL_PARAM *key2any_settable_ctx_params(void *provctx)` —
/// `encode_key2any.c:1201-1204`.
///
/// # Safety
/// The encoder `settable_ctx_params` dispatch contract.
unsafe extern "C" fn key2any_settable_ctx_params(_provctx: *mut c_void) -> *const OsslParam {
    KEY2ANY_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int key2any_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `encode_key2any.c:1206-1237`, over the generated decoder.
///
/// # Safety
/// The encoder `set_ctx_params` dispatch contract.
unsafe extern "C" fn key2any_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<Key2anyCtx>();
    let mut p = Key2anySetCtxParams {
        cipher: ptr::null(),
        propq: ptr::null(),
        svprm: ptr::null(),
    };

    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live, `params` is the caller's, and `p` is this frame's.
    if unsafe { key2any_set_ctx_params_decoder(params, &mut p) } == 0 {
        return 0;
    }

    if !p.cipher.is_null() {
        let mut ciphername: *const c_char = ptr::null();
        let mut props: *const c_char = ptr::null();

        // SAFETY: `p.cipher` is live and `ciphername` is this frame's.
        if unsafe { OSSL_PARAM_get_utf8_string_ptr(p.cipher, &mut ciphername) } == 0 {
            return 0;
        }
        if !p.propq.is_null()
            // SAFETY: `p.propq` is live and `props` is this frame's.
            && unsafe { OSSL_PARAM_get_utf8_string_ptr(p.propq, &mut props) } == 0
        {
            return 0;
        }

        // SAFETY: `ctx` is live.
        let libctx = unsafe { ossl_prov_ctx_get0_libctx((*ctx).provctx) };
        // SAFETY: `ctx` is live; the previous cipher is released.
        unsafe {
            EVP_CIPHER_free((*ctx).cipher);
            (*ctx).cipher = ptr::null_mut();
            (*ctx).cipher_intent = c_int::from(!ciphername.is_null());
        }
        if !ciphername.is_null() {
            // SAFETY: the strings are NUL-terminated and `libctx` is the provider's.
            unsafe { (*ctx).cipher = EVP_CIPHER_fetch(libctx, ciphername, props) };
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).cipher }.is_null() {
                return 0;
            }
        }
    }

    if !p.svprm.is_null()
        // SAFETY: `p.svprm` is live and `ctx` is live.
        && unsafe { OSSL_PARAM_get_int(p.svprm, &mut (*ctx).save_parameters) } == 0
    {
        return 0;
    }

    1
}

/// `static int key2any_check_selection(int selection, int selection_mask)` —
/// `encode_key2any.c:1239-1270`.
///
/// The selections are levels: the first of the three the caller asks for is answered by whether
/// the row's mask carries it, and an empty selection is accepted so the caller may guess.
fn key2any_check_selection(selection: c_int, selection_mask: c_int) -> c_int {
    let checks = [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    ];

    if selection == 0 {
        return 1;
    }
    for check in checks {
        let check1 = (selection & check) != 0;
        let check2 = (selection_mask & check) != 0;
        if check1 {
            return c_int::from(check2);
        }
    }
    0
}

/// `static int key2any_encode(KEY2ANY_CTX *ctx, OSSL_CORE_BIO *cout, const void *key, int type,
/// const char *pemname, check_key_type_fn *checker, key_to_der_fn *writer,
/// OSSL_PASSPHRASE_CALLBACK *pwcb, void *pwcbarg, key_to_paramstring_fn *key2paramstring,
/// OSSL_i2d_of_void_ctx *key2der)` — `encode_key2any.c:1272-1298`.
///
/// # Safety
/// Every argument is the row's own per the encoder `encode` contract.
unsafe fn key2any_encode(
    ctx: *mut Key2anyCtx,
    cout: *mut c_void,
    key: *const c_void,
    type_: c_int,
    pemname: *const c_char,
    checker: Option<unsafe extern "C" fn(*const c_void, c_int) -> c_int>,
    writer: Option<KeyToDerFn>,
    pwcb: Option<OsslPassphraseCallback>,
    pwcbarg: *mut c_void,
    key2paramstring: Option<KeyToParamstringFn>,
    key2der: OsslI2dOfVoidCtx,
) -> c_int {
    let mut ret = 0;

    if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&KEY2ANY_1283) };
    } else {
        // SAFETY: `checker` is the row's own per the contract.
        let check_ok = writer.is_some()
            && match checker {
                None => true,
                Some(c) => {
                    // SAFETY: `checker` is the row's own per the contract.
                    let ok = unsafe { c(key, type_) };
                    ok != 0
                }
            };
        if check_ok {
            // SAFETY: `cout` is the core BIO the framework wrapped.
            let out = unsafe { ossl_bio_new_from_core_bio(cout.cast()) };
            if !out.is_null() {
                // SAFETY: `ctx` is live and `cb`/`cbarg` are the caller's.
                let pw_ok = match pwcb {
                    Some(cb) => {
                        // SAFETY: `ctx` is live and `cb`/`pwcbarg` are the caller's.
                        let rc = unsafe {
                            ossl_pw_set_ossl_passphrase_cb(
                                ptr::addr_of_mut!((*ctx).pwdata),
                                Some(cb),
                                pwcbarg,
                            )
                        };
                        rc != 0
                    }
                    None => true,
                };
                if pw_ok {
                    // `check_ok` above proves `writer` is `Some`.
                    if let Some(w) = writer {
                        // SAFETY: `out` is live and every argument is the row's own.
                        ret = unsafe { w(out, key, type_, pemname, key2paramstring, key2der, ctx) };
                    }
                }
            }
            // SAFETY: `out` is live and this call owns the reference the bridge took.
            unsafe { BIO_free(out) };
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&KEY2ANY_1295) };
        }
    }
    ret
}

// ---------------------------------------------------------------------------------------------
// The 208 `MAKE_ENCODER` expansions — `encode_key2any.c:1538-1819`
// ---------------------------------------------------------------------------------------------

/// The six selection masks the `DO_##kind##_selection_mask` macros reduce to
/// (`encode_key2any.c:1300-1448`).
const MASK_PRIV: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const MASK_PUB: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const MASK_PARAMS: c_int = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
const MASK_KEYPAIR: c_int = MASK_PRIV | MASK_PUB;
const MASK_ALL: c_int = MASK_PRIV | MASK_PUB | MASK_PARAMS;
const MASK_NO_PUB: c_int = MASK_PRIV | MASK_PARAMS;

/// The DER producer a table arm that has no producer passes; it is never called, because the arm
/// it belongs to is unreachable under its row's selection mask.
unsafe extern "C" fn key2any_unused_k2d(
    _key: *const c_void,
    _pder: *mut *mut c_uchar,
    _ctx: *mut c_void,
) -> c_int {
    0
}

/// One `MAKE_ENCODER(impl, type, kind, output)` expansion (`encode_key2any.c:1467-1532`).
///
/// The generated names follow the macro's own substitution: five idents (the four functions and
/// the table) mirror `impl##_to_##kind##_##output##_*`, `$func` is the generated `encode`'s own
/// name for the two raise coordinates in its body, and the eight expression arguments are the
/// resolved `DO_##kind` pieces — the EVP type, the three `(writer, k2d)` arms, and the type's
/// `checker`/`key2paramstring`.
macro_rules! make_encoder {
    (
        $encode:ident, $import:ident, $free:ident, $does:ident, $table:ident, $func:expr,
        $evp:expr, $pem:literal, $keymgmt:path, $mask:expr,
        $checker:expr, $p2s:expr,
        $wpriv:expr, $kpriv:expr,
        $wpub:expr, $kpub:expr,
        $wparam:expr, $kparam:expr,
    ) => {
        /// `import_object` — `ossl_prov_import_key(<keymgmt>, ctx, selection, params)`.
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

        /// `does_selection` — `key2any_check_selection(selection, $mask)`.
        ///
        /// # Safety
        /// The encoder `does_selection` dispatch contract.
        unsafe extern "C" fn $does(_ctx: *mut c_void, selection: c_int) -> c_int {
            key2any_check_selection(selection, $mask)
        }

        /// `encode` — the macro's generated body: refuse an abstract object, then run the shared
        /// engine over the first selection level the row supports.
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
                unsafe { raise_site(&key2any_site(1504, $func, ERR_R_PASSED_INVALID_ARGUMENT)) };
                return 0;
            }
            let ctx = vctx.cast::<Key2anyCtx>();
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                // SAFETY: the encoder contract is the caller's; the engine is this unit's own.
                return unsafe {
                    key2any_encode(
                        ctx,
                        cout,
                        key,
                        $evp,
                        concat!($pem, " PRIVATE KEY\0").as_ptr().cast::<c_char>(),
                        $checker,
                        $wpriv,
                        cb,
                        cbarg,
                        $p2s,
                        $kpriv,
                    )
                };
            }
            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                // SAFETY: as above.
                return unsafe {
                    key2any_encode(
                        ctx,
                        cout,
                        key,
                        $evp,
                        concat!($pem, " PUBLIC KEY\0").as_ptr().cast::<c_char>(),
                        $checker,
                        $wpub,
                        cb,
                        cbarg,
                        $p2s,
                        $kpub,
                    )
                };
            }
            if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 {
                // SAFETY: as above, with the parameters arm's NULL callback.
                return unsafe {
                    key2any_encode(
                        ctx,
                        cout,
                        key,
                        $evp,
                        concat!($pem, " PARAMETERS\0").as_ptr().cast::<c_char>(),
                        $checker,
                        $wparam,
                        None,
                        ptr::null_mut(),
                        None,
                        $kparam,
                    )
                };
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&key2any_site(1509, $func, ERR_R_PASSED_INVALID_ARGUMENT)) };
            0
        }

        // The table carries the eight dispatch slots the authority's `MAKE_ENCODER` array does,
        // in its order (`encode_key2any.c:1515-1531`), plus the terminator.
        #[allow(dead_code)] // the two SM2-structure expansions are transcribed but unregistered
        pub(crate) static $table: [OsslDispatch; 9] = [
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_NEWCTX,
                function: key2any_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREECTX,
                function: key2any_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                function: key2any_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
                function: key2any_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_DOES_SELECTION,
                function: $does as *mut c_void,
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

/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `include/openssl/evp.h:105`, the domain-or-other pair.
/// The crate keeps no shared constant for it, so it is spelled here from the two halves.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

// One `make_encoder!` expansion per authority `MAKE_ENCODER` line, in the
// authority's order (`encode_key2any.c:1538-1819`). The two `sm2`/`SM2`-structure
// expansions are transcribed and left unregistered, as the module doc says.
make_encoder!(
    rsa_to_type_specific_keypair_der_encode,
    rsa_to_type_specific_keypair_der_import_object,
    rsa_to_type_specific_keypair_der_free_object,
    rsa_to_type_specific_keypair_der_does_selection,
    RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER_FUNCTIONS,
    c"rsa_to_type_specific_keypair_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_der_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_type_specific_params_der_encode,
    dh_to_type_specific_params_der_import_object,
    dh_to_type_specific_params_der_free_object,
    dh_to_type_specific_params_der_does_selection,
    DH_TO_TYPE_SPECIFIC_PARAMS_DER_FUNCTIONS,
    c"dh_to_type_specific_params_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_type_specific_params_der_encode,
    dhx_to_type_specific_params_der_import_object,
    dhx_to_type_specific_params_der_free_object,
    dhx_to_type_specific_params_der_does_selection,
    DHX_TO_TYPE_SPECIFIC_PARAMS_DER_FUNCTIONS,
    c"dhx_to_type_specific_params_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dsa_to_type_specific_der_encode,
    dsa_to_type_specific_der_import_object,
    dsa_to_type_specific_der_free_object,
    dsa_to_type_specific_der_does_selection,
    DSA_TO_TYPE_SPECIFIC_DER_FUNCTIONS,
    c"dsa_to_type_specific_der_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_ALL,
    None,
    Some(prepare_dsa_params),
    Some(key_to_type_specific_der_bio),
    dsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    dsa_pub_k2d,
    Some(key_to_type_specific_der_bio),
    dsa_param_k2d,
);
make_encoder!(
    ec_to_type_specific_no_pub_der_encode,
    ec_to_type_specific_no_pub_der_import_object,
    ec_to_type_specific_no_pub_der_free_object,
    ec_to_type_specific_no_pub_der_does_selection,
    EC_TO_TYPE_SPECIFIC_NO_PUB_DER_FUNCTIONS,
    c"ec_to_type_specific_no_pub_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_der_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    ec_param_k2d,
);
make_encoder!(
    sm2_to_type_specific_no_pub_der_encode,
    sm2_to_type_specific_no_pub_der_import_object,
    sm2_to_type_specific_no_pub_der_free_object,
    sm2_to_type_specific_no_pub_der_does_selection,
    SM2_TO_TYPE_SPECIFIC_NO_PUB_DER_FUNCTIONS,
    c"sm2_to_type_specific_no_pub_der_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_der_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    ec_param_k2d,
);
make_encoder!(
    rsa_to_type_specific_keypair_pem_encode,
    rsa_to_type_specific_keypair_pem_import_object,
    rsa_to_type_specific_keypair_pem_free_object,
    rsa_to_type_specific_keypair_pem_does_selection,
    RSA_TO_TYPE_SPECIFIC_KEYPAIR_PEM_FUNCTIONS,
    c"rsa_to_type_specific_keypair_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_type_specific_params_pem_encode,
    dh_to_type_specific_params_pem_import_object,
    dh_to_type_specific_params_pem_free_object,
    dh_to_type_specific_params_pem_does_selection,
    DH_TO_TYPE_SPECIFIC_PARAMS_PEM_FUNCTIONS,
    c"dh_to_type_specific_params_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_type_specific_params_pem_encode,
    dhx_to_type_specific_params_pem_import_object,
    dhx_to_type_specific_params_pem_free_object,
    dhx_to_type_specific_params_pem_does_selection,
    DHX_TO_TYPE_SPECIFIC_PARAMS_PEM_FUNCTIONS,
    c"dhx_to_type_specific_params_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dsa_to_type_specific_pem_encode,
    dsa_to_type_specific_pem_import_object,
    dsa_to_type_specific_pem_free_object,
    dsa_to_type_specific_pem_does_selection,
    DSA_TO_TYPE_SPECIFIC_PEM_FUNCTIONS,
    c"dsa_to_type_specific_pem_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_ALL,
    None,
    Some(prepare_dsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    dsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    dsa_pub_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dsa_param_k2d,
);
make_encoder!(
    ec_to_type_specific_no_pub_pem_encode,
    ec_to_type_specific_no_pub_pem_import_object,
    ec_to_type_specific_no_pub_pem_free_object,
    ec_to_type_specific_no_pub_pem_does_selection,
    EC_TO_TYPE_SPECIFIC_NO_PUB_PEM_FUNCTIONS,
    c"ec_to_type_specific_no_pub_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_pem_priv_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    ec_param_k2d,
);
make_encoder!(
    sm2_to_type_specific_no_pub_pem_encode,
    sm2_to_type_specific_no_pub_pem_import_object,
    sm2_to_type_specific_no_pub_pem_free_object,
    sm2_to_type_specific_no_pub_pem_does_selection,
    SM2_TO_TYPE_SPECIFIC_NO_PUB_PEM_FUNCTIONS,
    c"sm2_to_type_specific_no_pub_pem_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_pem_priv_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    ec_param_k2d,
);
make_encoder!(
    rsa_to_EncryptedPrivateKeyInfo_der_encode,
    rsa_to_EncryptedPrivateKeyInfo_der_import_object,
    rsa_to_EncryptedPrivateKeyInfo_der_free_object,
    rsa_to_EncryptedPrivateKeyInfo_der_does_selection,
    RSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"rsa_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_epki_der_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_EncryptedPrivateKeyInfo_pem_encode,
    rsa_to_EncryptedPrivateKeyInfo_pem_import_object,
    rsa_to_EncryptedPrivateKeyInfo_pem_free_object,
    rsa_to_EncryptedPrivateKeyInfo_pem_does_selection,
    RSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"rsa_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_epki_pem_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_PrivateKeyInfo_der_encode,
    rsa_to_PrivateKeyInfo_der_import_object,
    rsa_to_PrivateKeyInfo_der_free_object,
    rsa_to_PrivateKeyInfo_der_does_selection,
    RSA_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"rsa_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_pki_der_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_PrivateKeyInfo_pem_encode,
    rsa_to_PrivateKeyInfo_pem_import_object,
    rsa_to_PrivateKeyInfo_pem_free_object,
    rsa_to_PrivateKeyInfo_pem_does_selection,
    RSA_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"rsa_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_pki_pem_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_SubjectPublicKeyInfo_der_encode,
    rsa_to_SubjectPublicKeyInfo_der_import_object,
    rsa_to_SubjectPublicKeyInfo_der_free_object,
    rsa_to_SubjectPublicKeyInfo_der_does_selection,
    RSA_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"rsa_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_SubjectPublicKeyInfo_pem_encode,
    rsa_to_SubjectPublicKeyInfo_pem_import_object,
    rsa_to_SubjectPublicKeyInfo_pem_free_object,
    rsa_to_SubjectPublicKeyInfo_pem_does_selection,
    RSA_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"rsa_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_EncryptedPrivateKeyInfo_der_encode,
    rsapss_to_EncryptedPrivateKeyInfo_der_import_object,
    rsapss_to_EncryptedPrivateKeyInfo_der_free_object,
    rsapss_to_EncryptedPrivateKeyInfo_der_does_selection,
    RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"rsapss_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_epki_der_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_EncryptedPrivateKeyInfo_pem_encode,
    rsapss_to_EncryptedPrivateKeyInfo_pem_import_object,
    rsapss_to_EncryptedPrivateKeyInfo_pem_free_object,
    rsapss_to_EncryptedPrivateKeyInfo_pem_does_selection,
    RSAPSS_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"rsapss_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_epki_pem_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_PrivateKeyInfo_der_encode,
    rsapss_to_PrivateKeyInfo_der_import_object,
    rsapss_to_PrivateKeyInfo_der_free_object,
    rsapss_to_PrivateKeyInfo_der_does_selection,
    RSAPSS_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"rsapss_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_pki_der_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_PrivateKeyInfo_pem_encode,
    rsapss_to_PrivateKeyInfo_pem_import_object,
    rsapss_to_PrivateKeyInfo_pem_free_object,
    rsapss_to_PrivateKeyInfo_pem_does_selection,
    RSAPSS_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"rsapss_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_pki_pem_priv_bio),
    rsa_prv_k2d,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_SubjectPublicKeyInfo_der_encode,
    rsapss_to_SubjectPublicKeyInfo_der_import_object,
    rsapss_to_SubjectPublicKeyInfo_der_free_object,
    rsapss_to_SubjectPublicKeyInfo_der_does_selection,
    RSAPSS_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"rsapss_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_SubjectPublicKeyInfo_pem_encode,
    rsapss_to_SubjectPublicKeyInfo_pem_import_object,
    rsapss_to_SubjectPublicKeyInfo_pem_free_object,
    rsapss_to_SubjectPublicKeyInfo_pem_does_selection,
    RSAPSS_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"rsapss_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_EncryptedPrivateKeyInfo_der_encode,
    dh_to_EncryptedPrivateKeyInfo_der_import_object,
    dh_to_EncryptedPrivateKeyInfo_der_free_object,
    dh_to_EncryptedPrivateKeyInfo_der_does_selection,
    DH_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"dh_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_epki_der_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_EncryptedPrivateKeyInfo_pem_encode,
    dh_to_EncryptedPrivateKeyInfo_pem_import_object,
    dh_to_EncryptedPrivateKeyInfo_pem_free_object,
    dh_to_EncryptedPrivateKeyInfo_pem_does_selection,
    DH_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dh_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_epki_pem_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_PrivateKeyInfo_der_encode,
    dh_to_PrivateKeyInfo_der_import_object,
    dh_to_PrivateKeyInfo_der_free_object,
    dh_to_PrivateKeyInfo_der_does_selection,
    DH_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"dh_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_pki_der_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_PrivateKeyInfo_pem_encode,
    dh_to_PrivateKeyInfo_pem_import_object,
    dh_to_PrivateKeyInfo_pem_free_object,
    dh_to_PrivateKeyInfo_pem_does_selection,
    DH_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dh_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_pki_pem_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_SubjectPublicKeyInfo_der_encode,
    dh_to_SubjectPublicKeyInfo_der_import_object,
    dh_to_SubjectPublicKeyInfo_der_free_object,
    dh_to_SubjectPublicKeyInfo_der_does_selection,
    DH_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"dh_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    dh_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_SubjectPublicKeyInfo_pem_encode,
    dh_to_SubjectPublicKeyInfo_pem_import_object,
    dh_to_SubjectPublicKeyInfo_pem_free_object,
    dh_to_SubjectPublicKeyInfo_pem_does_selection,
    DH_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"dh_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    dh_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_EncryptedPrivateKeyInfo_der_encode,
    dhx_to_EncryptedPrivateKeyInfo_der_import_object,
    dhx_to_EncryptedPrivateKeyInfo_der_free_object,
    dhx_to_EncryptedPrivateKeyInfo_der_does_selection,
    DHX_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"dhx_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_epki_der_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_EncryptedPrivateKeyInfo_pem_encode,
    dhx_to_EncryptedPrivateKeyInfo_pem_import_object,
    dhx_to_EncryptedPrivateKeyInfo_pem_free_object,
    dhx_to_EncryptedPrivateKeyInfo_pem_does_selection,
    DHX_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dhx_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_epki_pem_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_PrivateKeyInfo_der_encode,
    dhx_to_PrivateKeyInfo_der_import_object,
    dhx_to_PrivateKeyInfo_der_free_object,
    dhx_to_PrivateKeyInfo_der_does_selection,
    DHX_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"dhx_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_pki_der_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_PrivateKeyInfo_pem_encode,
    dhx_to_PrivateKeyInfo_pem_import_object,
    dhx_to_PrivateKeyInfo_pem_free_object,
    dhx_to_PrivateKeyInfo_pem_does_selection,
    DHX_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dhx_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    Some(key_to_pki_pem_priv_bio),
    dh_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_SubjectPublicKeyInfo_der_encode,
    dhx_to_SubjectPublicKeyInfo_der_import_object,
    dhx_to_SubjectPublicKeyInfo_der_free_object,
    dhx_to_SubjectPublicKeyInfo_der_does_selection,
    DHX_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"dhx_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    dh_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dhx_to_SubjectPublicKeyInfo_pem_encode,
    dhx_to_SubjectPublicKeyInfo_pem_import_object,
    dhx_to_SubjectPublicKeyInfo_pem_free_object,
    dhx_to_SubjectPublicKeyInfo_pem_does_selection,
    DHX_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"dhx_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    dh_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_EncryptedPrivateKeyInfo_der_encode,
    dsa_to_EncryptedPrivateKeyInfo_der_import_object,
    dsa_to_EncryptedPrivateKeyInfo_der_free_object,
    dsa_to_EncryptedPrivateKeyInfo_der_does_selection,
    DSA_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"dsa_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_dsa_params),
    Some(key_to_epki_der_priv_bio),
    dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_EncryptedPrivateKeyInfo_pem_encode,
    dsa_to_EncryptedPrivateKeyInfo_pem_import_object,
    dsa_to_EncryptedPrivateKeyInfo_pem_free_object,
    dsa_to_EncryptedPrivateKeyInfo_pem_does_selection,
    DSA_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dsa_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_dsa_params),
    Some(key_to_epki_pem_priv_bio),
    dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_PrivateKeyInfo_der_encode,
    dsa_to_PrivateKeyInfo_der_import_object,
    dsa_to_PrivateKeyInfo_der_free_object,
    dsa_to_PrivateKeyInfo_der_does_selection,
    DSA_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"dsa_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_dsa_params),
    Some(key_to_pki_der_priv_bio),
    dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_PrivateKeyInfo_pem_encode,
    dsa_to_PrivateKeyInfo_pem_import_object,
    dsa_to_PrivateKeyInfo_pem_free_object,
    dsa_to_PrivateKeyInfo_pem_does_selection,
    DSA_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"dsa_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_dsa_params),
    Some(key_to_pki_pem_priv_bio),
    dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_SubjectPublicKeyInfo_der_encode,
    dsa_to_SubjectPublicKeyInfo_der_import_object,
    dsa_to_SubjectPublicKeyInfo_der_free_object,
    dsa_to_SubjectPublicKeyInfo_der_does_selection,
    DSA_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"dsa_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_dsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dsa_to_SubjectPublicKeyInfo_pem_encode,
    dsa_to_SubjectPublicKeyInfo_pem_import_object,
    dsa_to_SubjectPublicKeyInfo_pem_free_object,
    dsa_to_SubjectPublicKeyInfo_pem_does_selection,
    DSA_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"dsa_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_dsa_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_EncryptedPrivateKeyInfo_der_encode,
    ec_to_EncryptedPrivateKeyInfo_der_import_object,
    ec_to_EncryptedPrivateKeyInfo_der_free_object,
    ec_to_EncryptedPrivateKeyInfo_der_does_selection,
    EC_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ec_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_epki_der_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_EncryptedPrivateKeyInfo_pem_encode,
    ec_to_EncryptedPrivateKeyInfo_pem_import_object,
    ec_to_EncryptedPrivateKeyInfo_pem_free_object,
    ec_to_EncryptedPrivateKeyInfo_pem_does_selection,
    EC_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ec_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_epki_pem_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_PrivateKeyInfo_der_encode,
    ec_to_PrivateKeyInfo_der_import_object,
    ec_to_PrivateKeyInfo_der_free_object,
    ec_to_PrivateKeyInfo_der_does_selection,
    EC_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ec_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_pki_der_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_PrivateKeyInfo_pem_encode,
    ec_to_PrivateKeyInfo_pem_import_object,
    ec_to_PrivateKeyInfo_pem_free_object,
    ec_to_PrivateKeyInfo_pem_does_selection,
    EC_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ec_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_pki_pem_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_SubjectPublicKeyInfo_der_encode,
    ec_to_SubjectPublicKeyInfo_der_import_object,
    ec_to_SubjectPublicKeyInfo_der_free_object,
    ec_to_SubjectPublicKeyInfo_der_does_selection,
    EC_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ec_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_ec_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ec_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ec_to_SubjectPublicKeyInfo_pem_encode,
    ec_to_SubjectPublicKeyInfo_pem_import_object,
    ec_to_SubjectPublicKeyInfo_pem_free_object,
    ec_to_SubjectPublicKeyInfo_pem_does_selection,
    EC_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ec_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_ec_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ec_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_EncryptedPrivateKeyInfo_der_encode,
    sm2_to_EncryptedPrivateKeyInfo_der_import_object,
    sm2_to_EncryptedPrivateKeyInfo_der_free_object,
    sm2_to_EncryptedPrivateKeyInfo_der_does_selection,
    SM2_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"sm2_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_epki_der_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_EncryptedPrivateKeyInfo_pem_encode,
    sm2_to_EncryptedPrivateKeyInfo_pem_import_object,
    sm2_to_EncryptedPrivateKeyInfo_pem_free_object,
    sm2_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SM2_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"sm2_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_epki_pem_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_PrivateKeyInfo_der_encode,
    sm2_to_PrivateKeyInfo_der_import_object,
    sm2_to_PrivateKeyInfo_der_free_object,
    sm2_to_PrivateKeyInfo_der_does_selection,
    SM2_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"sm2_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_pki_der_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_PrivateKeyInfo_pem_encode,
    sm2_to_PrivateKeyInfo_pem_import_object,
    sm2_to_PrivateKeyInfo_pem_free_object,
    sm2_to_PrivateKeyInfo_pem_does_selection,
    SM2_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"sm2_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    Some(prepare_ec_params),
    Some(key_to_pki_pem_priv_bio),
    ec_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_SubjectPublicKeyInfo_der_encode,
    sm2_to_SubjectPublicKeyInfo_der_import_object,
    sm2_to_SubjectPublicKeyInfo_der_free_object,
    sm2_to_SubjectPublicKeyInfo_der_does_selection,
    SM2_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"sm2_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_ec_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ec_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    sm2_to_SubjectPublicKeyInfo_pem_encode,
    sm2_to_SubjectPublicKeyInfo_pem_import_object,
    sm2_to_SubjectPublicKeyInfo_pem_free_object,
    sm2_to_SubjectPublicKeyInfo_pem_does_selection,
    SM2_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"sm2_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    Some(prepare_ec_params),
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ec_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_EncryptedPrivateKeyInfo_der_encode,
    ed25519_to_EncryptedPrivateKeyInfo_der_import_object,
    ed25519_to_EncryptedPrivateKeyInfo_der_free_object,
    ed25519_to_EncryptedPrivateKeyInfo_der_does_selection,
    ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ed25519_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_EncryptedPrivateKeyInfo_pem_encode,
    ed25519_to_EncryptedPrivateKeyInfo_pem_import_object,
    ed25519_to_EncryptedPrivateKeyInfo_pem_free_object,
    ed25519_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ED25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ed25519_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_PrivateKeyInfo_der_encode,
    ed25519_to_PrivateKeyInfo_der_import_object,
    ed25519_to_PrivateKeyInfo_der_free_object,
    ed25519_to_PrivateKeyInfo_der_does_selection,
    ED25519_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ed25519_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_PrivateKeyInfo_pem_encode,
    ed25519_to_PrivateKeyInfo_pem_import_object,
    ed25519_to_PrivateKeyInfo_pem_free_object,
    ed25519_to_PrivateKeyInfo_pem_does_selection,
    ED25519_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ed25519_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_SubjectPublicKeyInfo_der_encode,
    ed25519_to_SubjectPublicKeyInfo_der_import_object,
    ed25519_to_SubjectPublicKeyInfo_der_free_object,
    ed25519_to_SubjectPublicKeyInfo_der_does_selection,
    ED25519_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ed25519_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed25519_to_SubjectPublicKeyInfo_pem_encode,
    ed25519_to_SubjectPublicKeyInfo_pem_import_object,
    ed25519_to_SubjectPublicKeyInfo_pem_free_object,
    ed25519_to_SubjectPublicKeyInfo_pem_does_selection,
    ED25519_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ed25519_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ED25519,
    "ED25519",
    crate::provider::ecx_kmgmt::ED25519_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_EncryptedPrivateKeyInfo_der_encode,
    ed448_to_EncryptedPrivateKeyInfo_der_import_object,
    ed448_to_EncryptedPrivateKeyInfo_der_free_object,
    ed448_to_EncryptedPrivateKeyInfo_der_does_selection,
    ED448_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ed448_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_EncryptedPrivateKeyInfo_pem_encode,
    ed448_to_EncryptedPrivateKeyInfo_pem_import_object,
    ed448_to_EncryptedPrivateKeyInfo_pem_free_object,
    ed448_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ED448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ed448_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_PrivateKeyInfo_der_encode,
    ed448_to_PrivateKeyInfo_der_import_object,
    ed448_to_PrivateKeyInfo_der_free_object,
    ed448_to_PrivateKeyInfo_der_does_selection,
    ED448_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ed448_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_PrivateKeyInfo_pem_encode,
    ed448_to_PrivateKeyInfo_pem_import_object,
    ed448_to_PrivateKeyInfo_pem_free_object,
    ed448_to_PrivateKeyInfo_pem_does_selection,
    ED448_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ed448_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_SubjectPublicKeyInfo_der_encode,
    ed448_to_SubjectPublicKeyInfo_der_import_object,
    ed448_to_SubjectPublicKeyInfo_der_free_object,
    ed448_to_SubjectPublicKeyInfo_der_does_selection,
    ED448_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ed448_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ed448_to_SubjectPublicKeyInfo_pem_encode,
    ed448_to_SubjectPublicKeyInfo_pem_import_object,
    ed448_to_SubjectPublicKeyInfo_pem_free_object,
    ed448_to_SubjectPublicKeyInfo_pem_does_selection,
    ED448_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ed448_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ED448,
    "ED448",
    crate::provider::ecx_kmgmt::ED448_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_EncryptedPrivateKeyInfo_der_encode,
    x25519_to_EncryptedPrivateKeyInfo_der_import_object,
    x25519_to_EncryptedPrivateKeyInfo_der_free_object,
    x25519_to_EncryptedPrivateKeyInfo_der_does_selection,
    X25519_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"x25519_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_EncryptedPrivateKeyInfo_pem_encode,
    x25519_to_EncryptedPrivateKeyInfo_pem_import_object,
    x25519_to_EncryptedPrivateKeyInfo_pem_free_object,
    x25519_to_EncryptedPrivateKeyInfo_pem_does_selection,
    X25519_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"x25519_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_PrivateKeyInfo_der_encode,
    x25519_to_PrivateKeyInfo_der_import_object,
    x25519_to_PrivateKeyInfo_der_free_object,
    x25519_to_PrivateKeyInfo_der_does_selection,
    X25519_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"x25519_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_PrivateKeyInfo_pem_encode,
    x25519_to_PrivateKeyInfo_pem_import_object,
    x25519_to_PrivateKeyInfo_pem_free_object,
    x25519_to_PrivateKeyInfo_pem_does_selection,
    X25519_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"x25519_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_SubjectPublicKeyInfo_der_encode,
    x25519_to_SubjectPublicKeyInfo_der_import_object,
    x25519_to_SubjectPublicKeyInfo_der_free_object,
    x25519_to_SubjectPublicKeyInfo_der_does_selection,
    X25519_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"x25519_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x25519_to_SubjectPublicKeyInfo_pem_encode,
    x25519_to_SubjectPublicKeyInfo_pem_import_object,
    x25519_to_SubjectPublicKeyInfo_pem_free_object,
    x25519_to_SubjectPublicKeyInfo_pem_does_selection,
    X25519_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"x25519_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_X25519,
    "X25519",
    crate::provider::ecx_kmgmt::X25519_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_EncryptedPrivateKeyInfo_der_encode,
    x448_to_EncryptedPrivateKeyInfo_der_import_object,
    x448_to_EncryptedPrivateKeyInfo_der_free_object,
    x448_to_EncryptedPrivateKeyInfo_der_does_selection,
    X448_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"x448_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_EncryptedPrivateKeyInfo_pem_encode,
    x448_to_EncryptedPrivateKeyInfo_pem_import_object,
    x448_to_EncryptedPrivateKeyInfo_pem_free_object,
    x448_to_EncryptedPrivateKeyInfo_pem_does_selection,
    X448_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"x448_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_PrivateKeyInfo_der_encode,
    x448_to_PrivateKeyInfo_der_import_object,
    x448_to_PrivateKeyInfo_der_free_object,
    x448_to_PrivateKeyInfo_der_does_selection,
    X448_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"x448_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_PrivateKeyInfo_pem_encode,
    x448_to_PrivateKeyInfo_pem_import_object,
    x448_to_PrivateKeyInfo_pem_free_object,
    x448_to_PrivateKeyInfo_pem_does_selection,
    X448_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"x448_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ecx_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_SubjectPublicKeyInfo_der_encode,
    x448_to_SubjectPublicKeyInfo_der_import_object,
    x448_to_SubjectPublicKeyInfo_der_free_object,
    x448_to_SubjectPublicKeyInfo_der_does_selection,
    X448_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"x448_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    x448_to_SubjectPublicKeyInfo_pem_encode,
    x448_to_SubjectPublicKeyInfo_pem_import_object,
    x448_to_SubjectPublicKeyInfo_pem_free_object,
    x448_to_SubjectPublicKeyInfo_pem_does_selection,
    X448_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"x448_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_X448,
    "X448",
    crate::provider::ecx_kmgmt::X448_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ecx_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_der_encode,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_der_import_object,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_der_free_object,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256S_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256s_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_pem_encode,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_pem_import_object,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_pem_free_object,
    slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256F_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256f_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_PrivateKeyInfo_der_encode,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_128s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_128f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_192s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_192f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_256s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_sha2_256f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_128s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_128s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_128s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_128f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_128f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_128f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_192s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_192s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_192s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_192f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_192f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_192f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_256s_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_256s_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_256s_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256s_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_PrivateKeyInfo_der_encode,
    slh_dsa_shake_256f_to_PrivateKeyInfo_der_import_object,
    slh_dsa_shake_256f_to_PrivateKeyInfo_der_free_object,
    slh_dsa_shake_256f_to_PrivateKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256f_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_128s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_128s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_128s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_128f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_128f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_128f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_192s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_192s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_192s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_192f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_192f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_192f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_256s_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_256s_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_256s_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256S_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256s_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_PrivateKeyInfo_pem_encode,
    slh_dsa_shake_256f_to_PrivateKeyInfo_pem_import_object,
    slh_dsa_shake_256f_to_PrivateKeyInfo_pem_free_object,
    slh_dsa_shake_256f_to_PrivateKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256F_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256f_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    slh_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_128F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_128f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_128F,
    "SLH-DSA-SHA2-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_128F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192S,
    "SLH-DSA-SHA2-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_192F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_192f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_192F,
    "SLH-DSA-SHA2-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_192F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256S,
    "SLH-DSA-SHA2-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHA2_256F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_sha2_256f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHA2_256F,
    "SLH-DSA-SHA2-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHA2_256F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_128f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_192f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256s_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_der_encode,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_der_import_object,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_der_free_object,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_der_does_selection,
    SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"slh_dsa_shake_256f_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_128s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_128f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_128F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_128f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_128F,
    "SLH-DSA-SHAKE-128f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_128F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_192s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192S,
    "SLH-DSA-SHAKE-192s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_192f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_192F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_192f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_192F,
    "SLH-DSA-SHAKE-192f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_192F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_256s_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256S_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256s_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256S,
    "SLH-DSA-SHAKE-256s",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256S_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_pem_encode,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_pem_import_object,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_pem_free_object,
    slh_dsa_shake_256f_to_SubjectPublicKeyInfo_pem_does_selection,
    SLH_DSA_SHAKE_256F_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"slh_dsa_shake_256f_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_SLH_DSA_SHAKE_256F,
    "SLH-DSA-SHAKE-256f",
    crate::provider::slh_dsa_kmgmt::SLH_DSA_SHAKE_256F_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    slh_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_EncryptedPrivateKeyInfo_der_encode,
    ml_kem_512_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_kem_512_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_kem_512_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_512_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_kem_512_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_kem_512_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_kem_512_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_KEM_512_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_512_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_PrivateKeyInfo_der_encode,
    ml_kem_512_to_PrivateKeyInfo_der_import_object,
    ml_kem_512_to_PrivateKeyInfo_der_free_object,
    ml_kem_512_to_PrivateKeyInfo_der_does_selection,
    ML_KEM_512_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_512_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_PrivateKeyInfo_pem_encode,
    ml_kem_512_to_PrivateKeyInfo_pem_import_object,
    ml_kem_512_to_PrivateKeyInfo_pem_free_object,
    ml_kem_512_to_PrivateKeyInfo_pem_does_selection,
    ML_KEM_512_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_512_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_SubjectPublicKeyInfo_der_encode,
    ml_kem_512_to_SubjectPublicKeyInfo_der_import_object,
    ml_kem_512_to_SubjectPublicKeyInfo_der_free_object,
    ml_kem_512_to_SubjectPublicKeyInfo_der_does_selection,
    ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_kem_512_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_512_to_SubjectPublicKeyInfo_pem_encode,
    ml_kem_512_to_SubjectPublicKeyInfo_pem_import_object,
    ml_kem_512_to_SubjectPublicKeyInfo_pem_free_object,
    ml_kem_512_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_KEM_512_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_512_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_512,
    "ML-KEM-512",
    crate::provider::ml_kem_kmgmt::ML_KEM_512_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_EncryptedPrivateKeyInfo_der_encode,
    ml_kem_768_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_kem_768_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_kem_768_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_768_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_kem_768_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_kem_768_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_kem_768_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_KEM_768_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_768_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_PrivateKeyInfo_der_encode,
    ml_kem_768_to_PrivateKeyInfo_der_import_object,
    ml_kem_768_to_PrivateKeyInfo_der_free_object,
    ml_kem_768_to_PrivateKeyInfo_der_does_selection,
    ML_KEM_768_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_768_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_PrivateKeyInfo_pem_encode,
    ml_kem_768_to_PrivateKeyInfo_pem_import_object,
    ml_kem_768_to_PrivateKeyInfo_pem_free_object,
    ml_kem_768_to_PrivateKeyInfo_pem_does_selection,
    ML_KEM_768_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_768_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_SubjectPublicKeyInfo_der_encode,
    ml_kem_768_to_SubjectPublicKeyInfo_der_import_object,
    ml_kem_768_to_SubjectPublicKeyInfo_der_free_object,
    ml_kem_768_to_SubjectPublicKeyInfo_der_does_selection,
    ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_kem_768_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_768_to_SubjectPublicKeyInfo_pem_encode,
    ml_kem_768_to_SubjectPublicKeyInfo_pem_import_object,
    ml_kem_768_to_SubjectPublicKeyInfo_pem_free_object,
    ml_kem_768_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_KEM_768_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_768_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_768,
    "ML-KEM-768",
    crate::provider::ml_kem_kmgmt::ML_KEM_768_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_EncryptedPrivateKeyInfo_der_encode,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_1024_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_kem_1024_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_KEM_1024_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_1024_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_PrivateKeyInfo_der_encode,
    ml_kem_1024_to_PrivateKeyInfo_der_import_object,
    ml_kem_1024_to_PrivateKeyInfo_der_free_object,
    ml_kem_1024_to_PrivateKeyInfo_der_does_selection,
    ML_KEM_1024_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_kem_1024_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_PrivateKeyInfo_pem_encode,
    ml_kem_1024_to_PrivateKeyInfo_pem_import_object,
    ml_kem_1024_to_PrivateKeyInfo_pem_free_object,
    ml_kem_1024_to_PrivateKeyInfo_pem_does_selection,
    ML_KEM_1024_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_1024_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_kem_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_SubjectPublicKeyInfo_der_encode,
    ml_kem_1024_to_SubjectPublicKeyInfo_der_import_object,
    ml_kem_1024_to_SubjectPublicKeyInfo_der_free_object,
    ml_kem_1024_to_SubjectPublicKeyInfo_der_does_selection,
    ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_kem_1024_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_kem_1024_to_SubjectPublicKeyInfo_pem_encode,
    ml_kem_1024_to_SubjectPublicKeyInfo_pem_import_object,
    ml_kem_1024_to_SubjectPublicKeyInfo_pem_free_object,
    ml_kem_1024_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_KEM_1024_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_kem_1024_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_KEM_1024,
    "ML-KEM-1024",
    crate::provider::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_kem_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_RSA_der_encode,
    rsa_to_RSA_der_import_object,
    rsa_to_RSA_der_free_object,
    rsa_to_RSA_der_does_selection,
    RSA_TO_RSA_DER_FUNCTIONS,
    c"rsa_to_RSA_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_der_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_RSA_pem_encode,
    rsa_to_RSA_pem_import_object,
    rsa_to_RSA_pem_free_object,
    rsa_to_RSA_pem_does_selection,
    RSA_TO_RSA_PEM_FUNCTIONS,
    c"rsa_to_RSA_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_DH_der_encode,
    dh_to_DH_der_import_object,
    dh_to_DH_der_free_object,
    dh_to_DH_der_does_selection,
    DH_TO_DH_DER_FUNCTIONS,
    c"dh_to_DH_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dh_to_DH_pem_encode,
    dh_to_DH_pem_import_object,
    dh_to_DH_pem_free_object,
    dh_to_DH_pem_does_selection,
    DH_TO_DH_PEM_FUNCTIONS,
    c"dh_to_DH_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_DHX_der_encode,
    dhx_to_DHX_der_import_object,
    dhx_to_DHX_der_free_object,
    dhx_to_DHX_der_does_selection,
    DHX_TO_DHX_DER_FUNCTIONS,
    c"dhx_to_DHX_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_DHX_pem_encode,
    dhx_to_DHX_pem_import_object,
    dhx_to_DHX_pem_free_object,
    dhx_to_DHX_pem_does_selection,
    DHX_TO_DHX_PEM_FUNCTIONS,
    c"dhx_to_DHX_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dsa_to_DSA_der_encode,
    dsa_to_DSA_der_import_object,
    dsa_to_DSA_der_free_object,
    dsa_to_DSA_der_does_selection,
    DSA_TO_DSA_DER_FUNCTIONS,
    c"dsa_to_DSA_der_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_ALL,
    None,
    Some(prepare_dsa_params),
    Some(key_to_type_specific_der_bio),
    dsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    dsa_pub_k2d,
    Some(key_to_type_specific_der_bio),
    dsa_param_k2d,
);
make_encoder!(
    dsa_to_DSA_pem_encode,
    dsa_to_DSA_pem_import_object,
    dsa_to_DSA_pem_free_object,
    dsa_to_DSA_pem_does_selection,
    DSA_TO_DSA_PEM_FUNCTIONS,
    c"dsa_to_DSA_pem_encode",
    EVP_PKEY_DSA,
    "DSA",
    crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS,
    MASK_ALL,
    None,
    Some(prepare_dsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    dsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    dsa_pub_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dsa_param_k2d,
);
make_encoder!(
    ec_to_EC_der_encode,
    ec_to_EC_der_import_object,
    ec_to_EC_der_free_object,
    ec_to_EC_der_does_selection,
    EC_TO_EC_DER_FUNCTIONS,
    c"ec_to_EC_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_der_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    ec_param_k2d,
);
make_encoder!(
    ec_to_EC_pem_encode,
    ec_to_EC_pem_import_object,
    ec_to_EC_pem_free_object,
    ec_to_EC_pem_does_selection,
    EC_TO_EC_PEM_FUNCTIONS,
    c"ec_to_EC_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_pem_priv_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    ec_param_k2d,
);
make_encoder!(
    sm2_to_SM2_der_encode,
    sm2_to_SM2_der_import_object,
    sm2_to_SM2_der_free_object,
    sm2_to_SM2_der_does_selection,
    SM2_TO_SM2_DER_FUNCTIONS,
    c"sm2_to_SM2_der_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_der_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    ec_param_k2d,
);
make_encoder!(
    sm2_to_SM2_pem_encode,
    sm2_to_SM2_pem_import_object,
    sm2_to_SM2_pem_free_object,
    sm2_to_SM2_pem_does_selection,
    SM2_TO_SM2_PEM_FUNCTIONS,
    c"sm2_to_SM2_pem_encode",
    EVP_PKEY_EC,
    "SM2",
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_pem_priv_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    ec_param_k2d,
);
make_encoder!(
    rsa_to_PKCS1_der_encode,
    rsa_to_PKCS1_der_import_object,
    rsa_to_PKCS1_der_free_object,
    rsa_to_PKCS1_der_does_selection,
    RSA_TO_PKCS1_DER_FUNCTIONS,
    c"rsa_to_PKCS1_der_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_der_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsa_to_PKCS1_pem_encode,
    rsa_to_PKCS1_pem_import_object,
    rsa_to_PKCS1_pem_free_object,
    rsa_to_PKCS1_pem_does_selection,
    RSA_TO_PKCS1_PEM_FUNCTIONS,
    c"rsa_to_PKCS1_pem_encode",
    EVP_PKEY_RSA,
    "RSA",
    crate::provider::rsa_kmgmt::RSA_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_PKCS1_der_encode,
    rsapss_to_PKCS1_der_import_object,
    rsapss_to_PKCS1_der_free_object,
    rsapss_to_PKCS1_der_does_selection,
    RSAPSS_TO_PKCS1_DER_FUNCTIONS,
    c"rsapss_to_PKCS1_der_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_der_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_der_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    rsapss_to_PKCS1_pem_encode,
    rsapss_to_PKCS1_pem_import_object,
    rsapss_to_PKCS1_pem_free_object,
    rsapss_to_PKCS1_pem_does_selection,
    RSAPSS_TO_PKCS1_PEM_FUNCTIONS,
    c"rsapss_to_PKCS1_pem_encode",
    EVP_PKEY_RSA_PSS,
    "RSA-PSS",
    crate::provider::rsa_kmgmt::RSA_PSS_KEYMGMT_FUNCTIONS,
    MASK_KEYPAIR,
    Some(rsa_check_key_type),
    Some(prepare_rsa_params),
    Some(key_to_type_specific_pem_priv_bio),
    rsa_prv_k2d,
    Some(key_to_type_specific_pem_pub_bio),
    rsa_pub_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    dh_to_PKCS3_der_encode,
    dh_to_PKCS3_der_import_object,
    dh_to_PKCS3_der_free_object,
    dh_to_PKCS3_der_does_selection,
    DH_TO_PKCS3_DER_FUNCTIONS,
    c"dh_to_PKCS3_der_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dh_to_PKCS3_pem_encode,
    dh_to_PKCS3_pem_import_object,
    dh_to_PKCS3_pem_free_object,
    dh_to_PKCS3_pem_does_selection,
    DH_TO_PKCS3_PEM_FUNCTIONS,
    c"dh_to_PKCS3_pem_encode",
    EVP_PKEY_DH,
    "DH",
    crate::provider::keymgmt::DH_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_X9_42_der_encode,
    dhx_to_X9_42_der_import_object,
    dhx_to_X9_42_der_free_object,
    dhx_to_X9_42_der_does_selection,
    DHX_TO_X9_42_DER_FUNCTIONS,
    c"dhx_to_X9_42_der_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    dhx_to_X9_42_pem_encode,
    dhx_to_X9_42_pem_import_object,
    dhx_to_X9_42_pem_free_object,
    dhx_to_X9_42_pem_does_selection,
    DHX_TO_X9_42_PEM_FUNCTIONS,
    c"dhx_to_X9_42_pem_encode",
    EVP_PKEY_DHX,
    "X9.42 DH",
    crate::provider::keymgmt::DHX_KEYMGMT_FUNCTIONS,
    MASK_PARAMS,
    Some(dh_check_key_type),
    Some(prepare_dh_params),
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    dh_type_specific_params_to_der,
);
make_encoder!(
    ec_to_X9_62_der_encode,
    ec_to_X9_62_der_import_object,
    ec_to_X9_62_der_free_object,
    ec_to_X9_62_der_does_selection,
    EC_TO_X9_62_DER_FUNCTIONS,
    c"ec_to_X9_62_der_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_der_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_der_bio),
    ec_param_k2d,
);
make_encoder!(
    ec_to_X9_62_pem_encode,
    ec_to_X9_62_pem_import_object,
    ec_to_X9_62_pem_free_object,
    ec_to_X9_62_pem_does_selection,
    EC_TO_X9_62_PEM_FUNCTIONS,
    c"ec_to_X9_62_pem_encode",
    EVP_PKEY_EC,
    "EC",
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    MASK_NO_PUB,
    None,
    Some(prepare_ec_params),
    Some(key_to_type_specific_pem_priv_bio),
    ec_prv_k2d,
    None,
    key2any_unused_k2d,
    Some(key_to_type_specific_pem_param_bio),
    ec_param_k2d,
);
make_encoder!(
    ml_dsa_44_to_EncryptedPrivateKeyInfo_der_encode,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_44_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_44_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_dsa_44_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_DSA_44_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_44_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_44_to_PrivateKeyInfo_der_encode,
    ml_dsa_44_to_PrivateKeyInfo_der_import_object,
    ml_dsa_44_to_PrivateKeyInfo_der_free_object,
    ml_dsa_44_to_PrivateKeyInfo_der_does_selection,
    ML_DSA_44_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_44_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_44_to_PrivateKeyInfo_pem_encode,
    ml_dsa_44_to_PrivateKeyInfo_pem_import_object,
    ml_dsa_44_to_PrivateKeyInfo_pem_free_object,
    ml_dsa_44_to_PrivateKeyInfo_pem_does_selection,
    ML_DSA_44_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_44_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_44_to_SubjectPublicKeyInfo_der_encode,
    ml_dsa_44_to_SubjectPublicKeyInfo_der_import_object,
    ml_dsa_44_to_SubjectPublicKeyInfo_der_free_object,
    ml_dsa_44_to_SubjectPublicKeyInfo_der_does_selection,
    ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_44_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_44_to_SubjectPublicKeyInfo_pem_encode,
    ml_dsa_44_to_SubjectPublicKeyInfo_pem_import_object,
    ml_dsa_44_to_SubjectPublicKeyInfo_pem_free_object,
    ml_dsa_44_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_DSA_44_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_44_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_44,
    "ML-DSA-44",
    crate::provider::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_EncryptedPrivateKeyInfo_der_encode,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_65_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_dsa_65_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_DSA_65_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_65_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_PrivateKeyInfo_der_encode,
    ml_dsa_65_to_PrivateKeyInfo_der_import_object,
    ml_dsa_65_to_PrivateKeyInfo_der_free_object,
    ml_dsa_65_to_PrivateKeyInfo_der_does_selection,
    ML_DSA_65_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_65_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_PrivateKeyInfo_pem_encode,
    ml_dsa_65_to_PrivateKeyInfo_pem_import_object,
    ml_dsa_65_to_PrivateKeyInfo_pem_free_object,
    ml_dsa_65_to_PrivateKeyInfo_pem_does_selection,
    ML_DSA_65_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_65_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_SubjectPublicKeyInfo_der_encode,
    ml_dsa_65_to_SubjectPublicKeyInfo_der_import_object,
    ml_dsa_65_to_SubjectPublicKeyInfo_der_free_object,
    ml_dsa_65_to_SubjectPublicKeyInfo_der_does_selection,
    ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_65_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_65_to_SubjectPublicKeyInfo_pem_encode,
    ml_dsa_65_to_SubjectPublicKeyInfo_pem_import_object,
    ml_dsa_65_to_SubjectPublicKeyInfo_pem_free_object,
    ml_dsa_65_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_DSA_65_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_65_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_65,
    "ML-DSA-65",
    crate::provider::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_EncryptedPrivateKeyInfo_der_encode,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_der_import_object,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_der_free_object,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_der_does_selection,
    ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_87_to_EncryptedPrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_EncryptedPrivateKeyInfo_pem_encode,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_pem_import_object,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_pem_free_object,
    ml_dsa_87_to_EncryptedPrivateKeyInfo_pem_does_selection,
    ML_DSA_87_TO_ENCRYPTEDPRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_87_to_EncryptedPrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_epki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_PrivateKeyInfo_der_encode,
    ml_dsa_87_to_PrivateKeyInfo_der_import_object,
    ml_dsa_87_to_PrivateKeyInfo_der_free_object,
    ml_dsa_87_to_PrivateKeyInfo_der_does_selection,
    ML_DSA_87_TO_PRIVATEKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_87_to_PrivateKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_der_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_PrivateKeyInfo_pem_encode,
    ml_dsa_87_to_PrivateKeyInfo_pem_import_object,
    ml_dsa_87_to_PrivateKeyInfo_pem_free_object,
    ml_dsa_87_to_PrivateKeyInfo_pem_does_selection,
    ML_DSA_87_TO_PRIVATEKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_87_to_PrivateKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PRIV,
    None,
    None,
    Some(key_to_pki_pem_priv_bio),
    ml_dsa_pki_priv_to_der,
    None,
    key2any_unused_k2d,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_SubjectPublicKeyInfo_der_encode,
    ml_dsa_87_to_SubjectPublicKeyInfo_der_import_object,
    ml_dsa_87_to_SubjectPublicKeyInfo_der_free_object,
    ml_dsa_87_to_SubjectPublicKeyInfo_der_does_selection,
    ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_DER_FUNCTIONS,
    c"ml_dsa_87_to_SubjectPublicKeyInfo_der_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_der_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);
make_encoder!(
    ml_dsa_87_to_SubjectPublicKeyInfo_pem_encode,
    ml_dsa_87_to_SubjectPublicKeyInfo_pem_import_object,
    ml_dsa_87_to_SubjectPublicKeyInfo_pem_free_object,
    ml_dsa_87_to_SubjectPublicKeyInfo_pem_does_selection,
    ML_DSA_87_TO_SUBJECTPUBLICKEYINFO_PEM_FUNCTIONS,
    c"ml_dsa_87_to_SubjectPublicKeyInfo_pem_encode",
    EVP_PKEY_ML_DSA_87,
    "ML-DSA-87",
    crate::provider::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT_FUNCTIONS,
    MASK_PUB,
    None,
    None,
    None,
    key2any_unused_k2d,
    Some(key_to_spki_pem_pub_bio),
    ml_dsa_spki_pub_to_der,
    None,
    key2any_unused_k2d,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder_meth::OSSL_FUNC_ENCODER_DOES_SELECTION;

    /// Every transcribed table is the authority's nine-slot shape — `newctx`, `freectx`,
    /// `settable_ctx_params`, `set_ctx_params`, `does_selection`, `import_object`, `free_object`,
    /// `encode` — and the terminator.
    #[test]
    fn each_table_is_the_authoritys_nine_slot_shape() {
        // The registered rows are read out of the two provider tables; the two unregistered
        // `SM2`-structure expansions are not reachable from here, so the smoke test walks the
        // registration instead.
        for table in [
            &crate::provider::encode_key2text::DEFLT_ENCODERS[..],
            &crate::provider::encode_key2text::BASE_ENCODERS[..],
        ] {
            let _ = table;
        }
        let mut i = 0;
        let mut seen = [false; 8];
        let mut unexpected = 0;
        // SAFETY: the table is terminated and each read is within it.
        unsafe {
            while (*RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER_FUNCTIONS.as_ptr().add(i)).function_id
                != OSSL_DISPATCH_END
            {
                match (*RSA_TO_TYPE_SPECIFIC_KEYPAIR_DER_FUNCTIONS.as_ptr().add(i)).function_id {
                    OSSL_FUNC_ENCODER_NEWCTX => seen[0] = true,
                    OSSL_FUNC_ENCODER_FREECTX => seen[1] = true,
                    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS => seen[2] = true,
                    OSSL_FUNC_ENCODER_SET_CTX_PARAMS => seen[3] = true,
                    OSSL_FUNC_ENCODER_DOES_SELECTION => seen[4] = true,
                    OSSL_FUNC_ENCODER_IMPORT_OBJECT => seen[5] = true,
                    OSSL_FUNC_ENCODER_FREE_OBJECT => seen[6] = true,
                    OSSL_FUNC_ENCODER_ENCODE => seen[7] = true,
                    _ => unexpected += 1,
                }
                i += 1;
            }
        }
        assert_eq!(unexpected, 0, "the table carries an unexpected slot");
        assert!(seen.iter().all(|&s| s), "the table is missing a slot");
        assert_eq!(i, 8);
    }

    /// The selection rule is the authority's: an empty selection is accepted, and the first of
    /// the three levels the caller asks for is answered by the mask.
    #[test]
    fn the_selection_rule_is_the_authoritys() {
        assert_eq!(key2any_check_selection(0, MASK_ALL), 1);
        assert_eq!(key2any_check_selection(MASK_PRIV, MASK_PRIV), 1);
        assert_eq!(key2any_check_selection(MASK_PUB, MASK_PRIV), 0);
        assert_eq!(key2any_check_selection(MASK_PARAMS, MASK_NO_PUB), 1);
        assert_eq!(MASK_ALL, 0x87);
        assert_eq!(MASK_NO_PUB, 0x85);
    }
}
