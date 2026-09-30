//! Phase 10.1 — `providers/implementations/encode_decode/ml_dsa_codecs.c`: the ML-DSA
//! `d2i`/`i2d` PKCS#8 and `SubjectPublicKeyInfo` codecs and the `ossl_ml_dsa_key_to_text` printer.
//!
//! This unit is `ml_kem_codecs.c`'s sibling and the second *closure* unit D435 measured: the same
//! four `ossl_ml_dsa_d2i_PKCS8`/`_PUBKEY`/`i2d_*` helpers the two big row-publishers call, and the
//! `ossl_ml_dsa_key_to_text` printer the three withheld `ML-DSA` text tables call. Its primitives
//! landed with `crypto/ml_dsa/` (`src/ml_dsa/`) in Phase 8.
//!
//! ## What differs from the ML-KEM unit
//!
//! Three things, and each is observable. The PKCS#8 table's six shapes carry a 32-byte seed where
//! ML-KEM's carry 64. `ossl_ml_dsa_d2i_PKCS8` collects the seed and/or the key and hands them to
//! `ossl_ml_dsa_set_prekey` rather than storing an encoded private key in `encoded_dk`. And the
//! printer requires a **public** key regardless of selection (it raises `PROV_R_MISSING_KEY` with
//! no key material), where ML-KEM's outputs whichever of the seed/key/public it has. A
//! transcription that reused ML-KEM's printer would answer different bytes and a different refusal.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]
// The `d2i`/`i2d` half of this unit is reached only by `decode_der2key.c` and `encode_key2any.c`,
// which have not landed; the `*_to_text` printer is reached by the text-encoder tables this slice
// publishes. The allow covers the former until those two units land.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_long, c_uchar, CStr};
use core::ptr;

use crate::asn1::layout::V_ASN1_UNDEF;
use crate::asn1::p8_pkey::{d2i_PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free, PKCS8_pkey_get0};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::encoder_lib::ossl_bio_print_labeled_buf;
use crate::evp::pkey::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
use crate::ml_dsa::encoders::ossl_ml_dsa_pk_decode;
use crate::ml_dsa::key::{
    ossl_ml_dsa_key_free, ossl_ml_dsa_key_get_priv, ossl_ml_dsa_key_get_pub,
    ossl_ml_dsa_key_get_seed, ossl_ml_dsa_key_new, ossl_ml_dsa_key_params, ossl_ml_dsa_set_prekey,
};
use crate::ml_dsa::{ossl_ml_dsa_params_get, MlDsaKey, ML_DSA_SEED_BYTES};
use crate::provider::ctx::{ossl_prov_ctx_get_param, prov_libctx_of, ProvCtx};
use crate::provider::ml_common_codecs::{
    load_u16_be, load_u32_be, store_u16_be, store_u32_be, MlCommonCodec, MlCommonPkcs8Fmt,
    MlCommonPkcs8FmtPref, MlCommonSpkiFmt, ML_COMMON_SPKI_OVERHEAD, NUM_PKCS8_FORMATS,
};
use crate::provider::ml_dsa_kmgmt::ossl_prov_ml_dsa_new;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, CRYPTO_memdup};
use crate::runtime::obj::OBJ_obj2nid;

/// The unit's own `__FILE__`. `ml_dsa_codecs.c` is a plain `.c`, so the compiler records the
/// source-tree path with the build's relative prefix (D235).
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/encode_decode/ml_dsa_codecs.c".as_ptr();
/// `ml_dsa_codecs.c:263`, the `end:` arm's `OPENSSL_free(fmt_slots)` in `ossl_ml_dsa_d2i_PKCS8`.
const LINE_FREE_IN_SLOTS: c_int = 263;
/// `ml_dsa_codecs.c:282`, `ossl_ml_dsa_i2d_pubkey`'s `OPENSSL_memdup(pk, params->pk_len)`.
const LINE_MEMDUP_PUB: c_int = 282;
/// `ml_dsa_codecs.c:341`, `ossl_ml_dsa_i2d_prvkey`'s `OPENSSL_malloc((size_t)len)`.
const LINE_MALLOC: c_int = 341;
/// `ml_dsa_codecs.c:403`, `ossl_ml_dsa_i2d_prvkey`'s `OPENSSL_free(fmt_slots)`.
const LINE_FREE_OUT_SLOTS: c_int = 403;
/// `ml_dsa_codecs.c:405`, `ossl_ml_dsa_i2d_prvkey`'s `OPENSSL_free(buf)`.
const LINE_FREE_OUT_BUF: c_int = 405;

/// `OSSL_PKEY_PARAM_ML_DSA_INPUT_FORMATS` — `core_names.h:427`.
const OSSL_PKEY_PARAM_ML_DSA_INPUT_FORMATS: *const c_char = c"ml-dsa.input_formats".as_ptr();
/// `OSSL_PKEY_PARAM_ML_DSA_OUTPUT_FORMATS` — `core_names.h:428`.
const OSSL_PKEY_PARAM_ML_DSA_OUTPUT_FORMATS: *const c_char = c"ml-dsa.output_formats".as_ptr();

// ---------------------------------------------------------------------------
// The per-variant tables — `ml_dsa_codecs.c:29-93`
// ---------------------------------------------------------------------------

// `ML-DSA-44` public key 1312 (0x0520), private key 2560 (0x0a00).
/// `ml_dsa_44_spkifmt` — `ml_dsa_codecs.c:29-33`.
static ML_DSA_44_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x05, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x03, 0x11, 0x03, 0x82, 0x05, 0x21, 0x00,
    ],
};

/// `ml_dsa_44_p8fmt[NUM_PKCS8_FORMATS]` — `ml_dsa_codecs.c:34-41`.
static ML_DSA_44_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x0a2a,
        p8_shift: 0,
        p8_magic: 0x3082_0a26,
        seed_magic: 0x0420,
        seed_offset: 6,
        seed_length: 0x20,
        priv_magic: 0x0482_0a00,
        priv_offset: 0x2a,
        priv_length: 0x0a00,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x0a04,
        p8_shift: 0,
        p8_magic: 0x0482_0a00,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0a00,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x0f24,
        p8_shift: 0,
        p8_magic: 0x0482_0f20,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0a00,
        pub_offset: 0x0a04,
        pub_length: 0x0520,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0022,
        p8_shift: 2,
        p8_magic: 0x8020,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x0a00,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x0a00,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0020,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// `ML-DSA-65` public key 1952 (0x07a0), private key 4032 (0x0fc0).
/// `ml_dsa_65_spkifmt` — `ml_dsa_codecs.c:48-52`.
static ML_DSA_65_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
    ],
};

/// `ml_dsa_65_p8fmt[NUM_PKCS8_FORMATS]` — `ml_dsa_codecs.c:53-60`.
static ML_DSA_65_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x0fea,
        p8_shift: 0,
        p8_magic: 0x3082_0fe6,
        seed_magic: 0x0420,
        seed_offset: 6,
        seed_length: 0x20,
        priv_magic: 0x0482_0fc0,
        priv_offset: 0x2a,
        priv_length: 0x0fc0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x0fc4,
        p8_shift: 0,
        p8_magic: 0x0482_0fc0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0fc0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x1764,
        p8_shift: 0,
        p8_magic: 0x0482_1760,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0fc0,
        pub_offset: 0x0fc4,
        pub_length: 0x07a0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0022,
        p8_shift: 2,
        p8_magic: 0x8020,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x0fc0,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x0fc0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0020,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// `ML-DSA-87` public key 2592 (0x0a20), private key 4896 (0x1320).
/// `ml_dsa_87_spkifmt` — `ml_dsa_codecs.c:67-71`.
static ML_DSA_87_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x0a, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x03, 0x13, 0x03, 0x82, 0x0a, 0x21, 0x00,
    ],
};

/// `ml_dsa_87_p8fmt[NUM_PKCS8_FORMATS]` — `ml_dsa_codecs.c:72-79`.
static ML_DSA_87_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x134a,
        p8_shift: 0,
        p8_magic: 0x3082_1346,
        seed_magic: 0x0420,
        seed_offset: 6,
        seed_length: 0x20,
        priv_magic: 0x0482_1320,
        priv_offset: 0x2a,
        priv_length: 0x1320,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x1324,
        p8_shift: 0,
        p8_magic: 0x0482_1320,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x1320,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x1d44,
        p8_shift: 0,
        p8_magic: 0x0482_1d40,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x1320,
        pub_offset: 0x1324,
        pub_length: 0x0a20,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0022,
        p8_shift: 2,
        p8_magic: 0x8020,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x1320,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x1320,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0020,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x20,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// Indices of slots in the codec table below.
/// `ML_DSA_44_CODEC` — `ml_dsa_codecs.c:82`, slot 0.
const ML_DSA_44_CODEC: usize = 0;
/// `ML_DSA_65_CODEC` — `ml_dsa_codecs.c:83`, slot 1.
const ML_DSA_65_CODEC: usize = 1;
/// `ML_DSA_87_CODEC` — `ml_dsa_codecs.c:84`, slot 2.
const ML_DSA_87_CODEC: usize = 2;

/// `static const ML_COMMON_CODEC codecs[3]` — `ml_dsa_codecs.c:89-93`.
static CODECS: [MlCommonCodec; 3] = [
    MlCommonCodec {
        spkifmt: &ML_DSA_44_SPKIFMT,
        p8fmt: ML_DSA_44_P8FMT.as_ptr(),
    },
    MlCommonCodec {
        spkifmt: &ML_DSA_65_SPKIFMT,
        p8fmt: ML_DSA_65_P8FMT.as_ptr(),
    },
    MlCommonCodec {
        spkifmt: &ML_DSA_87_SPKIFMT,
        p8fmt: ML_DSA_87_P8FMT.as_ptr(),
    },
];

/// `static const ML_COMMON_CODEC *ml_dsa_get_codec(int evp_type)` — `ml_dsa_codecs.c:96-107`.
fn ml_dsa_get_codec(evp_type: c_int) -> *const MlCommonCodec {
    match evp_type {
        crate::ml_dsa::EVP_PKEY_ML_DSA_44 => &CODECS[ML_DSA_44_CODEC],
        crate::ml_dsa::EVP_PKEY_ML_DSA_65 => &CODECS[ML_DSA_65_CODEC],
        crate::ml_dsa::EVP_PKEY_ML_DSA_87 => &CODECS[ML_DSA_87_CODEC],
        _ => ptr::null(),
    }
}

/// Raise `prefix || alg || suffix` through `site`.
///
/// # Safety
/// `alg` must be NUL-terminated.
unsafe fn raise_one(site: &err_sites::ErrSite, prefix: &str, alg: *const c_char, suffix: &str) {
    // SAFETY: `alg` is NUL-terminated per the contract.
    let bytes = unsafe { CStr::from_ptr(alg) }.to_bytes();
    let mut msg = Vec::with_capacity(prefix.len() + bytes.len() + suffix.len() + 1);
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(bytes);
    msg.extend_from_slice(suffix.as_bytes());
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated just above.
    unsafe { raise_site_data(site, msg.as_ptr().cast()) };
}

/// Free a format-slot list the helper returned, if any.
///
/// # Safety
/// `slots` must be NULL or a list `ossl_ml_common_pkcs8_fmt_order` returned.
unsafe fn free_slots(slots: *mut MlCommonPkcs8FmtPref, line: c_int) {
    if !slots.is_null() {
        // SAFETY: `slots` is this call's list and `line` its coordinate.
        unsafe { CRYPTO_free(slots.cast(), FILE, line) };
    }
}

/// `ML_DSA_KEY *ossl_ml_dsa_d2i_PUBKEY(const uint8_t *pk, int pk_len, int evp_type,`
/// `PROV_CTX *provctx, const char *propq)` — `ml_dsa_codecs.c:109-139`.
///
/// # Safety
/// `pk` is readable for `pk_len` bytes; `provctx` is a live provider context; `propq` is NULL or
/// NUL-terminated.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_dsa_d2i_PUBKEY`)
pub(crate) unsafe fn ossl_ml_dsa_d2i_PUBKEY(
    pk: *const u8,
    pk_len: c_int,
    evp_type: c_int,
    provctx: *mut ProvCtx,
    propq: *const c_char,
) -> *mut MlDsaKey {
    // SAFETY: `provctx` is a live context per the contract.
    let libctx = unsafe { prov_libctx_of(provctx.cast()) };
    let params = ossl_ml_dsa_params_get(evp_type);
    let codec = ml_dsa_get_codec(evp_type);
    if params.is_null() || codec.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `params` and `codec` are live past the guard; `pk` is readable for `pk_len`.
    unsafe {
        if pk_len != (ML_COMMON_SPKI_OVERHEAD as c_int) + (*params).pk_len as c_int
            || pk.is_null()
            || CRYPTO_memcmp(
                pk.cast(),
                (*(*codec).spkifmt).asn1_prefix.as_ptr().cast(),
                ML_COMMON_SPKI_OVERHEAD,
            ) != 0
        {
            return ptr::null_mut();
        }
    }
    // SAFETY: `pk` is readable for `pk_len` >= ML_COMMON_SPKI_OVERHEAD bytes per the contract.
    let payload = unsafe { pk.add(ML_COMMON_SPKI_OVERHEAD) };
    let payload_len = pk_len - ML_COMMON_SPKI_OVERHEAD as c_int;

    // SAFETY: `libctx` and `propq` are the caller's; the primitive owns the new key.
    let ret = unsafe { ossl_ml_dsa_key_new(libctx, propq, evp_type) };
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `payload` is readable for `payload_len` and `ret` is live.
    if unsafe { ossl_ml_dsa_pk_decode(ret, payload, payload_len as usize) } == 0 {
        // SAFETY: `params` is live and `ret` is this frame's key.
        unsafe {
            raise_one(
                &err_sites::ML_DSA_CODECS_131,
                "error parsing ",
                (*params).alg,
                " public key from input SPKI",
            );
            ossl_ml_dsa_key_free(ret);
        }
        return ptr::null_mut();
    }

    ret
}

/// `ML_DSA_KEY *ossl_ml_dsa_d2i_PKCS8(const uint8_t *prvenc, int prvlen, int evp_type,`
/// `PROV_CTX *provctx, const char *propq)` — `ml_dsa_codecs.c:141-268`.
///
/// # Safety
/// `prvenc` is readable for `prvlen` bytes; `provctx` is a live provider context; `propq` is NULL or
/// NUL-terminated.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_dsa_d2i_PKCS8`)
pub(crate) unsafe fn ossl_ml_dsa_d2i_PKCS8(
    prvenc: *const u8,
    prvlen: c_int,
    evp_type: c_int,
    provctx: *mut ProvCtx,
    propq: *const c_char,
) -> *mut MlDsaKey {
    let v = ossl_ml_dsa_params_get(evp_type);
    let codec = ml_dsa_get_codec(evp_type);
    if v.is_null() || codec.is_null() {
        return ptr::null_mut();
    }

    let mut slots: *mut MlCommonPkcs8FmtPref = ptr::null_mut();
    let mut key: *mut MlDsaKey = ptr::null_mut();
    let mut ret: *mut MlDsaKey = ptr::null_mut();
    let mut buf: *const c_uchar = ptr::null();
    let mut alg: *const X509Algor = ptr::null();
    let mut len: c_int = 0;
    let mut seed: *const u8 = ptr::null();
    let mut priv_: *const u8 = ptr::null();

    // SAFETY: `prvlen` is the caller's length and the d2i takes its own pointer-to-pointer.
    let mut cursor = prvenc;
    // SAFETY: the d2i reads `prvlen` bytes from `cursor` and answers a fresh `p8inf`.
    let p8inf = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut cursor, prvlen as c_long) };
    if p8inf.is_null() {
        return ptr::null_mut();
    }

    'end: {
        // SAFETY: `p8inf` is live; the three out-pointers are this frame's.
        if unsafe { PKCS8_pkey_get0(ptr::null_mut(), &mut buf, &mut len, &mut alg, p8inf) } == 0 {
            break 'end;
        }
        // Bail out early if this is some other key type.
        // SAFETY: `alg` is live past the accessor.
        if unsafe { OBJ_obj2nid((*alg).algorithm) } != evp_type {
            break 'end;
        }

        // SAFETY: `provctx` is live and the parameter name is a static literal.
        let formats = unsafe {
            ossl_prov_ctx_get_param(provctx, OSSL_PKEY_PARAM_ML_DSA_INPUT_FORMATS, ptr::null())
        };
        // SAFETY: `v`'s name, `codec`'s table and `formats` are live.
        slots = unsafe {
            crate::provider::ml_common_codecs::ossl_ml_common_pkcs8_fmt_order(
                (*v).alg,
                (*codec).p8fmt,
                c"input".as_ptr(),
                formats,
            )
        };
        if slots.is_null() {
            break 'end;
        }

        // Parameters must be absent.
        let mut ptype: c_int = 0;
        // SAFETY: `alg` is live and `ptype` is this frame's.
        unsafe { X509_ALGOR_get0(ptr::null_mut(), &mut ptype, ptr::null_mut(), alg) };
        if ptype != V_ASN1_UNDEF {
            // SAFETY: `v` is live.
            unsafe {
                raise_one(
                    &err_sites::ML_DSA_CODECS_187,
                    "unexpected parameters with a PKCS#8 ",
                    (*v).alg,
                    " private key",
                );
            }
            break 'end;
        }
        if len < 4 {
            break 'end;
        }

        // Find the matching p8 info slot, that also has the expected length.
        let mut magic: u32 = 0;
        // SAFETY: `buf` is readable for `len` >= 4 bytes.
        let mut pos = unsafe { load_u32_be(buf, &mut magic) };
        let mut p8fmt: *const MlCommonPkcs8Fmt = ptr::null();
        // SAFETY: `slots` is the returned list, terminated by a NULL `fmt`.
        unsafe {
            let mut slot = slots;
            loop {
                let f = (*slot).fmt;
                if f.is_null() {
                    break;
                }
                if len as i64 == (*f).p8_bytes as i64
                    && ((*f).p8_shift == 4
                        || (magic >> ((*f).p8_shift * 8) as u32) == (*f).p8_magic)
                {
                    pos = pos.sub((*f).p8_shift as usize);
                    p8fmt = f;
                    break;
                }
                slot = slot.add(1);
            }
        }
        if p8fmt.is_null() {
            // SAFETY: `v` is live.
            unsafe {
                raise_one(
                    &err_sites::ML_DSA_CODECS_210,
                    "no matching enabled ",
                    (*v).alg,
                    " private key input formats",
                );
            }
            break 'end;
        }
        // SAFETY: `p8fmt` and `v` are live.
        unsafe {
            if ((*p8fmt).seed_length > 0 && (*p8fmt).seed_length != ML_DSA_SEED_BYTES)
                || ((*p8fmt).priv_length > 0 && (*p8fmt).priv_length != (*v).sk_len)
                || ((*p8fmt).pub_length > 0 && (*p8fmt).pub_length != (*v).pk_len)
            {
                raise_one(
                    &err_sites::ML_DSA_CODECS_210,
                    "no matching enabled ",
                    (*v).alg,
                    " private key input formats",
                );
                break 'end;
            }

            if (*p8fmt).seed_length > 0 {
                // Check |seed| tag/len, if not subsumed by |magic|.
                if pos.add(2) == buf.add((*p8fmt).seed_offset) {
                    let mut seed_magic: u16 = 0;
                    pos = load_u16_be(pos, &mut seed_magic);
                    if seed_magic != (*p8fmt).seed_magic {
                        break 'end;
                    }
                } else if pos != buf.add((*p8fmt).seed_offset) {
                    break 'end;
                }
                pos = pos.add(ML_DSA_SEED_BYTES);
            }
            if (*p8fmt).priv_length > 0 {
                // Check |priv| tag/len.
                if pos.add(4) == buf.add((*p8fmt).priv_offset) {
                    pos = load_u32_be(pos, &mut magic);
                    if magic != (*p8fmt).priv_magic {
                        break 'end;
                    }
                } else if pos != buf.add((*p8fmt).priv_offset) {
                    break 'end;
                }
                pos = pos.add((*v).sk_len);
            }
            if (*p8fmt).pub_length > 0 {
                if pos != buf.add((*p8fmt).pub_offset) {
                    break 'end;
                }
                pos = pos.add((*v).pk_len);
            }
            if pos != buf.add(len as usize) {
                break 'end;
            }

            // Collect the seed and/or key into a "decoded" private key object, to be turned into a
            // real key on provider "load" or "import".
            key = ossl_prov_ml_dsa_new(provctx, propq, evp_type);
            if key.is_null() {
                break 'end;
            }
            if (*p8fmt).seed_length > 0 {
                seed = buf.add((*p8fmt).seed_offset);
            }
            if (*p8fmt).priv_length > 0 {
                priv_ = buf.add((*p8fmt).priv_offset);
            }
            // Any OQS public key content is ignored.
            if ossl_ml_dsa_set_prekey(key, 0, 0, seed, ML_DSA_SEED_BYTES, priv_, (*v).sk_len) != 0 {
                ret = key;
            }
        }
    }

    // SAFETY: `slots` is NULL or this frame's list; `p8inf` is live.
    unsafe {
        free_slots(slots, LINE_FREE_IN_SLOTS);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if ret.is_null() {
            ossl_ml_dsa_key_free(key);
        }
    }
    ret
}

/// `int ossl_ml_dsa_i2d_pubkey(const ML_DSA_KEY *key, unsigned char **out)` —
/// `ml_dsa_codecs.c:270-285`.
///
/// # Safety
/// `key` is live; `out` is NULL or writable for a `*mut c_uchar`.
pub(crate) unsafe fn ossl_ml_dsa_i2d_pubkey(key: *const MlDsaKey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: `key` is live per the contract.
    let params = unsafe { ossl_ml_dsa_key_params(key) };
    // SAFETY: `key` is live.
    let pk = unsafe { ossl_ml_dsa_key_get_pub(key) };

    if pk.is_null() {
        // SAFETY: `params` is live.
        unsafe {
            raise_one(
                &err_sites::ML_DSA_CODECS_277,
                "no ",
                (*params).alg,
                " public key data available",
            );
        }
        return 0;
    }
    if out.is_null() {
        return 0;
    }
    // SAFETY: `pk` is readable for `pk_len` and the allocation is the authority's own.
    let dup = unsafe { CRYPTO_memdup(pk.cast(), (*params).pk_len, FILE, LINE_MEMDUP_PUB) }
        .cast::<c_uchar>();
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `out` is writable per the contract.
    unsafe { *out = dup };
    // SAFETY: `params` is live.
    unsafe { (*params).pk_len as c_int }
}

/// `int ossl_ml_dsa_i2d_prvkey(const ML_DSA_KEY *key, uint8_t **out, PROV_CTX *provctx)` —
/// `ml_dsa_codecs.c:287-407`.
///
/// # Safety
/// `key` is live; `out` is NULL or writable for a `*mut u8`; `provctx` is a live provider context.
pub(crate) unsafe fn ossl_ml_dsa_i2d_prvkey(
    key: *const MlDsaKey,
    out: *mut *mut u8,
    provctx: *mut ProvCtx,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    let params = unsafe { ossl_ml_dsa_key_params(key) };
    // SAFETY: `params` is live per the contract.
    let codec = ml_dsa_get_codec(unsafe { (*params).evp_type });
    if codec.is_null() {
        return 0;
    }

    // SAFETY: `key` is live.
    let seed = unsafe { ossl_ml_dsa_key_get_seed(key) };
    // SAFETY: `key` is live.
    let sk = unsafe { ossl_ml_dsa_key_get_priv(key) };

    if sk.is_null() {
        // SAFETY: `params` is live.
        unsafe {
            raise_one(
                &err_sites::ML_DSA_CODECS_307,
                "no ",
                (*params).alg,
                " private key data available",
            );
        }
        return 0;
    }

    // SAFETY: `provctx` is live and the name is a static literal.
    let formats = unsafe {
        ossl_prov_ctx_get_param(provctx, OSSL_PKEY_PARAM_ML_DSA_OUTPUT_FORMATS, ptr::null())
    };
    // SAFETY: `params`'s alg, `codec`'s table and `formats` are live.
    let fmt_slots = unsafe {
        crate::provider::ml_common_codecs::ossl_ml_common_pkcs8_fmt_order(
            (*params).alg,
            (*codec).p8fmt,
            c"output".as_ptr(),
            formats,
        )
    };
    if fmt_slots.is_null() {
        return 0;
    }

    let len: c_int;
    let mut ret: c_int = 0;
    let mut buf: *mut u8 = ptr::null_mut();

    'end: {
        // If we don't have a seed, skip seedful entries.
        let mut p8fmt: *const MlCommonPkcs8Fmt = ptr::null();
        // SAFETY: `fmt_slots` is the returned list, terminated by a NULL `fmt`.
        unsafe {
            let mut slot = fmt_slots;
            while !(*slot).fmt.is_null() {
                let f = (*slot).fmt;
                if !seed.is_null() || (*f).seed_length == 0 {
                    p8fmt = f;
                    break;
                }
                slot = slot.add(1);
            }
        }
        // SAFETY: `params` is live.
        unsafe {
            if p8fmt.is_null()
                || ((*p8fmt).seed_length > 0 && (*p8fmt).seed_length != ML_DSA_SEED_BYTES)
                || ((*p8fmt).priv_length > 0 && (*p8fmt).priv_length != (*params).sk_len)
                || ((*p8fmt).pub_length > 0 && (*p8fmt).pub_length != (*params).pk_len)
            {
                raise_one(
                    &err_sites::ML_DSA_CODECS_329,
                    "no matching enabled ",
                    (*params).alg,
                    " private key output formats",
                );
                break 'end;
            }
            len = (*p8fmt).p8_bytes as c_int;

            if out.is_null() {
                ret = len;
                break 'end;
            }

            buf = CRYPTO_malloc(len as usize, FILE, LINE_MALLOC).cast::<u8>();
            if buf.is_null() {
                break 'end;
            }
            let mut pos = buf;

            match (*p8fmt).p8_shift {
                0 => pos = store_u32_be(pos, (*p8fmt).p8_magic),
                2 => pos = store_u16_be(pos, (*p8fmt).p8_magic as u16),
                4 => {}
                _ => {
                    raise_one(
                        &err_sites::ML_DSA_CODECS_354,
                        "error encoding ",
                        (*params).alg,
                        " private key",
                    );
                    break 'end;
                }
            }

            if (*p8fmt).seed_length != 0 {
                // Either the tag/len were already included in |magic| or they require us to write
                // two bytes now.
                if pos.add(2) == buf.add((*p8fmt).seed_offset) {
                    pos = store_u16_be(pos, (*p8fmt).seed_magic);
                }
                if pos != buf.add((*p8fmt).seed_offset) {
                    raise_one(
                        &err_sites::ML_DSA_CODECS_367,
                        "error encoding ",
                        (*params).alg,
                        " private key",
                    );
                    break 'end;
                }
                ptr::copy_nonoverlapping(seed, pos, ML_DSA_SEED_BYTES);
                pos = pos.add(ML_DSA_SEED_BYTES);
            }
            if (*p8fmt).priv_length != 0 {
                if pos.add(4) == buf.add((*p8fmt).priv_offset) {
                    pos = store_u32_be(pos, (*p8fmt).priv_magic);
                }
                if pos != buf.add((*p8fmt).priv_offset) {
                    raise_one(
                        &err_sites::ML_DSA_CODECS_378,
                        "error encoding ",
                        (*params).alg,
                        " private key",
                    );
                    break 'end;
                }
                ptr::copy_nonoverlapping(sk, pos, (*params).sk_len);
                pos = pos.add((*params).sk_len);
            }
            // OQS form output with tacked-on public key.
            if (*p8fmt).pub_length != 0 {
                // The OQS pubkey is never separately DER-wrapped.
                if pos != buf.add((*p8fmt).pub_offset) {
                    raise_one(
                        &err_sites::ML_DSA_CODECS_389,
                        "error encoding ",
                        (*params).alg,
                        " private key",
                    );
                    break 'end;
                }
                ptr::copy_nonoverlapping(ossl_ml_dsa_key_get_pub(key), pos, (*params).pk_len);
                pos = pos.add((*params).pk_len);
            }

            if pos == buf.add(len as usize) {
                *out = buf;
                ret = len;
            }
        }
    }

    // SAFETY: `fmt_slots` is this frame's list; `buf` is NULL or this frame's allocation.
    unsafe {
        free_slots(fmt_slots, LINE_FREE_OUT_SLOTS);
        if ret == 0 {
            CRYPTO_free(buf.cast(), FILE, LINE_FREE_OUT_BUF);
        }
    }
    ret
}

/// `int ossl_ml_dsa_key_to_text(BIO *out, const ML_DSA_KEY *key, int selection)` —
/// `ml_dsa_codecs.c:409-451`.
///
/// # Safety
/// `out` is NULL or live; `key` is NULL or live.
pub(crate) unsafe fn ossl_ml_dsa_key_to_text(
    out: *mut Bio,
    key: *const MlDsaKey,
    selection: c_int,
) -> c_int {
    if out.is_null() || key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ML_DSA_CODECS_415) };
        return 0;
    }
    // SAFETY: `key` is live past the guard.
    let params = unsafe { ossl_ml_dsa_key_params(key) };
    // SAFETY: `key` is live.
    let pk = unsafe { ossl_ml_dsa_key_get_pub(key) };
    // SAFETY: `key` is live.
    let sk = unsafe { ossl_ml_dsa_key_get_priv(key) };
    // SAFETY: `key` is live.
    let seed = unsafe { ossl_ml_dsa_key_get_seed(key) };

    if pk.is_null() {
        // Regardless of the |selection|, there must be a public key.
        // SAFETY: `params` is live.
        unsafe {
            raise_one(
                &err_sites::ML_DSA_CODECS_425,
                "no ",
                (*params).alg,
                " key material available",
            );
        }
        return 0;
    }

    // SAFETY: `params` is live and the printer's helpers take the buffers below.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            if sk.is_null() {
                raise_one(
                    &err_sites::ML_DSA_CODECS_432,
                    "no ",
                    (*params).alg,
                    " key material available",
                );
                return 0;
            }
            if BIO_printf(out, c"%s Private-Key:\n".as_ptr(), (*params).alg) <= 0 {
                return 0;
            }
            if !seed.is_null()
                && ossl_bio_print_labeled_buf(out, c"seed:".as_ptr(), seed, ML_DSA_SEED_BYTES) == 0
            {
                return 0;
            }
            if ossl_bio_print_labeled_buf(out, c"priv:".as_ptr(), sk, (*params).sk_len) == 0 {
                return 0;
            }
        } else if (selection & crate::evp::pkey::OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            && BIO_printf(out, c"%s Public-Key:\n".as_ptr(), (*params).alg) <= 0
        {
            return 0;
        }

        if ossl_bio_print_labeled_buf(out, c"pub:".as_ptr(), pk, (*params).pk_len) == 0 {
            return 0;
        }
    }

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each variant's SPKI prefix is 22 bytes and its PKCS#8 table has the six named shapes.
    #[test]
    fn the_tables_carry_the_authoritys_shapes() {
        for codec in CODECS.iter() {
            // SAFETY: each table is a live static of the stated length.
            unsafe {
                assert_eq!((*codec.spkifmt).asn1_prefix[0], 0x30);
                let mut names: Vec<Vec<u8>> = Vec::new();
                for i in 0..NUM_PKCS8_FORMATS {
                    names.push(
                        CStr::from_ptr((*(codec.p8fmt.add(i))).p8_name)
                            .to_bytes()
                            .to_vec(),
                    );
                }
                assert_eq!(names[0], b"seed-priv".to_vec());
                assert_eq!(names[5], b"bare-seed".to_vec());
                // The ML-DSA seed is 32 bytes, not ML-KEM's 64.
                let seed_only = &*codec.p8fmt.add(3);
                assert_eq!(seed_only.seed_length, ML_DSA_SEED_BYTES);
            }
        }
    }

    /// `ml_dsa_get_codec` answers each variant's slot and NULL for anything else.
    #[test]
    fn the_codec_lookup_is_the_three_variants() {
        assert!(core::ptr::eq(
            ml_dsa_get_codec(crate::ml_dsa::EVP_PKEY_ML_DSA_44),
            &CODECS[ML_DSA_44_CODEC]
        ));
        assert!(core::ptr::eq(
            ml_dsa_get_codec(crate::ml_dsa::EVP_PKEY_ML_DSA_87),
            &CODECS[ML_DSA_87_CODEC]
        ));
        assert!(ml_dsa_get_codec(0).is_null());
    }
}
