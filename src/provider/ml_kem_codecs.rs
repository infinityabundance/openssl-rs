//! Phase 10.1 — `providers/implementations/encode_decode/ml_kem_codecs.c`: the ML-KEM
//! `d2i`/`i2d` PKCS#8 and `SubjectPublicKeyInfo` codecs and the `ossl_ml_kem_key_to_text` printer.
//!
//! This unit publishes **no provider row**. It is the *closure* D435 measured: `decode_der2key.c`
//! (138 rows) and `encode_key2any.c` (412 rows) both call `ossl_ml_kem_d2i_PKCS8`/`_PUBKEY` and
//! `ossl_ml_kem_i2d_pubkey`/`_prvkey`, and `encode_key2text.c`'s three withheld `ML-KEM` tables call
//! `ossl_ml_kem_key_to_text`. None of the four is in §1a's eleven publishers — the measurement the
//! plan's ordering correction records — so it lands here with its ML-DSA sibling and the SLH-DSA
//! printer, and the rows it unblocks follow.
//!
//! ## The primitives are Phase 8's; this is the codec layer over them
//!
//! Every primitive this unit drives already landed with `crypto/ml_kem/` (`src/ml_kem/`):
//! `ossl_ml_kem_key_new`/`_free`, `ossl_ml_kem_parse_public_key`, `ossl_ml_kem_set_seed`,
//! `ossl_ml_kem_encode_public_key`/`_private_key`/`_seed`, the `have_*` predicates and the key
//! struct's `encoded_dk` slot. What is new is the ASN.1: the 22-byte SPKI prefix per variant, the
//! six-row PKCS#8 format table, and the acceptance loop that reads a `PrivateKeyInfo` back into the
//! key object or refuses it at a coordinate.
//!
//! ## The bytes are the contract
//!
//! The six PKCS#8 shapes are not interchangeable: `seed-priv` writes a `PrivateKeyInfo`-style
//! sequence, `priv-only` a bare `OCTET STRING`, `oqskeypair` an OQS private+public string,
//! `seed-only` a two-byte-tagged seed, and `bare-priv`/`bare-seed` the raw bytes with no tag at
//! all. A round-tripping transcription that picked one shape is a different codec; `RT-CODEC`
//! compares the exact bytes and the exact refusal for the rest.
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
use crate::ml_kem::key::{
    ossl_ml_kem_encode_private_key, ossl_ml_kem_encode_public_key, ossl_ml_kem_encode_seed,
    ossl_ml_kem_get_vinfo, ossl_ml_kem_key_free, ossl_ml_kem_parse_public_key,
    ossl_ml_kem_set_seed,
};
use crate::ml_kem::{
    ossl_ml_kem_have_prvkey, ossl_ml_kem_have_pubkey, ossl_ml_kem_have_seed, MlKemKey,
    ML_KEM_SEED_BYTES,
};
use crate::provider::ctx::{ossl_prov_ctx_get_param, prov_libctx_of, ProvCtx};
use crate::provider::ml_common_codecs::{
    load_u16_be, load_u32_be, store_u16_be, store_u32_be, MlCommonCodec, MlCommonPkcs8Fmt,
    MlCommonPkcs8FmtPref, MlCommonSpkiFmt, ML_COMMON_SPKI_OVERHEAD, NUM_PKCS8_FORMATS,
};
use crate::provider::ml_kem_kmgmt::ossl_prov_ml_kem_new;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp};
use crate::runtime::obj::OBJ_obj2nid;
use crate::runtime::secure::CRYPTO_secure_malloc;

/// The unit's own `__FILE__`. `ml_kem_codecs.c` is a plain `.c`, so the compiler records the
/// source-tree path with the build's relative prefix (D235).
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/encode_decode/ml_kem_codecs.c".as_ptr();
/// `ml_kem_codecs.c:388`, `ossl_ml_kem_d2i_PKCS8`'s `OPENSSL_secure_malloc(p8fmt->priv_length)`.
const LINE_SECURE_MALLOC: c_int = 388;
/// `ml_kem_codecs.c:421`, `ossl_ml_kem_i2d_pubkey`'s `OPENSSL_malloc(publen)`.
const LINE_MALLOC_PUB: c_int = 421;
/// `ml_kem_codecs.c:486`, `ossl_ml_kem_i2d_prvkey`'s `OPENSSL_malloc((size_t)len)`.
const LINE_MALLOC: c_int = 486;
/// `ml_kem_codecs.c:586`, `ossl_ml_kem_key_to_text`'s `OPENSSL_malloc(prvlen)`.
const LINE_MALLOC_TO_TEXT_PRV: c_int = 586;
/// `ml_kem_codecs.c:602`, `ossl_ml_kem_key_to_text`'s `OPENSSL_malloc(key->vinfo->pubkey_bytes)`.
const LINE_MALLOC_TO_TEXT_PUB: c_int = 602;

/// `OSSL_PKEY_PARAM_ML_KEM_INPUT_FORMATS` — `core_names.h:433`.
const OSSL_PKEY_PARAM_ML_KEM_INPUT_FORMATS: *const c_char = c"ml-kem.input_formats".as_ptr();
/// `OSSL_PKEY_PARAM_ML_KEM_OUTPUT_FORMATS` — `core_names.h:434`.
const OSSL_PKEY_PARAM_ML_KEM_OUTPUT_FORMATS: *const c_char = c"ml-kem.output_formats".as_ptr();

// ---------------------------------------------------------------------------
// The per-variant tables — `ml_kem_codecs.c:26-218`
// ---------------------------------------------------------------------------

// `ML-KEM-512` public key 800 (0x0320), private key 1632 (0x0660).
/// `ml_kem_512_spkifmt` — `ml_kem_codecs.c:26-51`.
static ML_KEM_512_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x03, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x04, 0x01, 0x03, 0x82, 0x03, 0x21, 0x00,
    ],
};

/// `ml_kem_512_p8fmt[NUM_PKCS8_FORMATS]` — `ml_kem_codecs.c:52-59`.
static ML_KEM_512_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x06aa,
        p8_shift: 0,
        p8_magic: 0x3082_06a6,
        seed_magic: 0x0440,
        seed_offset: 6,
        seed_length: 0x40,
        priv_magic: 0x0482_0660,
        priv_offset: 0x4a,
        priv_length: 0x0660,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x0664,
        p8_shift: 0,
        p8_magic: 0x0482_0660,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0660,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x0984,
        p8_shift: 0,
        p8_magic: 0x0482_0980,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0660,
        pub_offset: 0x0664,
        pub_length: 0x0320,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0042,
        p8_shift: 2,
        p8_magic: 0x8040,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x0660,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x0660,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0040,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// `ML-KEM-768` public key 1184 (0x04a0), private key 2400 (0x0960).
/// `ml_kem_768_spkifmt` — `ml_kem_codecs.c:66-91`.
static ML_KEM_768_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x04, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x04, 0x02, 0x03, 0x82, 0x04, 0xa1, 0x00,
    ],
};

/// `ml_kem_768_p8fmt[NUM_PKCS8_FORMATS]` — `ml_kem_codecs.c:92-164`.
static ML_KEM_768_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x09aa,
        p8_shift: 0,
        p8_magic: 0x3082_09a6,
        seed_magic: 0x0440,
        seed_offset: 6,
        seed_length: 0x40,
        priv_magic: 0x0482_0960,
        priv_offset: 0x4a,
        priv_length: 0x0960,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x0964,
        p8_shift: 0,
        p8_magic: 0x0482_0960,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0960,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x0e04,
        p8_shift: 0,
        p8_magic: 0x0482_0e00,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0960,
        pub_offset: 0x0964,
        pub_length: 0x04a0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0042,
        p8_shift: 2,
        p8_magic: 0x8040,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x0960,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x0960,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0040,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// `ML-KEM-1024` private key 3168 (0x0c60), public key 1568 (0x0620).
/// `ml_kem_1024_spkifmt` — `ml_kem_codecs.c:171-196`.
static ML_KEM_1024_SPKIFMT: MlCommonSpkiFmt = MlCommonSpkiFmt {
    asn1_prefix: [
        0x30, 0x82, 0x06, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x04, 0x03, 0x03, 0x82, 0x06, 0x21, 0x00,
    ],
};

/// `ml_kem_1024_p8fmt[NUM_PKCS8_FORMATS]` — `ml_kem_codecs.c:197-204`.
static ML_KEM_1024_P8FMT: [MlCommonPkcs8Fmt; NUM_PKCS8_FORMATS] = [
    MlCommonPkcs8Fmt {
        p8_name: c"seed-priv".as_ptr(),
        p8_bytes: 0x0caa,
        p8_shift: 0,
        p8_magic: 0x3082_0ca6,
        seed_magic: 0x0440,
        seed_offset: 6,
        seed_length: 0x40,
        priv_magic: 0x0482_0c60,
        priv_offset: 0x4a,
        priv_length: 0x0c60,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"priv-only".as_ptr(),
        p8_bytes: 0x0c64,
        p8_shift: 0,
        p8_magic: 0x0482_0c60,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0c60,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"oqskeypair".as_ptr(),
        p8_bytes: 0x1284,
        p8_shift: 0,
        p8_magic: 0x0482_1280,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0x04,
        priv_length: 0x0c60,
        pub_offset: 0x0c64,
        pub_length: 0x0620,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"seed-only".as_ptr(),
        p8_bytes: 0x0042,
        p8_shift: 2,
        p8_magic: 0x8040,
        seed_magic: 0,
        seed_offset: 2,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-priv".as_ptr(),
        p8_bytes: 0x0c60,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0x0c60,
        pub_offset: 0,
        pub_length: 0,
    },
    MlCommonPkcs8Fmt {
        p8_name: c"bare-seed".as_ptr(),
        p8_bytes: 0x0040,
        p8_shift: 4,
        p8_magic: 0,
        seed_magic: 0,
        seed_offset: 0,
        seed_length: 0x40,
        priv_magic: 0,
        priv_offset: 0,
        priv_length: 0,
        pub_offset: 0,
        pub_length: 0,
    },
];

// Indices of slots in the `codecs` table below.
/// `ML_KEM_512_CODEC` — `ml_kem_codecs.c:207`, slot 0.
const ML_KEM_512_CODEC: usize = 0;
/// `ML_KEM_768_CODEC` — `ml_kem_codecs.c:208`, slot 1.
const ML_KEM_768_CODEC: usize = 1;
/// `ML_KEM_1024_CODEC` — `ml_kem_codecs.c:209`, slot 2.
const ML_KEM_1024_CODEC: usize = 2;

/// `static const ML_COMMON_CODEC codecs[3]` — `ml_kem_codecs.c:214-218`.
static CODECS: [MlCommonCodec; 3] = [
    MlCommonCodec {
        spkifmt: &ML_KEM_512_SPKIFMT,
        p8fmt: ML_KEM_512_P8FMT.as_ptr(),
    },
    MlCommonCodec {
        spkifmt: &ML_KEM_768_SPKIFMT,
        p8fmt: ML_KEM_768_P8FMT.as_ptr(),
    },
    MlCommonCodec {
        spkifmt: &ML_KEM_1024_SPKIFMT,
        p8fmt: ML_KEM_1024_P8FMT.as_ptr(),
    },
];

/// `static const ML_COMMON_CODEC *ml_kem_get_codec(int evp_type)` — `ml_kem_codecs.c:221-232`.
fn ml_kem_get_codec(evp_type: c_int) -> *const MlCommonCodec {
    match evp_type {
        crate::ml_kem::EVP_PKEY_ML_KEM_512 => &CODECS[ML_KEM_512_CODEC],
        crate::ml_kem::EVP_PKEY_ML_KEM_768 => &CODECS[ML_KEM_768_CODEC],
        crate::ml_kem::EVP_PKEY_ML_KEM_1024 => &CODECS[ML_KEM_1024_CODEC],
        _ => ptr::null(),
    }
}

/// Raise `fmt` with one `%s`, filled from `alg`, through `site`.
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

/// The crate's `ossl_ssize_t` (a signed pointer-width integer) for the two length comparisons that
/// the authority spells with a cast.
type OsslSsizeT = i64;

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

/// `ML_KEM_KEY *ossl_ml_kem_d2i_PUBKEY(const uint8_t *pubenc, int publen, int evp_type,`
/// `PROV_CTX *provctx, const char *propq)` — `ml_kem_codecs.c:234-266`.
///
/// # Safety
/// `pubenc` is readable for `publen` bytes; `provctx` is a live provider context; `propq` is NULL or
/// NUL-terminated.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_kem_d2i_PUBKEY`)
pub(crate) unsafe fn ossl_ml_kem_d2i_PUBKEY(
    pubenc: *const u8,
    publen: c_int,
    evp_type: c_int,
    provctx: *mut ProvCtx,
    propq: *const c_char,
) -> *mut MlKemKey {
    // SAFETY: `provctx` is a live context per the contract.
    let libctx = unsafe { prov_libctx_of(provctx.cast()) };
    // SAFETY: the answer is a pointer into `src/ml_kem`'s static table.
    let v = unsafe { ossl_ml_kem_get_vinfo(evp_type) };
    let codec = ml_kem_get_codec(evp_type);
    if v.is_null() || codec.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `codec` is live and dereferenced past the guard.
    let vspki = unsafe { (*codec).spkifmt };
    // SAFETY: `v` and `vspki` are live; `pubenc` is readable for `publen`.
    unsafe {
        if publen != (ML_COMMON_SPKI_OVERHEAD as c_int) + (*v).pubkey_bytes as c_int
            || pubenc.is_null()
            || CRYPTO_memcmp(
                pubenc.cast(),
                (*vspki).asn1_prefix.as_ptr().cast(),
                ML_COMMON_SPKI_OVERHEAD,
            ) != 0
        {
            return ptr::null_mut();
        }
    }
    // SAFETY: `pubenc` is readable for `publen` >= ML_COMMON_SPKI_OVERHEAD bytes per the contract.
    let payload = unsafe { pubenc.add(ML_COMMON_SPKI_OVERHEAD) };
    let payload_len = publen - ML_COMMON_SPKI_OVERHEAD as c_int;

    // SAFETY: `libctx` and `propq` are the caller's; the primitive owns the new key.
    let ret = unsafe { crate::ml_kem::key::ossl_ml_kem_key_new(libctx, propq, evp_type) };
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `payload` is readable for `payload_len` and `ret` is live.
    if unsafe { ossl_ml_kem_parse_public_key(payload, payload_len as usize, ret) } == 0 {
        // SAFETY: `v` is live and `ret` is this frame's key.
        unsafe {
            raise_one(
                &err_sites::ML_KEM_CODECS_258,
                "error parsing ",
                (*v).algorithm_name,
                " public key from input SPKI",
            );
            ossl_ml_kem_key_free(ret);
        }
        return ptr::null_mut();
    }

    ret
}

/// `ML_KEM_KEY *ossl_ml_kem_d2i_PKCS8(const uint8_t *prvenc, int prvlen, int evp_type,`
/// `PROV_CTX *provctx, const char *propq)` — `ml_kem_codecs.c:268-405`.
///
/// # Safety
/// `prvenc` is readable for `prvlen` bytes; `provctx` is a live provider context; `propq` is NULL or
/// NUL-terminated.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_kem_d2i_PKCS8`)
pub(crate) unsafe fn ossl_ml_kem_d2i_PKCS8(
    prvenc: *const u8,
    prvlen: c_int,
    evp_type: c_int,
    provctx: *mut ProvCtx,
    propq: *const c_char,
) -> *mut MlKemKey {
    // SAFETY: the answer is a pointer into `src/ml_kem`'s static table.
    let v = unsafe { ossl_ml_kem_get_vinfo(evp_type) };
    let codec = ml_kem_get_codec(evp_type);
    if v.is_null() || codec.is_null() {
        return ptr::null_mut();
    }

    let mut slots: *mut MlCommonPkcs8FmtPref = ptr::null_mut();
    let mut key: *mut MlKemKey = ptr::null_mut();
    let mut ret: *mut MlKemKey = ptr::null_mut();
    let mut buf: *const c_uchar = ptr::null();
    let mut alg: *const X509Algor = ptr::null();
    let mut len: c_int = 0;
    // SAFETY: `prvlen` is the caller's length and the d2i takes its own pointer-to-pointer.
    let mut cursor = prvenc;
    // SAFETY: the d2i reads `prvlen` bytes from `cursor` and answers a fresh `p8inf`.
    let p8inf = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &mut cursor, prvlen as c_long) };
    if p8inf.is_null() {
        return ptr::null_mut();
    }

    // Everything below shares the `end:` cleanup.
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
            ossl_prov_ctx_get_param(provctx, OSSL_PKEY_PARAM_ML_KEM_INPUT_FORMATS, ptr::null())
        };
        // SAFETY: `v`'s name, `codec`'s table and `formats` are live.
        slots = unsafe {
            crate::provider::ml_common_codecs::ossl_ml_common_pkcs8_fmt_order(
                (*v).algorithm_name,
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
                    &err_sites::ML_KEM_CODECS_312,
                    "unexpected parameters with a PKCS#8 ",
                    (*v).algorithm_name,
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
                if len as OsslSsizeT == (*f).p8_bytes as OsslSsizeT
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
                    &err_sites::ML_KEM_CODECS_335,
                    "no matching enabled ",
                    (*v).algorithm_name,
                    " private key input formats",
                );
            }
            break 'end;
        }
        // SAFETY: `p8fmt` and `v` are live.
        unsafe {
            if ((*p8fmt).seed_length > 0 && (*p8fmt).seed_length != ML_KEM_SEED_BYTES)
                || ((*p8fmt).priv_length > 0 && (*p8fmt).priv_length != (*v).prvkey_bytes)
                || ((*p8fmt).pub_length > 0 && (*p8fmt).pub_length != (*v).pubkey_bytes)
            {
                raise_one(
                    &err_sites::ML_KEM_CODECS_335,
                    "no matching enabled ",
                    (*v).algorithm_name,
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
                pos = pos.add(ML_KEM_SEED_BYTES);
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
                pos = pos.add((*v).prvkey_bytes);
            }
            if (*p8fmt).pub_length > 0 {
                if pos != buf.add((*p8fmt).pub_offset) {
                    break 'end;
                }
                pos = pos.add((*v).pubkey_bytes);
            }
            if pos != buf.add(len as usize) {
                break 'end;
            }

            // Collect the seed and/or key into a "decoded" private key object, to be turned into a
            // real key on provider "load" or "import".
            key = ossl_prov_ml_kem_new(provctx, propq, evp_type);
            if key.is_null() {
                break 'end;
            }

            // The seed is written through the landed `ossl_ml_kem_set_seed` primitive.
            if (*p8fmt).seed_length > 0
                && ossl_ml_kem_set_seed(buf.add((*p8fmt).seed_offset), ML_KEM_SEED_BYTES, key)
                    .is_null()
            {
                raise_one(
                    &err_sites::ML_KEM_CODECS_381,
                    "error storing ",
                    (*v).algorithm_name,
                    " private key seed",
                );
                break 'end;
            }
            if (*p8fmt).priv_length > 0 {
                let dk = CRYPTO_secure_malloc((*p8fmt).priv_length, FILE, LINE_SECURE_MALLOC);
                if dk.is_null() {
                    raise_one(
                        &err_sites::ML_KEM_CODECS_389,
                        "error parsing ",
                        (*v).algorithm_name,
                        " private key",
                    );
                    break 'end;
                }
                (*key).encoded_dk = dk.cast::<u8>();
                ptr::copy_nonoverlapping(
                    buf.add((*p8fmt).priv_offset),
                    (*key).encoded_dk,
                    (*p8fmt).priv_length,
                );
            }
            // Any OQS public key content is ignored.
            ret = key;
        }
    }

    // SAFETY: `slots` is NULL or this frame's list; `p8inf` is live.
    unsafe {
        free_slots(slots, 400);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if ret.is_null() {
            ossl_ml_kem_key_free(key);
        }
    }
    ret
}

/// `int ossl_ml_kem_i2d_pubkey(const ML_KEM_KEY *key, unsigned char **out)` —
/// `ml_kem_codecs.c:408-432`.
///
/// # Safety
/// `key` is live; `out` is NULL or writable for a `*mut c_uchar`.
pub(crate) unsafe fn ossl_ml_kem_i2d_pubkey(key: *const MlKemKey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: `key` is live per the contract.
    let v = unsafe { (*key).vinfo };
    // SAFETY: `key` is live per the contract.
    if !unsafe { ossl_ml_kem_have_pubkey(key) } {
        // SAFETY: `v` is live.
        unsafe {
            raise_one(
                &err_sites::ML_KEM_CODECS_413,
                "no ",
                (*v).algorithm_name,
                " public key data available",
            );
        }
        return 0;
    }
    // SAFETY: `v` is live.
    let publen = unsafe { (*v).pubkey_bytes };

    if out.is_null() {
        return 0;
    }
    // SAFETY: `out` is writable and the allocation is the authority's own.
    let p = CRYPTO_malloc(publen, FILE, LINE_MALLOC_PUB).cast::<c_uchar>();
    if p.is_null() {
        return 0;
    }
    // SAFETY: `out` is writable per the contract.
    unsafe { *out = p };
    // SAFETY: `p` is a live buffer of `publen` bytes; `key` is live.
    if unsafe { ossl_ml_kem_encode_public_key(p, publen, key) } == 0 {
        // SAFETY: `v` is live and `p` is this frame's allocation.
        unsafe {
            raise_one(
                &err_sites::ML_KEM_CODECS_424,
                "error encoding ",
                (*v).algorithm_name,
                " public key",
            );
            CRYPTO_free(p.cast(), FILE, 427);
        }
        return 0;
    }

    publen as c_int
}

/// `int ossl_ml_kem_i2d_prvkey(const ML_KEM_KEY *key, uint8_t **out, PROV_CTX *provctx)` —
/// `ml_kem_codecs.c:435-556`.
///
/// # Safety
/// `key` is live; `out` is NULL or writable for a `*mut u8`; `provctx` is a live provider context.
pub(crate) unsafe fn ossl_ml_kem_i2d_prvkey(
    key: *const MlKemKey,
    out: *mut *mut u8,
    provctx: *mut ProvCtx,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    let v = unsafe { (*key).vinfo };
    // SAFETY: `v` is live per the contract.
    let codec = ml_kem_get_codec(unsafe { (*v).evp_type });
    if codec.is_null() {
        return 0;
    }

    // SAFETY: `key` is live per the contract.
    if !unsafe { ossl_ml_kem_have_prvkey(key) } {
        // SAFETY: `v` is live.
        unsafe {
            raise_one(
                &err_sites::ML_KEM_CODECS_452,
                "no ",
                (*v).algorithm_name,
                " private key data available",
            );
        }
        return 0;
    }

    // SAFETY: `provctx` is live and the name is a static literal.
    let formats = unsafe {
        ossl_prov_ctx_get_param(provctx, OSSL_PKEY_PARAM_ML_KEM_OUTPUT_FORMATS, ptr::null())
    };
    // SAFETY: `v`'s name, `codec`'s table and `formats` are live.
    let fmt_slots = unsafe {
        crate::provider::ml_common_codecs::ossl_ml_common_pkcs8_fmt_order(
            (*v).algorithm_name,
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
                if ossl_ml_kem_have_seed(key) || (*f).seed_length == 0 {
                    p8fmt = f;
                    break;
                }
                slot = slot.add(1);
            }
        }
        // SAFETY: `v` is live.
        unsafe {
            if p8fmt.is_null()
                || ((*p8fmt).seed_length > 0 && (*p8fmt).seed_length != ML_KEM_SEED_BYTES)
                || ((*p8fmt).priv_length > 0 && (*p8fmt).priv_length != (*v).prvkey_bytes)
                || ((*p8fmt).pub_length > 0 && (*p8fmt).pub_length != (*v).pubkey_bytes)
            {
                raise_one(
                    &err_sites::ML_KEM_CODECS_474,
                    "no matching enabled ",
                    (*v).algorithm_name,
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
                        &err_sites::ML_KEM_CODECS_499,
                        "error encoding ",
                        (*v).algorithm_name,
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
                if pos != buf.add((*p8fmt).seed_offset)
                    || ossl_ml_kem_encode_seed(pos, ML_KEM_SEED_BYTES, key) == 0
                {
                    raise_one(
                        &err_sites::ML_KEM_CODECS_514,
                        "error encoding ",
                        (*v).algorithm_name,
                        " private key",
                    );
                    break 'end;
                }
                pos = pos.add(ML_KEM_SEED_BYTES);
            }
            if (*p8fmt).priv_length != 0 {
                if pos.add(4) == buf.add((*p8fmt).priv_offset) {
                    pos = store_u32_be(pos, (*p8fmt).priv_magic);
                }
                if pos != buf.add((*p8fmt).priv_offset)
                    || ossl_ml_kem_encode_private_key(pos, (*v).prvkey_bytes, key) == 0
                {
                    raise_one(
                        &err_sites::ML_KEM_CODECS_526,
                        "error encoding ",
                        (*v).algorithm_name,
                        " private key",
                    );
                    break 'end;
                }
                pos = pos.add((*v).prvkey_bytes);
            }
            // OQS form output with tacked-on public key.
            if (*p8fmt).pub_length != 0 {
                // The OQS pubkey is never separately DER-wrapped.
                if pos != buf.add((*p8fmt).pub_offset)
                    || ossl_ml_kem_encode_public_key(pos, (*v).pubkey_bytes, key) == 0
                {
                    raise_one(
                        &err_sites::ML_KEM_CODECS_538,
                        "error encoding ",
                        (*v).algorithm_name,
                        " private key",
                    );
                    break 'end;
                }
                pos = pos.add((*v).pubkey_bytes);
            }

            if pos == buf.add(len as usize) {
                *out = buf;
                ret = len;
            }
        }
    }

    // SAFETY: `fmt_slots` is NULL or this frame's list; `buf` is NULL or this frame's allocation.
    unsafe {
        free_slots(fmt_slots, 552);
        if ret == 0 {
            CRYPTO_free(buf.cast(), FILE, 554);
        }
    }
    ret
}

/// `int ossl_ml_kem_key_to_text(BIO *out, const ML_KEM_KEY *key, int selection)` —
/// `ml_kem_codecs.c:558-619`.
///
/// # Safety
/// `out` is NULL or live; `key` is NULL or live.
pub(crate) unsafe fn ossl_ml_kem_key_to_text(
    out: *mut Bio,
    key: *const MlKemKey,
    selection: c_int,
) -> c_int {
    if out.is_null() || key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ML_KEM_CODECS_566) };
        return 0;
    }
    // SAFETY: `key` is live past the guard.
    let v = unsafe { (*key).vinfo };
    // SAFETY: `v` is live.
    let (type_label, publen, prvlen) =
        unsafe { ((*v).algorithm_name, (*v).pubkey_bytes, (*v).prvkey_bytes) };
    let mut ret = 0;

    // SAFETY: `key` is live; the encode helpers answer 0 on failure.
    unsafe {
        let mut prvenc: *mut u8 = ptr::null_mut();
        let mut pubenc: *mut u8 = ptr::null_mut();
        let mut seed = [0u8; ML_KEM_SEED_BYTES];

        'end: {
            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && (ossl_ml_kem_have_prvkey(key) || ossl_ml_kem_have_seed(key))
            {
                if BIO_printf(out, c"%s Private-Key:\n".as_ptr(), type_label) <= 0 {
                    break 'end;
                }

                if ossl_ml_kem_have_seed(key) {
                    if ossl_ml_kem_encode_seed(seed.as_mut_ptr(), seed.len(), key) == 0 {
                        break 'end;
                    }
                    if ossl_bio_print_labeled_buf(out, c"seed:".as_ptr(), seed.as_ptr(), seed.len())
                        == 0
                    {
                        break 'end;
                    }
                }
                if ossl_ml_kem_have_prvkey(key) {
                    prvenc = CRYPTO_malloc(prvlen, FILE, LINE_MALLOC_TO_TEXT_PRV).cast::<u8>();
                    if prvenc.is_null() {
                        break 'end;
                    }
                    if ossl_ml_kem_encode_private_key(prvenc, prvlen, key) == 0 {
                        break 'end;
                    }
                    if ossl_bio_print_labeled_buf(out, c"dk:".as_ptr(), prvenc, prvlen) == 0 {
                        break 'end;
                    }
                }
                ret = 1;
            }

            // The public key is output regardless of the selection.
            if ossl_ml_kem_have_pubkey(key) {
                // If we did not output private key bits, this is a public key.
                if ret == 0 && BIO_printf(out, c"%s Public-Key:\n".as_ptr(), type_label) <= 0 {
                    break 'end;
                }

                pubenc = CRYPTO_malloc(publen, FILE, LINE_MALLOC_TO_TEXT_PUB).cast::<u8>();
                if pubenc.is_null()
                    || ossl_ml_kem_encode_public_key(pubenc, publen, key) == 0
                    || ossl_bio_print_labeled_buf(out, c"ek:".as_ptr(), pubenc, publen) == 0
                {
                    break 'end;
                }
                ret = 1;
            }
        }

        // If we got here, and ret == 0, there was no key material.
        if ret == 0 {
            raise_one(
                &err_sites::ML_KEM_CODECS_611,
                "no ",
                type_label,
                " key material available",
            );
        }

        CRYPTO_free(pubenc.cast(), FILE, 616);
        CRYPTO_free(prvenc.cast(), FILE, 617);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each variant's SPKI prefix is 22 bytes and starts with the `SEQUENCE` tag; each PKCS#8 table
    /// has six named shapes with the `seed-priv` first, as the authority's tables do.
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
                assert_eq!(
                    names,
                    vec![
                        b"seed-priv".to_vec(),
                        b"priv-only".to_vec(),
                        b"oqskeypair".to_vec(),
                        b"seed-only".to_vec(),
                        b"bare-priv".to_vec(),
                        b"bare-seed".to_vec()
                    ]
                );
            }
        }
    }

    /// `ml_kem_get_codec` answers each variant's slot and NULL for anything else.
    #[test]
    fn the_codec_lookup_is_the_three_variants() {
        assert!(core::ptr::eq(
            ml_kem_get_codec(crate::ml_kem::EVP_PKEY_ML_KEM_512),
            &CODECS[ML_KEM_512_CODEC]
        ));
        assert!(core::ptr::eq(
            ml_kem_get_codec(crate::ml_kem::EVP_PKEY_ML_KEM_1024),
            &CODECS[ML_KEM_1024_CODEC]
        ));
        assert!(ml_kem_get_codec(0).is_null());
    }
}
