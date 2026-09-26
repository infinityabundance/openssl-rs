//! `crypto/pem/pvkfmt.c` — the PVK file format and the Microsoft PUBLICKEYBLOB/PRIVATEKEYBLOB
//! structure. Phase 10.6.
//!
//! Ten of the twenty-six hand-off exports are here: the four `b2i_*` readers of a bare blob, the
//! two `i2b_*` writers, the two PVK readers (`b2i_PVK_bio(_ex)`) and the two PVK writers
//! (`i2b_PVK_bio(_ex)`). The unit also carries the internal helpers `crypto/pem/pem_local.h` names
//! and no header exports: `ossl_do_blob_header`, `ossl_blob_length`, `ossl_b2i_RSA_after_header`
//! and `ossl_b2i_DSA_after_header` (which `decode_msblob2key.c`'s two rows call) and
//! `b2i_RSA_PVK_bio_ex`/`b2i_DSA_PVK_bio_ex` (which `decode_pvk2key.c`'s two rows call). Those
//! four are `pub(crate)` for that reason, not `#[no_mangle]`: the authority's `include/crypto/pem.h`
//! declares them internally and they are not in `libcrypto.so.3`'s export set (measured:
//! `symbols-libcrypto.json` carries none of them).
//!
//! ## The two formats, and what is the contract
//!
//! A **blob** is little-endian throughout: a 16-byte header (`bType`, version, reserved,
//! `aiKeyAlg`, magic, `bitlen`) followed by the key's components, each a fixed-width little-endian
//! integer. `ossl_do_blob_header` validates the header and answers the magic and bit length; the
//! `*_after_header` pair turns the body into an `RSA *`/`DSA *`.
//!
//! A **PVK** file is the same blob with a 24-byte header in front (magic `0xb0b5f11e`, key type,
//! encryption flag, salt length, key length). An unencrypted PVK is the header plus the blob
//! verbatim; an encrypted one runs the blob's bytes through RC4 with a key derived by the
//! `PVKKDF` KDF. **The encrypted arm needs two provider implementations that are not landed** —
//! `PVKKDF` and the `RC4` cipher live in the `legacy` provider (`ossl_kdf_pvk_functions`,
//! `ossl_rc4128_functions`) and the crate publishes neither — so `EVP_KDF_fetch`/`EVP_CIPHER_fetch`
//! answer NULL and the arm refuses where the authority decrypts. `RT-KEYFORMAT` drives the
//! unencrypted arm and holds the encrypted one `pending` with that reason (`docs/PHASE-10-
//! SUBPHASES.md` §3.5). The code is transcribed whole: the refusal is a runtime fetch, not an
//! omitted call.
//!
//! ## The `b2i_PVK_bio_ex` argument pass-through is the authority's own quirk
//!
//! `b2i_PVK_bio_ex` (`:1013-1021`) accepts `libctx`/`propq` and then calls `do_PVK_key_bio(…,
//! NULL, NULL)` — it drops both. That is transcribed as written rather than "fixed", because the
//! observed contract is the authority's behaviour; the asymmetry with `b2i_RSA_PVK_bio_ex` (which
//! forwards them) is a property of the pinned source.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::too_many_arguments)] // every signature mirrors the authority's

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::bn::arith::BN_mod_exp;
use crate::bn::bignum::{
    BN_bn2lebinpad, BN_free, BN_lebin2bn, BN_new, BN_num_bits, BN_set_flags, BN_set_word, BigNum,
    BN_FLG_CONSTTIME,
};
use crate::dsa::object::{
    DSA_free, DSA_get0_key, DSA_get0_pqg, DSA_new, DSA_set0_key, DSA_set0_pqg,
};
use crate::dsa::Dsa;
use crate::evp::cipher::{EVP_CIPHER_fetch, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::kdf::{EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EvpKdf};
use crate::evp::p_legacy_assign::{EVP_PKEY_get0_RSA, EVP_PKEY_set1_RSA};
use crate::evp::pem_bridge::PemPasswordCb;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get0_DSA, EVP_PKEY_get_id, EVP_PKEY_is_a, EVP_PKEY_new,
    EVP_PKEY_set1_DSA, EvpPkey,
};
use crate::params::{OSSL_PARAM_construct_end, OsslParam};
use crate::pem::pem_lib::{PEM_def_callback, PEM_BUFSIZE};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::rsa::object::{
    RSA_bits, RSA_free, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_new,
    RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_size,
};
use crate::rsa::Rsa;
use crate::runtime::bio::{BIO_read, BIO_write, Bio};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};

/// `BN_CTX`/`BN_CTX_new`/`BN_CTX_free` — the modular-exponentiation context the DSA public-key
/// recovery needs.
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BnCtx};

/// `EVP_PKEY_RSA` / `EVP_PKEY_DSA` — the two ids this unit's `switch`es name.
const EVP_PKEY_RSA: c_int = 6;
const EVP_PKEY_DSA: c_int = 116;

/// `#define MS_PUBLICKEYBLOB 0x6` and its siblings — `crypto/pem/pvkfmt.c:128-142`.
const MS_PUBLICKEYBLOB: c_uchar = 0x6;
const MS_PRIVATEKEYBLOB: c_uchar = 0x7;
const MS_RSA1MAGIC: c_uint = 0x3141_5352;
const MS_RSA2MAGIC: c_uint = 0x3241_5352;
const MS_DSS1MAGIC: c_uint = 0x3153_5344;
const MS_DSS2MAGIC: c_uint = 0x3253_5344;
const MS_KEYALG_RSA_KEYX: c_uint = 0xa400;
const MS_KEYALG_DSS_SIGN: c_uint = 0x2200;
const MS_KEYTYPE_KEYX: c_uint = 0x1;
const MS_KEYTYPE_SIGN: c_uint = 0x2;
const MS_PVKMAGIC: c_uint = 0xb0b5_f11e;
const PVK_SALTLEN: c_uint = 0x10;
const PVK_MAX_KEYLEN: c_uint = 102400;
const PVK_MAX_SALTLEN: c_uint = 10240;
/// `BLOB_MAX_LENGTH` — `include/crypto/pem.h:20`.
const BLOB_MAX_LENGTH: c_uint = 102400;

/// `OSSL_KDF_PARAM_SALT`/`_PASSWORD`/`_DIGEST`/`_PROPERTIES` — `core_names.h`, module-private
/// elsewhere in the crate, so spelled from their names as `p5_crpt.c` does.
const OSSL_KDF_PARAM_SALT: *const c_char = c"salt".as_ptr();
const OSSL_KDF_PARAM_PASSWORD: *const c_char = c"pass".as_ptr();
const OSSL_KDF_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
const OSSL_KDF_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();
/// `SN_sha1` — `obj_mac.h`, the short name the PVKKDF is asked to use.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();

/// `BN_num_bytes(a)` — `include/openssl/bn.h`, `(BN_num_bits(a)+7)/8`.
///
/// # Safety
/// `a` must be live.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: `a` is live per the contract.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// `static unsigned int read_ledword(const unsigned char **in)` — `pvkfmt.c:37-48`.
///
/// # Safety
/// `in` must point at a readable cursor for at least four bytes.
unsafe fn read_ledword(in_: *mut *const c_uchar) -> c_uint {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };
    // SAFETY: four readable bytes follow `p`, and each read advances the local cursor.
    let ret = unsafe {
        let b0 = c_uint::from(*p);
        p = p.add(1);
        let b1 = c_uint::from(*p) << 8;
        p = p.add(1);
        let b2 = c_uint::from(*p) << 16;
        p = p.add(1);
        let b3 = c_uint::from(*p) << 24;
        p = p.add(1);
        b0 | b1 | b2 | b3
    };
    // SAFETY: `in` is the caller's writable cursor slot.
    unsafe { *in_ = p };
    ret
}

/// `static int read_lebn(const unsigned char **in, unsigned int nbyte, BIGNUM **r)` —
/// `pvkfmt.c:55-62`.
///
/// # Safety
/// `in` must point at a readable cursor for `nbyte` bytes; `r` must be a writable slot.
unsafe fn read_lebn(in_: *mut *const c_uchar, nbyte: c_uint, r: *mut *mut BigNum) -> c_int {
    // SAFETY: `in` is the caller's readable cursor and `r` a writable slot.
    unsafe {
        *r = BN_lebin2bn(*in_, nbyte as c_int, ptr::null_mut());
        if (*r).is_null() {
            return 0;
        }
        *in_ = (*in_).add(nbyte as usize);
    }
    1
}

/// `static EVP_PKEY *evp_pkey_new0_key(void *key, int evp_type)` — `pvkfmt.c:73-124`.
///
/// Takes ownership of `key` when `evp_type` is RSA or DSA. The engine/IPv6 pieces of the original
/// `EVP_PKEY_assign` path are the crate's own `EVP_PKEY_set1_*`, which is the same reference-count
/// transfer.
///
/// # Safety
/// `key` must be a live `RSA *`/`DSA *` or NULL.
unsafe fn evp_pkey_new0_key(key: *mut c_void, evp_type: c_int) -> *mut EvpPkey {
    if key.is_null() {
        return ptr::null_mut();
    }
    if !(evp_type == EVP_PKEY_RSA || evp_type == EVP_PKEY_DSA) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_85) };
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if !pkey.is_null() {
        let ok = if evp_type == EVP_PKEY_RSA {
            // SAFETY: `pkey` is live and `key` is the RSA the caller transferred.
            (unsafe { EVP_PKEY_set1_RSA(pkey, key.cast::<Rsa>()) }) != 0
        } else {
            // SAFETY: `pkey` is live and `key` is the DSA the caller transferred.
            (unsafe { EVP_PKEY_set1_DSA(pkey, key.cast::<Dsa>()) }) != 0
        };
        if !ok {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_94) };
            // SAFETY: `pkey` is live and this call owns it.
            unsafe { EVP_PKEY_free(pkey) };
            let pkey = ptr::null_mut();
            // SAFETY: the two low-level frees below own `key`; the type check above made it one of
            // the two.
            unsafe { free_low_level(key, evp_type) };
            return pkey;
        }
    } else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_109) };
    }

    // SAFETY: `key` is the low-level key the caller transferred for this type.
    unsafe { free_low_level(key, evp_type) };
    pkey
}

/// The authority's trailing `switch (evp_type)` in `evp_pkey_new0_key` (`:112-121`), which frees
/// the low-level key whichever way the `EVP_PKEY` construction went — `EVP_PKEY_set1_*` took its
/// own reference.
///
/// # Safety
/// `key` must be a live low-level key of `evp_type`, or NULL.
unsafe fn free_low_level(key: *mut c_void, evp_type: c_int) {
    if evp_type == EVP_PKEY_RSA {
        // SAFETY: `key` is the RSA the caller transferred.
        unsafe { RSA_free(key.cast::<Rsa>()) };
    } else {
        // SAFETY: `key` is the DSA the caller transferred.
        unsafe { DSA_free(key.cast::<Dsa>()) };
    }
}

/// `int ossl_do_blob_header(const unsigned char **in, unsigned int length, unsigned int *pmagic,
/// unsigned int *pbitlen, int *pisdss, int *pispub)` — `pvkfmt.c:164-252`.
///
/// # Safety
/// `in` must point at a readable cursor for `length` bytes; the four out-parameters writable.
pub(crate) unsafe fn ossl_do_blob_header(
    in_: *mut *const c_uchar,
    length: c_uint,
    pmagic: *mut c_uint,
    pbitlen: *mut c_uint,
    pisdss: *mut c_int,
    pispub: *mut c_int,
) -> c_int {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };

    if length < 16 {
        return 0;
    }
    // SAFETY: at least 16 bytes are readable from `p`.
    let btype = unsafe { *p };
    match btype {
        MS_PUBLICKEYBLOB => {
            // SAFETY: `pispub` is writable per the contract.
            if unsafe { *pispub } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_176) };
                return 0;
            }
            // SAFETY: `pispub` is writable.
            unsafe { *pispub = 1 };
        }
        MS_PRIVATEKEYBLOB => {
            // SAFETY: `pispub` is writable per the contract.
            if unsafe { *pispub } == 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_184) };
                return 0;
            }
            // SAFETY: `pispub` is writable.
            unsafe { *pispub = 0 };
        }
        _ => return 0,
    }
    // SAFETY: the read advances the cursor within the 16-byte header.
    let version = unsafe {
        p = p.add(1);
        *p
    };
    if version != 0x2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_196) };
        return 0;
    }
    // SAFETY: the cursor advances six reserved bytes and reads the two little-endian words.
    unsafe {
        p = p.add(1 + 6);
        *pmagic = read_ledword(&raw mut p);
        *pbitlen = read_ledword(&raw mut p);
    }

    // SAFETY: `pmagic`/`pispub`/`pisdss` are writable per the contract.
    let magic = unsafe { *pmagic };
    match magic {
        MS_DSS1MAGIC | MS_RSA1MAGIC => {
            // SAFETY: `pispub` is writable.
            if unsafe { *pispub } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_209) };
                return 0;
            }
        }
        MS_DSS2MAGIC | MS_RSA2MAGIC => {
            // SAFETY: `pispub` is writable.
            if unsafe { *pispub } == 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_217) };
                return 0;
            }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_223) };
            return -1;
        }
    }

    match magic {
        MS_DSS1MAGIC | MS_DSS2MAGIC => {
            // SAFETY: `pisdss` is writable.
            if unsafe { *pisdss } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_232) };
                return 0;
            }
            // SAFETY: `pisdss` is writable.
            unsafe { *pisdss = 1 };
        }
        MS_RSA1MAGIC | MS_RSA2MAGIC => {
            // SAFETY: `pisdss` is writable.
            if unsafe { *pisdss } == 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_240) };
                return 0;
            }
            // SAFETY: `pisdss` is writable.
            unsafe { *pisdss = 0 };
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_247) };
            return -1;
        }
    }
    // SAFETY: `in` is the caller's writable cursor slot.
    unsafe { *in_ = p };
    1
}

/// `unsigned int ossl_blob_length(unsigned bitlen, int isdss, int ispub)` — `pvkfmt.c:254-284`.
///
/// Pure arithmetic, so no safety contract.
pub(crate) fn ossl_blob_length(bitlen: c_uint, isdss: c_int, ispub: c_int) -> c_uint {
    let nbyte = (bitlen + 7) >> 3;
    let hnbyte = (bitlen + 15) >> 4;

    if isdss != 0 {
        if ispub != 0 {
            44 + 3 * nbyte
        } else {
            64 + 2 * nbyte
        }
    } else if ispub != 0 {
        4 + nbyte
    } else {
        4 + 2 * nbyte + 5 * hnbyte
    }
}

/// `static void *do_b2i_key(const unsigned char **in, unsigned int length, int *isdss, int *ispub)`
/// — `pvkfmt.c:286-315`.
///
/// # Safety
/// `in`/`isdss`/`ispub` as [`ossl_do_blob_header`] plus the `i2d` cursor contract.
unsafe fn do_b2i_key(
    in_: *mut *const c_uchar,
    length: c_uint,
    isdss: *mut c_int,
    ispub: *mut c_int,
) -> *mut c_void {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };
    let mut bitlen: c_uint = 0;
    let mut magic: c_uint = 0;
    let mut len = length;

    // SAFETY: `p`, `isdss`, `ispub` are the caller's; `magic`/`bitlen` are this frame's.
    if unsafe {
        ossl_do_blob_header(
            &raw mut p,
            length,
            &raw mut magic,
            &raw mut bitlen,
            isdss,
            ispub,
        )
    } <= 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_294) };
        return ptr::null_mut();
    }
    len -= 16;
    // SAFETY: `isdss`/`ispub` are the caller's readable slots.
    let (dss, pub_) = unsafe { (*isdss, *ispub) };
    if len < ossl_blob_length(bitlen, dss, pub_) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_299) };
        return ptr::null_mut();
    }
    let key: *mut c_void = if dss == 0 {
        // SAFETY: `p` is the blob body cursor and `pub_` its flag.
        unsafe { ossl_b2i_RSA_after_header(&raw mut p, bitlen, pub_).cast::<c_void>() }
    } else {
        // SAFETY: `p` is the blob body cursor and `pub_` its flag.
        unsafe { ossl_b2i_DSA_after_header(&raw mut p, bitlen, pub_).cast::<c_void>() }
    };

    if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_310) };
        return ptr::null_mut();
    }
    key
}

/// `#define isdss_to_evp_type(isdss)` — `pvkfmt.c:70-72`.
fn isdss_to_evp_type(isdss: c_int) -> c_int {
    if isdss == 0 {
        EVP_PKEY_RSA
    } else if isdss == 1 {
        EVP_PKEY_DSA
    } else {
        crate::evp::pkey::EVP_PKEY_NONE
    }
}

/// `EVP_PKEY *ossl_b2i(const unsigned char **in, unsigned int length, int *ispub)` —
/// `pvkfmt.c:317-323`.
///
/// # Safety
/// As [`do_b2i_key`].
pub(crate) unsafe fn ossl_b2i(
    in_: *mut *const c_uchar,
    length: c_uint,
    ispub: *mut c_int,
) -> *mut EvpPkey {
    let mut isdss: c_int = -1;
    // SAFETY: `in`/`ispub` are the caller's and `isdss` is this frame's.
    let key = unsafe { do_b2i_key(in_, length, &raw mut isdss, ispub) };
    // SAFETY: `key` is NULL or the low-level key `do_b2i_key` made.
    unsafe { evp_pkey_new0_key(key, isdss_to_evp_type(isdss)) }
}

/// `EVP_PKEY *ossl_b2i_bio(BIO *in, int *ispub)` — `pvkfmt.c:325-372`.
///
/// # Safety
/// `in` must be a live BIO; `ispub` a writable slot.
pub(crate) unsafe fn ossl_b2i_bio(in_: *mut Bio, ispub: *mut c_int) -> *mut EvpPkey {
    let mut hdr_buf = [0 as c_uchar; 16];
    let mut bitlen: c_uint = 0;
    let mut magic: c_uint = 0;
    let mut isdss: c_int = -1;

    // SAFETY: `in` is live and `hdr_buf` is 16 bytes.
    if unsafe { BIO_read(in_, hdr_buf.as_mut_ptr().cast::<c_void>(), 16) } != 16 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_335) };
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = hdr_buf.as_ptr();
    // SAFETY: `p`, `ispub` are this frame's; `isdss` is a local.
    if unsafe {
        ossl_do_blob_header(
            &raw mut p,
            16,
            &raw mut magic,
            &raw mut bitlen,
            &raw mut isdss,
            ispub,
        )
    } <= 0
    {
        return ptr::null_mut();
    }

    // SAFETY: `ispub` is a readable slot.
    let length = ossl_blob_length(bitlen, isdss, unsafe { *ispub });
    if length > BLOB_MAX_LENGTH {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_344) };
        return ptr::null_mut();
    }
    // SAFETY: `length` bytes as a raw allocation.
    let buf = CRYPTO_malloc(length as usize, ptr::null(), 0).cast::<c_uchar>();
    if buf.is_null() {
        return ptr::null_mut();
    }
    p = buf;
    // SAFETY: `buf` holds `length` bytes and `in` is live.
    if unsafe { BIO_read(in_, buf.cast::<c_void>(), length as c_int) } != length as c_int {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_352) };
        // SAFETY: `buf` is this frame's allocation.
        unsafe { CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0) };
        return ptr::null_mut();
    }

    // SAFETY: `ispub` is a readable slot.
    let pub_ = unsafe { *ispub };
    let key: *mut c_void = if isdss == 0 {
        // SAFETY: `p` is the blob body cursor.
        unsafe { ossl_b2i_RSA_after_header(&raw mut p, bitlen, pub_).cast::<c_void>() }
    } else {
        // SAFETY: `p` is the blob body cursor.
        unsafe { ossl_b2i_DSA_after_header(&raw mut p, bitlen, pub_).cast::<c_void>() }
    };

    let pkey = if key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_364) };
        ptr::null_mut()
    } else {
        // SAFETY: `key` is the low-level key just decoded.
        unsafe { evp_pkey_new0_key(key, isdss_to_evp_type(isdss)) }
    };
    // SAFETY: `buf` is this frame's allocation.
    unsafe { CRYPTO_free(buf.cast::<c_void>(), ptr::null(), 0) };
    pkey
}

/// `DSA *ossl_b2i_DSA_after_header(const unsigned char **in, unsigned int bitlen, int ispub)` —
/// `pvkfmt.c:375-445`.
///
/// # Safety
/// `in` must point at a readable cursor for the DSA body.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_b2i_DSA_after_header(
    in_: *mut *const c_uchar,
    bitlen: c_uint,
    ispub: c_int,
) -> *mut Dsa {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut pbn: *mut BigNum = ptr::null_mut();
    let mut qbn: *mut BigNum = ptr::null_mut();
    let mut gbn: *mut BigNum = ptr::null_mut();
    let mut priv_key: *mut BigNum = ptr::null_mut();
    let mut pub_key: *mut BigNum = ptr::null_mut();
    let nbyte = (bitlen + 7) >> 3;

    // SAFETY: no preconditions.
    let dsa = unsafe { DSA_new() };
    if dsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_431) };
        return ptr::null_mut();
    }
    // SAFETY: `p` is the caller's cursor and `pbn` is this frame's slot.
    if unsafe { read_lebn(&raw mut p, nbyte, &raw mut pbn) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_434) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
        return ptr::null_mut();
    }
    // SAFETY: as above.
    if unsafe { read_lebn(&raw mut p, 20, &raw mut qbn) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_434) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
        return ptr::null_mut();
    }
    // SAFETY: as above.
    if unsafe { read_lebn(&raw mut p, nbyte, &raw mut gbn) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_434) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
        return ptr::null_mut();
    }

    if ispub != 0 {
        // SAFETY: `p` is the caller's cursor and `pub_key` is this frame's slot.
        if unsafe { read_lebn(&raw mut p, nbyte, &raw mut pub_key) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_434) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `p` is the caller's cursor and `priv_key` is this frame's slot.
        if unsafe { read_lebn(&raw mut p, 20, &raw mut priv_key) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_434) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
            return ptr::null_mut();
        }
        // SAFETY: `priv_key` is live and this is the authority's constant-time flag.
        unsafe { BN_set_flags(priv_key, BN_FLG_CONSTTIME) };

        /* Calculate public key */
        // SAFETY: no preconditions.
        pub_key = unsafe { BN_new() };
        if pub_key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_434) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        ctx = unsafe { BN_CTX_new() };
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_434) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
            return ptr::null_mut();
        }
        // SAFETY: all four are live.
        if unsafe { BN_mod_exp(pub_key, gbn, priv_key, pbn, ctx) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_434) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is this frame's own.
        unsafe { BN_CTX_free(ctx) };
        ctx = ptr::null_mut();
    }
    // SAFETY: `dsa` is live and the three BIGNUMs are this frame's own.
    if unsafe { DSA_set0_pqg(dsa, pbn, qbn, gbn) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_431) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
        return ptr::null_mut();
    }
    pbn = ptr::null_mut();
    qbn = ptr::null_mut();
    gbn = ptr::null_mut();
    // SAFETY: `dsa` is live and the two BIGNUMs are this frame's own.
    if unsafe { DSA_set0_key(dsa, pub_key, priv_key) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_431) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { dsa_bn_err(dsa, pbn, qbn, gbn, pub_key, priv_key, ctx) };
        return ptr::null_mut();
    }
    // SAFETY: `in` is the caller's writable cursor.
    unsafe { *in_ = p };
    dsa
}

/// The authority's `err:` label of `ossl_b2i_DSA_after_header` (`:436-444`), as one function.
///
/// # Safety
/// Every pointer must be NULL or a live object of its named type.
unsafe fn dsa_bn_err(
    dsa: *mut Dsa,
    pbn: *mut BigNum,
    qbn: *mut BigNum,
    gbn: *mut BigNum,
    pub_key: *mut BigNum,
    priv_key: *mut BigNum,
    ctx: *mut BnCtx,
) {
    // SAFETY: each pointer is NULL or live per the contract.
    unsafe {
        DSA_free(dsa);
        BN_free(pbn);
        BN_free(qbn);
        BN_free(gbn);
        BN_free(pub_key);
        BN_free(priv_key);
        BN_CTX_free(ctx);
    }
}

/// `RSA *ossl_b2i_RSA_after_header(const unsigned char **in, unsigned int bitlen, int ispub)` —
/// `pvkfmt.c:448-512`.
///
/// # Safety
/// `in` must point at a readable cursor for the RSA body.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_b2i_RSA_after_header(
    in_: *mut *const c_uchar,
    bitlen: c_uint,
    ispub: c_int,
) -> *mut Rsa {
    // SAFETY: `in` is the caller's readable cursor.
    let mut pin = unsafe { *in_ };
    let mut n: *mut BigNum = ptr::null_mut();
    let mut d: *mut BigNum = ptr::null_mut();
    let mut p: *mut BigNum = ptr::null_mut();
    let mut q: *mut BigNum = ptr::null_mut();
    let mut dmp1: *mut BigNum = ptr::null_mut();
    let mut dmq1: *mut BigNum = ptr::null_mut();
    let mut iqmp: *mut BigNum = ptr::null_mut();
    let nbyte = (bitlen + 7) >> 3;
    let hnbyte = (bitlen + 15) >> 4;

    // SAFETY: no preconditions.
    let rsa = unsafe { RSA_new() };
    if rsa.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_496) };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let e = unsafe { BN_new() };
    if e.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_499) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
        return ptr::null_mut();
    }
    // SAFETY: `pin` is the caller's cursor and `e` is this frame's.
    if unsafe { BN_set_word(e, c_ulong::from(read_ledword(&raw mut pin))) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_499) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
        return ptr::null_mut();
    }
    // SAFETY: the cursor and slot are this frame's.
    if unsafe { read_lebn(&raw mut pin, nbyte, &raw mut n) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_499) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
        return ptr::null_mut();
    }
    if ispub == 0 {
        // SAFETY: the cursor and each slot are this frame's.
        if unsafe { read_lebn(&raw mut pin, hnbyte, &raw mut p) } == 0
            // SAFETY: as the first read; `pin` and `q` are this frame's.
            || unsafe { read_lebn(&raw mut pin, hnbyte, &raw mut q) } == 0
            // SAFETY: as the first read; `pin` and `dmp1` are this frame's.
            || unsafe { read_lebn(&raw mut pin, hnbyte, &raw mut dmp1) } == 0
            // SAFETY: as the first read; `pin` and `dmq1` are this frame's.
            || unsafe { read_lebn(&raw mut pin, hnbyte, &raw mut dmq1) } == 0
            // SAFETY: as the first read; `pin` and `iqmp` are this frame's.
            || unsafe { read_lebn(&raw mut pin, hnbyte, &raw mut iqmp) } == 0
            // SAFETY: as the first read; `pin` and `d` are this frame's.
            || unsafe { read_lebn(&raw mut pin, nbyte, &raw mut d) } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_499) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
            return ptr::null_mut();
        }
        // SAFETY: `rsa` is live and the two factors are this frame's own.
        if unsafe { RSA_set0_factors(rsa, p, q) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_496) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
            return ptr::null_mut();
        }
        p = ptr::null_mut();
        q = ptr::null_mut();
        // SAFETY: `rsa` is live and the three CRT parameters are this frame's own.
        if unsafe { RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_496) };
            // SAFETY: every pointer is NULL or this frame's own.
            unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
            return ptr::null_mut();
        }
        dmp1 = ptr::null_mut();
        dmq1 = ptr::null_mut();
        iqmp = ptr::null_mut();
    }
    // SAFETY: `rsa` is live and the three components are this frame's own.
    if unsafe { RSA_set0_key(rsa, n, e, d) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_496) };
        // SAFETY: every pointer is NULL or this frame's own.
        unsafe { rsa_bn_err(rsa, e, n, p, q, dmp1, dmq1, iqmp, d) };
        return ptr::null_mut();
    }
    // SAFETY: `in` is the caller's writable cursor.
    unsafe { *in_ = pin };
    rsa
}

/// The authority's `err:` label of `ossl_b2i_RSA_after_header` (`:501-511`).
///
/// # Safety
/// Every pointer must be NULL or a live object of its named type.
unsafe fn rsa_bn_err(
    rsa: *mut Rsa,
    e: *mut BigNum,
    n: *mut BigNum,
    p: *mut BigNum,
    q: *mut BigNum,
    dmp1: *mut BigNum,
    dmq1: *mut BigNum,
    iqmp: *mut BigNum,
    d: *mut BigNum,
) {
    // SAFETY: each pointer is NULL or live per the contract.
    unsafe {
        BN_free(e);
        BN_free(n);
        BN_free(p);
        BN_free(q);
        BN_free(dmp1);
        BN_free(dmq1);
        BN_free(iqmp);
        BN_free(d);
        RSA_free(rsa);
    }
}

/// `EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length)` — `pvkfmt.c:514-519`.
///
/// # Safety
/// `in` must point at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn b2i_PrivateKey(in_: *mut *const c_uchar, length: c_long) -> *mut EvpPkey {
    let mut ispub: c_int = 0;
    // SAFETY: `in`/`ispub` are this call's own.
    unsafe { ossl_b2i(in_, length as c_uint, &raw mut ispub) }
}

/// `EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length)` — `pvkfmt.c:521-526`.
///
/// # Safety
/// `in` must point at a readable cursor for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn b2i_PublicKey(in_: *mut *const c_uchar, length: c_long) -> *mut EvpPkey {
    let mut ispub: c_int = 1;
    // SAFETY: `in`/`ispub` are this call's own.
    unsafe { ossl_b2i(in_, length as c_uint, &raw mut ispub) }
}

/// `EVP_PKEY *b2i_PrivateKey_bio(BIO *in)` — `pvkfmt.c:528-533`.
///
/// # Safety
/// `in` must be a live BIO.
#[no_mangle]
pub unsafe extern "C" fn b2i_PrivateKey_bio(in_: *mut Bio) -> *mut EvpPkey {
    let mut ispub: c_int = 0;
    // SAFETY: `in`/`ispub` are this call's own.
    unsafe { ossl_b2i_bio(in_, &raw mut ispub) }
}

/// `EVP_PKEY *b2i_PublicKey_bio(BIO *in)` — `pvkfmt.c:535-540`.
///
/// # Safety
/// `in` must be a live BIO.
#[no_mangle]
pub unsafe extern "C" fn b2i_PublicKey_bio(in_: *mut Bio) -> *mut EvpPkey {
    let mut ispub: c_int = 1;
    // SAFETY: `in`/`ispub` are this call's own.
    unsafe { ossl_b2i_bio(in_, &raw mut ispub) }
}

/// `static void write_ledword(unsigned char **out, unsigned int dw)` — `pvkfmt.c:542-551`.
///
/// # Safety
/// `out` must point at a writable cursor for four bytes.
unsafe fn write_ledword(out: *mut *mut c_uchar, dw: c_uint) {
    // SAFETY: `out` is the caller's writable cursor slot.
    let mut p = unsafe { *out };
    // SAFETY: four writable bytes follow `p`.
    unsafe {
        *p = (dw & 0xff) as c_uchar;
        p = p.add(1);
        *p = ((dw >> 8) & 0xff) as c_uchar;
        p = p.add(1);
        *p = ((dw >> 16) & 0xff) as c_uchar;
        p = p.add(1);
        *p = ((dw >> 24) & 0xff) as c_uchar;
        p = p.add(1);
    }
    // SAFETY: `out` is the caller's writable cursor slot.
    unsafe { *out = p };
}

/// `static void write_lebn(unsigned char **out, const BIGNUM *bn, int len)` — `pvkfmt.c:553-557`.
///
/// # Safety
/// `out` must point at a writable cursor for `len` bytes; `bn` must be live.
unsafe fn write_lebn(out: *mut *mut c_uchar, bn: *const BigNum, len: c_int) {
    // SAFETY: `bn` is live and `*out` is writable for `len` bytes.
    unsafe { BN_bn2lebinpad(bn, *out, len) };
    // SAFETY: `out` is the caller's writable cursor slot.
    unsafe { *out = (*out).add(len as usize) };
}

/// `static int do_i2b(unsigned char **out, const EVP_PKEY *pk, int ispub)` — `pvkfmt.c:567-619`.
///
/// # Safety
/// `out` NULL or a writable cursor; `pk` live.
unsafe fn do_i2b(out: *mut *mut c_uchar, pk: *const EvpPkey, ispub: c_int) -> c_int {
    let mut bitlen: c_uint = 0;
    let mut magic: c_uint = 0;
    let mut keyalg: c_uint = 0;
    let mut outlen: c_int = -1;
    let mut noinc = 0;

    // SAFETY: `pk` is live and the name is a literal.
    if unsafe { EVP_PKEY_is_a(pk, c"RSA".as_ptr()) } != 0 {
        // SAFETY: `pk` is live and `EVP_PKEY_get0_RSA` reads its own key.
        let rsa = unsafe { EVP_PKEY_get0_RSA(pk) };
        // SAFETY: `rsa` is the key `pk` holds; `magic` is this frame's out-parameter.
        bitlen = unsafe { check_bitlen_rsa(rsa, ispub, &raw mut magic) } as c_uint;
        keyalg = MS_KEYALG_RSA_KEYX;
    // SAFETY: `pk` is live and the name is a literal.
    } else if unsafe { EVP_PKEY_is_a(pk, c"DSA".as_ptr()) } != 0 {
        // SAFETY: `pk` is live and `EVP_PKEY_get0_DSA` reads its own key.
        let dsa = unsafe { EVP_PKEY_get0_DSA(pk) };
        // SAFETY: `dsa` is the key `pk` holds; `magic` is this frame's out-parameter.
        bitlen = unsafe { check_bitlen_dsa(dsa, ispub, &raw mut magic) } as c_uint;
        keyalg = MS_KEYALG_DSS_SIGN;
    }
    if bitlen == 0 {
        return outlen;
    }
    outlen =
        16 + ossl_blob_length(bitlen, c_int::from(keyalg == MS_KEYALG_DSS_SIGN), ispub) as c_int;
    if out.is_null() {
        return outlen;
    }
    let mut p: *mut c_uchar;
    // SAFETY: `out` is the caller's cursor slot.
    if !unsafe { *out }.is_null() {
        // SAFETY: `*out` is the caller's buffer.
        p = unsafe { *out };
    } else {
        // SAFETY: `outlen` bytes as a raw allocation.
        p = CRYPTO_malloc(outlen as usize, ptr::null(), 0).cast::<c_uchar>();
        if p.is_null() {
            return -1;
        }
        // SAFETY: `out` is the caller's cursor slot.
        unsafe { *out = p };
        noinc = 1;
    }
    // SAFETY: `p` has 16 header bytes of room.
    unsafe {
        if ispub != 0 {
            *p = MS_PUBLICKEYBLOB;
        } else {
            *p = MS_PRIVATEKEYBLOB;
        }
        p = p.add(1);
        *p = 0x2;
        p = p.add(1);
        *p = 0;
        p = p.add(1);
        *p = 0;
        p = p.add(1);
    }
    // SAFETY: `p` is the frame's cursor and each write advances it.
    unsafe {
        write_ledword(&raw mut p, keyalg);
        write_ledword(&raw mut p, magic);
        write_ledword(&raw mut p, bitlen);
    }
    if keyalg == MS_KEYALG_RSA_KEYX {
        // SAFETY: `pk` is live and `EVP_PKEY_get0_RSA` reads its own key.
        let rsa = unsafe { EVP_PKEY_get0_RSA(pk) };
        // SAFETY: `rsa` is the key `pk` holds and `p` is the frame's cursor.
        unsafe { write_rsa(&raw mut p, rsa, ispub) };
    } else {
        // SAFETY: `pk` is live and `EVP_PKEY_get0_DSA` reads its own key.
        let dsa = unsafe { EVP_PKEY_get0_DSA(pk) };
        // SAFETY: `dsa` is the key `pk` holds and `p` is the frame's cursor.
        unsafe { write_dsa(&raw mut p, dsa, ispub) };
    }
    if noinc == 0 {
        // SAFETY: `out` is the caller's cursor slot.
        unsafe { *out = (*out).add(outlen as usize) };
    }
    outlen
}

/// `static int do_i2b_bio(BIO *out, const EVP_PKEY *pk, int ispub)` — `pvkfmt.c:621-634`.
///
/// # Safety
/// `out` must be a live BIO; `pk` live.
unsafe fn do_i2b_bio(out: *mut Bio, pk: *const EvpPkey, ispub: c_int) -> c_int {
    let mut tmp: *mut c_uchar = ptr::null_mut();
    // SAFETY: `tmp`/`pk` are this frame's.
    let outlen = unsafe { do_i2b(&raw mut tmp, pk, ispub) };
    if outlen < 0 {
        return -1;
    }
    // SAFETY: `out` is live and `tmp` holds `outlen` bytes.
    let wrlen = unsafe { BIO_write(out, tmp.cast::<c_void>(), outlen) };
    // SAFETY: `tmp` is this frame's allocation.
    unsafe { CRYPTO_free(tmp.cast::<c_void>(), ptr::null(), 0) };
    if wrlen == outlen {
        return outlen;
    }
    -1
}

/// `static int check_bitlen_rsa(const RSA *rsa, int ispub, unsigned int *pmagic)` —
/// `pvkfmt.c:636-674`.
///
/// # Safety
/// `rsa` must be live (`EVP_PKEY_get0_RSA` returns a borrowed key, never NULL in this unit);
/// `pmagic` writable.
unsafe fn check_bitlen_rsa(rsa: *const Rsa, ispub: c_int, pmagic: *mut c_uint) -> c_int {
    let mut e: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and `e` is this frame's slot.
    unsafe { RSA_get0_key(rsa, ptr::null_mut(), &raw mut e, ptr::null_mut()) };
    // SAFETY: `e` is the key's own exponent.
    if unsafe { BN_num_bits(e) } > 32 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_672) };
        return 0;
    }
    // SAFETY: `rsa` is live.
    let bitlen = unsafe { RSA_bits(rsa) };
    // SAFETY: `rsa` is live.
    let nbyte = unsafe { RSA_size(rsa) };
    let hnbyte = (bitlen + 15) >> 4;
    if ispub != 0 {
        // SAFETY: `pmagic` is writable per the contract.
        unsafe { *pmagic = MS_RSA1MAGIC };
        return bitlen;
    }
    // SAFETY: `pmagic` is writable.
    unsafe { *pmagic = MS_RSA2MAGIC };
    let mut d: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and `d` is this frame's slot.
    unsafe { RSA_get0_key(rsa, ptr::null_mut(), ptr::null_mut(), &raw mut d) };
    // SAFETY: `d` is the key's own private exponent.
    if unsafe { bn_num_bytes(d) } > nbyte {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_672) };
        return 0;
    }
    let mut p: *const BigNum = ptr::null();
    let mut q: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and `p`/`q` are this frame's slots.
    unsafe { RSA_get0_factors(rsa, &raw mut p, &raw mut q) };
    let mut dmp1: *const BigNum = ptr::null();
    let mut dmq1: *const BigNum = ptr::null();
    let mut iqmp: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and the three slots are this frame's.
    unsafe { RSA_get0_crt_params(rsa, &raw mut dmp1, &raw mut dmq1, &raw mut iqmp) };
    // SAFETY: all five are the key's own parameters.
    if unsafe { bn_num_bytes(iqmp) } > hnbyte
        // SAFETY: as the first read; `p` is the key's own.
        || unsafe { bn_num_bytes(p) } > hnbyte
        // SAFETY: as the first read; `q` is the key's own.
        || unsafe { bn_num_bytes(q) } > hnbyte
        // SAFETY: as the first read; `dmp1` is the key's own.
        || unsafe { bn_num_bytes(dmp1) } > hnbyte
        // SAFETY: as the first read; `dmq1` is the key's own.
        || unsafe { bn_num_bytes(dmq1) } > hnbyte
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_672) };
        return 0;
    }
    bitlen
}

/// `static void write_rsa(unsigned char **out, const RSA *rsa, int ispub)` — `pvkfmt.c:676-696`.
///
/// # Safety
/// `out` a writable cursor; `rsa` live.
unsafe fn write_rsa(out: *mut *mut c_uchar, rsa: *const Rsa, ispub: c_int) {
    // SAFETY: `rsa` is live.
    let nbyte = unsafe { RSA_size(rsa) };
    // SAFETY: `rsa` is live.
    let hnbyte = (unsafe { RSA_bits(rsa) } + 15) >> 4;
    let mut n: *const BigNum = ptr::null();
    let mut e: *const BigNum = ptr::null();
    let mut d: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and the three slots are this frame's.
    unsafe { RSA_get0_key(rsa, &raw mut n, &raw mut e, &raw mut d) };
    // SAFETY: `e`/`n` are the key's own and `out` is the frame's cursor.
    unsafe {
        write_lebn(out, e, 4);
        write_lebn(out, n, nbyte);
    }
    if ispub != 0 {
        return;
    }
    let mut p: *const BigNum = ptr::null();
    let mut q: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and the two slots are this frame's.
    unsafe { RSA_get0_factors(rsa, &raw mut p, &raw mut q) };
    let mut dmp1: *const BigNum = ptr::null();
    let mut dmq1: *const BigNum = ptr::null();
    let mut iqmp: *const BigNum = ptr::null();
    // SAFETY: `rsa` is live and the three slots are this frame's.
    unsafe { RSA_get0_crt_params(rsa, &raw mut dmp1, &raw mut dmq1, &raw mut iqmp) };
    // SAFETY: every BN is the key's own and `out` is the frame's cursor.
    unsafe {
        write_lebn(out, p, hnbyte);
        write_lebn(out, q, hnbyte);
        write_lebn(out, dmp1, hnbyte);
        write_lebn(out, dmq1, hnbyte);
        write_lebn(out, iqmp, hnbyte);
        write_lebn(out, d, nbyte);
    }
}

/// `static int check_bitlen_dsa(const DSA *dsa, int ispub, unsigned int *pmagic)` —
/// `pvkfmt.c:699-725`.
///
/// # Safety
/// `dsa` live; `pmagic` writable.
unsafe fn check_bitlen_dsa(dsa: *const Dsa, ispub: c_int, pmagic: *mut c_uint) -> c_int {
    let mut p: *const BigNum = ptr::null();
    let mut q: *const BigNum = ptr::null();
    let mut g: *const BigNum = ptr::null();
    let mut pub_key: *const BigNum = ptr::null();
    let mut priv_key: *const BigNum = ptr::null();
    // SAFETY: `dsa` is live and the three slots are this frame's.
    unsafe { DSA_get0_pqg(dsa, &raw mut p, &raw mut q, &raw mut g) };
    // SAFETY: `dsa` is live and the two slots are this frame's.
    unsafe { DSA_get0_key(dsa, &raw mut pub_key, &raw mut priv_key) };
    // SAFETY: `p` is the key's own.
    let bitlen = unsafe { BN_num_bits(p) };
    // SAFETY: `q`/`g` are the key's own.
    if (bitlen & 7) != 0 || unsafe { BN_num_bits(q) } != 160 || unsafe { BN_num_bits(g) } > bitlen {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_723) };
        return 0;
    }
    if ispub != 0 {
        // SAFETY: `pub_key` is the key's own.
        if unsafe { BN_num_bits(pub_key) } > bitlen {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_723) };
            return 0;
        }
        // SAFETY: `pmagic` is writable.
        unsafe { *pmagic = MS_DSS1MAGIC };
    } else {
        // SAFETY: `priv_key` is the key's own.
        if unsafe { BN_num_bits(priv_key) } > 160 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_723) };
            return 0;
        }
        // SAFETY: `pmagic` is writable.
        unsafe { *pmagic = MS_DSS2MAGIC };
    }
    bitlen
}

/// `static void write_dsa(unsigned char **out, const DSA *dsa, int ispub)` — `pvkfmt.c:727-747`.
///
/// # Safety
/// `out` a writable cursor; `dsa` live.
unsafe fn write_dsa(out: *mut *mut c_uchar, dsa: *const Dsa, ispub: c_int) {
    let mut p: *const BigNum = ptr::null();
    let mut q: *const BigNum = ptr::null();
    let mut g: *const BigNum = ptr::null();
    let mut pub_key: *const BigNum = ptr::null();
    let mut priv_key: *const BigNum = ptr::null();
    // SAFETY: `dsa` is live and the three slots are this frame's.
    unsafe { DSA_get0_pqg(dsa, &raw mut p, &raw mut q, &raw mut g) };
    // SAFETY: `dsa` is live and the two slots are this frame's.
    unsafe { DSA_get0_key(dsa, &raw mut pub_key, &raw mut priv_key) };
    // SAFETY: `p` is the key's own.
    let nbyte = unsafe { bn_num_bytes(p) };
    // SAFETY: every BN is the key's own and `out` is the frame's cursor.
    unsafe {
        write_lebn(out, p, nbyte);
        write_lebn(out, q, 20);
        write_lebn(out, g, nbyte);
    }
    if ispub != 0 {
        // SAFETY: `pub_key` is the key's own and `out` is the frame's cursor.
        unsafe { write_lebn(out, pub_key, nbyte) };
    } else {
        // SAFETY: `priv_key` is the key's own and `out` is the frame's cursor.
        unsafe { write_lebn(out, priv_key, 20) };
    }
    /* Set "invalid" for seed structure values */
    // SAFETY: `*out` has 24 writable bytes and the write advances it.
    unsafe {
        ptr::write_bytes(*out, 0xff, 24);
        *out = (*out).add(24);
    }
}

/// `int i2b_PrivateKey_bio(BIO *out, const EVP_PKEY *pk)` — `pvkfmt.c:750-753`.
///
/// # Safety
/// `out` a live BIO; `pk` live.
#[no_mangle]
pub unsafe extern "C" fn i2b_PrivateKey_bio(out: *mut Bio, pk: *const EvpPkey) -> c_int {
    // SAFETY: `out`/`pk` are the caller's.
    unsafe { do_i2b_bio(out, pk, 0) }
}

/// `int i2b_PublicKey_bio(BIO *out, const EVP_PKEY *pk)` — `pvkfmt.c:755-758`.
///
/// # Safety
/// `out` a live BIO; `pk` live.
#[no_mangle]
pub unsafe extern "C" fn i2b_PublicKey_bio(out: *mut Bio, pk: *const EvpPkey) -> c_int {
    // SAFETY: `out`/`pk` are the caller's.
    unsafe { do_i2b_bio(out, pk, 1) }
}

/// `int ossl_do_PVK_header(const unsigned char **in, unsigned int length, int skip_magic,
/// int *isdss, unsigned int *psaltlen, unsigned int *pkeylen)` — `pvkfmt.c:760-819`.
///
/// # Safety
/// `in` a readable cursor for `length` bytes; the three out-parameters writable.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn ossl_do_PVK_header(
    in_: *mut *const c_uchar,
    length: c_uint,
    skip_magic: c_int,
    isdss: *mut c_int,
    psaltlen: *mut c_uint,
    pkeylen: *mut c_uint,
) -> c_int {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };
    let is_encrypted: c_uint;

    if skip_magic != 0 {
        if length < 20 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_769) };
            return 0;
        }
    } else {
        if length < 24 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_774) };
            return 0;
        }
        // SAFETY: `p` has at least 24 readable bytes.
        let pvk_magic = unsafe { read_ledword(&raw mut p) };
        if pvk_magic != MS_PVKMAGIC {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_779) };
            return 0;
        }
    }
    /* Skip reserved */
    // SAFETY: the cursor advances four reserved bytes.
    unsafe { p = p.add(4) };
    /* Check the key type */
    // SAFETY: `p` has a readable word and `isdss` is a writable slot.
    match unsafe { read_ledword(&raw mut p) } {
        MS_KEYTYPE_KEYX => {
            // SAFETY: `isdss` is writable.
            if unsafe { *isdss } == 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_789) };
                return 0;
            }
            // SAFETY: `isdss` is writable.
            unsafe { *isdss = 0 };
        }
        MS_KEYTYPE_SIGN => {
            // SAFETY: `isdss` is writable.
            if unsafe { *isdss } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_796) };
                return 0;
            }
            // SAFETY: `isdss` is writable.
            unsafe { *isdss = 1 };
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_802) };
            return 0;
        }
    }
    // SAFETY: `p` has three readable words and the slots are writable.
    unsafe {
        is_encrypted = read_ledword(&raw mut p);
        *psaltlen = read_ledword(&raw mut p);
        *pkeylen = read_ledword(&raw mut p);
    }

    // SAFETY: the two slots are readable.
    if unsafe { *pkeylen } > PVK_MAX_KEYLEN || unsafe { *psaltlen } > PVK_MAX_SALTLEN {
        return 0;
    }
    // SAFETY: `psaltlen` is readable.
    if is_encrypted != 0 && unsafe { *psaltlen } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_813) };
        return 0;
    }
    // SAFETY: `in` is the caller's writable cursor.
    unsafe { *in_ = p };
    1
}

/// `static int derive_pvk_key(unsigned char *key, size_t keylen, const unsigned char *salt,
/// unsigned int saltlen, const unsigned char *pass, int passlen, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `pvkfmt.c:822-851`.
///
/// # Safety
/// `key` writable for `keylen`; `salt`/`pass` readable for their lengths; the two strings NULL or
/// NUL-terminated.
unsafe fn derive_pvk_key(
    key: *mut c_uchar,
    keylen: usize,
    salt: *const c_uchar,
    saltlen: c_uint,
    pass: *const c_uchar,
    passlen: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the three arguments are the caller's.
    let kdf: *mut EvpKdf = unsafe { EVP_KDF_fetch(libctx, c"PVKKDF".as_ptr(), propq) };
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: `kdf` is live and this call owns it.
    let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is this frame's own.
    unsafe { crate::evp::kdf::EVP_KDF_free(kdf) };
    if ctx.is_null() {
        return 0;
    }

    let mut params: [OsslParam; 5] = [OSSL_PARAM_construct_end(); 5];
    // SAFETY: every constructor is called with this frame's buffers.
    unsafe {
        params[0] = crate::params::OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt.cast_mut().cast::<c_void>(),
            saltlen as usize,
        );
        params[1] = crate::params::OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            pass.cast_mut().cast::<c_void>(),
            passlen as usize,
        );
        params[2] = crate::params::OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            SN_SHA1.cast_mut(),
            0,
        );
        params[3] = crate::params::OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_PROPERTIES,
            propq.cast_mut(),
            0,
        );
        params[4] = OSSL_PARAM_construct_end();
    }

    // SAFETY: `ctx` is live and `params` is a terminated array.
    let rv = unsafe { EVP_KDF_derive(ctx, key, keylen, params.as_ptr()) };
    // SAFETY: `ctx` is this frame's own.
    unsafe { EVP_KDF_CTX_free(ctx) };
    rv
}

/// `static void *do_PVK_body_key(const unsigned char **in, unsigned int saltlen,
/// unsigned int keylen, pem_password_cb *cb, void *u, int *isdss, int *ispub, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `pvkfmt.c:854-947`.
///
/// # Safety
/// `in`/`isdss`/`ispub` as [`do_b2i_key`]; `cb` the caller's password callback.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn do_PVK_body_key(
    in_: *mut *const c_uchar,
    saltlen: c_uint,
    keylen: c_uint,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    isdss: *mut c_int,
    ispub: *mut c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: `in` is the caller's readable cursor.
    let mut p = unsafe { *in_ };
    let mut enctmp: *mut c_uchar = ptr::null_mut();
    let mut keybuf = [0 as c_uchar; 20];

    // SAFETY: no preconditions.
    let cctx = EVP_CIPHER_CTX_new();
    if cctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_870) };
        return ptr::null_mut();
    }

    let mut rc4: *mut EvpCipher = ptr::null_mut();
    if saltlen != 0 {
        let mut psbuf = [0 as c_char; PEM_BUFSIZE as usize];
        // SAFETY: `cb` is the caller's or NULL; the buffer is this frame's.
        let inlen = match cb {
            // SAFETY: every argument is this frame's and the callback's contract is the header's.
            Some(f) => unsafe { f(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
            // SAFETY: the callback contract is `PEM_def_callback`'s.
            None => unsafe { PEM_def_callback(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
        };
        if inlen < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_886) };
            // SAFETY: `cctx` is this frame's own.
            unsafe { EVP_CIPHER_CTX_free(cctx) };
            return ptr::null_mut();
        }
        // SAFETY: `keylen + 8` bytes as a raw allocation.
        enctmp = CRYPTO_malloc(keylen as usize + 8, ptr::null(), 0).cast::<c_uchar>();
        if enctmp.is_null() {
            // SAFETY: `cctx` is this frame's own.
            unsafe { EVP_CIPHER_CTX_free(cctx) };
            return ptr::null_mut();
        }
        // SAFETY: every argument is this frame's.
        if unsafe {
            derive_pvk_key(
                keybuf.as_mut_ptr(),
                keybuf.len(),
                p,
                saltlen,
                psbuf.as_ptr().cast::<c_uchar>(),
                inlen,
                libctx,
                propq,
            )
        } == 0
        {
            // SAFETY: the two allocations and the context are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                EVP_CIPHER_CTX_free(cctx);
            }
            return ptr::null_mut();
        }
        // SAFETY: `p` is the caller's cursor and `saltlen` bytes follow.
        unsafe { p = p.add(saltlen as usize) };
        if keylen < 8 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_897) };
            // SAFETY: the two allocations and the context are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                EVP_CIPHER_CTX_free(cctx);
            }
            return ptr::null_mut();
        }
        /* Copy BLOBHEADER across, decrypt rest */
        // SAFETY: `p` has 8 readable bytes and `enctmp` has 8 writable.
        unsafe { ptr::copy_nonoverlapping(p, enctmp, 8) };
        // SAFETY: the cursor advances past the copied header.
        unsafe { p = p.add(8) };
        let inlen2 = keylen as c_int - 8;
        // SAFETY: `enctmp` has `keylen+8` bytes; `q` starts after the header.
        let mut q = unsafe { enctmp.add(8) };
        // SAFETY: the two strings are the caller's.
        rc4 = unsafe { EVP_CIPHER_fetch(libctx, c"RC4".as_ptr(), propq) };
        if rc4.is_null() {
            // SAFETY: the two allocations and the context are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                EVP_CIPHER_CTX_free(cctx);
            }
            return ptr::null_mut();
        }
        let mut enctmplen: c_int = 0;
        // SAFETY: every argument is live and this frame's.
        if unsafe { EVP_DecryptInit_ex(cctx, rc4, ptr::null_mut(), keybuf.as_ptr(), ptr::null()) }
            == 0
            // SAFETY: as the init; `cctx`/`q`/`p` are this frame's.
            || unsafe { EVP_DecryptUpdate(cctx, q, &raw mut enctmplen, p, inlen2) } == 0
            // SAFETY: as the init; `q` is this frame's decrypted buffer.
            || unsafe { EVP_DecryptFinal_ex(cctx, q.add(enctmplen as usize), &raw mut enctmplen) }
                == 0
        {
            // SAFETY: the two allocations and the context are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                EVP_CIPHER_CTX_free(cctx);
                crate::evp::cipher::EVP_CIPHER_free(rc4);
            }
            return ptr::null_mut();
        }
        // SAFETY: `q` is a readable cursor over the decrypted bytes.
        let mut cursor: *const c_uchar = q;
        // SAFETY: `cursor` is a readable cursor for four bytes.
        let mut magic = unsafe { read_ledword(&raw mut cursor) };
        if magic != MS_RSA2MAGIC && magic != MS_DSS2MAGIC {
            // SAFETY: `enctmp` has `keylen+8` bytes; the retry restarts at the header.
            q = unsafe { enctmp.add(8) };
            // SAFETY: `keybuf` has 20 bytes and the authority clears the 11 after the 5th.
            unsafe { ptr::write_bytes(keybuf.as_mut_ptr().add(5), 0, 11) };
            // SAFETY: every argument is live and this frame's.
            if unsafe {
                EVP_DecryptInit_ex(cctx, rc4, ptr::null_mut(), keybuf.as_ptr(), ptr::null())
            } == 0
                // SAFETY: as the init; `cctx`/`q`/`p` are this frame's.
                || unsafe { EVP_DecryptUpdate(cctx, q, &raw mut enctmplen, p, inlen2) } == 0
                // SAFETY: as the init; `q` is this frame's re-decrypted buffer.
                || unsafe {
                    EVP_DecryptFinal_ex(cctx, q.add(enctmplen as usize), &raw mut enctmplen)
                } == 0
            {
                // SAFETY: the two allocations and the context are this frame's own.
                unsafe {
                    OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                    CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                    EVP_CIPHER_CTX_free(cctx);
                    crate::evp::cipher::EVP_CIPHER_free(rc4);
                }
                return ptr::null_mut();
            }
            // SAFETY: `q` is a readable cursor over the re-decrypted bytes.
            cursor = q;
            // SAFETY: `cursor` is a readable cursor for four bytes.
            magic = unsafe { read_ledword(&raw mut cursor) };
            if magic != MS_RSA2MAGIC && magic != MS_DSS2MAGIC {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PVKFMT_925) };
                // SAFETY: the two allocations and the context are this frame's own.
                unsafe {
                    OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                    CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
                    EVP_CIPHER_CTX_free(cctx);
                    crate::evp::cipher::EVP_CIPHER_free(rc4);
                }
                return ptr::null_mut();
            }
        }
        p = enctmp;
    }

    // SAFETY: `p` is the blob body cursor and `keylen` its length.
    let key = unsafe { do_b2i_key(&raw mut p, keylen, isdss, ispub) };
    // SAFETY: the context is this frame's own.
    unsafe { EVP_CIPHER_CTX_free(cctx) };
    // SAFETY: `rc4` is NULL or this frame's own.
    unsafe { crate::evp::cipher::EVP_CIPHER_free(rc4) };
    if !enctmp.is_null() {
        // SAFETY: the key buffer and the allocation are this frame's own.
        unsafe {
            OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
            CRYPTO_free(enctmp.cast::<c_void>(), ptr::null(), 0);
        }
    }
    key
}

/// `static void *do_PVK_key_bio(BIO *in, pem_password_cb *cb, void *u, int *isdss, int *ispub,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `pvkfmt.c:949-981`.
///
/// # Safety
/// `in` a live BIO; `isdss`/`ispub` writable; `cb` the caller's.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn do_PVK_key_bio(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    isdss: *mut c_int,
    ispub: *mut c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    let mut pvk_hdr = [0 as c_uchar; 24];
    let mut saltlen: c_uint = 0;
    let mut keylen: c_uint = 0;

    // SAFETY: `in` is live and `pvk_hdr` is 24 bytes.
    if unsafe { BIO_read(in_, pvk_hdr.as_mut_ptr().cast::<c_void>(), 24) } != 24 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_960) };
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = pvk_hdr.as_ptr();

    // SAFETY: every pointer is this frame's.
    if unsafe { ossl_do_PVK_header(&raw mut p, 24, 0, isdss, &raw mut saltlen, &raw mut keylen) }
        == 0
    {
        return ptr::null_mut();
    }
    let buflen = keylen + saltlen;
    // SAFETY: `buflen` bytes as a raw allocation.
    let buf = CRYPTO_malloc(buflen as usize, ptr::null(), 0).cast::<c_uchar>();
    if buf.is_null() {
        return ptr::null_mut();
    }
    p = buf;
    // SAFETY: `buf` holds `buflen` bytes and `in` is live.
    if unsafe { BIO_read(in_, buf.cast::<c_void>(), buflen as c_int) } != buflen as c_int {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PVKFMT_973) };
        // SAFETY: `buf` is this frame's allocation.
        unsafe { CRYPTO_clear_free(buf.cast::<c_void>(), buflen as usize, ptr::null(), 0) };
        return ptr::null_mut();
    }
    // SAFETY: every pointer is this frame's.
    let key = unsafe {
        do_PVK_body_key(
            &raw mut p, saltlen, keylen, cb, u, isdss, ispub, libctx, propq,
        )
    };
    // SAFETY: `buf` is this frame's allocation.
    unsafe { CRYPTO_clear_free(buf.cast::<c_void>(), buflen as usize, ptr::null(), 0) };
    key
}

/// `DSA *b2i_DSA_PVK_bio_ex(BIO *in, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `pvkfmt.c:984-991`.
///
/// # Safety
/// `in` a live BIO; `cb` the caller's.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn b2i_DSA_PVK_bio_ex(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Dsa {
    let mut isdss: c_int = 1;
    let mut ispub: c_int = 0;
    // SAFETY: every pointer is this frame's.
    unsafe {
        do_PVK_key_bio(in_, cb, u, &raw mut isdss, &raw mut ispub, libctx, propq).cast::<Dsa>()
    }
}

/// `RSA *b2i_RSA_PVK_bio_ex(BIO *in, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `pvkfmt.c:999-1006`.
///
/// # Safety
/// `in` a live BIO; `cb` the caller's.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn b2i_RSA_PVK_bio_ex(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Rsa {
    let mut isdss: c_int = 0;
    let mut ispub: c_int = 0;
    // SAFETY: every pointer is this frame's.
    unsafe {
        do_PVK_key_bio(in_, cb, u, &raw mut isdss, &raw mut ispub, libctx, propq).cast::<Rsa>()
    }
}

/// `EVP_PKEY *b2i_PVK_bio_ex(BIO *in, pem_password_cb *cb, void *u, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `pvkfmt.c:1013-1021`.
///
/// The authority passes `NULL, NULL` to `do_PVK_key_bio` and drops its own `libctx`/`propq`; that
/// is transcribed as written (see the module doc).
///
/// # Safety
/// `in` a live BIO; `cb` the caller's.
#[no_mangle]
pub unsafe extern "C" fn b2i_PVK_bio_ex(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    _libctx: *mut c_void,
    _propq: *const c_char,
) -> *mut EvpPkey {
    let mut isdss: c_int = -1;
    let mut ispub: c_int = -1;
    // SAFETY: every pointer is this frame's.
    let key = unsafe {
        do_PVK_key_bio(
            in_,
            cb,
            u,
            &raw mut isdss,
            &raw mut ispub,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    // SAFETY: `key` is NULL or the low-level key just decoded.
    unsafe { evp_pkey_new0_key(key, isdss_to_evp_type(isdss)) }
}

/// `EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u)` — `pvkfmt.c:1023-1026`.
///
/// # Safety
/// `in` a live BIO; `cb` the caller's.
#[no_mangle]
pub unsafe extern "C" fn b2i_PVK_bio(
    in_: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EvpPkey {
    // SAFETY: `in`/`cb`/`u` are the caller's; the context is NULL.
    unsafe { b2i_PVK_bio_ex(in_, cb, u, ptr::null_mut(), ptr::null()) }
}

/// `static int i2b_PVK(unsigned char **out, const EVP_PKEY *pk, int enclevel, pem_password_cb *cb,
/// void *u, OSSL_LIB_CTX *libctx, const char *propq)` — `pvkfmt.c:1028-1127`.
///
/// # Safety
/// `out` NULL or a writable cursor; `pk` live; `cb` the caller's.
#[allow(non_snake_case)] // the authority's own internal name
unsafe fn i2b_PVK(
    out: *mut *mut c_uchar,
    pk: *const EvpPkey,
    enclevel: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut outlen: c_int = 24;
    let mut start: *mut c_uchar = ptr::null_mut();
    let mut salt: *mut c_uchar = ptr::null_mut();
    let mut rc4: *mut EvpCipher = ptr::null_mut();

    if enclevel != 0 {
        outlen += PVK_SALTLEN as c_int;
    }
    // SAFETY: `pk` is live and the sizing pass takes a NULL cursor.
    let pklen = unsafe { do_i2b(ptr::null_mut(), pk, 0) };
    if pklen < 0 {
        return -1;
    }
    outlen += pklen;
    if out.is_null() {
        return outlen;
    }
    let mut p: *mut c_uchar;
    // SAFETY: `out` is the caller's cursor slot.
    if !unsafe { *out }.is_null() {
        // SAFETY: `out` is the caller's cursor slot and the branch read it as non-NULL.
        p = unsafe { *out };
    } else {
        // SAFETY: `outlen` bytes as a raw allocation.
        start = CRYPTO_malloc(outlen as usize, ptr::null(), 0).cast::<c_uchar>();
        if start.is_null() {
            return -1;
        }
        p = start;
    }

    // SAFETY: no preconditions.
    let cctx = EVP_CIPHER_CTX_new();
    if cctx.is_null() {
        // SAFETY: `out` is the caller's cursor slot.
        if unsafe { *out }.is_null() {
            // SAFETY: `start` is this frame's allocation.
            unsafe { CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0) };
        }
        return -1;
    }

    // SAFETY: `p` has room for the six little-endian header words.
    unsafe {
        write_ledword(&raw mut p, MS_PVKMAGIC);
        write_ledword(&raw mut p, 0);
    }
    // SAFETY: `pk` is live.
    if unsafe { EVP_PKEY_get_id(pk) } == EVP_PKEY_RSA {
        // SAFETY: `p` is the frame's cursor.
        unsafe { write_ledword(&raw mut p, MS_KEYTYPE_KEYX) };
    } else {
        // SAFETY: `p` is the frame's cursor.
        unsafe { write_ledword(&raw mut p, MS_KEYTYPE_SIGN) };
    }
    // SAFETY: `p` is the frame's cursor.
    unsafe {
        write_ledword(&raw mut p, u32::from(enclevel != 0));
        write_ledword(&raw mut p, if enclevel != 0 { PVK_SALTLEN } else { 0 });
        write_ledword(&raw mut p, pklen as c_uint);
    }
    if enclevel != 0 {
        // SAFETY: `libctx` is the caller's and `p` has PVK_SALTLEN writable bytes.
        if unsafe { RAND_bytes_ex(libctx, p, PVK_SALTLEN as usize, 0) } <= 0 {
            // SAFETY: the context and allocation are this frame's own.
            unsafe {
                EVP_CIPHER_CTX_free(cctx);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
        salt = p;
        // SAFETY: the cursor advances past the salt.
        unsafe { p = p.add(PVK_SALTLEN as usize) };
    }
    // SAFETY: `p` is the frame's cursor and `pk` is live.
    unsafe { do_i2b(&raw mut p, pk, 0) };
    if enclevel != 0 {
        let mut psbuf = [0 as c_char; PEM_BUFSIZE as usize];
        let mut keybuf = [0 as c_uchar; 20];
        // SAFETY: `cb` is the caller's or NULL; the buffer is this frame's.
        let inlen = match cb {
            // SAFETY: every argument is this frame's.
            Some(f) => unsafe { f(psbuf.as_mut_ptr(), PEM_BUFSIZE, 1, u) },
            // SAFETY: the callback contract is `PEM_def_callback`'s.
            None => unsafe { PEM_def_callback(psbuf.as_mut_ptr(), PEM_BUFSIZE, 1, u) },
        };
        if inlen <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PVKFMT_1091) };
            // SAFETY: the context and allocation are this frame's own.
            unsafe {
                EVP_CIPHER_CTX_free(cctx);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
        // SAFETY: every argument is this frame's.
        if unsafe {
            derive_pvk_key(
                keybuf.as_mut_ptr(),
                keybuf.len(),
                salt,
                PVK_SALTLEN,
                psbuf.as_ptr().cast::<c_uchar>(),
                inlen,
                libctx,
                propq,
            )
        } == 0
        {
            // SAFETY: the context and allocation are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                EVP_CIPHER_CTX_free(cctx);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
        // SAFETY: the two strings are the caller's.
        rc4 = unsafe { EVP_CIPHER_fetch(libctx, c"RC4".as_ptr(), propq) };
        if rc4.is_null() {
            // SAFETY: the context and allocation are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                EVP_CIPHER_CTX_free(cctx);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
        if enclevel == 1 {
            // SAFETY: `keybuf` has 20 bytes and the authority clears the 11 after the 5th.
            unsafe { ptr::write_bytes(keybuf.as_mut_ptr().add(5), 0, 11) };
        }
        // SAFETY: `salt` is the frame's salt region and the cursor lands after it.
        let q = unsafe { salt.add(PVK_SALTLEN as usize + 8) };
        let mut enctmplen: c_int = 0;
        // SAFETY: every argument is live and this frame's.
        if unsafe { EVP_EncryptInit_ex(cctx, rc4, ptr::null_mut(), keybuf.as_ptr(), ptr::null()) }
            == 0
        {
            // SAFETY: the context, cipher and allocation are this frame's own.
            unsafe {
                OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), keybuf.len());
                EVP_CIPHER_CTX_free(cctx);
                crate::evp::cipher::EVP_CIPHER_free(rc4);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
        // SAFETY: `keybuf` is this frame's.
        unsafe { OPENSSL_cleanse(keybuf.as_mut_ptr().cast::<c_void>(), 20) };
        // SAFETY: `q` is the frame's ciphertext region and `pklen - 8` its length.
        if unsafe { EVP_EncryptUpdate(cctx, q, &raw mut enctmplen, q, pklen - 8) } == 0
            // SAFETY: as the update; `q` is the frame's ciphertext region.
            || unsafe { EVP_EncryptFinal_ex(cctx, q.add(enctmplen as usize), &raw mut enctmplen) }
                == 0
        {
            // SAFETY: the context, cipher and allocation are this frame's own.
            unsafe {
                EVP_CIPHER_CTX_free(cctx);
                crate::evp::cipher::EVP_CIPHER_free(rc4);
                if (*out).is_null() {
                    CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0);
                }
            }
            return -1;
        }
    }

    // SAFETY: `out` is the caller's cursor slot.
    if unsafe { *out }.is_null() {
        // SAFETY: `out` is the caller's writable slot.
        unsafe { *out = start };
    }
    // SAFETY: the context and cipher are this frame's own.
    unsafe {
        EVP_CIPHER_CTX_free(cctx);
        crate::evp::cipher::EVP_CIPHER_free(rc4);
    }
    // SAFETY: `out` is the caller's cursor slot.
    if unsafe { *out }.is_null() {
        // SAFETY: `start` is this frame's allocation.
        unsafe { CRYPTO_free(start.cast::<c_void>(), ptr::null(), 0) };
    }
    outlen
}

/// `int i2b_PVK_bio_ex(BIO *out, const EVP_PKEY *pk, int enclevel, pem_password_cb *cb, void *u,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `pvkfmt.c:1129-1146`.
///
/// # Safety
/// `out` a live BIO; `pk` live; `cb` the caller's.
#[no_mangle]
pub unsafe extern "C" fn i2b_PVK_bio_ex(
    out: *mut Bio,
    pk: *const EvpPkey,
    enclevel: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut tmp: *mut c_uchar = ptr::null_mut();
    // SAFETY: every argument is the caller's or this frame's.
    let outlen = unsafe { i2b_PVK(&raw mut tmp, pk, enclevel, cb, u, libctx, propq) };
    if outlen < 0 {
        return -1;
    }
    // SAFETY: `out` is live and `tmp` holds `outlen` bytes.
    let wrlen = unsafe { BIO_write(out, tmp.cast::<c_void>(), outlen) };
    // SAFETY: `tmp` is this frame's allocation.
    unsafe { CRYPTO_free(tmp.cast::<c_void>(), ptr::null(), 0) };
    if wrlen == outlen {
        return outlen;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::PVKFMT_1144) };
    -1
}

/// `int i2b_PVK_bio(BIO *out, const EVP_PKEY *pk, int enclevel, pem_password_cb *cb, void *u)` —
/// `pvkfmt.c:1148-1152`.
///
/// # Safety
/// `out` a live BIO; `pk` live; `cb` the caller's.
#[no_mangle]
pub unsafe extern "C" fn i2b_PVK_bio(
    out: *mut Bio,
    pk: *const EvpPkey,
    enclevel: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: every argument is the caller's; the context is NULL.
    unsafe { i2b_PVK_bio_ex(out, pk, enclevel, cb, u, ptr::null_mut(), ptr::null()) }
}
