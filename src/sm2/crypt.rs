//! Phase 8 — `crypto/sm2/sm2_crypt.c`: the `SM2_Ciphertext` DER codec and the encrypt/decrypt pair.
//!
//! Four hundred and thirty-two lines, six functions, transcribed whole (D327). The provider's `SM2`
//! asym-cipher unit (`src/provider/sm2_enc.rs`) reaches all four of `ossl_sm2_ciphertext_size`,
//! `ossl_sm2_plaintext_size`, `ossl_sm2_encrypt` and `ossl_sm2_decrypt`; the two helpers
//! (`ec_field_size`, `is_all_zeros`) are `static` in the authority and private here.
//!
//! ## The codec is an ASN.1 template, exactly the authority's
//!
//! `SM2_Ciphertext` is a four-field `ASN1_SEQUENCE`: two `BIGNUM`s (`C1x`, `C1y`, the ephemeral
//! point) then two `ASN1_OCTET_STRING`s (`C3`, the digest, then `C2`, the masked message) — note the
//! **authority's field order**, `C3` before `C2`, which the DER bytes make observable. The template
//! is built here the way `src/rsa/asn1.rs` builds `RSA_PRIME_INFO`, over the crate's own
//! `BIGNUM_it`/`ASN1_OCTET_STRING_it`, and the four `IMPLEMENT_ASN1_FUNCTIONS` entry points
//! (`SM2_Ciphertext_new`/`_free`, `d2i_SM2_Ciphertext`, `i2d_SM2_Ciphertext`) are the four thin
//! wrappers over `ASN1_item_*` the macro would have generated.
//!
//! ## The KDF is X9.63 with no salt, which the authority says is the SM2 KDF
//!
//! `ossl_ecdh_kdf_X9_63` (`src/ec/kdf.rs`) computes the mask, and the all-zero mask is retried with
//! a fresh `k` — the `again:` label the loop below mirrors.
//!
//! ## The evidence is the authority's own published vectors
//!
//! `test/sm2_internal_test.c` carries the GM/T 0003.5-2012 Annex C encryption known answer: a
//! private key, the plaintext `"encryption standard"`, the ephemeral `k`, and the expected
//! ciphertext DER. The decrypt direction is deterministic, so the test below drives the vector
//! through [`ossl_sm2_decrypt`] and requires the exact plaintext back — the derived values (`C3`
//! and the mask) are closed against the published vector rather than against a second
//! transcription (D400/D401's rule).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::size_of;
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::der::ASN1_object_size;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_get0_data,
    ASN1_STRING_length,
};
use crate::asn1::x_bignum::BIGNUM_it;
use crate::bn::bignum::{BN_bn2binpad, BN_num_bits, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::ec::kdf::ossl_ecdh_kdf_X9_63;
use crate::ec::key::{
    ossl_ec_key_get0_propq, ossl_ec_key_get_libctx, EC_KEY_get0_group, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key,
};
use crate::ec::lib::{
    EC_GROUP_get0_field, EC_GROUP_get0_order, EC_POINT_free, EC_POINT_get_affine_coordinates,
    EC_POINT_mul, EC_POINT_new, EC_POINT_set_affine_coordinates,
};
use crate::ec::{EcGroup, EcKey, EcPoint};
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_get_size, EvpMd, EvpMdCtx,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free, CRYPTO_memcmp, CRYPTO_zalloc};

/// The unit's own `__FILE__`. `sm2_crypt.c` is a source-tree file, so the compiler records the
/// admitted build record's prefix.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/sm2/sm2_crypt.c".as_ptr();

/// `INT_MAX` — `include/internal/numbers.h`'s `0x7fffffff`. Two guards use it, both as the bound
/// on an encoding length that must fit an `int`.
const INT_MAX: usize = i32::MAX as usize;

/// `struct SM2_Ciphertext_st` — `sm2_crypt.c:31-36`. Four fields in the authority's order; the
/// template below reads them by offset.
#[repr(C)]
struct Sm2Ciphertext {
    /// `BIGNUM *C1x` — the ephemeral point's x.
    c1x: *mut BigNum,
    /// `BIGNUM *C1y` — the ephemeral point's y.
    c1y: *mut BigNum,
    /// `ASN1_OCTET_STRING *C3` — the digest, **before** `C2` in the sequence.
    c3: *mut Asn1String,
    /// `ASN1_OCTET_STRING *C2` — the masked message.
    c2: *mut Asn1String,
}

/// `SM2_Ciphertext_seq_tt` — `sm2_crypt.c:38-43`'s four `ASN1_SIMPLE` rows, read against the
/// crate's own field offsets.
static SM2_CIPHERTEXT_SEQ_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(Sm2Ciphertext, c1x) as c_ulong,
        field_name: c"C1x".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(Sm2Ciphertext, c1y) as c_ulong,
        field_name: c"C1y".as_ptr(),
        item: BIGNUM_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(Sm2Ciphertext, c3) as c_ulong,
        field_name: c"C3".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: core::mem::offset_of!(Sm2Ciphertext, c2) as c_ulong,
        field_name: c"C2".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `SM2_Ciphertext_it` — `ASN1_SEQUENCE_END(SM2_Ciphertext)`'s item. `IMPLEMENT_ASN1_FUNCTIONS`
/// makes it `static`, so it is private here.
#[allow(non_snake_case)] // the authority's name is the contract
fn SM2_Ciphertext_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: SM2_CIPHERTEXT_SEQ_TT.as_ptr(),
        tcount: 4,
        funcs: ptr::null(),
        size: size_of::<Sm2Ciphertext>() as c_long,
        sname: c"SM2_Ciphertext".as_ptr(),
    };
    &IT
}

/// `SM2_Ciphertext *SM2_Ciphertext_new(void)` — the `ASN1_SEQUENCE_END` generated accessor. It has
/// no caller on this profile (the authority's `d2i` path allocates through the item layer), so it
/// is transcribed whole (D327) and marked rather than dropped.
///
/// # Safety
/// The item layer's own contract; the returned value is owned by the caller.
#[allow(dead_code)]
#[allow(non_snake_case)] // the authority's name is the contract
unsafe fn SM2_Ciphertext_new() -> *mut Sm2Ciphertext {
    // SAFETY: the item is a `static` this module owns.
    unsafe { ASN1_item_new(SM2_Ciphertext_it()).cast::<Sm2Ciphertext>() }
}

/// `void SM2_Ciphertext_free(SM2_Ciphertext *a)`.
///
/// # Safety
/// `a` is NULL or a value built by [`SM2_Ciphertext_new`]/`d2i_SM2_Ciphertext`.
#[allow(non_snake_case)] // the authority's name is the contract
unsafe fn SM2_Ciphertext_free(a: *mut Sm2Ciphertext) {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_free(a.cast(), SM2_Ciphertext_it()) };
}

/// `SM2_Ciphertext *d2i_SM2_Ciphertext(SM2_Ciphertext **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `in` points at a `*const u8` holding `len` bytes; the returned value is owned by the caller.
#[allow(non_snake_case)] // the authority's name is the contract
unsafe fn d2i_SM2_Ciphertext(in_: *mut *const c_uchar, len: c_long) -> *mut Sm2Ciphertext {
    // SAFETY: the caller's contract; a NULL `pval` makes the item layer allocate.
    unsafe { ASN1_item_d2i(ptr::null_mut(), in_, len, SM2_Ciphertext_it()).cast::<Sm2Ciphertext>() }
}

/// `int i2d_SM2_Ciphertext(const SM2_Ciphertext *a, unsigned char **out)`.
///
/// # Safety
/// `a` is live; `out` is NULL (size query) or writable.
#[allow(non_snake_case)] // the authority's name is the contract
unsafe fn i2d_SM2_Ciphertext(a: *const Sm2Ciphertext, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, SM2_Ciphertext_it()) }
}

/// `BN_num_bytes(a)` — the header's macro, written out (`src/ec/depr.rs`'s rule).
///
/// # Safety
/// `a` is NULL or live.
#[inline]
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (BN_num_bits(a) + 7) / 8 }
}

/// `static int ec_field_size(const EC_GROUP *group)` — `sm2_crypt.c:47-55`.
///
/// # Safety
/// `group` is live.
unsafe fn ec_field_size(group: *const EcGroup) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let p = EC_GROUP_get0_field(group);
        if p.is_null() {
            return 0;
        }
        bn_num_bytes(p)
    }
}

/// `static int is_all_zeros(const unsigned char *msg, size_t msglen)` — `sm2_crypt.c:57-67`. The
/// accumulator is an `unsigned char`, so the OR wraps exactly as the authority's does.
///
/// # Safety
/// `msg` is `msglen` bytes.
unsafe fn is_all_zeros(msg: *const u8, msglen: usize) -> c_int {
    // SAFETY: the caller's contract.
    let bytes = unsafe { core::slice::from_raw_parts(msg, msglen) };
    let mut re: u8 = 0;
    for b in bytes {
        re |= *b;
    }
    (re == 0) as c_int
}

/// `int ossl_sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)` —
/// `sm2_crypt.c:69-85`.
///
/// # Safety
/// `ct` is `ct_size` bytes; `pt_size` is writable.
pub(crate) unsafe fn ossl_sm2_plaintext_size(
    ct: *const u8,
    ct_size: usize,
    pt_size: *mut usize,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe {
        let mut in_ = ct;
        let sm2_ctext = d2i_SM2_Ciphertext(ptr::addr_of_mut!(in_), ct_size as c_long);

        if sm2_ctext.is_null() {
            raise_site(&err_sites::SM2_CRYPT_77);
            return 0;
        }

        *pt_size = ASN1_STRING_length((*sm2_ctext).c2) as usize;
        SM2_Ciphertext_free(sm2_ctext);

        1
    }
}

/// `int ossl_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,`
/// `size_t *ct_size)` — `sm2_crypt.c:87-105`.
///
/// # Safety
/// `key` and `digest` are live; `ct_size` is writable.
pub(crate) unsafe fn ossl_sm2_ciphertext_size(
    key: *const EcKey,
    digest: *const EvpMd,
    msg_len: usize,
    ct_size: *mut usize,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe {
        let field_size = ec_field_size(EC_KEY_get0_group(key));
        let md_size = EVP_MD_get_size(digest);

        if field_size == 0 || md_size <= 0 || msg_len > INT_MAX / 2 {
            return 0;
        }

        /* Integer and string are simple types; set constructed = 0, primitive definite length. */
        let sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
            + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
            + ASN1_object_size(0, msg_len as c_int, V_ASN1_OCTET_STRING);
        /* Sequence is structured; set constructed = 1, constructed definite length. */
        *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE) as usize;

        1
    }
}

/// `int ossl_sm2_encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,`
/// `size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)` — `sm2_crypt.c:107-290`.
///
/// # Safety
/// `key` is live with a public key; `digest` is live; `msg` is `msg_len` bytes; `ciphertext_buf`
/// holds `*ciphertext_len` bytes on entry; `ciphertext_len` is writable.
pub(crate) unsafe fn ossl_sm2_encrypt(
    key: *const EcKey,
    digest: *const EvpMd,
    msg: *const u8,
    msg_len: usize,
    ciphertext_buf: *mut u8,
    ciphertext_len: *mut usize,
) -> c_int {
    let mut rc: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut k_g: *mut EcPoint = ptr::null_mut();
    let mut k_p: *mut EcPoint = ptr::null_mut();
    let mut msg_mask: *mut u8 = ptr::null_mut();
    let mut x2y2: *mut u8 = ptr::null_mut();
    let mut c3: *mut u8 = ptr::null_mut();
    let mut fetched_digest: *mut EvpMd = ptr::null_mut();
    let mut ctext = Sm2Ciphertext {
        c1x: ptr::null_mut(),
        c1y: ptr::null_mut(),
        c3: ptr::null_mut(),
        c2: ptr::null_mut(),
    };

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let group = EC_KEY_get0_group(key);
        let order = EC_GROUP_get0_order(group);
        let p_key = EC_KEY_get0_public_key(key);
        let hash = EVP_MD_CTX_new();
        let c3_size = EVP_MD_get_size(digest);
        let libctx = ossl_ec_key_get_libctx(key);
        let propq = ossl_ec_key_get0_propq(key);

        'done: {
            if msg_len > INT_MAX / 2 {
                raise_site(&err_sites::SM2_CRYPT_141);
                break 'done;
            }

            if hash.is_null() || c3_size <= 0 {
                raise_site(&err_sites::SM2_CRYPT_146);
                break 'done;
            }

            let field_size = ec_field_size(group);
            if field_size == 0 {
                raise_site(&err_sites::SM2_CRYPT_152);
                break 'done;
            }

            k_g = EC_POINT_new(group);
            k_p = EC_POINT_new(group);
            if k_g.is_null() || k_p.is_null() {
                raise_site(&err_sites::SM2_CRYPT_159);
                break 'done;
            }
            ctx = BN_CTX_new_ex(libctx);
            if ctx.is_null() {
                raise_site(&err_sites::SM2_CRYPT_164);
                break 'done;
            }

            BN_CTX_start(ctx);
            let k = BN_CTX_get(ctx);
            let x1 = BN_CTX_get(ctx);
            let x2 = BN_CTX_get(ctx);
            let y1 = BN_CTX_get(ctx);
            let y2 = BN_CTX_get(ctx);

            if y2.is_null() {
                raise_site(&err_sites::SM2_CRYPT_176);
                break 'done;
            }

            x2y2 = CRYPTO_calloc(2, field_size as usize, FILE, 180).cast::<u8>();
            c3 = CRYPTO_zalloc(c3_size as usize, FILE, 181).cast::<u8>();

            if x2y2.is_null() || c3.is_null() {
                break 'done;
            }

            ptr::write_bytes(ciphertext_buf, 0, *ciphertext_len);

            msg_mask = CRYPTO_zalloc(msg_len, FILE, 188).cast::<u8>();
            if msg_mask.is_null() {
                break 'done;
            }

            'again: loop {
                if BN_priv_rand_range_ex(k, order, 0, ctx) == 0 {
                    raise_site(&err_sites::SM2_CRYPT_194);
                    break 'done;
                }

                if EC_POINT_mul(group, k_g, k, ptr::null(), ptr::null(), ctx) == 0
                    || EC_POINT_get_affine_coordinates(group, k_g, x1, y1, ctx) == 0
                    || EC_POINT_mul(group, k_p, ptr::null(), p_key, k, ctx) == 0
                    || EC_POINT_get_affine_coordinates(group, k_p, x2, y2, ctx) == 0
                {
                    raise_site(&err_sites::SM2_CRYPT_202);
                    break 'done;
                }

                if BN_bn2binpad(x2, x2y2, field_size) < 0
                    || BN_bn2binpad(y2, x2y2.add(field_size as usize), field_size) < 0
                {
                    raise_site(&err_sites::SM2_CRYPT_208);
                    break 'done;
                }

                /* X9.63 with no salt happens to match the KDF used in SM2 */
                if ossl_ecdh_kdf_X9_63(
                    msg_mask,
                    msg_len,
                    x2y2,
                    2 * field_size as usize,
                    ptr::null(),
                    0,
                    digest,
                    libctx,
                    propq,
                ) == 0
                {
                    raise_site(&err_sites::SM2_CRYPT_215);
                    break 'done;
                }

                if is_all_zeros(msg_mask, msg_len) != 0 {
                    ptr::write_bytes(x2y2, 0, 2 * field_size as usize);
                    continue 'again;
                }

                for i in 0..msg_len {
                    *msg_mask.add(i) ^= *msg.add(i);
                }

                fetched_digest = EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
                if fetched_digest.is_null() {
                    raise_site(&err_sites::SM2_CRYPT_229);
                    break 'done;
                }
                if EVP_DigestInit(hash, fetched_digest) == 0
                    || EVP_DigestUpdate(hash, x2y2.cast::<c_void>(), field_size as usize) == 0
                    || EVP_DigestUpdate(hash, msg.cast::<c_void>(), msg_len) == 0
                    || EVP_DigestUpdate(
                        hash,
                        x2y2.add(field_size as usize).cast::<c_void>(),
                        field_size as usize,
                    ) == 0
                    || EVP_DigestFinal(hash, c3, ptr::null_mut()) == 0
                {
                    raise_site(&err_sites::SM2_CRYPT_237);
                    break 'done;
                }

                ctext.c1x = x1;
                ctext.c1y = y1;
                ctext.c3 = ASN1_OCTET_STRING_new();
                ctext.c2 = ASN1_OCTET_STRING_new();

                if ctext.c3.is_null() || ctext.c2.is_null() {
                    raise_site(&err_sites::SM2_CRYPT_247);
                    break 'done;
                }
                if ASN1_OCTET_STRING_set(ctext.c3, c3, c3_size) == 0
                    || ASN1_OCTET_STRING_set(ctext.c2, msg_mask, msg_len as c_int) == 0
                {
                    raise_site(&err_sites::SM2_CRYPT_252);
                    break 'done;
                }

                let ciphertext_leni = i2d_SM2_Ciphertext(ptr::addr_of!(ctext), ptr::null_mut());
                if ciphertext_leni < 0 {
                    raise_site(&err_sites::SM2_CRYPT_259);
                    break 'done;
                }

                if *ciphertext_len < ciphertext_leni as usize {
                    raise_site(&err_sites::SM2_CRYPT_264);
                    break 'done;
                }

                let mut out = ciphertext_buf;
                let written = i2d_SM2_Ciphertext(ptr::addr_of!(ctext), ptr::addr_of_mut!(out));
                if written < 0 {
                    raise_site(&err_sites::SM2_CRYPT_270);
                    break 'done;
                }
                *ciphertext_len = written as usize;

                rc = 1;
                break 'again;
            }
        }

        EVP_MD_free(fetched_digest);
        ASN1_OCTET_STRING_free(ctext.c2);
        ASN1_OCTET_STRING_free(ctext.c3);
        CRYPTO_free(msg_mask.cast(), FILE, 281);
        CRYPTO_free(x2y2.cast(), FILE, 282);
        CRYPTO_free(c3.cast(), FILE, 283);
        EVP_MD_CTX_free(hash);
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        EC_POINT_free(k_g);
        EC_POINT_free(k_p);
    }
    rc
}

/// `int ossl_sm2_decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *ciphertext,`
/// `size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)` — `sm2_crypt.c:292-432`.
///
/// On failure the caller's buffer is wiped (`:419-420`); `ptext_len` is only moved on success.
///
/// # Safety
/// `key` is live with a private key; `digest` is live; `ciphertext` is `ciphertext_len` bytes;
/// `ptext_buf` holds `*ptext_len` bytes on entry; `ptext_len` is writable.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn ossl_sm2_decrypt(
    key: *const EcKey,
    digest: *const EvpMd,
    ciphertext: *const u8,
    ciphertext_len: usize,
    ptext_buf: *mut u8,
    ptext_len: *mut usize,
) -> c_int {
    let mut rc: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut c1: *mut EcPoint = ptr::null_mut();
    let mut sm2_ctext: *mut Sm2Ciphertext = ptr::null_mut();
    let mut x2y2: *mut u8 = ptr::null_mut();
    let mut computed_c3: *mut u8 = ptr::null_mut();
    let mut msg_mask: *mut u8 = ptr::null_mut();
    let mut hash: *mut EvpMdCtx = ptr::null_mut();

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let group = EC_KEY_get0_group(key);
        let field_size = ec_field_size(group);
        let hash_size = EVP_MD_get_size(digest);
        let libctx = ossl_ec_key_get_libctx(key);
        let propq = ossl_ec_key_get0_propq(key);

        'done: {
            if field_size == 0 || hash_size <= 0 || ciphertext_len > i64::MAX as usize {
                break 'done;
            }

            ptr::write_bytes(ptext_buf, 0xff, *ptext_len);

            let mut in_ = ciphertext;
            sm2_ctext = d2i_SM2_Ciphertext(ptr::addr_of_mut!(in_), ciphertext_len as c_long);

            if sm2_ctext.is_null() {
                raise_site(&err_sites::SM2_CRYPT_325);
                break 'done;
            }

            if ASN1_STRING_length((*sm2_ctext).c3) != hash_size {
                raise_site(&err_sites::SM2_CRYPT_330);
                break 'done;
            }

            let c2 = ASN1_STRING_get0_data((*sm2_ctext).c2);
            let c3_ptr = ASN1_STRING_get0_data((*sm2_ctext).c3);
            let msg_len = ASN1_STRING_length((*sm2_ctext).c2) as usize;
            if *ptext_len < msg_len {
                raise_site(&err_sites::SM2_CRYPT_338);
                break 'done;
            }

            ctx = BN_CTX_new_ex(libctx);
            if ctx.is_null() {
                raise_site(&err_sites::SM2_CRYPT_344);
                break 'done;
            }

            BN_CTX_start(ctx);
            let x2 = BN_CTX_get(ctx);
            let y2 = BN_CTX_get(ctx);

            if y2.is_null() {
                raise_site(&err_sites::SM2_CRYPT_353);
                break 'done;
            }

            msg_mask = CRYPTO_zalloc(msg_len, FILE, 357).cast::<u8>();
            x2y2 = CRYPTO_calloc(2, field_size as usize, FILE, 358).cast::<u8>();
            computed_c3 = CRYPTO_zalloc(hash_size as usize, FILE, 359).cast::<u8>();

            if msg_mask.is_null() || x2y2.is_null() || computed_c3.is_null() {
                break 'done;
            }

            c1 = EC_POINT_new(group);
            if c1.is_null() {
                raise_site(&err_sites::SM2_CRYPT_366);
                break 'done;
            }

            if EC_POINT_set_affine_coordinates(group, c1, (*sm2_ctext).c1x, (*sm2_ctext).c1y, ctx)
                == 0
                || EC_POINT_mul(
                    group,
                    c1,
                    ptr::null(),
                    c1,
                    EC_KEY_get0_private_key(key),
                    ctx,
                ) == 0
                || EC_POINT_get_affine_coordinates(group, c1, x2, y2, ctx) == 0
            {
                raise_site(&err_sites::SM2_CRYPT_375);
                break 'done;
            }

            if BN_bn2binpad(x2, x2y2, field_size) < 0
                || BN_bn2binpad(y2, x2y2.add(field_size as usize), field_size) < 0
                || ossl_ecdh_kdf_X9_63(
                    msg_mask,
                    msg_len,
                    x2y2,
                    2 * field_size as usize,
                    ptr::null(),
                    0,
                    digest,
                    libctx,
                    propq,
                ) == 0
            {
                raise_site(&err_sites::SM2_CRYPT_383);
                break 'done;
            }

            if is_all_zeros(msg_mask, msg_len) != 0 {
                raise_site(&err_sites::SM2_CRYPT_388);
                break 'done;
            }

            for i in 0..msg_len {
                *ptext_buf.add(i) = *c2.add(i) ^ *msg_mask.add(i);
            }

            hash = EVP_MD_CTX_new();
            if hash.is_null() {
                raise_site(&err_sites::SM2_CRYPT_397);
                break 'done;
            }

            if EVP_DigestInit(hash, digest) == 0
                || EVP_DigestUpdate(hash, x2y2.cast::<c_void>(), field_size as usize) == 0
                || EVP_DigestUpdate(hash, ptext_buf.cast::<c_void>(), msg_len) == 0
                || EVP_DigestUpdate(
                    hash,
                    x2y2.add(field_size as usize).cast::<c_void>(),
                    field_size as usize,
                ) == 0
                || EVP_DigestFinal(hash, computed_c3, ptr::null_mut()) == 0
            {
                raise_site(&err_sites::SM2_CRYPT_406);
                break 'done;
            }

            if CRYPTO_memcmp(computed_c3.cast(), c3_ptr.cast(), hash_size as usize) != 0 {
                raise_site(&err_sites::SM2_CRYPT_411);
                break 'done;
            }

            rc = 1;
            *ptext_len = msg_len;
        }

        if rc == 0 {
            ptr::write_bytes(ptext_buf, 0, *ptext_len);
        }

        CRYPTO_free(msg_mask.cast(), FILE, 422);
        CRYPTO_free(x2y2.cast(), FILE, 423);
        CRYPTO_free(computed_c3.cast(), FILE, 424);
        EC_POINT_free(c1);
        if !ctx.is_null() {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(ctx);
        SM2_Ciphertext_free(sm2_ctext);
        EVP_MD_CTX_free(hash);
    }
    rc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_free, BN_hex2bn};
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
    use crate::ec::key::{
        ossl_ec_key_set0_libctx, EC_KEY_free, EC_KEY_new_by_curve_name, EC_KEY_set_private_key,
        EC_KEY_set_public_key,
    };
    use crate::runtime::obj::NID_sm2;

    /// GM/T 0003.5-2012 Annex C (and GB/T 32918.5-2016's), read back from the authority's own
    /// `test/sm2_internal_test.c:264-287`: the private key, the plaintext, the ephemeral nonce and
    /// the expected ciphertext, serialized per GM/T 0009-2012 Sec. 7.2.
    const ANNEX_C_PRIV: &core::ffi::CStr =
        c"3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    const ANNEX_C_MSG: &[u8] = b"encryption standard";
    const ANNEX_C_CTEXT: &str = "307C022004EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73022100E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0042059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766041321886CA989CA9C7D58087307CA93092D651EFA";

    /// Decodes a hex string. Local to the test module so the vector above can be read as the
    /// authority spells it.
    fn unhex(s: &str) -> Vec<u8> {
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            }
        }
        let b = s.as_bytes();
        assert_eq!(b.len() % 2, 0);
        (0..b.len() / 2)
            .map(|i| (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]))
            .collect()
    }

    /// Builds an `EC_KEY` on the SM2 curve from a hex private key, deriving its public half.
    ///
    /// # Safety
    /// The caller owns the returned key.
    unsafe fn key_from_hex(
        libctx: *mut core::ffi::c_void,
        priv_hex: &core::ffi::CStr,
    ) -> *mut EcKey {
        // SAFETY: this function's own contract.
        unsafe {
            let key = EC_KEY_new_by_curve_name(NID_sm2);
            assert!(!key.is_null());
            ossl_ec_key_set0_libctx(key, libctx);
            let group = EC_KEY_get0_group(key);

            let mut priv_bn: *mut BigNum = ptr::null_mut();
            assert!(BN_hex2bn(ptr::addr_of_mut!(priv_bn), priv_hex.as_ptr()) != 0);
            assert_eq!(EC_KEY_set_private_key(key, priv_bn), 1);

            let pt = EC_POINT_new(group);
            assert_eq!(
                EC_POINT_mul(
                    group,
                    pt,
                    priv_bn,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(EC_KEY_set_public_key(key, pt), 1);
            EC_POINT_free(pt);
            BN_free(priv_bn);
            key
        }
    }

    /// The published Annex C ciphertext decrypts to the published plaintext: the derived `C3` and
    /// the mask are closed against the authority's own vector.
    #[test]
    fn the_annex_c_ciphertext_decrypts() {
        // SAFETY: every pointer is this test's own, built below.
        unsafe {
            let libctx = OSSL_LIB_CTX_new();
            let key = key_from_hex(libctx, ANNEX_C_PRIV);
            let md = EVP_MD_fetch(libctx, c"SM3".as_ptr(), ptr::null());
            let ctext = unhex(ANNEX_C_CTEXT);

            let mut pt_size: usize = 0;
            assert_eq!(
                ossl_sm2_plaintext_size(ctext.as_ptr(), ctext.len(), ptr::addr_of_mut!(pt_size)),
                1
            );
            assert_eq!(pt_size, ANNEX_C_MSG.len());

            let mut out = vec![0u8; pt_size];
            let mut out_len = out.len();
            assert_eq!(
                ossl_sm2_decrypt(
                    key,
                    md,
                    ctext.as_ptr(),
                    ctext.len(),
                    out.as_mut_ptr(),
                    ptr::addr_of_mut!(out_len),
                ),
                1
            );
            assert_eq!(&out[..out_len], ANNEX_C_MSG);

            /* A flipped ciphertext byte must not decrypt. */
            let mut bad = ctext.clone();
            bad[10] ^= 1;
            let mut out2 = vec![0u8; pt_size];
            let mut out2_len = out2.len();
            assert_eq!(
                ossl_sm2_decrypt(
                    key,
                    md,
                    bad.as_ptr(),
                    bad.len(),
                    out2.as_mut_ptr(),
                    ptr::addr_of_mut!(out2_len),
                ),
                0
            );

            EVP_MD_free(md);
            EC_KEY_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
    }

    /// `ossl_sm2_ciphertext_size` agrees with the published ciphertext's own length, and an
    /// encrypt/decrypt round trip recovers the plaintext.
    #[test]
    fn the_ciphertext_size_matches_and_a_round_trip_holds() {
        // SAFETY: every pointer is this test's own, built below.
        unsafe {
            let libctx = OSSL_LIB_CTX_new();
            let key = key_from_hex(libctx, ANNEX_C_PRIV);
            let md = EVP_MD_fetch(libctx, c"SM3".as_ptr(), ptr::null());
            let expected_len = unhex(ANNEX_C_CTEXT).len();

            let mut ct_size: usize = 0;
            assert_eq!(
                ossl_sm2_ciphertext_size(key, md, ANNEX_C_MSG.len(), ptr::addr_of_mut!(ct_size)),
                1
            );
            // The authority's formula is the one the unit copies: it charges the full
            // `field_size + 1` to *both* integers, so it over-estimates by a byte when neither
            // coordinate's top bit is set. The published ciphertext is the exact length.
            assert!(ct_size >= expected_len);
            assert_eq!(ct_size, expected_len + 1);

            let mut ctext = vec![0u8; ct_size];
            let mut ctext_len = ctext.len();
            assert_eq!(
                ossl_sm2_encrypt(
                    key,
                    md,
                    ANNEX_C_MSG.as_ptr(),
                    ANNEX_C_MSG.len(),
                    ctext.as_mut_ptr(),
                    ptr::addr_of_mut!(ctext_len),
                ),
                1
            );
            // The exact DER length depends on the two ephemeral coordinates' leading zeroes, so
            // the random encryption's own length is bounded rather than pinned; the size query's 127
            // is the authority's own over-estimate (asserted above).
            assert!(ctext_len <= ct_size);
            assert!(ctext_len + 1 >= expected_len);

            let mut out = vec![0u8; ANNEX_C_MSG.len()];
            let mut out_len = out.len();
            assert_eq!(
                ossl_sm2_decrypt(
                    key,
                    md,
                    ctext.as_ptr(),
                    ctext_len,
                    out.as_mut_ptr(),
                    ptr::addr_of_mut!(out_len),
                ),
                1
            );
            assert_eq!(&out[..out_len], ANNEX_C_MSG);

            EVP_MD_free(md);
            EC_KEY_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
    }
}
