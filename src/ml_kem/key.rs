//! `crypto/ml_kem/ml_kem.c` — the key lifecycle, serialisation and the provider API.
//!
//! This file is `ml_kem.c:1592-2452`: the two wire-format encoders and their parsers, the
//! FIPS 203 `KeyGen_internal`/`Encaps_internal`/`Decaps_internal` trio (`genkey`, `encap`,
//! `decap`), `add_storage`, and the fifteen functions the `ossl_ml_kem_*` prefix exports to
//! `providers/implementations/keymgmt/ml_kem_kmgmt.c.in` and
//! `providers/implementations/kem/ml_kem_kem.c.in`.
//!
//! ## The error sites are the census's own constants
//!
//! Every `ERR_raise_data` in this half is a registered raise site with a coordinate in
//! `forensics/atlas/err-raise-sites.json`: the nine `err_sites::ML_KEM_*` constants below are
//! those coordinates, carrying the authority's own library and reason, so the message text is
//! the only thing this file supplies.
//!
//! ## `add_storage` recovers two allocations by pointer arithmetic
//!
//! The `|m|` matrix is the tail of the `|t|` allocation and the `|z|`/`|d|` block the tail of the
//! `|s|` allocation, which is why [`crate::ml_kem`]'s six `#[repr(C)]` allocation structs carry
//! their `offset_of!` assertions. Both are reproduced here as the C writes them, `pub.add(rank)`
//! and `priv.cast::<u8>().add(rank * size_of::<Scalar>())`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::CStr;

use crate::evp::digest::{
    EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EVP_MD_up_ref,
};
use crate::evp::pkey::{OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY};
use crate::rand::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};
use crate::runtime::constant_time::{constant_time_eq_int_8, constant_time_select_8};
use crate::runtime::err::{err_sites, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, CRYPTO_memdup, OPENSSL_cleanse,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_free, CRYPTO_secure_malloc};

use super::arith::{
    cbd1, decrypt_cpa, encrypt_cpa, gencbd_vector_ntt, hash_g, hash_h, hash_h_pubkey, kdf,
    matrix_expand, matrix_mult_transpose_add, vector_decode_12, vector_encode,
};
use super::{
    ctext_bytes, ossl_ml_kem_decoded_key, ossl_ml_kem_have_dkenc, ossl_ml_kem_have_prvkey,
    ossl_ml_kem_have_pubkey, ossl_ml_kem_have_seed, MlKemKey, MlKemVinfo, Scalar, FILE,
    ML_KEM_KEY_PROV_FLAGS_DEFAULT, ML_KEM_KEY_RETAIN_SEED, ML_KEM_PKHASH_BYTES,
    ML_KEM_RANDOM_BYTES, ML_KEM_SEED_BYTES, ML_KEM_SHARED_SECRET_BYTES, VINFO_MAP,
};

/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `core_dispatch.h:649`, `PRIVATE_KEY | PUBLIC_KEY`.
///
/// `src/evp/pkey.rs` keeps its own copy private, so this unit carries the authority's pair
/// directly rather than widening another module's constant.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int = 0x01 | 0x02;

/// The allocator coordinates `add_storage` and the lifecycle functions pass.
const LINE_ADD_STORAGE: c_int = 1907;
/// `ossl_ml_kem_key_new`'s `OPENSSL_malloc(sizeof(*key))`, `ml_kem.c:2002`.
const LINE_KEY_NEW: c_int = 2002;
/// `ossl_ml_kem_key_dup`'s `OPENSSL_memdup`, `ml_kem.c:2042`.
const LINE_KEY_DUP: c_int = 2042;
/// `ossl_ml_kem_key_dup`'s public-arm `OPENSSL_memdup(key->t, ...)`, `ml_kem.c:2061`.
const LINE_DUP_MEMDUP_PUB: c_int = 2061;
/// `ossl_ml_kem_key_dup`'s private-arm `OPENSSL_memdup(key->t, ...)`, `ml_kem.c:2065`.
const LINE_DUP_MEMDUP_PRV: c_int = 2065;
/// `ossl_ml_kem_key_dup`'s private-arm `OPENSSL_secure_malloc`, `ml_kem.c:2066`.
const LINE_DUP_SECURE: c_int = 2066;
/// `ossl_ml_kem_key_free`'s `OPENSSL_free(key)`, `ml_kem.c:2101`.
const LINE_KEY_FREE: c_int = 2101;
/// `ossl_ml_kem_set_seed`'s `OPENSSL_secure_malloc(seedlen)`, `ml_kem.c:2155`.
const LINE_SET_SEED: c_int = 2155;
/// `ossl_ml_kem_parse_public_key`'s `OPENSSL_malloc(vinfo->puballoc)`, `ml_kem.c:2186`.
const LINE_PARSE_PUB: c_int = 2186;
/// `ossl_ml_kem_parse_private_key`'s two allocations, `ml_kem.c:2217`/`2218`.
const LINE_PARSE_PRV: c_int = 2217;
/// `ml_kem.c:2218`.
const LINE_PARSE_PRV_SECURE: c_int = 2218;
/// `ossl_ml_kem_genkey`'s two allocations, `ml_kem.c:2266`/`2267`.
const LINE_GENKEY_PUB: c_int = 2266;
/// `ml_kem.c:2267`.
const LINE_GENKEY_PRV: c_int = 2267;
/// `ossl_ml_kem_key_reset`'s three secure-frees, `ml_kem.c:1952`/`1954`/`1963`.
const LINE_RESET_SEEDBUF: c_int = 1952;
/// `ml_kem.c:1954`.
const LINE_RESET_DKENC: c_int = 1954;
/// `ml_kem.c:1963`.
const LINE_RESET_PRV: c_int = 1963;

/// Raise an error whose message is `prefix || algorithm_name || suffix`.
///
/// The authority's format strings are `"... %s ..."` fed `vinfo->algorithm_name`, so the three
/// pieces are concatenated into one NUL-terminated buffer rather than formatted by `printf`.
///
/// # Safety
/// `alg` must be a NUL-terminated C string.
unsafe fn raise_with_alg(
    site: &crate::runtime::err::err_sites::ErrSite,
    prefix: &str,
    alg: *const c_char,
    suffix: &str,
) {
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

/// Raise a fixed message.
unsafe fn raise_fixed(site: &crate::runtime::err::err_sites::ErrSite, msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
}

/// `ossl_ml_kem_get_vinfo(evp_type)` — `ml_kem.c:1977-1988`.
///
/// # Safety
/// Nothing: the answer is a pointer into this module's own static table or NULL.
pub(crate) unsafe fn ossl_ml_kem_get_vinfo(evp_type: c_int) -> *const MlKemVinfo {
    match evp_type {
        super::EVP_PKEY_ML_KEM_512 => &VINFO_MAP.0[0],
        super::EVP_PKEY_ML_KEM_768 => &VINFO_MAP.0[1],
        super::EVP_PKEY_ML_KEM_1024 => &VINFO_MAP.0[2],
        _ => ptr::null(),
    }
}

/// `encode_pubkey(out, key)` — `ml_kem.c:1600-1607`.
///
/// # Safety
/// `out` must be writable for `pubkey_bytes` and `key` live with a populated `t`/`rho`.
unsafe fn encode_pubkey(out: *mut u8, key: *const MlKemKey) {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let rank = (*vinfo).rank;
        vector_encode(out, (*key).t, 12, rank);
        ptr::copy_nonoverlapping(
            (*key).rho,
            out.add((*vinfo).vector_bytes),
            ML_KEM_RANDOM_BYTES,
        );
    }
}

/// `encode_prvkey(out, key)` — `ml_kem.c:1615-1626`.
///
/// # Safety
/// `out` must be writable for `prvkey_bytes` and `key` live with a populated private half.
unsafe fn encode_prvkey(out: *mut u8, key: *const MlKemKey) {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let rank = (*vinfo).rank;
        let mut p = out;

        vector_encode(p, (*key).s, 12, rank);
        p = p.add((*vinfo).vector_bytes);
        encode_pubkey(p, key);
        p = p.add((*vinfo).pubkey_bytes);
        ptr::copy_nonoverlapping((*key).pkhash, p, ML_KEM_PKHASH_BYTES);
        p = p.add(ML_KEM_PKHASH_BYTES);
        ptr::copy_nonoverlapping((*key).z, p, ML_KEM_RANDOM_BYTES);
    }
}

/// `parse_pubkey(in, mdctx, key)` — `ml_kem.c:1636-1661`.
///
/// # Safety
/// `in` must be readable for `pubkey_bytes` and `key` live with allocated storage.
unsafe fn parse_pubkey(
    in_: *const u8,
    mdctx: *mut crate::evp::digest::EvpMdCtx,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;

        // Decode and check |t|
        if vector_decode_12((*key).t, in_, (*vinfo).rank) == 0 {
            raise_with_alg(
                &err_sites::ML_KEM_1642,
                "",
                (*vinfo).algorithm_name,
                " invalid public 't' vector",
            );
            return 0;
        }
        // Save the matrix |m| recovery seed |rho|
        ptr::copy_nonoverlapping(
            in_.add((*vinfo).vector_bytes),
            (*key).rho,
            ML_KEM_RANDOM_BYTES,
        );
        if hash_h((*key).pkhash, in_, (*vinfo).pubkey_bytes, mdctx, key) == 0
            || matrix_expand(mdctx, key) == 0
        {
            raise_with_alg(
                &err_sites::ML_KEM_1655,
                "internal error while parsing ",
                (*vinfo).algorithm_name,
                " public key",
            );
            return 0;
        }
        1
    }
}

/// `parse_prvkey(in, mdctx, key)` — `ml_kem.c:1669-1697`.
///
/// # Safety
/// `in` must be readable for `prvkey_bytes` and `key` live with allocated storage.
unsafe fn parse_prvkey(
    in_: *const u8,
    mdctx: *mut crate::evp::digest::EvpMdCtx,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let mut p = in_;

        // Decode and check |s|.
        if vector_decode_12((*key).s, p, (*vinfo).rank) == 0 {
            raise_with_alg(
                &err_sites::ML_KEM_1675,
                "",
                (*vinfo).algorithm_name,
                " invalid private 's' vector",
            );
            return 0;
        }
        p = p.add((*vinfo).vector_bytes);

        if parse_pubkey(p, mdctx, key) == 0 {
            return 0;
        }
        p = p.add((*vinfo).pubkey_bytes);

        // Check public key hash.
        if CRYPTO_memcmp((*key).pkhash.cast(), p.cast(), ML_KEM_PKHASH_BYTES) != 0 {
            raise_with_alg(
                &err_sites::ML_KEM_1688,
                "",
                (*vinfo).algorithm_name,
                " public key hash mismatch",
            );
            return 0;
        }
        p = p.add(ML_KEM_PKHASH_BYTES);

        ptr::copy_nonoverlapping(p, (*key).z, ML_KEM_RANDOM_BYTES);
        1
    }
}

/// `genkey(seed, mdctx, pubenc, key)` — `ml_kem.c:1724-1791`, FIPS 203 Algorithm 16 inlined.
///
/// # Safety
/// `key` must have preallocated storage for `rho`, `pkhash`, `t`, `m`, `s` and `z`.
unsafe fn genkey(
    seed: *const u8,
    mdctx: *mut crate::evp::digest::EvpMdCtx,
    pubenc: *mut u8,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut hashed = [0u8; 2 * ML_KEM_RANDOM_BYTES];
        let sigma = hashed.as_ptr().add(ML_KEM_RANDOM_BYTES);
        let mut augmented_seed = [0u8; ML_KEM_RANDOM_BYTES + 1];
        let vinfo = (*key).vinfo;
        let cbd_1 = cbd1((*vinfo).evp_type);
        let rank = (*vinfo).rank;
        let mut counter: u8 = 0;

        // Use the "d" seed salted with the rank to derive the public and private seeds rho and sigma.
        ptr::copy_nonoverlapping(seed, augmented_seed.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
        augmented_seed[ML_KEM_RANDOM_BYTES] = rank as u8;
        if hash_g(
            hashed.as_mut_ptr(),
            augmented_seed.as_ptr(),
            augmented_seed.len(),
            mdctx,
            key,
        ) == 0
        {
            OPENSSL_cleanse(augmented_seed.as_mut_ptr().cast(), augmented_seed.len());
            OPENSSL_cleanse(hashed.as_mut_ptr().cast(), hashed.len());
            raise_with_alg(
                &err_sites::ML_KEM_1786,
                "internal error while generating ",
                (*vinfo).algorithm_name,
                " private key",
            );
            return 0;
        }
        ptr::copy_nonoverlapping(hashed.as_ptr(), (*key).rho, ML_KEM_RANDOM_BYTES);

        // FIPS 203 |e| vector is initial value of key->t
        let ret;
        if matrix_expand(mdctx, key) == 0
            || gencbd_vector_ntt((*key).s, cbd_1, &mut counter, sigma, rank, mdctx, key) == 0
            || gencbd_vector_ntt((*key).t, cbd_1, &mut counter, sigma, rank, mdctx, key) == 0
        {
            ret = 0;
        } else {
            // To |e| we now add the product of transpose |m| and |s|, giving |t|.
            matrix_mult_transpose_add((*key).t, (*key).m, (*key).s, rank);

            if pubenc.is_null() {
                // Incremental digest of public key without in-full serialisation.
                ret = c_int::from(hash_h_pubkey((*key).pkhash, mdctx, key) != 0);
            } else {
                encode_pubkey(pubenc, key);
                ret = c_int::from(
                    hash_h((*key).pkhash, pubenc, (*vinfo).pubkey_bytes, mdctx, key) != 0,
                );
            }
        }

        if ret != 0 {
            // Save |z| portion of seed for "implicit rejection" on failure.
            ptr::copy_nonoverlapping(seed.add(ML_KEM_RANDOM_BYTES), (*key).z, ML_KEM_RANDOM_BYTES);

            // Optionally save the |d| portion of the seed
            (*key).d = (*key).z.add(ML_KEM_RANDOM_BYTES);
            if (*key).prov_flags & ML_KEM_KEY_RETAIN_SEED != 0 {
                ptr::copy_nonoverlapping(seed, (*key).d, ML_KEM_RANDOM_BYTES);
            } else {
                OPENSSL_cleanse((*key).d.cast(), ML_KEM_RANDOM_BYTES);
                (*key).d = ptr::null_mut();
            }
        }

        OPENSSL_cleanse(augmented_seed.as_mut_ptr().cast(), augmented_seed.len());
        OPENSSL_cleanse(hashed.as_mut_ptr().cast(), hashed.len());
        if ret == 0 {
            raise_with_alg(
                &err_sites::ML_KEM_1786,
                "internal error while generating ",
                (*vinfo).algorithm_name,
                " private key",
            );
        }
        ret
    }
}

/// `encap(ctext, secret, entropy, tmp, mdctx, key)` — `ml_kem.c:1801-1824`, FIPS 203 Algorithm 17.
///
/// # Safety
/// `tmp` must be live for `2 * rank` scalars and `ctext` for `ctext_bytes`.
unsafe fn encap(
    ctext: *mut u8,
    secret: *mut u8,
    entropy: *const u8,
    tmp: *mut Scalar,
    mdctx: *mut crate::evp::digest::EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut input = [0u8; ML_KEM_RANDOM_BYTES + ML_KEM_PKHASH_BYTES];
        let mut kr = [0u8; ML_KEM_SHARED_SECRET_BYTES + ML_KEM_RANDOM_BYTES];
        let r = kr.as_mut_ptr().add(ML_KEM_SHARED_SECRET_BYTES);

        ptr::copy_nonoverlapping(entropy, input.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
        ptr::copy_nonoverlapping(
            (*key).pkhash,
            input.as_mut_ptr().add(ML_KEM_RANDOM_BYTES),
            ML_KEM_PKHASH_BYTES,
        );
        let ret = hash_g(kr.as_mut_ptr(), input.as_ptr(), input.len(), mdctx, key) != 0
            && encrypt_cpa(ctext, entropy, r, tmp, mdctx, key) != 0;
        OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len());

        if ret {
            ptr::copy_nonoverlapping(kr.as_ptr(), secret, ML_KEM_SHARED_SECRET_BYTES);
        } else {
            raise_with_alg(
                &err_sites::ML_KEM_1819,
                "internal error while performing ",
                (*(*key).vinfo).algorithm_name,
                " encapsulation",
            );
        }
        OPENSSL_cleanse(kr.as_mut_ptr().cast(), kr.len());
        if ret {
            1
        } else {
            0
        }
    }
}

/// `decap(secret, ctext, tmp_ctext, tmp, mdctx, key)` — `ml_kem.c:1837-1890`, Algorithm 18.
///
/// # Safety
/// `tmp_ctext` must be live for `ctext_bytes` and `tmp` for `2 * rank` scalars.
unsafe fn decap(
    secret: *mut u8,
    ctext: *const u8,
    tmp_ctext: *mut u8,
    tmp: *mut Scalar,
    mdctx: *mut crate::evp::digest::EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut decrypted = [0u8; ML_KEM_SHARED_SECRET_BYTES + ML_KEM_PKHASH_BYTES];
        let mut failure_key = [0u8; ML_KEM_RANDOM_BYTES];
        let mut kr = [0u8; ML_KEM_SHARED_SECRET_BYTES + ML_KEM_RANDOM_BYTES];
        let r = kr.as_mut_ptr().add(ML_KEM_SHARED_SECRET_BYTES);
        let pkhash = (*key).pkhash;
        let vinfo = (*key).vinfo;

        if kdf(
            failure_key.as_mut_ptr(),
            (*key).z,
            ctext,
            (*vinfo).ctext_bytes,
            mdctx,
            key,
        ) == 0
        {
            raise_with_alg(
                &err_sites::ML_KEM_1866,
                "internal error while performing ",
                (*vinfo).algorithm_name,
                " decapsulation",
            );
            OPENSSL_cleanse(failure_key.as_mut_ptr().cast(), failure_key.len());
            return 0;
        }
        decrypt_cpa(decrypted.as_mut_ptr(), ctext, tmp, key);
        ptr::copy_nonoverlapping(
            pkhash,
            decrypted.as_mut_ptr().add(ML_KEM_SHARED_SECRET_BYTES),
            ML_KEM_PKHASH_BYTES,
        );
        if hash_g(
            kr.as_mut_ptr(),
            decrypted.as_ptr(),
            decrypted.len(),
            mdctx,
            key,
        ) == 0
            || encrypt_cpa(tmp_ctext, decrypted.as_ptr(), r, tmp, mdctx, key) == 0
        {
            ptr::copy_nonoverlapping(failure_key.as_ptr(), secret, ML_KEM_SHARED_SECRET_BYTES);
            OPENSSL_cleanse(decrypted.as_mut_ptr().cast(), ML_KEM_SHARED_SECRET_BYTES);
            OPENSSL_cleanse(kr.as_mut_ptr().cast(), kr.len());
            OPENSSL_cleanse(failure_key.as_mut_ptr().cast(), failure_key.len());
            return 1;
        }
        let mask = constant_time_eq_int_8(
            0,
            CRYPTO_memcmp(ctext.cast(), tmp_ctext.cast(), (*vinfo).ctext_bytes),
        );
        for i in 0..ML_KEM_SHARED_SECRET_BYTES {
            *secret.add(i) = constant_time_select_8(mask, kr[i], failure_key[i]);
        }
        OPENSSL_cleanse(decrypted.as_mut_ptr().cast(), ML_KEM_SHARED_SECRET_BYTES);
        OPENSSL_cleanse(kr.as_mut_ptr().cast(), kr.len());
        OPENSSL_cleanse(failure_key.as_mut_ptr().cast(), failure_key.len());
        1
    }
}

/// `add_storage(pub, priv, private, dup, key)` — `ml_kem.c:1899-1937`.
///
/// # Safety
/// `key` must be live and `pub`/`priv` the allocations from the matching `*Alloc` type.
unsafe fn add_storage(
    pub_: *mut Scalar,
    priv_: *mut Scalar,
    private: c_int,
    dup: c_int,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let rank = (*(*key).vinfo).rank as usize;

        if pub_.is_null() || (private != 0 && priv_.is_null()) {
            // It is legal to call free with a NULL pointer, so always attempt to free both.
            CRYPTO_free(pub_.cast(), FILE, LINE_ADD_STORAGE);
            CRYPTO_secure_free(priv_.cast(), FILE, LINE_ADD_STORAGE);
            return 0;
        }

        // Zero the key hash when creating fresh keys.
        if dup == 0 {
            ptr::write_bytes((*key).rho_pkhash.as_mut_ptr(), 0, 64);
        }
        (*key).rho = (*key).rho_pkhash.as_mut_ptr();
        (*key).pkhash = (*key).rho_pkhash.as_mut_ptr().add(ML_KEM_RANDOM_BYTES);
        (*key).d = ptr::null_mut();
        (*key).z = ptr::null_mut();

        // A public key needs space for |t| and |m|
        (*key).t = pub_;
        (*key).m = pub_.add(rank);

        // A private key also needs space for |s| and |z|.
        if private != 0 {
            (*key).s = priv_;
            (*key).z = priv_
                .cast::<u8>()
                .add(rank * core::mem::size_of::<Scalar>());
        }
        1
    }
}

/// `ossl_ml_kem_key_reset(key)` — `ml_kem.c:1943-1967`.
///
/// # Safety
/// `key` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_kem_key_reset(key: *mut MlKemKey) {
    // SAFETY: `key` is live (or NULL, which returns above) per the contract.
    unsafe {
        if !(*key).seedbuf.is_null() {
            CRYPTO_secure_clear_free(
                (*key).seedbuf.cast(),
                ML_KEM_SEED_BYTES,
                FILE,
                LINE_RESET_SEEDBUF,
            );
        }
        if ossl_ml_kem_have_dkenc(key) {
            CRYPTO_secure_clear_free(
                (*key).encoded_dk.cast(),
                (*(*key).vinfo).prvkey_bytes,
                FILE,
                LINE_RESET_DKENC,
            );
        }

        if !(*key).t.is_null() {
            if ossl_ml_kem_have_prvkey(key) {
                CRYPTO_secure_clear_free(
                    (*key).s.cast(),
                    (*(*key).vinfo).prvalloc,
                    FILE,
                    LINE_RESET_PRV,
                );
            }
            CRYPTO_free((*key).t.cast(), FILE, LINE_RESET_PRV);
        }
        (*key).d = ptr::null_mut();
        (*key).z = ptr::null_mut();
        (*key).seedbuf = ptr::null_mut();
        (*key).encoded_dk = ptr::null_mut();
        (*key).s = ptr::null_mut();
        (*key).m = ptr::null_mut();
        (*key).t = ptr::null_mut();
    }
}

/// `ossl_ml_kem_key_new(libctx, properties, evp_type)` — `ml_kem.c:1990-2026`.
///
/// # Safety
/// `properties` must be NULL or a NUL-terminated C string.
pub(crate) unsafe fn ossl_ml_kem_key_new(
    libctx: *mut c_void,
    properties: *const c_char,
    evp_type: c_int,
) -> *mut MlKemKey {
    // SAFETY: the answer is a pointer into this module's static table.
    let vinfo = unsafe { ossl_ml_kem_get_vinfo(evp_type) };
    if vinfo.is_null() {
        // SAFETY: the message is a NUL-terminated literal.
        unsafe {
            raise_fixed(
                &err_sites::ML_KEM_1997,
                &format!("unsupported ML-KEM key type: {evp_type}"),
            );
        }
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_malloc` answers NULL on failure, which is checked.
    let key =
        CRYPTO_malloc(core::mem::size_of::<MlKemKey>(), FILE, LINE_KEY_NEW).cast::<MlKemKey>();
    if key.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `key` is a fresh allocation; every field is written below.
    unsafe {
        (*key).vinfo = vinfo;
        (*key).libctx = libctx;
        (*key).prov_flags = ML_KEM_KEY_PROV_FLAGS_DEFAULT;
        (*key).shake128_md = EVP_MD_fetch(libctx, c"SHAKE128".as_ptr(), properties);
        (*key).shake256_md = EVP_MD_fetch(libctx, c"SHAKE256".as_ptr(), properties);
        (*key).sha3_256_md = EVP_MD_fetch(libctx, c"SHA3-256".as_ptr(), properties);
        (*key).sha3_512_md = EVP_MD_fetch(libctx, c"SHA3-512".as_ptr(), properties);
        (*key).d = ptr::null_mut();
        (*key).z = ptr::null_mut();
        (*key).rho = ptr::null_mut();
        (*key).pkhash = ptr::null_mut();
        (*key).encoded_dk = ptr::null_mut();
        (*key).seedbuf = ptr::null_mut();
        (*key).s = ptr::null_mut();
        (*key).m = ptr::null_mut();
        (*key).t = ptr::null_mut();

        if !(*key).shake128_md.is_null()
            && !(*key).shake256_md.is_null()
            && !(*key).sha3_256_md.is_null()
            && !(*key).sha3_512_md.is_null()
        {
            return key;
        }

        ossl_ml_kem_key_free(key);
        raise_with_alg(
            &err_sites::ML_KEM_2022,
            "missing SHA3 digest algorithms while creating ",
            (*vinfo).algorithm_name,
            " key",
        );
        ptr::null_mut()
    }
}

/// `ossl_ml_kem_key_dup(key, selection)` — `ml_kem.c:2028-2088`.
///
/// # Safety
/// `key` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_kem_key_dup(key: *const MlKemKey, selection: c_int) -> *mut MlKemKey {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut selection = selection;
        let mut ok = 0;

        if key.is_null() {
            return ptr::null_mut();
        }
        let vinfo = (*key).vinfo;

        if ossl_ml_kem_decoded_key(key) {
            return ptr::null_mut();
        }

        let ret = CRYPTO_memdup(
            key.cast(),
            core::mem::size_of::<MlKemKey>(),
            FILE,
            LINE_KEY_DUP,
        )
        .cast::<MlKemKey>();
        if ret.is_null() {
            return ptr::null_mut();
        }

        (*ret).d = ptr::null_mut();
        (*ret).z = ptr::null_mut();
        (*ret).rho = ptr::null_mut();
        (*ret).pkhash = ptr::null_mut();
        (*ret).s = ptr::null_mut();
        (*ret).m = ptr::null_mut();
        (*ret).t = ptr::null_mut();

        // Clear selection bits we can't fulfill
        if !ossl_ml_kem_have_pubkey(key) {
            selection = 0;
        } else if !ossl_ml_kem_have_prvkey(key) {
            selection &= !OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        } else if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
            selection &= !OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        }

        match selection & OSSL_KEYMGMT_SELECT_KEYPAIR {
            0 => ok = 1,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY => {
                ok = add_storage(
                    CRYPTO_memdup(
                        (*key).t.cast(),
                        (*vinfo).puballoc,
                        FILE,
                        LINE_DUP_MEMDUP_PUB,
                    )
                    .cast::<Scalar>(),
                    ptr::null_mut(),
                    0,
                    1,
                    ret,
                );
            }
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY => {
                // Frees both and returns 0 if either is NULL
                ok = add_storage(
                    CRYPTO_memdup(
                        (*key).t.cast(),
                        (*vinfo).puballoc,
                        FILE,
                        LINE_DUP_MEMDUP_PRV,
                    )
                    .cast::<Scalar>(),
                    CRYPTO_secure_malloc((*vinfo).prvalloc, FILE, LINE_DUP_SECURE).cast::<Scalar>(),
                    1,
                    1,
                    ret,
                );
                if ok != 0 {
                    ptr::copy_nonoverlapping(
                        (*key).s.cast::<u8>(),
                        (*ret).s.cast::<u8>(),
                        (*vinfo).prvalloc,
                    );
                    // Duplicated keys retain |d|, if available
                    if !(*key).d.is_null() {
                        (*ret).d = (*ret).z.add(ML_KEM_RANDOM_BYTES);
                    }
                }
            }
            _ => {}
        }

        if ok == 0 {
            CRYPTO_free(ret.cast(), FILE, LINE_KEY_FREE);
            return ptr::null_mut();
        }

        EVP_MD_up_ref((*ret).shake128_md);
        EVP_MD_up_ref((*ret).shake256_md);
        EVP_MD_up_ref((*ret).sha3_256_md);
        EVP_MD_up_ref((*ret).sha3_512_md);

        ret
    }
}

/// `ossl_ml_kem_key_free(key)` — `ml_kem.c:2090-2102`.
///
/// # Safety
/// `key` must be live, or NULL.
pub(crate) unsafe fn ossl_ml_kem_key_free(key: *mut MlKemKey) {
    if key.is_null() {
        return;
    }
    // SAFETY: `key` is live per the contract.
    unsafe {
        EVP_MD_free((*key).shake128_md);
        EVP_MD_free((*key).shake256_md);
        EVP_MD_free((*key).sha3_256_md);
        EVP_MD_free((*key).sha3_512_md);

        ossl_ml_kem_key_reset(key);
        CRYPTO_free(key.cast(), FILE, LINE_KEY_FREE);
    }
}

/// `ossl_ml_kem_encode_public_key(out, len, key)` — `ml_kem.c:2105-2113`.
///
/// # Safety
/// `out` must be writable for `len` bytes.
pub(crate) unsafe fn ossl_ml_kem_encode_public_key(
    out: *mut u8,
    len: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null() || !ossl_ml_kem_have_pubkey(key) || len != (*(*key).vinfo).pubkey_bytes {
            return 0;
        }
        encode_pubkey(out, key);
        1
    }
}

/// `ossl_ml_kem_encode_private_key(out, len, key)` — `ml_kem.c:2116-2124`.
///
/// # Safety
/// `out` must be writable for `len` bytes.
pub(crate) unsafe fn ossl_ml_kem_encode_private_key(
    out: *mut u8,
    len: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null() || !ossl_ml_kem_have_prvkey(key) || len != (*(*key).vinfo).prvkey_bytes {
            return 0;
        }
        encode_prvkey(out, key);
        1
    }
}

/// `ossl_ml_kem_encode_seed(out, len, key)` — `ml_kem.c:2126-2139`.
///
/// # Safety
/// `out` must be writable for `len` bytes.
pub(crate) unsafe fn ossl_ml_kem_encode_seed(
    out: *mut u8,
    len: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null() || (*key).d.is_null() || len != ML_KEM_SEED_BYTES {
            return 0;
        }
        // The |d| component of the seed is stored last, so we must copy each separately.
        ptr::copy_nonoverlapping((*key).d, out, ML_KEM_RANDOM_BYTES);
        ptr::copy_nonoverlapping((*key).z, out.add(ML_KEM_RANDOM_BYTES), ML_KEM_RANDOM_BYTES);
        1
    }
}

/// `ossl_ml_kem_set_seed(seed, seedlen, key)` — `ml_kem.c:2146-2166`.
///
/// # Safety
/// `seed` must be readable for `seedlen` bytes.
pub(crate) unsafe fn ossl_ml_kem_set_seed(
    seed: *const u8,
    seedlen: usize,
    key: *mut MlKemKey,
) -> *mut MlKemKey {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null()
            || ossl_ml_kem_have_pubkey(key)
            || ossl_ml_kem_have_seed(key)
            || seedlen != ML_KEM_SEED_BYTES
        {
            return ptr::null_mut();
        }

        if (*key).seedbuf.is_null() {
            (*key).seedbuf = CRYPTO_secure_malloc(seedlen, FILE, LINE_SET_SEED).cast::<u8>();
            if (*key).seedbuf.is_null() {
                return ptr::null_mut();
            }
        }

        (*key).z = (*key).seedbuf;
        (*key).d = (*key).z.add(ML_KEM_RANDOM_BYTES);
        ptr::copy_nonoverlapping(seed, (*key).d, ML_KEM_RANDOM_BYTES);
        ptr::copy_nonoverlapping(seed.add(ML_KEM_RANDOM_BYTES), (*key).z, ML_KEM_RANDOM_BYTES);
        key
    }
}

/// `ossl_ml_kem_parse_public_key(in, len, key)` — `ml_kem.c:2169-2193`.
///
/// # Safety
/// `in` must be readable for `len` bytes.
pub(crate) unsafe fn ossl_ml_kem_parse_public_key(
    in_: *const u8,
    len: usize,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut ret = 0;

        if key.is_null() || ossl_ml_kem_have_pubkey(key) || ossl_ml_kem_have_dkenc(key) {
            return 0;
        }
        let vinfo = (*key).vinfo;

        let mdctx = EVP_MD_CTX_new();
        if len != (*vinfo).pubkey_bytes || mdctx.is_null() {
            return 0;
        }

        if add_storage(
            CRYPTO_malloc((*vinfo).puballoc, FILE, LINE_PARSE_PUB).cast::<Scalar>(),
            ptr::null_mut(),
            0,
            0,
            key,
        ) != 0
        {
            ret = parse_pubkey(in_, mdctx, key);
        }

        if ret == 0 {
            ossl_ml_kem_key_reset(key);
        }
        EVP_MD_CTX_free(mdctx);
        ret
    }
}

/// `ossl_ml_kem_parse_private_key(in, len, key)` — `ml_kem.c:2196-2225`.
///
/// # Safety
/// `in` must be readable for `len` bytes.
pub(crate) unsafe fn ossl_ml_kem_parse_private_key(
    in_: *const u8,
    len: usize,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut ret = 0;

        if key.is_null() || ossl_ml_kem_have_pubkey(key) || ossl_ml_kem_have_dkenc(key) {
            return 0;
        }
        let vinfo = (*key).vinfo;

        let mdctx = EVP_MD_CTX_new();
        if len != (*vinfo).prvkey_bytes || mdctx.is_null() {
            return 0;
        }

        // Clear any unused seed
        ossl_ml_kem_key_reset(key);

        if add_storage(
            CRYPTO_malloc((*vinfo).puballoc, FILE, LINE_PARSE_PRV).cast::<Scalar>(),
            CRYPTO_secure_malloc((*vinfo).prvalloc, FILE, LINE_PARSE_PRV_SECURE).cast::<Scalar>(),
            1,
            0,
            key,
        ) != 0
        {
            ret = parse_prvkey(in_, mdctx, key);
        }

        if ret == 0 {
            ossl_ml_kem_key_reset(key);
        }
        EVP_MD_CTX_free(mdctx);
        ret
    }
}

/// `ossl_ml_kem_genkey(pubenc, publen, key)` — `ml_kem.c:2231-2287`.
///
/// # Safety
/// `pubenc` must be NULL or writable for `publen` bytes.
pub(crate) unsafe fn ossl_ml_kem_genkey(
    pubenc: *mut u8,
    publen: usize,
    key: *mut MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut seed = [0u8; ML_KEM_SEED_BYTES];
        let mut ret = 0;

        if key.is_null() || ossl_ml_kem_have_pubkey(key) || ossl_ml_kem_have_dkenc(key) {
            return 0;
        }
        let vinfo = (*key).vinfo;

        if !pubenc.is_null() && publen != (*vinfo).pubkey_bytes {
            return 0;
        }

        if !(*key).seedbuf.is_null() {
            if ossl_ml_kem_encode_seed(seed.as_mut_ptr(), seed.len(), key) == 0 {
                return 0;
            }
            ossl_ml_kem_key_reset(key);
        } else if RAND_priv_bytes_ex(
            (*key).libctx,
            seed.as_mut_ptr(),
            seed.len(),
            (*vinfo).secbits as u32,
        ) <= 0
        {
            return 0;
        }

        let mdctx = EVP_MD_CTX_new();
        if mdctx.is_null() {
            return 0;
        }

        if add_storage(
            CRYPTO_malloc((*vinfo).puballoc, FILE, LINE_GENKEY_PUB).cast::<Scalar>(),
            CRYPTO_secure_malloc((*vinfo).prvalloc, FILE, LINE_GENKEY_PRV).cast::<Scalar>(),
            1,
            0,
            key,
        ) != 0
        {
            ret = genkey(seed.as_ptr(), mdctx, pubenc, key);
        }
        OPENSSL_cleanse(seed.as_mut_ptr().cast(), seed.len());

        EVP_MD_CTX_free(mdctx);
        if ret == 0 {
            // Erase any partial public key output
            if !pubenc.is_null() {
                OPENSSL_cleanse(pubenc.cast(), (*vinfo).pubkey_bytes);
            }
            ossl_ml_kem_key_reset(key);
            return 0;
        }
        1
    }
}

/// `ossl_ml_kem_encap_seed(ctext, clen, shared_secret, slen, entropy, elen, key)` — `ml_kem.c:2293-2348`.
///
/// # Safety
/// The three buffers must be sized for the key's variant, as the authority's C requires.
pub(crate) unsafe fn ossl_ml_kem_encap_seed(
    ctext: *mut u8,
    clen: usize,
    shared_secret: *mut u8,
    slen: usize,
    entropy: *const u8,
    elen: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null() || !ossl_ml_kem_have_pubkey(key) {
            return 0;
        }
        let vinfo = (*key).vinfo;

        let mdctx = EVP_MD_CTX_new();
        if ctext.is_null()
            || clen != (*vinfo).ctext_bytes
            || shared_secret.is_null()
            || slen != ML_KEM_SHARED_SECRET_BYTES
            || entropy.is_null()
            || elen != ML_KEM_RANDOM_BYTES
            || mdctx.is_null()
        {
            return 0;
        }

        let mut ret = 0;
        match (*vinfo).evp_type {
            super::EVP_PKEY_ML_KEM_512 => {
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_512_RANK];
                ret = encap(ctext, shared_secret, entropy, tmp.as_mut_ptr(), mdctx, key);
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
            }
            super::EVP_PKEY_ML_KEM_768 => {
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_768_RANK];
                ret = encap(ctext, shared_secret, entropy, tmp.as_mut_ptr(), mdctx, key);
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
            }
            super::EVP_PKEY_ML_KEM_1024 => {
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_1024_RANK];
                ret = encap(ctext, shared_secret, entropy, tmp.as_mut_ptr(), mdctx, key);
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
            }
            _ => {}
        }

        // Erase any partial ciphertext output on failure
        if ret == 0 {
            OPENSSL_cleanse(ctext.cast(), clen);
        }

        EVP_MD_CTX_free(mdctx);
        ret
    }
}

/// `ossl_ml_kem_encap_rand(ctext, clen, shared_secret, slen, key)` — `ml_kem.c:2350-2370`.
///
/// # Safety
/// The buffers must be sized for the key's variant.
pub(crate) unsafe fn ossl_ml_kem_encap_rand(
    ctext: *mut u8,
    clen: usize,
    shared_secret: *mut u8,
    slen: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if key.is_null() {
            return 0;
        }
        let mut r = [0u8; ML_KEM_RANDOM_BYTES];
        if RAND_bytes_ex(
            (*key).libctx,
            r.as_mut_ptr(),
            ML_KEM_RANDOM_BYTES,
            (*(*key).vinfo).secbits as u32,
        ) < 1
        {
            return 0;
        }

        let ret =
            ossl_ml_kem_encap_seed(ctext, clen, shared_secret, slen, r.as_ptr(), r.len(), key);

        OPENSSL_cleanse(r.as_mut_ptr().cast(), r.len());
        ret
    }
}

/// `ossl_ml_kem_decap(shared_secret, slen, ctext, clen, key)` — `ml_kem.c:2372-2435`.
///
/// # Safety
/// The buffers must be sized for the key's variant.
pub(crate) unsafe fn ossl_ml_kem_decap(
    shared_secret: *mut u8,
    slen: usize,
    ctext: *const u8,
    clen: usize,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut ret = 0;

        // Need a private key here
        if !ossl_ml_kem_have_prvkey(key)
            || shared_secret.is_null()
            || slen < ML_KEM_SHARED_SECRET_BYTES
        {
            return 0;
        }
        let vinfo = (*key).vinfo;

        let mdctx = EVP_MD_CTX_new();
        if slen != ML_KEM_SHARED_SECRET_BYTES
            || ctext.is_null()
            || clen != (*vinfo).ctext_bytes
            || mdctx.is_null()
        {
            RAND_bytes_ex(
                (*key).libctx,
                shared_secret,
                ML_KEM_SHARED_SECRET_BYTES,
                (*vinfo).secbits as u32,
            );
            return 0;
        }

        match (*vinfo).evp_type {
            super::EVP_PKEY_ML_KEM_512 => {
                let mut cbuf = [0u8; ctext_bytes(
                    super::ML_KEM_512_RANK,
                    super::ML_KEM_512_DU,
                    super::ML_KEM_512_DV,
                )];
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_512_RANK];
                ret = decap(
                    shared_secret,
                    ctext,
                    cbuf.as_mut_ptr(),
                    tmp.as_mut_ptr(),
                    mdctx,
                    key,
                );
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
                OPENSSL_cleanse(cbuf.as_mut_ptr().cast(), cbuf.len());
            }
            super::EVP_PKEY_ML_KEM_768 => {
                let mut cbuf = [0u8; ctext_bytes(
                    super::ML_KEM_768_RANK,
                    super::ML_KEM_768_DU,
                    super::ML_KEM_768_DV,
                )];
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_768_RANK];
                ret = decap(
                    shared_secret,
                    ctext,
                    cbuf.as_mut_ptr(),
                    tmp.as_mut_ptr(),
                    mdctx,
                    key,
                );
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
                OPENSSL_cleanse(cbuf.as_mut_ptr().cast(), cbuf.len());
            }
            super::EVP_PKEY_ML_KEM_1024 => {
                let mut cbuf = [0u8; ctext_bytes(
                    super::ML_KEM_1024_RANK,
                    super::ML_KEM_1024_DU,
                    super::ML_KEM_1024_DV,
                )];
                let mut tmp = [Scalar::ZERO; 2 * super::ML_KEM_1024_RANK];
                ret = decap(
                    shared_secret,
                    ctext,
                    cbuf.as_mut_ptr(),
                    tmp.as_mut_ptr(),
                    mdctx,
                    key,
                );
                OPENSSL_cleanse(tmp.as_mut_ptr().cast(), core::mem::size_of_val(&tmp));
                OPENSSL_cleanse(cbuf.as_mut_ptr().cast(), cbuf.len());
            }
            _ => {}
        }

        EVP_MD_CTX_free(mdctx);
        ret
    }
}

/// `ossl_ml_kem_pubkey_cmp(key1, key2)` — `ml_kem.c:2437-2452`.
pub(crate) unsafe fn ossl_ml_kem_pubkey_cmp(key1: *const MlKemKey, key2: *const MlKemKey) -> c_int {
    // SAFETY: both are live per the contract.
    unsafe {
        if ossl_ml_kem_have_pubkey(key1) && ossl_ml_kem_have_pubkey(key2) {
            return if CRYPTO_memcmp(
                (*key1).pkhash.cast(),
                (*key2).pkhash.cast(),
                ML_KEM_PKHASH_BYTES,
            ) == 0
            {
                1
            } else {
                0
            };
        }
        // No match if just one of the public keys is not available.
        if !(ossl_ml_kem_have_pubkey(key1) ^ ossl_ml_kem_have_pubkey(key2)) {
            1
        } else {
            0
        }
    }
}
