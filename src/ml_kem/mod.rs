//! Phase 8 — `crypto/ml_kem/ml_kem.c`: the ML-KEM (FIPS 203) core the six keymgmt/KEM rows are built on.
//!
//! This module is the crate's transcription of the single translation unit
//! `crypto/ml_kem/ml_kem.c` (2,452 lines) and the header `include/crypto/ml_kem.h`, transcribed
//! whole per D327's rule. The one structure the header declares, [`MlKemKey`], is modelled
//! field-for-field, and the three key-material allocation shapes the C spells with three
//! macros are three Rust structs apiece, `#[repr(C)]`, because `add_storage` recovers the
//! `|m|` matrix from the tail of the `|t|` allocation by pointer arithmetic and the `|z|`
//! failure secret from the tail of the `|s|` allocation.
//!
//! ## The 410 table lines are generated, not transcribed
//!
//! `kNTTRoots`, `kInverseNTTRoots` and `kModRoots` are 128 entries each — 410 source lines.
//! They live in [`tables`], re-derived by `forensics/tools/gen_ml_kem_tables.py` from the
//! definition comments the file carries and checked entry for entry against the authority's
//! literals. Nothing here types them.
//!
//! ## `CONSTTIME_SECRET`/`CONSTTIME_DECLASSIFY` are the empty macros on this profile
//!
//! `crypto/ml_kem/ml_kem.c:150` selects the valgrind arm only under
//! `OPENSSL_CONSTANT_TIME_VALIDATION`, which this profile does not define, so the two macros
//! expand to nothing (`:169-170`). The fourteen call sites are recorded in
//! [`arith::CONSTTIME_SITES`] with their coordinates rather than written; the branch that
//! guards them is absent, not stubbed.
//!
//! ## No provider row is published by this module yet
//!
//! Exactly as `crypto/slh_dsa/` was before its two provider units landed (D398): the six rows
//! live in `providers/implementations/keymgmt/ml_kem_kmgmt.c.in` and
//! `providers/implementations/kem/ml_kem_kem.c.in`, which are a separate unit. The allow below
//! is a statement about *when* this module is reached, not a claim that any function is unused.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

pub(crate) mod arith;
pub(crate) mod key;
pub(crate) mod tables;

#[cfg(test)]
mod tests;

use core::ffi::{c_char, c_int, c_void};
use core::mem::offset_of;

use crate::evp::digest::EvpMd;
use crate::runtime::obj::{NID_ML_KEM_1024, NID_ML_KEM_512, NID_ML_KEM_768};

/// `ML_KEM_DEGREE` — `crypto/ml_kem.h:19`, the fixed degree of the quotient polynomial.
pub(crate) const ML_KEM_DEGREE: usize = 256;
/// `ML_KEM_PRIME` — `crypto/ml_kem.h:26`, `(ML_KEM_DEGREE * 13 + 1)`.
pub(crate) const ML_KEM_PRIME: u32 = tables::ML_KEM_PRIME;
/// `ML_KEM_RANDOM_BYTES` — `crypto/ml_kem.h:47`, `rho`, `sigma`, `d`, `z`, `m`, `r`.
pub(crate) const ML_KEM_RANDOM_BYTES: usize = 32;
/// `ML_KEM_SEED_BYTES` — `crypto/ml_kem.h:48`, the `(d, z)` keygen seed pair.
pub(crate) const ML_KEM_SEED_BYTES: usize = ML_KEM_RANDOM_BYTES * 2;
/// `ML_KEM_PKHASH_BYTES` — `crypto/ml_kem.h:50`.
pub(crate) const ML_KEM_PKHASH_BYTES: usize = 32;
/// `ML_KEM_SHARED_SECRET_BYTES` — `crypto/ml_kem.h:51`.
pub(crate) const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

/// `INVERSE_DEGREE` — `ml_kem.c:42`, `(ML_KEM_PRIME - 2 * 13)`, the `(n/2)^-1 mod q` of the iNTT.
pub(crate) const INVERSE_DEGREE: u16 = (ML_KEM_PRIME - 2 * 13) as u16;
/// `LOG2PRIME` — `ml_kem.c:43`.
pub(crate) const LOG2PRIME: u32 = 12;
/// `BARRETT_SHIFT` — `ml_kem.c:44`, `(2 * LOG2PRIME)`.
pub(crate) const BARRETT_SHIFT: u32 = 2 * LOG2PRIME;
/// `kBarrettMultiplier` — `ml_kem.c:239`, `(1 << BARRETT_SHIFT) / ML_KEM_PRIME`.
pub(crate) const KBARRETT_MULTIPLIER: u64 = (1u64 << BARRETT_SHIFT) / ML_KEM_PRIME as u64;
/// `kHalfPrime` — `ml_kem.c:240`, `(ML_KEM_PRIME - 1) / 2`.
pub(crate) const KHALFPRIME: u16 = ((ML_KEM_PRIME - 1) / 2) as u16;
/// `SCALAR_SAMPLING_BUFSIZE` — `ml_kem.c:83-85`. `SHA3_BLOCKSIZE(128)` is 168, divisible by 12.
pub(crate) const SCALAR_SAMPLING_BUFSIZE: usize = 168;

/// `ML_KEM_512_RANK` — `crypto/ml_kem.h:95`.
pub(crate) const ML_KEM_512_RANK: usize = 2;
/// `ML_KEM_512_DU` — `crypto/ml_kem.h:98`.
pub(crate) const ML_KEM_512_DU: usize = 10;
/// `ML_KEM_512_DV` — `crypto/ml_kem.h:99`.
pub(crate) const ML_KEM_512_DV: usize = 4;
/// `ML_KEM_512_BITS` — `crypto/ml_kem.h:94`.
pub(crate) const ML_KEM_512_BITS: c_int = 512;
/// `ML_KEM_512_SECBITS` — `crypto/ml_kem.h:100`.
pub(crate) const ML_KEM_512_SECBITS: c_int = 128;
/// `ML_KEM_512_SECURITY_CATEGORY` — `crypto/ml_kem.h:101`.
pub(crate) const ML_KEM_512_SECURITY_CATEGORY: c_int = 1;

/// `ML_KEM_768_RANK` — `crypto/ml_kem.h:105`.
pub(crate) const ML_KEM_768_RANK: usize = 3;
/// `ML_KEM_768_DU` — `crypto/ml_kem.h:108`.
pub(crate) const ML_KEM_768_DU: usize = 10;
/// `ML_KEM_768_DV` — `crypto/ml_kem.h:109`.
pub(crate) const ML_KEM_768_DV: usize = 4;
/// `ML_KEM_768_BITS` — `crypto/ml_kem.h:104`.
pub(crate) const ML_KEM_768_BITS: c_int = 768;
/// `ML_KEM_768_SECBITS` — `crypto/ml_kem.h:110`.
pub(crate) const ML_KEM_768_SECBITS: c_int = 192;
/// `ML_KEM_768_SECURITY_CATEGORY` — `crypto/ml_kem.h:111`.
pub(crate) const ML_KEM_768_SECURITY_CATEGORY: c_int = 3;

/// `ML_KEM_1024_RANK` — `crypto/ml_kem.h:115`.
pub(crate) const ML_KEM_1024_RANK: usize = 4;
/// `ML_KEM_1024_DU` — `crypto/ml_kem.h:118`.
pub(crate) const ML_KEM_1024_DU: usize = 11;
/// `ML_KEM_1024_DV` — `crypto/ml_kem.h:119`.
pub(crate) const ML_KEM_1024_DV: usize = 5;
/// `ML_KEM_1024_BITS` — `crypto/ml_kem.h:114`.
pub(crate) const ML_KEM_1024_BITS: c_int = 1024;
/// `ML_KEM_1024_SECBITS` — `crypto/ml_kem.h:120`.
pub(crate) const ML_KEM_1024_SECBITS: c_int = 256;
/// `ML_KEM_1024_SECURITY_CATEGORY` — `crypto/ml_kem.h:121`.
pub(crate) const ML_KEM_1024_SECURITY_CATEGORY: c_int = 5;

/// `EVP_PKEY_ML_KEM_512` — `crypto/ml_kem.h:93`, `NID_ML_KEM_512`.
pub(crate) const EVP_PKEY_ML_KEM_512: c_int = NID_ML_KEM_512;
/// `EVP_PKEY_ML_KEM_768` — `crypto/ml_kem.h:103`, `NID_ML_KEM_768`.
pub(crate) const EVP_PKEY_ML_KEM_768: c_int = NID_ML_KEM_768;
/// `EVP_PKEY_ML_KEM_1024` — `crypto/ml_kem.h:113`, `NID_ML_KEM_1024`.
pub(crate) const EVP_PKEY_ML_KEM_1024: c_int = NID_ML_KEM_1024;

/// `ML_KEM_KEY_RANDOM_PCT` — `crypto/ml_kem.h:123`.
pub(crate) const ML_KEM_KEY_RANDOM_PCT: c_int = 1 << 0;
/// `ML_KEM_KEY_FIXED_PCT` — `crypto/ml_kem.h:124`.
pub(crate) const ML_KEM_KEY_FIXED_PCT: c_int = 1 << 1;
/// `ML_KEM_KEY_PREFER_SEED` — `crypto/ml_kem.h:125`.
pub(crate) const ML_KEM_KEY_PREFER_SEED: c_int = 1 << 2;
/// `ML_KEM_KEY_RETAIN_SEED` — `crypto/ml_kem.h:126`.
pub(crate) const ML_KEM_KEY_RETAIN_SEED: c_int = 1 << 3;
/// `ML_KEM_KEY_PCT_TYPE` — `crypto/ml_kem.h:128`.
pub(crate) const ML_KEM_KEY_PCT_TYPE: c_int = ML_KEM_KEY_RANDOM_PCT | ML_KEM_KEY_FIXED_PCT;
/// `ML_KEM_KEY_PROV_FLAGS_DEFAULT` — `crypto/ml_kem.h:131`.
pub(crate) const ML_KEM_KEY_PROV_FLAGS_DEFAULT: c_int =
    ML_KEM_KEY_RANDOM_PCT | ML_KEM_KEY_PREFER_SEED | ML_KEM_KEY_RETAIN_SEED;

/// The unit's own `__FILE__`, for the allocator's debug arguments.
pub(crate) const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ml_kem/ml_kem.c".as_ptr();

/// `struct ossl_ml_kem_scalar_st` — `ml_kem.c:91-94`.
///
/// On every function entry and exit, `0 <= c[i] < ML_KEM_PRIME`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Scalar {
    /// `uint16_t c[ML_KEM_DEGREE]`.
    pub(crate) c: [u16; ML_KEM_DEGREE],
}

impl Scalar {
    /// An all-zero scalar, the `scalar tmp[...]` the two `case_*` macros stack-allocate.
    pub(crate) const ZERO: Scalar = Scalar {
        c: [0u16; ML_KEM_DEGREE],
    };
}

/// `struct pubkey_512_alloc` — `ml_kem.c:97-103` (`DECLARE_ML_KEM_PUBKEYDATA`), rank 2.
#[repr(C)]
pub(crate) struct Pubkey512Alloc {
    /// `scalar tbuf[2]` — the public vector `|t|`.
    pub(crate) tbuf: [Scalar; 2],
    /// `scalar mbuf[4]` — the pre-computed matrix `|m|` (FIPS 203 `|A|` transpose).
    pub(crate) mbuf: [Scalar; 4],
}

/// `struct prvkey_512_alloc` — `ml_kem.c:105-109` (`DECLARE_ML_KEM_PRVKEYDATA`), rank 2.
#[repr(C)]
pub(crate) struct Prvkey512Alloc {
    /// `scalar sbuf[2]`.
    pub(crate) sbuf: [Scalar; 2],
    /// `uint8_t zbuf[2 * ML_KEM_RANDOM_BYTES]` — `|z|` then `|d|`.
    pub(crate) zbuf: [u8; 2 * ML_KEM_RANDOM_BYTES],
}

/// `struct pubkey_768_alloc` — rank 3.
#[repr(C)]
pub(crate) struct Pubkey768Alloc {
    /// `scalar tbuf[3]`.
    pub(crate) tbuf: [Scalar; 3],
    /// `scalar mbuf[9]`.
    pub(crate) mbuf: [Scalar; 9],
}

/// `struct prvkey_768_alloc` — rank 3.
#[repr(C)]
pub(crate) struct Prvkey768Alloc {
    /// `scalar sbuf[3]`.
    pub(crate) sbuf: [Scalar; 3],
    /// `uint8_t zbuf[64]`.
    pub(crate) zbuf: [u8; 2 * ML_KEM_RANDOM_BYTES],
}

/// `struct pubkey_1024_alloc` — rank 4.
#[repr(C)]
pub(crate) struct Pubkey1024Alloc {
    /// `scalar tbuf[4]`.
    pub(crate) tbuf: [Scalar; 4],
    /// `scalar mbuf[16]`.
    pub(crate) mbuf: [Scalar; 16],
}

/// `struct prvkey_1024_alloc` — rank 4.
#[repr(C)]
pub(crate) struct Prvkey1024Alloc {
    /// `scalar sbuf[4]`.
    pub(crate) sbuf: [Scalar; 4],
    /// `uint8_t zbuf[64]`.
    pub(crate) zbuf: [u8; 2 * ML_KEM_RANDOM_BYTES],
}

// The layout `add_storage` depends on: the private vector `|s|` is immediately followed by the
// `|z|`/`|d|` block, and the public vector `|t|` by the `|m|` matrix, so `pub + rank` and
// `priv + rank * sizeof(scalar)` are the second arrays' first elements. The C relocates exactly
// that way, and a padding byte anywhere here would silently move both.
const _: () = {
    assert!(offset_of!(Prvkey512Alloc, zbuf) == ML_KEM_512_RANK * size_of::<Scalar>());
    assert!(offset_of!(Prvkey768Alloc, zbuf) == ML_KEM_768_RANK * size_of::<Scalar>());
    assert!(offset_of!(Prvkey1024Alloc, zbuf) == ML_KEM_1024_RANK * size_of::<Scalar>());
    assert!(offset_of!(Pubkey512Alloc, mbuf) == ML_KEM_512_RANK * size_of::<Scalar>());
    assert!(offset_of!(Pubkey768Alloc, mbuf) == ML_KEM_768_RANK * size_of::<Scalar>());
    assert!(offset_of!(Pubkey1024Alloc, mbuf) == ML_KEM_1024_RANK * size_of::<Scalar>());
};

/// `ML_KEM_VINFO` — `crypto/ml_kem.h:139-155`, field for field.
#[repr(C)]
pub(crate) struct MlKemVinfo {
    /// `const char *algorithm_name`.
    pub(crate) algorithm_name: *const c_char,
    /// `size_t prvkey_bytes`.
    pub(crate) prvkey_bytes: usize,
    /// `size_t prvalloc`.
    pub(crate) prvalloc: usize,
    /// `size_t pubkey_bytes`.
    pub(crate) pubkey_bytes: usize,
    /// `size_t puballoc`.
    pub(crate) puballoc: usize,
    /// `size_t ctext_bytes`.
    pub(crate) ctext_bytes: usize,
    /// `size_t vector_bytes`.
    pub(crate) vector_bytes: usize,
    /// `size_t u_vector_bytes`.
    pub(crate) u_vector_bytes: usize,
    /// `int evp_type`.
    pub(crate) evp_type: c_int,
    /// `int bits`.
    pub(crate) bits: c_int,
    /// `int rank`.
    pub(crate) rank: c_int,
    /// `int du`.
    pub(crate) du: c_int,
    /// `int dv`.
    pub(crate) dv: c_int,
    /// `int secbits`.
    pub(crate) secbits: c_int,
    /// `int security_category`.
    pub(crate) security_category: c_int,
}

/// `VECTOR_BYTES(b)` — `ml_kem.c:136`, `(3 * DEGREE / 2) * rank`.
pub(crate) const fn vector_bytes(rank: usize) -> usize {
    (3 * ML_KEM_DEGREE / 2) * rank
}

/// `PUBKEY_BYTES(b)` — `ml_kem.c:137`.
pub(crate) const fn pubkey_bytes(rank: usize) -> usize {
    vector_bytes(rank) + ML_KEM_RANDOM_BYTES
}

/// `PRVKEY_BYTES(b)` — `ml_kem.c:138`.
pub(crate) const fn prvkey_bytes(rank: usize) -> usize {
    2 * pubkey_bytes(rank) + ML_KEM_PKHASH_BYTES
}

/// `U_VECTOR_BYTES(b)` — `ml_kem.c:146`.
pub(crate) const fn u_vector_bytes(rank: usize, du: usize) -> usize {
    (ML_KEM_DEGREE / 8) * du * rank
}

/// `V_SCALAR_BYTES(b)` — `ml_kem.c:147`.
pub(crate) const fn v_scalar_bytes(dv: usize) -> usize {
    (ML_KEM_DEGREE / 8) * dv
}

/// `CTEXT_BYTES(b)` — `ml_kem.c:148`.
pub(crate) const fn ctext_bytes(rank: usize, du: usize, dv: usize) -> usize {
    u_vector_bytes(rank, du) + v_scalar_bytes(dv)
}

/// The three `ML_KEM_VINFO` rows of `vinfo_map` (`ml_kem.c:184-230`), in slot order.
///
/// `ML_KEM_512_VINFO` = 0, `ML_KEM_768_VINFO` = 1, `ML_KEM_1024_VINFO` = 2 (`:177-179`).
#[repr(transparent)]
pub(crate) struct VinfoMap(pub(crate) [MlKemVinfo; 3]);

// SAFETY: every pointer in the map is to a `'static` string literal, so the array is immutable and
// safe to share between threads, exactly like the C's `static const ML_KEM_VINFO vinfo_map[3]`.
unsafe impl Sync for VinfoMap {}

/// `static const ML_KEM_VINFO vinfo_map[3]` — `ml_kem.c:184-230`.
pub(crate) static VINFO_MAP: VinfoMap = VinfoMap([
    MlKemVinfo {
        algorithm_name: c"ML-KEM-512".as_ptr(),
        prvkey_bytes: prvkey_bytes(ML_KEM_512_RANK),
        prvalloc: size_of::<Prvkey512Alloc>(),
        pubkey_bytes: pubkey_bytes(ML_KEM_512_RANK),
        puballoc: size_of::<Pubkey512Alloc>(),
        ctext_bytes: ctext_bytes(ML_KEM_512_RANK, ML_KEM_512_DU, ML_KEM_512_DV),
        vector_bytes: vector_bytes(ML_KEM_512_RANK),
        u_vector_bytes: u_vector_bytes(ML_KEM_512_RANK, ML_KEM_512_DU),
        evp_type: EVP_PKEY_ML_KEM_512,
        bits: ML_KEM_512_BITS,
        rank: ML_KEM_512_RANK as c_int,
        du: ML_KEM_512_DU as c_int,
        dv: ML_KEM_512_DV as c_int,
        secbits: ML_KEM_512_SECBITS,
        security_category: ML_KEM_512_SECURITY_CATEGORY,
    },
    MlKemVinfo {
        algorithm_name: c"ML-KEM-768".as_ptr(),
        prvkey_bytes: prvkey_bytes(ML_KEM_768_RANK),
        prvalloc: size_of::<Prvkey768Alloc>(),
        pubkey_bytes: pubkey_bytes(ML_KEM_768_RANK),
        puballoc: size_of::<Pubkey768Alloc>(),
        ctext_bytes: ctext_bytes(ML_KEM_768_RANK, ML_KEM_768_DU, ML_KEM_768_DV),
        vector_bytes: vector_bytes(ML_KEM_768_RANK),
        u_vector_bytes: u_vector_bytes(ML_KEM_768_RANK, ML_KEM_768_DU),
        evp_type: EVP_PKEY_ML_KEM_768,
        bits: ML_KEM_768_BITS,
        rank: ML_KEM_768_RANK as c_int,
        du: ML_KEM_768_DU as c_int,
        dv: ML_KEM_768_DV as c_int,
        secbits: ML_KEM_768_SECBITS,
        security_category: ML_KEM_768_SECURITY_CATEGORY,
    },
    MlKemVinfo {
        algorithm_name: c"ML-KEM-1024".as_ptr(),
        prvkey_bytes: prvkey_bytes(ML_KEM_1024_RANK),
        prvalloc: size_of::<Prvkey1024Alloc>(),
        pubkey_bytes: pubkey_bytes(ML_KEM_1024_RANK),
        puballoc: size_of::<Pubkey1024Alloc>(),
        ctext_bytes: ctext_bytes(ML_KEM_1024_RANK, ML_KEM_1024_DU, ML_KEM_1024_DV),
        vector_bytes: vector_bytes(ML_KEM_1024_RANK),
        u_vector_bytes: u_vector_bytes(ML_KEM_1024_RANK, ML_KEM_1024_DU),
        evp_type: EVP_PKEY_ML_KEM_1024,
        bits: ML_KEM_1024_BITS,
        rank: ML_KEM_1024_RANK as c_int,
        du: ML_KEM_1024_DU as c_int,
        dv: ML_KEM_1024_DV as c_int,
        secbits: ML_KEM_1024_SECBITS,
        security_category: ML_KEM_1024_SECURITY_CATEGORY,
    },
]);

/// `struct ossl_ml_kem_key_st` — `crypto/ml_kem.h:161-203`, field for field.
#[repr(C)]
pub(crate) struct MlKemKey {
    /// `const ML_KEM_VINFO *vinfo`.
    pub(crate) vinfo: *const MlKemVinfo,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `EVP_MD *shake128_md`.
    pub(crate) shake128_md: *mut EvpMd,
    /// `EVP_MD *shake256_md`.
    pub(crate) shake256_md: *mut EvpMd,
    /// `EVP_MD *sha3_256_md`.
    pub(crate) sha3_256_md: *mut EvpMd,
    /// `EVP_MD *sha3_512_md`.
    pub(crate) sha3_512_md: *mut EvpMd,
    /// `uint8_t *rho` — the public matrix seed.
    pub(crate) rho: *mut u8,
    /// `uint8_t *pkhash` — the public key hash.
    pub(crate) pkhash: *mut u8,
    /// `struct ossl_ml_kem_scalar_st *t` — the public key vector.
    pub(crate) t: *mut Scalar,
    /// `struct ossl_ml_kem_scalar_st *m` — the pre-computed pubkey matrix.
    pub(crate) m: *mut Scalar,
    /// `struct ossl_ml_kem_scalar_st *s` — the private key secret vector.
    pub(crate) s: *mut Scalar,
    /// `uint8_t *z` — the private key FO failure secret.
    pub(crate) z: *mut u8,
    /// `uint8_t *d` — the private key seed.
    pub(crate) d: *mut u8,
    /// `int prov_flags` — prefer/retain seed and PCT flags.
    pub(crate) prov_flags: c_int,
    /// `uint8_t rho_pkhash[64]` — `|rho|` then `|pkhash|`.
    pub(crate) rho_pkhash: [u8; 64],
    /// `uint8_t *seedbuf` — `|z|` then `|d|` temporary secure storage buffer.
    pub(crate) seedbuf: *mut u8,
    /// `uint8_t *encoded_dk` — unparsed P8 private key.
    pub(crate) encoded_dk: *mut u8,
}

/// `ossl_ml_kem_key_vinfo(key)` — `crypto/ml_kem.h:206`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_key_vinfo(key: *const MlKemKey) -> *const MlKemVinfo {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).vinfo }
}

/// `ossl_ml_kem_have_pubkey(key)` — `crypto/ml_kem.h:207`, `(key)->t != NULL`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_have_pubkey(key: *const MlKemKey) -> bool {
    // SAFETY: `key` is live per the contract.
    unsafe { !(*key).t.is_null() }
}

/// `ossl_ml_kem_have_prvkey(key)` — `crypto/ml_kem.h:208`, `(key)->s != NULL`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_have_prvkey(key: *const MlKemKey) -> bool {
    // SAFETY: `key` is live per the contract.
    unsafe { !(*key).s.is_null() }
}

/// `ossl_ml_kem_have_seed(key)` — `crypto/ml_kem.h:209`, `(key)->d != NULL`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_have_seed(key: *const MlKemKey) -> bool {
    // SAFETY: `key` is live per the contract.
    unsafe { !(*key).d.is_null() }
}

/// `ossl_ml_kem_have_dkenc(key)` — `crypto/ml_kem.h:210`, `(key)->encoded_dk != NULL`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_have_dkenc(key: *const MlKemKey) -> bool {
    // SAFETY: `key` is live per the contract.
    unsafe { !(*key).encoded_dk.is_null() }
}

/// `ossl_ml_kem_decoded_key(key)` — `crypto/ml_kem.h:211-212`.
///
/// # Safety
/// `key` must be live.
pub(crate) unsafe fn ossl_ml_kem_decoded_key(key: *const MlKemKey) -> bool {
    // SAFETY: `key` is live per the contract.
    unsafe { ossl_ml_kem_have_dkenc(key) || ((*key).s.is_null() && !(*key).d.is_null()) }
}
