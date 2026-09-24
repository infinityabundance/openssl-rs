//! Phase 8 — `crypto/slh_dsa/slh_params.c` and `slh_params.h`: the twelve FIPS 205 parameter
//! sets and the name lookup.
//!
//! `slh_params.c` is 126 lines and declares one `static const SLH_DSA_PARAMS slh_dsa_params[]`
//! with its thirteen rows (twelve parameter sets and the `{ NULL }` terminator) and one lookup,
//! `ossl_slh_dsa_params_get` (`:115-126`). The numbers are FIPS 205 Section 11 Table 2, written
//! through the file's own `OSSL_SLH_PARAMS(name)` macro (`:84-94`), which expands to
//! `N, H, D, H_DASH, A, K, M, SECURITY_CATEGORY, PUB_BYTES, SIG_BYTES`.
//!
//! **The SHA-2 `H`/`T` zero-padding bound is the one field that is not a FIPS 205 table column.**
//! `OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1` is 64 (`slh_params.h:16`) and
//! `..._BOUND2` is 128 (`slh_params.c:15`); security category 1 uses the first and categories 3
//! and 5 the second (`slh_params.c:97-108`). The SHAKE rows carry a zero in that column because
//! `slh_hash.c`'s SHAKE functions never read it, which is how the authority writes them.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int};

use crate::runtime::obj::{
    NID_SLH_DSA_SHA2_128f, NID_SLH_DSA_SHA2_128s, NID_SLH_DSA_SHA2_192f, NID_SLH_DSA_SHA2_192s,
    NID_SLH_DSA_SHA2_256f, NID_SLH_DSA_SHA2_256s, NID_SLH_DSA_SHAKE_128f, NID_SLH_DSA_SHAKE_128s,
    NID_SLH_DSA_SHAKE_192f, NID_SLH_DSA_SHAKE_192s, NID_SLH_DSA_SHAKE_256f, NID_SLH_DSA_SHAKE_256s,
};

/// `OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1` — `slh_params.h:16`.
pub(crate) const OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1: usize = 64;
/// `OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2` — `slh_params.c:15`.
pub(crate) const OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2: usize = 128;

/// `SLH_DSA_PARAMS` — `slh_params.h:22-37`.
///
/// `lgw` is omitted by the authority because it is 4 for every parameter set (`slh_params.h:19`).
#[repr(C)]
pub(crate) struct SlhDsaParams {
    /// `const char *alg`.
    pub(crate) alg: *const c_char,
    /// `int type` — the `NID_SLH_DSA_*`.
    pub(crate) type_: c_int,
    /// `int is_shake` — 1 for the SHAKE sets, 0 for the SHA-2 ones.
    pub(crate) is_shake: c_int,
    /// `uint32_t n` — the security parameter, the hash output size in bytes.
    pub(crate) n: u32,
    /// `uint32_t h` — the total tree height.
    pub(crate) h: u32,
    /// `uint32_t d` — the number of tree layers.
    pub(crate) d: u32,
    /// `uint32_t hm` — the height of each Merkle tree (`h = hm * d`).
    pub(crate) hm: u32,
    /// `uint32_t a` — the FORS tree height.
    pub(crate) a: u32,
    /// `uint32_t k` — the number of FORS trees.
    pub(crate) k: u32,
    /// `uint32_t m` — the size of `H_MSG()`'s output.
    pub(crate) m: u32,
    /// `uint32_t security_category`.
    pub(crate) security_category: u32,
    /// `uint32_t pk_len` — the encoded public key length, `2 * n`.
    pub(crate) pk_len: u32,
    /// `uint32_t sig_len` — the signature length.
    pub(crate) sig_len: u32,
    /// `size_t sha2_h_and_t_bound`.
    pub(crate) sha2_h_and_t_bound: usize,
}

/// `static const SLH_DSA_PARAMS slh_dsa_params[]` — `slh_params.c:96-110`.
///
/// The newtype exists only so a `static` of raw pointers can carry a `Sync` impl; the thirteen
/// rows are `'static` and nothing writes the table.
struct SlhParamsTable([SlhDsaParams; 13]);
// SAFETY: the table holds `'static` string addresses, integers and a `NULL` terminator; it has
// no interior mutability and is never written.
unsafe impl Sync for SlhParamsTable {}

/// Thirteen rows: the twelve `OSSL_SLH_PARAMS` expansions in the authority's order (`:97-108`)
/// and the `{ NULL }` terminator (`:109`). The table is `#[rustfmt::skip]` so the wide
/// `OSSL_SLH_PARAMS` rows keep their one-row-per-line shape.
#[rustfmt::skip]
static SLH_DSA_PARAMS: SlhParamsTable = SlhParamsTable([
    SlhDsaParams { alg: c"SLH-DSA-SHA2-128s".as_ptr(), type_: NID_SLH_DSA_SHA2_128s, is_shake: 0,
        n: 16, h: 63, d: 7, hm: 9, a: 12, k: 14, m: 30, security_category: 1, pk_len: 32,
        sig_len: 7856, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-128s".as_ptr(), type_: NID_SLH_DSA_SHAKE_128s, is_shake: 1,
        n: 16, h: 63, d: 7, hm: 9, a: 12, k: 14, m: 30, security_category: 1, pk_len: 32,
        sig_len: 7856, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: c"SLH-DSA-SHA2-128f".as_ptr(), type_: NID_SLH_DSA_SHA2_128f, is_shake: 0,
        n: 16, h: 66, d: 22, hm: 3, a: 6, k: 33, m: 34, security_category: 1, pk_len: 32,
        sig_len: 17088, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND1 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-128f".as_ptr(), type_: NID_SLH_DSA_SHAKE_128f, is_shake: 1,
        n: 16, h: 66, d: 22, hm: 3, a: 6, k: 33, m: 34, security_category: 1, pk_len: 32,
        sig_len: 17088, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: c"SLH-DSA-SHA2-192s".as_ptr(), type_: NID_SLH_DSA_SHA2_192s, is_shake: 0,
        n: 24, h: 63, d: 7, hm: 9, a: 14, k: 17, m: 39, security_category: 3, pk_len: 48,
        sig_len: 16224, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-192s".as_ptr(), type_: NID_SLH_DSA_SHAKE_192s, is_shake: 1,
        n: 24, h: 63, d: 7, hm: 9, a: 14, k: 17, m: 39, security_category: 3, pk_len: 48,
        sig_len: 16224, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: c"SLH-DSA-SHA2-192f".as_ptr(), type_: NID_SLH_DSA_SHA2_192f, is_shake: 0,
        n: 24, h: 66, d: 22, hm: 3, a: 8, k: 33, m: 42, security_category: 3, pk_len: 48,
        sig_len: 35664, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-192f".as_ptr(), type_: NID_SLH_DSA_SHAKE_192f, is_shake: 1,
        n: 24, h: 66, d: 22, hm: 3, a: 8, k: 33, m: 42, security_category: 3, pk_len: 48,
        sig_len: 35664, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: c"SLH-DSA-SHA2-256s".as_ptr(), type_: NID_SLH_DSA_SHA2_256s, is_shake: 0,
        n: 32, h: 64, d: 8, hm: 8, a: 14, k: 22, m: 47, security_category: 5, pk_len: 64,
        sig_len: 29792, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-256s".as_ptr(), type_: NID_SLH_DSA_SHAKE_256s, is_shake: 1,
        n: 32, h: 64, d: 8, hm: 8, a: 14, k: 22, m: 47, security_category: 5, pk_len: 64,
        sig_len: 29792, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: c"SLH-DSA-SHA2-256f".as_ptr(), type_: NID_SLH_DSA_SHA2_256f, is_shake: 0,
        n: 32, h: 68, d: 17, hm: 4, a: 9, k: 35, m: 49, security_category: 5, pk_len: 64,
        sig_len: 49856, sha2_h_and_t_bound: OSSL_SLH_DSA_SHA2_NUM_ZEROS_H_AND_T_BOUND2 },
    SlhDsaParams { alg: c"SLH-DSA-SHAKE-256f".as_ptr(), type_: NID_SLH_DSA_SHAKE_256f, is_shake: 1,
        n: 32, h: 68, d: 17, hm: 4, a: 9, k: 35, m: 49, security_category: 5, pk_len: 64,
        sig_len: 49856, sha2_h_and_t_bound: 0 },
    SlhDsaParams { alg: core::ptr::null(), type_: 0, is_shake: 0, n: 0, h: 0, d: 0, hm: 0, a: 0,
        k: 0, m: 0, security_category: 0, pk_len: 0, sig_len: 0, sha2_h_and_t_bound: 0 },
]);

/// `strcmp(a, b) == 0` for two NUL-terminated C strings, with no libc dependency.
///
/// # Safety
/// `a` and `b` must each be NULL or point at a NUL-terminated byte string.
unsafe fn cstr_eq(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return a == b;
    }
    let mut i: isize = 0;
    loop {
        // SAFETY: both pointers are valid C strings per the contract, and `i` is inside both
        // because the loop stops at the first NUL of either.
        let ca = unsafe { *a.offset(i) };
        // SAFETY: as above.
        let cb = unsafe { *b.offset(i) };
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
    }
}

/// `const SLH_DSA_PARAMS *ossl_slh_dsa_params_get(const char *alg)` — `slh_params.c:115-126`.
///
/// # Safety
/// `alg` must be NULL or point at a NUL-terminated byte string.
pub(crate) unsafe fn ossl_slh_dsa_params_get(alg: *const c_char) -> *const SlhDsaParams {
    if alg.is_null() {
        return core::ptr::null();
    }
    for p in SLH_DSA_PARAMS.0.iter() {
        if p.alg.is_null() {
            break;
        }
        // SAFETY: `p.alg` is a `'static` C string and `alg` is the caller's.
        if unsafe { cstr_eq(p.alg, alg) } {
            return p;
        }
    }
    core::ptr::null()
}
