//! Phase 8.2 — `crypto/sm4/sm4.c`, the SM4 block cipher.
//!
//! **Provider-only.** The authority exports no `SM4_*` symbol: `nm -D libcrypto.so.3` lists none, so
//! there is no low-level public API to keep and this unit exists for the default provider's eight
//! `SM4-*` rows. `include/crypto/sm4.h` is an internal header, and the three names it declares —
//! `ossl_sm4_set_key`, `ossl_sm4_encrypt`, `ossl_sm4_decrypt` — are internal functions.
//!
//! **This unit *is* compiled in this profile, and the assembly is the decline.** The build tree
//! holds `libcrypto-lib-sm4.o` beside `libcrypto-lib-sm4-x86_64.o`, so `sm4.c` is a translation unit
//! and its `SM4_SBOX_T0`-based arithmetic is what runs when the CPU lacks the SM4 extension — which
//! is the same shape as AES (D209) and Camellia (D222): `cipher_sm4_hw.c`'s `HWSM4_CAPABLE` and the
//! x86-64 `.inc`'s `HWSM4_CAPABLE_X86_64` select a host property at runtime, and SM4 is a pure
//! function of key and block, so the bytes are the same either way.
//!
//! **Two tables are literal and two are derived, and the derivation is checked.** `SM4_S` and
//! `SM4_SBOX_T0` are transcribed from the authority's own initialisers, by
//! `court/gen-sm4.py`, so the 512 values are read rather than retyped. `SM4_SBOX_T1`..`T3` are
//! `SM4_SBOX_T0` rotated left by 8, 16 and 24 — the authority writes all four out because C has no
//! `const fn` — and the unit test binds the derivation to literal head values read from the same
//! file rather than to the relation alone.
//!
//! SPDX-License-Identifier: Apache-2.0

// The authority's spellings, kept: `SM4_T`, `SM4_key_sub`, `ossl_sm4_set_key` and so on are how the
// prerequisite gate joins a definition to its translation unit, and a name the tooling cannot join
// is indistinguishable from a name that is absent (D259).
#![allow(non_snake_case)]

use core::ffi::{c_int, c_uchar};

/// `SM4_BLOCK_SIZE` — `include/crypto/sm4.h:30`.
pub(crate) const SM4_BLOCK_SIZE: usize = 16;

/// `SM4_KEY_SCHEDULE` — `include/crypto/sm4.h:31`.
pub(crate) const SM4_KEY_SCHEDULE: usize = 32;

/// `static const uint8_t SM4_S[256]` — `sm4.c:18-46`. The 8-bit S-box, used only by
/// `SM4_T_non_lin_sub`, which is what the first and last rounds go through.
static SM4_S: [c_uchar; 256] = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
];

/// `static const uint32_t SM4_SBOX_T0[256]` — `sm4.c:52-87`. The authority's comment above it reads
/// `SM4_SBOX_T[j] == L(SM4_SBOX[j])`, and the precise statement is
/// `SM4_SBOX_T0[j] == L(SM4_S[j] << 24)` — the S-box's byte in the **top** position, so that
/// `SM4_T` can index `T0` with `X >> 24`.
static SM4_SBOX_T0: [u32; 256] = [
    0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787, 0xC93DF4F4, 0x6BB5DEDE,
    0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B, 0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414,
    0x872BACAC, 0xFB669D9D, 0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
    0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A, 0x1E061818, 0xFD9B6666,
    0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3, 0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9,
    0xFF33CCCC, 0x04555151, 0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
    0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020, 0x48EBA3A3, 0xC1975656,
    0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB, 0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A,
    0x5B461D1D, 0x1B071C1C, 0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
    0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616, 0x734E3D3D, 0x08AAA2A2,
    0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA, 0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E,
    0x18FBE3E3, 0x47E8AFAF, 0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
    0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161, 0x95D24747, 0x2AA08A8A,
    0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC, 0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E,
    0x84D75353, 0x00000000, 0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
    0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313, 0xE8CB2323, 0xE69C7A7A,
    0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B, 0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6,
    0x2FA18E8E, 0x2BF4DFDF, 0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
    0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0, 0x721A6868, 0x01545555,
    0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0, 0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F,
    0x691D7474, 0x2EF5DBDB, 0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
    0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D, 0x764F3939, 0xD36EBDBD,
    0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515, 0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC,
    0x0F030C0C, 0x03FCFFFF, 0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
    0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777, 0x4CBEF2F2, 0x837EFDFD,
    0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505, 0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363,
    0x220A2828, 0xC5C20707, 0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
    0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797, 0x64B6D2D2, 0x70B2C2C2,
    0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929, 0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9,
    0xF1649595, 0x5DBBE6E6, 0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
    0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373, 0x794C3535, 0xA0208080,
    0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8, 0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121,
];

/// A compile-time rotation, so the three derived tables are computed rather than written out.
const fn rotl(a: u32, n: u32) -> u32 {
    a.rotate_left(n)
}

/// `SM4_SBOX_T1[j] == L(SM4_S[j] << 16) == rotl(SM4_SBOX_T0[j], 24)` — the authority states the
/// table literally (`sm4.c:89-133`); both spellings of the relation are asserted in the unit test.
///
/// **The rotation runs the other way from the obvious reading, and the test is what found it.** The
/// four tables hold `L(S[j])` with the S-box's byte in the top, second, third and bottom position
/// respectively, and `SM4_T` indexes them in that order — so `SM4_SBOX_T0` holds the byte at the
/// top and `SM4_SBOX_T3` holds it at the bottom, which makes `T1` a rotation of `T0` **right**, not
/// left. The first version of this file derived `rotl(T0, 8)`, `16` and `24`, and the derivation
/// test — which compares against the authority's own literal head values — failed.
static SM4_SBOX_T1: [u32; 256] = derive_t(24);
/// `SM4_SBOX_T2[j] == L(SM4_S[j] << 8) == rotl(SM4_SBOX_T0[j], 16)` — `sm4.c:135-179`.
static SM4_SBOX_T2: [u32; 256] = derive_t(16);
/// `SM4_SBOX_T3[j] == L(SM4_S[j]) == rotl(SM4_SBOX_T0[j], 8)` — `sm4.c:181-225`.
static SM4_SBOX_T3: [u32; 256] = derive_t(8);

/// The three `SM4_SBOX_T1`..`T3` tables, built from `SM4_SBOX_T0` at compile time. `n` is the
/// rotation as `SM4_T`'s indexing requires it, which is `8 * (3 - k)` for `SM4_SBOX_Tk`.
const fn derive_t(n: u32) -> [u32; 256] {
    let mut out = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        out[i] = rotl(SM4_SBOX_T0[i], n);
        i += 1;
    }
    out
}

/// `static ossl_inline uint32_t load_u32_be(const uint8_t *b, uint32_t n)` — `sm4.c:232-235`.
///
/// **Big-endian**, unlike ChaCha20's little-endian word collection: SM4 is a Chinese national
/// standard and its byte order is the other one. This is the single most likely silent error in the
/// unit, which is why the known-answer vector in the tests is the standard's own.
///
/// # Safety
/// `b` is readable for `4 * n + 4` bytes.
#[inline]
unsafe fn load_u32_be(b: *const c_uchar, n: u32) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        ((*b.add(4 * n as usize) as u32) << 24)
            | ((*b.add(4 * n as usize + 1) as u32) << 16)
            | ((*b.add(4 * n as usize + 2) as u32) << 8)
            | (*b.add(4 * n as usize + 3) as u32)
    }
}

/// `static ossl_inline void store_u32_be(uint32_t v, uint8_t *b)` — `sm4.c:237-243`.
///
/// # Safety
/// `b` is writable for four bytes.
#[inline]
unsafe fn store_u32_be(v: u32, b: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        *b = (v >> 24) as c_uchar;
        *b.add(1) = (v >> 16) as c_uchar;
        *b.add(2) = (v >> 8) as c_uchar;
        *b.add(3) = v as c_uchar;
    }
}

/// `static ossl_inline uint32_t SM4_T_non_lin_sub(uint32_t X)` — `sm4.c:245-255`. The byte-wise
/// S-box application, which is what the slow rounds use and what a table-free reference would use
/// everywhere.
fn SM4_T_non_lin_sub(x: u32) -> u32 {
    ((SM4_S[(x >> 24) as u8 as usize] as u32) << 24)
        | ((SM4_S[(x >> 16) as u8 as usize] as u32) << 16)
        | ((SM4_S[(x >> 8) as u8 as usize] as u32) << 8)
        | (SM4_S[x as u8 as usize] as u32)
}

/// `static ossl_inline uint32_t SM4_T_slow(uint32_t X)` — `sm4.c:257-266`.
///
/// *"Uses byte-wise sbox in the first and last rounds to provide some protection from cache based
/// side channels"* — so the four outer rounds are deliberately table-free and the middle six
/// double-rounds are table-driven. That split is the authority's and is reproduced; a transcription
/// that used `SM4_T` everywhere would produce identical output and lose the property the comment
/// names.
fn SM4_T_slow(x: u32) -> u32 {
    let t = SM4_T_non_lin_sub(x);
    t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24)
}

/// `static ossl_inline uint32_t SM4_T(uint32_t X)` — `sm4.c:268-271`: the same `L` transform with
/// the S-box folded into four rotated tables.
fn SM4_T(x: u32) -> u32 {
    SM4_SBOX_T0[(x >> 24) as u8 as usize]
        ^ SM4_SBOX_T1[(x >> 16) as u8 as usize]
        ^ SM4_SBOX_T2[(x >> 8) as u8 as usize]
        ^ SM4_SBOX_T3[x as u8 as usize]
}

/// `static ossl_inline uint32_t SM4_key_sub(uint32_t X)` — `sm4.c:273-277`: the key schedule's own
/// linear transform, whose rotations are 13 and 23 rather than the round function's four.
fn SM4_key_sub(x: u32) -> u32 {
    let t = SM4_T_non_lin_sub(x);
    t ^ rotl(t, 13) ^ rotl(t, 23)
}

/// `typedef struct SM4_KEY_st { uint32_t rk[SM4_KEY_SCHEDULE]; } SM4_KEY` —
/// `include/crypto/sm4.h:32-34`.
#[repr(C)]
pub(crate) struct Sm4Key {
    /// `uint32_t rk[SM4_KEY_SCHEDULE]`.
    pub rk: [u32; SM4_KEY_SCHEDULE],
}

/// `int ossl_sm4_set_key(const uint8_t *key, SM4_KEY *ks)` — `sm4.c:279-326`.
///
/// **One schedule for both directions.** There is no decrypt variant: SM4's round function is
/// applied to the round keys in the opposite order, so `ossl_sm4_decrypt` walks `rk` backwards over
/// the key this produced. The `FK` family constant is xored in first and the `CK` constant at each
/// of the thirty-two rounds.
///
/// The loop advances four rounds at a time and each round's update reads the *already updated*
/// previous three words, so the four `^=` statements are order-dependent and are transcribed in the
/// authority's order.
///
/// Always answers 1: there is no key it refuses.
///
/// # Safety
/// `key` is readable for sixteen bytes; `ks` is writable.
pub(crate) unsafe fn ossl_sm4_set_key(key: *const c_uchar, ks: *mut Sm4Key) -> c_int {
    /// Family Key — `sm4.c:283-286`.
    static FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

    /// Constant Key — `sm4.c:289-297`.
    static CK: [u32; 32] = [
        0x0007_0E15,
        0x1C23_2A31,
        0x383F_464D,
        0x545B_6269,
        0x7077_7E85,
        0x8C93_9AA1,
        0xA8AF_B6BD,
        0xC4CB_D2D9,
        0xE0E7_EEF5,
        0xFC03_0A11,
        0x181F_262D,
        0x343B_4249,
        0x5057_5E65,
        0x6C73_7A81,
        0x888F_969D,
        0xA4AB_B2B9,
        0xC0C7_CED5,
        0xDCE3_EAF1,
        0xF8FF_060D,
        0x141B_2229,
        0x3037_3E45,
        0x4C53_5A61,
        0x686F_767D,
        0x848B_9299,
        0xA0A7_AEB5,
        0xBCC3_CAD1,
        0xD8DF_E6ED,
        0xF4FB_0209,
        0x1017_1E25,
        0x2C33_3A41,
        0x484F_565D,
        0x646B_7279,
    ];

    let mut k = [0u32; 4];
    // SAFETY: the caller's contract; `key` is readable for sixteen bytes.
    unsafe {
        k[0] = load_u32_be(key, 0) ^ FK[0];
        k[1] = load_u32_be(key, 1) ^ FK[1];
        k[2] = load_u32_be(key, 2) ^ FK[2];
        k[3] = load_u32_be(key, 3) ^ FK[3];

        let mut i = 0;
        while i < SM4_KEY_SCHEDULE {
            k[0] ^= SM4_key_sub(k[1] ^ k[2] ^ k[3] ^ CK[i]);
            k[1] ^= SM4_key_sub(k[2] ^ k[3] ^ k[0] ^ CK[i + 1]);
            k[2] ^= SM4_key_sub(k[3] ^ k[0] ^ k[1] ^ CK[i + 2]);
            k[3] ^= SM4_key_sub(k[0] ^ k[1] ^ k[2] ^ CK[i + 3]);
            (*ks).rk[i] = k[0];
            (*ks).rk[i + 1] = k[1];
            (*ks).rk[i + 2] = k[2];
            (*ks).rk[i + 3] = k[3];
            i += 4;
        }
    }

    1
}

/// `SM4_RNDS(k0, k1, k2, k3, F)` — `sm4.c:328-335`, the four-round macro both directions are built
/// from. `F` is passed as a value because the two outer double-rounds use `SM4_T_slow` and the six
/// inner ones `SM4_T`.
#[inline]
fn sm4_rnds(b: &mut [u32; 4], rk: &[u32; SM4_KEY_SCHEDULE], k: [usize; 4], f: fn(u32) -> u32) {
    b[0] ^= f(b[1] ^ b[2] ^ b[3] ^ rk[k[0]]);
    b[1] ^= f(b[0] ^ b[2] ^ b[3] ^ rk[k[1]]);
    b[2] ^= f(b[0] ^ b[1] ^ b[3] ^ rk[k[2]]);
    b[3] ^= f(b[0] ^ b[1] ^ b[2] ^ rk[k[3]]);
}

/// `SM4_RNDS` for the six middle `SM4_T` double-rounds, whose key indexes the two directions give
/// in **opposite orders**: encryption walks `(4,5,6,7)`, `(8,9,10,11)`, … `(24,25,26,27)` and
/// decryption walks `(27,26,25,24)`, … `(7,6,5,4)`. The authority writes all fourteen groups out
/// literally; they are written out here too, because the first version of this file derived them
/// from a formula and got the descending direction ascending — which the standard vector caught.
const ENC_T_GROUPS: [[usize; 4]; 6] = [
    [4, 5, 6, 7],
    [8, 9, 10, 11],
    [12, 13, 14, 15],
    [16, 17, 18, 19],
    [20, 21, 22, 23],
    [24, 25, 26, 27],
];

/// The decryption direction's six groups — `sm4.c:366-373`.
const DEC_T_GROUPS: [[usize; 4]; 6] = [
    [27, 26, 25, 24],
    [23, 22, 21, 20],
    [19, 18, 17, 16],
    [15, 14, 13, 12],
    [11, 10, 9, 8],
    [7, 6, 5, 4],
];

/// `void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)` — `sm4.c:337-359`.
///
/// **The output is byte-reversed relative to the state.** The last round's words are stored
/// `B3, B2, B1, B0` — the same swap `SM4_RNDS` leaving them in the reverse order produces, and the
/// reason the final round must not be un-swapped. Both directions end with it.
///
/// # Safety
/// `in` is readable for sixteen bytes; `out` is writable for sixteen; `ks` is live.
pub(crate) unsafe fn ossl_sm4_encrypt(in_: *const c_uchar, out: *mut c_uchar, ks: *const Sm4Key) {
    // SAFETY: the caller's contract.
    unsafe {
        let rk = &(*ks).rk;
        let mut b = [
            load_u32_be(in_, 0),
            load_u32_be(in_, 1),
            load_u32_be(in_, 2),
            load_u32_be(in_, 3),
        ];

        sm4_rnds(&mut b, rk, [0, 1, 2, 3], SM4_T_slow);
        for g in ENC_T_GROUPS {
            sm4_rnds(&mut b, rk, g, SM4_T);
        }
        sm4_rnds(&mut b, rk, [28, 29, 30, 31], SM4_T_slow);

        store_u32_be(b[3], out);
        store_u32_be(b[2], out.add(4));
        store_u32_be(b[1], out.add(8));
        store_u32_be(b[0], out.add(12));
    }
}

/// `void ossl_sm4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)` — `sm4.c:361-378`.
///
/// The same eight double-rounds with the round keys **reversed four at a time**, and the same final
/// swap. The schedule is the encryption one — there is no separate decrypt schedule.
///
/// # Safety
/// As `ossl_sm4_encrypt`.
pub(crate) unsafe fn ossl_sm4_decrypt(in_: *const c_uchar, out: *mut c_uchar, ks: *const Sm4Key) {
    // SAFETY: the caller's contract.
    unsafe {
        let rk = &(*ks).rk;
        let mut b = [
            load_u32_be(in_, 0),
            load_u32_be(in_, 1),
            load_u32_be(in_, 2),
            load_u32_be(in_, 3),
        ];

        sm4_rnds(&mut b, rk, [31, 30, 29, 28], SM4_T_slow);
        for g in DEC_T_GROUPS {
            sm4_rnds(&mut b, rk, g, SM4_T);
        }
        sm4_rnds(&mut b, rk, [3, 2, 1, 0], SM4_T_slow);

        store_u32_be(b[3], out);
        store_u32_be(b[2], out.add(4));
        store_u32_be(b[1], out.add(8));
        store_u32_be(b[0], out.add(12));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// **The derivation is checked, not assumed.** The three rotated tables are computed here and
    /// the authority writes them literally, so the first three head values of each are read out of
    /// `sm4.c` and compared.
    #[test]
    fn the_rotated_tables_are_the_authoritys_literal_ones() {
        assert_eq!(
            [SM4_SBOX_T1[0], SM4_SBOX_T1[1], SM4_SBOX_T1[2]],
            [0x5B8ED55B, 0x42D09242, 0xA74DEAA7]
        );
        assert_eq!(
            [SM4_SBOX_T2[0], SM4_SBOX_T2[1], SM4_SBOX_T2[2]],
            [0x5B5B8ED5, 0x4242D092, 0xA7A74DEA]
        );
        assert_eq!(
            [SM4_SBOX_T3[0], SM4_SBOX_T3[1], SM4_SBOX_T3[2]],
            [0xD55B5B8E, 0x924242D0, 0xEAA7A74D]
        );
        // And the S-box's own head, which is the first thing a wrong table would change.
        assert_eq!(SM4_S[0], 0xD6);
        assert_eq!(SM4_S[255], 0x48);
        assert_eq!(SM4_SBOX_T0[0], 0x8ED55B5B);
    }

    /// The GB/T 32907-2016 / RFC 8998 sample: key and plaintext
    /// `0123456789abcdeffedcba9876543210`, ciphertext
    /// `681edf34d206965e86b3e94f536e4246`. This is a **published standard vector**, not the
    /// authority's own output, which is the point: it is the only evidence that both byte orders and
    /// the round-key order are right, and a transcription that got `load_u32_be` backwards would
    /// still be self-consistent.
    #[test]
    fn the_standard_vector_round_trips() {
        let key = [
            0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut ks = Sm4Key { rk: [0; 32] };
        let mut ct = [0u8; 16];
        let mut back = [0u8; 16];

        // SAFETY: every buffer is a live local of the required length.
        unsafe {
            assert_eq!(ossl_sm4_set_key(key.as_ptr(), &mut ks), 1);
            ossl_sm4_encrypt(key.as_ptr(), ct.as_mut_ptr(), &ks);
        }
        assert_eq!(
            ct,
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46
            ]
        );

        // SAFETY: as above.
        unsafe {
            ossl_sm4_decrypt(ct.as_ptr(), back.as_mut_ptr(), &ks);
        }
        assert_eq!(back, key);
    }

    /// **The two `T` paths agree, which is what makes the slow rounds a choice rather than a
    /// difference.** `SM4_T_slow` is the byte-wise S-box plus `L`; `SM4_T` is the four folded
    /// tables. The authority uses the slow one for the first and last double-rounds "to provide some
    /// protection from cache based side channels", so a transcription that used `SM4_T` everywhere
    /// would be byte-identical and would have lost the property. Asserting the two agree is what
    /// lets that be a deliberate difference rather than a hopeful one.
    #[test]
    fn the_table_free_and_table_driven_transforms_agree() {
        let mut x: u32 = 0x9abc_def0;
        for _ in 0..64 {
            assert_eq!(SM4_T(x), SM4_T_slow(x));
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        }
    }

    /// Every round key is a function of the key alone, so two schedules from the same key are equal
    /// and one from a different key is not. A schedule built with a little-endian load would pass
    /// the first and fail the second only sometimes, which is why the standard vector above is the
    /// real check and this is the cheap one.
    #[test]
    fn the_key_schedule_is_deterministic_and_key_dependent() {
        let mut a = Sm4Key { rk: [0; 32] };
        let mut b = Sm4Key { rk: [0; 32] };
        let mut c = Sm4Key { rk: [0; 32] };
        let key = [0x11u8; 16];
        let mut other = [0x11u8; 16];
        other[15] = 0x12;

        // SAFETY: every buffer is a live local.
        unsafe {
            ossl_sm4_set_key(key.as_ptr(), &mut a);
            ossl_sm4_set_key(key.as_ptr(), &mut b);
            ossl_sm4_set_key(other.as_ptr(), &mut c);
        }
        assert_eq!(a.rk, b.rk);
        assert_ne!(a.rk, c.rk);
        // The first round key is not the first key word: `FK[0]` is xored in first.
        assert_ne!(a.rk[0], 0x1111_1111);
    }
}
