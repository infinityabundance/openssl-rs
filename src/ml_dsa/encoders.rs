//! `crypto/ml_dsa/ml_dsa_encoders.c` — the ML-DSA bit-packing codecs and the key and signature
//! serialisers built on them.
//!
//! This file is the whole of `ml_dsa_encoders.c:1-1025`: the twelve `static` bit-packing
//! primitives (`poly_encode_4_bits` through `poly_decode_signed_two_to_power_17`), the
//! `ossl_ml_dsa_pk_{encode,decode}` and `ossl_ml_dsa_sk_{encode,decode}` key serialisers, the
//! `hint_bits_{encode,decode}` pair, `ossl_ml_dsa_sig_{encode,decode}`,
//! `ossl_ml_dsa_poly_decode_expand_mask` — which `ml_dsa_local.h:100` declares and which
//! `ml_dsa_sample.c` calls, but which is *defined here* — and `ossl_ml_dsa_w1_encode`.
//!
//! ## The one raise
//!
//! The file holds a single `ERR_raise_data`, `ossl_ml_dsa_sk_decode`'s public-key-hash check at
//! `:820`. Its coordinate is `err_sites::ML_DSA_ENCODERS_820`, carrying the authority's own
//! library and reason (`ERR_LIB_PROV`, `PROV_R_INVALID_KEY`); the `%s` format argument is
//! `key->params->alg`, so [`raise_with_alg`] concatenates the algorithm name into the message the
//! way the authority's `printf` does.
//!
//! ## The byte-order helpers are the header's own
//!
//! `OPENSSL_load_u16_le`/`u32`/`u64` and their `store` counterparts (`<openssl/byteorder.h>`) are
//! transcribed as [`load_u16_le`]/[`load_u32_le`]/[`load_u64_le`] and
//! [`store_u16_le`]/[`store_u32_le`]/[`store_u64_le`], each returning the advanced pointer exactly
//! as the macro does. `PACKET_*` has no crate symbol (`include/internal/packet.h` is all
//! `static ossl_inline`), so the read half is [`Packet`]'s methods and the one helper the file
//! needs beyond them, `PACKET_copy_bytes`, is [`packet_copy_bytes`].
//!
//! ## All arithmetic wraps
//!
//! The crate builds with `overflow-checks = true`, where the authority promotes to `int`/`uint32_t`
//! and relies on two's-complement truncation. Every place the C leans on a shift dropping high bits
//! the Rust here does too — a left shift on a fixed-width integer discards out-of-range bits without
//! panicking — so the two agree bit for bit in a debug build.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::CStr;

use crate::evp::digest::{EVP_MD_CTX_free, EVP_MD_CTX_new};
use crate::packet::{
    Packet, WPACKET_allocate_bytes, WPACKET_finish, WPACKET_get_total_written,
    WPACKET_init_static_len, WPACKET_memcpy, Wpacket,
};
use crate::runtime::err::{err_sites, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_malloc, CRYPTO_memcmp, CRYPTO_memdup, OPENSSL_cleanse,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

use super::hash::shake_xof;
use super::key::{
    ossl_ml_dsa_key_priv_alloc, ossl_ml_dsa_key_pub_alloc, ossl_ml_dsa_key_public_from_private,
    ossl_ml_dsa_key_reset,
};
use super::poly::{Poly, Vector};
use super::{
    mod_sub, MlDsaKey, MlDsaParams, MlDsaSig, ML_DSA_ETA_4, ML_DSA_GAMMA1_TWO_POWER_19,
    ML_DSA_GAMMA2_Q_MINUS1_DIV32, ML_DSA_K_BYTES, ML_DSA_NUM_POLY_COEFFICIENTS, ML_DSA_RHO_BYTES,
    ML_DSA_SEED_BYTES, ML_DSA_TR_BYTES,
};

/// The unit's own `__FILE__`, for the allocator's debug arguments.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ml_dsa/ml_dsa_encoders.c".as_ptr();

/// `ossl_ml_dsa_pk_encode`'s `OPENSSL_malloc(enc_len)`, `ml_dsa_encoders.c:629`.
const LINE_PK_ENCODE_ENC: c_int = 629;
/// `ossl_ml_dsa_pk_encode`'s `OPENSSL_free(key->pub_encoding)`, `ml_dsa_encoders.c:644`.
const LINE_PK_ENCODE_FREE_PUB: c_int = 644;
/// `ossl_ml_dsa_pk_encode`'s err-arm `OPENSSL_free(enc)`, `ml_dsa_encoders.c:650`.
const LINE_PK_ENCODE_FREE_ENC: c_int = 650;
/// `ossl_ml_dsa_pk_decode`'s `OPENSSL_memdup(in, in_len)`, `ml_dsa_encoders.c:692`.
const LINE_PK_DECODE_MEMDUP: c_int = 692;
/// `ossl_ml_dsa_sk_encode`'s `OPENSSL_secure_malloc(enc_len)`, `ml_dsa_encoders.c:716`.
const LINE_SK_ENCODE_ENC: c_int = 716;
/// `ossl_ml_dsa_sk_encode`'s `OPENSSL_secure_clear_free(key->priv_encoding, enc_len)`,
/// `ml_dsa_encoders.c:744`.
const LINE_SK_ENCODE_CLEAR_PRV: c_int = 744;
/// `ossl_ml_dsa_sk_encode`'s err-arm `OPENSSL_secure_clear_free(enc, enc_len)`,
/// `ml_dsa_encoders.c:750`.
const LINE_SK_ENCODE_CLEAR_ENC: c_int = 750;
/// `ossl_ml_dsa_sk_decode`'s `OPENSSL_secure_clear_free(key->seed, ML_DSA_SEED_BYTES)`,
/// `ml_dsa_encoders.c:773`.
const LINE_SK_DECODE_CLEAR_SEED: c_int = 773;
/// `ossl_ml_dsa_sk_decode`'s `OPENSSL_secure_malloc(in_len)`, `ml_dsa_encoders.c:809`.
const LINE_SK_DECODE_PRV: c_int = 809;

/// An owned encoder block on this unit's allocator seam.
///
/// The public encoding is an `OPENSSL_malloc` block and the secret one an `OPENSSL_secure_malloc`
/// block, each released at its own `__LINE__`; this handle carries both the allocation and release
/// coordinates and the release kind, so a caller-installed `CRYPTO_set_mem_functions`/
/// `CRYPTO_secure_malloc` observer sees each exactly as it sees the authority's. `Drop` is the
/// block's single release; `into_raw` is how the encoding is transferred into the key, and the
/// secret variant's release is the authority's `OPENSSL_secure_clear_free` (cleansing preserved).
///
/// This is OB-1's model: each constructor fixes the extent and the release kind, `Drop` is the
/// block's single release and `into_raw` transfers it. The secure arm is verified separately: if
/// no secure heap is initialised `CRYPTO_secure_malloc` falls back to the plain seam, so `Drop`
/// calls `CRYPTO_secure_clear_free` on a non-secure block; that entry point recognises the
/// provenance, cleanses `len` bytes and releases it through `CRYPTO_free` — the fallback is
/// cleansed, not skipped.
struct OwnedBuf {
    ptr: ptr::NonNull<u8>,
    len: usize,
    file: *const c_char,
    line: c_int,
    secure: bool,
}

impl OwnedBuf {
    /// `OPENSSL_malloc(len)` at `file`/`line`, released by `Drop` at `release_line`.
    fn malloc(
        len: usize,
        file: *const c_char,
        line: c_int,
        release_line: c_int,
    ) -> Option<OwnedBuf> {
        // `CRYPTO_malloc` is a safe function: it answers NULL or a fresh, writable block of `len`
        // bytes.
        let raw = CRYPTO_malloc(len, file, line).cast::<u8>();
        ptr::NonNull::new(raw).map(|ptr| OwnedBuf {
            ptr,
            len,
            file,
            line: release_line,
            secure: false,
        })
    }

    /// `OPENSSL_secure_malloc(len)` at `file`/`line`, released by `Drop` with
    /// `OPENSSL_secure_clear_free` at `release_line`.
    ///
    /// If no secure heap is initialised the secure allocator falls back to the plain seam; the
    /// release still cleanses: `CRYPTO_secure_clear_free` recognises the non-secure provenance,
    /// cleanses these `len` bytes, then releases them through the plain seam.
    fn secure_malloc(
        len: usize,
        file: *const c_char,
        line: c_int,
        release_line: c_int,
    ) -> Option<OwnedBuf> {
        // SAFETY: `CRYPTO_secure_malloc` answers NULL or a fresh, writable block of `len` bytes.
        let raw = unsafe { CRYPTO_secure_malloc(len, file, line) }.cast::<u8>();
        ptr::NonNull::new(raw).map(|ptr| OwnedBuf {
            ptr,
            len,
            file,
            line: release_line,
            secure: true,
        })
    }

    /// The block's stable address, for the packet builder's writes.
    fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Hand the block to the key's owning member, so `Drop` no longer releases it.
    fn into_raw(self) -> *mut u8 {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBuf {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle allocated and has not handed out; `Drop` runs
        // once, so this is its single release, through the authority's own release seam and line.
        unsafe {
            if self.secure {
                CRYPTO_secure_clear_free(
                    self.ptr.as_ptr().cast::<c_void>(),
                    self.len,
                    self.file,
                    self.line,
                );
            } else {
                CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), self.file, self.line);
            }
        }
    }
}

/// `POLY_COEFF_NUM_BYTES(bits)` — `ml_dsa_encoders.c:19`, `bits * (256 / 8)`.
const fn poly_coeff_num_bytes(bits: usize) -> usize {
    bits * (ML_DSA_NUM_POLY_COEFFICIENTS / 8)
}

/// `ENCODE_FN` — `ml_dsa_encoders.c:23`, `int (const POLY *s, WPACKET *pkt)`.
type EncodeFn = unsafe fn(*const Poly, *mut Wpacket) -> c_int;
/// `DECODE_FN` — `ml_dsa_encoders.c:24`, `int (POLY *s, PACKET *pkt)`.
type DecodeFn = unsafe fn(*mut Poly, *mut Packet) -> c_int;

// ---------------------------------------------------------------------------------------------
// `<openssl/byteorder.h>`'s little-endian loads and stores
// ---------------------------------------------------------------------------------------------

/// `OPENSSL_load_u16_le(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 2`.
///
/// # Safety
/// `in_` must be readable for two bytes.
#[inline]
unsafe fn load_u16_le(in_: *const u8, accum: &mut u16) -> *const u8 {
    let mut bytes = [0u8; 2];
    // SAFETY: `in_` is readable for two bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 2) };
    *accum = u16::from_le_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(2) }
}

/// `OPENSSL_load_u32_le(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 4`.
///
/// # Safety
/// `in_` must be readable for four bytes.
#[inline]
unsafe fn load_u32_le(in_: *const u8, accum: &mut u32) -> *const u8 {
    let mut bytes = [0u8; 4];
    // SAFETY: `in_` is readable for four bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 4) };
    *accum = u32::from_le_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(4) }
}

/// `OPENSSL_load_u64_le(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 8`.
///
/// # Safety
/// `in_` must be readable for eight bytes.
#[inline]
unsafe fn load_u64_le(in_: *const u8, accum: &mut u64) -> *const u8 {
    let mut bytes = [0u8; 8];
    // SAFETY: `in_` is readable for eight bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 8) };
    *accum = u64::from_le_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(8) }
}

/// `OPENSSL_store_u16_le(out, v)` — `<openssl/byteorder.h>`, returns `out + 2`.
///
/// # Safety
/// `out` must be writable for two bytes.
#[inline]
unsafe fn store_u16_le(out: *mut u8, v: u16) -> *mut u8 {
    let bytes = v.to_le_bytes();
    // SAFETY: `out` is writable for two bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 2) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(2) }
}

/// `OPENSSL_store_u32_le(out, v)` — `<openssl/byteorder.h>`, returns `out + 4`.
///
/// # Safety
/// `out` must be writable for four bytes.
#[inline]
unsafe fn store_u32_le(out: *mut u8, v: u32) -> *mut u8 {
    let bytes = v.to_le_bytes();
    // SAFETY: `out` is writable for four bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 4) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(4) }
}

/// `OPENSSL_store_u64_le(out, v)` — `<openssl/byteorder.h>`, returns `out + 8`.
///
/// # Safety
/// `out` must be writable for eight bytes.
#[inline]
unsafe fn store_u64_le(out: *mut u8, v: u64) -> *mut u8 {
    let bytes = v.to_le_bytes();
    // SAFETY: `out` is writable for eight bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 8) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(8) }
}

// ---------------------------------------------------------------------------------------------
// The two file-local helpers the translation unit pulls in
// ---------------------------------------------------------------------------------------------

/// `PACKET_copy_bytes(pkt, dest, len)` — `include/internal/packet.h`, `PACKET_get_bytes` + `memcpy`.
///
/// `packet.h` is all `static ossl_inline`; this crate models its read half as [`Packet`]'s methods
/// and adds the one composite the file calls, because a bare `get_bytes`/`copy_nonoverlapping`
/// pair would hide the refusal that `PACKET_copy_bytes` is.
///
/// # Safety
/// `pkt` must be a live cursor and `dest` must be writable for `len` bytes, disjoint from the
/// bytes `pkt` reads.
unsafe fn packet_copy_bytes(pkt: *mut Packet, dest: *mut u8, len: usize) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    let Some(src) = (unsafe { (*pkt).get_bytes(len) }) else {
        return 0;
    };
    // SAFETY: `src` is readable and `dest` writable for `len` bytes, and they do not overlap per
    // the contract.
    unsafe { ptr::copy_nonoverlapping(src, dest, len) };
    1
}

/// Raise an error whose message is `prefix || algorithm_name || suffix`.
///
/// The authority's format string at `ml_dsa_encoders.c:820` is `"%s ..."` fed `params->alg`, so the
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
    // The three pieces are bounded static text, so this cannot overflow; checking the allocation
    // extent keeps it a defined refusal even if a future caller passes longer text (AGENTS §3).
    let Some(capacity) = prefix
        .len()
        .checked_add(bytes.len())
        .and_then(|n| n.checked_add(suffix.len()))
        .and_then(|n| n.checked_add(1))
    else {
        return;
    };
    let mut msg = Vec::with_capacity(capacity);
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(bytes);
    msg.extend_from_slice(suffix.as_bytes());
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated just above.
    unsafe { raise_site_data(site, msg.as_ptr().cast()) };
}

// ---------------------------------------------------------------------------------------------
// Bit packing
// ---------------------------------------------------------------------------------------------

/// `poly_encode_4_bits(p, pkt)` — `ml_dsa_encoders.c:53-68`. FIPS 204 Algorithm 16 with `b = 4`.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_4_bits(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let mut out: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live per the contract and `out` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, poly_coeff_num_bytes(4), &mut out) } == 0 {
        return 0;
    }
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `inp` names two coefficients of `p` and `out` names one writable byte of the
        // `poly_coeff_num_bytes(4)` just allocated.
        unsafe {
            let z0 = *inp;
            inp = inp.add(1);
            let z1 = *inp;
            inp = inp.add(1);
            *out = (z0 | (z1 << 4)) as u8;
            out = out.add(1);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_encode_6_bits(p, pkt)` — `ml_dsa_encoders.c:90-109`. FIPS 204 Algorithm 16 with `b = 43`.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_6_bits(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let mut out: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live per the contract and `out` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, poly_coeff_num_bytes(6), &mut out) } == 0 {
        return 0;
    }
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `inp` names four coefficients of `p` and `out` names three writable bytes.
        unsafe {
            let c0 = *inp;
            inp = inp.add(1);
            let c1 = *inp;
            inp = inp.add(1);
            let c2 = *inp;
            inp = inp.add(1);
            let c3 = *inp;
            inp = inp.add(1);
            *out = (c0 | (c1 << 6)) as u8;
            out = out.add(1);
            *out = ((c1 >> 2) | (c2 << 4)) as u8;
            out = out.add(1);
            *out = ((c2 >> 4) | (c3 << 2)) as u8;
            out = out.add(1);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_encode_10_bits(p, pkt)` — `ml_dsa_encoders.c:130-151`. FIPS 204 Algorithm 16, `b = 10`.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_10_bits(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let mut out: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live per the contract and `out` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, poly_coeff_num_bytes(10), &mut out) } == 0 {
        return 0;
    }
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `inp` names four coefficients of `p` and `out` names five writable bytes.
        unsafe {
            let c0 = *inp;
            inp = inp.add(1);
            let c1 = *inp;
            inp = inp.add(1);
            let c2 = *inp;
            inp = inp.add(1);
            let c3 = *inp;
            inp = inp.add(1);
            *out = c0 as u8;
            out = out.add(1);
            *out = ((c0 >> 8) | (c1 << 2)) as u8;
            out = out.add(1);
            *out = ((c1 >> 6) | (c2 << 4)) as u8;
            out = out.add(1);
            *out = ((c2 >> 4) | (c3 << 6)) as u8;
            out = out.add(1);
            *out = (c3 >> 2) as u8;
            out = out.add(1);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_10_bits(p, pkt)` — `ml_dsa_encoders.c:162-181`. FIPS 204 Algorithm 18, `b = 10`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_10_bits(p: *mut Poly, pkt: *mut Packet) -> c_int {
    let mask: u32 = 0x3ff; /* 10 bits */
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    // SAFETY: `out` is that array's first element, so `out + 256` is its one-past-the-end pointer.
    let end = unsafe { out.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(5) }) else {
            return 0;
        };
        let mut v: u32 = 0;
        // SAFETY: `in_` is readable for the five bytes just taken.
        let in_ = unsafe { load_u32_le(in_, &mut v) };
        // SAFETY: `in_` now names the fifth byte of the span.
        let w = unsafe { *in_ } as u32;

        // SAFETY: `out` names the next four coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = v & mask;
            out = out.add(1);
            *out = (v >> 10) & mask;
            out = out.add(1);
            *out = (v >> 20) & mask;
            out = out.add(1);
            *out = (v >> 30) | (w << 2);
            out = out.add(1);
        }
        if !(out < end) {
            break;
        }
    }
    1
}

/// `poly_encode_signed_4(p, pkt)` — `ml_dsa_encoders.c:199-213`. FIPS 204 Algorithm 17, `a = b = 4`.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_signed_4(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let mut out: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live per the contract and `out` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, 32 * 4, &mut out) } == 0 {
        return 0;
    }
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `inp` names two coefficients of `p` and `out` names one writable byte.
        unsafe {
            let z = mod_sub(4, *inp);
            inp = inp.add(1);
            let z1 = mod_sub(4, *inp);
            inp = inp.add(1);
            *out = (z | (z1 << 4)) as u8;
            out = out.add(1);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_signed_4(p, pkt)` — `ml_dsa_encoders.c:225-263`. FIPS 204 Algorithm 19, `a = b = 4`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_signed_4(p: *mut Poly, pkt: *mut Packet) -> c_int {
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    for _ in 0..(ML_DSA_NUM_POLY_COEFFICIENTS / 8) {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(4) }) else {
            return 0;
        };
        let mut v: u32 = 0;
        // SAFETY: `in_` is readable for the four bytes just taken.
        let _ = unsafe { load_u32_le(in_, &mut v) };

        /* None of the nibbles may be >= 9: if a nibble's MSB is set, no other bit may be. */
        let msbs = v & 0x8888_8888u32;
        let mask = (msbs >> 1) | (msbs >> 2) | (msbs >> 3);
        /*
         * A nibble is only out of range for invalid input, in which case it is okay to leak the
         * value; `black_box` is the crate's spelling of the authority's `value_barrier_32`.
         */
        if core::hint::black_box(mask & v) != 0 {
            return 0;
        }

        // SAFETY: `out` names the next eight coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = mod_sub(4, v & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 4) & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 8) & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 12) & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 16) & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 20) & 15);
            out = out.add(1);
            *out = mod_sub(4, (v >> 24) & 15);
            out = out.add(1);
            *out = mod_sub(4, v >> 28);
            out = out.add(1);
        }
    }
    1
}

/// `poly_encode_signed_2(p, pkt)` — `ml_dsa_encoders.c:287-311`. FIPS 204 Algorithm 17, `a = b = 2`.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_signed_2(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let mut out: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live per the contract and `out` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, poly_coeff_num_bytes(3), &mut out) } == 0 {
        return 0;
    }
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        let mut z: u32;
        // SAFETY: `inp` names eight coefficients of `p`; the reads advance within them.
        unsafe {
            z = mod_sub(2, *inp);
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 3;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 6;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 9;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 12;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 15;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 18;
            inp = inp.add(1);
            z |= mod_sub(2, *inp) << 21;
            inp = inp.add(1);
        }
        // SAFETY: `out` names the next three writable bytes of the `poly_coeff_num_bytes(3)`.
        unsafe {
            let next = store_u16_le(out, z as u16);
            *next = (z >> 16) as u8;
            out = next.add(1);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_signed_2(p, pkt)` — `ml_dsa_encoders.c:323-363`. FIPS 204 Algorithm 19, `a = b = 2`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_signed_2(p: *mut Poly, pkt: *mut Packet) -> c_int {
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    for _ in 0..(ML_DSA_NUM_POLY_COEFFICIENTS / 8) {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(3) }) else {
            return 0;
        };
        /*
         * The authority copies three bytes into a zeroed `uint32_t` and reads it little-endian;
         * that is exactly the little-endian word the three bytes (plus a zero high byte) name, so
         * the endianness of the host does not enter.
         */
        // SAFETY: `in_` is readable for the three bytes just taken.
        let (b0, b1, b2) = unsafe { (*in_, *in_.add(1), *in_.add(2)) };
        let v = u32::from_le_bytes([b0, b1, b2, 0]);

        /* Each 3-bit value must be <= 4: if its MSB is set, its bottom two bits must not be. */
        let msbs = v & 0o4444_4444u32;
        let mask = (msbs >> 1) | (msbs >> 2);
        /*
         * A value is only out of range for invalid input, in which case it is okay to leak it;
         * `black_box` is the crate's spelling of the authority's `value_barrier_32`.
         */
        if core::hint::black_box(mask & v) != 0 {
            return 0;
        }

        // SAFETY: `out` names the next eight coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = mod_sub(2, v & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 3) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 6) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 9) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 12) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 15) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 18) & 7);
            out = out.add(1);
            *out = mod_sub(2, (v >> 21) & 7);
            out = out.add(1);
        }
    }
    1
}

/// `poly_encode_signed_two_to_power_12(p, pkt)` — `ml_dsa_encoders.c:386-412`.
///
/// FIPS 204 Algorithm 17 with `a = 2^12 - 1`, `b = 2^12`; the `t0` half of the private key.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_signed_two_to_power_12(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let range: u32 = 1u32 << 12;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        let mut out: *mut u8 = ptr::null_mut();

        // SAFETY: `pkt` is live per the contract and `out` is a live local.
        if unsafe { WPACKET_allocate_bytes(pkt, 13, &mut out) } == 0 {
            return 0;
        }
        // SAFETY: `inp` names the next eight coefficients of `p`; `mod_sub` is a safe read.
        let (c0, c1, c2, c3, c4, c5, c6, c7) = unsafe {
            let c0 = *inp;
            inp = inp.add(1);
            let c1 = *inp;
            inp = inp.add(1);
            let c2 = *inp;
            inp = inp.add(1);
            let c3 = *inp;
            inp = inp.add(1);
            let c4 = *inp;
            inp = inp.add(1);
            let c5 = *inp;
            inp = inp.add(1);
            let c6 = *inp;
            inp = inp.add(1);
            let c7 = *inp;
            inp = inp.add(1);
            (c0, c1, c2, c3, c4, c5, c6, c7)
        };

        let mut a1: u64 = mod_sub(range, c0) as u64;
        a1 |= (mod_sub(range, c1) as u64) << 13;
        a1 |= (mod_sub(range, c2) as u64) << 26;
        a1 |= (mod_sub(range, c3) as u64) << 39;
        let mut a2: u64 = mod_sub(range, c4) as u64;
        a1 |= a2 << 52;
        a2 = (a2 >> 12) | ((mod_sub(range, c5) as u64) << 1);
        a2 |= (mod_sub(range, c6) as u64) << 14;
        a2 |= (mod_sub(range, c7) as u64) << 27;

        // SAFETY: `out` names the 13 writable bytes just allocated; each store advances within it.
        unsafe {
            let out = store_u64_le(out, a1);
            let out = store_u32_le(out, a2 as u32);
            *out = (a2 >> 32) as u8;
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_signed_two_to_power_12(p, pkt)` — `ml_dsa_encoders.c:423-453`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_signed_two_to_power_12(p: *mut Poly, pkt: *mut Packet) -> c_int {
    let range: u32 = 1u32 << 12;
    let mask_13_bits: u32 = (1u32 << 13) - 1;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    for _ in 0..(ML_DSA_NUM_POLY_COEFFICIENTS / 8) {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(13) }) else {
            return 0;
        };
        let mut a1: u64 = 0;
        let mut a2: u32 = 0;
        // SAFETY: `in_` is readable for the 13 bytes just taken.
        let in_ = unsafe { load_u64_le(in_, &mut a1) };
        // SAFETY: `in_` is readable for the next four bytes.
        let in_ = unsafe { load_u32_le(in_, &mut a2) };
        // SAFETY: `in_` now names the thirteenth byte.
        let b13 = unsafe { *in_ } as u32;

        // SAFETY: `out` names the next eight coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = mod_sub(range, (a1 & u64::from(mask_13_bits)) as u32);
            out = out.add(1);
            *out = mod_sub(range, ((a1 >> 13) & u64::from(mask_13_bits)) as u32);
            out = out.add(1);
            *out = mod_sub(range, ((a1 >> 26) & u64::from(mask_13_bits)) as u32);
            out = out.add(1);
            *out = mod_sub(range, ((a1 >> 39) & u64::from(mask_13_bits)) as u32);
            out = out.add(1);
            *out = mod_sub(range, ((a1 >> 52) as u32) | ((a2 << 12) & mask_13_bits));
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 1) & mask_13_bits);
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 14) & mask_13_bits);
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 27) | (b13 << 5));
            out = out.add(1);
        }
    }
    1
}

/// `poly_encode_signed_two_to_power_19(p, pkt)` — `ml_dsa_encoders.c:475-497`.
///
/// FIPS 204 Algorithm 17 with `b = 2^19`; the signature response for ML-DSA-65/87.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_signed_two_to_power_19(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let range: u32 = 1u32 << 19;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        let mut out: *mut u8 = ptr::null_mut();

        // SAFETY: `pkt` is live per the contract and `out` is a live local.
        if unsafe { WPACKET_allocate_bytes(pkt, 10, &mut out) } == 0 {
            return 0;
        }
        // SAFETY: `inp` names the next four coefficients of `p`.
        let (c0, c1, c2, c3) = unsafe {
            let c0 = *inp;
            inp = inp.add(1);
            let c1 = *inp;
            inp = inp.add(1);
            let c2 = *inp;
            inp = inp.add(1);
            let c3 = *inp;
            inp = inp.add(1);
            (c0, c1, c2, c3)
        };

        let mut z0 = mod_sub(range, c0);
        let mut z1 = mod_sub(range, c1);
        z0 |= z1 << 20;
        z1 = (z1 >> 12) | (mod_sub(range, c2) << 8);
        let z2 = mod_sub(range, c3);
        z1 |= z2 << 28;

        // SAFETY: `out` names the 10 writable bytes just allocated; each store advances within it.
        unsafe {
            let out = store_u32_le(out, z0);
            let out = store_u32_le(out, z1);
            store_u16_le(out, (z2 >> 4) as u16);
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_signed_two_to_power_19(p, pkt)` — `ml_dsa_encoders.c:508-534`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_signed_two_to_power_19(p: *mut Poly, pkt: *mut Packet) -> c_int {
    let range: u32 = 1u32 << 19;
    let mask_20_bits: u32 = (1u32 << 20) - 1;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    for _ in 0..(ML_DSA_NUM_POLY_COEFFICIENTS / 4) {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(10) }) else {
            return 0;
        };
        let mut a1: u32 = 0;
        let mut a2: u32 = 0;
        let mut a3: u16 = 0;
        // SAFETY: `in_` is readable for the 10 bytes just taken.
        let in_ = unsafe { load_u32_le(in_, &mut a1) };
        // SAFETY: `in_` is readable for the next four bytes.
        let in_ = unsafe { load_u32_le(in_, &mut a2) };
        // SAFETY: `in_` is readable for the final two bytes.
        let _ = unsafe { load_u16_le(in_, &mut a3) };

        // SAFETY: `out` names the next four coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = mod_sub(range, a1 & mask_20_bits);
            out = out.add(1);
            *out = mod_sub(range, (a1 >> 20) | ((a2 & 0xFF) << 12));
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 8) & mask_20_bits);
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 28) | (u32::from(a3) << 4));
            out = out.add(1);
        }
    }
    1
}

/// `poly_encode_signed_two_to_power_17(p, pkt)` — `ml_dsa_encoders.c:556-578`.
///
/// FIPS 204 Algorithm 17 with `b = 2^17`; the signature response for ML-DSA-44.
///
/// # Safety
/// `pkt` must be a live packet and `p` must name 256 coefficients.
unsafe fn poly_encode_signed_two_to_power_17(p: *const Poly, pkt: *mut Wpacket) -> c_int {
    let range: u32 = 1u32 << 17;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut inp = unsafe { (*p).coeff.as_ptr() };
    // SAFETY: `inp` is that array's first element, so `inp + 256` is its one-past-the-end pointer.
    let end = unsafe { inp.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        let mut out: *mut u8 = ptr::null_mut();

        // SAFETY: `pkt` is live per the contract and `out` is a live local.
        if unsafe { WPACKET_allocate_bytes(pkt, 9, &mut out) } == 0 {
            return 0;
        }
        // SAFETY: `inp` names the next four coefficients of `p`.
        let (c0, c1, c2, c3) = unsafe {
            let c0 = *inp;
            inp = inp.add(1);
            let c1 = *inp;
            inp = inp.add(1);
            let c2 = *inp;
            inp = inp.add(1);
            let c3 = *inp;
            inp = inp.add(1);
            (c0, c1, c2, c3)
        };

        let mut z0 = mod_sub(range, c0);
        let mut z1 = mod_sub(range, c1);
        z0 |= z1 << 18;
        z1 = (z1 >> 14) | (mod_sub(range, c2) << 4);
        let z2 = mod_sub(range, c3);
        z1 |= z2 << 22;

        // SAFETY: `out` names the nine writable bytes just allocated; each store advances within it.
        unsafe {
            let out = store_u32_le(out, z0);
            let out = store_u32_le(out, z1);
            *out = (z2 >> 10) as u8;
        }
        if !(inp < end) {
            break;
        }
    }
    1
}

/// `poly_decode_signed_two_to_power_17(p, pkt)` — `ml_dsa_encoders.c:589-612`.
///
/// # Safety
/// `pkt` must be a live cursor and `p` must name 256 coefficients.
unsafe fn poly_decode_signed_two_to_power_17(p: *mut Poly, pkt: *mut Packet) -> c_int {
    let range: u32 = 1u32 << 17;
    let mask_18_bits: u32 = (1u32 << 18) - 1;
    // SAFETY: `p` names one `Poly` per the contract, so `(*p).coeff` is a valid 256-`u32` array.
    let mut out = unsafe { (*p).coeff.as_mut_ptr() };
    // SAFETY: `out` is that array's first element, so `out + 256` is its one-past-the-end pointer.
    let end = unsafe { out.add(ML_DSA_NUM_POLY_COEFFICIENTS) };
    loop {
        // SAFETY: `pkt` is a live cursor per the contract.
        let Some(in_) = (unsafe { (*pkt).get_bytes(9) }) else {
            return 0;
        };
        let mut a1: u32 = 0;
        let mut a2: u32 = 0;
        // SAFETY: `in_` is readable for the nine bytes just taken.
        let in_ = unsafe { load_u32_le(in_, &mut a1) };
        // SAFETY: `in_` is readable for the next four bytes.
        let in_ = unsafe { load_u32_le(in_, &mut a2) };
        // SAFETY: `in_` now names the ninth byte.
        let a3 = unsafe { *in_ } as u32;

        // SAFETY: `out` names the next four coefficients of `p`, and `p` has 256 of them.
        unsafe {
            *out = mod_sub(range, a1 & mask_18_bits);
            out = out.add(1);
            *out = mod_sub(range, (a1 >> 18) | ((a2 & 0xF) << 14));
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 4) & mask_18_bits);
            out = out.add(1);
            *out = mod_sub(range, (a2 >> 22) | (a3 << 10));
            out = out.add(1);
        }
        if !(out < end) {
            break;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// Key serialisation
// ---------------------------------------------------------------------------------------------

/// `ossl_ml_dsa_pk_encode(key)` — `ml_dsa_encoders.c:622-652`. FIPS 204 Algorithm 22, `pkEncode()`.
///
/// # Safety
/// `key` must be live with an allocated `t1` and a populated `rho`, and
/// `key->pub_encoding` must be NULL or a live plain-seam allocation owned by the key (the state
/// the key constructors establish). On success the member is released and replaced with a fresh
/// owned block; on failure it is untouched.
pub(crate) unsafe fn ossl_ml_dsa_pk_encode(key: *mut MlDsaKey) -> c_int {
    let mut ret = 0;
    let mut written: usize = 0;
    // SAFETY: `key` is live per the contract.
    let t1 = unsafe { (*key).t1.poly };
    // SAFETY: `key` is live and its `t1` vector names `t1.num_poly` polynomials.
    let t1_len = unsafe { (*key).t1.num_poly };
    // SAFETY: `key` is live, so its `params` field names the key's static parameter set.
    let enc_len = unsafe { (*(*key).params).pk_len };
    // `OPENSSL_malloc(enc_len)` at `:629`, released by `Drop` at `:650` when the encoding does not
    // land (the authority's error-path `OPENSSL_free(enc)`); on success `into_raw` transfers it into
    // `key->pub_encoding`.
    let Some(enc_owned) =
        OwnedBuf::malloc(enc_len, FILE, LINE_PK_ENCODE_ENC, LINE_PK_ENCODE_FREE_ENC)
    else {
        return 0;
    };
    let enc = enc_owned.as_ptr();
    let mut enc_owned = Some(enc_owned);
    // SAFETY: `Wpacket` is a builder of integers and pointers; the value is initialised by the
    // `WPACKET_init_static_len` below before it is read, and `WPACKET_finish` on an all-zero
    // packet is the authority's NULL-`subs` early return.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };

    'err: {
        // SAFETY: `pkt` is a live local, `enc` is `enc_len` writable bytes and `key->rho` is the
        // first `ML_DSA_RHO_BYTES` the packet copies in.
        let header_ok = unsafe {
            WPACKET_init_static_len(&mut pkt, enc, enc_len, 0) != 0
                && WPACKET_memcpy(
                    &mut pkt,
                    (*key).rho.as_ptr().cast::<c_void>(),
                    ML_DSA_RHO_BYTES,
                ) != 0
        };
        if !header_ok {
            break 'err;
        }
        for i in 0..t1_len {
            // SAFETY: `t1 + i` names the i'th polynomial of the `t1_len`-polynomial vector.
            if unsafe { poly_encode_10_bits(t1.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `written` is a live local and `pkt` is live.
        if unsafe { WPACKET_get_total_written(&mut pkt, &mut written) } == 0 || written != enc_len {
            break 'err;
        }
        // SAFETY: `key->pub_encoding` is the key's own pointer; freed at most once here.
        unsafe {
            CRYPTO_free(
                (*key).pub_encoding.cast::<c_void>(),
                FILE,
                LINE_PK_ENCODE_FREE_PUB,
            )
        };
        // Transfer the owned block into the key; `take` stops its `Drop` from releasing it.
        // SAFETY: `key` is live and the block is this call's own.
        unsafe {
            (*key).pub_encoding = enc_owned.take().map_or(ptr::null_mut(), OwnedBuf::into_raw)
        };
        ret = 1;
    }
    // SAFETY: `pkt` was initialised above.
    unsafe { WPACKET_finish(&mut pkt) };
    // `enc_owned` is still `Some` only when the encoding did not land; its `Drop` is the authority's
    // error-path `OPENSSL_free(enc)` at `:650`.
    drop(enc_owned);
    ret
}

/// `ossl_ml_dsa_pk_decode(key, in, in_len)` — `ml_dsa_encoders.c:664-697`. FIPS 204 `pkDecode()`.
///
/// # Safety
/// `key` must be live and in its fresh state: `key->priv_encoding` and `key->pub_encoding` NULL
/// (a non-NULL member makes the call refuse without touching `in_`). `in_` must be readable for
/// `in_len` bytes. On success `key->pub_encoding` is a fresh plain-seam block owned by the key; on
/// failure it remains NULL and the partly decoded public members stay owned by the key.
pub(crate) unsafe fn ossl_ml_dsa_pk_decode(
    key: *mut MlDsaKey,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    let mut ret = 0;

    /* Do not allow key mutation. */
    // SAFETY: `key` is live per the contract.
    let mutating = unsafe { !(*key).priv_encoding.is_null() || !(*key).pub_encoding.is_null() };
    if mutating {
        return 0;
    }
    // SAFETY: `key` is live per the contract.
    if in_len != unsafe { (*(*key).params).pk_len } {
        return 0;
    }
    // SAFETY: `key` is live.
    if unsafe { ossl_ml_dsa_key_pub_alloc(key) } == 0 {
        return 0;
    }
    let ctx = EVP_MD_CTX_new();

    'err: {
        if ctx.is_null() {
            break 'err;
        }
        // SAFETY: `in_` is readable for `in_len` bytes.
        let Some(mut pkt) = (unsafe { Packet::buf_init(in_, in_len) }) else {
            break 'err;
        };
        // SAFETY: `pkt` is a live cursor and `key->rho` writable for `ML_DSA_RHO_BYTES`, disjoint
        // from the bytes `pkt` reads.
        if unsafe { packet_copy_bytes(&mut pkt, (*key).rho.as_mut_ptr(), ML_DSA_RHO_BYTES) } == 0 {
            break 'err;
        }
        // SAFETY: `key` is live and its `t1` vector was allocated by `ossl_ml_dsa_key_pub_alloc`.
        let t1 = unsafe { (*key).t1.poly };
        // SAFETY: `key` is live and its `t1` vector names `t1.num_poly` polynomials.
        let t1_len = unsafe { (*key).t1.num_poly };
        for i in 0..t1_len {
            // SAFETY: `t1 + i` names the i'th polynomial of the `t1_len`-polynomial vector.
            if unsafe { poly_decode_10_bits(t1.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        /* Cache the hash of the encoded public key. */
        // SAFETY: `ctx` is live, `in_` is readable for `in_len` bytes and `key->tr` writable for
        // `ML_DSA_TR_BYTES`.
        if unsafe {
            shake_xof(
                ctx,
                (*key).shake256_md,
                in_,
                in_len,
                (*key).tr.as_mut_ptr(),
                ML_DSA_TR_BYTES,
            )
        } == 0
        {
            break 'err;
        }
        // SAFETY: `in_` is readable for `in_len` bytes; `CRYPTO_memdup` copies them.
        let dup =
            unsafe { CRYPTO_memdup(in_.cast::<c_void>(), in_len, FILE, LINE_PK_DECODE_MEMDUP) }
                .cast::<u8>();
        // SAFETY: `key` is live.
        unsafe { (*key).pub_encoding = dup };
        ret = (!dup.is_null()) as c_int;
    }
    // SAFETY: `ctx` is live or NULL, and is freed at most once here.
    unsafe { EVP_MD_CTX_free(ctx) };
    ret
}

/// `ossl_ml_dsa_sk_encode(key)` — `ml_dsa_encoders.c:707-752`. FIPS 204 Algorithm 24, `skEncode()`.
///
/// # Safety
/// `key` must be live with allocated `s1`/`s2`/`t0` and a populated `rho`/`K`/`tr`, and
/// `key->priv_encoding` must be NULL or a live secure-seam block of `params->sk_len` bytes owned
/// by the key. On success that member is cleansed and released and replaced with a fresh owned
/// block; on failure it is untouched and the scratch block is cleansed before release.
pub(crate) unsafe fn ossl_ml_dsa_sk_encode(key: *mut MlDsaKey) -> c_int {
    let mut ret = 0;
    let mut written: usize = 0;
    // SAFETY: `key` is live per the contract.
    let params = unsafe { (*key).params };
    // SAFETY: `params` points at a static parameter set.
    let (k, l) = unsafe { ((*params).k, (*params).l) };
    // SAFETY: `params` points at a static parameter set.
    let enc_len = unsafe { (*params).sk_len };
    // SAFETY: `key` is live with an allocated `t0` vector per the contract.
    let mut t0 = unsafe { (*key).t0.poly };
    // `OPENSSL_secure_malloc(enc_len)` at `:716`, released by `Drop` (secure clear) at `:750` when
    // the encoding does not land; on success `into_raw` transfers it into `key->priv_encoding`.
    let Some(enc_owned) =
        OwnedBuf::secure_malloc(enc_len, FILE, LINE_SK_ENCODE_ENC, LINE_SK_ENCODE_CLEAR_ENC)
    else {
        return 0;
    };
    let enc = enc_owned.as_ptr();
    let mut enc_owned = Some(enc_owned);
    // SAFETY: `Wpacket` is initialised by the `WPACKET_init_static_len` below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };

    /* eta is the range of private key coefficients (-eta...eta). */
    // SAFETY: `params` points at a static parameter set.
    let encode_fn: EncodeFn = if unsafe { (*params).eta } == ML_DSA_ETA_4 {
        poly_encode_signed_4
    } else {
        poly_encode_signed_2
    };

    'err: {
        // SAFETY: `pkt` is live, `enc` is `enc_len` writable bytes, and the three memcpys each
        // read a distinct fixed-size array of `key`.
        let header_ok = unsafe {
            WPACKET_init_static_len(&mut pkt, enc, enc_len, 0) != 0
                && WPACKET_memcpy(
                    &mut pkt,
                    (*key).rho.as_ptr().cast::<c_void>(),
                    ML_DSA_RHO_BYTES,
                ) != 0
                && WPACKET_memcpy(&mut pkt, (*key).k.as_ptr().cast::<c_void>(), ML_DSA_K_BYTES) != 0
                && WPACKET_memcpy(
                    &mut pkt,
                    (*key).tr.as_ptr().cast::<c_void>(),
                    ML_DSA_TR_BYTES,
                ) != 0
        };
        if !header_ok {
            break 'err;
        }
        // SAFETY: `key` is live with an allocated `s1` vector per the contract.
        let s1 = unsafe { (*key).s1.poly };
        for i in 0..l {
            // SAFETY: `s1 + i` names the i'th polynomial of the `l`-polynomial secret vector.
            if unsafe { encode_fn(s1.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `key` is live with an allocated `s2` vector per the contract.
        let s2 = unsafe { (*key).s2.poly };
        for i in 0..k {
            // SAFETY: `s2 + i` names the i'th polynomial of the `k`-polynomial secret vector.
            if unsafe { encode_fn(s2.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        for _ in 0..k {
            // SAFETY: `t0` walks the `k`-polynomial `t0` vector in step with the loop.
            if unsafe { poly_encode_signed_two_to_power_12(t0, &mut pkt) } == 0 {
                break 'err;
            }
            // SAFETY: the pointer stays within the `t0` vector while `k` polynomials remain.
            t0 = unsafe { t0.add(1) };
        }
        // SAFETY: `written` is a live local and `pkt` is live.
        if unsafe { WPACKET_get_total_written(&mut pkt, &mut written) } == 0 || written != enc_len {
            break 'err;
        }
        // SAFETY: `key->priv_encoding` is the key's own secure-heap pointer; freed at most once.
        unsafe {
            CRYPTO_secure_clear_free(
                (*key).priv_encoding.cast::<c_void>(),
                enc_len,
                FILE,
                LINE_SK_ENCODE_CLEAR_PRV,
            )
        };
        // Transfer the owned block into the key; `take` stops its `Drop` from releasing it.
        // SAFETY: `key` is live and the block is this call's own.
        unsafe {
            (*key).priv_encoding = enc_owned.take().map_or(ptr::null_mut(), OwnedBuf::into_raw)
        };
        ret = 1;
    }
    // SAFETY: `pkt` was initialised above.
    unsafe { WPACKET_finish(&mut pkt) };
    // `enc_owned` is still `Some` only when the encoding did not land; its `Drop` is the authority's
    // error-path `OPENSSL_secure_clear_free(enc, enc_len)` at `:750`.
    drop(enc_owned);
    ret
}

/// `ossl_ml_dsa_sk_decode(key, in, in_len)` — `ml_dsa_encoders.c:764-830`. FIPS 204 `skDecode()`.
///
/// # Safety
/// `key` must be live. `key->seed` must be NULL or a live secure-seam block of
/// `ML_DSA_SEED_BYTES` bytes owned by the key; it is cleansed and released, then set NULL,
/// before any refusal. `key->pub_encoding` must be NULL, and `key->priv_encoding` must be NULL or
/// exactly `in_` (the explicit-key load path, where the key already owns that secure block); a
/// non-NULL `priv_encoding` other than `in_` refuses. `in_` must be readable for `in_len` bytes;
/// on a public-hash mismatch the key is reset, which releases `in_` when it is the key's own
/// `priv_encoding`, so that buffer must not be used afterwards.
pub(crate) unsafe fn ossl_ml_dsa_sk_decode(
    key: *mut MlDsaKey,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    let params = unsafe { (*key).params };
    // SAFETY: `params` points at a static parameter set.
    let (k, l) = unsafe { ((*params).k, (*params).l) };

    /* When loading from an explicit key, drop the seed. */
    // SAFETY: `key->seed` is the key's own secure-heap pointer; freed at most once here.
    unsafe {
        CRYPTO_secure_clear_free(
            (*key).seed.cast::<c_void>(),
            ML_DSA_SEED_BYTES,
            FILE,
            LINE_SK_DECODE_CLEAR_SEED,
        )
    };
    // SAFETY: `key` is live.
    unsafe { (*key).seed = ptr::null_mut() };

    /* Allow the key encoding to be already set to the provided pointer. */
    // SAFETY: `key` is live per the contract.
    let mutating = unsafe {
        (!(*key).priv_encoding.is_null() && !core::ptr::eq((*key).priv_encoding, in_))
            || !(*key).pub_encoding.is_null()
    };
    if mutating {
        return 0;
    }
    // SAFETY: `params` is live.
    if in_len != unsafe { (*params).sk_len } {
        return 0;
    }
    // SAFETY: `key` is live.
    if unsafe { ossl_ml_dsa_key_priv_alloc(key) } == 0 {
        return 0;
    }

    /* eta is the range of private key coefficients (-eta...eta). */
    // SAFETY: `params` points at a static parameter set.
    let decode_fn: DecodeFn = if unsafe { (*params).eta } == ML_DSA_ETA_4 {
        poly_decode_signed_4
    } else {
        poly_decode_signed_2
    };

    let mut input_tr = [0u8; ML_DSA_TR_BYTES];

    // SAFETY: `in_` is readable for `in_len` bytes.
    let Some(mut pkt) = (unsafe { Packet::buf_init(in_, in_len) }) else {
        return 0;
    };
    // SAFETY: `pkt` is a live cursor; each destination is a key array disjoint from `in_`.
    let header_ok = unsafe {
        packet_copy_bytes(&mut pkt, (*key).rho.as_mut_ptr(), ML_DSA_RHO_BYTES) != 0
            && packet_copy_bytes(&mut pkt, (*key).k.as_mut_ptr(), ML_DSA_K_BYTES) != 0
            && packet_copy_bytes(&mut pkt, input_tr.as_mut_ptr(), ML_DSA_TR_BYTES) != 0
    };
    if !header_ok {
        return 0;
    }

    'err: {
        // SAFETY: `key` is live with an allocated `s1` vector per the contract.
        let s1 = unsafe { (*key).s1.poly };
        for i in 0..l {
            // SAFETY: `s1 + i` names the i'th polynomial of the `l`-polynomial secret vector.
            if unsafe { decode_fn(s1.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `key` is live with an allocated `s2` vector per the contract.
        let s2 = unsafe { (*key).s2.poly };
        for i in 0..k {
            // SAFETY: `s2 + i` names the i'th polynomial of the `k`-polynomial secret vector.
            if unsafe { decode_fn(s2.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `key` is live with an allocated `t0` vector per the contract.
        let t0 = unsafe { (*key).t0.poly };
        for i in 0..k {
            // SAFETY: `t0 + i` names the i'th polynomial of the `k`-polynomial `t0` vector.
            if unsafe { poly_decode_signed_two_to_power_12(t0.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        if pkt.remaining() != 0 {
            break 'err;
        }
        // SAFETY: `key` is live per the contract.
        if unsafe { (*key).priv_encoding }.is_null() {
            // SAFETY: `CRYPTO_secure_malloc` answers NULL on failure, which is checked below.
            let enc =
                unsafe { CRYPTO_secure_malloc(in_len, FILE, LINE_SK_DECODE_PRV) }.cast::<u8>();
            // SAFETY: `key` is live.
            unsafe { (*key).priv_encoding = enc };
            if enc.is_null() {
                break 'err;
            }
            // SAFETY: `in_` is readable and `enc` writable for `in_len` bytes, and disjoint.
            unsafe { ptr::copy_nonoverlapping(in_, enc, in_len) };
        }
        /*
         * Computing the public key also computes its hash, which must be equal to the |tr| value
         * in the private key, else the key was corrupted.
         */
        // SAFETY: `key` is live.
        let pub_ok = unsafe { ossl_ml_dsa_key_public_from_private(key) };
        let tr_matches = pub_ok != 0
            // SAFETY: `input_tr` and `key->tr` are both readable for `ML_DSA_TR_BYTES`.
            && unsafe {
                CRYPTO_memcmp(
                    input_tr.as_ptr().cast::<c_void>(),
                    (*key).tr.as_ptr().cast::<c_void>(),
                    ML_DSA_TR_BYTES,
                )
            } == 0;
        if !tr_matches {
            // SAFETY: `params->alg` is a NUL-terminated C string.
            unsafe {
                raise_with_alg(
                    &err_sites::ML_DSA_ENCODERS_820,
                    "",
                    (*params).alg,
                    " private key does not match its pubkey part",
                )
            };
            // SAFETY: `key` is live per the contract.
            unsafe { ossl_ml_dsa_key_reset(key) };
            break 'err;
        }
        return 1;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Hint and signature serialisation
// ---------------------------------------------------------------------------------------------

/// `hint_bits_encode(hint, pkt, omega)` — `ml_dsa_encoders.c:840-858`.
///
/// FIPS 204 Algorithm 20, `HintBitPack()`: the `omega` set-coefficient positions followed by the
/// running index after each of the `k` polynomials.
///
/// # Safety
/// `pkt` must be a live packet and `hint` must name `k = hint.num_poly >= 1` allocated
/// polynomials. At most `omega` of their coefficients may be non-zero: that is FIPS 204's hint
/// weight bound, established for signing by `vector_make_hint` and the `vector_count_ones` check
/// in `ml_dsa_sign`. A violation is refused here rather than writing past the `omega + k`-byte
/// allocation (the authority's write would be out of bounds; AGENTS §17).
unsafe fn hint_bits_encode(hint: *const Vector, pkt: *mut Wpacket, omega: u32) -> c_int {
    // SAFETY: `hint` is live per the contract.
    let k = unsafe { (*hint).num_poly };
    // `omega + k` is the packet's byte extent; the authority's parameters are small, but the
    // extent is still checked rather than relying on that (AGENTS §3).
    let Some(total) = (omega as usize).checked_add(k) else {
        return 0;
    };
    let mut data: *mut u8 = ptr::null_mut();

    // SAFETY: `pkt` is live and `data` is a live local.
    if unsafe { WPACKET_allocate_bytes(pkt, total, &mut data) } == 0 {
        return 0;
    }
    // SAFETY: `data` names the `total` writable bytes just allocated.
    unsafe { ptr::write_bytes(data, 0, total) };

    let mut coeff_index: usize = 0;
    // SAFETY: `hint` is live per the contract.
    let mut p = unsafe { (*hint).poly };
    for i in 0..k {
        for j in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
            // SAFETY: `p` names the current polynomial and `j` indexes its 256 coefficients.
            if unsafe { (*p).coeff[j] } != 0 {
                // FIPS 204 permits at most `omega` set coefficients. Refuse the next one rather
                // than writing it: without this bound a hint with more ones would run past the
                // `omega + k`-byte allocation.
                if coeff_index >= omega as usize {
                    return 0;
                }
                // SAFETY: `coeff_index < omega <= total`, so this write names a byte of `data`.
                unsafe { *data.add(coeff_index) = j as u8 };
                coeff_index += 1;
            }
        }
        // SAFETY: `omega + i < total` for `i < k`.
        unsafe { *data.add(omega as usize + i) = coeff_index as u8 };
        // SAFETY: the pointer advances through the `k`-polynomial `hint` vector.
        p = unsafe { p.add(1) };
    }
    1
}

/// `hint_bits_decode(hint, pkt, omega)` — `ml_dsa_encoders.c:867-900`.
///
/// FIPS 204 Algorithm 21, `HintBitUnpack()`. Returns 0 if `pkt` is too small or malformed.
///
/// # Safety
/// `pkt` must be a live cursor and `hint` must name `k = hint.num_poly >= 1` allocated
/// polynomials (the parameter sets' `k`). A zero-length vector has no limit bytes to unpackage
/// and is refused.
unsafe fn hint_bits_decode(hint: *mut Vector, pkt: *mut Packet, omega: u32) -> c_int {
    let mut coeff_index: usize = 0;
    // SAFETY: `hint` is live per the contract.
    let k = unsafe { (*hint).num_poly };
    // The authority's `do { ... } while (++p < end)` runs one iteration even for `k == 0`, which
    // would read the zero-length limit span and write through a possibly-NULL `poly`; refuse it
    // instead of reproducing that out-of-bounds access (AGENTS §17).
    if k == 0 {
        return 0;
    }

    // SAFETY: `pkt` is a live cursor.
    let Some(in_) = (unsafe { (*pkt).get_bytes(omega as usize) }) else {
        return 0;
    };
    // SAFETY: `pkt` is a live cursor with the `k` limit bytes that follow.
    let Some(mut limits) = (unsafe { (*pkt).get_bytes(k) }) else {
        return 0;
    };

    /* Set all coefficients to zero. */
    // SAFETY: `hint` is live and names allocated polynomials.
    unsafe { (*hint).zero() };

    // SAFETY: `hint` is live per the contract.
    let mut p = unsafe { (*hint).poly };
    // SAFETY: `hint` names `k` polynomials, so `p + k` is its one-past-the-end pointer.
    let end = unsafe { p.add(k) };
    loop {
        // SAFETY: `limits` was given `k` readable bytes and is advanced at most `k` times.
        let limit = unsafe { *limits } as u32;
        // SAFETY: the pointer stays within the `k` limit bytes while `p < end`.
        limits = unsafe { limits.add(1) };
        let mut last: c_int = -1;

        if (limit as usize) < coeff_index || limit > omega {
            return 0;
        }

        while coeff_index < limit as usize {
            // SAFETY: `coeff_index < limit <= omega`, and `in_` has `omega` readable bytes.
            let byte = unsafe { *in_.add(coeff_index) } as c_int;
            coeff_index += 1;

            if last >= 0 && byte <= last {
                return 0;
            }
            last = byte;
            // SAFETY: `byte` is in 0..=255 and `p` names a 256-coefficient polynomial.
            unsafe { (*p).coeff[byte as usize] = 1 };
        }
        // SAFETY: the pointer advances through the `k`-polynomial `hint` vector.
        p = unsafe { p.add(1) };
        if !(p < end) {
            break;
        }
    }

    while coeff_index < omega as usize {
        // SAFETY: `coeff_index < omega`, and `in_` has `omega` readable bytes.
        if unsafe { *in_.add(coeff_index) } != 0 {
            return 0;
        }
        coeff_index += 1;
    }
    1
}

/// `ossl_ml_dsa_sig_encode(sig, params, out)` — `ml_dsa_encoders.c:910-942`.
///
/// FIPS 204 Algorithm 26, `sigEncode()`.
///
/// # Safety
/// `sig` must be live with a populated `z` and a `hint` of `params->k` polynomials carrying at
/// most `params->omega` non-zero coefficients, `params` must name a static set and `out` must be
/// writable for `params->sig_len` bytes. [`hint_bits_encode`] refuses a hint over the weight bound.
pub(crate) unsafe fn ossl_ml_dsa_sig_encode(
    sig: *const MlDsaSig,
    params: *const MlDsaParams,
    out: *mut u8,
) -> c_int {
    let mut ret = 0;

    if out.is_null() {
        return 0;
    }
    // SAFETY: `params` names a static parameter set per the contract.
    let encode_fn: EncodeFn = if unsafe { (*params).gamma1 } == ML_DSA_GAMMA1_TWO_POWER_19 as c_int
    {
        poly_encode_signed_two_to_power_19
    } else {
        poly_encode_signed_two_to_power_17
    };
    // SAFETY: `Wpacket` is initialised by the `WPACKET_init_static_len` below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };
    // SAFETY: `params` names a static parameter set per the contract.
    let sig_len = unsafe { (*params).sig_len };

    'err: {
        // SAFETY: `pkt` is live, `out` is `sig_len` writable bytes, and `sig->c_tilde` is readable
        // for `sig->c_tilde_len` bytes.
        let header_ok = unsafe {
            WPACKET_init_static_len(&mut pkt, out, sig_len, 0) != 0
                && WPACKET_memcpy(
                    &mut pkt,
                    (*sig).c_tilde.cast::<c_void>(),
                    (*sig).c_tilde_len,
                ) != 0
        };
        if !header_ok {
            break 'err;
        }
        // SAFETY: `sig` is live with a populated `z` vector per the contract.
        let z_poly = unsafe { (*sig).z.poly };
        // SAFETY: `sig` is live and its `z` vector names `z.num_poly` polynomials.
        let z_num = unsafe { (*sig).z.num_poly };
        for i in 0..z_num {
            // SAFETY: `z_poly + i` names the i'th polynomial of the response vector.
            if unsafe { encode_fn(z_poly.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `sig->hint` is live and `pkt` is live.
        if unsafe { hint_bits_encode(&(*sig).hint, &mut pkt, (*params).omega as u32) } == 0 {
            break 'err;
        }
        ret = 1;
    }
    // SAFETY: `pkt` was initialised above.
    unsafe { WPACKET_finish(&mut pkt) };
    /* Erase any partial signature output on failure. */
    if ret == 0 {
        // SAFETY: `out` is the caller's `sig_len` writable bytes.
        unsafe { OPENSSL_cleanse(out.cast::<c_void>(), sig_len) };
    }
    ret
}

/// `ossl_ml_dsa_sig_decode(sig, in, in_len, params)` — `ml_dsa_encoders.c:951-977`.
///
/// # Safety
/// `sig` must be live with an allocated `z`/`hint` and a `c_tilde` buffer of `c_tilde_len` bytes,
/// `in_` readable for `in_len` bytes and `params` must name a static set.
pub(crate) unsafe fn ossl_ml_dsa_sig_decode(
    sig: *mut MlDsaSig,
    in_: *const u8,
    in_len: usize,
    params: *const MlDsaParams,
) -> c_int {
    let mut ret = 0;
    // SAFETY: `params` names a static parameter set per the contract.
    let decode_fn: DecodeFn = if unsafe { (*params).gamma1 } == ML_DSA_GAMMA1_TWO_POWER_19 as c_int
    {
        poly_decode_signed_two_to_power_19
    } else {
        poly_decode_signed_two_to_power_17
    };

    'err: {
        // SAFETY: `in_` is readable for `in_len` bytes.
        let Some(mut pkt) = (unsafe { Packet::buf_init(in_, in_len) }) else {
            break 'err;
        };
        // SAFETY: `pkt` is a live cursor and `sig->c_tilde` is writable for `c_tilde_len` bytes,
        // disjoint from the bytes `pkt` reads.
        if unsafe { packet_copy_bytes(&mut pkt, (*sig).c_tilde, (*sig).c_tilde_len) } == 0 {
            break 'err;
        }
        // SAFETY: `sig` is live with an allocated `z` vector per the contract.
        let z_poly = unsafe { (*sig).z.poly };
        // SAFETY: `sig` is live and its `z` vector names `z.num_poly` polynomials.
        let z_num = unsafe { (*sig).z.num_poly };
        for i in 0..z_num {
            // SAFETY: `z_poly + i` names the i'th polynomial of the response vector.
            if unsafe { decode_fn(z_poly.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        // SAFETY: `sig->hint` is live, `pkt` is live, and `params->omega` is the set's own.
        if unsafe { hint_bits_decode(&mut (*sig).hint, &mut pkt, (*params).omega as u32) } == 0
            || pkt.remaining() != 0
        {
            break 'err;
        }
        ret = 1;
    }
    ret
}

/// `ossl_ml_dsa_poly_decode_expand_mask(out, in, in_len, gamma1)` — `ml_dsa_encoders.c:979-991`.
///
/// Declared in `ml_dsa_local.h:100` and called by `ml_dsa_sample.c`, but defined here.
///
/// # Safety
/// `out` must name 256 coefficients and `in_` must be readable for `in_len` bytes.
pub(crate) unsafe fn ossl_ml_dsa_poly_decode_expand_mask(
    out: *mut Poly,
    in_: *const u8,
    in_len: usize,
    gamma1: u32,
) -> c_int {
    // SAFETY: `in_` is readable for `in_len` bytes.
    let Some(mut pkt) = (unsafe { Packet::buf_init(in_, in_len) }) else {
        return 0;
    };
    if gamma1 == ML_DSA_GAMMA1_TWO_POWER_19 {
        // SAFETY: `out` names 256 coefficients and `pkt` is a live cursor.
        unsafe { poly_decode_signed_two_to_power_19(out, &mut pkt) }
    } else {
        // SAFETY: `out` names 256 coefficients and `pkt` is a live cursor.
        unsafe { poly_decode_signed_two_to_power_17(out, &mut pkt) }
    }
}

/// `ossl_ml_dsa_w1_encode(w1, gamma2, out, out_len)` — `ml_dsa_encoders.c:1004-1025`.
///
/// FIPS 204 Algorithm 28, `w1Encode()`.
///
/// # Safety
/// `w1` must name `num_poly` polynomials and `out` must be writable for `out_len` bytes.
pub(crate) unsafe fn ossl_ml_dsa_w1_encode(
    w1: *const Vector,
    gamma2: u32,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `Wpacket` is initialised by the `WPACKET_init_static_len` below before it is read.
    let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };

    // SAFETY: `pkt` is a live local and `out` is `out_len` writable bytes.
    if unsafe { WPACKET_init_static_len(&mut pkt, out, out_len, 0) } == 0 {
        return 0;
    }
    let encode_fn: EncodeFn = if gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32 {
        poly_encode_4_bits
    } else {
        poly_encode_6_bits
    };
    let mut ret = 0;
    'err: {
        // SAFETY: `w1` names `num_poly` polynomials per the contract.
        let w1_poly = unsafe { (*w1).poly };
        // SAFETY: `w1` is live and names `w1.num_poly` polynomials.
        let w1_num = unsafe { (*w1).num_poly };
        for i in 0..w1_num {
            // SAFETY: `w1_poly + i` names the i'th polynomial of `w1`.
            if unsafe { encode_fn(w1_poly.add(i), &mut pkt) } == 0 {
                break 'err;
            }
        }
        ret = 1;
    }
    // SAFETY: `pkt` was initialised above.
    unsafe { WPACKET_finish(&mut pkt) };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative control for the hint-weight bound: one polynomial, `omega = 1`, four set
    /// coefficients and a two-byte packet. Before the guard, the third and fourth writes ran past
    /// the `omega + k` allocation; the encoder must instead refuse the over-weight hint.
    #[test]
    fn hint_encode_refuses_a_hint_over_the_weight_bound() {
        let mut poly = Poly {
            coeff: [0u32; ML_DSA_NUM_POLY_COEFFICIENTS],
        };
        poly.coeff[0] = 1;
        poly.coeff[1] = 1;
        poly.coeff[2] = 1;
        poly.coeff[3] = 1;
        let hint = Vector::init(&mut poly, 1);
        let mut buf = [0u8; 2];
        // SAFETY: `buf` is a live two-byte local and `pkt` is a live local.
        let mut pkt = unsafe { core::mem::zeroed::<Wpacket>() };
        // SAFETY: `pkt` is a live local and `buf` is writable for its length.
        let encoded = unsafe {
            WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0) != 0
                && hint_bits_encode(&hint, &mut pkt, 1) != 0
        };
        assert!(
            !encoded,
            "a hint with more than omega set coefficients must be refused"
        );
        // SAFETY: `pkt` was initialised above.
        unsafe { WPACKET_finish(&mut pkt) };
    }

    /// Negative control for the zero-polynomial arm: with no limit bytes the authority's loop
    /// reads past the packet and adds a possibly-NULL polynomial pointer. The decoder refuses.
    #[test]
    fn hint_decode_refuses_an_empty_vector() {
        let mut hint = Vector::init(ptr::null_mut(), 0);
        let buf = [0u8; 1];
        // SAFETY: `buf` is a live one-byte local.
        let Some(mut pkt) = (unsafe { Packet::buf_init(buf.as_ptr(), buf.len()) }) else {
            unreachable!("a one-byte packet initialises")
        };
        // SAFETY: `pkt` is a live cursor and `hint` is a live (empty) vector.
        assert_eq!(unsafe { hint_bits_decode(&mut hint, &mut pkt, 1) }, 0);
    }
}
