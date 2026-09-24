//! Phase 8 — `crypto/slh_dsa/slh_adrs.c` and `slh_adrs.h`: the ADRS address blob and its two
//! method tables.
//!
//! An `ADRS` is FIPS 205's 32-byte or 22-byte address object (Section 4.2 for the uncompressed
//! form a SHAKE set uses, Section 11.2 for the compressed form a SHA-2 set uses). `slh_adrs.c` is
//! 184 lines and defines the four pairs of accessors plus `zero`/`copy` for each form
//! (`:68-151`) and the lookup `ossl_slh_get_adrs_fn` (`:153-184`), which answers one of two
//! eleven-entry tables indexed by `is_compressed`.
//!
//! **`set_tree_height` and `set_tree_index` are the same function as `set_chain_address` and
//! `set_hash_address`.** `slh_adrs.c:38-42` aliases them with `#define` because the fields sit at
//! the same offset in every address type (`SLH_ADRS_OFF_TREE_INDEX` is
//! `SLH_ADRS_OFF_HASH_ADDR`, `:20`), so the two table slots are filled with the chain/hash
//! writer rather than with two more copies. The transcription keeps the aliasing.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::c_int;

/// `SLH_ADRS_SIZE` — `slh_adrs.h:23`, the uncompressed blob's size.
pub(crate) const SLH_ADRS_SIZE: usize = 32;
/// `SLH_ADRSC_SIZE` — `slh_adrs.h:24`, the compressed blob's size.
pub(crate) const SLH_ADRSC_SIZE: usize = 22;
/// `SLH_ADRS_SIZE_MAX` — `slh_adrs.h:25`.
pub(crate) const SLH_ADRS_SIZE_MAX: usize = SLH_ADRS_SIZE;

/// `OPENSSL_store_u32_be` — `include/openssl/byteorder.h`, the big-endian store.
///
/// # Safety
/// `p` is writable for four bytes.
unsafe fn store_u32_be(p: *mut u8, v: u32) {
    // SAFETY: `p` is writable for four bytes per the contract.
    unsafe {
        *p = (v >> 24) as u8;
        *p.add(1) = (v >> 16) as u8;
        *p.add(2) = (v >> 8) as u8;
        *p.add(3) = v as u8;
    }
}

/// `OPENSSL_store_u64_be` — `include/openssl/byteorder.h`, the big-endian store.
///
/// # Safety
/// `p` is writable for eight bytes.
unsafe fn store_u64_be(p: *mut u8, v: u64) {
    // SAFETY: `p` is writable for eight bytes per the contract.
    unsafe {
        for i in 0..8 {
            *p.add(i) = (v >> (56 - 8 * i)) as u8;
        }
    }
}

/// `#define SLH_ADRS_DECLARE(a) uint8_t a[SLH_ADRS_SIZE_MAX]` — `slh_adrs.h:36`.
pub(crate) type SlhAdrs = [u8; SLH_ADRS_SIZE_MAX];

// See FIPS 205 - Section 4.3 Table 1 Uncompressed Addresses.
const SLH_ADRS_OFF_LAYER_ADR: usize = 0;
const SLH_ADRS_OFF_TREE_ADR: usize = 4;
const SLH_ADRS_OFF_TYPE: usize = 16;
const SLH_ADRS_OFF_KEYPAIR_ADDR: usize = 20;
const SLH_ADRS_OFF_CHAIN_ADDR: usize = 24;
const SLH_ADRS_OFF_HASH_ADDR: usize = 28;
const SLH_ADRS_SIZE_TYPE: usize = 4;
const SLH_ADRS_SIZE_TYPECLEAR: usize = SLH_ADRS_SIZE - (SLH_ADRS_OFF_TYPE + SLH_ADRS_SIZE_TYPE);
const SLH_ADRS_SIZE_KEYPAIR_ADDR: usize = 4;

// See FIPS 205 - Section 11.2 Table 3 Compressed Addresses.
const SLH_ADRSC_OFF_LAYER_ADR: usize = 0;
const SLH_ADRSC_OFF_TREE_ADR: usize = 1;
const SLH_ADRSC_OFF_TYPE: usize = 9;
const SLH_ADRSC_OFF_KEYPAIR_ADDR: usize = 10;
const SLH_ADRSC_OFF_CHAIN_ADDR: usize = 14;
const SLH_ADRSC_OFF_HASH_ADDR: usize = 18;
const SLH_ADRSC_SIZE_TYPE: usize = 1;
const SLH_ADRSC_SIZE_TYPECLEAR: usize = SLH_ADRS_SIZE - (SLH_ADRSC_OFF_TYPE + SLH_ADRSC_SIZE_TYPE);
const SLH_ADRSC_SIZE_KEYPAIR_ADDR: usize = SLH_ADRS_SIZE_KEYPAIR_ADDR;

// The seven address types — `slh_adrs.h:28-34`.
/// `SLH_ADRS_TYPE_WOTS_HASH`.
pub(crate) const SLH_ADRS_TYPE_WOTS_HASH: u32 = 0;
/// `SLH_ADRS_TYPE_WOTS_PK`.
pub(crate) const SLH_ADRS_TYPE_WOTS_PK: u32 = 1;
/// `SLH_ADRS_TYPE_TREE`.
pub(crate) const SLH_ADRS_TYPE_TREE: u32 = 2;
/// `SLH_ADRS_TYPE_FORS_TREE`.
pub(crate) const SLH_ADRS_TYPE_FORS_TREE: u32 = 3;
/// `SLH_ADRS_TYPE_FORS_ROOTS`.
pub(crate) const SLH_ADRS_TYPE_FORS_ROOTS: u32 = 4;
/// `SLH_ADRS_TYPE_WOTS_PRF`.
pub(crate) const SLH_ADRS_TYPE_WOTS_PRF: u32 = 5;
/// `SLH_ADRS_TYPE_FORS_PRF`.
pub(crate) const SLH_ADRS_TYPE_FORS_PRF: u32 = 6;

/// `SLH_ADRS_FUNC` — `slh_adrs.h:57-69`, eleven function pointers in declaration order.
#[repr(C)]
pub(crate) struct SlhAdrsFunc {
    pub(crate) set_layer_address: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) set_tree_address: unsafe extern "C" fn(*mut u8, u64),
    pub(crate) set_type_and_clear: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) set_keypair_address: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) copy_keypair_address: unsafe extern "C" fn(*mut u8, *const u8),
    pub(crate) set_chain_address: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) set_tree_height: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) set_hash_address: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) set_tree_index: unsafe extern "C" fn(*mut u8, u32),
    pub(crate) zero: unsafe extern "C" fn(*mut u8),
    pub(crate) copy: unsafe extern "C" fn(*mut u8, *const u8),
}

// --- the uncompressed (32-byte) accessors — `slh_adrs.c:68-111` ---

/// `static void slh_adrs_set_layer_address(uint8_t *adrs, uint32_t layer)` — `slh_adrs.c:68-71`.
unsafe extern "C" fn slh_adrs_set_layer_address(adrs: *mut u8, layer_addr: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrs.add(SLH_ADRS_OFF_LAYER_ADR), layer_addr) };
}

/// `static void slh_adrs_set_tree_address(uint8_t *adrs, uint64_t address)` — `slh_adrs.c:72-81`.
///
/// Twelve bytes are reserved for this, but the largest value any parameter set uses is 64 bits;
/// the write is at offset 4 within the 12 and assumes the leading four bytes are already zero.
unsafe extern "C" fn slh_adrs_set_tree_address(adrs: *mut u8, address: u64) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u64_be(adrs.add(SLH_ADRS_OFF_TREE_ADR + 4), address) };
}

/// `static void slh_adrs_set_type_and_clear(uint8_t *adrs, uint32_t type)` — `slh_adrs.c:82-86`.
unsafe extern "C" fn slh_adrs_set_type_and_clear(adrs: *mut u8, type_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe {
        store_u32_be(adrs.add(SLH_ADRS_OFF_TYPE), type_);
        core::ptr::write_bytes(
            adrs.add(SLH_ADRS_OFF_TYPE + SLH_ADRS_SIZE_TYPE),
            0,
            SLH_ADRS_SIZE_TYPECLEAR,
        );
    }
}

/// `static void slh_adrs_set_keypair_address(uint8_t *adrs, uint32_t in)` — `slh_adrs.c:87-90`.
unsafe extern "C" fn slh_adrs_set_keypair_address(adrs: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrs.add(SLH_ADRS_OFF_KEYPAIR_ADDR), in_) };
}

/// `static void slh_adrs_copy_keypair_address(uint8_t *dst, const uint8_t *src)` —
/// `slh_adrs.c:91-95`.
unsafe extern "C" fn slh_adrs_copy_keypair_address(dst: *mut u8, src: *const u8) {
    // SAFETY: `dst` is writable and `src` readable for the four bytes copied.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.add(SLH_ADRS_OFF_KEYPAIR_ADDR),
            dst.add(SLH_ADRS_OFF_KEYPAIR_ADDR),
            SLH_ADRS_SIZE_KEYPAIR_ADDR,
        )
    };
}

/// `static void slh_adrs_set_chain_address(uint8_t *adrs, uint32_t in)` — `slh_adrs.c:96-99`.
unsafe extern "C" fn slh_adrs_set_chain_address(adrs: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrs.add(SLH_ADRS_OFF_CHAIN_ADDR), in_) };
}

/// `static void slh_adrs_set_hash_address(uint8_t *adrs, uint32_t in)` — `slh_adrs.c:100-103`.
unsafe extern "C" fn slh_adrs_set_hash_address(adrs: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrs.add(SLH_ADRS_OFF_HASH_ADDR), in_) };
}

/// `static void slh_adrs_zero(uint8_t *adrs)` — `slh_adrs.c:104-107`.
unsafe extern "C" fn slh_adrs_zero(adrs: *mut u8) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { core::ptr::write_bytes(adrs, 0, SLH_ADRS_SIZE) };
}

/// `static void slh_adrs_copy(uint8_t *dst, const uint8_t *src)` — `slh_adrs.c:108-111`.
unsafe extern "C" fn slh_adrs_copy(dst: *mut u8, src: *const u8) {
    // SAFETY: `dst` is writable and `src` readable for the bytes copied.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, SLH_ADRS_SIZE) };
}

// --- the compressed (22-byte) accessors — `slh_adrs.c:113-151` ---

/// `static void slh_adrsc_set_layer_address(uint8_t *adrsc, uint32_t layer)` —
/// `slh_adrs.c:114-117`.
unsafe extern "C" fn slh_adrsc_set_layer_address(adrsc: *mut u8, layer_addr: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { *adrsc.add(SLH_ADRSC_OFF_LAYER_ADR) = layer_addr as u8 };
}

/// `static void slh_adrsc_set_tree_address(uint8_t *adrsc, uint64_t in)` —
/// `slh_adrs.c:118-121`.
unsafe extern "C" fn slh_adrsc_set_tree_address(adrsc: *mut u8, in_: u64) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u64_be(adrsc.add(SLH_ADRSC_OFF_TREE_ADR), in_) };
}

/// `static void slh_adrsc_set_type_and_clear(uint8_t *adrsc, uint32_t type)` —
/// `slh_adrs.c:122-126`.
unsafe extern "C" fn slh_adrsc_set_type_and_clear(adrsc: *mut u8, type_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe {
        *adrsc.add(SLH_ADRSC_OFF_TYPE) = type_ as u8;
        core::ptr::write_bytes(
            adrsc.add(SLH_ADRSC_OFF_TYPE + SLH_ADRSC_SIZE_TYPE),
            0,
            SLH_ADRSC_SIZE_TYPECLEAR,
        );
    }
}

/// `static void slh_adrsc_set_keypair_address(uint8_t *adrsc, uint32_t in)` —
/// `slh_adrs.c:127-130`.
unsafe extern "C" fn slh_adrsc_set_keypair_address(adrsc: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrsc.add(SLH_ADRSC_OFF_KEYPAIR_ADDR), in_) };
}

/// `static void slh_adrsc_copy_keypair_address(uint8_t *dst, const uint8_t *src)` —
/// `slh_adrs.c:131-135`.
unsafe extern "C" fn slh_adrsc_copy_keypair_address(dst: *mut u8, src: *const u8) {
    // SAFETY: `dst` is writable and `src` readable for the four bytes copied.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.add(SLH_ADRSC_OFF_KEYPAIR_ADDR),
            dst.add(SLH_ADRSC_OFF_KEYPAIR_ADDR),
            SLH_ADRSC_SIZE_KEYPAIR_ADDR,
        )
    };
}

/// `static void slh_adrsc_set_chain_address(uint8_t *adrsc, uint32_t in)` —
/// `slh_adrs.c:136-139`.
unsafe extern "C" fn slh_adrsc_set_chain_address(adrsc: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrsc.add(SLH_ADRSC_OFF_CHAIN_ADDR), in_) };
}

/// `static void slh_adrsc_set_hash_address(uint8_t *adrsc, uint32_t in)` —
/// `slh_adrs.c:140-143`.
unsafe extern "C" fn slh_adrsc_set_hash_address(adrsc: *mut u8, in_: u32) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { store_u32_be(adrsc.add(SLH_ADRSC_OFF_HASH_ADDR), in_) };
}

/// `static void slh_adrsc_zero(uint8_t *adrsc)` — `slh_adrs.c:144-147`.
unsafe extern "C" fn slh_adrsc_zero(adrsc: *mut u8) {
    // SAFETY: the ADRS is writable for its own size.
    unsafe { core::ptr::write_bytes(adrsc, 0, SLH_ADRSC_SIZE) };
}

/// `static void slh_adrsc_copy(uint8_t *dst, const uint8_t *src)` — `slh_adrs.c:148-151`.
unsafe extern "C" fn slh_adrsc_copy(dst: *mut u8, src: *const u8) {
    // SAFETY: `dst` is writable and `src` readable for the bytes copied.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, SLH_ADRSC_SIZE) };
}

/// `const SLH_ADRS_FUNC *ossl_slh_get_adrs_fn(int is_compressed)` — `slh_adrs.c:153-184`.
///
/// `is_compressed == 0` answers the uncompressed (SHAKE) table, anything else the compressed
/// (SHA-2) one — which is the authority's `methods[is_compressed == 0 ? 0 : 1]`.
pub(crate) unsafe fn ossl_slh_get_adrs_fn(is_compressed: c_int) -> *const SlhAdrsFunc {
    const METHODS: [SlhAdrsFunc; 2] = [
        SlhAdrsFunc {
            set_layer_address: slh_adrs_set_layer_address,
            set_tree_address: slh_adrs_set_tree_address,
            set_type_and_clear: slh_adrs_set_type_and_clear,
            set_keypair_address: slh_adrs_set_keypair_address,
            copy_keypair_address: slh_adrs_copy_keypair_address,
            set_chain_address: slh_adrs_set_chain_address,
            set_tree_height: slh_adrs_set_chain_address,
            set_hash_address: slh_adrs_set_hash_address,
            set_tree_index: slh_adrs_set_hash_address,
            zero: slh_adrs_zero,
            copy: slh_adrs_copy,
        },
        SlhAdrsFunc {
            set_layer_address: slh_adrsc_set_layer_address,
            set_tree_address: slh_adrsc_set_tree_address,
            set_type_and_clear: slh_adrsc_set_type_and_clear,
            set_keypair_address: slh_adrsc_set_keypair_address,
            copy_keypair_address: slh_adrsc_copy_keypair_address,
            set_chain_address: slh_adrsc_set_chain_address,
            set_tree_height: slh_adrsc_set_chain_address,
            set_hash_address: slh_adrsc_set_hash_address,
            set_tree_index: slh_adrsc_set_hash_address,
            zero: slh_adrsc_zero,
            copy: slh_adrsc_copy,
        },
    ];
    if is_compressed == 0 {
        &METHODS[0]
    } else {
        &METHODS[1]
    }
}
