//! Phase 8 — `crypto/der_writer.c`: the DER *writer* half of `internal/der.h`.
//!
//! This unit has no stratum's plan row and no crate module before this one. It is transcribed
//! because the X9.42 KDF landing surfaces it: `providers/implementations/kdfs/x942kdf.c`'s
//! `x942_encode_otherinfo` is a `WPACKET` program over `ossl_DER_w_*`, and `DH_KDF_X9_42`
//! fetches that row (`docs/DECISIONS.md` D346). The unit is `include/internal/der.h`'s, its
//! nine definitions are all internal, and its only other callers are the Phase 10 encoder
//! helpers `providers/common/der/*.c` — so landing it here serves both the row this commit
//! needs and the encoder family later.
//!
//! **Transcribed whole** (D327's rule): `int_start_context`/`int_end_context`, the four
//! `int_put_bytes_*` helpers, and the nine `ossl_DER_w_*` entry points. The tag constants
//! `DER_P_*`/`DER_F_CONSTRUCTED`/`DER_C_CONTEXT` are `include/internal/der.h`'s macros and are
//! written here as the numbers rather than symbols, which is the crate's convention for a
//! macro (`EVP_ORIG_GLOBAL` in [`crate::provider::util`] is the same).
//!
//! ## What is modelled, and what is not
//!
//! `WPACKET` is [`crate::packet`]'s, and the writer is only ever its client. `BN_BYTES` is
//! `sizeof(BN_ULONG)` — eight on this profile — and the one place the file reads a `BIGNUM`'s
//! limbs directly is `int_put_bytes_bn`'s top-byte probe, which goes through the crate's own
//! [`crate::bn::intern::bn_get_words`] rather than reinterpreting the object.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint, c_void};

use crate::bn::bignum::{BN_bn2bin, BN_is_negative, BN_is_zero, BN_num_bits, BigNum};
use crate::bn::intern::bn_get_words;
use crate::packet::{
    WPACKET_allocate_bytes, WPACKET_close, WPACKET_get_total_written, WPACKET_memcpy,
    WPACKET_put_bytes__, WPACKET_put_bytes_u8, WPACKET_set_flags, WPACKET_start_sub_packet,
    Wpacket, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH,
};

/// `DER_P_BOOLEAN` — `include/internal/der.h:30`.
const DER_P_BOOLEAN: u8 = 1;
/// `DER_P_INTEGER` — `include/internal/der.h:31`.
const DER_P_INTEGER: u8 = 2;
/// `DER_P_OCTET_STRING` — `include/internal/der.h:33`.
const DER_P_OCTET_STRING: u8 = 4;
/// `DER_P_NULL` — `include/internal/der.h:34`.
const DER_P_NULL: u8 = 5;
/// `DER_P_SEQUENCE` — `include/internal/der.h:41`.
const DER_P_SEQUENCE: u8 = 16;
/// `DER_F_CONSTRUCTED` — `include/internal/der.h:58`.
const DER_F_CONSTRUCTED: u8 = 0x20;
/// `DER_C_CONTEXT` — `include/internal/der.h:63`.
const DER_C_CONTEXT: u8 = 0x80;
/// `BN_BYTES` — `include/crypto/bn.h`'s `sizeof(BN_ULONG)`, eight on this profile.
const BN_BYTES: usize = 8;

/// `static int int_start_context(WPACKET *pkt, int tag)` — `crypto/der_writer.c:17-23`.
///
/// A negative tag means "no context wrapper" and answers 1 without touching the packet; the
/// `tag <= 30` guard is `ossl_assert`'s, live under `NDEBUG`.
///
/// # Safety
/// `pkt` live when `tag >= 0`.
unsafe fn int_start_context(pkt: *mut Wpacket, tag: c_int) -> c_int {
    if tag < 0 {
        return 1;
    }
    if tag > 30 {
        return 0;
    }
    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_start_sub_packet(pkt) }
}

/// `static int int_end_context(WPACKET *pkt, int tag)` — `crypto/der_writer.c:25-52`.
///
/// The two `WPACKET_get_total_written` calls straddle the close so a sub-packet that wrote
/// nothing does not get a context tag — the `size1 == size2` arm. Both counts are taken
/// because `WPACKET_close` is what decides the length encoding.
///
/// # Safety
/// `pkt` live when `tag >= 0`.
unsafe fn int_end_context(pkt: *mut Wpacket, tag: c_int) -> c_int {
    if tag < 0 {
        return 1;
    }
    if tag > 30 {
        return 0;
    }
    let tag = (tag as u8) | DER_F_CONSTRUCTED | DER_C_CONTEXT;

    let mut size1: usize = 0;
    let mut size2: usize = 0;
    // SAFETY: `pkt` is live per the contract; the two locals are writable.
    unsafe {
        (WPACKET_get_total_written(pkt, &mut size1) != 0
            && WPACKET_close(pkt) != 0
            && WPACKET_get_total_written(pkt, &mut size2) != 0
            && (size1 == size2 || WPACKET_put_bytes_u8(pkt, tag) != 0)) as c_int
    }
}

/// `int ossl_DER_w_precompiled(WPACKET *pkt, int tag, const unsigned char *precompiled,
/// size_t precompiled_n)` — `crypto/der_writer.c:54-58`.
///
/// # Safety
/// `pkt` live; `precompiled` readable for `precompiled_n` bytes.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_precompiled(
    pkt: *mut Wpacket,
    tag: c_int,
    precompiled: *const u8,
    precompiled_n: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (int_start_context(pkt, tag) != 0
            && WPACKET_memcpy(pkt, precompiled.cast::<c_void>(), precompiled_n) != 0
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_boolean(WPACKET *pkt, int tag, int b)` — `crypto/der_writer.c:60-68`.
///
/// # Safety
/// `pkt` live.
#[allow(dead_code)] // transcribed whole; the X9.42 path does not use it (D346)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_boolean(pkt: *mut Wpacket, tag: c_int, b: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (int_start_context(pkt, tag) != 0
            && WPACKET_start_sub_packet(pkt) != 0
            && (b == 0 || WPACKET_put_bytes_u8(pkt, 0xFF) != 0)
            && WPACKET_close(pkt) == 0
            && WPACKET_put_bytes_u8(pkt, DER_P_BOOLEAN) != 0
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_octet_string(WPACKET *pkt, int tag, const unsigned char *data,
/// size_t data_n)` — `crypto/der_writer.c:70-79`.
///
/// # Safety
/// `pkt` live; `data` readable for `data_n` bytes.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_octet_string(
    pkt: *mut Wpacket,
    tag: c_int,
    data: *const u8,
    data_n: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (int_start_context(pkt, tag) != 0
            && WPACKET_start_sub_packet(pkt) != 0
            && WPACKET_memcpy(pkt, data.cast::<c_void>(), data_n) != 0
            && WPACKET_close(pkt) != 0
            && WPACKET_put_bytes_u8(pkt, DER_P_OCTET_STRING) != 0
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_octet_string_uint32(WPACKET *pkt, int tag, uint32_t value)` —
/// `crypto/der_writer.c:81-91`.
///
/// The four bytes are always written, big-endian, with the leading zeroes a `uint32_t` has:
/// the loop fills `tmp` **backwards** from its last byte and stops when the value is
/// exhausted, so `1` becomes `00 00 00 01`. That is the octet string X9.42's
/// `keyInfo.counter` is, and the reason the writer has a dedicated spelling for it.
///
/// # Safety
/// `pkt` live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_octet_string_uint32(
    pkt: *mut Wpacket,
    tag: c_int,
    mut value: u32,
) -> c_int {
    let mut tmp = [0u8; 4];
    let mut i = tmp.len();
    while value > 0 {
        i -= 1;
        tmp[i] = (value & 0xFF) as u8;
        value >>= 8;
    }
    // SAFETY: `pkt` is live per the contract; `tmp` is four readable bytes.
    unsafe { ossl_DER_w_octet_string(pkt, tag, tmp.as_ptr(), tmp.len()) }
}

/// `static int int_der_w_integer(WPACKET *pkt, int tag, int (*put_bytes)(...), const void *v)`
/// — `crypto/der_writer.c:93-107`.
///
/// The `top_byte` probe is what decides whether a leading `00` is needed: a value whose most
/// significant byte has bit 8 set would otherwise read as negative.
///
/// # Safety
/// `pkt` live; `put_bytes` a live callback; `v` readable by that callback.
unsafe fn int_der_w_integer(
    pkt: *mut Wpacket,
    tag: c_int,
    put_bytes: unsafe fn(*mut Wpacket, *const c_void, *mut c_uint) -> c_int,
    v: *const c_void,
) -> c_int {
    let mut top_byte: c_uint = 0;

    // SAFETY: the caller's contract; `top_byte` is a live local.
    unsafe {
        (int_start_context(pkt, tag) != 0
            && WPACKET_start_sub_packet(pkt) != 0
            && put_bytes(pkt, v, &mut top_byte) != 0
            && ((top_byte & 0x80) == 0 || WPACKET_put_bytes_u8(pkt, 0) != 0)
            && WPACKET_close(pkt) != 0
            && WPACKET_put_bytes_u8(pkt, DER_P_INTEGER) != 0
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

/// `static int int_put_bytes_uint32(WPACKET *pkt, const void *v, unsigned int *top_byte)` —
/// `crypto/der_writer.c:109-125`.
///
/// # Safety
/// `pkt` live; `v` readable for a `u32`; `top_byte` writable.
unsafe fn int_put_bytes_uint32(
    pkt: *mut Wpacket,
    v: *const c_void,
    top_byte: *mut c_uint,
) -> c_int {
    // SAFETY: `v` is readable for a `u32` per the contract.
    let value = unsafe { *v.cast::<u32>() };
    let mut tmp = value;
    let mut n: usize = 0;
    while tmp != 0 {
        n += 1;
        // SAFETY: `top_byte` is writable per the contract.
        unsafe { *top_byte = (tmp & 0xFF) as c_uint };
        tmp >>= 8;
    }
    if n == 0 {
        n = 1;
    }

    // SAFETY: `pkt` is live per the contract.
    unsafe { WPACKET_put_bytes__(pkt, value as u64, n) }
}

/// `int ossl_DER_w_uint32(WPACKET *pkt, int tag, uint32_t v)` — `crypto/der_writer.c:127-131`.
///
/// # Safety
/// `pkt` live.
#[allow(dead_code)] // transcribed whole; the X9.42 path does not use it (D346)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_uint32(pkt: *mut Wpacket, tag: c_int, v: u32) -> c_int {
    // SAFETY: `pkt` is live per the contract; `v` is a live local.
    unsafe {
        int_der_w_integer(
            pkt,
            tag,
            int_put_bytes_uint32,
            core::ptr::addr_of!(v).cast(),
        )
    }
}

/// `static int int_put_bytes_bn(WPACKET *pkt, const void *v, unsigned int *top_byte)` —
/// `crypto/der_writer.c:133-148`.
///
/// # Safety
/// `pkt` live; `v` a live non-negative, non-zero `BIGNUM`; `top_byte` writable.
unsafe fn int_put_bytes_bn(pkt: *mut Wpacket, v: *const c_void, top_byte: *mut c_uint) -> c_int {
    let bn = v.cast::<BigNum>();
    // `BN_num_bytes(v)` is the header macro `(BN_num_bits(v) + 7) / 8`.
    // SAFETY: `v` is a live `BIGNUM` per the contract.
    let n = ((unsafe { BN_num_bits(bn) } + 7) / 8) as usize;
    // The caller has already refused zero and negative values, so `n >= 1`.
    let mut p: *mut u8 = core::ptr::null_mut();

    // SAFETY: `v` is a live `BIGNUM`; the limb index is in range because it came from the
    // bit count. The `BN_ULONG` is little-endian on this profile, which is why the top byte
    // comes out of the highest limb.
    unsafe {
        let word = *bn_get_words(bn).add((n - 1) / BN_BYTES);
        *top_byte = ((word >> (8 * ((n - 1) % BN_BYTES))) & 0xFF) as c_uint;

        if WPACKET_allocate_bytes(pkt, n, &mut p) == 0 {
            return 0;
        }
        if !p.is_null() {
            // `BN_bn2bin` writes `n` big-endian bytes; its answer is `n`.
            if BN_bn2bin(bn, p) != n as c_int {
                return 0;
            }
        }
    }
    1
}

/// `int ossl_DER_w_bn(WPACKET *pkt, int tag, const BIGNUM *v)` — `crypto/der_writer.c:150-158`.
///
/// Zero is written through the `uint32` path rather than the limb probe, which is what keeps
/// the `n - 1` index below from reaching a zero-length value.
///
/// # Safety
/// `pkt` live; `v` NULL or a live `BIGNUM`.
#[allow(dead_code)] // transcribed whole; the X9.42 path does not use it (D346)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_bn(pkt: *mut Wpacket, tag: c_int, v: *const BigNum) -> c_int {
    // SAFETY: `v` is NULL or live per the contract.
    unsafe {
        if v.is_null() || BN_is_negative(v) != 0 {
            return 0;
        }
        if BN_is_zero(v) != 0 {
            return ossl_DER_w_uint32(pkt, tag, 0);
        }

        int_der_w_integer(pkt, tag, int_put_bytes_bn, v.cast())
    }
}

/// `int ossl_DER_w_null(WPACKET *pkt, int tag)` — `crypto/der_writer.c:160-167`.
///
/// # Safety
/// `pkt` live.
#[allow(dead_code)] // transcribed whole; the X9.42 path does not use it (D346)
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_null(pkt: *mut Wpacket, tag: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (int_start_context(pkt, tag) != 0
            && WPACKET_start_sub_packet(pkt) != 0
            && WPACKET_close(pkt) != 0
            && WPACKET_put_bytes_u8(pkt, DER_P_NULL) != 0
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

/// `int ossl_DER_w_begin_sequence(WPACKET *pkt, int tag)` — `crypto/der_writer.c:170-174`.
///
/// # Safety
/// `pkt` live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_begin_sequence(pkt: *mut Wpacket, tag: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (int_start_context(pkt, tag) != 0 && WPACKET_start_sub_packet(pkt) != 0) as c_int }
}

/// `int ossl_DER_w_end_sequence(WPACKET *pkt, int tag)` — `crypto/der_writer.c:176-198`.
///
/// **The flag reproduction is the interesting arm.** When a sub-packet closed with nothing
/// written and carried `WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH`, the length is not written and
/// `int_end_context` must skip its own context tag too — so the flag is set on the packet
/// before that call. `WPACKET_set_flags` records it for the *current* sub-packet, which is
/// the one `int_end_context` may then wrap.
///
/// # Safety
/// `pkt` live.
#[allow(non_snake_case)] // the authority's name is the contract
pub(crate) unsafe fn ossl_DER_w_end_sequence(pkt: *mut Wpacket, tag: c_int) -> c_int {
    let mut size1: usize = 0;
    let mut size2: usize = 0;

    // SAFETY: `pkt` is live; the two locals are writable.
    unsafe {
        (WPACKET_get_total_written(pkt, &mut size1) != 0
            && WPACKET_close(pkt) != 0
            && WPACKET_get_total_written(pkt, &mut size2) != 0
            && (if size1 == size2 {
                WPACKET_set_flags(pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) != 0
            } else {
                WPACKET_put_bytes_u8(pkt, DER_F_CONSTRUCTED | DER_P_SEQUENCE) != 0
            })
            && int_end_context(pkt, tag) != 0) as c_int
    }
}

mod tests {
    // The unit's own shape test: the nine definitions exist and the four tag constants are
    // `include/internal/der.h`'s. The behavioural arms live in `RT-KDF`'s X9.42 block, which
    // drives the whole `x942_encode_otherinfo` program against the authority's bytes.
    #[test]
    fn the_tag_constants_are_the_headers_own_numbers() {
        assert_eq!(super::DER_P_BOOLEAN, 1);
        assert_eq!(super::DER_P_INTEGER, 2);
        assert_eq!(super::DER_P_OCTET_STRING, 4);
        assert_eq!(super::DER_P_NULL, 5);
        assert_eq!(super::DER_P_SEQUENCE, 16);
        assert_eq!(super::DER_F_CONSTRUCTED, 0x20);
        assert_eq!(super::DER_C_CONTEXT, 0x80);
    }
}
