//! Phase 8 — `crypto/asn1_dsa.c`: the DER encoder and decoder for `DSA-Sig-Value` and
//! `ECDSA-Sig-Value`.
//!
//! This unit has no stratum's plan row and no crate module before this one. It is transcribed
//! because the DSA landing surfaced it: `crypto/dsa/dsa_sign.c`'s `i2d_DSA_SIG` and
//! `d2i_DSA_SIG` are the whole body of those two functions, and `DSA_sign`/`DSA_verify` reach
//! them (`docs/DECISIONS.md` D333 named the blocker, D342 the landing). **Transcribed whole**
//! (D327's rule): all six definitions, `ossl_encode_der_length`, `ossl_encode_der_integer`,
//! `ossl_encode_der_dsa_sig`, `ossl_decode_der_length`, `ossl_decode_der_integer` and
//! `ossl_decode_der_dsa_sig`.
//!
//! ## The read side is the header, not this unit
//!
//! `crypto/asn1_dsa.c` writes through `crypto/packet.c`'s `WPACKET` and reads through
//! `include/internal/packet.h`'s `PACKET_*` family, which is a set of `static ossl_inline`
//! functions rather than symbols of any translation unit. The [`Packet`] below is those inlines,
//! modelled field-for-field (`curr`, `remaining`) and method-for-method for the five the decoder
//! calls: `PACKET_buf_init`, `PACKET_get_1`, `PACKET_get_sub_packet`,
//! `PACKET_get_length_prefixed_1`, `PACKET_get_length_prefixed_2`, `PACKET_get_bytes`,
//! `PACKET_remaining` and `PACKET_data`. The parent-advances invariant of
//! `PACKET_get_sub_packet` is what makes `ossl_decode_der_dsa_sig`'s `consumed` the whole
//! sequence rather than its header.
//!
//! ## The encoder's two passes
//!
//! `ossl_encode_der_dsa_sig` is written as a *sizing pass and a writing pass*: when the caller's
//! `WPACKET` has a NULL buffer the integers are written straight through, and when it has a real
//! buffer a second, NULL-buffered packet measures the content length first. That second pass, and
//! the `WPACKET_finish`/`WPACKET_cleanup` pair around it, is transcribed rather than simplified.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};

use crate::bn::bignum::{BN_bin2bn, BN_bn2binpad, BN_is_negative, BN_num_bits, BigNum};
use crate::packet::{
    WPACKET_allocate_bytes, WPACKET_cleanup, WPACKET_close, WPACKET_finish, WPACKET_get_length,
    WPACKET_init_null, WPACKET_is_null_buf, WPACKET_put_bytes_u16, WPACKET_put_bytes_u8,
    WPACKET_start_sub_packet, Wpacket,
};

/// `#define ID_SEQUENCE 0x30` — `crypto/asn1_dsa.c:29`.
const ID_SEQUENCE: u8 = 0x30;
/// `#define ID_INTEGER 0x02` — `crypto/asn1_dsa.c:30`.
const ID_INTEGER: u8 = 0x02;

/// `PACKET` — `include/internal/packet.h:22-27`.
///
/// A borrowed read cursor: a pointer into the caller's bytes and a count. The write side of
/// `packet.h` is [`crate::packet`]; this is the read side, and only the operations
/// `crypto/asn1_dsa.c` calls are modelled.
#[derive(Clone, Copy)]
pub(crate) struct Packet {
    /// `const unsigned char *curr`.
    curr: *const c_uchar,
    /// `size_t remaining`.
    remaining: usize,
}

impl Packet {
    /// `PACKET_buf_init`: a view of `len` bytes at `buf`, refusing a length above `SIZE_MAX / 2`.
    ///
    /// # Safety
    ///
    /// `buf` is readable for `len` bytes.
    unsafe fn buf_init(buf: *const c_uchar, len: usize) -> Option<Packet> {
        /* Sanity check for negative values. */
        if len > usize::MAX / 2 {
            return None;
        }
        Some(Packet {
            curr: buf,
            remaining: len,
        })
    }

    /// `PACKET_peek_1` + `PACKET_get_1`: the next byte, advancing.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_1(&mut self) -> Option<u8> {
        if self.remaining == 0 {
            return None;
        }
        // SAFETY: `remaining >= 1`, so the byte is readable.
        let b = unsafe { *self.curr };
        // SAFETY: the pointer advances within the same buffer.
        self.curr = unsafe { self.curr.add(1) };
        self.remaining -= 1;
        Some(b)
    }

    /// `PACKET_get_net_2`: two bytes in network order, advancing.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_net_2(&mut self) -> Option<u32> {
        if self.remaining < 2 {
            return None;
        }
        // SAFETY: `remaining >= 2`, so both bytes are readable.
        let hi = unsafe { *self.curr };
        // SAFETY: as above; the second byte is inside the buffer.
        let lo = unsafe { *self.curr.add(1) };
        // SAFETY: the pointer advances two bytes within the buffer.
        self.curr = unsafe { self.curr.add(2) };
        self.remaining -= 2;
        Some(((hi as u32) << 8) | lo as u32)
    }

    /// `PACKET_peek_bytes` + `PACKET_get_bytes`: a borrowed span, advancing.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_bytes(&mut self, len: usize) -> Option<*const c_uchar> {
        if self.remaining < len {
            return None;
        }
        let data = self.curr;
        // SAFETY: `len <= remaining`, so the advance stays inside the buffer.
        self.curr = unsafe { self.curr.add(len) };
        self.remaining -= len;
        Some(data)
    }

    /// `PACKET_peek_sub_packet` + `PACKET_get_sub_packet`: the next `len` bytes as a sub-packet,
    /// advancing the parent.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_sub(&mut self, len: usize) -> Option<Packet> {
        /* `PACKET_peek_sub_packet`'s own refusal: a prefix longer than what is left is not a
         * sub-packet, and without this the parent's `remaining` would underflow. */
        if self.remaining < len {
            return None;
        }
        // SAFETY: the sub-packet borrows a prefix of the same readable buffer.
        let sub = unsafe { Self::buf_init(self.curr, len) }?;
        // SAFETY: `len <= remaining`, so the advance stays inside the buffer.
        self.curr = unsafe { self.curr.add(len) };
        self.remaining -= len;
        Some(sub)
    }

    /// `PACKET_get_length_prefixed_1`: a one-byte-length-prefixed sub-packet.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_length_prefixed_1(&mut self) -> Option<Packet> {
        /* The header copies the packet first and commits only on success. */
        let mut tmp = *self;
        // SAFETY: `tmp` borrows the same buffer as `self`.
        let length = unsafe { tmp.get_1() }?;
        // SAFETY: as above.
        let data = unsafe { tmp.get_bytes(length as usize) }?;
        *self = tmp;
        Some(Packet {
            curr: data,
            remaining: length as usize,
        })
    }

    /// `PACKET_get_length_prefixed_2`: a two-byte-length-prefixed sub-packet.
    ///
    /// # Safety
    ///
    /// `self.curr` is readable for `self.remaining` bytes.
    unsafe fn get_length_prefixed_2(&mut self) -> Option<Packet> {
        /* The header copies the packet first and commits only on success. */
        let mut tmp = *self;
        // SAFETY: `tmp` borrows the same buffer as `self`.
        let length = unsafe { tmp.get_net_2() }?;
        // SAFETY: as above.
        let data = unsafe { tmp.get_bytes(length as usize) }?;
        *self = tmp;
        Some(Packet {
            curr: data,
            remaining: length as usize,
        })
    }

    /// `PACKET_remaining`.
    fn remaining(&self) -> usize {
        self.remaining
    }

    /// `PACKET_data`.
    fn data(&self) -> *const c_uchar {
        self.curr
    }
}

/// `int ossl_encode_der_length(WPACKET *pkt, size_t cont_len)` — `crypto/asn1_dsa.c:39-57`.
///
/// A content length above `0xffff` answers 0 without writing: the authority's writer supports
/// the short form and the two long forms only.
///
/// # Safety
///
/// `pkt` is a live `WPACKET`.
pub(crate) unsafe fn ossl_encode_der_length(pkt: *mut Wpacket, cont_len: usize) -> c_int {
    if cont_len > 0xffff {
        return 0; /* Too large for supported length encodings */
    }

    // SAFETY: `pkt` is live per the contract.
    unsafe {
        if cont_len > 0xff {
            if WPACKET_put_bytes_u8(pkt, 0x82) == 0
                || WPACKET_put_bytes_u16(pkt, cont_len as u16) == 0
            {
                return 0;
            }
        } else {
            if cont_len > 0x7f && WPACKET_put_bytes_u8(pkt, 0x81) == 0 {
                return 0;
            }
            if WPACKET_put_bytes_u8(pkt, cont_len as u8) == 0 {
                return 0;
            }
        }
    }

    1
}

/// `int ossl_encode_der_integer(WPACKET *pkt, const BIGNUM *n)` — `crypto/asn1_dsa.c:66-97`.
///
/// The content length is `BN_num_bits(n) / 8 + 1`, so a value whose bit count is a multiple of
/// eight gains a leading zero and stays positive in two's complement.
///
/// # Safety
///
/// `pkt` is a live `WPACKET`; `n` is a live `BIGNUM`.
pub(crate) unsafe fn ossl_encode_der_integer(pkt: *mut Wpacket, n: *const BigNum) -> c_int {
    /* `BN_is_negative(n)` is the first refusal; it is a live guard, not a debug one. */
    // SAFETY: `n` is live per the contract.
    if unsafe { BN_is_negative(n) } != 0 {
        return 0;
    }

    // SAFETY: `n` is live.
    let cont_len = (unsafe { BN_num_bits(n) } / 8 + 1) as usize;

    let mut bnbytes: *mut c_uchar = core::ptr::null_mut();
    // SAFETY: `pkt` is live and `bnbytes` is a live local.
    unsafe {
        if WPACKET_start_sub_packet(pkt) == 0
            || WPACKET_put_bytes_u8(pkt, ID_INTEGER) == 0
            || ossl_encode_der_length(pkt, cont_len) == 0
            || WPACKET_allocate_bytes(pkt, cont_len, &mut bnbytes) == 0
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    /* `BN_bn2binpad` is called only when the packet had a buffer. */
    if !bnbytes.is_null() {
        // SAFETY: `bnbytes` is `cont_len` writable bytes owned by `pkt`'s buffer and `n` is live.
        if unsafe { BN_bn2binpad(n, bnbytes, cont_len as c_int) } != cont_len as c_int {
            return 0;
        }
    }

    1
}

/// `int ossl_encode_der_dsa_sig(WPACKET *pkt, const BIGNUM *r, const BIGNUM *s)` —
/// `crypto/asn1_dsa.c:106-147`.
///
/// # Safety
///
/// `pkt` is a live `WPACKET`; `r` and `s` are live `BIGNUM`s.
pub(crate) unsafe fn ossl_encode_der_dsa_sig(
    pkt: *mut Wpacket,
    r: *const BigNum,
    s: *const BigNum,
) -> c_int {
    // SAFETY: a zeroed `WPACKET` is a valid starting state for `WPACKET_init_null`.
    let mut tmppkt: Wpacket = unsafe { core::mem::zeroed() };
    // SAFETY: `pkt` is live per the contract.
    let isnull = unsafe { WPACKET_is_null_buf(pkt) } != 0;

    // SAFETY: `pkt` is live.
    if unsafe { WPACKET_start_sub_packet(pkt) } == 0 {
        return 0;
    }

    let dummypkt: *mut Wpacket = if !isnull {
        // SAFETY: `tmppkt` is a live local.
        if unsafe { WPACKET_init_null(&mut tmppkt, 0) } == 0 {
            return 0;
        }
        &mut tmppkt
    } else {
        /* If the input packet has a NULL buffer, we don't need a dummy packet. */
        pkt
    };

    /* Calculate the content length. */
    let mut cont_len: usize = 0;
    // SAFETY: `dummypkt` is either `pkt` or the live local; `r` and `s` are live.
    let failed = unsafe {
        ossl_encode_der_integer(dummypkt, r) == 0
            || ossl_encode_der_integer(dummypkt, s) == 0
            || WPACKET_get_length(dummypkt, &mut cont_len) == 0
            || (!isnull && WPACKET_finish(dummypkt) == 0)
    };
    if failed {
        if !isnull {
            // SAFETY: `dummypkt` is `tmppkt`, a live packet.
            unsafe { WPACKET_cleanup(dummypkt) };
        }
        return 0;
    }

    /* Add the tag and length bytes. */
    // SAFETY: `pkt` is live; `r` and `s` are live.
    unsafe {
        if WPACKET_put_bytes_u8(pkt, ID_SEQUENCE) == 0
            || ossl_encode_der_length(pkt, cont_len) == 0
            /*
             * Really encode the integers. We already wrote to the main pkt
             * if it had a NULL buffer, so don't do it again.
             */
            || (!isnull && ossl_encode_der_integer(pkt, r) == 0)
            || (!isnull && ossl_encode_der_integer(pkt, s) == 0)
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    1
}

/// `int ossl_decode_der_length(PACKET *pkt, PACKET *subpkt)` — `crypto/asn1_dsa.c:155-171`.
///
/// # Safety
///
/// `pkt` is a live packet over a readable buffer; `subpkt` is writable.
pub(crate) unsafe fn ossl_decode_der_length(pkt: *mut Packet, subpkt: *mut Packet) -> c_int {
    // SAFETY: `pkt` is live per the contract.
    let byte = match unsafe { (*pkt).get_1() } {
        Some(b) => b,
        None => return 0,
    };

    // SAFETY: `pkt` is live; each arm writes `subpkt` on success.
    unsafe {
        if byte < 0x80 {
            return match (*pkt).get_sub(byte as usize) {
                Some(sub) => {
                    *subpkt = sub;
                    1
                }
                None => 0,
            };
        }
        if byte == 0x81 {
            return match (*pkt).get_length_prefixed_1() {
                Some(sub) => {
                    *subpkt = sub;
                    1
                }
                None => 0,
            };
        }
        if byte == 0x82 {
            return match (*pkt).get_length_prefixed_2() {
                Some(sub) => {
                    *subpkt = sub;
                    1
                }
                None => 0,
            };
        }
    }

    /* Too large, invalid, or not DER. */
    0
}

/// `int ossl_decode_der_integer(PACKET *pkt, BIGNUM *n)` — `crypto/asn1_dsa.c:187-217`.
///
/// Two encoding rules are enforced beyond the tag: the INTEGER must be positive (its first
/// content byte's high bit clear), and a zero pad byte must be followed by a byte with the high
/// bit set.
///
/// # Safety
///
/// `pkt` is a live packet over a readable buffer; `n` is a live `BIGNUM`.
pub(crate) unsafe fn ossl_decode_der_integer(pkt: *mut Packet, n: *mut BigNum) -> c_int {
    // SAFETY: a zeroed `PACKET` is a valid starting state; it is filled before any read.
    let mut contpkt: Packet = unsafe { core::mem::zeroed() };
    let mut tmppkt: Packet;
    let tag: u8;

    /* Check we have an integer and get the content bytes. */
    // SAFETY: `pkt` is live, `contpkt` is a live local.
    unsafe {
        match (*pkt).get_1() {
            Some(t) => tag = t,
            None => return 0,
        }
        if tag != ID_INTEGER || ossl_decode_der_length(pkt, &mut contpkt) == 0 {
            return 0;
        }
    }

    /* Peek ahead at the first bytes to check for proper encoding. */
    tmppkt = contpkt;
    /* The INTEGER must be positive. */
    // SAFETY: `tmppkt` borrows the content bytes.
    let tmp = match unsafe { tmppkt.get_1() } {
        Some(t) => t,
        None => return 0,
    };
    if (tmp & 0x80) != 0 {
        return 0;
    }
    /* If there is a zero padding byte the next byte must have the msb set. */
    if tmppkt.remaining() > 0 && tmp == 0 {
        // SAFETY: `tmppkt` still borrows the content bytes.
        match unsafe { tmppkt.get_1() } {
            Some(t) if (t & 0x80) != 0 => {}
            _ => return 0,
        }
    }

    // SAFETY: `contpkt` borrows the content bytes; `n` is live.
    if unsafe { BN_bin2bn(contpkt.data(), contpkt.remaining() as c_int, n) }.is_null() {
        return 0;
    }

    1
}

/// `size_t ossl_decode_der_dsa_sig(BIGNUM *r, BIGNUM *s, const unsigned char **ppin,`
/// `size_t len)` — `crypto/asn1_dsa.c:234-253`.
///
/// Returns the number of bytes consumed, or 0. On success `*ppin` advances past the sequence.
///
/// # Safety
///
/// `r` and `s` are live `BIGNUM`s; `ppin` is a live pointer to a readable pointer; `*ppin` is
/// readable for `len` bytes.
pub(crate) unsafe fn ossl_decode_der_dsa_sig(
    r: *mut BigNum,
    s: *mut BigNum,
    ppin: *mut *const c_uchar,
    len: usize,
) -> usize {
    // SAFETY: a zeroed `PACKET` is a valid starting state; it is filled before any read.
    let mut contpkt: Packet = unsafe { core::mem::zeroed() };
    let tag: u8;

    // SAFETY: `ppin` is live and `*ppin` is readable for `len` bytes per the contract.
    let mut pkt = match unsafe { Packet::buf_init(*ppin, len) } {
        Some(p) => p,
        None => return 0,
    };

    // SAFETY: `pkt` is a live packet over the caller's bytes; `contpkt`, `r` and `s` are live.
    unsafe {
        match pkt.get_1() {
            Some(t) => tag = t,
            None => return 0,
        }
        if tag != ID_SEQUENCE
            || ossl_decode_der_length(&mut pkt, &mut contpkt) == 0
            || ossl_decode_der_integer(&mut contpkt, r) == 0
            || ossl_decode_der_integer(&mut contpkt, s) == 0
            || contpkt.remaining() != 0
        {
            return 0;
        }

        let consumed = pkt.data().offset_from(*ppin) as usize;
        *ppin = (*ppin).add(consumed);
        consumed
    }
}
