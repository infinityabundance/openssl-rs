//! `crypto/ec/ec_asn1.c` — the three `ec.h` DER entry points `ecdsa_ossl.c` reaches, Phase 8.7.
//!
//! **A partial unit, and the ten internals it does not carry are named with their coordinate.**
//! `crypto/ec/ec_asn1.c` is 1,324 lines whose other exports are the
//! `ECParameters`/`ECPKParameters`/`EC_PRIVATEKEY` family and whose ten internals are the
//! `ASN1_SEQUENCE` template objects those families are encoded with —
//! `X9_62_PENTANOMIAL_new`/`_free`, `X9_62_CHARACTERISTIC_TWO_new`/`_free`,
//! `X9_62_CHARACTERISTIC_TWO_new`/`_free`'s siblings `EC_PRIVATEKEY_new`/`_free`,
//! `d2i_ECPKPARAMETERS`, `i2d_ECPKPARAMETERS`, `d2i_EC_PRIVATEKEY` and `i2d_EC_PRIVATEKEY`.
//! That machinery is **8.8's** (D334's "`ec_asn1.c`'s `d2i_`/`i2d_` and the `ECParameters`/
//! `ECPKParameters` family with `ec_ameth.c` and `eck_prn.c`"), and it is recorded in
//! `forensics/prerequisites.json`'s divergence list with this module rather than stubbed.
//!
//! Three exports are landed because a **landed** unit needs them and because they are `ec.h`'s,
//! which is this subphase's header:
//!
//! * [`ECDSA_size`] — `crypto/ec/ec_asn1.c:1301-1324`, the buffer size an ECDSA signature needs;
//! * [`i2d_ECDSA_SIG`] — `:1231-1270`, the `ECDSA-Sig-Value` encoder;
//! * [`d2i_ECDSA_SIG`] — `:1203-1229`, its decoder.
//!
//! ## The DER codec is a byte-exact substitution, and it is the one place this module departs
//!
//! In the authority the encoder and decoder are `crypto/asn1_dsa.c`'s
//! `ossl_encode_der_dsa_sig`/`ossl_decode_der_dsa_sig` over `crypto/packet.c`'s `WPACKET`/`PACKET`.
//! **Neither unit has a crate module and no stratum's plan row names one** — the same blocker
//! `src/dsa/sign.rs` records for `i2d_DSA_SIG`/`d2i_DSA_SIG` — so the two functions are
//! transcribed here as this module's own private `encode`/`decode` helpers with the authority's
//! exact semantics: the length octets, the positive-integer rule (content length `bits/8 + 1`, so
//! a value whose bit count is a multiple of eight gains a leading zero), the
//! sequence-only-no-trailing-garbage rule, the two refusal rules the decoder applies to an
//! INTEGER (a set high bit, and a zero pad byte followed by a byte without one), and the
//! `Hasse`-free `INTEGER`-only shape of `ECDSA-Sig-Value`.
//!
//! The difference from the authority is therefore the *call graph* and not the bytes: a caller
//! comparing `i2d_ECDSA_SIG`'s output or `d2i_ECDSA_SIG`'s answer against the authority sees the
//! same values, and `RT-EC`'s sign-then-verify arm drives both through the key method. The
//! substitution is recorded in `docs/DECISIONS.md` D340.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar};
use core::ptr;

use crate::bn::bignum::{BN_bin2bn, BN_bn2binpad, BN_is_negative, BN_new, BN_num_bits, BigNum};
use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_SIG_new};
use crate::ec::key::EC_KEY_get0_group;
use crate::ec::lib::EC_GROUP_get0_order;
use crate::ec::{EcKey, EcdsaSig};
use crate::runtime::mem::CRYPTO_malloc;

/// The translation-unit coordinate the one allocation this module makes is attributed to, as the
/// allocator reports it. `crypto/ec/ec_asn1.c` is a source-tree file, so its `__FILE__` carries
/// the admitted build record's prefix.
///
/// The authority's `i2d_ECDSA_SIG` allocates through `BUF_MEM_new`/`WPACKET` (which report
/// `crypto/buffer/buffer.c`); the codec here allocates the exact output directly, so this string
/// is part of the recorded substitution rather than the authority's own.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_asn1.c".as_ptr();

/// The line the encoder's one allocation is attributed to — `i2d_ECDSA_SIG`'s body.
const LINE: c_int = 1231;

/// `PACKET` — `include/internal/packet.h`'s read cursor: a pointer and a remaining length.
///
/// Only the four operations the decoder uses are modelled: a one-byte read, a sub-packet read
/// (which **advances** the parent, as `PACKET_get_sub_packet` does), the remaining length and the
/// data pointer. The parent-advances invariant is what makes the decoder's `consumed` the whole
/// sequence and not its header.
#[derive(Clone, Copy)]
struct Packet {
    p: *const c_uchar,
    len: usize,
}

impl Packet {
    /// `PACKET_buf_init`: no copy, the packet is a view of the caller's bytes.
    fn new(p: *const c_uchar, len: usize) -> Self {
        Packet { p, len }
    }

    /// `PACKET_get_1`.
    ///
    /// # Safety
    ///
    /// The packet is a view of a readable buffer whose length is `self.len`.
    unsafe fn get_1(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: `self.p` is readable for `self.len >= 1` bytes.
        let b = unsafe { *self.p };
        // SAFETY: the pointer advances within the same buffer.
        self.p = unsafe { self.p.add(1) };
        self.len -= 1;
        Some(b)
    }

    /// `PACKET_get_sub_packet`: take the next `n` bytes and advance past them.
    fn get_sub(&mut self, n: usize) -> Option<Packet> {
        if self.len < n {
            return None;
        }
        let sub = Packet { p: self.p, len: n };
        // SAFETY: `n <= self.len`, so the advance stays inside the buffer.
        self.p = unsafe { self.p.add(n) };
        self.len -= n;
        Some(sub)
    }

    /// `PACKET_remaining`.
    fn remaining(&self) -> usize {
        self.len
    }

    /// `PACKET_data`.
    fn data(&self) -> *const c_uchar {
        self.p
    }
}

/// `int ossl_encode_der_length(WPACKET *pkt, size_t cont_len)` — `crypto/asn1_dsa.c:39-57`.
///
/// A content length above 0xffff answers 0 without writing: the authority's packet writer
/// supports the short form and the two long forms only.
fn encode_der_length(out: &mut Vec<u8>, cont_len: usize) -> bool {
    if cont_len > 0xffff {
        return false;
    }
    if cont_len > 0xff {
        out.push(0x82);
        out.push((cont_len >> 8) as u8);
        out.push(cont_len as u8);
    } else {
        if cont_len > 0x7f {
            out.push(0x81);
        }
        out.push(cont_len as u8);
    }
    true
}

/// `int ossl_encode_der_integer(WPACKET *pkt, const BIGNUM *n)` — `crypto/asn1_dsa.c:66-97`.
///
/// The content length is `BN_num_bits(n) / 8 + 1`, **not** the byte width: a run of whole bytes
/// gains a leading zero byte so the value is still positive in two's complement, and zero is a
/// single zero byte. A negative `n` answers 0.
///
/// # Safety
///
/// `n` is live.
unsafe fn encode_der_integer(out: &mut Vec<u8>, n: *const BigNum) -> bool {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if BN_is_negative(n) != 0 {
            return false;
        }
        let cont_len = (BN_num_bits(n) / 8 + 1) as usize;

        out.push(0x02);
        if !encode_der_length(out, cont_len) {
            return false;
        }
        let start = out.len();
        out.resize(start + cont_len, 0);
        if BN_bn2binpad(
            n,
            // SAFETY: the vector was just resized to hold `cont_len` more bytes.
            out.as_mut_ptr().add(start),
            cont_len as c_int,
        ) != cont_len as c_int
        {
            return false;
        }
        true
    }
}

/// `int ossl_encode_der_dsa_sig(WPACKET *pkt, const BIGNUM *r, const BIGNUM *s)` —
/// `crypto/asn1_dsa.c:106-147`.
///
/// The authority measures the content by writing the two INTEGERs into a *null* packet, then
/// writes the SEQUENCE tag and length and the two INTEGERs again. Encoding the body once and
/// prefixing it produces the same bytes and is the substitution this module's documentation
/// records.
///
/// # Safety
///
/// `r` and `s` are live.
unsafe fn encode_der_dsa_sig(out: &mut Vec<u8>, r: *const BigNum, s: *const BigNum) -> bool {
    let mut body = Vec::new();
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    if !unsafe { encode_der_integer(&mut body, r) } {
        return false;
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    if !unsafe { encode_der_integer(&mut body, s) } {
        return false;
    }
    out.push(0x30);
    if !encode_der_length(out, body.len()) {
        return false;
    }
    out.extend_from_slice(&body);
    true
}

/// `int ossl_decode_der_length(PACKET *pkt, PACKET *subpkt)` — `crypto/asn1_dsa.c:155-171`.
///
/// The short form is a length below 0x80; `0x81` and `0x82` are the two length-prefixed long
/// forms the authority accepts. Anything else — an indefinite length, a form wider than two
/// octets, or an exhausted packet — answers `None`.
unsafe fn decode_der_length(pkt: &mut Packet) -> Option<Packet> {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    let byte = unsafe { pkt.get_1()? } as usize;
    if byte < 0x80 {
        return pkt.get_sub(byte);
    }
    if byte == 0x81 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
        let n = unsafe { pkt.get_1()? } as usize;
        return pkt.get_sub(n);
    }
    if byte == 0x82 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
        let hi = unsafe { pkt.get_1()? } as usize;
        // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
        let lo = unsafe { pkt.get_1()? } as usize;
        return pkt.get_sub((hi << 8) | lo);
    }
    None
}

/// `int ossl_decode_der_integer(PACKET *pkt, BIGNUM *n)` — `crypto/asn1_dsa.c:187-217`.
///
/// Two encoding rules are enforced before the value is read: the first content byte must have
/// its high bit **clear** (the INTEGER must be positive), and a leading zero pad byte must be
/// followed by a byte whose high bit is set (the pad must be necessary). The value is written
/// into the caller's already-allocated `n`.
///
/// # Safety
///
/// `pkt` is a view of readable bytes; `n` is a live, allocated `BIGNUM`.
unsafe fn decode_der_integer(pkt: &mut Packet, n: *mut BigNum) -> bool {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(tag) = pkt.get_1() else {
            return false;
        };
        if tag != 0x02 {
            return false;
        }
        let Some(contpkt) = decode_der_length(pkt) else {
            return false;
        };

        // Peek ahead at the first bytes to check for proper encoding.
        let mut tmppkt = contpkt;
        let Some(tmp) = tmppkt.get_1() else {
            return false;
        };
        // The INTEGER must be positive.
        if (tmp & 0x80) != 0 {
            return false;
        }
        // If there is a zero padding byte the next byte must have the msb set.
        if tmppkt.remaining() > 0 && tmp == 0 {
            let Some(next) = tmppkt.get_1() else {
                return false;
            };
            if (next & 0x80) == 0 {
                return false;
            }
        }

        if BN_bin2bn(contpkt.data(), contpkt.remaining() as c_int, n).is_null() {
            return false;
        }
        true
    }
}

/// `size_t ossl_decode_der_dsa_sig(BIGNUM *r, BIGNUM *s, const unsigned char **ppin, size_t len)`
/// — `crypto/asn1_dsa.c:234-253`.
///
/// Answers the number of bytes consumed, or 0. The whole sequence must be consumed
/// (`PACKET_remaining(&contpkt) != 0` is a refusal), which is the "no trailing garbage inside the
/// sequence" rule; a caller that wants the *outer* buffer to hold nothing else checks that
/// itself, which is what [`crate::ec::ecdsa_ossl`]'s verify does by re-encoding and comparing.
///
/// # Safety
///
/// `r` and `s` are live; `*ppin` is readable for `len` bytes; `ppin` is writable.
unsafe fn decode_der_dsa_sig(
    r: *mut BigNum,
    s: *mut BigNum,
    ppin: *mut *const c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let start = *ppin;
        let mut pkt = Packet::new(start, len);

        let Some(tag) = pkt.get_1() else {
            return 0;
        };
        if tag != 0x30 {
            return 0;
        }
        let Some(mut contpkt) = decode_der_length(&mut pkt) else {
            return 0;
        };
        if !decode_der_integer(&mut contpkt, r) || !decode_der_integer(&mut contpkt, s) {
            return 0;
        }
        if contpkt.remaining() != 0 {
            return 0;
        }

        let consumed = (pkt.data() as usize) - (start as usize);
        *ppin = start.add(consumed);
        consumed
    }
}

/// `ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **psig, const unsigned char **ppin, long len)` —
/// `crypto/ec/ec_asn1.c:1203-1229`.
///
/// A negative `len` answers NULL. An existing `*psig` is **reused** and updated in place; only
/// when there is none is a fresh object allocated, and a fresh object is freed on failure while
/// a caller's is not. On success the caller's slot is filled only when it was empty.
///
/// # Safety
///
/// `psig` is NULL or a writable pointer slot; `ppin` is a readable pointer slot over at least
/// `len` bytes; each `*psig` is NULL or a live `ECDSA_SIG`.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECDSA_SIG(
    psig: *mut *mut EcdsaSig,
    ppin: *mut *const c_uchar,
    len: c_long,
) -> *mut EcdsaSig {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if len < 0 {
            return ptr::null_mut();
        }

        let sig = if !psig.is_null() && !(*psig).is_null() {
            *psig
        } else {
            let s = ECDSA_SIG_new();
            if s.is_null() {
                return ptr::null_mut();
            }
            s
        };

        if (*sig).r.is_null() {
            (*sig).r = BN_new();
        }
        if (*sig).s.is_null() {
            (*sig).s = BN_new();
        }
        if (*sig).r.is_null()
            || (*sig).s.is_null()
            || decode_der_dsa_sig((*sig).r, (*sig).s, ppin, len as usize) == 0
        {
            if psig.is_null() || (*psig).is_null() {
                ECDSA_SIG_free(sig);
            }
            return ptr::null_mut();
        }
        if !psig.is_null() && (*psig).is_null() {
            *psig = sig;
        }
        sig
    }
}

/// `int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **ppout)` —
/// `crypto/ec/ec_asn1.c:1231-1270`.
///
/// Three call shapes: `ppout == NULL` measures and allocates nothing; `*ppout == NULL` allocates
/// exactly the encoded length and leaves the caller to release it; otherwise the bytes are
/// written where the caller points and the caller's pointer is advanced past them. The answer is
/// the encoded length in all three, or -1 for a negative `r`/`s`.
///
/// # Safety
///
/// `sig` is live; `ppout` is NULL or a writable slot whose `*ppout` is NULL or writable for the
/// encoded length.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECDSA_SIG(sig: *const EcdsaSig, ppout: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut out = Vec::new();
        if !encode_der_dsa_sig(&mut out, (*sig).r, (*sig).s) {
            return -1;
        }
        let encoded_len = out.len();

        if !ppout.is_null() {
            if (*ppout).is_null() {
                let buf = CRYPTO_malloc(encoded_len, FILE, LINE).cast::<c_uchar>();
                if buf.is_null() {
                    return -1;
                }
                ptr::copy_nonoverlapping(out.as_ptr(), buf, encoded_len);
                *ppout = buf;
            } else {
                ptr::copy_nonoverlapping(out.as_ptr(), *ppout, encoded_len);
                *ppout = (*ppout).add(encoded_len);
            }
        }

        encoded_len as c_int
    }
}

/// `int ECDSA_size(const EC_KEY *ec)` — `crypto/ec/ec_asn1.c:1301-1324`.
///
/// A NULL key, a key with no group or a group with no order all answer **0**, not -1 — this is a
/// size, and a caller treats 0 as "cannot sign". The size is measured by encoding a signature
/// whose two halves are both the group's order, which is the widest either half can be.
///
/// # Safety
///
/// `ec` is NULL or a live `EC_KEY`.
#[no_mangle]
pub unsafe extern "C" fn ECDSA_size(ec: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ec.is_null() {
            return 0;
        }
        let group = EC_KEY_get0_group(ec);
        if group.is_null() {
            return 0;
        }

        let bn = EC_GROUP_get0_order(group);
        if bn.is_null() {
            return 0;
        }

        let sig = EcdsaSig {
            r: bn.cast_mut(),
            s: bn.cast_mut(),
        };
        let mut ret = i2d_ECDSA_SIG(&sig, ptr::null_mut());

        if ret < 0 {
            ret = 0;
        }
        ret
    }
}

// The unit's ten template internals are withheld and named in the module documentation:
// `X9_62_PENTANOMIAL_new`/`_free`, `X9_62_CHARACTERISTIC_TWO_new`/`_free`,
// `EC_PRIVATEKEY_new`/`_free`, `d2i_ECPKPARAMETERS`, `i2d_ECPKPARAMETERS`, `d2i_EC_PRIVATEKEY`
// and `i2d_EC_PRIVATEKEY`. They are 8.8's ASN.1 template machinery, recorded in
// `forensics/prerequisites.json`'s divergence list with this module.
