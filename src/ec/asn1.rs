//! `crypto/ec/ec_asn1.c` — the `ECParameters`/`ECPKParameters`/`EC_PRIVATEKEY` DER family and the
//! three `ECDSA-Sig-Value` entry points, Phase 8.7.
//!
//! **The unit is whole (D327's rule), and D347 retires the divergence row this module used to carry.**
//! `crypto/ec/ec_asn1.c` is 1,324 lines. Twenty-one of its exports are here — the six ASN.1
//! templates and the internals `IMPLEMENT_ASN1_*` generates from them (`X9_62_PENTANOMIAL`,
//! `X9_62_CHARACTERISTIC_TWO`, `X9_62_FIELDID`, `X9_62_CURVE`, `ECPARAMETERS`, `ECPKPARAMETERS`,
//! `EC_PRIVATEKEY`), the `ASN1_ALLOC_FUNCTIONS` accessors (`ECPARAMETERS_new`/`_free`/`_it`,
//! `ECPKPARAMETERS_new`/`_free`/`_it`), the parameter codecs (`d2i_ECPKParameters`,
//! `i2d_ECPKParameters`, `d2i_ECParameters`, `i2d_ECParameters`, `EC_GROUP_get_ecparameters`,
//! `EC_GROUP_get_ecpkparameters`, `EC_GROUP_new_from_ecparameters`,
//! `EC_GROUP_new_from_ecpkparameters`), the SEC1 private-key pair (`d2i_ECPrivateKey`,
//! `i2d_ECPrivateKey`) and the two public-point codecs (`o2i_ECPublicKey`, `i2o_ECPublicKey`).
//!
//! The eight internals the divergence row used to name are built here **by the authority's own
//! spelling** rather than approximated, which is what makes the row retirable: `EC_PRIVATEKEY_new`,
//! `EC_PRIVATEKEY_free`, `X9_62_CHARACTERISTIC_TWO_new`, `X9_62_PENTANOMIAL_new`,
//! `d2i_ECPKPARAMETERS`, `i2d_ECPKPARAMETERS`, `d2i_EC_PRIVATEKEY` and `i2d_EC_PRIVATEKEY`. The
//! item accessors the two `static_ASN1_SEQUENCE_END` forms make private in the authority are private
//! fns here too; the two `ASN1_SEQUENCE_END`/`ASN1_CHOICE_END` forms give `ECPARAMETERS_it` and
//! `ECPKPARAMETERS_it` external linkage, which is why those two are exports.
//!
//! Three of the exports are the ECDSA-Sig-Value tail (D340 landed them first, when the unit had only
//! a partial module):
//!
//! * [`ECDSA_size`] — `crypto/ec/ec_asn1.c:1301-1324`, the buffer size an ECDSA signature needs;
//! * [`i2d_ECDSA_SIG`] — `:1231-1270`, the `ECDSA-Sig-Value` encoder;
//! * [`d2i_ECDSA_SIG`] — `:1203-1229`, its decoder.
//!
//! **`ECParameters_print` is not this unit's** — its body is `crypto/ec/ec_ameth.c:717-720` — and
//! it lives in [`crate::ec::prn`] with the `eck_prn.c` printers it is the callee of. The one
//! `ec_ameth.c` export that is **not** landed is `EC_KEY_print` (and its `_fp` wrapper), which is
//! withheld with the `EVP_PKEY_ASN1_METHOD` object it belongs to.
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

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::mem::{offset_of, size_of};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_free;
use crate::asn1::bitstr::{set_bits_left, ASN1_BIT_STRING_set};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{
    ASN1_INTEGER_get, ASN1_INTEGER_set, ASN1_INTEGER_to_BN, ASN1_OBJECT_free, BN_to_ASN1_INTEGER,
};
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_BIT_STRING_new, ASN1_INTEGER_new, ASN1_OCTET_STRING_new,
    ASN1_OCTET_STRING_set, ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set0,
};
use crate::asn1::typ::ASN1_NULL_new;
use crate::asn1::x_int64::INT32_it;
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_free, BN_is_negative, BN_is_zero, BN_new, BN_num_bits, BN_set_bit,
    BigNum,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BnCtx};
use crate::ec::curve::{ossl_ec_curve_nid_from_params, EC_GROUP_new_by_curve_name};
use crate::ec::cvt::{EC_GROUP_new_curve_GF2m, EC_GROUP_new_curve_GFp};
use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_SIG_new};
use crate::ec::key::{
    EC_KEY_free, EC_KEY_get0_group, EC_KEY_key2buf, EC_KEY_new, EC_KEY_oct2key, EC_KEY_oct2priv,
    EC_KEY_priv2buf, EC_KEY_set_flags, EC_FLAG_SM2_RANGE, EC_PKEY_NO_PUBKEY,
};
use crate::ec::lib::{
    EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get0_cofactor, EC_GROUP_get0_generator,
    EC_GROUP_get0_order, EC_GROUP_get_asn1_flag, EC_GROUP_get_basis_type, EC_GROUP_get_curve,
    EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_get_pentanomial_basis, EC_GROUP_get_point_conversion_form,
    EC_GROUP_get_trinomial_basis, EC_GROUP_set_asn1_flag, EC_GROUP_set_generator,
    EC_GROUP_set_point_conversion_form, EC_GROUP_set_seed, EC_POINT_clear_free, EC_POINT_free,
    EC_POINT_new,
};
use crate::ec::oct::{EC_POINT_oct2point, EC_POINT_point2buf, EC_POINT_point2oct};
use crate::ec::{EcGroup, EcKey, EcPoint, EcdsaSig};
use crate::evp::pkey_ctx::{OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    Asn1Object, NID_X9_62_characteristic_two_field, NID_X9_62_onBasis, NID_X9_62_ppBasis,
    NID_X9_62_prime_field, NID_X9_62_tpBasis, NID_sm2, NID_undef, OBJ_length, OBJ_nid2obj,
    OBJ_obj2nid,
};

/// The translation-unit coordinate every allocation this module makes is attributed to, as the
/// allocator reports it. `crypto/ec/ec_asn1.c` is a source-tree file, so its `__FILE__` carries
/// the admitted build record's prefix.
///
/// The authority's `i2d_ECDSA_SIG` allocates through `BUF_MEM_new`/`WPACKET` (which report
/// `crypto/buffer/buffer.c`); the codec here allocates the exact output directly, so `LINE`
/// below is part of the recorded substitution rather than the authority's own. The parameter
/// family's own allocations are attributed to the authority's line at each site.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_asn1.c".as_ptr();

/// The line the ECDSA encoder's one allocation is attributed to — `i2d_ECDSA_SIG`'s body.
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

// ---------------------------------------------------------------------------------------------
// The C structures the templates are laid out over — `crypto/ec/ec_asn1.c:28-99`
// ---------------------------------------------------------------------------------------------

/// `OPENSSL_ECC_MAX_FIELD_BITS` — `include/openssl/ec.h:103`. The largest field
/// `EC_GROUP_new_from_ecparameters` will build from explicit parameters.
const OPENSSL_ECC_MAX_FIELD_BITS: c_int = 661;

/// `EC_PKEY_NO_PARAMETERS` — `include/openssl/ec.h:950`. An `enc_flag` bit `i2d_ECPrivateKey`
/// reads to decide whether the `ECPKPARAMETERS` field is emitted. Its sibling
/// `EC_PKEY_NO_PUBKEY` lives in [`crate::ec::key`] because the backend reads it there too.
const EC_PKEY_NO_PARAMETERS: c_int = 0x001;

/// The three `ecpk_parameters_type_t` enumerators — `crypto/ec/ec_asn1.c:78-82`. They are the
/// `ECPKPARAMETERS` CHOICE's selector values, and the union arm each one selects.
const ECPKPARAMETERS_TYPE_NAMED: c_int = 0;
const ECPKPARAMETERS_TYPE_EXPLICIT: c_int = 1;
const ECPKPARAMETERS_TYPE_IMPLICIT: c_int = 2;

/// `X9_62_PENTANOMIAL` — `crypto/ec/ec_asn1.c:28-32`. The three exponent k's of a pentanomial
/// basis, each a raw `int32_t` in an `ASN1_EMBED` field rather than a pointer.
#[repr(C)]
struct X9_62Pentanomial {
    k1: i32,
    k2: i32,
    k3: i32,
}

/// `X9_62_CHARACTERISTIC_TWO` — `:34-48`.
///
/// The union `p` is modelled as one `*mut c_void`: every arm is a pointer of the same width, the
/// templates reach it through `offset_of!` alone, and which arm a value holds is decided by the
/// selector `type`, which is what the `ADB` table below keys on. `type_` carries the C member's
/// name.
#[repr(C)]
struct X9_62CharacteristicTwo {
    m: i32,
    type_: *mut Asn1Object,
    p: *mut c_void,
}

/// `X9_62_FIELDID` — `:50-61`. `field_type` is the `fieldType` member; `p` is the same
/// pointer-union modelling [`X9_62CharacteristicTwo`] uses.
#[repr(C)]
struct X9_62Fieldid {
    field_type: *mut Asn1Object,
    p: *mut c_void,
}

/// `X9_62_CURVE` — `:63-67`.
#[repr(C)]
struct X9_62Curve {
    a: *mut Asn1String,
    b: *mut Asn1String,
    seed: *mut Asn1String,
}

/// `ECPARAMETERS` (`struct ec_parameters_st`) — `:69-76`.
#[repr(C)]
pub struct EcParameters {
    version: i32,
    field_id: *mut X9_62Fieldid,
    curve: *mut X9_62Curve,
    base: *mut Asn1String,
    order: *mut Asn1String,
    cofactor: *mut Asn1String,
}

/// `ECPKPARAMETERS` (`struct ecpk_parameters_st`) — `:84-91`. The `value` union is a single
/// `*mut c_void` for the reason [`X9_62CharacteristicTwo`]'s is; `type_` carries the C member's
/// name and is the CHOICE selector.
#[repr(C)]
pub struct EcpkParameters {
    type_: c_int,
    value: *mut c_void,
}

/// `EC_PRIVATEKEY` (`struct ec_privatekey_st`) — `:94-99`, the SEC1 private key.
#[repr(C)]
struct EcPrivateKey {
    version: i32,
    private_key: *mut Asn1String,
    parameters: *mut EcpkParameters,
    public_key: *mut Asn1String,
}

/// The offsets the template arrays below name, derived rather than typed twice. A wrong offset is
/// a decode into the wrong member, which no round trip over a structure whose fields are all
/// pointers would catch — the same argument [`crate::dsa::asn1`] records.
const OFFSET_PENTA_K1: c_ulong = offset_of!(X9_62Pentanomial, k1) as c_ulong;
const OFFSET_PENTA_K2: c_ulong = offset_of!(X9_62Pentanomial, k2) as c_ulong;
const OFFSET_PENTA_K3: c_ulong = offset_of!(X9_62Pentanomial, k3) as c_ulong;
const OFFSET_CHAR_TWO_M: c_ulong = offset_of!(X9_62CharacteristicTwo, m) as c_ulong;
const OFFSET_CHAR_TWO_TYPE: c_ulong = offset_of!(X9_62CharacteristicTwo, type_) as c_ulong;
const OFFSET_CHAR_TWO_P: c_ulong = offset_of!(X9_62CharacteristicTwo, p) as c_ulong;
const OFFSET_FIELDID_TYPE: c_ulong = offset_of!(X9_62Fieldid, field_type) as c_ulong;
const OFFSET_FIELDID_P: c_ulong = offset_of!(X9_62Fieldid, p) as c_ulong;
const OFFSET_CURVE_A: c_ulong = offset_of!(X9_62Curve, a) as c_ulong;
const OFFSET_CURVE_B: c_ulong = offset_of!(X9_62Curve, b) as c_ulong;
const OFFSET_CURVE_SEED: c_ulong = offset_of!(X9_62Curve, seed) as c_ulong;
const OFFSET_EP_VERSION: c_ulong = offset_of!(EcParameters, version) as c_ulong;
const OFFSET_EP_FIELDID: c_ulong = offset_of!(EcParameters, field_id) as c_ulong;
const OFFSET_EP_CURVE: c_ulong = offset_of!(EcParameters, curve) as c_ulong;
const OFFSET_EP_BASE: c_ulong = offset_of!(EcParameters, base) as c_ulong;
const OFFSET_EP_ORDER: c_ulong = offset_of!(EcParameters, order) as c_ulong;
const OFFSET_EP_COFACTOR: c_ulong = offset_of!(EcParameters, cofactor) as c_ulong;
const OFFSET_PKP_TYPE: c_ulong = offset_of!(EcpkParameters, type_) as c_ulong;
const OFFSET_PKP_VALUE: c_ulong = offset_of!(EcpkParameters, value) as c_ulong;
const OFFSET_PK_VERSION: c_ulong = offset_of!(EcPrivateKey, version) as c_ulong;
const OFFSET_PK_PRIVATE: c_ulong = offset_of!(EcPrivateKey, private_key) as c_ulong;
const OFFSET_PK_PARAMS: c_ulong = offset_of!(EcPrivateKey, parameters) as c_ulong;
const OFFSET_PK_PUBLIC: c_ulong = offset_of!(EcPrivateKey, public_key) as c_ulong;

/// `sizeof` each of the seven structures, which is the `size` field of its item.
const PENTA_SIZE: c_long = size_of::<X9_62Pentanomial>() as c_long;
const CHAR_TWO_SIZE: c_long = size_of::<X9_62CharacteristicTwo>() as c_long;
const FIELDID_SIZE: c_long = size_of::<X9_62Fieldid>() as c_long;
const CURVE_SIZE: c_long = size_of::<X9_62Curve>() as c_long;
const EP_SIZE: c_long = size_of::<EcParameters>() as c_long;
const PKP_SIZE: c_long = size_of::<EcpkParameters>() as c_long;
const PK_SIZE: c_long = size_of::<EcPrivateKey>() as c_long;

const _: () = {
    assert!(PENTA_SIZE == 12);
    assert!(CHAR_TWO_SIZE == 24);
    assert!(FIELDID_SIZE == 16);
    assert!(CURVE_SIZE == 24);
    assert!(EP_SIZE == 48);
    assert!(PKP_SIZE == 16);
    assert!(PK_SIZE == 32);
    assert!(OFFSET_PENTA_K1 == 0 && OFFSET_PENTA_K2 == 4 && OFFSET_PENTA_K3 == 8);
    assert!(OFFSET_CHAR_TWO_M == 0 && OFFSET_CHAR_TWO_TYPE == 8 && OFFSET_CHAR_TWO_P == 16);
    assert!(OFFSET_FIELDID_TYPE == 0 && OFFSET_FIELDID_P == 8);
    assert!(OFFSET_CURVE_A == 0 && OFFSET_CURVE_B == 8 && OFFSET_CURVE_SEED == 16);
    assert!(
        OFFSET_EP_VERSION == 0
            && OFFSET_EP_FIELDID == 8
            && OFFSET_EP_CURVE == 16
            && OFFSET_EP_BASE == 24
            && OFFSET_EP_ORDER == 32
            && OFFSET_EP_COFACTOR == 40
    );
    assert!(OFFSET_PKP_TYPE == 0 && OFFSET_PKP_VALUE == 8);
    assert!(
        OFFSET_PK_VERSION == 0
            && OFFSET_PK_PRIVATE == 8
            && OFFSET_PK_PARAMS == 16
            && OFFSET_PK_PUBLIC == 24
    );
};

// ---------------------------------------------------------------------------------------------
// The `ANY DEFINED BY` tables — `ASN1_ADB_TEMPLATE`/`ADB_ENTRY`/`ASN1_ADB_END`
// ---------------------------------------------------------------------------------------------

/// The `ASN1_ADB` the ADB-carrying templates point at. Wrapped because [`Asn1Adb`] holds raw
/// pointers and is therefore not `Sync`; the wrapper's `unsafe impl` is the same claim
/// [`crate::asn1::layout`] makes for [`Asn1Item`] and [`Asn1Template`].
#[repr(transparent)]
struct SyncAdb(Asn1Adb);

// SAFETY: this value is built from constants — a null callback, a `&'static` table of compiled-in
// templates and two `&'static`/null template pointers — is written once by the loader and never
// again, and exposes no interior mutability through a shared reference. The machinery only ever
// reads it.
unsafe impl Sync for SyncAdb {}

/// `char_two_def_tt` — `ASN1_ADB_TEMPLATE(char_two_def) = ASN1_SIMPLE(X9_62_CHARACTERISTIC_TWO,
/// p.other, ASN1_ANY)` at `crypto/ec/ec_asn1.c:111`. The template an unmatched base type uses.
static CHAR_TWO_DEF_TT: Asn1Template = Asn1Template {
    flags: 0,
    tag: 0,
    offset: OFFSET_CHAR_TWO_P,
    field_name: c"p.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `X9_62_CHARACTERISTIC_TWO_adbtbl[]` — `crypto/ec/ec_asn1.c:113-117`. The three base types, in
/// the authority's order, each a `p.` arm of the union at the same offset.
static CHAR_TWO_ADBTBL: [Asn1AdbTable; 3] = [
    Asn1AdbTable {
        value: NID_X9_62_onBasis as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: OFFSET_CHAR_TWO_P,
            field_name: c"p.onBasis".as_ptr(),
            item: ASN1_NULL_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_X9_62_tpBasis as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: OFFSET_CHAR_TWO_P,
            field_name: c"p.tpBasis".as_ptr(),
            item: ASN1_INTEGER_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_X9_62_ppBasis as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: OFFSET_CHAR_TWO_P,
            field_name: c"p.ppBasis".as_ptr(),
            item: x9_62_pentanomial_it as *mut c_void,
        },
    },
];

/// `X9_62_CHARACTERISTIC_TWO_adb` — the `ASN1_ADB_END`-generated accessor at `:117`. The
/// selector is `type` at offset 8; the default is `char_two_def_tt` and there is no null arm.
static CHAR_TWO_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: OFFSET_CHAR_TWO_TYPE,
    adb_cb: None,
    tbl: CHAR_TWO_ADBTBL.as_ptr(),
    tblcount: 3,
    default_tt: ptr::addr_of!(CHAR_TWO_DEF_TT),
    null_tt: ptr::null(),
});

/// The `char_two_adb` accessor the `ADB` template stores: it answers the `ASN1_ADB`, which the
/// machinery reads through `call_item_exp` exactly as it reads an item accessor.
///
/// # Safety
///
/// None: it takes no pointer and answers a `&'static` constant.
fn x9_62_characteristic_two_adb() -> *const c_void {
    ptr::addr_of!(CHAR_TWO_ADB.0).cast::<c_void>()
}

/// `fieldID_def_tt` — `ASN1_ADB_TEMPLATE(fieldID_def)` at `crypto/ec/ec_asn1.c:128`.
static FIELDID_DEF_TT: Asn1Template = Asn1Template {
    flags: 0,
    tag: 0,
    offset: OFFSET_FIELDID_P,
    field_name: c"p.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `X9_62_FIELDID_adbtbl[]` — `crypto/ec/ec_asn1.c:130-133`.
static FIELDID_ADBTBL: [Asn1AdbTable; 2] = [
    Asn1AdbTable {
        value: NID_X9_62_prime_field as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: OFFSET_FIELDID_P,
            field_name: c"p.prime".as_ptr(),
            item: ASN1_INTEGER_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_X9_62_characteristic_two_field as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: OFFSET_FIELDID_P,
            field_name: c"p.char_two".as_ptr(),
            item: x9_62_characteristic_two_it as *mut c_void,
        },
    },
];

/// `X9_62_FIELDID_adb` — the `ASN1_ADB_END` accessor at `:133`. Selector `fieldType` at offset 0.
static FIELDID_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: OFFSET_FIELDID_TYPE,
    adb_cb: None,
    tbl: FIELDID_ADBTBL.as_ptr(),
    tblcount: 2,
    default_tt: ptr::addr_of!(FIELDID_DEF_TT),
    null_tt: ptr::null(),
});

/// The `fieldID_adb` accessor the `ADB` template stores.
fn x9_62_fieldid_adb() -> *const c_void {
    ptr::addr_of!(FIELDID_ADB.0).cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// The items and their accessors
// ---------------------------------------------------------------------------------------------

/// `X9_62_PENTANOMIAL_seq_tt` — `ASN1_SEQUENCE(X9_62_PENTANOMIAL)` at `crypto/ec/ec_asn1.c:102-106`.
static X9_62_PENTANOMIAL_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_PENTA_K1,
        field_name: c"k1".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_PENTA_K2,
        field_name: c"k2".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_PENTA_K3,
        field_name: c"k3".as_ptr(),
        item: INT32_it as *mut c_void,
    },
];

/// The `X9_62_PENTANOMIAL` item accessor — private, as `static_ASN1_SEQUENCE_END` makes it.
fn x9_62_pentanomial_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: X9_62_PENTANOMIAL_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::null(),
        size: PENTA_SIZE,
        sname: c"X9_62_PENTANOMIAL".as_ptr(),
    };
    &IT
}

/// `X9_62_CHARACTERISTIC_TWO_seq_tt` — `ASN1_SEQUENCE(X9_62_CHARACTERISTIC_TWO)` at `:119-123`.
/// The third template is the `ASN1_ADB_OBJECT` at `:122`: `tag` is -1 and `offset` 0 as the macro
/// spells it, and the selector's offset lives in [`CHAR_TWO_ADB`].
static X9_62_CHARACTERISTIC_TWO_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_CHAR_TWO_M,
        field_name: c"m".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_CHAR_TWO_TYPE,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"X9_62_CHARACTERISTIC_TWO".as_ptr(),
        item: x9_62_characteristic_two_adb as *mut c_void,
    },
];

/// The `X9_62_CHARACTERISTIC_TWO` item accessor — private.
fn x9_62_characteristic_two_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: X9_62_CHARACTERISTIC_TWO_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::null(),
        size: CHAR_TWO_SIZE,
        sname: c"X9_62_CHARACTERISTIC_TWO".as_ptr(),
    };
    &IT
}

/// `X9_62_FIELDID_seq_tt` — `ASN1_SEQUENCE(X9_62_FIELDID)` at `:135-138`.
static X9_62_FIELDID_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_FIELDID_TYPE,
        field_name: c"fieldType".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"X9_62_FIELDID".as_ptr(),
        item: x9_62_fieldid_adb as *mut c_void,
    },
];

/// The `X9_62_FIELDID` item accessor — private.
fn x9_62_fieldid_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: X9_62_FIELDID_SEQ_TT.as_ptr(),
        tcount: 2,
        funcs: ptr::null(),
        size: FIELDID_SIZE,
        sname: c"X9_62_FIELDID".as_ptr(),
    };
    &IT
}

/// `X9_62_CURVE_seq_tt` — `ASN1_SEQUENCE(X9_62_CURVE)` at `:140-141`: `a`, `b` and the optional
/// `seed`.
static X9_62_CURVE_SEQ_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_CURVE_A,
        field_name: c"a".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_CURVE_B,
        field_name: c"b".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: OFFSET_CURVE_SEED,
        field_name: c"seed".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// The `X9_62_CURVE` item accessor — private.
fn x9_62_curve_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: X9_62_CURVE_SEQ_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::null(),
        size: CURVE_SIZE,
        sname: c"X9_62_CURVE".as_ptr(),
    };
    &IT
}

/// `ECPARAMETERS_seq_tt` — `ASN1_SEQUENCE(ECPARAMETERS)` at `:143-144`. `cofactor` is OPTIONAL.
static ECPARAMETERS_SEQ_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_EP_VERSION,
        field_name: c"version".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_EP_FIELDID,
        field_name: c"fieldID".as_ptr(),
        item: x9_62_fieldid_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_EP_CURVE,
        field_name: c"curve".as_ptr(),
        item: x9_62_curve_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_EP_BASE,
        field_name: c"base".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_EP_ORDER,
        field_name: c"order".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: OFFSET_EP_COFACTOR,
        field_name: c"cofactor".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *ECPARAMETERS_it(void)` — `include/openssl/ec.h:911`, defined by the
/// non-static `ASN1_SEQUENCE_END(ECPARAMETERS)` at `crypto/ec/ec_asn1.c:144`, which is why it is
/// an export where the other six items are private.
#[no_mangle]
pub extern "C" fn ECPARAMETERS_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: ECPARAMETERS_SEQ_TT.as_ptr(),
        tcount: 6,
        funcs: ptr::null(),
        size: EP_SIZE,
        sname: c"ECPARAMETERS".as_ptr(),
    };
    &IT
}

/// `ECPKPARAMETERS_ch_tt` — `ASN1_CHOICE(ECPKPARAMETERS)` at `crypto/ec/ec_asn1.c:149-153`. Every
/// alternative shares the `value` union at offset 8; the selector is `type` at offset 0.
static ECPKPARAMETERS_CH_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PKP_VALUE,
        field_name: c"value.named_curve".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PKP_VALUE,
        field_name: c"value.parameters".as_ptr(),
        item: ecparameters_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PKP_VALUE,
        field_name: c"value.implicitlyCA".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
];

/// `const ASN1_ITEM *ECPKPARAMETERS_it(void)` — `include/openssl/ec.h:909`, from
/// `ASN1_CHOICE_END(ECPKPARAMETERS)` at `crypto/ec/ec_asn1.c:153`. The prefix of the template's
/// `value.parameters` alternative is the accessor's own symbol, so this fn answers both the
/// public item and the one the CHOICE names; it is spelled once because a CHOICE alternative's
/// `item` is a pointer to the accessor fn and could not be a token-pasted duplicate.
#[no_mangle]
pub extern "C" fn ECPKPARAMETERS_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_CHOICE,
        utype: OFFSET_PKP_TYPE as c_long,
        templates: ECPKPARAMETERS_CH_TT.as_ptr(),
        tcount: 3,
        funcs: ptr::null(),
        size: PKP_SIZE,
        sname: c"ECPKPARAMETERS".as_ptr(),
    };
    &IT
}

/// The internal alias the CHOICE's `value.parameters` template points at. The authority spells it
/// `ECPARAMETERS` (the item the alternative is defined by) and `ASN1_ITEM_ref(ECPARAMETERS)` is
/// `&ECPARAMETERS_it`; a static template cannot hold a `#[no_mangle]` accessor's address without
/// naming it, so the item's own accessor is reused rather than a second one written.
fn ecparameters_it() -> *const Asn1Item {
    ECPARAMETERS_it()
}

/// `EC_PRIVATEKEY_seq_tt` — `ASN1_SEQUENCE(EC_PRIVATEKEY)` at `crypto/ec/ec_asn1.c:159-164`. The
/// `parameters` field is `ASN1_EXP_OPT(..., 0)` and `publicKey` is `ASN1_EXP_OPT(..., 1)`, so both
/// carry `ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL` — the authority's macro expands to
/// `ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT | ASN1_TFLG_OPTIONAL`, and the **context bit is what
/// makes the wrapper's class context-specific**, so the emitted tags are `0xa0`/`0xa1` and not
/// the universal `0x20`/`0x21`. It is written out in full here rather than reduced, exactly as
/// [`crate::rsa::asn1`]'s PSS/OAEP templates do.
static EC_PRIVATEKEY_SEQ_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: OFFSET_PK_VERSION,
        field_name: c"version".as_ptr(),
        item: INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PK_PRIVATE,
        field_name: c"privateKey".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: OFFSET_PK_PARAMS,
        field_name: c"parameters".as_ptr(),
        item: ECPKPARAMETERS_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: OFFSET_PK_PUBLIC,
        field_name: c"publicKey".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// The `EC_PRIVATEKEY` item accessor — private, as `static_ASN1_SEQUENCE_END` makes it.
fn ec_privatekey_it() -> *const Asn1Item {
    static IT: Asn1Item = Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates: EC_PRIVATEKEY_SEQ_TT.as_ptr(),
        tcount: 4,
        funcs: ptr::null(),
        size: PK_SIZE,
        sname: c"EC_PRIVATEKEY".as_ptr(),
    };
    &IT
}

// ---------------------------------------------------------------------------------------------
// The `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` accessors — `crypto/ec/ec_asn1.c:108-168`
// ---------------------------------------------------------------------------------------------

/// `X9_62_PENTANOMIAL *X9_62_PENTANOMIAL_new(void)` — `crypto/ec/ec_asn1.c:108-109`.
///
/// # Safety
///
/// None beyond the item layer's: the answer is a fresh object or NULL.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn X9_62_PENTANOMIAL_new() -> *mut X9_62Pentanomial {
    // SAFETY: `x9_62_pentanomial_it()` answers a static item.
    unsafe { ASN1_item_new(x9_62_pentanomial_it()).cast::<X9_62Pentanomial>() }
}

/// `void X9_62_PENTANOMIAL_free(X9_62_PENTANOMIAL *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[allow(dead_code)]
// the item machinery frees a nested value through its own template, so this accessor has no in-crate reader (D347)
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn X9_62_PENTANOMIAL_free(a: *mut X9_62Pentanomial) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), x9_62_pentanomial_it()) }
}

/// `X9_62_CHARACTERISTIC_TWO *X9_62_CHARACTERISTIC_TWO_new(void)` — `crypto/ec/ec_asn1.c:125-126`.
///
/// # Safety
///
/// None beyond the item layer's.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn X9_62_CHARACTERISTIC_TWO_new() -> *mut X9_62CharacteristicTwo {
    // SAFETY: `x9_62_characteristic_two_it()` answers a static item.
    unsafe { ASN1_item_new(x9_62_characteristic_two_it()).cast::<X9_62CharacteristicTwo>() }
}

/// `void X9_62_CHARACTERISTIC_TWO_free(X9_62_CHARACTERISTIC_TWO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[allow(dead_code)]
// the item machinery frees a nested value through its own template, so this accessor has no in-crate reader (D347)
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn X9_62_CHARACTERISTIC_TWO_free(a: *mut X9_62CharacteristicTwo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), x9_62_characteristic_two_it()) }
}

/// `EC_PRIVATEKEY *EC_PRIVATEKEY_new(void)` — `crypto/ec/ec_asn1.c:166-168`.
///
/// # Safety
///
/// None beyond the item layer's.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn EC_PRIVATEKEY_new() -> *mut EcPrivateKey {
    // SAFETY: `ec_privatekey_it()` answers a static item.
    unsafe { ASN1_item_new(ec_privatekey_it()).cast::<EcPrivateKey>() }
}

/// `void EC_PRIVATEKEY_free(EC_PRIVATEKEY *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn EC_PRIVATEKEY_free(a: *mut EcPrivateKey) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), ec_privatekey_it()) }
}

/// `ECPARAMETERS *ECPARAMETERS_new(void)` — `include/openssl/ec.h:912`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)` at `crypto/ec/ec_asn1.c:146-147`.
#[no_mangle]
pub extern "C" fn ECPARAMETERS_new() -> *mut EcParameters {
    // SAFETY: `ECPARAMETERS_it()` answers a static item.
    unsafe { ASN1_item_new(ECPARAMETERS_it()).cast::<EcParameters>() }
}

/// `void ECPARAMETERS_free(ECPARAMETERS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ECPARAMETERS_free(a: *mut EcParameters) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), ECPARAMETERS_it()) }
}

/// `ECPKPARAMETERS *ECPKPARAMETERS_new(void)` — `include/openssl/ec.h:910`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(ECPKPARAMETERS)` at `crypto/ec/ec_asn1.c:155-157`.
#[no_mangle]
pub extern "C" fn ECPKPARAMETERS_new() -> *mut EcpkParameters {
    // SAFETY: `ECPKPARAMETERS_it()` answers a static item.
    unsafe { ASN1_item_new(ECPKPARAMETERS_it()).cast::<EcpkParameters>() }
}

/// `void ECPKPARAMETERS_free(ECPKPARAMETERS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ECPKPARAMETERS_free(a: *mut EcpkParameters) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast::<c_void>(), ECPKPARAMETERS_it()) }
}

/// `ECPKPARAMETERS *d2i_ECPKPARAMETERS(ECPKPARAMETERS **a, const unsigned char **in, long len)`
/// — the decoder `DECLARE_ASN1_FUNCTIONS(ECPKPARAMETERS)` generates at
/// `crypto/ec/ec_asn1.c:157`. Not an export: the name is in no installed header, so it is private
/// here as the authority's DSO version script hides it.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` is a readable cursor; `len` describes the input.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn d2i_ECPKPARAMETERS(
    a: *mut *mut EcpkParameters,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcpkParameters {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ECPKPARAMETERS_it()).cast::<EcpkParameters>() }
}

/// `int i2d_ECPKPARAMETERS(const ECPKPARAMETERS *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn i2d_ECPKPARAMETERS(a: *const EcpkParameters, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, ECPKPARAMETERS_it()) }
}

/// `EC_PRIVATEKEY *d2i_EC_PRIVATEKEY(EC_PRIVATEKEY **a, const unsigned char **in, long len)` —
/// `DECLARE_ASN1_ENCODE_FUNCTIONS_name(EC_PRIVATEKEY, EC_PRIVATEKEY)` at
/// `crypto/ec/ec_asn1.c:167`.
///
/// # Safety
///
/// As [`d2i_ECPKPARAMETERS`].
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn d2i_EC_PRIVATEKEY(
    a: *mut *mut EcPrivateKey,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcPrivateKey {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ec_privatekey_it()).cast::<EcPrivateKey>() }
}

/// `int i2d_EC_PRIVATEKEY(const EC_PRIVATEKEY *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// As [`i2d_ECPKPARAMETERS`].
#[allow(non_snake_case)] // the authority's own symbol name (D347)
unsafe fn i2d_EC_PRIVATEKEY(a: *const EcPrivateKey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ASN1_item_i2d(a.cast(), out, ec_privatekey_it()) }
}

// ---------------------------------------------------------------------------------------------
// The two file-local builders — `crypto/ec/ec_asn1.c:179-370`
// ---------------------------------------------------------------------------------------------

/// `int ec_asn1_group2fieldid(const EC_GROUP *group, X9_62_FIELDID *field)` —
/// `crypto/ec/ec_asn1.c:179-299`.
///
/// # Safety
///
/// `group` is a live group; `field` is a live `X9_62_FIELDID`, whose `field_type` and union arm
/// this writes. `OPENSSL_NO_EC2M` is absent from the admitted profile, so the
/// characteristic-two arm is the compiled one and the `OPENSSL_NO_EC2M` refusal is not present.
unsafe fn ec_asn1_group2fieldid(group: *const EcGroup, field: *mut X9_62Fieldid) -> c_int {
    if group.is_null() || field.is_null() {
        return 0;
    }
    let mut ok: c_int = 0;
    let mut tmp: *mut BigNum = ptr::null_mut();
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            ASN1_OBJECT_free((*field).field_type);
            ASN1_TYPE_free((*field).p.cast::<Asn1Type>());

            let nid = EC_GROUP_get_field_type(group);
            (*field).field_type = OBJ_nid2obj(nid);
            if (*field).field_type.is_null() {
                raise_site(&err_sites::EC_ASN1_194);
                break 'err;
            }

            if nid == NID_X9_62_prime_field {
                tmp = BN_new();
                if tmp.is_null() {
                    raise_site(&err_sites::EC_ASN1_200);
                    break 'err;
                }
                if EC_GROUP_get_curve(
                    group,
                    tmp,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ) == 0
                {
                    raise_site(&err_sites::EC_ASN1_205);
                    break 'err;
                }
                (*field).p = BN_to_ASN1_INTEGER(tmp, ptr::null_mut()).cast::<c_void>();
                if (*field).p.is_null() {
                    raise_site(&err_sites::EC_ASN1_211);
                    break 'err;
                }
            } else if nid == NID_X9_62_characteristic_two_field {
                let char_two = X9_62_CHARACTERISTIC_TWO_new();
                (*field).p = char_two.cast::<c_void>();
                if char_two.is_null() {
                    raise_site(&err_sites::EC_ASN1_229);
                    break 'err;
                }
                (*char_two).m = EC_GROUP_get_degree(group);

                let field_type = EC_GROUP_get_basis_type(group);
                if field_type == 0 {
                    raise_site(&err_sites::EC_ASN1_238);
                    break 'err;
                }
                (*char_two).type_ = OBJ_nid2obj(field_type);
                if (*char_two).type_.is_null() {
                    raise_site(&err_sites::EC_ASN1_243);
                    break 'err;
                }

                if field_type == NID_X9_62_tpBasis {
                    let mut k: c_uint = 0;
                    if EC_GROUP_get_trinomial_basis(group, &mut k) == 0 {
                        break 'err;
                    }
                    let tp = ASN1_INTEGER_new();
                    (*char_two).p = tp.cast::<c_void>();
                    if tp.is_null() {
                        raise_site(&err_sites::EC_ASN1_255);
                        break 'err;
                    }
                    if ASN1_INTEGER_set(tp, c_long::from(k)) == 0 {
                        raise_site(&err_sites::EC_ASN1_259);
                        break 'err;
                    }
                } else if field_type == NID_X9_62_ppBasis {
                    let mut k1: c_uint = 0;
                    let mut k2: c_uint = 0;
                    let mut k3: c_uint = 0;
                    if EC_GROUP_get_pentanomial_basis(group, &mut k1, &mut k2, &mut k3) == 0 {
                        break 'err;
                    }
                    let penta = X9_62_PENTANOMIAL_new();
                    (*char_two).p = penta.cast::<c_void>();
                    if penta.is_null() {
                        raise_site(&err_sites::EC_ASN1_270);
                        break 'err;
                    }
                    (*penta).k1 = k1 as c_int;
                    (*penta).k2 = k2 as c_int;
                    (*penta).k3 = k3 as c_int;
                } else {
                    // `field_type == NID_X9_62_onBasis`: the parameters are an ASN.1 NULL.
                    (*char_two).p = ASN1_NULL_new().cast::<c_void>();
                    if (*char_two).p.is_null() {
                        raise_site(&err_sites::EC_ASN1_283);
                        break 'err;
                    }
                }
            } else {
                raise_site(&err_sites::EC_ASN1_290);
                break 'err;
            }
            ok = 1;
        }
        BN_free(tmp);
    }
    ok
}

/// `int ec_asn1_group2curve(const EC_GROUP *group, X9_62_CURVE *curve)` —
/// `crypto/ec/ec_asn1.c:301-370`.
///
/// # Safety
///
/// `group` is a live group whose method has a `group_get_curve` column; `curve` is a live
/// `X9_62_CURVE` with non-null `a`/`b`.
unsafe fn ec_asn1_group2curve(group: *const EcGroup, curve: *mut X9_62Curve) -> c_int {
    if group.is_null()
        || curve.is_null()
        // SAFETY: the caller's contract makes `curve` a live pointer.
        || unsafe { (*curve).a.is_null() || (*curve).b.is_null() }
    {
        return 0;
    }
    let mut ok: c_int = 0;
    let tmp_1: *mut BigNum;
    let tmp_2: *mut BigNum;
    let mut a_buf: *mut c_uchar = ptr::null_mut();
    let mut b_buf: *mut c_uchar = ptr::null_mut();
    let len: c_int;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            tmp_1 = BN_new();
            tmp_2 = BN_new();
            if tmp_1.is_null() || tmp_2.is_null() {
                raise_site(&err_sites::EC_ASN1_312);
                break 'err;
            }
            if EC_GROUP_get_curve(group, ptr::null_mut(), tmp_1, tmp_2, ptr::null_mut()) == 0 {
                raise_site(&err_sites::EC_ASN1_318);
                break 'err;
            }

            // Per SEC 1 the coefficients are padded up to the field's octet width.
            len = (EC_GROUP_get_degree(group) + 7) / 8;
            a_buf = CRYPTO_malloc(len as usize, FILE, 328).cast::<c_uchar>();
            b_buf = CRYPTO_malloc(len as usize, FILE, 329).cast::<c_uchar>();
            if a_buf.is_null() || b_buf.is_null() {
                // The authority raises nothing on this arm; the outer caller does.
                break 'err;
            }
            if BN_bn2binpad(tmp_1, a_buf, len) < 0 || BN_bn2binpad(tmp_2, b_buf, len) < 0 {
                raise_site(&err_sites::EC_ASN1_333);
                break 'err;
            }
            if ASN1_OCTET_STRING_set((*curve).a, a_buf, len) == 0
                || ASN1_OCTET_STRING_set((*curve).b, b_buf, len) == 0
            {
                raise_site(&err_sites::EC_ASN1_340);
                break 'err;
            }

            if !(*group).seed.is_null() {
                if (*curve).seed.is_null() {
                    (*curve).seed = ASN1_BIT_STRING_new();
                    if (*curve).seed.is_null() {
                        raise_site(&err_sites::EC_ASN1_348);
                        break 'err;
                    }
                }
                set_bits_left((*curve).seed, 0);
                if ASN1_BIT_STRING_set((*curve).seed, (*group).seed, (*group).seed_len as c_int)
                    == 0
                {
                    raise_site(&err_sites::EC_ASN1_354);
                    break 'err;
                }
            } else {
                ASN1_BIT_STRING_free((*curve).seed);
                (*curve).seed = ptr::null_mut();
            }
            ok = 1;
        }
        CRYPTO_free(a_buf.cast(), FILE, 365);
        CRYPTO_free(b_buf.cast(), FILE, 366);
        BN_free(tmp_1);
        BN_free(tmp_2);
    }
    ok
}

// ---------------------------------------------------------------------------------------------
// The `ECPKParameters`/`ECParameters`/`EC_GROUP` entry points — `crypto/ec/ec_asn1.c:372-1119`
// ---------------------------------------------------------------------------------------------

/// `ECPARAMETERS *EC_GROUP_get_ecparameters(const EC_GROUP *group, ECPARAMETERS *params)` —
/// `crypto/ec/ec_asn1.c:372-456`. `include/openssl/ec.h:514`.
///
/// A NULL `params` allocates; a caller's is filled in place and is **not** freed on failure — the
/// `err` label frees only what this call allocated.
///
/// # Safety
///
/// `group` is a live group; `params` is NULL or a live `ECPARAMETERS`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_ecparameters(
    group: *const EcGroup,
    params: *mut EcParameters,
) -> *mut EcParameters {
    let len: usize;
    let ret: *mut EcParameters;
    let mut buffer: *mut c_uchar = ptr::null_mut();
    let mut orig: *mut Asn1String;
    let mut ok = false;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if params.is_null() {
                ret = ECPARAMETERS_new();
                if ret.is_null() {
                    raise_site(&err_sites::EC_ASN1_385);
                    break 'err;
                }
            } else {
                ret = params;
            }

            (*ret).version = 0x1;
            if ec_asn1_group2fieldid(group, (*ret).field_id) == 0 {
                raise_site(&err_sites::EC_ASN1_396);
                break 'err;
            }
            if ec_asn1_group2curve(group, (*ret).curve) == 0 {
                raise_site(&err_sites::EC_ASN1_402);
                break 'err;
            }

            let point = EC_GROUP_get0_generator(group);
            if point.is_null() {
                raise_site(&err_sites::EC_ASN1_408);
                break 'err;
            }
            let form = EC_GROUP_get_point_conversion_form(group);
            len = EC_POINT_point2buf(group, point, form, &mut buffer, ptr::null_mut());
            if len == 0 || len > c_int::MAX as usize {
                raise_site(&err_sites::EC_ASN1_416);
                break 'err;
            }
            if (*ret).base.is_null() {
                (*ret).base = ASN1_OCTET_STRING_new();
                if (*ret).base.is_null() {
                    CRYPTO_free(buffer.cast(), FILE, 420);
                    raise_site(&err_sites::EC_ASN1_421);
                    break 'err;
                }
            }
            ASN1_STRING_set0((*ret).base, buffer.cast(), len as c_int);

            let tmp = EC_GROUP_get0_order(group);
            if tmp.is_null() {
                raise_site(&err_sites::EC_ASN1_429);
                break 'err;
            }
            orig = (*ret).order;
            (*ret).order = BN_to_ASN1_INTEGER(tmp, orig);
            if (*ret).order.is_null() {
                (*ret).order = orig;
                raise_site(&err_sites::EC_ASN1_435);
                break 'err;
            }

            let tmp = EC_GROUP_get0_cofactor(group);
            if !tmp.is_null() {
                orig = (*ret).cofactor;
                (*ret).cofactor = BN_to_ASN1_INTEGER(tmp, orig);
                if (*ret).cofactor.is_null() {
                    (*ret).cofactor = orig;
                    raise_site(&err_sites::EC_ASN1_445);
                    break 'err;
                }
            }
            ok = true;
        }
        if ok {
            return ret;
        }
        if params.is_null() {
            ECPARAMETERS_free(ret);
        }
        ptr::null_mut()
    }
}

/// `ECPKPARAMETERS *EC_GROUP_get_ecpkparameters(const EC_GROUP *group, ECPKPARAMETERS *params)` —
/// `crypto/ec/ec_asn1.c:458-508`. `include/openssl/ec.h:530`.
///
/// # Safety
///
/// `group` is a live group; `params` is NULL or a live `ECPKPARAMETERS` whose selected arm this
/// call may release.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_ecpkparameters(
    group: *const EcGroup,
    params: *mut EcpkParameters,
) -> *mut EcpkParameters {
    let mut ok: c_int = 1;
    let mut ret: *mut EcpkParameters = params;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ret.is_null() {
            ret = ECPKPARAMETERS_new();
            if ret.is_null() {
                raise_site(&err_sites::EC_ASN1_466);
                return ptr::null_mut();
            }
        } else if (*ret).type_ == ECPKPARAMETERS_TYPE_NAMED {
            ASN1_OBJECT_free((*ret).value.cast::<Asn1Object>());
        } else if (*ret).type_ == ECPKPARAMETERS_TYPE_EXPLICIT && !(*ret).value.is_null() {
            ECPARAMETERS_free((*ret).value.cast::<EcParameters>());
        }

        if EC_GROUP_get_asn1_flag(group) == OPENSSL_EC_NAMED_CURVE {
            let tmp = EC_GROUP_get_curve_name(group);
            if tmp != 0 {
                let asn1obj = OBJ_nid2obj(tmp);
                if asn1obj.is_null() || OBJ_length(asn1obj) == 0 {
                    ASN1_OBJECT_free(asn1obj);
                    raise_site(&err_sites::EC_ASN1_487);
                    ok = 0;
                } else {
                    (*ret).type_ = ECPKPARAMETERS_TYPE_NAMED;
                    (*ret).value = asn1obj.cast::<c_void>();
                }
            } else {
                ok = 0;
            }
        } else {
            (*ret).type_ = ECPKPARAMETERS_TYPE_EXPLICIT;
            let p = EC_GROUP_get_ecparameters(group, ptr::null_mut());
            (*ret).value = p.cast::<c_void>();
            if p.is_null() {
                ok = 0;
            }
        }

        if ok == 0 {
            ECPKPARAMETERS_free(ret);
            return ptr::null_mut();
        }
        ret
    }
}

/// `EC_GROUP *EC_GROUP_new_from_ecparameters(const ECPARAMETERS *params)` —
/// `crypto/ec/ec_asn1.c:510-832`. `include/openssl/ec.h:508`.
///
/// # Safety
///
/// `params` is a live `ECPARAMETERS`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_from_ecparameters(
    params: *const EcParameters,
) -> *mut EcGroup {
    let mut ok: c_int = 0;
    let mut ret: *mut EcGroup = ptr::null_mut();
    let mut dup: *mut EcGroup = ptr::null_mut();
    let mut p: *mut BigNum = ptr::null_mut();
    let mut a: *mut BigNum = ptr::null_mut();
    let mut b: *mut BigNum = ptr::null_mut();
    let mut point: *mut EcPoint = ptr::null_mut();
    let field_bits: c_long;
    let curve_name: c_int;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if (*params).field_id.is_null()
                || (*(*params).field_id).field_type.is_null()
                || (*(*params).field_id).p.is_null()
            {
                raise_site(&err_sites::EC_ASN1_523);
                break 'err;
            }

            // SEC 1 fixes the coefficients' lengths; historical encodings did not, so any length
            // is accepted here for backwards compatibility.
            if (*params).curve.is_null()
                || (*(*params).curve).a.is_null()
                || (*(*(*params).curve).a).data.is_null()
                || (*(*params).curve).b.is_null()
                || (*(*(*params).curve).b).data.is_null()
            {
                raise_site(&err_sites::EC_ASN1_536);
                break 'err;
            }
            a = BN_bin2bn(
                (*(*(*params).curve).a).data,
                (*(*(*params).curve).a).length,
                ptr::null_mut(),
            );
            if a.is_null() {
                raise_site(&err_sites::EC_ASN1_541);
                break 'err;
            }
            b = BN_bin2bn(
                (*(*(*params).curve).b).data,
                (*(*(*params).curve).b).length,
                ptr::null_mut(),
            );
            if b.is_null() {
                raise_site(&err_sites::EC_ASN1_546);
                break 'err;
            }

            let field_nid = OBJ_obj2nid((*(*params).field_id).field_type);
            if field_nid == NID_X9_62_characteristic_two_field {
                let char_two = (*(*params).field_id).p.cast::<X9_62CharacteristicTwo>();
                field_bits = c_long::from((*char_two).m);
                if field_bits > c_long::from(OPENSSL_ECC_MAX_FIELD_BITS) {
                    raise_site(&err_sites::EC_ASN1_566);
                    break 'err;
                }
                p = BN_new();
                if p.is_null() {
                    raise_site(&err_sites::EC_ASN1_571);
                    break 'err;
                }
                let base = OBJ_obj2nid((*char_two).type_);
                if base == NID_X9_62_tpBasis {
                    if (*char_two).p.is_null() {
                        raise_site(&err_sites::EC_ASN1_582);
                        break 'err;
                    }
                    let tmp_long = ASN1_INTEGER_get((*char_two).p.cast::<Asn1String>());
                    if !(c_long::from((*char_two).m) > tmp_long && tmp_long > 0) {
                        raise_site(&err_sites::EC_ASN1_589);
                        break 'err;
                    }
                    if BN_set_bit(p, c_int::from((*char_two).m)) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, tmp_long as c_int) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, 0) == 0 {
                        break 'err;
                    }
                } else if base == NID_X9_62_ppBasis {
                    let penta = (*char_two).p.cast::<X9_62Pentanomial>();
                    if penta.is_null() {
                        raise_site(&err_sites::EC_ASN1_605);
                        break 'err;
                    }
                    if !(c_long::from((*char_two).m) > c_long::from((*penta).k3)
                        && c_long::from((*penta).k3) > c_long::from((*penta).k2)
                        && c_long::from((*penta).k2) > c_long::from((*penta).k1)
                        && (*penta).k1 > 0)
                    {
                        raise_site(&err_sites::EC_ASN1_611);
                        break 'err;
                    }
                    if BN_set_bit(p, c_int::from((*char_two).m)) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, (*penta).k1) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, (*penta).k2) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, (*penta).k3) == 0 {
                        break 'err;
                    }
                    if BN_set_bit(p, 0) == 0 {
                        break 'err;
                    }
                } else if base == NID_X9_62_onBasis {
                    raise_site(&err_sites::EC_ASN1_627);
                    break 'err;
                } else {
                    raise_site(&err_sites::EC_ASN1_631);
                    break 'err;
                }
                ret = EC_GROUP_new_curve_GF2m(p, a, b, ptr::null_mut());
            } else if field_nid == NID_X9_62_prime_field {
                if (*(*params).field_id).p.is_null() {
                    raise_site(&err_sites::EC_ASN1_643);
                    break 'err;
                }
                p = ASN1_INTEGER_to_BN(
                    (*(*params).field_id).p.cast::<Asn1String>(),
                    ptr::null_mut(),
                );
                if p.is_null() {
                    raise_site(&err_sites::EC_ASN1_648);
                    break 'err;
                }
                if BN_is_negative(p) != 0 || BN_is_zero(p) != 0 {
                    raise_site(&err_sites::EC_ASN1_653);
                    break 'err;
                }
                field_bits = c_long::from(BN_num_bits(p));
                if field_bits > c_long::from(OPENSSL_ECC_MAX_FIELD_BITS) {
                    raise_site(&err_sites::EC_ASN1_659);
                    break 'err;
                }
                ret = EC_GROUP_new_curve_GFp(p, a, b, ptr::null_mut());
            } else {
                raise_site(&err_sites::EC_ASN1_666);
                break 'err;
            }

            if ret.is_null() {
                raise_site(&err_sites::EC_ASN1_671);
                break 'err;
            }

            if !(*(*params).curve).seed.is_null() {
                // A zero-length seed is refused because the allocation below would choke on it.
                if (*(*(*params).curve).seed).length == 0 {
                    raise_site(&err_sites::EC_ASN1_684);
                    break 'err;
                }
                CRYPTO_free((*ret).seed.cast(), FILE, 687);
                (*ret).seed = CRYPTO_malloc((*(*(*params).curve).seed).length as usize, FILE, 688)
                    .cast::<c_uchar>();
                if (*ret).seed.is_null() {
                    break 'err;
                }
                ptr::copy_nonoverlapping(
                    (*(*(*params).curve).seed).data,
                    (*ret).seed,
                    (*(*(*params).curve).seed).length as usize,
                );
                (*ret).seed_len = (*(*(*params).curve).seed).length as usize;
            }

            if (*params).order.is_null()
                || (*params).base.is_null()
                || (*(*params).base).data.is_null()
                || (*(*params).base).length == 0
            {
                raise_site(&err_sites::EC_ASN1_699);
                break 'err;
            }

            point = EC_POINT_new(ret);
            if point.is_null() {
                break 'err;
            }

            EC_GROUP_set_point_conversion_form(ret, c_int::from((*(*(*params).base).data) & !0x01));

            if EC_POINT_oct2point(
                ret,
                point,
                (*(*params).base).data,
                (*(*params).base).length as usize,
                ptr::null_mut(),
            ) == 0
            {
                raise_site(&err_sites::EC_ASN1_712);
                break 'err;
            }

            if ASN1_INTEGER_to_BN((*params).order, a).is_null() {
                raise_site(&err_sites::EC_ASN1_718);
                break 'err;
            }
            if BN_is_negative(a) != 0 || BN_is_zero(a) != 0 {
                raise_site(&err_sites::EC_ASN1_722);
                break 'err;
            }
            if c_long::from(BN_num_bits(a)) > field_bits + 1 {
                // The Hasse bound.
                raise_site(&err_sites::EC_ASN1_726);
                break 'err;
            }

            if (*params).cofactor.is_null() {
                BN_free(b);
                b = ptr::null_mut();
            } else if ASN1_INTEGER_to_BN((*params).cofactor, b).is_null() {
                raise_site(&err_sites::EC_ASN1_735);
                break 'err;
            }
            if EC_GROUP_set_generator(ret, point, a, b) == 0 {
                raise_site(&err_sites::EC_ASN1_740);
                break 'err;
            }

            ctx = BN_CTX_new();
            if ctx.is_null() {
                raise_site(&err_sites::EC_ASN1_757);
                break 'err;
            }
            dup = EC_GROUP_dup(ret);
            if dup.is_null()
                || EC_GROUP_set_seed(dup, ptr::null(), 0) != 1
                || EC_GROUP_set_generator(dup, point, a, ptr::null_mut()) == 0
            {
                raise_site(&err_sites::EC_ASN1_763);
                break 'err;
            }
            curve_name = ossl_ec_curve_nid_from_params(dup, ctx);
            if curve_name != NID_undef {
                // The explicit parameters matched a built-in curve, so the specialized method is
                // used instead; the group still serializes as explicit by default.
                let named_group = EC_GROUP_new_by_curve_name(curve_name);
                if named_group.is_null() {
                    raise_site(&err_sites::EC_ASN1_788);
                    break 'err;
                }
                EC_GROUP_free(ret);
                ret = named_group;
                EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);
                if (*(*params).curve).seed.is_null() && EC_GROUP_set_seed(ret, ptr::null(), 0) != 1
                {
                    break 'err;
                }
            }
            ok = 1;
        }

        if ok == 0 {
            EC_GROUP_free(ret);
            ret = ptr::null_mut();
        }
        EC_GROUP_free(dup);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        ret
    }
}

/// `EC_GROUP *EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS *params)` —
/// `crypto/ec/ec_asn1.c:834-869`. `include/openssl/ec.h:524`.
///
/// # Safety
///
/// `params` is NULL or a live `ECPKPARAMETERS`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_from_ecpkparameters(
    params: *const EcpkParameters,
) -> *mut EcGroup {
    let ret: *mut EcGroup;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if params.is_null() {
            raise_site(&err_sites::EC_ASN1_840);
            return ptr::null_mut();
        }
        if (*params).type_ == ECPKPARAMETERS_TYPE_NAMED {
            let tmp = OBJ_obj2nid((*params).value.cast::<Asn1Object>());
            ret = EC_GROUP_new_by_curve_name(tmp);
            if ret.is_null() {
                raise_site(&err_sites::EC_ASN1_848);
                return ptr::null_mut();
            }
            EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_NAMED_CURVE);
        } else if (*params).type_ == ECPKPARAMETERS_TYPE_EXPLICIT {
            ret = EC_GROUP_new_from_ecparameters((*params).value.cast::<EcParameters>());
            if ret.is_null() {
                raise_site(&err_sites::EC_ASN1_856);
                return ptr::null_mut();
            }
            EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE);
        } else if (*params).type_ == ECPKPARAMETERS_TYPE_IMPLICIT {
            // Implicit parameters inherited from a CA are unsupported.
            return ptr::null_mut();
        } else {
            raise_site(&err_sites::EC_ASN1_864);
            return ptr::null_mut();
        }
        ret
    }
}

/// `EC_GROUP *d2i_ECPKParameters(EC_GROUP **a, const unsigned char **in, long len)` —
/// `crypto/ec/ec_asn1.c:873-900`. `include/openssl/ec.h:923`.
///
/// # Safety
///
/// `a` is NULL or a writable slot holding NULL or a live group; `in` is a readable cursor over at
/// least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECPKParameters(
    a: *mut *mut EcGroup,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut p: *const c_uchar = *in_;
        let params = d2i_ECPKPARAMETERS(ptr::null_mut(), &mut p, len);
        if params.is_null() {
            ECPKPARAMETERS_free(params);
            return ptr::null_mut();
        }
        let group = EC_GROUP_new_from_ecpkparameters(params);
        if group.is_null() {
            ECPKPARAMETERS_free(params);
            return ptr::null_mut();
        }
        if (*params).type_ == ECPKPARAMETERS_TYPE_EXPLICIT {
            (*group).decoded_from_explicit_params = 1;
        }
        if !a.is_null() {
            EC_GROUP_free(*a);
            *a = group;
        }
        ECPKPARAMETERS_free(params);
        *in_ = p;
        group
    }
}

/// `int i2d_ECPKParameters(const EC_GROUP *a, unsigned char **out)` — `crypto/ec/ec_asn1.c:902-917`.
/// `include/openssl/ec.h:924`.
///
/// # Safety
///
/// `a` is a live group; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECPKParameters(a: *const EcGroup, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let tmp = EC_GROUP_get_ecpkparameters(a, ptr::null_mut());
        if tmp.is_null() {
            raise_site(&err_sites::EC_ASN1_907);
            return 0;
        }
        let ret = i2d_ECPKPARAMETERS(tmp, out);
        if ret == 0 {
            raise_site(&err_sites::EC_ASN1_911);
            ECPKPARAMETERS_free(tmp);
            return 0;
        }
        ECPKPARAMETERS_free(tmp);
        ret
    }
}

/// `int i2d_ECParameters(const EC_KEY *a, unsigned char **out)` — `crypto/ec/ec_asn1.c:1076-1083`.
/// `include/openssl/ec.h:1232`.
///
/// # Safety
///
/// `a` is NULL or a live key; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECParameters(a: *const EcKey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if a.is_null() {
            raise_site(&err_sites::EC_ASN1_1079);
            return 0;
        }
        i2d_ECPKParameters((*a).group, out)
    }
}

/// `EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len)` —
/// `crypto/ec/ec_asn1.c:1085-1119`. `include/openssl/ec.h:1222`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in` is a readable cursor over at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECParameters(
    a: *mut *mut EcKey,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcKey {
    let ret: *mut EcKey;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if in_.is_null() || (*in_).is_null() {
            raise_site(&err_sites::EC_ASN1_1090);
            return ptr::null_mut();
        }
        if a.is_null() || (*a).is_null() {
            ret = EC_KEY_new();
            if ret.is_null() {
                raise_site(&err_sites::EC_ASN1_1096);
                return ptr::null_mut();
            }
        } else {
            ret = *a;
        }

        if d2i_ECPKParameters(&mut (*ret).group, in_, len).is_null() {
            if a.is_null() || *a != ret {
                EC_KEY_free(ret);
            } else {
                (*ret).dirty_cnt += 1;
            }
            return ptr::null_mut();
        }
        if EC_GROUP_get_curve_name((*ret).group) == NID_sm2 {
            EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE);
        }
        (*ret).dirty_cnt += 1;
        if !a.is_null() {
            *a = ret;
        }
        ret
    }
}

/// `EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len)` —
/// `crypto/ec/ec_asn1.c:921-1004`. `include/openssl/ec.h:1198`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in` is a readable cursor over at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_ECPrivateKey(
    a: *mut *mut EcKey,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcKey {
    let ret: *mut EcKey;
    // SAFETY: `in_` is a readable cursor per the contract.
    let mut p: *const c_uchar = unsafe { *in_ };
    // SAFETY: `p` is a live cursor and the first argument is the NULL slot the item layer accepts.
    let priv_key = unsafe { d2i_EC_PRIVATEKEY(ptr::null_mut(), &mut p, len) };
    if priv_key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if a.is_null() || (*a).is_null() {
                ret = EC_KEY_new();
                if ret.is_null() {
                    raise_site(&err_sites::EC_ASN1_932);
                    break 'err;
                }
            } else {
                ret = *a;
            }

            if !(*priv_key).parameters.is_null() {
                EC_GROUP_free((*ret).group);
                (*ret).group = EC_GROUP_new_from_ecpkparameters((*priv_key).parameters);
                if !(*ret).group.is_null()
                    && (*(*priv_key).parameters).type_ == ECPKPARAMETERS_TYPE_EXPLICIT
                {
                    (*(*ret).group).decoded_from_explicit_params = 1;
                }
            }
            if (*ret).group.is_null() {
                raise_site(&err_sites::EC_ASN1_947);
                break 'err;
            }

            (*ret).version = (*priv_key).version;
            if !(*priv_key).private_key.is_null() {
                let pkey = (*priv_key).private_key;
                if EC_KEY_oct2priv(
                    ret,
                    ASN1_STRING_get0_data(pkey),
                    ASN1_STRING_length(pkey) as usize,
                ) == 0
                {
                    break 'err;
                }
            } else {
                raise_site(&err_sites::EC_ASN1_960);
                break 'err;
            }

            if EC_GROUP_get_curve_name((*ret).group) == NID_sm2 {
                EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE);
            }

            EC_POINT_clear_free((*ret).pub_key);
            (*ret).pub_key = EC_POINT_new((*ret).group);
            if (*ret).pub_key.is_null() {
                raise_site(&err_sites::EC_ASN1_970);
                break 'err;
            }

            if !(*priv_key).public_key.is_null() {
                let pub_oct = ASN1_STRING_get0_data((*priv_key).public_key);
                let pub_oct_len = ASN1_STRING_length((*priv_key).public_key);
                if EC_KEY_oct2key(ret, pub_oct, pub_oct_len as usize, ptr::null_mut()) == 0 {
                    raise_site(&err_sites::EC_ASN1_981);
                    break 'err;
                }
            } else {
                let meth = (*(*ret).group).meth;
                match (*meth).keygenpub {
                    Some(keygenpub) => {
                        if keygenpub(ret) == 0 {
                            break 'err;
                        }
                    }
                    None => break 'err,
                }
                // Remember the original private-key-only encoding.
                (*ret).enc_flag |= EC_PKEY_NO_PUBKEY as c_uint;
            }

            if !a.is_null() {
                *a = ret;
            }
            EC_PRIVATEKEY_free(priv_key);
            *in_ = p;
            (*ret).dirty_cnt += 1;
            return ret;
        }

        if a.is_null() || *a != ret {
            EC_KEY_free(ret);
        }
        EC_PRIVATEKEY_free(priv_key);
        ptr::null_mut()
    }
}

/// `int i2d_ECPrivateKey(const EC_KEY *a, unsigned char **out)` — `crypto/ec/ec_asn1.c:1006-1074`.
/// `include/openssl/ec.h:1208`.
///
/// # Safety
///
/// `a` is NULL or a live key; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ECPrivateKey(a: *const EcKey, out: *mut *mut c_uchar) -> c_int {
    let mut ret: c_int = 0;
    let mut ok: c_int = 0;
    let mut priv_: *mut c_uchar = ptr::null_mut();
    let mut pub_: *mut c_uchar = ptr::null_mut();
    let mut privlen: usize = 0;
    let publen: usize;
    let mut priv_key: *mut EcPrivateKey = ptr::null_mut();
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if a.is_null()
                || (*a).group.is_null()
                || (((*a).enc_flag & EC_PKEY_NO_PUBKEY as c_uint) == 0 && (*a).pub_key.is_null())
            {
                raise_site(&err_sites::EC_ASN1_1015);
                break 'err;
            }

            priv_key = EC_PRIVATEKEY_new();
            if priv_key.is_null() {
                raise_site(&err_sites::EC_ASN1_1020);
                break 'err;
            }
            (*priv_key).version = (*a).version;

            privlen = EC_KEY_priv2buf(a, &mut priv_);
            if privlen == 0 || privlen > c_int::MAX as usize {
                raise_site(&err_sites::EC_ASN1_1029);
                break 'err;
            }
            ASN1_STRING_set0(
                (*priv_key).private_key,
                priv_.cast::<c_void>(),
                privlen as c_int,
            );
            priv_ = ptr::null_mut();

            if ((*a).enc_flag & EC_PKEY_NO_PARAMETERS as c_uint) == 0 {
                (*priv_key).parameters =
                    EC_GROUP_get_ecpkparameters((*a).group, (*priv_key).parameters);
                if (*priv_key).parameters.is_null() {
                    raise_site(&err_sites::EC_ASN1_1040);
                    break 'err;
                }
            }

            if ((*a).enc_flag & EC_PKEY_NO_PUBKEY as c_uint) == 0 {
                (*priv_key).public_key = ASN1_BIT_STRING_new();
                if (*priv_key).public_key.is_null() {
                    raise_site(&err_sites::EC_ASN1_1048);
                    break 'err;
                }
                publen = EC_KEY_key2buf(a, (*a).conv_form, &mut pub_, ptr::null_mut());
                if publen == 0 || publen > c_int::MAX as usize {
                    raise_site(&err_sites::EC_ASN1_1055);
                    break 'err;
                }
                set_bits_left((*priv_key).public_key, 0);
                ASN1_STRING_set0(
                    (*priv_key).public_key,
                    pub_.cast::<c_void>(),
                    publen as c_int,
                );
                pub_ = ptr::null_mut();
            }

            ret = i2d_EC_PRIVATEKEY(priv_key, out);
            if ret == 0 {
                raise_site(&err_sites::EC_ASN1_1065);
                break 'err;
            }
            ok = 1;
        }
        CRYPTO_clear_free(priv_.cast::<c_void>(), privlen, FILE, 1070);
        CRYPTO_free(pub_.cast::<c_void>(), FILE, 1071);
        EC_PRIVATEKEY_free(priv_key);
        if ok != 0 {
            ret
        } else {
            0
        }
    }
}

/// `EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len)` —
/// `crypto/ec/ec_asn1.c:1121-1140`. `include/openssl/ec.h:1247`.
///
/// # Safety
///
/// `a` points at a live key with a group; `in` is a readable cursor over at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn o2i_ECPublicKey(
    a: *mut *mut EcKey,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EcKey {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if a.is_null() || (*a).is_null() || (*(*a)).group.is_null() {
            // An EC_GROUP is needed to set the public key.
            raise_site(&err_sites::EC_ASN1_1129);
            return ptr::null_mut();
        }
        let ret = *a;
        if EC_KEY_oct2key(ret, *in_, len as usize, ptr::null_mut()) == 0 {
            raise_site(&err_sites::EC_ASN1_1135);
            return ptr::null_mut();
        }
        *in_ = (*in_).add(len as usize);
        ret
    }
}

/// `int i2o_ECPublicKey(const EC_KEY *a, unsigned char **out)` — `crypto/ec/ec_asn1.c:1142-1180`.
/// `include/openssl/ec.h:1258`.
///
/// # Safety
///
/// `a` is NULL or a live key; `out` is NULL or a writable cursor whose `*out` is NULL or writable
/// for the encoded length.
#[no_mangle]
pub unsafe extern "C" fn i2o_ECPublicKey(a: *const EcKey, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut new_buffer: c_int = 0;
        if a.is_null() || (*a).pub_key.is_null() {
            raise_site(&err_sites::EC_ASN1_1148);
            return 0;
        }
        let buf_len = EC_POINT_point2oct(
            (*a).group,
            (*a).pub_key,
            (*a).conv_form,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );
        if buf_len > c_int::MAX as usize {
            raise_site(&err_sites::EC_ASN1_1156);
            return 0;
        }
        if out.is_null() || buf_len == 0 {
            return buf_len as c_int;
        }
        if (*out).is_null() {
            let buf = CRYPTO_malloc(buf_len, FILE, 1164).cast::<c_uchar>();
            if buf.is_null() {
                return 0;
            }
            *out = buf;
            new_buffer = 1;
        }
        if EC_POINT_point2oct(
            (*a).group,
            (*a).pub_key,
            (*a).conv_form,
            *out,
            buf_len,
            ptr::null_mut(),
        ) == 0
        {
            raise_site(&err_sites::EC_ASN1_1170);
            if new_buffer != 0 {
                CRYPTO_free((*out).cast::<c_void>(), FILE, 1172);
                *out = ptr::null_mut();
            }
            return 0;
        }
        if new_buffer == 0 {
            *out = (*out).add(buf_len);
        }
        buf_len as c_int
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::lib::EC_GROUP_cmp;
    use crate::runtime::obj::NID_X9_62_prime256v1;
    use core::ffi::CStr;

    /// The six items this unit declares answer the authority's own names and `sizeof`s. `size` is
    /// what the interpreter allocates, so a wrong one is a heap overrun rather than a wrong value;
    /// the CHOICE's selector offset is what `get_choice_selector` reads.
    #[test]
    fn the_items_carry_the_authoritys_names_and_sizes() {
        let cases: [(*const Asn1Item, &str, c_long); 6] = [
            (ECPARAMETERS_it(), "ECPARAMETERS", 48),
            (ECPKPARAMETERS_it(), "ECPKPARAMETERS", 16),
            (x9_62_pentanomial_it(), "X9_62_PENTANOMIAL", 12),
            (
                x9_62_characteristic_two_it(),
                "X9_62_CHARACTERISTIC_TWO",
                24,
            ),
            (x9_62_fieldid_it(), "X9_62_FIELDID", 16),
            (x9_62_curve_it(), "X9_62_CURVE", 24),
        ];
        // SAFETY: the accessors answer `&'static` items; `sname` is a NUL-terminated static.
        unsafe {
            for (it, name, size) in cases {
                let it = &*it;
                assert_eq!(it.size, size, "{name}");
                assert_eq!(CStr::from_ptr(it.sname).to_bytes(), name.as_bytes());
            }
            // The CHOICE's `utype` is its selector offset, not a tag.
            assert_eq!((*ECPKPARAMETERS_it()).utype, 0);
            assert_eq!((*ECPKPARAMETERS_it()).itype, ASN1_ITYPE_CHOICE);
        }
    }

    /// `EC_GROUP_get_ecpkparameters` on a built-in named curve encodes the OID alone — a
    /// ten-octet `OBJECT IDENTIFIER` for P-256, a public constant and not a secret — and
    /// `d2i_ECPKParameters` rebuilds a group that `EC_GROUP_cmp` finds equal to the source. The
    /// cursor is left exactly at the end of the input.
    #[test]
    fn a_named_curves_parameters_are_the_oid_and_round_trip() {
        // SAFETY: every pointer below is either this test's own or checked before use.
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            let len = i2d_ECPKParameters(group, ptr::null_mut());
            assert_eq!(len, 10);
            let mut buf = vec![0u8; len as usize];
            let mut out = buf.as_mut_ptr();
            assert_eq!(i2d_ECPKParameters(group, &mut out), 10);
            assert_eq!(
                buf,
                [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
            );

            let mut p = buf.as_ptr();
            let back = d2i_ECPKParameters(ptr::null_mut(), &mut p, len as c_long);
            assert!(!back.is_null());
            assert_eq!(p, buf.as_ptr().add(len as usize));
            let ctx = BN_CTX_new();
            assert_eq!(EC_GROUP_cmp(group, back, ctx), 0);
            BN_CTX_free(ctx);
            EC_GROUP_free(back);
            EC_GROUP_free(group);
        }
    }

    /// The parameters family's public allocator and item accessor are reachable and consistent:
    /// a fresh `ECPARAMETERS` has its nested `X9_62_FIELDID`/`X9_62_CURVE` allocated by the item
    /// layer, which is what `ec_asn1_group2fieldid` writes through.
    #[test]
    fn a_fresh_ecparameters_has_its_nested_items() {
        // SAFETY: `ECPARAMETERS_new` answers a fresh object or NULL; the reads are of its fields.
        unsafe {
            let params = ECPARAMETERS_new();
            assert!(!params.is_null());
            assert!(!(*params).field_id.is_null());
            assert!(!(*params).curve.is_null());
            assert!(!(*params).base.is_null());
            assert!(!(*params).order.is_null());
            ECPARAMETERS_free(params);
        }
    }
}
