//! `crypto/ec/ec_print.c` — the two `EC_POINT` hex codecs, Phase 8.7.
//!
//! The unit is seventy-nine lines and defines **two exports and no internals**:
//! `EC_POINT_point2hex`, whose whole body is `EC_POINT_point2buf` followed by a two-digit
//! uppercase rendering of each octet, and `EC_POINT_hex2point`, whose whole body is the
//! inverse through `OPENSSL_hexstr2buf_ex` and `EC_POINT_oct2point`. Neither raises: the only
//! failures are allocation and the two called codecs' own refusals, and the authority's `err:`
//! label in the first function exists to free the octet buffer on the one path that can reach
//! it, not to raise.
//!
//! ## The whole unit lands, and it is the first of 8.7's residue a later EC slice can take
//!
//! `docs/DECISIONS.md` D344 measured these two names as same-stratum work: every callee they
//! reach — `EC_POINT_point2buf`, `EC_POINT_oct2point`, `EC_POINT_new`, `EC_POINT_clear_free`,
//! `OPENSSL_hexstr2buf_ex` and `ossl_to_hex` — is already in the crate, so nothing here waits
//! on another stratum. `EC_POINT_point2bn`/`EC_POINT_bn2point` are [`crate::ec::depr`]'s, the
//! `ec_deprecated.c` half of the same pair, and land in the same commit.
//!
//! ## `ossl_to_hex` is reached through [`crate::asn1::text`], and that is a substitution
//!
//! The authority's `ossl_to_hex` (`crypto/o_str.c:446`) writes two uppercase digits and
//! returns 2. The crate has that function twice — a private `to_hex` in
//! [`crate::runtime::str`] with exactly the authority's signature, and a `pub(crate)`
//! [`crate::asn1::text::to_hex`] over the same digit table that fills a two-byte array. This
//! module uses the latter, so the loop is written as two stores of the pair rather than one
//! pointer advance. The *bytes* are identical — same table, same case, same order — which is
//! what an observer of `EC_POINT_point2hex`'s answer can see.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use crate::asn1::text::to_hex;
use crate::bn::ctx::BnCtx;
use crate::ec::lib::{EC_POINT_clear_free, EC_POINT_new};
use crate::ec::oct::{EC_POINT_oct2point, EC_POINT_point2buf};
use crate::ec::{EcGroup, EcPoint, PointConversionForm};
use crate::runtime::bio::sys::strlen;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc};
use crate::runtime::str::OPENSSL_hexstr2buf_ex;

/// The translation unit every allocation and release below is attributed to, as the allocator
/// reports it. `ec_print.c` is a source-tree file, so its compiled `__FILE__` carries the admitted
/// build record's `../../src/openssl-3.6.4/` prefix — the spelling `src/packet.rs` and
/// `src/dh/ctrl.rs` use.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_print.c".as_ptr();

/// `char *EC_POINT_point2hex(const EC_GROUP *group, const EC_POINT *point,`
/// `point_conversion_form_t form, BN_CTX *ctx)` — `crypto/ec/ec_print.c:16-41`.
///
/// The return value must be freed with `OPENSSL_free`. A zero-length encoding — an empty
/// group, or a point the form cannot render — answers NULL, and so does a failed allocation of
/// the output; `buf` is released on both paths, which is what the authority's `err:` label
/// does.
///
/// # Safety
///
/// `group` and `point` are live and compatible; `ctx` is null or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_point2hex(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    ctx: *mut BnCtx,
) -> *mut c_char {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut buf: *mut c_uchar = ptr::null_mut();
        let buf_len = EC_POINT_point2buf(group, point, form, &mut buf, ctx);

        if buf_len == 0 {
            return ptr::null_mut();
        }

        // `OPENSSL_malloc(buf_len * 2 + 2)`, line 29.
        let ret = CRYPTO_malloc(buf_len * 2 + 2, FILE, 29).cast::<c_char>();
        if ret.is_null() {
            // goto err
            CRYPTO_free(buf.cast(), FILE, 39);
            return ret;
        }

        for i in 0..buf_len {
            // SAFETY: `buf` holds `buf_len` octets and `ret` holds room for two digits per octet.
            let mut pair = [0u8; 2];
            to_hex(&mut pair, *buf.add(i));
            *ret.add(2 * i) = pair[0] as c_char;
            *ret.add(2 * i + 1) = pair[1] as c_char;
        }
        *ret.add(2 * buf_len) = 0;

        // err: (the fall-through path shares the label with the allocation failure above)
        CRYPTO_free(buf.cast(), FILE, 39);
        ret
    }
}

/// The authority's shared `err:` tail of `EC_POINT_hex2point`, written once so the three
/// `goto err` sites cannot drift: release the octet buffer over the length the decoder wrote,
/// and, if the call did not succeed, clear the point it allocated but not the caller's own.
///
/// # Safety
///
/// `oct_buf` is NULL or a block of at least `oct_buf_len` bytes from this allocator that is not
/// owned elsewhere; `pt` is NULL or a live point; `point` is the caller's point parameter.
unsafe fn hex2point_tail(
    ok: c_int,
    oct_buf: *mut c_uchar,
    oct_buf_len: usize,
    pt: *mut EcPoint,
    point: *mut EcPoint,
) -> *mut EcPoint {
    // `OPENSSL_clear_free(oct_buf, oct_buf_len)`, line 72.
    // SAFETY: `oct_buf`/`oct_buf_len` are this frame's and the allocator's contract holds.
    unsafe { CRYPTO_clear_free(oct_buf.cast(), oct_buf_len, FILE, 72) };
    let mut pt = pt;
    if ok == 0 {
        if pt != point {
            // SAFETY: `pt` is this frame's own allocation, never the caller's point.
            unsafe { EC_POINT_clear_free(pt) };
        }
        pt = ptr::null_mut();
    }
    pt
}

/// `EC_POINT *EC_POINT_hex2point(const EC_GROUP *group, const char *hex, EC_POINT *point,`
/// `BN_CTX *ctx)` — `crypto/ec/ec_print.c:43-79`.
///
/// A NULL `point` allocates one; a non-NULL one is written in place and answered back. A NULL
/// `group` or `hex` answers NULL before anything is allocated, and every later failure clears
/// the point only when this call allocated it.
///
/// # Safety
///
/// `group` is null or live; `hex` is null or NUL-terminated; `point` is null or live and
/// compatible with `group`; `ctx` is null or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_hex2point(
    group: *const EcGroup,
    hex: *const c_char,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> *mut EcPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok = 0;
        let mut oct_buf: *mut c_uchar = ptr::null_mut();
        let mut oct_buf_len = 0usize;
        let pt: *mut EcPoint;

        if group.is_null() || hex.is_null() {
            return ptr::null_mut();
        }

        if point.is_null() {
            pt = EC_POINT_new(group);
            if pt.is_null() {
                return hex2point_tail(ok, oct_buf, oct_buf_len, pt, point);
            }
        } else {
            pt = point;
        }

        // `len = strlen(hex) / 2`, line 62.
        // SAFETY: `hex` is NUL-terminated per the caller's contract.
        let len = strlen(hex) / 2;
        // `OPENSSL_malloc(len)`, line 63.
        oct_buf = CRYPTO_malloc(len, FILE, 63).cast::<c_uchar>();
        if oct_buf.is_null() {
            return hex2point_tail(ok, oct_buf, oct_buf_len, pt, point);
        }

        if OPENSSL_hexstr2buf_ex(oct_buf, len, &mut oct_buf_len, hex, 0) == 0
            || EC_POINT_oct2point(group, pt, oct_buf, oct_buf_len, ctx) == 0
        {
            return hex2point_tail(ok, oct_buf, oct_buf_len, pt, point);
        }
        ok = 1;

        hex2point_tail(ok, oct_buf, oct_buf_len, pt, point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::ptr;

    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::lib::{
        EC_GROUP_free, EC_GROUP_get0_generator, EC_POINT_cmp, EC_POINT_copy, EC_POINT_free,
        EC_POINT_new,
    };
    use crate::runtime::obj::NID_X9_62_prime256v1;

    /// A P-256 group and its generator, the object both codecs below round-trip.
    unsafe fn group_and_point() -> (*mut EcGroup, *mut EcPoint) {
        // SAFETY: the two constructors and the copy are the crate's own.
        unsafe {
            let g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!g.is_null());
            let p = EC_POINT_new(g);
            assert!(!p.is_null());
            assert_eq!(EC_POINT_copy(p, EC_GROUP_get0_generator(g)), 1);
            (g, p)
        }
    }

    /// `EC_POINT_point2hex` and `EC_POINT_hex2point` are an inverse pair, and the hex string is
    /// two uppercase digits per octet of the uncompressed encoding.
    #[test]
    fn the_hex_codec_round_trips_and_is_uppercase() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let (g, p) = group_and_point();
            let hex = EC_POINT_point2hex(
                g,
                p,
                crate::ec::POINT_CONVERSION_UNCOMPRESSED,
                ptr::null_mut(),
            );
            assert!(!hex.is_null());
            let s = core::ffi::CStr::from_ptr(hex).to_bytes();
            assert_eq!(
                s.len(),
                130,
                "P-256 uncompressed is 65 octets -> 130 hex digits"
            );
            assert!(s
                .iter()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c)));

            let back = EC_POINT_hex2point(g, hex, ptr::null_mut(), ptr::null_mut());
            assert!(!back.is_null());
            assert_eq!(EC_POINT_cmp(g, p, back, ptr::null_mut()), 0);

            // A caller-supplied point is written in place and answered back.
            let inplace = EC_POINT_new(g);
            assert_eq!(
                EC_POINT_hex2point(g, hex, inplace, ptr::null_mut()),
                inplace
            );
            assert_eq!(EC_POINT_cmp(g, p, inplace, ptr::null_mut()), 0);

            EC_POINT_free(inplace);
            EC_POINT_free(back);
            CRYPTO_free(hex.cast::<c_void>(), FILE, 0);
            EC_POINT_free(p);
            EC_GROUP_free(g);
        }
    }

    /// The refusals `EC_POINT_hex2point` has: two before the decoder runs, three inside it, and a
    /// wrong-width octet string refused by `EC_POINT_oct2point`.
    #[test]
    fn the_hex_decoder_refuses_what_the_authority_refuses() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let (g, p) = group_and_point();
            assert!(EC_POINT_hex2point(
                ptr::null(),
                c"04".as_ptr(),
                ptr::null_mut(),
                ptr::null_mut()
            )
            .is_null());
            assert!(EC_POINT_hex2point(g, ptr::null(), ptr::null_mut(), ptr::null_mut()).is_null());
            // An odd digit count and a non-hex byte refuse in the decoder.
            assert!(
                EC_POINT_hex2point(g, c"04A".as_ptr(), ptr::null_mut(), ptr::null_mut()).is_null()
            );
            assert!(
                EC_POINT_hex2point(g, c"04ZZ".as_ptr(), ptr::null_mut(), ptr::null_mut()).is_null()
            );
            // A two-octet string whose first byte says "uncompressed" has the wrong width.
            assert!(
                EC_POINT_hex2point(g, c"04FF".as_ptr(), ptr::null_mut(), ptr::null_mut()).is_null()
            );
            // **A single `00` octet is the point-at-infinity encoding, not a refusal.**
            let inf = EC_POINT_hex2point(g, c"00".as_ptr(), ptr::null_mut(), ptr::null_mut());
            assert!(!inf.is_null());
            assert_eq!(crate::ec::lib::EC_POINT_is_at_infinity(g, inf), 1);
            EC_POINT_free(inf);
            EC_POINT_free(p);
            EC_GROUP_free(g);
        }
    }
}
