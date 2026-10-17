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

use crate::runtime::owned_buf::OwnedBuf;
use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::text::to_hex;
use crate::bn::ctx::BnCtx;
use crate::ec::lib::{EC_POINT_clear_free, EC_POINT_new};
use crate::ec::oct::{EC_POINT_oct2point, EC_POINT_point2buf};
use crate::ec::{EcGroup, EcPoint, PointConversionForm};
use crate::runtime::bio::sys::strlen;
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc};
use crate::runtime::str::OPENSSL_hexstr2buf_ex;

/// The translation unit every allocation and release below is attributed to, as the allocator
/// reports it. `ec_print.c` is a source-tree file, so its compiled `__FILE__` carries the admitted
/// build record's `../../src/openssl-3.6.4/` prefix — the spelling `src/packet.rs` and
/// `src/dh/ctrl.rs` use.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_print.c".as_ptr();

/// An owned seam block released with the authority's *cleansing* `CRYPTO_clear_free` over a recorded
/// length (`EC_POINT_hex2point`'s octet buffer), at its own `file`/`line`.
///
/// The block is a `OPENSSL_clear_free` whose length the decoder writes ([`Self::set_len`]), so the
/// release stays the authority's own cleansing call: `Drop` runs it over exactly the octets the
/// authority's `err:` tail cleansed.
struct OwnedClearBuf {
    ptr: *mut c_uchar,
    len: usize,
    file: *const c_char,
    line: c_int,
}

impl OwnedClearBuf {
    /// `CRYPTO_malloc(len, file, alloc_line)`, whose `Drop` cleanses and releases it at
    /// `file`/`release_line` (`OPENSSL_clear_free`), or `None` when the allocator answers NULL.
    fn new(
        len: usize,
        file: *const c_char,
        alloc_line: c_int,
        release_line: c_int,
    ) -> Option<OwnedClearBuf> {
        let ptr = CRYPTO_malloc(len, file, alloc_line).cast::<c_uchar>();
        if ptr.is_null() {
            return None;
        }
        Some(OwnedClearBuf {
            ptr,
            len,
            file,
            line: release_line,
        })
    }

    /// The writable start of the block.
    fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Record the length the decoder wrote, the extent the cleansing release must cover.
    fn set_len(&mut self, len: usize) {
        self.len = len;
    }
}

impl Drop for OwnedClearBuf {
    /// The block's single *cleansing* release, through the same seam.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released; `self.len` is the
        // extent the authority cleansed; the authority's own `CRYPTO_clear_free` accepts NULL.
        unsafe { CRYPTO_clear_free(self.ptr.cast::<c_void>(), self.len, self.file, self.line) };
    }
}

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

        // SAFETY: `EC_POINT_point2buf` answered this non-NULL `buf` as a `buf_len`-octet block the
        // crate's allocator produced in full, and this frame is its only owner; the authority
        // releases it with `OPENSSL_free` at line 39.
        // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL is the authority's own no-op `free(NULL)`.
        let buf = OwnedBuf::adopt_plain_nullable(buf, FILE, 39);

        // `OPENSSL_malloc(buf_len * 2 + 2)`, line 29.
        let Some(ret) = OwnedBuf::new(buf_len * 2 + 2, FILE, 29) else {
            // goto err: `buf` is released by its own `Drop` -- no `CRYPTO_free` written here.
            return ptr::null_mut();
        };
        let ret_ptr = ret.as_ptr().cast::<c_char>();

        for i in 0..buf_len {
            // SAFETY: `buf` holds `buf_len` octets and `ret` holds room for two digits per octet.
            let mut pair = [0u8; 2];
            to_hex(&mut pair, *buf.as_ptr().add(i));
            *ret_ptr.add(2 * i) = pair[0] as c_char;
            *ret_ptr.add(2 * i + 1) = pair[1] as c_char;
        }
        *ret_ptr.add(2 * buf_len) = 0;

        // err: (the fall-through path shares the label with the allocation failure above); `buf` is
        // released by its own `Drop`, and `ret` is the block the caller takes ownership of.
        ret.into_raw().cast::<c_char>()
    }
}

/// The authority's shared `err:` tail of `EC_POINT_hex2point`, written once so the three
/// `goto err` sites cannot drift: release the octet buffer over the length the decoder wrote (its
/// own `Drop` runs the authority's `OPENSSL_clear_free`, line 72), and, if the call did not
/// succeed, clear the point it allocated but not the caller's own.
///
/// # Safety
///
/// `pt` is NULL or a live point; `point` is the caller's point parameter. `oct_buf`, when `Some`,
/// is this frame's own octet block, released exactly once by this call.
unsafe fn hex2point_tail(
    ok: c_int,
    oct_buf: Option<OwnedClearBuf>,
    pt: *mut EcPoint,
    point: *mut EcPoint,
) -> *mut EcPoint {
    // `OPENSSL_clear_free(oct_buf, oct_buf_len)`, line 72: the block's own `Drop` runs it over the
    // recorded length.
    drop(oct_buf);
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
        let pt: *mut EcPoint;

        if group.is_null() || hex.is_null() {
            return ptr::null_mut();
        }

        if point.is_null() {
            pt = EC_POINT_new(group);
            if pt.is_null() {
                return hex2point_tail(ok, None, pt, point);
            }
        } else {
            pt = point;
        }

        // `len = strlen(hex) / 2`, line 62.
        // SAFETY: `hex` is NUL-terminated per the caller's contract.
        let len = strlen(hex) / 2;
        // `OPENSSL_malloc(len)`, line 63; the err tail's `OPENSSL_clear_free`, line 72.
        let Some(mut oct_buf) = OwnedClearBuf::new(len, FILE, 63, 72) else {
            // goto err: no block was allocated, so the authority's clear-free is a NULL release.
            return hex2point_tail(ok, None, pt, point);
        };

        let mut oct_buf_len = 0usize;
        let decoded = OPENSSL_hexstr2buf_ex(oct_buf.as_ptr(), len, &mut oct_buf_len, hex, 0);
        // The decoder records the length it wrote; the authority cleanses exactly that many octets.
        oct_buf.set_len(oct_buf_len);
        if decoded == 0 || EC_POINT_oct2point(group, pt, oct_buf.as_ptr(), oct_buf_len, ctx) == 0 {
            return hex2point_tail(ok, Some(oct_buf), pt, point);
        }
        ok = 1;

        hex2point_tail(ok, Some(oct_buf), pt, point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free;
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
