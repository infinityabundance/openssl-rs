//! Phase 8.2 — `crypto/mdc2/`: MDC-2, the hash built on DES.
//!
//! MDC2 is the one construction this stratum's row placed in 8.1 and D197 moved: its body is
//! the **low-level DES API** — `crypto/mdc2/mdc2dgst.c:94-100` calls `DES_set_odd_parity`,
//! `DES_set_key_unchecked` and `DES_encrypt1` on two lanes per block — so it cannot exist before
//! 8.2 lands DES, and it lives in the digest module because its observable is a digest.
//!
//! ## Its evidence shape is `CT-DIGEST`'s, not `CT-CIPHER`'s
//!
//! A hash built on a cipher is still a hash: the recorded observable is a digest over a message,
//! which is `CT-DIGEST`'s vector schema and its `index<TAB>algorithm<TAB>mode<TAB>message`
//! protocol. `CT-CIPHER`'s schema carries a key and an IV, which an MDC2 caller never sees, so
//! the vectors are emitted into `forensics/vectors/mdc2.json` and registered on `CT-DIGEST`
//! (D215), with `RT-DIGEST` carrying the differential arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::des::{DES_encrypt1, DES_set_key_unchecked, DES_set_odd_parity, DesKeySchedule};

/// `MDC2_BLOCK` — `include/openssl/mdc2.h:32`.
pub const MDC2_BLOCK: usize = 8;
/// `MDC2_DIGEST_LENGTH` — `include/openssl/mdc2.h:28`.
pub const MDC2_DIGEST_LENGTH: usize = 16;

/// `MDC2_CTX` — `include/openssl/mdc2.h:34-39`.
#[repr(C)]
pub struct Mdc2Ctx {
    /// `unsigned int num`.
    pub num: c_uint,
    /// `unsigned char data[MDC2_BLOCK]`.
    pub data: [u8; MDC2_BLOCK],
    /// `DES_cblock h`.
    pub h: [u8; 8],
    /// `DES_cblock hh`.
    pub hh: [u8; 8],
    /// `unsigned int pad_type` — either 1 or 2, default 1.
    pub pad_type: c_uint,
}

const _: () = {
    assert!(core::mem::offset_of!(Mdc2Ctx, data) == 4);
    assert!(core::mem::offset_of!(Mdc2Ctx, h) == 12);
    assert!(core::mem::offset_of!(Mdc2Ctx, hh) == 20);
    assert!(core::mem::offset_of!(Mdc2Ctx, pad_type) == 28);
    assert!(core::mem::size_of::<Mdc2Ctx>() == 32);
};

/// `c2l(c, l)` — `crypto/mdc2/mdc2dgst.c:24-27`, little-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn c2l(p: *const u8) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        (*p as c_uint)
            | ((*p.add(1) as c_uint) << 8)
            | ((*p.add(2) as c_uint) << 16)
            | ((*p.add(3) as c_uint) << 24)
    }
}

/// `l2c(l, c)` — `crypto/mdc2/mdc2dgst.c:30-33`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn l2c(v: c_uint, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = (v & 0xff) as u8;
        *p.add(1) = ((v >> 8) & 0xff) as u8;
        *p.add(2) = ((v >> 16) & 0xff) as u8;
        *p.add(3) = ((v >> 24) & 0xff) as u8;
    }
}

/// `mdc2_body` — `crypto/mdc2/mdc2dgst.c:77-114`.
///
/// # Safety
/// `c` a live context; `input` readable for `len` bytes, a multiple of eight.
unsafe fn mdc2_body(c: *mut Mdc2Ctx, input: *const u8, len: usize) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut k = DesKeySchedule {
            ks: [crate::des::DesKs { deslong: [0; 2] }; 16],
        };
        let mut i = 0;
        while i < len {
            let tin0 = c2l(input.add(i));
            let tin1 = c2l(input.add(i + 4));
            let mut d = [tin0, tin1];
            let mut dd = [tin0, tin1];

            (*c).h[0] = ((*c).h[0] & 0x9f) | 0x40;
            (*c).hh[0] = ((*c).hh[0] & 0x9f) | 0x20;

            DES_set_odd_parity(core::ptr::addr_of_mut!((*c).h));
            DES_set_key_unchecked(core::ptr::addr_of_mut!((*c).h), &mut k);
            DES_encrypt1(d.as_mut_ptr(), &mut k, 1);

            DES_set_odd_parity(core::ptr::addr_of_mut!((*c).hh));
            DES_set_key_unchecked(core::ptr::addr_of_mut!((*c).hh), &mut k);
            DES_encrypt1(dd.as_mut_ptr(), &mut k, 1);

            let ttin0 = tin0 ^ dd[0];
            let ttin1 = tin1 ^ dd[1];
            let tin0 = tin0 ^ d[0];
            let tin1 = tin1 ^ d[1];

            let p = (*c).h.as_mut_ptr();
            l2c(tin0, p);
            l2c(ttin1, p.add(4));
            let p = (*c).hh.as_mut_ptr();
            l2c(ttin0, p);
            l2c(tin1, p.add(4));

            i += 8;
        }
    }
}

/// `int MDC2_Init(MDC2_CTX *c)` — `crypto/mdc2/mdc2dgst.c:36-43`.
///
/// # Safety
/// `c` writable.
#[no_mangle]
pub unsafe extern "C" fn MDC2_Init(c: *mut Mdc2Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*c).num = 0;
        (*c).pad_type = 1;
        (*c).h = [0x52; MDC2_BLOCK];
        (*c).hh = [0x25; MDC2_BLOCK];
    }
    1
}

/// `int MDC2_Update(MDC2_CTX *c, const unsigned char *in, size_t len)` —
/// `crypto/mdc2/mdc2dgst.c:45-75`.
///
/// # Safety
/// `c` a live context; `in` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn MDC2_Update(c: *mut Mdc2Ctx, input: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut i = (*c).num as usize;
        let mut in_ = input;
        let mut len_ = len;

        if i != 0 {
            if len_ < MDC2_BLOCK - i {
                core::ptr::copy_nonoverlapping(in_, (*c).data.as_mut_ptr().add(i), len_);
                (*c).num += len_ as c_uint;
                return 1;
            }
            let j = MDC2_BLOCK - i;
            core::ptr::copy_nonoverlapping(in_, (*c).data.as_mut_ptr().add(i), j);
            len_ -= j;
            in_ = in_.add(j);
            (*c).num = 0;
            mdc2_body(c, (*c).data.as_ptr(), MDC2_BLOCK);
        }
        i = len_ & !(MDC2_BLOCK - 1);
        if i > 0 {
            mdc2_body(c, in_, i);
        }
        let j = len_ - i;
        if j > 0 {
            core::ptr::copy_nonoverlapping(in_.add(i), (*c).data.as_mut_ptr(), j);
            (*c).num = j as c_uint;
        }
    }
    1
}

/// `int MDC2_Final(unsigned char *md, MDC2_CTX *c)` — `crypto/mdc2/mdc2dgst.c:116-132`.
///
/// # Safety
/// `md` writable for sixteen bytes; `c` a live context.
#[no_mangle]
pub unsafe extern "C" fn MDC2_Final(md: *mut u8, c: *mut Mdc2Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut i = (*c).num as usize;
        let j = (*c).pad_type;
        if i > 0 || j == 2 {
            if j == 2 {
                (*c).data[i] = 0x80;
                i += 1;
            }
            for b in (*c).data.iter_mut().skip(i) {
                *b = 0;
            }
            mdc2_body(c, (*c).data.as_ptr(), MDC2_BLOCK);
        }
        core::ptr::copy_nonoverlapping((*c).h.as_ptr(), md, MDC2_BLOCK);
        core::ptr::copy_nonoverlapping((*c).hh.as_ptr(), md.add(MDC2_BLOCK), MDC2_BLOCK);
    }
    1
}

/// A process-global buffer for [`MDC2`], exactly as `crypto/mdc2/mdc2_one.c:22` keeps one.
static mut MDC2_ONESHOT_MD: [u8; MDC2_DIGEST_LENGTH] = [0; MDC2_DIGEST_LENGTH];

/// `unsigned char *MDC2(const unsigned char *d, size_t n, unsigned char *md)` —
/// `crypto/mdc2/mdc2_one.c:20-33`.
///
/// # Safety
/// `d` readable for `n` bytes; `md` writable for sixteen bytes or NULL. A NULL `md` returns the
/// shared static buffer, as in the authority.
#[no_mangle]
pub unsafe extern "C" fn MDC2(d: *const u8, n: usize, md: *mut u8) -> *mut u8 {
    // SAFETY: the caller's contract.
    unsafe {
        let md = if md.is_null() {
            core::ptr::addr_of_mut!(MDC2_ONESHOT_MD).cast::<u8>()
        } else {
            md
        };
        let mut c = Mdc2Ctx {
            num: 0,
            data: [0; MDC2_BLOCK],
            h: [0; 8],
            hh: [0; 8],
            pad_type: 0,
        };
        if MDC2_Init(&mut c) == 0 {
            return core::ptr::null_mut();
        }
        MDC2_Update(&mut c, d, n);
        MDC2_Final(md, &mut c);
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_vectors_match_both_padding_arms() {
        // `test/recipes/30-test_evp_data/evpmd_mdc2.txt`'s message: the default (`pad_type = 1`)
        // value and the `Padding = 2` value, both published in the pinned corpus.
        let msg = b"Now is the time for all ";
        let mut md = [0u8; MDC2_DIGEST_LENGTH];
        // SAFETY: live locals.
        unsafe { MDC2(msg.as_ptr(), msg.len(), md.as_mut_ptr()) };
        let hex: String = md.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "42e50cd224baceba760bdd2bd409281a");

        let mut c = Mdc2Ctx {
            num: 0,
            data: [0; MDC2_BLOCK],
            h: [0; 8],
            hh: [0; 8],
            pad_type: 2,
        };
        // SAFETY: live locals; `pad_type` is set after `Init` as the authority allows.
        unsafe {
            MDC2_Init(&mut c);
            c.pad_type = 2;
            MDC2_Update(&mut c, msg.as_ptr(), msg.len());
            MDC2_Final(md.as_mut_ptr(), &mut c);
        }
        let hex: String = md.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "2e4679b5add9ca7535d87afeab33bee2");
    }
}
