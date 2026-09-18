//! Phase 8.2 — `crypto/rc4/`: RC4, the stream cipher.
//!
//! RC4 has no block and no IV: its whole state is a 256-byte permutation and two indices, and
//! one call transforms an arbitrary number of bytes. That shape is why it is its own module
//! rather than another `block128_f` user, and why `RC4_options` is a real observable rather
//! than decoration.
//!
//! The authority's `RC4_set_key` and `RC4` are the perlasm arm (`crypto/rc4/asm/rc4-x86_64.pl`
//! defines all three exports), so this is the portable KSA/PRGA and `RT-CIPHER` is what proves
//! it is *this* implementation's observable function. The key schedule is a byte permutation,
//! so it is observed as bytes.
//!
//! ## `RC4_options` and the CPU dispatch
//!
//! The perlasm's `RC4_options` selects among three strings by two `OPENSSL_ia32cap` bits:
//! `rc4(16x,int)` when bit 30 is set, `rc4(8x,char)` when bit 20 is set, and otherwise the
//! default `rc4(8x,int)`. Measured against the pinned authority on this profile's host, the
//! answer is the default, `rc4(8x,int)`; the dispatch itself is Phase 19's
//! (`docs/RELEASE_GATES.md`, "Performance / CPU dispatch"), so this arm answers the measured
//! string and the dispatch is recorded rather than silently assumed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint};

/// `RC4_INT` — `include/openssl/configuration.h:195`, `unsigned int` in this profile.
pub type Rc4Int = c_uint;

/// `RC4_KEY` — `include/openssl/rc4.h:29-32`: two indices and the 256-word state.
#[repr(C)]
pub struct Rc4Key {
    /// `RC4_INT x`.
    pub x: Rc4Int,
    /// `RC4_INT y`.
    pub y: Rc4Int,
    /// `RC4_INT data[256]`.
    pub data: [Rc4Int; 256],
}

const _: () = {
    assert!(core::mem::offset_of!(Rc4Key, y) == 4);
    assert!(core::mem::offset_of!(Rc4Key, data) == 8);
    assert!(core::mem::size_of::<Rc4Key>() == 1032);
};

/// `const char *RC4_options(void)` — the authority's perlasm object, measured as the default
/// arm `rc4(8x,int)` (see the module doc).
///
/// # Safety
/// None; the pointer is a `'static` C string.
#[no_mangle]
pub unsafe extern "C" fn RC4_options() -> *const c_char {
    c"rc4(8x,int)".as_ptr()
}

/// `void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data)` —
/// `crypto/rc4/rc4_skey.c:33-66`.
///
/// # Safety
/// `key` writable for `size_of::<Rc4Key>()`; `data` readable for `len` bytes and `len > 0`
/// (a zero length divides by zero in `id1 % len`, exactly as the authority does).
#[no_mangle]
pub unsafe extern "C" fn RC4_set_key(key: *mut Rc4Key, len: c_int, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe {
        (*key).x = 0;
        (*key).y = 0;
        let d = (*key).data.as_mut_ptr();

        for i in 0..256 {
            *d.add(i) = i as Rc4Int;
        }

        let mut id1: usize = 0;
        let mut id2: u32 = 0;
        for n in 0..256usize {
            let tmp = *d.add(n);
            id2 = (*data.add(id1) as u32 + tmp + id2) & 0xff;
            id1 += 1;
            if id1 == len as usize {
                id1 = 0;
            }
            *d.add(n) = *d.add(id2 as usize);
            *d.add(id2 as usize) = tmp;
        }
    }
}

/// `void RC4(RC4_KEY *key, size_t len, const unsigned char *indata, unsigned char *outdata)` —
/// `crypto/rc4/rc4_enc.c:26-90`.
///
/// # Safety
/// `key` a live schedule; `indata` readable and `outdata` writable for `len` bytes (they may
/// alias).
#[no_mangle]
pub unsafe extern "C" fn RC4(key: *mut Rc4Key, len: usize, indata: *const u8, outdata: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        let d = (*key).data.as_mut_ptr();
        let mut x = (*key).x;
        let mut y = (*key).y;

        for i in 0..len {
            x = (x + 1) & 0xff;
            let tx = *d.add(x as usize);
            y = (tx + y) & 0xff;
            let ty = *d.add(y as usize);
            *d.add(x as usize) = ty;
            *d.add(y as usize) = tx;
            let k = *d.add(((tx + ty) & 0xff) as usize);
            *outdata.add(i) = *indata.add(i) ^ (k as u8);
        }

        (*key).x = x;
        (*key).y = y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classic `Key`/`Plaintext` vector `BBF316E8D940AF0AD3` (the authority's own corpus
    /// carries the same construction at `evpciph_rc4.txt`).
    #[test]
    fn the_reference_keystream() {
        let mut k = Rc4Key {
            x: 0,
            y: 0,
            data: [0; 256],
        };
        let key = b"Key";
        let plain = b"Plaintext";
        let mut out = [0u8; 9];
        // SAFETY: live locals; every pointer is to a local of this test.
        unsafe {
            RC4_set_key(&mut k, 3, key.as_ptr());
            RC4(&mut k, plain.len(), plain.as_ptr(), out.as_mut_ptr());
        }
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "bbf316e8d940af0ad3");
    }

    #[test]
    fn the_options_string_is_the_measured_default() {
        // SAFETY: the returned pointer is a static C string.
        let s = unsafe { RC4_options() };
        // SAFETY: `s` points at that static C string, which is NUL-terminated.
        let text = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes();
        assert_eq!(text, b"rc4(8x,int)");
    }
}
