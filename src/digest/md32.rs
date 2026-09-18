//! Phase 8.1a — `include/crypto/md32_common.h`: the 32-bit digest collector.
//!
//! Six of this stratum's constructions are the same machine over different compression
//! functions: MD4, MD5, RIPEMD-160, SHA-1 and the two SHA-2 widths all accumulate their
//! input in a 64-byte staging buffer, count it in two 32-bit words, and pad with a `0x80`,
//! zeros and a 64-bit *bit* length. The authority writes that machine **once**, as a header
//! of macros (`include/crypto/md32_common.h`) included five times with different `HASH_*`
//! definitions, so the five `X_Update`s are literally one body. This module is that body,
//! transcribed once, with a trait standing in for the five macro definitions.
//!
//! ## What the trait carries, and what it deliberately does not
//!
//! `HASH_LONG`, `HASH_CTX`, `HASH_CBLOCK`, `HASH_BLOCK_DATA_ORDER` and `HASH_MAKE_STRING` are
//! [`Md32`]'s methods and associated constant. `DATA_ORDER_IS_{BIG,LITTLE}_ENDIAN` is
//! [`Md32::LITTLE_ENDIAN`], because it decides two things a reader must not have to look up:
//! the byte order of the length field's two words, and the byte order of the digest.
//!
//! The one thing the trait adds is a byte view of the staging buffer. In C that is
//! `(unsigned char *)c->data` — the field is `HASH_LONG data[HASH_LBLOCK]` and the collector
//! copies *bytes* into it — and in Rust the same field is an array of `u32`, so the view is a
//! pointer. That is not an approximation of the layout: it is the layout, and the `const _`
//! assertions in each context's module pin the offsets the collector depends on.
//!
//! ## Three subtleties the transcription keeps, because all three are observable
//!
//! * **`HASH_UPDATE` with `len == 0` returns 1 *without touching the counters*.** A
//!   zero-length update is not an error and does not move the length, which is what lets a
//!   caller make `MD5_Update(&c, p, 0)` freely.
//! * **The low word's overflow *increments* the high word, and `len >> 29` is then added to
//!   it.** A transcription that computed the 64-bit length in one step would agree for every
//!   message shorter than 512 MiB and differ after it.
//! * **`HASH_FINAL` zeroes the staging buffer *before* it makes the digest string**, via
//!   `OPENSSL_cleanse(p, HASH_CBLOCK)`. So the context after a `Final` is not the context
//!   before it — the staging buffer is gone and `num` is 0 — and a second `Final` on the same
//!   context is a different call. Both are reproduced.
//!
//! ## The one place the loop form differs from the authority's text
//!
//! `sha1_block_data_order` in this profile compiles the fully unrolled arm, and the authority
//! also carries an `OPENSSL_SMALL_FOOTPRINT` arm of the same function — the same rounds in a
//! loop, which the project's own configure flag selects. The loop form is used here for all
//! three 32-bit constructions with a round table rather than an unrolled body, because it is
//! the *same arithmetic* and a differential court is what decides whether it is the same
//! function; `RT-DIGEST` observes every one of them, and `docs/DECISIONS.md` D198 records the
//! choice. An unrolled transcription would have been longer without being more faithful.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

/// `HASH_CBLOCK` — 64 bytes. Every construction that includes the collector stages in one
/// block of this size.
pub(crate) const MD32_CBLOCK: usize = 64;

/// What `include/crypto/md32_common.h` requires of a context, as one trait.
///
/// The methods are `HASH_*` macros there and are re-named here because a macro name is not a
/// type. Each one is implemented in the module of the construction it serves, beside the
/// context it reads, so a reader of `src/digest/md5.rs` sees all of MD5.
pub(crate) trait Md32: Sized {
    /// `DATA_ORDER_IS_LITTLE_ENDIAN` — the byte order of the length field and the digest.
    const LITTLE_ENDIAN: bool;

    /// `c->Nl`, `c->Nh` — the bit length, low word first.
    fn nl_nh(&self) -> (u32, u32);

    /// The setter for the pair above.
    fn set_nl_nh(&mut self, nl: u32, nh: u32);

    /// `c->num` — bytes held in the staging buffer.
    fn num(&self) -> u32;

    /// The setter for `num`.
    fn set_num(&mut self, num: u32);

    /// `(unsigned char *)c->data` — a byte view of the staging buffer.
    ///
    /// The pointer is valid for `MD32_CBLOCK` bytes and for as long as `self` is borrowed,
    /// which is what makes it a method rather than a field access.
    fn data_ptr(&mut self) -> *mut u8;

    /// `HASH_BLOCK_DATA_ORDER(c, p, n)` — the compression function.
    ///
    /// # Safety
    /// `data` must be readable for `num * MD32_CBLOCK` bytes.
    unsafe fn block(&mut self, data: *const u8, num: usize);

    /// `HASH_MAKE_STRING(c, md)` — the digest, in the construction's own byte order.
    ///
    /// It answers `c_int` because the one `HASH_MAKE_STRING` in the collector is not
    /// infallible: `crypto/sha/sha256.c`'s `switch` has a `default` arm that answers 0 for a
    /// `md_len` above the construction's maximum, and the macro's `return 0` returns from
    /// `HASH_FINAL`. Nothing in the public surface can set such a `md_len`, and the arm is
    /// still transcribed rather than dropped, because it is what the macro *is*.
    ///
    /// # Safety
    /// `md` must be writable for the construction's digest length.
    unsafe fn make_string(&self, md: *mut u8) -> c_int;
}

/// `HASH_UPDATE` — `include/crypto/md32_common.h:154-203`.
///
/// # Safety
/// `c` must be a live context and `data` readable for `len` bytes.
pub(crate) unsafe fn update<C: Md32>(c: *mut C, data: *const u8, len: usize) -> c_int {
    if len == 0 {
        return 1;
    }

    // SAFETY: `c` is live per the caller's contract.
    let (nl, old_nh) = unsafe { (*c).nl_nh() };
    let l = nl.wrapping_add((len as u32) << 3);
    let mut nh = old_nh;
    if l < nl {
        nh = nh.wrapping_add(1);
    }
    nh = nh.wrapping_add((len >> 29) as u32);
    // SAFETY: `c` is live.
    unsafe { (*c).set_nl_nh(l, nh) };

    // SAFETY: `c` is live.
    let mut n = unsafe { (*c).num() } as usize;
    let mut data = data;
    let mut len = len;

    if n != 0 {
        // SAFETY: `c` is live, so its staging buffer is valid for `MD32_CBLOCK` bytes.
        let p = unsafe { (*c).data_ptr() };
        if len >= MD32_CBLOCK || len + n >= MD32_CBLOCK {
            // SAFETY: `p` is valid for `MD32_CBLOCK` bytes from `n`; `data` is readable for
            // `MD32_CBLOCK - n`; the two regions are distinct because `p` is the context's.
            unsafe { ptr::copy_nonoverlapping(data, p.add(n), MD32_CBLOCK - n) };
            // SAFETY: the buffer holds a full block.
            unsafe { (*c).block(p, 1) };
            n = MD32_CBLOCK - n;
            // SAFETY: the caller guaranteed `len` readable bytes and `n <= len` here.
            data = unsafe { data.add(n) };
            len -= n;
            // SAFETY: `c` is live.
            unsafe { (*c).set_num(0) };
            // The authority's `memset(p, 0, HASH_CBLOCK)` — keep the buffer zeroed, which is
            // why `MD5_Init`'s own `memset` is not the only zeroing in the machine.
            // SAFETY: `p` is valid for `MD32_CBLOCK` bytes.
            unsafe { ptr::write_bytes(p, 0, MD32_CBLOCK) };
        } else {
            // SAFETY: the two regions are distinct and the copy is in bounds.
            unsafe { ptr::copy_nonoverlapping(data, p.add(n), len) };
            // SAFETY: `c` is live.
            unsafe { (*c).set_num((n + len) as u32) };
            return 1;
        }
    }

    n = len / MD32_CBLOCK;
    if n > 0 {
        // SAFETY: `data` is readable for `n * MD32_CBLOCK` bytes, which is `<= len`.
        unsafe { (*c).block(data, n) };
        let advance = n * MD32_CBLOCK;
        // SAFETY: as above; the block function read exactly this many bytes.
        data = unsafe { data.add(advance) };
        len -= advance;
    }

    if len != 0 {
        // SAFETY: `c` is live.
        let p = unsafe { (*c).data_ptr() };
        // SAFETY: `c` is live.
        unsafe { (*c).set_num(len as u32) };
        // SAFETY: `len < MD32_CBLOCK` here and `data` is readable for `len`.
        unsafe { ptr::copy_nonoverlapping(data, p, len) };
    }
    1
}

/// `HASH_TRANSFORM` — `include/crypto/md32_common.h:205-208`.
///
/// One block, straight through, with **no** length accounting and no `num` change: the
/// authority's `Transform` is a compression of the caller's 64 bytes and nothing else. A
/// caller that transforms a short buffer is reading past it, which is the authority's
/// contract too; `RT-DIGEST` drives it with a full block and with a longer-than-block buffer
/// rather than with a short one.
///
/// # Safety
/// `c` must be a live context and `data` readable for one block (`MD32_CBLOCK` bytes).
pub(crate) unsafe fn transform<C: Md32>(c: *mut C, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { (*c).block(data, 1) };
}

/// `HASH_FINAL` — `include/crypto/md32_common.h:210-241`.
///
/// # Safety
/// `c` must be a live context and `md` writable for the construction's digest length.
pub(crate) unsafe fn finalize<C: Md32>(md: *mut u8, c: *mut C) -> c_int {
    // SAFETY: `c` is live, so the staging buffer is valid for `MD32_CBLOCK` bytes.
    let p = unsafe { (*c).data_ptr() };
    // SAFETY: `c` is live.
    let mut n = unsafe { (*c).num() } as usize;

    // "there is always room for one": `num < MD32_CBLOCK` on every path that reaches Final.
    // SAFETY: `n < MD32_CBLOCK`.
    unsafe { *p.add(n) = 0x80 };
    n += 1;

    if n > MD32_CBLOCK - 8 {
        // SAFETY: `n <= MD32_CBLOCK`, so the range is within the buffer.
        unsafe { ptr::write_bytes(p.add(n), 0, MD32_CBLOCK - n) };
        n = 0;
        // SAFETY: the buffer holds a full block.
        unsafe { (*c).block(p, 1) };
    }
    // SAFETY: `n <= MD32_CBLOCK - 8` here, so the range is within the buffer.
    unsafe { ptr::write_bytes(p.add(n), 0, MD32_CBLOCK - 8 - n) };

    // SAFETY: `c` is live.
    let (nl, nh) = unsafe { (*c).nl_nh() };
    // SAFETY: the length field is the last eight bytes of the block.
    let q = unsafe { p.add(MD32_CBLOCK - 8) };
    if C::LITTLE_ENDIAN {
        store_word(q, nl, true);
        // SAFETY: `q` is valid for eight bytes.
        store_word(unsafe { q.add(4) }, nh, true);
    } else {
        store_word(q, nh, false);
        // SAFETY: as above.
        store_word(unsafe { q.add(4) }, nl, false);
    }

    // SAFETY: `p` is the start of the staging buffer here (`n` was reset if it advanced) and
    // the block is the one just filled.
    unsafe { (*c).block(p, 1) };
    // SAFETY: `c` is live.
    unsafe { (*c).set_num(0) };
    // `OPENSSL_cleanse(p, HASH_CBLOCK)`.
    // SAFETY: `p` is valid for `MD32_CBLOCK` bytes.
    unsafe { ptr::write_bytes(p, 0, MD32_CBLOCK) };

    // SAFETY: the caller guaranteed `md` writable for the digest length.
    unsafe { (*c).make_string(md) }
}

/// `HOST_l2c(l, c)` — one 32-bit word, in the context's data order.
///
/// The two `HOST_l2c` definitions in the collector differ only in byte order, and the *order
/// of the two calls* in `HASH_FINAL` differs with them, so the pair together is "the 64-bit
/// bit length, big-endian for a big-endian construction and little-endian for a
/// little-endian one" — which is what MD5's and SHA-1's padding are.
pub(crate) fn store_word(c: *mut u8, l: u32, little_endian: bool) {
    let bytes = if little_endian {
        l.to_le_bytes()
    } else {
        l.to_be_bytes()
    };
    // SAFETY: the caller guarantees four writable bytes at `c`.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), c, 4) };
}

/// `HOST_c2l(c, l)` — one 32-bit word, in the context's data order.
///
/// # Safety
/// `c` must be readable for four bytes.
#[inline]
pub(crate) unsafe fn load_word(c: *const u8, little_endian: bool) -> u32 {
    let mut buf = [0u8; 4];
    // SAFETY: the caller guarantees four readable bytes.
    unsafe { ptr::copy_nonoverlapping(c, buf.as_mut_ptr(), 4) };
    if little_endian {
        u32::from_le_bytes(buf)
    } else {
        u32::from_be_bytes(buf)
    }
}
