//! Phase 8.3 — OCB (`crypto/modes/ocb128.c`), the ten `CRYPTO_ocb128_*` exports.
//!
//! ## What is transcribed
//!
//! OCB's whole observable shape is here, including the two pieces the plan names:
//!
//! * the **L-table**: `L_* = E(K, 0^128)`, `L_$ = double(L_*)`, `L_0 = double(L_$)`, and
//!   `L_i = double(L_{i-1})`, where `double` is the OCB field doubling (left shift with the
//!   `0x87` reduction on the top bit). The table is grown lazily by `ocb_lookup_l`, which indexes
//!   it by `ntz(i)` — the number of trailing zero bits of the block counter — and reallocates it
//!   in place when the index is past `max_l_index`. It is the caller-invisible state the
//!   ciphertext and tag depend on.
//! * the **offset** chain for both AAD and data, the **checksum** over plaintext, and the
//!   `Offset_*`/`L_*` partial-block handling, so a message of unknown length must still be fed
//!   whole blocks first and at most one partial block last (a second partial block is not
//!   rejected — it is simply another call, and the authority's arithmetic does not forbid it;
//!   the court observes what it does).
//!
//! The `stream` acceleration is kept: when `ctx->stream` is non-NULL and the full-block count is
//! representable, the bulk encryption and decryption go through the caller's `ocb128_f` and the
//! per-block loop is skipped. This is **not** a host-selected dispatch like GCM's — the stream is
//! a caller-supplied pointer — so a probe can drive both arms with its own stream and compare
//! them; `RT-CIPHER` does exactly that.
//!
//! ## Allocation
//!
//! `_new`, `_init` and `_copy_ctx` allocate the context and its L-table through the crypto
//! allocator, so the context is opaque and is only ever obtained from [`CRYPTO_ocb128_new`] or
//! supplied as caller storage to [`CRYPTO_ocb128_copy_ctx`]. `cleanup` clears the table before
//! releasing it and then cleanses the context. The authority calls `OPENSSL_free` on `_new`'s
//! failure path and `OPENSSL_malloc`/`OPENSSL_malloc_array`/`OPENSSL_realloc_array` in the three
//! allocators; those are the same functions this crate exports as `CRYPTO_free`/`CRYPTO_malloc`
//! (the `OPENSSL_*` spellings are aliases of the `CRYPTO_*` ones for the default allocator), so
//! the crate calls the `CRYPTO_*` spellings and this note records the equivalence.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_void;
use core::ptr;

use crate::modes::{Block128F, Ocb128F};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_malloc_array, CRYPTO_memcmp,
    CRYPTO_realloc_array, OPENSSL_cleanse,
};

/// The translation-unit coordinates, as the allocator reports them.
const FILE: &core::ffi::CStr = c"crypto/modes/ocb128.c";
const LINE: core::ffi::c_int = 0;

/// `ocb128_context` — `include/crypto/modes.h:185-207`, flattened so the session block sits in
/// the same order and the whole struct has the same size. The type is opaque to every caller.
#[repr(C)]
pub struct OcbCtx {
    /// `block128_f encrypt, decrypt`.
    encrypt: Option<Block128F>,
    decrypt: Option<Block128F>,
    /// `void *keyenc, *keydec`.
    keyenc: *mut c_void,
    keydec: *mut c_void,
    /// `ocb128_f stream`.
    stream: Option<Ocb128F>,
    /// `size_t l_index, max_l_index`.
    l_index: usize,
    max_l_index: usize,
    /// `OCB_BLOCK l_star, l_dollar`.
    l_star: [u8; 16],
    l_dollar: [u8; 16],
    /// `OCB_BLOCK *l`.
    l: *mut [u8; 16],
    /// `sess.blocks_hashed, sess.blocks_processed`.
    blocks_hashed: u64,
    blocks_processed: u64,
    /// `sess.offset_aad, sum, offset, checksum`.
    offset_aad: [u8; 16],
    sum: [u8; 16],
    offset: [u8; 16],
    checksum: [u8; 16],
}

/// `static u32 ocb_ntz(u64 n)` — `crypto/modes/ocb128.c:20-37`.
fn ocb_ntz(mut n: u64) -> usize {
    let mut cnt = 0usize;
    while n & 1 == 0 {
        n >>= 1;
        cnt += 1;
    }
    cnt
}

/// `static void ocb_block_lshift(const unsigned char *in, size_t shift, unsigned char *out)` —
/// `crypto/modes/ocb128.c:42-53`. `shift` is in `0..=7`; the authority reads `in[i] >> (8 - shift)`
/// on a promoted `int`, so a zero shift contributes zero and the Rust widens to `u32` to match.
fn ocb_block_lshift(inp: &[u8], shift: usize, out: &mut [u8; 16]) {
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let next = ((inp[i] as u32) >> (8 - shift)) as u8;
        out[i] = ((inp[i] as u32) << shift) as u8 | carry;
        carry = next;
    }
}

/// `static void ocb_double(OCB_BLOCK *in, OCB_BLOCK *out)` — `crypto/modes/ocb128.c:58-73`.
fn ocb_double(inp: &[u8], out: &mut [u8; 16]) {
    let mask = if inp[0] & 0x80 != 0 { 0x87 } else { 0 };
    ocb_block_lshift(inp, 1, out);
    out[15] ^= mask;
}

/// `static void ocb_block_xor(...)` — `crypto/modes/ocb128.c:78-86`, byte for byte.
fn ocb_block_xor(in1: &[u8], in2: &[u8], len: usize, out: &mut [u8]) {
    for i in 0..len {
        out[i] = in1[i] ^ in2[i];
    }
}

/// The `ocb_block16_xor` macro — `include/crypto/modes.h:175-177`: XOR two blocks into `out`,
/// in place where the authority aliases `out` with an input.
fn xor16(out: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        out[i] ^= b[i];
    }
}

/// `static OCB_BLOCK *ocb_lookup_l(OCB128_CONTEXT *ctx, size_t idx)` —
/// `crypto/modes/ocb128.c:92-125`. Returns NULL only when the reallocation fails.
///
/// # Safety
/// `ctx` is a live OCB context whose `l` is NULL or a table from this allocator.
unsafe fn ocb_lookup_l(ctx: *mut OcbCtx, idx: usize) -> *mut [u8; 16] {
    // SAFETY: the caller's contract.
    unsafe {
        let mut l_index = (*ctx).l_index;

        if idx <= l_index {
            return (*ctx).l.add(idx);
        }

        if idx >= (*ctx).max_l_index {
            (*ctx).max_l_index += (idx - (*ctx).max_l_index + 4) & !3;
            let tmp =
                CRYPTO_realloc_array((*ctx).l.cast(), (*ctx).max_l_index, 16, FILE.as_ptr(), LINE);
            if tmp.is_null() {
                return ptr::null_mut();
            }
            (*ctx).l = tmp.cast();
        }
        while l_index < idx {
            let mut cur = [0u8; 16];
            cur.copy_from_slice(&*(*ctx).l.add(l_index));
            ocb_double(&cur, &mut *(*ctx).l.add(l_index + 1));
            l_index += 1;
        }
        (*ctx).l_index = l_index;

        (*ctx).l.add(idx)
    }
}

/// `OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec, block128_f encrypt,
/// block128_f decrypt, ocb128_f stream)` — `crypto/modes/ocb128.c:130-146`.
///
/// # Safety
/// `encrypt`/`decrypt` are the caller's live block functions and `keyenc`/`keydec` their
/// schedules; `stream` is NULL or the caller's own OCB stream.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_new(
    keyenc: *mut c_void,
    keydec: *mut c_void,
    encrypt: Block128F,
    decrypt: Block128F,
    stream: Option<Ocb128F>,
) -> *mut OcbCtx {
    // SAFETY: the caller's contract.
    unsafe {
        let octx =
            CRYPTO_malloc(core::mem::size_of::<OcbCtx>(), FILE.as_ptr(), LINE).cast::<OcbCtx>();
        if !octx.is_null() {
            if CRYPTO_ocb128_init(octx, keyenc, keydec, encrypt, decrypt, stream) != 0 {
                return octx;
            }
            CRYPTO_free(octx.cast(), FILE.as_ptr(), LINE);
        }
        ptr::null_mut()
    }
}

/// `int CRYPTO_ocb128_init(OCB128_CONTEXT *ctx, void *keyenc, void *keydec, block128_f encrypt,
/// block128_f decrypt, ocb128_f stream)` — `crypto/modes/ocb128.c:151-189`.
///
/// # Safety
/// `ctx` is live and writable; the block functions and schedules as [`CRYPTO_ocb128_new`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_init(
    ctx: *mut OcbCtx,
    keyenc: *mut c_void,
    keydec: *mut c_void,
    encrypt: Block128F,
    decrypt: Block128F,
    stream: Option<Ocb128F>,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract; the whole struct is this crate's own layout.
    unsafe {
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<OcbCtx>());
        (*ctx).l_index = 0;
        (*ctx).max_l_index = 5;
        let l = CRYPTO_malloc_array(5, 16, FILE.as_ptr(), LINE);
        if l.is_null() {
            return 0;
        }
        (*ctx).l = l.cast();

        (*ctx).encrypt = Some(encrypt);
        (*ctx).decrypt = Some(decrypt);
        (*ctx).stream = stream;
        (*ctx).keyenc = keyenc;
        (*ctx).keydec = keydec;

        /* L_* = ENCIPHER(K, zeros(128)) */
        encrypt((*ctx).l_star.as_ptr(), (*ctx).l_star.as_mut_ptr(), keyenc);

        /* L_$ = double(L_*), L_0 = double(L_$), L_i = double(L_{i-1}). */
        let mut star = [0u8; 16];
        star.copy_from_slice(&(*ctx).l_star);
        let mut dollar = [0u8; 16];
        ocb_double(&star, &mut dollar);
        (*ctx).l_dollar = dollar;
        let mut l0 = [0u8; 16];
        ocb_double(&dollar, &mut l0);
        *(*ctx).l = l0;
        for i in 0..4 {
            let mut cur = [0u8; 16];
            cur.copy_from_slice(&*(*ctx).l.add(i));
            ocb_double(&cur, &mut *(*ctx).l.add(i + 1));
        }
        (*ctx).l_index = 4;

        1
    }
}

/// `int CRYPTO_ocb128_copy_ctx(OCB128_CONTEXT *dest, OCB128_CONTEXT *src, void *keyenc,
/// void *keydec)` — `crypto/modes/ocb128.c:194-208`.
///
/// # Safety
/// `dest` is caller storage large enough for an `OcbCtx`; `src` is live; the key pointers are
/// NULL or live schedules owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_copy_ctx(
    dest: *mut OcbCtx,
    src: *mut OcbCtx,
    keyenc: *mut c_void,
    keydec: *mut c_void,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::copy_nonoverlapping(
            src.cast::<u8>(),
            dest.cast::<u8>(),
            core::mem::size_of::<OcbCtx>(),
        );
        if !keyenc.is_null() {
            (*dest).keyenc = keyenc;
        }
        if !keydec.is_null() {
            (*dest).keydec = keydec;
        }
        if !(*src).l.is_null() {
            let l = CRYPTO_malloc_array((*src).max_l_index, 16, FILE.as_ptr(), LINE);
            if l.is_null() {
                return 0;
            }
            (*dest).l = l.cast();
            ptr::copy_nonoverlapping(
                (*src).l.cast::<u8>(),
                (*dest).l.cast::<u8>(),
                ((*src).l_index + 1) * 16,
            );
        }
        1
    }
}

/// `int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv, size_t len,
/// size_t taglen)` — `crypto/modes/ocb128.c:213-257`.
///
/// # Safety
/// `ctx` is live and `iv` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_setiv(
    ctx: *mut OcbCtx,
    iv: *const u8,
    len: usize,
    taglen: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !(1..=15).contains(&len) || !(1..=16).contains(&taglen) {
            return -1;
        }

        /* Reset the session block. */
        (*ctx).blocks_hashed = 0;
        (*ctx).blocks_processed = 0;
        (*ctx).offset_aad = [0u8; 16];
        (*ctx).sum = [0u8; 16];
        (*ctx).offset = [0u8; 16];
        (*ctx).checksum = [0u8; 16];

        let mut nonce = [0u8; 16];
        nonce[0] = (((taglen * 8) % 128) << 1) as u8;
        ptr::copy_nonoverlapping(iv, nonce.as_mut_ptr().add(16 - len), len);
        nonce[15 - len] |= 1;

        let mut tmp = nonce;
        tmp[15] &= 0xc0;
        let mut ktop = [0u8; 16];
        if let Some(f) = (*ctx).encrypt {
            f(tmp.as_ptr(), ktop.as_mut_ptr(), (*ctx).keyenc);
        }

        let mut stretch = [0u8; 24];
        stretch[..16].copy_from_slice(&ktop);
        ocb_block_xor(&ktop, &ktop[1..], 8, &mut stretch[16..]);

        let bottom = (nonce[15] & 0x3f) as usize;
        let shift = bottom % 8;
        let mut offset = [0u8; 16];
        ocb_block_lshift(&stretch[bottom / 8..], shift, &mut offset);
        let mask = ((0xffu16 << (8 - shift)) & 0xff) as u8;
        let extra = (((stretch[bottom / 8 + 16] as u32) & (mask as u32)) >> (8 - shift)) as u8;
        offset[15] |= extra;
        (*ctx).offset = offset;

        1
    }
}

/// `int CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad, size_t len)` —
/// `crypto/modes/ocb128.c:263-318`.
///
/// # Safety
/// `ctx` is live and `aad` readable for `len` bytes (NULL is allowed when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_aad(
    ctx: *mut OcbCtx,
    aad: *const u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let num_blocks = len / 16;
        let all_num_blocks = num_blocks as u64 + (*ctx).blocks_hashed;

        let mut p = aad;
        let mut i = (*ctx).blocks_hashed + 1;
        while i <= all_num_blocks {
            let lookup = ocb_lookup_l(ctx, ocb_ntz(i));
            if lookup.is_null() {
                return 0;
            }
            let mut acc = (*ctx).offset_aad;
            xor16(&mut acc, &*lookup);
            (*ctx).offset_aad = acc;

            let mut tmp = [0u8; 16];
            ptr::copy_nonoverlapping(p, tmp.as_mut_ptr(), 16);
            p = p.add(16);

            let mut cipher_input = tmp;
            xor16(&mut cipher_input, &(*ctx).offset_aad);
            if let Some(f) = (*ctx).encrypt {
                f(
                    cipher_input.as_ptr(),
                    cipher_input.as_mut_ptr(),
                    (*ctx).keyenc,
                );
            }
            let mut sum = (*ctx).sum;
            xor16(&mut sum, &cipher_input);
            (*ctx).sum = sum;
            i += 1;
        }

        let last_len = len % 16;
        if last_len > 0 {
            let mut acc = (*ctx).offset_aad;
            let star = (*ctx).l_star;
            xor16(&mut acc, &star);
            (*ctx).offset_aad = acc;

            let mut tmp = [0u8; 16];
            ptr::copy_nonoverlapping(p, tmp.as_mut_ptr(), last_len);
            tmp[last_len] = 0x80;
            xor16(&mut tmp, &(*ctx).offset_aad);
            if let Some(f) = (*ctx).encrypt {
                f(tmp.as_ptr(), tmp.as_mut_ptr(), (*ctx).keyenc);
            }
            let mut sum = (*ctx).sum;
            xor16(&mut sum, &tmp);
            (*ctx).sum = sum;
        }

        (*ctx).blocks_hashed = all_num_blocks;
        1
    }
}

/// `int CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx, const unsigned char *in, unsigned char *out,
/// size_t len)` — `crypto/modes/ocb128.c:324-413`.
///
/// # Safety
/// `ctx` is live and `in`/`out` as the caller's contract requires for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_encrypt(
    ctx: *mut OcbCtx,
    input: *const u8,
    out: *mut u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let num_blocks = len / 16;
        let all_num_blocks = num_blocks as u64 + (*ctx).blocks_processed;

        let mut inp = input;
        let mut outp = out;

        if num_blocks != 0
            && all_num_blocks == all_num_blocks as usize as u64
            && (*ctx).stream.is_some()
        {
            let mut max_idx = 0usize;
            let mut top = all_num_blocks as usize;
            loop {
                top >>= 1;
                if top == 0 {
                    break;
                }
                max_idx += 1;
            }
            if ocb_lookup_l(ctx, max_idx).is_null() {
                return 0;
            }
            if let Some(f) = (*ctx).stream {
                f(
                    inp,
                    outp,
                    num_blocks,
                    (*ctx).keyenc.cast_const(),
                    (*ctx).blocks_processed as usize + 1,
                    (*ctx).offset.as_mut_ptr(),
                    (*ctx).l.cast::<[u8; 16]>().cast_const(),
                    (*ctx).checksum.as_mut_ptr(),
                );
            }
            let processed_bytes = num_blocks * 16;
            inp = inp.add(processed_bytes);
            outp = outp.add(processed_bytes);
        } else {
            let mut i = (*ctx).blocks_processed + 1;
            while i <= all_num_blocks {
                let lookup = ocb_lookup_l(ctx, ocb_ntz(i));
                if lookup.is_null() {
                    return 0;
                }
                let mut acc = (*ctx).offset;
                xor16(&mut acc, &*lookup);
                (*ctx).offset = acc;

                let mut tmp = [0u8; 16];
                ptr::copy_nonoverlapping(inp, tmp.as_mut_ptr(), 16);
                inp = inp.add(16);

                let mut cell = (*ctx).checksum;
                xor16(&mut cell, &tmp);
                (*ctx).checksum = cell;

                xor16(&mut tmp, &(*ctx).offset);
                if let Some(f) = (*ctx).encrypt {
                    f(tmp.as_ptr(), tmp.as_mut_ptr(), (*ctx).keyenc);
                }
                xor16(&mut tmp, &(*ctx).offset);

                ptr::copy_nonoverlapping(tmp.as_ptr(), outp, 16);
                outp = outp.add(16);
                i += 1;
            }
        }

        let last_len = len % 16;
        if last_len > 0 {
            let mut acc = (*ctx).offset;
            let star = (*ctx).l_star;
            xor16(&mut acc, &star);
            (*ctx).offset = acc;

            let mut pad = [0u8; 16];
            if let Some(f) = (*ctx).encrypt {
                f((*ctx).offset.as_ptr(), pad.as_mut_ptr(), (*ctx).keyenc);
            }

            ocb_block_xor(
                core::slice::from_raw_parts(inp, last_len),
                &pad,
                last_len,
                core::slice::from_raw_parts_mut(outp, last_len),
            );

            let mut cell = (*ctx).checksum;
            let mut star_block = [0u8; 16];
            star_block[..last_len].copy_from_slice(core::slice::from_raw_parts(inp, last_len));
            star_block[last_len] = 0x80;
            xor16(&mut cell, &star_block);
            (*ctx).checksum = cell;
        }

        (*ctx).blocks_processed = all_num_blocks;
        1
    }
}

/// `int CRYPTO_ocb128_decrypt(...)` — `crypto/modes/ocb128.c:419-508`.
///
/// # Safety
/// As [`CRYPTO_ocb128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_decrypt(
    ctx: *mut OcbCtx,
    input: *const u8,
    out: *mut u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let num_blocks = len / 16;
        let all_num_blocks = num_blocks as u64 + (*ctx).blocks_processed;

        let mut inp = input;
        let mut outp = out;

        if num_blocks != 0
            && all_num_blocks == all_num_blocks as usize as u64
            && (*ctx).stream.is_some()
        {
            let mut max_idx = 0usize;
            let mut top = all_num_blocks as usize;
            loop {
                top >>= 1;
                if top == 0 {
                    break;
                }
                max_idx += 1;
            }
            if ocb_lookup_l(ctx, max_idx).is_null() {
                return 0;
            }
            if let Some(f) = (*ctx).stream {
                f(
                    inp,
                    outp,
                    num_blocks,
                    (*ctx).keydec.cast_const(),
                    (*ctx).blocks_processed as usize + 1,
                    (*ctx).offset.as_mut_ptr(),
                    (*ctx).l.cast::<[u8; 16]>().cast_const(),
                    (*ctx).checksum.as_mut_ptr(),
                );
            }
            let processed_bytes = num_blocks * 16;
            inp = inp.add(processed_bytes);
            outp = outp.add(processed_bytes);
        } else {
            let mut i = (*ctx).blocks_processed + 1;
            while i <= all_num_blocks {
                let lookup = ocb_lookup_l(ctx, ocb_ntz(i));
                if lookup.is_null() {
                    return 0;
                }
                let mut acc = (*ctx).offset;
                xor16(&mut acc, &*lookup);
                (*ctx).offset = acc;

                let mut tmp = [0u8; 16];
                ptr::copy_nonoverlapping(inp, tmp.as_mut_ptr(), 16);
                inp = inp.add(16);

                xor16(&mut tmp, &(*ctx).offset);
                if let Some(f) = (*ctx).decrypt {
                    f(tmp.as_ptr(), tmp.as_mut_ptr(), (*ctx).keydec);
                }
                xor16(&mut tmp, &(*ctx).offset);

                let mut cell = (*ctx).checksum;
                xor16(&mut cell, &tmp);
                (*ctx).checksum = cell;

                ptr::copy_nonoverlapping(tmp.as_ptr(), outp, 16);
                outp = outp.add(16);
                i += 1;
            }
        }

        let last_len = len % 16;
        if last_len > 0 {
            let mut acc = (*ctx).offset;
            let star = (*ctx).l_star;
            xor16(&mut acc, &star);
            (*ctx).offset = acc;

            let mut pad = [0u8; 16];
            if let Some(f) = (*ctx).encrypt {
                f((*ctx).offset.as_ptr(), pad.as_mut_ptr(), (*ctx).keyenc);
            }

            ocb_block_xor(
                core::slice::from_raw_parts(inp, last_len),
                &pad,
                last_len,
                core::slice::from_raw_parts_mut(outp, last_len),
            );

            let mut cell = (*ctx).checksum;
            let mut star_block = [0u8; 16];
            star_block[..last_len].copy_from_slice(core::slice::from_raw_parts(outp, last_len));
            star_block[last_len] = 0x80;
            xor16(&mut cell, &star_block);
            (*ctx).checksum = cell;
        }

        (*ctx).blocks_processed = all_num_blocks;
        1
    }
}

/// `static int ocb_finish(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len, int write)` —
/// `crypto/modes/ocb128.c:510-533`. `write` selects `tag` (write, answer `1`) from `finish`
/// (compare, answer `CRYPTO_memcmp`'s result).
///
/// # Safety
/// `ctx` is live and `tag` writable (or readable) for `len` bytes.
unsafe fn ocb_finish(ctx: *mut OcbCtx, tag: *mut u8, len: usize, write: bool) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !(1..=16).contains(&len) {
            return -1;
        }

        let mut tmp = (*ctx).checksum;
        xor16(&mut tmp, &(*ctx).offset);
        let dollar = (*ctx).l_dollar;
        xor16(&mut tmp, &dollar);
        if let Some(f) = (*ctx).encrypt {
            f(tmp.as_ptr(), tmp.as_mut_ptr(), (*ctx).keyenc);
        }
        let sum = (*ctx).sum;
        xor16(&mut tmp, &sum);

        if write {
            ptr::copy_nonoverlapping(tmp.as_ptr(), tag, len);
            1
        } else {
            CRYPTO_memcmp(tmp.as_ptr().cast(), tag.cast(), len)
        }
    }
}

/// `int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag, size_t len)` —
/// `crypto/modes/ocb128.c:538-542`.
///
/// # Safety
/// `ctx` is live and `tag` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_finish(
    ctx: *mut OcbCtx,
    tag: *const u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe { ocb_finish(ctx, tag.cast_mut(), len, false) }
}

/// `int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len)` —
/// `crypto/modes/ocb128.c:547-550`.
///
/// # Safety
/// `ctx` is live and `tag` writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_tag(
    ctx: *mut OcbCtx,
    tag: *mut u8,
    len: usize,
) -> core::ffi::c_int {
    // SAFETY: the caller's contract.
    unsafe { ocb_finish(ctx, tag, len, true) }
}

/// `void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx)` — `crypto/modes/ocb128.c:555-561`.
///
/// # Safety
/// `ctx` is NULL or a live context from [`CRYPTO_ocb128_new`]/[`CRYPTO_ocb128_init`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ocb128_cleanup(ctx: *mut OcbCtx) {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() {
            CRYPTO_clear_free(
                (*ctx).l.cast(),
                (*ctx).max_l_index * 16,
                FILE.as_ptr(),
                LINE,
            );
            OPENSSL_cleanse(ctx.cast(), core::mem::size_of::<OcbCtx>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AesKey};
    use core::ffi::c_int;

    fn schedule(key: &[u8], bits: c_int) -> AesKey {
        let mut k = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits, &mut k), 0);
        }
        k
    }

    fn schedule_dec(key: &[u8], bits: c_int) -> AesKey {
        let mut k = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits, &mut k), 0);
        }
        k
    }

    // SAFETY: forwards its arguments to `AES_encrypt`.
    unsafe extern "C" fn aes_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the caller's contract.
        unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
    }

    // SAFETY: forwards its arguments to `AES_decrypt`.
    unsafe extern "C" fn aes_dec_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the caller's contract.
        unsafe { AES_decrypt(input, out, key.cast::<AesKey>()) }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
            .collect()
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 7253's first AES-128 vector (`evpciph_aes_ocb.txt:20`, the first block's `Tag`):
    /// empty AAD, empty message, so the tag is the whole answer.
    #[test]
    fn ocb_rfc7253_empty() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let iv = unhex("000102030405060708090a0b");
        // SAFETY: live locals and live schedules.
        unsafe {
            let ke = schedule(&key, 128);
            let kd = schedule_dec(&key, 128);
            let ctx = CRYPTO_ocb128_new(
                (&ke as *const AesKey).cast_mut().cast(),
                (&kd as *const AesKey).cast_mut().cast(),
                aes_block,
                aes_dec_block,
                None,
            );
            assert!(!ctx.is_null());
            assert_eq!(CRYPTO_ocb128_setiv(ctx, iv.as_ptr(), iv.len(), 16), 1);
            assert_eq!(
                CRYPTO_ocb128_encrypt(ctx, ptr::null(), ptr::null_mut(), 0),
                1
            );
            let mut tag = [0u8; 16];
            assert_eq!(CRYPTO_ocb128_tag(ctx, tag.as_mut_ptr(), 16), 1);
            assert_eq!(hex_of(&tag), "197b9c3c441d3c83eafb2bef633b9182");
            CRYPTO_ocb128_cleanup(ctx);
        }
    }

    /// RFC 7253's second AES-128 vector (`evpciph_aes_ocb.txt:28`/`:30`): AAD and a
    /// one-block message.
    #[test]
    fn ocb_rfc7253_aad_and_block() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let iv = unhex("000102030405060708090a0b");
        let aad = unhex("0001020304050607");
        let pt = unhex("0001020304050607");
        let want_ct = "92b657130a74b85a";
        let want_tag = "16dc76a46d47e1ead537209e8a96d14e";
        // SAFETY: live locals and live schedules.
        unsafe {
            let ke = schedule(&key, 128);
            let kd = schedule_dec(&key, 128);
            let ctx = CRYPTO_ocb128_new(
                (&ke as *const AesKey).cast_mut().cast(),
                (&kd as *const AesKey).cast_mut().cast(),
                aes_block,
                aes_dec_block,
                None,
            );
            assert!(!ctx.is_null());
            assert_eq!(CRYPTO_ocb128_setiv(ctx, iv.as_ptr(), iv.len(), 16), 1);
            assert_eq!(CRYPTO_ocb128_aad(ctx, aad.as_ptr(), aad.len()), 1);
            let mut ct = [0u8; 8];
            assert_eq!(
                CRYPTO_ocb128_encrypt(ctx, pt.as_ptr(), ct.as_mut_ptr(), pt.len()),
                1
            );
            assert_eq!(hex_of(&ct), want_ct);
            let mut tag = [0u8; 16];
            assert_eq!(CRYPTO_ocb128_tag(ctx, tag.as_mut_ptr(), 16), 1);
            assert_eq!(hex_of(&tag), want_tag);
            CRYPTO_ocb128_cleanup(ctx);

            // The decrypt direction rebuilds the same plaintext and accepts the tag.
            let ctx = CRYPTO_ocb128_new(
                (&ke as *const AesKey).cast_mut().cast(),
                (&kd as *const AesKey).cast_mut().cast(),
                aes_block,
                aes_dec_block,
                None,
            );
            assert_eq!(CRYPTO_ocb128_setiv(ctx, iv.as_ptr(), iv.len(), 16), 1);
            assert_eq!(CRYPTO_ocb128_aad(ctx, aad.as_ptr(), aad.len()), 1);
            let mut back = [0u8; 8];
            assert_eq!(
                CRYPTO_ocb128_decrypt(ctx, ct.as_ptr(), back.as_mut_ptr(), ct.len()),
                1
            );
            assert_eq!(hex_of(&back), hex_of(&pt));
            assert_eq!(CRYPTO_ocb128_finish(ctx, tag.as_ptr(), tag.len()), 0);
            let mut bad = tag;
            bad[0] ^= 1;
            assert_ne!(CRYPTO_ocb128_finish(ctx, bad.as_ptr(), bad.len()), 0);
            CRYPTO_ocb128_cleanup(ctx);
        }
    }
}
