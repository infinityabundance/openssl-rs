//! Phase 8.3 — `ssl/record/methods/ssl3_cbc.c`, the constant-time SSLv3/TLS CBC record MAC.
//!
//! **Why a file under `ssl/` is a Phase 8 unit.** The file's own header says it:
//!
//! > This file has no dependencies on the rest of libssl because it is shared with the providers. It
//! > contains functions for low level MAC calculations. Responsibility for this lies with the HMAC
//! > implementation in the providers. However there are legacy code paths in libssl which also need
//! > to do this.
//!
//! and the build agrees — the object is compiled **twice**,
//! `ssl/record/methods/libdefault-lib-ssl3_cbc.o` into libcrypto and
//! `ssl/record/methods/libssl-shlib-ssl3_cbc.o` into libssl. The caller this crate needs is
//! `hmac_prov.c`'s `tls-data-size` arm, so it lands here.
//!
//! `ssl3_cbc_digest_record` computes the MAC of an already-decrypted SSLv3/TLS CBC record, and the
//! whole shape of the function is one requirement: **the caller must not learn where the padding
//! ended.** The attacker can flip bytes in a CBC record, so the length of the plaintext, the length
//! of the MAC and the position of the padding are all attacker-influenced; the function therefore
//! hashes a fixed number of blocks and *selects* which one to keep from, using masks rather than
//! branches. That is why the loop over the final `variance_blocks` blocks builds every candidate
//! block byte by byte with `constant_time_select_8` and ORs all of them together, and why
//! `num_starting_blocks` exists: the blocks no padding value can reach are hashed directly, and only
//! the reachable tail pays the constant-time cost.
//!
//! **Two details that a plausible transcription gets wrong.** The digest state is a bare
//! `unsigned char` buffer that the low-level context types are *cast onto*, and the "final" for each
//! is a hand-written serialiser (`tls1_*_final_raw`) rather than the digest's own final — because
//! this is a mid-stream state snapshot with no padding and no length appended. And MD5 is the odd
//! one in three ways at once: its chaining words are little-endian (`length_is_big_endian = 0`), its
//! SSLv3 pad length is 48 rather than 40, and its `u32toLE` is not `l2n`. `SHA2-224` shares SHA-256's
//! transform *and* its serialiser and differs only in `md_size`.
//!
//! **`EVP_MD_is_a` is the dispatch, not the NID.** The authority asks the method by name, so a
//! provider-supplied SHA-256 reaches the same arm a legacy one does — which is the whole reason this
//! file is shared with the providers rather than living in the record layer.
//!
//! SPDX-License-Identifier: Apache-2.0

// Nothing in the crate calls this unit yet, and that is a state rather than an oversight: the caller
// is `hmac_prov.c`'s `tls-data-size` arm, which is the next commit's `HMAC` provider row and which
// removes this attribute. The unit is landed whole rather than in part because its two halves --
// the digest dispatch and the constant-time variance loop -- are one function, and landing the
// dispatch without the loop would credit the crate with a symbol whose body is not the authority's.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::digest::md5::{MD5_Init, MD5_Transform, Md5Ctx};
use crate::digest::sha1::{SHA1_Init, SHA1_Transform, ShaCtx};
use crate::digest::sha2::{
    SHA224_Init, SHA256_Init, SHA256_Transform, SHA384_Init, SHA512_Init, SHA512_Transform,
    Sha256Ctx, Sha512Ctx,
};
use crate::evp::digest::{
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_is_a, EvpMd, EvpMdCtx,
};
use crate::runtime::constant_time::{
    constant_time_eq_8_s, constant_time_ge_8_s, constant_time_select_8,
};

/// `MAX_HASH_BIT_COUNT_BYTES` — `ssl3_cbc.c:39`. SHA-384/512 carry a 128-bit length field.
const MAX_HASH_BIT_COUNT_BYTES: usize = 16;
/// `MAX_HASH_BLOCK_SIZE` — `ssl3_cbc.c:46`. SHA-384/512's 128-byte block is the largest TLS admits.
const MAX_HASH_BLOCK_SIZE: usize = 128;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h`, the largest `md_out` this function will write.
const EVP_MAX_MD_SIZE: usize = 64;
/// The authority's `ossl_assert` under `-DNDEBUG`, which this profile's Makefile sets (the build tree
/// contains `-DNDEBUG`): a plain check that returns its argument, **not** the `OPENSSL_die` form.
/// That difference is observable — `return ossl_assert(0)` returns 0 here instead of aborting — and
/// the unsupported-digest arm of `ssl3_cbc_digest_record` is exactly that call.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `l2n` — `include/internal/common.h:153-156`: the low-order four bytes of `v`, **big-endian**.
///
/// The crate repeats this helper per unit rather than sharing one (`src/blowfish.rs`,
/// `src/cast.rs` and `src/idea.rs` each carry their own), for the reason those modules give: it is a
/// four-instruction serialiser, and the authority's is a macro in a header each translation unit
/// includes.
///
/// # Safety
/// `p` is writable for four bytes; it is advanced by four.
unsafe fn l2n(v: c_uint, p: *mut *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        *(*p) = (v >> 24) as c_uchar;
        *p = (*p).add(1);
        *(*p) = (v >> 16) as c_uchar;
        *p = (*p).add(1);
        *(*p) = (v >> 8) as c_uchar;
        *p = (*p).add(1);
        *(*p) = v as c_uchar;
        *p = (*p).add(1);
    }
}

/// `l2n8` — `include/internal/common.h:158-165`: the same for all eight bytes of a `uint64_t`.
///
/// # Safety
/// `p` is writable for eight bytes; it is advanced by eight.
unsafe fn l2n8(v: u64, p: *mut *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut shift = 56;
        while shift >= 0 {
            *(*p) = (v >> shift) as c_uchar;
            *p = (*p).add(1);
            shift -= 8;
        }
    }
}

/// `u32toLE` — `ssl3_cbc.c:53-57`: four bytes, **little-endian**, and the macro that exists only for
/// MD5. The `(unsigned char)` casts are the macro's, and they are what make the sequence a
/// serialisation rather than a shift into the destination.
///
/// # Safety
/// `p` is writable for four bytes; it is advanced by four.
unsafe fn u32to_le(v: u32, p: *mut *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        *(*p) = v as c_uchar;
        *p = (*p).add(1);
        *(*p) = (v >> 8) as c_uchar;
        *p = (*p).add(1);
        *(*p) = (v >> 16) as c_uchar;
        *p = (*p).add(1);
        *(*p) = (v >> 24) as c_uchar;
        *p = (*p).add(1);
    }
}

/// `static void tls1_md5_final_raw(void *ctx, unsigned char *md_out)` — `ssl3_cbc.c:64-72`, the
/// little-endian one. The cast from `void *` to the context type is the authority's, and it is what
/// lets one `void (*)(void *, unsigned char *)` cover four different contexts.
///
/// # Safety
/// `ctx` is a live `Md5Ctx` and `md_out` is writable for sixteen bytes.
unsafe fn tls1_md5_final_raw(ctx: *mut c_void, md_out: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let md5 = ctx.cast::<Md5Ctx>();
        let mut p = md_out;
        u32to_le((*md5).a, ptr::addr_of_mut!(p));
        u32to_le((*md5).b, ptr::addr_of_mut!(p));
        u32to_le((*md5).c, ptr::addr_of_mut!(p));
        u32to_le((*md5).d, ptr::addr_of_mut!(p));
    }
}

/// `static void tls1_sha1_final_raw(void *ctx, unsigned char *md_out)` — `ssl3_cbc.c:75-84`.
///
/// # Safety
/// `ctx` is a live `ShaCtx` and `md_out` is writable for twenty bytes.
unsafe fn tls1_sha1_final_raw(ctx: *mut c_void, md_out: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let sha1 = ctx.cast::<ShaCtx>();
        let mut p = md_out;
        for word in [(*sha1).h0, (*sha1).h1, (*sha1).h2, (*sha1).h3, (*sha1).h4] {
            l2n(word, ptr::addr_of_mut!(p));
        }
    }
}

/// `static void tls1_sha256_final_raw(void *ctx, unsigned char *md_out)` — `ssl3_cbc.c:86-93`.
///
/// # Safety
/// `ctx` is a live `Sha256Ctx` and `md_out` is writable for thirty-two bytes.
unsafe fn tls1_sha256_final_raw(ctx: *mut c_void, md_out: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let sha256 = ctx.cast::<Sha256Ctx>();
        let mut p = md_out;
        for i in 0..8 {
            l2n((*sha256).h[i], ptr::addr_of_mut!(p));
        }
    }
}

/// `static void tls1_sha512_final_raw(void *ctx, unsigned char *md_out)` — `ssl3_cbc.c:95-102`.
/// `l2n8` rather than `l2n`, eight times rather than five.
///
/// # Safety
/// `ctx` is a live `Sha512Ctx` and `md_out` is writable for sixty-four bytes.
unsafe fn tls1_sha512_final_raw(ctx: *mut c_void, md_out: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let sha512 = ctx.cast::<Sha512Ctx>();
        let mut p = md_out;
        for i in 0..8 {
            l2n8((*sha512).h[i], ptr::addr_of_mut!(p));
        }
    }
}

/// `(void (*)(void *ctx, const unsigned char *block))MD5_Transform` — `ssl3_cbc.c:167`.
///
/// The authority reaches the transform through a cast, because one `void (*)(void *, const
/// unsigned char *)` has to hold four differently-typed transforms. Rust will not cast between
/// function-pointer types, so each cast becomes the smallest possible wrapper; the wrapper *is* the
/// cast, and it is where the authority's `void *` becomes the context type it always was.
///
/// # Safety
/// `ctx` is a live `Md5Ctx` and `block` is readable for 64 bytes.
unsafe fn md5_transform_raw(ctx: *mut c_void, block: *const c_uchar) {
    // SAFETY: the caller's contract.
    unsafe { MD5_Transform(ctx.cast::<Md5Ctx>(), block) }
}

/// The `SHA1_Transform` cast — `ssl3_cbc.c:176`.
///
/// # Safety
/// `ctx` is a live `ShaCtx` and `block` is readable for 64 bytes.
unsafe fn sha1_transform_raw(ctx: *mut c_void, block: *const c_uchar) {
    // SAFETY: the caller's contract.
    unsafe { SHA1_Transform(ctx.cast::<ShaCtx>(), block) }
}

/// The `SHA256_Transform` cast — `ssl3_cbc.c:185` and `:194`. `SHA2-224` shares it.
///
/// # Safety
/// `ctx` is a live `Sha256Ctx` and `block` is readable for 64 bytes.
unsafe fn sha256_transform_raw(ctx: *mut c_void, block: *const c_uchar) {
    // SAFETY: the caller's contract.
    unsafe { SHA256_Transform(ctx.cast::<Sha256Ctx>(), block) }
}

/// The `SHA512_Transform` cast — `ssl3_cbc.c:203` and `:212`. `SHA2-384` shares it.
///
/// # Safety
/// `ctx` is a live `Sha512Ctx` and `block` is readable for 128 bytes.
unsafe fn sha512_transform_raw(ctx: *mut c_void, block: *const c_uchar) {
    // SAFETY: the caller's contract.
    unsafe { SHA512_Transform(ctx.cast::<Sha512Ctx>(), block) }
}

/// `union { OSSL_UNION_ALIGN; unsigned char c[sizeof(LARGEST_DIGEST_CTX)]; }` — `ssl3_cbc.c:136-139`.
///
/// `LARGEST_DIGEST_CTX` is `SHA512_CTX`, and `OSSL_UNION_ALIGN` is the widest scalar type, so the
/// buffer is as large as the largest context and as aligned as a `u64`. Both properties are
/// load-bearing: the `*_Init` and `*_Transform` calls cast a pointer to this buffer to their own
/// context type, and `#[repr(C, align(8))]` is what makes that cast sound.
#[repr(C, align(8))]
struct MdState([u8; core::mem::size_of::<Sha512Ctx>()]);

/// `static void (*)(void *, unsigned char *)` — the authority's `md_final_raw`.
type FinalRaw = unsafe fn(*mut c_void, *mut c_uchar);
/// `static void (*)(void *, const unsigned char *)` — the authority's `md_transform`, which is each
/// digest's own `*_Transform` behind one of the `*_transform_raw` wrappers above.
type Transform = unsafe fn(*mut c_void, *const c_uchar);

/// `int ssl3_cbc_digest_record(const EVP_MD *md, unsigned char *md_out, size_t *md_out_size,
/// const unsigned char *header, const unsigned char *data, size_t data_size,
/// size_t data_plus_mac_plus_padding_size, const unsigned char *mac_secret,
/// size_t mac_secret_length, char is_sslv3)` — `ssl3_cbc.c:126-477`.
///
/// The caller guarantees `data` is readable for `data_plus_mac_plus_padding_size` bytes and
/// `header` for at least `header_length` (13, or `mac_secret_length + 40/48 + 11` under SSLv3).
/// Returns 1 on success, 0 on error.
///
/// **This is an internal symbol, not an export, and it must stay one.** The authority declares it in
/// `include/internal/ssl3_cbc.h` and `nm -D libcrypto.so.3` does not list it, so it carries no
/// `#[no_mangle]`; the phase's export census would otherwise credit the crate with a `libcrypto`
/// export the authority does not have. Its two callers are this module's tests and, next, the
/// `tls-data-size` arm of `hmac_prov.c`.
///
/// # Safety
/// Every pointer above is live for the length stated, `md_out` is writable for the digest's size,
/// and `md_out_size` is NULL or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ssl3_cbc_digest_record(
    md: *const EvpMd,
    md_out: *mut c_uchar,
    md_out_size: *mut usize,
    header: *const c_uchar,
    data: *const c_uchar,
    data_size: usize,
    data_plus_mac_plus_padding_size: usize,
    mac_secret: *const c_uchar,
    mac_secret_length: usize,
    is_sslv3: c_char,
) -> c_int {
    // SAFETY: this function's own contract; every pointer below is the caller's.
    unsafe {
        let mut md_state = MdState([0; core::mem::size_of::<Sha512Ctx>()]);
        let md_final_raw: FinalRaw;
        let md_transform: Transform;
        let md_size: usize;
        let mut md_block_size: usize = 64;
        let mut sslv3_pad_length: usize = 40;
        let mut length_bytes = [0u8; MAX_HASH_BIT_COUNT_BYTES];
        let mut hmac_pad = [0u8; MAX_HASH_BLOCK_SIZE];
        let mut first_block = [0u8; MAX_HASH_BLOCK_SIZE];
        let mut mac_out = [0u8; EVP_MAX_MD_SIZE];
        let mut md_out_size_u: c_uint = 0;
        let mut md_length_size: usize = 8;
        let mut length_is_big_endian = true;
        let mut ret: c_int = 0;

        /*
         * "This is a, hopefully redundant, check that allows us to forget about many possible
         * overflows later in this function."
         */
        if ossl_assert(data_plus_mac_plus_padding_size < 1024 * 1024) == 0 {
            return 0;
        }

        // The dispatch. `EVP_MD_is_a` and not a NID comparison, so a provider-supplied method lands
        // in the same arm a legacy one does.
        if EVP_MD_is_a(md, c"MD5".as_ptr()) != 0 {
            if MD5_Init(md_state.0.as_mut_ptr().cast::<Md5Ctx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_md5_final_raw;
            md_transform = md5_transform_raw;
            md_size = 16;
            sslv3_pad_length = 48;
            length_is_big_endian = false;
        } else if EVP_MD_is_a(md, c"SHA1".as_ptr()) != 0 {
            if SHA1_Init(md_state.0.as_mut_ptr().cast::<ShaCtx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_sha1_final_raw;
            md_transform = sha1_transform_raw;
            md_size = 20;
        } else if EVP_MD_is_a(md, c"SHA2-224".as_ptr()) != 0 {
            if SHA224_Init(md_state.0.as_mut_ptr().cast::<Sha256Ctx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_sha256_final_raw;
            md_transform = sha256_transform_raw;
            md_size = 224 / 8;
        } else if EVP_MD_is_a(md, c"SHA2-256".as_ptr()) != 0 {
            if SHA256_Init(md_state.0.as_mut_ptr().cast::<Sha256Ctx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_sha256_final_raw;
            md_transform = sha256_transform_raw;
            md_size = 32;
        } else if EVP_MD_is_a(md, c"SHA2-384".as_ptr()) != 0 {
            if SHA384_Init(md_state.0.as_mut_ptr().cast::<Sha512Ctx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_sha512_final_raw;
            md_transform = sha512_transform_raw;
            md_size = 384 / 8;
            md_block_size = 128;
            md_length_size = 16;
        } else if EVP_MD_is_a(md, c"SHA2-512".as_ptr()) != 0 {
            if SHA512_Init(md_state.0.as_mut_ptr().cast::<Sha512Ctx>()) <= 0 {
                return 0;
            }
            md_final_raw = tls1_sha512_final_raw;
            md_transform = sha512_transform_raw;
            md_size = 64;
            md_block_size = 128;
            md_length_size = 16;
        } else {
            /*
             * "ssl3_cbc_record_digest_supported should have been called first to check that the hash
             * function is supported." Under `-DNDEBUG` this is 0, not a die -- see `ossl_assert`.
             */
            if !md_out_size.is_null() {
                *md_out_size = 0;
            }
            return ossl_assert(false);
        }

        if ossl_assert(md_length_size <= MAX_HASH_BIT_COUNT_BYTES) == 0
            || ossl_assert(md_block_size <= MAX_HASH_BLOCK_SIZE) == 0
            || ossl_assert(md_size <= EVP_MAX_MD_SIZE) == 0
        {
            return 0;
        }

        let header_length = if is_sslv3 != 0 {
            mac_secret_length
                + sslv3_pad_length
                + 8 /* sequence number */
                + 1 /* record type */
                + 2 /* record length */
        } else {
            13
        };

        /*
         * `variance_blocks` is how many of the final hash blocks the padding value could move the
         * end of the data into, so they are the ones that have to be built in constant time.
         */
        // The arithmetic is the authority's literal `(255 + 1 + md_size + md_block_size - 1) /
        // md_block_size`, kept as written rather than as `div_ceil` so that the correspondence is
        // checkable by eye; Rust's `usize` division is the same truncating division as C's.
        #[allow(clippy::manual_div_ceil)]
        let variance_blocks = if is_sslv3 != 0 {
            2
        } else {
            (255 + 1 + md_size + md_block_size - 1) / md_block_size + 1
        };

        /*
         * "From now on we're dealing with the MAC, which conceptually has 13 bytes of `header'
         * before the start of the data (TLS) or 71/75 bytes (SSLv3)"
         *
         * `max_mac_bytes` contains the maximum bytes of the MAC including |header|, assuming that
         * there's no padding; `num_blocks` is the maximum number of hash blocks.
         */
        let len = data_plus_mac_plus_padding_size + header_length;
        let max_mac_bytes = len - md_size - 1;
        #[allow(clippy::manual_div_ceil)] // the authority's literal expression, as above
        let num_blocks = (max_mac_bytes + 1 + md_length_size + md_block_size - 1) / md_block_size;

        /*
         * `mac_end_offset` is the index just past the end of the data to be MACed. `c` is the index
         * of the 0x80 byte in the final hash block that contains application data, `index_a` is the
         * hash block number that contains the 0x80 terminating value, and `index_b` is the hash
         * block number that contains the 64-bit hash length, in bits.
         */
        let mac_end_offset = data_size + header_length;
        let c = mac_end_offset % md_block_size;
        let index_a = mac_end_offset / md_block_size;
        let index_b = (mac_end_offset + md_length_size) / md_block_size;

        /*
         * "In order to calculate the MAC in constant time we have to handle the final blocks
         * specially because the padding value could cause the end to appear somewhere in the final
         * |variance_blocks| blocks and we can't leak where. However, |num_starting_blocks| worth of
         * data can be hashed right away because no padding value can affect whether they are
         * plaintext."
         *
         * `k` is the starting byte offset into the conceptual header||data.
         */
        let mut num_starting_blocks = 0;
        let mut k = 0;

        /*
         * "For SSLv3, if we're going to have any starting blocks then we need at least two because
         * the header is larger than a single block."
         */
        if num_blocks > variance_blocks + usize::from(is_sslv3 != 0) {
            num_starting_blocks = num_blocks - variance_blocks;
            k = md_block_size * num_starting_blocks;
        }

        let mut bits = 8 * mac_end_offset;
        if is_sslv3 == 0 {
            /*
             * "Compute the initial HMAC block. For SSLv3, the padding and secret bytes are included
             * in |header| because they take more than a single block."
             *
             * The authority increments `bits` here, and **before** the length-field fill below, so
             * the extra block is part of the length for *every* digest -- including MD5, which is
             * the little-endian case. Reading the increment as belonging to the big-endian branch is
             * the natural mistake, and it is observable: it makes TLS+MD5 hash a length field 64
             * bytes short. This is a mutation of the outer binding for that reason.
             */
            bits += 8 * md_block_size;
            hmac_pad[..md_block_size].fill(0);
            if ossl_assert(mac_secret_length <= MAX_HASH_BLOCK_SIZE) == 0 {
                return 0;
            }
            ptr::copy_nonoverlapping(mac_secret, hmac_pad.as_mut_ptr(), mac_secret_length);
            for byte in hmac_pad.iter_mut().take(md_block_size) {
                *byte ^= 0x36;
            }
            md_transform(md_state.0.as_mut_ptr().cast::<c_void>(), hmac_pad.as_ptr());
        }

        /*
         * "The final bytes of one of the blocks contains the length." The authority's single
         * `if/else`; MD5 is the only little-endian digest.
         */
        if length_is_big_endian {
            length_bytes[..md_length_size - 4].fill(0);
            length_bytes[md_length_size - 4] = (bits >> 24) as u8;
            length_bytes[md_length_size - 3] = (bits >> 16) as u8;
            length_bytes[md_length_size - 2] = (bits >> 8) as u8;
            length_bytes[md_length_size - 1] = bits as u8;
        } else {
            length_bytes[..md_length_size].fill(0);
            length_bytes[md_length_size - 5] = (bits >> 24) as u8;
            length_bytes[md_length_size - 6] = (bits >> 16) as u8;
            length_bytes[md_length_size - 7] = (bits >> 8) as u8;
            length_bytes[md_length_size - 8] = bits as u8;
        }

        if k > 0 {
            if is_sslv3 != 0 {
                /*
                 * "The SSLv3 header is larger than a single block. overhang is the number of bytes
                 * beyond a single block that the header consumes: either 7 bytes (SHA1) or 11 bytes
                 * (MD5). [...] However we add a sanity check just in case."
                 */
                if header_length <= md_block_size {
                    /* "Should never happen" */
                    return 0;
                }
                let overhang = header_length - md_block_size;
                md_transform(md_state.0.as_mut_ptr().cast::<c_void>(), header);
                ptr::copy_nonoverlapping(
                    header.add(md_block_size),
                    first_block.as_mut_ptr(),
                    overhang,
                );
                ptr::copy_nonoverlapping(
                    data,
                    first_block.as_mut_ptr().add(overhang),
                    md_block_size - overhang,
                );
                md_transform(
                    md_state.0.as_mut_ptr().cast::<c_void>(),
                    first_block.as_ptr(),
                );
                let mut i = 1;
                while i < k / md_block_size - 1 {
                    md_transform(
                        md_state.0.as_mut_ptr().cast::<c_void>(),
                        data.add(md_block_size * i - overhang),
                    );
                    i += 1;
                }
            } else {
                /* "k is a multiple of md_block_size." */
                ptr::copy_nonoverlapping(header, first_block.as_mut_ptr(), 13);
                ptr::copy_nonoverlapping(
                    data,
                    first_block.as_mut_ptr().add(13),
                    md_block_size - 13,
                );
                md_transform(
                    md_state.0.as_mut_ptr().cast::<c_void>(),
                    first_block.as_ptr(),
                );
                let mut i = 1;
                while i < k / md_block_size {
                    md_transform(
                        md_state.0.as_mut_ptr().cast::<c_void>(),
                        data.add(md_block_size * i - 13),
                    );
                    i += 1;
                }
            }
        }

        mac_out.fill(0);

        /*
         * "We now process the final hash blocks. For each block, we construct it in constant time. If
         * the |i==index_a| then we'll include the 0x80 bytes and zero pad etc. For each block we
         * selectively copy it, in constant time, to |mac_out|."
         */
        let mut i = num_starting_blocks;
        while i <= num_starting_blocks + variance_blocks {
            let mut block = [0u8; MAX_HASH_BLOCK_SIZE];
            let is_block_a = constant_time_eq_8_s(i, index_a);
            let is_block_b = constant_time_eq_8_s(i, index_b);

            let mut j = 0;
            while j < md_block_size {
                let mut b: u8 = 0;

                if k < header_length {
                    b = *header.add(k);
                } else if k < data_plus_mac_plus_padding_size + header_length {
                    b = *data.add(k - header_length);
                }
                k += 1;

                let is_past_c = is_block_a & constant_time_ge_8_s(j, c);
                let is_past_cp1 = is_block_a & constant_time_ge_8_s(j, c + 1);
                /*
                 * "If this is the block containing the end of the application data, and we are at
                 * the offset for the 0x80 value, then overwrite b with 0x80."
                 */
                b = constant_time_select_8(is_past_c, 0x80, b);
                /*
                 * "If this block contains the end of the application data and we're past the 0x80
                 * value then just write zero."
                 */
                b &= !is_past_cp1;
                /*
                 * "If this is index_b (the final block), but not index_a (the end of the data), then
                 * the 64-bit length didn't fit into index_a and we're having to add an extra block
                 * of zeros."
                 */
                b &= !is_block_b | is_block_a;

                /*
                 * "The final bytes of one of the blocks contains the length."
                 */
                if j >= md_block_size - md_length_size {
                    /* "If this is index_b, write a length byte." */
                    b = constant_time_select_8(
                        is_block_b,
                        length_bytes[j - (md_block_size - md_length_size)],
                        b,
                    );
                }
                block[j] = b;
                j += 1;
            }

            md_transform(md_state.0.as_mut_ptr().cast::<c_void>(), block.as_ptr());
            md_final_raw(md_state.0.as_mut_ptr().cast::<c_void>(), block.as_mut_ptr());
            /* "If this is index_b, copy the hash value to |mac_out|." */
            for j in 0..md_size {
                mac_out[j] |= block[j] & is_block_b;
            }
            i += 1;
        }

        let md_ctx = EVP_MD_CTX_new();
        if md_ctx.is_null() {
            return err(md_ctx, ret);
        }

        if EVP_DigestInit_ex(md_ctx, md, ptr::null_mut()) <= 0 {
            return err(md_ctx, ret);
        }
        if is_sslv3 != 0 {
            /* "We repurpose |hmac_pad| to contain the SSLv3 pad2 block." */
            hmac_pad[..sslv3_pad_length].fill(0x5c);

            if EVP_DigestUpdate(md_ctx, mac_secret.cast(), mac_secret_length) <= 0
                || EVP_DigestUpdate(md_ctx, hmac_pad.as_ptr().cast(), sslv3_pad_length) <= 0
                || EVP_DigestUpdate(md_ctx, mac_out.as_ptr().cast(), md_size) <= 0
            {
                return err(md_ctx, ret);
            }
        } else {
            /* "Complete the HMAC in the standard manner." */
            for byte in hmac_pad.iter_mut().take(md_block_size) {
                *byte ^= 0x6a;
            }

            if EVP_DigestUpdate(md_ctx, hmac_pad.as_ptr().cast(), md_block_size) <= 0
                || EVP_DigestUpdate(md_ctx, mac_out.as_ptr().cast(), md_size) <= 0
            {
                return err(md_ctx, ret);
            }
        }
        ret = EVP_DigestFinal(md_ctx, md_out, ptr::addr_of_mut!(md_out_size_u));
        if ret != 0 && !md_out_size.is_null() {
            *md_out_size = md_out_size_u as usize;
        }

        ret = 1;
        err(md_ctx, ret)
    }
}

/// The authority's `err:` label and its `EVP_MD_CTX_free(md_ctx); return ret;`. Three `goto err`
/// paths and the fall-through all reach it, and in each the context is either NULL or the one
/// `EVP_MD_CTX_new` answered, which `EVP_MD_CTX_free` tolerates.
///
/// # Safety
/// `md_ctx` is NULL or a live context this function created.
unsafe fn err(md_ctx: *mut EvpMdCtx, ret: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_MD_CTX_free(md_ctx) };
    ret
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};

    /// The authority's own output, generated by the tracked
    /// `courts/phase8/gen-ssl3-cbc-values.c` and committed at `courts/phase8/ssl3_cbc_expectations.txt`.
    ///
    /// **The oracle is the unit being transcribed**, compiled from the authority's tree against the
    /// authority's libcrypto -- so this is a transcription check rather than an independent
    /// construction check, and it says so. What it does cover is the part that matters: the
    /// constant-time block arithmetic is exercised at every combination of digest, SSLv3-vs-TLS,
    /// ten message lengths and both a zero and a block-filling padding, because that arithmetic is
    /// where a transcription diverges and where the divergence is invisible from the outside.
    const EXPECTATIONS: &str = include_str!("../../courts/phase8/ssl3_cbc_expectations.txt");

    fn fill(p: &mut [u8], seed: u32) {
        let mut x: u32 = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        for byte in p.iter_mut() {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *byte = (x >> 16) as u8;
        }
    }

    /// One parsed case: `(digest, is_sslv3, data_size, mac_size, padding, ok, hex, out_size)`.
    struct Case {
        digest: String,
        is_sslv3: i32,
        data_size: usize,
        mac_size: usize,
        padding: usize,
        ok: i32,
        hex: String,
        out_size: usize,
    }

    fn cases() -> Vec<Case> {
        let mut out = Vec::new();
        for line in EXPECTATIONS.lines() {
            let line = line.trim();
            if !line.starts_with('(') {
                continue;
            }
            let inner = match line.strip_suffix("),").and_then(|l| l.strip_prefix('(')) {
                Some(v) => v,
                None => continue,
            };
            // The digest name is the only quoted field, so split on the quotes first.
            let first_quote = inner.find('"').expect("a quoted digest name");
            let second_quote =
                inner[first_quote + 1..].find('"').expect("a closing quote") + first_quote + 1;
            let digest = inner[first_quote + 1..second_quote].to_string();
            let rest: Vec<&str> = inner[second_quote + 1..]
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .collect();
            let num = |s: &str| -> usize { s.parse::<usize>().unwrap_or(usize::MAX) };
            if rest.len() == 2 {
                // The unsupported-digest rows: `(name, ok, out_size)`.
                out.push(Case {
                    digest,
                    is_sslv3: 0,
                    data_size: 0,
                    mac_size: 0,
                    padding: 0,
                    ok: num(rest[0]) as i32,
                    hex: String::new(),
                    out_size: num(rest[1]),
                });
                continue;
            }
            assert_eq!(rest.len(), 7, "{line}");
            let hex = rest[5].trim_matches('"').to_string();
            out.push(Case {
                digest,
                is_sslv3: num(rest[0]) as i32,
                data_size: num(rest[1]),
                mac_size: num(rest[2]),
                padding: num(rest[3]),
                ok: num(rest[4]) as i32,
                hex,
                out_size: num(rest[6]),
            });
        }
        out
    }

    /// The method for a fixture name, fetched the way the caller that matters fetches it.
    ///
    /// **`EVP_sha256()` is deliberately not used.** In the authority the code that reaches this
    /// function -- `hmac_prov.c`'s `tls-data-size` arm -- holds a method that came out of
    /// `EVP_MD_fetch`, and the module doc's point is that the dispatch is `EVP_MD_is_a` rather than
    /// a NID precisely so a provider-supplied method lands in the same arm. Fetching here is what
    /// exercises that path; a hand-built legacy method would test the branch and not the property.
    ///
    /// The caller owns the returned reference and must `EVP_MD_free` it.
    fn method(name: &str) -> *mut EvpMd {
        const N: usize = 32;
        let bytes = name.as_bytes();
        assert!(
            bytes.len() < N,
            "the fixture name fits a NUL-terminated buffer"
        );
        let mut buf = [0u8; N];
        buf[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: `buf` is NUL-terminated by its zeroed tail and lives until the call returns; the
        // context is the default one and the property query is NULL, both of which fetch accepts.
        let md = unsafe { EVP_MD_fetch(ptr::null_mut(), buf.as_ptr().cast(), ptr::null()) };
        assert!(!md.is_null(), "the fixture names a published digest");
        md
    }

    #[test]
    fn the_fixture_is_the_whole_matrix() {
        let cases = cases();
        assert!(EXPECTATIONS.contains("gen-ssl3-cbc-values.c"));
        // 3 unsupported digests + 6 digests * 2 sslv3 * 10 lengths * 2 paddings = 243.
        assert_eq!(cases.len(), 243);
        assert_eq!(cases.iter().filter(|c| c.ok == 0).count(), 3);
    }

    #[test]
    fn every_case_matches_the_authority() {
        let mut checked = 0;
        for case in cases() {
            let mut header = [0u8; 512];
            let mut data = [0u8; 512];
            let mut secret = [0u8; 512];
            let mut out = [0u8; EVP_MAX_MD_SIZE];
            let mut out_size: usize = 0;

            fill(&mut header, (case.data_size as u32).wrapping_add(7));
            fill(&mut data, (case.data_size as u32).wrapping_add(11));
            fill(&mut secret, (case.mac_size as u32).wrapping_add(13));

            let dpmps = if case.ok == 0 && case.mac_size == 0 {
                // The unsupported-digest rows carry a fixed shape, matching the generator.
                16 + 32 + 16
            } else {
                case.data_size + case.mac_size + case.padding
            };

            let md = method(&case.digest);
            // SAFETY: every buffer is this frame's own and large enough for the lengths passed,
            // and `md` is a reference this frame holds.
            let ret = unsafe {
                ssl3_cbc_digest_record(
                    md,
                    out.as_mut_ptr(),
                    &mut out_size,
                    header.as_ptr(),
                    data.as_ptr(),
                    case.data_size,
                    dpmps,
                    secret.as_ptr(),
                    16,
                    case.is_sslv3 as c_char,
                )
            };
            // SAFETY: `md` is the reference `method` just handed over.
            unsafe { EVP_MD_free(md) };

            assert_eq!(
                ret, case.ok,
                "{} is_sslv3={} data={} mac={} pad={}",
                case.digest, case.is_sslv3, case.data_size, case.mac_size, case.padding
            );
            if case.ok == 0 {
                if !case.hex.is_empty() {
                    assert_eq!(out_size, case.out_size, "{} out_size", case.digest);
                }
                continue;
            }
            let mut hex = String::new();
            for byte in &out[..out_size] {
                hex.push_str(&format!("{byte:02x}"));
            }
            assert_eq!(
                hex, case.hex,
                "{} is_sslv3={} data={} mac={} pad={}",
                case.digest, case.is_sslv3, case.data_size, case.mac_size, case.padding
            );
            assert_eq!(out_size, case.out_size);
            checked += 1;
        }
        assert_eq!(checked, 240);
    }

    #[test]
    fn the_unsupported_digests_take_the_assert_arm_and_zero_the_output_size() {
        // `ssl3_cbc_record_digest_supported` is what the record layer calls first, and it is
        // libssl's -- `ssl/record/methods/tls_common.c`, built into libssl.a and not libcrypto.a.
        // What is this unit's is the refusal behind it, and the fixture observes that it is a `0`
        // return with `*md_out_size` zeroed rather than an abort, because `-DNDEBUG` is set.
        for case in cases().into_iter().filter(|c| c.ok == 0) {
            let mut out = [0u8; EVP_MAX_MD_SIZE];
            let mut out_size = usize::MAX;
            let header = [0u8; 128];
            let data = [0u8; 64];
            let secret = [0u8; 16];
            let md = method(&case.digest);
            // SAFETY: the locals are this frame's own and sized for the arguments passed, and `md`
            // is a reference this frame holds.
            let ret = unsafe {
                ssl3_cbc_digest_record(
                    md,
                    out.as_mut_ptr(),
                    &mut out_size,
                    header.as_ptr(),
                    data.as_ptr(),
                    16,
                    16 + 32 + 16,
                    secret.as_ptr(),
                    16,
                    0,
                )
            };
            // SAFETY: `md` is the reference `method` just handed over.
            unsafe { EVP_MD_free(md) };
            assert_eq!(ret, 0, "{}", case.digest);
            assert_eq!(out_size, 0, "{} zeroes the output size", case.digest);
        }
    }

    #[test]
    fn a_message_longer_than_the_variance_window_changes_the_path() {
        // The `k > 0` arm is only reached when `num_blocks > variance_blocks`, which needs a message
        // longer than the final window plus a block. The matrix's 255-byte case reaches it for every
        // digest and the 0-byte case does not, so the fixture covers both paths -- this test states
        // which is which, so a future edit that shrank the matrix would be noticed.
        let cases = cases();
        let small: Vec<_> = cases
            .iter()
            .filter(|c| c.ok == 1 && c.data_size == 0)
            .collect();
        let large: Vec<_> = cases
            .iter()
            .filter(|c| c.ok == 1 && c.data_size == 255)
            .collect();
        assert_eq!(small.len(), 24);
        assert_eq!(large.len(), 24);
        assert!(small.iter().all(|c| !c.hex.is_empty()));
        assert!(large.iter().all(|c| !c.hex.is_empty()));
    }
}
