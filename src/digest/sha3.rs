//! Phase 8.1b — `crypto/sha/sha3.c` and `crypto/sha/keccak1600.c`: the Keccak sponge.
//!
//! SHA-3, SHAKE, the raw Keccak spellings and the cSHAKE-based `KECCAK-KMAC` pair are one
//! construction over one permutation. `crypto/sha/keccak1600.c` is the permutation and the
//! absorb/squeeze loop; `crypto/sha/sha3.c` is the padded sponge's state machine; and
//! `sha3_prov.c` (generated from `sha3_prov.c.in`) is the provider row, with the rate, the pad
//! byte and the default output length as the only per-spelling differences.
//!
//! ## No export, so this is provider work
//!
//! `include/openssl/sha.h` declares no `SHA3_*` and no `SHAKE*`, and
//! `forensics/atlas/…/symbols-libcrypto.json` has no record for `SHA3_absorb` or `SHA3_squeeze`
//! — D197 read both and the plan's §2 subsection carries the measurement. `crypto/sha/sha3.c`'s
//! entry points are the five `ossl_sha3_*` names and `keccak1600.c`'s are `SHA3_absorb`/
//! `SHA3_squeeze`, all local. Nothing here is `#[no_mangle]`; the surface is
//! `providers/defltprov.c:109-130`'s twelve rows, and `EVP_sha3_224` … `EVP_shake256` — Phase
//! 7's, already implemented — reach it through the provider.
//!
//! ## Which arm of `keccak1600.c`, and why the answer is "the reference one"
//!
//! The file carries five permutation variants (`KECCAK_REF`, `KECCAK_1X`, `KECCAK_1X_ALT`,
//! `KECCAK_2X`, `KECCAK_INPLACE`) selected by the build, plus perlasm on some platforms. The
//! reference arm is the one `keccak1600.c:110-245` writes, and it is the one transcribed here:
//! Theta, Rho, Pi, Chi and Iota over the `rhotates` and `iotas` tables the same file carries.
//! The other arms are the same permutation with the loops fused; `RT-DIGEST` is what proves this
//! one computes *this* construction's bytes rather than merely *a* Keccak.
//!
//! The state representation matters and is not the specification's: the authority indexes its
//! matrix `A[y][x]` and maps the input's first eight bytes to `A_flat[0]`, so the flat lane order
//! is the file's rather than FIPS 202's `A[x][y]`. Both the absorb loop and the permutation here
//! use the file's order, which is why the two agree lane for lane.
//!
//! ## The squeeze loop, which is where a transcription fails
//!
//! `SHA3_squeeze` may be called more than once. The first call must not permute — the padded
//! block was just absorbed — and every later call must permute before it reads. Output lengths
//! that are not a multiple of the rate are buffered by `ossl_sha3_squeeze`, which is why the loop
//! carries `next` and why `ossl_sha3_squeeze`'s buffered branch is transcribed rather than
//! simplified: `EVP_DigestSqueeze` reaches it in slices, and a version that always permuted would
//! drop bytes at the first slice boundary.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

/// `KECCAK1600_WIDTH` — `include/internal/sha3.h:17`. The state is 1600 bits.
const KECCAK1600_WIDTH: usize = 1600;
/// `SHA3_MDSIZE(bitlen)` — `include/internal/sha3.h:18`.
pub(crate) const fn sha3_mdsize(bitlen: usize) -> usize {
    bitlen / 8
}
/// `KMAC_MDSIZE(bitlen)` — `include/internal/sha3.h:19`.
pub(crate) const fn kmac_mdsize(bitlen: usize) -> usize {
    2 * (bitlen / 8)
}
/// `SHA3_BLOCKSIZE(bitlen)` — `include/internal/sha3.h:20`.
pub(crate) const fn sha3_blocksize(bitlen: usize) -> usize {
    (KECCAK1600_WIDTH - bitlen * 2) / 8
}
/// `KECCAK1600_WIDTH / 8 - 32` — the staging buffer's length, `include/internal/sha3.h:44`.
pub(crate) const KECCAK_BUF_LEN: usize = KECCAK1600_WIDTH / 8 - 32;

/// `XOF_STATE_INIT` … `XOF_STATE_SQUEEZE` — `include/internal/sha3.h:37-40`.
pub(crate) const XOF_STATE_INIT: c_int = 0;
/// See [`XOF_STATE_INIT`]. The authority's provider sets this in its `generic_sha3_absorb`; this
/// crate's provider calls `ossl_sha3_update` directly, and the only state the sponge reads is
/// `FINAL`/`SQUEEZE` (to refuse a later update), so the value is carried for the record.
#[allow(dead_code)]
pub(crate) const XOF_STATE_ABSORB: c_int = 1;
/// See [`XOF_STATE_INIT`].
pub(crate) const XOF_STATE_FINAL: c_int = 2;
/// See [`XOF_STATE_INIT`].
pub(crate) const XOF_STATE_SQUEEZE: c_int = 3;

/// `KECCAK1600_CTX` — `include/internal/sha3.h:42-50`. The authority's `PROV_SHA3_METHOD meth`
/// field selects a hardware absorb/final/squeeze at run time; this crate has no assembly
/// (`docs/RELEASE_GATES.md` puts performance and CPU dispatch in Phase 19), so the generic arm is
/// the only one and the field is not carried.
#[repr(C)]
pub struct KeccakCtx {
    /// `uint64_t A[5][5]` — the state, flat in the authority's row-major `A[y][x]` order.
    pub a: [u64; 25],
    /// `unsigned char buf[]` — the partial-block staging buffer.
    pub buf: [u8; KECCAK_BUF_LEN],
    /// `size_t block_size` — the rate in bytes.
    pub block_size: usize,
    /// `size_t md_size` — the output length in bytes, `usize::MAX` when unset.
    pub md_size: usize,
    /// `size_t bufsz` — used bytes in `buf`.
    pub bufsz: usize,
    /// `unsigned char pad` — the domain-separation byte.
    pub pad: u8,
    /// `int xof_state` — one of the `XOF_STATE_*` values.
    pub xof_state: c_int,
}

/// `rhotates[5][5]` — `keccak1600.c:75-81`, in the authority's `A[y][x]` order.
const RHOTATES: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

/// `iotas[]` — `keccak1600.c:83-108`, the `BIT_INTERLEAVE == 0` column (which is the one this
/// profile takes: `keccak1600.c:37-43` defines `BIT_INTERLEAVE (0)` on x86-64).
const IOTAS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// `KeccakF1600` — `keccak1600.c:234-245` (the `KECCAK_REF` arm). Theta, Rho, Pi, Chi, Iota,
/// twenty-four times.
fn keccakf1600(a: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    let mut t = [0u64; 25];
    for iota in IOTAS.iter() {
        // Theta
        for x in 0..5 {
            c[x] = a[x] ^ a[5 + x] ^ a[10 + x] ^ a[15 + x] ^ a[20 + x];
        }
        for x in 0..5 {
            let d = c[(x + 1) % 5].rotate_left(1) ^ c[(x + 4) % 5];
            for y in 0..5 {
                a[y * 5 + x] ^= d;
            }
        }
        // Rho
        for y in 0..5 {
            for x in 0..5 {
                a[y * 5 + x] = a[y * 5 + x].rotate_left(RHOTATES[y][x]);
            }
        }
        // Pi — `A[y][x] = T[x][(3*y+x) % 5]`
        t.copy_from_slice(&*a);
        for y in 0..5 {
            for x in 0..5 {
                a[y * 5 + x] = t[x * 5 + (3 * y + x) % 5];
            }
        }
        // Chi — `A[y][x] ^= ~A[y][(x+1)%5] & A[y][(x+2)%5]`
        for y in 0..5 {
            let row = [
                a[y * 5],
                a[y * 5 + 1],
                a[y * 5 + 2],
                a[y * 5 + 3],
                a[y * 5 + 4],
            ];
            for x in 0..5 {
                a[y * 5 + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // Iota
        a[0] ^= iota;
    }
}

/// One little-endian 64-bit word, byte-wise so the input need not be aligned.
///
/// # Safety
/// `p` must be readable for eight bytes.
#[inline]
unsafe fn load_le64(p: *const u8) -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: the caller guarantees eight readable bytes.
    unsafe { ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8) };
    u64::from_le_bytes(b)
}

/// One little-endian 64-bit word.
///
/// # Safety
/// `p` must be writable for eight bytes.
#[inline]
unsafe fn store_le64(p: *mut u8, v: u64) {
    let b = v.to_le_bytes();
    // SAFETY: the caller guarantees eight writable bytes.
    unsafe { ptr::copy_nonoverlapping(b.as_ptr(), p, 8) };
}

/// `size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len, size_t r)` —
/// `keccak1600.c:1095-1115`. Absorbs the largest multiple of `r` out of `len` and returns the
/// remainder, as the authority's contract says.
///
/// # Safety
/// `inp` must be readable for `len` bytes.
pub(crate) unsafe fn sha3_absorb(
    a: &mut [u64; 25],
    inp: *const u8,
    mut len: usize,
    r: usize,
) -> usize {
    let w = r / 8;
    let mut inp = inp;
    while len >= r {
        for (i, lane) in a.iter_mut().take(w).enumerate() {
            // SAFETY: `len >= r` and `i < w`, so `i*8+8 <= r <= len` bytes are readable.
            *lane ^= unsafe { load_le64(inp.add(i * 8)) };
        }
        keccakf1600(a);
        // SAFETY: `r <= len` bytes were read, so advancing by `r` stays in bounds.
        inp = unsafe { inp.add(r) };
        len -= r;
    }
    len
}

/// `void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r, int next)` —
/// `keccak1600.c:1126-1161`.
///
/// # Safety
/// `out` must be writable for `len` bytes.
pub(crate) unsafe fn sha3_squeeze(
    a: &mut [u64; 25],
    out: *mut u8,
    mut len: usize,
    r: usize,
    mut next: bool,
) {
    let w = r / 8;
    let mut out = out;
    while len != 0 {
        if next {
            keccakf1600(a);
        }
        next = true;
        let mut i = 0;
        while i < w && len != 0 {
            let ai = a[i];
            if len < 8 {
                for k in 0..len {
                    // SAFETY: `k < len` bytes remain at `out`.
                    unsafe { *out.add(k) = (ai >> (8 * k)) as u8 };
                }
                return;
            }
            // SAFETY: eight bytes remain at `out`.
            unsafe { store_le64(out, ai) };
            // SAFETY: as above; advancing eight stays inside the caller's buffer.
            out = unsafe { out.add(8) };
            len -= 8;
            i += 1;
        }
    }
}

/// `void ossl_sha3_reset(KECCAK1600_CTX *ctx)` — `crypto/sha/sha3.c:18-26`.
///
/// # Safety
/// `ctx` must be a live context.
pub(crate) unsafe fn ossl_sha3_reset(ctx: *mut KeccakCtx) {
    // SAFETY: `ctx` is live per the caller's contract.
    unsafe {
        ptr::write_bytes((*ctx).a.as_mut_ptr(), 0, 25);
        (*ctx).bufsz = 0;
        (*ctx).xof_state = XOF_STATE_INIT;
    }
}

/// `int ossl_sha3_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen)` —
/// `crypto/sha/sha3.c:28-41`.
///
/// # Safety
/// `ctx` must be a live context.
pub(crate) unsafe fn ossl_sha3_init(ctx: *mut KeccakCtx, pad: u8, bitlen: usize) -> c_int {
    let bsz = sha3_blocksize(bitlen);
    if bsz <= KECCAK_BUF_LEN {
        // SAFETY: `ctx` is live.
        unsafe {
            ossl_sha3_reset(ctx);
            (*ctx).block_size = bsz;
            (*ctx).md_size = bitlen / 8;
            (*ctx).pad = pad;
        }
        return 1;
    }
    0
}

/// `int ossl_keccak_init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen, size_t mdlen)` —
/// `crypto/sha/sha3.c:43-50`.
///
/// # Safety
/// `ctx` must be a live context.
pub(crate) unsafe fn ossl_keccak_init(
    ctx: *mut KeccakCtx,
    pad: u8,
    bitlen: usize,
    mdlen: usize,
) -> c_int {
    // SAFETY: `ctx` is live.
    let ret = unsafe { ossl_sha3_init(ctx, pad, bitlen) };
    if ret != 0 {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).md_size = mdlen / 8 };
    }
    ret
}

/// `int ossl_sha3_update(KECCAK1600_CTX *ctx, const void *_inp, size_t len)` —
/// `crypto/sha/sha3.c:52-96`.
///
/// # Safety
/// `ctx` must be a live context; `inp` readable for `len` bytes.
pub(crate) unsafe fn ossl_sha3_update(ctx: *mut KeccakCtx, inp: *const u8, len: usize) -> c_int {
    if len == 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let xof_state = unsafe { (*ctx).xof_state };
    if xof_state == XOF_STATE_SQUEEZE || xof_state == XOF_STATE_FINAL {
        return 0;
    }

    // SAFETY: `ctx` is live.
    let bsz = unsafe { (*ctx).block_size };
    let mut inp = inp;
    let mut len = len;

    // SAFETY: `ctx` is live.
    let num = unsafe { (*ctx).bufsz };
    if num != 0 {
        let rem = bsz - num;
        if len < rem {
            // SAFETY: `rem > len` bytes remain in `buf` from `num`, and `inp` is readable for
            // `len`; the two regions are distinct.
            unsafe {
                ptr::copy_nonoverlapping(inp, (*ctx).buf.as_mut_ptr().add(num), len);
                (*ctx).bufsz += len;
            }
            return 1;
        }
        // SAFETY: `rem` bytes fill the buffer and `inp` is readable for `rem`.
        unsafe {
            ptr::copy_nonoverlapping(inp, (*ctx).buf.as_mut_ptr().add(num), rem);
        }
        // SAFETY: `inp` is readable for `len >= rem`; `rem` bytes are consumed.
        inp = unsafe { inp.add(rem) };
        len -= rem;
        // SAFETY: `ctx` is live; the buffer holds a full block.
        let remaining = unsafe { sha3_absorb(&mut (*ctx).a, (*ctx).buf.as_ptr(), bsz, bsz) };
        let _ = remaining;
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).bufsz = 0 };
    }

    let rem = if len >= bsz {
        // SAFETY: `inp` is readable for `len` bytes.
        unsafe { sha3_absorb(&mut (*ctx).a, inp, len, bsz) }
    } else {
        len
    };

    if rem != 0 {
        // SAFETY: `rem` bytes remain at `inp + len - rem` and are copied into `buf`.
        unsafe {
            ptr::copy_nonoverlapping(inp.add(len - rem), (*ctx).buf.as_mut_ptr(), rem);
            (*ctx).bufsz = rem;
        }
    }
    1
}

/// The trailing `10*1` padding plus the final absorb, shared by `final` and `squeeze` —
/// `crypto/sha/sha3.c:119-123` and `:164-167`.
///
/// # Safety
/// `ctx` must be a live context.
unsafe fn pad_and_absorb(ctx: *mut KeccakCtx) {
    // SAFETY: `ctx` is live.
    let bsz = unsafe { (*ctx).block_size };
    // SAFETY: `ctx` is live.
    let num = unsafe { (*ctx).bufsz };
    // SAFETY: `num < bsz`, so the two writes stay inside the staging buffer.
    unsafe {
        ptr::write_bytes((*ctx).buf.as_mut_ptr().add(num), 0, bsz - num);
        (*ctx).buf[num] = (*ctx).pad;
        (*ctx).buf[bsz - 1] |= 0x80;
        sha3_absorb(&mut (*ctx).a, (*ctx).buf.as_ptr(), bsz, bsz);
    }
}

/// `int ossl_sha3_final(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)` —
/// `crypto/sha/sha3.c:103-128`. The single-shot final; `ossl_sha3_squeeze` is the repeatable one.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for `outlen` bytes.
pub(crate) unsafe fn ossl_sha3_final(ctx: *mut KeccakCtx, out: *mut u8, outlen: usize) -> c_int {
    if outlen == 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let xof_state = unsafe { (*ctx).xof_state };
    if xof_state == XOF_STATE_SQUEEZE || xof_state == XOF_STATE_FINAL {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let bsz = unsafe { (*ctx).block_size };
    // SAFETY: `ctx` is live.
    unsafe {
        pad_and_absorb(ctx);
        (*ctx).xof_state = XOF_STATE_FINAL;
        sha3_squeeze(&mut (*ctx).a, out, outlen, bsz, false);
    }
    1
}

/// `int ossl_sha3_squeeze(KECCAK1600_CTX *ctx, unsigned char *out, size_t outlen)` —
/// `crypto/sha/sha3.c:140-207`.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for `outlen` bytes.
pub(crate) unsafe fn ossl_sha3_squeeze(ctx: *mut KeccakCtx, out: *mut u8, outlen: usize) -> c_int {
    if outlen == 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).xof_state } == XOF_STATE_FINAL {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let bsz = unsafe { (*ctx).block_size };
    // SAFETY: `ctx` is live.
    let mut num = unsafe { (*ctx).bufsz };
    let mut next = true;

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).xof_state } != XOF_STATE_SQUEEZE {
        // SAFETY: `ctx` is live.
        unsafe {
            pad_and_absorb(ctx);
            (*ctx).xof_state = XOF_STATE_SQUEEZE;
            (*ctx).bufsz = 0;
        }
        num = 0;
        next = false;
    }

    let mut out = out;
    let mut outlen = outlen;

    // Step 1: consume bytes left over from a previous squeeze.
    if num != 0 {
        // SAFETY: `ctx` is live.
        let bufsz = unsafe { (*ctx).bufsz };
        let len = if outlen > bufsz { bufsz } else { outlen };
        // SAFETY: `bufsz` bytes at `buf[bsz - bufsz]` are readable and `out` is writable for
        // `len <= bufsz`.
        unsafe {
            ptr::copy_nonoverlapping((*ctx).buf.as_ptr().add(bsz - bufsz), out, len);
            (*ctx).bufsz -= len;
        }
        // SAFETY: `len` bytes were written, so advancing stays inside `out`.
        out = unsafe { out.add(len) };
        outlen -= len;
    }
    if outlen == 0 {
        return 1;
    }

    // Step 2: full squeezed blocks go straight to the output.
    if outlen >= bsz {
        let len = bsz * (outlen / bsz);
        // SAFETY: `out` is writable for `len` and the state is live.
        unsafe { sha3_squeeze(&mut (*ctx).a, out, len, bsz, next) };
        next = true;
        // SAFETY: `len` bytes were written.
        out = unsafe { out.add(len) };
        outlen -= len;
    }
    if outlen > 0 {
        // Step 3: squeeze one more block into the buffer.
        // SAFETY: `ctx` is live and `buf` is `bsz` bytes; `out` is writable for `outlen`.
        unsafe {
            sha3_squeeze(&mut (*ctx).a, (*ctx).buf.as_mut_ptr(), bsz, bsz, next);
            ptr::copy_nonoverlapping((*ctx).buf.as_ptr(), out, outlen);
            (*ctx).bufsz = bsz - outlen;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pad: u8) -> KeccakCtx {
        KeccakCtx {
            a: [0; 25],
            buf: [0; KECCAK_BUF_LEN],
            block_size: 0,
            md_size: 0,
            bufsz: 0,
            pad,
            xof_state: XOF_STATE_INIT,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// FIPS 202's own examples — the SHA-3 fixed-width vectors and the SHAKE128 `abc` prefix.
    #[test]
    fn the_standard_vectors() {
        let cases: [(u8, usize, usize, &str, &str); 5] = [
            (
                0x06,
                224,
                28,
                "abc",
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            ),
            (
                0x06,
                256,
                32,
                "abc",
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ),
            (
                0x06,
                384,
                48,
                "abc",
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
            ),
            (
                0x06,
                512,
                64,
                "abc",
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            ),
            (
                0x1f,
                128,
                32,
                "abc",
                "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
            ),
        ];
        for (pad, bitlen, outlen, input, want) in cases {
            let mut c = ctx(pad);
            let mut out = [0u8; 64];
            // SAFETY: every pointer below is a live local of this test.
            unsafe {
                assert_eq!(ossl_sha3_init(&mut c, pad, bitlen), 1);
                assert_eq!(ossl_sha3_update(&mut c, input.as_ptr(), input.len()), 1);
                assert_eq!(ossl_sha3_final(&mut c, out.as_mut_ptr(), outlen), 1);
            }
            assert_eq!(hex(&out[..outlen]), want, "pad {pad:#x} bitlen {bitlen}");
        }
    }

    /// The squeeze is repeatable: two `ossl_sha3_squeeze` calls give `n1 + n2` bytes of the same
    /// stream a single call of that length gives.
    #[test]
    fn the_squeeze_repeats_across_slices() {
        let input = b"abc";
        let mut one = ctx(0x1f);
        let mut split = ctx(0x1f);
        let mut whole = [0u8; 48];
        let mut a = [0u8; 17];
        let mut b = [0u8; 31];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(ossl_sha3_init(&mut one, 0x1f, 128), 1);
            assert_eq!(ossl_sha3_update(&mut one, input.as_ptr(), input.len()), 1);
            assert_eq!(ossl_sha3_final(&mut one, whole.as_mut_ptr(), 48), 1);

            assert_eq!(ossl_sha3_init(&mut split, 0x1f, 128), 1);
            assert_eq!(ossl_sha3_update(&mut split, input.as_ptr(), input.len()), 1);
            assert_eq!(ossl_sha3_squeeze(&mut split, a.as_mut_ptr(), 17), 1);
            assert_eq!(ossl_sha3_squeeze(&mut split, b.as_mut_ptr(), 31), 1);
        }
        assert_eq!(hex(&whole[..17]), hex(&a));
        assert_eq!(hex(&whole[17..]), hex(&b));
    }
}
