//! Phase 8.1b — `providers/implementations/digests/blake2b_prov.c` and `blake2s_prov.c`: BLAKE2.
//!
//! BLAKE2 is the one construction in this subphase whose authority file is the *provider* file:
//! `crypto/blake2/` does not exist, and `blake2b_prov.c`/`blake2s_prov.c` carry the whole
//! algorithm — the IV, the parameter block, the `SIGMA` schedule, the compression, the
//! update/final pair — beside the dispatch. That is the reading `docs/DECISIONS.md` D198 recorded
//! for an earlier deferral row that named a directory the authority does not have, and it is why
//! this module is transcribed from the provider files rather than from `crypto/`.
//!
//! ## No export, and the legacy wrappers are not this slice's
//!
//! `EVP_blake2b512`/`EVP_blake2s256` are Phase 13's (`forensics/prerequisites.json`), so the only
//! surface here is the provider row: `defltprov.c:140-141` publishes `BLAKE2S-256` and
//! `BLAKE2B-512` from `ossl_blake2s256_functions`/`ossl_blake2b512_functions`. Nothing carries
//! `#[no_mangle]`.
//!
//! ## The parameter block is a byte image, deliberately
//!
//! `blake2b_init_param` XORs the chaining words with the parameter struct read as *bytes*
//! (`load64((const uint8_t *)P + 8*i)`), so the struct's layout is part of the algorithm. This
//! module carries the parameter block as a `[u8; 64]`/`[u8; 32]` image with the authority's field
//! offsets, which is what makes that read a transcription rather than a reinterpretation.
//!
//! ## The provider context is the context plus its parameters
//!
//! `struct blake2b_md_data_st { BLAKE2B_CTX ctx; BLAKE2B_PARAM params; }` — the authority's
//! provider keeps the parameters beside the state so a `size` set before `init` survives the
//! re-initialisation. [`blake2b::MdData`] and [`blake2s::MdData`] are that struct, `ctx` first, so
//! the dispatch's `UPDATE`/`FINAL` callbacks (which take the provider context pointer) can treat
//! it as the bare context exactly as the C casts do.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

/// `load32` — `blake2_impl.h:20-35`, little-endian.
///
/// # Safety
/// `p` must be readable for four bytes.
#[inline]
unsafe fn load32(p: *const u8) -> u32 {
    let mut b = [0u8; 4];
    // SAFETY: the caller guarantees four readable bytes.
    unsafe { ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4) };
    u32::from_le_bytes(b)
}

/// `store32` — `blake2_impl.h:58-71`.
///
/// # Safety
/// `p` must be writable for four bytes.
#[inline]
unsafe fn store32(p: *mut u8, v: u32) {
    let b = v.to_le_bytes();
    // SAFETY: the caller guarantees four writable bytes.
    unsafe { ptr::copy_nonoverlapping(b.as_ptr(), p, 4) };
}

/// `load64` — `blake2_impl.h:37-56`.
///
/// # Safety
/// `p` must be readable for eight bytes.
#[inline]
unsafe fn load64(p: *const u8) -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: the caller guarantees eight readable bytes.
    unsafe { ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8) };
    u64::from_le_bytes(b)
}

/// `store64` — `blake2_impl.h:73-86`.
///
/// # Safety
/// `p` must be writable for eight bytes.
#[inline]
unsafe fn store64(p: *mut u8, v: u64) {
    let b = v.to_le_bytes();
    // SAFETY: the caller guarantees eight writable bytes.
    unsafe { ptr::copy_nonoverlapping(b.as_ptr(), p, 8) };
}

/// `crypto/blake2` does not exist in the authority; the algorithm lives in this file's two
/// provider transcription units.
pub mod blake2b {
    use core::ffi::c_int;
    use core::ptr;

    use super::{load64, store64};

    /// `BLAKE2B_BLOCKBYTES` — `prov/blake2.h:25`.
    pub const BLOCKBYTES: usize = 128;
    /// `BLAKE2B_OUTBYTES` — `prov/blake2.h:26`.
    pub const OUTBYTES: usize = 64;
    /// `BLAKE2B_DIGEST_LENGTH` — `prov/blake2.h:80`.
    pub const DIGEST_LENGTH: u8 = 64;

    /// `blake2b_IV` — `blake2b_prov.c:24-29`.
    const IV: [u64; 8] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];

    /// `blake2b_sigma` — `blake2b_prov.c:31-44`.
    const SIGMA: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];

    /// `BLAKE2B_PARAM` — `prov/blake2.h:55-67`, as a byte image: `digest_length`, `key_length`,
    /// `fanout`, `depth`, `leaf_length[4]`, `node_offset[8]`, `node_depth`, `inner_length`,
    /// `reserved[14]`, `salt[16]`, `personal[16]`.
    #[repr(C)]
    pub struct Param {
        /// The parameter block's bytes.
        pub b: [u8; 64],
    }

    /// `BLAKE2B_CTX` — `prov/blake2.h:71-78`.
    #[repr(C)]
    pub struct Ctx {
        /// `uint64_t h[8]` — the chaining state.
        pub h: [u64; 8],
        /// `uint64_t t[2]` — the byte counter.
        pub t: [u64; 2],
        /// `uint64_t f[2]` — the last-block flag.
        pub f: [u64; 2],
        /// `uint8_t buf[]` — the staged block.
        pub buf: [u8; BLOCKBYTES],
        /// `size_t buflen`.
        pub buflen: usize,
        /// `size_t outlen`.
        pub outlen: usize,
    }

    /// `struct blake2b_md_data_st` — `prov/blake2.h:86-89`.
    #[repr(C)]
    pub struct MdData {
        /// `BLAKE2B_CTX ctx`.
        pub ctx: Ctx,
        /// `BLAKE2B_PARAM params`.
        pub params: Param,
    }

    /// `ossl_blake2b_param_init` — `blake2b_prov.c:82-95`.
    pub fn param_init(p: &mut Param) {
        p.b = [0u8; 64];
        p.b[0] = DIGEST_LENGTH;
        p.b[1] = 0;
        p.b[2] = 1;
        p.b[3] = 1;
    }

    /// `ossl_blake2b_param_set_digest_length` — `blake2b_prov.c:97-100`.
    pub fn param_set_digest_length(p: &mut Param, outlen: u8) {
        p.b[0] = outlen;
    }

    /// `blake2b_set_lastblock` — `blake2b_prov.c:47-50`.
    fn set_lastblock(s: &mut Ctx) {
        s.f[0] = u64::MAX;
    }

    /// `blake2b_init0` — `blake2b_prov.c:53-61`.
    fn init0(s: &mut Ctx) {
        // `memset(S, 0, sizeof(*S))` then the IV into `h`.
        // SAFETY: `s` is a live `Ctx` and zeroing its bytes is what the authority's memset does.
        unsafe {
            ptr::write_bytes(s as *mut Ctx as *mut u8, 0, core::mem::size_of::<Ctx>());
        }
        s.h = IV;
    }

    /// `blake2b_init_param` — `blake2b_prov.c:64-79`.
    fn init_param(s: &mut Ctx, p: &Param) {
        init0(s);
        s.outlen = p.b[0] as usize;
        for i in 0..8 {
            // SAFETY: the parameter image is 64 bytes and `i < 8`, so `8*i+8 <= 64`.
            s.h[i] ^= unsafe { load64(p.b.as_ptr().add(i * 8)) };
        }
    }

    /// `ossl_blake2b_init` — `blake2b_prov.c:125-129`.
    ///
    /// # Safety
    /// `c` and `p` must be live.
    pub unsafe fn init(c: *mut Ctx, p: *const Param) {
        // SAFETY: both are live per the caller's contract.
        unsafe { init_param(&mut *c, &*p) };
    }

    /// One `G` — `blake2b_prov.c:204-214`.
    #[allow(clippy::too_many_arguments)]
    fn g(
        v: &mut [u64; 16],
        m: &[u64; 16],
        r: usize,
        i: usize,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    ) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i]]);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i + 1]]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    /// `blake2b_compress` — `blake2b_prov.c:153-254`.
    ///
    /// # Safety
    /// `blocks` must be readable for `len` bytes.
    unsafe fn compress(s: &mut Ctx, blocks: *const u8, mut len: usize) {
        let increment = if len < BLOCKBYTES { len } else { BLOCKBYTES };
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&s.h);
        let mut blocks = blocks;
        loop {
            let mut m = [0u64; 16];
            for (i, word) in m.iter_mut().enumerate() {
                // SAFETY: the loop's contract makes `increment`-aligned blocks readable; here at
                // least 16 words are read from the current block, which `compress`'s assertion
                // (a full block, or the final short one) allows for the callers below.
                *word = unsafe { load64(blocks.add(i * 8)) };
            }
            s.t[0] = s.t[0].wrapping_add(increment as u64);
            s.t[1] = s.t[1].wrapping_add(u64::from(s.t[0] < increment as u64));
            v[8] = IV[0];
            v[9] = IV[1];
            v[10] = IV[2];
            v[11] = IV[3];
            v[12] = s.t[0] ^ IV[4];
            v[13] = s.t[1] ^ IV[5];
            v[14] = s.f[0] ^ IV[6];
            v[15] = s.f[1] ^ IV[7];
            for r in 0..12 {
                g(&mut v, &m, r, 0, 0, 4, 8, 12);
                g(&mut v, &m, r, 1, 1, 5, 9, 13);
                g(&mut v, &m, r, 2, 2, 6, 10, 14);
                g(&mut v, &m, r, 3, 3, 7, 11, 15);
                g(&mut v, &m, r, 4, 0, 5, 10, 15);
                g(&mut v, &m, r, 5, 1, 6, 11, 12);
                g(&mut v, &m, r, 6, 2, 7, 8, 13);
                g(&mut v, &m, r, 7, 3, 4, 9, 14);
            }
            for i in 0..8 {
                v[i] ^= v[i + 8] ^ s.h[i];
            }
            s.h.copy_from_slice(&v[..8]);
            // SAFETY: `increment <= len`, so advancing stays inside the caller's region.
            blocks = unsafe { blocks.add(increment) };
            len -= increment;
            if len == 0 {
                break;
            }
            // The `do … while (len)` body always advances by a full block after the first pass.
        }
    }

    /// `ossl_blake2b_update` — `blake2b_prov.c:257-299`.
    ///
    /// # Safety
    /// `c` must be live; `data` readable for `datalen` bytes.
    pub unsafe fn update(c: *mut Ctx, data: *const u8, datalen: usize) -> c_int {
        // SAFETY: `c` is live.
        let s = unsafe { &mut *c };
        let mut in_ = data;
        let mut datalen = datalen;
        let fill = BLOCKBYTES - s.buflen;
        if datalen > fill {
            if s.buflen != 0 {
                // SAFETY: `in_` is readable for `fill` bytes and `fill` fills the staged buffer.
                unsafe {
                    ptr::copy_nonoverlapping(in_, s.buf.as_mut_ptr().add(s.buflen), fill);
                    compress(s, s.buf.as_ptr(), BLOCKBYTES);
                }
                s.buflen = 0;
                // SAFETY: `fill <= datalen`.
                in_ = unsafe { in_.add(fill) };
                datalen -= fill;
            }
            if datalen > BLOCKBYTES {
                let mut stashlen = datalen % BLOCKBYTES;
                if stashlen == 0 {
                    stashlen = BLOCKBYTES;
                }
                datalen -= stashlen;
                // SAFETY: `in_` is readable for `datalen` bytes.
                unsafe { compress(s, in_, datalen) };
                // SAFETY: as above.
                in_ = unsafe { in_.add(datalen) };
                datalen = stashlen;
            }
        }
        // SAFETY: `datalen <= BLOCKBYTES` here and `in_` is readable for it.
        unsafe {
            ptr::copy_nonoverlapping(in_, s.buf.as_mut_ptr().add(s.buflen), datalen);
        }
        s.buflen += datalen;
        1
    }

    /// `ossl_blake2b_final` — `blake2b_prov.c:305-332`.
    ///
    /// # Safety
    /// `c` must be live; `md` writable for `c.outlen` bytes.
    pub unsafe fn final_(md: *mut u8, c: *mut Ctx) -> c_int {
        // SAFETY: `c` is live.
        let s = unsafe { &mut *c };
        let outlen = s.outlen;
        set_lastblock(s);
        // Padding.
        // SAFETY: `buflen <= BLOCKBYTES`, so the range is inside `buf`.
        unsafe {
            ptr::write_bytes(s.buf.as_mut_ptr().add(s.buflen), 0, BLOCKBYTES - s.buflen);
            compress(s, s.buf.as_ptr(), s.buflen);
        }
        let iter = outlen.div_ceil(8);
        let mut outbuffer = [0u8; OUTBYTES];
        for i in 0..iter {
            // SAFETY: `i < iter <= 8`, so `8*i+8 <= 64 = OUTBYTES`.
            unsafe { store64(outbuffer.as_mut_ptr().add(i * 8), s.h[i]) };
        }
        // SAFETY: `md` is writable for `outlen <= OUTBYTES` bytes per the caller.
        unsafe { ptr::copy_nonoverlapping(outbuffer.as_ptr(), md, outlen) };
        // `OPENSSL_cleanse(c, sizeof(*c))`.
        // SAFETY: `s` is live.
        unsafe { ptr::write_bytes(s as *mut Ctx as *mut u8, 0, core::mem::size_of::<Ctx>()) };
        1
    }
}

/// The 32-bit sibling, transcribed from `blake2s_prov.c`.
pub mod blake2s {
    use core::ffi::c_int;
    use core::ptr;

    use super::{load32, store32};

    /// `BLAKE2S_BLOCKBYTES` — `prov/blake2.h:19`.
    pub const BLOCKBYTES: usize = 64;
    /// `BLAKE2S_OUTBYTES` — `prov/blake2.h:20`.
    pub const OUTBYTES: usize = 32;
    /// `BLAKE2S_DIGEST_LENGTH` — `prov/blake2.h:81`.
    pub const DIGEST_LENGTH: u8 = 32;

    /// `blake2s_IV` — `blake2s_prov.c:23-26`.
    const IV: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    /// `blake2s_sigma` — `blake2s_prov.c:28-39`.
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /// `BLAKE2S_PARAM` — `prov/blake2.h:31-42`, as a byte image: `digest_length`, `key_length`,
    /// `fanout`, `depth`, `leaf_length[4]`, `node_offset[6]`, `node_depth`, `inner_length`,
    /// `salt[8]`, `personal[8]`.
    #[repr(C)]
    pub struct Param {
        /// The parameter block's bytes.
        pub b: [u8; 32],
    }

    /// `BLAKE2S_CTX` — `prov/blake2.h:46-53`.
    #[repr(C)]
    pub struct Ctx {
        /// `uint32_t h[8]`.
        pub h: [u32; 8],
        /// `uint32_t t[2]`.
        pub t: [u32; 2],
        /// `uint32_t f[2]`.
        pub f: [u32; 2],
        /// `uint8_t buf[]`.
        pub buf: [u8; BLOCKBYTES],
        /// `size_t buflen`.
        pub buflen: usize,
        /// `size_t outlen`.
        pub outlen: usize,
    }

    /// `struct blake2s_md_data_st` — `prov/blake2.h:91-94`.
    #[repr(C)]
    pub struct MdData {
        /// `BLAKE2S_CTX ctx`.
        pub ctx: Ctx,
        /// `BLAKE2S_PARAM params`.
        pub params: Param,
    }

    /// `ossl_blake2s_param_init` — `blake2s_prov.c:76-88`.
    pub fn param_init(p: &mut Param) {
        p.b = [0u8; 32];
        p.b[0] = DIGEST_LENGTH;
        p.b[1] = 0;
        p.b[2] = 1;
        p.b[3] = 1;
    }

    /// `ossl_blake2s_param_set_digest_length` — `blake2s_prov.c:90-93`.
    pub fn param_set_digest_length(p: &mut Param, outlen: u8) {
        p.b[0] = outlen;
    }

    /// `blake2s_set_lastblock` — `blake2s_prov.c:42-45`.
    fn set_lastblock(s: &mut Ctx) {
        s.f[0] = u32::MAX;
    }

    /// `blake2s_init0` — `blake2s_prov.c:48-56`.
    fn init0(s: &mut Ctx) {
        // SAFETY: `s` is a live `Ctx`; the authority's memset zeroes exactly this.
        unsafe {
            ptr::write_bytes(s as *mut Ctx as *mut u8, 0, core::mem::size_of::<Ctx>());
        }
        s.h = IV;
    }

    /// `blake2s_init_param` — `blake2s_prov.c:59-74`.
    fn init_param(s: &mut Ctx, p: &Param) {
        init0(s);
        s.outlen = p.b[0] as usize;
        for i in 0..8 {
            // SAFETY: the parameter image is 32 bytes and `i < 8`, so `4*i+4 <= 32`.
            s.h[i] ^= unsafe { load32(p.b.as_ptr().add(i * 4)) };
        }
    }

    /// `ossl_blake2s_init` — `blake2s_prov.c:118-122`.
    ///
    /// # Safety
    /// `c` and `p` must be live.
    pub unsafe fn init(c: *mut Ctx, p: *const Param) {
        // SAFETY: both are live per the caller's contract.
        unsafe { init_param(&mut *c, &*p) };
    }

    /// One `G` — `blake2s_prov.c:197-207`.
    #[allow(clippy::too_many_arguments)]
    fn g(
        v: &mut [u32; 16],
        m: &[u32; 16],
        r: usize,
        i: usize,
        a: usize,
        b: usize,
        c: usize,
        d: usize,
    ) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i]]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[SIGMA[r][2 * i + 1]]);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    /// `blake2s_compress` — `blake2s_prov.c:146-245`.
    ///
    /// # Safety
    /// `blocks` must be readable for `len` bytes.
    unsafe fn compress(s: &mut Ctx, blocks: *const u8, mut len: usize) {
        let increment = if len < BLOCKBYTES {
            len as u32
        } else {
            BLOCKBYTES as u32
        };
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&s.h);
        let mut blocks = blocks;
        loop {
            let mut m = [0u32; 16];
            for (i, word) in m.iter_mut().enumerate() {
                // SAFETY: see the 64-bit sibling's note; the callers only compress full blocks or
                // the final padded block.
                *word = unsafe { load32(blocks.add(i * 4)) };
            }
            s.t[0] = s.t[0].wrapping_add(increment);
            s.t[1] = s.t[1].wrapping_add(u32::from(s.t[0] < increment));
            v[8] = IV[0];
            v[9] = IV[1];
            v[10] = IV[2];
            v[11] = IV[3];
            v[12] = s.t[0] ^ IV[4];
            v[13] = s.t[1] ^ IV[5];
            v[14] = s.f[0] ^ IV[6];
            v[15] = s.f[1] ^ IV[7];
            for r in 0..10 {
                g(&mut v, &m, r, 0, 0, 4, 8, 12);
                g(&mut v, &m, r, 1, 1, 5, 9, 13);
                g(&mut v, &m, r, 2, 2, 6, 10, 14);
                g(&mut v, &m, r, 3, 3, 7, 11, 15);
                g(&mut v, &m, r, 4, 0, 5, 10, 15);
                g(&mut v, &m, r, 5, 1, 6, 11, 12);
                g(&mut v, &m, r, 6, 2, 7, 8, 13);
                g(&mut v, &m, r, 7, 3, 4, 9, 14);
            }
            for i in 0..8 {
                v[i] ^= v[i + 8] ^ s.h[i];
            }
            s.h.copy_from_slice(&v[..8]);
            // SAFETY: `increment <= len`, so advancing stays inside the caller's region.
            blocks = unsafe { blocks.add(increment as usize) };
            len -= increment as usize;
            if len == 0 {
                break;
            }
        }
    }

    /// `ossl_blake2s_update` — `blake2s_prov.c:248-290`.
    ///
    /// # Safety
    /// `c` must be live; `data` readable for `datalen` bytes.
    pub unsafe fn update(c: *mut Ctx, data: *const u8, datalen: usize) -> c_int {
        // SAFETY: `c` is live.
        let s = unsafe { &mut *c };
        let mut in_ = data;
        let mut datalen = datalen;
        let fill = BLOCKBYTES - s.buflen;
        if datalen > fill {
            if s.buflen != 0 {
                // SAFETY: `in_` is readable for `fill` bytes and `fill` fills the staged buffer.
                unsafe {
                    ptr::copy_nonoverlapping(in_, s.buf.as_mut_ptr().add(s.buflen), fill);
                    compress(s, s.buf.as_ptr(), BLOCKBYTES);
                }
                s.buflen = 0;
                // SAFETY: `fill <= datalen`.
                in_ = unsafe { in_.add(fill) };
                datalen -= fill;
            }
            if datalen > BLOCKBYTES {
                let mut stashlen = datalen % BLOCKBYTES;
                if stashlen == 0 {
                    stashlen = BLOCKBYTES;
                }
                datalen -= stashlen;
                // SAFETY: `in_` is readable for `datalen` bytes.
                unsafe { compress(s, in_, datalen) };
                // SAFETY: as above.
                in_ = unsafe { in_.add(datalen) };
                datalen = stashlen;
            }
        }
        // SAFETY: `datalen <= BLOCKBYTES` here and `in_` is readable for it.
        unsafe {
            ptr::copy_nonoverlapping(in_, s.buf.as_mut_ptr().add(s.buflen), datalen);
        }
        s.buflen += datalen;
        1
    }

    /// `ossl_blake2s_final` — `blake2s_prov.c:296-323`.
    ///
    /// # Safety
    /// `c` must be live; `md` writable for `c.outlen` bytes.
    pub unsafe fn final_(md: *mut u8, c: *mut Ctx) -> c_int {
        // SAFETY: `c` is live.
        let s = unsafe { &mut *c };
        let outlen = s.outlen;
        set_lastblock(s);
        // SAFETY: `buflen <= BLOCKBYTES`, so the range is inside `buf`.
        unsafe {
            ptr::write_bytes(s.buf.as_mut_ptr().add(s.buflen), 0, BLOCKBYTES - s.buflen);
            compress(s, s.buf.as_ptr(), s.buflen);
        }
        let iter = outlen.div_ceil(4);
        let mut outbuffer = [0u8; OUTBYTES];
        for i in 0..iter {
            // SAFETY: `i < iter <= 8`, so `4*i+4 <= 32 = OUTBYTES`.
            unsafe { store32(outbuffer.as_mut_ptr().add(i * 4), s.h[i]) };
        }
        // SAFETY: `md` is writable for `outlen <= OUTBYTES` bytes per the caller.
        unsafe { ptr::copy_nonoverlapping(outbuffer.as_ptr(), md, outlen) };
        // SAFETY: `s` is live.
        unsafe { ptr::write_bytes(s as *mut Ctx as *mut u8, 0, core::mem::size_of::<Ctx>()) };
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BLAKE2 reference implementation's own published vectors for `abc`.
    #[test]
    fn the_published_vectors() {
        let mut b = blake2b::Ctx {
            h: [0; 8],
            t: [0; 2],
            f: [0; 2],
            buf: [0; blake2b::BLOCKBYTES],
            buflen: 0,
            outlen: 0,
        };
        let mut param = blake2b::Param { b: [0; 64] };
        blake2b::param_init(&mut param);
        let mut out = [0u8; blake2b::OUTBYTES];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            blake2b::init(&mut b, &param);
            assert_eq!(blake2b::update(&mut b, b"abc".as_ptr(), 3), 1);
            assert_eq!(blake2b::final_(out.as_mut_ptr(), &mut b), 1);
        }
        assert_eq!(
            hex(&out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );

        let mut s = blake2s::Ctx {
            h: [0; 8],
            t: [0; 2],
            f: [0; 2],
            buf: [0; blake2s::BLOCKBYTES],
            buflen: 0,
            outlen: 0,
        };
        let mut param = blake2s::Param { b: [0; 32] };
        blake2s::param_init(&mut param);
        let mut out = [0u8; blake2s::OUTBYTES];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            blake2s::init(&mut s, &param);
            assert_eq!(blake2s::update(&mut s, b"abc".as_ptr(), 3), 1);
            assert_eq!(blake2s::final_(out.as_mut_ptr(), &mut s), 1);
        }
        assert_eq!(
            hex(&out),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
