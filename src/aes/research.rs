//! Test-only research court for the PFP-63 portable AES.
//!
//! It carries the constructions that were evaluated and the benchmark that decided
//! which one ships:
//!
//! * `table` — the pre-conversion S-box table (differential reference);
//! * `bytewise` — the Boolean field-exponentiation circuit evaluated one byte at a
//!   time;
//! * `composite` — a genuine GF((2^4)^2) tower S-box (basis change, tower inverse,
//!   affine map), with the isomorphism and its inverse derived from public constants
//!   at first use;
//! * `bitsliced` — the same Boolean field-exponentiation circuit applied to all
//!   sixteen state bytes in parallel (the PFP-63 selection).
//!
//! PFP-70 added the Boyar–Peralta–Calik circuit, a planar driver, a fixed-slice
//! driver and a 16/32/64-bit-lane comparison; `pfp70_benchmarks` and
//! `pfp70_wide_lane_benchmarks` are the measurements that selected the
//! fixed-slice arm now dispatched by `portable::encrypt_block`.
//!
//! Nothing here is compiled into a production artefact.
//!
//! SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use core::ops::{BitAnd, BitOr, BitXor, BitXorAssign, Not, Shl, Shr};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use crate::digest::tables::AES_SBOX;

use super::portable;
use super::reference;

/// GF(2^4) with `x^4 + x + 1`, elements in the low nibble.
#[inline]
fn gf16_mul(a: u8, b: u8) -> u8 {
    let mut r = 0u8;
    let mut aa = a & 0xf;
    let mut bb = b & 0xf;
    let mut i = 0;
    while i < 4 {
        r ^= aa & 0u8.wrapping_sub(bb & 1);
        let hi = aa >> 3;
        aa = ((aa << 1) & 0xf) ^ (0x3 & 0u8.wrapping_sub(hi));
        bb >>= 1;
        i += 1;
    }
    r
}

#[inline]
fn gf16_square(a: u8) -> u8 {
    gf16_mul(a, a)
}

/// `a^14`, the multiplicative inverse in GF(2^4), with `0` mapped to `0`.
#[inline]
fn gf16_inv(a: u8) -> u8 {
    let a2 = gf16_square(a);
    let a4 = gf16_square(a2);
    let a8 = gf16_square(a4);
    gf16_mul(gf16_mul(a8, a4), a2)
}

/// Tower element `h*y + l`, stored as `(h << 4) | l`.
#[inline]
fn tower_mul(a: u16, b: u16, lambda: u8) -> u16 {
    let h1 = (a >> 4) as u8;
    let l1 = (a & 0xf) as u8;
    let h2 = (b >> 4) as u8;
    let l2 = (b & 0xf) as u8;
    let hh = gf16_mul(h1, h2);
    let high = hh ^ gf16_mul(h1, l2) ^ gf16_mul(h2, l1);
    let low = gf16_mul(lambda, hh) ^ gf16_mul(l1, l2);
    ((high as u16) << 4) | low as u16
}

#[inline]
fn tower_pow(mut a: u16, mut n: u32, lambda: u8) -> u16 {
    let mut r = 1u16;
    while n != 0 {
        if n & 1 == 1 {
            r = tower_mul(r, a, lambda);
        }
        a = tower_mul(a, a, lambda);
        n >>= 1;
    }
    r
}

/// Inverse in the tower. For `a = h*y + l`, the norm is
/// `N = lambda*h^2 + h*l + l^2` and `a^-1 = (h*y + (h+l)) / N`.
#[inline]
fn tower_inv(a: u16, lambda: u8) -> u16 {
    let h = (a >> 4) as u8;
    let l = (a & 0xf) as u8;
    let h2 = gf16_mul(h, h);
    let l2 = gf16_mul(l, l);
    let norm = gf16_mul(lambda, h2) ^ gf16_mul(h, l) ^ l2;
    let ninv = gf16_inv(norm);
    let high = gf16_mul(h, ninv);
    let low = gf16_mul(h ^ l, ninv);
    ((high as u16) << 4) | low as u16
}

/// The public, secret-independent constants of one tower representation.
struct Tower {
    lambda: u8,
    /// `basis[i] = beta^i`, the image of the AES basis element `x^i`.
    basis: [u16; 8],
    /// Columns of the inverse basis matrix: `from_tower` XORs these by input bit.
    inv_cols: [u8; 8],
}

impl Tower {
    fn build() -> Tower {
        // Pick an irreducible quadratic `y^2 + y + lambda`: Trace(lambda) = 1.
        let mut lambda = 0u8;
        let mut cand = 1u8;
        while cand < 16 {
            let c2 = gf16_square(cand);
            let c4 = gf16_square(c2);
            let c8 = gf16_square(c4);
            if (cand ^ c2 ^ c4 ^ c8) & 1 == 1 {
                lambda = cand;
                break;
            }
            cand += 1;
        }

        // Find a root of the AES polynomial x^8 + x^4 + x^3 + x + 1 in the tower.
        let mut beta = 0u16;
        for cand in 1u16..=0xff {
            let p8 = tower_pow(cand, 8, lambda);
            let p4 = tower_pow(cand, 4, lambda);
            let p3 = tower_pow(cand, 3, lambda);
            if p8 == p4 ^ p3 ^ cand ^ 1 {
                beta = cand;
                break;
            }
        }

        let mut basis = [0u16; 8];
        basis[0] = 1;
        let mut i = 1;
        while i < 8 {
            basis[i] = tower_mul(basis[i - 1], beta, lambda);
            i += 1;
        }

        // Invert the 8x8 matrix whose column i is basis[i].
        let mut mat = [[0u8; 16]; 8];
        let mut r = 0usize;
        while r < 8 {
            let mut c = 0usize;
            while c < 8 {
                mat[r][c] = ((basis[c] >> r) & 1) as u8;
                c += 1;
            }
            mat[r][8 + r] = 1;
            r += 1;
        }
        let mut c = 0usize;
        while c < 8 {
            let mut pivot = c;
            while mat[pivot][c] == 0 {
                pivot += 1;
            }
            if pivot != c {
                mat.swap(pivot, c);
            }
            let mut r = 0usize;
            while r < 8 {
                if r != c && mat[r][c] == 1 {
                    let mut k = 0usize;
                    while k < 16 {
                        mat[r][k] ^= mat[c][k];
                        k += 1;
                    }
                }
                r += 1;
            }
            c += 1;
        }
        let mut inv_cols = [0u8; 8];
        let mut col = 0usize;
        while col < 8 {
            let mut v = 0u8;
            let mut row = 0usize;
            while row < 8 {
                v |= mat[row][8 + col] << row;
                row += 1;
            }
            inv_cols[col] = v;
            col += 1;
        }

        Tower {
            lambda,
            basis,
            inv_cols,
        }
    }

    #[inline]
    fn map_to_tower(&self, x: u8) -> u16 {
        let mut t = 0u16;
        let mut i = 0usize;
        while i < 8 {
            t ^= self.basis[i] & 0u16.wrapping_sub(((x >> i) & 1) as u16);
            i += 1;
        }
        t
    }

    #[inline]
    fn map_from_tower(&self, t: u16) -> u8 {
        let mut x = 0u8;
        let mut i = 0usize;
        while i < 8 {
            x ^= self.inv_cols[i] & (0u8.wrapping_sub(((t >> i) & 1) as u8));
            i += 1;
        }
        x
    }

    #[inline]
    fn sbox(&self, x: u8) -> u8 {
        portable::affine(self.map_from_tower(tower_inv(self.map_to_tower(x), self.lambda)))
    }
}

fn tower() -> &'static Tower {
    static TOWER: OnceLock<Tower> = OnceLock::new();
    TOWER.get_or_init(Tower::build)
}

/// The composite-field arm.
pub(crate) fn composite_sbox(x: u8) -> u8 {
    tower().sbox(x)
}

/// Build the stored encryption schedule from the safe portable expansion.
fn encrypt_schedule(key: &[u8], bits: i32) -> ([u32; 60], usize) {
    let (mut w, rounds) = match portable::expand_encrypt_key(key, bits) {
        Some(v) => v,
        None => {
            unreachable!("bits is 128, 192 or 256");
        }
    };
    for word in w.iter_mut().take(4 * (rounds + 1)) {
        *word = word.swap_bytes();
    }
    (w, rounds)
}

/// The authority's decrypt transform over the stored schedule.
fn decrypt_schedule(key: &[u8], bits: i32) -> ([u32; 60], usize) {
    let (mut rk, rounds) = encrypt_schedule(key, bits);
    let mut i = 0usize;
    let mut j = 4 * rounds;
    while i < j {
        for k in 0..4 {
            rk.swap(i + k, j + k);
        }
        i += 4;
        j -= 4;
    }
    let mut off = 0usize;
    for _ in 1..rounds {
        off += 4;
        for jj in 0..4 {
            let tp1 = rk[off + jj];
            let m = tp1 & 0x8080_8080;
            let tp2 = ((tp1 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
            let m = tp2 & 0x8080_8080;
            let tp4 = ((tp2 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
            let m = tp4 & 0x8080_8080;
            let tp8 = ((tp4 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
            let tp9 = tp8 ^ tp1;
            let tpb = tp9 ^ tp2;
            let tpd = tp9 ^ tp4;
            let tpe = tp8 ^ tp4 ^ tp2;
            rk[off + jj] = tpe ^ tpd.rotate_left(16) ^ tp9.rotate_left(24) ^ tpb.rotate_left(8);
        }
    }
    (rk, rounds)
}

/// Every arm must be equal to the reference table before any timing is quoted.
#[test]
fn all_sbox_arms_are_exhaustively_equal_to_the_table() {
    for x in 0u16..=255 {
        let x = x as u8;
        let table = AES_SBOX[x as usize];
        assert_eq!(portable::sbox_byte(x), table, "bytewise {x:#04x}");
        assert_eq!(composite_sbox(x), table, "composite {x:#04x}");
        assert_eq!(portable::sbox_byte(x), composite_sbox(x), "arms {x:#04x}");
    }
}

fn sbox_bench(iters: usize, f: impl Fn(u8) -> u8) -> f64 {
    let t = Instant::now();
    let mut acc = 0u8;
    for i in 0..iters {
        acc ^= f(black_box(i as u8));
    }
    black_box(acc);
    t.elapsed().as_nanos() as f64 / iters as f64
}

fn bitsliced_sbox_bench(iters: usize) -> f64 {
    let t = Instant::now();
    let mut acc = 0u8;
    for i in 0..iters {
        let mut state = [black_box(i as u8); 16];
        portable::sub_bytes(&mut state);
        acc ^= state[0];
    }
    black_box(acc);
    t.elapsed().as_nanos() as f64 / (iters as f64 * 16.0)
}

fn block_bench<F: FnMut(&mut [u8; 16])>(iters: usize, mut f: F) -> f64 {
    let mut state = [0u8; 16];
    let t = Instant::now();
    for _ in 0..iters {
        f(&mut state);
        black_box(&state);
    }
    let per = t.elapsed().as_nanos() as f64 / iters as f64;
    // 16 bytes per block, in MB/s.
    16.0 / per * 1e9 / (1024.0 * 1024.0)
}

/// The measured comparison. Run alone for stable numbers:
/// `cargo test --lib aes::research::pfp63_benchmarks -- --nocapture --test-threads=1`.
/// The gate runs it too; its assertions-free body is a measurement, not a check.
#[test]
fn pfp63_benchmarks() {
    let iters = 50_000usize;
    println!("S-box arms, ns per 16 bytes (unoptimised test profile):");
    let table = sbox_bench(iters, |x| AES_SBOX[x as usize]);
    let bytewise = sbox_bench(iters, portable::sbox_byte);
    let composite = sbox_bench(iters, composite_sbox);
    let bitsliced = bitsliced_sbox_bench(iters / 16);
    println!("  table      {:.1}", table * 16.0);
    println!("  bytewise   {:.1}", bytewise * 16.0);
    println!("  composite  {:.1}", composite * 16.0);
    println!("  bitsliced  {:.1}", bitsliced * 16.0);

    let key = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let block_iters = 20_000usize;
    println!("Block throughput, MB/s (unoptimised test profile, 16-byte state):");
    for bits in [128i32, 192, 256] {
        let n = (bits / 8) as usize;
        let (ek, er) = encrypt_schedule(&key[..n], bits);
        let (dk, dr) = decrypt_schedule(&key[..n], bits);

        let table_enc = block_bench(block_iters, |s| {
            reference::encrypt_block(s, &ek, er);
        });
        let circ_enc = block_bench(block_iters, |s| {
            portable::encrypt_block(s, &ek, er);
        });
        let table_dec = block_bench(block_iters, |s| {
            reference::decrypt_block(s, &dk, dr);
        });
        let circ_dec = block_bench(block_iters, |s| {
            portable::decrypt_block(s, &dk, dr);
        });
        println!(
            "  AES-{bits}: enc table {table_enc:.1} / circuit {circ_enc:.1}; \
             dec table {table_dec:.1} / circuit {circ_dec:.1}"
        );
    }

    println!(
        "PFP-63 exponentiation baseline retained for comparison \
         (table {:.1} ns/16B, composite {:.1}, bytewise {:.1}, bitsliced {:.1}); \
         PFP-70 selects fixed-slice, see pfp70_benchmarks.",
        table * 16.0,
        composite * 16.0,
        bytewise * 16.0,
        bitsliced * 16.0
    );
}

/// PFP-70: the three portable arms plus the table reference, all measured by
/// the same harness in the same profile. Run alone for stable numbers:
/// `cargo test --lib aes::research::pfp70_benchmarks -- --nocapture --test-threads=1`.
#[test]
fn pfp70_benchmarks() {
    use super::portable::{
        decrypt_block_exp, decrypt_block_fixslice, decrypt_block_planar, encrypt_block_exp,
        encrypt_block_fixslice, encrypt_block_planar,
    };

    let key = [
        0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4b, 0x63, 0x1f, 0x95,
        0x4d, 0x61,
    ];
    type BlockArm = fn(&mut [u8; 16], &[u32; 60], usize);
    let iters = 20_000usize;
    println!("PFP-70 arms, MB/s (unoptimised test profile, same harness for every arm):");
    for bits in [128i32, 192, 256] {
        let n = (bits / 8) as usize;
        let (ek, er) = encrypt_schedule(&key[..n], bits);
        let (dk, dr) = decrypt_schedule(&key[..n], bits);

        let arms: [(&str, BlockArm); 4] = [
            ("table", reference::encrypt_block),
            ("exp", encrypt_block_exp),
            ("bp-planar", encrypt_block_planar),
            ("fixslice", encrypt_block_fixslice),
        ];
        let darms: [(&str, BlockArm); 4] = [
            ("table", reference::decrypt_block),
            ("exp", decrypt_block_exp),
            ("bp-planar", decrypt_block_planar),
            ("fixslice", decrypt_block_fixslice),
        ];
        for (name, f) in arms {
            let mbs = block_bench(iters, |s| f(s, &ek, er));
            println!("  AES-{bits} enc {name:9} {mbs:9.2} MB/s");
        }
        for (name, f) in darms {
            let mbs = block_bench(iters, |s| f(s, &dk, dr));
            println!("  AES-{bits} dec {name:9} {mbs:9.2} MB/s");
        }
    }
}

// ---------------------------------------------------------------------------
// PFP-70 64-bit-lane experiment
// ---------------------------------------------------------------------------
//
// The single-block ABI can only use the 16-bit carrier. To answer whether
// wider lanes help, the same fixed-slice round is run four (u64) or two (u32)
// blocks at a time by packing each block into a separate 16-bit sub-lane. The
// S-box and the linear layer are bitwise/within-lane, so the only change is
// that one instruction now carries several blocks. This is an experiment in
// the test-only research court; the shipped path stays u16.

trait Wide:
    Copy
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
{
    const N: u32;
    const M4: Self;
    const M12: Self;
    const M8: Self;
    fn zero() -> Self;
    fn from_u64(v: u64) -> Self;
    fn to_u64(self) -> u64;
}

impl Wide for u32 {
    const N: u32 = 2;
    const M4: u32 = 0x000f_000f;
    const M12: u32 = 0x0fff_0fff;
    const M8: u32 = 0x00ff_00ff;
    fn zero() -> u32 {
        0
    }
    fn from_u64(v: u64) -> u32 {
        v as u32
    }
    fn to_u64(self) -> u64 {
        self as u64
    }
}

impl Wide for u64 {
    const N: u32 = 4;
    const M4: u64 = 0x000f_000f_000f_000f;
    const M12: u64 = 0x0fff_0fff_0fff_0fff;
    const M8: u64 = 0x00ff_00ff_00ff_00ff;
    fn zero() -> u64 {
        0
    }
    fn from_u64(v: u64) -> u64 {
        v
    }
    fn to_u64(self) -> u64 {
        self
    }
}

fn rep16<W: Wide>(m: u16) -> W {
    let m = m as u64;
    W::from_u64(m | (m << 16) | (m << 32) | (m << 48))
}

fn wide_ror16_4<W: Wide>(x: W) -> W {
    ((x >> 4) & W::M12) | ((x & W::M4) << 12)
}

fn wide_ror16_8<W: Wide>(x: W) -> W {
    ((x >> 8) & W::M8) | ((x & W::M8) << 8)
}

fn wide_delta_swap<W: Wide>(a: &mut W, shift: u32, mask: W) {
    let t = (*a ^ (*a >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

fn wide_shift_rows_1<W: Wide>(state: &mut [W; 8]) {
    let mut i = 0usize;
    while i < 8 {
        wide_delta_swap(&mut state[i], 2, rep16::<W>(0x2310));
        wide_delta_swap(&mut state[i], 1, rep16::<W>(0x5050));
        i += 1;
    }
}

fn wide_inv_shift_rows_1<W: Wide>(state: &mut [W; 8]) {
    let mut i = 0usize;
    while i < 8 {
        wide_delta_swap(&mut state[i], 2, rep16::<W>(0x1320));
        wide_delta_swap(&mut state[i], 1, rep16::<W>(0x5050));
        i += 1;
    }
}

fn wide_mix_columns_0<W: Wide>(state: &mut [W; 8]) {
    let a = *state;
    let mut b = [W::zero(); 8];
    let mut c = [W::zero(); 8];
    let mut k = 0usize;
    while k < 8 {
        b[k] = wide_ror16_4(a[k]);
        c[k] = a[k] ^ b[k];
        k += 1;
    }
    state[0] = b[0] ^ c[7] ^ wide_ror16_8(c[0]);
    state[1] = b[1] ^ c[0] ^ c[7] ^ wide_ror16_8(c[1]);
    state[2] = b[2] ^ c[1] ^ wide_ror16_8(c[2]);
    state[3] = b[3] ^ c[2] ^ c[7] ^ wide_ror16_8(c[3]);
    state[4] = b[4] ^ c[3] ^ c[7] ^ wide_ror16_8(c[4]);
    state[5] = b[5] ^ c[4] ^ wide_ror16_8(c[5]);
    state[6] = b[6] ^ c[5] ^ wide_ror16_8(c[6]);
    state[7] = b[7] ^ c[6] ^ wide_ror16_8(c[7]);
}

fn wide_inv_mix_columns_0<W: Wide>(state: &mut [W; 8]) {
    let a = *state;
    let mut b = [W::zero(); 8];
    let mut c = [W::zero(); 8];
    let mut k = 0usize;
    while k < 8 {
        b[k] = wide_ror16_4(a[k]);
        c[k] = a[k] ^ b[k];
        k += 1;
    }
    let d = [
        a[0] ^ c[7],
        a[1] ^ c[0] ^ c[7],
        a[2] ^ c[1],
        a[3] ^ c[2] ^ c[7],
        a[4] ^ c[3] ^ c[7],
        a[5] ^ c[4],
        a[6] ^ c[5],
        a[7] ^ c[6],
    ];
    let e = [
        c[0] ^ d[6],
        c[1] ^ d[6] ^ d[7],
        c[2] ^ d[0] ^ d[7],
        c[3] ^ d[1] ^ d[6],
        c[4] ^ d[2] ^ d[6] ^ d[7],
        c[5] ^ d[3] ^ d[7],
        c[6] ^ d[4],
        c[7] ^ d[5],
    ];
    let mut k = 0usize;
    while k < 8 {
        state[k] = d[k] ^ e[k] ^ wide_ror16_8(e[k]);
        k += 1;
    }
}

fn wide_key_words(rk: &[u32; 60], round: usize) -> [u16; 8] {
    let mut k = [0u8; 16];
    let mut c = 0usize;
    while c < 4 {
        let word = rk[4 * round + c].swap_bytes();
        let mut r = 0usize;
        while r < 4 {
            k[4 * c + r] = ((word >> (24 - 8 * r)) & 0xff) as u8;
            r += 1;
        }
        c += 1;
    }
    portable::fix_bitslice(&k)
}

fn wide_pack<W: Wide>(blocks: &[[u8; 16]; 4]) -> [W; 8] {
    let mut per = [[0u16; 8]; 4];
    let mut j = 0usize;
    while j < 4 {
        per[j] = portable::fix_bitslice(&blocks[j]);
        j += 1;
    }
    let mut out = [W::zero(); 8];
    let mut k = 0usize;
    while k < 8 {
        let mut v = 0u64;
        let mut j = 0usize;
        while j < W::N as usize {
            v |= (per[j][k] as u64) << (16 * j);
            j += 1;
        }
        out[k] = W::from_u64(v);
        k += 1;
    }
    out
}

fn wide_unpack<W: Wide>(state: &[W; 8]) -> [[u8; 16]; 4] {
    let mut out = [[0u8; 16]; 4];
    let mut j = 0usize;
    while j < W::N as usize {
        let mut w = [0u16; 8];
        let mut k = 0usize;
        while k < 8 {
            w[k] = ((state[k].to_u64() >> (16 * j)) & 0xffff) as u16;
            k += 1;
        }
        out[j] = portable::fix_inv_bitslice(&w);
        j += 1;
    }
    out
}

fn wide_encrypt<W: Wide>(blocks: &mut [[u8; 16]; 4], rk: &[u32; 60], rounds: usize) {
    let mut keys = [[W::zero(); 8]; 15];
    let mut r = 0usize;
    while r <= rounds {
        let w = wide_key_words(rk, r);
        let mut k = 0usize;
        while k < 8 {
            keys[r][k] = rep16::<W>(w[k]);
            k += 1;
        }
        r += 1;
    }
    let mut s = wide_pack::<W>(blocks);
    let mut k = 0usize;
    while k < 8 {
        s[k] ^= keys[0][k];
        k += 1;
    }
    let mut r = 1usize;
    while r < rounds {
        portable::bp_sub_bytes(&mut s);
        portable::sub_bytes_nots(&mut s);
        wide_shift_rows_1(&mut s);
        wide_mix_columns_0(&mut s);
        let mut k = 0usize;
        while k < 8 {
            s[k] ^= keys[r][k];
            k += 1;
        }
        r += 1;
    }
    portable::bp_sub_bytes(&mut s);
    portable::sub_bytes_nots(&mut s);
    wide_shift_rows_1(&mut s);
    let mut k = 0usize;
    while k < 8 {
        s[k] ^= keys[rounds][k];
        k += 1;
    }
    *blocks = wide_unpack::<W>(&s);
}

fn wide_decrypt<W: Wide>(blocks: &mut [[u8; 16]; 4], rk: &[u32; 60], rounds: usize) {
    let mut keys = [[W::zero(); 8]; 15];
    let mut r = 0usize;
    while r <= rounds {
        let w = wide_key_words(rk, r);
        let mut k = 0usize;
        while k < 8 {
            keys[r][k] = rep16::<W>(w[k]);
            k += 1;
        }
        r += 1;
    }
    let mut s = wide_pack::<W>(blocks);
    let mut k = 0usize;
    while k < 8 {
        s[k] ^= keys[0][k];
        k += 1;
    }
    let mut r = 1usize;
    while r < rounds {
        portable::sub_bytes_nots(&mut s);
        portable::bp_inv_sub_bytes(&mut s);
        wide_inv_shift_rows_1(&mut s);
        wide_inv_mix_columns_0(&mut s);
        let mut k = 0usize;
        while k < 8 {
            s[k] ^= keys[r][k];
            k += 1;
        }
        r += 1;
    }
    portable::sub_bytes_nots(&mut s);
    portable::bp_inv_sub_bytes(&mut s);
    wide_inv_shift_rows_1(&mut s);
    let mut k = 0usize;
    while k < 8 {
        s[k] ^= keys[rounds][k];
        k += 1;
    }
    *blocks = wide_unpack::<W>(&s);
}

fn wide_bench<W: Wide>(iters: usize, rk: &[u32; 60], rounds: usize) -> f64 {
    let mut blocks = [[0u8; 16]; 4];
    let t = Instant::now();
    for i in 0..iters {
        blocks[0][0] = i as u8;
        wide_encrypt::<W>(&mut blocks, rk, rounds);
        black_box(&blocks);
    }
    let secs = t.elapsed().as_secs_f64();
    iters as f64 * (W::N as f64) * 16.0 / secs / (1024.0 * 1024.0)
}

/// Correctness of the wide-lane batches against the table reference, then the
/// per-byte throughput of the 16-, 32- and 64-bit lane forms.
#[test]
fn pfp70_wide_lane_benchmarks() {
    let key = [
        0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4b, 0x63, 0x1f, 0x95,
        0x4d, 0x61,
    ];
    let iters = 20_000usize;
    println!("PFP-70 lane-width experiment, MB/s over all blocks processed:");
    for bits in [128i32, 192, 256] {
        let n = (bits / 8) as usize;
        let (ek, er) = encrypt_schedule(&key[..n], bits);
        let (dk, dr) = decrypt_schedule(&key[..n], bits);

        // Correctness before any timing.
        let mut blocks = [[0u8; 16]; 4];
        for (j, b) in blocks.iter_mut().enumerate() {
            for (i, x) in b.iter_mut().enumerate() {
                *x = (i as u8).wrapping_mul(31).wrapping_add(j as u8 * 7);
            }
        }
        for (w, label) in [(2usize, "u32"), (4usize, "u64")] {
            let mut got = blocks;
            if w == 2 {
                wide_encrypt::<u32>(&mut got, &ek, er);
            } else {
                wide_encrypt::<u64>(&mut got, &ek, er);
            }
            for j in 0..w {
                let mut want = blocks[j];
                reference::encrypt_block(&mut want, &ek, er);
                assert_eq!(got[j], want, "{label} enc bits={bits} block={j}");
            }
            let mut got = blocks;
            if w == 2 {
                wide_decrypt::<u32>(&mut got, &dk, dr);
            } else {
                wide_decrypt::<u64>(&mut got, &dk, dr);
            }
            for j in 0..w {
                let mut want = blocks[j];
                reference::decrypt_block(&mut want, &dk, dr);
                assert_eq!(got[j], want, "{label} dec bits={bits} block={j}");
            }
        }

        let u16_mbs = block_bench(iters, |s| portable::encrypt_block(s, &ek, er));
        let u32_mbs = wide_bench::<u32>(iters, &ek, er);
        let u64_mbs = wide_bench::<u64>(iters, &ek, er);
        println!(
            "  AES-{bits} enc: u16x1 {u16_mbs:.2}, u32x2 {u32_mbs:.2}, u64x4 {u64_mbs:.2} MB/s"
        );
    }
}
