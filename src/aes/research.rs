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
//!   sixteen state bytes in parallel (the shipped construction).
//!
//! Nothing here is compiled into a production artefact.
//!
//! SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

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
        "Selected arm: bitsliced Boolean field-exponentiation circuit \
         (table {:.1} ns/16B, composite {:.1}, bytewise {:.1}, bitsliced {:.1}).",
        table * 16.0,
        composite * 16.0,
        bytewise * 16.0,
        bitsliced * 16.0
    );
}
