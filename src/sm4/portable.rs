//! Constant-pattern byte substitution for SM4: the portable, table-free arm.
//!
//! The shipped `src/sm4.rs` carried the authority's four `SM4_SBOX_T*` 256-word
//! tables and the 256-byte `SM4_S`, and indexed all of them by bytes of the round
//! state (and, in the key schedule, by bytes derived from the key). Those are
//! secret-indexed loads. The pinned OpenSSL 3.6.4 has a table-free SM4 path
//! (`hw_x86_64_sm4_encrypt`, the SM4-ISA/`vsm4rnds4` implementation) which it
//! selects when the CPU advertises the extension; the C fallback is table-indexed.
//! This module removes the table indexing from the portable implementation
//! unconditionally, so the crate no longer depends on the CPU-extension path to
//! avoid a secret-indexed address.
//!
//! # Approach
//!
//! The authority's S-box table is the single source of truth. Its algebraic
//! normal form (ANF) is derived from [`super::SM4_S`] at compile time by the
//! Möbius transform, and evaluated as a bitsliced boolean circuit over the four
//! bytes of a round word: monomials are ANDs of bit planes, output bits are XORs
//! of selected monomials. No array is addressed by a secret: the only indices are
//! the public subset counter and the output-bit counter.
//!
//! This is the same shape as the AES portable arm (`src/aes/portable.rs`): a
//! constant-pattern S-box with XOR/AND only, no secret-indexed memory and no
//! branch on a secret. It is not the AES field-exponentiation circuit, because
//! the SM4 S-box is not the AES inverse; the ANF is derived mechanically from the
//! authoritative table instead of hand-written, and the derivation is checked
//! exhaustively against that table in the tests below.
//!
//! This is a constant-pattern claim at the source level. ctgrind/dudect remain
//! `NOT_RUN` on this venue; no timing claim is made.

#![forbid(unsafe_code)]

use super::SM4_S;

/// The four lanes occupy the low four bits of a plane, one lane per input byte.
const LANES: u8 = 0x0f;

/// ANF coefficients: `ANF[j][s]` is the coefficient of monomial `s` in output
/// bit `j`. Computed from the authority's S-box table by the Möbius transform
/// `a_S = XOR_{T subset S} f(T)`; an entry is 0 or 1.
const fn derive_anf() -> [[u8; 256]; 8] {
    let mut a = [[0u8; 256]; 8];
    let mut x = 0usize;
    while x < 256 {
        let v = SM4_S[x];
        let mut j = 0usize;
        while j < 8 {
            a[j][x] = (v >> j) & 1;
            j += 1;
        }
        x += 1;
    }
    // Möbius transform over the subset lattice. `bit` is a public position.
    let mut i = 0usize;
    while i < 8 {
        let bit = 1usize << i;
        let mut s = 0usize;
        while s < 256 {
            if s & bit != 0 {
                let without = s ^ bit;
                let mut j = 0usize;
                while j < 8 {
                    a[j][s] ^= a[j][without];
                    j += 1;
                }
            }
            s += 1;
        }
        i += 1;
    }
    a
}

/// Read-only coefficient table. It is addressed only by the public subset index
/// and the public output-bit index, never by a state or key byte.
static ANF: [[u8; 256]; 8] = derive_anf();

/// Apply the SM4 S-box to each of the four bytes of `x`, preserving byte order.
///
/// The four bytes are bitsliced into eight planes; the ANF circuit is then
/// evaluated over all four lanes at once. Memory addresses in this function are
/// independent of the argument's value: [`ANF`] and the local monomial array are
/// indexed by loop counters.
pub(super) fn sub_bytes(x: u32) -> u32 {
    let b = [(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8];

    // Plane `i` holds bit `i` of each input byte: bit `k` is byte `k`.
    let mut p = [0u8; 8];
    let mut k = 0usize;
    while k < 4 {
        let v = b[k];
        let mut i = 0usize;
        while i < 8 {
            p[i] |= ((v >> i) & 1) << k;
            i += 1;
        }
        k += 1;
    }

    // Monomial planes. `s` is a public subset of the eight input bits and `i` is
    // `s`'s lowest set bit, so neither index depends on a secret.
    let mut m = [0u8; 256];
    m[0] = LANES;
    let mut s = 1usize;
    while s < 256 {
        let i = s.trailing_zeros() as usize;
        m[s] = m[s & (s - 1)] & p[i];
        s += 1;
    }

    // Each output bit is the XOR of the monomials whose coefficient is set. A
    // coefficient of 0 or 1 is expanded to a 0x00 / 0xff mask, so there is no
    // data-dependent branch here either.
    let mut out = [0u8; 8];
    let mut s = 0usize;
    while s < 256 {
        let mv = m[s];
        let mut j = 0usize;
        while j < 8 {
            out[j] ^= mv & 0u8.wrapping_sub(ANF[j][s]);
            j += 1;
        }
        s += 1;
    }

    // Un-bitslice back to four bytes in the original order.
    let mut r = 0u32;
    let mut k = 0usize;
    while k < 4 {
        let mut v = 0u8;
        let mut j = 0usize;
        while j < 8 {
            v |= ((out[j] >> k) & 1) << j;
            j += 1;
        }
        r = (r << 8) | u32::from(v);
        k += 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table-based reference: the authority's own S-box, applied bytewise.
    fn reference(x: u32) -> u32 {
        let b = [(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8];
        let s = |v: u8| u32::from(SM4_S[v as usize]);
        (s(b[0]) << 24) | (s(b[1]) << 16) | (s(b[2]) << 8) | s(b[3])
    }

    /// Every byte value in every lane, against three different fill patterns.
    /// This covers each possible S-box input in each lane; the lanes are
    /// independent by construction.
    #[test]
    fn the_circuit_matches_the_authority_sbox_in_every_lane() {
        for &fill in &[0x00u8, 0xffu8, 0x5a] {
            for v in 0u16..=255 {
                for lane in 0usize..4 {
                    let mut bs = [fill; 4];
                    bs[lane] = v as u8;
                    let x = u32::from_be_bytes(bs);
                    assert_eq!(
                        sub_bytes(x),
                        reference(x),
                        "fill={fill:#x} v={v} lane={lane}"
                    );
                }
            }
        }
    }

    /// A randomized differential over whole words. The S-box is bytewise, so the
    /// lane test above is the exhaustive one; this catches a wrong unbundle or a
    /// byte-order mistake that a symmetric input would hide.
    #[test]
    fn the_circuit_matches_the_reference_on_random_words() {
        let mut x: u32 = 0x9e37_79b9;
        let mut i = 0usize;
        while i < 8192 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            assert_eq!(sub_bytes(x), reference(x), "x={x:#010x}");
            i += 1;
        }
    }
}
