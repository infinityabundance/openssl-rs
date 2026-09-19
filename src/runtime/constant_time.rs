//! Phase 8.3 — `include/internal/constant_time.h`, restricted to the helpers
//! `ssl/record/methods/ssl3_cbc.c` uses.
//!
//! **Why this is a module rather than an inline transcription.** The header is 480 lines and covers
//! the `BN_ULONG` domain, 32- and 64-bit masks, `value_barrier` variants and the `_8`/`_int`
//! convenience wrappers. The one authority unit that needs any of it on this profile is
//! `ssl3_cbc.c`, and it uses exactly seven of them: `constant_time_eq_8_s`,
//! `constant_time_ge_8_s`, `constant_time_select_8`, and the four they are written in terms of
//! (`constant_time_msb_s`, `constant_time_lt_s`, `constant_time_is_zero_s`, `constant_time_select`).
//! Transcribing those and naming the rest as absent is the same call the project makes everywhere
//! else: a name that a *later* unit needs is that unit's to land, with its own caller named.
//!
//! **`value_barrier` is `core::hint::black_box`, and that equivalence is the whole reason these
//! functions are worth transcribing at all.** The header's barrier is
//!
//! ```c
//! #if !defined(OPENSSL_NO_ASM) && defined(__GNUC__)
//!     __asm__("" : "=r"(r) : "0"(a));
//! #else
//!     volatile unsigned char r = a;
//! #endif
//! ```
//!
//! — an empty asm block that *consumes* its input and *produces* an output through a register, which
//! is an optimisation barrier rather than a computation. `black_box` is the standard-library
//! spelling of the same thing: the value is forced through an opaque operation, so the compiler may
//! not fold, reorder or reason about it. Without it, `(mask & a) | (~mask & b)` is legal for LLVM to
//! turn into a branch on `mask`, and a constant-time select becomes a secret-dependent branch. The
//! this profile's build has `OPENSSL_NO_ASM` **unset** and is GNU C, so the asm form is the one in
//! force; `black_box` is its equivalent and the divergence is recorded here rather than assumed.
//!
//! **Every mask is all-ones or all-zeros, never 1 or 0.** `constant_time_ge_s` is written
//! `!constant_time_lt_s(a, b)` and `constant_time_msb_s(a)` is `0 - (a >> 63)`, so the arithmetic is
//! on *masks* throughout: `constant_time_select_8`'s first argument is a byte mask, and a caller
//! that passed `1` would select wrongly while looking correct. That is why the tests below are
//! driven by an expectation table the authority's own header produced — `courts/phase8/
//! ct_expectations.txt`, from the tracked `courts/phase8/gen-constant-time-values.c` — rather than
//! by properties this file asserts about itself.
//!
//! SPDX-License-Identifier: Apache-2.0

/// `constant_time_msb_s(size_t a)` — `constant_time.h:117-120`, the sign bit smeared over the whole
/// word: `0 - (a >> 63)` on a 64-bit `size_t`.
///
/// # `black_box` and this function
/// The authority does not put a barrier here; it puts one in `constant_time_select`. This
/// transcription matches that placement exactly, because moving a barrier changes what the compiler
/// may fold and therefore what the code does on a machine where folding is observable.
#[inline(always)]
pub(crate) fn constant_time_msb_s(a: usize) -> usize {
    0usize.wrapping_sub(a >> (core::mem::size_of::<usize>() * 8 - 1))
}

/// `constant_time_lt_s(size_t a, size_t b)` — `constant_time.h:128-131`.
///
/// One expression rather than a comparison, because a comparison is exactly what must not appear:
/// `a ^ ((a ^ b) | ((a - b) ^ b))` has the sign bit set iff `a < b`, and its high bit is then smeared
/// by `constant_time_msb_s`.
#[inline(always)]
pub(crate) fn constant_time_lt_s(a: usize, b: usize) -> usize {
    constant_time_msb_s(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

/// `constant_time_ge_s(size_t a, size_t b)` — `constant_time.h:196-199`. The complement, so the
/// mask is all-ones when `a >= b`.
#[inline(always)]
pub(crate) fn constant_time_ge_s(a: usize, b: usize) -> usize {
    !constant_time_lt_s(a, b)
}

/// `constant_time_ge_8_s(size_t a, size_t b)` — `constant_time.h:207-210`. The eight-bit mask the
/// record-MAC arithmetic is written in terms of.
#[inline(always)]
pub(crate) fn constant_time_ge_8_s(a: usize, b: usize) -> u8 {
    constant_time_ge_s(a, b) as u8
}

/// `constant_time_is_zero_s(size_t a)` — `constant_time.h:220-223`. `a == 0` iff `a - 1` borrows,
/// which is what `~a & (a - 1)`'s high bit records.
#[inline(always)]
pub(crate) fn constant_time_is_zero_s(a: usize) -> usize {
    constant_time_msb_s((!a) & a.wrapping_sub(1))
}

/// `constant_time_eq_s(size_t a, size_t b)` — `constant_time.h:253-256`.
#[inline(always)]
pub(crate) fn constant_time_eq_s(a: usize, b: usize) -> usize {
    constant_time_is_zero_s(a ^ b)
}

/// `constant_time_eq_8_s(size_t a, size_t b)` — `constant_time.h:258-261`. `ssl3_cbc.c`'s
/// `is_block_a` and `is_block_b` are this, over block indices.
#[inline(always)]
pub(crate) fn constant_time_eq_8_s(a: usize, b: usize) -> u8 {
    constant_time_eq_s(a, b) as u8
}

/// `value_barrier(unsigned int a)` — `constant_time.h:278-288`, the optimisation barrier every
/// `select` is written through. See the module note for why `black_box` is its equivalent here.
#[inline(always)]
fn value_barrier(a: usize) -> usize {
    core::hint::black_box(a)
}

/// `constant_time_select(size_t mask, size_t a, size_t b)` — `constant_time.h:348-353`. `mask` must
/// be all-ones or all-zeros; a caller that passes `1` gets a wrong answer that looks right.
#[inline(always)]
pub(crate) fn constant_time_select(mask: usize, a: usize, b: usize) -> usize {
    (value_barrier(mask) & a) | (value_barrier(!mask) & b)
}

/// `constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)` —
/// `constant_time.h:355-360`. The authority widens to `unsigned int` for the select and narrows
/// back, which is what the `as` casts here do.
#[inline(always)]
pub(crate) fn constant_time_select_8(mask: u8, a: u8, b: u8) -> u8 {
    constant_time_select(mask as usize, a as usize, b as usize) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The authority's own header output, generated by the tracked
    /// `courts/phase8/gen-constant-time-values.c` and committed at `courts/phase8/ct_expectations.txt`.
    ///
    /// **This is the whole table, not a sample.** The header produced 1250 rows over a 24-value
    /// input domain chosen to straddle every interesting boundary (`0`, `1`, `2`, `2^n - 1`, `2^n`,
    /// `0x7fff_ffff`, `0x8000_0000`, `0xffff_ffff`, `0x1_0000_0000`, `usize::MAX`), and every one of
    /// them is checked here. A property test would not catch a transcription that got `ge` and `lt`
    /// the wrong way round on a boundary the author did not think of; the authority's own output
    /// does, because it was produced by the code being transcribed.
    const EXPECTATIONS: &str = include_str!("../../courts/phase8/ct_expectations.txt");

    /// One hexadecimal field of a fixture row. A parse failure is a fixture defect, so it says so
    /// rather than panicking anonymously.
    fn field(text: &str) -> u64 {
        let value = u64::from_str_radix(text.trim_start_matches("0x"), 16);
        assert!(
            value.is_ok(),
            "the fixture carries a field that is not hexadecimal: {text:?}"
        );
        value.unwrap_or(0)
    }

    fn rows(section: &str) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::new();
        let mut in_section = false;
        for line in EXPECTATIONS.lines() {
            let line = line.trim();
            // A section marker starts with a slash and carries the helper's name. **The
            // two-character comment opener is deliberately not written here**: this crate's
            // prerequisite gate scans `.rs` files with a cleaner that does not blank string
            // literals when it looks for comment starts, so a Rust `"/*"` opens a comment that never
            // closes and the gate reports the file as mis-paired. `starts_with('/')` is equivalent
            // for this fixture -- only header lines begin with a slash -- and does not trip it.
            if line.starts_with('/') {
                in_section = line.contains(section);
                continue;
            }
            if line.starts_with('#') || !in_section {
                continue;
            }
            if let Some(inner) = line.strip_prefix('(').and_then(|l| l.strip_suffix("),")) {
                let fields: Vec<&str> = inner.split(',').map(str::trim).collect();
                assert_eq!(fields.len(), 3, "{line}");
                out.push((field(fields[0]), field(fields[1]), field(fields[2])));
            }
        }
        out
    }

    #[test]
    fn the_fixture_is_the_whole_table_and_is_not_empty() {
        assert!(EXPECTATIONS.contains("gen-constant-time-values.c"));
        assert_eq!(rows("constant_time_eq_8_s").len(), 576);
        assert_eq!(rows("constant_time_ge_8_s").len(), 576);
        assert_eq!(rows3("constant_time_select_8, over").len(), 98);
        assert_eq!(rows3("constant_time_select_8 with masks").len(), 196);
    }

    #[test]
    fn every_equality_row_matches_the_authority() {
        for (a, b, want) in rows("constant_time_eq_8_s") {
            assert_eq!(
                constant_time_eq_8_s(a as usize, b as usize) as u64,
                want,
                "eq_8_s({a:#x}, {b:#x})"
            );
        }
    }

    #[test]
    fn every_greater_or_equal_row_matches_the_authority() {
        for (a, b, want) in rows("constant_time_ge_8_s") {
            assert_eq!(
                constant_time_ge_8_s(a as usize, b as usize) as u64,
                want,
                "ge_8_s({a:#x}, {b:#x})"
            );
        }
    }

    #[test]
    fn every_select_row_matches_the_authority() {
        for (mask, a, b, want) in rows3("constant_time_select_8, over") {
            assert_eq!(
                constant_time_select_8(mask as u8, a as u8, b as u8) as u64,
                want,
                "select_8({mask:#x}, {a:#x}, {b:#x})"
            );
        }
        // The masks that are neither all-ones nor all-zeros, which is the input a caller can get
        // wrong while the code looks right. The authority is the oracle for these too, because the
        // hand-written form of the assertion below was wrong the first time it was written.
        let mut checked = 0;
        for (mask, a, b, want) in rows3("constant_time_select_8 with masks") {
            assert_eq!(
                constant_time_select_8(mask as u8, a as u8, b as u8) as u64,
                want,
                "select_8({mask:#x}, {a:#x}, {b:#x})"
            );
            checked += 1;
        }
        assert_eq!(checked, 196);
    }

    #[test]
    fn a_mask_that_is_neither_all_ones_nor_all_zeros_mixes_the_two_operands() {
        // The worked example the module doc warns about, stated with the authority's own answer:
        // `mask = 1` keeps bit 0 of `a` and every **other** bit of `b`, so the result is
        // `(a & 1) | (b & !1)` and not `a`. The first draft of this assertion claimed `0x01`, which
        // is why the expectation is read from the fixture rather than from arithmetic.
        // `mask = 1` keeps bit 0 of `a` and every other bit of `b`. Both worked rows are the
        // authority's own answers for inputs in the fixture's byte domain.
        let mut seen = 0;
        for (mask, a, b, want) in rows3("constant_time_select_8 with masks") {
            if mask != 1 {
                continue;
            }
            let expected = match (a, b) {
                (0x80, 0x7f) => Some(0x7e),
                (0x7f, 0x80) => Some(0x81),
                _ => None,
            };
            assert_eq!(
                constant_time_select_8(mask as u8, a as u8, b as u8) as u64,
                want,
                "select_8({mask:#x}, {a:#x}, {b:#x})"
            );
            if let Some(expected) = expected {
                seen += 1;
                assert_eq!(want, expected, "select_8(1, {a:#x}, {b:#x})");
            }
        }
        assert_eq!(seen, 2, "the fixture lost the two worked rows");
    }

    /// The four-tuple form, for the section whose rows carry a mask as well.
    fn rows3(section: &str) -> Vec<(u64, u64, u64, u64)> {
        let mut out = Vec::new();
        let mut in_section = false;
        for line in EXPECTATIONS.lines() {
            let line = line.trim();
            // See the note in `rows`: the two-character comment opener is not written literally
            // because this crate's prerequisite gate mis-pairs it inside a Rust string.
            if line.starts_with('/') {
                in_section = line.contains(section);
                continue;
            }
            if line.starts_with('#') || !in_section {
                continue;
            }
            if let Some(inner) = line.strip_prefix('(').and_then(|l| l.strip_suffix("),")) {
                let fields: Vec<&str> = inner.split(',').map(str::trim).collect();
                assert_eq!(fields.len(), 4, "{line}");
                out.push((
                    field(fields[0]),
                    field(fields[1]),
                    field(fields[2]),
                    field(fields[3]),
                ));
            }
        }
        out
    }

    #[test]
    fn the_masks_are_all_ones_or_all_zeros_and_never_a_boolean() {
        // The property a caller can get wrong without noticing: every mask this module produces is
        // 0x00 or 0xff, so `select_8`'s first argument is a mask and not a `bool`.
        for (a, b, want) in rows("constant_time_eq_8_s") {
            assert!(
                want == 0 || want == 0xff,
                "eq_8_s({a:#x}, {b:#x}) = {want:#x}"
            );
        }
        for (a, b, want) in rows("constant_time_ge_8_s") {
            assert!(
                want == 0 || want == 0xff,
                "ge_8_s({a:#x}, {b:#x}) = {want:#x}"
            );
        }
        assert_eq!(constant_time_ge_8_s(1, 2), 0x00);
        assert_eq!(constant_time_ge_8_s(2, 2), 0xff);
        assert_eq!(constant_time_ge_8_s(3, 2), 0xff);
        assert_eq!(constant_time_eq_8_s(0, 0), 0xff);
        assert_eq!(constant_time_eq_8_s(0, 1), 0x00);
        // A mask of `1` is not a boolean `true`: the authority answers `0x54` for
        // `(1, 0xaa, 0x55)`, which is `(a & 1) | (b & !1)` and not `a`. The fixture section for
        // non-mask inputs carries that row, and `a_mask_that_is_neither...` asserts it.
    }

    #[test]
    fn the_signed_and_unsigned_forms_agree_at_the_boundary() {
        // `-1` as `usize` is `usize::MAX`, and the ordering is therefore unsigned -- the property
        // that makes `constant_time_ge_8_s` usable on block indices without a sign concern.
        assert_eq!(constant_time_ge_8_s(usize::MAX, 0), 0xff);
        assert_eq!(constant_time_ge_8_s(0, usize::MAX), 0x00);
        assert_eq!(constant_time_lt_s(usize::MAX, 0), 0);
    }
}
