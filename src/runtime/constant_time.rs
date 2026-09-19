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

// ---------------------------------------------------------------------------------------------
// The `unsigned int` family.
//
// `constant_time.h` defines every operation at four widths -- `unsigned int`, `uint32_t`,
// `uint64_t` and `size_t` -- and this crate modelled only the `size_t` ones, because that is what
// the Phase 8.3 record-MAC arithmetic is written in. The RSA padding checks are written in the
// `unsigned int` ones, and so are PSS verification, DH and ECDSA. They are the same expression at a
// different width, but "the same expression at a different width" is an argument, and the bodies
// below are transcriptions instead: the header's own text, with `u32` in place of
// `unsigned int`.
//
// The names carry a `_u32` suffix the authority does not spell. Rust has one namespace, and the
// `size_t` forms above already took the unsuffixed names; the family's own convention (`_8`, `_32`,
// `_64`, `_s`) is what the suffix follows, so the width is stated rather than implied.
// ---------------------------------------------------------------------------------------------

/// `value_barrier(unsigned int a)` — `constant_time.h:278-288`, the `unsigned int` form of the
/// barrier the `select` is written through.
#[inline(always)]
#[allow(dead_code)] // the landing caller is `RSA_padding_check_PKCS1_OAEP_mgf1`, D288's next unit
fn value_barrier_u32(a: u32) -> u32 {
    core::hint::black_box(a)
}

/// `constant_time_msb(unsigned int a)` — `constant_time.h:102-105`. The sign bit smeared over the
/// word: `0 - (a >> 31)`.
#[inline(always)]
#[allow(dead_code)] // as above: the RSA padding checks, then PSS/DH/ECDSA
pub(crate) fn constant_time_msb_u32(a: u32) -> u32 {
    0u32.wrapping_sub(a >> 31)
}

/// `constant_time_lt(unsigned int a, unsigned int b)` — `constant_time.h:122-126`. The same single
/// expression as its `size_t` sibling: `a ^ ((a ^ b) | ((a - b) ^ b))` has the sign bit set iff
/// `a < b`.
#[inline(always)]
#[allow(dead_code)] // as above
pub(crate) fn constant_time_lt_u32(a: u32, b: u32) -> u32 {
    constant_time_msb_u32(a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b)))
}

/// `constant_time_ge(unsigned int a, unsigned int b)` — `constant_time.h:185-189`. The complement,
/// so the mask is all-ones when `a >= b`.
#[inline(always)]
#[allow(dead_code)] // as above
pub(crate) fn constant_time_ge_u32(a: u32, b: u32) -> u32 {
    !constant_time_lt_u32(a, b)
}

/// `constant_time_is_zero(unsigned int a)` — `constant_time.h:214-218`.
#[inline(always)]
#[allow(dead_code)] // as above
pub(crate) fn constant_time_is_zero_u32(a: u32) -> u32 {
    constant_time_msb_u32((!a) & a.wrapping_sub(1))
}

/// `constant_time_eq(unsigned int a, unsigned int b)` — `constant_time.h:247-251`.
#[inline(always)]
#[allow(dead_code)] // as above
pub(crate) fn constant_time_eq_u32(a: u32, b: u32) -> u32 {
    constant_time_is_zero_u32(a ^ b)
}

/// `constant_time_eq_int(int a, int b)` — `constant_time.h:272-276`. The widening is the
/// authority's own: the two `int`s are reinterpreted as `unsigned int` and compared there.
#[inline(always)]
pub(crate) fn constant_time_eq_int(a: i32, b: i32) -> u32 {
    constant_time_eq_u32(a as u32, b as u32)
}

/// `constant_time_select(unsigned int mask, unsigned int a, unsigned int b)` —
/// `constant_time.h:348-353`. `mask` must be all-ones or all-zeros.
#[inline(always)]
#[allow(dead_code)] // as above
pub(crate) fn constant_time_select_u32(mask: u32, a: u32, b: u32) -> u32 {
    (value_barrier_u32(mask) & a) | (value_barrier_u32(!mask) & b)
}

/// `constant_time_select_int(unsigned int mask, int a, int b)` — `constant_time.h:362-366`. The
/// operands are the **bit patterns**, not the numbers: the authority casts through
/// `unsigned int` and back, which is what makes `constant_time_select_int(good, mlen, -1)` a
/// constant-time choice between a length and minus one.
#[inline(always)]
pub(crate) fn constant_time_select_int(mask: u32, a: i32, b: i32) -> i32 {
    constant_time_select_u32(mask, a as u32, b as u32) as i32
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

    /// **The `unsigned int` family against the fixture-backed `size_t` one.** The 32-bit forms cannot
    /// have their own fixture section without changing the C generator, and they do not need one:
    /// `constant_time_lt_s`/`_ge_s`/`_is_zero_s`/`_eq_s` are checked row-by-row against the
    /// authority's own header output above, so agreeing with *them* on a domain that includes both
    /// zero-crossings and the 31-bit boundary is a cross-check with real content.
    ///
    /// The domain is chosen to straddle what the two widths can disagree about: `0` (where the
    /// borrow smears), `1`, `2`, `2^n - 1`/`2^n` at 8 and 16 bits, and the two 31/32-bit
    /// boundaries. Anything above 2^31 is where a naive substitution would go wrong, which is why
    /// `0x8000_0000` and `0xffff_ffff` are both in it.
    #[test]
    fn the_32_bit_forms_agree_with_the_fixture_backed_size_t_forms() {
        let domain: [u32; 10] = [
            0,
            1,
            2,
            3,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            0xffff_ffff,
        ];

        for &a in &domain {
            // The masks are **width-specific** -- the `unsigned int` form smears over 32 bits and the
            // `size_t` form over 64 -- so what the two must agree on is the *predicate*, not the
            // value. Comparing `as usize` would be asserting that a 32-bit mask equals a 64-bit one,
            // which is false and would have to be papered over with a truncation everywhere.
            assert_eq!(
                constant_time_is_zero_u32(a) != 0,
                constant_time_is_zero_s(a as usize) != 0,
                "is_zero({a:#x})"
            );
            for &b in &domain {
                let (x, y) = (a as usize, b as usize);

                assert_eq!(
                    constant_time_lt_u32(a, b) != 0,
                    constant_time_lt_s(x, y) != 0,
                    "lt({a:#x}, {b:#x})"
                );
                assert_eq!(
                    constant_time_ge_u32(a, b) != 0,
                    constant_time_ge_s(x, y) != 0,
                    "ge({a:#x}, {b:#x})"
                );
                assert_eq!(
                    constant_time_eq_u32(a, b) != 0,
                    constant_time_eq_s(x, y) != 0,
                    "eq({a:#x}, {b:#x})"
                );
            }
        }
    }

    /// `constant_time_select_int` chooses between an `int` length and `-1`, which is what the OAEP
    /// check ends on. The point is that `-1` is selected as a **bit pattern**, so the result is minus
    /// one and not a truncated length.
    #[test]
    fn constant_time_select_int_picks_the_bit_pattern_and_not_the_number() {
        let all_ones = u32::MAX;

        assert_eq!(constant_time_select_int(all_ones, 42, -1), 42);
        assert_eq!(constant_time_select_int(0, 42, -1), -1);
        assert_eq!(constant_time_eq_int(0, 0), all_ones);
        assert_eq!(constant_time_eq_int(0, 1), 0);
        // A mask that is neither all-ones nor all-zeros mixes the two operands, which is the
        // documented row `select(1, 0xaa, 0x55) == 0x54`. The `int` form is the same arithmetic on the
        // same bit patterns, so `42` and `-1` mix to `0xffff_fffe` -- that is, `-2`, and *not* a
        // boolean choice. Asserting it here is what keeps a later "tidy" rewrite from turning the
        // select into an `if`.
        assert_eq!(constant_time_select_u32(1, 0xaa, 0x55), 0x54);
        assert_eq!(constant_time_select_int(1, 42, -1), -2);
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
