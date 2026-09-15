//! Phase 5 — `crypto/ctype.c`: the ASCII character classes the ASN.1 parsers use.
//!
//! The authority's `ctype.c` carries a 128-entry table of class masks and three accessors
//! over it. None of those symbols is exported — `util/libcrypto.num` does not list
//! `ossl_ctype_check`, `ossl_isdigit` or `ossl_isxdigit`, and the ownership atlas has no
//! record for them — so there is no ABI obligation here and no symbol is declared. What
//! the parsers need is the *answer*, and only for two of the eleven classes.
//!
//! ## Why this is not the table
//!
//! Transcribing 128 masks would be exactly the kind of hand-copied constant
//! `docs/DECISIONS.md` D33 forbids: a transcription that nothing regenerates and that
//! nothing would notice going stale. The two classes in use are each an exact union of
//! ASCII ranges, so they are written as range tests and the equivalence is stated:
//!
//! ```text
//! CTYPE_MASK_digit  = { 0x30 .. 0x39 }
//! CTYPE_MASK_xdigit = { 0x30 .. 0x39 } | { 0x41 .. 0x46 } | { 0x61 .. 0x66 }
//! ```
//!
//! The xdigit set is 22 entries and was read back out of the authority's own table rather
//! than recalled — `0x30`-`0x39`, `0x41`-`0x46`, `0x61`-`0x66`, and nothing else.
//!
//! ## The bounds check is the interesting part
//!
//! `ossl_ctype_check` answers false for anything outside `[0, 128)`. The parsers pass it a
//! `char`, which is **signed** on this target, so a byte with the high bit set arrives as a
//! negative `int` and is rejected by the `a >= 0` half of the check rather than by the
//! range test. That is why `ossl_isdigit` and `ossl_isxdigit` are not the same shape here:
//! `ossl_isdigit` is the authority's `ASCII_IS_DIGIT(a)` — a bare range test with no bounds
//! check — while `ossl_isxdigit` is the mask check. A negative value fails both, but by
//! different mechanisms, and reproducing one as the other would diverge on an out-of-range
//! positive value such as 0x100 if a caller could produce one.
//!
//! SPDX-License-Identifier: Apache-2.0

/// `CTYPE_MASK_digit` as the range it is.
///
/// `[(c & ~127) == 0]` is the authority's `ossl_isascii` for the non-EBCDIC build; the
/// parsers reach these predicates with values taken from a signed `char`, so `c` can be
/// negative and the upper bound alone would not be enough.
fn ascii(c: core::ffi::c_int) -> Option<u8> {
    if (0..128).contains(&c) {
        Some(c as u8)
    } else {
        None
    }
}

/// `int ossl_isdigit(int c)`
///
/// The authority's `ASCII_IS_DIGIT(a)`, which is a plain range test: `a >= 0x30 && a <=
/// 0x39`. A negative `c` fails it because it is below the lower bound, not because of a
/// bounds check — see the module documentation for why the distinction is preserved.
pub(crate) fn ossl_isdigit(c: core::ffi::c_int) -> bool {
    (0x30..=0x39).contains(&c)
}

/// `ossl_isxdigit(c)` — the authority's macro over `ossl_ctype_check(c, CTYPE_MASK_xdigit)`.
///
/// The 128 bound and the three ranges are both required: `ossl_ctype_check` indexes a
/// 128-entry table, so it answers false outside the range before any class is consulted.
pub(crate) fn ossl_isxdigit(c: core::ffi::c_int) -> bool {
    match ascii(c) {
        None => false,
        Some(a) => {
            (0x30..=0x39).contains(&a) || (0x41..=0x46).contains(&a) || (0x61..=0x66).contains(&a)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two classes against the ranges the authority's table records, including the
    /// values immediately outside each.
    #[test]
    fn digit_is_exactly_the_ascii_decimal_range() {
        for c in 0..256 {
            let expected = (0x30..=0x39).contains(&c);
            assert_eq!(ossl_isdigit(c), expected, "ossl_isdigit({c})");
        }
    }

    #[test]
    fn xdigit_is_exactly_the_three_ascii_ranges() {
        for c in 0..256 {
            let expected = (0x30..=0x39).contains(&c)
                || (0x41..=0x46).contains(&c)
                || (0x61..=0x66).contains(&c);
            assert_eq!(ossl_isxdigit(c), expected, "ossl_isxdigit({c})");
        }
    }

    /// A byte with the high bit set arrives negative from a signed `char`, and neither
    /// class accepts it. This is the case the parsers actually hit on a malformed line.
    #[test]
    fn a_high_bit_byte_is_rejected() {
        assert!(!ossl_isdigit(-1));
        assert!(!ossl_isxdigit(-1));
        assert!(!ossl_isdigit(b'\x80' as i8 as core::ffi::c_int));
        assert!(!ossl_isxdigit(b'\x80' as i8 as core::ffi::c_int));
    }
}
