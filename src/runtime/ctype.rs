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

/// `ossl_isascii(c)` — the non-EBCDIC arm, `(((c) & ~127) == 0)`.
///
/// It is a *mask* test rather than a range test, and that is observable: a negative `c`
/// fails it by having bits outside the low seven set, exactly as a value above 127 does.
/// The two agree on every input, but the authority writes the mask and this reproduces it
/// rather than replacing it with `(0..128).contains(&c)`.
pub(crate) fn ossl_isascii(c: core::ffi::c_int) -> bool {
    (c & !127) == 0
}

/// `ossl_isspace(c)` — `ossl_ctype_check(c, CTYPE_MASK_space)`.
///
/// The space class is `{ 0x09 .. 0x0D, 0x20 }`, which is *not* the same as C's `isspace`
/// on any locale that adds to it, nor the same as the ASN.1 printable set.
///
/// The only caller is `crypto/asn1/asn_moid.c`'s `do_create`, which lands with that
/// module; the class is kept here because this file is where the authority's classes
/// live and because the derivation above is what makes it checkable.
#[allow(dead_code)]
pub(crate) fn ossl_isspace(c: core::ffi::c_int) -> bool {
    match ascii(c) {
        None => false,
        Some(a) => (0x09..=0x0D).contains(&a) || a == 0x20,
    }
}

/// `ossl_isasn1print(c)` — `ossl_ctype_check(c, CTYPE_MASK_asn1print)`.
///
/// The `asn1print` class is the PrintableString alphabet of X.680: space, apostrophe,
/// the three brackets, `+ , - . /`, the ten digits, colon, equals, question mark, and both
/// letter ranges. Read out of the authority's own table and written as the ranges it is:
///
/// ```text
/// asn1print = { 0x20 } | [ 0x27 .. 0x29 ] | [ 0x2B .. 0x3A ]
///           | { 0x3D } | { 0x3F } | [ 0x41 .. 0x5A ] | [ 0x61 .. 0x7A ]
/// ```
///
/// `;` (0x3B) and `<` (0x3C) fall inside no range, which is why the second range stops at
/// `:` — they are the reason this cannot be written as one interval.
pub(crate) fn ossl_isasn1print(c: core::ffi::c_int) -> bool {
    match ascii(c) {
        None => false,
        Some(a) => matches!(
            a,
            0x20 | 0x27..=0x29 | 0x2B..=0x3A | 0x3D | 0x3F | 0x41..=0x5A | 0x61..=0x7A
        ),
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
        assert!(!ossl_isasn1print(b'\x80' as i8 as core::ffi::c_int));
    }

    /// The PrintableString alphabet, checked against the characters the authority's own
    /// table marks and the two it famously does not.
    #[test]
    fn asn1print_is_the_printable_alphabet() {
        let accepted = " '()+,-./0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for b in 0u8..=127 {
            let want = accepted.as_bytes().contains(&b);
            assert_eq!(
                ossl_isasn1print(core::ffi::c_int::from(b)),
                want,
                "{b:#04x}"
            );
        }
        // The two characters inside the alphabet's range that are not in it.
        assert!(!ossl_isasn1print(core::ffi::c_int::from(b';')));
        assert!(!ossl_isasn1print(core::ffi::c_int::from(b'<')));
        assert!(!ossl_isasn1print(core::ffi::c_int::from(b'|')));
        assert!(!ossl_isasn1print(core::ffi::c_int::from(b'~')));
    }

    /// The space class and the three range tests, over every one-byte value.
    #[test]
    fn space_ascii_and_the_boundary_are_exact() {
        for c in -256..512 {
            let in_ascii = (0..128).contains(&c);
            assert_eq!(ossl_isascii(c), in_ascii, "ossl_isascii({c})");
            let want_space = (0x09..=0x0D).contains(&c) || c == 0x20;
            assert_eq!(ossl_isspace(c), want_space, "ossl_isspace({c})");
        }
    }
}
