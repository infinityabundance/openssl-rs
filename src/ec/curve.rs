//! `crypto/ec/ec_curve.c`'s built-in curve parameters, Phase 8.7.
//!
//! The file is 3,178 lines: eighty-two `static const struct { EC_CURVE_DATA h; unsigned char
//! data[N]; }` initialisers, one `ec_list_element curve_list[]` naming them, and six
//! functions. Four of those functions are this slice's — `EC_get_builtin_curves`,
//! `EC_curve_nid2nist` and `EC_curve_nist2nid` are three of them, and the fourth is why
//! this is not the whole unit.
//!
//! ## The constants are generated, and the generator is the point
//!
//! Every `p`, `a`, `b`, `gx`, `gy`, `order`, cofactor and seed lives in
//! [`crate::ec::curve_data`], which `forensics/tools/gen_ec_curves.py` **reads back from the
//! admitted authority** — a probe linked against its own `libcrypto` walks
//! `EC_get_builtin_curves`, builds each group with `EC_GROUP_new_by_curve_name` and prints
//! `BN_bn2hex` of the seven numbers — rather than transposing `ec_curve.c`. D332's argument
//! for `crypto/bn/bn_dh.c` is the reason and it is stronger here: a typo in a 521-bit prime
//! is invisible to everything except a comparison with the authority itself, and a curve
//! whose `b` came from the row below it would round-trip through every property test anyone
//! would think to write. The generator also checks each read-back against the authority's
//! own `data[]` slice, member for member and width for width, so the two derivations have
//! to agree before the file is written.
//!
//! ## `curve_list[]`'s fourth column is recorded and not transcribed, and this is why
//!
//! The authority's row is
//!
//! ```text
//! typedef struct _ec_list_element_st {
//!     int nid;
//!     const EC_CURVE_DATA *data;
//!     const EC_METHOD *(*meth)(void);
//!     const char *comment;
//! } ec_list_element;
//! ```
//!
//! and its `meth` column is deliberately the one column this module does not carry.
//! `ec_nistp_64_gcc_128` is disabled in this profile and `ECP_NISTZ256_ASM` is defined, so
//! **exactly one** of the eighty-two rows resolves to a function — `NID_X9_62_prime256v1`
//! names `EC_GFp_nistz256_method` — and the rest are `0`. That symbol is `ec_local.h`'s
//! internal and not a DSO export, and its `EC_METHOD` table (`ecp_nistz256.c:1569-1630`)
//! names `ossl_ec_key_simple_priv2oct`/`_oct2priv`/`_generate_key`/`_check_key`/
//! `_generate_public_key` (`ec_key.c`), `ossl_ecdh_simple_compute_key` (`ecdh_ossl.c`) and
//! `ossl_ecdsa_simple_sign_setup`/`_sign_sig`/`_verify_sig` (`ecdsa_ossl.c`).
//!
//! `ec_key.c`, `ecdh_ossl.c` and `ecdsa_ossl.c` are **not this subphase's** — 8.7's row
//! claims `ec_key.c` and this slice does not land it, and `ecdh_*`/`ecdsa_*` are the unit
//! `docs/PHASE-8-SUBPHASES.md` defers. So the method cannot be built, and a row that wrote
//! `None` where the authority writes a function would be a fabricated value — the one thing
//! this project refuses more firmly than an omission. The column is therefore **recorded in
//! `forensics/atlas/ec-curves.json`** for every row, with the profile's `#if`/`#elif`
//! resolution written out and the probe's own method observation beside it (the group's
//! `EC_GROUP_method_of` identity, which is `other` for the one nistz256 curve and one of the
//! four exported constructors for the rest), so the claim "exactly one non-NULL row, and it
//! is `NID_X9_62_prime256v1`" is a measurement rather than a reading.
//!
//! **What it blocks, stated as the authority coordinate rather than as a symptom.**
//! `EC_GROUP_new_by_curve_name_ex` and its static `ec_group_new_from_data` are the only
//! readers of the column, and they are the two labels of this unit that stay `open`
//! because of it: `ec_group_new_from_data`'s body branches on `curve.meth`, so a
//! transcription that dropped the branch would give `NID_X9_62_prime256v1` a *different*
//! `EC_GROUP_method_of` than the authority — an observable difference the moment
//! `EC_GROUP_new_by_curve_name` exists. `EC_get_builtin_curves`, whose answer is
//! `(nid, comment)` and which never reads the column, is unaffected and is landed here.
//! The divergence is `docs/SECURITY_DIVERGENCE_POLICY.md`'s `D-EC-1`, which names the
//! slice that removes it and the two tripwires that stop the field being added without
//! reading it.
//!
//! ## `EC_curve_nid2nist` and `EC_curve_nist2nid` are three-line wrappers, and their unit is
//! elsewhere
//!
//! Both are `crypto/evp/ec_support.c`'s `ossl_ec_curve_*_int` functions, transcribed in
//! [`crate::ec::support`] because that is where their tables live. This module holds the
//! two exported spellings only.
//!
//! ## `ossl_ec_curve_nid_from_params` is withheld, and the gate checks that it is
//!
//! The unit's sixth definition is not here. It validates a group's parameters against the
//! built-in table by reconstructing `(p, a, b, x, y, order)` from an `EC_GROUP` — so its
//! body is nine `ec_lib.c` calls (`EC_GROUP_get_curve_name`, `EC_GROUP_get_field_type`,
//! `EC_GROUP_get_seed_len`, `EC_GROUP_get0_seed`, `EC_GROUP_get0_cofactor`,
//! `EC_GROUP_get_curve`, `EC_GROUP_get0_generator`, `EC_POINT_get_affine_coordinates`,
//! `EC_GROUP_get_order`) — and none of them exists in this crate yet. It is recorded in
//! `forensics/prerequisites.json`'s divergence list with the module that owes it, which is
//! what turns the prerequisite gate's `unwired_function_in_the_current_stratum` finding
//! into a decision: a transcription that returned `NID_undef` or `-1` early would be a
//! fabricated answer for a name the group object owns.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};

use crate::ec::curve_data::EC_LIST_ELEMENTS;
use crate::ec::support;

/// `typedef struct { int nid; const char *comment; } EC_builtin_curve` —
/// `include/openssl/ec.h:537-540`.
///
/// The authority's anonymous-struct typedef, in its own field order. `comment` points at
/// one of the table's own string literals and is never owned by the caller.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EcBuiltinCurve {
    /// `nid` — the curve's object identifier, which is also what
    /// `EC_GROUP_new_by_curve_name` takes.
    pub nid: c_int,
    /// `comment` — a `&'static CStr` borrowed from `curve_list[]`, so a
    /// [`EC_get_builtin_curves`] caller must not free it.
    pub comment: *const c_char,
}

/// `struct EC_CURVE_DATA` — `crypto/ec/ec_curve.c:25-30`.
///
/// ```text
/// typedef struct {
///     int field_type, seed_len, param_len;
///     unsigned int cofactor;
/// } EC_CURVE_DATA;
/// ```
///
/// The first three fields are one declaration in the authority and three here, because a
/// Rust struct has no multi-declarator form; the *layout* is the same, which is the part
/// that matters. `cofactor` is an `unsigned int` and is stored as such — it is promoted to
/// `BN_ULONG` at the one place it is read (`ec_group_new_from_data`'s `BN_set_word`), and
/// narrowing it here would be a second place that could differ.
#[derive(Clone, Copy)]
pub struct EcCurveData {
    /// `field_type` — `NID_X9_62_prime_field` (406) or
    /// `NID_X9_62_characteristic_two_field` (407).
    pub field_type: c_int,
    /// `seed_len` — 20 for every curve whose parameters the standards publish a seed for,
    /// and 0 for the rest.
    pub seed_len: c_int,
    /// `param_len` — the width every one of the six parameters is zero-padded to. It is
    /// the width of `p`, which for a characteristic-two curve is its reduction polynomial.
    pub param_len: c_int,
    /// `cofactor` — 1 for the prime-field curves, 2 or 4 for the binary ones.
    pub cofactor: core::ffi::c_uint,
    /// `data` — the authority's own `unsigned char data[]`: a `seed_len`-byte seed
    /// followed by `p || a || b || gx || gy || order`, each exactly `param_len` bytes,
    /// big-endian.
    ///
    /// The seed is part of the array and not a separate field because that is the
    /// authority's own shape: `ec_group_new_from_data` reads `params = (data + 1)` and
    /// then `params += seed_len` before parsing the six numbers, so an array without the
    /// seed would be a different object.
    pub data: &'static [u8],
}

impl EcCurveData {
    /// The number of `param_len`-wide fields after the seed: six — `p || a || b || gx ||
    /// gy || order` — for all but `_EC_X9_62_PRIME_256V1`, which has eight.
    ///
    /// It is derived from the array's own length rather than stored, so a row whose
    /// declared array and header disagree fails rather than reading past the end.
    pub fn fields(&self) -> usize {
        (self.data.len() - self.seed_len as usize) / self.param_len as usize
    }
}

/// `typedef struct _ec_list_element_st { ... } ec_list_element` —
/// `crypto/ec/ec_curve.c:2533-2538`, with its `nid`, `data` and `comment` columns.
///
/// **The `meth` column is deliberately absent**, and its reason is the module
/// documentation's: a `None` where the authority has a function would be a fabricated
/// value, and the one non-NULL row's function belongs to units this subphase does not
/// own. `EC_get_builtin_curves`, the only landed reader of this table, does not read it.
/// The column is recorded per row in `forensics/atlas/ec-curves.json` until the slice
/// that can build `EC_GFp_nistz256_method` lands it here —
/// `docs/SECURITY_DIVERGENCE_POLICY.md`'s `D-EC-1`.
pub struct EcListElement {
    /// `nid` — the curve's NID, which is the lookup key and the first thing
    /// `EC_get_builtin_curves` hands back.
    pub nid: c_int,
    /// `data` — the curve's [`EcCurveData`], a `&'static` into
    /// [`crate::ec::curve_data`].
    pub data: &'static EcCurveData,
    /// `comment` — the authority's own description string, in its own spelling. A
    /// `&CStr` rather than a `&str` because `EC_get_builtin_curves` hands the caller a
    /// `const char *` that points into `.rodata`, and a Rust `&str` is not NUL-terminated.
    pub comment: &'static CStr,
}

/// `size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)` —
/// `crypto/ec/ec_curve.c:3045-3060`.
///
/// The table's size **whether or not** anything is written: a NULL `r` and a zero `nitems`
/// both answer `curve_list_length` without touching `r`, which is how a caller discovers
/// how much room to make. Otherwise the smaller of the two counts is copied and the full
/// length is still returned, so a short buffer is filled from the front and the answer says
/// so.
///
/// The comment the authority's own header note promises — "returns number of all available
/// curves or zero if a error occurred" — is wrong about the error: there is no path that
/// answers zero, because the table is a compile-time constant. `RT-EC` observes that.
///
/// # Safety
///
/// `r` is NULL or points to at least `nitems` writable [`EcBuiltinCurve`]s.
#[no_mangle]
pub unsafe extern "C" fn EC_get_builtin_curves(r: *mut EcBuiltinCurve, nitems: usize) -> usize {
    let count = EC_LIST_ELEMENTS.len();
    if r.is_null() || nitems == 0 {
        return count;
    }
    let min = if nitems < count { nitems } else { count };
    // `for (i = 0; i < min; i++)` in the authority: `min` is `count` when the caller offers
    // more room than the table needs, so `take(min)` is the same bound.
    for (i, row) in EC_LIST_ELEMENTS.iter().take(min).enumerate() {
        // SAFETY: the caller guarantees `r` holds at least `nitems` entries and
        // `i < min <= nitems`; every field written comes from a `'static` table, so no
        // pointer written can dangle and none is owned by the caller.
        unsafe {
            (*r.add(i)).nid = row.nid;
            (*r.add(i)).comment = row.comment.as_ptr();
        }
    }
    count
}

/// `const char *EC_curve_nid2nist(int nid)` — `crypto/ec/ec_curve.c:3062-3065`.
///
/// A three-line wrapper around [`support::ossl_ec_curve_nid2nist_int`], which is where the
/// fifteen-row table lives. It answers NULL for every non-NIST curve, including the ones
/// that *have* a NIST spelling under a different NID (`secp192r1` is `prime192v1`).
#[no_mangle]
pub extern "C" fn EC_curve_nid2nist(nid: c_int) -> *const c_char {
    support::ossl_ec_curve_nid2nist_int(nid)
}

/// `int EC_curve_nist2nid(const char *name)` — `crypto/ec/ec_curve.c:3067-3070`.
///
/// A three-line wrapper around [`support::ossl_ec_curve_nist2nid_int`], whose comparison
/// is a **case-sensitive** `strcmp`: `"P-256"` is a curve and `"p-256"` is `NID_undef`.
///
/// # Safety
///
/// `name` is a NUL-terminated string; a NULL faults inside `strcmp`, exactly as the
/// authority's does, and `RT-EC` does not call it with one.
#[no_mangle]
pub unsafe extern "C" fn EC_curve_nist2nid(name: *const c_char) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { support::ossl_ec_curve_nist2nid_int(name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::obj;

    /// `EC_builtin_curve` is the one ABI structure this slice exposes, and it is measured rather
    /// than reasoned about: `courts/layout/measure-ec-builtin-curve.c` answers against the
    /// authority's own compiler and its four numbers are asserted here. The declaration cannot
    /// settle it — `int nid; const char *comment;` leaves four bytes of padding whose presence is
    /// the profile's — and a probe cannot see it either, because a probe reading a wrong layout
    /// back would read the same wrong layout on both sides.
    #[test]
    fn the_builtin_curve_structure_is_the_authoritys_shape() {
        assert_eq!(core::mem::size_of::<EcBuiltinCurve>(), 16);
        assert_eq!(core::mem::align_of::<EcBuiltinCurve>(), 8);
        assert_eq!(core::mem::offset_of!(EcBuiltinCurve, nid), 0);
        assert_eq!(core::mem::offset_of!(EcBuiltinCurve, comment), 8);
        // The four bytes at 4..8 are padding, which is what the offsets above mean and what a
        // `nid` stored at 4 would move.
        assert_eq!(core::mem::offset_of!(EcBuiltinCurve, comment), 8);
    }

    /// The two field types, as `obj_table.rs` declares them and as the generated headers
    /// record them. A mismatch would mean the atlas's number and the crate's constant
    /// disagree, which the generator cannot see.
    #[test]
    fn the_two_field_type_numbers_are_the_object_tables() {
        assert_eq!(obj::NID_X9_62_prime_field, 406);
        assert_eq!(obj::NID_X9_62_characteristic_two_field, 407);
        for row in &EC_LIST_ELEMENTS {
            assert!(
                row.data.field_type == obj::NID_X9_62_prime_field
                    || row.data.field_type == obj::NID_X9_62_characteristic_two_field,
                "{}",
                row.comment.to_str().unwrap_or("?")
            );
        }
    }

    /// A row's own slice of its `data[]`, by field index: 0 is `p`, 5 is the order.
    fn slice(row: &EcListElement, index: usize) -> &'static [u8] {
        let d = row.data;
        let start = d.seed_len as usize + index * d.param_len as usize;
        &d.data[start..start + d.param_len as usize]
    }

    /// A big-endian field's bit width, without a bignum: the authority's widest field is
    /// 521 bits and the arrays go up to 72 bytes, so a `u128` would be wrong.
    fn bits(row: &EcListElement, index: usize) -> u32 {
        let bytes = slice(row, index);
        for (i, b) in bytes.iter().enumerate() {
            if *b != 0 {
                return (bytes.len() as u32 - i as u32) * 8 - b.leading_zeros();
            }
        }
        0
    }

    fn is_zero(row: &EcListElement, index: usize) -> bool {
        slice(row, index).iter().all(|b| *b == 0)
    }

    /// The `NNN` and the word from a comment's `over a NNN bit (prime|binary) field`, or
    /// `None` if the comment is not that shape.
    fn comment_size(row: &EcListElement) -> Option<(u32, bool)> {
        let text = row.comment.to_str().ok()?;
        let after = text.split("over a ").nth(1)?;
        // The authority writes `... over a 521 bit prime field`, and the three IPSec rows
        // write it in the middle of a multi-line comment; the split finds the first one
        // either way.
        let size: u32 = after.split(' ').next()?.parse().ok()?;
        Some((size, after.contains("bit prime field")))
    }

    #[test]
    fn every_row_is_the_shape_and_width_its_own_header_declares() {
        // The authority's own rule for `param_len`, which its `ossl_ec_curve_nid_from_params`
        // states in a comment: *"The size of the padding is determined by either the number
        // of bytes in the field modulus (p) or the EC group order, whichever is larger."*
        // So the width is **tight** in one direction and slack in the other, and that is a
        // property a reader can check without the authority.
        for row in &EC_LIST_ELEMENTS {
            let d = row.data;
            assert_eq!(
                d.data.len(),
                d.seed_len as usize + d.fields() * d.param_len as usize,
                "{:#x}'s array is not a seed plus whole fields",
                row.nid
            );
            assert!(d.seed_len == 0 || d.seed_len == 20, "{:#x}", row.nid);
            assert!(d.param_len > 0, "{:#x}", row.nid);
            assert!(d.cofactor > 0, "{:#x}", row.nid);
            let (p, n) = (bits(row, 0), bits(row, 5));
            let width = u32::max(p, n);
            let bytes = d.param_len as u32 * 8;
            assert!(
                width <= bytes,
                "{:#x}'s fields overflow their width",
                row.nid
            );
            assert!(
                width > bytes - 8,
                "{:#x}'s `param_len` is wider than p or the order needs",
                row.nid
            );
            // `a` may legitimately be zero -- the Koblitz binary curves' are -- but `b` and
            // the generator's two coordinates may not be, and a field modulus and an order
            // are at least 2.
            for (index, name) in [(0, "p"), (2, "b"), (3, "gx"), (4, "gy"), (5, "order")] {
                assert!(!is_zero(row, index), "{:#x}'s {name} is zero", row.nid);
            }
            // `p` is odd: a prime modulus is, and a characteristic-two field's reduction
            // polynomial `x^m + ...` has a constant term.
            assert_eq!(
                slice(row, 0)[d.param_len as usize - 1] & 1,
                1,
                "{:#x}",
                row.nid
            );
        }
    }

    #[test]
    fn the_comments_field_size_is_the_polynomials_degree() {
        // Every one of the eighty-two comments is `<something> over a NNN bit (prime|binary)
        // field`, and the number and the word are a *second* statement of what the header
        // says -- one the object table carries, since `curve_list[]`'s comment column is
        // what `EC_get_builtin_curves` hands a caller.
        for row in &EC_LIST_ELEMENTS {
            let d = row.data;
            let Some((size, prime_word)) = comment_size(row) else {
                unreachable!("every comment is `<text> over a NNN bit <word> field`")
            };
            let is_prime = d.field_type == obj::NID_X9_62_prime_field;
            assert_eq!(
                prime_word, is_prime,
                "{:#x}'s comment and its field type disagree",
                row.nid
            );
            // A prime field's modulus *is* `NNN` bits; a binary field's `p` is
            // `x^NNN + (lower terms)`, so it is one bit wider.
            let expected = if is_prime { size } else { size + 1 };
            assert_eq!(
                bits(row, 0),
                expected,
                "{:#x}'s p is not the {} field its comment names",
                row.nid,
                if is_prime { "prime" } else { "binary" }
            );
            // The order is at most one bit wider than the field, which is Hasse's bound's
            // shadow: |n| <= |p| + 1 for every curve here, and `param_len` is the wider of
            // the two.
            assert!(bits(row, 5) <= size + 1, "{:#x}", row.nid);
        }
    }

    #[test]
    fn the_table_is_the_authoritys_eighty_two_rows_in_order() {
        // The two ends and the count, which is what a dropped, added or reordered row
        // moves. The generator checks every row's `nid`, `data` and `comment` against
        // `ec_curve.c`, in both of its tiers.
        assert_eq!(EC_LIST_ELEMENTS.len(), 82);
        assert_eq!(EC_LIST_ELEMENTS[0].nid, obj::NID_secp112r1);
        assert_eq!(EC_LIST_ELEMENTS[81].nid, obj::NID_sm2);
        // The row whose method column is the authority's only non-NULL one, and the row
        // whose comment carries the two whitespace bytes.
        assert_eq!(EC_LIST_ELEMENTS[19].nid, obj::NID_X9_62_prime256v1);
        assert_eq!(EC_LIST_ELEMENTS[65].nid, obj::NID_ipsec3);
        assert_eq!(EC_LIST_ELEMENTS[66].nid, obj::NID_ipsec4);
        assert!(EC_LIST_ELEMENTS[65].comment.to_bytes().contains(&b'\n'));
        // No duplicate NID: `curve_list[]` is a search key and the authority has one row
        // per NID, which is also what `NID_secp192r1` being absent from it means.
        let mut seen = [0i32; 82];
        for (i, row) in EC_LIST_ELEMENTS.iter().enumerate() {
            assert!(!seen.contains(&row.nid), "{:#x} appears twice", row.nid);
            seen[i] = row.nid;
        }
    }

    #[test]
    fn the_two_lookups_are_the_authoritys_and_their_refusals_are_its() {
        // The fifteen NIST spellings, through both directions.
        for (name, nid) in support::NIST_CURVE_ROWS {
            let back = EC_curve_nid2nist(nid);
            assert!(!back.is_null());
            // SAFETY: the answer is one of `ec_support.c`'s own `&'static CStr`s, and the
            // assert above rules the null out.
            assert_eq!(unsafe { CStr::from_ptr(back) }, name);
            // SAFETY: `back` is a pointer to a `&'static CStr`'s buffer, so it is
            // NUL-terminated.
            assert_eq!(unsafe { EC_curve_nist2nid(back) }, nid);
        }
        // `P-192` is `prime192v1`'s NIST name, and `secp192r1` -- the SECG spelling of the
        // same curve -- is not in the table at all.
        assert_eq!(
            EC_curve_nid2nist(obj::NID_brainpoolP256r1),
            core::ptr::null()
        );
        assert_eq!(EC_curve_nid2nist(obj::NID_undef), core::ptr::null());
        assert_eq!(EC_curve_nid2nist(-1), core::ptr::null());
        assert_eq!(EC_curve_nid2nist(999_999), core::ptr::null());
        // The case sensitivity, and the trailing-space refusal. Every argument is a
        // `&'static CStr` and so NUL-terminated.
        let nist2nid = |name: &'static CStr| {
            // SAFETY: `name` is a `&'static CStr`, hence NUL-terminated.
            unsafe { EC_curve_nist2nid(name.as_ptr()) }
        };
        assert_eq!(nist2nid(c"p-256"), obj::NID_undef);
        assert_eq!(nist2nid(c"B-163 "), obj::NID_undef);
        assert_eq!(nist2nid(c"P-999"), obj::NID_undef);
        assert_eq!(nist2nid(c""), obj::NID_undef);
        assert_eq!(nist2nid(c"P-256"), obj::NID_X9_62_prime256v1);
    }

    #[test]
    fn the_builtin_curve_reader_answers_the_table_length_for_every_short_buffer() {
        // SAFETY: a NULL `r` is the documented "just tell me the size" call.
        let size_only = unsafe { EC_get_builtin_curves(core::ptr::null_mut(), 0) };
        assert_eq!(size_only, 82);
        let mut one = [EcBuiltinCurve {
            nid: 0,
            comment: core::ptr::null(),
        }; 3];
        // SAFETY: `one` holds three writable entries and every call below passes a
        // `nitems` no larger than three.
        let fill =
            |buf: *mut EcBuiltinCurve, nitems: usize| unsafe { EC_get_builtin_curves(buf, nitems) };
        assert_eq!(fill(one.as_mut_ptr(), 0), 82);
        // A one-entry buffer is filled from the front and the *answer* is still 82.
        assert_eq!(fill(one.as_mut_ptr(), 1), 82);
        assert_eq!(one[0].nid, obj::NID_secp112r1);
        assert_eq!(one[1].nid, 0, "the authority writes only `min` entries");
        // A three-entry buffer is filled from the front, and a full-size buffer beside it
        // is filled completely -- the same walk, one buffer longer than the table.
        assert_eq!(fill(one.as_mut_ptr(), 3), 82);
        assert_eq!(one[1].nid, obj::NID_secp112r2);
        assert_eq!(one[2].nid, obj::NID_secp128r1);
        assert_eq!(one[0].comment, EC_LIST_ELEMENTS[0].comment.as_ptr());
        // SAFETY: the pointer is the table's own `&'static CStr` buffer, so
        // NUL-terminated.
        let first = unsafe { CStr::from_ptr(one[0].comment) };
        assert_eq!(first, c"SECG/WTLS curve over a 112 bit prime field");
        let mut all = [EcBuiltinCurve {
            nid: 0,
            comment: core::ptr::null(),
        }; 82];
        assert_eq!(fill(all.as_mut_ptr(), 82), 82);
        assert_eq!(all[81].nid, EC_LIST_ELEMENTS[81].nid);
        for (i, row) in all.iter().enumerate() {
            assert_eq!(row.nid, EC_LIST_ELEMENTS[i].nid);
            assert_eq!(row.comment, EC_LIST_ELEMENTS[i].comment.as_ptr());
        }
    }
}
