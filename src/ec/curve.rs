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
//! ## `curve_list[]`'s fourth column is resolved in code, and the one non-NULL row is `D-EC-2`
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
//! and its `meth` column is resolved by [`curve_list_method`], a function of the row's NID rather
//! than a field of the generated [`crate::ec::curve_data`] table. `ec_nistp_64_gcc_128` is disabled
//! in this profile and `ECP_NISTZ256_ASM` is defined, so **exactly one** of the eighty-two rows is
//! non-NULL in the authority — `NID_X9_62_prime256v1` names `EC_GFp_nistz256_method` — and the rest
//! are `0`. That symbol is `ec_local.h`'s internal and not a DSO export, its field arithmetic is
//! `crypto/ec/ecp_nistz256-x86_64.s` with no portable arm, and its Montgomery representation is
//! observable, so it is neither transcribable nor inventable (D334's rule, applied one level down).
//!
//! The landing therefore resolves that one row to `EC_GFp_simple_method`, exactly as every NULL row
//! resolves through `EC_GROUP_new_curve_GFp`, and records the difference as
//! `docs/SECURITY_DIVERGENCE_POLICY.md`'s **`D-EC-2`**, which **supersedes `D-EC-1`**. D-EC-1 named
//! the column as "not transcribed"; D-EC-2 is the same boundary with the answer the landing
//! actually gives — a stated behaviour a court can compare rather than a NULL. The consequences and
//! the trigger are written out on [`curve_list_method`].
//!
//! `ec_group_new_from_data`'s `curve.meth` branch is therefore real: on this profile it takes the
//! `Some` arm for `NID_X9_62_prime256v1` (whose `group_full_init` column is NULL, so the generic
//! `group_set_curve` path runs) and the `None` arm for every other row. The `if let Some(meth)`
//! shape is the authority's own and nothing is short-circuited.
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
use core::ptr;

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_free, BN_is_word, BN_is_zero, BN_num_bits, BN_set_word, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::ec::curve_data::EC_LIST_ELEMENTS;
use crate::ec::cvt::{EC_GROUP_new_curve_GF2m, EC_GROUP_new_curve_GFp};
use crate::ec::lib::{
    ossl_ec_group_new_ex, EC_GROUP_free, EC_GROUP_get0_cofactor, EC_GROUP_get0_generator,
    EC_GROUP_get0_seed, EC_GROUP_get_asn1_flag, EC_GROUP_get_curve, EC_GROUP_get_curve_name,
    EC_GROUP_get_field_type, EC_GROUP_get_order, EC_GROUP_get_seed_len, EC_GROUP_set_asn1_flag,
    EC_GROUP_set_curve_name, EC_GROUP_set_generator, EC_GROUP_set_seed, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_new, EC_POINT_set_affine_coordinates,
};
use crate::ec::smpl::EC_GFp_simple_method;
use crate::ec::support;
use crate::ec::{EcGroup, EcMethod, EcPoint};
use crate::evp::pkey_ctx::{OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc_array};
use crate::runtime::obj::{
    NID_X9_62_prime256v1, NID_X9_62_prime_field, NID_undef, OBJ_length, OBJ_nid2obj, OBJ_nid2sn,
};

extern "C" {
    /// `int memcmp(const void *, const void *, size_t)`.
    fn memcmp(a: *const core::ffi::c_void, b: *const core::ffi::c_void, n: usize) -> c_int;
}

/// The translation-unit coordinate the one `OPENSSL_malloc_array`/`OPENSSL_free` pair in
/// `ossl_ec_curve_nid_from_params` is attributed to, as the allocator reports it.
const FILE: *const c_char = c"crypto/ec/ec_curve.c".as_ptr();

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
/// **The `meth` column is not a field of this type**, and its reason is the module
/// documentation's: the one non-NULL row's authority value (`EC_GFp_nistz256_method`) belongs to
/// units this subphase does not own and is not inventable. The column is therefore resolved by
/// [`curve_list_method`] — a function of the row's NID — rather than stored per row, so the
/// generated [`crate::ec::curve_data`] table keeps its three transcribed columns and the fourth is
/// the one place `D-EC-2` is written down.
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

/// `const EC_METHOD *(*meth)(void)` — `crypto/ec/ec_curve.c:2536`, the type of `curve_list[]`'s
/// fourth column.
///
/// A **safe** `extern "C"` function pointer, because the four constructors it can hold are safe
/// functions in this crate (`EC_GFp_simple_method()` takes no pointer and dereferences none) and
/// the authority's call `curve.meth()` is not one of its guarded calls either.
pub type EcMethodCtor = extern "C" fn() -> *const EcMethod;

/// `curve_list[]`'s fourth column, resolved for this profile — `crypto/ec/ec_curve.c:2615-2837`.
///
/// The authority leaves the column NULL for every one of its eighty-two rows except
/// `NID_X9_62_prime256v1`, whose row resolves to `EC_GFp_nistz256_method` (`ECP_NISTZ256_ASM` is
/// defined here and `ec_nistp_64_gcc_128` is not). That symbol is `ec_local.h`'s internal rather
/// than a DSO export, its field arithmetic is `crypto/ec/ecp_nistz256-x86_64.s` with no portable
/// arm (D334), and its representation is observable through every subsequent multiplication — so
/// it is **not transcribable** and its construction is not inventable. The landing therefore
/// resolves that one row to [`EC_GFp_simple_method`], exactly as every NULL row resolves through
/// `EC_GROUP_new_curve_GFp`, and records the difference as
/// `docs/SECURITY_DIVERGENCE_POLICY.md`'s **`D-EC-2`**, which **supersedes `D-EC-1`**:
///
/// * **Obligation:** the method identity `EC_GROUP_method_of` reports for
///   `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`, and every point operation on that group.
/// * **Authority:** `EC_GFp_nistz256_method`, the column's one non-NULL value.
/// * **Crate:** this function answers `EC_GFp_simple_method` for that NID, so
///   [`ec_group_new_from_data`]'s `curve.meth` branch is real and the field it reads is the
///   divergence.
/// * **Observable consequences:** (a) `EC_GROUP_method_of` answers `EC_GFp_simple_method` where the
///   authority answers `EC_GFp_nistz256_method`; (b) a `secp256r1` signature is the same *value* on
///   both sides — the group is the same — but not the same *code path*; (c) `EC_nistz256_pre_comp_free`
///   and `_dup` are not defined, so `EC_GROUP_copy` and `EC_pre_comp_free` do not transcribe their
///   two `#ifdef ECP_NISTZ256_ASM` arms, an omission unreachable while no nistz256 group exists.
/// * **Trigger:** the slice that supplies a construction for the perlasm unit, at which point the
///   column is written with the real constructor and this function returns it.
///
/// The mapping is written for this profile's macros; the generator records the same resolution per
/// row in `forensics/atlas/ec-curves.json`, which is the measurement this function's single branch
/// is checked against.
pub(crate) fn curve_list_method(nid: c_int) -> Option<EcMethodCtor> {
    if nid == NID_X9_62_prime256v1 {
        Some(EC_GFp_simple_method)
    } else {
        None
    }
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

/// `static const ec_list_element *ec_curve_nid2curve(int nid)` —
/// `crypto/ec/ec_curve.c:2842-2854`.
///
/// A linear walk of `curve_list[]` in table order. A non-positive NID answers NULL without
/// walking, which is the authority's own guard and not an optimisation: `NID_undef` is 0 and
/// `NID_undef` is what `ec_group_explicit_to_named` tests for.
///
/// # Safety
///
/// None: the table is `'static` and the answer points into it.
unsafe fn ec_curve_nid2curve(nid: c_int) -> *const EcListElement {
    if nid <= 0 {
        return ptr::null();
    }

    for row in EC_LIST_ELEMENTS.iter() {
        if row.nid == nid {
            return row as *const EcListElement;
        }
    }
    ptr::null()
}

/// `static EC_GROUP *ec_group_new_from_data(OSSL_LIB_CTX *libctx, const char *propq,
/// const ec_list_element curve)` — `crypto/ec/ec_curve.c:2856-3016`.
///
/// The one constructor that reads `curve_list[]`'s `data` column and, for a row that names a
/// method, its fourth column too. The method read is the **divergence `D-EC-1`**: see the
/// binding below and [`EcListElement`]'s documentation. Everything else is the authority's own
/// order — the seed and the six `param_len`-wide numbers are parsed from the row's array, the
/// curve is set, the base point read and checked, the order and cofactor set, and the seed kept
/// — with the authority's ASN.1 flag adjustment for a curve with no OID under
/// `#ifndef FIPS_MODULE`, which is compiled here.
///
/// The authority's `curve.data == NULL` arm (its first statement) is **not writable**: the crate
/// carries [`EcListElement::data`] as a `&'static`, so no row can have a NULL data column and
/// the arm is unreachable for all eighty-two rows rather than dropped.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or a NUL-terminated string;
/// `curve` is a row of [`EC_LIST_ELEMENTS`].
unsafe fn ec_group_new_from_data(
    libctx: *mut core::ffi::c_void,
    propq: *const c_char,
    curve: &'static EcListElement,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut group: *mut EcGroup = ptr::null_mut();
        let mut p: *mut BigNum = ptr::null_mut();
        let mut a: *mut BigNum = ptr::null_mut();
        let mut b: *mut BigNum = ptr::null_mut();
        let mut x: *mut BigNum = ptr::null_mut();
        let mut y: *mut BigNum = ptr::null_mut();
        let mut order: *mut BigNum = ptr::null_mut();
        let mut point: *mut EcPoint = ptr::null_mut();
        let mut ok = false;

        // `curve.meth` — `curve_list[]`'s fourth column, resolved by [`curve_list_method`]: every
        // row is NULL on this profile except `NID_X9_62_prime256v1`, whose authority value is the
        // perlasm-only `EC_GFp_nistz256_method` and whose crate value is `EC_GFp_simple_method` —
        // `D-EC-2`. The branch below is therefore the authority's own and the field it reads is
        // the divergence.
        let curve_meth: Option<EcMethodCtor> = curve_list_method(curve.nid);

        let ctx = BN_CTX_new_ex(libctx);
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site (`ec_curve.c:2876`, ERR_R_BN_LIB).
            raise_site(&err_sites::EC_CURVE_2876);
            return ptr::null_mut();
        }

        let data = curve.data;
        let seed_len = data.seed_len;
        let param_len = data.param_len;
        let seed = data.data.as_ptr(); /* `(const unsigned char *)(data + 1)` */
        let params = seed.add(seed_len as usize); /* `params += seed_len` */

        'build: {
            if let Some(meth) = curve_meth {
                let meth = meth();
                group = ossl_ec_group_new_ex(libctx, propq, meth);
                if group.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_curve.c:2888`, ERR_R_EC_LIB).
                    raise_site(&err_sites::EC_CURVE_2888);
                    break 'build;
                }
                if let Some(group_full_init) = (*meth).group_full_init {
                    if group_full_init(group, params) == 0 {
                        // SAFETY: a compile-time-constant site (`ec_curve.c:2893`, ERR_R_EC_LIB).
                        raise_site(&err_sites::EC_CURVE_2893);
                        break 'build;
                    }
                    EC_GROUP_set_curve_name(group, curve.nid);
                    BN_CTX_free(ctx);
                    return group;
                }
            }

            /* params += seed_len */
            p = BN_bin2bn(params.add(0), param_len, ptr::null_mut());
            a = BN_bin2bn(params.add(param_len as usize), param_len, ptr::null_mut());
            b = BN_bin2bn(
                params.add(2 * param_len as usize),
                param_len,
                ptr::null_mut(),
            );
            if p.is_null() || a.is_null() || b.is_null() {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2907`, ERR_R_BN_LIB).
                raise_site(&err_sites::EC_CURVE_2907);
                break 'build;
            }

            if !group.is_null() {
                let Some(set_curve) = (*(*group).meth).group_set_curve else {
                    // A NULL `group_set_curve` cannot occur on a landed table.
                    raise_site(&err_sites::EC_CURVE_2913);
                    break 'build;
                };
                if set_curve(group, p, a, b, ctx) == 0 {
                    // SAFETY: a compile-time-constant site (`ec_curve.c:2913`, ERR_R_EC_LIB).
                    raise_site(&err_sites::EC_CURVE_2913);
                    break 'build;
                }
            } else if data.field_type == NID_X9_62_prime_field {
                group = EC_GROUP_new_curve_GFp(p, a, b, ctx);
                if group.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_curve.c:2918`, ERR_R_EC_LIB).
                    raise_site(&err_sites::EC_CURVE_2918);
                    break 'build;
                }
            } else {
                /* field_type == NID_X9_62_characteristic_two_field */
                group = EC_GROUP_new_curve_GF2m(p, a, b, ctx);
                if group.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_curve.c:2927`, ERR_R_EC_LIB).
                    raise_site(&err_sites::EC_CURVE_2927);
                    break 'build;
                }
            }

            EC_GROUP_set_curve_name(group, curve.nid);

            point = EC_POINT_new(group);
            if point.is_null() {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2936`, ERR_R_EC_LIB).
                raise_site(&err_sites::EC_CURVE_2936);
                break 'build;
            }

            x = BN_bin2bn(
                params.add(3 * param_len as usize),
                param_len,
                ptr::null_mut(),
            );
            y = BN_bin2bn(
                params.add(4 * param_len as usize),
                param_len,
                ptr::null_mut(),
            );
            if x.is_null() || y.is_null() {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2942`, ERR_R_BN_LIB).
                raise_site(&err_sites::EC_CURVE_2942);
                break 'build;
            }
            if EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 0 {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2946`, ERR_R_EC_LIB).
                raise_site(&err_sites::EC_CURVE_2946);
                break 'build;
            }
            order = BN_bin2bn(
                params.add(5 * param_len as usize),
                param_len,
                ptr::null_mut(),
            );
            if order.is_null() || BN_set_word(x, data.cofactor as core::ffi::c_ulong) == 0 {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2951`, ERR_R_BN_LIB).
                raise_site(&err_sites::EC_CURVE_2951);
                break 'build;
            }
            if EC_GROUP_set_generator(group, point, order, x) == 0 {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2955`, ERR_R_EC_LIB).
                raise_site(&err_sites::EC_CURVE_2955);
                break 'build;
            }
            if seed_len != 0 && EC_GROUP_set_seed(group, seed, seed_len as usize) == 0 {
                // SAFETY: a compile-time-constant site (`ec_curve.c:2960`, ERR_R_EC_LIB).
                raise_site(&err_sites::EC_CURVE_2960);
                break 'build;
            }

            if EC_GROUP_get_asn1_flag(group) == OPENSSL_EC_NAMED_CURVE {
                let asn1obj = OBJ_nid2obj(curve.nid);
                if asn1obj.is_null() {
                    // SAFETY: a compile-time-constant site (`ec_curve.c:2982`, ERR_R_OBJ_LIB).
                    raise_site(&err_sites::EC_CURVE_2982);
                    break 'build;
                }
                if OBJ_length(asn1obj) == 0 {
                    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
                }
                ASN1_OBJECT_free(asn1obj);
            }

            ok = true;
        }

        if !ok {
            EC_GROUP_free(group);
            group = ptr::null_mut();
        }
        EC_POINT_free(point);
        BN_CTX_free(ctx);
        BN_free(p);
        BN_free(a);
        BN_free(b);
        BN_free(order);
        BN_free(x);
        BN_free(y);
        group
    }
}

/// `EC_GROUP *EC_GROUP_new_by_curve_name_ex(OSSL_LIB_CTX *libctx, const char *propq, int nid)`
/// — `crypto/ec/ec_curve.c:3018-3036`.
///
/// The lookup and the constructor are one expression in the authority, so a name that resolves
/// but whose data fails answers the same `EC_R_UNKNOWN_GROUP` as a name that does not resolve.
/// On this profile (`#ifndef FIPS_MODULE`) the raise carries `name=<sn>` through
/// `ERR_raise_data`; the crate's `raise_site_data` is the same path.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_by_curve_name_ex(
    libctx: *mut core::ffi::c_void,
    propq: *const c_char,
    nid: c_int,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let curve = ec_curve_nid2curve(nid);
        let ret = if !curve.is_null() {
            ec_group_new_from_data(libctx, propq, &*curve)
        } else {
            ptr::null_mut()
        };
        if curve.is_null() || ret.is_null() {
            // `ERR_raise_data(ERR_LIB_EC, EC_R_UNKNOWN_GROUP, "name=%s", OBJ_nid2sn(nid))`
            // (`ec_curve.c:3027`): the reason is carried by the site and the short name is the
            // formatted data argument. The `#else` arm at `:3030` is the FIPS one and is not
            // compiled here.
            let mut msg = [0 as c_char; 128];
            // SAFETY: `msg` is a 128-byte buffer and the format is the authority's own.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s".as_ptr(),
                OBJ_nid2sn(nid),
            );
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            raise_site_data(&err_sites::EC_CURVE_3027, msg.as_ptr());
            return ptr::null_mut();
        }
        ret
    }
}

/// `EC_GROUP *EC_GROUP_new_by_curve_name(int nid)` — `crypto/ec/ec_curve.c:3039-3042`.
///
/// `#ifndef FIPS_MODULE`, compiled here. The default library context and no property query.
#[no_mangle]
pub extern "C" fn EC_GROUP_new_by_curve_name(nid: c_int) -> *mut EcGroup {
    // SAFETY: this function takes no pointer; the two NULLs are the authority's own.
    unsafe { EC_GROUP_new_by_curve_name_ex(ptr::null_mut(), ptr::null(), nid) }
}

/// `int ossl_ec_curve_nid_from_params(const EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ec_curve.c:3081-3178`.
///
/// Reconstructs `(p, a, b, x, y, order)` from the group, zero-pads each to the widest of
/// `BN_num_bytes(order)` and `BN_num_bytes(field)`, and walks `curve_list[]` for a row whose
/// field type, width, NID (unless the group has none), cofactor and seed all agree and whose
/// packed parameters are byte-equal. The answer is the matching NID, `NID_undef` when none
/// matches, and **−1** only when a step fails before the walk.
///
/// `BN_num_bytes` is `(BN_num_bits + 7) / 8`; the crate does not export it as a function and
/// the inline form is used here, exactly as `src/bn/rand.rs` does.
///
/// # Safety
///
/// `group` is a live group; `ctx` is a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_curve_nid_from_params(
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = -1;
        const NUM_BN_FIELDS: usize = 6;
        let mut bn: [*mut BigNum; NUM_BN_FIELDS] = [ptr::null_mut(); NUM_BN_FIELDS];

        /* Use the optional named curve nid as a search field */
        let nid = EC_GROUP_get_curve_name(group);
        let field_type = EC_GROUP_get_field_type(group);
        let seed_len = EC_GROUP_get_seed_len(group);
        let seed = EC_GROUP_get0_seed(group);
        let cofactor = EC_GROUP_get0_cofactor(group);

        BN_CTX_start(ctx);

        /*
         * The built-in curves hold (p, a, b, x, y, order) zero-padded to the wider of the field
         * modulus and the group order.
         */
        let mut param_len = (BN_num_bits((*group).order) + 7) / 8;
        let len = (BN_num_bits((*group).field) + 7) / 8;
        if len > param_len {
            param_len = len;
        }

        let param_bytes = CRYPTO_malloc_array(NUM_BN_FIELDS, param_len as usize, FILE, 3114)
            .cast::<core::ffi::c_uchar>();

        'walk: {
            if param_bytes.is_null() {
                break 'walk;
            }

            for slot in bn.iter_mut() {
                *slot = BN_CTX_get(ctx);
                if slot.is_null() {
                    break 'walk;
                }
            }

            /* p, a, b */
            let generator = EC_GROUP_get0_generator(group);
            if generator.is_null() {
                break 'walk;
            }
            if EC_GROUP_get_curve(group, bn[0], bn[1], bn[2], ctx) == 0
                /* x, y */
                || EC_POINT_get_affine_coordinates(group, generator, bn[3], bn[4], ctx) == 0
                /* order */
                || EC_GROUP_get_order(group, bn[5], ctx) == 0
            {
                break 'walk;
            }

            for (i, value) in bn.iter().enumerate() {
                if BN_bn2binpad(*value, param_bytes.add(i * param_len as usize), param_len) <= 0 {
                    break 'walk;
                }
            }

            for row in EC_LIST_ELEMENTS.iter() {
                let data = row.data;
                /* `params_seed = (const unsigned char *)(data + 1)`, then `params += seed_len` */
                let params_seed = data.data.as_ptr();
                let params = params_seed.add(data.seed_len as usize);

                if data.field_type == field_type
                    && param_len == data.param_len
                    && (nid <= 0 || nid == row.nid)
                    && (cofactor.is_null()
                        || BN_is_zero(cofactor) != 0
                        || BN_is_word(cofactor, data.cofactor as core::ffi::c_ulong) != 0)
                    && (data.seed_len == 0
                        || seed_len == 0
                        || (data.seed_len as usize == seed_len
                            && memcmp(params_seed.cast(), seed.cast(), seed_len) == 0))
                    && memcmp(
                        param_bytes.cast(),
                        params.cast(),
                        param_len as usize * NUM_BN_FIELDS,
                    ) == 0
                {
                    ret = row.nid;
                    break 'walk;
                }
            }
            /* Gets here if the group was not found */
            ret = NID_undef;
        }

        CRYPTO_free(param_bytes.cast(), FILE, 3175);
        BN_CTX_end(ctx);
        ret
    }
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
