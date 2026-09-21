//! `crypto/ec/` — Phase 8.7: the `EC_KEY`, `EC_GROUP` and `EC_POINT` objects, the built-in
//! curve tables, and the EC provider surfaces.
//!
//! This module is Phase 8.7's, and it is **the first slice of it rather than the block**.
//! The block is two hundred and two labels, and its core is one indivisible layer: unlike
//! 8.4's, 8.5's and 8.6's method tables, none of the EC units could be landed alone, and
//! the reason is a *cycle the plan's own reading missed*. `crypto/ec/ec_lib.c`'s
//! `ossl_ec_group_new_ex` is reached by every constructor and reaches a `meth->group_init`
//! through a method table; the tables are `ecp_smpl.c`, `ecp_mont.c`, `ecp_nist.c`,
//! `ecp_nistz256.c` and `ec2_smpl.c`; and `ec_curve.c`'s `curve_list[]` names one of those
//! tables in its **fourth column**. So the curve table, the group object and the field
//! arithmetic are one landing, and no part of it is reachable from nothing the way
//! `dh_meth.c` and `dsa_meth.c` were.
//!
//! ## What is landed here, and what is not
//!
//! Landed: **[`curve`]** and **[`support`]**, which are `ec_curve.c`'s built-in parameters
//! and `crypto/evp/ec_support.c`'s name tables — the constants D332's argument says must be
//! *read back from the authority rather than typed*, and the three lookups over them. That
//! is four exports: `EC_get_builtin_curves`, `EC_curve_nid2nist`, `EC_curve_nist2nid` and
//! `OSSL_EC_curve_nid2name`.
//!
//! Not landed, and deliberately not started: `ec_lib.c`'s group and point objects
//! (sixty-nine labels), the field and point arithmetic they dispatch to, `ec_key.c`'s
//! thirty-three, and every other unit of the block. Each is `open` in
//! `forensics/phase8-obligations.json` and nothing is stubbed.
//!
//! ## The one authority coordinate that decides this boundary
//!
//! `EC_GROUP_new_by_curve_name_ex` is `ec_curve.c`'s and it is reachable from nothing in
//! this slice, because `ec_group_new_from_data` reads `curve_list[]`'s fourth column and
//! that column is **not** what the other three are. On this profile exactly one of the
//! eighty-two rows is non-NULL — `NID_X9_62_prime256v1` names `EC_GFp_nistz256_method` —
//! and that symbol is an `ec_local.h` internal, not a DSO export, whose `EC_METHOD` table
//! (`ecp_nistz256.c:1569-1630`) names `ossl_ec_key_simple_*` (`ec_key.c`),
//! `ossl_ecdh_simple_compute_key` (`ecdh_ossl.c`) and `ossl_ecdsa_simple_*`
//! (`ecdsa_ossl.c`) — three units this subphase does not own. A row written with a NULL
//! where the authority writes a function would be a fabricated value, so the column is
//! recorded in `forensics/atlas/ec-curves.json` (with the profile's `#if` resolution and
//! the probe's own method observation beside it) and not transcribed. [`curve`] says so at
//! the field it would occupy.
//!
//! ## The shapes, which is the one part of the layer that *is* landable
//!
//! `crypto/ec/ec_local.h` is a header, and a header defines no symbol, so nothing in it is
//! a ledger row and nothing in it is a callee: the seven types below are the only piece of
//! 8.7 that can be transcribed before the units that fill them, and they are transcribed
//! here exactly as `crypto/dsa/dsa_local.h`'s shapes are beside DSA's method table.
//!
//! Every size and offset is a contract rather than a detail, and every one of them is
//! **measured** against the admitted authority by `courts/layout/measure-ec.c` rather than
//! read off the declaration — `ossl_ec_group_new_ex`, `EC_POINT_new`,
//! `ossl_ec_key_new_method_int` and `EC_KEY_METHOD_new` allocate `struct ec_group_st`,
//! `struct ec_point_st`, `struct ec_key_st` and `struct ec_key_method_st` with
//! `OPENSSL_zalloc`, so a missed member is a heap overrun in the authority's own allocator
//! and a wrong size in an application's `CRYPTO_set_mem_functions` callback. The three
//! numbers that cannot be reasoned about from the declaration are `struct ec_group_st`'s
//! `poly` at **72** (five four-byte members at 32..48 plus the pointer at 48 and `seed_len`
//! at 56 put `field` at 64 and 24 bytes of `int poly[6]` at 72), `struct ec_key_st`'s
//! `ex_data` at **64** (`references` is a four-byte `_Atomic int` at 56 followed by another
//! four-byte `int`), and `struct ec_key_method_st`'s `init` at **16** (`int32_t flags` at
//! 8 followed by a pointer). The unit tests assert all four sizes, all seventy-odd offsets
//! and the seven constants.
//!
//! **The ladder inlines are deliberately not here.** `ec_local.h:762-798` ends with three
//! `static ossl_inline` helpers — `ec_point_ladder_pre`, `_step` and `_post` — each of
//! which is "call `group->meth->ladder_*` or fall back to `EC_POINT_copy`/`EC_POINT_dbl`/
//! `EC_POINT_add`". Those fallbacks are `ec_lib.c`'s public functions, so the three helpers
//! are not a shape: they are the first thing in item 4's reach that reads the `ladder_*`
//! columns of [`EcMethod`], and transcribing them here would put three calls to functions
//! this crate does not have inside a module that is otherwise pure layout.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod asn1;
pub mod backend;
pub mod check;
pub mod ctrl;
pub mod curve;
pub(crate) mod curve_data;
pub mod cvt;
pub mod depr;
pub mod ecdh_ossl;
pub mod ecdsa;
pub mod ecdsa_ossl;
pub mod key;
pub mod kmeth;
pub mod lib;
pub mod mont;
pub mod mult;
pub mod nist;
pub mod oct;
pub mod print;
pub mod smpl;
pub mod smpl2;
pub mod support;

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::sync::atomic::AtomicI32;

use crate::bn::bignum::BigNum;
use crate::bn::ctx::BnCtx;
use crate::bn::mont::MontCtx;
use crate::evp::pkey_asn1::Engine;
use crate::runtime::ex_data::CryptoExData;

/// `EC_FLAGS_DEFAULT_OCT` — `crypto/ec/ec_local.h:26`. The bit every one of the five
/// prime-field and binary-field tables carries, meaning "use the method's own `point2oct`/
/// `oct2point`/`point_set_compressed_coordinates` rather than a caller-supplied one".
pub const EC_FLAGS_DEFAULT_OCT: c_int = 0x1;

/// `EC_FLAGS_CUSTOM_CURVE` — `crypto/ec/ec_local.h:29`. Set by a provider that supplies its
/// own `EC_GROUP` format; **no unit on this profile sets it**, and its readers are
/// `ec_lib.c`'s `ossl_ec_group_new_ex`, `EC_GROUP_copy` and `EC_GROUP_cmp` (which skip the
/// `order`/`cofactor` allocations and the curve comparison for such a group), plus
/// `ec_ameth.c`'s and `ec_asn1.c`'s parameter decoders, which are 8.8's.
pub const EC_FLAGS_CUSTOM_CURVE: c_int = 0x2;

/// `EC_FLAGS_NO_SIGN` — `crypto/ec/ec_local.h:32`. A curve that does not support signing.
///
/// `#[allow(dead_code)]`'s reason: **its only reader is `ec_key.c`'s `EC_KEY_can_sign`**, which
/// is a later item of 8.7, and **no method table on this profile sets it**: the SM2 and s390x
/// tables that would are not built here, so the bit is carried and never observed.
#[allow(dead_code)] // read by `ec_key.c`'s `EC_KEY_can_sign`, which is a later item of 8.7
pub const EC_FLAGS_NO_SIGN: c_int = 0x4;

/// `EC_KEY_METHOD_DYNAMIC` — `crypto/ec/ec_local.h:690`. `EC_KEY_METHOD_new` sets it on
/// every table it allocates, and `EC_KEY_METHOD_free` releases a table **only** while it is
/// set — which is why freeing the authority's own static `openssl_ec_key_method` is a no-op
/// rather than a fault.
pub const EC_KEY_METHOD_DYNAMIC: c_int = 1;

/// `point_conversion_form_t` — `include/openssl/ec.h:1130-1134`.
///
/// A four-byte `int`-backed enum with three enumerators, and the width is the reason it is
/// transcribed: it is the type of [`EcGroup::asn1_form`] and [`EcKey::conv_form`], so a
/// transcription that made it one byte would move [`EcKey::references`] off 56.
/// `courts/layout/measure-ec.c` prints the four bytes and the three values.
pub type PointConversionForm = c_int;

/// `POINT_CONVERSION_COMPRESSED` — `include/openssl/ec.h:1131`.
pub const POINT_CONVERSION_COMPRESSED: c_int = 2;
/// `POINT_CONVERSION_UNCOMPRESSED` — `include/openssl/ec.h:1132`. `ossl_ec_key_new_method_int`
/// stores it in every key it builds, and `ossl_ec_group_new_ex` stores it in every group.
pub const POINT_CONVERSION_UNCOMPRESSED: c_int = 4;
/// `POINT_CONVERSION_HYBRID` — `include/openssl/ec.h:1133`.
pub const POINT_CONVERSION_HYBRID: c_int = 6;

/// `PCT_none` .. `PCT_ec` — the anonymous enum `crypto/ec/ec_local.h:267-275` declares inside
/// `struct ec_group_st` for the `pre_comp` union's discriminator.
///
/// The names match the union member they select, which is what `SETPRECOMP`/`HAVEPRECOMP`
/// (`ec_local.h:289-293`) token-paste into `group->pre_comp.<type>`. On this profile only
/// [`Pct::None`], [`Pct::Nistz256`] and [`Pct::Ec`] are reachable: `ECP_NISTZ256_ASM` is
/// defined and `OPENSSL_NO_EC_NISTP_64_GCC_128` is, so `ec_lib.c`'s two switches compile the
/// four `PCT_nistp224`..`PCT_nistp521` arms out to empty (`ec_lib.c:96-115`, `:191-210`) and
/// the remaining two are what `EC_GROUP_precompute_mult` and its default `mul` reach.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Pct {
    /// `PCT_none` — no precomputation is held.
    None = 0,
    /// `PCT_nistp224` — compiled out on this profile.
    Nistp224 = 1,
    /// `PCT_nistp256` — compiled out on this profile.
    Nistp256 = 2,
    /// `PCT_nistp384` — compiled out on this profile.
    Nistp384 = 3,
    /// `PCT_nistp521` — compiled out on this profile.
    Nistp521 = 4,
    /// `PCT_nistz256` — the perlasm-backed P-256 method's, whose table this crate does not
    /// build (see [`curve`]).
    Nistz256 = 5,
    /// `PCT_ec` — `ec_mult.c`'s generic `ossl_ec_wNAF_mul` precomputation.
    Ec = 6,
}

/// `struct ec_method_st` — `crypto/ec/ec_local.h:43-200`.
///
/// **448 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`: two four-byte `int`s
/// at 0 and 4 and **fifty-five** function pointers from 8 to 440. Every member is
/// `Option<...>` because every one of the authority's five tables leaves some of them NULL, and
/// a NULL read back through `EC_GROUP_method_of` is the authority's answer rather than a defect.
/// `EC_GFp_simple_method` leaves **fourteen** NULL: `mul`, `precompute_mult`,
/// `have_precompute_mult`, `field_div`, `field_encode`, `field_decode`, `field_set_to_one`,
/// `set_private`, `keycopy`, `keyfinish` and `field_inverse_mod_ord` are eleven of them, and
/// `point_set_compressed_coordinates`, `point2oct` and `oct2point` are the other three — the
/// ones its [`EC_FLAGS_DEFAULT_OCT`] bit defers to `ec_oct.c`'s defaults rather than the table.
///
/// The member order is load-bearing in a way the size alone does not show: `point_init` at
/// **80** and `point_finish` at **88** are adjacent pointers to *different* callbacks (one
/// returns `int`, one returns `void`), so a transcription that swapped them would keep the
/// size and move two calls. The unit test asserts every offset for that reason.
#[repr(C)]
pub struct EcMethod {
    /// `int flags` — the `EC_FLAGS_*` bit set.
    pub(crate) flags: c_int,
    /// `int field_type` — a NID, and what `EC_METHOD_get_field_type` returns: 406
    /// (`NID_X9_62_prime_field`) or 407 (`NID_X9_62_characteristic_two_field`).
    pub(crate) field_type: c_int,
    /// `int (*group_init)(EC_GROUP *)`.
    pub group_init: Option<EcGroupInitFn>,
    /// `void (*group_finish)(EC_GROUP *)`.
    pub group_finish: Option<EcGroupFinishFn>,
    /// `void (*group_clear_finish)(EC_GROUP *)` — used by `EC_GROUP_clear_free` when present.
    pub group_clear_finish: Option<EcGroupFinishFn>,
    /// `int (*group_copy)(EC_GROUP *, const EC_GROUP *)`.
    pub group_copy: Option<EcGroupCopyFn>,
    /// `int (*group_set_curve)(EC_GROUP *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub group_set_curve: Option<EcGroupSetCurveFn>,
    /// `int (*group_get_curve)(const EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *)`.
    pub group_get_curve: Option<EcGroupGetCurveFn>,
    /// `int (*group_get_degree)(const EC_GROUP *)`.
    pub group_get_degree: Option<EcGroupQueryFn>,
    /// `int (*group_order_bits)(const EC_GROUP *)`.
    pub group_order_bits: Option<EcGroupQueryFn>,
    /// `int (*group_check_discriminant)(const EC_GROUP *, BN_CTX *)`.
    pub group_check_discriminant: Option<EcGroupCheckDiscriminantFn>,
    /// `int (*point_init)(EC_POINT *)`.
    pub point_init: Option<EcPointInitFn>,
    /// `void (*point_finish)(EC_POINT *)`.
    pub point_finish: Option<EcPointFinishFn>,
    /// `void (*point_clear_finish)(EC_POINT *)`.
    pub point_clear_finish: Option<EcPointFinishFn>,
    /// `int (*point_copy)(EC_POINT *, const EC_POINT *)`.
    pub point_copy: Option<EcPointCopyFn>,
    /// `int (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *)`.
    pub point_set_to_infinity: Option<EcPointSetToInfinityFn>,
    /// `int (*point_set_affine_coordinates)(const EC_GROUP *, EC_POINT *, const BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub point_set_affine_coordinates: Option<EcPointSetAffineFn>,
    /// `int (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *)`.
    pub point_get_affine_coordinates: Option<EcPointGetAffineFn>,
    /// `int (*point_set_compressed_coordinates)(const EC_GROUP *, EC_POINT *, const BIGNUM *, int, BN_CTX *)`.
    pub point_set_compressed_coordinates: Option<EcPointSetCompressedFn>,
    /// `size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t, unsigned char *, size_t, BN_CTX *)`.
    pub point2oct: Option<EcPoint2OctFn>,
    /// `int (*oct2point)(const EC_GROUP *, EC_POINT *, const unsigned char *, size_t, BN_CTX *)`.
    pub oct2point: Option<EcOct2PointFn>,
    /// `int (*add)(const EC_GROUP *, EC_POINT *, const EC_POINT *, const EC_POINT *, BN_CTX *)`.
    pub add: Option<EcPointAddFn>,
    /// `int (*dbl)(const EC_GROUP *, EC_POINT *, const EC_POINT *, BN_CTX *)`.
    pub dbl: Option<EcPointDblFn>,
    /// `int (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *)`.
    pub invert: Option<EcPointUnaryFn>,
    /// `int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *)`.
    pub is_at_infinity: Option<EcPointIsAtInfinityFn>,
    /// `int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *)`.
    pub is_on_curve: Option<EcPointIsOnCurveFn>,
    /// `int (*point_cmp)(const EC_GROUP *, const EC_POINT *, const EC_POINT *, BN_CTX *)`.
    pub point_cmp: Option<EcPointCmpFn>,
    /// `int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *)`.
    pub make_affine: Option<EcPointUnaryFn>,
    /// `int (*points_make_affine)(const EC_GROUP *, size_t, EC_POINT *[], BN_CTX *)`.
    pub points_make_affine: Option<EcPointsMakeAffineFn>,
    /// `int (*mul)(const EC_GROUP *, EC_POINT *, const BIGNUM *, size_t, const EC_POINT *[], const BIGNUM *[], BN_CTX *)`.
    ///
    /// NULL in four of the five tables. `ec_lib.c`'s `EC_POINT_mul` and its siblings fall
    /// back to `ec_mult.c`'s `ossl_ec_wNAF_mul` when it is — a *fall-through*, not a call
    /// through the pointer — which is why the NULL is the authority's rather than a gap.
    pub mul: Option<EcPointMulFn>,
    /// `int (*precompute_mult)(EC_GROUP *, BN_CTX *)`.
    pub precompute_mult: Option<EcPrecomputeMultFn>,
    /// `int (*have_precompute_mult)(const EC_GROUP *)`.
    pub have_precompute_mult: Option<EcGroupQueryFn>,
    /// `int (*field_mul)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub field_mul: Option<EcFieldMulFn>,
    /// `int (*field_sqr)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub field_sqr: Option<EcFieldSqrFn>,
    /// `int (*field_div)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub field_div: Option<EcFieldMulFn>,
    /// `int (*field_inv)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub field_inv: Option<EcFieldSqrFn>,
    /// `int (*field_encode)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)` — to
    /// Montgomery form in the mont table, NULL in the other three prime-field tables.
    pub field_encode: Option<EcFieldSqrFn>,
    /// `int (*field_decode)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)`.
    pub field_decode: Option<EcFieldSqrFn>,
    /// `int (*field_set_to_one)(const EC_GROUP *, BIGNUM *, BN_CTX *)`.
    pub field_set_to_one: Option<EcFieldSetToOneFn>,
    /// `size_t (*priv2oct)(const EC_KEY *, unsigned char *, size_t)`.
    pub priv2oct: Option<EcPriv2OctFn>,
    /// `int (*oct2priv)(EC_KEY *, const unsigned char *, size_t)`.
    pub oct2priv: Option<EcOct2PrivFn>,
    /// `int (*set_private)(EC_KEY *, const BIGNUM *)` — NULL in every one of the five.
    pub set_private: Option<EcKeySetPrivateFn>,
    /// `int (*keygen)(EC_KEY *)`.
    pub keygen: Option<EcKeyInitFn>,
    /// `int (*keycheck)(const EC_KEY *)`.
    pub keycheck: Option<EcKeyCheckFn>,
    /// `int (*keygenpub)(EC_KEY *)`.
    pub keygenpub: Option<EcKeyInitFn>,
    /// `int (*keycopy)(EC_KEY *, const EC_KEY *)` — NULL in every one of the five.
    pub keycopy: Option<EcKeyCopyFn>,
    /// `void (*keyfinish)(EC_KEY *)` — NULL in every one of the five.
    pub keyfinish: Option<EcKeyFinishFn>,
    /// `int (*ecdh_compute_key)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *)`.
    pub ecdh_compute_key: Option<EcComputeKeyFn>,
    /// `int (*ecdsa_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **)`.
    pub ecdsa_sign_setup: Option<EcKeySignSetupFn>,
    /// `ECDSA_SIG *(*ecdsa_sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *)`.
    pub ecdsa_sign_sig: Option<EcKeySignSigFn>,
    /// `int (*ecdsa_verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *)`.
    pub ecdsa_verify_sig: Option<EcKeyVerifySigFn>,
    /// `int (*field_inverse_mod_ord)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)` —
    /// NULL in every one of the five, so `EC_GROUP`'s ECDSA inverse falls back to
    /// `BN_mod_inverse`.
    pub field_inverse_mod_ord: Option<EcFieldSqrFn>,
    /// `int (*blind_coordinates)(const EC_GROUP *, EC_POINT *, BN_CTX *)`.
    pub blind_coordinates: Option<EcPointUnaryFn>,
    /// `int (*ladder_pre)(const EC_GROUP *, EC_POINT *, EC_POINT *, EC_POINT *, BN_CTX *)`.
    pub ladder_pre: Option<EcLadderFn>,
    /// `int (*ladder_step)(const EC_GROUP *, EC_POINT *, EC_POINT *, EC_POINT *, BN_CTX *)`.
    pub ladder_step: Option<EcLadderFn>,
    /// `int (*ladder_post)(const EC_GROUP *, EC_POINT *, EC_POINT *, EC_POINT *, BN_CTX *)`.
    pub ladder_post: Option<EcLadderFn>,
    /// `int (*group_full_init)(EC_GROUP *, const unsigned char *)` — the fifty-fifth and last
    /// member, and the perlasm-table-only one: `ecp_nistz256.c`'s
    /// `ecp_nistz256group_full_init` is its only non-NULL value, and D334 records that this
    /// crate selects the simple method for `NID_X9_62_prime256v1` instead of building it.
    pub group_full_init: Option<EcGroupFullInitFn>,
}

/// `int (*)(EC_GROUP *)` — `ec_local.h:52`.
pub type EcGroupInitFn = unsafe extern "C" fn(group: *mut EcGroup) -> c_int;
/// `void (*)(EC_GROUP *)` — `ec_local.h:53-54`.
pub type EcGroupFinishFn = unsafe extern "C" fn(group: *mut EcGroup);
/// `int (*)(EC_GROUP *, const EC_GROUP *)` — `ec_local.h:55`.
pub type EcGroupCopyFn = unsafe extern "C" fn(dest: *mut EcGroup, src: *const EcGroup) -> c_int;
/// `int (*)(EC_GROUP *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)` —
/// `ec_local.h:57-58`.
pub type EcGroupSetCurveFn = unsafe extern "C" fn(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, BIGNUM *, BIGNUM *, BIGNUM *, BN_CTX *)` — `ec_local.h:59-60`.
pub type EcGroupGetCurveFn = unsafe extern "C" fn(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *)` — `ec_local.h:62-63` and `:139`, one type for
/// `group_get_degree`, `group_order_bits` and `have_precompute_mult` because the authority
/// spells all three the same way.
pub type EcGroupQueryFn = unsafe extern "C" fn(group: *const EcGroup) -> c_int;
/// `int (*)(const EC_GROUP *, BN_CTX *)` — `ec_local.h:65`.
pub type EcGroupCheckDiscriminantFn =
    unsafe extern "C" fn(group: *const EcGroup, ctx: *mut BnCtx) -> c_int;
/// `int (*)(EC_POINT *)` — `ec_local.h:70`.
pub type EcPointInitFn = unsafe extern "C" fn(point: *mut EcPoint) -> c_int;
/// `void (*)(EC_POINT *)` — `ec_local.h:71-72`.
pub type EcPointFinishFn = unsafe extern "C" fn(point: *mut EcPoint);
/// `int (*)(EC_POINT *, const EC_POINT *)` — `ec_local.h:73`.
pub type EcPointCopyFn = unsafe extern "C" fn(dest: *mut EcPoint, src: *const EcPoint) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *)` — `ec_local.h:82`.
pub type EcPointSetToInfinityFn =
    unsafe extern "C" fn(group: *const EcGroup, point: *mut EcPoint) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, const BIGNUM *, const BIGNUM *, BN_CTX *)` —
/// `ec_local.h:83-85`.
pub type EcPointSetAffineFn = unsafe extern "C" fn(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, const EC_POINT *, BIGNUM *, BIGNUM *, BN_CTX *)` —
/// `ec_local.h:86-87`.
pub type EcPointGetAffineFn = unsafe extern "C" fn(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, const BIGNUM *, int, BN_CTX *)` —
/// `ec_local.h:88-90`.
pub type EcPointSetCompressedFn = unsafe extern "C" fn(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y_bit: c_int,
    ctx: *mut BnCtx,
) -> c_int;
/// `size_t (*)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t, unsigned char *,
/// size_t, BN_CTX *)` — `ec_local.h:92-94`.
pub type EcPoint2OctFn = unsafe extern "C" fn(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    buf: *mut c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> usize;
/// `int (*)(const EC_GROUP *, EC_POINT *, const unsigned char *, size_t, BN_CTX *)` —
/// `ec_local.h:95-96`.
pub type EcOct2PointFn = unsafe extern "C" fn(
    group: *const EcGroup,
    point: *mut EcPoint,
    buf: *const c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, const EC_POINT *, const EC_POINT *, BN_CTX *)` —
/// `ec_local.h:98-99`.
pub type EcPointAddFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, const EC_POINT *, BN_CTX *)` — `ec_local.h:100`.
pub type EcPointDblFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, BN_CTX *)` — `ec_local.h:101`, `:110` and `:189`, one
/// type for `invert`, `make_affine` and `blind_coordinates`.
pub type EcPointUnaryFn =
    unsafe extern "C" fn(group: *const EcGroup, point: *mut EcPoint, ctx: *mut BnCtx) -> c_int;
/// `int (*)(const EC_GROUP *, const EC_POINT *)` — `ec_local.h:105`.
pub type EcPointIsAtInfinityFn =
    unsafe extern "C" fn(group: *const EcGroup, point: *const EcPoint) -> c_int;
/// `int (*)(const EC_GROUP *, const EC_POINT *, BN_CTX *)` — `ec_local.h:106`.
pub type EcPointIsOnCurveFn =
    unsafe extern "C" fn(group: *const EcGroup, point: *const EcPoint, ctx: *mut BnCtx) -> c_int;
/// `int (*)(const EC_GROUP *, const EC_POINT *, const EC_POINT *, BN_CTX *)` —
/// `ec_local.h:107-108`.
pub type EcPointCmpFn = unsafe extern "C" fn(
    group: *const EcGroup,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, size_t, EC_POINT *[], BN_CTX *)` — `ec_local.h:111-112`. The
/// authority spells the array as `EC_POINT *[]`, which is `EC_POINT **` — an *array of
/// pointers*, so the Rust is a pointer to a pointer rather than a plain pointer.
pub type EcPointsMakeAffineFn = unsafe extern "C" fn(
    group: *const EcGroup,
    num: usize,
    points: *mut *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, const BIGNUM *, size_t, const EC_POINT *[],
/// const BIGNUM *[], BN_CTX *)` — `ec_local.h:135-137`. `points` and `scalars` are each an
/// `const X *[]`: the array *decays* to a pointer to its `const X *` element, so the outer
/// pointer is the decayed one and is not itself const — `*mut *const X`, which is what
/// `ABI-PROTOTYPE` reports for the authority.
pub type EcPointMulFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
    num: usize,
    points: *mut *const EcPoint,
    scalars: *mut *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(EC_GROUP *, BN_CTX *)` — `ec_local.h:138`.
pub type EcPrecomputeMultFn = unsafe extern "C" fn(group: *mut EcGroup, ctx: *mut BnCtx) -> c_int;
/// `int (*)(const EC_GROUP *, BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)` —
/// `ec_local.h:147-151`, one type for `field_mul` and `field_div`.
pub type EcFieldMulFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, BIGNUM *, const BIGNUM *, BN_CTX *)` — `ec_local.h:149`,
/// `:158`, `:160-161`, `:163-164` and `:187-188`, one type for `field_sqr`, `field_inv`,
/// `field_encode`, `field_decode` and `field_inverse_mod_ord`.
pub type EcFieldSqrFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(const EC_GROUP *, BIGNUM *, BN_CTX *)` — `ec_local.h:165`.
///
/// A **separate type from [`EcFieldSqrFn`]**, because the authority's `field_set_to_one`
/// takes no multiplicand: it is the one three-argument `EC_METHOD` column, so folding it
/// into the four-argument `EcFieldSqrFn` would drop an argument at every call site. Only
/// `EC_GFp_mont_method` names it; the other four tables leave it NULL.
pub type EcFieldSetToOneFn =
    unsafe extern "C" fn(group: *const EcGroup, r: *mut BigNum, ctx: *mut BnCtx) -> c_int;
/// `size_t (*)(const EC_KEY *, unsigned char *, size_t)` — `ec_local.h:167`.
pub type EcPriv2OctFn =
    unsafe extern "C" fn(eckey: *const EcKey, buf: *mut c_uchar, len: usize) -> usize;
/// `int (*)(EC_KEY *, const unsigned char *, size_t)` — `ec_local.h:168`.
pub type EcOct2PrivFn =
    unsafe extern "C" fn(eckey: *mut EcKey, buf: *const c_uchar, len: usize) -> c_int;
/// `int (*)(EC_KEY *, const BIGNUM *)` — `ec_local.h:169`.
pub type EcKeySetPrivateFn =
    unsafe extern "C" fn(eckey: *mut EcKey, priv_key: *const BigNum) -> c_int;
/// `int (*)(EC_KEY *)` — `ec_local.h:170` and `:172`, one type for `keygen` and `keygenpub`.
pub type EcKeyInitFn = unsafe extern "C" fn(eckey: *mut EcKey) -> c_int;
/// `int (*)(const EC_KEY *)` — `ec_local.h:171`.
pub type EcKeyCheckFn = unsafe extern "C" fn(eckey: *const EcKey) -> c_int;
/// `int (*)(EC_KEY *, const EC_KEY *)` — `ec_local.h:173`.
pub type EcKeyCopyFn = unsafe extern "C" fn(dst: *mut EcKey, src: *const EcKey) -> c_int;
/// `void (*)(EC_KEY *)` — `ec_local.h:174`.
pub type EcKeyFinishFn = unsafe extern "C" fn(eckey: *mut EcKey);
/// `int (*)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *)` —
/// `ec_local.h:176-177`.
pub type EcComputeKeyFn = unsafe extern "C" fn(
    pout: *mut *mut c_uchar,
    poutlen: *mut usize,
    pub_key: *const EcPoint,
    ecdh: *const EcKey,
) -> c_int;
/// `int (*)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **)` — `ec_local.h:179-180`.
pub type EcKeySignSetupFn = unsafe extern "C" fn(
    eckey: *mut EcKey,
    ctx: *mut BnCtx,
    kinvp: *mut *mut BigNum,
    rp: *mut *mut BigNum,
) -> c_int;
/// `ECDSA_SIG *(*)(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *)` —
/// `ec_local.h:181-183`.
pub type EcKeySignSigFn = unsafe extern "C" fn(
    dgst: *const c_uchar,
    dgstlen: c_int,
    kinv: *const BigNum,
    r: *const BigNum,
    eckey: *mut EcKey,
) -> *mut EcdsaSig;
/// `int (*)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *)` — `ec_local.h:184-185`.
pub type EcKeyVerifySigFn = unsafe extern "C" fn(
    dgst: *const c_uchar,
    dgstlen: c_int,
    sig: *const EcdsaSig,
    eckey: *mut EcKey,
) -> c_int;
/// `int (*)(const EC_GROUP *, EC_POINT *, EC_POINT *, EC_POINT *, BN_CTX *)` —
/// `ec_local.h:190-198`, one type for `ladder_pre`, `ladder_step` and `ladder_post`.
pub type EcLadderFn = unsafe extern "C" fn(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int;
/// `int (*)(EC_GROUP *, const unsigned char *)` — `ec_local.h:199`.
pub type EcGroupFullInitFn =
    unsafe extern "C" fn(group: *mut EcGroup, data: *const c_uchar) -> c_int;

/// The six precomputation types `ec_local.h:205-210` forward-declares and never defines.
///
/// They are **incomplete types** in that header — `struct nistp224_pre_comp_st` and its four
/// siblings are defined in the perlasm or non-compiled units that own them
/// (`ecp_nistz256.c`, `ecp_nistp224.c`, `ecp_nistp256.c`, `ecp_nistp384.c`, `ecp_nistp521.c`)
/// and `struct ec_pre_comp_st` in `ec_mult.c` — so a pointer to one is all this header can
/// name and all this module can hold. `c_void` is what the crate uses for an opaque pointer
/// whose pointee is another unit's private object.
pub type PreCompPtr = *mut c_void;

/// `union { ... } pre_comp` — `crypto/ec/ec_local.h:276-283`.
///
/// An anonymous union of six pointers, discriminated by [`EcGroup::pre_comp_type`]. Every
/// member is the same width, so the union is eight bytes whichever arm is live; the arms are
/// named because `SETPRECOMP(g, type, pre)` writes the arm its `type` token names and a
/// transcription that made it one `*mut c_void` would lose which precomposition a group
/// holds.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EcPreComp {
    /// `NISTP224_PRE_COMP *nistp224` — compiled out on this profile.
    pub nistp224: PreCompPtr,
    /// `NISTP256_PRE_COMP *nistp256` — compiled out on this profile.
    pub nistp256: PreCompPtr,
    /// `NISTP384_PRE_COMP *nistp384` — compiled out on this profile.
    pub nistp384: PreCompPtr,
    /// `NISTP521_PRE_COMP *nistp521` — compiled out on this profile.
    pub nistp521: PreCompPtr,
    /// `NISTZ256_PRE_COMP *nistz256` — the perlasm table's, and the arm `ec_lib.c:93`/`:188`
    /// keeps because `ECP_NISTZ256_ASM` is defined here.
    pub nistz256: PreCompPtr,
    /// `EC_PRE_COMP *ec` — `ec_mult.c`'s generic precomputation.
    pub ec: PreCompPtr,
}

/// `int (*)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)` — `ec_local.h:257-258`,
/// and the same shape as `bn.h:541`'s `int BN_nist_mod_192(...)` family it is stored from.
/// The `field_mod_func` member of [`EcGroup`], which is **not** a method-table entry: the
/// nist table stores one of `BN_nist_mod_192`..`_521` here directly and
/// `ossl_ec_GFp_nist_field_mul` calls it through the group rather than through the table.
///
/// The return is `int`, not `*mut BIGNUM`: the five `BN_nist_mod_*` functions answer a
/// status and write their result into `r`, so a pointer return would be a different ABI at
/// every call `ossl_ec_GFp_nist_field_mul` makes through this member.
pub type EcFieldModFn = unsafe extern "C" fn(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int;

/// `struct ec_group_st` — `crypto/ec/ec_local.h:212-287`.
///
/// **184 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`. `ossl_ec_group_new_ex`
/// allocates it with `OPENSSL_zalloc` and stores only `meth`, so the twenty-one zeroed members
/// are the authority's own starting state and not this crate's choice. The offset the
/// declaration does not show is `poly` at **72**: five four-byte members at 32..48, the `seed`
/// pointer at 48, `seed_len` at 56 and `field` at 64 leave 24 bytes of `int poly[6]` there, and
/// the two pointers `a`/`b` follow at 96.
///
/// `pre_comp_type` is the anonymous enum at 152 and `pre_comp` the union at 160, so the union
/// is eight-aligned and its four bytes of padding at 156..160 are the profile's. `libctx` and
/// `propq` are the constructor's two arguments, kept for every sub-object the group builds.
#[repr(C)]
pub struct EcGroup {
    /// `const EC_METHOD *meth` — borrowed, never owned, and what `EC_GROUP_method_of` returns.
    pub(crate) meth: *const EcMethod,
    /// `EC_POINT *generator` — optional.
    pub(crate) generator: *mut EcPoint,
    /// `BIGNUM *order`.
    pub(crate) order: *mut BigNum,
    /// `BIGNUM *cofactor`.
    pub(crate) cofactor: *mut BigNum,
    /// `int curve_name` — an optional NID for a named curve.
    pub(crate) curve_name: c_int,
    /// `int asn1_flag` — `OPENSSL_EC_NAMED_CURVE` or `OPENSSL_EC_EXPLICIT_CURVE`.
    pub(crate) asn1_flag: c_int,
    /// `int decoded_from_explicit_params`.
    pub(crate) decoded_from_explicit_params: c_int,
    /// `point_conversion_form_t asn1_form`.
    pub(crate) asn1_form: PointConversionForm,
    /// `unsigned char *seed` — optional, and released by `EC_GROUP_free`.
    pub(crate) seed: *mut c_uchar,
    /// `size_t seed_len`.
    pub(crate) seed_len: usize,
    /// `BIGNUM *field` — the modulus for GF(p), the reduction polynomial for GF(2^m).
    pub(crate) field: *mut BigNum,
    /// `int poly[6]` — the binary field's irreducible, terminated with `-1` where it is shorter
    /// than six terms.
    pub(crate) poly: [c_int; 6],
    /// `BIGNUM *a`.
    pub(crate) a: *mut BigNum,
    /// `BIGNUM *b`.
    pub(crate) b: *mut BigNum,
    /// `int a_is_minus3` — the `A == p - 3` optimisation flag `ossl_ec_GFp_simple_group_set_curve`
    /// computes rather than takes.
    pub(crate) a_is_minus3: c_int,
    /// `void *field_data1` — the mont table's `BN_MONT_CTX`.
    pub(crate) field_data1: *mut c_void,
    /// `void *field_data2` — the mont table's encoded one.
    pub(crate) field_data2: *mut c_void,
    /// `int (*field_mod_func)(...)` — the nist table's reduction, NULL in the other four.
    pub(crate) field_mod_func: Option<EcFieldModFn>,
    /// `BN_MONT_CTX *mont_data` — data for the ECDSA inverse.
    pub(crate) mont_data: *mut MontCtx,
    /// `pre_comp_type` — the discriminator for [`EcGroup::pre_comp`].
    pub(crate) pre_comp_type: Pct,
    /// `pre_comp` — the union's six arms.
    pub(crate) pre_comp: EcPreComp,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — owned, and released by `EC_GROUP_free`.
    pub(crate) propq: *mut c_char,
}

/// `struct ec_key_st` — `crypto/ec/ec_local.h:294-313`.
///
/// **104 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`.
/// `ossl_ec_key_new_method_int` allocates it with `OPENSSL_zalloc` and then fills nine of the
/// fourteen members, so the five it leaves zeroed — `version` excepted, which it sets to 1 —
/// are the authority's. The offset the declaration does not show is `ex_data` at **64**: the
/// four-byte `_Atomic int references` at 56 is followed by another four-byte `int flags`, so
/// the two-pointer `CRYPTO_EX_DATA` that follows them is eight-aligned rather than adjacent.
///
/// `engine` is the one member the declaration gives unconditionally; `ex_data` is the one
/// that sits inside `#ifndef FIPS_MODULE`, and this profile is not FIPS, so both are present
/// in the authority's own object and here. `dirty_cnt` is the provider's `size_t` change
/// counter, which is why the object ends at 104 rather than at 96.
#[repr(C)]
pub struct EcKey {
    /// `const EC_KEY_METHOD *meth` — borrowed, and what `EC_KEY_get_method` returns.
    pub(crate) meth: *const EcKeyMethod,
    /// `ENGINE *engine` — the declaration's second member, and **not** inside
    /// `#ifndef FIPS_MODULE` (only `ex_data` is). NULL on every object this crate can
    /// build, because `ENGINE_get_default_EC` returns NULL without an engine registry and the
    /// authority's own `ossl_ec_key_new_method_int` leaves it so in that case.
    pub(crate) engine: *mut Engine,
    /// `int version` — 1 on every object the authority builds.
    pub(crate) version: c_int,
    /// `EC_GROUP *group` — the domain parameters, NULL until `EC_KEY_set_group`.
    pub(crate) group: *mut EcGroup,
    /// `EC_POINT *pub_key` — NULL until a public key is derived or set.
    pub(crate) pub_key: *mut EcPoint,
    /// `BIGNUM *priv_key` — NULL until a private key is generated or set.
    pub(crate) priv_key: *mut BigNum,
    /// `unsigned int enc_flag` — `EVP_PKEY_*` encoding flags.
    pub(crate) enc_flag: c_uint,
    /// `point_conversion_form_t conv_form`.
    pub(crate) conv_form: PointConversionForm,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` in this profile, so [`AtomicI32`] rather
    /// than a plain integer, exactly as [`crate::rsa::Rsa::references`] is.
    pub(crate) references: AtomicI32,
    /// `int flags` — the `EC_FLAG_*` bit set.
    pub(crate) flags: c_int,
    /// `CRYPTO_EX_DATA ex_data` — inside `#ifndef FIPS_MODULE`.
    pub(crate) ex_data: CryptoExData,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — owned.
    pub(crate) propq: *mut c_char,
    /// `size_t dirty_cnt` — bumped by every mutator so a provider's cached key material is
    /// discarded.
    pub(crate) dirty_cnt: usize,
}

/// `struct ec_point_st` — `crypto/ec/ec_local.h:315-329`.
///
/// **48 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`. `EC_POINT_new`
/// allocates it and `ossl_ec_GFp_simple_point_init`/`ossl_ec_GF2m_simple_point_init` fill it, so
/// the three `BIGNUM`s are the object's own from construction. The four bytes at 12..16 are
/// padding after the four-byte `curve_name`, and the last member is the four-byte `Z_is_one`
/// flag that lets the arithmetic skip a reduction — a flag the authority recomputes
/// conservatively and a transcription that made it a `bool` would leave as one byte.
#[repr(C)]
pub struct EcPoint {
    /// `const EC_METHOD *meth` — borrowed, and what `EC_POINT_method_of` returns.
    pub(crate) meth: *const EcMethod,
    /// `int curve_name` — the NID for the curve if known.
    pub(crate) curve_name: c_int,
    /// `BIGNUM *X` — Jacobian `X`.
    pub(crate) x: *mut BigNum,
    /// `BIGNUM *Y` — Jacobian `Y`.
    pub(crate) y: *mut BigNum,
    /// `BIGNUM *Z` — Jacobian `Z`, so the point is `(X/Z^2, Y/Z^3)` while `Z != 0`.
    pub(crate) z: *mut BigNum,
    /// `int Z_is_one` — the affine fast path.
    pub(crate) z_is_one: c_int,
}

/// `struct ECDSA_SIG_st` — `crypto/ec/ec_local.h:701-704`.
///
/// **16 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`. Two `BIGNUM`
/// pointers and nothing else: the `r` and `s` of a signature, owned by the object that
/// `ECDSA_SIG_new` allocates and released by `ECDSA_SIG_free`. It is declared in this header
/// rather than in `ecdsa_sign.c` because both `EC_KEY_METHOD`'s `sign_sig`/`verify_sig`
/// columns and `EC_METHOD`'s are typed by the pointer.
#[repr(C)]
pub struct EcdsaSig {
    /// `BIGNUM *r`.
    pub(crate) r: *mut BigNum,
    /// `BIGNUM *s`.
    pub(crate) s: *mut BigNum,
}

/// `struct ec_key_method_st` — `crypto/ec/ec_local.h:664-688`.
///
/// **120 bytes**, alignment 8, measured by `courts/layout/measure-ec.c`: a `name` pointer at 0,
/// a four-byte `int32_t flags` at 8, and **thirteen** function pointers from 16 to 112. The
/// offset the declaration does not show is `init` at **16** — `flags` is four bytes and the
/// member after it is a pointer, so 12..16 is padding.
///
/// This is the table `EC_KEY_METHOD_new` allocates, which is why its `flags` word matters: the
/// authority's own static table carries **0** and only a copy made by `EC_KEY_METHOD_new`
/// carries [`EC_KEY_METHOD_DYNAMIC`]. `EC_KEY_METHOD_new(NULL)` therefore returns a table of
/// NULLs whose `flags` is 1, and `EC_KEY_METHOD_free` on the authority's static is a no-op.
#[repr(C)]
pub struct EcKeyMethod {
    /// `const char *name` — duplicated by the caller, never owned by the table.
    pub name: *const c_char,
    /// `int32_t flags` — [`EC_KEY_METHOD_DYNAMIC`] once [`EcKeyMethod`] has been through
    /// `EC_KEY_METHOD_new`.
    pub flags: i32,
    /// `int (*init)(EC_KEY *)`.
    pub init: Option<EcKeyInitFn>,
    /// `void (*finish)(EC_KEY *)`.
    pub finish: Option<EcKeyFinishFn>,
    /// `int (*copy)(EC_KEY *, const EC_KEY *)`.
    pub copy: Option<EcKeyCopyFn>,
    /// `int (*set_group)(EC_KEY *, const EC_GROUP *)`.
    pub set_group: Option<EcKeySetGroupFn>,
    /// `int (*set_private)(EC_KEY *, const BIGNUM *)`.
    pub set_private: Option<EcKeySetPrivateFn>,
    /// `int (*set_public)(EC_KEY *, const EC_POINT *)`.
    pub set_public: Option<EcKeySetPublicFn>,
    /// `int (*keygen)(EC_KEY *)`.
    pub keygen: Option<EcKeyInitFn>,
    /// `int (*compute_key)(unsigned char **, size_t *, const EC_POINT *, const EC_KEY *)`.
    pub compute_key: Option<EcComputeKeyFn>,
    /// `int (*sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
    /// const BIGNUM *, const BIGNUM *, EC_KEY *)`.
    pub sign: Option<EcKeySignFn>,
    /// `int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **)`.
    pub sign_setup: Option<EcKeySignSetupFn>,
    /// `ECDSA_SIG *(*sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *)`.
    pub sign_sig: Option<EcKeySignSigFn>,
    /// `int (*verify)(int, const unsigned char *, int, const unsigned char *, int, EC_KEY *)`.
    pub verify: Option<EcKeyVerifyFn>,
    /// `int (*verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *)`.
    pub verify_sig: Option<EcKeyVerifySigFn>,
}

/// `int (*)(EC_KEY *, const EC_GROUP *)` — `ec_local.h:670`.
pub type EcKeySetGroupFn = unsafe extern "C" fn(eckey: *mut EcKey, group: *const EcGroup) -> c_int;
/// `int (*)(EC_KEY *, const EC_POINT *)` — `ec_local.h:672`.
pub type EcKeySetPublicFn =
    unsafe extern "C" fn(eckey: *mut EcKey, pub_key: *const EcPoint) -> c_int;
/// `int (*)(int, const unsigned char *, int, unsigned char *, unsigned int *, const BIGNUM *,
/// const BIGNUM *, EC_KEY *)` — `ec_local.h:676-677`. The `int type` is the `EVP_PKEY_*`
/// algorithm the caller is signing with, not a flag word.
pub type EcKeySignFn = unsafe extern "C" fn(
    type_: c_int,
    dgst: *const c_uchar,
    dlen: c_int,
    sig: *mut c_uchar,
    siglen: *mut c_uint,
    kinv: *const BigNum,
    r: *const BigNum,
    eckey: *mut EcKey,
) -> c_int;
/// `int (*)(int, const unsigned char *, int, const unsigned char *, int, EC_KEY *)` —
/// `ec_local.h:684-685`.
pub type EcKeyVerifyFn = unsafe extern "C" fn(
    type_: c_int,
    dgst: *const c_uchar,
    dgst_len: c_int,
    sigbuf: *const c_uchar,
    sig_len: c_int,
    eckey: *mut EcKey,
) -> c_int;

/// `ec_point_is_compat` — `crypto/ec/ec_local.h:331-338`.
///
/// The header's one `static ossl_inline` *predicate*: a point belongs to a group when the two
/// share a method and neither has a curve name or the two names agree. It is here because it
/// reads nothing but the four fields [`EcGroup`] and [`EcPoint`] hold, and it is the check
/// `EC_POINT_cmp`, `EC_POINT_add`, `EC_POINT_dbl` and `EC_GROUP_set_generator` make before
/// any arithmetic. Its callers are `ec_lib.c`'s exports and the five method-table units'.
///
/// # Safety
///
/// `point` and `group` are valid, non-NULL and fully initialised.
pub(crate) unsafe fn ec_point_is_compat(point: *const EcPoint, group: *const EcGroup) -> bool {
    // SAFETY: the caller's contract.
    unsafe {
        (*group).meth == (*point).meth
            && ((*group).curve_name == 0
                || (*point).curve_name == 0
                || (*group).curve_name == (*point).curve_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    /// The three `EC_FLAGS_*` and the one `EC_KEY_METHOD_*` word, from
    /// `courts/layout/measure-ec.c`'s read-back of the authority's own headers.
    #[test]
    fn the_method_flags_are_the_authoritys_words() {
        assert_eq!(EC_FLAGS_DEFAULT_OCT, 1);
        assert_eq!(EC_FLAGS_CUSTOM_CURVE, 2);
        assert_eq!(EC_FLAGS_NO_SIGN, 4);
        assert_eq!(EC_KEY_METHOD_DYNAMIC, 1);
    }

    /// The conversion form is a four-byte enum whose three values are 2, 4 and 6 — not 0, 1, 2.
    /// A transcription that numbered them from zero would leave every struct size below
    /// unchanged and every `EC_KEY_get_conv_form` answer wrong.
    #[test]
    fn the_conversion_form_enum_is_the_authoritys() {
        assert_eq!(size_of::<PointConversionForm>(), 4);
        assert_eq!(POINT_CONVERSION_COMPRESSED, 2);
        assert_eq!(POINT_CONVERSION_UNCOMPRESSED, 4);
        assert_eq!(POINT_CONVERSION_HYBRID, 6);
    }

    /// The seven pre-computation discriminators, in the authority's own declaration order.
    #[test]
    fn the_pre_comp_discriminators_are_zero_based_and_ordered() {
        assert_eq!(Pct::None as i32, 0);
        assert_eq!(Pct::Nistp224 as i32, 1);
        assert_eq!(Pct::Nistp256 as i32, 2);
        assert_eq!(Pct::Nistp384 as i32, 3);
        assert_eq!(Pct::Nistp521 as i32, 4);
        assert_eq!(Pct::Nistz256 as i32, 5);
        assert_eq!(Pct::Ec as i32, 6);
    }

    /// `struct ec_method_st` is 448 bytes: two `int`s and fifty-five pointers. The offsets that
    /// pin the *order* are `point_init`/`point_finish` (80/88, an `int`-returning and a
    /// `void`-returning callback that a swap would leave the size of), `mul` at 224 after
    /// `points_make_affine` at 216, and `group_full_init` at 440 as the last of the fifty-five.
    #[test]
    fn the_method_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcMethod>(), 448);
        assert_eq!(align_of::<EcMethod>(), 8);
        assert_eq!(offset_of!(EcMethod, flags), 0);
        assert_eq!(offset_of!(EcMethod, field_type), 4);
        assert_eq!(offset_of!(EcMethod, group_init), 8);
        assert_eq!(offset_of!(EcMethod, group_finish), 16);
        assert_eq!(offset_of!(EcMethod, group_clear_finish), 24);
        assert_eq!(offset_of!(EcMethod, group_copy), 32);
        assert_eq!(offset_of!(EcMethod, group_set_curve), 40);
        assert_eq!(offset_of!(EcMethod, group_get_curve), 48);
        assert_eq!(offset_of!(EcMethod, group_get_degree), 56);
        assert_eq!(offset_of!(EcMethod, group_order_bits), 64);
        assert_eq!(offset_of!(EcMethod, group_check_discriminant), 72);
        assert_eq!(offset_of!(EcMethod, point_init), 80);
        assert_eq!(offset_of!(EcMethod, point_finish), 88);
        assert_eq!(offset_of!(EcMethod, point_clear_finish), 96);
        assert_eq!(offset_of!(EcMethod, point_copy), 104);
        assert_eq!(offset_of!(EcMethod, point_set_to_infinity), 112);
        assert_eq!(offset_of!(EcMethod, point_set_affine_coordinates), 120);
        assert_eq!(offset_of!(EcMethod, point_get_affine_coordinates), 128);
        assert_eq!(offset_of!(EcMethod, point_set_compressed_coordinates), 136);
        assert_eq!(offset_of!(EcMethod, point2oct), 144);
        assert_eq!(offset_of!(EcMethod, oct2point), 152);
        assert_eq!(offset_of!(EcMethod, add), 160);
        assert_eq!(offset_of!(EcMethod, dbl), 168);
        assert_eq!(offset_of!(EcMethod, invert), 176);
        assert_eq!(offset_of!(EcMethod, is_at_infinity), 184);
        assert_eq!(offset_of!(EcMethod, is_on_curve), 192);
        assert_eq!(offset_of!(EcMethod, point_cmp), 200);
        assert_eq!(offset_of!(EcMethod, make_affine), 208);
        assert_eq!(offset_of!(EcMethod, points_make_affine), 216);
        assert_eq!(offset_of!(EcMethod, mul), 224);
        assert_eq!(offset_of!(EcMethod, precompute_mult), 232);
        assert_eq!(offset_of!(EcMethod, have_precompute_mult), 240);
        assert_eq!(offset_of!(EcMethod, field_mul), 248);
        assert_eq!(offset_of!(EcMethod, field_sqr), 256);
        assert_eq!(offset_of!(EcMethod, field_div), 264);
        assert_eq!(offset_of!(EcMethod, field_inv), 272);
        assert_eq!(offset_of!(EcMethod, field_encode), 280);
        assert_eq!(offset_of!(EcMethod, field_decode), 288);
        assert_eq!(offset_of!(EcMethod, field_set_to_one), 296);
        assert_eq!(offset_of!(EcMethod, priv2oct), 304);
        assert_eq!(offset_of!(EcMethod, oct2priv), 312);
        assert_eq!(offset_of!(EcMethod, set_private), 320);
        assert_eq!(offset_of!(EcMethod, keygen), 328);
        assert_eq!(offset_of!(EcMethod, keycheck), 336);
        assert_eq!(offset_of!(EcMethod, keygenpub), 344);
        assert_eq!(offset_of!(EcMethod, keycopy), 352);
        assert_eq!(offset_of!(EcMethod, keyfinish), 360);
        assert_eq!(offset_of!(EcMethod, ecdh_compute_key), 368);
        assert_eq!(offset_of!(EcMethod, ecdsa_sign_setup), 376);
        assert_eq!(offset_of!(EcMethod, ecdsa_sign_sig), 384);
        assert_eq!(offset_of!(EcMethod, ecdsa_verify_sig), 392);
        assert_eq!(offset_of!(EcMethod, field_inverse_mod_ord), 400);
        assert_eq!(offset_of!(EcMethod, blind_coordinates), 408);
        assert_eq!(offset_of!(EcMethod, ladder_pre), 416);
        assert_eq!(offset_of!(EcMethod, ladder_step), 424);
        assert_eq!(offset_of!(EcMethod, ladder_post), 432);
        assert_eq!(offset_of!(EcMethod, group_full_init), 440);
    }

    /// `struct ec_group_st` is 184 bytes. `poly` at **72** and the union `pre_comp` at **160**
    /// are the two offsets a reader would not predict: 24 bytes of `int[6]` sit between `field`
    /// and `a`, and the four-byte discriminator at 152 is followed by four bytes of padding
    /// before an eight-byte-aligned union.
    #[test]
    fn the_group_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcGroup>(), 184);
        assert_eq!(align_of::<EcGroup>(), 8);
        assert_eq!(offset_of!(EcGroup, meth), 0);
        assert_eq!(offset_of!(EcGroup, generator), 8);
        assert_eq!(offset_of!(EcGroup, order), 16);
        assert_eq!(offset_of!(EcGroup, cofactor), 24);
        assert_eq!(offset_of!(EcGroup, curve_name), 32);
        assert_eq!(offset_of!(EcGroup, asn1_flag), 36);
        assert_eq!(offset_of!(EcGroup, decoded_from_explicit_params), 40);
        assert_eq!(offset_of!(EcGroup, asn1_form), 44);
        assert_eq!(offset_of!(EcGroup, seed), 48);
        assert_eq!(offset_of!(EcGroup, seed_len), 56);
        assert_eq!(offset_of!(EcGroup, field), 64);
        assert_eq!(offset_of!(EcGroup, poly), 72);
        assert_eq!(offset_of!(EcGroup, a), 96);
        assert_eq!(offset_of!(EcGroup, b), 104);
        assert_eq!(offset_of!(EcGroup, a_is_minus3), 112);
        assert_eq!(offset_of!(EcGroup, field_data1), 120);
        assert_eq!(offset_of!(EcGroup, field_data2), 128);
        assert_eq!(offset_of!(EcGroup, field_mod_func), 136);
        assert_eq!(offset_of!(EcGroup, mont_data), 144);
        assert_eq!(offset_of!(EcGroup, pre_comp_type), 152);
        assert_eq!(offset_of!(EcGroup, pre_comp), 160);
        assert_eq!(offset_of!(EcGroup, libctx), 168);
        assert_eq!(offset_of!(EcGroup, propq), 176);
    }

    /// `struct ec_point_st` is 48 bytes, with the four bytes at 12..16 the profile's padding.
    #[test]
    fn the_point_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcPoint>(), 48);
        assert_eq!(align_of::<EcPoint>(), 8);
        assert_eq!(offset_of!(EcPoint, meth), 0);
        assert_eq!(offset_of!(EcPoint, curve_name), 8);
        assert_eq!(offset_of!(EcPoint, x), 16);
        assert_eq!(offset_of!(EcPoint, y), 24);
        assert_eq!(offset_of!(EcPoint, z), 32);
        assert_eq!(offset_of!(EcPoint, z_is_one), 40);
    }

    /// `struct ec_key_st` is 104 bytes. `ex_data` at **64** is the offset that shows
    /// `references` and `flags` are both four bytes: were either pointer-sized, `ex_data` would
    /// be at 72 and the object eight bytes wider.
    #[test]
    fn the_key_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcKey>(), 104);
        assert_eq!(align_of::<EcKey>(), 8);
        assert_eq!(offset_of!(EcKey, meth), 0);
        assert_eq!(offset_of!(EcKey, engine), 8);
        assert_eq!(offset_of!(EcKey, version), 16);
        assert_eq!(offset_of!(EcKey, group), 24);
        assert_eq!(offset_of!(EcKey, pub_key), 32);
        assert_eq!(offset_of!(EcKey, priv_key), 40);
        assert_eq!(offset_of!(EcKey, enc_flag), 48);
        assert_eq!(offset_of!(EcKey, conv_form), 52);
        assert_eq!(offset_of!(EcKey, references), 56);
        assert_eq!(offset_of!(EcKey, flags), 60);
        assert_eq!(offset_of!(EcKey, ex_data), 64);
        assert_eq!(offset_of!(EcKey, libctx), 80);
        assert_eq!(offset_of!(EcKey, propq), 88);
        assert_eq!(offset_of!(EcKey, dirty_cnt), 96);
    }

    /// `struct ec_key_method_st` is 120 bytes: a pointer, a four-byte `int32_t`, four bytes of
    /// padding, and thirteen pointers.
    #[test]
    fn the_key_method_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcKeyMethod>(), 120);
        assert_eq!(align_of::<EcKeyMethod>(), 8);
        assert_eq!(offset_of!(EcKeyMethod, name), 0);
        assert_eq!(offset_of!(EcKeyMethod, flags), 8);
        assert_eq!(offset_of!(EcKeyMethod, init), 16);
        assert_eq!(offset_of!(EcKeyMethod, finish), 24);
        assert_eq!(offset_of!(EcKeyMethod, copy), 32);
        assert_eq!(offset_of!(EcKeyMethod, set_group), 40);
        assert_eq!(offset_of!(EcKeyMethod, set_private), 48);
        assert_eq!(offset_of!(EcKeyMethod, set_public), 56);
        assert_eq!(offset_of!(EcKeyMethod, keygen), 64);
        assert_eq!(offset_of!(EcKeyMethod, compute_key), 72);
        assert_eq!(offset_of!(EcKeyMethod, sign), 80);
        assert_eq!(offset_of!(EcKeyMethod, sign_setup), 88);
        assert_eq!(offset_of!(EcKeyMethod, sign_sig), 96);
        assert_eq!(offset_of!(EcKeyMethod, verify), 104);
        assert_eq!(offset_of!(EcKeyMethod, verify_sig), 112);
    }

    /// `struct ECDSA_SIG_st` is two pointers and nothing else.
    #[test]
    fn the_ecdsa_sig_structure_is_the_authoritys_shape() {
        assert_eq!(size_of::<EcdsaSig>(), 16);
        assert_eq!(align_of::<EcdsaSig>(), 8);
        assert_eq!(offset_of!(EcdsaSig, r), 0);
        assert_eq!(offset_of!(EcdsaSig, s), 8);
    }

    /// The union's six arms are all eight bytes, so the group's size is the same whichever
    /// precomputation it holds — which is what makes `SETPRECOMP`'s arm choice a *discriminator*
    /// rather than a layout decision.
    #[test]
    fn every_pre_comp_arm_is_pointer_sized() {
        assert_eq!(size_of::<EcPreComp>(), 8);
        assert_eq!(align_of::<EcPreComp>(), 8);
    }

    /// `ec_point_is_compat` is the four-field comparison, and the two `curve_name == 0` arms are
    /// what make a group with no name and a point with no name compatible. The `meth` identity is
    /// the first conjunct, so two points of the same name under different tables are not.
    #[test]
    fn point_compatibility_is_the_authoritys_four_field_test() {
        // SAFETY: every field read is initialised here, and the three `BIGNUM` pointers are
        // never dereferenced by the predicate.
        unsafe {
            let mut group: EcGroup = core::mem::zeroed();
            let mut point: EcPoint = core::mem::zeroed();
            let method: EcMethod = core::mem::zeroed();
            let other: EcMethod = core::mem::zeroed();

            group.meth = &method;
            point.meth = &method;
            // Both names zero: the third disjunct holds whatever `curve_name` is set to below.
            assert!(ec_point_is_compat(&point, &group));

            group.curve_name = 409;
            assert!(ec_point_is_compat(&point, &group));

            point.curve_name = 409;
            assert!(ec_point_is_compat(&point, &group));

            point.curve_name = 415;
            assert!(!ec_point_is_compat(&point, &group));

            point.curve_name = 409;
            group.meth = &other;
            assert!(!ec_point_is_compat(&point, &group));
        }
    }
}
