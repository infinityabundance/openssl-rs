//! `crypto/ec/ec_lib.c` — the `EC_GROUP` and `EC_POINT` objects, Phase 8.7.
//!
//! One thousand eight hundred lines: sixty-nine exports, six internals and five file-static
//! helpers. All sixty-nine exports land here, including `EC_GROUP_new_from_params` and
//! `EC_GROUP_to_params`, which reach `ossl_ec_group_todata`, `ossl_ec_encoding_param2id` and
//! `ossl_ec_pt_format_param2id` — `crypto/ec/ec_backend.c`'s, landed in [`crate::ec::backend`]
//! — and whose two statics `group_new_from_name` and `ec_group_explicit_to_named` sit beside
//! them at the end of this file.
//!
//! The six internals are the whole set: `ossl_ec_group_new_ex`, `ossl_ec_group_set_params`,
//! `ossl_ec_group_do_inverse_ord`, `ossl_ec_group_simple_order_bits`,
//! `ossl_ec_point_blind_coordinates` and `EC_pre_comp_free`. `ossl_ec_group_set_params` reads
//! `ossl_ec_encoding_param2id`/`ossl_ec_pt_format_param2id` **by crate path** from
//! [`crate::ec::backend`], the unit that defines them.
//!
//! ## The two directions of the layer's cycle are both inside this file
//!
//! `ecp_smpl.c` calls eight of this unit's exports directly (`EC_POINT_dbl`, `_copy`,
//! `_is_at_infinity`, `_set_affine_coordinates`, `_get_affine_coordinates`, `_invert`,
//! `_set_to_infinity`, `_set_Jprojective_coordinates_GFp`), and this unit calls
//! `ecp_smpl.c`'s `ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp`/`_get_…` from its two
//! `EC_POINT_*Jprojective*` exports. That is why §3 of the plan measures the pair as one landing
//! rather than an order, and why this module and [`crate::ec::smpl`] are in one commit. The other
//! three names it reaches are `ec_mult.c`'s (`ossl_ec_wNAF_mul`, `_precompute_mult`,
//! `_have_precompute_mult`, `EC_ec_pre_comp_dup`/`_free`), all in [`crate::ec::mult`], and
//! `ecp_nistz256.c`'s `EC_nistz256_pre_comp_dup`/`_free`, which are **not given a module**: the
//! field construction behind them is perlasm-only, so the two arms that read them are transcribed
//! as references to `crate::ec::nistz256` and the arithmetic they guard is unreachable while no
//! nistz256 group can be constructed. §8 of the plan records that boundary as `D-EC-2`.
//!
//! ## The error sites
//!
//! The `ERR_raise` sites this unit reaches are named `err_sites::EC_LIB_<line>` after the
//! generator's stem for `crypto/ec/ec_lib.c`, which `forensics/tools/gen_err_raise_sites.py`'s
//! `COVERED_FILES` now lists.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::bn::arith::{BN_add, BN_cmp, BN_div, BN_rshift1, BN_sub};
use crate::bn::bignum::{
    BN_clear_free, BN_copy, BN_free, BN_is_negative, BN_is_odd, BN_is_zero, BN_new, BN_num_bits,
    BN_set_bit, BN_set_word, BN_value_one, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new, BN_CTX_new_ex, BN_CTX_secure_new,
    BN_CTX_start, BnCtx,
};
use crate::bn::exp::bn_mod_exp_mont_fixed_top;
use crate::bn::mont::{
    BN_MONT_CTX_copy, BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set, MontCtx,
};
use crate::ec::curve::{ossl_ec_curve_nid_from_params, EC_GROUP_new_by_curve_name_ex};
use crate::ec::cvt::{EC_GROUP_new_curve_GF2m, EC_GROUP_new_curve_GFp};
use crate::ec::mult::{
    ossl_ec_wNAF_have_precompute_mult, ossl_ec_wNAF_mul, ossl_ec_wNAF_precompute_mult,
    EC_ec_pre_comp_dup, EC_ec_pre_comp_free, EcPreCompSt,
};
use crate::ec::oct::EC_POINT_oct2point;
use crate::ec::smpl::{
    ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp,
    ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp,
};
use crate::ec::support::ossl_ec_curve_name2nid;
use crate::ec::{ec_point_is_compat, EcGroup, EcKey, EcMethod, EcPoint, Pct};
use crate::evp::pkey_ctx::{OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param, OSSL_PARAM_BLD,
};
use crate::params::{
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_get_utf8_ptr, OsslParam, OSSL_PARAM_UTF8_PTR,
    OSSL_PARAM_UTF8_STRING,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{CRYPTO_get_ex_data, CRYPTO_set_ex_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::obj::{
    NID_X9_62_characteristic_two_field, NID_X9_62_ppBasis, NID_X9_62_tpBasis, NID_undef,
};

/// The translation-unit coordinate the `OPENSSL_zalloc`/`OPENSSL_malloc`/`OPENSSL_strdup`/
/// `OPENSSL_free` sites in this unit are attributed to, as the allocator reports them.
const FILE: *const c_char = c"crypto/ec/ec_lib.c".as_ptr();

// `#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128` holds on this profile, so `PCT_nistp224` ..
// `PCT_nistp521` compile to empty arms in the two pre-computation switches. The four arms are
// therefore written as one no-op arm where the authority writes four `break`s. `PCT_nistz256`'s
// arm reads `EC_nistz256_pre_comp_free`/`_dup` (`crypto/ec/ecp_nistz256.c`), which is not given
// a module because its field construction is perlasm-only; §8 of the plan records that boundary
// as `D-EC-2`, and the two arms are therefore the **named omission** that record describes
// rather than an untaken branch: the pre-computation path is unreachable while no nistz256 group
// can be constructed, and the two names are given here so nothing is silently dropped.

/// `EC_GROUP *ossl_ec_group_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
/// const EC_METHOD *meth)` — `crypto/ec/ec_lib.c:30-75`.
///
/// A NULL method raises `EC_R_SLOT_FULL`; a method with no `group_init` raises
/// `ERR_R_SHOULD_NOT_BE_HAVE_BEEN_CALLED`; otherwise the group is zero-allocated, its `libctx`
/// and duplicated `propq` stored, `order`/`cofactor` made unless the method is a custom-curve
/// table, `asn1_flag`/`asn1_form` set to `OPENSSL_EC_EXPLICIT_CURVE`/`POINT_CONVERSION_UNCOMPRESSED`,
/// and `group_init` run. Every failure path after the allocation releases exactly what it set.
///
/// # Safety
///
/// `meth` is NULL or points to a live, immutable `EC_METHOD`; `propq` is NULL or a
/// NUL-terminated string; `libctx` is NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
    meth: *const EcMethod,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if meth.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:36`, EC_R_SLOT_FULL).
            raise_site(&err_sites::EC_LIB_36);
            return ptr::null_mut();
        }
        if (*meth).group_init.is_none() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:40`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_40);
            return ptr::null_mut();
        }

        // `OPENSSL_zalloc(sizeof(*ret))`, line 44.
        let ret = CRYPTO_zalloc(core::mem::size_of::<EcGroup>(), FILE, 44).cast::<EcGroup>();
        if ret.is_null() {
            return ptr::null_mut();
        }

        (*ret).libctx = libctx;
        if !propq.is_null() {
            (*ret).propq = CRYPTO_strdup(propq, FILE, 50);
            if (*ret).propq.is_null() {
                return new_ex_err(ret);
            }
        }
        (*ret).meth = meth;
        if (*meth).flags & crate::ec::EC_FLAGS_CUSTOM_CURVE == 0 {
            (*ret).order = BN_new();
            if (*ret).order.is_null() {
                return new_ex_err(ret);
            }
            (*ret).cofactor = BN_new();
            if (*ret).cofactor.is_null() {
                return new_ex_err(ret);
            }
        }
        (*ret).asn1_flag = OPENSSL_EC_EXPLICIT_CURVE;
        (*ret).asn1_form = crate::ec::POINT_CONVERSION_UNCOMPRESSED;
        let Some(group_init) = (*meth).group_init else {
            unreachable!("checked above")
        };
        if group_init(ret) == 0 {
            return new_ex_err(ret);
        }
        ret
    }
}

/// The authority's `err:` label of [`ossl_ec_group_new_ex`] (`ec_lib.c:69-74`): release the two
/// BIGNUMs, the property string and the object.
///
/// # Safety
///
/// `group` is the object this constructor just allocated and has not published.
unsafe fn new_ex_err(group: *mut EcGroup) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_free((*group).order);
        BN_free((*group).cofactor);
        // `OPENSSL_free(ret->propq)` / `OPENSSL_free(ret)`, lines 72-73.
        CRYPTO_free((*group).propq.cast(), FILE, 72);
        CRYPTO_free(group.cast(), FILE, 73);
    }
    ptr::null_mut()
}

/// `EC_GROUP *EC_GROUP_new(const EC_METHOD *meth)` — `crypto/ec/ec_lib.c:79-82`.
///
/// `#ifndef OPENSSL_NO_DEPRECATED_3_0` and `#ifndef FIPS_MODULE`, both open on this profile, so
/// the deprecated constructor is compiled. It is `ossl_ec_group_new_ex(NULL, NULL, meth)`.
///
/// # Safety
///
/// `meth` is NULL or a live, immutable `EC_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new(meth: *const EcMethod) -> *mut EcGroup {
    // SAFETY: this function's own contract.
    unsafe { ossl_ec_group_new_ex(ptr::null_mut(), ptr::null(), meth) }
}

/// `void EC_pre_comp_free(EC_GROUP *group)` — `crypto/ec/ec_lib.c:86-121`.
///
/// The discriminator decides which union arm is released. `PCT_nistz256`'s arm is compiled on
/// this profile (`ECP_NISTZ256_ASM` is defined) and names `crate::ec::nistz256`'s free; the four
/// `PCT_nistp*` arms compile to empty; `PCT_ec` names [`EC_ec_pre_comp_free`]. The final store
/// clears the `ec` arm whichever one was live, exactly as the authority does.
///
/// # Safety
///
/// `group` is live and owns whatever its `pre_comp` arm points at.
#[no_mangle]
pub unsafe extern "C" fn EC_pre_comp_free(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        match (*group).pre_comp_type {
            Pct::None => {}
            // `EC_nistz256_pre_comp_free(group->pre_comp.nistz256)` (`ec_lib.c:93`) is the
            // `ECP_NISTZ256_ASM` arm, defined on this profile and **omitted as D-EC-2**: the
            // symbol is `crypto/ec/ecp_nistz256.c`'s and that unit has no crate module, so the
            // arm is unreachable rather than untranscribed. See the note above this section.
            Pct::Nistz256 => {}
            // `#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128` is false here: the four arms are empty.
            Pct::Nistp224 | Pct::Nistp256 | Pct::Nistp384 | Pct::Nistp521 => {}
            Pct::Ec => {
                // SAFETY: `pre_comp_type` is `PCT_ec`, so this arm is the live one.
                EC_ec_pre_comp_free((*group).pre_comp.ec.cast::<EcPreCompSt>());
            }
        }
        (*group).pre_comp.ec = ptr::null_mut();
    }
}

/// `void EC_GROUP_free(EC_GROUP *group)` — `crypto/ec/ec_lib.c:123-139`.
///
/// # Safety
///
/// `group` is NULL or a live, owned group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_free(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            return;
        }

        if let Some(group_finish) = (*group).meth.as_ref().and_then(|m| m.group_finish) {
            group_finish(group);
        }

        EC_pre_comp_free(group);
        BN_MONT_CTX_free((*group).mont_data);
        EC_POINT_free((*group).generator);
        BN_free((*group).order);
        BN_free((*group).cofactor);
        CRYPTO_free((*group).seed.cast(), FILE, 136);
        CRYPTO_free((*group).propq.cast(), FILE, 137);
        CRYPTO_free(group.cast(), FILE, 138);
    }
}

/// `void EC_GROUP_clear_free(EC_GROUP *group)` — `crypto/ec/ec_lib.c:142-159`.
///
/// `#ifndef OPENSSL_NO_DEPRECATED_3_0`, compiled here. The `clear_finish` column is preferred
/// over `finish`, and the bignums, seed and object are all cleansed before release.
///
/// # Safety
///
/// `group` is NULL or a live, owned group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_clear_free(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            return;
        }

        let meth = (*group).meth;
        if let Some(clear_finish) = (*meth).group_clear_finish {
            clear_finish(group);
        } else if let Some(finish) = (*meth).group_finish {
            finish(group);
        }

        EC_pre_comp_free(group);
        BN_MONT_CTX_free((*group).mont_data);
        EC_POINT_clear_free((*group).generator);
        BN_clear_free((*group).order);
        BN_clear_free((*group).cofactor);
        // `OPENSSL_clear_free(group->seed, group->seed_len)`, line 157.
        CRYPTO_clear_free((*group).seed.cast(), (*group).seed_len, FILE, 157);
        // `OPENSSL_clear_free(group, sizeof(*group))`, line 158.
        CRYPTO_clear_free(group.cast(), core::mem::size_of::<EcGroup>(), FILE, 158);
    }
}

/// `int EC_GROUP_copy(EC_GROUP *dest, const EC_GROUP *src)` — `crypto/ec/ec_lib.c:162-269`.
///
/// The copy is field by field; the pre-computation switch mirrors [`EC_pre_comp_free`]'s, the
/// Montgomery data and generator are made or cleared as the source has them, and the seed is
/// reallocated rather than shared. The method's own `group_copy` is the last call and its answer
/// is the function's.
///
/// # Safety
///
/// `dest` is a live, mutable group; `src` is a live group compatible with it.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_copy(dest: *mut EcGroup, src: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*dest).meth.as_ref().and_then(|m| m.group_copy).is_none() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:165`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_165);
            return 0;
        }
        if (*dest).meth != (*src).meth {
            // SAFETY: a compile-time-constant site (`ec_lib.c:169`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_169);
            return 0;
        }
        if dest == src.cast_mut() {
            return 1;
        }

        (*dest).libctx = (*src).libctx;
        (*dest).curve_name = (*src).curve_name;

        EC_pre_comp_free(dest);

        /* Copy precomputed */
        (*dest).pre_comp_type = (*src).pre_comp_type;
        match (*src).pre_comp_type {
            Pct::None => {
                (*dest).pre_comp.ec = ptr::null_mut();
            }
            // `EC_nistz256_pre_comp_dup(src->pre_comp.nistz256)` (`ec_lib.c:188`) is omitted as
            // D-EC-2, exactly as [`EC_pre_comp_free`]'s free arm is.
            Pct::Nistz256 => {}
            // The four `PCT_nistp*` arms are empty on this profile.
            Pct::Nistp224 | Pct::Nistp256 | Pct::Nistp384 | Pct::Nistp521 => {}
            Pct::Ec => {
                // SAFETY: `src->pre_comp_type` is `PCT_ec`, so this arm is the live one.
                (*dest).pre_comp.ec =
                    EC_ec_pre_comp_dup((*src).pre_comp.ec.cast::<EcPreCompSt>()).cast::<c_void>();
            }
        }

        if !(*src).mont_data.is_null() {
            if (*dest).mont_data.is_null() {
                (*dest).mont_data = BN_MONT_CTX_new();
                if (*dest).mont_data.is_null() {
                    return 0;
                }
            }
            if BN_MONT_CTX_copy((*dest).mont_data, (*src).mont_data).is_null() {
                return 0;
            }
        } else {
            /* src->generator == NULL */
            BN_MONT_CTX_free((*dest).mont_data);
            (*dest).mont_data = ptr::null_mut();
        }

        if !(*src).generator.is_null() {
            if (*dest).generator.is_null() {
                (*dest).generator = EC_POINT_new(dest);
                if (*dest).generator.is_null() {
                    return 0;
                }
            }
            if EC_POINT_copy((*dest).generator, (*src).generator) == 0 {
                return 0;
            }
        } else {
            /* src->generator == NULL */
            EC_POINT_clear_free((*dest).generator);
            (*dest).generator = ptr::null_mut();
        }

        if (*(*src).meth).flags & crate::ec::EC_FLAGS_CUSTOM_CURVE == 0 {
            if BN_copy((*dest).order, (*src).order).is_null() {
                return 0;
            }
            if BN_copy((*dest).cofactor, (*src).cofactor).is_null() {
                return 0;
            }
        }

        (*dest).asn1_flag = (*src).asn1_flag;
        (*dest).asn1_form = (*src).asn1_form;
        (*dest).decoded_from_explicit_params = (*src).decoded_from_explicit_params;

        if !(*src).seed.is_null() {
            CRYPTO_free((*dest).seed.cast(), FILE, 256);
            (*dest).seed = CRYPTO_malloc((*src).seed_len, FILE, 257).cast::<core::ffi::c_uchar>();
            if (*dest).seed.is_null() {
                return 0;
            }
            // The authority tests `!memcpy(..)`, which is unreachable: `memcpy` cannot return
            // NULL. The copy is unconditional here, as the authority's own transfer is.
            ptr::copy_nonoverlapping((*src).seed, (*dest).seed, (*src).seed_len);
            (*dest).seed_len = (*src).seed_len;
        } else {
            CRYPTO_free((*dest).seed.cast(), FILE, 263);
            (*dest).seed = ptr::null_mut();
            (*dest).seed_len = 0;
        }

        let Some(group_copy) = (*(*dest).meth).group_copy else {
            // A table with a NULL `group_copy` is one the authority never builds; the column is
            // non-NULL in all five landed tables, so this arm is unreachable and answers the
            // failure value rather than a fabricated copy.
            return 0;
        };
        group_copy(dest, src)
    }
}

/// `EC_GROUP *EC_GROUP_dup(const EC_GROUP *a)` — `crypto/ec/ec_lib.c:271-292`.
///
/// A NULL argument answers NULL; otherwise a fresh group is made through
/// [`ossl_ec_group_new_ex`] with the source's context, property string and method, and
/// [`EC_GROUP_copy`] fills it. A failed copy frees the new group.
///
/// # Safety
///
/// `a` is NULL or a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_dup(a: *const EcGroup) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if a.is_null() {
            return ptr::null_mut();
        }

        let t = ossl_ec_group_new_ex((*a).libctx, (*a).propq, (*a).meth);
        if t.is_null() {
            return ptr::null_mut();
        }
        if EC_GROUP_copy(t, a) == 0 {
            EC_GROUP_free(t);
            return ptr::null_mut();
        }
        t
    }
}

/// `const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:295-298`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_method_of(group: *const EcGroup) -> *const EcMethod {
    // SAFETY: the caller's contract.
    unsafe { (*group).meth }
}

/// `int EC_METHOD_get_field_type(const EC_METHOD *meth)` — `crypto/ec/ec_lib.c:300-303`.
///
/// # Safety
///
/// `meth` is a live, immutable `EC_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn EC_METHOD_get_field_type(meth: *const EcMethod) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*meth).field_type }
}

/// `static int ec_precompute_mont_data(EC_GROUP *)` — forward declaration at `ec_lib.c:306`,
/// body at `:1188-1215`.
///
/// Builds `group->mont_data` from `group->order`. The field is cleared first, so a failure leaves
/// it NULL rather than stale. The context is the group's own `libctx`.
///
/// # Safety
///
/// `group` is live and its `order` is live.
unsafe fn ec_precompute_mont_data(group: *mut EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ctx = BN_CTX_new_ex((*group).libctx);
        let mut ret = 0;

        BN_MONT_CTX_free((*group).mont_data);
        (*group).mont_data = ptr::null_mut();

        if ctx.is_null() {
            return ret;
        }

        (*group).mont_data = BN_MONT_CTX_new();
        if (*group).mont_data.is_null() {
            BN_CTX_free(ctx);
            return ret;
        }

        if BN_MONT_CTX_set((*group).mont_data, (*group).order, ctx) == 0 {
            BN_MONT_CTX_free((*group).mont_data);
            (*group).mont_data = ptr::null_mut();
            BN_CTX_free(ctx);
            return ret;
        }

        ret = 1;
        BN_CTX_free(ctx);
        ret
    }
}

/// `static int ec_guess_cofactor(EC_GROUP *group)` — `crypto/ec/ec_lib.c:321-368`.
///
/// The Hasse-bound argument in the authority's comment is transcribed at the one place it
/// decides a branch: an order no longer than `lg(4*sqrt(q))` makes the cofactor ambiguous, so
/// the cofactor is zeroed and success is reported. Otherwise `q` is `2^m` for a
/// characteristic-two field and `p` otherwise, and `h = floor((q + 1 + n/2)/n)`.
///
/// # Safety
///
/// `group` is live; its `order`, `field`, `cofactor` and `libctx` are live.
unsafe fn ec_guess_cofactor(group: *mut EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = 0;

        if BN_num_bits((*group).order) <= (BN_num_bits((*group).field) + 1) / 2 + 3 {
            crate::bn::bignum::BN_zero_ex((*group).cofactor);
            return 1;
        }

        let ctx = BN_CTX_new_ex((*group).libctx);
        if ctx.is_null() {
            return 0;
        }

        BN_CTX_start(ctx);
        let q = BN_CTX_get(ctx);
        if q.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        /* set q = 2**m for binary fields; q = p otherwise */
        if (*(*group).meth).field_type == NID_X9_62_characteristic_two_field {
            crate::bn::bignum::BN_zero_ex(q);
            if BN_set_bit(q, BN_num_bits((*group).field) - 1) == 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ret;
            }
        } else if BN_copy(q, (*group).field).is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        /* h = floor((q + 1)/n) == floor((q + 1 + n/2)/n) */
        if BN_rshift1((*group).cofactor, (*group).order) == 0
            || BN_add((*group).cofactor, (*group).cofactor, q) == 0
            || BN_add((*group).cofactor, (*group).cofactor, BN_value_one()) == 0
            || BN_div(
                (*group).cofactor,
                ptr::null_mut(),
                (*group).cofactor,
                (*group).order,
                ctx,
            ) == 0
        {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        ret = 1;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        ret
    }
}

/// `int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order,
/// const BIGNUM *cofactor)` — `crypto/ec/ec_lib.c:370-438`.
///
/// Four refusals precede the copy: a NULL generator, a field that is missing, zero or negative,
/// an order that is missing, zero, negative or more than one bit longer than the field, and a
/// negative cofactor. The generator is then made if the group has none, the order is copied, and
/// the cofactor is either the caller's non-zero one or [`ec_guess_cofactor`]'s. An odd order
/// finishes through [`ec_precompute_mont_data`]; an even one clears the Montgomery data because
/// its setup would fail.
///
/// # Safety
///
/// `group` is live; `generator` is live; `order` and `cofactor` are live or NULL.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_generator(
    group: *mut EcGroup,
    generator: *const EcPoint,
    order: *const BigNum,
    cofactor: *const BigNum,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if generator.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:374`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_LIB_374);
            return 0;
        }

        /* require group->field >= 1 */
        if (*group).field.is_null()
            || BN_is_zero((*group).field) != 0
            || BN_is_negative((*group).field) != 0
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:381`, EC_R_INVALID_FIELD).
            raise_site(&err_sites::EC_LIB_381);
            return 0;
        }

        if order.is_null()
            || BN_is_zero(order) != 0
            || BN_is_negative(order) != 0
            || BN_num_bits(order) > BN_num_bits((*group).field) + 1
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:392`, EC_R_INVALID_GROUP_ORDER).
            raise_site(&err_sites::EC_LIB_392);
            return 0;
        }

        if !cofactor.is_null() && BN_is_negative(cofactor) != 0 {
            // SAFETY: a compile-time-constant site (`ec_lib.c:402`, EC_R_UNKNOWN_COFACTOR).
            raise_site(&err_sites::EC_LIB_402);
            return 0;
        }

        if (*group).generator.is_null() {
            (*group).generator = EC_POINT_new(group);
            if (*group).generator.is_null() {
                return 0;
            }
        }
        if EC_POINT_copy((*group).generator, generator) == 0 {
            return 0;
        }

        if BN_copy((*group).order, order).is_null() {
            return 0;
        }

        /* Either take the provided positive cofactor, or try to compute it */
        if !cofactor.is_null() && BN_is_zero(cofactor) == 0 {
            if BN_copy((*group).cofactor, cofactor).is_null() {
                return 0;
            }
        } else if ec_guess_cofactor(group) == 0 {
            crate::bn::bignum::BN_zero_ex((*group).cofactor);
            return 0;
        }

        if BN_is_odd((*group).order) != 0 {
            return ec_precompute_mont_data(group);
        }

        BN_MONT_CTX_free((*group).mont_data);
        (*group).mont_data = ptr::null_mut();
        1
    }
}

/// `const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group)` —
/// `crypto/ec/ec_lib.c:440-443`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get0_generator(group: *const EcGroup) -> *const EcPoint {
    // SAFETY: the caller's contract.
    unsafe { (*group).generator }
}

/// `BN_MONT_CTX *EC_GROUP_get_mont_data(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:445-448`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_mont_data(group: *const EcGroup) -> *mut MontCtx {
    // SAFETY: the caller's contract.
    unsafe { (*group).mont_data }
}

/// `int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:450-458`.
///
/// The answer is 0 when the group has no order, and otherwise the copy's own success **and** the
/// copied value's non-zeroness. `ctx` is ignored.
///
/// # Safety
///
/// `group` is live; `order` is a live, writable `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_order(
    group: *const EcGroup,
    order: *mut BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).order.is_null() {
            return 0;
        }
        if BN_copy(order, (*group).order).is_null() {
            return 0;
        }

        c_int::from(BN_is_zero(order) == 0)
    }
}

/// `const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:460-463`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get0_order(group: *const EcGroup) -> *const BigNum {
    // SAFETY: the caller's contract.
    unsafe { (*group).order }
}

/// `int EC_GROUP_order_bits(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:465-468`.
///
/// # Safety
///
/// `group` is live and its method has an `group_order_bits` column.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_order_bits(group: *const EcGroup) -> c_int {
    // SAFETY: the caller's contract; the column is read as the authority reads it.
    unsafe {
        match (*(*group).meth).group_order_bits {
            Some(group_order_bits) => group_order_bits(group),
            None => 0,
        }
    }
}

/// `int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:470-480`.
///
/// As [`EC_GROUP_get_order`], but the non-zeroness test is against the group's own cofactor
/// rather than the copy.
///
/// # Safety
///
/// `group` is live; `cofactor` is a live, writable `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_cofactor(
    group: *const EcGroup,
    cofactor: *mut BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).cofactor.is_null() {
            return 0;
        }
        if BN_copy(cofactor, (*group).cofactor).is_null() {
            return 0;
        }

        c_int::from(BN_is_zero((*group).cofactor) == 0)
    }
}

/// `const BIGNUM *EC_GROUP_get0_cofactor(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:482-485`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get0_cofactor(group: *const EcGroup) -> *const BigNum {
    // SAFETY: the caller's contract.
    unsafe { (*group).cofactor }
}

/// `void EC_GROUP_set_curve_name(EC_GROUP *group, int nid)` — `crypto/ec/ec_lib.c:487-493`.
///
/// The ASN.1 flag is a consequence of the NID rather than a separate argument: `NID_undef` means
/// explicit parameters and anything else named ones.
///
/// # Safety
///
/// `group` is live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_curve_name(group: *mut EcGroup, nid: c_int) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*group).curve_name = nid;
        (*group).asn1_flag = if nid != NID_undef {
            OPENSSL_EC_NAMED_CURVE
        } else {
            OPENSSL_EC_EXPLICIT_CURVE
        };
    }
}

/// `int EC_GROUP_get_curve_name(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:495-498`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_curve_name(group: *const EcGroup) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*group).curve_name }
}

/// `const BIGNUM *EC_GROUP_get0_field(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:500-503`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get0_field(group: *const EcGroup) -> *const BigNum {
    // SAFETY: the caller's contract.
    unsafe { (*group).field }
}

/// `int EC_GROUP_get_field_type(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:505-508`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_field_type(group: *const EcGroup) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*(*group).meth).field_type }
}

/// `void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag)` — `crypto/ec/ec_lib.c:510-513`.
///
/// # Safety
///
/// `group` is live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_asn1_flag(group: *mut EcGroup, flag: c_int) {
    // SAFETY: the caller's contract.
    unsafe { (*group).asn1_flag = flag };
}

/// `int EC_GROUP_get_asn1_flag(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:515-518`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_asn1_flag(group: *const EcGroup) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*group).asn1_flag }
}

/// `void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form)` —
/// `crypto/ec/ec_lib.c:520-524`.
///
/// # Safety
///
/// `group` is live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_point_conversion_form(
    group: *mut EcGroup,
    form: crate::ec::PointConversionForm,
) {
    // SAFETY: the caller's contract.
    unsafe { (*group).asn1_form = form };
}

/// `point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *group)` —
/// `crypto/ec/ec_lib.c:526-530`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_point_conversion_form(
    group: *const EcGroup,
) -> crate::ec::PointConversionForm {
    // SAFETY: the caller's contract.
    unsafe { (*group).asn1_form }
}

/// `size_t EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *p, size_t len)` —
/// `crypto/ec/ec_lib.c:532-547`.
///
/// The old seed is always released and cleared first. A zero length or a NULL pointer then
/// answers **1** — not 0 and not `len` — which is the authority's own "cleared successfully"
/// answer and the one `ec_group_explicit_to_named`'s `!= 1` tests rely on.
///
/// # Safety
///
/// `group` is live; `p` is NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_seed(
    group: *mut EcGroup,
    p: *const core::ffi::c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        CRYPTO_free((*group).seed.cast(), FILE, 534);
        (*group).seed = ptr::null_mut();
        (*group).seed_len = 0;

        if len == 0 || p.is_null() {
            return 1;
        }

        (*group).seed = CRYPTO_malloc(len, FILE, 541).cast::<core::ffi::c_uchar>();
        if (*group).seed.is_null() {
            return 0;
        }
        ptr::copy_nonoverlapping(p, (*group).seed, len);
        (*group).seed_len = len;

        len
    }
}

/// `unsigned char *EC_GROUP_get0_seed(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:549-552`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get0_seed(group: *const EcGroup) -> *mut core::ffi::c_uchar {
    // SAFETY: the caller's contract.
    unsafe { (*group).seed }
}

/// `size_t EC_GROUP_get_seed_len(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:554-557`.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_seed_len(group: *const EcGroup) -> usize {
    // SAFETY: the caller's contract.
    unsafe { (*group).seed_len }
}

/// `int EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:559-567`.
///
/// # Safety
///
/// `group` is live and its method has a `group_set_curve` column; `p`, `a`, `b` are live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_curve(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(group_set_curve) = (*(*group).meth).group_set_curve else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:563`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_563);
            return 0;
        };
        group_set_curve(group, p, a, b, ctx)
    }
}

/// `int EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)`
/// — `crypto/ec/ec_lib.c:569-577`.
///
/// # Safety
///
/// `group` is live and its method has a `group_get_curve` column; `p`, `a`, `b` are live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_curve(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(group_get_curve) = (*(*group).meth).group_get_curve else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:573`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_573);
            return 0;
        };
        group_get_curve(group, p, a, b, ctx)
    }
}

/// `int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:580-584`. A deprecated spelling of
/// [`EC_GROUP_set_curve`].
///
/// # Safety
///
/// As [`EC_GROUP_set_curve`].
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_curve_GFp(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_GROUP_set_curve(group, p, a, b, ctx) }
}

/// `int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:586-590`.
///
/// # Safety
///
/// As [`EC_GROUP_get_curve`].
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_curve_GFp(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_GROUP_get_curve(group, p, a, b, ctx) }
}

/// `int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:593-597`, inside `#ifndef OPENSSL_NO_EC2M`
/// and deprecated.
///
/// # Safety
///
/// As [`EC_GROUP_set_curve`].
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_set_curve_GF2m(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_GROUP_set_curve(group, p, a, b, ctx) }
}

/// `int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:599-603`, inside `#ifndef OPENSSL_NO_EC2M` and deprecated.
///
/// # Safety
///
/// As [`EC_GROUP_get_curve`].
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_curve_GF2m(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_GROUP_get_curve(group, p, a, b, ctx) }
}

/// `int EC_GROUP_get_degree(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:607-614`.
///
/// # Safety
///
/// `group` is live and its method has a `group_get_degree` column.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_degree(group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(group_get_degree) = (*(*group).meth).group_get_degree else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:610`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_610);
            return 0;
        };
        group_get_degree(group)
    }
}

/// `int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:616-623`.
///
/// # Safety
///
/// `group` is live and its method has a `group_check_discriminant` column; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_check_discriminant(
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(check) = (*(*group).meth).group_check_discriminant else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:619`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_619);
            return 0;
        };
        check(group, ctx)
    }
}

/// `int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:625-712`.
///
/// The answer is 0 for equal, 1 for different and −1 for an error. Field type and, when both
/// groups carry one, curve name are compared first; a custom-curve method is equal to anything
/// of the same field type. Otherwise `(p, a, b)` are read from both methods, the generators are
/// compared through [`EC_POINT_cmp`], and finally the orders and — when both are present — the
/// cofactors. The context is made when the caller supplies none.
///
/// # Safety
///
/// `a` and `b` are live groups; `ctx` is NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_cmp(
    a: *const EcGroup,
    b: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut r = 0;
        let mut ctx = ctx;
        let mut ctx_new: *mut BnCtx = ptr::null_mut();

        /* compare the field types */
        if EC_GROUP_get_field_type(a) != EC_GROUP_get_field_type(b) {
            return 1;
        }
        /* compare the curve name (if present in both) */
        if EC_GROUP_get_curve_name(a) != 0
            && EC_GROUP_get_curve_name(b) != 0
            && EC_GROUP_get_curve_name(a) != EC_GROUP_get_curve_name(b)
        {
            return 1;
        }
        if (*(*a).meth).flags & crate::ec::EC_FLAGS_CUSTOM_CURVE != 0 {
            return 0;
        }

        if ctx.is_null() {
            ctx_new = BN_CTX_new();
            ctx = ctx_new;
        }
        if ctx.is_null() {
            return -1;
        }

        BN_CTX_start(ctx);
        let a1 = BN_CTX_get(ctx);
        let a2 = BN_CTX_get(ctx);
        let a3 = BN_CTX_get(ctx);
        let b1 = BN_CTX_get(ctx);
        let b2 = BN_CTX_get(ctx);
        let b3 = BN_CTX_get(ctx);
        if b3.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx_new);
            return -1;
        }

        let group_get_curve_a = (*(*a).meth).group_get_curve;
        let group_get_curve_b = (*(*b).meth).group_get_curve;
        match (group_get_curve_a, group_get_curve_b) {
            (Some(ga), Some(gb)) => {
                if ga(a, a1, a2, a3, ctx) == 0 || gb(b, b1, b2, b3, ctx) == 0 {
                    r = 1;
                }
            }
            // A NULL `group_get_curve` cannot occur on a landed table; answer "different".
            _ => r = 1,
        }

        if r != 0 || BN_cmp(a1, b1) != 0 || BN_cmp(a2, b2) != 0 || BN_cmp(a3, b3) != 0 {
            r = 1;
        }

        if r != 0
            || EC_POINT_cmp(
                a,
                EC_GROUP_get0_generator(a),
                EC_GROUP_get0_generator(b),
                ctx,
            ) != 0
        {
            r = 1;
        }

        if r == 0 {
            let ao = EC_GROUP_get0_order(a);
            let bo = EC_GROUP_get0_order(b);
            if ao.is_null() || bo.is_null() {
                r = -1;
                BN_CTX_end(ctx);
                BN_CTX_free(ctx_new);
                return r;
            }
            if BN_cmp(ao, bo) != 0 {
                r = 1;
                BN_CTX_end(ctx);
                BN_CTX_free(ctx_new);
                return r;
            }
            let ac = EC_GROUP_get0_cofactor(a);
            let bc = EC_GROUP_get0_cofactor(b);
            if BN_is_zero(ac) == 0 && BN_is_zero(bc) == 0 && BN_cmp(ac, bc) != 0 {
                r = 1;
            }
        }
        BN_CTX_end(ctx);
        BN_CTX_free(ctx_new);
        r
    }
}

/* functions for EC_POINT objects */

/// `EC_POINT *EC_POINT_new(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:716-742`.
///
/// A NULL group and a method without `point_init` are refused before the allocation; the new
/// point borrows the group's method and curve name and is filled by `point_init`.
///
/// # Safety
///
/// `group` is NULL or a live group whose method has a `point_init` column.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_new(group: *const EcGroup) -> *mut EcPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:721`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_LIB_721);
            return ptr::null_mut();
        }
        if (*(*group).meth).point_init.is_none() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:725`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_725);
            return ptr::null_mut();
        }

        // `OPENSSL_zalloc(sizeof(*ret))`, line 729.
        let ret = CRYPTO_zalloc(core::mem::size_of::<EcPoint>(), FILE, 729).cast::<EcPoint>();
        if ret.is_null() {
            return ptr::null_mut();
        }

        (*ret).meth = (*group).meth;
        (*ret).curve_name = (*group).curve_name;

        let Some(point_init) = (*(*ret).meth).point_init else {
            // A NULL `point_init` cannot occur on a landed table.
            CRYPTO_free(ret.cast(), FILE, 737);
            return ptr::null_mut();
        };
        if point_init(ret) == 0 {
            CRYPTO_free(ret.cast(), FILE, 737);
            return ptr::null_mut();
        }

        ret
    }
}

/// `void EC_POINT_free(EC_POINT *point)` — `crypto/ec/ec_lib.c:744-756`.
///
/// `OPENSSL_PEDANTIC_ZEROIZATION` is not defined on this profile, so the non-clearing arm is the
/// one compiled: the method's `point_finish` runs and the object is released.
///
/// # Safety
///
/// `point` is NULL or a live, owned point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_free(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if point.is_null() {
            return;
        }

        if let Some(point_finish) = (*point).meth.as_ref().and_then(|m| m.point_finish) {
            point_finish(point);
        }
        CRYPTO_free(point.cast(), FILE, 754);
    }
}

/// `void EC_POINT_clear_free(EC_POINT *point)` — `crypto/ec/ec_lib.c:758-768`.
///
/// # Safety
///
/// `point` is NULL or a live, owned point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_clear_free(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if point.is_null() {
            return;
        }

        let meth = (*point).meth;
        if let Some(clear_finish) = (*meth).point_clear_finish {
            clear_finish(point);
        } else if let Some(finish) = (*meth).point_finish {
            finish(point);
        }
        // `OPENSSL_clear_free(point, sizeof(*point))`, line 767.
        CRYPTO_clear_free(point.cast(), core::mem::size_of::<EcPoint>(), FILE, 767);
    }
}

/// `int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)` — `crypto/ec/ec_lib.c:770-786`.
///
/// The compatibility test is the point's own: equal methods and either curve name zero or
/// equal. An identical pair is a no-op that answers 1.
///
/// # Safety
///
/// `dest` is a live, mutable point; `src` is a live point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_copy(dest: *mut EcPoint, src: *const EcPoint) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*dest).meth.as_ref().and_then(|m| m.point_copy).is_none() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:773`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_773);
            return 0;
        }
        if (*dest).meth != (*src).meth
            || ((*dest).curve_name != (*src).curve_name
                && (*dest).curve_name != 0
                && (*src).curve_name != 0)
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:780`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_780);
            return 0;
        }
        if dest == src.cast_mut() {
            return 1;
        }
        match (*(*dest).meth).point_copy {
            Some(point_copy) => point_copy(dest, src),
            None => 0,
        }
    }
}

/// `EC_POINT *EC_POINT_dup(const EC_POINT *a, const EC_GROUP *group)` —
/// `crypto/ec/ec_lib.c:788-805`.
///
/// A NULL point answers NULL; otherwise a fresh point is made in `group` and the copy fills it.
///
/// # Safety
///
/// `a` is NULL or a live point; `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_dup(a: *const EcPoint, group: *const EcGroup) -> *mut EcPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if a.is_null() {
            return ptr::null_mut();
        }

        let t = EC_POINT_new(group);
        if t.is_null() {
            return ptr::null_mut();
        }
        if EC_POINT_copy(t, a) == 0 {
            EC_POINT_free(t);
            return ptr::null_mut();
        }
        t
    }
}

/// `const EC_METHOD *EC_POINT_method_of(const EC_POINT *point)` — `crypto/ec/ec_lib.c:808-811`.
///
/// # Safety
///
/// `point` is a live point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_method_of(point: *const EcPoint) -> *const EcMethod {
    // SAFETY: the caller's contract.
    unsafe { (*point).meth }
}

/// `int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)` —
/// `crypto/ec/ec_lib.c:814-825`.
///
/// This one checks method *identity* rather than [`ec_point_is_compat`], because the point's
/// curve name is not yet meaningful.
///
/// # Safety
///
/// `group` is live and its method has a `point_set_to_infinity` column; `point` is a live point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_to_infinity(
    group: *const EcGroup,
    point: *mut EcPoint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*(*group).meth).point_set_to_infinity.is_none() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:817`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_817);
            return 0;
        }
        if (*group).meth != (*point).meth {
            // SAFETY: a compile-time-constant site (`ec_lib.c:821`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_821);
            return 0;
        }
        match (*(*group).meth).point_set_to_infinity {
            Some(point_set_to_infinity) => point_set_to_infinity(group, point),
            None => 0,
        }
    }
}

/// `int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:828-843`.
///
/// The `ec_local.h` internal `ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp` is called
/// directly rather than through the method table, which is why this export is the pair's
/// `ec_smpl.c` edge rather than a dispatch.
///
/// # Safety
///
/// `group` is live and a prime-field group; `point` is a live compatible point; `x`, `y`, `z`
/// are live; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_Jprojective_coordinates_GFp(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    z: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*(*group).meth).field_type != crate::runtime::obj::NID_X9_62_prime_field {
            // SAFETY: a compile-time-constant site (`ec_lib.c:834`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_834);
            return 0;
        }
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:838`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_838);
            return 0;
        }
        ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(group, point, x, y, z, ctx)
    }
}

/// `int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
/// BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:845-860`.
///
/// # Safety
///
/// As [`EC_POINT_set_Jprojective_coordinates_GFp`], with `x`, `y`, `z` writable.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_get_Jprojective_coordinates_GFp(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    z: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*(*group).meth).field_type != crate::runtime::obj::NID_X9_62_prime_field {
            // SAFETY: a compile-time-constant site (`ec_lib.c:851`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_851);
            return 0;
        }
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:855`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_855);
            return 0;
        }
        ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(group, point, x, y, z, ctx)
    }
}

/// `int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:863-883`.
///
/// The point is put on the curve by the method and then **checked** with
/// [`EC_POINT_is_on_curve`], whose `<= 0` answer is the failure the authority reports as
/// `EC_R_POINT_IS_NOT_ON_CURVE`.
///
/// # Safety
///
/// `group` is live and its method has a `point_set_affine_coordinates` column; `point` is a live
/// compatible point; `x` and `y` are live; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_affine_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(set_affine) = (*(*group).meth).point_set_affine_coordinates else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:868`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_868);
            return 0;
        };
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:872`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_872);
            return 0;
        }
        if set_affine(group, point, x, y, ctx) == 0 {
            return 0;
        }

        if EC_POINT_is_on_curve(group, point, ctx) <= 0 {
            // SAFETY: a compile-time-constant site (`ec_lib.c:879`, EC_R_POINT_IS_NOT_ON_CURVE).
            raise_site(&err_sites::EC_LIB_879);
            return 0;
        }
        1
    }
}

/// `int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:886-891`. Deprecated.
///
/// # Safety
///
/// As [`EC_POINT_set_affine_coordinates`].
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_affine_coordinates_GFp(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_POINT_set_affine_coordinates(group, point, x, y, ctx) }
}

/// `int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:894-899`, inside
/// `#ifndef OPENSSL_NO_EC2M` and deprecated.
///
/// # Safety
///
/// As [`EC_POINT_set_affine_coordinates`].
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_affine_coordinates_GF2m(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_POINT_set_affine_coordinates(group, point, x, y, ctx) }
}

/// `int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *point,
/// BIGNUM *x, BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:903-920`.
///
/// The point at infinity has no affine coordinates, and the check precedes the method call.
///
/// # Safety
///
/// `group` is live and its method has a `point_get_affine_coordinates` column; `point` is a live
/// compatible point; `x` and `y` are live or NULL; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_get_affine_coordinates(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(get_affine) = (*(*group).meth).point_get_affine_coordinates else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:908`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_908);
            return 0;
        };
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:912`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_912);
            return 0;
        }
        if EC_POINT_is_at_infinity(group, point) != 0 {
            // SAFETY: a compile-time-constant site (`ec_lib.c:916`, EC_R_POINT_AT_INFINITY).
            raise_site(&err_sites::EC_LIB_916);
            return 0;
        }
        get_affine(group, point, x, y, ctx)
    }
}

/// `int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *point,
/// BIGNUM *x, BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:923-928`. Deprecated.
///
/// # Safety
///
/// As [`EC_POINT_get_affine_coordinates`].
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_get_affine_coordinates_GFp(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_POINT_get_affine_coordinates(group, point, x, y, ctx) }
}

/// `int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group, const EC_POINT *point,
/// BIGNUM *x, BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:931-936`, inside
/// `#ifndef OPENSSL_NO_EC2M` and deprecated.
///
/// # Safety
///
/// As [`EC_POINT_get_affine_coordinates`].
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_get_affine_coordinates_GF2m(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { EC_POINT_get_affine_coordinates(group, point, x, y, ctx) }
}

/// `int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:940-953`.
///
/// # Safety
///
/// `group` is live and its method has an `add` column; `r`, `a` and `b` are live compatible
/// points; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_add(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(add) = (*(*group).meth).add else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:944`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_944);
            return 0;
        };
        if !ec_point_is_compat(r, group)
            || !ec_point_is_compat(a, group)
            || !ec_point_is_compat(b, group)
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:949`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_949);
            return 0;
        }
        add(group, r, a, b, ctx)
    }
}

/// `int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:955-967`.
///
/// # Safety
///
/// `group` is live and its method has a `dbl` column; `r` and `a` are live compatible points;
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_dbl(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(dbl) = (*(*group).meth).dbl else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:959`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_959);
            return 0;
        };
        if !ec_point_is_compat(r, group) || !ec_point_is_compat(a, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:963`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_963);
            return 0;
        }
        dbl(group, r, a, ctx)
    }
}

/// `int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:969-980`.
///
/// # Safety
///
/// `group` is live and its method has an `invert` column; `a` is a live compatible point; `ctx`
/// is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_invert(
    group: *const EcGroup,
    a: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(invert) = (*(*group).meth).invert else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:972`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_972);
            return 0;
        };
        if !ec_point_is_compat(a, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:976`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_976);
            return 0;
        }
        invert(group, a, ctx)
    }
}

/// `int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)` —
/// `crypto/ec/ec_lib.c:982-993`.
///
/// # Safety
///
/// `group` is live and its method has an `is_at_infinity` column; `point` is a live compatible
/// point.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_is_at_infinity(
    group: *const EcGroup,
    point: *const EcPoint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(is_at_infinity) = (*(*group).meth).is_at_infinity else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:985`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_985);
            return 0;
        };
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:989`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_989);
            return 0;
        }
        is_at_infinity(group, point)
    }
}

/// `int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:1002-1014`.
///
/// The answer is **not a boolean**: 1 on the curve, 0 off it, −1 on an error. The authority's
/// own comment says so and `EC_POINT_set_affine_coordinates` is the caller that relies on it.
///
/// # Safety
///
/// `group` is live and its method has an `is_on_curve` column; `point` is a live compatible
/// point; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_is_on_curve(
    group: *const EcGroup,
    point: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(is_on_curve) = (*(*group).meth).is_on_curve else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1006`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1006);
            return 0;
        };
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1010`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_1010);
            return 0;
        }
        is_on_curve(group, point, ctx)
    }
}

/// `int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx)`
/// — `crypto/ec/ec_lib.c:1016-1028`.
///
/// The error answer is **−1**, not 0, so a caller that treats "different" as false does not read
/// an error as agreement.
///
/// # Safety
///
/// `group` is live and its method has a `point_cmp` column; `a` and `b` are live compatible
/// points; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_cmp(
    group: *const EcGroup,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(point_cmp) = (*(*group).meth).point_cmp else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1020`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1020);
            return -1;
        };
        if !ec_point_is_compat(a, group) || !ec_point_is_compat(b, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1024`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_1024);
            return -1;
        }
        point_cmp(group, a, b, ctx)
    }
}

/// `int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:1031-1042`. Deprecated.
///
/// # Safety
///
/// `group` is live and its method has a `make_affine` column; `point` is a live compatible point;
/// `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_make_affine(
    group: *const EcGroup,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(make_affine) = (*(*group).meth).make_affine else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1034`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1034);
            return 0;
        };
        if !ec_point_is_compat(point, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1038`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_1038);
            return 0;
        }
        make_affine(group, point, ctx)
    }
}

/// `int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[],
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:1044-1060`.
///
/// Every point is checked for compatibility before the method is called, so a method never sees
/// a foreign point.
///
/// # Safety
///
/// `group` is live and its method has a `points_make_affine` column; `points` holds `num` live
/// compatible points; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINTs_make_affine(
    group: *const EcGroup,
    num: usize,
    points: *mut *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(points_make_affine) = (*(*group).meth).points_make_affine else {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1050`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1050);
            return 0;
        };
        for i in 0..num {
            if !ec_point_is_compat(*points.add(i), group) {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1055`, EC_R_INCOMPATIBLE_OBJECTS).
                raise_site(&err_sites::EC_LIB_1055);
                return 0;
            }
        }
        points_make_affine(group, num, points, ctx)
    }
}

/// `int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar, size_t num,
/// const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:1070-1114`. Deprecated.
///
/// The method's `mul` column is used when it is present and `ossl_ec_wNAF_mul` otherwise — a
/// fall-through rather than a call through a NULL, which is why [`crate::ec::EcMethod::mul`]'s
/// doc calls the column's absence the authority's own. A NULL scalar with `num == 0` is the
/// point at infinity, and the secure context is made when the caller supplies none.
///
/// # Safety
///
/// `group` is live; `r` and every `points[i]` are live compatible points; `scalar`, `scalars[i]`
/// are live or NULL; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINTs_mul(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
    num: usize,
    points: *mut *const EcPoint,
    scalars: *mut *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ret;
        let mut ctx = ctx;
        let mut new_ctx: *mut BnCtx = ptr::null_mut();

        if !ec_point_is_compat(r, group) {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1081`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_1081);
            return 0;
        }

        if scalar.is_null() && num == 0 {
            return EC_POINT_set_to_infinity(group, r);
        }

        for i in 0..num {
            if !ec_point_is_compat(*points.add(i), group) {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1090`, EC_R_INCOMPATIBLE_OBJECTS).
                raise_site(&err_sites::EC_LIB_1090);
                return 0;
            }
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_secure_new();
            ctx = new_ctx;
        }
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1100`, ERR_R_INTERNAL_ERROR).
            raise_site(&err_sites::EC_LIB_1100);
            return 0;
        }

        if let Some(mul) = (*(*group).meth).mul {
            ret = mul(group, r, scalar, num, points, scalars, ctx);
        } else {
            ret = ossl_ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);
        }

        BN_CTX_free(new_ctx);
        ret
    }
}

/// `int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
/// const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:1117-1155`.
///
/// The two scalars are packed into the one-element arrays [`EC_POINTs_mul`] takes: `num` is 1
/// only when both a point and its scalar are present.
///
/// # Safety
///
/// `group` is live; `r` and `point` are live compatible points (or `point` NULL); `g_scalar` and
/// `p_scalar` are live or NULL; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_mul(
    group: *const EcGroup,
    r: *mut EcPoint,
    g_scalar: *const BigNum,
    point: *const EcPoint,
    p_scalar: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ret;
        let mut ctx = ctx;
        let mut new_ctx: *mut BnCtx = ptr::null_mut();

        if !ec_point_is_compat(r, group) || (!point.is_null() && !ec_point_is_compat(point, group))
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1128`, EC_R_INCOMPATIBLE_OBJECTS).
            raise_site(&err_sites::EC_LIB_1128);
            return 0;
        }

        if g_scalar.is_null() && p_scalar.is_null() {
            return EC_POINT_set_to_infinity(group, r);
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_secure_new();
            ctx = new_ctx;
        }
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1140`, ERR_R_INTERNAL_ERROR).
            raise_site(&err_sites::EC_LIB_1140);
            return 0;
        }

        let num = if !point.is_null() && !p_scalar.is_null() {
            1
        } else {
            0
        };
        // The authority passes `&point`/`&p_scalar` — the addresses of its own local parameter
        // copies — which is what `const EC_POINT *points[]` decays to. Rust has to name the
        // storage mutably to hand out the same `*mut *const` shape.
        let mut points_slot: *const EcPoint = point;
        let mut scalars_slot: *const BigNum = p_scalar;
        if let Some(mul) = (*(*group).meth).mul {
            ret = mul(
                group,
                r,
                g_scalar,
                num,
                &mut points_slot,
                &mut scalars_slot,
                ctx,
            );
        } else {
            ret = ossl_ec_wNAF_mul(
                group,
                r,
                g_scalar,
                num,
                &mut points_slot,
                &mut scalars_slot,
                ctx,
            );
        }

        BN_CTX_free(new_ctx);
        ret
    }
}

/// `int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:1158-1168`. Deprecated.
///
/// With no `mul` column the default `ossl_ec_wNAF_precompute_mult` runs; with one, the table's
/// own `precompute_mult` is preferred and a table that has neither column reports success
/// without doing anything.
///
/// # Safety
///
/// `group` is live; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_precompute_mult(group: *mut EcGroup, ctx: *mut BnCtx) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*(*group).meth).mul.is_none() {
            return ossl_ec_wNAF_precompute_mult(group, ctx);
        }

        if let Some(precompute_mult) = (*(*group).meth).precompute_mult {
            precompute_mult(group, ctx)
        } else {
            1 /* nothing to do, so report success */
        }
    }
}

/// `int EC_GROUP_have_precompute_mult(const EC_GROUP *group)` —
/// `crypto/ec/ec_lib.c:1170-1181`. Deprecated.
///
/// The authority's own asymmetry: with no `mul` column it asks the default implementation, and
/// with one but no `have_precompute_mult` column it answers 0 — *cannot tell*, not *no*.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_have_precompute_mult(group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*(*group).meth).mul.is_none() {
            return ossl_ec_wNAF_have_precompute_mult(group);
        }

        if let Some(have_precompute_mult) = (*(*group).meth).have_precompute_mult {
            have_precompute_mult(group)
        } else {
            0 /* cannot tell whether precomputation has been performed */
        }
    }
}

/// `int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg)` — `crypto/ec/ec_lib.c:1218-1221`.
///
/// `#ifndef FIPS_MODULE`, compiled here.
///
/// # Safety
///
/// `key` is live; `arg` is whatever the index's free/dup callbacks expect.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_ex_data(
    key: *mut EcKey,
    idx: c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract; `ex_data` is a field of the live key.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*key).ex_data), idx, arg) }
}

/// `void *EC_KEY_get_ex_data(const EC_KEY *key, int idx)` — `crypto/ec/ec_lib.c:1223-1226`.
///
/// # Safety
///
/// `key` is a live key; `idx` is an index earlier registered for this object.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get_ex_data(key: *const EcKey, idx: c_int) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*key).ex_data), idx) }
}

/// `int ossl_ec_group_simple_order_bits(const EC_GROUP *group)` —
/// `crypto/ec/ec_lib.c:1229-1234`.
///
/// The default `group_order_bits` column of every one of the five tables: the bit length of the
/// group's order, or 0 when it has none.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_simple_order_bits(group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).order.is_null() {
            return 0;
        }
        BN_num_bits((*group).order)
    }
}

/// `static int ec_field_inverse_mod_ord(const EC_GROUP *group, BIGNUM *r, const BIGNUM *x,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:1236-1282`.
///
/// The default inverse modulo the order: Fermat's little theorem, `x^(order-2) mod order`,
/// through `bn_mod_exp_mont_fixed_top` so the result is fixed-top. No Montgomery data or no
/// context is a failure, not a fallback.
///
/// # Safety
///
/// `group` is live with live `order` and `mont_data`; `r` and `x` are live; `ctx` is NULL or a
/// live secure context.
unsafe fn ec_field_inverse_mod_ord(
    group: *const EcGroup,
    r: *mut BigNum,
    x: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret = 0;
        let mut ctx = ctx;
        let mut new_ctx: *mut BnCtx = ptr::null_mut();

        if (*group).mont_data.is_null() {
            return 0;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_secure_new();
            ctx = new_ctx;
        }
        if ctx.is_null() {
            return 0;
        }

        BN_CTX_start(ctx);
        let e = BN_CTX_get(ctx);
        if e.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        if BN_set_word(e, 2) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }
        if BN_sub(e, (*group).order, e) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }
        if bn_mod_exp_mont_fixed_top(r, x, e, (*group).order, ctx, (*group).mont_data) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        ret = 1;
        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
        ret
    }
}

/// `int ossl_ec_group_do_inverse_ord(const EC_GROUP *group, BIGNUM *res, const BIGNUM *x,
/// BN_CTX *ctx)` — `crypto/ec/ec_lib.c:1297-1304`.
///
/// The method's `field_inverse_mod_ord` column when it has one — none of the five tables on this
/// profile does — and [`ec_field_inverse_mod_ord`] otherwise.
///
/// # Safety
///
/// `group` is live; `res` and `x` are live; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_do_inverse_ord(
    group: *const EcGroup,
    res: *mut BigNum,
    x: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(field_inverse_mod_ord) = (*(*group).meth).field_inverse_mod_ord {
            field_inverse_mod_ord(group, res, x, ctx)
        } else {
            ec_field_inverse_mod_ord(group, res, x, ctx)
        }
    }
}

/// `int ossl_ec_point_blind_coordinates(const EC_GROUP *group, EC_POINT *p, BN_CTX *ctx)` —
/// `crypto/ec/ec_lib.c:1316-1323`.
///
/// A method that does not implement blinding reports success rather than failure: the wrapper
/// answers 1 when the column is NULL, because coordinate blinding is an optimisation the
/// authority tolerates the absence of.
///
/// # Safety
///
/// `group` is live; `p` is a live compatible point; `ctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_point_blind_coordinates(
    group: *const EcGroup,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let Some(blind_coordinates) = (*(*group).meth).blind_coordinates else {
            return 1; /* ignore if not implemented */
        };

        blind_coordinates(group, p, ctx)
    }
}

/// `int EC_GROUP_get_basis_type(const EC_GROUP *group)` — `crypto/ec/ec_lib.c:1325-1346`.
///
/// The first zero in `poly[]` decides: four terms is a pentanomial basis, two is a trinomial
/// one, anything else is unsupported. A non-binary field is 0 without raising.
///
/// # Safety
///
/// `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_basis_type(group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_GROUP_get_field_type(group) != NID_X9_62_characteristic_two_field {
            /* everything else is currently not supported */
            return 0;
        }

        /* Find the last non-zero element of group->poly[] */
        let mut i = 0usize;
        while i < (*group).poly.len() && (*group).poly[i] != 0 {
            i += 1;
        }

        if i == 4 {
            NID_X9_62_ppBasis
        } else if i == 2 {
            NID_X9_62_tpBasis
        } else {
            /* everything else is currently not supported */
            0
        }
    }
}

/// `int EC_GROUP_get_trinomial_basis(const EC_GROUP *group, unsigned int *k)` —
/// `crypto/ec/ec_lib.c:1349-1365`, inside `#ifndef OPENSSL_NO_EC2M`.
///
/// A NULL group answers 0 without raising; a non-binary field or a `poly[]` that is not a
/// trinomial raises and answers 0. The middle exponent is `poly[1]`.
///
/// # Safety
///
/// `group` is NULL or live; `k` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_trinomial_basis(
    group: *const EcGroup,
    k: *mut c_uint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            return 0;
        }

        if EC_GROUP_get_field_type(group) != NID_X9_62_characteristic_two_field
            || !((*group).poly[0] != 0 && (*group).poly[1] != 0 && (*group).poly[2] == 0)
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1357`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1357);
            return 0;
        }

        if !k.is_null() {
            *k = (*group).poly[1] as c_uint;
        }

        1
    }
}

/// `int EC_GROUP_get_pentanomial_basis(const EC_GROUP *group, unsigned int *k1,
/// unsigned int *k2, unsigned int *k3)` — `crypto/ec/ec_lib.c:1367-1389`, inside
/// `#ifndef OPENSSL_NO_EC2M`.
///
/// As the trinomial accessor, with the three exponents written in the authority's own reverse
/// order (`k1 = poly[3]`, `k2 = poly[2]`, `k3 = poly[1]`).
///
/// # Safety
///
/// `group` is NULL or live; each out-pointer is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_get_pentanomial_basis(
    group: *const EcGroup,
    k1: *mut c_uint,
    k2: *mut c_uint,
    k3: *mut c_uint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            return 0;
        }

        if EC_GROUP_get_field_type(group) != NID_X9_62_characteristic_two_field
            || !((*group).poly[0] != 0
                && (*group).poly[1] != 0
                && (*group).poly[2] != 0
                && (*group).poly[3] != 0
                && (*group).poly[4] == 0)
        {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1377`, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
            raise_site(&err_sites::EC_LIB_1377);
            return 0;
        }

        if !k1.is_null() {
            *k1 = (*group).poly[3] as c_uint;
        }
        if !k2.is_null() {
            *k2 = (*group).poly[2] as c_uint;
        }
        if !k3.is_null() {
            *k3 = (*group).poly[1] as c_uint;
        }

        1
    }
}

/// `int ossl_ec_group_set_params(EC_GROUP *group, const OSSL_PARAM params[])` —
/// `crypto/ec/ec_lib.c:1505-1538`. The unit's one internal, reached by `EC_GROUP_new_from_params`.
///
/// Three parameters are read: the point conversion format, the encoding flag and the optional
/// seed. The first two are decoded by `ec_backend.c`'s `ossl_ec_pt_format_param2id` and
/// `ossl_ec_encoding_param2id`, in [`crate::ec::backend`]; the seed is taken directly from the
/// descriptor. Every parameter is optional, so an empty array succeeds.
///
/// `#[allow(dead_code)]` was here while its only callers — the two `EC_GROUP_*_params` exports —
/// were withheld; both now land at the end of this file.
///
/// # Safety
///
/// `group` is live; `params` is a NUL-key-terminated descriptor array.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_group_set_params(
    group: *mut EcGroup,
    params: *const crate::params::OsslParam,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut encoding_flag: c_int = -1;
        let mut format: c_int = -1;

        // `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` is `"point-format"` (`core_names.h:394`).
        let p = crate::params::OSSL_PARAM_locate_const(params, c"point-format".as_ptr());
        if !p.is_null() {
            if crate::ec::backend::ossl_ec_pt_format_param2id(p, &mut format) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1513`, EC_R_INVALID_FORM).
                raise_site(&err_sites::EC_LIB_1513);
                return 0;
            }
            EC_GROUP_set_point_conversion_form(group, format);
        }

        let p = crate::params::OSSL_PARAM_locate_const(
            params,
            crate::evp::pkey_ctx::OSSL_PKEY_PARAM_EC_ENCODING,
        );
        if !p.is_null() {
            if crate::ec::backend::ossl_ec_encoding_param2id(p, &mut encoding_flag) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1522`, EC_R_INVALID_FORM).
                raise_site(&err_sites::EC_LIB_1522);
                return 0;
            }
            EC_GROUP_set_asn1_flag(group, encoding_flag);
        }
        /* Optional seed */
        // `OSSL_PKEY_PARAM_EC_SEED` is `"seed"` (`core_names.h:397`).
        let p = crate::params::OSSL_PARAM_locate_const(params, c"seed".as_ptr());
        if !p.is_null() {
            /* The seed is allowed to be NULL */
            if (*p).data_type != crate::params::OSSL_PARAM_OCTET_STRING
                || EC_GROUP_set_seed(group, (*p).data.cast(), (*p).data_size) == 0
            {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1533`, EC_R_INVALID_SEED).
                raise_site(&err_sites::EC_LIB_1533);
                return 0;
            }
        }
        1
    }
}

/// `OPENSSL_ECC_MAX_FIELD_BITS` — `include/openssl/ec.h:103`. The largest field
/// `EC_GROUP_new_from_params` will build from explicit parameters.
const OPENSSL_ECC_MAX_FIELD_BITS: c_int = 661;

/// `static EC_GROUP *ec_group_explicit_to_named(const EC_GROUP *group, OSSL_LIB_CTX *libctx,
/// const char *propq, BN_CTX *ctx)` — `crypto/ec/ec_lib.c:1404-1472`.
///
/// Duplicates the group, clears its seed and its cofactor, and asks
/// [`ossl_ec_curve_nid_from_params`] whether the result matches a built-in curve. A match is
/// replaced by the named group the NID names — which is how a set of explicit parameters a
/// caller assembled gets the specialised method for the curve it happens to describe — with the
/// seed removed again when the caller supplied none, so a parsed key keeps its DER encoding.
/// No match answers the **same pointer it was given**, which is why the caller compares
/// `named_group == group` rather than testing for NULL.
///
/// `#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128` is the arm that maps the `wtls12` alias to
/// `secp224r1`; it is not compiled on this profile, exactly as in the authority.
///
/// # Safety
///
/// `group` is live; `libctx` is NULL or a live library context; `propq` is NULL or
/// NUL-terminated; `ctx` is a live `BN_CTX`.
unsafe fn ec_group_explicit_to_named(
    group: *const EcGroup,
    libctx: *mut c_void,
    propq: *const c_char,
    ctx: *mut BnCtx,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret_group: *mut EcGroup = ptr::null_mut();

        let point = EC_GROUP_get0_generator(group);
        let order = EC_GROUP_get0_order(group);
        let no_seed = EC_GROUP_get0_seed(group).is_null();

        let dup = EC_GROUP_dup(group);
        if dup.is_null()
            || EC_GROUP_set_seed(dup, ptr::null(), 0) != 1
            || EC_GROUP_set_generator(dup, point, order, ptr::null()) == 0
        {
            EC_GROUP_free(dup);
            EC_GROUP_free(ret_group);
            return ptr::null_mut();
        }

        let curve_name_nid = ossl_ec_curve_nid_from_params(dup, ctx);
        if curve_name_nid != NID_undef {
            ret_group = EC_GROUP_new_by_curve_name_ex(libctx, propq, curve_name_nid);
            if ret_group.is_null() {
                EC_GROUP_free(dup);
                EC_GROUP_free(ret_group);
                return ptr::null_mut();
            }
            EC_GROUP_set_asn1_flag(ret_group, OPENSSL_EC_EXPLICIT_CURVE);
            if no_seed && EC_GROUP_set_seed(ret_group, ptr::null(), 0) != 1 {
                EC_GROUP_free(dup);
                EC_GROUP_free(ret_group);
                return ptr::null_mut();
            }
        } else {
            ret_group = group.cast_mut();
        }
        EC_GROUP_free(dup);
        ret_group
    }
}

/// `static EC_GROUP *group_new_from_name(const OSSL_PARAM *p, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/ec/ec_lib.c:1475-1502`.
///
/// The simple named-group case of `EC_GROUP_new_from_params`: read the group name out of a
/// `UTF8_STRING` in place or a `UTF8_PTR` through `OSSL_PARAM_get_utf8_ptr`, resolve it with
/// [`ossl_ec_curve_name2nid`] and build it. An unresolved name raises `EC_R_INVALID_CURVE`
/// (`:1495`) and answers NULL; a descriptor of no handled type answers NULL **without** raising.
///
/// # Safety
///
/// `p` is a live `OSSL_PARAM`; `libctx`/`propq` as in [`ec_group_explicit_to_named`].
unsafe fn group_new_from_name(
    p: *const OsslParam,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok = false;
        let mut curve_name: *const c_char = ptr::null();

        if (*p).data_type == OSSL_PARAM_UTF8_STRING {
            // The OSSL_PARAM functions have no support for this.
            curve_name = (*p).data.cast();
            ok = !curve_name.is_null();
        } else if (*p).data_type == OSSL_PARAM_UTF8_PTR {
            ok = OSSL_PARAM_get_utf8_ptr(p, &mut curve_name) != 0;
        }

        if ok {
            let nid = ossl_ec_curve_name2nid(curve_name);
            if nid == NID_undef {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1495`, EC_R_INVALID_CURVE).
                raise_site(&err_sites::EC_LIB_1495);
                return ptr::null_mut();
            }
            return EC_GROUP_new_by_curve_name_ex(libctx, propq, nid);
        }
        ptr::null_mut()
    }
}

/// `EC_GROUP *EC_GROUP_new_from_params(const OSSL_PARAM params[], OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/ec/ec_lib.c:1540-1765`.
///
/// Two paths. A `group-name` parameter is the simple named-group case, handed to
/// [`group_new_from_name`] and then [`ossl_ec_group_set_params`]. Without one the group is built
/// from explicit parameters: the field type, `a`, `b`, `p`, the optional seed, the generator
/// octets, the order (with the Hasse-bound check `BN_num_bits(order) <= field_bits + 1`) and the
/// optional cofactor, and the result is offered to [`ec_group_explicit_to_named`] so that a set of
/// parameters describing a built-in curve is replaced by the named one.
///
/// The FIPS arm (`:1581-1583`, `EC_R_EXPLICIT_PARAMS_NOT_SUPPORTED`) is not compiled on this
/// profile; the `OPENSSL_NO_EC2M` arm (`:1651-1653`) is not compiled either. Every raise
/// coordinate is the authority's own line.
///
/// # Safety
///
/// `params` is a NULL-or-NUL-key-terminated descriptor array; `libctx` is NULL or a live
/// library context; `propq` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_from_params(
    params: *const OsslParam,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcGroup {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        const P_GROUP_NAME: *const c_char = c"group".as_ptr();
        const P_DECODED: *const c_char = c"decoded-from-explicit".as_ptr();
        const P_FIELD_TYPE: *const c_char = c"field-type".as_ptr();
        const P_A: *const c_char = c"a".as_ptr();
        const P_B: *const c_char = c"b".as_ptr();
        const P_P: *const c_char = c"p".as_ptr();
        const P_SEED: *const c_char = c"seed".as_ptr();
        const P_GENERATOR: *const c_char = c"generator".as_ptr();
        const P_ORDER: *const c_char = c"order".as_ptr();
        const P_COFACTOR: *const c_char = c"cofactor".as_ptr();
        const P_ENCODING: *const c_char = c"encoding".as_ptr();

        let mut group: *mut EcGroup = ptr::null_mut();

        // This is the simple named group case.
        let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_GROUP_NAME);
        if !ptmp.is_null() {
            let mut decoded: c_int = 0;

            group = group_new_from_name(ptmp, libctx, propq);
            if group.is_null() {
                return ptr::null_mut();
            }
            if ossl_ec_group_set_params(group, params) == 0 {
                EC_GROUP_free(group);
                return ptr::null_mut();
            }

            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_DECODED);
            if !ptmp.is_null() && OSSL_PARAM_get_int(ptmp, &mut decoded) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1574`, EC_R_WRONG_CURVE_PARAMETERS).
                raise_site(&err_sites::EC_LIB_1574);
                EC_GROUP_free(group);
                return ptr::null_mut();
            }
            (*group).decoded_from_explicit_params = (decoded > 0) as c_int;
            return group;
        }

        // If it gets here then we are trying explicit parameters.
        let bnctx = BN_CTX_new_ex(libctx);
        if bnctx.is_null() {
            // SAFETY: a compile-time-constant site (`ec_lib.c:1588`, ERR_R_BN_LIB).
            raise_site(&err_sites::EC_LIB_1588);
            return ptr::null_mut();
        }
        BN_CTX_start(bnctx);

        let mut p = BN_CTX_get(bnctx);
        let mut a = BN_CTX_get(bnctx);
        let mut b = BN_CTX_get(bnctx);
        let mut order = BN_CTX_get(bnctx);
        let mut cofactor: *mut BigNum = ptr::null_mut();
        let mut point: *mut EcPoint = ptr::null_mut();
        let mut field_bits: c_int = 0;
        let is_prime_field;
        let mut encoding_flag: c_int = -1;
        let mut ok = false;

        'build: {
            if order.is_null() {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1598`, ERR_R_BN_LIB).
                raise_site(&err_sites::EC_LIB_1598);
                break 'build;
            }

            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_FIELD_TYPE);
            if ptmp.is_null() || (*ptmp).data_type != OSSL_PARAM_UTF8_STRING {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1604`, EC_R_INVALID_FIELD).
                raise_site(&err_sites::EC_LIB_1604);
                break 'build;
            }
            // `SN_X9_62_prime_field` / `SN_X9_62_characteristic_two_field` (`obj_mac.h`).
            if crate::runtime::str::OPENSSL_strcasecmp((*ptmp).data.cast(), c"prime-field".as_ptr())
                == 0
            {
                is_prime_field = true;
            } else if crate::runtime::str::OPENSSL_strcasecmp(
                (*ptmp).data.cast(),
                c"characteristic-two-field".as_ptr(),
            ) == 0
            {
                is_prime_field = false;
            } else {
                // Invalid field.
                // SAFETY: a compile-time-constant site (`ec_lib.c:1615`, EC_R_UNSUPPORTED_FIELD).
                raise_site(&err_sites::EC_LIB_1615);
                break 'build;
            }

            let pa = crate::params::OSSL_PARAM_locate_const(params, P_A);
            if OSSL_PARAM_get_BN(pa, &mut a) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1621`, EC_R_INVALID_A).
                raise_site(&err_sites::EC_LIB_1621);
                break 'build;
            }
            let pb = crate::params::OSSL_PARAM_locate_const(params, P_B);
            if OSSL_PARAM_get_BN(pb, &mut b) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1626`, EC_R_INVALID_B).
                raise_site(&err_sites::EC_LIB_1626);
                break 'build;
            }

            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_P);
            if OSSL_PARAM_get_BN(ptmp, &mut p) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1633`, EC_R_INVALID_P).
                raise_site(&err_sites::EC_LIB_1633);
                break 'build;
            }

            if is_prime_field {
                if BN_is_negative(p) != 0 || BN_is_zero(p) != 0 {
                    // SAFETY: a compile-time-constant site (`ec_lib.c:1639`, EC_R_INVALID_P).
                    raise_site(&err_sites::EC_LIB_1639);
                    break 'build;
                }
                field_bits = BN_num_bits(p);
                if field_bits > OPENSSL_ECC_MAX_FIELD_BITS {
                    // SAFETY: a compile-time-constant site (`ec_lib.c:1644`, EC_R_FIELD_TOO_LARGE).
                    raise_site(&err_sites::EC_LIB_1644);
                    break 'build;
                }
                group = EC_GROUP_new_curve_GFp(p, a, b, bnctx);
            } else {
                group = EC_GROUP_new_curve_GF2m(p, a, b, ptr::null_mut());
                if !group.is_null() {
                    field_bits = EC_GROUP_get_degree(group);
                    if field_bits > OPENSSL_ECC_MAX_FIELD_BITS {
                        // SAFETY: a compile-time-constant site (`ec_lib.c:1660`,
                        // EC_R_FIELD_TOO_LARGE).
                        raise_site(&err_sites::EC_LIB_1660);
                        break 'build;
                    }
                }
            }

            if group.is_null() {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1668`, ERR_R_EC_LIB).
                raise_site(&err_sites::EC_LIB_1668);
                break 'build;
            }

            // Optional seed.
            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_SEED);
            if !ptmp.is_null()
                && ((*ptmp).data_type != crate::params::OSSL_PARAM_OCTET_STRING
                    || EC_GROUP_set_seed(group, (*ptmp).data.cast(), (*ptmp).data_size) == 0)
            {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1676`, EC_R_INVALID_SEED).
                raise_site(&err_sites::EC_LIB_1676);
                break 'build;
            }

            // Generator base point.
            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_GENERATOR);
            if ptmp.is_null()
                || (*ptmp).data_type != crate::params::OSSL_PARAM_OCTET_STRING
                || (*ptmp).data_size == 0
            {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1688`, EC_R_INVALID_GENERATOR).
                raise_site(&err_sites::EC_LIB_1688);
                break 'build;
            }
            let buf: *const core::ffi::c_uchar = (*ptmp).data.cast();
            point = EC_POINT_new(group);
            if point.is_null() {
                break 'build;
            }
            EC_GROUP_set_point_conversion_form(group, ((*buf) as c_int) & !0x01);
            if EC_POINT_oct2point(group, point, buf, (*ptmp).data_size, bnctx) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1697`, EC_R_INVALID_GENERATOR).
                raise_site(&err_sites::EC_LIB_1697);
                break 'build;
            }

            // Order.
            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_ORDER);
            if OSSL_PARAM_get_BN(ptmp, &mut order) == 0
                || BN_is_negative(order) != 0
                || BN_is_zero(order) != 0
                || BN_num_bits(order) > field_bits + 1
            {
                // Hasse bound.
                // SAFETY: a compile-time-constant site (`ec_lib.c:1706`, EC_R_INVALID_GROUP_ORDER).
                raise_site(&err_sites::EC_LIB_1706);
                break 'build;
            }

            // Optional cofactor.
            let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_COFACTOR);
            if !ptmp.is_null() {
                cofactor = BN_CTX_get(bnctx);
                if cofactor.is_null() || OSSL_PARAM_get_BN(ptmp, &mut cofactor) == 0 {
                    // SAFETY: a compile-time-constant site (`ec_lib.c:1715`, EC_R_INVALID_COFACTOR).
                    raise_site(&err_sites::EC_LIB_1715);
                    break 'build;
                }
            }

            // Set the generator, order and cofactor (if present).
            if EC_GROUP_set_generator(group, point, order, cofactor) == 0 {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1722`, EC_R_INVALID_GENERATOR).
                raise_site(&err_sites::EC_LIB_1722);
                break 'build;
            }

            let named_group = ec_group_explicit_to_named(group, libctx, propq, bnctx);
            if named_group.is_null() {
                // SAFETY: a compile-time-constant site (`ec_lib.c:1728`,
                // EC_R_INVALID_NAMED_GROUP_CONVERSION).
                raise_site(&err_sites::EC_LIB_1728);
                break 'build;
            }
            if named_group == group {
                // If we did not find a named group then the encoding should be explicit if it
                // was specified.
                let ptmp = crate::params::OSSL_PARAM_locate_const(params, P_ENCODING);
                if !ptmp.is_null()
                    && crate::ec::backend::ossl_ec_encoding_param2id(ptmp, &mut encoding_flag) == 0
                {
                    // SAFETY: a compile-time-constant site (`ec_lib.c:1739`, EC_R_INVALID_ENCODING).
                    raise_site(&err_sites::EC_LIB_1739);
                    break 'build;
                }
                if encoding_flag == OPENSSL_EC_NAMED_CURVE {
                    // SAFETY: a compile-time-constant site (`ec_lib.c:1743`, EC_R_INVALID_ENCODING).
                    raise_site(&err_sites::EC_LIB_1743);
                    break 'build;
                }
                EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
            } else {
                EC_GROUP_free(group);
                group = named_group;
            }
            // We've imported the group from explicit parameters, set it so.
            (*group).decoded_from_explicit_params = 1;
            ok = true;
        }

        if !ok {
            EC_GROUP_free(group);
            group = ptr::null_mut();
        }
        EC_POINT_free(point);
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
        group
    }
}

/// `OSSL_PARAM *EC_GROUP_to_params(const EC_GROUP *group, OSSL_LIB_CTX *libctx,
/// const char *propq, BN_CTX *bnctx)` — `crypto/ec/ec_lib.c:1767-1800`.
///
/// Builds a fresh `OSSL_PARAM_BLD`, fills it through [`crate::ec::backend::ossl_ec_group_todata`]
/// and returns the descriptor array. A caller-supplied `BN_CTX` is borrowed and not released; one
/// this function makes is released with it. Every failure answers NULL after the same cleanup, so
/// a group that is NULL, a builder that cannot be allocated and a `todata` refusal are
/// indistinguishable to a caller — which is the authority's own shape.
///
/// # Safety
///
/// `group` is NULL or live; `libctx` is NULL or a live library context; `propq` is NULL or
/// NUL-terminated; `bnctx` is NULL or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_to_params(
    group: *const EcGroup,
    libctx: *mut c_void,
    propq: *const c_char,
    bnctx: *mut BnCtx,
) -> *mut OsslParam {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut tmpl: *mut OSSL_PARAM_BLD = ptr::null_mut();
        let mut new_bnctx: *mut BnCtx = ptr::null_mut();
        let mut gen_buf: *mut core::ffi::c_uchar = ptr::null_mut();
        let mut params: *mut OsslParam = ptr::null_mut();
        let mut bnctx = bnctx;

        'build: {
            if group.is_null() {
                break 'build;
            }

            tmpl = OSSL_PARAM_BLD_new();
            if tmpl.is_null() {
                break 'build;
            }

            if bnctx.is_null() {
                new_bnctx = BN_CTX_new_ex(libctx);
                bnctx = new_bnctx;
            }
            if bnctx.is_null() {
                break 'build;
            }
            BN_CTX_start(bnctx);

            if crate::ec::backend::ossl_ec_group_todata(
                group,
                tmpl,
                ptr::null_mut(),
                libctx,
                propq,
                bnctx,
                &mut gen_buf,
            ) == 0
            {
                break 'build;
            }

            params = OSSL_PARAM_BLD_to_param(tmpl);
        }

        OSSL_PARAM_BLD_free(tmpl);
        CRYPTO_free(gen_buf.cast(), FILE, 1796);
        BN_CTX_end(bnctx);
        BN_CTX_free(new_bnctx);
        params
    }
}
