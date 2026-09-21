//! `crypto/ec/ec_key.c` — the `EC_KEY` object and its key-derivation and key-check surface,
//! Phase 8.7.
//!
//! One thousand and seventy-eight lines: fourteen internals — `ossl_ec_key_gen`,
//! `ossl_ec_key_simple_generate_key`, `ossl_ec_key_simple_generate_public_key`,
//! `ossl_ec_key_simple_check_key`, the three `ossl_ec_key_public_check*`, the private and pairwise
//! checks, the two `ossl_ec_key_simple_{priv2oct,oct2priv}` and the four libctx/propq
//! readers/writers — and thirty-three exports, `EC_KEY_generate_key` among them. The plan's §1
//! step 7 is this unit together with [`crate::ec::kmeth`], and D339 is why: `EC_KEY_free` frees its
//! group and its point by calling `EC_GROUP_free` and `EC_POINT_free` **by name**, exactly as the
//! authority does, so this unit needs twenty-six of [`crate::ec::lib`]'s exports before it links.
//!
//! ## The two `#ifndef FIPS_MODULE` blocks that are this profile's, and the two `ENGINE` blocks that
//! are not
//!
//! This profile is not FIPS, so the `#ifndef FIPS_MODULE` halves compile and are transcribed:
//! `EC_KEY_new`, `EC_KEY_new_by_curve_name`, and the `CRYPTO_dup_ex_data`/
//! `CRYPTO_free_ex_data`/`CRYPTO_new_ex_data` calls. The two
//! `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` blocks in [`EC_KEY_free`],
//! [`EC_KEY_copy`] and [`EC_KEY_set_group`]'s neighbourhood call `ENGINE_finish`/`ENGINE_init`; the
//! crate has no engine registry and nothing in it can build an `ENGINE`, so each is **reduced to
//! the one effect it has when the registry is empty** — `engine` stays NULL — exactly as
//! [`crate::ec::kmeth`]'s module documentation records for the constructor. Every engine call is
//! named rather than silently dropped.
//!
//! ## The one internal this unit withholds, and its coordinate
//!
//! `ossl_ec_generate_key_dhkem` (`ec_key.c:357-386`) is **not** transcribed. Its body derives a
//! private scalar through `ossl_ec_dhkem_derive_private`
//! (`providers/implementations/kem/libdefault-lib-ec_kem.c:181`), which is the provider KEM DSO's
//! and is not a `libcrypto` export: no crate module can name it, the distribution shell does not
//! scaffold it, and calling it would leave the candidate DSO with an undefined reference. Its only
//! two callers in the whole authority are the provider key management and KEM rows
//! (`providers/implementations/keymgmt/ec_kmgmt.c:1294` and
//! `providers/implementations/kem/ec_kem.c.in:486`), neither of which is in this crate. The name is
//! recorded in `forensics/prerequisites.json`'s divergence list with this module, which is what
//! turns the prerequisite gate's `unwired_function_in_the_current_stratum` finding into a decision:
//! the alternative is a fabricated derivation for a function the provider half owns.
//!
//! ## The `EC_FLAG_*` key-level bits, which are not the `EC_FLAGS_*` method-level ones
//!
//! `include/openssl/ec.h:954-963` declares a second, differently-spelled set — `EC_FLAG_SM2_RANGE`
//! and `EC_FLAG_COFACTOR_ECDH` are the two this unit and [`crate::ec::ecdh_ossl`] read — and they
//! are *key* flags ([`EcKey::flags`]), not the method table's `EC_FLAGS_*` word. The two are
//! defined below; the other members are named where the authority uses them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::bn::arith::{BN_cmp, BN_sub};
use crate::bn::bignum::{
    bn_get_top, bn_wexpand, BN_bin2bn, BN_bn2binpad, BN_clear, BN_clear_free, BN_copy, BN_dup,
    BN_free, BN_is_negative, BN_is_one, BN_is_zero, BN_new, BN_num_bits, BN_secure_new,
    BN_set_flags, BN_value_one, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_secure_new_ex, BN_CTX_start, BnCtx,
};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::ec::curve::EC_GROUP_new_by_curve_name_ex;
use crate::ec::ecdsa::{ECDSA_SIG_free, ECDSA_do_sign, ECDSA_do_verify};
use crate::ec::kmeth::ossl_ec_key_new_method_int;
use crate::ec::lib::{
    ossl_ec_group_new_ex, EC_GROUP_copy, EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get0_cofactor,
    EC_GROUP_get0_order, EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_order_bits, EC_GROUP_precompute_mult, EC_GROUP_set_asn1_flag,
    EC_GROUP_set_point_conversion_form, EC_POINT_cmp, EC_POINT_copy, EC_POINT_dup, EC_POINT_free,
    EC_POINT_get_affine_coordinates, EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_mul,
    EC_POINT_new, EC_POINT_set_affine_coordinates, EC_POINT_set_to_infinity,
};
use crate::ec::oct::{EC_POINT_oct2point, EC_POINT_point2buf};
use crate::ec::{EcGroup, EcKey, EcPoint, EC_FLAGS_CUSTOM_CURVE, EC_FLAGS_NO_SIGN};
use crate::evp::pkey_asn1::Engine;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_EX_INDEX_EC_KEY};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_X9_62_prime_field, NID_sm2};
use crate::selftest::{
    OSSL_SELF_TEST_free, OSSL_SELF_TEST_get_callback, OSSL_SELF_TEST_new, OSSL_SELF_TEST_onbegin,
    OSSL_SELF_TEST_oncorrupt_byte, OSSL_SELF_TEST_onend, OsslCallback,
};

use crate::ec::backend::ossl_ec_key_dup;

/// The translation-unit coordinate the `OPENSSL_free`/`OPENSSL_clear_free`/`OPENSSL_malloc` sites
/// in this unit are attributed to, as the allocator reports them.
const FILE: *const c_char = c"crypto/ec/ec_key.c".as_ptr();

/// `OSSL_SELF_TEST_TYPE_PCT` — `include/openssl/self_test.h:32`.
const OSSL_SELF_TEST_TYPE_PCT: &core::ffi::CStr = c"Conditional_PCT";
/// `OSSL_SELF_TEST_DESC_PCT_ECDSA` — `include/openssl/self_test.h:52`.
const OSSL_SELF_TEST_DESC_PCT_ECDSA: &core::ffi::CStr = c"ECDSA";

/// `EC_FLAG_SM2_RANGE` — `include/openssl/ec.h:954`. Set by [`EC_KEY_set_group`] for an SM2 group,
/// and read by `ec_generate_key`'s private-key range choice.
pub const EC_FLAG_SM2_RANGE: c_int = 0x0004;
/// `EC_FLAG_COFACTOR_ECDH` — `include/openssl/ec.h:955`. Read by
/// [`crate::ec::ecdh_ossl::ossl_ecdh_simple_compute_key`], which multiplies the peer point by the
/// cofactor before the private scalar.
pub const EC_FLAG_COFACTOR_ECDH: c_int = 0x1000;
/// `EC_FLAG_CHECK_NAMED_GROUP` — `include/openssl/ec.h:956`. One of the two bits
/// [`EC_FLAG_CHECK_NAMED_GROUP_MASK`] selects; set by
/// [`crate::ec::backend::ossl_ec_set_check_group_type_from_name`].
pub const EC_FLAG_CHECK_NAMED_GROUP: c_int = 0x2000;
/// `EC_FLAG_CHECK_NAMED_GROUP_NIST` — `include/openssl/ec.h:957`.
pub const EC_FLAG_CHECK_NAMED_GROUP_NIST: c_int = 0x4000;
/// `EC_FLAG_CHECK_NAMED_GROUP_MASK` — `include/openssl/ec.h:958-959`, the OR of the two bits above.
/// `ossl_ec_set_check_group_type_from_name` clears exactly this mask before setting the new mode.
pub const EC_FLAG_CHECK_NAMED_GROUP_MASK: c_int =
    EC_FLAG_CHECK_NAMED_GROUP | EC_FLAG_CHECK_NAMED_GROUP_NIST;
/// `EC_PKEY_NO_PUBKEY` — `include/openssl/ec.h:951`. An `enc_flag` bit read by
/// [`crate::ec::backend::ossl_ec_key_otherparams_fromdata`]'s `EC_INCLUDE_PUBLIC` handling.
pub const EC_PKEY_NO_PUBKEY: c_int = 0x002;

/// `OSSL_KEYMGMT_SELECT_ALL` — `include/openssl/core_dispatch.h`. The selection
/// [`EC_KEY_dup`] passes to `ossl_ec_key_dup`: `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS |
/// OSSL_KEYMGMT_SELECT_ALL_KEY_MATERIAL`. `src/evp/pkey.rs:890` spells the same bits out for its
/// own selection and this unit cannot reach that binding, so the value is repeated here with the
/// header's own coordinate rather than imported.
const OSSL_KEYMGMT_SELECT_ALL: c_int = (0x01 | 0x02) | (0x04 | 0x80);

/// `EC_KEY *EC_KEY_new(void)` — `crypto/ec/ec_key.c:34-37`, inside `#ifndef FIPS_MODULE`, compiled
/// here.
///
/// The three NULLs are the authority's own: no library context, no property query and no engine.
///
/// # Safety
///
/// None observable to the caller: the function takes no pointer and dereferences none.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_new() -> *mut EcKey {
    // SAFETY: this function's own contract.
    unsafe { ossl_ec_key_new_method_int(ptr::null_mut(), ptr::null(), ptr::null_mut()) }
}

/// `EC_KEY *EC_KEY_new_ex(OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/ec/ec_key.c:40-43`.
///
/// # Safety
///
/// `ctx` is NULL or a live library context; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_new_ex(ctx: *mut c_void, propq: *const c_char) -> *mut EcKey {
    // SAFETY: this function's own contract.
    unsafe { ossl_ec_key_new_method_int(ctx, propq, ptr::null_mut()) }
}

/// `EC_KEY *EC_KEY_new_by_curve_name_ex(OSSL_LIB_CTX *ctx, const char *propq, int nid)` —
/// `crypto/ec/ec_key.c:45-62`.
///
/// The group is built first and the method's `set_group` decides the answer; a failure on either
/// path releases the half-built key, so the caller owns nothing on failure.
///
/// # Safety
///
/// `ctx` is NULL or a live library context; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_new_by_curve_name_ex(
    ctx: *mut c_void,
    propq: *const c_char,
    nid: c_int,
) -> *mut EcKey {
    unsafe {
        // SAFETY: this function's own contract.
        let ret = EC_KEY_new_ex(ctx, propq);
        if ret.is_null() {
            return ptr::null_mut();
        }
        (*ret).group = EC_GROUP_new_by_curve_name_ex(ctx, propq, nid);
        if (*ret).group.is_null() {
            // SAFETY: `ret` is this call's own object.
            EC_KEY_free(ret);
            return ptr::null_mut();
        }
        if let Some(set_group) = (*ret).meth.as_ref().and_then(|m| m.set_group) {
            // SAFETY: the table's own callback, handed this object and its group.
            if set_group(ret, (*ret).group) == 0 {
                EC_KEY_free(ret);
                return ptr::null_mut();
            }
        }
        ret
    }
}

/// `EC_KEY *EC_KEY_new_by_curve_name(int nid)` — `crypto/ec/ec_key.c:65-68`, inside
/// `#ifndef FIPS_MODULE`, compiled here.
///
/// # Safety
///
/// None observable to the caller: `nid` is a value and the two NULLs are the authority's own.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_new_by_curve_name(nid: c_int) -> *mut EcKey {
    // SAFETY: the two NULLs are the authority's own.
    unsafe { EC_KEY_new_by_curve_name_ex(ptr::null_mut(), ptr::null(), nid) }
}

/// `void EC_KEY_free(EC_KEY *r)` — `crypto/ec/ec_key.c:71-104`.
///
/// NULL is a no-op. The release order is the contract, and it is transcribed statement for
/// statement:
///
/// 1. the count is decremented and a positive remainder returns **without** touching anything;
/// 2. the key method's `finish` (the object is still whole, so a table may read it);
/// 3. the engine release, which has no call on this crate's reachable states (see the module
///    documentation);
/// 4. the group method's `keyfinish`, which is why it is read through `r->group` rather than
///    `r->meth`;
/// 5. `CRYPTO_free_ex_data`, then `CRYPTO_FREE_REF` (a no-op on this profile), then the group and
///    the public point, the private scalar through `BN_clear_free`, the property query and finally
///    the object.
///
/// `REF_PRINT_COUNT("EC_KEY", i, r)` between (1) and (2) and `REF_ASSERT_ISNT(i < 0)` are empty
/// under this profile's `NDEBUG`.
///
/// # Safety
///
/// `r` is NULL or a live object, and must not be used again after this call unless a reference
/// remains.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_free(r: *mut EcKey) {
    if r.is_null() {
        return;
    }

    // `CRYPTO_DOWN_REF(&r->references, &i)`: a release fetch-sub, then the header's conditional
    // acquire fence when the count reaches zero.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if i == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    if i > 0 {
        return;
    }
    // `REF_ASSERT_ISNT(i < 0)` is empty under `NDEBUG`.

    // The authority's `if (r->meth != NULL && r->meth->finish != NULL) r->meth->finish(r)`.
    // SAFETY: `r` is live and this is the last reference.
    if let Some(finish) = unsafe { (*r).meth.as_ref() }.and_then(|m| m.finish) {
        // SAFETY: `finish` is that table's own destructor for this object.
        unsafe { finish(r) };
    }

    // The authority's `ENGINE_finish(r->engine)` is omitted: `r->engine` is NULL on every state
    // this crate can reach, and `ENGINE_finish(NULL)` returns 1 without touching anything. See the
    // module documentation.

    // SAFETY: `r` is live and this is the last reference.
    unsafe {
        if !(*r).group.is_null() {
            if let Some(keyfinish) = (*(*r).group).meth.as_ref().and_then(|m| m.keyfinish) {
                // SAFETY: `keyfinish` is the group table's own destructor for this key.
                keyfinish(r);
            }
        }
    }

    // SAFETY: `r` is live and `ex_data` is a field of it.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_EC_KEY,
            r.cast(),
            ptr::addr_of_mut!((*r).ex_data),
        )
    };
    // `CRYPTO_FREE_REF(&r->references)` is empty on this profile's arm of the header.

    // SAFETY: each field is NULL or the object's own; this is the last reference.
    unsafe {
        EC_GROUP_free((*r).group);
        EC_POINT_free((*r).pub_key);
        BN_clear_free((*r).priv_key);
        // `OPENSSL_free(r->propq)`, line 101.
        CRYPTO_free((*r).propq.cast(), FILE, 101);
        // `OPENSSL_clear_free((void *)r, sizeof(EC_KEY))`, line 103.
        CRYPTO_clear_free(r.cast(), core::mem::size_of::<EcKey>(), FILE, 103);
    }
}

/// `EC_KEY *EC_KEY_copy(EC_KEY *dest, const EC_KEY *src)` — `crypto/ec/ec_key.c:106-185`.
///
/// When the two objects use different methods the destination's old method is finished, its group
/// method's `keyfinish` runs, and the engine block clears the reference. The group is copied
/// through [`ossl_ec_group_new_ex`] and [`EC_GROUP_copy`]; the public point and private scalar are
/// copied when the source has them, and the private branch reaches the group method's `keycopy`.
/// The rest — encoding flags, conversion form, version, key flags and the ex-data — is copied
/// field for field, and the method is stored only when it differs, with the source method's
/// `copy` deciding the final answer.
///
/// The two `#if !defined(OPENSSL_NO_ENGINE)` blocks are reduced to the clear (see the module
/// documentation): `dest->engine` is NULL either way.
///
/// # Safety
///
/// `dest` is a live object and `src` is a live object distinct from it, or either is NULL.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_copy(dest: *mut EcKey, src: *const EcKey) -> *mut EcKey {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if dest.is_null() || src.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:109`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_109);
            return ptr::null_mut();
        }
        if (*src).meth != (*dest).meth {
            if let Some(finish) = (*dest).meth.as_ref().and_then(|m| m.finish) {
                // SAFETY: `dest` is live and the table's `finish` is its own destructor for it.
                finish(dest);
            }
            if !(*dest).group.is_null() {
                if let Some(keyfinish) = (*(*dest).group).meth.as_ref().and_then(|m| m.keyfinish) {
                    // SAFETY: `dest` is live; `keyfinish` is the group table's own.
                    keyfinish(dest);
                }
            }
            // The `#if !defined(OPENSSL_NO_ENGINE)` arm's three statements reduce to the clear:
            // `ENGINE_finish(dest->engine)` with a NULL engine returns 1.
            (*dest).engine = ptr::null_mut();
        }
        (*dest).libctx = (*src).libctx;
        /* copy the parameters */
        if !(*src).group.is_null() {
            /* clear the old group */
            EC_GROUP_free((*dest).group);
            (*dest).group = ossl_ec_group_new_ex((*src).libctx, (*src).propq, (*(*src).group).meth);
            if (*dest).group.is_null() {
                return ptr::null_mut();
            }
            if EC_GROUP_copy((*dest).group, (*src).group) == 0 {
                return ptr::null_mut();
            }

            /* copy the public key */
            if !(*src).pub_key.is_null() {
                EC_POINT_free((*dest).pub_key);
                (*dest).pub_key = EC_POINT_new((*src).group);
                if (*dest).pub_key.is_null() {
                    return ptr::null_mut();
                }
                if EC_POINT_copy((*dest).pub_key, (*src).pub_key) == 0 {
                    return ptr::null_mut();
                }
            }
            /* copy the private key */
            if !(*src).priv_key.is_null() {
                if (*dest).priv_key.is_null() {
                    (*dest).priv_key = BN_new();
                    if (*dest).priv_key.is_null() {
                        return ptr::null_mut();
                    }
                }
                if BN_copy((*dest).priv_key, (*src).priv_key).is_null() {
                    return ptr::null_mut();
                }
                if let Some(keycopy) = (*(*src).group).meth.as_ref().and_then(|m| m.keycopy) {
                    // SAFETY: `keycopy` is the group table's own, handed the two live objects.
                    if keycopy(dest, src) == 0 {
                        return ptr::null_mut();
                    }
                }
            }
        }

        /* copy the rest */
        (*dest).enc_flag = (*src).enc_flag;
        (*dest).conv_form = (*src).conv_form;
        (*dest).version = (*src).version;
        (*dest).flags = (*src).flags;
        // `#ifndef FIPS_MODULE`, compiled here.
        if CRYPTO_dup_ex_data(
            CRYPTO_EX_INDEX_EC_KEY,
            ptr::addr_of_mut!((*dest).ex_data),
            ptr::addr_of!((*src).ex_data),
        ) == 0
        {
            return ptr::null_mut();
        }

        if (*src).meth != (*dest).meth {
            // The `#if !defined(OPENSSL_NO_ENGINE)` arm reduces: `src->engine` is NULL, so
            // `ENGINE_init` is not called and `dest->engine = src->engine` stores NULL.
            (*dest).engine = (*src).engine;
            (*dest).meth = (*src).meth;
        }

        if let Some(copy) = (*src).meth.as_ref().and_then(|m| m.copy) {
            // SAFETY: `copy` is the table's own, handed the two live objects.
            if copy(dest, src) == 0 {
                return ptr::null_mut();
            }
        }

        (*dest).dirty_cnt += 1;

        dest
    }
}

/// `EC_KEY *EC_KEY_dup(const EC_KEY *ec_key)` — `crypto/ec/ec_key.c:187-190`.
///
/// A one-line wrapper over `ossl_ec_key_dup(ec_key, OSSL_KEYMGMT_SELECT_ALL)`. That callee is
/// `crypto/ec/ec_backend.c`'s (`:594`), which is the plan's step 9 and not this session's, so the
/// call is a reference named by its crate path and module rather than a transcription.
///
/// # Safety
///
/// `ec_key` is a live object.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_dup(ec_key: *const EcKey) -> *mut EcKey {
    // SAFETY: this function's own contract; `ossl_ec_key_dup` is `ec_backend.c`'s.
    unsafe { ossl_ec_key_dup(ec_key, OSSL_KEYMGMT_SELECT_ALL) }
}

/// `int EC_KEY_up_ref(EC_KEY *r)` — `crypto/ec/ec_key.c:192-202`.
///
/// Answers **1** for any object a caller can legitimately hold; the `i > 1` test is the
/// authority's own, and `CRYPTO_UP_REF` cannot fail, so the only 0 is an object whose count has
/// already reached zero. `REF_ASSERT_ISNT(i < 2)` is empty here.
///
/// # Safety
///
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_up_ref(r: *mut EcKey) -> c_int {
    // `CRYPTO_UP_REF` is a *relaxed* fetch-add.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_add(1, Ordering::Relaxed) }.wrapping_add(1);
    if i > 1 {
        1
    } else {
        0
    }
}

/// `ENGINE *EC_KEY_get0_engine(const EC_KEY *eckey)` — `crypto/ec/ec_key.c:204-207`.
///
/// # Safety
///
/// `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get0_engine(eckey: *const EcKey) -> *mut Engine {
    // SAFETY: the caller's contract.
    unsafe { (*eckey).engine }
}

/// `int EC_KEY_generate_key(EC_KEY *eckey)` — `crypto/ec/ec_key.c:209-226`.
///
/// The key method's `keygen` decides the answer, and a success bumps the change counter. A key
/// whose table has no `keygen` raises `EC_R_OPERATION_NOT_SUPPORTED` rather than answering
/// silently. This is the export that retires `forensics/phase8-obligations.json`'s `deferred` row.
///
/// # Safety
///
/// `eckey` is NULL or a live key with a group.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_generate_key(eckey: *mut EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if eckey.is_null() || (*eckey).group.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:212`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_212);
            return 0;
        }
        if let Some(keygen) = (*eckey).meth.as_ref().and_then(|m| m.keygen) {
            // SAFETY: `keygen` is the table's own, handed this key.
            let ret = keygen(eckey);
            if ret == 1 {
                (*eckey).dirty_cnt += 1;
            }
            return ret;
        }
        // SAFETY: a compile-time-constant site (`ec_key.c:224`, EC_R_OPERATION_NOT_SUPPORTED).
        raise_site(&err_sites::EC_KEY_224);
        0
    }
}

/// `int ossl_ec_key_gen(EC_KEY *eckey)` — `crypto/ec/ec_key.c:228-237`. Internal.
///
/// The default key method's `keygen`; it reaches the **group** method's `keygen`, which is
/// `ossl_ec_key_simple_generate_key` for every landed table.
///
/// # Safety
///
/// `eckey` is a live key with a group whose method has a `keygen`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_gen(eckey: *mut EcKey) -> c_int {
    unsafe {
        // SAFETY: the caller's contract.
        let Some(keygen) = (*(*eckey).group).meth.as_ref().and_then(|m| m.keygen) else {
            // Every landed table sets `keygen`; a NULL column is the authority's crash and
            // answers failure here.
            return 0;
        };
        let ret = keygen(eckey);
        if ret == 1 {
            (*eckey).dirty_cnt += 1;
        }
        ret
    }
}

/// `static int ec_generate_key(EC_KEY *eckey, int pairwise_test)` —
/// `crypto/ec/ec_key.c:251-350`. The unit's static, transcribed with [`ossl_ec_key_simple_generate_key`].
///
/// "Key Pair Generation by Testing Candidates" (SP800-56AR3 5.6.1.2.2): the private scalar is
/// drawn from `[1, n-1]` (from `[1, n-1)` for an SM2 group), the public point is `priv_key * G`,
/// and only then are the two stored on the object and the change counter bumped. The `#ifdef
/// FIPS_MODULE` forcing of `pairwise_test` is not this profile's; the `#ifndef FIPS_MODULE` body
/// is.
///
/// The authority's `err:` label is transcribed whole, including its "clear the private key and set
/// the public point to infinity" failure fix-up.
///
/// # Safety
///
/// `eckey` is a live key with a group. `pairwise_test` is 0 or 1.
unsafe fn ec_generate_key(eckey: *mut EcKey, pairwise_test: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok: c_int = 0;
        let mut priv_key: *mut BigNum = ptr::null_mut();
        let mut order: *mut BigNum = ptr::null_mut();
        let mut pub_key: *mut EcPoint = ptr::null_mut();
        let group = (*eckey).group;
        let ctx = BN_CTX_secure_new_ex((*eckey).libctx);
        let sm2 = c_int::from(EC_KEY_get_flags(eckey) & EC_FLAG_SM2_RANGE != 0);

        if ctx.is_null() {
            return err_ec_generate_key(
                &mut priv_key,
                &mut pub_key,
                &mut order,
                ctx,
                group,
                eckey,
                ok,
            );
        }

        if (*eckey).priv_key.is_null() {
            priv_key = BN_secure_new();
            if priv_key.is_null() {
                return err_ec_generate_key(
                    &mut priv_key,
                    &mut pub_key,
                    &mut order,
                    ctx,
                    group,
                    eckey,
                    ok,
                );
            }
        } else {
            priv_key = (*eckey).priv_key;
        }

        /*
         * Steps (1-2): Check domain parameters and security strength. These steps must be done by
         * the user. This would need to be stated in the security policy.
         */
        let tmp = EC_GROUP_get0_order(group);
        if tmp.is_null() {
            return err_ec_generate_key(
                &mut priv_key,
                &mut pub_key,
                &mut order,
                ctx,
                group,
                eckey,
                ok,
            );
        }

        /*
         * Steps (3-7): priv_key = DRBG_RAND(order_n_bits) (range [1, n-1]).
         */
        /* range of SM2 private key is [1, n-1) */
        if sm2 != 0 {
            order = BN_new();
            if order.is_null() || BN_sub(order, tmp, BN_value_one()) == 0 {
                return err_ec_generate_key(
                    &mut priv_key,
                    &mut pub_key,
                    &mut order,
                    ctx,
                    group,
                    eckey,
                    ok,
                );
            }
        } else {
            order = BN_dup(tmp);
            if order.is_null() {
                return err_ec_generate_key(
                    &mut priv_key,
                    &mut pub_key,
                    &mut order,
                    ctx,
                    group,
                    eckey,
                    ok,
                );
            }
        }

        loop {
            if BN_priv_rand_range_ex(priv_key, order, 0, ctx) == 0 {
                return err_ec_generate_key(
                    &mut priv_key,
                    &mut pub_key,
                    &mut order,
                    ctx,
                    group,
                    eckey,
                    ok,
                );
            }
            if BN_is_zero(priv_key) == 0 {
                break;
            }
        }

        if (*eckey).pub_key.is_null() {
            pub_key = EC_POINT_new(group);
            if pub_key.is_null() {
                return err_ec_generate_key(
                    &mut priv_key,
                    &mut pub_key,
                    &mut order,
                    ctx,
                    group,
                    eckey,
                    ok,
                );
            }
        } else {
            pub_key = (*eckey).pub_key;
        }

        /* Step (8) : pub_key = priv_key * G (where G is a point on the curve) */
        if EC_POINT_mul(group, pub_key, priv_key, ptr::null(), ptr::null(), ctx) == 0 {
            return err_ec_generate_key(
                &mut priv_key,
                &mut pub_key,
                &mut order,
                ctx,
                group,
                eckey,
                ok,
            );
        }

        (*eckey).priv_key = priv_key;
        (*eckey).pub_key = pub_key;
        priv_key = ptr::null_mut();
        pub_key = ptr::null_mut();

        (*eckey).dirty_cnt += 1;

        // `#ifdef FIPS_MODULE pairwise_test = 1;` is not this profile's.

        ok = 1;
        if pairwise_test != 0 {
            let mut cb: Option<OsslCallback> = None;
            let mut cbarg: *mut c_void = ptr::null_mut();

            OSSL_SELF_TEST_get_callback((*eckey).libctx, &raw mut cb, &raw mut cbarg);
            ok = ecdsa_keygen_pairwise_test(eckey, cb, cbarg);
        }
        err_ec_generate_key(
            &mut priv_key,
            &mut pub_key,
            &mut order,
            ctx,
            group,
            eckey,
            ok,
        )
    }
}

/// The authority's `err:` label of [`ec_generate_key`] (`ec_key.c:337-349`).
///
/// Step (9): a failure clears the private key and sets the public point to infinity, and the four
/// locals are released whatever `ok` is. Written as its own function because the Rust `?`-free
/// transcription has eight early exits that all reach it.
///
/// # Safety
///
/// The pointers are those [`ec_generate_key`] holds; `group` is the key's group and `eckey` the key.
#[allow(clippy::too_many_arguments)] // the authority's own `err:` label (`ec_key.c:337-349`): it reads the seven locals the label below it declared plus `ok`, and keeping the label literal at that arity is what lets a reader line this error path up with the authority's line by line
unsafe fn err_ec_generate_key(
    priv_key: &mut *mut BigNum,
    pub_key: &mut *mut EcPoint,
    order: &mut *mut BigNum,
    ctx: *mut BnCtx,
    group: *mut EcGroup,
    eckey: *mut EcKey,
    ok: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* Step (9): If there is an error return an invalid keypair. */
        if ok == 0 {
            BN_clear((*eckey).priv_key);
            if !(*eckey).pub_key.is_null() {
                EC_POINT_set_to_infinity(group, (*eckey).pub_key);
            }
        }

        EC_POINT_free(*pub_key);
        BN_clear_free(*priv_key);
        BN_CTX_free(ctx);
        BN_free(*order);
        ok
    }
}

/// `int ossl_ec_key_simple_generate_key(EC_KEY *eckey)` — `crypto/ec/ec_key.c:389-392`. Internal.
///
/// The `keygen` column every landed group table names; [`ec_generate_key`] with no pairwise test.
///
/// # Safety
///
/// `eckey` is a live key with a group.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_simple_generate_key(eckey: *mut EcKey) -> c_int {
    // SAFETY: this function's own contract.
    unsafe { ec_generate_key(eckey, 0) }
}

/// `int ossl_ec_key_simple_generate_public_key(EC_KEY *eckey)` — `crypto/ec/ec_key.c:394-414`.
/// Internal.
///
/// SP800-56AR3 5.6.1.2.2 step (8) on its own: `pub_key = priv_key * G`, with its own `BN_CTX` so a
/// caller need not supply one. A success bumps the change counter.
///
/// # Safety
///
/// `eckey` is a live key with a group, a private scalar and a public point.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_simple_generate_public_key(eckey: *mut EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ctx = BN_CTX_new_ex((*eckey).libctx);
        if ctx.is_null() {
            return 0;
        }

        let ret = EC_POINT_mul(
            (*eckey).group,
            (*eckey).pub_key,
            (*eckey).priv_key,
            ptr::null(),
            ptr::null(),
            ctx,
        );

        BN_CTX_free(ctx);
        if ret == 1 {
            (*eckey).dirty_cnt += 1;
        }
        ret
    }
}

/// `int EC_KEY_check_key(const EC_KEY *eckey)` — `crypto/ec/ec_key.c:416-429`.
///
/// The group method's `keycheck` decides the answer; a table without one raises
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` rather than answering.
///
/// # Safety
///
/// `eckey` is NULL or a live key with a group and a public point.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_check_key(eckey: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if eckey.is_null() || (*eckey).group.is_null() || (*eckey).pub_key.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:419`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_419);
            return 0;
        }

        if let Some(keycheck) = (*(*eckey).group).meth.as_ref().and_then(|m| m.keycheck) {
            // SAFETY: `keycheck` is the group table's own, handed this key.
            return keycheck(eckey);
        }
        // SAFETY: a compile-time-constant site (`ec_key.c:424`,
        // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
        raise_site(&err_sites::EC_KEY_424);
        0
    }
}

/// `static int ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key)` —
/// `crypto/ec/ec_key.c:440-471`. The unit's static, transcribed with [`ossl_ec_key_public_check_quick`].
///
/// SP800-56A R3 5.6.2.3.3 (Part 2): for a prime field both affine coordinates are in `[0, p - 1]`,
/// and for a characteristic-two field both are at most `m` bits wide. The context's two temporaries
/// are fetched and released through its own mark, exactly as the authority nests `BN_CTX_start`/
/// `BN_CTX_end`.
///
/// # Safety
///
/// `ctx` is a live `BN_CTX`; `key` is a live key with a group and a public point.
unsafe fn ec_key_public_range_check(ctx: *mut BnCtx, key: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret: c_int = 0;

        BN_CTX_start(ctx);
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        if y.is_null() {
            BN_CTX_end(ctx);
            return ret;
        }

        if EC_POINT_get_affine_coordinates((*key).group, (*key).pub_key, x, y, ctx) == 0 {
            BN_CTX_end(ctx);
            return ret;
        }

        if EC_GROUP_get_field_type((*key).group) == NID_X9_62_prime_field {
            if BN_is_negative(x) != 0
                || BN_cmp(x, (*(*key).group).field) >= 0
                || BN_is_negative(y) != 0
                || BN_cmp(y, (*(*key).group).field) >= 0
            {
                BN_CTX_end(ctx);
                return ret;
            }
        } else {
            let m = EC_GROUP_get_degree((*key).group);
            if BN_num_bits(x) > m || BN_num_bits(y) > m {
                BN_CTX_end(ctx);
                return ret;
            }
        }
        ret = 1;
        BN_CTX_end(ctx);
        ret
    }
}

/// `int ossl_ec_key_public_check_quick(const EC_KEY *eckey, BN_CTX *ctx)` —
/// `crypto/ec/ec_key.c:477-502`. Internal.
///
/// SP800-56A R3 5.6.2.3.4: the point is not at infinity, its coordinates are in range, and it is on
/// the curve — three refusals, each raising its own reason.
///
/// # Safety
///
/// `eckey` is NULL or a live key with a group and a public point; `ctx` is a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_public_check_quick(
    eckey: *const EcKey,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if eckey.is_null() || (*eckey).group.is_null() || (*eckey).pub_key.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:480`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_480);
            return 0;
        }

        /* 5.6.2.3.3 (Step 1): Q != infinity */
        if EC_POINT_is_at_infinity((*eckey).group, (*eckey).pub_key) != 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:486`, EC_R_POINT_AT_INFINITY).
            raise_site(&err_sites::EC_KEY_486);
            return 0;
        }

        /* 5.6.2.3.3 (Step 2) Test if the public key is in range */
        if ec_key_public_range_check(ctx, eckey) == 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:492`,
            // EC_R_COORDINATES_OUT_OF_RANGE).
            raise_site(&err_sites::EC_KEY_492);
            return 0;
        }

        /* 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve */
        if EC_POINT_is_on_curve((*eckey).group, (*eckey).pub_key, ctx) <= 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:498`,
            // EC_R_POINT_IS_NOT_ON_CURVE).
            raise_site(&err_sites::EC_KEY_498);
            return 0;
        }
        1
    }
}

/// `int ossl_ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx)` —
/// `crypto/ec/ec_key.c:508-545`. Internal.
///
/// SP800-56A R3 5.6.2.3.3, full: the quick check, then — unless the cofactor is 1, which skips an
/// expensive multiplication — `pub_key * order` must be the point at infinity.
///
/// # Safety
///
/// `eckey` is a live key with a group and a public point; `ctx` is a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_public_check(eckey: *const EcKey, ctx: *mut BnCtx) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret: c_int = 0;
        let cofactor = EC_GROUP_get0_cofactor((*eckey).group);

        if ossl_ec_key_public_check_quick(eckey, ctx) == 0 {
            return 0;
        }

        if !cofactor.is_null() && BN_is_one(cofactor) != 0 {
            /* Skip the unnecessary expensive computation for curves with cofactor of 1. */
            return 1;
        }

        let point: *mut EcPoint = EC_POINT_new((*eckey).group);
        if point.is_null() {
            return 0;
        }

        let order = (*(*eckey).group).order;
        if BN_is_zero(order) != 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:529`, EC_R_INVALID_GROUP_ORDER).
            raise_site(&err_sites::EC_KEY_529);
            EC_POINT_free(point);
            return ret;
        }
        /* 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. */
        if EC_POINT_mul(
            (*eckey).group,
            point,
            ptr::null(),
            (*eckey).pub_key,
            order,
            ctx,
        ) == 0
        {
            // SAFETY: a compile-time-constant site (`ec_key.c:534`, ERR_R_EC_LIB).
            raise_site(&err_sites::EC_KEY_534);
            EC_POINT_free(point);
            return ret;
        }
        if EC_POINT_is_at_infinity((*eckey).group, point) == 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:538`, EC_R_WRONG_ORDER).
            raise_site(&err_sites::EC_KEY_538);
            EC_POINT_free(point);
            return ret;
        }
        ret = 1;
        EC_POINT_free(point);
        ret
    }
}

/// `int ossl_ec_key_private_check(const EC_KEY *eckey)` — `crypto/ec/ec_key.c:552-564`. Internal.
///
/// SP800-56A R3 5.6.2.1.2: the private scalar is in `[1, order - 1]`.
///
/// # Safety
///
/// `eckey` is NULL or a live key with a group and a private scalar.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_private_check(eckey: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if eckey.is_null() || (*eckey).group.is_null() || (*eckey).priv_key.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:555`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_555);
            return 0;
        }
        if BN_cmp((*eckey).priv_key, BN_value_one()) < 0
            || BN_cmp((*eckey).priv_key, (*(*eckey).group).order) >= 0
        {
            // SAFETY: a compile-time-constant site (`ec_key.c:560`, EC_R_INVALID_PRIVATE_KEY).
            raise_site(&err_sites::EC_KEY_560);
            return 0;
        }
        1
    }
}

/// `int ossl_ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx)` —
/// `crypto/ec/ec_key.c:571-600`. Internal.
///
/// SP800-56A R3 5.6.2.1.4 (b): `generator * priv_key` must equal the stored public point.
///
/// # Safety
///
/// `eckey` is NULL or a live key with a group, a public point and a private scalar; `ctx` is a live
/// `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_pairwise_check(eckey: *const EcKey, ctx: *mut BnCtx) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret: c_int = 0;

        if eckey.is_null()
            || (*eckey).group.is_null()
            || (*eckey).pub_key.is_null()
            || (*eckey).priv_key.is_null()
        {
            // SAFETY: a compile-time-constant site (`ec_key.c:580`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_580);
            return 0;
        }

        let point: *mut EcPoint = EC_POINT_new((*eckey).group);
        if point.is_null() {
            EC_POINT_free(point);
            return ret;
        }

        if EC_POINT_mul(
            (*eckey).group,
            point,
            (*eckey).priv_key,
            ptr::null(),
            ptr::null(),
            ctx,
        ) == 0
        {
            // SAFETY: a compile-time-constant site (`ec_key.c:589`, ERR_R_EC_LIB).
            raise_site(&err_sites::EC_KEY_589);
            EC_POINT_free(point);
            return ret;
        }
        if EC_POINT_cmp((*eckey).group, point, (*eckey).pub_key, ctx) != 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:593`, EC_R_INVALID_PRIVATE_KEY).
            raise_site(&err_sites::EC_KEY_593);
            EC_POINT_free(point);
            return ret;
        }
        ret = 1;
        EC_POINT_free(point);
        ret
    }
}

/// `int ossl_ec_key_simple_check_key(const EC_KEY *eckey)` — `crypto/ec/ec_key.c:612-636`.
/// Internal.
///
/// The `keycheck` column every landed group table names: the full public check followed, when the
/// key has a private scalar, by the private and pairwise checks.
///
/// # Safety
///
/// `eckey` is NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_simple_check_key(eckey: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok: c_int = 0;

        if eckey.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:618`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_618);
            return 0;
        }
        let ctx = BN_CTX_new_ex((*eckey).libctx);
        if ctx.is_null() {
            return 0;
        }

        if ossl_ec_key_public_check(eckey, ctx) == 0 {
            BN_CTX_free(ctx);
            return ok;
        }

        if !(*eckey).priv_key.is_null()
            && (ossl_ec_key_private_check(eckey) == 0
                || ossl_ec_key_pairwise_check(eckey, ctx) == 0)
        {
            BN_CTX_free(ctx);
            return ok;
        }
        ok = 1;
        BN_CTX_free(ctx);
        ok
    }
}

/// `int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y)` —
/// `crypto/ec/ec_key.c:638-693`.
///
/// The point is built from the two coordinates, read back and compared with the originals — the
/// range check itself is deferred to [`EC_KEY_check_key`] — and only then stored through
/// [`EC_KEY_set_public_key`], whose change-counter bump is the authority's own comment.
///
/// # Safety
///
/// `key` is NULL or a live key with a group; `x` and `y` are live `BIGNUM`s.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_public_key_affine_coordinates(
    key: *mut EcKey,
    x: *mut BigNum,
    y: *mut BigNum,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ok: c_int = 0;

        if key.is_null() || (*key).group.is_null() || x.is_null() || y.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:647`, ERR_R_PASSED_NULL_PARAMETER).
            raise_site(&err_sites::EC_KEY_647);
            return 0;
        }
        let ctx = BN_CTX_new_ex((*key).libctx);
        if ctx.is_null() {
            return 0;
        }

        BN_CTX_start(ctx);
        let point: *mut EcPoint = EC_POINT_new((*key).group);

        if point.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        let tx = BN_CTX_get(ctx);
        let ty = BN_CTX_get(ctx);
        if ty.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        if EC_POINT_set_affine_coordinates((*key).group, point, x, y, ctx) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }
        if EC_POINT_get_affine_coordinates((*key).group, point, tx, ty, ctx) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        /*
         * Check if retrieved coordinates match originals. The range check is done inside
         * EC_KEY_check_key().
         */
        if BN_cmp(x, tx) != 0 || BN_cmp(y, ty) != 0 {
            // SAFETY: a compile-time-constant site (`ec_key.c:675`,
            // EC_R_COORDINATES_OUT_OF_RANGE).
            raise_site(&err_sites::EC_KEY_675);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        /* EC_KEY_set_public_key updates dirty_cnt */
        if EC_KEY_set_public_key(key, point) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        if EC_KEY_check_key(key) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            EC_POINT_free(point);
            return ok;
        }

        ok = 1;

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(point);
        ok
    }
}

/// `OSSL_LIB_CTX *ossl_ec_key_get_libctx(const EC_KEY *key)` — `crypto/ec/ec_key.c:695-698`.
/// Internal.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_get_libctx(key: *const EcKey) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { (*key).libctx }
}

/// `const char *ossl_ec_key_get0_propq(const EC_KEY *key)` — `crypto/ec/ec_key.c:700-703`.
/// Internal.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_get0_propq(key: *const EcKey) -> *const c_char {
    // SAFETY: the caller's contract.
    unsafe { (*key).propq }
}

/// `void ossl_ec_key_set0_libctx(EC_KEY *key, OSSL_LIB_CTX *libctx)` —
/// `crypto/ec/ec_key.c:705-709`. Internal.
///
/// The authority's own comment asks whether the context should be propagated to the group; it is
/// not, and neither is it here.
///
/// # Safety
///
/// `key` is a live key; `libctx` is NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_set0_libctx(key: *mut EcKey, libctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe { (*key).libctx = libctx };
}

/// `const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)` — `crypto/ec/ec_key.c:711-714`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get0_group(key: *const EcKey) -> *const EcGroup {
    // SAFETY: the caller's contract.
    unsafe { (*key).group }
}

/// `int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)` — `crypto/ec/ec_key.c:716-727`.
///
/// The method's `set_group` runs first, the old group is freed, the new one is **duplicated**, and
/// an SM2 group sets [`EC_FLAG_SM2_RANGE`]. The engine block between the free and the duplication
/// is reduced (see the module documentation).
///
/// # Safety
///
/// `key` is a live key; `group` is a live group.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_group(key: *mut EcKey, group: *const EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(set_group) = (*key).meth.as_ref().and_then(|m| m.set_group) {
            // SAFETY: `set_group` is the table's own, handed this key and the new group.
            if set_group(key, group) == 0 {
                return 0;
            }
        }
        EC_GROUP_free((*key).group);
        (*key).group = EC_GROUP_dup(group);
        if !(*key).group.is_null() && EC_GROUP_get_curve_name((*key).group) == NID_sm2 {
            EC_KEY_set_flags(key, EC_FLAG_SM2_RANGE);
        }

        (*key).dirty_cnt += 1;
        c_int::from(!(*key).group.is_null())
    }
}

/// `const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key)` — `crypto/ec/ec_key.c:729-732`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get0_private_key(key: *const EcKey) -> *const BigNum {
    // SAFETY: the caller's contract.
    unsafe { (*key).priv_key }
}

/// `int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key)` —
/// `crypto/ec/ec_key.c:734-827`.
///
/// Both method tables' `set_private` columns run before anything is stored, and a NULL scalar
/// **clears and answers 0** — the authority's intentional legacy-compatibility arm, quoted at
/// `:766-770`. Otherwise the scalar is duplicated, `BN_FLG_CONSTTIME` is set on the copy, and the
/// buffer is pre-grown to `bn_get_top(order) + 2` words so that no later operation reallocates and
/// leaks the secret's length. The long comment at `:772-809` is the authority's and is quoted in
/// the doc of [`ossl_ec_key_simple_generate_key`]'s neighbourhood rather than repeated.
///
/// # Safety
///
/// `key` is a live key with a group whose order is set; `priv_key` is NULL or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_private_key(key: *mut EcKey, priv_key: *const BigNum) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*key).group.is_null() || (*(*key).group).meth.is_null() {
            return 0;
        }

        let order = EC_GROUP_get0_order((*key).group);
        if order.is_null() || BN_is_zero(order) != 0 {
            return 0; /* This should never happen */
        }

        if let Some(set_private) = (*(*key).group).meth.as_ref().and_then(|m| m.set_private) {
            // SAFETY: `set_private` is the group table's own.
            if set_private(key, priv_key) == 0 {
                return 0;
            }
        }
        if let Some(set_private) = (*key).meth.as_ref().and_then(|m| m.set_private) {
            // SAFETY: `set_private` is the key table's own.
            if set_private(key, priv_key) == 0 {
                return 0;
            }
        }

        /*
         * Return `0` to comply with legacy behavior for this function, see
         * https://github.com/openssl/openssl/issues/18744#issuecomment-1195175696
         */
        if priv_key.is_null() {
            BN_clear_free((*key).priv_key);
            (*key).priv_key = ptr::null_mut();
            return 0; /* intentional for legacy compatibility */
        }

        let tmp_key = BN_dup(priv_key);
        if tmp_key.is_null() {
            return 0;
        }

        BN_set_flags(tmp_key, BN_FLG_CONSTTIME);

        let fixed_top = bn_get_top(order) + 2;
        if bn_wexpand(tmp_key, fixed_top).is_null() {
            BN_clear_free(tmp_key);
            return 0;
        }

        BN_clear_free((*key).priv_key);
        (*key).priv_key = tmp_key;
        (*key).dirty_cnt += 1;

        1
    }
}

/// `const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)` — `crypto/ec/ec_key.c:829-832`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get0_public_key(key: *const EcKey) -> *const EcPoint {
    // SAFETY: the caller's contract.
    unsafe { (*key).pub_key }
}

/// `int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub_key)` —
/// `crypto/ec/ec_key.c:834-843`.
///
/// The key table's `set_public` runs first, the old point is freed, the new one is **duplicated**
/// against the key's own group, and the change counter is bumped whatever the duplication answers.
///
/// # Safety
///
/// `key` is a live key; `pub_key` is a live point compatible with the key's group.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_public_key(key: *mut EcKey, pub_key: *const EcPoint) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if let Some(set_public) = (*key).meth.as_ref().and_then(|m| m.set_public) {
            // SAFETY: `set_public` is the table's own, handed this key and the new point.
            if set_public(key, pub_key) == 0 {
                return 0;
            }
        }
        EC_POINT_free((*key).pub_key);
        (*key).pub_key = EC_POINT_dup(pub_key, (*key).group);
        (*key).dirty_cnt += 1;
        c_int::from(!(*key).pub_key.is_null())
    }
}

/// `unsigned int EC_KEY_get_enc_flags(const EC_KEY *key)` — `crypto/ec/ec_key.c:845-848`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get_enc_flags(key: *const EcKey) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe { (*key).enc_flag }
}

/// `void EC_KEY_set_enc_flags(EC_KEY *key, unsigned int flags)` — `crypto/ec/ec_key.c:850-853`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_enc_flags(key: *mut EcKey, flags: c_uint) {
    // SAFETY: the caller's contract.
    unsafe { (*key).enc_flag = flags };
}

/// `point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key)` —
/// `crypto/ec/ec_key.c:855-858`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get_conv_form(key: *const EcKey) -> crate::ec::PointConversionForm {
    // SAFETY: the caller's contract.
    unsafe { (*key).conv_form }
}

/// `void EC_KEY_set_conv_form(EC_KEY *key, point_conversion_form_t cform)` —
/// `crypto/ec/ec_key.c:860-865`.
///
/// The form is stored on the key and propagated to the group when there is one.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_conv_form(
    key: *mut EcKey,
    cform: crate::ec::PointConversionForm,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*key).conv_form = cform;
        if !(*key).group.is_null() {
            EC_GROUP_set_point_conversion_form((*key).group, cform);
        }
    }
}

/// `void EC_KEY_set_asn1_flag(EC_KEY *key, int flag)` — `crypto/ec/ec_key.c:867-871`.
///
/// **The flag is stored on the group, not the key**, and this is a no-op for a key with no group.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_asn1_flag(key: *mut EcKey, flag: c_int) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !(*key).group.is_null() {
            EC_GROUP_set_asn1_flag((*key).group, flag);
        }
    }
}

/// `int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx)` — `crypto/ec/ec_key.c:874-879`, inside
/// `#ifndef OPENSSL_NO_DEPRECATED_3_0`, compiled here.
///
/// # Safety
///
/// `key` is a live key; `ctx` is NULL or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_precompute_mult(key: *mut EcKey, ctx: *mut BnCtx) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*key).group.is_null() {
            return 0;
        }
        EC_GROUP_precompute_mult((*key).group, ctx)
    }
}

/// `int EC_KEY_get_flags(const EC_KEY *key)` — `crypto/ec/ec_key.c:882-885`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get_flags(key: *const EcKey) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*key).flags }
}

/// `void EC_KEY_set_flags(EC_KEY *key, int flags)` — `crypto/ec/ec_key.c:887-891`.
///
/// A **set** of the named bits, not a store, and a change-counter bump.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_flags(key: *mut EcKey, flags: c_int) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*key).flags |= flags;
        (*key).dirty_cnt += 1;
    }
}

/// `void EC_KEY_clear_flags(EC_KEY *key, int flags)` — `crypto/ec/ec_key.c:893-897`.
///
/// # Safety
///
/// `key` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_clear_flags(key: *mut EcKey, flags: c_int) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*key).flags &= !flags;
        (*key).dirty_cnt += 1;
    }
}

/// `int EC_KEY_decoded_from_explicit_params(const EC_KEY *key)` — `crypto/ec/ec_key.c:899-904`.
///
/// Answers **-1** for a key with no group, which is a three-state answer rather than a boolean.
///
/// # Safety
///
/// `key` is NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_decoded_from_explicit_params(key: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if key.is_null() || (*key).group.is_null() {
            return -1;
        }
        (*(*key).group).decoded_from_explicit_params
    }
}

/// `size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form, unsigned char **pbuf,
/// BN_CTX *ctx)` — `crypto/ec/ec_key.c:906-912`.
///
/// # Safety
///
/// `key` is NULL or a live key; `pbuf` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_key2buf(
    key: *const EcKey,
    form: crate::ec::PointConversionForm,
    pbuf: *mut *mut c_uchar,
    ctx: *mut BnCtx,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if key.is_null() || (*key).pub_key.is_null() || (*key).group.is_null() {
            return 0;
        }
        EC_POINT_point2buf((*key).group, (*key).pub_key, form, pbuf, ctx)
    }
}

/// `int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len, BN_CTX *ctx)` —
/// `crypto/ec/ec_key.c:914-936`.
///
/// The public point is built from the encoding and the conversion form is recovered from the first
/// octet — `buf[0] & ~0x01` — for every group that is not a custom curve.
///
/// # Safety
///
/// `key` is NULL or a live key; `buf` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_oct2key(
    key: *mut EcKey,
    buf: *const c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if key.is_null() || (*key).group.is_null() {
            return 0;
        }
        if (*key).pub_key.is_null() {
            (*key).pub_key = EC_POINT_new((*key).group);
        }
        if (*key).pub_key.is_null() {
            return 0;
        }
        if EC_POINT_oct2point((*key).group, (*key).pub_key, buf, len, ctx) == 0 {
            return 0;
        }
        (*key).dirty_cnt += 1;
        /*
         * Save the point conversion form. For non-custom curves the first octet of the buffer
         * (excluding the last significant bit) contains the point conversion form.
         * EC_POINT_oct2point() has already performed sanity checking of the buffer so we know it is
         * valid.
         */
        if (*(*key).group).meth.as_ref().map_or(0, |m| m.flags) & EC_FLAGS_CUSTOM_CURVE == 0 {
            (*key).conv_form = c_int::from(*buf & !0x01);
        }
        1
    }
}

/// `size_t EC_KEY_priv2oct(const EC_KEY *eckey, unsigned char *buf, size_t len)` —
/// `crypto/ec/ec_key.c:938-949`.
///
/// The group method's `priv2oct` decides the answer; a table without one raises
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` rather than answering.
///
/// # Safety
///
/// `eckey` is a live key with a group; `buf` is NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_priv2oct(
    eckey: *const EcKey,
    buf: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*eckey).group.is_null() || (*(*eckey).group).meth.is_null() {
            return 0;
        }
        if let Some(priv2oct) = (*(*eckey).group).meth.as_ref().and_then(|m| m.priv2oct) {
            // SAFETY: `priv2oct` is the group table's own.
            return priv2oct(eckey, buf, len);
        }
        // SAFETY: a compile-time-constant site (`ec_key.c:944`,
        // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
        raise_site(&err_sites::EC_KEY_944);
        0
    }
}

/// `size_t ossl_ec_key_simple_priv2oct(const EC_KEY *eckey, unsigned char *buf, size_t len)` —
/// `crypto/ec/ec_key.c:951-972`. Internal. The `priv2oct` column every landed table names.
///
/// The width is `(EC_GROUP_order_bits(group) + 7) / 8` and a NULL `buf` answers it without writing,
/// which is how [`EC_KEY_priv2buf`] sizes its allocation.
///
/// # Safety
///
/// `eckey` is a live key with a group; `buf` is NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_simple_priv2oct(
    eckey: *const EcKey,
    buf: *mut c_uchar,
    len: usize,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let buf_len = (EC_GROUP_order_bits((*eckey).group) + 7) / 8;
        if (*eckey).priv_key.is_null() {
            return 0;
        }
        if buf.is_null() {
            return buf_len as usize;
        } else if len < buf_len as usize {
            return 0;
        }

        /* Octetstring may need leading zeros if BN is to short */

        if BN_bn2binpad((*eckey).priv_key, buf, buf_len) == -1 {
            // SAFETY: a compile-time-constant site (`ec_key.c:967`, EC_R_BUFFER_TOO_SMALL).
            raise_site(&err_sites::EC_KEY_967);
            return 0;
        }

        buf_len as usize
    }
}

/// `int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len)` —
/// `crypto/ec/ec_key.c:974-988`.
///
/// # Safety
///
/// `eckey` is a live key with a group; `buf` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_oct2priv(
    eckey: *mut EcKey,
    buf: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*eckey).group.is_null() || (*(*eckey).group).meth.is_null() {
            return 0;
        }
        if let Some(oct2priv) = (*(*eckey).group).meth.as_ref().and_then(|m| m.oct2priv) {
            // SAFETY: `oct2priv` is the group table's own.
            let ret = oct2priv(eckey, buf, len);
            if ret == 1 {
                (*eckey).dirty_cnt += 1;
            }
            return ret;
        }
        // SAFETY: a compile-time-constant site (`ec_key.c:981`,
        // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
        raise_site(&err_sites::EC_KEY_981);
        0
    }
}

/// `int ossl_ec_key_simple_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len)` —
/// `crypto/ec/ec_key.c:990-1009`. Internal. The `oct2priv` column every landed table names.
///
/// A `len` above `INT_MAX` is refused before the scalar is allocated, and the buffer is read
/// through `BN_bin2bn` — which is why the two failures below raise `ERR_R_BN_LIB` rather than a
/// length reason.
///
/// # Safety
///
/// `eckey` is a live key; `buf` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_simple_oct2priv(
    eckey: *mut EcKey,
    buf: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if len > c_int::MAX as usize {
            // SAFETY: a compile-time-constant site (`ec_key.c:994`, ERR_R_PASSED_INVALID_ARGUMENT).
            raise_site(&err_sites::EC_KEY_994);
            return 0;
        }
        if (*eckey).priv_key.is_null() {
            (*eckey).priv_key = BN_secure_new();
        }
        if (*eckey).priv_key.is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:1000`, ERR_R_BN_LIB).
            raise_site(&err_sites::EC_KEY_1000);
            return 0;
        }
        if BN_bin2bn(buf, len as c_int, (*eckey).priv_key).is_null() {
            // SAFETY: a compile-time-constant site (`ec_key.c:1004`, ERR_R_BN_LIB).
            raise_site(&err_sites::EC_KEY_1004);
            return 0;
        }
        (*eckey).dirty_cnt += 1;
        1
    }
}

/// `size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf)` —
/// `crypto/ec/ec_key.c:1011-1028`.
///
/// The two-call sizing idiom: the NULL-`buf` call answers the width, the allocation is made at that
/// width, and the second call fills it. A second-call failure releases the buffer, so the caller
/// owns nothing on failure.
///
/// # Safety
///
/// `eckey` is a live key; `pbuf` is writable.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_priv2buf(eckey: *const EcKey, pbuf: *mut *mut c_uchar) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut len = EC_KEY_priv2oct(eckey, ptr::null_mut(), 0);
        if len == 0 {
            return 0;
        }
        let buf = CRYPTO_malloc(len, FILE, 1019).cast::<c_uchar>();
        if buf.is_null() {
            return 0;
        }
        len = EC_KEY_priv2oct(eckey, buf, len);
        if len == 0 {
            // `OPENSSL_free(buf)`, line 1023.
            CRYPTO_free(buf.cast(), FILE, 1023);
            return 0;
        }
        *pbuf = buf;
        len
    }
}

/// `int EC_KEY_can_sign(const EC_KEY *eckey)` — `crypto/ec/ec_key.c:1030-1036`.
///
/// The group method's [`EC_FLAGS_NO_SIGN`] bit is the whole test, which is why the bit is carried
/// in [`crate::ec`] even though no landed table sets it.
///
/// # Safety
///
/// `eckey` is a live key.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_can_sign(eckey: *const EcKey) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*eckey).group.is_null()
            || (*(*eckey).group).meth.is_null()
            || ((*(*(*eckey).group).meth).flags & EC_FLAGS_NO_SIGN) != 0
        {
            return 0;
        }
        1
    }
}

/// `static int ecdsa_keygen_pairwise_test(EC_KEY *eckey, OSSL_CALLBACK *cb, void *cbarg)` —
/// `crypto/ec/ec_key.c:1047-1078`. The unit's static, reached by
/// [`ec_generate_key`]'s pairwise arm only.
///
/// FIPS 140-2 IG 9.9 AS09.33: a sign/verify round trip over a sixteen-zero-byte digest, with the
/// self-test framework's corrupt-a-byte hook between the two. The digest is public and no secret is
/// printed.
///
/// # Safety
///
/// `eckey` is a live key with a private scalar and a public point; `cb`/`cbarg` are the
/// self-test callback pair.
unsafe fn ecdsa_keygen_pairwise_test(
    eckey: *mut EcKey,
    cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut ret: c_int = 0;
        let mut dgst = [0u8; 16];
        let dgst_len = dgst.len() as c_int;

        let st = OSSL_SELF_TEST_new(cb, cbarg);
        if st.is_null() {
            return 0;
        }

        OSSL_SELF_TEST_onbegin(
            st,
            OSSL_SELF_TEST_TYPE_PCT.as_ptr(),
            OSSL_SELF_TEST_DESC_PCT_ECDSA.as_ptr(),
        );

        let sig = ECDSA_do_sign(dgst.as_ptr(), dgst_len, eckey);
        if sig.is_null() {
            OSSL_SELF_TEST_onend(st, ret);
            OSSL_SELF_TEST_free(st);
            ECDSA_SIG_free(sig);
            return ret;
        }

        OSSL_SELF_TEST_oncorrupt_byte(st, dgst.as_mut_ptr());

        if ECDSA_do_verify(dgst.as_ptr(), dgst_len, sig, eckey) != 1 {
            OSSL_SELF_TEST_onend(st, ret);
            OSSL_SELF_TEST_free(st);
            ECDSA_SIG_free(sig);
            return ret;
        }

        ret = 1;
        OSSL_SELF_TEST_onend(st, ret);
        OSSL_SELF_TEST_free(st);
        ECDSA_SIG_free(sig);
        ret
    }
}
