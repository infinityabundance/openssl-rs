//! Phase 8 — `crypto/dh/dh_key.c`: the default `DH_METHOD`, generation, and agreement.
//!
//! This module holds the `dh_ossl` table the object layer's constructor installs, the three
//! entry points that drive it (`DH_generate_key`, `DH_compute_key`, `DH_compute_key_padded`),
//! the two internals those reach with the public surface (`ossl_dh_generate_public_key`,
//! `ossl_dh_compute_key`), the two provider-facing conversions (`ossl_dh_buf2key`,
//! `ossl_dh_key2buf`) and the three lifecycle statics (`dh_bn_mod_exp`, `dh_init`, `dh_finish`).
//!
//! ## The table, and the cycle it closes with `dh_lib.c`
//!
//! `dh_ossl` (`:165-175`) is initialised `{ "OpenSSL DH Method", generate_key,
//! ossl_dh_compute_key, dh_bn_mod_exp, dh_init, dh_finish, DH_FLAG_FIPS_METHOD, NULL, NULL }` —
//! and its eighth and ninth members are **NULL**, which is contract twice over: the header's
//! comment marks `bn_mod_exp` "Can be null", and `DH_generate_parameters_ex` reads
//! `generate_params` and falls through to its own builtin generator precisely because this table
//! leaves it NULL. `DH_get_default_method` answers `&dh_ossl` until `DH_set_default_method`
//! replaces it, and `dh_new_intern` reads it, so this file and `crate::dh::object` land together:
//! D329 measured the cycle and this slice is its other half.
//!
//! ## One reduction, and the one arm that was written as its field read and is now a call
//!
//! **1. `rhs->meth->...` is an `Option` and the authority's is a bare pointer.** `DH_generate_key`
//! (`:225`), `DH_compute_key` (`:123`), `DH_compute_key_padded` (`:152`),
//! `ossl_dh_compute_key`'s `bn_mod_exp` (`:86`) and `ossl_dh_generate_public_key`'s (`:256`) all
//! call a member the header itself marks nullable and none of them tests it. This crate cannot
//! fault, so each absent member answers the failure the surrounding `goto err` handles and says so
//! at the site; for the three entry points that is `0`, the same as a refusing method. That is
//! unreachable for every table this crate builds — `dh_ossl` sets the first three — and is the
//! same shape as `src/rsa/ossl.rs`'s identical reduction.
//!
//! **2. `DH_get_nid` — the reduction D331 recorded, now a real call.** `generate_key`
//! (`:313`) branches on `DH_get_nid(dh) != NID_undef`; the function is
//! `crypto/dh/dh_group_params.c:94-100`, the named-group unit that waited with the two
//! tables `ffc_dh.c`'s `dh_named_groups[]` reads. D331 wrote the branch as the
//! `params.nid` field read it reduces to, with the argument that the field had **no
//! writer** in the crate — `dh_param_init` and `ossl_dh_cache_named_group` are both in
//! that unit, and `ossl_ffc_params_init` zeroes the field. Both are landed now, so the
//! branch is the call and the arm is live: `DH_new_by_nid(NID_ffdhe2048)` followed by
//! `DH_generate_key` takes the named-group path, where `dh->length` is the RFC 7919 key
//! length the table supplies and `ossl_ffc_generate_private_key` gets its
//! `max_strength` from `ossl_ifc_ffc_compute_security_bits`. `RT-DH` exercises it.
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * [`generate_key`] reuses an existing `priv_key` or `pub_key` **without a copy**, and the
//!   object's members are assigned before the `err:` label runs — the two `if (pub_key !=
//!   dh->pub_key)` tests at the label are what make a reused key survive the failure path rather
//!   than be freed twice.
//! * [`DH_compute_key`]'s unpadding is the authority's own `volatile` loop: it counts leading zero
//!   bytes while touching every byte, so the count is not a branch on the secret's first byte. The
//!   `read_volatile` below preserves the load; the two counters are ordinary locals, whose value
//!   semantics are identical.
//! * [`ossl_dh_compute_key`] raises `DH_R_MODULUS_TOO_SMALL` and **returns 0** while the two
//!   above it raise and jump to the shared `err:` label that answers -1. That asymmetry is the
//!   observable contract of the two refusals and is preserved.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{BN_cmp, BN_sub_word};
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_clear, BN_clear_bit, BN_clear_free, BN_copy, BN_free,
    BN_is_bit_set, BN_is_word, BN_new, BN_num_bits, BN_secure_new, BN_set_flags, BN_value_one,
    BN_with_flags, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::mont::{BN_MONT_CTX_free, BN_MONT_CTX_set_locked, BN_mod_exp_mont, MontCtx};
use crate::bn::rand::{BN_priv_rand_ex, BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ONE};
use crate::ffc::key_generate::ossl_ffc_generate_private_key;
use crate::ffc::params_validate::ossl_ffc_params_simple_validate;
use crate::ffc::FFC_PARAM_TYPE_DH;
use crate::rsa::object::ossl_ifc_ffc_compute_security_bits;
use crate::runtime::err::err_reasons::{
    DH_R_BN_ERROR, DH_R_INVALID_PUBKEY, DH_R_NO_PARAMETERS_SET,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::NID_undef;

use super::check::ossl_dh_check_pub_key_partial;
use super::group_params::DH_get_nid;
use super::object::{DH_get0_key, DH_get0_pqg, DH_set0_key};
use super::{
    Dh, DhBnModExpFn, DhComputeKeyFn, DhGenerateKeyFn, DhLifecycleFn, DhMethod,
    DH_FLAG_CACHE_MONT_P, DH_FLAG_FIPS_METHOD, DH_GENERATOR_2, DH_MIN_MODULUS_BITS,
    OPENSSL_DH_MAX_MODULUS_BITS,
};

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`. The bit `ossl_dh_compute_key` and
/// `ossl_dh_generate_public_key` set on the private key so the modular exponentiation below takes
/// its constant-time path.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `MIN_STRENGTH` — `dh_key.c:24-27`, the `#else` arm. `FIPS_MODULE` is not defined on this
/// profile, so the key layer's floor is 80 rather than 112.
const MIN_STRENGTH: c_int = 80;

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dh/dh_key.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — read out of the authority's own
/// `build/.../crypto/dh/libcrypto-lib-dh_key.o`. It reaches an application through
/// `CRYPTO_set_mem_functions`, so it is part of the contract and `RT-DH` compares it.
const FILE_DH_KEY: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_key.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `int ossl_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)` —
/// `dh_key.c:40-108`.
///
/// "See SP800-56Ar3 Section 5.7.1.1 Finite Field Cryptography Diffie-Hellman (FFC DH) Primitive."
///
/// The three refusals are in the authority's order and are not the same shape: the modulus bound
/// **jumps** and answers -1, the subgroup-order bound **jumps** and answers -1, and the minimum
/// bound **returns 0** immediately. The `err:` label then releases the scratch `z` and the
/// context; `z` is NULL when the minimum-bound arm is taken, and `BN_clear`/`BN_CTX_end` accept
/// that.
///
/// # Safety
///
/// `key` is writable for `DH_size(dh)` bytes; `pub_key` is a live `BIGNUM`; `dh` is a live object
/// whose `priv_key` and parameters the caller has set.
pub(crate) unsafe extern "C" fn ossl_dh_compute_key(
    key: *mut c_uchar,
    pub_key: *const BigNum,
    dh: *mut Dh,
) -> c_int {
    let mut mont: *mut MontCtx = ptr::null_mut();
    let z: *mut BigNum;
    let pminus1: *mut BigNum;
    let ctx: *mut BnCtx;
    let mut ret: c_int = -1;

    // SAFETY: `dh` is live per the contract.
    unsafe {
        if BN_num_bits((*dh).params.p) > OPENSSL_DH_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_48);
            return ret;
        }
        if !(*dh).params.q.is_null() && BN_num_bits((*dh).params.q) > OPENSSL_DH_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_54);
            return ret;
        }
        if BN_num_bits((*dh).params.p) < DH_MIN_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_59);
            return 0;
        }

        ctx = BN_CTX_new_ex((*dh).libctx);
        if ctx.is_null() {
            return ret;
        }

        BN_CTX_start(ctx);
        pminus1 = BN_CTX_get(ctx);
        z = BN_CTX_get(ctx);
        if z.is_null() {
            return err_exit(z, ctx, ret);
        }

        if (*dh).priv_key.is_null() {
            raise_site(&err_sites::DH_KEY_73);
            return err_exit(z, ctx, ret);
        }

        if ((*dh).flags & DH_FLAG_CACHE_MONT_P) != 0 {
            mont = BN_MONT_CTX_set_locked(
                ptr::addr_of_mut!((*dh).method_mont_p),
                (*dh).lock,
                (*dh).params.p,
                ctx,
            );
            BN_set_flags((*dh).priv_key, BN_FLG_CONSTTIME);
            if mont.is_null() {
                return err_exit(z, ctx, ret);
            }
        }

        /* (Step 1) Z = pub_key^priv_key mod p */
        let meth = (*dh).meth;
        let exp = if meth.is_null() {
            None
        } else {
            (*meth).bn_mod_exp
        };
        match exp {
            Some(f) => {
                if f(dh, z, pub_key, (*dh).priv_key, (*dh).params.p, ctx, mont) == 0 {
                    raise_site(&err_sites::DH_KEY_88);
                    ret = -1;
                } else {
                    /* (Step 2) Error if z <= 1 or z = p - 1 */
                    if BN_copy(pminus1, (*dh).params.p).is_null()
                        || BN_sub_word(pminus1, 1) == 0
                        || BN_cmp(z, BN_value_one()) <= 0
                        || BN_cmp(z, pminus1) == 0
                    {
                        raise_site(&err_sites::DH_KEY_97);
                        ret = -1;
                    } else {
                        /* return the padded key, i.e. same number of bytes as the modulus */
                        ret = BN_bn2binpad(z, key, (BN_num_bits((*dh).params.p) + 7) / 8);
                    }
                }
            }
            // The header marks this member "Can be null" and the authority calls it anyway; an
            // absent member answers the failure the shared `err:` label handles.
            None => ret = -1,
        }

        err_exit(z, ctx, ret)
    }
}

/// The authority's `err:` label of [`ossl_dh_compute_key`]: `BN_clear(z)`, then the context's end
/// and release, then the answer. `z` is NULL or a live temporary the context owns; `BN_clear` and
/// the two context calls each accept that, which is what makes the three early exits above share
/// this one epilogue.
///
/// # Safety
///
/// `z` is NULL or a live `BIGNUM`; `ctx` is live and is this call's own.
unsafe fn err_exit(z: *mut BigNum, ctx: *mut BnCtx, ret: c_int) -> c_int {
    // SAFETY: `z` is the caller's scratch and `ctx` its own context, per the contract.
    unsafe {
        BN_clear(z); /* (Step 2) destroy intermediate values */
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ret
}

/// `int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)` — `dh_key.c:114-142`.
///
/// "NB: This function is inherently not constant time due to the RFC 5246 (8.1.2) padding style
/// that strips leading zero bytes."
///
/// # Safety
///
/// As [`ossl_dh_compute_key`].
#[no_mangle]
pub unsafe extern "C" fn DH_compute_key(
    key: *mut c_uchar,
    pub_key: *const BigNum,
    dh: *mut Dh,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let meth = unsafe { (*dh).meth };
    // SAFETY: `meth` is the object's own table; the header marks `compute_key` nullable and the
    // authority calls it without a test. An absent member answers 0, the failure answer below.
    let ret = match unsafe { (*meth).compute_key } {
        // SAFETY: `f` is the table's entry point, handed the same arguments the authority hands it.
        Some(f) => unsafe { f(key, pub_key, dh) },
        None => return 0,
    };
    if ret <= 0 {
        return ret;
    }

    let mut npad: c_int = 0;
    let mut mask: c_int = 1;
    /* count leading zero bytes, yet still touch all bytes */
    for i in 0..ret {
        // `read_volatile` is what makes every byte touched rather than short-circuited away, the
        // role the authority's `volatile` counters play on the other two locals.
        // SAFETY: `key` is writable for `ret` bytes per the contract and `i < ret`.
        let b = unsafe { ptr::read_volatile(key.add(i as usize)) };
        mask &= c_int::from(b == 0);
        npad += mask;
    }

    /* unpad key */
    let unpadded = ret - npad;
    // SAFETY: `key` is writable for the original `ret` bytes and `key + npad` is inside it, so the
    // two ranges overlap and `ptr::copy` is `memmove`'s spelling.
    unsafe {
        ptr::copy(key.add(npad as usize), key, unpadded as usize);
        ptr::write_bytes(key.add(unpadded as usize), 0, npad as usize);
    }

    unpadded
}

/// `int DH_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh)` —
/// `dh_key.c:144-163`.
///
/// The same primitive without the RFC 5246 unpadding: `BN_bn2binpad` already produced exactly
/// `DH_size(dh)` bytes, so `pad` is zero for every method this crate can install and the two
/// functions agree. The subtraction is kept because the authority's is about a *caller-supplied*
/// method that returned fewer bytes.
///
/// # Safety
///
/// As [`ossl_dh_compute_key`].
#[no_mangle]
pub unsafe extern "C" fn DH_compute_key_padded(
    key: *mut c_uchar,
    pub_key: *const BigNum,
    dh: *mut Dh,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let meth = unsafe { (*dh).meth };
    // SAFETY: as `DH_compute_key`'s; an absent member answers 0.
    let rv = match unsafe { (*meth).compute_key } {
        // SAFETY: as `DH_compute_key`'s arm: the table's own entry point, its own arguments.
        Some(f) => unsafe { f(key, pub_key, dh) },
        None => return 0,
    };
    if rv <= 0 {
        return rv;
    }
    // SAFETY: `dh` is live per the contract.
    let pad = unsafe { (BN_num_bits((*dh).params.p) + 7) / 8 } - rv;
    /* pad is constant (zero) unless compute_key is external */
    if pad > 0 {
        // SAFETY: `key` is writable for `DH_size(dh)` bytes per the contract and the two ranges
        // `[pad, pad + rv)` and `[0, rv)` overlap, so this is a `memmove`.
        unsafe {
            ptr::copy(key, key.add(pad as usize), rv as usize);
            ptr::write_bytes(key, 0, pad as usize);
        }
    }
    rv + pad
}

/// `static DH_METHOD dh_ossl` — `dh_key.c:165-175`.
///
/// The table's address is contract in three places: [`DH_get_default_method`] answers it,
/// [`DH_OpenSSL`] answers it, and `DEFAULT_DH_METHOD` is initialised with it. The object is a
/// `static` whose address is taken and is never written.
///
/// **`app_data` and `generate_params` are NULL**, which D329 records; the ninth member's NULL is
/// what makes `DH_generate_parameters_ex` fall through to `dh_gen.c`'s builtin generator.
struct StaticDhMethod(core::cell::UnsafeCell<DhMethod>);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every
// consumer reads one field or takes the address; no `&mut` is ever created.
unsafe impl Sync for StaticDhMethod {}

static DH_OSSL: StaticDhMethod = StaticDhMethod(core::cell::UnsafeCell::new(DhMethod {
    name: c"OpenSSL DH Method".as_ptr().cast_mut(),
    generate_key: Some(generate_key as DhGenerateKeyFn),
    compute_key: Some(ossl_dh_compute_key as DhComputeKeyFn),
    bn_mod_exp: Some(dh_bn_mod_exp as DhBnModExpFn),
    init: Some(dh_init as DhLifecycleFn),
    finish: Some(dh_finish as DhLifecycleFn),
    flags: DH_FLAG_FIPS_METHOD,
    app_data: ptr::null_mut(),
    generate_params: None,
}));

/// The stable address of the authority's `dh_ossl` object, for the two accessors and for
/// `DEFAULT_DH_METHOD`'s initialiser.
const fn dh_ossl() -> *const DhMethod {
    DH_OSSL.0.get()
}

/// `static const DH_METHOD *default_DH_method = &dh_ossl` — `dh_key.c:177`.
///
/// Modelled as an [`AtomicPtr`] rather than a `static mut`, exactly as `src/rsa/ossl.rs:307`
/// models `default_RSA_meth`: the authority's write is unsynchronised, and the crate's option for
/// a process-wide pointer a caller may replace is the atomic. Every access is `Relaxed`, because
/// the authority has no fence.
static DEFAULT_DH_METHOD: AtomicPtr<DhMethod> = AtomicPtr::new(dh_ossl() as *mut DhMethod);

/// `const DH_METHOD *DH_OpenSSL(void)` — `dh_key.c:179-182`.
///
/// The table's *address* is the answer, so two calls — and a call to [`DH_get_default_method`]
/// before any [`DH_set_default_method`] — compare equal.
///
/// # Safety
///
/// None: the answer is a constant.
#[no_mangle]
pub extern "C" fn DH_OpenSSL() -> *const DhMethod {
    dh_ossl()
}

/// `const DH_METHOD *DH_get_default_method(void)` — `dh_key.c:184-187`.
///
/// # Safety
///
/// None: the answer is this module's own table address or the one a caller installed.
#[no_mangle]
pub extern "C" fn DH_get_default_method() -> *const DhMethod {
    DEFAULT_DH_METHOD.load(Ordering::Relaxed)
}

/// `static int dh_bn_mod_exp(...)` — `dh_key.c:189-198`.
///
/// The `#ifdef S390X_MOD_EXP` arm is not taken on this profile, so the body is
/// `BN_mod_exp_mont(r, a, p, m, ctx, m_ctx)`.
///
/// # Safety
///
/// Every pointer is as `BN_mod_exp_mont`'s own contract requires.
unsafe extern "C" fn dh_bn_mod_exp(
    _dh: *const Dh,
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { BN_mod_exp_mont(r, a, p, m, ctx, m_ctx) }
}

/// `static int dh_init(DH *dh)` — `dh_key.c:200-205`.
///
/// Sets the cache flag and bumps the provider's change counter. This is why every object
/// `DH_new` builds caches a Montgomery context for `p` on its first agreement rather than
/// recomputing one per call.
///
/// # Safety
///
/// `dh` is a live object.
unsafe extern "C" fn dh_init(dh: *mut Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe {
        (*dh).flags |= DH_FLAG_CACHE_MONT_P;
        (*dh).dirty_cnt += 1;
    }
    1
}

/// `static int dh_finish(DH *dh)` — `dh_key.c:207-211`. Releases the cached Montgomery context.
///
/// # Safety
///
/// `dh` is a live object.
unsafe extern "C" fn dh_finish(dh: *mut Dh) -> c_int {
    // SAFETY: `dh` is live and `method_mont_p` is NULL or the object's own context.
    unsafe { BN_MONT_CTX_free((*dh).method_mont_p) };
    1
}

/// `void DH_set_default_method(const DH_METHOD *meth)` — `dh_key.c:214-217`.
///
/// A pointer store and nothing else: no reference is taken, no old table is released, and NULL is
/// an accepted value that [`DH_get_default_method`] then answers.
///
/// # Safety
///
/// `meth` is NULL or a live table that outlives its installation.
#[no_mangle]
pub unsafe extern "C" fn DH_set_default_method(meth: *const DhMethod) {
    DEFAULT_DH_METHOD.store(meth.cast_mut(), Ordering::Relaxed);
}

/// `int DH_generate_key(DH *dh)` — `dh_key.c:220-227`.
///
/// `FIPS_MODULE` is not defined, so the body is the method dispatch:
/// `dh->meth->generate_key(dh)`.
///
/// # Safety
///
/// `dh` is a live object whose parameters the caller has set.
#[no_mangle]
pub unsafe extern "C" fn DH_generate_key(dh: *mut Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let meth = unsafe { (*dh).meth };
    // SAFETY: `meth` is the object's own table; the header marks `generate_key` nullable and the
    // authority calls it without a test. An absent member answers 0, the failure answer.
    match unsafe { (*meth).generate_key } {
        // SAFETY: `f` is the table's entry point, handed the object the authority hands it.
        Some(f) => unsafe { f(dh) },
        None => 0,
    }
}

/// `int ossl_dh_generate_public_key(BN_CTX *ctx, const DH *dh, const BIGNUM *priv_key,`
/// `BIGNUM *pub_key)` — `dh_key.c:229-263`. Internal.
///
/// The input is `const DH *` and the authority lies about it to reach its Montgomery cache — the
/// cast and its comment are the authority's own. The private key is copied into a scratch with
/// `BN_FLG_CONSTTIME` so the exponentiation is constant-time and the original is not modified.
///
/// # Safety
///
/// `ctx` is live; `dh` is live with live parameters; `priv_key` is live; `pub_key` is a live,
/// writable `BIGNUM`.
pub(crate) unsafe fn ossl_dh_generate_public_key(
    ctx: *mut BnCtx,
    dh: *const Dh,
    priv_key: *const BigNum,
    pub_key: *mut BigNum,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let prk = unsafe { BN_new() };
    let mut mont: *mut MontCtx = ptr::null_mut();

    if prk.is_null() {
        return 0;
    }

    // SAFETY: `dh` is live per the contract. It is a `*const` and the authority casts the
    // `method_mont_p` slot to mutable for exactly this call (`BN_MONT_CTX **pmont =
    // (BN_MONT_CTX **)&dh->method_mont_p;`), which the site comment records.
    unsafe {
        if ((*dh).flags & DH_FLAG_CACHE_MONT_P) != 0 {
            mont = BN_MONT_CTX_set_locked(
                ptr::addr_of_mut!((*dh.cast_mut()).method_mont_p),
                (*dh).lock,
                (*dh).params.p,
                ctx,
            );
            if mont.is_null() {
                BN_clear_free(prk);
                return ret;
            }
        }
        BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);

        /* pub_key = g^priv_key mod p */
        let meth = (*dh).meth;
        let exp = if meth.is_null() {
            None
        } else {
            (*meth).bn_mod_exp
        };
        if let Some(f) = exp {
            /* pub_key = g^priv_key mod p */
            // SAFETY: `f` is the table's entry point, handed the arguments the authority hands it.
            if f(dh, pub_key, (*dh).params.g, prk, (*dh).params.p, ctx, mont) != 0 {
                ret = 1;
            }
        }
        BN_clear_free(prk);
    }
    ret
}

/// `static int generate_key(DH *dh)` — `dh_key.c:265-387`.
///
/// Three arms on this profile, and the middle one is the authority's own split:
///
/// * the modulus and subgroup bounds, answering 0 with their reasons;
/// * **a named group**: the `DH_get_nid` branch, live since D332 — a `DH` built by
///   `DH_new_by_nid` or built from a table row's own numbers takes it, and its exponent
///   is `dh->length` bits rather than the `l` the explicit arm computes;
/// * **an explicit group**: with no `q` the exponent is a random `l`-bit value with the two
///   top/bottom bit rules, and with a `q` the pair is partially validated and the exponent is
///   `ossl_ffc_generate_private_key` over `len(q)` at `MIN_STRENGTH`.
///
/// The `err:` label distinguishes a reused key from a fresh one with `pub_key != dh->pub_key`, so
/// a caller who supplied a public key keeps it on failure and a caller who did not has theirs
/// released.
///
/// # Safety
///
/// `dh` is a live object whose parameters the caller has set.
unsafe extern "C" fn generate_key(dh: *mut Dh) -> c_int {
    let mut ok: c_int = 0;
    let mut generate_new_key: c_int = 0;
    let pub_key: *mut BigNum;
    let priv_key: *mut BigNum;

    // SAFETY: `dh` is live per the contract.
    unsafe {
        if BN_num_bits((*dh).params.p) > OPENSSL_DH_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_276);
            return 0;
        }
        if !(*dh).params.q.is_null() && BN_num_bits((*dh).params.q) > OPENSSL_DH_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_282);
            return 0;
        }
        if BN_num_bits((*dh).params.p) < DH_MIN_MODULUS_BITS {
            raise_site(&err_sites::DH_KEY_287);
            return 0;
        }
    }

    // SAFETY: `dh` is live per the contract.
    let ctx = unsafe { BN_CTX_new_ex((*dh).libctx) };
    if ctx.is_null() {
        /* The authority's `err:` label with nothing allocated: `ok != 1`, so it raises. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_KEY_379) };
        return ok;
    }

    // SAFETY: `dh` is live per the contract; the scratch objects are this call's own.
    unsafe {
        /* The two allocations the authority makes before its `if (generate_new_key)` block, each
         * with its own `goto err`; the label's release tests are the same ones the epilogue uses
         * below, so a reused key is never freed here. */
        if (*dh).priv_key.is_null() {
            priv_key = BN_secure_new();
            if priv_key.is_null() {
                raise_site(&err_sites::DH_KEY_379);
                BN_CTX_free(ctx);
                return ok;
            }
            generate_new_key = 1;
        } else {
            priv_key = (*dh).priv_key;
        }

        if (*dh).pub_key.is_null() {
            pub_key = BN_new();
            if pub_key.is_null() {
                raise_site(&err_sites::DH_KEY_379);
                if priv_key != (*dh).priv_key {
                    BN_free(priv_key);
                }
                BN_CTX_free(ctx);
                return ok;
            }
        } else {
            pub_key = (*dh).pub_key;
        }

        'generate: {
            if generate_new_key == 0 {
                break 'generate;
            }

            /* Is it an approved safe prime ? */
            // SAFETY: `dh` is live per this function's contract.
            if DH_get_nid(dh) != NID_undef {
                let max_strength = c_int::from(ossl_ifc_ffc_compute_security_bits(BN_num_bits(
                    (*dh).params.p,
                )));
                if (*dh).params.q.is_null() || (*dh).length > BN_num_bits((*dh).params.q) {
                    break 'generate;
                }
                /* dh->length = maximum bit length of generated private key */
                if ossl_ffc_generate_private_key(
                    ctx,
                    ptr::addr_of!((*dh).params),
                    (*dh).length,
                    max_strength,
                    priv_key,
                ) == 0
                {
                    break 'generate;
                }
            } else if (*dh).params.q.is_null() {
                /* secret exponent length, must satisfy 2^l < (p-1)/2 */
                let mut l = BN_num_bits((*dh).params.p);
                if (*dh).length >= l {
                    break 'generate;
                }
                l -= 2;
                if (*dh).length != 0 && (*dh).length < l {
                    l = (*dh).length;
                }
                if BN_priv_rand_ex(priv_key, l, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx) == 0 {
                    break 'generate;
                }
                /*
                 * We handle just one known case where g is a quadratic non-residue:
                 * for g = 2: p % 8 == 3
                 */
                if BN_is_word((*dh).params.g, DH_GENERATOR_2 as c_ulong) != 0
                    && BN_is_bit_set((*dh).params.p, 2) == 0
                {
                    /* clear bit 0, since it won't be a secret anyway */
                    if BN_clear_bit(priv_key, 0) == 0 {
                        break 'generate;
                    }
                }
            } else {
                /* Do a partial check for invalid p, q, g */
                if ossl_ffc_params_simple_validate(
                    (*dh).libctx,
                    ptr::addr_of!((*dh).params),
                    FFC_PARAM_TYPE_DH,
                    ptr::null_mut(),
                ) == 0
                {
                    break 'generate;
                }
                /*
                 * For FFC FIPS 186-4 keygen
                 * security strength s = 112,
                 * Max Private key size N = len(q)
                 */
                if ossl_ffc_generate_private_key(
                    ctx,
                    ptr::addr_of!((*dh).params),
                    BN_num_bits((*dh).params.q),
                    MIN_STRENGTH,
                    priv_key,
                ) == 0
                {
                    break 'generate;
                }
            }

            if ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key) == 0 {
                break 'generate;
            }

            (*dh).pub_key = pub_key;
            (*dh).priv_key = priv_key;
            (*dh).dirty_cnt += 1;
            ok = 1;
        }

        /* The authority's `err:` label, reached by every failure above and by the success path —
         * where `ok == 1` so no raise is made, and neither pointer equals the object's member so
         * neither is released. */
        if ok != 1 {
            raise_site(&err_sites::DH_KEY_379);
        }

        if pub_key != (*dh).pub_key {
            BN_free(pub_key);
        }
        if priv_key != (*dh).priv_key {
            BN_free(priv_key);
        }
        BN_CTX_free(ctx);
    }
    ok
}

/// `int ossl_dh_buf2key(DH *dh, const unsigned char *buf, size_t len)` — `dh_key.c:389-415`.
/// Internal.
///
/// Four refusals, and **the reason is dynamic**: the authority assigns `err_reason` and raises it
/// at one shared site, so the coordinate is constant and the reason is not. A public key that is
/// out of range is `DH_R_INVALID_PUBKEY`; a `p` that is absent or zero-length is
/// `DH_R_NO_PARAMETERS_SET`; everything before that is `DH_R_BN_ERROR`.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider keymgmt and the ameth's
/// import** (`dh_kmgmt.c:380`, `dh_ameth.c:409`), both beyond this slice.
///
/// # Safety
///
/// `dh` is a live object; `buf` is readable for `len` bytes.
#[allow(dead_code)] // read by the provider keymgmt and the ameth, which are later slices
pub(crate) unsafe fn ossl_dh_buf2key(dh: *mut Dh, buf: *const c_uchar, len: usize) -> c_int {
    let mut err_reason: c_int = DH_R_BN_ERROR;

    // SAFETY: `buf` is readable for `len` bytes per the contract.
    let pubkey = unsafe {
        if len > c_int::MAX as usize {
            ptr::null_mut()
        } else {
            BN_bin2bn(buf, len as c_int, ptr::null_mut())
        }
    };
    if pubkey.is_null() {
        // SAFETY: a compile-time-constant coordinate with a dynamic reason.
        unsafe { raise_site_dynamic(&err_sites::DH_KEY_412, err_reason) };
        return 0;
    }

    // SAFETY: `dh` is live per the contract.
    let mut p: *const BigNum = ptr::null_mut();
    // SAFETY: `dh` is live and `p` is a writable local.
    unsafe { DH_get0_pqg(dh, ptr::addr_of_mut!(p), ptr::null_mut(), ptr::null_mut()) };
    let p_bytes = if p.is_null() {
        0
    } else {
        // SAFETY: `p` is non-NULL on this arm, so `BN_num_bits` has its object.
        unsafe { (BN_num_bits(p) + 7) / 8 }
    };
    if p.is_null() || p_bytes == 0 {
        err_reason = DH_R_NO_PARAMETERS_SET;
        // SAFETY: a compile-time-constant coordinate with a dynamic reason.
        unsafe { raise_site_dynamic(&err_sites::DH_KEY_412, err_reason) };
        // SAFETY: `pubkey` is this call's own and nothing else holds it.
        unsafe { BN_free(pubkey) };
        return 0;
    }

    let mut ret: c_int = 0;
    // SAFETY: `dh` is live, `pubkey` is live, and `ret` is a writable local.
    if unsafe { ossl_dh_check_pub_key_partial(dh, pubkey, &raw mut ret) } == 0 {
        err_reason = DH_R_INVALID_PUBKEY;
        // SAFETY: a compile-time-constant coordinate with a dynamic reason.
        unsafe { raise_site_dynamic(&err_sites::DH_KEY_412, err_reason) };
        // SAFETY: `pubkey` is this call's own and nothing else holds it.
        unsafe { BN_free(pubkey) };
        return 0;
    }
    // SAFETY: `dh` is live and `pubkey`'s ownership transfers on success.
    if unsafe { DH_set0_key(dh, pubkey, ptr::null_mut()) } != 1 {
        // SAFETY: a compile-time-constant coordinate with a dynamic reason.
        unsafe { raise_site_dynamic(&err_sites::DH_KEY_412, err_reason) };
        // SAFETY: `pubkey` is this call's own and nothing else holds it.
        unsafe { BN_free(pubkey) };
        return 0;
    }
    1
}

/// `size_t ossl_dh_key2buf(const DH *dh, unsigned char **pbuf_out, size_t size, int alloc)` —
/// `dh_key.c:417-459`. Internal.
///
/// Two allocation policies and four refusals. The `alloc == 0` arm writes **into the caller's
/// buffer** only when it is at least `DH_size(dh)` bytes; the `alloc != 0` arm allocates and the
/// caller owns the result. As per RFC 8446 section 4.2.8.1 the public key is left-padded to the
/// size of `p`.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider keymgmt, the ameth's export and
/// the EVP control translator** (`dh_kmgmt.c:332`, `dh_ameth.c:414`,
/// `ctrl_params_translate.c:1610`), all beyond this slice.
///
/// # Safety
///
/// `dh` is a live object with a public key; `pbuf_out` is NULL or writable for a `*mut u8`.
#[allow(dead_code)] // read by the provider keymgmt/ameth/translator, which are later slices
pub(crate) unsafe fn ossl_dh_key2buf(
    dh: *const Dh,
    pbuf_out: *mut *mut c_uchar,
    size: usize,
    alloc: c_int,
) -> usize {
    let mut pbuf: *mut c_uchar = ptr::null_mut();
    let mut pubkey: *const BigNum = ptr::null_mut();
    let mut p: *const BigNum = ptr::null_mut();

    // SAFETY: `dh` is live and both out-parameters are writable locals.
    unsafe {
        DH_get0_pqg(dh, ptr::addr_of_mut!(p), ptr::null_mut(), ptr::null_mut());
        DH_get0_key(dh, ptr::addr_of_mut!(pubkey), ptr::null_mut());
    }
    if p.is_null() || pubkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_KEY_430) };
        return 0;
    }
    // SAFETY: `p` is non-NULL past the guard above, so `BN_num_bits` has its object.
    let p_size = unsafe { (BN_num_bits(p) + 7) / 8 };
    // SAFETY: `pubkey` is non-NULL past the guard above, so `BN_num_bits` has its object.
    let pubkey_bytes = unsafe { (BN_num_bits(pubkey) + 7) / 8 };
    if p_size == 0 || pubkey_bytes == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_KEY_430) };
        return 0;
    }

    // SAFETY: `pbuf_out` is NULL or writable per the contract.
    if !pbuf_out.is_null() && (alloc != 0 || unsafe { !(*pbuf_out).is_null() }) {
        if alloc == 0 {
            if size >= p_size as usize {
                // SAFETY: `pbuf_out` is non-NULL on this arm.
                pbuf = unsafe { *pbuf_out };
            }
            if pbuf.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DH_KEY_438) };
            }
        } else {
            // `CRYPTO_malloc` is a safe function in this crate: it reads no caller pointer.
            pbuf = CRYPTO_malloc(p_size as usize, FILE_DH_KEY, LINE).cast::<c_uchar>();
        }

        /* Errors raised above */
        if pbuf.is_null() {
            return 0;
        }
        /*
         * As per Section 4.2.8.1 of RFC 8446 left pad public
         * key with zeros to the size of p
         */
        // SAFETY: `pbuf` is writable for `p_size` bytes on both arms, and `pubkey` is live.
        if unsafe { BN_bn2binpad(pubkey, pbuf, p_size) } < 0 {
            if alloc != 0 {
                // SAFETY: `pbuf` is this call's own allocation on the `alloc != 0` arm.
                unsafe { CRYPTO_free(pbuf.cast(), FILE_DH_KEY, LINE) };
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DH_KEY_453) };
            return 0;
        }
        // SAFETY: `pbuf_out` is non-NULL on this arm.
        unsafe { *pbuf_out = pbuf };
    }
    p_size as usize
}
