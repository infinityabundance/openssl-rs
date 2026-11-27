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

use core::ffi::{c_int, c_uchar, c_ulong};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{BN_cmp, BN_sub_word};
use crate::bn::bignum::{
    BN_bin2bn, BN_bn2binpad, BN_clear, BN_clear_bit, BN_clear_free, BN_copy, BN_free,
    BN_is_bit_set, BN_is_word, BN_new, BN_num_bits, BN_secure_new, BN_set_flags, BN_value_one,
    BN_with_flags, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::mont::{bn_mod_exp_mont_policy, BN_MONT_CTX_free, BN_MONT_CTX_set_locked, MontCtx};
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
use crate::runtime::obj::NID_undef;
use crate::runtime::owned_buf::OwnedBuf;

use super::check::ossl_dh_check_pub_key_partial;
use super::group_params::DH_get_nid;
use super::object::{DH_get0_key, DH_get0_pqg, DH_set0_key};
use super::{
    Dh, DhBnModExpFn, DhComputeKeyFn, DhGenerateKeyFn, DhLifecycleFn, DhMethod,
    DH_FLAG_CACHE_MONT_P, DH_FLAG_FIPS_METHOD, DH_GENERATOR_2, DH_MIN_MODULUS_BITS,
    OPENSSL_DH_MAX_MODULUS_BITS,
};
use crate::runtime::mem_coords::SeamFile;

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
const FILE_DH_KEY_SEAM: SeamFile = SeamFile::new(c"../../src/openssl-3.6.4/crypto/dh/dh_key.c");

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
/// The `#ifdef S390X_MOD_EXP` arm is not taken on this profile, so the authority's body is
/// `BN_mod_exp_mont(r, a, p, m, ctx, m_ctx)`.
///
/// **Deliberate, recorded divergence:** the authority ignores `dh` here, so its
/// constant-time ladder runs `p->top * BN_BITS2` regardless of the group's declared
/// private-key length. This body passes the object's public bound (`dh->length`, else the
/// named group's RFC 7919 key length) to the ladder, whose iteration count is then fixed by
/// the group rather than the modulus. The bound is configuration, not key material; the
/// value computed is identical, and `PFP8-WIDTH-POLICY` records the timing consequence.
///
/// # Safety
///
/// Every pointer is as `BN_mod_exp_mont`'s own contract requires; `dh` is NULL or a live
/// object whose parameters and key bound are readable.
unsafe extern "C" fn dh_bn_mod_exp(
    dh: *const Dh,
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    m_ctx: *mut MontCtx,
) -> c_int {
    // SAFETY: `dh` is NULL or a live object per this entry point's contract.
    let policy = unsafe { dh_policy_limbs(dh) };
    // SAFETY: forwarded under this function's contract. `ctx` is unused by the Montgomery
    // entry point here, exactly as it is in the authority's body.
    unsafe { bn_mod_exp_mont_policy(r, a, p, m, m_ctx, policy) }
}

/// The group's declared maximum private-key length, in 64-bit limbs.
///
/// `dh->length` is the caller's explicit bound (`DH_set_length`, or a decoded
/// `recommended-private-length`); when it is unset, the named group's RFC 7919 key length
/// (`params.keylength`, the value `ossl_ffc_generate_private_key` falls back to) is the
/// bound generation uses. Both are public configuration of the object and neither is a
/// property of any private exponent, so the iteration count derived from them is constant
/// for a given group and configuration.
///
/// `0` means "no declared bound" — an unnamed group with no length and no key length, where
/// generation uses `BN_num_bits(q)` or `BN_num_bits(p) - 2` — and keeps the modulus-width
/// ladder.
///
/// # Safety
///
/// `dh` is NULL or a live `Dh` whose `length` and `params.keylength` are readable.
unsafe fn dh_policy_limbs(dh: *const Dh) -> usize {
    if dh.is_null() {
        return 0;
    }
    // SAFETY: `dh` is non-NULL above and is a live object per every caller of the table
    // entry point.
    let bits = unsafe {
        if (*dh).length > 0 {
            (*dh).length
        } else {
            (*dh).params.keylength
        }
    };
    if bits <= 0 {
        return 0;
    }
    (bits as usize).div_ceil(64)
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
/// **The released slot is cleared.** `DH_set_method` runs this hook on each method transition
/// and `DH_free` runs it again through the destructor body, so leaving the freed pointer
/// installed would make the second pass release it a second time; the next key operation would
/// also take `BN_MONT_CTX_set_locked`'s non-NULL fast path with freed storage. Clearing is a
/// deliberate divergence from the authority (the M17-D1/M20-D2 class, §17: do not reproduce the
/// authority's UB) and is not observable to a caller that uses a released context correctly.
///
/// # Safety
///
/// `dh` is a live object.
unsafe extern "C" fn dh_finish(dh: *mut Dh) -> c_int {
    // SAFETY: `dh` is live and `method_mont_p` is NULL or the object's own context.
    unsafe {
        BN_MONT_CTX_free((*dh).method_mont_p);
        (*dh).method_mont_p = ptr::null_mut();
    }
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
/// Those three arms generate a *private* key, and the authority wraps them in
/// `if (generate_new_key)`. Its `ossl_dh_generate_public_key` call is **outside** that block
/// (`dh_key.c:370`), so all four key-state combinations — generated or caller-supplied private
/// key, crossed with an absent or already-present public key — derive `g^priv mod p`, and an
/// existing public-key slot is overwritten in place.
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
            /* The authority's `if (generate_new_key)` wraps only the private-key generation;
             * `ossl_dh_generate_public_key` is called *outside* it (`dh_key.c:370`), so a
             * caller-supplied private key still derives its public key and an existing public
             * key is recomputed in place. Public-key computation belongs below, not in here. */
            if generate_new_key != 0 {
                /* Is it an approved safe prime ? */
                // SAFETY: `dh` is live per this function's contract.
                if DH_get_nid(dh) != NID_undef {
                    let max_strength = c_int::from(ossl_ifc_ffc_compute_security_bits(
                        BN_num_bits((*dh).params.p),
                    ));
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
                    if BN_priv_rand_ex(priv_key, l, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY, 0, ctx)
                        == 0
                    {
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
    // The `alloc != 0` arm's owned block; `None` on the caller-buffer arm and before allocation.
    let mut pbuf_owner: Option<OwnedBuf> = None;

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
    let p_bits = unsafe { BN_num_bits(p) };
    let Some(p_size) = p_bits.checked_add(7).map(|bits| bits / 8) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_KEY_430) };
        return 0;
    };
    // SAFETY: `pubkey` is non-NULL past the guard above, so `BN_num_bits` has its object.
    let pubkey_bits = unsafe { BN_num_bits(pubkey) };
    let Some(pubkey_bytes) = pubkey_bits.checked_add(7).map(|bits| bits / 8) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_KEY_430) };
        return 0;
    };
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
            // The allocation's ownership is the local owner's until the transfer edge below.
            pbuf_owner = OwnedBuf::new_plain_released(
                p_size as usize,
                FILE_DH_KEY_SEAM,
                LINE,
                FILE_DH_KEY_SEAM,
                LINE,
            );
            pbuf = match pbuf_owner.as_ref() {
                Some(owner) => owner.as_ptr(),
                None => ptr::null_mut(),
            };
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
                // The owned arm releases its block at the authority's own coordinates; the
                // caller-buffer arm owns nothing and releases nothing.
                drop(pbuf_owner);
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DH_KEY_453) };
            return 0;
        }
        // SAFETY: `pbuf_out` is non-NULL on this arm.
        unsafe { *pbuf_out = pbuf };
        if let Some(owner) = pbuf_owner {
            // The documented transfer edge: `*pbuf_out` is the caller's block from here on.
            let _ = owner.into_raw();
        }
    }
    p_size as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::mont::BN_MONT_CTX_new;
    use crate::dh::object::{DH_free, DH_new, DH_set_method};

    /// `DH_set_method` runs the outgoing table's `finish`, and a later `DH_free` runs it again
    /// through the destructor body. The first pass must clear the cache so the second cannot
    /// release the same context twice (the M17-D1/M20-D2 class).
    #[test]
    fn the_finish_hook_clears_the_mont_cache_it_releases() {
        // SAFETY: the object and the cached context are this test's own; all three calls are the
        // public lifecycle entry points under their documented contracts.
        unsafe {
            let dh = DH_new();
            assert!(!dh.is_null());
            (*dh).method_mont_p = BN_MONT_CTX_new();
            assert!(!(*dh).method_mont_p.is_null());
            assert_eq!(DH_set_method(dh, DH_OpenSSL()), 1);
            assert!(
                (*dh).method_mont_p.is_null(),
                "the finished cache must not remain installed"
            );
            // The negative control: before the repair this second call released the same block.
            DH_free(dh);
        }
    }

    /// Sweep every seam-visible allocation in a full finite-field DH agreement
    /// (`ossl_dh_compute_key`: the context, the temporaries, the fixed-pattern
    /// exponentiation and the encoding). Each injected failure must be reported as
    /// the entry point's error, never as an abort.
    #[test]
    fn every_allocation_failure_in_dh_compute_key_returns_an_error() {
        use crate::dh::group_params::DH_new_by_nid;
        use crate::dh::object::{DH_free, DH_size};
        use crate::runtime::obj::NID_ffdhe2048;

        // SAFETY: every object and buffer below is this test's own and live.
        unsafe {
            let dh = DH_new_by_nid(NID_ffdhe2048);
            assert!(!dh.is_null());
            assert_eq!(DH_generate_key(dh), 1);
            let mut pub_key: *const BigNum = core::ptr::null();
            DH_get0_key(dh, &mut pub_key, core::ptr::null_mut());
            assert!(!pub_key.is_null());
            let len = DH_size(dh) as usize;
            let mut out = vec![0u8; len];

            // A warm-up fixes the object's caches and context pool, so the sweep sees
            // one stable allocation pattern.
            assert!(ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0);
            let allocations = crate::bn::alloc::test_fail::sweep_sites(|| {
                ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0
            });
            assert!(
                allocations > 0,
                "the seam must see the DH path's allocations"
            );
            eprintln!("T22 sites: dh_compute_key={allocations}");
            assert!(
                ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0,
                "the same call succeeds once the seam is disarmed"
            );
            DH_free(dh);
        }
    }

    /// Reuse is causal on the DH path rather than a cold-start artefact.
    ///
    /// The same live object, key, parameters, context pool and method are used for
    /// both counts; only parameter reuse is toggled. The first count takes the
    /// cached Montgomery context. The second clears `DH_FLAG_CACHE_MONT_P` and the
    /// cached slot, so `BN_mod_exp_mont` recomputes `R`, `R^2` and `R mod p` inside
    /// the timed operation. Nothing about the object's lifecycle changes between
    /// the two counts, so the difference isolates the reuse mechanism instead of
    /// a fresh-object setup cost.
    #[test]
    fn disabling_dh_parameter_reuse_on_a_warm_object_adds_the_precomputation_allocations() {
        use crate::bn::alloc::test_fail;
        use crate::dh::group_params::DH_new_by_nid;
        use crate::dh::object::{DH_free, DH_size};
        use crate::runtime::obj::NID_ffdhe2048;

        // SAFETY: every object and buffer below is this test's own and live.
        unsafe {
            let dh = DH_new_by_nid(NID_ffdhe2048);
            assert!(!dh.is_null());
            assert_eq!(DH_generate_key(dh), 1);
            let mut pub_key: *const BigNum = core::ptr::null();
            DH_get0_key(dh, &mut pub_key, core::ptr::null_mut());
            assert!(!pub_key.is_null());
            let len = DH_size(dh) as usize;
            let mut out = vec![0u8; len];

            // Warm the object and publish the cached Montgomery context.
            assert!(ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0);
            assert!(
                !(*dh).method_mont_p.is_null(),
                "the warm-up must leave a cached context"
            );

            let reused = {
                let _count = test_fail::count_start();
                assert!(ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0);
                test_fail::counted()
            };

            // Disable reuse on the same object: remove the flag and release the
            // cached context. The key, parameters, pool and method stay as they are.
            (*dh).flags &= !DH_FLAG_CACHE_MONT_P;
            BN_MONT_CTX_free((*dh).method_mont_p);
            (*dh).method_mont_p = ptr::null_mut();

            let rebuilt = {
                let _count = test_fail::count_start();
                assert!(ossl_dh_compute_key(out.as_mut_ptr(), pub_key, dh) > 0);
                test_fail::counted()
            };
            eprintln!("DH reuse mutation: reused={reused} rebuilt={rebuilt}");
            assert!(
                rebuilt > reused,
                "disabling reuse must add the precomputation allocations: reused={reused} rebuilt={rebuilt}"
            );
            DH_free(dh);
        }
    }

    /// PFP8-WIDTH-POLICY: the ladder width is the group's declared private-key
    /// bound in limbs — public configuration, not key material.
    #[test]
    fn the_policy_width_is_the_groups_declared_key_length() {
        use crate::dh::group_params::DH_new_by_nid;
        use crate::dh::object::DH_set_length;
        use crate::runtime::obj::{
            NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192,
            NID_modp_1536, NID_modp_2048, NID_modp_8192,
        };

        // 225/275/325/375/400 are the authority's `ffc_dh.c` key lengths; the
        // policy width is `ceil(bits / 64)`.
        let cases = [
            (NID_ffdhe2048, 4),
            (NID_ffdhe3072, 5),
            (NID_ffdhe4096, 6),
            (NID_ffdhe6144, 6),
            (NID_ffdhe8192, 7),
            (NID_modp_1536, 4),
            (NID_modp_2048, 4),
            (NID_modp_8192, 7),
        ];
        for (nid, expected) in cases {
            // SAFETY: the object is this test's own and live.
            unsafe {
                let dh = DH_new_by_nid(nid);
                assert!(!dh.is_null());
                assert_eq!(dh_policy_limbs(dh), expected, "NID {nid}");
                // A caller's explicit length overrides the group's.
                assert_eq!(DH_set_length(dh, 640), 1);
                assert_eq!(dh_policy_limbs(dh), 10);
                DH_free(dh);
            }
        }
    }

    /// PFP8-WIDTH-POLICY: a real key generation through the policy width answers
    /// exactly `g^priv mod p` computed by the full modulus-width ladder, and the
    /// generated private key stays inside the group's declared bound.
    #[test]
    fn the_policy_width_keygen_equals_the_modulus_width_exponentiation() {
        use crate::bn::arith::mod_exp_core_consttime_from_parts;
        use crate::bn::bignum::magnitude;
        use crate::dh::group_params::DH_new_by_nid;
        use crate::runtime::obj::NID_ffdhe2048;

        // SAFETY: every object below is this test's own and live.
        unsafe {
            let dh = DH_new_by_nid(NID_ffdhe2048);
            assert!(!dh.is_null());
            assert_eq!(DH_generate_key(dh), 1);
            assert!(
                BN_num_bits((*dh).priv_key) <= 225,
                "the declared key length"
            );

            let md = magnitude(Some(&*(*dh).params.p));
            let ad = magnitude(Some(&*(*dh).params.g));
            let pd = magnitude(Some(&*(*dh).priv_key));
            let Some(mut expected) = mod_exp_core_consttime_from_parts(ad, pd, md, md.len()) else {
                unreachable!("the modulus-width ladder answers for this group")
            };
            let mut got = magnitude(Some(&*(*dh).pub_key)).to_vec();
            crate::bn::limbs::normalise(&mut expected);
            crate::bn::limbs::normalise(&mut got);
            assert_eq!(got, expected, "pub == g^priv mod p");
            DH_free(dh);
        }
    }

    /// `PFP8-KEYGEN-PRESET-PRIV`: all four `DH_generate_key` key-state combinations.
    ///
    /// **The expectations are the OpenSSL 3.6.4 authority's, not this crate's.**
    /// `crypto/dh/dh_key.c:265-387` places `ossl_dh_generate_public_key()` *outside*
    /// `if (generate_new_key)` (the call is at `dh_key.c:370`), so for a generated or a
    /// caller-supplied private key, and with an absent or an already-present public-key slot,
    /// the call answers 1, leaves the error queue empty, and ends with a public key; an existing
    /// public-key slot is overwritten in place. The preset rows' expected values are the
    /// authority's own `g^priv mod p` output for the `PRIV225` operands, recorded in
    /// `evidence/performance-frontier/campaigns/PFP-8/raw/preset-priv-matrix.json` — they are
    /// pins, not values recomputed by this crate.
    #[test]
    fn the_four_key_state_combinations_all_derive_the_public_key() {
        use crate::bn::bignum::BN_set_word;
        use crate::dh::group_params::DH_new_by_nid;
        use crate::dh::object::{DH_free, DH_get0_key, DH_set0_key, DH_size};
        use crate::runtime::err::{ERR_clear_error, ERR_peek_error};
        use crate::runtime::obj::{NID_ffdhe2048, NID_ffdhe3072, NID_modp_2048};

        /// The authority's `DH_generate_key` public key for `PRIV225`, per group.
        const CASES: [(c_int, &str); 3] = [
            (
                NID_ffdhe2048,
                "ddc74e099f0a7ed7cc42dda99f1ae76c3a4bfdf8e3a52e8e81a3bf67cc0ea2cfa203847b637094c5f774f1d51286fbd7ebfc5e94c61cfe1a796eb1ade0e5bd46b51044befc0f56dfcc61e219aa1858feac69d3d2f1f360f95515c9fe093daf29634895e7b2f1f2c9c7bb482df43096fb80f398468f59252084e61dab5a607f2fa301d70a60613959e2f77c69e31deabdd7d94a4e7367822f8b411bed9a1ba7c162e5ace3a7e5faef58c89add82a8560468a6615140d6679223f2ef8c3af979e93d926e90d2070d064085ebec911a7d89e07ef5fae03b89ba97404b166f93fa76b79e40d115c31498ff347652eab552ab009165ca8ef630146069b4367df1dcbb",
            ),
            (
                NID_ffdhe3072,
                "2d3712adf096f4e09265a854b6dab03156558ec98dab1d03d3559beba1e77c3643964734581b9b043a038b7b02108f2c24b03e4f76ae748f042771b45fd3aa861938dea61c4e23786b3265f4fb7b7578779cfa80e215859cc971b5b33ef0a321c0a9e39a421c7d6b21e491a6114b719957de35f52eb8f1ec852ac540d970b83444d1a28e6a1df282caa95e858f047e0ffd8f3df8e914c037c2d7c789b891f6da426c804d57a12858b479d5af6d54fedfb9a393129c0e001711073020c058e59777412d29a31991c12b8817579159a5626a6bd09d10f9d719cf902a077fa0510d3f49850864c9171f9cc09951531614a55061bed2cab155105ab18f2c6ade6882bf415870e38447449515c3b824b4af6fe8f514cd1dd9aaa07505151f1b10b85eabc1a1307125821f65efad0720ce4f88087a8b56e72d25c074247c4bfea0b056aa9de9661b9a14ca08864f0bbbc88b27bb79b42d526dd2f1965765d8a412a3247f591d9d9344f50e459db1653257e5dd72eece5cfb0652a5b8481be134b2c199",
            ),
            (
                NID_modp_2048,
                "39c0f02ec8b01f08879396d9f12ac5cf6e66992500ac76f453a01655e8a3b0028fa8ddaf7a5491c2a0a0d20c7c10d3734c2ff0c2cdaeb54a2646425b92b16200f44845f48aafca41006c1cfc72b476bfc8b1398964b73c1fe6ad3cbe293c835f985101606539ade3bde48b6430ce59774f1c137f2e466cad16c2ebeb40a497ea8cbe66f58b5322e14bdacfecb84e6b59e5dc1e2421aa4a01616aee3ac9b1a675e7b71f2e7ed92fb717f9b47a8d852c4de6812d253deeef77e05eecf9417f65793c2cf24d4c7503f98b4ce5fa3e7395b50010bbd1362f05266a6192b44680b6d0a3c77b0fc794702f4a2e3f6679dc7d62a0e47d91d4ba8c404337a646ae24c725",
            ),
        ];
        let preset = "002605d5555b1446323a0d7efe724f93e54c7b3dc85ea4b0360ed5fe07";

        // The preset's own bit length, which the authority preserves unchanged.
        const PRESET_BITS: c_int = 222;

        fn preset_bn(preset: &str) -> *mut BigNum {
            // The preset is a compile-time lowercase hex literal; the assertion makes
            // the nibble fallback below unreachable if it is ever edited wrongly.
            assert!(
                preset.len().is_multiple_of(2)
                    && preset
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "the preset is even-length lowercase hex"
            );
            let nibble = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                _ => c - b'a' + 10,
            };
            let bytes: Vec<u8> = (0..preset.len())
                .step_by(2)
                .map(|i| {
                    let raw = preset.as_bytes();
                    (nibble(raw[i]) << 4) | nibble(raw[i + 1])
                })
                .collect();
            // SAFETY: `bytes` is live for the call and `BN_bin2bn` does not retain it.
            unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len() as c_int, ptr::null_mut()) }
        }

        fn padded_hex(v: *const BigNum, bytes: c_int) -> String {
            let mut out = vec![0u8; bytes as usize];
            // SAFETY: `out` is writable for `bytes` bytes and `v` is a live borrowed key.
            let rc = unsafe { BN_bn2binpad(v, out.as_mut_ptr(), bytes) };
            assert_eq!(rc, bytes, "the key encodes to DH_size bytes");
            out.iter().map(|b| format!("{b:02x}")).collect()
        }

        // SAFETY: every object and buffer below is this test's own and live; `DH_set0_key`
        // takes ownership of its BIGNUM arguments, as its contract states.
        unsafe {
            for (nid, expected_pub) in CASES {
                // (1) generated private key, public key absent.
                {
                    let dh = DH_new_by_nid(nid);
                    assert!(!dh.is_null());
                    ERR_clear_error();
                    assert_eq!(DH_generate_key(dh), 1, "nid {nid}: absent/absent");
                    assert_eq!(ERR_peek_error(), 0, "nid {nid}: success leaves no error");
                    let mut pub_key: *const BigNum = ptr::null();
                    let mut priv_key: *const BigNum = ptr::null();
                    DH_get0_key(dh, &mut pub_key, &mut priv_key);
                    assert!(!pub_key.is_null(), "nid {nid}: public key computed");
                    assert!(!priv_key.is_null(), "nid {nid}: private key generated");
                    DH_free(dh);
                }

                // (2) caller-supplied private key, public key absent.
                {
                    let dh = DH_new_by_nid(nid);
                    assert!(!dh.is_null());
                    assert_eq!(DH_set0_key(dh, ptr::null_mut(), preset_bn(preset)), 1);
                    ERR_clear_error();
                    assert_eq!(DH_generate_key(dh), 1, "nid {nid}: preset/absent");
                    assert_eq!(ERR_peek_error(), 0, "nid {nid}: success leaves no error");
                    let mut pub_key: *const BigNum = ptr::null();
                    let mut priv_key: *const BigNum = ptr::null();
                    DH_get0_key(dh, &mut pub_key, &mut priv_key);
                    assert!(!pub_key.is_null(), "nid {nid}: public key computed");
                    assert_eq!(BN_num_bits(priv_key), PRESET_BITS, "nid {nid}: key reused");
                    assert_eq!(
                        padded_hex(pub_key, DH_size(dh)),
                        expected_pub,
                        "nid {nid}: the authority's g^priv mod p"
                    );
                    DH_free(dh);
                }

                // (3) generated private key, public key slot present.
                {
                    let dh = DH_new_by_nid(nid);
                    assert!(!dh.is_null());
                    let sentinel = BN_new();
                    assert!(!sentinel.is_null());
                    assert_eq!(BN_set_word(sentinel, 2), 1);
                    assert_eq!(DH_set0_key(dh, sentinel, ptr::null_mut()), 1);
                    ERR_clear_error();
                    assert_eq!(DH_generate_key(dh), 1, "nid {nid}: absent/present");
                    assert_eq!(ERR_peek_error(), 0, "nid {nid}: success leaves no error");
                    let mut pub_key: *const BigNum = ptr::null();
                    let mut priv_key: *const BigNum = ptr::null();
                    DH_get0_key(dh, &mut pub_key, &mut priv_key);
                    assert!(!pub_key.is_null(), "nid {nid}: public key computed");
                    assert!(
                        BN_is_word(pub_key, 2) == 0,
                        "nid {nid}: the supplied slot is overwritten"
                    );
                    DH_free(dh);
                }

                // (4) caller-supplied private key, public key slot present.
                {
                    let dh = DH_new_by_nid(nid);
                    assert!(!dh.is_null());
                    let sentinel = BN_new();
                    assert!(!sentinel.is_null());
                    assert_eq!(BN_set_word(sentinel, 2), 1);
                    assert_eq!(DH_set0_key(dh, sentinel, preset_bn(preset)), 1);
                    ERR_clear_error();
                    assert_eq!(DH_generate_key(dh), 1, "nid {nid}: preset/present");
                    assert_eq!(ERR_peek_error(), 0, "nid {nid}: success leaves no error");
                    let mut pub_key: *const BigNum = ptr::null();
                    let mut priv_key: *const BigNum = ptr::null();
                    DH_get0_key(dh, &mut pub_key, &mut priv_key);
                    assert!(!pub_key.is_null(), "nid {nid}: public key computed");
                    assert_eq!(BN_num_bits(priv_key), PRESET_BITS, "nid {nid}: key reused");
                    assert_eq!(
                        padded_hex(pub_key, DH_size(dh)),
                        expected_pub,
                        "nid {nid}: the authority's g^priv mod p"
                    );
                    DH_free(dh);
                }
            }
        }
    }

    /// PFP-43: a caller-supplied private key wider than both the group's declared
    /// policy and the modulus is not refused. `DH_generate_key` derives
    /// `g^x mod p`, `DH_compute_key` agrees with an ordinary peer, and
    /// `ossl_dh_check_pairwise` accepts the recomputed public key — the three
    /// paths that reach `dh_bn_mod_exp`.
    ///
    /// The exponent is 2400 bits of `0xab` (300 bytes, the court's
    /// `long_2400bit` preset) against the 2048-bit ffdhe2048 modulus: 38 limbs
    /// versus 32, and far above the group's 225-bit declared key length.
    #[test]
    fn an_out_of_policy_private_key_derives_and_agrees() {
        use crate::bn::bignum::BN_bin2bn;
        use crate::dh::group_params::DH_new_by_nid;
        use crate::dh::object::{DH_free, DH_get0_key, DH_set0_key, DH_size};
        use crate::runtime::obj::NID_ffdhe2048;

        let wide = [0xabu8; 300];
        // SAFETY: every object and buffer below is this test's own and live;
        // `DH_set0_key` takes ownership of `priv_a`, and `BN_bin2bn` copies the
        // 300 bytes without retaining them.
        unsafe {
            let a = DH_new_by_nid(NID_ffdhe2048);
            let b = DH_new_by_nid(NID_ffdhe2048);
            assert!(!a.is_null() && !b.is_null());

            let priv_a = BN_bin2bn(wide.as_ptr(), wide.len() as c_int, ptr::null_mut());
            assert!(!priv_a.is_null());
            assert_eq!(BN_num_bits(priv_a), 2400);
            assert_eq!(DH_set0_key(a, ptr::null_mut(), priv_a), 1);

            // keygen: `g^priv mod p` for the preset private key.
            assert_eq!(DH_generate_key(a), 1, "the authority derives this key");
            let mut pub_a: *const BigNum = ptr::null();
            DH_get0_key(a, &mut pub_a, ptr::null_mut());
            assert!(!pub_a.is_null());
            assert!(BN_num_bits(pub_a) > 0);

            // compute_key: an ordinary in-policy peer agrees with the wide key.
            assert_eq!(DH_generate_key(b), 1);
            let mut pub_b: *const BigNum = ptr::null();
            DH_get0_key(b, &mut pub_b, ptr::null_mut());
            assert!(!pub_b.is_null());
            let len = DH_size(a) as usize;
            let mut k1 = vec![0u8; len];
            let mut k2 = vec![0u8; len];
            let n1 = DH_compute_key_padded(k1.as_mut_ptr(), pub_b, a);
            let n2 = DH_compute_key_padded(k2.as_mut_ptr(), pub_a, b);
            assert_eq!(n1, len as c_int);
            assert_eq!(n2, len as c_int);
            assert_eq!(k1, k2, "shared-secret symmetry with one out-of-policy key");

            // pairwise: recompute `g^priv` and compare with the stored public key.
            assert_eq!(crate::dh::check::ossl_dh_check_pairwise(a, 0), 1);

            DH_free(a);
            DH_free(b);
        }
    }
}
