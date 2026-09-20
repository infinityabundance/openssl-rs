//! Phase 8 — `crypto/dsa/dsa_lib.c`: the `DSA` object layer.
//!
//! `dsa_new_intern` and its three entry points, `DSA_free`, `DSA_up_ref`, the ex-data pair, the
//! flag trio, `DSA_set_method`/`DSA_get_method`, `DSA_dup_DH`, every `DSA_get0_*`/`DSA_set0_*`
//! accessor, the three readers `DSA_bits`/`DSA_size`/`DSA_security_bits` (the first and third here;
//! `DSA_size` is `dsa_sign.c`'s), and the internal `ossl_dsa_new`/`ossl_dsa_set0_libctx`/
//! `ossl_dsa_get0_params` — twenty-four exports and three internals, in authority order.
//!
//! ## The cycle this file and `dsa_ossl.c` close together
//!
//! `dsa_new_intern` (`:153`) reads `DSA_get_default_method()`, whose `default_DSA_method` is
//! `&openssl_dsa_meth` — and `openssl_dsa_meth` is `crypto/dsa/dsa_ossl.c:53-67`, not this file. So
//! the constructor cannot be transcribed before that table exists, and the table cannot be built
//! before its five member functions' addresses do. D329 named the cycle for DH, D331 closed it, and
//! this slice closes it for DSA, which is why [`crate::dsa::ossl`] exists in the same commit.
//!
//! ## One reachable-answer reduction, and it is the one D331 recorded for DH
//!
//! **`ENGINE_*`.** `DSA_set_method` and `DSA_free` call `ENGINE_finish(dsa->engine)` (`:126`,
//! `:216`); `dsa_new_intern` calls `ENGINE_init`, `ENGINE_get_default_DSA` and `ENGINE_get_DSA`
//! (`:156`, `:161`, `:163`). None of the five is in this crate. The authority's own comment on
//! `DSA_set_method` — "The caller is specifically setting a method, so it's not up to us to deal
//! with which ENGINE it comes from" — is the shape of the reduction: with no engine registry,
//! `ENGINE_get_default_DSA()` selects from an empty table and answers NULL (`tb_dsa.c`), so
//! `dsa->engine` is NULL on every state this crate can reach and `ENGINE_finish(NULL)` returns 1
//! without touching anything (`eng_init.c:108-111`). The two `finish` calls are therefore omitted
//! with the `dsa->engine = NULL;` assignment kept where the authority writes it, which is
//! `src/rsa/object.rs`'s established reduction and D313/D331's argument. Its observable half is
//! that `DSA_get0_engine` answers NULL for every object the crate can build, and `RT-DSA` asserts
//! it. The two `ERR_R_ENGINE_LIB` raise sites inside that block (`:158`, `:167`) are therefore
//! unreachable and no `raise_site` names them; the generated `err_sites::DSA_LIB_158`/`_167`
//! coordinates are still emitted by the lexical scan and still carried in `err_sites::ALL`,
//! exactly as D330 records for the two FIPS-only FFC sites and D331 for `DH_LIB_100`/`_109`.
//!
//! ## One internal is withheld, and it is the same blocker `DH_KDF_X9_42` names
//!
//! `ossl_dsa_ffc_params_fromdata` (`:355-365`) is `ossl_ffc_params_fromdata` plus a `dirty_cnt`
//! bump, and that function is `crypto/ffc/ffc_backend.c`'s — a unit with **no crate module**, for
//! the reason D330 and D332 record: it calls `crypto/param_build_set.c`'s four
//! `ossl_param_build_set_*`, a unit no stratum's plan row names. It is one of the two names this
//! slice records in `forensics/prerequisites.json` as a deferral rather than approximating, and
//! the row names its own blocker.
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * [`dsa_new_intern`] acquires the lock, then the reference, then stores `libctx` and the method,
//!   and only then installs the ex-data: the `err:` label answers `DSA_free(ret)`, so every field
//!   set on the way in must be one `DSA_free` already knows how to release. The reference is stored
//!   **before** the ex-data so that the failure path's `DSA_free` decrements from 1 to 0 and
//!   reaches the release rather than returning early.
//! * [`DSA_free`] decrements first and returns **without touching anything** on a positive
//!   remainder; then the method's `finish`, then the ex-data, the lock and the (empty)
//!   `CRYPTO_FREE_REF`, then the FFC parameters, then the two key `BIGNUM`s and finally the object.
//!   `BN_clear_free` is used for both keys because both are secret material.
//! * [`DSA_set_method`] runs the outgoing table's `finish` before it stores the incoming one, and
//!   the incoming table's `init` after.
//!
//! ## Macro spellings, checked rather than assumed
//!
//! * `OPENSSL_free`/`OPENSSL_zalloc` are `CRYPTO_free`/`CRYPTO_zalloc` with this unit's own file
//!   string, and `CRYPTO_zalloc` is a *safe* function in this crate (D113), so the constructor's
//!   allocation needs no guard.
//! * `CRYPTO_NEW_REF`/`CRYPTO_FREE_REF`/`CRYPTO_UP_REF`/`CRYPTO_DOWN_REF` and
//!   `REF_ASSERT_ISNT`/`REF_PRINT_COUNT` are `include/internal/refcount.h`. This profile takes the
//!   `__GNUC__` arm: `CRYPTO_NEW_REF`'s fallback is the plain store the constructor writes,
//!   `CRYPTO_UP_REF` is a relaxed fetch-add, `CRYPTO_DOWN_REF` a release fetch-sub with an acquire
//!   fence at zero, `CRYPTO_FREE_REF` is empty, `REF_ASSERT_ISNT` is `NDEBUG`-gated and empty, and
//!   `REF_PRINT_COUNT` is an `OSSL_TRACE3` omitted with this sentence as its record.
//! * The authority's constructor calls `ossl_crypto_new_ex_data_ex(libctx, …)`, the internal behind
//!   the `CRYPTO_new_ex_data` macro. This crate reaches the same behaviour through
//!   `CRYPTO_new_ex_data`, which is what `src/dh/object.rs` does and for the same reason: the
//!   `libctx` argument only selects which ex-data implementation is consulted, and this crate has
//!   one registry.
//! * `#ifndef FIPS_MODULE` and `#ifndef OPENSSL_NO_DH` both hold on this profile, so `DSA_dup_DH`
//!   and every `#ifndef FIPS_MODULE` block below is compiled.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::bn::bignum::{BN_clear_free, BN_dup, BN_free, BN_num_bits, BN_security_bits, BigNum};
use crate::dh::object::{ossl_dh_get0_params, DH_free, DH_new, DH_set0_key};
use crate::evp::pkey_asn1::Engine;
use crate::ffc::params::{
    ossl_ffc_params_cleanup, ossl_ffc_params_copy, ossl_ffc_params_get0_pqg, ossl_ffc_params_init,
    ossl_ffc_params_set0_pqg,
};
use crate::ffc::FfcParams;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
    CRYPTO_EX_INDEX_DSA,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new};

use super::ossl::DSA_get_default_method;
use super::{Dsa, DsaMethod, DSA_FLAG_NON_FIPS_ALLOW};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dsa/dsa_lib.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — the check D280 applied to the cipher units and D329/D331 to
/// the two DH units. It reaches an application through `CRYPTO_set_mem_functions`, so it is part
/// of the contract and `RT-DSA` compares it.
const FILE_DSA_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/dsa/dsa_lib.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `DSA *DSA_new(void)` — `dsa_lib.c:194-197`. `dsa_new_intern(NULL, NULL)`: no engine, and the
/// library context the default one.
///
/// # Safety
///
/// Takes no pointer.
#[no_mangle]
pub unsafe extern "C" fn DSA_new() -> *mut Dsa {
    // SAFETY: neither argument is read by the constructor beyond the store of `libctx`, which is
    // NULL here.
    unsafe { dsa_new_intern(ptr::null_mut(), ptr::null_mut()) }
}

/// `DSA *DSA_new_method(ENGINE *engine)` — `dsa_lib.c:190-193`.
///
/// **The engine argument is ignored**, which is the constructor's reduction record: the crate has
/// no `ENGINE` to hand `ENGINE_init`, so `DSA_new_method(NULL)` is this function's whole reachable
/// surface.
///
/// # Safety
///
/// `engine` is NULL and is ignored.
#[no_mangle]
pub unsafe extern "C" fn DSA_new_method(engine: *mut Engine) -> *mut Dsa {
    // SAFETY: `engine` is not read; the library context is NULL as the authority passes it.
    unsafe { dsa_new_intern(engine, ptr::null_mut()) }
}

/// `DSA *ossl_dsa_new(OSSL_LIB_CTX *libctx)` — `dsa_lib.c:199-202`. Internal.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider paths** — `dsa_backend.c` and
/// the decode/import units — none of which is in this slice. It is transcribed with the rest of
/// the object because the file defines it and D327's rule is that a unit is whole.
///
/// # Safety
///
/// `libctx` is NULL or a live library context that outlives the object.
#[allow(dead_code)] // read by `crypto/dsa/dsa_backend.c`, which is a later slice
pub(crate) unsafe fn ossl_dsa_new(libctx: *mut c_void) -> *mut Dsa {
    // SAFETY: neither argument is read by the constructor beyond the store of `libctx`.
    unsafe { dsa_new_intern(ptr::null_mut(), libctx) }
}

/// `static DSA *dsa_new_intern(ENGINE *engine, OSSL_LIB_CTX *libctx)` — `dsa_lib.c:139-188`.
///
/// `OPENSSL_zalloc(sizeof(*ret))` is a zeroed 200-byte allocation, which is why every member the
/// authority does not assign here — `pad`, `version`, `pub_key`, `priv_key`, `method_mont_p`,
/// `dirty_cnt` — is NULL or zero and why `DSA_free` may release any of them.
///
/// # Safety
///
/// `engine` is NULL and is ignored; `libctx` is NULL or a live library context.
unsafe fn dsa_new_intern(_engine: *mut Engine, libctx: *mut c_void) -> *mut Dsa {
    // `OPENSSL_zalloc` is `CRYPTO_zalloc(.., OPENSSL_FILE, OPENSSL_LINE)`, and `CRYPTO_zalloc` is
    // a *safe* function in this crate (D113), so this call needs no guard.
    let ret = CRYPTO_zalloc(core::mem::size_of::<Dsa>(), FILE_DSA_LIB, LINE).cast::<Dsa>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_THREAD_lock_new` reads no caller pointer.
    let lock = CRYPTO_THREAD_lock_new();
    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).lock = lock };
    if lock.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSA_LIB_141) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        unsafe { CRYPTO_free(ret.cast(), FILE_DSA_LIB, LINE) };
        return ptr::null_mut();
    }

    // `if (!CRYPTO_NEW_REF(&ret->references, 1))` — the header's fallback arm on this profile is
    // `refcnt->val = n; return 1;`, so the test is the assignment and the branch is unreachable
    // rather than omitted.
    // SAFETY: `references` is a field of this call's own allocation.
    unsafe { (*ret).references.store(1, Ordering::Relaxed) };

    // The authority's `err:` label (`:186`), reached by the failures below and by none above it. It
    // answers `DSA_free(ret)`; every field set on the way in is one `DSA_free` releases.
    let built = 'build: {
        // SAFETY: `ret` is this call's own allocation; `libctx` is the caller's, stored as the
        // authority stores it and never read here.
        unsafe { (*ret).libctx = libctx };
        // SAFETY: `DSA_get_default_method` takes no pointers.
        let meth = DSA_get_default_method();
        // SAFETY: `ret` is this call's own allocation.
        unsafe { (*ret).meth = meth };

        // `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)` — compiled here, and reduced:
        // the engine lookup answers NULL, so the block's whole reachable effect is the assignment
        // below. The `ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW;` the authority
        // writes first is the "early default init" and is kept.
        // SAFETY: `meth` is the table the getter answered, read exactly as the authority reads it.
        unsafe { (*ret).flags = (*meth).flags & !DSA_FLAG_NON_FIPS_ALLOW };
        // SAFETY: `ret` is this call's own allocation; the engine is NULL on every reachable state.
        unsafe { (*ret).engine = ptr::null_mut() };

        // The second assignment, and the one that matters when an engine replaced the table.
        // SAFETY: `ret` is this call's own allocation and `meth` its own member.
        unsafe { (*ret).flags = (*(*ret).meth).flags & !DSA_FLAG_NON_FIPS_ALLOW };

        // SAFETY: `ret` is this call's own allocation and `ex_data` is a field of it.
        if unsafe {
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_DSA,
                ret.cast(),
                ptr::addr_of_mut!((*ret).ex_data),
            )
        } == 0
        {
            break 'build false;
        }

        // SAFETY: `ret` is this call's own allocation and `params` is a field of it.
        unsafe { ossl_ffc_params_init(ptr::addr_of_mut!((*ret).params)) };

        // SAFETY: `ret` is this call's own allocation and `meth` is a member of it.
        if let Some(init) = unsafe { (*(*ret).meth).init } {
            // SAFETY: the table's own initialiser, handed this object as the authority hands it.
            if unsafe { init(ret) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSA_LIB_184) };
                break 'build false;
            }
        }
        true
    };

    if !built {
        // SAFETY: `ret` is this call's own object and the authority's `err:` label releases it
        // through `DSA_free` on exactly these paths.
        unsafe { DSA_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `void DSA_free(DSA *r)` — `dsa_lib.c:204-231`.
///
/// NULL is a no-op. The release order is the contract and is transcribed statement for statement;
/// see the module documentation for the omitted `ENGINE_finish`. `REF_ASSERT_ISNT(i < 0)` is empty
/// under this profile's `NDEBUG`.
///
/// # Safety
///
/// `r` is NULL or a live object, and must not be used again after this call unless a reference
/// remains.
#[no_mangle]
pub unsafe extern "C" fn DSA_free(r: *mut Dsa) {
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

    // The authority's `if (r->meth != NULL && r->meth->finish != NULL)`.
    // SAFETY: `r` is live and this is the last reference.
    let meth = unsafe { (*r).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is the object's own table, alive until this statement.
        if let Some(finish) = unsafe { (*meth).finish } {
            // SAFETY: `finish` is that table's own destructor for this object.
            unsafe { finish(r) };
        }
    }

    // The authority's `ENGINE_finish(r->engine)` is omitted: `r->engine` is NULL on every state
    // this crate can reach. See the module documentation.

    // SAFETY: `r` is live and `ex_data` is a field of it.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_DSA,
            r.cast(),
            ptr::addr_of_mut!((*r).ex_data),
        )
    };
    // SAFETY: `r` is live and `lock` is the lock the constructor created.
    unsafe { CRYPTO_THREAD_lock_free((*r).lock) };

    // `CRYPTO_FREE_REF(&r->references)` is empty on this profile's arm of the header.

    // SAFETY: `params` is the object's own embedded parameters, whose four `BIGNUM`s and seed are
    // each NULL or owned by it; this is the last reference.
    unsafe { ossl_ffc_params_cleanup(ptr::addr_of_mut!((*r).params)) };
    // SAFETY: both keys are NULL or the object's own `BIGNUM`s, and both are secret material, so
    // the clearing form the authority spells is used.
    unsafe {
        BN_clear_free((*r).pub_key);
        BN_clear_free((*r).priv_key);
    }
    // SAFETY: `r` is this object's own allocation, released last.
    unsafe { CRYPTO_free(r.cast(), FILE_DSA_LIB, LINE) };
}

/// `int DSA_up_ref(DSA *r)` — `dsa_lib.c:233-243`.
///
/// Answers **1** for any object a caller can legitimately hold; the `i > 1` test is the authority's
/// own and the only way to answer 0 is a count already at zero. `REF_ASSERT_ISNT(i < 2)` is empty
/// here.
///
/// # Safety
///
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_up_ref(r: *mut Dsa) -> c_int {
    // `CRYPTO_UP_REF` is a *relaxed* fetch-add, and the relaxedness is deliberate.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_add(1, Ordering::Relaxed) }.wrapping_add(1);
    if i > 1 {
        1
    } else {
        0
    }
}

/// `void ossl_dsa_set0_libctx(DSA *d, OSSL_LIB_CTX *libctx)` — `dsa_lib.c:245-248`. Internal.
///
/// A bare store with no reference taken. `#[allow(dead_code)]`'s reason: **its callers are the
/// provider decode paths** (`decode_der2key.c.in`), which are beyond this phase.
///
/// # Safety
///
/// `d` is a live object; `libctx` is NULL or live for as long as it is read.
#[allow(dead_code)] // read by the provider decode paths, which are a later stratum
pub(crate) unsafe fn ossl_dsa_set0_libctx(d: *mut Dsa, libctx: *mut c_void) {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).libctx = libctx };
}

/// `int DSA_set_ex_data(DSA *d, int idx, void *arg)` — `dsa_lib.c:29-32`.
///
/// # Safety
///
/// `d` is a live object; `arg` is whatever the index's own free callback expects.
#[no_mangle]
pub unsafe extern "C" fn DSA_set_ex_data(d: *mut Dsa, idx: c_int, arg: *mut c_void) -> c_int {
    // SAFETY: `d` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*d).ex_data), idx, arg) }
}

/// `void *DSA_get_ex_data(const DSA *d, int idx)` — `dsa_lib.c:34-37`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is whatever was stored, or NULL.
#[no_mangle]
pub unsafe extern "C" fn DSA_get_ex_data(d: *const Dsa, idx: c_int) -> *mut c_void {
    // SAFETY: `d` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*d).ex_data), idx) }
}

/// `DH *DSA_dup_DH(const DSA *r)` — `dsa_lib.c:40-79`.
///
/// A `DSA`'s `p`/`q`/`g` are a superset of a `DH`'s: the authority's own comment lists both
/// ("DSA has p, q, g, optional pub_key, optional priv_key. DH has p, optional length, g, optional
/// pub_key, optional priv_key, optional q"), and this function copies the parameter block through
/// `ossl_ffc_params_copy` and the two keys through `DH_set0_key`.
///
/// **The `else if (r->priv_key != NULL)` arm is the interesting one**: a `DSA` with a private key
/// and no public key is a state the authority calls "Shouldn't happen" and refuses with the `err:`
/// label rather than dropping the private key silently.
///
/// # Safety
///
/// `r` is NULL or a live object. The answer is a fresh `DH` the caller owns, or NULL.
#[no_mangle]
pub unsafe extern "C" fn DSA_dup_DH(r: *const Dsa) -> *mut crate::dh::Dh {
    /*
     * DSA has p, q, g, optional pub_key, optional priv_key.
     * DH has p, optional length, g, optional pub_key,
     * optional priv_key, optional q.
     */
    let mut ret: *mut crate::dh::Dh = ptr::null_mut();
    let mut pub_key: *mut BigNum = ptr::null_mut();
    let mut priv_key: *mut BigNum = ptr::null_mut();

    if r.is_null() {
        // SAFETY: every argument is NULL and `DH_free(NULL)` is a no-op.
        return unsafe { dup_dh_err(pub_key, priv_key, ret) };
    }
    // SAFETY: `DH_new` takes no pointer.
    ret = unsafe { DH_new() };
    if ret.is_null() {
        // SAFETY: `pub_key` and `priv_key` are NULL and `ret` is NULL.
        return unsafe { dup_dh_err(pub_key, priv_key, ret) };
    }

    // SAFETY: `ret` is this call's own object and `r` is live; both parameter blocks are live.
    if unsafe { ossl_ffc_params_copy(ossl_dh_get0_params(ret), ptr::addr_of!((*r).params)) } == 0 {
        // SAFETY: both keys are NULL and `ret` is this call's own object.
        return unsafe { dup_dh_err(pub_key, priv_key, ret) };
    }

    // SAFETY: `r` is live per the contract.
    unsafe {
        if !(*r).pub_key.is_null() {
            // SAFETY: `BN_dup` reads the live source and allocates the answer.
            pub_key = BN_dup((*r).pub_key);
            if pub_key.is_null() {
                return dup_dh_err(pub_key, priv_key, ret);
            }
            if !(*r).priv_key.is_null() {
                // SAFETY: as above.
                priv_key = BN_dup((*r).priv_key);
                if priv_key.is_null() {
                    return dup_dh_err(pub_key, priv_key, ret);
                }
            }
            // SAFETY: `ret` is this call's own object and both keys are this call's own.
            if DH_set0_key(ret, pub_key, priv_key) == 0 {
                return dup_dh_err(pub_key, priv_key, ret);
            }
        } else if !(*r).priv_key.is_null() {
            /* Shouldn't happen */
            return dup_dh_err(pub_key, priv_key, ret);
        }
    }

    ret
}

/// `DSA_dup_DH`'s `err:` label (`dsa_lib.c:74-78`): both keys are released, then the object.
///
/// # Safety
///
/// Each pointer is NULL or live and owned by the caller of this function.
unsafe fn dup_dh_err(
    pub_key: *mut BigNum,
    priv_key: *mut BigNum,
    ret: *mut crate::dh::Dh,
) -> *mut crate::dh::Dh {
    // SAFETY: `BN_free` accepts NULL, and both keys are this call's own or NULL.
    unsafe {
        BN_free(pub_key);
        BN_free(priv_key);
        DH_free(ret);
    }
    ptr::null_mut()
}

/// `void DSA_clear_flags(DSA *d, int flags)` — `dsa_lib.c:82-85`.
///
/// # Safety
///
/// `d` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_clear_flags(d: *mut Dsa, flags: c_int) {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).flags &= !flags };
}

/// `int DSA_test_flags(const DSA *d, int flags)` — `dsa_lib.c:87-90`.
///
/// Answers the masked word, not a boolean: a caller that passes a multi-bit mask gets the bits that
/// were set. That asymmetry with a `!= 0` test is the authority's.
///
/// # Safety
///
/// `d` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_test_flags(d: *const Dsa, flags: c_int) -> c_int {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).flags & flags }
}

/// `void DSA_set_flags(DSA *d, int flags)` — `dsa_lib.c:92-95`.
///
/// # Safety
///
/// `d` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_set_flags(d: *mut Dsa, flags: c_int) {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).flags |= flags };
}

/// `ENGINE *DSA_get0_engine(DSA *d)` — `dsa_lib.c:97-100`.
///
/// **NULL for every object this crate can build**, because there is no engine registry to attach
/// one; that is the observable half of the constructor's reduction and `RT-DSA` asserts it.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_engine(d: *mut Dsa) -> *mut Engine {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).engine }
}

/// `int DSA_set_method(DSA *dsa, const DSA_METHOD *meth)` — `dsa_lib.c:102-122`.
///
/// **Always answers 1, and the old method is shut down before the new one is installed.** See this
/// module's reduction note for the omitted `ENGINE_finish`; the `dsa->engine = NULL;` assignment
/// the authority writes beside it is kept.
///
/// # Safety
///
/// `dsa` is a live object; `meth` is a live table that outlives its use.
#[no_mangle]
pub unsafe extern "C" fn DSA_set_method(dsa: *mut Dsa, meth: *const DsaMethod) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let mtmp = unsafe { (*dsa).meth };
    // SAFETY: `mtmp` is the object's own table and is live.
    if let Some(finish) = unsafe { (*mtmp).finish } {
        // SAFETY: `finish` is that table's own destructor for this object.
        unsafe { finish(dsa) };
    }
    // The authority's `ENGINE_finish(dsa->engine)` is omitted: `dsa->engine` is NULL on every state
    // this crate can reach and `ENGINE_finish(NULL)` returns 1 without touching anything.
    // SAFETY: `dsa` is live per the contract.
    unsafe { (*dsa).engine = ptr::null_mut() };
    // SAFETY: `dsa` is live per the contract.
    unsafe { (*dsa).meth = meth };
    // SAFETY: `meth` is live per the contract.
    if let Some(init) = unsafe { (*meth).init } {
        // SAFETY: `init` is that table's own initialiser for this object.
        unsafe { init(dsa) };
    }
    1
}

/// `const DSA_METHOD *DSA_get_method(DSA *d)` — `dsa_lib.c:126-129`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get_method(d: *mut Dsa) -> *const DsaMethod {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).meth }
}

/// `void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)` —
/// `dsa_lib.c:252-256`.
///
/// A one-line delegation to the FFC accessor, which owns the three NULL-able out-parameters.
///
/// # Safety
///
/// `d` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_pqg(
    d: *const Dsa,
    p: *mut *const BigNum,
    q: *mut *const BigNum,
    g: *mut *const BigNum,
) {
    // SAFETY: `d` is live and `params` is a field of it; each out-parameter is NULL or writable per
    // the contract, and the FFC accessor writes exactly one `*mut BigNum` through each.
    unsafe {
        ossl_ffc_params_get0_pqg(
            ptr::addr_of!((*d).params),
            p.cast::<*mut BigNum>(),
            q.cast::<*mut BigNum>(),
            g.cast::<*mut BigNum>(),
        )
    };
}

/// `int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)` — `dsa_lib.c:258-270`.
///
/// **Three refusals before anything is stored**, one per slot: `p`, `q` and `g` are each required
/// when the object's own slot is empty. That is `DH_set0_pqg`'s two refusals plus one — the
/// authority's DH accessor lets `q` stay NULL, this one does not, because a `DSA` cannot verify
/// without it. On success `dirty_cnt` is bumped and the parameters are stored.
///
/// # Safety
///
/// `d` is live; each of `p`, `q` and `g` is NULL or a live `BIGNUM` whose ownership the caller
/// transfers on the success path.
#[no_mangle]
pub unsafe extern "C" fn DSA_set0_pqg(
    d: *mut Dsa,
    p: *mut BigNum,
    q: *mut BigNum,
    g: *mut BigNum,
) -> c_int {
    /* If the fields p, q and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    // SAFETY: `d` is live per the contract.
    unsafe {
        if ((*d).params.p.is_null() && p.is_null())
            || ((*d).params.q.is_null() && q.is_null())
            || ((*d).params.g.is_null() && g.is_null())
        {
            return 0;
        }

        ossl_ffc_params_set0_pqg(ptr::addr_of_mut!((*d).params), p, q, g);
        (*d).dirty_cnt += 1;
    }

    1
}

/// `const BIGNUM *DSA_get0_p(const DSA *d)` — `dsa_lib.c:272-275`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_p(d: *const Dsa) -> *const BigNum {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).params.p }
}

/// `const BIGNUM *DSA_get0_q(const DSA *d)` — `dsa_lib.c:277-280`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_q(d: *const Dsa) -> *const BigNum {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).params.q }
}

/// `const BIGNUM *DSA_get0_g(const DSA *d)` — `dsa_lib.c:282-285`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_g(d: *const Dsa) -> *const BigNum {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).params.g }
}

/// `const BIGNUM *DSA_get0_pub_key(const DSA *d)` — `dsa_lib.c:287-290`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_pub_key(d: *const Dsa) -> *const BigNum {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).pub_key }
}

/// `const BIGNUM *DSA_get0_priv_key(const DSA *d)` — `dsa_lib.c:292-295`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_priv_key(d: *const Dsa) -> *const BigNum {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).priv_key }
}

/// `void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)` —
/// `dsa_lib.c:297-303`.
///
/// # Safety
///
/// `d` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DSA_get0_key(
    d: *const Dsa,
    pub_key: *mut *const BigNum,
    priv_key: *mut *const BigNum,
) {
    // SAFETY: `d` is live and each out-parameter is NULL or writable per the contract.
    unsafe {
        if !pub_key.is_null() {
            *pub_key = (*d).pub_key;
        }
        if !priv_key.is_null() {
            *priv_key = (*d).priv_key;
        }
    }
}

/// `int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)` — `dsa_lib.c:305-318`.
///
/// Each slot is replaced **only when the argument is non-NULL**, and the outgoing value is cleared
/// rather than freed — this is key material. Always answers 1, including for a NULL pair.
///
/// # Safety
///
/// `d` is live; each argument is NULL or a live `BIGNUM` whose ownership the caller transfers.
#[no_mangle]
pub unsafe extern "C" fn DSA_set0_key(
    d: *mut Dsa,
    pub_key: *mut BigNum,
    priv_key: *mut BigNum,
) -> c_int {
    // SAFETY: `d` is live per the contract; the outgoing values are the object's own.
    unsafe {
        if !pub_key.is_null() {
            BN_clear_free((*d).pub_key);
            (*d).pub_key = pub_key;
        }
        if !priv_key.is_null() {
            BN_clear_free((*d).priv_key);
            (*d).priv_key = priv_key;
        }

        (*d).dirty_cnt += 1;
    }

    1
}

/// `int DSA_security_bits(const DSA *d)` — `dsa_lib.c:320-326`.
///
/// The modulus-and-subgroup table, through the landed [`BN_security_bits`] — **not**
/// `ossl_ifc_ffc_compute_security_bits`, which is the *RSA* reader (`RSA_security_bits` calls it
/// when `n` is set) and lives in `src/rsa/object.rs`. `DH_security_bits` and `DSA_security_bits`
/// both call `BN_security_bits`, and the two functions answer differently above 3072 bits, which
/// is D320's measurement and the reason the two are not interchangeable.
///
/// Answers **-1** with no modulus or no subgroup order, which is the authority's sentinel rather
/// than a strength of zero.
///
/// # Safety
///
/// `d` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_security_bits(d: *const Dsa) -> c_int {
    // SAFETY: `d` is live per the contract, and each read is guarded by the NULL test the authority
    // writes.
    unsafe {
        if !(*d).params.p.is_null() && !(*d).params.q.is_null() {
            return BN_security_bits(BN_num_bits((*d).params.p), BN_num_bits((*d).params.q));
        }
    }
    -1
}

/// `int DSA_bits(const DSA *dsa)` — `dsa_lib.c:328-333`.
///
/// Answers **-1** rather than 0 for an object with no modulus.
///
/// # Safety
///
/// `dsa` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DSA_bits(dsa: *const Dsa) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    unsafe {
        if !(*dsa).params.p.is_null() {
            return BN_num_bits((*dsa).params.p);
        }
    }
    -1
}

/// `FFC_PARAMS *ossl_dsa_get0_params(DSA *dsa)` — `dsa_lib.c:335-338`. Internal.
///
/// The bridge the key layer, the generator, the verifier and the provider all use to reach the
/// embedded parameters. It is reached here by [`crate::dsa::key`], [`crate::dsa::gen`] and
/// [`crate::dsa::ossl`] through the object's own fields, and its `pub(crate)` callers outside this
/// module are the provider backend's.
///
/// # Safety
///
/// `dsa` is a live object. The returned pointer is borrowed from it.
#[allow(dead_code)] // read by the provider backend/import paths, which are later slices
pub(crate) unsafe fn ossl_dsa_get0_params(dsa: *mut Dsa) -> *mut FfcParams {
    // SAFETY: `dsa` is live per the contract.
    unsafe { ptr::addr_of_mut!((*dsa).params) }
}
