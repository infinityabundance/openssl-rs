//! Phase 8 — `crypto/dh/dh_lib.c`: the `DH` object layer.
//!
//! `DH_new`/`DH_new_method` and their static `dh_new_intern`, `DH_free`, `DH_up_ref`, the
//! ex-data pair, every `DH_get0_*`/`DH_set0_*` accessor, the four `DH_bits`/`DH_size`/
//! `DH_security_bits`/`DH_get_length` readers, the flag trio, `DH_get0_engine`, and the two
//! internal accessors `ossl_dh_get0_params`/`ossl_dh_get0_nid` — twenty-five exports and five
//! internals, in authority order.
//!
//! ## The cycle this file and `dh_key.c` close together
//!
//! `dh_new_intern` (`:95`) reads `DH_get_default_method()`, whose `default_DH_method` is
//! `&dh_ossl` — and `dh_ossl` is `crypto/dh/dh_key.c:165-175`, not this file. So the constructor
//! cannot be transcribed before that table exists, and the table cannot be built before its
//! three member functions' addresses do. D329 named the cycle; this commit lands both halves at
//! once, which is why [`crate::dh::key`] exists in the same slice.
//!
//! ## One reachable-answer reduction, and the second one undone
//!
//! **1. `ENGINE_*`.** [`DH_set_method`] and [`DH_free`] call `ENGINE_finish(dh->engine)`
//! (`:43`, `:153`); `dh_new_intern` calls `ENGINE_init`, `ENGINE_get_default_DH` and
//! `ENGINE_get_DH` (`:99`, `:105`, `:107`). None is in this crate. The authority's comment on
//! [`DH_set_method`] — "The caller is specifically setting a method, so it's not up to us to deal
//! with which ENGINE it comes from" — is the shape of the reduction: with no engine registry,
//! `ENGINE_get_default_DH()` selects from an empty table and answers NULL (`tb_dh.c`), so
//! `(*dh).engine` is NULL on every state this crate can reach and `ENGINE_finish(NULL)` returns 1
//! without touching anything (`eng_init.c:108-111`). The two `finish` calls are therefore omitted
//! with `dh->engine = NULL;` kept where the authority writes it, which is
//! `src/rsa/object.rs`'s established reduction and D313's argument. Its observable half is that
//! `DH_get0_engine` answers NULL for every object the crate can build, and the probe asserts it.
//!
//! The constructor's three calls reduce one step further: with `ENGINE_get_default_DH()`
//! answering NULL the `if (ret->engine)` block — the only reader of `ENGINE_get_DH` — is
//! unreachable, so the whole `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)` block
//! becomes `ret->engine = NULL;` with the two `flags` assignments the authority makes around it
//! kept. The two `ERR_R_ENGINE_LIB` raise sites the block contains (`:100`, `:109`) are therefore
//! unreachable on this crate's states and no `raise_site` names them; the generated
//! `err_sites::DH_LIB_100`/`DH_LIB_109` coordinates are still emitted by the lexical scan and
//! still carried in `err_sites::ALL`, which is what D330 records for the two FIPS-only FFC sites.
//!
//! **2. `ossl_dh_cache_named_group` — the reduction D329, D330 and D331 recorded, now a
//! real call.** [`DH_set0_pqg`] calls it (`:242`), and it lives in
//! `crypto/dh/dh_group_params.c`, the named-group unit whose two tables (the
//! `ossl_bignum_*` constants and `ffc_dh.c`'s `dh_named_groups[]`) D329/D330 left as a
//! separable data transcription. Both tables are landed now
//! ([`crate::bn::dh`], [`crate::ffc::dh`], [`crate::dh::group_params`]), so the call is
//! [`crate::dh::group_params::ossl_dh_cache_named_group`] and the three `DH_get_nid`
//! reads in `dh_key.c`/`dh_check.c` are real calls too. **What the reduction had to say
//! is still worth keeping**, because it is why the call is observable at all: until this
//! slice `params.nid` had *no* writer in the crate — the field's only two writers are
//! `dh_param_init` and `ossl_dh_cache_named_group`, both in that unit — so the cache's
//! whole effect on a crate-built object was the flush of a field that already held the
//! flushed value. `RT-DH` now observes the other half: a `DH` built from a group's own
//! numbers acquires that group's `nid`, `q` and key length.
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * [`dh_new_intern`] acquires the lock, then the reference, then stores `libctx` and the
//!   method, and only then installs the ex-data: the `err:` label answers `DH_free(ret)`, so every
//!   field set on the way in must be one `DH_free` already knows how to release. The reference is
//!   stored **before** the ex-data so that the failure path's `DH_free` decrements from 1 to 0
//!   and reaches the release rather than returning early.
//! * [`DH_free`] decrements first and returns **without touching anything** on a positive
//!   remainder; then the method's `finish`, then the ex-data, the lock and the (empty)
//!   `CRYPTO_FREE_REF`, then the FFC parameters, then the two key `BIGNUM`s and finally the
//!   object. `curl`-style `BN_clear_free` is used for both keys because both are secret material.
//! * [`DH_set_method`] runs the outgoing table's `finish` before it stores the incoming one, and
//!   runs the incoming table's `init` after. An object whose method was set by hand must not hold
//!   a *functional* engine reference it no longer has a table for.
//!
//! ## Macro spellings, checked rather than assumed
//!
//! * `BN_num_bytes(a)` (`include/openssl/bn.h`) is `((BN_num_bits(a) + 7) / 8)`, so [`DH_size`] is
//!   written as the body behind it, exactly as `src/rsa/object.rs` writes [`crate::rsa::RSA_size`].
//! * `CRYPTO_NEW_REF`/`CRYPTO_FREE_REF`/`CRYPTO_UP_REF`/`CRYPTO_DOWN_REF` and
//!   `REF_ASSERT_ISNT`/`REF_PRINT_COUNT` are `include/internal/refcount.h`. This profile takes the
//!   `__GNUC__` arm: `CRYPTO_NEW_REF`'s fallback is the plain store the constructor writes,
//!   `CRYPTO_UP_REF` is a relaxed fetch-add, `CRYPTO_DOWN_REF` a release fetch-sub with an acquire
//!   fence at zero, `CRYPTO_FREE_REF` is empty, `REF_ASSERT_ISNT` is `NDEBUG`-gated and empty, and
//!   `REF_PRINT_COUNT` is an `OSSL_TRACE3` omitted with this sentence as its record.
//! * `OPENSSL_free`/`OPENSSL_zalloc` are `CRYPTO_free`/`CRYPTO_zalloc` with this unit's own file
//!   string (`CRYPTO_free(p, OPENSSL_FILE, OPENSSL_LINE)`), and `CRYPTO_zalloc` is a safe function
//!   in this crate (D113), so the constructor's allocation needs no guard.
//! * `#ifndef OPENSSL_PEDANTIC_ZEROIZATION` holds — no `-DOPENSSL_PEDANTIC_ZEROIZATION` appears in
//!   the pinned Configure line — so `ossl_ffc_params_cleanup` inside [`DH_free`] is the
//!   `BN_free`/`OPENSSL_free` arm, as `src/ffc/params.rs` already records.
//! * `#ifndef FIPS_MODULE` holds throughout, so every `#ifndef FIPS_MODULE` block is compiled and
//!   its `#ifdef FIPS_MODULE` twin is not.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::bn::bignum::{BN_clear_free, BN_num_bits, BN_security_bits, BigNum};
use crate::dh::group_params::ossl_dh_cache_named_group;
use crate::evp::pkey_asn1::Engine;
use crate::ffc::params::{
    ossl_ffc_params_cleanup, ossl_ffc_params_get0_pqg, ossl_ffc_params_init,
    ossl_ffc_params_set0_pqg,
};
use crate::ffc::FfcParams;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
    CRYPTO_EX_INDEX_DH,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new};

use super::key::DH_get_default_method;
use super::{Dh, DhMethod};

/// The allocation-tracking `file` argument for this unit's allocations.
///
/// `crypto/dh/dh_lib.c` is a **source-tree** file, so its `__FILE__` carries the
/// `../../src/openssl-3.6.4/` prefix — read out of the authority's own
/// `build/.../crypto/dh/libcrypto-lib-dh_lib.o`, the check D280 applied to the cipher units. It
/// reaches an application through `CRYPTO_set_mem_functions`, so it is part of the contract and
/// `RT-DH` compares it.
const FILE_DH_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_lib.c".as_ptr();

/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `int DH_set_method(DH *dh, const DH_METHOD *meth)` — `dh_lib.c:32-50`.
///
/// **Always answers 1, and the old method is shut down before the new one is installed.** See this
/// module's reduction note for the omitted `ENGINE_finish`; the `dh->engine = NULL;` assignment the
/// authority writes beside it is kept.
///
/// # Safety
///
/// `dh` is a live object; `meth` is a live table that outlives its use.
#[no_mangle]
pub unsafe extern "C" fn DH_set_method(dh: *mut Dh, meth: *const DhMethod) -> c_int {
    // SAFETY: `dh` is live per the contract.
    let mtmp = unsafe { (*dh).meth };
    // SAFETY: `mtmp` is the object's own table and is live.
    if let Some(finish) = unsafe { (*mtmp).finish } {
        // SAFETY: `finish` is that table's own destructor for this object.
        unsafe { finish(dh) };
    }
    // The authority's `ENGINE_finish(dh->engine)` is omitted: `dh->engine` is NULL on every state
    // this crate can reach and `ENGINE_finish(NULL)` returns 1 without touching anything.
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).engine = ptr::null_mut() };
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).meth = meth };
    // SAFETY: `meth` is live per the contract.
    if let Some(init) = unsafe { (*meth).init } {
        // SAFETY: `init` is that table's own initialiser for this object.
        unsafe { init(dh) };
    }
    1
}

/// `const DH_METHOD *ossl_dh_get_method(const DH *dh)` — `dh_lib.c:52-55`. Internal
/// (`include/crypto/dh.h:47`), so `pub(crate)`.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider backend's.**
/// `crypto/dh/dh_backend.c:125` is the only caller in the authority, and that unit is beyond this
/// slice; the accessor is transcribed with the rest of the object rather than left out as the one
/// member of the file with no body.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[allow(dead_code)] // read by `crypto/dh/dh_backend.c`, which is a later slice
pub(crate) unsafe fn ossl_dh_get_method(dh: *const Dh) -> *const DhMethod {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).meth }
}

/// `DH *DH_new(void)` — `dh_lib.c:57-60`. `dh_new_intern(NULL, NULL)`: no engine, and the library
/// context the default one.
///
/// # Safety
///
/// Takes no pointer.
#[no_mangle]
pub unsafe extern "C" fn DH_new() -> *mut Dh {
    // SAFETY: neither argument is read by the constructor beyond the store of `libctx`, which is
    // NULL here.
    unsafe { dh_new_intern(ptr::null_mut(), ptr::null_mut()) }
}

/// `DH *DH_new_method(ENGINE *engine)` — `dh_lib.c:63-66`.
///
/// **The engine argument is ignored**, which is what the constructor's reduction note records:
/// the crate has no `ENGINE` to hand `ENGINE_init`, so `DH_new_method(NULL)` is this function's
/// whole reachable surface.
///
/// # Safety
///
/// `engine` is NULL and is ignored.
#[no_mangle]
pub unsafe extern "C" fn DH_new_method(engine: *mut Engine) -> *mut Dh {
    // SAFETY: `engine` is not read; the library context is NULL as the authority passes it.
    unsafe { dh_new_intern(engine, ptr::null_mut()) }
}

/// `DH *ossl_dh_new_ex(OSSL_LIB_CTX *libctx)` — `dh_lib.c:69-72`. Internal.
///
/// Read by `dh_group_params.c`'s `dh_param_init` ([`crate::dh::group_params`]) and by the
/// provider backend's `dh_backend.c`; the first is landed.
///
/// # Safety
///
/// `libctx` is NULL or a live library context that outlives the object.
pub(crate) unsafe fn ossl_dh_new_ex(libctx: *mut c_void) -> *mut Dh {
    // SAFETY: neither argument is read by the constructor beyond the store of `libctx`.
    unsafe { dh_new_intern(ptr::null_mut(), libctx) }
}

/// `static DH *dh_new_intern(ENGINE *engine, OSSL_LIB_CTX *libctx)` — `dh_lib.c:74-134`.
///
/// `OPENSSL_zalloc(sizeof(*ret))` is a zeroed 208-byte allocation, which is why every member the
/// authority does not assign here — `pad`, `version`, `length`, `pub_key`, `priv_key`,
/// `method_mont_p`, `dirty_cnt` — is NULL or zero and why `DH_free` may release any of them.
///
/// The authority writes `ret->lock` and tests it in one bracket; the transcription splits the
/// assignment out so the null test reads the local, which is the same object.
///
/// # Safety
///
/// `engine` is NULL and is ignored; `libctx` is NULL or a live library context.
unsafe fn dh_new_intern(_engine: *mut Engine, libctx: *mut c_void) -> *mut Dh {
    // `OPENSSL_zalloc` is `CRYPTO_zalloc(.., OPENSSL_FILE, OPENSSL_LINE)`, and `CRYPTO_zalloc` is
    // a *safe* function in this crate (D113), so this call needs no guard.
    let ret = CRYPTO_zalloc(core::mem::size_of::<Dh>(), FILE_DH_LIB, LINE).cast::<Dh>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `CRYPTO_THREAD_lock_new` reads no caller pointer.
    let lock = CRYPTO_THREAD_lock_new();
    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).lock = lock };
    if lock.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_LIB_83) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        unsafe { CRYPTO_free(ret.cast(), FILE_DH_LIB, LINE) };
        return ptr::null_mut();
    }

    // `if (!CRYPTO_NEW_REF(&ret->references, 1))` — the header's fallback arm on this profile is
    // `refcnt->val = n; return 1;`, so the test is the assignment and the branch is unreachable
    // rather than omitted. The store is `Relaxed` because the fallback arm's write is a plain
    // store into a field nothing else can see yet.
    // SAFETY: `references` is a field of this call's own allocation.
    unsafe { (*ret).references.store(1, Ordering::Relaxed) };

    // The authority's `err:` label (`:131`), reached by the failures below and by none above it.
    // It answers `DH_free(ret)`; every field set on the way in is one `DH_free` releases.
    let built = 'build: {
        // SAFETY: `ret` is this call's own allocation; `libctx` is the caller's, stored as the
        // authority stores it and never read here.
        unsafe { (*ret).libctx = libctx };
        // SAFETY: `DH_get_default_method` takes no pointers.
        let meth = DH_get_default_method();
        // SAFETY: `ret` is this call's own allocation.
        unsafe { (*ret).meth = meth };

        // `#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)` — compiled here, and
        // reduced: the engine lookup answers NULL, so the block's whole reachable effect is the
        // assignment below. The `ret->flags = ret->meth->flags;` the authority writes first is
        // the "early default init" and is kept.
        // SAFETY: `meth` is the table the getter answered, read exactly as the authority reads it.
        unsafe { (*ret).flags = (*meth).flags };
        // SAFETY: `ret` is this call's own allocation; the engine is NULL on every reachable state.
        unsafe { (*ret).engine = ptr::null_mut() };

        // The second assignment, and the one that matters when an engine replaced the table.
        // SAFETY: `ret` is this call's own allocation and `meth` its own member.
        unsafe { (*ret).flags = (*(*ret).meth).flags };

        // SAFETY: `ret` is this call's own allocation and `ex_data` is a field of it.
        if unsafe {
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_DH,
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
                unsafe { raise_site(&err_sites::DH_LIB_125) };
                break 'build false;
            }
        }
        true
    };

    if !built {
        // SAFETY: `ret` is this call's own object and the authority's `err:` label releases it
        // through `DH_free` on exactly these paths.
        unsafe { DH_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `void DH_free(DH *r)` — `dh_lib.c:136-165`.
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
pub unsafe extern "C" fn DH_free(r: *mut Dh) {
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
            CRYPTO_EX_INDEX_DH,
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
    unsafe { CRYPTO_free(r.cast(), FILE_DH_LIB, LINE) };
}

/// `int DH_up_ref(DH *r)` — `dh_lib.c:167-177`.
///
/// Answers **1** for any object a caller can legitimately hold; the `i > 1` test is the
/// authority's own and the only way to answer 0 is a count already at zero. `REF_ASSERT_ISNT(i < 2)`
/// is empty here.
///
/// # Safety
///
/// `r` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_up_ref(r: *mut Dh) -> c_int {
    // `CRYPTO_UP_REF` is a *relaxed* fetch-add, and the relaxedness is deliberate.
    // SAFETY: `r` is live per the contract.
    let i = unsafe { (*r).references.fetch_add(1, Ordering::Relaxed) }.wrapping_add(1);
    if i > 1 {
        1
    } else {
        0
    }
}

/// `void ossl_dh_set0_libctx(DH *d, OSSL_LIB_CTX *libctx)` — `dh_lib.c:179-182`. Internal.
///
/// A bare store with no reference taken. `#[allow(dead_code)]`'s reason: **its callers are the
/// provider decode paths** (`decode_der2key.c.in:435`), which are beyond this phase.
///
/// # Safety
///
/// `d` is a live object; `libctx` is NULL or live for as long as it is read.
#[allow(dead_code)] // read by the provider decode paths, which are a later stratum
pub(crate) unsafe fn ossl_dh_set0_libctx(d: *mut Dh, libctx: *mut c_void) {
    // SAFETY: `d` is live per the contract.
    unsafe { (*d).libctx = libctx };
}

/// `int DH_set_ex_data(DH *d, int idx, void *arg)` — `dh_lib.c:185-188`.
///
/// # Safety
///
/// `d` is a live object; `arg` is whatever the index's own free callback expects.
#[no_mangle]
pub unsafe extern "C" fn DH_set_ex_data(d: *mut Dh, idx: c_int, arg: *mut c_void) -> c_int {
    // SAFETY: `d` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_set_ex_data(ptr::addr_of_mut!((*d).ex_data), idx, arg) }
}

/// `void *DH_get_ex_data(const DH *d, int idx)` — `dh_lib.c:190-193`.
///
/// # Safety
///
/// `d` is a live object. The returned pointer is whatever was stored, or NULL.
#[no_mangle]
pub unsafe extern "C" fn DH_get_ex_data(d: *const Dh, idx: c_int) -> *mut c_void {
    // SAFETY: `d` is live and `ex_data` is a field of it.
    unsafe { CRYPTO_get_ex_data(ptr::addr_of!((*d).ex_data), idx) }
}

/// `int DH_bits(const DH *dh)` — `dh_lib.c:196-201`.
///
/// Answers **-1** rather than 0 for an object with no modulus, which is the authority's sentinel.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_bits(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe {
        if !(*dh).params.p.is_null() {
            return BN_num_bits((*dh).params.p);
        }
    }
    -1
}

/// `int DH_size(const DH *dh)` — `dh_lib.c:203-208`.
///
/// `BN_num_bytes(p)` is `(BN_num_bits(p) + 7) / 8`, written as its body. Answers -1 with no
/// modulus.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_size(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe {
        if !(*dh).params.p.is_null() {
            return (BN_num_bits((*dh).params.p) + 7) / 8;
        }
    }
    -1
}

/// `int DH_security_bits(const DH *dh)` — `dh_lib.c:210-223`.
///
/// The subgroup order decides `N` when it is present; otherwise the object's own `length` does;
/// otherwise `N` is -1, which makes `BN_security_bits` fall back to its modulus-only table.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_security_bits(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per the contract, and each reader below is reached only with the
    // matching slot non-NULL.
    unsafe {
        let n = if !(*dh).params.q.is_null() {
            BN_num_bits((*dh).params.q)
        } else if (*dh).length != 0 {
            (*dh).length
        } else {
            -1
        };
        if !(*dh).params.p.is_null() {
            return BN_security_bits(BN_num_bits((*dh).params.p), n);
        }
    }
    -1
}

/// `void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)` —
/// `dh_lib.c:225-229`.
///
/// A one-line delegation to the FFC accessor, which owns the three NULL-able out-parameters.
///
/// # Safety
///
/// `dh` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_pqg(
    dh: *const Dh,
    p: *mut *const BigNum,
    q: *mut *const BigNum,
    g: *mut *const BigNum,
) {
    // SAFETY: `dh` is live and `params` is a field of it; each out-parameter is NULL or writable
    // per the contract, and the FFC accessor writes exactly one `*mut BigNum` through each.
    unsafe {
        ossl_ffc_params_get0_pqg(
            ptr::addr_of!((*dh).params),
            p.cast::<*mut BigNum>(),
            q.cast::<*mut BigNum>(),
            g.cast::<*mut BigNum>(),
        )
    };
}

/// `int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)` — `dh_lib.c:231-245`.
///
/// **Two refusals before anything is stored**: a NULL `p` on an object with no `p`, and a NULL `g`
/// on an object with no `g`. `q` is explicitly allowed to stay NULL. On success the authority also
/// refreshes the named-group cache and bumps `dirty_cnt`, and both are here: the cache is
/// [`crate::dh::group_params::ossl_dh_cache_named_group`], whose effect on a `DH` built from a
/// group's own numbers is what `RT-DH` observes.
///
/// # Safety
///
/// `dh` is live; each of `p`, `q` and `g` is NULL or a live `BIGNUM` whose ownership the caller
/// transfers on the success path.
#[no_mangle]
pub unsafe extern "C" fn DH_set0_pqg(
    dh: *mut Dh,
    p: *mut BigNum,
    q: *mut BigNum,
    g: *mut BigNum,
) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe {
        if ((*dh).params.p.is_null() && p.is_null()) || ((*dh).params.g.is_null() && g.is_null()) {
            return 0;
        }

        ossl_ffc_params_set0_pqg(ptr::addr_of_mut!((*dh).params), p, q, g);
        ossl_dh_cache_named_group(dh);
        (*dh).dirty_cnt += 1;
    }
    1
}

/// `long DH_get_length(const DH *dh)` — `dh_lib.c:247-250`.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_get_length(dh: *const Dh) -> core::ffi::c_long {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).length as core::ffi::c_long }
}

/// `int DH_set_length(DH *dh, long length)` — `dh_lib.c:252-257`.
///
/// A store plus a `dirty_cnt` bump; always answers 1.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_set_length(dh: *mut Dh, length: core::ffi::c_long) -> c_int {
    // SAFETY: `dh` is live per the contract. The authority assigns a `long` to an `int32_t`
    // member, and the narrowing is the authority's own.
    unsafe {
        (*dh).length = length as i32;
        (*dh).dirty_cnt += 1;
    }
    1
}

/// `void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)` —
/// `dh_lib.c:259-265`.
///
/// # Safety
///
/// `dh` is live; each out-parameter is NULL or writable for a `*const BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_key(
    dh: *const Dh,
    pub_key: *mut *const BigNum,
    priv_key: *mut *const BigNum,
) {
    // SAFETY: `dh` is live and each out-parameter is NULL or writable per the contract.
    unsafe {
        if !pub_key.is_null() {
            *pub_key = (*dh).pub_key;
        }
        if !priv_key.is_null() {
            *priv_key = (*dh).priv_key;
        }
    }
}

/// `int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)` — `dh_lib.c:267-280`.
///
/// Each slot is replaced **only when the argument is non-NULL**, and the outgoing value is cleared
/// rather than freed — this is key material. Always answers 1.
///
/// # Safety
///
/// `dh` is live; each argument is NULL or a live `BIGNUM` whose ownership the caller transfers.
#[no_mangle]
pub unsafe extern "C" fn DH_set0_key(
    dh: *mut Dh,
    pub_key: *mut BigNum,
    priv_key: *mut BigNum,
) -> c_int {
    // SAFETY: `dh` is live per the contract; the outgoing values are the object's own.
    unsafe {
        if !pub_key.is_null() {
            BN_clear_free((*dh).pub_key);
            (*dh).pub_key = pub_key;
        }
        if !priv_key.is_null() {
            BN_clear_free((*dh).priv_key);
            (*dh).priv_key = priv_key;
        }

        (*dh).dirty_cnt += 1;
    }
    1
}

/// `const BIGNUM *DH_get0_p(const DH *dh)` — `dh_lib.c:282-285`.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_p(dh: *const Dh) -> *const BigNum {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).params.p }
}

/// `const BIGNUM *DH_get0_q(const DH *dh)` — `dh_lib.c:287-290`.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_q(dh: *const Dh) -> *const BigNum {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).params.q }
}

/// `const BIGNUM *DH_get0_g(const DH *dh)` — `dh_lib.c:292-295`.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_g(dh: *const Dh) -> *const BigNum {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).params.g }
}

/// `const BIGNUM *DH_get0_priv_key(const DH *dh)` — `dh_lib.c:297-300`.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_priv_key(dh: *const Dh) -> *const BigNum {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).priv_key }
}

/// `const BIGNUM *DH_get0_pub_key(const DH *dh)` — `dh_lib.c:302-305`.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_pub_key(dh: *const Dh) -> *const BigNum {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).pub_key }
}

/// `void DH_clear_flags(DH *dh, int flags)` — `dh_lib.c:307-310`.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_clear_flags(dh: *mut Dh, flags: c_int) {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).flags &= !flags };
}

/// `int DH_test_flags(const DH *dh, int flags)` — `dh_lib.c:312-315`.
///
/// Answers the masked word, not a boolean: a caller that passes a multi-bit mask gets the bits
/// that were set. That asymmetry with a `!= 0` test is the authority's.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_test_flags(dh: *const Dh, flags: c_int) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).flags & flags }
}

/// `void DH_set_flags(DH *dh, int flags)` — `dh_lib.c:317-320`.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_set_flags(dh: *mut Dh, flags: c_int) {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).flags |= flags };
}

/// `ENGINE *DH_get0_engine(DH *dh)` — `dh_lib.c:322-327`.
///
/// **NULL for every object this crate can build**, because there is no engine registry to attach
/// one; that is the observable half of the constructor's reduction and `RT-DH` asserts it.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn DH_get0_engine(dh: *mut Dh) -> *mut Engine {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).engine }
}

/// `FFC_PARAMS *ossl_dh_get0_params(DH *dh)` — `dh_lib.c:329-332`. Internal.
///
/// The bridge the key layer, the validator, the provider and 8.6's `DSA_dup_DH` use to reach the
/// embedded parameters. **D333 is when the annotation came off**: its stated reader was "the
/// provider backend/keymgmt", and `crypto/dsa/dsa_lib.c`'s `DSA_dup_DH` — a core-side unit, not a
/// provider one — is the first crate caller, so the allow would now be hiding real dead code
/// rather than marking a boundary (D327's rule, the same reasoning that removed D330's
/// subtree-wide allow in D331). The provider callers of `dh_backend.c` are still later slices, and
/// this accessor's `dh`-shaped half of them is what 8.6's `DSA_dup_DH` stands in for.
///
/// # Safety
///
/// `dh` is a live object. The returned pointer is borrowed from it.
pub(crate) unsafe fn ossl_dh_get0_params(dh: *mut Dh) -> *mut FfcParams {
    // SAFETY: `dh` is live per the contract.
    unsafe { ptr::addr_of_mut!((*dh).params) }
}

/// `int ossl_dh_get0_nid(const DH *dh)` — `dh_lib.c:333-336`. Internal.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider backend/keymgmt units.** It is
/// the read of `params.nid` that `DH_get_nid` (`dh_group_params.c`) wraps with a NULL test.
///
/// # Safety
///
/// `dh` is a live object.
#[allow(dead_code)] // read by the provider backend/keymgmt, which are later slices
pub(crate) unsafe fn ossl_dh_get0_nid(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe { (*dh).params.nid }
}
