//! `crypto/ec/ec_kmeth.c` — the `EC_KEY_METHOD` table and the key constructor that reads it,
//! Phase 8.7.
//!
//! Three hundred and thirty-six lines: one `static const EC_KEY_METHOD openssl_ec_key_method`,
//! one `static const EC_KEY_METHOD *default_ec_key_meth`, nineteen exports and the unit's one
//! internal `ossl_ec_key_new_method_int`. The table is the authority's own "OpenSSL EC_KEY
//! method" and its seven live columns name `ec_key.c`'s `ossl_ec_key_gen`, `ecdh_ossl.c`'s
//! `ossl_ecdh_compute_key` and `ecdsa_ossl.c`'s five `ossl_ecdsa_*` entry points — units that are
//! **not** transcribed here, so the table's columns are *references by crate path* to names this
//! session does not build. That is the correct intermediate state and it is why
//! `ossl_ec_key_new_method_int` reaches `EC_KEY_free` (in `ec_key.c`'s module) rather than a
//! transcription of it.
//!
//! ## What this unit cannot be without, stated as coordinates
//!
//! `ossl_ec_key_new_method_int` is the constructor `EC_KEY_new_method` and `EC_KEY_new` reach,
//! and it is one call away from the whole key layer: `EC_KEY_free` (`ec_key.c`), `ret->meth->init`
//! (`ec_key.c`'s `ossl_ec_key_simple_*`/the table's own), `CRYPTO_new_ex_data`
//! (`crypto/ex_data.c`, landed) and `CRYPTO_NEW_REF` (`internal/refcount.h`, whose fallback arm
//! this profile takes — a plain store of 1). Its `EC_KEY_get_default_method` reader is in this
//! module, so the constructor and the table land together, and `ec_key.c` and this module are
//! one commit by §1 step 7 of the integration plan.
//!
//! ## The `ENGINE` block, and the reduction the crate's RSA layer already records
//!
//! `ossl_ec_key_new_method_int` and `EC_KEY_set_method` each carry an
//! `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` block that calls
//! `ENGINE_init`, `ENGINE_get_default_EC`, `ENGINE_get_EC` and `ENGINE_finish`. `OPENSSL_NO_ENGINE`
//! is not defined on this profile, so the authority compiles the block; this crate has no engine
//! registry and nothing in it can build an `ENGINE`, so the block is **reduced to the one effect
//! it has when the registry is empty** — `ret->engine` is NULL and the method is the default —
//! exactly as `src/rsa/object.rs` records for `rsa_new_intern`. Every one of those four engine
//! calls is named here rather than silently dropped, and the reduction is a recorded one rather
//! than a compiled-out `#ifdef` arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::ec::ecdh_ossl::ossl_ecdh_compute_key;
use crate::ec::ecdsa_ossl::{
    ossl_ecdsa_sign, ossl_ecdsa_sign_setup, ossl_ecdsa_sign_sig, ossl_ecdsa_verify,
    ossl_ecdsa_verify_sig,
};
use crate::ec::key::{ossl_ec_key_gen, EC_KEY_free};
use crate::ec::{
    EcComputeKeyFn, EcKey, EcKeyCopyFn, EcKeyFinishFn, EcKeyInitFn, EcKeyMethod, EcKeySetGroupFn,
    EcKeySetPrivateFn, EcKeySetPublicFn, EcKeySignFn, EcKeySignSetupFn, EcKeySignSigFn,
    EcKeyVerifyFn, EcKeyVerifySigFn, EcPoint, EC_KEY_METHOD_DYNAMIC, POINT_CONVERSION_UNCOMPRESSED,
};
use crate::evp::pkey_asn1::Engine;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{CRYPTO_new_ex_data, CRYPTO_EX_INDEX_EC_KEY};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};

/// The translation-unit coordinate the `OPENSSL_zalloc`/`OPENSSL_strdup`/`OPENSSL_free` sites in
/// this unit are attributed to, as the allocator reports them.
const FILE: *const c_char = c"crypto/ec/ec_kmeth.c".as_ptr();

/// `static const EC_KEY_METHOD openssl_ec_key_method` — `crypto/ec/ec_kmeth.c:24-35`.
///
/// The authority's default key method. Its `name` is a `.rodata` literal, `flags` is 0 (so
/// [`EC_KEY_METHOD_free`] on it is a no-op), and the first six columns are NULL — `init`,
/// `finish`, `copy`, `set_group`, `set_private` and `set_public`. The last seven name the key,
/// ECDH and ECDSA entry points; all seven are **units this session does not transcribe**, so
/// each is a crate-path reference whose definition lands with §1 step 7's `ec_key.c` and step 8's
/// `ecdsa_ossl.c`/`ecdh_ossl.c`. The table is therefore a value with unresolvable columns rather
/// than a table with fabricated `None`s where the authority has a function.
///
/// It is a `static` whose address is taken and never written, exactly like
/// `src/dh/key.rs`'s `dh_ossl`, so it is wrapped to carry the `Sync` bound the raw `name`
/// pointer denies it.
struct StaticEcKeyMethod(core::cell::UnsafeCell<EcKeyMethod>);

// SAFETY: the inner value is fully initialised at compile time and is never written. Every
// consumer reads one field or takes the address; no `&mut` is ever created.
unsafe impl Sync for StaticEcKeyMethod {}

static OPENSSL_EC_KEY_METHOD: StaticEcKeyMethod =
    StaticEcKeyMethod(core::cell::UnsafeCell::new(EcKeyMethod {
        name: c"OpenSSL EC_KEY method".as_ptr(),
        flags: 0,
        init: None,
        finish: None,
        copy: None,
        set_group: None,
        set_private: None,
        set_public: None,
        keygen: Some(ossl_ec_key_gen as EcKeyInitFn),
        compute_key: Some(ossl_ecdh_compute_key as EcComputeKeyFn),
        sign: Some(ossl_ecdsa_sign as EcKeySignFn),
        sign_setup: Some(ossl_ecdsa_sign_setup as EcKeySignSetupFn),
        sign_sig: Some(ossl_ecdsa_sign_sig as EcKeySignSigFn),
        verify: Some(ossl_ecdsa_verify as EcKeyVerifyFn),
        verify_sig: Some(ossl_ecdsa_verify_sig as EcKeyVerifySigFn),
    }));

/// The stable address of the authority's `openssl_ec_key_method`, for the accessors below and
/// for [`DEFAULT_EC_KEY_METHOD`]'s initialiser.
const fn openssl_ec_key_method() -> *const EcKeyMethod {
    OPENSSL_EC_KEY_METHOD.0.get()
}

/// `static const EC_KEY_METHOD *default_ec_key_meth = &openssl_ec_key_method` —
/// `crypto/ec/ec_kmeth.c:37`.
///
/// Modelled as an [`AtomicPtr`] rather than a `static mut`, exactly as `src/dh/key.rs` models
/// `default_DH_method`: the authority's write is unsynchronised, and the crate's option for a
/// process-wide pointer a caller may replace is the atomic. Every access is `Relaxed`, because
/// the authority has no fence.
static DEFAULT_EC_KEY_METHOD: AtomicPtr<EcKeyMethod> =
    AtomicPtr::new(openssl_ec_key_method() as *mut EcKeyMethod);

/// `const EC_KEY_METHOD *EC_KEY_OpenSSL(void)` — `crypto/ec/ec_kmeth.c:39-42`.
///
/// The table's *address* is the answer, so two calls — and a call to [`EC_KEY_get_default_method`]
/// before any [`EC_KEY_set_default_method`] — compare equal.
#[no_mangle]
pub extern "C" fn EC_KEY_OpenSSL() -> *const EcKeyMethod {
    openssl_ec_key_method()
}

/// `const EC_KEY_METHOD *EC_KEY_get_default_method(void)` — `crypto/ec/ec_kmeth.c:44-47`.
#[no_mangle]
pub extern "C" fn EC_KEY_get_default_method() -> *const EcKeyMethod {
    DEFAULT_EC_KEY_METHOD.load(Ordering::Relaxed)
}

/// `void EC_KEY_set_default_method(const EC_KEY_METHOD *meth)` — `crypto/ec/ec_kmeth.c:49-55`.
///
/// A NULL argument **restores** the authority's own table rather than clearing the pointer, so
/// the process-wide default is never NULL.
///
/// # Safety
///
/// `meth` is NULL or points to a live, immutable `EC_KEY_METHOD` that outlives its use as the
/// default.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_default_method(meth: *const EcKeyMethod) {
    let chosen = if meth.is_null() {
        openssl_ec_key_method()
    } else {
        meth
    };
    DEFAULT_EC_KEY_METHOD.store(chosen as *mut EcKeyMethod, Ordering::Relaxed);
}

/// `const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key)` — `crypto/ec/ec_kmeth.c:57-60`.
///
/// # Safety
///
/// `key` is a live `EC_KEY`.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_get_method(key: *const EcKey) -> *const EcKeyMethod {
    // SAFETY: the caller's contract.
    unsafe { (*key).meth }
}

/// `int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth)` — `crypto/ec/ec_kmeth.c:62-78`.
///
/// The outgoing table's `finish` runs before the new table is stored, and the new table's `init`
/// decides the answer: a table with no `init` reports success without touching the key.
///
/// The authority's engine block (`:69-72`) calls `ENGINE_finish(key->engine)` and clears
/// `key->engine`; it is reduced to the clear, for the reason the module documentation gives.
///
/// # Safety
///
/// `key` is live; `meth` is a live, immutable table.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_set_method(key: *mut EcKey, meth: *const EcKeyMethod) -> c_int {
    unsafe {
        // SAFETY: the caller's contract; `finish` is read exactly as the authority reads it.
        let finish = (*key).meth.as_ref().and_then(|m| m.finish);
        if let Some(finish) = finish {
            finish(key);
        }

        // The `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` arm's two statements,
        // reduced to the clear: the crate can build no `ENGINE` to finish.
        (*key).engine = ptr::null_mut();

        (*key).meth = meth;
        if let Some(init) = (*meth).init {
            // SAFETY: the table's own initialiser, handed this object as the authority hands it.
            return init(key);
        }
        1
    }
}

/// `EC_KEY *ossl_ec_key_new_method_int(OSSL_LIB_CTX *libctx, const char *propq,
/// ENGINE *engine)` — `crypto/ec/ec_kmeth.c:80-139`. The unit's one internal.
///
/// The authority's engine argument and its whole engine block are reduced to nothing here (the
/// doc comment on [`EC_KEY_set_method`] and the module documentation give the reason), so
/// `engine` is ignored and `ret->engine` is NULL. On the no-engine path the table comes from
/// [`EC_KEY_get_default_method`], `version` is 1, `conv_form` is
/// [`POINT_CONVERSION_UNCOMPRESSED`], `CRYPTO_new_ex_data` runs against
/// `CRYPTO_EX_INDEX_EC_KEY`, and the table's `init` — when it has one — decides the answer. A
/// failure on any of those paths answers `EC_KEY_free(ret)`, which is `ec_key.c`'s and therefore
/// a reference this session resolves by name.
///
/// `CRYPTO_NEW_REF(&ret->references, 1)` is the header's fallback arm on this profile — a plain
/// store of 1 that cannot fail — so it is a `Relaxed` store and the untaken branch is named in
/// `src/rsa/object.rs` rather than reproduced.
///
/// # Safety
///
/// `engine` is ignored; `libctx` is NULL or a live library context; `propq` is NULL or a
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_key_new_method_int(
    libctx: *mut c_void,
    propq: *const c_char,
    _engine: *mut Engine,
) -> *mut EcKey {
    // SAFETY: `OPENSSL_zalloc` is `CRYPTO_zalloc(.., OPENSSL_FILE, OPENSSL_LINE)`, line 83.
    unsafe {
        let ret = CRYPTO_zalloc(core::mem::size_of::<EcKey>(), FILE, 83).cast::<EcKey>();
        if ret.is_null() {
            return ptr::null_mut();
        }

        // `if (!CRYPTO_NEW_REF(&ret->references, 1))`: the fallback arm's plain, infallible store.
        (*ret).references.store(1, Ordering::Relaxed);

        (*ret).libctx = libctx;
        if !propq.is_null() {
            (*ret).propq = CRYPTO_strdup(propq, FILE, 95);
            if (*ret).propq.is_null() {
                return fail(ret);
            }
        }

        (*ret).meth = EC_KEY_get_default_method();
        // The engine block (`:101-117`) is reduced: `ret->engine` stays NULL and the table is the
        // default one.

        (*ret).version = 1;
        (*ret).conv_form = POINT_CONVERSION_UNCOMPRESSED;

        // `#ifndef FIPS_MODULE`, compiled here.
        if CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_EC_KEY,
            ret.cast(),
            ptr::addr_of_mut!((*ret).ex_data),
        ) == 0
        {
            // SAFETY: a compile-time-constant site (`ec_kmeth.c:125`, ERR_R_CRYPTO_LIB).
            raise_site(&err_sites::EC_KMETH_125);
            return fail(ret);
        }

        if let Some(init) = (*ret).meth.as_ref().and_then(|m| m.init) {
            // SAFETY: the table's own initialiser, handed this object as the authority hands it.
            if init(ret) == 0 {
                // SAFETY: a compile-time-constant site (`ec_kmeth.c:131`, ERR_R_INIT_FAIL).
                raise_site(&err_sites::EC_KMETH_131);
                return fail(ret);
            }
        }
        ret
    }
}

/// The authority's `err:` label — `EC_KEY_free(ret); return NULL;` (`ec_kmeth.c:136-138`).
///
/// # Safety
///
/// `ret` is the object this unit just allocated and has not published.
unsafe fn fail(ret: *mut EcKey) -> *mut EcKey {
    // SAFETY: `ret` is this unit's own object and `EC_KEY_free` releases exactly what is set on
    // it; it is `ec_key.c`'s, so the reference is a named coordinate until step 7 lands.
    unsafe { EC_KEY_free(ret) };
    ptr::null_mut()
}

/// `EC_KEY *EC_KEY_new_method(ENGINE *engine)` — `crypto/ec/ec_kmeth.c:142-145`.
///
/// Inside `#ifndef FIPS_MODULE` and compiled here. The two NULLs are the authority's own: no
/// library context and no property query.
///
/// # Safety
///
/// `engine` is ignored, as [`ossl_ec_key_new_method_int`]'s is.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_new_method(engine: *mut Engine) -> *mut EcKey {
    // SAFETY: this function's own contract.
    unsafe { ossl_ec_key_new_method_int(ptr::null_mut(), ptr::null(), engine) }
}

/// `void *(*)(const void *, size_t, void *, size_t *)` — the authority's `KDF` parameter of
/// [`ECDH_compute_key`] (`ec_kmeth.c:150-151`), an inline function-pointer type rather than a
/// named one.
type EcdhKdfFn = unsafe extern "C" fn(
    input: *const c_void,
    inlen: usize,
    out: *mut c_void,
    outlen: *mut usize,
) -> *mut c_void;

/// `int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *eckey,
/// void *(*KDF)(const void *, size_t, void *, size_t *))` — `crypto/ec/ec_kmeth.c:148-174`.
///
/// The method's `compute_key` writes the shared secret into a fresh buffer; with a NULL `KDF`
/// that buffer is truncated or zero-extended to the caller's `outlen`, and with one the KDF
/// rewrites `outlen` itself. The secure buffer is always cleansed on the success path, and the
/// caller's `outlen > INT_MAX` is refused before any allocation.
///
/// # Safety
///
/// `out` is writable for `outlen` bytes; `pub_key` and `eckey` are live and compatible; `KDF` is
/// NULL or a function that fills `out`.
#[no_mangle]
pub unsafe extern "C" fn ECDH_compute_key(
    out: *mut c_void,
    mut outlen: usize,
    pub_key: *const EcPoint,
    eckey: *const EcKey,
    kdf: Option<EcdhKdfFn>,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut sec: *mut u8 = ptr::null_mut();
        let mut seclen: usize = 0;

        let Some(compute_key) = (*eckey).meth.as_ref().and_then(|m| m.compute_key) else {
            // SAFETY: a compile-time-constant site (`ec_kmeth.c:156`, EC_R_OPERATION_NOT_SUPPORTED).
            raise_site(&err_sites::EC_KMETH_156);
            return 0;
        };
        if outlen > i32::MAX as usize {
            // SAFETY: a compile-time-constant site (`ec_kmeth.c:160`, EC_R_INVALID_OUTPUT_LENGTH).
            raise_site(&err_sites::EC_KMETH_160);
            return 0;
        }
        if compute_key(&mut sec, &mut seclen, pub_key, eckey) == 0 {
            return 0;
        }
        if let Some(kdf) = kdf {
            let _ = kdf(sec.cast(), seclen, out, &mut outlen);
        } else {
            if outlen > seclen {
                outlen = seclen;
            }
            ptr::copy_nonoverlapping(sec, out.cast::<u8>(), outlen);
        }
        // `OPENSSL_clear_free(sec, seclen)`, line 172.
        CRYPTO_clear_free(sec.cast(), seclen, FILE, 172);
        outlen as c_int
    }
}

/// `EC_KEY_METHOD *EC_KEY_METHOD_new(const EC_KEY_METHOD *meth)` — `crypto/ec/ec_kmeth.c:176-186`.
///
/// A NULL argument yields a table of NULLs; a non-NULL one is copied field for field, and either
/// way [`EC_KEY_METHOD_DYNAMIC`] is set so that [`EC_KEY_METHOD_free`] knows the copy is the
/// caller's.
///
/// # Safety
///
/// `meth` is NULL or points to a live, immutable table.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_new(meth: *const EcKeyMethod) -> *mut EcKeyMethod {
    // SAFETY: `OPENSSL_zalloc(sizeof(*meth))`, line 178.
    unsafe {
        let ret =
            CRYPTO_zalloc(core::mem::size_of::<EcKeyMethod>(), FILE, 178).cast::<EcKeyMethod>();
        if ret.is_null() {
            return ptr::null_mut();
        }
        if !meth.is_null() {
            ptr::copy_nonoverlapping(meth, ret, 1);
        }
        (*ret).flags |= EC_KEY_METHOD_DYNAMIC;
        ret
    }
}

/// `void EC_KEY_METHOD_free(EC_KEY_METHOD *meth)` — `crypto/ec/ec_kmeth.c:188-192`.
///
/// The authority's own static table carries `flags == 0`, so freeing it is a no-op; only a table
/// [`EC_KEY_METHOD_new`] produced is released.
///
/// # Safety
///
/// `meth` is a live table.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_free(meth: *mut EcKeyMethod) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*meth).flags & EC_KEY_METHOD_DYNAMIC != 0 {
            // `OPENSSL_free(meth)`, line 191.
            CRYPTO_free(meth.cast(), FILE, 191);
        }
    }
}

/// `void EC_KEY_METHOD_set_init(EC_KEY_METHOD *meth, int (*init)(EC_KEY *),
/// void (*finish)(EC_KEY *), int (*copy)(EC_KEY *, const EC_KEY *),
/// int (*set_group)(EC_KEY *, const EC_GROUP *), int (*set_private)(EC_KEY *, const BIGNUM *),
/// int (*set_public)(EC_KEY *, const EC_POINT *))` — `crypto/ec/ec_kmeth.c:194-210`.
///
/// # Safety
///
/// `meth` is a live, mutable table; every function pointer is NULL or has the type its column
/// declares.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_set_init(
    meth: *mut EcKeyMethod,
    init: Option<EcKeyInitFn>,
    finish: Option<EcKeyFinishFn>,
    copy: Option<EcKeyCopyFn>,
    set_group: Option<EcKeySetGroupFn>,
    set_private: Option<EcKeySetPrivateFn>,
    set_public: Option<EcKeySetPublicFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*meth).init = init;
        (*meth).finish = finish;
        (*meth).copy = copy;
        (*meth).set_group = set_group;
        (*meth).set_private = set_private;
        (*meth).set_public = set_public;
    }
}

/// `void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD *meth, int (*keygen)(EC_KEY *))` —
/// `crypto/ec/ec_kmeth.c:212-216`.
///
/// # Safety
///
/// `meth` is a live, mutable table; `keygen` is NULL or a key generator.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_set_keygen(
    meth: *mut EcKeyMethod,
    keygen: Option<EcKeyInitFn>,
) {
    // SAFETY: the caller's contract.
    unsafe { (*meth).keygen = keygen };
}

/// `void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD *meth, int (*ckey)(unsigned char **,
/// size_t *, const EC_POINT *, const EC_KEY *))` — `crypto/ec/ec_kmeth.c:218-225`.
///
/// # Safety
///
/// `meth` is a live, mutable table; `ckey` is NULL or a shared-secret computation.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_set_compute_key(
    meth: *mut EcKeyMethod,
    ckey: Option<EcComputeKeyFn>,
) {
    // SAFETY: the caller's contract.
    unsafe { (*meth).compute_key = ckey };
}

/// `void EC_KEY_METHOD_set_sign(EC_KEY_METHOD *meth, int (*sign)(int, const unsigned char *, int,
/// unsigned char *, unsigned int *, const BIGNUM *, const BIGNUM *, EC_KEY *),
/// int (*sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **),
/// ECDSA_SIG *(*sign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *))`
/// — `crypto/ec/ec_kmeth.c:227-244`.
///
/// # Safety
///
/// `meth` is a live, mutable table; each function pointer is NULL or has the type its column
/// declares.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_set_sign(
    meth: *mut EcKeyMethod,
    sign: Option<EcKeySignFn>,
    sign_setup: Option<EcKeySignSetupFn>,
    sign_sig: Option<EcKeySignSigFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*meth).sign = sign;
        (*meth).sign_setup = sign_setup;
        (*meth).sign_sig = sign_sig;
    }
}

/// `void EC_KEY_METHOD_set_verify(EC_KEY_METHOD *meth, int (*verify)(int, const unsigned char *,
/// int, const unsigned char *, int, EC_KEY *),
/// int (*verify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *))` —
/// `crypto/ec/ec_kmeth.c:246-257`.
///
/// # Safety
///
/// `meth` is a live, mutable table; each function pointer is NULL or has the type its column
/// declares.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_set_verify(
    meth: *mut EcKeyMethod,
    verify: Option<EcKeyVerifyFn>,
    verify_sig: Option<EcKeyVerifySigFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*meth).verify = verify;
        (*meth).verify_sig = verify_sig;
    }
}

/// `void EC_KEY_METHOD_get_init(const EC_KEY_METHOD *meth, int (**pinit)(EC_KEY *),
/// void (**pfinish)(EC_KEY *), int (**pcopy)(EC_KEY *, const EC_KEY *),
/// int (**pset_group)(EC_KEY *, const EC_GROUP *),
/// int (**pset_private)(EC_KEY *, const BIGNUM *),
/// int (**pset_public)(EC_KEY *, const EC_POINT *))` — `crypto/ec/ec_kmeth.c:259-282`.
///
/// Each out-pointer is optional and is written only when the caller supplies one, which is the
/// authority's own guard and not a convenience.
///
/// # Safety
///
/// `meth` is live; each out-pointer is NULL or points to storage for the column it names.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_get_init(
    meth: *const EcKeyMethod,
    pinit: *mut Option<EcKeyInitFn>,
    pfinish: *mut Option<EcKeyFinishFn>,
    pcopy: *mut Option<EcKeyCopyFn>,
    pset_group: *mut Option<EcKeySetGroupFn>,
    pset_private: *mut Option<EcKeySetPrivateFn>,
    pset_public: *mut Option<EcKeySetPublicFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pinit.is_null() {
            *pinit = (*meth).init;
        }
        if !pfinish.is_null() {
            *pfinish = (*meth).finish;
        }
        if !pcopy.is_null() {
            *pcopy = (*meth).copy;
        }
        if !pset_group.is_null() {
            *pset_group = (*meth).set_group;
        }
        if !pset_private.is_null() {
            *pset_private = (*meth).set_private;
        }
        if !pset_public.is_null() {
            *pset_public = (*meth).set_public;
        }
    }
}

/// `void EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD *meth, int (**pkeygen)(EC_KEY *))` —
/// `crypto/ec/ec_kmeth.c:284-289`.
///
/// # Safety
///
/// `meth` is live; `pkeygen` is NULL or points to storage for a key generator.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_get_keygen(
    meth: *const EcKeyMethod,
    pkeygen: *mut Option<EcKeyInitFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pkeygen.is_null() {
            *pkeygen = (*meth).keygen;
        }
    }
}

/// `void EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD *meth, int (**pck)(unsigned char **,
/// size_t *, const EC_POINT *, const EC_KEY *))` — `crypto/ec/ec_kmeth.c:291-299`.
///
/// # Safety
///
/// `meth` is live; `pck` is NULL or points to storage for a shared-secret computation.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_get_compute_key(
    meth: *const EcKeyMethod,
    pck: *mut Option<EcComputeKeyFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pck.is_null() {
            *pck = (*meth).compute_key;
        }
    }
}

/// `void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth, int (**psign)(int,
/// const unsigned char *, int, unsigned char *, unsigned int *, const BIGNUM *,
/// const BIGNUM *, EC_KEY *), int (**psign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **),
/// ECDSA_SIG *(**psign_sig)(const unsigned char *, int, const BIGNUM *, const BIGNUM *,
/// EC_KEY *))` — `crypto/ec/ec_kmeth.c:301-321`.
///
/// # Safety
///
/// `meth` is live; each out-pointer is NULL or points to storage for the column it names.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_get_sign(
    meth: *const EcKeyMethod,
    psign: *mut Option<EcKeySignFn>,
    psign_setup: *mut Option<EcKeySignSetupFn>,
    psign_sig: *mut Option<EcKeySignSigFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !psign.is_null() {
            *psign = (*meth).sign;
        }
        if !psign_setup.is_null() {
            *psign_setup = (*meth).sign_setup;
        }
        if !psign_sig.is_null() {
            *psign_sig = (*meth).sign_sig;
        }
    }
}

/// `void EC_KEY_METHOD_get_verify(const EC_KEY_METHOD *meth, int (**pverify)(int,
/// const unsigned char *, int, const unsigned char *, int, EC_KEY *),
/// int (**pverify_sig)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *))` —
/// `crypto/ec/ec_kmeth.c:323-336`.
///
/// # Safety
///
/// `meth` is live; each out-pointer is NULL or points to storage for the column it names.
#[no_mangle]
pub unsafe extern "C" fn EC_KEY_METHOD_get_verify(
    meth: *const EcKeyMethod,
    pverify: *mut Option<EcKeyVerifyFn>,
    pverify_sig: *mut Option<EcKeyVerifySigFn>,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !pverify.is_null() {
            *pverify = (*meth).verify;
        }
        if !pverify_sig.is_null() {
            *pverify_sig = (*meth).verify_sig;
        }
    }
}
