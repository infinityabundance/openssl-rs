//! `crypto/ec/ecx_key.c` — the `ECX_KEY` object and the X25519/X448 agreement, Phase 8.7.
//!
//! One hundred and sixty-six lines, six non-static functions: `ossl_ecx_key_new`,
//! `ossl_ecx_key_free`, `ossl_ecx_key_set0_libctx`, `ossl_ecx_key_up_ref`,
//! `ossl_ecx_key_allocate_privkey` and `ossl_ecx_compute_key`. The unit is the object the four
//! ECX `EVP_PKEY` methods share, and its closure is the two curve units D370 and D371 landed:
//! [`ossl_ecx_compute_key`] is the only caller of [`crate::ec::curve25519::ossl_x25519`] and
//! [`crate::ec::curve448::ossl_x448`] outside their own modules.
//!
//! ## Two representation differences, both recorded rather than smoothed
//!
//! * `unsigned int haspubkey : 1` is a one-bit field in the authority. Rust has no bitfields, so
//!   [`EcxKey::haspubkey`] is the storage unit and every writer stores 0 or 1; nothing outside
//!   this crate reads the struct as C, and the four methods read the field through the
//!   accessors here. The **size** of the object therefore differs from the authority's by the
//!   padding a one-bit field saves; there is no court that measures `sizeof(ECX_KEY)` and none
//!   is claimed.
//! * `OPENSSL_PEDANTIC_ZEROIZATION` is undefined in this profile, so the authority's
//!   `OPENSSL_cleanse(&key->pubkey, ...)` in `ossl_ecx_key_free` is not compiled and is not
//!   here. The private scalar is still released through
//!   [`crate::runtime::secure::CRYPTO_secure_clear_free`], exactly as the C does.
//!
//! ## Where the raises come from
//!
//! The unit raises, so it joins `gen_err_raise_sites.py`'s `COVERED_FILES` (stem `ECX_KEY`, seven
//! sites). Five are on the portable path and are referenced below; the two inside the
//! `#ifdef S390X_EC_ASM` arms are generated but not compiled on this profile, like every other
//! unbuilt arm the generator still records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{fence, AtomicI32, Ordering};

use crate::ec::curve25519::ossl_x25519;
use crate::ec::curve448::ossl_x448;
use crate::runtime::bio::owned::CtxDestroy;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_zalloc};

const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ecx_key.c".as_ptr();

/// `X25519_KEYLEN` — `include/crypto/ecx.h:26`.
pub(crate) const X25519_KEYLEN: usize = 32;
/// `X448_KEYLEN` — `include/crypto/ecx.h:27`.
pub(crate) const X448_KEYLEN: usize = 56;
/// `ED25519_KEYLEN` — `include/crypto/ecx.h:28`.
pub(crate) const ED25519_KEYLEN: usize = 32;
/// `ED448_KEYLEN` — `include/crypto/ecx.h:29`.
pub(crate) const ED448_KEYLEN: usize = 57;
/// `MAX_KEYLEN` — `include/crypto/ecx.h:31`.
pub(crate) const MAX_KEYLEN: usize = ED448_KEYLEN;

/// `ECX_KEY_TYPE_X25519` — `include/crypto/ecx.h:45`.
pub(crate) const ECX_KEY_TYPE_X25519: c_int = 0;
/// `ECX_KEY_TYPE_X448` — `include/crypto/ecx.h:46`.
pub(crate) const ECX_KEY_TYPE_X448: c_int = 1;
/// `ECX_KEY_TYPE_ED25519` — `include/crypto/ecx.h:47`.
pub(crate) const ECX_KEY_TYPE_ED25519: c_int = 2;
/// `ECX_KEY_TYPE_ED448` — `include/crypto/ecx.h:48`.
pub(crate) const ECX_KEY_TYPE_ED448: c_int = 3;

/// `struct ecx_key_st` — `include/crypto/ecx.h:58`.
///
/// `haspubkey` models the authority's one-bit field as its storage unit (see the module
/// documentation); every writer stores 0 or 1.
#[repr(C)]
pub struct EcxKey {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
    /// `unsigned int haspubkey : 1` — modelled as its storage unit; see the module docs.
    pub(crate) haspubkey: c_uint,
    /// `unsigned char pubkey[MAX_KEYLEN]`.
    pub(crate) pubkey: [u8; MAX_KEYLEN],
    /// `unsigned char *privkey` — a secure allocation of `keylen` bytes.
    pub(crate) privkey: *mut u8,
    /// `size_t keylen`.
    pub(crate) keylen: usize,
    /// `ECX_KEY_TYPE type`.
    pub(crate) type_: c_int,
    /// `CRYPTO_REF_COUNT references` — `_Atomic int` on this profile.
    pub(crate) references: AtomicI32,
}

// ---------------------------------------------------------------------------------------------
// Ownership of the ECX_KEY object
// ---------------------------------------------------------------------------------------------

// SAFETY: (a) holds: `destroy_body` is `ossl_ecx_key_free` minus the block -- the `propq`
// duplicate and the secure private scalar (cleansed by `CRYPTO_secure_clear_free`), each
// NULL-tolerant, never the enclosing block. (b) holds: `EcxKey` is a `#[repr(C)]` record of raw
// pointers, integers, a byte array and an atomic, so an all-zero block is a valid `EcxKey`, and
// `destroy_body` is sound on it (`CRYPTO_free(NULL)` and `CRYPTO_secure_clear_free(NULL, 0, ...)`).
unsafe impl CtxDestroy for EcxKey {
    const LINE_FREE: c_int = 83;

    unsafe fn destroy_body(ptr: *mut EcxKey) {
        // SAFETY: `ptr` is a live `ECX_KEY` per the trait contract; `propq` is NULL or this unit's
        // own `CRYPTO_strdup` block and `privkey` NULL or a `CRYPTO_secure_zalloc` block.
        unsafe {
            // `OPENSSL_free(key->propq)`, line 77.
            CRYPTO_free((*ptr).propq.cast(), FILE, 77);
            // `OPENSSL_PEDANTIC_ZEROIZATION` is undefined, so the pubkey cleanse is not compiled.
            // `OPENSSL_secure_clear_free(key->privkey, key->keylen)`, line 81.
            CRYPTO_secure_clear_free((*ptr).privkey.cast(), (*ptr).keylen, FILE, 81);
        }
    }
}

/// An owned, fully constructed `ECX_KEY` block.
///
/// The block keeps the authority's `#[repr(C)]` layout, its `CRYPTO_zalloc` size/`file` and its
/// stable address (the C ABI hands it out and takes it back), but its *ownership* is this type:
/// [`Self::into_raw`] hands it out and [`Self::from_raw`] reclaims it so `Drop` runs the
/// authority's own destructor body ([`CtxDestroy::destroy_body`]) followed by its single block
/// release at `ossl_ecx_key_free`'s own site. A Rust `Box` would hide both releases from a
/// caller-installed `CRYPTO_set_mem_functions` hook.
struct OwnedCtx<T: CtxDestroy> {
    ptr: ptr::NonNull<T>,
}

impl<T: CtxDestroy> OwnedCtx<T> {
    /// Give up ownership of the block to the C caller's context pointer.
    fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim a block a previous `into_raw` handed to the C caller, for release by `Drop`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live block a previous `into_raw` gave up and `Drop` has not released.
    unsafe fn from_raw(ptr: *mut T) -> Option<OwnedCtx<T>> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedCtx { ptr })
    }
}

impl<T: CtxDestroy> Drop for OwnedCtx<T> {
    /// The object's destructor: the authority's own free body ([`CtxDestroy::destroy_body`])
    /// followed by its single block release, through the same allocator seam and the authority's own
    /// site.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `into_raw`/`from_raw` handed out and this is its single
        // release; `Drop` runs once, and `destroy_body` is the authority's own free body.
        unsafe {
            T::destroy_body(self.ptr.as_ptr());
            CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), FILE, T::LINE_FREE);
        }
    }
}

/// An owned `ECX_KEY` block still under construction.
///
/// `ossl_ecx_key_new` allocates the block and fills its fields one at a time; until `assume_init`
/// the block is not yet a valid `ECX_KEY` and its release is the block alone — the authority's own
/// `OPENSSL_free(ret)` at its `:60` error arm — so the destructor ([`CtxDestroy::destroy_body`])
/// over fields that may not be set must not run. [`Self::assume_init`] closes the window.
struct RawEcxKey {
    ptr: ptr::NonNull<EcxKey>,
}

impl RawEcxKey {
    /// `CRYPTO_zalloc(sizeof(*ret), FILE, 23)`, or `None` when the allocator answers NULL.
    fn zalloc() -> Option<RawEcxKey> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<EcxKey>()` bytes, exactly `ECX_KEY`'s layout.
        let raw = CRYPTO_zalloc(core::mem::size_of::<EcxKey>(), FILE, 23).cast::<EcxKey>();
        ptr::NonNull::new(raw).map(|ptr| RawEcxKey { ptr })
    }

    /// The writable start of the block, for the field writes that construct the object.
    fn as_ptr(&self) -> *mut EcxKey {
        self.ptr.as_ptr()
    }

    /// The validated transition: the block now holds a fully initialised, valid `ECX_KEY`.
    ///
    /// # Safety
    /// Every field [`CtxDestroy::destroy_body`] reads has been written, so the block is a valid
    /// `ECX_KEY`, and no other owner will release it: the returned handle's `Drop` is the block's
    /// single release.
    unsafe fn assume_init(self) -> OwnedCtx<EcxKey> {
        let ptr = self.ptr;
        core::mem::forget(self);
        OwnedCtx { ptr }
    }
}

impl Drop for RawEcxKey {
    /// The authority's `ossl_ecx_key_new` error-arm release (`:60`): the block alone. The `:57`
    /// `OPENSSL_free(propq)` is over the NULL the failed `strdup` returned, which the allocator
    /// seam ignores, so the block release is the whole observable release.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `zalloc` allocated and has not been handed out; its
        // single release is the authority's own plain `CRYPTO_free` at the error arm.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), FILE, 60) };
    }
}

/// `ECX_KEY *ossl_ecx_key_new(OSSL_LIB_CTX *libctx, ECX_KEY_TYPE type, int haspubkey,
/// const char *propq)` — `crypto/ec/ecx_key.c:20`.
///
/// # Safety
/// `libctx` is NULL or a live library context; `propq` is NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_new(
    libctx: *mut c_void,
    type_: c_int,
    haspubkey: c_int,
    propq: *const c_char,
) -> *mut EcxKey {
    let raw = match RawEcxKey::zalloc() {
        Some(raw) => raw,
        None => return ptr::null_mut(),
    };
    let ret = raw.as_ptr();

    // SAFETY: `ret` is this call's own freshly zeroed block; each field write leaves a valid value.
    unsafe {
        (*ret).libctx = libctx;
        (*ret).haspubkey = haspubkey as c_uint;
        (*ret).keylen = match type_ {
            ECX_KEY_TYPE_X25519 => X25519_KEYLEN,
            ECX_KEY_TYPE_X448 => X448_KEYLEN,
            ECX_KEY_TYPE_ED25519 => ED25519_KEYLEN,
            ECX_KEY_TYPE_ED448 => ED448_KEYLEN,
            // The authority's `switch` has no `default`, so an out-of-range type leaves
            // `keylen` at the zero `OPENSSL_zalloc` gave it.
            _ => 0,
        };
        (*ret).type_ = type_;

        // `CRYPTO_NEW_REF(&ret->references, 1)` — an atomic store of 1 on this profile.
        (*ret).references = AtomicI32::new(1);
    }

    if !propq.is_null() {
        // `OPENSSL_strdup(propq)`, line 50.
        // SAFETY: `propq` is a NUL-terminated string per the contract, and this crate's
        // `CRYPTO_strdup` dereferences nothing else the caller owns.
        let propq_dup = unsafe { CRYPTO_strdup(propq, FILE, 50) };
        if propq_dup.is_null() {
            // `CRYPTO_FREE_REF` is empty on this profile, so `raw`'s `Drop` is the authority's
            // whole error-arm release (the NULL `propq` free at `:57` is unobservable).
            return ptr::null_mut();
        }
        // SAFETY: `ret` is this frame's own live object.
        unsafe { (*ret).propq = propq_dup };
    }

    // SAFETY: every field `destroy_body` reads is now written, so the block is a valid `ECX_KEY`,
    // and `raw` holds its only ownership; `into_raw` hands it to the C caller.
    unsafe { raw.assume_init().into_raw() }
}

/// `void ossl_ecx_key_free(ECX_KEY *key)` — `crypto/ec/ecx_key.c:64`.
///
/// # Safety
/// `key` is NULL or a live object, and must not be used again after this call unless a
/// reference remains.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_free(key: *mut EcxKey) {
    if key.is_null() {
        return;
    }

    // `CRYPTO_DOWN_REF(&key->references, &i)`.
    // SAFETY: `key` is live per the contract.
    let i = unsafe { (*key).references.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if i == 0 {
        fence(Ordering::Acquire);
    }
    if i > 0 {
        return;
    }
    // `REF_ASSERT_ISNT(i < 0)` and `REF_PRINT_COUNT` are empty under `NDEBUG`.

    // SAFETY: `key` is live, this is its last reference, and `OwnedCtx`'s `Drop` runs the
    // authority's own member release (`:77`, `:81`) followed by the block release (`:83`).
    let _owner = unsafe { OwnedCtx::from_raw(key) };
}

/// `void ossl_ecx_key_set0_libctx(ECX_KEY *key, OSSL_LIB_CTX *libctx)` —
/// `crypto/ec/ecx_key.c:86`.
///
/// # Safety
/// `key` is live; `libctx` is NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_set0_libctx(key: *mut EcxKey, libctx: *mut c_void) {
    // SAFETY: `key` is live per the contract.
    unsafe { (*key).libctx = libctx };
}

/// `int ossl_ecx_key_up_ref(ECX_KEY *key)` — `crypto/ec/ecx_key.c:91`.
///
/// # Safety
/// `key` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_up_ref(key: *mut EcxKey) -> c_int {
    // `CRYPTO_UP_REF` is a relaxed fetch-add, and the answer is the *new* count.
    // SAFETY: `key` is live per the contract.
    let i = unsafe { (*key).references.fetch_add(1, Ordering::Relaxed) }.wrapping_add(1);
    if i <= 0 {
        return 0;
    }
    // `REF_ASSERT_ISNT(i < 2)` is empty under `NDEBUG`.
    c_int::from(i > 1)
}

/// `unsigned char *ossl_ecx_key_allocate_privkey(ECX_KEY *key)` —
/// `crypto/ec/ecx_key.c:103`.
///
/// # Safety
/// `key` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_allocate_privkey(key: *mut EcxKey) -> *mut u8 {
    // `OPENSSL_secure_zalloc(key->keylen)`, line 105.
    // SAFETY: `key` is live per the contract.
    let p = unsafe { CRYPTO_secure_zalloc((*key).keylen, FILE, 105) }.cast::<u8>();
    // SAFETY: `key` is live.
    unsafe { (*key).privkey = p };
    // SAFETY: `key` is live.
    unsafe { (*key).privkey }
}

/// `int ossl_ecx_compute_key(ECX_KEY *peer, ECX_KEY *priv, size_t keylen,
/// unsigned char *secret, size_t *secretlen, size_t outlen)` — `crypto/ec/ecx_key.c:110`.
///
/// The `#ifdef S390X_EC_ASM` arms are not compiled on this profile, so the two
/// `FAILED_DURING_DERIVATION` raises inside them are not reachable and are not transcribed;
/// the portable pair is.
///
/// # Safety
/// `peer`/`priv` are NULL or live; `secret` is NULL or writable for the returned length;
/// `secretlen` is writable.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_compute_key(
    peer: *mut EcxKey,
    priv_: *mut EcxKey,
    keylen: usize,
    secret: *mut u8,
    secretlen: *mut usize,
    outlen: usize,
) -> c_int {
    // SAFETY: each pointer is NULL or live per the contract; `privkey` is read only when the
    // object is non-NULL.
    unsafe {
        if priv_.is_null() || (*priv_).privkey.is_null() || peer.is_null() {
            // SAFETY: a compile-time-constant site (`ecx_key.c:116`, PROV_R_MISSING_KEY).
            raise_site(&err_sites::ECX_KEY_116);
            return 0;
        }

        if !(keylen == X25519_KEYLEN || keylen == X448_KEYLEN) {
            // SAFETY: a compile-time-constant site (`ecx_key.c:122`, PROV_R_INVALID_KEY_LENGTH).
            raise_site(&err_sites::ECX_KEY_122);
            return 0;
        }

        if secret.is_null() {
            *secretlen = keylen;
            return 1;
        }
        if outlen < keylen {
            // SAFETY: a compile-time-constant site (`ecx_key.c:131`, PROV_R_OUTPUT_BUFFER_TOO_SMALL).
            raise_site(&err_sites::ECX_KEY_131);
            return 0;
        }

        if keylen == X25519_KEYLEN {
            if ossl_x25519(secret, (*priv_).privkey, (*peer).pubkey.as_ptr()) == 0 {
                // SAFETY: a compile-time-constant site (`ecx_key.c:146`, PROV_R_FAILED_DURING_DERIVATION).
                raise_site(&err_sites::ECX_KEY_146);
                return 0;
            }
        } else if ossl_x448(secret, (*priv_).privkey, (*peer).pubkey.as_ptr()) == 0 {
            // SAFETY: a compile-time-constant site (`ecx_key.c:160`, PROV_R_FAILED_DURING_DERIVATION).
            raise_site(&err_sites::ECX_KEY_160);
            return 0;
        }
        *secretlen = keylen;
    }
    1
}
