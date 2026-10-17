//! `crypto/ct/ct_sct_ctx.c` — the SCT verification context. Phase 10.14.15's CT layer.
//!
//! `crypto/ct/ct_sct_ctx.c` is 274 lines and transcribes whole. It owns the `SCT_CTX` structure
//! (`crypto/ct/ct_local.h:87-107`) and its lifecycle and setters. Its four functions are declared in
//! the internal `crypto/ct/ct_local.h`, **not** in `include/openssl/ct.h`, so none of them carries
//! `#[no_mangle]`; the sibling CT units reach them by Rust path.
//!
//! The unit also owns the two extension helpers `ct_x509_get_ext` and `ct_x509_cert_fixup`, and the
//! key hasher `ct_public_key_hash`, all `static` in the authority.
//!
//! The unit raises nothing, so it declares no coordinates.
//!
//! Two authority helpers are spelled inline because the crate does not export them: the macros
//! `X509_set_issuer_name` (`= X509_NAME_set(&x->cert_info.issuer, name)`, `include/crypto/x509.h`)
//! and `X509_get_X509_PUBKEY` (`= x->cert_info.key`). Both are the authority's own expansion, and
//! the `X509`/`X509Cinf` fields are `pub(crate)` and layout-asserted in `src/x509/x_x509.rs`.
//!
//! **Withheld by name**: none.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::owned_str::OwnedStr;
use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{
    NID_authority_key_identifier, NID_ct_precert_poison, NID_ct_precert_scts,
};
use crate::x509::x509_cmp::X509_get_issuer_name;
use crate::x509::x509_ext::{X509_delete_ext, X509_get_ext, X509_get_ext_by_NID};
use crate::x509::x509_v3::{X509_EXTENSION_get_data, X509_EXTENSION_set_data};
use crate::x509::x_exten::X509_EXTENSION_free;
use crate::x509::x_name::X509_NAME_set;
use crate::x509::x_pubkey::{i2d_X509_PUBKEY, X509Pubkey, X509_PUBKEY_get};
use crate::x509::x_x509::{i2d_X509, i2d_re_X509_tbs, X509_dup, X509_free, X509};

/// `SHA256_DIGEST_LENGTH` — `include/openssl/sha.h`, the hash width every CT v1 identifier uses.
const SHA256_DIGEST_LENGTH: usize = 32;

/// `struct sct_ctx_st` — `SCT_CTX`, from `crypto/ct/ct_local.h:87-107`.
#[repr(C)]
pub struct SctCtx {
    /// `EVP_PKEY *pkey` — the log's public key.
    pub(crate) pkey: *mut EvpPkey,
    /// `unsigned char *pkeyhash`.
    pub(crate) pkeyhash: *mut c_uchar,
    /// `size_t pkeyhashlen`.
    pub(crate) pkeyhashlen: usize,
    /// `unsigned char *ihash` — the issuer public key hash for a precert.
    pub(crate) ihash: *mut c_uchar,
    /// `size_t ihashlen`.
    pub(crate) ihashlen: usize,
    /// `unsigned char *certder`.
    pub(crate) certder: *mut c_uchar,
    /// `size_t certderlen`.
    pub(crate) certderlen: usize,
    /// `unsigned char *preder`.
    pub(crate) preder: *mut c_uchar,
    /// `size_t prederlen`.
    pub(crate) prederlen: usize,
    /// `uint64_t epoch_time_in_ms`.
    pub(crate) epoch_time_in_ms: u64,
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq`.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<SctCtx>() == 96);
    assert!(core::mem::offset_of!(SctCtx, pkey) == 0);
    assert!(core::mem::offset_of!(SctCtx, pkeyhash) == 8);
    assert!(core::mem::offset_of!(SctCtx, pkeyhashlen) == 16);
    assert!(core::mem::offset_of!(SctCtx, ihash) == 24);
    assert!(core::mem::offset_of!(SctCtx, ihashlen) == 32);
    assert!(core::mem::offset_of!(SctCtx, certder) == 40);
    assert!(core::mem::offset_of!(SctCtx, certderlen) == 48);
    assert!(core::mem::offset_of!(SctCtx, preder) == 56);
    assert!(core::mem::offset_of!(SctCtx, prederlen) == 64);
    assert!(core::mem::offset_of!(SctCtx, epoch_time_in_ms) == 72);
    assert!(core::mem::offset_of!(SctCtx, libctx) == 80);
    assert!(core::mem::offset_of!(SctCtx, propq) == 88);
};

// ---------------------------------------------------------------------------------------------
// Ownership of the `SCT_CTX` record, its `propq` string and its `DER` scratch blocks
// ---------------------------------------------------------------------------------------------

/// The authority's `SCT_CTX_free` body (`crypto/ct/ct_sct_ctx.c:42-53`), without the block release
/// [`OwnedCtx`]'s `Drop` performs: the key reference, the two key hashes, the certificate and
/// pre-certificate `DER` buffers and the duplicated `propq`.
///
/// # Safety
///
/// An implementer takes on both halves of the contract, because the safe [`OwnedCtx::new_zeroed`]
/// builds the owner and its `Drop` runs the implementer's body through a safe interface:
///
/// * (a) **destructor** -- `destroy_body(ptr)` runs the authority's `SCT_CTX_free` member body
///   **exactly once** for that object; it releases **exactly** the members the object owns (every
///   releaser is the authority's own and accepts the not-yet-set NULL/zero state) and **never**
///   releases the enclosing block, which [`OwnedCtx`]'s `Drop` releases; and
/// * (b) **zero-validity** -- an all-zero block of `Self` is a valid `Self` for which `destroy_body`
///   and every operation the owner performs are sound. This is the obligation the safe
///   [`OwnedCtx::new_zeroed`] leans on: it validates a `CRYPTO_zalloc` block with no caller
///   assertion.
///
/// Breaking (a) lets safe Rust double-release or release the enclosing block; breaking (b) runs
/// `destroy_body` on a value that is not a valid `Self`.
unsafe trait CtxDestroy: Sized {
    /// The authority's `SCT_CTX_free` body, without the block release `Drop` performs.
    ///
    /// # Safety
    ///
    /// `ptr` is a live record this file allocated and has not released.
    unsafe fn destroy_body(ptr: *mut Self);
}

/// An owned `SCT_CTX` record.
///
/// The block keeps the authority's `#[repr(C)]` layout and its exact `CRYPTO_zalloc` size, but its
/// *ownership* is this type: [`Self::new_zeroed`] allocates it, [`Self::from_raw`] takes back the
/// block the C ABI hands to `SCT_CTX_free`, and `Drop` runs the authority's own free body
/// ([`CtxDestroy::destroy_body`]) followed by its single block release. A Rust `Box` would hide both
/// the release and the caller-installed `CRYPTO_set_mem_functions` hook.
struct OwnedCtx<T: CtxDestroy> {
    ptr: ptr::NonNull<T>,
    file: *const c_char,
    line: c_int,
}

impl<T: CtxDestroy> OwnedCtx<T> {
    /// `CRYPTO_zalloc(size_of::<T>(), file, line)`, or `None` when it answers NULL. The zeroed image
    /// is the authority's own starting state -- every owned member is NULL -- so
    /// [`CtxDestroy::destroy_body`] on it is the authority's own all-empty free.
    fn new_zeroed(file: *const c_char, line: c_int) -> Option<OwnedCtx<T>> {
        let raw = CRYPTO_zalloc(core::mem::size_of::<T>(), file, line).cast::<T>();
        ptr::NonNull::new(raw).map(|ptr| OwnedCtx { ptr, file, line })
    }

    /// The block's address, the C ABI's `SCT_CTX *`.
    fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Reclaim the block the C ABI hands to `SCT_CTX_free`, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live record this file allocated that `Drop` has not released.
    unsafe fn from_raw(ptr: *mut T, file: *const c_char, line: c_int) -> Option<OwnedCtx<T>> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedCtx { ptr, file, line })
    }

    /// Give up ownership of the record to the C ABI's answer.
    fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl<T: CtxDestroy> Drop for OwnedCtx<T> {
    /// The record's destructor: the authority's own `SCT_CTX_free` body followed by its single block
    /// release, through the same allocator seam.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle owns and has not released; `destroy_body` is
        // the authority's own free body and this is the block's single release.
        unsafe {
            T::destroy_body(self.ptr.as_ptr());
            CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), self.file, self.line);
        }
    }
}

// SAFETY: (a) holds: `destroy_body` is the authority's `SCT_CTX_free` body minus the block -- the
// key reference, the two key hashes, the certificate and pre-certificate DER buffers and the
// duplicated `propq`, each NULL-tolerant, never the enclosing block. (b) holds: an all-zero
// `SCT_CTX` has every member NULL, so the body is the authority's own all-empty teardown -- what the
// safe `OwnedCtx::new_zeroed` leans on.
unsafe impl CtxDestroy for SctCtx {
    unsafe fn destroy_body(ptr: *mut SctCtx) {
        // SAFETY: `ptr` is a live record per the trait contract; each member is NULL or a block this
        // file owns.
        unsafe {
            EVP_PKEY_free((*ptr).pkey);
            CRYPTO_free((*ptr).pkeyhash.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*ptr).ihash.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*ptr).certder.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*ptr).preder.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free((*ptr).propq.cast::<c_void>(), ptr::null(), 0);
        }
    }
}

/// `SCT_CTX *SCT_CTX_new(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ct/ct_sct_ctx.c:23-40`.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or NUL-terminated.
pub(crate) unsafe fn SCT_CTX_new(libctx: *mut c_void, propq: *const c_char) -> *mut SctCtx {
    let Some(sctx) = OwnedCtx::<SctCtx>::new_zeroed(ptr::null(), 0) else {
        return ptr::null_mut();
    };
    // SAFETY: `sctx.as_ptr()` is a fresh zeroed record; `libctx` is a pointer value.
    unsafe { (*sctx.as_ptr()).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy =
            unsafe { OwnedStr::adopt(CRYPTO_strdup(propq, ptr::null(), 0), ptr::null(), 0) };
        // The authority frees the block alone when the duplicate fails; the handle's `Drop` is that
        // same release over the still-NULL members (its free body's own all-empty free).
        let Some(propq_copy) = propq_copy else {
            return ptr::null_mut();
        };
        // Ownership of the duplicate passes to `sctx`.
        // SAFETY: `sctx` is live.
        unsafe { (*sctx.as_ptr()).propq = propq_copy.into_raw() };
    }
    sctx.into_raw()
}

/// `void SCT_CTX_free(SCT_CTX *sctx)` — `crypto/ct/ct_sct_ctx.c:42-53`.
///
/// # Safety
///
/// `sctx` is NULL or a live `SCT_CTX` this crate owns and that is not used afterwards.
pub(crate) unsafe fn SCT_CTX_free(sctx: *mut SctCtx) {
    // SAFETY: `sctx` is NULL or a live `SCT_CTX` this crate owns and that is not used afterwards;
    // `from_raw` reclaims it and `Drop` runs the authority's own free body and block release.
    drop(unsafe { OwnedCtx::<SctCtx>::from_raw(sctx, ptr::null(), 0) });
}

/// `static int ct_x509_get_ext(X509 *cert, int nid, int *is_duplicated)` —
/// `crypto/ct/ct_sct_ctx.c:60-68`.
///
/// # Safety
///
/// `cert` is a live `X509`; `is_duplicated` is NULL or writable.
unsafe fn ct_x509_get_ext(cert: *mut X509, nid: c_int, is_duplicated: *mut c_int) -> c_int {
    // SAFETY: `cert` is live per the contract.
    let ret = unsafe { X509_get_ext_by_NID(cert, nid, -1) };
    if !is_duplicated.is_null() {
        // SAFETY: `cert` is live; the second lookup continues from `ret`.
        let extra = ret >= 0 && unsafe { X509_get_ext_by_NID(cert, nid, ret) } >= 0;
        // SAFETY: `is_duplicated` is writable per the contract.
        unsafe { *is_duplicated = extra as c_int };
    }
    ret
}

/// `static int ct_x509_cert_fixup(X509 *cert, X509 *presigner)` —
/// `crypto/ct/ct_sct_ctx.c:75-116`.
///
/// # Safety
///
/// `cert` and, when non-NULL, `presigner` are live `X509`s.
unsafe fn ct_x509_cert_fixup(cert: *mut X509, presigner: *mut X509) -> c_int {
    let mut pre_akid_ext_is_dup: c_int = 0;
    let mut cert_akid_ext_is_dup: c_int = 0;

    if presigner.is_null() {
        return 1;
    }

    // SAFETY: `presigner` and `cert` are live per the contract.
    let preidx = unsafe {
        ct_x509_get_ext(
            presigner,
            NID_authority_key_identifier,
            &mut pre_akid_ext_is_dup,
        )
    };
    // SAFETY: `cert` is live per the contract.
    let certidx = unsafe {
        ct_x509_get_ext(
            cert,
            NID_authority_key_identifier,
            &mut cert_akid_ext_is_dup,
        )
    };

    if preidx < -1 || certidx < -1 {
        return 0;
    }
    if pre_akid_ext_is_dup != 0 || cert_akid_ext_is_dup != 0 {
        return 0;
    }
    if preidx >= 0 && certidx == -1 {
        return 0;
    }
    if preidx == -1 && certidx >= 0 {
        return 0;
    }

    // `X509_set_issuer_name(cert, X509_get_issuer_name(presigner))`: the authority's macro pair,
    // which the crate does not export. `X509_set_issuer_name(a, n)` is
    // `X509_NAME_set(&a->cert_info.issuer, n)` (`include/crypto/x509.h:392`).
    // SAFETY: `presigner` is live; the issuer is the embedded `X509_NAME *`.
    let issuer = unsafe { X509_get_issuer_name(presigner) };
    // SAFETY: `cert` is live and `&raw mut (*cert).cert_info.issuer` is its live slot.
    if unsafe { X509_NAME_set(&raw mut (*cert).cert_info.issuer, issuer) } == 0 {
        return 0;
    }

    if preidx != -1 {
        // SAFETY: `presigner` and `cert` are live and the indices are in range.
        let preext = unsafe { X509_get_ext(presigner, preidx) };
        // SAFETY: as above.
        let certext = unsafe { X509_get_ext(cert, certidx) };

        if preext.is_null() || certext.is_null() {
            return 0;
        }
        // SAFETY: `preext` is live per the null check.
        let preextdata = unsafe { X509_EXTENSION_get_data(preext) };
        // SAFETY: `certext` is live and `preextdata` is NULL or a live octet string.
        if preextdata.is_null() || unsafe { X509_EXTENSION_set_data(certext, preextdata) } == 0 {
            return 0;
        }
    }
    1
}

/// `int SCT_CTX_set1_cert(SCT_CTX *sctx, X509 *cert, X509 *presigner)` —
/// `crypto/ct/ct_sct_ctx.c:118-198`.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`; `cert` is a live `X509`; `presigner` is NULL or live.
pub(crate) unsafe fn SCT_CTX_set1_cert(
    sctx: *mut SctCtx,
    cert: *mut X509,
    presigner: *mut X509,
) -> c_int {
    // The two `DER` blocks this call encodes and, on success, installs into `sctx`; on any `break`
    // they still hold the block the authority's `err:` tail releases, so `Drop` is that release.
    let mut certder_owner: Option<OwnedBuf> = None;
    let mut preder_owner: Option<OwnedBuf> = None;
    // The duplicate whose extensions are fixed up; `X509_free` is its single release.
    let mut pretmp: *mut X509 = ptr::null_mut();
    let mut certderlen: c_int = 0;
    let mut prederlen: c_int = 0;
    let mut idx: c_int;
    let mut poison_ext_is_dup: c_int = 0;
    let mut sct_ext_is_dup: c_int = 0;
    let mut ret: c_int = 0;

    'blk: {
        // SAFETY: `cert` is live per the contract.
        let poison_idx =
            unsafe { ct_x509_get_ext(cert, NID_ct_precert_poison, &mut poison_ext_is_dup) };

        if poison_ext_is_dup != 0 {
            break 'blk;
        }

        // If *cert doesn't have a poison extension, it isn't a precert.
        if poison_idx == -1 {
            if !presigner.is_null() {
                break 'blk;
            }
            let mut der: *mut c_uchar = ptr::null_mut();
            // SAFETY: `cert` is live; `der` is an out-slot.
            certderlen = unsafe { i2d_X509(cert, &mut der) };
            // The encoder's block is owned from here; `Drop` is the authority's `err:` release.
            // SAFETY: `der` is NULL or a live block this crate allocated that no one else owns.
            certder_owner = Some(unsafe { OwnedBuf::adopt_plain_nullable(der, ptr::null(), 0) });
            if certderlen < 0 {
                break 'blk;
            }
        }

        // See if cert has a precert SCTs extension.
        // SAFETY: `cert` is live per the contract.
        idx = unsafe { ct_x509_get_ext(cert, NID_ct_precert_scts, &mut sct_ext_is_dup) };
        if sct_ext_is_dup != 0 {
            break 'blk;
        }
        if idx >= 0 && poison_idx >= 0 {
            break 'blk;
        }
        if idx == -1 {
            idx = poison_idx;
        }

        if idx >= 0 {
            // Take a copy so the passed certificate is not modified.
            // SAFETY: `cert` is live per the contract.
            pretmp = unsafe { X509_dup(cert) };
            if pretmp.is_null() {
                break 'blk;
            }
            // SAFETY: `pretmp` is live and `idx` is a valid extension index.
            unsafe { X509_EXTENSION_free(X509_delete_ext(pretmp, idx)) };
            // SAFETY: `pretmp` is live; `presigner` is NULL or live.
            if unsafe { ct_x509_cert_fixup(pretmp, presigner) } == 0 {
                break 'blk;
            }
            let mut der: *mut c_uchar = ptr::null_mut();
            // SAFETY: `pretmp` is live; `der` is an out-slot.
            prederlen = unsafe { i2d_re_X509_tbs(pretmp, &mut der) };
            // SAFETY: `der` is NULL or a live block this crate allocated that no one else owns.
            preder_owner = Some(unsafe { OwnedBuf::adopt_plain_nullable(der, ptr::null(), 0) });
            if prederlen <= 0 {
                break 'blk;
            }
        }

        // SAFETY: `pretmp` is NULL or the copy this call owns; `X509_free` accepts NULL.
        unsafe { X509_free(pretmp) };
        pretmp = ptr::null_mut();

        // The authority's success path releases `sctx`'s old buffers and installs this call's
        // blocks, whose ownership passes to `sctx`.
        // SAFETY: `sctx` is live; its old buffers are NULL or owned blocks; the two owners hold the
        // blocks this call allocated.
        unsafe {
            // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL is the authority's own no-op `free(NULL)`.
            drop(OwnedBuf::adopt_plain_nullable(
                (*sctx).certder,
                ptr::null(),
                0,
            ));
            (*sctx).certder = certder_owner
                .take()
                .map_or(ptr::null_mut(), OwnedBuf::into_raw);
            (*sctx).certderlen = certderlen as usize;

            // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL is the authority's own no-op `free(NULL)`.
            drop(OwnedBuf::adopt_plain_nullable(
                (*sctx).preder,
                ptr::null(),
                0,
            ));
            (*sctx).preder = preder_owner
                .take()
                .map_or(ptr::null_mut(), OwnedBuf::into_raw);
            (*sctx).prederlen = prederlen as usize;
        }
        ret = 1;
    }

    if ret == 0 {
        // The authority's `err:` release order: the certificate `DER`, the pre-certificate `DER`,
        // then the duplicate. The owners were taken on success, so only the failed arms drop here.
        // SAFETY: each owner is NULL-or-this-call's-block; `pretmp` is NULL or this call's copy.
        unsafe {
            drop(certder_owner.take());
            drop(preder_owner.take());
            X509_free(pretmp);
        }
    }
    ret
}

/// `static int ct_public_key_hash(SCT_CTX *sctx, X509_PUBKEY *pkey, unsigned char **hash, size_t
/// *hash_len)` — `crypto/ct/ct_sct_ctx.c:200-242`.
///
/// The authority's single error path frees `md` **unconditionally**, even when `md` aliases a
/// caller-supplied `*hash` reused from a previous call (its `md = NULL` before `err:` covers only
/// the success path). That is reproduced rather than corrected: an error on a second call for the
/// same out-buffer frees the caller's own block, exactly as the authority does. No probe exercise
/// reaches that arm, and correcting it would change which allocation a later `SCT_CTX_free`
/// releases.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`; `pkey` is a live `X509_PUBKEY`; `hash` and `hash_len` are writable.
unsafe fn ct_public_key_hash(
    sctx: *mut SctCtx,
    pkey: *mut X509Pubkey,
    hash: *mut *mut c_uchar,
    hash_len: *mut usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut md: *mut c_uchar = ptr::null_mut();
    // The encoder's `DER` block, owned from the moment `i2d_X509_PUBKEY` answers it; `Drop` is the
    // authority's own error-tail release.
    let mut der_owner: Option<OwnedBuf> = None;
    let mut md_len: c_uint = 0;

    // SAFETY: `sctx` is live per the contract.
    let sha256: *mut EvpMd =
        unsafe { EVP_MD_fetch((*sctx).libctx, c"SHA2-256".as_ptr(), (*sctx).propq) };

    'blk: {
        if sha256.is_null() {
            break 'blk;
        }

        // Reuse the existing buffer when it is large enough.
        // SAFETY: `hash` and `hash_len` are writable per the contract.
        unsafe {
            if !(*hash).is_null() && *hash_len >= SHA256_DIGEST_LENGTH {
                md = *hash;
            } else {
                md = CRYPTO_malloc(SHA256_DIGEST_LENGTH, ptr::null(), 0).cast::<c_uchar>();
                if md.is_null() {
                    break 'blk;
                }
            }
        }

        // Calculate the key hash.
        let mut der: *mut c_uchar = ptr::null_mut();
        // SAFETY: `pkey` is live per the contract; `der` is an out-slot.
        let der_len = unsafe { i2d_X509_PUBKEY(pkey, &mut der) };
        // SAFETY: `der` is NULL or a live block this crate allocated that no one else owns.
        der_owner = Some(unsafe { OwnedBuf::adopt_plain_nullable(der, ptr::null(), 0) });
        if der_len <= 0 {
            break 'blk;
        }

        // SAFETY: `der` is readable for `der_len` bytes; `md` is writable for the digest.
        if unsafe {
            EVP_Digest(
                der.cast::<c_void>(),
                der_len as usize,
                md,
                &mut md_len,
                sha256,
                ptr::null_mut(),
            )
        } == 0
        {
            break 'blk;
        }

        // SAFETY: `hash` and `hash_len` are writable per the contract.
        unsafe {
            if md != *hash {
                CRYPTO_free((*hash).cast::<c_void>(), ptr::null(), 0);
                *hash = md;
                *hash_len = SHA256_DIGEST_LENGTH;
            }
        }
        md = ptr::null_mut();
        ret = 1;
    }

    // SAFETY: `sha256` is NULL or the fetched digest this call owns; `md` is NULL or the block the
    // authority's single error path releases.
    unsafe {
        EVP_MD_free(sha256);
        CRYPTO_free(md.cast::<c_void>(), ptr::null(), 0);
    }
    // `der_owner`'s `Drop` is the authority's own `OPENSSL_free(der)`, after `md` as the authority
    // orders; it is empty on the paths that never reached the encoder.
    drop(der_owner);
    ret
}

/// `int SCT_CTX_set1_issuer(SCT_CTX *sctx, const X509 *issuer)` —
/// `crypto/ct/ct_sct_ctx.c:244-247`.
///
/// An internal convenience the authority declares in `crypto/ct/ct_local.h:148` but no CT unit in
/// this directory calls; it is transcribed whole and kept, marked allowed-dead until a caller
/// outside the nine units reaches it.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`; `issuer` is a live `X509`.
#[allow(dead_code)]
pub(crate) unsafe fn SCT_CTX_set1_issuer(sctx: *mut SctCtx, issuer: *const X509) -> c_int {
    // `X509_get_X509_PUBKEY(issuer)` is the authority's macro, `issuer->cert_info.key`.
    // SAFETY: `issuer` is live per the contract; the key field is the embedded `X509_PUBKEY *`.
    let pubkey = unsafe { (*issuer).cert_info.key };
    // SAFETY: `sctx` and `pubkey` are live per the contract.
    unsafe { SCT_CTX_set1_issuer_pubkey(sctx, pubkey) }
}

/// `int SCT_CTX_set1_issuer_pubkey(SCT_CTX *sctx, X509_PUBKEY *pubkey)` —
/// `crypto/ct/ct_sct_ctx.c:249-252`.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`; `pubkey` is a live `X509_PUBKEY`.
pub(crate) unsafe fn SCT_CTX_set1_issuer_pubkey(
    sctx: *mut SctCtx,
    pubkey: *mut X509Pubkey,
) -> c_int {
    // SAFETY: `sctx` and `pubkey` are live per the contract.
    unsafe {
        ct_public_key_hash(
            sctx,
            pubkey,
            &raw mut (*sctx).ihash,
            &raw mut (*sctx).ihashlen,
        )
    }
}

/// `int SCT_CTX_set1_pubkey(SCT_CTX *sctx, X509_PUBKEY *pubkey)` —
/// `crypto/ct/ct_sct_ctx.c:254-269`.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`; `pubkey` is a live `X509_PUBKEY`.
pub(crate) unsafe fn SCT_CTX_set1_pubkey(sctx: *mut SctCtx, pubkey: *mut X509Pubkey) -> c_int {
    // SAFETY: `pubkey` is live per the contract.
    let pkey = unsafe { X509_PUBKEY_get(pubkey) };
    // `X509_PUBKEY_get` stores no error; it returns NULL when the key cannot be decoded.
    if pkey.is_null() {
        return 0;
    }

    // SAFETY: `sctx` and `pubkey` are live; the out-slots are `sctx`'s own fields.
    if unsafe {
        ct_public_key_hash(
            sctx,
            pubkey,
            &raw mut (*sctx).pkeyhash,
            &raw mut (*sctx).pkeyhashlen,
        )
    } == 0
    {
        // SAFETY: `pkey` is the reference this call took.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }

    // SAFETY: `sctx` is live; its old `pkey` is NULL or owned; `pkey` is this call's reference.
    unsafe {
        EVP_PKEY_free((*sctx).pkey);
        (*sctx).pkey = pkey;
    }
    1
}

/// `void SCT_CTX_set_time(SCT_CTX *sctx, uint64_t time_in_ms)` —
/// `crypto/ct/ct_sct_ctx.c:271-274`.
///
/// # Safety
///
/// `sctx` is a live `SCT_CTX`.
pub(crate) unsafe fn SCT_CTX_set_time(sctx: *mut SctCtx, time_in_ms: u64) {
    // SAFETY: `sctx` is live per the contract.
    unsafe { (*sctx).epoch_time_in_ms = time_in_ms };
}
