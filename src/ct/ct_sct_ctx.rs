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

/// `SCT_CTX *SCT_CTX_new(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/ct/ct_sct_ctx.c:23-40`.
///
/// # Safety
///
/// `libctx` is NULL or a live library context; `propq` is NULL or NUL-terminated.
pub(crate) unsafe fn SCT_CTX_new(libctx: *mut c_void, propq: *const c_char) -> *mut SctCtx {
    let sctx = CRYPTO_zalloc(core::mem::size_of::<SctCtx>(), ptr::null(), 0).cast::<SctCtx>();
    if sctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `sctx` is a fresh zeroed allocation; `libctx` is a pointer value.
    unsafe { (*sctx).libctx = libctx };
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the contract.
        let propq_copy = unsafe { CRYPTO_strdup(propq, ptr::null(), 0) };
        if propq_copy.is_null() {
            // SAFETY: `sctx` is the allocation this call owns.
            unsafe { CRYPTO_free(sctx.cast::<c_void>(), ptr::null(), 0) };
            return ptr::null_mut();
        }
        // SAFETY: `sctx` is live; `propq_copy` is the copy this call owns.
        unsafe { (*sctx).propq = propq_copy };
    }
    sctx
}

/// `void SCT_CTX_free(SCT_CTX *sctx)` — `crypto/ct/ct_sct_ctx.c:42-53`.
///
/// # Safety
///
/// `sctx` is NULL or a live `SCT_CTX` this crate owns and that is not used afterwards.
pub(crate) unsafe fn SCT_CTX_free(sctx: *mut SctCtx) {
    if sctx.is_null() {
        return;
    }
    // SAFETY: `sctx` is live per the contract; each field is NULL or owned.
    unsafe {
        EVP_PKEY_free((*sctx).pkey);
        CRYPTO_free((*sctx).pkeyhash.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sctx).ihash.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sctx).certder.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sctx).preder.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sctx).propq.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(sctx.cast::<c_void>(), ptr::null(), 0);
    }
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
    let mut certder: *mut c_uchar = ptr::null_mut();
    let mut preder: *mut c_uchar = ptr::null_mut();
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
            // SAFETY: `cert` is live; `certder` is an out-slot.
            certderlen = unsafe { i2d_X509(cert, &mut certder) };
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
            // SAFETY: `pretmp` is live; `preder` is an out-slot.
            prederlen = unsafe { i2d_re_X509_tbs(pretmp, &mut preder) };
            if prederlen <= 0 {
                break 'blk;
            }
        }

        // SAFETY: `pretmp` is NULL or the copy this call owns.
        unsafe { X509_free(pretmp) };

        // SAFETY: `sctx` is live; its old buffers are NULL or owned.
        unsafe {
            CRYPTO_free((*sctx).certder.cast::<c_void>(), ptr::null(), 0);
            (*sctx).certder = certder;
            (*sctx).certderlen = certderlen as usize;

            CRYPTO_free((*sctx).preder.cast::<c_void>(), ptr::null(), 0);
            (*sctx).preder = preder;
            (*sctx).prederlen = prederlen as usize;
        }
        ret = 1;
    }

    if ret == 0 {
        // SAFETY: each is NULL or an allocation this call still owns.
        unsafe {
            CRYPTO_free(certder.cast::<c_void>(), ptr::null(), 0);
            CRYPTO_free(preder.cast::<c_void>(), ptr::null(), 0);
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
    let mut der: *mut c_uchar = ptr::null_mut();
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
        // SAFETY: `pkey` is live per the contract; `der` is an out-slot.
        let der_len = unsafe { i2d_X509_PUBKEY(pkey, &mut der) };
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
    // authority's single error path releases; `der` is NULL or the encoder's block.
    unsafe {
        EVP_MD_free(sha256);
        CRYPTO_free(md.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(der.cast::<c_void>(), ptr::null(), 0);
    }
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
