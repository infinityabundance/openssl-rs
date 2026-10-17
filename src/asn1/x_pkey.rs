//! `crypto/asn1/x_pkey.c` — the `X509_PKEY` lifecycle the `X509_INFO` reader fills. Phase 11.7.
//!
//! `crypto/asn1/x_pkey.c` is 46 lines and two exports, `X509_PKEY_new` (`:16`) and
//! `X509_PKEY_free` (`:35`). It is the private-key slot of an `X509_INFO`: `_new` zero-allocates
//! the record and gives it an empty `enc_algor` (`X509_ALGOR_new`) and `enc_pkey`
//! (`ASN1_OCTET_STRING_new`), and `_free` releases those two plus the decrypted `EVP_PKEY`, the
//! owned `key_data` when `key_free` is set, and the record itself.
//!
//! ## Why this 11.7 unit lands with 11.6
//!
//! `PEM_X509_INFO_read_bio_ex` (`crypto/pem/pem_info.c`) classifies a `PRIVATE KEY` block into
//! `xi->x_pkey = X509_PKEY_new()` and `PEM_X509_INFO_write_bio` releases it through
//! `X509_PKEY_free`; both are 11.6's (`docs/PHASE-11-SUBPHASES.md` section 2 row 11.6), while
//! this unit is named in 11.7's row. The reader cannot land without it, so it lands here and is
//! recorded rather than forced into the 11.7 row (section 5).
//!
//! ## The one raise
//!
//! `_new` raises `ERR_LIB_ASN1`/`ERR_R_ASN1_LIB` at `:28` when either of its two allocations
//! fails, which is why `crypto/asn1/x_pkey.c` is added to `gen_err_raise_sites.py`'s covered set
//! and the coordinate `X_PKEY_28` exists. The two `OPENSSL_free` sites are `:44` and `:45`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_new};
use crate::evp::pem_bridge::EvpCipherInfo;
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx, RawCtx};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;

/// `OPENSSL_FILE` at `crypto/asn1/x_pkey.c`'s allocation and free sites.
const FILE: *const c_char = c"crypto/asn1/x_pkey.c".as_ptr();

/// `OPENSSL_zalloc` at `X509_PKEY_new` (`crypto/asn1/x_pkey.c:20`).
const LINE_ZALLOC: c_int = 20;
/// `OPENSSL_free(x->key_data)` at `X509_PKEY_free` (`crypto/asn1/x_pkey.c:44`).
const LINE_FREE_KEY_DATA: c_int = 44;
/// `OPENSSL_free(x)` at `X509_PKEY_free` (`crypto/asn1/x_pkey.c:45`).
const LINE_FREE_RECORD: c_int = 45;

/// `struct private_key_st` — `X509_PKEY`, from `include/openssl/x509.h:372-385`.
///
/// The authority's fields in order, including the embedded `EVP_CIPHER_INFO cipher`.
#[repr(C)]
pub struct X509Pkey {
    /// `int version`.
    pub(crate) version: c_int,
    /// `X509_ALGOR *enc_algor` — the encryption algorithm, allocated by `_new`.
    pub(crate) enc_algor: *mut X509Algor,
    /// `ASN1_OCTET_STRING *enc_pkey` — the encrypted public key, allocated by `_new`.
    pub(crate) enc_pkey: *mut Asn1String,
    /// `EVP_PKEY *dec_pkey` — the decrypted key, or NULL.
    pub(crate) dec_pkey: *mut EvpPkey,
    /// `int key_length`.
    pub(crate) key_length: c_int,
    /// `char *key_data` — an owned buffer when `key_free` is set.
    pub(crate) key_data: *mut c_char,
    /// `int key_free`.
    pub(crate) key_free: c_int,
    /// `EVP_CIPHER_INFO cipher` — the expanded cipher info.
    pub(crate) cipher: EvpCipherInfo,
}

const _: () = {
    assert!(core::mem::size_of::<X509Pkey>() == 80);
    assert!(core::mem::offset_of!(X509Pkey, version) == 0);
    assert!(core::mem::offset_of!(X509Pkey, enc_algor) == 8);
    assert!(core::mem::offset_of!(X509Pkey, enc_pkey) == 16);
    assert!(core::mem::offset_of!(X509Pkey, dec_pkey) == 24);
    assert!(core::mem::offset_of!(X509Pkey, key_length) == 32);
    assert!(core::mem::offset_of!(X509Pkey, key_data) == 40);
    assert!(core::mem::offset_of!(X509Pkey, key_free) == 48);
    assert!(core::mem::offset_of!(X509Pkey, cipher) == 56);
};

/// `X509_PKEY_free`'s member releases, without the record's own `OPENSSL_free` at `:45`.
///
/// (a) The body releases the two constructed members, the decrypted key and (when `key_free` is
/// set) `key_data` at the authority's `:44`, and never the enclosing record, which [`OwnedCtx`]'s
/// `Drop` releases at `:45`; and (b) a zeroed `X509Pkey` is the state `X509_PKEY_new` starts from
/// (NULL pointers, `key_free == 0`, zeroed cipher), every releaser accepts NULL and the `key_free`
/// test is false, so the safe zeroed constructor may run this body.
// SAFETY: the trait's two obligations are established by the body below -- it releases only the
// record's own members (each NULL or owned) and never the block, and the zeroed constructor state
// is the authority's own, for which every release is the NULL no-op.
unsafe impl CtxDestroy for X509Pkey {
    const FILE: *const c_char = FILE;
    const LINE_ALLOC: c_int = LINE_ZALLOC;
    const LINE_FREE: c_int = LINE_FREE_RECORD;

    unsafe fn destroy_body(x: *mut X509Pkey) {
        // SAFETY: `x` is a live context per the trait contract; each pointer is NULL or owned by
        // this record.
        unsafe {
            X509_ALGOR_free((*x).enc_algor);
            ASN1_OCTET_STRING_free((*x).enc_pkey);
            EVP_PKEY_free((*x).dec_pkey);
            if (*x).key_free != 0 {
                CRYPTO_free((*x).key_data.cast::<c_void>(), FILE, LINE_FREE_KEY_DATA);
            }
        }
    }
}

/// `X509_PKEY *X509_PKEY_new(void)` — `crypto/asn1/x_pkey.c:16-33`.
///
/// Zero-allocates the record, then gives it an empty `enc_algor` and `enc_pkey`. Either
/// allocation failing frees the partly built value, raises `ERR_R_ASN1_LIB` (`:27`) and answers
/// NULL.
#[no_mangle]
pub extern "C" fn X509_PKEY_new() -> *mut X509Pkey {
    // The window before the two slots are published is a `RawCtx`: its `Drop` would release the
    // block alone, so a refusal before the record is a valid `X509Pkey` cannot run a destructor.
    let Some(raw) = RawCtx::<X509Pkey>::zalloc() else {
        return ptr::null_mut();
    };
    let ret = raw.as_ptr();
    // SAFETY: `ret` is the zeroed block; its two member slots are written here.
    unsafe {
        (*ret).enc_algor = X509_ALGOR_new();
        (*ret).enc_pkey = ASN1_OCTET_STRING_new();
    }
    // SAFETY: every field is initialised -- the block was zeroed and the two pointer slots are
    // written above -- so it is a valid `X509Pkey` for the destructor, and this handle is its
    // single owner.
    let owned = unsafe { raw.assume_init() };
    // SAFETY: `owned` is live.
    let (algor, pkey) = unsafe { ((*owned.as_ptr()).enc_algor, (*owned.as_ptr()).enc_pkey) };
    if algor.is_null() || pkey.is_null() {
        // The authority's `X509_PKEY_free`: the members acquired so far, then the block, in that
        // order.
        drop(owned);
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X_PKEY_28) };
        return ptr::null_mut();
    }
    owned.into_raw()
}

/// `void X509_PKEY_free(X509_PKEY *x)` — `crypto/asn1/x_pkey.c:35-46`.
///
/// # Safety
/// `x` is NULL or a value `X509_PKEY_new` built (or an equally shaped record) whose four
/// pointer fields are NULL or owned.
#[no_mangle]
pub unsafe extern "C" fn X509_PKEY_free(x: *mut X509Pkey) {
    if x.is_null() {
        return;
    }
    // SAFETY: `x` is NULL or a live record this file allocated and has not released per the
    // contract; the reclaimed handle's `Drop` releases the members (`key_data` at `:44` when
    // `key_free` is set) and then the record itself at `:45`, each exactly once.
    drop(unsafe { OwnedCtx::<X509Pkey>::from_raw(x) });
}
