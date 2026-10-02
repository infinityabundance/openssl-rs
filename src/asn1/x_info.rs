//! `crypto/asn1/x_info.c` — the `X509_INFO` lifecycle the PEM bundle reader uses. Phase 11.7.
//!
//! `crypto/asn1/x_info.c` is 37 lines and two exports, `X509_INFO_new` (`:16`) and
//! `X509_INFO_free` (`:27`). It is the record `crypto/pem/pem_info.c`'s bundle reader fills: one
//! certificate slot, one CRL slot, one private-key slot and the encrypted-data scratch the
//! writer reads back. `_new` is a single zero-allocation, so every slot starts NULL and every
//! scalar zero; `_free` releases the three owned objects and the scratch buffer.
//!
//! ## Why this 11.7 unit lands with 11.6
//!
//! `PEM_X509_INFO_read[_bio]_ex` and `PEM_X509_INFO_write_bio` (`crypto/pem/pem_info.c`) are
//! 11.6's, and they allocate `X509_INFO_new()`, push the records onto a `STACK_OF(X509_INFO)`
//! and release them through `X509_INFO_free` (`pem_info.c:76`, `:100`, `:194`, `:200-205`). The
//! 11.6 slice cannot land its five names without this item, so it lands here and is recorded
//! rather than forced into 11.7's row (`docs/PHASE-11-SUBPHASES.md` section 5).
//!
//! ## The two free lines are `CRYPTO_free`, and there is no raise
//!
//! `X509_INFO_free`'s `OPENSSL_free` sites are `:35` (the scratch buffer) and `:36` (the
//! record). The unit raises nothing, so `crypto/asn1/x_info.c` is deliberately absent from
//! `gen_err_raise_sites.py`'s covered set, for the reason `x_sig.c` is: an entry for a file that
//! can never raise would read as coverage that does not exist.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::x_pkey::{X509Pkey, X509_PKEY_free};
use crate::evp::pem_bridge::EvpCipherInfo;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::x509::x_crl::{X509Crl, X509_CRL_free};
use crate::x509::x_x509::{X509_free, X509};

/// `OPENSSL_FILE` at `crypto/asn1/x_info.c`'s allocation and free sites.
const FILE: *const c_char = c"crypto/asn1/x_info.c".as_ptr();

/// `OPENSSL_zalloc` at `X509_INFO_new` (`crypto/asn1/x_info.c:20`).
const LINE_ZALLOC: c_int = 20;
/// `OPENSSL_free(x->enc_data)` at `X509_INFO_free` (`crypto/asn1/x_info.c:35`).
const LINE_FREE_DATA: c_int = 35;
/// `OPENSSL_free(x)` at `X509_INFO_free` (`crypto/asn1/x_info.c:36`).
const LINE_FREE_RECORD: c_int = 36;

/// `struct X509_info_st` — `X509_INFO`, from `include/openssl/x509.h:387-394`.
///
/// The authority's fields in order: the certificate, the CRL, the private key and the encrypted
/// data the writer replays.
#[repr(C)]
pub struct X509Info {
    /// `X509 *x509` — a certificate block, or NULL.
    pub(crate) x509: *mut X509,
    /// `X509_CRL *crl` — a CRL block, or NULL.
    pub(crate) crl: *mut X509Crl,
    /// `X509_PKEY *x_pkey` — a private-key block, or NULL.
    pub(crate) x_pkey: *mut X509Pkey,
    /// `EVP_CIPHER_INFO enc_cipher` — the cipher info of a not-yet-decrypted key.
    pub(crate) enc_cipher: EvpCipherInfo,
    /// `int enc_len` — how many bytes `enc_data` holds.
    pub(crate) enc_len: c_int,
    /// `char *enc_data` — an owned encrypted-key buffer, or NULL.
    pub(crate) enc_data: *mut c_char,
}

const _: () = {
    assert!(core::mem::size_of::<X509Info>() == 64);
    assert!(core::mem::offset_of!(X509Info, x509) == 0);
    assert!(core::mem::offset_of!(X509Info, crl) == 8);
    assert!(core::mem::offset_of!(X509Info, x_pkey) == 16);
    assert!(core::mem::offset_of!(X509Info, enc_cipher) == 24);
    assert!(core::mem::offset_of!(X509Info, enc_len) == 48);
    assert!(core::mem::offset_of!(X509Info, enc_data) == 56);
};

/// `X509_INFO *X509_INFO_new(void)` — `crypto/asn1/x_info.c:16-25`.
///
/// A zero-allocation: every slot is NULL and every scalar zero, so the reader can test
/// `xi->x509 != NULL` and the writer can test `xi->enc_data != NULL` on a fresh value.
#[no_mangle]
pub extern "C" fn X509_INFO_new() -> *mut X509Info {
    // SAFETY: the allocator's contract; the file/line are the authority's own.
    CRYPTO_zalloc(core::mem::size_of::<X509Info>(), FILE, LINE_ZALLOC).cast::<X509Info>()
}

/// `void X509_INFO_free(X509_INFO *x)` — `crypto/asn1/x_info.c:27-37`.
///
/// # Safety
/// `x` is NULL or a value `X509_INFO_new` built whose three object slots are NULL or owned and
/// whose `enc_data` is NULL or owned.
#[no_mangle]
pub unsafe extern "C" fn X509_INFO_free(x: *mut X509Info) {
    if x.is_null() {
        return;
    }
    // SAFETY: `x` is live and each field is its own.
    unsafe {
        X509_free((*x).x509);
        X509_CRL_free((*x).crl);
        X509_PKEY_free((*x).x_pkey);
        CRYPTO_free((*x).enc_data.cast::<c_void>(), FILE, LINE_FREE_DATA);
        // SAFETY: `x` is this call's own record.
        CRYPTO_free(x.cast::<c_void>(), FILE, LINE_FREE_RECORD);
    }
}
