//! `crypto/pkcs7/bio_pk7.c` — the streaming-encode BIO for `PKCS7`. Phase 12.2.
//!
//! One call into Phase 5's `BIO_new_NDEF`, exactly as the authority's `bio_pk7.c:16-19`.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::asn1::bio_asn1::BIO_new_NDEF;
use crate::pkcs7::pk7_asn1::{PKCS7_it, Pkcs7};
use crate::runtime::bio::Bio;

/// `BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7)` — `bio_pk7.c:16-19`.
///
/// # Safety
/// `out` is null or a live BIO; `p7` is live.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_PKCS7(out: *mut Bio, p7: *mut Pkcs7) -> *mut Bio {
    // SAFETY: the caller's contract; `PKCS7_it()` is a static item.
    unsafe { BIO_new_NDEF(out, p7.cast(), PKCS7_it()) }
}
