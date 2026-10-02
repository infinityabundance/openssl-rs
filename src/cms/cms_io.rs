//! `crypto/cms/cms_io.c` — the CMS <-> BIO/PEM/S/MIME readers. Phase 12.3.
//!
//! Only [`CMS_stream`] lands in this pass: it is the streaming callback's boundary hook and
//! `cms_asn1.rs`/`cms_lib.rs` reach it. The remaining exports of this unit
//! (`d2i_CMS_bio`/`i2d_CMS_bio`, `BIO_new_CMS`, the four `PEM_*_CMS` and the three `SMIME_*`)
//! are withheld pending the PASS-2 completion of this subphase and are named in the module
//! ledger as still open; their bodies are one call each into Phase 5's PEM bridge and this
//! stratum's Phase-12.9 `asn_mime.c` hand-off.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::asn1::layout::{ASN1_STRING_FLAG_CONT, ASN1_STRING_FLAG_NDEF};
use crate::asn1::string::ASN1_STRING_new;

use super::cms_asn1::*;
use super::cms_lib::{raise_cms, CMS_get0_content, ERR_R_CMS_LIB};

/// `int CMS_stream(unsigned char ***boundary, CMS_ContentInfo *cms)` — `cms_io.c:18-35`.
///
/// # Safety
/// `boundary` is writable; `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_stream(
    boundary: *mut *mut *mut u8,
    cms: *mut CmsContentInfo,
) -> c_int {
    // SAFETY: `cms` is live.
    let pos = unsafe { CMS_get0_content(cms) };
    if pos.is_null() {
        return 0;
    }
    // SAFETY: `pos` is a live slot.
    unsafe {
        if (*pos).is_null() {
            *pos = ASN1_STRING_new();
        }
        if !(*pos).is_null() {
            (*(*pos)).flags |= ASN1_STRING_FLAG_NDEF;
            (*(*pos)).flags &= !ASN1_STRING_FLAG_CONT;
            *boundary = ptr::addr_of_mut!((*(*pos)).data);
            return 1;
        }
    }
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_cms(33, c"CMS_stream", ERR_R_CMS_LIB) };
    0
}
