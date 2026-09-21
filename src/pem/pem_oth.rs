//! Phase 9 staging — `crypto/pem/pem_oth.c`: the "other PEM" reader.
//!
//! The unit is 36 lines and one export, and it exists because a PEM block that is *not* a private
//! key needs a different discipline from `PEM_read_bio_PrivateKey`: the block is decoded by the
//! caller's own `d2i` function rather than through the ASN.1 method registry, so
//! `PEM_ASN1_read_bio` is the base64 reader plus one callback. It is the reader every
//! `IMPLEMENT_PEM_read_bio` expansion in `crypto/pem/pem_all.c` calls, which is why it lands with
//! `pem_lib.c`'s plumbing (D350) rather than with the private-key family.
//!
//! ## Why a module of its own
//!
//! `crypto/pem/pem_oth.c` is a separate authority translation unit, and the transcription atlas's
//! `build_edges` maps a crate module to the one unit its definitions dominantly come from. Putting
//! this export in `src/pem/pem_lib.rs` would make that module's dominant unit `pem_lib.c` and
//! leave `pem_oth.c` reached by nothing — which is what `plan_reconciliation.py`'s P1 census
//! watches for. One unit, one module, exactly as `src/x509/` does for its three files.
//!
//! ## The `const unsigned char *` cursor
//!
//! `d2i` takes `const unsigned char **` and advances it past what it consumed.
//! `PEM_ASN1_read_bio` does not look at the advanced cursor — it frees the buffer and answers the
//! decoded object — but the cursor must still be a live local for the call, so it is one here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::D2iOfVoid;
use crate::evp::pem_bridge::PemPasswordCb;
use crate::pem::pem_lib::PEM_bytes_read_bio;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;

/// `OPENSSL_FILE` at `PEM_ASN1_read_bio`'s `OPENSSL_free(data)` (`pem_oth.c:34`).
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/pem/pem_oth.c".as_ptr();

/// `void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
/// pem_password_cb *cb, void *u)` — `crypto/pem/pem_oth.c:20-36`.
///
/// Read the block through [`PEM_bytes_read_bio`] — which may prompt for a pass phrase if the
/// block is encrypted and `cb` is NULL — then hand the decoded bytes to `d2i`. A `d2i` refusal
/// raises `ERR_R_ASN1_LIB` and answers NULL, and the buffer is freed either way.
///
/// # Safety
/// `d2i` the decoder for `name`'s object type; `name` NUL-terminated; `bp` a live readable BIO;
/// `x` the decoder's destination; `cb` NULL or a `pem_password_cb`; `u` passed through to it.
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_read_bio(
    d2i: D2iOfVoid,
    name: *const c_char,
    bp: *mut Bio,
    x: *mut *mut c_void,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut c_void {
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;

    // SAFETY: `bp` is live and the two out-parameters are this frame's own.
    if unsafe { PEM_bytes_read_bio(&mut data, &mut len, ptr::null_mut(), name, bp, cb, u) } == 0 {
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = data;
    // SAFETY: `x` is the caller's destination, `p` is readable for `len` bytes, and `d2i` is the
    // caller's decoder.
    let ret = unsafe { d2i(x, &mut p, len) };
    if ret.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_OTH_33) };
    }
    // SAFETY: `data` is the buffer `PEM_bytes_read_bio` allocated for this call.
    unsafe { CRYPTO_free(data.cast::<c_void>(), FILE, LINE_READ_BIO_FREE) };
    ret
}

/// `PEM_ASN1_read_bio`'s `OPENSSL_free(data)` (`pem_oth.c:34`).
const LINE_READ_BIO_FREE: c_int = 34;
