//! `crypto/x509/x509_set.c`'s `X509_SIG_INFO_set` and `X509_up_ref`, the two functions of the
//! unit that 10.8's object core reaches. Phase 8.8 (D349) landed the first; Phase 10.8 adds the
//! second.
//!
//! ## A partial unit, and the two exports this slice reaches
//!
//! `crypto/x509/x509_set.c` is the X.509 object's mutator layer: **21 exports**, of which this
//! module lands **five**: `X509_SIG_INFO_set` (`:200`) and `X509_up_ref` (`:120`) from Phase 8.8
//! and 10.8, plus the three that 10.14.1's comparison/accessor slice reaches -- `X509_get_version`
//! (`:132-135`), `X509_set_version` (`:27-47`) and the `ossl_x509_set1_time` helper (`:78-92`)
//! that `x509cset.c`'s CRL setters and this unit's own validity setters share. The other sixteen
//! -- the four `X509_set_issuer_name`/`_subject_name`/`_pubkey`/`_serialNumber` setters, the six
//! `notBefore`/`notAfter` accessors, `X509_get0_extensions`, `X509_get0_uids`,
//! `X509_get0_tbs_sigalg`, `X509_get_X509_PUBKEY`, `X509_get_signature_info`,
//! `X509_SIG_INFO_get`, `X509_get_signature_type` and `ossl_x509_init_sig_info` -- are the `X509`
//! mutator layer proper. They are not this subphase's, and are withheld rather than stubbed.
//!
//! **`X509_up_ref` was withheld by D349 as "the `X509` object layer proper" and is landed here**,
//! because 10.8 is that object layer: `OSSL_STORE_INFO_get1_CERT` (`src/store/store_lib.rs`) is a
//! fetched arm that calls it, and the reference count `X509_it`'s `ASN1_AFLG_REFCOUNT` maintains
//! is the same count this function moves. Its defining unit is this file, which is why it lands
//! here and not beside the `X509` struct in `src/x509/x_x509.rs`.
//!
//! The unit's one remaining internal, `ossl_x509_init_sig_info` (`:305-309`), is withheld with
//! them and is one of the `covers` of this module's divergence row in
//! `forensics/prerequisites.json`; it is a one-line delegation to the file-local
//! `static x509_sig_info_init` (`:217`). `ossl_x509_set1_time` (`:78-92`) was withheld with the
//! mutator layer until 10.14.1, and lands here: it duplicates one `ASN1_TIME` with
//! `ASN1_STRING_dup`, frees the old one and sets a caller's `modified` flag (or, for the CRL
//! paths, a NULL one).
//!
//! ## The `X509SigInfo` layout
//!
//! `struct x509_sig_info_st` is declared in `include/crypto/x509.h:50-59`, an internal
//! header, and this module is its canonical definition because the setter below is the one
//! function of its authority that writes all four fields. The authority's `mdnid`, `pknid`
//! and `secbits` are `int` and its `flags` is `uint32_t`, so the crate's fields are
//! `c_int`, `c_int`, `c_int`, `u32` and the size is 16. `src/evp/pkey_asn1.rs` re-exports
//! the name for the `sig_print` callback signature rather than declaring a second,
//! placeholder one (D348's rule).
//!
//! The authority's reader, `X509_SIG_INFO_get` (`:186-198`), is not landed, so nothing
//! reads the three fields this setter writes except the court and the unit test. They are
//! read through the structure directly, which is what the reader does.
//!
//! ## No raise, and the court
//!
//! The setter is four assignments and answers nothing, so there is no raise to generate and
//! `crypto/x509/x509_set.c` is deliberately **not** added to `gen_err_raise_sites.py`'s
//! `COVERED_FILES`. The arm lives in `RT-ASN1-TEMPLATE`: it stack-allocates the
//! authority's own `struct x509_sig_info_st`, calls the setter over four probe constants,
//! and prints the four fields — no address, no secret.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_dup, ASN1_TIME_free};
use crate::x509::x_x509::X509;

/// `struct x509_sig_info_st` — `X509_SIG_INFO`, from `include/crypto/x509.h:50-59`.
///
/// The authority's four members in order. `X509_SIG_INFO_get` reads them back and
/// [`X509_SIG_INFO_set`] writes them; nothing else in the authority touches the type.
#[repr(C)]
pub struct X509SigInfo {
    /// `int mdnid` — the message-digest NID, or `NID_undef`.
    pub(crate) mdnid: c_int,
    /// `int pknid` — the public-key-algorithm NID, or `NID_undef`.
    pub(crate) pknid: c_int,
    /// `int secbits` — the security strength in bits.
    pub(crate) secbits: c_int,
    /// `uint32_t flags` — the `X509_SIG_INFO_*` words; `X509_SIG_INFO_VALID` is the one
    /// `X509_SIG_INFO_get`'s return value tests.
    pub(crate) flags: u32,
}

const _: () = {
    assert!(core::mem::size_of::<X509SigInfo>() == 16);
    assert!(core::mem::offset_of!(X509SigInfo, mdnid) == 0);
    assert!(core::mem::offset_of!(X509SigInfo, pknid) == 4);
    assert!(core::mem::offset_of!(X509SigInfo, secbits) == 8);
    assert!(core::mem::offset_of!(X509SigInfo, flags) == 12);
};

/// `int X509_set_version(X509 *x, long version)` — `crypto/x509/x509_set.c:27-47`.
///
/// A no-op that answers 1 when the requested version already holds; version 1 frees the version
/// integer so the DER omits it (the `[ 0 ]` default); any other version allocates it on first
/// use. Every success marks the cached encoding stale.
///
/// # Safety
///
/// `x` must be NULL or a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set_version(x: *mut X509, version: c_long) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract.
    unsafe {
        if version == X509_get_version(x) {
            return 1;
        }
        if version == X509_VERSION_1 {
            ASN1_INTEGER_free((*x).cert_info.version);
            (*x).cert_info.version = core::ptr::null_mut();
            (*x).cert_info.enc.modified = 1;
            return 1;
        }
        if (*x).cert_info.version.is_null() {
            (*x).cert_info.version = ASN1_INTEGER_new();
            if (*x).cert_info.version.is_null() {
                return 0;
            }
        }
        if ASN1_INTEGER_set((*x).cert_info.version, version) == 0 {
            return 0;
        }
        (*x).cert_info.enc.modified = 1;
    }
    1
}

/// `long X509_get_version(const X509 *x)` — `crypto/x509/x509_set.c:132-135`.
///
/// A NULL version pointer reads as 0 through `ASN1_INTEGER_get`, which is the authority's v1
/// default. `X509_NAME_cmp`'s `X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT`-free callers and the
/// Suite-B chain check reach it.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get_version(x: *const X509) -> c_long {
    // SAFETY: `x` is live per the contract.
    unsafe { ASN1_INTEGER_get((*x).cert_info.version) }
}

/// `int ossl_x509_set1_time(int *modified, ASN1_TIME **ptm, const ASN1_TIME *tm)` —
/// `crypto/x509/x509_set.c:78-92`.
///
/// Duplicates `tm` into `*ptm`, frees the previous value and sets `*modified` (when non-NULL).
/// A `tm` of NULL is the authority's "clear" case: it frees the old value, writes NULL and
/// answers 1. Identity (`*ptm == tm`) is a no-op.
///
/// # Safety
///
/// `ptm` must be writable and `*ptm` must be NULL or a live `ASN1_TIME`; `tm` must be NULL or a
/// live `ASN1_TIME`; `modified` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_set1_time(
    modified: *mut c_int,
    ptm: *mut *mut Asn1String,
    tm: *const Asn1String,
) -> c_int {
    // SAFETY: `ptm` is writable per the contract.
    if unsafe { *ptm == tm.cast_mut() } {
        return 1;
    }
    // SAFETY: `tm` is NULL or live per the contract.
    let new = unsafe { ASN1_STRING_dup(tm) };
    if !tm.is_null() && new.is_null() {
        return 0;
    }
    // SAFETY: `ptm` is writable and `*ptm` is NULL or live.
    unsafe {
        ASN1_TIME_free(*ptm);
        *ptm = new;
        if !modified.is_null() {
            *modified = 1;
        }
    }
    1
}

/// `X509_VERSION_1` — `include/openssl/x509.h:651`, the version `X509_set_version` omits from
/// the encoding rather than writing.
const X509_VERSION_1: c_long = 0;

/// `void X509_SIG_INFO_set(X509_SIG_INFO *siginf, int mdnid, int pknid, int secbits,
/// uint32_t flags)` — `crypto/x509/x509_set.c:200-207`.
///
/// Four assignments and nothing else: no validation, no allocation and no return value,
/// which is the whole of its contract. `flags` is assigned verbatim, so the caller owns the
/// question of whether `X509_SIG_INFO_VALID` is set.
///
/// # Safety
///
/// `siginf` is a live, writable `X509_SIG_INFO`.
#[no_mangle]
pub unsafe extern "C" fn X509_SIG_INFO_set(
    siginf: *mut X509SigInfo,
    mdnid: c_int,
    pknid: c_int,
    secbits: c_int,
    flags: u32,
) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for the writes.
    unsafe {
        (*siginf).mdnid = mdnid;
        (*siginf).pknid = pknid;
        (*siginf).secbits = secbits;
        (*siginf).flags = flags;
    }
}

/// `int X509_up_ref(X509 *x)` — `crypto/x509/x509_set.c:120-130`.
///
/// `CRYPTO_UP_REF` followed by the authority's `i > 1` test. The count is the same field
/// `X509_it`'s `ASN1_AFLG_REFCOUNT` initialises to 1 and `X509_free` decrements.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_up_ref(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract.
    let i = unsafe { (*x).references.wrapping_add(1) };
    // SAFETY: `x` is live and writable.
    unsafe { (*x).references = i };
    c_int::from(i > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four fields land where the layout says, in the order the arguments name them.
    #[test]
    fn the_four_fields_are_written_in_order() {
        let mut siginf = X509SigInfo {
            mdnid: 0,
            pknid: 0,
            secbits: 0,
            flags: 0,
        };
        // SAFETY: `siginf` is a live local.
        unsafe { X509_SIG_INFO_set(&raw mut siginf, 672, 6, 128, 0x5) };
        assert_eq!(siginf.mdnid, 672);
        assert_eq!(siginf.pknid, 6);
        assert_eq!(siginf.secbits, 128);
        assert_eq!(siginf.flags, 0x5);
    }
}
