//! `crypto/x509/x509_set.c` — the X.509 object's mutator layer, transcribed whole. Phase 11.4
//! completes it; Phases 8.8, 10.8, 10.14.1 and 10.14.5 landed its first seven exports.
//!
//! `crypto/x509/x509_set.c` is 309 lines and **21 public exports**. The earlier phases landed
//! five of them -- `X509_SIG_INFO_set` (`:200`), `X509_up_ref` (`:120`), `X509_set_version`
//! (`:27-47`), `X509_get_version` (`:132-135`) and `X509_get0_extensions` (`:167-170`) -- plus the
//! two internal helpers `ossl_x509_set1_time` (`:78-92`) and `ossl_x509_init_sig_info`
//! (`:305-309`). **This slice lands the remaining sixteen**, the mutator layer proper:
//!
//! * the four setters `X509_set_serialNumber` (`:49-60`), `X509_set_issuer_name` (`:62-68`),
//!   `X509_set_subject_name` (`:70-76`) and `X509_set_pubkey` (`:110-118`);
//! * the six validity accessors `X509_set1_notBefore` (`:94-100`), `X509_set1_notAfter`
//!   (`:102-108`), `X509_get0_notBefore` (`:137-140`), `X509_get0_notAfter` (`:142-145`),
//!   `X509_getm_notBefore` (`:147-150`) and `X509_getm_notAfter` (`:152-155`);
//! * the four readers `X509_get_signature_type` (`:157-160`), `X509_get_X509_PUBKEY` (`:162-165`),
//!   `X509_get0_uids` (`:172-179`) and `X509_get0_tbs_sigalg` (`:181-184`);
//! * `X509_SIG_INFO_get` (`:186-198`) and `X509_get_signature_info` (`:209-214`).
//!
//! Every one of the sixteen raises nothing, and the whole unit is now landed. The `X509_CRL_set_*`
//! and `X509_REQ_set_*` families some plans group with this layer live in `x509cset.c` and
//! `x509rset.c` (the latter already landed in [`crate::x509::x509rset`]) and are not this file's.
//!
//! **`ossl_x509_init_sig_info` is landed because `ossl_x509v3_cache_extensions` names it**, and
//! it is the third of the three non-`x509_ext.c` names that function was measured to need (D461).
//! Of its two authority callers, `X509_get_signature_info` (`:209-214`) is landed by this same
//! slice and calls it, so the initialiser is reachable now; the other, `ossl_x509v3_cache_extensions`,
//! remains withheld. Its `default:` branch routes through
//! `EVP_get_digestbynid`/`EVP_get_digestbyname`, the crate's recorded legacy-`OBJ_NAME` divergence
//! (D333/D343); the transcription reproduces that path rather than papering over it.
//!
//! **`ossl_x509_set1_time` (`:78-92`) was withheld with the mutator layer until 10.14.1**, and
//! lands here: it duplicates one `ASN1_TIME` with `ASN1_STRING_dup`, frees the old one and sets a
//! caller's `modified` flag (or, for the CRL paths, a NULL one). It is the shared half of the six
//! validity setters landed by this slice.
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
//! The authority's reader, `X509_SIG_INFO_get` (`:186-198`), is landed by this same slice and
//! reads the four fields this setter writes; the unit test drives the pair.
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
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_copy, ASN1_STRING_dup, ASN1_TIME_free,
};
use crate::asn1::x_algor::X509Algor;
use crate::evp::digest::{EVP_MD_get_size, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{EVP_PKEY_get_security_bits, EvpPkey};
use crate::evp::pkey_asn1::{EVP_PKEY_asn1_find, EVP_PKEY_type};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_id_GostR3411_94, NID_md5, NID_sha1, NID_sha256, NID_sha384, NID_sha512, NID_undef,
    OBJ_find_sigid_algs, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x_name::{X509Name, X509_NAME_set};
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_get0, X509_PUBKEY_set};
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

/// `const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)` —
/// `crypto/x509/x509_set.c:167-170`.
///
/// The certificate's extension stack, borrowed. **Landed by 10.14.2**, un-withheld from the
/// mutator layer because `X509_sign`/`X509_sign_ctx` (`crypto/x509/x_all.c`) test its length to
/// decide whether to force version 3, and the `X509` object 10.8 landed makes the one-field read
/// writable. The stack is `OpenSslStack`; only its length and elements are read, by the signer
/// and by the `X509v3_*` surface `x509_v3.c` (10.11) owns.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get0_extensions(x: *const X509) -> *const OpenSslStack {
    // SAFETY: `x` is live per the contract.
    unsafe { (*x).cert_info.extensions }
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

/// `X509_SIG_INFO_VALID` — `include/openssl/x509.h.in:66`, the "`siginf` was filled" bit.
const X509_SIG_INFO_VALID: u32 = 0x1;
/// `X509_SIG_INFO_TLS` — `include/openssl/x509.h.in:68`, set for the four TLS-legal digests.
const X509_SIG_INFO_TLS: u32 = 0x2;

/// `static int x509_sig_info_init(X509_SIG_INFO *siginf, const X509_ALGOR *alg, const ASN1_STRING
/// *sig, const EVP_PKEY *pubkey)` — `crypto/x509/x509_set.c:217-302`.
///
/// Resolves the signature algorithm's digest and public-key NIDs through `OBJ_find_sigid_algs`,
/// then fills the four `siginf` fields: `mdnid`/`pknid` always, `secbits` by the digest's own
/// strength (with the three historical overrides for SHA-1, MD5 and GOST R 34.11-94), and the
/// `X509_SIG_INFO_VALID`/`_TLS` bits. A custom `siginf_set` method on the key's ASN.1 method wins
/// when the digest NID is `NID_undef`; otherwise the public key's security bits are tried.
///
/// The `default:` branch is `EVP_get_digestbynid(mdnid)` — the macro
/// `EVP_get_digestbyname(OBJ_nid2sn(mdnid))` — which the crate's legacy `OBJ_NAME` tables answer
/// NULL for (D333/D343); the transcription keeps the authority's call rather than substituting a
/// fetched digest, so the divergence stays where the crate records it rather than being hidden
/// here.
///
/// # Safety
///
/// `siginf` must be writable; `alg` must be a live `X509_ALGOR`; `sig` must be NULL or a live
/// `ASN1_STRING`; `pubkey` must be NULL or a live `EVP_PKEY`.
unsafe fn x509_sig_info_init(
    siginf: *mut X509SigInfo,
    alg: *const X509Algor,
    sig: *const Asn1String,
    pubkey: *const crate::evp::pkey::EvpPkey,
) -> c_int {
    // SAFETY: `siginf` is writable per the contract.
    unsafe {
        (*siginf).mdnid = NID_undef;
        (*siginf).pknid = NID_undef;
        (*siginf).secbits = -1;
        (*siginf).flags = 0;
    }
    let mut mdnid: c_int = 0;
    let mut pknid: c_int = 0;
    // SAFETY: `alg` is live per the contract; the two out-parameters are locals.
    let found = unsafe {
        OBJ_find_sigid_algs(
            OBJ_obj2nid((*alg).algorithm),
            &raw mut mdnid,
            &raw mut pknid,
        )
    };
    if found == 0 || pknid == NID_undef {
        // SAFETY: a compiled-in site coordinate.
        unsafe { raise_site(&err_sites::X509_SET_230) };
        return 0;
    }
    // SAFETY: `siginf` is writable per the contract.
    unsafe {
        (*siginf).mdnid = mdnid;
        (*siginf).pknid = pknid;
    }

    if mdnid == NID_undef {
        // SAFETY: `EVP_PKEY_asn1_find` takes a NULL engine slot and an integer NID.
        let ameth = unsafe { EVP_PKEY_asn1_find(ptr::null_mut(), pknid) };
        let mut handled = false;
        if !ameth.is_null() {
            // SAFETY: `ameth` is non-NULL and live.
            if let Some(f) = unsafe { (*ameth).siginf_set } {
                // SAFETY: `f` is the method's callback, called with the authority's arguments.
                if unsafe { f(siginf, alg, sig) } != 0 {
                    handled = true;
                }
            }
        }
        if !handled && !pubkey.is_null() {
            // SAFETY: `pubkey` is non-NULL and live per the contract.
            let secbits = unsafe { EVP_PKEY_get_security_bits(pubkey) };
            if secbits != 0 {
                // SAFETY: `siginf` is writable per the contract.
                unsafe { (*siginf).secbits = secbits };
                handled = true;
            }
        }
        if !handled {
            // SAFETY: a compiled-in site coordinate.
            unsafe { raise_site(&err_sites::X509_SET_252) };
            return 0;
        }
    } else if mdnid == NID_sha1 {
        // SAFETY: `siginf` is writable per the contract.
        unsafe { (*siginf).secbits = 63 }
    } else if mdnid == NID_md5 {
        // SAFETY: `siginf` is writable per the contract.
        unsafe { (*siginf).secbits = 39 }
    } else if mdnid == NID_id_GostR3411_94 {
        // SAFETY: `siginf` is writable per the contract.
        unsafe { (*siginf).secbits = 105 }
    } else {
        // `EVP_get_digestbynid(mdnid)` — `include/openssl/evp.h`, the macro
        // `EVP_get_digestbyname(OBJ_nid2sn(nid))`.
        // SAFETY: `OBJ_nid2sn` takes an integer NID and `EVP_get_digestbyname` a NUL-terminated
        // name; both are the authority's own calls.
        let md: *const EvpMd = unsafe { EVP_get_digestbyname(OBJ_nid2sn(mdnid)) };
        if md.is_null() {
            // SAFETY: a compiled-in site coordinate.
            unsafe { raise_site(&err_sites::X509_SET_284) };
            return 0;
        }
        // SAFETY: `md` is a live digest per the guard above.
        let md_size = unsafe { EVP_MD_get_size(md) };
        if md_size <= 0 {
            return 0;
        }
        // SAFETY: `siginf` is writable per the contract.
        unsafe { (*siginf).secbits = md_size * 4 }
    }

    if mdnid == NID_sha1 || mdnid == NID_sha256 || mdnid == NID_sha384 || mdnid == NID_sha512 {
        // SAFETY: `siginf` is writable per the contract.
        unsafe { (*siginf).flags |= X509_SIG_INFO_TLS }
    }
    // SAFETY: `siginf` is writable per the contract.
    unsafe { (*siginf).flags |= X509_SIG_INFO_VALID }
    1
}

/// `int ossl_x509_init_sig_info(X509 *x)` — `crypto/x509/x509_set.c:305-309`.
///
/// The one-line delegation [`ossl_x509v3_cache_extensions`] calls last. `X509_PUBKEY_get0`
/// answers NULL for a certificate with no public key, which the initialiser's `pubkey` branch is
/// written to accept.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_init_sig_info(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract; the three field addresses and the key are its own.
    unsafe {
        x509_sig_info_init(
            &raw mut (*x).siginf,
            &raw const (*x).sig_alg,
            &raw const (*x).signature,
            X509_PUBKEY_get0((*x).cert_info.key),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The mutator layer proper — `crypto/x509/x509_set.c:49-214` (Phase 11.4)
// ---------------------------------------------------------------------------------------------

/// `int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial)` — `crypto/x509/x509_set.c:49-60`.
///
/// Copies `serial` into the certificate's embedded `cert_info.serialNumber`; when the source is the
/// field itself the copy is skipped and the cached encoding marked stale instead, which is the
/// authority's own distinction between "the caller set it" and "it is already this value".
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `serial` is NULL or a live `ASN1_INTEGER`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set_serialNumber(x: *mut X509, serial: *mut Asn1String) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract; `serialNumber` is its own embedded field.
    let in_ = unsafe { &raw mut (*x).cert_info.serialNumber };
    if in_ != serial {
        // SAFETY: `in_` is the certificate's own field and `serial` is live per the contract.
        return unsafe { ASN1_STRING_copy(in_, serial) };
    }
    // SAFETY: `x` is live and `enc.modified` is its own field.
    unsafe { (*x).cert_info.enc.modified = 1 };
    1
}

/// `int X509_set_issuer_name(X509 *x, const X509_NAME *name)` — `crypto/x509/x509_set.c:62-68`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `name` is NULL or a live `X509_NAME`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set_issuer_name(x: *mut X509, name: *const X509Name) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live, so the `issuer` slot is its own; `name` is NULL or live per the
    // contract.
    if unsafe { X509_NAME_set(&raw mut (*x).cert_info.issuer, name) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live and `enc.modified` is its own field.
    unsafe { (*x).cert_info.enc.modified = 1 };
    1
}

/// `int X509_set_subject_name(X509 *x, const X509_NAME *name)` — `crypto/x509/x509_set.c:70-76`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `name` is NULL or a live `X509_NAME`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set_subject_name(x: *mut X509, name: *const X509Name) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live, so the `subject` slot is its own; `name` is NULL or live per the
    // contract.
    if unsafe { X509_NAME_set(&raw mut (*x).cert_info.subject, name) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live and `enc.modified` is its own field.
    unsafe { (*x).cert_info.enc.modified = 1 };
    1
}

/// `int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm)` — `crypto/x509/x509_set.c:94-100`.
///
/// A NULL `x` or `tm` is refused; otherwise [`ossl_x509_set1_time`] duplicates `tm` into the
/// validity field and marks the cached encoding stale.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `tm` is NULL or a live `ASN1_TIME`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set1_notBefore(x: *mut X509, tm: *const Asn1String) -> c_int {
    if x.is_null() || tm.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract, so both field slots are its own; `tm` is live.
    unsafe {
        ossl_x509_set1_time(
            &raw mut (*x).cert_info.enc.modified,
            &raw mut (*x).cert_info.validity.notBefore,
            tm,
        )
    }
}

/// `int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm)` — `crypto/x509/x509_set.c:102-108`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `tm` is NULL or a live `ASN1_TIME`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set1_notAfter(x: *mut X509, tm: *const Asn1String) -> c_int {
    if x.is_null() || tm.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract, so both field slots are its own; `tm` is live.
    unsafe {
        ossl_x509_set1_time(
            &raw mut (*x).cert_info.enc.modified,
            &raw mut (*x).cert_info.validity.notAfter,
            tm,
        )
    }
}

/// `int X509_set_pubkey(X509 *x, EVP_PKEY *pkey)` — `crypto/x509/x509_set.c:110-118`.
///
/// # Safety
///
/// `x` is NULL or a live `X509`; `pkey` is NULL or a live `EVP_PKEY`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_set_pubkey(x: *mut X509, pkey: *mut EvpPkey) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live, so the `key` slot is its own; `pkey` is NULL or live per the contract.
    if unsafe { X509_PUBKEY_set(&raw mut (*x).cert_info.key, pkey) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live and `enc.modified` is its own field.
    unsafe { (*x).cert_info.enc.modified = 1 };
    1
}

/// `const ASN1_TIME *X509_get0_notBefore(const X509 *x)` — `crypto/x509/x509_set.c:137-140`.
///
/// The borrowed validity start; `X509_getm_notBefore` is its mutable twin.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get0_notBefore(x: *const X509) -> *const Asn1String {
    // SAFETY: `x` is live per the contract; `validity.notBefore` is its own field.
    unsafe { (*x).cert_info.validity.notBefore as *const Asn1String }
}

/// `const ASN1_TIME *X509_get0_notAfter(const X509 *x)` — `crypto/x509/x509_set.c:142-145`.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get0_notAfter(x: *const X509) -> *const Asn1String {
    // SAFETY: `x` is live per the contract; `validity.notAfter` is its own field.
    unsafe { (*x).cert_info.validity.notAfter as *const Asn1String }
}

/// `ASN1_TIME *X509_getm_notBefore(const X509 *x)` — `crypto/x509/x509_set.c:147-150`.
///
/// The mutable form, which the deprecated `X509_get_notBefore` macro also spells.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_getm_notBefore(x: *const X509) -> *mut Asn1String {
    // SAFETY: `x` is live per the contract; `validity.notBefore` is its own field.
    unsafe { (*x).cert_info.validity.notBefore }
}

/// `ASN1_TIME *X509_getm_notAfter(const X509 *x)` — `crypto/x509/x509_set.c:152-155`.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_getm_notAfter(x: *const X509) -> *mut Asn1String {
    // SAFETY: `x` is live per the contract; `validity.notAfter` is its own field.
    unsafe { (*x).cert_info.validity.notAfter }
}

/// `int X509_get_signature_type(const X509 *x)` — `crypto/x509/x509_set.c:157-160`.
///
/// `EVP_PKEY_type(OBJ_obj2nid(x->sig_alg.algorithm))` — the key type the outer signature names,
/// not the signature algorithm.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get_signature_type(x: *const X509) -> c_int {
    // SAFETY: `x` is live per the contract; `sig_alg.algorithm` is its own.
    unsafe { EVP_PKEY_type(OBJ_obj2nid((*x).sig_alg.algorithm)) }
}

/// `X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x)` — `crypto/x509/x509_set.c:162-165`.
///
/// The embedded `cert_info.key`, borrowed; the header's own comment gives its one use,
/// `i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &buf)`.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509Pubkey {
    // SAFETY: `x` is live per the contract; `cert_info.key` is its own field.
    unsafe { (*x).cert_info.key }
}

/// `void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **piuid, const ASN1_BIT_STRING
/// **psuid)` — `crypto/x509/x509_set.c:172-179`.
///
/// Writes the optional issuer/subject unique IDs through whichever slot the caller passed.
///
/// # Safety
///
/// `x` is a live `X509`; `piuid` and `psuid` are each NULL or a writable slot.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get0_uids(
    x: *const X509,
    piuid: *mut *const Asn1String,
    psuid: *mut *const Asn1String,
) {
    if !piuid.is_null() {
        // SAFETY: `piuid` is writable and `x` is live per the contract.
        unsafe { *piuid = (*x).cert_info.issuerUID };
    }
    if !psuid.is_null() {
        // SAFETY: `psuid` is writable and `x` is live per the contract.
        unsafe { *psuid = (*x).cert_info.subjectUID };
    }
}

/// `const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x)` — `crypto/x509/x509_set.c:181-184`.
///
/// The TBS signature algorithm, borrowed from the embedded `cert_info.signature`.
///
/// # Safety
///
/// `x` is a live `X509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get0_tbs_sigalg(x: *const X509) -> *const X509Algor {
    // SAFETY: `x` is live per the contract; `cert_info.signature` is its own embedded field.
    unsafe { &raw const (*x).cert_info.signature }
}

/// `int X509_SIG_INFO_get(const X509_SIG_INFO *siginf, int *mdnid, int *pknid, int *secbits,
/// uint32_t *flags)` — `crypto/x509/x509_set.c:186-198`.
///
/// The reader for the [`X509SigInfo`] block [`X509_SIG_INFO_set`] writes; its answer tests the
/// `X509_SIG_INFO_VALID` bit.
///
/// # Safety
///
/// `siginf` is a live `X509_SIG_INFO`; each out-pointer is NULL or writable for its type.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_SIG_INFO_get(
    siginf: *const X509SigInfo,
    mdnid: *mut c_int,
    pknid: *mut c_int,
    secbits: *mut c_int,
    flags: *mut u32,
) -> c_int {
    // SAFETY: `siginf` is live per the contract; each out-pointer is NULL or writable for its type.
    unsafe {
        if !mdnid.is_null() {
            *mdnid = (*siginf).mdnid;
        }
        if !pknid.is_null() {
            *pknid = (*siginf).pknid;
        }
        if !secbits.is_null() {
            *secbits = (*siginf).secbits;
        }
        if !flags.is_null() {
            *flags = (*siginf).flags;
        }
        c_int::from((*siginf).flags & X509_SIG_INFO_VALID != 0)
    }
}

/// `int X509_get_signature_info(X509 *x, int *mdnid, int *pknid, int *secbits, uint32_t *flags)` —
/// `crypto/x509/x509_set.c:209-214`.
///
/// Runs `X509_check_purpose(x, -1, -1)` first so the certificate's cached `siginf` is current, then
/// reports it through [`X509_SIG_INFO_get`].
///
/// # Safety
///
/// `x` is a live `X509`; each out-pointer is NULL or writable for its type.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn X509_get_signature_info(
    x: *mut X509,
    mdnid: *mut c_int,
    pknid: *mut c_int,
    secbits: *mut c_int,
    flags: *mut u32,
) -> c_int {
    // SAFETY: `x` is live per the contract; each out-pointer is NULL or writable for its type.
    unsafe {
        X509_check_purpose(x, -1, -1);
        X509_SIG_INFO_get(&raw const (*x).siginf, mdnid, pknid, secbits, flags)
    }
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

        // The reader landed by the same slice reports the four fields back, and its answer tests
        // the `X509_SIG_INFO_VALID` bit.
        let mut mdnid = 0;
        let mut pknid = 0;
        let mut secbits = 0;
        let mut flags = 0u32;
        // SAFETY: `siginf` is a live local and every out-pointer is a live local.
        let valid = unsafe {
            X509_SIG_INFO_get(
                &raw const siginf,
                &raw mut mdnid,
                &raw mut pknid,
                &raw mut secbits,
                &raw mut flags,
            )
        };
        assert_eq!((mdnid, pknid, secbits, flags), (672, 6, 128, 0x5));
        assert_eq!(valid, 1);
    }
}
