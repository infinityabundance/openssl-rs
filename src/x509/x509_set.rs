//! `crypto/x509/x509_set.c`'s `X509_SIG_INFO_set`, the one setter of the signature-info
//! structure that the `rsa_ameth.c` and `ecx_meth.c` method objects call by name (`:771`
//! and `:586`/`:602` respectively). Phase 8.8 (D349).
//!
//! ## A partial unit, and the one export this slice reaches
//!
//! `crypto/x509/x509_set.c` is the X.509 object's mutator layer: **21 exports**, of which
//! this module lands **one** (`:200`). The other twenty — the `X509_get_version`/
//! `X509_set_version` pair, the four `X509_set_issuer_name`/`_subject_name`/`_pubkey`/
//! `_serialNumber` setters, the six `notBefore`/`notAfter` accessors, `X509_get0_extensions`,
//! `X509_get0_uids`, `X509_get0_tbs_sigalg`, `X509_get_X509_PUBKEY`,
//! `X509_get_signature_info`, `X509_SIG_INFO_get`, `X509_up_ref` and
//! `X509_get_signature_type` — are the `X509` object layer proper. They are not this
//! subphase's and none of the five ASN.1 method objects calls any of them; they are
//! withheld with the rest of the object layer, not stubbed.
//!
//! The two internals of the unit, `ossl_x509_init_sig_info` (`:305-309`) and
//! `ossl_x509_set1_time` (`:78-92`), are withheld with them and are the `covers` of this
//! module's divergence row in `forensics/prerequisites.json`. `ossl_x509_init_sig_info` is a
//! one-line delegation to the file-local `static x509_sig_info_init` (`:217`);
//! `ossl_x509_set1_time` duplicates one `ASN1_TIME` with `ASN1_STRING_dup`, frees the old
//! one and sets a caller's `modified` flag.
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

use core::ffi::c_int;

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
