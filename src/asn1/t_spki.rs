//! Phase 11.7 — `crypto/asn1/t_spki.c`'s `NETSCAPE_SPKI_print`.
//!
//! `crypto/asn1/t_spki.c` is 55 lines and publishes exactly one function, the Netscape SPKI
//! printer. Every callee it names -- `X509_PUBKEY_get0_param`/`_get`, `EVP_PKEY_print_public`,
//! `EVP_PKEY_free`, `OBJ_obj2nid`/`OBJ_nid2ln` and the `BIO_*` writers -- is landed, so the unit
//! lands whole. (It is *not* blocked on `X509_signature_print`, which is the `t_acert.c` printers'
//! blocker; the SPKI printer formats its own signature bytes.)
//!
//! The printer is a fixed layout: the header line, the public-key algorithm's **long name** (or
//! `UNKNOWN`), the key's own public print when it can be loaded, the challenge when present, and
//! the signature as `xx:xx:...`, seven spaces in at every eighteenth byte. `crypto/asn1/t_spki.c`
//! raises nothing, so it is deliberately **not** listed in `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::x_spki::NetScapeSpki;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_print_public};
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_undef, OBJ_nid2ln, OBJ_obj2nid};
use crate::x509::x_pubkey::{X509_PUBKEY_get, X509_PUBKEY_get0_param};

/// `int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki)` — `crypto/asn1/t_spki.c:20-56`.
///
/// The whole unit, and it always answers 1: no arm reports failure, even when the public key
/// cannot be loaded (that prints a line instead).
///
/// # Safety
/// `out` must be a live BIO; `spki` a live `NETSCAPE_SPKI` whose `spkac` is present.
#[no_mangle]
pub unsafe extern "C" fn NETSCAPE_SPKI_print(out: *mut Bio, spki: *mut NetScapeSpki) -> c_int {
    // SAFETY: `out`, `spki` and `spki`'s `spkac` are live per the contract, so every field read
    // below is inside a live structure.
    unsafe {
        let _ = BIO_printf(out, c"Netscape SPKI:\n".as_ptr());

        let mut spkioid: *mut Asn1Object = ptr::null_mut();
        let _ = X509_PUBKEY_get0_param(
            &raw mut spkioid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            (*(*spki).spkac).pubkey,
        );
        let i = OBJ_obj2nid(spkioid);
        let alg_name = if i == NID_undef {
            c"UNKNOWN".as_ptr()
        } else {
            OBJ_nid2ln(i)
        };
        let _ = BIO_printf(
            out,
            c"  Public Key Algorithm: %s\n".as_ptr(),
            alg_name.cast::<c_char>(),
        );

        let pkey = X509_PUBKEY_get((*(*spki).spkac).pubkey);
        if pkey.is_null() {
            let _ = BIO_printf(out, c"  Unable to load public key\n".as_ptr());
        } else {
            let _ = EVP_PKEY_print_public(out, pkey, 4, ptr::null_mut());
            EVP_PKEY_free(pkey);
        }

        let chal = (*(*spki).spkac).challenge;
        if (*chal).length != 0 {
            let _ = BIO_printf(
                out,
                c"  Challenge String: %.*s\n".as_ptr(),
                (*chal).length,
                (*chal).data.cast::<c_char>(),
            );
        }

        let i = OBJ_obj2nid((*spki).sig_algor.algorithm);
        let sig_name = if i == NID_undef {
            c"UNKNOWN".as_ptr()
        } else {
            OBJ_nid2ln(i)
        };
        let _ = BIO_printf(
            out,
            c"  Signature Algorithm: %s".as_ptr(),
            sig_name.cast::<c_char>(),
        );

        let sig = (*spki).signature;
        let n = (*sig).length;
        let s = (*sig).data;
        let mut i: c_int = 0;
        while i < n {
            if i % 18 == 0 {
                let _ = BIO_write(out, c"\n      ".as_ptr().cast::<c_void>(), 7);
            }
            let byte = *s.add(i as usize) as c_int;
            let sep = if i + 1 == n {
                c"".as_ptr()
            } else {
                c":".as_ptr()
            };
            let _ = BIO_printf(out, c"%02x%s".as_ptr(), byte, sep.cast::<c_char>());
            i += 1;
        }
        let _ = BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1);
    }
    1
}
