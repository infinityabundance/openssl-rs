//! `crypto/x509/t_x509.c`'s `X509_signature_dump`, the one helper of that unit the
//! `rsa_ameth.c` and `dsa_ameth.c` method objects call by name. Phase 8.8 (D349).
//!
//! ## A partial unit, and the one export this slice reaches
//!
//! `crypto/x509/t_x509.c` is the X.509 text layer: **10 exports**, of which this module
//! lands **one** (`:269`). The other nine — `X509_print`, `X509_print_ex`,
//! `X509_print_ex_fp`, `X509_print_fp`, `X509_signature_print`, `X509_aux_print`,
//! `X509_ocspid_print`, `OSSL_STACK_OF_X509_free` and
//! `X509_STORE_CTX_print_verify_cb` — print a whole certificate through `X509_print_ex`'s
//! `do_print_ex`, which reads nearly every field of the object and is not this subphase's.
//! They are withheld with the object layer, not stubbed. The unit's two internals,
//! `ossl_serial_number_print` (`:519-559`) and `ossl_x509_print_ex_brief` (`:383-411`), are
//! the `covers` of this module's divergence row in `forensics/prerequisites.json`.
//!
//! ## `X509_signature_dump`'s closure is Phase 4 alone
//!
//! The brief asks whether this body is "Phase 4 alone", and it is, measured rather than
//! asserted: the body is a loop over `sig->length` octets that reaches exactly
//! `BIO_write` (`crypto/bio/bio_lib.c:366`), `BIO_indent` (`crypto/bio/bio_lib.c:626`) and
//! `BIO_printf` (`crypto/bio/bio_print.c:1047`, whose C-variadic definition the crate holds
//! in `src/runtime/bio/bio_variadic.c`) — all Phase 4 and landed — plus the two
//! `ASN1_STRING` members `length` and `data` (Phase 5's `src/asn1/layout.rs`). It calls no
//! other authority function and raises nothing: every failure arm answers 0. So
//! `crypto/x509/t_x509.c` is deliberately **not** added to `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! ## The layout it reads
//!
//! `const ASN1_STRING *sig` is the crate's [`Asn1String`] (`struct asn1_string_st`,
//! `src/asn1/layout.rs`) — the only structure the function touches, and already the
//! crate's. No new type is defined here.
//!
//! ## The court, and what it prints
//!
//! The arm lives in `RT-ASN1-TEMPLATE`. It sets a twenty-octet `ASN1_OCTET_STRING` from a
//! probe constant, dumps it into a memory BIO at indent 4, and prints the BIO's contents:
//! those bytes are the probe's own public constant formatted by the library, so printing
//! them is the differential evidence rather than a leak, and the arm also observes the
//! return code and the nineteen- and zero-octet widths that make the `i % 18` line break
//! and the trailing newline visible. (The zero-octet arm is why the trailing newline is
//! observable at all: with no octets the loop never runs, so the dump is that newline
//! alone — no indent is written on that path.) No key and no random draw is involved.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::asn1::layout::Asn1String;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;

/// `int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)` —
/// `crypto/x509/t_x509.c:269-290`.
///
/// Eighteen octets per line, each as two lower-case hex digits separated by `:`, a newline
/// and `BIO_indent` before every line but the first, and a final newline. Both `BIO_write`
/// calls are the authority's own: the loop breaks only when `BIO_write` reports `<= 0` on
/// the newline, while the trailing one is stricter and requires **exactly 1**. A zero-length
/// string skips the loop entirely — so it writes neither a line nor an indent — and answers 1
/// after writing the trailing newline alone.
///
/// # Safety
///
/// `bp` is a live BIO; `sig` is a live `ASN1_STRING` whose `data` is readable for
/// `sig->length` bytes (or NULL when the length is 0).
#[no_mangle]
pub unsafe extern "C" fn X509_signature_dump(
    bp: *mut Bio,
    sig: *const Asn1String,
    indent: c_int,
) -> c_int {
    /// The authority's line width, named rather than written as a literal in the test.
    const PER_LINE: c_int = 18;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let n = (*sig).length;
        let s = (*sig).data;

        let mut i: c_int = 0;
        while i < n {
            if i % PER_LINE == 0 {
                if i > 0 && BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) <= 0 {
                    return 0;
                }
                if BIO_indent(bp, indent, indent) <= 0 {
                    return 0;
                }
            }
            // The last octet has no separator; every other one is followed by a colon.
            let sep = if i + 1 == n {
                c"".as_ptr()
            } else {
                c":".as_ptr()
            };
            if BIO_printf(
                bp,
                c"%02x%s".as_ptr(),
                c_int::from(*s.offset(i as isize)),
                sep,
            ) <= 0
            {
                return 0;
            }
            i += 1;
        }

        if BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) != 1 {
            return 0;
        }
    }
    1
}
