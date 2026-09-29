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
//! They are withheld with the object layer, not stubbed. Of the unit's two internals,
//! `ossl_serial_number_print` (`:519-559`) landed in Phase 10.14.8 as the prerequisite of
//! `crypto/x509/v3_rolespec.c`, whose printer calls it at `v3_rolespec.c:49`; it is a
//! `pub(crate)` Rust function with no `#[no_mangle]`, because `include/crypto/x509.h:398`
//! is an internal header and the admitted DSO's version script hides the symbol (`nm -D
//! libcrypto.so.3` does not list it) -- D140's rule for `ossl_*` internals. The unit's
//! other internal, `ossl_x509_print_ex_brief` (`:383-411`), is withheld with the printers
//! (the object layer) and remains the sole `covers` name of this module's divergence row in
//! `forensics/prerequisites.json`. The landed helper raises nothing, so
//! `crypto/x509/t_x509.c` stays out of `gen_err_raise_sites.py`'s `COVERED_FILES` and no
//! raise coordinate is declared here.
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

use crate::asn1::layout::{Asn1String, V_ASN1_NEG_INTEGER};
use crate::asn1::prim::ASN1_INTEGER_get_int64;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};

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

/// `int ossl_serial_number_print(BIO *out, const ASN1_INTEGER *bs, int indent)` —
/// `crypto/x509/t_x509.c:519-559`.
///
/// An `ASN1_INTEGER` (`Asn1String`) serial rendered two ways. A zero-length value prints
/// `" (Empty)"` and answers 0. Otherwise `ASN1_INTEGER_get_int64` is tried between an
/// `ERR_set_mark`/`ERR_pop_to_mark` pair, so a decode that fails leaves nothing on the error
/// queue: when it succeeds the value is printed as decimal and hex, negated through
/// `wrapping_neg` and prefixed `-` for a `V_ASN1_NEG_INTEGER`; when it does not fit an
/// `int64`, the octets are printed as colon-separated hex under a newline, `indent` spaces
/// and `" (Negative)"` for a negative value. Every failure arm answers `-1`, and a
/// successful one `0`.
///
/// This is a crate-internal helper per the module doc, so it carries no `#[no_mangle]`.
///
/// # Safety
///
/// `out` is a live BIO; `bs` is a live `ASN1_INTEGER` whose `data` is readable for
/// `bs->length` octets (or NULL when the length is 0).
pub(crate) unsafe extern "C" fn ossl_serial_number_print(
    out: *mut Bio,
    bs: *const Asn1String,
    indent: c_int,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if (*bs).length == 0 {
            // SAFETY: `out` is a live BIO; the literal is static.
            if BIO_puts(out, c" (Empty)".as_ptr()) <= 0 {
                return -1;
            }
            return 0;
        }

        // The mark discards whatever `ASN1_INTEGER_get_int64` raises for an out-of-range
        // value, which is why this failing arm is an answer of 0 rather than a reason.
        ERR_set_mark();
        let mut l: i64 = 0;
        // SAFETY: `bs` is live; `l` is a writable slot for the out-parameter.
        let ok = ASN1_INTEGER_get_int64(&raw mut l, bs);
        ERR_pop_to_mark();

        if ok != 0 {
            let (ul, neg) = if (*bs).type_ == V_ASN1_NEG_INTEGER {
                ((l as u64).wrapping_neg(), c"-".as_ptr())
            } else {
                (l as u64, c"".as_ptr())
            };
            // SAFETY: `out` is a live BIO; the format and its arguments are constants.
            if BIO_printf(out, c" %s%ju (%s0x%jx)".as_ptr(), neg, ul, neg, ul) <= 0 {
                return -1;
            }
        } else {
            let neg = if (*bs).type_ == V_ASN1_NEG_INTEGER {
                c" (Negative)".as_ptr()
            } else {
                c"".as_ptr()
            };
            // SAFETY: `out` is a live BIO; the format and its arguments are constants.
            if BIO_printf(out, c"\n%*s%s".as_ptr(), indent, c"".as_ptr(), neg) <= 0 {
                return -1;
            }
            let n = (*bs).length;
            let data = (*bs).data;
            let mut i: c_int = 0;
            while i < n - 1 {
                // SAFETY: `data` is readable for `n` octets and `i` is in bounds; each
                // `unsigned char` is promoted to `int` for the variadic `%02x`.
                if BIO_printf(
                    out,
                    c"%02x%c".as_ptr(),
                    c_int::from(*data.offset(i as isize)),
                    c_int::from(b':'),
                ) <= 0
                {
                    return -1;
                }
                i += 1;
            }
            // SAFETY: `data` is readable for `n` octets and `i == n - 1` is in bounds.
            if BIO_printf(out, c"%02x".as_ptr(), c_int::from(*data.offset(i as isize))) <= 0 {
                return -1;
            }
        }
        0
    }
}
