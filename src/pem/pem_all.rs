//! `crypto/pem/pem_all.c` — Phase 11's half: the X.509, request, CRL, public-key and Netscape
//! PEM readers and writers. Phase 11.6.
//!
//! `crypto/pem/pem_all.c` has no function bodies worth the name: it is 225 lines of
//! `IMPLEMENT_PEM_*` invocations whose macro expansion is the whole file. Phase 8.9 already
//! landed the unit's Phase-8 half (`src/pem/key_legacy.rs`: the `*PrivateKey`, `*params`,
//! `RSAPublicKey` and `PKCS#7` names), and this module is the **expansion** of the other eleven
//! invocations, each a `#[no_mangle]` function whose body is the one `PEM_ASN1_read` /
//! `PEM_ASN1_read_bio` / `PEM_ASN1_write` / `PEM_ASN1_write_bio` call the macro produced, with
//! the `(d2i_of_void *)`/`(i2d_of_void *)` cast written as a Rust shim.
//!
//! ```text
//! IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)       :37  (4 names)
//! IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, ...) :39  (2 names)
//! IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)       :40  (4 names)
//! IMPLEMENT_PEM_rw(X509_PUBKEY, X509_PUBKEY, PEM_STRING_PUBLIC, ...)        :41  (3 names)
//! IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, ...)                             :44  (4 names)
//! IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA, PEM_STRING_PUBLIC, RSA_PUBKEY)          :90  (4 names)
//! IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)          :118 (4 names)
//! IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)         :163 (4 names)
//! IMPLEMENT_PEM_provided_write(PUBKEY, EVP_PKEY, pkey, ...)                 :225 (4 names)
//! ```
//!
//! ## The one asymmetry against Phase 8's half
//!
//! `IMPLEMENT_PEM_rw(X509_PUBKEY, ...)` and `IMPLEMENT_PEM_provided_write(PUBKEY, ...)` name the
//! same `write_bio` entry point in different ways: `PEM_write_bio_X509_PUBKEY` (the earlier
//! macro) is already landed in `src/pem/pem_lib.rs`, pulled forward by Phase 10.3's
//! `encode_key2any.c` (`D451`'s note), while `PEM_write_bio_PUBKEY` (the provided-write macro) is
//! this unit's. Only the `FILE *` writer `PEM_write_X509_PUBKEY` and the two `X509_PUBKEY`
//! readers remain here.
//!
//! ## The provided writers try the encoder first
//!
//! `IMPLEMENT_PEM_provided_write` (`crypto/pem/pem_local.h:95-110`) builds an
//! `OSSL_ENCODER_CTX` for the key, writes through it when it has any encoders, and otherwise
//! falls back to the legacy `PEM_ASN1_write` over `i2d_PUBKEY` — which is what a legacy
//! `EVP_PKEY_set1_*` key takes. The four `PUBKEY` writers below transcribe both arms, and the
//! `_ex` pair differs only in carrying `propq` into `OSSL_ENCODER_CTX_new_for_pkey`.
//!
//! ## Netscape
//!
//! `IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE, PEM_STRING_X509, ...)`
//! reuses the `CERTIFICATE` header (`PEM_STRING_X509`) for the Netscape bundle. Its item is
//! [`crate::asn1::nsseq`], a 11.7 unit landed with this subphase because the four readers and
//! writers cannot exist without it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::I2dOfVoid;
use crate::asn1::nsseq::{
    d2i_NETSCAPE_CERT_SEQUENCE, i2d_NETSCAPE_CERT_SEQUENCE, NetScapeCertSequence,
};
use crate::dsa::Dsa;
use crate::ec::EcKey;
use crate::encoder_lib::{
    OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio, OSSL_ENCODER_to_fp,
};
use crate::encoder_meth::OSSL_ENCODER_CTX_free;
use crate::encoder_pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::evp::pem_bridge::PemPasswordCb;
use crate::evp::pkey::EvpPkey;
use crate::pem::pem_lib::{
    PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio, PEM_STRING_PUBLIC, PEM_STRING_X509,
    PEM_STRING_X509_CRL, PEM_STRING_X509_REQ, PEM_STRING_X509_REQ_OLD,
};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::pkcs7::pk7_asn1::{d2i_PKCS7, i2d_PKCS7, Pkcs7};
use crate::rsa::Rsa;
use crate::runtime::bio::Bio;
use crate::x509::x509_req::X509Req;
use crate::x509::x_crl::{d2i_X509_CRL, i2d_X509_CRL, X509Crl};
use crate::x509::x_pubkey::{
    d2i_DSA_PUBKEY, d2i_EC_PUBKEY, d2i_RSA_PUBKEY, d2i_X509_PUBKEY, i2d_DSA_PUBKEY, i2d_EC_PUBKEY,
    i2d_PUBKEY, i2d_RSA_PUBKEY, i2d_X509_PUBKEY, X509Pubkey,
};
use crate::x509::x_req::{d2i_X509_REQ, i2d_X509_REQ};

/// `EVP_PKEY_PUBLIC_KEY` — `include/openssl/evp.h`, `EVP_PKEY_KEY_PARAMETERS |
/// OSSL_KEYMGMT_SELECT_PUBLIC_KEY` = `0x04 | 0x02`. The selection the `PUBKEY` writers encode.
const EVP_PKEY_PUBLIC_KEY: c_int = 0x04 | 0x02;

/// `PEM_STRUCTURE_PUBKEY` — `crypto/pem/pem_local.h:33`, the encoder structure the `PUBKEY`
/// writers name.
const PEM_STRUCTURE_PUBKEY: *const c_char = c"SubjectPublicKeyInfo".as_ptr();

// ---------------------------------------------------------------------------------------------
// The `(d2i_of_void *)`/`(i2d_of_void *)` shims, one per codec the macro expansions name.
// ---------------------------------------------------------------------------------------------

/// A shim's `# Safety`: the `void *` arguments are the typed codec's own arguments, which the
/// `PEM_ASN1_*` call site guarantees.
macro_rules! d2i_shim {
    ($name:ident, $typed:path, $ty:ty) => {
        /// The `(d2i_of_void *)` cast for this codec.
        ///
        /// # Safety
        /// The `void *` arguments must be the typed decoder's own arguments.
        unsafe extern "C" fn $name(
            a: *mut *mut c_void,
            in_: *mut *const c_uchar,
            len: c_long,
        ) -> *mut c_void {
            // SAFETY: the caller's contract, restated in the typed decoder's terms.
            unsafe { $typed(a.cast::<*mut $ty>(), in_, len).cast::<c_void>() }
        }
    };
}

/// A shim's `# Safety`: `x` is live and `out` is the encoder's own cursor.
macro_rules! i2d_shim {
    ($name:ident, $typed:path, $ty:ty) => {
        /// The `(i2d_of_void *)` cast for this codec.
        ///
        /// # Safety
        /// `x` must be live and `out` the encoder's own cursor.
        unsafe extern "C" fn $name(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
            // SAFETY: the caller's contract, restated in the typed encoder's terms.
            unsafe { $typed(x.cast::<$ty>(), out) }
        }
    };
}

d2i_shim!(d2i_void_x509_req, d2i_X509_REQ, X509Req);
i2d_shim!(i2d_void_x509_req, i2d_X509_REQ, X509Req);
d2i_shim!(d2i_void_x509_crl, d2i_X509_CRL, X509Crl);
i2d_shim!(i2d_void_x509_crl, i2d_X509_CRL, X509Crl);
d2i_shim!(d2i_void_x509_pubkey, d2i_X509_PUBKEY, X509Pubkey);
i2d_shim!(i2d_void_x509_pubkey, i2d_X509_PUBKEY, X509Pubkey);
d2i_shim!(
    d2i_void_nsseq,
    d2i_NETSCAPE_CERT_SEQUENCE,
    NetScapeCertSequence
);
i2d_shim!(
    i2d_void_nsseq,
    i2d_NETSCAPE_CERT_SEQUENCE,
    NetScapeCertSequence
);
d2i_shim!(d2i_void_pkcs7, d2i_PKCS7, Pkcs7);
i2d_shim!(i2d_void_pkcs7, i2d_PKCS7, Pkcs7);
d2i_shim!(d2i_void_rsa_pubkey, d2i_RSA_PUBKEY, Rsa);
i2d_shim!(i2d_void_rsa_pubkey, i2d_RSA_PUBKEY, Rsa);
d2i_shim!(d2i_void_dsa_pubkey, d2i_DSA_PUBKEY, Dsa);
i2d_shim!(i2d_void_dsa_pubkey, i2d_DSA_PUBKEY, Dsa);
d2i_shim!(d2i_void_ec_pubkey, d2i_EC_PUBKEY, EcKey);
i2d_shim!(i2d_void_ec_pubkey, i2d_EC_PUBKEY, EcKey);
i2d_shim!(i2d_void_pubkey, i2d_PUBKEY, EvpPkey);

/// The shared body of every plain writer: one `PEM_ASN1_write`.
///
/// # Safety
/// `out` writable; `name` NUL-terminated; `x` live and `i2d` its encoder.
unsafe fn plain_write(
    i2d: I2dOfVoid,
    name: *const c_char,
    out: *mut c_void,
    x: *const c_void,
) -> c_int {
    // SAFETY: the caller's contract; the two NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write(
            Some(i2d),
            name,
            out,
            x,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// The shared body of every plain BIO writer: one `PEM_ASN1_write_bio`.
///
/// # Safety
/// `out` a live BIO; `name` NUL-terminated; `x` live and `i2d` its encoder.
unsafe fn plain_write_bio(
    i2d: I2dOfVoid,
    name: *const c_char,
    out: *mut Bio,
    x: *const c_void,
) -> c_int {
    // SAFETY: the caller's contract; the two NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            name,
            out,
            x,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(X509_REQ, X509_REQ, PEM_STRING_X509_REQ, X509_REQ)` — `pem_all.c:37`.
// ---------------------------------------------------------------------------------------------

/// `X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:37`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_REQ(
    fp: *mut c_void,
    x: *mut *mut X509Req,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Req {
    // SAFETY: `d2i_X509_REQ` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_x509_req, PEM_STRING_X509_REQ, fp, x.cast(), cb, u) }
        .cast::<X509Req>()
}

/// `X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:37`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_REQ(
    bp: *mut Bio,
    x: *mut *mut X509Req,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Req {
    // SAFETY: `d2i_X509_REQ` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_x509_req, PEM_STRING_X509_REQ, bp, x.cast(), cb, u) }
        .cast::<X509Req>()
}

/// `int PEM_write_X509_REQ(FILE *out, const X509_REQ *x)` — `crypto/pem/pem_all.c:37`.
///
/// # Safety
/// `out` an open writable stream; `x` a live request.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_REQ(out: *mut c_void, x: *const X509Req) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_req` is the encoder.
    unsafe { plain_write(i2d_void_x509_req, PEM_STRING_X509_REQ, out, x.cast()) }
}

/// `int PEM_write_bio_X509_REQ(BIO *out, const X509_REQ *x)` — `crypto/pem/pem_all.c:37`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live request.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_REQ(out: *mut Bio, x: *const X509Req) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_req` is the encoder.
    unsafe { plain_write_bio(i2d_void_x509_req, PEM_STRING_X509_REQ, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write(X509_REQ_NEW, X509_REQ, PEM_STRING_X509_REQ_OLD, X509_REQ)` —
// `pem_all.c:39`. The old `"NEW CERTIFICATE REQUEST"` header, writers only.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_X509_REQ_NEW(FILE *out, const X509_REQ *x)` — `crypto/pem/pem_all.c:39`.
///
/// # Safety
/// `out` an open writable stream; `x` a live request.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_REQ_NEW(out: *mut c_void, x: *const X509Req) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_req` is the encoder.
    unsafe { plain_write(i2d_void_x509_req, PEM_STRING_X509_REQ_OLD, out, x.cast()) }
}

/// `int PEM_write_bio_X509_REQ_NEW(BIO *out, const X509_REQ *x)` — `crypto/pem/pem_all.c:39`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live request.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_REQ_NEW(out: *mut Bio, x: *const X509Req) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_req` is the encoder.
    unsafe { plain_write_bio(i2d_void_x509_req, PEM_STRING_X509_REQ_OLD, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(X509_CRL, X509_CRL, PEM_STRING_X509_CRL, X509_CRL)` — `pem_all.c:40`.
// ---------------------------------------------------------------------------------------------

/// `X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:40`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_CRL(
    fp: *mut c_void,
    x: *mut *mut X509Crl,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Crl {
    // SAFETY: `d2i_X509_CRL` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_x509_crl, PEM_STRING_X509_CRL, fp, x.cast(), cb, u) }
        .cast::<X509Crl>()
}

/// `X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:40`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_CRL(
    bp: *mut Bio,
    x: *mut *mut X509Crl,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Crl {
    // SAFETY: `d2i_X509_CRL` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_x509_crl, PEM_STRING_X509_CRL, bp, x.cast(), cb, u) }
        .cast::<X509Crl>()
}

/// `int PEM_write_X509_CRL(FILE *out, const X509_CRL *x)` — `crypto/pem/pem_all.c:40`.
///
/// # Safety
/// `out` an open writable stream; `x` a live CRL.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_CRL(out: *mut c_void, x: *const X509Crl) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_crl` is the encoder.
    unsafe { plain_write(i2d_void_x509_crl, PEM_STRING_X509_CRL, out, x.cast()) }
}

/// `int PEM_write_bio_X509_CRL(BIO *out, const X509_CRL *x)` — `crypto/pem/pem_all.c:40`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live CRL.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_CRL(out: *mut Bio, x: *const X509Crl) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_crl` is the encoder.
    unsafe { plain_write_bio(i2d_void_x509_crl, PEM_STRING_X509_CRL, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(X509_PUBKEY, X509_PUBKEY, PEM_STRING_PUBLIC, X509_PUBKEY)` — `pem_all.c:41`.
// The `write_bio` half is already landed in `src/pem/pem_lib.rs` (Phase 10.3); the other three
// names are here.
// ---------------------------------------------------------------------------------------------

/// `X509_PUBKEY *PEM_read_X509_PUBKEY(FILE *fp, X509_PUBKEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:41`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_PUBKEY(
    fp: *mut c_void,
    x: *mut *mut X509Pubkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Pubkey {
    // SAFETY: `d2i_X509_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_x509_pubkey, PEM_STRING_PUBLIC, fp, x.cast(), cb, u) }
        .cast::<X509Pubkey>()
}

/// `X509_PUBKEY *PEM_read_bio_X509_PUBKEY(BIO *bp, X509_PUBKEY **x, pem_password_cb *cb,
/// void *u)` — `crypto/pem/pem_all.c:41`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_PUBKEY(
    bp: *mut Bio,
    x: *mut *mut X509Pubkey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Pubkey {
    // SAFETY: `d2i_X509_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_x509_pubkey, PEM_STRING_PUBLIC, bp, x.cast(), cb, u) }
        .cast::<X509Pubkey>()
}

/// `int PEM_write_X509_PUBKEY(FILE *out, const X509_PUBKEY *x)` — `crypto/pem/pem_all.c:41`.
///
/// # Safety
/// `out` an open writable stream; `x` a live `X509_PUBKEY`.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_PUBKEY(out: *mut c_void, x: *const X509Pubkey) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_x509_pubkey` is the encoder.
    unsafe { plain_write(i2d_void_x509_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE, PEM_STRING_X509,
// NETSCAPE_CERT_SEQUENCE)` — `pem_all.c:44`.
// ---------------------------------------------------------------------------------------------

/// `NETSCAPE_CERT_SEQUENCE *PEM_read_NETSCAPE_CERT_SEQUENCE(FILE *fp, NETSCAPE_CERT_SEQUENCE **x,
/// pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:44`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_NETSCAPE_CERT_SEQUENCE(
    fp: *mut c_void,
    x: *mut *mut NetScapeCertSequence,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut NetScapeCertSequence {
    // SAFETY: `d2i_NETSCAPE_CERT_SEQUENCE` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_nsseq, PEM_STRING_X509, fp, x.cast(), cb, u) }
        .cast::<NetScapeCertSequence>()
}

/// `NETSCAPE_CERT_SEQUENCE *PEM_read_bio_NETSCAPE_CERT_SEQUENCE(BIO *bp,
/// NETSCAPE_CERT_SEQUENCE **x, pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:44`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_NETSCAPE_CERT_SEQUENCE(
    bp: *mut Bio,
    x: *mut *mut NetScapeCertSequence,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut NetScapeCertSequence {
    // SAFETY: `d2i_NETSCAPE_CERT_SEQUENCE` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_nsseq, PEM_STRING_X509, bp, x.cast(), cb, u) }
        .cast::<NetScapeCertSequence>()
}

/// `int PEM_write_NETSCAPE_CERT_SEQUENCE(FILE *out, const NETSCAPE_CERT_SEQUENCE *x)` —
/// `crypto/pem/pem_all.c:44`.
///
/// # Safety
/// `out` an open writable stream; `x` a live sequence.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_NETSCAPE_CERT_SEQUENCE(
    out: *mut c_void,
    x: *const NetScapeCertSequence,
) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_nsseq` is the encoder.
    unsafe { plain_write(i2d_void_nsseq, PEM_STRING_X509, out, x.cast()) }
}

/// `int PEM_write_bio_NETSCAPE_CERT_SEQUENCE(BIO *out, const NETSCAPE_CERT_SEQUENCE *x)` —
/// `crypto/pem/pem_all.c:44`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live sequence.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_NETSCAPE_CERT_SEQUENCE(
    out: *mut Bio,
    x: *const NetScapeCertSequence,
) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_nsseq` is the encoder.
    unsafe { plain_write_bio(i2d_void_nsseq, PEM_STRING_X509, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(PKCS7, PKCS7, PEM_STRING_PKCS7, PKCS7)` — `pem_all.c:42`.
// ---------------------------------------------------------------------------------------------

/// `PEM_STRING_PKCS7` — `include/openssl/pem.h:47`.
const PEM_STRING_PKCS7: *const c_char = c"PKCS7".as_ptr();

/// `PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:42`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_PKCS7(
    fp: *mut c_void,
    x: *mut *mut Pkcs7,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Pkcs7 {
    // SAFETY: `d2i_PKCS7` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_pkcs7, PEM_STRING_PKCS7, fp, x.cast(), cb, u) }.cast::<Pkcs7>()
}

/// `PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:42`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_PKCS7(
    bp: *mut Bio,
    x: *mut *mut Pkcs7,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Pkcs7 {
    // SAFETY: `d2i_PKCS7` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_pkcs7, PEM_STRING_PKCS7, bp, x.cast(), cb, u) }
        .cast::<Pkcs7>()
}

/// `int PEM_write_PKCS7(FILE *out, const PKCS7 *x)` — `crypto/pem/pem_all.c:42`.
///
/// # Safety
/// `out` an open writable stream; `x` a live container.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PKCS7(out: *mut c_void, x: *const Pkcs7) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_pkcs7` is the encoder.
    unsafe { plain_write(i2d_void_pkcs7, PEM_STRING_PKCS7, out, x.cast()) }
}

/// `int PEM_write_bio_PKCS7(BIO *out, const PKCS7 *x)` — `crypto/pem/pem_all.c:42`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live container.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PKCS7(out: *mut Bio, x: *const Pkcs7) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_pkcs7` is the encoder.
    unsafe { plain_write_bio(i2d_void_pkcs7, PEM_STRING_PKCS7, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(RSA_PUBKEY, RSA, PEM_STRING_PUBLIC, RSA_PUBKEY)` — `pem_all.c:90`.
// ---------------------------------------------------------------------------------------------

/// `RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:90`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSA_PUBKEY(
    fp: *mut c_void,
    x: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `d2i_RSA_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_rsa_pubkey, PEM_STRING_PUBLIC, fp, x.cast(), cb, u) }
        .cast::<Rsa>()
}

/// `RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:90`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSA_PUBKEY(
    bp: *mut Bio,
    x: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `d2i_RSA_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_rsa_pubkey, PEM_STRING_PUBLIC, bp, x.cast(), cb, u) }
        .cast::<Rsa>()
}

/// `int PEM_write_RSA_PUBKEY(FILE *out, const RSA *x)` — `crypto/pem/pem_all.c:90`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSA_PUBKEY(out: *mut c_void, x: *const Rsa) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_rsa_pubkey` is the encoder.
    unsafe { plain_write(i2d_void_rsa_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

/// `int PEM_write_bio_RSA_PUBKEY(BIO *out, const RSA *x)` — `crypto/pem/pem_all.c:90`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSA_PUBKEY(out: *mut Bio, x: *const Rsa) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_rsa_pubkey` is the encoder.
    unsafe { plain_write_bio(i2d_void_rsa_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(DSA_PUBKEY, DSA, PEM_STRING_PUBLIC, DSA_PUBKEY)` — `pem_all.c:118`.
// ---------------------------------------------------------------------------------------------

/// `DSA *PEM_read_DSA_PUBKEY(FILE *fp, DSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:118`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSA_PUBKEY(
    fp: *mut c_void,
    x: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `d2i_DSA_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_dsa_pubkey, PEM_STRING_PUBLIC, fp, x.cast(), cb, u) }
        .cast::<Dsa>()
}

/// `DSA *PEM_read_bio_DSA_PUBKEY(BIO *bp, DSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:118`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSA_PUBKEY(
    bp: *mut Bio,
    x: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `d2i_DSA_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_dsa_pubkey, PEM_STRING_PUBLIC, bp, x.cast(), cb, u) }
        .cast::<Dsa>()
}

/// `int PEM_write_DSA_PUBKEY(FILE *out, const DSA *x)` — `crypto/pem/pem_all.c:118`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSA_PUBKEY(out: *mut c_void, x: *const Dsa) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_dsa_pubkey` is the encoder.
    unsafe { plain_write(i2d_void_dsa_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

/// `int PEM_write_bio_DSA_PUBKEY(BIO *out, const DSA *x)` — `crypto/pem/pem_all.c:118`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSA_PUBKEY(out: *mut Bio, x: *const Dsa) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_dsa_pubkey` is the encoder.
    unsafe { plain_write_bio(i2d_void_dsa_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(EC_PUBKEY, EC_KEY, PEM_STRING_PUBLIC, EC_PUBKEY)` — `pem_all.c:163`.
// ---------------------------------------------------------------------------------------------

/// `EC_KEY *PEM_read_EC_PUBKEY(FILE *fp, EC_KEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:163`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_EC_PUBKEY(
    fp: *mut c_void,
    x: *mut *mut EcKey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcKey {
    // SAFETY: `d2i_EC_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_ec_pubkey, PEM_STRING_PUBLIC, fp, x.cast(), cb, u) }
        .cast::<EcKey>()
}

/// `EC_KEY *PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:163`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_EC_PUBKEY(
    bp: *mut Bio,
    x: *mut *mut EcKey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcKey {
    // SAFETY: `d2i_EC_PUBKEY` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_ec_pubkey, PEM_STRING_PUBLIC, bp, x.cast(), cb, u) }
        .cast::<EcKey>()
}

/// `int PEM_write_EC_PUBKEY(FILE *out, const EC_KEY *x)` — `crypto/pem/pem_all.c:163`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_EC_PUBKEY(out: *mut c_void, x: *const EcKey) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_ec_pubkey` is the encoder.
    unsafe { plain_write(i2d_void_ec_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

/// `int PEM_write_bio_EC_PUBKEY(BIO *out, const EC_KEY *x)` — `crypto/pem/pem_all.c:163`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_EC_PUBKEY(out: *mut Bio, x: *const EcKey) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_ec_pubkey` is the encoder.
    unsafe { plain_write_bio(i2d_void_ec_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_provided_write(PUBKEY, EVP_PKEY, pkey, PEM_STRING_PUBLIC, PUBKEY)` —
// `pem_all.c:225`, expanding `pem_local.h:95-110`.
// ---------------------------------------------------------------------------------------------

/// The `legacy:` fallback every `PUBKEY` writer shares: `PEM_ASN1_write` over `i2d_PUBKEY`.
///
/// # Safety
/// `out` writable; `x` a live key.
unsafe fn pubkey_legacy_fp(out: *mut c_void, x: *const EvpPkey) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_pubkey` is the encoder.
    unsafe { plain_write(i2d_void_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

/// The BIO spelling of [`pubkey_legacy_fp`].
///
/// # Safety
/// `out` a live BIO; `x` a live key.
unsafe fn pubkey_legacy_bio(out: *mut Bio, x: *const EvpPkey) -> c_int {
    // SAFETY: `out`/`x` are the caller's and `i2d_void_pubkey` is the encoder.
    unsafe { plain_write_bio(i2d_void_pubkey, PEM_STRING_PUBLIC, out, x.cast()) }
}

/// `int PEM_write_PUBKEY(FILE *out, const EVP_PKEY *x)` — `crypto/pem/pem_all.c:225`'s
/// `IMPLEMENT_PEM_provided_write_fp`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PUBKEY(out: *mut c_void, x: *const EvpPkey) -> c_int {
    // SAFETY: `x` is the caller's live key and the two strings are literals; the property argument
    // is the macro's NULL.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_PUBLIC_KEY,
            c"PEM".as_ptr(),
            PEM_STRUCTURE_PUBKEY,
            ptr::null(),
        )
    };
    // SAFETY: `ctx` is NULL or live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: `ctx` is NULL or this frame's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: as `pubkey_legacy_fp`.
        return unsafe { pubkey_legacy_fp(out, x) };
    }
    // SAFETY: `ctx` is live and `out` is the caller's.
    let ret = unsafe { OSSL_ENCODER_to_fp(ctx, out) };
    // SAFETY: `ctx` is this frame's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// `int PEM_write_bio_PUBKEY(BIO *out, const EVP_PKEY *x)` — `crypto/pem/pem_all.c:225`'s
/// `IMPLEMENT_PEM_provided_write_bio`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PUBKEY(out: *mut Bio, x: *const EvpPkey) -> c_int {
    // SAFETY: `x` is the caller's live key and the two strings are literals; the property argument
    // is the macro's NULL.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_PUBLIC_KEY,
            c"PEM".as_ptr(),
            PEM_STRUCTURE_PUBKEY,
            ptr::null(),
        )
    };
    // SAFETY: `ctx` is NULL or live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: `ctx` is NULL or this frame's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: as `pubkey_legacy_bio`.
        return unsafe { pubkey_legacy_bio(out, x) };
    }
    // SAFETY: `ctx` is live and `out` is the caller's.
    let ret = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
    // SAFETY: `ctx` is this frame's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// `int PEM_write_PUBKEY_ex(FILE *out, const EVP_PKEY *x, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/pem/pem_all.c:225`'s `IMPLEMENT_PEM_provided_write_ex_fp`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_PUBKEY_ex(
    out: *mut c_void,
    x: *const EvpPkey,
    _libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `x` is the caller's live key, the two strings are literals, `propq` is the caller's.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_PUBLIC_KEY,
            c"PEM".as_ptr(),
            PEM_STRUCTURE_PUBKEY,
            propq,
        )
    };
    // SAFETY: `ctx` is NULL or live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: `ctx` is NULL or this frame's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: as `pubkey_legacy_fp`.
        return unsafe { pubkey_legacy_fp(out, x) };
    }
    // SAFETY: `ctx` is live and `out` is the caller's.
    let ret = unsafe { OSSL_ENCODER_to_fp(ctx, out) };
    // SAFETY: `ctx` is this frame's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// `int PEM_write_bio_PUBKEY_ex(BIO *out, const EVP_PKEY *x, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/pem/pem_all.c:225`'s `IMPLEMENT_PEM_provided_write_ex_bio`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_PUBKEY_ex(
    out: *mut Bio,
    x: *const EvpPkey,
    _libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `x` is the caller's live key, the two strings are literals, `propq` is the caller's.
    let ctx = unsafe {
        OSSL_ENCODER_CTX_new_for_pkey(
            x,
            EVP_PKEY_PUBLIC_KEY,
            c"PEM".as_ptr(),
            PEM_STRUCTURE_PUBKEY,
            propq,
        )
    };
    // SAFETY: `ctx` is NULL or live.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: `ctx` is NULL or this frame's own.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        // SAFETY: as `pubkey_legacy_bio`.
        return unsafe { pubkey_legacy_bio(out, x) };
    }
    // SAFETY: `ctx` is live and `out` is the caller's.
    let ret = unsafe { OSSL_ENCODER_to_bio(ctx, out) };
    // SAFETY: `ctx` is this frame's own.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}
