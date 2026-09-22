//! Phase 8.9 — `crypto/pem/pem_all.c`: the `pem.h` helpers Phase 8 owns, written out.
//!
//! `crypto/pem/pem_all.c` has no function bodies worth the name: it is 225 lines of
//! `IMPLEMENT_PEM_*` invocations whose macro expansion is the whole file. The crate has no C
//! preprocessor, so this module is the **expansion** — each of the thirty `pem.h` names Phase 8
//! owns is a `#[no_mangle]` function whose body is the one `PEM_ASN1_read` /
//! `PEM_ASN1_read_bio` / `PEM_ASN1_write` / `PEM_ASN1_write_bio` call the macro produced, with
//! the `(d2i_of_void *)`/`(i2d_of_void *)` cast the macro spells written as a Rust function
//! pointer cast at the call site.
//!
//! ```text
//! IMPLEMENT_PEM_rw(name, TYPE, str, ASN1)       read + write, both spellings, plain writers
//! IMPLEMENT_PEM_write(name, TYPE, str, ASN1)    both writers, no readers
//! IMPLEMENT_PEM_write_cb(name, TYPE, str, ASN1) both writers, the pass-phrase callback form
//! ```
//!
//! ## The six private-key readers, and what they waited on
//!
//! `pem_all.c` defines six readers by hand rather than through the macros —
//! `PEM_read_RSAPrivateKey`, `PEM_read_bio_RSAPrivateKey`, `PEM_read_DSAPrivateKey`,
//! `PEM_read_bio_DSAPrivateKey`, `PEM_read_ECPrivateKey` and `PEM_read_bio_ECPrivateKey` — and
//! each is `PEM_read[_bio]_PrivateKey` followed by one of the file's three `pkey_get_*`
//! helpers (`:53`, `:93`, `:134`). **D369 lands all six**: the helpers call
//! `EVP_PKEY_get1_RSA`/`_get1_DSA`/`_get1_EC_KEY`, which landed with the 8.8 ameth slice
//! (D353), and the `PEM_read_*PrivateKey` pair they wrap is now in `src/pem/pem_pkey.rs`,
//! whose last missing callee was `ossl_d2i_PUBKEY_legacy` (D369, item 1). The three
//! `pkey_get_*` helpers are transcribed here beside them, each taking ownership of the key it
//! is handed.
//!
//! ## The one `EC_PUBKEY` and `DSA_PUBKEY` asymmetry
//!
//! `crypto/pem/pem_all.c` also expands `IMPLEMENT_PEM_rw(DSA_PUBKEY, ...)`,
//! `IMPLEMENT_PEM_rw(EC_PUBKEY, ...)`, `IMPLEMENT_PEM_rw(RSA_PUBKEY, ...)` and the four
//! `IMPLEMENT_PEM_rw(X509_*)`, and those ten readers/writers are **not here** because they are
//! not Phase 8's: `symbol-ownership.json` assigns their `pem.h` declarations to Phase 11. Their
//! `d2i_`/`i2d_` pairs — `d2i_DSA_PUBKEY`/`i2d_DSA_PUBKEY`, `d2i_EC_PUBKEY`/`i2d_EC_PUBKEY` and
//! `d2i_RSA_PUBKEY`/`i2d_RSA_PUBKEY` — **landed with D369's completion of
//! `crypto/x509/x_pubkey.c`**, so the ten are transcribable now and remain Phase 11's to write;
//! the sentence D349 wrote here ("they reach ... which are Phase 11's and unlanded") is
//! corrected rather than kept, because the second half is no longer true. This module is a
//! partial one in the shape of `src/rsa/asn1.rs`: it lands every row Phase 8 owns and names the
//! rest.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::I2dOfVoid;
use crate::dh::asn1::{d2i_DHparams, d2i_DHxparams, i2d_DHparams, i2d_DHxparams};
use crate::dh::Dh;
use crate::dsa::asn1::{d2i_DSAparams, i2d_DSAPrivateKey, i2d_DSAparams};
use crate::dsa::object::DSA_free;
use crate::dsa::Dsa;
use crate::ec::asn1::{d2i_ECPKParameters, i2d_ECPKParameters, i2d_ECPrivateKey};
use crate::ec::key::EC_KEY_free;
use crate::ec::{EcGroup, EcKey};
use crate::evp::cipher::EvpCipher;
use crate::evp::p_legacy_assign::EVP_PKEY_get1_EC_KEY;
use crate::evp::pem_bridge::PemPasswordCb;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get1_DSA, EvpPkey};
use crate::pem::pem_lib::{
    PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio, PEM_STRING_DHPARAMS, PEM_STRING_DHXPARAMS,
    PEM_STRING_DSA, PEM_STRING_DSAPARAMS, PEM_STRING_ECPARAMETERS, PEM_STRING_ECPRIVATEKEY,
    PEM_STRING_RSA, PEM_STRING_RSA_PUBLIC,
};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::pem::pem_pkey::{PEM_read_PrivateKey, PEM_read_bio_PrivateKey};
use crate::rsa::asn1::{d2i_RSAPublicKey, i2d_RSAPrivateKey, i2d_RSAPublicKey};
use crate::rsa::object::RSA_free;
use crate::rsa::Rsa;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;

/// The `(d2i_of_void *)d2i_RSAPublicKey` cast the `IMPLEMENT_PEM_read_*` macros spell.
///
/// C casts the typed decoder function pointer to the `void *`-based type the reader takes, and
/// the reader casts its arguments back. Rust has no such cast between function pointer types, so
/// each is a one-line shim that performs the same two `void *` conversions and calls the typed
/// function. One shim per decoder/encoder the twenty-four expansions name.
///
/// # Safety
/// The `void *` arguments must be the typed decoder's own arguments, which is what the reader's
/// call site guarantees.
unsafe extern "C" fn d2i_void_rsa_public_key(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_RSAPublicKey(a.cast::<*mut Rsa>(), in_, len).cast::<c_void>() }
}

/// `(d2i_of_void *)d2i_DSAparams`.
///
/// # Safety
/// As [`d2i_void_rsa_public_key`].
unsafe extern "C" fn d2i_void_dsa_params(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_DSAparams(a.cast::<*mut Dsa>(), in_, len).cast::<c_void>() }
}

/// `(d2i_of_void *)d2i_ECPKParameters`.
///
/// # Safety
/// As [`d2i_void_rsa_public_key`].
unsafe extern "C" fn d2i_void_ecpk_parameters(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_ECPKParameters(a.cast::<*mut EcGroup>(), in_, len).cast::<c_void>() }
}

/// `(i2d_of_void *)i2d_RSAPublicKey`.
///
/// # Safety
/// `x` must be live and `out` the encoder's own cursor.
unsafe extern "C" fn i2d_void_rsa_public_key(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_RSAPublicKey(x.cast::<Rsa>(), out) }
}

/// `(i2d_of_void *)i2d_RSAPrivateKey`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_rsa_private_key(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_RSAPrivateKey(x.cast::<Rsa>(), out) }
}

/// `(i2d_of_void *)i2d_DSAPrivateKey`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_dsa_private_key(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_DSAPrivateKey(x.cast::<Dsa>(), out) }
}

/// `(i2d_of_void *)i2d_DSAparams`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_dsa_params(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_DSAparams(x.cast::<Dsa>(), out) }
}

/// `(i2d_of_void *)i2d_ECPKParameters`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_ecpk_parameters(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_ECPKParameters(x.cast::<EcGroup>(), out) }
}

/// `(i2d_of_void *)i2d_ECPrivateKey`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_ec_private_key(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_ECPrivateKey(x.cast::<EcKey>(), out) }
}

/// `(i2d_of_void *)i2d_DHparams`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_dh_params(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_DHparams(x.cast::<Dh>(), out) }
}

/// `(i2d_of_void *)i2d_DHxparams`.
///
/// # Safety
/// As [`i2d_void_rsa_public_key`].
unsafe extern "C" fn i2d_void_dhx_params(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_DHxparams(x.cast::<Dh>(), out) }
}

/// The `PEM_ASN1_write_bio` body the three plain writers share, with `enc` and the pass phrase
/// all NULL — which is what the `IMPLEMENT_PEM_write`/`IMPLEMENT_PEM_write_bio` macros spell and
/// the reason a plain writer never reaches `PEM_def_callback`.
///
/// # Safety
/// `bp` a live writable BIO; `name` NUL-terminated; `x` the object `i2d` reads.
unsafe fn plain_write_bio(
    i2d: I2dOfVoid,
    name: *const c_char,
    bp: *mut Bio,
    x: *const c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            name,
            bp,
            x,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// The `PEM_ASN1_write` body the three plain `FILE *` writers share; see [`plain_write_bio`].
///
/// # Safety
/// `fp` an open writable stream; `name` NUL-terminated; `x` the object `i2d` reads.
unsafe fn plain_write_fp(
    i2d: I2dOfVoid,
    name: *const c_char,
    fp: *mut c_void,
    x: *const c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        PEM_ASN1_write(
            Some(i2d),
            name,
            fp,
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
// `IMPLEMENT_PEM_rw(RSAPublicKey, RSA, PEM_STRING_RSA_PUBLIC, RSAPublicKey)` — `pem_all.c:89`.
// ---------------------------------------------------------------------------------------------

/// `RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:89`'s `IMPLEMENT_PEM_read_fp`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSAPublicKey(
    fp: *mut c_void,
    x: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `d2i_RSAPublicKey` is the RSA public-key decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read(
            d2i_void_rsa_public_key,
            PEM_STRING_RSA_PUBLIC,
            fp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<Rsa>()
}

/// `RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:89`'s `IMPLEMENT_PEM_read_bio`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSAPublicKey(
    bp: *mut Bio,
    x: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `d2i_RSAPublicKey` is the RSA public-key decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read_bio(
            d2i_void_rsa_public_key,
            PEM_STRING_RSA_PUBLIC,
            bp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<Rsa>()
}

/// `int PEM_write_RSAPublicKey(FILE *out, const RSA *x)` — `crypto/pem/pem_all.c:89`'s
/// `IMPLEMENT_PEM_write_fp`.
///
/// # Safety
/// `out` an open writable stream; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSAPublicKey(out: *mut c_void, x: *const Rsa) -> c_int {
    // SAFETY: `i2d_RSAPublicKey` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_fp(
            i2d_void_rsa_public_key,
            PEM_STRING_RSA_PUBLIC,
            out,
            x.cast::<c_void>(),
        )
    }
}

/// `int PEM_write_bio_RSAPublicKey(BIO *out, const RSA *x)` — `crypto/pem/pem_all.c:89`'s
/// `IMPLEMENT_PEM_write_bio`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSAPublicKey(out: *mut Bio, x: *const Rsa) -> c_int {
    // SAFETY: `i2d_RSAPublicKey` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_bio(
            i2d_void_rsa_public_key,
            PEM_STRING_RSA_PUBLIC,
            out,
            x.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write_cb(RSAPrivateKey, RSA, PEM_STRING_RSA, RSAPrivateKey)` — `pem_all.c:88`.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_RSAPrivateKey(FILE *out, const RSA *x, const EVP_CIPHER *enc,
/// const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:88`'s
/// `IMPLEMENT_PEM_write_cb_fp`.
///
/// # Safety
/// As [`PEM_ASN1_write`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_RSAPrivateKey(
    out: *mut c_void,
    x: *const Rsa,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_RSAPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void_rsa_private_key),
            PEM_STRING_RSA,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

/// `int PEM_write_bio_RSAPrivateKey(BIO *out, const RSA *x, const EVP_CIPHER *enc,
/// const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:88`'s
/// `IMPLEMENT_PEM_write_cb_bio`.
///
/// # Safety
/// As [`PEM_ASN1_write_bio`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_RSAPrivateKey(
    out: *mut Bio,
    x: *const Rsa,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_RSAPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void_rsa_private_key),
            PEM_STRING_RSA,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write_cb(DSAPrivateKey, DSA, PEM_STRING_DSA, DSAPrivateKey)` — `pem_all.c:117`.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_DSAPrivateKey(FILE *out, const DSA *x, const EVP_CIPHER *enc,
/// const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:117`.
///
/// # Safety
/// As [`PEM_ASN1_write`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSAPrivateKey(
    out: *mut c_void,
    x: *const Dsa,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_DSAPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void_dsa_private_key),
            PEM_STRING_DSA,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

/// `int PEM_write_bio_DSAPrivateKey(BIO *out, const DSA *x, ...)` — `crypto/pem/pem_all.c:117`.
///
/// # Safety
/// As [`PEM_ASN1_write_bio`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSAPrivateKey(
    out: *mut Bio,
    x: *const Dsa,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_DSAPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void_dsa_private_key),
            PEM_STRING_DSA,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(DSAparams, DSA, PEM_STRING_DSAPARAMS, DSAparams)` — `pem_all.c:129`.
// ---------------------------------------------------------------------------------------------

/// `DSA *PEM_read_DSAparams(FILE *fp, DSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:129`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSAparams(
    fp: *mut c_void,
    x: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `d2i_DSAparams` is the DSA parameter decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read(
            d2i_void_dsa_params,
            PEM_STRING_DSAPARAMS,
            fp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<Dsa>()
}

/// `DSA *PEM_read_bio_DSAparams(BIO *bp, DSA **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:129`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSAparams(
    bp: *mut Bio,
    x: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `d2i_DSAparams` is the DSA parameter decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read_bio(
            d2i_void_dsa_params,
            PEM_STRING_DSAPARAMS,
            bp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<Dsa>()
}

/// `int PEM_write_DSAparams(FILE *out, const DSA *x)` — `crypto/pem/pem_all.c:129`.
///
/// # Safety
/// `out` an open writable stream; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DSAparams(out: *mut c_void, x: *const Dsa) -> c_int {
    // SAFETY: `i2d_DSAparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_fp(
            i2d_void_dsa_params,
            PEM_STRING_DSAPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

/// `int PEM_write_bio_DSAparams(BIO *out, const DSA *x)` — `crypto/pem/pem_all.c:129`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DSAparams(out: *mut Bio, x: *const Dsa) -> c_int {
    // SAFETY: `i2d_DSAparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_bio(
            i2d_void_dsa_params,
            PEM_STRING_DSAPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(ECPKParameters, EC_GROUP, PEM_STRING_ECPARAMETERS, ECPKParameters)`
// — `pem_all.c:158`.
// ---------------------------------------------------------------------------------------------

/// `EC_GROUP *PEM_read_ECPKParameters(FILE *fp, EC_GROUP **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:158`.
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_ECPKParameters(
    fp: *mut c_void,
    x: *mut *mut EcGroup,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcGroup {
    // SAFETY: `d2i_ECPKParameters` is the decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read(
            d2i_void_ecpk_parameters,
            PEM_STRING_ECPARAMETERS,
            fp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<EcGroup>()
}

/// `EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:158`.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_ECPKParameters(
    bp: *mut Bio,
    x: *mut *mut EcGroup,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcGroup {
    // SAFETY: `d2i_ECPKParameters` is the decoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_read_bio(
            d2i_void_ecpk_parameters,
            PEM_STRING_ECPARAMETERS,
            bp,
            x.cast::<*mut c_void>(),
            cb,
            u,
        )
    }
    .cast::<EcGroup>()
}

/// `int PEM_write_ECPKParameters(FILE *out, const EC_GROUP *x)` — `crypto/pem/pem_all.c:158`.
///
/// # Safety
/// `out` an open writable stream; `x` a live group.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_ECPKParameters(out: *mut c_void, x: *const EcGroup) -> c_int {
    // SAFETY: `i2d_ECPKParameters` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_fp(
            i2d_void_ecpk_parameters,
            PEM_STRING_ECPARAMETERS,
            out,
            x.cast::<c_void>(),
        )
    }
}

/// `int PEM_write_bio_ECPKParameters(BIO *out, const EC_GROUP *x)` — `crypto/pem/pem_all.c:158`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live group.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_ECPKParameters(out: *mut Bio, x: *const EcGroup) -> c_int {
    // SAFETY: `i2d_ECPKParameters` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_bio(
            i2d_void_ecpk_parameters,
            PEM_STRING_ECPARAMETERS,
            out,
            x.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write_cb(ECPrivateKey, EC_KEY, PEM_STRING_ECPRIVATEKEY, ECPrivateKey)`
// — `pem_all.c:161`.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_ECPrivateKey(FILE *out, const EC_KEY *x, const EVP_CIPHER *enc,
/// const unsigned char *kstr, int klen, pem_password_cb *cb, void *u)` — `crypto/pem/pem_all.c:161`.
///
/// # Safety
/// As [`PEM_ASN1_write`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_ECPrivateKey(
    out: *mut c_void,
    x: *const EcKey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_ECPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void_ec_private_key),
            PEM_STRING_ECPRIVATEKEY,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

/// `int PEM_write_bio_ECPrivateKey(BIO *out, const EC_KEY *x, ...)` — `crypto/pem/pem_all.c:161`.
///
/// # Safety
/// As [`PEM_ASN1_write_bio`].
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_ECPrivateKey(
    out: *mut Bio,
    x: *const EcKey,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `i2d_ECPrivateKey` is the encoder and the arguments are the caller's.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void_ec_private_key),
            PEM_STRING_ECPRIVATEKEY,
            out,
            x.cast::<c_void>(),
            enc,
            kstr,
            klen,
            cb,
            u,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write(DHparams, DH, PEM_STRING_DHPARAMS, DHparams)` — `pem_all.c:178`.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_DHparams(FILE *out, const DH *x)` — `crypto/pem/pem_all.c:178`.
///
/// # Safety
/// `out` an open writable stream; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DHparams(out: *mut c_void, x: *const Dh) -> c_int {
    // SAFETY: `i2d_DHparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_fp(
            i2d_void_dh_params,
            PEM_STRING_DHPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

/// `int PEM_write_bio_DHparams(BIO *out, const DH *x)` — `crypto/pem/pem_all.c:178`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DHparams(out: *mut Bio, x: *const Dh) -> c_int {
    // SAFETY: `i2d_DHparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_bio(
            i2d_void_dh_params,
            PEM_STRING_DHPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_write(DHxparams, DH, PEM_STRING_DHXPARAMS, DHxparams)` — `pem_all.c:179`.
// ---------------------------------------------------------------------------------------------

/// `int PEM_write_DHxparams(FILE *out, const DH *x)` — `crypto/pem/pem_all.c:179`.
///
/// # Safety
/// `out` an open writable stream; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_DHxparams(out: *mut c_void, x: *const Dh) -> c_int {
    // SAFETY: `i2d_DHxparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_fp(
            i2d_void_dhx_params,
            PEM_STRING_DHXPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

/// `int PEM_write_bio_DHxparams(BIO *out, const DH *x)` — `crypto/pem/pem_all.c:179`.
///
/// # Safety
/// `out` a live writable BIO; `x` a live parameter set.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_DHxparams(out: *mut Bio, x: *const Dh) -> c_int {
    // SAFETY: `i2d_DHxparams` is the encoder and `out`/`x` are the caller's.
    unsafe {
        plain_write_bio(
            i2d_void_dhx_params,
            PEM_STRING_DHXPARAMS,
            out,
            x.cast::<c_void>(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// `PEM_read_bio_DHparams` and `PEM_read_DHparams`, the two hand-written readers — `pem_all.c:183`.
// ---------------------------------------------------------------------------------------------

/// `DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:183-205`.
///
/// The one reader that is neither a macro expansion nor a `pkey_get_*` wrapper: it asks for the
/// **`DH PARAMETERS`** name, and then chooses the decoder from the name actually found, so an
/// `X9.42 DH PARAMETERS` block is read as `d2i_DHxparams` and a `DH PARAMETERS` block as
/// `d2i_DHparams`. The match is what `check_pem`'s DH arm exists for.
///
/// # Safety
/// `bp` a live readable BIO; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DHparams(
    bp: *mut Bio,
    x: *mut *mut Dh,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dh {
    let mut nm: *mut c_char = ptr::null_mut();
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;

    // SAFETY: `bp` is live and the three out-parameters are this frame's own.
    if unsafe {
        crate::pem::pem_lib::PEM_bytes_read_bio(
            &mut data,
            &mut len,
            &mut nm,
            PEM_STRING_DHPARAMS,
            bp,
            cb,
            u,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    let mut p: *const c_uchar = data;

    // SAFETY: `nm` is the name the reader allocated and is NUL-terminated.
    let ret = if unsafe { crate::runtime::bio::sys::strcmp(nm, PEM_STRING_DHXPARAMS) } == 0 {
        // SAFETY: `x` is the destination, `p` is readable for `len` bytes, and the decoder is
        // `d2i_DHxparams`.
        unsafe { d2i_DHxparams(x, &mut p, len) }
    } else {
        // SAFETY: as above, with `d2i_DHparams`.
        unsafe { d2i_DHparams(x, &mut p, len) }
    };

    if ret.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_ALL_201) };
    }
    // SAFETY: `nm` and `data` are the reader's buffers for this call.
    unsafe {
        CRYPTO_free(nm.cast::<c_void>(), FILE, LINE_ALL_202);
        CRYPTO_free(data.cast::<c_void>(), FILE, LINE_ALL_203);
    }
    ret
}

/// `DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:208-221`.
///
/// The `FILE *` spelling of [`PEM_read_bio_DHparams`].
///
/// # Safety
/// `fp` an open readable stream; `x` the decoder's destination; `cb`/`u` passed to the reader.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DHparams(
    fp: *mut c_void,
    x: *mut *mut Dh,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dh {
    // SAFETY: `BIO_s_file` is a static method table.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_ALL_214) };
        return ptr::null_mut();
    }
    // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
    // SAFETY: `b` is live and `fp` is the caller's stream.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, 0, fp) };
    // SAFETY: `b` is a live file BIO and the rest is the caller's.
    let ret = unsafe { PEM_read_bio_DHparams(b, x, cb, u) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `OPENSSL_FILE` at the two hand-written readers' sites (`crypto/pem/pem_all.c`).
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/pem/pem_all.c".as_ptr();
/// `PEM_read_bio_DHparams`'s `OPENSSL_free(nm)` (`pem_all.c:202`).
const LINE_ALL_202: c_int = 202;
/// `PEM_read_bio_DHparams`'s `OPENSSL_free(data)` (`pem_all.c:203`).
const LINE_ALL_203: c_int = 203;

// ---------------------------------------------------------------------------------------------
// The six private-key readers and the three `pkey_get_*` helpers — `pem_all.c:46-171`
// ---------------------------------------------------------------------------------------------
//
// The three `pkey_get_*` helpers read an `EVP_PKEY` with `PEM_read[_bio]_PrivateKey` and hand back
// the low-level key it holds, so "traditional" and PKCS#8 blocks are both readable through them.
// D369 lands them: the only two names they waited on were `PEM_read[_bio]_PrivateKey`, which
// `src/pem/pem_pkey.rs` now carries, and `EVP_PKEY_get1_*`, which landed with the 8.8 ameth slice
// (D353). Each helper takes ownership of the key it is given and frees it on every path, which is
// why the `_PrivateKey` call passes a NULL out-slot rather than the caller's address.

/// `static RSA *pkey_get_rsa(EVP_PKEY *key, RSA **rsa)` — `crypto/pem/pem_all.c:53-67`.
///
/// # Safety
/// `key` is NULL or a live key this call takes ownership of; `rsa` is NULL or a writable slot.
unsafe fn pkey_get_rsa(key: *mut EvpPkey, rsa: *mut *mut Rsa) -> *mut Rsa {
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `key` is live per the contract.
    let rtmp = unsafe { crate::evp::p_legacy_assign::EVP_PKEY_get1_RSA(key) };
    // SAFETY: `key` is this call's own and is always released here.
    unsafe { EVP_PKEY_free(key) };
    if rtmp.is_null() {
        return ptr::null_mut();
    }
    if !rsa.is_null() {
        // SAFETY: `rsa` is a live slot.
        unsafe {
            RSA_free(*rsa);
            *rsa = rtmp;
        }
    }
    rtmp
}

/// `static DSA *pkey_get_dsa(EVP_PKEY *key, DSA **dsa)` — `crypto/pem/pem_all.c:93-107`.
///
/// # Safety
/// `key` is NULL or a live key this call takes ownership of; `dsa` is NULL or a writable slot.
unsafe fn pkey_get_dsa(key: *mut EvpPkey, dsa: *mut *mut Dsa) -> *mut Dsa {
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `key` is live per the contract.
    let dtmp = unsafe { EVP_PKEY_get1_DSA(key) };
    // SAFETY: `key` is this call's own and is always released here.
    unsafe { EVP_PKEY_free(key) };
    if dtmp.is_null() {
        return ptr::null_mut();
    }
    if !dsa.is_null() {
        // SAFETY: `dsa` is a live slot.
        unsafe {
            DSA_free(*dsa);
            *dsa = dtmp;
        }
    }
    dtmp
}

/// `static EC_KEY *pkey_get_eckey(EVP_PKEY *key, EC_KEY **eckey)` —
/// `crypto/pem/pem_all.c:134-148`.
///
/// # Safety
/// `key` is NULL or a live key this call takes ownership of; `eckey` is NULL or a writable slot.
unsafe fn pkey_get_eckey(key: *mut EvpPkey, eckey: *mut *mut EcKey) -> *mut EcKey {
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `key` is live per the contract.
    let dtmp = unsafe { EVP_PKEY_get1_EC_KEY(key) };
    // SAFETY: `key` is this call's own and is always released here.
    unsafe { EVP_PKEY_free(key) };
    if dtmp.is_null() {
        return ptr::null_mut();
    }
    if !eckey.is_null() {
        // SAFETY: `eckey` is a live slot.
        unsafe {
            EC_KEY_free(*eckey);
            *eckey = dtmp;
        }
    }
    dtmp
}

/// `RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:69-75`.
///
/// # Safety
/// `bp` a live readable BIO; `rsa` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_RSAPrivateKey(
    bp: *mut Bio,
    rsa: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `bp` is live and the rest is the caller's.
    let pktmp = unsafe { PEM_read_bio_PrivateKey(bp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `rsa` is the caller's slot.
    unsafe { pkey_get_rsa(pktmp, rsa) }
}

/// `RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **rsa, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:79-84`.
///
/// # Safety
/// `fp` an open readable stream; `rsa` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_RSAPrivateKey(
    fp: *mut c_void,
    rsa: *mut *mut Rsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Rsa {
    // SAFETY: `fp` is the caller's stream and the rest is the caller's.
    let pktmp = unsafe { PEM_read_PrivateKey(fp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `rsa` is the caller's slot.
    unsafe { pkey_get_rsa(pktmp, rsa) }
}

/// `DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **dsa, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:109-115`.
///
/// # Safety
/// `bp` a live readable BIO; `dsa` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_DSAPrivateKey(
    bp: *mut Bio,
    dsa: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `bp` is live and the rest is the caller's.
    let pktmp = unsafe { PEM_read_bio_PrivateKey(bp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `dsa` is the caller's slot.
    unsafe { pkey_get_dsa(pktmp, dsa) }
}

/// `DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **dsa, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:120-125`.
///
/// # Safety
/// `fp` an open readable stream; `dsa` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_DSAPrivateKey(
    fp: *mut c_void,
    dsa: *mut *mut Dsa,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `fp` is the caller's stream and the rest is the caller's.
    let pktmp = unsafe { PEM_read_PrivateKey(fp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `dsa` is the caller's slot.
    unsafe { pkey_get_dsa(pktmp, dsa) }
}

/// `EC_KEY *PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **key, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:150-156`.
///
/// # Safety
/// `bp` a live readable BIO; `key` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_ECPrivateKey(
    bp: *mut Bio,
    key: *mut *mut EcKey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcKey {
    // SAFETY: `bp` is live and the rest is the caller's.
    let pktmp = unsafe { PEM_read_bio_PrivateKey(bp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `key` is the caller's slot.
    unsafe { pkey_get_eckey(pktmp, key) }
}

/// `EC_KEY *PEM_read_ECPrivateKey(FILE *fp, EC_KEY **eckey, pem_password_cb *cb, void *u)` —
/// `crypto/pem/pem_all.c:165-171`.
///
/// # Safety
/// `fp` an open readable stream; `eckey` NULL or a writable slot; `cb`/`u` the pass-phrase pair.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_ECPrivateKey(
    fp: *mut c_void,
    eckey: *mut *mut EcKey,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut EcKey {
    // SAFETY: `fp` is the caller's stream and the rest is the caller's.
    let pktmp = unsafe { PEM_read_PrivateKey(fp, ptr::null_mut(), cb, u) };
    // SAFETY: `pktmp` is NULL or a key this call now owns; `eckey` is the caller's slot.
    unsafe { pkey_get_eckey(pktmp, eckey) }
}
