//! `crypto/pkcs12/p12_p8d.c` — the two `PKCS8_decrypt` spellings. Phase 10 (D368).
//!
//! Thirty-one lines: each function borrows the `X509_SIG`'s algorithm and encrypted octets with
//! `X509_SIG_get0`, then hands them to `PKCS12_item_decrypt_d2i_ex` with `zbuf` set — the
//! decrypted `PrivateKeyInfo` plaintext is Zeroed before it is released, because it is a private
//! key. `PKCS8_decrypt` is the `_ex` spelling with a null context, which is what
//! `pem_read_bio_key_legacy` calls.
//!
//! The unit raises nothing, so it is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`: an entry for it would read as coverage that
//! does not exist.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::p8_pkey::{PKCS8_PRIV_KEY_INFO_it, Pkcs8PrivKeyInfo};
use crate::asn1::x_algor::X509Algor;
use crate::asn1::x_sig::{X509Sig, X509_SIG_get0};
use crate::pkcs12::p12_decr::PKCS12_item_decrypt_d2i_ex;

/// `PKCS8_PRIV_KEY_INFO *PKCS8_decrypt_ex(const X509_SIG *p8, const char *pass, int passlen,
/// OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/pkcs12/p12_p8d.c:14-25`.
///
/// # Safety
/// `p8` must be a live `X509_SIG`; `pass` must be NULL or a string of `passlen` bytes (or
/// `passlen == -1`); `ctx`/`propq` are the PBE lookup's.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_decrypt_ex(
    p8: *const X509Sig,
    pass: *const c_char,
    passlen: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs8PrivKeyInfo {
    let mut dalg: *const X509Algor = ptr::null();
    let mut doct: *const Asn1String = ptr::null();
    // SAFETY: `p8` is live and both out-slots are this frame's.
    unsafe { X509_SIG_get0(p8, &raw mut dalg, &raw mut doct) };
    // SAFETY: `dalg`/`doct` are borrowed from the live `p8`; the item is a static this crate
    // owns; `zbuf` is 1, so the plaintext is cleansed before release.
    unsafe {
        PKCS12_item_decrypt_d2i_ex(
            dalg,
            PKCS8_PRIV_KEY_INFO_it(),
            pass,
            passlen,
            doct,
            1,
            ctx,
            propq,
        )
    }
    .cast::<Pkcs8PrivKeyInfo>()
}

/// `PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(const X509_SIG *p8, const char *pass, int passlen)` —
/// `crypto/pkcs12/p12_p8d.c:27-31`.
///
/// # Safety
/// As [`PKCS8_decrypt_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_decrypt(
    p8: *const X509Sig,
    pass: *const c_char,
    passlen: c_int,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS8_decrypt_ex(p8, pass, passlen, ptr::null_mut(), ptr::null()) }
}
