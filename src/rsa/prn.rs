//! `crypto/rsa/rsa_prn.c` — the two `RSA` printers, Phase 8.4.
//!
//! The unit is fifty lines and defines **two exports and no internals**:
//! [`RSA_print_fp`] (`rsa_prn.c:22-36`), the `FILE *` wrapper around the other, and
//! [`RSA_print`] (`rsa_prn.c:38-50`), which builds a throwaway `EVP_PKEY`, assigns the `RSA` to it
//! with `EVP_PKEY_set1_RSA`, and prints through the **private** spelling
//! `EVP_PKEY_print_private`. The `EVP_PKEY` is freed on every path, and the assignment's return
//! value gates the print — a failed assign answers that failure rather than reaching a printer with
//! a blank key.
//!
//! `EVP_PKEY_print_private` is `crypto/evp/p_lib.c`'s and was Phase 7's deferred-to-Phase-10
//! export; it lands in the same commit as this module, and the reason it is the *first* arm of this
//! file's chain rather than a legacy call is that `print_pkey` (`p_lib.c:1196`) asks the encoder
//! framework first and falls through to `ameth->priv_print` only when no encoder answers the key.
//! This crate registers no provider encoder, so the fall-through is the live path — but it is the
//! authority's own path, not a reduction at the call site.
//!
//! ## The raise is generated, not reconstructed
//!
//! `crypto/rsa/rsa_prn.c` is in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the single refusal
//! at `rsa_prn.c:28` (`ERR_LIB_RSA`/`ERR_R_BUF_LIB`) is [`crate::runtime::err_sites::RSA_PRN_28`],
//! the generator's own constant, rather than a hand-written expansion the way
//! [`crate::dh::prn`] had to build one for `dh_prn.c`.
//!
//! ## The court
//!
//! `RT-AMETH` builds an `RSA` from probe constants, prints it into a memory BIO through
//! [`RSA_print`], and observes **the first bytes only** — the leading indent and the header line —
//! never the key material. See `courts/phase8/rt_ameth_probe.c`'s print arms.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_void};

use crate::evp::p_legacy_assign::EVP_PKEY_set1_RSA;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_print_private, EvpPkey};
use crate::rsa::Rsa;
use crate::runtime::bio::{
    bss_file::BIO_s_file, BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE,
};
use crate::runtime::err::{err_sites, raise_site};

/// `int RSA_print_fp(FILE *fp, const RSA *x, int off)` — `crypto/rsa/rsa_prn.c:22-36`.
///
/// The whole body sits inside `#ifndef OPENSSL_NO_STDIO` (`:21-36`), which holds on this profile.
/// `BIO_set_fp(b, fp, BIO_NOCLOSE)` is the authority's macro for
/// `BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE, (char *)fp)`; this transcription writes the
/// `BIO_ctrl` call the macro expands to, the shape [`crate::dh::prn`] uses.
///
/// # Safety
/// `fp` is a live `FILE *`; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn RSA_print_fp(fp: *mut c_void, x: *const Rsa, off: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* b = BIO_new(BIO_s_file()), line 27. */
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&err_sites::RSA_PRN_28);
            return 0;
        }
        /* BIO_set_fp(b, fp, BIO_NOCLOSE), line 31. */
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = RSA_print(b, x, off);
        BIO_free(b);
        ret
    }
}

/// `int RSA_print(BIO *bp, const RSA *x, int off)` — `crypto/rsa/rsa_prn.c:38-50`.
///
/// The throwaway `EVP_PKEY` is assigned the caller's `RSA` — taking a reference, which
/// `EVP_PKEY_free` releases — and only a successful assign reaches `EVP_PKEY_print_private`. `off`
/// is the authority's indent and is passed straight through.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn RSA_print(bp: *mut Bio, x: *const Rsa, off: c_int) -> c_int {
    // SAFETY: no preconditions.
    let pk: *mut EvpPkey = unsafe { EVP_PKEY_new() };
    if pk.is_null() {
        return 0;
    }
    // SAFETY: `pk` is this frame's own key and `x` is live per the contract; `set1` takes its
    // reference and the cast is the authority's own `(RSA *)x` on a const parameter.
    let mut ret = unsafe { EVP_PKEY_set1_RSA(pk, x.cast_mut()) };
    if ret != 0 {
        // SAFETY: `bp` is a live BIO and `pk` now holds the assigned key.
        ret = unsafe { EVP_PKEY_print_private(bp, pk, off, core::ptr::null_mut()) };
    }
    // SAFETY: `pk` is this frame's own key; this releases the assignment's reference.
    unsafe { EVP_PKEY_free(pk) };
    ret
}
