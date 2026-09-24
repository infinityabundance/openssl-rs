//! `crypto/dsa/dsa_prn.c` — the four `DSA` printers, Phase 8.6.
//!
//! The unit is seventy-nine lines and defines **four exports and no internals**: two `FILE *`
//! wrappers, [`DSA_print_fp`] (`dsa_prn.c:22-35`) and [`DSAparams_print_fp`] (`:37-50`), and the two
//! `BIO` printers they wrap, [`DSA_print`] (`:53-65`) and [`DSAparams_print`] (`:67-79`).
//!
//! Each `BIO` printer builds a throwaway `EVP_PKEY`, assigns the caller's `DSA` with
//! `EVP_PKEY_set1_DSA`, and prints through a `crypto/evp/p_lib.c` export — the **private** spelling
//! `EVP_PKEY_print_private` for [`DSA_print`], and the **parameters** spelling
//! `EVP_PKEY_print_params` with the indent **4** for [`DSAparams_print`]. Both free the `EVP_PKEY`
//! on every path, and the assignment's return value gates the print.
//!
//! The two are the printers the task brief calls out as the *second* pair through the same
//! encoder-first path: `print_pkey` (`p_lib.c:1196`) asks the encoder framework first and falls
//! through to `ameth->priv_print`/`param_print` only when no encoder answers. This crate registers
//! no provider encoder, so the fall-through is the live path — through the authority's own code, not
//! a reduction at the call site.
//!
//! ## The raises are generated, not reconstructed
//!
//! `crypto/dsa/dsa_prn.c` joined `gen_err_raise_sites.py`'s `COVERED_FILES` with this module, so the
//! two refusals at `:28` and `:43` (both `ERR_LIB_DSA`/`ERR_R_BUF_LIB`) are the generator's own
//! [`crate::runtime::err_sites::DSA_PRN_28`]/[`crate::runtime::err_sites::DSA_PRN_43`], not a
//! hand-written expansion the way [`crate::dh::prn`] had to build one for `dh_prn.c`.
//!
//! ## The court
//!
//! `RT-AMETH` builds a `DSA` from probe constants and prints it into a memory BIO through both
//! printers, observing **the first bytes only** — the leading indent and the header line — never the
//! key material. See `courts/phase8/rt_ameth_probe.c`'s print arms.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use crate::dsa::Dsa;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_print_params, EVP_PKEY_print_private, EVP_PKEY_set1_DSA,
    EvpPkey,
};
use crate::runtime::bio::{
    bss_file::BIO_s_file, BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE,
};
use crate::runtime::err::{err_sites, raise_site};

/// `int DSA_print_fp(FILE *fp, const DSA *x, int off)` — `crypto/dsa/dsa_prn.c:22-35`.
///
/// The whole body sits inside `#ifndef OPENSSL_NO_STDIO`, which holds on this profile.
/// `BIO_set_fp(b, fp, BIO_NOCLOSE)` is written as the `BIO_ctrl` its header macro expands to.
///
/// # Safety
/// `fp` is a live `FILE *`; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DSA_print_fp(fp: *mut c_void, x: *const Dsa, off: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* b = BIO_new(BIO_s_file()), line 27. */
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&err_sites::DSA_PRN_28);
            return 0;
        }
        /* BIO_set_fp(b, fp, BIO_NOCLOSE), line 32. */
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = DSA_print(b, x, off);
        BIO_free(b);
        ret
    }
}

/// `int DSAparams_print_fp(FILE *fp, const DSA *x)` — `crypto/dsa/dsa_prn.c:37-50`.
///
/// The parameters twin: same `FILE` BIO, and the indent lives in [`DSAparams_print`].
///
/// # Safety
/// `fp` is a live `FILE *`; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DSAparams_print_fp(fp: *mut c_void, x: *const Dsa) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* b = BIO_new(BIO_s_file()), line 42. */
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&err_sites::DSA_PRN_43);
            return 0;
        }
        /* BIO_set_fp(b, fp, BIO_NOCLOSE), line 47. */
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = DSAparams_print(b, x);
        BIO_free(b);
        ret
    }
}

/// `int DSA_print(BIO *bp, const DSA *x, int off)` — `crypto/dsa/dsa_prn.c:53-65`.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DSA_print(bp: *mut Bio, x: *const Dsa, off: c_int) -> c_int {
    // SAFETY: no preconditions.
    let pk: *mut EvpPkey = unsafe { EVP_PKEY_new() };
    if pk.is_null() {
        return 0;
    }
    // SAFETY: `pk` is this frame's own key and `x` is live per the contract; the cast is the
    // authority's own `(DSA *)x` on a const parameter.
    let mut ret = unsafe { EVP_PKEY_set1_DSA(pk, x.cast_mut()) };
    if ret != 0 {
        // SAFETY: `bp` is a live BIO and `pk` now holds the assigned key.
        ret = unsafe { EVP_PKEY_print_private(bp, pk, off, ptr::null_mut()) };
    }
    // SAFETY: `pk` is this frame's own key; this releases the assignment's reference.
    unsafe { EVP_PKEY_free(pk) };
    ret
}

/// `int DSAparams_print(BIO *bp, const DSA *x)` — `crypto/dsa/dsa_prn.c:67-79`.
///
/// The indent is the authority's literal **4**, not the caller's `off`: this spelling has no `off`
/// parameter at all.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DSAparams_print(bp: *mut Bio, x: *const Dsa) -> c_int {
    // SAFETY: no preconditions.
    let pk: *mut EvpPkey = unsafe { EVP_PKEY_new() };
    if pk.is_null() {
        return 0;
    }
    // SAFETY: `pk` is this frame's own key and `x` is live per the contract.
    let mut ret = unsafe { EVP_PKEY_set1_DSA(pk, x.cast_mut()) };
    if ret != 0 {
        // SAFETY: `bp` is a live BIO and `pk` now holds the assigned key; the indent is line 75's.
        ret = unsafe { EVP_PKEY_print_params(bp, pk, 4, ptr::null_mut()) };
    }
    // SAFETY: `pk` is this frame's own key; this releases the assignment's reference.
    unsafe { EVP_PKEY_free(pk) };
    ret
}
