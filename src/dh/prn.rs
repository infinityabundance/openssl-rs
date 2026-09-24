//! `crypto/dh/dh_prn.c` — the `FILE *` spelling of the parameters print, Phase 8.5.
//!
//! The unit is thirty-six lines and defines **one export and no internals**: a `FILE *` is wrapped
//! in a `FILE` BIO, the parameters print runs against it, and the BIO is released. The whole body
//! sits inside `#ifndef OPENSSL_NO_STDIO` (`dh_prn.c:21-36`), which holds on this profile.
//!
//! `BIO_set_fp(b, fp, BIO_NOCLOSE)` is the authority's macro for `BIO_ctrl(b,
//! BIO_C_SET_FILE_PTR, BIO_NOCLOSE, (char *)fp)`, and this transcription writes the `BIO_ctrl`
//! call the macro expands to rather than inventing a wrapper — the same shape
//! [`crate::runtime::bio::bss_file`] uses for `BIO_new_fp`. The close flag is `BIO_NOCLOSE`, so
//! the caller's `FILE` is left open.
//!
//! The one refusal raises `ERR_LIB_DH`/`ERR_R_BUF_LIB` at `dh_prn.c:28`. `dh_prn.c` is not in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`, so [`raise_at_dh_prn_28`] reconstructs the site from
//! the authority's own `__FILE__`/`__LINE__`/`__func__`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::dh::ameth::DHparams_print;
use crate::dh::Dh;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::err::{openssl_rs_err_set_error, ERR_new, ERR_set_debug};

/// `ERR_LIB_DH` — `include/openssl/err.h:79`.
const ERR_LIB_DH: c_int = 5;
/// `ERR_R_BUF_LIB` — `include/openssl/err.h:323`, `ERR_LIB_BUF (7) | ERR_RFLAG_COMMON (0x2 << 18)`.
const ERR_R_BUF_LIB: c_int = 7 | (0x2 << 18);

/// The translation unit the raise below is attributed to, with the admitted build record's
/// `../../src/openssl-3.6.4/` prefix that its compiled `__FILE__` carries.
const FILE_PRN: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_prn.c".as_ptr();

/// `__func__` at `dh_prn.c:28` — the enclosing function's name, which `ERR_raise`'s `OPENSSL_FUNC`
/// records. No generated site carries it because `dh_prn.c` is not in
/// `gen_err_raise_sites.py`'s `COVERED_FILES`.
const FUNC_DHPARAMS_PRINT_FP: *const c_char = c"DHparams_print_fp".as_ptr();

/// `ERR_raise(ERR_LIB_DH, ERR_R_BUF_LIB)` at `crypto/dh/dh_prn.c:28`, written as the authority's
/// own `ERR_raise_data` expansion because there is no generated `err_sites::DH_PRN_28`.
///
/// # Safety
///
/// The two string constants are NUL-terminated statics.
unsafe fn raise_at_dh_prn_28() {
    ERR_new();
    // SAFETY: the two constants are NUL-terminated statics.
    unsafe { ERR_set_debug(FILE_PRN, 28, FUNC_DHPARAMS_PRINT_FP) };
    // SAFETY: a NULL message is the authority's own `ERR_raise(lib, reason)` data.
    unsafe { openssl_rs_err_set_error(ERR_LIB_DH, ERR_R_BUF_LIB, core::ptr::null()) };
}

/// `int DHparams_print_fp(FILE *fp, const DH *x)` — `crypto/dh/dh_prn.c:22-35`.
///
/// # Safety
///
/// `fp` is a live `FILE *`; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DHparams_print_fp(fp: *mut c_void, x: *const Dh) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        // `b = BIO_new(BIO_s_file())`, line 27.
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_at_dh_prn_28();
            return 0;
        }
        // `BIO_set_fp(b, fp, BIO_NOCLOSE)`, line 31.
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp);
        let ret = DHparams_print(b, x);
        BIO_free(b);
        ret
    }
}
