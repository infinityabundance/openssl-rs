//! `crypto/dh/dh_ameth.c`'s two unwired exports — `DHparams_dup` and `DHparams_print`, Phase 8.5.
//!
//! ## A partial unit, and why these two functions are the whole of it that can land
//!
//! `crypto/dh/dh_ameth.c` is six hundred and forty-eight lines and thirty-three functions, of
//! which **three** reach Phase 11 (`X509_PUBKEY_get0_param:72`, `X509_ALGOR_get0:74`,
//! `X509_PUBKEY_set0_param:147`, `PKCS8_pkey_set0:215` — D341's table) and are the
//! `EVP_PKEY_ASN1_METHOD` callbacks that will exist only when Phase 11's
//! `X509_PUBKEY`/`X509_ALGOR`/`PKCS8_PRIV_KEY_INFO` bodies do. Two of the file's exports touch
//! none of that:
//!
//! * [`DHparams_dup`] (`dh_ameth.c:334-345`) is `DH_new` plus the file-local
//!   `int_dh_param_copy` — `ossl_ffc_params_copy` wrapped with the `length`/`dirty_cnt` fix-ups.
//! * [`DHparams_print`] (`dh_ameth.c:393-396`) is the file-local `do_dh_print` with `ptype == 0`,
//!   which prints the parameters through `BIO_indent`, `BIO_printf`, `ASN1_bn_print` and
//!   [`crate::ffc::params::ossl_ffc_params_print`]. It reads `priv_key`/`pub_key` only for
//!   `ptype > 0`; a `DHparams` print never touches a private scalar.
//!
//! Both are transcribed here whole — the two functions and the two `static` helpers they reach,
//! which no other function of `dh_ameth.c` calls — and the rest of the unit is left unlanded and
//! named rather than stubbed. That is the [`crate::ec::asn1`] shape: a unit transcribed as far as
//! its stratum reaches, with the remainder withheld.
//!
//! ## This module is deliberately not named for the unit, and that is a measured choice
//!
//! The crate's transcription atlas maps a module to the **dominant** authority unit among the
//! symbols it defines, and the prerequisite gate's direction B then inspects *every* identifier
//! that unit's bodies reference. A module that claimed `crypto/dh/dh_ameth.c` would therefore
//! re-open `EVP_PKEY_assign` (`crypto/evp/p_lib.c`, whose crate module does not yet name it) and
//! the ameth's Phase 11 `X509_*`/`PKCS8_*` callees onto the gate — the D336/D339 shape, where a
//! partial transcription of a unit costs findings about the rest of it. So the two exports live
//! in [`crate::dh::mod`], which is where the ledger already labels all three `DHparams_*` names,
//! and the atlas keeps `dh_ameth.c` as a unit with no module. This is recorded in D345.
//!
//! ## The raise site is reconstructed from the authority's own `__FILE__`/`__LINE__`/`__func__`
//!
//! `dh_ameth.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so there is no
//! `err_sites::DH_AMETH_*` constant for its `ERR_raise` site. [`raise_at_do_dh_print`] writes the
//! authority's own `ERR_raise_data` expansion (`ERR_new`, `ERR_set_debug`, `ERR_set_error`) with
//! `crypto/dh/dh_ameth.c`, line 297 and the enclosing `__func__` `do_dh_print`, so the drained
//! coordinate a court reads is the authority's rather than a placeholder. The failure reason is
//! `ERR_R_PASSED_NULL_PARAMETER` when a required scalar is absent, and `ERR_R_BUF_LIB` is the
//! initial value reached only if a `BIO_*` call fails below that null check.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::asn1::t_pkey::ASN1_bn_print;
use crate::dh::object::{DH_bits, DH_free, DH_new};
use crate::dh::Dh;
use crate::ffc::params::{ossl_ffc_params_copy, ossl_ffc_params_print};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::runtime::err::{openssl_rs_err_set_error, ERR_new, ERR_set_debug};

/// `ERR_LIB_DH` — `include/openssl/err.h:79`.
const ERR_LIB_DH: c_int = 5;
/// `ERR_R_BUF_LIB` — `include/openssl/err.h:323`, `ERR_LIB_BUF (7) | ERR_RFLAG_COMMON (0x2 << 18)`.
/// The `do_dh_print` initial reason, reached only below the null check.
const ERR_R_BUF_LIB: c_int = 7 | (0x2 << 18);
/// `ERR_R_FATAL` — `include/openssl/err.h:353`, `ERR_RFLAG_FATAL (0x1 << 18) | ERR_RFLAG_COMMON
/// (0x2 << 18)`. The two flag bits are both set on every fatal reason.
const ERR_R_FATAL: c_int = (0x1 << 18) | (0x2 << 18);
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h:356`, `258 | ERR_R_FATAL`. The reason a
/// parameters print answers when `x->params.p` is absent.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_R_FATAL;

/// The translation unit both raise sites below are attributed to, with the admitted build record's
/// `../../src/openssl-3.6.4/` prefix that its compiled `__FILE__` carries.
const FILE_AMETH: *const c_char = c"../../src/openssl-3.6.4/crypto/dh/dh_ameth.c".as_ptr();

/// `__func__` at `dh_ameth.c:297` — the enclosing function's name, which `ERR_raise`'s
/// `OPENSSL_FUNC` records and `ERR_get_error_all` hands back. No generated site carries it because
/// `dh_ameth.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`.
const FUNC_DO_DH_PRINT: *const c_char = c"do_dh_print".as_ptr();

/// `ERR_raise(ERR_LIB_DH, reason)` at `crypto/dh/dh_ameth.c:297` — the `do_dh_print` `err:` label.
///
/// The three calls are the authority's `ERR_raise_data` expansion (`ERR_new`,
/// `ERR_set_debug(file, line, func)`, `ERR_set_error(lib, reason, NULL)`), written out because
/// there is no generated `err_sites::DH_AMETH_297` constant for the unit.
///
/// # Safety
///
/// The two string constants are NUL-terminated statics.
unsafe fn raise_at_do_dh_print(reason: c_int) {
    ERR_new();
    // SAFETY: `FILE_AMETH` and `FUNC_DO_DH_PRINT` are NUL-terminated statics.
    unsafe { ERR_set_debug(FILE_AMETH, 297, FUNC_DO_DH_PRINT) };
    // SAFETY: a NULL message is the authority's own `ERR_raise(lib, reason)` data.
    unsafe { openssl_rs_err_set_error(ERR_LIB_DH, reason, core::ptr::null()) };
}

/// `static int int_dh_param_copy(DH *to, const DH *from, int is_x942)` —
/// `crypto/dh/dh_ameth.c:322-332`.
///
/// `is_x942 == -1` asks the function to read the object: a `q` means X9.42, and in that case the
/// `length` field is left alone because it describes a `q`-less PKCS#3 recommendation.
///
/// # Safety
///
/// `to` is a live, writable key; `from` is a live key; neither is the other.
unsafe fn int_dh_param_copy(to: *mut Dh, from: *const Dh, is_x942: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut is_x942 = is_x942;
        if is_x942 == -1 {
            is_x942 = c_int::from(!(*from).params.q.is_null());
        }
        if ossl_ffc_params_copy(&raw mut (*to).params, &(*from).params) == 0 {
            return 0;
        }
        if is_x942 == 0 {
            (*to).length = (*from).length;
        }
        (*to).dirty_cnt += 1;
        1
    }
}

/// `DH *DHparams_dup(const DH *dh)` — `crypto/dh/dh_ameth.c:334-345`.
///
/// A fresh object with the same FFC parameters. `-1` is the authority's "read `is_x942` from the
/// source" argument, and the duplicate's old value is released on a copy failure.
///
/// # Safety
///
/// `dh` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DHparams_dup(dh: *const Dh) -> *mut Dh {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ret = DH_new();
        if ret.is_null() {
            return ret;
        }
        if int_dh_param_copy(ret, dh, -1) == 0 {
            DH_free(ret);
            return core::ptr::null_mut();
        }
        ret
    }
}

/// `static int do_dh_print(BIO *bp, const DH *x, int indent, int ptype)` —
/// `crypto/dh/dh_ameth.c:244-299`.
///
/// `ptype` is `0` for parameters, `1` for a public key and `2` for a private one; the authority
/// writes one function because the three prints differ only in which of the two scalars they
/// show and the label they lead with.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live key.
unsafe fn do_dh_print(bp: *mut Bio, x: *const Dh, indent: c_int, ptype: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut reason = ERR_R_BUF_LIB;

        let priv_key = if ptype == 2 {
            (*x).priv_key
        } else {
            core::ptr::null_mut()
        };
        let pub_key = if ptype > 0 {
            (*x).pub_key
        } else {
            core::ptr::null_mut()
        };

        if (*x).params.p.is_null()
            || (ptype == 2 && priv_key.is_null())
            || (ptype > 0 && pub_key.is_null())
        {
            reason = ERR_R_PASSED_NULL_PARAMETER;
            // goto err
            raise_at_do_dh_print(reason);
            return 0;
        }

        let ktype: *const c_char = if ptype == 2 {
            c"DH Private-Key".as_ptr()
        } else if ptype == 1 {
            c"DH Public-Key".as_ptr()
        } else {
            c"DH Parameters".as_ptr()
        };

        if BIO_indent(bp, indent, 128) == 0
            || BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ktype, DH_bits(x)) <= 0
        {
            raise_at_do_dh_print(reason);
            return 0;
        }
        let indent = indent + 4;

        if ASN1_bn_print(
            bp,
            c"private-key:".as_ptr(),
            priv_key,
            core::ptr::null_mut(),
            indent,
        ) == 0
        {
            raise_at_do_dh_print(reason);
            return 0;
        }
        if ASN1_bn_print(
            bp,
            c"public-key:".as_ptr(),
            pub_key,
            core::ptr::null_mut(),
            indent,
        ) == 0
        {
            raise_at_do_dh_print(reason);
            return 0;
        }

        if ossl_ffc_params_print(bp, &(*x).params, indent) == 0 {
            raise_at_do_dh_print(reason);
            return 0;
        }

        if (*x).length != 0
            && (BIO_indent(bp, indent, 128) == 0
                || BIO_printf(
                    bp,
                    c"recommended-private-length: %d bits\n".as_ptr(),
                    (*x).length,
                ) <= 0)
        {
            raise_at_do_dh_print(reason);
            return 0;
        }

        1
    }
}

/// `int DHparams_print(BIO *bp, const DH *x)` — `crypto/dh/dh_ameth.c:393-396`.
///
/// The parameters spelling of [`do_dh_print`], with the authority's own `indent == 4`.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live key.
#[no_mangle]
pub unsafe extern "C" fn DHparams_print(bp: *mut Bio, x: *const Dh) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { do_dh_print(bp, x, 4, 0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    use crate::bn::arith::BN_cmp;
    use crate::dh::group_params::DH_new_by_nid;
    use crate::dh::object::{DH_get0_pqg, DH_new};
    use crate::dh::prn::DHparams_print_fp;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::sys::{fclose, FILE};
    use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_CTRL_INFO};
    use crate::runtime::obj::NID_ffdhe2048;

    extern "C" {
        /// `FILE *tmpfile(void)` — the libc constructor `dh_prn.c`'s caller uses to obtain the
        /// `FILE *` it passes. It is not part of the crate's BIO surface, which exposes only
        /// `fopen`, so the test declares it; `fclose` and `FILE` come from
        /// [`crate::runtime::bio::sys`] so the declarations cannot disagree.
        fn tmpfile() -> *mut FILE;
    }

    /// `DHparams_dup` is `DH_new` plus the FFC copy, so the duplicate's three parameters compare
    /// with the original's.
    #[test]
    fn the_duplicate_has_the_same_parameters() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let dup = DHparams_dup(d);
            assert!(!dup.is_null());
            let (mut sp, mut sq, mut sg) = (ptr::null(), ptr::null(), ptr::null());
            let (mut dp, mut dq, mut dg) = (ptr::null(), ptr::null(), ptr::null());
            DH_get0_pqg(d, &mut sp, &mut sq, &mut sg);
            DH_get0_pqg(dup, &mut dp, &mut dq, &mut dg);
            assert_eq!(BN_cmp(dp, sp), 0);
            assert_eq!(BN_cmp(dq, sq), 0);
            assert_eq!(BN_cmp(dg, sg), 0);
            DH_free(dup);
            DH_free(d);
        }
    }

    /// A parameters print writes the group and answers 1; the text opens with the authority's own
    /// four-space indent and then its `DH Parameters` label.
    #[test]
    fn the_print_writes_the_parameters_and_answers_one() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let b = BIO_new(BIO_s_mem());
            assert!(!b.is_null());
            assert_eq!(DHparams_print(b, d), 1);
            let mut data: *mut core::ffi::c_char = ptr::null_mut();
            let len = BIO_ctrl(b, BIO_CTRL_INFO, 0, ptr::addr_of_mut!(data).cast());
            assert!(len > 6 && !data.is_null());
            // SAFETY: `data` is the BIO's own buffer, `len` bytes long.
            let text = core::slice::from_raw_parts(data.cast::<u8>(), len as usize);
            assert!(
                text.starts_with(b"    DH Parameters:"),
                "indent is 4, then the label"
            );
            BIO_free(b);
            DH_free(d);
        }
    }

    /// A key with no `p` prints nothing and raises the null-parameter reason at `dh_ameth.c:297`,
    /// with the authority's own file, line and function name — the coordinate `raise_at_do_dh_print`
    /// reconstructs because the unit is not in the raise-site generator's covered set.
    #[test]
    fn a_key_without_p_is_refused_with_the_coordinate() {
        // SAFETY: every pointer below is this test's own live object, and each out-parameter of
        // `ERR_get_error_all` is this frame's slot.
        unsafe {
            use core::ffi::CStr;

            let empty = DH_new();
            let b = BIO_new(BIO_s_mem());
            crate::runtime::err::ERR_clear_error();
            assert_eq!(DHparams_print(b, empty), 0);

            let mut file: *const c_char = ptr::null();
            let mut line: c_int = 0;
            let mut func: *const c_char = ptr::null();
            assert_ne!(
                crate::runtime::err::ERR_get_error_all(
                    &mut file,
                    &mut line,
                    &mut func,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                0
            );
            assert!(CStr::from_ptr(file)
                .to_bytes()
                .ends_with(b"crypto/dh/dh_ameth.c"));
            assert_eq!(line, 297);
            assert_eq!(CStr::from_ptr(func).to_bytes(), b"do_dh_print");

            BIO_free(b);
            DH_free(empty);
        }
    }

    /// The `FILE *` wrapper answers the print's verdict.
    #[test]
    fn the_file_pointer_wrapper_answers_the_print() {
        // SAFETY: `fp` is libc's own temporary file and every other pointer is this test's.
        unsafe {
            let d = DH_new_by_nid(NID_ffdhe2048);
            let fp = tmpfile();
            assert!(!fp.is_null());
            assert_eq!(DHparams_print_fp(fp.cast(), d), 1);
            fclose(fp);
            DH_free(d);
        }
    }
}
