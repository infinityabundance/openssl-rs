//! `crypto/x509/t_x509.c` -- the X.509 text layer. Phase 8.8 (D349) landed the one helper the
//! `rsa_ameth.c` and `dsa_ameth.c` method objects call by name; **Phase 11.4 lands the printers**.
//!
//! ## What this module now owns
//!
//! `crypto/x509/t_x509.c` is 559 lines and defines **ten exports** and two internals. This module
//! lands **nine** of the ten exports:
//!
//! * `X509_signature_dump` (`:269-290`) -- Phase 8.8's slice, the hex dumper the RSA and DSA
//!   method objects call.
//! * `OSSL_STACK_OF_X509_free` (`:25-28`) -- `sk_X509_pop_free(certs, X509_free)`, the stack
//!   release `crypto/x509/x509_lu.c` used to transcribe as a local thunk.
//! * `X509_print` (`:53-56`) and `X509_print_ex` (`:58-200`) -- the certificate printer, whose
//!   body reads every field of the object.
//! * `X509_print_fp` (`:31-34`) and `X509_print_ex_fp` (`:36-50`) -- the `FILE *` spellings.
//! * `X509_signature_print` (`:292-323`) -- the algorithm line, the optional value and, on the
//!   admitted profile, the `ameth->sig_print` callback its `#ifndef OPENSSL_NO_DEPRECATED_3_6`
//!   block reaches (`OPENSSL_NO_DEPRECATED_3_6` is undefined; `src/x509/v3_ac_tgt.rs` reads the
//!   same block for `OSSL_OBJECT_DIGEST_INFO`).
//! * `X509_aux_print` (`:325-377`) -- the trust/alias/key-id suffix.
//! * `X509_ocspid_print` (`:202-267`) -- the subject and public-key OCSP SHA-1 hashes.
//!
//! ## Withheld by name, with the name's blocker
//!
//! One export remains:
//!
//! * `X509_STORE_CTX_print_verify_cb` (`crypto/x509/t_x509.c:449-513`) -- the verification
//!   callback that extends the error queue with a brief print of the failed certificate. Its body
//!   calls the unit's other internal, `ossl_x509_print_ex_brief` (`:383-411`), which this crate
//!   withholds deliberately: `ossl_x509_print_ex_brief` is the `covers` name of this module's
//!   divergence row in `forensics/prerequisites.json` (row 6, narrowed by D470), and
//!   `forensics/tools/prerequisite_gate.py` fails with `divergence_record_does_not_match` the
//!   moment the crate defines or references it. Faithful transcription cannot omit the
//!   brief-printer tail, so the callback stays withheld with the withheld internal rather than
//!   reimplemented under another name. The two statics it is the only caller of, `print_certs`
//!   (`:413-433`) and `print_store_certs` (`:435-446`), are withheld with it.
//!
//! The unit's other internal, `ossl_serial_number_print` (`:519-559`), landed in Phase 10.14.8 as
//! the prerequisite of `crypto/x509/v3_rolespec.c`, whose printer calls it; it is a `pub(crate)`
//! Rust function with no `#[no_mangle]`, because `include/crypto/x509.h:398` is an internal header
//! and the admitted DSO's version script hides the symbol -- D140's rule for `ossl_*` internals.
//!
//! ## The raise
//!
//! `X509_print_ex_fp` raises `ERR_LIB_X509`/`ERR_R_BUF_LIB` at `:43` when its `FILE` BIO cannot be
//! made; that is the only raise among the nine exports (the other eight answer 0 or 1 and raise
//! nothing). The unit is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the coordinate
//! is declared here as `X509_PRINT_EX_FP_43` in the crate's `ErrSite` idiom.
//!
//! ## The layouts it reads, and the court
//!
//! Every structure the printers touch -- `X509`/`X509_CINF`, `X509_ALGOR`, `ASN1_STRING` and
//! the extension stack -- is already the crate's; no type is defined here. A `FILE *` is the
//! `*mut c_void` the crate models a stream as. `RT-X509-REQ` (`courts/phase11/rt_x509_req_probe.c`)
//! is the differential court: it drives each export over the fixed DER fixtures and compares the
//! exact printed bytes to the authority's, printing no address.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_strex::X509_NAME_print_ex;
use crate::asn1::layout::{Asn1String, ASN1_DTFLGS_RFC822, V_ASN1_NEG_INTEGER};
use crate::asn1::prim::ASN1_INTEGER_get_int64;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::asn1::time::ossl_asn1_time_print_ex;
use crate::asn1::x_algor::X509Algor;
use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free, EvpMd};
use crate::evp::pkey::EVP_PKEY_print_public;
use crate::evp::pkey_asn1::EVP_PKEY_asn1_find;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR, BIO_NOCLOSE};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_pop_to_mark, ERR_print_errors, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, NID_undef, OBJ_find_sigid_algs, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_prn::X509V3_extensions_print;
use crate::x509::x509_cmp::{
    X509_get0_pubkey, X509_get0_serialNumber, X509_get_issuer_name, X509_get_subject_name,
};
use crate::x509::x509_set::{
    X509_get0_extensions, X509_get0_notAfter, X509_get0_notBefore, X509_get0_tbs_sigalg,
    X509_get0_uids, X509_get_X509_PUBKEY, X509_get_version,
};
use crate::x509::x_name::i2d_X509_NAME;
use crate::x509::x_pubkey::{X509_PUBKEY_get0_param, X509_get0_pubkey_bitstr};
use crate::x509::x_x509::{X509_free, X509_get0_signature, X509};
use crate::x509::x_x509a::{
    X509_alias_get0, X509_get0_reject_objects, X509_get0_trust_objects, X509_keyid_get0,
    X509_trusted,
};

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_BUF_LIB` -- `include/openssl/err.h.in:323`, `ERR_LIB_BUF | ERR_RFLAG_COMMON`.
const ERR_R_BUF_LIB: c_int = 524295;

/// `X509_FLAG_COMPAT` -- `include/openssl/x509.h.in:137`, `0`.
const X509_FLAG_COMPAT: c_ulong = 0;
/// `X509_FLAG_NO_HEADER` -- `include/openssl/x509.h.in:138`, `1L`.
const X509_FLAG_NO_HEADER: c_ulong = 1;
/// `X509_FLAG_NO_VERSION` -- `include/openssl/x509.h.in:139`.
const X509_FLAG_NO_VERSION: c_ulong = 1 << 1;
/// `X509_FLAG_NO_SERIAL` -- `include/openssl/x509.h.in:140`.
const X509_FLAG_NO_SERIAL: c_ulong = 1 << 2;
/// `X509_FLAG_NO_SIGNAME` -- `include/openssl/x509.h.in:141`.
const X509_FLAG_NO_SIGNAME: c_ulong = 1 << 3;
/// `X509_FLAG_NO_ISSUER` -- `include/openssl/x509.h.in:142`.
const X509_FLAG_NO_ISSUER: c_ulong = 1 << 4;
/// `X509_FLAG_NO_VALIDITY` -- `include/openssl/x509.h.in:143`.
const X509_FLAG_NO_VALIDITY: c_ulong = 1 << 5;
/// `X509_FLAG_NO_SUBJECT` -- `include/openssl/x509.h.in:144`.
const X509_FLAG_NO_SUBJECT: c_ulong = 1 << 6;
/// `X509_FLAG_NO_PUBKEY` -- `include/openssl/x509.h.in:145`.
const X509_FLAG_NO_PUBKEY: c_ulong = 1 << 7;
/// `X509_FLAG_NO_EXTENSIONS` -- `include/openssl/x509.h.in:146`.
const X509_FLAG_NO_EXTENSIONS: c_ulong = 1 << 8;
/// `X509_FLAG_NO_SIGDUMP` -- `include/openssl/x509.h.in:147`.
const X509_FLAG_NO_SIGDUMP: c_ulong = 1 << 9;
/// `X509_FLAG_NO_AUX` -- `include/openssl/x509.h.in:148`.
const X509_FLAG_NO_AUX: c_ulong = 1 << 10;
/// `X509_FLAG_NO_IDS` -- `include/openssl/x509.h.in:150`.
const X509_FLAG_NO_IDS: c_ulong = 1 << 12;

/// `XN_FLAG_SEP_MASK` -- `include/openssl/x509.h.in:157`, the separator group selector.
const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
/// `XN_FLAG_COMPAT` -- `include/openssl/x509.h.in:159`; selects the old `X509_NAME_print`.
const XN_FLAG_COMPAT: c_ulong = 0;
/// `XN_FLAG_SEP_MULTILINE` -- `include/openssl/x509.h.in:163`; one field per line.
const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;

/// `X509_VERSION_1` -- `include/openssl/x509.h.in:651`, `0`.
const X509_VERSION_1: c_long = 0;
/// `X509_VERSION_3` -- `include/openssl/x509.h.in:653`, `2`.
const X509_VERSION_3: c_long = 2;

/// `SN_sha1` -- the short name `X509_ocspid_print` fetches its digest with. `"SHA1"`, not
/// `"SHA-1"`.
const SN_SHA1: &CStr = c"SHA1";
/// `SHA_DIGEST_LENGTH` -- `include/openssl/sha.h`, `20`; the width of the two OCSP hashes.
const SHA_DIGEST_LENGTH: c_int = 20;

/// The authority translation unit, as the raise coordinate spells it.
const FILE: &CStr = c"crypto/x509/t_x509.c";
/// `X509_ocspid_print`'s `OPENSSL_malloc(derlen)` at `crypto/x509/t_x509.c:224`.
const LINE_MALLOC_DER: c_int = 224;
/// `X509_ocspid_print`'s success-path `OPENSSL_free(der)` at `crypto/x509/t_x509.c:238`.
const LINE_FREE_DER: c_int = 238;
/// `X509_ocspid_print`'s `err:`-label `OPENSSL_free(der)` at `crypto/x509/t_x509.c:264`.
const LINE_FREE_DER_ERR: c_int = 264;

/// One `t_x509.c` raise coordinate, declared locally because the unit is not in
/// `gen_err_raise_sites.py`'s covered set (see the module doc).
const fn t_x509_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/t_x509.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_print_ex_fp`'s BIO-creation failure at `crypto/x509/t_x509.c:43`, `ERR_R_BUF_LIB`.
const X509_PRINT_EX_FP_43: ErrSite = t_x509_site(43, c"X509_print_ex_fp", ERR_R_BUF_LIB);

/// The `void (*)(void *)` destructor shape `OPENSSL_sk_pop_free` takes, adapting [`X509_free`]
/// for [`OSSL_STACK_OF_X509_free`].
///
/// # Safety
///
/// `p` must be NULL or a live `X509`.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast::<X509>()) };
}

/// `void OSSL_STACK_OF_X509_free(STACK_OF(X509) *certs)` -- `crypto/x509/t_x509.c:25-28`.
///
/// Exactly `sk_X509_pop_free(certs, X509_free)`: the stack and every certificate it holds are
/// released. `crypto/x509/x509_lu.c` transcribed the expansion locally while this export was
/// withheld; the name is landed here now.
///
/// # Safety
///
/// `certs` is NULL or a live stack of live `X509` (a NULL or empty stack is accepted).
#[no_mangle]
pub unsafe extern "C" fn OSSL_STACK_OF_X509_free(certs: *mut OpenSslStack) {
    // SAFETY: `certs` is a live (or NULL) stack of live certificates per the contract.
    unsafe { OPENSSL_sk_pop_free(certs, Some(x509_free_void)) };
}

/// `int X509_print_fp(FILE *fp, X509 *x)` -- `crypto/x509/t_x509.c:31-34`.
///
/// The whole body sits inside `#ifndef OPENSSL_NO_STDIO`, which holds on this profile: it is
/// [`X509_print_ex_fp`] with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
///
/// # Safety
///
/// `fp` is a live writable stream; `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_print_fp(fp: *mut c_void, x: *mut X509) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe { X509_print_ex_fp(fp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT) }
}

/// `int X509_print_ex_fp(FILE *fp, X509 *x, unsigned long nmflag, unsigned long cflag)` --
/// `crypto/x509/t_x509.c:36-50`.
///
/// Wraps `fp` in a no-close `BIO_s_file` BIO and prints through [`X509_print_ex`]. A BIO that
/// cannot be made raises `ERR_R_BUF_LIB` at `:43` and answers 0. `BIO_set_fp(b, fp, BIO_NOCLOSE)`
/// is written as the `BIO_ctrl` its header macro expands to.
///
/// # Safety
///
/// `fp` is a live writable stream; `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_print_ex_fp(
    fp: *mut c_void,
    x: *mut X509,
    nmflag: c_ulong,
    cflag: c_ulong,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let b = BIO_new(BIO_s_file());
        if b.is_null() {
            raise_site(&X509_PRINT_EX_FP_43);
            return 0;
        }
        BIO_ctrl(b, BIO_C_SET_FILE_PTR, c_long::from(BIO_NOCLOSE), fp);
        let ret = X509_print_ex(b, x, nmflag, cflag);
        BIO_free(b);
        ret
    }
}

/// `int X509_print(BIO *bp, X509 *x)` -- `crypto/x509/t_x509.c:53-56`.
///
/// [`X509_print_ex`] with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT` -- the authority's default
/// spelling.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_print(bp: *mut Bio, x: *mut X509) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract.
    unsafe { X509_print_ex(bp, x, XN_FLAG_COMPAT, X509_FLAG_COMPAT) }
}

/// `int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflags, unsigned long cflag)` --
/// `crypto/x509/t_x509.c:58-200`.
///
/// The certificate printer. A multiline separator sets the field separator to newline and the name
/// indent to 12; `XN_FLAG_COMPAT` makes [`X509_NAME_print_ex`]'s "no name printed" answer of 0 a
/// failure. Each unflagged section prints one field of the object, in the authority's order:
/// header, version, serial, TBS signature name, issuer, validity, subject, public key, the two
/// unique IDs, the extensions, the outer signature and the trust/alias suffix. Every failure arm
/// answers 0; success answers 1.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_print_ex(
    bp: *mut Bio,
    x: *mut X509,
    nmflags: c_ulong,
    cflag: c_ulong,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        let mut mlch: c_int = c_int::from(b' ');
        let mut nmindent: c_int = 0;
        let mut printok: c_int = 0;

        if (nmflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE {
            mlch = c_int::from(b'\n');
            nmindent = 12;
        }
        if nmflags == XN_FLAG_COMPAT {
            printok = 1;
        }

        if cflag & X509_FLAG_NO_HEADER == 0 {
            if BIO_write(bp, c"Certificate:\n".as_ptr().cast(), 13) <= 0 {
                return 0;
            }
            if BIO_write(bp, c"    Data:\n".as_ptr().cast(), 10) <= 0 {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_VERSION == 0 {
            let l = X509_get_version(x);
            if (X509_VERSION_1..=X509_VERSION_3).contains(&l) {
                if BIO_printf(
                    bp,
                    c"%8sVersion: %ld (0x%lx)\n".as_ptr(),
                    c"".as_ptr(),
                    l + 1,
                    l as c_ulong,
                ) <= 0
                {
                    return 0;
                }
            } else if BIO_printf(bp, c"%8sVersion: Unknown (%ld)\n".as_ptr(), c"".as_ptr(), l) <= 0
            {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_SERIAL == 0 {
            let bs = X509_get0_serialNumber(x);
            if BIO_write(bp, c"        Serial Number:".as_ptr().cast(), 22) <= 0 {
                return 0;
            }
            if ossl_serial_number_print(bp, bs, 12) != 0 {
                return 0;
            }
            if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                return 0;
            }
        }

        if cflag & X509_FLAG_NO_SIGNAME == 0 {
            let tsig_alg = X509_get0_tbs_sigalg(x);
            if BIO_puts(bp, c"    ".as_ptr()) <= 0 {
                return 0;
            }
            if X509_signature_print(bp, tsig_alg, ptr::null()) <= 0 {
                return 0;
            }
        }

        if cflag & X509_FLAG_NO_ISSUER == 0 {
            if BIO_printf(bp, c"        Issuer:%c".as_ptr(), mlch) <= 0 {
                return 0;
            }
            if X509_NAME_print_ex(bp, X509_get_issuer_name(x), nmindent, nmflags) < printok {
                return 0;
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_VALIDITY == 0 {
            if BIO_write(bp, c"        Validity\n".as_ptr().cast(), 17) <= 0 {
                return 0;
            }
            if BIO_write(bp, c"            Not Before: ".as_ptr().cast(), 24) <= 0 {
                return 0;
            }
            if ossl_asn1_time_print_ex(bp, X509_get0_notBefore(x), ASN1_DTFLGS_RFC822) == 0 {
                return 0;
            }
            if BIO_write(bp, c"\n            Not After : ".as_ptr().cast(), 25) <= 0 {
                return 0;
            }
            if ossl_asn1_time_print_ex(bp, X509_get0_notAfter(x), ASN1_DTFLGS_RFC822) == 0 {
                return 0;
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_SUBJECT == 0 {
            if BIO_printf(bp, c"        Subject:%c".as_ptr(), mlch) <= 0 {
                return 0;
            }
            if X509_NAME_print_ex(bp, X509_get_subject_name(x), nmindent, nmflags) < printok {
                return 0;
            }
            if BIO_write(bp, c"\n".as_ptr().cast(), 1) <= 0 {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_PUBKEY == 0 {
            let xpkey = X509_get_X509_PUBKEY(x);
            let mut xpoid: *mut Asn1Object = ptr::null_mut();
            X509_PUBKEY_get0_param(
                &raw mut xpoid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                xpkey,
            );
            if BIO_write(
                bp,
                c"        Subject Public Key Info:\n".as_ptr().cast(),
                33,
            ) <= 0
            {
                return 0;
            }
            if BIO_printf(bp, c"%12sPublic Key Algorithm: ".as_ptr(), c"".as_ptr()) <= 0 {
                return 0;
            }
            if i2a_ASN1_OBJECT(bp, xpoid) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                return 0;
            }

            let pkey = X509_get0_pubkey(x);
            if pkey.is_null() {
                BIO_printf(
                    bp,
                    c"%12sUnable to load Public Key\n".as_ptr(),
                    c"".as_ptr(),
                );
                ERR_print_errors(bp);
            } else {
                EVP_PKEY_print_public(bp, pkey, 16, ptr::null_mut());
            }
        }

        if cflag & X509_FLAG_NO_IDS == 0 {
            let mut iuid: *const Asn1String = ptr::null();
            let mut suid: *const Asn1String = ptr::null();
            X509_get0_uids(x, &raw mut iuid, &raw mut suid);
            if !iuid.is_null() {
                if BIO_printf(bp, c"%8sIssuer Unique ID: ".as_ptr(), c"".as_ptr()) <= 0 {
                    return 0;
                }
                if X509_signature_dump(bp, iuid, 12) == 0 {
                    return 0;
                }
            }
            if !suid.is_null() {
                if BIO_printf(bp, c"%8sSubject Unique ID: ".as_ptr(), c"".as_ptr()) <= 0 {
                    return 0;
                }
                if X509_signature_dump(bp, suid, 12) == 0 {
                    return 0;
                }
            }
        }

        if cflag & X509_FLAG_NO_EXTENSIONS == 0
            && X509V3_extensions_print(
                bp,
                c"X509v3 extensions".as_ptr(),
                X509_get0_extensions(x),
                cflag,
                8,
            ) == 0
        {
            return 0;
        }

        if cflag & X509_FLAG_NO_SIGDUMP == 0 {
            let mut sig_alg: *const X509Algor = ptr::null();
            let mut sig: *const Asn1String = ptr::null();
            X509_get0_signature(&raw mut sig, &raw mut sig_alg, x);
            if X509_signature_print(bp, sig_alg, sig) <= 0 {
                return 0;
            }
        }
        if cflag & X509_FLAG_NO_AUX == 0 && X509_aux_print(bp, x, 0) == 0 {
            return 0;
        }
        1
    }
}

/// `int X509_ocspid_print(BIO *bp, X509 *x)` -- `crypto/x509/t_x509.c:202-267`.
///
/// Prints the SHA-1 of the DER subject name and, on the next line, the SHA-1 of the
/// `SubjectPublicKeyInfo`'s bit-string payload -- the two hashes an OCSP request carries. The
/// digest is fetched by `SN_sha1` through the object's own library context and property query.
/// A NULL `x` or `bp` answers 0; every other failure arm answers 0 after releasing the DER buffer
/// and the fetched method.
///
/// # Safety
///
/// `bp` is a live BIO; `x` is NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_ocspid_print(bp: *mut Bio, x: *mut X509) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if x.is_null() || bp.is_null() {
            return 0;
        }
        let mut der: *mut c_void = ptr::null_mut();
        let mut md: *mut EvpMd = ptr::null_mut();
        let mut sha1md = [0 as c_uchar; SHA_DIGEST_LENGTH as usize];

        if BIO_printf(bp, c"        Subject OCSP hash: ".as_ptr()) <= 0 {
            return ocspid_err(der, md);
        }
        let subj = X509_get_subject_name(x);
        let derlen = i2d_X509_NAME(subj, ptr::null_mut());
        if derlen <= 0 {
            return ocspid_err(der, md);
        }
        der = CRYPTO_malloc(derlen as usize, FILE.as_ptr(), LINE_MALLOC_DER);
        if der.is_null() {
            return ocspid_err(der, md);
        }
        let mut dertmp = der.cast::<c_uchar>();
        if i2d_X509_NAME(subj, &raw mut dertmp) < 0 {
            return ocspid_err(der, md);
        }
        md = EVP_MD_fetch((*x).libctx, SN_SHA1.as_ptr(), (*x).propq);
        if md.is_null() {
            return ocspid_err(der, md);
        }
        if EVP_Digest(
            der,
            derlen as usize,
            sha1md.as_mut_ptr(),
            ptr::null_mut(),
            md,
            ptr::null_mut(),
        ) == 0
        {
            return ocspid_err(der, md);
        }
        let mut i: c_int = 0;
        while i < SHA_DIGEST_LENGTH {
            if BIO_printf(bp, c"%02X".as_ptr(), c_int::from(sha1md[i as usize])) <= 0 {
                return ocspid_err(der, md);
            }
            i += 1;
        }
        CRYPTO_free(der, FILE.as_ptr(), LINE_FREE_DER);
        der = ptr::null_mut();

        if BIO_printf(bp, c"\n        Public key OCSP hash: ".as_ptr()) <= 0 {
            return ocspid_err(der, md);
        }
        let keybstr = X509_get0_pubkey_bitstr(x);
        if keybstr.is_null() {
            return ocspid_err(der, md);
        }
        if EVP_Digest(
            (*keybstr).data.cast(),
            (*keybstr).length as usize,
            sha1md.as_mut_ptr(),
            ptr::null_mut(),
            md,
            ptr::null_mut(),
        ) == 0
        {
            return ocspid_err(der, md);
        }
        i = 0;
        while i < SHA_DIGEST_LENGTH {
            if BIO_printf(bp, c"%02X".as_ptr(), c_int::from(sha1md[i as usize])) <= 0 {
                return ocspid_err(der, md);
            }
            i += 1;
        }
        BIO_printf(bp, c"\n".as_ptr());
        EVP_MD_free(md);
        1
    }
}

/// The `err:` tail of [`X509_ocspid_print`] (`crypto/x509/t_x509.c:263-266`): release the DER
/// buffer if it is still held, release the fetched method if it is, answer 0. The authority's
/// `OPENSSL_free(NULL)` is a no-op, matched here by the NULL checks.
///
/// # Safety
///
/// `der` is NULL or a buffer from the enclosing call's `CRYPTO_malloc`; `md` is NULL or its
/// `EVP_MD_fetch`.
unsafe fn ocspid_err(der: *mut c_void, md: *mut EvpMd) -> c_int {
    // SAFETY: both pointers are NULL or owned by the caller per this function's contract.
    unsafe {
        if !der.is_null() {
            CRYPTO_free(der, FILE.as_ptr(), LINE_FREE_DER_ERR);
        }
        if !md.is_null() {
            EVP_MD_free(md);
        }
    }
    0
}

/// `int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent)` --
/// `crypto/x509/t_x509.c:269-290`.
///
/// Eighteen octets per line, each as two lower-case hex digits separated by `:`, a newline
/// and `BIO_indent` before every line but the first, and a final newline. Both `BIO_write`
/// calls are the authority's own: the loop breaks only when `BIO_write` reports `<= 0` on
/// the newline, while the trailing one is stricter and requires **exactly 1**. A zero-length
/// string skips the loop entirely -- so it writes neither a line nor an indent -- and answers 1
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

/// `int X509_signature_print(BIO *bp, const X509_ALGOR *sigalg, const ASN1_STRING *sig)` --
/// `crypto/x509/t_x509.c:292-323`.
///
/// Writes `    Signature Algorithm: ` and the algorithm's OID, then, when `sig` is non-NULL,
/// `\n    Signature Value:`. The admitted profile leaves `OPENSSL_NO_DEPRECATED_3_6` undefined, so
/// the block at `:306-317` is compiled in: a known signature NID whose key type has an `ameth`
/// `sig_print` prints through it (RSA and DSA do; EC does not), otherwise the value is dumped by
/// [`X509_signature_dump`] at `indent + 4`. Answers 1 when `sig` is NULL and the algorithm printed.
///
/// # Safety
///
/// `bp` is a live BIO; `sigalg` is a live `X509_ALGOR`; `sig` is NULL or a live `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn X509_signature_print(
    bp: *mut Bio,
    sigalg: *const X509Algor,
    sig: *const Asn1String,
) -> c_int {
    /// The authority's fixed indent.
    const INDENT: c_int = 4;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if BIO_printf(
            bp,
            c"%*sSignature Algorithm: ".as_ptr(),
            INDENT,
            c"".as_ptr(),
        ) <= 0
        {
            return 0;
        }
        if i2a_ASN1_OBJECT(bp, (*sigalg).algorithm) <= 0 {
            return 0;
        }

        if !sig.is_null()
            && BIO_printf(bp, c"\n%*sSignature Value:".as_ptr(), INDENT, c"".as_ptr()) <= 0
        {
            return 0;
        }
        // The authority's `#ifndef OPENSSL_NO_DEPRECATED_3_6` block (`:306-317`), compiled in the
        // admitted build: a known signature NID with an ameth `sig_print` prints through it.
        let sig_nid = OBJ_obj2nid((*sigalg).algorithm);
        if sig_nid != NID_undef {
            let mut dig_nid: c_int = 0;
            let mut pkey_nid: c_int = 0;
            // SAFETY: both output slots are this frame's own.
            if OBJ_find_sigid_algs(sig_nid, &raw mut dig_nid, &raw mut pkey_nid) != 0 {
                // SAFETY: no preconditions; the lookup searches this crate's own tables.
                let ameth = EVP_PKEY_asn1_find(ptr::null_mut(), pkey_nid);
                if !ameth.is_null() {
                    // SAFETY: `ameth` is a live method row.
                    if let Some(sig_print) = (*ameth).sig_print {
                        // SAFETY: `bp` and `sig` are live and `sigalg` is the caller's live
                        // algorithm; the last argument is the authority's NULL `ASN1_PCTX`.
                        return sig_print(bp, sigalg, sig, INDENT + 4, ptr::null_mut());
                    }
                }
            }
        }
        if BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) != 1 {
            return 0;
        }
        if !sig.is_null() {
            return X509_signature_dump(bp, sig, INDENT + 4);
        }
        1
    }
}

/// `int X509_aux_print(BIO *out, X509 *x, int indent)` -- `crypto/x509/t_x509.c:325-377`.
///
/// A certificate with no `X509_CERT_AUX` (`X509_trusted` answers 0) prints nothing and answers 1.
/// Otherwise the trust and reject OID lists, the alias (an OCTET STRING printed as a `%.*s` span)
/// and the key id (colon-separated upper-case hex) are written at `indent`. Every OID is spelled
/// through `OBJ_obj2txt` with `no_name` 0.
///
/// # Safety
///
/// `out` is a live BIO; `x` is a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_aux_print(out: *mut Bio, x: *mut X509, indent: c_int) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every read.
    unsafe {
        if X509_trusted(x) == 0 {
            return 1;
        }
        let trust = X509_get0_trust_objects(x);
        let reject = X509_get0_reject_objects(x);
        let mut oidstr = [0 as c_char; 80];
        let mut i: c_int = 0;

        if !trust.is_null() {
            let mut first = 1;
            BIO_printf(
                out,
                c"%*sTrusted Uses:\n%*s".as_ptr(),
                indent,
                c"".as_ptr(),
                indent + 2,
                c"".as_ptr(),
            );
            let n = OPENSSL_sk_num(trust);
            for k in 0..n {
                if first == 0 {
                    BIO_puts(out, c", ".as_ptr());
                } else {
                    first = 0;
                }
                OBJ_obj2txt(
                    oidstr.as_mut_ptr(),
                    80,
                    OPENSSL_sk_value(trust, k).cast::<Asn1Object>(),
                    0,
                );
                BIO_puts(out, oidstr.as_ptr());
            }
            BIO_puts(out, c"\n".as_ptr());
        } else {
            BIO_printf(out, c"%*sNo Trusted Uses.\n".as_ptr(), indent, c"".as_ptr());
        }
        if !reject.is_null() {
            let mut first = 1;
            BIO_printf(
                out,
                c"%*sRejected Uses:\n%*s".as_ptr(),
                indent,
                c"".as_ptr(),
                indent + 2,
                c"".as_ptr(),
            );
            let n = OPENSSL_sk_num(reject);
            for k in 0..n {
                if first == 0 {
                    BIO_puts(out, c", ".as_ptr());
                } else {
                    first = 0;
                }
                OBJ_obj2txt(
                    oidstr.as_mut_ptr(),
                    80,
                    OPENSSL_sk_value(reject, k).cast::<Asn1Object>(),
                    0,
                );
                BIO_puts(out, oidstr.as_ptr());
            }
            BIO_puts(out, c"\n".as_ptr());
        } else {
            BIO_printf(
                out,
                c"%*sNo Rejected Uses.\n".as_ptr(),
                indent,
                c"".as_ptr(),
            );
        }
        let alias = X509_alias_get0(x, &raw mut i);
        if !alias.is_null() {
            BIO_printf(
                out,
                c"%*sAlias: %.*s\n".as_ptr(),
                indent,
                c"".as_ptr(),
                i,
                alias,
            );
        }
        let mut keyidlen: c_int = 0;
        let keyid = X509_keyid_get0(x, &raw mut keyidlen);
        if !keyid.is_null() {
            BIO_printf(out, c"%*sKey Id: ".as_ptr(), indent, c"".as_ptr());
            let mut k: c_int = 0;
            while k < keyidlen {
                let sep = if k != 0 { c":".as_ptr() } else { c"".as_ptr() };
                BIO_printf(
                    out,
                    c"%s%02X".as_ptr(),
                    sep,
                    c_int::from(*keyid.offset(k as isize)),
                );
                k += 1;
            }
            BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1);
        }
        1
    }
}

/// `int ossl_serial_number_print(BIO *out, const ASN1_INTEGER *bs, int indent)` --
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
