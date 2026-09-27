//! `crypto/pkcs12/p12_npas.c` — the PKCS#12 password-change routine. Phase 10 (10.3).
//!
//! The unit is 263 lines and one export, [`PKCS12_newpass`], over four internal workers:
//! `newpass_p12` (unpack the outer `PFX`, re-encrypt each `SafeContents` under the new password
//! and repack), `newpass_bags`/`newpass_bag` (the shrouded-key-bag re-wrap) and `alg_get` (read a
//! PBE `AlgorithmIdentifier` back into the tuple the repack needs). **All five land here.**
//!
//! Its closure was measured with `nm --undefined-only` over the authority's
//! `libcrypto-lib-p12_npas.o`. Every undefined symbol is a landed crate name:
//! `PKCS12_unpack_authsafes`/`PKCS12_unpack_p7data`/`PKCS12_unpack_p7encdata`,
//! `PKCS12_pack_p7data`/`PKCS12_pack_p7encdata_ex`/`PKCS12_pack_authsafes`,
//! `PKCS12_gen_mac`/`PKCS12_verify_mac`, `PKCS8_decrypt_ex`/`PKCS8_encrypt_ex`,
//! `PKCS8_PRIV_KEY_INFO_free`, `PKCS12_SAFEBAG_get_nid`/`PKCS12_SAFEBAG_free`, the
//! `PBE2PARAM`/`PBEPARAM`/`PBKDF2PARAM` items, `ASN1_item_unpack`,
//! `ASN1_TYPE_unpack_sequence`, `ASN1_INTEGER_get`, `X509_ALGOR_get0`, `X509_SIG_free`/`_get0`/
//! `_getm`, the `ASN1_OCTET_STRING_*` trio, `EVP_CIPHER_fetch`/`_free`, `OBJ_nid2sn`/`OBJ_obj2nid`
//! and the `OPENSSL_sk_*` stack functions. Nothing in the unit is blocked.
//!
//! ## The local `err_sites` declaration
//!
//! `crypto/pkcs12/p12_npas.c` is not yet in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! three `PKCS12_newpass` raise sites (`PKCS12_R_INVALID_NULL_PKCS12_POINTER` at `:39`,
//! `PKCS12_R_MAC_VERIFY_FAILURE` at `:46` and `PKCS12_R_PARSE_ERROR` at `:51`) are declared under
//! the generator's own naming here, exactly as `src/provider/encode_key2any.rs` and
//! `src/provider/cipher_gcm.rs` do, and move into `src/runtime/err_sites.rs` when that generator's
//! file list next carries this unit. The workers raise nothing of their own.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::a_type::ASN1_TYPE_unpack_sequence;
use crate::asn1::asn_pack::ASN1_item_unpack;
use crate::asn1::layout::{Asn1String, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE};
use crate::asn1::p5_pbe::{PBEPARAM_free, PBEPARAM_it, Pbeparam};
use crate::asn1::p5_pbev2::{
    PBE2PARAM_free, PBE2PARAM_it, PBKDF2PARAM_free, PBKDF2PARAM_it, Pbe2Param, Pbkdf2Param,
};
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_free;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::asn1::x_sig::{X509Sig, X509_SIG_free, X509_SIG_get0, X509_SIG_getm};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::pkcs12::p12_add::{
    PKCS12_pack_authsafes, PKCS12_pack_p7data, PKCS12_pack_p7encdata_ex, PKCS12_unpack_authsafes,
    PKCS12_unpack_p7data, PKCS12_unpack_p7encdata,
};
use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, Pkcs12, Pkcs12Safebag};
use crate::pkcs12::p12_mutl::{PKCS12_gen_mac, PKCS12_verify_mac};
use crate::pkcs12::p12_p8d::PKCS8_decrypt_ex;
use crate::pkcs12::p12_p8e::PKCS8_encrypt_ex;
use crate::pkcs12::p12_sbag::PKCS12_SAFEBAG_get_nid;
use crate::pkcs7::{PKCS7_free, Pkcs7};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    Asn1Object, NID_hmacWithSHA1, NID_pbes2, NID_pkcs7_data, NID_pkcs7_encrypted,
    NID_pkcs8ShroudedKeyBag, NID_undef, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`, the width of the MAC scratch.
const EVP_MAX_MD_SIZE: c_int = 64;

/// `ERR_LIB_PKCS12` — `include/openssl/err.h` (`ERR_LIB_PKCS12`, 35).
const ERR_LIB_PKCS12: c_int = 35;
/// `PKCS12_R_INVALID_NULL_PKCS12_POINTER` — `include/openssl/pkcs12err.h:30`.
const PKCS12_R_INVALID_NULL_PKCS12_POINTER: c_int = 105;
/// `PKCS12_R_MAC_VERIFY_FAILURE` — `include/openssl/pkcs12err.h:38`.
const PKCS12_R_MAC_VERIFY_FAILURE: c_int = 113;
/// `PKCS12_R_PARSE_ERROR` — `include/openssl/pkcs12err.h:39`.
const PKCS12_R_PARSE_ERROR: c_int = 114;

/// The `ErrSite` builder for this unit's three coordinates, declared locally because
/// `crypto/pkcs12/p12_npas.c` is not yet in `gen_err_raise_sites.py`'s `COVERED_FILES` (see the
/// module doc).
const fn npas_site(line: c_int, func: &'static CStr, reason: c_int) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/pkcs12/p12_npas.c",
        line,
        func,
        lib: ERR_LIB_PKCS12,
        reason,
        dynamic_reason: false,
    }
}

/// `PKCS12_newpass` at `crypto/pkcs12/p12_npas.c:39`.
const PKCS12_NPAS_39: err_sites::ErrSite =
    npas_site(39, c"PKCS12_newpass", PKCS12_R_INVALID_NULL_PKCS12_POINTER);
/// `PKCS12_newpass` at `crypto/pkcs12/p12_npas.c:46`.
const PKCS12_NPAS_46: err_sites::ErrSite =
    npas_site(46, c"PKCS12_newpass", PKCS12_R_MAC_VERIFY_FAILURE);
/// `PKCS12_newpass` at `crypto/pkcs12/p12_npas.c:51`.
const PKCS12_NPAS_51: err_sites::ErrSite = npas_site(51, c"PKCS12_newpass", PKCS12_R_PARSE_ERROR);

/// `void pkcs7_free_void(void *p)` — the `FreeFn` shape `OPENSSL_sk_pop_free` takes, wrapping
/// [`PKCS7_free`] for the two `PKCS7` stacks the cleanup releases.
///
/// # Safety
/// `p` is null or a `PKCS7` this item layer owns.
unsafe extern "C" fn pkcs7_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { PKCS7_free(p.cast()) }
}

/// `void safebag_free_void(void *p)` — the same shape wrapping [`PKCS12_SAFEBAG_free`].
///
/// # Safety
/// `p` is null or a `PKCS12_SAFEBAG` this item layer owns.
unsafe extern "C" fn safebag_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { PKCS12_SAFEBAG_free(p.cast()) }
}

/// `static int alg_get(const X509_ALGOR *alg, int *pnid, int *piter, int *psaltlen, int
/// *cipherid)` — `crypto/pkcs12/p12_npas.c:198-263`.
///
/// Reads a PBE `AlgorithmIdentifier` back into the tuple the repack needs: for PBES2
/// (`NID_pbes2`) the PRF NID, iteration count, salt length and encryption cipher; for the PKCS#5
/// v1.5 form the scheme NID, iteration count and salt length, with `cipherid` left `NID_undef`.
/// Every malformed shape answers 0 with the four out-slots untouched.
///
/// # Safety
/// `alg` is a live `X509_ALGOR`; the four out-pointers are writable.
unsafe fn alg_get(
    alg: *const X509Algor,
    pnid: *mut c_int,
    piter: *mut c_int,
    psaltlen: *mut c_int,
    pcipherid: *mut c_int,
) -> c_int {
    let mut ret: c_int = 0;
    let mut pbe: *mut Pbeparam = ptr::null_mut();
    let mut pbe2: *mut Pbe2Param = ptr::null_mut();
    let mut kdf: *mut Pbkdf2Param = ptr::null_mut();

    let mut aoid: *const Asn1Object = ptr::null();
    let mut aparamtype: c_int = 0;
    let mut aparam: *const c_void = ptr::null();
    // SAFETY: `alg` is live and the three out-slots are this frame's.
    unsafe { X509_ALGOR_get0(&raw mut aoid, &raw mut aparamtype, &raw mut aparam, alg) };
    // SAFETY: `aoid` is the algorithm's own object.
    let pbenid = unsafe { OBJ_obj2nid(aoid) };

    'body: {
        // SAFETY: `alg`/`aparam` are live or NULL; every pointer is checked before use.
        unsafe {
            if pbenid == NID_pbes2 {
                if aparamtype == V_ASN1_SEQUENCE {
                    pbe2 = ASN1_item_unpack(aparam.cast::<Asn1String>(), PBE2PARAM_it())
                        .cast::<Pbe2Param>();
                }
                if pbe2.is_null() {
                    break 'body;
                }
                X509_ALGOR_get0(
                    ptr::null_mut(),
                    &raw mut aparamtype,
                    &raw mut aparam,
                    (*pbe2).keyfunc,
                );
                X509_ALGOR_get0(
                    &raw mut aoid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    (*pbe2).encryption,
                );
                let encnid = OBJ_obj2nid(aoid);
                if aparamtype == V_ASN1_SEQUENCE {
                    kdf = ASN1_item_unpack(aparam.cast::<Asn1String>(), PBKDF2PARAM_it())
                        .cast::<Pbkdf2Param>();
                }
                if kdf.is_null() {
                    break 'body;
                }
                let slt = (*kdf).salt;
                // Only OCTET_STRING is supported.
                if (*slt).type_ != V_ASN1_OCTET_STRING {
                    break 'body;
                }
                let prfnid = if (*kdf).prf.is_null() {
                    NID_hmacWithSHA1
                } else {
                    X509_ALGOR_get0(&raw mut aoid, ptr::null_mut(), ptr::null_mut(), (*kdf).prf);
                    OBJ_obj2nid(aoid)
                };
                *psaltlen = (*(*slt).value.ptr.cast::<Asn1String>()).length;
                *piter = ASN1_INTEGER_get((*kdf).iter) as c_int;
                *pnid = prfnid;
                *pcipherid = encnid;
                ret = 1;
            } else {
                pbe = ASN1_TYPE_unpack_sequence(PBEPARAM_it(), (*alg).parameter).cast::<Pbeparam>();
                if pbe.is_null() {
                    break 'body;
                }
                *pnid = OBJ_obj2nid((*alg).algorithm);
                *piter = ASN1_INTEGER_get((*pbe).iter) as c_int;
                *psaltlen = (*(*pbe).salt).length;
                *pcipherid = NID_undef;
                ret = 1;
            }
        }
    }
    // SAFETY: each is NULL or this frame's own.
    unsafe {
        if !kdf.is_null() {
            PBKDF2PARAM_free(kdf);
        }
        if !pbe2.is_null() {
            PBE2PARAM_free(pbe2);
        }
        if !pbe.is_null() {
            PBEPARAM_free(pbe);
        }
    }
    ret
}

/// `static int newpass_bag(PKCS12_SAFEBAG *bag, const char *oldpass, const char *newpass,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pkcs12/p12_npas.c:158-196`.
///
/// Only a `NID_pkcs8ShroudedKeyBag` is touched: every other bag answers success untouched. A
/// shrouded key bag is decrypted under the old password, its PBE tuple read back with [`alg_get`],
/// and re-encrypted under the new one; the old `X509_SIG` is released and the bag's union slot
/// takes the new one.
///
/// # Safety
/// `bag` is a live `PKCS12_SAFEBAG`; `oldpass`/`newpass` are NUL-terminated; `libctx`/`propq` are
/// the cipher fetch's.
unsafe fn newpass_bag(
    bag: *mut Pkcs12Safebag,
    oldpass: *const c_char,
    newpass: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut cipher: *mut EvpCipher = ptr::null_mut();
    let mut p8_nid: c_int = 0;
    let mut p8_saltlen: c_int = 0;
    let mut p8_iter: c_int = 0;
    let mut cipherid: c_int = 0;

    // SAFETY: `bag` is live per the caller's contract.
    unsafe {
        if PKCS12_SAFEBAG_get_nid(bag) != NID_pkcs8ShroudedKeyBag {
            return 1;
        }
        let shkeybag = (*bag).value.cast::<X509Sig>();
        let p8 = PKCS8_decrypt_ex(shkeybag, oldpass, -1, libctx, propq);
        if p8.is_null() {
            return 0;
        }
        let mut shalg: *const X509Algor = ptr::null();
        X509_SIG_get0(shkeybag, &raw mut shalg, ptr::null_mut());
        if alg_get(
            shalg,
            &raw mut p8_nid,
            &raw mut p8_iter,
            &raw mut p8_saltlen,
            &raw mut cipherid,
        ) == 0
        {
            PKCS8_PRIV_KEY_INFO_free(p8);
            return 0;
        }
        if cipherid != NID_undef {
            cipher = EVP_CIPHER_fetch(libctx, OBJ_nid2sn(cipherid), propq);
            if cipher.is_null() {
                PKCS8_PRIV_KEY_INFO_free(p8);
                return 0;
            }
        }
        let p8new = PKCS8_encrypt_ex(
            p8_nid,
            cipher,
            newpass,
            -1,
            ptr::null_mut(),
            p8_saltlen,
            p8_iter,
            p8,
            libctx,
            propq,
        );
        PKCS8_PRIV_KEY_INFO_free(p8);
        EVP_CIPHER_free(cipher);
        if p8new.is_null() {
            return 0;
        }
        X509_SIG_free(shkeybag);
        (*bag).value = p8new.cast::<c_void>();
    }
    1
}

/// `static int newpass_bags(STACK_OF(PKCS12_SAFEBAG) *bags, const char *oldpass, const char
/// *newpass, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/pkcs12/p12_npas.c:143-154`.
///
/// # Safety
/// `bags` is a live stack of `PKCS12_SAFEBAG`; the rest is forwarded to [`newpass_bag`].
unsafe fn newpass_bags(
    bags: *mut OpenSslStack,
    oldpass: *const c_char,
    newpass: *const c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `bags` is live per the caller's contract.
    unsafe {
        for i in 0..OPENSSL_sk_num(bags) {
            let bag = OPENSSL_sk_value(bags, i).cast::<Pkcs12Safebag>();
            if newpass_bag(bag, oldpass, newpass, libctx, propq) == 0 {
                return 0;
            }
        }
    }
    1
}

/// `static int newpass_p12(PKCS12 *p12, const char *oldpass, const char *newpass)` —
/// `crypto/pkcs12/p12_npas.c:60-141`.
///
/// Unpacks the outer `PFX`'s authsafes, re-encrypts each `SafeContents` under the new password
/// (dropping bags of any other content type), repacks the container and regenerates the `MacData`
/// digest. The old `authsafes` octet string is restored on any failure.
///
/// # Safety
/// `p12` is a live `PKCS12`; `oldpass`/`newpass` are NUL-terminated.
unsafe fn newpass_p12(p12: *mut Pkcs12, oldpass: *const c_char, newpass: *const c_char) -> c_int {
    let mut bags: *mut OpenSslStack = ptr::null_mut();
    let mut p12_data_tmp: *mut Asn1String = ptr::null_mut();
    let mut mac = [0 as c_uchar; EVP_MAX_MD_SIZE as usize];
    let mut maclen: c_uint = 0;
    let mut rv = 0;

    // SAFETY: `p12` is live per the caller's contract.
    let asafes = unsafe { PKCS12_unpack_authsafes(p12) };
    let newsafes = OPENSSL_sk_new_null();

    'body: {
        // SAFETY: `asafes`/`newsafes` are checked; every pointer below is checked before use.
        unsafe {
            if asafes.is_null() || newsafes.is_null() {
                break 'body;
            }
            let mut pbe_nid: c_int = 0;
            let mut pbe_iter: c_int = 0;
            let mut pbe_saltlen: c_int = 0;
            let mut cipherid: c_int = NID_undef;
            for i in 0..OPENSSL_sk_num(asafes) {
                let p7 = OPENSSL_sk_value(asafes, i).cast::<Pkcs7>();
                let bagnid = OBJ_obj2nid((*p7).type_);
                if bagnid == NID_pkcs7_data {
                    bags = PKCS12_unpack_p7data(p7);
                } else if bagnid == NID_pkcs7_encrypted {
                    bags = PKCS12_unpack_p7encdata(p7, oldpass, -1);
                    let enc = (*p7).d.encrypted;
                    if enc.is_null()
                        || alg_get(
                            (*(*enc).enc_data).algorithm,
                            &raw mut pbe_nid,
                            &raw mut pbe_iter,
                            &raw mut pbe_saltlen,
                            &raw mut cipherid,
                        ) == 0
                    {
                        break 'body;
                    }
                } else {
                    continue;
                }
                if bags.is_null() {
                    break 'body;
                }
                if newpass_bags(bags, oldpass, newpass, (*p7).ctx.libctx, (*p7).ctx.propq) == 0 {
                    break 'body;
                }
                // Repack the bag in the same form under the new password.
                let p7new = if bagnid == NID_pkcs7_data {
                    PKCS12_pack_p7data(bags)
                } else {
                    PKCS12_pack_p7encdata_ex(
                        pbe_nid,
                        newpass,
                        -1,
                        ptr::null_mut(),
                        pbe_saltlen,
                        pbe_iter,
                        bags,
                        (*p7).ctx.libctx,
                        (*p7).ctx.propq,
                    )
                };
                if p7new.is_null() || OPENSSL_sk_push(newsafes, p7new.cast()) == 0 {
                    PKCS7_free(p7new);
                    break 'body;
                }
                OPENSSL_sk_pop_free(bags, Some(safebag_free_void));
                bags = ptr::null_mut();
            }

            // Repack the safe, saving the old one in case of error.
            p12_data_tmp = (*(*p12).authsafes).d.data;
            let fresh = ASN1_OCTET_STRING_new();
            (*(*p12).authsafes).d.data = fresh;
            if fresh.is_null() {
                break 'body;
            }
            if PKCS12_pack_authsafes(p12, newsafes) == 0 {
                break 'body;
            }
            if !(*p12).mac.is_null() {
                if PKCS12_gen_mac(p12, newpass, -1, mac.as_mut_ptr(), &raw mut maclen) == 0 {
                    break 'body;
                }
                let mut macoct: *mut Asn1String = ptr::null_mut();
                X509_SIG_getm((*(*p12).mac).dinfo, ptr::null_mut(), &raw mut macoct);
                if ASN1_OCTET_STRING_set(macoct, mac.as_ptr(), maclen as c_int) == 0 {
                    break 'body;
                }
            }
            rv = 1;
        }
    }
    // SAFETY: `p12` is live; each pointer is NULL or this frame's own.
    unsafe {
        if rv == 1 {
            ASN1_OCTET_STRING_free(p12_data_tmp);
        } else if !p12_data_tmp.is_null() {
            ASN1_OCTET_STRING_free((*(*p12).authsafes).d.data);
            (*(*p12).authsafes).d.data = p12_data_tmp;
        }
        OPENSSL_sk_pop_free(bags, Some(safebag_free_void));
        OPENSSL_sk_pop_free(asafes, Some(pkcs7_free_void));
        OPENSSL_sk_pop_free(newsafes, Some(pkcs7_free_void));
    }
    rv
}

/// `int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass)` —
/// `crypto/pkcs12/p12_npas.c:34-56`.
///
/// A null container raises `PKCS12_R_INVALID_NULL_PKCS12_POINTER`; when a `MacData` is present the
/// old password is verified first, and a mismatch raises `PKCS12_R_MAC_VERIFY_FAILURE`; a failed
/// repack raises `PKCS12_R_PARSE_ERROR`.
///
/// # Safety
/// `p12` is NULL or a live `PKCS12`; `oldpass`/`newpass` are NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_newpass(
    p12: *mut Pkcs12,
    oldpass: *const c_char,
    newpass: *const c_char,
) -> c_int {
    // SAFETY: `p12` is NULL or live per the caller's contract.
    unsafe {
        if p12.is_null() {
            raise_site(&PKCS12_NPAS_39);
            return 0;
        }
        if !(*p12).mac.is_null() && PKCS12_verify_mac(p12, oldpass, -1) == 0 {
            raise_site(&PKCS12_NPAS_46);
            return 0;
        }
        if newpass_p12(p12, oldpass, newpass) == 0 {
            raise_site(&PKCS12_NPAS_51);
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site.
    fn packed(site: &err_sites::ErrSite) -> core::ffi::c_ulong {
        (((site.lib as core::ffi::c_ulong) & 0xff) << 23)
            | ((site.reason as core::ffi::c_ulong) & 0x7f_ffff)
    }

    /// A null container is refused with `PKCS12_R_INVALID_NULL_PKCS12_POINTER` before any object
    /// is touched. The error queue is process-global state, so the test runs alone.
    #[test]
    fn newpass_refuses_a_null_container() {
        let _guard = crate::test_support::lock_global_state();
        ERR_clear_error();
        // SAFETY: the container is deliberately NULL, which is the arm under test.
        let ret = unsafe { PKCS12_newpass(ptr::null_mut(), c"a".as_ptr(), c"b".as_ptr()) };
        assert_eq!(ret, 0);
        assert_eq!(ERR_peek_error(), packed(&PKCS12_NPAS_39));
        ERR_clear_error();
    }
}
