//! `crypto/ec/ecx_backend.c` — the shared ECX backend for the legacy `EVP_PKEY_ASN1_METHOD` and
//! `EVP_PKEY_METHOD` objects and for provider implementations alike, Phase 8.7.
//!
//! Two hundred and fifty-three lines, four non-static functions: `ossl_ecx_public_from_private`,
//! `ossl_ecx_key_fromdata`, `ossl_ecx_key_dup`, and the `#ifndef FIPS_MODULE` tail
//! `ossl_ecx_key_op` + `ossl_ecx_key_from_pkcs8`. It is the unit `crypto/ec/ecx_meth.c`'s both
//! halves call for nearly every key operation, so D372 lands it beside `ecx_key.c`.
//!
//! ## The two header macros, and the one place they are not what the brief said
//!
//! `KEYLENID(id)` and `KEYNID2TYPE(id)` are `crypto/ec/ecx_backend.h`'s, not `ecx_meth.c`'s — the
//! brief attributes them to `ecx_meth.c:31` and `:35`, and the file they are actually in is the
//! header this module owns, which is also why they are [`keylenid`]/[`keynid2type`] here.
//! `KEYTYPE2NID(type)` is `include/crypto/ecx.h:51`'s and is used only by `ecx_meth.c`, so it
//! lives there. `KEYLEN(p)` is likewise the header's, expanded at its use sites rather than
//! transcribed as a function.
//!
//! ## `ecx_key_op_t`, modelled as its storage unit
//!
//! `typedef enum { KEY_OP_PUBLIC, KEY_OP_PRIVATE, KEY_OP_KEYGEN } ecx_key_op_t` has no
//! `#repr`, so its width in a signature is the platform `int`; [`ossl_ecx_key_op`] takes a
//! [`c_int`] and the three [`KEY_OP_*`] constants name its values, the same modelling
//! `ECX_KEY_TYPE` gets in [`crate::ec::ecx_key`].
//!
//! ## One authority path that raises nothing, recorded rather than smoothed
//!
//! `ossl_ecx_key_op`'s `KEY_OP_KEYGEN` arm calls `RAND_priv_bytes_ex` and, on its failure,
//! takes the `goto err` — **without an `ERR_raise`**. It is the one failure on this unit's
//! portable path that is silent, so no `err_sites` entry exists for it and none is invented;
//! the nine raises the unit does have are the six `EC_R_INVALID_ENCODING`/`ERR_R_EC_LIB` arms
//! and the three `EC_R_FAILED_MAKING_PUBLIC_KEY` arms, and all nine are referenced below.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1String, V_ASN1_UNDEF};
use crate::asn1::p8_pkey::{PKCS8_pkey_get0, Pkcs8PrivKeyInfo};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::typ::d2i_ASN1_OCTET_STRING;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::ec::curve25519::{ossl_ed25519_public_from_private, ossl_x25519_public_from_private};
use crate::ec::curve448::{ossl_ed448_public_from_private, ossl_x448_public_from_private};
use crate::ec::ecx_key::{
    ossl_ecx_key_allocate_privkey, ossl_ecx_key_free, ossl_ecx_key_new, EcxKey,
    ECX_KEY_TYPE_ED25519, ECX_KEY_TYPE_ED448, ECX_KEY_TYPE_X25519, ECX_KEY_TYPE_X448, MAX_KEYLEN,
    X25519_KEYLEN, X448_KEYLEN,
};
use crate::evp::pkey::{OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY};
use crate::params::{OSSL_PARAM_get_octet_string, OsslParam};
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::OBJ_obj2nid;
use crate::runtime::secure::CRYPTO_secure_clear_free;

const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ecx_backend.c".as_ptr();

/// `KEY_OP_PUBLIC` — `include/crypto/ecx.h:130`.
pub(crate) const KEY_OP_PUBLIC: c_int = 0;
/// `KEY_OP_PRIVATE` — `include/crypto/ecx.h:131`.
pub(crate) const KEY_OP_PRIVATE: c_int = 1;
/// `KEY_OP_KEYGEN` — `include/crypto/ecx.h:132`.
pub(crate) const KEY_OP_KEYGEN: c_int = 2;

/// `IS25519(id)` — `crypto/ec/ecx_backend.h:13`: X25519 or Ed25519, the two 32-byte types.
pub(crate) fn is25519(id: c_int) -> bool {
    id == crate::runtime::obj::NID_X25519 || id == crate::runtime::obj::NID_ED25519
}

/// `ISX448(id)` — `crypto/ec/ecx_backend.h:12`.
pub(crate) fn isx448(id: c_int) -> bool {
    id == crate::runtime::obj::NID_X448
}

/// `KEYLENID(id)` — `crypto/ec/ecx_backend.h:14`: the key length a NID names.
///
/// The C is a nested conditional with no out-of-range arm, so a NID that is none of the four
/// answers `ED448_KEYLEN` — the inner conditional's fall-through — rather than zero.
pub(crate) fn keylenid(id: c_int) -> usize {
    if is25519(id) {
        X25519_KEYLEN
    } else if isx448(id) {
        X448_KEYLEN
    } else {
        crate::ec::ecx_key::ED448_KEYLEN
    }
}

/// `KEYNID2TYPE(id)` — `crypto/ec/ecx_backend.h:16`: the `ECX_KEY_TYPE` a NID names.
///
/// As [`keylenid`], the innermost conditional's fall-through is `ECX_KEY_TYPE_ED448`.
pub(crate) fn keynid2type(id: c_int) -> c_int {
    if is25519(id) {
        if id == crate::runtime::obj::NID_X25519 {
            ECX_KEY_TYPE_X25519
        } else {
            ECX_KEY_TYPE_ED25519
        }
    } else if isx448(id) {
        ECX_KEY_TYPE_X448
    } else {
        ECX_KEY_TYPE_ED448
    }
}

/// `int ossl_ecx_public_from_private(ECX_KEY *key)` — `crypto/ec/ecx_backend.c:26`.
///
/// The `switch` has **no `default`**, exactly as the C: an out-of-range `type` falls through
/// every arm and the function answers 1 without writing `pubkey`.
///
/// # Safety
/// `key` is live, and `key.privkey` is readable for `key.keylen` bytes when set.
#[no_mangle]
#[allow(clippy::collapsible_match)] // each arm is one `case` of the authority's `switch` with its
                                    // own `if`, and collapsing the `if` into the arm would move two
                                    // distinct `ERR_raise` sites into one shape
pub unsafe extern "C" fn ossl_ecx_public_from_private(key: *mut EcxKey) -> c_int {
    // SAFETY: `key` is live per the contract; each arm reads what that type's key length names.
    unsafe {
        match (*key).type_ {
            ECX_KEY_TYPE_X25519 => {
                // The X25519 arm ignores its return: it is `void` in the authority.
                ossl_x25519_public_from_private((*key).pubkey.as_mut_ptr(), (*key).privkey);
            }
            ECX_KEY_TYPE_ED25519 => {
                if ossl_ed25519_public_from_private(
                    (*key).libctx,
                    (*key).pubkey.as_mut_ptr(),
                    (*key).privkey,
                    (*key).propq,
                ) == 0
                {
                    // SAFETY: a compile-time-constant site (`ecx_backend.c:37`).
                    raise_site(&err_sites::ECX_BACKEND_37);
                    return 0;
                }
            }
            ECX_KEY_TYPE_X448 => {
                ossl_x448_public_from_private((*key).pubkey.as_mut_ptr(), (*key).privkey);
            }
            ECX_KEY_TYPE_ED448 => {
                if ossl_ed448_public_from_private(
                    (*key).libctx,
                    (*key).pubkey.as_mut_ptr(),
                    (*key).privkey,
                    (*key).propq,
                ) == 0
                {
                    // SAFETY: a compile-time-constant site (`ecx_backend.c:47`).
                    raise_site(&err_sites::ECX_BACKEND_47);
                    return 0;
                }
            }
            _ => {}
        }
    }
    1
}

/// `int ossl_ecx_key_fromdata(ECX_KEY *ecx, const OSSL_PARAM *param_pub_key,
/// const OSSL_PARAM *param_priv_key, int include_private)` — `crypto/ec/ecx_backend.c:53`.
///
/// The private octets are read into the key's own `privkey` slot when the parameter carries
/// `keylen` bytes, and the `privkeylen != keylen` arm clears and releases them through
/// `OPENSSL_secure_clear_free(privkey, privkeylen)` — with the **received** length, precisely
/// so that `ossl_ecx_key_free`, which assumes `keylen`, is not reached with the wrong one.
///
/// # Safety
/// `ecx` is NULL or live; each `param` is NULL or a live parameter; when `ecx` is live its
/// `privkey`/`pubkey` are as the object's contract says.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_fromdata(
    ecx: *mut EcxKey,
    param_pub_key: *const OsslParam,
    param_priv_key: *const OsslParam,
    include_private: c_int,
) -> c_int {
    let mut privkeylen: usize = 0;
    let mut pubkeylen: usize = 0;

    if ecx.is_null() {
        return 0;
    }
    if param_pub_key.is_null() && param_priv_key.is_null() {
        return 0;
    }

    // SAFETY: `ecx` is live per the contract.
    unsafe {
        if include_private != 0 && !param_priv_key.is_null() {
            // `(void **)&ecx->privkey` hands the getter the address of the key's own slot, so a
            // value of `keylen` bytes is written in place rather than through a fresh allocation.
            let priv_slot: *mut *mut u8 = &raw mut (*ecx).privkey;
            if OSSL_PARAM_get_octet_string(
                param_priv_key,
                priv_slot.cast::<*mut c_void>(),
                (*ecx).keylen,
                &mut privkeylen,
            ) == 0
            {
                return 0;
            }
            if privkeylen != (*ecx).keylen {
                // `OPENSSL_secure_clear_free(ecx->privkey, privkeylen)` — the received length.
                CRYPTO_secure_clear_free((*ecx).privkey.cast(), privkeylen, FILE, 88);
                (*ecx).privkey = ptr::null_mut();
                return 0;
            }
        }

        // `pubkey = ecx->pubkey;` — a local pointer into the object's own array.
        let mut pubkey: *mut u8 = (*ecx).pubkey.as_mut_ptr();
        // `(void **)&pubkey` — the address of the *local*, which is what the C passes.
        let pub_slot: *mut *mut u8 = &raw mut pubkey;
        if !param_pub_key.is_null()
            && OSSL_PARAM_get_octet_string(
                param_pub_key,
                pub_slot.cast::<*mut c_void>(),
                MAX_KEYLEN,
                &mut pubkeylen,
            ) == 0
        {
            return 0;
        }

        if !param_pub_key.is_null() && pubkeylen != (*ecx).keylen {
            return 0;
        }

        if param_pub_key.is_null() && ossl_ecx_public_from_private(ecx) == 0 {
            return 0;
        }

        (*ecx).haspubkey = 1;
    }

    1
}

/// `ECX_KEY *ossl_ecx_key_dup(const ECX_KEY *key, int selection)` —
/// `crypto/ec/ecx_backend.c:104`.
///
/// # Safety
/// `key` is live; the returned object is a fresh key the caller owns.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_dup(key: *const EcxKey, selection: c_int) -> *mut EcxKey {
    // SAFETY: `OPENSSL_zalloc(sizeof(*ret))`, line 106.
    let ret = CRYPTO_zalloc(core::mem::size_of::<EcxKey>(), FILE, 106).cast::<EcxKey>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `key` is live and `ret` is this call's own object.
    unsafe {
        (*ret).libctx = (*key).libctx;
        (*ret).haspubkey = 0;
        (*ret).keylen = (*key).keylen;
        (*ret).type_ = (*key).type_;
        (*ret).references = core::sync::atomic::AtomicI32::new(1);

        if !(*key).propq.is_null() {
            // `OPENSSL_strdup(key->propq)`, line 119.
            (*ret).propq = CRYPTO_strdup((*key).propq, FILE, 119);
            if (*ret).propq.is_null() {
                return dup_err(ret);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && (*key).haspubkey == 1 {
            ptr::copy_nonoverlapping(
                (*key).pubkey.as_ptr(),
                (*ret).pubkey.as_mut_ptr(),
                MAX_KEYLEN,
            );
            (*ret).haspubkey = 1;
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && !(*key).privkey.is_null() {
            if ossl_ecx_key_allocate_privkey(ret).is_null() {
                // SAFETY: a compile-time-constant site (`ecx_backend.c:133`, ERR_R_EC_LIB).
                raise_site(&err_sites::ECX_BACKEND_133);
                return dup_err(ret);
            }
            ptr::copy_nonoverlapping((*key).privkey, (*ret).privkey, (*ret).keylen);
        }
    }

    ret
}

/// The `err:` label of [`ossl_ecx_key_dup`] — `crypto/ec/ecx_backend.c:138-141`.
///
/// `CRYPTO_FREE_REF` is empty on this profile, so the label is `ossl_ecx_key_free(ret)`.
///
/// # Safety
/// `ret` is a live, uniquely-owned key.
unsafe fn dup_err(ret: *mut EcxKey) -> *mut EcxKey {
    // SAFETY: `ret` is live and uniquely owned per the contract.
    unsafe { ossl_ecx_key_free(ret) };
    ptr::null_mut()
}

/// `ECX_KEY *ossl_ecx_key_op(const X509_ALGOR *palg, const unsigned char *p, int plen, int id,
/// ecx_key_op_t op, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/ec/ecx_backend.c:144`.
///
/// The `op != KEY_OP_KEYGEN` prologue is the algorithm-parameters check: the parameters must be
/// absent (`V_ASN1_UNDEF`), the NID must match the `X509_ALGOR`'s own unless the caller passes
/// `EVP_PKEY_NONE`, and the octet length must be exactly `KEYLENID(id)`. The `KEY_OP_KEYGEN`
/// arm masks the private scalar to the curve's clamping rules, which is the authority's own
/// random-key shape rather than a validation.
///
/// # Safety
/// `palg` is NULL or live; `p` is NULL or readable for `plen` bytes; `libctx`/`propq` are NULL
/// or live; on success the answer is a fresh key the caller owns.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_op(
    palg: *const X509Algor,
    p: *const u8,
    plen: c_int,
    mut id: c_int,
    op: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcxKey {
    const EVP_PKEY_NONE: c_int = crate::evp::pkey::EVP_PKEY_NONE;

    if op != KEY_OP_KEYGEN {
        if !palg.is_null() {
            let mut ptype: c_int = 0;
            // SAFETY: `palg` is live; `ptype` is this frame's slot.
            unsafe { X509_ALGOR_get0(ptr::null_mut(), &mut ptype, ptr::null_mut(), palg) };
            if ptype != V_ASN1_UNDEF {
                // SAFETY: a compile-time-constant site (`ecx_backend.c:163`).
                unsafe { raise_site(&err_sites::ECX_BACKEND_163) };
                return ptr::null_mut();
            }
            // SAFETY: `palg` is live and its `algorithm` is its own object.
            let alg_nid = unsafe { OBJ_obj2nid((*palg).algorithm) };
            if id == EVP_PKEY_NONE {
                id = alg_nid;
            } else if id != alg_nid {
                // SAFETY: a compile-time-constant site (`ecx_backend.c:169`).
                unsafe { raise_site(&err_sites::ECX_BACKEND_169) };
                return ptr::null_mut();
            }
        }

        if p.is_null() || id == EVP_PKEY_NONE || plen as usize != keylenid(id) {
            // SAFETY: a compile-time-constant site (`ecx_backend.c:175`).
            unsafe { raise_site(&err_sites::ECX_BACKEND_175) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `KEYNID2TYPE` and the constructor's contract; `libctx`/`propq` are the caller's.
    let key = unsafe { ossl_ecx_key_new(libctx, keynid2type(id), 1, propq) };
    if key.is_null() {
        // SAFETY: a compile-time-constant site (`ecx_backend.c:182`, ERR_R_EC_LIB).
        unsafe { raise_site(&err_sites::ECX_BACKEND_182) };
        return ptr::null_mut();
    }

    if op == KEY_OP_PUBLIC {
        // `memcpy(pubkey, p, plen)` — `pubkey` is `key->pubkey`.
        // SAFETY: `p` is readable for `plen` bytes and `id`'s key length is `plen` (checked
        // above), and the destination is the object's 57-byte array.
        unsafe { ptr::copy_nonoverlapping(p, (*key).pubkey.as_mut_ptr(), plen as usize) };
    } else {
        // SAFETY: `key` is live.
        let privkey = unsafe { ossl_ecx_key_allocate_privkey(key) };
        if privkey.is_null() {
            // SAFETY: a compile-time-constant site (`ecx_backend.c:192`, ERR_R_EC_LIB).
            unsafe { raise_site(&err_sites::ECX_BACKEND_192) };
            // SAFETY: `key` is live and uniquely owned here.
            unsafe { ossl_ecx_key_free(key) };
            return ptr::null_mut();
        }
        if op == KEY_OP_KEYGEN {
            if id != EVP_PKEY_NONE {
                // SAFETY: `privkey` is writable for `KEYLENID(id)` bytes; `libctx` is the
                // caller's. A failure here takes the `goto err` **without** a raise.
                if unsafe { RAND_priv_bytes_ex(libctx, privkey, keylenid(id), 0) } <= 0 {
                    // SAFETY: `key` is live and uniquely owned here.
                    unsafe { ossl_ecx_key_free(key) };
                    return ptr::null_mut();
                }
                // SAFETY: `privkey` holds `KEYLENID(id)` bytes; the two masks are the
                // authority's X25519/X448 clamping.
                unsafe {
                    if id == crate::runtime::obj::NID_X25519 {
                        *privkey &= 248;
                        *privkey.add(X25519_KEYLEN - 1) &= 127;
                        *privkey.add(X25519_KEYLEN - 1) |= 64;
                    } else if id == crate::runtime::obj::NID_X448 {
                        *privkey &= 252;
                        *privkey.add(X448_KEYLEN - 1) |= 128;
                    }
                }
            }
        } else {
            // `memcpy(privkey, p, KEYLENID(id))`.
            // SAFETY: `plen == KEYLENID(id)` was checked above, so `p` is readable for that many
            // bytes and `privkey` is writable for `keylen == KEYLENID(id)`.
            unsafe { ptr::copy_nonoverlapping(p, privkey, keylenid(id)) };
        }
        // SAFETY: `key` is live and its private scalar is set.
        if unsafe { ossl_ecx_public_from_private(key) } == 0 {
            // SAFETY: a compile-time-constant site (`ecx_backend.c:212`).
            unsafe { raise_site(&err_sites::ECX_BACKEND_212) };
            // SAFETY: `key` is live and uniquely owned here.
            unsafe { ossl_ecx_key_free(key) };
            return ptr::null_mut();
        }
    }

    key
}

/// `ECX_KEY *ossl_ecx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/ec/ecx_backend.c:222`.
///
/// The PKCS#8 private key is an `OCTET STRING` inside the `PrivateKeyInfo`, so the body decodes
/// it, falls back to a NULL/zero-length pair when the decode fails — which then fails
/// [`ossl_ecx_key_op`]'s `p == NULL` check — and frees the decoded `ASN1_OCTET_STRING` even when
/// it is NULL.
///
/// # Safety
/// `p8inf` is live; `libctx`/`propq` are NULL or live; the answer is a fresh key the caller owns.
#[no_mangle]
pub unsafe extern "C" fn ossl_ecx_key_from_pkcs8(
    p8inf: *const Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EcxKey {
    let mut p: *const u8 = ptr::null();
    let mut plen: c_int = 0;
    let mut palg: *const X509Algor = ptr::null();

    // SAFETY: `p8inf` is live per the contract; the three out-slots are this frame's.
    if unsafe { PKCS8_pkey_get0(ptr::null_mut(), &mut p, &mut plen, &mut palg, p8inf) } == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `p` points into `p8inf`'s own octets for `plen` bytes.
    let oct: *mut Asn1String =
        unsafe { d2i_ASN1_OCTET_STRING(ptr::null_mut(), &mut p, plen as core::ffi::c_long) };
    if oct.is_null() {
        p = ptr::null();
        plen = 0;
    } else {
        // SAFETY: `oct` is live.
        unsafe {
            p = ASN1_STRING_get0_data(oct);
            plen = ASN1_STRING_length(oct);
        }
    }

    // `EVP_PKEY_NONE` means `ossl_ecx_key_op` must determine the key type itself.
    // SAFETY: the caller's contract for each argument.
    let ecx = unsafe {
        ossl_ecx_key_op(
            palg,
            p,
            plen,
            crate::evp::pkey::EVP_PKEY_NONE,
            KEY_OP_PRIVATE,
            libctx,
            propq,
        )
    };
    // SAFETY: `oct` is NULL or live and this call owns it.
    unsafe { ASN1_OCTET_STRING_free(oct) };
    ecx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::ecx_key::ossl_ecx_compute_key;

    fn hexn(s: &str, n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect()
    }

    /// A private key through `ossl_ecx_key_op(..., KEY_OP_PRIVATE, ...)`, which is the object's
    /// own path: it allocates the private scalar, installs the octets and derives the public key
    /// with `ossl_ecx_public_from_private`.
    fn private_key(id: c_int, sk: &[u8]) -> *mut EcxKey {
        // SAFETY: `sk` is readable for its length and the rest is the constructor's contract.
        unsafe {
            ossl_ecx_key_op(
                ptr::null(),
                sk.as_ptr(),
                sk.len() as c_int,
                id,
                KEY_OP_PRIVATE,
                ptr::null_mut(),
                ptr::null(),
            )
        }
    }

    fn pubkey(key: *const EcxKey, n: usize) -> Vec<u8> {
        // SAFETY: `key` is live and its `pubkey` array is `MAX_KEYLEN` bytes.
        unsafe { (&(*key).pubkey)[..n].to_vec() }
    }

    /// The four `KEYLENID` answers, their bound and the `KEYNID2TYPE` fall-through, which is what
    /// `ossl_ecx_key_op`'s length test and the `EVP_PKEY_ASN1_METHOD` callbacks both read.
    #[test]
    fn keylen_and_type_tables() {
        use crate::runtime::obj::{NID_ED25519, NID_ED448, NID_X25519, NID_X448};
        assert_eq!(keylenid(NID_X25519), 32);
        assert_eq!(keylenid(NID_ED25519), 32);
        assert_eq!(keylenid(NID_X448), 56);
        assert_eq!(keylenid(NID_ED448), 57);
        // The header's inner conditional has no out-of-range arm: a foreign NID answers ED448's
        // length and type, which is the authority's own fall-through.
        assert_eq!(keylenid(crate::runtime::obj::NID_sha256), 57);

        assert_eq!(keynid2type(NID_X25519), ECX_KEY_TYPE_X25519);
        assert_eq!(keynid2type(NID_ED25519), ECX_KEY_TYPE_ED25519);
        assert_eq!(keynid2type(NID_X448), ECX_KEY_TYPE_X448);
        assert_eq!(keynid2type(NID_ED448), ECX_KEY_TYPE_ED448);
        assert_eq!(
            keynid2type(crate::runtime::obj::NID_sha256),
            ECX_KEY_TYPE_ED448
        );
    }

    /// RFC 7748 §6.1 through the object layer: two `ossl_ecx_key_op` private keys whose public
    /// halves `ossl_ecx_public_from_private` derives, and the shared secret their
    /// `ossl_ecx_compute_key` agrees on. The vectors are the authority's own
    /// `test/recipes/30-test_evp_data/evppkey_ecx.txt`.
    #[test]
    fn x25519_agreement_rfc7748_section_6_1() {
        let alice_sk = hexn(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            32,
        );
        let bob_sk = hexn(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            32,
        );

        let alice = private_key(crate::runtime::obj::NID_X25519, &alice_sk);
        let bob = private_key(crate::runtime::obj::NID_X25519, &bob_sk);
        assert!(!alice.is_null() && !bob.is_null());

        assert_eq!(
            pubkey(alice, 32),
            hexn(
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                32
            )
        );
        assert_eq!(
            pubkey(bob, 32),
            hexn(
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                32
            )
        );

        let mut secret = [0u8; 32];
        let mut secretlen: usize = 0;
        // SAFETY: both keys are live and the output buffer is 32 bytes with `outlen` 32.
        let ok = unsafe {
            ossl_ecx_compute_key(bob, alice, 32, secret.as_mut_ptr(), &mut secretlen, 32)
        };
        assert_eq!(ok, 1);
        assert_eq!(secretlen, 32);
        assert_eq!(
            secret.to_vec(),
            hexn(
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                32
            )
        );

        // The length-only query: a NULL output answers the key length without deriving.
        let mut only_len: usize = 0;
        // SAFETY: both keys are live; the output pointer is NULL by construction.
        let ok = unsafe { ossl_ecx_compute_key(bob, alice, 32, ptr::null_mut(), &mut only_len, 0) };
        assert_eq!(ok, 1);
        assert_eq!(only_len, 32);

        // SAFETY: both keys are this test's own and each holds one reference.
        unsafe {
            ossl_ecx_key_free(alice);
            ossl_ecx_key_free(bob);
        }
    }
}
