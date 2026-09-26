//! `crypto/pkcs12/p12_add.c` — the `SafeBag` packer and the `PKCS#7` container readers. Phase 10
//! (10.3).
//!
//! The authority file is 227 lines and ten exports in two halves. The first half is the
//! `SafeBag`-shaped pair — [`PKCS12_item_pack_safebag`], which packs an arbitrary item into an
//! `x509Certificate`/`keyBag`-style `certBag`/`secretBag`, and the two `PKCS12_decrypt_skey`
//! spellings that read a `PKCS8_PRIV_KEY_INFO` out of a shrouded key bag. **Both land here.**
//!
//! The second half is the four `PKCS#7` container spellings (`PKCS12_pack_p7data`,
//! `PKCS12_unpack_p7data`, `PKCS12_pack_p7encdata[_ex]`, `PKCS12_unpack_p7encdata`) and the two
//! `PKCS12_pack/unpack_authsafes`. Every one of them dereferences the `PKCS7` object or calls
//! `PKCS7_new`/`PKCS7_type_is_*`, and `PKCS7_it` is `crypto/pkcs7/pk7_asn1.c`'s — Phase 12's.
//! **The `PKCS7` subset was pulled forward** (see [`crate::pkcs7`]), so four of the six land here:
//! [`PKCS12_pack_p7data`], [`PKCS12_unpack_p7data`], [`PKCS12_unpack_p7encdata`],
//! [`PKCS12_pack_authsafes`] and [`PKCS12_unpack_authsafes`]. The two `p7encdata` **writers** stay
//! `open`: `PKCS12_pack_p7encdata_ex` reaches Phase 11's `PKCS5_pbe_set_ex`/`PKCS5_pbe2_set_iv_ex`
//! at `:120`/`:122` to build its `AlgorithmIdentifier`, and `PKCS12_pack_p7encdata` is its
//! one-line wrapper. They are the only pair here whose blocker is not the `PKCS7` object itself.
//!
//! ## `PKCS12_item_pack_safebag` unblocks 10.2, one blocker of two
//!
//! `PKCS12_SAFEBAG_create_cert`/`create_crl` (`crypto/pkcs12/p12_sbag.c`, 10.2) call this function
//! with `ASN1_ITEM_rptr(X509)`/`X509_CRL`; landing it here removes 10.3 from their closure, but
//! **both still need Phase 11's `X509_it`/`X509_CRL_it`** to name the item at all, so they remain
//! `open` and their court blocker moves from `phase-10.3` to `phase-11-x509` rather than
//! disappearing. That split is recorded rather than rounded away.
//!
//! The unit raises from [`PKCS12_item_pack_safebag`], so `crypto/pkcs12/p12_add.c` is an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES` with stem `PKCS12_ADD` (the `PKCS12` stem is
//! already carried by `p12_decr.c`/`p12_sbag.c`, whose line numbers collide with this file's, and
//! a shared stem would emit two different constants with one name).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::asn_pack::{ASN1_item_pack, ASN1_item_unpack_ex};
use crate::asn1::layout::{Asn1Item, Asn1String};
use crate::asn1::p8_pkey::Pkcs8PrivKeyInfo;
use crate::asn1::string::ASN1_OCTET_STRING_new;
use crate::asn1::x_sig::X509Sig;
use crate::pkcs12::p12_asn::{
    PKCS12_AUTHSAFES_it, PKCS12_BAGS_free, PKCS12_BAGS_new, PKCS12_SAFEBAGS_it, PKCS12_SAFEBAG_new,
    Pkcs12, Pkcs12Safebag,
};
use crate::pkcs12::p12_decr::PKCS12_item_decrypt_d2i_ex;
use crate::pkcs12::p12_p8d::PKCS8_decrypt_ex;
use crate::pkcs7::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_ctx_propagate, PKCS7_free,
    PKCS7_new, Pkcs7,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{OBJ_nid2obj, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};

/// `PKCS12_SAFEBAG *PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it, int nid1, int nid2)`
/// — `crypto/pkcs12/p12_add.c:20-46`.
///
/// Packs `obj` through `it` into a `PKCS12_BAGS` whose `BAG-TYPE` is `nid1`, then wraps that in a
/// `PKCS12_SAFEBAG` whose `bagId` is `nid2`. The three allocation/decode failures each raise
/// `ERR_R_ASN1_LIB` and answer NULL, and the `PKCS12_BAGS` is released on the two that happen
/// after it exists.
///
/// # Safety
/// `obj` is NULL or a live value of `it`'s type; `it` is a live item. The answer is owned by the
/// caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_item_pack_safebag(
    obj: *mut c_void,
    it: *const Asn1Item,
    nid1: c_int,
    nid2: c_int,
) -> *mut Pkcs12Safebag {
    // SAFETY: no preconditions.
    let bag = PKCS12_BAGS_new();
    if bag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_ADD_27) };
        return ptr::null_mut();
    }
    // SAFETY: `bag` is live and its `type_` slot is writable.
    unsafe { (*bag).type_ = OBJ_nid2obj(nid1) };

    // The `value` union's `octet` arm is the `ASN1_OCTET_STRING *` an `ASN1_item_pack` fills; it
    // shares the union's offset, so the field's own address is the out-slot the packer writes.
    // SAFETY: `bag` is live; `obj`/`it` are the caller's; the packer owns the slot's content on
    // success and leaves it untouched on failure.
    let packed =
        unsafe { ASN1_item_pack(obj, it, (&raw mut (*bag).value).cast::<*mut Asn1String>()) };
    if packed.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_ADD_32) };
        // SAFETY: `bag` is live and this call owns it.
        unsafe { PKCS12_BAGS_free(bag) };
        return ptr::null_mut();
    }

    // SAFETY: no preconditions.
    let safebag = PKCS12_SAFEBAG_new();
    if safebag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_ADD_36) };
        // SAFETY: `bag` is live and this call owns it.
        unsafe { PKCS12_BAGS_free(bag) };
        return ptr::null_mut();
    }
    // SAFETY: both are live; ownership of `bag` passes to `safebag`.
    unsafe {
        (*safebag).value = bag.cast();
        (*safebag).type_ = OBJ_nid2obj(nid2);
    }
    safebag
}

/// `PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey_ex(const PKCS12_SAFEBAG *bag, const char *pass,
/// int passlen, OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/pkcs12/p12_add.c:173-178`.
///
/// The shrouded-key-bag reader: it borrows the bag's `X509_SIG` and hands it to
/// `PKCS8_decrypt_ex`. The selector is not checked here — the authority spells none either, so a
/// bag of another type reinterprets the union's `shkeybag` arm exactly as it does.
///
/// # Safety
/// `bag` is live; `pass` is NULL or a string of `passlen` bytes (or `passlen == -1`);
/// `ctx`/`propq` are the PBE lookup's. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_decrypt_skey_ex(
    bag: *const Pkcs12Safebag,
    pass: *const c_char,
    passlen: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: `bag` is live; the union's `shkeybag` arm is read as the authority reads it.
    let shkeybag = unsafe { (*bag).value.cast::<X509Sig>() };
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { PKCS8_decrypt_ex(shkeybag, pass, passlen, ctx, propq) }
}

/// `PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(const PKCS12_SAFEBAG *bag, const char *pass,
/// int passlen)` — `crypto/pkcs12/p12_add.c:180-184`.
///
/// # Safety
/// As [`PKCS12_decrypt_skey_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_decrypt_skey(
    bag: *const Pkcs12Safebag,
    pass: *const c_char,
    passlen: c_int,
) -> *mut Pkcs8PrivKeyInfo {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS12_decrypt_skey_ex(bag, pass, passlen, ptr::null_mut(), ptr::null()) }
}

/// `PKCS7_type_is_data(a)` — `pkcs7.h.in:194`, `OBJ_obj2nid((a)->type) == NID_pkcs7_data`. The
/// macro's spelling, which is how the two `unpack` readers guard their arm.
///
/// # Safety
/// `p7` is null or a live `PKCS7`.
unsafe fn pkcs7_type_is_data(p7: *const Pkcs7) -> bool {
    if p7.is_null() {
        return false;
    }
    // SAFETY: `p7` is live per the caller's contract.
    unsafe { OBJ_obj2nid((*p7).type_) == crate::runtime::obj::NID_pkcs7_data }
}

/// `PKCS7_type_is_encrypted(a)` — `pkcs7.h.in:190`.
///
/// # Safety
/// `p7` is null or a live `PKCS7`.
unsafe fn pkcs7_type_is_encrypted(p7: *const Pkcs7) -> bool {
    if p7.is_null() {
        return false;
    }
    // SAFETY: `p7` is live per the caller's contract.
    unsafe { OBJ_obj2nid((*p7).type_) == crate::runtime::obj::NID_pkcs7_encrypted }
}

/// `void pkcs7_free_void(void *p)` — the `FreeFn` shape `OPENSSL_sk_pop_free` takes, wrapping
/// [`PKCS7_free`] for the stack the authority releases on its `err:` label.
///
/// # Safety
/// `p` is null or a `PKCS7` this item layer owns.
unsafe extern "C" fn pkcs7_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { PKCS7_free(p.cast()) }
}

/// `PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk)` — `crypto/pkcs12/p12_add.c:49-72`.
///
/// Builds a `NID_pkcs7_data` contentInfo whose octet string is the `PKCS12_SAFEBAGS` encoding of
/// `sk`. The type OID is assigned rather than set through `PKCS7_set_type`, exactly as the
/// authority does, and the three failures each raise and release the half-built object.
///
/// # Safety
/// `sk` is null or a live stack of `PKCS12_SAFEBAG`. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_pack_p7data(sk: *mut OpenSslStack) -> *mut Pkcs7 {
    // SAFETY: no preconditions.
    let p7 = PKCS7_new();
    if p7.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_ADD_54) };
        return ptr::null_mut();
    }
    // SAFETY: `p7` is live; the item layer built it with an empty content union.
    unsafe {
        (*p7).type_ = OBJ_nid2obj(crate::runtime::obj::NID_pkcs7_data);
        (*p7).d.data = ASN1_OCTET_STRING_new();
        if (*p7).d.data.is_null() {
            raise_site(&err_sites::PKCS12_ADD_59);
            PKCS7_free(p7);
            return ptr::null_mut();
        }
        // The `value` slot's own address is the out-slot the packer fills.
        let packed = ASN1_item_pack(sk.cast(), PKCS12_SAFEBAGS_it(), &raw mut (*p7).d.data);
        if packed.is_null() {
            raise_site(&err_sites::PKCS12_ADD_64);
            PKCS7_free(p7);
            return ptr::null_mut();
        }
    }
    p7
}

/// `STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7)` — `crypto/pkcs12/p12_add.c:75-90`.
///
/// A non-`data` contentInfo and a null octet string are each refused with their own reason; the
/// decode itself runs in the container's context, which is why the `PKCS7` object carries one.
///
/// # Safety
/// `p7` is a live `PKCS7` this item layer built. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_unpack_p7data(p7: *mut Pkcs7) -> *mut OpenSslStack {
    // SAFETY: `p7` is live per the caller's contract.
    unsafe {
        if !pkcs7_type_is_data(p7) {
            raise_site(&err_sites::PKCS12_ADD_78);
            return ptr::null_mut();
        }
        let oct = (*p7).d.data;
        if oct.is_null() {
            raise_site(&err_sites::PKCS12_ADD_83);
            return ptr::null_mut();
        }
        ASN1_item_unpack_ex(
            oct,
            PKCS12_SAFEBAGS_it(),
            ossl_pkcs7_ctx_get0_libctx(&(*p7).ctx),
            ossl_pkcs7_ctx_get0_propq(&(*p7).ctx),
        )
        .cast::<OpenSslStack>()
    }
}

/// `STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7encdata(PKCS7 *p7, const char *pass, int passlen)`
/// — `crypto/pkcs12/p12_add.c:155-171`.
///
/// The encrypted reader: a non-`encrypted` contentInfo answers NULL **without** raising, exactly
/// as the authority's bare `return NULL` does, while a missing content arm raises the decode
/// error. The inner decrypt is the landed `PKCS12_item_decrypt_d2i_ex`, run in the object's own
/// context.
///
/// # Safety
/// `p7` is a live `PKCS7`; `pass` is NULL or a string of `passlen` bytes. The answer is owned by
/// the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_unpack_p7encdata(
    p7: *mut Pkcs7,
    pass: *const c_char,
    passlen: c_int,
) -> *mut OpenSslStack {
    // SAFETY: `p7` is live per the caller's contract.
    unsafe {
        if !pkcs7_type_is_encrypted(p7) {
            return ptr::null_mut();
        }
        let enc = (*p7).d.encrypted;
        if enc.is_null() {
            raise_site(&err_sites::PKCS12_ADD_162);
            return ptr::null_mut();
        }
        let content = (*enc).enc_data;
        PKCS12_item_decrypt_d2i_ex(
            (*content).algorithm,
            PKCS12_SAFEBAGS_it(),
            pass,
            passlen,
            (*content).enc_data,
            1,
            (*p7).ctx.libctx,
            (*p7).ctx.propq,
        )
        .cast::<OpenSslStack>()
    }
}

/// `int PKCS12_pack_authsafes(PKCS12 *p12, STACK_OF(PKCS7) *safes)` —
/// `crypto/pkcs12/p12_add.c:186-192`.
///
/// Packs the `PKCS12_AUTHSAFES` `SEQUENCE OF PKCS7` straight into the `authsafes` object's octet
/// string. It answers 1 on success and 0 otherwise; it raises nothing.
///
/// # Safety
/// `p12` is a live `PKCS12` whose `authsafes` column is set; `safes` is null or a live stack of
/// `PKCS7`.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_pack_authsafes(
    p12: *mut Pkcs12,
    safes: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `p12` and its `authsafes` are live per the caller's contract.
    let packed = unsafe {
        ASN1_item_pack(
            safes.cast(),
            PKCS12_AUTHSAFES_it(),
            &raw mut (*(*p12).authsafes).d.data,
        )
    };
    if packed.is_null() {
        0
    } else {
        1
    }
}

/// `STACK_OF(PKCS7) *PKCS12_unpack_authsafes(const PKCS12 *p12)` —
/// `crypto/pkcs12/p12_add.c:194-227`.
///
/// A non-`data` container and a null octet string are each refused; the decode runs in the
/// container's context and each decoded `PKCS7` has that context propagated into it, so a
/// failure releases the whole stack through [`PKCS7_free`].
///
/// # Safety
/// `p12` is a live `PKCS12` this item layer built. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_unpack_authsafes(p12: *const Pkcs12) -> *mut OpenSslStack {
    // SAFETY: `p12` is live per the caller's contract.
    unsafe {
        let authsafes = (*p12).authsafes;
        if !pkcs7_type_is_data(authsafes) {
            raise_site(&err_sites::PKCS12_ADD_202);
            return ptr::null_mut();
        }
        let oct = (*authsafes).d.data;
        if oct.is_null() {
            raise_site(&err_sites::PKCS12_ADD_207);
            return ptr::null_mut();
        }
        let p7ctx = &(*authsafes).ctx;
        let p7s = ASN1_item_unpack_ex(
            oct,
            PKCS12_AUTHSAFES_it(),
            ossl_pkcs7_ctx_get0_libctx(p7ctx),
            ossl_pkcs7_ctx_get0_propq(p7ctx),
        )
        .cast::<OpenSslStack>();
        if !p7s.is_null() {
            for i in 0..OPENSSL_sk_num(p7s) {
                let p7 = OPENSSL_sk_value(p7s, i).cast::<Pkcs7>();
                if ossl_pkcs7_ctx_propagate(authsafes, p7) == 0 {
                    OPENSSL_sk_pop_free(p7s, Some(pkcs7_free_void));
                    return ptr::null_mut();
                }
            }
        }
        p7s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::items::ASN1_INTEGER_it;
    use crate::asn1::prim::ASN1_INTEGER_set;
    use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new};
    use crate::pkcs12::p12_asn::PKCS12_SAFEBAG_free;
    use crate::pkcs12::p12_sbag::{
        PKCS12_SAFEBAG_get0_bag_obj, PKCS12_SAFEBAG_get_bag_nid, PKCS12_SAFEBAG_get_nid,
    };
    use crate::runtime::obj::{NID_certBag, NID_x509Certificate};

    /// A fixed `ASN1_INTEGER` packed as a `certBag`'s value, and the resulting `SafeBag` reports
    /// the two NIDs the call named. The packed string is the bag's encoding of the caller's
    /// object, which stays the caller's. The object table is process-global state, so the test
    /// runs alone.
    #[test]
    fn item_pack_safebag_builds_a_cert_bag() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions; the integer is set below before it is packed.
        let value = unsafe {
            let i = ASN1_INTEGER_new();
            assert!(!i.is_null());
            assert_eq!(ASN1_INTEGER_set(i, 0x2a), 1);
            i
        };
        // SAFETY: `value` is a live integer of `ASN1_INTEGER_it`'s type; the two NIDs name the
        // bag types the authority's own `create_cert` uses.
        let bag = unsafe {
            PKCS12_item_pack_safebag(
                value.cast(),
                ASN1_INTEGER_it(),
                NID_x509Certificate,
                NID_certBag,
            )
        };
        assert!(!bag.is_null());
        // SAFETY: `bag` is live and its selector says the union holds a `bag`.
        unsafe {
            assert_eq!(PKCS12_SAFEBAG_get_nid(bag), NID_certBag);
            assert_eq!(PKCS12_SAFEBAG_get_bag_nid(bag), NID_x509Certificate);
            // `get0_bag_obj` answers NULL for the three certificate BAG types by design, so the
            // `x509Certificate` arm this call selected is the one that returns nothing.
            assert!(PKCS12_SAFEBAG_get0_bag_obj(bag).is_null());
            // The bag owns the packed string, so the caller's integer is untouched and is freed
            // here; `PKCS12_SAFEBAG_free` releases the bag's own copy.
            ASN1_INTEGER_free(value);
            PKCS12_SAFEBAG_free(bag);
        }
    }
}
