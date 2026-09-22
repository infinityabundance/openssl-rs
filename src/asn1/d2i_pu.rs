//! `crypto/asn1/d2i_pu.c` — `d2i_PublicKey`, the type-switched public-key reader.
//!
//! One export, and it is the reason two `*_ameth.c` objects and `evp_pkey_copy_downgraded` had to
//! exist before it could: the `switch` is on `EVP_PKEY_get_base_id(ret)` — which is `EVP_PKEY_type`
//! reached through `pkey->type`, and therefore the `standard_methods[]` rows D353 published — and
//! each of its three arms names a unit that was withheld at D341's measurement: `d2i_RSAPublicKey`
//! (8.4's, D345), `d2i_DSAPublicKey` (8.6's, D345) and `o2i_ECPublicKey` (8.7's, D347).
//!
//! **The three arms write the `pkey` union in three different ways, and the difference is the
//! authority's rather than this transcription's:** RSA and DSA go through the decoder's own
//! `RSA **`/`DSA **` out-parameter and assign the result, while the EC arm has a
//! **downgraded-parameter** step that moves the group from `copy` into `ret` *before* the point is
//! read — `ret->pkey.ec = copy->pkey.ec; copy->pkey.ec = NULL;` — so that an SEC1 point with no
//! parameters in it is read against the group the caller's provider key already had.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::dsa::asn1::d2i_DSAPublicKey;
use crate::dsa::Dsa;
use crate::ec::asn1::o2i_ECPublicKey;
use crate::ec::EcKey;
use crate::evp::pkey::{
    evp_pkey_copy_downgraded, evp_pkey_is_provided, EVP_PKEY_free, EVP_PKEY_get_base_id,
    EVP_PKEY_get_id, EVP_PKEY_new, EVP_PKEY_set_type, EvpPkey,
};
use crate::evp::pkey_ctx::{EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_RSA};
use crate::rsa::asn1::d2i_RSAPublicKey;
use crate::runtime::err::{err_sites, raise_site};

/// `EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `crypto/asn1/d2i_pu.c:28`.
///
/// `copy` is local and owned by this call on every path: the success path frees it after moving its
/// EC group out, and the `err:` path frees it whether or not it was ever filled. A caller who
/// passes `a == NULL` still gets a key back and still loses `copy`.
///
/// The downgrade happens **before** the type is set, and the `|| copy != NULL` in the type test is
/// what makes the assignment happen on a key whose id already matches: the copy carries the
/// parameters the original's provider side could not give the decoder.
///
/// # Safety
/// `a` must be NULL or point at a writable `EVP_PKEY *` slot; `pp` must point at a readable cursor
/// for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_PublicKey(
    type_: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    let ret: *mut EvpPkey;
    let mut copy: *mut EvpPkey = ptr::null_mut();

    // SAFETY: `a` is NULL or points at the caller's readable slot; the dereference is guarded by the
    // short-circuit, so `*a` is read only when `a` is non-NULL.
    let hold = !a.is_null() && !(unsafe { *a }).is_null();

    if !hold {
        // SAFETY: no preconditions.
        ret = unsafe { EVP_PKEY_new() };
        if ret.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PU_36) };
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `hold` is true, so `a` is non-NULL and `*a` is a live key.
        ret = unsafe { *a };

        /* A provider-side EC key is downgraded so the point can be read against a legacy group. */
        // SAFETY: `ret` is live.
        if unsafe { evp_pkey_is_provided(ret) } != 0
            // SAFETY: `ret` is live.
            && unsafe { EVP_PKEY_get_base_id(ret) } == EVP_PKEY_EC
        {
            // SAFETY: `copy` is a writable local slot and `ret` is live.
            if unsafe { evp_pkey_copy_downgraded(&mut copy, ret) } == 0 {
                // SAFETY: `ret`, `a` and `copy` are the caller's and this call's own.
                return unsafe { err_out(ret, a, copy) };
            }
        }
    }

    let ok = 'body: {
        // SAFETY: `ret` is live.
        if (type_ != unsafe { EVP_PKEY_get_id(ret) } || !copy.is_null())
            // SAFETY: `ret` is live.
            && unsafe { EVP_PKEY_set_type(ret, type_) } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PU_53) };
            break 'body false;
        }

        // SAFETY: `ret` is live.
        match unsafe { EVP_PKEY_get_base_id(ret) } {
            EVP_PKEY_RSA => {
                /* The decoder's own out-parameter is NULL: `d2i_RSAPublicKey(NULL, ...)` builds a
                 * fresh key rather than reading into `ret->pkey.rsa`. */
                // SAFETY: the caller's cursor contract covers `pp` and `length`.
                let rsa = unsafe { d2i_RSAPublicKey(ptr::null_mut(), pp, length) };
                // SAFETY: `ret` is live.
                unsafe { (*ret).pkey = rsa.cast() };
                if rsa.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::D2I_PU_60) };
                    break 'body false;
                }
            }
            EVP_PKEY_DSA => {
                /* `d2i_DSAPublicKey(&ret->pkey.dsa, pp, length)`: the member's address is the
                 * out-parameter, so the local stands in for it and is written back. */
                // SAFETY: `ret` is live.
                let mut dsa: *mut Dsa = unsafe { (*ret).pkey }.cast();
                // SAFETY: the caller's cursor contract covers `pp` and `length`.
                let r = unsafe { d2i_DSAPublicKey(&mut dsa, pp, length) };
                // SAFETY: `ret` is live.
                unsafe { (*ret).pkey = dsa.cast() };
                if r.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::D2I_PU_67) };
                    break 'body false;
                }
            }
            EVP_PKEY_EC => {
                if !copy.is_null() {
                    /* Move the downgraded group into `ret` and clear the copy's, so freeing `copy`
                     * does not free the group the point was read against. */
                    // SAFETY: both keys are live.
                    unsafe {
                        (*ret).pkey = (*copy).pkey;
                        (*copy).pkey = ptr::null_mut();
                    }
                }
                // SAFETY: `ret` is live.
                let mut ec: *mut EcKey = unsafe { (*ret).pkey }.cast();
                // SAFETY: the caller's cursor contract covers `pp` and `length`.
                let r = unsafe { o2i_ECPublicKey(&mut ec, pp, length) };
                // SAFETY: `ret` is live.
                unsafe { (*ret).pkey = ec.cast() };
                if r.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::D2I_PU_80) };
                    break 'body false;
                }
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::D2I_PU_86) };
                break 'body false;
            }
        }
        true
    };

    if !ok {
        // SAFETY: `ret`, `a` and `copy` are the caller's and this call's own.
        return unsafe { err_out(ret, a, copy) };
    }

    if !a.is_null() {
        // SAFETY: `a` is the caller's writable slot.
        unsafe { *a = ret };
    }
    // SAFETY: `copy` is NULL or the downgraded key this call owns.
    unsafe { EVP_PKEY_free(copy) };
    ret
}

/// The authority's `err:` label — `d2i_pu.c:93-97` — as one function, because four arms reach it.
///
/// `*a` is written only on success, so a caller who passed a slot that already held the key this
/// call was given does **not** have it freed under them: the test is pointer identity, not NULL.
///
/// # Safety
/// `ret` must be NULL or live; `a` must be NULL or a live `EVP_PKEY *` slot; `copy` must be NULL or
/// a key this call owns.
unsafe fn err_out(ret: *mut EvpPkey, a: *mut *mut EvpPkey, copy: *mut EvpPkey) -> *mut EvpPkey {
    // SAFETY: `a` is NULL or live and `ret` is NULL or live.
    if a.is_null() || unsafe { *a } != ret {
        // SAFETY: `ret` is NULL or live.
        unsafe { EVP_PKEY_free(ret) };
    }
    // SAFETY: `copy` is NULL or a key this call owns.
    unsafe { EVP_PKEY_free(copy) };
    ptr::null_mut()
}
