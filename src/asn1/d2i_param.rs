//! `crypto/asn1/d2i_param.c` — the two `d2i_KeyParams` readers.
//!
//! The smallest unit on 8.8's closure: two exports and no callback of their own. Both are readers
//! of an **algorithm-parameter** encoding rather than a key, and the thing that makes them landable
//! only now is that `ret->ameth->param_decode` has somewhere to come from — the eleven
//! `standard_methods[]` rows D353 published are what `EVP_PKEY_set_type` resolves `type` through,
//! and the four landed `*_ameth.c` objects are what install a `param_decode` (`dh_param_decode`,
//! `dsa_param_decode`, `eckey_param_decode` and `rsa_param_decode`).
//!
//! `d2i_KeyParams` is the unit's whole contract in nine statements, and each is a different
//! refusal: an untyped `ret` is refused by `EVP_PKEY_set_type`, a typed one with **no** method — or
//! a method with no `param_decode` — is refused with `ASN1_R_UNSUPPORTED_TYPE`, and the callback's
//! own `0` is the third. `d2i_KeyParams_bio` is a `BUF_MEM` read around it, with the buffer
//! released on **both** paths.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::a_d2i_fp::asn1_d2i_read_bio;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get_id, EVP_PKEY_new, EVP_PKEY_set_type, EvpPkey};
use crate::runtime::bio::Bio;
use crate::runtime::buffer::{BUF_MEM_free, BufMem};
use crate::runtime::err::{err_sites, raise_site};

/// `EVP_PKEY *d2i_KeyParams(int type, EVP_PKEY **a, const unsigned char **pp, long length)` —
/// `crypto/asn1/d2i_param.c:18`.
///
/// Two things a reader should not have to re-derive from the body: the caller's slot is written
/// only on success (`a` is NULL-safe, and `*a` is left alone when the read fails), and the method's
/// `param_decode` is the **third** parameter of the three refusals rather than the first — a type
/// whose method has no decoder is refused before the callback is reached.
///
/// The authority passes its `long length` to a callback declared to take `int`, which is an
/// implicit narrowing; the cast reproduces it rather than widening the callback the header fixes.
///
/// # Safety
/// `a` must be NULL or point at a writable `EVP_PKEY *` slot; `pp` must point at a readable cursor
/// for `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn d2i_KeyParams(
    type_: c_int,
    a: *mut *mut EvpPkey,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut EvpPkey {
    // SAFETY: `a` is NULL or points at the caller's readable slot; the dereference is guarded by the
    // short-circuit, so `*a` is read only when `a` is non-NULL.
    let hold = !a.is_null() && !(unsafe { *a }).is_null();

    let ret: *mut EvpPkey;
    if !hold {
        // SAFETY: no preconditions.
        ret = unsafe { EVP_PKEY_new() };
        if ret.is_null() {
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `hold` is true, so `a` is non-NULL and `*a` is a live key.
        ret = unsafe { *a };
    }

    let ok = 'body: {
        // SAFETY: `ret` is live.
        if type_ != unsafe { EVP_PKEY_get_id(ret) }
            // SAFETY: `ret` is live.
            && unsafe { EVP_PKEY_set_type(ret, type_) } == 0
        {
            break 'body false;
        }

        // SAFETY: `ret` is live.
        let ameth = unsafe { (*ret).ameth };
        let param_decode = if ameth.is_null() {
            None
        } else {
            // SAFETY: `ameth` is non-NULL.
            unsafe { (*ameth).param_decode }
        };
        let Some(param_decode) = param_decode else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::D2I_PARAM_33) };
            break 'body false;
        };

        // SAFETY: the callback is the method's own; `ret`, `pp` and `length` are the caller's.
        if unsafe { param_decode(ret, pp, length as c_int) } == 0 {
            break 'body false;
        }
        true
    };

    if ok {
        if !a.is_null() {
            // SAFETY: `a` is the caller's writable slot.
            unsafe { *a = ret };
        }
        return ret;
    }

    /* err: */
    // SAFETY: `a` is NULL or live; `ret` is live.
    if a.is_null() || unsafe { *a } != ret {
        // SAFETY: `ret` is live.
        unsafe { EVP_PKEY_free(ret) };
    }
    ptr::null_mut()
}

/// `EVP_PKEY *d2i_KeyParams_bio(int type, EVP_PKEY **a, BIO *in)` —
/// `crypto/asn1/d2i_param.c:49`.
///
/// The `BUF_MEM` read, then the same call, and the buffer is released on **both** paths — which is
/// the authority's `err:` label being shared by the `len < 0` arm and the success path rather than
/// a `goto` that skips it.
///
/// # Safety
/// `a` must be NULL or point at a writable `EVP_PKEY *` slot; `in` must be a live `BIO`.
#[no_mangle]
pub unsafe extern "C" fn d2i_KeyParams_bio(
    type_: c_int,
    a: *mut *mut EvpPkey,
    in_: *mut Bio,
) -> *mut EvpPkey {
    let mut b: *mut BufMem = ptr::null_mut();
    let mut ret: *mut EvpPkey = ptr::null_mut();

    // SAFETY: `in_` is live and `b` is the out-parameter the reader fills.
    let len = unsafe { asn1_d2i_read_bio(in_, &mut b) };
    if len >= 0 {
        // SAFETY: the reader answered a non-negative length, so `b` is live and `b->data` is
        // readable for `len` bytes; `p` is a live local cursor.
        let mut p: *const c_uchar = unsafe { (*b).data }.cast();
        // SAFETY: `a` is the caller's contract; `p` is the buffer above.
        ret = unsafe { d2i_KeyParams(type_, a, &mut p, len as c_long) };
    }

    // SAFETY: `b` is NULL or the buffer this call owns.
    unsafe { BUF_MEM_free(b) };
    ret
}
