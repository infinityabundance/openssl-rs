//! Phase 5 — `a_dup.c`: duplicate a value by encoding and decoding it.
//!
//! There is no structural copy here and there deliberately is not one. The authority's
//! own comment says so: "At some point this could be rewritten to directly dup the
//! underlying structure instead of doing an encode and decode." Until then the
//! duplicate is whatever the round trip produces, which is observable: a structure whose
//! cached encoding is stale, or one whose `ASN1_AUX` callback transforms it, duplicates
//! as the *encoded* form rather than as the in-memory form.
//!
//! ## The callbacks are given the original, not the copy
//!
//! `ASN1_ITEM_DUP_PRE` is told about the input, and `ASN1_OP_GET0_LIBCTX` /
//! `ASN1_OP_GET0_PROPQ` are how the value hands its library context and property query to
//! the decode — so a duplicate of a value fetched with a non-default context is decoded
//! under that same context. `ASN1_OP_DUP_POST` is handed **both**: the new value as
//! `pval` and the original as the callback's `exarg`. A callback that only looks at
//! `pval` therefore sees the copy, and one that also uses `exarg` can compare the two.
//!
//! The callback is only fetched for the three item types that can carry one, and that
//! check is not an optimisation: for a `PRIMITIVE` or `EXTERN` item `funcs` is a
//! different structure, so reading `asn1_cb` out of it would be reading another type's
//! field.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::d2i::ASN1_item_d2i_ex;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::str::OPENSSL_strnlen;

/// The authority translation unit for the duplication path.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_dup.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// How many bytes precede the NUL of a C string, via the crate's own `OPENSSL_strnlen`.
///
/// # Safety
///
/// `s` must be null or point to a NUL-terminated string.
unsafe fn c_strlen(s: *const core::ffi::c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe { OPENSSL_strnlen(s, usize::MAX) }
}

/// `void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, const void *x)`
///
/// The legacy `xnew`-less pair: the encode and the decode are the caller's, and the
/// buffer between them is a plain allocation of the encoded length **plus ten** — the
/// slack is the authority's and is not used by anything, which is why a caller cannot
/// observe it beyond the allocation succeeding where a tighter one might have.
///
/// # Safety
///
/// `i2d` and `d2i` must be live functions matching each other's type; neither is checked
/// for null, here or in the authority. `x` must be null or a live value of that type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_dup(i2d: I2dOfVoid, d2i: D2iOfVoid, x: *const c_void) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        if x.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `i2d` is the caller's live function and a null destination is the
        // sizing convention it shares with `ASN1_item_i2d`.
        let sized = unsafe { i2d(x, core::ptr::null_mut()) };
        if sized <= 0 {
            return core::ptr::null_mut();
        }
        // `+ 10` is the authority's slack, reproduced because the allocation either
        // succeeds or does not, and a caller can observe which.
        let b = CRYPTO_malloc(sized as usize + 10, FILE.as_ptr(), LINE) as *mut c_uchar;
        if b.is_null() {
            return core::ptr::null_mut();
        }
        let mut p = b;
        // SAFETY: `p` has room for the length the sizing pass reported, and `i2d` is
        // the caller's function.
        let written = unsafe { i2d(x, &mut p) };
        let mut p2: *const c_uchar = b;
        // SAFETY: `b` holds `written` bytes and `d2i` is the caller's function.
        let ret = unsafe { d2i(core::ptr::null_mut(), &mut p2, c_long::from(written)) };
        // SAFETY: `b` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(b.cast::<c_void>(), FILE.as_ptr(), LINE) };
        ret
    })
}

/// `void *ASN1_item_dup(const ASN1_ITEM *it, const void *x)`
///
/// The item-driven form, which allocates no intermediate buffer of its own:
/// `ASN1_item_i2d` with a null `out` allocates exactly the encoding, and the decode reads
/// from it.
///
/// The three `ASN1_AUX` callbacks are only consulted for the item types that can carry
/// one. When any of them fails the whole call reports `ASN1_R_AUX_ERROR` with
/// `Type=<sname>` as additional data, which is the same tail `asn1_item_embed_d2i` uses.
///
/// # Safety
///
/// `it` must be a live item. `x` must be null or a live value of `it`'s type.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_dup(it: *const Asn1Item, x: *const c_void) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        if x.is_null() || it.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `it` is non-null per the check above.
        let item = unsafe { &*it };

        // Only a `CHOICE` or a `SEQUENCE` item can carry an `ASN1_AUX`: for the other
        // types `funcs` is a different structure, so this guard is what keeps the read
        // below from being a read of another type's field.
        let mut cb: Option<Asn1AuxCb> = None;
        if matches!(
            item.itype,
            ASN1_ITYPE_SEQUENCE | ASN1_ITYPE_CHOICE | ASN1_ITYPE_NDEF_SEQUENCE
        ) {
            let aux = item.funcs.cast::<Asn1Aux>();
            if !aux.is_null() {
                // SAFETY: for these three item types `funcs` is the `ASN1_AUX`.
                cb = unsafe { (*aux).asn1_cb };
            }
        }

        // The callbacks are given the *original*, and the library context and property
        // query come out of it, so the decode below happens under the context the value
        // was fetched with rather than the default one.
        let mut libctx: *mut c_void = core::ptr::null_mut();
        let mut propq: *const core::ffi::c_char = core::ptr::null();
        if let Some(f) = cb {
            // The authority passes the address of its own `x` parameter, so a callback
            // that writes through the slot replaces the value this call duplicates.
            let mut xslot: *const c_void = x;
            // SAFETY: the callback is the caller's, with the authority's signature, and
            // every output is this frame's own slot.
            let ok = unsafe {
                f(
                    ASN1_OP_DUP_PRE,
                    (&mut xslot as *mut *const c_void).cast::<*mut c_void>(),
                    it,
                    core::ptr::null_mut(),
                ) != 0
                    && f(
                        ASN1_OP_GET0_LIBCTX,
                        (&mut xslot as *mut *const c_void).cast::<*mut c_void>(),
                        it,
                        (&mut libctx as *mut *mut c_void).cast::<c_void>(),
                    ) != 0
                    && f(
                        ASN1_OP_GET0_PROPQ,
                        (&mut xslot as *mut *const c_void).cast::<*mut c_void>(),
                        it,
                        (&mut propq as *mut *const core::ffi::c_char).cast::<c_void>(),
                    ) != 0
            };
            if !ok {
                return aux_error(item);
            }
        }

        let mut b: *mut c_uchar = core::ptr::null_mut();
        // SAFETY: `x` is a live value of the item's type and `b` is a null slot, which
        // is what asks for an allocation.
        let n = unsafe { ASN1_item_i2d(x, &mut b, it) };
        if n < 0 || b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_DUP_79) };
            return core::ptr::null_mut();
        }
        let mut p: *const c_uchar = b;
        // SAFETY: `b` holds `n` bytes and `p` is advanced by the decode.
        let ret = unsafe {
            ASN1_item_d2i_ex(
                core::ptr::null_mut(),
                &mut p,
                c_long::from(n),
                it,
                libctx,
                propq,
            )
        };
        // SAFETY: `b` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(b.cast::<c_void>(), FILE.as_ptr(), LINE) };

        if let Some(f) = cb {
            let mut retslot: *mut c_void = ret;
            // `exarg` is the original here, not null, which is the only callback in this
            // file that gets one.
            // SAFETY: the callback is the caller's.
            if unsafe {
                f(
                    ASN1_OP_DUP_POST,
                    &mut retslot,
                    it,
                    x.cast_mut().cast::<c_void>(),
                )
            } == 0
            {
                return aux_error(item);
            }
            // The callback may have replaced the value it was handed.
            return retslot;
        }

        ret
    })
}

/// The authority's `auxerr:` tail: `ASN1_R_AUX_ERROR` with the item's name as data.
///
/// It is `ERR_raise_data`, not `ERR_raise`, so the entry carries `Type=<sname>` and a
/// caller reading `ERR_get_error_all` sees it — which is what makes a callback failure
/// distinguishable from the decode failure it would otherwise look like.
fn aux_error(item: &Asn1Item) -> *mut c_void {
    // SAFETY: `item.sname` is the item's own static NUL-terminated name.
    let n = unsafe { c_strlen(item.sname) };
    // SAFETY: `sname` is NUL-terminated, so `n` bytes are readable.
    let sname = unsafe { core::slice::from_raw_parts(item.sname.cast::<u8>(), n) };
    let msg = format!("Type={}\0", String::from_utf8_lossy(sname));
    // SAFETY: `msg` is NUL-terminated and outlives the call; the site is a
    // compile-time constant.
    unsafe { raise_site_data(&err_sites::A_DUP_93, msg.as_ptr().cast()) };
    core::ptr::null_mut()
}
