//! Phase 5 — the `d2i_*` readers for the primitive types.
//!
//! Each of these is, in the authority, one call to `ASN1_item_d2i` with the
//! matching item. There is no `ASN1_ITEM` for the primitive types in this crate
//! yet — the template machinery is subphase 5.4 — so the path those items take is
//! reproduced directly here: `asn1_d2i_ex_primitive` in `crypto/asn1/tasn_dec.c`,
//! restricted to what an item with no `funcs`, no `templates` and a fixed `utype`
//! can reach.
//!
//! ## Why stating that restriction is safe
//!
//! An `ASN1_ITYPE_PRIMITIVE` item with `templates == NULL` reaches exactly one
//! branch of the authority's decoder, and the branches needing the wider machinery
//! are unreachable from it: no `CHOICE` selector, no optional field, no `ANY`
//! (`utype` is never `V_ASN1_ANY`), no `MSTRING`, and no supplied
//! `ASN1_PRIMITIVE_FUNCS`, so the `pf->prim_c2i` path at `tasn_dec.c:873` is not
//! taken. What *is* reachable is everything a caller can hand a malformed encoding:
//! the tag and class check, the definite/indefinite distinction, the constructed
//! form, the collected content, and the per-type `c2i` — all implemented below with
//! the authority's own error coordinates.
//!
//! ## The two branches a reader is most likely to get wrong
//!
//! **The `TOO_LONG` check runs before the header check.** `asn1_check_tlen` is
//! given a non-null `ctx` by `ASN1_item_d2i`, so it takes the caching branch, and
//! in that branch it validates `plen + hdrlen <= len` *before* it looks at the
//! header's error bit. Reordering those two reports `BAD_OBJECT_HEADER` where the
//! authority reports `TOO_LONG`.
//!
//! **A constructed string is collected, not rejected.** `OCTET STRING` has a legal
//! constructed form, so the decoder concatenates the contents of its elements into
//! one buffer and hands *that* to `c2i` with ownership transferred. Only `NULL`,
//! `BOOLEAN`, `OBJECT`, `INTEGER` and `ENUMERATED` are refused in constructed form
//! (`TYPE_NOT_PRIMITIVE`). The collected buffer is allocated with the `CRYPTO_*`
//! allocator rather than a Rust `Vec`, because `ASN1_STRING_set0` takes ownership of
//! it and releases it with `CRYPTO_free` — a `Vec`'s pointer would be a mismatch no
//! test would notice until a heap hook was installed.
//!
//! ## What is still deferred, and it is named
//!
//! The wrappers for the *other* primitive types — `BIT_STRING`, `NULL`, the fifteen
//! string types, `TIME` and its two forms — are subphase 5.3's remaining work and
//! land the same way. This module holds the three `der.rs`'s `ASN1_parse_dump`
//! needs, so that the DER codec can be courted.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::layout::*;
use crate::asn1::prim::ossl_c2i_ASN1_INTEGER;
use crate::asn1::string::{string_embed_free, string_set_body, string_type_new};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};

/// The authority translation unit for the decoder these wrappers reproduce.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_dec.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ASN1_MAX_STRING_NEST` — how deep a constructed string may nest. Read from
/// `tasn_dec.c:1080`, where the authority defines it.
const MAX_STRING_NEST: c_int = 5;

/// `asn1_check_eoc` — is the next thing an end-of-contents marker?
///
/// # Safety
///
/// `in_` must point to a slot holding a readable pointer to `len` bytes; the slot
/// is advanced past the marker when one is found.
unsafe fn check_eoc(in_: *mut *const c_uchar, len: c_long) -> bool {
    if len < 2 {
        return false;
    }
    // SAFETY: the caller guarantees the slot and its pointee.
    let p = unsafe { *in_ };
    // SAFETY: `len >= 2`, so two octets are readable.
    let zero_zero = unsafe { *p } == 0 && unsafe { *p.add(1) } == 0;
    if zero_zero {
        // SAFETY: the slot is writable per the caller's contract.
        unsafe { *in_ = p.add(2) };
    }
    zero_zero
}

/// The buffer `asn1_collect` fills. A `CRYPTO_*` allocation because
/// `ASN1_STRING_set0` takes ownership of it.
struct Collected {
    /// The bytes so far, or null when nothing has been appended.
    data: *mut u8,
    /// How many are meaningful.
    len: usize,
    /// How many are allocated.
    cap: usize,
}

impl Collected {
    fn new() -> Self {
        Collected {
            data: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// `collect_data` — grow to fit and append, or raise and answer 0.
    ///
    /// # Safety
    ///
    /// `p` must be readable for `plen` bytes.
    unsafe fn append(&mut self, p: *const u8, plen: usize) -> c_int {
        // The authority's own overflow test: the *resulting* length must fit a
        // `long`.
        if (self.len as c_long).saturating_add(plen as c_long) < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_1147) };
            return 0;
        }
        let want = self.len + plen;
        if want > self.cap {
            // SAFETY: `self.data` came from this allocator or is null; `want` is
            // the new size.
            let fresh =
                unsafe { CRYPTO_realloc(self.data.cast::<c_void>(), want, FILE.as_ptr(), LINE) }
                    as *mut u8;
            if fresh.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_1151) };
                return 0;
            }
            self.data = fresh;
            self.cap = want;
        }
        if plen != 0 {
            // SAFETY: the destination has room for `plen` bytes at `len`, and the
            // source is readable for `plen`.
            unsafe { core::ptr::copy_nonoverlapping(p, self.data.add(self.len), plen) };
        }
        self.len += plen;
        1
    }

    /// Release the buffer. Used only on failure paths: on success ownership passes
    /// to an `ASN1_STRING`.
    fn discard(&mut self) {
        if !self.data.is_null() {
            // SAFETY: `data` came from this allocator and is not used again.
            unsafe { CRYPTO_free(self.data.cast::<c_void>(), FILE.as_ptr(), LINE) };
            self.data = core::ptr::null_mut();
            self.len = 0;
            self.cap = 0;
        }
    }
}

/// `asn1_collect` — concatenate the content octets of successive elements.
///
/// # Safety
///
/// `in_` must point to a slot holding a readable pointer to `len_in` bytes; the
/// slot is advanced past what was consumed.
unsafe fn collect(
    buf: &mut Collected,
    in_: *mut *const c_uchar,
    len_in: c_long,
    inf_in: bool,
    tag: c_int,
    aclass: c_int,
    depth: c_int,
) -> c_int {
    // SAFETY: the caller guarantees the slot and its pointee.
    let mut p = unsafe { *in_ };
    let mut len = len_in;
    let mut inf = inf_in;
    while len > 0 {
        let q = p;
        // SAFETY: `p` is readable for `len` bytes and the slot is writable.
        let mut slot = p;
        // SAFETY: `p` is readable for `len` bytes and the slot is writable.
        if unsafe { check_eoc(&mut slot, len) } {
            p = slot;
            if !inf {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_1107) };
                return 0;
            }
            inf = false;
            break;
        }
        let mut plen: c_long = 0;
        let mut ininf: c_uchar = 0;
        let mut cst: c_uchar = 0;
        // `asn1_check_tlen` with a null cache — no `TOO_LONG` pre-check here, which
        // is why the authority passes `ctx = NULL` on this call too.
        // SAFETY: `p` is readable for `len` bytes; the outputs are local slots.
        let ok = unsafe {
            check_tlen(
                &mut plen,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut ininf,
                &mut cst,
                &mut p,
                len,
                tag,
                aclass,
                false,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_1116) };
            return 0;
        }
        if cst != 0 {
            if depth >= MAX_STRING_NEST {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_1123) };
                return 0;
            }
            // SAFETY: `buf` is ours; the recursion advances `p`.
            if unsafe { collect(buf, &mut p, plen, ininf != 0, tag, aclass, depth + 1) } == 0 {
                return 0;
            }
        } else if plen != 0 {
            // SAFETY: `p` is readable for `plen` bytes.
            if unsafe { buf.append(p, plen as usize) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            p = unsafe { p.add(plen as usize) };
        }
        len -= p as c_long - q as c_long;
    }
    if inf {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_1133) };
        return 0;
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *in_ = p };
    1
}

/// `asn1_check_tlen` — read one header, honouring a cache when `ctx` is non-null.
///
/// Returns 1 on success, 0 on error, and -1 for an absent optional field.
///
/// # Safety
///
/// `in_` must point to a slot holding a readable pointer to `len` bytes. Every
/// output pointer must be null or writable, and `ctx` null or a live cache.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn check_tlen(
    olen: *mut c_long,
    otag: *mut c_int,
    oclass: *mut c_uchar,
    inf: *mut c_uchar,
    cst: *mut c_uchar,
    in_: *mut *const c_uchar,
    len: c_long,
    exptag: c_int,
    expclass: c_int,
    opt: bool,
    ctx: *mut Asn1Tlc,
) -> c_int {
    // SAFETY: the caller guarantees the slot and its pointee.
    let mut p = unsafe { *in_ };
    let q = p;

    if len <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_1196) };
        return 0;
    }
    let mut ptag: c_int = 0;
    let mut pclass: c_int = 0;
    let mut plen: c_long = 0;
    let i;
    // SAFETY: `ctx` is null or live per the caller's contract.
    let cached = !ctx.is_null() && unsafe { (*ctx).valid } != 0;
    if cached {
        // SAFETY: `ctx` is live and marked valid.
        unsafe {
            i = (*ctx).ret;
            plen = (*ctx).plen;
            pclass = (*ctx).pclass;
            ptag = (*ctx).ptag;
            p = p.add((*ctx).hdrlen as usize);
        }
    } else {
        // SAFETY: `p` is readable for `len` bytes; the outputs are local slots.
        i = unsafe {
            crate::asn1::der::ASN1_get_object(&mut p, &mut plen, &mut ptag, &mut pclass, len)
        };
        if !ctx.is_null() {
            // SAFETY: `ctx` is a live cache; the slot is writable.
            unsafe {
                (*ctx).ret = i;
                (*ctx).plen = plen;
                (*ctx).pclass = pclass;
                (*ctx).ptag = ptag;
                (*ctx).hdrlen = (p as c_long - q as c_long) as c_int;
                (*ctx).valid = 1;
            }
            // A definite length with no error must fit the available data. This
            // check runs *before* the header's error bit is consulted, which is the
            // ordering a reader most easily gets wrong.
            // SAFETY: `ctx` is live.
            if (i & 0x81) == 0 && unsafe { (*ctx).hdrlen as c_long } + plen > len {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_1219) };
                return 0;
            }
        }
    }
    if i & 0x80 != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_1226) };
        return 0;
    }
    if exptag >= 0 {
        if exptag != ptag || expclass != pclass {
            if opt {
                // "Not present" rather than "wrong"; the caller decides.
                return -1;
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_1236) };
            return 0;
        }
        if !ctx.is_null() {
            // SAFETY: `ctx` is a live cache.
            unsafe { (*ctx).valid = 0 };
        }
    }
    if i & 1 != 0 {
        plen = len - (p as c_long - q as c_long);
    }
    if !inf.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *inf = (i & 1) as c_uchar };
    }
    if !cst.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *cst = (i & V_ASN1_CONSTRUCTED) as c_uchar };
    }
    if !olen.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *olen = plen };
    }
    if !oclass.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *oclass = pclass as c_uchar };
    }
    if !otag.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *otag = ptag };
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *in_ = p };
    1
}

/// `asn1_d2i_ex_primitive` restricted to an item with no `funcs`, no `templates`
/// and a fixed `utype`.
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `inlen` bytes. `a` must
/// be null or point to a slot holding null or a live string of type `utype`.
unsafe fn d2i_ex_primitive(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    inlen: c_long,
    utype: c_int,
) -> *mut Asn1String {
    if pp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller guarantees the slot and its pointee.
    let mut p = unsafe { *pp };
    // `ASN1_item_d2i` hands the decoder a cache, so the `TOO_LONG` pre-check runs.
    let mut tlc = Asn1Tlc {
        valid: 0,
        ret: 0,
        plen: 0,
        ptag: 0,
        pclass: 0,
        hdrlen: 0,
    };
    let mut plen: c_long = 0;
    let mut inf: c_uchar = 0;
    let mut cst: c_uchar = 0;
    // SAFETY: `p` is readable for `inlen` bytes; the outputs are local slots.
    let ret = unsafe {
        check_tlen(
            &mut plen,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut inf,
            &mut cst,
            &mut p,
            inlen,
            utype,
            V_ASN1_UNIVERSAL,
            false,
            &mut tlc,
        )
    };
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_779) };
        return core::ptr::null_mut();
    }
    if ret == -1 {
        // Unreachable with `opt == false`, but the authority's contract allows it.
        return core::ptr::null_mut();
    }

    // SEQUENCE, SET and OTHER are kept in encoded form; none of them is this
    // decoder's `utype`, so that branch is not reachable here.
    let mut buf = Collected::new();
    let mut free_cont = false;
    let cont: *const u8;
    let len: c_long;
    if cst != 0 {
        if matches!(
            utype,
            V_ASN1_NULL | V_ASN1_BOOLEAN | V_ASN1_OBJECT | V_ASN1_INTEGER | V_ASN1_ENUMERATED
        ) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_814) };
            return core::ptr::null_mut();
        }
        let mut q = p;
        // SAFETY: `q` is readable for `plen` bytes.
        if unsafe { collect(&mut buf, &mut q, plen, inf != 0, -1, V_ASN1_UNIVERSAL, 0) } == 0 {
            buf.discard();
            return core::ptr::null_mut();
        }
        p = q;
        free_cont = true;
        cont = buf.data;
        len = buf.len as c_long;
    } else {
        // SAFETY: `p` is readable for `plen` bytes.
        cont = p;
        len = plen;
        // SAFETY: `p` holds `plen` content bytes by the header just read.
        p = unsafe { p.add(plen.max(0) as usize) };
    }

    let ilen = len as c_int;
    let existing = if a.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the caller's slot is readable.
        unsafe { *a }
    };

    let ret = match utype {
        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            let mut cur = cont;
            // SAFETY: `cur` is readable for `len` bytes.
            let tint = unsafe { ossl_c2i_ASN1_INTEGER(a, &mut cur, len) };
            if tint.is_null() {
                buf.discard();
                return core::ptr::null_mut();
            }
            // The expected type is stamped over whatever the content codec left,
            // keeping only the sign bit.
            // SAFETY: `tint` is live.
            unsafe { (*tint).type_ = utype | ((*tint).type_ & V_ASN1_NEG) };
            tint
        }
        _ => {
            // `OCTET STRING`, the string types, `OTHER`, `SET` and `SEQUENCE`: all
            // `ASN1_STRING`-based and handled the same way.
            if len != ilen as c_long {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_950) };
                buf.discard();
                return core::ptr::null_mut();
            }
            let stmp = if existing.is_null() {
                let fresh = string_type_new(utype);
                if fresh.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_973) };
                    buf.discard();
                    return core::ptr::null_mut();
                }
                if !a.is_null() {
                    // SAFETY: the caller's slot is writable.
                    unsafe { *a = fresh };
                }
                fresh
            } else {
                // SAFETY: `existing` is live.
                unsafe { (*existing).type_ = utype };
                existing
            };
            if free_cont {
                // The collected buffer becomes the string's storage; ownership
                // transfers, so it must not be freed here.
                // SAFETY: `stmp` is live and uniquely owned; `cont` is the buffer
                // `buf` owns, which is handed over by this call.
                unsafe {
                    crate::asn1::string::ASN1_STRING_set0(stmp, cont as *mut c_void, ilen);
                }
                // Ownership has moved; stop `buf` from releasing it.
                buf.data = core::ptr::null_mut();
                buf.cap = 0;
                buf.len = 0;
            // SAFETY: `stmp` is live; `cont` is readable for `ilen`.
            } else if unsafe { string_set_body(stmp, cont, ilen) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_987) };
                // SAFETY: `stmp` is ours because it was just allocated; when it is
                // the caller's, the caller keeps it, as the authority does.
                if existing.is_null() {
                    // SAFETY: `stmp` was allocated above and is ours.
                    unsafe { string_embed_free(stmp, 0) };
                    if !a.is_null() {
                        // SAFETY: the caller's slot is writable.
                        unsafe { *a = core::ptr::null_mut() };
                    }
                }
                buf.discard();
                return core::ptr::null_mut();
            }
            stmp
        }
    };
    buf.discard();
    // SAFETY: the caller's slot is writable and the content has been consumed.
    unsafe { *pp = p };
    ret
}

/// `ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a,
/// const unsigned char **in, long len)`
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must be
/// null or point to a slot holding null or a live octet string.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_OCTET_STRING(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract is null-or-valid.
        unsafe { d2i_ex_primitive(a, pp, len, V_ASN1_OCTET_STRING) }
    })
}

/// `ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in,
/// long len)`
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must be
/// null or point to a slot holding null or a live integer.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_INTEGER(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract is null-or-valid.
        unsafe { d2i_ex_primitive(a, pp, len, V_ASN1_INTEGER) }
    })
}

/// `ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a,
/// const unsigned char **in, long len)`
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must be
/// null or point to a slot holding null or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_ENUMERATED(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract is null-or-valid.
        unsafe { d2i_ex_primitive(a, pp, len, V_ASN1_ENUMERATED) }
    })
}
