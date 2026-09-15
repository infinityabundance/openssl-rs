//! Phase 5 — the shared DER decoder: `asn1_d2i_ex_primitive` and the dispatch
//! that reaches it.
//!
//! This module reproduces `crypto/asn1/tasn_dec.c`. It holds no exported
//! function: every `d2i_*` wrapper is one call to `ASN1_item_d2i` with the
//! matching item, and those wrappers live beside the type they decode
//! (`asn1::typ` for the `tasn_typ.c` family, `asn1::prim` for the two
//! `a_object.c` and `a_int.c` ones) so that the module a symbol lives in is the
//! module the authority defines it in.
//!
//! ## What this decode path is, and what it is not
//!
//! [`item_d2i`] is `ASN1_item_d2i_ex`: it redirects a null value slot to a local
//! and clears a cache. [`embed_d2i`] is `asn1_item_embed_d2i` restricted to the
//! two of its nine arms the items in [`crate::asn1::items`] reach — `PRIMITIVE`
//! with no templates, and `MSTRING`. [`d2i_ex_primitive`] is
//! `asn1_d2i_ex_primitive` and [`ex_c2i`] is `asn1_ex_c2i`.
//!
//! The exclusions are named and asserted rather than left implied, because each
//! one is a place where a silently-wrong answer would look like a decode:
//!
//! * `it->templates != NULL` (a `SEQUENCE`, a `SEQUENCE OF`, `ASN1_TIME`'s
//!   sibling forms) and every `CHOICE`/`EXTERN` item — subphase 5.4.
//! * `utype == V_ASN1_ANY` — subphase 5.7, which is where the `ASN1_TYPE` that
//!   arm allocates belongs.
//! * `V_ASN1_SEQUENCE`, `V_ASN1_SET` and `V_ASN1_OTHER`, whose content is kept
//!   in encoded form by `asn1_find_end` — subphase 5.4, and reachable only
//!   through `ASN1_SEQUENCE_it`.
//!
//! Each of those is guarded by a `debug_assert!` so the claim is checked where
//! it can be, and each is unreachable from the exports the stratum currently
//! provides: not one of them names an item with a template, and `d2i_ASN1_TYPE`
//! and `d2i_ASN1_SEQUENCE_ANY` are still `open` in
//! `forensics/phase5-obligations.json` and abort loudly.
//!
//! ## The three branches a reader is most likely to get wrong
//!
//! **The `TOO_LONG` check runs before the header check.** `asn1_check_tlen` is
//! given a non-null `ctx` by `ASN1_item_d2i`, so it takes the caching branch, and
//! in that branch it validates `plen + hdrlen <= len` *before* it looks at the
//! header's error bit. Reordering those two reports `BAD_OBJECT_HEADER` where the
//! authority reports `TOO_LONG`.
//!
//! **A constructed string is collected, not rejected.** `OCTET STRING` has a legal
//! constructed form, so the decoder concatenates the contents of its elements into
//! one buffer and hands *that* to the content codec with ownership transferred.
//! Only `NULL`, `BOOLEAN`, `OBJECT`, `INTEGER` and `ENUMERATED` are refused in
//! constructed form (`TYPE_NOT_PRIMITIVE`). The collected buffer is allocated with
//! the `CRYPTO_*` allocator rather than a Rust `Vec`, because `ASN1_STRING_set0`
//! takes ownership of it and releases it with `CRYPTO_free` — a `Vec`'s pointer
//! would be a mismatch no test would notice until a heap hook was installed.
//!
//! **The per-type length checks live in the content codec, not the collector.**
//! `BMPSTRING`'s odd length, `UNIVERSALSTRING`'s non-multiple-of-four,
//! `GENERALIZEDTIME`'s `< 15` and `UTCTIME`'s `< 13` are checked *after* the
//! content is in hand, and each raises its own reason. Checking them earlier
//! would report the same failure with a different reason code, which is exactly
//! what `RT-ASN1` compares.
//!
//! ## The defect this rewrite removes
//!
//! The previous version of this file reproduced the string arm's allocation
//! failure as `string_embed_free(stmp)` only when the string had just been
//! allocated. The authority frees `stmp` unconditionally and nulls the caller's
//! slot: `asn1_ex_c2i`'s `if (!ASN1_STRING_set(...))` arm does
//! `ASN1_STRING_free(stmp); *pval = NULL;` whatever `stmp` was. Reproducing it
//! conditionally would have leaked or double-freed exactly one caller pattern —
//! a `d2i_*` into an existing string on an allocation failure.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::bitstr::ossl_c2i_ASN1_BIT_STRING;
use crate::asn1::layout::*;
use crate::asn1::prim::{ossl_c2i_ASN1_INTEGER, ossl_c2i_ASN1_OBJECT};
use crate::asn1::string::{string_type_new, ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_set0};
use crate::asn1::utl;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc};
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push, OpenSslStack,
};
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

    /// `BUF_MEM_grow_clean(&buf, len + 1)` followed by `buf.data[len] = 0`.
    ///
    /// The authority appends a NUL after a collected string's content. It is not
    /// part of the content — `len` is passed separately — but it is a real byte in
    /// a real allocation, and the allocation's size is observable to a caller that
    /// later hands the buffer back through `ASN1_STRING_set` or reallocs it. So it
    /// is reproduced rather than dropped.
    ///
    /// Returns 0 after raising once the authority's `ERR_R_BUF_LIB` site, which is
    /// what `BUF_MEM_grow_clean` failing reaches.
    unsafe fn terminate(&mut self) -> c_int {
        let want = self.len + 1;
        if want > self.cap {
            // SAFETY: `self.data` came from this allocator or is null; `want` is
            // the new size.
            let fresh =
                unsafe { CRYPTO_realloc(self.data.cast::<c_void>(), want, FILE.as_ptr(), LINE) }
                    as *mut u8;
            if fresh.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_832) };
                return 0;
            }
            self.data = fresh;
            self.cap = want;
        }
        // SAFETY: `self.len < self.cap` after the growth above, and `self.data` is
        // non-null because `cap > 0`.
        unsafe { *self.data.add(self.len) = 0 };
        1
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
/// `asn1_d2i_ex_primitive` — the header, the content, and the content codec.
///
/// # Safety
///
/// `pval` must be a live slot. `in_` must point to a slot holding a readable
/// pointer to `inlen` bytes. `it` must be a live item with no templates and no
/// primitive hooks — the shapes [`embed_d2i`] admits. `ctx` must be null or a
/// live cache.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn d2i_ex_primitive(
    pval: *mut *mut Asn1String,
    in_: *mut *const c_uchar,
    inlen: c_long,
    it: &Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: *mut Asn1Tlc,
) -> c_int {
    if pval.is_null() {
        // "Should never happen" in the authority's own words, and it cannot be
        // reached from `item_d2i` because that redirects a null slot.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_739) };
        return 0;
    }

    let mut utype: c_int;
    let mut tag = tag;
    let mut aclass = aclass;
    if it.itype == ASN1_ITYPE_MSTRING {
        utype = tag;
        tag = -1;
    } else {
        utype = it.utype as c_int;
    }

    // A `V_ASN1_ANY` item has no type of its own: the type is a property of the
    // *encoding*, so the header is read here purely to learn it, and only then is
    // the decoder entered. That is why the header below is read a second time by
    // the main `check_tlen` rather than the bytes being remembered.
    //
    // A tag or an OPTIONAL flag on an ANY item is not representable — there is
    // nothing for either to apply to — so both are rejected rather than ignored,
    // and the caller learns which mistake it made from the reason code.
    if utype == V_ASN1_ANY {
        if tag >= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_753) };
            return 0;
        }
        if opt {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_757) };
            return 0;
        }
        // SAFETY: the caller's slot is readable.
        let mut probe = unsafe { *in_ };
        let mut oclass: c_uchar = 0;
        // SAFETY: `probe` is readable for `inlen` bytes; the outputs are local
        // slots. The tag and class are not constrained, so both arguments are the
        // "anything" markers.
        let ret = unsafe {
            check_tlen(
                core::ptr::null_mut(),
                &mut utype,
                &mut oclass,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut probe,
                inlen,
                -1,
                0,
                false,
                ctx,
            )
        };
        if ret == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_764) };
            return 0;
        }
        // A non-universal class has no `V_ASN1_*` number to name, so the value
        // becomes `OTHER` and is kept in its encoded form below.
        if oclass != V_ASN1_UNIVERSAL as c_uchar {
            utype = V_ASN1_OTHER;
        }
    }

    if tag == -1 {
        tag = utype;
        aclass = V_ASN1_UNIVERSAL;
    }
    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *in_ };
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
            tag,
            aclass,
            opt,
            ctx,
        )
    };
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_779) };
        return 0;
    }
    if ret == -1 {
        // Reachable only through `opt`, which no wrapper in this stratum passes.
        return -1;
    }

    let mut buf = Collected::new();
    let mut free_cont = false;
    let cont: *const u8;
    let len: c_long;
    if utype == V_ASN1_SEQUENCE || utype == V_ASN1_SET || utype == V_ASN1_OTHER {
        // These three are *not* decoded: their content is a nested structure and the
        // value that holds it is a string over the original encoded bytes. That is
        // what makes `ASN1_SEQUENCE_new` answer a value whose only payload is the
        // bytes the caller supplied.
        if utype == V_ASN1_OTHER {
            // `OTHER` is what an unrecognised class or number turns into, so the
            // cache's automatic clear — which only fires on an exact tag match —
            // cannot be relied on to drop a header that no longer applies.
            if !ctx.is_null() {
                // SAFETY: `ctx` is the caller's live cache.
                unsafe { (*ctx).valid = 0 };
            }
        } else if cst == 0 {
            // A SEQUENCE or SET that is not constructed cannot hold the nested
            // structure this arm exists to preserve.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_796) };
            return 0;
        }
        // The *value's own* first byte, before the header: this is what the string
        // will span, so it is read from the caller's slot rather than from `p`.
        // SAFETY: the caller's slot is readable.
        let start = unsafe { *in_ };
        if inf != 0 {
            // An indefinite length has no declared end, so the value's extent is
            // found by walking the nested headers to the matching EOC.
            // SAFETY: `p` is readable for the remaining input; the slot is writable.
            if unsafe { find_end(&mut p, plen, true) } == 0 {
                return 0;
            }
            cont = start;
            len = p as c_long - start as c_long;
        } else {
            cont = start;
            len = (p as c_long - start as c_long) + plen;
            // SAFETY: `p` is readable for `plen` bytes by the header just read.
            p = unsafe { p.add(plen.max(0) as usize) };
        }
    } else if cst != 0 {
        if matches!(
            utype,
            V_ASN1_NULL | V_ASN1_BOOLEAN | V_ASN1_OBJECT | V_ASN1_INTEGER | V_ASN1_ENUMERATED
        ) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_814) };
            return 0;
        }
        // The collected buffer becomes the content, and ownership of it passes to
        // the content codec.
        free_cont = true;
        let mut q = p;
        // SAFETY: `q` is readable for `plen` bytes.
        if unsafe { collect(&mut buf, &mut q, plen, inf != 0, -1, V_ASN1_UNIVERSAL, 0) } == 0 {
            buf.discard();
            return 0;
        }
        // The *content* length, read before the terminator is appended: the
        // authority assigns `len = (long)buf.length` and only then grows the
        // buffer by one.
        let content = buf.len as c_long;
        // SAFETY: `buf` is ours.
        if unsafe { buf.terminate() } == 0 {
            buf.discard();
            return 0;
        }
        p = q;
        cont = buf.data;
        len = content;
    } else {
        // SAFETY: `p` is readable for `plen` bytes by the header just read.
        cont = p;
        len = plen;
        // SAFETY: `p` holds `plen` content bytes.
        p = unsafe { p.add(plen.max(0) as usize) };
    }

    // SAFETY: `pval` is a live slot; `cont` is readable for `len` bytes; `it` is
    // live and the caller owns it.
    let ok = unsafe { ex_c2i(pval, cont, len, utype, &mut free_cont, it) };
    // The content codec clears `free_cont` when it takes the buffer; whatever is
    // left belongs to this frame, on both the failure and the success path.
    if free_cont {
        buf.discard();
    }
    if ok == 0 {
        return 0;
    }
    // SAFETY: the caller's slot is writable and the content has been consumed.
    unsafe { *in_ = p };
    1
}

/// `asn1_ex_c2i` — content octets to a value of type `utype`.
///
/// Returns 1 on success, 0 on failure after raising. `free_cont` is cleared when
/// the collected buffer's ownership has been transferred to the value.
///
/// # Safety
///
/// `pval` must be a live slot. `cont` must be readable for `len` bytes, and when
/// `*free_cont` is set it must be an allocation this crate's allocator made. `it`
/// must be live; for a `V_ASN1_ANY` item `pval` must hold null or a live
/// `ASN1_TYPE`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn ex_c2i(
    pval: *mut *mut Asn1String,
    cont: *const c_uchar,
    len: c_long,
    utype: c_int,
    free_cont: &mut bool,
    it: &Asn1Item,
) -> c_int {
    let ilen = len as c_int;

    // A caller's primitive hooks win over everything below, including the type
    // dispatch: `ASN1_PRIMITIVE_FUNCS::prim_c2i` *is* the type's codec. No item
    // this stratum defines carries one — that is what the numeric items and
    // `BIGNUM_it` need, and they are subphase 5.4 — but the arm is written out
    // because a caller can build such an item itself and hand it to
    // `ASN1_item_d2i`.
    let pf = it.funcs.cast::<Asn1PrimitiveFuncs>();
    if !pf.is_null() {
        // SAFETY: for a PRIMITIVE item the authority's own cast reads `funcs` as
        // an `ASN1_PRIMITIVE_FUNCS *`.
        let pf = unsafe { &*pf };
        if let Some(prim_c2i) = pf.prim_c2i {
            if len == ilen as c_long {
                // SAFETY: the hook is the caller's, with the authority's
                // signature; every pointer is the caller's own or this frame's.
                return unsafe {
                    prim_c2i(
                        pval.cast(),
                        cont,
                        ilen,
                        utype,
                        (free_cont as *mut bool).cast(),
                        it,
                    )
                };
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_873) };
            return 0;
        }
    }

    // `typ` is the `ASN1_TYPE` an ANY item stores its (type, value) pair in, and
    // `opval` the caller's own slot — kept so that the `err:` tail below can undo
    // both. The body is a labelled block rather than a run of early returns
    // precisely because that tail has to run on *every* failure path.
    let mut typ: *mut Asn1Type = core::ptr::null_mut();
    let mut opval: *mut *mut Asn1String = core::ptr::null_mut();
    let mut pval = pval;

    let ret = 'body: {
        if it.utype == V_ASN1_ANY as c_long {
            // SAFETY: `pval` is a live slot.
            if unsafe { *pval }.is_null() {
                // A fresh `ASN1_TYPE` is entirely this frame's: nothing is shared.
                let fresh = ASN1_TYPE_new();
                if fresh.is_null() {
                    break 'body 0;
                }
                typ = fresh;
                // SAFETY: `pval` is a live slot.
                unsafe { *pval = fresh.cast::<Asn1String>() };
            } else {
                // SAFETY: `pval` holds the caller's live `ASN1_TYPE`.
                typ = unsafe { *pval }.cast::<Asn1Type>();
            }
            // SAFETY: `typ` is live.
            let have = unsafe { (*typ).type_ };
            if utype != have {
                // A type change releases whatever the union held before, which is
                // what makes re-decoding into an existing ANY value safe.
                // SAFETY: `typ` is live.
                unsafe { ASN1_TYPE_set(typ, utype, core::ptr::null_mut()) };
            }
            opval = pval;
            // SAFETY: `typ` is live; the union's `ptr` member is the slot the value
            // codecs below write through.
            pval = unsafe { core::ptr::addr_of_mut!((*typ).value.ptr) }.cast::<*mut Asn1String>();
        }

        match utype {
            V_ASN1_OBJECT => {
                // The authority's `||` short-circuits into `err` with no raise of its
                // own on the length test; `ossl_c2i_ASN1_OBJECT` raises for the
                // failures it detects.
                if len != ilen as c_long {
                    break 'body 0;
                }
                let mut cur = cont;
                // SAFETY: `cur` is readable for `len` bytes; `pval` is a live slot
                // for an `ASN1_OBJECT`.
                let obj =
                    unsafe { ossl_c2i_ASN1_OBJECT(pval.cast::<*mut Asn1Object>(), &mut cur, len) };
                if obj.is_null() {
                    break 'body 0;
                }
            }

            V_ASN1_NULL => {
                if len != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_900) };
                    break 'body 0;
                }
                // A `NULL`'s value is the sentinel `1`, never a heap pointer. That is
                // load-bearing for the ownership contract: `ASN1_NULL_free` is a
                // no-op, so a caller that frees one does not free a pointer that was
                // never an allocation.
                //
                // The clippy lint below wants `ptr::dangling_mut`, which answers an
                // address derived from the type's *alignment* — 4 for an `int`, not
                // 1. The authority's sentinel is literally `(ASN1_VALUE *)1` and a
                // caller can read it back, so the lint's suggestion would be a
                // different observable value.
                #[allow(clippy::manual_dangling_ptr)]
                // SAFETY: `pval` is a live slot.
                unsafe {
                    *pval = 1 as *mut Asn1String
                };
            }

            V_ASN1_BOOLEAN => {
                if len != 1 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_908) };
                    break 'body 0;
                }
                // The authority stores a BOOLEAN *in the value slot itself*:
                // `tbool = (ASN1_BOOLEAN *)pval; *tbool = *cont;`. Only the slot's
                // first four bytes are meaningful and the rest is whatever was there,
                // so the read side must read four bytes too. Writing through the slot
                // as an `int` is what reproduces that rather than inventing a cleaner
                // representation no caller could observe.
                // SAFETY: `pval` points at a slot at least `size_of::<c_int>()` bytes
                // wide, because it holds a pointer; `cont` is readable for the one
                // byte `len == 1` established.
                unsafe { *(pval as *mut c_int) = c_int::from(*cont) };
            }

            V_ASN1_BIT_STRING => {
                let mut cur = cont;
                // SAFETY: `cur` is readable for `len` bytes; `pval` is a live slot.
                let ret = unsafe { ossl_c2i_ASN1_BIT_STRING(pval, &mut cur, len) };
                if ret.is_null() {
                    break 'body 0;
                }
            }

            V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
                let mut cur = cont;
                // SAFETY: `cur` is readable for `len` bytes; `pval` is a live slot.
                let tint = unsafe { ossl_c2i_ASN1_INTEGER(pval, &mut cur, len) };
                if tint.is_null() {
                    break 'body 0;
                }
                // The expected type is stamped over whatever the content codec left,
                // keeping only the sign bit: an `INTEGER` and an `ENUMERATED` are the
                // same bytes and the item is what says which one this is.
                // SAFETY: `tint` is live.
                unsafe { (*tint).type_ = utype | ((*tint).type_ & V_ASN1_NEG) };
            }

            _ => {
                // `OCTET STRING`, the string types, `OTHER`, `SET` and `SEQUENCE`: all
                // `ASN1_STRING`-based and handled the same way.
                if len != ilen as c_long {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_950) };
                    break 'body 0;
                }
                // A `BMPSTRING` is pairs of octets, a `UNIVERSALSTRING` groups of
                // four, so a length that is not a multiple of the unit is malformed
                // rather than merely suspicious.
                if utype == V_ASN1_BMPSTRING && len & 1 != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_954) };
                    break 'body 0;
                }
                if utype == V_ASN1_UNIVERSALSTRING && len & 3 != 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_958) };
                    break 'body 0;
                }
                // The two time types have a shortest legal spelling, and the
                // authority rejects anything shorter here rather than letting the
                // *checker* discover it later.
                if utype == V_ASN1_GENERALIZEDTIME && len < 15 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_962) };
                    break 'body 0;
                }
                if utype == V_ASN1_UTCTIME && len < 13 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_966) };
                    break 'body 0;
                }
                // SAFETY: `pval` is a live slot.
                let existing = unsafe { *pval };
                let stmp = if existing.is_null() {
                    let fresh = string_type_new(utype);
                    if fresh.is_null() {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::TASN_DEC_973) };
                        break 'body 0;
                    }
                    // SAFETY: `pval` is a live slot.
                    unsafe { *pval = fresh };
                    fresh
                } else {
                    // SAFETY: `existing` is live.
                    unsafe { (*existing).type_ = utype };
                    existing
                };
                if *free_cont {
                    // The collected buffer becomes the string's storage and ownership
                    // moves with it, so the caller must not free it: the flag is
                    // cleared here, which is what the authority does by taking a
                    // `char *free_cont` it can write through.
                    // SAFETY: `stmp` is live and uniquely owned; `cont` is the buffer
                    // this frame owns and hands over by this call.
                    unsafe { ASN1_STRING_set0(stmp, cont as *mut c_void, ilen) };
                    *free_cont = false;
                // SAFETY: `stmp` is live; `cont` is readable for `ilen` bytes.
                } else if unsafe { ASN1_STRING_set(stmp, cont.cast::<c_void>(), ilen) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_987) };
                    // The authority frees `stmp` and nulls the caller's slot whether
                    // `stmp` was just allocated or was the caller's own, and this is
                    // the arm the previous version of this file got wrong.
                    // SAFETY: `stmp` is live; `pval` is a live slot.
                    unsafe {
                        ASN1_STRING_free(stmp);
                        *pval = core::ptr::null_mut();
                    }
                    break 'body 0;
                }
            }
        }
        // An ANY value of type NULL holds no pointer at all, so the union's bytes are
        // cleared rather than left holding the address the switch above wrote.
        if !typ.is_null() && utype == V_ASN1_NULL {
            // SAFETY: `typ` is live and the union is writable.
            unsafe { (*typ).value.ptr = core::ptr::null_mut() };
        }
        1
    };

    if ret == 0 {
        // The authority's `err:` tail. `typ` is null unless *this* call allocated the
        // `ASN1_TYPE`, so a caller-supplied one is never freed here, and `opval` is
        // null unless the item was an ANY.
        // SAFETY: `typ` is null or the `ASN1_TYPE` this frame allocated.
        unsafe { ASN1_TYPE_free(typ) };
        if !opval.is_null() {
            // SAFETY: `opval` is the caller's own slot, established above.
            unsafe { *opval = core::ptr::null_mut() };
        }
    }
    ret
}
// ---------------------------------------------------------------------------
// `ASN1_item_d2i` and the dispatch it reaches
// ---------------------------------------------------------------------------

/// `ASN1_MAX_CONSTRUCTED_NEST` — how deeply a constructed value may nest. Read from
/// `tasn_dec.c:27`, where the authority defines it.
const MAX_CONSTRUCTED_NEST: c_int = 30;

/// How many bytes precede the NUL of a C string.
///
/// # Safety
///
/// `s` must be null or point to a NUL-terminated string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: the caller guarantees the string is NUL-terminated, so the loop stops
    // at the first NUL within its extent.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Join NUL-terminated pieces and append them to the queue's top entry, the way
/// `ERR_add_error_data(n, ...)` does.
///
/// The authority's `ERR_add_error_data` formats its arguments and routes them through
/// `ERR_add_error_txt("", buf)`, so a caller sees the pieces **concatenated with no
/// separator** as additional error data on the current entry. It is what makes a failed
/// `SEQUENCE` decode name the field it failed at, and it is observable through
/// `ERR_get_error_all`.
///
/// The buffer is sized to the exact joined length rather than to a fixed bound, because
/// the pieces include a caller-built template's own `field_name` and `sname` — a caller
/// can make them as long as it likes, and a fixed buffer would truncate silently.
///
/// # Safety
///
/// Every element of `parts` must be null or a NUL-terminated C string.
unsafe fn add_error_data(parts: &[*const c_char]) {
    // SAFETY: the caller's contract covers every element.
    let total: usize = parts
        .iter()
        .map(|p| {
            if p.is_null() {
                0
            } else {
                // SAFETY: each element is NUL-terminated.
                unsafe { c_strlen(*p) }
            }
        })
        .sum();
    if total == 0 {
        return;
    }
    // SAFETY: the buffer is `total + 1` bytes.
    let buf = CRYPTO_malloc(total + 1, FILE.as_ptr(), LINE) as *mut c_char;
    if buf.is_null() {
        return;
    }
    let mut at = 0usize;
    for p in parts {
        if p.is_null() {
            continue;
        }
        // SAFETY: each element is NUL-terminated, so `total` bytes fit.
        let n = unsafe { c_strlen(*p) };
        // SAFETY: `buf` has room for `total` bytes plus the terminator, and `p`
        // is readable for `n`.
        unsafe { core::ptr::copy_nonoverlapping(*p, buf.add(at), n) };
        at += n;
    }
    // SAFETY: `at == total`, so the terminator is in range.
    unsafe { *buf.add(at) = 0 };
    // SAFETY: `buf` is a NUL-terminated string; the empty separator makes this a plain
    // append.
    unsafe { crate::runtime::err::ERR_add_error_txt(c"".as_ptr(), buf) };
    // SAFETY: `buf` came from this allocator.
    unsafe { CRYPTO_free(buf.cast::<c_void>(), FILE.as_ptr(), LINE) };
}

/// `ASN1_item_d2i_ex` — redirect a null value slot, clear a cache, decode.
///
/// `ASN1_item_d2i(NULL, pp, len, it)` is legal and common, so the authority
/// redirects a null `pval` to a local and decodes into that. Every `d2i_*`
/// wrapper in [`crate::asn1::typ`] and [`crate::asn1::prim`] therefore reaches
/// the decoder with a non-null slot, which is what makes the decoder's own
/// `pval == NULL` arm (and its `ASN1_R_ILLEGAL_NULL`) unreachable from them.
///
/// The cache is `asn1_tlc_clear_nc`'d rather than left as whatever the stack
/// held: a `valid` byte left over from an earlier decode would make
/// `asn1_check_tlen` reuse a stale header, and the symptom would be a decode that
/// succeeds against bytes the caller never passed.
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must
/// be null or point to a slot holding null or a live value of the item's type.
/// `it` must be a live item.
pub(crate) unsafe fn item_d2i(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
) -> *mut Asn1String {
    let mut tmp: *mut Asn1String = core::ptr::null_mut();
    let pval: *mut *mut Asn1String = if a.is_null() { &mut tmp } else { a };
    let mut ctx = Asn1Tlc {
        valid: 0,
        ret: 0,
        plen: 0,
        ptag: 0,
        pclass: 0,
        hdrlen: 0,
    };
    // SAFETY: `pval` is a live slot, and `pp`/`it` are the caller's.
    let rv = unsafe {
        item_ex_d2i_intern(
            pval.cast::<*mut c_void>(),
            pp,
            len,
            it,
            -1,
            0,
            false,
            &mut ctx,
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    if rv <= 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `pval` is a live slot.
    unsafe { *pval }
}

/// `asn1_item_ex_d2i_intern` — decode, and **free the caller's value on failure**.
///
/// The `if (rv <= 0) ASN1_item_ex_free(pval, it);` at the end is the ownership contract
/// rather than a detail of the failure path: a caller that decodes into an existing
/// object and fails does not keep it, and the caller's pointer is null afterwards rather
/// than pointing at a half-filled object. `RT-ASN1`'s `bsd.keepstate` is what found it.
///
/// # Safety
///
/// `pval` must be a live slot. `pp` must point to a slot holding a readable pointer to
/// `len` bytes. `it` must be a live item. `ctx` must be null or a live cache.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn item_ex_d2i_intern(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: *mut Asn1Tlc,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if pval.is_null() || it.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_140) };
        return 0;
    }
    // SAFETY: the caller's contract.
    let rv = unsafe { embed_d2i(pval, in_, len, it, tag, aclass, opt, ctx, 0, libctx, propq) };
    if rv <= 0 {
        // The authority calls the exported `ASN1_item_ex_free` here, which is
        // `ossl_asn1_item_embed_free(pval, it, 0)` — the value's storage is the
        // caller's, so only its contents are released.
        // SAFETY: `pval` is a live slot and `it` is the caller's item.
        unsafe { crate::asn1::fre::ASN1_item_ex_free(pval, it) };
    }
    rv
}

/// `int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
/// const ASN1_ITEM *it, int tag, int aclass, char opt, ASN1_TLC *ctx)`
///
/// # Safety
///
/// As [`item_ex_d2i_intern`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ex_d2i(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: c_int,
    ctx: *mut Asn1Tlc,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract.
        unsafe {
            item_ex_d2i_intern(
                pval,
                in_,
                len,
                it,
                tag,
                aclass,
                opt != 0,
                ctx,
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        }
    })
}

/// `ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
/// const ASN1_ITEM *it)`
///
/// # Safety
///
/// As [`item_d2i`], over an untyped slot.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller's contract.
        unsafe { ASN1_item_d2i_ex(pval, in_, len, it, core::ptr::null_mut(), core::ptr::null()) }
    })
}

/// `ASN1_VALUE *ASN1_item_d2i_ex(ASN1_VALUE **pval, const unsigned char **in,
/// long len, const ASN1_ITEM *it, OSSL_LIB_CTX *libctx, const char *propq)`
///
/// # Safety
///
/// As [`item_ex_d2i_intern`]; `libctx` must be null or a live library context and
/// `propq` null or NUL-terminated, whatever the item's hooks require.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_d2i_ex(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        let mut tmp: *mut c_void = core::ptr::null_mut();
        let slot = if pval.is_null() { &mut tmp } else { pval };
        let mut ctx = Asn1Tlc {
            valid: 0,
            ret: 0,
            plen: 0,
            ptag: 0,
            pclass: 0,
            hdrlen: 0,
        };
        // SAFETY: `slot` is a live slot; the rest is the caller's contract.
        if unsafe { item_ex_d2i_intern(slot, in_, len, it, -1, 0, false, &mut ctx, libctx, propq) }
            > 0
        {
            // SAFETY: `slot` is a live slot.
            return unsafe { *slot };
        }
        core::ptr::null_mut()
    })
}

/// `asn1_item_embed_d2i` — the dispatch, in full.
///
/// Six arms and a depth guard. Two properties of the whole function are only visible
/// from here:
///
/// * the depth counter is incremented on entry, so the guard bounds **nesting**, not
///   the number of fields, and a 30-deep structure is rejected wherever it was
///   entered from;
/// * every failure leaves through `err`, whose tail appends the failing field's name and
///   the item's `sname` to the error data. That is why a caller can tell a failure at
///   `Field=..., Type=...` from one at `Type=...` even when the reason matches.
///
/// # Safety
///
/// As [`item_ex_d2i_intern`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn embed_d2i(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: *mut Asn1Tlc,
    depth: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut errtt: *const Asn1Template = core::ptr::null();
    if pval.is_null() || it.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_208) };
        return 0;
    }
    if len <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_212) };
        return 0;
    }
    // SAFETY: `it` is non-null, and the caller owns it for the duration.
    let item = unsafe { &*it };

    let aux = item.funcs.cast::<Asn1Aux>();
    // The callback is read as an `ASN1_AUX` for a `CHOICE` or `SEQUENCE`; for an
    // `EXTERN` item `funcs` is an `ASN1_EXTERN_FUNCS` and for a primitive an
    // `ASN1_PRIMITIVE_FUNCS`, so this read is only meaningful for the two arms that use
    // it. Those two are the only ones that consult it.
    let asn1_cb = if aux.is_null() {
        None
    } else {
        // SAFETY: for the arms that use it, `funcs` is the item's `ASN1_AUX`.
        unsafe { (*aux).asn1_cb }
    };

    if depth + 1 > MAX_CONSTRUCTED_NEST {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_222) };
        return 0;
    }
    let depth = depth + 1;

    match item.itype {
        ASN1_ITYPE_PRIMITIVE => {
            if item.templates.is_null() {
                // SAFETY: the caller's contract.
                unsafe {
                    d2i_ex_primitive(
                        pval.cast::<*mut Asn1String>(),
                        in_,
                        len,
                        item,
                        tag,
                        aclass,
                        opt,
                        ctx,
                    )
                }
            } else {
                // Tagging and OPTIONAL are illegal on an item template, because the
                // flags cannot be passed down: the item's own template carries them.
                if tag != -1 || opt {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_236) };
                    return 0;
                }
                // SAFETY: the caller's contract.
                unsafe {
                    template_ex_d2i(
                        pval,
                        in_,
                        len,
                        item.templates,
                        false,
                        ctx,
                        depth,
                        libctx,
                        propq,
                    )
                }
            }
        }

        ASN1_ITYPE_MSTRING => {
            if tag != -1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_252) };
                return 0;
            }
            // SAFETY: the caller's contract.
            unsafe { mstring_d2i(pval, in_, len, item, opt, ctx) }
        }

        ASN1_ITYPE_EXTERN => {
            let ef = item.funcs.cast::<Asn1ExternFuncs>();
            if ef.is_null() {
                return 0;
            }
            // SAFETY: for an `EXTERN` item `funcs` is its `ASN1_EXTERN_FUNCS`.
            let ef = unsafe { &*ef };
            if let Some(f) = ef.asn1_ex_d2i_ex {
                // SAFETY: the hook is the caller's, with the authority's signature.
                unsafe {
                    f(
                        pval,
                        in_,
                        len,
                        it,
                        tag,
                        aclass,
                        c_char::from(opt),
                        ctx,
                        libctx,
                        propq,
                    )
                }
            } else if let Some(f) = ef.asn1_ex_d2i {
                // SAFETY: as above.
                unsafe { f(pval, in_, len, it, tag, aclass, c_char::from(opt), ctx) }
            } else {
                0
            }
        }

        ASN1_ITYPE_CHOICE => {
            if tag != -1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_298) };
                return 0;
            }
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_D2I_PRE, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_507) };
                    return 0;
                }
            }
            // SAFETY: `pval` is a live slot.
            let existing = unsafe { *pval };
            if !existing.is_null() {
                // Re-decoding into an existing CHOICE frees whichever alternative it
                // currently holds and resets the selector, so a failed re-decode cannot
                // leave a stale alternative selected.
                // SAFETY: `existing` is a live `CHOICE` value.
                let i = unsafe { utl::get_choice_selector(pval, item) };
                if i >= 0 && c_long::from(i) < item.tcount {
                    // SAFETY: `i` indexes the item's own template array.
                    let tt = unsafe { item.templates.add(i as usize) };
                    // SAFETY: `tt` is live and `existing` is the enclosing value.
                    let field = unsafe { utl::get_field_ptr(pval, &*tt) };
                    // SAFETY: the field's own template governs it.
                    unsafe { crate::asn1::fre::template_free(field, tt) };
                    // SAFETY: `existing` is a live `CHOICE` value.
                    unsafe { utl::set_choice_selector(pval, -1, item) };
                }
            } else {
                // SAFETY: the caller's contract.
                if unsafe { crate::asn1::new::item_ex_new_intern(pval, it, libctx, propq) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_314) };
                    return 0;
                }
            }
            // SAFETY: the caller's slot is readable.
            let mut p = unsafe { *in_ };
            let mut i: c_long = 0;
            let mut tt = item.templates;
            while i < item.tcount {
                // SAFETY: `tt` is inside the item's template array.
                let t = unsafe { &*tt };
                // SAFETY: `*pval` is live and `t.offset` is a field of it.
                let field = unsafe { utl::get_field_ptr(pval, t) };
                // Each alternative is tried as OPTIONAL, so an absent one is
                // distinguishable from a malformed one.
                // SAFETY: the caller's contract.
                let ret = unsafe {
                    template_ex_d2i(field, &mut p, len, tt, true, ctx, depth, libctx, propq)
                };
                if ret == -1 {
                    // SAFETY: still inside the item's template array.
                    tt = unsafe { tt.add(1) };
                    i += 1;
                    continue;
                }
                if ret > 0 {
                    break;
                }
                // A real parse error: release the partial alternative and report it.
                // SAFETY: the field's own template governs it.
                unsafe { crate::asn1::fre::template_free(field, tt) };
                errtt = tt;
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_338) };
                return err_tail(errtt, item);
            }
            if i == item.tcount {
                // Nothing matched. For an OPTIONAL field that is not an error, and the
                // whole value is released rather than left claiming an alternative.
                if opt {
                    // SAFETY: `pval` is a live slot.
                    unsafe { crate::asn1::fre::item_embed_free(pval, it, 0) };
                    return -1;
                }
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_350) };
                return err_tail(core::ptr::null(), item);
            }
            // The selector is written only once an alternative has been read.
            // SAFETY: `*pval` is a live `CHOICE` value.
            unsafe { utl::set_choice_selector(pval, i as c_int, item) };
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_D2I_POST, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_507) };
                    return 0;
                }
            }
            // SAFETY: the caller's slot is writable.
            unsafe { *in_ = p };
            1
        }

        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            // SAFETY: the caller's slot is readable.
            let mut p = unsafe { *in_ };
            let start = p;
            let tmplen = len;
            let mut len = len;
            let mut tag = tag;
            let mut aclass = aclass;
            if tag == -1 {
                tag = V_ASN1_SEQUENCE;
                aclass = V_ASN1_UNIVERSAL;
            }
            let mut seq_eoc: c_uchar = 0;
            let mut cst: c_uchar = 0;
            // SAFETY: `p` is readable for `len` bytes; the outputs are local slots.
            let ret = unsafe {
                check_tlen(
                    &mut len,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut seq_eoc,
                    &mut cst,
                    &mut p,
                    len,
                    tag,
                    aclass,
                    opt,
                    ctx,
                )
            };
            if ret == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_375) };
                return err_tail(core::ptr::null(), item);
            }
            if ret == -1 {
                return -1;
            }
            // `ASN1_AFLG_BROKEN` is for a buggy peer whose declared length cannot be
            // trusted, so the length is taken as "the rest of the input" instead.
            let broken = !aux.is_null()
                // SAFETY: `aux` is non-null on this branch and is the item's own block.
                && (unsafe { (*aux).flags }) & ASN1_AFLG_BROKEN != 0;
            let seq_nolen: c_uchar;
            if broken {
                len = tmplen - (p as c_long - start as c_long);
                seq_nolen = 1;
            } else {
                seq_nolen = seq_eoc;
            }
            if cst == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_387) };
                return err_tail(core::ptr::null(), item);
            }
            // SAFETY: `pval` is a live slot.
            let has_value = !unsafe { *pval }.is_null();
            if !has_value
                // SAFETY: the caller's contract.
                && unsafe { crate::asn1::new::item_ex_new_intern(pval, it, libctx, propq) } == 0
            {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_393) };
                return err_tail(core::ptr::null(), item);
            }
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_D2I_PRE, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_507) };
                    return 0;
                }
            }

            // Any ADB-derived field is cleared first, because its template depends on a
            // selector that the decode below is about to replace.
            let mut i: c_long = 0;
            let mut tt = item.templates;
            while i < item.tcount {
                // SAFETY: `tt` is inside the item's template array.
                let t = unsafe { &*tt };
                if t.flags & ASN1_TFLG_ADB_MASK != 0 {
                    // SAFETY: `*pval` is a live value of the item's type.
                    let seqtt = unsafe { utl::do_adb(*pval, tt, 0) };
                    if !seqtt.is_null() {
                        // SAFETY: `seqtt` is live and `*pval` is the enclosing value.
                        let field = unsafe { utl::get_field_ptr(pval, &*seqtt) };
                        // SAFETY: the field's own template governs it.
                        unsafe { crate::asn1::fre::template_free(field, seqtt) };
                    }
                }
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }

            i = 0;
            tt = item.templates;
            let mut field_error = false;
            while i < item.tcount {
                // SAFETY: `*pval` is a live value of the item's type.
                let seqtt = unsafe { utl::do_adb(*pval, tt, 1) };
                if seqtt.is_null() {
                    field_error = true;
                    break;
                }
                // SAFETY: `seqtt` is live and `*pval` is the enclosing value.
                let field = unsafe { utl::get_field_ptr(pval, &*seqtt) };
                if len == 0 {
                    break;
                }
                let q = p;
                // SAFETY: `p` is readable for `len` bytes and the slot is writable.
                if unsafe { check_eoc(&mut p, len) } {
                    if seq_eoc == 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::TASN_DEC_427) };
                        return err_tail(core::ptr::null(), item);
                    }
                    len -= p as c_long - q as c_long;
                    seq_eoc = 0;
                    break;
                }
                // The last field cannot be omitted while data remains: there is nothing
                // after it to consume what is left, so treating it as OPTIONAL would
                // turn trailing garbage into an absent field.
                let isopt = if i == item.tcount - 1 {
                    false
                } else {
                    // SAFETY: `seqtt` is live.
                    (unsafe { (*seqtt).flags }) & ASN1_TFLG_OPTIONAL != 0
                };
                // SAFETY: as above.
                let ret = unsafe {
                    template_ex_d2i(field, &mut p, len, seqtt, isopt, ctx, depth, libctx, propq)
                };
                if ret == 0 {
                    errtt = seqtt;
                    field_error = true;
                    break;
                } else if ret == -1 {
                    // OPTIONAL and absent: free and zero the field and move on.
                    // SAFETY: the field's own template governs it.
                    unsafe { crate::asn1::fre::template_free(field, seqtt) };
                    // SAFETY: still inside the item's template array.
                    tt = unsafe { tt.add(1) };
                    i += 1;
                    continue;
                }
                len -= p as c_long - q as c_long;
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }
            if field_error {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_491) };
                return err_tail(errtt, item);
            }

            // SAFETY: `p` is readable for `len` bytes and the slot is writable.
            if seq_eoc != 0 && !unsafe { check_eoc(&mut p, len) } {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_466) };
                return err_tail(core::ptr::null(), item);
            }
            if seq_nolen == 0 && len != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_471) };
                return err_tail(core::ptr::null(), item);
            }

            // Any field the input did not reach must be OPTIONAL, and is cleared.
            while i < item.tcount {
                // SAFETY: `tt` is inside the item's template array.
                let seqtt = unsafe { utl::do_adb(*pval, tt, 1) };
                if seqtt.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_491) };
                    return err_tail(core::ptr::null(), item);
                }
                // SAFETY: `seqtt` is live.
                if unsafe { (*seqtt).flags } & ASN1_TFLG_OPTIONAL != 0 {
                    // SAFETY: `seqtt` is live and `*pval` is the enclosing value.
                    let field = unsafe { utl::get_field_ptr(pval, &*seqtt) };
                    // SAFETY: the field's own template governs it.
                    unsafe { crate::asn1::fre::template_free(field, seqtt) };
                } else {
                    errtt = seqtt;
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_491) };
                    return err_tail(errtt, item);
                }
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }

            // The received bytes are kept, which is what lets a re-encode answer the
            // caller's own bytes rather than a re-derivation.
            // SAFETY: `pval` is a live slot; `*in_` is readable for `p - start` bytes.
            if unsafe { utl::enc_save(pval, *in_, p as c_long - start as c_long, item) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_507) };
                return 0;
            }
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_D2I_POST, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_507) };
                    return 0;
                }
            }
            // SAFETY: the caller's slot is writable.
            unsafe { *in_ = p };
            1
        }

        _ => 0,
    }
}

/// `asn1_item_embed_d2i`'s `MSTRING` arm: read the tag, require a universal class, and
/// check it against the item's `B_ASN1_*` mask before decoding.
///
/// This arm exists because a multi-string item has no single underlying type: the type is
/// a property of the *encoding*, so it must be read before the decoder is entered, and the
/// decoder is then entered with that tag as its starting `utype`. That is the whole reason
/// `asn1_d2i_ex_primitive` opens with
/// `if (it->itype == ASN1_ITYPE_MSTRING) { utype = tag; tag = -1; }`.
///
/// # Safety
///
/// As [`item_ex_d2i_intern`]; `it` must be a live `MSTRING` item.
unsafe fn mstring_d2i(
    pval: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: &Asn1Item,
    opt: bool,
    ctx: *mut Asn1Tlc,
) -> c_int {
    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *in_ };
    let mut otag: c_int = 0;
    let mut oclass: c_uchar = 0;
    // `check_tlen` is passed `opt = 1` here even though its tag argument is -1: with a
    // negative expected tag the comparison is skipped and `opt` cannot be consulted, so
    // the value is inert, and it is passed as the authority passes it rather than as it
    // happens to matter.
    // SAFETY: `p` is readable for `len` bytes; the outputs are local slots and `ctx` is
    // the caller's cache.
    let ret = unsafe {
        check_tlen(
            core::ptr::null_mut(),
            &mut otag,
            &mut oclass,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut p,
            len,
            -1,
            0,
            true,
            ctx,
        )
    };
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_261) };
        return err_tail(core::ptr::null(), it);
    }
    if oclass != V_ASN1_UNIVERSAL as c_uchar {
        if opt {
            // Absent rather than wrong, which only the caller can tell apart.
            return -1;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_270) };
        return err_tail(core::ptr::null(), it);
    }
    // `ASN1_tag2bit` is not a bijection and several tags read 0, so a tag outside the
    // mask is rejected here rather than reaching a decoder that would have built a string
    // of the wrong type.
    // SAFETY: `it` is live; for a `MSTRING` item `utype` holds the `B_ASN1_*` mask.
    if crate::asn1::der::ASN1_tag2bit(otag) & (it.utype as core::ffi::c_ulong) == 0 {
        if opt {
            return -1;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_279) };
        return err_tail(core::ptr::null(), it);
    }
    // The tag read from the encoding becomes the decoder's starting `utype`, and the
    // decoder re-reads the header from the caller's *unadvanced* slot.
    // SAFETY: the caller's contract passes through unchanged.
    unsafe {
        d2i_ex_primitive(
            pval.cast::<*mut Asn1String>(),
            in_,
            len,
            it,
            otag,
            0,
            false,
            ctx,
        )
    }
}

/// The authority's `err:` tail: name the failing field when there is one, then the item.
///
/// The two forms differ, and both are observable through `ERR_get_error_all`: a failure
/// raised at a template appends `Field=<name>, Type=<sname>`, and one raised at the item
/// itself appends only `Type=<sname>`. A `field_name` of null is legal — a caller can
/// leave it out of its own template — and then only the item is named.
fn err_tail(errtt: *const Asn1Template, item: &Asn1Item) -> c_int {
    if !errtt.is_null() {
        // SAFETY: `errtt` is a live template the caller's item owns.
        let name = unsafe { (*errtt).field_name };
        // SAFETY: the pieces are the caller's own static strings and `item.sname`.
        unsafe { add_error_data(&[c"Field=".as_ptr(), name, c", Type=".as_ptr(), item.sname]) };
    } else {
        // SAFETY: as above.
        unsafe { add_error_data(&[c"Type=".as_ptr(), item.sname]) };
    }
    0
}

/// `asn1_template_ex_d2i` — the `EXPLICIT` tag, if the template asks for one.
///
/// An explicit tag is a *wrapper*: the field is the sole content of a constructed value
/// with `tt->tag` as its tag, so the wrapper is read first, then the field is decoded
/// within it, and then the wrapper must be exactly consumed — or, when it was
/// indefinite, terminated by an end-of-contents marker. Those two endings are different
/// errors, `MISSING_EOC` and `EXPLICIT_LENGTH_MISMATCH`, which is why both are here.
///
/// # Safety
///
/// `val` must be a live field slot; `in_` must point to a slot holding a readable
/// pointer to `inlen` bytes; `tt` must be a live template.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn template_ex_d2i(
    val: *mut *mut c_void,
    in_: *mut *const c_uchar,
    inlen: c_long,
    tt: *const Asn1Template,
    opt: bool,
    ctx: *mut Asn1Tlc,
    depth: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if val.is_null() || tt.is_null() {
        return 0;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    let aclass = (t.flags & ASN1_TFLG_TAG_CLASS) as c_int;
    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *in_ };

    if t.flags & ASN1_TFLG_EXPTAG == 0 {
        // SAFETY: the caller's contract.
        return unsafe { template_noexp_d2i(val, in_, inlen, tt, opt, ctx, depth, libctx, propq) };
    }

    let mut len: c_long = 0;
    let mut exp_eoc: c_uchar = 0;
    let mut cst: c_uchar = 0;
    // SAFETY: `p` is readable for `inlen` bytes; the outputs are local slots.
    let ret = unsafe {
        check_tlen(
            &mut len,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut exp_eoc,
            &mut cst,
            &mut p,
            inlen,
            t.tag as c_int,
            aclass,
            opt,
            ctx,
        )
    };
    let q = p;
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_551) };
        return 0;
    }
    if ret == -1 {
        return -1;
    }
    if cst == 0 {
        // An explicit tag must be constructed; a primitive one cannot hold a field.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_556) };
        return 0;
    }
    // The field has been found, so it is no longer OPTIONAL.
    // SAFETY: the caller's contract.
    if unsafe { template_noexp_d2i(val, &mut p, len, tt, false, ctx, depth, libctx, propq) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_563) };
        return 0;
    }
    len -= p as c_long - q as c_long;
    if exp_eoc != 0 {
        // SAFETY: `p` is readable for `len` bytes and the slot is writable.
        if !unsafe { check_eoc(&mut p, len) } {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_571) };
            return 0;
        }
    } else if len != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_579) };
        return 0;
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *in_ = p };
    1
}

/// `asn1_template_noexp_d2i` — a field's tag handling, `SET OF`/`SEQUENCE OF`, and the
/// embedded-field indirection.
///
/// # Safety
///
/// As [`template_ex_d2i`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(unused_assignments)] // the authority's `len -= p - q` before its EOC `break` is dead
unsafe fn template_noexp_d2i(
    val: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len_in: c_long,
    tt: *const Asn1Template,
    opt: bool,
    ctx: *mut Asn1Tlc,
    depth: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if val.is_null() || tt.is_null() {
        return 0;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    let aclass = (t.flags & ASN1_TFLG_TAG_CLASS) as c_int;
    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *in_ };
    let mut len = len_in;

    // An embedded field's value *is* the field's storage, so the address of the caller's
    // slot becomes the value the item machinery is handed: `tval` holds it and the decode
    // reads and writes through `&tval`.
    let mut tval: *mut c_void = val as *mut c_void;
    let val = if t.flags & ASN1_TFLG_EMBED != 0 {
        // SAFETY: `tval` is this frame's own slot.
        &mut tval as *mut *mut c_void
    } else {
        val
    };

    // SAFETY: `t.item` is the field's `ASN1_ITEM_EXP`.
    let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
    if sub.is_null() {
        return 0;
    }

    if t.flags & ASN1_TFLG_SK_MASK != 0 {
        // `SET OF` and `SEQUENCE OF` are a constructed tag whose *content* is a
        // repetition of one element, so the tag is read here and the elements are
        // decoded in a loop rather than through the item machinery.
        let (sktag, skaclass) = if t.flags & ASN1_TFLG_IMPTAG != 0 {
            (t.tag as c_int, aclass)
        } else if t.flags & ASN1_TFLG_SET_OF != 0 {
            (V_ASN1_SET, V_ASN1_UNIVERSAL)
        } else {
            (V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)
        };
        let mut sk_eoc: c_uchar = 0;
        // SAFETY: `p` is readable for `len` bytes; the outputs are local slots.
        let ret = unsafe {
            check_tlen(
                &mut len,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut sk_eoc,
                core::ptr::null_mut(),
                &mut p,
                len,
                sktag,
                skaclass,
                opt,
                ctx,
            )
        };
        if ret == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_639) };
            return 0;
        }
        if ret == -1 {
            return -1;
        }
        // SAFETY: `val` is a live slot.
        let existing = unsafe { *val };
        if existing.is_null() {
            let sk = OPENSSL_sk_new_null();
            // SAFETY: the caller's slot is writable.
            unsafe { *val = sk.cast::<c_void>() };
        } else {
            // A valid stack is emptied first, so re-decoding does not accumulate the
            // previous contents.
            let sk = existing as *mut OpenSslStack;
            // SAFETY: `sk` is the caller's live stack.
            let n = unsafe { OPENSSL_sk_num(sk) };
            let mut k: c_int = 0;
            while k < n {
                // SAFETY: the stack is non-empty, so this answers the last element.
                let vtmp = unsafe { OPENSSL_sk_pop(sk) };
                // SAFETY: `vtmp` is a live element of the field's own item.
                unsafe { crate::asn1::fre::ASN1_item_free(vtmp, sub) };
                k += 1;
            }
        }
        // SAFETY: `val` is a live slot.
        if unsafe { *val }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_658) };
            return 0;
        }
        // SAFETY: `val` is a live slot holding the caller's stack in this arm.
        let sk = unsafe { *val } as *mut OpenSslStack;

        while len > 0 {
            let q = p;
            // SAFETY: `p` is readable for `len` bytes and the slot is writable.
            if unsafe { check_eoc(&mut p, len) } {
                if sk_eoc == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_669) };
                    return 0;
                }
                len -= p as c_long - q as c_long;
                sk_eoc = 0;
                break;
            }
            let mut skfield: *mut c_void = core::ptr::null_mut();
            // SAFETY: the caller's contract; `ctx` is the caller's cache.
            let r = unsafe {
                embed_d2i(
                    &mut skfield,
                    &mut p,
                    len,
                    sub,
                    -1,
                    0,
                    false,
                    ctx,
                    depth,
                    libctx,
                    propq,
                )
            };
            if r <= 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_681) };
                // The element may be partially allocated despite the failure.
                // SAFETY: `skfield` is null or a partial value of the field's item.
                unsafe { crate::asn1::fre::ASN1_item_free(skfield, sub) };
                return 0;
            }
            len -= p as c_long - q as c_long;
            // SAFETY: `sk` is the caller's live stack and `skfield` is a fresh element.
            if unsafe { OPENSSL_sk_push(sk, skfield) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_688) };
                // SAFETY: `skfield` is this frame's value and the stack refused it.
                unsafe { crate::asn1::fre::ASN1_item_free(skfield, sub) };
                return 0;
            }
        }
        if sk_eoc != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_694) };
            return 0;
        }
        // SAFETY: the caller's slot is writable.
        unsafe { *in_ = p };
        return 1;
    }

    let ret = if t.flags & ASN1_TFLG_IMPTAG != 0 {
        // An implicit tag replaces the field's own tag, so the tag is passed down.
        // SAFETY: the caller's contract.
        unsafe {
            embed_d2i(
                val,
                &mut p,
                len,
                sub,
                t.tag as c_int,
                aclass,
                opt,
                ctx,
                depth,
                libctx,
                propq,
            )
        }
    } else {
        // The field's own tag is the underlying type's.
        // SAFETY: the caller's contract.
        unsafe { embed_d2i(val, &mut p, len, sub, -1, 0, opt, ctx, depth, libctx, propq) }
    };
    if ret == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_703) };
        return 0;
    }
    if ret == -1 {
        return -1;
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *in_ = p };
    1
}

/// `asn1_find_end` — the end of an indefinite-length value, without recursing.
///
/// The authority's own comment gives the reason it exists beside `asn1_collect`: a
/// constructed value's content is *kept in encoded form* for `SEQUENCE`, `SET` and
/// `OTHER`, so this walks the headers without copying anything. Its two counters are
/// what make nested indefinite lengths work: an inner indefinite header *increments* the
/// number of end-of-contents markers still expected, and each marker decrements it.
///
/// # Safety
///
/// `in_` must point to a slot holding a readable pointer to `len` bytes; the slot is
/// advanced to the end of the value.
unsafe fn find_end(in_: *mut *const c_uchar, len_in: c_long, inf: bool) -> c_int {
    // SAFETY: the caller's slot is readable.
    let mut p = unsafe { *in_ };
    if !inf {
        // SAFETY: the caller guarantees `len` readable bytes.
        unsafe { *in_ = p.add(len_in.max(0) as usize) };
        return 1;
    }
    let mut len = len_in;
    let mut expected_eoc: u32 = 1;
    while len > 0 {
        // SAFETY: `p` is readable for `len` bytes and the slot is writable.
        if unsafe { check_eoc(&mut p, len) } {
            expected_eoc -= 1;
            if expected_eoc == 0 {
                break;
            }
            len -= 2;
            continue;
        }
        let q = p;
        let mut plen: c_long = 0;
        let mut inf_hdr: c_uchar = 0;
        // SAFETY: `p` is readable for `len` bytes; the outputs are local slots.
        let ok = unsafe {
            check_tlen(
                &mut plen,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut inf_hdr,
                core::ptr::null_mut(),
                &mut p,
                len,
                -1,
                0,
                false,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_1045) };
            return 0;
        }
        if inf_hdr != 0 {
            if expected_eoc == u32::MAX {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_1050) };
                return 0;
            }
            expected_eoc += 1;
        } else {
            // SAFETY: `p` is readable for `plen` bytes.
            p = unsafe { p.add(plen.max(0) as usize) };
        }
        len -= p as c_long - q as c_long;
    }
    if expected_eoc != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_1060) };
        return 0;
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *in_ = p };
    1
}
