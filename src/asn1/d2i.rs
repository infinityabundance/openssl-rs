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

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::bitstr::ossl_c2i_ASN1_BIT_STRING;
use crate::asn1::layout::*;
use crate::asn1::prim::{ossl_c2i_ASN1_INTEGER, ossl_c2i_ASN1_OBJECT};
use crate::asn1::string::{string_type_new, ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_set0};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};
use crate::runtime::obj::Asn1Object;
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
// ---------------------------------------------------------------------------
// `asn1_item_embed_d2i`
// ---------------------------------------------------------------------------

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
/// `it` must be a live item, and for this stratum's items it must be one of the
/// two shapes [`embed_d2i`] documents as reachable.
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
    let rv = unsafe { embed_d2i(pval, pp, len, it, -1, 0, false, &mut ctx) };
    if rv <= 0 {
        // A failed decode **frees the caller's value and nulls the caller's
        // slot**. That is the authority's `asn1_item_ex_d2i_intern`, and it is the
        // ownership contract rather than a detail of the failure path: a caller
        // that decodes into an existing object and fails does not keep it.
        //
        // SAFETY: `pval` is a live slot and `it` is the caller's item.
        unsafe { crate::asn1::fre::item_ex_free(pval, it) };
        return core::ptr::null_mut();
    }
    // SAFETY: `pval` is a live slot.
    unsafe { *pval }
}

/// `asn1_item_embed_d2i`, restricted to the `PRIMITIVE`-without-templates and
/// `MSTRING` arms.
///
/// The two arms not taken here cannot be reached from any item
/// [`crate::asn1::items`] defines, and the `debug_assert!` is what makes that a
/// checked statement rather than a comment: it fires in the unit-test profile the
/// court runs, so a future edit that routes a template-bearing item here is
/// caught by a test rather than by a caller.
///
/// # Safety
///
/// As [`item_d2i`]. `pval` must be non-null — this is the inner entry point, and
/// the null redirect belongs to [`item_d2i`].
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn embed_d2i(
    pval: *mut *mut Asn1String,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: bool,
    ctx: *mut Asn1Tlc,
) -> c_int {
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
    let it = unsafe { &*it };
    if it.itype == ASN1_ITYPE_MSTRING {
        if tag != -1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_DEC_252) };
            return 0;
        }
        // SAFETY: the caller's contract passes through unchanged.
        return unsafe { mstring_d2i(pval, in_, len, it, opt, ctx) };
    }
    debug_assert!(
        it.itype == ASN1_ITYPE_PRIMITIVE && it.templates.is_null(),
        "item dispatch beyond the primitive and MSTRING arms is subphase 5.4"
    );
    if it.itype != ASN1_ITYPE_PRIMITIVE || !it.templates.is_null() {
        // Unreachable by construction. Failing closed for the same reason the
        // assertion exists: if the exclusion ever stops holding, the symptom must
        // be a decode that fails, never a decode that answers.
        return 0;
    }
    // SAFETY: the caller's contract passes through unchanged.
    unsafe { d2i_ex_primitive(pval, in_, len, it, tag, aclass, opt, ctx) }
}

/// The `ASN1_ITYPE_MSTRING` arm: read the tag, require a universal class, and
/// check it against the item's `B_ASN1_*` mask before decoding.
///
/// This arm exists because a multi-string item has no single underlying type: the
/// type is a property of the *encoding*, so it must be read before the decoder is
/// entered, and the decoder is then entered with that tag as its starting
/// `utype`. That is the whole reason `asn1_d2i_ex_primitive` opens with
/// `if (it->itype == ASN1_ITYPE_MSTRING) { utype = tag; tag = -1; }`.
///
/// # Safety
///
/// As [`item_d2i`]; `it` must be a live `MSTRING` item.
unsafe fn mstring_d2i(
    pval: *mut *mut Asn1String,
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
    // `asn1_check_tlen` is passed `opt = 1` here even though its tag argument is
    // -1: with `exptag < 0` the tag comparison is skipped and `opt` cannot be
    // consulted, so the value is inert, and it is passed as the authority passes
    // it rather than as it happens to matter.
    // SAFETY: `p` is readable for `len` bytes; the outputs are local slots and
    // `ctx` is the caller's cache.
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
        return 0;
    }
    if oclass != V_ASN1_UNIVERSAL as c_uchar {
        if opt {
            // Not present rather than wrong; the caller decides.
            return -1;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_270) };
        return 0;
    }
    // `ASN1_tag2bit` is not a bijection and several tags read 0, so a tag outside
    // the mask is rejected here rather than reaching a decoder that would have
    // built a string of the wrong type.
    // SAFETY: `it` is a live item; `utype` holds the mask for a MSTRING.
    if crate::asn1::der::ASN1_tag2bit(otag) & (it.utype as core::ffi::c_ulong) == 0 {
        if opt {
            return -1;
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_DEC_279) };
        return 0;
    }
    // The tag read from the encoding becomes the decoder's starting `utype`.
    // SAFETY: the caller's contract passes through unchanged.
    unsafe { d2i_ex_primitive(pval, in_, len, it, otag, 0, false, ctx) }
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

    let utype: c_int;
    let mut tag = tag;
    let mut aclass = aclass;
    if it.itype == ASN1_ITYPE_MSTRING {
        utype = tag;
        tag = -1;
    } else {
        utype = it.utype as c_int;
    }

    // `V_ASN1_ANY` reads the type from the encoding and allocates an `ASN1_TYPE`
    // to hold the pair: subphase 5.7. No item this stratum defines has that
    // `utype` other than `ASN1_ANY_it`, whose only consumer is `ASN1_item_d2i`.
    debug_assert!(utype != V_ASN1_ANY, "V_ASN1_ANY is subphase 5.7");

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

    // SEQUENCE, SET and OTHER keep their encoded form, which needs
    // `asn1_find_end`: subphase 5.4, and reachable only through
    // `ASN1_SEQUENCE_it`.
    debug_assert!(
        utype != V_ASN1_SEQUENCE && utype != V_ASN1_SET && utype != V_ASN1_OTHER,
        "the encoded-form arm is subphase 5.4"
    );

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
/// must be live and must not have `utype == V_ASN1_ANY`.
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

    // `V_ASN1_ANY` allocates an `ASN1_TYPE`, sets its type, and redirects `pval`
    // into the union: subphase 5.7. `has_any` is constant-false here, which is why
    // the authority's `err:` tail reduces to a plain return.
    debug_assert!(
        it.utype != V_ASN1_ANY as c_long,
        "V_ASN1_ANY is subphase 5.7"
    );

    match utype {
        V_ASN1_OBJECT => {
            // The authority's `||` short-circuits into `err` with no raise of its
            // own on the length test; `ossl_c2i_ASN1_OBJECT` raises for the
            // failures it detects.
            if len != ilen as c_long {
                return 0;
            }
            let mut cur = cont;
            // SAFETY: `cur` is readable for `len` bytes; `pval` is a live slot for
            // an `ASN1_OBJECT`.
            let ret =
                unsafe { ossl_c2i_ASN1_OBJECT(pval.cast::<*mut Asn1Object>(), &mut cur, len) };
            if ret.is_null() {
                return 0;
            }
        }

        V_ASN1_NULL => {
            if len != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_900) };
                return 0;
            }
            // A `NULL`'s value is the sentinel `1`, never a heap pointer. That is
            // load-bearing for the ownership contract: `ASN1_NULL_free` is a
            // no-op, so a caller that frees one does not free a pointer that was
            // never an allocation.
            //
            // The clippy lint below wants `ptr::dangling_mut`, which answers an
            // address derived from the type's *alignment* — 4 for an `int`, not 1.
            // The authority's sentinel is literally `(ASN1_VALUE *)1` and a caller
            // can read it back, so the lint's suggestion would be a different
            // observable value.
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
                return 0;
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
                return 0;
            }
        }

        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            let mut cur = cont;
            // SAFETY: `cur` is readable for `len` bytes; `pval` is a live slot.
            let tint = unsafe { ossl_c2i_ASN1_INTEGER(pval, &mut cur, len) };
            if tint.is_null() {
                return 0;
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
                return 0;
            }
            // A `BMPSTRING` is pairs of octets, a `UNIVERSALSTRING` groups of
            // four, so a length that is not a multiple of the unit is malformed
            // rather than merely suspicious.
            if utype == V_ASN1_BMPSTRING && len & 1 != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_954) };
                return 0;
            }
            if utype == V_ASN1_UNIVERSALSTRING && len & 3 != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_958) };
                return 0;
            }
            // The two time types have a shortest legal spelling, and the authority
            // rejects anything shorter here rather than letting the *checker*
            // discover it later.
            if utype == V_ASN1_GENERALIZEDTIME && len < 15 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_962) };
                return 0;
            }
            if utype == V_ASN1_UTCTIME && len < 13 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_DEC_966) };
                return 0;
            }
            // SAFETY: `pval` is a live slot.
            let existing = unsafe { *pval };
            let stmp = if existing.is_null() {
                let fresh = string_type_new(utype);
                if fresh.is_null() {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_DEC_973) };
                    return 0;
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
                return 0;
            }
        }
    }
    1
}
