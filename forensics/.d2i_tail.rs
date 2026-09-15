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
    if unsafe { embed_d2i(pval, pp, len, it, -1, 0, false, &mut ctx) } > 0 {
        // SAFETY: `pval` is a live slot.
        unsafe { *pval }
    } else {
        core::ptr::null_mut()
    }
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

    let mut utype: c_int;
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
            // SAFETY: `cur` is readable for `ilen` bytes; `pval` is a live slot
            // for an `ASN1_OBJECT`.
            let ret =
                unsafe { ossl_c2i_ASN1_OBJECT(pval.cast::<*mut Asn1Object>(), &mut cur, ilen) };
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
            // SAFETY: `pval` is a live slot.
            unsafe { *pval = 1 as *mut Asn1String };
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
