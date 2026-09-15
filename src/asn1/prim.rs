//! Phase 5 — `ASN1_OBJECT`, the `ASN1_INTEGER`/`ASN1_ENUMERATED` family, and the
//! two opaque context objects `ASN1_PCTX` and `ASN1_SCTX`.
//!
//! ## The shape of an integer
//!
//! `ASN1_INTEGER` is an `ASN1_STRING` whose `data` holds the **magnitude** in
//! big-endian order and whose sign is a bit in `type` (`V_ASN1_NEG`). The DER
//! encoding is *not* the stored bytes; it is computed by `i2c_ibuf` on the way out
//! and recovered by `c2i_ibuf` on the way in. Both are two's-complement
//! transformations, and both have padding rules that are observable in the encoded
//! octets:
//!
//! * A positive magnitude whose first octet is above `0x7f` gains a `00` pad,
//!   because otherwise the encoding would read as negative.
//! * A negative magnitude gains an `FF` pad when its first octet is above `0x80`.
//!   When that octet is exactly `0x80` it gains one **only if a later octet is
//!   non-zero** — so `-0x8000…00` encodes without the pad and `-0x8000…01` with
//!   it. That distinction is the reason the special case exists at all, and it is
//!   the one a reader is most likely to "simplify" away.
//! * Zero content is illegal on input (`ILLEGAL_ZERO_CONTENT`) and encodes as a
//!   single `00` octet on output.
//! * On input, content whose first two octets have matching sign bits is illegal
//!   padding (`ILLEGAL_PADDING`).
//!
//! ## Two quirks that are not bugs
//!
//! `bn_to_asn1_string` sets `V_ASN1_NEG_INTEGER` regardless of which type it was
//! asked for. For an ENUMERATED that reads as a bug until the arithmetic is done:
//! `V_ASN1_ENUMERATED | V_ASN1_NEG_INTEGER` is `0x10a`, and so is
//! `V_ASN1_NEG_ENUMERATED`. The result is the intended one.
//!
//! `ASN1_ENUMERATED_get` answers `0xffffffffL` — not `-1` — when the content is
//! longer than a `long`. `ASN1_INTEGER_get` answers `-1` for every failure. Both
//! are contract: a caller distinguishes "too big to represent" from "not an
//! integer" by which one it called.
//!
//! ## Where this file deviates, and only where the authority faults
//!
//! The authority dereferences several of these pointers without a NULL check —
//! `ossl_i2c_ASN1_INTEGER` reads `a->data`, `asn1_string_set_int64` writes
//! `a->type`, `ASN1_INTEGER_cmp` reads both operands. Where it does, this module
//! answers a documented value instead of faulting, and the divergences are
//! registered in `docs/SECURITY_DIVERGENCE_POLICY.md` rather than reproduced. The
//! differential court cannot compare a crash, so none of those paths is exercised
//! there either.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};

use crate::asn1::layout::*;
use crate::asn1::string::{
    as_str, as_str_mut, string_embed_free, string_set_body, string_type_new,
};
use crate::ffi::guard_ffi;
use crate::runtime::err::{raise_site, raise_site_dynamic};
use crate::runtime::err_sites;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::{
    object_create, object_free, object_new, Asn1Object, OBJ_nid2obj, OBJ_obj2nid,
    ASN1_OBJECT_FLAG_DYNAMIC, ASN1_OBJECT_FLAG_DYNAMIC_DATA, ASN1_OBJECT_FLAG_DYNAMIC_STRINGS,
};

/// The authority translation unit for the integer family.
pub(crate) const INT_FILE: &core::ffi::CStr = c"crypto/asn1/a_int.c";
/// The authority translation unit for the object type.
pub(crate) const OBJECT_FILE: &core::ffi::CStr = c"crypto/asn1/a_object.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ABS_INT64_MIN` — the magnitude of `INT64_MIN`, spelled as the authority spells
/// it to avoid the overflow its own comment warns about. It is `2^63`.
const ABS_INT64_MIN: u64 = 1u64 << 63;

/// `NID_undef` — the authority's "this object has no name" identifier. The object
/// database keeps it private, so it is restated here as the value it is.
const NID_UNDEF: c_int = 0;

// ---------------------------------------------------------------------------
// The two's-complement content codecs
// ---------------------------------------------------------------------------

/// `twos_complement` — copy with pad `0x00`, or with pad `0xff` complement and add
/// one. With pad `0xff` a leading run of zeros maps to itself, which is the
/// property `i2c_ibuf` relies on to handle "negative zero" and `0x80` followed by
/// zeros without a special case.
///
/// # Safety
///
/// `dst` must be writable for `len` bytes and `src` readable for `len` bytes; they
/// must not overlap. `len` may be zero, in which case neither is read.
unsafe fn twos_complement(dst: *mut u8, src: *const u8, len: usize, pad: u8) {
    let mut carry: u32 = (pad & 1) as u32;
    let mut d = dst;
    let mut s = src;
    if len != 0 {
        // SAFETY: the caller guarantees `len` readable/writable bytes.
        d = unsafe { dst.add(len) };
        s = unsafe { src.add(len) };
    }
    let mut n = len;
    while n != 0 {
        n -= 1;
        // SAFETY: `n` counts down from `len`, so both pointers stay inside the
        // caller's buffers.
        let (v, dd) = unsafe { (s.sub(1).read(), d.sub(1)) };
        s = unsafe { s.sub(1) };
        d = dd;
        carry += (v ^ pad) as u32;
        // SAFETY: `dd` is inside the caller's destination buffer.
        unsafe { dd.write((carry & 0xff) as u8) };
        carry >>= 8;
    }
}

/// `i2c_ibuf` — magnitude and sign to content octets. Returns the length, and
/// advances `*pp` when `pp` is non-null. `blen == 0` (or a null `b`) encodes as the
/// single octet `pb`, which is `0` for a positive.
///
/// # Safety
///
/// `b` must be readable for `blen` bytes. `pp` must be null or point to a slot
/// holding null or a pointer with room for the encoded length.
unsafe fn i2c_ibuf(b: *const u8, blen_in: usize, neg: bool, pp: *mut *mut c_uchar) -> usize {
    let mut pad: usize = 0;
    let mut pb: u8 = 0;
    let mut blen = blen_in;
    let ret;
    if !b.is_null() && blen != 0 {
        // SAFETY: the caller guarantees `blen` readable bytes.
        let first = unsafe { *b };
        if !neg && first > 127 {
            pad = 1;
            pb = 0;
        } else if neg {
            pb = 0xFF;
            if first > 128 {
                pad = 1;
            } else if first == 128 {
                // Only pad when a later octet is non-zero: `0x80` followed by
                // zeros is the minimal negative for its length and must not be
                // padded, while `0x80 00 … 01` is not.
                let mut acc: u8 = 0;
                let mut i = 1usize;
                while i < blen {
                    // SAFETY: `i < blen`.
                    acc |= unsafe { *b.add(i) };
                    i += 1;
                }
                pb = if acc != 0 { 0xff } else { 0 };
                pad = (pb & 1) as usize;
            }
        }
        ret = blen + pad;
    } else {
        ret = 1;
        blen = 0;
    }
    if pp.is_null() {
        return ret;
    }
    // SAFETY: `pp` is a valid slot per the caller's contract.
    let p = unsafe { *pp };
    if p.is_null() {
        return ret;
    }
    // SAFETY: the destination holds `ret` bytes, of which `pad + blen` are written
    // here (`twos_complement` writes `blen` at offset `pad`).
    unsafe {
        *p = pb;
        twos_complement(p.add(pad), b, blen, pb);
        *pp = p.add(ret);
    }
    ret
}

/// `c2i_ibuf` — content octets to magnitude and sign. Returns the magnitude length,
/// or `0` on a malformed encoding (after raising). `pneg` may be null.
///
/// # Safety
///
/// `p` must be readable for `plen` bytes. `b` must be null or writable for the
/// magnitude length, which is at most `plen`.
unsafe fn c2i_ibuf(b: *mut u8, pneg: *mut c_int, p: *const u8, plen_in: usize) -> usize {
    if plen_in == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_160) };
        return 0;
    }
    // SAFETY: `plen_in >= 1`, so `p` is readable for one byte.
    let neg = (unsafe { *p } & 0x80) != 0;
    if !pneg.is_null() {
        // SAFETY: the caller offers a writable slot.
        unsafe { *pneg = c_int::from(neg) };
    }
    if plen_in == 1 {
        if !b.is_null() {
            // SAFETY: `p` is readable and `b` writable for one byte.
            let v = unsafe { *p };
            // SAFETY: as above.
            unsafe { *b = if neg { (v ^ 0xFF).wrapping_add(1) } else { v } };
        }
        return 1;
    }
    let mut pad: usize = 0;
    // SAFETY: `plen_in >= 2`.
    let first = unsafe { *p };
    if first == 0 {
        pad = 1;
    } else if first == 0xFF {
        let mut acc: u8 = 0;
        let mut i = 1usize;
        while i < plen_in {
            // SAFETY: `i < plen_in`.
            acc |= unsafe { *p.add(i) };
            i += 1;
        }
        pad = usize::from(acc != 0);
    }
    // Reject illegal padding: the first two octets' top bits cannot match.
    // SAFETY: `plen_in >= 2`, so `p[1]` is readable.
    if pad != 0 && neg == ((unsafe { *p.add(1) } & 0x80) != 0) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_193) };
        return 0;
    }
    // SAFETY: skipping a pad byte that was just verified to exist.
    let p = unsafe { p.add(pad) };
    let plen = plen_in - pad;
    if !b.is_null() {
        // SAFETY: the destination holds at least `plen` bytes and does not overlap
        // the source.
        unsafe { twos_complement(b, p, plen, if neg { 0xff } else { 0 }) };
    }
    plen
}

/// `ossl_i2c_ASN1_INTEGER` — the length of the DER content, and the encoding when
/// `pp` is non-null.
///
/// # Safety
///
/// `a` must be null or a live `ASN1_STRING` in the integer family. `pp` must be
/// null or point to a slot holding null or a pointer with room for the content.
pub(crate) unsafe fn ossl_i2c_ASN1_INTEGER(a: *mut Asn1String, pp: *mut *mut c_uchar) -> c_int {
    // The authority reads `a->data` here with no NULL check; answering 0 instead of
    // faulting is the documented divergence (docs/SECURITY_DIVERGENCE_POLICY.md).
    let Some(s) = (unsafe { as_str(a) }) else {
        return 0;
    };
    let mut ptr = if pp.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the caller offers a readable slot.
        unsafe { *pp }
    };
    // SAFETY: `s.data` is readable for `s.length` bytes; `ptr` is the caller's.
    let ret = unsafe {
        i2c_ibuf(
            s.data,
            s.length.max(0) as usize,
            s.type_ & V_ASN1_NEG != 0,
            &mut ptr,
        )
    };
    if ret > c_int::MAX as usize {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_213) };
        return 0;
    }
    if !pp.is_null() {
        // SAFETY: the caller's slot is writable.
        unsafe { *pp = ptr };
    }
    ret as c_int
}

/// `ossl_c2i_ASN1_INTEGER` — content octets to an `ASN1_INTEGER`. Reuses `*a` when
/// it is non-null, otherwise allocates and stores the new object through it.
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must be
/// null or point to a slot holding null or a live `ASN1_INTEGER`.
pub(crate) unsafe fn ossl_c2i_ASN1_INTEGER(
    a: *mut *mut Asn1String,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1String {
    if pp.is_null() || len < 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `pp` holds a readable pointer per the caller's contract.
    let p = unsafe { *pp };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // The magnitude length, computed without writing so the destination can be
    // sized. A malformed encoding raises here, once.
    // SAFETY: `p` is readable for `len` bytes.
    let r = unsafe {
        c2i_ibuf(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            p,
            len as usize,
        )
    };
    if r == 0 {
        return core::ptr::null_mut();
    }
    let existing = if a.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the caller's slot is readable.
        unsafe { *a }
    };
    let ret = if existing.is_null() {
        let fresh = string_type_new(V_ASN1_INTEGER);
        if fresh.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `fresh` is live.
        unsafe { (*fresh).type_ = V_ASN1_INTEGER };
        fresh
    } else {
        existing
    };
    if r > c_int::MAX as usize {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_320) };
        // The authority's `goto err` frees only when the object is not the
        // caller's; the same rule is applied here.
        if a.is_null() || unsafe { *a } != ret {
            // SAFETY: `ret` is ours.
            unsafe { string_embed_free(ret, 0) };
        }
        return core::ptr::null_mut();
    }
    // SAFETY: `ret` is a live string; `string_set_body` sizes the buffer. `data` is
    // null, so only the length is set here.
    if unsafe { string_set_body(ret, core::ptr::null(), r as c_int) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_320) };
        if a.is_null() || unsafe { *a } != ret {
            // SAFETY: `ret` is ours.
            unsafe { string_embed_free(ret, 0) };
        }
        return core::ptr::null_mut();
    }
    // SAFETY: `ret` is live and owns at least `r` bytes at `data`.
    let neg = unsafe {
        let mut n: c_int = 0;
        c2i_ibuf((*ret).data, &mut n, p, len as usize);
        n
    };
    // SAFETY: `ret` is live.
    unsafe {
        if neg != 0 {
            (*ret).type_ |= V_ASN1_NEG;
        } else {
            (*ret).type_ &= !V_ASN1_NEG;
        }
        *pp = p.add(len as usize);
        if !a.is_null() {
            *a = ret;
        }
    }
    ret
}

/// `ossl_c2i_ASN1_OBJECT` — OID content octets to an `ASN1_OBJECT`.
///
/// A registered OID is *not* allocated for: the decoder asks the object database
/// and, on a match, returns the shared static table entry, freeing whatever the
/// caller had in `*a` first. Only an OID the database does not know becomes a
/// dynamically allocated object, and only then is the X.690 8.19.2 sub-identifier
/// check applied — a registered encoding is valid by construction.
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `len` bytes. `a` must be
/// null or point to a slot holding null or a live `ASN1_OBJECT`.
pub(crate) unsafe fn ossl_c2i_ASN1_OBJECT(
    a: *mut *mut Asn1Object,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut Asn1Object {
    if len <= 0 || len > c_int::MAX as c_long || pp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_OBJECT_259) };
        return core::ptr::null_mut();
    }
    // SAFETY: `pp` holds a readable pointer per the caller's contract.
    let p = unsafe { *pp };
    if p.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_OBJECT_259) };
        return core::ptr::null_mut();
    }
    let length = len as usize;
    // The last octet's top bit must be clear: an OID whose final sub-identifier
    // continues would be truncated.
    // SAFETY: `p` is readable for `length` bytes.
    if unsafe { *p.add(length - 1) } & 0x80 != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_OBJECT_259) };
        return core::ptr::null_mut();
    }
    // Ask the database about a non-owning view of the encoding. A match means the
    // encoding is one the authority ships, so it is valid and need not be checked.
    let mut probe = Asn1Object {
        sn: core::ptr::null(),
        ln: core::ptr::null(),
        nid: NID_UNDEF,
        length: length as c_int,
        data: p,
        flags: 0,
    };
    // SAFETY: `probe` is a complete object; `OBJ_obj2nid` only reads it.
    let nid = unsafe { OBJ_obj2nid(&mut probe) };
    if nid != NID_UNDEF {
        // SAFETY: the registry hands out a live static entry for a known nid.
        let ret = unsafe { OBJ_nid2obj(nid) };
        if !a.is_null() {
            // SAFETY: the caller's slot holds a live object or null.
            let old = unsafe { *a };
            if !old.is_null() {
                // SAFETY: `old` came from this layer.
                unsafe { object_free(old) };
            }
            // SAFETY: the caller's slot is writable.
            unsafe { *a = ret };
        }
        // SAFETY: `pp` is writable and the content has been consumed.
        unsafe { *pp = p.add(length) };
        return ret;
    }
    // Unregistered: apply 8.19.2, because a dynamic encoding is not vouched for by
    // the table. A `0x80` octet may not lead a sub-identifier unless the previous
    // octet also continued.
    let mut i = 0usize;
    while i < length {
        // SAFETY: `i < length`.
        let octet = unsafe { *p.add(i) };
        if octet == 0x80 && (i == 0 || unsafe { *p.add(i - 1) } & 0x80 == 0) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_OBJECT_289) };
            return core::ptr::null_mut();
        }
        i += 1;
    }
    let existing = if a.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the caller's slot is readable.
        unsafe { *a }
    };
    let reusable = !existing.is_null()
        // SAFETY: `existing` is live per the caller's contract.
        && unsafe { (*existing).flags } & ASN1_OBJECT_FLAG_DYNAMIC != 0;
    let ret = if reusable { existing } else { object_new() };
    if ret.is_null() {
        return core::ptr::null_mut();
    }
    // Detach the old data so it can be reused as the destination when it is large
    // enough, exactly as the authority does.
    // SAFETY: `ret` is live and owned here.
    let old_data = unsafe {
        let d = (*ret).data as *mut u8;
        (*ret).data = core::ptr::null();
        d
    };
    let reuse = !old_data.is_null()
        // SAFETY: `ret` is live.
        && unsafe { (*ret).length as usize } >= length;
    let data = if reuse {
        old_data
    } else {
        if !old_data.is_null() {
            // SAFETY: `old_data` came from this layer's allocator.
            unsafe { CRYPTO_free(old_data.cast::<c_void>(), OBJECT_FILE.as_ptr(), LINE) };
        }
        // SAFETY: `ret` is live and owned here.
        unsafe { (*ret).length = 0 };
        // SAFETY: `CRYPTO_malloc` answers null or `length` writable bytes.
        let fresh = unsafe { CRYPTO_malloc(length, OBJECT_FILE.as_ptr(), LINE) } as *mut u8;
        if fresh.is_null() {
            // The authority raises with `i` still holding the loop counter, which
            // is `length` at this point. That is the authority's own behaviour and
            // is reproduced rather than corrected.
            // SAFETY: `A_OBJECT_334` is a dynamic-reason site.
            unsafe { raise_site_dynamic(&err_sites::A_OBJECT_334, length as c_int) };
            if a.is_null() || unsafe { *a } != ret {
                // SAFETY: `ret` is ours.
                unsafe { object_free(ret) };
            }
            return core::ptr::null_mut();
        }
        // SAFETY: `ret` is live.
        unsafe { (*ret).flags |= ASN1_OBJECT_FLAG_DYNAMIC_DATA };
        fresh
    };
    // SAFETY: `data` is writable for `length` bytes and `p` readable for the same.
    unsafe { core::ptr::copy_nonoverlapping(p, data, length) };
    // SAFETY: `ret` is live and owned here.
    unsafe {
        let o = &mut *ret;
        if o.flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS != 0 {
            if !o.sn.is_null() {
                CRYPTO_free(o.sn as *mut c_void, OBJECT_FILE.as_ptr(), LINE);
            }
            if !o.ln.is_null() {
                CRYPTO_free(o.ln as *mut c_void, OBJECT_FILE.as_ptr(), LINE);
            }
            o.flags &= !ASN1_OBJECT_FLAG_DYNAMIC_STRINGS;
        }
        o.data = data;
        o.length = length as c_int;
        o.sn = core::ptr::null();
        o.ln = core::ptr::null();
        *pp = p.add(length);
        if !a.is_null() {
            *a = ret;
        }
    }
    ret
}

// ---------------------------------------------------------------------------
// `ASN1_OBJECT`
// ---------------------------------------------------------------------------

/// `ASN1_OBJECT *ASN1_OBJECT_new(void)`
#[no_mangle]
pub extern "C" fn ASN1_OBJECT_new() -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), object_new)
}

/// `ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
/// const char *sn, const char *ln)`
///
/// # Safety
///
/// `data` must be readable for `len` bytes; `sn` and `ln` must be null or
/// NUL-terminated. All three are copied.
#[no_mangle]
pub unsafe extern "C" fn ASN1_OBJECT_create(
    nid: c_int,
    data: *mut u8,
    len: c_int,
    sn: *const c_char,
    ln: *const c_char,
) -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-valid per this function's `# Safety` section.
        unsafe { object_create(nid, data, len, sn, ln) }
    })
}

/// `void ASN1_OBJECT_free(ASN1_OBJECT *a)`
///
/// # Safety
///
/// `a` must be null or a live object from this layer that is not used again.
#[no_mangle]
pub unsafe extern "C" fn ASN1_OBJECT_free(a: *mut Asn1Object) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { object_free(a) }
    })
}

/// `ASN1_OBJECT *d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
/// long length)`
///
/// # Safety
///
/// `pp` must point to a slot holding a readable pointer to `length` bytes. `a` must
/// be null or point to a slot holding null or a live object.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASN1_OBJECT(
    a: *mut *mut Asn1Object,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-valid per this function's `# Safety` section.
        unsafe {
            let Some(mut p) = as_ptr_slot(pp) else {
                return core::ptr::null_mut();
            };
            let mut len: c_long = 0;
            let mut tag: c_int = 0;
            let mut xclass: c_int = 0;
            let inf =
                crate::asn1::der::ASN1_get_object(&mut p, &mut len, &mut tag, &mut xclass, length);
            if inf & 0x80 != 0 {
                // The authority's `i` is left holding the header code, so the
                // reason is the value it accumulated rather than a constant.
                raise_site_dynamic(&err_sites::A_OBJECT_241, ASN1_R_BAD_OBJECT_HEADER);
                return core::ptr::null_mut();
            }
            if tag != V_ASN1_OBJECT {
                raise_site_dynamic(&err_sites::A_OBJECT_241, ASN1_R_EXPECTING_AN_OBJECT);
                return core::ptr::null_mut();
            }
            let ret = ossl_c2i_ASN1_OBJECT(a, &mut p, len);
            if !ret.is_null() {
                *pp = p;
            }
            ret
        }
    })
}

/// `int i2d_ASN1_OBJECT(const ASN1_OBJECT *a, unsigned char **pp)`
///
/// # Safety
///
/// `a` must be null or a live object. `pp` must be null, or point to a slot holding
/// null (allocate) or a pointer with room for the encoding.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASN1_OBJECT(a: *const Asn1Object, pp: *mut *mut c_uchar) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is null-or-live.
        let Some(o) = (unsafe { as_object(a) }) else {
            return 0;
        };
        if o.data.is_null() {
            return 0;
        }
        let objsize = crate::asn1::der::ASN1_object_size(0, o.length, V_ASN1_OBJECT);
        if pp.is_null() || objsize == -1 {
            return objsize;
        }
        // SAFETY: `pp` is a readable slot.
        let slot = unsafe { *pp };
        let (p, allocated) = if slot.is_null() {
            // SAFETY: `CRYPTO_malloc` answers null or `objsize` writable bytes.
            let fresh =
                unsafe { CRYPTO_malloc(objsize as usize, OBJECT_FILE.as_ptr(), LINE) } as *mut u8;
            if fresh.is_null() {
                return 0;
            }
            (fresh, true)
        } else {
            (slot, false)
        };
        // SAFETY: `p` holds `objsize` writable bytes and `o.length` content octets
        // are copied into it after the header, which `ASN1_object_size` accounted
        // for.
        unsafe {
            let mut q = p;
            crate::asn1::der::ASN1_put_object(&mut q, 0, o.length, V_ASN1_OBJECT, V_ASN1_UNIVERSAL);
            core::ptr::copy_nonoverlapping(o.data, q, o.length as usize);
            *pp = if allocated {
                p
            } else {
                q.add(o.length as usize)
            };
        }
        objsize
    })
}

// The two reason constants `d2i_ASN1_OBJECT` raises. They are the values behind
// `ASN1_R_BAD_OBJECT_HEADER` and `ASN1_R_EXPECTING_AN_OBJECT`, which the generated
// raise-site table records as a *dynamic* site because the authority accumulates
// them in a local before raising.
const ASN1_R_BAD_OBJECT_HEADER: c_int = 101;
const ASN1_R_EXPECTING_AN_OBJECT: c_int = 127;

/// Read a `const unsigned char **` argument as a value.
///
/// # Safety
///
/// `pp` must be null or point to a readable slot.
unsafe fn as_ptr_slot<'a>(pp: *mut *const c_uchar) -> Option<&'a mut *const c_uchar> {
    if pp.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly a readable slot.
        Some(unsafe { &mut *pp })
    }
}

/// Read a `const ASN1_OBJECT *` as a reference.
///
/// # Safety
///
/// `p` must be null or point to a live object.
unsafe fn as_object<'a>(p: *const Asn1Object) -> Option<&'a Asn1Object> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly a live object.
        Some(unsafe { &*p })
    }
}

// ---------------------------------------------------------------------------
// The 64-bit conversions the integer accessors are built on
// ---------------------------------------------------------------------------

/// `asn1_put_uint64` — big-endian with no leading zero octets. Returns the offset
/// of the first octet written, so `8` means "all eight were".
fn asn1_put_uint64(b: &mut [u8; 8], mut r: u64) -> usize {
    let mut off = 8usize;
    loop {
        off -= 1;
        b[off] = (r & 0xff) as u8;
        r >>= 8;
        if r == 0 {
            return off;
        }
    }
}

/// `asn1_get_uint64` — content octets to an unsigned 64-bit value. A value wider
/// than the destination is `TOO_LARGE`; a null buffer with a zero length is *not* an
/// error, because the length check comes first and the null check does not raise.
///
/// # Safety
///
/// `b` must be null or readable for `blen` bytes, and `pr` writable.
unsafe fn asn1_get_uint64(pr: *mut u64, b: *const u8, blen: usize) -> c_int {
    if blen > 8 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_228) };
        return 0;
    }
    if b.is_null() {
        return 0;
    }
    let mut r: u64 = 0;
    let mut i = 0usize;
    while i < blen {
        r <<= 8;
        // SAFETY: `i < blen`.
        r |= unsafe { *b.add(i) } as u64;
        i += 1;
    }
    // SAFETY: the caller offers a writable slot.
    unsafe { *pr = r };
    1
}

/// `asn1_get_int64` — as above, then the sign is applied and the range checked
/// against `INT64_MIN`/`INT64_MAX` rather than against the unsigned width.
///
/// # Safety
///
/// `b` must be null or readable for `blen` bytes, and `pr` writable.
unsafe fn asn1_get_int64(pr: *mut i64, b: *const u8, blen: usize, neg: bool) -> c_int {
    let mut r: u64 = 0;
    // SAFETY: forwarded per this function's `# Safety` section.
    if unsafe { asn1_get_uint64(&mut r, b, blen) } == 0 {
        return 0;
    }
    let out = if neg {
        if r <= i64::MAX as u64 {
            // The top bit is clear, so the negation is meaningful.
            -(r as i64)
        } else if r == ABS_INT64_MIN {
            // The one magnitude a signed negation cannot express: `-(r as i64)`
            // is `-(INT64_MIN)`, so the negation is done in the unsigned domain
            // and then reinterpreted, which is what the authority's `0 - r` does.
            (r as i64).wrapping_neg()
        } else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_INT_284) };
            return 0;
        }
    } else if r <= i64::MAX as u64 {
        r as i64
    } else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_291) };
        return 0;
    };
    // SAFETY: the caller offers a writable slot.
    unsafe { *pr = out };
    1
}

/// `asn1_string_get_int64`
///
/// # Safety
///
/// `a` must be null or a live string in the integer family, and `pr` writable.
unsafe fn asn1_string_get_int64(pr: *mut i64, a: *const Asn1String, itype: c_int) -> c_int {
    let Some(s) = (unsafe { as_str(a) }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_344) };
        return 0;
    };
    if (s.type_ & !V_ASN1_NEG) != itype {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_348) };
        return 0;
    }
    // SAFETY: `s.data` is readable for `s.length` bytes.
    unsafe {
        asn1_get_int64(
            pr,
            s.data,
            s.length.max(0) as usize,
            s.type_ & V_ASN1_NEG != 0,
        )
    }
}

/// `asn1_string_get_uint64`
///
/// # Safety
///
/// `a` must be null or a live string in the integer family, and `pr` writable.
unsafe fn asn1_string_get_uint64(pr: *mut u64, a: *const Asn1String, itype: c_int) -> c_int {
    let Some(s) = (unsafe { as_str(a) }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_381) };
        return 0;
    };
    if (s.type_ & !V_ASN1_NEG) != itype {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_385) };
        return 0;
    }
    if s.type_ & V_ASN1_NEG != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_389) };
        return 0;
    }
    // SAFETY: `s.data` is readable for `s.length` bytes.
    unsafe { asn1_get_uint64(pr, s.data, s.length.max(0) as usize) }
}

/// `asn1_string_set_int64` — the magnitude is `|r|`, written as the minimum number
/// of octets, and the sign goes into `type`.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned string in the integer family.
unsafe fn asn1_string_set_int64(a: *mut Asn1String, r: i64, itype: c_int) -> c_int {
    // The authority writes `a->type` with no NULL check; answering 0 is the
    // documented divergence.
    let Some(s) = (unsafe { as_str_mut(a) }) else {
        return 0;
    };
    let mut tbuf = [0u8; 8];
    let (off, neg) = if r < 0 {
        // `0 - (uint64_t)r` has to go through the unsigned domain: `-r` is
        // undefined for `INT64_MIN`.
        (asn1_put_uint64(&mut tbuf, (r as u64).wrapping_neg()), true)
    } else {
        (asn1_put_uint64(&mut tbuf, r as u64), false)
    };
    s.type_ = itype;
    if neg {
        s.type_ |= V_ASN1_NEG;
    } else {
        s.type_ &= !V_ASN1_NEG;
    }
    // SAFETY: `tbuf` is readable from `off` to its end.
    unsafe { string_set_body(a, tbuf.as_ptr().add(off), (tbuf.len() - off) as c_int) }
}

/// `asn1_string_set_uint64`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned string in the integer family.
unsafe fn asn1_string_set_uint64(a: *mut Asn1String, r: u64, itype: c_int) -> c_int {
    let Some(s) = (unsafe { as_str_mut(a) }) else {
        return 0;
    };
    let mut tbuf = [0u8; 8];
    let off = asn1_put_uint64(&mut tbuf, r);
    s.type_ = itype;
    // SAFETY: `tbuf` is readable from `off` to its end.
    unsafe { string_set_body(a, tbuf.as_ptr().add(off), (tbuf.len() - off) as c_int) }
}

// ---------------------------------------------------------------------------
// The exported integer accessors
// ---------------------------------------------------------------------------

/// `ASN1_INTEGER *ASN1_INTEGER_new(void)`
#[no_mangle]
pub extern "C" fn ASN1_INTEGER_new() -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || string_type_new(V_ASN1_INTEGER))
}

/// `ASN1_INTEGER *ASN1_ENUMERATED_new(void)`
#[no_mangle]
pub extern "C" fn ASN1_ENUMERATED_new() -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || string_type_new(V_ASN1_ENUMERATED))
}

/// `void ASN1_INTEGER_free(ASN1_INTEGER *a)`
///
/// # Safety
///
/// `a` must be null or a live integer from this layer that is not used again.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_free(a: *mut Asn1String) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { string_embed_free(a, 0) }
    });
}

/// `void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a)`
///
/// # Safety
///
/// `a` must be null or a live enumerated from this layer that is not used again.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_free(a: *mut Asn1String) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { string_embed_free(a, 0) }
    });
}

/// `ASN1_INTEGER *ASN1_INTEGER_dup(const ASN1_INTEGER *x)`
///
/// # Safety
///
/// `x` must be null or a live integer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_dup(x: *const Asn1String) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: forwarded per this function's `# Safety` section.
        unsafe { crate::asn1::string::ASN1_STRING_dup(x) }
    })
}

/// `ASN1_ENUMERATED *ASN1_ENUMERATED_dup(const ASN1_ENUMERATED *x)`
///
/// # Safety
///
/// `x` must be null or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_dup(x: *const Asn1String) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: forwarded per this function's `# Safety` section.
        unsafe { crate::asn1::string::ASN1_STRING_dup(x) }
    })
}

/// `int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y)`
///
/// The sign dominates the magnitude, so a negative is always less than a positive
/// whatever their contents; two negatives compare by reversed magnitude.
///
/// # Safety
///
/// `x` and `y` must be null or live integer values.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_cmp(x: *const Asn1String, y: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // The authority reads `x->type` with no NULL check; a null operand answers
        // 0 here, which is the documented divergence.
        let (Some(a), Some(b)) = (unsafe { as_str(x) }, unsafe { as_str(y) }) else {
            return 0;
        };
        let neg_a = a.type_ & V_ASN1_NEG != 0;
        let neg_b = b.type_ & V_ASN1_NEG != 0;
        if neg_a != neg_b {
            return if neg_a { -1 } else { 1 };
        }
        // SAFETY: both operands are live.
        let ret = unsafe { crate::asn1::string::ASN1_STRING_cmp(x, y) };
        if neg_a {
            -ret
        } else {
            ret
        }
    })
}

/// `int ASN1_INTEGER_set_int64(ASN1_INTEGER *a, int64_t r)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned integer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set_int64(a: *mut Asn1String, r: i64) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_set_int64(a, r, V_ASN1_INTEGER) }
    })
}

/// `int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED *a, int64_t r)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned enumerated value.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_set_int64(a: *mut Asn1String, r: i64) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_set_int64(a, r, V_ASN1_ENUMERATED) }
    })
}

/// `int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned integer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set_uint64(a: *mut Asn1String, r: u64) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_set_uint64(a, r, V_ASN1_INTEGER) }
    })
}

/// `int ASN1_INTEGER_set(ASN1_INTEGER *a, long v)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned integer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_set(a: *mut Asn1String, v: c_long) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_set_int64(a, v as i64, V_ASN1_INTEGER) }
    })
}

/// `int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned enumerated value.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_set(a: *mut Asn1String, v: c_long) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_set_int64(a, v as i64, V_ASN1_ENUMERATED) }
    })
}

/// `int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a)`
///
/// # Safety
///
/// `a` must be null or a live integer, and `pr` writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get_int64(pr: *mut i64, a: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_get_int64(pr, a, V_ASN1_INTEGER) }
    })
}

/// `int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a)`
///
/// # Safety
///
/// `a` must be null or a live enumerated value, and `pr` writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_get_int64(pr: *mut i64, a: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_get_int64(pr, a, V_ASN1_ENUMERATED) }
    })
}

/// `int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a)`
///
/// # Safety
///
/// `a` must be null or a live integer, and `pr` writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get_uint64(pr: *mut u64, a: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_get_uint64(pr, a, V_ASN1_INTEGER) }
    })
}

/// `long ASN1_INTEGER_get(const ASN1_INTEGER *a)`
///
/// A null operand answers `0`; every other failure answers `-1`, including a value
/// outside `long`'s range. A caller tells "nothing there" from "not an integer" by
/// the operand it passed, not by the answer.
///
/// # Safety
///
/// `a` must be null or a live integer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_get(a: *const Asn1String) -> c_long {
    guard_ffi(0, || {
        if a.is_null() {
            return 0;
        }
        let mut r: i64 = 0;
        // SAFETY: `a` is live.
        if unsafe { asn1_string_get_int64(&mut r, a, V_ASN1_INTEGER) } == 0 {
            return -1;
        }
        if r > c_long::MAX as i64 || r < c_long::MIN as i64 {
            return -1;
        }
        r as c_long
    })
}

/// `long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a)`
///
/// Differs from `ASN1_INTEGER_get` in the two answers a caller may be testing for:
/// a value whose *content* is longer than a `long` answers `0xffffffffL` rather
/// than `-1`, and a value of the wrong type answers `-1` **without** raising, so a
/// wrong-type ENUMERATED is silent where a wrong-type INTEGER is not.
///
/// # Safety
///
/// `a` must be null or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_get(a: *const Asn1String) -> c_long {
    guard_ffi(0, || {
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is live.
        let s = unsafe { &*a };
        if (s.type_ & !V_ASN1_NEG) != V_ASN1_ENUMERATED {
            return -1;
        }
        if s.length as usize > core::mem::size_of::<c_long>() {
            return 0xffff_ffff;
        }
        let mut r: i64 = 0;
        // SAFETY: `a` is live.
        if unsafe { asn1_string_get_int64(&mut r, a, V_ASN1_ENUMERATED) } == 0 {
            return -1;
        }
        if r > c_long::MAX as i64 || r < c_long::MIN as i64 {
            return -1;
        }
        r as c_long
    })
}

// ---------------------------------------------------------------------------
// The `BIGNUM` bridges
// ---------------------------------------------------------------------------

/// `bn_to_asn1_string` — a `BIGNUM` into an integer of the requested type.
///
/// # Safety
///
/// `bn` must be null or a live bignum; `ai` must be null or a live,
/// uniquely-owned string.
unsafe fn bn_to_asn1_string(
    bn: *const crate::bn::bignum::BigNum,
    ai: *mut Asn1String,
    atype: c_int,
) -> *mut Asn1String {
    // The authority dereferences `bn` immediately; answering NULL is the
    // documented divergence.
    if bn.is_null() {
        return core::ptr::null_mut();
    }
    let ret = if ai.is_null() {
        let fresh = string_type_new(atype);
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_INT_488) };
            return core::ptr::null_mut();
        }
        fresh
    } else {
        // SAFETY: `ai` is live and uniquely owned.
        unsafe { (*ai).type_ = atype };
        ai
    };
    // SAFETY: `bn` and `ret` are live.
    unsafe {
        if crate::bn::bignum::BN_is_negative(bn) != 0 && crate::bn::bignum::BN_is_zero(bn) == 0 {
            // Deliberately `V_ASN1_NEG_INTEGER` whatever `atype` was: the value is
            // the same bit pattern for ENUMERATED, and reproducing the authority's
            // spelling is how that stays true.
            (*ret).type_ |= V_ASN1_NEG_INTEGER;
        }
        let mut len = (crate::bn::bignum::BN_num_bits(bn) + 7) / 8;
        if len == 0 {
            len = 1;
        }
        if string_set_body(ret, core::ptr::null(), len) == 0 {
            raise_site(&err_sites::A_INT_501);
            if ret != ai {
                string_embed_free(ret, 0);
            }
            return core::ptr::null_mut();
        }
        if crate::bn::bignum::BN_is_zero(bn) != 0 {
            *(*ret).data = 0;
        } else {
            len = crate::bn::bignum::BN_bn2bin(bn, (*ret).data);
        }
        (*ret).length = len;
    }
    ret
}

/// `asn1_string_to_bn` — an integer of the requested type into a `BIGNUM`,
/// allocating one when `bn` is null.
///
/// # Safety
///
/// `ai` must be null or a live string; `bn` must be null or a live bignum.
unsafe fn asn1_string_to_bn(
    ai: *const Asn1String,
    bn: *mut crate::bn::bignum::BigNum,
    itype: c_int,
) -> *mut crate::bn::bignum::BigNum {
    // The authority reads `ai->type` with no NULL check; answering NULL is the
    // documented divergence.
    let Some(s) = (unsafe { as_str(ai) }) else {
        return core::ptr::null_mut();
    };
    if (s.type_ & !V_ASN1_NEG) != itype {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_524) };
        return core::ptr::null_mut();
    }
    // SAFETY: `s.data` is readable for `s.length` bytes; `bn` is null or live.
    let ret = unsafe { crate::bn::bignum::BN_bin2bn(s.data, s.length.max(0), bn) };
    if ret.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_INT_530) };
        return core::ptr::null_mut();
    }
    if s.type_ & V_ASN1_NEG != 0 {
        // SAFETY: `ret` is a live bignum.
        unsafe { crate::bn::bignum::BN_set_negative(ret, 1) };
    }
    ret
}

/// `ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai)`
///
/// # Safety
///
/// `bn` must be null or a live bignum; `ai` must be null or a live,
/// uniquely-owned integer.
#[no_mangle]
pub unsafe extern "C" fn BN_to_ASN1_INTEGER(
    bn: *const crate::bn::bignum::BigNum,
    ai: *mut Asn1String,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { bn_to_asn1_string(bn, ai, V_ASN1_INTEGER) }
    })
}

/// `ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(const BIGNUM *bn, ASN1_ENUMERATED *ai)`
///
/// # Safety
///
/// `bn` must be null or a live bignum; `ai` must be null or a live,
/// uniquely-owned enumerated value.
#[no_mangle]
pub unsafe extern "C" fn BN_to_ASN1_ENUMERATED(
    bn: *const crate::bn::bignum::BigNum,
    ai: *mut Asn1String,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { bn_to_asn1_string(bn, ai, V_ASN1_ENUMERATED) }
    })
}

/// `BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn)`
///
/// # Safety
///
/// `ai` must be null or a live integer; `bn` must be null or a live bignum.
#[no_mangle]
pub unsafe extern "C" fn ASN1_INTEGER_to_BN(
    ai: *const Asn1String,
    bn: *mut crate::bn::bignum::BigNum,
) -> *mut crate::bn::bignum::BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_to_bn(ai, bn, V_ASN1_INTEGER) }
    })
}

/// `BIGNUM *ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED *ai, BIGNUM *bn)`
///
/// # Safety
///
/// `ai` must be null or a live enumerated value; `bn` must be null or a live
/// bignum.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ENUMERATED_to_BN(
    ai: *const Asn1String,
    bn: *mut crate::bn::bignum::BigNum,
) -> *mut crate::bn::bignum::BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        unsafe { asn1_string_to_bn(ai, bn, V_ASN1_ENUMERATED) }
    })
}

// ---------------------------------------------------------------------------
// The two opaque context objects
// ---------------------------------------------------------------------------

/// `ASN1_PCTX *ASN1_PCTX_new(void)` — zeroed, so every flag starts clear.
#[no_mangle]
pub extern "C" fn ASN1_PCTX_new() -> *mut Asn1Pctx {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `CRYPTO_zalloc` answers null or `sizeof(ASN1_PCTX)` zeroed
        // bytes.
        unsafe {
            CRYPTO_zalloc(core::mem::size_of::<Asn1Pctx>(), OBJECT_FILE.as_ptr(), LINE)
                .cast::<Asn1Pctx>()
        }
    })
}

/// `ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb)(ASN1_SCTX *p))`
///
/// The streaming callback is stored, not called, and the rest of the state is
/// filled in as the stream advances.
#[no_mangle]
pub extern "C" fn ASN1_SCTX_new(
    scan_cb: Option<unsafe extern "C" fn(*mut Asn1Sctx) -> c_int>,
) -> *mut Asn1Sctx {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `CRYPTO_zalloc` answers null or `sizeof(ASN1_SCTX)` zeroed
        // bytes.
        let ret = unsafe {
            CRYPTO_zalloc(core::mem::size_of::<Asn1Sctx>(), OBJECT_FILE.as_ptr(), LINE)
                .cast::<Asn1Sctx>()
        };
        if ret.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `ret` is a fresh zeroed `ASN1_SCTX`.
        unsafe { (*ret).cb = scan_cb };
        ret
    })
}

/// `void ASN1_SCTX_free(ASN1_SCTX *p)`
///
/// # Safety
///
/// `p` must be null or an object this layer allocated and has not freed.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_free(p: *mut Asn1Sctx) {
    guard_ffi((), || {
        if p.is_null() {
            return;
        }
        // SAFETY: `p` came from this layer's allocator per the caller's contract.
        unsafe { CRYPTO_free(p.cast::<c_void>(), OBJECT_FILE.as_ptr(), LINE) };
    });
}

/// `const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_SCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_get_item(p: *mut Asn1Sctx) -> *const Asn1Item {
    guard_ffi(core::ptr::null(), || unsafe {
        match p.as_ref() {
            Some(x) => x.it,
            None => core::ptr::null(),
        }
    })
}

/// `const ASN1_TEMPLATE *ASN1_SCTX_get_template(ASN1_SCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_SCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_get_template(p: *mut Asn1Sctx) -> *const Asn1Template {
    guard_ffi(core::ptr::null(), || unsafe {
        match p.as_ref() {
            Some(x) => x.template,
            None => core::ptr::null(),
        }
    })
}

/// `unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_SCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_get_flags(p: *mut Asn1Sctx) -> c_ulong {
    guard_ffi(0, || unsafe {
        match p.as_ref() {
            Some(x) => x.flags,
            None => 0,
        }
    })
}

/// `void *ASN1_SCTX_get_app_data(ASN1_SCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_SCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_get_app_data(p: *mut Asn1Sctx) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || unsafe {
        match p.as_ref() {
            Some(x) => x.app_data,
            None => core::ptr::null_mut(),
        }
    })
}

/// `void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_SCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_SCTX_set_app_data(p: *mut Asn1Sctx, data: *mut c_void) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.app_data = data;
        }
    });
}

/// `ASN1_PCTX_free(ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or an object this layer allocated and has not freed.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_free(p: *mut Asn1Pctx) {
    guard_ffi((), || {
        if p.is_null() {
            return;
        }
        // SAFETY: `p` came from this layer's allocator per the caller's contract.
        unsafe { CRYPTO_free(p.cast::<c_void>(), OBJECT_FILE.as_ptr(), LINE) };
    });
}

/// `unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_get_flags(p: *const Asn1Pctx) -> c_ulong {
    guard_ffi(0, || unsafe { pctx_flags(p).0 })
}

/// `void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_set_flags(p: *mut Asn1Pctx, flags: c_ulong) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.flags = flags;
        }
    });
}

/// `unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_get_nm_flags(p: *const Asn1Pctx) -> c_ulong {
    guard_ffi(0, || unsafe { pctx_flags(p).1 })
}

/// `void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_set_nm_flags(p: *mut Asn1Pctx, flags: c_ulong) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.nm_flags = flags;
        }
    });
}

/// `unsigned long ASN1_PCTX_get_cert_flags(const ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_get_cert_flags(p: *const Asn1Pctx) -> c_ulong {
    guard_ffi(0, || unsafe { pctx_flags(p).2 })
}

/// `void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_set_cert_flags(p: *mut Asn1Pctx, flags: c_ulong) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.cert_flags = flags;
        }
    });
}

/// `unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_get_oid_flags(p: *const Asn1Pctx) -> c_ulong {
    guard_ffi(0, || unsafe { pctx_flags(p).3 })
}

/// `void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_set_oid_flags(p: *mut Asn1Pctx, flags: c_ulong) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.oid_flags = flags;
        }
    });
}

/// `unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p)`
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_get_str_flags(p: *const Asn1Pctx) -> c_ulong {
    guard_ffi(0, || unsafe { pctx_flags(p).4 })
}

/// `void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags)`
///
/// # Safety
///
/// `p` must be null or a live, uniquely-owned `ASN1_PCTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_PCTX_set_str_flags(p: *mut Asn1Pctx, flags: c_ulong) {
    guard_ffi((), || unsafe {
        if let Some(x) = p.as_mut() {
            x.str_flags = flags;
        }
    });
}

/// Read the five flags of an `ASN1_PCTX` at once, so the five getters differ only
/// in which element of the tuple they take.
///
/// # Safety
///
/// `p` must be null or a live `ASN1_PCTX`.
unsafe fn pctx_flags(p: *const Asn1Pctx) -> (c_ulong, c_ulong, c_ulong, c_ulong, c_ulong) {
    if p.is_null() {
        return (0, 0, 0, 0, 0);
    }
    // SAFETY: the caller's contract is exactly a live `ASN1_PCTX`.
    let x = unsafe { &*p };
    (x.flags, x.nm_flags, x.cert_flags, x.oid_flags, x.str_flags)
}
