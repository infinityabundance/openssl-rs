//! Phase 5 — the item allocator: `crypto/asn1/tasn_new.c`.
//!
//! `ASN1_item_new` is the only way a caller can obtain a value for a structure type
//! it did not build itself, so this module is the entry point to every `SEQUENCE`,
//! `CHOICE` and `ANY` in the library. Four exports live here — `ASN1_item_new`,
//! `ASN1_item_new_ex`, `ASN1_item_ex_new` and their free counterparts in
//! [`crate::asn1::fre`], which are in `tasn_fre.c` in the authority for the same
//! reason they are in a different module here.
//!
//! ## What "embed" means, and why it is the subtle part
//!
//! Every function here takes an `embed` flag. It is not an optimisation: an *embedded*
//! field is one whose storage is the field itself rather than a pointer to a separate
//! allocation (`ASN1_TFLG_EMBED`), and the authority's own comment on
//! `ASN1_TFLG_ADB_MASK`'s neighbours calls out that this is why `ossl_asn1_get_field_ptr`
//! has to return `(int *)` for a `BOOLEAN`. The three places `embed` changes behaviour
//! are all observable:
//!
//! * a `CHOICE` or `SEQUENCE` value is `memset` rather than `zalloc`'d, so the caller's
//!   storage is reused — and the failure path must **not** free it;
//! * a primitive is built in place, `memset` to zero with its type stamped and
//!   `ASN1_STRING_FLAG_EMBED` set, so freeing it must not release the field;
//! * `prim_clear` replaces `prim_new` in the hooks' dispatch.
//!
//! ## The two failure labels, which are not interchangeable
//!
//! `asn1err` raises `ERR_R_ASN1_LIB` and `auxerr` raises `ASN1_R_AUX_ERROR`, and the two
//! `*err2` labels fall into them after freeing the partial value. So a caller can tell
//! "a field could not be allocated" from "the application callback refused" by the
//! reason alone, which is why both are reproduced with their own coordinates rather
//! than collapsed into one path.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::fre::item_embed_free;
use crate::asn1::layout::*;
use crate::asn1::string::ASN1_STRING_type_new;
use crate::asn1::utl;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::OBJ_nid2obj;
use crate::runtime::stack::OPENSSL_sk_new_null;

/// The authority translation unit for the allocator.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_new.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `NID_undef` — the object a freshly allocated `OBJECT` starts as.
const NID_UNDEF: c_int = 0;

/// `ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)`
///
/// Answers null when the allocation or the initialisation failed, having already raised
/// and released whatever was partly built.
///
/// # Safety
///
/// `it` must be a live item.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_new(it: *const Asn1Item) -> *mut c_void {
    let mut ret: *mut c_void = core::ptr::null_mut();
    // SAFETY: the caller's contract; `ret` is a live slot.
    if unsafe { ASN1_item_ex_new(&mut ret, it) } > 0 {
        return ret;
    }
    core::ptr::null_mut()
}

/// `ASN1_VALUE *ASN1_item_new_ex(const ASN1_ITEM *it, OSSL_LIB_CTX *libctx,
/// const char *propq)`
///
/// The same, with a library context and a property query for the items whose hooks take
/// them. The context and query are passed straight through: this crate has no
/// `OSSL_LIB_CTX` yet (Phase 6), so an `EXTERN` item that uses them is the only reader,
/// and a caller that passes one is asking for that item's behaviour.
///
/// # Safety
///
/// `it` must be a live item. `libctx` must be null or a live library context, and
/// `propq` null or a NUL-terminated string, whatever the item's hooks require.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_new_ex(
    it: *const Asn1Item,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    let mut ret: *mut c_void = core::ptr::null_mut();
    // SAFETY: the caller's contract; `ret` is a live slot.
    if unsafe { item_embed_new(&mut ret, it, 0, libctx, propq) } > 0 {
        return ret;
    }
    core::ptr::null_mut()
}

/// `int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot; `it` must be a live item.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ex_new(pval: *mut *mut c_void, it: *const Asn1Item) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { item_embed_new(pval, it, 0, core::ptr::null_mut(), core::ptr::null()) }
}

/// `ossl_asn1_item_ex_new_intern` — the form the `d2i` arms call, so that a `CHOICE`
/// alternative or a `SEQUENCE` field is built through one entry point.
///
/// # Safety
///
/// As [`ASN1_item_ex_new`].
#[allow(dead_code)] // the template d2i arms are the only caller and land with them
pub(crate) unsafe fn item_ex_new_intern(
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { item_embed_new(pval, it, 0, libctx, propq) }
}

/// `asn1_item_embed_new` — allocate and initialise a value of `it`'s type.
///
/// # Safety
///
/// `pval` must be a live slot; `it` must be a live item. When `embed` is non-zero,
/// `*pval` must point at storage the caller owns and which this call may `memset`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn item_embed_new(
    pval: *mut *mut c_void,
    it: *const Asn1Item,
    embed: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if pval.is_null() || it.is_null() {
        return 0;
    }
    // SAFETY: `it` is non-null, and the caller owns it for the duration.
    let item = unsafe { &*it };

    // The application callback, taken once: every arm below either calls it or ignores
    // it, and an item with no `ASN1_AUX` has none.
    let aux = item.funcs.cast::<Asn1Aux>();
    let asn1_cb = if aux.is_null() {
        None
    } else {
        // SAFETY: `aux` is the item's own `ASN1_AUX`.
        unsafe { (*aux).asn1_cb }
    };

    match item.itype {
        ASN1_ITYPE_EXTERN => {
            let ef = item.funcs.cast::<Asn1ExternFuncs>();
            if !ef.is_null() {
                // SAFETY: `ef` is the item's own `ASN1_EXTERN_FUNCS`.
                let ef = unsafe { &*ef };
                if let Some(new_ex) = ef.asn1_ex_new_ex {
                    // SAFETY: the hook is the caller's, with the authority's
                    // signature.
                    if unsafe { new_ex(pval, it, libctx, propq) } == 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::TASN_NEW_162) };
                        return 0;
                    }
                } else if let Some(new) = ef.asn1_ex_new {
                    // SAFETY: as above.
                    if unsafe { new(pval, it) } == 0 {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::TASN_NEW_162) };
                        return 0;
                    }
                }
            }
            1
        }

        ASN1_ITYPE_PRIMITIVE => {
            if !item.templates.is_null() {
                // SAFETY: the caller's contract; `item.templates` is the item's own
                // template.
                if unsafe { template_new(pval, item.templates, libctx, propq) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_162) };
                    return 0;
                }
            } else {
                // SAFETY: the caller's contract.
                if unsafe { primitive_new(pval, it, embed) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_162) };
                    return 0;
                }
            }
            1
        }

        ASN1_ITYPE_MSTRING => {
            // SAFETY: the caller's contract.
            if unsafe { primitive_new(pval, it, embed) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_NEW_162) };
                return 0;
            }
            1
        }

        ASN1_ITYPE_CHOICE => {
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's, with the authority's signature.
                let i = unsafe { cb(ASN1_OP_NEW_PRE, pval, it, core::ptr::null_mut()) };
                if i == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_168) };
                    return 0;
                }
                if i == 2 {
                    // "Handled"; the callback has done the work.
                    return 1;
                }
            }
            if embed != 0 {
                // SAFETY: the caller's contract: `*pval` is this call's storage, of
                // `item.size` bytes.
                unsafe { core::ptr::write_bytes(*pval, 0, item.size.max(0) as usize) };
            } else {
                // SAFETY: the allocation is `item.size` bytes.
                let fresh = CRYPTO_zalloc(item.size.max(0) as usize, FILE.as_ptr(), LINE);
                // SAFETY: the caller's slot is writable.
                unsafe { *pval = fresh };
                if fresh.is_null() {
                    return 0;
                }
            }
            // A CHOICE with no alternative selected is -1, and that is what makes
            // `ASN1_item_new` on a CHOICE a value a caller can inspect rather than one
            // that claims an alternative it never decoded.
            // SAFETY: `*pval` is a live value of the item's type.
            unsafe { utl::set_choice_selector(pval, -1, item) };
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_NEW_POST, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: `*pval` is live and this call owns it.
                    unsafe { item_embed_free(pval, it, embed) };
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_168) };
                    return 0;
                }
            }
            1
        }

        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's, with the authority's signature.
                let i = unsafe { cb(ASN1_OP_NEW_PRE, pval, it, core::ptr::null_mut()) };
                if i == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_168) };
                    return 0;
                }
                if i == 2 {
                    return 1;
                }
            }
            if embed != 0 {
                // SAFETY: the caller's contract: `*pval` is this call's storage, of
                // `item.size` bytes.
                unsafe { core::ptr::write_bytes(*pval, 0, item.size.max(0) as usize) };
            } else {
                // SAFETY: the allocation is `item.size` bytes.
                let fresh = CRYPTO_zalloc(item.size.max(0) as usize, FILE.as_ptr(), LINE);
                // SAFETY: the caller's slot is writable.
                unsafe { *pval = fresh };
                if fresh.is_null() {
                    return 0;
                }
            }
            // The reference count, if the item carries one. A negative answer is a
            // failure and must not leave the value allocated when this call owns it.
            // SAFETY: `*pval` is a live value of the item's type.
            if unsafe { utl::do_lock(pval, 0, item) } < 0 {
                if embed == 0 {
                    // SAFETY: `*pval` came from this allocator and is not yet published.
                    unsafe { crate::runtime::mem::CRYPTO_free(*pval, FILE.as_ptr(), LINE) };
                    // SAFETY: the caller's slot is writable.
                    unsafe { *pval = core::ptr::null_mut() };
                }
                return 0;
            }
            // SAFETY: `*pval` is a live value of the item's type.
            unsafe { utl::enc_init(pval, item) };
            let mut i: c_long = 0;
            let mut tt = item.templates;
            while i < item.tcount {
                if tt.is_null() {
                    break;
                }
                // SAFETY: `tt` is inside the item's own template array for `tcount`
                // entries.
                let t = unsafe { &*tt };
                // SAFETY: `*pval` is live and `t.offset` is a field of it.
                let field = unsafe { utl::get_field_ptr(pval, t) };
                // SAFETY: the caller's contract, for the field's own item.
                if unsafe { template_new(field, tt, libctx, propq) } == 0 {
                    // SAFETY: `*pval` is live and this call owns it.
                    unsafe { item_embed_free(pval, it, embed) };
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_162) };
                    return 0;
                }
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }
            if let Some(cb) = asn1_cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_NEW_POST, pval, it, core::ptr::null_mut()) } == 0 {
                    // SAFETY: `*pval` is live and this call owns it.
                    unsafe { item_embed_free(pval, it, embed) };
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::TASN_NEW_168) };
                    return 0;
                }
            }
            1
        }

        _ => 0,
    }
}

/// `asn1_item_clear` — return a value to the state `ASN1_item_new` would produce,
/// releasing nothing.
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live value of `it`'s type.
pub(crate) unsafe fn item_clear(pval: *mut *mut c_void, it: &Asn1Item) {
    match it.itype {
        ASN1_ITYPE_EXTERN => {
            let ef = it.funcs.cast::<Asn1ExternFuncs>();
            if !ef.is_null() {
                // SAFETY: `ef` is the item's own `ASN1_EXTERN_FUNCS`.
                if let Some(clear) = unsafe { (*ef).asn1_ex_clear } {
                    // SAFETY: the hook is the caller's.
                    unsafe { clear(pval, it) };
                    return;
                }
            }
            // SAFETY: the caller's slot is writable.
            unsafe { *pval = core::ptr::null_mut() };
        }
        ASN1_ITYPE_PRIMITIVE => {
            if !it.templates.is_null() {
                // SAFETY: the caller's contract; the template is the item's own.
                unsafe { template_clear(pval, it.templates) };
            } else {
                // SAFETY: the caller's contract.
                unsafe { primitive_clear(pval, it) };
            }
        }
        ASN1_ITYPE_MSTRING => {
            // SAFETY: the caller's contract.
            unsafe { primitive_clear(pval, it) };
        }
        _ => {
            // SAFETY: the caller's slot is writable.
            unsafe { *pval = core::ptr::null_mut() };
        }
    }
}

/// `asn1_template_new` — allocate one field through its template.
///
/// # Safety
///
/// `pval` must be a live field slot of the enclosing value; `tt` must be a live
/// template. When `ASN1_TFLG_EMBED` is set, the field itself is the value's storage.
pub(crate) unsafe fn template_new(
    pval: *mut *mut c_void,
    tt: *const Asn1Template,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if tt.is_null() {
        return 0;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    let embed = c_int::from(t.flags & ASN1_TFLG_EMBED != 0);
    // For an embedded field the value *is* the field, so the item machinery is handed
    // the address of a pointer to the field rather than the field's own slot. That
    // indirection is the authority's, and it is what makes `embed` propagate.
    // SAFETY: the caller's contract covers this slot.
    let mut tval: *mut c_void = unsafe { *pval };
    let pval = if embed != 0 {
        // SAFETY: `pval` is a live slot; `tval` is this frame's copy.
        unsafe { pval.write(tval) };
        tval = pval as *mut c_void;
        &mut tval as *mut *mut c_void
    } else {
        pval
    };

    if t.flags & ASN1_TFLG_OPTIONAL != 0 {
        // An optional field is left absent rather than allocated, so a caller can tell
        // "not present" from "present and empty".
        // SAFETY: `pval` is a live slot.
        unsafe { template_clear(pval, tt) };
        return 1;
    }
    // An `ANY DEFINED BY` field has no type until the selector is decoded.
    if t.flags & ASN1_TFLG_ADB_MASK != 0 {
        // SAFETY: `pval` is a live slot.
        unsafe { *pval = core::ptr::null_mut() };
        return 1;
    }
    // `SET OF` and `SEQUENCE OF` are stacks, and an empty stack is a value.
    if t.flags & ASN1_TFLG_SK_MASK != 0 {
        let sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_NEW_231) };
            return 0;
        }
        // SAFETY: `pval` is a live slot.
        unsafe { *pval = sk.cast::<c_void>() };
        return 1;
    }
    // SAFETY: `t.item` is the field's `ASN1_ITEM_EXP`, and the caller's contract covers
    // the item it answers.
    let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
    // SAFETY: as above.
    unsafe { item_embed_new(pval, sub, embed, libctx, propq) }
}

/// `asn1_template_clear` — return one field to its empty state.
///
/// # Safety
///
/// `pval` must be a live field slot of the enclosing value; `tt` must be a live
/// template.
pub(crate) unsafe fn template_clear(pval: *mut *mut c_void, tt: *const Asn1Template) {
    if tt.is_null() {
        return;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    if t.flags & (ASN1_TFLG_ADB_MASK | ASN1_TFLG_SK_MASK) != 0 {
        // Nothing was allocated for either, so there is nothing to clear but the slot.
        // SAFETY: `pval` is a live slot.
        unsafe { *pval = core::ptr::null_mut() };
        return;
    }
    // SAFETY: `t.item` is the field's `ASN1_ITEM_EXP`.
    let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
    if sub.is_null() {
        // SAFETY: `pval` is a live slot.
        unsafe { *pval = core::ptr::null_mut() };
        return;
    }
    // SAFETY: the caller's contract covers the field's own item.
    let sub_ref = unsafe { &*sub };
    // SAFETY: as above.
    unsafe { item_clear(pval, sub_ref) };
}

/// `asn1_primitive_new` — allocate a primitive, or initialise one in place.
///
/// The `BOOLEAN` and `NULL` arms store their values **in the slot**: a `BOOLEAN` is the
/// item's `size` cast to an `int`, and a `NULL` is the sentinel `1`. The `ANY` arm is the
/// only one that allocates an `ASN1_TYPE`, and it is the only place an `ASN1_TYPE` is
/// created before Phase 5.7 lands the rest of that type's surface.
///
/// # Safety
///
/// `pval` must be a live slot; `it` must be a live item. When `embed` is non-zero,
/// `*pval` must point at storage this call may `memset`.
unsafe fn primitive_new(pval: *mut *mut c_void, it: *const Asn1Item, embed: c_int) -> c_int {
    if it.is_null() {
        return 0;
    }
    // SAFETY: `it` is non-null.
    let item = unsafe { &*it };

    // A caller's hooks win over the type dispatch, and `embed` selects which of them:
    // in place it is a clear, otherwise a new.
    let pf = item.funcs.cast::<Asn1PrimitiveFuncs>();
    if !pf.is_null() {
        // SAFETY: for a PRIMITIVE item the authority's own cast reads `funcs` as an
        // `ASN1_PRIMITIVE_FUNCS *`.
        let pf = unsafe { &*pf };
        if embed != 0 {
            if let Some(clear) = pf.prim_clear {
                // SAFETY: the hook is the caller's.
                unsafe { clear(pval, it) };
                return 1;
            }
        } else if let Some(new) = pf.prim_new {
            // SAFETY: as above.
            return unsafe { new(pval, it) };
        }
    }

    let utype = if item.itype == ASN1_ITYPE_MSTRING {
        // A multi-string's type is not known until a decode supplies it, and `-1` is
        // how the item says so.
        V_ASN1_UNDEF
    } else {
        item.utype as c_int
    };

    match utype {
        V_ASN1_OBJECT => {
            // A fresh object is the shared `NID_undef` entry rather than an allocation,
            // so freeing one must not release it.
            // SAFETY: the slot is writable and `OBJ_nid2obj` answers a live object.
            unsafe { *pval = OBJ_nid2obj(NID_UNDEF).cast::<c_void>() };
        }
        V_ASN1_BOOLEAN => {
            // The value is the slot's own first four bytes, and the initial value is
            // the item's `size` — its default.
            // SAFETY: `pval` is at least `size_of::<c_int>()` bytes wide.
            unsafe { *(pval as *mut c_int) = item.size as c_int };
        }
        V_ASN1_NULL => {
            // The sentinel, which `ASN1_NULL_free` never dereferences. The clippy lint
            // wants `ptr::dangling_mut`, whose address comes from the type's alignment
            // rather than being 1; the authority's value is literally
            // `(ASN1_VALUE *)1` and `ASN1_NULL_new` hands the same value out, so the
            // lint's suggestion would be a different observable value.
            #[allow(clippy::manual_dangling_ptr)]
            // SAFETY: the slot is writable.
            unsafe {
                *pval = 1 as *mut c_void
            };
        }
        V_ASN1_ANY => {
            // `OPENSSL_malloc` rather than `zalloc`: the authority sets both fields
            // explicitly, and the union's other bytes are not part of the value.
            // SAFETY: the allocation is one `ASN1_TYPE`.
            let typ = CRYPTO_malloc(core::mem::size_of::<Asn1Type>(), FILE.as_ptr(), LINE)
                as *mut Asn1Type;
            if typ.is_null() {
                return 0;
            }
            // SAFETY: `typ` is a fresh `ASN1_TYPE`.
            unsafe {
                (*typ).value.ptr = core::ptr::null_mut();
                (*typ).type_ = V_ASN1_UNDEF;
            }
            // SAFETY: the slot is writable.
            unsafe { *pval = typ.cast::<c_void>() };
        }
        _ => {
            // Every other primitive is an `ASN1_STRING` whose `type` is this `utype`.
            let str_: *mut Asn1String;
            if embed != 0 {
                // The field itself is the string, so it is zeroed and the embed flag is
                // set — which is what stops a free releasing the field.
                // SAFETY: the caller's contract: `*pval` is storage of
                // `size_of::<Asn1String>()` bytes.
                str_ = unsafe { *pval }.cast::<Asn1String>();
                // SAFETY: as above.
                unsafe {
                    core::ptr::write_bytes(
                        str_.cast::<u8>(),
                        0,
                        core::mem::size_of::<Asn1String>(),
                    );
                    (*str_).type_ = utype;
                    (*str_).flags = ASN1_STRING_FLAG_EMBED;
                }
            } else {
                str_ = ASN1_STRING_type_new(utype);
                // SAFETY: the slot is writable.
                unsafe { *pval = str_.cast::<c_void>() };
            }
            if item.itype == ASN1_ITYPE_MSTRING && !str_.is_null() {
                // SAFETY: `str_` is live; the flag is what tells a later decode that
                // the type is not yet known.
                unsafe { (*str_).flags |= ASN1_STRING_FLAG_MSTRING };
            }
        }
    }
    // SAFETY: the slot is readable.
    c_int::from(!unsafe { *pval }.is_null())
}

/// `asn1_primitive_clear` — return a primitive to its empty state.
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live value of `it`'s type.
unsafe fn primitive_clear(pval: *mut *mut c_void, it: &Asn1Item) {
    if !it.funcs.is_null() {
        // SAFETY: for a PRIMITIVE item `funcs` is an `ASN1_PRIMITIVE_FUNCS *`.
        let pf = unsafe { &*it.funcs.cast::<Asn1PrimitiveFuncs>() };
        if let Some(clear) = pf.prim_clear {
            // SAFETY: the hook is the caller's.
            unsafe { clear(pval, it) };
        } else {
            // SAFETY: the slot is writable.
            unsafe { *pval = core::ptr::null_mut() };
        }
        return;
    }
    let utype = if it.itype == ASN1_ITYPE_MSTRING {
        V_ASN1_UNDEF
    } else {
        it.utype as c_int
    };
    if utype == V_ASN1_BOOLEAN {
        // SAFETY: the slot is at least `size_of::<c_int>()` bytes wide, and the clear
        // value is the item's default.
        unsafe { *(pval as *mut c_int) = it.size as c_int };
    } else {
        // SAFETY: the slot is writable.
        unsafe { *pval = core::ptr::null_mut() };
    }
}
