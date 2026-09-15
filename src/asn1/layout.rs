//! Phase 5 — the ASN.1 type layouts and the constants the codec reads.
//!
//! **Structures a caller can see.** `ASN1_STRING`, `ASN1_TYPE`, `ASN1_ITEM`,
//! `ASN1_TEMPLATE`, `ASN1_ENCODING` and `ASN1_STRING_TABLE` are declared in
//! installed headers (`asn1.h`, `asn1t.h`), so their field order, sizes, alignment
//! and offsets are the ABI. `ASN1_ITEM` and `ASN1_TEMPLATE` are stronger than
//! that: a consumer builds them itself with the `ASN1_SEQUENCE` family of macros
//! and hands the result to `ASN1_item_i2d`, so this stratum interprets the
//! authority's own templates rather than merely agreeing with a header.
//!
//! **Structures the caller cannot see.** `ASN1_OBJECT`, `ASN1_PCTX` and
//! `ASN1_SCTX` are opaque in `types.h`. `ASN1_OBJECT` is nevertheless laid out
//! exactly like the authority's internal `struct asn1_object_st`, because
//! `OBJ_nid2obj` hands callers a pointer straight into a static array and
//! `OBJ_length`/`OBJ_get0_data` expose two of its fields; that structure lives in
//! [`crate::runtime::obj`], where the object database is. `ASN1_PCTX` and
//! `ASN1_SCTX` are genuinely ours, and are the only two types here whose
//! representation is a free choice.
//!
//! Every constant here is materialised: `ABI-CONSTANTS` compiles the authority's
//! header expression and this one and compares the values, so a transcription
//! error fails a court rather than silently reinterpreting a caller's structure.
//!
//! **Why the dead-code lint is off for this module.** It is a projection, so the
//! members it does not yet use are not dead code — they are the part of the
//! contract the later subphases read (`docs/PHASE-5-SUBPHASES.md`). The
//! `ASN1_ITYPE_*`, `ASN1_TFLG_*`, `ASN1_AFLG_*` and `ASN1_OP_*` sets exist for the
//! template machinery in 5.4 and the printer in 5.6. Deleting them to satisfy the
//! lint would delete the record that they were read from the authority, and
//! re-adding them one subphase at a time would churn the file repeatedly.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};

use crate::runtime::bio::Bio;

/// `ASN1_STRING` — the one string type every other string type is.
///
/// ```text
/// struct asn1_string_st {
///     int length;
///     int type;
///     unsigned char *data;   /* length bytes, which may include NULs */
///     long flags;            /* type-dependent; BIT_STRING's unused bits */
/// };
/// ```
///
/// `data` is owned by the structure and released by `ASN1_STRING_free`, except
/// when [`ASN1_STRING_FLAG_EMBED`] is set — that flag means `data` points into
/// memory the structure does not own, and it is how the authority avoids a copy in
/// several places.
#[repr(C)]
pub struct Asn1String {
    /// Number of bytes at `data`. Never negative.
    pub(crate) length: c_int,
    /// `V_ASN1_*`, or one of the `V_ASN1_NEG_*` values for the signed types.
    pub(crate) type_: c_int,
    /// The content octets, or null when `length` is 0.
    pub(crate) data: *mut c_uchar,
    /// `ASN1_STRING_FLAG_*` plus, for a bit string, the unused-bit count in the
    /// low three bits.
    pub(crate) flags: c_long,
}

/// `ASN1_TYPE` — the type/value pair `ANY` is.
///
/// ```text
/// struct asn1_type_st {
///     int type;
///     union {
///         char *ptr;
///         ASN1_BOOLEAN boolean;   /* an int */
///         ASN1_STRING *asn1_string;
///         ... one member per string type ...
///         ASN1_OBJECT *object;
///         ASN1_VALUE *asn1_value;
///     } value;
/// };
/// ```
///
/// Every union member is a pointer except `boolean`, so the union is eight bytes
/// and `boolean` occupies the *first four* of them. Both are modelled so a
/// `boolean` round-trips through the same memory a pointer would.
#[repr(C)]
pub struct Asn1Type {
    /// `V_ASN1_*`; `V_ASN1_NULL` with a null `value` is the valid null.
    pub(crate) type_: c_int,
    /// The payload, read through [`Asn1TypeValue`].
    pub(crate) value: Asn1TypeValue,
}

/// The `ASN1_TYPE` union. See [`Asn1Type`].
#[repr(C)]
pub union Asn1TypeValue {
    /// Any of the pointer members of the authority's union.
    pub(crate) ptr: *mut c_void,
    /// The `ASN1_BOOLEAN` member, an `int` in the union's first four bytes.
    pub(crate) boolean: c_int,
}

/// `ASN1_ENCODING` — a received encoding kept beside a decoded structure.
///
/// `ASN1_AFLG_ENCODING` makes the template machinery store the bytes it was given
/// here, so that re-encoding a structure that has not changed can return the
/// original bytes rather than a re-derivation. That is how the authority preserves
/// a signature over a non-canonical encoding.
#[repr(C)]
pub struct Asn1Encoding {
    /// The received bytes, or null.
    pub(crate) enc: *mut c_uchar,
    /// Their length.
    pub(crate) len: c_long,
    /// Non-zero once the structure is modified and `enc` is stale.
    pub(crate) modified: c_int,
}

/// `ASN1_STRING_TABLE` — one row of the string-type policy table.
///
/// `ASN1_STRING_TABLE_get` answers a pointer to a row keyed by NID and callers
/// read `minsize`/`maxsize`/`mask`/`flags` through it, so the row is part of the
/// contract.
#[repr(C)]
pub struct Asn1StringTable {
    /// The NID this row governs.
    pub(crate) nid: c_int,
    /// Minimum length, or -1 for "no minimum".
    pub(crate) minsize: c_long,
    /// Maximum length, or -1 for "no maximum".
    pub(crate) maxsize: c_long,
    /// `B_ASN1_*` mask of acceptable string types.
    pub(crate) mask: c_ulong,
    /// `STABLE_FLAGS_*` — ownership of the row.
    pub(crate) flags: c_ulong,
}

/// `ASN1_TEMPLATE` — one field of a `SEQUENCE`/`CHOICE` template.
///
/// `item` is declared as a pointer to `ASN1_ITEM_EXP`, which is
/// `const ASN1_ITEM *ASN1_ITEM_EXP(void)` — a *function* returning the item. For
/// an `ANY DEFINED BY` field the same slot holds an `ASN1_ADB` cast to the same
/// type, and the `ASN1_TFLG_ADB_*` bits in `flags` say which reading is correct.
/// It is modelled untyped for that reason.
#[repr(C)]
pub struct Asn1Template {
    /// `ASN1_TFLG_*`.
    pub(crate) flags: c_ulong,
    /// The tag number, meaningful only when `ASN1_TFLG_TAG_MASK` is set.
    pub(crate) tag: c_long,
    /// `offsetof(stname, field)`.
    pub(crate) offset: c_ulong,
    /// The field's name, or null.
    pub(crate) field_name: *const c_char,
    /// The field's `ASN1_ITEM_EXP`, or an `ASN1_ADB`.
    pub(crate) item: *mut c_void,
}

/// `ASN1_ADB` — an `ANY DEFINED BY` table.
#[repr(C)]
pub struct Asn1Adb {
    /// `ASN1_TFLG_ADB_OID` or `ASN1_TFLG_ADB_INT`.
    pub(crate) flags: c_ulong,
    /// `offsetof` of the selector field in the enclosing structure.
    pub(crate) offset: c_ulong,
    /// Optional application selector, called as `adb_cb(&mut sel)`.
    pub(crate) adb_cb: Option<unsafe extern "C" fn(*mut c_long) -> c_int>,
    /// The table of (selector value, template) rows.
    pub(crate) tbl: *const Asn1AdbTable,
    /// Number of rows in `tbl`.
    pub(crate) tblcount: c_long,
    /// Used when no row matches.
    pub(crate) default_tt: *const Asn1Template,
    /// Used when the selector itself is absent.
    pub(crate) null_tt: *const Asn1Template,
}

/// One row of an [`Asn1Adb`].
#[repr(C)]
pub struct Asn1AdbTable {
    /// The OID NID or integer this row matches.
    pub(crate) value: c_long,
    /// The template to use when it does.
    pub(crate) tt: Asn1Template,
}

/// `ASN1_ITEM` — a type's template.
///
/// ```text
/// struct ASN1_ITEM_st {
///     char itype;                      /* ASN1_ITYPE_* */
///     long utype;                      /* the underlying V_ASN1_* */
///     const ASN1_TEMPLATE *templates;   /* fields, for SEQUENCE and CHOICE */
///     long tcount;                     /* how many */
///     const void *funcs;               /* AUX*, PRIMITIVE_FUNCS* or EXTERN_FUNCS* */
///     long size;                       /* sizeof the structure, usually */
///     const char *sname;               /* the type's name */
/// };
/// ```
///
/// The most observable structure in the stratum: `X_it()` returns a pointer to a
/// *function-local static*, so two calls compare equal, the fields are readable
/// through that pointer, and `ASN1_item_i2d` on a caller-built template of this
/// exact shape is how a third-party structure gets DER-encoded.
#[repr(C)]
pub struct Asn1Item {
    /// `ASN1_ITYPE_*`.
    pub(crate) itype: c_char,
    /// The underlying `V_ASN1_*`, or a mask of them for `MSTRING`.
    pub(crate) utype: c_long,
    /// The template array, for `SEQUENCE` and `CHOICE`.
    pub(crate) templates: *const Asn1Template,
    /// Number of entries in `templates`.
    pub(crate) tcount: c_long,
    /// `ASN1_AUX *`, `ASN1_PRIMITIVE_FUNCS *` or `ASN1_EXTERN_FUNCS *`.
    pub(crate) funcs: *const c_void,
    /// `sizeof` the described structure; the selector offset for `CHOICE`.
    pub(crate) size: c_long,
    /// The item's name, as the constructing macro spelled it.
    pub(crate) sname: *const c_char,
}

/// `ASN1_AUX` — the optional behaviour block an `ASN1_ITEM` may carry.
#[repr(C)]
pub struct Asn1Aux {
    /// Application data, handed to the callback.
    pub(crate) app_data: *mut c_void,
    /// `ASN1_AFLG_*`.
    pub(crate) flags: c_int,
    /// Offset of the reference count, for `ASN1_AFLG_REFCOUNT`.
    pub(crate) ref_offset: c_int,
    /// Offset of the lock protecting it.
    pub(crate) ref_lock: c_int,
    /// The informational callback, called around each operation.
    pub(crate) asn1_cb: Option<Asn1AuxCb>,
    /// Offset of the `ASN1_ENCODING`, for `ASN1_AFLG_ENCODING`.
    pub(crate) enc_offset: c_int,
    /// The const-correct variant, for the non-modifying operations.
    pub(crate) asn1_const_cb: Option<Asn1AuxConstCb>,
}

/// `ASN1_aux_cb` — `int (*)(int, ASN1_VALUE **, const ASN1_ITEM *, void *)`.
pub type Asn1AuxCb =
    unsafe extern "C" fn(c_int, *mut *mut c_void, *const Asn1Item, *mut c_void) -> c_int;

/// `ASN1_aux_const_cb` — the same, with a `const ASN1_VALUE **`.
pub type Asn1AuxConstCb =
    unsafe extern "C" fn(c_int, *const *const c_void, *const Asn1Item, *mut c_void) -> c_int;

/// `ASN1_PRIMITIVE_FUNCS` — the hooks a primitive type may supply.
///
/// A caller can supply its own, and an `ASN1_ITYPE_PRIMITIVE` item with non-null
/// `funcs` must dispatch to it; that dispatch is part of the contract even though
/// this crate's own primitive items leave the slot null.
#[repr(C)]
pub struct Asn1PrimitiveFuncs {
    /// Application data.
    pub(crate) app_data: *mut c_void,
    /// `ASN1_PFLG_*`; currently unused and zero.
    pub(crate) flags: c_ulong,
    /// Allocate the primitive.
    pub(crate) prim_new: Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item) -> c_int>,
    /// Free it.
    pub(crate) prim_free: Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item)>,
    /// Clear it back to empty.
    pub(crate) prim_clear: Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item)>,
    /// Content octets to value.
    pub(crate) prim_c2i: Option<
        unsafe extern "C" fn(
            *mut *mut c_void,
            *const c_uchar,
            c_int,
            c_int,
            *mut c_char,
            *const Asn1Item,
        ) -> c_int,
    >,
    /// Value to content octets.
    pub(crate) prim_i2c: Option<
        unsafe extern "C" fn(
            *const *const c_void,
            *mut c_uchar,
            *mut c_int,
            *const Asn1Item,
        ) -> c_int,
    >,
    /// Print it.
    pub(crate) prim_print: Option<
        unsafe extern "C" fn(
            *mut Bio,
            *const *const c_void,
            *const Asn1Item,
            c_int,
            *const Asn1Pctx,
        ) -> c_int,
    >,
}

/// `ASN1_EXTERN_FUNCS` — the hooks of an `ASN1_ITYPE_EXTERN` item.
#[repr(C)]
pub struct Asn1ExternFuncs {
    /// Application data.
    pub(crate) app_data: *mut c_void,
    /// Allocate.
    pub(crate) asn1_ex_new:
        Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item) -> c_int>,
    /// Free.
    pub(crate) asn1_ex_free: Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item)>,
    /// Clear.
    pub(crate) asn1_ex_clear: Option<unsafe extern "C" fn(*mut *mut c_void, *const Asn1Item)>,
    /// Decode.
    pub(crate) asn1_ex_d2i: Option<
        unsafe extern "C" fn(
            *mut *mut c_void,
            *mut *const c_uchar,
            c_long,
            *const Asn1Item,
            c_int,
            c_int,
            c_char,
            *mut Asn1Tlc,
        ) -> c_int,
    >,
    /// Encode.
    pub(crate) asn1_ex_i2d: Option<
        unsafe extern "C" fn(
            *const *const c_void,
            *mut *mut c_uchar,
            *const Asn1Item,
            c_int,
            c_int,
        ) -> c_int,
    >,
    /// Print.
    pub(crate) asn1_ex_print: Option<
        unsafe extern "C" fn(
            *mut Bio,
            *const *const c_void,
            c_int,
            *const c_char,
            *const Asn1Pctx,
        ) -> c_int,
    >,
    /// Allocate with a library context.
    pub(crate) asn1_ex_new_ex: Option<
        unsafe extern "C" fn(
            *mut *mut c_void,
            *const Asn1Item,
            *mut c_void,
            *const c_char,
        ) -> c_int,
    >,
    /// Decode with a library context.
    #[allow(clippy::type_complexity)] // mirrors the authority's typedef exactly
    pub(crate) asn1_ex_d2i_ex: Option<
        unsafe extern "C" fn(
            *mut *mut c_void,
            *mut *const c_uchar,
            c_long,
            *const Asn1Item,
            c_int,
            c_int,
            c_char,
            *mut Asn1Tlc,
            *mut c_void,
            *const c_char,
        ) -> c_int,
    >,
}

/// `ASN1_TLC` — the tag/length cache a `CHOICE` decode keeps.
///
/// `CHOICE` must look at the next header to decide which alternative it is and then
/// hand the same bytes to that alternative; rather than parse the header twice, the
/// decoder caches it here. Public because the `ASN1_ex_d2i` signature names it.
#[repr(C)]
pub struct Asn1Tlc {
    /// Non-zero when the cached fields are valid.
    pub(crate) valid: c_char,
    /// The header's return class, as `ASN1_get_object` reports it.
    pub(crate) ret: c_int,
    /// The content length.
    pub(crate) plen: c_long,
    /// The tag number.
    pub(crate) ptag: c_int,
    /// The tag class, as `ASN1_get_object` reports it.
    pub(crate) pclass: c_int,
    /// The whole header's length.
    pub(crate) hdrlen: c_int,
}

/// `ASN1_PCTX` — the printing options `ASN1_item_print` takes.
///
/// Opaque in the installed headers, so this representation is ours; the five
/// accessors in `asn1.h` pair with the five fields.
#[repr(C)]
pub struct Asn1Pctx {
    /// `ASN1_PCTX_FLAGS_*`.
    pub(crate) flags: c_ulong,
    /// Flags restricting name lookup.
    pub(crate) nm_flags: c_ulong,
    /// Flags restricting certificate printing.
    pub(crate) cert_flags: c_ulong,
    /// Flags restricting OID printing.
    pub(crate) oid_flags: c_ulong,
    /// Flags restricting string printing.
    pub(crate) str_flags: c_ulong,
}

/// `ASN1_SCTX` — the state a streaming decode carries.
///
/// Opaque in the installed headers, so this representation is ours. An `ASN1_AUX`
/// callback receives one of these through its `exarg` argument, which is why the
/// accessors exist.
#[repr(C)]
pub struct Asn1Sctx {
    /// The item being streamed.
    pub(crate) it: *const Asn1Item,
    /// The template governing the field currently being processed.
    pub(crate) template: *const Asn1Template,
    /// Where the stream is read from or written to.
    pub(crate) bp: *mut Bio,
    /// The streaming callback.
    pub(crate) cb: Option<unsafe extern "C" fn(*mut Asn1Sctx) -> c_int>,
    /// `ASN1_SCTX_*` flags.
    pub(crate) flags: c_ulong,
    /// Application data.
    pub(crate) app_data: *mut c_void,
    /// Diagnostic name of the field being processed.
    pub(crate) name: *const c_char,
}

// ---------------------------------------------------------------------------
// `ASN1_ITYPE_*` — how an `ASN1_ITEM` is interpreted.
// ---------------------------------------------------------------------------

/// A primitive type: one of the `ASN1_STRING` family, or whatever `funcs` says.
pub(crate) const ASN1_ITYPE_PRIMITIVE: c_char = 0x0;
/// A `SEQUENCE`: `templates` is the field list.
pub(crate) const ASN1_ITYPE_SEQUENCE: c_char = 0x1;
/// A `CHOICE`: `templates` is the alternative list and `size` the selector offset.
pub(crate) const ASN1_ITYPE_CHOICE: c_char = 0x2;
/// An extern type: `funcs` does everything.
pub(crate) const ASN1_ITYPE_EXTERN: c_char = 0x4;
/// A `CHOICE` of character strings in one `ASN1_STRING`; `utype` is a `B_ASN1_*`
/// mask.
pub(crate) const ASN1_ITYPE_MSTRING: c_char = 0x5;
/// A `SEQUENCE` encoded with indefinite length when asked.
pub(crate) const ASN1_ITYPE_NDEF_SEQUENCE: c_char = 0x6;

// ---------------------------------------------------------------------------
// `ASN1_TFLG_*` — per-field template flags.
// ---------------------------------------------------------------------------

/// The field may be absent.
pub(crate) const ASN1_TFLG_OPTIONAL: c_ulong = 0x1;
/// The field is a `SET OF`.
pub(crate) const ASN1_TFLG_SET_OF: c_ulong = 0x1 << 1;
/// The field is a `SEQUENCE OF`.
pub(crate) const ASN1_TFLG_SEQUENCE_OF: c_ulong = 0x2 << 1;
/// Mask of the two "of" kinds.
pub(crate) const ASN1_TFLG_SK_MASK: c_ulong = 0x3 << 1;
/// Implicit tagging: the underlying tag is replaced.
pub(crate) const ASN1_TFLG_IMPTAG: c_ulong = 0x1 << 3;
/// Explicit tagging: the underlying type is wrapped in a constructed one.
pub(crate) const ASN1_TFLG_EXPTAG: c_ulong = 0x2 << 3;
/// Mask of the two tagging kinds.
pub(crate) const ASN1_TFLG_TAG_MASK: c_ulong = 0x3 << 3;
/// Universal tag class.
pub(crate) const ASN1_TFLG_UNIVERSAL: c_ulong = 0x0 << 6;
/// Application tag class.
pub(crate) const ASN1_TFLG_APPLICATION: c_ulong = 0x1 << 6;
/// Context-specific tag class.
pub(crate) const ASN1_TFLG_CONTEXT: c_ulong = 0x2 << 6;
/// Private tag class.
pub(crate) const ASN1_TFLG_PRIVATE: c_ulong = 0x3 << 6;
/// Mask of the tag class bits.
pub(crate) const ASN1_TFLG_TAG_CLASS: c_ulong = 0x3 << 6;
/// Mask of the `ANY DEFINED BY` bits.
pub(crate) const ASN1_TFLG_ADB_MASK: c_ulong = 0x3 << 8;
/// The selector is an OID; `item` is an `ASN1_ADB`.
pub(crate) const ASN1_TFLG_ADB_OID: c_ulong = 0x1 << 8;
/// The selector is an integer; `item` is an `ASN1_ADB`.
pub(crate) const ASN1_TFLG_ADB_INT: c_ulong = 0x1 << 9;
/// Encode with indefinite length when required.
pub(crate) const ASN1_TFLG_NDEF: c_ulong = 0x1 << 11;
/// The field is embedded in the structure rather than pointed at.
pub(crate) const ASN1_TFLG_EMBED: c_ulong = 0x1 << 12;
/// Context-specific implicit tagging, as the macros spell it.
pub(crate) const ASN1_TFLG_IMPLICIT: c_ulong = ASN1_TFLG_IMPTAG | ASN1_TFLG_CONTEXT;
/// Context-specific explicit tagging, as the macros spell it.
pub(crate) const ASN1_TFLG_EXPLICIT: c_ulong = ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT;

// ---------------------------------------------------------------------------
// `ASN1_AFLG_*` — behaviour bits in `ASN1_AUX.flags`.
// ---------------------------------------------------------------------------

/// Maintain a reference count at `ref_offset`.
pub(crate) const ASN1_AFLG_REFCOUNT: c_int = 1;
/// Remember the received encoding at `enc_offset`.
pub(crate) const ASN1_AFLG_ENCODING: c_int = 2;
/// The type is broken in a way the callback must be told about.
pub(crate) const ASN1_AFLG_BROKEN: c_int = 4;
/// Use `asn1_const_cb` for the non-modifying operations.
pub(crate) const ASN1_AFLG_CONST_CB: c_int = 8;

// ---------------------------------------------------------------------------
// `ASN1_OP_*` — the operations an `ASN1_AUX` callback is told about.
// ---------------------------------------------------------------------------

/// Before a new value is created.
pub(crate) const ASN1_OP_NEW_PRE: c_int = 0;
/// After one is.
pub(crate) const ASN1_OP_NEW_POST: c_int = 1;
/// Before a value is freed.
pub(crate) const ASN1_OP_FREE_PRE: c_int = 2;
/// After one is.
pub(crate) const ASN1_OP_FREE_POST: c_int = 3;
/// Before decoding.
pub(crate) const ASN1_OP_D2I_PRE: c_int = 4;
/// After decoding.
pub(crate) const ASN1_OP_D2I_POST: c_int = 5;
/// Before encoding.
pub(crate) const ASN1_OP_I2D_PRE: c_int = 6;
/// After encoding.
pub(crate) const ASN1_OP_I2D_POST: c_int = 7;
/// Before printing.
pub(crate) const ASN1_OP_PRINT_PRE: c_int = 8;
/// After printing.
pub(crate) const ASN1_OP_PRINT_POST: c_int = 9;
/// Before a streaming decode.
pub(crate) const ASN1_OP_STREAM_PRE: c_int = 10;
/// After one.
pub(crate) const ASN1_OP_STREAM_POST: c_int = 11;
/// Before a value is detached from its parent.
pub(crate) const ASN1_OP_DETACHED_PRE: c_int = 12;
/// After one is.
pub(crate) const ASN1_OP_DETACHED_POST: c_int = 13;
/// Before a duplicate is made.
pub(crate) const ASN1_OP_DUP_PRE: c_int = 14;
/// After one is.
pub(crate) const ASN1_OP_DUP_POST: c_int = 15;
/// Ask the callback for the library context.
pub(crate) const ASN1_OP_GET0_LIBCTX: c_int = 16;
/// Ask the callback for the property query.
pub(crate) const ASN1_OP_GET0_PROPQ: c_int = 17;

// ---------------------------------------------------------------------------
// `ASN1_STRING_FLAG_*` — the non-numeric part of `ASN1_STRING.flags`.
// ---------------------------------------------------------------------------

/// The string is a constructed, indefinite-length encoding.
pub(crate) const ASN1_STRING_FLAG_NDEF: c_long = 0x010;
/// The content continues in the next value of the same type.
pub(crate) const ASN1_STRING_FLAG_CONT: c_long = 0x020;
/// The type came from a `MSTRING` decode of unknown type.
pub(crate) const ASN1_STRING_FLAG_MSTRING: c_long = 0x040;
/// `data` points at memory this structure does not own.
pub(crate) const ASN1_STRING_FLAG_EMBED: c_long = 0x080;
/// The string is an X.509 time whose type may be adjusted on assignment.
pub(crate) const ASN1_STRING_FLAG_X509_TIME: c_long = 0x100;
/// Mask of the unused-bit count a bit string keeps in the low bits.
pub(crate) const ASN1_STRING_FLAG_BITS_LEFT: c_long = 0x08;

// ---------------------------------------------------------------------------
// The `V_ASN1_*` universal type numbers.
// ---------------------------------------------------------------------------

/// End-of-contents.
pub(crate) const V_ASN1_EOC: c_int = 0;
/// `BOOLEAN`.
pub(crate) const V_ASN1_BOOLEAN: c_int = 1;
/// `INTEGER`.
pub(crate) const V_ASN1_INTEGER: c_int = 2;
/// `BIT STRING`.
pub(crate) const V_ASN1_BIT_STRING: c_int = 3;
/// `OCTET STRING`.
pub(crate) const V_ASN1_OCTET_STRING: c_int = 4;
/// `NULL`.
pub(crate) const V_ASN1_NULL: c_int = 5;
/// `OBJECT IDENTIFIER`.
pub(crate) const V_ASN1_OBJECT: c_int = 6;
/// `ObjectDescriptor`.
pub(crate) const V_ASN1_OBJECT_DESCRIPTOR: c_int = 7;
/// `EXTERNAL`.
pub(crate) const V_ASN1_EXTERNAL: c_int = 8;
/// `REAL`.
pub(crate) const V_ASN1_REAL: c_int = 9;
/// `ENUMERATED`.
pub(crate) const V_ASN1_ENUMERATED: c_int = 10;
/// `UTF8String`.
pub(crate) const V_ASN1_UTF8STRING: c_int = 12;
/// `SEQUENCE`.
pub(crate) const V_ASN1_SEQUENCE: c_int = 16;
/// `SET`.
pub(crate) const V_ASN1_SET: c_int = 17;
/// `NumericString`.
pub(crate) const V_ASN1_NUMERICSTRING: c_int = 18;
/// `PrintableString`.
pub(crate) const V_ASN1_PRINTABLESTRING: c_int = 19;
/// `TeletexString`, also spelled `T61String`.
pub(crate) const V_ASN1_T61STRING: c_int = 20;
/// `IA5String`.
pub(crate) const V_ASN1_IA5STRING: c_int = 22;
/// `UTCTime`.
pub(crate) const V_ASN1_UTCTIME: c_int = 23;
/// `GeneralizedTime`.
pub(crate) const V_ASN1_GENERALIZEDTIME: c_int = 24;
/// `GraphicString`.
pub(crate) const V_ASN1_GRAPHICSTRING: c_int = 25;
/// `VisibleString`, also spelled `ISO64String`.
pub(crate) const V_ASN1_VISIBLESTRING: c_int = 26;
/// `GeneralString`.
pub(crate) const V_ASN1_GENERALSTRING: c_int = 27;
/// `UniversalString`.
pub(crate) const V_ASN1_UNIVERSALSTRING: c_int = 28;
/// `BMPString`.
pub(crate) const V_ASN1_BMPSTRING: c_int = 30;
/// `ANY` — the caller does not constrain the type.
pub(crate) const V_ASN1_ANY: c_int = -4;
/// `OTHER` — not one of the universal types.
pub(crate) const V_ASN1_OTHER: c_int = -3;
/// The caller chooses the application type.
pub(crate) const V_ASN1_APP_CHOOSE: c_int = -2;
/// The type is undefined.
pub(crate) const V_ASN1_UNDEF: c_int = -1;
/// The bit that turns an integer or enumerated type into its negative form.
pub(crate) const V_ASN1_NEG: c_int = 0x100;
/// `INTEGER`, negated.
pub(crate) const V_ASN1_NEG_INTEGER: c_int = V_ASN1_NEG | V_ASN1_INTEGER;
/// `ENUMERATED`, negated.
pub(crate) const V_ASN1_NEG_ENUMERATED: c_int = V_ASN1_NEG | V_ASN1_ENUMERATED;
/// The constructed bit.
pub(crate) const V_ASN1_CONSTRUCTED: c_int = 0x20;
/// The low five bits of a tag: `0x1f` means a high-tag-number form follows.
pub(crate) const V_ASN1_PRIMITIVE_TAG: c_int = 0x1f;
/// The universal class.
pub(crate) const V_ASN1_UNIVERSAL: c_int = 0x00;
/// The application class.
pub(crate) const V_ASN1_APPLICATION: c_int = 0x40;
/// The context-specific class.
pub(crate) const V_ASN1_CONTEXT_SPECIFIC: c_int = 0x80;
/// The private class.
pub(crate) const V_ASN1_PRIVATE: c_int = 0xc0;

// ---------------------------------------------------------------------------
// `B_ASN1_*` — the type masks a `MSTRING` item or a string-table row carries.
// ---------------------------------------------------------------------------

/// `NumericString`.
pub(crate) const B_ASN1_NUMERICSTRING: c_ulong = 0x0001;
/// `PrintableString`.
pub(crate) const B_ASN1_PRINTABLESTRING: c_ulong = 0x0002;
/// `TeletexString`.
pub(crate) const B_ASN1_T61STRING: c_ulong = 0x0004;
/// `TeletexString`, spelled as `DIRECTORYSTRING` spells it.
pub(crate) const B_ASN1_TELETEXSTRING: c_ulong = 0x0004;
/// `VideotexString`.
pub(crate) const B_ASN1_VIDEOTEXSTRING: c_ulong = 0x0008;
/// `IA5String`.
pub(crate) const B_ASN1_IA5STRING: c_ulong = 0x0010;
/// `GraphicString`.
pub(crate) const B_ASN1_GRAPHICSTRING: c_ulong = 0x0020;
/// `VisibleString` / `ISO64String`.
pub(crate) const B_ASN1_ISO64STRING: c_ulong = 0x0040;
/// `VisibleString`, as the mask names it.
pub(crate) const B_ASN1_VISIBLESTRING: c_ulong = 0x0040;
/// `GeneralString`.
pub(crate) const B_ASN1_GENERALSTRING: c_ulong = 0x0080;
/// `UniversalString`.
pub(crate) const B_ASN1_UNIVERSALSTRING: c_ulong = 0x0100;
/// `OCTET STRING`.
pub(crate) const B_ASN1_OCTET_STRING: c_ulong = 0x0200;
/// `BIT STRING`.
pub(crate) const B_ASN1_BIT_STRING: c_ulong = 0x0400;
/// `BMPString`.
pub(crate) const B_ASN1_BMPSTRING: c_ulong = 0x0800;
/// A type outside the universal set.
pub(crate) const B_ASN1_UNKNOWN: c_ulong = 0x1000;
/// `UTF8String`.
pub(crate) const B_ASN1_UTF8STRING: c_ulong = 0x2000;
/// `UTCTime`.
pub(crate) const B_ASN1_UTCTIME: c_ulong = 0x4000;
/// `GeneralizedTime`.
pub(crate) const B_ASN1_GENERALIZEDTIME: c_ulong = 0x8000;
/// `SEQUENCE`.
pub(crate) const B_ASN1_SEQUENCE: c_ulong = 0x10000;
/// The string types that make up `DirectoryString`.
pub(crate) const B_ASN1_DIRECTORYSTRING: c_ulong = B_ASN1_PRINTABLESTRING
    | B_ASN1_TELETEXSTRING
    | B_ASN1_BMPSTRING
    | B_ASN1_UNIVERSALSTRING
    | B_ASN1_UTF8STRING;
/// The string types `DisplayText` allows.
pub(crate) const B_ASN1_DISPLAYTEXT: c_ulong =
    B_ASN1_IA5STRING | B_ASN1_VISIBLESTRING | B_ASN1_BMPSTRING | B_ASN1_UTF8STRING;
/// Everything the authority's `B_ASN1_PRINTABLE` means.
///
/// Note the bits that are not string types — `B_ASN1_BIT_STRING`,
/// `B_ASN1_SEQUENCE` and `B_ASN1_UNKNOWN` are in the authority's definition, and
/// they are what makes `ASN1_STRING_set_by_NID` accept a bit string or a sequence
/// for a NID whose mask is this.
pub(crate) const B_ASN1_PRINTABLE: c_ulong = B_ASN1_NUMERICSTRING
    | B_ASN1_PRINTABLESTRING
    | B_ASN1_T61STRING
    | B_ASN1_IA5STRING
    | B_ASN1_BIT_STRING
    | B_ASN1_UNIVERSALSTRING
    | B_ASN1_BMPSTRING
    | B_ASN1_UTF8STRING
    | B_ASN1_SEQUENCE
    | B_ASN1_UNKNOWN;
/// The two time types.
pub(crate) const B_ASN1_TIME: c_ulong = B_ASN1_UTCTIME | B_ASN1_GENERALIZEDTIME;

// ---------------------------------------------------------------------------
// `MBSTRING_*` — the arguments of `ASN1_mbstring_*`.
// ---------------------------------------------------------------------------

/// The bit that distinguishes an encoding argument from a `B_ASN1_*` mask.
pub(crate) const MBSTRING_FLAG: c_int = 0x1000;
/// UTF-8 input.
pub(crate) const MBSTRING_UTF8: c_int = MBSTRING_FLAG;
/// Latin-1 input, one character per byte.
pub(crate) const MBSTRING_ASC: c_int = MBSTRING_FLAG | 1;
/// Big-endian two-byte input.
pub(crate) const MBSTRING_BMP: c_int = MBSTRING_FLAG | 2;
/// Big-endian four-byte input.
pub(crate) const MBSTRING_UNIV: c_int = MBSTRING_FLAG | 4;
/// Mask of the low bits of the encoding argument.
pub(crate) const MBSTRING_ENC_MASK: c_int = 0x0f;

// ---------------------------------------------------------------------------
// `STABLE_FLAGS_*` — ownership of an `ASN1_STRING_TABLE` row.
// ---------------------------------------------------------------------------

/// The row was allocated by `ASN1_STRING_TABLE_add` and must be freed with it.
pub(crate) const STABLE_FLAGS_MALLOC: c_ulong = 0x01;

// ---------------------------------------------------------------------------
// `ASN1_PCTX_FLAGS_*` — the printing-option bits.
// ---------------------------------------------------------------------------

/// Show absent OPTIONAL fields.
pub(crate) const ASN1_PCTX_FLAGS_SHOW_ABSENT: c_ulong = 0x001;
/// Show the SEQUENCE header.
pub(crate) const ASN1_PCTX_FLAGS_SHOW_SEQUENCE: c_ulong = 0x002;
/// Show SET OF and SEQUENCE OF headers.
pub(crate) const ASN1_PCTX_FLAGS_SHOW_SSOF: c_ulong = 0x004;
/// Show the type of a primitive.
pub(crate) const ASN1_PCTX_FLAGS_SHOW_TYPE: c_ulong = 0x008;
/// Do not annotate `ANY`.
pub(crate) const ASN1_PCTX_FLAGS_NO_ANY_TYPE: c_ulong = 0x010;
/// Do not annotate a MSTRING's type.
pub(crate) const ASN1_PCTX_FLAGS_NO_MSTRING_TYPE: c_ulong = 0x020;
/// Do not print field names.
pub(crate) const ASN1_PCTX_FLAGS_NO_FIELD_NAME: c_ulong = 0x040;
/// Show a field's structure name.
pub(crate) const ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME: c_ulong = 0x080;
/// Do not print structure names.
pub(crate) const ASN1_PCTX_FLAGS_NO_STRUCT_NAME: c_ulong = 0x100;

// ---------------------------------------------------------------------------
// `ASN1_STRFLGS_*` — the flags `ASN1_STRING_print_ex` takes.
// ---------------------------------------------------------------------------

/// Escape RFC2253 special characters.
pub(crate) const ASN1_STRFLGS_ESC_2253: c_ulong = 1;
/// Escape control characters.
pub(crate) const ASN1_STRFLGS_ESC_CTRL: c_ulong = 2;
/// Escape characters with the high bit set.
pub(crate) const ASN1_STRFLGS_ESC_MSB: c_ulong = 4;
/// Escape with backslash *and* quote.
pub(crate) const ASN1_STRFLGS_ESC_QUOTE: c_ulong = 8;
/// Convert to UTF-8 before printing.
pub(crate) const ASN1_STRFLGS_UTF8_CONVERT: c_ulong = 0x10;
/// Print the content regardless of the type.
pub(crate) const ASN1_STRFLGS_IGNORE_TYPE: c_ulong = 0x20;
/// Prefix the content with its type name.
pub(crate) const ASN1_STRFLGS_SHOW_TYPE: c_ulong = 0x40;
/// Dump the DER of every value.
pub(crate) const ASN1_STRFLGS_DUMP_ALL: c_ulong = 0x80;
/// Dump the DER of a type the printer does not know.
pub(crate) const ASN1_STRFLGS_DUMP_UNKNOWN: c_ulong = 0x100;
/// Dump the DER rather than the content.
pub(crate) const ASN1_STRFLGS_DUMP_DER: c_ulong = 0x200;
/// Escape RFC2254 special characters.
pub(crate) const ASN1_STRFLGS_ESC_2254: c_ulong = 0x400;
/// The RFC2253 default set.
pub(crate) const ASN1_STRFLGS_RFC2253: c_ulong = ASN1_STRFLGS_ESC_2253
    | ASN1_STRFLGS_ESC_CTRL
    | ASN1_STRFLGS_ESC_MSB
    | ASN1_STRFLGS_UTF8_CONVERT
    | ASN1_STRFLGS_DUMP_UNKNOWN
    | ASN1_STRFLGS_DUMP_DER;

// ---------------------------------------------------------------------------
// `ASN1_DTFLGS_*` — the time-formatting flags `ASN1_TIME_print_ex` takes.
// ---------------------------------------------------------------------------

/// Mask of the output-type bits.
pub(crate) const ASN1_DTFLGS_TYPE_MASK: c_ulong = 0x0F;
/// RFC 822 output, the default.
pub(crate) const ASN1_DTFLGS_RFC822: c_ulong = 0x00;
/// ISO 8601 output.
pub(crate) const ASN1_DTFLGS_ISO8601: c_ulong = 0x01;

// ---------------------------------------------------------------------------
// `ASN1_SCTX_*` — the streaming flags.
// ---------------------------------------------------------------------------

/// No callback is installed.
pub(crate) const ASN1_SCTX_OP_CB_NONE: c_ulong = 0;
/// A callback is installed.
pub(crate) const ASN1_SCTX_OP_CB_SET: c_ulong = 1;
