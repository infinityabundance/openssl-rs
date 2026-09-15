//! Phase 5 — the `ASN1_ITEM` descriptors the authority defines for the coded
//! types, and the `*_it()` accessors that hand them out.
//!
//! The authority puts all of these in one place — `crypto/asn1/tasn_typ.c`'s
//! `IMPLEMENT_ASN1_STRING_FUNCTIONS` block, plus `ASN1_TIME` in `a_time.c` — and
//! this module follows that grouping rather than scattering an item next to each
//! type. The reason is the one `mod.rs` gives for the module tree as a whole:
//! the ownership atlas and the raise-site coordinates are keyed on the
//! authority's file boundaries, so a reader asking "where does the authority
//! define this?" gets the same answer from both.
//!
//! ## The item is not a lookup table; it is the object
//!
//! `IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING)` expands to
//!
//! ```text
//! const ASN1_ITEM *ASN1_OCTET_STRING_it(void)
//! {
//!     static const ASN1_ITEM local_it = {
//!         ASN1_ITYPE_PRIMITIVE, V_ASN1_OCTET_STRING, NULL, 0, NULL, 0,
//!         "ASN1_OCTET_STRING"
//!     };
//!     return &local_it;
//! }
//! ```
//!
//! so the accessor answers a pointer to an immutable static, two calls answer
//! the same address, and every field is readable through it. The `size` field is
//! the one that looks like a detail and is not: it is `0` for the plain types
//! because `IMPLEMENT_ASN1_TYPE` passes `0` as `ASN1_ITEM_start`'s last-but-one
//! initializer, while `IMPLEMENT_ASN1_TYPE_ex` passes whatever it is given —
//! which is how `ASN1_TBOOLEAN` and `ASN1_FBOOLEAN` carry a *default* and how
//! `ASN1_OCTET_STRING_NDEF` carries `ASN1_TFLG_NDEF`. The boolean encoder reads
//! that field to decide whether a value is omitted, so a wrong `size` silently
//! changes the bytes an item encodes to.
//!
//! ## Why these are `static` and what that costs
//!
//! [`Asn1Item`] holds raw pointers, so it is not `Sync` by default and a `static`
//! of it needs the impl [`layout`] carries. That impl is sound for the reason
//! written there: the values are compiled-in constants.
//!
//! ## What is deliberately absent
//!
//! The twelve numeric items (`BIGNUM_it`, `INT32_it`, `ZLONG_it`, …) are not here.
//! Each carries an `ASN1_PRIMITIVE_FUNCS` whose `prim_new`/`prim_free`/`prim_clear`/
//! `prim_c2i`/`prim_i2c`/`prim_print` hooks are what make it work, and they live with
//! their hooks in [`crate::asn1::x_int64`], [`crate::asn1::x_long`] and
//! [`crate::asn1::x_bignum`] because a hook is a function rather than a constant.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_long, c_void};

use crate::asn1::layout::*;

/// `sizeof(ASN1_STRING)` — the `size` field of the four MSTRING items.
///
/// `IMPLEMENT_ASN1_MSTRING` passes `sizeof(ASN1_STRING)` rather than a default,
/// because a MSTRING item *is* an `ASN1_STRING` and the template machinery reads
/// the field when it allocates one. It is 24 on this target, and the constant is
/// derived from the size the ABI court measures rather than typed: `ABI-SIZES`
/// compares `sizeof(ASN1_STRING)` for the authority header and for
/// [`Asn1String`], so if this ever needed to change it could not do so quietly.
const SIZEOF_ASN1_STRING: c_long = core::mem::size_of::<Asn1String>() as c_long;

/// Declare one `IMPLEMENT_ASN1_TYPE`-shaped item and its accessor.
///
/// Both identifiers are written out at each use because a macro cannot build a
/// `#[no_mangle]` symbol from another token — the same constraint
/// `asn1::string`'s `define_new_free` records. The macro exists so the *shape* is
/// stated once: `ASN1_ITYPE_PRIMITIVE`, no templates, no hooks, and a name the
/// authority's macro stringified from the item's own symbol.
macro_rules! primitive_item {
    ($item:ident, $getter:ident, $utype:expr, $size:expr, $sname:expr, $doc:expr) => {
        #[doc = $doc]
        ///
        /// `size` is the authority's `ASN1_ITEM.size`, which the boolean encoder
        /// reads as the item's default.
        static $item: Asn1Item = Asn1Item {
            itype: ASN1_ITYPE_PRIMITIVE,
            utype: $utype as c_long,
            templates: core::ptr::null(),
            tcount: 0,
            funcs: core::ptr::null(),
            size: $size,
            sname: $sname.as_ptr(),
        };

        #[doc = $doc]
        ///
        /// The authority's `ASN1_ITEM_start` answers `&local_it`, a
        /// function-local `static`, so two calls answer the same address and the
        /// fields are readable through it.
        #[no_mangle]
        pub extern "C" fn $getter() -> *const Asn1Item {
            &$item
        }
    };
}

/// Declare one `IMPLEMENT_ASN1_MSTRING`-shaped item and its accessor.
///
/// `utype` is a `B_ASN1_*` *mask* rather than a single tag: a MSTRING item is a
/// choice over the character string types that mask admits, and the decoder reads
/// the real type from the encoding and checks it against the mask.
macro_rules! mstring_item {
    ($item:ident, $getter:ident, $mask:expr, $sname:expr, $doc:expr) => {
        #[doc = $doc]
        ///
        /// `size` is `sizeof(ASN1_STRING)`, as `IMPLEMENT_ASN1_MSTRING` passes.
        static $item: Asn1Item = Asn1Item {
            itype: ASN1_ITYPE_MSTRING,
            utype: $mask as c_long,
            templates: core::ptr::null(),
            tcount: 0,
            funcs: core::ptr::null(),
            size: SIZEOF_ASN1_STRING,
            sname: $sname.as_ptr(),
        };

        #[doc = $doc]
        ///
        /// The authority's `ASN1_ITEM_start` answers `&local_it`, a
        /// function-local `static`, so two calls answer the same address and the
        /// fields are readable through it.
        #[no_mangle]
        pub extern "C" fn $getter() -> *const Asn1Item {
            &$item
        }
    };
}

// ---------------------------------------------------------------------------
// The plain string types — `IMPLEMENT_ASN1_STRING_FUNCTIONS` in `tasn_typ.c`
// ---------------------------------------------------------------------------

primitive_item!(
    ASN1_OCTET_STRING_ITEM,
    ASN1_OCTET_STRING_it,
    V_ASN1_OCTET_STRING,
    0,
    c"ASN1_OCTET_STRING",
    "`const ASN1_ITEM *ASN1_OCTET_STRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_OCTET_STRING)`."
);
primitive_item!(
    ASN1_INTEGER_ITEM,
    ASN1_INTEGER_it,
    V_ASN1_INTEGER,
    0,
    c"ASN1_INTEGER",
    "`const ASN1_ITEM *ASN1_INTEGER_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_INTEGER)`."
);
primitive_item!(
    ASN1_ENUMERATED_ITEM,
    ASN1_ENUMERATED_it,
    V_ASN1_ENUMERATED,
    0,
    c"ASN1_ENUMERATED",
    "`const ASN1_ITEM *ASN1_ENUMERATED_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_ENUMERATED)`."
);
primitive_item!(
    ASN1_BIT_STRING_ITEM,
    ASN1_BIT_STRING_it,
    V_ASN1_BIT_STRING,
    0,
    c"ASN1_BIT_STRING",
    "`const ASN1_ITEM *ASN1_BIT_STRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_BIT_STRING)`."
);
primitive_item!(
    ASN1_UTF8STRING_ITEM,
    ASN1_UTF8STRING_it,
    V_ASN1_UTF8STRING,
    0,
    c"ASN1_UTF8STRING",
    "`const ASN1_ITEM *ASN1_UTF8STRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UTF8STRING)`."
);
primitive_item!(
    ASN1_PRINTABLESTRING_ITEM,
    ASN1_PRINTABLESTRING_it,
    V_ASN1_PRINTABLESTRING,
    0,
    c"ASN1_PRINTABLESTRING",
    "`const ASN1_ITEM *ASN1_PRINTABLESTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_PRINTABLESTRING)`."
);
primitive_item!(
    ASN1_T61STRING_ITEM,
    ASN1_T61STRING_it,
    V_ASN1_T61STRING,
    0,
    c"ASN1_T61STRING",
    "`const ASN1_ITEM *ASN1_T61STRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_T61STRING)`."
);
primitive_item!(
    ASN1_IA5STRING_ITEM,
    ASN1_IA5STRING_it,
    V_ASN1_IA5STRING,
    0,
    c"ASN1_IA5STRING",
    "`const ASN1_ITEM *ASN1_IA5STRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_IA5STRING)`."
);
primitive_item!(
    ASN1_GENERALSTRING_ITEM,
    ASN1_GENERALSTRING_it,
    V_ASN1_GENERALSTRING,
    0,
    c"ASN1_GENERALSTRING",
    "`const ASN1_ITEM *ASN1_GENERALSTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_GENERALSTRING)`."
);
primitive_item!(
    ASN1_UTCTIME_ITEM,
    ASN1_UTCTIME_it,
    V_ASN1_UTCTIME,
    0,
    c"ASN1_UTCTIME",
    "`const ASN1_ITEM *ASN1_UTCTIME_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UTCTIME)`."
);
primitive_item!(
    ASN1_GENERALIZEDTIME_ITEM,
    ASN1_GENERALIZEDTIME_it,
    V_ASN1_GENERALIZEDTIME,
    0,
    c"ASN1_GENERALIZEDTIME",
    "`const ASN1_ITEM *ASN1_GENERALIZEDTIME_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_GENERALIZEDTIME)`."
);
primitive_item!(
    ASN1_VISIBLESTRING_ITEM,
    ASN1_VISIBLESTRING_it,
    V_ASN1_VISIBLESTRING,
    0,
    c"ASN1_VISIBLESTRING",
    "`const ASN1_ITEM *ASN1_VISIBLESTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_VISIBLESTRING)`."
);
primitive_item!(
    ASN1_UNIVERSALSTRING_ITEM,
    ASN1_UNIVERSALSTRING_it,
    V_ASN1_UNIVERSALSTRING,
    0,
    c"ASN1_UNIVERSALSTRING",
    "`const ASN1_ITEM *ASN1_UNIVERSALSTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_UNIVERSALSTRING)`."
);
primitive_item!(
    ASN1_BMPSTRING_ITEM,
    ASN1_BMPSTRING_it,
    V_ASN1_BMPSTRING,
    0,
    c"ASN1_BMPSTRING",
    "`const ASN1_ITEM *ASN1_BMPSTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_STRING_FUNCTIONS(ASN1_BMPSTRING)`."
);

// ---------------------------------------------------------------------------
// The remaining plain types — `IMPLEMENT_ASN1_TYPE` in `tasn_typ.c`
// ---------------------------------------------------------------------------

primitive_item!(
    ASN1_NULL_ITEM,
    ASN1_NULL_it,
    V_ASN1_NULL,
    0,
    c"ASN1_NULL",
    "`const ASN1_ITEM *ASN1_NULL_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE(ASN1_NULL)`."
);
primitive_item!(
    ASN1_OBJECT_ITEM,
    ASN1_OBJECT_it,
    V_ASN1_OBJECT,
    0,
    c"ASN1_OBJECT",
    "`const ASN1_ITEM *ASN1_OBJECT_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)`."
);
primitive_item!(
    ASN1_ANY_ITEM,
    ASN1_ANY_it,
    V_ASN1_ANY,
    0,
    c"ASN1_ANY",
    "`const ASN1_ITEM *ASN1_ANY_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE(ASN1_ANY)`. `utype` is `V_ASN1_ANY`, which is how the \
     shared decoder knows to read the type from the encoding rather than from the \
     item."
);
primitive_item!(
    ASN1_SEQUENCE_ITEM,
    ASN1_SEQUENCE_it,
    V_ASN1_SEQUENCE,
    0,
    c"ASN1_SEQUENCE",
    "`const ASN1_ITEM *ASN1_SEQUENCE_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE(ASN1_SEQUENCE)`, which the file's own comment describes \
     as \"just swallow an `ASN1_SEQUENCE` in an `ASN1_STRING`\"."
);

// ---------------------------------------------------------------------------
// The three BOOLEANs and the NDEF octet string — `IMPLEMENT_ASN1_TYPE_ex`
// ---------------------------------------------------------------------------

primitive_item!(
    ASN1_BOOLEAN_ITEM,
    ASN1_BOOLEAN_it,
    V_ASN1_BOOLEAN,
    -1,
    c"ASN1_BOOLEAN",
    "`const ASN1_ITEM *ASN1_BOOLEAN_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)`. `size` is `-1`, \
     which the boolean encoder reads as \"no default\": the value is always \
     encoded."
);
primitive_item!(
    ASN1_TBOOLEAN_ITEM,
    ASN1_TBOOLEAN_it,
    V_ASN1_BOOLEAN,
    1,
    c"ASN1_TBOOLEAN",
    "`const ASN1_ITEM *ASN1_TBOOLEAN_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE_ex(ASN1_TBOOLEAN, ASN1_BOOLEAN, 1)`. `size` is the \
     *default* `TRUE`, so a true value is omitted from the encoding."
);
primitive_item!(
    ASN1_FBOOLEAN_ITEM,
    ASN1_FBOOLEAN_it,
    V_ASN1_BOOLEAN,
    0,
    c"ASN1_FBOOLEAN",
    "`const ASN1_ITEM *ASN1_FBOOLEAN_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE_ex(ASN1_FBOOLEAN, ASN1_BOOLEAN, 0)`. `size` is the \
     *default* `FALSE`, so a false value is omitted from the encoding."
);
primitive_item!(
    ASN1_OCTET_STRING_NDEF_ITEM,
    ASN1_OCTET_STRING_NDEF_it,
    V_ASN1_OCTET_STRING,
    ASN1_TFLG_NDEF as c_long,
    c"ASN1_OCTET_STRING_NDEF",
    "`const ASN1_ITEM *ASN1_OCTET_STRING_NDEF_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_TYPE_ex(ASN1_OCTET_STRING_NDEF, ASN1_OCTET_STRING, \
     ASN1_TFLG_NDEF)`. The `size` field carries the NDEF flag rather than a size, \
     which is what `asn1_ex_i2c`'s `it->size == ASN1_TFLG_NDEF` arm tests for."
);

// ---------------------------------------------------------------------------
// The four multi-string types — `IMPLEMENT_ASN1_MSTRING`
// ---------------------------------------------------------------------------

mstring_item!(
    ASN1_PRINTABLE_ITEM,
    ASN1_PRINTABLE_it,
    B_ASN1_PRINTABLE,
    c"ASN1_PRINTABLE",
    "`const ASN1_ITEM *ASN1_PRINTABLE_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_MSTRING(ASN1_PRINTABLE, B_ASN1_PRINTABLE)`."
);
mstring_item!(
    DISPLAYTEXT_ITEM,
    DISPLAYTEXT_it,
    B_ASN1_DISPLAYTEXT,
    c"DISPLAYTEXT",
    "`const ASN1_ITEM *DISPLAYTEXT_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_MSTRING(DISPLAYTEXT, B_ASN1_DISPLAYTEXT)`."
);
mstring_item!(
    DIRECTORYSTRING_ITEM,
    DIRECTORYSTRING_it,
    B_ASN1_DIRECTORYSTRING,
    c"DIRECTORYSTRING",
    "`const ASN1_ITEM *DIRECTORYSTRING_it(void)` — `tasn_typ.c`'s \
     `IMPLEMENT_ASN1_MSTRING(DIRECTORYSTRING, B_ASN1_DIRECTORYSTRING)`."
);
mstring_item!(
    ASN1_TIME_ITEM,
    ASN1_TIME_it,
    B_ASN1_TIME,
    c"ASN1_TIME",
    "`const ASN1_ITEM *ASN1_TIME_it(void)` — `a_time.c`'s \
     `IMPLEMENT_ASN1_MSTRING(ASN1_TIME, B_ASN1_TIME)`, which this module groups \
     with the others because it is the same shape."
);

// ---------------------------------------------------------------------------
// The two `*_ANY` items — `ASN1_ITEM_TEMPLATE` in `tasn_typ.c`
// ---------------------------------------------------------------------------

/// Declare one `ASN1_ITEM_TEMPLATE`-shaped item: an item whose *value* is described by
/// a single `ASN1_TEMPLATE` of its own.
///
/// The shape is unusual and worth stating, because two of its fields are what the
/// interpreter keys on:
///
/// * `utype` is `V_ASN1_UNDEF`, not a tag. The item has no type of its own — the template
///   does — and the authority passes the literal `-1` here.
/// * `tcount` is 0 while `templates` is non-null. For a `PRIMITIVE` item with a template,
///   the machine reads `it->templates` directly; `tcount` describes a *field* array, which
///   this item does not have.
///
/// A template's `item` field is an `ASN1_ITEM_EXP` — in C, `&ASN1_ANY_it`, the address of
/// the accessor **function**, not of the item it answers. That is what
/// `ASN1_ITEM_ref(type)` expands to and what [`crate::asn1::utl::call_item_exp`] calls.
///
/// Both identifiers are written out at each use for the reason the other macros here
/// record: a macro cannot build a `#[no_mangle]` symbol from another token.
macro_rules! template_item {
    ($item:ident, $tt:ident, $getter:ident, $flags:expr, $sname:literal, $sub:path, $doc:expr) => {
        #[doc = $doc]
        ///
        /// The item's single template. `tag` and `offset` are 0 because a `SEQUENCE OF`
        /// takes its tag from the flags and has no field to be offset to.
        static $tt: Asn1Template = Asn1Template {
            flags: $flags,
            tag: 0,
            offset: 0,
            field_name: $sname.as_ptr(),
            item: $sub as *mut c_void,
        };

        #[doc = $doc]
        ///
        /// The authority's `ASN1_ITEM_start` answers `&local_it`, a function-local
        /// `static`, so two calls answer the same address and the fields are readable
        /// through it.
        static $item: Asn1Item = Asn1Item {
            itype: ASN1_ITYPE_PRIMITIVE,
            utype: V_ASN1_UNDEF as c_long,
            templates: &$tt,
            tcount: 0,
            funcs: core::ptr::null_mut(),
            size: 0,
            sname: $sname.as_ptr(),
        };

        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $getter() -> *const Asn1Item {
            &$item
        }
    };
}

template_item!(
    ASN1_SEQUENCE_ANY_ITEM,
    ASN1_SEQUENCE_ANY_TT,
    ASN1_SEQUENCE_ANY_it,
    ASN1_TFLG_SEQUENCE_OF,
    c"ASN1_SEQUENCE_ANY",
    ASN1_ANY_it,
    "`const ASN1_ITEM *ASN1_SEQUENCE_ANY_it(void)` — `tasn_typ.c`'s \
     `ASN1_ITEM_TEMPLATE(ASN1_SEQUENCE_ANY)`, whose template is \
     `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ASN1_SEQUENCE_ANY, ASN1_ANY)`. \
     The value is therefore a `STACK_OF(ASN1_TYPE)`, and each element is decoded by \
     `ASN1_ANY_it` rather than by this item."
);

template_item!(
    ASN1_SET_ANY_ITEM,
    ASN1_SET_ANY_TT,
    ASN1_SET_ANY_it,
    ASN1_TFLG_SET_OF,
    c"ASN1_SET_ANY",
    ASN1_ANY_it,
    "`const ASN1_ITEM *ASN1_SET_ANY_it(void)` — `tasn_typ.c`'s \
     `ASN1_ITEM_TEMPLATE(ASN1_SET_ANY)`, the same shape as `ASN1_SEQUENCE_ANY` with \
     `ASN1_TFLG_SET_OF`. The flag is what makes the encoder sort the elements into \
     canonical order, so the two items produce different bytes for the same stack."
);

// ---------------------------------------------------------------------------
// The primitive-hook items — `ASN1_ITEM_start` over `ASN1_PRIMITIVE_FUNCS`
// ---------------------------------------------------------------------------

/// Declare one `ASN1_PRIMITIVE_FUNCS`-carrying item and its accessor.
///
/// These are the items whose codec is a *function* rather than the generic content codec:
/// `x_int64.c`'s eight, `x_long.c`'s two and `x_bignum.c`'s two. The decoder and encoder
/// reach them through `it->funcs` before any type dispatch, which is why the hook, not
/// `utype`, is what makes them work.
///
/// `size` is **not** a size here. All twelve of those items overwrite the field with flags
/// — `INTxx_FLAG_*` for the integers, the `ASN1_LONG_UNDEF` sentinel for `LONG`, the
/// sensitivity bit for `CBIGNUM` — and the hooks read it back. That abuse is the
/// authority's, and the decoder's `V_ASN1_BOOLEAN` arm is the only place in the generic
/// machinery that also treats `size` as a value rather than a layout fact, so it is worth
/// naming here rather than discovering later.
///
/// `funcs` is a `&'static Asn1PrimitiveFuncs` at each use and is stored as a raw pointer
/// because that is what the item holds.
macro_rules! funcs_item {
    ($item:ident, $getter:ident, $funcs:expr, $size:expr, $sname:literal, $doc:expr) => {
        #[doc = $doc]
        ///
        /// `size` is the authority's flags word, not a `sizeof`: see [`funcs_item`].
        static $item: Asn1Item = Asn1Item {
            itype: ASN1_ITYPE_PRIMITIVE,
            utype: V_ASN1_INTEGER as c_long,
            templates: core::ptr::null(),
            tcount: 0,
            funcs: (&$funcs as *const Asn1PrimitiveFuncs).cast::<c_void>(),
            size: $size,
            sname: $sname.as_ptr(),
        };

        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $getter() -> *const Asn1Item {
            &$item
        }
    };
}

pub(crate) use funcs_item;
