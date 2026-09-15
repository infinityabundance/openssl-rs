//! Phase 6.7b — the property list and definition types, `property_local.h` and
//! `internal/property.h`.
//!
//! A parsed property string is one allocation holding a header and a **variable
//! number of definitions**:
//!
//! ```c
//! struct ossl_property_definition_st {
//!     OSSL_PROPERTY_IDX name_idx;
//!     OSSL_PROPERTY_TYPE type;
//!     OSSL_PROPERTY_OPER oper;
//!     unsigned int optional : 1;
//!     union {
//!         int64_t int_val;         /* Signed integer */
//!         OSSL_PROPERTY_IDX str_val; /* String */
//!     } v;
//! };
//!
//! struct ossl_property_list_st {
//!     int num_properties;
//!     unsigned int has_optional : 1;
//!     OSSL_PROPERTY_DEFINITION properties[1];
//! };
//! ```
//!
//! Everything below is a compatibility fact rather than a convenience, and three of
//! them are the kind that a plausible implementation gets wrong:
//!
//!   1. **`name_idx` is first**, because `stack_to_property_list` sorts the array by
//!      it and `ossl_property_match_count` walks two sorted arrays together. The
//!      field order is therefore load-bearing, not incidental.
//!   2. **`v` is a union of an `int64_t` and an `OSSL_PROPERTY_IDX` (`int32_t`)**,
//!      and it is compared with `memcmp(&q[i].v, &d[j].v, sizeof(q[i].v))` —
//!      eight bytes of the union, whatever the type. So the *padding* of the union
//!      is compared: a definition built by `parse_string` leaves the upper four
//!      bytes as `memset` put them, and a query that compares equal must have the
//!      same upper four bytes. That is why `ossl_parse_query` and
//!      `ossl_parse_property` both `memset(&prop->v, 0, sizeof(prop->v))` before
//!      filling it, and why the comparison is a byte comparison here rather than a
//!      field comparison.
//!   3. **`has_optional` is a bitfield on the list**, set by OR-ing every
//!      definition's `optional`.
//!
//! A `#[repr(C)]` Rust type with the same field order gives the same offsets and the
//! same `size_of`, including the bitfields, because both bitfields are `unsigned
//! int : 1` in the low bits of their storage unit.
//!
//! ## The union is a union in Rust too, and for the same reason
//!
//! Reading the wrong arm is undefined in C and would be undefined here, so the
//! accessor is `unsafe` and the callers are the authority's. The `memcmp` is
//! reproduced as a byte comparison of the eight-byte union, which is the only place
//! a `#[repr(C)]` `union` earns its place: a Rust `enum` would compare the *variant*
//! and answer `false` for a definition and a query that the authority calls equal.

use core::ffi::c_int;

/// `OSSL_PROPERTY_IDX` — `typedef int`, `property_local.h`.
pub(crate) type OsslPropertyIdx = c_int;

/// `typedef enum { OSSL_PROPERTY_TYPE_STRING, OSSL_PROPERTY_TYPE_NUMBER,
/// OSSL_PROPERTY_TYPE_VALUE_UNDEFINED } OSSL_PROPERTY_TYPE` — `internal/property.h`.
pub(crate) const OSSL_PROPERTY_TYPE_STRING: c_int = 0;
pub(crate) const OSSL_PROPERTY_TYPE_NUMBER: c_int = 1;
pub(crate) const OSSL_PROPERTY_TYPE_VALUE_UNDEFINED: c_int = 2;

/// `typedef enum { OSSL_PROPERTY_OPER_EQ, OSSL_PROPERTY_OPER_NE,
/// OSSL_PROPERTY_OVERRIDE } OSSL_PROPERTY_OPER`.
pub(crate) const OSSL_PROPERTY_OPER_EQ: c_int = 0;
pub(crate) const OSSL_PROPERTY_OPER_NE: c_int = 1;
pub(crate) const OSSL_PROPERTY_OVERRIDE: c_int = 2;

/// `#define OSSL_PROPERTY_TRUE 1` and `OSSL_PROPERTY_FALSE 2` — `property_local.h`.
///
/// They live in `parse.rs` with the initialiser that assigns them; re-exported here
/// because every reader of a definition compares against them.
pub(crate) use crate::property::parse::{OSSL_PROPERTY_FALSE, OSSL_PROPERTY_TRUE};

/// The `v` union of `struct ossl_property_definition_st`.
///
/// Eight bytes either way, so the union's `size_of` is 8 and the `memcmp` in
/// `ossl_property_match_count` covers all of it.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union PropertyValue {
    /// `int64_t int_val` — the `NUMBER` arm.
    pub(crate) int_val: i64,
    /// `OSSL_PROPERTY_IDX str_val` — the `STRING` arm. Only the low four bytes of
    /// the union, which is why the upper four are the padding that `memset` decides.
    pub(crate) str_val: OsslPropertyIdx,
}

/// `struct ossl_property_definition_st`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OsslPropertyDefinition {
    /// `OSSL_PROPERTY_IDX name_idx` — first, because the list is sorted by it.
    pub(crate) name_idx: OsslPropertyIdx,
    /// `OSSL_PROPERTY_TYPE type`.
    pub(crate) type_: c_int,
    /// `OSSL_PROPERTY_OPER oper`.
    pub(crate) oper: c_int,
    /// `unsigned int optional : 1` — one bit of a storage unit that `#[repr(C)]`
    /// places as C does.
    pub(crate) optional: u32,
    /// `union { int64_t; OSSL_PROPERTY_IDX; } v`.
    pub(crate) v: PropertyValue,
}

/// The byte width of the `v` union, which is what `ossl_property_match_count`'s
/// `memcmp` covers.
pub(crate) const PROPERTY_VALUE_BYTES: usize = core::mem::size_of::<PropertyValue>();

/// A **view** of an `OSSL_PROPERTY_LIST`: a run of definitions.
///
/// The authority's type is one allocation with a flexible tail
/// (`properties[1]`), and its layout is the authority's — `parse.rs` allocates it
/// with `size_of::<OsslPropertyList>() + (n - 1) * size_of::<OsslPropertyDefinition>()`
/// exactly as `stack_to_property_list` does. This struct is the header half, so the
/// reader can address the tail by running past it.
#[repr(C)]
pub(crate) struct OsslPropertyList {
    /// `int num_properties`.
    pub(crate) num_properties: c_int,
    /// `unsigned int has_optional : 1`.
    pub(crate) has_optional: u32,
    /// `OSSL_PROPERTY_DEFINITION properties[1]` — the first element of the tail. The
    /// remaining `num_properties - 1` follow it contiguously.
    pub(crate) properties: [OsslPropertyDefinition; 1],
}

/// The definition array of a list, as a raw pointer to the first element.
///
/// # Safety
/// `list` must be a live list from `ossl_parse_property`, `ossl_parse_query` or
/// `ossl_property_merge`, so the tail really has `num_properties` elements.
pub(crate) unsafe fn properties_ptr(
    list: *const OsslPropertyList,
) -> *const OsslPropertyDefinition {
    // SAFETY: `properties` is the first field of the tail, at a fixed offset from
    // the header, so this is an interior address of the same allocation.
    unsafe { core::ptr::addr_of!((*list).properties).cast::<OsslPropertyDefinition>() }
}

/// The number of definitions in `list`, or 0 for NULL.
///
/// # Safety
/// `list` must be NULL or a live list.
pub(crate) unsafe fn num_properties(list: *const OsslPropertyList) -> c_int {
    if list.is_null() {
        0
    } else {
        // SAFETY: `list` is live per the contract.
        unsafe { (*list).num_properties }
    }
}

pub(crate) unsafe fn properties<'len>(
    list: *const OsslPropertyList,
    len: usize,
) -> &'len [OsslPropertyDefinition] {
    // SAFETY: the caller guarantees `len` is the tail's length.
    unsafe { core::slice::from_raw_parts(properties_ptr(list), len) }
}
