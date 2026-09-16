//! Phase 6.7b — `crypto/property/property_query.c`, reading a parsed list back out.
//!
//! Eighty lines, and every one of them is a consequence of the sorted array
//! `stack_to_property_list` produces. The definitions are ordered by `name_idx`, so
//! a name is found by binary search over the array rather than by walking it, and
//! the search compares **the index the string table assigns to the caller's name**
//! against each definition's stored index.
//!
//! ## The name query is a lookup, not an intern
//!
//! ```c
//! if (list == NULL || name == NULL
//!     || (name_idx = ossl_property_name(libctx, name, 0)) == 0)
//!     return NULL;
//! ```
//!
//! `create` is **0**, so asking a list whether it carries a name that has never
//! been interned does not intern it — it answers 0, which is the "no such name"
//! index, and the function returns NULL without searching. That is not merely an
//! optimisation: interning would assign an index, and a later `create` call for the
//! same name would then find an existing entry whose position in the *name* table
//! was decided by a read.
//!
//! ## `ossl_property_is_enabled` compares the value index, not the string
//!
//! ```c
//! return (prop->type == OSSL_PROPERTY_TYPE_STRING
//!     && ((prop->oper == OSSL_PROPERTY_OPER_EQ && prop->v.str_val == OSSL_PROPERTY_TRUE)
//!         || (prop->oper == OSSL_PROPERTY_OPER_NE && prop->v.str_val != OSSL_PROPERTY_TRUE)));
//! ```
//!
//! `OSSL_PROPERTY_TRUE` is 1, the index the string table gives `"yes"`. So the test
//! is "the value is the interned index of yes", and an *uninterned* value cannot be
//! true. The `NE` arm is deliberately loose — `str_val != OSSL_PROPERTY_TRUE` is true
//! for the index of `"no"` (2) and equally for the index of `"42"` or of any other
//! string, which is what makes `fips!=yes` mean "anything but yes" rather than
//! "no".
//!
//! Note also the "separate check for override", which the authority comments: an
//! override clause is `-name`, and it sets `oper` **without setting `type`**, so a
//! test that reached the value comparison for an override would read an
//! uninitialised-or-stale union member. The `prop->oper == OSSL_PROPERTY_OVERRIDE`
//! arm is therefore load-bearing, and it answers 0 — an override is not an
//! enablement.

use core::ffi::{c_char, c_int, c_void};

use crate::property::list::{
    num_properties, properties, properties_ptr, OsslPropertyDefinition, OsslPropertyIdx,
    OsslPropertyList, OSSL_PROPERTY_OPER_EQ, OSSL_PROPERTY_OPER_NE, OSSL_PROPERTY_OVERRIDE,
    OSSL_PROPERTY_TRUE, OSSL_PROPERTY_TYPE_NUMBER, OSSL_PROPERTY_TYPE_STRING,
};
use crate::property::strings::{ossl_property_name, ossl_property_value_str};
use crate::runtime::bsearch::ossl_bsearch;

/// `static int property_idx_cmp(const void *keyp, const void *compare)`
///
/// `return key - defn->name_idx;` — the authority's comparator answers a
/// *difference*, not a sign, which is fine because the search only reads its sign.
///
/// # Safety
/// `keyp` must point at an `OSSL_PROPERTY_IDX` and `compare` at a definition.
unsafe extern "C" fn property_idx_cmp(keyp: *const c_void, compare: *const c_void) -> c_int {
    // SAFETY: both are live per the caller's contract.
    unsafe {
        let key = *(keyp.cast::<OsslPropertyIdx>());
        let defn = &*compare.cast::<OsslPropertyDefinition>();
        key - defn.name_idx
    }
}

/// `const OSSL_PROPERTY_DEFINITION *ossl_property_find_property(const OSSL_PROPERTY_LIST *list,
/// OSSL_LIB_CTX *libctx, const char *name)`
///
/// NULL for a NULL list, a NULL name, or a name this context has never interned.
///
/// # Safety
/// `list` must be NULL or a live list; `libctx` must be NULL or a live context;
/// `name` must be NULL or NUL-terminated.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_find_property(
    list: *const OsslPropertyList,
    libctx: *mut c_void,
    name: *const c_char,
) -> *const OsslPropertyDefinition {
    if list.is_null() || name.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `list` is live and `name` is NUL-terminated; `create` is 0, so this is
    // a lookup and never an intern.
    let name_idx = unsafe { ossl_property_name(libctx, name, 0) };
    if name_idx == 0 {
        return core::ptr::null();
    }
    // SAFETY: the list is live, so its tail has `num_properties` elements, and the
    // index protocol of `ossl_bsearch` reproduces the authority's probe order. The
    // probe is the authority's own comparator, taking the key's address and the
    // element's address, which is why it is a C-shaped function rather than a
    // closure that reads the element directly.
    unsafe {
        let n = num_properties(list) as usize;
        let props = properties(list, n);
        let key = name_idx;
        let found = ossl_bsearch(n, 0, &mut |i| {
            // SAFETY: `i < n` by the search's own bounds, so `props[i]` is an element
            // of the tail, and `key` is live for the whole call.
            property_idx_cmp(
                core::ptr::addr_of!(key).cast::<c_void>(),
                core::ptr::addr_of!(props[i]).cast::<c_void>(),
            )
        });
        match found {
            Some(i) => properties_ptr(list).add(i),
            None => core::ptr::null(),
        }
    }
}

/// `OSSL_PROPERTY_TYPE ossl_property_get_type(const OSSL_PROPERTY_DEFINITION *prop)`
///
/// # Safety
/// `prop` must be live.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_get_type(prop: *const OsslPropertyDefinition) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*prop).type_ }
}

/// `const char *ossl_property_get_string_value(OSSL_LIB_CTX *libctx,
/// const OSSL_PROPERTY_DEFINITION *prop)`
///
/// NULL or a `STRING`-typed definition answers NULL; otherwise the reverse lookup
/// turns the stored index back into the string the table holds.
///
/// # Safety
/// `prop` must be NULL or live; `libctx` must be NULL or a live context.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_get_string_value(
    libctx: *mut c_void,
    prop: *const OsslPropertyDefinition,
) -> *const c_char {
    if prop.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `prop` is live.
    let (type_, v) = unsafe { ((*prop).type_, (*prop).v) };
    if type_ != OSSL_PROPERTY_TYPE_STRING {
        return core::ptr::null();
    }
    // SAFETY: the `STRING` arm is the one the type says is live, so `str_val` is the
    // index the string table assigned.
    unsafe { ossl_property_value_str(libctx, v.str_val) }
}

/// `int64_t ossl_property_get_number_value(const OSSL_PROPERTY_DEFINITION *prop)`
///
/// A definition that is not a `NUMBER` answers **0**, not an error: the answer is
/// the same shape as a number, and the caller distinguishes by
/// [`ossl_property_get_type`].
///
/// # Safety
/// `prop` must be live.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_get_number_value(prop: *const OsslPropertyDefinition) -> i64 {
    // SAFETY: `prop` is live.
    unsafe {
        if (*prop).type_ != OSSL_PROPERTY_TYPE_NUMBER {
            return 0;
        }
        (*prop).v.int_val
    }
}

/// `int ossl_property_has_optional(const OSSL_PROPERTY_LIST *query)`
///
/// The whole of it is the bit the list carries, which `stack_to_property_list`
/// computed by OR-ing every definition's own bit.
///
/// # Safety
/// `query` must be live.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_has_optional(query: *const OsslPropertyList) -> c_int {
    // SAFETY: the caller's contract. The field is a one-bit bitfield in the
    // authority, so only 0 or 1 is ever stored.
    unsafe {
        if (*query).has_optional != 0 {
            1
        } else {
            0
        }
    }
}

/// `int ossl_property_is_enabled(OSSL_LIB_CTX *ctx, const char *property_name,
/// const OSSL_PROPERTY_LIST *prop_list)`
///
/// # Safety
/// `prop_list` must be NULL or live; `ctx` must be NULL or a live context;
/// `property_name` must be NULL or NUL-terminated.
#[allow(dead_code)]
// unreachable until 6.8's fetch calls it; this whole module is the interface the
// provider registry is written against, and the seal of no earlier phase named it
pub(crate) unsafe fn ossl_property_is_enabled(
    ctx: *mut c_void,
    property_name: *const c_char,
    prop_list: *const OsslPropertyList,
) -> c_int {
    // SAFETY: forwarded under the caller's contract.
    let prop = unsafe { ossl_property_find_property(prop_list, ctx, property_name) };
    if prop.is_null() {
        return 0;
    }
    // SAFETY: `prop` is a live definition. All three fields are plain reads; the
    // `OVERRIDE` arm has to come before the union is touched, because an override
    // sets `oper` without setting `type` and its union member is not meaningful.
    let (optional, oper, type_) = unsafe { ((*prop).optional, (*prop).oper, (*prop).type_) };
    if optional != 0 || oper == OSSL_PROPERTY_OVERRIDE {
        return 0;
    }
    if type_ != OSSL_PROPERTY_TYPE_STRING {
        return 0;
    }
    // SAFETY: the `STRING` arm is the live one per the type.
    let str_val = unsafe { (*prop).v.str_val };
    let eq_true = oper == OSSL_PROPERTY_OPER_EQ && str_val == OSSL_PROPERTY_TRUE;
    let ne_true = oper == OSSL_PROPERTY_OPER_NE && str_val != OSSL_PROPERTY_TRUE;
    c_int::from(eq_true || ne_true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::list::{PropertyValue, PROPERTY_VALUE_BYTES};

    /// A definition built by hand, which is what the parser produces.
    fn defn(
        name_idx: OsslPropertyIdx,
        type_: c_int,
        oper: c_int,
        v: PropertyValue,
    ) -> OsslPropertyDefinition {
        OsslPropertyDefinition {
            name_idx,
            type_,
            oper,
            optional: 0,
            v,
        }
    }

    #[test]
    fn the_comparator_answers_a_difference_not_a_sign() {
        let d = defn(
            7,
            OSSL_PROPERTY_TYPE_STRING,
            OSSL_PROPERTY_OPER_EQ,
            PropertyValue { int_val: 0 },
        );
        let key: OsslPropertyIdx = 9;
        // SAFETY: both pointers are to live values of the declared types.
        let c = unsafe {
            property_idx_cmp(
                core::ptr::addr_of!(key).cast::<c_void>(),
                core::ptr::addr_of!(d).cast::<c_void>(),
            )
        };
        // 9 - 7, not 1: the authority's comparator returns the difference and the
        // search reads only its sign.
        assert_eq!(c, 2);
    }

    #[test]
    fn a_definition_that_is_not_a_number_answers_zero_for_its_number() {
        let d = defn(
            1,
            OSSL_PROPERTY_TYPE_STRING,
            OSSL_PROPERTY_OPER_EQ,
            PropertyValue { int_val: 99 },
        );
        // SAFETY: `d` is live.
        assert_eq!(unsafe { ossl_property_get_number_value(&d) }, 0);
        // The string arm reads only the low four bytes, which is what the union's
        // layout decides on a little-endian target.
        let ds = defn(
            1,
            OSSL_PROPERTY_TYPE_STRING,
            OSSL_PROPERTY_OPER_EQ,
            PropertyValue { str_val: 5 },
        );
        // SAFETY: `ds` is live and its type says the string arm is the live one.
        assert_eq!(unsafe { ds.v.str_val }, 5);
    }

    #[test]
    fn the_parsers_zero_the_whole_union_which_is_what_the_match_comparison_covers() {
        // `ossl_property_match_count` compares two definitions with
        // `memcmp(&q[i].v, &d[j].v, sizeof(q[i].v))` — **eight** bytes — so the four
        // bytes above a four-byte `str_val` take part in equality. Both parsers
        // therefore zero the union before filling it (`memset(&prop->v, 0,
        // sizeof(prop->v))`), and this asserts the contract from the candidate's side:
        // a definition whose value is a string has zeroes above it, and then the
        // index.
        //
        // This is deliberately **not** written as a comparison of two bare union
        // literals. A Rust `PropertyValue { str_val: 1 }` leaves the upper four bytes
        // uninitialised, so such a test would assert something the language does not
        // promise — measured: it happened to pass for the wrong reason, and failed
        // once the initialisation was made explicit. What the authority guarantees is
        // that its *parser* writes all eight bytes, and that is what is checked.
        let c = crate::context::OSSL_LIB_CTX_new();
        assert!(!c.is_null());
        // SAFETY: `c` is live and its slot 3 was built by `context_init`.
        assert_eq!(unsafe { crate::property::ossl_property_parse_init(c) }, 1);
        // SAFETY: `c` is live and the literal is NUL-terminated.
        unsafe {
            let l = crate::property::parse::ossl_parse_property(c, c"fips=yes".as_ptr());
            assert!(!l.is_null());
            let p = &*properties_ptr(l);
            assert_eq!(p.type_, OSSL_PROPERTY_TYPE_STRING);
            let bytes: [u8; PROPERTY_VALUE_BYTES] = core::mem::transmute_copy(&p.v);
            assert_eq!(
                &bytes[4..],
                &[0u8; PROPERTY_VALUE_BYTES - 4],
                "the parser zeroes the union above the string index"
            );
            assert_ne!(
                bytes, [0u8; PROPERTY_VALUE_BYTES],
                "and then writes the index into it"
            );
            crate::property::parse::ossl_property_free(l);
            crate::context::OSSL_LIB_CTX_free(c);
        }
    }
}
