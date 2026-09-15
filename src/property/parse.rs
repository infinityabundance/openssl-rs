//! Phase 6.7a — `crypto/property/property_parse.c`'s list type and its two entry points.
//!
//! `property_parse.c` is 763 lines and most of it is the property grammar: the
//! definition form (`name=value`), the query form (`name=value`, `name!=value` and
//! `-name`), the merge, the match count and the reverse printer. All of that is
//! 6.7b's, because none of it is observable until a provider fetch can select on a
//! query.
//!
//! Two things from that file are 6.7a's, and both are here:
//!
//!   * [`ossl_property_parse_init`] — `context_init`'s last step before the
//!     compression methods, which interns the six predefined names and the two
//!     Boolean values in the authority's order. Without it the string table exists
//!     but is empty, and the grammar's own constants (`OSSL_PROPERTY_TRUE` is 1,
//!     `OSSL_PROPERTY_FALSE` is 2) would name nothing.
//!   * [`ossl_property_free`] — nine characters of C, `OPENSSL_free(p)`, and the
//!     releaser the definition cache's element destructor calls. `OPENSSL_free`
//!     accepts NULL, which is what every element of the cache currently holds.
//!
//! ## The ordering the two Boolean values are asserted against
//!
//! ```c
//! if ((ossl_property_value(ctx, "yes", 1) != OSSL_PROPERTY_TRUE)
//!     || (ossl_property_value(ctx, "no", 1) != OSSL_PROPERTY_FALSE))
//!     goto err;
//! ```
//!
//! The `||` short-circuits, so a table that numbered `"yes"` wrongly would also
//! leave `"no"` uninterned — the authority's own failure path reaches that state, and
//! it is reproduced here by the same two `if`s rather than by a tuple comparison,
//! which would evaluate both regardless.

use core::ffi::{c_char, c_int, c_void};

use crate::property::strings::{ossl_property_name, ossl_property_value};

/// `OSSL_PROPERTY_LIST` — opaque here. 6.7b gives it its layout; nothing in this
/// stratum allocates one.
#[repr(C)]
pub(crate) struct OsslPropertyList {
    _private: [u8; 0],
}

/// `#define OSSL_PROPERTY_TRUE 1` — `property_local.h`.
pub(crate) const OSSL_PROPERTY_TRUE: c_int = 1;
/// `#define OSSL_PROPERTY_FALSE 2` — `property_local.h`.
pub(crate) const OSSL_PROPERTY_FALSE: c_int = 2;

/// `int ossl_property_parse_init(OSSL_LIB_CTX *ctx)`
///
/// The six predefined names, then the two Boolean values, in that order and with
/// `create` set. Answers 1, or 0 at the first failure — which is also what the
/// authority answers, because its `err:` label is a bare `return 0`.
///
/// # Safety
/// `ctx` must be NULL or a live context whose slot 3 has been constructed: the call
/// reaches `ossl_lib_ctx_get_data`, which needs the datum to intern into.
pub(crate) unsafe fn ossl_property_parse_init(ctx: *mut c_void) -> c_int {
    /// The authority's `predefined_names`, verbatim and in its order.
    static PREDEFINED_NAMES: [&core::ffi::CStr; 6] = [
        c"provider",  // Name of provider (default, legacy, fips)
        c"version",   // Version number of this provider
        c"fips",      // FIPS validated or FIPS supporting algorithm
        c"output",    // Output type for encoders
        c"input",     // Input type for decoders
        c"structure", // Structure name for encoders and decoders
    ];

    for n in PREDEFINED_NAMES {
        // SAFETY: `ctx` is live per the contract and `n` is a `'static` string.
        if unsafe { ossl_property_name(ctx, n.as_ptr(), 1) } == 0 {
            return 0;
        }
    }

    // SAFETY: as above. The two calls are short-circuiting exactly as the
    // authority's `||` is: when `"yes"` is not 1, `"no"` is never interned.
    unsafe {
        if ossl_property_value(ctx, c"yes".as_ptr(), 1) != OSSL_PROPERTY_TRUE
            || ossl_property_value(ctx, c"no".as_ptr(), 1) != OSSL_PROPERTY_FALSE
        {
            return 0;
        }
    }

    1
}

/// `void ossl_property_free(OSSL_PROPERTY_LIST *p)`
///
/// One `OPENSSL_free`, which is what the authority has. Its NULL case is the one
/// this stratum actually relies on today: every definition-cache element this crate
/// can create holds a NULL `defn`, and the releaser is shared with 6.7b's.
///
/// # Safety
/// `p` must be NULL or a list this crate allocated and has not released.
pub(crate) unsafe fn ossl_property_free(p: *mut OsslPropertyList) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` came from this crate's allocator; the block is the whole list, as
    // `ossl_property_free` is a bare release in the authority.
    unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), FILE, LINE_FREE_LIST) };
}

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/property/property_parse.c".as_ptr();

/// `ossl_property_free`'s `OPENSSL_free(p)`.
const LINE_FREE_LIST: c_int = 529;
