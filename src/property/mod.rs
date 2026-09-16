//! Phase 6.7 — the property engine, `crypto/property/`.
//!
//! OpenSSL 3 selects an algorithm by *properties*: a provider's algorithm declares
//! `provider=default`, `fips=yes`, `output=certificate` and so on, and a fetch
//! carries a query which either *requires* or *forbids* each property. The engine
//! that makes that work is six translation units and about 2,250 lines:
//!
//! ```text
//! property.c            949   the method store and the fetch algorithm
//! property_parse.c      763   the definition and query grammars
//! property_string.c     273   the name/value string tables
//! property_query.c       80   reading a parsed property back out
//! defn_cache.c          137   the per-context definition cache
//! property_err.c         46   the error string table
//! ```
//!
//! ## This subsystem has no exported surface, and that decides its court
//!
//! Every entry point here is `ossl_property_*`, `ossl_ctx_global_properties*` or
//! `ossl_prop_defn_*` — **internal**. Nothing in `libcrypto.so.3`'s export list
//! names the property engine, so no consumer can call it directly and no
//! differential probe compiled against *installed headers* can reach one function
//! of the grammar.
//!
//! What a consumer *can* reach is `OSSL_LIB_CTX_get_data`, which takes an integer
//! index, and three of the eighteen live indices name objects this subsystem owns:
//!
//! | index | slot | owner |
//! |---|---|---|
//! | 2 | `property_defns` | `defn_cache.c` |
//! | 3 | `property_string_data` | `property_string.c` |
//! | 14 | `global_properties` | `property.c` |
//!
//! So this stratum's obligation is those three slots, observed exactly as slot 4
//! was in 6.6b and slot 17 in 6.6c: `RT-LIBCTX` sweeps the index table and its
//! `filled_slots` array gains the three numbers. **`RT-PROPERTY` is therefore not a
//! separate court, and `docs/PHASE-6-SUBPHASES.md`'s earlier criterion for 6.7 —
//! "definition, parse, string round-trip, matching, query parse and negative
//! selection" — was not observable through any export.** That is a correction to
//! the plan rather than a reduction of the obligation: the *behaviour* it named is
//! real and is required, but the place it becomes observable is where a consumer
//! meets it, which is a provider fetch.
//!
//! `docs/PROVIDER_MODEL.md` §5's gate item 4 — "property-based fetch selection
//! matches, **including negative selection**" — is therefore discharged at 6.8,
//! where `OSSL_PROVIDER_*` and the fetch API make a query's effect on a selection
//! observable, and corroborated at 6.12, where an independently written C provider
//! registered with its own properties is selected by the authority and by this
//! crate under the same queries. A subdivision that claimed the grammar was courted
//! *here* would be claiming an observation no probe can make.
//!
//! ## The subdivision
//!
//! | # | subphase | authority files | obligation |
//! |---|---|---|---|
//! | 6.7a | the string table and the three slots | `property_string.c`; `defn_cache.c`'s constructor and releaser; `property.c`'s two global-property functions | slots 2, 3 and 14 filled, `ossl_property_parse_init` run from `context_init`, the name and value indices assigned in the authority's order |
//! | 6.7b | the grammars | `property_parse.c`, `property_query.c`, the cache's `get` and `set` | `ossl_parse_property`, `ossl_parse_query`, `ossl_property_match_count`, `ossl_property_merge`, `ossl_property_list_to_string`, and the negative-selection rule |
//! | 6.7c | the store and the fetch | `property.c`'s remainder | `ossl_method_store_*` and the fetch cache, which need the provider store and are therefore 6.8's |
//!
//! 6.7a is what this module lands first. The split is by *observability* as much as
//! by size: 6.7a is the part three slots can witness, and 6.7b is the part only a
//! provider fetch can.
//!
//! ## Why the string table comes first even though it is the least interesting
//!
//! `context_init` calls `ossl_property_parse_init(ctx)` as its last step before the
//! compression methods, and that call is what assigns the indices the grammar's own
//! constants are compared against:
//!
//! ```c
//! if ((ossl_property_value(ctx, "yes", 1) != OSSL_PROPERTY_TRUE)
//!     || (ossl_property_value(ctx, "no", 1) != OSSL_PROPERTY_FALSE))
//!     goto err;
//! ```
//!
//! `OSSL_PROPERTY_TRUE` is 1 and `OSSL_PROPERTY_FALSE` is 2, and the value table's
//! counter is *separate* from the name table's, so "yes" and "no" are the first two
//! values while the six predefined names take 1..6 in their own space. A table that
//! numbered values differently would make every boolean property answer the wrong
//! thing, and the check above is the authority asserting its own ordering at start
//! up. It is reproduced here in the same order, for the same reason.

pub mod defn_cache;
pub mod globals;
pub mod list;
pub mod parse;
pub mod query;
pub mod strings;

pub(crate) use defn_cache::{ossl_property_defns_free, ossl_property_defns_new};
pub(crate) use globals::{ossl_ctx_global_properties_free, ossl_ctx_global_properties_new};
pub(crate) use parse::ossl_property_parse_init;
pub(crate) use strings::{ossl_property_string_data_free, ossl_property_string_data_new};
