//! `crypto/ec/` — Phase 8.7: the `EC_KEY`, `EC_GROUP` and `EC_POINT` objects, the built-in
//! curve tables, and the EC provider surfaces.
//!
//! This module is Phase 8.7's, and it is **the first slice of it rather than the block**.
//! The block is two hundred and two labels, and its core is one indivisible layer: unlike
//! 8.4's, 8.5's and 8.6's method tables, none of the EC units could be landed alone, and
//! the reason is a *cycle the plan's own reading missed*. `crypto/ec/ec_lib.c`'s
//! `ossl_ec_group_new_ex` is reached by every constructor and reaches a `meth->group_init`
//! through a method table; the tables are `ecp_smpl.c`, `ecp_mont.c`, `ecp_nist.c`,
//! `ecp_nistz256.c` and `ec2_smpl.c`; and `ec_curve.c`'s `curve_list[]` names one of those
//! tables in its **fourth column**. So the curve table, the group object and the field
//! arithmetic are one landing, and no part of it is reachable from nothing the way
//! `dh_meth.c` and `dsa_meth.c` were.
//!
//! ## What is landed here, and what is not
//!
//! Landed: **[`curve`]** and **[`support`]**, which are `ec_curve.c`'s built-in parameters
//! and `crypto/evp/ec_support.c`'s name tables — the constants D332's argument says must be
//! *read back from the authority rather than typed*, and the three lookups over them. That
//! is four exports: `EC_get_builtin_curves`, `EC_curve_nid2nist`, `EC_curve_nist2nid` and
//! `OSSL_EC_curve_nid2name`.
//!
//! Not landed, and deliberately not started: `ec_lib.c`'s group and point objects
//! (sixty-nine labels), the field and point arithmetic they dispatch to, `ec_key.c`'s
//! thirty-three, and every other unit of the block. Each is `open` in
//! `forensics/phase8-obligations.json` and nothing is stubbed.
//!
//! ## The one authority coordinate that decides this boundary
//!
//! `EC_GROUP_new_by_curve_name_ex` is `ec_curve.c`'s and it is reachable from nothing in
//! this slice, because `ec_group_new_from_data` reads `curve_list[]`'s fourth column and
//! that column is **not** what the other three are. On this profile exactly one of the
//! eighty-two rows is non-NULL — `NID_X9_62_prime256v1` names `EC_GFp_nistz256_method` —
//! and that symbol is an `ec_local.h` internal, not a DSO export, whose `EC_METHOD` table
//! (`ecp_nistz256.c:1569-1630`) names `ossl_ec_key_simple_*` (`ec_key.c`),
//! `ossl_ecdh_simple_compute_key` (`ecdh_ossl.c`) and `ossl_ecdsa_simple_*`
//! (`ecdsa_ossl.c`) — three units this subphase does not own. A row written with a NULL
//! where the authority writes a function would be a fabricated value, so the column is
//! recorded in `forensics/atlas/ec-curves.json` (with the profile's `#if` resolution and
//! the probe's own method observation beside it) and not transcribed. [`curve`] says so at
//! the field it would occupy.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod curve;
pub(crate) mod curve_data;
pub mod support;
