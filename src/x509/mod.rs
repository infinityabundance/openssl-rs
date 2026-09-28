//! The crate's `crypto/x509/` substream, in two strata. The transcription atlas maps a crate
//! module to the authority translation unit its definitions dominantly come from
//! (`forensics/atlas/transcription-edges.json`'s `body.modules`, `build_edges`'s "the unit is the
//! dominant authority translation unit among the symbols the module defines"), so each unit gets
//! one module named for its file:
//!
//! ```text
//! src/x509/x_pubkey.rs   <-  crypto/x509/x_pubkey.c     (Phase 8.8, D349/D369)
//! src/x509/x509_set.rs   <-  crypto/x509/x509_set.c     (Phase 8.8, + 10.8's X509_up_ref)
//! src/x509/t_x509.rs     <-  crypto/x509/t_x509.c       (Phase 8.8)
//! src/x509/x509_att.rs   <-  crypto/x509/x509_att.c     (10.2's staging, D368)
//! src/x509/x_attrib.rs   <-  crypto/x509/x_attrib.c     (10.2's staging, D368)
//! src/x509/x_exten.rs    <-  crypto/x509/x_exten.c      (10.8)
//! src/x509/x_name.rs     <-  crypto/x509/x_name.c       (10.8)
//! src/x509/x_x509.rs     <-  crypto/x509/x_x509.c       (10.8)
//! src/x509/x_crl.rs      <-  crypto/x509/x_crl.c        (10.8, + X509_CRL_up_ref from x509cset.c)
//! src/x509/x509_txt.rs   <-  crypto/x509/x509_txt.c     (10.12)
//! src/x509/x_x509a.rs    <-  crypto/x509/x_x509a.c      (10.12)
//! src/x509/pcy_lib.rs    <-  crypto/x509/pcy_lib.c      (10.12)
//! src/x509/v3_ia5.rs     <-  crypto/x509/v3_ia5.c       (10.12)
//! src/x509/v3_skid.rs    <-  crypto/x509/v3_skid.c      (10.12)
//! src/x509/v3_pcia.rs    <-  crypto/x509/v3_pcia.c      (10.12)
//! src/x509/v3_ist.rs     <-  crypto/x509/v3_ist.c       (10.12)
//! src/x509/v3_lib.rs     <-  crypto/x509/v3_lib.c       (10.13)
//! src/x509/v3_pku.rs     <-  crypto/x509/v3_pku.c       (10.13)
//! src/x509/v3_timespec.rs<-  crypto/x509/v3_timespec.c  (10.13)
//! src/x509/v3_utf8.rs    <-  crypto/x509/v3_utf8.c      (10.13)
//! src/x509/v3_no_rev_avail.rs <- crypto/x509/v3_no_rev_avail.c (10.13)
//! src/x509/v3_single_use.rs   <- crypto/x509/v3_single_use.c   (10.13)
//! src/x509/v3_soa_id.rs       <- crypto/x509/v3_soa_id.c       (10.13)
//! src/x509/x509_cmp.rs   <-  crypto/x509/x509_cmp.c     (10.14.1)
//! src/x509/x509cset.rs   <-  crypto/x509/x509cset.c     (10.14.1)
//! src/x509/x509type.rs   <-  crypto/x509/x509type.c     (10.14.1)
//! ```
//!
//! ## Phase 8.8 — the accessor slices
//!
//! `src/x509/` did not exist before D349. It was created for the accessor slices of
//! `x_pubkey.c`, `x509_set.c` and `t_x509.c` that the ASN.1 method objects call by name. All
//! three are **partial** transcriptions, and each module withholds what it does not build and
//! names it, in both directions, in `forensics/prerequisites.json`'s `divergences` — the mechanism
//! D345 established for `src/dh/ameth.rs`. `x_pubkey.c` was completed by D369.
//!
//! ## Phase 10.8 — the X.509 object core
//!
//! The owner pulled a measured subset of Phase 11 forward on D442/D444's precedent: the certificate
//! object graph is what every one of Phase 10's open rows waits on. 10.8 lands the **object core**
//! of that graph, not its whole dependency-closed component: the `X509`, `X509_CINF`, `X509_CRL`,
//! `X509_CRL_INFO`, `X509_REVOKED`, `X509_NAME`, `X509_NAME_ENTRY`, `X509_VAL` and
//! `X509_EXTENSION` structures, their `ASN1_ITEM` descriptors, and the lifecycles and `d2i`/`i2d`
//! entry points the blocked STORE and PKCS#12 rows reach. Every arm whose closure is unlanded is
//! **withheld with its own note** rather than stubbed, and each module's doc lists the withheld
//! names with their blockers. `crypto/x509/x_val.c` lands as `src/asn1/x_val.rs` (its own
//! directory, as its path requires).
//!
//! The ownership is unchanged: the atlas still gives every `x509.h` export to Phase 11, Phase 10's
//! ledger reads `284 implemented / 14 open` and its provider census `634 implemented / 2 open` (the
//! rows this slice closes are the two `OSSL_STORE_INFO` readers' reachability, not new rows), and
//! **Phase 11 still derives `not-started`** — no Phase 11 evidence, ledger, plan, seal or state row
//! is created.
//!
//! ## Phase 10.12 — the leaf extension items and the policy graph
//!
//! The second pulled-forward slice after 10.8: the leaf `crypto/x509/` units whose closure the
//! certificate object graph needs and which 10.11 left unblocked. `x_x509a.rs` lands the
//! `X509_CERT_AUX` item and the trust/alias/key-id surface, which un-withholds
//! `d2i_X509_AUX`/`i2d_X509_AUX` in `x_x509.rs`; `x509_txt.rs` lands `X509_verify_cert_error_string`;
//! `pcy_lib.rs` lands the policy-tree accessors and the four `pcy_local.h` layouts;
//! `v3_pcia.rs` and `v3_ist.rs` land their items; `v3_ia5.rs`/`v3_skid.rs` land their string
//! helpers. **Withheld by name, each with its blocker**: `pcy_node.rs` (all six `ossl_policy_*`
//! operations — internal and unreachable), the four table-only `v3_*` leaves
//! (`v3_audit_id`/`v3_group_ac`/`v3_ind_iss`/`v3_no_ass`), the `v3_ia5`/`v3_skid`/`v3_ist` tables
//! and their `static` callbacks (`X509V3_add_standard_extensions`, `v3_lib.c`, 10.14), and the
//! `http`/`punycode` units `x_all.c` reaches (`X509_load_http`, 10.14). Every module's own doc
//! names its withholds.
//!
//! ## Phase 10.13 — the remaining leaf extension items, and one deliberate scope increase
//!
//! The third pulled-forward slice after 10.8. Section 6 gives this subphase six units / 875 lines:
//! `v3_timespec.c` (599), `v3_pku.c` (52) and the four table-only leaves (`v3_utf8.c`,
//! `v3_no_rev_avail.c`, `v3_single_use.c`, `v3_soa_id.c`; 224 between them). D455 measured that
//! only the first two are drivable as-is and named the four leaves' blocker as "no exported symbols
//! to name, and no landed caller"; the plan expected that pulling `crypto/x509/v3_lib.c` in -- the
//! unit holding `X509V3_add_standard_extensions`, the leaves' only authority caller -- would make
//! them land.
//!
//! **It does not, and this subphase measures exactly why.** `v3_lib.rs` lands its registration
//! half (`X509V3_EXT_add`/`_add_list`/`_cleanup`, `X509V3_add_standard_extensions`, the
//! `X509V3_EXT_METHOD` layout) but **withholds its lookup half by name**: `X509V3_EXT_get_nid`
//! searches `standard_exts[]` (`standard_exts.h:15-95`), which names **63 `ossl_v3_*` tables**,
//! of which this subphase lands six and the other ~57 belong to units it does not own (`v3_bcons.c`,
//! `v3_key_usage.c`, `v3_alt.c`, `v3_cpols.c`, the `crypto/ocsp/` rows, …). A partial table would
//! silently change `OBJ_bsearch_ext`'s answers, so `X509V3_EXT_get_nid`, `_get`, `_add_alias`,
//! `_EXT_d2i`, `_get_d2i` and `_add1_i2d` are withheld together. The four leaves therefore remain
//! withheld -- but with that precise blocker, which is *sharper* than D455's. `v3_utf8.rs` lands
//! the unit's two public helpers and withholds only its table; `v3_no_rev_avail.rs`,
//! `v3_single_use.rs` and `v3_soa_id.rs` are doc-only withholds. `v3_timespec.rs` and `v3_pku.rs`
//! land their item groups (the i2r printers are reached only through the withheld tables).
//!
//! ## Phase 10.14.1 — the certificate comparison and accessor surface
//!
//! The first sub-subphase of section 6's 10.14, the certificate object graph. It lands the units
//! the rest of the graph builds its comparisons on: `x509_cmp.rs` (`crypto/x509/x509_cmp.c`'s
//! comparison and accessor surface, with `X509_cmp` and the four `X509_add_cert*` functions
//! withheld by name on `X509_check_purpose` and `X509_self_signed`), `x509cset.rs`
//! (`crypto/x509/x509cset.c` whole but for `X509_CRL_up_ref`, already in `x_crl.rs`), and
//! `x509type.rs` (`crypto/x509/x509type.c`). `x509_set.rs` un-withholds `X509_get_version`,
//! `X509_set_version` and `ossl_x509_set1_time`, which the CRL setters need. See the subphases
//! document's section 6 for the decomposition this is the first piece of.
//!
//! ## The canonical structures
//!
//! Each `#[repr(C)]` structure a module is the canonical definition for — [`x_pubkey::X509Pubkey`],
//! [`x509_set::X509SigInfo`], [`x_name::X509Name`]/[`x_name::X509NameEntry`],
//! [`x_x509::X509`]/[`x_x509::X509Cinf`], [`x_crl::X509Crl`]/[`x_crl::X509CrlInfo`]/
//! [`x_crl::X509Revoked`], [`crate::asn1::x_val::X509Val`], [`x_x509a::X509CertAux`],
//! [`pcy_lib::X509PolicyTree`]/[`pcy_lib::X509PolicyLevel`]/[`pcy_lib::X509PolicyNode`]/
//! [`pcy_lib::X509PolicyData`], [`v3_pcia::ProxyPolicy`]/[`v3_pcia::ProxyCertInfoExtension`] and
//! [`v3_ist::IssuerSignTool`], [`v3_pku::PkeyUsagePeriod`], [`v3_lib::X509V3ExtMethod`] and the
//! eleven `v3_timespec::Ossl*` structures -- is the authority's own layout, with its offsets asserted by
//! `core::mem::offset_of!` and a `const _: () = { assert!(...) }` block. The `X.509` numbers come
//! from `courts/layout/measure-x509.c`, compiled against the pinned authority's own internal
//! headers, rather than from the declarations.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod t_x509;
// Phase 10's `crypto/x509/x_attrib.c` -- the `X509_ATTRIBUTE` family, landed early because
// `crypto/asn1/p8_pkey.c`'s template names `X509_ATTRIBUTE_it` (D368).
pub mod x509_att;
pub mod x509_set;
pub mod x_attrib;
// Phase 10.8's object core -- `crypto/x509/x_crl.c`, `x_exten.c`, `x_name.c` and `x_x509.c`.
pub mod x_crl;
pub mod x_exten;
pub mod x_name;
pub mod x_pubkey;
pub mod x_x509;
// Phase 10.10's `crypto/x509/x509_obj.c` -- `X509_NAME_oneline`, the DN printer
// `x_name.c`'s withheld `X509_NAME_print` was blocked on.
pub mod x509_obj;
// Phase 10.11's `crypto/x509/x509_v3.c` -- the X.509v3 extension add/get/count/delete surface.
// `x509rset.c` and `x509name.c` are the subphase's other two `crypto/x509/` units.
pub mod x509_v3;
pub mod x509name;
pub mod x509rset;
// Phase 10.12's `crypto/x509/x509_txt.c` -- the `X509_verify_cert_error_string` table.
pub mod x509_txt;
// Phase 10.12's `crypto/x509/x_x509a.c` -- the `X509_CERT_AUX` item and the trust/alias/key-id
// surface that unblocks `d2i_X509_AUX` in `x_x509.rs`.
pub mod x_x509a;
// Phase 10.12's policy graph: `pcy_lib.rs` lands the tree/level/node accessors and the four
// `pcy_local.h` layouts; `pcy_node.rs` withholds the six internal node operations by name.
pub mod pcy_lib;
pub mod pcy_node;
// Phase 10.12's small `v3_*` leaves. `v3_pcia.rs` lands the two RFC 3820 items; `v3_ist.rs`
// lands the Issuer Sign Tool item; `v3_ia5.rs` and `v3_skid.rs` land their string helpers and
// withhold their tables; the other four withhold their table-only units whole.
pub mod v3_audit_id;
pub mod v3_group_ac;
pub mod v3_ia5;
pub mod v3_ind_iss;
pub mod v3_ist;
pub mod v3_no_ass;
pub mod v3_pcia;
pub mod v3_skid;
// Phase 10.13's remaining leaf extension items. `v3_lib.rs` lands the extension registration
// surface (and withholds the `standard_exts[]`-backed lookup by name); `v3_timespec.rs` and
// `v3_pku.rs` land their item groups; `v3_utf8.rs` lands its two string helpers; the three
// `ASN1_NULL`-only tables withhold whole. See the module docs.
pub mod v3_lib;
pub mod v3_no_rev_avail;
pub mod v3_pku;
pub mod v3_single_use;
pub mod v3_soa_id;
pub mod v3_timespec;
pub mod v3_utf8;
// Phase 10.14.1's certificate comparison and accessor surface -- `crypto/x509/x509_cmp.c`,
// `x509cset.c` and `x509type.c`. The two `_cmp`/`_cset` units build the comparators and CRL
// mutators every other certificate unit calls; `x509_set.rs` completes the three helpers they
// need. See the module docs.
pub mod x509_cmp;
pub mod x509cset;
pub mod x509type;
