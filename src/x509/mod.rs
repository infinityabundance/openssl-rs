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
//! src/x509/x_all.rs      <-  crypto/x509/x_all.c        (10.14.2)
//! src/x509/x509_def.rs   <-  crypto/x509/x509_def.c     (10.14.2)
//! src/x509/x509_meth.rs  <-  crypto/x509/x509_meth.c    (10.14.2, doc-only withholds)
//! src/x509/x509spki.rs   <-  crypto/x509/x509spki.c     (10.14.2)
//! src/asn1/x_spki.rs     <-  crypto/asn1/x_spki.c       (10.14.2)
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
//! ## Phase 10.14.2 — the certificate encode/decode faces and the defaults
//!
//! The second sub-subphase. `x_all.rs` lands `crypto/x509/x_all.c`'s reachable functions — the
//! sign/verify doors, the certificate/CRL and PKCS#8/PUBKEY/private-key/public-key and
//! RSA/DSA/EC `_fp`/`_bio` faces, and the digest family — with the `X509_REQ`, `X509_ACERT`,
//! PKCS#7, HTTP and `PKCS7_ISSUER_AND_SERIAL` faces withheld by name. `x509_def.rs` lands the two
//! environment-variable names and withholds the four forensic-`OPENSSLDIR` paths. `x509spki.rs`
//! and `src/asn1/x_spki.rs` land the Netscape SPKI object and its four convenience functions.
//! `x509_meth.rs` withholds `crypto/x509/x509_meth.c` whole on the missing `X509_LOOKUP` type.
//! `x509_set.rs` and `x_pubkey.rs` un-withhold `X509_get0_extensions` and
//! `X509_get0_pubkey_bitstr`, which `X509_sign` and `X509_pubkey_digest` read. Each module's own
//! doc names its withholds and blockers.
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
// Phase 10.14.2's certificate encode/decode faces, the defaults, the Netscape SPKI surface and
// the withheld lookup-method unit. See the module docs.
pub mod x509_def;
pub mod x509_meth;
pub mod x509spki;
pub mod x_all;
// Phase 10.14.4's `crypto/x509/v3_genn.c` -- the `GENERAL_NAME`/`GENERAL_NAMES` items and the
// nine hand-written accessors, the hub every extension table and `v3_utl.rs`'s address checks
// were measured to wait on. It lands whole; `v3_ncons.c` and `v3_conf.c` are 10.14.4's other two
// units and are withheld with their measured blockers. See the module docs.
pub mod v3_genn;
// Phase 10.14.3's `crypto/x509/v3_utl.c` -- the X.509v3 extension string/value utilities,
// landed at function granularity: 31 of its 51 hand-written functions are transcribed and 20 are
// withheld by name (nine on an unlanded callee, eleven closure-complete but unreachable).
// It is the keystone the forty-odd `v3_*` tables and `v3_prn.c` wait on. See the module docs.
pub mod v3_utl;
// Phase 10.14.5's `crypto/x509/x509_ext.c` -- the `X509`/`X509_CRL`/`X509_REVOKED` extension
// accessors, landed at function granularity: 21 of the unit's 27 containers land and the six
// `*_get_ext_d2i`/`*_add1_ext_i2d` functions are withheld by name behind `v3_lib.rs`'s
// `standard_exts[]`-backed lookups. Three of its names are three of the six
// `ossl_x509v3_cache_extensions` was measured to need. See the module docs.
pub mod x509_ext;
// Phase 10.14.6's `crypto/x509/v3_crld.c` -- landed at function granularity: the
// `DIST_POINT_NAME` layout and one export, `DIST_POINT_set_dpname`, land; the five extension
// tables and every section/printer callback are withheld by name behind the same
// `standard_exts[]`/`v3_conf`/`v3_san` blockers. `DIST_POINT_set_dpname` is one of the two
// non-`x509_ext.c` names `ossl_x509v3_cache_extensions` needs (`ossl_x509_init_sig_info` being
// the other). See the module docs.
pub mod v3_crld;
// Phase 10.14.6's `crypto/x509/v3_bcons.c` -- the `BASIC_CONSTRAINTS` item group, landed so its
// `BASIC_CONSTRAINTS_free` (the seventh name `ossl_x509v3_cache_extensions` was measured to need)
// is real; `ossl_v3_bcons` and the two callbacks are withheld by name behind `standard_exts[]`.
// See the module docs.
pub mod v3_bcons;
// Phase 10.14's table layer -- the `ossl_v3_*` rows themselves. Each module lands its unit's row,
// its item group's callbacks and its `i2s_`/`s2i_`/`i2r_`/`r2i_` printers; only the published
// `standard_exts[]` and the six `v3_lib.rs` lookup names stay withheld until all 63 tables exist
// (D456/D463). See `docs/PHASE-10-SUBPHASES.md` section 7.
pub mod v3_enum;
pub mod v3_int;
// Phase 10.14.6's `crypto/x509/v3_bitst.c` -- the `keyUsage` and `nsCertType` tables, landed
// whole. See the module docs.
pub mod v3_bitst;
// Phase 10.14.4's `crypto/x509/v3_conf.c` -- the extension-configuration surface. This slice lands
// its config-value layer (`X509V3_get_section`/`_section_free`, the `nconf`/`lhash` method tables
// and the four setters) and withholds the extension-building chain by name behind
// `X509V3_EXT_get_nid`. The `X509V3_CTX` and `X509V3_CONF_METHOD` layouts live here. See the
// module docs.
pub mod v3_conf;
// Phase 10.14.6's `crypto/x509/v3_san.c` -- the general-name printers. This slice lands
// `GENERAL_NAME_print`, `i2v_GENERAL_NAME` and `i2v_GENERAL_NAMES` (the widest hub D464 measured)
// and withholds the `v2i` cluster by name behind `ASN1_generate_v3`. See the module docs.
pub mod v3_san;
// The 10.14 closure-ready table units this slice lands: `v3_extku.c` (four rows),
// `v3_pmaps.c`, `v3_pcons.c`, `v3_battcons.c`, `v3_tlsf.c` and `v3_iobo.c`; and the table half of
// `v3_bcons.c`. Each lands its item group(s), callbacks and `OSSL_V3_EXT_METHOD` row, and
// withholds only the published `standard_exts[]` and the six `v3_lib.rs` lookup names (D456). See
// the module docs and `docs/PHASE-10-SUBPHASES.md` section 7.
pub mod v3_battcons;
pub mod v3_extku;
pub mod v3_info;
pub mod v3_iobo;
pub mod v3_pcons;
pub mod v3_pmaps;
pub mod v3_sda;
pub mod v3_tlsf;

// The 10.14 closure-ready table units, second batch: `v3_crld.c` (six rows), `v3_asid.c`,
// `v3_timespec.c`, `v3_cpols.c`, `v3_skid.c` and `v3_sxnet.c`. Each lands its item group(s),
// callbacks and `OSSL_V3_EXT_METHOD` row(s), and withholds only the published `standard_exts[]` and
// the six `v3_lib.rs` lookup names (D456). See the module docs and docs/PHASE-10-SUBPHASES.md section 7.
//
// `v3_crld`, `v3_skid` and `v3_timespec` already had declarations above (their 10.13/10.14.6
// blocks); only the three units whose files are new to this batch are declared here.
pub mod v3_asid;
pub mod v3_cpols;
pub mod v3_sxnet;

// The 10.14 closure-ready table units, third batch: `v3_admis.c`, `v3_pci.c`, `v3_ac_tgt.c`,
// `v3_attrdesc.c`, `v3_attrmap.c`, `v3_aaa.c` and `v3_usernotice.c` (each one table), plus the
// table and the two callbacks of `v3_ist.c` (whose item groups landed at 10.12). Each withholds
// only the published `standard_exts[]` and the six `v3_lib.rs` lookup names (D456). See the module
// docs and docs/PHASE-10-SUBPHASES.md section 7.
pub mod v3_aaa;
pub mod v3_ac_tgt;
pub mod v3_admis;
pub mod v3_attrdesc;
pub mod v3_attrmap;
pub mod v3_pci;
pub mod v3_usernotice;

// The 10.14 blocked-unit pivots, first batch: `crypto/x509/v3_addr.c` (whose only blocker is the
// naming shim `ossl_asn1_string_set_bits_left`, landed as `asn1::bitstr::set_bits_left`) and
// `crypto/x509/v3_rolespec.c` (blocked on `ossl_serial_number_print`, landed alongside it in
// `src/x509/t_x509.rs`). Each withholds only the published `standard_exts[]` and the six
// `v3_lib.rs` lookup names (D456). See the module docs and docs/PHASE-10-SUBPHASES.md section 7.
pub mod v3_addr;
pub mod v3_rolespec;

// The 10.14 blocked-unit pivots, second batch: `crypto/x509/v3_akeya.c` (the `AUTHORITY_KEYID`
// item group, the blocker `crypto/x509/v3_akid.c` names) and `crypto/x509/v3_authattid.c` (whose
// one blocker is `OSSL_ISSUER_SERIAL_it`, defined in `v3_ac_tgt.rs`). Each withholds only the
// published `standard_exts[]` and the six `v3_lib.rs` lookup names (D456).
pub mod v3_akeya;
pub mod v3_authattid;
