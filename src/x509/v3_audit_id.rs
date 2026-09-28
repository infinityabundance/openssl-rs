//! Phase 10.12 — `crypto/x509/v3_audit_id.c`: the Audit Identity table, **withheld whole**.
//!
//! `crypto/x509/v3_audit_id.c` is twenty lines and its only definition is `ossl_v3_audit_identity`
//! (`:13-20`), the `NID_ac_auditIdentity` `X509V3_EXT_METHOD` row that names
//! `ASN1_ITEM_ref(ASN1_OCTET_STRING)`, `i2s_ASN1_OCTET_STRING` and `s2i_ASN1_OCTET_STRING` (both of
//! which landed in `v3_skid.rs`).
//!
//! **Withheld by name**: `ossl_v3_audit_identity` (`crypto/x509/v3_audit_id.c:13-20`). Its
//! blocker is the one every v3 table in this subphase shares — it is an internal symbol the
//! admitted DSO does not export (`nm -D` shows no `ossl_v3_*`), so the differential plane cannot
//! name it, and its only authority caller is `X509V3_add_standard_extensions`
//! (`crypto/x509/v3_lib.c:127`), which is 10.14's. The table's closure is otherwise landed, so it
//! can be transcribed whole the moment that caller arrives.
//!
//! Nothing is stubbed and no symbol is declared, so the crate's surface is unchanged by this
//! module's existence — it records the withhold rather than filling the unit with a placeholder.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. `ossl_v3_audit_identity` is withheld by name.
