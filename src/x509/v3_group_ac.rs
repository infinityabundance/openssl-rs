//! Phase 10.12 — `crypto/x509/v3_group_ac.c`: the Group AC table, **withheld whole**.
//!
//! `crypto/x509/v3_group_ac.c` is 53 lines: four `static` callbacks (`i2r_GROUP_AC` `:17-22`,
//! `r2i_GROUP_AC` `:24-28`, `i2s_GROUP_AC` `:30-33`, `s2i_GROUP_AC` `:35-38`, all answering
//! `ASN1_NULL_new()` or the literal `"NULL"`), and the `ossl_v3_group_ac` `NID_group_ac` row
//! (`:44-53`) that names them.
//!
//! All five are **withheld by name**:
//!
//! * `ossl_v3_group_ac` (`:44-53`) — internal, not exported by the admitted DSO, and its only
//!   authority caller is `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`, 10.14).
//! * `i2r_GROUP_AC` (`:17-22`), `r2i_GROUP_AC` (`:24-28`), `i2s_GROUP_AC` (`:30-33`) and
//!   `s2i_GROUP_AC` (`:35-38`) — `static` callbacks reached only through the withheld table, so
//!   landing them would be dead code with no court.
//!
//! The unit raises nothing, so it is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`.
//! Nothing is stubbed and no symbol is declared.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. The five authority names are withheld by name.
