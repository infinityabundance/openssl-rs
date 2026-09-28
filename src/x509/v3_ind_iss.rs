//! Phase 10.12 — `crypto/x509/v3_ind_iss.c`: the Indirect Issuer table, **withheld whole**.
//!
//! `crypto/x509/v3_ind_iss.c` is 53 lines, the same shape as `v3_group_ac.c`: four `static`
//! callbacks (`i2r_INDIRECT_ISSUER` `:17-22`, `r2i_INDIRECT_ISSUER` `:24-28`,
//! `i2s_INDIRECT_ISSUER` `:30-33`, `s2i_INDIRECT_ISSUER` `:35-38`) and the
//! `ossl_v3_indirect_issuer` `NID_indirect_issuer` row (`:44-53`).
//!
//! All five are **withheld by name**, each for the blocker the other v3 tables share:
//!
//! * `ossl_v3_indirect_issuer` (`:44-53`) — internal, not exported by the admitted DSO, its only
//!   authority caller being `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`, 10.14).
//! * `i2r_INDIRECT_ISSUER` (`:17-22`), `r2i_INDIRECT_ISSUER` (`:24-28`), `i2s_INDIRECT_ISSUER`
//!   (`:30-33`) and `s2i_INDIRECT_ISSUER` (`:35-38`) — `static` callbacks reached only through the
//!   withheld table.
//!
//! It is the ITU X.509 (2019) §17.5.2.5 `indirectIssuer` extension, added in the same release as
//! the groupAC and noAssertion leaves. The unit raises nothing, so it is not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. Nothing is stubbed and no symbol is declared.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. The five authority names are withheld by name.
