//! Phase 10.13 — `crypto/x509/v3_single_use.c`: the singleUse table, **withheld whole**.
//!
//! `crypto/x509/v3_single_use.c` is 53 lines: four `static` callbacks (`i2r_SINGLE_USE`
//! `:17-22`, `r2i_SINGLE_USE` `:24-28`, `i2s_SINGLE_USE` `:30-33`, `s2i_SINGLE_USE` `:35-38`, all
//! answering `ASN1_NULL_new()` or the literal `"NULL"`), and the `ossl_v3_single_use`
//! `NID_single_use` row (`:44-53`) that names them over `ASN1_ITEM_ref(ASN1_NULL)`.
//!
//! All five are **withheld by name**:
//!
//! * `ossl_v3_single_use` (`:44-53`) — internal, and the admitted DSO exports no `ossl_v3_*`
//!   symbol (`nm -D`), so no differential arm can name it. Its only authority caller is
//!   `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`), which lands in
//!   [`crate::x509::v3_lib`]. The dispatch that could reach it by NID -- `X509V3_EXT_get_nid` --
//!   is withheld there because it searches `standard_exts[]` (`standard_exts.h:15-95`), which
//!   names ~63 `ossl_v3_*` tables from units this subphase does not own. See
//!   [`crate::x509::v3_lib`].
//! * `i2r_SINGLE_USE` (`:17-22`), `r2i_SINGLE_USE` (`:24-28`), `i2s_SINGLE_USE` (`:30-33`) and
//!   `s2i_SINGLE_USE` (`:35-38`) — `static` callbacks reached only through the withheld table, so
//!   landing them would be dead code with no court.
//!
//! The unit raises nothing, so it is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`.
//! Nothing is stubbed and no symbol is declared.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. The five authority names are withheld by name.
