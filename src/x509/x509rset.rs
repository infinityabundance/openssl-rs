//! Phase 10.11 — `crypto/x509/x509rset.c`: the `X509_REQ` field setters, **withheld whole**.
//!
//! `crypto/x509/x509rset.c` is three functions, and **all three are withheld by name** because
//! the frontier falls at the unit's first line: each writes through `X509_REQ`'s
//! `req_info` sub-structure (`x->req_info.enc.modified`, `x->req_info.version`,
//! `x->req_info.subject`, `x->req_info.pubkey`), and `struct X509_req_st` /
//! `struct X509_req_info_st` are declared in `crypto/x509/x509_local.h` and built by
//! `crypto/x509/x509_req.c`, which is 10.14's. The crate has no `X509Req` type to name, so no
//! part of this unit can be typed, let alone driven.
//!
//! * `X509_REQ_set_version` (`crypto/x509/x509rset.c:18-26`) — blocked on `X509_REQ`
//!   (`crypto/x509/x509_req.c`), which is 10.14's; it raises
//!   `ERR_LIB_X509`/`ERR_R_PASSED_INVALID_ARGUMENT` at `:21` for a NULL request or a version
//!   other than `X509_REQ_VERSION_1`.
//! * `X509_REQ_set_subject_name` (`:28-34`) — blocked on `X509_REQ` (10.14); its callee
//!   `X509_NAME_set` is landed (`src/x509/x_name.rs`), but it is reached only through a
//!   `req_info.subject` field the crate cannot name.
//! * `X509_REQ_set_pubkey` (`:36-42`) — blocked on `X509_REQ` (10.14); its callee
//!   `X509_PUBKEY_set` is landed (`src/x509/x_pubkey.rs`), with the same field blocker.
//!
//! When 10.14 lands `crypto/x509/x509_req.c` and the two structures, all three functions can be
//! transcribed directly, because both of their non-field callees are already here. Nothing is
//! stubbed and no symbol is declared, so the crate's surface is unchanged by this module's
//! existence -- it records the withhold rather than filling the unit with a placeholder.
//!
//! SPDX-License-Identifier: Apache-2.0

// No items: see the module documentation. The three authority functions are withheld by name.
