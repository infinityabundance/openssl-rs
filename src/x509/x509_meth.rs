//! Phase 10.14.2 — `crypto/x509/x509_meth.c`: the `X509_LOOKUP_METHOD` object.
//!
//! `crypto/x509/x509_meth.c` is 157 lines and publishes **all twenty** of its functions: the
//! `X509_LOOKUP_meth_new`/`_free` pair and the nine setters/getters that fill the
//! `X509_LOOKUP_METHOD` vtable (`new_item`, `free`, `init`, `shutdown`, `ctrl`,
//! `get_by_subject`, `get_by_issuer_serial`, `get_by_fingerprint`, `get_by_alias`).
//!
//! **Every one is withheld by name, with one blocker**: the `X509_LOOKUP`/`X509_LOOKUP_METHOD`
//! objects. The method struct is declared in `crypto/x509/x509_local.h` and its `ctrl` and
//! `get_by_*` members are typed by `X509_LOOKUP_ctrl_fn` and the four
//! `X509_LOOKUP_get_by_*_fn` typedefs, whose first parameter is `X509_LOOKUP *`; the crate has
//! no `X509_LOOKUP` type and no `X509_LOOKUP_METHOD` layout. Both are `crypto/x509/x509_lu.c`'s
//! (10.14.10), and every caller of these setters is one of the lookup-table constructors
//! (`by_dir.c`/`by_file.c`/`by_store.c`) that unit's subphase lands. A transcription here would
//! have to invent the layout the object is a vtable for, so the unit is withheld whole rather
//! than stubbed — the shape D454 gave `x509rset.c`.
//!
//! `crypto/x509/x509_meth.c` raises nothing, so it is deliberately **not** listed in
//! `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0
