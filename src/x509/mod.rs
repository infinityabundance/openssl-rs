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
//! ## The canonical structures
//!
//! Each `#[repr(C)]` structure a module is the canonical definition for — [`x_pubkey::X509Pubkey`],
//! [`x509_set::X509SigInfo`], [`x_name::X509Name`]/[`x_name::X509NameEntry`],
//! [`x_x509::X509`]/[`x_x509::X509Cinf`], [`x_crl::X509Crl`]/[`x_crl::X509CrlInfo`]/
//! [`x_crl::X509Revoked`] and [`crate::asn1::x_val::X509Val`] — is the authority's own layout, with
//! its offsets asserted by `core::mem::offset_of!` and a `const _: () = { assert!(...) }` block.
//! The numbers come from `courts/layout/measure-x509.c`, compiled against the pinned authority's
//! own internal headers, rather than from the declarations.
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
