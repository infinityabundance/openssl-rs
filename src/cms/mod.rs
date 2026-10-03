//! `crypto/cms/` — the Cryptographic Message Syntax container. Phase 12.3.
//!
//! Phase 12.3 lands the whole of `cms.h`'s open surface: the `CMS_ContentInfo` object graph
//! (`cms_lib.c`), the item groups (`cms_asn1.c`), the signer-info and recipient-info engines
//! (`cms_sd.c`, `cms_env.c`), the KARI/KEMRI key-agreement arms (`cms_kari.c`, `cms_kemri.c`),
//! the password recipient (`cms_pwri.c`), the encrypted-content utility (`cms_enc.c`), the
//! attribute stack (`cms_att.c`), the receipt/ESS surface (`cms_ess.c`), the S/MIME bridge and
//! the top-level sign/verify/encrypt/decrypt entry points (`cms_smime.c`) and the BIO/PEM
//! readers (`cms_io.c`).
//!
//! ## What is delegated rather than landed here
//!
//! * The `SMIME_*` codec lives in the authority's `crypto/asn1/asn_mime.c` and is Phase 12.9's
//!   hand-off; `cms_io.rs` names it as the authority's own prototype rather than re-landing it.
//! * The S/MIME capability surface (`CMS_add_smimecap` and friends) reaches
//!   `crypto/x509/x509_att.c`'s `X509_add1_*` helpers, which Phase 11 landed; the citation is
//!   in `cms_sd.rs`.
//! * The ESS item groups (`ESS_SIGNING_CERT` and friends) are Phase 12.7's; `cms_ess.rs` carries
//!   the `CMS_ReceiptRequest` surface, whose defining unit is `cms_ess.c`.
//!
//! ## The bytes are the contract
//!
//! Every item group is the authority's own `ASN1_*` template in its own order, and
//! `docs/PHASE-12-SUBPHASES.md` §3.1 is why a round trip is not enough: the differential court
//! compares the container's DER byte for byte against the authority's.
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) mod cms_asn1;
pub(crate) mod cms_att;
pub(crate) mod cms_enc;
pub(crate) mod cms_env;
pub(crate) mod cms_ess;
pub(crate) mod cms_io;
pub(crate) mod cms_kari;
pub(crate) mod cms_kemri;
pub(crate) mod cms_lib;
pub(crate) mod cms_pwri;
pub(crate) mod cms_sd;
pub(crate) mod cms_smime;

// The defining units the authority keeps outside the open 153: the per-key envelope arm
// (`cms_dh.c`, `cms_ec.c`, `cms_rsa.c`, `cms_kem.c`) and the DigestedData content builder
// (`cms_dd.c`). They define no export the atlas attributes to this stratum, so the ledger does not
// name them; they are pulled forward because `cms_env.c` and `cms_sd.c` reach them and they are
// cms-local. `cms_cd.c` is absent: the authority is built `OPENSSL_NO_ZLIB`, so that unit defines
// nothing and `CMS_compress`/`CMS_uncompress` are the refusal arms (`cms_smime.c:1041-1052`).
pub(crate) mod cms_dd;
pub(crate) mod cms_dh;
pub(crate) mod cms_ec;
pub(crate) mod cms_kem;
pub(crate) mod cms_rsa;
