//! # openssl-rs
//!
//! A native-Rust, custodian-level reconstruction of the externally observable
//! contract of a pinned OpenSSL distribution.
//!
//! This crate is **not** a wrapper, binding or façade. It does not use OpenSSL
//! or any other cryptographic implementation as a backend. Its objective is that
//! unmodified OpenSSL consumers can compile, link, load, execute and behave
//! correctly with `openssl-rs` substituted for OpenSSL, for an explicitly stated
//! authority, build profile and platform.
//!
//! ## Read this first
//!
//! The governing documents are the Phase 0 constitution in `docs/`:
//!
//! * [`docs/CUSTODIAN_CONTRACT.md`] — mission, the single-crate rule, the
//!   definition of "custodian compatible", and what must never be done.
//! * [`docs/PARITY_MODEL.md`] — what a parity obligation is and how it is
//!   promoted. Read this before interpreting any status.
//! * [`docs/AUTHORITY_POLICY.md`] — the admitted authorities and build profiles.
//! * [`docs/RELEASE_GATES.md`] — the phase order and maturity levels.
//! * [`docs/NON_CLAIMS.md`] — what this project explicitly does **not** claim.
//!
//! ## Current state
//!
//! The crate types no current-state counts. A count written into prose has no
//! generator to correct it, and the one that stood here drifted: it named a
//! phase set and a subsystem set the evidence had long since overtaken. The
//! authoritative state is machine-readable instead. `openssl_rs::status` types
//! only the static, dependency-ordered stratum list; `forensics/STATUS.md`
//! renders the derived states; and `forensics/phase-state.json` is that derived
//! truth, produced from artefact existence by `forensics/tools/phase_state.py`.
//!
//! **No symbol is `PARITY_VERIFIED`.** This is a durable non-claim, not a count:
//! "implemented" means the compiled output defines a symbol with that name, and
//! parity is promoted only by courts, dimension by dimension
//! (`docs/PARITY_MODEL.md`). No such promotion has happened.
//!
//! ## Evidence binding
//!
//! `build.rs` refuses to build without the constitution and the admitted
//! authority registry, and exposes the authority identity to the crate:
//!
//! ```
//! use openssl_rs::status;
//! assert_eq!(status::PRODUCTION_AUTHORITY_ID, "openssl-3.6.4-production");
//! assert_eq!(status::AUTHORITY_ARCHIVE_SHA256.len(), 64);
//! ```
//!
//! A binary therefore cannot exist without naming the authority it was built
//! against.
//!
//! [`docs/CUSTODIAN_CONTRACT.md`]: ../docs/CUSTODIAN_CONTRACT.md
//! [`docs/PARITY_MODEL.md`]: ../docs/PARITY_MODEL.md
//! [`docs/AUTHORITY_POLICY.md`]: ../docs/AUTHORITY_POLICY.md
//! [`docs/RELEASE_GATES.md`]: ../docs/RELEASE_GATES.md
//! [`docs/NON_CLAIMS.md`]: ../docs/NON_CLAIMS.md

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

pub mod aes;
pub mod aria;
pub mod asn1;
// Phase 8's `crypto/asn1_dsa.c`: the DER `DSA-Sig-Value` codec. It has no stratum's plan row and
// arrived with the DSA landing, because `dsa_sign.c`'s `i2d_DSA_SIG`/`d2i_DSA_SIG` are its whole
// body (D342).
pub(crate) mod asn1_dsa;
pub mod blowfish;
pub mod bn;
pub mod camellia;
pub mod cast;
pub mod chacha;
// The generated cipher tables (Phase 8.2). `gen_phase8_cipher_tables.py` derives every
// number from the pinned authority's `crypto/` tree; the modules that read them carry the
// structure.
pub(crate) mod cipher_tables;
pub mod context;
pub(crate) mod der_writer;
pub mod des;
pub mod dh;
pub mod digest;
// Phase 8.6's `crypto/dsa/` substream: the `DSA` object, its method table and its key, generation
// and signature layers. Its first slice is D333's, and its own module documentation names what is
// landed and what waits — the DER `DSA-Sig-Value` codec behind `DSA_sign`/`DSA_verify`, the ASN.1
// method objects and the EVP controls.
pub mod dsa;
pub mod dso;
// Phase 8.7's `crypto/ec/` substream: the built-in curve parameters, and the curve-name
// lookups over them, as the subphase's first slice. Its own module documentation names the
// boundary — the indivisibility of `ec_lib.c`'s group object with the field arithmetic it
// dispatches to, and the `curve_list[]` method column that is the authority coordinate
// deciding it.
pub mod ec;
pub mod evp;
// Phase 8.5's `crypto/ffc/` primitives: the FFC domain-parameter object, its generators and
// validators, and the private-key generator and validators DH and DSA are built on. Every name
// in the subtree is internal, so no ledger row moves when it lands.
//
// The `#[allow(dead_code)]` D330 put on this declaration is **gone, as that entry said it would
// be deleted here**: `dh_lib.c`'s object layer, `dh_key.c`'s key layer, `dh_gen.c`'s generator and
// `dh_check.c`'s validators all landed in D331, so every name in the subtree is now reachable from
// the crate root and an allow would be hiding real dead code rather than marking a boundary. The
// names that are still reached by no crate caller — `ossl_ffc_params_print` and the provider-facing
// accessors — carry their own item-level `#[allow(dead_code)]` with the caller they wait for, in
// `src/ffc/` itself, so the annotation no longer covers a whole unit by accident.
pub(crate) mod ffc;
pub mod ffi;
pub mod hpke;
pub mod idea;
pub mod mac;
// Phase 8's `crypto/ml_kem/` (FIPS 203): the single translation unit the six keymgmt and KEM rows
// are built on. The module is new here; no provider row is published by it yet, so it is
// `pub(crate)` like `crypto/slh_dsa/` was, and reached only by its own tests.
pub(crate) mod ml_kem;
// Phase 8's `crypto/ml_dsa/` (FIPS 204): the eight translation units the six keymgmt and signature
// rows are built on. Like `crypto/ml_kem/` and `crypto/slh_dsa/`, it is `pub(crate)` and reaches no
// provider row yet, so it is exercised by its own tests until its provider units land.
pub(crate) mod ml_dsa;
pub mod modes;
pub mod params;
// Phase 8.7's `crypto/param_build_set.c`: the two-way key-management writers a provider's
// `export()` and `get_params()` methods share. `crypto/ec/ec_backend.c` is the first caller the
// crate reaches; `crypto/ffc/ffc_backend.c`'s withheld `ossl_ffc_params_todata` reaches the same
// four, so the unit lands whole rather than as the reachable subset (D327's rule).
pub(crate) mod param_build_set;
// Phase 8's `crypto/packet.c`: the write-side packet builder. It has no stratum's plan row and
// arrived with the DSA landing, because `dsa_sign.c`'s `i2d_DSA_SIG` is a `WPACKET` program. It is
// transcribed whole, QUIC half and all (D342).
pub(crate) mod packet;
// Phase 10's `crypto/encode_decode/encoder_meth.c`: the `OSSL_ENCODER` method object and the
// `OSSL_FUNC_ENCODER_*` dispatch scan (D360). It lands ahead of its stratum, as `src/ui/` and
// `src/passphrase.rs` did, because the eight Phase-8 printers reach it through `print_pkey`.
pub mod decoder_lib;
pub mod decoder_meth;
pub mod decoder_pkey;
pub mod encoder_lib;
pub mod encoder_meth;
pub mod encoder_pkey;
pub mod passphrase;
pub mod pem;
// Phase 10's `crypto/pkcs12/` substream (D368): `p12_decr.c`'s PBE buffer crypt and the
// ASN.1 decrypt/encrypt pair over it, and `p12_p8d.c`'s two `PKCS8_decrypt` spellings. It
// lands early because `PKCS8_decrypt` is the PKCS#8 reader `pem_read_bio_key_legacy` reaches.
pub mod pkcs12;
pub mod property;
pub mod provider;
// Phase 8's `crypto/quic_vlint.c`: the QUIC variable-length integer codec, transcribed whole
// because `crypto/packet.c`'s QUIC half calls it and `OPENSSL_NO_QUIC` is absent from the admitted
// profile (D342).
pub(crate) mod quic_vlint;
pub mod rand;
pub mod rc2;
pub mod rc4;
pub mod rsa;
pub mod runtime;
pub mod seed;
pub mod selftest;
// Phase 8's `crypto/slh_dsa/` (FIPS 205): the ten-unit SLH-DSA core the twelve keymgmt and twelve
// signature rows are built on. The directory is new here; no provider row is published by this
// module yet, so it is `pub(crate)` and reached only by its own tests.
pub(crate) mod slh_dsa;
pub mod sm4;
// Phase 8's `crypto/sm2/` (D406): the SM2 Z-digest/sign pair and the `SM2_Ciphertext` codec, the
// two crypt units the `SM2` signature and asym-cipher rows publish on.
pub(crate) mod sm2;
pub mod status;
// Phase 8.8's `crypto/x509/` substream (D349): the accessor slices of `x_pubkey.c`,
// `x509_set.c` and `t_x509.c` that the ASN.1 method objects call by name. The directory
// is new here; each module is a partial transcription and names what it withholds in
// `forensics/prerequisites.json`.
pub mod x509;
// Phase 13 staging — `crypto/ui/`: the `UI` program the password path is built on. It lands
// ahead of its stratum because `EVP_read_pw_string_min` (`crypto/evp/evp_key.c:52`) is `UI_new`,
// two `UI_add_*_string` calls, `UI_process` and `UI_free`, and that function is the whole of
// `PEM_def_callback`'s prompting arm — the hinge the next commit opens. D350 records it.
pub mod ui;
