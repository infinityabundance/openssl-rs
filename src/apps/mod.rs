//! Phase 16.4 — `apps/`: the `openssl` CLI, its option parser and its tables.
//!
//! `forensics/tools/phase16_obligations.py`'s `crate_module` maps `apps/<stem>.c`
//! to `src/apps/<stem>.rs`, so this directory is the crate's layout of the
//! authority's `apps/` subtree. The `openssl` executable the Phase-2 link
//! machinery emits is built from [`openssl::run`] rather than the Phase-2
//! scaffold (`forensics/tools/phase2_shell.py`).
//!
//! SPDX-License-Identifier: Apache-2.0

// `apps/errstr.c` is the first of the 52 command bodies Phase 17.1 lands behind the
// dispatcher; see its module header for the recorded `-help` divergence.
pub mod asn1parse;
pub mod ciphers;
pub mod configutl;
pub mod crl;
pub mod crl2pkcs7;
pub mod dhparam;
// 17.1f's seven bodies: dgst, pkcs7, ocsp, ts, speed, fipsinstall and srp.
pub mod dgst;
pub mod dsa;
pub mod dsaparam;
pub mod ec;
pub mod ecparam;
pub mod enc;
pub mod engine;
pub mod errstr;
pub mod fipsinstall;
pub mod gendsa;
pub mod genpkey;
pub mod genrsa;
pub mod info;
pub mod kdf;
// The `apps/lib/apps.c` credential-loader surface (bio_open_default, load_key,
// load_pubkey, load_cert, load_crl, load_keyparams), reduced to its observable;
// 17.1d's command bodies load through it. It is the one non-command module here.
pub mod keyio;
pub mod list;
pub mod mac;
pub mod nseq;
pub mod ocsp;
// The authority's unit is `apps/openssl.c`, so the crate's file is
// `apps/openssl.rs` and the module path is `apps::openssl`; the inception is the
// layout, not a naming accident.
#[allow(clippy::module_inception)]
pub mod openssl;
pub mod opt;
pub mod passwd;
pub mod pkcs7;
pub mod pkcs8;
pub mod pkey;
pub mod pkeyparam;
pub mod pkeyutl;
pub mod prime;
pub mod rand;
pub mod rehash;
pub mod rsa;
pub mod rsautl;
pub mod sess_id;
pub mod skeyutl;
pub mod speed;
pub mod spkac;
pub mod srp;
pub mod storeutl;
// `apps/list.c`'s option-list arm (`-options`) and standard-command listing are
// the surface 16.4's capture measures; `apps/version.c`'s default arm is
// build-independent. Both are pulled forward; see their module headers.
pub mod tables;
pub mod ts;
pub mod verify;
pub mod version;
