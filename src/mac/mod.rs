//! Phase 7.6 — the two legacy one-shot MAC interfaces, `crypto/hmac` and `crypto/cmac`.
//!
//! These are **not** the MAC machinery `EVP_MAC` fetches from a provider. `crypto/hmac/hmac.c`
//! and `crypto/cmac/cmac.c` are the pre-3.0 entry points kept for source compatibility; they are
//! written over the *object* interfaces this stratum already built (`EVP_MD`/`EVP_MD_CTX` for
//! HMAC, `EVP_CIPHER`/`EVP_CIPHER_CTX` for CMAC, and `EVP_Q_mac` for the one-shot `HMAC()`), which
//! is what the plan's row 7.6 means by "implemented against the `EVP_MAC`/`EVP_KDF` objects 7.3
//! built". A court for each observes its own surface and not the shared machinery.
//!
//! `ssl3_cbc` belongs here for the other reason a record MAC can: `ssl/record/methods/ssl3_cbc.c`
//! is compiled into **libcrypto** as well as libssl because it is shared with the providers, and
//! `hmac_prov.c` is its caller. It is Phase 8.3's, and the module says why under `ssl/`.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod cmac;
pub mod hmac;
pub mod siphash;
pub mod ssl3_cbc;
