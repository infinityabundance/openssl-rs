//! Phase 8 — `crypto/sm2/`: the SM2 crypt units.
//!
//! `crypto/sm2/` is four files. `sm2_key.c` (SM2's private-key range check) is already landed as
//! [`crate::ec::sm2_key`] because the `SM2` key management row D389 landed calls it. This module
//! carries the other two crypt units:
//!
//! * [`sign`] — `crypto/sm2/sm2_sign.c`, the Z-digest and the sign/verify pair the `SM2` signature
//!   unit publishes on; and
//! * [`crypt`] — `crypto/sm2/sm2_crypt.c`, the `SM2_Ciphertext` DER codec and the encrypt/decrypt
//!   pair the `SM2` asym-cipher unit publishes on.
//!
//! `sm2_err.c` publishes no row and defines no function of its own — it is the generated reason
//! table, and the crate's `src/runtime/err_reasons.rs` already carries all fifteen `SM2_R_*` values
//! (D389). Both units here are transcribed **whole** (D327).
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) mod crypt;
pub(crate) mod sign;
