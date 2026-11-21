//! Historical path for the secret-bearing heap owner.
//!
//! The storage policy and the [`SecretBuf`] implementation moved to
//! [`crate::runtime::secret`] (T26), so the runtime-wide abstraction no longer
//! depends on the BN subsystem. This module keeps the `bn::secret` path as a
//! thin re-export so existing call sites are unchanged.

#[cfg(test)]
pub(crate) use crate::runtime::secret::drop_probe;
pub(crate) use crate::runtime::secret::SecretBuf;
