//! Historical path for the fallible-allocation helpers and their test seam.
//!
//! The implementation moved to [`crate::runtime::alloc`] (T26) so the
//! runtime-wide secret storage policy can allocate fallibly without the runtime
//! layer depending on the BN subsystem. This module keeps the `bn::alloc` path
//! as a re-export so existing call sites and test sweeps are unchanged.

#[cfg(test)]
pub(crate) use crate::runtime::alloc::test_fail;
pub(crate) use crate::runtime::alloc::{try_boxed, try_clone_slice, try_reserve, try_zeroed};
