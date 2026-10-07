//! Phase 23 — explicit adapters between the historical FFI façade and the canonical internals.
//!
//! A historical object and a modern object are **different layouts**, so there is no cast that
//! is correct: `FacadeEvpMdCtx` is four fields (`digest`, `engine`, `flags`, `md_data`) where the
//! canonical `EvpMdCtx` is nine, and `FacadeHmacCtx` embeds three `EVP_MD_CTX` **by value** and a
//! 128-byte key where the canonical `HmacCtx` holds three `EVP_MD_CTX *` and no key at all. Every
//! adapter here therefore copies fields one at a time and states what it cannot carry across
//! (`docs/ABI_POLICY.md` section 2, `docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7).
//!
//! The adapters are safe: the façade stores the same pointer and integer types the canonical
//! object does, so a field copy needs no `unsafe`. The `#[cfg(test)]` tests below pin the
//! property that makes the whole module necessary — the two representations differ in size, so a
//! blind `transmute`/`cast` of an old object to a modern one would be wrong.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_uchar, c_uint};
use core::ptr;

use super::layout_generated::{FacadeEvpMdCtx, FacadeHmacCtx};
use crate::evp::digest::EvpMdCtx;

/// `HMAC_MAX_MD_CBLOCK` — `crypto/hmac/hmac.h:69` at the 0.9.8zh generation.
pub const HMAC_MAX_MD_CBLOCK_PRE_1_1_0: usize = 128;

/// The canonical state a pre-1.1.0 `HMAC_CTX` carries, translated field by field.
///
/// The historical context embeds its `EVP_MD_CTX`s and its key; the canonical one holds heap
/// `EVP_MD_CTX *`s and keeps the key only in the initialising call. This value carries both, so a
/// caller of the historical contract can see every field the old object had without the canonical
/// type pretending to have them.
pub struct HmacPre1_1_0State {
    /// `const EVP_MD *md`.
    pub md: *const crate::evp::digest::EvpMd,
    /// The running context (`md_ctx` in the historical struct), adapted to the canonical layout.
    pub md_ctx: EvpMdCtx,
    /// The ipad-keyed context (`i_ctx`), adapted to the canonical layout.
    pub i_ctx: EvpMdCtx,
    /// The opad-keyed context (`o_ctx`), adapted to the canonical layout.
    pub o_ctx: EvpMdCtx,
    /// `unsigned int key_length`.
    pub key_length: c_uint,
    /// `unsigned char key[HMAC_MAX_MD_CBLOCK]`.
    pub key: [c_uchar; HMAC_MAX_MD_CBLOCK_PRE_1_1_0],
}

/// Translate a pre-1.1.0 `EVP_MD_CTX` façade into the canonical [`EvpMdCtx`].
///
/// The historical `digest` is the requested method and the canonical context keeps both the
/// requested (`reqdigest`) and the resolved (`digest`) method; a release before 1.1.0 had only
/// the one, so both canonical fields receive it. The provider-era members (`pctx`, `update`,
/// `algctx`, `fetched_digest`) have no pre-1.1.0 counterpart and are left null/default rather than
/// fabricated from an adjacent field.
pub fn evp_md_ctx_from_pre_1_1_0(facade: &FacadeEvpMdCtx) -> EvpMdCtx {
    EvpMdCtx {
        reqdigest: facade.digest,
        digest: facade.digest,
        engine: facade.engine,
        flags: facade.flags,
        md_data: facade.md_data,
        pctx: ptr::null_mut(),
        update: None,
        algctx: ptr::null_mut(),
        fetched_digest: ptr::null_mut(),
    }
}

/// Translate the canonical [`EvpMdCtx`] back into the pre-1.1.0 façade.
///
/// This direction is lossy by construction — it cannot represent the provider-era members, and it
/// takes the requested method rather than the resolved one — which is exactly why it is an
/// explicit function and not a reinterpretation.
pub fn evp_md_ctx_to_pre_1_1_0(ctx: &EvpMdCtx) -> FacadeEvpMdCtx {
    FacadeEvpMdCtx {
        digest: ctx.reqdigest,
        engine: ctx.engine,
        flags: ctx.flags,
        md_data: ctx.md_data,
    }
}

/// Translate a pre-1.1.0 `HMAC_CTX` façade into the canonical state.
///
/// Each embedded `EVP_MD_CTX` goes through [`evp_md_ctx_from_pre_1_1_0`] individually; the three
/// are not assumed to be at any particular relative offset, because the adapter never reads raw
/// memory — it reads the fields the `#[repr(C)]` façade declares, whose offsets the generated
/// assertions pin to the measurement.
pub fn hmac_state_from_pre_1_1_0(facade: &FacadeHmacCtx) -> HmacPre1_1_0State {
    HmacPre1_1_0State {
        md: facade.md,
        md_ctx: evp_md_ctx_from_pre_1_1_0(&facade.md_ctx),
        i_ctx: evp_md_ctx_from_pre_1_1_0(&facade.i_ctx),
        o_ctx: evp_md_ctx_from_pre_1_1_0(&facade.o_ctx),
        key_length: facade.key_length,
        key: facade.key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::digest::EvpMd;
    use crate::mac::hmac::HmacCtx;

    fn facade_md_ctx(digest: *const EvpMd) -> FacadeEvpMdCtx {
        FacadeEvpMdCtx {
            digest,
            engine: ptr::null_mut(),
            flags: 0x4,
            md_data: ptr::null_mut(),
        }
    }

    #[test]
    fn the_md_ctx_adapter_maps_every_historical_field() {
        let digest = 0x1234usize as *const EvpMd;
        let f = facade_md_ctx(digest);
        let c = evp_md_ctx_from_pre_1_1_0(&f);
        assert!(core::ptr::eq(c.reqdigest, digest));
        assert!(core::ptr::eq(c.digest, digest));
        assert!(c.engine.is_null());
        assert_eq!(c.flags, 0x4);
        assert!(c.md_data.is_null());
        // The provider-era members are not fabricated.
        assert!(c.pctx.is_null());
        assert!(c.update.is_none());
        assert!(c.algctx.is_null());
        assert!(c.fetched_digest.is_null());
    }

    #[test]
    fn the_md_ctx_adapter_round_trips_the_shared_fields() {
        let digest = 0x5678usize as *const EvpMd;
        let f = facade_md_ctx(digest);
        let back = evp_md_ctx_to_pre_1_1_0(&evp_md_ctx_from_pre_1_1_0(&f));
        assert!(core::ptr::eq(back.digest, digest));
        assert_eq!(back.flags, f.flags);
        assert!(back.engine.is_null());
    }

    #[test]
    fn the_hmac_adapter_adapts_each_embedded_context() {
        let digest = 0x9abcusize as *const EvpMd;
        let mut key = [0u8; HMAC_MAX_MD_CBLOCK_PRE_1_1_0];
        key[0] = 0xaa;
        key[127] = 0xbb;
        let facade = FacadeHmacCtx {
            md: digest,
            md_ctx: facade_md_ctx(digest),
            i_ctx: facade_md_ctx(ptr::null()),
            o_ctx: facade_md_ctx(ptr::null()),
            key_length: 20,
            key,
        };
        let state = hmac_state_from_pre_1_1_0(&facade);
        assert!(core::ptr::eq(state.md, digest));
        assert!(core::ptr::eq(state.md_ctx.reqdigest, digest));
        assert!(state.i_ctx.reqdigest.is_null());
        assert!(state.o_ctx.reqdigest.is_null());
        assert_eq!(state.key_length, 20);
        assert_eq!(state.key[0], 0xaa);
    }

    /// The property the module exists for: the historical and canonical representations are
    /// different sizes, so no cast between them can be correct.
    #[test]
    fn a_blind_cast_is_impossible() {
        let facade_md = core::mem::size_of::<FacadeEvpMdCtx>();
        let canonical_md = core::mem::size_of::<EvpMdCtx>();
        assert_ne!(facade_md, canonical_md);
        let facade_hmac = core::mem::size_of::<FacadeHmacCtx>();
        let canonical_hmac = core::mem::size_of::<HmacCtx>();
        assert_ne!(facade_hmac, canonical_hmac);
    }
}
