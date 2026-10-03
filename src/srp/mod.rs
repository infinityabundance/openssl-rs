//! `crypto/srp/` — the RFC 5054 SRP (Secure Remote Password) surface. Phase 12.8.
//!
//! Phase 12.8 lands the SRP verifier and arithmetic surface `srp.h` declares, transcribed
//! from the authority's `crypto/srp/` units and the one `crypto/bn/` unit the arithmetic is
//! built on. The units and what each is:
//!
//! * [`srp_lib`] — `crypto/srp/srp_lib.c`: the client- and server-side arithmetic
//!   (`SRP_Calc_A`/`_B`/`_u`/`_x`/`_server_key`/`_client_key` and their `_ex` forms), the
//!   two verifiers `SRP_Verify_{A,B}_mod_N`, and the RFC 5054 group table accessors
//!   `SRP_check_known_gN_param`/`SRP_get_default_gN`.
//! * [`srp_vfy`] — `crypto/srp/srp_vfy.c`: the `SRP_user_pwd`/`SRP_VBASE` verifier store
//!   (`SRP_user_pwd_*`, `SRP_VBASE_*`) and the verifier creators
//!   `SRP_create_verifier[_BN][_ex]`, plus the SRP-variant base64 codec `t_fromb64`/
//!   `t_tob64` they are built on.
//!
//! The ten RFC 5054 group constants themselves are `crypto/bn/bn_srp.c`, landed
//! crate-internally as [`crate::bn::bn_srp`]; `srp_lib`'s `knowngN[]` table is the only
//! consumer.
//!
//! ## Deprecation
//!
//! Every export here is `OSSL_DEPRECATEDIN_3_0` in the header, and the authority compiles
//! the whole of both units under `OPENSSL_SUPPRESS_DEPRECATED`. The crate transcribes them
//! because `srp.h` is the surface and a drop-in replacement must still resolve the symbols;
//! it is not a recommendation to use SRP.
//!
//! ## What is withheld, and why
//!
//! One `crypto/srp/srp_vfy.c` entry point is **not** landed:
//!
//! * `SRP_VBASE_init` (`crypto/srp/srp_vfy.c:394-510`) reads a verifier file through
//!   `TXT_DB_read` (`:423`) and releases it through `TXT_DB_free` (`:504`), and both are
//!   `txt_db.h`'s — Phase **13**'s, per `forensics/atlas/symbol-ownership.json`. Its private
//!   helpers that only it reaches (`SRP_gN_new_init`, `SRP_gN_free`, `SRP_gN_place_bn`,
//!   `SRP_get_gN_by_id`, `SRP_user_pwd_set_sv`) are transcribed in [`srp_vfy`] but carry an
//!   item-level `#[allow(dead_code)]` naming that withheld caller, because pulling the
//!   `TXT_DB` reader forward to satisfy one deprecated entry point is disproportionate.
//!
//! SPDX-License-Identifier: Apache-2.0

// The authority's struct fields keep the header's spelling (`N`, `gN_cache`, `default_N`),
// exactly as the C struct does; renaming them would make the layout harder to pair with
// `include/openssl/srp.h.in`.
#![allow(non_snake_case)]

use core::ffi::c_char;

use crate::bn::bignum::BigNum;
use crate::runtime::stack::OpenSslStack;

pub(crate) mod srp_lib;
pub(crate) mod srp_vfy;

/// `struct SRP_gN_cache_st` — `include/openssl/srp.h.in:46-49`. A cached RFC 5054 group:
/// the SRP-variant base64 spelling of a `BIGNUM` and the number it decodes to.
#[repr(C)]
pub(crate) struct SrpGNCache {
    /// `char *b64_bn` — the base64 text, owned by the cache row.
    pub(crate) b64_bn: *mut c_char,
    /// `BIGNUM *bn` — the decoded value, owned by the cache row.
    pub(crate) bn: *mut BigNum,
}

/// `struct SRP_user_pwd_st` — `include/openssl/srp.h.in:56-66`. One verifier entry: the
/// identity, the salt and verifier it owns, and the group it borrows.
#[repr(C)]
pub(crate) struct SrpUserPwd {
    /// `char *id` — the username, owned by us.
    pub(crate) id: *mut c_char,
    /// `BIGNUM *s` — the salt, owned by us.
    pub(crate) s: *mut BigNum,
    /// `BIGNUM *v` — the verifier, owned by us.
    pub(crate) v: *mut BigNum,
    /// `const BIGNUM *g` — the generator, **not** owned by us.
    pub(crate) g: *const BigNum,
    /// `const BIGNUM *N` — the modulus, **not** owned by us.
    pub(crate) N: *const BigNum,
    /// `char *info` — free-form user info, owned by us.
    pub(crate) info: *mut c_char,
}

/// `struct SRP_VBASE_st` — `include/openssl/srp.h.in:87-94`. The verifier database: the
/// user stack, the group cache, the optional seed key and the default group.
#[repr(C)]
pub(crate) struct SrpVbase {
    /// `STACK_OF(SRP_user_pwd) *users_pwd` — the users, owned by the base.
    pub(crate) users_pwd: *mut OpenSslStack,
    /// `STACK_OF(SRP_gN_cache) *gN_cache` — the decoded group cache, owned by the base.
    pub(crate) gN_cache: *mut OpenSslStack,
    /// `char *seed_key` — the simulated-user seed, owned by the base; NULL if unset.
    pub(crate) seed_key: *mut c_char,
    /// `const BIGNUM *default_g` — the default generator, borrowed.
    pub(crate) default_g: *const BigNum,
    /// `const BIGNUM *default_N` — the default modulus, borrowed.
    pub(crate) default_N: *const BigNum,
}

/// `struct SRP_gN_st` — `include/openssl/srp.h.in:99-103`. One known RFC 5054 group: its
/// id string and the generator and modulus it borrows.
#[repr(C)]
pub(crate) struct SrpGN {
    /// `char *id` — the group's id, a process-lifetime string constant.
    pub(crate) id: *mut c_char,
    /// `const BIGNUM *g` — the generator, borrowed from [`crate::bn::bn_srp`].
    pub(crate) g: *const BigNum,
    /// `const BIGNUM *N` — the modulus, borrowed from [`crate::bn::bn_srp`].
    pub(crate) N: *const BigNum,
}
