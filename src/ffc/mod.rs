//! Phase 8 — `crypto/ffc/`, the finite-field cryptography DH and DSA are built on.
//!
//! This module is Phase 8.5's, and it is the first link of the chain D329 recorded: the
//! `crypto/ffc/` primitives, then `crypto/dh/dh_lib.c`'s object layer, then `dh_key.c` and
//! `dh_gen.c`. Nothing here is a `dh.h` export — every name in this subtree is internal — so
//! this unit moves no ledger row and no court-coverage arm; what says it landed is the body
//! of the work and the unit tests beside each transcription.
//!
//! ## What the unit is, and how the set was read from the authority rather than from a list
//!
//! D329 planned "about 1,700 lines across `ffc_params.c`, `ffc_key_generate.c`,
//! `ffc_key_validate.c`, `ffc_params_validate.c` and `ffc_params_generate.c`", and that is
//! the set this module lands — taken from the authority's call graph rather than from the
//! plan's prose. `crypto/dh/dh_key.c`'s `ossl_dh_generate_key` reaches
//! [`ossl_ffc_generate_private_key`] (`dh_key.c:320`, `:361`) and
//! [`ossl_ffc_params_simple_validate`] (`:353`); `dh_gen.c` reaches
//! [`ossl_ffc_params_FIPS186_4_generate`] and [`ossl_ffc_params_FIPS186_2_generate`];
//! `dh_check.c` reaches [`ossl_ffc_params_FIPS186_4_validate`], [`ossl_ffc_validate_public_key`],
//! [`ossl_ffc_validate_public_key_partial`] and [`ossl_ffc_validate_private_key`];
//! `dh_lib.c`, `dh_asn1.c` and `dh_ameth.c` reach the `ffc_params.c` lifecycle, accessors,
//! copy, comparison and print. `simple_validate` in turn reaches `FIPS186_4_gen_verify` and
//! its `generate_p` / `generate_q_fips186_4` / `generate_canonical_g` /
//! `generate_unverifiable_g` helpers, plus the FIPS 186-2 twin for the `VALIDATE_LEGACY`
//! flag path.
//!
//! **`crypto/ffc/ffc_dh.c` is transcribed in this subtree, and D332 is when it landed.**
//! [`dh`] carries `dh_named_groups[]` — fourteen rows read out of the file with its three
//! macros expanded — and its eight entry points, over the thirty-two `ossl_bignum_*`
//! constants in [`crate::bn::dh`] and the generated [`crate::bn::dh_data`]. D329 and D330
//! both named that data as a separable follow-up whose values only a comparison with the
//! authority can check; `forensics/tools/gen_bn_dh.py` is that comparison, and the unit
//! tests beside the table are what assert its rows.
//!
//! **One `crypto/ffc/` unit is still deliberately not transcribed, and it is named with
//! the reach that would be needed.** `crypto/ffc/ffc_backend.c`
//! (`ossl_ffc_params_fromdata`) is reached by `crypto/dh/dh_backend.c`, which is not on the
//! `dh_lib.c`/`dh_key.c`/`dh_gen.c`/`dh_check.c` path, and it calls
//! `crypto/param_build_set.c`'s four `ossl_param_build_set_*` — a unit with no crate module
//! and no implementation. So `ffc_backend.c` has **no module here**, which is D327's
//! `rsa_sp800_56b_check.c` precedent rather than a half-landing, and `ossl_ffc_params_todata`
//! is withheld for the same reason and is the one function of a transcribed unit that is not
//! here.
//!
//! ## The struct, and why its shape is a measurement rather than a reading
//!
//! [`FfcParams`] is `crypto/ffc/ffc_params.c`'s `FFC_PARAMS` (`include/internal/ffc.h:90-123`)
//! and it is `repr(C)` for a reason the next slice makes load-bearing: `struct dh_st` embeds
//! it **by value** (`crypto/dh/dh_local.h:23`), so `DH_new`'s allocation size and every
//! accessor's offset are downstream of this layout. `ossl_ffc_params_init` also memsets
//! `sizeof(*params)`, so a struct that is a member too wide zeroes past its own object.
//! `courts/layout/measure-ffc-params.c` compiles against the authority's own internal header
//! and prints the size and all fourteen offsets; the unit test
//! `the_ffc_params_struct_is_the_authoritys_shape` asserts them.
//!
//! The one offset that cannot be reasoned about from the declaration is `mdname`: `flags` is a
//! four-byte `unsigned int` at 64 and `mdname` is a pointer, so the four bytes at 68..72 are
//! padding and `mdname` sits at 72 rather than the 68 a packed reading would give.

pub(crate) mod dh;
pub(crate) mod key_generate;
pub(crate) mod key_validate;
pub(crate) mod params;
pub(crate) mod params_generate;
pub(crate) mod params_validate;

use core::ffi::{c_char, c_int, c_uint};

use crate::bn::bignum::BigNum;

/// `FFC_UNVERIFIABLE_GINDEX` — `include/internal/ffc.h:23`.
///
/// The value `gindex` carries when canonical generation of g is not used. It is a
/// *sentinel* rather than a loop bound: `ossl_ffc_params_FIPS186_4_gen_verify` selects the
/// canonical arm only when `gindex != -1`, so a caller that wants an unverifiable g leaves
/// this in place and gets the `h`-search instead.
pub(crate) const FFC_UNVERIFIABLE_GINDEX: c_int = -1;

/// `FFC_PARAM_TYPE_DSA` — `include/internal/ffc.h:26`.
pub(crate) const FFC_PARAM_TYPE_DSA: c_int = 0;
/// `FFC_PARAM_TYPE_DH` — `include/internal/ffc.h:27`.
pub(crate) const FFC_PARAM_TYPE_DH: c_int = 1;

/// `FFC_PARAM_MODE_VERIFY` — `include/internal/ffc.h:33`.
pub(crate) const FFC_PARAM_MODE_VERIFY: c_int = 0;
/// `FFC_PARAM_MODE_GENERATE` — `include/internal/ffc.h:34`.
pub(crate) const FFC_PARAM_MODE_GENERATE: c_int = 1;

/// `FFC_PARAM_RET_STATUS_FAILED` — `include/internal/ffc.h:37`.
pub(crate) const FFC_PARAM_RET_STATUS_FAILED: c_int = 0;
/// `FFC_PARAM_RET_STATUS_SUCCESS` — `include/internal/ffc.h:38`.
pub(crate) const FFC_PARAM_RET_STATUS_SUCCESS: c_int = 1;
/// `FFC_PARAM_RET_STATUS_UNVERIFIABLE_G` — `include/internal/ffc.h:40`.
///
/// Returned when validating and g is only partially verifiable. It is a **third** answer, not
/// a failure: `ossl_ffc_params_simple_validate` turns it and `SUCCESS` into the same `1`.
pub(crate) const FFC_PARAM_RET_STATUS_UNVERIFIABLE_G: c_int = 2;

/// `FFC_PARAM_FLAG_VALIDATE_PQ` — `include/internal/ffc.h:43`.
pub(crate) const FFC_PARAM_FLAG_VALIDATE_PQ: c_uint = 0x01;
/// `FFC_PARAM_FLAG_VALIDATE_G` — `include/internal/ffc.h:44`.
pub(crate) const FFC_PARAM_FLAG_VALIDATE_G: c_uint = 0x02;
/// `FFC_PARAM_FLAG_VALIDATE_PQG` — `include/internal/ffc.h:45-46`, the union of the two above.
pub(crate) const FFC_PARAM_FLAG_VALIDATE_PQG: c_uint =
    FFC_PARAM_FLAG_VALIDATE_PQ | FFC_PARAM_FLAG_VALIDATE_G;
/// `FFC_PARAM_FLAG_VALIDATE_LEGACY` — `include/internal/ffc.h:47`.
///
/// Selects the FIPS 186-2 validator. `ffc_params_validate.c` guards that arm with
/// `#ifndef FIPS_MODULE`, so it is this profile's.
pub(crate) const FFC_PARAM_FLAG_VALIDATE_LEGACY: c_uint = 0x04;

/// `FFC_CHECK_P_NOT_PRIME` — `include/internal/ffc.h:53`.
pub(crate) const FFC_CHECK_P_NOT_PRIME: c_int = 0x00001;
/// `FFC_CHECK_P_NOT_SAFE_PRIME` — `include/internal/ffc.h:54`.
// Unreached in this crate: the reader is in `crypto/dsa/` and the provider keymgmt paths. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) const FFC_CHECK_P_NOT_SAFE_PRIME: c_int = 0x00002;
/// `FFC_CHECK_UNKNOWN_GENERATOR` — `include/internal/ffc.h:55`.
// Unreached in this crate: the reader is in `crypto/dsa/dsa_check.c` and the FIPS generator's
// refusal path. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) const FFC_CHECK_UNKNOWN_GENERATOR: c_int = 0x00004;
/// `FFC_CHECK_NOT_SUITABLE_GENERATOR` — `include/internal/ffc.h:56`.
// Unreached in this crate: the reader is in `crypto/dsa/dsa_check.c` and `crypto/ffc/ffc_backend.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) const FFC_CHECK_NOT_SUITABLE_GENERATOR: c_int = 0x00008;
/// `FFC_CHECK_Q_NOT_PRIME` — `include/internal/ffc.h:57`.
pub(crate) const FFC_CHECK_Q_NOT_PRIME: c_int = 0x00010;
/// `FFC_CHECK_INVALID_Q_VALUE` — `include/internal/ffc.h:58`.
pub(crate) const FFC_CHECK_INVALID_Q_VALUE: c_int = 0x00020;
/// `FFC_CHECK_INVALID_J_VALUE` — `include/internal/ffc.h:59`.
// Unreached in this crate: the reader is in `crypto/dsa/dsa_check.c` and `crypto/dh/dh_asn1.c`. Kept because the unit around it
// is whole (D327's rule); D330's subtree-wide allow on `pub(crate) mod ffc;` is deleted in D331.
#[allow(dead_code)]
pub(crate) const FFC_CHECK_INVALID_J_VALUE: c_int = 0x00040;
// `0x80` and `0x100` are reserved by `include/openssl/dh.h` for check bits that are not
// relevant to FFC (`include/internal/ffc.h:61-64`), so the enumeration skips them.
/// `FFC_CHECK_MISSING_SEED_OR_COUNTER` — `include/internal/ffc.h:66`.
pub(crate) const FFC_CHECK_MISSING_SEED_OR_COUNTER: c_int = 0x00200;
/// `FFC_CHECK_INVALID_G` — `include/internal/ffc.h:67`.
pub(crate) const FFC_CHECK_INVALID_G: c_int = 0x00400;
/// `FFC_CHECK_INVALID_PQ` — `include/internal/ffc.h:68`.
pub(crate) const FFC_CHECK_INVALID_PQ: c_int = 0x00800;
/// `FFC_CHECK_INVALID_COUNTER` — `include/internal/ffc.h:69`.
pub(crate) const FFC_CHECK_INVALID_COUNTER: c_int = 0x01000;
/// `FFC_CHECK_P_MISMATCH` — `include/internal/ffc.h:70`.
pub(crate) const FFC_CHECK_P_MISMATCH: c_int = 0x02000;
/// `FFC_CHECK_Q_MISMATCH` — `include/internal/ffc.h:71`.
pub(crate) const FFC_CHECK_Q_MISMATCH: c_int = 0x04000;
/// `FFC_CHECK_G_MISMATCH` — `include/internal/ffc.h:72`.
pub(crate) const FFC_CHECK_G_MISMATCH: c_int = 0x08000;
/// `FFC_CHECK_COUNTER_MISMATCH` — `include/internal/ffc.h:73`.
pub(crate) const FFC_CHECK_COUNTER_MISMATCH: c_int = 0x10000;
/// `FFC_CHECK_BAD_LN_PAIR` — `include/internal/ffc.h:74`.
pub(crate) const FFC_CHECK_BAD_LN_PAIR: c_int = 0x20000;
/// `FFC_CHECK_INVALID_SEED_SIZE` — `include/internal/ffc.h:75`.
pub(crate) const FFC_CHECK_INVALID_SEED_SIZE: c_int = 0x40000;

/// `FFC_ERROR_PUBKEY_TOO_SMALL` — `include/internal/ffc.h:78`.
pub(crate) const FFC_ERROR_PUBKEY_TOO_SMALL: c_int = 0x01;
/// `FFC_ERROR_PUBKEY_TOO_LARGE` — `include/internal/ffc.h:79`.
pub(crate) const FFC_ERROR_PUBKEY_TOO_LARGE: c_int = 0x02;
/// `FFC_ERROR_PUBKEY_INVALID` — `include/internal/ffc.h:80`.
pub(crate) const FFC_ERROR_PUBKEY_INVALID: c_int = 0x04;
/// `FFC_ERROR_NOT_SUITABLE_GENERATOR` — `include/internal/ffc.h:81`.
pub(crate) const FFC_ERROR_NOT_SUITABLE_GENERATOR: c_int = 0x08;
/// `FFC_ERROR_PRIVKEY_TOO_SMALL` — `include/internal/ffc.h:82`.
pub(crate) const FFC_ERROR_PRIVKEY_TOO_SMALL: c_int = 0x10;
/// `FFC_ERROR_PRIVKEY_TOO_LARGE` — `include/internal/ffc.h:83`.
pub(crate) const FFC_ERROR_PRIVKEY_TOO_LARGE: c_int = 0x20;
/// `FFC_ERROR_PASSED_NULL_PARAM` — `include/internal/ffc.h:84`.
pub(crate) const FFC_ERROR_PASSED_NULL_PARAM: c_int = 0x40;

/// `struct ffc_params_st` — `include/internal/ffc.h:90-123`.
///
/// Finite field cryptography domain parameters, shared by DH and DSA and defined by FIPS
/// 186-4 Appendices A and B. Two things about the shape are load-bearing rather than
/// descriptive: `struct dh_st` embeds this **by value** (`crypto/dh/dh_local.h:23`) and
/// `struct dsa_st` does the same, so the size decides both objects' allocation sizes; and
/// `ossl_ffc_params_init` memsets the whole struct, so the padding bytes at 68..72 are
/// written by the authority too.
///
/// `mdname` and `mdprops` are **borrowed** `const char *` throughout the authority: the
/// params object never owns them, `ossl_ffc_set_digest` stores the caller's pointer, and
/// `ossl_ffc_params_copy` copies the two pointers rather than the strings — which is why a
/// caller's digest name must outlive every copy of the params it set it on.
#[repr(C)]
pub(crate) struct FfcParams {
    /// `p` — the prime modulus.
    pub p: *mut BigNum,
    /// `q` — the subgroup order. Optional for some DH groups.
    pub q: *mut BigNum,
    /// `g` — the generator.
    pub g: *mut BigNum,
    /// `j` — the DH X9.42 optional subgroup factor `j >= 2` where `p = j * q + 1`.
    pub j: *mut BigNum,
    /// `seed` — required for the FIPS 186-4 validation of `p`, `q` and optionally canonical `g`.
    pub seed: *mut u8,
    /// `seedlen` — if zero, the hash size is used as the seed length.
    pub seedlen: usize,
    /// `pcounter` — the counter `p` was found at. `-1` means "not set".
    pub pcounter: c_int,
    /// `nid` — the identity of a named group, or `NID_undef`.
    pub nid: c_int,
    /// `gindex` — required for canonical generation and validation of `g`; `-1` selects
    /// unverifiable `g`.
    pub gindex: c_int,
    /// `h` — the loop counter the unverifiable-`g` search finished at.
    pub h: c_int,
    /// `flags` — the `FFC_PARAM_FLAG_*` bit set.
    pub flags: c_uint,
    /// `mdname` — the digest to use for generation or validation, or NULL to choose one from `N`.
    pub mdname: *const c_char,
    /// `mdprops` — the property query for that digest.
    pub mdprops: *const c_char,
    /// `keylength` — the default key length for known named groups, from RFC 7919.
    pub keylength: c_int,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    /// `sizeof(FFC_PARAMS)` and all fourteen member offsets, measured by
    /// `courts/layout/measure-ffc-params.c`.
    ///
    /// The offsets are asserted and not only the size, because the two spellings of a wrong
    /// order are different bugs: a swap of `mdname` and `mdprops` keeps the size and moves
    /// two borrowed pointers, and a `flags` read as pointer-sized moves `mdname` from 72 to
    /// 80 and grows the struct by eight — which `struct dh_st`'s allocation would then carry.
    #[test]
    fn the_ffc_params_struct_is_the_authoritys_shape() {
        assert_eq!(size_of::<FfcParams>(), 96);
        assert_eq!(align_of::<FfcParams>(), 8);
        assert_eq!(core::mem::offset_of!(FfcParams, p), 0);
        assert_eq!(core::mem::offset_of!(FfcParams, q), 8);
        assert_eq!(core::mem::offset_of!(FfcParams, g), 16);
        assert_eq!(core::mem::offset_of!(FfcParams, j), 24);
        assert_eq!(core::mem::offset_of!(FfcParams, seed), 32);
        assert_eq!(core::mem::offset_of!(FfcParams, seedlen), 40);
        assert_eq!(core::mem::offset_of!(FfcParams, pcounter), 48);
        assert_eq!(core::mem::offset_of!(FfcParams, nid), 52);
        assert_eq!(core::mem::offset_of!(FfcParams, gindex), 56);
        assert_eq!(core::mem::offset_of!(FfcParams, h), 60);
        assert_eq!(core::mem::offset_of!(FfcParams, flags), 64);
        assert_eq!(core::mem::offset_of!(FfcParams, mdname), 72);
        assert_eq!(core::mem::offset_of!(FfcParams, mdprops), 80);
        assert_eq!(core::mem::offset_of!(FfcParams, keylength), 88);
    }

    /// The flag set is the one the header defines, and `P`/`G`/`PQG` are **not** independent:
    /// `FFC_PARAM_FLAG_VALIDATE_PQG` is the union, and three call sites compare it as a whole
    /// (`ffc_params_generate.c:733`, `:989`). A transcription that made `PQG` a third bit
    /// would make both `VALIDATE_PQG` masks fire on a params object carrying only `PQ`.
    #[test]
    fn the_validation_flags_are_the_headers_three_bits() {
        assert_eq!(FFC_PARAM_FLAG_VALIDATE_PQ, 0x01);
        assert_eq!(FFC_PARAM_FLAG_VALIDATE_G, 0x02);
        assert_eq!(FFC_PARAM_FLAG_VALIDATE_PQG, 0x03);
        assert_eq!(FFC_PARAM_FLAG_VALIDATE_LEGACY, 0x04);
        assert_eq!(
            FFC_PARAM_FLAG_VALIDATE_PQG & FFC_PARAM_FLAG_VALIDATE_PQ,
            0x01
        );
    }

    /// The check and error bits are disjoint by construction, and the two gaps the header
    /// documents (`0x80`, `0x100`) are gaps here too. `ossl_ffc_params_simple_validate` tests
    /// `*res & FFC_ERROR_NOT_SUITABLE_GENERATOR`, so a collision between the two families
    /// would make a `CHECK_*` bit raise a DH error.
    #[test]
    fn the_check_and_error_bits_do_not_collide() {
        let checks = [
            FFC_CHECK_P_NOT_PRIME,
            FFC_CHECK_P_NOT_SAFE_PRIME,
            FFC_CHECK_UNKNOWN_GENERATOR,
            FFC_CHECK_NOT_SUITABLE_GENERATOR,
            FFC_CHECK_Q_NOT_PRIME,
            FFC_CHECK_INVALID_Q_VALUE,
            FFC_CHECK_INVALID_J_VALUE,
            FFC_CHECK_MISSING_SEED_OR_COUNTER,
            FFC_CHECK_INVALID_G,
            FFC_CHECK_INVALID_PQ,
            FFC_CHECK_INVALID_COUNTER,
            FFC_CHECK_P_MISMATCH,
            FFC_CHECK_Q_MISMATCH,
            FFC_CHECK_G_MISMATCH,
            FFC_CHECK_COUNTER_MISMATCH,
            FFC_CHECK_BAD_LN_PAIR,
            FFC_CHECK_INVALID_SEED_SIZE,
        ];
        let mut seen: c_int = 0;
        for bit in checks {
            assert!(bit != 0);
            assert_eq!(seen & bit, 0, "{bit:#x} collides with an earlier check bit");
            seen |= bit;
        }
        /* `0x80` and `0x100` belong to `dh.h` and are not in this family. */
        assert_eq!(seen & 0x180, 0);
        assert_eq!(FFC_CHECK_INVALID_SEED_SIZE, 0x40000);
        assert_eq!(FFC_ERROR_NOT_SUITABLE_GENERATOR, 0x08);
        assert_eq!(FFC_ERROR_PUBKEY_INVALID, 0x04);
    }

    /// `FFC_PARAM_TYPE_DSA` is 0 and `FFC_PARAM_MODE_VERIFY` is 0 — the two zero-valued
    /// enumerators. A transcription that gave either a non-zero default would make a
    /// zero-initialised caller take the other branch, and `ffc_params_validate.c:100`'s
    /// `FFC_PARAMS tmpparams = { 0 }` plus `ossl_ffc_params_init`'s memset are both real
    /// zero-initialised objects.
    #[test]
    fn the_zero_valued_enumerators_are_zero() {
        assert_eq!(FFC_PARAM_TYPE_DSA, 0);
        assert_eq!(FFC_PARAM_TYPE_DH, 1);
        assert_eq!(FFC_PARAM_MODE_VERIFY, 0);
        assert_eq!(FFC_PARAM_MODE_GENERATE, 1);
        assert_eq!(FFC_PARAM_RET_STATUS_FAILED, 0);
        assert_eq!(FFC_PARAM_RET_STATUS_SUCCESS, 1);
        assert_eq!(FFC_PARAM_RET_STATUS_UNVERIFIABLE_G, 2);
        assert_eq!(FFC_UNVERIFIABLE_GINDEX, -1);
    }
}
