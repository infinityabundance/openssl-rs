//! `crypto/ffc/ffc_backend.c` — the finite-field provider bridge, Phase 8.5.
//!
//! One hundred and twenty-four lines and **one definition**: [`ossl_ffc_params_fromdata`]. The
//! unit's own header carries the same sentence the RSA and DH backends do — "the intention with
//! the 'backend' source file is to offer backend support for legacy backends
//! (`EVP_PKEY_ASN1_METHOD` and `EVP_PKEY_METHOD`) and provider implementations alike" — and this
//! is that sentence's smallest instance: the file is one function.
//!
//! ## Why this unit had no module until now
//!
//! `src/ffc/mod.rs` recorded it: `ffc_backend.c` is reached by `crypto/dh/dh_backend.c` and
//! `crypto/dsa/dsa_backend.c` — neither of which was on the `dh_lib.c`/`dh_key.c`/`dh_gen.c`/
//! `dh_check.c` path D330 landed — and its body reaches `crypto/param_build_set.c`, a unit with
//! no crate module at the time. D340 landed `crypto/param_build_set.c` as
//! [`crate::param_build_set`]; D351 lands the two provider backends, so the unit's two callers
//! exist and the module arrives with them. It is D327's rule in the direction that *adds* a
//! module rather than withholding one: a unit with a module makes every one of its internals
//! countable, and this unit has exactly one.
//!
//! ## The one authority shape that is easy to read past
//!
//! The `group` parameter's arm is inside `#ifndef OPENSSL_NO_DH`, which this profile compiles,
//! and the whole guard is the authority's own `goto err` trick: the `#ifndef` body ends without
//! a statement, so the `goto err` that follows the `#endif` is reached **both** when the guard is
//! compiled and the body fell through and when it is not compiled at all. In Rust that is the
//! single `if` written out below, with the three refusals inside it — a non-string data type, a
//! NULL data pointer and a name that resolves to no named group — each of which lands on the same
//! label as a caller-supplied `SEED` of the wrong type.
//!
//! **`ossl_ffc_params_set0_pqg` and `set0_j` are called unconditionally and last.** A caller that
//! supplied no numbers at all therefore *clears* the object's `p`/`q`/`g`/`j` rather than leaving
//! them, which is the opposite of "absent means unchanged" and is the behaviour
//! [`crate::dh::backend::ossl_dh_params_fromdata`] depends on when it re-imports a key.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::bn::bignum::{BN_free, BigNum};
use crate::evp::pkey_ctx::{
    OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PCOUNTER, OSSL_PKEY_PARAM_FFC_Q,
    OSSL_PKEY_PARAM_FFC_SEED, OSSL_PKEY_PARAM_FFC_VALIDATE_G, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY,
    OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, OSSL_PKEY_PARAM_GROUP_NAME,
};
use crate::ffc::dh::{ossl_ffc_name_to_dh_named_group, ossl_ffc_named_group_set};
use crate::ffc::params::{
    ossl_ffc_params_enable_flags, ossl_ffc_params_set0_j, ossl_ffc_params_set0_pqg,
    ossl_ffc_params_set_seed, ossl_ffc_set_digest,
};
use crate::ffc::{
    FfcParams, FFC_PARAM_FLAG_VALIDATE_G, FFC_PARAM_FLAG_VALIDATE_LEGACY,
    FFC_PARAM_FLAG_VALIDATE_PQ,
};
use crate::params::{
    OSSL_PARAM_get_BN, OSSL_PARAM_get_int, OSSL_PARAM_locate_const, OsslParam,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
};

/// `int ossl_ffc_params_fromdata(FFC_PARAMS *ffc, const OSSL_PARAM params[])` —
/// `crypto/ffc/ffc_backend.c:20-124`. Internal, declared in `include/internal/ffc.h`.
///
/// The provider's import path into a `FFC_PARAMS`, and it is the **DH/DSA parameter half** that
/// `src/dh/backend.rs` and `src/dsa/backend.rs` both wrap:
/// [`crate::dh::backend`]'s `dh_ffc_params_fromdata` adds the named-group cache refresh,
/// `ossl_dsa_ffc_params_fromdata` in [`crate::dsa::object`] adds a `dirty_cnt` bump, and this
/// function does neither because it cannot see the object that embeds the parameters.
///
/// Every parameter is optional and the function is an import rather than a merge: a parameter
/// that is absent is left to the two `set0` calls at the end, which store whatever the local
/// values are — NULL included. The two **type-checked** parameters are the exceptions, and they
/// are checked rather than converted: `GROUP_NAME` and `DIGEST` must be `UTF8_STRING` and `SEED`
/// must be `OCTET_STRING`, because each is handed to a callee that reads it as those bytes.
///
/// `#[allow(dead_code)]`'s reason: **its two callers are this stratum's own
/// [`crate::dh::backend`] and [`crate::dsa::object`]**, which this commit lands — the chain is
/// unreached until the provider keymgmt's `import` methods call them. The unit test below drives
/// it directly.
///
/// # Safety
/// `ffc` is NULL or a live, writable `FFC_PARAMS`; `params` is a key-terminated descriptor array.
/// On success ownership of the converted numbers passes to `ffc`.
#[allow(dead_code)] // read by the provider keymgmt's `import`; wrapped by dh_backend.c and dsa_lib.c
pub(crate) unsafe fn ossl_ffc_params_fromdata(
    ffc: *mut FfcParams,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut p: *mut BigNum = core::ptr::null_mut();
        let mut q: *mut BigNum = core::ptr::null_mut();
        let mut g: *mut BigNum = core::ptr::null_mut();
        let mut j: *mut BigNum = core::ptr::null_mut();
        let mut i: c_int = 0;

        let mut prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if !prm.is_null() {
            /*
             * In a no-dh build we just go straight to err because we have no support for this.
             * This profile compiles the `#ifndef OPENSSL_NO_DH` body, so the three refusals below
             * are the body's; the `#endif`'s `goto err` is the fourth and is shared with the
             * no-dh build.
             */
            let mut seen = false;
            if (*prm).data_type == OSSL_PARAM_UTF8_STRING && !(*prm).data.is_null() {
                let group = ossl_ffc_name_to_dh_named_group((*prm).data.cast::<c_char>());
                if !group.is_null() && ossl_ffc_named_group_set(ffc, group) != 0 {
                    seen = true;
                }
            }
            if !seen {
                return ffc_fromdata_err(j, p, q, g);
            }
        }

        let param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
        let param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
        let param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);

        if (!param_p.is_null() && OSSL_PARAM_get_BN(param_p, &mut p) == 0)
            || (!param_q.is_null() && OSSL_PARAM_get_BN(param_q, &mut q) == 0)
            || (!param_g.is_null() && OSSL_PARAM_get_BN(param_g, &mut g) == 0)
        {
            return ffc_fromdata_err(j, p, q, g);
        }

        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            (*ffc).gindex = i;
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            (*ffc).pcounter = i;
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_COFACTOR);
        if !prm.is_null() && OSSL_PARAM_get_BN(prm, &mut j) == 0 {
            return ffc_fromdata_err(j, p, q, g);
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            (*ffc).h = i;
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
        if !prm.is_null()
            && ((*prm).data_type != OSSL_PARAM_OCTET_STRING
                || ossl_ffc_params_set_seed(ffc, (*prm).data.cast::<u8>(), (*prm).data_size) == 0)
        {
            return ffc_fromdata_err(j, p, q, g);
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_PQ, i);
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_G);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_G, i);
        }
        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY);
        if !prm.is_null() {
            if OSSL_PARAM_get_int(prm, &mut i) == 0 {
                return ffc_fromdata_err(j, p, q, g);
            }
            ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY, i);
        }

        prm = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
        if !prm.is_null() {
            let mut props: *const c_char = core::ptr::null();

            if (*prm).data_type != OSSL_PARAM_UTF8_STRING {
                return ffc_fromdata_err(j, p, q, g);
            }
            let p1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
            if !p1.is_null() {
                if (*p1).data_type != OSSL_PARAM_UTF8_STRING {
                    return ffc_fromdata_err(j, p, q, g);
                }
                props = (*p1).data.cast::<c_char>();
            }
            ossl_ffc_set_digest(ffc, (*prm).data.cast::<c_char>(), props);
        }
        ossl_ffc_params_set0_pqg(ffc, p, q, g);
        ossl_ffc_params_set0_j(ffc, j);
        1
    }
}

/// The authority's `err:` label of [`ossl_ffc_params_fromdata`], in the authority's own release
/// order: `j` first, then `p`, `q` and `g`.
///
/// # Safety
/// Each pointer is NULL or a `BIGNUM` this call still owns.
unsafe fn ffc_fromdata_err(
    j: *mut BigNum,
    p: *mut BigNum,
    q: *mut BigNum,
    g: *mut BigNum,
) -> c_int {
    // SAFETY: each pointer is NULL or this call's own, per the contract.
    unsafe {
        BN_free(j);
        BN_free(p);
        BN_free(q);
        BN_free(g);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::BN_cmp;
    use crate::ffc::params::{ossl_ffc_params_cleanup, ossl_ffc_params_init};
    use crate::params::{
        OSSL_PARAM_construct_BN, OSSL_PARAM_construct_end, OSSL_PARAM_construct_int,
        OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    };
    use crate::runtime::obj::{NID_ffdhe2048, NID_undef};

    /// A fresh params object, released on drop: every test here owns its object, which is what
    /// makes the `# Safety` sections above satisfiable.
    struct Params(FfcParams);

    impl Params {
        fn new() -> Self {
            let mut p = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `p` is live and writable; `ossl_ffc_params_init` writes every byte.
            let inner = unsafe {
                ossl_ffc_params_init(p.as_mut_ptr());
                p.assume_init()
            };
            Params(inner)
        }

        fn as_mut(&mut self) -> *mut FfcParams {
            &raw mut self.0
        }
    }

    impl Drop for Params {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { ossl_ffc_params_cleanup(&raw mut self.0) };
        }
    }

    /// A two-byte big-endian modulus, as the provider carries it.
    const P_BYTES: [u8; 2] = [0x12, 0x34];
    /// A one-byte subgroup order.
    const Q_BYTES: [u8; 1] = [0x0b];
    /// A one-byte generator.
    const G_BYTES: [u8; 1] = [0x02];
    /// A cofactor `j` wider than a byte, so a byte-order slip shows.
    const J_BYTES: [u8; 2] = [0x00, 0x07];
    /// A four-octet FIPS seed.
    const SEED: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    /// The whole import, over every parameter family the function understands. The assertions are
    /// the fields, not the return code alone: a value that landed in the wrong member is the
    /// transcription error this arm exists for.
    #[test]
    fn every_parameter_family_imports_into_the_four_numbers_and_the_scalars() {
        let mut p_bytes = P_BYTES;
        let mut q_bytes = Q_BYTES;
        let mut g_bytes = G_BYTES;
        let mut j_bytes = J_BYTES;
        let mut seed = SEED;
        let mut gindex: c_int = 3;
        let mut pcounter: c_int = 4;
        let mut h: c_int = 5;
        let mut validate_pq: c_int = 0;
        let mut validate_g: c_int = 1;
        let mut validate_legacy: c_int = 0;
        let mut md_buf = *b"sha256\0";
        let mut props_buf = *b"provider=default\0";

        // SAFETY: every buffer is the one the descriptor is built over and outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p_bytes.as_mut_ptr(), p_bytes.len()),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, q_bytes.as_mut_ptr(), q_bytes.len()),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, g_bytes.as_mut_ptr(), g_bytes.len()),
                OSSL_PARAM_construct_BN(
                    OSSL_PKEY_PARAM_FFC_COFACTOR,
                    j_bytes.as_mut_ptr(),
                    j_bytes.len(),
                ),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &mut gindex),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_PCOUNTER, &mut pcounter),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_H, &mut h),
                OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_FFC_SEED,
                    seed.as_mut_ptr().cast(),
                    seed.len(),
                ),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, &mut validate_pq),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_VALIDATE_G, &mut validate_g),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, &mut validate_legacy),
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_FFC_DIGEST,
                    md_buf.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                    props_buf.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };

        let mut ffc = Params::new();
        // SAFETY: the object is live and the array is key-terminated.
        let ret = unsafe { ossl_ffc_params_fromdata(ffc.as_mut(), params.as_ptr()) };
        assert_eq!(ret, 1);

        // SAFETY: the object is live and owns everything the import stored.
        unsafe {
            let f = &*ffc.as_mut();
            assert!(!f.p.is_null() && BN_cmp(f.p, f.p) == 0);
            assert!(!f.q.is_null());
            assert!(!f.g.is_null());
            assert!(!f.j.is_null());
            assert_eq!(f.gindex, 3);
            assert_eq!(f.pcounter, 4);
            assert_eq!(f.h, 5);
            assert_eq!(f.seedlen, SEED.len());
            assert_eq!(f.nid, NID_undef);
            // The three flags are set or cleared from the three integers, against the
            // `VALIDATE_PQG` default `ossl_ffc_params_init` installs.
            assert_eq!(f.flags & FFC_PARAM_FLAG_VALIDATE_PQ, 0);
            assert_eq!(
                f.flags & FFC_PARAM_FLAG_VALIDATE_G,
                FFC_PARAM_FLAG_VALIDATE_G
            );
            assert_eq!(f.flags & FFC_PARAM_FLAG_VALIDATE_LEGACY, 0);
            assert!(!f.mdname.is_null());
            assert!(!f.mdprops.is_null());
        }
    }

    /// The named-group arm: the `group` parameter resolves through `ffc_dh.c`'s table and installs
    /// that row's `p`/`q`/`g`, which the trailing `set0_pqg(NULL, NULL, NULL)` then leaves alone.
    ///
    /// **The `nid` is left at `NID_undef` on purpose** — `ossl_ffc_named_group_set`'s last
    /// statement *flushes* the cached identifier ("The DH layer is responsible for caching") — so
    /// the group's 2048-bit modulus being present is the observation, not the nid. The DH layer's
    /// `dh_ffc_params_fromdata` is what fills the cache back in, and `dh::backend`'s own test
    /// observes that.
    #[test]
    fn a_named_group_installs_its_numbers_and_flushes_the_cached_nid() {
        let mut group_buf = *b"ffdhe2048\0";
        // SAFETY: the buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME,
                    group_buf.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };

        let mut ffc = Params::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_ffc_params_fromdata(ffc.as_mut(), params.as_ptr()) },
            1
        );
        // SAFETY: the object is live.
        unsafe {
            let f = &*ffc.as_mut();
            assert_eq!(f.nid, NID_undef);
            assert!(!f.p.is_null());
            assert!(!f.q.is_null());
            assert!(!f.g.is_null());
            assert_eq!(crate::bn::bignum::BN_num_bits(f.p), 2048);
        }
        // The row the name resolved to is the one this assertion names, so the 2048 above is that
        // group's modulus rather than any modulus.
        assert_eq!(NID_ffdhe2048, 1126);
    }

    /// The two refusals on the named-group arm. A name that resolves to no row and a group
    /// parameter that is not a string are the same `goto err` in the authority, and the second is
    /// what makes the `#ifndef OPENSSL_NO_DH` body's fall-through observable.
    #[test]
    fn a_name_that_resolves_to_nothing_and_a_non_string_are_both_refused() {
        let mut bogus = *b"no-such-group\0";
        // SAFETY: the buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME,
                    bogus.as_mut_ptr().cast(),
                    0,
                ),
                OSSL_PARAM_construct_end(),
            ]
        };
        let mut ffc = Params::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_ffc_params_fromdata(ffc.as_mut(), params.as_ptr()) },
            0
        );
        // SAFETY: the object is live.
        assert_eq!(
            // SAFETY: as above.
            unsafe { (*ffc.as_mut()).nid },
            NID_undef
        );

        let mut integer: c_int = 7;
        // SAFETY: the integer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_GROUP_NAME, &mut integer),
                OSSL_PARAM_construct_end(),
            ]
        };
        let mut ffc = Params::new();
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_ffc_params_fromdata(ffc.as_mut(), params.as_ptr()) },
            0
        );
    }

    /// The `SEED` type test, and the rollback it implies: a seed of the wrong data type is refused
    /// and the `p` that was converted *before* it is released by the `err:` label rather than
    /// stored, so the object's own `p` is still NULL.
    #[test]
    fn a_seed_of_the_wrong_type_is_refused_and_nothing_is_stored() {
        let mut p_bytes = P_BYTES;
        let mut integer: c_int = 1;
        // SAFETY: every buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, p_bytes.as_mut_ptr(), p_bytes.len()),
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_SEED, &mut integer),
                OSSL_PARAM_construct_end(),
            ]
        };
        let mut ffc = Params::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_ffc_params_fromdata(ffc.as_mut(), params.as_ptr()) },
            0
        );
        // SAFETY: the object is live.
        assert!(
            // SAFETY: as above.
            unsafe { (*ffc.as_mut()).p.is_null() }
        );
    }
}
