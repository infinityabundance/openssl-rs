//! Phase 8 — `crypto/dh/dh_gen.c`: DH parameter generation.
//!
//! Two exports and three internals: `DH_generate_parameters_ex`, its static builtin safe-prime
//! generator, the FFC dispatch `ossl_dh_generate_ffc_parameters`, and the size-to-`nid` mapping
//! `ossl_dh_get_named_group_uid_from_size`.
//!
//! ## The arm this profile compiles, and why the other is not here
//!
//! `DH_generate_parameters_ex` is `#ifdef FIPS_MODULE`-split. The FIPS arm generates a **named
//! group** by `nid` and copies its parameters; it is not compiled here, so neither it nor its
//! helper `dh_gen_named_group` is transcribed. The `#else` arm — dispatch to a caller-supplied
//! method, else the builtin safe-prime generator — is the whole function below.
//!
//! `dh_ossl` leaves its `generate_params` member NULL (D329), so on every object this crate
//! constructs `DH_generate_parameters_ex` takes the builtin arm. That is not a reduction: it is
//! the same branch the authority takes for the default method.
//!
//! ## `DH_generate_parameters` is not in this unit
//!
//! The deprecated wrapper is `crypto/dh/dh_depr.c:25-48` and it is transcribed in
//! [`crate::dh::depr`]. The prompt that asked for this slice named it here; the authority puts it
//! there, and the deferred-hand-off row that names all three generation entry points is retired
//! only when both files land.
//!
//! ## The two internals with no caller in this crate
//!
//! `ossl_dh_generate_ffc_parameters` is reached by the FIPS arm above and by
//! `providers/implementations/keymgmt/dh_kmgmt.c:780`; `ossl_dh_get_named_group_uid_from_size` by
//! the same provider unit at `:735`. Both are transcribed because they are the unit's body —
//! `ossl_dh_generate_ffc_parameters` is the FFC generator's only other caller after
//! `ffc_params_generate.c`'s own validator — and each carries `#[allow(dead_code)]` with the
//! caller that will read it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::bn::bignum::{BN_new, BN_set_word};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BN_GENCB_call, BnGencb,
};
use crate::bn::primes::BN_generate_prime_ex2;
use crate::ffc::params_generate::{
    ossl_ffc_params_FIPS186_2_generate, ossl_ffc_params_FIPS186_4_generate,
};
use crate::ffc::FFC_PARAM_TYPE_DH;
use crate::rsa::object::ossl_ifc_ffc_compute_security_bits;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{
    NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192, NID_undef,
};

use super::{
    Dh, DH_GENERATOR_2, DH_GENERATOR_5, DH_MIN_MODULUS_BITS, DH_PARAMGEN_TYPE_FIPS_186_2,
    OPENSSL_DH_MAX_MODULUS_BITS,
};

/// `int ossl_dh_generate_ffc_parameters(DH *dh, int type, int pbits, int qbits,`
/// `BN_GENCB *cb)` — `dh_gen.c:39-57`. Internal.
///
/// The dispatch between the FIPS 186-2 and 186-4 generators, with the dirty counter bumped only
/// when the generator answered a positive status. **The two generators share a signature and an
/// answer domain**, so the only thing this function decides is which one runs: 186-2 for
/// `DH_PARAMGEN_TYPE_FIPS_186_2`, 186-4 for everything else.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the FIPS arm of
/// `DH_generate_parameters_ex`, which is not compiled on this profile, and the provider
/// keymgmt's generate path** (`dh_kmgmt.c:780`), beyond this slice.
///
/// # Safety
///
/// `dh` is a live object; `cb` is NULL or a live `BN_GENCB`.
#[allow(dead_code)] // read by the FIPS arm and the provider keymgmt, which are not in this slice
pub(crate) unsafe fn ossl_dh_generate_ffc_parameters(
    dh: *mut Dh,
    type_: c_int,
    pbits: c_int,
    qbits: c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut res: c_int = 0;

    // SAFETY: `dh` is live per the contract; `params` is a field of it; `cb` is the caller's.
    let ret = unsafe {
        if type_ == DH_PARAMGEN_TYPE_FIPS_186_2 {
            ossl_ffc_params_FIPS186_2_generate(
                (*dh).libctx,
                core::ptr::addr_of_mut!((*dh).params),
                FFC_PARAM_TYPE_DH,
                pbits as usize,
                qbits as usize,
                &raw mut res,
                cb,
            )
        } else {
            ossl_ffc_params_FIPS186_4_generate(
                (*dh).libctx,
                core::ptr::addr_of_mut!((*dh).params),
                FFC_PARAM_TYPE_DH,
                pbits as usize,
                qbits as usize,
                &raw mut res,
                cb,
            )
        }
    };
    if ret > 0 {
        // SAFETY: `dh` is live per the contract.
        unsafe { (*dh).dirty_cnt += 1 };
    }
    ret
}

/// `int ossl_dh_get_named_group_uid_from_size(int pbits)` — `dh_gen.c:59-91`. Internal.
///
/// The one-to-one map from a modulus size to the RFC 7919 group that names it, answering
/// `NID_undef` for every other size. Only the five approved sizes are mapped; 2048 is the first,
/// and a caller asking for 1024 gets `NID_undef` rather than the nearest group.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the FIPS named-group arm and the provider
/// keymgmt** (`dh_kmgmt.c:735`), neither of which is in this slice.
///
/// # Safety
///
/// Takes no pointer.
#[allow(dead_code)] // read by the FIPS arm and the provider keymgmt, which are not in this slice
pub(crate) unsafe fn ossl_dh_get_named_group_uid_from_size(pbits: c_int) -> c_int {
    match pbits {
        2048 => NID_ffdhe2048,
        3072 => NID_ffdhe3072,
        4096 => NID_ffdhe4096,
        6144 => NID_ffdhe6144,
        8192 => NID_ffdhe8192,
        /* unsupported prime_len */
        _ => NID_undef,
    }
}

/// `int DH_generate_parameters_ex(DH *ret, int prime_len, int generator, BN_GENCB *cb)` —
/// `dh_gen.c:115-127`, the `#else` arm.
///
/// The caller's method is consulted first and its own generator used when it has one; otherwise
/// the builtin safe-prime generator below runs. `dh_ossl` has no `generate_params`, so the
/// builtin arm is the default method's answer.
///
/// # Safety
///
/// `ret` is a live object; `cb` is NULL or a live `BN_GENCB`.
#[no_mangle]
pub unsafe extern "C" fn DH_generate_parameters_ex(
    ret: *mut Dh,
    prime_len: c_int,
    generator: c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `ret` is live per the contract.
    let meth = unsafe { (*ret).meth };
    // SAFETY: `meth` is the object's own table; the header marks `generate_params` nullable, and
    // `dh_ossl` leaves it NULL by design — that NULL is what selects the builtin generator.
    if let Some(generate_params) = unsafe { (*meth).generate_params } {
        // SAFETY: the table's own generator, handed this object as the authority hands it.
        return unsafe { generate_params(ret, prime_len, generator, cb) };
    }
    // SAFETY: `ret` is live and `cb` is the caller's.
    unsafe { dh_builtin_genparams(ret, prime_len, generator, cb) }
}

/// `static int dh_builtin_genparams(DH *ret, int prime_len, int generator, BN_GENCB *cb)` —
/// `dh_gen.c:156-238`.
///
/// The safe-prime generator, with the three congruences the authority's comment derives:
/// `p mod 8 == 7` for `g = 2`, `p mod 24 == 23` for 2, `p mod 12 == 11` for 3, and
/// `p mod 60 == 59` for 5 — each expressed as a `t1`/`t2` pair handed to
/// `BN_generate_prime_ex2`.
///
/// **The generator bound is checked after the two `BIGNUM`s are created**, so a generator of 0 or
/// 1 allocates `p` and `g` and then refuses with `DH_R_BAD_GENERATOR`, leaving `ret` holding a
/// pair of fresh `BIGNUM`s. That ordering is the authority's and is transcribed.
///
/// `ret->length` is set to the RFC 7919 private-key length of the generated group — `(2s + 24) /
/// 25 * 25` where `s` is the security strength — which is why a generated group's exponent is
/// 150 bits for a 512-bit modulus rather than the 510 the raw modulus would allow.
///
/// # Safety
///
/// `ret` is a live object; `cb` is NULL or a live `BN_GENCB`.
unsafe fn dh_builtin_genparams(
    ret: *mut Dh,
    prime_len: c_int,
    generator: c_int,
    cb: *mut BnGencb,
) -> c_int {
    let g: c_int;
    let mut ok: c_int = -1;

    // SAFETY: `ret` is live per the contract.
    unsafe {
        if prime_len > OPENSSL_DH_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_GEN_164);
            return 0;
        }
        if prime_len < DH_MIN_MODULUS_BITS {
            raise_site(&err_sites::DH_GEN_169);
            return 0;
        }
    }

    // SAFETY: `ret` is live per the contract.
    let ctx = unsafe { BN_CTX_new_ex((*ret).libctx) };
    if ctx.is_null() {
        /* The authority's `err:` label, with `ok == -1` and a NULL context. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DH_GEN_231) };
        // SAFETY: `ctx` is NULL, which both callees accept.
        unsafe {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
        return 0;
    }

    // SAFETY: `ctx` is live and is this call's own; `ret` is live.
    unsafe {
        'build: {
            BN_CTX_start(ctx);
            let t1 = BN_CTX_get(ctx);
            let t2 = BN_CTX_get(ctx);
            if t2.is_null() {
                break 'build;
            }

            /* Make sure 'ret' has the necessary elements */
            if (*ret).params.p.is_null() {
                (*ret).params.p = BN_new();
                if (*ret).params.p.is_null() {
                    break 'build;
                }
            }
            if (*ret).params.g.is_null() {
                (*ret).params.g = BN_new();
                if (*ret).params.g.is_null() {
                    break 'build;
                }
            }

            if generator <= 1 {
                raise_site(&err_sites::DH_GEN_189);
                break 'build;
            }
            if generator == DH_GENERATOR_2 {
                if BN_set_word(t1, 24) == 0 || BN_set_word(t2, 23) == 0 {
                    break 'build;
                }
                g = 2;
            } else if generator == DH_GENERATOR_5 {
                if BN_set_word(t1, 60) == 0 || BN_set_word(t2, 59) == 0 {
                    break 'build;
                }
                g = 5;
            } else {
                /*
                 * in the general case, don't worry if 'generator' is a generator or
                 * not: since we are using safe primes, it will generate either an
                 * order-q or an order-2q group, which both is OK
                 */
                if BN_set_word(t1, 12) == 0 || BN_set_word(t2, 11) == 0 {
                    break 'build;
                }
                g = generator;
            }

            if BN_generate_prime_ex2((*ret).params.p, prime_len, 1, t1, t2, cb, ctx) == 0 {
                break 'build;
            }
            if BN_GENCB_call(cb, 3, 0) == 0 {
                break 'build;
            }
            if BN_set_word((*ret).params.g, g as core::ffi::c_ulong) == 0 {
                break 'build;
            }
            /* We are using safe prime p, set key length equivalent to RFC 7919 */
            (*ret).length =
                (2 * c_int::from(ossl_ifc_ffc_compute_security_bits(prime_len)) + 24) / 25 * 25;
            (*ret).dirty_cnt += 1;
            ok = 1;
        }

        /* The authority's `err:` label: a failure after the context exists still raises
         * `ERR_R_BN_LIB` here, so a refused generator leaves *two* records rather than one. */
        if ok == -1 {
            raise_site(&err_sites::DH_GEN_231);
            ok = 0;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ok
}
