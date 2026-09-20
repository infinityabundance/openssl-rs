//! Phase 8 — `crypto/dsa/dsa_gen.c`: DSA parameter generation.
//!
//! Two definitions: [`ossl_dsa_generate_ffc_parameters`] (`dsa_gen.c:21-40`), the internal that
//! selects between the two FIPS generators, and [`DSA_generate_parameters_ex`] (`dsa_gen.c:42-76`),
//! the export that chooses between them by size and seed.
//!
//! ## The choice is FIPS 186-2 or 186-4, and the *caller* mostly decides
//!
//! `DSA_generate_parameters_ex`'s rule is `bits < 2048 && seed_len <= 20` — the authority's own
//! comment calls the first arm "The old code used FIPS 186-2 DSA Parameter generation" — and it
//! passes `qbits` 160 for that arm and 0 for the other, where 0 means "choose `N` from `L`". So a
//! caller asking for 1024 or 512 bits gets the FIPS 186-2 path with a 160-bit subgroup, and a
//! caller asking for 2048 gets 186-4, whatever it passes as `seed_len` up to 20.
//!
//! Both generators are [`crate::ffc::params_generate`]'s, landed whole in D330 with
//! `ffc_params_validate.c`'s validators and `ffc_key_generate.c`'s exponent generation. What this
//! unit adds is the **dispatch**, the seed plumbing and the two out-parameters.
//!
//! ## The method table's NULL is what makes this reachable
//!
//! `if (dsa->meth->dsa_paramgen)` is the first statement of `DSA_generate_parameters_ex`, and the
//! authority's own table leaves that member NULL (`dsa_ossl.c:65`). A caller that installs a table
//! with a `dsa_paramgen` gets *that* called and none of the FFC machinery, which is why the test
//! is transcribed and not simplified into a direct call.
//!
//! ## The seed, and the `-1` counter that marks it
//!
//! A non-NULL `seed_in` is installed through `ossl_ffc_params_set_validate_params(…, -1)` — the
//! counter is deliberately set to "not set" so that the generator fills it in — and the two
//! out-parameters read back `params.pcounter` and `params.h` **only after a success**, which is
//! why a caller that passes them and gets 0 sees them untouched.
//!
//! `dsa_gen.c` raises nothing: every failure is a `return 0`, and the reason a caller sees comes
//! from the FFC generator's own site. That is why this unit is absent from
//! `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong};

use crate::bn::ctx::BnGencb;
use crate::ffc::params::ossl_ffc_params_set_validate_params;
use crate::ffc::params_generate::{
    ossl_ffc_params_FIPS186_2_generate, ossl_ffc_params_FIPS186_4_generate,
};
use crate::ffc::FFC_PARAM_TYPE_DSA;

use super::{Dsa, DSA_PARAMGEN_TYPE_FIPS_186_2, DSA_PARAMGEN_TYPE_FIPS_186_4};

/// `int ossl_dsa_generate_ffc_parameters(DSA *dsa, int type, int pbits, int qbits,`
/// `BN_GENCB *cb)` — `dsa_gen.c:21-40`. Internal.
///
/// `type == DSA_PARAMGEN_TYPE_FIPS_186_2` selects the legacy generator on this profile; every
/// other value — including `DSA_PARAMGEN_TYPE_FIPS_DEFAULT`, which only the provider's parameter
/// type maps to — takes the FIPS 186-4 arm. The `dirty_cnt` bump is guarded by `ret > 0` rather
/// than `ret != 0`: a *failure* that is not zero is `FFC_PARAM_RET_STATUS_FAILED`'s negative
/// tri-state, and nothing changed on the object in that case.
///
/// # Safety
///
/// `dsa` is a live object; `cb` is NULL or a live generator callback.
pub(crate) unsafe fn ossl_dsa_generate_ffc_parameters(
    dsa: *mut Dsa,
    type_: c_int,
    pbits: c_int,
    qbits: c_int,
    cb: *mut BnGencb,
) -> c_int {
    let mut res: c_int = 0;

    // SAFETY: `dsa` is live per the contract, and the generator's own contract is the caller's
    // here: `libctx` is the object's, `params` is its embedded block.
    let ret = unsafe {
        if type_ == DSA_PARAMGEN_TYPE_FIPS_186_2 {
            ossl_ffc_params_FIPS186_2_generate(
                (*dsa).libctx,
                core::ptr::addr_of_mut!((*dsa).params),
                FFC_PARAM_TYPE_DSA,
                pbits as usize,
                qbits as usize,
                &raw mut res,
                cb,
            )
        } else {
            ossl_ffc_params_FIPS186_4_generate(
                (*dsa).libctx,
                core::ptr::addr_of_mut!((*dsa).params),
                FFC_PARAM_TYPE_DSA,
                pbits as usize,
                qbits as usize,
                &raw mut res,
                cb,
            )
        }
    };
    if ret > 0 {
        // SAFETY: `dsa` is live per the contract.
        unsafe { (*dsa).dirty_cnt += 1 };
    }
    ret
}

/// `int DSA_generate_parameters_ex(DSA *dsa, int bits, const unsigned char *seed_in,`
/// `int seed_len, int *counter_ret, unsigned long *h_ret, BN_GENCB *cb)` — `dsa_gen.c:42-76`.
///
/// Three arms: a caller-supplied `dsa_paramgen`, the FIPS 186-2 arm for `bits < 2048 &&
/// seed_len <= 20`, and the FIPS 186-4 arm otherwise. See the module documentation for the seed
/// and the two out-parameters.
///
/// # Safety
///
/// `dsa` is a live object; `seed_in` is NULL or readable for `seed_len` bytes; `counter_ret` and
/// `h_ret` are NULL or writable; `cb` is NULL or a live generator callback.
#[no_mangle]
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
pub unsafe extern "C" fn DSA_generate_parameters_ex(
    dsa: *mut Dsa,
    bits: c_int,
    seed_in: *const c_uchar,
    seed_len: c_int,
    counter_ret: *mut c_int,
    h_ret: *mut c_ulong,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `dsa` is live per the contract.
    let meth = unsafe { (*dsa).meth };
    if !meth.is_null() {
        // SAFETY: `meth` is the object's own table, alive for the call.
        if let Some(paramgen) = unsafe { (*meth).dsa_paramgen } {
            // SAFETY: `paramgen` is that table's entry point, handed the arguments the authority
            // hands it.
            return unsafe { paramgen(dsa, bits, seed_in, seed_len, counter_ret, h_ret, cb) };
        }
    }

    if !seed_in.is_null() {
        // SAFETY: `dsa` is live, `seed_in` is readable for `seed_len` bytes, and the counter is
        // `-1` as the authority passes it.
        if unsafe {
            ossl_ffc_params_set_validate_params(
                core::ptr::addr_of_mut!((*dsa).params),
                seed_in,
                seed_len.max(0) as usize,
                -1,
            )
        } == 0
        {
            return 0;
        }
    }

    /* The old code used FIPS 186-2 DSA Parameter generation */
    // SAFETY: `dsa` is live per the contract and `cb` is the caller's.
    if bits < 2048 && seed_len <= 20 {
        // SAFETY: `dsa` is live per the contract and `cb` is the caller's.
        if unsafe {
            ossl_dsa_generate_ffc_parameters(dsa, DSA_PARAMGEN_TYPE_FIPS_186_2, bits, 160, cb)
        } == 0
        {
            return 0;
        }
    // SAFETY: `dsa` is live per the contract and `cb` is the caller's.
    } else if unsafe {
        ossl_dsa_generate_ffc_parameters(dsa, DSA_PARAMGEN_TYPE_FIPS_186_4, bits, 0, cb)
    } == 0
    {
        return 0;
    }

    // SAFETY: `dsa` is live; each out-parameter is NULL or writable per the contract.
    unsafe {
        if !counter_ret.is_null() {
            *counter_ret = (*dsa).params.pcounter;
        }
        if !h_ret.is_null() {
            *h_ret = (*dsa).params.h as c_ulong;
        }
    }
    1
}
