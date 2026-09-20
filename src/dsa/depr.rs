//! Phase 8 — `crypto/dsa/dsa_depr.c`: the one deprecated wrapper.
//!
//! `dsa_depr.c` is a single function, `DSA_generate_parameters`, and it is here rather than beside
//! `DSA_generate_parameters_ex` in [`crate::dsa::gen`] because the authority puts it here: the file
//! exists to hold the 0.9.8-era entry point that builds its own `BN_GENCB` from a plain callback.
//! It is the same shape as `crypto/dh/dh_depr.c`, and `src/dh/depr.rs`'s note on it applies
//! unchanged — including the prompt's own coordinate: this wrapper is the whole file, so the
//! deprecated name is *not* in `dsa_gen.c`.
//!
//! **The object's ownership is split down the middle.** On success the caller gets the `DSA *` and
//! the `BN_GENCB` is released here; on failure both are released here and the caller gets NULL. The
//! two releases are separate statements in the authority rather than a shared label — the `cb`
//! release comes first on both paths — and that order is preserved.
//!
//! This file raises nothing, so it adds no `err_sites` coordinate and is absent from
//! `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar, c_ulong, c_void};

use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new, BN_GENCB_set_old, BnGencb};

use super::gen::DSA_generate_parameters_ex;
use super::object::{DSA_free, DSA_new};
use super::Dsa;

/// `DSA *DSA_generate_parameters(int bits, unsigned char *seed_in, int seed_len,`
/// `int *counter_ret, unsigned long *h_ret, void (*callback)(int, int, void *), void *cb_arg)` —
/// `dsa_depr.c:29-55`.
///
/// The deprecated wrapper over [`DSA_generate_parameters_ex`] that installs an *old-style*
/// callback. A NULL `callback` is accepted: `BN_GENCB_set_old` stores it and `BN_GENCB_call` then
/// answers 1 without invoking anything, which is why `DSA_generate_parameters(1024, NULL, 0, NULL,
/// NULL, NULL, NULL)` is the probe's deterministic arm.
///
/// Note the argument the modern spelling keeps read-only: `unsigned char *seed_in` here is
/// non-const in the authority's own 0.9.8-era prototype, and the pointer is passed straight to
/// `DSA_generate_parameters_ex`, which reads it.
///
/// # Safety
///
/// `seed_in` is NULL or readable for `seed_len` bytes; `counter_ret` and `h_ret` are NULL or
/// writable; `callback` is NULL or an old-style `BN_GENCB` callback safe to call with `cb_arg`.
#[no_mangle]
pub unsafe extern "C" fn DSA_generate_parameters(
    bits: c_int,
    seed_in: *mut c_uchar,
    seed_len: c_int,
    counter_ret: *mut c_int,
    h_ret: *mut c_ulong,
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
    cb_arg: *mut c_void,
) -> *mut Dsa {
    // SAFETY: `DSA_new` takes no pointer.
    let ret = unsafe { DSA_new() };
    if ret.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `BN_GENCB_new` reads no caller pointer.
    let cb: *mut BnGencb = unsafe { BN_GENCB_new() };
    if cb.is_null() {
        // SAFETY: `ret` is this call's own object.
        unsafe { DSA_free(ret) };
        return core::ptr::null_mut();
    }

    // SAFETY: `cb` is live and `callback`/`cb_arg` are the caller's.
    unsafe { BN_GENCB_set_old(cb, callback, cb_arg) };

    // SAFETY: `ret` is live, `cb` is live and `seed_in` is NULL or readable per the contract.
    if unsafe { DSA_generate_parameters_ex(ret, bits, seed_in, seed_len, counter_ret, h_ret, cb) }
        != 0
    {
        // SAFETY: `cb` is this call's own and the `DSA *` is being returned.
        unsafe { BN_GENCB_free(cb) };
        return ret;
    }
    // SAFETY: both objects are this call's own.
    unsafe {
        BN_GENCB_free(cb);
        DSA_free(ret);
    }
    core::ptr::null_mut()
}
