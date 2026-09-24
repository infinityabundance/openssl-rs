//! Phase 8 — `crypto/dh/dh_depr.c`: the one deprecated wrapper.
//!
//! `dh_depr.c` is a single function, `DH_generate_parameters`, and it is here rather than beside
//! `DH_generate_parameters_ex` in [`crate::dh::gen`] because the authority puts it here: the file
//! exists to hold the 0.9.8-era entry point that builds its own `BN_GENCB` from a plain callback.
//! The prompt for this slice named it under `dh_gen.c`; the authority's own `build.info` and the
//! file's header comment ("This file contains deprecated functions as wrappers to the new ones")
//! are the coordinate that settles it.
//!
//! **The object's ownership is split down the middle.** On success the caller gets the `DH *` and
//! the `BN_GENCB` is released here; on failure both are released here and the caller gets NULL. The
//! two releases are separate statements in the authority rather than a shared label — the `cb`
//! release comes first on both paths — and that order is preserved. This file raises nothing, so
//! it adds no `err_sites` coordinate and is absent from `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new, BN_GENCB_set_old, BnGencb};

use super::gen::DH_generate_parameters_ex;
use super::object::{DH_free, DH_new};
use super::Dh;

/// `DH *DH_generate_parameters(int prime_len, int generator,`
/// `void (*callback)(int, int, void *), void *cb_arg)` — `dh_depr.c:25-48`.
///
/// The deprecated wrapper over [`DH_generate_parameters_ex`] that installs an *old-style*
/// callback. A NULL `callback` is accepted: `BN_GENCB_set_old` stores it and `BN_GENCB_call` then
/// answers 1 without invoking anything, which is why `DH_generate_parameters(512, 2, NULL, NULL)`
/// is the probe's deterministic arm.
///
/// # Safety
///
/// `callback` is NULL or an old-style `BN_GENCB` callback safe to call with `cb_arg`.
#[no_mangle]
pub unsafe extern "C" fn DH_generate_parameters(
    prime_len: c_int,
    generator: c_int,
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
    cb_arg: *mut c_void,
) -> *mut Dh {
    // SAFETY: `DH_new` takes no pointer.
    let ret = unsafe { DH_new() };
    if ret.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `BN_GENCB_new` reads no caller pointer.
    let cb: *mut BnGencb = unsafe { BN_GENCB_new() };
    if cb.is_null() {
        // SAFETY: `ret` is this call's own object.
        unsafe { DH_free(ret) };
        return core::ptr::null_mut();
    }

    // SAFETY: `cb` is live and `callback`/`cb_arg` are the caller's.
    unsafe { BN_GENCB_set_old(cb, callback, cb_arg) };

    // SAFETY: `ret` is live and `cb` is live.
    if unsafe { DH_generate_parameters_ex(ret, prime_len, generator, cb) } != 0 {
        // SAFETY: `cb` is this call's own and the `DH *` is being returned.
        unsafe { BN_GENCB_free(cb) };
        return ret;
    }
    // SAFETY: both objects are this call's own.
    unsafe {
        BN_GENCB_free(cb);
        DH_free(ret);
    }
    core::ptr::null_mut()
}
