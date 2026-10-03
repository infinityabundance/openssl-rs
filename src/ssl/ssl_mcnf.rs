//! Phase 14.9 — `ssl/ssl_mcnf.c`: the `SSL_CTX_config`/`SSL_add_ssl_module` config glue.
//!
//! The three rows the plan gives this unit: `SSL_add_ssl_module` (the authority's deliberate
//! no-op — libcrypto registers the `ssl_conf` reader itself), `SSL_config` and `SSL_CTX_config`,
//! which run a named command set out of the configuration the `ssl_conf` module stored. The
//! reader is `ssl_do_config` (`ssl_mcnf.c:23-92`), transcribed in full: it finds the named set
//! through `conf_ssl_name_find`/`conf_ssl_get`, builds an `SSL_CONF_CTX` against the connection or
//! context, sets the file/certificate/role flags, switches the thread's default library context,
//! and runs each `cmd,arg` through `SSL_CONF_cmd`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`ssl_ctx_system_config` is a private call of `SSL_CTX_new_ex`.** The authority runs the
//!   `system_default` set at context construction (`ssl_lib.c:4280`); `src/ssl/ssl_lib.rs` calls
//!   this module's `ssl_ctx_system_config` there, so a loaded configuration's `system_default`
//!   section applies exactly as the authority applies it.
//! * **The invalid-name raise carries no `name=%s` data.** The authority's
//!   `ERR_raise_data(..., "name=%s", name)` attaches formatted text; this crate's raise records the
//!   library and reason only. Error text is not compared by this stratum's courts (the candidate's
//!   error state is a documented duplicate, `src/ssl/mod.rs`), so only the reason code is
//!   meaningful here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use crate::context::{OSSL_LIB_CTX_get_conf_diagnostics, OSSL_LIB_CTX_set0_default};
use crate::ffi::guard_ffi;
use crate::runtime::conf::conf_ssl::{conf_ssl_get, conf_ssl_get_cmd, conf_ssl_name_find};
use crate::runtime::err::raise_with;
use crate::ssl::ssl_conf::{
    SSL_CONF_CTX_finish, SSL_CONF_CTX_free, SSL_CONF_CTX_new, SSL_CONF_CTX_set_flags,
    SSL_CONF_CTX_set_ssl, SSL_CONF_CTX_set_ssl_ctx, SSL_CONF_cmd,
};
use crate::ssl::ssl_lib::{Ssl, SslCtx};

/// `ERR_LIB_SSL` — `err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h:353` (`258 | ERR_R_FATAL`).
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | (3 << 18);
/// `SSL_R_INVALID_CONFIGURATION_NAME` — `sslerr.h:148`.
const SSL_R_INVALID_CONFIGURATION_NAME: c_int = 113;

/// `SSL_CONF_FLAG_FILE` — `ssl.h:604`.
const SSL_CONF_FLAG_FILE: c_uint = 0x2;
/// `SSL_CONF_FLAG_CLIENT` — `ssl.h:605`.
const SSL_CONF_FLAG_CLIENT: c_uint = 0x4;
/// `SSL_CONF_FLAG_SERVER` — `ssl.h:606`.
const SSL_CONF_FLAG_SERVER: c_uint = 0x8;
/// `SSL_CONF_FLAG_SHOW_ERRORS` — `ssl.h:607`.
const SSL_CONF_FLAG_SHOW_ERRORS: c_uint = 0x10;
/// `SSL_CONF_FLAG_CERTIFICATE` — `ssl.h:608`.
const SSL_CONF_FLAG_CERTIFICATE: c_uint = 0x20;
/// `SSL_CONF_FLAG_REQUIRE_PRIVATE` — `ssl.h:609`.
const SSL_CONF_FLAG_REQUIRE_PRIVATE: c_uint = 0x40;

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_mcnf.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` one of this file's constants.
    unsafe { raise_with(ERR_LIB_SSL, reason, c"ssl/ssl_mcnf.c".as_ptr(), line) };
}

/// `void SSL_add_ssl_module(void)` — `ssl/ssl_mcnf.c:18-21`.
///
/// The authority's whole body is a comment: libcrypto's built-in modules add the `ssl_conf`
/// reader, so this is deliberately a no-op.
#[no_mangle]
pub extern "C" fn SSL_add_ssl_module() {}

/// `static int ssl_do_config(SSL *s, SSL_CTX *ctx, const char *name, int system)` —
/// `ssl/ssl_mcnf.c:23-92`.
///
/// # Safety
/// Exactly one of `s`/`ctx` must be non-NULL or both NULL (the refusal arm); `name` must be NULL
/// or NUL-terminated; whichever of `s`/`ctx` is non-NULL must be live.
unsafe fn ssl_do_config(
    s: *mut Ssl,
    ctx: *mut SslCtx,
    name: *const c_char,
    mut system: c_int,
) -> c_int {
    let mut err: c_int = 1;
    let mut conf_diagnostics: c_int = 0;
    let mut prev_libctx: *mut core::ffi::c_void = ptr::null_mut();
    let libctx: *mut core::ffi::c_void;
    let mut cctx: *mut crate::ssl::ssl_conf::SslConfCtx = ptr::null_mut();

    if s.is_null() && ctx.is_null() {
        // SAFETY: a constant site.
        unsafe { raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 36) };
        // SAFETY: `cctx` is NULL and `prev_libctx` NULL, so the release calls are no-ops.
        return unsafe { finish_do_config(cctx, prev_libctx, err, system, conf_diagnostics) };
    }

    let mut cfg_name = name;
    if cfg_name.is_null() && system != 0 {
        cfg_name = c"system_default".as_ptr();
    }
    let mut idx: usize = 0;
    // SAFETY: `cfg_name` is NULL or NUL-terminated per the caller's contract; `idx` is writable.
    if unsafe { conf_ssl_name_find(cfg_name, &mut idx) } == 0 {
        if system == 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_INVALID_CONFIGURATION_NAME, 44) };
        }
        // SAFETY: `cctx` is NULL and `prev_libctx` NULL, so the release calls are no-ops.
        return unsafe { finish_do_config(cctx, prev_libctx, err, system, conf_diagnostics) };
    }
    let mut cmd_count: usize = 0;
    // SAFETY: `idx` came from `conf_ssl_name_find`, and both out-parameters are writable.
    let cmds = unsafe { conf_ssl_get(idx, &mut cfg_name, &mut cmd_count) };
    // SAFETY: a fresh zeroed configuration context.
    cctx = unsafe { SSL_CONF_CTX_new() };
    if cctx.is_null() {
        // A fatal allocation error is always reported.
        system = 0;
        // SAFETY: `cctx` is NULL and `prev_libctx` NULL, so the release calls are no-ops.
        return unsafe { finish_do_config(cctx, prev_libctx, err, system, conf_diagnostics) };
    }

    let mut flags: c_uint = SSL_CONF_FLAG_FILE;
    if system == 0 {
        flags |= SSL_CONF_FLAG_CERTIFICATE | SSL_CONF_FLAG_REQUIRE_PRIVATE;
    }
    let meth = if !s.is_null() {
        // SAFETY: `s` is live per the caller's contract.
        let meth = unsafe { (*s).method };
        // SAFETY: `cctx` and `s` are live.
        unsafe { SSL_CONF_CTX_set_ssl(cctx, s) };
        // SAFETY: `s` is live; its `ctx` is live.
        libctx = unsafe { (*(*s).ctx).libctx };
        meth
    } else {
        // SAFETY: `ctx` is live per the caller's contract.
        let meth = unsafe { (*ctx).method };
        // SAFETY: `cctx` and `ctx` are live.
        unsafe { SSL_CONF_CTX_set_ssl_ctx(cctx, ctx) };
        // SAFETY: `ctx` is live.
        libctx = unsafe { (*ctx).libctx };
        meth
    };
    // SAFETY: `libctx` is NULL or live.
    conf_diagnostics = unsafe { OSSL_LIB_CTX_get_conf_diagnostics(libctx) };
    if conf_diagnostics != 0 {
        flags |= SSL_CONF_FLAG_SHOW_ERRORS;
    }
    if meth.is_null() {
        // A context or connection always carries a method; guard defensively so the flags below do
        // not read through NULL.
        // SAFETY: `cctx`/`prev_libctx` are live or NULL per the guards above.
        return unsafe { finish_do_config(cctx, prev_libctx, err, system, conf_diagnostics) };
    }
    // SAFETY: `meth` is live.
    if unsafe { (*meth).default_server } {
        flags |= SSL_CONF_FLAG_SERVER;
    }
    // SAFETY: `meth` is live.
    if unsafe { (*meth).default_client } {
        flags |= SSL_CONF_FLAG_CLIENT;
    }
    // SAFETY: `cctx` is live.
    unsafe { SSL_CONF_CTX_set_flags(cctx, flags) };
    // SAFETY: `libctx` is NULL or live; the previous default is restored at the end.
    prev_libctx = unsafe { OSSL_LIB_CTX_set0_default(libctx) };
    err = 0;
    let mut i: usize = 0;
    while i < cmd_count {
        let mut cmdstr: *mut c_char = ptr::null_mut();
        let mut arg: *mut c_char = ptr::null_mut();
        // SAFETY: `i < cmd_count`, and both out-parameters are writable.
        unsafe { conf_ssl_get_cmd(cmds, i, &mut cmdstr, &mut arg) };
        // SAFETY: `cctx` is live; the strings belong to the stored configuration.
        let rv = unsafe { SSL_CONF_cmd(cctx, cmdstr, arg) };
        if rv <= 0 {
            err += 1;
        }
        i += 1;
    }
    // SAFETY: `cctx` is live.
    if unsafe { SSL_CONF_CTX_finish(cctx) } == 0 {
        err += 1;
    }
    // SAFETY: as above.
    unsafe { finish_do_config(cctx, prev_libctx, err, system, conf_diagnostics) }
}

/// The authority's `err:` label: restore the default library context, release the configuration
/// context, and fold the error count into the return.
///
/// # Safety
/// `cctx` must be NULL or a live `SSL_CONF_CTX`; `prev_libctx` the value `OSSL_LIB_CTX_set0_default`
/// returned (or NULL when that call never ran).
unsafe fn finish_do_config(
    cctx: *mut crate::ssl::ssl_conf::SslConfCtx,
    prev_libctx: *mut core::ffi::c_void,
    err: c_int,
    system: c_int,
    conf_diagnostics: c_int,
) -> c_int {
    // SAFETY: `prev_libctx` is NULL or the value the setter returned; passing NULL is a no-op.
    unsafe { OSSL_LIB_CTX_set0_default(prev_libctx) };
    // SAFETY: `cctx` is NULL or live and owned here.
    unsafe { SSL_CONF_CTX_free(cctx) };
    c_int::from(err == 0 || (system != 0 && conf_diagnostics == 0))
}

/// `int SSL_config(SSL *s, const char *name)` — `ssl/ssl_mcnf.c:94-97`.
///
/// # Safety
/// `s` must be a live connection; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_config(s: *mut Ssl, name: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live; `name` is NULL or NUL-terminated per the caller's contract.
        unsafe { ssl_do_config(s, ptr::null_mut(), name, 0) }
    })
}

/// `int SSL_CTX_config(SSL_CTX *ctx, const char *name)` — `ssl/ssl_mcnf.c:99-102`.
///
/// # Safety
/// `ctx` must be a live context; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_config(ctx: *mut SslCtx, name: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live; `name` is NULL or NUL-terminated per the caller's contract.
        unsafe { ssl_do_config(ptr::null_mut(), ctx, name, 0) }
    })
}

/// `int ssl_ctx_system_config(SSL_CTX *ctx)` — `ssl/ssl_mcnf.c:104-107`.
///
/// # Safety
/// `ctx` must be a live context.
pub(crate) unsafe fn ssl_ctx_system_config(ctx: *mut SslCtx) -> c_int {
    // SAFETY: `ctx` is live per the caller's contract; `name` is NULL and `system` set.
    unsafe { ssl_do_config(ptr::null_mut(), ctx, ptr::null(), 1) }
}
