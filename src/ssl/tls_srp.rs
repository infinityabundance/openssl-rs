//! Phase 14.9 — `ssl/tls_srp.c`: the SRP credential and callback surface.
//!
//! The plan names nineteen rows for this unit: the context- and connection-level SRP credential
//! initialisers and destructors (`SSL_CTX_SRP_CTX_init`/`_free`, `SSL_SRP_CTX_init`/`_free`), the
//! context setters (`SSL_CTX_set_srp_username`/`_password`/`_strength`/`_cb_arg` and the three
//! callback installers), the server-parameter setters (`SSL_set_srp_server_param[_pw]`), the
//! readers (`SSL_get_srp_g`/`_N`/`_username`/`_userinfo`), the server public-key computation
//! (`SSL_srp_server_param_with_username`) and the client `A` computation (`SRP_Calc_A_param`).
//!
//! The credential block is the authority's `SRP_CTX` (`ssl_local.h:571-586`), transcribed as
//! [`SrpCtx`](crate::ssl::ssl_lib::SrpCtx) on both `SslCtx` and `Ssl`. The setters reproduce the
//! body the authority's `ssl3_ctx_ctrl`/`ssl3_ctx_callback_ctrl` (`s3_lib.c:4517-4550`,
//! `:4686-4699`) run; the arms live on `SSL_CTX_ctrl`/`SSL_CTX_callback_ctrl` in
//! `src/ssl/ssl_lib.rs`, so a direct control call and these wrappers agree.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`SSL_srp_server_param_with_username` computes `B` with the crate's landed `SRP_Calc_B_ex`.**
//!   The authority's `SSLfatal` site on a missing verifier is reproduced as the bare `SSL3_AL_FATAL`
//!   return; the fatal-error bookkeeping (`ossl_statem_fatal`) is the state machine's and is not
//!   reachable before a handshake.
//! * **The internal `srp_generate_*_master_secret` and `srp_verify_server_param` are not landed.**
//!   They are file-internal to the authority's `tls_srp.c` and are reached only from the handshake
//!   (`statem_srvr.c`/`statem_clnt.c`), which this stratum's tests do not drive; no exported row
//!   names them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::bn::bignum::{BN_bin2bn, BN_clear_free, BN_copy, BN_dup, BN_free};
use crate::ffi::guard_ffi;
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, OPENSSL_cleanse};
use crate::srp::srp_lib::{SRP_Calc_A, SRP_Calc_B_ex, SRP_get_default_gN};
use crate::srp::srp_vfy::SRP_create_verifier_BN_ex;
use crate::ssl::ssl_lib::{Ssl, SslCtx, SSL_MAX_MASTER_KEY_LENGTH};

/// `SRP_MINIMAL_N` — `include/openssl/srp.h.in:205`; the default minimum group bit length.
const SRP_MINIMAL_N: c_int = 1024;

/// `SSL3_AL_FATAL` — `ssl3.h`; the fatal alert level.
const SSL3_AL_FATAL: c_int = 2;
/// `SSL_AD_UNKNOWN_PSK_IDENTITY` — `tls1.h`.
const SSL_AD_UNKNOWN_PSK_IDENTITY: c_int = 47;
/// `SSL_AD_INTERNAL_ERROR` — `tls1.h`.
const SSL_AD_INTERNAL_ERROR: c_int = 80;
/// `SSL_ERROR_NONE` — `ssl.h:1258`.
const SSL_ERROR_NONE: c_int = 0;

/// `ssl_ctx_srp_ctx_free_intern` — `ssl/tls_srp.c:33-50`.
///
/// # Safety
/// `ctx` must be NULL or a live context whose `srp_ctx` this call may release.
unsafe fn srp_ctx_free(srp: *mut crate::ssl::ssl_lib::SrpCtx) {
    // SAFETY: `srp` is a live `SrpCtx` per the caller's contract; each field is NULL or owned.
    unsafe {
        CRYPTO_free((*srp).login.cast(), c"ssl/tls_srp.c".as_ptr(), 37);
        CRYPTO_free((*srp).info.cast(), c"ssl/tls_srp.c".as_ptr(), 38);
        BN_free((*srp).n);
        BN_free((*srp).g);
        BN_free((*srp).s);
        BN_free((*srp).b_pub);
        BN_free((*srp).a_pub);
        BN_free((*srp).a);
        BN_free((*srp).b);
        BN_free((*srp).v);
        ptr::write_bytes(srp, 0, 1);
        (*srp).strength = SRP_MINIMAL_N;
    }
}

/// `int ssl_ctx_srp_ctx_free_intern(SSL_CTX *ctx)` — `ssl/tls_srp.c:33-50`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
pub(crate) unsafe fn ssl_ctx_srp_ctx_free_intern(ctx: *mut SslCtx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL and live per the caller's contract.
    unsafe { srp_ctx_free(ptr::addr_of_mut!((*ctx).srp_ctx)) };
    1
}

/// `int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx)` — `ssl/tls_srp.c:52-55`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_SRP_CTX_free(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live per the caller's contract.
        unsafe { ssl_ctx_srp_ctx_free_intern(ctx) }
    })
}

/// `int ssl_srp_ctx_free_intern(SSL_CONNECTION *s)` — `ssl/tls_srp.c:61-78`.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl_srp_ctx_free_intern(s: *mut Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { srp_ctx_free(ptr::addr_of_mut!((*s).srp_ctx)) };
    1
}

/// `int SSL_SRP_CTX_free(SSL *s)` — `ssl/tls_srp.c:80-86`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_SRP_CTX_free(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the call works with a NULL `s`, as the authority's comment records.
        unsafe { ssl_srp_ctx_free_intern(s) }
    })
}

/// `int ssl_srp_ctx_init_intern(SSL_CONNECTION *s)` — `ssl/tls_srp.c:92-139`.
///
/// Copies the context's SRP credentials and callbacks onto the connection. The authority's single
/// `||` chain over the eight `BN_dup`s is kept as an ordered sequence, and any failure releases the
/// whole block and answers 0.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl_srp_ctx_init_intern(s: *mut Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is live per the caller's contract; its `ctx` is live for a live connection.
    let ctx = unsafe { (*s).ctx };
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `s` and `ctx` are live; `src` is the context's SRP block.
    unsafe {
        let src = ptr::addr_of!((*ctx).srp_ctx);
        ptr::write_bytes(ptr::addr_of_mut!((*s).srp_ctx), 0, 1);
        (*s).srp_ctx.srp_cb_arg = (*src).srp_cb_arg;
        (*s).srp_ctx.username_callback = (*src).username_callback;
        (*s).srp_ctx.verify_param_callback = (*src).verify_param_callback;
        (*s).srp_ctx.give_client_pwd_callback = (*src).give_client_pwd_callback;
        (*s).srp_ctx.strength = (*src).strength;
        (*s).srp_ctx.srp_mask = (*src).srp_mask;

        let dup_pairs: [(
            *const crate::bn::bignum::BigNum,
            *mut *mut crate::bn::bignum::BigNum,
        ); 8] = [
            ((*src).n, ptr::addr_of_mut!((*s).srp_ctx.n)),
            ((*src).g, ptr::addr_of_mut!((*s).srp_ctx.g)),
            ((*src).s, ptr::addr_of_mut!((*s).srp_ctx.s)),
            ((*src).b_pub, ptr::addr_of_mut!((*s).srp_ctx.b_pub)),
            ((*src).a_pub, ptr::addr_of_mut!((*s).srp_ctx.a_pub)),
            ((*src).a, ptr::addr_of_mut!((*s).srp_ctx.a)),
            ((*src).v, ptr::addr_of_mut!((*s).srp_ctx.v)),
            ((*src).b, ptr::addr_of_mut!((*s).srp_ctx.b)),
        ];
        for (from, to) in dup_pairs {
            if !from.is_null() {
                let d = BN_dup(from);
                if d.is_null() {
                    ssl_srp_ctx_free_intern(s);
                    return 0;
                }
                *to = d;
            }
        }
        if !(*src).login.is_null() {
            let d = CRYPTO_strdup((*src).login, c"ssl/tls_srp.c".as_ptr(), 115);
            if d.is_null() {
                ssl_srp_ctx_free_intern(s);
                return 0;
            }
            (*s).srp_ctx.login = d;
        }
        if !(*src).info.is_null() {
            let d = CRYPTO_strdup((*src).info, c"ssl/tls_srp.c".as_ptr(), 119);
            if d.is_null() {
                ssl_srp_ctx_free_intern(s);
                return 0;
            }
            (*s).srp_ctx.info = d;
        }
    }
    1
}

/// `int SSL_SRP_CTX_init(SSL *s)` — `ssl/tls_srp.c:141-147`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_SRP_CTX_init(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the call works with a NULL `s`.
        unsafe { ssl_srp_ctx_init_intern(s) }
    })
}

/// `int ssl_ctx_srp_ctx_init_intern(SSL_CTX *ctx)` — `ssl/tls_srp.c:153-162`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
pub(crate) unsafe fn ssl_ctx_srp_ctx_init_intern(ctx: *mut SslCtx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL and live per the caller's contract.
    unsafe {
        ptr::write_bytes(ptr::addr_of_mut!((*ctx).srp_ctx), 0, 1);
        (*ctx).srp_ctx.strength = SRP_MINIMAL_N;
    }
    1
}

/// `int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx)` — `ssl/tls_srp.c:164-167`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_SRP_CTX_init(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live per the caller's contract.
        unsafe { ssl_ctx_srp_ctx_init_intern(ctx) }
    })
}

/// `static char *srp_password_from_info_cb(SSL *s, void *arg)` — `s3_lib.c:3942-3950`.
///
/// The default client-password callback `SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD` installs: it answers a
/// fresh copy of the connection's stored `info`.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe extern "C" fn srp_password_from_info_cb(
    s: *mut Ssl,
    _arg: *mut c_void,
) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `s` is live; `info` is NULL or a NUL-terminated string.
    unsafe { CRYPTO_strdup((*s).srp_ctx.info, c"ssl/s3_lib.c".as_ptr(), 3949) }
}

/// `int ssl_srp_server_param_with_username_intern(SSL_CONNECTION *s, int *ad)` —
/// `ssl/tls_srp.c:174-202`.
///
/// # Safety
/// `s` must be a live connection and `ad` a writable `int`.
unsafe fn srp_server_param_with_username(s: *mut Ssl, ad: *mut c_int) -> c_int {
    let mut b = [0u8; SSL_MAX_MASTER_KEY_LENGTH];
    // SAFETY: `s` is live per the caller's contract.
    let ctx = unsafe { (*s).ctx };
    // SAFETY: `ad` is writable; `s` is live.
    unsafe {
        *ad = SSL_AD_UNKNOWN_PSK_IDENTITY;
        if let Some(cb) = (*s).srp_ctx.username_callback {
            let al = cb(s, ad, (*s).srp_ctx.srp_cb_arg);
            if al != SSL_ERROR_NONE {
                return al;
            }
        }
        *ad = SSL_AD_INTERNAL_ERROR;
        if (*s).srp_ctx.n.is_null()
            || (*s).srp_ctx.g.is_null()
            || (*s).srp_ctx.s.is_null()
            || (*s).srp_ctx.v.is_null()
        {
            return SSL3_AL_FATAL;
        }
        let libctx = if ctx.is_null() {
            ptr::null_mut()
        } else {
            (*ctx).libctx
        };
        if RAND_priv_bytes_ex(libctx, b.as_mut_ptr(), b.len(), 0) <= 0 {
            return SSL3_AL_FATAL;
        }
        (*s).srp_ctx.b = BN_bin2bn(b.as_ptr(), b.len() as c_int, ptr::null_mut());
        OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len());
        let propq = if ctx.is_null() {
            ptr::null()
        } else {
            (*ctx).propq
        };
        let bn = SRP_Calc_B_ex(
            (*s).srp_ctx.b,
            (*s).srp_ctx.n,
            (*s).srp_ctx.g,
            (*s).srp_ctx.v,
            libctx,
            propq,
        );
        (*s).srp_ctx.b_pub = bn;
        if bn.is_null() {
            SSL3_AL_FATAL
        } else {
            SSL_ERROR_NONE
        }
    }
}

/// `int SSL_srp_server_param_with_username(SSL *s, int *ad)` — `ssl/tls_srp.c:204-212`.
///
/// # Safety
/// `s` must be NULL or a live connection; `ad` a writable `int`.
#[no_mangle]
pub unsafe extern "C" fn SSL_srp_server_param_with_username(s: *mut Ssl, ad: *mut c_int) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return SSL3_AL_FATAL;
        }
        // SAFETY: `s` is live; `ad` is writable per the caller's contract.
        unsafe { srp_server_param_with_username(s, ad) }
    })
}

/// `int SSL_set_srp_server_param_pw(SSL *s, const char *user, const char *pass, const char *grp)`
/// — `ssl/tls_srp.c:218-242`.
///
/// # Safety
/// `s` must be NULL or a live connection; `user`/`pass`/`grp` NULL or NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_srp_server_param_pw(
    s: *mut Ssl,
    user: *const c_char,
    pass: *const c_char,
    grp: *const c_char,
) -> c_int {
    guard_ffi(-1, || {
        if s.is_null() {
            return -1;
        }
        // SAFETY: `grp` is NULL or NUL-terminated per the caller's contract.
        let gn = unsafe { SRP_get_default_gN(grp) };
        if gn.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; `gn` is a process-lifetime constant row.
        unsafe {
            (*s).srp_ctx.n = BN_dup((*gn).N);
            (*s).srp_ctx.g = BN_dup((*gn).g);
            BN_clear_free((*s).srp_ctx.v);
            (*s).srp_ctx.v = ptr::null_mut();
            BN_clear_free((*s).srp_ctx.s);
            (*s).srp_ctx.s = ptr::null_mut();
            let ctx = (*s).ctx;
            let libctx = if ctx.is_null() {
                ptr::null_mut()
            } else {
                (*ctx).libctx
            };
            let propq = if ctx.is_null() {
                ptr::null()
            } else {
                (*ctx).propq
            };
            if SRP_create_verifier_BN_ex(
                user,
                pass,
                ptr::addr_of_mut!((*s).srp_ctx.s),
                ptr::addr_of_mut!((*s).srp_ctx.v),
                (*s).srp_ctx.n,
                (*s).srp_ctx.g,
                libctx,
                propq,
            ) == 0
            {
                return -1;
            }
        }
        1
    })
}

/// `int SSL_set_srp_server_param(SSL *s, const BIGNUM *N, const BIGNUM *g, BIGNUM *sa,
/// BIGNUM *v, char *info)` — `ssl/tls_srp.c:244-299`.
///
/// # Safety
/// `s` must be NULL or a live connection; `N`/`g`/`sa`/`v` NULL or live `BIGNUM`s; `info` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_srp_server_param(
    s: *mut Ssl,
    big_n: *const crate::bn::bignum::BigNum,
    g: *const crate::bn::bignum::BigNum,
    sa: *mut crate::bn::bignum::BigNum,
    v: *mut crate::bn::bignum::BigNum,
    info: *mut c_char,
) -> c_int {
    guard_ffi(-1, || {
        if s.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; every pointer argument is NULL or live per the caller's contract.
        unsafe {
            if !big_n.is_null() {
                if !(*s).srp_ctx.n.is_null() {
                    if BN_copy((*s).srp_ctx.n, big_n).is_null() {
                        BN_free((*s).srp_ctx.n);
                        (*s).srp_ctx.n = ptr::null_mut();
                    }
                } else {
                    (*s).srp_ctx.n = BN_dup(big_n);
                }
            }
            if !g.is_null() {
                if !(*s).srp_ctx.g.is_null() {
                    if BN_copy((*s).srp_ctx.g, g).is_null() {
                        BN_free((*s).srp_ctx.g);
                        (*s).srp_ctx.g = ptr::null_mut();
                    }
                } else {
                    (*s).srp_ctx.g = BN_dup(g);
                }
            }
            if !sa.is_null() {
                if !(*s).srp_ctx.s.is_null() {
                    if BN_copy((*s).srp_ctx.s, sa).is_null() {
                        BN_free((*s).srp_ctx.s);
                        (*s).srp_ctx.s = ptr::null_mut();
                    }
                } else {
                    (*s).srp_ctx.s = BN_dup(sa);
                }
            }
            if !v.is_null() {
                if !(*s).srp_ctx.v.is_null() {
                    if BN_copy((*s).srp_ctx.v, v).is_null() {
                        BN_free((*s).srp_ctx.v);
                        (*s).srp_ctx.v = ptr::null_mut();
                    }
                } else {
                    (*s).srp_ctx.v = BN_dup(v);
                }
            }
            if !info.is_null() {
                if !(*s).srp_ctx.info.is_null() {
                    CRYPTO_free((*s).srp_ctx.info.cast(), c"ssl/tls_srp.c".as_ptr(), 290);
                }
                let d = CRYPTO_strdup(info, c"ssl/tls_srp.c".as_ptr(), 291);
                if d.is_null() {
                    return -1;
                }
                (*s).srp_ctx.info = d;
            }
            if (*s).srp_ctx.n.is_null()
                || (*s).srp_ctx.g.is_null()
                || (*s).srp_ctx.s.is_null()
                || (*s).srp_ctx.v.is_null()
            {
                return -1;
            }
        }
        1
    })
}

/// `int ssl_srp_calc_a_param_intern(SSL_CONNECTION *s)` — `ssl/tls_srp.c:427-442`.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn srp_calc_a_param(s: *mut Ssl) -> c_int {
    let mut rnd = [0u8; SSL_MAX_MASTER_KEY_LENGTH];
    // SAFETY: `s` is live per the caller's contract.
    let ctx = unsafe { (*s).ctx };
    let libctx = if ctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `ctx` is non-NULL and live per the guard above.
        unsafe { (*ctx).libctx }
    };
    // SAFETY: the buffer is this function's own.
    if unsafe { RAND_priv_bytes_ex(libctx, rnd.as_mut_ptr(), rnd.len(), 0) } <= 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe {
        (*s).srp_ctx.a = BN_bin2bn(rnd.as_ptr(), rnd.len() as c_int, (*s).srp_ctx.a);
        OPENSSL_cleanse(rnd.as_mut_ptr().cast(), rnd.len());
        let a = SRP_Calc_A((*s).srp_ctx.a, (*s).srp_ctx.n, (*s).srp_ctx.g);
        (*s).srp_ctx.a_pub = a;
        if a.is_null() {
            0
        } else {
            1
        }
    }
}

/// `int SRP_Calc_A_param(SSL *s)` — `ssl/tls_srp.c:444-452`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SRP_Calc_A_param(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe { srp_calc_a_param(s) }
    })
}

/// `BIGNUM *SSL_get_srp_g(SSL *s)` — `ssl/tls_srp.c:454-464`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_srp_g(s: *mut Ssl) -> *mut crate::bn::bignum::BigNum {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live; its `ctx` is live for a live connection.
        unsafe {
            if !(*s).srp_ctx.g.is_null() {
                return (*s).srp_ctx.g;
            }
            (*s).ctx.as_ref().map_or(ptr::null_mut(), |c| c.srp_ctx.g)
        }
    })
}

/// `BIGNUM *SSL_get_srp_N(SSL *s)` — `ssl/tls_srp.c:466-476`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_srp_N(s: *mut Ssl) -> *mut crate::bn::bignum::BigNum {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live; its `ctx` is live for a live connection.
        unsafe {
            if !(*s).srp_ctx.n.is_null() {
                return (*s).srp_ctx.n;
            }
            (*s).ctx.as_ref().map_or(ptr::null_mut(), |c| c.srp_ctx.n)
        }
    })
}

/// `char *SSL_get_srp_username(SSL *s)` — `ssl/tls_srp.c:478-488`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_srp_username(s: *mut Ssl) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live; its `ctx` is live for a live connection.
        unsafe {
            if !(*s).srp_ctx.login.is_null() {
                return (*s).srp_ctx.login;
            }
            (*s).ctx
                .as_ref()
                .map_or(ptr::null_mut(), |c| c.srp_ctx.login)
        }
    })
}

/// `char *SSL_get_srp_userinfo(SSL *s)` — `ssl/tls_srp.c:490-500`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_srp_userinfo(s: *mut Ssl) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live; its `ctx` is live for a live connection.
        unsafe {
            if !(*s).srp_ctx.info.is_null() {
                return (*s).srp_ctx.info;
            }
            (*s).ctx
                .as_ref()
                .map_or(ptr::null_mut(), |c| c.srp_ctx.info)
        }
    })
}

// -------------------------------------------------------------------------------------------
// The context setters — `ssl/tls_srp.c:505-545`. Each is `tls1_ctx_ctrl` (`ssl3_ctx_ctrl`) or
// `tls1_ctx_callback_ctrl` (`ssl3_ctx_callback_ctrl`); the crate's `SSL_CTX_ctrl` /
// `SSL_CTX_callback_ctrl` carry those arms.
// -------------------------------------------------------------------------------------------

/// `int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name)` — `ssl/tls_srp.c:505-508`.
///
/// # Safety
/// `ctx` must be NULL or a live context; `name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_username(ctx: *mut SslCtx, name: *mut c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live; `name` is the control's `parg`.
        unsafe {
            crate::ssl::ssl_lib::ssl3_ctx_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_TLS_EXT_SRP_USERNAME,
                0,
                name.cast(),
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_password(SSL_CTX *ctx, char *password)` — `ssl/tls_srp.c:510-513`.
///
/// # Safety
/// `ctx` must be NULL or a live context; `password` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_password(
    ctx: *mut SslCtx,
    password: *mut c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live; `password` is the control's `parg`.
        unsafe {
            crate::ssl::ssl_lib::ssl3_ctx_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD,
                0,
                password.cast(),
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength)` — `ssl/tls_srp.c:515-519`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_strength(ctx: *mut SslCtx, strength: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live.
        unsafe {
            crate::ssl::ssl_lib::ssl3_ctx_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH,
                strength as core::ffi::c_long,
                ptr::null_mut(),
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx, int (*cb)(SSL *, void *))` —
/// `ssl/tls_srp.c:521-526`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_verify_param_callback(
    ctx: *mut SslCtx,
    cb: Option<crate::ssl::ssl_lib::SrpVerifyParamCb>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live; the callback is transmuted to the `void (*)(void)` shape
        // `SSL_CTX_callback_ctrl` takes, exactly as the authority casts it.
        unsafe {
            crate::ssl::ssl_lib::SSL_CTX_callback_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_SRP_VERIFY_PARAM_CB,
                cb.map(|f| core::mem::transmute::<_, unsafe extern "C" fn()>(f)),
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_cb_arg(SSL_CTX *ctx, void *arg)` — `ssl/tls_srp.c:528-531`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_cb_arg(ctx: *mut SslCtx, arg: *mut c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live.
        unsafe {
            crate::ssl::ssl_lib::ssl3_ctx_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_SRP_ARG,
                0,
                arg,
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_username_callback(SSL_CTX *ctx, int (*cb)(SSL *, int *, void *))` —
/// `ssl/tls_srp.c:533-538`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_username_callback(
    ctx: *mut SslCtx,
    cb: Option<crate::ssl::ssl_lib::SrpUsernameCb>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live; the callback is transmuted as above.
        unsafe {
            crate::ssl::ssl_lib::SSL_CTX_callback_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB,
                cb.map(|f| core::mem::transmute::<_, unsafe extern "C" fn()>(f)),
            ) as c_int
        }
    })
}

/// `int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx, char *(*cb)(SSL *, void *))` —
/// `ssl/tls_srp.c:540-545`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_srp_client_pwd_callback(
    ctx: *mut SslCtx,
    cb: Option<crate::ssl::ssl_lib::SrpClientPwdCb>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live; the callback is transmuted as above.
        unsafe {
            crate::ssl::ssl_lib::SSL_CTX_callback_ctrl(
                ctx,
                crate::ssl::ssl_lib::SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB,
                cb.map(|f| core::mem::transmute::<_, unsafe extern "C" fn()>(f)),
            ) as c_int
        }
    })
}
