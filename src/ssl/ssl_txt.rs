//! Phase 14.7 — `ssl/ssl_txt.c`: the session printers.
//!
//! The three exported rows — `SSL_SESSION_print`, `SSL_SESSION_print_fp` and
//! `SSL_SESSION_print_keylog`. The body is the authority's `BIO_printf`/`BIO_puts` sequence, so a
//! differential court can compare the two transcripts byte for byte over an in-memory BIO.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The compression arm is reduced to the no-method answer.** The authority calls
//!   `ssl_cipher_get_evp(..., &comp, 0)` to name the compression method (`ssl_txt.c:123`); that
//!   internal helper is `ssl_ciph.c`'s and is not exported, so when `compress_meth != 0` this
//!   prints the `Compression: %d` form (the authority's own answer when `comp == NULL`). No court
//!   arm drives a session with a compression method set.
//! * **`SSL_SESSION_print_fp` reaches the file BIO through `BIO_ctrl`.** `BIO_set_fp` is a macro in
//!   the authority; here it is the `BIO_C_SET_FILE_PTR` control the macro expands to.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::{BIO_free, BIO_new, BIO_puts, Bio, BIO_NOCLOSE};
use crate::runtime::err::raise_with;
use crate::ssl::ssl_ciph::ssl_protocol_to_string;
use crate::ssl::ssl_lib::{SslSession, SSL_SESS_FLAG_EXTMS};
use crate::x509::x509_txt::X509_verify_cert_error_string;

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_txt.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_R_BUF_LIB`.
const ERR_R_BUF_LIB: c_int = 7 | (2 << 18);
/// `BIO_C_SET_FILE_PTR` — the control `BIO_set_fp` is a macro for.
const BIO_C_SET_FILE_PTR: c_int = 106;
/// `TLS1_3_VERSION` — `tls1.h`.
const TLS1_3_VERSION: c_int = 0x0304;

/// `int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x)` — `ssl/ssl_txt.c:34-173`.
///
/// # Safety
/// `bp` must be a live writable BIO; `x` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_print(bp: *mut Bio, x: *const SslSession) -> c_int {
    guard_ffi(0, || {
        if x.is_null() {
            return 0;
        }
        // SAFETY: `bp`/`x` are live per the caller's contract.
        unsafe {
            let s = &*x;
            let istls13 = s.ssl_version == TLS1_3_VERSION;
            if BIO_puts(bp, c"SSL-Session:\n".as_ptr()) <= 0 {
                return 0;
            }
            let proto = ssl_protocol_to_string(s.ssl_version);
            if BIO_printf(bp, c"    Protocol  : %s\n".as_ptr(), proto) <= 0 {
                return 0;
            }
            if s.cipher.is_null() {
                if (s.cipher_id & 0xff00_0000) == 0x0200_0000 {
                    if BIO_printf(
                        bp,
                        c"    Cipher    : %06lX\n".as_ptr(),
                        s.cipher_id & 0xff_ffff,
                    ) <= 0
                    {
                        return 0;
                    }
                } else if BIO_printf(
                    bp,
                    c"    Cipher    : %04lX\n".as_ptr(),
                    s.cipher_id & 0xffff,
                ) <= 0
                {
                    return 0;
                }
            } else {
                let name = (*s.cipher).name;
                let p = if name.is_empty() {
                    c"unknown".as_ptr()
                } else {
                    name.as_ptr().cast::<c_char>()
                };
                if BIO_printf(bp, c"    Cipher    : %s\n".as_ptr(), p) <= 0 {
                    return 0;
                }
            }
            if BIO_puts(bp, c"    Session-ID: ".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..s.session_id_length {
                if BIO_printf(bp, c"%02X".as_ptr(), s.session_id[i] as c_int) <= 0 {
                    return 0;
                }
            }
            if BIO_puts(bp, c"\n    Session-ID-ctx: ".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..s.sid_ctx_length {
                if BIO_printf(bp, c"%02X".as_ptr(), s.sid_ctx[i] as c_int) <= 0 {
                    return 0;
                }
            }
            if istls13 {
                if BIO_puts(bp, c"\n    Resumption PSK: ".as_ptr()) <= 0 {
                    return 0;
                }
            } else if BIO_puts(bp, c"\n    Master-Key: ".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..s.master_key_length {
                if BIO_printf(bp, c"%02X".as_ptr(), s.master_key[i] as c_int) <= 0 {
                    return 0;
                }
            }
            if BIO_puts(bp, c"\n    PSK identity: ".as_ptr()) <= 0 {
                return 0;
            }
            let psk = if s.psk_identity.is_null() {
                c"None".as_ptr()
            } else {
                s.psk_identity
            };
            if BIO_printf(bp, c"%s".as_ptr(), psk) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c"\n    PSK identity hint: ".as_ptr()) <= 0 {
                return 0;
            }
            let hint = if s.psk_identity_hint.is_null() {
                c"None".as_ptr()
            } else {
                s.psk_identity_hint
            };
            if BIO_printf(bp, c"%s".as_ptr(), hint) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c"\n    SRP username: ".as_ptr()) <= 0 {
                return 0;
            }
            let srp = if s.srp_username.is_null() {
                c"None".as_ptr()
            } else {
                s.srp_username
            };
            if BIO_printf(bp, c"%s".as_ptr(), srp) <= 0 {
                return 0;
            }
            if s.ext_tick_lifetime_hint != 0
                && BIO_printf(
                    bp,
                    c"\n    TLS session ticket lifetime hint: %ld (seconds)".as_ptr(),
                    s.ext_tick_lifetime_hint,
                ) <= 0
            {
                return 0;
            }
            if !s.ext_tick.is_null() {
                if BIO_puts(bp, c"\n    TLS session ticket:\n".as_ptr()) <= 0 {
                    return 0;
                }
                if BIO_dump_indent(bp, s.ext_tick.cast::<c_void>(), s.ext_ticklen as c_int, 4) <= 0
                {
                    return 0;
                }
            }
            if s.compress_meth != 0 {
                // The authority looks the method up; this build's sessions carry none.
                if BIO_printf(
                    bp,
                    c"\n    Compression: %d".as_ptr(),
                    s.compress_meth as c_int,
                ) <= 0
                {
                    return 0;
                }
            }
            if s.time != 0 && BIO_printf(bp, c"\n    Start Time: %lld".as_ptr(), s.time as i64) <= 0
            {
                return 0;
            }
            if s.timeout != 0
                && BIO_printf(
                    bp,
                    c"\n    Timeout   : %lld (sec)".as_ptr(),
                    s.timeout as i64,
                ) <= 0
            {
                return 0;
            }
            if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c"    Verify return code: ".as_ptr()) <= 0 {
                return 0;
            }
            if BIO_printf(
                bp,
                c"%ld (%s)\n".as_ptr(),
                s.verify_result,
                X509_verify_cert_error_string(s.verify_result),
            ) <= 0
            {
                return 0;
            }
            let extms = if s.flags & SSL_SESS_FLAG_EXTMS != 0 {
                c"yes".as_ptr()
            } else {
                c"no".as_ptr()
            };
            if BIO_printf(bp, c"    Extended master secret: %s\n".as_ptr(), extms) <= 0 {
                return 0;
            }
            if istls13
                && BIO_printf(
                    bp,
                    c"    Max Early Data: %u\n".as_ptr(),
                    s.ext_max_early_data as c_uint,
                ) <= 0
            {
                return 0;
            }
            1
        }
    })
}

/// `int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *x)` — `ssl/ssl_txt.c:18-31`.
///
/// # Safety
/// `fp` must be a live writable stream; `x` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_print_fp(fp: *mut c_void, x: *const SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BIO_s_file` is a static method table.
        let b = unsafe { BIO_new(BIO_s_file()) };
        if b.is_null() {
            // SAFETY: the error state is thread-local.
            unsafe { raise_with(ERR_LIB_SSL, ERR_R_BUF_LIB, FILE, 24) };
            return 0;
        }
        // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
        // SAFETY: `b` is a live file BIO; `fp` is the caller's stream.
        unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE as c_long, fp) };
        // SAFETY: `b` is live and `x` is the caller's.
        let ret = unsafe { SSL_SESSION_print(b, x) };
        // SAFETY: `b` is this frame's own BIO.
        unsafe { BIO_free(b) };
        ret
    })
}

/// `int SSL_SESSION_print_keylog(BIO *bp, const SSL_SESSION *x)` — `ssl/ssl_txt.c:179-214`.
///
/// # Safety
/// `bp` must be a live writable BIO; `x` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_print_keylog(bp: *mut Bio, x: *const SslSession) -> c_int {
    guard_ffi(0, || {
        if x.is_null() {
            return 0;
        }
        // SAFETY: `bp`/`x` are live per the caller's contract.
        unsafe {
            let s = &*x;
            if s.session_id_length == 0 || s.master_key_length == 0 {
                return 0;
            }
            if BIO_puts(bp, c"RSA ".as_ptr()) <= 0 {
                return 0;
            }
            if BIO_puts(bp, c"Session-ID:".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..s.session_id_length {
                if BIO_printf(bp, c"%02X".as_ptr(), s.session_id[i] as c_int) <= 0 {
                    return 0;
                }
            }
            if BIO_puts(bp, c" Master-Key:".as_ptr()) <= 0 {
                return 0;
            }
            for i in 0..s.master_key_length {
                if BIO_printf(bp, c"%02X".as_ptr(), s.master_key[i] as c_int) <= 0 {
                    return 0;
                }
            }
            if BIO_puts(bp, c"\n".as_ptr()) <= 0 {
                return 0;
            }
            1
        }
    })
}
