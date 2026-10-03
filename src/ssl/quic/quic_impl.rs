//! Phase 14.10 — `ssl/quic/quic_impl.c`: `SSL_inject_net_dgram`.
//!
//! This crate owns exactly one export of `quic_impl.c` (`ssl.h`'s `SSL_inject_net_dgram`); the rest
//! of the unit is `quic.h`'s and belongs to Phase 15. The authority's body begins
//! `if (!expect_quic_csl(s, &ctx)) return 0;` (`quic_impl.c:3301`), which is false for every object
//! that is not a QUIC connection, listener or stream.
//!
//! ## Measured divergence, recorded rather than hidden
//!
//! **The QUIC-object arm is unreachable.** This crate builds no QUIC object — `SSL_new_listener`,
//! `SSL_new_stream` and their neighbours answer for a non-QUIC connection (14.1 records that
//! reduction) — so `expect_quic_csl` is always false and the demux-injection half below it
//! (`quic_impl.c:3304-3317`) is not modelled. `RT-SSL-INIT` drives the NULL/QUIC/TLS refusal arms,
//! where the authority's own answer is 0.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::ffi::guard_ffi;
use crate::ssl::ssl_lib::{SSL_is_quic, Ssl};

/// `int SSL_inject_net_dgram(SSL *s, const unsigned char *buf, size_t buf_len, const BIO_ADDR *peer,
/// const BIO_ADDR *local)` — `ssl/quic/quic_impl.c:3291-3318`, reduced as the module header records.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf`/`peer`/`local` are read only on the QUIC arm, which
/// is unreachable here.
#[no_mangle]
pub unsafe extern "C" fn SSL_inject_net_dgram(
    s: *mut Ssl,
    buf: *const u8,
    buf_len: usize,
    peer: *const c_void,
    local: *const c_void,
) -> c_int {
    let _ = (buf, buf_len, peer, local);
    guard_ffi(0, || {
        // `expect_quic_csl(s, &ctx)` is false for NULL and for every object this crate builds.
        // SAFETY: `SSL_is_quic` accepts NULL.
        if s.is_null() || unsafe { SSL_is_quic(s) } == 0 {
            return 0;
        }
        0
    })
}
