//! Phase 15 — `ssl/quic/quic_method.c`: the three `quic.h` method constructors.
//!
//! This module lands the whole of `quic_method.c`, the unit that defines `quic.h`'s three exports
//! and nothing else: `OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and
//! `OSSL_QUIC_server_method`. Each is the `IMPLEMENT_quic_meth_func` expansion
//! (`ssl/quic/quic_local.h:301-340`) — a process-lifetime `static const SSL_METHOD` returned by
//! the constructor.
//!
//! ## What this crate stores, and what it does not
//!
//! The authority's `SSL_METHOD` is a function-pointer block; this crate's [`SslMethod`]
//! (`src/ssl/ssl_lib.rs`, 14.2) keeps only the fields a landed subphase reads — `version`, `flags`,
//! `mask`, the default timeout, and the two derived predicates `dtls` (the `ssl3_enc` table's
//! `SSL_ENC_FLAG_DTLS` bit) and `default_server`/`default_client`
//! (`method->ssl_accept`/`ssl_connect != ssl_undefined_function`). The three QUIC rows are built
//! from the authority's own table:
//!
//! * `version` is `OSSL_QUIC_ANY_VERSION` (`quic_local.h:298`, `0xFFFFF`) for all three;
//! * `flags` and `mask` are both `0` (`IMPLEMENT_quic_meth_func` passes `0, 0`);
//! * `timeout_secs` is `tls1_default_timeout` (`quic_local.h:333`), also two hours;
//! * `dtls` is false and `enc_flags` is `0`: the table's `ssl3_enc` is `ssl3_undef_enc_method`
//!   (`ssl_lib.c:75-86`), whose `enc_flags` is not initialised and is therefore zero, so the
//!   method carries neither `SSL_ENC_FLAG_DTLS` nor the TLS1.2 cipher bits;
//! * `default_server` is `q_accept != ssl_undefined_function` and `default_client` is
//!   `q_connect != ssl_undefined_function`: the two client constructors install
//!   `ossl_quic_connect` and `ssl_undefined_function`, the server constructor installs
//!   `ossl_quic_accept` and `ssl_undefined_function` (`quic_method.c:14-27`).
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! **The QUIC dispatch table and the QUIC object are not built here.** `ossl_quic_new`,
//! `ossl_quic_free`, `ossl_quic_connect`/`_accept` and the rest of `quic_impl.c` are the QUIC
//! implementation object, which the plan defers to a later stratum (the installed-distribution
//! work is Phase 16's; the message layer `ssl/statem/statem_clnt.c` and `statem_srvr.c` are the
//! same deferral in `forensics/prerequisites.json`); this module installs only the method
//! *identity* the objects above model, which is all a constructor observable without a connection
//! reads. The consequence is named rather than implied:
//!
//! * **`SSL_new` on a QUIC method is not the authority's.** The authority's `ossl_quic_new`
//!   (`quic_impl.c:591`) builds a `QUIC_CONNECTION` (and *refuses* `OSSL_QUIC_server_method`
//!   with `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`), so a candidate connection built from these
//!   methods is an ordinary `SSL` object and reports `SSL_is_quic == 0` where the authority
//!   reports `1`. `RT-QUIC` therefore does not drive `SSL_new`; the QUIC object is the later
//!   stratum's, and this divergence is what keeps the constructors' court honest about it.
//! * **`SSL_CTX_set_ssl_version`'s `IS_QUIC_CTX` refusal is not modelled.** The authority refuses
//!   a QUIC context there via `IS_QUIC_METHOD` pointer identity
//!   (`ssl_unwrap.h:52-54`, `ssl_lib.c:662-687`); `src/ssl/ssl_lib.rs:8701` records that the
//!   contexts this crate builds never reach the arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::ssl::ssl_lib::SslMethod;

/// `OSSL_QUIC_ANY_VERSION` — `ssl/quic/quic_local.h:298` (`0xFFFFF`), the version every QUIC
/// method carries.
const OSSL_QUIC_ANY_VERSION: c_int = 0xFFFFF;

/// `tls1_default_timeout` (`t1_lib.c:96-103`) — `ossl_seconds2time(60 * 60 * 2)`, reduced to
/// seconds, the timeout `IMPLEMENT_quic_meth_func` installs (`quic_local.h:333`).
const TIMEOUT_SECS: u64 = 60 * 60 * 2;

/// Build a QUIC table row: `flags` and `mask` are zero, the `ssl3_enc` is `ssl3_undef_enc_method`
/// (no enc flags), and the role predicates come from the `q_accept`/`q_connect` pair.
const fn quic(default_server: bool, default_client: bool) -> SslMethod {
    SslMethod {
        version: OSSL_QUIC_ANY_VERSION,
        flags: 0 as c_uint,
        mask: 0,
        timeout_secs: TIMEOUT_SECS,
        dtls: false,
        enc_flags: 0,
        default_server,
        default_client,
    }
}

/// `OSSL_QUIC_client_method`'s table — `quic_method.c:14-17` (`q_accept = ssl_undefined_function`,
/// `q_connect = ossl_quic_connect`).
static OSSL_QUIC_CLIENT_METHOD_DATA: SslMethod = quic(false, true);
/// `OSSL_QUIC_client_thread_method`'s table — `quic_method.c:19-22`, identical to the client
/// method's but a distinct static (the authority builds a separate `_data` per constructor).
static OSSL_QUIC_CLIENT_THREAD_METHOD_DATA: SslMethod = quic(false, true);
/// `OSSL_QUIC_server_method`'s table — `quic_method.c:24-27` (`q_accept = ossl_quic_accept`,
/// `q_connect = ssl_undefined_function`).
static OSSL_QUIC_SERVER_METHOD_DATA: SslMethod = quic(true, false);

/// `const SSL_METHOD *OSSL_QUIC_client_method(void)` — `ssl/quic/quic_method.c:14-17`.
///
/// # Safety
///
/// The returned pointer is to a process-lifetime static; it is never freed and may be read by any
/// thread. No other precondition.
#[no_mangle]
pub unsafe extern "C" fn OSSL_QUIC_client_method() -> *const SslMethod {
    &OSSL_QUIC_CLIENT_METHOD_DATA
}

/// `const SSL_METHOD *OSSL_QUIC_client_thread_method(void)` — `ssl/quic/quic_method.c:19-22`.
///
/// # Safety
///
/// As [`OSSL_QUIC_client_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn OSSL_QUIC_client_thread_method() -> *const SslMethod {
    &OSSL_QUIC_CLIENT_THREAD_METHOD_DATA
}

/// `const SSL_METHOD *OSSL_QUIC_server_method(void)` — `ssl/quic/quic_method.c:24-27`.
///
/// # Safety
///
/// As [`OSSL_QUIC_client_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn OSSL_QUIC_server_method() -> *const SslMethod {
    &OSSL_QUIC_SERVER_METHOD_DATA
}
