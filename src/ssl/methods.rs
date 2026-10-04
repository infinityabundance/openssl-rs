//! Phase 14.2 — `ssl/methods.c`, the `TLS_*`/`DTLS_*`/`TLSv1_*` constructor table.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives the method and version tables to 14.2. This module lands
//! the whole of `ssl/methods.c`: the 21 exported constructors and the static `SSL_METHOD` tables
//! `IMPLEMENT_tls_meth_func`/`IMPLEMENT_dtls1_meth_func` (`ssl_local.h:2344-2464`) build. Slice 1
//! of 14.1 pulled `TLS_method` forward; it is the same table here, now beside its siblings.
//!
//! Each constructor returns a process-lifetime static whose observable fields this crate keeps on
//! [`SslMethod`] (`ssl_lib.rs`): the authority's table is a function-pointer block, and this crate
//! stores only what a landed subphase reads — `version`, `flags`, `mask`, the default timeout and
//! the two derived predicates `dtls` (the enc-flag's `SSL_ENC_FLAG_DTLS`) and `default_server`
//! (`method->ssl_accept != ssl_undefined_function`, `ssl_lib.c:917`). The accept/connect/read/write
//! callbacks themselves, the cipher-by-char codec and the `ssl3_enc` pointer are the record layer's
//! and state machine's (14.4/14.5) and are not represented.
//!
//! **Measured divergences, recorded rather than hidden.**
//!
//! * **The version a fresh connection reports for a `DTLS_method` is installed by `SSL_new`, not
//!   here.** `dtls1_clear` (`d1_lib.c:217-218`) maps `DTLS_ANY_VERSION` to `DTLS_MAX_VERSION_INTERNAL`
//!   exactly as `tls1_clear` maps `TLS_ANY_VERSION` to `TLS_MAX_VERSION_INTERNAL`; `src/ssl/ssl_lib.rs`
//!   carries both rules. Without that correction a `DTLS_method` connection would report the raw
//!   `DTLS_ANY_VERSION` (`0x1FFFF`) where the authority reports `DTLSv1.2` (`0xFEFD`).
//! * **The `mask` and `flags` fields are stored but not yet read.** `SSL_OP_NO_TLSv1_*`/`_DTLSv1_*`
//!   and `SSL_METHOD_NO_SUITEB` gate option handling that later subphases land; the court reads
//!   only what a fresh context/connection exposes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::ssl::ssl_lib::{SslMethod, DTLS_ANY_VERSION, TLS_ANY_VERSION};

/// `TLS1_VERSION` — `prov_ssl.h` (`(0x03 << 8) | 0x01`).
const TLS1_VERSION: c_int = 0x0301;
/// `TLS1_3_VERSION` — `prov_ssl.h` (`(0x03 << 8) | 0x04`).
const TLS1_3_VERSION: c_int = 0x0304;
/// `SSL_OP_NO_TLSv1_3` — `ssl.h:432` (`SSL_OP_BIT(29)`).
const SSL_OP_NO_TLSV1_3: u64 = 1 << 29;
/// `TLS1_1_VERSION` — `prov_ssl.h` (`(0x03 << 8) | 0x02`).
const TLS1_1_VERSION: c_int = 0x0302;
/// `TLS1_2_VERSION` — `prov_ssl.h` (`(0x03 << 8) | 0x03`).
const TLS1_2_VERSION: c_int = 0x0303;
/// `DTLS1_VERSION` — `prov_ssl.h:28`.
const DTLS1_VERSION: c_int = 0xFEFF;
/// `DTLS1_2_VERSION` — `prov_ssl.h:29`.
const DTLS1_2_VERSION: c_int = 0xFEFD;
/// `SSL_METHOD_NO_SUITEB` — `ssl_local.h:2342` (`1U << 1`).
const SSL_METHOD_NO_SUITEB: c_uint = 1 << 1;
/// `SSL_OP_NO_TLSv1` — `ssl.h:429` (`SSL_OP_BIT(26)`).
const SSL_OP_NO_TLSV1: u64 = 1 << 26;
/// `SSL_OP_NO_TLSv1_1` — `ssl.h:431` (`SSL_OP_BIT(28)`).
const SSL_OP_NO_TLSV1_1: u64 = 1 << 28;
/// `SSL_OP_NO_TLSv1_2` — `ssl.h:430` (`SSL_OP_BIT(27)`).
const SSL_OP_NO_TLSV1_2: u64 = 1 << 27;
/// `SSL_OP_NO_DTLSv1` — `ssl.h:433` (`SSL_OP_BIT(26)`).
const SSL_OP_NO_DTLSV1: u64 = 1 << 26;
/// `SSL_OP_NO_DTLSv1_2` — `ssl.h:434` (`SSL_OP_BIT(27)`).
const SSL_OP_NO_DTLSV1_2: u64 = 1 << 27;

/// `tls1_default_timeout` (`t1_lib.c:96-103`) — `ossl_seconds2time(60 * 60 * 2)`, reduced to seconds.
const TIMEOUT_SECS: u64 = 60 * 60 * 2;

/// `ssl3_enc->enc_flags` — `SSL_ENC_FLAG_TLS1_2_CIPHERS` (`ssl_local.h:2195`).
const SSL_ENC_FLAG_TLS1_2_CIPHERS: c_uint = 0x10;
/// `ssl3_enc->enc_flags` — `SSL_ENC_FLAG_SIGALGS` (`ssl_local.h:2186`).
const SSL_ENC_FLAG_SIGALGS: c_uint = 0x2;
/// `ssl3_enc->enc_flags` — `SSL_ENC_FLAG_DTLS` (`ssl_local.h:2190`).
const SSL_ENC_FLAG_DTLS: c_uint = 0x8;

/// Build a TLS table row: `timeout_secs` is `tls1_default_timeout`, `dtls` is false.
const fn tls(
    version: c_int,
    flags: c_uint,
    mask: u64,
    default_server: bool,
    default_client: bool,
) -> SslMethod {
    // `TLSv1_2_enc_data` carries `SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_TLS1_2_CIPHERS`; the older
    // enc tables (`TLSv1_enc_data`, `TLSv1_1_enc_data`) carry neither.
    let enc_flags = if version == TLS_ANY_VERSION || version == TLS1_2_VERSION {
        SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_TLS1_2_CIPHERS
    } else {
        0
    };
    SslMethod {
        version,
        flags,
        mask,
        timeout_secs: TIMEOUT_SECS,
        dtls: false,
        enc_flags,
        default_server,
        default_client,
    }
}

/// Build a DTLS table row: `timeout_secs` is `dtls1_default_timeout` (`d1_lib.c:56-63`), also two
/// hours, and `dtls` is true (the `DTLSv1_enc_data`/`DTLSv1_2_enc_data` `SSL_ENC_FLAG_DTLS` bit).
const fn dtls(
    version: c_int,
    flags: c_uint,
    mask: u64,
    default_server: bool,
    default_client: bool,
) -> SslMethod {
    // `DTLSv1_2_enc_data` adds `SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_TLS1_2_CIPHERS`; `DTLSv1_enc_data`
    // does not.
    let enc_flags = SSL_ENC_FLAG_DTLS
        | if version == DTLS_ANY_VERSION || version == DTLS1_2_VERSION {
            SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_TLS1_2_CIPHERS
        } else {
            0
        };
    SslMethod {
        version,
        flags,
        mask,
        timeout_secs: TIMEOUT_SECS,
        dtls: true,
        enc_flags,
        default_server,
        default_client,
    }
}

// ---------------------------------------------------------------------------------------------
// TLS/SSLv3 methods (methods.c:19-112)
// ---------------------------------------------------------------------------------------------

/// `TLS_method`'s static table — `IMPLEMENT_tls_meth_func(TLS_ANY_VERSION, 0, 0, TLS_method, ...)`.
static TLS_METHOD_DATA: SslMethod = tls(TLS_ANY_VERSION, 0, 0, true, true);
/// `TLS_server_method`'s table — `s_accept = ossl_statem_accept`, `s_connect = ssl_undefined_function`.
static TLS_SERVER_METHOD_DATA: SslMethod = tls(TLS_ANY_VERSION, 0, 0, true, false);
/// `TLS_client_method`'s table — `s_accept = ssl_undefined_function`.
static TLS_CLIENT_METHOD_DATA: SslMethod = tls(TLS_ANY_VERSION, 0, 0, false, true);

/// `tlsv1_3_server_method`'s table — `methods.c:54-57`.
static TLSV1_3_SERVER_METHOD_DATA: SslMethod =
    tls(TLS1_3_VERSION, 0, SSL_OP_NO_TLSV1_3, true, false);
/// `tlsv1_3_client_method`'s table — `methods.c:83-86`.
static TLSV1_3_CLIENT_METHOD_DATA: SslMethod =
    tls(TLS1_3_VERSION, 0, SSL_OP_NO_TLSV1_3, false, true);

/// The version-specific method a connection switches to once TLS1.3 is negotiated
/// (`tls_setup_handshake`, `ssl/statem/statem_lib.c:2292` installs `best_method`). `server` selects
/// the role table, exactly as the authority's `version_info` does.
pub(crate) fn tls13_method(server: bool) -> *const SslMethod {
    if server {
        &TLSV1_3_SERVER_METHOD_DATA
    } else {
        &TLSV1_3_CLIENT_METHOD_DATA
    }
}

/// `const SSL_METHOD *TLS_method(void)` — `ssl/methods.c:19-22`.
///
/// # Safety
///
/// The returned pointer is to a process-lifetime static; it is never freed and may be read by any
/// thread. No other precondition.
#[no_mangle]
pub unsafe extern "C" fn TLS_method() -> *const SslMethod {
    &TLS_METHOD_DATA
}

/// `const SSL_METHOD *TLS_server_method(void)` — `ssl/methods.c:50-53`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLS_server_method() -> *const SslMethod {
    &TLS_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *TLS_client_method(void)` — `ssl/methods.c:83-86`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLS_client_method() -> *const SslMethod {
    &TLS_CLIENT_METHOD_DATA
}

/// `tlsv1_2_method`'s table — `methods.c:28-31` (`TLS1_2_VERSION`, no flags, `SSL_OP_NO_TLSv1_2`).
static TLSV1_2_METHOD_DATA: SslMethod = tls(TLS1_2_VERSION, 0, SSL_OP_NO_TLSV1_2, true, true);
/// `tlsv1_2_server_method`'s table — `methods.c:59-62`.
static TLSV1_2_SERVER_METHOD_DATA: SslMethod =
    tls(TLS1_2_VERSION, 0, SSL_OP_NO_TLSV1_2, true, false);
/// `tlsv1_2_client_method`'s table — `methods.c:92-95`.
static TLSV1_2_CLIENT_METHOD_DATA: SslMethod =
    tls(TLS1_2_VERSION, 0, SSL_OP_NO_TLSV1_2, false, true);

/// `const SSL_METHOD *TLSv1_2_method(void)` — `ssl/methods.c:178-181` (returns `tlsv1_2_method()`).
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_2_method() -> *const SslMethod {
    &TLSV1_2_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_2_server_method(void)` — `ssl/methods.c:183-186`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_2_server_method() -> *const SslMethod {
    &TLSV1_2_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_2_client_method(void)` — `ssl/methods.c:188-191`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_2_client_method() -> *const SslMethod {
    &TLSV1_2_CLIENT_METHOD_DATA
}

/// `tlsv1_1_method`'s table — `methods.c:34-37` (`SSL_METHOD_NO_SUITEB`, `SSL_OP_NO_TLSv1_1`).
static TLSV1_1_METHOD_DATA: SslMethod = tls(
    TLS1_1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1_1,
    true,
    true,
);
/// `tlsv1_1_server_method`'s table — `methods.c:65-68`.
static TLSV1_1_SERVER_METHOD_DATA: SslMethod = tls(
    TLS1_1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1_1,
    true,
    false,
);
/// `tlsv1_1_client_method`'s table — `methods.c:98-101`.
static TLSV1_1_CLIENT_METHOD_DATA: SslMethod = tls(
    TLS1_1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1_1,
    false,
    true,
);

/// `const SSL_METHOD *TLSv1_1_method(void)` — `ssl/methods.c:195-198`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_1_method() -> *const SslMethod {
    &TLSV1_1_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_1_server_method(void)` — `ssl/methods.c:200-203`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_1_server_method() -> *const SslMethod {
    &TLSV1_1_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_1_client_method(void)` — `ssl/methods.c:205-208`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_1_client_method() -> *const SslMethod {
    &TLSV1_1_CLIENT_METHOD_DATA
}

/// `tlsv1_method`'s table — `methods.c:40-42` (`SSL_METHOD_NO_SUITEB`, `SSL_OP_NO_TLSv1`).
static TLSV1_METHOD_DATA: SslMethod = tls(
    TLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1,
    true,
    true,
);
/// `tlsv1_server_method`'s table — `methods.c:71-74`.
static TLSV1_SERVER_METHOD_DATA: SslMethod = tls(
    TLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1,
    true,
    false,
);
/// `tlsv1_client_method`'s table — `methods.c:104-107`.
static TLSV1_CLIENT_METHOD_DATA: SslMethod = tls(
    TLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_TLSV1,
    false,
    true,
);

/// `const SSL_METHOD *TLSv1_method(void)` — `ssl/methods.c:212-215`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_method() -> *const SslMethod {
    &TLSV1_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_server_method(void)` — `ssl/methods.c:217-220`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_server_method() -> *const SslMethod {
    &TLSV1_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *TLSv1_client_method(void)` — `ssl/methods.c:222-225`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn TLSv1_client_method() -> *const SslMethod {
    &TLSV1_CLIENT_METHOD_DATA
}

// ---------------------------------------------------------------------------------------------
// DTLS methods (methods.c:116-175)
// ---------------------------------------------------------------------------------------------

/// `dtlsv1_method`'s table — `methods.c:117-120` (`DTLS1_VERSION`, `SSL_METHOD_NO_SUITEB`,
/// `SSL_OP_NO_DTLSv1`).
static DTLSV1_METHOD_DATA: SslMethod = dtls(
    DTLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_DTLSV1,
    true,
    true,
);
/// `dtlsv1_server_method`'s table — `methods.c:137-140`.
static DTLSV1_SERVER_METHOD_DATA: SslMethod = dtls(
    DTLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_DTLSV1,
    true,
    false,
);
/// `dtlsv1_client_method`'s table — `methods.c:157-160`.
static DTLSV1_CLIENT_METHOD_DATA: SslMethod = dtls(
    DTLS1_VERSION,
    SSL_METHOD_NO_SUITEB,
    SSL_OP_NO_DTLSV1,
    false,
    true,
);
/// `dtlsv1_2_method`'s table — `methods.c:123-126` (`DTLS1_2_VERSION`, no flags,
/// `SSL_OP_NO_DTLSv1_2`).
static DTLSV1_2_METHOD_DATA: SslMethod = dtls(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSV1_2, true, true);
/// `dtlsv1_2_server_method`'s table — `methods.c:143-146`.
static DTLSV1_2_SERVER_METHOD_DATA: SslMethod =
    dtls(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSV1_2, true, false);
/// `dtlsv1_2_client_method`'s table — `methods.c:167-170`.
static DTLSV1_2_CLIENT_METHOD_DATA: SslMethod =
    dtls(DTLS1_2_VERSION, 0, SSL_OP_NO_DTLSV1_2, false, true);
/// `DTLS_method`'s table — `methods.c:128-131` (`DTLS_ANY_VERSION`, no flags, no mask).
static DTLS_METHOD_DATA: SslMethod = dtls(DTLS_ANY_VERSION, 0, 0, true, true);
/// `DTLS_server_method`'s table — `methods.c:148-151`.
static DTLS_SERVER_METHOD_DATA: SslMethod = dtls(DTLS_ANY_VERSION, 0, 0, true, false);
/// `DTLS_client_method`'s table — `methods.c:172-175`.
static DTLS_CLIENT_METHOD_DATA: SslMethod = dtls(DTLS_ANY_VERSION, 0, 0, false, true);

/// `const SSL_METHOD *DTLSv1_method(void)` — `ssl/methods.c:263-266`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_method() -> *const SslMethod {
    &DTLSV1_METHOD_DATA
}

/// `const SSL_METHOD *DTLSv1_server_method(void)` — `ssl/methods.c:268-271`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_server_method() -> *const SslMethod {
    &DTLSV1_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *DTLSv1_client_method(void)` — `ssl/methods.c:273-276`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_client_method() -> *const SslMethod {
    &DTLSV1_CLIENT_METHOD_DATA
}

/// `const SSL_METHOD *DTLSv1_2_method(void)` — `ssl/methods.c:246-249`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_2_method() -> *const SslMethod {
    &DTLSV1_2_METHOD_DATA
}

/// `const SSL_METHOD *DTLSv1_2_server_method(void)` — `ssl/methods.c:251-254`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_2_server_method() -> *const SslMethod {
    &DTLSV1_2_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *DTLSv1_2_client_method(void)` — `ssl/methods.c:256-259`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_2_client_method() -> *const SslMethod {
    &DTLSV1_2_CLIENT_METHOD_DATA
}

/// `const SSL_METHOD *DTLS_method(void)` — `ssl/methods.c:128-131`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLS_method() -> *const SslMethod {
    &DTLS_METHOD_DATA
}

/// `const SSL_METHOD *DTLS_server_method(void)` — `ssl/methods.c:148-151`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLS_server_method() -> *const SslMethod {
    &DTLS_SERVER_METHOD_DATA
}

/// `const SSL_METHOD *DTLS_client_method(void)` — `ssl/methods.c:172-175`.
///
/// # Safety
///
/// As [`TLS_method`]: a process-lifetime static.
#[no_mangle]
pub unsafe extern "C" fn DTLS_client_method() -> *const SslMethod {
    &DTLS_CLIENT_METHOD_DATA
}
