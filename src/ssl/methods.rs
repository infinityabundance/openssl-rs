//! Phase 14.1 — `ssl/methods.c`, the one constructor Slice 1 pulls forward.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives the method and version tables to 14.2, and this module is
//! **not** that work: it lands the single constructor the 14.1 court needs to allocate a context
//! with, and records the pull-forward in `src/ssl/mod.rs`. On the authority, `TLS_method`
//! (`ssl/methods.c:19-22`, expanded by `IMPLEMENT_tls_meth_func`, `ssl_local.h:2344-2383`) returns a
//! static `SSL_METHOD` whose `version` is `TLS_ANY_VERSION` and whose `get_timeout` is
//! `tls1_default_timeout` (`ssl/t1_lib.c:96-102`, 2 hours). Everything else the authority's table
//! carries — the accept/connect entries, the record-layer read/write entries, the cipher-by-char
//! codec — is `s3_lib.c`'s and 14.2's, and remains open.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::ssl::ssl_lib::{SslMethod, TLS_ANY_VERSION};

/// `TLS_method`'s static table — the reduced `TLS_method_data` `IMPLEMENT_tls_meth_func` defines.
///
/// `version` is `TLS_ANY_VERSION` (`methods.c:19`), the enc-flag is TLS (not DTLS), and
/// `timeout_secs` is `tls1_default_timeout`'s `60 * 60 * 2`.
static TLS_METHOD_DATA: SslMethod = SslMethod {
    version: TLS_ANY_VERSION,
    flags: 0,
    mask: 0,
    timeout_secs: 60 * 60 * 2,
    dtls: false,
    default_server: true,
};

/// `const SSL_METHOD *TLS_method(void)` — `ssl/methods.c:19-22`.
///
/// # Safety
///
/// The returned pointer is to a process-lifetime static; it is never freed and may be read by any
/// thread. No other precondition.
#[no_mangle]
pub extern "C" fn TLS_method() -> *const SslMethod {
    &TLS_METHOD_DATA
}
