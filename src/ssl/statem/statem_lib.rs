//! Phase 14.7b — `ssl/statem/statem_lib.c`: the protocol-version helpers 14.7b needs.
//!
//! `ssl/statem/statem_lib.c` is the handshake message layer 14.5b records as unlanded. This module
//! lands three of its internal helpers — `ssl_version_cmp` (`statem_lib.c:1848-1857`), the two
//! version tables (`:1870-1918`), `ssl_method_error` (`:1928-1944`) and `ssl_get_min_max_version`
//! (`:2481-2576`) — because `ssl_set_client_disabled` (`t1_lib.c:2848`) calls
//! `ssl_get_min_max_version` and `t1_lib.c`'s `ssl_cipher_disabled` calls `ssl_version_cmp`, and
//! both are what `SSL_get1_supported_ciphers` (`ssl_lib.c:3276`) needs. No export is defined by
//! `statem_lib.c`, so this partial landing does not move the ledger.
//!
//! **Measured divergence, recorded rather than hidden.** The version tables name each version's
//! pinned client method and read its `flags`/`mask` through it; the crate has no
//! `tlsv1_3_client_method` (only the pinned TLS1_2/1_1/1 and DTLS1_2/1 tables 14.2 landed), so the
//! table carries each version's `(mask, flags)` directly, transcribed from `methods.c`. The
//! `cmeth == NULL` "compile hole" arm is therefore unreachable in the admitted build, exactly as
//! it is in the authority, and is represented by the table's own `present` field.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};

use crate::runtime::err::err_reasons::{
    SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE, SSL_R_NO_PROTOCOLS_AVAILABLE,
    SSL_R_UNSUPPORTED_PROTOCOL, SSL_R_VERSION_TOO_HIGH, SSL_R_VERSION_TOO_LOW,
};
use crate::ssl::ssl_cert::ssl_security;
use crate::ssl::ssl_ciph_table::{
    SSL_OP_NO_DTLSv1_2, SSL_OP_NO_SSLv3, SSL_OP_NO_TLSv1_1, SSL_OP_NO_TLSv1_2, SSL_OP_NO_TLSv1_3,
    SSL_CERT_FLAG_SUITEB_128_LOS,
};
use crate::ssl::ssl_lib::{SSL_is_dtls, Ssl, DTLS_ANY_VERSION, TLS_ANY_VERSION};

/// `SSL_SECOP_VERSION` — `ssl.h:2730` (`9 | SSL_SECOP_OTHER_NONE`).
const SSL_SECOP_VERSION: c_int = 9;
/// `SSL_METHOD_NO_SUITEB` — `ssl_local.h:2342` (`1U << 1`).
const SSL_METHOD_NO_SUITEB: c_uint = 1 << 1;
/// `SSL_OP_NO_TLSv1` — `ssl.h` (`SSL_OP_BIT(26)`), the same bit `SSL_OP_NO_DTLSv1` uses.
const SSL_OP_NO_TLSV1: u64 = 1 << 26;
/// `SSL3_VERSION` — `ssl3.h:136`.
const SSL3_VERSION: c_int = 0x0300;
/// `TLS1_VERSION` — `tls1.h:199`.
const TLS1_VERSION: c_int = 0x0301;
/// `TLS1_1_VERSION` — `tls1.h:200`.
const TLS1_1_VERSION: c_int = 0x0302;
/// `TLS1_2_VERSION` — `tls1.h:201`.
const TLS1_2_VERSION: c_int = 0x0303;
/// `TLS1_3_VERSION` — `tls1.h`.
const TLS1_3_VERSION: c_int = 0x0304;
/// `DTLS1_VERSION` — `dtls1.h:73`.
const DTLS1_VERSION: c_int = 0xFEFF;
/// `DTLS1_2_VERSION` — `prov_ssl.h:29`.
const DTLS1_2_VERSION: c_int = 0xFEFD;
/// `DTLS1_BAD_VER` — `ssl3.h:231`.
const DTLS1_BAD_VER: c_int = 0x0100;
/// `ERR_R_INTERNAL_ERROR` — `err.h` (`1 | ERR_RFLAG_COMMON | ERR_RFLAG_FATAL`).
const ERR_R_INTERNAL_ERROR: c_int = 1 | (2 << 18) | (1 << 18);

/// One row of `tls_version_table`/`dtls_version_table`: the version, the client method's option
/// mask and its `SSL_METHOD_*` flags, plus whether a client method exists at all (the "compile
/// hole" the walk tracks). `methods.c` defines the `(mask, flags)` pairs.
struct VersionInfo {
    version: c_int,
    mask: u64,
    flags: c_uint,
    present: bool,
}

/// `tls_version_table[]` — `ssl/statem/statem_lib.c:1870-1897`, high to low.
const TLS_VERSION_TABLE: [VersionInfo; 5] = [
    VersionInfo {
        version: TLS1_3_VERSION,
        mask: SSL_OP_NO_TLSv1_3,
        flags: 0,
        present: true,
    },
    VersionInfo {
        version: TLS1_2_VERSION,
        mask: SSL_OP_NO_TLSv1_2,
        flags: 0,
        present: true,
    },
    VersionInfo {
        version: TLS1_1_VERSION,
        mask: SSL_OP_NO_TLSv1_1,
        flags: SSL_METHOD_NO_SUITEB,
        present: true,
    },
    VersionInfo {
        version: TLS1_VERSION,
        mask: SSL_OP_NO_TLSV1,
        flags: SSL_METHOD_NO_SUITEB,
        present: true,
    },
    VersionInfo {
        version: SSL3_VERSION,
        mask: SSL_OP_NO_SSLv3,
        flags: SSL_METHOD_NO_SUITEB,
        present: true,
    },
];

/// `dtls_version_table[]` — `ssl/statem/statem_lib.c:1904-1918`, high to low.
const DTLS_VERSION_TABLE: [VersionInfo; 3] = [
    VersionInfo {
        version: DTLS1_2_VERSION,
        mask: SSL_OP_NO_DTLSv1_2,
        flags: 0,
        present: true,
    },
    VersionInfo {
        version: DTLS1_VERSION,
        mask: SSL_OP_NO_TLSV1,
        flags: SSL_METHOD_NO_SUITEB,
        present: true,
    },
    VersionInfo {
        version: DTLS1_BAD_VER,
        mask: SSL_OP_NO_TLSV1,
        flags: SSL_METHOD_NO_SUITEB,
        present: true,
    },
];

/// `dtls_ver_ordinal(v)` — `ssl/ssl_local.h:57`.
const fn dtls_ver_ordinal(v: c_int) -> c_int {
    if v == DTLS1_BAD_VER {
        0xff00
    } else {
        v
    }
}

/// `int ssl_version_cmp(const SSL_CONNECTION *s, int versiona, int versionb)` —
/// `ssl/statem/statem_lib.c:1848-1857`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn ssl_version_cmp(s: *const Ssl, versiona: c_int, versionb: c_int) -> c_int {
    if versiona == versionb {
        return 0;
    }
    // SAFETY: `s` is live per the caller's contract.
    let dtls = unsafe { SSL_is_dtls(s) } != 0;
    if !dtls {
        return if versiona < versionb { -1 } else { 1 };
    }
    // `DTLS_VERSION_LT(versiona, versionb)` is `dtls_ver_ordinal(versiona) > dtls_ver_ordinal(versionb)`.
    if dtls_ver_ordinal(versiona) > dtls_ver_ordinal(versionb) {
        -1
    } else {
        1
    }
}

/// `static int ssl_method_error(const SSL_CONNECTION *s, const SSL_METHOD *method)` —
/// `ssl/statem/statem_lib.c:1928-1944`, over a table row's `(version, mask, flags)`.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn ssl_method_error(s: *const Ssl, version: c_int, mask: u64, flags: c_uint) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if ((*s).min_proto_version != 0 && ssl_version_cmp(s, version, (*s).min_proto_version) < 0)
            || ssl_security(s, SSL_SECOP_VERSION, 0, version, core::ptr::null_mut()) == 0
        {
            return SSL_R_VERSION_TOO_LOW;
        }
        if (*s).max_proto_version != 0 && ssl_version_cmp(s, version, (*s).max_proto_version) > 0 {
            return SSL_R_VERSION_TOO_HIGH;
        }
        if ((*s).options & mask) != 0 {
            return SSL_R_UNSUPPORTED_PROTOCOL;
        }
        let cert_flags = (*(*s).cert).cert_flags as u64;
        if (flags & SSL_METHOD_NO_SUITEB) != 0 && (cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS) != 0 {
            return SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE;
        }
    }
    0
}

/// `int ssl_get_min_max_version(const SSL_CONNECTION *s, int *min_version, int *max_version,
/// int *real_max)` — `ssl/statem/statem_lib.c:2481-2576`.
///
/// # Safety
/// `s` must be a live connection; the out-pointers must be writable (or NULL, for `real_max`).
pub(crate) unsafe fn ssl_get_min_max_version(
    s: *const Ssl,
    min_version: *mut c_int,
    max_version: *mut c_int,
    real_max: *mut c_int,
) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    let method = unsafe { (*s).method };
    // SAFETY: `method` is a process-lifetime static table.
    let method_version = unsafe { (*method).version };
    let table: &[VersionInfo] = match method_version {
        TLS_ANY_VERSION => &TLS_VERSION_TABLE,
        DTLS_ANY_VERSION => &DTLS_VERSION_TABLE,
        _ => {
            // A pinned method reports its own version as both bounds, and the real-max arm is
            // only meaningful for a version-flexible method.
            // SAFETY: the out-pointers are writable per the contract.
            unsafe {
                *min_version = (*s).version;
                *max_version = (*s).version;
            }
            if !real_max.is_null() {
                return ERR_R_INTERNAL_ERROR;
            }
            return 0;
        }
    };

    let mut version = 0;
    let mut hole = 1;
    let mut tmp_real_max = 0;
    // SAFETY: the out-pointers are writable per the contract.
    unsafe {
        *min_version = 0;
        if !real_max.is_null() {
            *real_max = 0;
        }
    }
    for ent in table {
        if !ent.present {
            hole = 1;
            tmp_real_max = 0;
            continue;
        }
        if hole == 1 && tmp_real_max == 0 {
            tmp_real_max = ent.version;
        }
        // SAFETY: `s` is live.
        if unsafe { ssl_method_error(s, ent.version, ent.mask, ent.flags) } != 0 {
            hole = 1;
        } else if hole == 0 {
            // SAFETY: the out-pointer is writable.
            unsafe { *min_version = ent.version };
        } else {
            if !real_max.is_null() && tmp_real_max != 0 {
                // SAFETY: the out-pointer is writable per the contract.
                unsafe { *real_max = tmp_real_max };
            }
            version = ent.version;
            // SAFETY: the out-pointer is writable.
            unsafe { *min_version = version };
            hole = 0;
        }
    }
    // SAFETY: the out-pointer is writable.
    unsafe { *max_version = version };

    if version == 0 {
        return SSL_R_NO_PROTOCOLS_AVAILABLE;
    }
    0
}
