//! Phase 14.3 — `ssl/ssl_conf.c`: the `SSL_CONF_CTX` command parser.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives 14.3 `ssl_conf.c` (11 open rows). They are the configuration
//! context's lifecycle and flag accessors (`SSL_CONF_CTX_new`/`_free`/`_set_flags`/`_clear_flags`/
//! `_set1_prefix`/`_set_ssl`/`_set_ssl_ctx`), the command dispatch (`SSL_CONF_cmd`,
//! `SSL_CONF_cmd_value_type`, `SSL_CONF_cmd_argv`) and the finishing pass (`SSL_CONF_CTX_finish`).
//!
//! The command table is the one 14.3's sibling module `src/ssl/ssl_ciph.rs` serves: the
//! `cipher`/`ciphersuites` handlers call the ciphersuite setters, and `protocol`/`options`/`verify`
//! drive the option/verify words the object model landed in 14.1.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The certificate- and key-loading commands are not wired.** `cert`, `key`, `dhparam`, the
//!   `*CAfile`/`*CApath`/`*CAstore` family and `serverinfo` name loaders that are 14.7's; this
//!   module keeps every such row in the command table (so `SSL_CONF_cmd_value_type` and command
//!   *recognition* are the authority's) but the handler itself returns the authority's failure
//!   value rather than attempting a load. The court drives those rows' value types only.
//! * **The signature-algorithm and group-list commands are not wired.** `sigalgs`, `client_sigalgs`,
//!   `groups`, `curves` and `named_curve` name setters that are 14.5's; their table rows are kept
//!   and their handlers return the authority's failure value. As above, only their value types are
//!   driven.
//! * **`ssl_set_version_bound` is pulled forward from 14.5.** `min_protocol`/`max_protocol` call
//!   `ssl_set_version_bound` (`ssl/statem/statem_lib.c:2107-2156`), which is 14.5's unit; it is
//!   transcribed here because 14.3's parser is what drives it, and `src/ssl/mod.rs` records the
//!   correction.
//! * **`SSL_CONF_CTX_finish`'s `canames` hand-off is unreachable.** The authority pops a
//!   `STACK_OF(X509_NAME)` onto the context or connection; nothing in this slice installs one, so
//!   `canames` is always NULL and the stack is freed with `OPENSSL_sk_free` rather than a typed
//!   `sk_X509_NAME_pop_free`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)] // the handlers carry the authority's `cmd_<Name>` spellings

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{OPENSSL_sk_free, OpenSslStack};
use crate::ssl::ssl_ciph::{SSL_CTX_set_ciphersuites, SSL_set_ciphersuites};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_lib::{
    SSL_CTX_set_block_padding_ex, SSL_CTX_set_cipher_list, SSL_CTX_set_num_tickets,
    SSL_set_block_padding_ex, SSL_set_cipher_list, SSL_set_num_tickets, Ssl, SslCtx,
};

const FILE: *const c_char = c"ssl/ssl_conf.c".as_ptr();

/// `SSL_TFLAG_INV` — `ssl_conf.c:40`.
const SSL_TFLAG_INV: c_uint = 0x1;
/// `SSL_TFLAG_TYPE_MASK` — `ssl_conf.c:42`.
const SSL_TFLAG_TYPE_MASK: c_uint = 0xf00;
/// `SSL_TFLAG_CERT` — `ssl_conf.c:46`.
const SSL_TFLAG_CERT: c_uint = 0x100;
/// `SSL_TFLAG_VFY` — `ssl_conf.c:48`.
const SSL_TFLAG_VFY: c_uint = 0x200;
/// `SSL_TFLAG_BOTH` — `SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_SERVER`.
const SSL_TFLAG_BOTH: c_uint = 0x4 | 0x8;

/// `SSL_PKEY_NUM` — `ssl_local.h`; the certificate-slot count the filename array is sized by.
const SSL_PKEY_NUM: usize = 9;

type ConfCmdFn = unsafe extern "C" fn(*mut SslConfCtx, *const c_char) -> c_int;

/// `struct ssl_flag_tbl` — `ssl_conf.c:26-31`.
struct SslFlagTbl {
    name: &'static [u8],
    name_flags: c_uint,
    option_value: u64,
}

/// `struct ssl_switch_tbl` — `ssl_conf.c:34-37`.
struct SslSwitchTbl {
    option_value: u64,
    name_flags: c_uint,
}

/// `struct ssl_conf_cmd_tbl` — `ssl_conf.c:737-743`, indexed by row. For a switch row `cmd` is
/// `None`; the authority's `#name`/`cmdopt` macro expansion puts the command's C name in
/// `str_file` and its command-line spelling in `str_cmdline`.
struct SslConfCmdTbl {
    cmd: Option<ConfCmdFn>,
    str_file: Option<&'static [u8]>,
    str_cmdline: Option<&'static [u8]>,
    flags: c_uint,
    value_type: c_uint,
}

/// `struct ssl_conf_ctx_st` — `ssl_conf.c:77-109`. Opaque to a consumer.
pub struct SslConfCtx {
    flags: c_uint,
    prefix: *mut c_char,
    prefixlen: usize,
    ctx: *mut SslCtx,
    ssl: *mut Ssl,
    poptions: *mut u64,
    cert_filename: *mut *mut c_char,
    num_cert_filename: usize,
    pcert_flags: *mut c_long,
    pvfy_flags: *mut c_int,
    min_version: *mut c_int,
    max_version: *mut c_int,
    tbl: *const SslFlagTbl,
    ntbl: usize,
    canames: *mut OpenSslStack,
}

fn flag_both(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_srv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: 0x8,
        option_value: value,
    }
}

fn flag_inv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_INV | SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_cert(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_CERT | SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_vfy_cli(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_VFY | 0x4,
        option_value: value,
    }
}

fn flag_vfy_srv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_VFY | 0x8,
        option_value: value,
    }
}

/// `ssl_set_option` — `ssl_conf.c:111-144`.
unsafe fn ssl_set_option(
    cctx: *mut SslConfCtx,
    name_flags: c_uint,
    option_value: u64,
    onoff: c_int,
) {
    // SAFETY: `cctx` is live per the callers' contracts.
    let c = unsafe { &mut *cctx };
    if c.poptions.is_null() {
        return;
    }
    let mut on = onoff;
    if (name_flags & SSL_TFLAG_INV) != 0 {
        on ^= 1;
    }
    let pflags: *mut u64 = match name_flags & SSL_TFLAG_TYPE_MASK {
        SSL_TFLAG_CERT => c.pcert_flags.cast::<u64>(),
        SSL_TFLAG_VFY => c.pvfy_flags.cast::<u64>(),
        _ => {
            // SAFETY: `poptions` is non-NULL (checked above) and points at a live u64.
            unsafe {
                if on != 0 {
                    *c.poptions |= option_value;
                } else {
                    *c.poptions &= !option_value;
                }
            }
            return;
        }
    };
    if pflags.is_null() {
        return;
    }
    // SAFETY: the flag pointers are live; the authority's table carries 32-bit values, so the
    // high half written through the `c_long`-sized view stays zero.
    unsafe {
        if on != 0 {
            *pflags |= option_value;
        } else {
            *pflags &= !option_value;
        }
    }
}

/// `ssl_match_option` — `ssl_conf.c:146-160`.
unsafe fn ssl_match_option(
    cctx: *mut SslConfCtx,
    tbl: &SslFlagTbl,
    elem: *const c_char,
    len: c_int,
    onoff: c_int,
) -> bool {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    if (c.flags & tbl.name_flags & SSL_TFLAG_BOTH) == 0 {
        return false;
    }
    let name = tbl.name;
    if len == -1 {
        // SAFETY: `elem` is NUL-terminated.
        if unsafe { core::ffi::CStr::from_ptr(elem) }.to_bytes() != name {
            return false;
        }
    } else {
        if name.len() != len as usize {
            return false;
        }
        // SAFETY: `elem` is readable for `len` bytes.
        let got = unsafe { core::slice::from_raw_parts(elem as *const u8, len as usize) };
        if !got.eq_ignore_ascii_case(name) {
            return false;
        }
    }
    // SAFETY: `cctx` is live.
    unsafe { ssl_set_option(cctx, tbl.name_flags, tbl.option_value, onoff) };
    true
}

/// `ssl_set_option_list` — `ssl_conf.c:162-190`.
unsafe extern "C" fn ssl_set_option_list(
    elem: *const c_char,
    len: c_int,
    usr: *mut c_void,
) -> c_int {
    let cctx = usr as *mut SslConfCtx;
    let mut e = elem;
    let mut l = len;
    let mut onoff = 1;
    if e.is_null() {
        return 0;
    }
    if l != -1 {
        // SAFETY: `e` is readable for `l` bytes.
        let first = unsafe { *e } as u8;
        if first == b'+' {
            // SAFETY: the token continues inside the buffer.
            e = unsafe { e.add(1) };
            l -= 1;
        } else if first == b'-' {
            // SAFETY: the token continues inside the buffer.
            e = unsafe { e.add(1) };
            l -= 1;
            onoff = 0;
        }
    }
    // SAFETY: `cctx` is live per `SSL_CONF_cmd`.
    let c = unsafe { &*cctx };
    for i in 0..c.ntbl {
        // SAFETY: `i` is in range of the table `tbl` points into.
        let tbl = unsafe { &*c.tbl.add(i) };
        // SAFETY: the pointers are per the callback contract.
        if unsafe { ssl_match_option(cctx, tbl, e, l, onoff) } {
            return 1;
        }
    }
    0
}

/// `protocol_from_string` — `ssl_conf.c:303-333`.
fn protocol_from_string(value: &[u8]) -> c_int {
    let table: [(&[u8], c_int); 8] = [
        (b"None", 0),
        (b"SSLv3", t::SSL3_VERSION as c_int),
        (b"TLSv1", t::TLS1_VERSION as c_int),
        (b"TLSv1.1", t::TLS1_1_VERSION as c_int),
        (b"TLSv1.2", t::TLS1_2_VERSION as c_int),
        (b"TLSv1.3", t::TLS1_3_VERSION as c_int),
        (b"DTLSv1", t::DTLS1_VERSION as c_int),
        (b"DTLSv1.2", t::DTLS1_2_VERSION as c_int),
    ];
    for (name, version) in table {
        if value == name {
            return version;
        }
    }
    -1
}

/// `dtls_ver_ordinal` — `ssl_local.h:58`.
fn dtls_ordinal(v: c_int) -> c_int {
    if v == t::DTLS1_BAD_VER as c_int {
        0xff00
    } else {
        v
    }
}

/// `ssl_set_version_bound` — `ssl/statem/statem_lib.c:2107-2156` (pulled forward from 14.5).
fn ssl_set_version_bound(method_version: c_int, version: c_int, bound: *mut c_int) -> bool {
    if version == 0 {
        // SAFETY: `bound` is a live context/connection field per the callers' contract.
        unsafe { *bound = version };
        return true;
    }
    let valid_tls = version >= t::SSL3_VERSION as c_int && version <= t::TLS1_3_VERSION as c_int;
    let valid_dtls = version == t::DTLS1_BAD_VER as c_int
        || (dtls_ordinal(version) >= dtls_ordinal(t::DTLS1_2_VERSION as c_int)
            && dtls_ordinal(version) <= dtls_ordinal(t::DTLS1_VERSION as c_int));
    if !valid_tls && !valid_dtls {
        return false;
    }
    match method_version {
        v if v == crate::ssl::ssl_lib::TLS_ANY_VERSION && valid_tls => {
            // SAFETY: `bound` is a live field.
            unsafe { *bound = version };
        }
        v if v == crate::ssl::ssl_lib::DTLS_ANY_VERSION && valid_dtls => {
            // SAFETY: `bound` is a live field.
            unsafe { *bound = version };
        }
        _ => {}
    }
    true
}

/// `min_max_proto` — `ssl_conf.c:335-349`.
unsafe fn min_max_proto(cctx: *mut SslConfCtx, value: *const c_char, bound: *mut c_int) -> c_int {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    let method_version = if !c.ctx.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*(*c.ctx).method).version }
    } else if !c.ssl.is_null() {
        // SAFETY: `ssl` is live.
        unsafe { (*(*c.ssl).defltmeth).version }
    } else {
        return 0;
    };
    // SAFETY: `value` is NUL-terminated.
    let v = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let new_version = protocol_from_string(v);
    if new_version < 0 {
        return 0;
    }
    c_int::from(ssl_set_version_bound(method_version, new_version, bound))
}

/// `cmd_Protocol` — `ssl_conf.c:280-296`.
unsafe extern "C" fn cmd_Protocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_inv(b"ALL", t::SSL_OP_NO_SSL_MASK),
        flag_inv(b"SSLv2", t::SSL_OP_NO_SSLv2),
        flag_inv(b"SSLv3", t::SSL_OP_NO_SSLv3),
        flag_inv(b"TLSv1", t::SSL_OP_NO_TLSv1),
        flag_inv(b"TLSv1.1", t::SSL_OP_NO_TLSv1_1),
        flag_inv(b"TLSv1.2", t::SSL_OP_NO_TLSv1_2),
        flag_inv(b"TLSv1.3", t::SSL_OP_NO_TLSv1_3),
        flag_inv(b"DTLSv1", t::SSL_OP_NO_DTLSv1),
        flag_inv(b"DTLSv1.2", t::SSL_OP_NO_DTLSv1_2),
    ];
    // SAFETY: `cctx` is live.
    unsafe {
        (*cctx).tbl = table.as_ptr();
        (*cctx).ntbl = table.len();
    }
    // SAFETY: `value` is NUL-terminated; the callback and arg are per `CONF_parse_list`.
    unsafe {
        CONF_parse_list(
            value,
            b',' as c_int,
            1,
            Some(ssl_set_option_list),
            cctx.cast::<c_void>(),
        )
    }
}

/// `cmd_Options` — `ssl_conf.c:375-416`.
unsafe extern "C" fn cmd_Options(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_inv(b"SessionTicket", t::SSL_OP_NO_TICKET),
        flag_inv(b"EmptyFragments", t::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        flag_both(b"Bugs", t::SSL_OP_ALL),
        flag_inv(b"Compression", t::SSL_OP_NO_COMPRESSION),
        flag_srv(b"ServerPreference", t::SSL_OP_SERVER_PREFERENCE),
        flag_srv(
            b"NoResumptionOnRenegotiation",
            t::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        ),
        flag_srv(b"DHSingle", t::SSL_OP_SINGLE_DH_USE),
        flag_srv(b"ECDHSingle", t::SSL_OP_SINGLE_ECDH_USE),
        flag_both(
            b"UnsafeLegacyRenegotiation",
            t::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        ),
        flag_both(
            b"UnsafeLegacyServerConnect",
            t::SSL_OP_LEGACY_SERVER_CONNECT,
        ),
        flag_both(b"ClientRenegotiation", t::SSL_OP_ALLOW_CLIENT_RENEGOTIATION),
        flag_inv(b"EncryptThenMac", t::SSL_OP_NO_ENCRYPT_THEN_MAC),
        flag_both(b"NoRenegotiation", t::SSL_OP_NO_RENEGOTIATION),
        flag_both(b"AllowNoDHEKEX", t::SSL_OP_ALLOW_NO_DHE_KEX),
        flag_both(b"PreferNoDHEKEX", t::SSL_OP_PREFER_NO_DHE_KEX),
        flag_both(b"PrioritizeChaCha", t::SSL_OP_PRIORITIZE_CHACHA),
        flag_both(b"MiddleboxCompat", t::SSL_OP_ENABLE_MIDDLEBOX_COMPAT),
        flag_inv(b"AntiReplay", t::SSL_OP_NO_ANTI_REPLAY),
        flag_inv(b"ExtendedMasterSecret", t::SSL_OP_NO_EXTENDED_MASTER_SECRET),
        flag_inv(b"CANames", t::SSL_OP_DISABLE_TLSEXT_CA_NAMES),
        flag_both(b"KTLS", t::SSL_OP_ENABLE_KTLS),
        flag_cert(b"StrictCertCheck", t::SSL_CERT_FLAG_TLS_STRICT),
        flag_inv(
            b"TxCertificateCompression",
            t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
        ),
        flag_inv(
            b"RxCertificateCompression",
            t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
        ),
        flag_both(
            b"KTLSTxZerocopySendfile",
            t::SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE,
        ),
        flag_both(b"IgnoreUnexpectedEOF", t::SSL_OP_IGNORE_UNEXPECTED_EOF),
        flag_both(b"LegacyECPointFormats", t::SSL_OP_LEGACY_EC_POINT_FORMATS),
    ];
    if value.is_null() {
        return -3;
    }
    // SAFETY: `cctx` is live.
    unsafe {
        (*cctx).tbl = table.as_ptr();
        (*cctx).ntbl = table.len();
    }
    // SAFETY: as in `cmd_Protocol`.
    unsafe {
        CONF_parse_list(
            value,
            b',' as c_int,
            1,
            Some(ssl_set_option_list),
            cctx.cast::<c_void>(),
        )
    }
}

/// `cmd_VerifyMode` — `ssl_conf.c:418-436`.
unsafe extern "C" fn cmd_VerifyMode(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_vfy_cli(b"Peer", t::SSL_VERIFY_PEER),
        flag_vfy_srv(b"Request", t::SSL_VERIFY_PEER),
        flag_vfy_srv(
            b"Require",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
        flag_vfy_srv(b"Once", t::SSL_VERIFY_PEER | t::SSL_VERIFY_CLIENT_ONCE),
        flag_vfy_srv(
            b"RequestPostHandshake",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_POST_HANDSHAKE,
        ),
        flag_vfy_srv(
            b"RequirePostHandshake",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_POST_HANDSHAKE | t::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
    ];
    if value.is_null() {
        return -3;
    }
    // SAFETY: `cctx` is live.
    unsafe {
        (*cctx).tbl = table.as_ptr();
        (*cctx).ntbl = table.len();
    }
    // SAFETY: `value` is NUL-terminated; the callback and arg are per `CONF_parse_list`.
    unsafe {
        CONF_parse_list(
            value,
            b',' as c_int,
            1,
            Some(ssl_set_option_list),
            cctx.cast::<c_void>(),
        )
    }
}

/// `cmd_CipherString` — `ssl_conf.c:258-267`.
unsafe extern "C" fn cmd_CipherString(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let mut rv = 1;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_cipher_list((*cctx).ctx, value);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_cipher_list((*cctx).ssl, value);
        }
    }
    c_int::from(rv > 0)
}

/// `cmd_Ciphersuites` — `ssl_conf.c:269-278`.
unsafe extern "C" fn cmd_Ciphersuites(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let mut rv = 1;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_ciphersuites((*cctx).ctx, value);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_ciphersuites((*cctx).ssl, value);
        }
    }
    c_int::from(rv > 0)
}

/// `cmd_MinProtocol` — `ssl_conf.c:358-361`.
unsafe extern "C" fn cmd_MinProtocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `cctx` is live.
    unsafe { min_max_proto(cctx, value, (*cctx).min_version) }
}

/// `cmd_MaxProtocol` — `ssl_conf.c:370-373`.
unsafe extern "C" fn cmd_MaxProtocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `cctx` is live.
    unsafe { min_max_proto(cctx, value, (*cctx).max_version) }
}

/// `atoi` — `ssl_conf.c:726`; the leading integer `cmd_NumTickets` reads.
fn atoi_prefix(text: &str) -> c_int {
    let t = text.trim_start();
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let mut v: c_int = digits.parse().unwrap_or(0);
    if neg {
        v = -v;
    }
    v
}

/// `cmd_NumTickets` — `ssl_conf.c:723-735`.
unsafe extern "C" fn cmd_NumTickets(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `value` is NUL-terminated.
    let v = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let num_tickets = atoi_prefix(&String::from_utf8_lossy(v));
    let mut rv = 0;
    if num_tickets >= 0 {
        // SAFETY: `cctx` is live; the pointers are NULL or live.
        unsafe {
            if !(*cctx).ctx.is_null() {
                rv = SSL_CTX_set_num_tickets((*cctx).ctx, num_tickets as usize);
            }
            if !(*cctx).ssl.is_null() {
                rv = SSL_set_num_tickets((*cctx).ssl, num_tickets as usize);
            }
        }
    }
    rv
}

/// `cmd_RecordPadding` — `ssl_conf.c:667-721`.
unsafe extern "C" fn cmd_RecordPadding(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `value` is NUL-terminated.
    let bytes = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let text = core::str::from_utf8(bytes).unwrap_or("");
    let (a, b) = match text.split_once(',') {
        Some((x, y)) => (x, Some(y)),
        None => (text, None),
    };
    let block: usize = match a.parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let hs: usize = match b {
        None => block,
        Some("") => return 0,
        Some(y) => match y.parse() {
            Ok(v) => v,
            Err(_) => return 0,
        },
    };
    let mut rv = 0;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_block_padding_ex((*cctx).ctx, block, hs);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_block_padding_ex((*cctx).ssl, block, hs);
        }
    }
    rv
}

/// A command whose named unit is a later subphase: recognised by the table, refused by the
/// handler (recorded in the module header).
unsafe extern "C" fn cmd_unwired(_cctx: *mut SslConfCtx, _value: *const c_char) -> c_int {
    0
}

/// `SSL_CONF_CMD`/`SSL_CONF_CMD_STRING`/`SSL_CONF_CMD_SWITCH` rows — `ssl_conf.c:758-841`.
///
/// The order is the authority's, because `ctrl_switch_option` indexes the switch table by this
/// row's position (`ssl_conf.c:953-968`).
fn commands() -> Vec<SslConfCmdTbl> {
    let cmdstr =
        |f: ConfCmdFn, file: &'static [u8], cmdline: Option<&'static [u8]>, flags: c_uint| {
            SslConfCmdTbl {
                cmd: Some(f),
                str_file: Some(file),
                str_cmdline: cmdline,
                flags,
                value_type: t::SSL_CONF_TYPE_STRING as c_uint,
            }
        };
    let cmdtype = |f: ConfCmdFn,
                   file: &'static [u8],
                   cmdline: Option<&'static [u8]>,
                   flags: c_uint,
                   vt: u64| {
        SslConfCmdTbl {
            cmd: Some(f),
            str_file: Some(file),
            str_cmdline: cmdline,
            flags,
            value_type: vt as c_uint,
        }
    };
    let switch = |name: &'static [u8], flags: c_uint| SslConfCmdTbl {
        cmd: None,
        str_file: None,
        str_cmdline: Some(name),
        flags,
        value_type: t::SSL_CONF_TYPE_NONE as c_uint,
    };

    vec![
        switch(b"no_ssl3", 0),
        switch(b"no_tls1", 0),
        switch(b"no_tls1_1", 0),
        switch(b"no_tls1_2", 0),
        switch(b"no_tls1_3", 0),
        switch(b"bugs", 0),
        switch(b"no_comp", 0),
        switch(b"comp", 0),
        switch(b"no_tx_cert_comp", 0),
        switch(b"tx_cert_comp", 0),
        switch(b"no_rx_cert_comp", 0),
        switch(b"rx_cert_comp", 0),
        switch(b"ecdh_single", 0x8),
        switch(b"no_ticket", 0),
        switch(b"serverpref", 0x8),
        switch(b"legacy_renegotiation", 0),
        switch(b"client_renegotiation", 0x8),
        switch(b"legacy_server_connect", 0x4),
        switch(b"no_renegotiation", 0),
        switch(b"no_resumption_on_reneg", 0x8),
        switch(b"no_legacy_server_connect", 0x4),
        switch(b"allow_no_dhe_kex", 0),
        switch(b"prefer_no_dhe_kex", 0),
        switch(b"prioritize_chacha", 0x8),
        switch(b"strict", 0),
        switch(b"no_middlebox", 0),
        switch(b"anti_replay", 0x8),
        switch(b"no_anti_replay", 0x8),
        switch(b"no_etm", 0),
        switch(b"no_ems", 0),
        switch(b"legacy_ec_point_formats", 0),
        cmdstr(cmd_unwired, b"SignatureAlgorithms", Some(b"sigalgs"), 0),
        cmdstr(
            cmd_unwired,
            b"ClientSignatureAlgorithms",
            Some(b"client_sigalgs"),
            0,
        ),
        cmdstr(cmd_unwired, b"Curves", Some(b"curves"), 0),
        cmdstr(cmd_unwired, b"Groups", Some(b"groups"), 0),
        cmdstr(cmd_unwired, b"ECDHParameters", Some(b"named_curve"), 0x8),
        cmdstr(cmd_CipherString, b"CipherString", Some(b"cipher"), 0),
        cmdstr(cmd_Ciphersuites, b"Ciphersuites", Some(b"ciphersuites"), 0),
        cmdstr(cmd_Protocol, b"Protocol", None, 0),
        cmdstr(cmd_MinProtocol, b"MinProtocol", Some(b"min_protocol"), 0),
        cmdstr(cmd_MaxProtocol, b"MaxProtocol", Some(b"max_protocol"), 0),
        cmdstr(cmd_Options, b"Options", None, 0),
        cmdstr(cmd_VerifyMode, b"VerifyMode", None, 0),
        cmdtype(
            cmd_unwired,
            b"Certificate",
            Some(b"cert"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"PrivateKey",
            Some(b"key"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ServerInfoFile",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAPath",
            Some(b"chainCApath"),
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAFile",
            Some(b"chainCAfile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAStore",
            Some(b"chainCAstore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAPath",
            Some(b"verifyCApath"),
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAFile",
            Some(b"verifyCAfile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAStore",
            Some(b"verifyCAstore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAFile",
            Some(b"requestCAFile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAFile",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAPath",
            None,
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAPath",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAStore",
            Some(b"requestCAStore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAStore",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"DHParameters",
            Some(b"dhparam"),
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdstr(
            cmd_RecordPadding,
            b"RecordPadding",
            Some(b"record_padding"),
            0,
        ),
        cmdstr(cmd_NumTickets, b"NumTickets", Some(b"num_tickets"), 0x8),
    ]
}

/// `ssl_cmd_switches` — `ssl_conf.c:844-891`, the same order as the switch rows above.
fn switches() -> [SslSwitchTbl; 31] {
    [
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_SSLv3,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_1,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_2,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_3,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALL,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_SINGLE_ECDH_USE,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TICKET,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_SERVER_PREFERENCE,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_CLIENT_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_SERVER_CONNECT,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_SERVER_CONNECT,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_NO_DHE_KEX,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_PREFER_NO_DHE_KEX,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_PRIORITIZE_CHACHA,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_CERT_FLAG_TLS_STRICT,
            name_flags: SSL_TFLAG_CERT,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ANTI_REPLAY,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ANTI_REPLAY,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ENCRYPT_THEN_MAC,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_EXTENDED_MASTER_SECRET,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_EC_POINT_FORMATS,
            name_flags: 0,
        },
    ]
}

/// `ssl_conf_cmd_skip_prefix` — `ssl_conf.c:893-912`.
unsafe fn skip_prefix(cctx: *mut SslConfCtx, pcmd: *mut *const c_char) -> bool {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    if pcmd.is_null() {
        return false;
    }
    // SAFETY: `pcmd` is non-NULL and points at a live `const char *` per the caller's contract.
    let inner = unsafe { *pcmd };
    if inner.is_null() {
        return false;
    }
    let cmd = inner;
    // SAFETY: `cmd` is NUL-terminated.
    let s = unsafe { core::ffi::CStr::from_ptr(cmd) }.to_bytes();
    if !c.prefix.is_null() {
        if s.len() <= c.prefixlen {
            return false;
        }
        // SAFETY: `prefix` is NUL-terminated and `prefixlen` bytes long.
        let pre = unsafe { core::slice::from_raw_parts(c.prefix as *const u8, c.prefixlen) };
        let head = &s[..c.prefixlen];
        if (c.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 && head != pre {
            return false;
        }
        if (c.flags & t::SSL_CONF_FLAG_FILE as c_uint) != 0 && !head.eq_ignore_ascii_case(pre) {
            return false;
        }
        // SAFETY: the prefix is within the string.
        unsafe { *pcmd = cmd.add(c.prefixlen) };
    } else if (c.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 {
        if s.first() != Some(&b'-') || s.len() < 2 {
            return false;
        }
        // SAFETY: the string is non-empty.
        unsafe { *pcmd = cmd.add(1) };
    }
    true
}

/// `ssl_conf_cmd_allowed` — `ssl_conf.c:915-927`.
fn cmd_allowed(cctx: &SslConfCtx, row: &SslConfCmdTbl) -> bool {
    let tfl = row.flags;
    let cfl = cctx.flags;
    if (tfl & 0x8) != 0 && (cfl & 0x8) == 0 {
        return false;
    }
    if (tfl & 0x4) != 0 && (cfl & 0x4) == 0 {
        return false;
    }
    if (tfl & 0x20) != 0 && (cfl & 0x20) == 0 {
        return false;
    }
    true
}

/// `ssl_conf_cmd_lookup` — `ssl_conf.c:929-951`, returning the row index.
fn cmd_lookup(cctx: &SslConfCtx, cmd: &[u8], table: &[SslConfCmdTbl]) -> Option<usize> {
    for (i, row) in table.iter().enumerate() {
        if !cmd_allowed(cctx, row) {
            continue;
        }
        if (cctx.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 {
            if let Some(cl) = row.str_cmdline {
                if cmd == cl {
                    return Some(i);
                }
            }
        }
        if (cctx.flags & t::SSL_CONF_FLAG_FILE as c_uint) != 0 {
            if let Some(fl) = row.str_file {
                if cmd.eq_ignore_ascii_case(fl) {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// `ctrl_switch_option` — `ssl_conf.c:953-968`.
unsafe fn ctrl_switch_option(cctx: *mut SslConfCtx, idx: usize) -> c_int {
    let sw = switches();
    if idx >= sw.len() {
        return 0;
    }
    // SAFETY: `cctx` is live.
    unsafe { ssl_set_option(cctx, sw[idx].name_flags, sw[idx].option_value, 1) };
    1
}

/// `int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value)` —
/// `ssl/ssl_conf.c:970-1010`.
///
/// # Safety
/// `cctx` NULL or live; `cmd`/`value` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd(
    cctx: *mut SslConfCtx,
    cmd: *const c_char,
    value: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if cctx.is_null() || cmd.is_null() {
            return 0;
        }
        let mut p = cmd;
        // SAFETY: `cctx` and `cmd` are per the guards above.
        if !unsafe { skip_prefix(cctx, &mut p) } {
            return -2;
        }
        // SAFETY: `p` points into the (NUL-terminated) command string.
        let name = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
        let table = commands();
        // SAFETY: `cctx` is live.
        let c = unsafe { &*cctx };
        let Some(idx) = cmd_lookup(c, name, &table) else {
            return -2;
        };
        let row = &table[idx];
        if row.value_type == t::SSL_CONF_TYPE_NONE as c_uint {
            // SAFETY: `cctx` is live.
            return unsafe { ctrl_switch_option(cctx, idx) };
        }
        if value.is_null() {
            return -3;
        }
        let Some(f) = row.cmd else {
            return -2;
        };
        // SAFETY: `cctx` and `value` are live per the caller's contract.
        let rv = unsafe { f(cctx, value) };
        if rv > 0 {
            return 2;
        }
        if rv != -2 {
            0
        } else {
            rv
        }
    })
}

/// `int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)` —
/// `ssl/ssl_conf.c:1012-1044`.
///
/// # Safety
/// `cctx` live; `pargc`/`pargv` per the C contract.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd_argv(
    cctx: *mut SslConfCtx,
    pargc: *mut c_int,
    pargv: *mut *mut *mut c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `pargc` is NULL or points at a live `int` per the caller's contract.
        let count0 = if pargc.is_null() {
            0
        } else {
            // SAFETY: `pargc` is non-NULL, so it points at a live `int` per the caller.
            unsafe { *pargc }
        };
        if !pargc.is_null() && count0 == 0 {
            return 0;
        }
        if pargv.is_null() {
            return 0;
        }
        // SAFETY: `pargv` dereferences per the caller's contract.
        let argv = unsafe { *pargv };
        if argv.is_null() {
            return 0;
        }
        // The authority reads `**pargv` only when `pargc` is NULL or positive.
        if !pargc.is_null() && count0 <= 0 {
            return 0;
        }
        // SAFETY: `argv[0]` is the argument per the caller's contract.
        let arg = unsafe { *argv };
        if arg.is_null() {
            return 0;
        }
        // SAFETY: `pargc` is NULL or points at a live `int` per the caller's contract.
        let argn = if pargc.is_null() || count0 > 1 {
            // SAFETY: `argv[1]` is present per the caller's contract.
            unsafe { *argv.add(1) }
        } else {
            ptr::null_mut()
        };
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags &= !(t::SSL_CONF_FLAG_FILE as c_uint);
            (*cctx).flags |= t::SSL_CONF_FLAG_CMDLINE as c_uint;
        }
        // SAFETY: `cctx`/`arg`/`argn` are per `SSL_CONF_cmd`'s contract.
        let rv = unsafe { SSL_CONF_cmd(cctx, arg, argn) };
        if rv > 0 {
            // SAFETY: `pargv`/`pargc` are per the caller's contract.
            unsafe {
                *pargv = argv.add(rv as usize);
                if !pargc.is_null() {
                    *pargc -= rv;
                }
            }
            return rv;
        }
        if rv == -2 {
            return 0;
        }
        if rv == 0 {
            return -1;
        }
        rv
    })
}

/// `int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd)` —
/// `ssl/ssl_conf.c:1046-1055`.
///
/// # Safety
/// `cctx` live; `cmd` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd_value_type(
    cctx: *mut SslConfCtx,
    cmd: *const c_char,
) -> c_int {
    guard_ffi(t::SSL_CONF_TYPE_UNKNOWN as c_int, || {
        if cctx.is_null() {
            return t::SSL_CONF_TYPE_UNKNOWN as c_int;
        }
        let mut p = cmd;
        // SAFETY: `cctx` is live.
        if unsafe { skip_prefix(cctx, &mut p) } {
            // SAFETY: `p` points into the command string.
            let name = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
            let table = commands();
            // SAFETY: `cctx` is live.
            let c = unsafe { &*cctx };
            if let Some(idx) = cmd_lookup(c, name, &table) {
                return table[idx].value_type as c_int;
            }
        }
        t::SSL_CONF_TYPE_UNKNOWN as c_int
    })
}

/// `SSL_CONF_CTX *SSL_CONF_CTX_new(void)` — `ssl/ssl_conf.c:1057-1062`.
///
/// # Safety
/// The returned pointer is owned by the caller and released with [`SSL_CONF_CTX_free`].
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_new() -> *mut SslConfCtx {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: a fresh zeroed block.
        CRYPTO_zalloc(core::mem::size_of::<SslConfCtx>(), FILE, 1059).cast::<SslConfCtx>()
    })
}

/// `int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx)` — `ssl/ssl_conf.c:1064-1101`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_finish(cctx: *mut SslConfCtx) -> c_int {
    guard_ffi(0, || {
        if cctx.is_null() {
            return 0;
        }
        // The private-key back-fill runs only under `SSL_CONF_FLAG_REQUIRE_PRIVATE`, which this
        // slice never installs; `canames` is always NULL, so the hand-off is a no-op.
        1
    })
}

/// `void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx)` — `ssl/ssl_conf.c:1114-1122`.
///
/// # Safety
/// `cctx` must be NULL or a live context, and not used after this call.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_free(cctx: *mut SslConfCtx) {
    guard_ffi((), || {
        if cctx.is_null() {
            return;
        }
        // SAFETY: `cctx` is live and owned here.
        unsafe {
            free_cert_filename(&mut *cctx);
            CRYPTO_free((*cctx).prefix.cast(), FILE, 0);
            OPENSSL_sk_free((*cctx).canames);
            CRYPTO_free(cctx.cast(), FILE, 1120);
        }
    })
}

/// `unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags)` —
/// `ssl/ssl_conf.c:1124-1128`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_flags(cctx: *mut SslConfCtx, flags: c_uint) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags |= flags;
            (*cctx).flags
        }
    })
}

/// `unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags)` —
/// `ssl/ssl_conf.c:1130-1134`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_clear_flags(cctx: *mut SslConfCtx, flags: c_uint) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags &= !flags;
            (*cctx).flags
        }
    })
}

/// `int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)` —
/// `ssl/ssl_conf.c:1136-1151`.
///
/// # Safety
/// `cctx` live; `pre` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set1_prefix(
    cctx: *mut SslConfCtx,
    pre: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        let mut tmp: *mut c_char = ptr::null_mut();
        if !pre.is_null() {
            // SAFETY: `pre` is NUL-terminated; `CRYPTO_strdup` copies it.
            tmp = unsafe { CRYPTO_strdup(pre, FILE, 1140) };
            if tmp.is_null() {
                return 0;
            }
        }
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            CRYPTO_free((*cctx).prefix.cast(), FILE, 0);
            (*cctx).prefix = tmp;
            (*cctx).prefixlen = if tmp.is_null() {
                0
            } else {
                core::ffi::CStr::from_ptr(tmp).to_bytes().len()
            };
        }
        1
    })
}

/// `void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl)` — `ssl/ssl_conf.c:1153-1179`.
///
/// # Safety
/// `cctx` live; `ssl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_ssl(cctx: *mut SslConfCtx, ssl: *mut Ssl) {
    guard_ffi((), || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            let c = &mut *cctx;
            c.ssl = ssl;
            c.ctx = ptr::null_mut();
            free_cert_filename(c);
            if ssl.is_null() {
                c.poptions = ptr::null_mut();
                c.min_version = ptr::null_mut();
                c.max_version = ptr::null_mut();
                c.pcert_flags = ptr::null_mut();
                c.pvfy_flags = ptr::null_mut();
                return;
            }
            c.poptions = &mut (*ssl).options;
            c.min_version = &mut (*ssl).min_proto_version;
            c.max_version = &mut (*ssl).max_proto_version;
            c.pvfy_flags = &mut (*ssl).verify_mode;
            c.pcert_flags = if (*ssl).cert.is_null() {
                ptr::null_mut()
            } else {
                &mut (*(*ssl).cert).cert_flags
            };
            let arr = CRYPTO_zalloc(
                SSL_PKEY_NUM * core::mem::size_of::<*mut c_char>(),
                FILE,
                1168,
            )
            .cast::<*mut c_char>();
            c.cert_filename = arr;
            if !arr.is_null() {
                c.num_cert_filename = SSL_PKEY_NUM;
            }
        }
    })
}

/// `void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx)` — `ssl/ssl_conf.c:1181-1203`.
///
/// # Safety
/// `cctx` live; `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SslConfCtx, ctx: *mut SslCtx) {
    guard_ffi((), || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            let c = &mut *cctx;
            c.ctx = ctx;
            c.ssl = ptr::null_mut();
            free_cert_filename(c);
            if ctx.is_null() {
                c.poptions = ptr::null_mut();
                c.min_version = ptr::null_mut();
                c.max_version = ptr::null_mut();
                c.pcert_flags = ptr::null_mut();
                c.pvfy_flags = ptr::null_mut();
                return;
            }
            c.poptions = &mut (*ctx).options;
            c.min_version = &mut (*ctx).min_proto_version;
            c.max_version = &mut (*ctx).max_proto_version;
            c.pvfy_flags = &mut (*ctx).verify_mode;
            c.pcert_flags = if (*ctx).cert.is_null() {
                ptr::null_mut()
            } else {
                &mut (*(*ctx).cert).cert_flags
            };
            let arr = CRYPTO_zalloc(
                SSL_PKEY_NUM * core::mem::size_of::<*mut c_char>(),
                FILE,
                1192,
            )
            .cast::<*mut c_char>();
            c.cert_filename = arr;
            if !arr.is_null() {
                c.num_cert_filename = SSL_PKEY_NUM;
            }
        }
    })
}

/// `free_cert_filename` — `ssl_conf.c:1103-1112`.
unsafe fn free_cert_filename(c: &mut SslConfCtx) {
    if c.cert_filename.is_null() {
        return;
    }
    // SAFETY: the array has `num_cert_filename` slots per its allocation.
    unsafe {
        for i in 0..c.num_cert_filename {
            CRYPTO_free(*c.cert_filename.add(i).cast::<*mut c_void>(), FILE, 0);
        }
        CRYPTO_free(c.cert_filename.cast(), FILE, 0);
    }
    c.cert_filename = ptr::null_mut();
    c.num_cert_filename = 0;
}
