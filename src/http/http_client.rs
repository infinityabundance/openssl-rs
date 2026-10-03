//! `crypto/http/http_client.c` — the HTTP/1.0 request/response client, transcribed whole.
//!
//! This is subphase 12.1's unit. It lands the 21 open `http.h` exports the unit defines —
//! `OSSL_HTTP_REQ_CTX_new`/`_free`/`_get0_mem_bio`/`_get_resp_len`/
//! `_set_max_response_length`/`_set_max_response_hdr_lines`/`_set_request_line`/
//! `_add1_header`/`_set_expected`/`_set1_req`/`_nbio`/`_nbio_d2i`/`_exchange`/`_is_alive`
//! and `OSSL_HTTP_open`/`_set1_request`/`_exchange`/`_get`/`_transfer`/`_close`/
//! `_proxy_connect` — together with every `static` helper they call. The two `http_lib.c`
//! names the ledger opens in this stratum (`OSSL_HTTP_parse_url`, `OSSL_HTTP_adapt_proxy`)
//! land in [`super::http_lib`]; this unit is their caller.
//!
//! ## What is reachable, and the network it uses
//!
//! `http.h`'s low-level API takes its `wbio`/`rbio` explicitly, so the whole request/response
//! state machine is drivable over memory BIOs and is what `courts/phase12/rt_http_probe.c`
//! drives. The high-level API's only transport is the BIO layer: `http_new_bio` builds a
//! connection BIO with `BIO_new_connect` and `BIO_set_conn_port` (`crypto/bio/bss_conn.c`, the
//! landed `RT-BIO-CONN` unit), and `OSSL_HTTP_open` may instead take a caller-supplied `bio`.
//! No socket is opened by this module itself; the withholding Phases 10 and 11 recorded —
//! that the crate "deliberately does not fabricate the network transport" — is lifted because
//! the transport is a landed dependency, not a thing this unit invents.
//!
//! ## The raise sites
//!
//! `crypto/http/http_client.c` is not in `gen_err_raise_sites.py`'s covered set, so its raise
//! coordinates are **declared locally** — the same treatment [`super::http_lib`] gives its own.
//! Their reason values are read from the authority's `httperr.h`/`err.h.in`/`cmperr.h`, not
//! typed from memory; `ErrSite::file` carries the authority build record's
//! `../../src/openssl-3.6.4/...` spelling.
//!
//! ## The `OSSL_TRACE` calls
//!
//! `OSSL_HTTP_REQ_CTX_nbio` and its siblings bracket their I/O with `OSSL_TRACE`/`OSSL_TRACE1`/
//! `OSSL_TRACE_STRING` (`OSSL_TRACE_ENABLED(HTTP)`). The admitted build configures `no-trace`,
//! so every such call is compiled out and is omitted here with this sentence as its record,
//! the crate's convention (`src/evp/evp_cnf.rs`). The one control-flow consequence is the
//! `OHS_HEADERS_ERROR` arm below: with tracing disabled the authority discards the error
//! content rather than reading it, which is transcribed here.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_i2d_fp::ASN1_item_i2d_mem_bio;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::layout::{Asn1Item, V_ASN1_CONSTRUCTED, V_ASN1_SEQUENCE};
use crate::evp::encode::EVP_EncodeBlock;
use crate::runtime::bio::addr_info::BIO_parse_hostserv;
use crate::runtime::bio::bf_buff::BIO_f_buffer;
use crate::runtime::bio::bss_conn::BIO_new_connect;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::iolib::{
    BIO_do_connect_retry, BIO_get_line, BIO_gets, BIO_read, BIO_wait, BIO_write, BIO_write_ex,
};
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::sys::{memchr, strchr, strlen, strtoul, time, SEEK_END, SEEK_SET};
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_free_all, BIO_method_type, BIO_new, BIO_pop, BIO_push, BIO_test_flags,
    BIO_up_ref, Bio, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_RESET,
    BIO_C_GET_FILE_PTR, BIO_C_SET_CONNECT, BIO_FLAGS_SHOULD_RETRY, BIO_PARSE_PRIO_HOST,
    BIO_R_CONNECT_ERROR, BIO_R_CONNECT_TIMEOUT, BIO_TYPE_FILE,
};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::ctype::{ossl_isprint, ossl_isspace};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{
    raise_site, raise_site_data, ERR_clear_last_mark, ERR_peek_error, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strncasecmp};
use crate::runtime::time::TimeT;

extern "C" {
    /// `void ERR_add_error_data(int num, ...)` — a C-variadic function, defined for the crate in
    /// `src/runtime/err_variadic.c` (and exported by the authority's libcrypto).
    fn ERR_add_error_data(num: c_int, ...);
    /// `char *strpbrk(const char *s, const char *accept)`.
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char;
    /// `int fseek(FILE *stream, long offset, int whence)`.
    fn fseek(stream: *mut crate::runtime::bio::sys::FILE, offset: c_long, whence: c_int) -> c_int;
    /// `long ftell(FILE *stream)`.
    fn ftell(stream: *mut crate::runtime::bio::sys::FILE) -> c_long;
}

// ---------------------------------------------------------------------------
// Constants — http_client.c's own macros
// ---------------------------------------------------------------------------

/// `#define HTTP_PREFIX "HTTP/"` — `crypto/http/http_client.c:27`.
const HTTP_PREFIX: &[u8] = b"HTTP/";
/// `#define HTTP_VERSION_PATT "1."` — `crypto/http/http_client.c:28`.
const HTTP_VERSION_PATT: &[u8] = b"1.";
/// `#define HTTP_VERSION_STR_LEN sizeof(HTTP_VERSION_PATT)` — `http_client.c:29`. The `sizeof`
/// of `"1."` is 3, terminator included.
const HTTP_VERSION_STR_LEN: usize = 3;
/// `#define HTTP_PREFIX_VERSION HTTP_PREFIX "" HTTP_VERSION_PATT` — `http_client.c:30`.
const HTTP_PREFIX_VERSION: &[u8] = b"HTTP/1.";
/// `#define HTTP_1_0 HTTP_PREFIX_VERSION "0"` — `http_client.c:31`.
const HTTP_1_0: &core::ffi::CStr = c"HTTP/1.0";
/// `#define HTTP_LINE1_MINLEN (sizeof(HTTP_PREFIX_VERSION "x 200\n") - 1)` — `http_client.c:32`.
const HTTP_LINE1_MINLEN: c_int = 13;
/// `#define HTTP_VERSION_MAX_REDIRECTIONS 50` — `http_client.c:33`.
const HTTP_VERSION_MAX_REDIRECTIONS: c_int = 50;
/// `#define HTTP_STATUS_CODE_OK 200` — `http_client.c:35`.
const HTTP_STATUS_CODE_OK: c_int = 200;
/// `#define HTTP_STATUS_CODE_MOVED_PERMANENTLY 301` — `http_client.c:36`.
const HTTP_STATUS_CODE_MOVED_PERMANENTLY: c_int = 301;
/// `#define HTTP_STATUS_CODE_FOUND 302` — `http_client.c:37`.
const HTTP_STATUS_CODE_FOUND: c_int = 302;
/// `#define HTTP_STATUS_CODES_NONFATAL_ERROR 400` — `http_client.c:38`.
const HTTP_STATUS_CODES_NONFATAL_ERROR: c_int = 400;
/// `#define HTTP_STATUS_CODE_NOT_FOUND 404` — `http_client.c:39`.
const HTTP_STATUS_CODE_NOT_FOUND: c_int = 404;
/// `#define BUF_SIZE (8 * 1024)` — `http_client.c:1463`, in `OSSL_HTTP_proxy_connect`.
const BUF_SIZE: usize = 8 * 1024;

/// `#define OSSL_HTTP_DEFAULT_MAX_LINE_LEN (4 * 1024)` — `include/openssl/http.h:42`.
const OSSL_HTTP_DEFAULT_MAX_LINE_LEN: c_int = 4 * 1024;
/// `#define OSSL_HTTP_DEFAULT_MAX_RESP_LEN (100 * 1024)` — `include/openssl/http.h:43`.
const OSSL_HTTP_DEFAULT_MAX_RESP_LEN: usize = 100 * 1024;
/// `#define OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES 256` — `include/openssl/http.h:45`.
const OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES: usize = 256;
/// `#define OSSL_HTTP_PREFIX OSSL_HTTP_NAME "://"` — `include/openssl/http.h:27`; used by
/// `OSSL_HTTP_REQ_CTX_set_request_line` as the format `OSSL_HTTP_PREFIX "%s"`.
const OSSL_HTTP_PREFIX: &core::ffi::CStr = c"http://%s";
/// `#define OSSL_HTTPS_NAME "https"` — `include/openssl/http.h:26`, for `redirection_ok`'s
/// `OSSL_HTTPS_NAME ":"` prefix test.
const OSSL_HTTPS_NAME_COLON: &[u8] = b"https:";

/* HTTP client OSSL_HTTP_REQ_CTX_nbio() internal states, in typical order — http_client.c:77-94 */

/// `#define OHS_NOREAD 0x1000` — `http_client.c:77`.
const OHS_NOREAD: c_int = 0x1000;
/// `#define OHS_ERROR (0 | OHS_NOREAD)` — `http_client.c:78`.
const OHS_ERROR: c_int = OHS_NOREAD;
/// `#define OHS_ADD_HEADERS (1 | OHS_NOREAD)` — `http_client.c:79`.
const OHS_ADD_HEADERS: c_int = 1 | OHS_NOREAD;
/// `#define OHS_WRITE_INIT (2 | OHS_NOREAD)` — `http_client.c:80`.
const OHS_WRITE_INIT: c_int = 2 | OHS_NOREAD;
/// `#define OHS_WRITE_HDR1 (3 | OHS_NOREAD)` — `http_client.c:81`.
const OHS_WRITE_HDR1: c_int = 3 | OHS_NOREAD;
/// `#define OHS_WRITE_HDR (4 | OHS_NOREAD)` — `http_client.c:82`.
const OHS_WRITE_HDR: c_int = 4 | OHS_NOREAD;
/// `#define OHS_WRITE_REQ (5 | OHS_NOREAD)` — `http_client.c:83`.
const OHS_WRITE_REQ: c_int = 5 | OHS_NOREAD;
/// `#define OHS_FLUSH (6 | OHS_NOREAD)` — `http_client.c:84`.
const OHS_FLUSH: c_int = 6 | OHS_NOREAD;
/// `#define OHS_FIRSTLINE 1` — `http_client.c:86`.
const OHS_FIRSTLINE: c_int = 1;
/// `#define OHS_HEADERS 2` — `http_client.c:87`.
const OHS_HEADERS: c_int = 2;
/// `#define OHS_HEADERS_ERROR 3` — `http_client.c:88`.
const OHS_HEADERS_ERROR: c_int = 3;
/// `#define OHS_REDIRECT 4` — `http_client.c:89`.
const OHS_REDIRECT: c_int = 4;
/// `#define OHS_ASN1_HEADER 5` — `http_client.c:90`.
const OHS_ASN1_HEADER: c_int = 5;
/// `#define OHS_ASN1_CONTENT 6` — `http_client.c:91`.
const OHS_ASN1_CONTENT: c_int = 6;
/// `#define OHS_ASN1_DONE 7` — `http_client.c:92`.
const OHS_ASN1_DONE: c_int = 7;
/// `#define OHS_STREAM 8` — `http_client.c:93`.
const OHS_STREAM: c_int = 8;
/// `#define OHS_ERROR_CONTENT 9` — `http_client.c:94`.
const OHS_ERROR_CONTENT: c_int = 9;

/// `ERR_LIB_HTTP` — `include/openssl/err.h.in:126`.
const ERR_LIB_HTTP: c_int = 61;
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_LIB_BIO` — `include/openssl/err.h.in:97`.
const ERR_LIB_BIO: c_int = 32;
/// `ERR_LIB_CMP` — `include/openssl/err.h.in:123`.
const ERR_LIB_CMP: c_int = 58;
/// `ERR_LIB_SYS` — `include/openssl/err.h.in`; `ERR_GET_LIB`'s answer for a system error.
const ERR_LIB_SYS: c_int = 2;

/// `ERR_R_FATAL` — `include/openssl/err.h:352`, `ERR_RFLAG_FATAL | ERR_RFLAG_COMMON`.
const ERR_R_FATAL: c_int = (0x1 << 18) | (0x2 << 18);
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` — `include/openssl/err.h:354`, `257 | ERR_R_FATAL`.
const ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED: c_int = 257 | ERR_R_FATAL;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h:355`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_R_FATAL;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h:358`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 262 | (0x2 << 18);

/// `HTTP_R_CONNECT_FAILURE` — `include/openssl/httperr.h:23`.
const HTTP_R_CONNECT_FAILURE: c_int = 100;
/// `HTTP_R_ERROR_RECEIVING` — `include/openssl/httperr.h:28`.
const HTTP_R_ERROR_RECEIVING: c_int = 103;
/// `HTTP_R_ERROR_SENDING` — `include/openssl/httperr.h:29`.
const HTTP_R_ERROR_SENDING: c_int = 102;
/// `HTTP_R_FAILED_READING_DATA` — `include/openssl/httperr.h:30`.
const HTTP_R_FAILED_READING_DATA: c_int = 128;
/// `HTTP_R_HEADER_PARSE_ERROR` — `include/openssl/httperr.h:31`.
const HTTP_R_HEADER_PARSE_ERROR: c_int = 126;
/// `HTTP_R_INCONSISTENT_CONTENT_LENGTH` — `include/openssl/httperr.h:32`.
const HTTP_R_INCONSISTENT_CONTENT_LENGTH: c_int = 120;
/// `HTTP_R_MAX_RESP_LEN_EXCEEDED` — `include/openssl/httperr.h:36`.
const HTTP_R_MAX_RESP_LEN_EXCEEDED: c_int = 117;
/// `HTTP_R_MISSING_ASN1_ENCODING` — `include/openssl/httperr.h:37`.
const HTTP_R_MISSING_ASN1_ENCODING: c_int = 110;
/// `HTTP_R_MISSING_CONTENT_TYPE` — `include/openssl/httperr.h:38`.
const HTTP_R_MISSING_CONTENT_TYPE: c_int = 121;
/// `HTTP_R_MISSING_REDIRECT_LOCATION` — `include/openssl/httperr.h:39`.
const HTTP_R_MISSING_REDIRECT_LOCATION: c_int = 111;
/// `HTTP_R_RECEIVED_WRONG_HTTP_VERSION` — `include/openssl/httperr.h:41`.
const HTTP_R_RECEIVED_WRONG_HTTP_VERSION: c_int = 106;
/// `HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP` — `include/openssl/httperr.h:42`.
const HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP: c_int = 112;
/// `HTTP_R_REDIRECTION_NOT_ENABLED` — `include/openssl/httperr.h:43`.
const HTTP_R_REDIRECTION_NOT_ENABLED: c_int = 116;
/// `HTTP_R_RESPONSE_LINE_TOO_LONG` — `include/openssl/httperr.h:44`.
const HTTP_R_RESPONSE_LINE_TOO_LONG: c_int = 113;
/// `HTTP_R_RESPONSE_TOO_MANY_HDRLINES` — `include/openssl/httperr.h:46`.
const HTTP_R_RESPONSE_TOO_MANY_HDRLINES: c_int = 130;
/// `HTTP_R_RETRY_TIMEOUT` — `include/openssl/httperr.h:47`.
const HTTP_R_RETRY_TIMEOUT: c_int = 129;
/// `HTTP_R_SERVER_CANCELED_CONNECTION` — `include/openssl/httperr.h:48`.
const HTTP_R_SERVER_CANCELED_CONNECTION: c_int = 127;
/// `HTTP_R_STATUS_CODE_UNSUPPORTED` — `include/openssl/httperr.h:50`.
const HTTP_R_STATUS_CODE_UNSUPPORTED: c_int = 114;
/// `HTTP_R_TLS_NOT_ENABLED` — `include/openssl/httperr.h:51`.
const HTTP_R_TLS_NOT_ENABLED: c_int = 107;
/// `HTTP_R_TOO_MANY_REDIRECTIONS` — `include/openssl/httperr.h:52`.
const HTTP_R_TOO_MANY_REDIRECTIONS: c_int = 115;
/// `HTTP_R_UNEXPECTED_CONTENT_TYPE` — `include/openssl/httperr.h:53`.
const HTTP_R_UNEXPECTED_CONTENT_TYPE: c_int = 118;
/// `HTTP_R_CONTENT_TYPE_MISMATCH` — `include/openssl/httperr.h:24`.
const HTTP_R_CONTENT_TYPE_MISMATCH: c_int = 131;
/// `HTTP_R_ERROR_PARSING_ASN1_LENGTH` — `include/openssl/httperr.h:25`.
const HTTP_R_ERROR_PARSING_ASN1_LENGTH: c_int = 109;
/// `HTTP_R_ERROR_PARSING_CONTENT_LENGTH` — `include/openssl/httperr.h:26`.
const HTTP_R_ERROR_PARSING_CONTENT_LENGTH: c_int = 119;

/// `CMP_R_POTENTIALLY_INVALID_CERTIFICATE` — `include/openssl/cmperr.h:95`.
const CMP_R_POTENTIALLY_INVALID_CERTIFICATE: c_int = 147;

/// `ERROR_SYSTEM_FLAG` / `ERR_GET_LIB` / `ERR_GET_REASON`'s masks — `include/openssl/err.h:220`,
/// `:228-232`. `ERR_GET_LIB`/`ERR_GET_REASON` are the header's inline functions, which map a
/// system error to `ERR_LIB_SYS`/`errno` before masking.
const ERR_SYSTEM_FLAG: c_ulong = 1 << 31;
const ERR_LIB_OFFSET: c_ulong = 23;
const ERR_LIB_MASK: c_ulong = 0xff;
const ERR_REASON_MASK: c_ulong = 0x7f_ffff;
const ERR_SYSTEM_MASK: c_ulong = 0x7fff_ffff;

/// The `OPENSSL_FILE` string for this unit's `CRYPTO_*` macro expansions.
const FILE: &core::ffi::CStr = c"crypto/http/http_client.c";

// ---------------------------------------------------------------------------
// The struct and the callback type
// ---------------------------------------------------------------------------

/// `BIO *(*OSSL_HTTP_bio_cb_t)(BIO *bio, void *arg, int connect, int detail)` —
/// `include/openssl/http.h:73`. A NULL function pointer is a valid value, so the field is an
/// `Option` (the null-pointer-optimised, FFI-safe representation).
pub type OSSL_HTTP_bio_cb_t = Option<
    unsafe extern "C" fn(
        bio: *mut Bio,
        arg: *mut c_void,
        connect: c_int,
        detail: c_int,
    ) -> *mut Bio,
>;

/// `struct ossl_http_req_ctx_st` (the public `OSSL_HTTP_REQ_CTX`) —
/// `crypto/http/http_client.c:45-73`.
#[repr(C)]
pub struct OsslHttpReqCtx {
    /// `int state`.
    pub state: c_int,
    /// `unsigned char *buf`.
    pub buf: *mut c_uchar,
    /// `int buf_size`.
    pub buf_size: c_int,
    /// `int free_wbio`.
    pub free_wbio: c_int,
    /// `BIO *wbio`.
    pub wbio: *mut Bio,
    /// `BIO *rbio`.
    pub rbio: *mut Bio,
    /// `OSSL_HTTP_bio_cb_t upd_fn`.
    pub upd_fn: OSSL_HTTP_bio_cb_t,
    /// `void *upd_arg`.
    pub upd_arg: *mut c_void,
    /// `int use_ssl`.
    pub use_ssl: c_int,
    /// `char *proxy`.
    pub proxy: *mut c_char,
    /// `char *server`.
    pub server: *mut c_char,
    /// `char *port`.
    pub port: *mut c_char,
    /// `BIO *mem`.
    pub mem: *mut Bio,
    /// `BIO *req`.
    pub req: *mut Bio,
    /// `int method_POST`.
    pub method_POST: c_int,
    /// `int text`.
    pub text: c_int,
    /// `char *expected_ct`.
    pub expected_ct: *mut c_char,
    /// `int expect_asn1`.
    pub expect_asn1: c_int,
    /// `unsigned char *pos`.
    pub pos: *mut c_uchar,
    /// `long len_to_send`.
    pub len_to_send: c_long,
    /// `size_t resp_len`.
    pub resp_len: usize,
    /// `size_t max_resp_len`.
    pub max_resp_len: usize,
    /// `int keep_alive`.
    pub keep_alive: c_int,
    /// `time_t max_time`.
    pub max_time: TimeT,
    /// `time_t max_total_time`.
    pub max_total_time: TimeT,
    /// `char *redirection_url`.
    pub redirection_url: *mut c_char,
    /// `size_t max_hdr_lines`.
    pub max_hdr_lines: usize,
}

// ---------------------------------------------------------------------------
// The raise sites — declared locally (see the module doc)
// ---------------------------------------------------------------------------

/// One `http_client.c` raise coordinate, declared locally (see the module doc).
const fn http_client_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/http/http_client.c",
        line,
        func,
        lib: ERR_LIB_HTTP,
        reason,
        dynamic_reason: false,
    }
}

macro_rules! site {
    ($name:ident, $line:literal, $func:literal, $reason:expr) => {
        #[doc = concat!("`", stringify!($func), "` at `http_client.c:", stringify!($line), "`.")]
        const $name: ErrSite = http_client_site($line, $func, $reason);
    };
}

site!(HC_101, 101, c"no_crlf", ERR_R_PASSED_INVALID_ARGUMENT);
site!(
    HC_113,
    113,
    c"OSSL_HTTP_REQ_CTX_new",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_159,
    159,
    c"OSSL_HTTP_REQ_CTX_get0_mem_bio",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_168,
    168,
    c"OSSL_HTTP_REQ_CTX_get_resp_len",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_178,
    178,
    c"OSSL_HTTP_REQ_CTX_set_max_response_length",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_194,
    194,
    c"OSSL_HTTP_REQ_CTX_set_request_line",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_225,
    225,
    c"OSSL_HTTP_REQ_CTX_set_request_line",
    ERR_R_PASSED_INVALID_ARGUMENT
);
site!(
    HC_247,
    247,
    c"OSSL_HTTP_REQ_CTX_add1_header",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_251,
    251,
    c"OSSL_HTTP_REQ_CTX_add1_header",
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
);
site!(
    HC_274,
    274,
    c"OSSL_HTTP_REQ_CTX_set_expected",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_280,
    280,
    c"OSSL_HTTP_REQ_CTX_set_expected",
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
);
site!(HC_308, 308, c"set1_content", ERR_R_PASSED_NULL_PARAMETER);
site!(
    HC_321,
    321,
    c"set1_content",
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
);
site!(
    HC_384,
    384,
    c"OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_510,
    510,
    c"parse_http_line1",
    HTTP_R_STATUS_CODE_UNSUPPORTED
);
site!(HC_522, 522, c"parse_http_line1", HTTP_R_HEADER_PARSE_ERROR);
site!(HC_529, 529, c"check_max_len", HTTP_R_MAX_RESP_LEN_EXCEEDED);
site!(
    HC_541,
    541,
    c"check_set_resp_len",
    HTTP_R_INCONSISTENT_CONTENT_LENGTH
);
site!(HC_555, 555, c"may_still_retry", HTTP_R_RETRY_TIMEOUT);
site!(
    HC_580,
    580,
    c"OSSL_HTTP_REQ_CTX_nbio",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_584,
    584,
    c"OSSL_HTTP_REQ_CTX_nbio",
    ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
);
site!(
    HC_614,
    614,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_FAILED_READING_DATA
);
site!(
    HC_683,
    683,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_FAILED_READING_DATA
);
site!(
    HC_751,
    751,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_RESPONSE_TOO_MANY_HDRLINES
);
site!(
    HC_758,
    758,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_RESPONSE_LINE_TOO_LONG
);
site!(
    HC_783,
    783,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_REDIRECTION_NOT_ENABLED
);
site!(
    HC_823,
    823,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_CONTENT_TYPE_MISMATCH
);
site!(
    HC_841,
    841,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_UNEXPECTED_CONTENT_TYPE
);
site!(
    HC_861,
    861,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_ERROR_PARSING_CONTENT_LENGTH
);
site!(
    HC_887,
    887,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_SERVER_CANCELED_CONNECTION
);
site!(
    HC_906,
    906,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_MISSING_CONTENT_TYPE
);
site!(
    HC_912,
    912,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_MISSING_REDIRECT_LOCATION
);
site!(
    HC_941,
    941,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_MISSING_ASN1_ENCODING
);
site!(
    HC_956,
    956,
    c"OSSL_HTTP_REQ_CTX_nbio",
    HTTP_R_ERROR_PARSING_ASN1_LENGTH
);
site!(
    HC_1056,
    1056,
    c"OSSL_HTTP_REQ_CTX_exchange",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_1073,
    1073,
    c"OSSL_HTTP_REQ_CTX_exchange",
    HTTP_R_ERROR_SENDING
);
site!(
    HC_1075,
    1075,
    c"OSSL_HTTP_REQ_CTX_exchange",
    HTTP_R_ERROR_RECEIVING
);
site!(HC_1100, 1100, c"OSSL_HTTP_open", HTTP_R_TLS_NOT_ENABLED);
site!(
    HC_1104,
    1104,
    c"OSSL_HTTP_open",
    ERR_R_PASSED_INVALID_ARGUMENT
);
site!(
    HC_1111,
    1111,
    c"OSSL_HTTP_open",
    ERR_R_PASSED_INVALID_ARGUMENT
);
site!(
    HC_1119,
    1119,
    c"OSSL_HTTP_open",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_1185,
    1185,
    c"OSSL_HTTP_set1_request",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_1190,
    1190,
    c"OSSL_HTTP_set1_request",
    ERR_R_PASSED_INVALID_ARGUMENT
);
site!(
    HC_1215,
    1215,
    c"OSSL_HTTP_exchange",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_1226,
    1226,
    c"OSSL_HTTP_exchange",
    HTTP_R_REDIRECTION_NOT_ENABLED
);
site!(
    HC_1270,
    1270,
    c"redirection_ok",
    HTTP_R_TOO_MANY_REDIRECTIONS
);
site!(
    HC_1276,
    1276,
    c"redirection_ok",
    HTTP_R_REDIRECTION_FROM_HTTPS_TO_HTTP
);
site!(HC_1300, 1300, c"OSSL_HTTP_get", ERR_R_PASSED_NULL_PARAMETER);
site!(
    HC_1474,
    1474,
    c"OSSL_HTTP_proxy_connect",
    ERR_R_PASSED_NULL_PARAMETER
);
site!(
    HC_1559,
    1559,
    c"OSSL_HTTP_proxy_connect",
    HTTP_R_HEADER_PARSE_ERROR
);
site!(
    HC_1566,
    1566,
    c"OSSL_HTTP_proxy_connect",
    HTTP_R_RECEIVED_WRONG_HTTP_VERSION
);
site!(
    HC_1582,
    1582,
    c"OSSL_HTTP_proxy_connect",
    HTTP_R_CONNECT_FAILURE
);

// ---------------------------------------------------------------------------
// Small local helpers for the bio.h macros
// ---------------------------------------------------------------------------

/// `ossl_assert(x)` — `include/internal/common.h:52-53`, the admitted build's non-aborting form.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `HAS_PREFIX(str, pre)` — `include/internal/common.h:58`: `strncmp(str, pre, sizeof(pre)-1)`.
///
/// # Safety
/// `s` must be NUL-terminated.
#[inline]
unsafe fn has_prefix(s: *const c_char, pre: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract; `pre` is a static slice.
    unsafe { crate::runtime::bio::sys::strncmp(s, pre.as_ptr().cast::<c_char>(), pre.len()) == 0 }
}

/// `HAS_CASE_PREFIX(s, p)` — `include/internal/common.h:63`.
///
/// # Safety
/// `s` must be NUL-terminated.
#[inline]
unsafe fn has_case_prefix(s: *const c_char, p: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract; `p` is a static slice.
    unsafe { OPENSSL_strncasecmp(s, p.as_ptr().cast::<c_char>(), p.len()) == 0 }
}

/// `BIO_should_retry(a)` — `bio.h:272`, `BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_should_retry(b: *mut Bio) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) }
}

/// `BIO_reset(b)` — `bio.h:632`, `BIO_ctrl(b, BIO_CTRL_RESET, 0, NULL)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_reset(b: *mut Bio) -> c_int {
    // SAFETY: `b` is NULL or live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_RESET, 0, ptr::null_mut()) as c_int }
}

/// `BIO_eof(b)` — `bio.h:633`, `BIO_ctrl(b, BIO_CTRL_EOF, 0, NULL)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_eof(b: *mut Bio) -> c_int {
    // SAFETY: `b` is NULL or live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_EOF, 0, ptr::null_mut()) as c_int }
}

/// `BIO_flush(b)` — `bio.h:641`, `BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL)`.
///
/// # Safety
/// `b` must be NULL or a live BIO.
#[inline]
unsafe fn bio_flush(b: *mut Bio) -> c_int {
    // SAFETY: `b` is NULL or live per the contract.
    unsafe { BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut()) as c_int }
}

/// `BIO_get_mem_data(b, pp)` — `bio.h:615`, `BIO_ctrl(b, BIO_CTRL_INFO, 0, pp)`. The answer is
/// the available byte count, and the control writes the buffer pointer through `pp`.
///
/// # Safety
/// `b` must be live; `pp` writable for one pointer.
#[inline]
unsafe fn bio_get_mem_data(b: *mut Bio, pp: *mut *mut c_uchar) -> c_long {
    // SAFETY: `b` is live and `pp` is the out-parameter the control writes.
    unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, pp.cast::<c_void>()) }
}

/// `BIO_get_fp(b, fpp)` — `bio.h:569`, `BIO_ctrl(b, BIO_C_GET_FILE_PTR, 0, (char *)fpp)`.
///
/// # Safety
/// `b` must be a live file BIO; `fpp` writable for one `FILE *`.
#[inline]
unsafe fn bio_get_fp(b: *mut Bio, fpp: *mut *mut crate::runtime::bio::sys::FILE) -> c_int {
    // SAFETY: `b` is live and `fpp` is the out-parameter the control writes.
    unsafe { BIO_ctrl(b, BIO_C_GET_FILE_PTR, 0, fpp.cast::<c_void>()) as c_int }
}

/// `BIO_set_conn_port(b, port)` — `bio.h:518`, `BIO_ctrl(b, BIO_C_SET_CONNECT, 1, (char*)port)`.
///
/// # Safety
/// `b` must be a live connect BIO; `port` NUL-terminated.
#[inline]
unsafe fn bio_set_conn_port(b: *mut Bio, port: *const c_char) -> c_long {
    // SAFETY: `b` is live and `port` is a NUL-terminated string per the contract.
    unsafe { BIO_ctrl(b, BIO_C_SET_CONNECT, 1, port.cast_mut().cast::<c_void>()) }
}

/// `ERR_GET_LIB` — `include/openssl/err.h:243-249`, the header's inline function.
fn err_get_lib(e: c_ulong) -> c_int {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        ERR_LIB_SYS
    } else {
        ((e >> ERR_LIB_OFFSET) & ERR_LIB_MASK) as c_int
    }
}

/// `ERR_GET_REASON` — `include/openssl/err.h:257-263`, the header's inline function.
fn err_get_reason(e: c_ulong) -> c_int {
    if (e & ERR_SYSTEM_FLAG) != 0 {
        (e & ERR_SYSTEM_MASK) as c_int
    } else {
        (e & ERR_REASON_MASK) as c_int
    }
}

/// The C `for (end = reason + strlen(reason) - 1; ossl_isspace(*end); end--) *end = 0;` loop of
/// `parse_http_line1`, and the `for` loop that blanks a non-printing line before raising.
///
/// # Safety
/// `s` must be NUL-terminated.
#[inline]
unsafe fn str_len(s: *const c_char) -> usize {
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe { strlen(s) }
}

// ---------------------------------------------------------------------------
// Low-level API implementation
// ---------------------------------------------------------------------------

/// `static int no_crlf(const char *component, const char *value)` —
/// `crypto/http/http_client.c:98-106`.
///
/// # Safety
/// `component` and `value` must each be NULL or NUL-terminated.
unsafe fn no_crlf(component: *const c_char, value: *const c_char) -> c_int {
    // SAFETY: `value` is NULL or NUL-terminated; the literal is static.
    if !value.is_null() && !unsafe { strpbrk(value, c"\r\n".as_ptr()) }.is_null() {
        let mut msg = [0 as c_char; 512];
        // SAFETY: `msg` is writable for its own length; the format arguments match the
        // authority's own `ERR_raise_data`.
        unsafe {
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"CR or LF character in %s".as_ptr(),
                component,
            );
        }
        // SAFETY: `msg` is a NUL-terminated stack buffer.
        unsafe { raise_site_data(&HC_101, msg.as_ptr()) };
        return 0;
    }
    1
}

/// `OSSL_HTTP_REQ_CTX *OSSL_HTTP_REQ_CTX_new(BIO *wbio, BIO *rbio, int buf_size)` —
/// `crypto/http/http_client.c:108-132`.
///
/// # Safety
/// `wbio` and `rbio` must each be NULL or a live BIO; a non-NULL pair is kept borrowed by the
/// context, so both must outlive it.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_new(
    wbio: *mut Bio,
    rbio: *mut Bio,
    buf_size: c_int,
) -> *mut OsslHttpReqCtx {
    // SAFETY: the whole body. `wbio`/`rbio` are NULL or live per the contract; the struct is the
    // fresh zeroed allocation this call owns.
    unsafe {
        if wbio.is_null() || rbio.is_null() {
            raise_site(&HC_113);
            return ptr::null_mut();
        }

        let rctx = CRYPTO_zalloc(core::mem::size_of::<OsslHttpReqCtx>(), FILE.as_ptr(), 117)
            .cast::<OsslHttpReqCtx>();
        if rctx.is_null() {
            return ptr::null_mut();
        }
        (*rctx).state = OHS_ERROR;
        (*rctx).buf_size = if buf_size > 0 {
            buf_size
        } else {
            OSSL_HTTP_DEFAULT_MAX_LINE_LEN
        };
        (*rctx).buf =
            CRYPTO_malloc((*rctx).buf_size as usize, FILE.as_ptr(), 121).cast::<c_uchar>();
        (*rctx).wbio = wbio;
        (*rctx).rbio = rbio;
        (*rctx).max_hdr_lines = OSSL_HTTP_DEFAULT_MAX_RESP_HDR_LINES;
        if (*rctx).buf.is_null() {
            // SAFETY: `rctx` is the allocation above and only this call owns it.
            CRYPTO_free(rctx.cast(), FILE.as_ptr(), 126);
            return ptr::null_mut();
        }
        (*rctx).max_resp_len = OSSL_HTTP_DEFAULT_MAX_RESP_LEN;
        rctx
    }
}

/// `void OSSL_HTTP_REQ_CTX_free(OSSL_HTTP_REQ_CTX *rctx)` — `crypto/http/http_client.c:134-154`.
///
/// # Safety
/// `rctx` must be NULL or a context this crate allocated and that no other owner holds.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_free(rctx: *mut OsslHttpReqCtx) {
    // SAFETY: the whole body. `rctx` is NULL or this crate's allocation per the contract.
    unsafe {
        if rctx.is_null() {
            return;
        }
        /*
         * Use BIO_free_all() because bio_update_fn may prepend or append to cbio. This also frees
         * any (e.g., SSL/TLS) BIOs linked with bio.
         */
        if (*rctx).free_wbio != 0 {
            BIO_free_all((*rctx).wbio);
        }
        /* do not free rctx->rbio */
        BIO_free((*rctx).mem);
        BIO_free((*rctx).req);
        CRYPTO_free((*rctx).buf.cast(), FILE.as_ptr(), 148);
        CRYPTO_free((*rctx).proxy.cast(), FILE.as_ptr(), 149);
        CRYPTO_free((*rctx).server.cast(), FILE.as_ptr(), 150);
        CRYPTO_free((*rctx).port.cast(), FILE.as_ptr(), 151);
        CRYPTO_free((*rctx).expected_ct.cast(), FILE.as_ptr(), 152);
        CRYPTO_free(rctx.cast(), FILE.as_ptr(), 153);
    }
}

/// `BIO *OSSL_HTTP_REQ_CTX_get0_mem_bio(const OSSL_HTTP_REQ_CTX *rctx)` —
/// `crypto/http/http_client.c:156-163`.
///
/// # Safety
/// `rctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: *const OsslHttpReqCtx) -> *mut Bio {
    // SAFETY: `rctx` is NULL or live per the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_159);
            return ptr::null_mut();
        }
        (*rctx).mem
    }
}

/// `size_t OSSL_HTTP_REQ_CTX_get_resp_len(const OSSL_HTTP_REQ_CTX *rctx)` —
/// `crypto/http/http_client.c:165-172`.
///
/// # Safety
/// `rctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_get_resp_len(rctx: *const OsslHttpReqCtx) -> usize {
    // SAFETY: `rctx` is NULL or live per the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_168);
            return 0;
        }
        (*rctx).resp_len
    }
}

/// `void OSSL_HTTP_REQ_CTX_set_max_response_length(OSSL_HTTP_REQ_CTX *rctx, unsigned long len)` —
/// `crypto/http/http_client.c:174-182`.
///
/// # Safety
/// `rctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_max_response_length(
    rctx: *mut OsslHttpReqCtx,
    len: c_ulong,
) {
    // SAFETY: `rctx` is NULL or live per the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_178);
            return;
        }
        (*rctx).max_resp_len = if len != 0 {
            len as usize
        } else {
            OSSL_HTTP_DEFAULT_MAX_RESP_LEN
        };
    }
}

/// `int OSSL_HTTP_REQ_CTX_set_request_line(OSSL_HTTP_REQ_CTX *rctx, int method_POST,
/// const char *server, const char *port, const char *path)` — `crypto/http/http_client.c:189-241`.
///
/// # Safety
/// `rctx` must be NULL or live; `server`, `port` and `path` must each be NULL or a
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_request_line(
    rctx: *mut OsslHttpReqCtx,
    method_POST: c_int,
    server: *const c_char,
    port: *const c_char,
    path: *const c_char,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live; every string is NULL or NUL-terminated.
    unsafe {
        let mut path = path;
        if rctx.is_null() {
            raise_site(&HC_194);
            return 0;
        }
        if no_crlf(c"server".as_ptr(), server) == 0
            || no_crlf(c"port".as_ptr(), port) == 0
            || no_crlf(c"path".as_ptr(), path) == 0
        {
            return 0;
        }
        BIO_free((*rctx).mem);
        (*rctx).mem = BIO_new(BIO_s_mem());
        if (*rctx).mem.is_null() {
            return 0;
        }

        (*rctx).method_POST = c_int::from(method_POST != 0);
        if BIO_printf(
            (*rctx).mem,
            c"%s ".as_ptr(),
            if (*rctx).method_POST != 0 {
                c"POST".as_ptr()
            } else {
                c"GET".as_ptr()
            },
        ) <= 0
        {
            return 0;
        }

        if !server.is_null() {
            /*
             * Section 5.1.2 of RFC 1945 states that the absoluteURI form is only allowed when
             * using a proxy.
             */
            if BIO_printf((*rctx).mem, OSSL_HTTP_PREFIX.as_ptr(), server) <= 0 {
                return 0;
            }
            if !port.is_null() && BIO_printf((*rctx).mem, c":%s".as_ptr(), port) <= 0 {
                return 0;
            }
        }

        /* Make sure path includes a forward slash (abs_path) */
        if path.is_null() {
            path = c"/".as_ptr();
        } else if has_prefix(path, b"http://") {
            /* absoluteURI for proxy use */
            if !server.is_null() {
                raise_site(&HC_225);
                return 0;
            }
        } else if *path != b'/' as c_char && BIO_printf((*rctx).mem, c"/".as_ptr()) <= 0 {
            return 0;
        }
        /*
         * Add (the rest of) the path and the HTTP version, which is fixed to 1.0 for
         * straightforward implementation of keep-alive.
         */
        if BIO_printf((*rctx).mem, c"%s %s\r\n".as_ptr(), path, HTTP_1_0.as_ptr()) <= 0 {
            return 0;
        }

        (*rctx).resp_len = 0;
        (*rctx).state = OHS_ADD_HEADERS;
        1
    }
}

/// `int OSSL_HTTP_REQ_CTX_add1_header(OSSL_HTTP_REQ_CTX *rctx, const char *name,
/// const char *value)` — `crypto/http/http_client.c:243-267`.
///
/// # Safety
/// `rctx` must be NULL or live; `name` must be NULL or NUL-terminated; `value` must be NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_add1_header(
    rctx: *mut OsslHttpReqCtx,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live and both strings are NULL or NUL-terminated.
    unsafe {
        if rctx.is_null() || name.is_null() {
            raise_site(&HC_247);
            return 0;
        }
        if (*rctx).mem.is_null() {
            raise_site(&HC_251);
            return 0;
        }
        if no_crlf(c"header name".as_ptr(), name) == 0
            || no_crlf(c"header value".as_ptr(), value) == 0
        {
            return 0;
        }

        if crate::runtime::bio::BIO_puts((*rctx).mem, name) <= 0 {
            return 0;
        }
        if !value.is_null() {
            if BIO_write((*rctx).mem, c": ".as_ptr().cast(), 2) != 2 {
                return 0;
            }
            if crate::runtime::bio::BIO_puts((*rctx).mem, value) <= 0 {
                return 0;
            }
        }
        c_int::from(BIO_write((*rctx).mem, c"\r\n".as_ptr().cast(), 2) == 2)
    }
}

/// `int OSSL_HTTP_REQ_CTX_set_expected(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
/// int asn1, int timeout, int keep_alive)` — `crypto/http/http_client.c:269-297`.
///
/// # Safety
/// `rctx` must be NULL or live; `content_type` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_expected(
    rctx: *mut OsslHttpReqCtx,
    content_type: *const c_char,
    asn1: c_int,
    timeout: c_int,
    keep_alive: c_int,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live; `content_type` is NULL or NUL-terminated.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_274);
            return 0;
        }
        if keep_alive != 0 && (*rctx).state != OHS_ERROR && (*rctx).state != OHS_ADD_HEADERS {
            /* Cannot anymore set keep-alive in request header */
            raise_site(&HC_280);
            return 0;
        }

        CRYPTO_free((*rctx).expected_ct.cast(), FILE.as_ptr(), 284);
        (*rctx).expected_ct = ptr::null_mut();
        if !content_type.is_null() {
            (*rctx).expected_ct = CRYPTO_strdup(content_type, FILE.as_ptr(), 287);
            if (*rctx).expected_ct.is_null() {
                return 0;
            }
        }

        (*rctx).expect_asn1 = asn1;
        if timeout >= 0 {
            (*rctx).max_time = if timeout > 0 {
                time(ptr::null_mut()) + timeout as c_long
            } else {
                0
            };
        } else {
            /* take over any |overall_timeout| arg of OSSL_HTTP_open(), else 0 */
            (*rctx).max_time = (*rctx).max_total_time;
        }
        (*rctx).keep_alive = keep_alive;
        1
    }
}

/// `static int set1_content(OSSL_HTTP_REQ_CTX *rctx, const char *content_type, BIO *req)` —
/// `crypto/http/http_client.c:299-366`.
///
/// # Safety
/// `rctx` must be NULL or live; `content_type` must be NULL or NUL-terminated; `req` must be NULL
/// or a live BIO. `req` (when non-NULL) is `BIO_up_ref`'d and kept by the context.
unsafe fn set1_content(
    rctx: *mut OsslHttpReqCtx,
    content_type: *const c_char,
    req: *mut Bio,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live, `content_type` NULL or NUL-terminated, `req`
    // NULL or live per the contract.
    unsafe {
        let mut req_len: c_long = 0;
        let mut fp: *mut crate::runtime::bio::sys::FILE = ptr::null_mut();

        if rctx.is_null() || (req.is_null() && !content_type.is_null()) {
            raise_site(&HC_308);
            return 0;
        }

        if (*rctx).keep_alive != 0
            && OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Connection".as_ptr(), c"keep-alive".as_ptr())
                == 0
        {
            return 0;
        }

        BIO_free((*rctx).req);
        (*rctx).req = ptr::null_mut();
        if req.is_null() {
            return 1;
        }
        if (*rctx).method_POST == 0 {
            raise_site(&HC_321);
            return 0;
        }

        if content_type.is_null() {
            /* assuming request to be text by default, used just for tracing */
            (*rctx).text = 1;
        } else {
            if has_case_prefix(content_type, b"text/") {
                (*rctx).text = 1;
            }
            if OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Content-Type".as_ptr(), content_type) == 0 {
                return 0;
            }
        }

        /*
         * BIO_CTRL_INFO yields the data length at least for memory BIOs, but for file-based BIOs
         * it gives the current position, which is not what we need.
         */
        if BIO_method_type(req) == BIO_TYPE_FILE {
            if bio_get_fp(req, &mut fp) == 1 && fseek(fp, 0, SEEK_END) == 0 {
                req_len = ftell(fp);
                let _ = fseek(fp, 0, SEEK_SET);
            } else {
                fp = ptr::null_mut();
            }
        } else {
            req_len = BIO_ctrl(req, BIO_CTRL_INFO, 0, ptr::null_mut());
            /*
             * Streaming BIOs likely will not support querying the size at all, and we assume we
             * got a correct value if req_len > 0.
             */
        }
        if (!fp.is_null() || req_len > 0)
            && BIO_printf((*rctx).mem, c"Content-Length: %ld\r\n".as_ptr(), req_len) < 0
        {
            return 0;
        }

        if BIO_up_ref(req) == 0 {
            return 0;
        }
        (*rctx).req = req;
        1
    }
}

/// `int OSSL_HTTP_REQ_CTX_set1_req(OSSL_HTTP_REQ_CTX *rctx, const char *content_type,
/// const ASN1_ITEM *it, const ASN1_VALUE *req)` — `crypto/http/http_client.c:368-379`.
///
/// # Safety
/// `rctx` must be NULL or live; `content_type` NULL or NUL-terminated; `it` must be a live item
/// and `req` a live value of its type, or NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set1_req(
    rctx: *mut OsslHttpReqCtx,
    content_type: *const c_char,
    it: *const Asn1Item,
    req: *const c_void,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live; `it`/`req` are the caller's per the contract.
    unsafe {
        let mut mem: *mut Bio = ptr::null_mut();
        let mut res = 1;
        if !req.is_null() {
            mem = ASN1_item_i2d_mem_bio(it, req);
            res = c_int::from(!mem.is_null());
        }
        res = c_int::from(res != 0 && set1_content(rctx, content_type, mem) != 0);
        BIO_free(mem);
        res
    }
}

/// `void OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(OSSL_HTTP_REQ_CTX *rctx, size_t count)` —
/// `crypto/http/http_client.c:381-389`.
///
/// # Safety
/// `rctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_set_max_response_hdr_lines(
    rctx: *mut OsslHttpReqCtx,
    count: usize,
) {
    // SAFETY: `rctx` is NULL or live per the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_384);
            return;
        }
        (*rctx).max_hdr_lines = count;
    }
}

/// `static int add1_headers(OSSL_HTTP_REQ_CTX *rctx, const STACK_OF(CONF_VALUE) *headers,
/// const char *host)` — `crypto/http/http_client.c:391-409`.
///
/// # Safety
/// `rctx` must be NULL or live; `headers` must be NULL or a live `STACK_OF(CONF_VALUE)` whose
/// elements are live `CONF_VALUE`s; `host` NULL or NUL-terminated.
unsafe fn add1_headers(
    rctx: *mut OsslHttpReqCtx,
    headers: *const crate::runtime::stack::OpenSslStack,
    host: *const c_char,
) -> c_int {
    // SAFETY: the whole body. Every stack element is a live `CONF_VALUE` per the contract.
    unsafe {
        let mut add_host = !host.is_null() && *host != 0;
        let n = OPENSSL_sk_num(headers);
        let mut i = 0;
        while i < n {
            let hdr = OPENSSL_sk_value(headers, i).cast::<ConfValue>();
            if add_host && OPENSSL_strcasecmp(c"host".as_ptr(), (*hdr).name) == 0 {
                add_host = false;
            }
            if OSSL_HTTP_REQ_CTX_add1_header(rctx, (*hdr).name, (*hdr).value) == 0 {
                return 0;
            }
            i += 1;
        }

        if add_host && OSSL_HTTP_REQ_CTX_add1_header(rctx, c"Host".as_ptr(), host) == 0 {
            return 0;
        }
        1
    }
}

/// `static OSSL_HTTP_REQ_CTX *http_req_ctx_new(int free_wbio, BIO *wbio, BIO *rbio,
/// OSSL_HTTP_bio_cb_t bio_update_fn, void *arg, int use_ssl, const char *proxy,
/// const char *server, const char *port, int buf_size, int overall_timeout)` —
/// `crypto/http/http_client.c:412-442`.
///
/// # Safety
/// As [`OSSL_HTTP_REQ_CTX_new`]; `proxy`/`server`/`port` must each be NULL or NUL-terminated.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn http_req_ctx_new(
    free_wbio: c_int,
    wbio: *mut Bio,
    rbio: *mut Bio,
    bio_update_fn: OSSL_HTTP_bio_cb_t,
    arg: *mut c_void,
    use_ssl: c_int,
    proxy: *const c_char,
    server: *const c_char,
    port: *const c_char,
    buf_size: c_int,
    overall_timeout: c_int,
) -> *mut OsslHttpReqCtx {
    // SAFETY: the whole body. `wbio`/`rbio` are NULL or live; the three strings NULL or
    // NUL-terminated, all per the contract.
    unsafe {
        let rctx = OSSL_HTTP_REQ_CTX_new(wbio, rbio, buf_size);
        if rctx.is_null() {
            return ptr::null_mut();
        }
        (*rctx).free_wbio = free_wbio;
        (*rctx).upd_fn = bio_update_fn;
        (*rctx).upd_arg = arg;
        (*rctx).use_ssl = use_ssl;
        if !proxy.is_null() {
            (*rctx).proxy = CRYPTO_strdup(proxy, FILE.as_ptr(), 428);
            if (*rctx).proxy.is_null() {
                OSSL_HTTP_REQ_CTX_free(rctx);
                return ptr::null_mut();
            }
        }
        if !server.is_null() {
            (*rctx).server = CRYPTO_strdup(server, FILE.as_ptr(), 431);
            if (*rctx).server.is_null() {
                OSSL_HTTP_REQ_CTX_free(rctx);
                return ptr::null_mut();
            }
        }
        if !port.is_null() {
            (*rctx).port = CRYPTO_strdup(port, FILE.as_ptr(), 434);
            if (*rctx).port.is_null() {
                OSSL_HTTP_REQ_CTX_free(rctx);
                return ptr::null_mut();
            }
        }
        (*rctx).max_total_time = if overall_timeout > 0 {
            time(ptr::null_mut()) + overall_timeout as c_long
        } else {
            0
        };
        rctx
    }
}

/// `static int parse_http_line1(char *line, int *found_keep_alive)` —
/// `crypto/http/http_client.c:450-524`.
///
/// # Safety
/// `line` must point at a writable NUL-terminated buffer at least `HTTP_LINE1_MINLEN` bytes long;
/// `found_keep_alive` must point at a writable `int`.
unsafe fn parse_http_line1(line: *mut c_char, found_keep_alive: *mut c_int) -> c_int {
    // SAFETY: the whole body. `line` is a writable NUL-terminated buffer and `found_keep_alive` a
    // writable int, both per the contract; every scan stops at `line`'s own NUL or within it.
    unsafe {
        let mut line = line;

        if !has_prefix(line, HTTP_PREFIX_VERSION) {
            return parse_http_line1_err(line);
        }
        line = line.add(HTTP_PREFIX_VERSION.len());
        /* above HTTP 1.0, connection persistence is the default */
        *found_keep_alive = c_int::from(*line > b'0' as c_char);

        /* Skip to first whitespace (past protocol info) */
        let mut code = line;
        while *code != 0 && !ossl_isspace(*code as c_int) {
            code = code.add(1);
        }
        if *code == 0 {
            return parse_http_line1_err(line);
        }

        /* Skip past whitespace to start of response code */
        while *code != 0 && ossl_isspace(*code as c_int) {
            code = code.add(1);
        }
        if *code == 0 {
            return parse_http_line1_err(line);
        }

        /* Find end of response code: first whitespace after start of code */
        let mut reason = code;
        while *reason != 0 && !ossl_isspace(*reason as c_int) {
            reason = reason.add(1);
        }
        if *reason == 0 {
            return parse_http_line1_err(line);
        }

        /* Set end of response code and start of message */
        *reason = 0;
        reason = reason.add(1);

        /* Attempt to parse numeric code */
        let mut end: *mut c_char = ptr::null_mut();
        let retcode = strtoul(code, &mut end, 10) as c_int;
        if *end != 0 {
            return parse_http_line1_err(line);
        }

        /* Skip over any leading whitespace in message */
        while *reason != 0 && ossl_isspace(*reason as c_int) {
            reason = reason.add(1);
        }

        if *reason != 0 {
            /*
             * Finally zap any trailing whitespace in message (include CRLF). We know reason has a
             * non-whitespace character so this is OK.
             */
            end = reason.add(str_len(reason) - 1);
            while ossl_isspace(*end as c_int) {
                *end = 0;
                end = end.sub(1);
            }
        }

        match retcode {
            HTTP_STATUS_CODE_OK | HTTP_STATUS_CODE_MOVED_PERMANENTLY | HTTP_STATUS_CODE_FOUND => {
                retcode
            }
            _ => {
                if retcode == HTTP_STATUS_CODE_NOT_FOUND
                    || retcode < HTTP_STATUS_CODES_NONFATAL_ERROR
                {
                    let mut msg = [0 as c_char; 512];
                    BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"code=%s".as_ptr(), code);
                    raise_site_data(&HC_510, msg.as_ptr());
                    if *reason != 0 {
                        ERR_add_error_data(2, c", reason=".as_ptr(), reason);
                    }
                }
                /* must return content normally if status >= 400, still tentatively raised error on 404 */
                retcode
            }
        }
    }
}

/// The `err:` tail of `parse_http_line1` (`http_client.c:517-523`), extracted so the Rust version
/// of the function has no `goto`.
///
/// # Safety
/// As [`parse_http_line1`].
unsafe fn parse_http_line1_err(line: *mut c_char) -> c_int {
    // SAFETY: `line` is a writable NUL-terminated buffer, per the caller's contract.
    unsafe {
        let mut i = 0;
        while i < 60 && *line.add(i) != 0 {
            if !ossl_isprint(*line.add(i) as c_int) {
                *line.add(i) = b' ' as c_char;
            }
            i += 1;
        }
        *line.add(i) = 0;
        let mut msg = [0 as c_char; 512];
        BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"content=%s".as_ptr(), line);
        raise_site_data(&HC_522, msg.as_ptr());
        0
    }
}

/// `static int check_max_len(const char *desc, size_t max_len, size_t len)` —
/// `crypto/http/http_client.c:526-534`.
///
/// # Safety
/// `desc` must be NUL-terminated.
unsafe fn check_max_len(desc: *const c_char, max_len: usize, len: usize) -> c_int {
    // SAFETY: `desc` is NUL-terminated per the contract.
    unsafe {
        if max_len != 0 && len > max_len {
            let mut msg = [0 as c_char; 512];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s length=%zu, max=%zu".as_ptr(),
                desc,
                len,
                max_len,
            );
            raise_site_data(&HC_529, msg.as_ptr());
            return 0;
        }
        1
    }
}

/// `static int check_set_resp_len(const char *desc, OSSL_HTTP_REQ_CTX *rctx, size_t len)` —
/// `crypto/http/http_client.c:536-547`.
///
/// # Safety
/// `desc` must be NUL-terminated; `rctx` must be live.
unsafe fn check_set_resp_len(desc: *const c_char, rctx: *mut OsslHttpReqCtx, len: usize) -> c_int {
    // SAFETY: `desc` is NUL-terminated and `rctx` live, per the contract.
    unsafe {
        if check_max_len(desc, (*rctx).max_resp_len, len) == 0 {
            return 0;
        }
        if (*rctx).resp_len != 0 && (*rctx).resp_len != len {
            let mut msg = [0 as c_char; 512];
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"%s length=%zu, Content-Length=%zu".as_ptr(),
                desc,
                len,
                (*rctx).resp_len,
            );
            raise_site_data(&HC_541, msg.as_ptr());
            return 0;
        }
        (*rctx).resp_len = len;
        1
    }
}

/// `static int may_still_retry(time_t max_time, int *ptimeout)` —
/// `crypto/http/http_client.c:549-562`.
///
/// # Safety
/// `ptimeout` must point at a writable `int`.
unsafe fn may_still_retry(max_time: TimeT, ptimeout: *mut c_int) -> c_int {
    // SAFETY: `ptimeout` is writable per the contract.
    unsafe {
        if max_time != 0 {
            let now = time(ptr::null_mut());
            if max_time < now {
                raise_site(&HC_555);
                return 0;
            }
            let time_diff = max_time - now;
            *ptimeout = if time_diff > c_int::MAX as c_long {
                c_int::MAX
            } else {
                time_diff as c_int
            };
        }
        1
    }
}

/// `int OSSL_HTTP_REQ_CTX_nbio(OSSL_HTTP_REQ_CTX *rctx)` — `crypto/http/http_client.c:568-987`.
///
/// The non-blocking request/response state machine. The authority's `goto next_io` and
/// `goto next_line` are the labeled loops below; the `switch` fall-throughs are the dispatch
/// loop, whose arms set `state` and let the loop re-dispatch.
///
/// # Safety
/// `rctx` must be NULL or a live context whose `mem`, `wbio` and `rbio` are live BIOs, and whose
/// `buf` is writable for `buf_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_nbio(rctx: *mut OsslHttpReqCtx) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live with the BIOs and buffer the contract
    // requires; the state machine only reads/writes through them and its own fields.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_580);
            return 0;
        }
        let ctx = &mut *rctx;
        if ctx.mem.is_null() || ctx.wbio.is_null() || ctx.rbio.is_null() {
            raise_site(&HC_584);
            return 0;
        }

        let mut found_expected_ct = 0;
        let mut found_keep_alive = 0;
        let mut status_code = 0;
        let mut got_text: c_int;
        let mut resp_len: usize = 0;
        let mut resp_hdr_lines: usize = 0;

        ctx.redirection_url = ptr::null_mut();

        'next_io: loop {
            let buf = ctx.buf.cast::<c_char>();

            if (ctx.state & OHS_NOREAD) == 0 {
                let n: c_long = if ctx.expect_asn1 != 0
                    && (ctx.state == OHS_ASN1_HEADER || ctx.state == OHS_ASN1_CONTENT)
                {
                    BIO_read(ctx.rbio, buf.cast(), ctx.buf_size) as c_long
                } else {
                    /* read one text line */
                    ERR_set_mark();
                    let mut n = BIO_gets(ctx.rbio, buf, ctx.buf_size) as c_long;
                    if n == -2 {
                        /* some BIOs, such as SSL, do not support "gets" */
                        ERR_pop_to_mark();
                        n = BIO_get_line(ctx.rbio, buf, ctx.buf_size) as c_long;
                    } else {
                        ERR_clear_last_mark();
                    }
                    n
                };
                if n <= 0 {
                    if ctx.state == OHS_ERROR_CONTENT {
                        /* end of error response content; throw error on inconsistent length */
                        let _ =
                            check_set_resp_len(c"error response content".as_ptr(), ctx, resp_len);
                        return 0;
                    }
                    if bio_should_retry(ctx.rbio) != 0 {
                        return -1;
                    }
                    raise_site(&HC_614);
                    return 0;
                }

                /* Write data to memory BIO */
                if BIO_write(ctx.mem, buf.cast(), n as c_int) != n as c_int {
                    return 0;
                }
            }

            /* The switch's fall-throughs are this loop: an arm sets `state` and re-dispatches. */
            loop {
                let mem = ctx.mem;
                match ctx.state {
                    OHS_ERROR => return 0,

                    OHS_ADD_HEADERS => {
                        /* Last operation was adding headers: need a final \r\n */
                        if BIO_write(mem, c"\r\n".as_ptr().cast(), 2) != 2 {
                            ctx.state = OHS_ERROR;
                            return 0;
                        }
                        ctx.state = OHS_WRITE_INIT;
                        /* fall through */
                    }

                    OHS_WRITE_INIT => {
                        ctx.len_to_send = bio_get_mem_data(mem, &mut ctx.pos);
                        ctx.state = OHS_WRITE_HDR1;
                        /* fall through */
                    }

                    OHS_WRITE_HDR1 | OHS_WRITE_HDR | OHS_WRITE_REQ => {
                        if ctx.len_to_send > 0 {
                            let mut sz: usize = 0;
                            if BIO_write_ex(
                                ctx.wbio,
                                ctx.pos.cast(),
                                ctx.len_to_send as usize,
                                &mut sz,
                            ) == 0
                            {
                                if bio_should_retry(ctx.wbio) != 0 {
                                    return -1;
                                }
                                ctx.state = OHS_ERROR;
                                return 0;
                            }
                            if ctx.state == OHS_WRITE_HDR1 {
                                ctx.state = OHS_WRITE_HDR;
                            }
                            ctx.pos = ctx.pos.add(sz);
                            ctx.len_to_send -= sz as c_long;
                            continue 'next_io;
                        }
                        if ctx.state == OHS_WRITE_HDR {
                            bio_reset(mem);
                            ctx.state = OHS_WRITE_REQ;
                        }
                        if !ctx.req.is_null() && bio_eof(ctx.req) == 0 {
                            let n = BIO_read(ctx.req, buf.cast(), ctx.buf_size) as c_long;
                            if n <= 0 {
                                if bio_should_retry(ctx.req) != 0 {
                                    return -1;
                                }
                                raise_site(&HC_683);
                                return 0;
                            }
                            ctx.pos = ctx.buf;
                            ctx.len_to_send = n;
                            continue 'next_io;
                        }
                        ctx.state = OHS_FLUSH;
                        /* fall through */
                    }

                    OHS_FLUSH => {
                        let i = bio_flush(ctx.wbio);
                        if i > 0 {
                            ctx.state = OHS_FIRSTLINE;
                            continue 'next_io;
                        }
                        if bio_should_retry(ctx.wbio) != 0 {
                            return -1;
                        }
                        ctx.state = OHS_ERROR;
                        return 0;
                    }

                    OHS_FIRSTLINE | OHS_HEADERS | OHS_HEADERS_ERROR | OHS_REDIRECT
                    | OHS_ERROR_CONTENT => {
                        'next_line: loop {
                            /*
                             * Due to strange memory BIO behavior with BIO_gets we have to check
                             * there's a complete line in there before calling BIO_gets.
                             */
                            let mut p: *mut c_uchar = ptr::null_mut();
                            let mut n = bio_get_mem_data(mem, &mut p);
                            if n <= 0 || memchr(p.cast(), b'\n' as c_int, n as usize).is_null() {
                                if n >= ctx.buf_size as c_long {
                                    ctx.state = OHS_ERROR;
                                    return 0;
                                }
                                continue 'next_io;
                            }
                            n = BIO_gets(mem, buf, ctx.buf_size) as c_long;

                            if n <= 0 {
                                if bio_should_retry(mem) != 0 {
                                    continue 'next_io;
                                }
                                ctx.state = OHS_ERROR;
                                return 0;
                            }

                            if ctx.state == OHS_ERROR_CONTENT {
                                resp_len += n as usize;
                                if check_max_len(
                                    c"error response content".as_ptr(),
                                    ctx.max_resp_len,
                                    resp_len,
                                ) == 0
                                {
                                    return 0;
                                }
                                continue 'next_line;
                            }

                            resp_hdr_lines += 1;
                            if ctx.max_hdr_lines != 0 && ctx.max_hdr_lines < resp_hdr_lines {
                                raise_site(&HC_751);
                                ctx.state = OHS_ERROR;
                                return 0;
                            }

                            /* Don't allow excessive lines */
                            if n == ctx.buf_size as c_long {
                                raise_site(&HC_758);
                                ctx.state = OHS_ERROR;
                                return 0;
                            }

                            /* First line in response header */
                            if ctx.state == OHS_FIRSTLINE {
                                status_code = parse_http_line1(buf, &mut found_keep_alive);
                                match status_code {
                                    HTTP_STATUS_CODE_OK => {
                                        ctx.state = OHS_HEADERS;
                                        continue 'next_line;
                                    }
                                    HTTP_STATUS_CODE_MOVED_PERMANENTLY | HTTP_STATUS_CODE_FOUND => {
                                        if ctx.method_POST == 0 {
                                            /* method is GET */
                                            ctx.state = OHS_REDIRECT;
                                            continue 'next_line;
                                        }
                                        raise_site(&HC_783);
                                        /*
                                         * redirection is not supported/recommended for POST; fall
                                         * through to the default arm.
                                         */
                                        ctx.state =
                                            if status_code < HTTP_STATUS_CODES_NONFATAL_ERROR {
                                                OHS_HEADERS_ERROR
                                            } else {
                                                OHS_HEADERS
                                            };
                                        continue 'next_line;
                                    }
                                    _ => {
                                        /* must return content if status >= 400 */
                                        ctx.state =
                                            if status_code < HTTP_STATUS_CODES_NONFATAL_ERROR {
                                                OHS_HEADERS_ERROR
                                            } else {
                                                OHS_HEADERS
                                            };
                                        continue 'next_line;
                                    }
                                }
                            }

                            let key = buf;
                            let mut value = strchr(key, b':' as c_int);
                            let mut line_end: *mut c_char = ptr::null_mut();
                            if !value.is_null() {
                                *value = 0;
                                value = value.add(1);
                                while ossl_isspace(*value as c_int) {
                                    value = value.add(1);
                                }
                                line_end = strchr(value, b'\r' as c_int);
                                if line_end.is_null() {
                                    line_end = strchr(value, b'\n' as c_int);
                                }
                                if !line_end.is_null() {
                                    *line_end = 0;
                                }
                            }
                            if !value.is_null() && !line_end.is_null() {
                                if ctx.state == OHS_REDIRECT
                                    && OPENSSL_strcasecmp(key, c"Location".as_ptr()) == 0
                                {
                                    ctx.redirection_url = value;
                                    /* stop reading due to redirect */
                                    bio_reset(ctx.rbio);
                                    return 0;
                                }
                                if OPENSSL_strcasecmp(key, c"Content-Type".as_ptr()) == 0 {
                                    got_text = c_int::from(has_case_prefix(value, b"text/"));
                                    if got_text != 0
                                        && ctx.state == OHS_HEADERS
                                        && ctx.expect_asn1 != 0
                                        && (status_code >= HTTP_STATUS_CODES_NONFATAL_ERROR
                                            || status_code == HTTP_STATUS_CODE_OK)
                                    {
                                        let mut msg = [0 as c_char; 512];
                                        BIO_snprintf(
                                            msg.as_mut_ptr(),
                                            msg.len(),
                                            c"expected ASN.1 content but got http code %d with Content-Type: %s".as_ptr(),
                                            status_code,
                                            value,
                                        );
                                        raise_site_data(&HC_823, msg.as_ptr());
                                        ctx.state = OHS_HEADERS_ERROR;
                                        continue 'next_line;
                                    }
                                    if ctx.state == OHS_HEADERS && !ctx.expected_ct.is_null() {
                                        let semicolon = strchr(value, b';' as c_int);

                                        let neq = OPENSSL_strcasecmp(ctx.expected_ct, value) != 0;
                                        let mismatch = neq
                                            && (!strchr(ctx.expected_ct, b';' as c_int).is_null()
                                                || semicolon.is_null()
                                                || {
                                                    let diff =
                                                        semicolon.offset_from(value) as usize;
                                                    diff != str_len(ctx.expected_ct)
                                                        || OPENSSL_strncasecmp(
                                                            ctx.expected_ct,
                                                            value,
                                                            diff,
                                                        ) != 0
                                                });
                                        if mismatch {
                                            let mut msg = [0 as c_char; 512];
                                            BIO_snprintf(
                                                msg.as_mut_ptr(),
                                                msg.len(),
                                                c"expected=%s, actual=%s".as_ptr(),
                                                ctx.expected_ct,
                                                value,
                                            );
                                            raise_site_data(&HC_841, msg.as_ptr());
                                            return 0;
                                        }
                                        found_expected_ct = 1;
                                    }
                                }

                                /* https://tools.ietf.org/html/rfc7230#section-6.3 Persistence */
                                if OPENSSL_strcasecmp(key, c"Connection".as_ptr()) == 0 {
                                    if OPENSSL_strcasecmp(value, c"keep-alive".as_ptr()) == 0 {
                                        found_keep_alive = 1;
                                    } else if OPENSSL_strcasecmp(value, c"close".as_ptr()) == 0 {
                                        found_keep_alive = 0;
                                    }
                                } else if OPENSSL_strcasecmp(key, c"Content-Length".as_ptr()) == 0 {
                                    let content_len = strtoul(value, &mut line_end, 10) as usize;

                                    if line_end == value || *line_end != 0 {
                                        let mut msg = [0 as c_char; 512];
                                        BIO_snprintf(
                                            msg.as_mut_ptr(),
                                            msg.len(),
                                            c"input=%s".as_ptr(),
                                            value,
                                        );
                                        raise_site_data(&HC_861, msg.as_ptr());
                                        return 0;
                                    }
                                    if check_set_resp_len(
                                        c"response content-length".as_ptr(),
                                        ctx,
                                        content_len,
                                    ) == 0
                                    {
                                        return 0;
                                    }
                                }
                            }

                            /* Look for blank line indicating end of headers */
                            let mut q = ctx.buf;
                            while *q != 0 {
                                if *q != b'\r' as c_uchar && *q != b'\n' as c_uchar {
                                    break;
                                }
                                q = q.add(1);
                            }
                            if *q != 0 {
                                /* not end of headers or not end of error response content */
                                continue 'next_line;
                            }

                            /* Found blank line(s) indicating end of headers */
                            if ctx.keep_alive != 0
                                /* do not let server initiate keep_alive */
                                && found_keep_alive == 0
                            {
                                /* otherwise there is no change */
                                if ctx.keep_alive == 2 {
                                    ctx.keep_alive = 0;
                                    raise_site(&HC_887);
                                    return 0;
                                }
                                ctx.keep_alive = 0;
                            }

                            if ctx.state == OHS_HEADERS_ERROR {
                                ctx.state = OHS_ERROR_CONTENT;
                                /* discard response content when trace not enabled */
                                bio_reset(ctx.rbio);
                                return 0;
                            }

                            if !ctx.expected_ct.is_null() && found_expected_ct == 0 {
                                let mut msg = [0 as c_char; 512];
                                BIO_snprintf(
                                    msg.as_mut_ptr(),
                                    msg.len(),
                                    c"expected=%s".as_ptr(),
                                    ctx.expected_ct,
                                );
                                raise_site_data(&HC_906, msg.as_ptr());
                                return 0;
                            }
                            if ctx.state == OHS_REDIRECT {
                                /* http status code indicated redirect but there was no Location */
                                raise_site(&HC_912);
                                return 0;
                            }

                            if ctx.expect_asn1 == 0 {
                                ctx.state = OHS_STREAM;
                                return 1;
                            }
                            ctx.state = OHS_ASN1_HEADER;
                            break 'next_line;
                        }
                        /* fall through to OHS_ASN1_HEADER */
                    }

                    OHS_ASN1_HEADER => {
                        /*
                         * Now reading ASN1 header: can read at least 2 bytes which is enough for
                         * an ASN1 SEQUENCE header and either the length field or its own length.
                         */
                        let mut p: *mut c_uchar = ptr::null_mut();
                        let n = bio_get_mem_data(mem, &mut p);
                        if n < 2 {
                            continue 'next_io;
                        }

                        /* Check it is an ASN1 SEQUENCE */
                        let first = *p;
                        p = p.add(1);
                        if first != (V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED) as c_uchar {
                            raise_site(&HC_941);
                            return 0;
                        }

                        /* Check out length field */
                        if (*p & 0x80) != 0 {
                            /*
                             * If MSB set on initial length octet we can now always read 6 octets:
                             * make sure we have them.
                             */
                            if n < 6 {
                                continue 'next_io;
                            }
                            let l = (*p & 0x7f) as c_int;
                            /* Not NDEF or excessive length */
                            if l == 0 || l > 4 {
                                raise_site(&HC_956);
                                return 0;
                            }
                            p = p.add(1);
                            resp_len = 0;
                            for _ in 0..l {
                                resp_len <<= 8;
                                resp_len |= *p as usize;
                                p = p.add(1);
                            }
                            resp_len += l as usize + 2;
                        } else {
                            resp_len = (*p as usize) + 2;
                        }
                        if check_set_resp_len(c"ASN.1 DER content".as_ptr(), ctx, resp_len) == 0 {
                            return 0;
                        }
                        ctx.state = OHS_ASN1_CONTENT;
                        /* fall through */
                    }

                    OHS_ASN1_CONTENT => {
                        let n = bio_get_mem_data(mem, ptr::null_mut());
                        if n < 0 || (n as usize) < ctx.resp_len {
                            continue 'next_io;
                        }
                        ctx.state = OHS_ASN1_DONE;
                        return 1;
                    }

                    _ => return 0,
                }
            }
        }
    }
}

/// `int OSSL_HTTP_REQ_CTX_nbio_d2i(OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval,
/// const ASN1_ITEM *it)` — `crypto/http/http_client.c:989-1000`.
///
/// # Safety
/// As [`OSSL_HTTP_REQ_CTX_nbio`]; `pval` must be writable for one pointer, and `it` a live item.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_nbio_d2i(
    rctx: *mut OsslHttpReqCtx,
    pval: *mut *mut c_void,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the whole body. `rctx` is the caller's per nbio's contract; `pval` is writable; `it`
    // is a live item, all per this function's contract.
    unsafe {
        *pval = ptr::null_mut();
        let rv = OSSL_HTTP_REQ_CTX_nbio(rctx);
        if rv != 1 {
            return rv;
        }
        let mut p: *mut c_uchar = ptr::null_mut();
        let len = bio_get_mem_data((*rctx).mem, &mut p);
        let mut cp: *const c_uchar = p;
        *pval = ASN1_item_d2i(ptr::null_mut(), &mut cp, len, it);
        c_int::from(!(*pval).is_null())
    }
}

/// `static const char *explict_or_default_port(const char *hostserv, const char *port,
/// int use_ssl)` — `crypto/http/http_client.c:1004-1016`.
///
/// # Safety
/// `hostserv` must be NUL-terminated; `port` must be NULL or NUL-terminated.
unsafe fn explict_or_default_port(
    hostserv: *const c_char,
    mut port: *const c_char,
    use_ssl: c_int,
) -> *const c_char {
    // SAFETY: the whole body. `hostserv` is NUL-terminated and `port` NULL or NUL-terminated.
    unsafe {
        if port.is_null() {
            let mut service: *mut c_char = ptr::null_mut();
            if BIO_parse_hostserv(hostserv, ptr::null_mut(), &mut service, BIO_PARSE_PRIO_HOST) == 0
            {
                return ptr::null();
            }
            if service.is_null() {
                /* implicit port */
                port = if use_ssl != 0 {
                    c"443".as_ptr()
                } else {
                    c"80".as_ptr()
                };
            }
            CRYPTO_free(service.cast(), FILE.as_ptr(), 1013);
        } /* otherwise take the explicitly given port */
        port
    }
}

/// `static BIO *http_new_bio(const char *server, const char *server_port, int use_ssl,
/// const char *proxy, const char *proxy_port)` — `crypto/http/http_client.c:1019-1047`.
///
/// # Safety
/// `server` must be non-NULL and NUL-terminated; the other three must each be NULL or
/// NUL-terminated.
unsafe fn http_new_bio(
    server: *const c_char,
    server_port: *const c_char,
    use_ssl: c_int,
    proxy: *const c_char,
    proxy_port: *const c_char,
) -> *mut Bio {
    // SAFETY: the whole body. `server` is NUL-terminated and non-NULL; the rest NULL or
    // NUL-terminated, per the contract.
    unsafe {
        let mut host = server;
        let mut port = server_port;

        if ossl_assert(!server.is_null()) == 0 {
            return ptr::null_mut();
        }

        if !proxy.is_null() {
            host = proxy;
            port = proxy_port;
        }

        port = explict_or_default_port(host, port, use_ssl);

        let cbio = BIO_new_connect(host);
        if cbio.is_null() {
            return cbio;
        }
        if !port.is_null() {
            let _ = bio_set_conn_port(cbio, port);
        }
        cbio
    }
}

/// `BIO *OSSL_HTTP_REQ_CTX_exchange(OSSL_HTTP_REQ_CTX *rctx)` —
/// `crypto/http/http_client.c:1051-1080`.
///
/// # Safety
/// As [`OSSL_HTTP_REQ_CTX_nbio`].
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_REQ_CTX_exchange(rctx: *mut OsslHttpReqCtx) -> *mut Bio {
    // SAFETY: the whole body. `rctx` is NULL or live per the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_1056);
            return ptr::null_mut();
        }

        let mut rv;
        loop {
            rv = OSSL_HTTP_REQ_CTX_nbio(rctx);
            if rv != -1 {
                break;
            }
            /* BIO_should_retry was true; will not actually wait if rctx->max_time == 0 */
            if BIO_wait((*rctx).rbio, (*rctx).max_time, 100) <= 0 {
                return ptr::null_mut();
            }
        }

        if rv == 0 {
            if (*rctx).redirection_url.is_null() {
                /* an error occurred */
                if (*rctx).len_to_send > 0 {
                    raise_site(&HC_1073);
                } else {
                    raise_site(&HC_1075);
                }
            }
            return ptr::null_mut();
        }
        if (*rctx).state == OHS_STREAM {
            (*rctx).rbio
        } else {
            (*rctx).mem
        }
    }
}

/// `int OSSL_HTTP_is_alive(const OSSL_HTTP_REQ_CTX *rctx)` — `crypto/http/http_client.c:1082-1085`.
///
/// # Safety
/// `rctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_is_alive(rctx: *const OsslHttpReqCtx) -> c_int {
    // SAFETY: `rctx` is NULL or live per the contract.
    unsafe { c_int::from(!rctx.is_null() && (*rctx).keep_alive != 0) }
}

/// `OSSL_HTTP_REQ_CTX *OSSL_HTTP_open(const char *server, const char *port, const char *proxy,
/// const char *no_proxy, int use_ssl, BIO *bio, BIO *rbio, OSSL_HTTP_bio_cb_t bio_update_fn,
/// void *arg, int buf_size, int overall_timeout)` — `crypto/http/http_client.c:1090-1174`.
///
/// # Safety
/// Every string must be NULL or NUL-terminated; `bio`/`rbio` NULL or live (a `bio` handed in is
/// kept borrowed by the returned context); `bio_update_fn` must be callable with the states the
/// authority calls it in.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_open(
    server: *const c_char,
    port: *const c_char,
    proxy: *const c_char,
    no_proxy: *const c_char,
    use_ssl: c_int,
    bio: *mut Bio,
    rbio: *mut Bio,
    bio_update_fn: OSSL_HTTP_bio_cb_t,
    arg: *mut c_void,
    buf_size: c_int,
    overall_timeout: c_int,
) -> *mut OsslHttpReqCtx {
    // SAFETY: the whole body. Every string is NULL or NUL-terminated and every BIO NULL or live,
    // per the contract.
    unsafe {
        let mut port = port;
        let mut cbio: *mut Bio;

        if use_ssl != 0 && bio_update_fn.is_none() {
            raise_site(&HC_1100);
            return ptr::null_mut();
        }
        if !rbio.is_null() && (bio.is_null() || bio_update_fn.is_some()) {
            raise_site(&HC_1104);
            return ptr::null_mut();
        }

        if !bio.is_null() {
            cbio = bio;
            if !proxy.is_null() || !no_proxy.is_null() {
                raise_site(&HC_1111);
                return ptr::null_mut();
            }
        } else {
            let mut proxy_host: *mut c_char = ptr::null_mut();
            let mut proxy_port: *mut c_char = ptr::null_mut();

            if server.is_null() {
                raise_site(&HC_1119);
                return ptr::null_mut();
            }
            if !port.is_null() && *port == 0 {
                port = ptr::null();
            }
            let proxy = super::http_lib::OSSL_HTTP_adapt_proxy(proxy, no_proxy, server, use_ssl);
            if !proxy.is_null()
                && super::http_lib::OSSL_HTTP_parse_url(
                    proxy,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut proxy_host,
                    &mut proxy_port,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ) == 0
            {
                return ptr::null_mut();
            }
            cbio = http_new_bio(server, port, use_ssl, proxy_host, proxy_port);
            CRYPTO_free(proxy_host.cast(), FILE.as_ptr(), 1131);
            CRYPTO_free(proxy_port.cast(), FILE.as_ptr(), 1132);
            if cbio.is_null() {
                return ptr::null_mut();
            }
        }

        ERR_set_mark(); /* prepare removing any spurious libssl errors */
        if rbio.is_null() && BIO_do_connect_retry(cbio, overall_timeout, -1) <= 0 {
            if bio.is_null() {
                /* cbio was not provided by caller */
                BIO_free_all(cbio);
            }
            ERR_clear_last_mark();
            return ptr::null_mut();
        }
        /* now overall_timeout is guaranteed to be >= 0 */

        /* adapt in order to fix callback design flaw, see #17088 */
        if let Some(f) = bio_update_fn {
            let orig_bio = cbio;
            cbio = f(cbio, arg, 1 /* connect */, c_int::from(use_ssl != 0));
            if cbio.is_null() {
                if bio.is_null() {
                    /* cbio was not provided by caller */
                    BIO_free_all(orig_bio);
                }
                ERR_clear_last_mark();
                return ptr::null_mut();
            }
        }

        let rctx = http_req_ctx_new(
            c_int::from(bio.is_null()),
            cbio,
            if !rbio.is_null() { rbio } else { cbio },
            bio_update_fn,
            arg,
            use_ssl,
            proxy,
            server,
            port,
            buf_size,
            overall_timeout,
        );

        if !rctx.is_null() {
            /* remove any spurious error queue entries by ssl_add_cert_chain() */
            ERR_pop_to_mark();
        } else {
            ERR_clear_last_mark();
        }
        rctx
    }
}

/// `int OSSL_HTTP_set1_request(OSSL_HTTP_REQ_CTX *rctx, const char *path,
/// const STACK_OF(CONF_VALUE) *headers, const char *content_type, BIO *req,
/// const char *expected_content_type, int expect_asn1, size_t max_resp_len, int timeout,
/// int keep_alive)` — `crypto/http/http_client.c:1176-1203`.
///
/// # Safety
/// `rctx` must be NULL or live; every string NULL or NUL-terminated; `headers` NULL or a live
/// `STACK_OF(CONF_VALUE)`; `req` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_set1_request(
    rctx: *mut OsslHttpReqCtx,
    path: *const c_char,
    headers: *const crate::runtime::stack::OpenSslStack,
    content_type: *const c_char,
    req: *mut Bio,
    expected_content_type: *const c_char,
    expect_asn1: c_int,
    max_resp_len: usize,
    timeout: c_int,
    keep_alive: c_int,
) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live and every argument follows its own contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_1185);
            return 0;
        }
        let use_http_proxy = !(*rctx).proxy.is_null() && (*rctx).use_ssl == 0;
        if use_http_proxy && (*rctx).server.is_null() {
            raise_site(&HC_1190);
            return 0;
        }
        (*rctx).max_resp_len = max_resp_len; /* allows for 0: indefinite */

        c_int::from(
            OSSL_HTTP_REQ_CTX_set_request_line(
                rctx,
                c_int::from(!req.is_null()),
                if use_http_proxy {
                    (*rctx).server
                } else {
                    ptr::null()
                },
                (*rctx).port,
                path,
            ) != 0
                && add1_headers(rctx, headers, (*rctx).server) != 0
                && OSSL_HTTP_REQ_CTX_set_expected(
                    rctx,
                    expected_content_type,
                    expect_asn1,
                    timeout,
                    keep_alive,
                ) != 0
                && set1_content(rctx, content_type, req) != 0,
        )
    }
}

/// `BIO *OSSL_HTTP_exchange(OSSL_HTTP_REQ_CTX *rctx, char **redirection_url)` —
/// `crypto/http/http_client.c:1210-1265`.
///
/// # Safety
/// `rctx` must be NULL or live; `redirection_url` must be NULL or writable for one `char *`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_exchange(
    rctx: *mut OsslHttpReqCtx,
    redirection_url: *mut *mut c_char,
) -> *mut Bio {
    // SAFETY: the whole body. `rctx` is NULL or live and `redirection_url` NULL or writable, per
    // the contract.
    unsafe {
        if rctx.is_null() {
            raise_site(&HC_1215);
            return ptr::null_mut();
        }

        if !redirection_url.is_null() {
            *redirection_url = ptr::null_mut(); /* do this beforehand to prevent dbl free */
        }

        let mut resp = OSSL_HTTP_REQ_CTX_exchange(rctx);
        if resp.is_null() {
            if !(*rctx).redirection_url.is_null() {
                if redirection_url.is_null() {
                    raise_site(&HC_1226);
                } else {
                    /* may be NULL if out of memory: */
                    *redirection_url = CRYPTO_strdup((*rctx).redirection_url, FILE.as_ptr(), 1229);
                }
            } else {
                let mut buf = [0 as c_char; 200];
                let err = ERR_peek_error();
                let lib = err_get_lib(err);
                let reason = err_get_reason(err);

                if lib == ERR_LIB_SSL
                    || lib == ERR_LIB_HTTP
                    || (lib == ERR_LIB_BIO && reason == BIO_R_CONNECT_TIMEOUT)
                    || (lib == ERR_LIB_BIO && reason == BIO_R_CONNECT_ERROR)
                    || (lib == ERR_LIB_CMP && reason == CMP_R_POTENTIALLY_INVALID_CERTIFICATE)
                {
                    if !(*rctx).server.is_null() && *(*rctx).server != 0 {
                        BIO_snprintf(
                            buf.as_mut_ptr(),
                            buf.len(),
                            c"server=http%s://%s%s%s".as_ptr(),
                            if (*rctx).use_ssl != 0 {
                                c"s".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                            (*rctx).server,
                            if !(*rctx).port.is_null() {
                                c":".as_ptr()
                            } else {
                                c"".as_ptr()
                            },
                            if !(*rctx).port.is_null() {
                                (*rctx).port
                            } else {
                                c"".as_ptr()
                            },
                        );
                        ERR_add_error_data(1, buf.as_ptr());
                    }
                    if !(*rctx).proxy.is_null() {
                        ERR_add_error_data(2, c" proxy=".as_ptr(), (*rctx).proxy);
                    }
                    if err == 0 {
                        BIO_snprintf(
                            buf.as_mut_ptr(),
                            buf.len(),
                            c" peer has disconnected%s".as_ptr(),
                            if (*rctx).use_ssl != 0 {
                                c" violating the protocol".as_ptr()
                            } else {
                                c", likely because it requires the use of TLS".as_ptr()
                            },
                        );
                        ERR_add_error_data(1, buf.as_ptr());
                    }
                }
            }
        }

        if !resp.is_null() && BIO_up_ref(resp) == 0 {
            resp = ptr::null_mut();
        }
        resp
    }
}

/// `static int redirection_ok(int n_redir, const char *old_url, const char *new_url)` —
/// `crypto/http/http_client.c:1267-1280`.
///
/// # Safety
/// `old_url` and `new_url` must be NUL-terminated.
unsafe fn redirection_ok(n_redir: c_int, old_url: *const c_char, new_url: *const c_char) -> c_int {
    // SAFETY: both strings are NUL-terminated per the contract.
    unsafe {
        if n_redir >= HTTP_VERSION_MAX_REDIRECTIONS {
            raise_site(&HC_1270);
            return 0;
        }
        if *new_url == b'/' as c_char {
            /* redirection to same server => same protocol */
            return 1;
        }
        if has_prefix(old_url, OSSL_HTTPS_NAME_COLON) && !has_prefix(new_url, OSSL_HTTPS_NAME_COLON)
        {
            raise_site(&HC_1276);
            return 0;
        }
        1
    }
}

/// `BIO *OSSL_HTTP_get(const char *url, const char *proxy, const char *no_proxy, BIO *bio,
/// BIO *rbio, OSSL_HTTP_bio_cb_t bio_update_fn, void *arg, int buf_size,
/// const STACK_OF(CONF_VALUE) *headers, const char *expected_ct, int expect_asn1,
/// size_t max_resp_len, int timeout)` — `crypto/http/http_client.c:1283-1369`.
///
/// # Safety
/// Every string NULL or NUL-terminated; `bio`/`rbio` NULL or live; `headers` NULL or a live
/// `STACK_OF(CONF_VALUE)`; `bio_update_fn` callable as the authority calls it.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_get(
    url: *const c_char,
    proxy: *const c_char,
    no_proxy: *const c_char,
    bio: *mut Bio,
    rbio: *mut Bio,
    bio_update_fn: OSSL_HTTP_bio_cb_t,
    arg: *mut c_void,
    buf_size: c_int,
    headers: *const crate::runtime::stack::OpenSslStack,
    expected_ct: *const c_char,
    expect_asn1: c_int,
    max_resp_len: usize,
    timeout: c_int,
) -> *mut Bio {
    // SAFETY: the whole body. Every pointer follows its own contract.
    unsafe {
        let mut n_redirs = 0;
        let mut use_ssl = 0;
        let mut host: *mut c_char = ptr::null_mut();
        let mut port: *mut c_char = ptr::null_mut();
        let mut path: *mut c_char = ptr::null_mut();
        let mut resp: *mut Bio = ptr::null_mut();
        let mut timeout = timeout;
        let max_time = if timeout > 0 {
            time(ptr::null_mut()) + timeout as c_long
        } else {
            0
        };

        if url.is_null() {
            raise_site(&HC_1300);
            return ptr::null_mut();
        }
        let mut current_url = CRYPTO_strdup(url, FILE.as_ptr(), 1303);
        if current_url.is_null() {
            return ptr::null_mut();
        }

        'outer: loop {
            if super::http_lib::OSSL_HTTP_parse_url(
                current_url,
                &mut use_ssl,
                ptr::null_mut(),
                &mut host,
                &mut port,
                ptr::null_mut(),
                &mut path,
                ptr::null_mut(),
                ptr::null_mut(),
            ) == 0
            {
                break;
            }

            let mut rctx = OSSL_HTTP_open(
                host,
                port,
                proxy,
                no_proxy,
                use_ssl,
                bio,
                rbio,
                bio_update_fn,
                arg,
                buf_size,
                timeout,
            );

            'new_rpath: loop {
                let mut redirection_url: *mut c_char = ptr::null_mut();
                if !rctx.is_null() {
                    if OSSL_HTTP_set1_request(
                        rctx,
                        path,
                        headers,
                        ptr::null(),     /* content_type */
                        ptr::null_mut(), /* req */
                        expected_ct,
                        expect_asn1,
                        max_resp_len,
                        -1, /* use same max time (timeout) */
                        0,  /* no keep_alive */
                    ) == 0
                    {
                        OSSL_HTTP_REQ_CTX_free(rctx);
                        rctx = ptr::null_mut();
                    } else {
                        resp = OSSL_HTTP_exchange(rctx, &mut redirection_url);
                    }
                }
                CRYPTO_free(path.cast(), FILE.as_ptr(), 1332);
                if resp.is_null() && !redirection_url.is_null() {
                    n_redirs += 1;
                    if redirection_ok(n_redirs, current_url, redirection_url) != 0
                        && may_still_retry(max_time, &mut timeout) != 0
                    {
                        bio_reset(bio);
                        CRYPTO_free(current_url.cast(), FILE.as_ptr(), 1337);
                        current_url = redirection_url;
                        if *redirection_url == b'/' as c_char {
                            /* redirection to same server */
                            path = CRYPTO_strdup(redirection_url, FILE.as_ptr(), 1340);
                            if path.is_null() {
                                CRYPTO_free(host.cast(), FILE.as_ptr(), 1342);
                                CRYPTO_free(port.cast(), FILE.as_ptr(), 1343);
                                let _ = OSSL_HTTP_close(rctx, 1);
                                BIO_free(resp);
                                CRYPTO_free(current_url.cast(), FILE.as_ptr(), 1346);
                                return ptr::null_mut();
                            }
                            continue 'new_rpath;
                        }
                        CRYPTO_free(host.cast(), FILE.as_ptr(), 1351);
                        CRYPTO_free(port.cast(), FILE.as_ptr(), 1352);
                        let _ = OSSL_HTTP_close(rctx, 1);
                        continue 'outer;
                    }
                    /* if redirection not allowed, ignore it */
                    CRYPTO_free(redirection_url.cast(), FILE.as_ptr(), 1357);
                }
                CRYPTO_free(host.cast(), FILE.as_ptr(), 1359);
                CRYPTO_free(port.cast(), FILE.as_ptr(), 1360);
                if OSSL_HTTP_close(rctx, c_int::from(!resp.is_null())) == 0 {
                    BIO_free(resp);
                    resp = ptr::null_mut();
                }
                break 'outer;
            }
        }
        CRYPTO_free(current_url.cast(), FILE.as_ptr(), 1367);
        resp
    }
}

/// `BIO *OSSL_HTTP_transfer(OSSL_HTTP_REQ_CTX **prctx, const char *server, const char *port,
/// const char *path, int use_ssl, const char *proxy, const char *no_proxy, BIO *bio, BIO *rbio,
/// OSSL_HTTP_bio_cb_t bio_update_fn, void *arg, int buf_size,
/// const STACK_OF(CONF_VALUE) *headers, const char *content_type, BIO *req,
/// const char *expected_ct, int expect_asn1, size_t max_resp_len, int timeout,
/// int keep_alive)` — `crypto/http/http_client.c:1372-1408`.
///
/// # Safety
/// Every pointer follows the contract of [`OSSL_HTTP_open`]/[`OSSL_HTTP_set1_request`];
/// `prctx` must be NULL or writable for one context pointer.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_transfer(
    prctx: *mut *mut OsslHttpReqCtx,
    server: *const c_char,
    port: *const c_char,
    path: *const c_char,
    use_ssl: c_int,
    proxy: *const c_char,
    no_proxy: *const c_char,
    bio: *mut Bio,
    rbio: *mut Bio,
    bio_update_fn: OSSL_HTTP_bio_cb_t,
    arg: *mut c_void,
    buf_size: c_int,
    headers: *const crate::runtime::stack::OpenSslStack,
    content_type: *const c_char,
    req: *mut Bio,
    expected_ct: *const c_char,
    expect_asn1: c_int,
    max_resp_len: usize,
    timeout: c_int,
    keep_alive: c_int,
) -> *mut Bio {
    // SAFETY: the whole body. Every pointer follows the contract its callee documents.
    unsafe {
        let mut rctx = if prctx.is_null() {
            ptr::null_mut()
        } else {
            *prctx
        };
        let mut timeout = timeout;
        let mut resp: *mut Bio = ptr::null_mut();

        if rctx.is_null() {
            rctx = OSSL_HTTP_open(
                server,
                port,
                proxy,
                no_proxy,
                use_ssl,
                bio,
                rbio,
                bio_update_fn,
                arg,
                buf_size,
                timeout,
            );
            timeout = -1; /* Already set during opening the connection */
        }
        if !rctx.is_null() {
            if OSSL_HTTP_set1_request(
                rctx,
                path,
                headers,
                content_type,
                req,
                expected_ct,
                expect_asn1,
                max_resp_len,
                timeout,
                keep_alive,
            ) != 0
            {
                resp = OSSL_HTTP_exchange(rctx, ptr::null_mut());
            }
            if resp.is_null() || OSSL_HTTP_is_alive(rctx) == 0 {
                if OSSL_HTTP_close(rctx, c_int::from(!resp.is_null())) == 0 {
                    BIO_free(resp);
                    resp = ptr::null_mut();
                }
                rctx = ptr::null_mut();
            }
        }
        if !prctx.is_null() {
            *prctx = rctx;
        }
        resp
    }
}

/// `int OSSL_HTTP_close(OSSL_HTTP_REQ_CTX *rctx, int ok)` — `crypto/http/http_client.c:1410-1425`.
///
/// # Safety
/// `rctx` must be NULL or a live context this crate allocated; `upd_fn` (when set) must be
/// callable in the disconnect state.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_close(rctx: *mut OsslHttpReqCtx, ok: c_int) -> c_int {
    // SAFETY: the whole body. `rctx` is NULL or live per the contract; the callback is the one the
    // context stored.
    unsafe {
        let mut ret = 1;

        /* callback can be used to finish TLS session and free its BIO */
        if !rctx.is_null() {
            if let Some(f) = (*rctx).upd_fn {
                let wbio = f((*rctx).wbio, (*rctx).upd_arg, 0 /* disconnect */, ok);
                ret = c_int::from(!wbio.is_null());
                if ret != 0 {
                    (*rctx).wbio = wbio;
                }
            }
        }
        OSSL_HTTP_REQ_CTX_free(rctx);
        ret
    }
}

/// `static char *base64encode(const void *buf, size_t len)` — `crypto/http/http_client.c:1428-1451`.
///
/// # Safety
/// `buf` must be readable for `len` bytes.
unsafe fn base64encode(buf: *const c_void, len: usize) -> *mut c_char {
    // SAFETY: the whole body. `buf` is readable for `len` bytes per the contract.
    unsafe {
        if len > c_int::MAX as usize {
            return ptr::null_mut();
        }
        /* Calculate size of encoded data */
        let mut outl = len / 3;
        if !len.is_multiple_of(3) {
            outl += 1;
        }
        outl <<= 2;
        let out = CRYPTO_malloc(outl + 1, FILE.as_ptr(), 1441).cast::<c_char>();
        if out.is_null() {
            return ptr::null_mut();
        }

        let i = EVP_EncodeBlock(out.cast::<c_uchar>(), buf.cast::<c_uchar>(), len as c_int);
        if !(0 <= i && (i as usize) <= outl) {
            CRYPTO_free(out.cast(), FILE.as_ptr(), 1447);
            return ptr::null_mut();
        }
        out
    }
}

/// `int OSSL_HTTP_proxy_connect(BIO *bio, const char *server, const char *port,
/// const char *proxyuser, const char *proxypass, int timeout, BIO *bio_err, const char *prog)` —
/// `crypto/http/http_client.c:1458-1610`.
///
/// # Safety
/// `bio` may be NULL or a live BIO; `server` must be NULL or NUL-terminated; `port`, `proxyuser`,
/// `proxypass` and `prog` must each be NULL or NUL-terminated; `bio_err` NULL or a live BIO.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_proxy_connect(
    bio: *mut Bio,
    server: *const c_char,
    port: *const c_char,
    proxyuser: *const c_char,
    proxypass: *const c_char,
    timeout: c_int,
    bio_err: *mut Bio,
    prog: *const c_char,
) -> c_int {
    // SAFETY: the whole body. Every pointer follows its own contract, and the CONNECT request is
    // written through the caller's `bio`.
    unsafe {
        let mut mbuf: *mut c_char = ptr::null_mut();
        let mut read_len: c_int;
        let mut ret = 0;
        let mut fbio: *mut Bio = ptr::null_mut();
        let max_time = if timeout > 0 {
            time(ptr::null_mut()) + timeout as c_long
        } else {
            0
        };
        let mut port = port;

        if bio.is_null() || server.is_null() || (!bio_err.is_null() && prog.is_null()) {
            raise_site(&HC_1474);
            return finish_proxy_connect(fbio, mbuf, ret);
        }
        if port.is_null() || *port == 0 {
            port = c"443".as_ptr();
        }
        if no_crlf(c"server".as_ptr(), server) == 0 || no_crlf(c"port".as_ptr(), port) == 0 {
            return finish_proxy_connect(fbio, mbuf, ret);
        }

        mbuf = CRYPTO_malloc(BUF_SIZE, FILE.as_ptr(), 1482).cast::<c_char>();
        fbio = BIO_new(BIO_f_buffer());
        if mbuf.is_null() || fbio.is_null() {
            BIO_printf(
                bio_err, /* may be NULL */
                c"%s: out of memory".as_ptr(),
                prog,
            );
            return finish_proxy_connect(fbio, mbuf, ret);
        }
        BIO_push(fbio, bio);

        /* Add square brackets around a naked IPv6 address */
        if *server != b'[' as c_char && !strchr(server, b':' as c_int).is_null() {
            BIO_printf(
                fbio,
                c"CONNECT [%s]:%s %s\r\n".as_ptr(),
                server,
                port,
                HTTP_1_0.as_ptr(),
            );
        } else {
            BIO_printf(
                fbio,
                c"CONNECT %s:%s %s\r\n".as_ptr(),
                server,
                port,
                HTTP_1_0.as_ptr(),
            );
        }

        /*
         * Workaround for broken proxies which would otherwise close the connection when entering
         * tunnel mode (e.g., Squid 2.6).
         */
        BIO_printf(fbio, c"Proxy-Connection: Keep-Alive\r\n".as_ptr());

        /* Support for basic (base64) proxy authentication */
        if !proxyuser.is_null() {
            let mut len = str_len(proxyuser) + 1;
            let mut proxyauthenc: *mut c_char = ptr::null_mut();

            if !proxypass.is_null() {
                len += str_len(proxypass);
            }
            let proxyauth = CRYPTO_malloc(len + 1, FILE.as_ptr(), 1508).cast::<c_char>();
            if proxyauth.is_null() {
                return finish_proxy_connect(fbio, mbuf, ret);
            }
            if BIO_snprintf(
                proxyauth,
                len + 1,
                c"%s:%s".as_ptr(),
                proxyuser,
                if !proxypass.is_null() {
                    proxypass
                } else {
                    c"".as_ptr()
                },
            ) == len as c_int
            {
                proxyauthenc = base64encode(proxyauth.cast(), len);
                if !proxyauthenc.is_null() {
                    BIO_printf(
                        fbio,
                        c"Proxy-Authorization: Basic %s\r\n".as_ptr(),
                        proxyauthenc,
                    );
                    CRYPTO_clear_free(
                        proxyauthenc.cast(),
                        str_len(proxyauthenc),
                        FILE.as_ptr(),
                        1518,
                    );
                }
            }
            CRYPTO_clear_free(proxyauth.cast(), len, FILE.as_ptr(), 1521);
            if proxyauthenc.is_null() {
                return finish_proxy_connect(fbio, mbuf, ret);
            }
        }

        /* Terminate the HTTP CONNECT request */
        BIO_printf(fbio, c"\r\n".as_ptr());

        loop {
            if bio_flush(fbio) != 0 {
                break;
            }
            /* potentially needs to be retried if BIO is non-blocking */
            if bio_should_retry(fbio) == 0 {
                break;
            }
        }

        loop {
            /* will not actually wait if timeout == 0 */
            let rv = BIO_wait(fbio, max_time, 100 /* milliseconds */);
            if rv <= 0 {
                BIO_printf(
                    bio_err,
                    c"%s: HTTP CONNECT %s\n".as_ptr(),
                    prog,
                    if rv == 0 {
                        c"timed out".as_ptr()
                    } else {
                        c"failed waiting for data".as_ptr()
                    },
                );
                return finish_proxy_connect(fbio, mbuf, ret);
            }

            /*
             * The first line is the HTTP response. According to RFC 7230, it is formatted exactly
             * like this: HTTP/d.d ddd reason text\r\n
             */
            read_len = BIO_gets(fbio, mbuf, BUF_SIZE as c_int);
            /* the BIO may not block, so we must wait for the 1st line to come in */
            if read_len < HTTP_LINE1_MINLEN {
                continue;
            }

            /* Check for HTTP/1.x */
            let mut mbufp = mbuf;
            if !has_prefix(mbufp, HTTP_PREFIX) {
                raise_site(&HC_1559);
                BIO_printf(
                    bio_err,
                    c"%s: HTTP CONNECT failed, non-HTTP response\n".as_ptr(),
                    prog,
                );
                /* Wrong protocol, not even HTTP, so stop reading headers */
                return finish_proxy_connect(fbio, mbuf, ret);
            }
            mbufp = mbufp.add(HTTP_PREFIX.len());
            if !has_prefix(mbufp, HTTP_VERSION_PATT) {
                raise_site(&HC_1566);
                BIO_printf(
                    bio_err,
                    c"%s: HTTP CONNECT failed, bad HTTP version %.*s\n".as_ptr(),
                    prog,
                    HTTP_VERSION_STR_LEN as c_int,
                    mbufp,
                );
                return finish_proxy_connect(fbio, mbuf, ret);
            }
            mbufp = mbufp.add(HTTP_VERSION_STR_LEN);

            /* RFC 7231 4.3.6: any 2xx status code is valid */
            if !has_prefix(mbufp, b" 2") {
                if ossl_isspace(*mbufp as c_int) {
                    mbufp = mbufp.add(1);
                }
                /* chop any trailing whitespace */
                while read_len > 0 && ossl_isspace(*mbuf.add((read_len - 1) as usize) as c_int) {
                    read_len -= 1;
                }
                *mbuf.add(read_len as usize) = 0;
                let mut msg = [0 as c_char; 512];
                BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"reason=%s".as_ptr(), mbufp);
                raise_site_data(&HC_1582, msg.as_ptr());
                BIO_printf(
                    bio_err,
                    c"%s: HTTP CONNECT failed, reason=%s\n".as_ptr(),
                    prog,
                    mbufp,
                );
                return finish_proxy_connect(fbio, mbuf, ret);
            }
            ret = 1;
            break;
        }

        /* Read past all following headers */
        loop {
            read_len = BIO_gets(fbio, mbuf, BUF_SIZE as c_int);
            if read_len <= 2 {
                break;
            }
        }

        finish_proxy_connect(fbio, mbuf, ret)
    }
}

/// The `end:` tail shared by every exit of [`OSSL_HTTP_proxy_connect`] (`http_client.c:1601-1609`).
///
/// # Safety
/// `fbio` must be NULL or a live filter BIO this call pushed; `mbuf` NULL or this call's
/// allocation.
unsafe fn finish_proxy_connect(fbio: *mut Bio, mbuf: *mut c_char, ret: c_int) -> c_int {
    // SAFETY: both pointers are NULL or this call's own objects, per the contract.
    unsafe {
        if !fbio.is_null() {
            let _ = bio_flush(fbio);
            BIO_pop(fbio);
            BIO_free(fbio);
        }
        CRYPTO_free(mbuf.cast(), FILE.as_ptr(), 1607);
        ret
    }
}
