//! `crypto/http/http_lib.c` — the URL parser and the proxy selector.
//!
//! The authority unit is 318 lines. `OSSL_parse_url` (`:54-200`) sits *outside*
//! `#ifndef OPENSSL_NO_HTTP` — the file's own comment at `:35` says so, because the generic
//! RFC 3986 split is useful even without an HTTP client — and it is landed whole, together
//! with the four `static` helpers it calls: `init_pstring` (`:26-31`), `init_pint`
//! (`:33-38`), `copy_substring` (`:40-44`) and `free_pstring` (`:46-52`). The three names
//! below `:202`, which sit inside `#ifndef OPENSSL_NO_HTTP`, are landed by subphase 12.1:
//! `OSSL_HTTP_parse_url` (`:204-259`), the `static use_proxy` (`:262-298`) and
//! `OSSL_HTTP_adapt_proxy` (`:301-316`). **There is no remaining withheld name in this
//! unit.**
//!
//! Through Phases 10 and 11 this module's doc said the crate "deliberately does not fabricate
//! the network transport," and withheld the three names because their only callers were the
//! HTTP entry points the crate did not implement. That withholding is lifted here: the
//! transport those callers use is the BIO layer's — `crypto/bio/`'s connection BIOs
//! (`BIO_new_connect`, `BIO_s_connect`, `BIO_set_conn_port`; `src/runtime/bio/bss_conn.rs`,
//! the `RT-BIO-CONN` unit) — which is landed, so there is no unreachable surface left to
//! withhold. `OSSL_HTTP_parse_url` feeds `OSSL_HTTP_open` in [`super::http_client`].
//!
//! All four `OSSL_*`-family functions are authority exports declared in the public
//! `include/openssl/http.h` — `OSSL_parse_url` at `:36` (also outside `OPENSSL_NO_HTTP`),
//! `OSSL_HTTP_parse_url` at `:107` and `OSSL_HTTP_adapt_proxy` at `:110` — so each is
//! `#[no_mangle] pub unsafe extern "C" fn`. The five helpers (`init_pstring`, `init_pint`,
//! `copy_substring`, `free_pstring`, `use_proxy`) are `static` in the authority and carry no
//! `#[no_mangle]`.
//!
//! ## The raise sites
//!
//! `crypto/http/http_lib.c` is not in `gen_err_raise_sites.py`'s covered set, so its five
//! raise coordinates are **declared locally**, their reason values read from the authority's
//! `httperr.h`/`err.h.in` (not typed from memory), the way `src/x509/v3_asid.rs` declares its
//! own. `ERR_LIB_HTTP` is `err.h.in:126`; `ERR_R_PASSED_NULL_PARAMETER` is the `err.h.in:356`
//! composite `(258 | ERR_R_FATAL)`; the four `HTTP_R_*` reasons are the `httperr.h` rows read
//! below the helper. `use_proxy` and `OSSL_HTTP_adapt_proxy` raise nothing. `ErrSite::file`
//! carries the authority build record's `../../src/openssl-3.6.4/...` spelling, matching
//! `err_sites.rs`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{memchr, strchr, strcmp, strlen, strncmp};
use crate::runtime::ctype::{ossl_isalpha, ossl_isdigit, ossl_isspace};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_strndup};

// `strpbrk`, `strstr` and `strncpy` are not among `runtime::bio::sys`'s declarations, so they
// are declared here as the module's own C imports (the pattern `src/ml_dsa/sign.rs` and
// `src/engine/eng_ctrl.rs` use). `sscanf` is used only for the single `"%u"`/`"%d"`
// conversions.
extern "C" {
    /// `char *strpbrk(const char *s, const char *accept)`.
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char;
    /// `char *strstr(const char *haystack, const char *needle)`.
    fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
    /// `char *strncpy(char *dest, const char *src, size_t n)`.
    fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
    /// `int sscanf(const char *s, const char *format, ...)` — the C-variadic ABI.
    fn sscanf(s: *const c_char, format: *const c_char, ...) -> c_int;
}

/// `#define OSSL_URL_SCHEME_SUFFIX "://"` — `crypto/http/http_lib.c:24`.
const OSSL_URL_SCHEME_SUFFIX: &[u8] = b"://";

/// `#define OSSL_HTTP_NAME "http"` — `include/openssl/http.h:25`.
const OSSL_HTTP_NAME: &core::ffi::CStr = c"http";
/// `#define OSSL_HTTPS_NAME "https"` — `include/openssl/http.h:26`.
const OSSL_HTTPS_NAME: &core::ffi::CStr = c"https";
/// `#define OSSL_HTTP_PORT "80"` — `include/openssl/http.h:29`.
const OSSL_HTTP_PORT: &core::ffi::CStr = c"80";
/// `#define OSSL_HTTPS_PORT "443"` — `include/openssl/http.h:30`.
const OSSL_HTTPS_PORT: &core::ffi::CStr = c"443";
/// `#define OPENSSL_NO_PROXY "NO_PROXY"` — `include/openssl/http.h:31`.
const OPENSSL_NO_PROXY: &core::ffi::CStr = c"NO_PROXY";
/// `#define OPENSSL_HTTP_PROXY "HTTP_PROXY"` — `include/openssl/http.h:32`.
const OPENSSL_HTTP_PROXY: &core::ffi::CStr = c"HTTP_PROXY";
/// `#define OPENSSL_HTTPS_PROXY "HTTPS_PROXY"` — `include/openssl/http.h:33`.
const OPENSSL_HTTPS_PROXY: &core::ffi::CStr = c"HTTPS_PROXY";

/// `ERR_LIB_HTTP` — `include/openssl/err.h.in:126`.
const ERR_LIB_HTTP: c_int = 61;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `HTTP_R_ERROR_PARSING_URL` — `include/openssl/httperr.h:27`.
const HTTP_R_ERROR_PARSING_URL: c_int = 101;
/// `HTTP_R_INVALID_PORT_NUMBER` — `include/openssl/httperr.h:33`.
const HTTP_R_INVALID_PORT_NUMBER: c_int = 123;
/// `HTTP_R_INVALID_URL_PATH` — `include/openssl/httperr.h:34`.
const HTTP_R_INVALID_URL_PATH: c_int = 125;
/// `HTTP_R_INVALID_URL_SCHEME` — `include/openssl/httperr.h:35`.
const HTTP_R_INVALID_URL_SCHEME: c_int = 124;

/// `NI_MAXHOST` — glibc's `<netdb.h>`; `use_proxy`'s `char host[NI_MAXHOST]` at
/// `crypto/http/http_lib.c:266`. The same value and citation as `src/runtime/bio/addr.rs:74`.
const NI_MAXHOST: usize = 1025;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_strndup`/`OPENSSL_malloc`/`OPENSSL_free`
/// macro expansions — `crypto/http/http_lib.c`.
const FILE: &core::ffi::CStr = c"crypto/http/http_lib.c";

/// One `http_lib.c` raise coordinate, declared locally (see the module doc).
const fn http_lib_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/http/http_lib.c",
        line,
        func,
        lib: ERR_LIB_HTTP,
        reason,
        dynamic_reason: false,
    }
}

/// `OSSL_parse_url`'s NULL-`url` rejection at `http_lib.c:79`.
const HTTP_LIB_79: ErrSite = http_lib_site(79, c"OSSL_parse_url", ERR_R_PASSED_NULL_PARAMETER);
/// `OSSL_parse_url`'s invalid-port rejection at `http_lib.c:132`.
const HTTP_LIB_132: ErrSite = http_lib_site(132, c"OSSL_parse_url", HTTP_R_INVALID_PORT_NUMBER);
/// `OSSL_parse_url`'s invalid-path-opening rejection at `http_lib.c:143`.
const HTTP_LIB_143: ErrSite = http_lib_site(143, c"OSSL_parse_url", HTTP_R_INVALID_URL_PATH);
/// `OSSL_parse_url`'s `parse_err:` label raise at `http_lib.c:189`.
const HTTP_LIB_189: ErrSite = http_lib_site(189, c"OSSL_parse_url", HTTP_R_ERROR_PARSING_URL);
/// `OSSL_HTTP_parse_url`'s non-HTTP scheme rejection at `http_lib.c:224`.
const HTTP_LIB_224: ErrSite = http_lib_site(224, c"OSSL_HTTP_parse_url", HTTP_R_INVALID_URL_SCHEME);

// ---------------------------------------------------------------------------
// The four `static` helpers
// ---------------------------------------------------------------------------

/// `static void init_pstring(char **pstr)` — `crypto/http/http_lib.c:26-31`.
///
/// # Safety
///
/// `pstr` must be NULL or point at a writable `char *`.
unsafe fn init_pstring(pstr: *mut *mut c_char) {
    if !pstr.is_null() {
        // SAFETY: `pstr` is non-NULL and writable per the contract.
        unsafe { *pstr = ptr::null_mut() };
    }
}

/// `static void init_pint(int *pint)` — `crypto/http/http_lib.c:33-38`.
///
/// # Safety
///
/// `pint` must be NULL or point at a writable `int`.
unsafe fn init_pint(pint: *mut c_int) {
    if !pint.is_null() {
        // SAFETY: `pint` is non-NULL and writable per the contract.
        unsafe { *pint = 0 };
    }
}

/// `static int copy_substring(char **dest, const char *start, const char *end)` —
/// `crypto/http/http_lib.c:40-44`.
///
/// Answers true when `dest` is NULL or the `OPENSSL_strndup` succeeded, false on a failed
/// allocation. The copy always NUL-terminates, so a zero-length range yields `""`.
///
/// # Safety
///
/// `dest` must be NULL or writable; `start`/`end` must delimit a readable range with
/// `start <= end`.
unsafe fn copy_substring(
    dest: *mut *mut c_char,
    start: *const c_char,
    end: *const c_char,
) -> c_int {
    if dest.is_null() {
        return 1;
    }
    // SAFETY: `start <= end` per the contract, so the difference is the readable length.
    let len = unsafe { end.offset_from(start) } as usize;
    // SAFETY: `start` is readable for `len` bytes per the contract; `OPENSSL_strndup`'s
    // expansion is at `http_lib.c:43`.
    let p = unsafe { CRYPTO_strndup(start, len, FILE.as_ptr(), 43) };
    // SAFETY: `dest` is non-NULL and writable per the contract.
    unsafe { *dest = p };
    c_int::from(!p.is_null())
}

/// `static void free_pstring(char **pstr)` — `crypto/http/http_lib.c:46-52`.
///
/// # Safety
///
/// `pstr` must be NULL or point at a writable `char *` that is NULL or a
/// `CRYPTO_strndup`/`CRYPTO_malloc` result.
unsafe fn free_pstring(pstr: *mut *mut c_char) {
    if !pstr.is_null() {
        // SAFETY: `pstr` is writable; `*pstr` is NULL or an allocation to release.
        // `OPENSSL_free`'s expansion is at `http_lib.c:49`.
        unsafe { CRYPTO_free((*pstr).cast(), FILE.as_ptr(), 49) };
        // SAFETY: `pstr` is writable per the contract.
        unsafe { *pstr = ptr::null_mut() };
    }
}

/// `HAS_PREFIX(str, pre)` — `include/internal/common.h:59`:
/// `strncmp(str, pre "", sizeof(pre) - 1) == 0`. For the `"://"` suffix test below.
///
/// # Safety
///
/// `s` must be NUL-terminated, so `strncmp` stops at its terminator rather than reading past it.
unsafe fn has_prefix(s: *const c_char, pre: &[u8]) -> bool {
    // SAFETY: `s` is NUL-terminated per the contract; `pre` is a static byte slice.
    unsafe { strncmp(s, pre.as_ptr().cast::<c_char>(), pre.len()) == 0 }
}

// ---------------------------------------------------------------------------
// OSSL_parse_url
// ---------------------------------------------------------------------------

/// `int OSSL_parse_url(const char *url, char **pscheme, char **puser, char **phost,
/// char **pport, int *pport_num, char **ppath, char **pquery, char **pfrag)` —
/// `crypto/http/http_lib.c:54-200`.
///
/// Splits `url` into its RFC 3986 components. Every output pointer is optional (`NULL` means
/// "do not record this part"), and every non-NULL slot is set to `NULL` up front and filled
/// with a fresh allocation on success. Answers 1 on success, 0 on a NULL `url`, a bad port, a
/// bad path opening, or any failed allocation — freeing whatever had already been allocated.
///
/// # Safety
///
/// `url` must be NULL or a NUL-terminated string; each other pointer must be NULL or point at
/// a writable slot of the type its C parameter has; `pport_num` must be NULL or point at a
/// writable `int`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_parse_url(
    url: *const c_char,
    pscheme: *mut *mut c_char,
    puser: *mut *mut c_char,
    phost: *mut *mut c_char,
    pport: *mut *mut c_char,
    pport_num: *mut c_int,
    ppath: *mut *mut c_char,
    pquery: *mut *mut c_char,
    pfrag: *mut *mut c_char,
) -> c_int {
    // SAFETY: this block encloses the whole transcription. `url` is NULL or NUL-terminated and
    // every read stays within it (the terminator stops every scan); each output-slot pointer is
    // NULL or writable and is written only through its own non-NULL pointer; `pport_num` is NULL
    // or writable. Each arithmetic step's own invariant is stated where it is relied on.
    unsafe {
        init_pstring(pscheme);
        init_pstring(puser);
        init_pstring(phost);
        init_pstring(pport);
        init_pint(pport_num);
        init_pstring(ppath);
        init_pstring(pfrag);
        init_pstring(pquery);

        if url.is_null() {
            // The site is a compile-time constant whose pointers are static.
            raise_site(&HTTP_LIB_79);
            return 0;
        }

        // `goto parse_err` sets this so the `parse_err:` raise runs after the block, before the
        // frees; a plain `goto err` `break`s with it false. Keeping it a flag is what preserves
        // the authority's ordering when the invalid-path branch raises *two* errors in a row.
        let mut parse_err = false;

        'body: {
            let mut p: *const c_char = url;
            let scheme: *const c_char = url;
            let mut scheme_end: *const c_char = url;

            // Optional prefix "<scheme>://", per RFC 3986.
            if ossl_isalpha(c_int::from(*p)) {
                while *p != 0
                    && (ossl_isalpha(c_int::from(*p))
                        || ossl_isdigit(c_int::from(*p))
                        || !strchr(c"+-.".as_ptr(), c_int::from(*p)).is_null())
                {
                    p = p.add(1);
                }
                if has_prefix(p, OSSL_URL_SCHEME_SUFFIX) {
                    scheme_end = p;
                    p = p.add(OSSL_URL_SCHEME_SUFFIX.len());
                } else {
                    p = url;
                }
            }

            // Optional "userinfo@".
            let user: *const c_char = p;
            let mut user_end: *const c_char = p;
            let mut authority_end = strpbrk(p, c"/?#".as_ptr()).cast_const();
            if authority_end.is_null() {
                authority_end = p.add(strlen(p));
            }
            let at = memchr(
                p.cast(),
                c_int::from(b'@'),
                authority_end.offset_from(p) as usize,
            )
            .cast::<c_char>();
            let mut host: *const c_char = at;
            if !host.is_null() {
                user_end = host;
                host = host.add(1);
            } else {
                host = p;
            }

            // Parse the hostname/address as far as needed here.
            let mut host_end: *const c_char;
            if c_int::from(*host) == c_int::from(b'[') {
                // IPv6 literal, which may include ':'.
                host_end = memchr(
                    host.add(1).cast(),
                    c_int::from(b']'),
                    (authority_end.offset_from(host) - 1) as usize,
                )
                .cast::<c_char>()
                .cast_const();
                if host_end.is_null() {
                    parse_err = true;
                    break 'body;
                }
                host_end = host_end.add(1);
                p = host_end;
            } else {
                // Look for the start of an optional port, path, query, or fragment.
                host_end = strpbrk(host, c":/?#".as_ptr()).cast_const();
                if host_end.is_null() {
                    host_end = host.add(strlen(host));
                }
                p = host_end;
            }

            // Optional port specification starting with ':'.
            let mut port: *const c_char = c"0".as_ptr();
            if c_int::from(*p) == c_int::from(b':') {
                p = p.add(1);
                port = p;
            }
            // The remaining port spec handling is also done for the default value.
            let mut portnum: c_uint = 0;
            if sscanf(port, c"%u".as_ptr(), &mut portnum) <= 0 || portnum > 65535 {
                // The authority's `ERR_raise_data(..., "%s", port)` formats exactly `strlen(port)`
                // bytes, which `raise_site_data`'s `strlen`-sized copy reproduces.
                raise_site_data(&HTTP_LIB_132, port);
                break 'body;
            }
            let mut port_end: *const c_char = port;
            while c_int::from(*port_end) >= c_int::from(b'0')
                && c_int::from(*port_end) <= c_int::from(b'9')
            {
                port_end = port_end.add(1);
            }
            if port == p {
                // Port was given explicitly; skip past the digits.
                p = p.add(port_end.offset_from(port) as usize);
            }

            // Optional path starting with '/' or '?'; else the string must start with '#'.
            let path: *const c_char = p;
            let pc = c_int::from(*path);
            if pc != 0
                && pc != c_int::from(b'/')
                && pc != c_int::from(b'?')
                && pc != c_int::from(b'#')
            {
                raise_site(&HTTP_LIB_143);
                parse_err = true;
                break 'body;
            }
            let mut path_end = path.add(strlen(path));
            let mut query = path_end;
            let mut query_end = path_end;
            let mut frag = path_end;
            let frag_end = path_end;

            // Optional "?query".
            let mut tmp = strchr(p, c_int::from(b'?')).cast_const();
            if !tmp.is_null() {
                p = tmp;
                if !pquery.is_null() {
                    path_end = p;
                    query = p.add(1);
                }
            }

            // Optional "#fragment".
            tmp = strchr(p, c_int::from(b'#')).cast_const();
            if !tmp.is_null() {
                if query == path_end {
                    // We did not record a query component.
                    path_end = tmp;
                }
                query_end = tmp;
                frag = tmp.add(1);
            }

            if copy_substring(pscheme, scheme, scheme_end) == 0
                || copy_substring(phost, host, host_end) == 0
                || copy_substring(pport, port, port_end) == 0
                || copy_substring(puser, user, user_end) == 0
                || copy_substring(pquery, query, query_end) == 0
                || copy_substring(pfrag, frag, frag_end) == 0
            {
                break 'body;
            }
            if !pport_num.is_null() {
                *pport_num = portnum as c_int;
            }
            if c_int::from(*path) == c_int::from(b'/') {
                if copy_substring(ppath, path, path_end) == 0 {
                    break 'body;
                }
            } else if !ppath.is_null() {
                // Must prepend '/'.
                let diff = path_end.offset_from(path) as usize;
                let buflen = diff + 2;
                let alloc = CRYPTO_malloc(buflen, FILE.as_ptr(), 182).cast::<c_char>();
                *ppath = alloc;
                if alloc.is_null() {
                    break 'body;
                }
                BIO_snprintf(alloc, buflen, c"/%s".as_ptr(), path);
            }
            return 1;
        }

        if parse_err {
            raise_site(&HTTP_LIB_189);
        }

        free_pstring(pscheme);
        free_pstring(puser);
        free_pstring(phost);
        free_pstring(pport);
        free_pstring(ppath);
        free_pstring(pquery);
        free_pstring(pfrag);
        0
    }
}

/// `ossl_assert(x)` — `include/internal/common.h:52-53`, the admitted build's non-aborting form
/// (`NDEBUG`): a plain boolean-to-`int` conversion, not the `OPENSSL_die` form. The same local
/// helper `src/mac/ssl3_cbc.rs`, `src/x509/v3_asid.rs` and the rest of the crate carry.
#[inline]
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

// ---------------------------------------------------------------------------
// OSSL_HTTP_parse_url, use_proxy and OSSL_HTTP_adapt_proxy
// ---------------------------------------------------------------------------

/// `int OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost,
/// char **pport, int *pport_num, char **ppath, char **pquery, char **pfrag)` —
/// `crypto/http/http_lib.c:204-259`.
///
/// The scheme/port layer over [`OSSL_parse_url`]. It calls that splitter, accepts an optional
/// `http`/`https` scheme (setting `*pssl` for `https`), and substitutes the scheme's default
/// port (`80`/`443`) when the URL carried none. A scheme that is neither empty nor `http`/`https`
/// is rejected at `:224` with `HTTP_R_INVALID_URL_SCHEME`, and the `*pport` slot is NULLed up
/// front through `init_pstring` the way `OSSL_parse_url`'s own outputs are.
///
/// # Safety
///
/// `url` must be NULL or a NUL-terminated string; every other pointer must be NULL or point at
/// a writable slot of the type its C parameter has (`pssl`/`pport_num` at an `int`, the rest at a
/// `char *`).
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_parse_url(
    url: *const c_char,
    pssl: *mut c_int,
    puser: *mut *mut c_char,
    phost: *mut *mut c_char,
    pport: *mut *mut c_char,
    pport_num: *mut c_int,
    ppath: *mut *mut c_char,
    pquery: *mut *mut c_char,
    pfrag: *mut *mut c_char,
) -> c_int {
    // SAFETY: the whole transcription. `url` is NULL or NUL-terminated per the contract; every
    // output slot is NULL or writable and is written only through its non-NULL pointer; each
    // `CRYPTO_*` call's `file`/`line` are the authority's own expansion coordinates.
    unsafe {
        let mut scheme: *mut c_char = ptr::null_mut();
        let mut port: *mut c_char = ptr::null_mut();
        let mut ssl: c_int = 0;
        let mut portnum: c_int = 0;

        init_pstring(pport);
        if !pssl.is_null() {
            *pssl = 0;
        }
        if OSSL_parse_url(
            url,
            &mut scheme,
            puser,
            phost,
            &mut port,
            pport_num,
            ppath,
            pquery,
            pfrag,
        ) == 0
        {
            return 0;
        }

        'body: {
            // Check for optional HTTP scheme "http[s]".
            if strcmp(scheme, OSSL_HTTPS_NAME.as_ptr()) == 0 {
                ssl = 1;
                if !pssl.is_null() {
                    *pssl = ssl;
                }
            } else if *scheme != 0 && strcmp(scheme, OSSL_HTTP_NAME.as_ptr()) != 0 {
                raise_site(&HTTP_LIB_224);
                // SAFETY: `scheme` is `OSSL_parse_url`'s allocation.
                CRYPTO_free(scheme.cast(), FILE.as_ptr(), 225);
                // SAFETY: `port` is `OSSL_parse_url`'s allocation.
                CRYPTO_free(port.cast(), FILE.as_ptr(), 226);
                break 'body;
            }
            // SAFETY: `scheme` is `OSSL_parse_url`'s allocation.
            CRYPTO_free(scheme.cast(), FILE.as_ptr(), 229);

            if strcmp(port, c"0".as_ptr()) == 0 {
                // set default port
                // SAFETY: `port` is `OSSL_parse_url`'s allocation.
                CRYPTO_free(port.cast(), FILE.as_ptr(), 233);
                port = (if ssl != 0 {
                    OSSL_HTTPS_PORT
                } else {
                    OSSL_HTTP_PORT
                })
                .as_ptr()
                .cast_mut();
                if ossl_assert(sscanf(port, c"%d".as_ptr(), &mut portnum) == 1) == 0 {
                    break 'body;
                }
                if !pport_num.is_null() {
                    *pport_num = portnum;
                }
                if !pport.is_null() {
                    // SAFETY: `port` is a static NUL-terminated string.
                    *pport = CRYPTO_strdup(port, FILE.as_ptr(), 240).cast::<c_char>();
                    if (*pport).is_null() {
                        break 'body;
                    }
                }
            } else if !pport.is_null() {
                *pport = port;
            } else {
                // SAFETY: `port` is `OSSL_parse_url`'s allocation.
                CRYPTO_free(port.cast(), FILE.as_ptr(), 248);
            }
            return 1;
        }

        // `err:` — the shared cleanup, reached without freeing `port`.
        free_pstring(puser);
        free_pstring(phost);
        free_pstring(ppath);
        free_pstring(pquery);
        free_pstring(pfrag);
        0
    }
}

/// `static int use_proxy(const char *no_proxy, const char *server)` —
/// `crypto/http/http_lib.c:262-298`.
///
/// Answers 1 when `server` is *not* named in the `no_proxy` list (so a proxy may be used) and 0
/// when it is. A bracketed IPv6 `server` is unwrapped before matching, an empty `server` is never
/// matched, and a NULL `no_proxy` falls back to the `no_proxy`/`NO_PROXY` environment variables,
/// so the caller's result depends on the process environment unless it passes a list.
///
/// # Safety
///
/// `no_proxy` must be NULL or NUL-terminated; `server` must be NUL-terminated.
unsafe fn use_proxy(no_proxy: *const c_char, server: *const c_char) -> c_int {
    // SAFETY: the whole body. `server` is NUL-terminated and `no_proxy` NULL or NUL-terminated
    // per the contract; every scan stays within them.
    unsafe {
        let mut host = [0 as c_char; NI_MAXHOST];
        let mut found: *const c_char = ptr::null();
        let mut server = server;

        if ossl_assert(!server.is_null()) == 0 {
            return 0;
        }
        let mut sl = strlen(server);
        if (2..NI_MAXHOST + 2).contains(&sl)
            && *server == b'[' as c_char
            && *server.add(sl - 1) == b']' as c_char
        {
            // strip leading '[' and trailing ']' from escaped IPv6 address
            sl -= 2;
            strncpy(host.as_mut_ptr(), server.add(1), sl);
            host[sl] = 0;
            server = host.as_ptr();
        }

        if sl == 0 {
            return 1;
        }

        /*
         * using environment variable names, both lowercase and uppercase variants, compatible
         * with other HTTP client implementations like wget, curl and git
         */
        let mut no_proxy = no_proxy;
        if no_proxy.is_null() {
            no_proxy = ossl_safe_getenv(c"no_proxy".as_ptr());
        }
        if no_proxy.is_null() {
            no_proxy = ossl_safe_getenv(OPENSSL_NO_PROXY.as_ptr());
        }

        if !no_proxy.is_null() {
            found = strstr(no_proxy, server);
        }
        while !found.is_null()
            && ((found != no_proxy
                && !ossl_isspace(*found.sub(1) as c_int)
                && *found.sub(1) != b',' as c_char)
                || (*found.add(sl) != 0
                    && !ossl_isspace(*found.add(sl) as c_int)
                    && *found.add(sl) != b',' as c_char))
        {
            found = strstr(found.add(1), server);
        }
        c_int::from(found.is_null())
    }
}

/// `const char *OSSL_HTTP_adapt_proxy(const char *proxy, const char *no_proxy,
/// const char *server, int use_ssl)` — `crypto/http/http_lib.c:301-316`.
///
/// Resolves which proxy to use: an explicit `proxy` wins, otherwise the `https_proxy`/`http_proxy`
/// (then `HTTPS_PROXY`/`HTTP_PROXY`) environment variables, with a NULL answer when none is set,
/// the resolved name is empty, or `no_proxy` matches `server`. The return value is a borrowed
/// pointer — either the caller's `proxy` or the environment's storage — never a fresh allocation.
///
/// # Safety
///
/// `proxy` and `no_proxy` must each be NULL or NUL-terminated; `server` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HTTP_adapt_proxy(
    proxy: *const c_char,
    no_proxy: *const c_char,
    server: *const c_char,
    use_ssl: c_int,
) -> *const c_char {
    // SAFETY: the whole transcription. Every pointer is NULL or NUL-terminated per the contract,
    // and both environment lookups return a NUL-terminated value or NULL.
    unsafe {
        let mut proxy = proxy;

        /*
         * using environment variable names, both lowercase and uppercase variants, compatible
         * with other HTTP client implementations like wget, curl and git
         */
        if proxy.is_null() {
            let name = if use_ssl != 0 {
                c"https_proxy".as_ptr()
            } else {
                c"http_proxy".as_ptr()
            };
            proxy = ossl_safe_getenv(name);
        }
        if proxy.is_null() {
            let name = if use_ssl != 0 {
                OPENSSL_HTTPS_PROXY.as_ptr()
            } else {
                OPENSSL_HTTP_PROXY.as_ptr()
            };
            proxy = ossl_safe_getenv(name);
        }

        if proxy.is_null() || *proxy == 0 || use_proxy(no_proxy, server) == 0 {
            return ptr::null();
        }
        proxy
    }
}
