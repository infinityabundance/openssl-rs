//! `crypto/http/http_lib.c` — the URL parser `crypto/x509/v3_ncons.c`'s name-constraint
//! matching depends on. Only the name that unit needs is landed; the rest of the file's
//! surface is withheld by name below.
//!
//! The authority unit is 318 lines. `OSSL_parse_url` (`:54-200`) sits *outside*
//! `#ifndef OPENSSL_NO_HTTP` — the file's own comment at `:35` says so, because the generic
//! RFC 3986 split is useful even without an HTTP client — and it is landed whole, together
//! with the four `static` helpers it calls: `init_pstring` (`:26-31`), `init_pint`
//! (`:33-38`), `copy_substring` (`:40-44`) and `free_pstring` (`:46-52`).
//!
//! `OSSL_parse_url` is an authority export (`util/libcrypto.num:4885`, version `3_0_0`) and
//! is declared in the public `include/openssl/http.h:36`, so it is `#[no_mangle] pub unsafe
//! extern "C" fn`. The four helpers are `static` in the authority and carry no
//! `#[no_mangle]`.
//!
//! ## Withheld by name
//!
//! Everything below `:202` lies inside `#ifndef OPENSSL_NO_HTTP` and is not the name
//! `v3_ncons.c` reaches, so it is withheld whole — named here, not defined and not stubbed:
//!
//! * `OSSL_HTTP_parse_url` (`:204-259`) — the scheme/port layer over `OSSL_parse_url`; its
//!   only callers are the HTTP transport entry points (`OSSL_HTTP_open`/`_get`/`_transfer`)
//!   this crate does not implement, so landing it would advertise an unreachable HTTP surface.
//! * `use_proxy` (`:262-298`, `static`) — `no_proxy`-list matching shared only by
//!   `OSSL_HTTP_adapt_proxy`, which is itself withheld, so it has no reachable caller.
//! * `OSSL_HTTP_adapt_proxy` (`:301-316`) — resolves a proxy from the process environment
//!   (`https_proxy`/`no_proxy` via `ossl_safe_getenv`) for the network transport this crate
//!   deliberately does not fabricate.
//!
//! ## The raise sites
//!
//! `crypto/http/http_lib.c` is not in `gen_err_raise_sites.py`'s covered set, so its four
//! raise coordinates are **declared locally**, their reason values read from the authority's
//! `httperr.h`/`err.h.in` (not typed from memory), the way `src/x509/v3_asid.rs` declares its
//! own. `ERR_LIB_HTTP` is `err.h.in:126`; `ERR_R_PASSED_NULL_PARAMETER` is the `err.h.in:356`
//! composite `(258 | ERR_R_FATAL)`; the three `HTTP_R_*` reasons are the `httperr.h` rows read
//! below the helper. `ErrSite::file` carries the authority build record's
//! `../../src/openssl-3.6.4/...` spelling, matching `err_sites.rs`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{memchr, strchr, strlen, strncmp};
use crate::runtime::ctype::{ossl_isalpha, ossl_isdigit};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strndup};

// `strpbrk` and `sscanf` are not among `runtime::bio::sys`'s declarations, so they are
// declared here as the module's own C imports (the pattern `src/ml_dsa/sign.rs` and
// `src/engine/eng_ctrl.rs` use). `sscanf` is used only for the single `"%u"` conversion.
extern "C" {
    /// `char *strpbrk(const char *s, const char *accept)`.
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char;
    /// `int sscanf(const char *s, const char *format, ...)` — the C-variadic ABI.
    fn sscanf(s: *const c_char, format: *const c_char, ...) -> c_int;
}

/// `#define OSSL_URL_SCHEME_SUFFIX "://"` — `crypto/http/http_lib.c:24`.
const OSSL_URL_SCHEME_SUFFIX: &[u8] = b"://";

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
