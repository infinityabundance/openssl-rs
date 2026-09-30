//! `crypto/x509/v3_pci.c` — the RFC 3820 proxy-certificate extension printer and its row. Phase
//! 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_pci.c` is 323 lines and transcribes whole:
//!
//! * `i2r_pci` (`:74-90`), the static `r2i_pci` machinery through its two static helpers
//!   `process_pci_value` (`:92-240`) and `r2i_pci` (`:242-323`).
//! * The row [`ossl_v3_pci`] (`:57-72`), `NID_proxyCertInfo`, item
//!   [`crate::x509::v3_pcia::PROXY_CERT_INFO_EXTENSION_it`], printer [`i2r_pci`] and parser
//!   [`r2i_pci`].
//!
//! The item group itself is landed by `crypto/x509/v3_pcia.c`
//! ([`crate::x509::v3_pcia`]); this unit only references it, so no item is defined here.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the array
//! is withheld until all 63 tables exist. This unit contributes one of the 63. The row is internal
//! data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the two callbacks are the
//! drivable surface.
//!
//! ## The two header-macro expansions, defined locally
//!
//! `X509V3_conf_err` (`x509v3.h:632-635`) and `CHECK_AND_SKIP_PREFIX` (`internal/common.h:60-61`)
//! are macros, not functions. `X509V3_conf_err` is expanded here as [`conf_err`] through
//! [`crate::runtime::err::openssl_rs_err_add_data`] with the authority's NULL-becomes-`<NULL>` rule
//! (`crypto/err/err.c:855-856`), as `crypto/x509/v3_cpols.c` does; `CHECK_AND_SKIP_PREFIX` is
//! expanded as [`check_and_skip_prefix`], returning the advanced cursor.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_pci.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! thirteen coordinates are **declared locally** with the `err_sites::ErrSite` shape, as
//! `v3_pcons.rs` does. Their reason values are read from the authority's own headers (`x509v3err.h`
//! for the eight `X509V3_R_*`, `err.h` for the two `ERR_R_*_LIB`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{memcpy, strcmp, strlen};
use crate::runtime::bio::{
    BIO_free_all, BIO_new_file, BIO_read, BIO_test_flags, Bio, BIO_FLAGS_SHOULD_RETRY,
};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_INCORRECT_POLICY_SYNTAX_TAG, X509V3_R_INVALID_OBJECT_IDENTIFIER,
    X509V3_R_INVALID_PROXY_POLICY_SETTING, X509V3_R_INVALID_SECTION,
    X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED, X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED,
    X509V3_R_POLICY_PATH_LENGTH, X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED,
    X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY,
};
use crate::runtime::err::{openssl_rs_err_add_data, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};
use crate::runtime::obj::{
    Asn1Object, NID_Independent, NID_id_ppl_inheritAll, NID_proxyCertInfo, OBJ_obj2nid, OBJ_txt2obj,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::runtime::str::OPENSSL_hexstr2buf;
use crate::x509::v3_conf::{X509V3Ctx, X509V3_get_section, X509V3_section_free};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_pcia::{
    PROXY_CERT_INFO_EXTENSION_free, PROXY_CERT_INFO_EXTENSION_new, ProxyCertInfoExtension,
};
use crate::x509::v3_utl::{X509V3_conf_free, X509V3_get_value_int, X509V3_parse_list};

/// `OPENSSL_FILE` for this unit's `OPENSSL_realloc`/`OPENSSL_free` expansions — `crypto/x509/v3_pci.c`.
const FILE: &CStr = c"crypto/x509/v3_pci.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`, `ERR_LIB_ASN1` = 13.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_BIO_LIB` — `err.h:333`, `(ERR_LIB_BIO | ERR_RFLAG_COMMON)`, `ERR_LIB_BIO` = 32.
const ERR_R_BIO_LIB: c_int = 524320;

/// The `OPENSSL_realloc` call at `v3_pci.c:143` (`hex:` arm).
const LINE_REALLOC_HEX: c_int = 143;
/// The `OPENSSL_free(tmp_data2)` at `v3_pci.c:152` (realloc-failure arm of `hex:`).
const LINE_FREE_HEX2_FAIL: c_int = 152;
/// The `OPENSSL_free((*policy)->data)` at `v3_pci.c:157` (realloc-failure arm of `hex:`).
const LINE_FREE_HEX_DATA_FAIL: c_int = 157;
/// The `OPENSSL_free(tmp_data2)` at `v3_pci.c:163` (success arm of `hex:`).
const LINE_FREE_HEX2_OK: c_int = 163;
/// The `OPENSSL_realloc` call at `v3_pci.c:178` (`file:` arm).
const LINE_REALLOC_FILE: c_int = 178;
/// The `OPENSSL_free((*policy)->data)` at `v3_pci.c:182` (realloc-failure arm of `file:`).
const LINE_FREE_FILE_FAIL: c_int = 182;
/// The `OPENSSL_realloc` call at `v3_pci.c:204` (`text:` arm).
const LINE_REALLOC_TEXT: c_int = 204;
/// The `OPENSSL_free((*policy)->data)` at `v3_pci.c:217` (realloc-failure arm of `text:`).
const LINE_FREE_TEXT_FAIL: c_int = 217;

/// One `v3_pci.c` raise coordinate, declared locally (see the module doc).
const fn v3_pci_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_pci.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `process_pci_value`'s duplicate `language` raise at `v3_pci.c:100` —
/// `X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED` (`x509v3err.h:78`, 155).
const V3_PCI_100: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    100,
    c"process_pci_value",
    X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED,
);
/// `process_pci_value`'s failed `OBJ_txt2obj` raise at `v3_pci.c:105` —
/// `X509V3_R_INVALID_OBJECT_IDENTIFIER` (`x509v3err.h:57`, 110).
const V3_PCI_105: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    105,
    c"process_pci_value",
    X509V3_R_INVALID_OBJECT_IDENTIFIER,
);
/// `process_pci_value`'s duplicate `pathlen` raise at `v3_pci.c:111` —
/// `X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED` (`x509v3err.h:80`, 157).
const V3_PCI_111: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    111,
    c"process_pci_value",
    X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED,
);
/// `process_pci_value`'s bad `pathlen` raise at `v3_pci.c:117` —
/// `X509V3_R_POLICY_PATH_LENGTH` (`x509v3err.h:79`, 156).
const V3_PCI_117: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(117, c"process_pci_value", X509V3_R_POLICY_PATH_LENGTH);
/// `process_pci_value`'s `ASN1_OCTET_STRING_new` raise at `v3_pci.c:129` —
/// `ERR_R_ASN1_LIB` (`err.h:328`, 524301).
const V3_PCI_129: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(129, c"process_pci_value", ERR_R_ASN1_LIB);
/// `process_pci_value`'s `BIO_new_file` raise at `v3_pci.c:169` —
/// `ERR_R_BIO_LIB` (`err.h:333`, 524320).
const V3_PCI_169: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(169, c"process_pci_value", ERR_R_BIO_LIB);
/// `process_pci_value`'s short-read raise at `v3_pci.c:198` —
/// `ERR_R_BIO_LIB` (`err.h:333`, 524320).
const V3_PCI_198: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(198, c"process_pci_value", ERR_R_BIO_LIB);
/// `process_pci_value`'s unknown `policy` tag raise at `v3_pci.c:224` —
/// `X509V3_R_INCORRECT_POLICY_SYNTAX_TAG` (`x509v3err.h:42`, 152).
const V3_PCI_224: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    224,
    c"process_pci_value",
    X509V3_R_INCORRECT_POLICY_SYNTAX_TAG,
);
/// `r2i_pci`'s malformed-entry raise at `v3_pci.c:257` —
/// `X509V3_R_INVALID_PROXY_POLICY_SETTING` (`x509v3err.h:60`, 153).
const V3_PCI_257: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(257, c"r2i_pci", X509V3_R_INVALID_PROXY_POLICY_SETTING);
/// `r2i_pci`'s missing-section raise at `v3_pci.c:267` —
/// `X509V3_R_INVALID_SECTION` (`x509v3err.h:63`, 135).
const V3_PCI_267: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(267, c"r2i_pci", X509V3_R_INVALID_SECTION);
/// `r2i_pci`'s missing-language raise at `v3_pci.c:288` —
/// `X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED` (`x509v3err.h:73`, 154).
const V3_PCI_288: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    288,
    c"r2i_pci",
    X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED,
);
/// `r2i_pci`'s policy-with-no-policy-language raise at `v3_pci.c:294` —
/// `X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY` (`x509v3err.h:81`, 159).
const V3_PCI_294: crate::runtime::err::err_sites::ErrSite = v3_pci_site(
    294,
    c"r2i_pci",
    X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY,
);
/// `r2i_pci`'s `PROXY_CERT_INFO_EXTENSION_new` raise at `v3_pci.c:301` —
/// `ERR_R_ASN1_LIB` (`err.h:328`, 524301).
const V3_PCI_301: crate::runtime::err::err_sites::ErrSite =
    v3_pci_site(301, c"r2i_pci", ERR_R_ASN1_LIB);

// ---------------------------------------------------------------------------------------------
// The two header-macro expansions
// ---------------------------------------------------------------------------------------------

/// Append `p`, or the literal `<NULL>` when it is null, to `buf`.
///
/// # Safety
///
/// `p` must be NULL or NUL-terminated.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { CStr::from_ptr(p) }.to_bytes());
    }
}

/// `X509V3_conf_err(val)` — the `x509v3.h:632-635` macro's expansion,
/// `ERR_add_error_data(6, "section:", (val)->section, ",name:", (val)->name, ",value:",
/// (val)->value)`.
///
/// # Safety
///
/// `val` must be a live `CONF_VALUE`.
unsafe fn conf_err(val: *const ConfValue) {
    let mut buf: Vec<u8> = b"section:".to_vec();
    // SAFETY: `val` is live per the contract.
    unsafe { push_cstr_or_null(&mut buf, (*val).section) };
    buf.extend_from_slice(b",name:");
    // SAFETY: as above.
    unsafe { push_cstr_or_null(&mut buf, (*val).name) };
    buf.extend_from_slice(b",value:");
    // SAFETY: as above.
    unsafe { push_cstr_or_null(&mut buf, (*val).value) };
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated.
    unsafe { openssl_rs_err_add_data(buf.as_ptr().cast::<c_char>()) };
}

/// `CHECK_AND_SKIP_PREFIX(str, pre)` — `include/internal/common.h:60-61`.
///
/// Answers the advanced cursor, or `None` when the prefix does not match. The authority's macro
/// mutates its argument; a Rust transcription cannot, so the cursor is the return value.
///
/// # Safety
///
/// `s` must be NUL-terminated.
unsafe fn check_and_skip_prefix(s: *const c_char, pre: &[u8]) -> Option<*mut c_char> {
    // SAFETY: the caller's contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    if bytes.len() >= pre.len() && &bytes[..pre.len()] == pre {
        // SAFETY: the match proves `pre.len()` bytes lie before the terminator.
        Some(unsafe { s.add(pre.len()) }.cast_mut())
    } else {
        None
    }
}

/// `sk_CONF_VALUE_pop_free(..., X509V3_conf_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// The `goto err` tail of `process_pci_value` (`crypto/x509/v3_pci.c:234-239`).
///
/// # Safety
///
/// `policy` is a writable slot; when `free_policy` is set it holds a value this call allocated.
unsafe fn process_pci_value_err(free_policy: bool, policy: *mut *mut Asn1String) -> c_int {
    if free_policy {
        // SAFETY: `policy` holds a value this call allocated and does not own.
        unsafe {
            ASN1_OCTET_STRING_free(*policy);
            *policy = ptr::null_mut();
        }
    }
    0
}

/// `static int process_pci_value(CONF_VALUE *val, ASN1_OBJECT **language, ASN1_INTEGER **pathlen,
/// ASN1_OCTET_STRING **policy)` — `crypto/x509/v3_pci.c:92-240`.
///
/// Handles one `language`/`pathlen`/`policy` entry of a proxy policy, mutating the three out
/// parameters. The `policy` arms parse the `hex:`/`file:`/`text:` prefixes.
///
/// # Safety
///
/// `val` is a live `CONF_VALUE`; the three out parameters are writable slots.
unsafe fn process_pci_value(
    val: *mut ConfValue,
    language: *mut *mut Asn1Object,
    pathlen: *mut *mut Asn1String,
    policy: *mut *mut Asn1String,
) -> c_int {
    let mut free_policy = false;
    // SAFETY: `val` is live per the contract.
    let (name, value) = unsafe { ((*val).name, (*val).value) };
    // SAFETY: `name` is NUL-terminated per the contract.
    let is_language = unsafe { strcmp(name, c"language".as_ptr()) } == 0;
    // SAFETY: as above.
    let is_pathlen = unsafe { strcmp(name, c"pathlen".as_ptr()) } == 0;
    // SAFETY: as above.
    let is_policy = unsafe { strcmp(name, c"policy".as_ptr()) } == 0;

    if is_language {
        // SAFETY: `language` is a writable slot per the contract.
        if !unsafe { *language }.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_100) };
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            return 0;
        }
        // SAFETY: `value` is NUL-terminated per the contract.
        let obj = unsafe { OBJ_txt2obj(value, 0) };
        // SAFETY: `language` is a writable slot.
        unsafe { *language = obj };
        if obj.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_105) };
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            return 0;
        }
    } else if is_pathlen {
        // SAFETY: `pathlen` is a writable slot per the contract.
        if !unsafe { *pathlen }.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_111) };
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            return 0;
        }
        // SAFETY: `val` is live; `pathlen` is a writable slot.
        if unsafe { X509V3_get_value_int(val, pathlen) } == 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_117) };
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            return 0;
        }
    } else if is_policy {
        let mut valp = value;
        let mut tmp_data: *mut c_uchar = ptr::null_mut();
        let mut val_len: c_long = 0;
        // SAFETY: `policy` is a writable slot per the contract.
        if unsafe { *policy }.is_null() {
            let os = ASN1_OCTET_STRING_new();
            // SAFETY: `policy` is a writable slot.
            unsafe { *policy = os };
            if os.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PCI_129) };
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                return 0;
            }
            free_policy = true;
        }
        // SAFETY: `policy` is a writable slot holding a live octet string.
        let pol = unsafe { *policy };
        // SAFETY: `valp` is NUL-terminated per the contract.
        let hex = unsafe { check_and_skip_prefix(valp, b"hex:") };
        // SAFETY: `valp` is NUL-terminated per the contract.
        let file = unsafe { check_and_skip_prefix(valp, b"file:") };
        // SAFETY: `valp` is NUL-terminated per the contract.
        let text = unsafe { check_and_skip_prefix(valp, b"text:") };
        if let Some(rest) = hex {
            valp = rest;
            // SAFETY: `valp` is NUL-terminated per the contract.
            let data2 = unsafe { OPENSSL_hexstr2buf(valp, &raw mut val_len) };
            if data2.is_null() {
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                return unsafe { process_pci_value_err(free_policy, policy) };
            }
            // SAFETY: `pol` is the live policy string; `data2` is live for `val_len` bytes.
            let newp = unsafe {
                CRYPTO_realloc(
                    (*pol).data.cast::<c_void>(),
                    ((*pol).length as c_long + val_len + 1) as usize,
                    FILE.as_ptr(),
                    LINE_REALLOC_HEX,
                )
            };
            if !newp.is_null() {
                // SAFETY: `pol` is live and the copy lies within the new allocation.
                unsafe {
                    (*pol).data = newp.cast::<c_uchar>();
                    memcpy(
                        (*pol).data.add((*pol).length as usize).cast::<c_void>(),
                        data2.cast::<c_void>(),
                        val_len as usize,
                    );
                    (*pol).length += val_len as c_int;
                    *(*pol).data.add((*pol).length as usize) = 0;
                }
                tmp_data = newp.cast::<c_uchar>();
            } else {
                // SAFETY: `data2` and `pol`'s `data` are this call's allocations.
                unsafe {
                    CRYPTO_free(data2.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_HEX2_FAIL);
                    CRYPTO_free(
                        (*pol).data.cast::<c_void>(),
                        FILE.as_ptr(),
                        LINE_FREE_HEX_DATA_FAIL,
                    );
                    (*pol).data = ptr::null_mut();
                    (*pol).length = 0;
                }
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                return unsafe { process_pci_value_err(free_policy, policy) };
            }
            // SAFETY: `data2` is this call's allocation and not owned elsewhere.
            unsafe { CRYPTO_free(data2.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_HEX2_OK) };
        } else if let Some(rest) = file {
            valp = rest;
            let mut buf = [0 as c_uchar; 2048];
            // SAFETY: `valp` is NUL-terminated; the mode literal is static.
            let b = unsafe { BIO_new_file(valp, c"r".as_ptr()) };
            if b.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PCI_169) };
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                return unsafe { process_pci_value_err(free_policy, policy) };
            }
            let mut n: c_int;
            loop {
                // SAFETY: `b` is live; `buf` has room for 2048 bytes.
                n = unsafe { BIO_read(b, buf.as_mut_ptr().cast::<c_void>(), 2048) };
                // SAFETY: `b` is live. `BIO_should_retry(b)` is this flag test.
                let retry = unsafe { BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY) } != 0;
                if n <= 0 && !(n == 0 && retry) {
                    break;
                }
                if n == 0 {
                    continue;
                }
                // SAFETY: `pol` is the live policy string.
                let newp = unsafe {
                    CRYPTO_realloc(
                        (*pol).data.cast::<c_void>(),
                        ((*pol).length as c_long + n as c_long + 1) as usize,
                        FILE.as_ptr(),
                        LINE_REALLOC_FILE,
                    )
                };
                if newp.is_null() {
                    // SAFETY: `pol`'s `data` is this call's allocation.
                    unsafe {
                        CRYPTO_free(
                            (*pol).data.cast::<c_void>(),
                            FILE.as_ptr(),
                            LINE_FREE_FILE_FAIL,
                        );
                        (*pol).data = ptr::null_mut();
                        (*pol).length = 0;
                    }
                    // SAFETY: `val` is live.
                    unsafe { conf_err(val) };
                    // SAFETY: `b` is the BIO this call opened.
                    unsafe { BIO_free_all(b) };
                    // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                    return unsafe { process_pci_value_err(free_policy, policy) };
                }
                // SAFETY: `pol` is live and the copy lies within the new allocation.
                unsafe {
                    (*pol).data = newp.cast::<c_uchar>();
                    memcpy(
                        (*pol).data.add((*pol).length as usize).cast::<c_void>(),
                        buf.as_mut_ptr().cast::<c_void>(),
                        n as usize,
                    );
                    (*pol).length += n;
                    *(*pol).data.add((*pol).length as usize) = 0;
                }
                tmp_data = newp.cast::<c_uchar>();
            }
            // SAFETY: `b` is the BIO this call opened.
            unsafe { BIO_free_all(b) };
            if n < 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PCI_198) };
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                return unsafe { process_pci_value_err(free_policy, policy) };
            }
        } else if let Some(rest) = text {
            valp = rest;
            // SAFETY: `valp` is NUL-terminated per the contract. The authority truncates the
            // `size_t` to an `int` before widening it to the `long`.
            val_len = (unsafe { strlen(valp) } as c_int) as c_long;
            // SAFETY: `pol` is the live policy string.
            let newp = unsafe {
                CRYPTO_realloc(
                    (*pol).data.cast::<c_void>(),
                    ((*pol).length as c_long + val_len + 1) as usize,
                    FILE.as_ptr(),
                    LINE_REALLOC_TEXT,
                )
            };
            if !newp.is_null() {
                // SAFETY: `pol` is live and the copy lies within the new allocation.
                unsafe {
                    (*pol).data = newp.cast::<c_uchar>();
                    memcpy(
                        (*pol).data.add((*pol).length as usize).cast::<c_void>(),
                        value.add(5).cast::<c_void>(),
                        val_len as usize,
                    );
                    (*pol).length += val_len as c_int;
                    *(*pol).data.add((*pol).length as usize) = 0;
                }
                tmp_data = newp.cast::<c_uchar>();
            } else {
                // SAFETY: `pol`'s `data` is this call's allocation.
                unsafe {
                    CRYPTO_free(
                        (*pol).data.cast::<c_void>(),
                        FILE.as_ptr(),
                        LINE_FREE_TEXT_FAIL,
                    );
                    (*pol).data = ptr::null_mut();
                    (*pol).length = 0;
                }
                // SAFETY: `val` is live.
                unsafe { conf_err(val) };
                // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
                return unsafe { process_pci_value_err(free_policy, policy) };
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_224) };
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
            return unsafe { process_pci_value_err(free_policy, policy) };
        }
        if tmp_data.is_null() {
            // SAFETY: `val` is live.
            unsafe { conf_err(val) };
            // SAFETY: `policy` is a writable slot; the site is the local goto-err tail.
            return unsafe { process_pci_value_err(free_policy, policy) };
        }
    }
    1
}

/// `static int i2r_pci(X509V3_EXT_METHOD *method, PROXY_CERT_INFO_EXTENSION *pci, BIO *out, int
/// indent)` — `crypto/x509/v3_pci.c:74-90`.
///
/// Prints the path-length constraint (or `infinite`), the policy language and, when present, the
/// policy text.
///
/// # Safety
///
/// `out` is a live BIO; `in_` is a live `PROXY_CERT_INFO_EXTENSION`.
unsafe extern "C" fn i2r_pci(
    _method: *const X509V3ExtMethod,
    in_: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let pci = in_.cast::<ProxyCertInfoExtension>();
    // SAFETY: `out` is live; the literal is static.
    unsafe {
        BIO_printf(
            out,
            c"%*sPath Length Constraint: ".as_ptr(),
            indent,
            c"".as_ptr(),
        )
    };
    // SAFETY: `pci` is live per the contract.
    let pathlen = unsafe { (*pci).pcPathLengthConstraint };
    if !pathlen.is_null() {
        // SAFETY: `out` is live; `pathlen` is a live INTEGER.
        unsafe { i2a_ASN1_INTEGER(out, pathlen) };
    } else {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"infinite".as_ptr()) };
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_printf(out, c"%*sPolicy Language: ".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `pci` is live; its `proxyPolicy` is the mandatory live value the item built.
    let policy = unsafe { (*pci).proxyPolicy };
    // SAFETY: `out` is live; `policy`'s language is a live object.
    unsafe { i2a_ASN1_OBJECT(out, (*policy).policyLanguage) };
    // SAFETY: `policy` is live.
    let pol = unsafe { (*policy).policy };
    let mut pol_data: *mut c_uchar = ptr::null_mut();
    if !pol.is_null() {
        // SAFETY: `pol` is a live string; its `data` is a live pointer.
        pol_data = unsafe { (*pol).data };
    }
    if !pol_data.is_null() {
        // SAFETY: `out` is live; `pol_data` is `length` readable bytes and the precision bounds the
        // read.
        unsafe {
            BIO_printf(
                out,
                c"\n%*sPolicy Text: %.*s".as_ptr(),
                indent,
                c"".as_ptr(),
                (*pol).length,
                pol_data.cast::<c_char>(),
            )
        };
    }
    1
}

/// `static PROXY_CERT_INFO_EXTENSION *r2i_pci(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char
/// *value)` — `crypto/x509/v3_pci.c:242-323`.
///
/// Parses a proxy-policy string into a `PROXY_CERT_INFO_EXTENSION`; an `@`-prefixed entry names a
/// config section. Answers NULL (with the error queue set) on failure.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `value` is NUL-terminated.
unsafe extern "C" fn r2i_pci(
    _method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    value: *const c_char,
) -> *mut c_void {
    let ctx = ctx.cast::<X509V3Ctx>();
    let mut pci: *mut ProxyCertInfoExtension = ptr::null_mut();
    let mut language: *mut Asn1Object = ptr::null_mut();
    let mut pathlen: *mut Asn1String = ptr::null_mut();
    let mut policy: *mut Asn1String = ptr::null_mut();
    let mut failed = false;
    // SAFETY: `value` is NUL-terminated per the contract.
    let vals = unsafe { X509V3_parse_list(value) };
    'body: {
        // SAFETY: `vals` is NULL or a live `CONF_VALUE` stack.
        let num = unsafe { OPENSSL_sk_num(vals) };
        let mut i = 0;
        while i < num {
            // SAFETY: the stack is live and `i` is in bounds.
            let cnf = unsafe { OPENSSL_sk_value(vals, i) }.cast::<ConfValue>();
            // SAFETY: `cnf` is live per the contract.
            let name = unsafe { (*cnf).name };
            // SAFETY: `cnf` is live; `name` is NULL or NUL-terminated.
            let leading_at = !name.is_null() && unsafe { *name } == b'@' as c_char;
            // SAFETY: `cnf` is live.
            let value_null = unsafe { (*cnf).value }.is_null();
            if name.is_null() || (!leading_at && value_null) {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PCI_257) };
                // SAFETY: `cnf` is live.
                unsafe { conf_err(cnf) };
                failed = true;
                break 'body;
            }
            if leading_at {
                let mut success_p = 1;
                // SAFETY: `ctx` is live and `name + 1` names a section.
                let sect = unsafe { X509V3_get_section(ctx, name.add(1)) };
                if sect.is_null() {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_PCI_267) };
                    // SAFETY: `cnf` is live.
                    unsafe { conf_err(cnf) };
                    failed = true;
                    break 'body;
                }
                // SAFETY: `sect` is a live `CONF_VALUE` stack.
                let snum = unsafe { OPENSSL_sk_num(sect) };
                let mut j = 0;
                while success_p != 0 && j < snum {
                    // SAFETY: the stack is live and `j` is in bounds.
                    let cv = unsafe { OPENSSL_sk_value(sect, j) }.cast::<ConfValue>();
                    // SAFETY: `cv` is live and the three out slots are this frame's.
                    success_p = unsafe {
                        process_pci_value(cv, &raw mut language, &raw mut pathlen, &raw mut policy)
                    };
                    j += 1;
                }
                // SAFETY: `ctx` is live and `sect` is a section this call owns.
                unsafe { X509V3_section_free(ctx, sect) };
                if success_p == 0 {
                    failed = true;
                    break 'body;
                }
            } else {
                // SAFETY: `cnf` is live and the three out slots are this frame's.
                if unsafe {
                    process_pci_value(cnf, &raw mut language, &raw mut pathlen, &raw mut policy)
                } == 0
                {
                    // SAFETY: `cnf` is live.
                    unsafe { conf_err(cnf) };
                    failed = true;
                    break 'body;
                }
            }
            i += 1;
        }
        // Language is mandatory.
        if language.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_288) };
            failed = true;
            break 'body;
        }
        // SAFETY: `language` is a live object.
        let nid = unsafe { OBJ_obj2nid(language) };
        if (nid == NID_Independent || nid == NID_id_ppl_inheritAll) && !policy.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_294) };
            failed = true;
            break 'body;
        }
        pci = PROXY_CERT_INFO_EXTENSION_new();
        if pci.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PCI_301) };
            failed = true;
            break 'body;
        }
        // SAFETY: `pci` is live; its `proxyPolicy` is the mandatory live value the item built, so
        // both field slots below are writable.
        unsafe {
            (*(*pci).proxyPolicy).policyLanguage = language;
            language = ptr::null_mut();
            (*(*pci).proxyPolicy).policy = policy;
            policy = ptr::null_mut();
            (*pci).pcPathLengthConstraint = pathlen;
            pathlen = ptr::null_mut();
        }
    }
    if failed {
        // SAFETY: each is NULL or a live value this call owns.
        unsafe {
            ASN1_OBJECT_free(language);
            ASN1_INTEGER_free(pathlen);
            ASN1_OCTET_STRING_free(policy);
            PROXY_CERT_INFO_EXTENSION_free(pci);
            pci = ptr::null_mut();
        }
    }
    // SAFETY: `vals` is NULL or a `CONF_VALUE` list this call owns; the thunk is its destructor.
    unsafe { OPENSSL_sk_pop_free(vals, Some(conf_value_free_thunk)) };
    pci.cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_pci` — `crypto/x509/v3_pci.c:57-72`.
///
/// `NID_proxyCertInfo`, item [`crate::x509::v3_pcia::PROXY_CERT_INFO_EXTENSION_it`], printer
/// [`i2r_pci`] and parser [`r2i_pci`]; every other slot is zero.
pub static ossl_v3_pci: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_proxyCertInfo,
    ext_flags: 0,
    it: Some(crate::x509::v3_pcia::PROXY_CERT_INFO_EXTENSION_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_pci),
    r2i: Some(r2i_pci),
    usr_data: ptr::null_mut(),
};
