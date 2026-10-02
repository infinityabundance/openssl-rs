//! Phase 12.9 — `crypto/asn1/asn_mime.c`'s MIME reader and writer, landed whole.
//!
//! `asn_mime.c` is 1077 lines and its two halves were split by *dependency*, not by
//! file. Phase 5 landed the half that needs only Phase 4: [`SMIME_crlf_copy`] and
//! [`i2d_ASN1_bio_stream`] (with their helper `strip_eol`). The MIME *reader and
//! writer* — [`SMIME_write_ASN1_ex`]/[`SMIME_write_ASN1`],
//! [`SMIME_read_ASN1_ex`]/[`SMIME_read_ASN1`] and [`SMIME_text`] — need
//! `BIO_f_base64` (the EVP codec, Phase 7) and the `X509_ALGOR` set for the `micalg`
//! parameter (Phase 11). Both now exist, so this module is the whole file, including
//! the file-static helpers the five exports reach: `asn1_output_data`,
//! `asn1_write_micalg`, `B64_write_ASN1`, `b64_read_asn1`, `multi_split`, the
//! `MIME_HEADER`/`MIME_PARAM` object model and its helpers, and the no-op
//! `mime_debug` macro.
//!
//! ## What is observable
//!
//! * the **CRLF policy** in every combination of `SMIME_TEXT`, `SMIME_BINARY`,
//!   `SMIME_ASCIICRLF` and `SMIME_CRLFEOL`: which terminators survive, which are
//!   rewritten as `\r\n`, and where a trailing-space line lands;
//! * the **buffering filter**. `SMIME_crlf_copy` pushes a `BIO_f_buffer` in front of
//!   the sink and pops it afterwards, so the bytes reach the sink in the filter's
//!   blocks rather than one line at a time;
//! * the **flush result combining with the copy's**. `ret = BIO_flush(out) > 0 && ret`,
//!   so a failing flush turns a successful copy into a failure and *not* the other way
//!   round;
//! * the two **null-argument refusals**, each with its own reason;
//! * the **unwinding loop** in the streaming arms. `BIO_pop` is called until it answers
//!   the caller's original BIO, so the chain is destroyed in exactly that order and the
//!   caller is left owning `out` alone (`D-MIME-1` records the authority's non-terminating
//!   form of it);
//! * the **random multipart boundary** the detached writer mints with `RAND_bytes_ex`
//!   and renders as 32 hex nibbles, and the `multipart/signed` envelope around it;
//! * the **header state machine** in `mime_parse_hdr` — which lines become headers,
//!   which become parameters, how quotes and comments are skipped, and that a blank
//!   line ends the block;
//! * the **two-part split** in `multi_split` — the boundary scan, the strip of the
//!   previous line's terminator, and the memory BIO each part is collected into.
//!
//! The `flags` are `pkcs7.h`'s (`SMIME_TEXT` and `SMIME_BINARY` are `PKCS7_TEXT` and
//! `PKCS7_BINARY`; `SMIME_DETACHED` is `PKCS7_DETACHED`; `SMIME_ASCIICRLF` is
//! `pkcs7.h`'s own), which is why the constants below carry their `pkcs7.h` values
//! alongside their `asn1.h` and `cms.h` siblings.
//!
//! ## The `micalg` digest lookup is a recorded deferral, transcribed faithfully
//!
//! `asn1_write_micalg` resolves the digest with `EVP_get_digestbynid(md_nid)` — the
//! macro `EVP_get_digestbyname(OBJ_nid2sn(md_nid))` — and, when the method carries an
//! `md_ctrl`, asks it for `EVP_MD_CTRL_MICALG`. The crate's legacy `OBJ_NAME`
//! digest-name table is the Phase-13 deferral already named in `RT-CMS`/`RT-CRMF`/
//! `RT-OCSP` and recorded for `ossl_x509_algor_get_md` (D343, D344): the lookup
//! answers NULL for every built-in name. The authority's code is transcribed anyway —
//! the `md_ctrl` arm is written against the crate's real `EvpMd.md_ctrl` field and
//! compiles — but it cannot be entered until that table lands, so the authority's own
//! `switch (md_nid)` below it produces the answer. The two SHAKE cases are handled
//! *before* the lookup, exactly as the authority orders them, so `shake-128` and
//! `shake-256` are reached without a method.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void, CStr};
use core::ptr;

use crate::asn1::a_d2i_fp::ASN1_item_d2i_bio_ex;
use crate::asn1::a_i2d_fp::ASN1_item_i2d_bio;
use crate::asn1::bio_asn1::{Asn1StreamArg, BIO_new_NDEF};
use crate::asn1::layout::{Asn1Aux, Asn1Item, ASN1_OP_DETACHED_POST, ASN1_OP_DETACHED_PRE};
use crate::asn1::x_algor::X509Algor;
use crate::evp::bio_enc::BIO_f_base64;
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::bf_buff::BIO_f_buffer;
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::iolib::{BIO_ctrl, BIO_get_line, BIO_gets, BIO_puts, BIO_read, BIO_write};
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::sys::{strcmp, strlen, strncmp};
use crate::runtime::bio::{
    BIO_free, BIO_new, BIO_pop, BIO_push, BIO_vfree, Bio, BIO_CTRL_FLUSH,
    BIO_C_SET_BUF_MEM_EOF_RETURN,
};
use crate::runtime::ctype::{ossl_isspace, ossl_tolower};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::obj::{
    NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512, NID_id_GostR3411_94,
    NID_id_smime_ct_authEnvelopedData, NID_id_smime_ct_compressedData, NID_id_smime_ct_receipt,
    NID_md5, NID_pkcs7_enveloped, NID_pkcs7_signed, NID_sha1, NID_sha256, NID_sha384, NID_sha512,
    NID_shake128, NID_shake256, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};

/// The authority's stack buffer in `strip_eol`'s callers and in the binary arm.
const MAX_SMLEN: c_int = 1024;

/// `SMIME_TEXT` — `pkcs7.h`'s `PKCS7_TEXT`. The sink is given a `text/plain`
/// content-type block before the body.
pub(crate) const SMIME_TEXT: c_int = 0x1;
/// `SMIME_BINARY` — `pkcs7.h`'s `PKCS7_BINARY`. The body is copied verbatim.
pub(crate) const SMIME_BINARY: c_int = 0x80;
/// `CMS_BINARY` — `cms.h`'s own flag, which selects the same verbatim behaviour in
/// `strip_eol`'s first branch. Numerically equal to `SMIME_BINARY`, and deliberately
/// spelled as its own name because the authority tests both.
pub(crate) const CMS_BINARY: c_int = 0x80;
/// `SMIME_CRLFEOL` — `asn1.h`. Each line ends `\r\n`.
pub(crate) const SMIME_CRLFEOL: c_int = 0x800;
/// `SMIME_STREAM` — `asn1.h`. `i2d_ASN1_bio_stream` streams rather than buffers.
pub(crate) const SMIME_STREAM: c_int = 0x1000;
/// `SMIME_ASCIICRLF` — `pkcs7.h`. Blank lines are held back and re-emitted as `\r\n`
/// runs.
pub(crate) const SMIME_ASCIICRLF: c_int = 0x80000;
/// `SMIME_OLDMIME` — `pkcs7.h`. The writer prefixes `application/x-pkcs7-` rather
/// than `application/pkcs7-`.
const SMIME_OLDMIME: c_int = 0x400;
/// `SMIME_DETACHED` — `pkcs7.h`'s `PKCS7_DETACHED`. With a `data` BIO the writer
/// emits a `multipart/signed` body instead of an opaque one.
const SMIME_DETACHED: c_int = 0x40;
/// `PKCS7_REUSE_DIGEST` — `pkcs7.h`. With `SMIME_DETACHED` it selects the
/// already-set-up output BIO rather than the detached callback path.
const PKCS7_REUSE_DIGEST: c_int = 0x8000;

/// `EVP_MD_CTRL_MICALG` — `include/openssl/evp.h`. `src/evp/digest.rs` keeps its own
/// copy private; this is the value `asn1_write_micalg` passes to `md_ctrl`.
const EVP_MD_CTRL_MICALG: c_int = 0x2;

/// The authority translation unit for this file's `OPENSSL_malloc`/`OPENSSL_strdup`/
/// `OPENSSL_free` expansions.
const FILE: &CStr = c"crypto/asn1/asn_mime.c";
/// `asn1_write_micalg`'s `OPENSSL_free(micstr)` (`:189`).
const LINE_MICALG_FREE: c_int = 189;
/// `mime_hdr_new`'s `OPENSSL_strdup(name)` (`:903`).
const LINE_HDR_NEW_STRDUP_NAME: c_int = 903;
/// `mime_hdr_new`'s `OPENSSL_strdup(value)` (`:909`).
const LINE_HDR_NEW_STRDUP_VALUE: c_int = 909;
/// `mime_hdr_new`'s `OPENSSL_malloc(sizeof(*mhdr))` (`:914`).
const LINE_HDR_NEW_MALLOC: c_int = 914;
/// `mime_hdr_new`'s error-path free of `tmpname` (`:924`).
const LINE_HDR_NEW_FREE_NAME: c_int = 924;
/// `mime_hdr_new`'s error-path free of `tmpval` (`:925`).
const LINE_HDR_NEW_FREE_VALUE: c_int = 925;
/// `mime_hdr_new`'s error-path free of `mhdr` (`:926`).
const LINE_HDR_NEW_FREE_HDR: c_int = 926;
/// `mime_hdr_addparam`'s `OPENSSL_strdup(name)` (`:936`).
const LINE_ADDPARAM_STRDUP_NAME: c_int = 936;
/// `mime_hdr_addparam`'s `OPENSSL_strdup(value)` (`:944`).
const LINE_ADDPARAM_STRDUP_VALUE: c_int = 944;
/// `mime_hdr_addparam`'s `OPENSSL_malloc(sizeof(*mparam))` (`:948`).
const LINE_ADDPARAM_MALLOC: c_int = 948;
/// `mime_hdr_addparam`'s error-path free of `tmpname` (`:957`).
const LINE_ADDPARAM_FREE_NAME: c_int = 957;
/// `mime_hdr_addparam`'s error-path free of `tmpval` (`:958`).
const LINE_ADDPARAM_FREE_VALUE: c_int = 958;
/// `mime_hdr_addparam`'s error-path free of `mparam` (`:959`).
const LINE_ADDPARAM_FREE_PARAM: c_int = 959;
/// `mime_hdr_free`'s free of `hdr->name` (`:1010`).
const LINE_HDR_FREE_NAME: c_int = 1010;
/// `mime_hdr_free`'s free of `hdr->value` (`:1011`).
const LINE_HDR_FREE_VALUE: c_int = 1011;
/// `mime_hdr_free`'s free of `hdr` (`:1014`).
const LINE_HDR_FREE_HDR: c_int = 1014;
/// `mime_param_free`'s free of `param->param_name` (`:1019`).
const LINE_PARAM_FREE_NAME: c_int = 1019;
/// `mime_param_free`'s free of `param->param_value` (`:1020`).
const LINE_PARAM_FREE_VALUE: c_int = 1020;
/// `mime_param_free`'s free of `param` (`:1021`).
const LINE_PARAM_FREE_PARAM: c_int = 1021;

/// `MIME_INVALID` — `asn_mime.c:715`. The parser's state machine starts at
/// `MIME_START` and never enters this state, but the constant is the authority's own
/// and is kept beside its siblings.
#[allow(dead_code)]
const MIME_INVALID: c_int = 0;
/// `MIME_START` — `asn_mime.c:716`.
const MIME_START: c_int = 1;
/// `MIME_TYPE` — `asn_mime.c:717`.
const MIME_TYPE: c_int = 2;
/// `MIME_NAME` — `asn_mime.c:718`.
const MIME_NAME: c_int = 3;
/// `MIME_VALUE` — `asn_mime.c:719`.
const MIME_VALUE: c_int = 4;
/// `MIME_QUOTE` — `asn_mime.c:720`.
const MIME_QUOTE: c_int = 5;
/// `MIME_COMMENT` — `asn_mime.c:721`.
const MIME_COMMENT: c_int = 6;

/// `strip_eol` — cut the trailing line terminator and answer whether there was one.
///
/// Two branches, and the first is `cms.h`'s: with `CMS_BINARY` the line must end `\n`
/// and, with `SMIME_CRLFEOL`, `\r\n`; exactly those bytes are removed and nothing is
/// scanned. Otherwise the terminator is scanned for from the end: a `\n` sets the
/// answer, a `\r` is skipped, and — only once a `\n` has been seen and
/// `SMIME_ASCIICRLF` is set — a trailing space is skipped too and the scan continues.
/// `*plen` is left holding the line length *without* the terminator; on a line with no
/// terminator it drops only the `\r`s.
///
/// # Safety
///
/// `linebuf` must be writable for the `*plen` bytes the caller reports, and `plen` a
/// writable slot. The signed-`char` comparison is the authority's own.
pub(crate) unsafe fn strip_eol(linebuf: *mut c_char, plen: *mut c_int, flags: c_int) -> c_int {
    // SAFETY: the caller's contract.
    let mut len = unsafe { *plen };
    let mut is_eol = 0;

    if flags & CMS_BINARY != 0 {
        if len <= 0 {
            return 0;
        }
        // SAFETY: `len >= 1`, so the last byte is inside the caller's buffer.
        if unsafe { *linebuf.add(len as usize - 1) } != b'\n' as c_char {
            return 0;
        }
        if flags & SMIME_CRLFEOL != 0 {
            if len <= 1 {
                return 0;
            }
            // SAFETY: `len >= 2`.
            if unsafe { *linebuf.add(len as usize - 2) } != b'\r' as c_char {
                return 0;
            }
            len -= 1;
        }
        len -= 1;
        // SAFETY: `plen` is the caller's writable slot.
        unsafe { *plen = len };
        return 1;
    }

    let mut i = len;
    while i > 0 {
        // SAFETY: `i - 1` is inside the caller's buffer.
        let c = unsafe { *linebuf.add(i as usize - 1) };
        if c == b'\n' as c_char {
            is_eol = 1;
        } else if is_eol != 0 && flags & SMIME_ASCIICRLF != 0 && c == 32 {
            // A trailing space on a line whose EOL has already been seen: skipped,
            // and the scan continues. `32` is `' '` written as the authority spells
            // it.
        } else if c != b'\r' as c_char {
            break;
        }
        i -= 1;
    }
    // SAFETY: `plen` is the caller's writable slot.
    unsafe { *plen = i };
    is_eol
}

/// `int SMIME_crlf_copy(BIO *in, BIO *out, int flags)`
///
/// Copies `in` to `out` under the CRLF policy. The module header lists what is
/// observable; the two details worth repeating are that the copy is made *through* a
/// `BIO_f_buffer` pushed onto `out` and popped again, and that the final answer is the
/// flush's result **and** the copy's, in that order.
///
/// # Safety
///
/// `in_` and `out` must be null or live BIOs. A null one is refused with
/// `ERR_R_PASSED_NULL_PARAMETER` rather than dereferenced.
#[no_mangle]
pub unsafe extern "C" fn SMIME_crlf_copy(in_: *mut Bio, out: *mut Bio, flags: c_int) -> c_int {
    if in_.is_null() || out.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:554`).
        unsafe { raise_site(&err_sites::ASN_MIME_554) };
        return 0;
    }
    // SAFETY: `BIO_f_buffer` answers the buffer filter's method and `BIO_new` only
    // reads it.
    let bf = unsafe { BIO_new(BIO_f_buffer()) };
    if bf.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:564`).
        unsafe { raise_site(&err_sites::ASN_MIME_564) };
        return 0;
    }
    // SAFETY: `bf` and `out` are live BIOs.
    let chain = unsafe { BIO_push(bf, out) };

    let mut linebuf = [0 as c_char; MAX_SMLEN as usize];
    let mut ok = true;

    if flags & SMIME_BINARY != 0 {
        loop {
            // SAFETY: `in_` is a live BIO and `linebuf` holds `MAX_SMLEN` bytes.
            let len = unsafe { BIO_read(in_, linebuf.as_mut_ptr().cast(), MAX_SMLEN) };
            if len <= 0 {
                break;
            }
            // SAFETY: as above, and `len <= MAX_SMLEN`.
            if unsafe { BIO_write(chain, linebuf.as_ptr().cast(), len) } != len {
                ok = false;
                break;
            }
        }
    } else {
        let mut eolcnt = 0;
        if flags & SMIME_TEXT != 0 {
            // SAFETY: `chain` is live and the string is a static literal.
            if unsafe { BIO_puts(chain, c"Content-Type: text/plain\r\n\r\n".as_ptr()) } < 0 {
                ok = false;
            }
        }
        while ok {
            // SAFETY: `in_` is a live BIO and `linebuf` holds `MAX_SMLEN` bytes.
            let len = unsafe { BIO_gets(in_, linebuf.as_mut_ptr(), MAX_SMLEN) };
            if len <= 0 {
                break;
            }
            let mut len = len;
            // SAFETY: `linebuf` holds `len` bytes and `&mut len` is this frame's.
            let eol = unsafe { strip_eol(linebuf.as_mut_ptr(), &mut len, flags) };
            if len > 0 {
                if flags & SMIME_ASCIICRLF != 0 {
                    let mut i = 0;
                    while i < eolcnt {
                        // SAFETY: `chain` is live.
                        if unsafe { BIO_puts(chain, c"\r\n".as_ptr()) } < 0 {
                            ok = false;
                            break;
                        }
                        i += 1;
                    }
                    eolcnt = 0;
                    if !ok {
                        break;
                    }
                }
                // SAFETY: `linebuf` holds `len` bytes and `chain` is live.
                if unsafe { BIO_write(chain, linebuf.as_ptr().cast(), len) } != len {
                    ok = false;
                    break;
                }
                if eol != 0 {
                    // SAFETY: `chain` is live.
                    if unsafe { BIO_puts(chain, c"\r\n".as_ptr()) } < 0 {
                        ok = false;
                        break;
                    }
                }
            } else if flags & SMIME_ASCIICRLF != 0 {
                eolcnt += 1;
            } else if eol != 0 {
                // SAFETY: `chain` is live.
                if unsafe { BIO_puts(chain, c"\r\n".as_ptr()) } < 0 {
                    ok = false;
                    break;
                }
            }
        }
    }

    // The authority's single `err:` label: `ret = BIO_flush(out) > 0 && ret`. The
    // flush can turn a success into a failure; a failed copy cannot be turned back.
    // SAFETY: `chain` is a live BIO.
    let flushed =
        unsafe { BIO_ctrl(chain, BIO_CTRL_FLUSH, 0 as c_long, core::ptr::null_mut()) } > 0;
    let ret = c_int::from(flushed && ok);
    // SAFETY: `chain` is the pushed chain, so this unlinks `bf` from `out`.
    unsafe { BIO_pop(chain) };
    // SAFETY: `bf` is live and this function owns it.
    unsafe { BIO_free(bf) };
    ret
}

/// `int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
/// const ASN1_ITEM *it)`
///
/// With `SMIME_STREAM` the structure is emitted *around* a stream: `BIO_new_NDEF`
/// builds a filter chain that writes `val`'s header, the body is then streamed through
/// it from `in_`, and the chain is unwound with `BIO_pop` until it answers the caller's
/// own `out`. Without the flag the structure is encoded whole by `ASN1_item_i2d_bio`.
///
/// The unwind is why `val` is not `const`: `CMS_stream` and PKCS#7's equivalent pass a
/// value the NDEF filter's callback may fill in.
///
/// # Safety
///
/// `out` must be a live BIO. `in_` must be a live BIO when `SMIME_STREAM` is set, and
/// is not read otherwise. `it` must be a live item and `val` a live value of its type,
/// or null where the item tolerates it.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASN1_bio_stream(
    out: *mut Bio,
    val: *mut c_void,
    in_: *mut Bio,
    flags: c_int,
    it: *const Asn1Item,
) -> c_int {
    if flags & SMIME_STREAM == 0 {
        // SAFETY: `it`, `out` and `val` are live per the caller's contract.
        return unsafe { ASN1_item_i2d_bio(it, out, val) };
    }

    // SAFETY: `out` and `it` are live per the caller's contract.
    let mut bio = unsafe { BIO_new_NDEF(out, val, it) };
    if bio.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:79`).
        unsafe { raise_site(&err_sites::ASN_MIME_79) };
        return 0;
    }
    let mut rv = 1;
    // SAFETY: `in_` and `bio` are live BIOs, which is that function's contract.
    if unsafe { SMIME_crlf_copy(in_, bio, flags) } == 0 {
        rv = 0;
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_ctrl(bio, BIO_CTRL_FLUSH, 0 as c_long, core::ptr::null_mut()) };
    // Free successive BIOs until we hit the old output BIO. The authority's loop is
    // `while (bio != out)` with no null test, so a chain that never reaches `out` spins
    // forever there; this one stops. See D-MIME-1.
    loop {
        // SAFETY: `bio` is live.
        let tbio = unsafe { BIO_pop(bio) };
        // SAFETY: `bio` is live and owned by this function.
        unsafe { BIO_free(bio) };
        bio = tbio;
        if bio == out || bio.is_null() {
            break;
        }
    }
    rv
}

// ---------------------------------------------------------------------------------------------
// `crypto/asn1/asn_mime.c` — the file-static helpers the five exports reach.
// ---------------------------------------------------------------------------------------------

/// `struct mime_param_st` — `asn_mime.c:32-35`.
#[repr(C)]
struct MimeParam {
    /// `char *param_name` — e.g. `"boundary"`, lower-cased.
    param_name: *mut c_char,
    /// `char *param_value` — e.g. the boundary itself; parameter values keep their case.
    param_value: *mut c_char,
}

/// `struct mime_header_st` — `asn_mime.c:37-41`.
#[repr(C)]
struct MimeHeader {
    /// `char *name` — e.g. `"content-type"`, lower-cased.
    name: *mut c_char,
    /// `char *value` — e.g. `"text/plain"`, lower-cased.
    value: *mut c_char,
    /// `STACK_OF(MIME_PARAM) *params` — zero or more parameters.
    params: *mut OpenSslStack,
}

/// `static int B64_write_ASN1(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
/// const ASN1_ITEM *it)` — `crypto/asn1/asn_mime.c:105-124`.
///
/// A `BIO_f_base64` is pushed in front of `out`, the stream is written through it, and
/// the filter is popped and freed again. The flush is `(void)`: the authority discards
/// its result and answers only what `i2d_ASN1_bio_stream` said.
///
/// # Safety
///
/// `out` must be a live BIO. `in_` must be a live BIO when `flags` has `SMIME_STREAM`
/// and is unread otherwise. `val` and `it` are `i2d_ASN1_bio_stream`'s.
#[allow(non_snake_case)] // the authority's `B64_write_ASN1` name is kept
unsafe fn B64_write_ASN1(
    out: *mut Bio,
    val: *mut c_void,
    in_: *mut Bio,
    flags: c_int,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the method table is a compile-time constant.
    let b64 = unsafe { BIO_new(BIO_f_base64()) };
    if b64.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:112`).
        unsafe { raise_site(&err_sites::ASN_MIME_112) };
        return 0;
    }
    // Prepend the b64 BIO so all data is base64 encoded.
    // SAFETY: `b64` is live and `out` is the caller's.
    let out = unsafe { BIO_push(b64, out) };
    // SAFETY: `out` is live and the rest are the caller's.
    let r = unsafe { i2d_ASN1_bio_stream(out, val, in_, flags, it) };
    // SAFETY: `out` is live; the pop/free pair balances the push above.
    unsafe {
        let _ = BIO_ctrl(out, BIO_CTRL_FLUSH, 0 as c_long, ptr::null_mut());
        BIO_pop(out);
        BIO_free(b64);
    }
    r
}

/// `static ASN1_VALUE *b64_read_asn1(BIO *bio, const ASN1_ITEM *it, ASN1_VALUE **x,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/asn_mime.c:136-154`.
///
/// # Safety
///
/// `bio` must be a live BIO; `it` a live item; `x` null or a live value slot; `libctx`
/// null or live and `propq` null or NUL-terminated.
unsafe fn b64_read_asn1(
    bio: *mut Bio,
    it: *const Asn1Item,
    x: *mut *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: the method table is a compile-time constant.
    let b64 = unsafe { BIO_new(BIO_f_base64()) };
    if b64.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:143`).
        unsafe { raise_site(&err_sites::ASN_MIME_143) };
        return ptr::null_mut();
    }
    // SAFETY: `b64` is live and `bio` is the caller's.
    let bio = unsafe { BIO_push(b64, bio) };
    // SAFETY: `bio` is live and the rest are the caller's; `x` is the value slot cast to
    // the item layer's `void *`.
    let val = unsafe { ASN1_item_d2i_bio_ex(it, bio, x.cast::<c_void>(), libctx, propq) };
    if val.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:149`).
        unsafe { raise_site(&err_sites::ASN_MIME_149) };
    }
    // SAFETY: `bio` is live; the pop/free pair balances the push above.
    unsafe {
        let _ = BIO_ctrl(bio, BIO_CTRL_FLUSH, 0 as c_long, ptr::null_mut());
        BIO_pop(bio);
        BIO_free(b64);
    }
    val
}

/// `static int asn1_write_micalg(BIO *out, STACK_OF(X509_ALGOR) *mdalgs)` —
/// `crypto/asn1/asn_mime.c:158-254`.
///
/// Writes the comma-separated `micalg` parameter. SHAKE is named `shake-128`/
/// `shake-256` before the digest lookup; every other digest is first offered to the
/// method's `md_ctrl` (`EVP_MD_CTRL_MICALG`) and, when that answers `-2` or there is no
/// method, named by the authority's own `switch`. The section on the module header
/// records why the `md_ctrl` arm cannot be entered until Phase 13.
///
/// # Safety
///
/// `out` must be a live BIO; `mdalgs` must be null or a live `STACK_OF(X509_ALGOR)`
/// whose elements are live `X509_ALGOR`s.
unsafe fn asn1_write_micalg(out: *mut Bio, mdalgs: *mut OpenSslStack) -> c_int {
    let mut have_unknown = 0;
    let mut write_comma = 0;
    let mut ret = 0;
    'err: {
        // SAFETY: `mdalgs` is null or a live stack.
        let n = unsafe { OPENSSL_sk_num(mdalgs) };
        let mut i = 0;
        while i < n {
            if write_comma != 0 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c",".as_ptr()) } < 0 {
                    break 'err;
                }
            }
            write_comma = 1;
            // SAFETY: `i < n`, so this is one of the stack's own elements.
            let algor = unsafe { OPENSSL_sk_value(mdalgs, i) }.cast::<X509Algor>();
            // SAFETY: `algor` is a live `X509_ALGOR`.
            let md_nid = unsafe { OBJ_obj2nid((*algor).algorithm) };

            // RFC 8702 does not define a micalg for SHAKE, assuming "shake-<bitlen>".
            if md_nid == NID_shake128 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"shake-128".as_ptr()) } < 0 {
                    break 'err;
                }
                i += 1;
                continue;
            }
            if md_nid == NID_shake256 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"shake-256".as_ptr()) } < 0 {
                    break 'err;
                }
                i += 1;
                continue;
            }

            // `EVP_get_digestbynid(md_nid)` is the macro
            // `EVP_get_digestbyname(OBJ_nid2sn(md_nid))`. The name table answers NULL
            // for built-ins until Phase 13 (module header), so this arm is transcribed
            // and compiles but is not entered.
            // SAFETY: `OBJ_nid2sn` answers a static string or NULL, which
            // `EVP_get_digestbyname` treats as "unknown".
            let md = unsafe { EVP_get_digestbyname(OBJ_nid2sn(md_nid)) };
            if !md.is_null() {
                // SAFETY: `md` is live.
                if let Some(ctrl) = unsafe { (*md).md_ctrl } {
                    let mut micstr: *mut c_char = ptr::null_mut();
                    // SAFETY: the ctrl is the method's own and `micstr` is the output
                    // slot its `MICALG` command fills; the authority passes a NULL
                    // digest context.
                    let mut rv = unsafe {
                        ctrl(
                            ptr::null_mut(),
                            EVP_MD_CTRL_MICALG,
                            0,
                            (&raw mut micstr).cast::<c_void>(),
                        )
                    };
                    if rv > 0 {
                        // SAFETY: `out` is live and `micstr` is the ctrl's string.
                        rv = unsafe { BIO_puts(out, micstr) };
                        // SAFETY: `micstr` is the allocation the ctrl made and the
                        // authority frees it here (`crypto/asn1/asn_mime.c:189`).
                        unsafe {
                            CRYPTO_free(micstr.cast::<c_void>(), FILE.as_ptr(), LINE_MICALG_FREE)
                        };
                        if rv < 0 {
                            break 'err;
                        }
                        i += 1;
                        continue;
                    }
                    if rv != -2 {
                        break 'err;
                    }
                }
            }

            if md_nid == NID_sha1 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"sha1".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_md5 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"md5".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_sha256 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"sha-256".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_sha384 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"sha-384".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_sha512 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"sha-512".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_id_GostR3411_94 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"gostr3411-94".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_id_GostR3411_2012_256 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"gostr3411-2012-256".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if md_nid == NID_id_GostR3411_2012_512 {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"gostr3411-2012-512".as_ptr()) } < 0 {
                    break 'err;
                }
            } else if have_unknown != 0 {
                write_comma = 0;
            } else {
                // SAFETY: `out` is live and the literal is static.
                if unsafe { BIO_puts(out, c"unknown".as_ptr()) } < 0 {
                    break 'err;
                }
                have_unknown = 1;
            }
            i += 1;
        }
        ret = 1;
    }
    ret
}

/// `int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
/// int ctype_nid, int econt_nid, STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/asn1/asn_mime.c:258-364`.
///
/// With `SMIME_DETACHED` and a `data` BIO the writer emits a `multipart/signed` body:
/// a random 32-nibble boundary, the `micalg` list, the two parts, and the base64
/// signature. Otherwise it emits one opaque part whose `smime-type` header is chosen
/// from `ctype_nid`/`econt_nid`.
///
/// # Safety
///
/// `bio` must be the live sink; `data` null or live; `val` and `it` as the encoder
/// requires; `mdalgs` null or a live `STACK_OF(X509_ALGOR)`; `libctx` null or live;
/// `propq` null or NUL-terminated.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn SMIME_write_ASN1_ex(
    bio: *mut Bio,
    val: *mut c_void,
    data: *mut Bio,
    flags: c_int,
    ctype_nid: c_int,
    econt_nid: c_int,
    mdalgs: *mut OpenSslStack,
    it: *const Asn1Item,
    libctx: *mut c_void,
    _propq: *const c_char,
) -> c_int {
    let mut bound = [0 as c_char; 33];
    let mut cname: *const c_char = c"smime.p7m".as_ptr();
    let mut msg_type: *const c_char = ptr::null();

    let mime_prefix: *const c_char = if flags & SMIME_OLDMIME != 0 {
        c"application/x-pkcs7-".as_ptr()
    } else {
        c"application/pkcs7-".as_ptr()
    };
    let mime_eol: *const c_char = if flags & SMIME_CRLFEOL != 0 {
        c"\r\n".as_ptr()
    } else {
        c"\n".as_ptr()
    };

    if flags & SMIME_DETACHED != 0 && !data.is_null() {
        // We want multipart/signed. Generate a random boundary.
        // SAFETY: `bound` holds 32 writable bytes and `libctx` is the caller's.
        if unsafe { RAND_bytes_ex(libctx, bound.as_mut_ptr().cast::<u8>(), 32, 0) } <= 0 {
            return 0;
        }
        let mut i = 0;
        while i < 32 {
            let cb = bound[i] as c_int;
            let mut c = cb & 0xf;
            if c < 10 {
                c += b'0' as c_int;
            } else {
                c += b'A' as c_int - 10;
            }
            bound[i] = c as c_char;
            i += 1;
        }
        bound[32] = 0;
        // SAFETY: `bio` is live and every string argument is static.
        if unsafe {
            BIO_printf(
                bio,
                c"MIME-Version: 1.0%sContent-Type: multipart/signed; protocol=\"%ssignature\"; micalg=\"".as_ptr(),
                mime_eol,
                mime_prefix,
            )
        } < 0
        {
            return 0;
        }
        // SAFETY: `bio` is live and `mdalgs` is null or a live stack.
        if unsafe { asn1_write_micalg(bio, mdalgs) } == 0 {
            return 0;
        }
        // SAFETY: `bio` is live and every argument is a static string or `bound`.
        if unsafe {
            BIO_printf(
                bio,
                c"\"; boundary=\"----%s\"%s%sThis is an S/MIME signed message%s%s------%s%s"
                    .as_ptr(),
                bound.as_ptr(),
                mime_eol,
                mime_eol,
                mime_eol,
                mime_eol,
                bound.as_ptr(),
                mime_eol,
            )
        } < 0
        {
            return 0;
        }
        // SAFETY: `data`/`bio` are live BIOs and the rest are the caller's.
        if unsafe { asn1_output_data(bio, data, val, flags, it) } == 0 {
            return 0;
        }
        // SAFETY: `bio` is live and the arguments are static or `bound`.
        if unsafe {
            BIO_printf(
                bio,
                c"%s------%s%s".as_ptr(),
                mime_eol,
                bound.as_ptr(),
                mime_eol,
            )
        } < 0
        {
            return 0;
        }

        // Headers for the signature.
        // SAFETY: `bio` is live and every string argument is static.
        if unsafe {
            BIO_printf(
                bio,
                c"Content-Type: %ssignature; name=\"smime.p7s\"%sContent-Transfer-Encoding: base64%sContent-Disposition: attachment; filename=\"smime.p7s\"%s%s".as_ptr(),
                mime_prefix,
                mime_eol,
                mime_eol,
                mime_eol,
                mime_eol,
            )
        } < 0
        {
            return 0;
        }
        // SAFETY: `bio` is live; `val`/`it` are the caller's.
        if unsafe { B64_write_ASN1(bio, val, ptr::null_mut(), 0, it) } == 0 {
            return 0;
        }
        // SAFETY: `bio` is live and every argument is static or `bound`.
        if unsafe {
            BIO_printf(
                bio,
                c"%s------%s--%s%s".as_ptr(),
                mime_eol,
                bound.as_ptr(),
                mime_eol,
                mime_eol,
            )
        } < 0
        {
            return 0;
        }
        return 1;
    }

    // Determine the smime-type header.
    if ctype_nid == NID_pkcs7_enveloped {
        msg_type = c"enveloped-data".as_ptr();
    } else if ctype_nid == NID_id_smime_ct_authEnvelopedData {
        msg_type = c"authEnveloped-data".as_ptr();
    } else if ctype_nid == NID_pkcs7_signed {
        if econt_nid == NID_id_smime_ct_receipt {
            msg_type = c"signed-receipt".as_ptr();
        // SAFETY: `mdalgs` is null or a live stack.
        } else if unsafe { OPENSSL_sk_num(mdalgs) } >= 0 {
            msg_type = c"signed-data".as_ptr();
        } else {
            msg_type = c"certs-only".as_ptr();
        }
    } else if ctype_nid == NID_id_smime_ct_compressedData {
        msg_type = c"compressed-data".as_ptr();
        cname = c"smime.p7z".as_ptr();
    }
    // MIME headers.
    // SAFETY: `bio` is live and the arguments are static strings.
    if unsafe {
        BIO_printf(
            bio,
            c"MIME-Version: 1.0%sContent-Disposition: attachment; filename=\"%s\"%s".as_ptr(),
            mime_eol,
            cname,
            mime_eol,
        )
    } < 0
    {
        return 0;
    }
    // SAFETY: `bio` is live and the arguments are static strings.
    if unsafe { BIO_printf(bio, c"Content-Type: %smime;".as_ptr(), mime_prefix) } < 0 {
        return 0;
    }
    // SAFETY: `msg_type` is null or a static string; `bio` is live.
    if !msg_type.is_null() && unsafe { BIO_printf(bio, c" smime-type=%s;".as_ptr(), msg_type) } < 0
    {
        return 0;
    }
    // SAFETY: `bio` is live and the arguments are static strings.
    if unsafe {
        BIO_printf(
            bio,
            c" name=\"%s\"%sContent-Transfer-Encoding: base64%s%s".as_ptr(),
            cname,
            mime_eol,
            mime_eol,
            mime_eol,
        )
    } < 0
    {
        return 0;
    }
    // SAFETY: `bio`/`data` are live or null per the contract and the rest are the
    // caller's.
    if unsafe { B64_write_ASN1(bio, val, data, flags, it) } == 0 {
        return 0;
    }
    // SAFETY: `bio` is live and the format's only argument is the static `mime_eol`.
    c_int::from(unsafe { BIO_printf(bio, c"%s".as_ptr(), mime_eol) } >= 0)
}

/// `int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
/// int ctype_nid, int econt_nid, STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it)` —
/// `crypto/asn1/asn_mime.c:366-372`.
///
/// The context-free delegate: every argument is forwarded and `NULL, NULL` are passed
/// for `libctx`/`propq`.
///
/// # Safety
///
/// As [`SMIME_write_ASN1_ex`], with the two context arguments null.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub unsafe extern "C" fn SMIME_write_ASN1(
    bio: *mut Bio,
    val: *mut c_void,
    data: *mut Bio,
    flags: c_int,
    ctype_nid: c_int,
    econt_nid: c_int,
    mdalgs: *mut OpenSslStack,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: every argument is the caller's and the two context arguments are null.
    unsafe {
        SMIME_write_ASN1_ex(
            bio,
            val,
            data,
            flags,
            ctype_nid,
            econt_nid,
            mdalgs,
            it,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `static int asn1_output_data(BIO *out, BIO *data, ASN1_VALUE *val, int flags,
/// const ASN1_ITEM *it)` — `crypto/asn1/asn_mime.c:377-424`.
///
/// Either the data is copied straight through (not detached, or resigning), or the
/// item's `ASN1_OP_DETACHED_PRE`/`_POST` callback is run around a copy through the
/// filter BIOs it prepends, and those filters are then unwound. The authority's unwind
/// is `while (sarg.ndef_bio != out)` with no null test, so a chain that never reaches
/// `out` spins forever there; this one stops at NULL too. See `D-MIME-1`.
///
/// # Safety
///
/// `out`/`data` must be live BIOs; `val` and `it` as the encoder requires.
unsafe fn asn1_output_data(
    out: *mut Bio,
    data: *mut Bio,
    val: *mut c_void,
    flags: c_int,
    it: *const Asn1Item,
) -> c_int {
    // If data is not detached or is resigning then the output BIO is already set up to
    // finalise when it is written through.
    if flags & SMIME_DETACHED == 0 || flags & PKCS7_REUSE_DIGEST != 0 {
        // SAFETY: `data`/`out` are live BIOs.
        return unsafe { SMIME_crlf_copy(data, out, flags) };
    }

    // SAFETY: `it` is a live item.
    let aux = unsafe { (*it).funcs as *const Asn1Aux };
    if aux.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:394`).
        unsafe { raise_site(&err_sites::ASN_MIME_394) };
        return 0;
    }
    // SAFETY: `aux` is the item's `funcs`, which for a templated item is an `ASN1_AUX`.
    let Some(cb) = (unsafe { (*aux).asn1_cb }) else {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:394`).
        unsafe { raise_site(&err_sites::ASN_MIME_394) };
        return 0;
    };

    let mut val = val;
    let mut sarg = Asn1StreamArg {
        out,
        ndef_bio: ptr::null_mut(),
        boundary: ptr::null_mut(),
    };

    // Let the ASN1 code prepend any needed BIOs.
    // SAFETY: `cb` is the item's callback, `val`/`sarg` are live locals and `it` is the
    // caller's item.
    if unsafe {
        cb(
            ASN1_OP_DETACHED_PRE,
            &raw mut val,
            it,
            (&raw mut sarg).cast::<c_void>(),
        )
    } <= 0
    {
        return 0;
    }
    let mut rv = 1;
    // Copy data across, passing through filter BIOs for processing.
    // SAFETY: `data` and `sarg.ndef_bio` are live BIOs.
    if unsafe { SMIME_crlf_copy(data, sarg.ndef_bio, flags) } == 0 {
        rv = 0;
    }
    // Finalize structure.
    // SAFETY: `cb` is the item's callback, `val`/`sarg` are live locals and `it` is the
    // caller's item.
    if unsafe {
        cb(
            ASN1_OP_DETACHED_POST,
            &raw mut val,
            it,
            (&raw mut sarg).cast::<c_void>(),
        )
    } <= 0
    {
        rv = 0;
    }

    // Now remove any digests prepended to the BIO. The authority's loop is
    // `while (sarg.ndef_bio != out)` with no null test; this one stops at NULL too and
    // records the divergence as D-MIME-1.
    while sarg.ndef_bio != out {
        // SAFETY: `sarg.ndef_bio` is live.
        let tmpbio = unsafe { BIO_pop(sarg.ndef_bio) };
        // SAFETY: `sarg.ndef_bio` is live and owned by this frame.
        unsafe { BIO_free(sarg.ndef_bio) };
        sarg.ndef_bio = tmpbio;
        if sarg.ndef_bio.is_null() {
            break;
        }
    }
    rv
}

/// Format the authority's `"type: %s"` `ERR_raise_data` operand into `msg`.
///
/// # Safety
///
/// `msg` must be writable for its whole length and `value` NUL-terminated.
unsafe fn mime_type_msg(msg: *mut c_char, len: usize, value: *const c_char) {
    // SAFETY: `msg` is writable for `len` bytes and `value` is NUL-terminated.
    unsafe { BIO_snprintf(msg, len, c"type: %s".as_ptr(), value) };
}

/// `ASN1_VALUE *SMIME_read_ASN1_ex(BIO *bio, int flags, BIO **bcont,
/// const ASN1_ITEM *it, ASN1_VALUE **x, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/asn1/asn_mime.c:432-537`.
///
/// `multipart/signed` is split into its two parts and the signature part decoded;
/// otherwise the body must be an opaque `application/pkcs7-mime` and is decoded whole.
///
/// # Safety
///
/// `bio` must be a live BIO; `bcont` null or writable; `it` a live item; `x` null or a
/// live value slot; `libctx` null or live; `propq` null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SMIME_read_ASN1_ex(
    bio: *mut Bio,
    flags: c_int,
    bcont: *mut *mut Bio,
    it: *const Asn1Item,
    x: *mut *mut c_void,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    if !bcont.is_null() {
        // SAFETY: `bcont` is writable per the contract.
        unsafe { *bcont = ptr::null_mut() };
    }

    // SAFETY: `bio` is a live BIO.
    let mut headers = unsafe { mime_parse_hdr(bio) };
    if headers.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:448`).
        unsafe { raise_site(&err_sites::ASN_MIME_448) };
        return ptr::null_mut();
    }

    // SAFETY: `headers` is a live stack of headers.
    let mut hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };
    // SAFETY: `hdr` is null or one of the stack's own headers.
    if hdr.is_null() || unsafe { (*hdr).value }.is_null() {
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:455`).
        unsafe { raise_site(&err_sites::ASN_MIME_455) };
        return ptr::null_mut();
    }

    // Handle multipart/signed.
    // SAFETY: `hdr->value` is non-null and NUL-terminated.
    if unsafe { strcmp((*hdr).value, c"multipart/signed".as_ptr()) } == 0 {
        // Split into two parts.
        // SAFETY: `hdr` is a live header.
        let prm = unsafe { mime_param_find(hdr, c"boundary".as_ptr()) };
        // SAFETY: `prm` is null or one of the header's own parameters.
        if prm.is_null() || unsafe { (*prm).param_value }.is_null() {
            // SAFETY: `headers` is this frame's own stack.
            unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
            // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:466`).
            unsafe { raise_site(&err_sites::ASN_MIME_466) };
            return ptr::null_mut();
        }
        let mut parts: *mut OpenSslStack = ptr::null_mut();
        // SAFETY: `bio` is live, `prm->param_value` is NUL-terminated and `parts` is a
        // writable slot.
        let ret = unsafe { multi_split(bio, flags, (*prm).param_value, &mut parts) };
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        // SAFETY: `parts` is null or the stack `multi_split` answered.
        if ret == 0 || unsafe { OPENSSL_sk_num(parts) } != 2 {
            // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:472`).
            unsafe { raise_site(&err_sites::ASN_MIME_472) };
            // SAFETY: `parts` is null or this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
            return ptr::null_mut();
        }

        // Parse the signature piece.
        // SAFETY: `parts` holds two BIOs.
        let asnin = unsafe { OPENSSL_sk_value(parts, 1) }.cast::<Bio>();

        // SAFETY: `asnin` is a live BIO.
        headers = unsafe { mime_parse_hdr(asnin) };
        if headers.is_null() {
            // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:481`).
            unsafe { raise_site(&err_sites::ASN_MIME_481) };
            // SAFETY: `parts` is this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
            return ptr::null_mut();
        }

        // Get the content type.
        // SAFETY: `headers` is a live stack.
        hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };
        // SAFETY: `hdr` is null or one of the stack's own headers.
        if hdr.is_null() || unsafe { (*hdr).value }.is_null() {
            // SAFETY: `headers` is this frame's own stack.
            unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
            // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:491`).
            unsafe { raise_site(&err_sites::ASN_MIME_491) };
            // SAFETY: `parts` is this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
            return ptr::null_mut();
        }

        // SAFETY: `hdr->value` is non-null and NUL-terminated; the literals are static.
        let sig_type_a =
            unsafe { strcmp((*hdr).value, c"application/x-pkcs7-signature".as_ptr()) } != 0;
        // SAFETY: as above.
        let sig_type_b =
            unsafe { strcmp((*hdr).value, c"application/pkcs7-signature".as_ptr()) } != 0;
        if sig_type_a && sig_type_b {
            let mut msg = [0 as c_char; MAX_SMLEN as usize + 8];
            // SAFETY: `msg` is writable and `(*hdr).value` is NUL-terminated.
            unsafe { mime_type_msg(msg.as_mut_ptr(), msg.len(), (*hdr).value) };
            // SAFETY: a compile-time-constant site; `msg` is NUL-terminated.
            unsafe { raise_site_data(&err_sites::ASN_MIME_497, msg.as_ptr()) };
            // SAFETY: `headers` is this frame's own stack.
            unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
            // SAFETY: `parts` is this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
            return ptr::null_mut();
        }
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        // Read in ASN1.
        // SAFETY: `asnin` is a live BIO and the rest are the caller's.
        let val = unsafe { b64_read_asn1(asnin, it, x, libctx, propq) };
        if val.is_null() {
            // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:506`).
            unsafe { raise_site(&err_sites::ASN_MIME_506) };
            // SAFETY: `parts` is this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
            return ptr::null_mut();
        }

        if !bcont.is_null() {
            // SAFETY: `parts` holds two BIOs.
            unsafe { *bcont = OPENSSL_sk_value(parts, 0).cast::<Bio>() };
            // SAFETY: `asnin` is a live BIO this frame owns.
            unsafe { BIO_free(asnin) };
            // SAFETY: `parts` is this frame's own stack; its remaining element is not
            // freed here because it was just handed to `*bcont`.
            unsafe { OPENSSL_sk_free(parts) };
        } else {
            // SAFETY: `parts` is this frame's own stack of BIOs.
            unsafe { OPENSSL_sk_pop_free(parts, Some(bio_vfree_thunk)) };
        }
        return val;
    }

    // OK, if not multipart/signed try the opaque signature.
    // SAFETY: `hdr->value` is non-null and NUL-terminated; the literals are static.
    let mime_type_a = unsafe { strcmp((*hdr).value, c"application/x-pkcs7-mime".as_ptr()) } != 0;
    // SAFETY: as above.
    let mime_type_b = unsafe { strcmp((*hdr).value, c"application/pkcs7-mime".as_ptr()) } != 0;
    if mime_type_a && mime_type_b {
        let mut msg = [0 as c_char; MAX_SMLEN as usize + 8];
        // SAFETY: `msg` is writable and `(*hdr).value` is NUL-terminated.
        unsafe { mime_type_msg(msg.as_mut_ptr(), msg.len(), (*hdr).value) };
        // SAFETY: a compile-time-constant site; `msg` is NUL-terminated.
        unsafe { raise_site_data(&err_sites::ASN_MIME_524, msg.as_ptr()) };
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        return ptr::null_mut();
    }
    // SAFETY: `headers` is this frame's own stack.
    unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };

    // SAFETY: `bio` is a live BIO and the rest are the caller's.
    let val = unsafe { b64_read_asn1(bio, it, x, libctx, propq) };
    if val.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:533`).
        unsafe { raise_site(&err_sites::ASN_MIME_533) };
        return ptr::null_mut();
    }
    val
}

/// `ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it)` —
/// `crypto/asn1/asn_mime.c:539-543`.
///
/// The context-free delegate: `flags = 0`, `x = libctx = NULL`, `propq = NULL`.
///
/// # Safety
///
/// `bio` must be a live BIO; `bcont` null or writable; `it` a live item.
#[no_mangle]
pub unsafe extern "C" fn SMIME_read_ASN1(
    bio: *mut Bio,
    bcont: *mut *mut Bio,
    it: *const Asn1Item,
) -> *mut c_void {
    // SAFETY: every argument is the caller's; `flags` is 0 and the value/context slots
    // are null.
    unsafe {
        SMIME_read_ASN1_ex(
            bio,
            0,
            bcont,
            it,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int SMIME_text(BIO *in, BIO *out)` — `crypto/asn1/asn_mime.c:612-640`.
///
/// Strips a `text/plain` header block from `in_` and copies the body to `out`. The
/// answer is the last `BIO_read` result `>= 0`, so a clean EOF reports success.
///
/// # Safety
///
/// `in_`/`out` must be live BIOs.
#[no_mangle]
pub unsafe extern "C" fn SMIME_text(in_: *mut Bio, out: *mut Bio) -> c_int {
    let mut iobuf = [0 as c_char; 4096];
    // SAFETY: `in_` is a live BIO.
    let headers = unsafe { mime_parse_hdr(in_) };
    if headers.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:620`).
        unsafe { raise_site(&err_sites::ASN_MIME_620) };
        return 0;
    }
    // SAFETY: `headers` is a live stack.
    let hdr = unsafe { mime_hdr_find(headers, c"content-type".as_ptr()) };
    // SAFETY: `hdr` is null or one of the stack's own headers.
    if hdr.is_null() || unsafe { (*hdr).value }.is_null() {
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:625`).
        unsafe { raise_site(&err_sites::ASN_MIME_625) };
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        return 0;
    }
    // SAFETY: `hdr->value` is non-null and NUL-terminated; the literal is static.
    if unsafe { strcmp((*hdr).value, c"text/plain".as_ptr()) } != 0 {
        let mut msg = [0 as c_char; MAX_SMLEN as usize + 8];
        // SAFETY: `msg` is writable and `(*hdr).value` is NUL-terminated.
        unsafe { mime_type_msg(msg.as_mut_ptr(), msg.len(), (*hdr).value) };
        // SAFETY: a compile-time-constant site (`crypto/asn1/asn_mime.c:630`).
        unsafe { raise_site_data(&err_sites::ASN_MIME_630, msg.as_ptr()) };
        // SAFETY: `headers` is this frame's own stack.
        unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
        return 0;
    }
    // SAFETY: `headers` is this frame's own stack.
    unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };

    let mut len: c_int;
    loop {
        // SAFETY: `in_` is a live BIO and `iobuf` holds 4096 bytes.
        len = unsafe {
            BIO_read(
                in_,
                iobuf.as_mut_ptr().cast::<c_void>(),
                iobuf.len() as c_int,
            )
        };
        if len <= 0 {
            break;
        }
        // SAFETY: `iobuf` holds `len` bytes and `out` is a live BIO.
        if unsafe { BIO_write(out, iobuf.as_ptr().cast::<c_void>(), len) } != len && !out.is_null()
        {
            return 0;
        }
    }
    c_int::from(len >= 0)
}

/// `static int multi_split(BIO *bio, int flags, const char *bound, STACK_OF(BIO) **ret)` —
/// `crypto/asn1/asn_mime.c:647-711`.
///
/// Splits a `multipart/XXX` body into one memory BIO per part, answering the stack
/// through `ret`. Each part's final terminator becomes the next part's first, which is
/// why the previous line's `eol` is replayed before the current line's bytes.
///
/// # Safety
///
/// `bio` must be a live BIO; `bound` NUL-terminated; `ret` writable.
unsafe fn multi_split(
    bio: *mut Bio,
    flags: c_int,
    bound: *const c_char,
    ret: *mut *mut OpenSslStack,
) -> c_int {
    let mut linebuf = [0 as c_char; MAX_SMLEN as usize];
    // SAFETY: `bound` is NUL-terminated per the contract.
    let blen_s = unsafe { strlen(bound) };
    let mut eol = 0;
    let mut bpart: *mut Bio = ptr::null_mut();
    let mut part = 0;
    let mut first = 1;

    if blen_s > MAX_SMLEN as usize {
        return 0;
    }
    let blen = blen_s as c_int;

    // SAFETY: `OPENSSL_sk_new_null` allocates a fresh stack.
    let parts = OPENSSL_sk_new_null();
    // SAFETY: `ret` is writable per the contract.
    unsafe { *ret = parts };
    if parts.is_null() {
        return 0;
    }
    loop {
        // SAFETY: `bio` is live and `linebuf` holds `MAX_SMLEN` bytes.
        let len = unsafe { BIO_get_line(bio, linebuf.as_mut_ptr(), MAX_SMLEN) };
        if len <= 0 {
            break;
        }
        // SAFETY: `linebuf` holds `len` bytes and `bound`/`blen` describe the boundary.
        let state = unsafe { mime_bound_check(linebuf.as_mut_ptr(), len, bound, blen) };
        if state == 1 {
            first = 1;
            part += 1;
        } else if state == 2 {
            // SAFETY: `parts` is live and `bpart` is this frame's own part BIO.
            if unsafe { OPENSSL_sk_push(parts, bpart.cast::<c_void>()) } == 0 {
                // SAFETY: `bpart` is this frame's own BIO.
                unsafe { BIO_free(bpart) };
                return 0;
            }
            return 1;
        } else if part != 0 {
            let mut len = len;
            // Strip (possibly CR +) LF from linebuf.
            // SAFETY: `linebuf` holds `len` bytes and `&mut len` is this frame's.
            let next_eol = unsafe { strip_eol(linebuf.as_mut_ptr(), &mut len, flags) };
            if first != 0 {
                first = 0;
                if !bpart.is_null() {
                    // SAFETY: `parts` is live and `bpart` is this frame's own BIO.
                    if unsafe { OPENSSL_sk_push(parts, bpart.cast::<c_void>()) } == 0 {
                        // SAFETY: `bpart` is this frame's own BIO.
                        unsafe { BIO_free(bpart) };
                        return 0;
                    }
                }
                // SAFETY: the memory method is a compile-time constant.
                bpart = unsafe { BIO_new(BIO_s_mem()) };
                if bpart.is_null() {
                    return 0;
                }
                // `BIO_set_mem_eof_return(bpart, 0)`.
                // SAFETY: `bpart` is a live memory BIO.
                unsafe {
                    let _ = BIO_ctrl(
                        bpart,
                        BIO_C_SET_BUF_MEM_EOF_RETURN,
                        0 as c_long,
                        ptr::null_mut(),
                    );
                }
            } else if eol != 0 {
                if flags & CMS_BINARY == 0 || flags & SMIME_CRLFEOL != 0 {
                    // SAFETY: `bpart` is a live BIO and the literal is static.
                    if unsafe { BIO_puts(bpart, c"\r\n".as_ptr()) } < 0 {
                        // SAFETY: `bpart` is this frame's own BIO.
                        unsafe { BIO_free(bpart) };
                        return 0;
                    }
                } else {
                    // SAFETY: `bpart` is a live BIO and the literal is static.
                    if unsafe { BIO_puts(bpart, c"\n".as_ptr()) } < 0 {
                        // SAFETY: `bpart` is this frame's own BIO.
                        unsafe { BIO_free(bpart) };
                        return 0;
                    }
                }
            }
            eol = next_eol;
            if len > 0 {
                // SAFETY: `linebuf` holds `len` bytes and `bpart` is a live BIO.
                if unsafe { BIO_write(bpart, linebuf.as_ptr().cast::<c_void>(), len) } != len {
                    // SAFETY: `bpart` is this frame's own BIO.
                    unsafe { BIO_free(bpart) };
                    return 0;
                }
            }
        }
    }
    // err:
    // SAFETY: `bpart` is null or this frame's own BIO.
    unsafe { BIO_free(bpart) };
    0
}

/// `mime_debug(x)` — `asn_mime.c:64`. The authority deletes its argument at
/// preprocessing time; this consumes it so the calls can stay where they are.
macro_rules! mime_debug {
    ($($arg:tt)*) => {{
        let _: &str = $($arg)*;
    }};
}

/// `static STACK_OF(MIME_HEADER) *mime_parse_hdr(BIO *bio)` —
/// `crypto/asn1/asn_mime.c:723-848`.
///
/// The header state machine. `mime_debug` calls sit where the authority's do and are
/// no-ops. A blank line ends the block; the headers and their parameters are then
/// sorted so `mime_hdr_find`/`mime_param_find` may binary-search them.
///
/// # Safety
///
/// `bio` must be a live BIO.
#[allow(unused_assignments)] // `new_hdr = NULL` after a successful push keeps the error path from double-freeing
unsafe fn mime_parse_hdr(bio: *mut Bio) -> *mut OpenSslStack {
    let mut linebuf = [0 as c_char; MAX_SMLEN as usize];
    let mut mhdr: *mut MimeHeader = ptr::null_mut();
    let mut new_hdr: *mut MimeHeader = ptr::null_mut();

    // `OPENSSL_sk_new` takes the typed-stack comparator and allocates a fresh stack.
    let headers = OPENSSL_sk_new(Some(mime_hdr_cmp));
    if headers.is_null() {
        return ptr::null_mut();
    }

    'parse: {
        loop {
            // SAFETY: `bio` is live and `linebuf` holds `MAX_SMLEN` bytes.
            let len = unsafe { BIO_gets(bio, linebuf.as_mut_ptr(), MAX_SMLEN) };
            if len <= 0 {
                break;
            }
            // A line starting with whitespace is a continuation only once a header
            // exists.
            let mut state = if !mhdr.is_null() && ossl_isspace(linebuf[0] as c_int) {
                MIME_NAME
            } else {
                MIME_START
            };
            let mut save_state = MIME_INVALID;
            let mut ntmp: *mut c_char = ptr::null_mut();
            let mut q = linebuf.as_mut_ptr();
            let mut p = linebuf.as_mut_ptr();
            loop {
                // SAFETY: `p` walks `linebuf`, which is NUL-terminated.
                let c = unsafe { *p };
                if c == 0 || c == b'\r' as c_char || c == b'\n' as c_char {
                    break;
                }
                match state {
                    MIME_START => {
                        if c == b':' as c_char {
                            state = MIME_TYPE;
                            // SAFETY: `p` is inside `linebuf`.
                            unsafe { *p = 0 };
                            // SAFETY: `q` points inside `linebuf`.
                            ntmp = unsafe { strip_ends(q) };
                            // SAFETY: `p` is inside `linebuf`, so `p + 1` is at most one
                            // past the NUL.
                            q = unsafe { p.add(1) };
                        }
                    }
                    MIME_TYPE => {
                        if c == b';' as c_char {
                            mime_debug!("Found End Value\n");
                            // SAFETY: `p` is inside `linebuf`.
                            unsafe { *p = 0 };
                            // SAFETY: `ntmp` is null or a pointer into `linebuf`; `q` too.
                            new_hdr = unsafe { mime_hdr_new(ntmp, strip_ends(q)) };
                            if new_hdr.is_null() {
                                break 'parse;
                            }
                            // SAFETY: `headers` is live and `new_hdr` is this frame's
                            // allocation.
                            if unsafe { OPENSSL_sk_push(headers, new_hdr.cast::<c_void>()) } == 0 {
                                break 'parse;
                            }
                            mhdr = new_hdr;
                            new_hdr = ptr::null_mut();
                            ntmp = ptr::null_mut();
                            // SAFETY: `p` is inside `linebuf`.
                            q = unsafe { p.add(1) };
                            state = MIME_NAME;
                        } else if c == b'(' as c_char {
                            save_state = state;
                            state = MIME_COMMENT;
                        }
                    }
                    MIME_COMMENT => {
                        if c == b')' as c_char {
                            state = save_state;
                        }
                    }
                    MIME_NAME => {
                        if c == b'=' as c_char {
                            state = MIME_VALUE;
                            // SAFETY: `p` is inside `linebuf`.
                            unsafe { *p = 0 };
                            // SAFETY: `q` points inside `linebuf`.
                            ntmp = unsafe { strip_ends(q) };
                            // SAFETY: `p` is inside `linebuf`.
                            q = unsafe { p.add(1) };
                        }
                    }
                    MIME_VALUE => {
                        if c == b';' as c_char {
                            state = MIME_NAME;
                            // SAFETY: `p` is inside `linebuf`.
                            unsafe { *p = 0 };
                            // SAFETY: `mhdr` is live in this state; `ntmp`/`q` point into
                            // `linebuf`.
                            unsafe { mime_hdr_addparam(mhdr, ntmp, strip_ends(q)) };
                            ntmp = ptr::null_mut();
                            // SAFETY: `p` is inside `linebuf`.
                            q = unsafe { p.add(1) };
                        } else if c == b'"' as c_char {
                            mime_debug!("Found Quote\n");
                            state = MIME_QUOTE;
                        } else if c == b'(' as c_char {
                            save_state = state;
                            state = MIME_COMMENT;
                        }
                    }
                    MIME_QUOTE if c == b'"' as c_char => {
                        mime_debug!("Found Match Quote\n");
                        state = MIME_VALUE;
                    }
                    _ => {}
                }
                // SAFETY: `p` walks `linebuf` up to and including its NUL terminator.
                p = unsafe { p.add(1) };
            }

            if state == MIME_TYPE {
                // SAFETY: `ntmp` is null or a pointer into `linebuf`; `q` too.
                new_hdr = unsafe { mime_hdr_new(ntmp, strip_ends(q)) };
                if new_hdr.is_null() {
                    break 'parse;
                }
                // SAFETY: `headers` is live and `new_hdr` is this frame's allocation.
                if unsafe { OPENSSL_sk_push(headers, new_hdr.cast::<c_void>()) } == 0 {
                    break 'parse;
                }
                mhdr = new_hdr;
                new_hdr = ptr::null_mut();
            } else if state == MIME_VALUE {
                // SAFETY: `mhdr` is live in this state; `ntmp`/`q` point into `linebuf`.
                unsafe { mime_hdr_addparam(mhdr, ntmp, strip_ends(q)) };
            }
            if p == linebuf.as_mut_ptr() {
                break; // Blank line means end of headers.
            }
        }

        // Sort the headers and their params for faster searching.
        // SAFETY: `headers` is a live stack with `mime_hdr_cmp`.
        unsafe { OPENSSL_sk_sort(headers) };
        // SAFETY: `headers` is live.
        let n = unsafe { OPENSSL_sk_num(headers) };
        let mut i = 0;
        while i < n {
            // SAFETY: `i < n`, so this is one of the stack's own headers.
            mhdr = unsafe { OPENSSL_sk_value(headers, i) }.cast::<MimeHeader>();
            if !mhdr.is_null() {
                // SAFETY: `mhdr` is live.
                let params = unsafe { (*mhdr).params };
                if !params.is_null() {
                    // SAFETY: `params` is live with `mime_param_cmp`.
                    unsafe { OPENSSL_sk_sort(params) };
                }
            }
            i += 1;
        }
        return headers;
    }

    // err:
    // SAFETY: `new_hdr` is null or this frame's allocation.
    unsafe { mime_hdr_free(new_hdr) };
    // SAFETY: `headers` is this frame's own stack of headers.
    unsafe { OPENSSL_sk_pop_free(headers, Some(mime_hdr_free_thunk)) };
    ptr::null_mut()
}

/// `static char *strip_ends(char *name)` — `crypto/asn1/asn_mime.c:850-853`.
///
/// # Safety
///
/// `name` must be null or NUL-terminated.
unsafe fn strip_ends(name: *mut c_char) -> *mut c_char {
    // SAFETY: `name` is null or NUL-terminated per the contract.
    unsafe { strip_end(strip_start(name)) }
}

/// `static char *strip_start(char *name)` — `crypto/asn1/asn_mime.c:856-872`.
///
/// # Safety
///
/// `name` must be NUL-terminated.
unsafe fn strip_start(name: *mut c_char) -> *mut c_char {
    let mut p = name;
    loop {
        // SAFETY: `p` walks the caller's NUL-terminated string.
        let c = unsafe { *p };
        if c == 0 {
            return ptr::null_mut();
        }
        if c == b'"' as c_char {
            // SAFETY: `p` points at the quote inside the string.
            if unsafe { *p.add(1) } != 0 {
                // SAFETY: the byte after the quote is non-NUL, so the next byte is valid.
                return unsafe { p.add(1) };
            }
            return ptr::null_mut();
        }
        if !ossl_isspace(c as c_int) {
            return p;
        }
        // SAFETY: `p` walks the string and `*p` was non-NUL.
        p = unsafe { p.add(1) };
    }
}

/// `static char *strip_end(char *name)` — `crypto/asn1/asn_mime.c:875-895`.
///
/// # Safety
///
/// `name` must be null or NUL-terminated.
unsafe fn strip_end(name: *mut c_char) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `name` is NUL-terminated per the contract.
    let len = unsafe { strlen(name) };
    let mut p = name.wrapping_add(len.wrapping_sub(1));
    while p >= name {
        // SAFETY: `p` is at or after `name` and inside the string.
        let c = unsafe { *p };
        if c == b'"' as c_char {
            if p.wrapping_sub(1) == name {
                return ptr::null_mut();
            }
            // SAFETY: `p` is inside the caller's buffer.
            unsafe { *p = 0 };
            return name;
        }
        if ossl_isspace(c as c_int) {
            // SAFETY: `p` is inside the caller's buffer.
            unsafe { *p = 0 };
        } else {
            return name;
        }
        p = p.wrapping_sub(1);
    }
    ptr::null_mut()
}

/// `static MIME_HEADER *mime_hdr_new(const char *name, const char *value)` —
/// `crypto/asn1/asn_mime.c:897-928`.
///
/// Both halves are duplicated and lower-cased; the parameter stack is created with
/// `mime_param_cmp`.
///
/// # Safety
///
/// `name` and `value` must each be null or NUL-terminated.
unsafe fn mime_hdr_new(name: *const c_char, value: *const c_char) -> *mut MimeHeader {
    let mut tmpname: *mut c_char = ptr::null_mut();
    let mut tmpval: *mut c_char = ptr::null_mut();
    let mut mhdr: *mut MimeHeader = ptr::null_mut();

    'build: {
        if !name.is_null() {
            // SAFETY: `name` is NUL-terminated per the contract.
            tmpname = unsafe { CRYPTO_strdup(name, FILE.as_ptr(), LINE_HDR_NEW_STRDUP_NAME) };
            if tmpname.is_null() {
                break 'build;
            }
            let mut p = tmpname;
            // SAFETY: `p` walks the string just duplicated.
            while unsafe { *p } != 0 {
                // SAFETY: `p` is inside the duplicate.
                let cur = unsafe { *p };
                // SAFETY: `p` is inside the duplicate.
                unsafe { *p = ossl_tolower(cur as c_int) as c_char };
                // SAFETY: `*p` was non-NUL.
                p = unsafe { p.add(1) };
            }
        }
        if !value.is_null() {
            // SAFETY: `value` is NUL-terminated per the contract.
            tmpval = unsafe { CRYPTO_strdup(value, FILE.as_ptr(), LINE_HDR_NEW_STRDUP_VALUE) };
            if tmpval.is_null() {
                break 'build;
            }
            let mut p = tmpval;
            // SAFETY: `p` walks the string just duplicated.
            while unsafe { *p } != 0 {
                // SAFETY: `p` is inside the duplicate.
                let cur = unsafe { *p };
                // SAFETY: `p` is inside the duplicate.
                unsafe { *p = ossl_tolower(cur as c_int) as c_char };
                // SAFETY: `*p` was non-NUL.
                p = unsafe { p.add(1) };
            }
        }
        // SAFETY: this allocates one `MimeHeader`.
        mhdr = CRYPTO_malloc(
            core::mem::size_of::<MimeHeader>(),
            FILE.as_ptr(),
            LINE_HDR_NEW_MALLOC,
        )
        .cast::<MimeHeader>();
        if mhdr.is_null() {
            break 'build;
        }
        // SAFETY: `mhdr` is a fresh `MimeHeader`.
        unsafe {
            (*mhdr).name = tmpname;
            (*mhdr).value = tmpval;
        }
        // `OPENSSL_sk_new` takes the typed-stack comparator.
        let params = OPENSSL_sk_new(Some(mime_param_cmp));
        // SAFETY: `mhdr` is live.
        unsafe { (*mhdr).params = params };
        if params.is_null() {
            break 'build;
        }
        return mhdr;
    }

    // err:
    // SAFETY: each pointer is null or this frame's allocation.
    unsafe {
        CRYPTO_free(
            tmpname.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_HDR_NEW_FREE_NAME,
        );
        CRYPTO_free(
            tmpval.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_HDR_NEW_FREE_VALUE,
        );
        CRYPTO_free(mhdr.cast::<c_void>(), FILE.as_ptr(), LINE_HDR_NEW_FREE_HDR);
    }
    ptr::null_mut()
}

/// `static int mime_hdr_addparam(MIME_HEADER *mhdr, const char *name,
/// const char *value)` — `crypto/asn1/asn_mime.c:930-961`.
///
/// The parameter *name* is lower-cased; the value is copied as is because parameter
/// values are case sensitive.
///
/// # Safety
///
/// `mhdr` must be a live header; `name`/`value` null or NUL-terminated.
unsafe fn mime_hdr_addparam(
    mhdr: *mut MimeHeader,
    name: *const c_char,
    value: *const c_char,
) -> c_int {
    let mut tmpname: *mut c_char = ptr::null_mut();
    let mut tmpval: *mut c_char = ptr::null_mut();
    let mut mparam: *mut MimeParam = ptr::null_mut();

    'build: {
        if !name.is_null() {
            // SAFETY: `name` is NUL-terminated per the contract.
            tmpname = unsafe { CRYPTO_strdup(name, FILE.as_ptr(), LINE_ADDPARAM_STRDUP_NAME) };
            if tmpname.is_null() {
                break 'build;
            }
            let mut p = tmpname;
            // SAFETY: `p` walks the string just duplicated.
            while unsafe { *p } != 0 {
                // SAFETY: `p` is inside the duplicate.
                let cur = unsafe { *p };
                // SAFETY: `p` is inside the duplicate.
                unsafe { *p = ossl_tolower(cur as c_int) as c_char };
                // SAFETY: `*p` was non-NUL.
                p = unsafe { p.add(1) };
            }
        }
        if !value.is_null() {
            // SAFETY: `value` is NUL-terminated per the contract.
            tmpval = unsafe { CRYPTO_strdup(value, FILE.as_ptr(), LINE_ADDPARAM_STRDUP_VALUE) };
            if tmpval.is_null() {
                break 'build;
            }
        }
        // Parameter values are case sensitive so leave as is.
        // SAFETY: this allocates one `MimeParam`.
        mparam = CRYPTO_malloc(
            core::mem::size_of::<MimeParam>(),
            FILE.as_ptr(),
            LINE_ADDPARAM_MALLOC,
        )
        .cast::<MimeParam>();
        if mparam.is_null() {
            break 'build;
        }
        // SAFETY: `mparam` is a fresh `MimeParam`.
        unsafe {
            (*mparam).param_name = tmpname;
            (*mparam).param_value = tmpval;
        }
        // SAFETY: `mhdr` is live, its `params` stack is live and `mparam` is this
        // frame's allocation.
        if unsafe { OPENSSL_sk_push((*mhdr).params, mparam.cast::<c_void>()) } == 0 {
            break 'build;
        }
        return 1;
    }

    // err:
    // SAFETY: each pointer is null or this frame's allocation.
    unsafe {
        CRYPTO_free(
            tmpname.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_ADDPARAM_FREE_NAME,
        );
        CRYPTO_free(
            tmpval.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_ADDPARAM_FREE_VALUE,
        );
        CRYPTO_free(
            mparam.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_ADDPARAM_FREE_PARAM,
        );
    }
    0
}

/// `static int mime_hdr_cmp(const MIME_HEADER *const *a,
/// const MIME_HEADER *const *b)` — `crypto/asn1/asn_mime.c:963-970`.
///
/// # Safety
///
/// `a` and `b` must each point to a slot holding a live `MimeHeader`.
unsafe extern "C" fn mime_hdr_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the caller's contract is the typed-stack comparator's.
    let a = unsafe { *(a as *const *const MimeHeader) };
    // SAFETY: as above.
    let b = unsafe { *(b as *const *const MimeHeader) };
    // SAFETY: `a` is a live header.
    let an = unsafe { (*a).name };
    // SAFETY: `b` is a live header.
    let bn = unsafe { (*b).name };
    if an.is_null() || bn.is_null() {
        return c_int::from(!an.is_null()) - c_int::from(!bn.is_null());
    }
    // SAFETY: both names are non-null and NUL-terminated.
    unsafe { strcmp(an, bn) }
}

/// `static int mime_param_cmp(const MIME_PARAM *const *a,
/// const MIME_PARAM *const *b)` — `crypto/asn1/asn_mime.c:972-978`.
///
/// # Safety
///
/// `a` and `b` must each point to a slot holding a live `MimeParam`.
unsafe extern "C" fn mime_param_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the caller's contract is the typed-stack comparator's.
    let a = unsafe { *(a as *const *const MimeParam) };
    // SAFETY: as above.
    let b = unsafe { *(b as *const *const MimeParam) };
    // SAFETY: `a` is a live parameter.
    let an = unsafe { (*a).param_name };
    // SAFETY: `b` is a live parameter.
    let bn = unsafe { (*b).param_name };
    if an.is_null() || bn.is_null() {
        return c_int::from(!an.is_null()) - c_int::from(!bn.is_null());
    }
    // SAFETY: both names are non-null and NUL-terminated.
    unsafe { strcmp(an, bn) }
}

/// `static MIME_HEADER *mime_hdr_find(STACK_OF(MIME_HEADER) *hdrs, const char *name)` —
/// `crypto/asn1/asn_mime.c:982-993`.
///
/// # Safety
///
/// `hdrs` must be null or a live stack with `mime_hdr_cmp`; `name` NUL-terminated.
unsafe fn mime_hdr_find(hdrs: *mut OpenSslStack, name: *const c_char) -> *mut MimeHeader {
    let htmp = MimeHeader {
        name: name as *mut c_char,
        value: ptr::null_mut(),
        params: ptr::null_mut(),
    };
    // SAFETY: `hdrs` is null or live and `htmp` is a live local; the comparator receives
    // its address, as the typed-stack form requires.
    let idx = unsafe { OPENSSL_sk_find(hdrs, (&raw const htmp).cast::<c_void>()) };
    // SAFETY: `idx` is -1 or a valid index of `hdrs`.
    unsafe { OPENSSL_sk_value(hdrs, idx) }.cast::<MimeHeader>()
}

/// `static MIME_PARAM *mime_param_find(MIME_HEADER *hdr, const char *name)` —
/// `crypto/asn1/asn_mime.c:995-1004`.
///
/// # Safety
///
/// `hdr` must be a live header; `name` NUL-terminated.
unsafe fn mime_param_find(hdr: *mut MimeHeader, name: *const c_char) -> *mut MimeParam {
    let param = MimeParam {
        param_name: name as *mut c_char,
        param_value: ptr::null_mut(),
    };
    // SAFETY: `hdr` is a live header and `param` is a live local; the comparator receives
    // its address, as the typed-stack form requires.
    let idx = unsafe { OPENSSL_sk_find((*hdr).params, (&raw const param).cast::<c_void>()) };
    // SAFETY: `idx` is -1 or a valid index of the header's parameter stack.
    unsafe { OPENSSL_sk_value((*hdr).params, idx) }.cast::<MimeParam>()
}

/// `static void mime_hdr_free(MIME_HEADER *hdr)` — `crypto/asn1/asn_mime.c:1006-1015`.
///
/// # Safety
///
/// `hdr` must be null or a header from `mime_hdr_new` that no one else owns.
unsafe fn mime_hdr_free(hdr: *mut MimeHeader) {
    if hdr.is_null() {
        return;
    }
    // SAFETY: the three slots are this header's own, allocated by `mime_hdr_new`.
    unsafe {
        CRYPTO_free(
            (*hdr).name.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_HDR_FREE_NAME,
        );
        CRYPTO_free(
            (*hdr).value.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_HDR_FREE_VALUE,
        );
        if !(*hdr).params.is_null() {
            OPENSSL_sk_pop_free((*hdr).params, Some(mime_param_free_thunk));
        }
        CRYPTO_free(hdr.cast::<c_void>(), FILE.as_ptr(), LINE_HDR_FREE_HDR);
    }
}

/// `static void mime_param_free(MIME_PARAM *param)` — `crypto/asn1/asn_mime.c:1017-1022`.
///
/// # Safety
///
/// `param` must be a live parameter from `mime_hdr_addparam` that no one else owns.
unsafe fn mime_param_free(param: *mut MimeParam) {
    // SAFETY: the two slots are this parameter's own, allocated by `mime_hdr_addparam`.
    unsafe {
        CRYPTO_free(
            (*param).param_name.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_PARAM_FREE_NAME,
        );
        CRYPTO_free(
            (*param).param_value.cast::<c_void>(),
            FILE.as_ptr(),
            LINE_PARAM_FREE_VALUE,
        );
        CRYPTO_free(param.cast::<c_void>(), FILE.as_ptr(), LINE_PARAM_FREE_PARAM);
    }
}

/// The `void (*)(void *)` thunk for `sk_MIME_HEADER_pop_free(..., mime_hdr_free)`.
///
/// # Safety
///
/// `p` must be a live `MimeHeader` from `mime_hdr_new`, or the stack element is null.
unsafe extern "C" fn mime_hdr_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `MIME_HEADER` pointers per the contract.
    unsafe { mime_hdr_free(p.cast::<MimeHeader>()) };
}

/// The `void (*)(void *)` thunk for `sk_MIME_PARAM_pop_free(..., mime_param_free)`.
///
/// # Safety
///
/// `p` must be a live `MimeParam` from `mime_hdr_addparam`.
unsafe extern "C" fn mime_param_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `MIME_PARAM` pointers per the contract.
    unsafe { mime_param_free(p.cast::<MimeParam>()) };
}

/// The `void (*)(void *)` thunk for `sk_BIO_pop_free(parts, BIO_vfree)`.
///
/// # Safety
///
/// `p` must be a live `BIO` or null.
unsafe extern "C" fn bio_vfree_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `BIO` pointers per the contract.
    unsafe { BIO_vfree(p.cast::<Bio>()) };
}

/// `static int mime_bound_check(char *line, int linelen, const char *bound,
/// int blen)` — `crypto/asn1/asn_mime.c:1030-1041`.
///
/// Returns `0` for no boundary, `1` for a part boundary and `2` for the final one. The
/// `CHECK_AND_SKIP_PREFIX(line, "--")` macro advances the local pointer by two when the
/// prefix matches.
///
/// # Safety
///
/// `line` must be readable for `linelen` bytes; `bound` NUL-terminated and `blen`
/// non-negative.
unsafe fn mime_bound_check(
    line: *mut c_char,
    linelen: c_int,
    bound: *const c_char,
    blen: c_int,
) -> c_int {
    if linelen < 0 || blen < 0 {
        return 0;
    }
    // Quickly eliminate if the line length is too short.
    if blen + 2 > linelen {
        return 0;
    }
    // Check for the part boundary.
    // SAFETY: `line` is readable for `linelen >= 2` bytes.
    let mut p = line;
    // SAFETY: `line` is readable for at least two bytes per the check above.
    if unsafe { strncmp(p, c"--".as_ptr(), 2) } == 0 {
        // SAFETY: the two matched bytes leave the rest of the line readable.
        p = unsafe { p.add(2) };
        // SAFETY: `blen + 2 <= linelen`, so `blen` bytes are readable from `p`.
        if unsafe { strncmp(p, bound, blen as usize) } == 0 {
            // SAFETY: the boundary's `blen` bytes are inside the line, so the two after
            // them are too.
            return if unsafe { strncmp(p.add(blen as usize), c"--".as_ptr(), 2) } == 0 {
                2
            } else {
                1
            };
        }
    }
    0
}
