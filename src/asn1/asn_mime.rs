//! Phase 5 — `crypto/asn1/asn_mime.c`'s copying half: the CRLF policy and the
//! streaming `i2d`.
//!
//! `asn_mime.c` is 1077 lines and its two halves have different owners. The MIME
//! *reader and writer* — `multi_split`, the multipart parser, `SMIME_read_ASN1_ex`
//! and `SMIME_write_ASN1_ex` — need `BIO_f_base64` (the EVP codec, Phase 7) and the
//! `X509_ALGOR` set for the `micalg` parameter (Phase 11), so those four exports are
//! handed to Phase 12, the first stratum in which both exist. **This** module is the
//! half that needs nothing but Phase 4:
//!
//! * `SMIME_crlf_copy` — `asn1.h` declares it, so the declaring-header rule gives it
//!   to this stratum, and its only dependencies are `BIO_f_buffer` and this
//!   translation unit's own `strip_eol`. A hand-off whose reason is a *file* rather
//!   than a *dependency* is the error D49 recorded, so it is implemented here (D92).
//! * `i2d_ASN1_bio_stream` — the streaming `i2d` of a structure. Its non-streaming
//!   arm is `ASN1_item_i2d_bio` and its streaming arm is `BIO_new_NDEF`, both this
//!   stratum's, plus `SMIME_crlf_copy` above.
//!
//! `PEM_write_bio_ASN1_stream` is the third export `asn1.h` declares here, and it is
//! separately dispositioned: `B64_write_ASN1` wraps its sink in
//! `BIO_new(BIO_f_base64())`, and that filter BIO is Phase 4's deferral to Phase 7.
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
//! * the **unwinding loop** in the streaming arm. `BIO_pop` is called until it answers
//!   the caller's original BIO, so the chain is destroyed in exactly that order and the
//!   caller is left owning `out` alone.
//!
//! The `flags` are `pkcs7.h`'s (`SMIME_TEXT` and `SMIME_BINARY` are `PKCS7_TEXT` and
//! `PKCS7_BINARY`; `SMIME_ASCIICRLF` is `pkcs7.h`'s own), which is why the constants
//! below carry their `pkcs7.h` values alongside their `asn1.h` and `cms.h` siblings.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::a_i2d_fp::ASN1_item_i2d_bio;
use crate::asn1::bio_asn1::BIO_new_NDEF;
use crate::asn1::layout::Asn1Item;
use crate::runtime::bio::bf_buff::BIO_f_buffer;
use crate::runtime::bio::iolib::{BIO_ctrl, BIO_gets, BIO_puts, BIO_read, BIO_write};
use crate::runtime::bio::{BIO_free, BIO_new, BIO_pop, BIO_push, Bio, BIO_CTRL_FLUSH};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

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
