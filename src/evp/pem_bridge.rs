//! Phase 7.5 — `crypto/pem/pem_lib.c` and `crypto/pem/pem_sign.c`: the half of the `pem.h`
//! surface whose dependency on the EVP framework is a *parameter* rather than a method table.
//!
//! Ten exports land here. Twenty-five of the thirty-five `PEM_*` names in this row do not, and the
//! table below groups them by the blocker **reached first**, which is the one each `NOT_MEASURED_`
//! line in `RT-EVP-PEM` names -- a name may have more than one blocker behind that one, and the
//! `PEM_write_bio_PrivateKey_traditional` row is where that shows.
//!
//! | blocked first by | names | why |
//! |---|---|---|
//! | `EVP_md5()` | 8 | `crypto/evp/legacy_md5.c:36` is a legacy `EVP_MD` over `MD5_Init`/`_Update`/`_Final`, and `crypto/md5/` is Phase 13's |
//! | `OSSL_ENCODER_*` / `OSSL_DECODER_*` | 15 | `decoder.h`/`encoder.h` are Phase 10's, and a provider key takes that branch *first* |
//! | `EVP_read_pw_string_min` | 1 | it is a `UI` program, and `ui.h` is Phase 13's |
//! | `evp_pkey_copy_downgraded` | 1 | Phase 8's, and `PEM_write_bio_PrivateKey_traditional` reads the legacy `ameth` beside it before it reads any encoder |
//!
//! ## `PEM_do_header` is the hinge, and the hinge is one function call
//!
//! `PEM_bytes_read_bio`, its `pem_bytes_read_bio_flags` body, `PEM_ASN1_read_bio` — and through it
//! `PEM_ASN1_read` — and every `PEM_read_bio_PrivateKey*` and `PEM_read_bio_Parameters*` spelling
//! reach
//!
//! ```text
//! crypto/pem/pem_lib.c:479   if (!EVP_BytesToKey(cipher->cipher, EVP_md5(), &(cipher->iv[0]), ...
//! ```
//!
//! `EVP_BytesToKey` is in the crate — 7.4l landed it (`docs/DECISIONS.md` D193) — and `EVP_md5` is
//! not. `docs/PHASE-7-SUBPHASES.md`'s 7.3g row hands `EVP_md5` to **Phase 13** with its primitive
//! unit named, because a legacy method static whose callbacks call `MD5_Init`/`MD5_Update`/`MD5_Final`
//! cannot be written before `crypto/md5/` exists. So the six names are withheld with that blocker
//! named rather than answered from something else: writing the export against a symbol that is not
//! defined fails `cargo test`'s **link**, not the call, which is the shape D190 records. A
//! *partial* answer would be worse than the absence — `PEM_do_header`'s whole observable is whether
//! the decryption succeeds, and every reachable input would have to be answered from elsewhere.
//!
//! ## What does land, and why each is enough on its own
//!
//! * **`PEM_read_bio_ex`** is the reader's whole framing layer: `get_name` finds the `-----BEGIN `
//!   line, `get_header_and_data` splits headers from body through two memory BIOs it *swaps* when
//!   there is no header, and the body is base64-decoded **in place** inside the data BIO's own
//!   `BUF_MEM`. It is generic over nothing at all, so it is the one entry point in this row a probe
//!   can drive on both sides with its own bytes.
//! * **`PEM_read_bio`/`PEM_read`/`PEM_write_bio`/`PEM_write`** are the framing pair, with the
//!   `FILE *` spellings reaching them through `BIO_s_file` and `BIO_set_fp`.
//! * **`PEM_get_EVP_CIPHER_INFO`** parses `Proc-Type:`/`DEK-Info:` and resolves the algorithm name
//!   with `EVP_get_cipherbyname`, which 7.3g landed (D162). It cannot be exercised end to end
//!   without `PEM_do_header`, but it is observable alone, including its seven refusals, and the
//!   court drives every one.
//! * **`PEM_SignInit`/`Update`/`Final`** are three one-line wrappers over `EVP_DigestInit_ex`,
//!   `EVP_DigestUpdate` and `EVP_SignFinal` — all landed — plus `EVP_EncodeBlock`, which is this
//!   slice's. `PEM_SignFinal` is the only function in the row that both signs and base64s, so it is
//!   where the two new surfaces meet.
//! * **`PEM_write_bio_ASN1_stream`** is `crypto/asn1/asn_mime.c:128`'s and **not** `bio_asn1.c`'s,
//!   which the brief for this row guessed and this slice measured. Its whole body is two
//!   `BIO_printf`s around `B64_write_ASN1`, which pushes `BIO_f_base64` over the caller's BIO and
//!   calls `i2d_ASN1_bio_stream` (`src/asn1/asn_mime.rs`, landed). It is one of the three Phase-5
//!   `asn1.h` hand-offs and the only one that builds; the other two are `ASN1_item_sign_ex` and
//!   `ASN1_item_verify_ex`, whose delegates `ASN1_item_sign_ctx`/`_verify_ctx` are Phase 11's
//!   (D193).
//!
//! ## The two `pem_malloc`/`pem_free` flavours, and the flag that chooses
//!
//! `PEM_MALLOC`/`PEM_FREE` are macros over two functions that take `OPENSSL_FILE`/`OPENSSL_LINE`,
//! and they split on `PEM_FLAG_SECURE`: the secure flavour is `CRYPTO_secure_malloc` and, on the
//! free side, `CRYPTO_secure_clear_free` with the **length** — so a caller that passes
//! `PEM_FLAG_SECURE` and then frees with a different length has changed what the allocator is told.
//! `PEM_bytes_read_bio_secmem` is the spelling that always sets it and is withheld with
//! `PEM_do_header`; `PEM_read_bio_ex` takes the flag from its caller, and the court drives both `0`
//! and `PEM_FLAG_SECURE` through it.
//!
//! ## `sanitize_line` is three rules in one function, and two of them are not interchangeable
//!
//! Which one runs is `flags`:
//!
//! * `PEM_FLAG_EAY_COMPATIBLE` strips trailing whitespace and then steps **back onto** the last
//!   non-whitespace byte, so the newline is appended after it (`:739-742`);
//! * `PEM_FLAG_ONLY_B64` stops at the first byte that is not base64 **or** is `'\n'`/`'\r'`;
//! * the default turns control characters into spaces and stops at the first line ending.
//!
//! The two flags are mutually exclusive and `PEM_read_bio_ex` refuses the combination before it
//! allocates anything (`:957-961`) — the first of its two reasons, and the one the court reaches
//! with a flag pair alone.
//!
//! ## `get_header_and_data` swaps its two BIOs rather than copying
//!
//! Its `header`/`data` parameters are `BIO **` for one reason: when a PEM block has no header —
//! which is *most* of them — the function ends by exchanging the two pointers (`:904-907`), so the
//! accumulated text ends up in the data BIO without a byte being moved. `PEM_read_bio_ex` then
//! reads the header's *length* through `BIO_get_mem_data` and the data through `BIO_read`, in that
//! order, and the decoded bytes go back into the data BIO's own `BUF_MEM` buffer — an aliasing
//! read-write the authority relies on (`EVP_DecodeUpdate(ctx, buf_mem->data, &len, buf_mem->data,
//! len)` at `:994`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::asn_mime::i2d_ASN1_bio_stream;
use crate::asn1::layout::Asn1Item;
use crate::evp::bio_enc::BIO_f_base64;
use crate::evp::cipher::{EVP_CIPHER_get_iv_length, EvpCipher};
use crate::evp::digest::{EVP_DigestInit_ex, EVP_DigestUpdate, EvpMd, EvpMdCtx};
use crate::evp::encode::{
    EVP_DecodeFinal, EVP_DecodeInit, EVP_DecodeUpdate, EVP_ENCODE_CTX_free, EVP_ENCODE_CTX_new,
    EVP_EncodeBlock, EVP_EncodeFinal, EVP_EncodeInit, EVP_EncodeUpdate, EvpEncodeCtx,
};
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::evp::p_legacy::EVP_SignFinal;
use crate::evp::pkey::{EVP_PKEY_get_size, EvpPkey};
use crate::pem::pem_lib::PEM_BUFSIZE;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::bss_mem::{BIO_s_mem, BIO_s_secmem};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::{
    BIO_ctrl, BIO_free, BIO_gets, BIO_new, BIO_pop, BIO_push, BIO_puts, BIO_read, BIO_write, Bio,
    BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_C_GET_BUF_MEM_PTR, BIO_C_SET_FILE_PTR,
};
use crate::runtime::buffer::BufMem;
use crate::runtime::ctype::ossl_ctype_check;
use crate::runtime::ctype_table::mask::{MASK_BASE64, MASK_CNTRL};
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_malloc_array};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};
use crate::runtime::str::OPENSSL_hexchar2int;

/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `PEM_FLAG_SECURE` — `include/openssl/pem.h:381`.
pub(crate) const PEM_FLAG_SECURE: c_uint = 0x1;
/// `PEM_FLAG_EAY_COMPATIBLE` — `include/openssl/pem.h:382`.
pub(crate) const PEM_FLAG_EAY_COMPATIBLE: c_uint = 0x2;
/// `PEM_FLAG_ONLY_B64` — `include/openssl/pem.h:384`.
pub(crate) const PEM_FLAG_ONLY_B64: c_uint = 0x4;
/// `BIO_NOCLOSE` — `include/openssl/bio.h`.
const BIO_NOCLOSE: c_long = 0x00;
/// `LINESIZE` — `crypto/pem/pem_lib.c:767`.
const LINESIZE: c_int = 255;
/// `BEGINSTR` — `crypto/pem/pem_lib.c:769`.
const BEGINSTR: &[u8] = b"-----BEGIN ";
/// `ENDSTR` — `crypto/pem/pem_lib.c:770`.
const ENDSTR: &[u8] = b"-----END ";
/// `TAILSTR` — `crypto/pem/pem_lib.c:771`.
const TAILSTR: &[u8] = b"-----\n";

/// `OPENSSL_FILE` at the allocation and free sites in `crypto/pem/pem_lib.c`.
const FILE_PEM_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c".as_ptr();
/// `OPENSSL_FILE` at the allocation site in `crypto/pem/pem_sign.c`.
const FILE_PEM_SIGN: *const c_char = c"../../src/openssl-3.6.4/crypto/pem/pem_sign.c".as_ptr();

/// `ERR_R_EVP_LIB` — `err.h`'s `(ERR_LIB_EVP | ERR_RFLAG_COMMON)`, which is the reason
/// `PEM_write_bio`'s single dynamic report carries on its first and fourth arms. Read from the
/// site that raises it statically rather than typed.
const ERR_R_EVP_LIB: c_int = err_sites::PEM_LIB_989.reason;
/// `ERR_R_BIO_LIB` — `err.h`'s `(ERR_LIB_BIO | ERR_RFLAG_COMMON)`, the reason on the other three
/// arms.
const ERR_R_BIO_LIB: c_int = err_sites::PEM_LIB_967.reason;

/// `EVP_CIPHER_INFO` — `include/openssl/evp.h`'s two-field structure.
///
/// It is a *public* struct, so a probe can declare its own copy and compare the fields after
/// `PEM_get_EVP_CIPHER_INFO` has filled them in. The `iv` half is zeroed before the header is
/// parsed — including on the early return for an absent header — which is what lets a caller
/// compare all sixteen bytes.
#[repr(C)]
pub struct EvpCipherInfo {
    /// `const EVP_CIPHER *cipher` — NULL when the block is not encrypted.
    pub cipher: *const EvpCipher,
    /// `unsigned char iv[EVP_MAX_IV_LENGTH]`.
    pub iv: [c_uchar; EVP_MAX_IV_LENGTH],
}

const _: () = {
    assert!(core::mem::offset_of!(EvpCipherInfo, cipher) == 0);
    assert!(core::mem::offset_of!(EvpCipherInfo, iv) == 8);
    assert!(core::mem::size_of::<EvpCipherInfo>() == 24);
};

/// `pem_password_cb` — `include/openssl/pem.h:57`'s function *type*.
///
/// A type and not a pointer, exactly as `d2i_of_void` is, so a parameter spelled
/// `pem_password_cb *` is a bare function pointer and a NULL one is `Option::None`.
pub type PemPasswordCb = unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int;

/// `PEM_MALLOC(num, flags)` — `crypto/pem/pem_lib.c:234`.
///
/// Shared with `src/pem/pem_lib.rs` (D350), which is the unit's other module: `PEM_bytes_read_bio`
/// and its `_secmem` spelling allocate through the `PEM_MALLOC`/`PEM_FREE` pair, and one
/// definition of the flag dispatch is what keeps the `PEM_FLAG_SECURE` branch single.
///
/// # Safety
/// The returned block is the caller's and must be released by [`pem_free`] with the same `flags`.
pub(crate) unsafe fn pem_malloc(
    num: usize,
    flags: c_uint,
    file: *const c_char,
    line: c_int,
) -> *mut c_void {
    if flags & PEM_FLAG_SECURE != 0 {
        // SAFETY: the secure allocator validates its own argument.
        unsafe { CRYPTO_secure_malloc(num, file, line) }
    } else {
        CRYPTO_malloc(num, file, line)
    }
}

/// `PEM_FREE(p, flags, num)` — `crypto/pem/pem_lib.c:223`.
///
/// Shared with `src/pem/pem_lib.rs` (D350); see [`pem_malloc`].
///
/// # Safety
/// `p` must be NULL or a block from [`pem_malloc`] with the same `flags`, and `num` its length.
pub(crate) unsafe fn pem_free(
    p: *mut c_void,
    flags: c_uint,
    num: usize,
    file: *const c_char,
    line: c_int,
) {
    if flags & PEM_FLAG_SECURE != 0 {
        // SAFETY: the caller's contract.
        unsafe { CRYPTO_secure_clear_free(p, num, file, line) }
    } else {
        // SAFETY: as above.
        unsafe { CRYPTO_free(p, file, line) }
    }
}

/// `HAS_PREFIX(str, pre)` — `include/internal/common.h:59`:
/// `strncmp(str, pre "", sizeof(pre) - 1) == 0`.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn has_prefix(s: *const c_char, pre: &[u8]) -> bool {
    // SAFETY: the caller's contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    bytes.len() >= pre.len() && &bytes[..pre.len()] == pre
}

/// `CHECK_AND_SKIP_PREFIX(str, pre)` — `include/internal/common.h:61`.
///
/// Answers the advanced cursor, or `None` when the prefix does not match. The authority's macro
/// mutates its argument; a Rust transcription cannot, so the cursor is the return value.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn check_and_skip_prefix(s: *const c_char, pre: &[u8]) -> Option<*const c_char> {
    // SAFETY: the caller's contract.
    if unsafe { has_prefix(s, pre) } {
        // SAFETY: the match above proves the region is readable for `pre.len()` bytes.
        Some(unsafe { s.add(pre.len()) })
    } else {
        None
    }
}

/// `strspn(s, accept)` — the C library's, over a NUL-terminated string.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn strspn(s: *const c_char, accept: &[u8]) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: the caller's contract makes `s` NUL-terminated, so the walk stops at the NUL.
        let b = unsafe { *s.add(n) } as u8;
        if b == 0 || !accept.contains(&b) {
            return n;
        }
        n += 1;
    }
}

/// `strcspn(s, reject)` — the C library's, over a NUL-terminated string.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn strcspn(s: *const c_char, reject: &[u8]) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: as above.
        let b = unsafe { *s.add(n) } as u8;
        if b == 0 || reject.contains(&b) {
            return n;
        }
        n += 1;
    }
}

/// `int ossl_pem_check_suffix(const char *pem_str, const char *suffix)` —
/// `crypto/pem/pem_lib.c:1047-1062`.
///
/// Answers the length of the *prefix* when `pem_str` ends in `" suffix"`, and 0 otherwise. It is
/// the one externally-linked internal in this unit that is not an export — `crypto/pem.h` declares
/// it and that header is not installed — and the prerequisite gate owes it the moment `pem_lib.c`
/// has a module. Its callers are `check_pem` (`crypto/pem/pem_lib.c:143`, `:159`) and
/// `pem_read_bio_key_legacy` (`crypto/pem/pem_pkey.c:176`), both of which need a symbol this slice
/// withholds, so it carries no `#[no_mangle]` and has no caller yet — which is what its
/// `allow(dead_code)` names.
///
/// `suffix_len + 1 >= pem_len` is the whole boundary: a `pem_str` of exactly `"x" + suffix` has a
/// prefix of length 0 and is refused, so a match never answers 0. That is what lets callers use
/// `> 0` as the test and hand the result straight to `EVP_PKEY_asn1_find_str`.
///
/// # Safety
/// Both arguments must be NUL-terminated strings.
#[allow(dead_code)] // the landing callers are `check_pem` (`pem_lib.c:143`) and `pem_pkey.c:176`
pub(crate) unsafe fn ossl_pem_check_suffix(pem_str: *const c_char, suffix: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    let pem = unsafe { CStr::from_ptr(pem_str) }.to_bytes();
    // SAFETY: as above.
    let suf = unsafe { CStr::from_ptr(suffix) }.to_bytes();
    let pem_len = pem.len() as c_int;
    let suffix_len = suf.len() as c_int;

    if suffix_len + 1 >= pem_len {
        return 0;
    }
    if &pem[(pem_len - suffix_len) as usize..] != suf {
        return 0;
    }
    if pem[(pem_len - suffix_len - 1) as usize] != b' ' {
        return 0;
    }
    pem_len - suffix_len - 1
}

/// `static int load_iv(char **fromp, unsigned char *to, int num)` — `crypto/pem/pem_lib.c:594-615`.
///
/// `num` *bytes* of IV, and therefore `2 * num` hex characters, with the odd/even nibble placed by
/// the authority's `(!(i & 1)) * 4` — the high nibble first. A short string makes
/// `OPENSSL_hexchar2int(0)` fail and the whole parse refuses with `PEM_R_BAD_IV_CHARS`, which is
/// why a truncated `DEK-Info` never leaves a partially-filled IV behind.
///
/// # Safety
/// `from` must point at a NUL-terminated hex string with at least `2 * num` characters; `to` must
/// be writable for `num` bytes.
unsafe fn load_iv(from: *const c_char, to: *mut c_uchar, num: c_int) -> c_int {
    let mut from = from;
    for i in 0..num {
        // SAFETY: `to` is writable for `num` bytes.
        unsafe { *to.add(i as usize) = 0 };
    }
    let num = num * 2;
    for i in 0..num {
        // SAFETY: the caller's contract makes `from` NUL-terminated.
        let v = OPENSSL_hexchar2int(unsafe { *from } as c_uchar);
        if v < 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_606) };
            return 0;
        }
        // SAFETY: as above; the walk stops at the NUL, where `OPENSSL_hexchar2int` answers -1.
        from = unsafe { from.add(1) };
        // SAFETY: `i / 2 < num` bytes of `to`.
        unsafe {
            *to.add((i / 2) as usize) |= (v as c_uchar) << ((if i & 1 == 0 { 4 } else { 0 }) as u8);
        }
    }
    1
}

/// `int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher)` —
/// `crypto/pem/pem_lib.c:521-592`.
///
/// Seven refusals, and their *order* is the contract: an empty or newline-first header is a
/// **success** with a NULL cipher and a zeroed IV; a header that does not start with `Proc-Type:`
/// is `PEM_R_NOT_PROC_TYPE`; the version must be `4,`; `ENCRYPTED` must follow and must be followed
/// by whitespace; then `DEK-Info:`, an algorithm name, and an IV whose presence is decided by
/// `EVP_CIPHER_get_iv_length` — a zero-length cipher must **not** have a comma and a non-zero one
/// must.
///
/// The algorithm name is resolved by `EVP_get_cipherbyname`, which is 7.3g's and landed. It answers
/// NULL for a name nothing publishes — including `DES-CBC` on the candidate, whose legacy
/// `OBJ_NAME` table is Phase 13's — and that is a **contents** divergence D162 already records, not
/// a structural one: the refusal, its reason and its site are the same.
///
/// `header` is written through: the algorithm-name scan **punctuates the caller's buffer** with a
/// NUL and restores the byte immediately afterwards. That is why the parameter is `char *` and not
/// `const char *`, and it is observable — a probe that passes a mutable buffer finds it unchanged
/// afterwards.
///
/// # Safety
/// `header` must be a writable NUL-terminated string; `cipher` writable for one [`EvpCipherInfo`].
#[no_mangle]
pub unsafe extern "C" fn PEM_get_EVP_CIPHER_INFO(
    header: *mut c_char,
    cipher: *mut EvpCipherInfo,
) -> c_int {
    // SAFETY: `cipher` is writable per the contract.
    unsafe {
        (*cipher).cipher = ptr::null();
        ptr::write_bytes((*cipher).iv.as_mut_ptr(), 0, EVP_MAX_IV_LENGTH);
    }
    if header.is_null() {
        return 1;
    }
    // SAFETY: `header` is NUL-terminated per the contract.
    let first = unsafe { *header } as u8;
    if first == 0 || first == b'\n' {
        return 1;
    }

    // SAFETY: `header` is NUL-terminated.
    let Some(proc_type) = (unsafe { check_and_skip_prefix(header, b"Proc-Type:") }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_LIB_533) };
        return 0;
    };
    // The cursor is mutable from here on because the `DEK-Info:` scan below punctuates the
    // caller's own buffer; `header` is a `char *` for exactly that reason.
    let mut h = proc_type.cast_mut();
    // SAFETY: `h` walks the same NUL-terminated string.
    h = unsafe { h.add(strspn(h, b" \t")) };

    // SAFETY: `h` has at least the two bytes tested, because `Proc-Type:` was found before them.
    unsafe {
        if *h != b'4' as c_char {
            return 0;
        }
        h = h.add(1);
        if *h != b',' as c_char {
            return 0;
        }
        h = h.add(1);
    }
    // SAFETY: `h` walks the same string.
    h = unsafe { h.add(strspn(h, b" \t")) };

    // We expect "ENCRYPTED" followed by optional white-space and a line break.
    // SAFETY: the pointer is live per the caller's contract.
    match unsafe { check_and_skip_prefix(h, b"ENCRYPTED") } {
        // SAFETY: `h` walks the same string.
        Some(rest) if unsafe { strspn(rest, b" \t\r\n") } != 0 => h = rest.cast_mut(),
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_544) };
            return 0;
        }
    }
    // SAFETY: `h` walks the same string.
    h = unsafe { h.add(strspn(h, b" \t\r")) };
    // SAFETY: the `ENCRYPTED` arm above required a line ending, which is right here.
    unsafe {
        if *h != b'\n' as c_char {
            raise_site(&err_sites::PEM_LIB_549);
            return 0;
        }
        h = h.add(1);
    }

    // RFC 1421 §4.6.1.3: we expect "DEK-Info: algo[,hex-parameters]".
    // SAFETY: `h` walks the same string.
    let Some(dek_info) = (unsafe { check_and_skip_prefix(h, b"DEK-Info:") }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_LIB_558) };
        return 0;
    };
    // SAFETY: `dek_info` walks the same string.
    let mut h = dek_info.cast_mut();
    // SAFETY: the pointer is live per the caller's contract.
    h = unsafe { h.add(strspn(h, b" \t")) };
    // The name starts **after** the whitespace, and that is the pointer the authority hands to
    // `EVP_get_cipherbyname`: it assigns `dekinfostart = header` *after* its own
    // `header += strspn(header, " \t")` (`crypto/pem/pem_lib.c:561`, `:567`, `:571`). Passing the
    // un-skipped pointer here resolves `" UNDEF"` instead of `"UNDEF"` and refuses a header the
    // authority accepts.
    let name_start = h;

    // DEK-INFO is a comma-separated combination of algorithm name and optional parameters.
    // SAFETY: `h` walks the caller's writable string; the byte `strcspn` stopped on is restored
    // immediately, and a stop on the NUL writes the NUL back over itself.
    unsafe {
        h = h.add(strcspn(h, b" \t,"));
        let c = *h;
        *h = 0;
        (*cipher).cipher = EVP_get_cipherbyname(name_start);
        *h = c;
    }
    // SAFETY: as above.
    h = unsafe { h.add(strspn(h, b" \t")) };

    // SAFETY: `cipher` was written just above.
    let enc = unsafe { (*cipher).cipher };
    if enc.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PEM_LIB_576) };
        return 0;
    }
    // SAFETY: `enc` is a live method.
    let ivlen = unsafe { EVP_CIPHER_get_iv_length(enc) };
    if ivlen > 0 {
        // SAFETY: `h` walks the same string; the `DEK-Info:` prefix and a non-empty name precede
        // it, so the byte is readable.
        if unsafe { *h } as u8 != b',' {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_581) };
            return 0;
        }
        // SAFETY: as above.
        h = unsafe { h.add(1) };
    } else {
        // SAFETY: `h` walks the same string.
        if unsafe { *h } as u8 == b',' {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_584) };
            return 0;
        }
    }

    // SAFETY: `h` is the IV's hex string and `cipher->iv` is writable for `ivlen` bytes.
    if unsafe { load_iv(h, (*cipher).iv.as_mut_ptr(), ivlen) } == 0 {
        return 0;
    }
    1
}

/// `static int sanitize_line(char *linebuf, int len, unsigned int flags, int first_call)` —
/// `crypto/pem/pem_lib.c:722-765`.
///
/// Answers the new length. The caller allocated `LINESIZE + 1`, so both writes below are inside it;
/// the UTF-8 BOM strip on the first call is why a file with a BOM reads at all.
///
/// # Safety
/// `linebuf` must be writable for `LINESIZE + 1` bytes and hold `len` valid bytes.
unsafe fn sanitize_line(
    linebuf: *mut c_char,
    len: c_int,
    flags: c_uint,
    first_call: c_int,
) -> c_int {
    let mut len = len;
    if first_call != 0 && len > 3 {
        // Other BOMs imply unsupported multibyte encoding, so don't strip them and let the error
        // raise.
        const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
        // SAFETY: `len > 3`, so three bytes are readable at `linebuf`.
        let head = unsafe { core::slice::from_raw_parts(linebuf.cast::<u8>(), 3) };
        if head == UTF8_BOM {
            // SAFETY: the two regions are the caller's own and overlap by construction, which is
            // why this is `memmove` and not `memcpy`.
            unsafe {
                ptr::copy(linebuf.add(3), linebuf, (len - 3) as usize);
                *linebuf.add(len as usize - 3) = 0;
            }
            len -= 3;
        }
    }

    if flags & PEM_FLAG_EAY_COMPATIBLE != 0 {
        // Strip trailing whitespace...
        // SAFETY: the pointer is live per the caller's contract.
        while len >= 0 && unsafe { *linebuf.add(len as usize) } as u8 <= b' ' {
            len -= 1;
        }
        // ...and go back to the whitespace before applying the uniform line ending.
        len += 1;
    } else if flags & PEM_FLAG_ONLY_B64 != 0 {
        let mut i = 0;
        while i < len {
            // SAFETY: `i < len` bytes are the caller's.
            let b = unsafe { *linebuf.add(i as usize) } as u8;
            if !ossl_ctype_check(c_int::from(b), MASK_BASE64) || b == b'\n' || b == b'\r' {
                break;
            }
            i += 1;
        }
        len = i;
    } else {
        // `EVP_DecodeBlock` strips leading and trailing whitespace, so just strip control
        // characters in place and let everything through.
        let mut i = 0;
        while i < len {
            // SAFETY: `i < len` bytes are the caller's.
            let b = unsafe { *linebuf.add(i as usize) } as u8;
            if b == b'\n' || b == b'\r' {
                break;
            }
            if ossl_ctype_check(c_int::from(b), MASK_CNTRL) {
                // SAFETY: `i < len`, so the byte is writable.
                unsafe { *linebuf.add(i as usize) = b' ' as c_char };
            }
            i += 1;
        }
        len = i;
    }
    // The caller allocated `LINESIZE + 1`, so this is safe.
    // SAFETY: `len <= LINESIZE`, so the newline and the terminator fit.
    unsafe {
        *linebuf.add(len as usize) = b'\n' as c_char;
        *linebuf.add(len as usize + 1) = 0;
    }
    len + 1
}

/// `static int get_name(BIO *bp, char **name, unsigned int flags)` —
/// `crypto/pem/pem_lib.c:775-817`.
///
/// Scans forward to the first line that is a well-formed `-----BEGIN X-----\n`, allocates the name
/// without its delimiters, and answers 1. A line that merely starts with `BEGINSTR` but is too
/// short or does not end in `TAILSTR` is skipped, which is what makes a `-----BEGIN` line with
/// trailing text unrecognisable rather than an error. A read that ends before any such line is
/// `PEM_R_NO_START_LINE` and *not* a silent zero.
///
/// # Safety
/// `bp` must be a live readable BIO; `name` writable for one pointer.
unsafe fn get_name(bp: *mut Bio, name: *mut *mut c_char, flags: c_uint) -> c_int {
    let mut first_call = 1;

    // Need to hold the trailing NUL (accounted for by `BIO_gets`) and the newline that will be
    // added by `sanitize_line` (the extra `1`).
    // SAFETY: `flags` is a real flag word.
    let linebuf =
        unsafe { pem_malloc((LINESIZE + 1) as usize, flags, FILE_PEM_LIB, 786) }.cast::<c_char>();
    if linebuf.is_null() {
        return 0;
    }

    let mut len;
    loop {
        // SAFETY: `bp` is live and `linebuf` is writable for `LINESIZE`.
        len = unsafe { BIO_gets(bp, linebuf, LINESIZE) };
        if len <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_794) };
            // SAFETY: this frame's own buffer, freed exactly once on this path.
            unsafe {
                pem_free(
                    linebuf.cast(),
                    flags,
                    (LINESIZE + 1) as usize,
                    FILE_PEM_LIB,
                    815,
                )
            };
            return 0;
        }
        // Strip trailing garbage and standardise the ending. `ONLY_B64` is masked out here and only
        // here.
        // SAFETY: `len` bytes are valid in the caller's buffer.
        len = unsafe { sanitize_line(linebuf, len, flags & !PEM_FLAG_ONLY_B64, first_call) };
        first_call = 0;

        // Allow leading empty or non-matching lines.
        // SAFETY: `linebuf` is NUL-terminated by `sanitize_line`.
        let ok = unsafe {
            has_prefix(linebuf, BEGINSTR)
                && len >= TAILSTR.len() as c_int
                && has_prefix(
                    linebuf.add((len - TAILSTR.len() as c_int) as usize),
                    TAILSTR,
                )
        };
        if ok {
            break;
        }
    }
    // SAFETY: `len >= TAILSTR.len()` from the test above, so the byte is inside the buffer.
    unsafe { *linebuf.add((len - TAILSTR.len() as c_int) as usize) = 0 };
    len = len - BEGINSTR.len() as c_int - TAILSTR.len() as c_int + 1;
    // SAFETY: `name` is the caller's out-parameter; `flags` is a real flag word.
    let nm = unsafe { pem_malloc(len as usize, flags, FILE_PEM_LIB, 808) }.cast::<c_char>();
    if nm.is_null() {
        // SAFETY: this frame's own buffer, freed exactly once on this path.
        unsafe {
            pem_free(
                linebuf.cast(),
                flags,
                (LINESIZE + 1) as usize,
                FILE_PEM_LIB,
                815,
            )
        };
        return 0;
    }
    // SAFETY: `nm` is writable for `len` bytes and the source is inside `linebuf`.
    unsafe {
        ptr::copy_nonoverlapping(linebuf.add(BEGINSTR.len()), nm, len as usize);
        *name = nm;
    }
    // SAFETY: as above. The authority reaches this through `ret = 1; goto err`, so the free below
    // is the same statement the two early returns above perform.
    unsafe {
        pem_free(
            linebuf.cast(),
            flags,
            (LINESIZE + 1) as usize,
            FILE_PEM_LIB,
            815,
        )
    };
    1
}

/// `enum header_status` — `crypto/pem/pem_lib.c:820-824`.
///
/// The three enumerators' shared `_HEADER` postfix is the authority's spelling, not a naming
/// choice this crate made, so the lint is allowed rather than the names changed.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderStatus {
    /// `MAYBE_HEADER`.
    MaybeHeader,
    /// `IN_HEADER`.
    InHeader,
    /// `POST_HEADER`.
    PostHeader,
}

/// `static int get_header_and_data(BIO *bp, BIO **header, BIO **data, char *name, unsigned int flags)`
/// — `crypto/pem/pem_lib.c:837-936`.
///
/// Two things here are not obvious and both are observed:
///
/// * the `*header`/`*data` **swap** for a block that has no header — the common case — so the
///   body's text is in the data BIO and the (empty) header BIO becomes the old data one;
/// * the 65-byte line test applies only *after* the header has ended, and a shorter line sets
///   `end`, after which a non-`END` line is `PEM_R_BAD_END_LINE`. A wrapped body is therefore
///   rejected and a body whose last line is short must be followed immediately by the footer.
///
/// # Safety
/// `bp` must be a live readable BIO; `header`/`data` writable for one pointer each and pointing at
/// live memory BIOs; `name` NUL-terminated.
unsafe fn get_header_and_data(
    bp: *mut Bio,
    header: *mut *mut Bio,
    data: *mut *mut Bio,
    name: *const c_char,
    flags: c_uint,
) -> c_int {
    // SAFETY: `header` is the caller's out-parameter.
    let mut tmp = unsafe { *header };
    let mut end = 0;
    let mut prev_partial_line_read = 0;
    // SAFETY: `flags` is a real flag word.
    let linebuf =
        unsafe { pem_malloc((LINESIZE + 1) as usize, flags, FILE_PEM_LIB, 850) }.cast::<c_char>();
    if linebuf.is_null() {
        return 0;
    }
    // 0 if not seen (yet), 1 if reading header, 2 if finished header.
    let mut got_header = HeaderStatus::MaybeHeader;

    loop {
        let mut flags_mask: c_uint = c_uint::MAX;
        // SAFETY: `bp` is live and `linebuf` is writable for `LINESIZE`.
        let mut len = unsafe { BIO_gets(bp, linebuf, LINESIZE) };
        if len <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_858) };
            // SAFETY: this frame's own buffer, freed exactly once on this path.
            unsafe {
                pem_free(
                    linebuf.cast(),
                    flags,
                    (LINESIZE + 1) as usize,
                    FILE_PEM_LIB,
                    934,
                )
            };
            return 0;
        }

        // Check if the line has been read completely or if only part of it has. Keep the previous
        // value to ignore newlines that appear due to reading a line up to the char before the
        // newline.
        // SAFETY: `len <= LINESIZE`, so the byte is inside the caller's buffer.
        let partial_line_read = len == LINESIZE - 1
            && unsafe { *linebuf.add(LINESIZE as usize - 2) } != b'\n' as c_char;
        let prev = prev_partial_line_read;
        prev_partial_line_read = c_int::from(partial_line_read);

        if got_header == HeaderStatus::MaybeHeader {
            // SAFETY: `len` bytes are valid in the buffer.
            let has_colon =
                unsafe { core::slice::from_raw_parts(linebuf.cast::<u8>(), len as usize) }
                    .contains(&b':');
            if has_colon {
                got_header = HeaderStatus::InHeader;
            }
        }
        // SAFETY: `linebuf` is NUL-terminated by `BIO_gets` or the previous `sanitize_line`.
        if unsafe { has_prefix(linebuf, ENDSTR) } || got_header == HeaderStatus::InHeader {
            flags_mask &= !PEM_FLAG_ONLY_B64;
        }
        // SAFETY: `len` bytes are valid in the caller's buffer.
        len = unsafe { sanitize_line(linebuf, len, flags & flags_mask, 0) };

        // Check for the end of the header.
        // SAFETY: the pointer is live per the caller's contract.
        if unsafe { *linebuf } as u8 == b'\n' {
            // If the previous line was read only partially this newline is a regular newline at the
            // end of a line and not an empty line.
            if prev == 0 {
                if got_header == HeaderStatus::PostHeader {
                    // Another blank line is an error.
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PEM_LIB_887) };
                    // SAFETY: this frame's own buffer.
                    unsafe {
                        pem_free(
                            linebuf.cast(),
                            flags,
                            (LINESIZE + 1) as usize,
                            FILE_PEM_LIB,
                            934,
                        )
                    };
                    return 0;
                }
                got_header = HeaderStatus::PostHeader;
                // SAFETY: `data` is the caller's out-parameter.
                tmp = unsafe { *data };
            }
            continue;
        }

        // Check for the end of stream (which means there is no header).
        // SAFETY: `linebuf` is NUL-terminated by `sanitize_line`.
        if let Some(p) = unsafe { check_and_skip_prefix(linebuf, ENDSTR) } {
            // SAFETY: `name` is NUL-terminated per the contract.
            let name_bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
            let namelen = name_bytes.len();
            // SAFETY: `p` is NUL-terminated and `namelen` bytes of it are compared with `name`.
            let rest = unsafe { CStr::from_ptr(p) }.to_bytes();
            // SAFETY: the pointer is live per the caller's contract.
            let tail_ok = unsafe { has_prefix(p.add(namelen), TAILSTR) };
            if rest.len() < namelen || &rest[..namelen] != name_bytes || !tail_ok {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PEM_LIB_901) };
                // SAFETY: this frame's own buffer.
                unsafe {
                    pem_free(
                        linebuf.cast(),
                        flags,
                        (LINESIZE + 1) as usize,
                        FILE_PEM_LIB,
                        934,
                    )
                };
                return 0;
            }
            if got_header == HeaderStatus::MaybeHeader {
                // SAFETY: the two out-parameters are the caller's.
                unsafe {
                    *header = *data;
                    *data = tmp;
                }
            }
            break;
        } else if end != 0 {
            // Malformed input; short line not at end of data.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_911) };
            // SAFETY: this frame's own buffer.
            unsafe {
                pem_free(
                    linebuf.cast(),
                    flags,
                    (LINESIZE + 1) as usize,
                    FILE_PEM_LIB,
                    934,
                )
            };
            return 0;
        }
        // Else, a line of text -- could be header or data; we don't know yet. Just pass it
        // through.
        // SAFETY: `tmp` is a live memory BIO and `linebuf` is NUL-terminated.
        if unsafe { BIO_puts(tmp, linebuf) } < 0 {
            // SAFETY: this frame's own buffer.
            unsafe {
                pem_free(
                    linebuf.cast(),
                    flags,
                    (LINESIZE + 1) as usize,
                    FILE_PEM_LIB,
                    934,
                )
            };
            return 0;
        }
        // Only encrypted files need the line length check applied.
        if got_header == HeaderStatus::PostHeader {
            // 65 includes the trailing newline.
            if len > 65 {
                // SAFETY: this frame's own buffer.
                unsafe {
                    pem_free(
                        linebuf.cast(),
                        flags,
                        (LINESIZE + 1) as usize,
                        FILE_PEM_LIB,
                        934,
                    )
                };
                return 0;
            }
            if len < 65 {
                end = 1;
            }
        }
    }

    // SAFETY: as above. The authority reaches this through `ret = 1; goto err`, so the free below
    // is the same statement the six early returns above perform.
    unsafe {
        pem_free(
            linebuf.cast(),
            flags,
            (LINESIZE + 1) as usize,
            FILE_PEM_LIB,
            934,
        )
    };
    1
}

/// The `end:` label of [`PEM_read_bio_ex`]: free the encode context, the name (when the caller has
/// not taken it) and the two memory BIOs. Every path through the reader reaches it exactly once.
///
/// # Safety
/// `ctx`/`name`/`header_b`/`data_b` are that frame's own; `flags` is a real flag word.
unsafe fn pem_read_bio_end(
    ctx: *mut EvpEncodeCtx,
    name: *mut c_char,
    header_b: *mut Bio,
    data_b: *mut Bio,
    flags: c_uint,
) {
    // SAFETY: each pointer is freed exactly once on this path; NULL is accepted by all three.
    unsafe {
        EVP_ENCODE_CTX_free(ctx);
        pem_free(name.cast(), flags, 0, FILE_PEM_LIB, 1029);
        BIO_free(header_b);
        BIO_free(data_b);
    }
}

/// The `out_free:` label of [`PEM_read_bio_ex`]: release the two blocks the caller's
/// out-parameters point at and NULL them, so the `end:` label cannot free them a second time.
///
/// # Safety
/// `header`/`data` must be that frame's own out-parameters.
unsafe fn pem_read_bio_out_free(header: *mut *mut c_char, data: *mut *mut c_uchar, flags: c_uint) {
    // SAFETY: the two slots hold this frame's own blocks or NULL.
    unsafe {
        pem_free((*header).cast(), flags, 0, FILE_PEM_LIB, 1023);
        *header = ptr::null_mut();
        pem_free((*data).cast(), flags, 0, FILE_PEM_LIB, 1025);
        *data = ptr::null_mut();
    }
}

/// `int PEM_read_bio_ex(BIO *bp, char **name_out, char **header, unsigned char **data, long *len_out, unsigned int flags)`
/// — `crypto/pem/pem_lib.c:944-1033`.
///
/// The reader's whole framing layer, and the only `PEM_*` entry point in this row that needs
/// nothing from another stratum. Its first statement is a refusal: `PEM_FLAG_EAY_COMPATIBLE` and
/// `PEM_FLAG_ONLY_B64` cannot both be set, because the first strips trailing whitespace and the
/// second stops at it — asking for both asks for two different bodies.
///
/// The decode is **in place** (`EVP_DecodeUpdate(ctx, buf_mem->data, &len, buf_mem->data, len)`),
/// which is why the input and output pointers are the same expression in the authority's own
/// source and why the two calls may not be reordered with respect to the read.
///
/// # Safety
/// `bp` must be a live readable BIO; the four out-parameters writable; `flags` a real flag word.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_ex(
    bp: *mut Bio,
    name_out: *mut *mut c_char,
    header: *mut *mut c_char,
    data: *mut *mut c_uchar,
    len_out: *mut c_long,
    flags: c_uint,
) -> c_int {
    let mut ctx: *mut EvpEncodeCtx = ptr::null_mut();
    let mut header_b: *mut Bio = ptr::null_mut();
    let mut data_b: *mut Bio = ptr::null_mut();
    let mut name: *mut c_char = ptr::null_mut();
    let mut ret = 0;

    // SAFETY: the four out-parameters are the caller's.
    unsafe {
        *len_out = 0;
        *name_out = ptr::null_mut();
        *header = ptr::null_mut();
        *data = ptr::null_mut();
    }

    'body: {
        if flags & PEM_FLAG_EAY_COMPATIBLE != 0 && flags & PEM_FLAG_ONLY_B64 != 0 {
            // These two are mutually incompatible; bail out.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_959) };
            break 'body;
        }
        // SAFETY: `flags` is a real flag word.
        let bmeth = if flags & PEM_FLAG_SECURE != 0 {
            BIO_s_secmem()
        } else {
            BIO_s_mem()
        };

        // SAFETY: `bmeth` is a live method table.
        unsafe {
            header_b = BIO_new(bmeth);
            data_b = BIO_new(bmeth);
        }
        if header_b.is_null() || data_b.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_967) };
            break 'body;
        }

        // SAFETY: `bp` is live and `name` is this frame's own slot.
        if unsafe { get_name(bp, &mut name, flags) } == 0 {
            break 'body;
        }
        // SAFETY: as above; `name` is NUL-terminated by `get_name`.
        if unsafe { get_header_and_data(bp, &mut header_b, &mut data_b, name, flags) } == 0 {
            break 'body;
        }

        // `BIO_get_mem_ptr(dataB, &buf_mem)` — a macro over `BIO_ctrl`.
        let mut buf_mem: *mut BufMem = ptr::null_mut();
        // SAFETY: `data_b` is a live memory BIO and `buf_mem` is this frame's own slot.
        unsafe {
            BIO_ctrl(
                data_b,
                BIO_C_GET_BUF_MEM_PTR,
                0,
                (&mut buf_mem as *mut *mut BufMem).cast(),
            )
        };
        if buf_mem.is_null() {
            break 'body;
        }
        // SAFETY: `buf_mem` is the memory BIO's own `BUF_MEM`, which the BIO keeps alive.
        if unsafe { (*buf_mem).length } > c_int::MAX as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_978) };
            break 'body;
        }
        // SAFETY: `buf_mem` is live.
        let mut len = unsafe { (*buf_mem).length } as c_int;

        // There was no data in the PEM file.
        if len == 0 {
            break 'body;
        }

        // SAFETY: the constructor's contract.
        ctx = EVP_ENCODE_CTX_new();
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_989) };
            break 'body;
        }

        let mut taillen: c_int = 0;
        // SAFETY: `ctx` is live; the input and the output are the same `BUF_MEM` buffer, which is
        // the authority's own aliasing decode.
        let decoded = unsafe {
            EVP_DecodeInit(ctx);
            EVP_DecodeUpdate(
                ctx,
                (*buf_mem).data.cast::<c_uchar>(),
                &mut len,
                (*buf_mem).data.cast::<c_uchar>(),
                len,
            ) < 0
                || EVP_DecodeFinal(
                    ctx,
                    (*buf_mem).data.add(len as usize).cast::<c_uchar>(),
                    &mut taillen,
                ) < 0
        };
        if decoded {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PEM_LIB_1000) };
            break 'body;
        }
        len += taillen;
        // SAFETY: `buf_mem` is live and the decode wrote in place.
        unsafe { (*buf_mem).length = len as usize };

        // `headerlen = BIO_get_mem_data(headerB, NULL)` — a macro over `BIO_ctrl`, and the answer
        // is the *available* byte count, not the buffer's capacity.
        let mut headerp: *mut c_char = ptr::null_mut();
        // SAFETY: `header_b` is a live memory BIO and `headerp` is this frame's own slot.
        let headerlen = unsafe {
            BIO_ctrl(
                header_b,
                BIO_CTRL_INFO,
                0,
                (&mut headerp as *mut *mut c_char).cast(),
            )
        } as c_int;

        // SAFETY: `flags` is a real flag word.
        let hdr = unsafe { pem_malloc((headerlen + 1) as usize, flags, FILE_PEM_LIB, 1007) }
            .cast::<c_char>();
        // SAFETY: as above.
        let dat = unsafe { pem_malloc(len as usize, flags, FILE_PEM_LIB, 1008) }.cast::<c_uchar>();
        // SAFETY: the two slots are the caller's out-parameters.
        unsafe {
            *header = hdr;
            *data = dat;
        }
        if hdr.is_null() || dat.is_null() {
            // SAFETY: the two slots are this frame's own blocks or NULL.
            unsafe { pem_read_bio_out_free(header, data, flags) };
            break 'body;
        }
        // SAFETY: `hdr` is writable for `headerlen + 1` bytes and `header_b` is live.
        let header_ok =
            headerlen == 0 || unsafe { BIO_read(header_b, hdr.cast(), headerlen) } == headerlen;
        if !header_ok {
            // SAFETY: the two slots are this frame's own blocks.
            unsafe { pem_read_bio_out_free(header, data, flags) };
            break 'body;
        }
        // SAFETY: `hdr` is writable for `headerlen + 1` bytes.
        unsafe { *hdr.add(headerlen as usize) = 0 };
        // SAFETY: `dat` is writable for `len` bytes and `data_b` is live.
        if unsafe { BIO_read(data_b, dat.cast(), len) } != len {
            // SAFETY: the two slots are this frame's own blocks.
            unsafe { pem_read_bio_out_free(header, data, flags) };
            break 'body;
        }
        // SAFETY: the three out-parameters are the caller's, and `name` is now theirs.
        unsafe {
            *len_out = len as c_long;
            *name_out = name;
        }
        name = ptr::null_mut();
        ret = 1;
    }

    // SAFETY: this frame's own pointers, freed exactly once on every path.
    unsafe { pem_read_bio_end(ctx, name, header_b, data_b, flags) };
    ret
}

/// `int PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data, long *len)` —
/// `crypto/pem/pem_lib.c:1035-1039`.
///
/// `PEM_FLAG_EAY_COMPATIBLE` and nothing else, which is what makes the plain reader strip trailing
/// whitespace from every line and *not* apply the base64-only rule.
///
/// # Safety
/// As [`PEM_read_bio_ex`] with this flag word.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio(
    bp: *mut Bio,
    name: *mut *mut c_char,
    header: *mut *mut c_char,
    data: *mut *mut c_uchar,
    len: *mut c_long,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { PEM_read_bio_ex(bp, name, header, data, len, PEM_FLAG_EAY_COMPATIBLE) }
}

/// `BIO_new(BIO_s_file())` + `BIO_set_fp(b, fp, BIO_NOCLOSE)` — the prelude both `FILE *` spellings
/// in this file share.
///
/// Answers NULL after raising the caller's site, which is why the site is a parameter: `PEM_read`
/// raises at `:711` and `PEM_write` at `:625`, and the reason is the same `ERR_R_BUF_LIB` at both.
///
/// # Safety
/// `fp` must be an open stream of the right direction.
unsafe fn bio_from_fp(fp: *mut c_void, site: &crate::runtime::err::err_sites::ErrSite) -> *mut Bio {
    // SAFETY: `BIO_s_file` is a static method table.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the caller passes one of the two compile-time-constant sites.
        unsafe { raise_site(site) };
        return ptr::null_mut();
    }
    // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
    // SAFETY: `b` is live and `fp` is the caller's stream.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, BIO_NOCLOSE, fp) };
    b
}

/// `int PEM_read(FILE *fp, char **name, char **header, unsigned char **data, long *len)` —
/// `crypto/pem/pem_lib.c:704-718`.
///
/// # Safety
/// `fp` must be an open readable stream; the four out-parameters as [`PEM_read_bio_ex`].
#[no_mangle]
pub unsafe extern "C" fn PEM_read(
    fp: *mut c_void,
    name: *mut *mut c_char,
    header: *mut *mut c_char,
    data: *mut *mut c_uchar,
    len: *mut c_long,
) -> c_int {
    // SAFETY: `fp` is the caller's stream.
    let b = unsafe { bio_from_fp(fp, &err_sites::PEM_LIB_711) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a live file BIO and the out-parameters are the caller's.
    let ret = unsafe { PEM_read_bio(b, name, header, data, len) };
    // SAFETY: `b` is this frame's own file BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int PEM_write(FILE *fp, const char *name, const char *header, const unsigned char *data, long len)`
/// — `crypto/pem/pem_lib.c:618-632`.
///
/// # Safety
/// `fp` must be an open writable stream; `name` and `header` NUL-terminated; `data` readable for
/// `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn PEM_write(
    fp: *mut c_void,
    name: *const c_char,
    header: *const c_char,
    data: *const c_uchar,
    len: c_long,
) -> c_int {
    // SAFETY: `fp` is the caller's stream.
    let b = unsafe { bio_from_fp(fp, &err_sites::PEM_LIB_625) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: `b` is a live file BIO and the rest are the caller's.
    let ret = unsafe { PEM_write_bio(b, name, header, data, len) };
    // SAFETY: `b` is this frame's own file BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `err:` in [`PEM_write_bio`] — raise once, then release the context and the line buffer.
///
/// # Safety
/// `ctx` must be this frame's own context or NULL; `buf` its own line buffer or NULL.
unsafe fn pem_write_bio_err(
    ctx: *mut EvpEncodeCtx,
    buf: *mut c_uchar,
    reason: c_int,
    retval: c_int,
) {
    if retval == 0 && reason != 0 {
        // SAFETY: the reason is this frame's runtime choice, which is why the generator marked
        // `PEM_LIB_697` `dynamic_reason`.
        unsafe { raise_site_dynamic(&err_sites::PEM_LIB_697, reason) };
    }
    // SAFETY: this frame's own context and buffer; NULL is accepted by both.
    unsafe {
        EVP_ENCODE_CTX_free(ctx);
        CRYPTO_clear_free(buf.cast(), (PEM_BUFSIZE * 8) as usize, FILE_PEM_LIB, 699);
    }
}

/// `int PEM_write_bio(BIO *bp, const char *name, const char *header, const unsigned char *data, long len)`
/// — `crypto/pem/pem_lib.c:635-701`.
///
/// The `reason`/`retval` pair is one error report for five failure points: every arm sets `reason`
/// and jumps to `err:`, and the single `ERR_raise(ERR_LIB_PEM, reason)` at `:697` fires only while
/// `retval` is still 0. So a short `BIO_write` of the footer reports `ERR_R_BIO_LIB` **once** with
/// no chain of five records, and the return value is the encoded body's length, not the whole
/// block's.
///
/// # Safety
/// `bp` must be a live writable BIO; `name` and `header` NUL-terminated; `data` readable for `len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio(
    bp: *mut Bio,
    name: *const c_char,
    header: *const c_char,
    data: *const c_uchar,
    len: c_long,
) -> c_int {
    // SAFETY: the constructor's contract.
    let ctx = EVP_ENCODE_CTX_new();
    let mut reason: c_int = 0;
    let mut retval: c_int = 0;
    let mut buf: *mut c_uchar = ptr::null_mut();

    if ctx.is_null() {
        reason = ERR_R_EVP_LIB;
        // SAFETY: this frame's own context and buffer.
        unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
        return retval;
    }

    // SAFETY: `ctx` is live.
    unsafe { EVP_EncodeInit(ctx) };
    // SAFETY: `name` is NUL-terminated per the contract.
    let nlen = unsafe { CStr::from_ptr(name) }.to_bytes().len() as c_int;

    // SAFETY: `bp` is live and the three statements are the caller's.
    let wrote_head = unsafe {
        BIO_write(bp, c"-----BEGIN ".as_ptr().cast(), 11) == 11
            && BIO_write(bp, name.cast(), nlen) == nlen
            && BIO_write(bp, c"-----\n".as_ptr().cast(), 6) == 6
    };
    if !wrote_head {
        reason = ERR_R_BIO_LIB;
        // SAFETY: this frame's own context and buffer.
        unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
        return retval;
    }

    let mut i = if header.is_null() {
        0
    } else {
        // SAFETY: `header` is NUL-terminated per the contract.
        unsafe { CStr::from_ptr(header) }.to_bytes().len() as c_int
    };
    if i > 0 {
        // SAFETY: `bp` is live and `header` is readable for `i` bytes.
        let wrote_header = unsafe {
            BIO_write(bp, header.cast(), i) == i && BIO_write(bp, c"\n".as_ptr().cast(), 1) == 1
        };
        if !wrote_header {
            reason = ERR_R_BIO_LIB;
            // SAFETY: this frame's own context and buffer.
            unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
            return retval;
        }
    }

    // `OPENSSL_malloc_array(PEM_BUFSIZE, 8)`.
    buf = CRYPTO_malloc_array(PEM_BUFSIZE as usize, 8, FILE_PEM_LIB, 665).cast::<c_uchar>();
    if buf.is_null() {
        // SAFETY: this frame's own context and buffer.
        unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
        return retval;
    }

    let mut j: c_long = 0;
    let mut len = len;
    let mut outl: c_int = 0;
    // `i = j = 0;` — the header's length was in `i` one statement ago and the accumulator starts
    // again here.
    i = 0;
    while len > 0 {
        let n = if len > c_long::from(PEM_BUFSIZE * 5) {
            PEM_BUFSIZE * 5
        } else {
            len as c_int
        };
        // SAFETY: `ctx` is live; `buf` is writable for one line; `data + j` is readable for `n`,
        // because `j` is the number of bytes already encoded.
        let ok = unsafe { EVP_EncodeUpdate(ctx, buf, &mut outl, data.offset(j as isize), n) };
        if ok == 0 {
            reason = ERR_R_EVP_LIB;
            // SAFETY: this frame's own context and buffer.
            unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
            return retval;
        }
        if outl != 0 {
            // SAFETY: `bp` is live and `buf` holds `outl` bytes.
            if unsafe { BIO_write(bp, buf.cast(), outl) } != outl {
                reason = ERR_R_BIO_LIB;
                // SAFETY: this frame's own context and buffer.
                unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
                return retval;
            }
        }
        i += outl;
        len -= c_long::from(n);
        j += c_long::from(n);
    }
    // SAFETY: `ctx` is live and `buf` is writable for one line.
    unsafe { EVP_EncodeFinal(ctx, buf, &mut outl) };
    if outl > 0 {
        // SAFETY: `bp` is live and `buf` holds `outl` bytes.
        if unsafe { BIO_write(bp, buf.cast(), outl) } != outl {
            reason = ERR_R_BIO_LIB;
            // SAFETY: this frame's own context and buffer.
            unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
            return retval;
        }
    }
    // SAFETY: `bp` is live; the three statements are the caller's.
    let wrote_tail = unsafe {
        BIO_write(bp, c"-----END ".as_ptr().cast(), 9) == 9
            && BIO_write(bp, name.cast(), nlen) == nlen
            && BIO_write(bp, c"-----\n".as_ptr().cast(), 6) == 6
    };
    if !wrote_tail {
        reason = ERR_R_BIO_LIB;
        // SAFETY: this frame's own context and buffer.
        unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
        return retval;
    }
    retval = i + outl;

    // SAFETY: this frame's own context and buffer.
    unsafe { pem_write_bio_err(ctx, buf, reason, retval) };
    retval
}

// ---------------------------------------------------------------------------------------------
// `crypto/pem/pem_sign.c`
// ---------------------------------------------------------------------------------------------

/// `int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type)` — `crypto/pem/pem_sign.c:17-20`.
///
/// The `ENGINE *` argument `EVP_DigestInit_ex` takes is NULL, which is the whole reason this
/// wrapper exists: it is the pre-3.0 spelling of the call.
///
/// # Safety
/// `ctx` must be a live digest context; `type_` a live method or NULL.
#[no_mangle]
pub unsafe extern "C" fn PEM_SignInit(ctx: *mut EvpMdCtx, type_: *mut EvpMd) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_DigestInit_ex(ctx, type_, ptr::null_mut()) }
}

/// `int PEM_SignUpdate(EVP_MD_CTX *ctx, const unsigned char *data, unsigned int count)` —
/// `crypto/pem/pem_sign.c:22-26`.
///
/// `count` is an `unsigned int` and `EVP_DigestUpdate` takes a `size_t`, so the widening is
/// implicit and exact.
///
/// # Safety
/// `ctx` must be a live digest context; `data` readable for `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn PEM_SignUpdate(
    ctx: *mut EvpMdCtx,
    data: *const c_uchar,
    count: c_uint,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_DigestUpdate(ctx, data.cast(), count as usize) }
}

/// `int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey)`
/// — `crypto/pem/pem_sign.c:28-49`.
///
/// Three layers in eight lines: `EVP_PKEY_get_size` sizes the scratch block, `EVP_SignFinal` signs
/// into it, and `EVP_EncodeBlock` base64s the signature into the caller's buffer — so `*siglen` is
/// the *encoded* length and has nothing to do with the signature's. The scratch block is freed on
/// both paths, and the context is the callee's to zero, which the authority's own comment says at
/// the label.
///
/// # Safety
/// `ctx` must be a live digest context; `sigret` writable for the encoded signature; `siglen`
/// writable; `pkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn PEM_SignFinal(
    ctx: *mut EvpMdCtx,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    pkey: *mut EvpPkey,
) -> c_int {
    let mut ret = 0;
    // SAFETY: `pkey` is live per the contract.
    let size = unsafe { EVP_PKEY_get_size(pkey) };
    // SAFETY: the allocation validates its own argument; `size` is the key's signature length.
    let m = CRYPTO_malloc(size as usize, FILE_PEM_SIGN, 35).cast::<c_uchar>();
    if m.is_null() {
        return ret;
    }

    let mut m_len: c_uint = 0;
    // SAFETY: `ctx` and `pkey` are live and `m` is writable for `size`.
    let signed = unsafe { EVP_SignFinal(ctx, m, &mut m_len, pkey) };
    if signed <= 0 {
        // SAFETY: `m` is this frame's own block.
        unsafe { CRYPTO_free(m.cast(), FILE_PEM_SIGN, 47) };
        return ret;
    }

    // SAFETY: `sigret` is writable for the encoded form of `m_len` and `m` is readable for it.
    let i = unsafe { EVP_EncodeBlock(sigret, m, m_len as c_int) };
    // SAFETY: `siglen` is the caller's out-parameter.
    unsafe { *siglen = i as c_uint };
    ret = 1;
    // `ctx` has been zeroed by `EVP_SignFinal()`.
    // SAFETY: `m` is this frame's own block.
    unsafe { CRYPTO_free(m.cast(), FILE_PEM_SIGN, 47) };
    ret
}

// ---------------------------------------------------------------------------------------------
// `crypto/asn1/asn_mime.c` — the one `asn1.h` hand-off that builds
// ---------------------------------------------------------------------------------------------

/// `static int B64_write_ASN1(BIO *out, ASN1_VALUE *val, BIO *in, int flags, const ASN1_ITEM *it)`
/// — `crypto/asn1/asn_mime.c:105-124`.
///
/// # Safety
/// `out` and `in_` must be live BIOs; `val` and `it` as `i2d_ASN1_bio_stream` requires.
unsafe fn b64_write_asn1(
    out: *mut Bio,
    val: *mut c_void,
    in_: *mut Bio,
    flags: c_int,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the method table is a static.
    let b64 = unsafe { BIO_new(BIO_f_base64()) };
    if b64.is_null() {
        // SAFETY: a compile-time-constant site.
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
        let _ = BIO_ctrl(out, BIO_CTRL_FLUSH, 0, ptr::null_mut());
        BIO_pop(out);
        BIO_free(b64);
    }
    r
}

/// `int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags, const char *hdr, const ASN1_ITEM *it)`
/// — `crypto/asn1/asn_mime.c:128-134`.
///
/// **This function is `asn_mime.c`'s and not `bio_asn1.c`'s**, which the brief for this row guessed
/// and this slice measured. It is one of the three Phase-5 `asn1.h` hand-offs and the only one that
/// builds, because everything under it — `BIO_f_base64` (this slice), `i2d_ASN1_bio_stream`
/// (`src/asn1/asn_mime.rs`) and `BIO_printf` — is already in the crate.
///
/// The whole body is three statements joined by `&&`, so the footer is written **only** when the
/// header and the body succeeded; the test on `BIO_printf` is `>= 0`, not `> 0`.
///
/// # Safety
/// `out` and `in_` must be live BIOs; `hdr` NUL-terminated; `val` and `it` as
/// `i2d_ASN1_bio_stream` requires.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_ASN1_stream(
    out: *mut Bio,
    val: *mut c_void,
    in_: *mut Bio,
    flags: c_int,
    hdr: *const c_char,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: `out` is live and `hdr` is NUL-terminated per the contract.
    let head = unsafe { BIO_printf(out, c"-----BEGIN %s-----\n".as_ptr(), hdr) } >= 0;
    // SAFETY: the four arguments are the caller's.
    let body = head && unsafe { b64_write_asn1(out, val, in_, flags, it) } != 0;
    // SAFETY: `out` is live and `hdr` is NUL-terminated.
    let tail = body && unsafe { BIO_printf(out, c"-----END %s-----\n".as_ptr(), hdr) } >= 0;
    c_int::from(tail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::cipher::{EVP_CIPHER_meth_new, EVP_CIPHER_meth_set_iv_length};
    use crate::evp::legacy_evp::EVP_add_cipher;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{BIO_free, BIO_new};

    /// `PEM_write_bio` then `PEM_read_bio_ex` over one memory BIO: the name, the header and the
    /// bytes all come back as this test wrote them, and the writer's answer is the *encoded body's*
    /// length.
    #[test]
    fn write_then_read_round_trips_the_name_header_and_bytes() {
        let tbs = b"\x01\x02\x03\x04\x05";
        // SAFETY: every pointer below is one of this test's own objects.
        unsafe {
            let bio = BIO_new(BIO_s_mem());
            assert!(!bio.is_null());
            let n = PEM_write_bio(
                bio,
                c"TEST ITEM".as_ptr(),
                c"X-Foo: bar\n".as_ptr(),
                tbs.as_ptr(),
                tbs.len() as c_long,
            );
            assert_eq!(
                n, 9,
                "five bytes are one padded block of eight characters and a line break, and the\n                 header's length is not part of the answer -- which is what makes the `i = j = 0;`\n                 reset at `pem_lib.c:669` observable"
            );

            let mut name: *mut c_char = ptr::null_mut();
            let mut header: *mut c_char = ptr::null_mut();
            let mut data: *mut c_uchar = ptr::null_mut();
            let mut len: c_long = 0;
            assert_eq!(
                PEM_read_bio_ex(
                    bio,
                    &mut name,
                    &mut header,
                    &mut data,
                    &mut len,
                    PEM_FLAG_EAY_COMPATIBLE,
                ),
                1
            );
            assert_eq!(
                CStr::from_ptr(name).to_bytes(),
                b"TEST ITEM",
                "the delimiters and the prefix are stripped"
            );
            assert_eq!(
                CStr::from_ptr(header).to_bytes(),
                b"X-Foo: bar\n",
                "the header keeps its own newline and loses the blank line that ends it"
            );
            assert_eq!(len, tbs.len() as c_long);
            assert_eq!(core::slice::from_raw_parts(data, len as usize), tbs);

            pem_free(name.cast(), 0, 0, FILE_PEM_LIB, 0);
            pem_free(header.cast(), 0, 0, FILE_PEM_LIB, 0);
            pem_free(data.cast(), 0, 0, FILE_PEM_LIB, 0);
            assert_eq!(BIO_free(bio), 1);
        }
    }

    /// The three answers `PEM_get_EVP_CIPHER_INFO` gives before it needs a cipher: an absent header
    /// is a success with a NULL cipher and a zeroed IV, `Proc-Type:` without `DEK-Info:` refuses,
    /// and a well-formed pair naming an algorithm nothing resolves refuses with a NULL cipher.
    #[test]
    fn cipher_info_parses_the_proc_type_and_dek_info_pair() {
        // SAFETY: every buffer below is this test's own storage.
        unsafe {
            let mut info = EvpCipherInfo {
                cipher: ptr::null(),
                iv: [0u8; EVP_MAX_IV_LENGTH],
            };

            let mut empty = *b"\0";
            assert_eq!(
                PEM_get_EVP_CIPHER_INFO(empty.as_mut_ptr().cast(), &mut info),
                1
            );
            assert!(info.cipher.is_null());
            assert_eq!(info.iv, [0u8; EVP_MAX_IV_LENGTH]);

            let mut no_dek = *b"Proc-Type: 4,ENCRYPTED\n\0";
            assert_eq!(
                PEM_get_EVP_CIPHER_INFO(no_dek.as_mut_ptr().cast(), &mut info),
                0
            );

            let mut bad_algo = *b"Proc-Type: 4,ENCRYPTED\nDEK-Info: NO-SUCH-CIPHER,000102030405060708090A0B0C0D0E0F\n\0";
            assert_eq!(
                PEM_get_EVP_CIPHER_INFO(bad_algo.as_mut_ptr().cast(), &mut info),
                0
            );
            assert!(info.cipher.is_null(), "an unresolvable name leaves NULL");
        }
    }

    /// The `DEK-Info:` name is looked up **after** the whitespace that separates it from the
    /// label: the authority assigns `dekinfostart = header` *after* its own
    /// `header += strspn(header, " \t")` (`crypto/pem/pem_lib.c:561`, `:567`, `:571`). A
    /// regression that passed the un-skipped pointer would look up `" PROBE-CIPH"` and answer
    /// `PEM_R_UNSUPPORTED_ENCRYPTION` here -- the authority answers 1 with the cipher and the eight
    /// IV bytes.
    ///
    /// The method is registered with `EVP_add_cipher` because `EVP_get_cipherbyname` finds a name
    /// only in the legacy `OBJ_NAME` table (`crypto/evp/names.c:86`), which is the other half of
    /// what this test pins. It is deliberately not freed: the table holds the borrowed pointer.
    #[test]
    fn cipher_info_skips_the_whitespace_before_the_dek_info_name() {
        // SAFETY: the method is this test's own object, every buffer is its own storage, and the
        // header below is NUL-terminated.
        unsafe {
            // `NID_undef` is 0, so the method registers under `"UNDEF"`/`"undefined"`.
            let cipher = EVP_CIPHER_meth_new(0, 1, 8);
            assert!(!cipher.is_null());
            assert_eq!(EVP_CIPHER_meth_set_iv_length(cipher, 8), 1);
            assert_eq!(EVP_add_cipher(cipher), 1);

            let mut info = EvpCipherInfo {
                cipher: ptr::null(),
                iv: [0u8; EVP_MAX_IV_LENGTH],
            };
            let mut hdr = *b"Proc-Type: 4,ENCRYPTED\nDEK-Info: UNDEF,0001020304050607\n\0";

            assert_eq!(
                PEM_get_EVP_CIPHER_INFO(hdr.as_mut_ptr().cast(), &mut info),
                1
            );
            assert_eq!(info.cipher, cipher);
            assert_eq!(&info.iv[..9], &[0, 1, 2, 3, 4, 5, 6, 7, 0]);
        }
    }

    /// `ossl_pem_check_suffix` answers the *prefix* length, and 0 when there is no prefix — which
    /// is why its callers can use `> 0` as the test.
    #[test]
    fn pem_check_suffix_answers_the_prefix_length() {
        // SAFETY: both arguments are NUL-terminated statics.
        unsafe {
            assert_eq!(
                ossl_pem_check_suffix(c"RSA PRIVATE KEY".as_ptr(), c"PRIVATE KEY".as_ptr()),
                3
            );
            assert_eq!(
                ossl_pem_check_suffix(c"PRIVATE KEY".as_ptr(), c"PRIVATE KEY".as_ptr()),
                0
            );
            assert_eq!(
                ossl_pem_check_suffix(c"DH PARAMETERS".as_ptr(), c"PARAMETERS".as_ptr()),
                2
            );
        }
    }
}
