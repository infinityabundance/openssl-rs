//! Phase 5 / Phase 9 staging — `crypto/pem/pem_lib.c`.
//!
//! Phase 5 landed this file's two header formatters, `PEM_proc_type` and `PEM_dek_info` —
//! the two exports of the unit that need nothing beyond `BIO_snprintf`. Phase 9's slice
//! (D350) adds the **password-and-plumbing** half of the same unit: `PEM_def_callback`, the
//! `pem_bytes_read_bio_flags` reader and its two public wrappers, `check_pem`, `PEM_do_header`,
//! `PEM_ASN1_read`/`_write`/`_write_bio`/`_write_bio_ctx` and the `PEM_ASN1_write_bio_internal`
//! body the three writers share. `crypto/pem/pem_oth.c`'s single export `PEM_ASN1_read_bio`
//! lands beside it in [`crate::pem::pem_oth`], because it is a separate translation unit and
//! keeping one unit per module is what makes the transcription atlas's `build_edges` measurable.
//!
//! ## What Phase 5 wrote, unchanged
//!
//! `PEM_proc_type` and `PEM_dek_info` are the only two exports of the PEM stratum that need
//! nothing beyond `BIO_snprintf`, and they are the two that *append* rather than write: each
//! starts at `buf + strlen(buf)` and leaves whatever was already there alone.
//! `PEM_ASN1_write_bio_internal` assembles a header by calling them in sequence — first the
//! `Proc-Type`, then the `DEK-Info` — and that accumulation is the observable part of them.
//!
//! ## The one place the authority writes outside the buffer, and this one does not
//!
//! `PEM_BUFSIZE` is the only length either function has to work with; the caller is
//! not asked for one, so the contract is "a `PEM_BUFSIZE`-byte buffer". The authority
//! computes the remaining space as an `int` and converts it to `size_t` at each call,
//! so a negative remainder becomes enormous. It does not test for that, and two paths
//! reach it:
//!
//! * `PEM_proc_type`'s `BIO_snprintf(p, PEM_BUFSIZE - (p - buf), …)`, when the
//!   caller's existing prefix is already longer than `PEM_BUFSIZE`;
//! * `PEM_dek_info`'s per-byte `%02X`, which returns `2` whether or not two bytes
//!   were written. With exactly one byte left it writes the NUL alone and leaves `j`
//!   at `-1`; the next iteration then calls `BIO_snprintf(p, (size_t)-1, …)` and
//!   writes the encoding of every remaining byte past the end of the buffer.
//!
//! The candidate clamps the length to zero and stops the loop when no room is left.
//! Everything inside the buffer is identical — the truncated NULs land in the same
//! places — so the divergence is only in the region the authority writes illegally.
//! It is recorded as `D-PEM-1` and no compatibility claim covers that region.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::{D2iOfVoid, I2dOfVoid};
use crate::evp::cipher::{EVP_CIPHER_get0_name, EVP_CIPHER_get_iv_length, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::legacy_md5::EVP_md5;
use crate::evp::p_legacy::{EVP_BytesToKey, EVP_get_pw_prompt, EVP_read_pw_string_min};
use crate::evp::pem_bridge::{
    pem_free, EvpCipherInfo, PemPasswordCb, PEM_FLAG_EAY_COMPATIBLE, PEM_FLAG_SECURE,
};
use crate::evp::pkey_asn1::{EVP_PKEY_asn1_find_str, Engine, EvpPkeyAsn1Method};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{memcpy, strcmp, strlen};
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_SET_FILE_PTR};
use crate::runtime::err::{err_sites, peek_first_reason, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc, OPENSSL_cleanse};
use crate::runtime::str::OPENSSL_strnlen;

/// `PEM_BUFSIZE` — `pem.h`'s header buffer length.
pub(crate) const PEM_BUFSIZE: c_int = 1024;
/// `PEM_TYPE_ENCRYPTED` — `pem.h`.
pub(crate) const PEM_TYPE_ENCRYPTED: c_int = 10;
/// `PEM_TYPE_MIC_ONLY` — `pem.h`.
pub(crate) const PEM_TYPE_MIC_ONLY: c_int = 20;
/// `PEM_TYPE_MIC_CLEAR` — `pem.h`.
pub(crate) const PEM_TYPE_MIC_CLEAR: c_int = 30;

/// `void PEM_proc_type(char *buf, int type)`
///
/// Appends `Proc-Type: 4,<name>\n` at the end of what `buf` already holds. Only
/// `ENCRYPTED`, `MIC-CLEAR` and `MIC-ONLY` are named; every other value — including
/// `pem.h`'s `PEM_TYPE_CLEAR`, which has no arm of its own — appends `BAD-TYPE`.
///
/// # Safety
///
/// `buf` must point at a NUL-terminated string in a writable region of at least
/// `PEM_BUFSIZE` bytes, or be null, in which case the authority dereferences it and
/// this does too.
#[no_mangle]
pub unsafe extern "C" fn PEM_proc_type(buf: *mut c_char, type_: c_int) {
    let str_ = match type_ {
        PEM_TYPE_ENCRYPTED => c"ENCRYPTED".as_ptr(),
        PEM_TYPE_MIC_CLEAR => c"MIC-CLEAR".as_ptr(),
        PEM_TYPE_MIC_ONLY => c"MIC-ONLY".as_ptr(),
        _ => c"BAD-TYPE".as_ptr(),
    };
    // SAFETY: the caller's contract makes `buf` a NUL-terminated string.
    let used = unsafe { OPENSSL_strnlen(buf, usize::MAX) } as c_int;
    // The authority subtracts as an `int` and converts at the call; the clamp is the
    // divergence D-PEM-1 describes.
    let room = (PEM_BUFSIZE - used).max(0) as usize;
    // SAFETY: `buf + used` is inside the caller's `PEM_BUFSIZE`-byte region when the
    // caller honoured the contract, `room` is what is left of it, and the format and
    // argument match. The cursor arithmetic is wrapping because `used` can exceed
    // `PEM_BUFSIZE` for a caller that did not; see D-PEM-1.
    unsafe {
        BIO_snprintf(
            buf.wrapping_add(used as usize),
            room,
            c"Proc-Type: 4,%s\n".as_ptr(),
            str_,
        )
    };
}

/// `void PEM_dek_info(char *buf, const char *type, int len, const char *str)`
///
/// Appends `DEK-Info: <type>,` and then `len` bytes of `str` as uppercase hex, then a
/// newline — but only if more than one byte of room remains for it, which is the
/// authority's `if (j > 1)`. A `BIO_snprintf` that answers zero or less abandons the
/// whole thing without further writes.
///
/// # Safety
///
/// `buf` as [`PEM_proc_type`]; `type` must be a NUL-terminated string; `str` must be
/// readable for `len` bytes, and `len` non-negative.
#[no_mangle]
pub unsafe extern "C" fn PEM_dek_info(
    buf: *mut c_char,
    type_: *const c_char,
    len: c_int,
    str_: *const c_char,
) {
    // SAFETY: the caller's contract makes `buf` a NUL-terminated string.
    let used = unsafe { OPENSSL_strnlen(buf, usize::MAX) } as c_int;
    let mut p = used as usize;
    let mut j = PEM_BUFSIZE - used;
    // SAFETY: the caller's contract; `type_` is NUL-terminated.
    let n = unsafe {
        BIO_snprintf(
            buf.wrapping_add(p),
            j.max(0) as usize,
            c"DEK-Info: %s,".as_ptr(),
            type_,
        )
    };
    if n <= 0 {
        return;
    }
    j -= n;
    p += n as usize;
    let mut i = 0;
    while i < len {
        // The authority reaches this call with a negative `j` and a `size_t` that is
        // therefore enormous; see D-PEM-1. Stopping here is what keeps the write
        // inside the caller's buffer.
        if j <= 0 {
            return;
        }
        // SAFETY: `str_` is readable for `len` bytes and `i < len`.
        let byte = c_int::from(unsafe { *str_.add(i as usize) } as u8);
        // SAFETY: `p` is inside the buffer and `j` bytes of room remain. Wrapping
        // again: the authority advances past the end here and this does not write
        // there, but the cursor value has to stay representable.
        let n = unsafe { BIO_snprintf(buf.wrapping_add(p), j as usize, c"%02X".as_ptr(), byte) };
        if n <= 0 {
            return;
        }
        j -= n;
        p += n as usize;
        i += 1;
    }
    if j > 1 {
        // SAFETY: `j > 1` means `buf + p` has at least two writable bytes, and the
        // two-byte static is NUL-terminated.
        unsafe { copy_two(buf.wrapping_add(p), c"\n".as_ptr()) };
    }
}

/// `strcpy(dst, "\n")` — the two bytes, `\n` and the terminator.
///
/// # Safety
///
/// `dst` must be writable for two bytes.
unsafe fn copy_two(dst: *mut c_char, src: *const c_char) {
    // SAFETY: the caller's contract.
    unsafe {
        *dst = *src;
        *dst.add(1) = *src.add(1);
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 9's slice of `crypto/pem/pem_lib.c` (D350).
// ---------------------------------------------------------------------------------------------

/// `MIN_LENGTH` — `crypto/pem/pem_lib.c:30`. The minimum `PEM_def_callback` asks for when
/// *encrypting*, where the authority assumes the caller is choosing a new pass phrase.
const MIN_LENGTH: c_int = 4;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `EVP_MAX_BLOCK_LENGTH` — `include/openssl/evp.h:37`. The spare block the writer allocates
/// beyond the DER length so the cipher's final block has room.
const EVP_MAX_BLOCK_LENGTH: usize = 32;
/// `INT_MAX` — the ``LONG_MAX > INT_MAX`` guard's bound.
const INT_MAX: c_long = 2147483647;

/// `PEM_STRING_EVP_PKEY` — `include/openssl/pem.h:35`.
const PEM_STRING_EVP_PKEY: *const c_char = c"ANY PRIVATE KEY".as_ptr();
/// `PEM_STRING_PKCS8` — `include/openssl/pem.h:44`.
const PEM_STRING_PKCS8: *const c_char = c"ENCRYPTED PRIVATE KEY".as_ptr();
/// `PEM_STRING_PKCS8INF` — `include/openssl/pem.h:45`.
const PEM_STRING_PKCS8INF: *const c_char = c"PRIVATE KEY".as_ptr();
/// `PEM_STRING_PARAMETERS` — `include/openssl/pem.h:52`.
const PEM_STRING_PARAMETERS: *const c_char = c"PARAMETERS".as_ptr();
/// `PEM_STRING_DHPARAMS` — `include/openssl/pem.h:46`.
pub(crate) const PEM_STRING_DHPARAMS: *const c_char = c"DH PARAMETERS".as_ptr();
/// `PEM_STRING_DHXPARAMS` — `include/openssl/pem.h:47`.
pub(crate) const PEM_STRING_DHXPARAMS: *const c_char = c"X9.42 DH PARAMETERS".as_ptr();
/// `PEM_STRING_RSA` — `include/openssl/pem.h:38`.
pub(crate) const PEM_STRING_RSA: *const c_char = c"RSA PRIVATE KEY".as_ptr();
/// `PEM_STRING_RSA_PUBLIC` — `include/openssl/pem.h:39`.
pub(crate) const PEM_STRING_RSA_PUBLIC: *const c_char = c"RSA PUBLIC KEY".as_ptr();
/// `PEM_STRING_DSA` — `include/openssl/pem.h:40`.
pub(crate) const PEM_STRING_DSA: *const c_char = c"DSA PRIVATE KEY".as_ptr();
/// `PEM_STRING_DSAPARAMS` — `include/openssl/pem.h:49`.
pub(crate) const PEM_STRING_DSAPARAMS: *const c_char = c"DSA PARAMETERS".as_ptr();
/// `PEM_STRING_ECPARAMETERS` — `include/openssl/pem.h:51`.
pub(crate) const PEM_STRING_ECPARAMETERS: *const c_char = c"EC PARAMETERS".as_ptr();
/// `PEM_STRING_PUBLIC` — `include/openssl/pem.h:36`. The name the four `*_PUBKEY` expansions use;
/// those are Phase 11's, so no row here reaches it, and the constant is not defined until one does.
/// `PEM_STRING_ECPRIVATEKEY` — `include/openssl/pem.h:53`.
pub(crate) const PEM_STRING_ECPRIVATEKEY: *const c_char = c"EC PRIVATE KEY".as_ptr();

/// `OSSL_i2d_of_void_ctx` — `include/openssl/asn1.h:334`'s function *type*.
///
/// `int (*)(const void *, unsigned char **, void *vctx)`. A type and not a pointer, exactly as
/// `i2d_of_void` is, so `PEM_ASN1_write_bio_ctx`'s parameter is a bare function pointer.
pub type OsslI2dOfVoidCtx =
    unsafe extern "C" fn(*const c_void, *mut *mut c_uchar, *mut c_void) -> c_int;

/// `int PEM_def_callback(char *buf, int num, int rwflag, void *userdata)` —
/// `crypto/pem/pem_lib.c:36-69`.
///
/// The two arms are the whole contract. With `userdata` non-NULL the pass phrase is a
/// `strlen`/`memcpy` clamped to `num` — no prompting, no `UI`, and the arm every
/// `PEM_ASN1_write_*` caller with a supplied `kstr` reaches. With `userdata` NULL it prompts
/// through `EVP_read_pw_string_min`, which is the `UI` program; a refusal raises
/// `PEM_R_PROBLEMS_GETTING_PASSWORD`, zeroes the whole `num`-byte buffer and answers `-1`.
///
/// The signature is exactly `pem_password_cb`'s, because the function is one.
///
/// # Safety
/// `buf` writable for `num` bytes; `userdata` NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn PEM_def_callback(
    buf: *mut c_char,
    num: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
) -> c_int {
    if !userdata.is_null() {
        // SAFETY: `userdata` is NUL-terminated per the contract.
        let mut i = unsafe { strlen(userdata.cast::<c_char>()) } as c_int;
        if i > num {
            i = num;
        }
        // SAFETY: `buf` is `num` writable bytes and `userdata` is `i` readable bytes.
        unsafe { memcpy(buf.cast::<c_void>(), userdata, i as usize) };
        return i;
    }

    // SAFETY: `EVP_get_pw_prompt` touches only its own static.
    let mut prompt = unsafe { EVP_get_pw_prompt() };
    if prompt.is_null() {
        prompt = c"Enter PEM pass phrase:".as_ptr().cast_mut();
    }

    /* `rwflag == 0` is decryption, `rwflag == 1` encryption; only encryption has a minimum. */
    let min_len = if rwflag != 0 { MIN_LENGTH } else { 0 };

    // SAFETY: `buf` is `num` writable bytes and `prompt` is NUL-terminated.
    let i = unsafe { EVP_read_pw_string_min(buf, min_len, num, prompt, rwflag) };
    if i != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_64) };
        // SAFETY: `buf` is `num` writable bytes.
        unsafe { ptr::write_bytes(buf, 0, num.max(0) as usize) };
        return -1;
    }
    // SAFETY: `buf` holds a NUL-terminated pass phrase written by the prompt path.
    unsafe { strlen(buf) as c_int }
}

/// `static int pem_bytes_read_bio_flags(...)` — `crypto/pem/pem_lib.c:243-284`.
///
/// The reader every PEM entry point funnels through. Its loop is the interesting part: each
/// candidate block is read with `PEM_read_bio_ex` and rejected by [`check_pem`] until one
/// matches `name`, and the three buffers are freed at the **top** of each iteration with the
/// previous pass's `len`. A read that finds no BEGIN line appends `"Expecting: <name>"` to the
/// queue only when the oldest error is `PEM_R_NO_START_LINE`.
///
/// # Safety
/// `pdata`/`plen` writable; `pnm` NULL or writable; `name` NUL-terminated; `bp` a live readable
/// BIO; `cb` NULL or a `pem_password_cb`; `u` passed through to the callback.
#[allow(clippy::too_many_arguments)]
unsafe fn pem_bytes_read_bio_flags(
    pdata: *mut *mut c_uchar,
    plen: *mut c_long,
    pnm: *mut *mut c_char,
    name: *const c_char,
    bp: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
    flags: c_uint,
) -> c_int {
    // SAFETY: the all-zero `EvpCipherInfo` is a valid value and `PEM_get_EVP_CIPHER_INFO`
    // overwrites both fields before they are read.
    let mut cipher: EvpCipherInfo = unsafe { core::mem::zeroed() };
    let mut nm: *mut c_char = ptr::null_mut();
    let mut header: *mut c_char = ptr::null_mut();
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;
    let mut ret: c_int = 0;

    loop {
        // `PEM_FREE(nm, flags, 0)`, `PEM_FREE(header, flags, 0)`, `PEM_FREE(data, flags, len)`.
        // SAFETY: each pointer is NULL or a block from the previous iteration's `pem_malloc`, and
        // `len` is that iteration's length.
        unsafe {
            pem_free(nm.cast::<c_void>(), flags, 0, FILE, LINE_BYTES_255);
            pem_free(header.cast::<c_void>(), flags, 0, FILE, LINE_BYTES_256);
            pem_free(
                data.cast::<c_void>(),
                flags,
                len as usize,
                FILE,
                LINE_BYTES_257,
            );
        }
        // SAFETY: `bp` is live and the three out-parameters are this frame's own.
        if unsafe {
            crate::evp::pem_bridge::PEM_read_bio_ex(
                bp,
                &mut nm,
                &mut header,
                &mut data,
                &mut len,
                flags,
            )
        } == 0
        {
            // SAFETY: `ERR_peek_error` touches only the calling thread's queue.
            if peek_first_reason() as c_int == err_sites::PEM_LIB_794.reason {
                // SAFETY: `name` is NUL-terminated per the contract.
                unsafe { add_expecting_error(name) };
            }
            return 0;
        }
        // SAFETY: `nm` and `name` are NUL-terminated.
        if unsafe { check_pem(nm, name) } != 0 {
            break;
        }
    }
    // SAFETY: `header` is the reader's header string and `cipher` is this frame's own.
    if unsafe { crate::evp::pem_bridge::PEM_get_EVP_CIPHER_INFO(header, &mut cipher) } == 0 {
        // SAFETY: the buffers are this frame's own and `flags` the caller's.
        return unsafe { bytes_read_epilogue(ret, pnm, nm, header, data, len, flags) };
    }
    // SAFETY: `cipher`/`data`/`len` are this frame's own and `cb`/`u` are the caller's.
    if unsafe { PEM_do_header(&mut cipher, data, &mut len, cb, u) } == 0 {
        // SAFETY: the buffers are this frame's own and `flags` the caller's.
        return unsafe { bytes_read_epilogue(ret, pnm, nm, header, data, len, flags) };
    }

    // SAFETY: the three out-parameters are the caller's per the contract.
    unsafe {
        *pdata = data;
        *plen = len;
        if !pnm.is_null() {
            *pnm = nm;
        }
    }
    ret = 1;
    // SAFETY: the buffers are this frame's own and `flags` the caller's.
    unsafe { bytes_read_epilogue(ret, pnm, nm, header, data, len, flags) }
}

/// `err:` of `pem_bytes_read_bio_flags` — `crypto/pem/pem_lib.c:277-283`.
///
/// Three frees whose guards differ: the name is released unless it is being handed back
/// (`pnm != NULL` on success), the header always, and the data only on failure.
///
/// # Safety
/// `nm`/`header`/`data` are NULL or blocks from `pem_malloc` under `flags`; `len` is the data's.
unsafe fn bytes_read_epilogue(
    ret: c_int,
    pnm: *mut *mut c_char,
    nm: *mut c_char,
    header: *mut c_char,
    data: *mut c_uchar,
    len: c_long,
    flags: c_uint,
) -> c_int {
    // SAFETY: the pointers are NULL or ours.
    unsafe {
        if ret == 0 || pnm.is_null() {
            pem_free(nm.cast::<c_void>(), flags, 0, FILE, LINE_BYTES_279);
        }
        pem_free(header.cast::<c_void>(), flags, 0, FILE, LINE_BYTES_280);
        if ret == 0 {
            pem_free(
                data.cast::<c_void>(),
                flags,
                len as usize,
                FILE,
                LINE_BYTES_282,
            );
        }
    }
    ret
}

/// `ERR_add_error_data(2, "Expecting: ", name)` — `crypto/pem/pem_lib.c:260`.
///
/// The concatenation is built here and handed to the queue's one data slot, because
/// `ERR_add_error_data` is C-variadic and the crate routes every such call through
/// `openssl_rs_err_add_data` with the joined string.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn add_expecting_error(name: *const c_char) {
    let mut buf: [c_char; 1024] = [0; 1024];
    // SAFETY: `buf` is 1024 bytes and both `%s` arguments are NUL-terminated.
    unsafe { BIO_snprintf(buf.as_mut_ptr(), buf.len(), c"Expecting: %s".as_ptr(), name) };
    // SAFETY: `buf` is NUL-terminated by the format above.
    unsafe { crate::runtime::err::openssl_rs_err_add_data(buf.as_ptr()) };
}

/// `int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name,
/// BIO *bp, pem_password_cb *cb, void *u)` — `crypto/pem/pem_lib.c:286-292`.
///
/// The `PEM_FLAG_EAY_COMPATIBLE` spelling — the one every caller that is not reading a secret
/// uses.
///
/// # Safety
/// As [`pem_bytes_read_bio_flags`].
#[no_mangle]
pub unsafe extern "C" fn PEM_bytes_read_bio(
    pdata: *mut *mut c_uchar,
    plen: *mut c_long,
    pnm: *mut *mut c_char,
    name: *const c_char,
    bp: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { pem_bytes_read_bio_flags(pdata, plen, pnm, name, bp, cb, u, PEM_FLAG_EAY_COMPATIBLE) }
}

/// `int PEM_bytes_read_bio_secmem(...)` — `crypto/pem/pem_lib.c:294-300`.
///
/// Identical to [`PEM_bytes_read_bio`] except that `PEM_FLAG_SECURE` is added, so the three
/// buffers come from — and are cleared back into — the secure heap.
///
/// # Safety
/// As [`pem_bytes_read_bio_flags`].
#[no_mangle]
pub unsafe extern "C" fn PEM_bytes_read_bio_secmem(
    pdata: *mut *mut c_uchar,
    plen: *mut c_long,
    pnm: *mut *mut c_char,
    name: *const c_char,
    bp: *mut Bio,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        pem_bytes_read_bio_flags(
            pdata,
            plen,
            pnm,
            name,
            bp,
            cb,
            u,
            PEM_FLAG_SECURE | PEM_FLAG_EAY_COMPATIBLE,
        )
    }
}

/// `static int check_pem(const char *nm, const char *name)` — `crypto/pem/pem_lib.c:128-221`.
///
/// The name-matching table. `name` is what the caller asked for and `nm` is what was found; the
/// pairs that match are the authority's own compatibility list. The two `ANY PRIVATE KEY` /
/// `PARAMETERS` arms consult the ASN.1 method registry through `EVP_PKEY_asn1_find_str`, so a
/// method object with a decoding callback makes its PEM name acceptable.
///
/// The `PARAMETERS` arm is the one place the authority holds an `ENGINE *`: it passes `&e` to
/// `EVP_PKEY_asn1_find_str` and calls `ENGINE_finish(e)` before answering. `ENGINE` is Phase 13's
/// and this crate has no engine registry, so the `*pe = NULL` the find function writes is the
/// whole of that arm — D181's reduction, the same one `src/evp/pkey_asn1.rs` records for
/// `EVP_PKEY_asn1_find`.
///
/// # Safety
/// `nm` and `name` must be NUL-terminated.
unsafe fn check_pem(nm: *const c_char, name: *const c_char) -> c_int {
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, name) } == 0 {
        return 1;
    }

    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(name, PEM_STRING_EVP_PKEY) } == 0 {
        // SAFETY: both are NUL-terminated per the contract.
        if unsafe { strcmp(nm, PEM_STRING_PKCS8) } == 0 {
            return 1;
        }
        // SAFETY: both are NUL-terminated per the contract.
        if unsafe { strcmp(nm, PEM_STRING_PKCS8INF) } == 0 {
            return 1;
        }
        // SAFETY: `nm` is NUL-terminated and the suffix is a static.
        let slen =
            unsafe { crate::evp::pem_bridge::ossl_pem_check_suffix(nm, c"PRIVATE KEY".as_ptr()) };
        if slen > 0 {
            // SAFETY: `nm` is readable for `slen` bytes and the engine slot is this frame's own.
            let ameth = unsafe { EVP_PKEY_asn1_find_str(ptr::null_mut(), nm, slen) };
            if !ameth.is_null() {
                // SAFETY: `ameth` is a live method object.
                if unsafe { (*ameth).old_priv_decode }.is_some() {
                    return 1;
                }
            }
        }
        return 0;
    }

    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(name, PEM_STRING_PARAMETERS) } == 0 {
        // SAFETY: `nm` is NUL-terminated and the suffix is a static.
        let slen =
            unsafe { crate::evp::pem_bridge::ossl_pem_check_suffix(nm, c"PARAMETERS".as_ptr()) };
        if slen > 0 {
            let mut e: *mut Engine = ptr::null_mut();
            // SAFETY: `nm` is readable for `slen` bytes and `e` is this frame's own slot.
            let ameth = unsafe { EVP_PKEY_asn1_find_str(&mut e, nm, slen) };
            if !ameth.is_null() {
                // SAFETY: `ameth` is a live method object.
                let r = c_int::from(unsafe { (*ameth).param_decode }.is_some());
                // `ENGINE_finish(e)` — the `*pe = NULL` that `EVP_PKEY_asn1_find_str` wrote is the
                // whole of the engine arm (D181): with no engine registered the authority's arm
                // answers NULL too, so there is nothing to finish.
                return r;
            }
        }
        return 0;
    }

    /* If reading DH parameters handle X9.42 DH format too. */
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, PEM_STRING_DHXPARAMS) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, PEM_STRING_DHPARAMS) } == 0
    {
        return 1;
    }

    /* Permit older strings. */
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"X509 CERTIFICATE".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"CERTIFICATE".as_ptr()) } == 0
    {
        return 1;
    }
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"NEW CERTIFICATE REQUEST".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"CERTIFICATE REQUEST".as_ptr()) } == 0
    {
        return 1;
    }
    /* Allow normal certs to be read as trusted certs. */
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"CERTIFICATE".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"TRUSTED CERTIFICATE".as_ptr()) } == 0
    {
        return 1;
    }
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"X509 CERTIFICATE".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"TRUSTED CERTIFICATE".as_ptr()) } == 0
    {
        return 1;
    }
    /* Some CAs use PKCS#7 with CERTIFICATE headers. */
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"CERTIFICATE".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"PKCS7".as_ptr()) } == 0
    {
        return 1;
    }
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"PKCS #7 SIGNED DATA".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"PKCS7".as_ptr()) } == 0
    {
        return 1;
    }
    /* Allow CMS to be read from PKCS#7 headers. */
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"CERTIFICATE".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"CMS".as_ptr()) } == 0
    {
        return 1;
    }
    // SAFETY: both are NUL-terminated per the contract.
    if unsafe { strcmp(nm, c"PKCS7".as_ptr()) } == 0
        // SAFETY: both are NUL-terminated per the contract.
        && unsafe { strcmp(name, c"CMS".as_ptr()) } == 0
    {
        return 1;
    }

    0
}

/// `int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
/// pem_password_cb *callback, void *u)` — `crypto/pem/pem_lib.c:445-504`.
///
/// Answers `1` immediately when the block is not encrypted (`cipher->cipher == NULL`), which is
/// the arm every plain `PEM_read_*` takes. Otherwise the key is derived with `EVP_BytesToKey`
/// over the header's IV-as-salt and the block is decrypted in place. The pass phrase comes from
/// the callback, or from [`PEM_def_callback`] when the caller supplied none.
///
/// `*plen` is updated incrementally: the decrypted-so-far length is stored **before** the final
/// block runs, so a failed `EVP_DecryptFinal_ex` leaves the caller's length already shortened.
/// The `LONG_MAX > INT_MAX` guard is active on this platform.
///
/// # Safety
/// `cipher` live; `data` writable for `*plen` bytes plus a cipher block; `plen` writable; `cb`
/// NULL or a `pem_password_cb`; `u` passed through to the callback.
#[no_mangle]
pub unsafe extern "C" fn PEM_do_header(
    cipher: *mut EvpCipherInfo,
    data: *mut c_uchar,
    plen: *mut c_long,
    callback: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `plen` is writable per the contract.
    let len = unsafe { *plen };
    let mut key = [0 as c_uchar; EVP_MAX_KEY_LENGTH];
    let mut buf = [0 as c_char; PEM_BUFSIZE as usize];

    if len > INT_MAX {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_459) };
        return 0;
    }
    let mut ilen = len as c_int;

    // SAFETY: `cipher` is live per the contract.
    if unsafe { (*cipher).cipher }.is_null() {
        return 1;
    }
    let keylen = match callback {
        // SAFETY: the callback's contract; `buf` is `PEM_BUFSIZE` bytes and `u` is the caller's.
        Some(cb) => unsafe { cb(buf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
        // SAFETY: `PEM_def_callback`'s contract; the buffer and `u` are as above.
        None => unsafe { PEM_def_callback(buf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
    };
    if keylen < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_471) };
        return 0;
    }

    // SAFETY: `cipher` is live; `key` is a 64-byte buffer; the IV and pass phrase are readable.
    if unsafe {
        EVP_BytesToKey(
            (*cipher).cipher,
            EVP_md5(),
            (*cipher).iv.as_ptr(),
            buf.as_ptr().cast::<c_uchar>(),
            keylen,
            1,
            key.as_mut_ptr(),
            ptr::null_mut(),
        )
    } == 0
    {
        return 0;
    }

    // SAFETY: no preconditions.
    let ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live; `cipher` is live; `key` and the IV are readable.
    let mut ok = unsafe {
        EVP_DecryptInit_ex(
            ctx,
            (*cipher).cipher,
            ptr::null_mut(),
            key.as_ptr(),
            (*cipher).iv.as_ptr(),
        )
    };
    if ok != 0 {
        // SAFETY: `ctx` is live; `data` is `ilen` readable and writable bytes.
        ok = unsafe { EVP_DecryptUpdate(ctx, data, &mut ilen, data, ilen) };
    }
    if ok != 0 {
        // Squirrel away the length of data decrypted so far.
        // SAFETY: `plen` is writable per the contract.
        unsafe { *plen = ilen as c_long };
        // SAFETY: `ctx` is live and `data + ilen` has room for the final block.
        ok = unsafe { EVP_DecryptFinal_ex(ctx, data.add(ilen as usize), &mut ilen) };
    }
    if ok != 0 {
        // SAFETY: `plen` is writable per the contract.
        unsafe { *plen += ilen as c_long };
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_498) };
    }

    // SAFETY: `ctx` is a live context this call created.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    // SAFETY: both are this frame's own arrays.
    unsafe {
        OPENSSL_cleanse(buf.as_mut_ptr().cast::<c_void>(), buf.len());
        OPENSSL_cleanse(key.as_mut_ptr().cast::<c_void>(), key.len());
    }
    ok
}

/// `int PEM_ASN1_write_bio_internal(...)` — `crypto/pem/pem_lib.c:322-426`.
///
/// The DER-then-wrap body all three writers share. `i2d` and `i2d_ctx` are alternatives: exactly
/// one is non-NULL and the other is the parameter the caller left NULL, which is why the
/// `both NULL` arm raises `CRYPTO_R_INVALID_NULL_ARGUMENT`. The encryption arm is the only one
/// that touches the pass phrase, and the plain writers pass `enc == NULL` so they never reach the
/// callback at all — the reason this function is not itself a `PEM_def_callback` blocker.
///
/// # Safety
/// `i2d`/`i2d_ctx` one non-NULL; `name` NUL-terminated; `bp` a live writable BIO; `x` the object
/// the encoder reads; `enc` NULL or live; `kstr` NULL or `klen` readable bytes; `cb`/`u` as
/// [`PEM_do_header`].
#[allow(clippy::too_many_arguments)]
#[allow(non_snake_case)]
unsafe fn PEM_ASN1_write_bio_internal(
    i2d: Option<I2dOfVoid>,
    i2d_ctx: Option<OsslI2dOfVoidCtx>,
    vctx: *mut c_void,
    name: *const c_char,
    bp: *mut Bio,
    x: *const c_void,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    callback: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    let mut dsize: c_int = 0;
    let mut i: c_int;
    let mut j: c_int = 0;
    let mut ret: c_int = 0;
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut klen = klen;
    let mut buf = [0 as c_char; PEM_BUFSIZE as usize];
    let mut key = [0 as c_uchar; EVP_MAX_KEY_LENGTH];
    let mut iv = [0 as c_uchar; EVP_MAX_IV_LENGTH];
    let mut ctx: *mut crate::evp::cipher_ctx::EvpCipherCtx = ptr::null_mut();

    /* The C body is a sequence of `goto err` jumps to one `err:` label. A labelled block is the
     * same control flow without the inlined exit, which also keeps the teardown in one place. */
    'body: {
        let mut objstr: *const c_char = ptr::null();
        if !enc.is_null() {
            // SAFETY: `enc` is live per the contract.
            objstr = unsafe { EVP_CIPHER_get0_name(enc) };
            // SAFETY: `enc` is live per the contract.
            let ivlen = unsafe { EVP_CIPHER_get_iv_length(enc) };
            let namelen = if objstr.is_null() {
                0
            } else {
                // SAFETY: `objstr` is NULL or a NUL-terminated method name.
                unsafe { strlen(objstr) as c_int }
            };
            if objstr.is_null()
                || ivlen == 0
                || ivlen > EVP_MAX_IV_LENGTH as c_int
                || namelen + 23 + 2 * ivlen + 13 > PEM_BUFSIZE
            {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::PEM_LIB_346) };
                break 'body;
            }
        }

        if i2d.is_none() && i2d_ctx.is_none() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::PEM_LIB_352) };
            dsize = 0;
            break 'body;
        }
        // SAFETY: exactly one encoder is present and `x` is the object it reads.
        dsize = unsafe {
            match (i2d, i2d_ctx) {
                (Some(f), _) => f(x, ptr::null_mut()),
                (None, Some(f)) => f(x, ptr::null_mut(), vctx),
                (None, None) => 0,
            }
        };
        if dsize <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::PEM_LIB_358) };
            dsize = 0;
            break 'body;
        }
        // Allocate enough space for one extra cipher block.
        // SAFETY: `CRYPTO_malloc` validates its own allocation.
        data = CRYPTO_malloc(
            dsize as usize + EVP_MAX_BLOCK_LENGTH,
            FILE,
            LINE_ASN1_WRITE_ALLOC,
        )
        .cast::<c_uchar>();
        if data.is_null() {
            break 'body;
        }
        let mut p = data;
        // SAFETY: `data` is `dsize + EVP_MAX_BLOCK_LENGTH` bytes and `p` starts at its head.
        i = unsafe {
            match (i2d, i2d_ctx) {
                (Some(f), _) => f(x, &mut p),
                (None, Some(f)) => f(x, &mut p, vctx),
                (None, None) => 0,
            }
        };

        if !enc.is_null() {
            if kstr.is_null() {
                klen = match callback {
                    // SAFETY: the callback's contract; `buf` is `PEM_BUFSIZE` bytes.
                    Some(cb) => unsafe { cb(buf.as_mut_ptr(), PEM_BUFSIZE, 1, u) },
                    // SAFETY: `PEM_def_callback`'s contract; `buf` and `u` are as above.
                    None => unsafe { PEM_def_callback(buf.as_mut_ptr(), PEM_BUFSIZE, 1, u) },
                };
                if klen <= 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::PEM_LIB_376) };
                    break 'body;
                }
            }
            // Generate a salt.
            // SAFETY: `iv` is 16 bytes and `EVP_CIPHER_get_iv_length` is the method's own length.
            if unsafe { RAND_bytes(iv.as_mut_ptr(), EVP_CIPHER_get_iv_length(enc)) } <= 0 {
                break 'body;
            }
            /* The IV is used as the IV and as a salt; it is NOT taken from `EVP_BytesToKey`. */
            // SAFETY: `enc` is live; `iv` and the pass phrase are readable; `key` is 64 bytes.
            let derive_ok = unsafe {
                EVP_BytesToKey(
                    enc,
                    EVP_md5(),
                    iv.as_ptr(),
                    if kstr.is_null() {
                        buf.as_ptr().cast::<c_uchar>()
                    } else {
                        kstr
                    },
                    klen,
                    1,
                    key.as_mut_ptr(),
                    ptr::null_mut(),
                )
            } != 0;
            if !derive_ok {
                break 'body;
            }

            if kstr.is_null() {
                // SAFETY: `buf` is this frame's own `PEM_BUFSIZE`-byte array.
                unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast::<c_void>(), PEM_BUFSIZE as usize) };
            }

            buf[0] = 0;
            // SAFETY: `buf` is `PEM_BUFSIZE` bytes.
            unsafe { PEM_proc_type(buf.as_mut_ptr(), PEM_TYPE_ENCRYPTED) };
            // SAFETY: `buf` is `PEM_BUFSIZE` bytes; `objstr` is NUL-terminated; `iv` is readable.
            unsafe {
                PEM_dek_info(
                    buf.as_mut_ptr(),
                    objstr,
                    EVP_CIPHER_get_iv_length(enc),
                    iv.as_ptr().cast::<c_char>(),
                )
            };

            ret = 1;
            // SAFETY: no preconditions.
            ctx = EVP_CIPHER_CTX_new();
            let mut enc_ok = !ctx.is_null();
            if enc_ok {
                // SAFETY: `ctx` is live; `enc`, `key` and `iv` are readable.
                enc_ok = unsafe {
                    EVP_EncryptInit_ex(ctx, enc, ptr::null_mut(), key.as_ptr(), iv.as_ptr())
                } != 0;
            }
            if enc_ok {
                // SAFETY: `ctx` is live; `data` is `i` readable and writable bytes.
                enc_ok = unsafe { EVP_EncryptUpdate(ctx, data, &mut j, data, i) } != 0;
            }
            if enc_ok {
                // SAFETY: `ctx` is live and `data + j` has room for the final block.
                enc_ok = unsafe { EVP_EncryptFinal_ex(ctx, data.add(j as usize), &mut i) } != 0;
            }
            if !enc_ok {
                ret = 0;
            }
            if ret == 0 {
                break 'body;
            }
            i += j;
        } else {
            ret = 1;
            buf[0] = 0;
        }
        // SAFETY: `bp` is a live writable BIO and `buf`/`data` are this frame's own.
        i = unsafe {
            crate::evp::pem_bridge::PEM_write_bio(bp, name, buf.as_ptr(), data, i as c_long)
        };
        if i <= 0 {
            ret = 0;
        }
    }
    // SAFETY: every pointer is this frame's own (`ctx` the context created above, `data` the DER
    // buffer, the three arrays the local buffers) and each may be NULL.
    unsafe { asn1_write_epilogue(ret, ctx, &mut key, &mut iv, &mut buf, data, dsize) }
}

/// `err:` of `PEM_ASN1_write_bio_internal` — `crypto/pem/pem_lib.c:419-425`.
///
/// The shared exit: cleanse the derived key, the IV and the header buffer, free the cipher
/// context and clear-free the DER buffer. The `dsize`-length clear-free is the one that matters —
/// a plain `CRYPTO_free` would leave the plaintext DER behind.
///
/// # Safety
/// `ctx` NULL or this call's context; `data` NULL or this call's `dsize`-byte DER buffer.
#[allow(clippy::too_many_arguments)]
unsafe fn asn1_write_epilogue(
    ret: c_int,
    ctx: *mut crate::evp::cipher_ctx::EvpCipherCtx,
    key: &mut [c_uchar; EVP_MAX_KEY_LENGTH],
    iv: &mut [c_uchar; EVP_MAX_IV_LENGTH],
    buf: &mut [c_char; PEM_BUFSIZE as usize],
    data: *mut c_uchar,
    dsize: c_int,
) -> c_int {
    // SAFETY: the three arrays are this frame's own and the context was created here.
    unsafe {
        OPENSSL_cleanse(key.as_mut_ptr().cast::<c_void>(), key.len());
        OPENSSL_cleanse(iv.as_mut_ptr().cast::<c_void>(), iv.len());
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(buf.as_mut_ptr().cast::<c_void>(), buf.len());
        CRYPTO_clear_free(
            data.cast::<c_void>(),
            dsize.max(0) as usize,
            FILE,
            LINE_ASN1_WRITE_FREE,
        );
    }
    ret
}

/// `int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp, const void *x,
/// const EVP_CIPHER *enc, const unsigned char *kstr, int klen, pem_password_cb *callback,
/// void *u)` — `crypto/pem/pem_lib.c:428-434`.
///
/// The plain encoder form: `i2d_ctx` and its `vctx` are both NULL.
///
/// # Safety
/// As [`PEM_ASN1_write_bio_internal`] with the `i2d`/`i2d_ctx` pair resolved.
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_write_bio(
    i2d: Option<I2dOfVoid>,
    name: *const c_char,
    bp: *mut Bio,
    x: *const c_void,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    callback: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        PEM_ASN1_write_bio_internal(
            i2d,
            None,
            ptr::null_mut(),
            name,
            bp,
            x,
            enc,
            kstr,
            klen,
            callback,
            u,
        )
    }
}

/// `int PEM_ASN1_write_bio_ctx(OSSL_i2d_of_void_ctx *i2d, void *vctx, const char *name, BIO *bp,
/// const void *x, const EVP_CIPHER *enc, const unsigned char *kstr, int klen,
/// pem_password_cb *callback, void *u)` — `crypto/pem/pem_lib.c:436-443`.
///
/// The context-taking form, which the encoder layer uses to pass a value the callback needs.
///
/// # Safety
/// As [`PEM_ASN1_write_bio_internal`] with the `i2d_ctx`/`vctx` pair resolved.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_write_bio_ctx(
    i2d: Option<OsslI2dOfVoidCtx>,
    vctx: *mut c_void,
    name: *const c_char,
    bp: *mut Bio,
    x: *const c_void,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    callback: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        PEM_ASN1_write_bio_internal(None, i2d, vctx, name, bp, x, enc, kstr, klen, callback, u)
    }
}

/// `void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
/// pem_password_cb *cb, void *u)` — `crypto/pem/pem_lib.c:111-125`.
///
/// The `FILE *` spelling of [`PEM_ASN1_read_bio`]: wrap the stream in a file BIO, read, release
/// the BIO. The BIO is created with `BIO_NOCLOSE`, so the caller's stream stays open.
///
/// # Safety
/// `d2i` the decoder; `name` NUL-terminated; `fp` an open readable stream; `x` the decoder's
/// destination; `cb`/`u` as [`PEM_do_header`].
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_read(
    d2i: D2iOfVoid,
    name: *const c_char,
    fp: *mut c_void,
    x: *mut *mut c_void,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut c_void {
    // SAFETY: `BIO_s_file` is a static method table.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_118) };
        return ptr::null_mut();
    }
    // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
    // SAFETY: `b` is live and `fp` is the caller's stream.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, 0, fp) };
    // SAFETY: `b` is a live file BIO and the rest is the caller's.
    let ret = unsafe { PEM_ASN1_read_bio(d2i, name, b, x, cb, u) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp, const void *x,
/// const EVP_CIPHER *enc, const unsigned char *kstr, int klen, pem_password_cb *callback,
/// void *u)` — `crypto/pem/pem_lib.c:303-319`.
///
/// The `FILE *` spelling of [`PEM_ASN1_write_bio`].
///
/// # Safety
/// As [`PEM_ASN1_write_bio`], with `fp` an open writable stream.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn PEM_ASN1_write(
    i2d: Option<I2dOfVoid>,
    name: *const c_char,
    fp: *mut c_void,
    x: *const c_void,
    enc: *const EvpCipher,
    kstr: *const c_uchar,
    klen: c_int,
    callback: Option<PemPasswordCb>,
    u: *mut c_void,
) -> c_int {
    // SAFETY: `BIO_s_file` is a static method table.
    let b = unsafe { BIO_new(BIO_s_file()) };
    if b.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::PEM_LIB_312) };
        return 0;
    }
    // `BIO_set_fp(b, fp, BIO_NOCLOSE)`.
    // SAFETY: `b` is live and `fp` is the caller's stream.
    unsafe { BIO_ctrl(b, BIO_C_SET_FILE_PTR, 0, fp) };
    // SAFETY: `b` is a live file BIO and the rest is the caller's.
    let ret = unsafe { PEM_ASN1_write_bio(i2d, name, b, x, enc, kstr, klen, callback, u) };
    // SAFETY: `b` is this frame's own BIO.
    unsafe { BIO_free(b) };
    ret
}

/// `OPENSSL_FILE` at the sites in `crypto/pem/pem_lib.c` whose line numbers these constants name.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c".as_ptr();
/// `PEM_FREE(nm, ...)` in the reader's loop (`pem_lib.c:255`).
const LINE_BYTES_255: c_int = 255;
/// `PEM_FREE(header, ...)` in the reader's loop (`pem_lib.c:256`).
const LINE_BYTES_256: c_int = 256;
/// `PEM_FREE(data, ...)` in the reader's loop (`pem_lib.c:257`).
const LINE_BYTES_257: c_int = 257;
/// `PEM_FREE(nm, ...)` in the reader's `err:` (`pem_lib.c:279`).
const LINE_BYTES_279: c_int = 279;
/// `PEM_FREE(header, ...)` in the reader's `err:` (`pem_lib.c:280`).
const LINE_BYTES_280: c_int = 280;
/// `PEM_FREE(data, ...)` in the reader's `err:` (`pem_lib.c:282`).
const LINE_BYTES_282: c_int = 282;
/// `PEM_ASN1_write_bio_internal`'s `OPENSSL_malloc` (`pem_lib.c:363`).
const LINE_ASN1_WRITE_ALLOC: c_int = 363;
/// `PEM_ASN1_write_bio_internal`'s `OPENSSL_clear_free` (`pem_lib.c:424`).
const LINE_ASN1_WRITE_FREE: c_int = 424;

/// The zero `EvpPkeyAsn1Method` shape is never constructed here; the import keeps the `Engine`
/// and method-object types the `check_pem` signature reads in one place.
#[allow(dead_code)]
fn _method_types_are_named(_e: *const Engine, _m: *const EvpPkeyAsn1Method) {}
