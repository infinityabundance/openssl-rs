//! Phase 7.4l — the five legacy entry points that are not the `standard_methods[]` readers.
//!
//! This module is the ledger's `src/evp/p_legacy.rs` row, which groups thirteen open symbols by
//! prefix rather than by translation unit. Five authority files own them, and the grouping is
//! worth stating because the row's name is not any one of them:
//!
//! ```text
//! crypto/evp/evp_key.c    EVP_BytesToKey, EVP_get_pw_prompt, EVP_set_pw_prompt,
//!                         EVP_read_pw_string, EVP_read_pw_string_min
//! crypto/evp/p_sign.c     EVP_SignFinal_ex, EVP_SignFinal
//! crypto/evp/p_verify.c   EVP_VerifyFinal_ex, EVP_VerifyFinal
//! crypto/evp/p_open.c     EVP_OpenInit, EVP_OpenFinal
//! crypto/evp/p_seal.c     EVP_SealInit, EVP_SealFinal
//! ```
//!
//! Eleven of the thirteen land and two do not, and each of the two is a stratum boundary rather
//! than a size boundary:
//!
//!   * **`EVP_BytesToKey`** is a digest loop over the landed `EVP_DigestInit_ex` / `Update` /
//!     `Final_ex` and the two cipher length accessors. It has no provider, no method table and no
//!     context of its own, so it is complete. Its one boundary is the pair of `OPENSSL_assert`s
//!     (see below), and `OpenSSL`'s is an active `OPENSSL_die` rather than an `ossl_assert`.
//!   * **`EVP_SignFinal(_ex)`** and **`EVP_VerifyFinal(_ex)`** are written over
//!     `EVP_PKEY_CTX_new_from_pkey` + `EVP_PKEY_sign_init`/`verify_init` + `EVP_PKEY_sign`/`verify`,
//!     all of which 7.4c and 7.4d landed. The `_ex` spellings are the bodies and the plain ones are
//!     one-line wrappers with `libctx`/`propq` NULL — the authority's own shape, transcribed.
//!   * **`EVP_OpenInit`**, **`EVP_OpenFinal`**, **`EVP_SealInit`** and **`EVP_SealFinal`** are
//!     `EVP_CIPHER_CTX` and `EVP_PKEY_decrypt`/`encrypt` calls, all landed. `EVP_SealInit`'s two
//!     former blockers have both landed (D315): `RAND_priv_bytes_ex` (`crypto/rand/rand_lib.c`,
//!     Phase 9) directly at `p_seal.c:46`, and `EVP_CIPHER_CTX_rand_key` at `:42`.
//!   * **`EVP_read_pw_string`** and **`EVP_read_pw_string_min`** are **not** here: they are the
//!     `UI`-backed pair and `ui.h` is Phase 13. They are withheld rather than stubbed, and
//!     `EVP_read_pw_string` goes with them because its whole body is a call to `_min`.
//!   * **`EVP_get_pw_prompt`** and **`EVP_set_pw_prompt`** *do* land: they touch the file's
//!     eighty-byte static and nothing else, so the `UI` boundary does not reach them. This is the
//!     one place the row's prefix grouping and the dependency boundary disagree, and the measurement
//!     says so rather than the prefix.
//!
//! ## `OPENSSL_assert` is not `NDEBUG`-gated, and the crate refuses instead
//!
//! `EVP_BytesToKey` opens with `OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH)` and
//! `OPENSSL_assert(niv >= 0 && niv <= EVP_MAX_IV_LENGTH)`. `include/openssl/crypto.h:475` expands
//! `OPENSSL_assert` to `OPENSSL_die`, which is an unconditional abort — so a cipher whose key
//! length is 65 or whose IV length is negative faults the authority *before* the `data == NULL`
//! early return. This crate refuses instead (returning 0), which is `D-RCU-3`'s disposition for the
//! same shape, and `RT-EVP-PBE` names the boundary without driving it because a fault cannot be
//! compared. `EVP_MAX_KEY_LENGTH` is 64 and `EVP_MAX_IV_LENGTH` is 16.
//!
//! ## The `goto err` is not the fall-through, and the return value says which
//!
//! `rv` is 0 and is assigned the cipher's key length **only** on the loop's normal exit; every
//! `goto err` skips the assignment. So a digest failure mid-derivation answers 0 where a success
//! answers `nkey`, even though both take the same `EVP_MD_CTX_free` and `OPENSSL_cleanse`. The
//! transcription carries a `done` flag for exactly that distinction.
//!
//! ## `EVP_SignFinal`'s two `EVP_DigestFinal_ex` doors
//!
//! The `FINALISE` flag chooses between finalising the caller's context in place and finalising a
//! *copy*, so a non-finalising call leaves the caller's context usable. The copy branch has the
//! authority's own fallback: if `EVP_MD_CTX_copy_ex` fails, it finalises the original instead and
//! frees the copy either way. Every one of those paths returns `0` on a digest failure, and only
//! the `tmp_ctx == NULL` arm raises — the others have already had their error recorded by the
//! digest layer.
//!
//! ## `EVP_OpenInit`'s two decrypts, and the NULL key length of the first
//!
//! The first `EVP_PKEY_decrypt(pctx, NULL, &keylen, ek, ekl)` is a size query: it writes the
//! required length and answers > 0 without a buffer. The `keylen` that the second call consumes is
//! therefore the provider's answer, not the caller's. `OPENSSL_clear_free(key, keylen)` must run on
//! the way out, so the module allocates through `CRYPTO_malloc` with the authority's own file and
//! line — the two coordinates a caller sees if the allocation is recordable.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::evp::asymcipher::{
    EVP_PKEY_decrypt, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::cipher::{
    EVP_CIPHER_get0_provider, EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_reset, EVP_CIPHER_CTX_set_key_length, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EvpCipherCtx,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get0_md, EVP_MD_CTX_new, EVP_MD_CTX_test_flags, EvpMd, EvpMdCtx,
};
use crate::evp::pkey::{EVP_PKEY_get_size, EvpPkey};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_CTX_set_signature_md,
    EvpPkeyCtx,
};
use crate::evp::signature::{
    EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify, EVP_PKEY_verify_init,
};
use crate::provider::ossl_provider_libctx;
use crate::rand::rand_lib::RAND_priv_bytes_ex;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_malloc, OPENSSL_cleanse};

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: c_int = 64;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: c_int = 16;
/// `PKCS5_SALT_LEN` — `include/openssl/evp.h`, the eight bytes `EVP_BytesToKey` salts with.
const PKCS5_SALT_LEN: usize = 8;

/// `EVP_MD_CTX_FLAG_FINALISE` — `include/openssl/evp.h`, **0x0200**.
///
/// The flag `EVP_SignFinal_ex`/`EVP_VerifyFinal_ex` test to decide whether the caller wants its
/// own context finalised; `src/evp/digest.rs` keeps the same constant private for the same reason.
const EVP_MD_CTX_FLAG_FINALISE: c_int = 0x0200;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE_OPEN: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/p_open.c".as_ptr();
/// `EVP_OpenInit`'s `OPENSSL_malloc(keylen)` (`p_open.c:45`).
const LINE_OPEN_MALLOC: c_int = 45;
/// `EVP_OpenInit`'s `OPENSSL_clear_free(key, keylen)` (`p_open.c:58`).
const LINE_OPEN_CLEAR_FREE: c_int = 58;

/// `EVP_BytesToKey`'s `static char prompt_string[80]` — `crypto/evp/evp_key.c:22`.
///
/// File-scope and shared by the four password functions, which is why it is not a local. The
/// authority initialises it to zeros with a comment rather than an initialiser; a zeroed Rust
/// static is the same state.
static mut PROMPT_STRING: [c_char; 80] = [0; 80];

/// `int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt,
/// const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv)` —
/// `crypto/evp/evp_key.c:80`.
///
/// The two `OPENSSL_assert`s are refusals here rather than aborts: see the module doc. The
/// `data == NULL` arm answers `nkey` **before** any digest is created, which is the one arm that
/// does no work at all. `count` is cast to `unsigned` exactly as the authority casts it, so
/// `count == 0` runs the inner loop zero times and a negative `count` would run it ~2^32 times on
/// both sides — the court drives the first and not the second.
///
/// # Safety
/// `type_` and `md` live; `salt` NULL or eight readable bytes; `data` NULL or `datal` readable
/// bytes; `key` NULL or `EVP_CIPHER_get_key_length(type_)` writable bytes; `iv` NULL or
/// `EVP_CIPHER_get_iv_length(type_)` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_BytesToKey(
    type_: *const EvpCipher,
    md: *const EvpMd,
    salt: *const c_uchar,
    data: *const c_uchar,
    datal: c_int,
    count: c_int,
    key: *mut c_uchar,
    iv: *mut c_uchar,
) -> c_int {
    let mut md_buf = [0u8; EVP_MAX_MD_SIZE];
    let mut rv: c_int = 0;
    // SAFETY: `type_` is live per the contract.
    let mut nkey = unsafe { EVP_CIPHER_get_key_length(type_) };
    // SAFETY: `type_` is live per the contract.
    let mut niv = unsafe { EVP_CIPHER_get_iv_length(type_) };

    /* `OPENSSL_assert(nkey <= EVP_MAX_KEY_LENGTH)` and
     * `OPENSSL_assert(niv >= 0 && niv <= EVP_MAX_IV_LENGTH)` are active aborts in the authority;
     * this crate refuses, which `D-RCU-3` records for the same shape. The range form is the two
     * comparisons the assertion spells. */
    if nkey > EVP_MAX_KEY_LENGTH || !(0..=EVP_MAX_IV_LENGTH).contains(&niv) {
        return 0;
    }

    if data.is_null() {
        return nkey;
    }

    // SAFETY: nothing: `EVP_MD_CTX_new` takes no arguments and validates its own allocation.
    let c = EVP_MD_CTX_new();
    if c.is_null() {
        return rv;
    }

    let mut addmd: c_int = 0;
    let mut mds: c_uint = 0;
    let mut key = key;
    let mut iv = iv;
    let mut done = false;

    'outer: loop {
        // SAFETY: `c` is a live context, `md` is live per the contract, and the third argument is
        // the authority's NULL.
        if unsafe { EVP_DigestInit_ex(c, md, ptr::null_mut()) } == 0 {
            break 'outer;
        }
        let began = addmd;
        addmd += 1;
        if began != 0 {
            // SAFETY: `c` is live and `md_buf` holds `mds` bytes from the previous final.
            if unsafe { EVP_DigestUpdate(c, md_buf.as_ptr().cast::<c_void>(), mds as usize) } == 0 {
                break 'outer;
            }
        }
        // SAFETY: `c` is live; `data` is `datal` readable bytes per the contract.
        if unsafe { EVP_DigestUpdate(c, data.cast::<c_void>(), datal as usize) } == 0 {
            break 'outer;
        }
        if !salt.is_null() {
            // SAFETY: `c` is live; `salt` is eight readable bytes per the contract.
            if unsafe { EVP_DigestUpdate(c, salt.cast::<c_void>(), PKCS5_SALT_LEN) } == 0 {
                break 'outer;
            }
        }
        // SAFETY: `c` is live and `md_buf` is `EVP_MAX_MD_SIZE` bytes, the digest maximum.
        if unsafe { EVP_DigestFinal_ex(c, md_buf.as_mut_ptr(), &mut mds) } == 0 {
            break 'outer;
        }

        /* `for (i = 1; i < (unsigned int)count; i++)`, and `i` is the authority's `unsigned int`. */
        let mut i: c_uint = 1;
        while i < count as c_uint {
            // SAFETY: `c` is live and `md` is live per the contract.
            if unsafe { EVP_DigestInit_ex(c, md, ptr::null_mut()) } == 0 {
                break 'outer;
            }
            // SAFETY: `c` is live and `md_buf` holds `mds` bytes.
            if unsafe { EVP_DigestUpdate(c, md_buf.as_ptr().cast::<c_void>(), mds as usize) } == 0 {
                break 'outer;
            }
            // SAFETY: `c` is live and `md_buf` is the digest buffer.
            if unsafe { EVP_DigestFinal_ex(c, md_buf.as_mut_ptr(), &mut mds) } == 0 {
                break 'outer;
            }
            i = i.wrapping_add(1);
        }
        i = 0;

        if nkey != 0 {
            loop {
                if nkey == 0 {
                    break;
                }
                if i == mds {
                    break;
                }
                if !key.is_null() {
                    // SAFETY: `i < mds <= EVP_MAX_MD_SIZE`, so the index is in `md_buf`; `key` is
                    // `nkey` writable bytes per the contract and `nkey` counts down.
                    unsafe {
                        *key = md_buf[i as usize];
                        key = key.add(1);
                    }
                }
                nkey -= 1;
                i += 1;
            }
        }
        if niv != 0 && i != mds {
            loop {
                if niv == 0 {
                    break;
                }
                if i == mds {
                    break;
                }
                if !iv.is_null() {
                    // SAFETY: `i < mds <= EVP_MAX_MD_SIZE`; `iv` is `niv` writable bytes per the
                    // contract and `niv` counts down.
                    unsafe {
                        *iv = md_buf[i as usize];
                        iv = iv.add(1);
                    }
                }
                niv -= 1;
                i += 1;
            }
        }
        if nkey == 0 && niv == 0 {
            done = true;
            break;
        }
    }

    if done {
        // SAFETY: `type_` is live per the contract.
        rv = unsafe { EVP_CIPHER_get_key_length(type_) };
    }
    // SAFETY: `c` is a live context this call created.
    unsafe { EVP_MD_CTX_free(c) };
    // SAFETY: `md_buf` is this frame's own array.
    unsafe { OPENSSL_cleanse(md_buf.as_mut_ptr().cast::<c_void>(), md_buf.len()) };
    rv
}

/// `void EVP_set_pw_prompt(const char *prompt)` — `crypto/evp/evp_key.c:24`.
///
/// A NULL prompt **clears** rather than refuses, so the empty state is reachable through the
/// public API and `EVP_get_pw_prompt` answers NULL again. `strncpy(prompt_string, prompt, 79)` is
/// copied as a bounded copy with NUL padding: the padding's bytes are unobservable because every
/// reader stops at the first NUL, and the `prompt_string[79] = '\0'` that follows it is preserved.
///
/// # Safety
/// `prompt` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_set_pw_prompt(prompt: *const c_char) {
    if prompt.is_null() {
        // SAFETY: `PROMPT_STRING` is this module's own static and the index is in bounds.
        unsafe { PROMPT_STRING[0] = 0 };
        return;
    }
    let mut j = 0usize;
    // SAFETY: `prompt` is NUL-terminated per the contract.
    while j < 79 && unsafe { *prompt.add(j) } != 0 {
        // SAFETY: `j < 79 < 80`, so the destination index is in bounds.
        unsafe { PROMPT_STRING[j] = *prompt.add(j) };
        j += 1;
    }
    while j < 80 {
        // SAFETY: the index is in bounds.
        unsafe { PROMPT_STRING[j] = 0 };
        j += 1;
    }
}

/// `char *EVP_get_pw_prompt(void)` — `crypto/evp/evp_key.c:34`.
///
/// The empty buffer answers **NULL**, not the empty string, and the answer is the static itself
/// rather than a copy — so a caller that writes through it edits the shared prompt.
///
/// # Safety
/// Nothing: the answer is this module's own static.
#[no_mangle]
pub unsafe extern "C" fn EVP_get_pw_prompt() -> *mut c_char {
    // SAFETY: `PROMPT_STRING` is this module's own static.
    if unsafe { PROMPT_STRING[0] } == 0 {
        return ptr::null_mut();
    }
    ptr::addr_of_mut!(PROMPT_STRING).cast::<c_char>()
}

/// `int EVP_SignFinal_ex(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen,
/// EVP_PKEY *pkey, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p_sign.c:17`.
///
/// The body whose algorithm is the plain spelling's too. `*siglen` is written **0 first**, before
/// anything can fail, so a refusal never leaves a stale length. The digest is taken through
/// `EVP_DigestFinal_ex` and then handed to `EVP_PKEY_sign`, which is why this is not
/// `EVP_DigestSign`: the context here carries a *digest*, and the signing is one-shot.
///
/// # Safety
/// `ctx` and `pkey` live; `sigret` writable for `EVP_PKEY_get_size(pkey)` bytes; `siglen`
/// writable; `libctx` NULL or live; `propq` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_SignFinal_ex(
    ctx: *mut EvpMdCtx,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    pkey: *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut m = [0u8; EVP_MAX_MD_SIZE];
    let mut m_len: c_uint = 0;
    let mut i: c_int = 0;
    let mut pkctx: *mut EvpPkeyCtx = ptr::null_mut();

    // SAFETY: `siglen` is writable per the contract.
    unsafe { *siglen = 0 };

    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_FINALISE) } != 0 {
        // SAFETY: `ctx` is live and `m` is the digest buffer.
        if unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &mut m_len) } == 0 {
            // SAFETY: `pkctx` is NULL here.
            unsafe { EVP_PKEY_CTX_free(pkctx) };
            return i;
        }
    } else {
        // SAFETY: nothing: `EVP_MD_CTX_new` takes no arguments.
        let tmp_ctx = EVP_MD_CTX_new();
        if tmp_ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P_SIGN_36) };
            return 0;
        }
        // SAFETY: both contexts are live and distinct.
        let mut rv = unsafe { EVP_MD_CTX_copy_ex(tmp_ctx, ctx) };
        if rv != 0 {
            // SAFETY: `tmp_ctx` is live and `m` is the digest buffer.
            rv = unsafe { EVP_DigestFinal_ex(tmp_ctx, m.as_mut_ptr(), &mut m_len) };
        } else {
            // SAFETY: the copy failed, so the caller's context is finalised in place.
            rv = unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &mut m_len) };
        }
        // SAFETY: `tmp_ctx` is live.
        unsafe { EVP_MD_CTX_free(tmp_ctx) };
        if rv == 0 {
            return 0;
        }
    }

    // SAFETY: `pkey` is live per the contract.
    let mut sltmp: usize = unsafe { EVP_PKEY_get_size(pkey) } as usize;

    i = 0;
    // SAFETY: `pkey` is live and `libctx`/`propq` are as the contract states.
    pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    if pkctx.is_null() {
        // SAFETY: `pkctx` is NULL here.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_sign_init(pkctx) } <= 0 {
        // SAFETY: `pkctx` is live.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live and `ctx`'s method is the digest the caller asked for.
    if unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, EVP_MD_CTX_get0_md(ctx)) } <= 0 {
        // SAFETY: `pkctx` is live.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live, `sigret` is `sltmp` writable bytes, and `m` is `m_len` bytes.
    if unsafe { EVP_PKEY_sign(pkctx, sigret, &mut sltmp, m.as_ptr(), m_len as usize) } <= 0 {
        // SAFETY: `pkctx` is live.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `siglen` is writable per the contract.
    unsafe { *siglen = sltmp as c_uint };
    i = 1;
    // SAFETY: `pkctx` is live.
    unsafe { EVP_PKEY_CTX_free(pkctx) };
    i
}

/// `int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen,
/// EVP_PKEY *pkey)` — `crypto/evp/p_sign.c:67`.
///
/// One line: the `_ex` body with the library context and property query NULL.
///
/// # Safety
/// As `EVP_SignFinal_ex`, with `libctx`/`propq` NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_SignFinal(
    ctx: *mut EvpMdCtx,
    sigret: *mut c_uchar,
    siglen: *mut c_uint,
    pkey: *mut EvpPkey,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_SignFinal_ex(ctx, sigret, siglen, pkey, ptr::null_mut(), ptr::null()) }
}

/// `int EVP_VerifyFinal_ex(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen,
/// EVP_PKEY *pkey, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/evp/p_verify.c:17`.
///
/// `i` starts at **-1** and is overwritten by `EVP_PKEY_verify`'s answer, so the two ways out
/// before the verify are distinguishable from a failed verification (0) and from a success (1).
/// The digest half is `EVP_SignFinal_ex`'s exactly, including the two `EVP_DigestFinal_ex` doors.
///
/// # Safety
/// `ctx` and `pkey` live; `sigbuf` readable for `siglen` bytes; `libctx` NULL or live; `propq`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyFinal_ex(
    ctx: *mut EvpMdCtx,
    sigbuf: *const c_uchar,
    siglen: c_uint,
    pkey: *mut EvpPkey,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut m = [0u8; EVP_MAX_MD_SIZE];
    let mut m_len: c_uint = 0;
    let mut i: c_int = 0;
    let mut pkctx: *mut EvpPkeyCtx = ptr::null_mut();

    // SAFETY: `ctx` is live per the contract.
    if unsafe { EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_FINALISE) } != 0 {
        // SAFETY: `ctx` is live and `m` is the digest buffer.
        if unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &mut m_len) } == 0 {
            // SAFETY: `pkctx` is NULL here.
            unsafe { EVP_PKEY_CTX_free(pkctx) };
            return i;
        }
    } else {
        // SAFETY: nothing: `EVP_MD_CTX_new` takes no arguments.
        let tmp_ctx = EVP_MD_CTX_new();
        if tmp_ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::P_VERIFY_34) };
            return 0;
        }
        // SAFETY: both contexts are live and distinct.
        let mut rv = unsafe { EVP_MD_CTX_copy_ex(tmp_ctx, ctx) };
        if rv != 0 {
            // SAFETY: `tmp_ctx` is live and `m` is the digest buffer.
            rv = unsafe { EVP_DigestFinal_ex(tmp_ctx, m.as_mut_ptr(), &mut m_len) };
        } else {
            // SAFETY: the copy failed, so the caller's context is finalised in place.
            rv = unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &mut m_len) };
        }
        // SAFETY: `tmp_ctx` is live.
        unsafe { EVP_MD_CTX_free(tmp_ctx) };
        if rv == 0 {
            return 0;
        }
    }

    i = -1;
    // SAFETY: `pkey` is live and `libctx`/`propq` are as the contract states.
    pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    if pkctx.is_null() {
        // SAFETY: `pkctx` is NULL here.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live.
    if unsafe { EVP_PKEY_verify_init(pkctx) } <= 0 {
        // SAFETY: `pkctx` is live.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live and `ctx`'s method is the digest the caller asked for.
    if unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, EVP_MD_CTX_get0_md(ctx)) } <= 0 {
        // SAFETY: `pkctx` is live.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        return i;
    }
    // SAFETY: `pkctx` is live, `sigbuf` is `siglen` bytes, and `m` is `m_len` bytes.
    i = unsafe { EVP_PKEY_verify(pkctx, sigbuf, siglen as usize, m.as_ptr(), m_len as usize) };
    // SAFETY: `pkctx` is live.
    unsafe { EVP_PKEY_CTX_free(pkctx) };
    i
}

/// `int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen,
/// EVP_PKEY *pkey)` — `crypto/evp/p_verify.c:61`.
///
/// The `_ex` body with the library context and property query NULL.
///
/// # Safety
/// As `EVP_VerifyFinal_ex`, with `libctx`/`propq` NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_VerifyFinal(
    ctx: *mut EvpMdCtx,
    sigbuf: *const c_uchar,
    siglen: c_uint,
    pkey: *mut EvpPkey,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_VerifyFinal_ex(ctx, sigbuf, siglen, pkey, ptr::null_mut(), ptr::null()) }
}

/// `int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *ek,
/// int ekl, const unsigned char *iv, EVP_PKEY *priv)` — `crypto/evp/p_open.c:18`.
///
/// Three states, and the middle one is a success with no work: a non-NULL `type` resets and
/// initialises the cipher context, a **NULL `priv` answers 1 immediately** (the caller wanted only
/// the cipher setup), and otherwise the wrapped key is decrypted and installed. The first
/// `EVP_PKEY_decrypt` is the size query that fills `keylen`, so the allocation the second one
/// writes into is sized by the provider rather than by the caller.
///
/// # Safety
/// `ctx` live; `type` NULL or live; `ek` readable for `ekl` bytes; `iv` NULL or the cipher's IV
/// length; `priv` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_OpenInit(
    ctx: *mut EvpCipherCtx,
    type_: *const EvpCipher,
    ek: *const c_uchar,
    ekl: c_int,
    iv: *const c_uchar,
    priv_: *mut EvpPkey,
) -> c_int {
    let mut key: *mut c_uchar = ptr::null_mut();
    let mut keylen: usize = 0;
    let mut ret: c_int = 0;
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();

    if !type_.is_null() {
        // SAFETY: `ctx` is live per the contract.
        unsafe { EVP_CIPHER_CTX_reset(ctx) };
        // SAFETY: `ctx` is live and `type_` is live per the check above.
        if unsafe { EVP_DecryptInit_ex(ctx, type_, ptr::null_mut(), ptr::null(), ptr::null()) } == 0
        {
            // SAFETY: `pctx` is NULL here.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            // SAFETY: `key` is NULL here.
            unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
            return ret;
        }
    }

    if priv_.is_null() {
        return 1;
    }

    // SAFETY: `priv_` is live per the contract; the NULL engine is the only one this crate has.
    pctx = unsafe { EVP_PKEY_CTX_new(priv_, ptr::null_mut()) };
    if pctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_OPEN_37) };
        // SAFETY: `pctx` is NULL here.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is NULL here.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }

    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_decrypt_init(pctx) } <= 0 {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is NULL here.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }
    // SAFETY: `pctx` is live; the NULL output is the size query, `ek` is `ekl` bytes.
    if unsafe { EVP_PKEY_decrypt(pctx, ptr::null_mut(), &mut keylen, ek, ekl as usize) } <= 0 {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is NULL here.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }

    /* `CRYPTO_malloc` is one of the crate's safe entry points: it validates its own argument and
     * answers NULL rather than reading anything of the caller's. */
    key = CRYPTO_malloc(keylen, FILE_OPEN, LINE_OPEN_MALLOC).cast::<c_uchar>();
    if key.is_null() {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is NULL here.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }

    // SAFETY: `pctx` is live, `key` is `keylen` writable bytes, `ek` is `ekl` bytes.
    if unsafe { EVP_PKEY_decrypt(pctx, key, &mut keylen, ek, ekl as usize) } <= 0 {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is this call's own allocation of `keylen` bytes.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }

    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, keylen as c_int) } <= 0 {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is this call's own allocation of `keylen` bytes.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }
    // SAFETY: `ctx` is live, `key` is `keylen` bytes, `iv` is as the contract states.
    if unsafe { EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key, iv) } == 0 {
        // SAFETY: `pctx` is live.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: `key` is this call's own allocation of `keylen` bytes.
        unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
        return ret;
    }

    ret = 1;
    // SAFETY: `pctx` is live.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    // SAFETY: `key` is this call's own allocation of `keylen` bytes, released on every path.
    unsafe { CRYPTO_clear_free(key.cast(), keylen, FILE_OPEN, LINE_OPEN_CLEAR_FREE) };
    ret
}

/// `int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)` —
/// `crypto/evp/p_open.c:62`.
///
/// The decrypt's final, then a **re-init with all-NULL arguments** on success: that resets the
/// context to its initialised-but-keyless state so it can be used again, and it is the reason the
/// answer is the re-init's and not the final's. Both are the same value when the re-init succeeds.
///
/// # Safety
/// `ctx` live; `out` writable for a block; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_OpenFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: `ctx` is live and `out`/`outl` are as the contract states.
    let mut i = unsafe { EVP_DecryptFinal_ex(ctx, out, outl) };
    if i != 0 {
        // SAFETY: `ctx` is live and the three pointers are the authority's NULLs.
        i = unsafe {
            EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null())
        };
    }
    i
}

/// `int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek, int *ekl,
/// unsigned char *iv, EVP_PKEY **pubk, int npubk)` — `crypto/evp/p_seal.c:22`.
///
/// Three states, and the middle one is a success with no work — the `EVP_OpenInit` shape read
/// encrypt-side. A non-NULL `type` resets and initialises the cipher context; a `npubk <= 0` or a
/// NULL `pubk` **answers 1 immediately**, before any random is drawn; otherwise a fresh key is
/// generated into the stack buffer and an IV is drawn with `RAND_priv_bytes_ex`. Each `pubk[i]`
/// then wraps that same key: `ek[i]` is sized by `EVP_PKEY_get_size(pubk[i])` and `ekl[i]` is the
/// provider's answer, not the caller's.
///
/// The answer is `npubk` on the loop's normal exit and 0 on every `goto err`, so the `pctx = NULL`
/// after the loop is load-bearing: the shared cleanup must free a per-key context exactly once.
///
/// # Safety
/// `ctx` live; `type_` NULL or live; when `npubk > 0`, `pubk` points at `npubk` live keys, `ek`
/// at `npubk` writable pointers, `ekl` at `npubk` writable ints, and `iv` at
/// `EVP_CIPHER_CTX_get_iv_length(ctx)` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_SealInit(
    ctx: *mut EvpCipherCtx,
    type_: *const EvpCipher,
    ek: *mut *mut c_uchar,
    ekl: *mut c_int,
    iv: *mut c_uchar,
    pubk: *mut *mut EvpPkey,
    npubk: c_int,
) -> c_int {
    let mut key = [0u8; EVP_MAX_KEY_LENGTH as usize];
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut rv: c_int = 0;

    if !type_.is_null() {
        // SAFETY: `ctx` is live per the contract.
        unsafe { EVP_CIPHER_CTX_reset(ctx) };
        // SAFETY: `ctx` is live, `type_` is live per the check above, and the three NULLs are the
        // authority's own.
        if unsafe { EVP_EncryptInit_ex(ctx, type_, ptr::null_mut(), ptr::null(), ptr::null()) } == 0
        {
            return 0;
        }
    }

    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    if !cipher.is_null() {
        // SAFETY: `cipher` is live per the check above.
        let prov = unsafe { EVP_CIPHER_get0_provider(cipher) };
        if !prov.is_null() {
            // SAFETY: `prov` is live per the check above.
            libctx = unsafe { ossl_provider_libctx(prov) };
        }
    }

    if npubk <= 0 || pubk.is_null() {
        return 1;
    }

    // SAFETY: `ctx` is live per the contract and `key` is this frame's own `EVP_MAX_KEY_LENGTH`
    // bytes.
    if unsafe { crate::evp::cipher_ctx::EVP_CIPHER_CTX_rand_key(ctx, key.as_mut_ptr()) } <= 0 {
        return 0;
    }

    'body: {
        // SAFETY: `ctx` is live per the contract.
        let mut len = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if len < 0 {
            break 'body;
        }

        // SAFETY: `libctx` is the cipher's provider context or NULL, and `iv` is `len` writable
        // bytes per the contract.
        if unsafe { RAND_priv_bytes_ex(libctx, iv, len as usize, 0) } <= 0 {
            break 'body;
        }

        // SAFETY: `ctx` is live per the contract.
        len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
        if len < 0 {
            break 'body;
        }

        // SAFETY: `ctx` is live, `key` is `EVP_MAX_KEY_LENGTH` bytes and `iv` is the block just
        // written above.
        if unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv) } == 0 {
            break 'body;
        }

        let mut i: c_int = 0;
        while i < npubk {
            let keylen = len as usize;
            // SAFETY: `pubk` holds `npubk` live keys per the contract and `i < npubk`.
            let mut outlen = unsafe { EVP_PKEY_get_size(*pubk.add(i as usize)) } as usize;

            // SAFETY: `libctx` is the provider context or NULL, `pubk[i]` is live, and the NULL
            // property query is the authority's.
            pctx =
                unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, *pubk.add(i as usize), ptr::null()) };
            if pctx.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::P_SEAL_62) };
                break 'body;
            }

            // SAFETY: `pctx` is live.
            if unsafe { EVP_PKEY_encrypt_init(pctx) } <= 0 {
                break 'body;
            }
            // SAFETY: `pctx` is live, `ek[i]` is `EVP_PKEY_get_size(pubk[i])` writable bytes per
            // the contract, and `key` is `keylen` readable bytes.
            if unsafe {
                EVP_PKEY_encrypt(pctx, *ek.add(i as usize), &mut outlen, key.as_ptr(), keylen)
            } <= 0
            {
                break 'body;
            }
            // SAFETY: `ekl` holds `npubk` writable slots per the contract and `i < npubk`.
            unsafe { *ekl.add(i as usize) = outlen as c_int };
            // SAFETY: `pctx` is live and was created by this call.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            i += 1;
        }
        pctx = ptr::null_mut();
        rv = npubk;
    }

    // SAFETY: `pctx` is NULL or a live context this call created.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    // SAFETY: `key` is this frame's own array.
    unsafe { OPENSSL_cleanse(key.as_mut_ptr().cast::<c_void>(), key.len()) };
    rv
}

/// `int EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)` —
/// `crypto/evp/p_seal.c:80`.
///
/// `EVP_OpenFinal`'s encrypt-side twin, and identical in shape. Its `EVP_SealInit` sibling is the
/// function immediately above (D315), and this half still needs no random.
///
/// # Safety
/// `ctx` live; `out` writable for a block; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_SealFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: `ctx` is live and `out`/`outl` are as the contract states.
    let mut i = unsafe { EVP_EncryptFinal_ex(ctx, out, outl) };
    if i != 0 {
        // SAFETY: `ctx` is live and the three pointers are the authority's NULLs.
        i = unsafe {
            EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null())
        };
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EVP_set_pw_prompt(NULL)` clears, and the empty buffer answers NULL rather than "".
    #[test]
    fn the_prompt_starts_empty_and_a_null_clears_it() {
        // SAFETY: the prompt is this module's own static and these calls only touch it.
        unsafe {
            EVP_set_pw_prompt(ptr::null());
            assert!(EVP_get_pw_prompt().is_null());
            let p = c"Password: ";
            EVP_set_pw_prompt(p.as_ptr());
            assert!(!EVP_get_pw_prompt().is_null());
            EVP_set_pw_prompt(ptr::null());
            assert!(EVP_get_pw_prompt().is_null());
        }
    }

    /// A prompt longer than 79 bytes is truncated and NUL-terminated at 79.
    #[test]
    fn a_long_prompt_is_truncated_at_seventy_nine() {
        let long: [c_char; 100] = {
            let mut b = [b'x' as c_char; 100];
            b[99] = 0;
            b
        };
        // SAFETY: `long` is NUL-terminated at index 99, and the prompt is this module's static.
        unsafe {
            EVP_set_pw_prompt(long.as_ptr());
            let got = EVP_get_pw_prompt();
            assert!(!got.is_null());
            let mut n = 0usize;
            while *got.add(n) != 0 {
                n += 1;
            }
            assert_eq!(n, 79);
        }
    }

    /// The four bounds are the authority's own, and the refusal test pins them.
    #[test]
    fn the_bytestokey_bounds_are_the_authority_headers() {
        assert_eq!(EVP_MAX_KEY_LENGTH, 64);
        assert_eq!(EVP_MAX_IV_LENGTH, 16);
        assert_eq!(EVP_MAX_MD_SIZE, 64);
        assert_eq!(PKCS5_SALT_LEN, 8);
    }
}
