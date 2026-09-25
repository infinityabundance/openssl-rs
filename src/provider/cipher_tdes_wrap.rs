//! Phase 9 — the default provider's **DES3-WRAP** cipher engine.
//!
//! `EVP_CIPHER_fetch(NULL, "DES3-WRAP", NULL)` — and its two aliases `id-smime-alg-CMS3DESwrap`
//! and `1.2.840.113549.1.9.16.3.6` — resolves through the default provider's `OSSL_OP_CIPHER`
//! query to the `ossl_tdes_wrap_cbc_functions` table this module publishes. It is one of the
//! fifteen provider registration rows Phase 9 owns (D294), and it is the row D237's census found
//! invisible to the symbol atlas because a registration row is not a symbol.
//!
//! The row was Phase 8's obligation, handed to Phase 9 with its blocker named rather than stubbed
//! (D237): `des_ede3_wrap` generates the wrap IV with
//! `RAND_bytes_ex(ctx->libctx, ctx->iv, ivlen, 0)` (`cipher_tdes_wrap.c:101`), and `RAND_bytes_ex`
//! is this phase's (`src/rand/rand_lib.rs`). That is the only random draw in the unit.
//!
//! ## The unit and the authority lines transcribed
//!
//! `providers/implementations/ciphers/cipher_tdes_wrap.c` (209 lines) is transcribed whole:
//! `des_ede3_unwrap` (`:34-78`), `des_ede3_wrap` (`:80-110`), `tdes_wrap_cipher_internal`
//! (`:112-126`), `tdes_wrap_cipher` (`:128-150`), `tdes_wrap_update` (`:152-169`) and the
//! `IMPLEMENT_WRAP_CIPHER` expansion (`:171-209`; its dispatch table is `:185-206`, its invocation
//! `:209`).
//!
//! `providers/implementations/ciphers/cipher_tdes_wrap_hw.c` (20 lines) is transcribed as the one
//! hardware table it produces: `#define ossl_cipher_hw_tdes_wrap_initkey
//! ossl_cipher_hw_tdes_ede3_initkey` (`:18`) followed by `PROV_CIPHER_HW_tdes_mode(wrap, cbc)`
//! (`:20`). That macro is `cipher_tdes_default.h:89-98`; expanded with the `#define` applied it is
//! `{ ossl_cipher_hw_tdes_ede3_initkey, ossl_cipher_hw_tdes_cbc, ossl_cipher_hw_tdes_copyctx }`,
//! i.e. **exactly** the three methods of the crate's existing `TDES_EDE3_CBC_HW`
//! (`src/provider/cipher.rs:3149`), which is the measurement this module's `TDES_WRAP_CBC_HW`
//! reproduces.
//!
//! ## The row
//!
//! `providers/defltprov.c:308` is `ALG(PROV_NAMES_DES3_WRAP, ossl_tdes_wrap_cbc_functions)`,
//! between the `DES-EDE3-CFB1` row (`:307`) and the `DES-EDE-ECB` row (`:309`). The alias string is
//! `PROV_NAMES_DES3_WRAP` = `"DES3-WRAP:id-smime-alg-CMS3DESwrap:1.2.840.113549.1.9.16.3.6"` (read
//! from `forensics/atlas/provider-algorithms.json`; `prov/names.h` itself is not in this forensics
//! copy). `ossl_tdes_wrap_cbc_functions` is declared at
//! `providers/implementations/include/prov/implementations.h` — the reviewer gives `:229`, but that
//! header is *also* absent from this forensics copy, so the line number could not be re-verified
//! here; only the `declared_in` fact (from `forensics/atlas/internal-symbols.json`) is.
//!
//! ## Facts this module depends on
//!
//! * `TDES_WRAP_FLAGS` is `PROV_CIPHER_FLAG_CUSTOM_IV | PROV_CIPHER_FLAG_RAND_KEY`
//!   (`cipher_tdes_wrap.c:25`) — `0x0002 | 0x0010`. It is **not** `TDES_FLAGS`, which is the bare
//!   `PROV_CIPHER_FLAG_RAND_KEY` the EDE rows publish.
//! * `IMPLEMENT_WRAP_CIPHER(TDES_WRAP_FLAGS, 64 * 3, 64, 0)` (`:209`) — 192 key bits, a 64-bit
//!   block, and **zero** IV bits.
//! * The macro renames its two per-translation-unit statics through its parameters: `tdes_wrap_newctx`
//!   (`:172-178`) and `tdes_wrap_get_params` (`:179-184`). Both are `static` in C — one definition
//!   per translation unit — so Rust needs them unique; no other module in this crate defines either
//!   name, so this module keeps the authority's macro-expanded spellings unchanged.
//! * `tdes_wrap_cipher_internal` (`:120`) bounds the input with `inl >= EVP_MAXCHUNK` **and**
//!   `inl % 8`. `EVP_MAXCHUNK` is `((size_t)1 << (sizeof(long) * 8 - 2))` (`include/openssl/evp.h`)
//!   — `1 << 62` on this 64-bit target. Neither the crate nor this forensics copy carries that
//!   public header, so the bound is restated below in the macro's own spelling rather than baked to
//!   a literal; the companion bounds are `INT_MAX` in `des_ede3_wrap` (`:88`) and `inl < 24` in
//!   `des_ede3_unwrap` (`:40`).
//! * `wrap_iv[8]` is `{ 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 }` (`:30-32`) — the fixed IV
//!   the wrapped output is finally encrypted under, after the random IV header.
//!
//! ## The dispatch table, in the authority's order
//!
//! `:185-206` publishes thirteen entries and `OSSL_DISPATCH_END`, in this order:
//! `ENCRYPT_INIT`→`ossl_tdes_einit`, `DECRYPT_INIT`→`ossl_tdes_dinit`, `CIPHER`→`tdes_wrap_cipher`,
//! `NEWCTX`→`tdes_wrap_newctx`, `FREECTX`→`ossl_tdes_freectx`, `UPDATE`→`tdes_wrap_update`,
//! `FINAL`→`ossl_cipher_generic_stream_final`, `GET_PARAMS`→`tdes_wrap_get_params`,
//! `GETTABLE_PARAMS`→`ossl_cipher_generic_gettable_params`, `GET_CTX_PARAMS`→`ossl_tdes_get_ctx_params`,
//! `GETTABLE_CTX_PARAMS`→`ossl_tdes_gettable_ctx_params`, `SET_CTX_PARAMS`→`ossl_cipher_generic_set_ctx_params`,
//! `SETTABLE_CTX_PARAMS`→`ossl_cipher_generic_settable_ctx_params`. The `CIPHER`/`UPDATE` bodies and
//! both the `NEWCTX`/`GET_PARAMS` macro items are this file's; the rest are the shared TDES or
//! generic-cipher engine's.
//!
//! **One substitution, named rather than implied.** The authority's init pair is
//! `ossl_tdes_einit`/`ossl_tdes_dinit` (`cipher_tdes_common.c:117-129`, over `tdes_init`). This
//! crate has no object of either name: its own EDE rows publish the shared
//! `ossl_cipher_generic_einit`/`ossl_cipher_generic_dinit` instead (`src/provider/cipher.rs`'s
//! `cipher_row!`, `:2986-2993`), and `cipher_generic_init_internal` is *not* a superset of
//! `tdes_init`. The wrap row follows the crate's established TDES convention -- the generic pair --
//! so the table below names `ossl_cipher_generic_einit`/`ossl_cipher_generic_dinit`.
//!
//! The deltas between the two init bodies, measured rather than summarised, are three:
//!
//! 1. `tdes_init` has **no `EVP_CIPH_ECB_MODE` guard** on its `iv != NULL` branch
//!    (`cipher_tdes_common.c:83-88`), where `cipher_generic_init_internal` refuses to install an
//!    IV for an ECB context (`ciphercommon.c.in:214`). An EDE ECB row initialised with a non-NULL
//!    IV therefore reaches `ossl_cipher_generic_initiv` on the authority and does not here.
//! 2. `tdes_init` does **not** reset `ctx->updated`; `cipher_generic_init_internal` does
//!    (`ciphercommon.c.in:208`).
//! 3. The wrong-key-length raise is at a different **coordinate** (`cipher_tdes_common.c:101` vs
//!    `ciphercommon.c.in:229`); both raise `PROV_R_INVALID_KEY_LENGTH`, and the coordinate is not
//!    part of the parity model, so this one is not observable.
//!
//! Deltas 1 and 2 are the kind nothing objects to: both sit behind arms no court drives yet, and
//! the crate's own EDE rows have carried them since they landed. They are named here rather than
//! described as equivalent. See `docs/DECISIONS.md` D418.
//!
//! ## What is deliberately not transcribed
//!
//! Nothing in `cipher_tdes_wrap.c` is dropped. This unit carries no test (the landing quarter's
//! call); the two `ERR_raise` coordinates it queues are declared here because
//! `src/runtime/err_sites.rs` is generated and does not yet carry `cipher_tdes_wrap.c`.
// SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::digest::sha1::SHA1;
use crate::evp::cipher::{
    OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_ENCRYPT_INIT,
    OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE,
};
use crate::params::OsslParam;
use crate::provider::cipher::{
    cipher_hw_tdes_copyctx, cipher_hw_tdes_ede3_initkey, ossl_cipher_generic_dinit,
    ossl_cipher_generic_einit, ossl_cipher_generic_get_params, ossl_cipher_generic_gettable_params,
    ossl_cipher_generic_initkey, ossl_cipher_generic_set_ctx_params,
    ossl_cipher_generic_settable_ctx_params, ossl_cipher_generic_stream_final,
    ossl_cipher_hw_tdes_cbc, ossl_tdes_get_ctx_params, ossl_tdes_gettable_ctx_params, tdes_freectx,
    ProvCipherCtx, ProvCipherHw, ProvTdesCtx, CTX_ENC, EVP_CIPH_WRAP_MODE, FILE_TDES, LINE,
    PROV_CIPHER_FLAG_CUSTOM_IV, PROV_CIPHER_FLAG_RAND_KEY,
};
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::buffer::BUF_reverse;
use crate::runtime::err::{err_reasons, err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_memcmp, CRYPTO_zalloc, OPENSSL_cleanse};

/// `ERR_LIB_PROV` — `include/openssl/proverr.h`.
const ERR_LIB_PROV: c_int = 57;

/// `TDES_IVLEN` — `cipher_tdes.h:16`. The IV, ICV and `wrap_iv` are all this many bytes.
const TDES_IVLEN: usize = 8;
/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h:28`.
const SHA_DIGEST_LENGTH: usize = 20;
/// `INT_MAX` — `include/limits.h`. The `des_ede3_wrap` length guard's bound.
const INT_MAX: usize = c_int::MAX as usize;

/// `EVP_MAXCHUNK` — `include/openssl/evp.h`, `((size_t)1 << (sizeof(long) * 8 - 2))`. Restated in
/// the header's own terms because neither tree in this checkout carries the public header.
const EVP_MAXCHUNK: usize = 1usize << (core::mem::size_of::<c_long>() * 8 - 2);

/// `TDES_WRAP_FLAGS` — `cipher_tdes_wrap.c:25`.
const TDES_WRAP_FLAGS: u64 = PROV_CIPHER_FLAG_CUSTOM_IV | PROV_CIPHER_FLAG_RAND_KEY;

/// `static const unsigned char wrap_iv[8]` — `cipher_tdes_wrap.c:30-32`.
static WRAP_IV: [c_uchar; TDES_IVLEN] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

/// One `cipher_tdes_wrap.c` raise coordinate. `cipher_tdes_wrap.c` is a plain source file, so its
/// `__FILE__` carries the pinned build's `../../src/openssl-3.6.4/` prefix, as the generated
/// `err_sites` entries for its sibling units do.
const fn wrap_site(line: c_int, func: &'static CStr, reason: c_int) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_tdes_wrap.c",
        line,
        func,
        lib: ERR_LIB_PROV,
        reason,
        dynamic_reason: false,
    }
}

/// `tdes_wrap_cipher` at `cipher_tdes_wrap.c:140` (`PROV_R_OUTPUT_BUFFER_TOO_SMALL`).
const WRAP_140: err_sites::ErrSite = wrap_site(
    140,
    c"tdes_wrap_cipher",
    err_reasons::PROV_R_OUTPUT_BUFFER_TOO_SMALL,
);
/// `tdes_wrap_update` at `:160` (`PROV_R_OUTPUT_BUFFER_TOO_SMALL`).
const WRAP_160: err_sites::ErrSite = wrap_site(
    160,
    c"tdes_wrap_update",
    err_reasons::PROV_R_OUTPUT_BUFFER_TOO_SMALL,
);
/// `tdes_wrap_update` at `:165` (`PROV_R_CIPHER_OPERATION_FAILED`).
const WRAP_165: err_sites::ErrSite = wrap_site(
    165,
    c"tdes_wrap_update",
    err_reasons::PROV_R_CIPHER_OPERATION_FAILED,
);

/// `ossl_prov_is_running` — `providers/prov_running.c`, spelled locally as every provider cipher
/// module spells it: the default provider is always in a happy state on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// The authority's `ERR_raise(...); return 0;` pair.
#[inline]
fn fail_at(site: &err_sites::ErrSite) -> c_int {
    // SAFETY: `site` is a compile-time constant whose string pointers are `'static`.
    unsafe { raise_site(site) };
    0
}

// ---------------------------------------------------------------------------------------------
// `cipher_tdes_wrap.c` — the wrap/unwrap bodies
// ---------------------------------------------------------------------------------------------

/// `des_ede3_unwrap` — `cipher_tdes_wrap.c:34-78`.
///
/// The reverse of [`des_ede3_wrap`]: the final IV and the whole message are re-reversed, decrypted
/// again under the recovered IV, and the eight-byte ICV is checked against `SHA1(out, inl - 16)`.
/// A mismatch cleanses the output and answers `-1`.
///
/// # Safety
/// `ctx` is a live `PROV_TDES_CTX`; `in_` is readable for `inl` bytes; `out` is NULL or writable
/// for `inl` bytes (in-place is allowed, and is why the first central block is moved).
unsafe fn des_ede3_unwrap(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    mut in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut icv = [0u8; TDES_IVLEN];
        let mut iv = [0u8; TDES_IVLEN];
        let mut sha1tmp = [0u8; SHA_DIGEST_LENGTH];
        let mut rv: c_int = -1;

        if inl < 24 {
            return -1;
        }
        if out.is_null() {
            return (inl - 16) as c_int;
        }

        ptr::copy_nonoverlapping(WRAP_IV.as_ptr(), (*ctx).iv.as_mut_ptr(), 8);
        /* Decrypt first block which will end up as icv */
        ((*(*ctx).hw).cipher)(ctx, icv.as_mut_ptr(), in_, 8);
        /* Decrypt central blocks */
        /*
         * If decrypting in place move whole output along a block so the next
         * des_ede_cbc_cipher is in place.
         */
        if out == in_.cast_mut() {
            ptr::copy(out, out.add(8), inl - 8);
            in_ = in_.sub(8);
        }
        ((*(*ctx).hw).cipher)(ctx, out, in_.add(8), inl - 16);
        /* Decrypt final block which will be IV */
        ((*(*ctx).hw).cipher)(ctx, iv.as_mut_ptr(), in_.add(inl - 8), 8);
        /* Reverse order of everything */
        BUF_reverse(icv.as_mut_ptr(), ptr::null(), 8);
        BUF_reverse(out, ptr::null(), inl - 16);
        BUF_reverse((*ctx).iv.as_mut_ptr(), iv.as_ptr(), 8);
        /* Decrypt again using new IV */
        ((*(*ctx).hw).cipher)(ctx, out, out, inl - 16);
        ((*(*ctx).hw).cipher)(ctx, icv.as_mut_ptr(), icv.as_ptr(), 8);
        if !SHA1(out, inl - 16, sha1tmp.as_mut_ptr()).is_null() /* Work out hash of first portion */
            && CRYPTO_memcmp(sha1tmp.as_ptr().cast(), icv.as_ptr().cast(), 8) == 0
        {
            rv = (inl - 16) as c_int;
        }
        OPENSSL_cleanse(icv.as_mut_ptr().cast(), 8);
        OPENSSL_cleanse(sha1tmp.as_mut_ptr().cast(), SHA_DIGEST_LENGTH);
        OPENSSL_cleanse(iv.as_mut_ptr().cast(), 8);
        OPENSSL_cleanse((*ctx).iv.as_mut_ptr().cast(), (*ctx).iv.len());
        if rv == -1 {
            OPENSSL_cleanse(out.cast(), inl - 16);
        }

        rv
    }
}

/// `des_ede3_wrap` — `cipher_tdes_wrap.c:80-110`.
///
/// The output is `IV || 3DES-CBC(in) || ICV`, all reversed, where `IV` is eight random bytes from
/// [`RAND_bytes_ex`] and `ICV` is the first eight bytes of `SHA1(in)`.
///
/// # Safety
/// `ctx` is a live `PROV_TDES_CTX`; `in_` is readable for `inl` bytes; `out` is NULL or writable
/// for `inl + 2 * TDES_IVLEN` bytes. `ctx->libctx` is the library context the IV draw uses.
unsafe fn des_ede3_wrap(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut sha1tmp = [0u8; SHA_DIGEST_LENGTH];
        let ivlen = TDES_IVLEN;
        let icvlen = TDES_IVLEN;
        let len = inl + ivlen + icvlen;

        if len > INT_MAX {
            return 0;
        }
        if out.is_null() {
            return len as c_int;
        }

        /* Copy input to output buffer + 8 so we have space for IV */
        ptr::copy(in_, out.add(ivlen), inl);
        /* Work out ICV */
        if SHA1(in_, inl, sha1tmp.as_mut_ptr()).is_null() {
            return 0;
        }
        ptr::copy_nonoverlapping(sha1tmp.as_ptr(), out.add(inl + ivlen), icvlen);
        OPENSSL_cleanse(sha1tmp.as_mut_ptr().cast(), SHA_DIGEST_LENGTH);
        /* Generate random IV */
        if RAND_bytes_ex((*ctx).libctx, (*ctx).iv.as_mut_ptr(), ivlen, 0) <= 0 {
            return 0;
        }
        ptr::copy_nonoverlapping((*ctx).iv.as_ptr(), out, ivlen);
        /* Encrypt everything after IV in place */
        ((*(*ctx).hw).cipher)(ctx, out.add(ivlen), out.add(ivlen), inl + ivlen);
        BUF_reverse(out, ptr::null(), len);
        ptr::copy_nonoverlapping(WRAP_IV.as_ptr(), (*ctx).iv.as_mut_ptr(), ivlen);
        ((*(*ctx).hw).cipher)(ctx, out, out, len);
        len as c_int
    }
}

/// `tdes_wrap_cipher_internal` — `cipher_tdes_wrap.c:112-126`.
///
/// The length guard is above the direction split, so an overlength or non-multiple-of-eight input is
/// refused before either body runs.
///
/// # Safety
/// `ctx` is a live `PROV_TDES_CTX`; `out`/`in_` as [`des_ede3_wrap`] or [`des_ede3_unwrap`] require.
unsafe fn tdes_wrap_cipher_internal(
    ctx: *mut ProvCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        /*
         * Sanity check input length: we typically only wrap keys so EVP_MAXCHUNK
         * is more than will ever be needed. Also input length must be a multiple
         * of 8 bits.
         */
        if inl >= EVP_MAXCHUNK || !inl.is_multiple_of(8) {
            return -1;
        }
        if (*ctx).bits & CTX_ENC != 0 {
            des_ede3_wrap(ctx, out, in_, inl)
        } else {
            des_ede3_unwrap(ctx, out, in_, inl)
        }
    }
}

/// `tdes_wrap_cipher` — `cipher_tdes_wrap.c:128-150`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_wrap_cipher(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let ctx = vctx.cast::<ProvCipherCtx>();
        *outl = 0;
        if is_running() == 0 {
            return 0;
        }

        if outsize < inl {
            return fail_at(&WRAP_140);
        }

        let ret = tdes_wrap_cipher_internal(ctx, out, in_, inl);
        if ret <= 0 {
            return 0;
        }

        *outl = ret as usize;
        1
    }
}

/// `tdes_wrap_update` — `cipher_tdes_wrap.c:152-169`.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_wrap_update(
    vctx: *mut c_void,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
    in_: *const c_uchar,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        *outl = 0;
        if inl == 0 {
            return 1;
        }
        if outsize < inl {
            return fail_at(&WRAP_160);
        }

        if tdes_wrap_cipher(vctx, out, outl, outsize, in_, inl) == 0 {
            return fail_at(&WRAP_165);
        }
        1
    }
}

// ---------------------------------------------------------------------------------------------
// `cipher_tdes_wrap_hw.c` — the one hardware table
// ---------------------------------------------------------------------------------------------

/// `static const PROV_CIPHER_HW wrap_cbc` — `cipher_tdes_wrap_hw.c:20`, the
/// `PROV_CIPHER_HW_tdes_mode(wrap, cbc)` expansion with
/// `ossl_cipher_hw_tdes_wrap_initkey` aliased to `ossl_cipher_hw_tdes_ede3_initkey` (`:18`).
///
/// Its three methods are byte-for-byte the ones `TDES_EDE3_CBC_HW` installs
/// (`src/provider/cipher.rs:3149`), which is why the two tables are the same type values.
static TDES_WRAP_CBC_HW: ProvCipherHw = ProvCipherHw {
    init: cipher_hw_tdes_ede3_initkey,
    cipher: ossl_cipher_hw_tdes_cbc,
    copyctx: Some(cipher_hw_tdes_copyctx),
};

// ---------------------------------------------------------------------------------------------
// `cipher_tdes_wrap.c` — the `IMPLEMENT_WRAP_CIPHER` expansion
// ---------------------------------------------------------------------------------------------

/// `tdes_wrap_newctx` — `cipher_tdes_wrap.c:173-178`, over `ossl_tdes_newctx`
/// (`cipher_tdes_common.c:23-38`).
///
/// The authority's wrapper only forwards `ossl_tdes_newctx(provctx, EVP_CIPH_WRAP_MODE, 64 * 3, 64,
/// 0, flags, ossl_prov_cipher_hw_tdes_wrap_cbc())`. This crate has no `ossl_tdes_newctx` object, so
/// its five effective lines — the running check, the zeroed `PROV_TDES_CTX`, and the
/// `ossl_cipher_generic_initkey` call — are inlined here with the row's arguments.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_wrap_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract; `ossl_cipher_generic_initkey` writes only within the
    // allocation.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }
        let tctx = CRYPTO_zalloc(core::mem::size_of::<ProvTdesCtx>(), FILE_TDES, LINE);
        if !tctx.is_null() {
            ossl_cipher_generic_initkey(
                tctx,
                64 * 3,
                64,
                0,
                EVP_CIPH_WRAP_MODE,
                TDES_WRAP_FLAGS,
                ptr::addr_of!(TDES_WRAP_CBC_HW),
                provctx,
            );
        }
        tctx
    }
}

/// `tdes_wrap_get_params` — `cipher_tdes_wrap.c:180-184`.
///
/// Unlike the EDE rows' `ossl_tdes_get_params`, this one calls `ossl_cipher_generic_get_params`
/// directly, so the `decrypt-only` parameter the EDE rows publish is **not** on this row.
///
/// # Safety
/// The dispatch contract.
unsafe extern "C" fn tdes_wrap_get_params(params: *mut OsslParam) -> c_int {
    // SAFETY: the dispatch contract.
    unsafe {
        ossl_cipher_generic_get_params(params, EVP_CIPH_WRAP_MODE, TDES_WRAP_FLAGS, 64 * 3, 64, 0)
    }
}

/// `ossl_tdes_wrap_cbc_functions` — `cipher_tdes_wrap.c:185-206`, the whole
/// `IMPLEMENT_WRAP_CIPHER` dispatch table in the authority's entry order, `OSSL_DISPATCH_END` last.
///
/// Thirteen entries plus the terminator. The two `*_INIT` entries name the shared generic init pair
/// this crate's EDE rows publish rather than the authority's `ossl_tdes_einit`/`ossl_tdes_dinit`
/// (see the module header's named substitution); every other entry is the authority's own function.
pub(crate) static TDES_WRAP_CBC_FUNCTIONS: [OsslDispatch; 14] = [
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_ENCRYPT_INIT,
        function: ossl_cipher_generic_einit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_DECRYPT_INIT,
        function: ossl_cipher_generic_dinit as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_CIPHER,
        function: tdes_wrap_cipher as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_NEWCTX,
        function: tdes_wrap_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FREECTX,
        function: tdes_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_UPDATE,
        function: tdes_wrap_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_FINAL,
        function: ossl_cipher_generic_stream_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_PARAMS,
        function: tdes_wrap_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        function: ossl_cipher_generic_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
        function: ossl_tdes_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        function: ossl_tdes_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        function: ossl_cipher_generic_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        function: ossl_cipher_generic_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
