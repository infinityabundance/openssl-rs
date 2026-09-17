//! Phase 7.6 — `crypto/cmac/cmac.c`: the legacy CMAC interface.
//!
//! Nine exports and one internal, and the plan's row is explicit that this is **not** the MAC
//! implementation underneath: `EVP_MAC`'s `"CMAC"` is a provider (`providers/implementations/macs/
//! cmac_prov.c`, Phase 13) and is what `EVP_Q_mac(ctx, "CMAC", ...)` reaches. What is transcribed
//! here is the pre-3.0 construction written directly over `EVP_CIPHER_CTX`, which is what makes it
//! a separate surface a separate court can observe.
//!
//! ## The struct is the authority's, and it is in the `.c` file
//!
//! There is no `crypto/cmac/cmac_local.h`; the authoritative layout is `struct CMAC_CTX_st` at
//! `crypto/cmac/cmac.c:25` — the cipher context, the two subkeys `k1`/`k2`, the running block
//! `tbl`, the saved final block `last_block`, and `nlast_block`, whose **-1 means "not
//! initialised"** and is the gate every one of the nine exports tests first. The field set is
//! transcribed from the file rather than remembered, and the header that promises the internal is
//! `include/crypto/cmac.h`, which declares `ossl_cmac_init` — so that internal is landed beside
//! its nine exports rather than left to the gate.
//!
//! ## `CMAC_Init` is three separate initialisations in one
//!
//! `ossl_cmac_init` (`cmac.c:111`) is the whole of `CMAC_Init` and it has three entry conditions
//! a court can reach independently:
//!
//!   * **all four arguments zero/`NULL`** is the *restart*: it re-arms the existing context with
//!     the zero IV and answers 0 for a context that was never initialised.
//!   * **a non-NULL `cipher`** with a NULL key arms the cipher only, explicitly setting
//!     `nlast_block = -1` so the context cannot be used until a key arrives ("ensure we can't use
//!     this ctx until we also have a key").
//!   * **a non-NULL `key`** completes the initialisation: it sets the key length, encrypts one
//!     zero block to derive the subkeys, and resets the context ready for the first data block.
//!
//! `CMAC_Init` with `cipher == NULL` and a NULL key but a non-empty `keylen` is therefore *not*
//! the restart: the first test requires `keylen == 0`, and the call falls through both blocks and
//! answers 1 with the context untouched — which is the arm the court drives for "reuses the
//! previous cipher".
//!
//! ## What is not here
//!
//! Nothing. `crypto/cmac/cmac.c` has no `#ifdef` block, no ENGINE-only arm and no Phase-13
//! primitive under it; every call it makes is an `EVP_CIPHER_CTX` entry point this stratum built.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::evp::cipher::EvpCipher;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_reset,
    EVP_CIPHER_CTX_set_key_length, EVP_Cipher, EVP_EncryptInit_ex, EVP_EncryptInit_ex2,
    EvpCipherCtx,
};
use crate::params::OsslParam;
use crate::runtime::mem::{cleanse, CRYPTO_free, CRYPTO_malloc};

/// `LOCAL_BUF_SIZE` — `crypto/cmac/cmac.c:24`. The burst buffer `CMAC_Update` encrypts through.
const LOCAL_BUF_SIZE: usize = 2048;

/// `EVP_MAX_BLOCK_LENGTH` — `include/openssl/evp.h:37`. The length of `k1`, `k2`, `tbl`,
/// `last_block` and the zero IV.
const EVP_MAX_BLOCK_LENGTH: usize = 32;

/// `crypto/cmac/cmac.c` — the translation unit the crate's allocations and frees are attributed
/// to. The file raises nothing, so there are no `err_sites` coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/cmac/cmac.c".as_ptr();

/// `CMAC_CTX_new`'s `OPENSSL_malloc(sizeof(*ctx))` (line 58).
const LINE_MALLOC_CTX: c_int = 58;
/// `CMAC_CTX_new`'s `OPENSSL_free(ctx)` when the cipher-context allocation fails (line 62).
const LINE_FREE_CTX_ON_NEW: c_int = 62;
/// `CMAC_CTX_free`'s `OPENSSL_free(ctx)` (line 90).
const LINE_FREE_CTX: c_int = 90;

/// `struct CMAC_CTX_st` — `crypto/cmac/cmac.c:25`.
///
/// `pub` for the reason every internal type in an exported signature is: the nine exports take a
/// `CMAC_CTX *`, and the authority keeps the struct in the `.c` file. Every field is `pub(crate)`.
///
/// The four byte arrays are **zero-initialised here where the authority's `OPENSSL_malloc` leaves
/// them uninitialised**. It is not observable: `nlast_block` is set to -1 before the constructor
/// returns and every read of those arrays is gated on a value that only a completed initialisation
/// writes.
#[repr(C)]
pub struct CmacCtx {
    /// `EVP_CIPHER_CTX *cctx` — the cipher context the construction runs through.
    pub(crate) cctx: *mut EvpCipherCtx,
    /// `unsigned char k1[EVP_MAX_BLOCK_LENGTH]` — the subkey for a complete final block.
    pub(crate) k1: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `unsigned char k2[EVP_MAX_BLOCK_LENGTH]` — the subkey for a padded final block.
    pub(crate) k2: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `unsigned char tbl[EVP_MAX_BLOCK_LENGTH]` — the last encrypted block, which is also the
    /// running IV `CMAC_resume` re-arms with.
    pub(crate) tbl: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `unsigned char last_block[EVP_MAX_BLOCK_LENGTH]` — the block held back as possibly-final.
    pub(crate) last_block: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `int nlast_block` — `-1` means "not initialised"; `0` means "armed, no data yet".
    pub(crate) nlast_block: c_int,
}

/// `static void make_kn(unsigned char *k1, const unsigned char *l, int bl)` —
/// `crypto/cmac/cmac.c:41`.
///
/// The left-shift-with-carry and the conditional XOR of `R`, where `R` is `0x87` for a sixteen-byte
/// block and `0x1b` for every other length. `0 - carry` is the authority's `int` negation in a
/// byte context: it is `0xff` when the top bit was set and `0x00` otherwise.
///
/// # Safety
/// `k1` must be writable for `bl` bytes; `l` readable for `bl` bytes; `0 <= bl <= 32`.
unsafe fn make_kn(k1: *mut c_uchar, l: *const c_uchar, bl: c_int) {
    // SAFETY: `l` is readable for `bl` bytes per the contract and `bl > 0`.
    let mut c = unsafe { *l };
    let carry: c_uchar = c >> 7;

    // SAFETY: the indices are in range for `0 <= bl <= 32`.
    unsafe {
        let mut i: c_int = 0;
        while i < bl - 1 {
            let next = *l.offset(i as isize + 1);
            *k1.offset(i as isize) = (c << 1) | (next >> 7);
            c = next;
            i += 1;
        }
        let r: c_uchar = if bl == 16 { 0x87 } else { 0x1b };
        *k1.offset(i as isize) = (c << 1) ^ ((0u8.wrapping_sub(carry)) & r);
    }
}

/// `CMAC_CTX *CMAC_CTX_new(void)` — `crypto/cmac/cmac.c:54`.
#[no_mangle]
pub extern "C" fn CMAC_CTX_new() -> *mut CmacCtx {
    let ctx =
        CRYPTO_malloc(core::mem::size_of::<CmacCtx>(), FILE, LINE_MALLOC_CTX).cast::<CmacCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is a fresh block this call owns and `CmacCtx`'s four arrays are plain bytes;
    // the authority leaves them as `OPENSSL_malloc` found them and this writes them.
    unsafe { ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<CmacCtx>()) };
    // SAFETY: `ctx` is this call's own block.
    let cctx = EVP_CIPHER_CTX_new();
    if cctx.is_null() {
        // SAFETY: `ctx` came from this crate's allocator and holds nothing yet.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is this call's own block.
    unsafe {
        (*ctx).cctx = cctx;
        (*ctx).nlast_block = -1;
    }
    ctx
}

/// `void CMAC_CTX_cleanup(CMAC_CTX *ctx)` — `crypto/cmac/cmac.c:69`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn CMAC_CTX_cleanup(ctx: *mut CmacCtx) {
    // SAFETY: `ctx` is live per the contract, so `cctx` is live.
    unsafe { EVP_CIPHER_CTX_reset((*ctx).cctx) };
    // SAFETY: the four buffers are this context's own fields.
    unsafe {
        cleanse((*ctx).tbl.as_mut_ptr(), EVP_MAX_BLOCK_LENGTH);
        cleanse((*ctx).k1.as_mut_ptr(), EVP_MAX_BLOCK_LENGTH);
        cleanse((*ctx).k2.as_mut_ptr(), EVP_MAX_BLOCK_LENGTH);
        cleanse((*ctx).last_block.as_mut_ptr(), EVP_MAX_BLOCK_LENGTH);
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).nlast_block = -1 };
}

/// `EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx)` — `crypto/cmac/cmac.c:79`.
///
/// The relation the court drives: the answered pointer *is* the context the CMAC is running on, so
/// a key length read through it agrees with the one `CMAC_Init` set.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn CMAC_CTX_get0_cipher_ctx(ctx: *mut CmacCtx) -> *mut EvpCipherCtx {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cctx }
}

/// `void CMAC_CTX_free(CMAC_CTX *ctx)` — `crypto/cmac/cmac.c:84`.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn CMAC_CTX_free(ctx: *mut CmacCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { CMAC_CTX_cleanup(ctx) };
    // SAFETY: `ctx` is live and `cctx` is the context this crate owns.
    unsafe { EVP_CIPHER_CTX_free((*ctx).cctx) };
    // SAFETY: `ctx` came from this crate's allocator and has been released of everything it held.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX) };
}

/// `int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in)` — `crypto/cmac/cmac.c:93`.
///
/// The refusal first: an uninitialised source (`nlast_block == -1`) and a cipher with no block
/// size both answer 0 **before** anything is copied, so a failed copy leaves the destination as it
/// was. The block size is the copy length for the four arrays and is deliberately the source's, so
/// a destination whose cipher differs is overwritten with the source's cipher by the
/// `EVP_CIPHER_CTX_copy` above it.
///
/// # Safety
/// `out` and `in` must be live contexts.
#[no_mangle]
pub unsafe extern "C" fn CMAC_CTX_copy(out: *mut CmacCtx, in_: *const CmacCtx) -> c_int {
    // SAFETY: `in_` is live per the contract.
    if unsafe { (*in_).nlast_block } == -1 {
        return 0;
    }
    // SAFETY: `in_` is live and armed, so its cipher is live.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size((*in_).cctx) };
    if bl == 0 {
        return 0;
    }
    // SAFETY: both contexts are live; `EVP_CIPHER_CTX_copy` refuses a NULL source itself.
    if unsafe { EVP_CIPHER_CTX_copy((*out).cctx, (*in_).cctx) } == 0 {
        return 0;
    }
    // SAFETY: `bl` is the source cipher's block size, at most `EVP_MAX_BLOCK_LENGTH`, and both the
    // source and destination arrays are that long.
    unsafe {
        ptr::copy_nonoverlapping((*in_).k1.as_ptr(), (*out).k1.as_mut_ptr(), bl as usize);
        ptr::copy_nonoverlapping((*in_).k2.as_ptr(), (*out).k2.as_mut_ptr(), bl as usize);
        ptr::copy_nonoverlapping((*in_).tbl.as_ptr(), (*out).tbl.as_mut_ptr(), bl as usize);
        ptr::copy_nonoverlapping(
            (*in_).last_block.as_ptr(),
            (*out).last_block.as_mut_ptr(),
            bl as usize,
        );
        (*out).nlast_block = (*in_).nlast_block;
    }
    1
}

/// `int ossl_cmac_init(CMAC_CTX *ctx, const void *key, size_t keylen,
///     const EVP_CIPHER *cipher, ENGINE *impl, const OSSL_PARAM param[])` —
/// `crypto/cmac/cmac.c:111`, declared in `include/crypto/cmac.h:18`.
///
/// The internal the header promises and the whole body of `CMAC_Init`. It is landed here because
/// implementing `CMAC_Init` makes the gate owe the unit's header-declared internals, and because
/// `CMAC_Init`'s body *is* the call to it — the same split D190 recorded for `evp_pkey_type`.
///
/// # Safety
/// `ctx` must be a live context; `key` readable for `keylen` bytes unless NULL; `cipher` NULL or
/// live; `impl` NULL (no ENGINE can be built here); `param` NULL or terminated.
pub(crate) unsafe fn ossl_cmac_init(
    ctx: *mut CmacCtx,
    key: *const c_void,
    keylen: usize,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
    param: *const OsslParam,
) -> c_int {
    /// `static const unsigned char zero_iv[EVP_MAX_BLOCK_LENGTH] = { 0 }` (`cmac.c:115`).
    const ZERO_IV: [c_uchar; EVP_MAX_BLOCK_LENGTH] = [0; EVP_MAX_BLOCK_LENGTH];

    // All zeros means restart.
    if key.is_null() && cipher.is_null() && impl_.is_null() && keylen == 0 {
        // SAFETY: `ctx` is live per the contract.
        if unsafe { (*ctx).nlast_block } == -1 {
            return 0;
        }
        // SAFETY: `ctx` is live; the zero IV is a compile-time constant.
        if unsafe {
            EVP_EncryptInit_ex2(
                (*ctx).cctx,
                ptr::null(),
                ptr::null(),
                ZERO_IV.as_ptr(),
                param,
            )
        } == 0
        {
            return 0;
        }
        // SAFETY: `ctx` is live.
        let block_len = unsafe { EVP_CIPHER_CTX_get_block_size((*ctx).cctx) };
        if block_len == 0 {
            return 0;
        }
        // SAFETY: `tbl` is 32 bytes and `block_len` is a cipher block size, at most 32.
        unsafe { ptr::write_bytes((*ctx).tbl.as_mut_ptr(), 0, block_len as usize) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).nlast_block = 0 };
        return 1;
    }
    // Initialise context.
    if !cipher.is_null() {
        // Ensure we can't use this ctx until we also have a key.
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).nlast_block = -1 };
        if !impl_.is_null() {
            // SAFETY: `ctx` is live and `cipher` is non-NULL; `impl_` is non-NULL on this arm.
            if unsafe { EVP_EncryptInit_ex((*ctx).cctx, cipher, impl_, ptr::null(), ptr::null()) }
                == 0
            {
                return 0;
            }
        } else {
            // SAFETY: `ctx` is live and `cipher` is non-NULL.
            if unsafe { EVP_EncryptInit_ex2((*ctx).cctx, cipher, ptr::null(), ptr::null(), param) }
                == 0
            {
                return 0;
            }
        }
    }
    // Non-NULL key means initialisation complete.
    if !key.is_null() {
        // If anything fails then ensure we can't use this ctx.
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).nlast_block = -1 };
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_get0_cipher((*ctx).cctx) }.is_null() {
            return 0;
        }
        // `keylen > INT_MAX` and the size the cipher accepts. The first is a `size_t` test in the
        // authority and is written after `keylen` has been cast; it is unreachable on this profile
        // for any caller that could build a buffer, and it is kept because it is the authority's.
        if keylen > c_int::MAX as usize {
            return 0;
        }
        // SAFETY: `ctx` is live per the contract.
        if unsafe { EVP_CIPHER_CTX_set_key_length((*ctx).cctx, keylen as c_int) } <= 0 {
            return 0;
        }
        // SAFETY: `ctx` is live; `key` is non-NULL and readable for `keylen` bytes.
        if unsafe {
            EVP_EncryptInit_ex2(
                (*ctx).cctx,
                ptr::null(),
                key.cast::<c_uchar>(),
                ZERO_IV.as_ptr(),
                param,
            )
        } == 0
        {
            return 0;
        }
        // SAFETY: `ctx` is live.
        let bl = unsafe { EVP_CIPHER_CTX_get_block_size((*ctx).cctx) };
        if bl < 0 {
            return 0;
        }
        // SAFETY: `ctx` is live; `tbl` is 32 bytes and `bl` is the cipher's block size.
        if unsafe {
            EVP_Cipher(
                (*ctx).cctx,
                (*ctx).tbl.as_mut_ptr(),
                ZERO_IV.as_ptr(),
                bl as u32,
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `tbl` readable and `k1` writable for `bl` bytes.
        unsafe { make_kn((*ctx).k1.as_mut_ptr(), (*ctx).tbl.as_ptr(), bl) };
        // SAFETY: `k1` readable and `k2` writable for `bl` bytes.
        unsafe { make_kn((*ctx).k2.as_mut_ptr(), (*ctx).k1.as_ptr(), bl) };
        // SAFETY: `tbl` is 32 bytes and `bl` is at most 32.
        unsafe { cleanse((*ctx).tbl.as_mut_ptr(), bl as usize) };
        // Reset context again ready for first data block.
        // SAFETY: `ctx` is live.
        if unsafe {
            EVP_EncryptInit_ex2(
                (*ctx).cctx,
                ptr::null(),
                ptr::null(),
                ZERO_IV.as_ptr(),
                param,
            )
        } == 0
        {
            return 0;
        }
        // Zero tbl so resume works.
        // SAFETY: `tbl` is 32 bytes and `bl` is at most 32.
        unsafe { ptr::write_bytes((*ctx).tbl.as_mut_ptr(), 0, bl as usize) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).nlast_block = 0 };
    }
    1
}

/// `int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen,
///     const EVP_CIPHER *cipher, ENGINE *impl)` — `crypto/cmac/cmac.c:174`.
///
/// # Safety
/// `ctx` must be a live context; `key` readable for `keylen` bytes unless NULL; `cipher` NULL or
/// live; `impl` NULL.
#[no_mangle]
pub unsafe extern "C" fn CMAC_Init(
    ctx: *mut CmacCtx,
    key: *const c_void,
    keylen: usize,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract; the parameter array is
    // NULL, as the authority passes it.
    unsafe { ossl_cmac_init(ctx, key, keylen, cipher, impl_, ptr::null()) }
}

/// `int CMAC_Update(CMAC_CTX *ctx, const void *in, size_t dlen)` —
/// `crypto/cmac/cmac.c:180`.
///
/// The block-cipher chain: fill the held `last_block` first, then encrypt every complete block
/// **except the last**, which is kept as possibly-final. The burst buffer is an optimisation and
/// is transcribed because its boundary (`max_burst_blocks == 0`, a block larger than the local
/// buffer) is the one arm a plain loop would not have.
///
/// # Safety
/// `ctx` must be a live context; `in` readable for `dlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn CMAC_Update(ctx: *mut CmacCtx, in_: *const c_void, dlen: usize) -> c_int {
    let mut data = in_.cast::<c_uchar>();
    let mut dlen = dlen;
    let mut buf = [0 as c_uchar; LOCAL_BUF_SIZE];

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).nlast_block } == -1 {
        return 0;
    }
    if dlen == 0 {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size((*ctx).cctx) };
    if bl == 0 {
        return 0;
    }
    // Copy into partial block if we need to.
    // SAFETY: `ctx` is live, so `nlast_block` is readable and `last_block` writable.
    if unsafe { (*ctx).nlast_block } > 0 {
        // SAFETY: `ctx` is live and `nlast_block` is positive on this arm.
        let nlast = unsafe { (*ctx).nlast_block };
        let mut nleft = bl as usize - nlast as usize;
        if dlen < nleft {
            nleft = dlen;
        }
        // SAFETY: `last_block` has `nlast_block + nleft <= bl <= 32` bytes written, `nleft <= bl`.
        unsafe {
            ptr::copy_nonoverlapping(
                data,
                (*ctx).last_block.as_mut_ptr().add(nlast as usize),
                nleft,
            );
        }
        dlen -= nleft;
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).nlast_block += nleft as c_int };
        // If no more to process return.
        if dlen == 0 {
            return 1;
        }
        // SAFETY: `data` is the caller's buffer advanced by `nleft`.
        data = unsafe { data.add(nleft) };
        // Else not final block so encrypt it.
        // SAFETY: `ctx` is live; `tbl` writable and `last_block` readable for `bl` bytes.
        if unsafe {
            EVP_Cipher(
                (*ctx).cctx,
                (*ctx).tbl.as_mut_ptr(),
                (*ctx).last_block.as_ptr(),
                bl as u32,
            )
        } <= 0
        {
            return 0;
        }
    }
    // Encrypt all but one of the complete blocks left.
    let max_burst_blocks = LOCAL_BUF_SIZE / bl as usize;
    let mut cipher_blocks = (dlen - 1) / bl as usize;
    if max_burst_blocks == 0 {
        // When block length is greater than local buffer size, use ctx->tbl as cipher output.
        while dlen > bl as usize {
            // SAFETY: `ctx` is live; `tbl` writable for `bl` bytes and `data` readable for them.
            if unsafe { EVP_Cipher((*ctx).cctx, (*ctx).tbl.as_mut_ptr(), data, bl as u32) } <= 0 {
                return 0;
            }
            dlen -= bl as usize;
            // SAFETY: `data` advanced by `bl`, which `dlen` still covers.
            data = unsafe { data.add(bl as usize) };
        }
    } else {
        while cipher_blocks > max_burst_blocks {
            // SAFETY: `buf` is `LOCAL_BUF_SIZE` bytes and `max_burst_blocks * bl <= LOCAL_BUF_SIZE`.
            if unsafe {
                EVP_Cipher(
                    (*ctx).cctx,
                    buf.as_mut_ptr(),
                    data,
                    (max_burst_blocks * bl as usize) as u32,
                )
            } <= 0
            {
                return 0;
            }
            dlen -= max_burst_blocks * bl as usize;
            // SAFETY: `data` advanced by a span `dlen` still covers.
            data = unsafe { data.add(max_burst_blocks * bl as usize) };
            cipher_blocks -= max_burst_blocks;
        }
        if cipher_blocks > 0 {
            // SAFETY: `buf` has room for `cipher_blocks * bl <= LOCAL_BUF_SIZE` bytes.
            if unsafe {
                EVP_Cipher(
                    (*ctx).cctx,
                    buf.as_mut_ptr(),
                    data,
                    (cipher_blocks * bl as usize) as u32,
                )
            } <= 0
            {
                return 0;
            }
            dlen -= cipher_blocks * bl as usize;
            // SAFETY: `data` advanced by a span `dlen` still covers.
            data = unsafe { data.add(cipher_blocks * bl as usize) };
            // SAFETY: the destination `tbl` is 32 bytes; the source is `bl` bytes inside `buf`.
            unsafe {
                ptr::copy_nonoverlapping(
                    buf.as_ptr().add((cipher_blocks - 1) * bl as usize),
                    (*ctx).tbl.as_mut_ptr(),
                    bl as usize,
                )
            };
        }
    }
    // Copy any data left to last block buffer.
    // SAFETY: `dlen < bl <= 32` on every arm above, so `last_block` has room.
    unsafe { ptr::copy_nonoverlapping(data, (*ctx).last_block.as_mut_ptr(), dlen) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).nlast_block = dlen as c_int };
    1
}

/// `int CMAC_Final(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen)` —
/// `crypto/cmac/cmac.c:248`.
///
/// Three arms a court can separate: the length query (`out == NULL` answers 1 after writing the
/// block size), the complete final block XOR'd with `k1`, and the padded one XOR'd with `k2`. The
/// padded arm **mutates `last_block`**, which is why `CMAC_resume` exists and why a second
/// `CMAC_Final` on the same context is not idempotent — the authority's own comment on
/// `CMAC_resume` says so.
///
/// # Safety
/// `ctx` must be a live context; `out` NULL or writable for the block size; `poutlen` NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn CMAC_Final(
    ctx: *mut CmacCtx,
    out: *mut c_uchar,
    poutlen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).nlast_block } == -1 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size((*ctx).cctx) };
    if bl == 0 {
        return 0;
    }
    if !poutlen.is_null() {
        // SAFETY: `poutlen` is non-NULL on this arm.
        unsafe { *poutlen = bl as usize };
    }
    if out.is_null() {
        return 1;
    }
    // SAFETY: `ctx` is live.
    let lb = unsafe { (*ctx).nlast_block };
    // Is last block complete?
    if lb == bl {
        for i in 0..bl as usize {
            // SAFETY: `last_block`, `k1` and `out` are all `bl` bytes.
            unsafe { *out.add(i) = (*ctx).last_block[i] ^ (*ctx).k1[i] };
        }
    } else {
        // SAFETY: `last_block` is 32 bytes and `lb < bl <= 32`.
        unsafe {
            (*ctx).last_block[lb as usize] = 0x80;
            if bl - lb > 1 {
                ptr::write_bytes(
                    (*ctx).last_block.as_mut_ptr().add(lb as usize + 1),
                    0,
                    (bl - lb - 1) as usize,
                );
            }
        }
        for i in 0..bl as usize {
            // SAFETY: `last_block`, `k2` and `out` are all `bl` bytes.
            unsafe { *out.add(i) = (*ctx).last_block[i] ^ (*ctx).k2[i] };
        }
    }
    // SAFETY: `ctx` is live; `out` is readable and writable for `bl` bytes.
    if unsafe { EVP_Cipher((*ctx).cctx, out, out, bl as u32) } <= 0 {
        // SAFETY: `out` is `bl` bytes per the contract.
        unsafe { cleanse(out, bl as usize) };
        return 0;
    }
    1
}

/// `int CMAC_resume(CMAC_CTX *ctx)` — `crypto/cmac/cmac.c:279`.
///
/// Re-arms the cipher context with `tbl` as the IV, so the construction can continue after a
/// `CMAC_Final` that modified `last_block`. The refusal on an uninitialised context is the same
/// `nlast_block == -1` gate as everywhere else.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn CMAC_resume(ctx: *mut CmacCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).nlast_block } == -1 {
        return 0;
    }
    // SAFETY: `ctx` is live; the key is NULL so the previous one is reused and `tbl` is the IV.
    unsafe {
        EVP_EncryptInit_ex(
            (*ctx).cctx,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            (*ctx).tbl.as_ptr(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh context owns a live cipher context, answers -1 from the constructor's own gate, and
    /// refuses every operation that tests it.
    #[test]
    fn new_context_is_uninitialised() {
        let ctx = CMAC_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is the live context just built.
        unsafe {
            assert_eq!((*ctx).nlast_block, -1);
            assert!(!(*ctx).cctx.is_null());
            assert_eq!(CMAC_CTX_get0_cipher_ctx(ctx), (*ctx).cctx);
            assert_eq!(CMAC_Update(ctx, ptr::null(), 0), 0);
            assert_eq!(CMAC_Final(ctx, ptr::null_mut(), ptr::null_mut()), 0);
            assert_eq!(CMAC_resume(ctx), 0);
            // The restart arm refuses an uninitialised context (`cmac.c:121`).
            assert_eq!(
                ossl_cmac_init(
                    ctx,
                    ptr::null(),
                    0,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null()
                ),
                0
            );
            CMAC_CTX_free(ctx);
        }
    }

    /// `CMAC_CTX_free` accepts NULL; `CMAC_CTX_copy` refuses an uninitialised source without
    /// touching the destination.
    #[test]
    fn copy_refuses_an_uninitialised_source() {
        let src = CMAC_CTX_new();
        let dst = CMAC_CTX_new();
        assert!(!src.is_null() && !dst.is_null());
        // SAFETY: both are live contexts this test owns.
        unsafe {
            assert_eq!(CMAC_CTX_copy(dst, src), 0);
            CMAC_CTX_free(dst);
            CMAC_CTX_free(src);
            CMAC_CTX_free(ptr::null_mut());
        }
    }
}
