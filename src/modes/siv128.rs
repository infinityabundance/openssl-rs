//! Phase 8.3 — `crypto/modes/siv128.c`, the SIV context the AES-SIV and AES-GCM-SIV provider
//! rows drive.
//!
//! `siv128.c` publishes **no** `libcrypto` symbol: `util/libcrypto.num` has no `ossl_siv128_*`
//! entry, so the unit is invisible to the export atlas and is not an entry in
//! `forensics/prerequisites.json`. It is transcribed because a **row** reaches it —
//! `providers/defltprov.c:195-200`'s six `AES-*-SIV`/`AES-*-GCM-SIV` rows — and a row is not a
//! stub-able thing: D237 exists precisely to name the rows the export atlas cannot see.
//!
//! ## Why this unit is a composition rather than a construction
//!
//! RFC 5297's SIV mode is a two-key construction whose pieces are not new primitives: the S2V
//! pseudorandom function is **CMAC-AES**, and the payload is encrypted with **AES-CTR** under
//! the SIV. So `siv128.c` drives the crate's already-courted EVP machinery —
//! `EVP_MAC_fetch(…, "CMAC", …)`, `EVP_MAC_CTX_dup`/`_update`/`_final`, and
//! `EVP_CipherInit_ex`/`EVP_EncryptUpdate` over the row's fetched AES-CTR — rather than
//! reimplementing either. That is the authority's own structure, and it is why the courts'
//! `AES-*-SIV` arms are evidence about the *composition*: CMAC and AES-CTR each already have
//! their own differential and construction vectors, so what those arms add is that the glue
//! reproduces the authority's own tag and ciphertext.
//!
//! ## `SIV_BLOCK` really is a union
//!
//! C's `union { uint64_t word[2]; unsigned char byte[16]; }` has both views used:
//! `siv128_dbl` doubles the element through the *word* view while `siv128_do_s2v_p` fills it
//! through the *byte* view, and `ossl_siv128_decrypt` reads `t.word[0] | t.word[1]` on bytes
//! that were written through the byte view. It is a Rust `union` for that reason, and the byte
//! view is addressed as the union's own base pointer, which is what C's member-at-offset-zero
//! guarantees.
//!
//! ## The endianness arm is the authority's own compile-time selection
//!
//! `siv128_getword`/`siv128_putword` are guarded by `DECLARE_IS_ENDIAN` in the authority, so the
//! `byteswap8` branch is chosen when the translation unit is compiled.
//! `cfg!(target_endian = "little")` is that same selection spelled once, so both arms are
//! transcribed rather than one being dropped for this profile; on the little-endian targets this
//! crate builds for it is the `byteswap8` arm, which means a `SIV_BLOCK`'s word view is
//! **big-endian**.
//!
//! ## `ossl_siv128_new` is transcribed, with one line of memory-safety divergence
//!
//! The authority's `ossl_siv128_new` is `OPENSSL_malloc` (not `zalloc`) followed immediately by
//! `ossl_siv128_init`, whose first four statements `EVP_CIPHER_CTX_free`, `EVP_MAC_CTX_free` and
//! `EVP_MAC_free` three pointers **read from that uninitialised block**. §3 of
//! `docs/SECURITY_DIVERGENCE_POLICY.md` prohibits copying a known memory-safety defect to obtain
//! parity, so the transcription allocates with `CRYPTO_zalloc`, which is the state
//! `ossl_siv128_init` requires of its caller and the state every other caller reaches it in. No
//! observable changes, and the function's own doc comment says so (D239).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_get0_name, EvpCipher};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherInit_ex,
    EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch,
    EVP_MAC_final, EVP_MAC_free, EVP_MAC_up_ref, EVP_MAC_update, EvpMac, EvpMacCtx,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OsslParam,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc, OPENSSL_cleanse};

/// `SIV_LEN` — `include/crypto/modes.h:212`.
pub const SIV_LEN: usize = 16;

/// The allocation-tracking `file` argument for this unit's allocations: `crypto/modes/siv128.c`.
const FILE: *const c_char = c"crypto/modes/siv128.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `OSSL_MAC_NAME_CMAC` — `core_names.h:60` (`"CMAC"`). The MAC the row is built on; the crate's
/// own CMAC is what `EVP_MAC_fetch` resolves, because the fetch lands in the default provider.
const OSSL_MAC_NAME_CMAC: *const c_char = c"CMAC".as_ptr();
/// `OSSL_MAC_PARAM_CIPHER` — `core_names.h:339`, aliased to `OSSL_ALG_PARAM_CIPHER` (`"cipher"`).
const OSSL_MAC_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();
/// `OSSL_MAC_PARAM_KEY` — `core_names.h:350` (`"key"`).
const OSSL_MAC_PARAM_KEY: *const c_char = c"key".as_ptr();

/// `SIV_BLOCK` — `include/crypto/modes.h:214-217`: sixteen octets seen as two `uint64_t` and as
/// an array of `unsigned char`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SivBlock {
    /// `uint64_t word[SIV_LEN / sizeof(uint64_t)]`.
    pub word: [u64; 2],
    /// `unsigned char byte[SIV_LEN]`.
    pub byte: [c_uchar; SIV_LEN],
}

impl SivBlock {
    /// The all-zero block, which C spells `memset(&t, 0, sizeof(t))` or `= { 0 }`.
    pub fn zero() -> Self {
        SivBlock { word: [0, 0] }
    }
}

/// `SIV128_CONTEXT` — `include/crypto/modes.h:219-229`.
///
/// `cipher_ctx`/`mac`/`mac_ctx_init` are owned references. `ossl_siv128_init` and
/// `ossl_siv128_cleanup` are the only places they are freed and the only places they are
/// released; `ossl_siv128_copy_ctx` is the only place the `mac` reference is taken.
#[repr(C)]
pub struct Siv128Context {
    /// `SIV_BLOCK d` — `D` from RFC 5297 §2.4's S2V pseudocode.
    pub d: SivBlock,
    /// `SIV_BLOCK tag` — the tag the caller sets, or the one S2V computed.
    pub tag: SivBlock,
    /// `EVP_CIPHER_CTX *cipher_ctx` — the row's fetched AES-CTR context.
    pub cipher_ctx: *mut EvpCipherCtx,
    /// `EVP_MAC *mac` — the fetched CMAC method, shared by reference on a copy.
    pub mac: *mut EvpMac,
    /// `EVP_MAC_CTX *mac_ctx_init` — the CMAC context S2V duplicates on every call.
    pub mac_ctx_init: *mut EvpMacCtx,
    /// `int final_ret` — `-1` until a crypto operation completed, then `0`.
    pub final_ret: c_int,
    /// `int crypto_ok` — one crypto operation per context, or `-1` under `speed`.
    pub crypto_ok: c_int,
}

/// `static ossl_inline uint32_t rotl8(uint32_t x)` — `siv128.c:24-27`. `(x << 8) | (x >> 24)`
/// on a `uint32_t` is `rotate_left(8)`, which is the intrinsic Rust names for it.
fn rotl8(x: u32) -> u32 {
    x.rotate_left(8)
}

/// `static ossl_inline uint32_t rotr8(uint32_t x)` — `siv128.c:29-32`. As [`rotl8`].
fn rotr8(x: u32) -> u32 {
    x.rotate_right(8)
}

/// `static ossl_inline uint64_t byteswap8(uint64_t x)` — `siv128.c:34-45`. The authority swaps
/// the two halves and then byte-reverses each with the two rotate-and-mask steps.
fn byteswap8(x: u64) -> u64 {
    let mut high = (x >> 32) as u32;
    let mut low = x as u32;

    high = (rotl8(high) & 0x00ff00ff) | (rotr8(high) & 0xff00ff00);
    low = (rotl8(low) & 0x00ff00ff) | (rotr8(low) & 0xff00ff00);
    ((low as u64) << 32) | (high as u64)
}

/// `static ossl_inline uint64_t siv128_getword(SIV_BLOCK const *b, size_t i)` — `siv128.c:47-54`.
///
/// # Safety
/// `b` points at a live `SIV_BLOCK`; `i` is `0` or `1`.
unsafe fn siv128_getword(b: *const SivBlock, i: usize) -> u64 {
    // SAFETY: the caller's contract, and the word view is the same sixteen octets.
    let w = unsafe { (*b).word[i] };
    if cfg!(target_endian = "little") {
        byteswap8(w)
    } else {
        w
    }
}

/// `static ossl_inline void siv128_putword(SIV_BLOCK *b, size_t i, uint64_t x)` —
/// `siv128.c:56-64`.
///
/// # Safety
/// `b` points at a live, writable `SIV_BLOCK`; `i` is `0` or `1`.
unsafe fn siv128_putword(b: *mut SivBlock, i: usize, x: u64) {
    let v = if cfg!(target_endian = "little") {
        byteswap8(x)
    } else {
        x
    };
    // SAFETY: the caller's contract, and the word view is the same sixteen octets.
    unsafe { (*b).word[i] = v };
}

/// `static ossl_inline void siv128_xorblock(SIV_BLOCK *x, SIV_BLOCK const *y)` —
/// `siv128.c:66-71`.
///
/// # Safety
/// `x` is writable and `y` readable; both point at live `SIV_BLOCK`s.
unsafe fn siv128_xorblock(x: *mut SivBlock, y: *const SivBlock) {
    // SAFETY: the caller's contract.
    unsafe {
        (*x).word[0] ^= (*y).word[0];
        (*x).word[1] ^= (*y).word[1];
    }
}

/// `static ossl_inline void siv128_dbl(SIV_BLOCK *b)` — `siv128.c:73-92`: double `b` as an
/// element of GF(2^128) modulo `x^128 + x^7 + x^2 + x + 1`. `low_mask` is the reduction
/// polynomial applied only when the *high* word's top bit was set.
///
/// # Safety
/// `b` points at a live, writable `SIV_BLOCK`.
unsafe fn siv128_dbl(b: *mut SivBlock) {
    // SAFETY: the caller's contract.
    unsafe {
        let high = siv128_getword(b, 0);
        let low = siv128_getword(b, 1);
        let high_carry = high & (1u64 << 63);
        let low_carry = low & (1u64 << 63);
        let low_mask = (-((high_carry >> 63) as i64)) & 0x87;
        let high_mask = low_carry >> 63;

        let high = (high << 1) | high_mask;
        let low = (low << 1) ^ (low_mask as u64);
        siv128_putword(b, 0, high);
        siv128_putword(b, 1, low);
    }
}

/// `static ossl_inline int siv128_do_s2v_p(SIV128_CONTEXT *ctx, SIV_BLOCK *out,
/// unsigned char const *in, size_t len)` — `siv128.c:94-128`.
///
/// RFC 5297 §2.4's two arms: a full final block comes from the input and is XORed with `D`,
/// while a short one is zero-padded, `0x80`-terminated and XORed with `dbl(D)`. The MAC context
/// is duplicated because `D` advances between calls and `mac_ctx_init` must not.
///
/// # Safety
/// `ctx` is live with a non-NULL `mac_ctx_init`; `out` is writable; `in` is readable for `len`.
unsafe fn siv128_do_s2v_p(
    ctx: *mut Siv128Context,
    out: *mut SivBlock,
    in_: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut t = SivBlock::zero();
        let mut out_len = SIV_LEN;
        let mac_ctx = EVP_MAC_CTX_dup((*ctx).mac_ctx_init);
        let mut ret = 0;

        if mac_ctx.is_null() {
            return 0;
        }

        's2v: {
            if len >= SIV_LEN {
                if EVP_MAC_update(mac_ctx, in_, len - SIV_LEN) == 0 {
                    break 's2v;
                }
                ptr::copy_nonoverlapping(in_.add(len - SIV_LEN), t.byte.as_mut_ptr(), SIV_LEN);
                siv128_xorblock(ptr::addr_of_mut!(t), ptr::addr_of!((*ctx).d));
                if EVP_MAC_update(mac_ctx, t.byte.as_ptr(), SIV_LEN) == 0 {
                    break 's2v;
                }
            } else {
                ptr::copy_nonoverlapping(in_, t.byte.as_mut_ptr(), len);
                t.byte[len] = 0x80;
                let d = ptr::addr_of_mut!((*ctx).d);
                siv128_dbl(d);
                siv128_xorblock(ptr::addr_of_mut!(t), d);
                if EVP_MAC_update(mac_ctx, t.byte.as_ptr(), SIV_LEN) == 0 {
                    break 's2v;
                }
            }
            if EVP_MAC_final(mac_ctx, out.cast::<c_uchar>(), &mut out_len, SIV_LEN) == 0
                || out_len != SIV_LEN
            {
                break 's2v;
            }

            ret = 1;
        }

        EVP_MAC_CTX_free(mac_ctx);
        ret
    }
}

/// `static ossl_inline int siv128_do_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out,
/// unsigned char const *in, size_t len, SIV_BLOCK *icv)` — `siv128.c:130-139`. The caller has
/// already cleared the two counter bits in `icv`; this re-initialises the row's AES-CTR context
/// on it and runs one update.
///
/// # Safety
/// `ctx` is a live cipher context; `out`/`in_` follow the dispatch contract; `icv` is readable.
unsafe fn siv128_do_encrypt(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    len: usize,
    icv: *mut SivBlock,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut out_len = len as c_int;

        if EVP_CipherInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            (*icv).byte.as_ptr(),
            1,
        ) == 0
        {
            return 0;
        }
        EVP_EncryptUpdate(ctx, out, &mut out_len, in_, out_len)
    }
}

/// `SIV128_CONTEXT *ossl_siv128_new(const unsigned char *key, int klen, EVP_CIPHER *cbc,
/// EVP_CIPHER *ctr, OSSL_LIB_CTX *libctx, const char *propq)` — `siv128.c:141-152`.
///
/// **One line differs from the authority, and it is a memory-safety fix rather than a
/// behavioural one.** The authority allocates with `OPENSSL_malloc` and then calls
/// `ossl_siv128_init`, whose first four statements `EVP_CIPHER_CTX_free`, `EVP_MAC_CTX_free` and
/// `EVP_MAC_free` three pointers **read from that uninitialised block**. §3 of
/// `docs/SECURITY_DIVERGENCE_POLICY.md` prohibits copying a known memory-safety defect to obtain
/// parity, so this transcription allocates with `CRYPTO_zalloc` — the state `ossl_siv128_init`
/// requires, and the state every other caller reaches it in through `aes_siv_newctx`'s zalloc.
/// No observable changes: `ossl_siv128_init` assigns `d`, frees-and-nulls the three pointers and
/// sets `final_ret`/`crypto_ok` on both the success and the failure path, so the two versions
/// return the same pointer and the same contents.
///
/// The authority spells the fetch parameters `EVP_CIPHER *`; they are `*const` here because
/// nothing writes through them.
///
/// # Safety
/// `key` is readable for `klen` bytes; `cbc`/`ctr` are live fetched ciphers or NULL; `propq` is
/// NULL or NUL-terminated.
pub unsafe fn ossl_siv128_new(
    key: *const c_uchar,
    klen: c_int,
    cbc: *const EvpCipher,
    ctr: *const EvpCipher,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Siv128Context {
    // SAFETY: the caller's contract; `ossl_siv128_init`'s own contract is satisfied because a
    // zeroed block is what it requires of its caller.
    unsafe {
        let ctx = CRYPTO_zalloc(core::mem::size_of::<Siv128Context>(), FILE, LINE)
            .cast::<Siv128Context>();

        if !ctx.is_null() {
            if ossl_siv128_init(ctx, key, klen, cbc, ctr, libctx, propq) != 0 {
                return ctx;
            }
            CRYPTO_free(ctx.cast(), FILE, LINE);
        }

        ptr::null_mut()
    }
}

/// `int ossl_siv128_init(SIV128_CONTEXT *ctx, const unsigned char *key, int klen,
/// const EVP_CIPHER *cbc, const EVP_CIPHER *ctr, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `siv128.c:157-215`.
///
/// `D` is CMAC over sixteen zero octets under the **first half** of the key and the row's
/// AES-CTR context is initialised with the **second half**; `klen` is the half-length, because
/// an SIV key is twice the underlying cipher's.
///
/// **`ctx` must be zeroed before the call.** The authority's first four statements free
/// `cipher_ctx`/`mac_ctx_init`/`mac` and then null them, which is only defined for a zeroed
/// context; every caller in this profile reaches it through `aes_siv_newctx`'s `OPENSSL_zalloc`
/// or from `ossl_siv128_cleanup`.
///
/// # Safety
/// `ctx` is a live, zeroed `SIV128_CONTEXT`; `key` is readable for `klen` bytes; `cbc`/`ctr` are
/// live fetched ciphers.
pub unsafe fn ossl_siv128_init(
    ctx: *mut Siv128Context,
    key: *const c_uchar,
    klen: c_int,
    cbc: *const EvpCipher,
    ctr: *const EvpCipher,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let zero = [0u8; SIV_LEN];
        let mut out_len = SIV_LEN;
        let mut mac_ctx: *mut EvpMacCtx = ptr::null_mut();
        let mut params: [OsslParam; 3] = [OSSL_PARAM_construct_end(); 3];

        if ctx.is_null() {
            return 0;
        }

        (*ctx).d = SivBlock::zero();
        EVP_CIPHER_CTX_free((*ctx).cipher_ctx);
        EVP_MAC_CTX_free((*ctx).mac_ctx_init);
        EVP_MAC_free((*ctx).mac);
        (*ctx).mac = ptr::null_mut();
        (*ctx).cipher_ctx = ptr::null_mut();
        (*ctx).mac_ctx_init = ptr::null_mut();

        if key.is_null() || cbc.is_null() || ctr.is_null() {
            return 0;
        }

        let cbc_name = EVP_CIPHER_get0_name(cbc);
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cbc_name.cast_mut(), 0);
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_KEY,
            key.cast_mut().cast::<c_void>(),
            klen as usize,
        );
        params[2] = OSSL_PARAM_construct_end();

        (*ctx).cipher_ctx = EVP_CIPHER_CTX_new();
        (*ctx).mac = EVP_MAC_fetch(libctx, OSSL_MAC_NAME_CMAC, propq);
        if !(*ctx).mac.is_null() {
            (*ctx).mac_ctx_init = EVP_MAC_CTX_new((*ctx).mac);
        }

        let failed = (*ctx).cipher_ctx.is_null()
            || (*ctx).mac.is_null()
            || (*ctx).mac_ctx_init.is_null()
            || EVP_MAC_CTX_set_params((*ctx).mac_ctx_init, params.as_ptr()) == 0
            || EVP_EncryptInit_ex(
                (*ctx).cipher_ctx,
                ctr,
                ptr::null_mut(),
                key.add(klen as usize),
                ptr::null(),
            ) == 0
            || {
                mac_ctx = EVP_MAC_CTX_dup((*ctx).mac_ctx_init);
                mac_ctx.is_null()
            }
            || EVP_MAC_update(mac_ctx, zero.as_ptr(), zero.len()) == 0
            || EVP_MAC_final(
                mac_ctx,
                ptr::addr_of_mut!((*ctx).d).cast::<c_uchar>(),
                &mut out_len,
                SIV_LEN,
            ) == 0;

        if failed {
            EVP_CIPHER_CTX_free((*ctx).cipher_ctx);
            (*ctx).cipher_ctx = ptr::null_mut();
            EVP_MAC_CTX_free((*ctx).mac_ctx_init);
            (*ctx).mac_ctx_init = ptr::null_mut();
            EVP_MAC_CTX_free(mac_ctx);
            EVP_MAC_free((*ctx).mac);
            (*ctx).mac = ptr::null_mut();
            return 0;
        }
        EVP_MAC_CTX_free(mac_ctx);

        (*ctx).final_ret = -1;
        (*ctx).crypto_ok = 1;

        1
    }
}

/// `int ossl_siv128_copy_ctx(SIV128_CONTEXT *dest, SIV128_CONTEXT *src)` — `siv128.c:220-239`.
///
/// The authority's `mac` is shared by reference, not duplicated: `dest->mac = src->mac` with an
/// up-ref. `cipher_ctx` is copied through `EVP_CIPHER_CTX_copy`, `mac_ctx_init` through
/// `EVP_MAC_CTX_dup`, and `dest->cipher_ctx` is created when it is NULL — which is the state
/// `aes_siv_dupctx` leaves it in before calling this.
///
/// # Safety
/// `dest` and `src` are live `SIV128_CONTEXT`s.
pub unsafe fn ossl_siv128_copy_ctx(dest: *mut Siv128Context, src: *mut Siv128Context) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*dest).d = (*src).d;
        if (*dest).cipher_ctx.is_null() {
            (*dest).cipher_ctx = EVP_CIPHER_CTX_new();
            if (*dest).cipher_ctx.is_null() {
                return 0;
            }
        }
        if EVP_CIPHER_CTX_copy((*dest).cipher_ctx, (*src).cipher_ctx) == 0 {
            return 0;
        }
        EVP_MAC_CTX_free((*dest).mac_ctx_init);
        (*dest).mac_ctx_init = EVP_MAC_CTX_dup((*src).mac_ctx_init);
        if (*dest).mac_ctx_init.is_null() {
            return 0;
        }
        (*dest).mac = (*src).mac;
        if !(*dest).mac.is_null() && EVP_MAC_up_ref((*dest).mac) == 0 {
            return 0;
        }
        1
    }
}

/// `int ossl_siv128_aad(SIV128_CONTEXT *ctx, const unsigned char *aad, size_t len)` —
/// `siv128.c:241-265`. Per RFC 5297 §2.6 the last piece of associated data is the nonce, but the
/// function does not treat it specially: every call is `D = dbl(D) XOR CMAC(aad)`.
///
/// # Safety
/// `ctx` is live; `aad` is readable for `len` bytes.
pub unsafe fn ossl_siv128_aad(ctx: *mut Siv128Context, aad: *const c_uchar, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut mac_out = SivBlock::zero();
        let mut out_len = SIV_LEN;

        siv128_dbl(ptr::addr_of_mut!((*ctx).d));

        let mac_ctx = EVP_MAC_CTX_dup((*ctx).mac_ctx_init);
        if mac_ctx.is_null()
            || EVP_MAC_update(mac_ctx, aad, len) == 0
            || EVP_MAC_final(
                mac_ctx,
                ptr::addr_of_mut!(mac_out).cast::<c_uchar>(),
                &mut out_len,
                SIV_LEN,
            ) == 0
            || out_len != SIV_LEN
        {
            EVP_MAC_CTX_free(mac_ctx);
            return 0;
        }
        EVP_MAC_CTX_free(mac_ctx);

        siv128_xorblock(ptr::addr_of_mut!((*ctx).d), ptr::addr_of!(mac_out));

        1
    }
}

/// `int ossl_siv128_encrypt(SIV128_CONTEXT *ctx, const unsigned char *in, unsigned char *out,
/// size_t len)` — `siv128.c:267-289`. The two `0x7f` masks are RFC 5297 §2.6's clearing of the
/// counter's top bits so a long payload cannot collide the counter with the SIV.
///
/// # Safety
/// `ctx` is live; `in_` is readable and `out` writable for `len`.
pub unsafe fn ossl_siv128_encrypt(
    ctx: *mut Siv128Context,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut q = SivBlock::zero();

        /* can only do one crypto operation */
        if (*ctx).crypto_ok == 0 {
            return 0;
        }
        (*ctx).crypto_ok -= 1;

        if siv128_do_s2v_p(ctx, ptr::addr_of_mut!(q), in_, len) == 0 {
            return 0;
        }

        (*ctx).tag = q;
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if siv128_do_encrypt((*ctx).cipher_ctx, out, in_, len, ptr::addr_of_mut!(q)) == 0 {
            return 0;
        }
        (*ctx).final_ret = 0;
        1
    }
}

/// `int ossl_siv128_decrypt(SIV128_CONTEXT *ctx, const unsigned char *in, unsigned char *out,
/// size_t len)` — `siv128.c:291-325`.
///
/// Decryption is CTR under the stored tag followed by S2V over the *recovered* plaintext,
/// compared against the tag; a mismatch **cleanses the output** before answering 0, which is an
/// observable side effect the court sees.
///
/// # Safety
/// `ctx` is live; `in_` is readable and `out` writable for `len`.
pub unsafe fn ossl_siv128_decrypt(
    ctx: *mut Siv128Context,
    in_: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut t = SivBlock::zero();

        /* can only do one crypto operation */
        if (*ctx).crypto_ok == 0 {
            return 0;
        }
        (*ctx).crypto_ok -= 1;

        let mut q = (*ctx).tag;
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        if siv128_do_encrypt((*ctx).cipher_ctx, out, in_, len, ptr::addr_of_mut!(q)) == 0
            || siv128_do_s2v_p(ctx, ptr::addr_of_mut!(t), out, len) == 0
        {
            return 0;
        }

        let tag = (*ctx).tag;
        for i in 0..SIV_LEN {
            t.byte[i] ^= tag.byte[i];
        }

        if (t.word[0] | t.word[1]) != 0 {
            OPENSSL_cleanse(out.cast(), len);
            return 0;
        }
        (*ctx).final_ret = 0;
        1
    }
}

/// `int ossl_siv128_finish(SIV128_CONTEXT *ctx)` — `siv128.c:327-332`: the already-computed
/// result, `-1` if no crypto operation ran.
///
/// # Safety
/// `ctx` is live.
pub unsafe fn ossl_siv128_finish(ctx: *mut Siv128Context) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).final_ret }
}

/// `int ossl_siv128_set_tag(SIV128_CONTEXT *ctx, const unsigned char *tag, size_t len)` —
/// `siv128.c:334-344`. Only `SIV_LEN` is accepted.
///
/// # Safety
/// `ctx` is live; `tag` is readable for `len`.
pub unsafe fn ossl_siv128_set_tag(
    ctx: *mut Siv128Context,
    tag: *const c_uchar,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if len != SIV_LEN {
            return 0;
        }
        ptr::copy_nonoverlapping(tag, (*ctx).tag.byte.as_mut_ptr(), len);
        1
    }
}

/// `int ossl_siv128_get_tag(SIV128_CONTEXT *ctx, unsigned char *tag, size_t len)` —
/// `siv128.c:346-356`. Only `SIV_LEN` is accepted.
///
/// # Safety
/// `ctx` is live; `tag` is writable for `len`.
pub unsafe fn ossl_siv128_get_tag(ctx: *mut Siv128Context, tag: *mut c_uchar, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if len != SIV_LEN {
            return 0;
        }
        ptr::copy_nonoverlapping((*ctx).tag.byte.as_ptr(), tag, len);
        1
    }
}

/// `int ossl_siv128_cleanup(SIV128_CONTEXT *ctx)` — `siv128.c:358-374`. Frees the three owned
/// references, cleanses `d` and `tag`, and restores the initial `final_ret`/`crypto_ok` — which
/// is what makes a cleaned-up context reusable rather than merely freed.
///
/// # Safety
/// `ctx` is NULL or a live, initialised `SIV128_CONTEXT`.
pub unsafe fn ossl_siv128_cleanup(ctx: *mut Siv128Context) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() {
            EVP_CIPHER_CTX_free((*ctx).cipher_ctx);
            (*ctx).cipher_ctx = ptr::null_mut();
            EVP_MAC_CTX_free((*ctx).mac_ctx_init);
            (*ctx).mac_ctx_init = ptr::null_mut();
            EVP_MAC_free((*ctx).mac);
            (*ctx).mac = ptr::null_mut();
            OPENSSL_cleanse(
                ptr::addr_of_mut!((*ctx).d).cast(),
                core::mem::size_of::<SivBlock>(),
            );
            OPENSSL_cleanse(
                ptr::addr_of_mut!((*ctx).tag).cast(),
                core::mem::size_of::<SivBlock>(),
            );
            (*ctx).final_ret = -1;
            (*ctx).crypto_ok = 1;
        }
        1
    }
}

/// `int ossl_siv128_speed(SIV128_CONTEXT *ctx, int arg)` — `siv128.c:376-380`. `arg == 1` sets
/// `crypto_ok` to `-1`, the "no single-operation limit" spelling the CTR speed-up uses.
///
/// # Safety
/// `ctx` is live.
pub unsafe fn ossl_siv128_speed(ctx: *mut Siv128Context, arg: c_int) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).crypto_ok = if arg == 1 { -1 } else { 1 };
        1
    }
}

impl Default for Siv128Context {
    /// The state `OPENSSL_zalloc` leaves, for a caller that has only a `OPENSSL_malloc` block.
    /// `ossl_siv128_init`'s first four statements require exactly this, and `aes_siv_newctx`
    /// reaches that state through the zalloc itself.
    fn default() -> Self {
        Siv128Context {
            d: SivBlock::zero(),
            tag: SivBlock::zero(),
            cipher_ctx: ptr::null_mut(),
            mac: ptr::null_mut(),
            mac_ctx_init: ptr::null_mut(),
            final_ret: -1,
            crypto_ok: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_views_are_the_same_sixteen_octets() {
        let mut b = SivBlock::zero();
        // SAFETY: `b` is this frame's own block.
        unsafe {
            for i in 0..SIV_LEN {
                b.byte[i] = i as c_uchar;
            }
            assert_eq!(b.word[0], u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]));
            assert_eq!(
                b.word[1],
                u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15])
            );
        }
    }

    #[test]
    fn the_word_view_is_big_endian_on_this_target() {
        let mut b = SivBlock::zero();
        // SAFETY: `b` is this frame's own block.
        unsafe {
            siv128_putword(ptr::addr_of_mut!(b), 0, 0x0102030405060708);
            let bytes = b.byte;
            assert_eq!(bytes[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(siv128_getword(ptr::addr_of!(b), 0), 0x0102030405060708);
        }
    }

    #[test]
    fn doubling_matches_the_field_polynomial() {
        // `dbl(1) == 2`, and the two carry arms: a carry **out of the low word** sets the high
        // word's bit 0, while a set top bit of the **high word** applies the reduction
        // polynomial `0x87` to the low word. The second is the only value that exercises
        // `low_mask`.
        let mut b = SivBlock::zero();
        // SAFETY: `b` is this frame's own block.
        unsafe {
            siv128_putword(ptr::addr_of_mut!(b), 1, 1);
            siv128_dbl(ptr::addr_of_mut!(b));
            assert_eq!(siv128_getword(ptr::addr_of!(b), 0), 0);
            assert_eq!(siv128_getword(ptr::addr_of!(b), 1), 2);

            b = SivBlock::zero();
            siv128_putword(ptr::addr_of_mut!(b), 0, 1u64 << 63);
            siv128_dbl(ptr::addr_of_mut!(b));
            assert_eq!(siv128_getword(ptr::addr_of!(b), 0), 0);
            assert_eq!(siv128_getword(ptr::addr_of!(b), 1), 0x87);

            b = SivBlock::zero();
            siv128_putword(ptr::addr_of_mut!(b), 1, 1u64 << 63);
            siv128_dbl(ptr::addr_of_mut!(b));
            assert_eq!(siv128_getword(ptr::addr_of!(b), 0), 1);
            assert_eq!(siv128_getword(ptr::addr_of!(b), 1), 0);
        }
    }

    #[test]
    fn byteswap8_is_an_involution() {
        assert_eq!(byteswap8(0x0102030405060708), 0x0807060504030201);
        assert_eq!(
            byteswap8(byteswap8(0xdead_beef_cafe_f00d)),
            0xdead_beef_cafe_f00d
        );
    }

    #[test]
    fn xorblock_xors_both_words() {
        let mut a = SivBlock::zero();
        let mut b = SivBlock::zero();
        // SAFETY: both blocks are this frame's own.
        unsafe {
            siv128_putword(ptr::addr_of_mut!(a), 0, 0x0f);
            siv128_putword(ptr::addr_of_mut!(a), 1, 0xf0);
            siv128_putword(ptr::addr_of_mut!(b), 0, 0xff);
            siv128_xorblock(ptr::addr_of_mut!(a), ptr::addr_of!(b));
            assert_eq!(siv128_getword(ptr::addr_of!(a), 0), 0xf0);
            assert_eq!(siv128_getword(ptr::addr_of!(a), 1), 0xf0);
        }
    }
}
