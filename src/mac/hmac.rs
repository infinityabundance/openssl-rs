//! Phase 7.6 — `crypto/hmac/hmac.c`: the legacy one-shot HMAC interface.
//!
//! Twelve exports, and the plan's row is explicit that this is **not** the MAC implementation
//! underneath: `EVP_MAC` fetches an HMAC *provider* for that (`crypto/evp/mac_lib.c`, landed in
//! 7.3e). What is transcribed here is the pre-3.0 construction written directly over
//! `EVP_MD_CTX`, which is what makes it a separate surface a separate court can observe.
//!
//! ## The struct is the authority's, and it is four pointers and a union
//!
//! `include/crypto/hmac.h` does not exist — the authoritative layout is
//! `crypto/hmac/hmac_local.h`'s `struct hmac_ctx_st`: `md`, `md_ctx`, `i_ctx`, `o_ctx`, and the
//! `plat` union. There is **no** `key`/`key_len`/`flags` field (the deprecated 1.0 layout had
//! those; 3.x moved the key into the two pre-keyed contexts) and the union's only member on this
//! profile is an `int dummy`, because `OPENSSL_HMAC_S390X` is not defined outside s390x. The
//! field set is therefore transcribed from the file rather than remembered.
//!
//! ## The one-shot `HMAC()` is a `EVP_Q_mac` call, not a second implementation
//!
//! `HMAC()` (`hmac.c:250`) does not build the construction itself: it computes the digest size,
//! then calls `EVP_Q_mac(NULL, "HMAC", NULL, EVP_MD_get0_name(evp_md), ...)`. That is the whole
//! of the modern path, and it is why the court can drive the one-shot against a probe-local
//! *provider* HMAC while the `HMAC_*` context calls are driven against a probe-local `EVP_MD`.
//!
//! ## What is not here
//!
//! `#ifdef OPENSSL_HMAC_S390X` and its five `s390x_HMAC_*` calls are omitted: the admitted
//! profile is x86-64 (`configdata.pm`'s `asm_arch` is `x86_64`), so the block is not compiled and
//! `s390x_HMAC_init`/`_update`/`_final`/`_CTX_copy`/`_CTX_cleanup` are not referenced. The
//! `plat` union is still declared because it is part of the struct the authority lays out.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_CTX_reset, EVP_MD_CTX_set_flags, EVP_MD_get0_name,
    EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_xof, EvpMd, EvpMdCtx,
};
use crate::evp::mac::EVP_Q_mac;
use crate::runtime::mem::{cleanse, CRYPTO_free, CRYPTO_zalloc};

/// `HMAC_MAX_MD_CBLOCK_SIZE` — `crypto/hmac/hmac_local.h:18`, "the current largest case is for
/// SHA3-224". The two stack buffers `HMAC_Init_ex` keys into are exactly this long.
const HMAC_MAX_MD_CBLOCK_SIZE: usize = 144;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h`, and the size of `HMAC_Final`'s inner buffer and
/// of `HMAC()`'s static.
const EVP_MAX_MD_SIZE: usize = 64;

/// `HMAC`'s own `static unsigned char static_md[EVP_MAX_MD_SIZE]`.
///
/// `md == NULL` is a defined call that answers a pointer to this buffer, so the buffer is a
/// process-wide static in the authority and is transcribed as one. It is reached only through
/// `core::ptr::addr_of_mut!`, never through a reference, which is what keeps the `static_mut_refs`
/// lint away from a transcription that cannot be a shared reference in the first place.
static mut STATIC_MD: [c_uchar; EVP_MAX_MD_SIZE] = [0; EVP_MAX_MD_SIZE];

/// `crypto/hmac/hmac.c` — the translation unit the crate's allocations and frees are attributed
/// to. The file raises nothing, so there are no `err_sites` coordinates; the allocator's own
/// records name it.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/hmac/hmac.c".as_ptr();

/// `HMAC_CTX_new`'s `OPENSSL_zalloc(sizeof(HMAC_CTX))` (line 166).
const LINE_ZALLOC_CTX: c_int = 166;
/// `HMAC_CTX_free`'s `OPENSSL_free(ctx)` (line 196).
const LINE_FREE_CTX: c_int = 196;

/// `struct hmac_ctx_st` — `crypto/hmac/hmac_local.h:20`.
///
/// `pub` for the reason every internal type in an exported signature is: the twelve exports take
/// an `HMAC_CTX *`, and the authority keeps the struct in an uninstalled header. Every field is
/// `pub(crate)`, so nothing outside the crate can name or reach one.
#[repr(C)]
pub struct HmacCtx {
    /// `const EVP_MD *md` — what the caller last initialised with, and what `_get_md` answers.
    pub(crate) md: *const EvpMd,
    /// `EVP_MD_CTX *md_ctx` — the running context, a copy of `i_ctx` between calls.
    pub(crate) md_ctx: *mut EvpMdCtx,
    /// `EVP_MD_CTX *i_ctx` — the ipad-keyed context, copied into `md_ctx` on each init.
    pub(crate) i_ctx: *mut EvpMdCtx,
    /// `EVP_MD_CTX *o_ctx` — the opad-keyed context, copied into `md_ctx` by `HMAC_Final`.
    pub(crate) o_ctx: *mut EvpMdCtx,
    /// `union { int dummy; ... } plat` — the s390x scratch, an `int` on this profile.
    pub(crate) plat: c_int,
}

/// `HMAC_Init_ex(ctx, key, len, md, impl)` — `crypto/hmac/hmac.c:25`.
///
/// The two special cases are the whole contract and the court drives both:
///
///   * **a NULL `key` reuses the previous key** and does not re-key: the `if (key != NULL)` block
///     is the only place `i_ctx`/`o_ctx` are filled, and the final `EVP_MD_CTX_copy_ex` then
///     re-arms `md_ctx` from the remembered ipad state.
///   * **a NULL `md` reuses `ctx->md`**, and both NULL is a refusal (`return 0` at line 43).
///
/// `impl` is the ENGINE and is passed through, as the authority passes it; no ENGINE can be built
/// here (Phase 13), so every caller reaches this with NULL.
///
/// # Safety
/// `ctx` must be a live context; `key` readable for `len` bytes unless NULL; `md` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn HMAC_Init_ex(
    ctx: *mut HmacCtx,
    key: *const c_void,
    len: c_int,
    md: *const EvpMd,
    impl_: *mut c_void,
) -> c_int {
    let mut rv = 0;
    let mut reset = false;
    let mut pad = [0 as c_uchar; HMAC_MAX_MD_CBLOCK_SIZE];
    let mut keytmp = [0 as c_uchar; HMAC_MAX_MD_CBLOCK_SIZE];
    let mut keytmp_length: c_uint = 0;
    let mut md = md;

    // If we are changing MD then we must have a key.
    // SAFETY: `ctx` is live per the contract.
    let ctx_md = unsafe { (*ctx).md };
    if !md.is_null() && md != ctx_md && (key.is_null() || len < 0) {
        return 0;
    }

    if !md.is_null() {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).md = md };
    } else if !ctx_md.is_null() {
        md = ctx_md;
    } else {
        return 0;
    }

    // The HMAC construction is not allowed with the XOF shake128/shake256.
    // SAFETY: `md` is non-NULL on every arm that reaches here.
    if unsafe { EVP_MD_xof(md) } != 0 {
        return 0;
    }

    if !key.is_null() {
        reset = true;

        // SAFETY: `md` is non-NULL and live.
        let j = unsafe { EVP_MD_get_block_size(md) };
        // `ossl_assert(j <= sizeof(keytmp))` is `ossl_likely((x) != 0)` under `NDEBUG`, which is
        // how the authority compiles (`include/internal/common.h:41`), so `!ossl_assert(c)` is
        // `c == 0` and both refusals below are live. `j` is a `block_size`, an `int`, and the
        // authority compares it against `(int)sizeof(keytmp)`.
        if j > HMAC_MAX_MD_CBLOCK_SIZE as c_int {
            return 0;
        }
        if j < 0 {
            return 0;
        }
        if j < len {
            // SAFETY: `ctx` is live and `md_ctx` is non-NULL after a reset.
            let ok_init = unsafe { EVP_DigestInit_ex((*ctx).md_ctx, md, impl_) };
            // SAFETY: as above.
            let ok_upd = unsafe { EVP_DigestUpdate((*ctx).md_ctx, key, len as usize) };
            // SAFETY: as above; `keytmp` is this frame's 144-byte buffer.
            let ok_fin = unsafe {
                EVP_DigestFinal_ex((*ctx).md_ctx, keytmp.as_mut_ptr(), &mut keytmp_length)
            };
            if ok_init == 0 || ok_upd == 0 || ok_fin == 0 {
                return 0;
            }
        } else {
            if len < 0 || len as usize > HMAC_MAX_MD_CBLOCK_SIZE {
                return 0;
            }
            // SAFETY: `key` is readable for `len` bytes per the contract and `keytmp` has room.
            unsafe {
                ptr::copy_nonoverlapping(key.cast::<c_uchar>(), keytmp.as_mut_ptr(), len as usize)
            };
            keytmp_length = len as c_uint;
        }
        if keytmp_length as usize != HMAC_MAX_MD_CBLOCK_SIZE {
            let start = keytmp_length as usize;
            // SAFETY: `start < 144` on this arm and `keytmp` is 144 bytes.
            unsafe {
                ptr::write_bytes(
                    keytmp.as_mut_ptr().add(start),
                    0,
                    HMAC_MAX_MD_CBLOCK_SIZE - start,
                )
            };
        }

        for i in 0..HMAC_MAX_MD_CBLOCK_SIZE {
            pad[i] = 0x36 ^ keytmp[i];
        }
        // SAFETY: `ctx` is live and `md` is non-NULL; `i_ctx` is non-NULL after a reset.
        let ok_ii = unsafe { EVP_DigestInit_ex((*ctx).i_ctx, md, impl_) };
        // SAFETY: as above; the authority's own update length is `EVP_MD_get_block_size(md)`,
        // which the checks above have just established is `0 <= j <= 144`.
        let ok_iu = unsafe { EVP_DigestUpdate((*ctx).i_ctx, pad.as_ptr().cast(), j as usize) };
        if ok_ii == 0 || ok_iu == 0 {
            // `goto err`, where `reset` is true and the buffers are cleansed.
            // SAFETY: `keytmp` and `pad` are this frame's own buffers.
            unsafe {
                cleanse(keytmp.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
                cleanse(pad.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
            }
            return rv;
        }

        for i in 0..HMAC_MAX_MD_CBLOCK_SIZE {
            pad[i] = 0x5c ^ keytmp[i];
        }
        // SAFETY: as above for `o_ctx`.
        let ok_oi = unsafe { EVP_DigestInit_ex((*ctx).o_ctx, md, impl_) };
        // SAFETY: as above.
        let ok_ou = unsafe { EVP_DigestUpdate((*ctx).o_ctx, pad.as_ptr().cast(), j as usize) };
        if ok_oi == 0 || ok_ou == 0 {
            // SAFETY: `keytmp` and `pad` are this frame's own buffers.
            unsafe {
                cleanse(keytmp.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
                cleanse(pad.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
            }
            return rv;
        }
    }
    // SAFETY: `ctx` is live; both contexts are non-NULL after a reset, or were already live when
    // `key` was NULL and this call reuses the previous key.
    if unsafe { EVP_MD_CTX_copy_ex((*ctx).md_ctx, (*ctx).i_ctx) } == 0 {
        if reset {
            // SAFETY: `keytmp` and `pad` are this frame's own buffers.
            unsafe {
                cleanse(keytmp.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
                cleanse(pad.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
            }
        }
        return rv;
    }
    rv = 1;
    if reset {
        // SAFETY: `keytmp` and `pad` are this frame's own buffers.
        unsafe {
            cleanse(keytmp.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
            cleanse(pad.as_mut_ptr(), HMAC_MAX_MD_CBLOCK_SIZE);
        }
    }
    rv
}

/// `int HMAC_Init(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md)` —
/// `crypto/hmac/hmac.c:110`.
///
/// The pre-1.1.0 spelling. It **resets first when both `key` and `md` are given**, which is the
/// one behavioural difference from `HMAC_Init_ex`, and then delegates.
///
/// # Safety
/// `ctx` must be a live context; `key` readable for `len` bytes unless NULL; `md` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn HMAC_Init(
    ctx: *mut HmacCtx,
    key: *const c_void,
    len: c_int,
    md: *const EvpMd,
) -> c_int {
    if !key.is_null() && !md.is_null() {
        // SAFETY: `ctx` is live per the contract.
        unsafe { HMAC_CTX_reset(ctx) };
    }
    // SAFETY: the arguments are forwarded under this function's contract; the ENGINE is NULL, as
    // the authority passes it.
    unsafe { HMAC_Init_ex(ctx, key, len, md, ptr::null_mut()) }
}

/// `int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)` —
/// `crypto/hmac/hmac.c:118`.
///
/// A NULL `ctx->md` is a refusal before anything is touched, which is how an unarmed context
/// reports "not initialised" rather than faulting.
///
/// # Safety
/// `ctx` must be a live context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn HMAC_Update(ctx: *mut HmacCtx, data: *const c_uchar, len: usize) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).md }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live and armed, so `md_ctx` is live.
    unsafe { EVP_DigestUpdate((*ctx).md_ctx, data.cast::<c_void>(), len) }
}

/// `int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)` —
/// `crypto/hmac/hmac.c:131`.
///
/// The opad half: finalise the ipad-keyed message, re-arm `md_ctx` from `o_ctx`, fold the inner
/// digest in, and finalise again. The context is left re-armed for the next message because
/// `md_ctx` ends holding the outer digest's state, not a cleared one — the same "reusable after
/// final" property `CMAC` has.
///
/// # Safety
/// `ctx` must be a live context; `md` writable for the digest's size; `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn HMAC_Final(
    ctx: *mut HmacCtx,
    md: *mut c_uchar,
    len: *mut c_uint,
) -> c_int {
    let mut buf = [0 as c_uchar; EVP_MAX_MD_SIZE];
    let mut i: c_uint = 0;

    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).md }.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live and armed, so `md_ctx` is live.
    if unsafe { EVP_DigestFinal_ex((*ctx).md_ctx, buf.as_mut_ptr(), &mut i) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and armed, so both contexts are live.
    if unsafe { EVP_MD_CTX_copy_ex((*ctx).md_ctx, (*ctx).o_ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live; `buf` holds `i <= 64` bytes from the final above.
    if unsafe { EVP_DigestUpdate((*ctx).md_ctx, buf.as_ptr().cast(), i as usize) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live; `md`/`len` are the caller's, written with the outer digest.
    if unsafe { EVP_DigestFinal_ex((*ctx).md_ctx, md, len) } == 0 {
        return 0;
    }
    1
}

/// `size_t HMAC_size(const HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:157`.
///
/// `EVP_MD_get_size(NULL)` answers **-1** with `EVP_R_MESSAGE_DIGEST_IS_NULL` and this folds that
/// to 0, which is why an unarmed context answers 0 rather than a negative size. The court drives
/// the answer before and after init.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn HMAC_size(ctx: *const HmacCtx) -> usize {
    // SAFETY: `ctx` is live per the contract, so `md` is NULL or live.
    let size = unsafe { EVP_MD_get_size((*ctx).md) };
    if size < 0 {
        0
    } else {
        size as usize
    }
}

/// `HMAC_CTX *HMAC_CTX_new(void)` — `crypto/hmac/hmac.c:164`.
#[no_mangle]
pub extern "C" fn HMAC_CTX_new() -> *mut HmacCtx {
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<HmacCtx>(), FILE, LINE_ZALLOC_CTX).cast::<HmacCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh zeroed block this call owns.
        if unsafe { HMAC_CTX_reset(ctx) } == 0 {
            // SAFETY: `ctx` is this call's own block.
            unsafe { HMAC_CTX_free(ctx) };
            return ptr::null_mut();
        }
    }
    ctx
}

/// `static void hmac_ctx_cleanup(HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:177`.
///
/// The three resets and the `md = NULL`. The order is the authority's and is not interchangeable:
/// `md` is nulled **after** the contexts are reset, so a reset that reads the method on a
/// re-arm path still finds it.
///
/// # Safety
/// `ctx` must be a live context.
unsafe fn hmac_ctx_cleanup(ctx: *mut HmacCtx) {
    // SAFETY: `ctx` is live per the contract, so all three are NULL or live; `EVP_MD_CTX_reset`
    // accepts NULL.
    unsafe {
        EVP_MD_CTX_reset((*ctx).i_ctx);
        EVP_MD_CTX_reset((*ctx).o_ctx);
        EVP_MD_CTX_reset((*ctx).md_ctx);
        (*ctx).md = ptr::null();
    }
}

/// `void HMAC_CTX_free(HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:189`.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_free(ctx: *mut HmacCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { hmac_ctx_cleanup(ctx) };
    // SAFETY: `ctx` is live and each pointer is NULL or a context this crate owns.
    unsafe {
        EVP_MD_CTX_free((*ctx).i_ctx);
        EVP_MD_CTX_free((*ctx).o_ctx);
        EVP_MD_CTX_free((*ctx).md_ctx);
    }
    // SAFETY: `ctx` came from this crate's allocator and has just been released of everything it
    // held, so this is its last use.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX) };
}

/// `static int hmac_ctx_alloc_mds(HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:200`.
///
/// Allocates only what is NULL, so a reused context keeps its contexts and its key material. A
/// failure leaves the earlier allocations in place for the caller's cleanup, as the authority's
/// does.
///
/// # Safety
/// `ctx` must be a live context.
unsafe fn hmac_ctx_alloc_mds(ctx: *mut HmacCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).i_ctx }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).i_ctx = EVP_MD_CTX_new() };
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).i_ctx }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).o_ctx }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).o_ctx = EVP_MD_CTX_new() };
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).o_ctx }.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).md_ctx }.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).md_ctx = EVP_MD_CTX_new() };
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).md_ctx }.is_null() {
        return 0;
    }
    1
}

/// `int HMAC_CTX_reset(HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:217`.
///
/// **A NULL `ctx` faults here** (`hmac_ctx_cleanup` dereferences it) and the probe does not call
/// it: the authority's own `HMAC_CTX_new` is the only caller that could pass one and it checks
/// first. The contract states non-NULL.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_reset(ctx: *mut HmacCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { hmac_ctx_cleanup(ctx) };
    // SAFETY: `ctx` is live.
    if unsafe { hmac_ctx_alloc_mds(ctx) } == 0 {
        // SAFETY: `ctx` is live.
        unsafe { hmac_ctx_cleanup(ctx) };
        return 0;
    }
    1
}

/// `int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)` — `crypto/hmac/hmac.c:227`.
///
/// A deep copy of all three contexts plus the method pointer, so the two contexts share no state:
/// advancing one does not advance the other. That is what the court measures — advance the copy,
/// then the original, and compare both against the probe's own two expected digests.
///
/// # Safety
/// `dctx` must be a live context; `sctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_copy(dctx: *mut HmacCtx, sctx: *mut HmacCtx) -> c_int {
    // SAFETY: `dctx` is live per the contract.
    if unsafe { hmac_ctx_alloc_mds(dctx) } == 0 {
        // SAFETY: `dctx` is live.
        unsafe { hmac_ctx_cleanup(dctx) };
        return 0;
    }
    // The authority's three statements short-circuit on failure, so each is its own test rather
    // than one `&` over all three: a failed `i_ctx` copy must leave `o_ctx` and `md_ctx`
    // untouched, which is a difference a later `HMAC_CTX_get_md`-style read could see.
    // SAFETY: both contexts are live per the contract.
    if unsafe { EVP_MD_CTX_copy_ex((*dctx).i_ctx, (*sctx).i_ctx) } == 0 {
        // SAFETY: `dctx` is live.
        unsafe { hmac_ctx_cleanup(dctx) };
        return 0;
    }
    // SAFETY: both contexts are live per the contract.
    if unsafe { EVP_MD_CTX_copy_ex((*dctx).o_ctx, (*sctx).o_ctx) } == 0 {
        // SAFETY: `dctx` is live.
        unsafe { hmac_ctx_cleanup(dctx) };
        return 0;
    }
    // SAFETY: both contexts are live per the contract.
    if unsafe { EVP_MD_CTX_copy_ex((*dctx).md_ctx, (*sctx).md_ctx) } == 0 {
        // SAFETY: `dctx` is live.
        unsafe { hmac_ctx_cleanup(dctx) };
        return 0;
    }
    // SAFETY: both contexts are live per the contract.
    unsafe { (*dctx).md = (*sctx).md };
    1
}

/// `unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
///     const unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len)` —
/// `crypto/hmac/hmac.c:250`.
///
/// One `EVP_Q_mac` call with the method's own name as the sub-algorithm, and a `static` output
/// buffer when the caller passes NULL for `md`. A method whose size is not positive answers NULL
/// without calling the fetch at all, which is the only refusal in the body.
///
/// # Safety
/// `evp_md` must be live; `key` readable for `key_len` bytes; `data` readable for `data_len`;
/// `md` writable for the method's size unless NULL; `md_len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn HMAC(
    evp_md: *const EvpMd,
    key: *const c_void,
    key_len: c_int,
    data: *const c_uchar,
    data_len: usize,
    md: *mut c_uchar,
    md_len: *mut c_uint,
) -> *mut c_uchar {
    // SAFETY: `evp_md` is live per the contract.
    let size = unsafe { EVP_MD_get_size(evp_md) };
    let mut temp_md_len: usize = 0;
    let mut ret: *mut c_uchar = ptr::null_mut();

    if size > 0 {
        // SAFETY: `md == NULL` selects the process-wide static; otherwise it is the caller's
        // buffer, sized for the method per the contract.
        let out = if md.is_null() {
            ptr::addr_of_mut!(STATIC_MD).cast::<c_uchar>()
        } else {
            md
        };
        // SAFETY: `evp_md` is live; `EVP_MD_get0_name` accepts it; the key/data spans are the
        // caller's under this function's contract; `out` has room for `size` bytes.
        ret = unsafe {
            EVP_Q_mac(
                ptr::null_mut(),
                c"HMAC".as_ptr(),
                ptr::null(),
                EVP_MD_get0_name(evp_md),
                ptr::null(),
                key,
                key_len as usize,
                data,
                data_len,
                out,
                size as usize,
                &mut temp_md_len,
            )
        };
        if !md_len.is_null() {
            // SAFETY: `md_len` is non-NULL on this arm per the check.
            unsafe { *md_len = temp_md_len as c_uint };
        }
    }
    ret
}

/// `void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags)` —
/// `crypto/hmac/hmac.c:269`.
///
/// Sets the same flag bits on all three contexts. The authority's parameter is `unsigned long`
/// and `EVP_MD_CTX_set_flags` takes an `int`, so the value is truncated by the callee; the court
/// drives the flags whose observable is the *final*'s behaviour.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_set_flags(ctx: *mut HmacCtx, flags: c_ulong) {
    // SAFETY: `ctx` is live per the contract, so all three are NULL or live; the setter accepts
    // a live context.
    unsafe {
        EVP_MD_CTX_set_flags((*ctx).i_ctx, flags as c_int);
        EVP_MD_CTX_set_flags((*ctx).o_ctx, flags as c_int);
        EVP_MD_CTX_set_flags((*ctx).md_ctx, flags as c_int);
    }
}

/// `const EVP_MD *HMAC_CTX_get_md(const HMAC_CTX *ctx)` — `crypto/hmac/hmac.c:276`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn HMAC_CTX_get_md(ctx: *const HmacCtx) -> *const EvpMd {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).md }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh context is armed with three live `EVP_MD_CTX`s and no method, so `_size` is 0 and
    /// `_get_md` is NULL. That is the state the court's "before init" arm prints.
    #[test]
    fn new_context_has_no_method_and_answers_zero_size() {
        let ctx = HMAC_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is the live context just built.
        unsafe {
            assert!((*ctx).md.is_null());
            assert!(!(*ctx).i_ctx.is_null());
            assert!(!(*ctx).o_ctx.is_null());
            assert!(!(*ctx).md_ctx.is_null());
            assert_eq!(HMAC_size(ctx), 0);
            assert!(HMAC_CTX_get_md(ctx).is_null());
            // An unarmed context refuses an update rather than faulting.
            assert_eq!(HMAC_Update(ctx, ptr::null(), 0), 0);
            assert_eq!(HMAC_Final(ctx, ptr::null_mut(), ptr::null_mut()), 0);
            HMAC_CTX_free(ctx);
        }
    }

    /// `HMAC_Init_ex` with both `md` and `ctx->md` NULL is the documented refusal (`hmac.c:43`).
    #[test]
    fn init_with_no_method_anywhere_refuses() {
        let ctx = HMAC_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live; `md` is NULL and `key` is non-NULL.
        unsafe {
            assert_eq!(
                HMAC_Init_ex(ctx, b"k".as_ptr().cast(), 1, ptr::null(), ptr::null_mut()),
                0
            );
            // `HMAC_CTX_reset` then reuse is a defined call and leaves a live context.
            assert_eq!(HMAC_CTX_reset(ctx), 1);
            assert_eq!(HMAC_size(ctx), 0);
            HMAC_CTX_free(ctx);
        }
    }

    /// A NULL context is the one argument `HMAC_CTX_free` accepts, and the reset of a fresh
    /// context succeeds because every `EVP_MD_CTX_reset` accepts NULL.
    #[test]
    fn free_accepts_null() {
        // SAFETY: NULL is the defined argument.
        unsafe { HMAC_CTX_free(ptr::null_mut()) };
    }
}
