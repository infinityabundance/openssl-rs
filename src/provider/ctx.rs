//! Phase 8.3 — `providers/common/provider_ctx.c` and `prov/provider_ctx.h`: the `PROV_CTX` a
//! provider's `init` function publishes as its `provctx`.
//!
//! **This is the provider's own library context, and it is load-bearing for randomness and for
//! every sub-fetch.** A provider row that fetches through `PROV_LIBCTX_OF(provctx)` —
//! `cmac_prov.c`'s `ossl_prov_cipher_load`, `cipher_aes_siv_hw.c`'s two `EVP_CIPHER_fetch` calls
//! and `ossl_siv128_init`'s `EVP_MAC_fetch(…, "CMAC", …)`, and the GCM and TDES-wrap rows'
//! `RAND_bytes_ex(ctx->libctx, …)` — must resolve in the library context of the provider that
//! created the row, not the global one. `ossl_cipher_generic_initkey` stores exactly that on
//! `ctx->libctx` (`ciphercommon.c.in:758-759`).
//!
//! Without it, an application that loads the default provider in a private `OSSL_LIB_CTX` A and
//! fetches a row in A would silently reach the *global* context, and a test taken against the
//! global context could not tell the difference — D240 recorded that as a measured obligation
//! and this module is its discharge. `RT-CIPHER`'s private-libctx arm is what takes the
//! observation where it can discriminate.
//!
//! **`corebiometh` is absent, and why.** The authority's `PROV_CTX` also carries the core
//! `BIO_METHOD` that `ossl_bio_prov_init_bio_method` builds (`prov/bio.c`). No landed provider
//! path reaches it, and the crate does not transcribe that unit yet; the struct's layout is
//! internal — no exported signature carries it — so a field nothing reads is named here rather
//! than carried with an accessor that nothing calls. It joins `deflt_get_params`/
//! `deflt_gettable_params`/`ossl_prov_get_capabilities` in the D117 residual.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// The allocation-tracking `file` argument for this unit's allocations:
/// `providers/common/provider_ctx.c`.
const FILE: *const c_char = c"providers/common/provider_ctx.c".as_ptr();
/// `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
const LINE: c_int = 0;

/// `OSSL_FUNC_core_get_params_fn` — `include/openssl/core_dispatch.h`: the core's parameter
/// callback, which a provider reaches through its `PROV_CTX` rather than through the `in` table
/// it was handed, so that a *child* provider can answer the same questions. It is stored as a
/// raw pointer because that is what an `OSSL_DISPATCH` entry is; this alias is the shape behind
/// it, and `core_dispatch.rs`'s `core_get_params` is the function it will point at.
#[allow(dead_code)] // the provider-params half is the D117 residual this unit names
pub(crate) type CoreGetParamsFn =
    unsafe extern "C" fn(*const c_void, *mut crate::params::OsslParam) -> c_int;

/// `struct prov_ctx_st` — `prov/provider_ctx.h:19-24`. `libctx` is the field every sub-fetch
/// resolves against; `handle` and `core_get_params` are what a child provider would need.
#[repr(C)]
pub(crate) struct ProvCtx {
    /// `const OSSL_CORE_HANDLE *handle`.
    pub handle: *const c_void,
    /// `OSSL_LIB_CTX *libctx` — for all provider modules.
    pub libctx: *mut c_void,
    /// `OSSL_FUNC_core_get_params_fn *core_get_params`.
    pub core_get_params: *mut c_void,
}

/// `PROV_CTX *ossl_prov_ctx_new(void)` — `provider_ctx.c:15-18`.
pub(crate) fn ossl_prov_ctx_new() -> *mut ProvCtx {
    CRYPTO_zalloc(core::mem::size_of::<ProvCtx>(), FILE, LINE).cast::<ProvCtx>()
}

/// `void ossl_prov_ctx_free(PROV_CTX *ctx)` — `provider_ctx.c:20-23`. A bare `OPENSSL_free`: the
/// context owns no references, which is why nothing is released first.
///
/// # Safety
/// `ctx` is NULL or a context this module allocated.
pub(crate) unsafe fn ossl_prov_ctx_free(ctx: *mut ProvCtx) {
    // SAFETY: the caller's contract.
    unsafe { CRYPTO_free(ctx.cast(), FILE, LINE) };
}

/// `void ossl_prov_ctx_set0_libctx(PROV_CTX *ctx, OSSL_LIB_CTX *libctx)` —
/// `provider_ctx.c:25-29`.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_prov_ctx_set0_libctx(ctx: *mut ProvCtx, libctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() {
            (*ctx).libctx = libctx;
        }
    }
}

/// `void ossl_prov_ctx_set0_handle(PROV_CTX *ctx, const OSSL_CORE_HANDLE *handle)` —
/// `provider_ctx.c:31-35`.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_prov_ctx_set0_handle(ctx: *mut ProvCtx, handle: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() {
            (*ctx).handle = handle;
        }
    }
}

/// `void ossl_prov_ctx_set0_core_get_params(PROV_CTX *ctx,
/// OSSL_FUNC_core_get_params_fn *c_get_params)` — `provider_ctx.c:43-48`.
///
/// # Safety
/// `ctx` is NULL or live; `c_get_params` is NULL or the core's own callback.
pub(crate) unsafe fn ossl_prov_ctx_set0_core_get_params(
    ctx: *mut ProvCtx,
    c_get_params: *mut c_void,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if !ctx.is_null() {
            (*ctx).core_get_params = c_get_params;
        }
    }
}

/// `OSSL_LIB_CTX *ossl_prov_ctx_get0_libctx(PROV_CTX *ctx)` — `provider_ctx.c:50-55`. A NULL
/// context answers NULL rather than dereferencing, which is what makes `PROV_LIBCTX_OF` safe on
/// a provider that published no context.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn ossl_prov_ctx_get0_libctx(ctx: *mut ProvCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).libctx
    }
}

/// `const OSSL_CORE_HANDLE *ossl_prov_ctx_get0_handle(PROV_CTX *ctx)` — `provider_ctx.c:57-62`.
///
/// # Safety
/// `ctx` is NULL or live.
#[allow(dead_code)] // the child-provider walks (6.8e) are the callers that will land
pub(crate) unsafe fn ossl_prov_ctx_get0_handle(ctx: *mut ProvCtx) -> *const c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if ctx.is_null() {
            return ptr::null();
        }
        (*ctx).handle
    }
}

/// `OSSL_FUNC_core_get_params_fn *ossl_prov_ctx_get0_core_get_params(PROV_CTX *ctx)` —
/// `provider_ctx.c:70-77`.
///
/// # Safety
/// `ctx` is NULL or live.
#[allow(dead_code)] // `deflt_get_params` is the caller that will land, with the D117 residual
pub(crate) unsafe fn ossl_prov_ctx_get0_core_get_params(ctx: *mut ProvCtx) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if ctx.is_null() {
            return ptr::null_mut();
        }
        (*ctx).core_get_params
    }
}

/// `PROV_LIBCTX_OF(provctx)` — `prov/provider_ctx.h:30-31`, the macro every provider sub-fetch
/// spells. It is a function here because Rust has no macro for it, and it is the *only* way a
/// provider module may obtain a library context: `NULL` means the global default context, which
/// is what a provider that published no context gets, and is not the same thing as A.
///
/// # Safety
/// `provctx` is the `PROV_CTX` the owning provider published, or NULL.
pub(crate) unsafe fn prov_libctx_of(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract; the cast is the macro's own.
    unsafe { ossl_prov_ctx_get0_libctx(provctx.cast::<ProvCtx>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_context_answers_null_rather_than_dereferencing() {
        // SAFETY: NULL is explicitly part of each accessor's contract, and that is the point of
        // the test: a provider that published no context must not be dereferenced.
        unsafe {
            assert!(prov_libctx_of(ptr::null_mut()).is_null());
            assert!(ossl_prov_ctx_get0_libctx(ptr::null_mut()).is_null());
            assert!(ossl_prov_ctx_get0_handle(ptr::null_mut()).is_null());
            assert!(ossl_prov_ctx_get0_core_get_params(ptr::null_mut()).is_null());
            ossl_prov_ctx_free(ptr::null_mut());
        }
    }

    #[test]
    fn the_setters_ignore_a_null_context_and_the_getters_return_what_was_set() {
        // Three distinct real addresses rather than integer sentinels, so nothing here is a
        // fabricated pointer and the three fields cannot be confused for each other.
        let mut libctx_marker: u8 = 0;
        let mut cgp_marker: u8 = 0;
        let handle_marker: u8 = 0;
        let libctx = ptr::addr_of_mut!(libctx_marker).cast::<c_void>();
        let cgp = ptr::addr_of_mut!(cgp_marker).cast::<c_void>();
        let handle = ptr::addr_of!(handle_marker).cast::<c_void>();

        let ctx = ossl_prov_ctx_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is this test's own live context, and the three markers outlive it.
        unsafe {
            // A NULL context is a no-op for every setter, so none of these dereference.
            ossl_prov_ctx_set0_libctx(ptr::null_mut(), libctx);
            ossl_prov_ctx_set0_handle(ptr::null_mut(), handle);
            ossl_prov_ctx_set0_core_get_params(ptr::null_mut(), cgp);

            assert!((*ctx).libctx.is_null(), "a fresh context is zeroed");
            ossl_prov_ctx_set0_libctx(ctx, libctx);
            ossl_prov_ctx_set0_handle(ctx, handle);
            ossl_prov_ctx_set0_core_get_params(ctx, cgp);
            assert_eq!(prov_libctx_of(ctx.cast()), libctx);
            assert_eq!(ossl_prov_ctx_get0_handle(ctx), handle);
            assert_eq!(ossl_prov_ctx_get0_core_get_params(ctx), cgp);
            ossl_prov_ctx_free(ctx);
        }
    }
}
