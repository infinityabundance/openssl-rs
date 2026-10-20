//! Phase 8.10 — `providers/implementations/signature/mac_legacy_sig.c`: the `HMAC`, `SIPHASH`,
//! `POLY1305` and `CMAC` `OSSL_OP_SIGNATURE` rows.
//!
//! Two hundred and sixty-four source lines, fourteen functions and four dispatch tables. The unit is
//! the legacy-MAC *signature* face of the same key objects `keymgmt/mac_legacy_kmgmt.c` publishes
//! (D389): `PROV_MAC_CTX` holds a [`MacKey`] borrow and an `EVP_MAC_CTX`, and the four rows differ
//! only in the MAC name their `newctx` fetches.
//!
//! ## What the unit is, and what it is not
//!
//! There is no signing arithmetic here at all. `mac_digest_sign_init` resolves the key's cipher name
//! (CMAC's case), sets `digest`/`cipher`/`engine`/`properties` on the MAC context through
//! [`ossl_prov_set_macctx`], and hands the private key to `EVP_MAC_init`; update and final are
//! forwarded to `EVP_MAC_update`/`EVP_MAC_final`. So the unit's whole closure is the MAC object
//! landed in D389 plus the `EVP_MAC_*` face, and it is the smallest member of the `OSSL_OP_SIGNATURE`
//! block — which is why it is the one the `DEFLT_SIGNATURES` table opens with.
//!
//! ## The `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` arm
//!
//! `mac_digest_sign_init`'s engine block (`:120-123`) is *compiled in* on this profile — D181
//! measured `OPENSSL_NO_ENGINE` as undefined — and it reads `ENGINE_get_id(key->cipher.engine)`.
//! `PROV_CIPHER.engine` can only ever be NULL in every state this crate can reach (D389's
//! measurement of the same field), so the block's guard is unreachable and the local `engine` is
//! NULL at the call below. It is **not emitted**, with that reason written at the site: the call is
//! absent because its guard is false in every reachable state, not because the unit was reduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{self, NonNull};

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::cipher::EVP_CIPHER_get0_name;
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch,
    EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_settable_ctx_params, EVP_MAC_update, EvpMac,
    EvpMacCtx,
};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DUPCTX,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
};
use crate::params::OsslParam;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::mac_legacy_kmgmt::{ossl_mac_key_free, ossl_mac_key_up_ref, MacKey};
use crate::provider::util::ossl_prov_set_macctx;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};

/// The unit's own `__FILE__`. `mac_legacy_sig.c` is a plain `.c`, so it carries the source-tree
/// prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/signature/mac_legacy_sig.c".as_ptr();

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_MAC_CTX` — `mac_legacy_sig.c:43-48`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvMacCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `MAC_KEY *key` — a borrow carrying a reference.
    key: *mut MacKey,
    /// `EVP_MAC_CTX *macctx`.
    macctx: *mut EvpMacCtx,
}

/// `mac_newctx`'s `OPENSSL_zalloc(sizeof(PROV_MAC_CTX))` — `mac_legacy_sig.c:58`.
const LINE_ALLOC_NEWCTX: c_int = 58;
/// `mac_dupctx`'s `OPENSSL_zalloc(sizeof(*srcctx))` — `mac_legacy_sig.c:179`.
const LINE_ALLOC_DUPCTX: c_int = 179;
/// `mac_newctx`'s `OPENSSL_strdup(propq)` — `mac_legacy_sig.c:63`.
const LINE_STRDUP_NEWCTX: c_int = 63;
/// `mac_dupctx`'s `OPENSSL_strdup(srcctx->propq)` — `mac_legacy_sig.c:188`.
const LINE_STRDUP_DUPCTX: c_int = 188;
/// `mac_newctx`'s `err:` `OPENSSL_free(pmacctx->propq)` — `mac_legacy_sig.c:79`.
const LINE_FREE_PROPQ_ERR: c_int = 79;
/// `mac_newctx`'s `err:` `OPENSSL_free(pmacctx)` — `mac_legacy_sig.c:80`.
const LINE_FREE_CTX_ERR: c_int = 80;
/// `mac_freectx`'s `OPENSSL_free(ctx->propq)` — `mac_legacy_sig.c:165`.
const LINE_FREE_PROPQ: c_int = 165;
/// `mac_freectx`'s `OPENSSL_free(ctx)` — `mac_legacy_sig.c:168`.
const LINE_FREE_CTX: c_int = 168;

/// An owned `PROV_MAC_CTX` block.
///
/// The block keeps the authority's `#[repr(C)]` layout and its stable address (the signature
/// dispatch hands it out as `*mut c_void` and `mac_freectx` takes it back), but its *ownership* is
/// this type: [`Self::zalloc`] allocates it through the crate's allocator seam at the authority's
/// own `__LINE__` and `Drop` is its single release, at the authority's own site. The block stays a
/// `CRYPTO_zalloc` rather than a Rust `Box` so a caller-installed `CRYPTO_set_mem_functions` hook
/// observes the allocation, its size and its release exactly as it observes the authority's.
///
/// The authority has two distinct release sites for the same block shape: `mac_freectx`
/// (`:165`/`:168`, run by the dispatch `freectx` and by `mac_dupctx`'s `err:`) and `mac_newctx`'s
/// own `err:` (`:79`/`:80`), so the two `__LINE__`s are carried per handle rather than fixed on
/// the type. The all-zero block is the authority's own constructed state for both, so `Drop` may
/// release the members (each NULL or an owned release) on either path.
struct OwnedCtx {
    ptr: NonNull<ProvMacCtx>,
    /// `__LINE__` of the `propq` release for this handle's path.
    propq_line: c_int,
    /// `__LINE__` of the block release for this handle's path.
    block_line: c_int,
}

impl OwnedCtx {
    /// `CRYPTO_zalloc(sizeof(PROV_MAC_CTX), FILE, alloc_line)` — the authority's `OPENSSL_zalloc`
    /// in `mac_newctx` (`:58`) or `mac_dupctx` (`:179`) — or `None` when the allocator answers
    /// NULL. `propq_line`/`block_line` are the `__LINE__`s this path frees at.
    fn zalloc(alloc_line: c_int, propq_line: c_int, block_line: c_int) -> Option<OwnedCtx> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block
        // of `size_of::<ProvMacCtx>()` bytes, which is exactly the context's layout.
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_zalloc(core::mem::size_of::<ProvMacCtx>(), FILE, alloc_line)
        }
        .cast::<ProvMacCtx>();
        NonNull::new(raw).map(|ptr| OwnedCtx {
            ptr,
            propq_line,
            block_line,
        })
    }

    /// Reclaim a block the dispatch handed back, for release by `Drop`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live `PROV_MAC_CTX` this unit allocated and has not released; the two
    /// `*_line`s are the authority's own release site for that context.
    unsafe fn from_raw(
        ptr: *mut ProvMacCtx,
        propq_line: c_int,
        block_line: c_int,
    ) -> Option<OwnedCtx> {
        NonNull::new(ptr).map(|ptr| OwnedCtx {
            ptr,
            propq_line,
            block_line,
        })
    }

    /// The stable address the dispatch hands out and `mac_freectx` takes back.
    fn as_ptr(&self) -> *mut ProvMacCtx {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the C caller's context pointer.
    fn into_raw(self) -> *mut ProvMacCtx {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedCtx {
    /// The context destructor: the authority's own `*_freectx`/`err:` body — the `propq` release,
    /// the MAC context release and the key's reference release — followed by the block release,
    /// each at the authority's own `__LINE__`.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a live `PROV_MAC_CTX` this handle owns (`zalloc`/`from_raw`) and
        // this is its single release; every member is NULL or an owned release (`propq` a strdup,
        // `macctx` an owned context, `key` a reference), and that zeroed/partially built state is
        // exactly what the authority's own body accepts.
        unsafe {
            CRYPTO_free(
                (*self.ptr.as_ptr()).propq.cast::<c_void>(),
                FILE,
                self.propq_line,
            );
            EVP_MAC_CTX_free((*self.ptr.as_ptr()).macctx);
            ossl_mac_key_free((*self.ptr.as_ptr()).key);
            CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), FILE, self.block_line);
        }
    }
}

/// `static void *mac_newctx(void *provctx, const char *propq, const char *macname)` —
/// `mac_legacy_sig.c:50-83`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `macname` is NUL-terminated.
unsafe fn mac_newctx(
    provctx: *mut c_void,
    propq: *const c_char,
    macname: *const c_char,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // `pmacctx = OPENSSL_zalloc(sizeof(PROV_MAC_CTX));` — `mac_legacy_sig.c:58`. The all-zero
    // block is the authority's own constructed state, so on the `err:` path below the owner
    // releases it exactly as the authority does; those two free lines are this function's own
    // `:79`/`:80`.
    let Some(ctx) = OwnedCtx::zalloc(LINE_ALLOC_NEWCTX, LINE_FREE_PROPQ_ERR, LINE_FREE_CTX_ERR)
    else {
        return ptr::null_mut();
    };
    let pmacctx = ctx.as_ptr();

    // SAFETY: `pmacctx` is this call's own allocation; `mac` is live or NULL.
    unsafe {
        (*pmacctx).libctx = prov_libctx_of(provctx);
        if !propq.is_null() {
            (*pmacctx).propq = CRYPTO_strdup(propq, FILE, LINE_STRDUP_NEWCTX);
            if (*pmacctx).propq.is_null() {
                return mac_newctx_err(ctx, ptr::null_mut());
            }
        }

        let mac = EVP_MAC_fetch((*pmacctx).libctx, macname, propq);
        if mac.is_null() {
            return mac_newctx_err(ctx, mac);
        }

        (*pmacctx).macctx = EVP_MAC_CTX_new(mac);
        if (*pmacctx).macctx.is_null() {
            return mac_newctx_err(ctx, mac);
        }

        EVP_MAC_free(mac);
    }

    ctx.into_raw().cast()
}

/// The authority's `err:` arm (`mac_legacy_sig.c:78-82`), a labelled block reached from three
/// statements in [`mac_newctx`]: the context's `Drop` is the authority's own `propq` and block
/// release (`:79`/`:80`) and the fetched MAC is freed after it, matching the authority's order.
///
/// # Safety
/// `mac` is NULL or a live fetched MAC.
unsafe fn mac_newctx_err(ctx: OwnedCtx, mac: *mut EvpMac) -> *mut c_void {
    drop(ctx);
    // SAFETY: `mac` is NULL or a live fetched MAC per the caller's contract.
    unsafe { EVP_MAC_free(mac) };
    ptr::null_mut()
}

/// `MAC_NEWCTX` — the four one-line `newctx` slots (`mac_legacy_sig.c:85-94`).
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_hmac_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"HMAC".as_ptr()) }
}

/// `mac_siphash_newctx` — `mac_legacy_sig.c:92`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_siphash_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"SIPHASH".as_ptr()) }
}

/// `mac_poly1305_newctx` — `mac_legacy_sig.c:93`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_poly1305_newctx(
    provctx: *mut c_void,
    propq: *const c_char,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"POLY1305".as_ptr()) }
}

/// `mac_cmac_newctx` — `mac_legacy_sig.c:94`.
///
/// # Safety
/// The signature `newctx` dispatch contract.
unsafe extern "C" fn mac_cmac_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { mac_newctx(provctx, propq, c"CMAC".as_ptr()) }
}

/// `static int mac_digest_sign_init(void *vpmacctx, const char *mdname, void *vkey,
/// const OSSL_PARAM params[])` — `mac_legacy_sig.c:96-137`.
///
/// The `#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)` engine block is named in this
/// module's header and is not emitted; `engine` is therefore NULL, which is the only value the
/// field can hold in this crate.
///
/// # Safety
/// The signature `digest_sign_init` dispatch contract.
unsafe extern "C" fn mac_digest_sign_init(
    vpmacctx: *mut c_void,
    mdname: *const c_char,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();
    let key = vkey.cast::<MacKey>();
    let mut ciphername: *const c_char = ptr::null();
    let engine: *const c_char = ptr::null();

    if is_running() == 0 || pmacctx.is_null() {
        return 0;
    }

    // SAFETY: both objects are the caller's, per the dispatch contract.
    unsafe {
        if (*pmacctx).key.is_null() && key.is_null() {
            raise_site(&err_sites::PROV_MAC_LEGACY_SIG_107);
            return 0;
        }

        if !key.is_null() {
            if ossl_mac_key_up_ref(key) == 0 {
                return 0;
            }
            ossl_mac_key_free((*pmacctx).key);
            (*pmacctx).key = key;
        }

        if !(*(*pmacctx).key).cipher.cipher.is_null() {
            ciphername = EVP_CIPHER_get0_name((*(*pmacctx).key).cipher.cipher);
        }

        if ossl_prov_set_macctx(
            (*pmacctx).macctx,
            ciphername,
            mdname,
            engine,
            (*(*pmacctx).key).properties,
        ) == 0
        {
            return 0;
        }

        if EVP_MAC_init(
            (*pmacctx).macctx,
            (*(*pmacctx).key).priv_key,
            (*(*pmacctx).key).priv_key_len,
            params,
        ) == 0
        {
            return 0;
        }
    }

    1
}

/// `int mac_digest_sign_update(void *vpmacctx, const unsigned char *data, size_t datalen)` —
/// `mac_legacy_sig.c:139-148`.
///
/// # Safety
/// The signature `digest_sign_update` dispatch contract.
unsafe extern "C" fn mac_digest_sign_update(
    vpmacctx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();

    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe {
        if pmacctx.is_null() || (*pmacctx).macctx.is_null() {
            return 0;
        }
        EVP_MAC_update((*pmacctx).macctx, data, datalen)
    }
}

/// `int mac_digest_sign_final(void *vpmacctx, unsigned char *mac, size_t *maclen,
/// size_t macsize)` — `mac_legacy_sig.c:150-159`.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
unsafe extern "C" fn mac_digest_sign_final(
    vpmacctx: *mut c_void,
    mac: *mut u8,
    maclen: *mut usize,
    macsize: usize,
) -> c_int {
    let pmacctx = vpmacctx.cast::<ProvMacCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe {
        if pmacctx.is_null() || (*pmacctx).macctx.is_null() {
            return 0;
        }
        EVP_MAC_final((*pmacctx).macctx, mac, maclen, macsize)
    }
}

/// `static void mac_freectx(void *vpmacctx)` — `mac_legacy_sig.c:161-169`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn mac_freectx(vpmacctx: *mut c_void) {
    let ctx = vpmacctx.cast::<ProvMacCtx>();

    // The dispatch hands the block back to `mac_freectx`.
    // SAFETY: `ctx` is NULL or a live `PROV_MAC_CTX` this unit allocated; `from_raw` reclaims it
    // and `Drop` runs the authority's own `mac_freectx` body (`:165`/`:168`).
    drop(unsafe { OwnedCtx::from_raw(ctx, LINE_FREE_PROPQ, LINE_FREE_CTX) });
}

/// `static void *mac_dupctx(void *vpmacctx)` — `mac_legacy_sig.c:171-205`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn mac_dupctx(vpmacctx: *mut c_void) -> *mut c_void {
    let srcctx = vpmacctx.cast::<ProvMacCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // `dstctx = OPENSSL_zalloc(sizeof(*srcctx));` — `mac_legacy_sig.c:179`. Its `err:` path is
    // `mac_freectx(dstctx)`, so the owner's free lines are that body's `:165`/`:168`.
    let Some(ctx) = OwnedCtx::zalloc(LINE_ALLOC_DUPCTX, LINE_FREE_PROPQ, LINE_FREE_CTX) else {
        return ptr::null_mut();
    };
    let dstctx = ctx.as_ptr();

    // SAFETY: both pointers are live per the contract; the copies are of this call's own
    // allocation.
    unsafe {
        *dstctx = *srcctx;
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).key = ptr::null_mut();
        (*dstctx).macctx = ptr::null_mut();

        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, LINE_STRDUP_DUPCTX);
            if (*dstctx).propq.is_null() {
                return mac_dupctx_err(ctx);
            }
        }

        if !(*srcctx).key.is_null() && ossl_mac_key_up_ref((*srcctx).key) == 0 {
            return mac_dupctx_err(ctx);
        }
        (*dstctx).key = (*srcctx).key;

        if !(*srcctx).macctx.is_null() {
            (*dstctx).macctx = EVP_MAC_CTX_dup((*srcctx).macctx);
            if (*dstctx).macctx.is_null() {
                return mac_dupctx_err(ctx);
            }
        }
    }

    ctx.into_raw().cast()
}

/// The authority's `err:` arm (`mac_legacy_sig.c:202-204`): `mac_freectx(dstctx)`, which is the
/// context's own `Drop`.
fn mac_dupctx_err(ctx: OwnedCtx) -> *mut c_void {
    drop(ctx);
    ptr::null_mut()
}

/// `static int mac_set_ctx_params(void *vpmacctx, const OSSL_PARAM params[])` —
/// `mac_legacy_sig.c:207-212`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn mac_set_ctx_params(vpmacctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vpmacctx.cast::<ProvMacCtx>();

    // SAFETY: the arguments are the caller's, per the dispatch contract.
    unsafe { EVP_MAC_CTX_set_params((*ctx).macctx, params) }
}

/// `static const OSSL_PARAM *mac_settable_ctx_params(void *ctx, void *provctx,
/// const char *macname)` — `mac_legacy_sig.c:214-229`.
///
/// # Safety
/// `provctx` is the caller's provider context; `macname` is NUL-terminated.
unsafe fn mac_settable_ctx_params(
    _ctx: *mut c_void,
    provctx: *mut c_void,
    macname: *const c_char,
) -> *const OsslParam {
    // SAFETY: both arguments are the caller's, per the dispatch contract.
    unsafe {
        let mac = EVP_MAC_fetch(prov_libctx_of(provctx), macname, ptr::null());
        if mac.is_null() {
            return ptr::null();
        }

        let params = EVP_MAC_settable_ctx_params(mac);
        EVP_MAC_free(mac);

        params
    }
}

/// `MAC_SETTABLE_CTX_PARAMS` — the four wrappers (`mac_legacy_sig.c:231-241`).
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_hmac_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"HMAC".as_ptr()) }
}

/// `mac_siphash_settable_ctx_params` — `mac_legacy_sig.c:239`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_siphash_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"SIPHASH".as_ptr()) }
}

/// `mac_poly1305_settable_ctx_params` — `mac_legacy_sig.c:240`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_poly1305_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"POLY1305".as_ptr()) }
}

/// `mac_cmac_settable_ctx_params` — `mac_legacy_sig.c:241`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mac_cmac_settable_ctx_params(
    ctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { mac_settable_ctx_params(ctx, provctx, c"CMAC".as_ptr()) }
}

/// `const OSSL_DISPATCH ossl_mac_legacy_hmac_signature_functions[]` —
/// `mac_legacy_sig.c:243-261`. Eight slots, the authority's, in its order.
pub(crate) static MAC_LEGACY_HMAC_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_hmac_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_hmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_siphash_signature_functions[]` —
/// `mac_legacy_sig.c:262`. The same eight slots with `newctx` and `settable_ctx_params` replaced.
pub(crate) static MAC_LEGACY_SIPHASH_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_siphash_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_siphash_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_poly1305_signature_functions[]` —
/// `mac_legacy_sig.c:263`.
pub(crate) static MAC_LEGACY_POLY1305_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_poly1305_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_poly1305_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `const OSSL_DISPATCH ossl_mac_legacy_cmac_signature_functions[]` — `mac_legacy_sig.c:264`.
pub(crate) static MAC_LEGACY_CMAC_SIGNATURE_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: mac_cmac_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: mac_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: mac_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: mac_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: mac_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: mac_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: mac_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: mac_cmac_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
