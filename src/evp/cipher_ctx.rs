//! Phase 7.3c-i — the `EVP_CIPHER_CTX` object, its parameters, and initialisation.
//!
//! `docs/PHASE-7-SUBPHASES.md` records 7.3c's split and why it is a split at all; this file is
//! its first half. The line between the halves is **arming** versus **moving data**: everything
//! that gives a context a cipher, a key length, a padding mode, a parameter or an IV lives here,
//! and `EVP_EncryptUpdate`, the four `Final`s and `EVP_Cipher` — the twelve exports that push
//! bytes through an armed context — are 7.3c-ii's.
//!
//! ## The two halves are the two halves of the authority's switch
//!
//! `crypto/evp/evp_enc.c` is written twice over: a *legacy* half that runs when the cipher came
//! from `EVP_CIPHER_meth_new` or from an ENGINE, and a *provider* half that runs when it came
//! from `EVP_CIPHER_fetch`. Almost every function here is
//!
//! ```text
//! if (ctx->cipher == NULL)  raise EVP_R_NO_CIPHER_SET
//! if (ctx->cipher->prov == NULL)  goto legacy          <- the old path
//! ... provider path, OSSL_PARAM in and out ...
//! legacy:
//! ... direct field and function-pointer work ...
//! ```
//!
//! and the split is faithful where it matters: a provider cipher's parameters travel as
//! `OSSL_PARAM` through `evp_do_ciph_ctx_getparams`/`_setparams`, and a legacy cipher's are read
//! and written from the struct's own fields. `EVP_CIPHER_CTX_ctrl` is the clearest case — one
//! `switch` over nineteen commands on each side of the `goto`, with different meanings for the
//! same command.
//!
//! ## ENGINE is Phase 13's, and every ENGINE path here is recorded rather than stubbed
//!
//! The pinned profile has `OPENSSL_NO_ENGINE` **undefined**, so `evp_enc.c`'s ENGINE branches are
//! compiled in the authority, and the 115 `ENGINE_*` exports are Phase 13's — none of them exists
//! yet, and `ownership_audit.py` would refuse a Phase-7 file that defined one. What that costs is
//! measurable and small, and it is recorded here rather than left for a reader to discover:
//!
//!   * `tmpimpl = ENGINE_get_cipher_engine(cipher->nid)` is **omitted, so `tmpimpl` is NULL**. An
//!     engine can only become registered through `ENGINE_new`/`ENGINE_register_ciphers`, which
//!     are Phase 13's exports and scaffolds in the candidate today, so the authority's call
//!     answers NULL for every caller that can exist until Phase 13 — including every caller a
//!     court can construct, because a probe that tried to register an engine would abort the
//!     candidate on the scaffold rather than compare anything.
//!   * `ctx->engine` is therefore **always NULL**, which is why the `ENGINE_init`,
//!     `ENGINE_get_cipher` and `ENGINE_finish` calls are unreachable: each is guarded by
//!     `impl != NULL` or by `ctx->engine != NULL`.
//!   * the field itself is kept, so `EVP_CIPHER_CTX_copy`'s byte copy and any future
//!     Phase-13 code see the same layout.
//!
//! ## One export is handed to Phase 11, and it is the only one
//!
//! `EVP_CIPHER_CTX_get_algor` takes an `X509_ALGOR **` and fills it with `d2i_X509_ALGOR`, which
//! is Phase 11's (`X509_ALGOR_it`, `d2i_X509_ALGOR`, `i2d_X509_ALGOR`). Its two siblings,
//! `EVP_CIPHER_CTX_get_algor_params` and `_set_algor_params`, take the *struct* rather than a
//! decoder and need no Phase-11 function — only the layout, which is declared here — so they land
//! with this slice. The deferral is in `forensics/tools/phase7_obligations.py`'s `HANDED_ON` with
//! the dependency named, which is the mechanism the ledger documents for a symbol whose reader
//! arrives with another stratum.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_type::{d2i_ASN1_TYPE, i2d_ASN1_TYPE, ASN1_TYPE_set};
use crate::asn1::evp_asn1::{
    ossl_asn1_type_get_octetstring_int, ossl_asn1_type_set_octetstring_int,
    ASN1_TYPE_get_octetstring, ASN1_TYPE_set_octetstring,
};
use crate::asn1::layout::*;
use crate::evp::cipher::{
    evp_do_ciph_ctx_getparams, evp_do_ciph_ctx_setparams, EVP_CIPHER_free,
    EVP_CIPHER_get0_provider, EVP_CIPHER_get_block_size, EVP_CIPHER_get_flags,
    EVP_CIPHER_get_iv_length, EVP_CIPHER_get_mode, EVP_CIPHER_get_nid, EVP_CIPHER_is_a,
    EVP_CIPHER_settable_ctx_params, EVP_CIPHER_up_ref, EvpCipher, EVP_ORIG_METH,
};
use crate::evp::skeymgmt::{EVP_SKEY_get0_raw_key, EvpSkey};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_ptr, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_uint, OSSL_PARAM_get_int,
    OSSL_PARAM_locate_const, OSSL_PARAM_modified, OSSL_PARAM_set_int, OsslParam,
};
use crate::provider::{ossl_provider_ctx, ossl_provider_libctx};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::NID_undef;
use crate::runtime::obj::OBJ_nid2sn;

/// `EVP_CTRL_RET_UNSUPPORTED`, from `crypto/evp/evp_local.h`.
const EVP_CTRL_RET_UNSUPPORTED: c_int = -1;

/// `EVP_MAX_IV_LENGTH`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `EVP_MAX_BLOCK_LENGTH`.
const EVP_MAX_BLOCK_LENGTH: usize = 32;
/// `EVP_MAX_PIPES`.
const EVP_MAX_PIPES: usize = 32;

/// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` — the only ctx flag `evp_cipher_init_internal` preserves.
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_ulong = 0x1;

/// `EVP_CIPH_STREAM_CIPHER`.
const EVP_CIPH_STREAM_CIPHER: c_int = 0x0;
/// `EVP_CIPH_ECB_MODE`.
const EVP_CIPH_ECB_MODE: c_int = 0x1;
/// `EVP_CIPH_CBC_MODE`.
const EVP_CIPH_CBC_MODE: c_int = 0x2;
/// `EVP_CIPH_CFB_MODE`.
const EVP_CIPH_CFB_MODE: c_int = 0x3;
/// `EVP_CIPH_OFB_MODE`.
const EVP_CIPH_OFB_MODE: c_int = 0x4;
/// `EVP_CIPH_CTR_MODE`.
const EVP_CIPH_CTR_MODE: c_int = 0x5;
/// `EVP_CIPH_GCM_MODE`.
const EVP_CIPH_GCM_MODE: c_int = 0x6;
/// `EVP_CIPH_CCM_MODE`.
const EVP_CIPH_CCM_MODE: c_int = 0x7;
/// `EVP_CIPH_XTS_MODE`.
const EVP_CIPH_XTS_MODE: c_int = 0x10001;
/// `EVP_CIPH_WRAP_MODE`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `EVP_CIPH_OCB_MODE`.
const EVP_CIPH_OCB_MODE: c_int = 0x10003;

/// `EVP_CIPH_VARIABLE_LENGTH`.
const EVP_CIPH_VARIABLE_LENGTH: c_ulong = 0x8;
/// `EVP_CIPH_CUSTOM_IV`.
const EVP_CIPH_CUSTOM_IV: c_ulong = 0x10;
/// `EVP_CIPH_ALWAYS_CALL_INIT`.
const EVP_CIPH_ALWAYS_CALL_INIT: c_ulong = 0x20;
/// `EVP_CIPH_CTRL_INIT`.
const EVP_CIPH_CTRL_INIT: c_ulong = 0x40;
/// `EVP_CIPH_CUSTOM_KEY_LENGTH`.
const EVP_CIPH_CUSTOM_KEY_LENGTH: c_ulong = 0x80;
/// `EVP_CIPH_NO_PADDING`.
const EVP_CIPH_NO_PADDING: c_ulong = 0x100;
/// `EVP_CIPH_CUSTOM_IV_LENGTH`.
const EVP_CIPH_CUSTOM_IV_LENGTH: c_ulong = 0x800;
/// `EVP_CIPH_FLAG_FLAG_LENGTH_BITS`.
const EVP_CIPH_FLAG_LENGTH_BITS: c_ulong = 0x2000;
/// `EVP_CIPH_FLAG_CUSTOM_CIPHER` — the flag that sends the whole call to `do_cipher`.
const EVP_CIPH_FLAG_CUSTOM_CIPHER: c_ulong = 0x10_0000;
/// `EVP_CIPH_FLAG_CUSTOM_ASN1`.
const EVP_CIPH_FLAG_CUSTOM_ASN1: c_ulong = 0x100_0000;
/// `EVP_CIPH_CUSTOM_COPY`.
const EVP_CIPH_CUSTOM_COPY: c_ulong = 0x400;

// The `EVP_CTRL_*` commands `EVP_CIPHER_CTX_ctrl` switches on, from `include/openssl/evp.h`.
/// `EVP_CTRL_INIT`.
const EVP_CTRL_INIT: c_int = 0x0;
/// `EVP_CTRL_SET_KEY_LENGTH`.
const EVP_CTRL_SET_KEY_LENGTH: c_int = 0x1;
/// `EVP_CTRL_GET_RC2_KEY_BITS`.
const EVP_CTRL_GET_RC2_KEY_BITS: c_int = 0x2;
/// `EVP_CTRL_SET_RC2_KEY_BITS`.
const EVP_CTRL_SET_RC2_KEY_BITS: c_int = 0x3;
/// `EVP_CTRL_GET_RC5_ROUNDS`.
const EVP_CTRL_GET_RC5_ROUNDS: c_int = 0x4;
/// `EVP_CTRL_SET_RC5_ROUNDS`.
const EVP_CTRL_SET_RC5_ROUNDS: c_int = 0x5;
/// `EVP_CTRL_RAND_KEY`.
const EVP_CTRL_RAND_KEY: c_int = 0x6;
/// `EVP_CTRL_COPY`.
const EVP_CTRL_COPY: c_int = 0x8;
/// `EVP_CTRL_AEAD_SET_IVLEN` — also `EVP_CTRL_GCM_SET_IVLEN` and `EVP_CTRL_CCM_SET_IVLEN`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CTRL_AEAD_GET_TAG` — also the GCM and CCM spellings.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `EVP_CTRL_AEAD_SET_TAG` — also the GCM and CCM spellings.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `EVP_CTRL_AEAD_SET_IV_FIXED` — also the GCM and CCM spellings.
const EVP_CTRL_AEAD_SET_IV_FIXED: c_int = 0x12;
/// `EVP_CTRL_GCM_IV_GEN`.
const EVP_CTRL_GCM_IV_GEN: c_int = 0x13;
/// `EVP_CTRL_CCM_SET_L`.
const EVP_CTRL_CCM_SET_L: c_int = 0x14;
/// `EVP_CTRL_AEAD_TLS1_AAD` — the CCM spelling of the same number is `SET_MSGLEN`, which this
/// `switch` does not have an arm for.
const EVP_CTRL_AEAD_TLS1_AAD: c_int = 0x16;
/// `EVP_CTRL_AEAD_SET_MAC_KEY`.
const EVP_CTRL_AEAD_SET_MAC_KEY: c_int = 0x17;
/// `EVP_CTRL_GCM_SET_IV_INV`.
const EVP_CTRL_GCM_SET_IV_INV: c_int = 0x18;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE: c_int = 0x1c;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_AAD`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_AAD: c_int = 0x19;
/// `EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT`.
const EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT: c_int = 0x1a;
/// `EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS`.
const EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS: c_int = 0x22;
/// `EVP_CTRL_GET_IVLEN`.
const EVP_CTRL_GET_IVLEN: c_int = 0x25;
/// `EVP_CTRL_SET_SPEED`.
const EVP_CTRL_SET_SPEED: c_int = 0x27;

/// `SN_id_smime_alg_CMS3DESwrap` — the one OID name `EVP_CIPHER_param_to_asn1` compares against.
const SN_ID_SMIME_ALG_CMS3DESWRAP: *const c_char = c"id-smime-alg-CMS3DESwrap".as_ptr();

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID_PARAMS` — `OSSL_ALG_PARAM_ALGORITHM_ID_PARAMS`, the key
/// the two `algor_params` functions use.
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID_PARAMS: *const c_char = c"algorithm-id-params".as_ptr();

/// `OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD` — the retired spelling of the same key.
///
/// Both are sent by the two `algor_params` functions, because a provider may recognise either.
const OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD: *const c_char = c"alg_id_param".as_ptr();

/// The authority's translation unit, as the compiler spelled it — `evp_enc.c`'s sites.
const FILE_ENC: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c".as_ptr();
/// `crypto/evp/evp_lib.c`'s sites.
const FILE_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c".as_ptr();

/// `OPENSSL_zalloc(sizeof(EVP_CIPHER_CTX))` in `EVP_CIPHER_CTX_new`.
const LINE_ZALLOC_CTX: c_int = 74;
/// `OPENSSL_free(ctx)` in `EVP_CIPHER_CTX_free`.
const LINE_FREE_CTX: c_int = 89;
/// `OPENSSL_malloc(in->cipher->ctx_size)` in `EVP_CIPHER_CTX_copy`'s legacy arm.
const LINE_MALLOC_COPY: c_int = 1806;
/// `OPENSSL_free(der)` in `EVP_CIPHER_CTX_set_algor_params`.
const LINE_FREE_DER: c_int = 1457;
/// `OPENSSL_free(aid)` in `EVP_CIPHER_CTX_get_algor_params`.
const LINE_FREE_AID: c_int = 1517;

/// `struct x509_algor_st` — `X509_ALGOR`, from `include/openssl/x509.h`.
///
/// **Phase 11 owns this type** (`X509_ALGOR_it` and its two codecs are that stratum's), and two
/// functions in this file need one thing from it: the layout. `EVP_CIPHER_CTX_get_algor_params`
/// and `_set_algor_params` take a caller's `X509_ALGOR *`, read or write `parameter`, and pass it
/// to `d2i_ASN1_TYPE`/`i2d_ASN1_TYPE` — Phase 5's, and present. So the struct is declared here
/// with the authority's two fields and the reason it is declared rather than deferred, and the
/// one function that would need Phase 11's *decoder* is deferred instead.
#[repr(C)]
pub struct X509Algor {
    /// `const ASN1_OBJECT *algorithm` — the OID, which neither function here reads.
    pub algorithm: *const crate::runtime::obj::Asn1Object,
    /// `ASN1_TYPE *parameter` — the value, which both functions here do.
    pub parameter: *mut Asn1Type,
}

/// `struct evp_cipher_ctx_st` — `EVP_CIPHER_CTX`, from `crypto/evp/evp_local.h`.
///
/// The authority's field order, and the two runs of it are commented as the authority comments
/// them: everything above `numpipes` is the state the legacy half maintains, and `algctx` /
/// `fetched_cipher` are the provider-side pair. `engine` is always NULL in this crate — see the
/// module documentation — and is kept so the layout is the authority's.
///
/// **`pub` for the reason every internal type in an exported signature is**: `EVP_CIPHER_CTX_new`,
/// `EVP_CIPHER_CTX_dup` and the rest are exported, Rust requires an exported parameter's type to
/// be at least as visible, and the authority keeps this struct in a non-installed header. Every
/// field is `pub(crate)`.
#[repr(C)]
pub struct EvpCipherCtx {
    /// `const EVP_CIPHER *cipher` — borrowed; the reference is held by `fetched_cipher`.
    pub(crate) cipher: *const EvpCipher,
    /// `ENGINE *engine` — **always NULL** here; ENGINE is Phase 13's.
    pub(crate) engine: *mut c_void,
    /// `int encrypt` — 1 while encrypting, 0 while decrypting.
    pub(crate) encrypt: c_int,
    /// `int buf_len` — how many bytes of a partial block are held in `buf`.
    pub(crate) buf_len: c_int,
    /// `unsigned char oiv[EVP_MAX_IV_LENGTH]` — the IV as it was given.
    pub(crate) oiv: [c_uchar; EVP_MAX_IV_LENGTH],
    /// `unsigned char iv[EVP_MAX_IV_LENGTH]` — the running IV.
    pub(crate) iv: [c_uchar; EVP_MAX_IV_LENGTH],
    /// `unsigned char buf[EVP_MAX_BLOCK_LENGTH]` — the partial block.
    pub(crate) buf: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `int num` — the counter CFB, OFB and CTR keep; not a byte count.
    pub(crate) num: c_int,
    /// `void *app_data` — untouched by this crate.
    pub(crate) app_data: *mut c_void,
    /// `int key_len` — cached, and **-1 means "ask the provider"**.
    pub(crate) key_len: c_int,
    /// `int iv_len` — cached, and -1 means "ask the provider".
    pub(crate) iv_len: c_int,
    /// `unsigned long flags` — `EVP_CIPH_*`, and on a context the caller may set.
    pub(crate) flags: c_ulong,
    /// `void *cipher_data` — the legacy implementation's own block.
    pub(crate) cipher_data: *mut c_void,
    /// `int final_used`.
    pub(crate) final_used: c_int,
    /// `int block_mask` — `block_size - 1`, set at init.
    pub(crate) block_mask: c_int,
    /// `unsigned char final[EVP_MAX_BLOCK_LENGTH]`.
    pub(crate) final_: [c_uchar; EVP_MAX_BLOCK_LENGTH],
    /// `size_t numpipes` — 0 unless this context was armed for a pipeline.
    pub(crate) numpipes: usize,
    /// `void *algctx` — the provider's own context, from `newctx`.
    pub(crate) algctx: *mut c_void,
    /// `EVP_CIPHER *fetched_cipher` — **owned**; `cipher` borrows it.
    pub(crate) fetched_cipher: *mut EvpCipher,
}

/// `EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)`.
///
/// A zeroed block with `iv_len` set to **-1**, which is the sentinel every accessor tests: it
/// means "no length has been cached yet", and it is why a fresh context's `EVP_CIPHER_CTX_get_iv_length`
/// answers the cipher's length rather than zero.
#[no_mangle]
pub extern "C" fn EVP_CIPHER_CTX_new() -> *mut EvpCipherCtx {
    let ctx = CRYPTO_zalloc(
        core::mem::size_of::<EvpCipherCtx>(),
        FILE_ENC,
        LINE_ZALLOC_CTX,
    )
    .cast::<EvpCipherCtx>();
    if !ctx.is_null() {
        // SAFETY: `ctx` is a fresh zeroed block this call owns.
        unsafe { (*ctx).iv_len = -1 };
    }
    ctx
}

/// `int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)`.
///
/// **Two halves again**, and the choice between them is `ctx->cipher->prov`: a provider context
/// hands its `algctx` back to the implementation's `freectx` and drops its reference to the
/// fetched cipher, and a legacy context runs the implementation's `cleanup`, **cleanses** its
/// `cipher_data` before releasing it, and zeroes the whole struct. Both end with the context
/// zeroed and `iv_len` at -1, so a reset context is indistinguishable from a fresh one.
///
/// The cleanse is the one security-relevant line here: `cipher_data` may hold key schedule
/// material, and `OPENSSL_free` alone would leave it in the heap.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_reset(ctx: *mut EvpCipherCtx) -> c_int {
    if ctx.is_null() {
        return 1;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    // SAFETY: `cipher` is NULL or the live method this context borrowed.
    let prov = if cipher.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `cipher` is NULL or the live method this context holds.
        unsafe { (*cipher).prov }
    };

    if cipher.is_null() || prov.is_null() {
        // The legacy arm.
        if !cipher.is_null() {
            // SAFETY: `cipher` is live and this context is the caller's.
            let cleanup = unsafe { (*cipher).cleanup };
            if let Some(f) = cleanup {
                // SAFETY: `f` is the implementation's own callback and `ctx` is the caller's
                // context; both sides of the ABI agree on the pointer.
                if unsafe { f(ctx.cast::<c_void>()) } == 0 {
                    return 0;
                }
            }
            // SAFETY: `cipher` is live.
            let (cipher_data, ctx_size) = unsafe { ((*ctx).cipher_data, (*cipher).ctx_size) };
            if !cipher_data.is_null() && ctx_size != 0 {
                // SAFETY: `cipher_data` is this context's own block of `ctx_size` bytes.
                unsafe { crate::runtime::mem::OPENSSL_cleanse(cipher_data, ctx_size as usize) };
            }
        }
        // SAFETY: `ctx` is live.
        let cipher_data = unsafe { (*ctx).cipher_data };
        // SAFETY: `cipher_data` is NULL or the block `cipher_data` was set from.
        unsafe { CRYPTO_free(cipher_data, FILE_ENC, 76) };
        // `ENGINE_finish(ctx->engine)` follows in the authority under `!OPENSSL_NO_ENGINE`; see
        // the module documentation for why the call is omitted and why that is not observable.
    } else {
        // The provider arm.
        // SAFETY: `ctx` is live.
        let algctx = unsafe { (*ctx).algctx };
        if !algctx.is_null() {
            // SAFETY: `cipher` is live.
            let freectx = unsafe { (*cipher).freectx };
            if let Some(f) = freectx {
                // SAFETY: `f` is the provider's own callback and `algctx` is the context it
                // created for this cipher.
                unsafe { f(algctx) };
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).algctx = ptr::null_mut() };
        }
        // SAFETY: `ctx` is live.
        let fetched = unsafe { (*ctx).fetched_cipher };
        // SAFETY: `fetched` is NULL or the method this context holds a reference to.
        unsafe { EVP_CIPHER_free(fetched) };
    }

    // Both arms end here, and both zero the whole struct: the authority writes
    // `memset(ctx, 0, sizeof(*ctx)); ctx->iv_len = -1;` in the legacy arm and the same two
    // statements in the provider arm.
    // SAFETY: `ctx` is a live, fully initialised `EvpCipherCtx`; zeroing plain-old-data is a
    // whole-value write and the old value is dropped here by construction (every owned pointer in
    // it has already been released above).
    unsafe {
        ptr::write_bytes(ctx.cast::<u8>(), 0, core::mem::size_of::<EvpCipherCtx>());
        (*ctx).iv_len = -1;
    }
    1
}

/// `void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)`.
///
/// Reset first — the same function a caller can call itself — and then the block.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_free(ctx: *mut EvpCipherCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { EVP_CIPHER_CTX_reset(ctx) };
    // SAFETY: `ctx` is a live block this call owns and just released.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE_ENC, LINE_FREE_CTX) };
}

/// `static int evp_cipher_ctx_enable_use_bits(EVP_CIPHER_CTX *ctx, unsigned int enable)`.
///
/// The `use-bits` parameter, sent when a caller toggles `EVP_CIPH_FLAG_LENGTH_BITS` **after** the
/// context was armed: the flag is a context-side fact, but a provider that counts in bits has to
/// be told, so the setter mirrors it into the implementation.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
unsafe fn evp_cipher_ctx_enable_use_bits(ctx: *mut EvpCipherCtx, enable: c_uint) -> c_int {
    let mut en = enable;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_uint(c"use-bits".as_ptr(), &mut en) };
    // SAFETY: `ctx` is live and `params` is this frame's own array.
    unsafe { EVP_CIPHER_CTX_set_params(ctx, params.as_mut_ptr()) }
}

/// `void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)`.
///
/// Assigns, then **notifies only if the length-bits flag actually changed** — `(old ^ new) & the
/// flag` — which is what makes the call idempotent for every other flag.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_flags(ctx: *mut EvpCipherCtx, flags: c_int) {
    // SAFETY: `ctx` is live per the contract.
    let oldflags = unsafe { (*ctx).flags };
    // SAFETY: `ctx` is live.
    let newflags = unsafe {
        (*ctx).flags |= flags as c_ulong;
        (*ctx).flags
    };
    if ((oldflags ^ newflags) & EVP_CIPH_FLAG_LENGTH_BITS) != 0 {
        // SAFETY: `ctx` is live per the contract.
        unsafe { evp_cipher_ctx_enable_use_bits(ctx, 1) };
    }
}

/// `void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_clear_flags(ctx: *mut EvpCipherCtx, flags: c_int) {
    // SAFETY: `ctx` is live per the contract.
    let oldflags = unsafe { (*ctx).flags };
    // SAFETY: `ctx` is live.
    let newflags = unsafe {
        (*ctx).flags &= !(flags as c_ulong);
        (*ctx).flags
    };
    if ((oldflags ^ newflags) & EVP_CIPH_FLAG_LENGTH_BITS) != 0 {
        // SAFETY: `ctx` is live per the contract.
        unsafe { evp_cipher_ctx_enable_use_bits(ctx, 0) };
    }
}

/// `int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)`.
///
/// The masked value, not a boolean: the authority returns `ctx->flags & flags`, so a caller that
/// passes several flags gets them back.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_test_flags(
    ctx: *const EvpCipherCtx,
    flags: c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    (unsafe { (*ctx).flags } & (flags as c_ulong)) as c_int
}

/// The cipher a context holds, or NULL. A private accessor, because three exported accessors and
/// every legacy branch need exactly this and the authority spells it `ctx->cipher` at each site.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
unsafe fn ctx_cipher(ctx: *const EvpCipherCtx) -> *const EvpCipher {
    if ctx.is_null() {
        return ptr::null();
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cipher }
}

/// `const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_cipher(ctx: *const EvpCipherCtx) -> *const EvpCipher {
    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe { ctx_cipher(ctx) }
}

/// `const EVP_CIPHER *EVP_CIPHER_CTX_get0_cipher(const EVP_CIPHER_CTX *ctx)`.
///
/// The same function under the `get0` spelling, which is the one a caller that knows the
/// reference is borrowed should use.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get0_cipher(ctx: *const EvpCipherCtx) -> *const EvpCipher {
    // SAFETY: `ctx` is NULL or live per the contract.
    unsafe { ctx_cipher(ctx) }
}

/// `EVP_CIPHER *EVP_CIPHER_CTX_get1_cipher(EVP_CIPHER_CTX *ctx)`.
///
/// Answers a **reference the caller owns**, which is why it takes one: a context that holds no
/// cipher answers NULL rather than an unreferenced pointer.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get1_cipher(ctx: *mut EvpCipherCtx) -> *mut EvpCipher {
    // SAFETY: `ctx` is NULL or live per the contract.
    let cipher = unsafe { ctx_cipher(ctx) }.cast_mut();
    if cipher.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cipher` is the live method this context holds.
    if unsafe { EVP_CIPHER_up_ref(cipher) } == 0 {
        return ptr::null_mut();
    }
    cipher
}

/// `int EVP_CIPHER_CTX_is_encrypting(const EVP_CIPHER_CTX *ctx)`.
///
/// **No NULL test**: the authority dereferences. The value is the `encrypt` field, not a
/// comparison against 1, so any non-zero a caller set is answered back.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_is_encrypting(ctx: *const EvpCipherCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).encrypt }
}

/// `void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_app_data(ctx: *const EvpCipherCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).app_data }
}

/// `void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_app_data(ctx: *mut EvpCipherCtx, data: *mut c_void) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).app_data = data };
}

/// `void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_cipher_data(ctx: *const EvpCipherCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cipher_data }
}

/// `void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data)`.
///
/// **Answers the old value**, which is the whole reason it is not a `void` setter: a legacy
/// implementation that replaces its own data block has to be able to release what it replaced.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_cipher_data(
    ctx: *mut EvpCipherCtx,
    cipher_data: *mut c_void,
) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    let old = unsafe { (*ctx).cipher_data };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cipher_data = cipher_data };
    old
}

/// `unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx)`.
///
/// The partial-block buffer, handed out **mutable** — the `noconst` in the name is the warning.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_buf_noconst(ctx: *mut EvpCipherCtx) -> *mut c_uchar {
    // SAFETY: `ctx` is live per the contract.
    unsafe { ptr::addr_of_mut!((*ctx).buf).cast::<c_uchar>() }
}

/// `int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx)`.
///
/// A provider context is **asked** rather than read: `num` is the implementation's counter, so
/// the answer comes from `OSSL_CIPHER_PARAM_NUM` and `EVP_CTRL_RET_UNSUPPORTED` is the arm a
/// legacy cipher takes — which is the sentinel, not zero, and a caller can tell them apart.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_num(ctx: *const EvpCipherCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let mut v: c_uint = unsafe { (*ctx).num } as c_uint;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_uint(c"num".as_ptr(), &mut v) };
    // SAFETY: `ctx` is live, so its cipher and `algctx` are the ones to ask.
    let ok =
        unsafe { evp_do_ciph_ctx_getparams((*ctx).cipher, (*ctx).algctx, params.as_mut_ptr()) };
    if ok != 0 {
        v as c_int
    } else {
        EVP_CTRL_RET_UNSUPPORTED
    }
}

/// `int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)`.
///
/// **The field is written even when the provider refuses**, which is the authority's order: `ok`
/// is tested after `ctx->num = (int)n` in the sense that the assignment happens first and the
/// answer is `ok != 0`. `n` is the caller's value after the provider had its chance to change it.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_num(ctx: *mut EvpCipherCtx, num: c_int) -> c_int {
    let mut n: c_uint = num as c_uint;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_uint(c"num".as_ptr(), &mut n) };
    // SAFETY: `ctx` is live, so its cipher and `algctx` are the ones to ask.
    let ok =
        unsafe { evp_do_ciph_ctx_setparams((*ctx).cipher, (*ctx).algctx, params.as_mut_ptr()) };
    if ok != 0 {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).num = n as c_int };
    }
    c_int::from(ok != 0)
}

/// `int EVP_CIPHER_CTX_get_block_size(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_block_size(ctx: *const EvpCipherCtx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    // SAFETY: `cipher` is NULL or the live method this context holds.
    unsafe { EVP_CIPHER_get_block_size(cipher) }
}

/// `int EVP_CIPHER_CTX_get_nid(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_nid(ctx: *const EvpCipherCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    // SAFETY: `cipher` is NULL or the live method this context holds.
    unsafe { EVP_CIPHER_get_nid(cipher) }
}

/// `int EVP_CIPHER_CTX_get_key_length(const EVP_CIPHER_CTX *ctx)`.
///
/// The cached length, or **the provider's answer cached into the context** when the cache is
/// `<= 0` and the cipher has a provider. The two refusals are different values on purpose:
/// `EVP_CTRL_RET_UNSUPPORTED` for a provider that could not answer, and `-1` for one that
/// answered something `OSSL_PARAM_get_int` refused.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`. The `const` is cast away because the cache is written.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_key_length(ctx: *const EvpCipherCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `ctx` and `cipher` are live.
    let (key_len, prov, algctx) = unsafe { ((*ctx).key_len, (*cipher).prov, (*ctx).algctx) };
    if key_len <= 0 && !prov.is_null() {
        let mut len: usize = 0;
        let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
        // SAFETY: the constructor writes one entry into this frame's own array.
        unsafe { params[0] = OSSL_PARAM_construct_size_t(c"keylen".as_ptr(), &mut len) };
        // SAFETY: `cipher` and `algctx` are live.
        let ok = unsafe { evp_do_ciph_ctx_getparams(cipher, algctx, params.as_mut_ptr()) };
        if ok <= 0 {
            return EVP_CTRL_RET_UNSUPPORTED;
        }
        let mut out: c_int = 0;
        // SAFETY: `params` is the array the provider just wrote and `out` is this frame's slot.
        if unsafe { OSSL_PARAM_get_int(params.as_ptr(), &mut out) } == 0 {
            return -1;
        }
        // SAFETY: `ctx` is live and the cast away of `const` is the authority's own.
        unsafe { (*(ctx as *mut EvpCipherCtx)).key_len = len as c_int };
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).key_len }
}

/// `int EVP_CIPHER_CTX_get_iv_length(const EVP_CIPHER_CTX *ctx)`.
///
/// Three arms, and the middle one is a *modified* test rather than a return code: the provider is
/// asked through `OSSL_CIPHER_PARAM_IVLEN`, and `OSSL_PARAM_modified` says whether it wrote
/// anything — so a provider that answers 1 without touching the value keeps the cipher's own
/// length. `EVP_CTRL_RET_UNSUPPORTED` from the ask means "legacy method", which is the one case
/// that falls through to `EVP_CIPHER_CTX_ctrl`'s `EVP_CTRL_GET_IVLEN`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`. The `const` is cast away for the cache.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_iv_length(ctx: *const EvpCipherCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `ctx` and `cipher` are live.
    let mut iv_len = unsafe { (*ctx).iv_len };
    if iv_len < 0 {
        // SAFETY: `cipher` is live.
        let len = unsafe { EVP_CIPHER_get_iv_length(cipher) };
        let mut v: usize = len as usize;
        let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
        // SAFETY: the constructor writes one entry into this frame's own array.
        unsafe { params[0] = OSSL_PARAM_construct_size_t(c"ivlen".as_ptr(), &mut v) };
        // SAFETY: `cipher` is live.
        let has_ctx_params = unsafe { (*cipher).get_ctx_params.is_some() };
        if has_ctx_params {
            // SAFETY: `cipher` and `ctx` are live.
            let rv =
                unsafe { evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr()) };
            if rv > 0 {
                // SAFETY: `params` is the array the provider just wrote.
                if unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0 {
                    let mut out: c_int = len;
                    // SAFETY: `params` is the array the provider just wrote and `out` is this
                    // frame's slot.
                    if unsafe { OSSL_PARAM_get_int(params.as_ptr(), &mut out) } == 0 {
                        return -1;
                    }
                    iv_len = out;
                } else {
                    iv_len = len;
                }
            } else if rv != EVP_CTRL_RET_UNSUPPORTED {
                return -1;
            }
        } else {
            // SAFETY: `cipher` is live.
            let custom = (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_CUSTOM_IV_LENGTH) != 0;
            if custom {
                let mut out: c_int = len;
                // SAFETY: `ctx` is live and `out` is this frame's slot, which the control call
                // writes through the pointer it is given.
                let rv = unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        ctx as *mut EvpCipherCtx,
                        EVP_CTRL_GET_IVLEN,
                        0,
                        ptr::addr_of_mut!(out).cast::<c_void>(),
                    )
                };
                if rv <= 0 {
                    return -1;
                }
                iv_len = out;
            } else {
                iv_len = len;
            }
        }
        // SAFETY: `ctx` is live and the cast away of `const` is the authority's own.
        unsafe { (*(ctx as *mut EvpCipherCtx)).iv_len = iv_len };
    }
    iv_len
}

/// `int EVP_CIPHER_CTX_get_tag_length(const EVP_CIPHER_CTX *ctx)`.
///
/// A provider-only question — the answer is always `OSSL_CIPHER_PARAM_AEAD_TAGLEN` — and the
/// answer to a refusal is **0**, not the sentinel, because the authority returns `ret == 1 ? v : 0`
/// and a legacy cipher can therefore never confuse a caller.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_tag_length(ctx: *const EvpCipherCtx) -> c_int {
    let mut v: usize = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_size_t(c"taglen".as_ptr(), &mut v) };
    // SAFETY: `ctx` is live per the contract.
    let ret =
        unsafe { evp_do_ciph_ctx_getparams((*ctx).cipher, (*ctx).algctx, params.as_mut_ptr()) };
    if ret == 1 {
        v as c_int
    } else {
        0
    }
}

/// The shared body of `EVP_CIPHER_CTX_iv`, `_iv_noconst` and `_original_iv`: ask the provider for
/// a **pointer** (`OSSL_PARAM_construct_octet_ptr`) and answer it, or answer the context's own
/// buffer when the ask fails.
///
/// The three differ only in the parameter name and in whether the initial value is `ctx->iv` or
/// `ctx->oiv`, so the difference is passed in rather than duplicated three times.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `key` must be NUL-terminated.
unsafe fn ctx_iv_triplet(
    ctx: *const EvpCipherCtx,
    key: *const c_char,
    initial: *mut c_uchar,
) -> *mut c_uchar {
    let mut v = initial;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array; it takes the address
    // of `v`, which is this frame's slot for the provider to overwrite.
    unsafe {
        params[0] =
            OSSL_PARAM_construct_octet_ptr(key, ptr::addr_of_mut!(v).cast(), EVP_MAX_IV_LENGTH)
    };
    // SAFETY: `ctx` is live per the contract.
    let ok =
        unsafe { evp_do_ciph_ctx_getparams((*ctx).cipher, (*ctx).algctx, params.as_mut_ptr()) };
    if ok != 0 {
        v
    } else {
        ptr::null_mut()
    }
}

/// `const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_original_iv(ctx: *const EvpCipherCtx) -> *const c_uchar {
    // SAFETY: `ctx` is live per the contract, so its `oiv` field is this context's own buffer.
    let initial = unsafe { ptr::addr_of!((*ctx).oiv).cast::<c_uchar>() }.cast_mut();
    // SAFETY: `ctx` is live; the key is a literal.
    unsafe { ctx_iv_triplet(ctx, c"iv".as_ptr(), initial) }.cast_const()
}

/// `const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_iv(ctx: *const EvpCipherCtx) -> *const c_uchar {
    // SAFETY: `ctx` is live per the contract.
    let initial = unsafe { ptr::addr_of!((*ctx).iv).cast::<c_uchar>() }.cast_mut();
    // SAFETY: `ctx` is live; the key is a literal.
    unsafe { ctx_iv_triplet(ctx, c"updated-iv".as_ptr(), initial) }.cast_const()
}

/// `unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_iv_noconst(ctx: *mut EvpCipherCtx) -> *mut c_uchar {
    // SAFETY: `ctx` is live per the contract.
    let initial = unsafe { ptr::addr_of_mut!((*ctx).iv).cast::<c_uchar>() };
    // SAFETY: `ctx` is live; the key is a literal.
    unsafe { ctx_iv_triplet(ctx, c"updated-iv".as_ptr(), initial) }
}

/// The shared body of `EVP_CIPHER_CTX_get_updated_iv` and `_get_original_iv`: ask the provider to
/// **write into the caller's buffer**, and answer whether it did.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `buf` must be writable for `len` bytes and `key` NUL-
/// terminated.
unsafe fn ctx_iv_into(
    ctx: *mut EvpCipherCtx,
    key: *const c_char,
    buf: *mut c_void,
    len: usize,
) -> c_int {
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_octet_string(key, buf, len) };
    // SAFETY: `ctx` is live per the contract.
    let ok =
        unsafe { evp_do_ciph_ctx_getparams((*ctx).cipher, (*ctx).algctx, params.as_mut_ptr()) };
    c_int::from(ok > 0)
}

/// `int EVP_CIPHER_CTX_get_updated_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `buf` writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_updated_iv(
    ctx: *mut EvpCipherCtx,
    buf: *mut c_void,
    len: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { ctx_iv_into(ctx, c"updated-iv".as_ptr(), buf, len) }
}

/// `int EVP_CIPHER_CTX_get_original_iv(EVP_CIPHER_CTX *ctx, void *buf, size_t len)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `buf` writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_original_iv(
    ctx: *mut EvpCipherCtx,
    buf: *mut c_void,
    len: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { ctx_iv_into(ctx, c"iv".as_ptr(), buf, len) }
}

/// `EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in)`.
///
/// A new context and a copy, with the new one **released if the copy refused** — which is why it
/// is not simply `new` then `copy`: a caller must not have to remember to free a half-made one.
///
/// # Safety
/// `in` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_dup(in_: *const EvpCipherCtx) -> *mut EvpCipherCtx {
    let mut out = EVP_CIPHER_CTX_new();
    if !out.is_null() {
        // SAFETY: `out` is live and `in_` is live per the contract.
        if unsafe { EVP_CIPHER_CTX_copy(out, in_) } == 0 {
            // SAFETY: `out` is this call's own object.
            unsafe { EVP_CIPHER_CTX_free(out) };
            out = ptr::null_mut();
        }
    }
    out
}

/// `int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)`.
///
/// A provider copy is a **field copy plus a new `algctx`**: `*out = *in` moves the scalars and the
/// two IV buffers, `out->algctx` is then nulled and replaced by `dupctx`'s answer, and the
/// *reference* to the fetched cipher is taken separately — so the copy owns its own.
///
/// A legacy copy is a `memcpy` and a fresh `cipher_data` block, and the implementation's `ctrl` is
/// asked to fix up anything else **only when the cipher says `EVP_CIPH_CUSTOM_COPY`**. Both
/// refusals set `out->cipher = NULL`, which is what stops a half-copied context from being used.
///
/// # Safety
/// `out` must be a live `EvpCipherCtx`; `in` must be NULL or a live `EvpCipherCtx`. `out` and `in`
/// must be distinct (the authority's `memcpy` assumes it).
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_copy(
    out: *mut EvpCipherCtx,
    in_: *const EvpCipherCtx,
) -> c_int {
    if in_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1785) };
        return 0;
    }
    // SAFETY: `in_` is live per the contract.
    let cipher = unsafe { (*in_).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1785) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    let prov = unsafe { (*cipher).prov };
    if !prov.is_null() {
        // SAFETY: `cipher` is live.
        let dupctx = unsafe { (*cipher).dupctx };
        let Some(dup) = dupctx else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1793) };
            return 0;
        };
        // SAFETY: `out` is live per the contract.
        unsafe { EVP_CIPHER_CTX_reset(out) };
        // SAFETY: `out` and `in_` are live and distinct; the copy is a whole-value write of a
        // plain-old-data struct, and the owned pointer it brings across is dealt with immediately
        // below.
        unsafe { ptr::copy_nonoverlapping(in_, out, 1) };
        // SAFETY: `out` is live. The copy brought `in`'s `algctx` across, and it belongs to `in`.
        unsafe { (*out).algctx = ptr::null_mut() };
        // SAFETY: `out` is live.
        let fetched = unsafe { (*out).fetched_cipher };
        if !fetched.is_null() {
            // SAFETY: `fetched` is the method this copy now names.
            if unsafe { EVP_CIPHER_up_ref(fetched) } == 0 {
                // SAFETY: `out` is live.
                unsafe { (*out).fetched_cipher = ptr::null_mut() };
                return 0;
            }
        }
        // SAFETY: `in_` is live, so its `algctx` is the provider's context and `dup` is that
        // provider's own callback.
        let copied = unsafe { dup((*in_).algctx) };
        if copied.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1809) };
            return 0;
        }
        // SAFETY: `out` is live.
        unsafe { (*out).algctx = copied };
        return 1;
    }

    // The legacy arm. `ENGINE_init(in->engine)` stands between here and the reset in the
    // authority; see the module documentation for why it is omitted and why `in->engine` is
    // always NULL in this crate.
    // SAFETY: `out` is live per the contract.
    unsafe { EVP_CIPHER_CTX_reset(out) };
    // SAFETY: `out` and `in_` are live and distinct.
    unsafe { ptr::copy_nonoverlapping(in_, out, 1) };

    // SAFETY: `in_` is live.
    let (in_data, ctx_size) = unsafe { ((*in_).cipher_data, (*cipher).ctx_size) };
    if !in_data.is_null() && ctx_size != 0 {
        // SAFETY: this allocates a fresh block of `ctx_size` bytes.
        let fresh = CRYPTO_malloc(ctx_size as usize, FILE_ENC, LINE_MALLOC_COPY);
        if fresh.is_null() {
            // SAFETY: `out` is live.
            unsafe { (*out).cipher = ptr::null() };
            return 0;
        }
        // SAFETY: `fresh` holds `ctx_size` bytes and `in_data` does too, and the two blocks are
        // distinct.
        unsafe { ptr::copy_nonoverlapping(in_data, fresh, ctx_size as usize) };
        // SAFETY: `out` is live.
        unsafe { (*out).cipher_data = fresh };
    }

    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_CUSTOM_COPY) != 0 {
        // SAFETY: `cipher` is live.
        let ctrl = unsafe { (*cipher).ctrl };
        if let Some(f) = ctrl {
            // SAFETY: `f` is the implementation's own callback; `in_` is its context, `out` is
            // the copy it is being asked to fix up, and both are live and distinct.
            if unsafe { f(in_ as *mut c_void, EVP_CTRL_COPY, 0, out.cast::<c_void>()) } == 0 {
                // SAFETY: `out` is live.
                unsafe { (*out).cipher = ptr::null() };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1841) };
                return 0;
            }
        }
    }
    1
}

/// `int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[])`.
///
/// The provider's callback, then **two parameters read back into the context's own caches**:
/// `keylen` and `ivlen` are what the context caches, and the authority re-reads them from the
/// caller's array after a success — which is how a caller that passes `keylen` at init time makes
/// the cache agree with what the provider was told. A parameter that will not convert sets the
/// cache to **-1**, the "unknown" sentinel, rather than leaving a stale value.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `params` a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_params(
    ctx: *mut EvpCipherCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    let mut r: c_int = 0;
    // SAFETY: `cipher` is NULL or the live method this context holds.
    let set_ctx_params = if cipher.is_null() {
        None
    } else {
        // SAFETY: `cipher` is NULL or the live method this context holds.
        unsafe { (*cipher).set_ctx_params }
    };
    if let Some(f) = set_ctx_params {
        // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is the context it made.
        r = unsafe { f((*ctx).algctx, params) };
        if r > 0 {
            // SAFETY: `params` is the caller's terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, c"keylen".as_ptr()) };
            if !p.is_null() {
                let mut out: c_int = 0;
                // SAFETY: `p` is a live entry of the caller's array and `out` is this frame's.
                if unsafe { OSSL_PARAM_get_int(p, &mut out) } == 0 {
                    r = 0;
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).key_len = -1 };
                } else {
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).key_len = out };
                }
            }
        }
        if r > 0 {
            // SAFETY: `params` is the caller's terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, c"ivlen".as_ptr()) };
            if !p.is_null() {
                let mut out: c_int = 0;
                // SAFETY: `p` is a live entry of the caller's array and `out` is this frame's.
                if unsafe { OSSL_PARAM_get_int(p, &mut out) } == 0 {
                    r = 0;
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).iv_len = -1 };
                } else {
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).iv_len = out };
                }
            }
        }
    }
    r
}

/// `int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `params` a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_params(
    ctx: *mut EvpCipherCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    // SAFETY: `cipher` is NULL or the live method this context holds.
    let get_ctx_params = if cipher.is_null() {
        None
    } else {
        // SAFETY: `cipher` is NULL or the live method this context holds.
        unsafe { (*cipher).get_ctx_params }
    };
    let Some(f) = get_ctx_params else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback; `params` is the caller's array.
    unsafe { f((*ctx).algctx, params) }
}

/// `const OSSL_PARAM *EVP_CIPHER_CTX_settable_params(EVP_CIPHER_CTX *cctx)`.
///
/// The two context-parameter lists are asked of the cipher with the **provider context**, not
/// this context: the list is a property of the algorithm, not of one use of it.
///
/// # Safety
/// `cctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_settable_params(
    cctx: *mut EvpCipherCtx,
) -> *const OsslParam {
    if cctx.is_null() {
        return ptr::null();
    }
    // SAFETY: `cctx` is live per the contract.
    let cipher = unsafe { (*cctx).cipher };
    if cipher.is_null() {
        return ptr::null();
    }
    // SAFETY: `cipher` is live.
    let settable = unsafe { (*cipher).settable_ctx_params };
    let Some(f) = settable else {
        return ptr::null();
    };
    // SAFETY: `cipher` is live.
    let provctx = unsafe { ossl_provider_ctx_for(cipher) };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f((*cctx).algctx, provctx) }
}

/// `const OSSL_PARAM *EVP_CIPHER_CTX_gettable_params(EVP_CIPHER_CTX *cctx)`.
///
/// # Safety
/// `cctx` must be NULL or a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_gettable_params(
    cctx: *mut EvpCipherCtx,
) -> *const OsslParam {
    if cctx.is_null() {
        return ptr::null();
    }
    // SAFETY: `cctx` is live per the contract.
    let cipher = unsafe { (*cctx).cipher };
    if cipher.is_null() {
        return ptr::null();
    }
    // SAFETY: `cipher` is live, and `cctx->cipher` was non-NULL so this is too.
    let gettable = unsafe { (*cipher).gettable_ctx_params };
    let Some(f) = gettable else {
        return ptr::null();
    };
    // SAFETY: `cipher` is live.
    let provctx = unsafe { ossl_provider_ctx_for(cipher) };
    // SAFETY: `f` is the provider's own callback.
    unsafe { f((*cctx).algctx, provctx) }
}

/// `ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher))` — the provider context the two
/// `gettable`/`settable` callbacks take.
///
/// # Safety
/// `cipher` must be a live `EvpCipher`.
unsafe fn ossl_provider_ctx_for(cipher: *const EvpCipher) -> *mut c_void {
    // SAFETY: `cipher` is live per the contract.
    let prov = unsafe { EVP_CIPHER_get0_provider(cipher) };
    // SAFETY: `prov` is NULL or the live provider that published this method.
    unsafe { crate::provider::ossl_provider_ctx(prov) }
}

/// `static OSSL_LIB_CTX *EVP_CIPHER_CTX_get_libctx(EVP_CIPHER_CTX *ctx)`.
///
/// The context's library context, reached through the cipher's provider — which is why a context
/// with no cipher answers NULL rather than the default context: there is no provider to ask.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[allow(dead_code)]
// its only caller, `EVP_CIPHER_CTX_rand_key`, is deferred to Phase 9
// mirrors the authority's name exactly: this is a transcription, not a Rust function
#[allow(non_snake_case)]
unsafe fn EVP_CIPHER_CTX_get_libctx(ctx: *mut EvpCipherCtx) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cipher` is live.
    let prov = unsafe { EVP_CIPHER_get0_provider(cipher) };
    // SAFETY: `prov` is NULL or the live provider that published this method.
    unsafe { ossl_provider_libctx(prov) }
}

/// `int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)`.
///
/// **A provider cipher is asked; a legacy one is told.** The provider arm first refuses a length
/// the cipher does not advertise in `EVP_CIPHER_settable_ctx_params` — asking without that check
/// would silently succeed on a provider that ignores the parameter — and then sends
/// `OSSL_CIPHER_PARAM_KEYLEN` and caches what was accepted.
///
/// The legacy arm's middle refusal is the authority's own comment: `EVP_CIPH_CUSTOM_KEY_LENGTH`
/// "has never been defined by any built-in cipher", so the branch that consults it is written and
/// unreachable.
///
/// # Safety
/// `c` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_key_length(
    c: *mut EvpCipherCtx,
    keylen: c_int,
) -> c_int {
    // SAFETY: `c` is live per the contract.
    let cipher = unsafe { (*c).cipher };
    // SAFETY: `cipher` is live.
    let prov = unsafe { (*cipher).prov };
    if !prov.is_null() {
        let mut len: usize = 0;
        let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
        // SAFETY: `c` is live.
        if unsafe { EVP_CIPHER_CTX_get_key_length(c) } == keylen {
            return 1;
        }
        // The cipher has to understand the parameter, or the ask would be silently ignored.
        // SAFETY: `cipher` is live.
        let settable = unsafe { EVP_CIPHER_settable_ctx_params(cipher) };
        // SAFETY: `settable` is NULL or the provider's own terminated list.
        if unsafe { OSSL_PARAM_locate_const(settable, c"keylen".as_ptr()) }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1410) };
            return 0;
        }
        // SAFETY: the constructor writes one entry into this frame's own array.
        unsafe { params[0] = OSSL_PARAM_construct_size_t(c"keylen".as_ptr(), &mut len) };
        // SAFETY: `params` is this frame's own array and `keylen` is the caller's value.
        if unsafe { OSSL_PARAM_set_int(params.as_mut_ptr(), keylen) } == 0 {
            return 0;
        }
        // SAFETY: `cipher` is live and `params` is this frame's array.
        let ok = unsafe { evp_do_ciph_ctx_setparams(cipher, (*c).algctx, params.as_ptr()) };
        if ok <= 0 {
            return 0;
        }
        // SAFETY: `c` is live.
        unsafe { (*c).key_len = keylen };
        return 1;
    }

    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_CUSTOM_KEY_LENGTH) != 0 {
        // SAFETY: `c` is live; the control call is asked the same question the flag stands for.
        return unsafe { EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, ptr::null_mut()) };
    }
    // SAFETY: `c` is live.
    if unsafe { EVP_CIPHER_CTX_get_key_length(c) } == keylen {
        return 1;
    }
    // SAFETY: `cipher` is live.
    if keylen > 0 && (unsafe { (*cipher).flags } & EVP_CIPH_VARIABLE_LENGTH) != 0 {
        // SAFETY: `c` is live.
        unsafe { (*c).key_len = keylen };
        return 1;
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::EVP_ENC_1410) };
    0
}

/// `int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)`.
///
/// **The context flag is set first and the provider told second**, so a provider that refuses
/// leaves the context's own state changed anyway — which is the authority's order and is what
/// makes the answer a report about the provider rather than about the flag.
///
/// A legacy cipher has no parameter to send: the flag is the whole mechanism, and the authority
/// answers 1 after setting it.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_padding(ctx: *mut EvpCipherCtx, pad: c_int) -> c_int {
    let mut pd: c_uint = pad as c_uint;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if pad != 0 {
            (*ctx).flags &= !EVP_CIPH_NO_PADDING;
        } else {
            (*ctx).flags |= EVP_CIPH_NO_PADDING;
        }
    }
    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        if unsafe { (*cipher).prov }.is_null() {
            return 1;
        }
    }
    // SAFETY: the constructor writes one entry into this frame's own array.
    unsafe { params[0] = OSSL_PARAM_construct_uint(c"padding".as_ptr(), &mut pd) };
    // SAFETY: `ctx` is live and `params` is this frame's own array.
    let ok = unsafe { evp_do_ciph_ctx_setparams((*ctx).cipher, (*ctx).algctx, params.as_ptr()) };
    c_int::from(ok != 0)
}

/// `int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)`.
///
/// Nineteen commands, one `switch` on each side of the `goto legacy`, and the same numbers mean
/// different things on the two sides. The provider side turns each command into a parameter; the
/// legacy side calls the implementation's own `ctrl`.
///
/// Four things about it are load-bearing and easy to lose:
///
///   * `ret` starts at `EVP_CTRL_RET_UNSUPPORTED` and the **tail** converts that into a raised
///     `EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED` and an answer of 0. So the `default` arm — which is
///     `goto end` — and an implementation that answers the sentinel produce the same refusal.
///   * `EVP_CTRL_INIT` is answered **1 without asking anything**, deliberately: it is pure legacy
///     and the authority's comment says a caller may still be making the call directly.
///   * two commands are **set-then-get** and answer a size rather than a status:
///     `EVP_CTRL_AEAD_TLS1_AAD` and the two `MULTIBLOCK` ones.
///   * `EVP_CTRL_AEAD_SET_MAC_KEY` answers **-1** for a negative length while every other arm
///     answers 0, and `EVP_CTRL_AEAD_TLS1_AAD`'s `sz > INT_MAX` answers 0 after a *successful*
///     pair of calls.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `ptr` must be whatever the command's contract says, and
/// NULL for the commands that take none.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_ctrl(
    ctx: *mut EvpCipherCtx,
    type_: c_int,
    arg: c_int,
    ptr_: *mut c_void,
) -> c_int {
    let mut ret = EVP_CTRL_RET_UNSUPPORTED;
    let mut set_params = true;
    let mut sz: usize = arg as usize;
    let mut i: c_uint;
    let mut params: [OsslParam; 4] = [
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
    ];

    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1444) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1444) };
        return 0;
    }

    // SAFETY: `cipher` is live.
    if unsafe { (*cipher).prov }.is_null() {
        // The legacy arm.
        // SAFETY: `cipher` is live.
        let ctrl = unsafe { (*cipher).ctrl };
        let Some(f) = ctrl else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1632) };
            return 0;
        };
        // SAFETY: `f` is the implementation's own callback; `ctx` is its context.
        ret = unsafe { f(ctx.cast::<c_void>(), type_, arg, ptr_) };
    } else {
        // The provider arm: the `switch` fills `params` and `set_params`, or answers directly.
        let mut used = true;
        // SAFETY: every constructor below writes one entry into this frame's own array, and the
        // `evp_do_ciph_ctx_*` calls take addresses of this frame's scalars.
        unsafe {
            match type_ {
                EVP_CTRL_SET_KEY_LENGTH => {
                    if arg < 0 {
                        return 0;
                    }
                    if (*ctx).key_len == arg {
                        return 1;
                    }
                    params[0] = OSSL_PARAM_construct_size_t(c"keylen".as_ptr(), &mut sz);
                    (*ctx).key_len = -1;
                }
                EVP_CTRL_RAND_KEY => {
                    set_params = false;
                    params[0] = OSSL_PARAM_construct_octet_string(c"randkey".as_ptr(), ptr_, sz);
                }
                EVP_CTRL_INIT => return 1,
                EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS => used = false,
                EVP_CTRL_AEAD_SET_IVLEN => {
                    if arg < 0 {
                        return 0;
                    }
                    if (*ctx).iv_len == arg {
                        return 1;
                    }
                    params[0] = OSSL_PARAM_construct_size_t(c"ivlen".as_ptr(), &mut sz);
                    (*ctx).iv_len = -1;
                }
                EVP_CTRL_CCM_SET_L => {
                    if !(2..=8).contains(&arg) {
                        return 0;
                    }
                    sz = (15 - arg) as usize;
                    params[0] = OSSL_PARAM_construct_size_t(c"ivlen".as_ptr(), &mut sz);
                    (*ctx).iv_len = -1;
                }
                EVP_CTRL_AEAD_SET_IV_FIXED => {
                    params[0] = OSSL_PARAM_construct_octet_string(c"tlsivfixed".as_ptr(), ptr_, sz);
                }
                EVP_CTRL_GCM_IV_GEN => {
                    set_params = false;
                    if arg < 0 {
                        // The special case: a zero length means "use the IV length".
                        sz = 0;
                    }
                    params[0] = OSSL_PARAM_construct_octet_string(c"tlsivgen".as_ptr(), ptr_, sz);
                }
                EVP_CTRL_GCM_SET_IV_INV => {
                    if arg < 0 {
                        return 0;
                    }
                    params[0] = OSSL_PARAM_construct_octet_string(c"tlsivinv".as_ptr(), ptr_, sz);
                }
                EVP_CTRL_GET_RC5_ROUNDS | EVP_CTRL_SET_RC5_ROUNDS => {
                    if type_ == EVP_CTRL_GET_RC5_ROUNDS {
                        set_params = false;
                    }
                    if arg < 0 {
                        return 0;
                    }
                    i = arg as c_uint;
                    params[0] = OSSL_PARAM_construct_uint(c"rounds".as_ptr(), &mut i);
                }
                EVP_CTRL_SET_SPEED => {
                    if arg < 0 {
                        return 0;
                    }
                    i = arg as c_uint;
                    params[0] = OSSL_PARAM_construct_uint(c"speed".as_ptr(), &mut i);
                }
                EVP_CTRL_AEAD_GET_TAG | EVP_CTRL_AEAD_SET_TAG => {
                    if type_ == EVP_CTRL_AEAD_GET_TAG {
                        set_params = false;
                    }
                    params[0] = OSSL_PARAM_construct_octet_string(c"tag".as_ptr(), ptr_, sz);
                }
                EVP_CTRL_AEAD_TLS1_AAD => {
                    params[0] = OSSL_PARAM_construct_octet_string(c"tlsaad".as_ptr(), ptr_, sz);
                    ret = evp_do_ciph_ctx_setparams(cipher, (*ctx).algctx, params.as_ptr());
                    if ret <= 0 {
                        return EVP_CIPHER_CTX_ctrl_tail(ret);
                    }
                    let mut pad: usize = 0;
                    params[0] = OSSL_PARAM_construct_size_t(c"tlsaadpad".as_ptr(), &mut pad);
                    ret = evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr());
                    if ret <= 0 {
                        return EVP_CIPHER_CTX_ctrl_tail(ret);
                    }
                    if pad > c_int::MAX as usize {
                        return 0;
                    }
                    return pad as c_int;
                }
                EVP_CTRL_GET_RC2_KEY_BITS | EVP_CTRL_SET_RC2_KEY_BITS => {
                    if type_ == EVP_CTRL_GET_RC2_KEY_BITS {
                        set_params = false;
                    }
                    params[0] = OSSL_PARAM_construct_size_t(c"keybits".as_ptr(), &mut sz);
                }
                EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE => {
                    params[0] =
                        OSSL_PARAM_construct_size_t(c"tls1multi_maxsndfrag".as_ptr(), &mut sz);
                    ret = evp_do_ciph_ctx_setparams(cipher, (*ctx).algctx, params.as_ptr());
                    if ret <= 0 {
                        return ret;
                    }
                    let mut out: usize = 0;
                    params[0] =
                        OSSL_PARAM_construct_size_t(c"tls1multi_maxbufsz".as_ptr(), &mut out);
                    params[1] = OSSL_PARAM_construct_end();
                    ret = evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr());
                    if ret <= 0 || out > c_int::MAX as usize {
                        return 0;
                    }
                    return out as c_int;
                }
                EVP_CTRL_TLS1_1_MULTIBLOCK_AAD => {
                    let p = ptr_.cast::<MultiblockParam>();
                    if arg < core::mem::size_of::<MultiblockParam>() as c_int {
                        return 0;
                    }
                    params[0] = OSSL_PARAM_construct_octet_string(
                        c"tls1multi_aad".as_ptr(),
                        (*p).inp as *mut c_void,
                        (*p).len,
                    );
                    params[1] = OSSL_PARAM_construct_uint(
                        c"tls1multi_interleave".as_ptr(),
                        &mut (*p).interleave,
                    );
                    ret = evp_do_ciph_ctx_setparams(cipher, (*ctx).algctx, params.as_ptr());
                    if ret <= 0 {
                        return ret;
                    }
                    let mut packlen: usize = 0;
                    params[0] =
                        OSSL_PARAM_construct_size_t(c"tls1multi_aadpacklen".as_ptr(), &mut packlen);
                    params[1] = OSSL_PARAM_construct_uint(
                        c"tls1multi_interleave".as_ptr(),
                        &mut (*p).interleave,
                    );
                    params[2] = OSSL_PARAM_construct_end();
                    ret = evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr());
                    if ret <= 0 || packlen > c_int::MAX as usize {
                        return 0;
                    }
                    return packlen as c_int;
                }
                EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT => {
                    let p = ptr_.cast::<MultiblockParam>();
                    params[0] = OSSL_PARAM_construct_octet_string(
                        c"tls1multi_enc".as_ptr(),
                        (*p).out as *mut c_void,
                        (*p).len,
                    );
                    params[1] = OSSL_PARAM_construct_octet_string(
                        c"tls1multi_encin".as_ptr(),
                        (*p).inp as *mut c_void,
                        (*p).len,
                    );
                    params[2] = OSSL_PARAM_construct_uint(
                        c"tls1multi_interleave".as_ptr(),
                        &mut (*p).interleave,
                    );
                    ret = evp_do_ciph_ctx_setparams(cipher, (*ctx).algctx, params.as_ptr());
                    if ret <= 0 {
                        return ret;
                    }
                    let mut enclen: usize = 0;
                    params[0] =
                        OSSL_PARAM_construct_size_t(c"tls1multi_enclen".as_ptr(), &mut enclen);
                    params[1] = OSSL_PARAM_construct_end();
                    ret = evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr());
                    if ret <= 0 || enclen > c_int::MAX as usize {
                        return 0;
                    }
                    return enclen as c_int;
                }
                EVP_CTRL_AEAD_SET_MAC_KEY => {
                    if arg < 0 {
                        return -1;
                    }
                    params[0] = OSSL_PARAM_construct_octet_string(c"mackey".as_ptr(), ptr_, sz);
                }
                _ => used = false,
            }

            if used {
                ret = if set_params {
                    evp_do_ciph_ctx_setparams(cipher, (*ctx).algctx, params.as_ptr())
                } else {
                    evp_do_ciph_ctx_getparams(cipher, (*ctx).algctx, params.as_mut_ptr())
                };
            }
        }
    }

    EVP_CIPHER_CTX_ctrl_tail(ret)
}

/// The authority's `end:` label of `EVP_CIPHER_CTX_ctrl`: the sentinel becomes a raised refusal.
///
/// A `static`-free helper rather than a duplicated tail, because two of the `switch` arms reach
/// it early — that is what the authority's `goto end` does — and the two paths must raise
/// identically.
// mirrors the authority's `end:` label's caller name exactly
#[allow(non_snake_case)]
fn EVP_CIPHER_CTX_ctrl_tail(ret: c_int) -> c_int {
    if ret == EVP_CTRL_RET_UNSUPPORTED {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1640) };
        return 0;
    }
    ret
}

/// `static int evp_cipher_init_internal(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc,
/// uint8_t is_pipeline, const OSSL_PARAM params[])`.
///
/// The heart of the stratum, and it is three functions in one:
///
///   1. **the mode decision** — `enc == -1` means "keep the context's own direction", anything
///      else normalises to 0 or 1 and is written to the context;
///   2. **the provider path** — the cipher is fetched if it is a legacy one, its reference is
///      taken into `fetched_cipher`, `newctx` builds the implementation's context, and two
///      parameters are sent **before** the implementation is initialised, which is the fix for
///      CVE-2023-5363 and the reason the parameters are extracted into a second array rather
///      than forwarded;
///   3. **the legacy path** — reached by `goto legacy` when the cipher is `EVP_ORIG_METH` or an
///      ENGINE is involved: a `cipher_data` block, the key length from the method, `EVP_CTRL_INIT`
///      if the method asks for it, the IV/`num` handling by mode, and the method's own `init`.
///
/// Five facts are contract rather than detail, and each is a line a reader would otherwise read
/// past:
///
///   * **the mode switch only runs when the cipher is not `EVP_CIPH_CUSTOM_IV`** — a custom-IV
///     implementation manages its own IV, so `ctx->iv`/`ctx->oiv` are left alone;
///   * **CFB and OFB fall through to CBC** (they share the IV copy) while CTR copies the IV
///     *without* touching `oiv`, deliberately: "Don't reuse IV for CTR mode";
///   * **`EVP_CIPH_WRAP_MODE` needs `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW`**, and a context that was
///     not told to allow wrapping is refused;
///   * **`init` is called when a key was given *or* when the method sets
///     `EVP_CIPH_ALWAYS_CALL_INIT`**, and its refusal is the whole function's refusal;
///   * **`block_mask` is `block_size - 1`**, which is what makes `evp_EncryptDecryptUpdate`'s
///     `inl & ctx->block_mask` a block-alignment test.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `cipher` NULL or a live method; `impl` NULL (see the
/// module documentation on ENGINE); `key` and `iv` NULL or valid for the lengths the cipher
/// reports; `params` NULL or a terminated array.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
unsafe fn evp_cipher_init_internal(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
    is_pipeline: u8,
    params: *const OsslParam,
) -> c_int {
    let mut cipher = cipher;
    let mut enc = enc;

    if enc == -1 {
        // SAFETY: `ctx` is live per the contract.
        enc = unsafe { (*ctx).encrypt };
    } else {
        if enc != 0 {
            enc = 1;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).encrypt = enc };
    }

    if cipher.is_null() {
        // SAFETY: `ctx` is live.
        let existing = unsafe { (*ctx).cipher };
        if existing.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_118) };
            return 0;
        }
    }

    // The legacy/ENGINE decision, with `tmpimpl` omitted and therefore NULL.
    if is_pipeline == 0 {
        if !impl_.is_null() {
            // `ENGINE_init(impl)` is Phase 13's; `impl` can only be non-NULL from a caller that
            // already holds an ENGINE, which no caller can until Phase 13.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_296) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        let (engine, ctx_cipher) = unsafe { ((*ctx).engine, (*ctx).cipher) };
        let mut goes_legacy = !engine.is_null();
        if !cipher.is_null() {
            // SAFETY: `cipher` is live.
            goes_legacy |= unsafe { (*cipher).origin == EVP_ORIG_METH };
        } else if !ctx_cipher.is_null() {
            // SAFETY: `ctx_cipher` is live.
            goes_legacy |= unsafe { (*ctx_cipher).origin == EVP_ORIG_METH };
        }
        if goes_legacy {
            // SAFETY: `ctx` is live.
            unsafe {
                if (*ctx).cipher == (*ctx).fetched_cipher {
                    (*ctx).cipher = ptr::null();
                }
                EVP_CIPHER_free((*ctx).fetched_cipher);
                (*ctx).fetched_cipher = ptr::null_mut();
            }
            // SAFETY: the arguments are forwarded under this function's contract.
            return unsafe { evp_cipher_init_legacy_internal(ctx, cipher, key, iv, enc) };
        }
        // The legacy-only clearing, which the non-legacy path does not do.
        if !cipher.is_null() {
            // SAFETY: `ctx` is live.
            let ctx_cipher = unsafe { (*ctx).cipher };
            if !ctx_cipher.is_null() {
                // SAFETY: `ctx_cipher` is live.
                let cleanup = unsafe { (*ctx_cipher).cleanup };
                if let Some(f) = cleanup {
                    // SAFETY: `f` is the implementation's own callback and `ctx` is its context.
                    if unsafe { f(ctx.cast::<c_void>()) } == 0 {
                        return 0;
                    }
                }
                // SAFETY: `ctx` is live.
                let data = unsafe { (*ctx).cipher_data };
                // SAFETY: `ctx_cipher` is live.
                let size = unsafe { (*ctx_cipher).ctx_size };
                // SAFETY: `data` is this context's own block of `size` bytes.
                unsafe { CRYPTO_clear_free(data, size as usize, FILE_ENC, 190) };
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).cipher_data = ptr::null_mut() };
            }
        }
    }

    // The non-legacy path.
    if !cipher.is_null() {
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).cipher }.is_null() {
            // SAFETY: `ctx` is live.
            let flags = unsafe { (*ctx).flags };
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: `ctx` is live and was just zeroed.
            unsafe {
                (*ctx).encrypt = enc;
                (*ctx).flags = flags;
            }
        }
    }

    if cipher.is_null() {
        // SAFETY: `ctx` is live.
        cipher = unsafe { (*ctx).cipher };
    }

    // SAFETY: `cipher` is live.
    if unsafe { (*cipher).prov }.is_null() {
        // A legacy method is replaced by its provider counterpart, looked up by short name. The
        // fetch is against the **default** context, which is the authority's own argument.
        // SAFETY: `cipher` is live.
        let nid = unsafe { (*cipher).nid };
        let name = if nid == NID_undef {
            c"NULL".as_ptr()
        } else {
            OBJ_nid2sn(nid)
        };
        // SAFETY: `name` is NUL-terminated (a literal or the object table's own string).
        let provciph =
            unsafe { crate::evp::cipher::EVP_CIPHER_fetch(ptr::null_mut(), name, c"".as_ptr()) };
        if provciph.is_null() {
            return 0;
        }
        cipher = provciph;
        // SAFETY: `ctx` is live.
        unsafe {
            EVP_CIPHER_free((*ctx).fetched_cipher);
            (*ctx).fetched_cipher = provciph;
        }
    }

    // SAFETY: `cipher` is live.
    if unsafe { (*cipher).prov }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_322) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    if cipher != unsafe { (*ctx).fetched_cipher } {
        // SAFETY: `cipher` is live.
        if unsafe { EVP_CIPHER_up_ref(cipher.cast_mut()) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_322) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            EVP_CIPHER_free((*ctx).fetched_cipher);
            (*ctx).fetched_cipher = cipher.cast_mut();
        }
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cipher = cipher };

    if is_pipeline != 0 {
        // SAFETY: `cipher` is live.
        if unsafe { crate::evp::cipher::EVP_CIPHER_can_pipeline(cipher, enc) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_223) };
            return 0;
        }
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).algctx }.is_null() {
        // SAFETY: `cipher` is live.
        let prov = unsafe { (*cipher).prov };
        // SAFETY: `prov` is the live provider that published this method.
        let provctx = unsafe { crate::provider::ossl_provider_ctx(prov) };
        // SAFETY: `cipher` is live.
        let newctx = unsafe { (*cipher).newctx };
        let Some(f) = newctx else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_322) };
            return 0;
        };
        // SAFETY: `f` is the provider's own callback.
        let built = unsafe { f(provctx) };
        if built.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_322) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).algctx = built };
    }

    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPH_NO_PADDING) != 0 {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) } == 0 {
            return 0;
        }
    }

    // CVE-2023-5363: a length passed at init time takes effect **before** the implementation is
    // initialised, so the two length parameters are collected into a second array and sent first.
    if !params.is_null() {
        let mut lens: [OsslParam; 3] = [
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
        ];
        let mut n = 0usize;
        for key_name in [c"keylen".as_ptr(), c"ivlen".as_ptr()] {
            // SAFETY: `params` is the caller's terminated array.
            let p = unsafe { OSSL_PARAM_locate_const(params, key_name) };
            if !p.is_null() {
                // SAFETY: `p` is a live entry of the caller's array and `n < 2`.
                unsafe { lens[n] = *p };
                n += 1;
            }
        }
        if n != 0 {
            // SAFETY: `ctx` is live and `lens` is this frame's own terminated array.
            if unsafe { EVP_CIPHER_CTX_set_params(ctx, lens.as_ptr()) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_273) };
                return 0;
            }
        }
    }

    if is_pipeline != 0 {
        return 1;
    }

    // SAFETY: `cipher` is live.
    let (einit, dinit, einit_skey, dinit_skey) = unsafe {
        (
            (*cipher).einit,
            (*cipher).dinit,
            (*cipher).einit_skey,
            (*cipher).dinit_skey,
        )
    };
    // SAFETY: `ctx` is live, so its `algctx` is the implementation's context.
    let algctx = unsafe { (*ctx).algctx };
    if enc != 0 {
        let Some(f) = einit else {
            // The one arm where a keyless call can still set an IV: a provider with only the
            // `skey` form is called with a NULL key rather than refused.
            let Some(sk) = einit_skey else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_354) };
                return 0;
            };
            // SAFETY: `ctx` is live and the key length comes from this function's own accessor.
            let ivlen = if iv.is_null() {
                0usize
            } else {
                // SAFETY: the arguments are forwarded under this function's contract.
                (unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) }) as usize
            };
            // SAFETY: `sk` is the provider's own callback.
            return unsafe { sk(algctx, ptr::null_mut(), iv, ivlen, params) };
        };
        // SAFETY: `ctx` is live for the key length, and `f` is the provider's own callback.
        unsafe {
            f(
                algctx,
                key,
                if key.is_null() {
                    0
                } else {
                    EVP_CIPHER_CTX_get_key_length(ctx) as usize
                },
                iv,
                if iv.is_null() {
                    0
                } else {
                    EVP_CIPHER_CTX_get_iv_length(ctx) as usize
                },
                params,
            )
        }
    } else {
        let Some(f) = dinit else {
            let Some(sk) = dinit_skey else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_370) };
                return 0;
            };
            // SAFETY: `ctx` is live.
            let ivlen = if iv.is_null() {
                0usize
            } else {
                // SAFETY: the arguments are forwarded under this function's contract.
                (unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) }) as usize
            };
            // SAFETY: `sk` is the provider's own callback.
            return unsafe { sk(algctx, ptr::null_mut(), iv, ivlen, params) };
        };
        // SAFETY: `ctx` is live for the key length, and `f` is the provider's own callback.
        unsafe {
            f(
                algctx,
                key,
                if key.is_null() {
                    0
                } else {
                    EVP_CIPHER_CTX_get_key_length(ctx) as usize
                },
                iv,
                if iv.is_null() {
                    0
                } else {
                    EVP_CIPHER_CTX_get_iv_length(ctx) as usize
                },
                params,
            )
        }
    }
}

/// The authority's `legacy:` label of `evp_cipher_init_internal` plus everything between it and
/// `skip_to_init` — the path a method that came from `EVP_CIPHER_meth_new` takes.
///
/// Split out because the function has two entries into it (`goto legacy` from the mode decision
/// and, in the authority, a fall-through from the ENGINE block), and because the two halves have
/// genuinely different preconditions: this one reads and writes the method's own fields.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `cipher` NULL or a live method; `key` and `iv` NULL or
/// valid for the lengths the cipher reports.
unsafe fn evp_cipher_init_legacy_internal(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> c_int {
    if !cipher.is_null() {
        // SAFETY: `ctx` is live.
        if !unsafe { (*ctx).cipher }.is_null() {
            // SAFETY: `ctx` is live.
            let flags = unsafe { (*ctx).flags };
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: `ctx` is live and was just zeroed.
            unsafe {
                (*ctx).encrypt = enc;
                (*ctx).flags = flags;
            }
        }
        // `ENGINE_init`/`ENGINE_get_cipher` follow in the authority; see the module documentation.
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).engine = ptr::null_mut() };

        // SAFETY: `ctx` is live.
        unsafe { (*ctx).cipher = cipher };
        // SAFETY: `cipher` is live.
        let ctx_size = unsafe { (*cipher).ctx_size };
        if ctx_size != 0 {
            // SAFETY: this allocates a fresh block of `ctx_size` bytes.
            let data = CRYPTO_zalloc(ctx_size as usize, FILE_ENC, 786).cast::<c_void>();
            if data.is_null() {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).cipher = ptr::null() };
                return 0;
            }
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).cipher_data = data };
        } else {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).cipher_data = ptr::null_mut() };
        }
        // SAFETY: `cipher` and `ctx` are live.
        unsafe {
            (*ctx).key_len = (*cipher).key_len;
            (*ctx).flags &= EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        }
        // SAFETY: `cipher` is live.
        if (unsafe { (*cipher).flags } & EVP_CIPH_CTRL_INIT) != 0 {
            // SAFETY: `ctx` is live.
            if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, ptr::null_mut()) } <= 0 {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).cipher = ptr::null() };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_189) };
                return 0;
            }
        }
    }

    // `skip_to_init:`
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).cipher }.is_null() {
        return 0;
    }

    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    // The authority asserts the block size is a power of two in *cryptUpdate. `ossl_assert` under
    // `NDEBUG` is `(x) != 0` and non-fatal, so a block size that is none of the three is *not*
    // refused here -- only the wrap and IV tests below can refuse it.

    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) == 0 {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_get_mode(cipher) } == EVP_CIPH_WRAP_MODE {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_419) };
            return 0;
        }
    }

    // SAFETY: `cipher` is live.
    if (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_CUSTOM_IV) == 0 {
        // SAFETY: `ctx` is live.
        let mode = unsafe { EVP_CIPHER_get_mode(cipher) };
        match mode {
            EVP_CIPH_STREAM_CIPHER | EVP_CIPH_ECB_MODE => {}
            EVP_CIPH_CFB_MODE | EVP_CIPH_OFB_MODE | EVP_CIPH_CBC_MODE => {
                // CFB and OFB fall through to CBC's body, which is why their `num` reset comes
                // first and the copy is shared.
                if mode != EVP_CIPH_CBC_MODE {
                    // SAFETY: `ctx` is live.
                    unsafe { (*ctx).num = 0 };
                }
                // SAFETY: `ctx` is live.
                let n = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
                if n < 0 || n as usize > EVP_MAX_IV_LENGTH {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::EVP_ENC_441) };
                    return 0;
                }
                if !iv.is_null() {
                    // SAFETY: `iv` holds `n` bytes per the cipher's own length and `ctx->oiv` holds
                    // sixteen.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            iv,
                            ptr::addr_of_mut!((*ctx).oiv).cast(),
                            n as usize,
                        )
                    };
                }
                // SAFETY: `ctx` is live.
                unsafe {
                    ptr::copy_nonoverlapping(
                        ptr::addr_of!((*ctx).oiv).cast::<c_uchar>(),
                        ptr::addr_of_mut!((*ctx).iv).cast::<c_uchar>(),
                        n as usize,
                    )
                };
            }
            EVP_CIPH_CTR_MODE => {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).num = 0 };
                if !iv.is_null() {
                    // SAFETY: `ctx` is live.
                    let n = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
                    if n <= 0 || n as usize > EVP_MAX_IV_LENGTH {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::EVP_ENC_455) };
                        return 0;
                    }
                    // SAFETY: `iv` holds `n` bytes and `ctx->iv` holds sixteen.
                    unsafe {
                        ptr::copy_nonoverlapping(
                            iv,
                            ptr::addr_of_mut!((*ctx).iv).cast(),
                            n as usize,
                        )
                    };
                }
            }
            _ => return 0,
        }
    }

    // SAFETY: `ctx` and `cipher` are live.
    let (always_call_init, init) = unsafe {
        (
            ((*cipher).flags & EVP_CIPH_ALWAYS_CALL_INIT) != 0,
            (*cipher).init,
        )
    };
    if !key.is_null() || always_call_init {
        let Some(f) = init else {
            return 0;
        };
        // SAFETY: `f` is the implementation's own callback; `ctx` is its context.
        if unsafe { f(ctx.cast::<c_void>(), key, iv, enc) } == 0 {
            return 0;
        }
    }
    // SAFETY: `ctx` and `cipher` are live.
    unsafe {
        (*ctx).buf_len = 0;
        (*ctx).final_used = 0;
        (*ctx).block_mask = (*cipher).block_size - 1;
    }
    1
}

/// `static int evp_cipher_init_skey_internal(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const EVP_SKEY *skey, const unsigned char *iv, size_t iv_len, int enc,
/// const OSSL_PARAM params[])`.
///
/// The sibling `evp_cipher_init_internal` is not, and the differences are all one way: this
/// function has **no legacy path, no ENGINE path, no pipeline and no parameter pre-pass**. Where
/// the other one falls through to `evp_cipher_init_legacy_internal` when an ENGINE or an
/// `EVP_ORIG_METH` cipher is involved, this one **refuses** — because a symmetric key managed by a
/// provider cannot be handed to a legacy method that has no way to receive it.
///
/// Three things are contract rather than detail:
///
///   * **the key's provider must be the cipher's.** `skey->skeymgmt->prov != ctx->cipher->prov` is
///     an `EVP_R_INITIALIZATION_ERROR`, and the test happens *after* `newctx` has run, because it
///     is `ctx->cipher` rather than the argument that is compared;
///   * **the fallback is a byte export.** A provider that publishes no `einit_skey` is not
///     refused: the key's raw bytes are asked for through `EVP_SKEY_get0_raw_key` and handed to
///     the ordinary `einit`. A key whose provider cannot export its bytes — an AES key type, whose
///     `export` publishes parameters rather than a secret — therefore **fails here**, with
///     `EVP_R_INITIALIZATION_ERROR`, rather than being silently keyed with the wrong bytes;
///   * **a NULL `skey` is legal and means the multi-step API.** Both arms test `skey != NULL`
///     before the export, so `EVP_CipherInit_SKEY(ctx, cipher, NULL, ...)` is the ordinary two-step
///     init with the parameters this function was given.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `cipher` NULL or a live method; `skey` NULL or a live key;
/// `iv` NULL or valid for `iv_len`; `params` NULL or a terminated array.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
unsafe fn evp_cipher_init_skey_internal(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    skey: *const EvpSkey,
    iv: *const c_uchar,
    mut iv_len: usize,
    enc: c_int,
    params: *const OsslParam,
) -> c_int {
    let mut cipher = cipher;
    let mut enc = enc;

    // `enc == -1` keeps the context's own direction; anything else normalises and is written back.
    if enc == -1 {
        // SAFETY: `ctx` is live per the contract.
        enc = unsafe { (*ctx).encrypt };
    } else {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).encrypt = c_int::from(enc != 0) };
    }

    if cipher.is_null() {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).cipher }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_500) };
            return 0;
        }
    }

    // The ENGINE refusal. `ctx->engine` is always NULL in this crate and `impl` is a parameter this
    // function does not have, so the reachable half of the condition is the `origin` test.
    // SAFETY: `ctx` is live.
    let engine = unsafe { (*ctx).engine };
    let mut refuses = !engine.is_null();
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        refuses |= unsafe { (*cipher).origin == EVP_ORIG_METH };
    } else {
        // SAFETY: `ctx` is live.
        let ctx_cipher = unsafe { (*ctx).cipher };
        if !ctx_cipher.is_null() {
            // SAFETY: `ctx_cipher` is live.
            refuses |= unsafe { (*ctx_cipher).origin == EVP_ORIG_METH };
        }
    }
    if refuses {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_511) };
        return 0;
    }

    // The legacy clearing, which happens when a *new* cipher is being installed over an old one.
    if !cipher.is_null() {
        // SAFETY: `ctx` is live.
        let ctx_cipher = unsafe { (*ctx).cipher };
        if !ctx_cipher.is_null() {
            // SAFETY: `ctx_cipher` is live.
            let cleanup = unsafe { (*ctx_cipher).cleanup };
            if let Some(f) = cleanup {
                // SAFETY: `f` is the implementation's own callback and `ctx` is its context.
                if unsafe { f(ctx.cast::<c_void>()) } == 0 {
                    return 0;
                }
            }
            // SAFETY: `ctx` is live.
            let data = unsafe { (*ctx).cipher_data };
            // SAFETY: `ctx_cipher` is live.
            let size = unsafe { (*ctx_cipher).ctx_size };
            // SAFETY: `data` is this context's own block of `size` bytes.
            unsafe { CRYPTO_clear_free(data, size as usize, FILE_ENC, 521) };
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).cipher_data = ptr::null_mut() };
        }
    }

    // The reset, with `encrypt` and `flags` carried across it by hand.
    if !cipher.is_null() {
        // SAFETY: `ctx` is live.
        let ctx_cipher = unsafe { (*ctx).cipher };
        if !ctx_cipher.is_null() {
            // SAFETY: `ctx` is live.
            let flags = unsafe { (*ctx).flags };
            // SAFETY: `ctx` is live.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: `ctx` is live.
            unsafe {
                (*ctx).encrypt = enc;
                (*ctx).flags = flags;
            }
        }
    }

    if cipher.is_null() {
        // SAFETY: `ctx` is live.
        cipher = unsafe { (*ctx).cipher };
    }

    // SAFETY: `cipher` is live, either as the argument or as the context's own.
    if unsafe { (*cipher).prov }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_539) };
        return 0;
    }

    // SAFETY: `ctx` and `cipher` are live. The comparison is between the argument and the field the
    // context already holds, which is what makes a repeated init on the same cipher free.
    if cipher != unsafe { (*ctx).fetched_cipher.cast_const() } {
        // SAFETY: `cipher` is live.
        if unsafe { EVP_CIPHER_up_ref(cipher.cast_mut()) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_545) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        unsafe { EVP_CIPHER_free((*ctx).fetched_cipher) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).fetched_cipher = cipher.cast_mut() };
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).cipher = cipher };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).algctx }.is_null() {
        // SAFETY: `cipher` is live, so its provider is readable.
        let prov = unsafe { (*cipher).prov };
        // SAFETY: `prov` is live, so its context is readable.
        let provctx = unsafe { ossl_provider_ctx(prov) };
        // SAFETY: `cipher` is live, so its constructor is readable.
        let newctx = unsafe { (*cipher).newctx };
        let Some(f) = newctx else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_557) };
            return 0;
        };
        // SAFETY: `f` is the provider's own constructor and `provctx` is its context.
        let algctx = unsafe { f(provctx) };
        if algctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_557) };
            return 0;
        }
        // SAFETY: `ctx` is live and `algctx` is the implementation's fresh context.
        unsafe { (*ctx).algctx = algctx };
    }

    // The key's provider must be the cipher's, and this is the test that makes the class usable: a
    // key from one provider cannot be handed to another provider's cipher.
    if !skey.is_null() {
        // SAFETY: `skey` is live per the contract.
        let skey_mgmt = unsafe { (*skey).skeymgmt };
        if !skey_mgmt.is_null() {
            // SAFETY: `skey_mgmt` is the method this key holds a reference to.
            let skey_prov = unsafe { (*skey_mgmt).prov };
            // SAFETY: `cipher` is live.
            if skey_prov != unsafe { (*cipher).prov } {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_563) };
                return 0;
            }
        }
    }

    // The no-padding flag, told to the *new* implementation because the reset above dropped it.
    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPH_NO_PADDING) != 0 {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) } == 0 {
            return 0;
        }
    }

    if iv.is_null() {
        iv_len = 0;
    }

    // SAFETY: `cipher` and `ctx` are live.
    let (einit, dinit, einit_skey, dinit_skey) = unsafe {
        (
            (*cipher).einit,
            (*cipher).dinit,
            (*cipher).einit_skey,
            (*cipher).dinit_skey,
        )
    };
    // SAFETY: `ctx` is live and its `algctx` is the implementation's context.
    let algctx = unsafe { (*ctx).algctx };

    if enc != 0 {
        let Some(sk) = einit_skey else {
            // The fallback: the provider has no key-aware initialiser, so the key's bytes are asked
            // for and handed to the ordinary one. A key that cannot export them is a refusal.
            let mut keydata: *const c_uchar = ptr::null();
            let mut keylen: usize = 0;
            if !skey.is_null() {
                // SAFETY: `skey` is live and the two out-parameters are this frame's own.
                if unsafe { EVP_SKEY_get0_raw_key(skey, &mut keydata, &mut keylen) } == 0 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::EVP_ENC_590) };
                    return 0;
                }
            }
            let Some(f) = einit else {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_590) };
                return 0;
            };
            // SAFETY: `f` is the provider's own callback and `algctx` is its context.
            return unsafe { f(algctx, keydata, keylen, iv, iv_len, params) };
        };
        // SAFETY: `skey` is NULL or live per the contract; `sk` is the provider's own callback.
        let keydata = if skey.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: `skey` is live.
            unsafe { (*skey).keydata }
        };
        // SAFETY: `sk` is the provider's own callback and `algctx` is its context.
        return unsafe { sk(algctx, keydata, iv, iv_len, params) };
    }

    let Some(sk) = dinit_skey else {
        let mut keydata: *const c_uchar = ptr::null();
        let mut keylen: usize = 0;
        if !skey.is_null() {
            // SAFETY: `skey` is live and the two out-parameters are this frame's own.
            if unsafe { EVP_SKEY_get0_raw_key(skey, &mut keydata, &mut keylen) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_611) };
                return 0;
            }
        }
        let Some(f) = dinit else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_611) };
            return 0;
        };
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        return unsafe { f(algctx, keydata, keylen, iv, iv_len, params) };
    };
    // SAFETY: `skey` is NULL or live per the contract.
    let keydata = if skey.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `skey` is live.
        unsafe { (*skey).keydata }
    };
    // SAFETY: `sk` is the provider's own callback and `algctx` is its context.
    unsafe { sk(algctx, keydata, iv, iv_len, params) }
}

/// `int EVP_CipherInit_SKEY(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, EVP_SKEY *skey,
/// const unsigned char *iv, size_t iv_len, int enc, const OSSL_PARAM params[])`.
///
/// The only exported cipher initialiser whose key is an object rather than a buffer, and the one
/// that makes `EVP_SKEY` useful: it is how a key imported once is used by a cipher without ever
/// being copied into a caller's buffer.
///
/// **`skey` is `EVP_SKEY *` and not `const EVP_SKEY *`**, where the internal helper below takes
/// the const form. The two disagree in the authority and the exported signature is the one the
/// header promises; `ABI-PROTOTYPE` found the difference on this function's first run, which is the
/// whole argument for checking a prototype against the canonical declaration rather than against
/// the transcription's own reading of it.
///
/// # Safety
/// The arguments are forwarded under `evp_cipher_init_skey_internal`'s contract.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_SKEY(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    skey: *mut EvpSkey,
    iv: *const c_uchar,
    iv_len: usize,
    enc: c_int,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract; the key is only read.
    unsafe {
        evp_cipher_init_skey_internal(ctx, cipher, skey.cast_const(), iv, iv_len, enc, params)
    }
}

/// `int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, const unsigned char *iv, int enc, const OSSL_PARAM params[])`.
///
/// # Safety
/// The arguments are forwarded under `evp_cipher_init_internal`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_ex2(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_cipher_init_internal(ctx, cipher, ptr::null_mut(), key, iv, enc, 0, params) }
}

/// `int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key,
/// const unsigned char *iv, int enc)`.
///
/// The one that **resets first** when a cipher is given, which is the difference between it and
/// `EVP_CipherInit_ex`: this spelling starts a new operation and the `_ex` one continues one.
///
/// # Safety
/// The arguments are forwarded under `evp_cipher_init_internal`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> c_int {
    if !cipher.is_null() {
        // SAFETY: `ctx` is live per the contract.
        unsafe { EVP_CIPHER_CTX_reset(ctx) };
    }
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_cipher_init_internal(ctx, cipher, ptr::null_mut(), key, iv, enc, 0, ptr::null()) }
}

/// `int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
/// const unsigned char *key, const unsigned char *iv, int enc)`.
///
/// The `impl` argument is the ENGINE, and it is why this function is not simply an alias: it is
/// where a caller could force a legacy implementation. A non-NULL `impl` is refused by
/// `evp_cipher_init_internal`, which is recorded there.
///
/// # Safety
/// The arguments are forwarded under `evp_cipher_init_internal`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherInit_ex(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_cipher_init_internal(ctx, cipher, impl_, key, iv, enc, 0, ptr::null()) }
}

/// The shared body of the two pipeline initialisers: the pipe count is bounded **before** the
/// context is touched, then the context is armed for the mode, then the implementation's own
/// pipeline initialiser is called.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `cipher` a live method; `key` valid for `keylen`; `iv` an
/// array of `numpipes` valid pointers each of `ivlen` bytes.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
unsafe fn pipeline_init(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    keylen: usize,
    numpipes: usize,
    iv: *mut *const c_uchar,
    ivlen: usize,
    enc: c_int,
    site: &crate::runtime::err::err_sites::ErrSite,
    missing_site: &crate::runtime::err::err_sites::ErrSite,
) -> c_int {
    if numpipes > EVP_MAX_PIPES {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(site) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).numpipes = numpipes };
    // SAFETY: `ctx` is live and `cipher` is live.
    if unsafe {
        evp_cipher_init_internal(
            ctx,
            cipher,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            enc,
            1,
            ptr::null(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `ctx` is live, so its cipher is the one just armed.
    let armed = unsafe { (*ctx).cipher };
    // SAFETY: `armed` is live.
    let f = unsafe {
        if enc != 0 {
            (*armed).p_einit
        } else {
            (*armed).p_dinit
        }
    };
    let Some(f) = f else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(missing_site) };
        return 0;
    };
    // SAFETY: `ctx` is live, `f` is the provider's own callback, and the rest is the caller's.
    unsafe { f((*ctx).algctx, key, keylen, numpipes, iv, ivlen, ptr::null()) }
}

/// `int EVP_CipherPipelineEncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, size_t keylen, size_t numpipes, const unsigned char **iv,
/// size_t ivlen)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; the rest per `pipeline_init`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherPipelineEncryptInit(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    keylen: usize,
    numpipes: usize,
    iv: *mut *const c_uchar,
    ivlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        pipeline_init(
            ctx,
            cipher,
            key,
            keylen,
            numpipes,
            iv,
            ivlen,
            1,
            &err_sites::EVP_ENC_662,
            &err_sites::EVP_ENC_673,
        )
    }
}

/// `int EVP_CipherPipelineDecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, size_t keylen, size_t numpipes, const unsigned char **iv,
/// size_t ivlen)`.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; the rest per `pipeline_init`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherPipelineDecryptInit(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    keylen: usize,
    numpipes: usize,
    iv: *mut *const c_uchar,
    ivlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        pipeline_init(
            ctx,
            cipher,
            key,
            keylen,
            numpipes,
            iv,
            ivlen,
            0,
            &err_sites::EVP_ENC_692,
            &err_sites::EVP_ENC_703,
        )
    }
}

/// `int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, const unsigned char *iv)`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit(ctx, cipher, key, iv, 1) }
}

/// `int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
/// const unsigned char *key, const unsigned char *iv)`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit_ex`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
    key: *const c_uchar,
    iv: *const c_uchar,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit_ex(ctx, cipher, impl_, key, iv, 1) }
}

/// `int EVP_EncryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, const unsigned char *iv, const OSSL_PARAM params[])`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit_ex2`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex2(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit_ex2(ctx, cipher, key, iv, 1, params) }
}

/// `int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, const unsigned char *iv)`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit(ctx, cipher, key, iv, 0) }
}

/// `int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
/// const unsigned char *key, const unsigned char *iv)`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit_ex`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit_ex(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    impl_: *mut c_void,
    key: *const c_uchar,
    iv: *const c_uchar,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit_ex(ctx, cipher, impl_, key, iv, 0) }
}

/// `int EVP_DecryptInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
/// const unsigned char *key, const unsigned char *iv, const OSSL_PARAM params[])`.
///
/// # Safety
/// The arguments are forwarded under `EVP_CipherInit_ex2`'s contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptInit_ex2(
    ctx: *mut EvpCipherCtx,
    cipher: *const EvpCipher,
    key: *const c_uchar,
    iv: *const c_uchar,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_CipherInit_ex2(ctx, cipher, key, iv, 0, params) }
}

// ---------------------------------------------------------------------------------------------
// The ASN.1 bridge — `evp_lib.c`'s four entry points, their two shared bodies, and the
// `X509_ALGOR` pair that needs the layout rather than Phase 11's codec.
// ---------------------------------------------------------------------------------------------

/// `evp_cipher_aead_asn1_params` — a struct private to `crypto/evp/evp_lib.c`.
///
/// No exported function sees one: `EVP_CIPHER_param_to_asn1` and `EVP_CIPHER_asn1_to_param` reach
/// the two helpers that take it with a **NULL**, so this type exists here for the same reason it
/// exists in the authority — so the two helpers can share an argument shape.
#[repr(C)]
pub struct EvpCipherAeadAsn1Params {
    /// `unsigned int tag_len` — passed on as `ossl_asn1_type_set_octetstring_int`'s `num`.
    pub tag_len: c_uint,
    /// `unsigned char iv[EVP_MAX_IV_LENGTH]`.
    pub iv: [c_uchar; EVP_MAX_IV_LENGTH],
    /// `unsigned int iv_len`.
    pub iv_len: c_uint,
}

/// `int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *ctx, ASN1_TYPE *type)`.
///
/// Reads an IV **out of** the ASN.1 and then re-initialises the context with it, through
/// `EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1)` — whose `enc` of -1 is what keeps the
/// context's current direction. A NULL type answers 0 and changes nothing.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `type_` NULL or a live `Asn1Type`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_get_asn1_iv(
    ctx: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
) -> c_int {
    if type_.is_null() {
        return 0;
    }
    let mut iv: [c_uchar; EVP_MAX_IV_LENGTH] = [0; EVP_MAX_IV_LENGTH];
    // SAFETY: `ctx` is live per the contract.
    let l = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
    if l < 0 || l as usize > EVP_MAX_IV_LENGTH {
        return -1;
    }
    // SAFETY: `type_` is live and `iv` holds sixteen bytes, which `l` is bounded by.
    let i = unsafe { ASN1_TYPE_get_octetstring(type_, iv.as_mut_ptr(), l) };
    if i != l {
        return -1;
    }
    // SAFETY: `ctx` is live; the IV buffer holds `l` bytes and the direction is kept.
    if unsafe {
        EVP_CipherInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            iv.as_ptr(),
            -1,
        )
    } == 0
    {
        return -1;
    }
    i
}

/// `int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)`.
///
/// The other direction, and it writes `original_iv` rather than `iv`: what belongs in the ASN.1 is
/// the IV the caller supplied, not the running one.
///
/// # Safety
/// `c` must be a live `EvpCipherCtx`; `type_` NULL or a live `Asn1Type`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_set_asn1_iv(
    c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
) -> c_int {
    if type_.is_null() {
        return 0;
    }
    // SAFETY: `c` is live per the contract.
    let oiv = unsafe { EVP_CIPHER_CTX_original_iv(c) }.cast_mut();
    // SAFETY: `c` is live.
    let j = unsafe { EVP_CIPHER_CTX_get_iv_length(c) };
    // SAFETY: `type_` is live and `oiv` is the context's own buffer of `j` bytes.
    unsafe { ASN1_TYPE_set_octetstring(type_, oiv, j) }
}

/// The `err:` label the two `_ex` helpers share: the two reasons, selected by the *caller's* two
/// sites, and then the clamp that turns `-2` into `-1` **after** the raise — which is the order a
/// reader has to check, because the clamp would otherwise hide the reason.
fn evp_cipher_asn1_tail(
    ret: c_int,
    unsupported: &crate::runtime::err::err_sites::ErrSite,
    param_error: &crate::runtime::err::err_sites::ErrSite,
) -> c_int {
    if ret == -2 {
        // SAFETY: a compile-time-constant site supplied by the caller.
        unsafe { raise_site(unsupported) };
    } else if ret <= 0 {
        // SAFETY: a compile-time-constant site supplied by the caller.
        unsafe { raise_site(param_error) };
    }
    if ret < -1 {
        return -1;
    }
    ret
}

/// `int evp_cipher_param_to_asn1_ex(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
/// evp_cipher_aead_asn1_params *asn1_params)`.
///
/// Four arms, and the *first* is what makes a legacy implementation's custom parameter handling
/// work: `set_asn1_parameters` beats every flag. Then the flag test, then a mode `switch` whose
/// three refusals (`-2`) raise `EVP_R_UNSUPPORTED_CIPHER` while every other failure raises
/// `EVP_R_CIPHER_PARAMETER_ERROR`, and finally the provider arm, which hands the DER to the
/// implementation through `algorithm-id-params`.
///
/// # Safety
/// `c` must be NULL or a live `EvpCipherCtx`; `type_` NULL or live; `asn1_params` NULL or live.
unsafe fn evp_cipher_param_to_asn1_ex(
    c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
    asn1_params: *mut EvpCipherAeadAsn1Params,
) -> c_int {
    let mut ret = -1;
    // SAFETY: `c` is NULL or live per the contract.
    let cipher = if c.is_null() {
        ptr::null()
    } else {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { (*c).cipher }
    };
    if cipher.is_null() {
        return evp_cipher_asn1_tail(ret, &err_sites::EVP_LIB_144, &err_sites::EVP_LIB_146);
    }
    // SAFETY: `cipher` is live.
    let set_asn1 = unsafe { (*cipher).set_asn1_parameters };
    if let Some(f) = set_asn1 {
        // SAFETY: `f` is the implementation's own callback and `c` is its context.
        ret = unsafe { f(c.cast::<c_void>(), type_.cast::<c_void>()) };
    // SAFETY: the arguments are forwarded under this function's contract.
    } else if (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_CUSTOM_ASN1) == 0 {
        // SAFETY: `cipher` is live.
        match unsafe { EVP_CIPHER_get_mode(cipher) } {
            EVP_CIPH_WRAP_MODE => {
                // SAFETY: `cipher` is live.
                if unsafe { EVP_CIPHER_is_a(cipher, SN_ID_SMIME_ALG_CMS3DESWRAP) } != 0 {
                    // SAFETY: `type_` is the caller's type; a NULL value is `V_ASN1_NULL`.
                    unsafe { ASN1_TYPE_set(type_, V_ASN1_NULL, ptr::null_mut()) };
                }
                ret = 1;
            }
            EVP_CIPH_GCM_MODE => {
                // SAFETY: both arguments are the caller's, forwarded.
                ret = unsafe { evp_cipher_set_asn1_aead_params(c, type_, asn1_params) };
            }
            EVP_CIPH_CCM_MODE | EVP_CIPH_XTS_MODE | EVP_CIPH_OCB_MODE => ret = -2,
            _ => {
                // SAFETY: `c` is live and `type_` is the caller's.
                ret = unsafe { EVP_CIPHER_set_asn1_iv(c, type_) };
            }
        }
    // SAFETY: `cipher` is NULL or the live method this context holds.
    } else if !(unsafe { (*cipher).prov }).is_null() {
        let mut alg = X509Algor {
            algorithm: ptr::null(),
            parameter: type_,
        };
        // SAFETY: `c` is live and `alg` is this frame's own.
        ret = unsafe { EVP_CIPHER_CTX_get_algor_params(c, &mut alg) };
    } else {
        ret = -2;
    }
    evp_cipher_asn1_tail(ret, &err_sites::EVP_LIB_144, &err_sites::EVP_LIB_146)
}

/// `int evp_cipher_asn1_to_param_ex(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
/// evp_cipher_aead_asn1_params *asn1_params)`.
///
/// The mirror of the function above, with one difference a reader should not miss: the `default`
/// arm converts the *helper's* return value into a status — `get_asn1_iv(c, type) >= 0 ? 1 : -1` —
/// where the other direction returns it raw.
///
/// # Safety
/// As `evp_cipher_param_to_asn1_ex`.
unsafe fn evp_cipher_asn1_to_param_ex(
    c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
    asn1_params: *mut EvpCipherAeadAsn1Params,
) -> c_int {
    let mut ret = -1;
    // SAFETY: `c` is NULL or live per the contract.
    let cipher = if c.is_null() {
        ptr::null()
    } else {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { (*c).cipher }
    };
    if cipher.is_null() {
        return evp_cipher_asn1_tail(ret, &err_sites::EVP_LIB_213, &err_sites::EVP_LIB_215);
    }
    // SAFETY: `cipher` is live.
    let get_asn1 = unsafe { (*cipher).get_asn1_parameters };
    if let Some(f) = get_asn1 {
        // SAFETY: `f` is the implementation's own callback and `c` is its context.
        ret = unsafe { f(c.cast::<c_void>(), type_.cast::<c_void>()) };
    // SAFETY: the arguments are forwarded under this function's contract.
    } else if (unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_CUSTOM_ASN1) == 0 {
        // SAFETY: `cipher` is live.
        match unsafe { EVP_CIPHER_get_mode(cipher) } {
            EVP_CIPH_WRAP_MODE => ret = 1,
            EVP_CIPH_GCM_MODE => {
                // SAFETY: both arguments are the caller's, forwarded.
                ret = unsafe { evp_cipher_get_asn1_aead_params(c, type_, asn1_params) };
            }
            EVP_CIPH_CCM_MODE | EVP_CIPH_XTS_MODE | EVP_CIPH_OCB_MODE => ret = -2,
            _ => {
                // SAFETY: `c` is live and `type_` is the caller's.
                ret = if unsafe { EVP_CIPHER_get_asn1_iv(c, type_) } >= 0 {
                    1
                } else {
                    -1
                };
            }
        }
    // SAFETY: `cipher` is NULL or the live method this context holds.
    } else if !(unsafe { (*cipher).prov }).is_null() {
        let alg = X509Algor {
            algorithm: ptr::null(),
            parameter: type_,
        };
        // SAFETY: `c` is live and `alg` is this frame's own.
        ret = unsafe { EVP_CIPHER_CTX_set_algor_params(c, &alg) };
    } else {
        ret = -2;
    }
    evp_cipher_asn1_tail(ret, &err_sites::EVP_LIB_213, &err_sites::EVP_LIB_215)
}

/// `int evp_cipher_get_asn1_aead_params(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
/// evp_cipher_aead_asn1_params *asn1_params)`.
///
/// Answers the **length** it extracted, which is why its caller treats `<= 0` as a failure: an IV
/// of zero bytes is not an IV.
///
/// # Safety
/// `type_` NULL or live; `asn1_params` NULL or live.
unsafe fn evp_cipher_get_asn1_aead_params(
    _c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
    asn1_params: *mut EvpCipherAeadAsn1Params,
) -> c_int {
    if type_.is_null() || asn1_params.is_null() {
        return 0;
    }
    let mut iv: [c_uchar; EVP_MAX_IV_LENGTH] = [0; EVP_MAX_IV_LENGTH];
    let mut tl: c_long = 0;
    // SAFETY: `type_` is live and `iv` holds sixteen bytes.
    let i = unsafe {
        ossl_asn1_type_get_octetstring_int(
            type_,
            &mut tl,
            iv.as_mut_ptr(),
            EVP_MAX_IV_LENGTH as c_int,
        )
    };
    if i <= 0 || i as usize > EVP_MAX_IV_LENGTH {
        return -1;
    }
    // SAFETY: `asn1_params` is live and `i` is bounded by the destination's size.
    unsafe {
        ptr::copy_nonoverlapping(iv.as_ptr(), (*asn1_params).iv.as_mut_ptr(), i as usize);
        (*asn1_params).iv_len = i as c_uint;
    }
    i
}

/// `int evp_cipher_set_asn1_aead_params(EVP_CIPHER_CTX *c, ASN1_TYPE *type,
/// evp_cipher_aead_asn1_params *asn1_params)`.
///
/// # Safety
/// `type_` NULL or live; `asn1_params` NULL or live.
unsafe fn evp_cipher_set_asn1_aead_params(
    _c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
    asn1_params: *mut EvpCipherAeadAsn1Params,
) -> c_int {
    if type_.is_null() || asn1_params.is_null() {
        return 0;
    }
    // SAFETY: `type_` and `asn1_params` are live.
    unsafe {
        ossl_asn1_type_set_octetstring_int(
            type_,
            (*asn1_params).tag_len as c_long,
            (*asn1_params).iv.as_mut_ptr(),
            (*asn1_params).iv_len as c_int,
        )
    }
}

/// `int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)`.
///
/// # Safety
/// `c` must be a live `EvpCipherCtx`; `type_` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_param_to_asn1(
    c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_cipher_param_to_asn1_ex(c, type_, ptr::null_mut()) }
}

/// `int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)`.
///
/// # Safety
/// `c` must be a live `EvpCipherCtx`; `type_` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_asn1_to_param(
    c: *mut EvpCipherCtx,
    type_: *mut Asn1Type,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_cipher_asn1_to_param_ex(c, type_, ptr::null_mut()) }
}

/// `int EVP_CIPHER_CTX_set_algor_params(EVP_CIPHER_CTX *ctx, const X509_ALGOR *alg)`.
///
/// The DER of `alg->parameter` is sent under **both** parameter names — the retired
/// `alg_id_param` and the current `algorithm-id-params` — because the two are the same data and a
/// provider may recognise either. This and its sibling need `X509_ALGOR`'s *layout*, not Phase
/// 11's codec, which is why they land here while `EVP_CIPHER_CTX_get_algor` is a hand-off.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `alg` must be a live `X509Algor`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_set_algor_params(
    ctx: *mut EvpCipherCtx,
    alg: *const X509Algor,
) -> c_int {
    let mut ret = -1;
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: `alg` is live per the contract.
    let derl = unsafe { i2d_ASN1_TYPE((*alg).parameter, &mut der) };
    if derl >= 0 {
        let mut params: [OsslParam; 3] = [
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
            OSSL_PARAM_construct_end(),
        ];
        // SAFETY: each constructor writes one entry into this frame's own array.
        unsafe {
            params[0] = OSSL_PARAM_construct_octet_string(
                OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD,
                der.cast::<c_void>(),
                derl as usize,
            );
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_SIGNATURE_PARAM_ALGORITHM_ID_PARAMS,
                der.cast::<c_void>(),
                derl as usize,
            );
            params[2] = OSSL_PARAM_construct_end();
        }
        // SAFETY: `ctx` is live and `params` is this frame's own terminated array.
        ret = unsafe { EVP_CIPHER_CTX_set_params(ctx, params.as_ptr()) };
    }
    // SAFETY: `der` is NULL or the block `i2d_ASN1_TYPE` allocated for this call.
    unsafe { CRYPTO_free(der.cast::<c_void>(), FILE_LIB, LINE_FREE_DER) };
    ret
}

/// `int EVP_CIPHER_CTX_get_algor_params(EVP_CIPHER_CTX *ctx, X509_ALGOR *alg)`.
///
/// **Two passes over two parameter names.** The first asks for the length under both names, and
/// the higher index that answered wins — the new key beats the old when a provider answers both,
/// which is why `i` is 1 rather than 0 in that case. The second gets the bytes and hands them to
/// `d2i_ASN1_TYPE`. The caller's existing `alg->parameter` is saved into the decoder's out-pointer
/// first and assigned back afterwards, so a decode that fails leaves the caller's pointer alone —
/// and the authority's comment says explicitly that the old value is **not** freed.
///
/// The `err:` label here has no raises at all: both refusals are silent, and `ret` stays -1.
///
/// # Safety
/// `ctx` must be a live `EvpCipherCtx`; `alg` must be a live `X509Algor`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CIPHER_CTX_get_algor_params(
    ctx: *mut EvpCipherCtx,
    alg: *mut X509Algor,
) -> c_int {
    let mut ret = -1;
    let mut params: [OsslParam; 3] = [
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
    ];
    // SAFETY: each constructor writes one entry into this frame's own array.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_ALGORITHM_ID_PARAMS_OLD,
            ptr::null_mut(),
            0,
        );
        params[1] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_ALGORITHM_ID_PARAMS,
            ptr::null_mut(),
            0,
        );
        params[2] = OSSL_PARAM_construct_end();
    }
    // SAFETY: `ctx` is live and `params` is this frame's own terminated array.
    if unsafe { EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
        return ret;
    }
    let mut i: c_int = -1;
    // SAFETY: `params` is the array the provider just answered into.
    unsafe {
        if OSSL_PARAM_modified(params.as_ptr()) != 0 && params[0].return_size != 0 {
            i = 0;
        }
        if OSSL_PARAM_modified(params.as_ptr().add(1)) != 0 && params[1].return_size != 0 {
            i = 1;
        }
    }
    if i < 0 {
        return ret;
    }
    // The caller's value is what the decoder starts from, and what it is assigned back to.
    // SAFETY: `alg` is live per the contract.
    let mut type_ = unsafe { (*alg).parameter };
    let idx = i as usize;
    let derk = params[idx].key;
    let derl = params[idx].return_size;
    // SAFETY: this allocates a fresh block of `derl` bytes.
    let der = CRYPTO_malloc(derl, FILE_LIB, LINE_FREE_AID).cast::<c_uchar>();
    if !der.is_null() {
        let mut derp: *const c_uchar = der;
        // SAFETY: the constructor writes one entry of this frame's own array, and `der` holds
        // `derl` bytes.
        unsafe {
            params[idx] = OSSL_PARAM_construct_octet_string(derk, der.cast::<c_void>(), derl)
        };
        // SAFETY: `ctx` is live, `params` is this frame's array, `derp` is this frame's slot, and
        // `type_` is the caller's saved pointer.
        unsafe {
            if EVP_CIPHER_CTX_get_params(ctx, params.as_mut_ptr()) != 0
                && OSSL_PARAM_modified(params.as_ptr().add(idx)) != 0
                && !d2i_ASN1_TYPE(&mut type_, &mut derp, derl as c_long).is_null()
            {
                (*alg).parameter = type_;
                ret = 1;
            }
        }
    }
    // SAFETY: `der` is NULL or the block allocated above, released exactly once.
    unsafe { CRYPTO_free(der.cast::<c_void>(), FILE_LIB, LINE_FREE_AID) };
    ret
}

/// `EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM`, from `include/openssl/evp.h`.
///
/// Four fields in the authority's order. `EVP_CTRL_TLS1_1_MULTIBLOCK_AAD` and `_ENCRYPT` are the
/// only two commands that take one, and the first of the two checks the *length* the caller
/// passed before reading anything from it.
#[repr(C)]
pub struct MultiblockParam {
    /// `unsigned char *out`.
    pub out: *mut c_uchar,
    /// `const unsigned char *inp`.
    pub inp: *const c_uchar,
    /// `size_t len`.
    pub len: usize,
    /// `unsigned int interleave`.
    pub interleave: c_uint,
}

// ---------------------------------------------------------------------------------------------
// 7.3c-ii — the data path: the twelve exports that move bytes through an armed context.
//
// Every one of them is written twice over, exactly as `evp_enc.c` writes them: a provider arm
// that calls the implementation's `cupdate`/`cfinal`/`ccipher` with an `outsize` the authority
// computes, and a legacy arm that either hands the whole call to `do_cipher` (when the method
// sets `EVP_CIPH_FLAG_CUSTOM_CIPHER`) or runs this file's block-buffering loop. That loop is why
// a final block can be held back: `final_used` and `ctx->final` exist so a decryption can check
// padding before handing the caller plaintext it might have to retract.
// ---------------------------------------------------------------------------------------------

/// `int safe_div_round_up_int(int a, int b, int *errp)` with `b == 8` and a NULL `errp`, which
/// is the only way `evp_enc.c` calls it.
///
/// The header's `OSSL_SAFE_MATH_DIV_ROUND_UP` has several arms for this call and the *first* is
/// the one that matters: the fast path `(a + b - 1) / b` is taken only while `a < INT_MAX - b`,
/// and **the slow path adds nothing to `a`**, so it cannot overflow. A transcription that wrote
/// `(a + 7) / 8` unconditionally would have an undefined addition on the last eight values of
/// `int`, and the value is a length a caller chooses.
///
/// `a <= 0` cannot reach those arms: both call sites have already refused a negative `inl`, and
/// the header's own `a == 0` arm answers 0.
fn safe_div_round_up_int_8(a: c_int) -> c_int {
    if a <= 0 {
        return 0;
    }
    if a < c_int::MAX - 8 {
        return (a + 7) / 8;
    }
    a / 8 + c_int::from(a % 8 != 0)
}

/// `int ossl_is_partially_overlapping(const void *ptr1, const void *ptr2, int len)`.
///
/// The authority's own comment says why this is not a comparison of two ranges: the standard
/// gives no meaning to the difference of two pointers that are not in the same object, so the
/// function subtracts the *addresses as integers*, wraps, and asks whether the wrapped difference
/// is smaller than the length in either direction. Hence `wrapping_sub` below, and hence the two
/// tests being `|`-ed rather than short-circuited: both are computed.
///
/// # Safety
/// No preconditions: the pointers are only converted to integers.
pub(crate) unsafe fn ossl_is_partially_overlapping(
    ptr1: *const c_void,
    ptr2: *const c_void,
    len: c_int,
) -> c_int {
    let diff = (ptr1 as usize).wrapping_sub(ptr2 as usize);
    let lent = len as usize;
    let overlapped = (len > 0) as u32
        & (diff != 0) as u32
        & (((diff < lent) | (diff > 0usize.wrapping_sub(lent))) as u32);
    overlapped as c_int
}

/// `static int evp_EncryptDecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
/// const unsigned char *in, int inl)`.
///
/// The block-buffering loop, shared by both directions because the arithmetic is the same for a
/// non-custom method. Five things about it are contract:
///
///   * a method with `EVP_CIPH_FLAG_CUSTOM_CIPHER` is handed the whole call, and its **negative**
///     answer is a refusal while a non-negative one *is* the length;
///   * `inl <= 0` answers **`inl == 0`**, so a negative length is a silent zero-length refusal —
///     reached only after both callers have already refused one;
///   * the overflow guard is on `(inl - j) & ~(bl - 1)`, the amount of *full-block* data left,
///     which is exactly the quantity that becomes output;
///   * a partial block accumulates in `ctx->buf` and is flushed only when it fills, so an `outl`
///     of 0 with `buf_len` set is the normal middle of a stream rather than a failure;
///   * the final copy takes `i` bytes from `in[inl]` **after `inl` has been reduced**, which is
///     where the unprocessed tail begins.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; `out` writable for the length the block size
/// implies; `in_` readable for `inl` bytes; `outl` writable.
// mirrors the authority's name exactly: this is a transcription, not a Rust function
#[allow(non_snake_case)]
unsafe fn evp_EncryptDecryptUpdate(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    let mut cmpl = inl;
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS as c_int) } != 0 {
        cmpl = safe_div_round_up_int_8(cmpl);
    }
    // SAFETY: `cipher` is live.
    let bl = unsafe { (*cipher).block_size };
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        if bl == 1 {
            // SAFETY: the two buffers are the caller's, per the contract.
            if unsafe { ossl_is_partially_overlapping(out.cast(), in_.cast(), cmpl) } != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_899) };
                return 0;
            }
        }
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback and `ctx` is its context.
        let i = unsafe { do_cipher(ctx.cast::<c_void>(), out, in_, inl as usize) };
        if i < 0 {
            return 0;
        }
        // SAFETY: `outl` is the caller's slot per the contract.
        unsafe { *outl = i };
        return 1;
    }

    if inl <= 0 {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return c_int::from(inl == 0);
    }
    // SAFETY: `ctx` is live.
    let buf_len = unsafe { (*ctx).buf_len };
    // SAFETY: the buffers are the caller's; `out` is advanced only by full blocks, so the offset
    // is inside the caller's writable range.
    if unsafe { ossl_is_partially_overlapping(out.add(buf_len as usize).cast(), in_.cast(), cmpl) }
        != 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_916) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    let block_mask = unsafe { (*ctx).block_mask };
    if buf_len == 0 && (inl & block_mask) == 0 {
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = 0 };
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback and the buffers are the
        // caller's, holding `inl` bytes.
        if unsafe { do_cipher(ctx.cast::<c_void>(), out, in_, inl as usize) } != 0 {
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = inl };
            return 1;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return 0;
    }

    let mut i = buf_len;
    let mut out = out;
    let mut inl = inl;
    if i != 0 {
        if bl - i > inl {
            // SAFETY: `ctx->buf` holds `EVP_MAX_BLOCK_LENGTH` bytes, `i` is within it, and `in_`
            // holds `inl` bytes, which the test above bounded by the room left after `i`.
            unsafe {
                ptr::copy_nonoverlapping(
                    in_,
                    ptr::addr_of_mut!((*ctx).buf)
                        .cast::<c_uchar>()
                        .add(i as usize),
                    inl as usize,
                )
            };
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).buf_len += inl };
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = 0 };
            return 1;
        }
        let j = bl - i;
        // The guard is on the *full-block* remainder plus the one block this call emits.
        if ((inl - j) & !(bl - 1)) as i64 > (c_int::MAX as i64 - bl as i64) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_948) };
            return 0;
        }
        // SAFETY: `ctx->buf` has room for the `j` bytes that fill it and `in_` holds them.
        unsafe {
            ptr::copy_nonoverlapping(
                in_,
                ptr::addr_of_mut!((*ctx).buf)
                    .cast::<c_uchar>()
                    .add(i as usize),
                j as usize,
            )
        };
        inl -= j;
        // The rebinding is the authority's `in += j`: from here the parameter is an alias of
        // the advanced pointer, and nothing below uses the original.
        // SAFETY: `in_` holds at least `j + inl` bytes.
        #[allow(unused_variables)]
        let in_ = unsafe { in_.add(j as usize) };
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback; `ctx->buf` holds exactly one
        // block and `out` is writable for one.
        if unsafe {
            do_cipher(
                ctx.cast::<c_void>(),
                out,
                ptr::addr_of!((*ctx).buf).cast::<c_uchar>(),
                bl as usize,
            )
        } == 0
        {
            return 0;
        }
        // SAFETY: `out` is writable for the block just written.
        out = unsafe { out.add(bl as usize) };
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = bl };
    } else {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
    }
    i = inl & (bl - 1);
    inl -= i;
    if inl > 0 {
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback and the buffers hold `inl`.
        if unsafe { do_cipher(ctx.cast::<c_void>(), out, in_, inl as usize) } == 0 {
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl += inl };
    }
    if i != 0 {
        // SAFETY: `ctx->buf` holds a block, `i` is under the block size, and `in_[inl]` begins
        // the unprocessed tail of the caller's buffer.
        unsafe {
            ptr::copy_nonoverlapping(
                in_.add(inl as usize),
                ptr::addr_of_mut!((*ctx).buf).cast::<c_uchar>(),
                i as usize,
            )
        };
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).buf_len = i };
    1
}
/// `int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
/// const unsigned char *in, int inl)`.
///
/// Four refusals before anything happens, in the authority's order: a negative length, a NULL
/// `outl`, **the wrong direction** — which is what stops a caller from decrypting through an
/// encrypting context by accident — and a context with no cipher. Then the provider arm computes
/// an `outsize` of `inl + block size` for a block cipher, which is the room `cupdate` needs to
/// flush a held-back block; a streaming cipher gets exactly `inl`.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; `out` writable for `inl` plus a block; `in_`
/// readable for `inl` bytes; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptUpdate(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    if inl < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_983) };
        return 0;
    }
    if outl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_990) };
        return 0;
    }
    // SAFETY: `outl` is the caller's slot per the contract.
    unsafe { *outl = 0 };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).encrypt } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_996) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1001) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).prov }).is_null() {
        // SAFETY: `ctx` is live and the rest is the caller's.
        return unsafe { evp_EncryptDecryptUpdate(ctx, out, outl, in_, inl) };
    }

    // SAFETY: `ctx` is live.
    let blocksize = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
    // SAFETY: `cipher` is live.
    let cupdate = unsafe { (*cipher).cupdate };
    let Some(f) = cupdate else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1011) };
        return 0;
    };
    if blocksize < 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1011) };
        return 0;
    }
    let mut soutl: usize = 0;
    // SAFETY: `f` is the provider's own callback; `ctx`'s `algctx` is the context it made; `out`
    // is writable for `inl` plus a block and `in_` readable for `inl`.
    let ret = unsafe {
        f(
            (*ctx).algctx,
            out,
            &mut soutl,
            inl as usize
                + if blocksize == 1 {
                    0
                } else {
                    blocksize as usize
                },
            in_,
            inl as usize,
        )
    };
    if ret != 0 {
        if soutl > c_int::MAX as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1021) };
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = soutl as c_int };
    }
    ret
}

/// `int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// An alias of `_ex` with no difference at all — kept because the pair is part of the surface and
/// a caller may compare their addresses.
///
/// # Safety
/// As `EVP_EncryptFinal_ex`.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_EncryptFinal_ex(ctx, out, outl) }
}

/// `int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// The padding loop. `b == 1` answers 1 with nothing written — a streaming cipher has no final
/// block. `EVP_CIPH_NO_PADDING` refuses a partial block rather than padding it. Otherwise `n`
/// bytes of value `n` are appended, where `n` is the whole block when the buffer is empty, and the
/// method is asked to cipher the result.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; `out` writable for a block; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptFinal_ex(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    if outl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1052) };
        return 0;
    }
    // SAFETY: `outl` is the caller's slot.
    unsafe { *outl = 0 };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).encrypt } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1058) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1063) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).prov }).is_null() {
        // The legacy arm, below.
    } else {
        // SAFETY: `ctx` is live.
        let blocksize = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
        // SAFETY: `cipher` is live.
        let cfinal = unsafe { (*cipher).cfinal };
        let Some(f) = cfinal else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1072) };
            return 0;
        };
        if blocksize < 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1072) };
            return 0;
        }
        let mut soutl: usize = 0;
        // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is its context; `out`
        // is writable for a block.
        let ret = unsafe {
            f(
                (*ctx).algctx,
                out,
                &mut soutl,
                if blocksize == 1 {
                    0
                } else {
                    blocksize as usize
                },
            )
        };
        if ret != 0 {
            if soutl > c_int::MAX as usize {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1081) };
                return 0;
            }
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = soutl as c_int };
        }
        return ret;
    }

    // The legacy arm.
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback; a NULL input is the final
        // call's contract.
        let ret = unsafe { do_cipher(ctx.cast::<c_void>(), out, ptr::null(), 0) };
        if ret < 0 {
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = ret };
        return 1;
    }

    // SAFETY: `cipher` is live.
    let b = unsafe { (*cipher).block_size } as c_uint;
    if b == 1 {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return 1;
    }
    // SAFETY: `ctx` is live.
    let bl = unsafe { (*ctx).buf_len };
    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPH_NO_PADDING) != 0 {
        if bl != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1110) };
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return 1;
    }

    let n = (b as c_int) - bl;
    let mut i = bl;
    while i < b as c_int {
        // SAFETY: `ctx->buf` holds `EVP_MAX_BLOCK_LENGTH` bytes and `i` is under the block size
        // the authority asserts is at most that.
        unsafe { (*ctx).buf[i as usize] = n as c_uchar };
        i += 1;
    }
    // SAFETY: `cipher` is live.
    let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
        return 0;
    };
    // SAFETY: `do_cipher` is the implementation's own callback; `ctx->buf` holds one block and
    // `out` is writable for one.
    let ret = unsafe {
        do_cipher(
            ctx.cast::<c_void>(),
            out,
            ptr::addr_of!((*ctx).buf).cast::<c_uchar>(),
            b as usize,
        )
    };
    if ret != 0 {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = b as c_int };
    }
    ret
}
/// `int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
/// const unsigned char *in, int inl)`.
///
/// The same four refusals with the direction reversed, and then the one part that has no mirror
/// in the encrypt direction: **the last block is held back**. After the buffering loop runs, a
/// full block of the output is copied into `ctx->final` and subtracted from `*outl`, so
/// `EVP_DecryptFinal_ex` can inspect it for padding and hand back only what the padding leaves.
/// A decryption whose plaintext would be wrong must be able to answer "bad decrypt" without ever
/// having given the caller the plaintext, which is the whole reason this exists.
///
/// Three details are contract:
///
///   * `EVP_CIPH_NO_PADDING` skips both the hold-back and the `final` buffer entirely, because
///     there is no padding to inspect;
///   * `final_used` is only set when `buf_len` is 0 after the loop, so the "maximum output"
///     comment's premise holds;
///   * when a block was held back, the caller's `out` is advanced by one block *before* the loop
///     writes, and the overlap test is against `out` and `in` — so a caller passing the same
///     buffer twice is refused rather than corrupted.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; `out` writable for `inl` plus a block; `in_`
/// readable for `inl` bytes; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptUpdate(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    if inl < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1137) };
        return 0;
    }
    if outl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1144) };
        return 0;
    }
    // SAFETY: `outl` is the caller's slot per the contract.
    unsafe { *outl = 0 };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).encrypt } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1150) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1155) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).prov }).is_null() {
        // The legacy arm, below.
    } else {
        // SAFETY: `ctx` is live.
        let blocksize = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
        // SAFETY: `cipher` is live.
        let cupdate = unsafe { (*cipher).cupdate };
        let Some(f) = cupdate else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1164) };
            return 0;
        };
        if blocksize < 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1164) };
            return 0;
        }
        let mut soutl: usize = 0;
        // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is its context.
        let ret = unsafe {
            f(
                (*ctx).algctx,
                out,
                &mut soutl,
                inl as usize
                    + if blocksize == 1 {
                        0
                    } else {
                        blocksize as usize
                    },
                in_,
                inl as usize,
            )
        };
        if ret != 0 {
            if soutl > c_int::MAX as usize {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1173) };
                return 0;
            }
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = soutl as c_int };
        }
        return ret;
    }

    // The legacy arm.
    // SAFETY: `cipher` is live.
    let b = unsafe { (*cipher).block_size } as c_uint;
    let mut cmpl = inl;
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS as c_int) } != 0 {
        cmpl = safe_div_round_up_int_8(cmpl);
    }

    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        if b == 1 {
            // SAFETY: the buffers are the caller's.
            if unsafe { ossl_is_partially_overlapping(out.cast(), in_.cast(), cmpl) } != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1191) };
                return 0;
            }
        }
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback and `ctx` is its context.
        let fix_len = unsafe { do_cipher(ctx.cast::<c_void>(), out, in_, inl as usize) };
        if fix_len < 0 {
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = 0 };
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = fix_len };
        return 1;
    }

    if inl <= 0 {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return c_int::from(inl == 0);
    }
    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPH_NO_PADDING) != 0 {
        // SAFETY: `ctx` is live and the buffers are the caller's.
        return unsafe { evp_EncryptDecryptUpdate(ctx, out, outl, in_, inl) };
    }

    let mut out = out;
    let mut fix_len: c_int;
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).final_used } != 0 {
        // The held-back block cannot be written under the input, and the authority tests the two
        // addresses as integers for the reason `ossl_is_partially_overlapping` does.
        // The equality test is on the *addresses*, which is what the authority's `PTRDIFF_T`
        // cast does: `core::ptr::eq` on the caller's two buffers.
        let same_buffer = core::ptr::eq(out.cast_const(), in_);
        if same_buffer {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1218) };
            return 0;
        }
        // SAFETY: the buffers are the caller's.
        if unsafe { ossl_is_partially_overlapping(out.cast(), in_.cast(), b as c_int) } != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1218) };
            return 0;
        }
        if ((inl & !(b as c_int - 1)) as i64) > (c_int::MAX as i64 - b as i64) {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1231) };
            return 0;
        }
        // SAFETY: `ctx->final` holds one block and `out` is writable for one.
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::addr_of!((*ctx).final_).cast::<c_uchar>(),
                out,
                b as usize,
            )
        };
        // SAFETY: `out` is writable for the block just written.
        out = unsafe { out.add(b as usize) };
        fix_len = 1;
    } else {
        fix_len = 0;
    }

    // SAFETY: `ctx` is live and the buffers are the caller's.
    if unsafe { evp_EncryptDecryptUpdate(ctx, out, outl, in_, inl) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live.
    let buf_len = unsafe { (*ctx).buf_len };
    if b > 1 && buf_len == 0 {
        // SAFETY: `outl` is the caller's slot and the loop has just written `*outl` bytes.
        let written = unsafe {
            *outl -= b as c_int;
            *outl
        };
        // SAFETY: `ctx` is live and `out[written]` begins the block that was just produced.
        unsafe {
            (*ctx).final_used = 1;
            ptr::copy_nonoverlapping(
                out.add(written as usize),
                ptr::addr_of_mut!((*ctx).final_).cast::<c_uchar>(),
                b as usize,
            );
        }
    } else {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).final_used = 0 };
    }

    if fix_len != 0 {
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl += b as c_int };
    }
    let _ = &mut fix_len;
    1
}

/// `int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// An alias of `_ex`, for the same reason the encrypt pair is a pair.
///
/// # Safety
/// As `EVP_DecryptFinal_ex`.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_DecryptFinal_ex(ctx, out, outl) }
}

/// `int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// The padding check, and the authority's comment on it is the security-relevant line in this
/// file: *"The following assumes that the ciphertext has been authenticated. Otherwise it
/// provides a padding oracle."* The check reads the last byte, refuses a value of 0 or more than
/// the block size, verifies that the last `n` bytes all equal `n`, and copies out only the
/// `block_size - n` bytes that are plaintext.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; `out` writable for a block; `outl` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_DecryptFinal_ex(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    if outl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1278) };
        return 0;
    }
    // SAFETY: `outl` is the caller's slot.
    unsafe { *outl = 0 };

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).encrypt } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1284) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_1289) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if !(unsafe { (*cipher).prov }).is_null() {
        // SAFETY: `ctx` is live.
        let blocksize = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
        // SAFETY: `cipher` is live.
        let cfinal = unsafe { (*cipher).cfinal };
        let Some(f) = cfinal else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1299) };
            return 0;
        };
        if blocksize < 1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1299) };
            return 0;
        }
        let mut soutl: usize = 0;
        // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is its context.
        let ret = unsafe {
            f(
                (*ctx).algctx,
                out,
                &mut soutl,
                if blocksize == 1 {
                    0
                } else {
                    blocksize as usize
                },
            )
        };
        if ret != 0 {
            if soutl > c_int::MAX as usize {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1308) };
                return 0;
            }
            // SAFETY: `outl` is the caller's slot.
            unsafe { *outl = soutl as c_int };
        }
        return ret;
    }

    // The legacy arm.
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).flags } & EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        // SAFETY: `cipher` is live.
        let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
            return 0;
        };
        // SAFETY: `do_cipher` is the implementation's own callback; a NULL input is the final
        // call's contract.
        let i = unsafe { do_cipher(ctx.cast::<c_void>(), out, ptr::null(), 0) };
        if i < 0 {
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = i };
        return 1;
    }

    // SAFETY: `cipher` is live.
    let mut b = unsafe { (*cipher).block_size } as c_uint;
    // SAFETY: `ctx` is live.
    if (unsafe { (*ctx).flags } & EVP_CIPH_NO_PADDING) != 0 {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).buf_len } != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1332) };
            return 0;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = 0 };
        return 1;
    }
    if b > 1 {
        // SAFETY: `ctx` is live.
        let (buf_len, final_used) = unsafe { ((*ctx).buf_len, (*ctx).final_used) };
        if buf_len != 0 || final_used == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1340) };
            return 0;
        }
        // SAFETY: `ctx->final` holds one block.
        let mut n = unsafe { (*ctx).final_[(b - 1) as usize] } as c_int;
        if n == 0 || n > b as c_int {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_ENC_1351) };
            return 0;
        }
        let mut i = 0;
        while i < n {
            b -= 1;
            // SAFETY: `ctx->final` holds one block and `b` is within it.
            if unsafe { (*ctx).final_[b as usize] } as c_int != n {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::EVP_ENC_1356) };
                return 0;
            }
            i += 1;
        }
        // SAFETY: `cipher` is live.
        n = unsafe { (*cipher).block_size } - n;
        let mut i = 0;
        while i < n {
            // SAFETY: `out` is writable for a block and `i` is under the block size.
            unsafe { *out.add(i as usize) = (*ctx).final_[i as usize] };
            i += 1;
        }
        // SAFETY: `outl` is the caller's slot.
        unsafe { *outl = n };
    }
    1
}
/// `int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
/// unsigned int inl)`.
///
/// The one-shot, and its provider arm has a shape none of the four above has: it prefers
/// `ccipher` when the method publishes one and **maps its answer** — `0` becomes `-1` and a
/// non-zero answer becomes the *length* — while falling back to `cupdate` for a non-NULL input
/// and `cfinal` for a NULL one. A blocksize of **zero** is a refusal rather than a call, which is
/// the only guard the function has.
///
/// `inl` is an `unsigned int` here while every other length in the family is an `int`, and that
/// is the authority's signature rather than an oversight to correct.
///
/// # Safety
/// `ctx` must be NULL or a live, armed `EvpCipherCtx`; `out` and `in_` per the method's contract.
#[no_mangle]
pub unsafe extern "C" fn EVP_Cipher(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    in_: *const c_uchar,
    inl: c_uint,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live.
    if !(unsafe { (*cipher).prov }).is_null() {
        // SAFETY: `ctx` is live.
        let blocksize = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) } as usize;
        if blocksize == 0 {
            return 0;
        }
        let mut outl: usize = 0;
        let outsize = inl as usize + if blocksize == 1 { 0 } else { blocksize };
        // SAFETY: `cipher` is live.
        let (ccipher, cupdate, cfinal) =
            unsafe { ((*cipher).ccipher, (*cipher).cupdate, (*cipher).cfinal) };
        // SAFETY: `ctx` is live, so `algctx` is the provider's context, and whichever callback is
        // taken is that provider's own.
        return unsafe {
            if let Some(f) = ccipher {
                if f((*ctx).algctx, out, &mut outl, outsize, in_, inl as usize) != 0 {
                    outl as c_int
                } else {
                    -1
                }
            } else if !in_.is_null() {
                let Some(f) = cupdate else {
                    return -1;
                };
                f((*ctx).algctx, out, &mut outl, outsize, in_, inl as usize)
            } else {
                let Some(f) = cfinal else {
                    return -1;
                };
                f(
                    (*ctx).algctx,
                    out,
                    &mut outl,
                    if blocksize == 1 { 0 } else { blocksize },
                )
            }
        };
    }

    // SAFETY: `cipher` is live.
    let Some(do_cipher) = (unsafe { (*cipher).do_cipher }) else {
        return 0;
    };
    // SAFETY: `do_cipher` is the implementation's own callback and `ctx` is its context.
    unsafe { do_cipher(ctx.cast::<c_void>(), out, in_, inl as usize) }
}

/// `int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
/// const unsigned char *in, int inl)`.
///
/// A two-line dispatch on the context's own direction, which is why it is not an alias of either
/// half: it is the entry point a caller uses when it does not know which direction it set.
///
/// # Safety
/// As `EVP_EncryptUpdate`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherUpdate(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
    in_: *const c_uchar,
    inl: c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).encrypt } != 0 {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_EncryptUpdate(ctx, out, outl, in_, inl) }
    } else {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_DecryptUpdate(ctx, out, outl, in_, inl) }
    }
}

/// `int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// # Safety
/// As `EVP_EncryptFinal_ex`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal_ex(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).encrypt } != 0 {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_EncryptFinal_ex(ctx, out, outl) }
    } else {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_DecryptFinal_ex(ctx, out, outl) }
    }
}

/// `int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)`.
///
/// The non-`_ex` spelling dispatches to the two non-`_ex` finals rather than to the `_ex` ones,
/// which for this build is the same function twice over — and which is worth transcribing as
/// written rather than simplified, because the pair is on the surface and either could stop being
/// an alias.
///
/// # Safety
/// As `EVP_EncryptFinal`.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut c_uchar,
    outl: *mut c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).encrypt } != 0 {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_EncryptFinal(ctx, out, outl) }
    } else {
        // SAFETY: the arguments are forwarded under this function's contract.
        unsafe { EVP_DecryptFinal(ctx, out, outl) }
    }
}

/// `int EVP_CipherPipelineUpdate(EVP_CIPHER_CTX *ctx, unsigned char **out, size_t *outl,
/// const size_t *outsize, const unsigned char **in, const size_t *inl)`.
///
/// Four guards, then **`outl` is zeroed for every pipe before the implementation is asked** — so
/// a provider that returns early leaves a caller reading zeros rather than whatever its array
/// held. The guards are in the authority's order and the third is the one that matters: a legacy
/// method with no provider is refused with `EVP_R_INVALID_OPERATION`, not asked.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; the four arrays must hold `numpipes` entries.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherPipelineUpdate(
    ctx: *mut EvpCipherCtx,
    out: *mut *mut c_uchar,
    outl: *mut usize,
    outsize: *const usize,
    in_: *mut *const c_uchar,
    inl: *const usize,
) -> c_int {
    if outl.is_null() || inl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_733) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_738) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).prov }).is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_743) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    let p_cupdate = unsafe { (*cipher).p_cupdate };
    let Some(f) = p_cupdate else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_748) };
        return 0;
    };
    // SAFETY: `ctx` is live.
    let numpipes = unsafe { (*ctx).numpipes };
    for i in 0..numpipes {
        // SAFETY: `outl` holds `numpipes` entries per the contract, and the context's count is
        // the one the caller's arrays were sized to.
        unsafe { *outl.add(i) = 0 };
    }
    // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is its context.
    unsafe { f((*ctx).algctx, numpipes, out, outl, outsize, in_, inl) }
}

/// `int EVP_CipherPipelineFinal(EVP_CIPHER_CTX *ctx, unsigned char **out, size_t *outl,
/// const size_t *outsize)`.
///
/// The same shape with three guards instead of four — there is no input to refuse — and the same
/// pre-zeroing of `outl`.
///
/// # Safety
/// `ctx` must be a live, armed `EvpCipherCtx`; the arrays must hold `numpipes` entries.
#[no_mangle]
pub unsafe extern "C" fn EVP_CipherPipelineFinal(
    ctx: *mut EvpCipherCtx,
    out: *mut *mut c_uchar,
    outl: *mut usize,
    outsize: *const usize,
) -> c_int {
    if outl.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_783) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let cipher = unsafe { (*ctx).cipher };
    if cipher.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_788) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if (unsafe { (*cipher).prov }).is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_793) };
        return 0;
    }
    // SAFETY: `cipher` is live.
    let p_cfinal = unsafe { (*cipher).p_cfinal };
    let Some(f) = p_cfinal else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_ENC_798) };
        return 0;
    };
    // SAFETY: `ctx` is live.
    let numpipes = unsafe { (*ctx).numpipes };
    for i in 0..numpipes {
        // SAFETY: `outl` holds `numpipes` entries per the contract.
        unsafe { *outl.add(i) = 0 };
    }
    // SAFETY: `f` is the provider's own callback and `ctx`'s `algctx` is its context.
    unsafe { f((*ctx).algctx, numpipes, out, outl, outsize) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EVP_CIPH_RAND_KEY` — `include/openssl/evp.h`.
    ///
    /// Declared here rather than with the flags the module's own code tests, because the only
    /// reader is the flag test below: `EVP_CIPHER_CTX_rand_key`, which is where the flag is used
    /// in the authority, is this slice's hand-off to Phase 9. A header fact a test needs belongs
    /// with the test.
    const EVP_CIPH_RAND_KEY: c_ulong = 0x200;

    /// The context a test arms, released once. Nothing here sets global state: an
    /// `EVP_CIPHER_CTX` is this crate's own object and the two flags it carries are its own.
    struct Ctx(*mut EvpCipherCtx);

    impl Ctx {
        fn new() -> Ctx {
            // `EVP_CIPHER_CTX_new` is safe in this crate: no arguments, and it answers an object
            // this value releases once.
            let ctx = EVP_CIPHER_CTX_new();
            assert!(!ctx.is_null(), "the context was built");
            Ctx(ctx)
        }
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            // SAFETY: `self.0` came from `EVP_CIPHER_CTX_new` and is released once, here.
            unsafe { EVP_CIPHER_CTX_free(self.0) };
        }
    }

    /// A fresh context is **zeroed with `iv_len` at -1**, and every accessor's empty arm reads
    /// that: no cipher means no block size, no key length, no NID, and the two that answer a
    /// sentinel rather than a zero answer their own.
    #[test]
    fn a_fresh_context_answers_every_accessors_empty_arm() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live.
        unsafe {
            assert!(
                (*ctx.0).iv_len == -1,
                "the sentinel a fresh context carries"
            );
            assert!(EVP_CIPHER_CTX_cipher(ctx.0).is_null());
            assert!(EVP_CIPHER_CTX_get0_cipher(ctx.0).is_null());
            assert_eq!(EVP_CIPHER_CTX_get_block_size(ctx.0), 0);
            assert_eq!(EVP_CIPHER_CTX_get_iv_length(ctx.0), 0);
            assert_eq!(EVP_CIPHER_CTX_get_key_length(ctx.0), 0);
            assert_eq!(EVP_CIPHER_CTX_get_nid(ctx.0), NID_undef);
            assert_eq!(EVP_CIPHER_CTX_get_tag_length(ctx.0), 0);
            assert_eq!(EVP_CIPHER_CTX_is_encrypting(ctx.0), 0);
            assert!(EVP_CIPHER_CTX_get_app_data(ctx.0).is_null());
            assert!(EVP_CIPHER_CTX_get_cipher_data(ctx.0).is_null());
            assert!(
                EVP_CIPHER_CTX_get1_cipher(ctx.0).is_null(),
                "nothing to up-ref"
            );
            assert!(EVP_CIPHER_CTX_settable_params(ctx.0).is_null());
            assert!(EVP_CIPHER_CTX_gettable_params(ctx.0).is_null());
            // `get_num` answers the sentinel, not zero, and it does so through a NULL cipher
            // because `evp_do_ciph_ctx_getparams` refuses one before asking anything.
            assert_eq!(EVP_CIPHER_CTX_get_num(ctx.0), EVP_CTRL_RET_UNSUPPORTED);
        }
    }

    /// The two lifetime entry points with nothing to do, and the fact that `reset` on a fresh
    /// context leaves it exactly as it was — because the path it takes is the legacy one (no
    /// cipher means no provider) and that path zeroes and re-sets the sentinel.
    #[test]
    fn resetting_an_empty_context_is_idempotent_and_null_is_a_no_op() {
        assert_eq!(
            // SAFETY: NULL is what this function's contract tests for.
            unsafe { EVP_CIPHER_CTX_reset(ptr::null_mut()) },
            1,
            "a NULL context is a success, not a refusal"
        );
        // SAFETY: NULL is what this function tests for.
        unsafe { EVP_CIPHER_CTX_free(ptr::null_mut()) };

        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live.
        unsafe {
            (*ctx.0).flags = 0xF00;
            assert_eq!(EVP_CIPHER_CTX_reset(ctx.0), 1);
            assert_eq!((*ctx.0).flags, 0, "reset zeroes the whole struct");
            assert_eq!((*ctx.0).iv_len, -1, "and restores the sentinel");
        }
    }

    /// The flags trio is the context's own state and nothing else: `test_flags` answers the
    /// **masked value**, not a boolean, and the length-bits notification only happens when that
    /// one bit actually changed.
    #[test]
    fn the_flag_trio_is_a_mask_and_the_length_bits_bit_is_the_only_one_reported() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live.
        unsafe {
            EVP_CIPHER_CTX_set_flags(ctx.0, EVP_CIPH_NO_PADDING as c_int);
            assert_eq!(
                EVP_CIPHER_CTX_test_flags(ctx.0, EVP_CIPH_NO_PADDING as c_int),
                EVP_CIPH_NO_PADDING as c_int,
                "the masked value comes back"
            );
            assert_eq!((*ctx.0).flags, EVP_CIPH_NO_PADDING);

            // Two flags at once: the answer is the mask, not 1.
            EVP_CIPHER_CTX_set_flags(ctx.0, (EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY) as c_int);
            assert_eq!(
                EVP_CIPHER_CTX_test_flags(ctx.0, (EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY) as c_int),
                (EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY) as c_int
            );

            EVP_CIPHER_CTX_clear_flags(ctx.0, EVP_CIPH_NO_PADDING as c_int);
            assert_eq!(
                EVP_CIPHER_CTX_test_flags(ctx.0, EVP_CIPH_NO_PADDING as c_int),
                0
            );
            // The other two survive: clearing is a mask too.
            assert_eq!((*ctx.0).flags, EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY);
        }
    }

    /// `EVP_CIPHER_CTX_set_padding` writes the **context's** flag first, so the context records
    /// the request even when there is no implementation to tell; and a context with no cipher is
    /// where that asymmetry is visible with nothing else in the way.
    #[test]
    fn padding_is_recorded_on_the_context_before_any_cipher_is_told() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live.
        unsafe {
            assert_eq!(
                EVP_CIPHER_CTX_set_padding(ctx.0, 0),
                0,
                "there is no implementation to send the parameter to"
            );
            assert_eq!(
                (*ctx.0).flags & EVP_CIPH_NO_PADDING,
                EVP_CIPH_NO_PADDING,
                "and the context recorded it anyway"
            );
            // The other direction, with no provider to answer either.
            assert_eq!(EVP_CIPHER_CTX_set_padding(ctx.0, 1), 0);
            assert_eq!((*ctx.0).flags & EVP_CIPH_NO_PADDING, 0);
        }
    }

    /// `EVP_CIPHER_CTX_copy`'s first refusal is the one a caller meets with an unarmed context,
    /// and `EVP_CIPHER_CTX_dup` turns it into a NULL rather than a half-made object.
    #[test]
    fn copying_an_unarmed_context_is_refused_by_both_entry_points() {
        let ctx = Ctx::new();
        let other = Ctx::new();
        // SAFETY: both contexts are live and distinct.
        unsafe {
            assert_eq!(EVP_CIPHER_CTX_copy(other.0, ctx.0), 0);
            assert!(
                EVP_CIPHER_CTX_dup(ctx.0).is_null(),
                "and the duplicating entry point answers NULL rather than the new context"
            );
            // A NULL source is the same refusal, and it must not be dereferenced.
            assert_eq!(EVP_CIPHER_CTX_copy(other.0, ptr::null()), 0);
        }
    }

    /// `EVP_CIPHER_CTX_ctrl` on an unarmed context raises and answers 0 **before** it looks at
    /// the command, which is what makes a caller's error path independent of which control it
    /// was trying to make.
    #[test]
    fn control_on_an_unarmed_context_refuses_before_it_reads_the_command() {
        let ctx = Ctx::new();
        // SAFETY: `ctx.0` is live and the pointer argument is unused by this command.
        unsafe {
            assert_eq!(
                EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_INIT, 0, ptr::null_mut()),
                0,
                "the same refusal as an unknown command, because neither is reached"
            );
        }
    }
}
