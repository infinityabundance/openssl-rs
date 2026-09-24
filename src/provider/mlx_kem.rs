//! Phase 8 — `providers/implementations/kem/mlx_kem.c`: the four hybrid `OSSL_OP_KEM` rows.
//!
//! Three hundred and fifty lines and **one** dispatch table — `ossl_mlx_kem_asym_kem_functions`,
//! shared by the `X25519MLKEM768`, `X448MLKEM1024`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`
//! rows of `deflt_asym_kem[]`, exactly as the authority's `defltprov.c` publishes them. This is the
//! thin provider face over the `MLX_KEY` the keymgmt unit builds: encapsulation runs an ML-KEM
//! encapsulation and an ephemeral ECDHE exchange and concatenates the two halves' outputs, in the
//! slot order `xinfo->ml_kem_slot` names.
//!
//! ## The size-query arms return without cleansing
//!
//! `mlx_kem_encapsulate`'s `ctext == NULL` arm and `mlx_kem_decapsulate`'s `shsec == NULL` arm are
//! plain `return`s inside the function, so the `end:` block's partial-shared-secret cleanse is
//! *skipped* on those paths — written as the authority writes them, because the difference is
//! observable the next time a caller runs the other operation without re-initialising.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::kem::{
    EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate,
    EVP_PKEY_encapsulate_init, OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT,
    OSSL_FUNC_KEM_ENCAPSULATE, OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX,
    OSSL_FUNC_KEM_NEWCTX, OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_SET_CTX_PARAMS,
};
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_get_octet_string_param, EVP_PKEY_new,
    EVP_PKEY_set1_encoded_public_key, EvpPkey,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EvpPkeyCtx, EVP_PKEY_OP_DECAPSULATE,
    EVP_PKEY_OP_ENCAPSULATE,
};
use crate::evp::pmeth_gn::{EVP_PKEY_keygen, EVP_PKEY_keygen_init};
use crate::ml_kem::ML_KEM_SHARED_SECRET_BYTES;
use crate::params::{OsslParam, END};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::mlx_kmgmt::{mlx_kem_have_prvkey, mlx_kem_have_pubkey, MlxKey};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};

/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();

/// The generated unit's own `__FILE__`. `mlx_kem.c` is a plain `.c`, so its `__FILE__` carries the
/// source-tree prefix.
const FILE: *const c_char =
    c"../../src/openssl-3.6.4/providers/implementations/kem/mlx_kem.c".as_ptr();

/// `mlx_kem.c:42`, `mlx_kem_newctx`'s `OPENSSL_malloc(sizeof(*ctx))`.
const LINE_NEWCTX: c_int = 42;
/// `mlx_kem.c:53`, `mlx_kem_freectx`'s `OPENSSL_free(vctx)`.
const LINE_FREECTX: c_int = 53;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_MLX_KEM_CTX` — `mlx_kem.c:32-36`.
#[repr(C)]
struct ProvMlxKemCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `MLX_KEY *key` — borrowed, **not** owned.
    key: *mut MlxKey,
    /// `int op`.
    op: c_int,
}

/// `static int mlx_kem_init(void *vctx, int op, void *key, const OSSL_PARAM params[])` —
/// `mlx_kem.c:56-66`.
///
/// # Safety
/// `vctx` is a live `ProvMlxKemCtx`; `key` is live or NULL.
unsafe fn mlx_kem_init(vctx: *mut c_void, op: c_int, key: *mut c_void) -> c_int {
    let ctx = vctx.cast::<ProvMlxKemCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).key = key.cast::<MlxKey>();
        (*ctx).op = op;
    }
    1
}

/// `static void *mlx_kem_newctx(void *provctx)` — `mlx_kem.c:38-49`.
///
/// # Safety
/// The KEM `newctx` dispatch contract.
unsafe extern "C" fn mlx_kem_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `CRYPTO_malloc` answers NULL on failure, which is checked.
    let ctx = CRYPTO_malloc(core::mem::size_of::<ProvMlxKemCtx>(), FILE, LINE_NEWCTX)
        .cast::<ProvMlxKemCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is a fresh allocation; every field is written below.
    unsafe {
        (*ctx).libctx = prov_libctx_of(provctx);
        (*ctx).key = ptr::null_mut();
        (*ctx).op = 0;
    }
    ctx.cast()
}

/// `static void mlx_kem_freectx(void *vctx)` — `mlx_kem.c:51-54`.
///
/// # Safety
/// The KEM `freectx` dispatch contract.
unsafe extern "C" fn mlx_kem_freectx(vctx: *mut c_void) {
    // SAFETY: `vctx` is the caller's; `CRYPTO_free` accepts NULL.
    unsafe { CRYPTO_free(vctx, FILE, LINE_FREECTX) };
}

/// `static int mlx_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `mlx_kem.c:68-78`.
///
/// # Safety
/// The KEM `encapsulate_init` dispatch contract.
unsafe extern "C" fn mlx_kem_encapsulate_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlxKey>();

    // SAFETY: `key` is live per the contract.
    unsafe {
        if !mlx_kem_have_pubkey(key) {
            raise_site(&err_sites::PROV_MLX_KEM_74);
            return 0;
        }
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { mlx_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey) }
}

/// `static int mlx_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `mlx_kem.c:80-90`.
///
/// # Safety
/// The KEM `decapsulate_init` dispatch contract.
unsafe extern "C" fn mlx_kem_decapsulate_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlxKey>();

    // SAFETY: `key` is live per the contract.
    unsafe {
        if !mlx_kem_have_prvkey(key) {
            raise_site(&err_sites::PROV_MLX_KEM_86);
            return 0;
        }
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { mlx_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey) }
}

/// `static const OSSL_PARAM *mlx_kem_settable_ctx_params(void *vctx, void *provctx)` —
/// `mlx_kem.c:92-98`.
///
/// # Safety
/// The KEM `settable_ctx_params` dispatch contract.
unsafe extern "C" fn mlx_kem_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    static PARAMS: [OsslParam; 1] = [END];
    PARAMS.as_ptr()
}

/// `static int mlx_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `mlx_kem.c:100-104`.
///
/// # Safety
/// The KEM `set_ctx_params` dispatch contract.
unsafe extern "C" fn mlx_kem_set_ctx_params(
    _vctx: *mut c_void,
    _params: *const OsslParam,
) -> c_int {
    1
}

/// Raise the authority's `ERR_raise_data` message of the form `prefix || alg || suffix`.
///
/// # Safety
/// `alg` is a NUL-terminated C string.
unsafe fn raise_with_alg(
    site: &err_sites::ErrSite,
    prefix: &str,
    alg: *const c_char,
    suffix: &str,
) {
    // SAFETY: `alg` is NUL-terminated per the contract.
    let a = unsafe { core::ffi::CStr::from_ptr(alg) }.to_string_lossy();
    let mut buf = format!("{prefix}{a}{suffix}").into_bytes();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
}

/// Raise a fixed message through a site, the `ERR_raise_data` form.
///
/// # Safety
/// Nothing: the message is NUL-terminated here.
unsafe fn raise_fixed(site: &err_sites::ErrSite, msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
}

/// `static int mlx_kem_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,`
/// `unsigned char *shsec, size_t *slen)` — `mlx_kem.c:106-246`.
///
/// # Safety
/// The KEM `encapsulate` dispatch contract.
unsafe extern "C" fn mlx_kem_encapsulate(
    vctx: *mut c_void,
    ctext: *mut u8,
    clen: *mut usize,
    shsec: *mut u8,
    slen: *mut usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*(vctx.cast::<ProvMlxKemCtx>())).key };
    let mut ctx: *mut EvpPkeyCtx;
    let mut xkey: *mut EvpPkey = ptr::null_mut();
    let mut ret = 0;

    // SAFETY: `key` is live per the contract; the buffers are the caller's.
    unsafe {
        let ml_kem_slot = (*(*key).xinfo).ml_kem_slot;
        let mut encap_clen = (*(*key).minfo).ctext_bytes + (*(*key).xinfo).pubkey_bytes;
        let mut encap_slen = ML_KEM_SHARED_SECRET_BYTES + (*(*key).xinfo).shsec_bytes;

        if !mlx_kem_have_pubkey(key) {
            raise_site(&err_sites::PROV_MLX_KEM_120);
            return 0;
        }

        if ctext.is_null() {
            if clen.is_null() && slen.is_null() {
                return 0;
            }
            if !clen.is_null() {
                *clen = encap_clen;
            }
            if !slen.is_null() {
                *slen = encap_slen;
            }
            // A plain return: the partial-shared-secret cleanse is *not* run on this path.
            return 1;
        }
        if shsec.is_null() {
            raise_fixed(
                &err_sites::PROV_MLX_KEM_136,
                "null shared-secret output buffer",
            );
            return 0;
        }

        if clen.is_null() {
            raise_fixed(
                &err_sites::PROV_MLX_KEM_142,
                "null ciphertext input/output length pointer",
            );
            return 0;
        } else if *clen < encap_clen {
            raise_fixed(&err_sites::PROV_MLX_KEM_146, "ciphertext buffer too small");
            return 0;
        } else {
            *clen = encap_clen;
        }

        if slen.is_null() {
            raise_fixed(
                &err_sites::PROV_MLX_KEM_154,
                "null shared secret input/output length pointer",
            );
            return 0;
        } else if *slen < encap_slen {
            raise_fixed(
                &err_sites::PROV_MLX_KEM_158,
                "shared-secret buffer too small",
            );
            return 0;
        } else {
            *slen = encap_slen;
        }

        // The authority's `end:` label, as one labelled block.
        'end: {
            // ML-KEM encapsulation.
            encap_clen = (*(*key).minfo).ctext_bytes;
            encap_slen = ML_KEM_SHARED_SECRET_BYTES;
            let mut cbuf = ctext.add(ml_kem_slot as usize * (*(*key).xinfo).pubkey_bytes);
            let mut sbuf = shsec.add(ml_kem_slot as usize * (*(*key).xinfo).shsec_bytes);
            ctx = EVP_PKEY_CTX_new_from_pkey((*key).libctx, (*key).mkey, (*key).propq);
            if ctx.is_null()
                || EVP_PKEY_encapsulate_init(ctx, ptr::null()) <= 0
                || EVP_PKEY_encapsulate(ctx, cbuf, &mut encap_clen, sbuf, &mut encap_slen) <= 0
            {
                break 'end;
            }
            if encap_clen != (*(*key).minfo).ctext_bytes {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_176,
                    "unexpected ",
                    (*(*key).minfo).algorithm_name,
                    &format!(" ciphertext output size: {encap_clen}"),
                );
                break 'end;
            }
            if encap_slen != ML_KEM_SHARED_SECRET_BYTES {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_182,
                    "unexpected ",
                    (*(*key).minfo).algorithm_name,
                    &format!(" shared secret output size: {encap_slen}"),
                );
                break 'end;
            }
            EVP_PKEY_CTX_free(ctx);

            // ECDHE encapsulation: generate an ephemeral private key and add its public key to
            // ctext.
            cbuf = ctext.add((1 - ml_kem_slot) as usize * (*(*key).minfo).ctext_bytes);
            encap_clen = (*(*key).xinfo).pubkey_bytes;
            ctx = EVP_PKEY_CTX_new_from_pkey((*key).libctx, (*key).xkey, (*key).propq);
            if ctx.is_null()
                || EVP_PKEY_keygen_init(ctx) <= 0
                || EVP_PKEY_keygen(ctx, &mut xkey) <= 0
                || EVP_PKEY_get_octet_string_param(
                    xkey,
                    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                    cbuf,
                    encap_clen,
                    &mut encap_clen,
                ) <= 0
            {
                break 'end;
            }
            if encap_clen != (*(*key).xinfo).pubkey_bytes {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_214,
                    "unexpected ",
                    (*(*key).xinfo).algorithm_name,
                    &format!(" public key output size: {encap_clen}"),
                );
                break 'end;
            }
            EVP_PKEY_CTX_free(ctx);

            // Derive the ECDH shared secret.
            encap_slen = (*(*key).xinfo).shsec_bytes;
            sbuf = shsec.add((1 - ml_kem_slot) as usize * ML_KEM_SHARED_SECRET_BYTES);
            ctx = EVP_PKEY_CTX_new_from_pkey((*key).libctx, xkey, (*key).propq);
            if ctx.is_null()
                || EVP_PKEY_derive_init(ctx) <= 0
                || EVP_PKEY_derive_set_peer(ctx, (*key).xkey) <= 0
                || EVP_PKEY_derive(ctx, sbuf, &mut encap_slen) <= 0
            {
                break 'end;
            }
            if encap_slen != (*(*key).xinfo).shsec_bytes {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_231,
                    "unexpected ",
                    (*(*key).xinfo).algorithm_name,
                    &format!(" shared secret output size: {encap_slen}"),
                );
                break 'end;
            }

            ret = 1;
        }

        // The `end:` block's partial-shared-secret erase — `mlx_kem.c:239-242`.
        if ret == 0 {
            OPENSSL_cleanse(
                shsec.cast(),
                ML_KEM_SHARED_SECRET_BYTES + (*(*key).xinfo).shsec_bytes,
            );
        }
        EVP_PKEY_free(xkey);
        EVP_PKEY_CTX_free(ctx);
    }
    ret
}

/// `static int mlx_kem_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,`
/// `const uint8_t *ctext, size_t clen)` — `mlx_kem.c:248-338`.
///
/// # Safety
/// The KEM `decapsulate` dispatch contract.
unsafe extern "C" fn mlx_kem_decapsulate(
    vctx: *mut c_void,
    shsec: *mut u8,
    slen: *mut usize,
    ctext: *const u8,
    clen: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*(vctx.cast::<ProvMlxKemCtx>())).key };
    let mut ctx: *mut EvpPkeyCtx;
    let mut xkey: *mut EvpPkey = ptr::null_mut();
    let mut ret = 0;

    // SAFETY: `key` is live per the contract; the buffers are the caller's.
    unsafe {
        let ml_kem_slot = (*(*key).xinfo).ml_kem_slot;
        let mut decap_slen = ML_KEM_SHARED_SECRET_BYTES + (*(*key).xinfo).shsec_bytes;
        let mut decap_clen = (*(*key).minfo).ctext_bytes + (*(*key).xinfo).pubkey_bytes;

        if !mlx_kem_have_prvkey(key) {
            raise_site(&err_sites::PROV_MLX_KEM_262);
            return 0;
        }

        if shsec.is_null() {
            if slen.is_null() {
                return 0;
            }
            *slen = decap_slen;
            // A plain return: the partial-shared-secret cleanse is *not* run on this path.
            return 1;
        }

        // For now tolerate newly-deprecated NULL length pointers: the authority points the local at
        // its own `decap_slen`, which is the value the calls below already read.
        if !slen.is_null() {
            if *slen < decap_slen {
                raise_fixed(
                    &err_sites::PROV_MLX_KEM_277,
                    "shared-secret buffer too small",
                );
                return 0;
            }
            *slen = decap_slen;
        }
        if clen != decap_clen {
            raise_fixed(
                &err_sites::PROV_MLX_KEM_284,
                &format!("wrong decapsulation input ciphertext size: {clen}"),
            );
            return 0;
        }

        // The authority's `end:` label, as one labelled block.
        'end: {
            // ML-KEM decapsulation.
            decap_clen = (*(*key).minfo).ctext_bytes;
            decap_slen = ML_KEM_SHARED_SECRET_BYTES;
            let cbuf = ctext.add(ml_kem_slot as usize * (*(*key).xinfo).pubkey_bytes);
            let mut sbuf = shsec.add(ml_kem_slot as usize * (*(*key).xinfo).shsec_bytes);
            ctx = EVP_PKEY_CTX_new_from_pkey((*key).libctx, (*key).mkey, (*key).propq);
            if ctx.is_null()
                || EVP_PKEY_decapsulate_init(ctx, ptr::null()) <= 0
                || EVP_PKEY_decapsulate(ctx, sbuf, &mut decap_slen, cbuf, decap_clen) <= 0
            {
                break 'end;
            }
            if decap_slen != ML_KEM_SHARED_SECRET_BYTES {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_301,
                    "unexpected ",
                    (*(*key).minfo).algorithm_name,
                    &format!(" shared secret output size: {decap_slen}"),
                );
                break 'end;
            }
            EVP_PKEY_CTX_free(ctx);

            // ECDH decapsulation.
            decap_clen = (*(*key).xinfo).pubkey_bytes;
            decap_slen = (*(*key).xinfo).shsec_bytes;
            let cbuf = ctext.add((1 - ml_kem_slot) as usize * (*(*key).minfo).ctext_bytes);
            sbuf = shsec.add((1 - ml_kem_slot) as usize * ML_KEM_SHARED_SECRET_BYTES);
            ctx = EVP_PKEY_CTX_new_from_pkey((*key).libctx, (*key).xkey, (*key).propq);
            xkey = EVP_PKEY_new();
            if ctx.is_null()
                || xkey.is_null()
                || EVP_PKEY_copy_parameters(xkey, (*key).xkey) <= 0
                || EVP_PKEY_set1_encoded_public_key(xkey, cbuf, decap_clen) <= 0
                || EVP_PKEY_derive_init(ctx) <= 0
                || EVP_PKEY_derive_set_peer(ctx, xkey) <= 0
                || EVP_PKEY_derive(ctx, sbuf, &mut decap_slen) <= 0
            {
                break 'end;
            }
            if decap_slen != (*(*key).xinfo).shsec_bytes {
                raise_with_alg(
                    &err_sites::PROV_MLX_KEM_323,
                    "unexpected ",
                    (*(*key).xinfo).algorithm_name,
                    &format!(" shared secret output size: {decap_slen}"),
                );
                break 'end;
            }

            ret = 1;
        }

        // The `end:` block's partial-shared-secret erase — `mlx_kem.c:331-334`.
        if ret == 0 {
            OPENSSL_cleanse(
                shsec.cast(),
                ML_KEM_SHARED_SECRET_BYTES + (*(*key).xinfo).shsec_bytes,
            );
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(xkey);
    }
    ret
}

/// `const OSSL_DISPATCH ossl_mlx_kem_asym_kem_functions[]` — `mlx_kem.c:340-350`. Eight slots, the
/// authority's, in its order. The four hybrid rows the census records share this one table.
pub(crate) static MLX_ASYM_KEM_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_NEWCTX,
        function: mlx_kem_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        function: mlx_kem_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE,
        function: mlx_kem_encapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE_INIT,
        function: mlx_kem_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE,
        function: mlx_kem_decapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_FREECTX,
        function: mlx_kem_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SET_CTX_PARAMS,
        function: mlx_kem_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        function: mlx_kem_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
