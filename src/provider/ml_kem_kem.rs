//! Phase 8 — `providers/implementations/kem/ml_kem_kem.c.in`: the three ML-KEM `OSSL_OP_KEM` rows.
//!
//! Two hundred and seventy-two source lines and **one** dispatch table —
//! `ossl_ml_kem_asym_kem_functions`, shared by the `ML-KEM-512`, `ML-KEM-768` and `ML-KEM-1024`
//! rows of `deflt_asym_kem[]`, exactly as the authority's `defltprov.c` publishes them. This is the
//! thin provider face over `crypto/ml_kem/ml_kem.c`; the arithmetic is all in `src/ml_kem/`.
//!
//! ## The one generated decoder is written the crate's way
//!
//! `util/perl/OpenSSL/paramnames.pm` emits, for the `produce_param_decoder` block at `:105-107`,
//! a nested character-by-character `switch` over the parameter's key. Its whole observable content
//! is the **repeated-key refusal** at `:129` plus the located pointer this unit's body reads. The
//! decoder here is the repeated-key scan plus `OSSL_PARAM_locate_const`, the shape
//! `src/provider/ecx_kem.rs` already uses for its three-key one.
//!
//! ## The `ctext == NULL` arm returns **without** cleansing the entropy
//!
//! `ml_kem_encapsulate`'s size-query arm (`:168-176`) is a `return 1` inside the function, so the
//! `end:` block's one-shot-entropy cleanse is *skipped* on that path. It is written as the
//! authority writes it — a plain return, not a jump to the tail — because the difference is
//! observable the next time a caller encapsulates without re-initialising.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::kem::{
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_ENCAPSULATE,
    OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_SET_CTX_PARAMS,
};
use crate::evp::pkey_ctx::{EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE};
use crate::ml_kem::key::{ossl_ml_kem_decap, ossl_ml_kem_encap_rand, ossl_ml_kem_encap_seed};
use crate::ml_kem::{
    ossl_ml_kem_have_prvkey, ossl_ml_kem_have_pubkey, ossl_ml_kem_key_vinfo, MlKemKey, MlKemVinfo,
    ML_KEM_RANDOM_BYTES, ML_KEM_SHARED_SECRET_BYTES,
};
use crate::params::{OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const, OsslParam, END};
use crate::provider::cipher::param_octet_string;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};

/// `OSSL_KEM_PARAM_IKME` — `core_names.h:325`.
const OSSL_KEM_PARAM_IKME: *const c_char = c"ikme".as_ptr();

/// The generated unit's own `__FILE__`. `ml_kem_kem.c.in` is `.c.in`-generated, so it is the bare
/// build-relative path.
const FILE: *const c_char = c"providers/implementations/kem/ml_kem_kem.c".as_ptr();

/// `ml_kem_kem.c:50`, the `OPENSSL_malloc(sizeof(*ctx))` in `ml_kem_newctx`.
const LINE_NEWCTX: c_int = 50;
/// `ml_kem_kem.c:65`, the `OPENSSL_free(ctx)` in `ml_kem_freectx`.
const LINE_FREECTX: c_int = 65;

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `PROV_ML_KEM_CTX` — `ml_kem_kem.c:39-44`.
#[repr(C)]
struct ProvMlKemCtx {
    /// `ML_KEM_KEY *key` — borrowed, **not** owned.
    key: *mut MlKemKey,
    /// `uint8_t entropy_buf[ML_KEM_RANDOM_BYTES]` — the built-in one-shot entropy buffer.
    entropy_buf: [u8; ML_KEM_RANDOM_BYTES],
    /// `uint8_t *entropy` — NULL, or `entropy_buf`, or a caller-supplied `ikmE`.
    entropy: *mut u8,
    /// `int op` — `EVP_PKEY_OP_ENCAPSULATE`/`_DECAPSULATE`.
    op: c_int,
}

/// `static const OSSL_PARAM ml_kem_set_ctx_params_list[]` — generated `ml_kem_kem.c`.
static ML_KEM_SET_CTX_PARAMS_LIST: [OsslParam; 2] = [param_octet_string(OSSL_KEM_PARAM_IKME), END];

/// The `void *ml_kem_newctx(void *provctx)` — `ml_kem_kem.c:46-57`.
///
/// # Safety
/// The KEM `newctx` dispatch contract.
unsafe extern "C" fn ml_kem_newctx(_provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `CRYPTO_malloc` answers NULL on failure, which is checked.
    let ctx = CRYPTO_malloc(core::mem::size_of::<ProvMlKemCtx>(), FILE, LINE_NEWCTX)
        .cast::<ProvMlKemCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is a fresh allocation; every field is written below.
    unsafe {
        (*ctx).key = ptr::null_mut();
        (*ctx).entropy = ptr::null_mut();
        (*ctx).op = 0;
    }
    ctx.cast()
}

/// `static void ml_kem_freectx(void *vctx)` — `ml_kem_kem.c:59-66`.
///
/// # Safety
/// The KEM `freectx` dispatch contract.
unsafe extern "C" fn ml_kem_freectx(vctx: *mut c_void) {
    let ctx = vctx.cast::<ProvMlKemCtx>();

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if !(*ctx).entropy.is_null() {
            OPENSSL_cleanse((*ctx).entropy.cast(), ML_KEM_RANDOM_BYTES);
        }
        CRYPTO_free(vctx, FILE, LINE_FREECTX);
    }
}

/// `static int ml_kem_init(void *vctx, int op, void *key, const OSSL_PARAM params[])` —
/// `ml_kem_kem.c:68-78`.
///
/// # Safety
/// `vctx` is a live `ProvMlKemCtx` and `params` NULL or key-terminated.
unsafe fn ml_kem_init(
    vctx: *mut c_void,
    op: c_int,
    key: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vctx.cast::<ProvMlKemCtx>();

    if is_running() == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).key = key.cast::<MlKemKey>();
        (*ctx).op = op;
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { ml_kem_set_ctx_params(vctx, params) }
}

/// `static int ml_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `ml_kem_kem.c:80-90`.
///
/// # Safety
/// The KEM `encapsulate_init` dispatch contract.
unsafe extern "C" fn ml_kem_encapsulate_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    // SAFETY: `key` is live per the contract.
    unsafe {
        if !ossl_ml_kem_have_pubkey(key) {
            raise_site(&err_sites::PROV_ML_KEM_KEM_84);
            return 0;
        }
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { ml_kem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, params) }
}

/// `static int ml_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])` —
/// `ml_kem_kem.c:92-102`.
///
/// # Safety
/// The KEM `decapsulate_init` dispatch contract.
unsafe extern "C" fn ml_kem_decapsulate_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let key = vkey.cast::<MlKemKey>();

    // SAFETY: `key` is live per the contract.
    unsafe {
        if !ossl_ml_kem_have_prvkey(key) {
            raise_site(&err_sites::PROV_ML_KEM_KEM_96);
            return 0;
        }
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { ml_kem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, params) }
}

/// `struct ml_kem_set_ctx_params_st` — generated `ml_kem_kem.c`.
struct MlKemSetCtxParams {
    /// `const OSSL_PARAM *ikme`.
    ikme: *const OsslParam,
}

/// The generated decoder's one repeated-key coordinate.
const ML_KEM_SET_CTX_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 1] =
    [(&err_sites::PROV_ML_KEM_KEM_129, OSSL_KEM_PARAM_IKME)];

/// The repeated-key scan the generated decoder is.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ml_kem_repeated_param_site(
    params: *const OsslParam,
    keys: &[(&'static err_sites::ErrSite, *const c_char)],
) -> Option<&'static err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the array is key-terminated per the contract; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if CStr::from_ptr(*name).to_bytes() == k {
                    let bit = 1u32 << i;
                    if seen & bit != 0 {
                        return Some(site);
                    }
                    seen |= bit;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
}

/// `ml_kem_set_ctx_params_decoder` — generated `ml_kem_kem.c`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn ml_kem_set_ctx_params_decoder(
    params: *const OsslParam,
    r: &mut MlKemSetCtxParams,
) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = ml_kem_repeated_param_site(params, &ML_KEM_SET_CTX_PARAMS_DECODER_KEYS)
        {
            raise_site(site);
            return 0;
        }
        r.ikme = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    }
    1
}

/// Raise a fixed message through a site, the `ERR_raise_data` form.
///
/// # Safety
/// Nothing: the message is a NUL-terminated literal built here.
unsafe fn raise_fixed(site: &crate::runtime::err::err_sites::ErrSite, msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated just above.
    unsafe { raise_site_data(site, buf.as_ptr().cast()) };
}

/// `static int ml_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])` —
/// `ml_kem_kem.c:110-142`.
///
/// # Safety
/// The KEM `set_ctx_params` dispatch contract.
unsafe extern "C" fn ml_kem_set_ctx_params(vctx: *mut c_void, params: *const OsslParam) -> c_int {
    let ctx = vctx.cast::<ProvMlKemCtx>();
    let mut p = MlKemSetCtxParams { ikme: ptr::null() };

    // SAFETY: `ctx`/`params` are the caller's; `p` is this call's own decoder result.
    unsafe {
        if ctx.is_null() || ml_kem_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        if (*ctx).op == EVP_PKEY_OP_DECAPSULATE && !(*ctx).entropy.is_null() {
            // Decapsulation is deterministic
            OPENSSL_cleanse((*ctx).entropy.cast(), ML_KEM_RANDOM_BYTES);
            (*ctx).entropy = ptr::null_mut();
        }

        // Encapsulation ephemeral input key material "ikmE"
        if (*ctx).op == EVP_PKEY_OP_ENCAPSULATE && !p.ikme.is_null() {
            let mut len = ML_KEM_RANDOM_BYTES;

            (*ctx).entropy = (*ctx).entropy_buf.as_mut_ptr();
            let mut ep: *mut c_void = (*ctx).entropy.cast();
            let ok = OSSL_PARAM_get_octet_string(p.ikme, &mut ep, ML_KEM_RANDOM_BYTES, &mut len);
            (*ctx).entropy = ep.cast::<u8>();
            if ok != 0 && len == ML_KEM_RANDOM_BYTES {
                return 1;
            }

            // Possibly, but much less likely wrong type
            raise_site(&err_sites::PROV_ML_KEM_KEM_166);
            OPENSSL_cleanse((*ctx).entropy_buf.as_mut_ptr().cast(), ML_KEM_RANDOM_BYTES);
            (*ctx).entropy = ptr::null_mut();
            return 0;
        }
    }

    1
}

/// `static const OSSL_PARAM *ml_kem_settable_ctx_params(void *vctx, void *provctx)` —
/// `ml_kem_kem.c:144-148`.
///
/// # Safety
/// The KEM `settable_ctx_params` dispatch contract.
unsafe extern "C" fn ml_kem_settable_ctx_params(
    _vctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    ML_KEM_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int ml_kem_encapsulate(void *vctx, unsigned char *ctext, size_t *clen,
/// unsigned char *shsec, size_t *slen)` — `ml_kem_kem.c:150-226`.
///
/// # Safety
/// The KEM `encapsulate` dispatch contract.
unsafe extern "C" fn ml_kem_encapsulate(
    vctx: *mut c_void,
    ctext: *mut u8,
    clen: *mut usize,
    shsec: *mut u8,
    slen: *mut usize,
) -> c_int {
    let ctx = vctx.cast::<ProvMlKemCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    let ret: c_int;

    // SAFETY: `key` is live per the contract; the buffers are the caller's.
    unsafe {
        // The authority's `goto end` targets, as one labelled block.
        'end: {
            if !ossl_ml_kem_have_pubkey(key) {
                raise_site(&err_sites::PROV_ML_KEM_KEM_192);
                ret = 0;
                break 'end;
            }
            let v: *const MlKemVinfo = ossl_ml_kem_key_vinfo(key);
            let encap_clen = (*v).ctext_bytes;
            let encap_slen = ML_KEM_SHARED_SECRET_BYTES;

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
                // A plain return: the one-shot tick is *not* cleansed on this path.
                return 1;
            }
            if shsec.is_null() {
                raise_fixed(&err_sites::PROV_ML_KEM_KEM_209, "NULL shared-secret buffer");
                ret = 0;
                break 'end;
            }

            if clen.is_null() {
                raise_fixed(
                    &err_sites::PROV_ML_KEM_KEM_215,
                    "null ciphertext input/output length pointer",
                );
                ret = 0;
                break 'end;
            } else if *clen < encap_clen {
                raise_fixed(
                    &err_sites::PROV_ML_KEM_KEM_219,
                    "ciphertext buffer too small",
                );
                ret = 0;
                break 'end;
            } else {
                *clen = encap_clen;
            }

            if slen.is_null() {
                raise_fixed(
                    &err_sites::PROV_ML_KEM_KEM_227,
                    "null shared secret input/output length pointer",
                );
                ret = 0;
                break 'end;
            } else if *slen < encap_slen {
                raise_fixed(
                    &err_sites::PROV_ML_KEM_KEM_231,
                    "shared-secret buffer too small",
                );
                ret = 0;
                break 'end;
            } else {
                *slen = encap_slen;
            }

            ret = if !(*ctx).entropy.is_null() {
                ossl_ml_kem_encap_seed(
                    ctext,
                    encap_clen,
                    shsec,
                    encap_slen,
                    (*ctx).entropy,
                    ML_KEM_RANDOM_BYTES,
                    key,
                )
            } else {
                ossl_ml_kem_encap_rand(ctext, encap_clen, shsec, encap_slen, key)
            };
        }

        // The `end:` block's one-shot entropy tick — `ml_kem_kem.c:213-225`.
        if !(*ctx).entropy.is_null() {
            OPENSSL_cleanse((*ctx).entropy.cast(), ML_KEM_RANDOM_BYTES);
            (*ctx).entropy = ptr::null_mut();
        }
    }
    ret
}

/// `static int ml_kem_decapsulate(void *vctx, uint8_t *shsec, size_t *slen,
/// const uint8_t *ctext, size_t clen)` — `ml_kem_kem.c:228-260`.
///
/// # Safety
/// The KEM `decapsulate` dispatch contract.
unsafe extern "C" fn ml_kem_decapsulate(
    vctx: *mut c_void,
    shsec: *mut u8,
    slen: *mut usize,
    ctext: *const u8,
    clen: usize,
) -> c_int {
    let ctx = vctx.cast::<ProvMlKemCtx>();
    // SAFETY: `ctx` is live per the contract.
    let key = unsafe { (*ctx).key };
    let decap_slen = ML_KEM_SHARED_SECRET_BYTES;

    // SAFETY: `key` is live per the contract; the buffers are the caller's.
    unsafe {
        if !ossl_ml_kem_have_prvkey(key) {
            raise_site(&err_sites::PROV_ML_KEM_KEM_267);
            return 0;
        }

        if shsec.is_null() {
            if slen.is_null() {
                return 0;
            }
            *slen = ML_KEM_SHARED_SECRET_BYTES;
            return 1;
        }

        // For now tolerate newly-deprecated NULL length pointers: the authority points the local
        // at its own `decap_slen`, which is the value the call below already reads.
        if !slen.is_null() {
            if *slen < decap_slen {
                raise_fixed(
                    &err_sites::PROV_ML_KEM_KEM_282,
                    "shared-secret buffer too small",
                );
                return 0;
            }
            *slen = decap_slen;
        }

        // ML-KEM decap handles incorrect ciphertext lengths internally
        ossl_ml_kem_decap(shsec, decap_slen, ctext, clen, key)
    }
}

/// `const OSSL_DISPATCH ossl_ml_kem_asym_kem_functions[]` — `ml_kem_kem.c:262-272`. Eight slots,
/// the authority's, in its order. The three `ML-KEM-*` rows the census records share this one
/// table, exactly as the authority's `deflt_asym_kem[]` publishes them.
pub(crate) static ML_KEM_ASYM_KEM_FUNCTIONS: [OsslDispatch; 9] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_NEWCTX,
        function: ml_kem_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        function: ml_kem_encapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_ENCAPSULATE,
        function: ml_kem_encapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE_INIT,
        function: ml_kem_decapsulate_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_DECAPSULATE,
        function: ml_kem_decapsulate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_FREECTX,
        function: ml_kem_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SET_CTX_PARAMS,
        function: ml_kem_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        function: ml_kem_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];
