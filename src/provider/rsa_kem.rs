//! Phase 8 — `providers/implementations/kem/rsa_kem.c`: the `RSA` `OSSL_OP_KEM` row.
//!
//! The unit is the **RSASVE** KEM of NIST SP 800-56B Rev 2 (§7.2.1.2 `RSASVE.GENERATE`, §7.2.1.3
//! `RSASVE.RECOVER`): encapsulation draws a random `1 < z < n-1`, returns `RSAEP((n,e), z)` as the
//! ciphertext and `z` as the shared secret; decapsulation runs `RSADP((n,d), c)` and returns the
//! result. The context (`PROV_RSA_CTX`) carries the `RSA` borrow and the *operation* — `KEM_OP_RSASVE`
//! (0) is the only value the name map can produce, so the two `switch` defaults that answer `-2` are
//! unreachable through the parameter interface and are transcribed anyway.
//!
//! ## The prerequisite, and the one arm that is `#ifndef FIPS_MODULE`
//!
//! `rsakem_init` calls `ossl_rsa_key_op_get_protect` (`:149`), landed with D395 beside `rsa_sig.c.in`'s
//! caller. Everything else is landed: `RSA_get0_key`/`RSA_get0_n`/`RSA_up_ref`/`RSA_free`,
//! `RSA_public_encrypt`/`RSA_private_decrypt`, `ossl_rsa_get0_libctx` (whose `#[allow(dead_code)]`
//! this row removes, because it was written for exactly this caller), the `BN_*` surface, and
//! `OPENSSL_strcasecmp`.
//!
//! `rsasve_recover`'s degenerate-ciphertext guard (`:412-448`) is the **non-FIPS** arm: `RSADP`'s own
//! `1 < c < n-1` bound lives in `crypto/rsa/rsa_ossl.c` under `FIPS_MODULE`, so a non-FIPS build
//! enforces it here, raising the primitive's own reasons (`RSA_R_DATA_TOO_SMALL` for `c <= 1`,
//! `RSA_R_DATA_TOO_LARGE_FOR_MODULUS` for `c >= n-1`) through the one site whose reason is chosen at
//! run time. The guard is this profile's arm, so it is transcribed; the FIPS tail of `rsakem_init`
//! (`:171-176`) and the two `*_FIPS_*` decoder keys are not.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::bn::arith::{BN_add_word, BN_cmp, BN_sub_word, BN_ucmp};
use crate::bn::bignum::{BN_bin2bn, BN_bn2binpad, BN_copy, BN_free, BN_new, BN_value_one, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_secure_new_ex, BN_CTX_start};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::kem::{
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_DUPCTX,
    OSSL_FUNC_KEM_ENCAPSULATE, OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX,
    OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_GET_CTX_PARAMS, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_FUNC_KEM_SET_CTX_PARAMS,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE, OSSL_KEM_PARAM_OPERATION, RSA_NO_PADDING,
};
use crate::params::{OsslParam, END, OSSL_PARAM_UTF8_STRING};
use crate::provider::cipher::param_utf8_string;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::securitycheck::ossl_rsa_key_op_get_protect;
use crate::rsa::object::{
    ossl_rsa_get0_libctx, RSA_free, RSA_get0_key, RSA_get0_n, RSA_private_decrypt,
    RSA_public_encrypt, RSA_size, RSA_up_ref,
};
use crate::rsa::Rsa;
use crate::runtime::err::err_reasons::{RSA_R_DATA_TOO_LARGE_FOR_MODULUS, RSA_R_DATA_TOO_SMALL};
use crate::runtime::err::{err_sites, raise_site, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc, OPENSSL_cleanse};
use crate::runtime::str::OPENSSL_strcasecmp;

/// The unit's own `__FILE__`. `rsa_kem.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path (D235's finding).
const FILE: *const c_char = c"providers/implementations/kem/rsa_kem.c".as_ptr();

/// `KEM_OP_UNDEFINED` — `rsa_kem.c:52`. The authority defines it as the pair of `KEM_OP_RSASVE`,
/// but no path in the unit reads it; transcribed so the pair is whole.
#[allow(dead_code)] // defined by the authority, unread by the authority's own code too
const KEM_OP_UNDEFINED: c_int = -1;

/// `KEM_OP_RSASVE` — `rsa_kem.c:53`. The only operation the map can produce, and the value
/// `rsakem_newctx` seeds.
const KEM_OP_RSASVE: c_int = 0;

/// `OSSL_KEM_PARAM_OPERATION_RSASVE` — `core_names.h:117`, the name the `operation` parameter
/// accepts.
const OSSL_KEM_PARAM_OPERATION_RSASVE: *const c_char = c"RSASVE".as_ptr();

/// `PROV_RSA_CTX` — `rsa_kem.c:60-65`. The `OSSL_FIPS_IND_DECLARE` at the foot is empty on this
/// profile.
#[repr(C)]
struct ProvRsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `RSA *rsa` — a borrow carrying a reference.
    rsa: *mut Rsa,
    /// `int op` — one of `KEM_OP_*`.
    op: c_int,
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static const OSSL_ITEM rsakem_opname_id_map[]` — `rsa_kem.c:67-69`.
struct KemOpItem {
    id: c_int,
    ptr: *const c_char,
}

// SAFETY: `ptr` is a `'static` literal and nothing mutates the table.
unsafe impl Sync for KemOpItem {}

static RSAKEM_OPNAME_ID_MAP: [KemOpItem; 1] = [KemOpItem {
    id: KEM_OP_RSASVE,
    ptr: OSSL_KEM_PARAM_OPERATION_RSASVE,
}];

/// `static int name2id(const char *name, const OSSL_ITEM *map, size_t sz)` — `rsa_kem.c:71-83`.
///
/// # Safety
/// `name` is NULL or a NUL-terminated string; `map` holds `sz` items.
unsafe fn name2id(name: *const c_char, map: *const KemOpItem, sz: usize) -> c_int {
    if name.is_null() {
        return -1;
    }

    for i in 0..sz {
        // SAFETY: `i < sz`, so the item is in bounds; `name` is non-NULL.
        if unsafe { OPENSSL_strcasecmp((*map.add(i)).ptr, name) } == 0 {
            // SAFETY: as above, `i < sz`.
            return unsafe { (*map.add(i)).id };
        }
    }
    -1
}

/// `static int rsakem_opname2id(const char *name)` — `rsa_kem.c:85-88`.
///
/// # Safety
/// As [`name2id`].
unsafe fn rsakem_opname2id(name: *const c_char) -> c_int {
    // SAFETY: the table is `'static` and its length is its own.
    unsafe {
        name2id(
            name,
            RSAKEM_OPNAME_ID_MAP.as_ptr(),
            RSAKEM_OPNAME_ID_MAP.len(),
        )
    }
}

/// `static void *rsakem_newctx(void *provctx)` — `rsa_kem.c:90-105`.
///
/// # Safety
/// The kem `newctx` dispatch contract.
unsafe extern "C" fn rsakem_newctx(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }
    // SAFETY: a fresh zeroed allocation of this call's own context.
    let prsactx = CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 97).cast::<ProvRsaCtx>();
    if prsactx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `prsactx` is this call's own allocation.
    unsafe {
        (*prsactx).libctx = prov_libctx_of(provctx);
        (*prsactx).op = KEM_OP_RSASVE;
    }
    prsactx.cast()
}

/// `static void rsakem_freectx(void *vprsactx)` — `rsa_kem.c:107-113`.
///
/// # Safety
/// The kem `freectx` dispatch contract.
unsafe extern "C" fn rsakem_freectx(vprsactx: *mut c_void) {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is this call's context.
    unsafe {
        RSA_free((*prsactx).rsa);
        CRYPTO_free(prsactx.cast(), FILE, 112);
    }
}

/// `static void *rsakem_dupctx(void *vprsactx)` — `rsa_kem.c:115-133`.
///
/// # Safety
/// The kem `dupctx` dispatch contract.
unsafe extern "C" fn rsakem_dupctx(vprsactx: *mut c_void) -> *mut c_void {
    let srcctx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's context.
    unsafe {
        let dstctx =
            CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 123).cast::<ProvRsaCtx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        // The authority's `*dstctx = *srcctx` is a whole-struct assignment; the pointer copy is
        // that assignment, and the borrowed `rsa` is then up-ref'd in place.
        core::ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        if !(*dstctx).rsa.is_null() && RSA_up_ref((*dstctx).rsa) == 0 {
            CRYPTO_free(dstctx.cast(), FILE, 129);
            return ptr::null_mut();
        }
        dstctx.cast()
    }
}

/// `static int rsakem_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[], int operation,
/// const char *desc)` — `rsa_kem.c:135-178`, without the `FIPS_MODULE` tail (`:171-176`).
///
/// # Safety
/// The kem `encapsulate_init`/`decapsulate_init` dispatch contract.
unsafe fn rsakem_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    _desc: *const c_char,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut protect: c_int = 0;

    if is_running() == 0 {
        return 0;
    }
    if prsactx.is_null() || vrsa.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context and `vrsa` is the caller's key.
    unsafe {
        if ossl_rsa_key_op_get_protect(vrsa.cast::<Rsa>(), operation, &mut protect) == 0 {
            return 0;
        }
        if RSA_up_ref(vrsa.cast::<Rsa>()) == 0 {
            return 0;
        }
        RSA_free((*prsactx).rsa);
        (*prsactx).rsa = vrsa.cast::<Rsa>();

        /*
         * Reject the trivial public exponent e <= 1. The FIPS module enforces the
         * full SP 800-56B §6.4.1.1 constraints via ossl_fips_ind_rsa_key_check()
         * below; non-FIPS callers wanting the complete §6.4.2 vetting can use
         * EVP_PKEY_public_check().
         */
        let mut e: *const BigNum = ptr::null();
        RSA_get0_key((*prsactx).rsa, ptr::null_mut(), &mut e, ptr::null_mut());
        if e.is_null() || BN_cmp(e, BN_value_one()) <= 0 {
            raise_site(&err_sites::PROV_RSA_KEM_162);
            return 0;
        }

        if rsakem_set_ctx_params(prsactx.cast(), params) == 0 {
            return 0;
        }
    }

    1
}

/// `static int rsakem_encapsulate_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_kem.c:180-183`.
///
/// # Safety
/// The kem `encapsulate_init` dispatch contract.
unsafe extern "C" fn rsakem_encapsulate_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsakem_init(
            vprsactx,
            vrsa,
            params,
            EVP_PKEY_OP_ENCAPSULATE,
            c"RSA Encapsulate Init".as_ptr(),
        )
    }
}

/// `static int rsakem_decapsulate_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_kem.c:185-190`.
///
/// # Safety
/// The kem `decapsulate_init` dispatch contract.
unsafe extern "C" fn rsakem_decapsulate_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsakem_init(
            vprsactx,
            vrsa,
            params,
            EVP_PKEY_OP_DECAPSULATE,
            c"RSA Decapsulate Init".as_ptr(),
        )
    }
}

/// `rsakem_get_ctx_params_decoder` — the generated get decoder at `rsa_kem.c:213-237`.
///
/// On this profile the generated struct is `{ int dummy; }` and the loop body is the bare `;` of the
/// `#else` arm: the decoder scans the array and writes nothing, so every array — including a NULL
/// one — decodes to the same empty result and the function's answer is always success. The one key
/// it could recognise, `fips-indicator`, exists only under `FIPS_MODULE`.
fn rsakem_get_ctx_params_decoder(_params: *const OsslParam) -> bool {
    true
}

/// `static const OSSL_PARAM rsakem_get_ctx_params_list[]` — `rsa_kem.c:195-200`, without its
/// `FIPS_MODULE` entry: an empty list on this profile.
static RSAKEM_GET_CTX_PARAMS_LIST: [OsslParam; 1] = [END];

/// `static int rsakem_get_ctx_params(void *vprsactx, OSSL_PARAM *params)` — `rsa_kem.c:241-252`,
/// without the `OSSL_FIPS_IND_GET_CTX_FROM_PARAM` call (a no-op here).
///
/// # Safety
/// The kem `get_ctx_params` dispatch contract.
unsafe extern "C" fn rsakem_get_ctx_params(
    vprsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let ctx = vprsactx.cast::<ProvRsaCtx>();

    if ctx.is_null() || !rsakem_get_ctx_params_decoder(params) {
        return 0;
    }
    1
}

/// `static const OSSL_PARAM *rsakem_gettable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_kem.c:254-258`.
///
/// # Safety
/// The kem `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn rsakem_gettable_ctx_params(
    _vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSAKEM_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct rsakem_set_ctx_params_st` — `rsa_kem.c:272-279`, without its `FIPS_MODULE` `ind_k` field.
#[derive(Clone, Copy)]
struct SetCtxParams {
    op: *const OsslParam,
}

/// `rsakem_set_ctx_params_decoder` — the generated set decoder at `rsa_kem.c:281-319`, without its
/// `FIPS_MODULE` `key-check` arm.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsakem_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams { op: ptr::null() };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            if s == b"operation" {
                if !r.op.is_null() {
                    raise_site(&err_sites::PROV_RSA_KEM_310);
                    return None;
                }
                r.op = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsakem_set_ctx_params_list[]` — `rsa_kem.c:263-269`, without its
/// `FIPS_MODULE` entry.
static RSAKEM_SET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_utf8_string(OSSL_KEM_PARAM_OPERATION), END];

/// `static int rsakem_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])` —
/// `rsa_kem.c:323-346`, without the two `OSSL_FIPS_IND_SET_CTX_FROM_PARAM` calls (a no-op here).
///
/// # Safety
/// The kem `set_ctx_params` dispatch contract.
unsafe extern "C" fn rsakem_set_ctx_params(
    vprsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if prsactx.is_null() {
        return 0;
    }
    // SAFETY: `prsactx` is the caller's context; `params` is a terminated array.
    let Some(p) = (unsafe { rsakem_set_ctx_params_decoder(params) }) else {
        return 0;
    };

    if !p.op.is_null() {
        // SAFETY: `p.op` is a parameter in the caller's array.
        unsafe {
            if (*p.op).data_type != OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            let op = rsakem_opname2id((*p.op).data.cast());
            if op < 0 {
                return 0;
            }
            (*prsactx).op = op;
        }
    }
    1
}

/// `static const OSSL_PARAM *rsakem_settable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_kem.c:348-352`.
///
/// # Safety
/// The kem `settable_ctx_params` dispatch contract.
unsafe extern "C" fn rsakem_settable_ctx_params(
    _vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSAKEM_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int rsasve_gen_rand_bytes(RSA *rsa_pub, unsigned char *out, int outlen)` —
/// `rsa_kem.c:262-291`.
///
/// # Safety
/// `rsa_pub` is a live key; `out` holds `outlen` writable bytes.
unsafe fn rsasve_gen_rand_bytes(rsa_pub: *mut Rsa, out: *mut u8, outlen: c_int) -> c_int {
    // SAFETY: `rsa_pub` is live per the contract.
    let bnctx = unsafe { BN_CTX_secure_new_ex(ossl_rsa_get0_libctx(rsa_pub)) };
    if bnctx.is_null() {
        return 0;
    }

    // SAFETY: `bnctx` is this call's own context; the temporaries live until `BN_CTX_end`.
    unsafe {
        /*
         * Generate a random in the range 1 < z < (n – 1).
         * Since BN_priv_rand_range_ex() returns a value in range 0 <= r < max
         * We can achieve this by adding 2.. but then we need to subtract 3 from
         * the upper bound i.e: 2 + (0 <= r < (n - 3))
         */
        BN_CTX_start(bnctx);
        let nminus3 = BN_CTX_get(bnctx);
        let z = BN_CTX_get(bnctx);
        let ret = c_int::from(
            !z.is_null()
                && !BN_copy(nminus3, RSA_get0_n(rsa_pub)).is_null()
                && BN_sub_word(nminus3, 3) != 0
                && BN_priv_rand_range_ex(z, nminus3, 0, bnctx) != 0
                && BN_add_word(z, 2) != 0
                && BN_bn2binpad(z, out, outlen) == outlen,
        );
        BN_CTX_end(bnctx);
        BN_CTX_free(bnctx);
        ret
    }
}

/// `static int rsasve_generate(PROV_RSA_CTX *prsactx, unsigned char *out, size_t *outlen, unsigned
/// char *secret, size_t *secretlen)` — `rsa_kem.c:297-352`.
///
/// # Safety
/// The kem `encapsulate` dispatch contract.
unsafe fn rsasve_generate(
    prsactx: *mut ProvRsaCtx,
    out: *mut u8,
    outlen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        /* Step (1): nlen = Ceil(len(n)/8) */
        let nlen = RSA_size((*prsactx).rsa) as usize;

        if out.is_null() {
            if nlen == 0 {
                raise_site(&err_sites::PROV_RSA_KEM_406);
                return 0;
            }
            if outlen.is_null() && secretlen.is_null() {
                return 0;
            }
            if !outlen.is_null() {
                *outlen = nlen;
            }
            if !secretlen.is_null() {
                *secretlen = nlen;
            }
            return 1;
        }

        /*
         * If outlen is specified, then it must report the length
         * of the out buffer on input so that we can confirm
         * its size is sufficient for encapsulation
         */
        if !outlen.is_null() && *outlen < nlen {
            raise_site(&err_sites::PROV_RSA_KEM_424);
            return 0;
        }

        /*
         * Step (2): Generate a random byte string z of nlen bytes where
         *            1 < z < n - 1
         */
        if rsasve_gen_rand_bytes((*prsactx).rsa, secret, nlen as c_int) == 0 {
            return 0;
        }

        /* Step(3): out = RSAEP((n,e), z) */
        let ret = RSA_public_encrypt(nlen as c_int, secret, out, (*prsactx).rsa, RSA_NO_PADDING);
        if ret <= 0 || ret != nlen as c_int {
            OPENSSL_cleanse(secret.cast(), nlen);
            return 0;
        }

        if !outlen.is_null() {
            *outlen = nlen;
        }
        if !secretlen.is_null() {
            *secretlen = nlen;
        }

        1
    }
}

/// `static int rsasve_recover(PROV_RSA_CTX *prsactx, unsigned char *out, size_t *outlen, const
/// unsigned char *in, size_t inlen)` — `rsa_kem.c:374-455`, including the non-FIPS
/// degenerate-ciphertext guard (`:412-448`).
///
/// # Safety
/// The kem `decapsulate` dispatch contract.
unsafe fn rsasve_recover(
    prsactx: *mut ProvRsaCtx,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        /* Step (1): get the byte length of n */
        let nlen = RSA_size((*prsactx).rsa) as usize;

        if out.is_null() {
            if nlen == 0 {
                raise_site(&err_sites::PROV_RSA_KEM_483);
                return 0;
            }
            *outlen = nlen;
            return 1;
        }

        /*
         * Step (2): check the input ciphertext 'inlen' matches the nlen
         * and that outlen is at least nlen bytes
         */
        if inlen != nlen {
            raise_site(&err_sites::PROV_RSA_KEM_495);
            return 0;
        }

        /*
         * If outlen is specified, then it must report the length
         * of the out buffer, so that we can confirm that it is of
         * sufficient size to hold the output of decapsulation
         */
        if !outlen.is_null() && *outlen < nlen {
            raise_site(&err_sites::PROV_RSA_KEM_505);
            return 0;
        }

        /*
         * Reject clearly degenerate ciphertexts, c in {0, 1, n-1}.
         *
         * SP 800-56B Rev 2, 7.1.2.1 requires RSADP to enforce 1 < c < n-1.  In a
         * FIPS build that bound is applied by the RSADP primitive itself (see
         * crypto/rsa/rsa_ossl.c, guarded by FIPS_MODULE), where it is also needed
         * for KTS-OAEP; the primitive does not apply it in a non-FIPS build, so
         * enforce it here for RSASVE.  Raise the same errors as the primitive so
         * the behaviour matches in both builds; keep the two sites in step.
         */
        {
            let n = RSA_get0_n((*prsactx).rsa);
            let c = BN_new();
            let nminus1 = BN_new();
            let mut reason: c_int = 0;

            if n.is_null()
                || c.is_null()
                || nminus1.is_null()
                || BN_bin2bn(input, inlen as c_int, c).is_null()
                || BN_copy(nminus1, n).is_null()
                || BN_sub_word(nminus1, 1) == 0
            {
                BN_free(c);
                BN_free(nminus1);
                return 0;
            }
            if BN_ucmp(c, BN_value_one()) <= 0 {
                reason = RSA_R_DATA_TOO_SMALL;
            } else if BN_ucmp(c, nminus1) >= 0 {
                reason = RSA_R_DATA_TOO_LARGE_FOR_MODULUS;
            }
            BN_free(c);
            BN_free(nminus1);
            if reason != 0 {
                raise_site_dynamic(&err_sites::PROV_RSA_KEM_541, reason);
                return 0;
            }
        }

        /* Step (3): out = RSADP((n,d), in) */
        let ret = RSA_private_decrypt(inlen as c_int, input, out, (*prsactx).rsa, RSA_NO_PADDING);
        if ret > 0 && !outlen.is_null() {
            *outlen = ret as usize;
        }
        c_int::from(ret > 0)
    }
}

/// `static int rsakem_generate(void *vprsactx, unsigned char *out, size_t *outlen, unsigned char
/// *secret, size_t *secretlen)` — `rsa_kem.c:554-571`.
///
/// # Safety
/// The kem `encapsulate` dispatch contract.
unsafe extern "C" fn rsakem_generate(
    vprsactx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        match (*prsactx).op {
            KEM_OP_RSASVE => rsasve_generate(prsactx, out, outlen, secret, secretlen),
            _ => -2,
        }
    }
}

/// `static int rsakem_recover(void *vprsactx, unsigned char *out, size_t *outlen, const unsigned
/// char *in, size_t inlen)` — `rsa_kem.c:573-590`.
///
/// # Safety
/// The kem `decapsulate` dispatch contract.
unsafe extern "C" fn rsakem_recover(
    vprsactx: *mut c_void,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        match (*prsactx).op {
            KEM_OP_RSASVE => rsasve_recover(prsactx, out, outlen, input, inlen),
            _ => -2,
        }
    }
}

/// `const OSSL_DISPATCH ossl_rsa_asym_kem_functions[]` — `rsa_kem.c:592-619`.
#[rustfmt::skip]
pub(crate) static RSA_ASYM_KEM_FUNCTIONS: [OsslDispatch; 12] = [
    OsslDispatch { function_id: OSSL_FUNC_KEM_NEWCTX, function: rsakem_newctx as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_ENCAPSULATE_INIT, function: rsakem_encapsulate_init as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_ENCAPSULATE, function: rsakem_generate as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_DECAPSULATE_INIT, function: rsakem_decapsulate_init as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_DECAPSULATE, function: rsakem_recover as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_FREECTX, function: rsakem_freectx as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_DUPCTX, function: rsakem_dupctx as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_GET_CTX_PARAMS, function: rsakem_get_ctx_params as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, function: rsakem_gettable_ctx_params as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_SET_CTX_PARAMS, function: rsakem_set_ctx_params as *mut c_void },
    OsslDispatch { function_id: OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, function: rsakem_settable_ctx_params as *mut c_void },
    OsslDispatch { function_id: OSSL_DISPATCH_END, function: ptr::null_mut() },
];
