//! Phase 8 — `providers/implementations/signature/rsa_sig.c`: the fourteen `RSA`
//! `OSSL_OP_SIGNATURE` rows.
//!
//! One thousand five hundred and thirty-one source lines and thirty dispatch slots. The unit is
//! the `RSA` face of the `RSA` key object `src/provider/rsa_kmgmt.rs` publishes (D391):
//! `PROV_RSA_CTX` holds an `RSA` borrow, an `EVP_MD`/`EVP_MD_CTX` pair for the message-digest path,
//! an MGF1 `EVP_MD` for PSS, the PSS salt length, and a working buffer. The plain `RSA` row is
//! `rsa_sign_init`/`rsa_verify_init` over `RSA_sign`/`RSA_verify` and the PSS pair; the thirteen
//! `RSA-<MD>` sigalgs are one implementation with the digest name, the operation and the pad mode
//! fixed at the call site.
//!
//! ## The three non-FIPS prerequisites, all landed with this unit
//!
//! `rsa_setup_md` calls `ossl_digest_rsa_sign_get_md_nid` (`:394`, `:485`, `src/provider/securitycheck_default.rs`);
//! `rsa_signverify_init` calls `ossl_rsa_key_op_get_protect` (`:530`, `src/provider/securitycheck.rs`);
//! and `rsa_generate_signature_aid` chooses between `ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption`
//! (`:331`, `src/provider/der_rsa_sig.rs`) and `ossl_DER_w_algorithmIdentifier_RSA_PSS` (`:353`,
//! `src/provider/der_rsa_key.rs`) on the pad mode. **The last of those is a correction to the
//! plan's map**, which put the PSS writer in `der_rsa_sig.c`; it is `der_rsa_key.c`'s, and that
//! whole unit is transcribed rather than one function pulled out of it.
//!
//! ## The FIPS arms, and the flags that are left
//!
//! Every `OSSL_FIPS_IND_*` macro and the four `OSSL_FIPS_IND_SETTABLE*` indicators are no-ops or
//! literals when `FIPS_MODULE` is undefined, so the `fips`-typed keys the generated decoders carry
//! are **absent from the tables here** and the `verify_message` lane and the `rsa_x931_padding_allowed`
//! refusal are not emitted. The six `unsigned int : 1` flags (`flag_sigalg`, `flag_allow_md`,
//! `mgf1_md_set`, `flag_allow_update`, `flag_allow_final`, `flag_allow_oneshot`) are one storage
//! lane with six bits, packed as the authority packs them.
//!
//! ## The one arm that is a cast
//!
//! `rsa_sign_message_final` passes an **uninitialised** `digest` to `rsa_sign_directly` when
//! `sig == NULL`, because that call returns before it reads the buffer. Rust has no
//! equivalent of "uninitialised but never read", so the buffer is zeroed and the module says so
//! rather than leaving a `MaybeUninit` the callee's early return makes safe.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_params, EVP_MD_CTX_new, EVP_MD_CTX_set_params, EVP_MD_fetch, EVP_MD_free,
    EVP_MD_get_size, EVP_MD_gettable_ctx_params, EVP_MD_is_a, EVP_MD_settable_ctx_params,
    EVP_MD_up_ref, EVP_MD_xof, EvpMd, EvpMdCtx,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFY, EVP_PKEY_OP_VERIFYMSG,
    EVP_PKEY_OP_VERIFYRECOVER, RSA_NO_PADDING, RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING,
    RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX,
    RSA_X931_PADDING,
};
use crate::evp::signature::{
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
    OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_INIT, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
    OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
};
use crate::packet::{
    WPACKET_cleanup, WPACKET_finish, WPACKET_get_curr, WPACKET_get_total_written, WPACKET_init_der,
    Wpacket,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_int,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_string, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string, OsslParam, END,
    OSSL_PARAM_UTF8_STRING,
};
use crate::provider::cipher::{param_int, param_octet_string, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::der_rsa_key::ossl_DER_w_algorithmIdentifier_RSA_PSS;
use crate::provider::der_rsa_sig::ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption;
use crate::provider::securitycheck::ossl_rsa_key_op_get_protect;
use crate::provider::securitycheck_default::ossl_digest_rsa_sign_get_md_nid;
use crate::rsa::object::{
    ossl_rsa_get0_pss_params_30, RSA_bits, RSA_free, RSA_private_encrypt, RSA_public_decrypt,
    RSA_size, RSA_test_flags, RSA_up_ref, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA,
    RSA_FLAG_TYPE_RSASSAPSS,
};
use crate::rsa::pss::{
    ossl_rsa_padding_add_PKCS1_PSS_mgf1, ossl_rsa_pss_params_30_hashalg,
    ossl_rsa_pss_params_30_is_unrestricted, ossl_rsa_pss_params_30_maskgenhashalg,
    ossl_rsa_pss_params_30_saltlen, ossl_rsa_pss_params_30_set_defaults,
    ossl_rsa_pss_params_30_set_hashalg, ossl_rsa_pss_params_30_set_maskgenhashalg,
    ossl_rsa_pss_params_30_set_saltlen, ossl_rsa_verify_PKCS1_PSS_mgf1,
};
use crate::rsa::schemes::ossl_rsa_oaeppss_nid2name;
use crate::rsa::sign::{ossl_rsa_verify, RSA_sign, RSA_sign_ASN1_OCTET_STRING, RSA_verify};
use crate::rsa::{RSA_X931_hash_id, Rsa, RsaPssParams30, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
    OPENSSL_cleanse,
};
use crate::runtime::obj::NID_undef;
use crate::runtime::str::{OPENSSL_strcasecmp, OPENSSL_strlcpy};

/// The unit's own `__FILE__`. `rsa_sig.c` is `.c.in`-generated, so the build compiles it from the
/// build tree and the compiler records the bare path (D235's finding).
const FILE: *const c_char = c"providers/implementations/signature/rsa_sig.c".as_ptr();

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_MAX_PROPQUERY_SIZE` — `include/internal/sizes.h:19`.
const OSSL_MAX_PROPQUERY_SIZE: usize = 256;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:449`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `RSA_DEFAULT_DIGEST_NAME` — `core_names.h:37`'s `OSSL_DIGEST_NAME_SHA1`.
const RSA_DEFAULT_DIGEST_NAME: *const c_char = c"SHA1".as_ptr();

/// `OSSL_SIGNATURE_PARAM_ALGORITHM_ID` — `core_names.h:546`, which is
/// `OSSL_PKEY_PARAM_ALGORITHM_ID` (`"algorithm-id"`).
const OSSL_SIGNATURE_PARAM_ALGORITHM_ID: *const c_char = c"algorithm-id".as_ptr();

/// `OSSL_SIGNATURE_PARAM_PAD_MODE` — `core_names.h:566`, which is `"pad-mode"`.
const OSSL_SIGNATURE_PARAM_PAD_MODE: *const c_char = c"pad-mode".as_ptr();

/// `OSSL_SIGNATURE_PARAM_DIGEST` — `core_names.h:550`, which is `OSSL_PKEY_PARAM_DIGEST`.
const OSSL_SIGNATURE_PARAM_DIGEST: *const c_char = c"digest".as_ptr();

/// `OSSL_SIGNATURE_PARAM_MGF1_DIGEST` — `core_names.h:562`.
const OSSL_SIGNATURE_PARAM_PSS_SALTLEN: *const c_char = c"saltlen".as_ptr();

/// `OSSL_SIGNATURE_PARAM_MGF1_DIGEST` — `core_names.h:562`.
const OSSL_SIGNATURE_PARAM_MGF1_DIGEST: *const c_char = c"mgf1-digest".as_ptr();

/// `OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES` — `core_names.h:563`.
const OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES: *const c_char = c"mgf1-properties".as_ptr();

/// `OSSL_SIGNATURE_PARAM_PROPERTIES` — `core_names.h:567`, which is `"properties"`.
const OSSL_SIGNATURE_PARAM_PROPERTIES: *const c_char = c"properties".as_ptr();

/// `OSSL_SIGNATURE_PARAM_SIGNATURE` — `core_names.h:569`.
const OSSL_SIGNATURE_PARAM_SIGNATURE: *const c_char = c"signature".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_PKCSV15` — `core_names.h:89`.
const OSSL_PKEY_RSA_PAD_MODE_PKCSV15: *const c_char = c"pkcs1".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_NONE` — `core_names.h:88`.
const OSSL_PKEY_RSA_PAD_MODE_NONE: *const c_char = c"none".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_X931` — `core_names.h:91`.
const OSSL_PKEY_RSA_PAD_MODE_X931: *const c_char = c"x931".as_ptr();

/// `OSSL_PKEY_RSA_PAD_MODE_PSS` — `core_names.h:92`.
const OSSL_PKEY_RSA_PAD_MODE_PSS: *const c_char = c"pss".as_ptr();

/// `OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST` — `core_names.h:95`.
const OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST: *const c_char = c"digest".as_ptr();

/// `OSSL_PKEY_RSA_PSS_SALT_LEN_MAX` — `core_names.h:96`.
const OSSL_PKEY_RSA_PSS_SALT_LEN_MAX: *const c_char = c"max".as_ptr();

/// `OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO` — `core_names.h:97`.
const OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO: *const c_char = c"auto".as_ptr();

/// `OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX` — `core_names.h:98`.
const OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX: *const c_char = c"auto-digestmax".as_ptr();

/// `OSSL_DIGEST_NAME_MDC2` — `core_names.h:47`. `rsa_sign_directly` spells it directly for the
/// `RSA_sign_ASN1_OCTET_STRING` arm MDC2 takes.
const OSSL_DIGEST_NAME_MDC2: *const c_char = c"MDC2".as_ptr();

/// `OSSL_SIGNATURE_PARAM_FIPS_KEY_CHECK` — `core_names.h:554`, which is
/// `OSSL_PKEY_PARAM_FIPS_KEY_CHECK` (`"key-check"`). The key is in the settable *list* even
/// though its `fips`-typed descriptor is absent from this profile's decoder.
const OSSL_SIGNATURE_PARAM_FIPS_KEY_CHECK: *const c_char = c"key-check".as_ptr();

/// `OSSL_SIGNATURE_PARAM_FIPS_DIGEST_CHECK` — `core_names.h:553`, `"digest-check"`.
const OSSL_SIGNATURE_PARAM_FIPS_DIGEST_CHECK: *const c_char = c"digest-check".as_ptr();

/// `OSSL_SIGNATURE_PARAM_FIPS_RSA_PSS_SALTLEN_CHECK` — `core_names.h:555`.
const OSSL_SIGNATURE_PARAM_FIPS_RSA_PSS_SALTLEN_CHECK: *const c_char =
    c"rsa-pss-saltlen-check".as_ptr();

/// `OSSL_SIGNATURE_PARAM_FIPS_SIGN_X931_PAD_CHECK` — `core_names.h:557`.
const OSSL_SIGNATURE_PARAM_FIPS_SIGN_X931_PAD_CHECK: *const c_char =
    c"sign-x931-pad-check".as_ptr();

/// `padding_item[]` — `rsa_sig.c.in:74-80`, the pad-mode number/name map both directions of
/// `rsa_get_ctx_params` and `rsa_set_ctx_params` walk. The terminator's `{ 0, NULL }` is the
/// walk's stop condition, so the array is one longer than the four modes.
struct PaddingItem {
    id: c_int,
    ptr: *const c_char,
}

// SAFETY: every `ptr` is a `'static` literal and nothing mutates the table.
unsafe impl Sync for PaddingItem {}

static PADDING_ITEM: [PaddingItem; 5] = [
    PaddingItem {
        id: RSA_PKCS1_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_PKCSV15,
    },
    PaddingItem {
        id: RSA_NO_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_NONE,
    },
    PaddingItem {
        id: RSA_X931_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_X931,
    },
    PaddingItem {
        id: RSA_PKCS1_PSS_PADDING,
        ptr: OSSL_PKEY_RSA_PAD_MODE_PSS,
    },
    PaddingItem {
        id: 0,
        ptr: ptr::null(),
    },
];

/// `ossl_param_is_empty` — `include/internal/common.h`.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn ossl_param_is_empty(params: *const OsslParam) -> bool {
    if params.is_null() {
        return true;
    }
    // SAFETY: the first entry of a key-terminated array is readable.
    unsafe { (*params).key.is_null() }
}

/// `atoi` — `stdlib.h`'s, which `rsa_set_ctx_params` calls for a numeric salt length string. The
/// authority reaches libc directly; this reproduces its leading-whitespace, optional-sign,
/// stop-at-first-non-digit semantics.
///
/// # Safety
/// `s` is NULL or NUL-terminated.
unsafe fn atoi(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let mut i = 0usize;
    while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let mut neg = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let mut val: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        val = val * 10 + i64::from(bytes[i] - b'0');
        i += 1;
    }
    if neg {
        val = -val;
    }
    val as c_int
}

/// `flag_sigalg`, the first `unsigned int : 1` on the context's storage lane
/// (`rsa_sig.c.in:103`).
const FLAG_SIGALG: c_uint = 1;
/// `flag_allow_md` — `:112`.
const FLAG_ALLOW_MD: c_uint = 2;
/// `mgf1_md_set` — `:113`.
const FLAG_MGF1_MD_SET: c_uint = 4;
/// `flag_allow_update` — `:125`.
const FLAG_ALLOW_UPDATE: c_uint = 8;
/// `flag_allow_final` — `:126`.
const FLAG_ALLOW_FINAL: c_uint = 16;
/// `flag_allow_oneshot` — `:127`.
const FLAG_ALLOW_ONESHOT: c_uint = 32;

/// `PROV_RSA_CTX` — `rsa_sig.c.in:88-163`. The `OSSL_FIPS_IND_DECLARE` at the foot is empty on
/// this profile and the `FIPS_MODULE` `verify_message` lane is absent, so the context is exactly
/// this field list; the six bitfields share one `c_uint`.
#[repr(C)]
struct ProvRsaCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `char *propq` — owned.
    propq: *mut c_char,
    /// `RSA *rsa` — a borrow carrying a reference.
    rsa: *mut Rsa,
    /// `int operation` — reuses `EVP_PKEY_OP_*`.
    operation: c_int,
    /// The six `unsigned int : 1` flags.
    flags: c_uint,
    /// `EVP_MD *md`.
    md: *mut EvpMd,
    /// `EVP_MD_CTX *mdctx`.
    mdctx: *mut EvpMdCtx,
    /// `int mdnid`.
    mdnid: c_int,
    /// `char mdname[OSSL_MAX_NAME_SIZE]` — purely informational.
    mdname: [c_char; OSSL_MAX_NAME_SIZE],
    /// `int pad_mode`.
    pad_mode: c_int,
    /// `EVP_MD *mgf1_md`.
    mgf1_md: *mut EvpMd,
    /// `int mgf1_mdnid`.
    mgf1_mdnid: c_int,
    /// `char mgf1_mdname[OSSL_MAX_NAME_SIZE]` — purely informational.
    mgf1_mdname: [c_char; OSSL_MAX_NAME_SIZE],
    /// `int saltlen`.
    saltlen: c_int,
    /// `int min_saltlen` — or -1 when the PSS parameters are not restricted.
    min_saltlen: c_int,
    /// `unsigned char *sig` — for verification.
    sig: *mut u8,
    /// `size_t siglen`.
    siglen: usize,
    /// `unsigned char *tbuf` — the working buffer.
    tbuf: *mut u8,
}

/// `OSSL_FUNC_signature_set_ctx_params_fn` — the callback `rsa_signverify_init` and
/// `rsa_sigalg_signverify_init` take.
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;

/// `rsa_pss_restricted(prsactx)` — `rsa_sig.c.in:166`.
#[inline]
unsafe fn rsa_pss_restricted(ctx: *const ProvRsaCtx) -> bool {
    // SAFETY: `ctx` is the caller's context.
    unsafe { (*ctx).min_saltlen != -1 }
}

/// `ossl_prov_is_running()` — the literal 1 on this build.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static int rsa_get_md_size(const PROV_RSA_CTX *prsactx)` — `rsa_sig.c.in:168-179`.
///
/// # Safety
/// `prsactx` is live.
unsafe fn rsa_get_md_size(prsactx: *const ProvRsaCtx) -> c_int {
    // SAFETY: `prsactx` is live per the contract.
    unsafe {
        if !(*prsactx).md.is_null() {
            let md_size = EVP_MD_get_size((*prsactx).md);
            if md_size <= 0 {
                return 0;
            }
            return md_size;
        }
    }
    0
}

/// `static int rsa_check_padding(const PROV_RSA_CTX *prsactx, const char *mdname, const char
/// *mgf1_mdname, int mdnid)` — `rsa_sig.c.in:181-212`.
///
/// # Safety
/// `prsactx` is live; `mdname`/`mgf1_mdname` are NULL or NUL-terminated.
unsafe fn rsa_check_padding(
    prsactx: *const ProvRsaCtx,
    mdname: *const c_char,
    mgf1_mdname: *const c_char,
    mdnid: c_int,
) -> c_int {
    // SAFETY: `prsactx` is live per the contract and `md` may be NULL.
    unsafe {
        match (*prsactx).pad_mode {
            RSA_NO_PADDING => {
                if !mdname.is_null() || mdnid != NID_undef {
                    raise_site(&err_sites::PROV_RSA_SIG_186);
                    return 0;
                }
            }
            RSA_X931_PADDING => {
                if crate::rsa::RSA_X931_hash_id(mdnid) == -1 {
                    raise_site(&err_sites::PROV_RSA_SIG_192);
                    return 0;
                }
            }
            RSA_PKCS1_PSS_PADDING
                if rsa_pss_restricted(prsactx)
                    && ((!mdname.is_null() && EVP_MD_is_a((*prsactx).md, mdname) == 0)
                        || (!mgf1_mdname.is_null()
                            && EVP_MD_is_a((*prsactx).mgf1_md, mgf1_mdname) == 0)) =>
            {
                raise_site(&err_sites::PROV_RSA_SIG_201);
                return 0;
            }
            _ => {}
        }
    }

    1
}

/// `static int rsa_check_parameters(PROV_RSA_CTX *prsactx, int min_saltlen)` —
/// `rsa_sig.c.in:214-230`.
///
/// # Safety
/// `prsactx` is live.
unsafe fn rsa_check_parameters(prsactx: *mut ProvRsaCtx, min_saltlen: c_int) -> c_int {
    // SAFETY: `prsactx` is live per the contract.
    unsafe {
        if (*prsactx).pad_mode == RSA_PKCS1_PSS_PADDING {
            /* See if minimum salt length exceeds maximum possible */
            let mut max_saltlen = RSA_size((*prsactx).rsa) - EVP_MD_get_size((*prsactx).md);
            if (RSA_bits((*prsactx).rsa) & 0x7) == 1 {
                max_saltlen -= 1;
            }
            if min_saltlen < 0 || min_saltlen > max_saltlen {
                raise_site(&err_sites::PROV_RSA_SIG_222);
                return 0;
            }
            (*prsactx).min_saltlen = min_saltlen;
        }
    }
    1
}

/// `static void *rsa_newctx(void *provctx, const char *propq)` — `rsa_sig.c.in:232-258`.
///
/// # Safety
/// The signature `newctx` dispatch contract; `propq` is NULL or NUL-terminated.
unsafe extern "C" fn rsa_newctx(provctx: *mut c_void, propq: *const c_char) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let prsactx = CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 238).cast::<ProvRsaCtx>();
    if prsactx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `prsactx` is this call's own allocation; `propq` is NULL or NUL-terminated.
    unsafe {
        let mut propq_copy: *mut c_char = ptr::null_mut();
        if !propq.is_null() {
            propq_copy = CRYPTO_strdup(propq, FILE, 240);
            if propq_copy.is_null() {
                CRYPTO_free(prsactx.cast(), FILE, 241);
                return ptr::null_mut();
            }
        }

        (*prsactx).libctx = prov_libctx_of(provctx);
        (*prsactx).flags = FLAG_ALLOW_MD;
        (*prsactx).propq = propq_copy;
        /* Maximum up to digest length for sign, auto for verify */
        (*prsactx).saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
        (*prsactx).min_saltlen = -1;
    }

    prsactx.cast()
}

/// `static int rsa_pss_compute_saltlen(PROV_RSA_CTX *ctx)` — `rsa_sig.c.in:260-311`.
///
/// # Safety
/// `ctx` is live.
unsafe fn rsa_pss_compute_saltlen(ctx: *mut ProvRsaCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let mut saltlen = unsafe { (*ctx).saltlen };
    let mut saltlen_max: c_int = -1;

    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if saltlen == RSA_PSS_SALTLEN_DIGEST {
            saltlen = EVP_MD_get_size((*ctx).md);
            if saltlen <= 0 {
                raise_site(&err_sites::PROV_RSA_SIG_272);
                return -1;
            }
        } else if saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
            saltlen = RSA_PSS_SALTLEN_MAX;
            saltlen_max = EVP_MD_get_size((*ctx).md);
            if saltlen_max <= 0 {
                raise_site(&err_sites::PROV_RSA_SIG_278);
                return -1;
            }
        }
        if saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO {
            let mdsize = EVP_MD_get_size((*ctx).md);
            if mdsize <= 0 {
                raise_site(&err_sites::PROV_RSA_SIG_286);
                return -1;
            }
            let rsasize = RSA_size((*ctx).rsa);
            if rsasize <= 2 || rsasize - 2 < mdsize {
                raise_site(&err_sites::PROV_RSA_SIG_290);
                return -1;
            }
            saltlen = rsasize - mdsize - 2;
            if (RSA_bits((*ctx).rsa) & 0x7) == 1 {
                saltlen -= 1;
            }
            if saltlen_max >= 0 && saltlen > saltlen_max {
                saltlen = saltlen_max;
            }
        }
        if saltlen < 0 {
            raise_site(&err_sites::PROV_RSA_SIG_300);
            return -1;
        } else if saltlen < (*ctx).min_saltlen {
            let mut msg = [0u8; 96];
            BIO_snprintf(
                msg.as_mut_ptr().cast(),
                msg.len(),
                c"minimum salt length: %d, actual salt length: %d".as_ptr(),
                (*ctx).min_saltlen,
                saltlen,
            );
            raise_site_data(&err_sites::PROV_RSA_SIG_303, msg.as_ptr().cast());
            return -1;
        }
    }
    saltlen
}

/// `static unsigned char *rsa_generate_signature_aid(PROV_RSA_CTX *ctx, unsigned char *aid_buf,
/// size_t buf_len, size_t *aid_len)` — `rsa_sig.c.in:313-373`.
///
/// The returned pointer is into the caller's `aid_buf`, exactly as in the authority, where the
/// `WPACKET` writes into that buffer and `WPACKET_get_curr` names the sequence's first byte.
///
/// # Safety
/// `ctx` is live; `aid_buf` is writable for `buf_len` bytes; `aid_len` is writable.
unsafe fn rsa_generate_signature_aid(
    ctx: *mut ProvRsaCtx,
    aid_buf: *mut u8,
    buf_len: usize,
    aid_len: *mut usize,
) -> *mut u8 {
    let mut pkt = core::mem::MaybeUninit::<Wpacket>::uninit();

    // SAFETY: `pkt` is a live local and `aid_buf` is the caller's.
    unsafe {
        if WPACKET_init_der(pkt.as_mut_ptr(), aid_buf, buf_len) == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_323);
            return ptr::null_mut();
        }
        let pkt = pkt.as_mut_ptr();

        match (*ctx).pad_mode {
            RSA_PKCS1_PADDING => {
                let ret = ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption(pkt, -1, (*ctx).mdnid);
                if ret <= 0 {
                    if ret == 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_335);
                        WPACKET_cleanup(pkt);
                        return ptr::null_mut();
                    }
                    let mut msg = [0u8; 64];
                    BIO_snprintf(
                        msg.as_mut_ptr().cast(),
                        msg.len(),
                        c"Algorithm ID generation - md NID: %d".as_ptr(),
                        (*ctx).mdnid,
                    );
                    raise_site_data(&err_sites::PROV_RSA_SIG_338, msg.as_ptr().cast());
                    WPACKET_cleanup(pkt);
                    return ptr::null_mut();
                }
            }
            RSA_PKCS1_PSS_PADDING => {
                let saltlen = rsa_pss_compute_saltlen(ctx);
                if saltlen < 0 {
                    WPACKET_cleanup(pkt);
                    return ptr::null_mut();
                }
                let mut pss_params = core::mem::MaybeUninit::<RsaPssParams30>::uninit();
                let pss = pss_params.as_mut_ptr();
                if ossl_rsa_pss_params_30_set_defaults(pss) == 0
                    || ossl_rsa_pss_params_30_set_hashalg(pss, (*ctx).mdnid) == 0
                    || ossl_rsa_pss_params_30_set_maskgenhashalg(pss, (*ctx).mgf1_mdnid) == 0
                    || ossl_rsa_pss_params_30_set_saltlen(pss, saltlen) == 0
                    || ossl_DER_w_algorithmIdentifier_RSA_PSS(pkt, -1, RSA_FLAG_TYPE_RSASSAPSS, pss)
                        == 0
                {
                    raise_site(&err_sites::PROV_RSA_SIG_354);
                    WPACKET_cleanup(pkt);
                    return ptr::null_mut();
                }
            }
            _ => {
                let mut msg = [0u8; 64];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"Algorithm ID generation - pad mode: %d".as_ptr(),
                    (*ctx).pad_mode,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_359, msg.as_ptr().cast());
                WPACKET_cleanup(pkt);
                return ptr::null_mut();
            }
        }

        let mut aid: *mut u8 = ptr::null_mut();
        if WPACKET_finish(pkt) != 0 {
            WPACKET_get_total_written(pkt, aid_len);
            aid = WPACKET_get_curr(pkt).cast::<u8>();
        }
        WPACKET_cleanup(pkt);
        aid
    }
}

/// `static int rsa_setup_md(PROV_RSA_CTX *ctx, const char *mdname, const char *mdprops, const char
/// *desc)` — `rsa_sig.c.in:375-467`. The `#ifdef FIPS_MODULE` block at `:410-424` is not this
/// profile's arm.
///
/// # Safety
/// `ctx` is live; the three name/queries are NULL or NUL-terminated.
unsafe fn rsa_setup_md(
    ctx: *mut ProvRsaCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
    _desc: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let mut mdprops = mdprops;
        if mdprops.is_null() {
            mdprops = (*ctx).propq;
        }

        if !mdname.is_null() {
            let mdname_len = CStr::from_ptr(mdname).to_bytes().len();

            let md = EVP_MD_fetch((*ctx).libctx, mdname, mdprops);
            if md.is_null() {
                let mut msg = [0u8; 160];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"%s could not be fetched".as_ptr(),
                    mdname,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_388, msg.as_ptr().cast());
                return rsa_setup_md_err(md);
            }
            let md_nid = ossl_digest_rsa_sign_get_md_nid(md);
            if md_nid == NID_undef {
                let mut msg = [0u8; 160];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"digest=%s".as_ptr(),
                    mdname,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_394, msg.as_ptr().cast());
                return rsa_setup_md_err(md);
            }
            if EVP_MD_xof(md) != 0 {
                raise_site(&err_sites::PROV_RSA_SIG_405);
                return rsa_setup_md_err(md);
            }

            if rsa_check_padding(ctx, mdname, ptr::null(), md_nid) == 0 {
                return rsa_setup_md_err(md);
            }
            if mdname_len >= OSSL_MAX_NAME_SIZE {
                let mut msg = [0u8; 160];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"%s exceeds name buffer length".as_ptr(),
                    mdname,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_427, msg.as_ptr().cast());
                return rsa_setup_md_err(md);
            }

            if (*ctx).flags & FLAG_ALLOW_MD == 0 {
                if (*ctx).mdname[0] != 0 && EVP_MD_is_a(md, (*ctx).mdname.as_ptr()) == 0 {
                    let mut msg = [0u8; 160];
                    BIO_snprintf(
                        msg.as_mut_ptr().cast(),
                        msg.len(),
                        c"digest %s != %s".as_ptr(),
                        mdname,
                        (*ctx).mdname.as_ptr(),
                    );
                    raise_site_data(&err_sites::PROV_RSA_SIG_434, msg.as_ptr().cast());
                    return rsa_setup_md_err(md);
                }
                EVP_MD_free(md);
                return 1;
            }

            if (*ctx).flags & FLAG_MGF1_MD_SET == 0 {
                if EVP_MD_up_ref(md) == 0 {
                    return rsa_setup_md_err(md);
                }
                EVP_MD_free((*ctx).mgf1_md);
                (*ctx).mgf1_md = md;
                (*ctx).mgf1_mdnid = md_nid;
                OPENSSL_strlcpy((*ctx).mgf1_mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
            }

            EVP_MD_CTX_free((*ctx).mdctx);
            EVP_MD_free((*ctx).md);

            (*ctx).mdctx = ptr::null_mut();
            (*ctx).md = md;
            (*ctx).mdnid = md_nid;
            OPENSSL_strlcpy((*ctx).mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
        }
    }

    1
}

/// The authority's `err:` arm (`rsa_sig.c.in:464-466`).
///
/// # Safety
/// `md` is NULL or a live fetched digest.
unsafe fn rsa_setup_md_err(md: *mut EvpMd) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { EVP_MD_free(md) };
    0
}

/// `static int rsa_setup_mgf1_md(PROV_RSA_CTX *ctx, const char *mdname, const char *mdprops)` —
/// `rsa_sig.c.in:469-506`.
///
/// # Safety
/// `ctx` is live; `mdname`/`mdprops` are NULL or NUL-terminated.
unsafe fn rsa_setup_mgf1_md(
    ctx: *mut ProvRsaCtx,
    mdname: *const c_char,
    mdprops: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let mut mdprops = mdprops;
        if mdprops.is_null() {
            mdprops = (*ctx).propq;
        }

        let md = EVP_MD_fetch((*ctx).libctx, mdname, mdprops);
        if md.is_null() {
            let mut msg = [0u8; 160];
            BIO_snprintf(
                msg.as_mut_ptr().cast(),
                msg.len(),
                c"%s could not be fetched".as_ptr(),
                mdname,
            );
            raise_site_data(&err_sites::PROV_RSA_SIG_478, msg.as_ptr().cast());
            return 0;
        }
        /* The default for mgf1 is SHA1 - so allow SHA1 */
        let mdnid = ossl_digest_rsa_sign_get_md_nid(md);
        if mdnid <= 0 || rsa_check_padding(ctx, ptr::null(), mdname, mdnid) == 0 {
            if mdnid <= 0 {
                let mut msg = [0u8; 160];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"digest=%s".as_ptr(),
                    mdname,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_486, msg.as_ptr().cast());
            }
            EVP_MD_free(md);
            return 0;
        }
        let len = OPENSSL_strlcpy((*ctx).mgf1_mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
        if len >= OSSL_MAX_NAME_SIZE {
            let mut msg = [0u8; 160];
            BIO_snprintf(
                msg.as_mut_ptr().cast(),
                msg.len(),
                c"%s exceeds name buffer length".as_ptr(),
                mdname,
            );
            raise_site_data(&err_sites::PROV_RSA_SIG_493, msg.as_ptr().cast());
            EVP_MD_free(md);
            return 0;
        }

        EVP_MD_free((*ctx).mgf1_md);
        (*ctx).mgf1_md = md;
        (*ctx).mgf1_mdnid = mdnid;
        (*ctx).flags |= FLAG_MGF1_MD_SET;
    }
    1
}

/// `static int rsa_signverify_init(PROV_RSA_CTX *prsactx, void *vrsa,
/// OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params, const OSSL_PARAM params[], int
/// operation, const char *desc)` — `rsa_sig.c.in:508-613`, without the `FIPS_MODULE` tail
/// (`:606-611`), which is `ossl_fips_ind_rsa_key_check`.
///
/// # Safety
/// The signature init dispatch contract.
unsafe fn rsa_signverify_init(
    prsactx: *mut ProvRsaCtx,
    vrsa: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let mut protect: c_int = 0;

    if is_running() == 0 || prsactx.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context; `vrsa` is NULL or the caller's key.
    unsafe {
        if vrsa.is_null() && (*prsactx).rsa.is_null() {
            raise_site(&err_sites::PROV_RSA_SIG_518);
            return 0;
        }

        if !vrsa.is_null() {
            let key = vrsa.cast::<Rsa>();
            if RSA_up_ref(key) == 0 {
                return 0;
            }
            RSA_free((*prsactx).rsa);
            (*prsactx).rsa = key;
        }
        if ossl_rsa_key_op_get_protect((*prsactx).rsa, operation, &mut protect) == 0 {
            return 0;
        }

        (*prsactx).operation = operation;
        (*prsactx).flags |= FLAG_ALLOW_UPDATE | FLAG_ALLOW_FINAL | FLAG_ALLOW_ONESHOT;

        /* Maximize up to digest length for sign, auto for verify */
        (*prsactx).saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
        (*prsactx).min_saltlen = -1;

        match RSA_test_flags((*prsactx).rsa, RSA_FLAG_TYPE_MASK) {
            RSA_FLAG_TYPE_RSA => {
                (*prsactx).pad_mode = RSA_PKCS1_PADDING;
            }
            RSA_FLAG_TYPE_RSASSAPSS => {
                (*prsactx).pad_mode = RSA_PKCS1_PSS_PADDING;

                let pss = ossl_rsa_get0_pss_params_30((*prsactx).rsa);
                if ossl_rsa_pss_params_30_is_unrestricted(pss) == 0 {
                    let md_nid = ossl_rsa_pss_params_30_hashalg(pss);
                    let mgf1md_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);
                    let min_saltlen = ossl_rsa_pss_params_30_saltlen(pss);

                    let mdname = ossl_rsa_oaeppss_nid2name(md_nid);
                    let mgf1mdname = ossl_rsa_oaeppss_nid2name(mgf1md_nid);

                    if mdname.is_null() {
                        raise_site_data(
                            &err_sites::PROV_RSA_SIG_561,
                            c"PSS restrictions lack hash algorithm".as_ptr(),
                        );
                        return 0;
                    }
                    if mgf1mdname.is_null() {
                        raise_site_data(
                            &err_sites::PROV_RSA_SIG_566,
                            c"PSS restrictions lack MGF1 hash algorithm".as_ptr(),
                        );
                        return 0;
                    }

                    let len =
                        OPENSSL_strlcpy((*prsactx).mdname.as_mut_ptr(), mdname, OSSL_MAX_NAME_SIZE);
                    if len >= OSSL_MAX_NAME_SIZE {
                        raise_site_data(
                            &err_sites::PROV_RSA_SIG_574,
                            c"hash algorithm name too long".as_ptr(),
                        );
                        return 0;
                    }
                    let len = OPENSSL_strlcpy(
                        (*prsactx).mgf1_mdname.as_mut_ptr(),
                        mgf1mdname,
                        OSSL_MAX_NAME_SIZE,
                    );
                    if len >= OSSL_MAX_NAME_SIZE {
                        raise_site_data(
                            &err_sites::PROV_RSA_SIG_581,
                            c"MGF1 hash algorithm name too long".as_ptr(),
                        );
                        return 0;
                    }
                    (*prsactx).saltlen = min_saltlen;

                    /* call rsa_setup_mgf1_md before rsa_setup_md to avoid duplication */
                    if rsa_setup_mgf1_md(prsactx, mgf1mdname, (*prsactx).propq) == 0
                        || rsa_setup_md(prsactx, mdname, (*prsactx).propq, desc) == 0
                        || rsa_check_parameters(prsactx, min_saltlen) == 0
                    {
                        return 0;
                    }
                }
            }
            _ => {
                raise_site(&err_sites::PROV_RSA_SIG_597);
                return 0;
            }
        }

        if set_ctx_params(prsactx.cast(), params) == 0 {
            return 0;
        }
    }

    1
}

/// `static int setup_tbuf(PROV_RSA_CTX *ctx)` — `rsa_sig.c.in:615-622`.
///
/// # Safety
/// `ctx` is live.
unsafe fn setup_tbuf(ctx: *mut ProvRsaCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if !(*ctx).tbuf.is_null() {
            return 1;
        }
        (*ctx).tbuf = CRYPTO_malloc(RSA_size((*ctx).rsa) as usize, FILE, 617).cast::<u8>();
        if (*ctx).tbuf.is_null() {
            return 0;
        }
    }
    1
}

/// `static void clean_tbuf(PROV_RSA_CTX *ctx)` — `rsa_sig.c.in:624-628`.
///
/// # Safety
/// `ctx` is live.
unsafe fn clean_tbuf(ctx: *mut ProvRsaCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if !(*ctx).tbuf.is_null() {
            OPENSSL_cleanse((*ctx).tbuf.cast(), RSA_size((*ctx).rsa) as usize);
        }
    }
}

/// `static void free_tbuf(PROV_RSA_CTX *ctx)` — `rsa_sig.c.in:630-635`.
///
/// # Safety
/// `ctx` is live.
unsafe fn free_tbuf(ctx: *mut ProvRsaCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        clean_tbuf(ctx);
        CRYPTO_free((*ctx).tbuf.cast(), FILE, 631);
        (*ctx).tbuf = ptr::null_mut();
    }
}

/// `static int rsa_sign_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_sig.c.in:663-674`.
///
/// # Safety
/// The signature `sign_init` dispatch contract.
unsafe extern "C" fn rsa_sign_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_signverify_init(
            vprsactx.cast(),
            vrsa,
            rsa_set_ctx_params,
            params,
            EVP_PKEY_OP_SIGN,
            c"RSA Sign Init".as_ptr(),
        )
    }
}

/// `static int rsa_sign_directly(PROV_RSA_CTX *prsactx, unsigned char *sig, size_t *siglen, size_t
/// sigsize, const unsigned char *tbs, size_t tbslen)` — `rsa_sig.c.in:681-829`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe fn rsa_sign_directly(
    prsactx: *mut ProvRsaCtx,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut ret: c_int;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        let rsasize = RSA_size((*prsactx).rsa) as usize;
        let mdsize = rsa_get_md_size(prsactx) as usize;

        if sig.is_null() {
            *siglen = rsasize;
            return 1;
        }

        if sigsize < rsasize {
            let mut msg = [0u8; 96];
            BIO_snprintf(
                msg.as_mut_ptr().cast(),
                msg.len(),
                c"is %zu, should be at least %zu".as_ptr(),
                sigsize,
                rsasize,
            );
            raise_site_data(&err_sites::PROV_RSA_SIG_696, msg.as_ptr().cast());
            return 0;
        }

        if mdsize != 0 {
            if tbslen != mdsize {
                raise_site(&err_sites::PROV_RSA_SIG_703);
                return 0;
            }

            if EVP_MD_is_a((*prsactx).md, OSSL_DIGEST_NAME_MDC2) != 0 {
                let mut sltmp: c_uint = 0;

                if (*prsactx).pad_mode != RSA_PKCS1_PADDING {
                    raise_site_data(
                        &err_sites::PROV_RSA_SIG_712,
                        c"only PKCS#1 padding supported with MDC2".as_ptr(),
                    );
                    return 0;
                }
                let r = RSA_sign_ASN1_OCTET_STRING(
                    0,
                    tbs,
                    tbslen as c_uint,
                    sig,
                    &mut sltmp,
                    (*prsactx).rsa,
                );
                if r <= 0 {
                    raise_site(&err_sites::PROV_RSA_SIG_720);
                    return 0;
                }
                ret = sltmp as c_int;
            } else {
                match (*prsactx).pad_mode {
                    RSA_X931_PADDING => {
                        if (RSA_size((*prsactx).rsa) as usize) < tbslen + 1 {
                            let mut msg = [0u8; 96];
                            BIO_snprintf(
                                msg.as_mut_ptr().cast(),
                                msg.len(),
                                c"RSA key size = %d, expected minimum = %d".as_ptr(),
                                RSA_size((*prsactx).rsa),
                                tbslen as c_int + 1,
                            );
                            raise_site_data(&err_sites::PROV_RSA_SIG_730, msg.as_ptr().cast());
                            return 0;
                        }
                        if setup_tbuf(prsactx) == 0 {
                            raise_site(&err_sites::PROV_RSA_SIG_736);
                            return 0;
                        }
                        ptr::copy_nonoverlapping(tbs, (*prsactx).tbuf, tbslen);
                        *(*prsactx).tbuf.add(tbslen) = RSA_X931_hash_id((*prsactx).mdnid) as u8;
                        ret = RSA_private_encrypt(
                            (tbslen + 1) as c_int,
                            (*prsactx).tbuf,
                            sig,
                            (*prsactx).rsa,
                            RSA_X931_PADDING,
                        );
                        clean_tbuf(prsactx);
                    }
                    RSA_PKCS1_PADDING => {
                        let mut sltmp: c_uint = 0;
                        ret = RSA_sign(
                            (*prsactx).mdnid,
                            tbs,
                            tbslen as c_uint,
                            sig,
                            &mut sltmp,
                            (*prsactx).rsa,
                        );
                        if ret <= 0 {
                            raise_site(&err_sites::PROV_RSA_SIG_751);
                            return 0;
                        }
                        ret = sltmp as c_int;
                    }
                    RSA_PKCS1_PSS_PADDING => {
                        if rsa_pss_restricted(prsactx) {
                            match (*prsactx).saltlen {
                                RSA_PSS_SALTLEN_DIGEST => {
                                    if (*prsactx).min_saltlen > EVP_MD_get_size((*prsactx).md) {
                                        let mut msg = [0u8; 128];
                                        BIO_snprintf(
                                            msg.as_mut_ptr().cast(),
                                            msg.len(),
                                            c"minimum salt length set to %d, but the digest only gives %d"
                                                .as_ptr(),
                                            (*prsactx).min_saltlen,
                                            EVP_MD_get_size((*prsactx).md),
                                        );
                                        raise_site_data(
                                            &err_sites::PROV_RSA_SIG_765,
                                            msg.as_ptr().cast(),
                                        );
                                        return 0;
                                    }
                                    if (*prsactx).saltlen >= 0
                                        && (*prsactx).saltlen < (*prsactx).min_saltlen
                                    {
                                        let mut msg = [0u8; 128];
                                        BIO_snprintf(
                                            msg.as_mut_ptr().cast(),
                                            msg.len(),
                                            c"minimum salt length set to %d, but theactual salt length is only set to %d"
                                                .as_ptr(),
                                            (*prsactx).min_saltlen,
                                            (*prsactx).saltlen,
                                        );
                                        raise_site_data(
                                            &err_sites::PROV_RSA_SIG_777,
                                            msg.as_ptr().cast(),
                                        );
                                        return 0;
                                    }
                                }
                                _ => {
                                    if (*prsactx).saltlen >= 0
                                        && (*prsactx).saltlen < (*prsactx).min_saltlen
                                    {
                                        let mut msg = [0u8; 128];
                                        BIO_snprintf(
                                            msg.as_mut_ptr().cast(),
                                            msg.len(),
                                            c"minimum salt length set to %d, but theactual salt length is only set to %d"
                                                .as_ptr(),
                                            (*prsactx).min_saltlen,
                                            (*prsactx).saltlen,
                                        );
                                        raise_site_data(
                                            &err_sites::PROV_RSA_SIG_777,
                                            msg.as_ptr().cast(),
                                        );
                                        return 0;
                                    }
                                }
                            }
                        }
                        if setup_tbuf(prsactx) == 0 {
                            return 0;
                        }
                        let mut saltlen = (*prsactx).saltlen;
                        if ossl_rsa_padding_add_PKCS1_PSS_mgf1(
                            (*prsactx).rsa,
                            (*prsactx).tbuf,
                            tbs,
                            (*prsactx).md,
                            (*prsactx).mgf1_md,
                            &mut saltlen,
                        ) == 0
                        {
                            raise_site(&err_sites::PROV_RSA_SIG_795);
                            return 0;
                        }
                        ret = RSA_private_encrypt(
                            RSA_size((*prsactx).rsa),
                            (*prsactx).tbuf,
                            sig,
                            (*prsactx).rsa,
                            RSA_NO_PADDING,
                        );
                        clean_tbuf(prsactx);
                    }
                    _ => {
                        raise_site_data(
                            &err_sites::PROV_RSA_SIG_808,
                            c"Only X.931, PKCS#1 v1.5 or PSS padding allowed".as_ptr(),
                        );
                        return 0;
                    }
                }
            }
        } else {
            ret = RSA_private_encrypt(
                tbslen as c_int,
                tbs,
                sig,
                (*prsactx).rsa,
                (*prsactx).pad_mode,
            );
        }

        if ret <= 0 {
            raise_site(&err_sites::PROV_RSA_SIG_821);
            return 0;
        }

        *siglen = ret as usize;
    }
    1
}

/// `static int rsa_signverify_message_update(void *vprsactx, const unsigned char *data, size_t
/// datalen)` — `rsa_sig.c.in:831-847`.
///
/// # Safety
/// The signature `sign_message_update`/`verify_message_update` dispatch contract.
unsafe extern "C" fn rsa_signverify_message_update(
    vprsactx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if prsactx.is_null() || (*prsactx).mdctx.is_null() {
            return 0;
        }

        if (*prsactx).flags & FLAG_ALLOW_UPDATE == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_839);
            return 0;
        }
        (*prsactx).flags &= !FLAG_ALLOW_ONESHOT;

        EVP_DigestUpdate((*prsactx).mdctx, data.cast(), datalen)
    }
}

/// `static int rsa_sign_message_final(void *vprsactx, unsigned char *sig, size_t *siglen, size_t
/// sigsize)` — `rsa_sig.c.in:849-883`.
///
/// # Safety
/// The signature `sign_message_final` dispatch contract.
unsafe extern "C" fn rsa_sign_message_final(
    vprsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    // The authority's `unsigned char digest[EVP_MAX_MD_SIZE]` is uninitialised when `sig == NULL`,
    // because `rsa_sign_directly` returns before reading it; Rust has no such state, so it is
    // zeroed and that early return is what makes the zeroing unobservable.
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 || prsactx.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).mdctx.is_null() {
            return 0;
        }
        if (*prsactx).flags & FLAG_ALLOW_FINAL == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_859);
            return 0;
        }

        /*
         * If sig is NULL then we're just finding out the sig size. Other fields
         * are ignored. Defer to rsa_sign.
         */
        if !sig.is_null() {
            if EVP_DigestFinal_ex((*prsactx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0 {
                return 0;
            }

            (*prsactx).flags &= !(FLAG_ALLOW_UPDATE | FLAG_ALLOW_ONESHOT | FLAG_ALLOW_FINAL);
        }

        rsa_sign_directly(
            prsactx,
            sig,
            siglen,
            sigsize,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `static int rsa_sign(void *vprsactx, unsigned char *sig, size_t *siglen, size_t sigsize, const
/// unsigned char *tbs, size_t tbslen)` — `rsa_sig.c.in:889-913`.
///
/// # Safety
/// The signature `sign` dispatch contract.
unsafe extern "C" fn rsa_sign(
    vprsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 || prsactx.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).flags & FLAG_ALLOW_ONESHOT == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_895);
            return 0;
        }

        if (*prsactx).operation == EVP_PKEY_OP_SIGNMSG {
            if sig.is_null() {
                return rsa_sign_message_final(vprsactx, sig, siglen, sigsize);
            }

            return c_int::from(
                rsa_signverify_message_update(vprsactx, tbs, tbslen) != 0
                    && rsa_sign_message_final(vprsactx, sig, siglen, sigsize) != 0,
            );
        }
        rsa_sign_directly(prsactx, sig, siglen, sigsize, tbs, tbslen)
    }
}

/// `static int rsa_verify_recover_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_sig.c.in:915-927`.
///
/// # Safety
/// The signature `verify_recover_init` dispatch contract.
unsafe extern "C" fn rsa_verify_recover_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_signverify_init(
            vprsactx.cast(),
            vrsa,
            rsa_set_ctx_params,
            params,
            EVP_PKEY_OP_VERIFYRECOVER,
            c"RSA VerifyRecover Init".as_ptr(),
        )
    }
}

/// `static int rsa_verify_recover(void *vprsactx, unsigned char *rout, size_t *routlen, size_t
/// routsize, const unsigned char *sig, size_t siglen)` — `rsa_sig.c.in:933-1036`.
///
/// # Safety
/// The signature `verify_recover` dispatch contract.
unsafe extern "C" fn rsa_verify_recover(
    vprsactx: *mut c_void,
    rout: *mut u8,
    routlen: *mut usize,
    routsize: usize,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut ret: c_int;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if rout.is_null() {
            *routlen = RSA_size((*prsactx).rsa) as usize;
            return 1;
        }

        if !(*prsactx).md.is_null() {
            match (*prsactx).pad_mode {
                RSA_X931_PADDING => {
                    if setup_tbuf(prsactx) == 0 {
                        return 0;
                    }
                    ret = RSA_public_decrypt(
                        siglen as c_int,
                        sig,
                        (*prsactx).tbuf,
                        (*prsactx).rsa,
                        RSA_X931_PADDING,
                    );
                    if ret <= 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_955);
                        return 0;
                    }
                    ret -= 1;
                    if *(*prsactx).tbuf.add(ret as usize)
                        != RSA_X931_hash_id((*prsactx).mdnid) as u8
                    {
                        raise_site(&err_sites::PROV_RSA_SIG_960);
                        return 0;
                    }
                    if ret != EVP_MD_get_size((*prsactx).md) {
                        let mut msg = [0u8; 64];
                        BIO_snprintf(
                            msg.as_mut_ptr().cast(),
                            msg.len(),
                            c"Should be %d, but got %d".as_ptr(),
                            EVP_MD_get_size((*prsactx).md),
                            ret,
                        );
                        raise_site_data(&err_sites::PROV_RSA_SIG_964, msg.as_ptr().cast());
                        return 0;
                    }

                    *routlen = ret as usize;
                    if rout != (*prsactx).tbuf {
                        if routsize < ret as usize {
                            let mut msg = [0u8; 64];
                            BIO_snprintf(
                                msg.as_mut_ptr().cast(),
                                msg.len(),
                                c"buffer size is %d, should be %d".as_ptr(),
                                routsize,
                                ret,
                            );
                            raise_site_data(&err_sites::PROV_RSA_SIG_973, msg.as_ptr().cast());
                            return 0;
                        }
                        ptr::copy_nonoverlapping((*prsactx).tbuf, rout, ret as usize);
                    }
                }
                RSA_PKCS1_PADDING => {
                    let mdsize = EVP_MD_get_size((*prsactx).md);
                    let mut sltmp: usize = 0;

                    if mdsize <= 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_987);
                        return 0;
                    }
                    if routsize < mdsize as usize {
                        let mut msg = [0u8; 64];
                        BIO_snprintf(
                            msg.as_mut_ptr().cast(),
                            msg.len(),
                            c"buffer size is %d, should be %d".as_ptr(),
                            routsize,
                            mdsize,
                        );
                        raise_site_data(&err_sites::PROV_RSA_SIG_991, msg.as_ptr().cast());
                        return 0;
                    }
                    ret = ossl_rsa_verify(
                        (*prsactx).mdnid,
                        core::ptr::null(),
                        0,
                        rout,
                        &mut sltmp,
                        sig,
                        siglen,
                        (*prsactx).rsa,
                    );
                    if ret <= 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_999);
                        return 0;
                    }
                    ret = sltmp as c_int;
                }
                _ => {
                    raise_site_data(
                        &err_sites::PROV_RSA_SIG_1006,
                        c"Only X.931 or PKCS#1 v1.5 padding allowed".as_ptr(),
                    );
                    return 0;
                }
            }
        } else {
            let rsasize = RSA_size((*prsactx).rsa);

            if routsize < rsasize as usize {
                let mut msg = [0u8; 64];
                BIO_snprintf(
                    msg.as_mut_ptr().cast(),
                    msg.len(),
                    c"buffer size is %d, should be %d".as_ptr(),
                    routsize,
                    rsasize,
                );
                raise_site_data(&err_sites::PROV_RSA_SIG_1014, msg.as_ptr().cast());
                return 0;
            }
            ret = RSA_public_decrypt(
                siglen as c_int,
                sig,
                rout,
                (*prsactx).rsa,
                (*prsactx).pad_mode,
            );
            /*
             * RSA_public_decrypt() returns -1 on error and otherwise the number
             * of recovered bytes, which may legitimately be zero for a raw
             * PKCS#1 v1.5 signature that encodes an empty payload.  Treat only
             * a negative result as an error.
             */
            if ret < 0 {
                raise_site(&err_sites::PROV_RSA_SIG_1028);
                return 0;
            }
        }
        *routlen = ret as usize;
    }
    1
}

/// `static int rsa_verify_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])` —
/// `rsa_sig.c.in:1038-1050`.
///
/// # Safety
/// The signature `verify_init` dispatch contract.
unsafe extern "C" fn rsa_verify_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        rsa_signverify_init(
            vprsactx.cast(),
            vrsa,
            rsa_set_ctx_params,
            params,
            EVP_PKEY_OP_VERIFY,
            c"RSA Verify Init".as_ptr(),
        )
    }
}

/// `static int rsa_verify_directly(PROV_RSA_CTX *prsactx, const unsigned char *sig, size_t siglen,
/// const unsigned char *tbs, size_t tbslen)` — `rsa_sig.c.in:1052-1140`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe fn rsa_verify_directly(
    prsactx: *mut ProvRsaCtx,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let mut rslen: usize = 0;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if !(*prsactx).md.is_null() {
            match (*prsactx).pad_mode {
                RSA_PKCS1_PADDING => {
                    if RSA_verify(
                        (*prsactx).mdnid,
                        tbs,
                        tbslen as c_uint,
                        sig,
                        siglen as c_uint,
                        (*prsactx).rsa,
                    ) == 0
                    {
                        raise_site(&err_sites::PROV_RSA_SIG_1063);
                        return 0;
                    }
                    return 1;
                }
                RSA_X931_PADDING => {
                    if setup_tbuf(prsactx) == 0 {
                        return 0;
                    }
                    if rsa_verify_recover(
                        prsactx.cast(),
                        (*prsactx).tbuf,
                        &mut rslen,
                        0,
                        sig,
                        siglen,
                    ) <= 0
                    {
                        return 0;
                    }
                }
                RSA_PKCS1_PSS_PADDING => {
                    /*
                     * We need to check this for the RSA_verify_PKCS1_PSS_mgf1()
                     * call
                     */
                    let mdsize = rsa_get_md_size(prsactx) as usize;
                    if tbslen != mdsize {
                        let mut msg = [0u8; 64];
                        BIO_snprintf(
                            msg.as_mut_ptr().cast(),
                            msg.len(),
                            c"Should be %d, but got %d".as_ptr(),
                            mdsize,
                            tbslen,
                        );
                        raise_site_data(&err_sites::PROV_RSA_SIG_1086, msg.as_ptr().cast());
                        return 0;
                    }

                    if setup_tbuf(prsactx) == 0 {
                        return 0;
                    }
                    let mut ret = RSA_public_decrypt(
                        siglen as c_int,
                        sig,
                        (*prsactx).tbuf,
                        (*prsactx).rsa,
                        RSA_NO_PADDING,
                    );
                    if ret <= 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_1097);
                        return 0;
                    }
                    let mut saltlen = (*prsactx).saltlen;
                    ret = ossl_rsa_verify_PKCS1_PSS_mgf1(
                        (*prsactx).rsa,
                        tbs,
                        (*prsactx).md,
                        (*prsactx).mgf1_md,
                        (*prsactx).tbuf,
                        &mut saltlen,
                    );
                    if ret <= 0 {
                        raise_site(&err_sites::PROV_RSA_SIG_1106);
                        return 0;
                    }
                    return 1;
                }
                _ => {
                    raise_site_data(
                        &err_sites::PROV_RSA_SIG_1116,
                        c"Only X.931, PKCS#1 v1.5 or PSS padding allowed".as_ptr(),
                    );
                    return 0;
                }
            }
        } else {
            if setup_tbuf(prsactx) == 0 {
                return 0;
            }
            let ret = RSA_public_decrypt(
                siglen as c_int,
                sig,
                (*prsactx).tbuf,
                (*prsactx).rsa,
                (*prsactx).pad_mode,
            );
            if ret <= 0 {
                raise_site(&err_sites::PROV_RSA_SIG_1128);
                return 0;
            }
            rslen = ret as usize;
        }

        if rslen != tbslen
            || core::slice::from_raw_parts(tbs, rslen)
                != core::slice::from_raw_parts((*prsactx).tbuf, rslen)
        {
            return 0;
        }
    }

    1
}

/// `static int rsa_verify_set_sig(void *vprsactx, const unsigned char *sig, size_t siglen)` —
/// `rsa_sig.c.in:1142-1152`.
///
/// # Safety
/// `vprsactx` is the caller's context; `sig` is readable for `siglen` bytes.
unsafe fn rsa_verify_set_sig(vprsactx: *mut c_void, sig: *const u8, siglen: usize) -> c_int {
    let mut params = [OsslParam {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }; 2];

    // SAFETY: `params` is this call's own array and `sig` is the caller's.
    unsafe {
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_SIGNATURE,
            sig.cast_mut().cast(),
            siglen,
        );
        params[1] = OSSL_PARAM_construct_end();
        rsa_sigalg_set_ctx_params(vprsactx, params.as_ptr())
    }
}

/// `static int rsa_verify_message_final(void *vprsactx)` — `rsa_sig.c.in:1154-1182`.
///
/// # Safety
/// The signature `verify_message_final` dispatch contract.
unsafe extern "C" fn rsa_verify_message_final(vprsactx: *mut c_void) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut digest = [0u8; EVP_MAX_MD_SIZE];
    let mut dlen: c_uint = 0;

    if is_running() == 0 || prsactx.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).mdctx.is_null() {
            return 0;
        }
        if (*prsactx).flags & FLAG_ALLOW_FINAL == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_1163);
            return 0;
        }

        if EVP_DigestFinal_ex((*prsactx).mdctx, digest.as_mut_ptr(), &mut dlen) == 0 {
            return 0;
        }

        (*prsactx).flags &= !(FLAG_ALLOW_UPDATE | FLAG_ALLOW_FINAL | FLAG_ALLOW_ONESHOT);

        rsa_verify_directly(
            prsactx,
            (*prsactx).sig,
            (*prsactx).siglen,
            digest.as_ptr(),
            dlen as usize,
        )
    }
}

/// `static int rsa_verify(void *vprsactx, const unsigned char *sig, size_t siglen, const unsigned
/// char *tbs, size_t tbslen)` — `rsa_sig.c.in:1188-1206`.
///
/// # Safety
/// The signature `verify` dispatch contract.
unsafe extern "C" fn rsa_verify(
    vprsactx: *mut c_void,
    sig: *const u8,
    siglen: usize,
    tbs: *const u8,
    tbslen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 || prsactx.is_null() {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).flags & FLAG_ALLOW_ONESHOT == 0 {
            raise_site(&err_sites::PROV_RSA_SIG_1195);
            return 0;
        }

        if (*prsactx).operation == EVP_PKEY_OP_VERIFYMSG {
            return c_int::from(
                rsa_verify_set_sig(vprsactx, sig, siglen) != 0
                    && rsa_signverify_message_update(vprsactx, tbs, tbslen) != 0
                    && rsa_verify_message_final(vprsactx) != 0,
            );
        }
        rsa_verify_directly(prsactx, sig, siglen, tbs, tbslen)
    }
}

/// `static int rsa_digest_signverify_init(void *vprsactx, const char *mdname, void *vrsa, const
/// OSSL_PARAM params[], int operation, const char *desc)` — `rsa_sig.c.in:1210-1248`.
///
/// # Safety
/// The signature `digest_sign_init`/`digest_verify_init` dispatch contract.
unsafe fn rsa_digest_signverify_init(
    vprsactx: *mut c_void,
    mdname: *const c_char,
    vrsa: *mut c_void,
    params: *const OsslParam,
    operation: c_int,
    desc: *const c_char,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if rsa_signverify_init(prsactx, vrsa, rsa_set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        if !mdname.is_null()
            /* was rsa_setup_md already called in rsa_signverify_init()? */
            && ((*mdname == 0) || OPENSSL_strcasecmp((*prsactx).mdname.as_ptr(), mdname) != 0)
            && rsa_setup_md(prsactx, mdname, (*prsactx).propq, desc) == 0
        {
            return 0;
        }

        (*prsactx).flags &= !FLAG_ALLOW_MD;

        if (*prsactx).mdctx.is_null() {
            (*prsactx).mdctx = EVP_MD_CTX_new();
            if (*prsactx).mdctx.is_null() {
                return rsa_digest_signverify_init_err(prsactx);
            }
        }

        if EVP_DigestInit_ex2((*prsactx).mdctx, (*prsactx).md, params) == 0 {
            return rsa_digest_signverify_init_err(prsactx);
        }
    }

    1
}

/// The authority's `err:` arm (`rsa_sig.c.in:1244-1247`).
///
/// # Safety
/// `ctx` is live.
unsafe fn rsa_digest_signverify_init_err(ctx: *mut ProvRsaCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        EVP_MD_CTX_free((*ctx).mdctx);
        (*ctx).mdctx = ptr::null_mut();
    }
    0
}

/// `static int rsa_digest_sign_init(void *vprsactx, const char *mdname, void *vrsa, const
/// OSSL_PARAM params[])` — `rsa_sig.c.in:1250-1258`.
///
/// # Safety
/// The signature `digest_sign_init` dispatch contract.
unsafe extern "C" fn rsa_digest_sign_init(
    vprsactx: *mut c_void,
    mdname: *const c_char,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe {
        rsa_digest_signverify_init(
            vprsactx,
            mdname,
            vrsa,
            params,
            EVP_PKEY_OP_SIGNMSG,
            c"RSA Digest Sign Init".as_ptr(),
        )
    }
}

/// `static int rsa_digest_sign_update(void *vprsactx, const unsigned char *data, size_t datalen)`
/// — `rsa_sig.c.in:1260-1272`.
///
/// # Safety
/// The signature `digest_sign_update` dispatch contract.
unsafe extern "C" fn rsa_digest_sign_update(
    vprsactx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        /* Sigalg implementations shouldn't do digest_sign */
        if (*prsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        rsa_signverify_message_update(vprsactx, data, datalen)
    }
}

/// `static int rsa_digest_sign_final(void *vprsactx, unsigned char *sig, size_t *siglen, size_t
/// sigsize)` — `rsa_sig.c.in:1274-1292`.
///
/// # Safety
/// The signature `digest_sign_final` dispatch contract.
unsafe extern "C" fn rsa_digest_sign_final(
    vprsactx: *mut c_void,
    sig: *mut u8,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut ok = 0;

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        /* Sigalg implementations shouldn't do digest_sign */
        if (*prsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        if rsa_sign_message_final(vprsactx, sig, siglen, sigsize) != 0 {
            ok = 1;
        }

        (*prsactx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static int rsa_digest_verify_init(void *vprsactx, const char *mdname, void *vrsa, const
/// OSSL_PARAM params[])` — `rsa_sig.c.in:1294-1302`.
///
/// # Safety
/// The signature `digest_verify_init` dispatch contract.
unsafe extern "C" fn rsa_digest_verify_init(
    vprsactx: *mut c_void,
    mdname: *const c_char,
    vrsa: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    // SAFETY: the caller's contract.
    unsafe {
        rsa_digest_signverify_init(
            vprsactx,
            mdname,
            vrsa,
            params,
            EVP_PKEY_OP_VERIFYMSG,
            c"RSA Digest Verify Init".as_ptr(),
        )
    }
}

/// `static int rsa_digest_verify_update(void *vprsactx, const unsigned char *data, size_t
/// datalen)` — `rsa_sig.c.in:1304-1316`.
///
/// # Safety
/// The signature `digest_verify_update` dispatch contract.
unsafe extern "C" fn rsa_digest_verify_update(
    vprsactx: *mut c_void,
    data: *const u8,
    datalen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        /* Sigalg implementations shouldn't do digest_sign */
        if (*prsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        rsa_signverify_message_update(vprsactx, data, datalen)
    }
}

/// `int rsa_digest_verify_final(void *vprsactx, const unsigned char *sig, size_t siglen)` —
/// `rsa_sig.c.in:1318-1337`. Non-`static` in the authority; the name is the contract.
///
/// # Safety
/// The signature `digest_verify_final` dispatch contract.
#[allow(non_snake_case)] // the authority's spelling is the contract
pub(crate) unsafe fn rsa_digest_verify_final(
    vprsactx: *mut c_void,
    sig: *const u8,
    siglen: usize,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut ok = 0;

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        /* Sigalg implementations shouldn't do digest_verify */
        if (*prsactx).flags & FLAG_SIGALG != 0 {
            return 0;
        }

        if rsa_verify_set_sig(vprsactx, sig, siglen) != 0 && rsa_verify_message_final(vprsactx) != 0
        {
            ok = 1;
        }

        (*prsactx).flags |= FLAG_ALLOW_MD;

        ok
    }
}

/// `static void rsa_freectx(void *vprsactx)` — `rsa_sig.c.in:1339-1355`.
///
/// # Safety
/// The signature `freectx` dispatch contract.
unsafe extern "C" fn rsa_freectx(vprsactx: *mut c_void) {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if prsactx.is_null() {
        return;
    }

    // SAFETY: `prsactx` is this call's context.
    unsafe {
        EVP_MD_CTX_free((*prsactx).mdctx);
        EVP_MD_free((*prsactx).md);
        EVP_MD_free((*prsactx).mgf1_md);
        CRYPTO_free((*prsactx).sig.cast(), FILE, 1347);
        CRYPTO_free((*prsactx).propq.cast(), FILE, 1348);
        free_tbuf(prsactx);
        RSA_free((*prsactx).rsa);

        CRYPTO_clear_free(
            prsactx.cast(),
            core::mem::size_of::<ProvRsaCtx>(),
            FILE,
            1352,
        );
    }
}

/// `static void *rsa_dupctx(void *vprsactx)` — `rsa_sig.c.in:1357-1413`.
///
/// # Safety
/// The signature `dupctx` dispatch contract.
unsafe extern "C" fn rsa_dupctx(vprsactx: *mut c_void) -> *mut c_void {
    let srcctx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's context.
    unsafe {
        let dstctx =
            CRYPTO_zalloc(core::mem::size_of::<ProvRsaCtx>(), FILE, 1363).cast::<ProvRsaCtx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        // The authority's `*dstctx = *srcctx` is a whole-struct assignment; the pointer copy is
        // that assignment, and the fields below then NULL the borrowed members as the authority
        // does before it re-acquires each one.
        core::ptr::copy_nonoverlapping(srcctx, dstctx, 1);
        (*dstctx).rsa = ptr::null_mut();
        (*dstctx).md = ptr::null_mut();
        (*dstctx).mgf1_md = ptr::null_mut();
        (*dstctx).mdctx = ptr::null_mut();
        (*dstctx).tbuf = ptr::null_mut();
        (*dstctx).propq = ptr::null_mut();
        (*dstctx).sig = ptr::null_mut();

        if !(*srcctx).rsa.is_null() && RSA_up_ref((*srcctx).rsa) == 0 {
            rsa_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).rsa = (*srcctx).rsa;

        if !(*srcctx).md.is_null() && EVP_MD_up_ref((*srcctx).md) == 0 {
            rsa_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).md = (*srcctx).md;

        if !(*srcctx).mgf1_md.is_null() && EVP_MD_up_ref((*srcctx).mgf1_md) == 0 {
            rsa_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).mgf1_md = (*srcctx).mgf1_md;

        if !(*srcctx).mdctx.is_null() {
            (*dstctx).mdctx = EVP_MD_CTX_new();
            if (*dstctx).mdctx.is_null()
                || EVP_MD_CTX_copy_ex((*dstctx).mdctx, (*srcctx).mdctx) == 0
            {
                rsa_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        if !(*srcctx).propq.is_null() {
            (*dstctx).propq = CRYPTO_strdup((*srcctx).propq, FILE, 1396);
            if (*dstctx).propq.is_null() {
                rsa_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        if !(*srcctx).sig.is_null() {
            (*dstctx).sig =
                CRYPTO_memdup((*srcctx).sig.cast(), (*srcctx).siglen, FILE, 1402).cast::<u8>();
            if (*dstctx).sig.is_null() {
                rsa_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        dstctx.cast()
    }
}

/// `struct rsa_get_ctx_params_st` — the `produce_param_decoder` expansion at
/// `rsa_sig.c:1435-1447`, without its two `fips`-typed fields.
#[derive(Clone, Copy)]
struct GetCtxParams {
    algid: *const OsslParam,
    digest: *const OsslParam,
    mgf1: *const OsslParam,
    pad: *const OsslParam,
    slen: *const OsslParam,
}

/// `rsa_get_ctx_params_decoder` — the decoder `produce_param_decoder` emits.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_get_ctx_params_decoder(params: *const OsslParam) -> Option<GetCtxParams> {
    let mut r = GetCtxParams {
        algid: ptr::null(),
        digest: ptr::null(),
        mgf1: ptr::null(),
        pad: ptr::null(),
        slen: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key and the slots are this call's own.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"algorithm-id" => {
                    if !r.algid.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1466);
                        return None;
                    }
                    r.algid = p;
                }
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1477);
                        return None;
                    }
                    r.digest = p;
                }
                b"mgf1-digest" => {
                    if !r.mgf1.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1501);
                        return None;
                    }
                    r.mgf1 = p;
                }
                b"pad-mode" => {
                    if !r.pad.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1512);
                        return None;
                    }
                    r.pad = p;
                }
                b"saltlen" => {
                    if !r.slen.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1523);
                        return None;
                    }
                    r.slen = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsa_get_ctx_params_list[]` — `rsa_sig.c:1416-1431`, without the two
/// `FIPS_MODULE` entries.
static RSA_GET_CTX_PARAMS_LIST: [OsslParam; 8] = [
    param_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_int(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    param_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    END,
];

/// `static int rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)` —
/// `rsa_sig.c:1550-1664`.
///
/// # Safety
/// The signature `get_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_get_ctx_params(vprsactx: *mut c_void, params: *mut OsslParam) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        let Some(p) = rsa_get_ctx_params_decoder(params) else {
            return 0;
        };

        if !p.algid.is_null() {
            /* The Algorithm Identifier of the combined signature algorithm */
            let mut aid_buf = [0u8; 128];
            let mut aid_len: usize = 0;

            let aid = rsa_generate_signature_aid(
                prsactx,
                aid_buf.as_mut_ptr(),
                aid_buf.len(),
                &mut aid_len,
            );
            if aid.is_null()
                || OSSL_PARAM_set_octet_string(p.algid.cast_mut(), aid.cast(), aid_len) == 0
            {
                return 0;
            }
        }

        if !p.pad.is_null() {
            if (*p.pad).data_type != OSSL_PARAM_UTF8_STRING {
                if OSSL_PARAM_set_int(p.pad.cast_mut(), (*prsactx).pad_mode) == 0 {
                    return 0;
                }
            } else {
                let mut word: *const c_char = ptr::null();

                let mut i = 0usize;
                while PADDING_ITEM[i].id != 0 {
                    if (*prsactx).pad_mode == PADDING_ITEM[i].id {
                        word = PADDING_ITEM[i].ptr;
                        break;
                    }
                    i += 1;
                }

                if !word.is_null() {
                    if OSSL_PARAM_set_utf8_string(p.pad.cast_mut(), word) == 0 {
                        return 0;
                    }
                } else {
                    raise_site(&err_sites::PROV_RSA_SIG_1589);
                }
            }
        }

        if !p.digest.is_null()
            && OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), (*prsactx).mdname.as_ptr()) == 0
        {
            return 0;
        }

        if !p.mgf1.is_null()
            && OSSL_PARAM_set_utf8_string(p.mgf1.cast_mut(), (*prsactx).mgf1_mdname.as_ptr()) == 0
        {
            return 0;
        }

        if !p.slen.is_null() {
            if (*p.slen).data_type != OSSL_PARAM_UTF8_STRING {
                if OSSL_PARAM_set_int(p.slen.cast_mut(), (*prsactx).saltlen) == 0 {
                    return 0;
                }
            } else {
                let mut value: *const c_char = ptr::null();

                match (*prsactx).saltlen {
                    RSA_PSS_SALTLEN_DIGEST => value = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST,
                    RSA_PSS_SALTLEN_MAX => value = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX,
                    RSA_PSS_SALTLEN_AUTO => value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO,
                    RSA_PSS_SALTLEN_AUTO_DIGEST_MAX => {
                        value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX
                    }
                    _ => {
                        let len = BIO_snprintf(
                            (*p.slen).data.cast(),
                            (*p.slen).data_size,
                            c"%d".as_ptr(),
                            (*prsactx).saltlen,
                        );

                        if len <= 0 {
                            return 0;
                        }
                        (*p.slen.cast_mut()).return_size = len as usize;
                    }
                }
                if !value.is_null() && OSSL_PARAM_set_utf8_string(p.slen.cast_mut(), value) == 0 {
                    return 0;
                }
            }
        }
    }

    1
}

/// `static const OSSL_PARAM *rsa_gettable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_sig.c:1666-1671`.
///
/// # Safety
/// The signature `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_gettable_ctx_params(
    _prsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    RSA_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct rsa_set_ctx_params_st` — `rsa_sig.c:1700-1719`, without its four `fips` fields. The two
/// generated set decoders fill a subset of it, and the sigalg decoder fills only [`sig`].
#[derive(Clone, Copy)]
struct SetCtxParams {
    digest: *const OsslParam,
    mgf1: *const OsslParam,
    mgf1pq: *const OsslParam,
    pad: *const OsslParam,
    propq: *const OsslParam,
    sig: *const OsslParam,
    slen: *const OsslParam,
}

/// `rsa_set_ctx_params_decoder` — the first `produce_param_decoder` expansion.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        digest: ptr::null(),
        mgf1: ptr::null(),
        mgf1pq: ptr::null(),
        pad: ptr::null(),
        propq: ptr::null(),
        sig: ptr::null(),
        slen: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"digest" => {
                    if !r.digest.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1773);
                        return None;
                    }
                    r.digest = p;
                }
                b"mgf1-digest" => {
                    if !r.mgf1.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1822);
                        return None;
                    }
                    r.mgf1 = p;
                }
                b"mgf1-properties" => {
                    if !r.mgf1pq.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1833);
                        return None;
                    }
                    r.mgf1pq = p;
                }
                b"pad-mode" => {
                    if !r.pad.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1853);
                        return None;
                    }
                    r.pad = p;
                }
                b"properties" => {
                    if !r.propq.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1864);
                        return None;
                    }
                    r.propq = p;
                }
                b"saltlen" => {
                    if !r.slen.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_1893);
                        return None;
                    }
                    r.slen = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `rsa_set_ctx_params_no_digest_decoder` — the second `produce_param_decoder` expansion, over the
/// names the restricted (`flag_allow_md == 0`) path accepts.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_set_ctx_params_no_digest_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        digest: ptr::null(),
        mgf1: ptr::null(),
        mgf1pq: ptr::null(),
        pad: ptr::null(),
        propq: ptr::null(),
        sig: ptr::null(),
        slen: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            match s {
                b"mgf1-digest" => {
                    if !r.mgf1.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_2033);
                        return None;
                    }
                    r.mgf1 = p;
                }
                b"mgf1-properties" => {
                    if !r.mgf1pq.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_2044);
                        return None;
                    }
                    r.mgf1pq = p;
                }
                b"pad-mode" => {
                    if !r.pad.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_2060);
                        return None;
                    }
                    r.pad = p;
                }
                b"saltlen" => {
                    if !r.slen.is_null() {
                        raise_site(&err_sites::PROV_RSA_SIG_2088);
                        return None;
                    }
                    r.slen = p;
                }
                _ => {}
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsa_set_ctx_params_list[]` — `rsa_sig.c:1690-1714`, without the four
/// `FIPS_MODULE` entries.
static RSA_SET_CTX_PARAMS_LIST: [OsslParam; 12] = [
    param_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_int(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    param_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    param_int(OSSL_SIGNATURE_PARAM_FIPS_KEY_CHECK),
    param_int(OSSL_SIGNATURE_PARAM_FIPS_DIGEST_CHECK),
    param_int(OSSL_SIGNATURE_PARAM_FIPS_RSA_PSS_SALTLEN_CHECK),
    END,
];

/// `static const OSSL_PARAM rsa_set_ctx_params_no_digest_list[]` — `rsa_sig.c:1927-1947`, without
/// the four `FIPS_MODULE` entries.
static RSA_SET_CTX_PARAMS_NO_DIGEST_LIST: [OsslParam; 8] = [
    param_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_int(OSSL_SIGNATURE_PARAM_PAD_MODE),
    param_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST),
    param_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES),
    param_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    param_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN),
    param_int(OSSL_SIGNATURE_PARAM_FIPS_SIGN_X931_PAD_CHECK),
    END,
];

/// `static int rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])` —
/// `rsa_sig.c:2117-2353`, without the four `OSSL_FIPS_IND_SET_CTX_FROM_PARAM` calls (literals on
/// this profile).
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_set_ctx_params(vprsactx: *mut c_void, params: *const OsslParam) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();
    let mut pad_mode: c_int;
    let mut saltlen: c_int;
    let mut mdname = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut pmdname: *mut c_char = ptr::null_mut();
    let mut mdprops = [0 as c_char; OSSL_MAX_PROPQUERY_SIZE];
    let mut pmdprops: *mut c_char = ptr::null_mut();
    let mut mgf1mdname = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut pmgf1mdname: *mut c_char = ptr::null_mut();
    let mut mgf1mdprops = [0 as c_char; OSSL_MAX_PROPQUERY_SIZE];
    let mut pmgf1mdprops: *mut c_char = ptr::null_mut();

    if prsactx.is_null() {
        return 0;
    }
    /* The processing code below doesn't handle no parameters properly */
    // SAFETY: `params` is NULL or a terminated array.
    unsafe {
        if ossl_param_is_empty(params) {
            return 1;
        }

        let p = if (*prsactx).flags & FLAG_ALLOW_MD != 0 {
            match rsa_set_ctx_params_decoder(params) {
                Some(p) => p,
                None => return 0,
            }
        } else {
            match rsa_set_ctx_params_no_digest_decoder(params) {
                Some(p) => p,
                None => return 0,
            }
        };

        pad_mode = (*prsactx).pad_mode;
        saltlen = (*prsactx).saltlen;

        if !p.digest.is_null() {
            pmdname = mdname.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.digest, &mut pmdname, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }

            if !p.propq.is_null() {
                pmdprops = mdprops.as_mut_ptr();
                if OSSL_PARAM_get_utf8_string(p.propq, &mut pmdprops, OSSL_MAX_PROPQUERY_SIZE) == 0
                {
                    return 0;
                }
            }
        }

        if !p.pad.is_null() {
            let mut err_extra_text: *const c_char = ptr::null();

            if (*p.pad).data_type != OSSL_PARAM_UTF8_STRING {
                /* Support for legacy pad mode number */
                if OSSL_PARAM_get_int(p.pad, &mut pad_mode) == 0 {
                    return 0;
                }
            } else {
                if (*p.pad).data.is_null() {
                    return 0;
                }

                let data = CStr::from_ptr((*p.pad).data.cast()).to_bytes();
                let mut i = 0usize;
                while PADDING_ITEM[i].id != 0 {
                    if CStr::from_ptr(PADDING_ITEM[i].ptr).to_bytes() == data {
                        pad_mode = PADDING_ITEM[i].id;
                        break;
                    }
                    i += 1;
                }
            }

            let mut bad_pad = false;
            match pad_mode {
                RSA_PKCS1_OAEP_PADDING => {
                    /*
                     * OAEP padding is for asymmetric cipher only so is not compatible
                     * with signature use.
                     */
                    err_extra_text = c"OAEP padding not allowed for signing / verifying".as_ptr();
                    bad_pad = true;
                }
                RSA_PKCS1_PSS_PADDING => {
                    if ((*prsactx).operation
                        & (EVP_PKEY_OP_SIGN
                            | EVP_PKEY_OP_SIGNMSG
                            | EVP_PKEY_OP_VERIFY
                            | EVP_PKEY_OP_VERIFYMSG))
                        == 0
                    {
                        err_extra_text =
                            c"PSS padding only allowed for sign and verify operations".as_ptr();
                        bad_pad = true;
                    }
                }
                RSA_PKCS1_PADDING => {
                    err_extra_text = c"PKCS#1 padding not allowed with RSA-PSS".as_ptr();
                    if RSA_test_flags((*prsactx).rsa, RSA_FLAG_TYPE_MASK) != RSA_FLAG_TYPE_RSA {
                        bad_pad = true;
                    }
                }
                RSA_NO_PADDING => {
                    err_extra_text = c"No padding not allowed with RSA-PSS".as_ptr();
                    if RSA_test_flags((*prsactx).rsa, RSA_FLAG_TYPE_MASK) != RSA_FLAG_TYPE_RSA {
                        bad_pad = true;
                    }
                }
                RSA_X931_PADDING => {
                    err_extra_text = c"X.931 padding not allowed with RSA-PSS".as_ptr();
                    if RSA_test_flags((*prsactx).rsa, RSA_FLAG_TYPE_MASK) != RSA_FLAG_TYPE_RSA {
                        bad_pad = true;
                    }
                }
                _ => {
                    bad_pad = true;
                }
            }

            if bad_pad {
                if err_extra_text.is_null() {
                    raise_site(&err_sites::PROV_RSA_SIG_2239);
                } else {
                    raise_site_data(&err_sites::PROV_RSA_SIG_2242, err_extra_text);
                }
                return 0;
            }
        }

        if !p.slen.is_null() {
            if pad_mode != RSA_PKCS1_PSS_PADDING {
                raise_site_data(
                    &err_sites::PROV_RSA_SIG_2251,
                    c"PSS saltlen can only be specified if PSS padding has been specified first"
                        .as_ptr(),
                );
                return 0;
            }

            if (*p.slen).data_type != OSSL_PARAM_UTF8_STRING {
                /* Support for legacy pad mode number */
                if OSSL_PARAM_get_int(p.slen, &mut saltlen) == 0 {
                    return 0;
                }
            } else {
                let data = CStr::from_ptr((*p.slen).data.cast()).to_bytes();
                if data == CStr::from_ptr(OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST).to_bytes() {
                    saltlen = RSA_PSS_SALTLEN_DIGEST;
                } else if data == CStr::from_ptr(OSSL_PKEY_RSA_PSS_SALT_LEN_MAX).to_bytes() {
                    saltlen = RSA_PSS_SALTLEN_MAX;
                } else if data == CStr::from_ptr(OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO).to_bytes() {
                    saltlen = RSA_PSS_SALTLEN_AUTO;
                } else if data
                    == CStr::from_ptr(OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX).to_bytes()
                {
                    saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
                } else {
                    saltlen = atoi((*p.slen).data.cast());
                }
            }

            /*
             * RSA_PSS_SALTLEN_AUTO_DIGEST_MAX seems curiously named in this check.
             * Contrary to what it's name suggests, it's the currently lowest
             * saltlen number possible.
             */
            if saltlen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
                raise_site(&err_sites::PROV_RSA_SIG_2280);
                return 0;
            }

            if rsa_pss_restricted(prsactx) {
                match saltlen {
                    RSA_PSS_SALTLEN_AUTO | RSA_PSS_SALTLEN_AUTO_DIGEST_MAX => {
                        if ((*prsactx).operation & (EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYMSG))
                            == 0
                        {
                            raise_site_data(
                                &err_sites::PROV_RSA_SIG_2291,
                                c"Cannot use autodetected salt length".as_ptr(),
                            );
                            return 0;
                        }
                    }
                    RSA_PSS_SALTLEN_DIGEST => {
                        if (*prsactx).min_saltlen > EVP_MD_get_size((*prsactx).md) {
                            let mut msg = [0u8; 160];
                            BIO_snprintf(
                                msg.as_mut_ptr().cast(),
                                msg.len(),
                                c"Should be more than %d, but would be set to match digest size (%d)"
                                    .as_ptr(),
                                (*prsactx).min_saltlen,
                                EVP_MD_get_size((*prsactx).md),
                            );
                            raise_site_data(&err_sites::PROV_RSA_SIG_2298, msg.as_ptr().cast());
                            return 0;
                        }
                    }
                    _ => {
                        if saltlen >= 0 && saltlen < (*prsactx).min_saltlen {
                            let mut msg = [0u8; 160];
                            BIO_snprintf(
                                msg.as_mut_ptr().cast(),
                                msg.len(),
                                c"Should be more than %d, but would be set to %d".as_ptr(),
                                (*prsactx).min_saltlen,
                                saltlen,
                            );
                            raise_site_data(&err_sites::PROV_RSA_SIG_2309, msg.as_ptr().cast());
                            return 0;
                        }
                    }
                }
            }
        }

        if !p.mgf1.is_null() {
            pmgf1mdname = mgf1mdname.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.mgf1, &mut pmgf1mdname, OSSL_MAX_NAME_SIZE) == 0 {
                return 0;
            }

            if !p.mgf1pq.is_null() {
                pmgf1mdprops = mgf1mdprops.as_mut_ptr();
                if OSSL_PARAM_get_utf8_string(p.mgf1pq, &mut pmgf1mdprops, OSSL_MAX_PROPQUERY_SIZE)
                    == 0
                {
                    return 0;
                }
            }

            if pad_mode != RSA_PKCS1_PSS_PADDING {
                raise_site(&err_sites::PROV_RSA_SIG_2333);
                return 0;
            }
        }

        (*prsactx).saltlen = saltlen;
        (*prsactx).pad_mode = pad_mode;

        if (*prsactx).md.is_null() && pmdname.is_null() && pad_mode == RSA_PKCS1_PSS_PADDING {
            pmdname = RSA_DEFAULT_DIGEST_NAME.cast_mut();
        }

        if !pmgf1mdname.is_null() && rsa_setup_mgf1_md(prsactx, pmgf1mdname, pmgf1mdprops) == 0 {
            return 0;
        }

        if !pmdname.is_null() {
            if rsa_setup_md(prsactx, pmdname, pmdprops, c"RSA Sign Set Ctx".as_ptr()) == 0 {
                return 0;
            }
        } else if rsa_check_padding(prsactx, ptr::null(), ptr::null(), (*prsactx).mdnid) == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *rsa_settable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_sig.c:2355-2363`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_settable_ctx_params(
    vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if !prsactx.is_null() && (*prsactx).flags & FLAG_ALLOW_MD == 0 {
            return RSA_SET_CTX_PARAMS_NO_DIGEST_LIST.as_ptr();
        }
    }
    RSA_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)` —
/// `rsa_sig.c:2365-2373`.
///
/// # Safety
/// The signature `get_ctx_md_params` dispatch contract.
unsafe extern "C" fn rsa_get_ctx_md_params(vprsactx: *mut c_void, params: *mut OsslParam) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).mdctx.is_null() {
            return 0;
        }
        EVP_MD_CTX_get_params((*prsactx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *rsa_gettable_ctx_md_params(void *vprsactx)` —
/// `rsa_sig.c:2375-2383`.
///
/// # Safety
/// The signature `gettable_ctx_md_params` dispatch contract.
unsafe extern "C" fn rsa_gettable_ctx_md_params(vprsactx: *mut c_void) -> *const OsslParam {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).md.is_null() {
            return ptr::null();
        }
        EVP_MD_gettable_ctx_params((*prsactx).md)
    }
}

/// `static int rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])` —
/// `rsa_sig.c:2385-2393`.
///
/// # Safety
/// The signature `set_ctx_md_params` dispatch contract.
unsafe extern "C" fn rsa_set_ctx_md_params(
    vprsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).mdctx.is_null() {
            return 0;
        }
        EVP_MD_CTX_set_params((*prsactx).mdctx, params)
    }
}

/// `static const OSSL_PARAM *rsa_settable_ctx_md_params(void *vprsactx)` —
/// `rsa_sig.c:2395-2403`.
///
/// # Safety
/// The signature `settable_ctx_md_params` dispatch contract.
unsafe extern "C" fn rsa_settable_ctx_md_params(vprsactx: *mut c_void) -> *const OsslParam {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if (*prsactx).md.is_null() {
            return ptr::null();
        }
        EVP_MD_settable_ctx_params((*prsactx).md)
    }
}

/// `const OSSL_DISPATCH ossl_rsa_signature_functions[]` — `rsa_sig.c:1876-1915`.
pub(crate) static RSA_SIGNATURE_FUNCTIONS: [OsslDispatch; 24] = [
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
        function: rsa_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
        function: rsa_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SIGN,
        function: rsa_sign as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
        function: rsa_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY,
        function: rsa_verify as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
        function: rsa_verify_recover_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
        function: rsa_verify_recover as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
        function: rsa_digest_sign_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
        function: rsa_digest_sign_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
        function: rsa_digest_sign_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
        function: rsa_digest_verify_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
        function: rsa_digest_verify_update as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
        function: rsa_digest_verify_final as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_FREECTX,
        function: rsa_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
        function: rsa_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
        function: rsa_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
        function: rsa_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
        function: rsa_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
        function: rsa_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
        function: rsa_get_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
        function: rsa_gettable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
        function: rsa_set_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
        function: rsa_settable_ctx_md_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static int rsa_sigalg_signverify_init(void *vprsactx, void *vrsa,
/// OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params, const OSSL_PARAM params[], const char
/// *mdname, int operation, int pad_mode, const char *desc)` — `rsa_sig.c:2426-2470`.
///
/// # Safety
/// The signature init dispatch contract.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn rsa_sigalg_signverify_init(
    vprsactx: *mut c_void,
    vrsa: *mut c_void,
    set_ctx_params: SetCtxParamsFn,
    params: *const OsslParam,
    mdname: *const c_char,
    operation: c_int,
    pad_mode: c_int,
    desc: *const c_char,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: `prsactx` is the caller's context.
    unsafe {
        if rsa_signverify_init(prsactx, vrsa, set_ctx_params, params, operation, desc) == 0 {
            return 0;
        }

        /* PSS is currently not supported as a sigalg */
        if (*prsactx).pad_mode == RSA_PKCS1_PSS_PADDING {
            raise_site(&err_sites::PROV_RSA_SIG_2484);
            return 0;
        }

        if rsa_setup_md(prsactx, mdname, ptr::null(), desc) == 0 {
            return 0;
        }

        (*prsactx).pad_mode = pad_mode;
        (*prsactx).flags |= FLAG_SIGALG;
        (*prsactx).flags &= !FLAG_ALLOW_MD;

        if (*prsactx).mdctx.is_null() {
            (*prsactx).mdctx = EVP_MD_CTX_new();
            if (*prsactx).mdctx.is_null() {
                return rsa_digest_signverify_init_err(prsactx);
            }
        }

        if EVP_DigestInit_ex2((*prsactx).mdctx, (*prsactx).md, params) == 0 {
            return rsa_digest_signverify_init_err(prsactx);
        }
    }

    1
}

/// `static const char **rsa_sigalg_query_key_types(void)` — `rsa_sig.c:2472-2477`.
unsafe extern "C" fn rsa_sigalg_query_key_types() -> *mut *const c_char {
    /// `static const char *keytypes[] = { "RSA", NULL }`.
    #[repr(C)]
    struct KeyTypeNames([*const c_char; 2]);

    // SAFETY: the array holds `'static` literals and a NULL terminator; nothing mutates it.
    unsafe impl Sync for KeyTypeNames {}

    static KEYTYPES: KeyTypeNames = KeyTypeNames([c"RSA".as_ptr(), ptr::null()]);

    KEYTYPES.0.as_ptr().cast_mut()
}

/// `rsa_sigalg_set_ctx_params_decoder` — the third `produce_param_decoder` expansion, over the one
/// name a sigalg's verify path takes.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn rsa_sigalg_set_ctx_params_decoder(params: *const OsslParam) -> Option<SetCtxParams> {
    let mut r = SetCtxParams {
        digest: ptr::null(),
        mgf1: ptr::null(),
        mgf1pq: ptr::null(),
        pad: ptr::null(),
        propq: ptr::null(),
        sig: ptr::null(),
        slen: ptr::null(),
    };

    if params.is_null() {
        return Some(r);
    }

    // SAFETY: the walk stops at the NULL key.
    unsafe {
        let mut p = params;
        while !(*p).key.is_null() {
            let s = CStr::from_ptr((*p).key).to_bytes();
            if s == b"signature" {
                if !r.sig.is_null() {
                    raise_site(&err_sites::PROV_RSA_SIG_2546);
                    return None;
                }
                r.sig = p;
            }
            p = p.add(1);
        }
    }

    Some(r)
}

/// `static const OSSL_PARAM rsa_sigalg_set_ctx_params_list[]` — `rsa_sig.c:2486-2489`.
static RSA_SIGALG_SET_CTX_PARAMS_LIST: [OsslParam; 2] =
    [param_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE), END];

/// `static const OSSL_PARAM *rsa_sigalg_settable_ctx_params(void *vprsactx, void *provctx)` —
/// `rsa_sig.c:2492-2500`.
///
/// # Safety
/// The signature `settable_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_sigalg_settable_ctx_params(
    vprsactx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context.
    unsafe {
        if !prsactx.is_null() && (*prsactx).operation == EVP_PKEY_OP_VERIFYMSG {
            return RSA_SIGALG_SET_CTX_PARAMS_LIST.as_ptr();
        }
    }
    ptr::null()
}

/// `static int rsa_sigalg_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])` —
/// `rsa_sig.c:2502-2521`.
///
/// # Safety
/// The signature `set_ctx_params` dispatch contract.
unsafe extern "C" fn rsa_sigalg_set_ctx_params(
    vprsactx: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let prsactx = vprsactx.cast::<ProvRsaCtx>();

    // SAFETY: `prsactx` is NULL or the caller's context; `params` is a terminated array.
    unsafe {
        if prsactx.is_null() {
            return 0;
        }
        let Some(p) = rsa_sigalg_set_ctx_params_decoder(params) else {
            return 0;
        };

        if (*prsactx).operation == EVP_PKEY_OP_VERIFYMSG && !p.sig.is_null() {
            CRYPTO_free((*prsactx).sig.cast(), FILE, 2578);
            (*prsactx).sig = ptr::null_mut();
            (*prsactx).siglen = 0;
            let mut sig: *mut c_void = ptr::null_mut();
            if OSSL_PARAM_get_octet_string(p.sig, &mut sig, 0, ptr::addr_of_mut!((*prsactx).siglen))
                == 0
            {
                return 0;
            }
            (*prsactx).sig = sig.cast::<u8>();
        }
    }
    1
}

/// One of the thirteen `RSA-<MD>` sigalgs' five init wrappers (`rsa_sig.c:2023-2099`'s
/// `IMPL_RSA_SIGALG`, whose bodies differ only in the digest name, the operation and the
/// description).
macro_rules! rsa_sigalg_init {
    ($fn_name:ident, $md:literal, $op:expr, $desc:literal) => {
        unsafe extern "C" fn $fn_name(
            vprsactx: *mut c_void,
            vrsa: *mut c_void,
            params: *const OsslParam,
        ) -> c_int {
            // SAFETY: the caller's contract.
            unsafe {
                rsa_sigalg_signverify_init(
                    vprsactx,
                    vrsa,
                    rsa_sigalg_set_ctx_params,
                    params,
                    $md.as_ptr(),
                    $op,
                    RSA_PKCS1_PADDING,
                    $desc.as_ptr(),
                )
            }
        }
    };
}

rsa_sigalg_init!(
    rsa_ripemd160_sign_init,
    c"RIPEMD160",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_ripemd160_sign_message_init,
    c"RIPEMD160",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_ripemd160_verify_init,
    c"RIPEMD160",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_ripemd160_verify_recover_init,
    c"RIPEMD160",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_ripemd160_verify_message_init,
    c"RIPEMD160",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha1_sign_init,
    c"SHA1",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha1_sign_message_init,
    c"SHA1",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha1_verify_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha1_verify_recover_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha1_verify_message_init,
    c"SHA1",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha224_sign_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha224_sign_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha224_verify_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha224_verify_recover_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha224_verify_message_init,
    c"SHA2-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha256_sign_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha256_sign_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha256_verify_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha256_verify_recover_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha256_verify_message_init,
    c"SHA2-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha384_sign_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha384_sign_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha384_verify_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha384_verify_recover_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha384_verify_message_init,
    c"SHA2-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha512_sign_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha512_sign_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha512_verify_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha512_verify_recover_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha512_verify_message_init,
    c"SHA2-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha512_224_sign_init,
    c"SHA2-512/224",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha512_224_sign_message_init,
    c"SHA2-512/224",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha512_224_verify_init,
    c"SHA2-512/224",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha512_224_verify_recover_init,
    c"SHA2-512/224",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha512_224_verify_message_init,
    c"SHA2-512/224",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha512_256_sign_init,
    c"SHA2-512/256",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha512_256_sign_message_init,
    c"SHA2-512/256",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha512_256_verify_init,
    c"SHA2-512/256",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha512_256_verify_recover_init,
    c"SHA2-512/256",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha512_256_verify_message_init,
    c"SHA2-512/256",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha3_224_sign_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha3_224_sign_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha3_224_verify_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha3_224_verify_recover_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha3_224_verify_message_init,
    c"SHA3-224",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha3_256_sign_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha3_256_sign_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha3_256_verify_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha3_256_verify_recover_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha3_256_verify_message_init,
    c"SHA3-256",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha3_384_sign_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha3_384_sign_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha3_384_verify_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha3_384_verify_recover_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha3_384_verify_message_init,
    c"SHA3-384",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sha3_512_sign_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sha3_512_sign_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sha3_512_verify_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sha3_512_verify_recover_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sha3_512_verify_message_init,
    c"SHA3-512",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

rsa_sigalg_init!(
    rsa_sm3_sign_init,
    c"SM3",
    EVP_PKEY_OP_SIGN,
    c"RSA Sigalg Sign Init"
);
rsa_sigalg_init!(
    rsa_sm3_sign_message_init,
    c"SM3",
    EVP_PKEY_OP_SIGNMSG,
    c"RSA Sigalg Sign Message Init"
);
rsa_sigalg_init!(
    rsa_sm3_verify_init,
    c"SM3",
    EVP_PKEY_OP_VERIFY,
    c"RSA Sigalg Verify Init"
);
rsa_sigalg_init!(
    rsa_sm3_verify_recover_init,
    c"SM3",
    EVP_PKEY_OP_VERIFYRECOVER,
    c"RSA Sigalg Verify Recover Init"
);
rsa_sigalg_init!(
    rsa_sm3_verify_message_init,
    c"SM3",
    EVP_PKEY_OP_VERIFYMSG,
    c"RSA Sigalg Verify Message Init"
);

/// One of the thirteen `RSA-<MD>` sigalgs' dispatch table (`rsa_sig.c:2101-2138`'s
/// `IMPL_RSA_SIGALG` tail, whose rows differ only in the five init slots).
macro_rules! rsa_sigalg_table {
    ($table:ident, $sign_init:ident, $sign_message_init:ident, $verify_init:ident, $verify_recover_init:ident, $verify_message_init:ident) => {
        pub(crate) static $table: [OsslDispatch; 21] = [
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_NEWCTX,
                function: rsa_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_INIT,
                function: $sign_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN,
                function: rsa_sign as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
                function: $sign_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
                function: rsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
                function: rsa_sign_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_INIT,
                function: $verify_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY,
                function: rsa_verify as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
                function: $verify_message_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
                function: rsa_signverify_message_update as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
                function: rsa_verify_message_final as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
                function: $verify_recover_init as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,
                function: rsa_verify_recover as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_FREECTX,
                function: rsa_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_DUPCTX,
                function: rsa_dupctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES,
                function: rsa_sigalg_query_key_types as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                function: rsa_get_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                function: rsa_gettable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                function: rsa_sigalg_set_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                function: rsa_sigalg_settable_ctx_params as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

rsa_sigalg_table!(
    RSA_RIPEMD160_SIGNATURE_FUNCTIONS,
    rsa_ripemd160_sign_init,
    rsa_ripemd160_sign_message_init,
    rsa_ripemd160_verify_init,
    rsa_ripemd160_verify_recover_init,
    rsa_ripemd160_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA1_SIGNATURE_FUNCTIONS,
    rsa_sha1_sign_init,
    rsa_sha1_sign_message_init,
    rsa_sha1_verify_init,
    rsa_sha1_verify_recover_init,
    rsa_sha1_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA224_SIGNATURE_FUNCTIONS,
    rsa_sha224_sign_init,
    rsa_sha224_sign_message_init,
    rsa_sha224_verify_init,
    rsa_sha224_verify_recover_init,
    rsa_sha224_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA256_SIGNATURE_FUNCTIONS,
    rsa_sha256_sign_init,
    rsa_sha256_sign_message_init,
    rsa_sha256_verify_init,
    rsa_sha256_verify_recover_init,
    rsa_sha256_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA384_SIGNATURE_FUNCTIONS,
    rsa_sha384_sign_init,
    rsa_sha384_sign_message_init,
    rsa_sha384_verify_init,
    rsa_sha384_verify_recover_init,
    rsa_sha384_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA512_SIGNATURE_FUNCTIONS,
    rsa_sha512_sign_init,
    rsa_sha512_sign_message_init,
    rsa_sha512_verify_init,
    rsa_sha512_verify_recover_init,
    rsa_sha512_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA512_224_SIGNATURE_FUNCTIONS,
    rsa_sha512_224_sign_init,
    rsa_sha512_224_sign_message_init,
    rsa_sha512_224_verify_init,
    rsa_sha512_224_verify_recover_init,
    rsa_sha512_224_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA512_256_SIGNATURE_FUNCTIONS,
    rsa_sha512_256_sign_init,
    rsa_sha512_256_sign_message_init,
    rsa_sha512_256_verify_init,
    rsa_sha512_256_verify_recover_init,
    rsa_sha512_256_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA3_224_SIGNATURE_FUNCTIONS,
    rsa_sha3_224_sign_init,
    rsa_sha3_224_sign_message_init,
    rsa_sha3_224_verify_init,
    rsa_sha3_224_verify_recover_init,
    rsa_sha3_224_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA3_256_SIGNATURE_FUNCTIONS,
    rsa_sha3_256_sign_init,
    rsa_sha3_256_sign_message_init,
    rsa_sha3_256_verify_init,
    rsa_sha3_256_verify_recover_init,
    rsa_sha3_256_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA3_384_SIGNATURE_FUNCTIONS,
    rsa_sha3_384_sign_init,
    rsa_sha3_384_sign_message_init,
    rsa_sha3_384_verify_init,
    rsa_sha3_384_verify_recover_init,
    rsa_sha3_384_verify_message_init
);
rsa_sigalg_table!(
    RSA_SHA3_512_SIGNATURE_FUNCTIONS,
    rsa_sha3_512_sign_init,
    rsa_sha3_512_sign_message_init,
    rsa_sha3_512_verify_init,
    rsa_sha3_512_verify_recover_init,
    rsa_sha3_512_verify_message_init
);
rsa_sigalg_table!(
    RSA_SM3_SIGNATURE_FUNCTIONS,
    rsa_sm3_sign_init,
    rsa_sm3_sign_message_init,
    rsa_sm3_verify_init,
    rsa_sm3_verify_recover_init,
    rsa_sm3_verify_message_init
);
