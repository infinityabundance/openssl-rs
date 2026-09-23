//! Phase 8 — the default provider's `OSSL_OP_KEYMGMT` rows, and the key-manager units behind them.
//!
//! The authority publishes forty rows of `providers/defltprov.c`'s `deflt_keymgmt[]`, and this
//! module is where the crate's own `deflt_query(OSSL_OP_KEYMGMT)` answers them. **Why it exists at
//! all** is the measurement D384/D385 recorded: the `OSSL_OP_KEYEXCH`, `OSSL_OP_SIGNATURE`,
//! `OSSL_OP_KEM` and `OSSL_OP_ASYM_CIPHER` rows are all reached through the *key type's* keymgmt
//! row — `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)` fetches `DH` under `OSSL_OP_KEYMGMT` first —
//! so with no keymgmt arm none of those operations is drivable and the exchange units the previous
//! passes withheld could not be courted. This is the gate.
//!
//! ## What is landed here, and what is not
//!
//! Each unit is transcribed **whole** (D327's rule). This module carries the
//! `kdf_legacy_kmgmt.c` unit, whose three rows (`TLS1-PRF`, `HKDF`, `SCRYPT`) share the authority's
//! one `ossl_kdf_keymgmt_functions` — a deliberately *empty* key manager: a legacy KDF has no key
//! material, so `kdf_has` answers 1 unconditionally and the only real content is the `KDF_DATA`
//! reference-counted handle `exchange/kdf_exch.c` also uses. It is the smallest of the reachable
//! keymgmt units and the one the exchange gate needs first.
//!
//! **`dh_kmgmt.c` is the second unit, landed in D387, and it is the keystone D385/D386 measured as
//! the highest-leverage one left**: its two rows (`DH` and `DHX`) gate the `exchange/dh_exch.c.in`
//! unit, and its closure was the last keymgmt unit that was neither behind a prerequisite nor
//! unreachable. Of everything it calls, only `ossl_dh_gen_type_name2id` was missing — the
//! fifteen-line linear search over `dhtype2id[]`, now landed beside its sibling in
//! `src/evp/pkey_ctx.rs`. The unit's two dispatch tables are the authority's: `DHX` differs from
//! `DH` in five slots (`newdata`, `gen_init`, `gen_set_params`, `gen_settable_params` and the
//! extra `QUERY_OPERATION_NAME`), and every other function pointer is shared.
//!
//! The PQC units (`ml_dsa_kmgmt.c.in`, `ml_kem_kmgmt.c.in`, `mlx_kmgmt.c.in`, `slh_dsa_kmgmt.c.in`)
//! are **not reachable** on this tree: their units are built on `crypto/ml_dsa/`, `crypto/ml_kem/`
//! and `crypto/slh_dsa/`, none of which the crate has. They are recorded rather than stubbed, the
//! the way D382/D384/D385 record their own unreachable units.
//!
//! **`ecx_kmgmt.c.in` is the third unit, landed in this pass**, and it is the largest reachable
//! keymgmt unit: four rows (`X25519`, `X448`, `ED25519`, `ED448`) over the ECX object layer D372
//! landed. Its own four dispatch tables live in [`crate::provider::ecx_kmgmt`] because the unit is
//! 1,338 lines and shares nothing with the two above but the dispatch-slot names; the four rows are
//! appended to [`DEFLT_KEYMGMT`] in the authority's order. Landing it is what makes the two
//! `exchange/ecx_exch.c.in` and two `kem/ecx_kem.c.in` rows drivable, which is why all three units
//! land in one pass.
//!
//! **`mac_legacy_kmgmt.c` is the fourth unit**, the four legacy MAC key types (`HMAC`, `SIPHASH`,
//! `POLY1305`, `CMAC`), transcribed whole in [`crate::provider::mac_legacy_kmgmt`]. Its one
//! `#if !defined(OPENSSL_NO_ENGINE)` arm is reduced the way D181 reduces that family, with its
//! reason at the site.
//!
//! ## The DH unit's one raise is a `_data` site, and it is the authority's `__func__`
//!
//! `dh_gen` raises `ERR_LIB_PROV`/`ERR_R_INTERNAL_ERROR` at `dh_kmgmt.c:725` through
//! `ERR_raise_data`, so the coordinate carries a message ("gen_type set to unsupported value %d")
//! and the enclosing function is `dh_gen`, not the generated constant's line alone. `gen_err_raise_sites.py`
//! records the unit as `PROV_DH_KMGMT`; the three `ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT)`
//! sites (`:544`, `:558`, `:681`) and the `ERR_R_UNSUPPORTED` one (`:653`) are the plain form.
//!
//! SPDX-License-Identifier: Apache-2.0

// The three `ossl_kdf_data_*` exports are `pub` and `#[no_mangle]` because the authority's own
// `prov/kdfexchange.h` declares them and `exchange/kdf_exch.c` links to them across translation
// units; here they are reached only from this crate, but the symbol and its width are the ABI's,
// not this module's. `provider` is a `pub(crate)` module, so `pub` on them is `unreachable_pub`; the
// module-level allow is the same one `src/rsa/object.rs` and `src/aria.rs` carry for the same
// reason. `unreachable_pub` is a *warn* in `Cargo.toml` and `-D warnings` promotes it, so without
// this the three symbols would have to be narrowed away from the ABI they transcribe.
#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::Ordering;

use crate::bn::arith::BN_cmp;
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set, BnGencb};
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dh::backend::{
    ossl_dh_dup, ossl_dh_key_fromdata, ossl_dh_key_todata, ossl_dh_params_fromdata,
    ossl_dh_params_todata,
};
use crate::dh::check::{
    ossl_dh_check_pairwise, ossl_dh_check_priv_key, ossl_dh_check_pub_key_partial, DH_check_ex,
    DH_check_params_ex, DH_check_pub_key_ex,
};
use crate::dh::gen::{
    ossl_dh_generate_ffc_parameters, ossl_dh_get_named_group_uid_from_size,
    DH_generate_parameters_ex,
};
use crate::dh::group_params::{ossl_dh_is_named_safe_prime_group, ossl_dh_new_by_nid_ex};
use crate::dh::key::{ossl_dh_buf2key, ossl_dh_key2buf, DH_generate_key};
use crate::dh::object::{
    ossl_dh_get0_params, ossl_dh_new_ex, DH_bits, DH_clear_flags, DH_free, DH_get0_g, DH_get0_p,
    DH_get0_priv_key, DH_get0_pub_key, DH_security_bits, DH_set_flags, DH_set_length, DH_size,
};
use crate::dh::Dh;
use crate::evp::keymgmt::{
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
};
use crate::evp::pkey::{OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY};
use crate::evp::pkey_ctx::{
    DH_PARAMGEN_TYPE_FIPS_186_2, DH_PARAMGEN_TYPE_GENERATOR, DH_PARAMGEN_TYPE_GROUP,
    OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_DH_GENERATOR, OSSL_PKEY_PARAM_DH_PRIV_LEN,
    OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_PCOUNTER,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED,
    OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PKEY_PARAM_GROUP_NAME,
};
use crate::ffc::dh::{ossl_ffc_name_to_dh_named_group, ossl_ffc_named_group_get_uid};
use crate::ffc::params::{
    ossl_ffc_params_cmp, ossl_ffc_params_copy, ossl_ffc_params_enable_flags,
    ossl_ffc_params_set_gindex, ossl_ffc_params_set_h, ossl_ffc_params_set_pcounter,
    ossl_ffc_params_set_seed, ossl_ffc_set_digest,
};
use crate::ffc::{FfcParams, FFC_PARAM_FLAG_VALIDATE_LEGACY};
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_int, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OsslParam, END, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UNSIGNED_INTEGER,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{param_int, param_octet_string, param_size_t, param_utf8_string};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::dsa_kmgmt::DSA_KEYMGMT_FUNCTIONS;
use crate::provider::ec_kmgmt::{EC_KEYMGMT_FUNCTIONS, SM2_KEYMGMT_FUNCTIONS};
use crate::provider::ecx_kmgmt::{
    ED25519_KEYMGMT_FUNCTIONS, ED448_KEYMGMT_FUNCTIONS, X25519_KEYMGMT_FUNCTIONS,
    X448_KEYMGMT_FUNCTIONS,
};
use crate::provider::mac_legacy_kmgmt::{
    CMAC_LEGACY_KEYMGMT_FUNCTIONS, MAC_LEGACY_KEYMGMT_FUNCTIONS,
};
use crate::provider::rsa_kmgmt::{RSA_KEYMGMT_FUNCTIONS, RSA_PSS_KEYMGMT_FUNCTIONS};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::obj::NID_undef;
use crate::selftest::OsslCallback;

/// The generated unit's own `__FILE__`, for `OPENSSL_zalloc`'s allocation attribution.
const FILE_KDF_LEGACY_KMGMT: *const core::ffi::c_char =
    c"providers/implementations/keymgmt/kdf_legacy_kmgmt.c".as_ptr();

/// `struct kdf_data_st` — `providers/implementations/include/prov/kdfexchange.h:14-17`. A legacy KDF
/// key-manager handle is nothing but the library context it was created in and a reference count;
/// the KDF itself lives in the `EVP_KDF_CTX` the *exchange* unit builds.
///
/// `CRYPTO_REF_COUNT` is a bare `int` on this profile (`internal/refcount.h`), so it is an
/// `AtomicI32` with relaxed/release ordering, exactly as `crypto/ec/ecx_key.c`'s object is.
#[repr(C)]
pub(crate) struct KdfData {
    /// `OSSL_LIB_CTX *libctx`.
    pub libctx: *mut c_void,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub refcnt: AtomicI32,
}

/// The default provider is always in a happy state on this build, so `ossl_prov_is_running()` — a
/// `FIPS_MODULE` self-test hook — answers 1. Kept as a function rather than an inlined `1` so every
/// authority guard is a guard in the transcription.
#[inline]
fn is_running() -> c_int {
    1
}

/// `KDF_DATA *ossl_kdf_data_new(void *provctx)` — `kdf_legacy_kmgmt.c:29-47`.
///
/// # Safety
/// `provctx` is the provider context the caller was given, or NULL.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_new(provctx: *mut c_void) -> *mut KdfData {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let kdfdata = CRYPTO_zalloc(core::mem::size_of::<KdfData>(), FILE_KDF_LEGACY_KMGMT, 0)
            .cast::<KdfData>();
        if kdfdata.is_null() {
            return ptr::null_mut();
        }

        // `if (!CRYPTO_NEW_REF(&kdfdata->refcnt, 1))` — the header's fallback arm on this profile is
        // `refcnt->val = n; return 1;`, so the failure branch (and its `OPENSSL_free`) is
        // unreachable rather than omitted. `NEW_REF` cannot fail for an inline atomic.
        // SAFETY: `refcnt` is a field of this call's own allocation.
        (*kdfdata).refcnt.store(1, Ordering::Relaxed);
        // SAFETY: as above; `provctx` is the caller's.
        (*kdfdata).libctx = prov_libctx_of(provctx);

        kdfdata
    }
}

/// `void ossl_kdf_data_free(KDF_DATA *kdfdata)` — `kdf_legacy_kmgmt.c:49-62`.
///
/// # Safety
/// `kdfdata` is NULL or a live handle; it must not be used again unless a reference remains.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_free(kdfdata: *mut KdfData) {
    if kdfdata.is_null() {
        return;
    }

    // SAFETY: `kdfdata` is live per the contract. `CRYPTO_DOWN_REF` answers the value *after* the
    // decrement, and the release/acquire fence is the header's.
    let ref_ = unsafe { (*kdfdata).refcnt.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
    if ref_ == 0 {
        core::sync::atomic::fence(Ordering::Acquire);
    }
    if ref_ > 0 {
        return;
    }

    // `CRYPTO_FREE_REF(&kdfdata->refcnt)` is empty on this profile's arm of the header.
    // SAFETY: this is the last reference to the handle.
    unsafe { CRYPTO_free(kdfdata.cast(), FILE_KDF_LEGACY_KMGMT, 61) };
}

/// `int ossl_kdf_data_up_ref(KDF_DATA *kdfdata)` — `kdf_legacy_kmgmt.c:64-80`. The one guard the
/// authority keeps though both current callers already hold it (the comment says so at `:68-74`).
///
/// # Safety
/// `kdfdata` is live.
#[no_mangle]
pub unsafe extern "C" fn ossl_kdf_data_up_ref(kdfdata: *mut KdfData) -> c_int {
    if is_running() == 0 {
        return 0;
    }
    // `CRYPTO_UP_REF` is a relaxed fetch-add; the authority ignores its out-parameter here.
    // SAFETY: `kdfdata` is live per the contract.
    unsafe { (*kdfdata).refcnt.fetch_add(1, Ordering::Relaxed) };
    1
}

/// `static void *kdf_newdata(void *provctx)` — `kdf_legacy_kmgmt.c:82-85`.
///
/// # Safety
/// The keymgmt `new` dispatch contract.
unsafe extern "C" fn kdf_newdata(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's.
    unsafe { ossl_kdf_data_new(provctx).cast() }
}

/// `static void kdf_freedata(void *kdfdata)` — `kdf_legacy_kmgmt.c:87-90`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn kdf_freedata(kdfdata: *mut c_void) {
    // SAFETY: the caller hands back what `kdf_newdata` answered.
    unsafe { ossl_kdf_data_free(kdfdata.cast()) };
}

/// `static int kdf_has(const void *keydata, int selection)` — `kdf_legacy_kmgmt.c:92-95`. Nothing is
/// missing, because there is nothing: a legacy KDF has no key material.
///
/// # Safety
/// The keymgmt `has` dispatch contract; neither argument is read.
unsafe extern "C" fn kdf_has(_keydata: *const c_void, _selection: c_int) -> c_int {
    1
}

/// `const OSSL_DISPATCH ossl_kdf_keymgmt_functions[]` — `kdf_legacy_kmgmt.c:97-102`. Three slots,
/// the authority's three, in its order.
pub(crate) static KDF_KEYMGMT_FUNCTIONS: [OsslDispatch; 4] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: kdf_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: kdf_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: kdf_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

// ---------------------------------------------------------------------------------------------
// `providers/implementations/keymgmt/dh_kmgmt.c` — the `DH` and `DHX` key types (D387)
//
// Nine hundred and ten lines, twenty-eight functions and two dispatch tables. The two rows differ
// in their **key type flag** (`DH_FLAG_TYPE_DH`/`DHX`), which the object carries and the exchange
// unit reads, and in the parameter-generation regime the two `*_gen_init` entry points select.
// ---------------------------------------------------------------------------------------------

/// `TYPE_ANY` — `crypto/evp/dh_support.c:22`, restated here because this unt one reads it through
/// `ossl_dh_gen_type_name2id`'s own table rather than through a constant of its own.
const DH_FLAG_TYPE_MASK: c_int = 0xF000;
/// `DH_FLAG_TYPE_DH` — `include/openssl/dh.h:111`. The zero word: a PKCS#3 parameter set.
const DH_FLAG_TYPE_DH: c_int = 0x0000;
/// `DH_FLAG_TYPE_DHX` — `include/openssl/dh.h:112`. X9.42.
const DH_FLAG_TYPE_DHX: c_int = 0x1000;

/// `DH_GENERATOR_2` — `include/openssl/dh.h:147`, repeated rather than re-exported for the reason
/// every numeric constant in this crate is.
const DH_GENERATOR_2: c_int = 2;

/// `OSSL_KEYMGMT_SELECT_PRIVATE_KEY` — `core_dispatch.h:640-652`.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
/// `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;
/// `OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS`.
const OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS: c_int = 0x80;
/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — the union of the two parameter bits.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
/// `OSSL_KEYMGMT_SELECT_KEYPAIR` — `PRIVATE_KEY | PUBLIC_KEY`.
const OSSL_KEYMGMT_SELECT_KEYPAIR: c_int =
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
/// `DH_POSSIBLE_SELECTIONS` — `dh_kmgmt.c:53-54`.
const DH_POSSIBLE_SELECTIONS: c_int =
    OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

/// `OSSL_KEYMGMT_VALIDATE_QUICK_CHECK` — `core_dispatch.h`. The other value the authority names,
/// `OSSL_KEYMGMT_VALIDATE_FULL_CHECK` (0), is the `else` arm's and is therefore not a name this
/// unit reads.
const OSSL_KEYMGMT_VALIDATE_QUICK_CHECK: c_int = 1;

/// `OSSL_PKEY_PARAM_SECURITY_BITS` — `core_names.h`. The three below are local because only this
/// unit's `dh_get_params` reads them.
const OSSL_PKEY_PARAM_SECURITY_BITS: *const c_char = c"security-bits".as_ptr();
/// `OSSL_PKEY_PARAM_MAX_SIZE`.
const OSSL_PKEY_PARAM_MAX_SIZE: *const c_char = c"max-size".as_ptr();
/// `OSSL_PKEY_PARAM_SECURITY_CATEGORY`, spelled `OSSL_ALG_PARAM_SECURITY_CATEGORY`.
const OSSL_PKEY_PARAM_SECURITY_CATEGORY: *const c_char = c"security-category".as_ptr();
/// `OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` — `core_names.h:398`.
const OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: *const c_char = c"encoded-pub-key".as_ptr();

/// `OSSL_GEN_PARAM_POTENTIAL` — `core_names.h`.
const OSSL_GEN_PARAM_POTENTIAL: *const c_char = c"potential".as_ptr();
/// `OSSL_GEN_PARAM_ITERATION`.
const OSSL_GEN_PARAM_ITERATION: *const c_char = c"iteration".as_ptr();

/// `FILE_DH_KMGMT` — the generated unit's own `__FILE__`.
const FILE_DH_KMGMT: *const c_char = c"providers/implementations/keymgmt/dh_kmgmt.c".as_ptr();

/// `struct dh_gen_ctx` — `dh_kmgmt.c:56-80`. The parameter-generation context, zero-allocated and
/// filled by `dh_gen_init_base` and the two `*_gen_set_params`; it is opaque in the authority
/// (`genctx` is a `void *` everywhere the dispatch contract sees it), so only the fields this
/// crate reads need a name.
#[repr(C)]
struct DhGenCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `FFC_PARAMS *ffc_params` — a template's parameters, borrowed, or NULL.
    ffc_params: *mut FfcParams,
    /// `int selection`.
    selection: c_int,
    /// `int group_nid`.
    group_nid: c_int,
    /// `size_t pbits`.
    pbits: usize,
    /// `size_t qbits`.
    qbits: usize,
    /// `unsigned char *seed` — optional FIPS186-4 parameter, owned.
    seed: *mut u8,
    /// `size_t seedlen`.
    seedlen: usize,
    /// `int gindex` — `-1` when unset.
    gindex: c_int,
    /// `int gen_type` — see `dhtype2id`.
    gen_type: c_int,
    /// `int generator` — used by `DH_PARAMGEN_TYPE_GENERATOR` in non-FIPS mode only.
    generator: c_int,
    /// `int pcounter`.
    pcounter: c_int,
    /// `int hindex`.
    hindex: c_int,
    /// `int priv_len`.
    priv_len: c_int,
    /// `char *mdname` — owned.
    mdname: *mut c_char,
    /// `char *mdprops` — owned.
    mdprops: *mut c_char,
    /// `OSSL_CALLBACK *cb` — the caller's progress callback.
    cb: Option<OsslCallback>,
    /// `void *cbarg`.
    cbarg: *mut c_void,
    /// `int dh_type` — `DH_FLAG_TYPE_DH` or `DH_FLAG_TYPE_DHX`.
    dh_type: c_int,
}

/// `static int dh_gen_type_name2id_w_default(const char *name, int type)` — `dh_kmgmt.c:82-99`.
///
/// The `#ifdef FIPS_MODULE` arm is not this profile's, so `"default"` is `FIPS_186_2` for a `DHX`
/// and `GENERATOR` for a `DH`; everything else is the shared table's answer.
///
/// # Safety
/// `name` is NUL-terminated.
unsafe fn dh_gen_type_name2id_w_default(name: *const c_char, type_: c_int) -> c_int {
    // SAFETY: `name` is NUL-terminated per the contract and the literal is `'static`.
    if unsafe { crate::runtime::bio::sys::strcmp(name, c"default".as_ptr()) } == 0 {
        if type_ == DH_FLAG_TYPE_DHX {
            return DH_PARAMGEN_TYPE_FIPS_186_2;
        }
        return DH_PARAMGEN_TYPE_GENERATOR;
    }

    // SAFETY: as above; the shared table's own contract.
    unsafe { crate::evp::pkey_ctx::ossl_dh_gen_type_name2id(name, type_) }
}

/// `ossl_param_is_empty` — `include/internal/common.h`. The same three-line reader
/// `src/provider/cipher.rs` and `src/provider/digest.rs` carry.
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn param_is_empty(params: *const OsslParam) -> bool {
    if params.is_null() {
        return true;
    }
    // SAFETY: the first entry of a key-terminated array is readable.
    unsafe { (*params).key.is_null() }
}

/// `static void *dh_newdata(void *provctx)` — `dh_kmgmt.c:101-113`.
///
/// # Safety
/// The keymgmt `new` dispatch contract; `provctx` is the caller's.
unsafe extern "C" fn dh_newdata(provctx: *mut c_void) -> *mut c_void {
    let mut dh: *mut Dh = ptr::null_mut();

    if is_running() != 0 {
        // SAFETY: `provctx` is the caller's provider context.
        dh = unsafe { ossl_dh_new_ex(prov_libctx_of(provctx)) };
        if !dh.is_null() {
            // SAFETY: `dh` is this call's own object.
            unsafe {
                DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
                DH_set_flags(dh, DH_FLAG_TYPE_DH);
            }
        }
    }
    dh.cast()
}

/// `static void *dhx_newdata(void *provctx)` — `dh_kmgmt.c:115-125`.
///
/// **No `ossl_prov_is_running()` guard**: the authority's `dhx_newdata` does not consult it, and
/// neither does this.
///
/// # Safety
/// The keymgmt `new` dispatch contract; `provctx` is the caller's.
unsafe extern "C" fn dhx_newdata(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: `provctx` is the caller's provider context.
    let dh = unsafe { ossl_dh_new_ex(prov_libctx_of(provctx)) };
    if !dh.is_null() {
        // SAFETY: `dh` is this call's own object.
        unsafe {
            DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
            DH_set_flags(dh, DH_FLAG_TYPE_DHX);
        }
    }
    dh.cast()
}

/// `static void dh_freedata(void *keydata)` — `dh_kmgmt.c:127-130`.
///
/// # Safety
/// The keymgmt `free` dispatch contract.
unsafe extern "C" fn dh_freedata(keydata: *mut c_void) {
    // SAFETY: the caller hands back what `dh_newdata`/`dhx_newdata` answered, or NULL.
    unsafe { DH_free(keydata.cast()) };
}

/// `static int dh_has(const void *keydata, int selection)` — `dh_kmgmt.c:132-149`.
///
/// The selection gate is `DH_POSSIBLE_SELECTIONS`, so a request for other types' parameters is
/// answered 1 rather than 0: there is nothing of the kind to be missing.
///
/// # Safety
/// The keymgmt `has` dispatch contract.
unsafe extern "C" fn dh_has(keydata: *const c_void, selection: c_int) -> c_int {
    let dh = keydata.cast::<Dh>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dh.is_null() {
        return 0;
    }
    if (selection & DH_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* the selection is not missing */
    }

    // SAFETY: `dh` is non-NULL past the guard above.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= c_int::from(!DH_get0_pub_key(dh).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= c_int::from(!DH_get0_priv_key(dh).is_null());
        }
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            ok &= c_int::from(!DH_get0_p(dh).is_null() && !DH_get0_g(dh).is_null());
        }
    }
    ok
}

/// `static int dh_match(const void *keydata1, const void *keydata2, int selection)` —
/// `dh_kmgmt.c:151-191`. The keypair half prefers the public keys and falls back to the private
/// ones only when no public pair was compared at all — which is why `key_checked` is a separate
/// local rather than folded into `ok`.
///
/// # Safety
/// The keymgmt `match` dispatch contract.
unsafe extern "C" fn dh_match(
    keydata1: *const c_void,
    keydata2: *const c_void,
    selection: c_int,
) -> c_int {
    let dh1 = keydata1.cast::<Dh>();
    let dh2 = keydata2.cast::<Dh>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the two objects are the caller's, per the dispatch contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let mut key_checked = 0;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
                let pa = DH_get0_pub_key(dh1);
                let pb = DH_get0_pub_key(dh2);
                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            if key_checked == 0 && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
                let pa = DH_get0_priv_key(dh1);
                let pb = DH_get0_priv_key(dh2);
                if !pa.is_null() && !pb.is_null() {
                    ok &= c_int::from(BN_cmp(pa, pb) == 0);
                    key_checked = 1;
                }
            }
            ok &= key_checked;
        }
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            let dhparams1 = ossl_dh_get0_params(dh1.cast_mut());
            let dhparams2 = ossl_dh_get0_params(dh2.cast_mut());
            ok &= ossl_ffc_params_cmp(dhparams1, dhparams2, 1);
        }
    }
    ok
}

/// `static int dh_import(void *keydata, int selection, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:193-214`.
///
/// # Safety
/// The keymgmt `import` dispatch contract.
unsafe extern "C" fn dh_import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> c_int {
    let dh = keydata.cast::<Dh>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dh.is_null() {
        return 0;
    }
    if (selection & DH_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    // SAFETY: `dh` is non-NULL past the guard above and `params` is the caller's array.
    unsafe {
        /* a key without parameters is meaningless */
        ok &= ossl_dh_params_fromdata(dh, params);

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
            ok &= ossl_dh_key_fromdata(dh, params, include_private);
        }
    }
    ok
}

/// `static int dh_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg)` —
/// `dh_kmgmt.c:216-253`.
///
/// # Safety
/// The keymgmt `export` dispatch contract.
unsafe extern "C" fn dh_export(
    keydata: *mut c_void,
    selection: c_int,
    param_cb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> c_int {
    let dh = keydata.cast::<Dh>();
    let mut ok: c_int = 1;

    if is_running() == 0 || dh.is_null() {
        return 0;
    }
    if (selection & DH_POSSIBLE_SELECTIONS) == 0 {
        return 0;
    }

    let tmpl = OSSL_PARAM_BLD_new();
    if tmpl.is_null() {
        return 0;
    }

    // SAFETY: `dh` is non-NULL past the guard; `tmpl` is this call's own builder.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 {
            ok &= ossl_dh_params_todata(dh, tmpl, ptr::null_mut());
        }
        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            let include_private = c_int::from((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
            ok &= ossl_dh_key_todata(dh, tmpl, ptr::null_mut(), include_private);
        }

        let params = if ok == 0 {
            ptr::null_mut()
        } else {
            OSSL_PARAM_BLD_to_param(tmpl)
        };
        if ok == 0 || params.is_null() {
            // The authority's `err:` label with `ok` set to 0: only the builder is released.
            OSSL_PARAM_BLD_free(tmpl);
            return 0;
        }

        let ret = match param_cb {
            Some(cb) => cb(params, cbarg),
            None => 0,
        };
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(tmpl);
        ret
    }
}

/* IMEXPORT = IMPORT + EXPORT */

/// `DH_IMEXPORTABLE_PARAMETERS` — `dh_kmgmt.c:257-267`, spliced into three tables the way the
/// authority's macro is. A macro that expands to a whole array literal rather than to a
/// comma-separated list, because Rust's macro expansion cannot splice a list into an array
/// literal; the ten entries are the authority's, in its order.
macro_rules! dh_imexportable_table {
    ($($extra:expr),* $(,)?) => {
        [
            param_bn(OSSL_PKEY_PARAM_FFC_P),
            param_bn(OSSL_PKEY_PARAM_FFC_Q),
            param_bn(OSSL_PKEY_PARAM_FFC_G),
            param_bn(OSSL_PKEY_PARAM_FFC_COFACTOR),
            param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
            param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
            param_int(OSSL_PKEY_PARAM_FFC_H),
            param_int(OSSL_PKEY_PARAM_DH_PRIV_LEN),
            param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
            param_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME),
            $($extra,)*
        ]
    };
}

/// `OSSL_PARAM_BN(key, NULL, 0)` — `include/openssl/params.h`: `UNSIGNED_INTEGER` with a zero
/// `data_size`, which is what the key-only form of a `BIGNUM` parameter carries.
const fn param_bn(key: *const c_char) -> OsslParam {
    OsslParam {
        key: key.cast(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `static const OSSL_PARAM dh_all_types[]` — `dh_kmgmt.c:272-277`.
static DH_ALL_TYPES: [OsslParam; 13] = dh_imexportable_table!(
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END
);

/// `static const OSSL_PARAM dh_parameter_types[]` — `dh_kmgmt.c:278-281`.
static DH_PARAMETER_TYPES: [OsslParam; 11] = dh_imexportable_table!(END);

/// `static const OSSL_PARAM dh_key_types[]` — `dh_kmgmt.c:282-286`.
static DH_KEY_TYPES: [OsslParam; 3] = [
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END,
];

/// `static const OSSL_PARAM *dh_types[]` — `dh_kmgmt.c:287-292`. Index 0 is "none of them".
///
/// The newtype is only here because a `static` of raw pointers needs a `Sync` impl; the four
/// entries are `'static` table addresses and nothing writes it.
struct DhTypes([*const OsslParam; 4]);
// SAFETY: the array holds `'static` addresses of `'static` const tables and has no interior
// mutability; the same reasoning `OsslParam` and `OsslDispatch` carry.
unsafe impl Sync for DhTypes {}

static DH_TYPES: DhTypes = DhTypes([
    ptr::null(),
    DH_PARAMETER_TYPES.as_ptr(),
    DH_KEY_TYPES.as_ptr(),
    DH_ALL_TYPES.as_ptr(),
]);

/// `static const OSSL_PARAM *dh_imexport_types(int selection)` — `dh_kmgmt.c:294-303`.
unsafe extern "C" fn dh_imexport_types(selection: c_int) -> *const OsslParam {
    let mut type_select = 0usize;

    if (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0 {
        type_select += 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
        type_select += 2;
    }
    DH_TYPES.0[type_select]
}

/// `static const OSSL_PARAM *dh_import_types(int selection)` — `dh_kmgmt.c:305-308`.
unsafe extern "C" fn dh_import_types(selection: c_int) -> *const OsslParam {
    // SAFETY: the shared helper reads only its argument.
    unsafe { dh_imexport_types(selection) }
}

/// `static const OSSL_PARAM *dh_export_types(int selection)` — `dh_kmgmt.c:310-313`.
unsafe extern "C" fn dh_export_types(selection: c_int) -> *const OsslParam {
    // SAFETY: as above.
    unsafe { dh_imexport_types(selection) }
}

/// `static ossl_inline int dh_get_params(void *key, OSSL_PARAM params[])` — `dh_kmgmt.c:315-343`.
///
/// The encoded-public-key write passes the descriptor's **own `data` slot** as the destination,
/// which is why the pointer is `&p->data` rather than a local: the caller supplied the buffer and
/// the answer's length lands in `return_size`.
///
/// # Safety
/// The keymgmt `get_params` dispatch contract.
unsafe extern "C" fn dh_get_params(key: *mut c_void, params: *mut OsslParam) -> c_int {
    let dh = key.cast::<Dh>();

    // SAFETY: `dh` and `params` are the caller's, per the dispatch contract; `locate` answers NULL
    // or an entry of the caller's array.
    unsafe {
        let mut p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if !p.is_null() && OSSL_PARAM_set_int(p, DH_bits(dh)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if !p.is_null() && OSSL_PARAM_set_int(p, DH_security_bits(dh)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if !p.is_null() && OSSL_PARAM_set_int(p, DH_size(dh)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if !p.is_null() {
            if (*p).data_type != OSSL_PARAM_OCTET_STRING {
                return 0;
            }
            (*p).return_size = ossl_dh_key2buf(
                dh,
                ptr::addr_of_mut!((*p).data).cast::<*mut c_uchar>(),
                (*p).data_size,
                0,
            );
            if (*p).return_size == 0 {
                return 0;
            }
        }
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
        if !p.is_null() && OSSL_PARAM_set_int(p, 0) == 0 {
            return 0;
        }

        c_int::from(
            ossl_dh_params_todata(dh, ptr::null_mut(), params) != 0
                && ossl_dh_key_todata(dh, ptr::null_mut(), params, 1) != 0,
        )
    }
}

/// `static const OSSL_PARAM dh_params[]` — `dh_kmgmt.c:345-355`.
static DH_PARAMS: [OsslParam; 18] = dh_imexportable_table!(
    param_int(OSSL_PKEY_PARAM_BITS),
    param_int(OSSL_PKEY_PARAM_SECURITY_BITS),
    param_int(OSSL_PKEY_PARAM_MAX_SIZE),
    param_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY),
    param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY),
    param_bn(OSSL_PKEY_PARAM_PUB_KEY),
    param_bn(OSSL_PKEY_PARAM_PRIV_KEY),
    END
);

/// `static const OSSL_PARAM *dh_gettable_params(void *provctx)` — `dh_kmgmt.c:357-360`.
unsafe extern "C" fn dh_gettable_params(_provctx: *mut c_void) -> *const OsslParam {
    DH_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM dh_known_settable_params[]` — `dh_kmgmt.c:362-365`.
static DH_KNOWN_SETTABLE_PARAMS: [OsslParam; 2] =
    [param_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY), END];

/// `static const OSSL_PARAM *dh_settable_params(void *provctx)` — `dh_kmgmt.c:367-370`.
unsafe extern "C" fn dh_settable_params(_provctx: *mut c_void) -> *const OsslParam {
    DH_KNOWN_SETTABLE_PARAMS.as_ptr()
}

/// `static int dh_set_params(void *key, const OSSL_PARAM params[])` — `dh_kmgmt.c:372-384`.
///
/// # Safety
/// The keymgmt `set_params` dispatch contract.
unsafe extern "C" fn dh_set_params(key: *mut c_void, params: *const OsslParam) -> c_int {
    let dh = key.cast::<Dh>();

    // SAFETY: `dh` and `params` are the caller's; `locate` answers NULL or an entry of `params`.
    unsafe {
        let p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if !p.is_null()
            && ((*p).data_type != OSSL_PARAM_OCTET_STRING
                || ossl_dh_buf2key(dh, (*p).data.cast::<c_uchar>(), (*p).data_size) == 0)
        {
            return 0;
        }

        1
    }
}

/// `static int dh_validate_public(const DH *dh, int checktype)` — `dh_kmgmt.c:386-403`.
///
/// # Safety
/// `dh` is live.
unsafe fn dh_validate_public(dh: *const Dh, _checktype: c_int) -> c_int {
    let mut res: c_int = 0;

    // SAFETY: `dh` is live per the contract.
    unsafe {
        let pub_key = DH_get0_pub_key(dh);
        if pub_key.is_null() {
            return 0;
        }

        /*
         * The partial test is only valid for named group's with q = (p - 1) / 2
         * but for that case it is also fully sufficient to check the key validity.
         */
        if ossl_dh_is_named_safe_prime_group(dh) != 0 {
            return ossl_dh_check_pub_key_partial(dh, pub_key, &mut res);
        }

        DH_check_pub_key_ex(dh, pub_key)
    }
}

/// `static int dh_validate_private(const DH *dh)` — `dh_kmgmt.c:405-414`.
///
/// # Safety
/// `dh` is live.
unsafe fn dh_validate_private(dh: *const Dh) -> c_int {
    let mut status: c_int = 0;

    // SAFETY: `dh` is live per the contract.
    unsafe {
        let priv_key = DH_get0_priv_key(dh);
        if priv_key.is_null() {
            return 0;
        }
        ossl_dh_check_priv_key(dh, priv_key, &mut status)
    }
}

/// `static int dh_validate(const void *keydata, int selection, int checktype)` —
/// `dh_kmgmt.c:416-449`.
///
/// # Safety
/// The keymgmt `validate` dispatch contract.
unsafe extern "C" fn dh_validate(
    keydata: *const c_void,
    selection: c_int,
    checktype: c_int,
) -> c_int {
    let dh = keydata.cast::<Dh>();
    let mut ok: c_int = 1;

    if is_running() == 0 {
        return 0;
    }
    if (selection & DH_POSSIBLE_SELECTIONS) == 0 {
        return 1; /* nothing to validate */
    }

    // SAFETY: `dh` is the caller's object, per the dispatch contract.
    unsafe {
        if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
            /*
             * Both of these functions check parameters. DH_check_params_ex()
             * performs a lightweight check (e.g. it does not check that p is a
             * safe prime)
             */
            if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                ok &= DH_check_params_ex(dh);
            } else {
                ok &= DH_check_ex(dh);
            }
        }

        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 {
            ok &= dh_validate_public(dh, checktype);
        }

        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 {
            ok &= dh_validate_private(dh);
        }

        if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR {
            ok &= ossl_dh_check_pairwise(dh, 0);
        }
    }
    ok
}

/// `static void *dh_gen_init_base(void *provctx, int selection, const OSSL_PARAM params[], int
/// type)` — `dh_kmgmt.c:451-489`.
///
/// # Safety
/// `provctx` is the caller's provider context; `params` is NULL or a key-terminated array.
unsafe fn dh_gen_init_base(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
    type_: c_int,
) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    if (selection & (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0 {
        return ptr::null_mut();
    }

    // SAFETY: a fresh zeroed allocation of this call's own context.
    let gctx =
        CRYPTO_zalloc(core::mem::size_of::<DhGenCtx>(), FILE_DH_KMGMT, 463).cast::<DhGenCtx>();
    if !gctx.is_null() {
        // SAFETY: `gctx` is this call's own allocation; `provctx` is the caller's.
        unsafe {
            (*gctx).selection = selection;
            (*gctx).libctx = prov_libctx_of(provctx);
            (*gctx).pbits = 2048;
            (*gctx).qbits = 224;
            (*gctx).mdname = ptr::null_mut();
            (*gctx).gen_type = if type_ == DH_FLAG_TYPE_DHX {
                DH_PARAMGEN_TYPE_FIPS_186_2
            } else {
                DH_PARAMGEN_TYPE_GENERATOR
            };
            (*gctx).gindex = -1;
            (*gctx).hindex = 0;
            (*gctx).pcounter = -1;
            (*gctx).generator = DH_GENERATOR_2;
            (*gctx).dh_type = type_;
        }
    }
    // SAFETY: `gctx` is NULL or this call's own context; `params` is the caller's array.
    if unsafe { dh_gen_set_params(gctx.cast(), params) } == 0 {
        // SAFETY: `gctx` is this call's own allocation, not yet published.
        unsafe { CRYPTO_free(gctx.cast(), FILE_DH_KMGMT, 485) };
        return ptr::null_mut();
    }
    gctx.cast()
}

/// `static void *dh_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:491-495`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn dh_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { dh_gen_init_base(provctx, selection, params, DH_FLAG_TYPE_DH) }
}

/// `static void *dhx_gen_init(void *provctx, int selection, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:497-501`.
///
/// # Safety
/// The keymgmt `gen_init` dispatch contract.
unsafe extern "C" fn dhx_gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OsslParam,
) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { dh_gen_init_base(provctx, selection, params, DH_FLAG_TYPE_DHX) }
}

/// `static int dh_gen_set_template(void *genctx, void *templ)` — `dh_kmgmt.c:503-512`.
///
/// # Safety
/// The keymgmt `gen_set_template` dispatch contract.
unsafe extern "C" fn dh_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int {
    let gctx = genctx.cast::<DhGenCtx>();
    let dh = templ.cast::<Dh>();

    if is_running() == 0 || gctx.is_null() || dh.is_null() {
        return 0;
    }
    // SAFETY: both objects are non-NULL past the guard.
    unsafe { (*gctx).ffc_params = ossl_dh_get0_params(dh) };
    1
}

/// `static int dh_set_gen_seed(struct dh_gen_ctx *gctx, unsigned char *seed, size_t seedlen)` —
/// `dh_kmgmt.c:514-527`.
///
/// # Safety
/// `gctx` is live; `seed` is NULL or readable for `seedlen` bytes.
unsafe fn dh_set_gen_seed(gctx: *mut DhGenCtx, seed: *mut u8, seedlen: usize) -> c_int {
    // SAFETY: `gctx` is live per the contract, and its own `seed`/`seedlen` are released here.
    unsafe {
        CRYPTO_clear_free((*gctx).seed.cast(), (*gctx).seedlen, FILE_DH_KMGMT, 517);
        (*gctx).seed = ptr::null_mut();
        (*gctx).seedlen = 0;
        if !seed.is_null() && seedlen > 0 {
            (*gctx).seed = CRYPTO_memdup(seed.cast(), seedlen, FILE_DH_KMGMT, 521).cast();
            if (*gctx).seed.is_null() {
                return 0;
            }
            (*gctx).seedlen = seedlen;
        }
    }
    1
}

/// `static int dh_gen_common_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:529-569`.
///
/// # Safety
/// `genctx` is NULL or a live `DhGenCtx`; `params` is NULL or a key-terminated array.
unsafe fn dh_gen_common_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<DhGenCtx>();

    if gctx.is_null() {
        return 0;
    }
    // SAFETY: `params` is NULL or a key-terminated array per the contract.
    if unsafe { param_is_empty(params) } {
        return 1;
    }

    // SAFETY: `gctx` is live past the guard; `params` is the caller's array and locate answers
    // NULL or one of its entries.
    unsafe {
        let mut p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_TYPE);
        if !p.is_null() {
            if (*p).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
                raise_site(&err_sites::PROV_DH_KMGMT_544);
                return 0;
            }
            let gen_type =
                dh_gen_type_name2id_w_default((*p).data.cast::<c_char>(), (*gctx).dh_type);
            if gen_type == -1 {
                raise_site(&err_sites::PROV_DH_KMGMT_544);
                return 0;
            }
            if gen_type != -1 {
                (*gctx).gen_type = gen_type;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if !p.is_null() {
            if (*p).data_type != crate::params::OSSL_PARAM_UTF8_STRING || (*p).data.is_null() {
                raise_site(&err_sites::PROV_DH_KMGMT_558);
                return 0;
            }
            let group = ossl_ffc_name_to_dh_named_group((*p).data.cast::<c_char>());
            if group.is_null() || ossl_ffc_named_group_get_uid(group) == NID_undef {
                raise_site(&err_sites::PROV_DH_KMGMT_558);
                return 0;
            }
            (*gctx).group_nid = ossl_ffc_named_group_get_uid(group);
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, ptr::addr_of_mut!((*gctx).pbits)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
        if !p.is_null() && OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*gctx).priv_len)) == 0 {
            return 0;
        }
    }
    1
}

/// `static const OSSL_PARAM *dh_gen_settable_params(void *genctx, void *provctx)` —
/// `dh_kmgmt.c:571-583`.
static DH_GEN_SETTABLE_PARAMS: [OsslParam; 6] = [
    param_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE),
    param_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME),
    param_int(OSSL_PKEY_PARAM_DH_PRIV_LEN),
    param_size_t(OSSL_PKEY_PARAM_FFC_PBITS),
    param_int(OSSL_PKEY_PARAM_DH_GENERATOR),
    END,
];

/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn dh_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DH_GEN_SETTABLE_PARAMS.as_ptr()
}

/// `static const OSSL_PARAM *dhx_gen_settable_params(void *genctx, void *provctx)` —
/// `dh_kmgmt.c:585-603`.
static DHX_GEN_SETTABLE_PARAMS: [OsslParam; 12] = [
    param_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE),
    param_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME),
    param_int(OSSL_PKEY_PARAM_DH_PRIV_LEN),
    param_size_t(OSSL_PKEY_PARAM_FFC_PBITS),
    param_size_t(OSSL_PKEY_PARAM_FFC_QBITS),
    param_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST),
    param_utf8_string(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS),
    param_int(OSSL_PKEY_PARAM_FFC_GINDEX),
    param_octet_string(OSSL_PKEY_PARAM_FFC_SEED),
    param_int(OSSL_PKEY_PARAM_FFC_PCOUNTER),
    param_int(OSSL_PKEY_PARAM_FFC_H),
    END,
];

/// # Safety
/// The keymgmt `gen_settable_params` dispatch contract.
unsafe extern "C" fn dhx_gen_settable_params(
    _genctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DHX_GEN_SETTABLE_PARAMS.as_ptr()
}

/// `static int dhx_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:605-657`.
///
/// # Safety
/// `genctx` is a live `DhGenCtx`; `params` is NULL or a key-terminated array.
unsafe fn dhx_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<DhGenCtx>();

    // SAFETY: the caller's contract.
    if unsafe { dh_gen_common_set_params(genctx, params) } == 0 {
        return 0;
    }

    // SAFETY: `gctx` is live and `params` is the caller's array; every out-parameter below is a
    // field of `gctx`.
    unsafe {
        /* Parameters related to fips186-4 and fips186-2 */
        let mut p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
        if !p.is_null() && OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*gctx).gindex)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
        if !p.is_null() && OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*gctx).pcounter)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
        if !p.is_null() && OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*gctx).hindex)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
        if !p.is_null()
            && ((*p).data_type != OSSL_PARAM_OCTET_STRING
                || dh_set_gen_seed(gctx, (*p).data.cast::<u8>(), (*p).data_size) == 0)
        {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS);
        if !p.is_null() && OSSL_PARAM_get_size_t(p, ptr::addr_of_mut!((*gctx).qbits)) == 0 {
            return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
        if !p.is_null() {
            if (*p).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).mdname.cast(), FILE_DH_KMGMT, 635);
            (*gctx).mdname = CRYPTO_strdup((*p).data.cast::<c_char>(), FILE_DH_KMGMT, 636);
            if (*gctx).mdname.is_null() {
                return 0;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
        if !p.is_null() {
            if (*p).data_type != crate::params::OSSL_PARAM_UTF8_STRING {
                return 0;
            }
            CRYPTO_free((*gctx).mdprops.cast(), FILE_DH_KMGMT, 644);
            (*gctx).mdprops = CRYPTO_strdup((*p).data.cast::<c_char>(), FILE_DH_KMGMT, 645);
            if (*gctx).mdprops.is_null() {
                return 0;
            }
        }

        /* Parameters that are not allowed for DHX */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
        if !p.is_null() {
            raise_site(&err_sites::PROV_DH_KMGMT_653);
            return 0;
        }
    }
    1
}

/// `static int dh_gen_set_params(void *genctx, const OSSL_PARAM params[])` —
/// `dh_kmgmt.c:659-685`.
///
/// # Safety
/// `genctx` is a live `DhGenCtx`; `params` is NULL or a key-terminated array.
unsafe fn dh_gen_set_params(genctx: *mut c_void, params: *const OsslParam) -> c_int {
    let gctx = genctx.cast::<DhGenCtx>();

    // SAFETY: the caller's contract.
    if unsafe { dh_gen_common_set_params(genctx, params) } == 0 {
        return 0;
    }

    // SAFETY: `gctx` is live and `params` is the caller's array.
    unsafe {
        let p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
        if !p.is_null() && OSSL_PARAM_get_int(p, ptr::addr_of_mut!((*gctx).generator)) == 0 {
            return 0;
        }

        /* Parameters that are not allowed for DH */
        if !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_QBITS).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST).is_null()
            || !OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS).is_null()
        {
            raise_site(&err_sites::PROV_DH_KMGMT_681);
            return 0;
        }
    }
    1
}

/// `static int dh_gencb(int p, int n, BN_GENCB *cb)` — `dh_kmgmt.c:687-696`. The adapter between
/// the `BN_GENCB` the generation loops call and the caller's `OSSL_CALLBACK`: the event number `p`
/// is `potential` and the iteration `n` is `iteration`.
///
/// # Safety
/// The `BN_GENCB` contract; `cb` carries a live `DhGenCtx` as its argument.
unsafe extern "C" fn dh_gencb(p: c_int, n: c_int, cb: *mut BnGencb) -> c_int {
    // SAFETY: `cb` is the callback the generation loop was handed.
    let gctx = unsafe { BN_GENCB_get_arg(cb) }.cast::<DhGenCtx>();
    let mut pv = p;
    let mut nv = n;
    let mut params = [END, END, END];

    // SAFETY: `params` is a three-entry local array and `pv`/`nv` outlive the calls that read
    // them.
    unsafe {
        params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &mut pv);
        params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &mut nv);
    }

    // SAFETY: `gctx` is the argument the caller installed; the callback contract is the
    // caller's.
    unsafe {
        match (*gctx).cb {
            Some(f) => f(params.as_mut_ptr(), (*gctx).cbarg),
            None => 0,
        }
    }
}

/// `static void *dh_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)` — `dh_kmgmt.c:698-816`.
///
/// The `#ifdef FIPS_MODULE` self-test arm is not this profile's and is not transcribed; the rest
/// is the authority's, including the `ossl_assert` that a `gen_type` outside the two known words
/// raises `ERR_R_INTERNAL_ERROR` **with a message** rather than refusing quietly.
///
/// # Safety
/// The keymgmt `gen` dispatch contract.
unsafe extern "C" fn dh_gen(
    genctx: *mut c_void,
    osslcb: Option<OsslCallback>,
    cbarg: *mut c_void,
) -> *mut c_void {
    let mut ret: c_int = 0;
    let gctx = genctx.cast::<DhGenCtx>();
    let dh: *mut Dh;
    let mut gencb: *mut BnGencb = ptr::null_mut();

    if is_running() == 0 || gctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `gctx` is non-NULL past the guard; every call below takes it or `dh`.
    unsafe {
        /*
         * If a group name is selected then the type is group regardless of what
         * the user selected. This overrides rather than errors for backwards
         * compatibility.
         */
        if (*gctx).group_nid != NID_undef {
            (*gctx).gen_type = DH_PARAMGEN_TYPE_GROUP;
        }

        /*
         * Do a bounds check on context gen_type. Must be in range:
         * DH_PARAMGEN_TYPE_GENERATOR <= gen_type <= DH_PARAMGEN_TYPE_GROUP
         * Noted here as this needs to be adjusted if a new group type is
         * added.
         */
        if ossl_assert(
            (*gctx).gen_type >= DH_PARAMGEN_TYPE_GENERATOR
                && (*gctx).gen_type <= DH_PARAMGEN_TYPE_GROUP,
        ) == 0
        {
            let mut msg = [0 as c_char; 48];
            // SAFETY: `msg` is a 48-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"gen_type set to unsupported value %d".as_ptr(),
                (*gctx).gen_type,
            );
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            raise_site_data(&err_sites::PROV_DH_KMGMT_725, msg.as_ptr());
            return ptr::null_mut();
        }

        let ffc: *mut FfcParams;
        /* For parameter generation - If there is a group name just create it */
        if (*gctx).gen_type == DH_PARAMGEN_TYPE_GROUP && (*gctx).ffc_params.is_null() {
            /* Select a named group if there is not one already */
            if (*gctx).group_nid == NID_undef {
                (*gctx).group_nid = ossl_dh_get_named_group_uid_from_size((*gctx).pbits as c_int);
            }
            if (*gctx).group_nid == NID_undef {
                return ptr::null_mut();
            }
            dh = ossl_dh_new_by_nid_ex((*gctx).libctx, (*gctx).group_nid);
            if dh.is_null() {
                return ptr::null_mut();
            }
            ffc = ossl_dh_get0_params(dh);
        } else {
            dh = ossl_dh_new_ex((*gctx).libctx);
            if dh.is_null() {
                return ptr::null_mut();
            }
            ffc = ossl_dh_get0_params(dh);

            /* Copy the template value if one was passed */
            if !(*gctx).ffc_params.is_null() && ossl_ffc_params_copy(ffc, (*gctx).ffc_params) == 0 {
                return dh_gen_end(dh, gencb, ret);
            }

            if ossl_ffc_params_set_seed(ffc, (*gctx).seed, (*gctx).seedlen) == 0 {
                return dh_gen_end(dh, gencb, ret);
            }
            if (*gctx).gindex != -1 {
                ossl_ffc_params_set_gindex(ffc, (*gctx).gindex);
                if (*gctx).pcounter != -1 {
                    ossl_ffc_params_set_pcounter(ffc, (*gctx).pcounter);
                }
            } else if (*gctx).hindex != 0 {
                ossl_ffc_params_set_h(ffc, (*gctx).hindex);
            }
            if !(*gctx).mdname.is_null() {
                ossl_ffc_set_digest(ffc, (*gctx).mdname, (*gctx).mdprops);
            }
            (*gctx).cb = osslcb;
            (*gctx).cbarg = cbarg;
            gencb = BN_GENCB_new();
            if !gencb.is_null() {
                BN_GENCB_set(gencb, Some(dh_gencb), genctx);
            }

            if ((*gctx).selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0 {
                /*
                 * NOTE: The old safe prime generator code is not used in fips mode,
                 * (i.e internally it ignores the generator and chooses a named
                 * group based on pbits.
                 */
                if (*gctx).gen_type == DH_PARAMGEN_TYPE_GENERATOR {
                    ret = DH_generate_parameters_ex(
                        dh,
                        (*gctx).pbits as c_int,
                        (*gctx).generator,
                        gencb,
                    );
                } else {
                    ret = ossl_dh_generate_ffc_parameters(
                        dh,
                        (*gctx).gen_type,
                        (*gctx).pbits as c_int,
                        (*gctx).qbits as c_int,
                        gencb,
                    );
                }
                if ret <= 0 {
                    return dh_gen_end(dh, gencb, ret);
                }
            }
        }

        if ((*gctx).selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0 {
            if (*ffc).p.is_null() || (*ffc).g.is_null() {
                return dh_gen_end(dh, gencb, ret);
            }
            if (*gctx).priv_len > 0 {
                DH_set_length(dh, (*gctx).priv_len as c_long);
            }
            ossl_ffc_params_enable_flags(
                ffc,
                FFC_PARAM_FLAG_VALIDATE_LEGACY,
                c_int::from((*gctx).gen_type == DH_PARAMGEN_TYPE_FIPS_186_2),
            );
            if DH_generate_key(dh) <= 0 {
                return dh_gen_end(dh, gencb, ret);
            }
        }
        DH_clear_flags(dh, DH_FLAG_TYPE_MASK);
        DH_set_flags(dh, (*gctx).dh_type);

        ret = 1;
    }
    // SAFETY: `dh` is the object built above and `gencb` is its callback, or NULL on a branch
    // that built no callback.
    unsafe { dh_gen_end(dh, gencb, ret) }
}

/// The authority's `end:` label of `dh_gen`: on failure the object is released and NULL answered,
/// otherwise the object is. The `BN_GENCB` is released either way.
///
/// # Safety
/// `dh` is NULL or a live object this call owns; `gencb` is NULL or a live `BN_GENCB`.
unsafe fn dh_gen_end(dh: *mut Dh, gencb: *mut BnGencb, ret: c_int) -> *mut c_void {
    let mut dh = dh;

    // SAFETY: the caller's contract.
    unsafe {
        if ret <= 0 {
            DH_free(dh);
            dh = ptr::null_mut();
        }
        BN_GENCB_free(gencb);
    }
    dh.cast()
}

/// `static void dh_gen_cleanup(void *genctx)` — `dh_kmgmt.c:818-829`.
///
/// # Safety
/// The keymgmt `gen_cleanup` dispatch contract.
unsafe extern "C" fn dh_gen_cleanup(genctx: *mut c_void) {
    let gctx = genctx.cast::<DhGenCtx>();

    if gctx.is_null() {
        return;
    }

    // SAFETY: `gctx` is the caller's context, allocated by `dh_gen_init_base`.
    unsafe {
        CRYPTO_free((*gctx).mdname.cast(), FILE_DH_KMGMT, 825);
        CRYPTO_free((*gctx).mdprops.cast(), FILE_DH_KMGMT, 826);
        CRYPTO_clear_free((*gctx).seed.cast(), (*gctx).seedlen, FILE_DH_KMGMT, 827);
        CRYPTO_free(gctx.cast(), FILE_DH_KMGMT, 828);
    }
}

/// `static void *dh_load(const void *reference, size_t reference_sz)` — `dh_kmgmt.c:831-843`.
///
/// # Safety
/// The keymgmt `load` dispatch contract.
unsafe extern "C" fn dh_load(reference: *const c_void, reference_sz: usize) -> *mut c_void {
    if is_running() != 0 && reference_sz == core::mem::size_of::<*mut Dh>() {
        // The contents of the reference is the address to our object.
        // SAFETY: `reference` is readable for `reference_sz` bytes and is writable here (the
        // authority detaches the object it names), per the dispatch contract.
        unsafe {
            let slot = reference.cast::<*mut Dh>().cast_mut();
            let dh = *slot;
            *slot = ptr::null_mut();
            return dh.cast();
        }
    }
    ptr::null_mut()
}

/// `static void *dh_dup(const void *keydata_from, int selection)` — `dh_kmgmt.c:845-850`.
///
/// # Safety
/// The keymgmt `dup` dispatch contract.
unsafe extern "C" fn dh_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void {
    if is_running() != 0 {
        // SAFETY: the caller's contract.
        return unsafe { ossl_dh_dup(keydata_from.cast(), selection) }.cast();
    }
    ptr::null_mut()
}

/// `const OSSL_DISPATCH ossl_dh_keymgmt_functions[]` — `dh_kmgmt.c:852-876`. Twenty-one slots,
/// the authority's, in its order.
pub(crate) static DH_KEYMGMT_FUNCTIONS: [OsslDispatch; 22] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: dh_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: dh_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        function: dh_gen_set_template as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: dh_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: dh_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: dh_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: dh_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: dh_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: dh_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: dh_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: dh_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: dh_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: dh_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: dh_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: dh_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: dh_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: dh_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: dh_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: dh_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: dh_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: dh_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const char *dhx_query_operation_name(int operation_id)` — `dh_kmgmt.c:878-882`. For any
/// DH key, the "DH" algorithms are used regardless of sub-type.
unsafe extern "C" fn dhx_query_operation_name(_operation_id: c_int) -> *const c_char {
    c"DH".as_ptr()
}

/// `const OSSL_DISPATCH ossl_dhx_keymgmt_functions[]` — `dh_kmgmt.c:884-910`. The same twenty-one
/// slots as `DH`, with **five** replaced: `newdata`, `gen_init`, `gen_set_params`,
/// `gen_settable_params` and, added before `DUP`, the `QUERY_OPERATION_NAME` slot.
pub(crate) static DHX_KEYMGMT_FUNCTIONS: [OsslDispatch; 23] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_NEW,
        function: dhx_newdata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_INIT,
        function: dhx_gen_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        function: dh_gen_set_template as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        function: dhx_gen_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        function: dhx_gen_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN,
        function: dh_gen as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
        function: dh_gen_cleanup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_LOAD,
        function: dh_load as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_FREE,
        function: dh_freedata as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GET_PARAMS,
        function: dh_get_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        function: dh_gettable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SET_PARAMS,
        function: dh_set_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        function: dh_settable_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_HAS,
        function: dh_has as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_MATCH,
        function: dh_match as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_VALIDATE,
        function: dh_validate as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT,
        function: dh_import as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
        function: dh_import_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT,
        function: dh_export as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
        function: dh_export_types as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        function: dhx_query_operation_name as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYMGMT_DUP,
        function: dh_dup as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `ossl_assert` — `include/internal/assert.h`. As `src/provider/seed_src.rs` and its neighbours
/// carry it: the NDEBUG form, which answers the expression rather than aborting.
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `static const OSSL_ALGORITHM deflt_keymgmt[]` — `providers/defltprov.c:551-666`, **the rows this
/// module has landed**, in the authority's order.
///
/// The `DH` and `DHX` rows are the authority's first two (`defltprov.c:553-558`); the `DSA` row is
/// next (`:561-562`); the `RSA` and `RSA-PSS` rows follow it (`:563-566`); the `EC` row is next
/// (`:568-569`); the four ECX rows (`X25519`, `X448`, `ED25519`, `ED448`) follow (`:571-578`); the
/// KDF rows share `ossl_kdf_keymgmt_functions` exactly as the authority's three do (`:588-595`);
/// the four legacy-MAC rows (`HMAC`, `SIPHASH`, `POLY1305`, `CMAC`, `:596-609`) come next, three
/// sharing `ossl_mac_legacy_keymgmt_functions` and `CMAC` its own; and the `SM2` row closes the
/// landed set (`:611-614`). The many-to-one associations are facts about the authority, and the
/// census's dispatch association is a partition equality (D386) so they are described rather than
/// rejected. The order is the authority's and the census requires it: the crate's rows must be a
/// **subsequence** of `deflt_keymgmt[]`.
///
/// **The property definition is `"provider=default"` on every row** (`defltprov.c`'s `ALG` macro,
/// D247), and the description is left NULL on every row, which is this crate's convention for the
/// fourth `OSSL_ALGORITHM` field (no landed table sets it, and nothing reads it).
pub(crate) static DEFLT_KEYMGMT: [OsslAlgorithm; 19] = [
    OsslAlgorithm {
        // `PROV_NAMES_DH`.
        algorithm_names: c"DH:dhKeyAgreement:1.2.840.113549.1.3.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DH_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DHX` — both names are part of the row.
        algorithm_names: c"DHX:X9.42 DH:dhpublicnumber:1.2.840.10046.2.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DHX_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA` — the OID alias is part of the row.
        algorithm_names: c"DSA:dsaEncryption:1.2.840.10040.4.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA` — the OID alias is part of the row.
        algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_PSS` — all three aliases are part of the row.
        algorithm_names: c"RSA-PSS:RSASSA-PSS:rsassaPss:1.2.840.113549.1.1.10".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_PSS_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_EC` — the OID alias is part of the row.
        algorithm_names: c"EC:id-ecPublicKey:1.2.840.10045.2.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: EC_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X25519`.
        algorithm_names: c"X25519:1.3.101.110".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: X25519_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X448`.
        algorithm_names: c"X448:1.3.101.111".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: X448_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED25519`.
        algorithm_names: c"ED25519:1.3.101.112".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED25519_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED448`.
        algorithm_names: c"ED448:1.3.101.113".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED448_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_TLS1_PRF` — the primary name alone.
        algorithm_names: c"TLS1-PRF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF`.
        algorithm_names: c"HKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SCRYPT` — the OID alias is part of the row.
        algorithm_names: c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HMAC`.
        algorithm_names: c"HMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SIPHASH`.
        algorithm_names: c"SIPHASH".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_POLY1305`.
        algorithm_names: c"POLY1305".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_CMAC`.
        algorithm_names: c"CMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: CMAC_LEGACY_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SM2` — the OID alias is part of the row.
        algorithm_names: c"SM2:1.2.156.10197.1.301".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SM2_KEYMGMT_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
