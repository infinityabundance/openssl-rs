//! Phase 7.4c-ii — `crypto/asn1/ameth_lib.c`: the `EVP_PKEY_ASN1_METHOD` registry and its accessors.
//!
//! Twenty-three exports, of which this file lands the eight that need no `standard_methods[]`:
//! `get_count`, `get0`, `add0`, `add_alias`, `get0_info`, `new`, `copy` and `free`. The two
//! `find` functions and `get0_asn1` are the rest, and each is held for a stated reason — see the
//! module's last section.
//!
//! ## The struct is forty-one members and the order is the ABI
//!
//! It is `include/crypto/asn1.h`'s `struct evp_pkey_asn1_method_st`, and the reason it lives here
//! rather than in Phase 8 is worth stating once: the typedef is in `include/openssl/types.h`, the
//! **body** is in an *internal* header that is not installed, and the exported accessors are declared
//! in `evp.h`. So the ownership atlas sees `evp.h`, assigns the accessors to this stratum, and this
//! stratum must define the struct to implement its own exports — exactly as it defines `EvpPkeyCtx`
//! to implement `pmeth_lib.c`'s. What is Phase 8's is the twelve `ossl_<alg>_asn1_meth` **objects**
//! that populate `standard_methods[]` (D163, D165), and only the two `find` functions touch that
//! table.
//!
//! Thirty-six of the forty-one members are function-pointer types. `ABI-PROTOTYPE` cannot see them,
//! because they are fields and not exports, and D170 records two real defects of exactly that shape
//! in this project — which is why the member list is transcribed against the header member by member
//! and why the `OSSL_CORE_MAKE_FUNC` type-plane generator D170 names is the check that makes this
//! credible rather than merely careful.
//!
//! ## The two flags, and the check `add0` makes that nothing else does
//!
//! ```text
//! ASN1_PKEY_ALIAS    0x1
//! ASN1_PKEY_DYNAMIC  0x2      set by `new`, and the only thing `free` frees on
//! ```
//!
//! `add0` refuses an entry whose `pem_str` and `ASN1_PKEY_ALIAS` disagree — an alias must have no
//! PEM string and a non-alias must have one — with `ERR_R_PASSED_INVALID_ARGUMENT`, because letting
//! one through "may lead to a corrupt ASN1 method table". That is the only validation in the file,
//! and it is a *pair* of conditions rather than one.
//!
//! ## `copy` copies the function pointers and restores five fields
//!
//! `*dst = *src` then five restores, and the authority's comment says why: "We only copy the function
//! pointers so restore the other values". So `dst` keeps its own `pkey_id`, `pkey_base_id`,
//! `pkey_flags`, `pem_str` and `info` — the owned strings and the identity — and takes everything
//! else from `src`. A transcription that copied the whole struct would alias `src`'s strings into
//! `dst` and then free them twice.
//!
//! ## What is not here, and the reason each is held
//!
//! `EVP_PKEY_asn1_find` and `EVP_PKEY_asn1_find_str` search `app_methods` **and then**
//! `standard_methods[]`, which is Phase 8's twelve objects; they land with a documented empty table
//! or with Phase 8, and the `D-PKEY-AMETH-1` precedent says which. `EVP_PKEY_get0_asn1` is
//! `return pkey->ameth;` and `EvpPkey` has no such field, so it lands with `EvpPkey`'s ameth rather
//! than with the accessors. And the fifteen `EVP_PKEY_asn1_set_*` mutators write the struct's
//! callback fields one by one; they are mechanical and they are next, not now, because each writes a
//! *different* subset of the thirty-six and every one has to be read against the header.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1Item, Asn1Pctx, Asn1String};
use crate::evp::digest::EvpMdCtx;
use crate::evp::keymgmt::KeymgmtImportFn;
use crate::evp::pkey::EvpPkey;
use crate::runtime::bio::Bio;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::selftest::OsslCallback;

/// `ASN1_PKEY_ALIAS` — `include/openssl/evp.h:1603`.
const ASN1_PKEY_ALIAS: c_long = 0x1;
/// `ASN1_PKEY_DYNAMIC` — `include/openssl/evp.h:1604`.
const ASN1_PKEY_DYNAMIC: c_long = 0x2;

// ---------------------------------------------------------------------------------------------
// The six types this struct names that the crate has not transcribed yet.
//
// Each is `#[repr(C)]` and empty, which is this crate's documented idiom for a type that appears in
// a signature — here, in a struct's member — before its body is. It is honest here rather than a
// shortcut: these accessors store and return the struct and never call through these members.
// ---------------------------------------------------------------------------------------------

/// `X509_PUBKEY` — Phase 10's object.
#[repr(C)]
pub struct X509Pubkey {
    _private: [u8; 0],
}
/// `PKCS8_PRIV_KEY_INFO` — Phase 10's object.
#[repr(C)]
pub struct Pkcs8PrivKeyInfo {
    _private: [u8; 0],
}
/// `X509_ALGOR` — Phase 10's object.
#[repr(C)]
pub struct X509Algor {
    _private: [u8; 0],
}
/// `X509_SIG_INFO` — Phase 10's object.
#[repr(C)]
pub struct X509SigInfo {
    _private: [u8; 0],
}
/// `ASN1_BIT_STRING` — Phase 5's object, and the one of the six whose body is in a header this
/// project has already read.
#[repr(C)]
pub struct Asn1BitString {
    _private: [u8; 0],
}

/// `struct evp_pkey_asn1_method_st` — `include/crypto/asn1.h:23-89`, forty-one members in ABI order.
#[repr(C)]
pub struct EvpPkeyAsn1Method {
    /// `int pkey_id`.
    pub(crate) pkey_id: c_int,
    /// `int pkey_base_id`.
    pub(crate) pkey_base_id: c_int,
    /// `unsigned long pkey_flags`.
    pub(crate) pkey_flags: c_long,
    /// `char *pem_str` — owned when `ASN1_PKEY_DYNAMIC` is set.
    pub(crate) pem_str: *mut c_char,
    /// `char *info` — owned on the same condition.
    pub(crate) info: *mut c_char,
    /// `int (*pub_decode)(EVP_PKEY *, const X509_PUBKEY *)`.
    pub(crate) pub_decode: Option<unsafe extern "C" fn(*mut EvpPkey, *const X509Pubkey) -> c_int>,
    /// `int (*pub_encode)(X509_PUBKEY *, const EVP_PKEY *)`.
    pub(crate) pub_encode: Option<unsafe extern "C" fn(*mut X509Pubkey, *const EvpPkey) -> c_int>,
    /// `int (*pub_cmp)(const EVP_PKEY *, const EVP_PKEY *)`.
    pub(crate) pub_cmp: Option<unsafe extern "C" fn(*const EvpPkey, *const EvpPkey) -> c_int>,
    /// `int (*pub_print)(BIO *, const EVP_PKEY *, int, ASN1_PCTX *)`.
    pub(crate) pub_print:
        Option<unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int>,
    /// `int (*priv_decode)(EVP_PKEY *, const PKCS8_PRIV_KEY_INFO *)`.
    pub(crate) priv_decode:
        Option<unsafe extern "C" fn(*mut EvpPkey, *const Pkcs8PrivKeyInfo) -> c_int>,
    /// `int (*priv_encode)(PKCS8_PRIV_KEY_INFO *, const EVP_PKEY *)`.
    pub(crate) priv_encode:
        Option<unsafe extern "C" fn(*mut Pkcs8PrivKeyInfo, *const EvpPkey) -> c_int>,
    /// `int (*priv_print)(BIO *, const EVP_PKEY *, int, ASN1_PCTX *)`.
    pub(crate) priv_print:
        Option<unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int>,
    /// `int (*pkey_size)(const EVP_PKEY *)`.
    pub(crate) pkey_size: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*pkey_bits)(const EVP_PKEY *)`.
    pub(crate) pkey_bits: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*pkey_security_bits)(const EVP_PKEY *)`.
    pub(crate) pkey_security_bits: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*param_decode)(EVP_PKEY *, const unsigned char **, int)`.
    pub(crate) param_decode:
        Option<unsafe extern "C" fn(*mut EvpPkey, *mut *const u8, c_int) -> c_int>,
    /// `int (*param_encode)(const EVP_PKEY *, unsigned char **)`.
    pub(crate) param_encode: Option<unsafe extern "C" fn(*const EvpPkey, *mut *mut u8) -> c_int>,
    /// `int (*param_missing)(const EVP_PKEY *)`.
    pub(crate) param_missing: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*param_copy)(EVP_PKEY *, const EVP_PKEY *)`.
    pub(crate) param_copy: Option<unsafe extern "C" fn(*mut EvpPkey, *const EvpPkey) -> c_int>,
    /// `int (*param_cmp)(const EVP_PKEY *, const EVP_PKEY *)`.
    pub(crate) param_cmp: Option<unsafe extern "C" fn(*const EvpPkey, *const EvpPkey) -> c_int>,
    /// `int (*param_print)(BIO *, const EVP_PKEY *, int, ASN1_PCTX *)`.
    pub(crate) param_print:
        Option<unsafe extern "C" fn(*mut Bio, *const EvpPkey, c_int, *mut Asn1Pctx) -> c_int>,
    /// `int (*sig_print)(BIO *, const X509_ALGOR *, const ASN1_STRING *, int, ASN1_PCTX *)`.
    pub(crate) sig_print: Option<
        unsafe extern "C" fn(
            *mut Bio,
            *const X509Algor,
            *const Asn1String,
            c_int,
            *mut Asn1Pctx,
        ) -> c_int,
    >,
    /// `void (*pkey_free)(EVP_PKEY *)`.
    pub(crate) pkey_free: Option<unsafe extern "C" fn(*mut EvpPkey)>,
    /// `int (*pkey_ctrl)(EVP_PKEY *, int, long, void *)`.
    pub(crate) pkey_ctrl:
        Option<unsafe extern "C" fn(*mut EvpPkey, c_int, c_long, *mut c_void) -> c_int>,
    /// `int (*old_priv_decode)(EVP_PKEY *, const unsigned char **, int)`.
    pub(crate) old_priv_decode:
        Option<unsafe extern "C" fn(*mut EvpPkey, *mut *const u8, c_int) -> c_int>,
    /// `int (*old_priv_encode)(const EVP_PKEY *, unsigned char **)`.
    pub(crate) old_priv_encode: Option<unsafe extern "C" fn(*const EvpPkey, *mut *mut u8) -> c_int>,
    /// `int (*item_verify)(EVP_MD_CTX *, const ASN1_ITEM *, const void *, const X509_ALGOR *,
    /// const ASN1_BIT_STRING *, EVP_PKEY *)`.
    pub(crate) item_verify: Option<
        unsafe extern "C" fn(
            *mut EvpMdCtx,
            *const Asn1Item,
            *const c_void,
            *const X509Algor,
            *const Asn1BitString,
            *mut EvpPkey,
        ) -> c_int,
    >,
    /// `int (*item_sign)(EVP_MD_CTX *, const ASN1_ITEM *, const void *, X509_ALGOR *, X509_ALGOR *,
    /// ASN1_BIT_STRING *)`.
    pub(crate) item_sign: Option<
        unsafe extern "C" fn(
            *mut EvpMdCtx,
            *const Asn1Item,
            *const c_void,
            *mut X509Algor,
            *mut X509Algor,
            *mut Asn1BitString,
        ) -> c_int,
    >,
    /// `int (*siginf_set)(X509_SIG_INFO *, const X509_ALGOR *, const ASN1_STRING *)`.
    pub(crate) siginf_set: Option<
        unsafe extern "C" fn(*mut X509SigInfo, *const X509Algor, *const Asn1String) -> c_int,
    >,
    /// `int (*pkey_check)(const EVP_PKEY *)`.
    pub(crate) pkey_check: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*pkey_public_check)(const EVP_PKEY *)`.
    pub(crate) pkey_public_check: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*pkey_param_check)(const EVP_PKEY *)`.
    pub(crate) pkey_param_check: Option<unsafe extern "C" fn(*const EvpPkey) -> c_int>,
    /// `int (*set_priv_key)(EVP_PKEY *, const unsigned char *, size_t)`.
    pub(crate) set_priv_key: Option<unsafe extern "C" fn(*mut EvpPkey, *const u8, usize) -> c_int>,
    /// `int (*set_pub_key)(EVP_PKEY *, const unsigned char *, size_t)`.
    pub(crate) set_pub_key: Option<unsafe extern "C" fn(*mut EvpPkey, *const u8, usize) -> c_int>,
    /// `int (*get_priv_key)(const EVP_PKEY *, unsigned char *, size_t *)`.
    pub(crate) get_priv_key:
        Option<unsafe extern "C" fn(*const EvpPkey, *mut u8, *mut usize) -> c_int>,
    /// `int (*get_pub_key)(const EVP_PKEY *, unsigned char *, size_t *)`.
    pub(crate) get_pub_key:
        Option<unsafe extern "C" fn(*const EvpPkey, *mut u8, *mut usize) -> c_int>,
    /// `size_t (*dirty_cnt)(const EVP_PKEY *)`.
    pub(crate) dirty_cnt: Option<unsafe extern "C" fn(*const EvpPkey) -> usize>,
    /// `int (*export_to)(const EVP_PKEY *, void *, OSSL_FUNC_keymgmt_import_fn *, OSSL_LIB_CTX *,
    /// const char *)`.
    pub(crate) export_to: Option<
        unsafe extern "C" fn(
            *const EvpPkey,
            *mut c_void,
            Option<KeymgmtImportFn>,
            *mut c_void,
            *const c_char,
        ) -> c_int,
    >,
    /// `OSSL_CALLBACK *import_from` — and `OsslCallback` is `selftest`'s canonical declaration of
    /// the authority's `OSSL_CALLBACK`, reused rather than redeclared because two aliases of one
    /// name in one crate shadow each other in `ABI-PROTOTYPE`'s alias table.
    pub(crate) import_from: Option<OsslCallback>,
    /// `int (*copy)(EVP_PKEY *, EVP_PKEY *)`.
    pub(crate) copy: Option<unsafe extern "C" fn(*mut EvpPkey, *mut EvpPkey) -> c_int>,
    /// `int (*priv_decode_ex)(EVP_PKEY *, const PKCS8_PRIV_KEY_INFO *, OSSL_LIB_CTX *,
    /// const char *)`.
    pub(crate) priv_decode_ex: Option<
        unsafe extern "C" fn(
            *mut EvpPkey,
            *const Pkcs8PrivKeyInfo,
            *mut c_void,
            *const c_char,
        ) -> c_int,
    >,
}

/// `standard_methods[]` — `crypto/asn1/ameth_lib.c`, twelve objects in the authority.
///
/// **Empty here, and that is the whole of this file's Phase-8 dependency.** The twelve
/// `ossl_<alg>_asn1_meth` objects are what `standard_methods[]` holds, they are Phase 8's contents
/// (D163, D165), and the count the authority reports is `OSSL_NELEM(standard_methods)` *plus* the
/// application methods. So `get_count` answers the application count here and the authority's
/// answer plus twelve there — the `D-PKEY-AMETH-1` divergence, reached through a different door, and
/// the reason the two `find` functions are held rather than landed with an empty table today.
const STANDARD_METHODS: [*const EvpPkeyAsn1Method; 0] = [];

/// `app_methods` — the application-registered methods, sorted by `ameth_cmp`.
static mut APP_METHODS: *mut OpenSslStack = ptr::null_mut();

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/asn1/ameth_lib.c".as_ptr();
/// `EVP_PKEY_asn1_new`'s `OPENSSL_zalloc(sizeof(*ameth))` (line 227).
const LINE_ZALLOC_AMETH: c_int = 227;
/// `EVP_PKEY_asn1_new`'s `OPENSSL_strdup(info)` (line 237).
const LINE_DUP_INFO: c_int = 237;
/// `EVP_PKEY_asn1_new`'s `OPENSSL_strdup(pem_str)` (line 243).
const LINE_DUP_PEM_STR: c_int = 243;

/// `static int ameth_cmp(const EVP_PKEY_ASN1_METHOD *const *a,
/// const EVP_PKEY_ASN1_METHOD *const *b)` — `crypto/asn1/ameth_lib.c:31`.
///
/// # Safety
/// Both arguments must point at live `*const EvpPkeyAsn1Method` slots.
unsafe extern "C" fn ameth_cmp(a: *const c_void, b: *const c_void) -> c_int {
    /* The stack stores the elements themselves and hands the comparator the addresses of the slots
     * they live in -- what the authority's `DECLARE_OBJ_BSEARCH_CMP_FN` macro spells as a
     * `*const *const` pair, and what the crate's `CompFn` erases to a `*const c_void` pair. */
    let a = a.cast::<*const EvpPkeyAsn1Method>();
    let b = b.cast::<*const EvpPkeyAsn1Method>();
    // SAFETY: both arguments are slots holding live methods per the contract.
    let (x, y) = unsafe { ((**a).pkey_id, (**b).pkey_id) };
    x - y
}

/// `int EVP_PKEY_asn1_get_count(void)` — `crypto/asn1/ameth_lib.c:40`.
///
/// `OSSL_NELEM(standard_methods)` plus the application count — and the first term is **zero here**,
/// because `standard_methods[]` is Phase 8's twelve objects. So this answers the application count
/// where the authority answers that plus twelve; the divergence is recorded at [`STANDARD_METHODS`]
/// and is the same one `D-PKEY-AMETH-1` records from the key-type side.
///
/// # Safety
/// Nothing: it touches no pointer argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_get_count() -> c_int {
    let mut num = STANDARD_METHODS.len() as c_int;
    // SAFETY: `APP_METHODS` is NULL or a stack this module owns.
    if !unsafe { APP_METHODS }.is_null() {
        // SAFETY: `APP_METHODS` is live.
        num += unsafe { OPENSSL_sk_num(APP_METHODS) };
    }
    num
}

/// `const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_get0(int idx)` — `crypto/asn1/ameth_lib.c:48`.
///
/// `idx < 0` answers NULL and the standard methods come first, so the two halves of the count are
/// two halves of the index space. With the standard half empty here every index lands in
/// `app_methods` — which is the same divergence as the count, and it is why this and `get_count`
/// are the only two of the family that need no struct body.
///
/// # Safety
/// Nothing: it touches no pointer argument. It is an `unsafe fn` because every export in this crate
/// is, and because it reads the module's own `APP_METHODS`.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_get0(idx: c_int) -> *const EvpPkeyAsn1Method {
    let num = STANDARD_METHODS.len() as c_int;
    if idx < 0 {
        return ptr::null();
    }
    if idx < num {
        return STANDARD_METHODS[idx as usize];
    }
    // SAFETY: `APP_METHODS` is NULL or a stack this module owns.
    unsafe { OPENSSL_sk_value(APP_METHODS, idx - num) }.cast::<EvpPkeyAsn1Method>()
}

/// `int EVP_PKEY_asn1_add0(const EVP_PKEY_ASN1_METHOD *ameth)` — `crypto/asn1/ameth_lib.c:144`.
///
/// The file's only validation, and it is a **pair** of conditions rather than one: an alias must have
/// no `pem_str` and a non-alias must have one, and anything else "may lead to a corrupt ASN1 method
/// table". Then a duplicate `pkey_id` is refused with its own reason code, and only then is the
/// method pushed and the stack re-sorted.
///
/// # Safety
/// `ameth` must be a live method, and it must outlive the registry.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_add0(ameth: *const EvpPkeyAsn1Method) -> c_int {
    // SAFETY: `ameth` is live per the contract.
    let (pem_str, flags, id) = unsafe { ((*ameth).pem_str, (*ameth).pkey_flags, (*ameth).pkey_id) };
    let is_alias = (flags & ASN1_PKEY_ALIAS) != 0;
    if !((pem_str.is_null() && is_alias) || (!pem_str.is_null() && !is_alias)) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::AMETH_LIB_162) };
        return 0;
    }

    // SAFETY: `APP_METHODS` is NULL or a stack this module owns.
    if unsafe { APP_METHODS }.is_null() {
        // SAFETY: the comparator reads only `pkey_id`, which every pushed method has.
        /* `OPENSSL_sk_new` is a safe entry point of this crate. */
        let st = OPENSSL_sk_new(Some(ameth_cmp));
        if st.is_null() {
            return 0;
        }
        // SAFETY: this module owns the pointer and nothing else writes it.
        unsafe { APP_METHODS = st };
    }

    /* The duplicate test compares `pkey_id` alone, which is why a caller that registers the same id
     * twice is refused here rather than at the sort. */
    /* SAFETY: every field is a scalar, a raw pointer or an `Option` of a function pointer, so
     * the all-zero bit pattern is valid -- and the comparator reads only `pkey_id`, which is
     * assigned immediately below. */
    let mut probe: EvpPkeyAsn1Method = unsafe { core::mem::zeroed() };
    probe.pkey_id = id;
    // SAFETY: `APP_METHODS` is live and `probe` is a live local of the right shape for the
    // comparator, which reads only `pkey_id`.
    if unsafe { OPENSSL_sk_find(APP_METHODS, ptr::addr_of!(probe).cast::<c_void>()) } >= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::AMETH_LIB_174) };
        return 0;
    }

    // SAFETY: `APP_METHODS` is live and `ameth` outlives the registry per the contract.
    if unsafe { OPENSSL_sk_push(APP_METHODS, ameth.cast::<c_void>()) } == 0 {
        return 0;
    }
    // SAFETY: `APP_METHODS` is live.
    unsafe { OPENSSL_sk_sort(APP_METHODS) };
    1
}

/// `int EVP_PKEY_asn1_add_alias(int to, int from)` — `crypto/asn1/ameth_lib.c:185`.
///
/// A new method for `from` with `ASN1_PKEY_ALIAS` set, its `pkey_base_id` pointed at `to`, then
/// `add0` — and on an `add0` refusal the new method is **freed**, which is only correct because
/// `new` set `ASN1_PKEY_DYNAMIC` and that is the flag `free` frees on.
///
/// # Safety
/// Nothing: both arguments are integers.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_add_alias(to: c_int, from: c_int) -> c_int {
    // SAFETY: the constructor takes no pointer the caller owns; the two strings are NULL, which the
    // alias flag requires.
    let ameth =
        unsafe { EVP_PKEY_asn1_new(from, ASN1_PKEY_ALIAS as c_int, ptr::null(), ptr::null()) };
    if ameth.is_null() {
        return 0;
    }
    // SAFETY: `ameth` is this call's own object.
    unsafe { (*ameth).pkey_base_id = to };
    // SAFETY: `ameth` is live.
    if unsafe { EVP_PKEY_asn1_add0(ameth) } == 0 {
        // SAFETY: `ameth` is this call's own object and has not been registered.
        unsafe { EVP_PKEY_asn1_free(ameth) };
        return 0;
    }
    1
}

/// `int EVP_PKEY_asn1_get0_info(int *, int *, int *, const char **, const char **,
/// const EVP_PKEY_ASN1_METHOD *)` — `crypto/asn1/ameth_lib.c:199`.
///
/// Six parameters and five out-parameters, each written **only if the caller passed one**, and a
/// NULL method answers 0 rather than raising. The two string outputs are the method's *own* pointers
/// and not copies — a caller that keeps `*pinfo` past the method's lifetime is holding a dangling
/// pointer, which is why `free` is the only thing that releases them.
///
/// # Safety
/// `ameth` NULL or live; every out-parameter NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_get0_info(
    ppkey_id: *mut c_int,
    ppkey_base_id: *mut c_int,
    ppkey_flags: *mut c_int,
    pinfo: *mut *const c_char,
    ppem_str: *mut *const c_char,
    ameth: *const EvpPkeyAsn1Method,
) -> c_int {
    if ameth.is_null() {
        return 0;
    }
    // SAFETY: `ameth` is live per the contract.
    let m = unsafe { &*ameth };
    if !ppkey_id.is_null() {
        // SAFETY: `ppkey_id` is writable per the contract.
        unsafe { *ppkey_id = m.pkey_id };
    }
    if !ppkey_base_id.is_null() {
        // SAFETY: as above.
        unsafe { *ppkey_base_id = m.pkey_base_id };
    }
    if !ppkey_flags.is_null() {
        // SAFETY: as above.
        unsafe { *ppkey_flags = m.pkey_flags as c_int };
    }
    if !pinfo.is_null() {
        // SAFETY: as above; the method's own pointer, not a copy.
        unsafe { *pinfo = m.info };
    }
    if !ppem_str.is_null() {
        // SAFETY: as above.
        unsafe { *ppem_str = m.pem_str };
    }
    1
}

/// `EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_new(int id, int flags, const char *pem_str,
/// const char *info)` — `crypto/asn1/ameth_lib.c:224`.
///
/// `pkey_base_id` starts equal to `id` and `ASN1_PKEY_DYNAMIC` is **or**ed into the caller's flags,
/// which is what makes `free` able to release the object and its two strings later. The two
/// duplications are separately guarded and share one `err:` label, so a failure of the second leaves
/// the first allocated — and `free` releases both, because both are owned by then.
///
/// # Safety
/// `pem_str` and `info` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_new(
    id: c_int,
    flags: c_int,
    pem_str: *const c_char,
    info: *const c_char,
) -> *mut EvpPkeyAsn1Method {
    /* SAFETY: `CRYPTO_zalloc` is a safe entry point of this crate. */
    let ameth = CRYPTO_zalloc(
        core::mem::size_of::<EvpPkeyAsn1Method>(),
        FILE,
        LINE_ZALLOC_AMETH,
    )
    .cast::<EvpPkeyAsn1Method>();
    if ameth.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `ameth` is this call's own object.
    unsafe {
        (*ameth).pkey_id = id;
        (*ameth).pkey_base_id = id;
        (*ameth).pkey_flags = (flags as c_long) | ASN1_PKEY_DYNAMIC;
    }

    if !info.is_null() {
        /* SAFETY: `info` is NUL-terminated per the contract. */
        let dup = unsafe { CRYPTO_strdup(info, FILE, LINE_DUP_INFO) };
        if dup.is_null() {
            // SAFETY: `ameth` is this call's own object and has not been returned.
            unsafe { EVP_PKEY_asn1_free(ameth) };
            return ptr::null_mut();
        }
        // SAFETY: `ameth` is this call's own object.
        unsafe { (*ameth).info = dup };
    }

    if !pem_str.is_null() {
        // SAFETY: `pem_str` is NUL-terminated per the contract.
        let dup = unsafe { CRYPTO_strdup(pem_str, FILE, LINE_DUP_PEM_STR) };
        if dup.is_null() {
            // SAFETY: `ameth` is this call's own object and has not been returned.
            unsafe { EVP_PKEY_asn1_free(ameth) };
            return ptr::null_mut();
        }
        // SAFETY: `ameth` is this call's own object.
        unsafe { (*ameth).pem_str = dup };
    }

    ameth
}

/// `void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD *dst, const EVP_PKEY_ASN1_METHOD *src)` —
/// `crypto/asn1/ameth_lib.c:255`.
///
/// `*dst = *src` and then **five restores**, and the authority's comment says why: "We only copy the
/// function pointers so restore the other values". So `dst` keeps its own identity and its own two
/// owned strings, and a transcription that copied the whole struct would alias `src`'s strings into
/// `dst` and then free them twice.
///
/// # Safety
/// `dst` and `src` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_copy(
    dst: *mut EvpPkeyAsn1Method,
    src: *const EvpPkeyAsn1Method,
) {
    // SAFETY: `dst` is live per the contract.
    let (pkey_id, pkey_base_id, pkey_flags, pem_str, info) = unsafe {
        (
            (*dst).pkey_id,
            (*dst).pkey_base_id,
            (*dst).pkey_flags,
            (*dst).pem_str,
            (*dst).info,
        )
    };

    // SAFETY: both are live and non-overlapping per the contract.
    unsafe { ptr::copy_nonoverlapping(src, dst, 1) };

    // SAFETY: `dst` is live.
    unsafe {
        (*dst).pkey_id = pkey_id;
        (*dst).pkey_base_id = pkey_base_id;
        (*dst).pkey_flags = pkey_flags;
        (*dst).pem_str = pem_str;
        (*dst).info = info;
    }
}

/// `void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth)` — `crypto/asn1/ameth_lib.c:274`.
///
/// **Only frees a `DYNAMIC` method**, and that is not a fast path: a method the caller owns
/// statically — which is every one of Phase 8's twelve — must survive a `free` call, so a
/// transcription that freed unconditionally would free a `static const` object.
///
/// # Safety
/// `ameth` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_asn1_free(ameth: *mut EvpPkeyAsn1Method) {
    if ameth.is_null() {
        return;
    }
    // SAFETY: `ameth` is live per the contract.
    if (unsafe { (*ameth).pkey_flags } & ASN1_PKEY_DYNAMIC) == 0 {
        return;
    }
    // SAFETY: `ameth` is live, `DYNAMIC` is set, so the two strings are this object's own.
    unsafe {
        CRYPTO_free((*ameth).pem_str.cast::<c_void>(), FILE, LINE_ZALLOC_AMETH);
        CRYPTO_free((*ameth).info.cast::<c_void>(), FILE, LINE_ZALLOC_AMETH);
        CRYPTO_free(ameth.cast::<c_void>(), FILE, LINE_ZALLOC_AMETH);
    }
}
