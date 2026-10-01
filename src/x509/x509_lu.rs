//! Phase 11.1 — `crypto/x509/x509_lu.c`: the `X509_STORE` object model, the `X509_LOOKUP`
//! registry and the `X509_OBJECT` cache. The stratum's first unit of its own work
//! (`docs/PHASE-11-SUBPHASES.md` section 2).
//!
//! `crypto/x509/x509_lu.c` is 958 lines and publishes **seventy-three** functions, and **this
//! slice lands all seventy-three**. Its last seven — `X509_STORE_new`/`_free`, the four
//! `set_flags`/`set_depth`/`set_purpose`/`set_trust` setters and `X509_STORE_set1_param`
//! (`:182-254`, `:783-807`) — waited on `X509_VERIFY_PARAM`, 11.2's `crypto/x509/x509_vpm.c`;
//! that unit has since landed, so the seven are transcribed here too.
//!
//! * **The lookup object lands whole** (`:18-158`): `X509_LOOKUP_new`/`_free`,
//!   `X509_LOOKUP_init`/`_shutdown`, the three `ctrl` doors, the five `by_*` dispatchers and
//!   the three method-data/store accessors. Its only dependency is the `X509_LOOKUP` layout,
//!   defined here.
//! * **The store's lifecycle, registry and accessors land** (`:182-254`, `:256-295`, `:429-445`,
//!   `:580-618`, `:783-958`): [`X509_STORE_new`]/[`X509_STORE_free`], [`X509_STORE_up_ref`],
//!   [`X509_STORE_add_lookup`], [`X509_STORE_add_cert`]/
//!   [`X509_STORE_add_crl`], the two object-cache readers, the five `X509_VERIFY_PARAM` setters
//!   (`set1_param` and the four `set_flags`/`set_depth`/`set_purpose`/`set_trust`), the twelve
//!   callback `set`/`get` pairs, the two `ex_data` doors and the two locks.
//! * **The `X509_OBJECT` object lands whole** (`:447-781`): the constructors/destructors, the
//!   three accessors, the two `set1_` updaters, the by-subject index/retrieve pair and
//!   [`X509_OBJECT_retrieve_match`].
//! * **The store's `_get_by_subject` read path lands** (`:298-384`, `:658-752`, `:955-958`):
//!   [`X509_STORE_CTX_get_obj_by_subject`], the internal `ossl_x509_store_ctx_get_by_subject`,
//!   its public boolean wrapper [`X509_STORE_CTX_get_by_subject`], the two cache readers
//!   [`X509_STORE_CTX_get1_certs`]/[`X509_STORE_CTX_get1_crls`] and
//!   [`X509_STORE_CTX_get0_store`]. Its closure is the [`X509StoreCtx`] layout defined here (see
//!   below); the context's *lifecycle* and verify roll are 11.2's and are not transcribed.
//!
//! ## The last seven: the blocker was discharged
//!
//! 11.1 originally withheld seven functions whose only unmet dependency was `struct
//! X509_VERIFY_PARAM_st` (`X509_VERIFY_PARAM`): `X509_STORE_new` (`:182`) is the field's only
//! constructor and `X509_STORE_free` (`:226`) its only destructor, `X509_STORE_set1_param`
//! (`:804-807`) and the four `set_flags`/`set_depth`/`set_purpose`/`set_trust` setters
//! (`:783-802`) all call `X509_VERIFY_PARAM_set*`/`_set1`, and [`X509_STORE_get0_param`]
//! (`:809`) returns the field. **That blocker is discharged**: Phase 11.2's
//! `src/x509/x509_vpm.rs` now lands the type and every setter those call sites need, so all
//! seven are transcribed here and the store's `param` member carries its real
//! `*mut X509VerifyParam` type instead of `*mut c_void`. It is a pointer either way, so the
//! layout is unchanged.
//!
//! ## The `X509_STORE_CTX` layout is defined here, but not its lifecycle
//!
//! The read path dereferences a `ctx`, so 11.1 defines [`X509StoreCtx`] — `struct
//! x509_store_ctx_st` from `include/crypto/x509.h:215-287`. What 11.1 does **not** land is the
//! context's *lifecycle* (`X509_STORE_CTX_new`/`_free`/`_init`) or its verify roll; those are
//! 11.2's (`crypto/x509/x509_vfy.c`), so no function that drives them appears here. The members
//! whose own types are a later stratum's — the ctx's `X509_VERIFY_PARAM *param` (the type is
//! landed now, but this file keeps the ctx member opaque because its retype belongs to 11.2's
//! `x509_vfy.c`, which casts it), `X509_POLICY_TREE *tree`, `SSL_DANE *dane`, the `OCSP_RESPONSE`
//! stack and the twelve `X509_STORE_CTX`-typed callbacks' context parameter — are modelled as
//! opaque pointers, exactly as the store's callbacks are; every one is a pointer, so the offsets
//! are exact.
//!
//! ## The substitutions: `OSSL_STACK_OF_X509_free`
//!
//! [`X509_STORE_get1_all_certs`] (`:620`) and [`X509_STORE_CTX_get1_certs`] (`:698`) release their
//! (partial) stacks through `OSSL_STACK_OF_X509_free` (`crypto/x509/t_x509.c:25`, withheld in
//! `t_x509.rs`, 11.4's). The authority's function is exactly `sk_X509_pop_free(certs, X509_free)`,
//! so its call is transcribed as that expansion — a file-local `x509_free_void` thunk over
//! [`X509_free`], the same adapter `store_result.rs` writes for the identical call.
//! [`X509_STORE_CTX_get1_crls`] (`:740`, `:746`) releases its stack through
//! `sk_X509_CRL_pop_free(sk, X509_CRL_free)`, transcribed with an `x509_crl_free_void` thunk for
//! the same reason. No behaviour differs.
//!
//! ## The layouts, measured
//!
//! `struct x509_lookup_method_st` and `struct x509_lookup_st` are declared in the internal
//! `crypto/x509/x509_local.h`; `struct x509_store_st`, `struct x509_object_st` and `struct
//! x509_store_ctx_st` are declared in `include/crypto/x509.h`. Their numbers below were read from
//! the pinned authority's own compiler (the technique `courts/layout/measure-x509.c` uses; that
//! program does not yet cover these five, and this slice may edit only its two files, so the
//! printing programme is recorded by result rather than committed). `X509_POLICY_TREE *`,
//! `SSL_DANE *` and the `OCSP_RESPONSE` stack are unlanded pointer types, modelled as
//! `*mut c_void`, as is the ctx's `X509_VERIFY_PARAM *param` (retyped to the real type only on
//! the store, above); each is a pointer, so every offset is exact. The two read-path
//! members [`X509StoreCtx`] adds beyond the store — `libctx` and `propq` — are read at offsets
//! 272 and 280.
//!
//! ## The raise sites
//!
//! `crypto/x509/x509_lu.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! coordinates are **declared locally** in the `err_sites::ErrSite` shape (as `v3_purp.rs`
//! does). **Eleven** are on landed code — the five in [`X509_STORE_new`]
//! (`:189`/`:194`/`:199`/`:203`/`:209`), [`X509_STORE_add_lookup`] (`:284`/`:292`),
//! [`X509_STORE_add_cert`] (`:432`), [`X509_STORE_add_crl`] (`:441`) and the two object-cache
//! readers (`:607`/`:627`). The reasons are read from `include/openssl/err.h.in`:
//! `ERR_LIB_X509` = 11 (`:85`), `ERR_R_X509_LIB` = `11 | ERR_RFLAG_COMMON` (`:327`),
//! `ERR_R_CRYPTO_LIB` = `15 | ERR_RFLAG_COMMON` (`:330`) and `ERR_R_PASSED_NULL_PARAMETER`
//! = `258 | ERR_R_FATAL` (`:356`), with `ERR_RFLAG_COMMON` = `0x2 << 18` (`:241`),
//! `ERR_R_FATAL` = `ERR_RFLAG_FATAL | ERR_RFLAG_COMMON` (`:353`) and `ERR_LIB_CRYPTO` = 15
//! (`:89`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, CStr};
use core::mem::{offset_of, size_of, MaybeUninit};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_X509_STORE,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_find, OPENSSL_sk_find_all, OPENSSL_sk_free,
    OPENSSL_sk_is_sorted, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};
use crate::x509::x509_cmp::{
    X509_CRL_cmp, X509_CRL_match, X509_add_cert, X509_cmp, X509_subject_name_cmp,
};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x509_vpm::{
    X509VerifyParam, X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set1,
    X509_VERIFY_PARAM_set_depth, X509_VERIFY_PARAM_set_flags, X509_VERIFY_PARAM_set_purpose,
    X509_VERIFY_PARAM_set_trust,
};
use crate::x509::x_crl::{X509Crl, X509_CRL_free, X509_CRL_up_ref};
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::{X509_free, X509};

// ---------------------------------------------------------------------------------------------
// Constants and raise coordinates — see the module doc.
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_X509_LIB` — `include/openssl/err.h.in:327`, `11 | ERR_RFLAG_COMMON`.
const ERR_R_X509_LIB: c_int = 524299;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `15 | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// The `X509_ADD_FLAG_UP_REF` word `X509_STORE_get1_all_certs` passes to
/// [`X509_add_cert`] — `include/openssl/x509.h:995`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_zalloc`/`OPENSSL_free` expansions.
const FILE: &CStr = c"crypto/x509/x509_lu.c";
/// `X509_LOOKUP_new`'s `OPENSSL_zalloc(sizeof(*ret))` (`:20`).
const LINE_ZALLOC_LOOKUP: c_int = 20;
/// `X509_LOOKUP_new`'s error-path `OPENSSL_free(ret)` (`:27`).
const LINE_FREE_LOOKUP_NEW: c_int = 27;
/// `X509_LOOKUP_free`'s `OPENSSL_free(ctx)` (`:39`).
const LINE_FREE_LOOKUP: c_int = 39;
/// `X509_STORE_new`'s `OPENSSL_zalloc(sizeof(*ret))` (`:184`).
const LINE_ZALLOC_STORE: c_int = 184;
/// `X509_STORE_new`'s error-path `OPENSSL_free(ret)` (`:222`).
const LINE_FREE_STORE_NEW: c_int = 222;
/// `X509_STORE_free`'s `OPENSSL_free(xs)` (`:253`).
const LINE_FREE_STORE: c_int = 253;
/// `X509_OBJECT_new`'s `OPENSSL_zalloc(sizeof(*ret))` (`:481`).
const LINE_ZALLOC_OBJECT: c_int = 481;
/// `X509_OBJECT_free`'s `OPENSSL_free(a)` (`:530`).
const LINE_FREE_OBJECT: c_int = 530;
/// `x509_object_dup`'s error-path `OPENSSL_free(ret)` (`:595`).
const LINE_FREE_OBJECT_DUP: c_int = 595;

/// One `x509_lu.c` raise coordinate, declared locally (see the module doc).
const fn x509_lu_site(line: c_int, func: &'static CStr, lib: c_int, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_lu.c",
        line,
        func,
        lib,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_STORE_add_lookup`'s failed `X509_LOOKUP_new` at `x509_lu.c:284`.
const X509_LU_284: ErrSite =
    x509_lu_site(284, c"X509_STORE_add_lookup", ERR_LIB_X509, ERR_R_X509_LIB);
/// `X509_STORE_add_lookup`'s failed `sk_X509_LOOKUP_push` at `x509_lu.c:292`.
const X509_LU_292: ErrSite = x509_lu_site(
    292,
    c"X509_STORE_add_lookup",
    ERR_LIB_X509,
    ERR_R_CRYPTO_LIB,
);
/// `X509_STORE_add_cert`'s failed `x509_store_add` at `x509_lu.c:432`.
const X509_LU_432: ErrSite =
    x509_lu_site(432, c"X509_STORE_add_cert", ERR_LIB_X509, ERR_R_X509_LIB);
/// `X509_STORE_add_crl`'s failed `x509_store_add` at `x509_lu.c:441`.
const X509_LU_441: ErrSite = x509_lu_site(441, c"X509_STORE_add_crl", ERR_LIB_X509, ERR_R_X509_LIB);
/// `X509_STORE_get1_objects`' NULL store at `x509_lu.c:607`.
const X509_LU_607: ErrSite = x509_lu_site(
    607,
    c"X509_STORE_get1_objects",
    ERR_LIB_X509,
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `X509_STORE_get1_all_certs`' NULL store at `x509_lu.c:627`.
const X509_LU_627: ErrSite = x509_lu_site(
    627,
    c"X509_STORE_get1_all_certs",
    ERR_LIB_X509,
    ERR_R_PASSED_NULL_PARAMETER,
);
/// `X509_STORE_new`'s failed `sk_X509_OBJECT_new` at `x509_lu.c:189`.
const X509_LU_189: ErrSite = x509_lu_site(189, c"X509_STORE_new", ERR_LIB_X509, ERR_R_CRYPTO_LIB);
/// `X509_STORE_new`'s failed `sk_X509_LOOKUP_new_null` at `x509_lu.c:194`.
const X509_LU_194: ErrSite = x509_lu_site(194, c"X509_STORE_new", ERR_LIB_X509, ERR_R_CRYPTO_LIB);
/// `X509_STORE_new`'s failed `X509_VERIFY_PARAM_new` at `x509_lu.c:199`.
const X509_LU_199: ErrSite = x509_lu_site(199, c"X509_STORE_new", ERR_LIB_X509, ERR_R_X509_LIB);
/// `X509_STORE_new`'s failed `CRYPTO_new_ex_data` at `x509_lu.c:203`.
const X509_LU_203: ErrSite = x509_lu_site(203, c"X509_STORE_new", ERR_LIB_X509, ERR_R_CRYPTO_LIB);
/// `X509_STORE_new`'s failed `CRYPTO_THREAD_lock_new` at `x509_lu.c:209`.
const X509_LU_209: ErrSite = x509_lu_site(209, c"X509_STORE_new", ERR_LIB_X509, ERR_R_CRYPTO_LIB);

// ---------------------------------------------------------------------------------------------
// The callback typedefs (declared in `include/openssl/x509_vfy.h`).
// ---------------------------------------------------------------------------------------------

/// `X509_LOOKUP_TYPE` — `include/openssl/x509_vfy.h:62-68`, an `int`-sized enum.
pub type X509_LOOKUP_TYPE = c_int;
/// `X509_LU_NONE` — `include/openssl/x509_vfy.h:64`.
pub const X509_LU_NONE: X509_LOOKUP_TYPE = 0;
/// `X509_LU_X509` — `include/openssl/x509_vfy.h:65`.
pub const X509_LU_X509: X509_LOOKUP_TYPE = 1;
/// `X509_LU_CRL` — `include/openssl/x509_vfy.h:66`.
pub const X509_LU_CRL: X509_LOOKUP_TYPE = 2;

/// `X509_LOOKUP_ctrl_fn` — `include/openssl/x509_vfy.h:540-541`, the method vtable's `ctrl`.
pub type X509_LOOKUP_ctrl_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        cmd: c_int,
        argc: *const c_char,
        argl: c_long,
        ret: *mut *mut c_char,
    ) -> c_int,
>;

/// `X509_LOOKUP_ctrl_ex_fn` — `include/openssl/x509_vfy.h:542-544`. `OSSL_LIB_CTX` is unlanded, so
/// its pointer is opaque.
pub type X509_LOOKUP_ctrl_ex_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        cmd: c_int,
        argc: *const c_char,
        argl: c_long,
        ret: *mut *mut c_char,
        libctx: *mut c_void,
        propq: *const c_char,
    ) -> c_int,
>;

/// `X509_LOOKUP_get_by_subject_fn` — `include/openssl/x509_vfy.h:546-549`.
pub type X509_LOOKUP_get_by_subject_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        type_: X509_LOOKUP_TYPE,
        name: *const X509Name,
        ret: *mut X509Object,
    ) -> c_int,
>;

/// `X509_LOOKUP_get_by_subject_ex_fn` — `include/openssl/x509_vfy.h:550-555`.
pub type X509_LOOKUP_get_by_subject_ex_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        type_: X509_LOOKUP_TYPE,
        name: *const X509Name,
        ret: *mut X509Object,
        libctx: *mut c_void,
        propq: *const c_char,
    ) -> c_int,
>;

/// `X509_LOOKUP_get_by_issuer_serial_fn` — `include/openssl/x509_vfy.h:556-560`.
pub type X509_LOOKUP_get_by_issuer_serial_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        type_: X509_LOOKUP_TYPE,
        name: *const X509Name,
        serial: *const Asn1String,
        ret: *mut X509Object,
    ) -> c_int,
>;

/// `X509_LOOKUP_get_by_fingerprint_fn` — `include/openssl/x509_vfy.h:561-565`.
pub type X509_LOOKUP_get_by_fingerprint_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        type_: X509_LOOKUP_TYPE,
        bytes: *const c_uchar,
        len: c_int,
        ret: *mut X509Object,
    ) -> c_int,
>;

/// `X509_LOOKUP_get_by_alias_fn` — `include/openssl/x509_vfy.h:566-570`.
pub type X509_LOOKUP_get_by_alias_fn = Option<
    unsafe extern "C" fn(
        ctx: *mut X509Lookup,
        type_: X509_LOOKUP_TYPE,
        str_: *const c_char,
        len: c_int,
        ret: *mut X509Object,
    ) -> c_int,
>;

/// `X509_STORE_CTX_verify_fn` — `include/openssl/x509_vfy.h:159`. `X509_STORE_CTX` is 11.2's type
/// (`crypto/x509/x509_vfy.c`), so its parameter is an opaque pointer here.
pub type X509_STORE_CTX_verify_fn = Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;
/// `X509_STORE_CTX_verify_cb` — `include/openssl/x509_vfy.h:157`.
pub type X509_STORE_CTX_verify_cb =
    Option<unsafe extern "C" fn(ok: c_int, ctx: *mut c_void) -> c_int>;
/// `X509_STORE_CTX_get_issuer_fn` — `include/openssl/x509_vfy.h:160-161`.
pub type X509_STORE_CTX_get_issuer_fn =
    Option<unsafe extern "C" fn(issuer: *mut *mut X509, ctx: *mut c_void, x: *mut X509) -> c_int>;
/// `X509_STORE_CTX_check_issued_fn` — `include/openssl/x509_vfy.h:162-163`.
pub type X509_STORE_CTX_check_issued_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, x: *mut X509, issuer: *mut X509) -> c_int>;
/// `X509_STORE_CTX_check_revocation_fn` — `include/openssl/x509_vfy.h:164`.
pub type X509_STORE_CTX_check_revocation_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;
/// `X509_STORE_CTX_get_crl_fn` — `include/openssl/x509_vfy.h:165-166`.
pub type X509_STORE_CTX_get_crl_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, crl: *mut *mut X509Crl, x: *mut X509) -> c_int>;
/// `X509_STORE_CTX_check_crl_fn` — `include/openssl/x509_vfy.h:167`.
pub type X509_STORE_CTX_check_crl_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, crl: *mut X509Crl) -> c_int>;
/// `X509_STORE_CTX_cert_crl_fn` — `include/openssl/x509_vfy.h:168-169`.
pub type X509_STORE_CTX_cert_crl_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, crl: *mut X509Crl, x: *mut X509) -> c_int>;
/// `X509_STORE_CTX_check_policy_fn` — `include/openssl/x509_vfy.h:170`.
pub type X509_STORE_CTX_check_policy_fn = Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;
/// `X509_STORE_CTX_lookup_certs_fn` — `include/openssl/x509_vfy.h:172-173`.
pub type X509_STORE_CTX_lookup_certs_fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, nm: *const X509Name) -> *mut OpenSslStack>;
/// `X509_STORE_CTX_lookup_crls_fn` — `include/openssl/x509_vfy.h:175-176`.
pub type X509_STORE_CTX_lookup_crls_fn =
    Option<unsafe extern "C" fn(ctx: *const c_void, nm: *const X509Name) -> *mut OpenSslStack>;
/// `X509_STORE_CTX_cleanup_fn` — `include/openssl/x509_vfy.h:177`.
pub type X509_STORE_CTX_cleanup_fn = Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;

// ---------------------------------------------------------------------------------------------
// The layouts — see the module doc for how the numbers were obtained.
// ---------------------------------------------------------------------------------------------

/// `struct x509_object_st` — `X509_OBJECT`, from `include/crypto/x509.h:304-311`.
///
/// A lookup type tag and the union of the two object kinds it can name. `X509_LOOKUP_TYPE` is
/// `int`-sized, so the union sits at offset 8 and the whole is 16 bytes.
#[repr(C)]
pub struct X509Object {
    /// `X509_LOOKUP_TYPE type` — `X509_LU_NONE`/`_X509`/`_CRL`.
    pub(crate) type_: X509_LOOKUP_TYPE,
    /// `union { X509 *x509; X509_CRL *crl; } data` — the named object.
    pub(crate) data: X509ObjectData,
}

/// The `X509_OBJECT` payload union — `include/crypto/x509.h:307-310`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union X509ObjectData {
    /// `X509 *x509` — set when `type` is `X509_LU_X509`.
    pub(crate) x509: *mut X509,
    /// `X509_CRL *crl` — set when `type` is `X509_LU_CRL`.
    pub(crate) crl: *mut X509Crl,
}

const _: () = {
    assert!(size_of::<X509Object>() == 16);
    assert!(offset_of!(X509Object, type_) == 0);
    assert!(offset_of!(X509Object, data) == 8);
};

/// `struct x509_lookup_method_st` — `X509_LOOKUP_METHOD`, from `crypto/x509/x509_local.h:74-98`.
///
/// The vtable `crypto/x509/x509_meth.c` fills. Every member after `name` is an optional callback;
/// the first parameter of each is the `X509_LOOKUP` instance the method is attached to.
#[repr(C)]
pub struct X509LookupMethod {
    /// `char *name` — the method's name, owned.
    pub(crate) name: *mut c_char,
    /// `int (*new_item)(X509_LOOKUP *ctx)` — the per-instance constructor.
    pub(crate) new_item: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
    /// `void (*free)(X509_LOOKUP *ctx)` — the instance destructor.
    pub(crate) free: Option<unsafe extern "C" fn(ctx: *mut X509Lookup)>,
    /// `int (*init)(X509_LOOKUP *ctx)` — the instance initialiser.
    pub(crate) init: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
    /// `int (*shutdown)(X509_LOOKUP *ctx)` — the instance shutdown.
    pub(crate) shutdown: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
    /// `int (*ctrl)(...)` — the method's control door.
    pub(crate) ctrl: X509_LOOKUP_ctrl_fn,
    /// `int (*get_by_subject)(...)` — the subject lookup.
    pub(crate) get_by_subject: X509_LOOKUP_get_by_subject_fn,
    /// `int (*get_by_issuer_serial)(...)` — the issuer-and-serial lookup.
    pub(crate) get_by_issuer_serial: X509_LOOKUP_get_by_issuer_serial_fn,
    /// `int (*get_by_fingerprint)(...)` — the fingerprint lookup.
    pub(crate) get_by_fingerprint: X509_LOOKUP_get_by_fingerprint_fn,
    /// `int (*get_by_alias)(...)` — the alias lookup.
    pub(crate) get_by_alias: X509_LOOKUP_get_by_alias_fn,
    /// `int (*get_by_subject_ex)(...)` — the library-context-aware subject lookup.
    pub(crate) get_by_subject_ex: X509_LOOKUP_get_by_subject_ex_fn,
    /// `int (*ctrl_ex)(...)` — the library-context-aware control door.
    pub(crate) ctrl_ex: X509_LOOKUP_ctrl_ex_fn,
}

const _: () = {
    assert!(size_of::<X509LookupMethod>() == 96);
    assert!(offset_of!(X509LookupMethod, name) == 0);
    assert!(offset_of!(X509LookupMethod, new_item) == 8);
    assert!(offset_of!(X509LookupMethod, free) == 16);
    assert!(offset_of!(X509LookupMethod, init) == 24);
    assert!(offset_of!(X509LookupMethod, shutdown) == 32);
    assert!(offset_of!(X509LookupMethod, ctrl) == 40);
    assert!(offset_of!(X509LookupMethod, get_by_subject) == 48);
    assert!(offset_of!(X509LookupMethod, get_by_issuer_serial) == 56);
    assert!(offset_of!(X509LookupMethod, get_by_fingerprint) == 64);
    assert!(offset_of!(X509LookupMethod, get_by_alias) == 72);
    assert!(offset_of!(X509LookupMethod, get_by_subject_ex) == 80);
    assert!(offset_of!(X509LookupMethod, ctrl_ex) == 88);
};

/// `struct x509_lookup_st` — `X509_LOOKUP`, from `crypto/x509/x509_local.h:101-107`.
///
/// One method instance: the method it belongs to, the method's private attachment, and the store
/// that owns it.
#[repr(C)]
pub struct X509Lookup {
    /// `int init` — non-zero once started.
    pub(crate) init: c_int,
    /// `int skip` — non-zero to take the lookup out of the search.
    pub(crate) skip: c_int,
    /// `X509_LOOKUP_METHOD *method` — the functions.
    pub(crate) method: *mut X509LookupMethod,
    /// `void *method_data` — the method's private data.
    pub(crate) method_data: *mut c_void,
    /// `X509_STORE *store_ctx` — the store that owns us.
    pub(crate) store_ctx: *mut X509Store,
}

const _: () = {
    assert!(size_of::<X509Lookup>() == 32);
    assert!(offset_of!(X509Lookup, init) == 0);
    assert!(offset_of!(X509Lookup, skip) == 4);
    assert!(offset_of!(X509Lookup, method) == 8);
    assert!(offset_of!(X509Lookup, method_data) == 16);
    assert!(offset_of!(X509Lookup, store_ctx) == 24);
};

/// `struct x509_store_st` — `X509_STORE`, from `crypto/x509/x509_local.h:114-149`.
///
/// The trusted-object cache, the external lookup methods, the verify parameters and the twelve
/// callbacks the verification engine reads. `X509_VERIFY_PARAM *param` is now the real
/// [`X509VerifyParam`] (11.2's `crypto/x509/x509_vpm.c`); the twelve callback members' context
/// parameter stays an opaque `*mut c_void` (see the module doc). Every one is a pointer, so the
/// layout is exact.
#[repr(C)]
pub struct X509Store {
    /// `int cache` — non-zero to stash hits in `objs`.
    pub(crate) cache: c_int,
    /// `STACK_OF(X509_OBJECT) *objs` — the cache of all objects.
    pub(crate) objs: *mut OpenSslStack,
    /// `STACK_OF(X509_LOOKUP) *get_cert_methods` — the external lookup methods.
    pub(crate) get_cert_methods: *mut OpenSslStack,
    /// `X509_VERIFY_PARAM *param` — the verify parameters ([`X509VerifyParam`], `x509_vpm.c`).
    pub(crate) param: *mut X509VerifyParam,
    /// `int (*verify)(X509_STORE_CTX *ctx)` — the chain verifier.
    pub(crate) verify: X509_STORE_CTX_verify_fn,
    /// `int (*verify_cb)(int ok, X509_STORE_CTX *ctx)` — the error callback.
    pub(crate) verify_cb: X509_STORE_CTX_verify_cb,
    /// `int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)`.
    pub(crate) get_issuer: X509_STORE_CTX_get_issuer_fn,
    /// `int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)`.
    pub(crate) check_issued: X509_STORE_CTX_check_issued_fn,
    /// `int (*check_revocation)(X509_STORE_CTX *ctx)`.
    pub(crate) check_revocation: X509_STORE_CTX_check_revocation_fn,
    /// `int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x)`.
    pub(crate) get_crl: X509_STORE_CTX_get_crl_fn,
    /// `int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl)`.
    pub(crate) check_crl: X509_STORE_CTX_check_crl_fn,
    /// `int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)`.
    pub(crate) cert_crl: X509_STORE_CTX_cert_crl_fn,
    /// `int (*check_policy)(X509_STORE_CTX *ctx)`.
    pub(crate) check_policy: X509_STORE_CTX_check_policy_fn,
    /// `STACK_OF(X509) *(*lookup_certs)(X509_STORE_CTX *ctx, const X509_NAME *nm)`.
    pub(crate) lookup_certs: X509_STORE_CTX_lookup_certs_fn,
    /// `STACK_OF(X509_CRL) *(*lookup_crls)(const X509_STORE_CTX *ctx, const X509_NAME *nm)`.
    pub(crate) lookup_crls: X509_STORE_CTX_lookup_crls_fn,
    /// `int (*cleanup)(X509_STORE_CTX *ctx)`.
    pub(crate) cleanup: X509_STORE_CTX_cleanup_fn,
    /// `CRYPTO_EX_DATA ex_data` — the application extension block.
    pub(crate) ex_data: CryptoExData,
    /// `CRYPTO_REF_COUNT references` — the count `X509_STORE_up_ref`/`_free` move.
    pub(crate) references: c_int,
    /// `CRYPTO_RWLOCK *lock` — the lock guarding `objs`.
    pub(crate) lock: *mut CryptoRwlock,
}

const _: () = {
    assert!(size_of::<X509Store>() == 160);
    assert!(offset_of!(X509Store, cache) == 0);
    assert!(offset_of!(X509Store, objs) == 8);
    assert!(offset_of!(X509Store, get_cert_methods) == 16);
    assert!(offset_of!(X509Store, param) == 24);
    assert!(offset_of!(X509Store, verify) == 32);
    assert!(offset_of!(X509Store, verify_cb) == 40);
    assert!(offset_of!(X509Store, get_issuer) == 48);
    assert!(offset_of!(X509Store, check_issued) == 56);
    assert!(offset_of!(X509Store, check_revocation) == 64);
    assert!(offset_of!(X509Store, get_crl) == 72);
    assert!(offset_of!(X509Store, check_crl) == 80);
    assert!(offset_of!(X509Store, cert_crl) == 88);
    assert!(offset_of!(X509Store, check_policy) == 96);
    assert!(offset_of!(X509Store, lookup_certs) == 104);
    assert!(offset_of!(X509Store, lookup_crls) == 112);
    assert!(offset_of!(X509Store, cleanup) == 120);
    assert!(offset_of!(X509Store, ex_data) == 128);
    assert!(offset_of!(X509Store, references) == 144);
    assert!(offset_of!(X509Store, lock) == 152);
};

/// `struct x509_store_ctx_st` — `X509_STORE_CTX`, from `include/crypto/x509.h:215-287`.
///
/// Phase 11.1 defines this layout because the store's read path dereferences `ctx->store`,
/// `ctx->libctx` and `ctx->propq`. What 11.1 does **not** land is the context's *lifecycle*
/// (`X509_STORE_CTX_new`/`_free`/`_init`) or its verify roll — those are 11.2's (`x509_vfy.c`),
/// so no function that drives them is transcribed here. The members whose own types are 11.2's or
/// a later stratum's (`X509_VERIFY_PARAM *param`, `X509_POLICY_TREE *tree`, `SSL_DANE *dane` and
/// the `OCSP_RESPONSE` stack) are modelled as opaque pointers; every one is a pointer, so the
/// offsets are exact.
#[repr(C)]
pub struct X509StoreCtx {
    /// `X509_STORE *store` — the store the search runs against.
    pub(crate) store: *mut X509Store,
    /// `X509 *cert` — the certificate to check.
    pub(crate) cert: *mut X509,
    /// `STACK_OF(X509) *untrusted` — the untrusted chain passed in.
    pub(crate) untrusted: *mut OpenSslStack,
    /// `STACK_OF(X509_CRL) *crls` — the CRLs passed in.
    pub(crate) crls: *mut OpenSslStack,
    /// `STACK_OF(OCSP_RESPONSE) *ocsp_resp` — `OCSP_RESPONSE` is Phase 12's.
    pub(crate) ocsp_resp: *mut OpenSslStack,
    /// `X509_VERIFY_PARAM *param` — 11.2's type.
    pub(crate) param: *mut c_void,
    /// `void *other_ctx` — the caller's private context.
    pub(crate) other_ctx: *mut c_void,
    /// `int (*verify)(X509_STORE_CTX *ctx)` — the chain verifier.
    pub(crate) verify: X509_STORE_CTX_verify_fn,
    /// `int (*verify_cb)(int ok, X509_STORE_CTX *ctx)` — the error callback.
    pub(crate) verify_cb: X509_STORE_CTX_verify_cb,
    /// `int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)`.
    pub(crate) get_issuer: X509_STORE_CTX_get_issuer_fn,
    /// `int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)`.
    pub(crate) check_issued: X509_STORE_CTX_check_issued_fn,
    /// `int (*check_revocation)(X509_STORE_CTX *ctx)`.
    pub(crate) check_revocation: X509_STORE_CTX_check_revocation_fn,
    /// `int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x)`.
    pub(crate) get_crl: X509_STORE_CTX_get_crl_fn,
    /// `int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl)`.
    pub(crate) check_crl: X509_STORE_CTX_check_crl_fn,
    /// `int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)`.
    pub(crate) cert_crl: X509_STORE_CTX_cert_crl_fn,
    /// `int (*check_policy)(X509_STORE_CTX *ctx)`.
    pub(crate) check_policy: X509_STORE_CTX_check_policy_fn,
    /// `STACK_OF(X509) *(*lookup_certs)(X509_STORE_CTX *ctx, const X509_NAME *nm)`.
    pub(crate) lookup_certs: X509_STORE_CTX_lookup_certs_fn,
    /// `STACK_OF(X509_CRL) *(*lookup_crls)(const X509_STORE_CTX *ctx, const X509_NAME *nm)`.
    pub(crate) lookup_crls: X509_STORE_CTX_lookup_crls_fn,
    /// `int (*cleanup)(X509_STORE_CTX *ctx)`.
    pub(crate) cleanup: X509_STORE_CTX_cleanup_fn,
    /// `int valid` — 0 to rebuild the chain.
    pub(crate) valid: c_int,
    /// `int num_untrusted` — the number of untrusted certificates.
    pub(crate) num_untrusted: c_int,
    /// `STACK_OF(X509) *chain` — the chain built up and trusted.
    pub(crate) chain: *mut OpenSslStack,
    /// `X509_POLICY_TREE *tree` — the valid policy tree, 11.2's type.
    pub(crate) tree: *mut c_void,
    /// `int explicit_policy` — the required explicit-policy value.
    pub(crate) explicit_policy: c_int,
    /// `int error_depth` — the depth at which `error` was set.
    pub(crate) error_depth: c_int,
    /// `int error` — the `X509_V_ERR_*` reason.
    pub(crate) error: c_int,
    /// `X509 *current_cert` — the certificate currently being tested.
    pub(crate) current_cert: *mut X509,
    /// `X509 *current_issuer` — the certificate currently tested as issuer.
    pub(crate) current_issuer: *mut X509,
    /// `X509_CRL *current_crl` — the current CRL.
    pub(crate) current_crl: *mut X509Crl,
    /// `int current_crl_score` — the current CRL's score.
    pub(crate) current_crl_score: c_int,
    /// `unsigned int current_reasons` — the current reason mask.
    pub(crate) current_reasons: c_uint,
    /// `X509_STORE_CTX *parent` — the parent context during CRL path validation.
    pub(crate) parent: *mut X509StoreCtx,
    /// `CRYPTO_EX_DATA ex_data` — the application extension block.
    pub(crate) ex_data: CryptoExData,
    /// `SSL_DANE *dane` — the DANE context, `SSL_DANE` being the SSL layer's.
    pub(crate) dane: *mut c_void,
    /// `int bare_ta_signed` — set when signed by a bare trust anchor's public key.
    pub(crate) bare_ta_signed: c_int,
    /// `EVP_PKEY *rpk` — the raw public key.
    pub(crate) rpk: *mut EvpPkey,
    /// `OSSL_LIB_CTX *libctx` — the library context the read path threads through.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — the property query the read path threads through.
    pub(crate) propq: *mut c_char,
}

const _: () = {
    assert!(size_of::<X509StoreCtx>() == 288);
    assert!(offset_of!(X509StoreCtx, store) == 0);
    assert!(offset_of!(X509StoreCtx, cert) == 8);
    assert!(offset_of!(X509StoreCtx, untrusted) == 16);
    assert!(offset_of!(X509StoreCtx, crls) == 24);
    assert!(offset_of!(X509StoreCtx, ocsp_resp) == 32);
    assert!(offset_of!(X509StoreCtx, param) == 40);
    assert!(offset_of!(X509StoreCtx, other_ctx) == 48);
    assert!(offset_of!(X509StoreCtx, verify) == 56);
    assert!(offset_of!(X509StoreCtx, verify_cb) == 64);
    assert!(offset_of!(X509StoreCtx, get_issuer) == 72);
    assert!(offset_of!(X509StoreCtx, check_issued) == 80);
    assert!(offset_of!(X509StoreCtx, check_revocation) == 88);
    assert!(offset_of!(X509StoreCtx, get_crl) == 96);
    assert!(offset_of!(X509StoreCtx, check_crl) == 104);
    assert!(offset_of!(X509StoreCtx, cert_crl) == 112);
    assert!(offset_of!(X509StoreCtx, check_policy) == 120);
    assert!(offset_of!(X509StoreCtx, lookup_certs) == 128);
    assert!(offset_of!(X509StoreCtx, lookup_crls) == 136);
    assert!(offset_of!(X509StoreCtx, cleanup) == 144);
    assert!(offset_of!(X509StoreCtx, valid) == 152);
    assert!(offset_of!(X509StoreCtx, num_untrusted) == 156);
    assert!(offset_of!(X509StoreCtx, chain) == 160);
    assert!(offset_of!(X509StoreCtx, tree) == 168);
    assert!(offset_of!(X509StoreCtx, explicit_policy) == 176);
    assert!(offset_of!(X509StoreCtx, error_depth) == 180);
    assert!(offset_of!(X509StoreCtx, error) == 184);
    assert!(offset_of!(X509StoreCtx, current_cert) == 192);
    assert!(offset_of!(X509StoreCtx, current_issuer) == 200);
    assert!(offset_of!(X509StoreCtx, current_crl) == 208);
    assert!(offset_of!(X509StoreCtx, current_crl_score) == 216);
    assert!(offset_of!(X509StoreCtx, current_reasons) == 220);
    assert!(offset_of!(X509StoreCtx, parent) == 224);
    assert!(offset_of!(X509StoreCtx, ex_data) == 232);
    assert!(offset_of!(X509StoreCtx, dane) == 248);
    assert!(offset_of!(X509StoreCtx, bare_ta_signed) == 256);
    assert!(offset_of!(X509StoreCtx, rpk) == 264);
    assert!(offset_of!(X509StoreCtx, libctx) == 272);
    assert!(offset_of!(X509StoreCtx, propq) == 280);
};

// ---------------------------------------------------------------------------------------------
// X509_LOOKUP — `crypto/x509/x509_lu.c:18-158`.
// ---------------------------------------------------------------------------------------------

/// `X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method)` — `crypto/x509/x509_lu.c:18-31`.
///
/// Allocates a zeroed lookup bound to `method` and runs the method's `new_item` hook; a hook that
/// answers 0 releases the instance and the function answers NULL.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD` (the authority dereferences it unconditionally).
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_new(method: *mut X509LookupMethod) -> *mut X509Lookup {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ret = CRYPTO_zalloc(size_of::<X509Lookup>(), FILE.as_ptr(), LINE_ZALLOC_LOOKUP)
        .cast::<X509Lookup>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is this call's own fresh allocation; `method` is live per the contract.
    unsafe {
        (*ret).method = method;
        if let Some(new_item) = (*method).new_item {
            if new_item(ret) == 0 {
                CRYPTO_free(ret.cast(), FILE.as_ptr(), LINE_FREE_LOOKUP_NEW);
                return ptr::null_mut();
            }
        }
    }
    ret
}

/// `void X509_LOOKUP_free(X509_LOOKUP *ctx)` — `crypto/x509/x509_lu.c:33-40`.
///
/// Runs the method's `free` hook (when both the method and the hook are present) and releases the
/// instance. A NULL `ctx` is a no-op.
///
/// # Safety
///
/// `ctx` must be NULL or a live `X509_LOOKUP`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_free(ctx: *mut X509Lookup) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract; its method may be NULL.
    unsafe {
        let method = (*ctx).method;
        if !method.is_null() {
            if let Some(free_fn) = (*method).free {
                free_fn(ctx);
            }
        }
        CRYPTO_free(ctx.cast(), FILE.as_ptr(), LINE_FREE_LOOKUP);
    }
}

/// `int X509_LOOKUP_init(X509_LOOKUP *ctx)` — `crypto/x509/x509_lu.c:57-65`.
///
/// Runs the method's `init` hook, or answers 1 when there is none. A missing method answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_init(ctx: *mut X509Lookup) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() {
            return 0;
        }
        match (*method).init {
            Some(init) => init(ctx),
            None => 1,
        }
    }
}

/// `int X509_LOOKUP_shutdown(X509_LOOKUP *ctx)` — `crypto/x509/x509_lu.c:67-75`.
///
/// Runs the method's `shutdown` hook, or answers 1 when there is none. A missing method answers 0.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_shutdown(ctx: *mut X509Lookup) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() {
            return 0;
        }
        match (*method).shutdown {
            Some(shutdown) => shutdown(ctx),
            None => 1,
        }
    }
}

/// `int X509_LOOKUP_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret,
/// OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x509_lu.c:77-87`.
///
/// Dispatches to the method's `ctrl_ex` hook, then its `ctrl` hook, and answers 1 when it has
/// neither. A missing method answers -1.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `argc`/`propq` NUL-terminated or NULL; `ret` writable or
/// NULL; `libctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_ctrl_ex(
    ctx: *mut X509Lookup,
    cmd: c_int,
    argc: *const c_char,
    argl: c_long,
    ret: *mut *mut c_char,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() {
            return -1;
        }
        if let Some(ctrl_ex) = (*method).ctrl_ex {
            return ctrl_ex(ctx, cmd, argc, argl, ret, libctx, propq);
        }
        if let Some(ctrl) = (*method).ctrl {
            return ctrl(ctx, cmd, argc, argl, ret);
        }
        1
    }
}

/// `int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret)` —
/// `crypto/x509/x509_lu.c:89-93`.
///
/// [`X509_LOOKUP_ctrl_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_LOOKUP_ctrl_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_ctrl(
    ctx: *mut X509Lookup,
    cmd: c_int,
    argc: *const c_char,
    argl: c_long,
    ret: *mut *mut c_char,
) -> c_int {
    // SAFETY: the contract is `X509_LOOKUP_ctrl_ex`'s with NULL libctx/propq.
    unsafe { X509_LOOKUP_ctrl_ex(ctx, cmd, argc, argl, ret, ptr::null_mut(), ptr::null()) }
}

/// `int X509_LOOKUP_by_subject_ex(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name,
/// X509_OBJECT *ret, OSSL_LIB_CTX *libctx, const char *propq)` — `crypto/x509/x509_lu.c:95-109`.
///
/// A skipped instance, a missing method or a method with neither subject door answers 0; otherwise
/// the `get_by_subject_ex` hook is preferred over `get_by_subject`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `name` live; `ret` writable; `libctx` NULL or live;
/// `propq` NUL-terminated or NULL.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_by_subject_ex(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if (*ctx).skip != 0
            || method.is_null()
            || ((*method).get_by_subject.is_none() && (*method).get_by_subject_ex.is_none())
        {
            return 0;
        }
        if let Some(get_by_subject_ex) = (*method).get_by_subject_ex {
            return get_by_subject_ex(ctx, type_, name, ret, libctx, propq);
        }
        match (*method).get_by_subject {
            Some(get_by_subject) => get_by_subject(ctx, type_, name, ret),
            None => 0,
        }
    }
}

/// `int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME *name,
/// X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:111-115`.
///
/// [`X509_LOOKUP_by_subject_ex`] with a NULL library context and property query.
///
/// # Safety
///
/// As [`X509_LOOKUP_by_subject_ex`], without `libctx`/`propq`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_by_subject(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: the contract is `X509_LOOKUP_by_subject_ex`'s with NULL libctx/propq.
    unsafe { X509_LOOKUP_by_subject_ex(ctx, type_, name, ret, ptr::null_mut(), ptr::null()) }
}

/// `int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const X509_NAME
/// *name, const ASN1_INTEGER *serial, X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:117-125`.
///
/// A missing method or method without the door answers 0; otherwise it dispatches to
/// `get_by_issuer_serial`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `name`/`serial` live; `ret` writable.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_by_issuer_serial(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    serial: *const Asn1String,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() || (*method).get_by_issuer_serial.is_none() {
            return 0;
        }
        match (*method).get_by_issuer_serial {
            Some(get_by_issuer_serial) => get_by_issuer_serial(ctx, type_, name, serial, ret),
            None => 0,
        }
    }
}

/// `int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const unsigned char
/// *bytes, int len, X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:127-134`.
///
/// A missing method or method without the door answers 0; otherwise it dispatches to
/// `get_by_fingerprint`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `bytes` live for `len`; `ret` writable.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_by_fingerprint(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    bytes: *const c_uchar,
    len: c_int,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() || (*method).get_by_fingerprint.is_none() {
            return 0;
        }
        match (*method).get_by_fingerprint {
            Some(get_by_fingerprint) => get_by_fingerprint(ctx, type_, bytes, len, ret),
            None => 0,
        }
    }
}

/// `int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const char *str, int len,
/// X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:136-142`.
///
/// A missing method or method without the door answers 0; otherwise it dispatches to `get_by_alias`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `str` live for `len`; `ret` writable.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_by_alias(
    ctx: *mut X509Lookup,
    type_: X509_LOOKUP_TYPE,
    str_: *const c_char,
    len: c_int,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let method = (*ctx).method;
        if method.is_null() || (*method).get_by_alias.is_none() {
            return 0;
        }
        match (*method).get_by_alias {
            Some(get_by_alias) => get_by_alias(ctx, type_, str_, len, ret),
            None => 0,
        }
    }
}

/// `int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data)` —
/// `crypto/x509/x509_lu.c:144-148`.
///
/// Stores the method's private data and answers 1.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`; `data` is stored verbatim.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_set_method_data(
    ctx: *mut X509Lookup,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live and writable per the contract.
    unsafe { (*ctx).method_data = data };
    1
}

/// `void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_lu.c:150-153`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_get_method_data(ctx: *const X509Lookup) -> *mut c_void {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).method_data }
}

/// `X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_lu.c:155-158`.
///
/// # Safety
///
/// `ctx` must be a live `X509_LOOKUP`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_get_store(ctx: *const X509Lookup) -> *mut X509Store {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).store_ctx }
}

// ---------------------------------------------------------------------------------------------
// The object comparator and the object stack — `crypto/x509/x509_lu.c:160-180`, `:479-618`.
// ---------------------------------------------------------------------------------------------

/// `static int x509_object_cmp(const X509_OBJECT *const *a, const X509_OBJECT *const *b)` —
/// `crypto/x509/x509_lu.c:160-180`.
///
/// Orders by lookup type, then — for `X509_LU_X509` by subject name and for `X509_LU_CRL` by
/// issuer name; the difference of the two types is returned directly and is not normalised.
/// `X509_LU_NONE` compares equal to itself. The stack passes element slots, so both arguments are
/// pointers to the `X509_OBJECT *` to compare.
///
/// # Safety
///
/// `a`/`b` must each be a live slot holding a live `X509_OBJECT`.
unsafe extern "C" fn x509_object_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack's comparator contract supplies two element slots.
    unsafe {
        let a = a.cast::<*const X509Object>();
        let b = b.cast::<*const X509Object>();
        let ta = (**a).type_;
        let tb = (**b).type_;
        let ret = ta - tb;
        if ret != 0 {
            return ret;
        }
        match ta {
            X509_LU_X509 => X509_subject_name_cmp((**a).data.x509, (**b).data.x509),
            X509_LU_CRL => X509_CRL_cmp((**a).data.crl, (**b).data.crl),
            _ => 0,
        }
    }
}

/// `X509_OBJECT *X509_OBJECT_new(void)` — `crypto/x509/x509_lu.c:479-487`.
///
/// A zeroed object tagged `X509_LU_NONE`.
///
/// # Safety
///
/// The returned object, when non-NULL, is owned by the caller and must be released with
/// [`X509_OBJECT_free`].
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_new() -> *mut X509Object {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ret = CRYPTO_zalloc(size_of::<X509Object>(), FILE.as_ptr(), LINE_ZALLOC_OBJECT)
        .cast::<X509Object>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is this call's own fresh allocation.
    unsafe { (*ret).type_ = X509_LU_NONE };
    ret
}

/// `static void x509_object_free_internal(X509_OBJECT *a)` — `crypto/x509/x509_lu.c:489-503`.
///
/// Releases the object the union names, by type. It does not release the `X509_OBJECT` itself.
///
/// # Safety
///
/// `a` must be NULL or a live `X509_OBJECT`.
unsafe fn x509_object_free_internal(a: *mut X509Object) {
    if a.is_null() {
        return;
    }
    // SAFETY: `a` is live per the contract.
    unsafe {
        match (*a).type_ {
            X509_LU_X509 => X509_free((*a).data.x509),
            X509_LU_CRL => X509_CRL_free((*a).data.crl),
            _ => {}
        }
    }
}

/// `void X509_OBJECT_free(X509_OBJECT *a)` — `crypto/x509/x509_lu.c:527-531`.
///
/// Releases the named object (via `x509_object_free_internal`) and the `X509_OBJECT` itself.
///
/// # Safety
///
/// `a` must be NULL or a live `X509_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_free(a: *mut X509Object) {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe {
        x509_object_free_internal(a);
        CRYPTO_free(a.cast(), FILE.as_ptr(), LINE_FREE_OBJECT);
    }
}

/// `int X509_OBJECT_up_ref_count(X509_OBJECT *a)` — `crypto/x509/x509_lu.c:447-458`.
///
/// Up-refs the named certificate or CRL and answers its refcount's success; an object tagged
/// `X509_LU_NONE` (or any other tag) answers 1 without touching anything.
///
/// # Safety
///
/// `a` must be a live `X509_OBJECT` whose union member is live for its tag.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_up_ref_count(a: *mut X509Object) -> c_int {
    // SAFETY: `a` is live per the contract.
    unsafe {
        match (*a).type_ {
            X509_LU_X509 => X509_up_ref((*a).data.x509),
            X509_LU_CRL => X509_CRL_up_ref((*a).data.crl),
            _ => 1,
        }
    }
}

/// `X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a)` — `crypto/x509/x509_lu.c:460-465`.
///
/// The named certificate, or NULL when `a` is NULL or tagged otherwise.
///
/// # Safety
///
/// `a` must be NULL or a live `X509_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_get0_X509(a: *const X509Object) -> *mut X509 {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe {
        if a.is_null() || (*a).type_ != X509_LU_X509 {
            return ptr::null_mut();
        }
        (*a).data.x509
    }
}

/// `X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a)` — `crypto/x509/x509_lu.c:467-472`.
///
/// The named CRL, or NULL when `a` is NULL or tagged otherwise.
///
/// # Safety
///
/// `a` must be NULL or a live `X509_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_get0_X509_CRL(a: *const X509Object) -> *mut X509Crl {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe {
        if a.is_null() || (*a).type_ != X509_LU_CRL {
            return ptr::null_mut();
        }
        (*a).data.crl
    }
}

/// `X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a)` —
/// `crypto/x509/x509_lu.c:474-477`.
///
/// # Safety
///
/// `a` must be a live `X509_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_get_type(a: *const X509Object) -> X509_LOOKUP_TYPE {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).type_ }
}

/// `int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj)` — `crypto/x509/x509_lu.c:505-514`.
///
/// Up-refs `obj`, releases whatever the object named before and retags it. A NULL `a` or a failed
/// up-ref answers 0.
///
/// # Safety
///
/// `a` must be a live `X509_OBJECT`; `obj` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_set1_X509(a: *mut X509Object, obj: *mut X509) -> c_int {
    // SAFETY: `obj` is live per the contract.
    if a.is_null() || unsafe { X509_up_ref(obj) } == 0 {
        return 0;
    }
    // SAFETY: `a` is live per the contract; `obj` now carries the extra reference.
    unsafe {
        x509_object_free_internal(a);
        (*a).type_ = X509_LU_X509;
        (*a).data.x509 = obj;
    }
    1
}

/// `int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj)` —
/// `crypto/x509/x509_lu.c:516-525`.
///
/// Up-refs `obj`, releases whatever the object named before and retags it. A NULL `a` or a failed
/// up-ref answers 0.
///
/// # Safety
///
/// `a` must be a live `X509_OBJECT`; `obj` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_set1_X509_CRL(a: *mut X509Object, obj: *mut X509Crl) -> c_int {
    // SAFETY: `obj` is live per the contract.
    if a.is_null() || unsafe { X509_CRL_up_ref(obj) } == 0 {
        return 0;
    }
    // SAFETY: `a` is live per the contract; `obj` now carries the extra reference.
    unsafe {
        x509_object_free_internal(a);
        (*a).type_ = X509_LU_CRL;
        (*a).data.crl = obj;
    }
    1
}

/// `static int x509_object_idx_cnt(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type, const X509_NAME
/// *name, int *pnmatch)` — `crypto/x509/x509_lu.c:534-559`.
///
/// Builds a search key whose only meaningful member is the name — a stack-local `X509` whose
/// `cert_info.subject` is `name`, or a stack-local `X509_CRL` whose `crl.issuer` is `name` — and
/// runs the stack's own `find_all`. An `X509_LU_NONE` type answers -1 without searching.
///
/// # Safety
///
/// `h` must be a live object stack whose comparator is [`x509_object_cmp`] (or the authority's
/// equivalent); `name` must be a live `X509_NAME`; `pnmatch` NULL or writable.
unsafe fn x509_object_idx_cnt(
    h: *mut OpenSslStack,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    pnmatch: *mut c_int,
) -> c_int {
    // The key's other members are never read: `x509_object_cmp` reads only `type` and the subject
    // or issuer name, exactly as the authority's stack-local objects leave everything else
    // undefined.
    let mut x509_s = MaybeUninit::<X509>::uninit();
    let mut crl_s = MaybeUninit::<X509Crl>::uninit();
    let mut stmp = MaybeUninit::<X509Object>::uninit();

    // SAFETY: `stmp` is a local slot; `type_` is written before the union member, exactly as the
    // authority writes `stmp.type` then one of `stmp.data.x509`/`stmp.data.crl`.
    unsafe {
        (*stmp.as_mut_ptr()).type_ = type_;
        match type_ {
            X509_LU_X509 => {
                (*x509_s.as_mut_ptr()).cert_info.subject = name.cast_mut();
                (*stmp.as_mut_ptr()).data.x509 = x509_s.as_mut_ptr();
            }
            X509_LU_CRL => {
                (*crl_s.as_mut_ptr()).crl.issuer = name.cast_mut();
                (*stmp.as_mut_ptr()).data.crl = crl_s.as_mut_ptr();
            }
            _ => return -1,
        }
        // SAFETY: `h` is the caller's live stack; the key is `stmp`.
        OPENSSL_sk_find_all(h, stmp.as_ptr().cast(), pnmatch)
    }
}

/// `int X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type, const
/// X509_NAME *name)` — `crypto/x509/x509_lu.c:562-566`.
///
/// The index of the first object matching `name`, or -1. Assumes `h` is locked for read.
///
/// # Safety
///
/// As `x509_object_idx_cnt` with a NULL match count.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_idx_by_subject(
    h: *mut OpenSslStack,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
) -> c_int {
    // SAFETY: the contract forwards to `x509_object_idx_cnt`.
    unsafe { x509_object_idx_cnt(h, type_, name, ptr::null_mut()) }
}

/// `X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
/// const X509_NAME *name)` — `crypto/x509/x509_lu.c:569-578`.
///
/// The first object at the index [`X509_OBJECT_idx_by_subject`] finds, or NULL. Assumes `h` is
/// locked for read.
///
/// # Safety
///
/// As [`X509_OBJECT_idx_by_subject`].
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_retrieve_by_subject(
    h: *mut OpenSslStack,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
) -> *mut X509Object {
    // SAFETY: `h` is live and the contract forwards to `x509_object_idx_cnt`.
    let idx = unsafe { X509_OBJECT_idx_by_subject(h, type_, name) };
    if idx == -1 {
        return ptr::null_mut();
    }
    // SAFETY: `h` is live; `idx` is in range.
    unsafe { OPENSSL_sk_value(h, idx).cast::<X509Object>() }
}

/// `X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h, X509_OBJECT *x)` —
/// `crypto/x509/x509_lu.c:754-781`.
///
/// Finds `x` in `h` and, when it is a certificate or a CRL, walks the run of equal-keyed entries
/// looking for the one that is byte-identical (`X509_cmp`/`X509_CRL_match`). Returns the match or
/// NULL.
///
/// # Safety
///
/// `h` must be a live object stack; `x` must be a live `X509_OBJECT` whose named object is live
/// for its tag.
#[no_mangle]
pub unsafe extern "C" fn X509_OBJECT_retrieve_match(
    h: *mut OpenSslStack,
    x: *mut X509Object,
) -> *mut X509Object {
    // SAFETY: `h` is live and `x` is the key, per the contract.
    let idx = unsafe { OPENSSL_sk_find(h, x.cast()) };
    if idx < 0 {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live per the contract.
    let type_ = unsafe { (*x).type_ };
    if type_ != X509_LU_X509 && type_ != X509_LU_CRL {
        // SAFETY: `h` is live; `idx` is in range.
        return unsafe { OPENSSL_sk_value(h, idx).cast::<X509Object>() };
    }
    // SAFETY: `h` is live.
    let num = unsafe { OPENSSL_sk_num(h) };
    let mut i = idx;
    while i < num {
        // SAFETY: `h` is live and `i` is in range.
        let obj = unsafe { OPENSSL_sk_value(h, i).cast::<X509Object>() };
        // SAFETY: `obj` and `x` are live objects; the comparator takes their slots.
        if unsafe { x509_object_cmp((&raw const obj).cast(), (&raw const x).cast()) } != 0 {
            return ptr::null_mut();
        }
        // SAFETY: `obj` and `x` are live per the contract.
        unsafe {
            if type_ == X509_LU_X509 {
                if X509_cmp((*obj).data.x509, (*x).data.x509) == 0 {
                    return obj;
                }
            } else if X509_CRL_match((*obj).data.crl, (*x).data.crl) == 0 {
                return obj;
            }
        }
        i += 1;
    }
    ptr::null_mut()
}

/// `static X509_OBJECT *x509_object_dup(const X509_OBJECT *obj)` —
/// `crypto/x509/x509_lu.c:585-600`.
///
/// A fresh object naming the same certificate or CRL, up-referenced. Answers NULL on a failed
/// allocation or up-ref.
///
/// # Safety
///
/// `obj` must be a live `X509_OBJECT`.
unsafe fn x509_object_dup(obj: *const X509Object) -> *mut X509Object {
    // SAFETY: neither constructor touches the stack's elements.
    let ret = unsafe { X509_OBJECT_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is live; `obj` is live per the contract.
    unsafe {
        (*ret).type_ = (*obj).type_;
        (*ret).data = (*obj).data;
    }
    // SAFETY: `ret` is live and names the same object as `obj`.
    if unsafe { X509_OBJECT_up_ref_count(ret) } == 0 {
        // SAFETY: `ret` is this call's own object; it names the same object as `obj`.
        unsafe {
            (*ret).type_ = X509_LU_NONE;
            CRYPTO_free(ret.cast(), FILE.as_ptr(), LINE_FREE_OBJECT_DUP);
        }
        return ptr::null_mut();
    }
    ret
}

/// The `X509_OBJECT *(*)(const void *)` copy shape `OPENSSL_sk_deep_copy` takes, adapting
/// [`x509_object_dup`].
///
/// # Safety
///
/// `p` must be a live `X509_OBJECT`.
unsafe extern "C" fn x509_object_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { x509_object_dup(p.cast::<X509Object>()) }.cast()
}

/// The `void (*)(void *)` destructor shape `OPENSSL_sk_deep_copy`/`pop_free` take, adapting
/// [`X509_OBJECT_free`].
///
/// # Safety
///
/// `p` must be NULL or a live `X509_OBJECT`.
unsafe extern "C" fn x509_object_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_OBJECT_free(p.cast::<X509Object>()) };
}

/// The `void (*)(void *)` destructor shape over
/// [`X509_free`], the expansion of
/// `OSSL_STACK_OF_X509_free` (see the module doc).
///
/// # Safety
///
/// `p` must be NULL or a live `X509`.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast::<X509>()) };
}

/// The `void (*)(void *)` destructor shape over
/// [`X509_CRL_free`], the expansion of
/// `sk_X509_CRL_pop_free(sk, X509_CRL_free)` in [`X509_STORE_CTX_get1_crls`].
///
/// # Safety
///
/// `p` must be NULL or a live `X509_CRL`.
unsafe extern "C" fn x509_crl_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_CRL_free(p.cast::<X509Crl>()) };
}

// ---------------------------------------------------------------------------------------------
// X509_STORE — `crypto/x509/x509_lu.c:42-55`, `:182-254`, `:256-295`, `:386-445`, `:580-652`,
// `:783-958`.
// ---------------------------------------------------------------------------------------------

/// `X509_STORE *X509_STORE_new(void)` — `crypto/x509/x509_lu.c:182-224`.
///
/// Allocates a zeroed store, then builds its object cache, its (empty) lookup-method stack, its
/// verify parameters, its extension block and its lock. Any of the five failing raises and reaches
/// the authority's `err:` label, which releases what has been built and answers NULL.
///
/// # Safety
///
/// No argument is read, so this is callable from any state; the returned store is the caller's to
/// release through [`X509_STORE_free`].
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_new() -> *mut X509Store {
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ret =
        CRYPTO_zalloc(size_of::<X509Store>(), FILE.as_ptr(), LINE_ZALLOC_STORE).cast::<X509Store>();
    if ret.is_null() {
        return ptr::null_mut();
    }

    // `if ((ret->objs = sk_X509_OBJECT_new(x509_object_cmp)) == NULL)`
    // SAFETY: the constructor takes only the comparator, which is this file's own.
    let objs = OPENSSL_sk_new(Some(x509_object_cmp));
    // SAFETY: `ret` is this call's own fresh allocation.
    unsafe { (*ret).objs = objs };
    if objs.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_189) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        return unsafe { x509_store_new_err(ret) };
    }

    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).cache = 1 };

    // `if ((ret->get_cert_methods = sk_X509_LOOKUP_new_null()) == NULL)`
    // SAFETY: the constructor takes no arguments.
    let methods = OPENSSL_sk_new_null();
    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).get_cert_methods = methods };
    if methods.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_194) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        return unsafe { x509_store_new_err(ret) };
    }

    // `if ((ret->param = X509_VERIFY_PARAM_new()) == NULL)`
    // SAFETY: the constructor takes no arguments.
    let param = X509_VERIFY_PARAM_new();
    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).param = param };
    if param.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_199) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        return unsafe { x509_store_new_err(ret) };
    }

    // `if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509_STORE, ret, &ret->ex_data))`
    // SAFETY: `ret` is this call's own allocation and `ex_data` is a field of it.
    if unsafe {
        CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_X509_STORE,
            ret.cast(),
            ptr::addr_of_mut!((*ret).ex_data),
        )
    } == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_203) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        return unsafe { x509_store_new_err(ret) };
    }

    // `ret->lock = CRYPTO_THREAD_lock_new();`
    // SAFETY: the constructor takes no arguments.
    let lock = CRYPTO_THREAD_lock_new();
    // SAFETY: `ret` is this call's own allocation.
    unsafe { (*ret).lock = lock };
    if lock.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_209) };
        // SAFETY: `ret` is this call's own allocation and nothing else holds it.
        return unsafe { x509_store_new_err(ret) };
    }

    // `if (!CRYPTO_NEW_REF(&ret->references, 1)) goto err;` — the header's `HAVE_ATOMICS` arm is
    // `refcnt->val = n; return 1;`, so the test is the assignment and the branch is unreachable
    // rather than omitted, exactly as `X509_STORE_up_ref` transcribes its half.
    // SAFETY: `references` is a field of this call's own allocation.
    unsafe { (*ret).references = 1 };
    ret
}

/// `X509_STORE_new`'s `err:` label (`crypto/x509/x509_lu.c:217-223`) — the shared failure exit.
///
/// Releases the four owned members in the authority's order and the block last, then answers NULL.
/// A member the constructor has not reached is still zero, and each release accepts NULL. The
/// authority does **not** call `CRYPTO_free_ex_data` here even when `CRYPTO_new_ex_data` succeeded
/// (only `X509_STORE_free` does), so neither does this.
///
/// # Safety
///
/// `ret` must be a live allocation from [`CRYPTO_zalloc`] that only this call still owns.
unsafe fn x509_store_new_err(ret: *mut X509Store) -> *mut X509Store {
    // SAFETY: `ret` is this call's own live allocation; each member is NULL or owned by it.
    unsafe {
        X509_VERIFY_PARAM_free((*ret).param);
        OPENSSL_sk_free((*ret).objs);
        OPENSSL_sk_free((*ret).get_cert_methods);
        CRYPTO_THREAD_lock_free((*ret).lock);
        CRYPTO_free(ret.cast(), FILE.as_ptr(), LINE_FREE_STORE_NEW);
    }
    ptr::null_mut()
}

/// `void X509_STORE_free(X509_STORE *xs)` — `crypto/x509/x509_lu.c:226-254`.
///
/// Decrements the store's reference count; when it reaches zero, shuts down and releases every
/// lookup method, frees the object cache, the extension block, the verify parameters and the lock,
/// and releases the block. NULL is a no-op.
///
/// # Safety
///
/// `xs` must be NULL, or a live store and this call must retire the last reference to it.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_free(xs: *mut X509Store) {
    if xs.is_null() {
        return;
    }

    // `CRYPTO_DOWN_REF(&xs->references, &i)` — the header's `HAVE_ATOMICS` arm answers the new
    // count. The field is a plain `c_int` here (as `X509_STORE_up_ref` transcribes the other half),
    // so the decrement is a plain store. `REF_PRINT_COUNT` is a trace hook that expands to nothing
    // without `REF_COUNT_DEBUG`, and `REF_ASSERT_ISNT(i < 0)` is empty under `NDEBUG`.
    // SAFETY: `xs` is live per the contract.
    let i = unsafe { (*xs).references.wrapping_sub(1) };
    // SAFETY: `xs` is live and writable.
    unsafe { (*xs).references = i };
    if i > 0 {
        return;
    }

    // SAFETY: `xs` is live and this is the last reference; its lookup stack is live.
    let sk = unsafe { (*xs).get_cert_methods };
    // SAFETY: `sk` is live or NULL, both accepted.
    let num = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..num {
        // SAFETY: `sk` is live and `i` is in range.
        let lu = unsafe { OPENSSL_sk_value(sk, i).cast::<X509Lookup>() };
        // SAFETY: `lu` is a live lookup the store owns.
        unsafe {
            X509_LOOKUP_shutdown(lu);
            X509_LOOKUP_free(lu);
        }
    }
    // SAFETY: `sk` is the store's own lookup stack, now empty of live elements.
    unsafe { OPENSSL_sk_free(sk) };
    // SAFETY: `xs` is live; its object cache is live and owns each element, released through the
    // `void (*)(void *)` thunk over `X509_OBJECT_free`.
    unsafe { OPENSSL_sk_pop_free((*xs).objs, Some(x509_object_free_void)) };

    // SAFETY: `xs` is live and `ex_data` is a field of it.
    unsafe {
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_X509_STORE,
            xs.cast(),
            ptr::addr_of_mut!((*xs).ex_data),
        )
    };
    // SAFETY: `param` is NULL or the object the constructor allocated.
    unsafe { X509_VERIFY_PARAM_free((*xs).param) };
    // SAFETY: `lock` is NULL or the lock the constructor created.
    unsafe { CRYPTO_THREAD_lock_free((*xs).lock) };
    // `CRYPTO_FREE_REF(&xs->references)` is empty on this profile's arm of the header.
    // SAFETY: `xs` is this call's own allocation, released last.
    unsafe { CRYPTO_free(xs.cast(), FILE.as_ptr(), LINE_FREE_STORE) };
}

/// `int X509_STORE_lock(X509_STORE *xs)` — `crypto/x509/x509_lu.c:42-45`.
///
/// Takes the store's write lock.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `lock`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_lock(xs: *mut X509Store) -> c_int {
    // SAFETY: `xs` is live with a live lock per the contract.
    unsafe { CRYPTO_THREAD_write_lock((*xs).lock) }
}

/// `int ossl_x509_store_read_lock(X509_STORE *xs)` — `crypto/x509/x509_lu.c:47-50`.
///
/// Takes the store's read lock. The authority declares it in the internal `x509_local.h`, so it
/// carries no `#[no_mangle]` here (the DSO's version script hides the symbol).
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `lock`.
pub unsafe extern "C" fn ossl_x509_store_read_lock(xs: *mut X509Store) -> c_int {
    // SAFETY: `xs` is live with a live lock per the contract.
    unsafe { CRYPTO_THREAD_read_lock((*xs).lock) }
}

/// `int X509_STORE_unlock(X509_STORE *xs)` — `crypto/x509/x509_lu.c:52-55`.
///
/// Releases the store's lock.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `lock`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_unlock(xs: *mut X509Store) -> c_int {
    // SAFETY: `xs` is live with a live lock per the contract.
    unsafe { CRYPTO_THREAD_unlock((*xs).lock) }
}

/// `int X509_STORE_up_ref(X509_STORE *xs)` — `crypto/x509/x509_lu.c:256-266`.
///
/// Increments the store's reference count, answering 1 unless the count was zero.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_up_ref(xs: *mut X509Store) -> c_int {
    // SAFETY: `xs` is live per the contract.
    let i = unsafe { (*xs).references.wrapping_add(1) };
    // SAFETY: `xs` is live and writable.
    unsafe { (*xs).references = i };
    c_int::from(i > 1)
}

/// `X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *xs, X509_LOOKUP_METHOD *m)` —
/// `crypto/x509/x509_lu.c:268-295`.
///
/// Returns the store's existing instance of method `m`, or a new one bound to the store and pushed
/// onto it. A failed instance or push raises and answers NULL.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`; `m` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_add_lookup(
    xs: *mut X509Store,
    m: *mut X509LookupMethod,
) -> *mut X509Lookup {
    // SAFETY: `xs` is live per the contract.
    let sk = unsafe { (*xs).get_cert_methods };
    // SAFETY: `sk` is live; each element is a live lookup.
    let num = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..num {
        // SAFETY: `sk` is live and `i` is in range.
        let lu = unsafe { OPENSSL_sk_value(sk, i).cast::<X509Lookup>() };
        // SAFETY: `lu` is a live lookup.
        if unsafe { (*lu).method } == m {
            return lu;
        }
    }
    // SAFETY: `m` is live per the contract.
    let lu = unsafe { X509_LOOKUP_new(m) };
    if lu.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_284) };
        return ptr::null_mut();
    }
    // SAFETY: `lu` is this call's own live lookup; `xs` owns it now.
    unsafe { (*lu).store_ctx = xs };
    // SAFETY: `xs`'s stack is live; `lu` is the element to push.
    if unsafe { OPENSSL_sk_push(sk, lu.cast()) } != 0 {
        return lu;
    }
    // SAFETY: a compile-time-constant site.
    unsafe {
        raise_site(&X509_LU_292);
        X509_LOOKUP_free(lu);
    }
    ptr::null_mut()
}

/// `static int x509_store_add(X509_STORE *store, void *x, int crl)` —
/// `crypto/x509/x509_lu.c:386-427`.
///
/// Wraps `x` in a fresh `X509_OBJECT` (as a CRL when `crl` is non-zero), up-refs it, and inserts it
/// into the store's cache unless an identical object is already there. Answers whether the object
/// is present afterwards.
///
/// # Safety
///
/// `store` must be a live `X509_STORE`; `x` must be NULL or a live `X509`/`X509_CRL` matching
/// `crl`.
unsafe fn x509_store_add(store: *mut X509Store, x: *mut c_void, crl: c_int) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: neither call touches the caller's object.
    let obj = unsafe { X509_OBJECT_new() };
    if obj.is_null() {
        return 0;
    }
    // SAFETY: `obj` is this call's own fresh object.
    unsafe {
        if crl != 0 {
            (*obj).type_ = X509_LU_CRL;
            (*obj).data.crl = x.cast::<X509Crl>();
        } else {
            (*obj).type_ = X509_LU_X509;
            (*obj).data.x509 = x.cast::<X509>();
        }
    }
    // SAFETY: `obj` names the caller's live object.
    if unsafe { X509_OBJECT_up_ref_count(obj) } == 0 {
        // SAFETY: `obj` is this call's own object; tag it so the free does not release the
        // caller's object a second time.
        unsafe {
            (*obj).type_ = X509_LU_NONE;
            X509_OBJECT_free(obj);
        }
        return 0;
    }
    // SAFETY: `store` is live per the contract.
    if unsafe { X509_STORE_lock(store) } == 0 {
        // SAFETY: `obj` is this call's own object.
        unsafe { X509_OBJECT_free(obj) };
        return 0;
    }
    // SAFETY: `store` is locked and its cache is live; `obj` is the key.
    let matched = unsafe { X509_OBJECT_retrieve_match((*store).objs, obj) };
    let ret;
    let added;
    if !matched.is_null() {
        ret = 1;
        added = 0;
    } else {
        // SAFETY: `store`'s cache is live; `obj` is the element to push.
        added = unsafe { OPENSSL_sk_push((*store).objs, obj.cast()) };
        ret = c_int::from(added != 0);
    }
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };
    if added == 0 {
        // SAFETY: `obj` was not inserted, so this call still owns it.
        unsafe { X509_OBJECT_free(obj) };
    }
    ret
}

/// `int X509_STORE_add_cert(X509_STORE *xs, X509 *x)` — `crypto/x509/x509_lu.c:429-436`.
///
/// Adds (an up-referenced) certificate to the store's cache. Failure raises.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`; `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_add_cert(xs: *mut X509Store, x: *mut X509) -> c_int {
    // SAFETY: the contract forwards to `x509_store_add`.
    if unsafe { x509_store_add(xs, x.cast(), 0) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_432) };
        return 0;
    }
    1
}

/// `int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x)` — `crypto/x509/x509_lu.c:438-445`.
///
/// Adds (an up-referenced) CRL to the store's cache. Failure raises.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`; `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_add_crl(xs: *mut X509Store, x: *mut X509Crl) -> c_int {
    // SAFETY: the contract forwards to `x509_store_add`.
    if unsafe { x509_store_add(xs, x.cast(), 1) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_441) };
        return 0;
    }
    1
}

/// `STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:580-583`.
///
/// The store's object cache, borrowed.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get0_objects(xs: *const X509Store) -> *mut OpenSslStack {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).objs }
}

/// `STACK_OF(X509_OBJECT) *X509_STORE_get1_objects(X509_STORE *store)` —
/// `crypto/x509/x509_lu.c:602-618`.
///
/// A deep copy of the store's object cache, taken under the read lock. A NULL store raises.
///
/// # Safety
///
/// `store` must be NULL or a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get1_objects(store: *mut X509Store) -> *mut OpenSslStack {
    if store.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_607) };
        return ptr::null_mut();
    }
    // SAFETY: `store` is live per the contract.
    if unsafe { ossl_x509_store_read_lock(store) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `store` is locked; its cache and the two element handlers are live.
    let objs = unsafe {
        OPENSSL_sk_deep_copy(
            (*store).objs,
            Some(x509_object_dup_void),
            Some(x509_object_free_void),
        )
    };
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };
    objs
}

/// `STACK_OF(X509) *X509_STORE_get1_all_certs(X509_STORE *store)` —
/// `crypto/x509/x509_lu.c:620-652`.
///
/// A fresh, sorted stack of every certificate in the store's cache, each up-referenced. A NULL
/// store raises; any failure answers NULL after releasing the partial stack.
///
/// # Safety
///
/// `store` must be NULL or a live `X509_STORE`. The returned stack is the caller's to release.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get1_all_certs(store: *mut X509Store) -> *mut OpenSslStack {
    if store.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_LU_627) };
        return ptr::null_mut();
    }
    // SAFETY: the constructor touches no caller object.
    let sk = OPENSSL_sk_new_null();
    if sk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `store` is live per the contract.
    if unsafe { X509_STORE_lock(store) } == 0 {
        // SAFETY: `sk` is this call's own empty stack.
        unsafe { OPENSSL_sk_pop_free(sk, Some(x509_free_void)) };
        return ptr::null_mut();
    }
    // SAFETY: `store` is locked; its cache is live.
    unsafe { OPENSSL_sk_sort((*store).objs) };
    // SAFETY: `store` is live per the contract.
    let objs = unsafe { X509_STORE_get0_objects(store) };
    // SAFETY: `objs` is live; each element is a live object.
    let num = unsafe { OPENSSL_sk_num(objs) };
    for i in 0..num {
        // SAFETY: `objs` is live and `i` is in range.
        let cert = unsafe { X509_OBJECT_get0_X509(OPENSSL_sk_value(objs, i).cast::<X509Object>()) };
        if !cert.is_null() {
            // SAFETY: `sk` and `cert` are live; the flag up-refs the inserted certificate.
            if unsafe { X509_add_cert(sk, cert, X509_ADD_FLAG_UP_REF) } == 0 {
                // SAFETY: `store` is locked and `sk` is this call's own stack.
                unsafe {
                    X509_STORE_unlock(store);
                    OPENSSL_sk_pop_free(sk, Some(x509_free_void));
                }
                return ptr::null_mut();
            }
        }
    }
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };
    sk
}

/// `int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags)` —
/// `crypto/x509/x509_lu.c:783-786`.
///
/// Sets `flags` on the store's verify parameters, answering whether the setter accepted them.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `param`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_flags(xs: *mut X509Store, flags: c_ulong) -> c_int {
    // SAFETY: `xs` is live and `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_flags((*xs).param, flags) }
}

/// `int X509_STORE_set_depth(X509_STORE *xs, int depth)` — `crypto/x509/x509_lu.c:788-792`.
///
/// Sets `depth` on the store's verify parameters and answers 1 (the authority's setter returns
/// nothing, so success is unconditional).
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `param`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_depth(xs: *mut X509Store, depth: c_int) -> c_int {
    // SAFETY: `xs` is live and `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_depth((*xs).param, depth) };
    1
}

/// `int X509_STORE_set_purpose(X509_STORE *xs, int purpose)` — `crypto/x509/x509_lu.c:794-797`.
///
/// Sets `purpose` on the store's verify parameters, answering whether it is a known purpose.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `param`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_purpose(xs: *mut X509Store, purpose: c_int) -> c_int {
    // SAFETY: `xs` is live and `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_purpose((*xs).param, purpose) }
}

/// `int X509_STORE_set_trust(X509_STORE *xs, int trust)` — `crypto/x509/x509_lu.c:799-802`.
///
/// Sets `trust` on the store's verify parameters, answering whether it is a known trust id.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `param`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_trust(xs: *mut X509Store, trust: c_int) -> c_int {
    // SAFETY: `xs` is live and `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_trust((*xs).param, trust) }
}

/// `int X509_STORE_set1_param(X509_STORE *xs, const X509_VERIFY_PARAM *param)` —
/// `crypto/x509/x509_lu.c:804-807`.
///
/// Copies `param` into the store's own verify parameters, answering whether the copy succeeded.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE` with a live `param`; `param` must be a live
/// `X509_VERIFY_PARAM`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set1_param(
    xs: *mut X509Store,
    param: *const X509VerifyParam,
) -> c_int {
    // SAFETY: `xs` is live and `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set1((*xs).param, param) }
}

/// `X509_VERIFY_PARAM *X509_STORE_get0_param(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:809-812`.
///
/// The store's verify parameters, borrowed.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get0_param(xs: *const X509Store) -> *mut X509VerifyParam {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).param }
}

/// `int X509_STORE_set_ex_data(X509_STORE *xs, int idx, void *data)` —
/// `crypto/x509/x509_lu.c:945-948`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`; `data` is stored verbatim.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_ex_data(
    xs: *mut X509Store,
    idx: c_int,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { CRYPTO_set_ex_data(&raw mut (*xs).ex_data, idx, data) }
}

/// `void *X509_STORE_get_ex_data(const X509_STORE *xs, int idx)` —
/// `crypto/x509/x509_lu.c:950-953`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_ex_data(xs: *const X509Store, idx: c_int) -> *mut c_void {
    // SAFETY: `xs` is live per the contract.
    unsafe { CRYPTO_get_ex_data(&raw const (*xs).ex_data, idx) }
}

// ---------------------------------------------------------------------------------------------
// The store callback accessors — `crypto/x509/x509_lu.c:814-943`.
// ---------------------------------------------------------------------------------------------

/// `void X509_STORE_set_verify(X509_STORE *xs, X509_STORE_CTX_verify_fn verify)` —
/// `crypto/x509/x509_lu.c:814-817`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`; `verify` is the callback contract's.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_verify(
    xs: *mut X509Store,
    verify: X509_STORE_CTX_verify_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).verify = verify };
}

/// `X509_STORE_CTX_verify_fn X509_STORE_get_verify(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:819-822`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_verify(xs: *const X509Store) -> X509_STORE_CTX_verify_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).verify }
}

/// `void X509_STORE_set_verify_cb(X509_STORE *xs, X509_STORE_CTX_verify_cb verify_cb)` —
/// `crypto/x509/x509_lu.c:824-828`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_verify_cb(
    xs: *mut X509Store,
    verify_cb: X509_STORE_CTX_verify_cb,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).verify_cb = verify_cb };
}

/// `X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:830-833`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_verify_cb(
    xs: *const X509Store,
) -> X509_STORE_CTX_verify_cb {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).verify_cb }
}

/// `void X509_STORE_set_get_issuer(X509_STORE *xs, X509_STORE_CTX_get_issuer_fn get_issuer)` —
/// `crypto/x509/x509_lu.c:835-839`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_get_issuer(
    xs: *mut X509Store,
    get_issuer: X509_STORE_CTX_get_issuer_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).get_issuer = get_issuer };
}

/// `X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:841-844`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_get_issuer(
    xs: *const X509Store,
) -> X509_STORE_CTX_get_issuer_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).get_issuer }
}

/// `void X509_STORE_set_check_issued(X509_STORE *xs, X509_STORE_CTX_check_issued_fn
/// check_issued)` — `crypto/x509/x509_lu.c:846-850`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_check_issued(
    xs: *mut X509Store,
    check_issued: X509_STORE_CTX_check_issued_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).check_issued = check_issued };
}

/// `X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:852-855`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_check_issued(
    xs: *const X509Store,
) -> X509_STORE_CTX_check_issued_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).check_issued }
}

/// `void X509_STORE_set_check_revocation(X509_STORE *xs, X509_STORE_CTX_check_revocation_fn cb)` —
/// `crypto/x509/x509_lu.c:857-861`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_check_revocation(
    xs: *mut X509Store,
    cb: X509_STORE_CTX_check_revocation_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).check_revocation = cb };
}

/// `X509_STORE_CTX_check_revocation_fn X509_STORE_get_check_revocation(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:863-866`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_check_revocation(
    xs: *const X509Store,
) -> X509_STORE_CTX_check_revocation_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).check_revocation }
}

/// `void X509_STORE_set_get_crl(X509_STORE *xs, X509_STORE_CTX_get_crl_fn get_crl)` —
/// `crypto/x509/x509_lu.c:868-872`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_get_crl(
    xs: *mut X509Store,
    get_crl: X509_STORE_CTX_get_crl_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).get_crl = get_crl };
}

/// `X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:874-877`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_get_crl(xs: *const X509Store) -> X509_STORE_CTX_get_crl_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).get_crl }
}

/// `void X509_STORE_set_check_crl(X509_STORE *xs, X509_STORE_CTX_check_crl_fn check_crl)` —
/// `crypto/x509/x509_lu.c:879-883`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_check_crl(
    xs: *mut X509Store,
    check_crl: X509_STORE_CTX_check_crl_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).check_crl = check_crl };
}

/// `X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:885-888`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_check_crl(
    xs: *const X509Store,
) -> X509_STORE_CTX_check_crl_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).check_crl }
}

/// `void X509_STORE_set_cert_crl(X509_STORE *xs, X509_STORE_CTX_cert_crl_fn cert_crl)` —
/// `crypto/x509/x509_lu.c:890-894`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_cert_crl(
    xs: *mut X509Store,
    cert_crl: X509_STORE_CTX_cert_crl_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).cert_crl = cert_crl };
}

/// `X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:896-899`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_cert_crl(
    xs: *const X509Store,
) -> X509_STORE_CTX_cert_crl_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).cert_crl }
}

/// `void X509_STORE_set_check_policy(X509_STORE *xs, X509_STORE_CTX_check_policy_fn
/// check_policy)` — `crypto/x509/x509_lu.c:901-905`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_check_policy(
    xs: *mut X509Store,
    check_policy: X509_STORE_CTX_check_policy_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).check_policy = check_policy };
}

/// `X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:907-910`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_check_policy(
    xs: *const X509Store,
) -> X509_STORE_CTX_check_policy_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).check_policy }
}

/// `void X509_STORE_set_lookup_certs(X509_STORE *xs, X509_STORE_CTX_lookup_certs_fn
/// lookup_certs)` — `crypto/x509/x509_lu.c:912-916`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_lookup_certs(
    xs: *mut X509Store,
    lookup_certs: X509_STORE_CTX_lookup_certs_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).lookup_certs = lookup_certs };
}

/// `X509_STORE_CTX_lookup_certs_fn X509_STORE_get_lookup_certs(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:918-921`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_lookup_certs(
    xs: *const X509Store,
) -> X509_STORE_CTX_lookup_certs_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).lookup_certs }
}

/// `void X509_STORE_set_lookup_crls(X509_STORE *xs, X509_STORE_CTX_lookup_crls_fn lookup_crls)` —
/// `crypto/x509/x509_lu.c:923-927`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_lookup_crls(
    xs: *mut X509Store,
    lookup_crls: X509_STORE_CTX_lookup_crls_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).lookup_crls = lookup_crls };
}

/// `X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:929-932`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_lookup_crls(
    xs: *const X509Store,
) -> X509_STORE_CTX_lookup_crls_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).lookup_crls }
}

/// `void X509_STORE_set_cleanup(X509_STORE *xs, X509_STORE_CTX_cleanup_fn cleanup)` —
/// `crypto/x509/x509_lu.c:934-938`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_set_cleanup(
    xs: *mut X509Store,
    cleanup: X509_STORE_CTX_cleanup_fn,
) {
    // SAFETY: `xs` is live and writable per the contract.
    unsafe { (*xs).cleanup = cleanup };
}

/// `X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(const X509_STORE *xs)` —
/// `crypto/x509/x509_lu.c:940-943`.
///
/// # Safety
///
/// `xs` must be a live `X509_STORE`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_get_cleanup(xs: *const X509Store) -> X509_STORE_CTX_cleanup_fn {
    // SAFETY: `xs` is live per the contract.
    unsafe { (*xs).cleanup }
}

// ---------------------------------------------------------------------------------------------
// The X509_STORE_CTX read path — `crypto/x509/x509_lu.c:298-384`, `:658-752`, `:955-958`.
// The read path only reads `ctx->store`/`ctx->libctx`/`ctx->propq`, so it lands once the
// `X509StoreCtx` layout above exists; the context's lifecycle and verify roll are 11.2's.
// ---------------------------------------------------------------------------------------------

/// `X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *ctx, X509_LOOKUP_TYPE type,
/// const X509_NAME *name)` — `crypto/x509/x509_lu.c:298-311`.
///
/// A fresh `X509_OBJECT` filled by [`X509_STORE_CTX_get_by_subject`], or NULL when the lookup
/// fails (the object is then released).
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE_CTX`; `name` must be a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_obj_by_subject(
    ctx: *mut X509StoreCtx,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
) -> *mut X509Object {
    // SAFETY: the constructor touches no caller object.
    let ret = unsafe { X509_OBJECT_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live per the contract; `ret` is this call's own object.
    if unsafe { X509_STORE_CTX_get_by_subject(ctx, type_, name, ret) } == 0 {
        // SAFETY: `ret` is this call's own object.
        unsafe { X509_OBJECT_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `int ossl_x509_store_ctx_get_by_subject(const X509_STORE_CTX *ctx, X509_LOOKUP_TYPE type,
/// const X509_NAME *name, X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:320-376`.
///
/// Resolves `name` through the store's object cache, then — for a miss, or for any CRL request —
/// through the registered lookup methods, caching new hits. Answers 1 on success, 0 when not
/// found, and -1 on failure. May be called with `ret` NULL purely for the caching side effect.
///
/// The authority declares it in the internal `crypto/x509.h`, so it carries no `#[no_mangle]` here
/// (the DSO's version script hides the symbol).
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE_CTX`; `name` must be a live `X509_NAME`; `ret` NULL or
/// writable.
pub unsafe extern "C" fn ossl_x509_store_ctx_get_by_subject(
    ctx: *const X509StoreCtx,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let store = unsafe { (*ctx).store };
    if store.is_null() {
        return 0;
    }

    // The stack-local probe the authority calls `stmp`; only `type` and its union tag are read by
    // the comparator, so nothing else is initialised.
    let mut stmp = X509Object {
        type_: X509_LU_NONE,
        data: X509ObjectData {
            x509: ptr::null_mut(),
        },
    };

    // SAFETY: `store` is live per the contract, with a live lock.
    if unsafe { ossl_x509_store_read_lock(store) } == 0 {
        return 0;
    }
    // SAFETY: `store` is read-locked; its cache is live.
    if unsafe { OPENSSL_sk_is_sorted((*store).objs) } == 0 {
        // SAFETY: `store` is locked as above.
        unsafe { X509_STORE_unlock(store) };
        // Take a write lock instead of a read lock.
        // SAFETY: `store` is live per the contract.
        if unsafe { X509_STORE_lock(store) } == 0 {
            return 0;
        }
        // SAFETY: `store` is write-locked; its cache is live and unsorted (sort exits early when
        // another thread sorted it first).
        unsafe { OPENSSL_sk_sort((*store).objs) };
    }
    // SAFETY: `store` is locked; `name` is live per the contract.
    let mut tmp = unsafe { X509_OBJECT_retrieve_by_subject((*store).objs, type_, name) };
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };

    if tmp.is_null() || type_ == X509_LU_CRL {
        // SAFETY: `store` is live per the contract.
        let methods = unsafe { (*store).get_cert_methods };
        // SAFETY: `methods` is live; each element is a live lookup.
        let num = unsafe { OPENSSL_sk_num(methods) };
        for i in 0..num {
            // SAFETY: `methods` is live and `i` is in range.
            let lu = unsafe { OPENSSL_sk_value(methods, i).cast::<X509Lookup>() };
            // SAFETY: `lu` is a live lookup; `stmp` is this call's own key object; `ctx`'s libctx
            // and propq are the caller's.
            unsafe {
                if (*lu).skip != 0 {
                    continue;
                }
                if (*lu).method.is_null() {
                    return -1;
                }
                let j = X509_LOOKUP_by_subject_ex(
                    lu,
                    type_,
                    name,
                    &raw mut stmp,
                    (*ctx).libctx,
                    (*ctx).propq,
                );
                if j != 0 {
                    tmp = &raw mut stmp;
                    break;
                }
            }
        }
        if tmp.is_null() {
            return 0;
        }
    }

    if !ret.is_null() {
        // SAFETY: `tmp` is a live object (the cached one or `stmp`).
        if unsafe { X509_OBJECT_up_ref_count(tmp) } == 0 {
            return -1;
        }
        // SAFETY: `ret` is writable per the contract; `tmp` is live.
        unsafe {
            (*ret).type_ = (*tmp).type_;
            (*ret).data = (*tmp).data;
        }
    }
    1
}

/// `int X509_STORE_CTX_get_by_subject(const X509_STORE_CTX *ctx, X509_LOOKUP_TYPE type, const
/// X509_NAME *name, X509_OBJECT *ret)` — `crypto/x509/x509_lu.c:379-384`.
///
/// [`ossl_x509_store_ctx_get_by_subject`] flattened to a boolean: 1 for its 1, 0 for its 0 or -1.
///
/// # Safety
///
/// As [`ossl_x509_store_ctx_get_by_subject`].
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_by_subject(
    ctx: *const X509StoreCtx,
    type_: X509_LOOKUP_TYPE,
    name: *const X509Name,
    ret: *mut X509Object,
) -> c_int {
    // SAFETY: the contract forwards to `ossl_x509_store_ctx_get_by_subject`.
    c_int::from(unsafe { ossl_x509_store_ctx_get_by_subject(ctx, type_, name, ret) } > 0)
}

/// `STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *ctx, const X509_NAME *nm)` —
/// `crypto/x509/x509_lu.c:658-705`.
///
/// Every certificate in the store whose subject matches `nm`, each up-referenced. A store-less
/// context answers an empty stack; an internal error answers NULL.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE_CTX`; `nm` must be a live `X509_NAME`. The returned stack is
/// the caller's to release (its elements carry a reference each).
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get1_certs(
    ctx: *mut X509StoreCtx,
    nm: *const X509Name,
) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    let store = unsafe { (*ctx).store };
    if store.is_null() {
        return OPENSSL_sk_new_null();
    }

    // SAFETY: `store` is live per the contract, with a live lock.
    if unsafe { X509_STORE_lock(store) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `store` is write-locked; its cache is live.
    unsafe { OPENSSL_sk_sort((*store).objs) };
    let mut cnt: c_int = 0;
    // SAFETY: `store` is locked; `nm` is live per the contract.
    let mut idx = unsafe { x509_object_idx_cnt((*store).objs, X509_LU_X509, nm, &raw mut cnt) };
    if idx < 0 {
        // Nothing found in cache: do lookup to possibly add new objects to cache.
        // SAFETY: `store` is locked as above.
        unsafe { X509_STORE_unlock(store) };
        // SAFETY: `ctx` is live per the contract.
        let i =
            unsafe { ossl_x509_store_ctx_get_by_subject(ctx, X509_LU_X509, nm, ptr::null_mut()) };
        if i <= 0 {
            if i < 0 {
                return ptr::null_mut();
            }
            return OPENSSL_sk_new_null();
        }
        // SAFETY: `store` is live per the contract.
        if unsafe { X509_STORE_lock(store) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: `store` is write-locked; its cache is live.
        unsafe { OPENSSL_sk_sort((*store).objs) };
        // SAFETY: `store` is locked; `nm` is live.
        idx = unsafe { x509_object_idx_cnt((*store).objs, X509_LU_X509, nm, &raw mut cnt) };
    }

    // A fresh empty stack for the matches.
    let sk = OPENSSL_sk_new_null();
    if idx < 0 || sk.is_null() {
        // SAFETY: `store` is locked per the above.
        unsafe { X509_STORE_unlock(store) };
        return sk;
    }
    let mut i = 0;
    while i < cnt {
        // SAFETY: `store` is locked and `idx` is in range.
        let obj = unsafe { OPENSSL_sk_value((*store).objs, idx).cast::<X509Object>() };
        // SAFETY: `obj` is a live object tagged `X509_LU_X509`.
        let x = unsafe { (*obj).data.x509 };
        // SAFETY: `sk` and `x` are live; the flag up-refs the inserted certificate.
        if unsafe { X509_add_cert(sk, x, X509_ADD_FLAG_UP_REF) } == 0 {
            // SAFETY: `store` is locked; `sk` is this call's own stack.
            unsafe {
                X509_STORE_unlock(store);
                OPENSSL_sk_pop_free(sk, Some(x509_free_void));
            }
            return ptr::null_mut();
        }
        i += 1;
        idx += 1;
    }
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };
    sk
}

/// `STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(const X509_STORE_CTX *ctx, const X509_NAME
/// *nm)` — `crypto/x509/x509_lu.c:708-752`.
///
/// Every CRL in the store whose issuer matches `nm`, each up-referenced. A lookup miss answers an
/// empty stack; an internal error answers NULL.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE_CTX`; `nm` must be a live `X509_NAME`. The returned stack is
/// the caller's to release (its elements carry a reference each).
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get1_crls(
    ctx: *const X509StoreCtx,
    nm: *const X509Name,
) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    let store = unsafe { (*ctx).store };
    // Always do lookup to possibly add new CRLs to cache.
    // SAFETY: `ctx` is live per the contract.
    let mut i =
        unsafe { ossl_x509_store_ctx_get_by_subject(ctx, X509_LU_CRL, nm, ptr::null_mut()) };
    if i < 0 {
        return ptr::null_mut();
    }
    // A fresh empty stack for the matches.
    let sk = OPENSSL_sk_new_null();
    if i == 0 {
        return sk;
    }
    // A found CRL implies a non-NULL store (see `ossl_x509_store_ctx_get_by_subject`), but keep
    // the lock's own failure branch exactly as the authority has it.
    // SAFETY: `store` is live per the contract, with a live lock.
    if unsafe { X509_STORE_lock(store) } == 0 {
        // SAFETY: `sk` is this call's own empty stack.
        unsafe { OPENSSL_sk_free(sk) };
        return ptr::null_mut();
    }
    // SAFETY: `store` is write-locked; its cache is live.
    unsafe { OPENSSL_sk_sort((*store).objs) };
    let mut cnt: c_int = 0;
    // SAFETY: `store` is locked; `nm` is live per the contract.
    let mut idx = unsafe { x509_object_idx_cnt((*store).objs, X509_LU_CRL, nm, &raw mut cnt) };
    if idx < 0 {
        // SAFETY: `store` is locked as above.
        unsafe { X509_STORE_unlock(store) };
        return sk;
    }
    i = 0;
    while i < cnt {
        // SAFETY: `store` is locked and `idx` is in range.
        let obj = unsafe { OPENSSL_sk_value((*store).objs, idx).cast::<X509Object>() };
        // SAFETY: `obj` is a live object tagged `X509_LU_CRL`.
        let x = unsafe { (*obj).data.crl };
        // SAFETY: `x` is a live CRL.
        if unsafe { X509_CRL_up_ref(x) } == 0 {
            // SAFETY: `store` is locked; `sk` is this call's own stack.
            unsafe {
                X509_STORE_unlock(store);
                OPENSSL_sk_pop_free(sk, Some(x509_crl_free_void));
            }
            return ptr::null_mut();
        }
        // SAFETY: `sk` is live; `x` now carries the extra reference the push transfers.
        if unsafe { OPENSSL_sk_push(sk, x.cast()) } == 0 {
            // SAFETY: `x` carries a reference this call must drop; `sk` is this call's own stack.
            unsafe {
                X509_STORE_unlock(store);
                X509_CRL_free(x);
                OPENSSL_sk_pop_free(sk, Some(x509_crl_free_void));
            }
            return ptr::null_mut();
        }
        i += 1;
        idx += 1;
    }
    // SAFETY: `store` is locked per the above.
    unsafe { X509_STORE_unlock(store) };
    sk
}

/// `X509_STORE *X509_STORE_CTX_get0_store(const X509_STORE_CTX *ctx)` —
/// `crypto/x509/x509_lu.c:955-958`.
///
/// # Safety
///
/// `ctx` must be a live `X509_STORE_CTX`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_store(ctx: *const X509StoreCtx) -> *mut X509Store {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).store }
}
