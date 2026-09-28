//! Phase 10 (10.5) — the `crypto/store/` subsystem: its loader object, its registry, its
//! strings, and its `OSSL_STORE_CTX` state machine and `OSSL_STORE_INFO`/
//! `OSSL_STORE_SEARCH` object model.
//!
//! This module is the crate's home for `crypto/store/`, and the ledger
//! (`forensics/phase10-obligations.json`) maps all seventy-six `store.h` exports of the
//! stratum to `src/store/mod.rs`. **All four export-bearing units are landable, and the
//! whole 76 is measured per function rather than per unit** — 10.16 published the two
//! `OSSL_OP_STORE` provider rows (`file_store.c`) and left only [`store_lib`]'s
//! `OSSL_STORE_load` open.
//!
//! # What landed, unit by unit
//!
//! * [`store_strings`] — `store_strings.c` (31 lines, one export,
//!   [`store_strings::OSSL_STORE_INFO_type_string`]).
//! * [`store_register`] — `store_register.c` (302 lines, sixteen exports): the legacy
//!   `OSSL_STORE_LOADER` object's constructor and accessors, the setters, and the
//!   process-global scheme registry (`OSSL_STORE_register_loader`/`_unregister_loader`/
//!   `OSSL_STORE_do_all_loaders`).
//! * [`store_meth`] — `store_meth.c` (511 lines, ten exports): the provider-side loader
//!   method object, the `OSSL_OP_STORE` dispatch scan, the fetch machinery over the
//!   store-loader method store (slot 15) and the by-name accessors.
//! * [`store_lib`] — `store_lib.c` (1,102 lines, forty-nine exports): the
//!   `OSSL_STORE_CTX` state machine (`open`/`open_ex`/`eof`/`error`/`expect`/`close`/
//!   `attach`/`delete`/`supports_search`/`find` and the two deprecated control entry
//!   points) and the `OSSL_STORE_INFO`/`OSSL_STORE_SEARCH` object model. Forty-six of
//!   the 49 land; see that module's doc for the three withheld with their measured
//!   blockers and the two carved arms.
//!
//! # What is withheld, and its measured blocker
//!
//! * **Three `store_lib.c` exports** — `OSSL_STORE_load` (its fetched branch
//!   calls `store_result.c`'s `ossl_store_handle_load_result`, whose closure reaches
//!   `d2i_X509`/`d2i_X509_AUX`/`d2i_X509_CRL` and `PKCS12_parse`),
//!   `OSSL_STORE_INFO_get1_CERT` (`X509_up_ref`) and
//!   `OSSL_STORE_INFO_get1_CRL` (`X509_CRL_up_ref`). Two arms inside
//!   functions that otherwise land are carved: `OSSL_STORE_INFO_free`'s CERT/CRL arms
//!   (`X509_free`/`X509_CRL_free`) and `OSSL_STORE_find`'s BY_NAME/BY_ISSUER_SERIAL arms
//!   (`i2d_X509_NAME`). Every one of those names is Phase 11's `X509` object graph, except
//!   `ossl_store_handle_load_result`'s `PKCS12_parse` arm, which 10.3 withholds.
//!   `docs/PHASE-10-SUBPHASES.md` section 4.2 records the same finding for the PKCS#12 unit:
//!   `X509_it` is Phase 11's.
//! * **The two `OSSL_OP_STORE` provider rows** (`forensics/atlas/provider-algorithms.json`:
//!   `default` and `base`, `algorithm_names` `file`, dispatch `ossl_file_store_functions`).
//!   **10.16 publishes them**: [`crate::provider::file_store`] transcribes `file_store.c` (and
//!   its private last-resort decoder `file_store_any2obj.c`), and `deflt_query`/`base_query`
//!   answer `DEFLT_STORES`/`BASE_STORES` on `OSSL_OP_STORE` (22). The row resolves through its
//!   open/attach/load/eof/close callbacks, so `OSSL_STORE_LOADER_fetch`/`do_all_provided` and
//!   the fetched `OSSL_STORE_find` arms are called by `RT-STORE` rather than reference-taken.
//!   The engine's *result* path — [`store_lib::OSSL_STORE_load`] through `store_result.c`'s
//!   `ossl_store_handle_load_result` — stays withheld on `PKCS12_parse`, which is the same
//!   Phase 11 blocker; a loader that opens, loads and closes is not a result handler.
//!
//! # The loader object, and where each field comes from
//!
//! [`OsslStoreLoader`] is `store_local.h:82-118`'s `struct ossl_store_loader_st`: the
//! deprecated legacy callback set (present because this crate's profile has
//! `OPENSSL_NO_DEPRECATED_3_0` unset), the provider attachment, the scheme name-map id, the
//! property definition and description (borrowed from the provider's own algorithm
//! definition), a reference count and the ten provider callbacks
//! (`OSSL_FUNC_STORE_{OPEN,ATTACH,SETTABLE_CTX_PARAMS,SET_CTX_PARAMS,LOAD,EOF,CLOSE,
//! EXPORT_OBJECT,DELETE,OPEN_EX}` — `include/openssl/core_dispatch.h:1025-1034`).
//!
//! The legacy `ctrl` callback is typed as [`OsslStoreCtrlFn`] whose third argument is an opaque
//! `*mut c_void`: the authority's `OSSL_STORE_ctrl_fn` takes a C `va_list`, and a `va_list`
//! cannot cross into Rust (the crate's `runtime/err_variadic.c` exists for the same reason).
//! The prototype court canonicalises a `va_list` as an opaque pointer, so this spelling is the
//! one it reads. The field is called by [`store_lib`]'s `OSSL_STORE_vctrl` (through
//! `openssl_rs_store_vctrl`), whose only `va_arg` walk is the `OSSL_STORE_C_USE_SECMEM`
//! `int *`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::AtomicI32;

use crate::params::OsslParam;
use crate::provider::OsslProvider;

pub(crate) mod store_lib;
pub(crate) mod store_meth;
pub(crate) mod store_register;
pub(crate) mod store_strings;

// ---------------------------------------------------------------------------
// The public `OSSL_STORE_INFO_*` type numbers — `include/openssl/store.h:157-162`
// ---------------------------------------------------------------------------

/// `#define OSSL_STORE_INFO_NAME 1` — `store.h:157`.
pub const OSSL_STORE_INFO_NAME: c_int = 1;
/// `#define OSSL_STORE_INFO_PARAMS 2` — `store.h:158`.
pub const OSSL_STORE_INFO_PARAMS: c_int = 2;
/// `#define OSSL_STORE_INFO_PUBKEY 3` — `store.h:159`.
pub const OSSL_STORE_INFO_PUBKEY: c_int = 3;
/// `#define OSSL_STORE_INFO_PKEY 4` — `store.h:160`.
pub const OSSL_STORE_INFO_PKEY: c_int = 4;
/// `#define OSSL_STORE_INFO_CERT 5` — `store.h:161`.
pub const OSSL_STORE_INFO_CERT: c_int = 5;
/// `#define OSSL_STORE_INFO_CRL 6` — `store.h:162`.
pub const OSSL_STORE_INFO_CRL: c_int = 6;

// ---------------------------------------------------------------------------
// The `OSSL_FUNC_STORE_*` identities — `include/openssl/core_dispatch.h:1025-1034`
// ---------------------------------------------------------------------------

/// `#define OSSL_FUNC_STORE_OPEN 1` — `core_dispatch.h:1025`.
pub(crate) const OSSL_FUNC_STORE_OPEN: c_int = 1;
/// `#define OSSL_FUNC_STORE_ATTACH 2` — `core_dispatch.h:1026`.
pub(crate) const OSSL_FUNC_STORE_ATTACH: c_int = 2;
/// `#define OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS 3` — `core_dispatch.h:1027`.
pub(crate) const OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS: c_int = 3;
/// `#define OSSL_FUNC_STORE_SET_CTX_PARAMS 4` — `core_dispatch.h:1028`.
pub(crate) const OSSL_FUNC_STORE_SET_CTX_PARAMS: c_int = 4;
/// `#define OSSL_FUNC_STORE_LOAD 5` — `core_dispatch.h:1029`.
pub(crate) const OSSL_FUNC_STORE_LOAD: c_int = 5;
/// `#define OSSL_FUNC_STORE_EOF 6` — `core_dispatch.h:1030`.
pub(crate) const OSSL_FUNC_STORE_EOF: c_int = 6;
/// `#define OSSL_FUNC_STORE_CLOSE 7` — `core_dispatch.h:1031`.
pub(crate) const OSSL_FUNC_STORE_CLOSE: c_int = 7;
/// `#define OSSL_FUNC_STORE_EXPORT_OBJECT 8` — `core_dispatch.h:1032`.
pub(crate) const OSSL_FUNC_STORE_EXPORT_OBJECT: c_int = 8;
/// `#define OSSL_FUNC_STORE_DELETE 9` — `core_dispatch.h:1033`.
pub(crate) const OSSL_FUNC_STORE_DELETE: c_int = 9;
/// `#define OSSL_FUNC_STORE_OPEN_EX 10` — `core_dispatch.h:1034`.
pub(crate) const OSSL_FUNC_STORE_OPEN_EX: c_int = 10;

// ---------------------------------------------------------------------------
// `typedef struct ossl_store_loader_ctx_st OSSL_STORE_LOADER_CTX` — `store.h:296`
// ---------------------------------------------------------------------------

/// `typedef struct ossl_store_loader_ctx_st OSSL_STORE_LOADER_CTX` — `store.h:296`.
///
/// The type is defined differently by each loader (`store_local.h:124`), so the crate only
/// ever carries a pointer to one. It is an uninhabited marker rather than `c_void` so the
/// legacy callback typedefs below can name it.
pub(crate) enum OsslStoreLoaderCtx {}

/// `typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_fn)(const OSSL_STORE_LOADER *loader,
/// const char *uri, const UI_METHOD *ui_method, void *ui_data)` — `store.h:297-298`.
pub(crate) type OsslStoreOpenFn = unsafe extern "C" fn(
    *const OsslStoreLoader,
    *const c_char,
    *const c_void,
    *mut c_void,
) -> *mut OsslStoreLoaderCtx;
/// `typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_open_ex_fn)(const OSSL_STORE_LOADER *loader,
/// const char *uri, OSSL_LIB_CTX *libctx, const char *propq, const UI_METHOD *ui_method,
/// void *ui_data)` — `store.h:299-301`.
pub(crate) type OsslStoreOpenExFn = unsafe extern "C" fn(
    *const OsslStoreLoader,
    *const c_char,
    *mut c_void,
    *const c_char,
    *const c_void,
    *mut c_void,
) -> *mut OsslStoreLoaderCtx;
/// `typedef OSSL_STORE_LOADER_CTX *(*OSSL_STORE_attach_fn)(const OSSL_STORE_LOADER *loader,
/// BIO *bio, OSSL_LIB_CTX *libctx, const char *propq, const UI_METHOD *ui_method,
/// void *ui_data)` — `store.h:303-305`.
pub(crate) type OsslStoreAttachFn = unsafe extern "C" fn(
    *const OsslStoreLoader,
    *mut c_void,
    *mut c_void,
    *const c_char,
    *const c_void,
    *mut c_void,
) -> *mut OsslStoreLoaderCtx;
/// `typedef int (*OSSL_STORE_ctrl_fn)(OSSL_STORE_LOADER_CTX *ctx, int cmd, va_list args)` —
/// `store.h:306`.
///
/// The C `va_list` is canonicalised by the prototype court as an opaque pointer, and the crate
/// has no `va_list` type (a `va_list` cannot cross into Rust; `runtime/err_variadic.c` exists for
/// that reason), so the third argument is spelled `*mut c_void`. `store_lib.c`'s `OSSL_STORE_vctrl`
/// is the only caller, and it forwards the list exactly as the authority does.
pub(crate) type OsslStoreCtrlFn =
    unsafe extern "C" fn(*mut OsslStoreLoaderCtx, c_int, *mut c_void) -> c_int;
/// `typedef int (*OSSL_STORE_expect_fn)(OSSL_STORE_LOADER_CTX *ctx, int expected)` —
/// `store.h:307`.
pub(crate) type OsslStoreExpectFn = unsafe extern "C" fn(*mut OsslStoreLoaderCtx, c_int) -> c_int;
/// `typedef int (*OSSL_STORE_find_fn)(OSSL_STORE_LOADER_CTX *ctx,
/// const OSSL_STORE_SEARCH *criteria)` — `store.h:308`.
pub(crate) type OsslStoreFindFn =
    unsafe extern "C" fn(*mut OsslStoreLoaderCtx, *const c_void) -> c_int;
/// `typedef OSSL_STORE_INFO *(*OSSL_STORE_load_fn)(OSSL_STORE_LOADER_CTX *ctx,
/// const UI_METHOD *ui_method, void *ui_data)` — `store.h:309`.
pub(crate) type OsslStoreLoadFn =
    unsafe extern "C" fn(*mut OsslStoreLoaderCtx, *const c_void, *mut c_void) -> *mut c_void;
/// `typedef int (*OSSL_STORE_eof_fn)(OSSL_STORE_LOADER_CTX *ctx)` — `store.h:310`.
pub(crate) type OsslStoreEofFn = unsafe extern "C" fn(*mut OsslStoreLoaderCtx) -> c_int;
/// `typedef int (*OSSL_STORE_error_fn)(OSSL_STORE_LOADER_CTX *ctx)` — `store.h:311`.
pub(crate) type OsslStoreErrorFn = unsafe extern "C" fn(*mut OsslStoreLoaderCtx) -> c_int;
/// `typedef int (*OSSL_STORE_close_fn)(OSSL_STORE_LOADER_CTX *ctx)` — `store.h:312`.
pub(crate) type OsslStoreCloseFn = unsafe extern "C" fn(*mut OsslStoreLoaderCtx) -> c_int;

// ---------------------------------------------------------------------------
// The provider callbacks — `core_dispatch.h`'s `OSSL_CORE_MAKE_FUNC` block
// ---------------------------------------------------------------------------

/// `OSSL_FUNC_store_open_fn` — `core_dispatch.h:1035`.
pub(crate) type StorePOpenFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
/// `OSSL_FUNC_store_attach_fn` — `core_dispatch.h:1036`.
pub(crate) type StorePAttachFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
/// `OSSL_FUNC_store_settable_ctx_params_fn` — `core_dispatch.h:1037-1038`.
pub(crate) type StorePSettableCtxParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_store_set_ctx_params_fn` — `core_dispatch.h:1039-1040`.
pub(crate) type StorePSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_store_load_fn` — `core_dispatch.h:1041-1044`.
///
/// `object_cb` and `pw_cb` are the authority's `OSSL_CALLBACK` and `OSSL_PASSPHRASE_CALLBACK`,
/// whose types this crate names; a nullable function pointer is `Option<...>`.
pub(crate) type StorePLoadFn = unsafe extern "C" fn(
    *mut c_void,
    Option<crate::selftest::OsslCallback>,
    *mut c_void,
    Option<crate::passphrase::OsslPassphraseCallback>,
    *mut c_void,
) -> c_int;
/// `OSSL_FUNC_store_eof_fn` — `core_dispatch.h:1045`.
pub(crate) type StorePEofFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_store_close_fn` — `core_dispatch.h:1046`.
pub(crate) type StorePCloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_store_export_object_fn` — `core_dispatch.h:1047-1049`.
pub(crate) type StorePExportObjectFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_void,
    usize,
    Option<crate::selftest::OsslCallback>,
    *mut c_void,
) -> c_int;
/// `OSSL_FUNC_store_delete_fn` — `core_dispatch.h:1050-1052`.
pub(crate) type StorePDeleteFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *const OsslParam,
    Option<crate::passphrase::OsslPassphraseCallback>,
    *mut c_void,
) -> c_int;
/// `OSSL_FUNC_store_open_ex_fn` — `core_dispatch.h:1053-1055`.
pub(crate) type StorePOpenExFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *const OsslParam,
    Option<crate::passphrase::OsslPassphraseCallback>,
    *mut c_void,
) -> *mut c_void;

/// `struct ossl_store_loader_st` — `store_local.h:82-117`.
///
/// One field per legacy callback and one per `<OSSL_FUNC_STORE_*>` entry
/// `loader_from_algorithm` may find. The provider callbacks are `Option`s because a table
/// need not supply them, and `None` is the authority's NULL. `scheme`, `propdef` and
/// `description` are **borrowed**, never freed by `OSSL_STORE_LOADER_free`: the legacy
/// `scheme` is the caller's constant string (`store_meth.c:42-45`), and the other two point
/// into the provider's own algorithm definition.
#[repr(C)]
pub struct OsslStoreLoader {
    /// `const char *scheme` — the legacy constant string, NULL for a provider loader.
    pub(crate) scheme: *const c_char,
    /// `ENGINE *engine` — the legacy ENGINE, carried and reported but never dereferenced.
    pub(crate) engine: *mut c_void,
    /// `OSSL_STORE_open_fn open`.
    pub(crate) open: Option<OsslStoreOpenFn>,
    /// `OSSL_STORE_attach_fn attach`.
    pub(crate) attach: Option<OsslStoreAttachFn>,
    /// `OSSL_STORE_ctrl_fn ctrl`.
    pub(crate) ctrl: Option<OsslStoreCtrlFn>,
    /// `OSSL_STORE_expect_fn expect`.
    pub(crate) expect: Option<OsslStoreExpectFn>,
    /// `OSSL_STORE_find_fn find`.
    pub(crate) find: Option<OsslStoreFindFn>,
    /// `OSSL_STORE_load_fn load`.
    pub(crate) load: Option<OsslStoreLoadFn>,
    /// `OSSL_STORE_eof_fn eof`.
    pub(crate) eof: Option<OsslStoreEofFn>,
    /// `OSSL_STORE_error_fn error`.
    pub(crate) error: Option<OsslStoreErrorFn>,
    /// `OSSL_STORE_close_fn closefn`.
    pub(crate) closefn: Option<OsslStoreCloseFn>,
    /// `OSSL_STORE_open_ex_fn open_ex`.
    pub(crate) open_ex: Option<OsslStoreOpenExFn>,

    /// `OSSL_PROVIDER *prov` — holding a reference, NULL for a legacy loader.
    pub(crate) prov: *mut OsslProvider,
    /// `int scheme_id` — the name-map number the loader answers to.
    pub(crate) scheme_id: c_int,
    /// `const char *propdef` — borrowed from the provider's algorithm definition.
    pub(crate) propdef: *const c_char,
    /// `const char *description` — borrowed from the provider's algorithm definition.
    pub(crate) description: *const c_char,
    /// `CRYPTO_REF_COUNT refcnt` — a plain `_Atomic int` in the authority.
    pub(crate) refcnt: AtomicI32,

    /// `OSSL_FUNC_store_open_fn *p_open`.
    pub(crate) p_open: Option<StorePOpenFn>,
    /// `OSSL_FUNC_store_attach_fn *p_attach`.
    pub(crate) p_attach: Option<StorePAttachFn>,
    /// `OSSL_FUNC_store_settable_ctx_params_fn *p_settable_ctx_params`.
    pub(crate) p_settable_ctx_params: Option<StorePSettableCtxParamsFn>,
    /// `OSSL_FUNC_store_set_ctx_params_fn *p_set_ctx_params`.
    pub(crate) p_set_ctx_params: Option<StorePSetCtxParamsFn>,
    /// `OSSL_FUNC_store_load_fn *p_load`.
    pub(crate) p_load: Option<StorePLoadFn>,
    /// `OSSL_FUNC_store_eof_fn *p_eof`.
    pub(crate) p_eof: Option<StorePEofFn>,
    /// `OSSL_FUNC_store_close_fn *p_close`.
    pub(crate) p_close: Option<StorePCloseFn>,
    /// `OSSL_FUNC_store_export_object_fn *p_export_object`.
    pub(crate) p_export_object: Option<StorePExportObjectFn>,
    /// `OSSL_FUNC_store_delete_fn *p_delete`.
    pub(crate) p_delete: Option<StorePDeleteFn>,
    /// `OSSL_FUNC_store_open_ex_fn *p_open_ex`.
    pub(crate) p_open_ex: Option<StorePOpenExFn>,
}
