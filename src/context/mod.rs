//! Phase 6 — `OSSL_LIB_CTX`, the object the rest of OpenSSL 3 is parameterised by.
//!
//! `docs/PROVIDER_MODEL.md` is this stratum's constitution. This module is its
//! first piece: the library context that a provider, a method store and a
//! property query all hang off. The authority's implementation is
//! `crypto/context.c` (658 lines), and the ten exports that declare it are in
//! `crypto.h`.
//!
//! ## The three behaviours a caller can observe
//!
//! Almost none of this is in the documentation, and all of it is in the
//! authority's source. Measured against the admitted authority by `RT-LIBCTX`
//! (`courts/phase6/rt_libctx_probe.c`):
//!
//! **1. The default chain.** A NULL context resolves to *this thread's* default
//! if one was set, and to the global default otherwise
//! ([`get_default_context`]). `OSSL_LIB_CTX_set0_default` is therefore not a
//! setter: it returns the **previous** default and sets a new one, and with a
//! NULL argument it is a pure query. One asymmetry is easy to miss and is part
//! of the contract: passing the *global* default as the new default does not
//! store it, it **clears** the thread's slot
//! ([`set_default_context`] rewrites it to NULL), which is observable because the
//! NULL context then resolves to the global object again.
//!
//! **2. Two of the three values `free` accepts are no-ops.** `ossl_lib_ctx_is_default`
//! answers 1 for NULL and for whatever the current thread's default resolves to,
//! so `OSSL_LIB_CTX_free(NULL)` and `OSSL_LIB_CTX_free(get0_global_default())`
//! return without releasing anything — and so does freeing a context that a
//! thread made its default, which means a caller who does that and keeps using
//! the context is *not* using freed memory. Only a context that is not the
//! default is actually released. `RT-LIBCTX` observes all three.
//!
//! **3. The index registry.** `OSSL_LIB_CTX_get_data(ctx, index)` is a plain
//! `switch` with **no bounds check**: the index space is fixed by
//! `include/internal/cryptlib.h`, and which numbers answer a pointer, which
//! answer NULL, and which answer an address *inside* the object are all
//! observable by a caller that passes integers. The authority's table, measured:
//!
//! ```text
//!  index  0..6   live   7,8,9 dead   10,11,12 live   13 dead   14..22 live   23+ dead
//! ```
//!
//! ## Which slots this stratum fills, and which are owed to a later one
//!
//! The switch below has an arm for every **live** index, and every arm reads the
//! field that will hold the sub-object. The fields a later stratum owns are
//! still NULL, so those arms answer NULL today and become correct the moment the
//! owning stratum fills its field. That is deliberate: the *shape* of the table
//! — the part a consumer can see through the exported function alone — is
//! already exact, and what is missing is named rather than faked.
//!
//! | index | slot | owner |
//! |---|---|---|
//! | 0 | `evp_method_store` | Phase 7 (EVP) |
//! | 1 | `provider_store` | **filled by 6.8b-slot** |
//! | 2 | `property_defns` | 6.7 |
//! | 3 | `property_string_data` | 6.7 |
//! | 4 | `namemap` | **6.6b** |
//! | 5 | `drbg` | Phase 9 (RAND) |
//! | 6 | `drbg_nonce` | Phase 9 |
//! | 10 | `encoder_store` | Phase 7 |
//! | 11 | `decoder_store` | Phase 7 |
//! | 12 | `self_test_cb` | 6.11 |
//! | 14 | `global_properties` | 6.7 |
//! | 15 | `store_loader_store` | Phase 10 |
//! | 16 | `provider_conf` | 6.8 |
//! | 17 | `bio_core` | **6.6c** |
//! | 18 | `child_provider` | 6.8 |
//! | 19 | `threads` | 6.6e |
//! | 20 | `decoder_cache` | Phase 7 |
//! | 21 | `comp_methods` | **this module** — the arm answers the address of the field itself, which is what the authority's arm does, so it is already exact |
//! | 22 | `indicator_cb` | 6.11 |
//!
//! The **stratum cannot close** while any of those slots is unfilled: a slot is
//! an obligation of the same kind as an unimplemented export, and
//! `docs/PHASE-6-SUBPHASES.md` carries the same table so it is not only here.
//! Filling one with a placeholder to make it non-NULL would be a fake-success
//! stub — the value is a live object of a type a later stratum owns — so the
//! arms answer NULL until their owner lands and the court's probe observes only
//! the slots this stratum owns.
//!
//! ## Allocation coordinates
//!
//! The context is allocated with [`CRYPTO_zalloc`] and released with
//! [`CRYPTO_free`], not with a Rust `Box`, so that an application which installs
//! its own allocator through `CRYPTO_set_mem_functions` sees these allocations
//! exactly as it sees the authority's. The reported source coordinates are the
//! authority's own, from `crypto/context.c`, because they are what a failing
//! allocation records in the error queue (`docs/ERROR_MODEL.md`).
//!
//! ## What is deliberately not built here
//!
//! * `context_init` in the authority constructs ~20 sub-objects and fails the
//!   context if any of them cannot be built. Only the fields this stratum owns
//!   are constructed here; the rest are the table above.
//! * `ossl_do_ex_data_init(ctx)` gives each context its own ex-data registry.
//!   `src/runtime/ex_data.rs` documents a single process-global registry as a
//!   Phase 3 deferral, and this module does not change it: `CRYPTO_EX_INDEX_OSSL_LIB_CTX`
//!   is observable only through the ex-data API, which `RT-EXDATA` already
//!   covers as a process-global one. It stays a recorded deferral.
//! * `ossl_ctx_thread_stop(ctx)` runs in `context_deinit` in the authority. The
//!   per-thread state it releases cannot exist until 6.6e registers threads
//!   against a context, so the call is not made yet and the omission is named
//!   here rather than silently absent.

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    CRYPTO_THREAD_cleanup_local, CRYPTO_THREAD_get_local, CRYPTO_THREAD_init_local,
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock,
    CRYPTO_THREAD_run_once, CRYPTO_THREAD_set_local, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoOnce, CryptoRwlock, CryptoThreadLocal,
};

pub mod core_bio;
pub mod dispatch;
pub mod namemap;
pub mod thread_data;

/// `OSSL_LIB_CTX_PROPERTY_STRING_INDEX`, from `include/internal/cryptlib.h`. Slot 3,
/// filled by 6.7a: the property name/value string tables.
pub(crate) const OSSL_LIB_CTX_PROPERTY_STRING_INDEX: c_int = 3;

/// `OSSL_LIB_CTX_PROPERTY_DEFN_INDEX`, from `include/internal/cryptlib.h`. Slot 2,
/// filled by 6.7a: the per-context property definition cache.
pub(crate) const OSSL_LIB_CTX_PROPERTY_DEFN_INDEX: c_int = 2;

/// `OSSL_LIB_CTX_GLOBAL_PROPERTIES`, from `include/internal/cryptlib.h`. Slot 14,
/// filled by 6.7a: the per-context global properties holder.
pub(crate) const OSSL_LIB_CTX_GLOBAL_PROPERTIES_INDEX: c_int = 14;

/// `OSSL_LIB_CTX_BIO_CORE_INDEX`, from `include/internal/cryptlib.h`. Slot 17,
/// filled by 6.6c.
pub(crate) const OSSL_LIB_CTX_BIO_CORE_INDEX: c_int = 17;

/// `OSSL_LIB_CTX_NAMEMAP_INDEX`, from `include/internal/cryptlib.h`. Slot 4,
/// filled by 6.6b.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) const OSSL_LIB_CTX_NAMEMAP_INDEX: c_int = 4;

/// `OSSL_LIB_CTX_SELF_TEST_CB_INDEX`, from `include/internal/cryptlib.h`. Slot 12,
/// filled by 6.11.
pub(crate) const OSSL_LIB_CTX_SELF_TEST_CB_INDEX: c_int = 12;

/// `OSSL_LIB_CTX_INDICATOR_CB_INDEX`. Slot 22, filled by 6.11.
pub(crate) const OSSL_LIB_CTX_INDICATOR_CB_INDEX: c_int = 22;

/// `OSSL_LIB_CTX_THREAD_INDEX`, from `include/internal/cryptlib.h`. Slot 19,
/// filled by 6.6e.
pub(crate) const OSSL_LIB_CTX_THREAD_INDEX: c_int = 19;

// The four method-store slots, named here because 6.8c's store bridges read them
// and a bridge that spelled its own `0` would be the one place the slot table's
// numbering was duplicated. Each is a *read* by this stratum and a *fill* by the
// stratum recorded beside it: `docs/PHASE-6-SUBPHASES.md` carries the same table.

/// `OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX`. Slot 0, filled by Phase 7.
pub(crate) const OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX: c_int = 0;

/// `OSSL_LIB_CTX_ENCODER_STORE_INDEX`. Slot 10, filled by Phase 7.
pub(crate) const OSSL_LIB_CTX_ENCODER_STORE_INDEX: c_int = 10;

/// `OSSL_LIB_CTX_DECODER_STORE_INDEX`. Slot 11, filled by Phase 7.
pub(crate) const OSSL_LIB_CTX_DECODER_STORE_INDEX: c_int = 11;

/// `OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX`. Slot 15, filled by Phase 10.
pub(crate) const OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX: c_int = 15;

/// The authority's translation unit, as its compiler spelled it, so a failing
/// allocation records the coordinates a consumer would see from the authority.
/// Derived from the admitted build record (`forensics/authorities/`), never
/// hand-typed.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/context.c".as_ptr();

/// `OPENSSL_zalloc(sizeof(*ctx))` is at `crypto/context.c:436`, `OPENSSL_free(ctx)`
/// at 439 (the failed-`context_init` arm) and at 495 (`OSSL_LIB_CTX_free`).
const LINE_ZALLOC_CTX: c_int = 436;
const LINE_FREE_INIT_FAILURE: c_int = 439;
const LINE_FREE: c_int = 495;

// ---------------------------------------------------------------------------
// The object
// ---------------------------------------------------------------------------

/// `struct ossl_lib_ctx_st`, from the authority's `crypto/context.c`.
///
/// Every slot is a `*mut c_void` because each holds an object of a type another
/// module owns and this one only stores and releases. The two scalars at the end
/// are the only state this module interprets.
///
/// The dead indices — 7, 8, 9 and 13 — have **no field**, deliberately: the
/// authority's `switch` has no arm for them either, so they answer NULL from the
/// `default:` arm. Giving them a field would invite an arm, and an arm would be
/// a divergence.
#[repr(C)]
struct OsslLibCtx {
    /// The context's own lock, which the authority's `ossl_lib_ctx_write_lock`
    /// and friends take for the property and provider paths. Created here
    /// because `context_init` creates it before anything else.
    lock: *mut CryptoRwlock,

    /// `OSSL_LIB_CTX_EVP_METHOD_STORE_INDEX` (0) — Phase 7.
    evp_method_store: *mut c_void,
    /// `OSSL_LIB_CTX_PROVIDER_STORE_INDEX` (1) — filled by `context_init` in
    /// 6.8b-slot, and **the first slot object the authority builds**. See
    /// `context_init` for why its position is first and the thread slot's is last.
    provider_store: *mut c_void,
    /// `OSSL_LIB_CTX_PROPERTY_DEFN_INDEX` (2) — 6.7.
    property_defns: *mut c_void,
    /// `OSSL_LIB_CTX_PROPERTY_STRING_INDEX` (3) — 6.7.
    property_string_data: *mut c_void,
    /// `OSSL_LIB_CTX_NAMEMAP_INDEX` (4) — **6.6b**.
    namemap: *mut c_void,
    /// `OSSL_LIB_CTX_DRBG_INDEX` (5) — Phase 9.
    drbg: *mut c_void,
    /// `OSSL_LIB_CTX_DRBG_NONCE_INDEX` (6) — Phase 9.
    drbg_nonce: *mut c_void,
    /// `OSSL_LIB_CTX_ENCODER_STORE_INDEX` (10) — Phase 7.
    encoder_store: *mut c_void,
    /// `OSSL_LIB_CTX_DECODER_STORE_INDEX` (11) — Phase 7.
    decoder_store: *mut c_void,
    /// `OSSL_LIB_CTX_SELF_TEST_CB_INDEX` (12) — 6.11.
    self_test_cb: *mut c_void,
    /// `OSSL_LIB_CTX_GLOBAL_PROPERTIES` (14) — 6.7.
    global_properties: *mut c_void,
    /// `OSSL_LIB_CTX_STORE_LOADER_STORE_INDEX` (15) — Phase 10.
    store_loader_store: *mut c_void,
    /// `OSSL_LIB_CTX_PROVIDER_CONF_INDEX` (16) — 6.8.
    provider_conf: *mut c_void,
    /// `OSSL_LIB_CTX_BIO_CORE_INDEX` (17) — **6.6c**.
    bio_core: *mut c_void,
    /// `OSSL_LIB_CTX_CHILD_PROVIDER_INDEX` (18) — 6.8.
    child_provider: *mut c_void,
    /// `OSSL_LIB_CTX_THREAD_INDEX` (19) — 6.6e, the thread pool context.
    threads: *mut c_void,
    /// `OSSL_LIB_CTX_DECODER_CACHE_INDEX` (20) — Phase 7.
    decoder_cache: *mut c_void,
    /// `OSSL_LIB_CTX_COMP_METHODS` (21). The arm answers the **address of this
    /// field**, not its value, which is the whole of that slot's behaviour: it is
    /// non-NULL for every context, including one whose compression-method stack
    /// is empty. The stack itself is a build-time list (`ossl_load_builtin_compressions`),
    /// which is a legacy-stratum obligation.
    comp_methods: *mut c_void,
    /// `OSSL_LIB_CTX_INDICATOR_CB_INDEX` (22) — 6.11.
    indicator_cb: *mut c_void,

    /// `int ischild;` — set by `OSSL_LIB_CTX_new_child` (6.6d), and read by
    /// `OSSL_LIB_CTX_free` to decide whether to deinit child-provider state.
    ischild: c_int,
    /// `int conf_diagnostics;` — the only interpreted scalar state.
    conf_diagnostics: c_int,
}

impl OsslLibCtx {
    /// A zeroed context, as `OPENSSL_zalloc` produces. Written as a struct
    /// literal so that every field is accounted for at compile time: a field
    /// added later cannot be forgotten here, which a `MaybeUninit` zeroing would
    /// not catch.
    const ZEROED: OsslLibCtx = OsslLibCtx {
        lock: ptr::null_mut(),
        evp_method_store: ptr::null_mut(),
        provider_store: ptr::null_mut(),
        property_defns: ptr::null_mut(),
        property_string_data: ptr::null_mut(),
        namemap: ptr::null_mut(),
        drbg: ptr::null_mut(),
        drbg_nonce: ptr::null_mut(),
        encoder_store: ptr::null_mut(),
        decoder_store: ptr::null_mut(),
        self_test_cb: ptr::null_mut(),
        global_properties: ptr::null_mut(),
        store_loader_store: ptr::null_mut(),
        provider_conf: ptr::null_mut(),
        bio_core: ptr::null_mut(),
        child_provider: ptr::null_mut(),
        threads: ptr::null_mut(),
        decoder_cache: ptr::null_mut(),
        comp_methods: ptr::null_mut(),
        indicator_cb: ptr::null_mut(),
        ischild: 0,
        conf_diagnostics: 0,
    };
}

/// The process-global default context, with a stable address.
///
/// The authority declares it as `static OSSL_LIB_CTX default_context_int;` — a
/// real static object, not a heap allocation — and that is observable:
/// `OSSL_LIB_CTX_get0_global_default` hands the same address to every thread, and
/// it is the address `get_data` answers interior pointers relative to.
///
/// `UnsafeCell` rather than `static mut`, following `src/asn1/a_strnid.rs` and
/// `src/runtime/conf/conf_ssl.rs`: `UnsafeCell::get` yields the address without
/// materialising a reference to a mutable static, which this crate does not do.
struct SyncCtx(UnsafeCell<OsslLibCtx>);

// SAFETY: every access goes through the authority's own discipline. The object is
// written only by `context_init` inside `RUN_ONCE` (which is `pthread_once`, so
// exactly one thread runs it and every other thread synchronises on it), and
// after that only `conf_diagnostics` is written, which the authority also writes
// without a lock. No `&mut` to the whole object is ever created.
unsafe impl Sync for SyncCtx {}

static DEFAULT_CONTEXT: SyncCtx = SyncCtx(UnsafeCell::new(OsslLibCtx::ZEROED));

/// `static CRYPTO_ONCE default_context_init = CRYPTO_ONCE_STATIC_INIT;`
///
/// `pthread_once` writes this field and nothing else does, so it is storage
/// rather than state this crate interprets; an `AtomicI32` is the crate's way of
/// having addressable mutable storage without a `static mut`. The declared type is
/// `CRYPTO_ONCE`, a [`CryptoOnce`], and `CRYPTO_ONCE_STATIC_INIT` is zero on this
/// platform.
static DEFAULT_CONTEXT_INIT: AtomicI32 = AtomicI32::new(0);

/// `static CRYPTO_THREAD_LOCAL default_context_thread_local;`
///
/// The `pthread_key_t` itself, stored in an `AtomicU32` for the same reason. The
/// declared type is `CRYPTO_THREAD_LOCAL`, a [`CryptoThreadLocal`]. Zero is a
/// *valid* key, so this value is only meaningful once [`DEFAULT_CONTEXT_INIT`] has
/// run — which is why every read of it goes through
/// [`get_thread_default_context`] and never through this static directly.
static DEFAULT_CONTEXT_THREAD_LOCAL: AtomicU32 = AtomicU32::new(0);

/// `static int default_context_inited = 0;`
///
/// The authority also carries the `RUN_ONCE` macro's own `default_context_init_ossl_ret_`,
/// which is set from the initialiser's return value. The two are always equal
/// here — the initialiser sets this one only on success and the macro records the
/// same success — so one `AtomicBool` carries both, and the equality is why
/// reading it outside `RUN_ONCE` is sound: every caller has already run the once.
static DEFAULT_CONTEXT_INITED: AtomicBool = AtomicBool::new(false);

/// The address of the global default object. Never NULL; the object exists from
/// process start, exactly as a C `static` does.
fn global_default() -> *mut OsslLibCtx {
    DEFAULT_CONTEXT.0.get()
}

// ---------------------------------------------------------------------------
// The default chain
// ---------------------------------------------------------------------------

/// `context_init(OSSL_LIB_CTX *ctx)` — create what this stratum owns.
///
/// Returns false only when the context's own lock cannot be allocated, which is
/// the one construction the authority performs that this stratum also performs.
/// The remaining ~19 constructions are the table in the module documentation;
/// none of them can be attempted before its owning stratum exists, and the
/// authority fails the whole context when one of them fails, so a partial
/// initialisation must not be reported as success. It is not: the arms in
/// [`OSSL_LIB_CTX_get_data`] answer NULL for exactly those slots.
fn context_init(ctx: *mut OsslLibCtx) -> bool {
    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        return false;
    }
    // SAFETY: `ctx` is either a fresh `CRYPTO_zalloc` block of at least
    // `size_of::<OsslLibCtx>()` bytes, or the process-global default during its
    // own `RUN_ONCE` — in both cases a live object no other thread can observe
    // yet, and this is the only write that publishes the lock.
    unsafe { (*ctx).lock = lock };

    // The provider-config object, slot 16 — the **first** slot object in this crate, and in
    // the authority it is built third, after `evp_method_store` (Phase 7) and before `drbg`
    // (Phase 9). Of the slots this crate has landed it is therefore first, and the P2 marker
    // on it is the same one the authority writes: it must be released *before* the provider
    // store, because a provider this module activated is recorded in the store.
    //
    // SAFETY: `ctx` is the live context being initialised — either a fresh `CRYPTO_zalloc`
    // block or the process-global default during its own `RUN_ONCE` — so it is a live object
    // no other thread can observe yet.
    let provider_conf =
        unsafe { crate::provider::conf::ossl_prov_conf_ctx_new(ctx.cast::<c_void>()) };
    if provider_conf.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above; the slot is published once, here.
    unsafe { (*ctx).provider_conf = provider_conf.cast::<c_void>() };

    // The provider store. **This is the first slot object the authority builds** among
    // those this crate has landed, and its position is not arbitrary: the authority's own
    // comment marks it *P1 -- needs to be freed before the child provider data is freed*,
    // while the seven slots it builds before this one are marked *P2 -- cleaned up before
    // the provider store*. The P2 slots are Phases 7, 9 and 10's, so in this crate the
    // provider store is simply first.
    //
    // Reading `context_init` to find this position is also what exposed that the *thread*
    // slot was being built first here and is the authority's **ninth** among the landed
    // set. Construction order is not directly observable -- a caller sees the finished
    // table, and this profile disables the allocation-failure injection that would expose
    // the cascade -- but `context_deinit`'s order is observable in principle, because a slot
    // object's destructor has side effects. Both orders are now the authority's.
    // SAFETY: `ctx` is the live context being initialised, and the store constructor only
    // stores the pointer it is given.
    let provider_store = unsafe { crate::provider::ossl_provider_store_new(ctx.cast::<c_void>()) };
    if provider_store.is_null() {
        // The authority's `err:` arm: release what was built, then report failure.
        // `OSSL_LIB_CTX_new` frees the block itself.
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above; the slot is published once, here.
    unsafe { (*ctx).provider_store = provider_store.cast::<c_void>() };

    // The property string table. The authority builds it **first** among the
    // slot objects this crate builds, before the namemap; and `property_parse_init`
    // below is what fills it. Its position relative to the namemap and the core BIO
    // globals is the authority's.
    let property_string_data = crate::property::ossl_property_string_data_new(ctx.cast::<c_void>());
    if property_string_data.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above; the slot is published once, here.
    unsafe { (*ctx).property_string_data = property_string_data.cast::<c_void>() };

    // The namemap. The authority builds it after `property_string_data` and
    // before `property_defns`; of those three this stratum builds only the one, and
    // its position relative to the two callback holders and the thread slot below
    // is the authority's.
    let namemap = crate::context::namemap::ossl_stored_namemap_new(ctx.cast::<c_void>());
    if namemap.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).namemap = namemap.cast::<c_void>() };

    // The property definition cache. The authority builds it immediately after the
    // namemap and before `global_properties`.
    let property_defns = crate::property::ossl_property_defns_new(ctx.cast::<c_void>());
    if property_defns.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).property_defns = property_defns.cast::<c_void>() };

    // The global properties holder. The authority builds it after `property_defns`
    // and before the core BIO globals. It is a zeroed block with a NULL `list`, which
    // is a valid empty holder rather than an uninitialised slot: the grammar that
    // could fill it is 6.7b's.
    let global_properties = crate::property::ossl_ctx_global_properties_new(ctx.cast::<c_void>());
    if global_properties.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).global_properties = global_properties.cast::<c_void>() };

    // The core BIO globals. The authority builds them after `global_properties`
    // (not this stratum's) and before `drbg_nonce`; their position relative to
    // the two callback holders and the thread slot below is the authority's.
    let bio_core = crate::context::core_bio::ossl_bio_core_globals_new(ctx.cast::<c_void>());
    if bio_core.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).bio_core = bio_core.cast::<c_void>() };

    // The two callback holders. The authority builds them after `drbg_nonce` and
    // before the thread slot, and each is a plain `OPENSSL_zalloc`ed pair.
    let self_test_cb = crate::selftest::ossl_self_test_set_callback_new(ctx.cast::<c_void>());
    if self_test_cb.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).self_test_cb = self_test_cb.cast::<c_void>() };

    let indicator_cb =
        crate::selftest::indicator::ossl_indicator_set_callback_new(ctx.cast::<c_void>());
    if indicator_cb.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above.
    unsafe { (*ctx).indicator_cb = indicator_cb.cast::<c_void>() };

    // The thread slot, which is **last** among the slot objects this crate builds.
    // `context_init` guards it with `#ifndef OPENSSL_NO_THREAD_POOL`, and this profile has
    // the pool compiled in -- which is not something any installed header says. It was
    // **measured**: index 19 answers a pointer from `OSSL_LIB_CTX_get_data`, and
    // `OSSL_get_thread_support_flags` answers the thread-pool flag. Both are observations
    // of the same build fact, and `RT-LIBCTX` re-measures the first on every run.
    //
    // In the authority this slot follows the FIPS-only pair and `indicator_cb`, and is
    // followed only by the child-provider context (6.8e) and the compression methods
    // (Phase 13) -- so among the objects that exist here it is correctly last.
    let threads = crate::context::thread_data::ossl_threads_ctx_new(ctx.cast::<c_void>());
    if threads.is_null() {
        context_deinit(ctx);
        return false;
    }
    // SAFETY: as above; the slot is published once, here.
    unsafe { (*ctx).threads = threads.cast::<c_void>() };

    // The property engine's pre-initialisation. The authority calls it last among
    // the objects it builds -- after the child-provider context, which is 6.8's, and
    // before the builtin compression methods, which are Phase 13's -- so it is the
    // last step here too. It needs only slot 3, filled above.
    //
    // This is where "yes" and "no" receive OSSL_PROPERTY_TRUE (1) and
    // OSSL_PROPERTY_FALSE (2). It is a start-up check, not an optimisation: a value
    // table numbered in another order makes every boolean property answer wrongly,
    // and the authority asserts the order here.
    // SAFETY: `ctx` is live and its slot 3 was built above.
    if unsafe { crate::property::ossl_property_parse_init(ctx.cast::<c_void>()) } == 0 {
        context_deinit(ctx);
        return false;
    }
    true
}

/// `context_deinit_objs(OSSL_LIB_CTX *ctx)` — release the slots this stratum owns.
///
/// Written as an explicit sequence rather than a loop so that each release names
/// its owner, matching the authority's own comment structure (`P1`/`P2` ordering
/// with respect to the provider store). Only slot 21 has no release: it is an
/// interior address, not an allocation.
fn context_deinit_objs(ctx: *mut OsslLibCtx) {
    // The provider-config object, released **first** among the slot objects, which is the
    // authority's order: `context_deinit_objs` releases `evp_method_store` (Phase 7),
    // `drbg` (Phase 9) and then this one, all before the provider store's *P1* position.
    // Releasing it here is what makes the P2 relation hold: a provider this module
    // activated lives in the store, and the module's list is what points at it.
    // SAFETY: `ctx` is a live context being torn down by `context_deinit`, and no other
    // thread holds a reference to it -- `OSSL_LIB_CTX_free` is the only caller and the
    // caller contract is that the object is no longer in use. Each slot is released exactly
    // once and re-NULLed.
    unsafe {
        if !(*ctx).provider_conf.is_null() {
            crate::provider::conf::ossl_prov_conf_ctx_free((*ctx).provider_conf);
            (*ctx).provider_conf = ptr::null_mut();
        }
    }

    // The provider store, released **first among the slot objects the authority marks P1**,
    // because the child-provider data that 6.8e lands must be freed after it. Releasing it
    // here is what makes the P1 relation hold once that arrives.
    // SAFETY: `ctx` is a live context being torn down by `context_deinit`, and no other
    // thread holds a reference to it -- `OSSL_LIB_CTX_free` is the only caller and the
    // caller contract is that the object is no longer in use. Each slot is released exactly
    // once and re-NULLed.
    unsafe {
        if !(*ctx).provider_store.is_null() {
            crate::provider::ossl_provider_store_free((*ctx).provider_store);
            (*ctx).provider_store = ptr::null_mut();
        }
    }

    // The property string table, released next among the slot objects, as the
    // authority releases them (before the namemap).
    // SAFETY: `ctx` is a live context being torn down by `context_deinit`, and no
    // other thread holds a reference to it -- `OSSL_LIB_CTX_free` is the only
    // caller and the caller contract is that the object is no longer in use. Each
    // slot is released exactly once and re-NULLed.
    unsafe {
        if !(*ctx).property_string_data.is_null() {
            crate::property::ossl_property_string_data_free((*ctx).property_string_data);
            (*ctx).property_string_data = ptr::null_mut();
        }
    }

    // SAFETY: as above.
    unsafe {
        if !(*ctx).namemap.is_null() {
            crate::context::namemap::ossl_stored_namemap_free(
                (*ctx)
                    .namemap
                    .cast::<crate::context::namemap::OsslNamemap>(),
            );
            (*ctx).namemap = ptr::null_mut();
        }
    }

    // The property definition cache and the global properties holder, released
    // after the namemap and before the core BIO globals -- the authority's order
    // exactly: `property_string_data`, `namemap`, `property_defns`,
    // `global_properties`, `bio_core`.
    // SAFETY: as above.
    unsafe {
        if !(*ctx).property_defns.is_null() {
            crate::property::ossl_property_defns_free((*ctx).property_defns);
            (*ctx).property_defns = ptr::null_mut();
        }
        if !(*ctx).global_properties.is_null() {
            crate::property::ossl_ctx_global_properties_free((*ctx).global_properties);
            (*ctx).global_properties = ptr::null_mut();
        }
    }

    // The core BIO globals, released before the two callback holders, as the
    // authority releases them (`bio_core` follows `global_properties` and precedes
    // `drbg_nonce` in its order too).
    // SAFETY: `ctx` is a live context being torn down by `context_deinit`, and no
    // other thread holds a reference to it -- `OSSL_LIB_CTX_free` is the only
    // caller and the caller contract is that the object is no longer in use. Each
    // slot is released exactly once and re-NULLed.
    unsafe {
        if !(*ctx).bio_core.is_null() {
            crate::context::core_bio::ossl_bio_core_globals_free(
                (*ctx)
                    .bio_core
                    .cast::<crate::context::core_bio::BioCoreGlobals>(),
            );
            (*ctx).bio_core = ptr::null_mut();
        }
    }

    // The two callback holders, in the authority's order: `indicator_cb` first,
    // then `self_test_cb`, both after `drbg_nonce` and before the thread slot.
    // SAFETY: as above.
    unsafe {
        if !(*ctx).indicator_cb.is_null() {
            crate::selftest::indicator::ossl_indicator_set_callback_free(
                (*ctx)
                    .indicator_cb
                    .cast::<crate::selftest::indicator::IndicatorCb>(),
            );
            (*ctx).indicator_cb = ptr::null_mut();
        }
        if !(*ctx).self_test_cb.is_null() {
            crate::selftest::ossl_self_test_set_callback_free(
                (*ctx).self_test_cb.cast::<crate::selftest::SelfTestCb>(),
            );
            (*ctx).self_test_cb = ptr::null_mut();
        }
    }

    // `#ifndef OPENSSL_NO_THREAD_POOL` in the authority, released after the two
    // callback slots and before `child_provider` and `comp_methods`.
    // SAFETY: as above.
    unsafe {
        if !(*ctx).threads.is_null() {
            crate::context::thread_data::ossl_threads_ctx_free(
                (*ctx)
                    .threads
                    .cast::<crate::context::thread_data::OsslLibCtxThreads>(),
            );
            (*ctx).threads = ptr::null_mut();
        }
    }

    // SAFETY: as above.
    unsafe {
        (*ctx).comp_methods = ptr::null_mut();
    }
}

/// `context_deinit(OSSL_LIB_CTX *ctx)`.
///
/// The authority calls `ossl_ctx_thread_stop(ctx)` **first**, before any of the
/// context's sub-objects are released: it stops the handlers registered for this
/// context on whatever threads still hold them, and those handlers may reach the
/// objects the release below is about to free. It landed with 6.6e-ii, which is
/// where the per-thread event-handler table comes from.
fn context_deinit(ctx: *mut OsslLibCtx) {
    // SAFETY: `ctx` is live, and `ossl_ctx_thread_stop` accepts NULL or live; the
    // context is passed as the concrete object, which is what the authority's own
    // call reaches through `ossl_lib_ctx_get_concrete`.
    unsafe { crate::runtime::thread_events::ossl_ctx_thread_stop(ctx.cast::<c_void>()) };
    context_deinit_objs(ctx);
    // SAFETY: `ctx->lock` was created by `context_init` (or is NULL for a
    // context whose initialisation failed before the lock, which cannot be freed
    // and cannot reach here) and is released exactly once, here, as the last step
    // of the object's life. `CRYPTO_THREAD_lock_free` accepts NULL.
    unsafe {
        CRYPTO_THREAD_lock_free((*ctx).lock);
        (*ctx).lock = ptr::null_mut();
    }
}

/// The authority's `default_context_do_init`, wrapped as `pthread_once` wants it:
/// no arguments, no return value, and the result stored where `RUN_ONCE` reads it.
extern "C" fn default_context_do_init() {
    // `CRYPTO_THREAD_init_local(&key, NULL)` — no destructor, because the value
    // stored in the slot is a borrowed pointer the context does not own.
    // SAFETY: `DEFAULT_CONTEXT_THREAD_LOCAL` is this module's storage for the
    // key and is written only by this initialiser.
    if unsafe { CRYPTO_THREAD_init_local(DEFAULT_CONTEXT_THREAD_LOCAL.as_ptr(), None) } == 0 {
        return;
    }
    if !context_init(global_default()) {
        // SAFETY: the key was created three lines above and the initialisation
        // that would have used it failed, so this thread is the only one that can
        // observe it.
        unsafe { CRYPTO_THREAD_cleanup_local(DEFAULT_CONTEXT_THREAD_LOCAL.as_ptr()) };
        return;
    }
    DEFAULT_CONTEXT_INITED.store(true, Ordering::Release);
}

/// `RUN_ONCE(&default_context_init, default_context_do_init)`: run the
/// initialiser once, and answer whether it **succeeded** — the macro's contract
/// is `run_once(...) ? ret_ : 0`, so a once that ran and failed is a failure, not
/// a success.
fn run_once_default_context() -> bool {
    // SAFETY: `DEFAULT_CONTEXT_INIT` is this module's storage for the once
    // control word, and `default_context_do_init` is a plain `extern "C" fn()`
    // with no arguments, which is what `pthread_once` requires.
    let ran = unsafe {
        CRYPTO_THREAD_run_once(
            DEFAULT_CONTEXT_INIT.as_ptr().cast::<CryptoOnce>(),
            Some(default_context_do_init),
        )
    } != 0;
    ran && DEFAULT_CONTEXT_INITED.load(Ordering::Acquire)
}

/// `get_thread_default_context(void)` — NULL when no default was set for *this*
/// thread, and NULL when the initialiser failed.
fn get_thread_default_context() -> *mut OsslLibCtx {
    if !run_once_default_context() {
        return ptr::null_mut();
    }
    // SAFETY: the key was created by the once that just succeeded on this thread.
    unsafe {
        CRYPTO_THREAD_get_local(
            DEFAULT_CONTEXT_THREAD_LOCAL
                .as_ptr()
                .cast::<CryptoThreadLocal>(),
        )
    }
    .cast::<OsslLibCtx>()
}

/// `get_default_context(void)` — the thread's default, or the global one, or NULL
/// if the initialiser failed.
fn get_default_context() -> *mut OsslLibCtx {
    let current = get_thread_default_context();
    if current.is_null() && DEFAULT_CONTEXT_INITED.load(Ordering::Acquire) {
        return global_default();
    }
    current
}

/// `set_default_context(OSSL_LIB_CTX *defctx)`.
///
/// The rewrite of the global default to NULL is the authority's, and it is the
/// reason `OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX_get0_global_default())` is a
/// *clear* rather than a store: the thread slot then holds NULL, which
/// [`get_default_context`] resolves to the same global object — but
/// `OSSL_LIB_CTX_set0_default(NULL)` afterwards reports the global default rather
/// than the pointer that was passed in. `RT-LIBCTX` observes that difference.
fn set_default_context(defctx: *mut OsslLibCtx) -> bool {
    let defctx = if defctx == global_default() {
        ptr::null_mut()
    } else {
        defctx
    };
    // SAFETY: the key is initialised by the once, which every caller of this
    // function has already run (`OSSL_LIB_CTX_set0_default` reaches it only
    // through `get_default_context`). The value stored is a borrowed pointer, so
    // the slot has no destructor to run.
    unsafe {
        CRYPTO_THREAD_set_local(
            DEFAULT_CONTEXT_THREAD_LOCAL
                .as_ptr()
                .cast::<CryptoThreadLocal>(),
            defctx.cast::<c_void>(),
        ) != 0
    }
}

/// `ossl_lib_ctx_get_concrete(OSSL_LIB_CTX *ctx)` — resolve NULL to the default.
fn concrete(ctx: *mut OsslLibCtx) -> *mut OsslLibCtx {
    if ctx.is_null() {
        get_default_context()
    } else {
        ctx
    }
}

/// `ossl_lib_ctx_is_default(OSSL_LIB_CTX *ctx)` — the predicate `free` consults.
fn lib_ctx_is_default(ctx: *mut OsslLibCtx) -> c_int {
    if ctx.is_null() || ctx == get_default_context() {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// The exported surface
// ---------------------------------------------------------------------------

/// `OSSL_LIB_CTX *OSSL_LIB_CTX_new(void)`
///
/// A fresh context, distinct from every other, or NULL when either the
/// allocation or the initialisation failed. A context that fails to initialise is
/// released rather than returned, so a caller never sees a half-built object.
#[no_mangle]
pub extern "C" fn OSSL_LIB_CTX_new() -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let ctx = CRYPTO_zalloc(core::mem::size_of::<OsslLibCtx>(), FILE, LINE_ZALLOC_CTX)
            .cast::<OsslLibCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        if !context_init(ctx) {
            // SAFETY: `ctx` came from `CRYPTO_zalloc` above, was never published,
            // and `context_init` failed -- so nothing else holds it and it is
            // released exactly once, here.
            unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_INIT_FAILURE) };
            return ptr::null_mut();
        }
        ctx.cast::<c_void>()
    })
}

/// `OSSL_LIB_CTX *OSSL_LIB_CTX_new_from_dispatch(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in)`
///
/// A context whose core BIO callbacks come from an application-supplied dispatch
/// table. It is exactly [`OSSL_LIB_CTX_new`] followed by the table walk, and the
/// context is released if the walk fails, so a caller never sees a half-built
/// one.
///
/// `handle` is accepted and unused — the authority passes it to nothing in this
/// path; a provider child context is `OSSL_LIB_CTX_new_child` (6.6d), which is
/// what actually uses a core handle.
///
/// # Safety
/// `disp` must be NULL or a `OSSL_DISPATCH_END`-terminated table whose function
/// pointers remain callable for as long as the context may use them, and whose
/// callbacks accept whatever handle [`crate::context::core_bio::BIO_new_from_core_bio`]
/// is later given.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_new_from_dispatch(
    handle: *const c_void,
    disp: *const crate::context::dispatch::OsslDispatch,
) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let _ = handle;
        let ctx = OSSL_LIB_CTX_new();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` was just created and has not been published, so this
        // thread is the only one that can observe the table walk's writes.
        if unsafe { crate::context::core_bio::ossl_bio_init_core(ctx, disp) } == 0 {
            // SAFETY: `ctx` is live and not the default, so this releases it.
            unsafe { OSSL_LIB_CTX_free(ctx) };
            return ptr::null_mut();
        }
        ctx
    })
}

/// `OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void)`
///
/// The process-global object, the same address for every caller in every thread,
/// or NULL if the initialiser failed.
#[no_mangle]
pub extern "C" fn OSSL_LIB_CTX_get0_global_default() -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if !run_once_default_context() {
            return ptr::null_mut();
        }
        global_default().cast::<c_void>()
    })
}

/// `int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file)`
///
/// The one-line forward `crypto/context.c` has, and it is a forward to a *different*
/// entry point than the initialiser's: `CONF_modules_load_file_ex(ctx, config_file, NULL, 0)`
/// with an explicit **zero** flag word, not `DEFAULT_CONF_MFLAGS`. Three consequences
/// follow from that and each is a behaviour a caller can see:
///
/// * the section that is read is `openssl_conf`, because `CONF_MFLAGS_DEFAULT_SECTION` is
///   not set — and yet `CONF_modules_load`'s fallback is `!appname ||`, so with a NULL
///   `appname` the file's `openssl_conf` is used either way;
/// * a missing file is an **error**, because `CONF_MFLAGS_IGNORE_MISSING_FILE` is not set:
///   this function answers 0 where the automatic loader would answer 1;
/// * a module that fails is an error for the same reason. The initialiser's flags tolerate
///   a failure and this call's do not.
///
/// The return is `> 0` and not `!= 0`, which matters and is not a style choice:
/// `CONF_modules_load_file_ex` answers **-1** when a module fails, so a `!= 0` test would
/// report success for it. The authority's `> 0` collapses the -1 to 0.
///
/// # Safety
/// `ctx` must be NULL or live, and `config_file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_load_config(
    ctx: *mut c_void,
    config_file: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is NULL or live and `config_file` is NULL or NUL-terminated, which is
        // exactly `CONF_modules_load_file_ex`'s contract; `appname` is NULL and `flags` is the
        // explicit zero the authority passes.
        let ret = unsafe {
            crate::runtime::confmod::CONF_modules_load_file_ex(ctx, config_file, ptr::null(), 0)
        };
        if ret > 0 {
            1
        } else {
            0
        }
    })
}

/// `OSSL_LIB_CTX *OSSL_LIB_CTX_set0_default(OSSL_LIB_CTX *libctx)`
///
/// Returns the **previous** default and installs `libctx` as this thread's
/// default; with NULL it returns the current default and changes nothing. The
/// return value of the store is ignored, so a caller sees the previous default
/// even if the store failed — the authority's behaviour, kept.
///
/// # Safety
/// `libctx` must be NULL or a live context that has not been released. A context
/// installed here is *not* owned by the library; the authority leaves it to the
/// caller to release, and `OSSL_LIB_CTX_free` deliberately refuses to release the
/// one this thread has installed.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_set0_default(libctx: *mut c_void) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let libctx = libctx.cast::<OsslLibCtx>();
        let current = get_default_context();
        if current.is_null() {
            return ptr::null_mut();
        }
        if !libctx.is_null() {
            set_default_context(libctx);
        }
        current.cast::<c_void>()
    })
}

/// `void OSSL_LIB_CTX_free(OSSL_LIB_CTX *ctx)`
///
/// Releases the context, unless it is NULL or is the default this thread would
/// resolve to — see the module documentation, and note that the second case
/// includes the global default in a thread that has not changed its default.
///
/// # Safety
/// `ctx` must be NULL or a context returned by one of the constructors and not
/// already released. A context that is the current default is *not* released by
/// this call, so the caller keeps ownership until it clears the default.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_free(ctx: *mut c_void) {
    guard_ffi((), || {
        let ctx = ctx.cast::<OsslLibCtx>();
        if ctx.is_null() || lib_ctx_is_default(ctx) != 0 {
            return;
        }
        // The authority calls `ossl_provider_deinit_child(ctx)` here when
        // `ischild` is set. `OSSL_LIB_CTX_new_child` is 6.6d, so no context can
        // have that flag yet; the call goes here when it can.
        context_deinit(ctx);
        // SAFETY: `ctx` is not the default, so this call owns it, and
        // `context_deinit` has released everything it held. It is freed exactly
        // once.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE) };
    })
}

/// `int OSSL_LIB_CTX_get_conf_diagnostics(OSSL_LIB_CTX *ctx)`
///
/// A NULL context reads the default's value, which is how a caller sets or reads
/// this on the default context without naming it.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_get_conf_diagnostics(ctx: *mut c_void) -> c_int {
    guard_ffi(0, || {
        let ctx = concrete(ctx.cast::<OsslLibCtx>());
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `concrete` answers either the caller's live context or the
        // process-global default, and the field is a plain `int` read.
        unsafe { (*ctx).conf_diagnostics }
    })
}

/// `void OSSL_LIB_CTX_set_conf_diagnostics(OSSL_LIB_CTX *ctx, int value)`
///
/// The value is stored verbatim; the authority does not range-check it, so a
/// negative value is a legal thing to set and to read back.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_set_conf_diagnostics(ctx: *mut c_void, value: c_int) {
    guard_ffi((), || {
        let ctx = concrete(ctx.cast::<OsslLibCtx>());
        if ctx.is_null() {
            return;
        }
        // SAFETY: as `OSSL_LIB_CTX_get_conf_diagnostics`; the write is to a
        // plain `int` field of a context this process owns.
        unsafe { (*ctx).conf_diagnostics = value };
    })
}

/// `void *OSSL_LIB_CTX_get_data(OSSL_LIB_CTX *ctx, int index)`
///
/// The index registry. The arms are the authority's, in the authority's order,
/// and there is deliberately **no bounds check** and no range guard: out-of-range
/// indices — negative ones and 23 and above — fall through to NULL exactly as
/// they do in the authority, and indices 7, 8, 9 and 13 are dead in the same way,
/// because the authority's `switch` has no arm for them either.
///
/// A slot whose owning stratum has not landed answers NULL. That is a **recorded
/// obligation, not a divergence that has been accepted**: the module
/// documentation carries the per-slot owner table, and
/// `docs/PHASE-6-SUBPHASES.md` requires every one of them to be filled before
/// this stratum can close.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_LIB_CTX_get_data(ctx: *mut c_void, index: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let ctx = concrete(ctx.cast::<OsslLibCtx>());
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `concrete` answers the caller's live context or the
        // process-global default; every read below is of a plain pointer field.
        // `COMP_METHODS` takes the field's *address*, which is the authority's
        // own arm and is why that slot is non-NULL for an empty context.
        unsafe {
            match index {
                0 => (*ctx).evp_method_store,
                1 => (*ctx).provider_store,
                OSSL_LIB_CTX_PROPERTY_DEFN_INDEX => (*ctx).property_defns,
                3 => (*ctx).property_string_data,
                4 => (*ctx).namemap,
                5 => (*ctx).drbg,
                6 => (*ctx).drbg_nonce,
                10 => (*ctx).encoder_store,
                11 => (*ctx).decoder_store,
                12 => (*ctx).self_test_cb,
                OSSL_LIB_CTX_GLOBAL_PROPERTIES_INDEX => (*ctx).global_properties,
                15 => (*ctx).store_loader_store,
                16 => (*ctx).provider_conf,
                17 => (*ctx).bio_core,
                18 => (*ctx).child_provider,
                19 => (*ctx).threads,
                20 => (*ctx).decoder_cache,
                21 => ptr::addr_of_mut!((*ctx).comp_methods).cast::<c_void>(),
                22 => (*ctx).indicator_cb,
                // 7, 8 and 13 were slots the authority reuses or leaves
                // unassigned, 9 is FIPS-only and this profile is not a FIPS
                // build, and anything outside the index space is the authority's
                // `default:` arm. All of them answer NULL there and here.
                _ => ptr::null_mut(),
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Internals later subphases call
// ---------------------------------------------------------------------------
//
// These are the parts of `crypto/context.c` that are not exports. They are
// `pub(crate)` and carry no `#[no_mangle]`, because they are not part of the
// authority's ABI surface (`docs/PARITY_MODEL.md`: only exported symbols are).
//
// Nothing in this crate calls them yet, so each carries a `dead_code` allowance
// rather than being removed: they are the interfaces the next subphases are
// written against, and a removal would be a silent narrowing of the module.

/// `void *ossl_lib_ctx_get_data(OSSL_LIB_CTX *ctx, int index)` — the internal
/// spelling of the export. The public function is a direct forward in the
/// authority, so it is a direct call here.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_get_data(ctx: *mut c_void, index: c_int) -> *mut c_void {
    // SAFETY: `OSSL_LIB_CTX_get_data`'s contract is this function's contract:
    // the caller passes NULL or a live context.
    unsafe { OSSL_LIB_CTX_get_data(ctx, index) }
}

/// `OSSL_LIB_CTX *ossl_lib_ctx_get_concrete(OSSL_LIB_CTX *ctx)` — internal.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_get_concrete(ctx: *mut c_void) -> *mut c_void {
    concrete(ctx.cast::<OsslLibCtx>()).cast::<c_void>()
}

/// `int ossl_lib_ctx_is_default(OSSL_LIB_CTX *ctx)` — internal.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_is_default_symbol(ctx: *mut c_void) -> c_int {
    lib_ctx_is_default(ctx.cast::<OsslLibCtx>())
}

/// `int ossl_lib_ctx_is_global_default(OSSL_LIB_CTX *ctx)` — internal. Answers 1
/// when the context resolves to the process-global object, which is *not* the
/// same question as [`lib_ctx_is_default_symbol`]: a thread that installed the
/// global default explicitly has it as its default and it is the global object.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_is_global_default(ctx: *mut c_void) -> c_int {
    if concrete(ctx.cast::<OsslLibCtx>()) == global_default() {
        1
    } else {
        0
    }
}

/// `int ossl_lib_ctx_write_lock(OSSL_LIB_CTX *ctx)` — internal. The three lock
/// helpers all answer 0 for a NULL context, which is how the property code
/// reports "no context" rather than "lock failed".
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_write_lock(ctx: *mut c_void) -> c_int {
    let ctx = concrete(ctx.cast::<OsslLibCtx>());
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live, so its lock was created by `context_init`;
    // `CRYPTO_THREAD_write_lock` answers 0 for a NULL lock.
    unsafe { CRYPTO_THREAD_write_lock((*ctx).lock) }
}

/// `int ossl_lib_ctx_read_lock(OSSL_LIB_CTX *ctx)` — internal.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_read_lock(ctx: *mut c_void) -> c_int {
    let ctx = concrete(ctx.cast::<OsslLibCtx>());
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: as `lib_ctx_write_lock`.
    unsafe { CRYPTO_THREAD_read_lock((*ctx).lock) }
}

/// `int ossl_lib_ctx_unlock(OSSL_LIB_CTX *ctx)` — internal.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn lib_ctx_unlock(ctx: *mut c_void) -> c_int {
    let ctx = concrete(ctx.cast::<OsslLibCtx>());
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: as `lib_ctx_write_lock`.
    unsafe { CRYPTO_THREAD_unlock((*ctx).lock) }
}

/// `void ossl_lib_ctx_default_deinit(void)` — internal, called by
/// `OPENSSL_cleanup` at process exit.
///
/// Releases the global default and the thread-local key. It is idempotent: the
/// authority returns immediately when the initialiser never ran, and
/// `OPENSSL_cleanup` can be called more than once by a program that also lets
/// `atexit` run.
#[allow(dead_code)] // unreachable until `OPENSSL_cleanup` calls it
pub(crate) fn lib_ctx_default_deinit() {
    if !DEFAULT_CONTEXT_INITED.swap(false, Ordering::AcqRel) {
        return;
    }
    context_deinit(global_default());
    // SAFETY: the key was created by the once whose success the flag recorded,
    // and the flag has just been cleared, so this runs at most once.
    unsafe {
        CRYPTO_THREAD_cleanup_local(
            DEFAULT_CONTEXT_THREAD_LOCAL
                .as_ptr()
                .cast::<CryptoThreadLocal>(),
        )
    };
}

/// `void ossl_release_default_drbg_ctx(void)` — internal. Phase 9 owns the DRBG
/// slot; this is here because the authority's only caller is the cleanup path
/// this module drives, and a slot release belongs with the slot.
#[allow(dead_code)] // unreachable until the DRBG slot exists
pub(crate) fn release_default_drbg_ctx() {
    // SAFETY: the global default object exists for the life of the process; the
    // field is a plain pointer and Phase 9 has not filled it yet, so this is a
    // NULL store today and the release goes on this line when it lands.
    unsafe { (*global_default()).drbg = ptr::null_mut() };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `COMP_METHODS` slot answers the *address of the field*, so it is
    /// non-NULL for a context nothing has ever filled. This is the one arm whose
    /// answer this stratum can be held to today, and it is also the arm most
    /// likely to be "simplified" into returning the field's value — which would
    /// answer NULL for every context and silently break a caller that only tests
    /// the pointer.
    #[test]
    fn comp_methods_slot_is_an_interior_address() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` was just created and has not been released.
        let slot = unsafe { OSSL_LIB_CTX_get_data(ctx, 21) };
        assert!(!slot.is_null());
        assert_ne!(slot, ctx);
        // SAFETY: as above.
        assert_eq!(slot, unsafe { OSSL_LIB_CTX_get_data(ctx, 21) });
        let other = OSSL_LIB_CTX_new();
        // SAFETY: both contexts are live.
        assert_ne!(slot, unsafe { OSSL_LIB_CTX_get_data(other, 21) });
        // SAFETY: both are non-default contexts and have not been released.
        unsafe {
            OSSL_LIB_CTX_free(other);
            OSSL_LIB_CTX_free(ctx);
        }
    }

    /// The dead indices and the out-of-range ones answer NULL. The distinction
    /// that matters is that a *dead* index is dead in the authority as well, so
    /// this test pins the boundary rather than the slots still owed.
    #[test]
    fn the_index_table_boundary() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        for dead in [-1, 7, 8, 9, 13, 23, 24, 255] {
            // SAFETY: `ctx` is live.
            let answer = unsafe { OSSL_LIB_CTX_get_data(ctx, dead) };
            assert!(answer.is_null(), "index {dead} must answer NULL");
        }
        // SAFETY: `ctx` is live and is not the default.
        unsafe { OSSL_LIB_CTX_free(ctx) };
    }

    /// `conf_diagnostics` is per-context state, and a NULL context reads the
    /// default's value rather than a third one.
    #[test]
    fn conf_diagnostics_is_per_context() {
        let a = OSSL_LIB_CTX_new();
        let b = OSSL_LIB_CTX_new();
        assert!(!a.is_null() && !b.is_null());
        // SAFETY: both contexts are live; the NULL calls resolve to the default.
        unsafe {
            OSSL_LIB_CTX_set_conf_diagnostics(a, 7);
            assert_eq!(OSSL_LIB_CTX_get_conf_diagnostics(a), 7);
            assert_eq!(OSSL_LIB_CTX_get_conf_diagnostics(b), 0);
            OSSL_LIB_CTX_set_conf_diagnostics(a, -3);
            assert_eq!(OSSL_LIB_CTX_get_conf_diagnostics(a), -3);
            OSSL_LIB_CTX_set_conf_diagnostics(a, 0);
            OSSL_LIB_CTX_free(b);
            OSSL_LIB_CTX_free(a);
        }
    }

    /// The global default is one object, and freeing it is a no-op.
    #[test]
    fn the_global_default_is_stable_and_not_released() {
        let gd = OSSL_LIB_CTX_get0_global_default();
        assert!(!gd.is_null());
        assert_eq!(gd, OSSL_LIB_CTX_get0_global_default());
        assert_eq!(lib_ctx_is_global_default(gd), 1);
        // SAFETY: the global default is live; freeing it is the no-op under test.
        unsafe { OSSL_LIB_CTX_free(gd) };
        assert_eq!(gd, OSSL_LIB_CTX_get0_global_default());
    }
}
