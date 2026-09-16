//! Phase 6.8c — activation, deactivation, the fallback walk, and the operation query.
//!
//! Activation is **not** the reference count. A provider is referenced while something
//! holds it and *activated* while something is using it, and the two are tracked
//! separately (`refcnt` and `activatecnt`) because a provider must stay initialised
//! after its last deactivation until its last reference goes — the authority's own
//! comment in `ossl_provider_free` says other structures may still be holding it. So
//! `activatecnt` is a counter, `flag_activated` is a summary of "at least one", and the
//! *teardown* is in `ossl_provider_free` rather than here.
//!
//! ## The lock discipline is the hard part, and the authority states it as rules
//!
//! `provider_core.c`'s header lists three locks (`store`, `flag_lock`,
//! `activatecnt_lock`), a required acquisition order, and the prohibition on holding
//! any of them across an upcall. The functions below follow that order, and each
//! releases before the operations that can make upcalls — the child callbacks, the
//! parent refcount, the decoder-cache flush.
//!
//! Two details are easy to get backwards:
//!
//! * `provider_activate` and `provider_deactivate` both take the store's lock as a
//!   **read** lock, but `flag_lock` is always a *write* lock, because the flag is what
//!   is being changed. The store is read-protected only because neither function
//!   mutates the provider stack.
//! * `provider_deactivate` answers the **count** and `-1` on failure, which is not a
//!   count: a caller cannot use truthiness and the authority's callers test `< 0`.
//!   `ossl_provider_deactivate` then converts that to a boolean, so the two have
//!   opposite conventions and `tests` below pins both.
//!
//! ## What is named rather than written, and why each is genuinely unreachable
//!
//! * the **`random_bytes` pair** — `ossl_rand_check_random_provider_on_load` and
//!   `_on_unload` are Phase 9's. The authority's guard is `prov->random_bytes != NULL`,
//!   and that field is set only by `provider_init`'s walk when a provider publishes
//!   `OSSL_FUNC_PROVIDER_RANDOM_BYTES`. So the call is reachable for a provider that
//!   does, and the check is **skipped** in this build. That is a real divergence and it
//!   is registered rather than hidden.
//! * the **parent pair and the child callbacks** — `ossl_provider_up_ref_parent`,
//!   `ossl_provider_free_parent` and the `store->child_cbs` walks are 6.8e's, and every
//!   one of them is guarded by `prov->ischild`, which nothing can set before 6.8e lands
//!   `ossl_provider_set_child`.
//! * **`create_provider_children`** — 6.8e's, and it walks a callback stack that only
//!   6.8e can push into. It is written here as a function that **asserts the stack is
//!   empty** and answers 1, so that if 6.8e ever registers a callback without adding the
//!   walk, this fails loudly instead of silently not creating children.
//! * **the store bridges** — `provider_flush_store_cache` and
//!   `provider_remove_store_methods` call the four method-store flush/remove pairs,
//!   which is [`crate::provider::stores`]'s subject and its module doc explains why each
//!   delegation is a checked invariant rather than a stub.
//! * **`ossl_provider_random_bytes`** — the provider's own callback, invoked through the
//!   pointer `provider_init` stored. It is written, because the pointer and the
//!   invocation are both this stratum's; what is missing is a caller, which is Phase 9's
//!   RAND, and that is why it carries a dead-code allowance.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use crate::context::lib_ctx_is_default_symbol;
use crate::params::OsslParam;
use crate::provider::init::provider_init;
use crate::provider::stores::{
    evp_method_store_cache_flush, evp_method_store_remove_all_provided, ossl_decoder_cache_flush,
    ossl_decoder_store_cache_flush, ossl_decoder_store_remove_all_provided,
    ossl_encoder_store_cache_flush, ossl_encoder_store_remove_all_provided,
    ossl_store_loader_store_cache_flush, ossl_store_loader_store_remove_all_provided,
};
use crate::provider::{
    c_strcmp, get_provider_store, ossl_provider_find, ossl_provider_free, provider_new,
    OsslProvider, ProviderStore, FILE, FLAG_ACTIVATED,
};
use crate::runtime::err::{err_sites, raise_site, ERR_get_next_error_library};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock, CRYPTO_atomic_add,
};

// `OSSL_CALLBACK` is declared once, in `src/selftest/mod.rs`, and re-exported here so this
// stratum's query surface uses one spelling of one typedef. A `use` rather than a second
// `type` alias, deliberately: the prototype court resolves `type` aliases per file, and two
// aliases for one C typedef would give it two spellings to keep in agreement.
pub(crate) use crate::selftest::OsslCallback;

/// `OPENSSL_free(prov->operation_bits)` in `provider_remove_store_methods`.
const L_REMOVE_METHODS_FREE_BITS: c_int = 1373;

/// `typedef int (*OSSL_CALLBACK)(const OSSL_PARAM params[], void *arg)` — `openssl/core.h`.
///
/// `typedef int (*OSSL_provider_doall_cb_fn)(OSSL_PROVIDER *provider, void *cbdata)`.
///
/// The signature `ossl_provider_doall_activated` takes, and the one
/// `OSSL_PROVIDER_do_all`'s public prototype spells inline.
// Unnamed parameters, for the reason `ProviderInitFn` states: `ABI-PROTOTYPE` reads a
// function pointer's *types*, and a named argument is not one.
pub(crate) type ProviderDoAllFn = unsafe extern "C" fn(*mut OsslProvider, *mut c_void) -> c_int;

/// `static int create_provider_children(OSSL_PROVIDER *prov)`.
///
/// Called with the store lock held, which is why nothing here takes one.
///
/// The authority walks `store->child_cbs` and calls each registered `create_cb`. That stack
/// can only be pushed into by `ossl_provider_register_child_cb`, which is **6.8e**'s, so in
/// this build it is empty and the authority's own loop over an empty stack answers 1. This
/// version *checks* the emptiness rather than assuming it: if a callback is ever registered
/// without the walk being written, the check fires instead of children silently not being
/// created.
///
/// # Safety
/// `prov` must be live and already inserted into a store.
unsafe fn create_provider_children(prov: *mut OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let store = unsafe { (*prov).store };
    if store.is_null() {
        return 1;
    }
    // SAFETY: `store` is live, so `child_cbs` is a live stack created with it.
    let n = unsafe { OPENSSL_sk_num((*store).child_cbs) };
    assert!(
        n == 0,
        "openssl-rs: a provider child callback is registered, but 6.8e's walk over \
         store->child_cbs has not landed; children would not be created"
    );
    1
}

/// `static int provider_flush_store_cache(const OSSL_PROVIDER *prov)`.
///
/// Called with the store lock **not** held, and it takes the store's read lock only to read
/// the `freeing` bit. A store being torn down answers 1 without touching the caches,
/// because the caches are released with it.
///
/// The sum is compared against 4, so an absent store (which answers 1 from each bridge)
/// counts as success — a detail [`crate::provider::stores`] pins with a unit test.
///
/// # Safety
/// `prov` must be live.
unsafe fn provider_flush_store_cache(prov: *const OsslProvider) -> c_int {
    // SAFETY: `prov` is live, so `libctx` is the context it was constructed against.
    let libctx = unsafe { (*prov).libctx };
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so its lock exists.
    let freeing = unsafe {
        if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return 0;
        }
        let freeing = (*store).freeing;
        CRYPTO_THREAD_unlock((*store).lock);
        freeing
    };
    if freeing != 0 {
        return 1;
    }
    // SAFETY: `libctx` is NULL or live, which is each bridge's contract.
    let acc = unsafe {
        evp_method_store_cache_flush(libctx)
            + ossl_encoder_store_cache_flush(libctx)
            + ossl_decoder_store_cache_flush(libctx)
            + ossl_store_loader_store_cache_flush(libctx)
    };
    c_int::from(acc == 4)
}

/// `static int provider_remove_store_methods(OSSL_PROVIDER *prov)`.
///
/// The deactivation counterpart: the provider's operation bitset is released under
/// `opbits_lock` — *before* the caches are swept, and under its own lock rather than the
/// store's — and then the four stores drop everything that came from this provider.
///
/// Unlike the flush, this one **is** the last use of `opbits_lock`'s contents, so the lock
/// is taken as a write lock and released before the sweep. A failure to take it answers 0,
/// which `ossl_provider_deactivate` reports as a failed deactivation.
///
/// # Safety
/// `prov` must be live.
unsafe fn provider_remove_store_methods(prov: *mut OsslProvider) -> c_int {
    // SAFETY: `prov` is live.
    let libctx = unsafe { (*prov).libctx };
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so its lock exists.
    let freeing = unsafe {
        if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return 0;
        }
        let freeing = (*store).freeing;
        CRYPTO_THREAD_unlock((*store).lock);
        freeing
    };
    if freeing != 0 {
        return 1;
    }
    // SAFETY: `prov` is live, so `opbits_lock` and `operation_bits` are live.
    if unsafe {
        if CRYPTO_THREAD_write_lock((*prov).opbits_lock) == 0 {
            return 0;
        }
        if !(*prov).operation_bits.is_null() {
            CRYPTO_free(
                (*prov).operation_bits.cast::<c_void>(),
                FILE,
                L_REMOVE_METHODS_FREE_BITS,
            );
            (*prov).operation_bits = ptr::null_mut();
        }
        (*prov).operation_bits_sz = 0;
        CRYPTO_THREAD_unlock((*prov).opbits_lock);
        1
    } == 0
    {
        return 0;
    }
    // SAFETY: `prov` is live.
    let acc = unsafe {
        evp_method_store_remove_all_provided(prov)
            + ossl_encoder_store_remove_all_provided(prov)
            + ossl_decoder_store_remove_all_provided(prov)
            + ossl_store_loader_store_remove_all_provided(prov)
    };
    c_int::from(acc == 4)
}

/// `static int provider_deactivate(OSSL_PROVIDER *prov, int upcalls, int removechildren)`.
///
/// Answers the activation count on success and **-1** on failure.
///
/// The store lock is taken only when the provider *has* a store, because a provider that has
/// not been added to one has not been shared with another thread — the authority's own
/// reasoning, and the reason `lock` is a variable rather than a constant.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn provider_deactivate(
    prov: *mut OsslProvider,
    upcalls: c_int,
    removechildren: c_int,
) -> c_int {
    if prov.is_null() {
        return -1;
    }
    // Phase 9: `if ((*prov).random_bytes != NULL && !ossl_rand_check_random_provider_on_unload(
    // (*prov).libctx, prov)) return -1;` — `random_bytes` is set only for a provider that
    // publishes `OSSL_FUNC_PROVIDER_RANDOM_BYTES`, and the check is skipped in this build.
    // Registered as a divergence rather than hidden.

    // SAFETY: `prov` is live.
    let libctx = unsafe { (*prov).libctx };
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    let lock = !store.is_null();

    // SAFETY: `store` is live when `lock` is set, so every lock named here exists.
    // `count` is bound rather than returned directly because the deactivation continues after
    // the locks are released -- the flag clear, the child walk and the decoder-cache flush all
    // need it. `provider_activate` has no such tail and so returns its block's value.
    let count = unsafe {
        if lock && CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return -1;
        }
        if lock && CRYPTO_THREAD_write_lock((*prov).flag_lock) == 0 {
            CRYPTO_THREAD_unlock((*store).lock);
            return -1;
        }
        let mut count = 0;
        let added = crate::runtime::thread::CRYPTO_atomic_add(
            ptr::addr_of_mut!((*prov).activatecnt),
            -1,
            ptr::addr_of_mut!(count),
            (*prov).activatecnt_lock,
        );
        if added == 0 {
            if lock {
                CRYPTO_THREAD_unlock((*prov).flag_lock);
                CRYPTO_THREAD_unlock((*store).lock);
            }
            return -1;
        }
        count
    };

    // 6.8e: the `count >= 1 && prov->ischild && upcalls` arm sets a `freeparent` flag whose
    // `ossl_provider_free_parent(prov, 1)` runs **after** the locks are released. `ischild`
    // is 0 until 6.8e lands `ossl_provider_set_child`, so the flag has nothing to set.
    let _ = upcalls;

    // SAFETY: `prov` is live.
    unsafe {
        if count < 1 {
            (*prov).flags &= !FLAG_ACTIVATED;
        }
    }
    // 6.8e: the authority's `else removechildren = 0;` — a provider with activations left
    // cannot have its children removed. With `ischild` 0 there is nothing to remove either
    // way, so the watch over the parameter is the whole of it.
    let _ = removechildren;

    if lock {
        // SAFETY: both locks are held and `store` is live.
        unsafe {
            CRYPTO_THREAD_unlock((*prov).flag_lock);
            CRYPTO_THREAD_unlock((*store).lock);
        }
        // Outside the lock, and the authority's comment says why: other threads tolerate
        // getting the wrong result briefly while creating `OSSL_DECODER_CTX`s.
        if count < 1 {
            // SAFETY: `libctx` is NULL or the live context this provider belongs to.
            unsafe { ossl_decoder_cache_flush(libctx) };
        }
    }
    count
}

/// `static int provider_activate(OSSL_PROVIDER *prov, int lock, int upcalls)`.
///
/// `lock` is a **parameter** rather than something decided here, and the authority's caller
/// passes 0 when it already holds the store lock. When the provider has no store yet the
/// parameter is overridden to 0 and `provider_init` is called, which is the only place
/// initialisation happens.
///
/// The `store` local is read **once**, before `provider_init`, and is deliberately not
/// re-read afterwards: the authority's `count == 1 && store != NULL` therefore still tests
/// the pre-init value, so a provider that had no store when it was activated does not
/// create children on that pass. Re-reading the field would be a plausible "fix" that
/// changes behaviour.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn provider_activate(
    prov: *mut OsslProvider,
    mut lock: c_int,
    upcalls: c_int,
) -> c_int {
    // SAFETY: `prov` is live.
    let store: *mut ProviderStore = unsafe { (*prov).store };
    if store.is_null() {
        lock = 0;
        // SAFETY: `prov` is live.
        if unsafe { provider_init(prov) } == 0 {
            return -1;
        }
    }

    // Phase 9: the `random_bytes` guard described in `provider_deactivate`.
    // 6.8e: `if (prov->ischild && upcalls && !ossl_provider_up_ref_parent(prov, 1)) return -1;`
    // — guarded by a flag nothing can set yet, and the failure arms below would have to
    // call `ossl_provider_free_parent(prov, 1)` to match.
    let _ = upcalls;

    // SAFETY: `store` is live when `lock` is set, so every lock named here exists.
    unsafe {
        if lock != 0 && CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return -1;
        }
        if lock != 0 && CRYPTO_THREAD_write_lock((*prov).flag_lock) == 0 {
            CRYPTO_THREAD_unlock((*store).lock);
            return -1;
        }
        let mut count = -1;
        let added = crate::runtime::thread::CRYPTO_atomic_add(
            ptr::addr_of_mut!((*prov).activatecnt),
            1,
            ptr::addr_of_mut!(count),
            (*prov).activatecnt_lock,
        );
        let mut ret = 1;
        if added != 0 {
            (*prov).flags |= FLAG_ACTIVATED;
            if count == 1 && !store.is_null() {
                ret = create_provider_children(prov);
            }
        }
        if lock != 0 {
            CRYPTO_THREAD_unlock((*prov).flag_lock);
            CRYPTO_THREAD_unlock((*store).lock);
            if count == 1 {
                // Outside the lock, as in the authority.
                ossl_decoder_cache_flush((*prov).libctx);
            }
        }
        if ret == 0 {
            return -1;
        }
        count
    }
}

/// `int ossl_provider_activate(OSSL_PROVIDER *prov, int upcalls, int aschild)`.
///
/// Two conventions in one function. `aschild` is a **no-op for a non-child**: the authority
/// returns *success* rather than declining, because the caller asked for something that is
/// already true. And the answer for a real activation is a boolean, but the flush is
/// consulted only on the **transition** from zero activations to one — `count == 1` — since
/// a provider that was already active has nothing new to publish.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_activate(
    prov: *mut OsslProvider,
    upcalls: c_int,
    aschild: c_int,
) -> c_int {
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live.
    if aschild != 0 && unsafe { (*prov).ischild } == 0 {
        return 1;
    }
    // SAFETY: `prov` is live.
    let count = unsafe { provider_activate(prov, 1, upcalls) };
    if count > 0 {
        if count == 1 {
            // SAFETY: `prov` is live.
            return unsafe { provider_flush_store_cache(prov) };
        }
        return 1;
    }
    0
}

/// `int ossl_provider_deactivate(OSSL_PROVIDER *prov, int removechildren)`.
///
/// Answers 1 for a non-negative count, so a caller sees a boolean rather than a count — the
/// opposite of the static function it wraps. And the store sweep happens only on the
/// **transition** to zero activations, mirroring the flush above.
///
/// # Safety
/// `prov` must be NULL or live.
pub(crate) unsafe fn ossl_provider_deactivate(
    prov: *mut OsslProvider,
    removechildren: c_int,
) -> c_int {
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live.
    let count = unsafe { provider_deactivate(prov, 1, removechildren) };
    if count < 0 {
        return 0;
    }
    if count == 0 {
        // SAFETY: `prov` is live.
        return unsafe { provider_remove_store_methods(prov) };
    }
    1
}

/// `void *ossl_provider_ctx(const OSSL_PROVIDER *prov)`.
///
/// `OSSL_ALGORITHM` — `openssl/core.h`: `typedef struct ossl_algorithm_st OSSL_ALGORITHM;`.
///
/// **An opaque forward declaration, not the definition.** Phase 7 owns the struct, because
/// its three members (`algorithm_names`, `property_definition`, `algorithm_description`) plus
/// the two dispatch pointers are what the fetch machinery walks. What this stratum needs is
/// only that `ossl_provider_query_operation`'s return type have the right **shape**, and a
/// pointer's pointee shape is the same whether the pointee is complete or opaque — the
/// prototype court's canonical form discards the pointee's name for exactly that reason.
#[repr(C)]
pub struct OsslAlgorithm {
    /// The authority's struct is not `#[repr(C)]`-complete here, so this type has no
    /// constructible values; the field exists only so the type is not a ZST by accident.
    _opaque: [u8; 0],
}

/// `typedef int (*OSSL_provider_random_bytes_fn)(void *provctx, int which, void *buf,
/// size_t n, unsigned int strength)` — the provider-side dispatch entry point.
type ProviderRandomBytesFn =
    unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize, core::ffi::c_uint) -> c_int;

// ---------------------------------------------------------------------------
// The fallback walk: `provider_activate_fallbacks` and its two callers
// ---------------------------------------------------------------------------

/// `static int provider_activate_fallbacks(struct provider_store_st *store)`.
///
/// Runs at most once per store, and the `use_fallbacks` flag is the latch: it is read under
/// the store's **read** lock, and if it is set the lock is retaken as a **write** lock and
/// the flag re-read, because another thread may have won the race in between. Only then does
/// the walk run, holding the write lock across the providers' own `init` calls — with the
/// authority's explicit justification, which is worth repeating because it is the one place
/// this library deliberately calls a provider under a lock: *"fallbacks are never third
/// party providers so we accept this."*
///
/// Two details are the authority's and are easy to "fix" wrongly:
///
/// * The internal `provider_new` is used rather than `ossl_provider_new`, precisely to avoid
///   a call loop: `ossl_provider_new` searches the store, and the store's lock is held.
/// * `provider_activate(prov, 0, 0)` — the lock argument is **0** because the store lock is
///   already held, and the upcalls argument is 0 because a fallback has no parent.
///
/// The provider's parameters come from the store's own builtin table, matched by name: a
/// caller who registered `default` through `OSSL_PROVIDER_add_builtin` with parameters has
/// those parameters applied to the instance the walk creates.
///
/// **Registered residual.** The three `init` pointers in
/// [`crate::provider::PREDEFINED_PROVIDERS`] are 7/8's, so `provider_new` here receives
/// `None` for each of them and `provider_activate` therefore takes `provider_init` down the
/// *module* branch, where `DSO_load` fails. The walk consequently answers 0 where the
/// authority answers 1. That is a real divergence, observable through
/// `OSSL_PROVIDER_available` and `OSSL_PROVIDER_do_all`, and it is recorded rather than
/// smoothed over: it is D116's third residual and it is named in `docs/PHASE-6-SUBPHASES.md`'s
/// 6.8c row.
///
/// # Safety
/// `store` must be a live store.
unsafe fn provider_activate_fallbacks(store: *mut ProviderStore) -> c_int {
    // SAFETY: `store` is live, so `use_fallbacks` is readable and `lock` exists.
    let use_fallbacks = unsafe {
        if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return 0;
        }
        let flag = (*store).use_fallbacks;
        CRYPTO_THREAD_unlock((*store).lock);
        flag
    };
    if use_fallbacks == 0 {
        return 1;
    }
    // SAFETY: `store` is live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*store).lock) == 0 {
            return 0;
        }
        // Checked again, just in case another thread changed it.
        if (*store).use_fallbacks == 0 {
            CRYPTO_THREAD_unlock((*store).lock);
            return 1;
        }
    }

    let mut activated: c_int = 0;
    let mut ret: c_int = 0;
    let mut failed = false;
    for row in crate::provider::PREDEFINED_PROVIDERS.iter() {
        // The terminator row: `p->name != NULL`.
        if row.name.to_bytes().is_empty() {
            break;
        }
        if row.is_fallback == 0 {
            continue;
        }
        // SAFETY: `store` is live, and the name is a `'static` literal with a terminator.
        let params = unsafe { find_registered_params(store, row.name.as_ptr()) };
        // SAFETY: `row.name` is a `'static` NUL-terminated literal; `params` is NULL or the
        // store's own list, which outlives the object this creates because `provider_new`
        // deep-copies it.
        let prov = unsafe { provider_new(row.name.as_ptr(), None, params) };
        if prov.is_null() {
            failed = true;
            break;
        }
        // SAFETY: `prov` is live and `store` is live.
        unsafe {
            // The internal constructor with a `None` entry point is a *builtin* with no init
            // function only if the template had one; the authority sets `libctx` and the
            // error library number here rather than in the constructor.
            (*prov).libctx = (*store).libctx;
            (*prov).error_lib = ERR_get_next_error_library();
        }
        // SAFETY: the store's lock is held, which is why the lock argument is 0.
        if unsafe { provider_activate(prov, 0, 0) } < 0 {
            // SAFETY: `prov` is live and has no store yet.
            unsafe { ossl_provider_free(prov) };
            failed = true;
            break;
        }
        // SAFETY: `prov` is live; `store` is live and its stack outlives the provider.
        unsafe {
            (*prov).store = store;
            if OPENSSL_sk_push((*store).providers, prov.cast::<c_void>()) == 0 {
                ossl_provider_free(prov);
                failed = true;
                break;
            }
        }
        activated += 1;
    }

    if !failed && activated > 0 {
        // SAFETY: `store` is live and the write lock is held.
        unsafe { (*store).use_fallbacks = 0 };
        ret = 1;
    }
    // SAFETY: `store` is live and the write lock is held.
    unsafe { CRYPTO_THREAD_unlock((*store).lock) };
    ret
}

/// The authority's inner loop: walk the store's registered builtin table by name and answer
/// the matching row's `parameters`, or NULL when no row matches.
///
/// A linear scan with `strcmp`, stopping at the first match, over an array of
/// `store->numprovinfo` entries.
///
/// # Safety
/// `store` must be live; `name` NUL-terminated.
unsafe fn find_registered_params(
    store: *mut ProviderStore,
    name: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: `store` is live.
    let (info, count) = unsafe { ((*store).provinfo, (*store).numprovinfo) };
    let mut i = 0;
    while i < count {
        // SAFETY: `info` is a live array of `count` entries and `i < count`, so entry `i` is
        // in bounds and its `name` is owned and NUL-terminated by construction.
        let entry_name = unsafe { (*info.add(i)).name };
        if !entry_name.is_null() {
            // SAFETY: both names are NUL-terminated.
            if unsafe { c_strcmp(entry_name, name) } == 0 {
                // SAFETY: entry `i` is in bounds.
                return unsafe { (*info.add(i)).parameters };
            }
        }
        i += 1;
    }
    ptr::null_mut()
}

/// `int ossl_provider_activate_fallbacks(OSSL_LIB_CTX *ctx)`.
///
/// A context with no store answers 0 rather than 1: the caller asked for something that
/// requires a store, and there is none.
///
/// # Safety
/// `ctx` must be NULL or live.
#[allow(dead_code)] // unreachable until 6.11's loader surface calls it
pub(crate) unsafe fn ossl_provider_activate_fallbacks(ctx: *mut c_void) -> c_int {
    // SAFETY: `ctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(ctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live and non-NULL.
    unsafe { provider_activate_fallbacks(store) }
}

/// `int ossl_provider_doall_activated(OSSL_LIB_CTX *ctx, int (*cb)(OSSL_PROVIDER *, void *),
/// void *cbdata)`.
///
/// The authority's shape is a **three-phase sweep**, and each phase exists for a reason that
/// is visible in the code:
///
/// 1. Under the store's **read** lock, walk the provider stack *backwards* taking a copy
///    (`sk_dup`) and, for each already-activated provider, up-ref it **and** up its activation
///    count; a provider that is not activated is deleted from the copy and `max` shrinks.
///    Working backwards is what makes the deletion safe, and `CRYPTO_UP_REF` is called
///    directly rather than through `ossl_provider_up_ref` to avoid upping the *parent*, which
///    must not happen while locks are held.
/// 2. Outside every lock, call the user callback for each surviving provider. A callback that
///    answers 0 stops the sweep and is **not** a failure of the sweep's own book-keeping.
/// 3. Walk whatever is left — from `curr + 1` on the early-exit path, from 0 otherwise —
///    undoing phase 1's work. A count that reaches 0 is not simply left there: the count is
///    raised again and a full `provider_deactivate(prov, 0, 1)` runs, because deactivation
///    needs the write lock that phase 1 deliberately avoided.
///
/// **The `assert(ref > 0)` in the authority is compiled out.** `NDEBUG` is in this profile's
/// defines (`src/context/namemap.rs` records the same build fact for `ossl_assert`), so the
/// authority's own comment — *"Not much we can do if this assert ever fails. So we don't use
/// `ossl_assert` here"* — means the line is a no-op and is **not** reproduced. Writing a
/// live assertion there would be a divergence, not a fidelity.
///
/// # Safety
/// `ctx` NULL or live; `cb` non-NULL and valid for every provider on the stack.
#[allow(dead_code)] // unreachable until 6.11's provider registry calls it
pub(crate) unsafe fn ossl_provider_doall_activated(
    ctx: *mut c_void,
    cb: ProviderDoAllFn,
    cbdata: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(ctx) };

    // Unless the context is the default one this is a no-op, and on the default context it
    // loads `openssl.cnf` first, so a provider named only in the configuration file is
    // present before the sweep.
    //
    // SAFETY: `lib_ctx_is_default_symbol` and `OPENSSL_init_crypto` are SAFE functions in
    // this crate, so there is nothing to guard here (D113).
    if lib_ctx_is_default_symbol(ctx) != 0 {
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, ptr::null());
    }

    if store.is_null() {
        return 1;
    }
    // SAFETY: `store` is live.
    if unsafe { provider_activate_fallbacks(store) } == 0 {
        return 0;
    }

    let mut ret: c_int = 0;
    // `goto err_unlock` in the authority. Rust has no `goto`, so the edge is a flag, and the
    // flag is only ever set immediately before breaking out of the walk. `curr` and `max` come
    // out of the lock scope because phase 3 resumes from them: on the early-unlock path `curr`
    // still names the provider whose lock could not be taken, so the undo loop starts *after*
    // it, and on every other path the callback phase sets it.
    //
    // SAFETY: `store` is live, so `providers` and `lock` are live; every provider on the copy
    // is one the store holds a reference to.
    let (provs, mut curr, max, unlocked_early) = unsafe {
        if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return 0;
        }
        let provs = OPENSSL_sk_dup((*store).providers);
        if provs.is_null() {
            CRYPTO_THREAD_unlock((*store).lock);
            return 0;
        }
        let mut max = OPENSSL_sk_num(provs);
        let mut curr = max - 1;
        let mut unlocked_early = false;
        while curr >= 0 {
            let prov = OPENSSL_sk_value(provs, curr).cast::<OsslProvider>();
            if CRYPTO_THREAD_read_lock((*prov).flag_lock) == 0 {
                unlocked_early = true;
                break;
            }
            if (*prov).flags & FLAG_ACTIVATED != 0 {
                // `CRYPTO_UP_REF` from `internal/refcount.h`'s GNU branch:
                // `*ret = __atomic_fetch_add(&val, 1, __ATOMIC_RELAXED) + 1`.
                let reference = (*prov).refcnt.fetch_add(1, Ordering::Relaxed) + 1;
                if reference <= 0 {
                    CRYPTO_THREAD_unlock((*prov).flag_lock);
                    unlocked_early = true;
                    break;
                }
                // The activation count is raised so the provider stays active until after
                // the user callback has run. `CRYPTO_atomic_add`'s `*ret` is the *resulting*
                // value, so `ref` here is not compared against anything.
                let mut raised = 0;
                if CRYPTO_atomic_add(
                    ptr::addr_of_mut!((*prov).activatecnt),
                    1,
                    ptr::addr_of_mut!(raised),
                    (*prov).activatecnt_lock,
                ) == 0
                {
                    // `CRYPTO_DOWN_REF`: release fetch-sub with the conditional acquire
                    // fence. The raise failed, so it is undone here rather than in phase 3,
                    // because phase 3 will not see this provider incremented.
                    let old = (*prov).refcnt.fetch_sub(1, Ordering::Release) - 1;
                    if old == 0 {
                        core::sync::atomic::fence(Ordering::Acquire);
                    }
                    CRYPTO_THREAD_unlock((*prov).flag_lock);
                    unlocked_early = true;
                    break;
                }
            } else {
                // The provider is not activated, so it is deleted from the copy and `max`
                // shrinks. Working **backwards** is what makes the deletion safe: every
                // index below `curr` is still in the same place afterwards.
                OPENSSL_sk_delete(provs, curr);
                max -= 1;
            }
            CRYPTO_THREAD_unlock((*prov).flag_lock);
            curr -= 1;
        }
        CRYPTO_THREAD_unlock((*store).lock);
        (provs, curr, max, unlocked_early)
    };

    if !unlocked_early {
        // Phase 2: the user callback, outside every lock, from the start of the copy.
        curr = 0;
        while curr < max {
            // SAFETY: `provs` is live and `curr` is in range.
            let prov = unsafe { OPENSSL_sk_value(provs, curr).cast::<OsslProvider>() };
            // SAFETY: `cb` is the caller's, and the contract requires it to be valid for every
            // provider on the stack.
            if unsafe { cb(prov, cbdata) } == 0 {
                break;
            }
            curr += 1;
        }
        if curr == max {
            ret = 1;
        }
        // The authority's `curr = -1` before the finish loop, re-expressed: phase 3 walks the
        // whole copy on success and from the last-called provider on a callback refusal.
        if curr == max {
            curr = 0;
        }
    }

    // Phase 3: undo, from `curr` onwards.
    while curr < max {
        // SAFETY: `provs` is live and `curr` is in range.
        let prov = unsafe { OPENSSL_sk_value(provs, curr).cast::<OsslProvider>() };
        // SAFETY: `prov` is a live provider the store holds a reference to.
        unsafe {
            let mut down = 0;
            if CRYPTO_atomic_add(
                ptr::addr_of_mut!((*prov).activatecnt),
                -1,
                ptr::addr_of_mut!(down),
                (*prov).activatecnt_lock,
            ) == 0
            {
                ret = 0;
                curr += 1;
                continue;
            }
            if down < 1 {
                // The authority's re-raise, then a **full** deactivation: deactivating needs
                // the write lock phase 1 deliberately avoided taking.
                let mut raised = 0;
                if CRYPTO_atomic_add(
                    ptr::addr_of_mut!((*prov).activatecnt),
                    1,
                    ptr::addr_of_mut!(raised),
                    (*prov).activatecnt_lock,
                ) != 0
                {
                    provider_deactivate(prov, 0, 1);
                } else {
                    ret = 0;
                }
            }
            // `CRYPTO_DOWN_REF` — release fetch-sub with the conditional acquire fence —
            // answers `*ret > 0`, so a count at or below zero is the failure answer. The
            // `assert(ref > 0)` the authority follows it with is compiled out under `NDEBUG`
            // and is deliberately not reproduced as a live assertion.
            let old = (*prov).refcnt.fetch_sub(1, Ordering::Release) - 1;
            if old == 0 {
                core::sync::atomic::fence(Ordering::Acquire);
            }
            if old <= 0 {
                ret = 0;
            }
        }
        curr += 1;
    }
    // SAFETY: `provs` is the copy phase 1 took and phase 3 has finished with.
    unsafe { OPENSSL_sk_free(provs) };
    ret
}

/// `int OSSL_PROVIDER_available(OSSL_LIB_CTX *libctx, const char *name)`.
///
/// The fallback walk comes first, so asking whether a provider is available is what loads the
/// default one. `ossl_provider_find` then takes a reference the caller must release, which is
/// why the `flag_activated` read happens under `flag_lock` and the release after it.
///
/// # Safety
/// `libctx` NULL or live; `name` NUL-terminated.
#[allow(dead_code)] // unreachable until the 22 exports are declared
pub(crate) unsafe fn ossl_provider_available(libctx: *mut c_void, name: *const c_char) -> c_int {
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live and non-NULL.
    if unsafe { provider_activate_fallbacks(store) } == 0 {
        return 0;
    }
    // SAFETY: `libctx` is NULL or live and `name` is NUL-terminated; the answer carries a new
    // reference.
    let prov = unsafe { ossl_provider_find(libctx, name, 0) };
    if prov.is_null() {
        return 0;
    }
    // SAFETY: `prov` is live, so `flag_lock` exists and `flags` is readable under it.
    let available = unsafe {
        if CRYPTO_THREAD_read_lock((*prov).flag_lock) == 0 {
            return 0;
        }
        let available = (*prov).flags & FLAG_ACTIVATED;
        CRYPTO_THREAD_unlock((*prov).flag_lock);
        c_int::from(available != 0)
    };
    // SAFETY: `prov` is live and holds the reference `ossl_provider_find` took.
    unsafe { ossl_provider_free(prov) };
    available
}

/// `int ossl_provider_random_bytes(const OSSL_PROVIDER *prov, int which, void *buf,
/// size_t n, unsigned int strength)`.
///
/// Answers 0 when the provider publishes no `random_bytes` entry point, which is every
/// provider in this build. The invocation itself is written because the pointer and the call
/// are this stratum's; the *callers* are Phase 9's RAND, which is why it carries a dead-code
/// allowance rather than a hand-off.
///
/// # Safety
/// `prov` must be live; `buf` must be writable for `n` bytes when the provider has the
/// entry point.
#[allow(dead_code)] // unreachable until Phase 9's RAND calls it
pub(crate) unsafe fn ossl_provider_random_bytes(
    prov: *const OsslProvider,
    which: c_int,
    buf: *mut c_void,
    n: usize,
    strength: core::ffi::c_uint,
) -> c_int {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).random_bytes };
    if f.is_null() {
        return 0;
    }
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_random_bytes`,
    // whose signature is the one `ProviderRandomBytesFn` names; `provider_init` stored it
    // from the provider's dispatch table and nothing else writes the field.
    let f = unsafe { core::mem::transmute::<*mut c_void, ProviderRandomBytesFn>(f) };
    // SAFETY: `provctx` is the context the provider's own init function wrote, and `buf` is
    // writable for `n` bytes per this function's contract.
    unsafe { f((*prov).provctx, which, buf, n, strength) }
}

// ---------------------------------------------------------------------------
// The provider query surface: eight delegated calls and one bitset
// ---------------------------------------------------------------------------
//
// Seven of the eight are the same three lines: read the provider's field, test it for NULL,
// and if it is set call it with the provider's own context. The NULL-test answers are not
// uniform and are the whole content of the functions:
//
//   gettable_params      NULL field  -> NULL
//   get_params           NULL field  -> 0     (explicit, and *not* a pass-through)
//   self_test            NULL field  -> 1     ("assume the test passed")
//   get_capabilities     NULL field  -> 1     ("assume the capability exists")
//   query_operation      NULL field  -> NULL
//   unquery_operation    NULL field  -> no-op
//   random_bytes         NULL field  -> 0
//
// `self_test` is the one with a side effect on failure: a provider whose self-test answers 0
// has its store methods **removed**, including its operation bitset, so a failing self-test
// cannot leave a cached algorithm behind. Note that it removes the methods and still returns
// 0 — the removal is not an attempt to succeed on a retry.

/// `const OSSL_PARAM *ossl_provider_gettable_params(const OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live; the answer is the provider's own table.
pub(crate) unsafe fn ossl_provider_gettable_params(prov: *const OsslProvider) -> *const OsslParam {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).gettable_params };
    if f.is_null() {
        return ptr::null();
    }
    // SAFETY: the stored pointer is the provider's own
    // `OSSL_FUNC_provider_gettable_params`, whose signature is this one.
    let f = unsafe {
        core::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void) -> *const OsslParam>(
            f,
        )
    };
    // SAFETY: `provctx` is the context the provider's own init function wrote.
    unsafe { f((*prov).provctx) }
}

/// `int ossl_provider_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])`.
///
/// # Safety
/// `prov` must be live; `params` is the provider's array.
pub(crate) unsafe fn ossl_provider_get_params(
    prov: *const OsslProvider,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).get_params };
    if f.is_null() {
        return 0;
    }
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_get_params`.
    let f = unsafe {
        core::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int,
        >(f)
    };
    // SAFETY: `provctx` is the provider's own; `params` is the caller's array.
    unsafe { f((*prov).provctx, params) }
}

/// `int ossl_provider_self_test(const OSSL_PROVIDER *prov)`.
///
/// The one delegated call with a consequence: a **0** answer takes the provider's store
/// methods down through [`provider_remove_store_methods`], whose answer is deliberately
/// discarded — the authority writes `(void)` in front of it, because the self-test's own
/// verdict is what the caller must see.
///
/// # Safety
/// `prov` must be live.
pub(crate) unsafe fn ossl_provider_self_test(prov: *const OsslProvider) -> c_int {
    let mut ret: c_int = 1;
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).self_test };
    if !f.is_null() {
        // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_self_test`.
        let f = unsafe {
            core::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void) -> c_int>(f)
        };
        // SAFETY: `provctx` is the provider's own.
        ret = unsafe { f((*prov).provctx) };
    }
    if ret == 0 {
        // The cast drops `const`: the authority casts the argument explicitly, because
        // removing the methods mutates the provider's bitset.
        // SAFETY: `prov` is live and the caller still owns it.
        unsafe { provider_remove_store_methods(prov.cast_mut()) };
    }
    ret
}

/// `int ossl_provider_get_capabilities(const OSSL_PROVIDER *prov, const char *capability,
/// OSSL_CALLBACK *cb, void *arg)`.
///
/// # Safety
/// `prov` must be live; `capability` NULL or NUL-terminated; `cb` and `arg` are the
/// provider's to interpret.
pub(crate) unsafe fn ossl_provider_get_capabilities(
    prov: *const OsslProvider,
    capability: *const c_char,
    cb: Option<OsslCallback>,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).get_capabilities };
    if f.is_null() {
        return 1;
    }
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_get_capabilities`.
    let f = unsafe {
        core::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(
                *mut c_void,
                *const c_char,
                Option<OsslCallback>,
                *mut c_void,
            ) -> c_int,
        >(f)
    };
    // SAFETY: `provctx` is the provider's own; the other three are the caller's.
    unsafe { f((*prov).provctx, capability, cb, arg) }
}

/// `const OSSL_ALGORITHM *ossl_provider_query_operation(const OSSL_PROVIDER *prov,
/// int operation_id, int *no_cache)`.
///
/// **There is no `#if defined(OPENSSL_NO_CACHED_FETCH)` arm to reproduce.** The authority
/// contains one that would force `*no_cache = 1`; the admitted profile does not define that
/// macro, so the block is not compiled and the parameter is passed through untouched. This
/// paragraph exists because the source reads as if the arm were live.
///
/// # Safety
/// `prov` must be live; `no_cache` NULL or writable.
pub(crate) unsafe fn ossl_provider_query_operation(
    prov: *const OsslProvider,
    operation_id: c_int,
    no_cache: *mut c_int,
) -> *const OsslAlgorithm {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).query_operation };
    if f.is_null() {
        return ptr::null();
    }
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_query_operation`,
    // whose return is `const OSSL_ALGORITHM *`; `OsslAlgorithm` is the opaque declaration of
    // that pointee above, so the cast does not change the pointer's shape.
    let f = unsafe {
        core::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const c_void,
        >(f)
    };
    // SAFETY: `provctx` is the provider's own.
    unsafe { f((*prov).provctx, operation_id, no_cache).cast::<OsslAlgorithm>() }
}

/// `void ossl_provider_unquery_operation(const OSSL_PROVIDER *prov, int operation_id,
/// const OSSL_ALGORITHM *algs)`.
///
/// Answers nothing, and a provider without the entry point is a no-op rather than an error:
/// the release path has nothing to report to.
///
/// # Safety
/// `prov` must be live; `algs` must be what the matching query returned.
pub(crate) unsafe fn ossl_provider_unquery_operation(
    prov: *const OsslProvider,
    operation_id: c_int,
    algs: *const OsslAlgorithm,
) {
    // SAFETY: `prov` is live.
    let f = unsafe { (*prov).unquery_operation };
    if f.is_null() {
        return;
    }
    // SAFETY: the stored pointer is the provider's own `OSSL_FUNC_provider_unquery_operation`.
    let f = unsafe {
        core::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut c_void, c_int, *const OsslAlgorithm),
        >(f)
    };
    // SAFETY: `provctx` is the provider's own; `algs` is what the query returned.
    unsafe { f((*prov).provctx, operation_id, algs) }
}

/// `int ossl_provider_set_operation_bit(OSSL_PROVIDER *provider, size_t bitnum)`.
///
/// A growable bitset under `opbits_lock`. The growth is the interesting part: the buffer is
/// extended only when the requested byte is at or beyond the current size, it grows to
/// exactly `byte + 1`, and the **gap** between the old size and the new one is zeroed
/// explicitly. That explicit `memset` is not redundant with the realloc — `OPENSSL_realloc`
/// preserves the old bytes and says nothing about the new ones.
///
/// `bit` is masked to 8 bits before the shift, which is what stops `bitnum % 8 == 7` from
/// shifting into the next byte.
///
/// # Safety
/// `provider` must be live.
#[allow(dead_code)] // unreachable until Phase 7's method stores mark an algorithm as seen
pub(crate) unsafe fn ossl_provider_set_operation_bit(
    provider: *mut OsslProvider,
    bitnum: usize,
) -> c_int {
    let byte = bitnum / 8;
    // The authority writes `unsigned char bit = (1 << (bitnum % 8)) & 0xFF;` and the mask is
    // redundant in both languages -- `bitnum % 8` is already in 0..8 and the target is one
    // byte. It is kept because it is the line the reader will compare against
    // `crypto/provider_core.c`, and the allow names the lint rather than silencing the file.
    #[allow(clippy::identity_op)]
    let bit: u8 = (1u8 << (bitnum % 8)) & 0xFF;

    // SAFETY: `provider` is live, so `opbits_lock` and `operation_bits` are live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*provider).opbits_lock) == 0 {
            return 0;
        }
        if (*provider).operation_bits_sz <= byte {
            // The authority's line number, so a failing reallocation records what a consumer
            // would see from the authority.
            let tmp = CRYPTO_realloc(
                (*provider).operation_bits.cast::<c_void>(),
                byte + 1,
                FILE,
                2034,
            )
            .cast::<u8>();
            if tmp.is_null() {
                CRYPTO_THREAD_unlock((*provider).opbits_lock);
                return 0;
            }
            (*provider).operation_bits = tmp;
            // The gap: everything from the old size to `byte` inclusive is zeroed.
            ptr::write_bytes(
                tmp.add((*provider).operation_bits_sz),
                0,
                byte + 1 - (*provider).operation_bits_sz,
            );
            (*provider).operation_bits_sz = byte + 1;
        }
        // SAFETY: `operation_bits_sz > byte`, so `byte` is in bounds.
        *(*provider).operation_bits.add(byte) |= bit;
        CRYPTO_THREAD_unlock((*provider).opbits_lock);
    }
    1
}

/// `int ossl_provider_test_operation_bit(OSSL_PROVIDER *provider, size_t bitnum,
/// int *result)`.
///
/// `*result` is written **before** the lock is taken, so a caller that cannot take it sees 0
/// rather than whatever it passed in. And a NULL `result` is the one place in this file the
/// authority reaches for `ossl_assert` *and* an error: the assertion is non-fatal under
/// `NDEBUG`, so the `ERR_raise` is what actually reports it, and the answer is 0.
///
/// # Safety
/// `provider` must be live; `result` must be non-NULL and writable.
#[allow(dead_code)] // unreachable until Phase 7's fetch asks whether an algorithm is cached
pub(crate) unsafe fn ossl_provider_test_operation_bit(
    provider: *mut OsslProvider,
    bitnum: usize,
    result: *mut c_int,
) -> c_int {
    if result.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PROVIDER_CORE_2059) };
        return 0;
    }
    let byte = bitnum / 8;
    // As in `ossl_provider_set_operation_bit`: the authority's `& 0xFF` is kept verbatim.
    #[allow(clippy::identity_op)]
    let bit: u8 = (1u8 << (bitnum % 8)) & 0xFF;

    // SAFETY: `result` is non-NULL and writable per the check above.
    unsafe { *result = 0 };
    // SAFETY: `provider` is live, so `opbits_lock` exists.
    unsafe {
        if CRYPTO_THREAD_read_lock((*provider).opbits_lock) == 0 {
            return 0;
        }
        if (*provider).operation_bits_sz > byte {
            // SAFETY: `operation_bits_sz > byte`, so `byte` is in bounds.
            *result = c_int::from(*(*provider).operation_bits.add(byte) & bit != 0);
        }
        CRYPTO_THREAD_unlock((*provider).opbits_lock);
    }
    1
}

/// `int ossl_provider_default_props_update(OSSL_LIB_CTX *libctx, const char *props)`.
///
/// The store's child callbacks are told that the default property query changed. The walk is
/// under the store's **read** lock and the callback is invoked under it, which is the
/// authority's shape and not an oversight: a child provider's `global_props_cb` is expected to
/// be cheap.
///
/// A context with no store answers 0, and so does a failed lock — but *not* an empty callback
/// stack, which answers 1. Nothing registered is a successful no-op.
///
/// # Safety
/// `libctx` NULL or live; `props` NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until 10.2's config loader calls it
pub(crate) unsafe fn ossl_provider_default_props_update(
    libctx: *mut c_void,
    props: *const c_char,
) -> c_int {
    // SAFETY: `libctx` is NULL or live, so the slot read inside is sound.
    let store = unsafe { get_provider_store(libctx) };
    if store.is_null() {
        return 0;
    }
    // SAFETY: `store` is live, so `child_cbs` and `lock` are live.
    unsafe {
        if CRYPTO_THREAD_read_lock((*store).lock) == 0 {
            return 0;
        }
        let max = OPENSSL_sk_num((*store).child_cbs);
        let mut i = 0;
        while i < max {
            let cb = OPENSSL_sk_value((*store).child_cbs, i).cast::<ProviderChildCb>();
            // SAFETY: `cb` is a live callback record; 6.8e fills the field and nothing in
            // this build can, so the test is against a NULL that is always NULL today.
            let f = (*cb).global_props_cb;
            if !f.is_null() {
                let f = core::mem::transmute::<
                    *mut c_void,
                    unsafe extern "C" fn(*const c_char, *mut c_void),
                >(f);
                f(props, (*cb).cbdata);
            }
            i += 1;
        }
        CRYPTO_THREAD_unlock((*store).lock);
    }
    1
}

/// `OSSL_PROVIDER_CHILD_CB` — `crypto/provider_local.h`.
///
/// **6.8e's struct.** It is forward-declared here only because the walk above has to have a
/// type to cast a stack element to; the fields 6.8e fills are named so that a reader can see
/// which ones this stratum reads. Nothing in this build can push onto `store->child_cbs`, so
/// the pointer this names is never dereferenced — see the `the_five_slots_are_unfilled` and
/// `no_provider_child_callback_exists` tests, which assert the stack is empty.
#[repr(C)]
pub(crate) struct ProviderChildCb {
    /// `OSSL_FUNC_provider_child_cb_fn global_props_cb` — the one this stratum invokes.
    pub(crate) global_props_cb: *mut c_void,
    /// `OSSL_FUNC_provider_child_cb_fn create_cb` — 6.8e's.
    pub(crate) create_cb: *mut c_void,
    /// `OSSL_FUNC_provider_child_cb_fn remove_cb` — 6.8e's.
    pub(crate) remove_cb: *mut c_void,
    /// The `cbdata` every one of the three receives.
    pub(crate) cbdata: *mut c_void,
}

/// The two things `ossl_provider_activate`'s answer distinguishes.
///
/// `provider_activate` answers a *count* and `ossl_provider_activate` a *boolean*, and the
/// conversion is not `>= 1`: it is "flush when the transition happened, else report plain
/// success". A unit test cannot reach the flush without a store, so what is pinned here is
/// the part that is reachable — the `aschild` short-circuit and both NULL conventions.
/// The reachable surface of 6.8c, pinned.
///
/// `provider_activate` answers a *count* and `ossl_provider_activate` a *boolean*, and the
/// conversion is not `>= 1`: it is "flush when the transition happened, else report plain
/// success". The flush itself needs a method store this build does not have, so what is pinned
/// here is everything up to it, plus the whole query surface, which a *declared* provider
/// exercises end to end.
///
/// The provider below is a real one in every respect that matters: `provider_init` calls its
/// `OSSL_provider_init`, the dispatch-table walk stores its eight entry points, and each of the
/// seven delegated calls is then made and its answer and its recorded context checked. That is
/// what makes `ossl_provider_ctx`'s delegation observable rather than assumed — a
/// `get_params` that passed the wrong `provctx` would be invisible to a call that returned a
/// constant.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
    use crate::provider::init::{
        FUNC_PROVIDER_GETTABLE_PARAMS, FUNC_PROVIDER_GET_CAPABILITIES, FUNC_PROVIDER_GET_PARAMS,
        FUNC_PROVIDER_QUERY_OPERATION, FUNC_PROVIDER_RANDOM_BYTES, FUNC_PROVIDER_SELF_TEST,
        FUNC_PROVIDER_TEARDOWN, FUNC_PROVIDER_UNQUERY_OPERATION,
    };
    use crate::provider::{
        ossl_provider_ctx, ossl_provider_free, ossl_provider_new, PREDEFINED_PROVIDERS,
    };
    use core::ffi::c_uint;
    use core::sync::atomic::AtomicI32;

    /// The `provctx` the test provider publishes, and the marker every callback checks its
    /// argument against. It is a `static` so its address is stable and can be compared.
    static PROVCTX: u8 = 0x5A;

    /// `SEEN[0]` records "the callback's `provctx` was the published one"; `SEEN[1]` the
    /// operation id the last call passed; `SEEN[2]` the same for `get_params`; `SEEN[3]` the
    /// `algs` an unquery received; `SEEN[4]` how many times the teardown ran; `SEEN[5]` the
    /// verdict the self-test callback should answer.
    ///
    /// Atomics rather than a `static mut`, and `i32` rather than a `Vec` because `alloc` is
    /// not linked for unit tests.
    static SEEN: [AtomicI32; 6] = [
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
        AtomicI32::new(0),
    ];

    /// The slot the self-test callback reads its verdict from, named so the test that flips it
    /// does not spell an index.
    const SELF_TEST_SLOT: usize = 5;

    /// `osl_provider_teardown`'s target: records that it ran **and** with which context.
    unsafe extern "C" fn p_teardown(ctx: *mut c_void) {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[0].store(i32::from(matches), Ordering::SeqCst);
        SEEN[4].fetch_add(1, Ordering::SeqCst);
    }

    /// `OSSL_FUNC_provider_gettable_params_fn`.
    unsafe extern "C" fn p_gettable_params(ctx: *mut c_void) -> *const OsslParam {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[1].store(i32::from(matches), Ordering::SeqCst);
        table_marker()
    }

    /// `OSSL_FUNC_provider_get_params_fn`.
    unsafe extern "C" fn p_get_params(ctx: *mut c_void, params: *mut OsslParam) -> c_int {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[2].store(i32::from(matches), Ordering::SeqCst);
        // The authority passes `params` through untouched, so the marker is `params`.
        c_int::from(params.is_null())
    }

    /// `OSSL_FUNC_provider_self_test_fn`.
    unsafe extern "C" fn p_self_test(ctx: *mut c_void) -> c_int {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[3].store(i32::from(matches), Ordering::SeqCst);
        SEEN[SELF_TEST_SLOT].load(Ordering::SeqCst)
    }

    /// `OSSL_FUNC_provider_get_capabilities_fn`. The `capability` string is checked by the
    /// first byte, because comparing NUL-terminated strings would need `CStr` and this
    /// callback's whole contract is that the pointer is passed through.
    unsafe extern "C" fn p_get_capabilities(
        ctx: *mut c_void,
        capability: *const c_char,
        _cb: Option<OsslCallback>,
        _arg: *mut c_void,
    ) -> c_int {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[0].store(i32::from(matches), Ordering::SeqCst);
        // The authority passes the caller's `cb` and `arg` straight through; the answers are
        // what this returns, and the pointer is what it records.
        // SAFETY: `capability` is NULL or NUL-terminated per the caller's contract.
        let first = unsafe { capability.as_ref() }.map_or(-1, |c| c_int::from(*c as u8));
        SEEN[1].store(first, Ordering::SeqCst);
        9
    }

    /// `OSSL_FUNC_provider_query_operation_fn` — the only one whose out-parameter is written.
    unsafe extern "C" fn p_query_operation(
        ctx: *mut c_void,
        operation_id: c_int,
        no_cache: *mut c_int,
    ) -> *const c_void {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[0].store(i32::from(matches), Ordering::SeqCst);
        SEEN[1].store(operation_id, Ordering::SeqCst);
        if !no_cache.is_null() {
            // SAFETY: `no_cache` is non-NULL and writable per the caller's contract.
            unsafe { *no_cache = 1 };
        }
        table_marker().cast::<c_void>()
    }

    /// `OSSL_FUNC_provider_unquery_operation_fn` — answers nothing, records what it got.
    unsafe extern "C" fn p_unquery_operation(
        ctx: *mut c_void,
        operation_id: c_int,
        algs: *const OsslAlgorithm,
    ) {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[0].store(i32::from(matches), Ordering::SeqCst);
        SEEN[1].store(operation_id, Ordering::SeqCst);
        SEEN[3].store(algs as usize as i32, Ordering::SeqCst);
    }

    /// `OSSL_FUNC_provider_random_bytes_fn`.
    unsafe extern "C" fn p_random_bytes(
        ctx: *mut c_void,
        which: c_int,
        _buf: *mut c_void,
        _n: usize,
        _strength: c_uint,
    ) -> c_int {
        // A pointer comparison, which needs no `unsafe` block: `provctx_addr` is a safe
        // function and comparing two raw pointers is a safe operation.
        let matches = ctx == provctx_addr();
        SEEN[0].store(i32::from(matches), Ordering::SeqCst);
        SEEN[1].store(which, Ordering::SeqCst);
        3
    }

    /// The address of [`PROVCTX`], in the type every callback compares against.
    fn provctx_addr() -> *mut c_void {
        (&PROVCTX as *const u8 as *mut u8).cast::<c_void>()
    }

    /// The marker every pointer answer is compared against. A `static`'s address, never
    /// dereferenced: `OsslParam` has no `Sync` impl because no authority-visible one is ever
    /// shared, so a `static OsslParam` is not expressible and would not be a better marker.
    fn table_marker() -> *const OsslParam {
        (&PROVCTX as *const u8).cast::<OsslParam>()
    }

    /// The provider's own dispatch table, published through `out`.
    static PROVIDER_DISPATCH: [OsslDispatch; 9] = [
        OsslDispatch {
            function_id: FUNC_PROVIDER_TEARDOWN,
            function: p_teardown as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_GETTABLE_PARAMS,
            function: p_gettable_params as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_GET_PARAMS,
            function: p_get_params as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_SELF_TEST,
            function: p_self_test as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_GET_CAPABILITIES,
            function: p_get_capabilities as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_QUERY_OPERATION,
            function: p_query_operation as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_UNQUERY_OPERATION,
            function: p_unquery_operation as *mut c_void,
        },
        OsslDispatch {
            function_id: FUNC_PROVIDER_RANDOM_BYTES,
            function: p_random_bytes as *mut c_void,
        },
        OsslDispatch {
            function_id: OSSL_DISPATCH_END,
            function: ptr::null_mut(),
        },
    ];

    /// The provider's entry point. It publishes the table and the context, and it records that
    /// the handle it was given is the provider object rather than a copy.
    unsafe extern "C" fn test_provider_init(
        handle: *const c_void,
        _input: *const OsslDispatch,
        output: *mut *const OsslDispatch,
        provctx: *mut *mut c_void,
    ) -> c_int {
        SEEN[0].store(c_int::from(!handle.is_null()), Ordering::SeqCst);
        // SAFETY: both out-parameters are writable per `ProviderInitFn`'s contract.
        unsafe {
            *output = PROVIDER_DISPATCH.as_ptr();
            *provctx = provctx_addr();
        }
        1
    }

    /// Registers the test entry point under `name` and constructs a provider from it **by
    /// name**, which is the path `OSSL_PROVIDER_add_builtin` opens: the store's own builtin
    /// table, not the compiled-in predefined one.
    ///
    /// Each test uses its own name. That is not tidiness: `ossl_provider_add_to_store` matches
    /// by name and hands back the store's object when one already exists, so two tests sharing
    /// a name would make the second one the *loser* of a race it never entered.
    ///
    /// # Safety
    /// Answers a live, storeless, uninitialised provider, or panics.
    unsafe fn registered_test_provider(name: &'static core::ffi::CStr) -> *mut OsslProvider {
        // SAFETY: a NULL context is the default one and `name` is a `'static` literal.
        let registered = unsafe {
            crate::provider::ossl_provider_add_builtin(
                ptr::null_mut(),
                name.as_ptr(),
                Some(test_provider_init),
            )
        };
        assert_eq!(registered, 1, "the builtin registration must succeed");
        // SAFETY: as above; the name now resolves through the store's builtin table.
        unsafe { ossl_provider_new(ptr::null_mut(), name.as_ptr(), None, ptr::null_mut(), 0) }
    }

    /// The authority's own construction order, which is not obvious and is why it is spelled
    /// out here: a provider is created **storeless**, activated **once** while storeless — which
    /// is when `provider_init` runs, and it can only run once, because a second storeless
    /// activation re-enters `provider_init`, finds `flag_initialized` set, and fails — and only
    /// then added to the store. `OSSL_PROVIDER_try_load_ex` is the caller that does exactly this
    /// sequence, so a test that skipped it would be testing an order no consumer uses.
    ///
    /// `actualprov` is **non-NULL** here, as it is in `try_load_ex`, and that matters: it is what
    /// makes the store's reference and the caller's reference two, so a caller's
    /// `OSSL_PROVIDER_unload` does not release the object the store is still pointing at.
    ///
    /// # Safety
    /// Answers a live, initialised provider that the store holds a reference to.
    unsafe fn activated_test_provider(name: &'static core::ffi::CStr) -> *mut OsslProvider {
        // SAFETY: this helper's contract is the caller's.
        let prov = unsafe { registered_test_provider(name) };
        assert!(
            !prov.is_null(),
            "the registered builtin must resolve by name"
        );
        // SAFETY: `prov` is live.
        let count = unsafe { ossl_provider_activate(prov, 1, 0) };
        assert_eq!(
            count, 1,
            "the storeless activation is the one that initialises"
        );
        let mut actual: *mut OsslProvider = ptr::null_mut();
        // SAFETY: `prov` is live and `actual` is a writable slot of the right type.
        let added = unsafe { crate::provider::ossl_provider_add_to_store(prov, &mut actual, 0) };
        assert_eq!(added, 1, "the store must accept the provider");
        assert_eq!(actual, prov, "a free slot takes the caller's own object");
        // SAFETY: `prov` is live and now in the store.
        let store = unsafe { (*prov).store };
        assert!(
            !store.is_null(),
            "the store must be recorded on the provider"
        );
        prov
    }

    /// The whole reachable surface against a provider that really declares it: the context
    /// round trip, the count-then-boolean convention, the seven delegated calls, the bitset,
    /// and the life-cycle rule that the teardown waits for the last *reference*.
    #[test]
    fn a_declared_provider_surface_round_trips() {
        for slot in SEEN.iter() {
            slot.store(0, Ordering::SeqCst);
        }
        // A passing self-test, so `provider_remove_store_methods` is not reached here.
        SEEN[SELF_TEST_SLOT].store(1, Ordering::SeqCst);
        // SAFETY: the helper's contract is this test's.
        let prov = unsafe { activated_test_provider(c"rs-rt") };

        // SAFETY: `prov` is live; the callbacks are this module's own and the contracts below
        // are the provider's.
        unsafe {
            // Activation is a **count**. The provider is already at 1 from the helper, and the
            // store is what makes repeated activation possible: a storeless second activation
            // re-enters `provider_init` and fails.
            assert_eq!(provider_activate(prov, 1, 0), 2);
            assert_eq!(provider_activate(prov, 1, 0), 3);
            // The boolean wrapper is not `count >= 1`: it is 1 unless the *transition* to one
            // activation happened, in which case it is the store flush's verdict.
            assert_eq!(ossl_provider_activate(prov, 1, 0), 1);
            assert_eq!(
                ossl_provider_activate(prov, 1, 1),
                1,
                "aschild on a non-child is success, and does not activate"
            );

            // The context the provider published is the one every call receives.
            assert_eq!(ossl_provider_ctx(prov), provctx_addr());

            assert_eq!(ossl_provider_gettable_params(prov), table_marker());
            assert_eq!(
                SEEN[1].load(Ordering::SeqCst),
                1,
                "gettable_params was given the published context"
            );

            // `get_params` answers the provider's own value, and the provider's answer here is
            // whether the caller's `params` was NULL -- so both directions are visible.
            assert_eq!(ossl_provider_get_params(prov, ptr::null_mut()), 1);
            assert_eq!(ossl_provider_get_params(prov, table_marker().cast_mut()), 0);
            assert_eq!(
                SEEN[2].load(Ordering::SeqCst),
                1,
                "get_params was given the published context"
            );

            assert_eq!(ossl_provider_self_test(prov), 1);

            // `capability` is passed through untouched: the callback sees its first byte.
            assert_eq!(
                ossl_provider_get_capabilities(prov, c"TLS-GROUP".as_ptr(), None, ptr::null_mut()),
                9
            );
            assert_eq!(SEEN[1].load(Ordering::SeqCst), b'T' as c_int);

            // The query writes through the caller's out-parameter and passes the operation id.
            let mut no_cache = 0;
            assert_eq!(
                ossl_provider_query_operation(prov, 7, &mut no_cache),
                table_marker().cast::<OsslAlgorithm>()
            );
            assert_eq!(no_cache, 1, "the provider's write reaches the caller");
            assert_eq!(SEEN[1].load(Ordering::SeqCst), 7);

            // The unquery receives exactly the pointer the query returned.
            ossl_provider_unquery_operation(prov, 7, table_marker().cast::<OsslAlgorithm>());
            assert_eq!(
                SEEN[3].load(Ordering::SeqCst),
                table_marker() as usize as i32
            );

            assert_eq!(
                ossl_provider_random_bytes(prov, 4, ptr::null_mut(), 0, 0),
                3
            );
            assert_eq!(SEEN[1].load(Ordering::SeqCst), 4);

            // The bitset, and its two edges: bit 7 is the last bit of byte 0, so a missing mask
            // would spill into byte 1; and a bit past the end reads 0 without growing.
            let mut result = -1;
            assert_eq!(ossl_provider_set_operation_bit(prov, 7), 1);
            assert_eq!(ossl_provider_test_operation_bit(prov, 7, &mut result), 1);
            assert_eq!(result, 1);
            assert_eq!(ossl_provider_test_operation_bit(prov, 6, &mut result), 1);
            assert_eq!(result, 0, "bit 7 must not spill into bit 6");
            assert_eq!(ossl_provider_test_operation_bit(prov, 1000, &mut result), 1);
            assert_eq!(result, 0, "a bit past the end is 0, not out of bounds");
            assert_eq!(
                ossl_provider_test_operation_bit(prov, 0, ptr::null_mut()),
                0
            );

            // Deactivation answers the **resulting** count, so from 4 activations the first
            // call answers 3. `ossl_provider_deactivate` is itself a deactivation that
            // collapses the count to a boolean, so it consumes one rather than reporting
            // one -- the two are not interchangeable and this is where that shows.
            assert_eq!(provider_deactivate(prov, 1, 1), 3);
            assert_eq!(ossl_provider_deactivate(prov, 1), 1);
            assert_eq!(provider_deactivate(prov, 1, 1), 1);
            assert_eq!(
                SEEN[4].load(Ordering::SeqCst),
                0,
                "deactivation is not teardown"
            );
            assert_eq!(provider_deactivate(prov, 1, 1), 0);
            assert_eq!(
                provider_deactivate(prov, 1, 1),
                -1,
                "past zero is the documented failure answer, which is not a count"
            );
            assert_eq!(
                SEEN[4].load(Ordering::SeqCst),
                0,
                "an exhausted activation count is still not teardown"
            );

            // The store holds a reference of its own, so the caller's release must *not*
            // destroy the object: that is the whole reason the two counts exist.
            ossl_provider_free(prov);
            assert_eq!(
                SEEN[4].load(Ordering::SeqCst),
                0,
                "the store's reference keeps the provider alive"
            );
        }
    }

    /// A failing self-test takes the provider's store methods down and still answers 0 — and
    /// that includes the operation bitset, so a failed self-test cannot leave a cached
    /// algorithm behind.
    #[test]
    fn a_failing_self_test_removes_the_store_methods() {
        // SAFETY: the helper's contract is this test's. The provider must be *initialised*,
        // because that is what makes its `self_test` entry point reachable at all: an
        // uninitialised provider has a NULL field there and `ossl_provider_self_test` answers
        // 1, "assume it passed".
        let prov = unsafe { activated_test_provider(c"rs-selftest") };
        // SAFETY: `prov` is live.
        unsafe {
            assert_eq!(ossl_provider_set_operation_bit(prov, 0), 1);
            let mut result = -1;
            assert_eq!(ossl_provider_test_operation_bit(prov, 0, &mut result), 1);
            assert_eq!(result, 1);
            // Now the failure. `ossl_provider_self_test` answers the self-test's own verdict,
            // and the removal it triggers is what the bitset shows.
            let before = SEEN[4].load(Ordering::SeqCst);
            SEEN[SELF_TEST_SLOT].store(0, Ordering::SeqCst);
            assert_eq!(ossl_provider_self_test(prov), 0);
            assert_eq!(ossl_provider_test_operation_bit(prov, 0, &mut result), 1);
            assert_eq!(result, 0, "the failing self-test cleared the bitset");
            assert_eq!(
                SEEN[4].load(Ordering::SeqCst),
                before,
                "removing the store methods is not a teardown"
            );
            SEEN[SELF_TEST_SLOT].store(1, Ordering::SeqCst);
            ossl_provider_free(prov);
        }
    }

    /// The other half of the life-cycle rule, made its own test because it needs the *absence*
    /// of a store: a provider whose last reference goes is torn down, and that is the only
    /// place the teardown happens.
    #[test]
    fn the_teardown_runs_on_the_last_reference() {
        // SAFETY: the helper's contract is this test's.
        let prov = unsafe { registered_test_provider(c"rs-td") };
        assert!(!prov.is_null());
        let before = SEEN[4].load(Ordering::SeqCst);
        // SAFETY: `prov` is live and storeless, so this is the storeless activation that
        // initialises it -- and there is exactly one reference, so releasing it is the end.
        unsafe {
            assert_eq!(ossl_provider_activate(prov, 1, 0), 1);
            assert_eq!(ossl_provider_ctx(prov), provctx_addr());
            ossl_provider_free(prov);
        }
        assert_eq!(
            SEEN[4].load(Ordering::SeqCst),
            before + 1,
            "the last reference is what tears down"
        );
        assert_eq!(
            SEEN[0].load(Ordering::SeqCst),
            1,
            "the teardown was given the provider's own context"
        );
    }

    /// The NULL conventions, which the authority states by returning early rather than by
    /// dereferencing: a NULL provider is *reported*, never a fault.
    #[test]
    fn null_is_reported_and_never_dereferenced() {
        // SAFETY: every one of these accepts NULL by contract.
        unsafe {
            assert_eq!(ossl_provider_activate(ptr::null_mut(), 1, 0), 0);
            assert_eq!(ossl_provider_deactivate(ptr::null_mut(), 1), 0);
            assert_eq!(provider_deactivate(ptr::null_mut(), 1, 1), -1);
            assert!(ossl_provider_ctx(ptr::null()).is_null());
        }
    }

    /// `create_provider_children` fires its check rather than assuming, so the invariant it
    /// rests on has to be true: no child callback exists in this build. And the predefined
    /// table's fallback count is what the fallback walk's arithmetic depends on.
    #[test]
    fn no_provider_child_callback_exists() {
        // SAFETY: a NULL context is the default one; the slot read is sound either way.
        let store = unsafe { get_provider_store(ptr::null_mut()) };
        assert!(!store.is_null(), "6.8b-slot fills the provider store");
        // SAFETY: `store` is live and non-NULL.
        let n = unsafe { OPENSSL_sk_num((*store).child_cbs) };
        assert_eq!(
            n, 0,
            "6.8e's child-callback walk is not written, so the stack must be empty"
        );
        let fallbacks = PREDEFINED_PROVIDERS
            .iter()
            .filter(|row| row.is_fallback != 0)
            .count();
        assert_eq!(fallbacks, 1, "only `default` is a fallback in this profile");
    }
}
