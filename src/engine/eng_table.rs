//! Phase 10.9 — `crypto/engine/eng_table.c`: the implementation table
//! `ENGINE_get_digest_engine` is defined over.
//!
//! This is the module the digest path actually selects through:
//! `ossl_asn1_item_digest_ex` calls `ENGINE_get_digest_engine(nid)`
//! (`crypto/engine/tb_digest.c:66-70`), which is `ossl_engine_table_select(&digest_table,
//! nid, …)` here. Every function of this unit lands; nothing is withheld.
//!
//! ## The table is an `lh_ENGINE_PILE` and the pile is private
//!
//! `struct st_engine_pile` (`eng_table.c:17-28`) is a module-private node: an `int nid`,
//! a `STACK_OF(ENGINE)`, the cached default `funct` and an `uptodate` flag. It never
//! crosses the module boundary, so its layout is reproduced rather than asserted. The
//! authority's `struct st_engine_table` is a one-member wrapper around the lhash
//! (`:31-33`); this module folds that wrapper away and stores the lhash pointer as the
//! `ENGINE_TABLE *`, exactly as `src/runtime/stack.rs` chooses a `Vec` for `OPENSSL_STACK`.
//! The `ENGINE_TABLE **` the callers pass is therefore a reference to an
//! [`EngineTableSlot`] (the typed home of each table static), and the one place the
//! authority frees `&(*table)->piles` and nulls `*table` (`:98-99`) is the same
//! `OPENSSL_LH_free` plus a slot `swap` to null here.
//!
//! ## The hashing is the pile's `nid`, and it is why the cache is keyed
//!
//! `engine_pile_hash` is `c->nid` and `engine_pile_cmp` is `a->nid - b->nid` (`:55-63`),
//! so a pile is found by algorithm number alone. `lh_ENGINE_PILE_new` is
//! `OPENSSL_LH_new(engine_pile_hash, engine_pile_cmp)` here; the crate's lhash stores the
//! two directly and iterates without a thunk, which is the same three operations the
//! generated accessors perform.
//!
//! ## The select's error state is deliberately cleared
//!
//! A failed `init` on a candidate engine is not a failure of the *lookup*: the authority
//! brackets the walk with `ERR_set_mark()` / `ERR_pop_to_mark()` (`:222`, `:295`) so a
//! caller sees a clean queue whether or not a candidate's `init` raised.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::engine::eng_init::{engine_unlocked_finish, engine_unlocked_init};
use crate::engine::eng_lib::{
    engine_cleanup_add_first, global_engine_lock, Engine, EngineCleanupCb,
};
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx, RawCtx};
use crate::runtime::err::err_sites::ENG_TABLE_135;
use crate::runtime::err::raise_site;
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};
use crate::runtime::lhash::{
    OPENSSL_LH_doall, OPENSSL_LH_doall_arg, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new,
    OPENSSL_LH_retrieve, OpenSslLhash,
};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_delete_ptr, OPENSSL_sk_find, OPENSSL_sk_free,
    OPENSSL_sk_new_null, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// The typed internal home of an `ENGINE_TABLE *` static.
///
/// The authority declares each table as `static ENGINE_TABLE *table` and passes `&table`
/// (`ENGINE_TABLE **`) to the helpers, which read and write `*table`. The crate keeps the
/// same slot, but as a type whose `load`/`store`/`swap` are the only way to reach the
/// pointer. It deliberately does **not** expose a raw double-pointer view of the atomic:
/// that cast asserts an ordinary-pointer representation and an aliasing class the atomic
/// does not have.
///
/// The engine lock remains the mechanism that protects the lhash's lifetime: `load` is
/// called under the read or write lock and every mutation under the write lock, exactly as
/// the authority's plain `*table` accesses are. The slot claims no synchronisation of its
/// own beyond what its atomic orderings state.
pub(crate) struct EngineTableSlot {
    /// The `ENGINE_TABLE *` the authority stores in its `static`.
    table: AtomicPtr<OpenSslLhash>,
}

impl EngineTableSlot {
    /// An empty slot, matching `static ENGINE_TABLE *table = NULL`.
    pub(crate) const fn new() -> Self {
        Self {
            table: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Reads the stored table pointer.
    ///
    /// `Acquire` pairs with the `Release` in [`store`](Self::store) and the `AcqRel` in
    /// [`swap`](Self::swap), so a reader that observes a non-NULL table also observes the
    /// initialisation that preceded its publication. The engine lock supplies that ordering
    /// at every current call site; the atomic ordering keeps the slot correct on its own.
    pub(crate) fn load(&self) -> *mut OpenSslLhash {
        self.table.load(Ordering::Acquire)
    }

    /// Publishes a table pointer.
    ///
    /// `Release` publishes the lhash's initialisation (see [`load`](Self::load)). Every
    /// mutation runs under the engine's write lock.
    pub(crate) fn store(&self, value: *mut OpenSslLhash) {
        self.table.store(value, Ordering::Release);
    }

    /// Exchanges the stored table pointer, returning the previous one.
    ///
    /// `AcqRel` acquires the previous table before it is released and publishes the new
    /// value. [`engine_table_cleanup`] takes the table out of the slot before releasing it,
    /// which also makes a second cleanup observe `NULL` and do nothing.
    pub(crate) fn swap(&self, value: *mut OpenSslLhash) -> *mut OpenSslLhash {
        self.table.swap(value, Ordering::AcqRel)
    }
}

/// `ENGINE_TABLE_FLAG_NOINIT` (`openssl/engine.h:64`) — `(unsigned int)0x0001`.
const ENGINE_TABLE_FLAG_NOINIT: c_uint = 0x0001;

/// `struct st_engine_pile` (`crypto/engine/eng_table.c:17-28`).
#[repr(C)]
struct EnginePile {
    /// `int nid`
    nid: c_int,
    /// `STACK_OF(ENGINE) *sk`
    sk: *mut OpenSslStack,
    /// `ENGINE *funct`
    funct: *mut Engine,
    /// `int uptodate`
    uptodate: c_int,
}

const _: () = {
    // Module-private, but asserted so a field inserted without updating this file is caught.
    assert!(size_of::<EnginePile>() == 32);
    assert!(core::mem::offset_of!(EnginePile, nid) == 0);
    assert!(core::mem::offset_of!(EnginePile, sk) == 8);
    assert!(core::mem::offset_of!(EnginePile, funct) == 16);
    assert!(core::mem::offset_of!(EnginePile, uptodate) == 24);
};

/// `int_cleanup_cb_doall`'s member body (`eng_table.c:177-185`), without the block release
/// [`OwnedCtx`]'s `Drop` performs: the pile's own engine stack, then the cached default engine.
///
/// [`OwnedCtx`]: crate::runtime::bio::owned::OwnedCtx
// SAFETY: (a) `destroy_body` is the authority's own `int_cleanup_cb_doall` body -- it releases
// exactly the pile's own `sk` (a NULL-tolerant `sk_ENGINE_free`) and finishes the cached default
// `funct` when set, and never releases the enclosing block, which `OwnedCtx`'s `Drop` releases
// through `CRYPTO_free` at `:113`; (b) an all-zero `EnginePile` is a valid value (`sk`/`funct`
// NULL, `nid`/`uptodate` zero), so the zeroed block `OwnedCtx::zalloc` would build is valid and
// this body is sound on it; (c) whenever `funct` is non-NULL the caller holds the engine lock --
// the body calls `engine_unlocked_finish`, which requires it. The only non-NULL-`funct` owners
// are built by `int_cleanup_cb_doall` under `engine_table_cleanup`'s lock; the register-failure
// owners always have `funct == NULL`.
unsafe impl CtxDestroy for EnginePile {
    /// `__FILE__` for the pile's `OPENSSL_malloc`/`OPENSSL_free` coordinates.
    const FILE: *const c_char = c"crypto/engine/eng_table.c".as_ptr();
    /// `OPENSSL_LINE` of the pile `OPENSSL_malloc` (`:106`).
    const LINE_ALLOC: c_int = 106;
    /// `OPENSSL_LINE` of the pile's normal `OPENSSL_free` (`int_cleanup_cb_doall`, `:184`).
    const LINE_FREE: c_int = 184;

    unsafe fn destroy_body(ptr: *mut EnginePile) {
        // SAFETY: `ptr` is a live pile per the trait contract; `sk` is this pile's own stack
        // (NULL-tolerant) and `funct` is NULL or the cached default engine.
        unsafe {
            OPENSSL_sk_free((*ptr).sk);
            if !(*ptr).funct.is_null() {
                engine_unlocked_finish((*ptr).funct, 0);
            }
        }
    }
}

/// `struct st_engine_pile_doall` (`:35-38`) — the doall adapter's argument.
#[repr(C)]
struct EnginePileDoall {
    /// `engine_table_doall_cb *cb`
    cb: Option<EngineTableDoallCb>,
    /// `void *arg`
    arg: *mut c_void,
}

/// `void (*)(int nid, STACK_OF(ENGINE) *sk, ENGINE *def, void *arg)`.
pub(crate) type EngineTableDoallCb =
    unsafe extern "C" fn(c_int, *mut OpenSslStack, *mut Engine, *mut c_void);

/// `static unsigned int table_flags = 0` (`:41`).
static TABLE_FLAGS: AtomicU32 = AtomicU32::new(0);

/// `unsigned int ENGINE_get_table_flags(void)` — `crypto/engine/eng_table.c:44-47`.
#[no_mangle]
pub extern "C" fn ENGINE_get_table_flags() -> c_uint {
    TABLE_FLAGS.load(Ordering::Acquire)
}

/// `void ENGINE_set_table_flags(unsigned int flags)` — `:49-52`.
#[no_mangle]
pub extern "C" fn ENGINE_set_table_flags(flags: c_uint) {
    TABLE_FLAGS.store(flags, Ordering::Release);
}

/// `static unsigned long engine_pile_hash(const ENGINE_PILE *c)` — `:55-58`.
///
/// # Safety
///
/// `c` must be a live, fully initialised `EnginePile`; only its `nid` field is read, so no other
/// member's state is relevant. It is **not** required that `c` be stored in the table: the lhash
/// also hashes the caller's stack-local query template. `engine_table_register` passes
/// `ptr::addr_of!(tmplate)` to `OPENSSL_LH_retrieve` at `:268` and `:308`, and
/// `ossl_engine_table_select` passes it at `:511`; the template is not an element of any table
/// and was not allocated by this module. The obligation is therefore "a live `EnginePile`, either
/// a stored element or a query template of the same shape", and both are established at those
/// call sites. A NULL pointer is never passed (the lhash rejects a NULL key before hashing).
unsafe extern "C" fn engine_pile_hash(c: *const c_void) -> core::ffi::c_ulong {
    let pile = c.cast::<EnginePile>();
    // SAFETY: `c` is a live pile or query template per the contract; `nid` is initialised in both.
    unsafe { (*pile).nid as core::ffi::c_ulong }
}

/// `static int engine_pile_cmp(const ENGINE_PILE *a, const ENGINE_PILE *b)` — `:60-63`.
///
/// # Safety
///
/// `a` and `b` must each be a live, fully initialised `EnginePile`, and only their `nid` fields
/// are read. One of them may be the caller's stack-local query template rather than a table
/// element: the crate's `OPENSSL_LH_retrieve` calls the comparator as `eq(stored, data)`, where
/// `data` is `ptr::addr_of!(tmplate)` at `:268`, `:308` and `:511`. The same obligation as
/// [`engine_pile_hash`] applies — "a stored pile or a query template of the same shape" — and is
/// established at those call sites. Neither argument is NULL.
unsafe extern "C" fn engine_pile_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<EnginePile>();
    let b = b.cast::<EnginePile>();
    // SAFETY: both arguments are live piles or a stored pile and a query template; both `nid`s are
    // initialised. Wrapping subtraction is the authority's two's-complement result without a
    // debug-build overflow panic across the `extern "C"` edge (the C subtraction is UB there).
    unsafe { (*a).nid.wrapping_sub((*b).nid) }
}

/// `static int int_table_check(ENGINE_TABLE **t, int create)` — `:65-77`.
///
/// # Safety
/// The engine lock must be held for the whole call: `t`'s lhash pointer is read and, when
/// `create` is set, published, and the returned table's lifetime is governed by that lock.
unsafe fn int_table_check(t: &EngineTableSlot, create: bool) -> bool {
    if !t.load().is_null() {
        return true;
    }
    if !create {
        return false;
    }
    let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
    if lh.is_null() {
        return false;
    }
    t.store(lh);
    true
}

/// `int engine_table_register(ENGINE_TABLE **table, ENGINE_CLEANUP_CB *cleanup,
///     ENGINE *e, const int *nids, int num_nids, int setdefault)` — `:83-149`.
///
/// # Safety
/// `e` must be a live, non-NULL `ENGINE` (the crate's register/set-default wrappers always
/// pass one, and the `setdefault` arm would dereference it; the authority's wrappers check
/// for NULL before calling); `nids` must point to `num_nids` integers; `cleanup` is a caller
/// callback that must remain valid until engine cleanup. The engine lock must be initialised
/// (non-NULL) and must not already be held by this thread; it is taken here. When the lock is
/// NULL (no `ENGINE` constructor has run), `CRYPTO_THREAD_write_lock` answers 0 and this
/// function returns 0 without touching the table: the authority-compatible refusal, not UB.
///
/// The registered entry is a **borrow**: `e` must remain alive until it is
/// unregistered, either because the global engine list holds the structural reference
/// (`ENGINE_add`) or because the caller keeps one. The authority assumes the same;
/// [`crate::engine::eng_list`]'s removal path retires the borrow before dropping the
/// list's reference.
pub(crate) unsafe fn engine_table_register(
    table: &EngineTableSlot,
    cleanup: Option<EngineCleanupCb>,
    e: *mut Engine,
    nids: *const c_int,
    num_nids: c_int,
    setdefault: c_int,
) -> c_int {
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return 0;
    }
    let mut ret = 0;
    let added = table.load().is_null();
    // SAFETY: the engine lock is held by this frame.
    if !unsafe { int_table_check(table, true) } {
        // SAFETY: the engine lock is held by the caller.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        return 0;
    }
    if added {
        // SAFETY: `cleanup` is the caller's callback.
        if unsafe { engine_cleanup_add_first(cleanup) } == 0 {
            // SAFETY: `table` holds the lhash `int_table_check` built.
            let lh = table.swap(ptr::null_mut());
            // SAFETY: `lh` is the lhash `int_table_check` built.
            unsafe { OPENSSL_LH_free(lh) };
            // SAFETY: the engine lock is held by the caller.
            unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            return 0;
        }
    }
    let mut remaining = num_nids;
    let mut cursor = nids;
    while remaining > 0 {
        remaining -= 1;
        // SAFETY: `cursor` points at the next of the caller's `num_nids` integers.
        let tmplate = EnginePile {
            // SAFETY: the operation's pointers are live per the caller's contract.
            nid: unsafe { *cursor },
            sk: ptr::null_mut(),
            funct: ptr::null_mut(),
            uptodate: 1,
        };
        // SAFETY: `table` holds a live lhash.
        let lh = table.load();
        // SAFETY: the lhash holds `EnginePile`s and `tmplate` is one to look up.
        let mut fnd = unsafe { OPENSSL_LH_retrieve(lh, ptr::addr_of!(tmplate).cast::<c_void>()) }
            .cast::<EnginePile>();
        if fnd.is_null() {
            // The pile is the authority's own `OPENSSL_malloc(sizeof(*fnd))` at `:106`; its `sk`
            // and `funct` members are the authority's `int_cleanup_cb_doall` body, run from
            // [`OwnedCtx`]'s `Drop`, and the block release is at `:113`.
            let Some(raw) = RawCtx::<EnginePile>::malloc() else {
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            };
            // SAFETY: `raw` is the fresh allocation; `tmplate` carries the nid.
            unsafe {
                let p = raw.as_ptr();
                (*p).uptodate = 1;
                (*p).nid = tmplate.nid;
                (*p).sk = OPENSSL_sk_new_null();
            }
            // SAFETY: `raw.as_ptr()` is live.
            if unsafe { (*raw.as_ptr()).sk.is_null() } {
                // The pile's `sk` failed to allocate, so the pile is not yet a valid
                // `EnginePile`; the raw handle's `Drop` releases the block alone at the
                // authority's failure site (`OPENSSL_free(fnd)` at `:113`).
                let mut raw = raw;
                raw.set_release_line(113);
                drop(raw);
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            // `sk` is set; `funct` is set to NULL now so every field this pile's destructor body
            // reads is initialised before the owning handle can run it.
            // SAFETY: `raw.as_ptr()` is live.
            unsafe { (*raw.as_ptr()).funct = ptr::null_mut() };
            // SAFETY: all four fields are written and `raw` is the only owner, so the storage is a
            // valid `EnginePile` whose destructor body is sound.
            let mut raw = unsafe { raw.assume_init() };
            // SAFETY: `raw.as_ptr()` is live; the lhash stores the pile as its node.
            unsafe { OPENSSL_LH_insert(lh, raw.as_ptr().cast::<c_void>()) };
            // SAFETY: the lhash is live and holds the node `raw` inserted.
            let again = unsafe { OPENSSL_LH_retrieve(lh, ptr::addr_of!(tmplate).cast::<c_void>()) }
                .cast::<EnginePile>();
            if again != raw.as_ptr() {
                // The lhash kept a different node; the handle's `Drop` runs the authority's own
                // `sk_ENGINE_free(fnd->sk)` + `OPENSSL_free(fnd)` at the failed-insert site
                // `:113` (funct is still NULL).
                raw.set_release_line(113);
                drop(raw);
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            // The lhash owns the pile now; `into_raw` disables the handle's `Drop`.
            fnd = raw.into_raw();
        }
        // A registration should not add duplicate entries.
        // SAFETY: `fnd` is a live pile and `e` is the caller's engine.
        unsafe {
            OPENSSL_sk_delete_ptr((*fnd).sk, e.cast::<c_void>());
        }
        // If `setdefault`, this ENGINE goes to the head of the list.
        // The stack stores a **borrowed** `ENGINE *`; `engine_table_register` takes no
        // reference for it (`eng_table.c:124-131`). The structural reference that keeps
        // `e` alive is the one `engine_list_add` took when the engine was added to the
        // global list (`ENGINE_add`). `engine_list_remove` retires this borrow through
        // `engine_unregister_from_all_tables` before dropping that reference, so the entry
        // cannot outlive its owner (a deliberate improvement over the authority, which does
        // not unregister on removal).
        // SAFETY: `fnd` is live and `e` is the caller's engine.
        if unsafe { OPENSSL_sk_push((*fnd).sk, e.cast::<c_void>()) } == 0 {
            // SAFETY: the engine lock is held by the caller.
            unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
            return ret;
        }
        // Touch this pile.
        // SAFETY: `fnd` is live.
        unsafe { (*fnd).uptodate = 0 };
        if setdefault != 0 {
            // SAFETY: the lock is held and `e` is live.
            if unsafe { engine_unlocked_init(e) } == 0 {
                // SAFETY: `ENG_TABLE_135` is a generated constant whose strings are static.
                unsafe { raise_site(&ENG_TABLE_135) };
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            // SAFETY: `fnd` is live.
            let old = unsafe { (*fnd).funct };
            if !old.is_null() {
                // SAFETY: the lock is held and `old` is the cached default.
                unsafe { engine_unlocked_finish(old, 0) };
            }
            // SAFETY: `fnd` is live.
            unsafe {
                (*fnd).funct = e;
                (*fnd).uptodate = 1;
            }
        }
        // SAFETY: `cursor` advances within the caller's array.
        cursor = unsafe { cursor.add(1) };
    }
    ret = 1;
    // SAFETY: the lock is held.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
    ret
}

/// `static void int_unregister_cb(ENGINE_PILE *pile, ENGINE *e)` — `:151-163`.
///
/// # Safety
///
/// `pile` must be a live `EnginePile` the table's `OPENSSL_LH_doall_arg` walk supplies and `e`
/// must be the live `ENGINE` being removed. The caller must hold the engine lock: when the pile's
/// cached `funct` is `e` the body calls `engine_unlocked_finish`, which requires it.
unsafe extern "C" fn int_unregister_cb(pile: *mut c_void, e: *mut c_void) {
    let pile = pile.cast::<EnginePile>();
    let e = e.cast::<Engine>();
    // Iterate the pile's stack, removing any occurrence of `e`.
    loop {
        // SAFETY: `pile` is a live pile node from the lhash.
        let n = unsafe { OPENSSL_sk_find((*pile).sk, e.cast::<c_void>()) };
        if n < 0 {
            break;
        }
        // SAFETY: `n` is a valid index in the pile's stack.
        unsafe {
            OPENSSL_sk_delete((*pile).sk, n);
            (*pile).uptodate = 0;
        }
    }
    // SAFETY: `pile` is live.
    if unsafe { (*pile).funct } == e {
        // SAFETY: the lock is held; `e` is the cached default.
        unsafe { engine_unlocked_finish(e, 0) };
        // SAFETY: `pile` is live.
        unsafe { (*pile).funct = ptr::null_mut() };
    }
}

/// `void engine_table_unregister(ENGINE_TABLE **table, ENGINE *e)` — `:167-175`.
///
/// # Safety
/// `e` must be a live `ENGINE`. The engine lock must be initialised (non-NULL) and must not
/// already be held by this thread; it is taken here. With a NULL lock,
/// `CRYPTO_THREAD_write_lock` answers 0 and this function returns without unregistering
/// anything: the authority-compatible refusal, not UB.
pub(crate) unsafe fn engine_table_unregister(table: &EngineTableSlot, e: *mut Engine) {
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return;
    }
    // SAFETY: the engine lock is held by this frame.
    unsafe { engine_table_unregister_locked(table, e) };
    // SAFETY: the engine lock is held by the caller.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
}

/// The body of [`engine_table_unregister`] for a caller that already holds the engine lock.
///
/// `ENGINE_remove` reaches this form: it unregisters `e` from every table while holding the
/// lock it took, before dropping the global list's structural reference. The authority's
/// `engine_table_unregister` always acquires the lock itself (`:167-175`); the crate's lock
/// refuses a recursive write acquisition, so the removal path cannot call the public form.
///
/// # Safety
/// `e` must be a live `ENGINE`; the engine lock must be held by the caller.
pub(crate) unsafe fn engine_table_unregister_locked(table: &EngineTableSlot, e: *mut Engine) {
    // SAFETY: the engine lock is held by the caller.
    if unsafe { int_table_check(table, false) } {
        // SAFETY: `table` holds a live lhash and `e` is the caller's engine.
        unsafe {
            OPENSSL_LH_doall_arg(table.load(), Some(int_unregister_cb), e.cast::<c_void>());
        }
    }
}

/// `static void int_cleanup_cb_doall(ENGINE_PILE *p)` — `:177-185`.
///
/// # Safety
///
/// `p` is NULL or a live `EnginePile` this crate allocated with `RawCtx::<EnginePile>` and
/// inserted, and the lhash still owns it. The walk must visit each element once and must not
/// itself release the pile: this callback adopts it with [`OwnedCtx::from_raw`], whose `Drop`
/// runs the authority's destructor body and then the block release. The caller must hold the
/// engine lock for any pile whose `funct` is non-NULL (`engine_unlocked_finish` requires it);
/// `engine_table_cleanup` does.
unsafe extern "C" fn int_cleanup_cb_doall(p: *mut c_void) {
    let p = p.cast::<EnginePile>();
    // `p` is a pile the lhash owns; the handle's `Drop` runs the authority's own
    // `int_cleanup_cb_doall` body (`sk_ENGINE_free` + `engine_unlocked_finish`) followed by the
    // block release at `:113`. A NULL `p` reclaims nothing.
    // SAFETY: `p` is NULL or a live pile this crate allocated and the lhash still owns.
    drop(unsafe { OwnedCtx::<EnginePile>::from_raw(p) });
}

/// `void engine_table_cleanup(ENGINE_TABLE **table)` — `:187-197`.
///
/// # Safety
/// The engine lock must be **initialised** (non-NULL) through the crate's lock-init path
/// ([`crate::engine::eng_lib::run_engine_lock_init`], reached from `ENGINE_new`,
/// `ENGINE_by_id` and `ENGINE_get_first`/`ENGINE_get_last`) and must not already be held by
/// this thread; it is taken here. The lock-init half is a real obligation, not a formality:
/// if the lock is NULL, `CRYPTO_THREAD_write_lock` answers 0 and this function returns
/// **without swapping the slot and without releasing the table**. That is a silent no-op
/// which leaves the lhash (and its piles) owned by the slot — a leak, not UB. Every public
/// path that yields an `ENGINE` runs the lock init, and registration is the only way to
/// enqueue the cleanup callback, so the precondition is established transitively in
/// production. The lhash is taken out of the slot before it is released, so a second cleanup
/// (with an initialised lock) sees `NULL` and does nothing.
pub(crate) unsafe fn engine_table_cleanup(table: &EngineTableSlot) {
    let lock = global_engine_lock();
    // Make the documented precondition explicit instead of relying on the NULL case of
    // `CRYPTO_THREAD_write_lock`: an uninitialised lock leaves the slot untouched and the
    // table unreleased, exactly as the authority's failed acquisition does. No panic, no
    // release, no behaviour change.
    //
    // This guard is redundant defence-in-depth, not an observable behaviour: deleting it alone
    // changes nothing, because `CRYPTO_THREAD_write_lock(NULL)` already answers 0 and the
    // acquisition check below refuses. The C1 control
    // (`cleanup_preserves_the_table_when_the_write_lock_acquisition_fails`) therefore covers
    // only the acquisition-failure arm; the evidence must not claim to detect removal of this
    // NULL guard.
    if lock.is_null() {
        return;
    }
    // SAFETY: `lock` is the engine lock created by the run-once and is non-NULL per the check.
    // A 0 answer is a real single-thread failure arm: the write lock refuses re-acquisition by
    // the thread that already holds it (`state.writer_id == Some(current_id())`), so cleanup
    // must leave the slot and the table untouched rather than deadlock or release them.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return;
    }
    // Taking the table out of the slot first is the typed equivalent of the authority's
    // `*table` read followed by `*table = NULL`: the slot is empty for any later cleanup.
    let lh = table.swap(ptr::null_mut());
    if !lh.is_null() {
        // SAFETY: `lh` is the table this slot held.
        unsafe {
            OPENSSL_LH_doall(lh, Some(int_cleanup_cb_doall));
            OPENSSL_LH_free(lh);
        }
    }
    // SAFETY: the engine lock is held by this frame (`lock` is the same pointer).
    unsafe { CRYPTO_THREAD_unlock(lock) };
}

/// `ENGINE *ossl_engine_table_select(ENGINE_TABLE **table, int nid,
///     const char *f, int l)` — `:200-297`.
///
/// `f`/`l` are the caller's `OPENSSL_FILE`/`OPENSSL_LINE`, used only by the
/// `OSSL_TRACE` calls, which are empty under this build's `no-trace`.
///
/// # Safety
/// `table` must be a slot this crate owns for the whole call (every caller passes one of the
/// `tb_*` module statics or a test-local slot). The engine lock must be initialised (non-NULL)
/// and must not already be held by this thread; it is taken here. With a NULL lock,
/// `CRYPTO_THREAD_write_lock` answers 0 and this returns `NULL` without reading the table: the
/// authority-compatible refusal, not UB. The returned engine is the table's borrowed or
/// functionally referenced answer, exactly as in the authority, so a caller must not treat it
/// as owning a reference it was not given.
pub(crate) unsafe fn ossl_engine_table_select(
    table: &EngineTableSlot,
    nid: c_int,
    f: *const c_char,
    l: c_int,
) -> *mut Engine {
    let _ = (f, l);
    // Load the config before taking the engine lock: configuration modules may register
    // engines, and that path takes the same lock.
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, ptr::null());

    // The authority checks `*table == NULL` before locking. The crate deliberately reads
    // the slot inside the write lock only, so a locked cleanup/register cannot be observed
    // through a stale unlocked read (AGENTS.md §17). A NULL table takes the same
    // `select_end` refusal below, after acquiring the lock.
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return ptr::null_mut();
    }
    ERR_set_mark();
    // Check the slot inside the lock, serialised against cleanup and registration.
    // SAFETY: the engine lock is held.
    if !unsafe { int_table_check(table, false) } {
        // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
        return unsafe { select_end(ptr::null_mut(), ptr::null_mut()) };
    }
    let tmplate = EnginePile {
        nid,
        sk: ptr::null_mut(),
        funct: ptr::null_mut(),
        uptodate: 1,
    };
    // SAFETY: `table` holds a live lhash.
    let lh = table.load();
    // SAFETY: the lhash holds `EnginePile`s and `tmplate` is one to look up.
    let fnd = unsafe { OPENSSL_LH_retrieve(lh, ptr::addr_of!(tmplate).cast::<c_void>()) }
        .cast::<EnginePile>();
    if fnd.is_null() {
        // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
        return unsafe { select_end(ptr::null_mut(), ptr::null_mut()) };
    }
    // SAFETY: `fnd` is a live pile.
    if !unsafe { (*fnd).funct }.is_null() {
        // SAFETY: the lock is held and `funct` is the cached default.
        if unsafe { engine_unlocked_init((*fnd).funct) } != 0 {
            // SAFETY: `fnd` is live.
            let ret = unsafe { (*fnd).funct };
            // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
            return unsafe { select_end(fnd, ret) };
        }
    }
    // The authority's own arm: `if (fnd->uptodate) { ret = fnd->funct; goto end; }`
    // (`eng_table.c:240-243`). When the cached default is present but
    // `engine_unlocked_init` answered 0, the cached pointer is returned **without** an
    // acquired functional reference. That is an authority-level contract hazard the
    // conversion inherits, not a new refusal: the crate's checked increment can also
    // answer 0 at `i32::MAX`, which the authority's plain fetch-add cannot observe.
    // Callers therefore receive an unowned engine on this arm in both implementations;
    // it is recorded with the borrowed-table-entry hazard, not discharged here.
    // SAFETY: `fnd` is live.
    if unsafe { (*fnd).uptodate } != 0 {
        // SAFETY: `fnd` is live.
        let ret = unsafe { (*fnd).funct };
        // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
        return unsafe { select_end(fnd, ret) };
    }
    let mut loop_index: c_int = 0;
    loop {
        // SAFETY: `fnd` is live and `loop_index` is a valid index or past the end.
        let ret = unsafe { OPENSSL_sk_value((*fnd).sk, loop_index) }.cast::<Engine>();
        loop_index += 1;
        if ret.is_null() {
            // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
            return unsafe { select_end(fnd, ptr::null_mut()) };
        }
        // Try to initialise the ENGINE? `ret->funct_ref > 0` skips the NOINIT flag.
        // SAFETY: `ret` is a candidate engine.
        let initres = if unsafe { (*ret).funct_ref } > 0
            || TABLE_FLAGS.load(Ordering::Acquire) & ENGINE_TABLE_FLAG_NOINIT == 0
        {
            // SAFETY: the lock is held and `ret` is live.
            unsafe { engine_unlocked_init(ret) }
        } else {
            0
        };
        if initres != 0 {
            // Update the cached default.
            // SAFETY: `fnd` and `ret` are live.
            let different = unsafe { (*fnd).funct } != ret;
            if different {
                // SAFETY: the lock is held and `ret` is live.
                if unsafe { engine_unlocked_init(ret) } != 0 {
                    // SAFETY: `fnd` is live.
                    let prev = unsafe { (*fnd).funct };
                    if !prev.is_null() {
                        // SAFETY: the lock is held.
                        unsafe { engine_unlocked_finish(prev, 0) };
                    }
                    // SAFETY: `fnd` is live.
                    unsafe { (*fnd).funct = ret };
                }
            }
            // SAFETY: the engine lock is held and `fnd` is NULL or a live pile.
            return unsafe { select_end(fnd, ret) };
        }
    }
}

/// The shared `end:` tail of [`ossl_engine_table_select`] — caches the pile's `uptodate`,
/// releases the lock and pops the mark the select set.
///
/// # Safety
/// The engine lock must be held; `fnd` is NULL or a live pile from the select's table.
unsafe fn select_end(fnd: *mut EnginePile, ret: *mut Engine) -> *mut Engine {
    // SAFETY: `fnd` is NULL or live per the caller.
    if !fnd.is_null() {
        // SAFETY: `fnd` is live.
        unsafe { (*fnd).uptodate = 1 };
    }
    // SAFETY: the lock is held.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
    ERR_pop_to_mark();
    ret
}

/// `static void int_dall(const ENGINE_PILE *pile, ENGINE_PILE_DOALL *dall)` — `:301-304`.
///
/// # Safety
///
/// `pile` must be a live `EnginePile` from the table the walk is visiting, and `dall` must point
/// at the live [`EnginePileDoall`] that [`engine_table_doall`] set up for this walk (whose `cb`
/// and `arg` the application supplied). The caller must hold the engine lock (read or write) and
/// must not mutate or free the table from `cb`: the body hands the callback the pile's borrowed
/// `nid`, stack and cached engine.
unsafe extern "C" fn int_dall(pile: *mut c_void, dall: *mut c_void) {
    let pile = pile.cast::<EnginePile>();
    let dall = dall.cast::<EnginePileDoall>();
    // SAFETY: both are the arguments `engine_table_doall` set up.
    if let Some(cb) = unsafe { (*dall).cb } {
        // SAFETY: `pile` is a live pile and `dall.arg` is the caller's argument.
        unsafe { cb((*pile).nid, (*pile).sk, (*pile).funct, (*dall).arg) };
    }
}

/// `void engine_table_doall(ENGINE_TABLE *table, engine_table_doall_cb *cb, void *arg)` —
/// `:308-316`.
///
/// # Safety
/// `table` must be NULL or a live `ENGINE_TABLE`; `cb` accepts each pile. The caller
/// must hold the engine lock (read or write) for the whole walk and must not mutate or
/// free the table from `cb`: the walk dereferences every pile and hands its borrowed
/// stack and engines to the callback (the crate's only caller holds the read lock).
pub(crate) unsafe fn engine_table_doall(
    table: *mut OpenSslLhash,
    cb: Option<EngineTableDoallCb>,
    arg: *mut c_void,
) {
    let mut dall = EnginePileDoall { cb, arg };
    if !table.is_null() {
        // SAFETY: `table` is live and `dall` outlives the walk.
        unsafe {
            OPENSSL_LH_doall_arg(
                table,
                Some(int_dall),
                ptr::addr_of_mut!(dall).cast::<c_void>(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::engine::eng_lib::{ENGINE_free, ENGINE_new};
    use crate::test_support::lock_global_state;

    static INIT_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn refusing_init(_e: *mut Engine) -> c_int {
        INIT_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    /// The authority returns the cached `fnd->funct` when `engine_unlocked_init` fails and
    /// `uptodate` is set (`eng_table.c:240-243`). The crate's checked increment adds a
    /// refusal at `i32::MAX` that the authority's plain fetch-add cannot observe; this test
    /// pins the authority's answer on that arm: the cached pointer, with no acquired
    /// functional reference.
    #[test]
    fn refused_init_returns_the_cached_default_without_a_reference() {
        let _g = lock_global_state();
        let nid: c_int = 0x4d7;
        let table = EngineTableSlot::new();
        // SAFETY: `table` is this test's own slot; the lhash, pile and engine are built
        // and released exactly once here.
        unsafe {
            assert!(int_table_check(&table, true));
            let raw = RawCtx::<EnginePile>::malloc();
            assert!(raw.is_some(), "the pile block allocates");
            let Some(raw) = raw else { return };
            {
                let p = raw.as_ptr();
                (*p).uptodate = 1;
                (*p).nid = nid;
                (*p).sk = OPENSSL_sk_new_null();
                assert!(!(*p).sk.is_null());
                (*p).funct = ptr::null_mut();
            }
            let raw = raw.assume_init();
            OPENSSL_LH_insert(table.load(), raw.as_ptr().cast::<c_void>());

            let tmplate = EnginePile {
                nid,
                sk: ptr::null_mut(),
                funct: ptr::null_mut(),
                uptodate: 1,
            };
            let fnd = OPENSSL_LH_retrieve(table.load(), ptr::addr_of!(tmplate).cast::<c_void>())
                .cast::<EnginePile>();
            assert_eq!(fnd, raw.as_ptr());
            let _ = raw.into_raw();

            let e = ENGINE_new();
            assert!(!e.is_null());
            (*fnd).funct = e;
            (*e).struct_ref.store(i32::MAX, Ordering::Relaxed);

            let got = ossl_engine_table_select(&table, nid, c"eng_table-test".as_ptr(), 0);
            assert_eq!(got, e, "the cached-default arm must match the authority");
            assert_eq!(
                (*e).struct_ref.load(Ordering::Relaxed),
                i32::MAX,
                "no structural reference was acquired"
            );
            assert_eq!((*e).funct_ref, 0, "no functional reference was acquired");

            // Clear the borrowed cache before the pile's destructor runs: the cached
            // pointer carries no functional reference for `engine_unlocked_finish` to drop.
            (*e).struct_ref.store(1, Ordering::Relaxed);
            (*fnd).funct = ptr::null_mut();
            engine_table_cleanup(&table);
            assert_eq!(ENGINE_free(e), 1);
        }
    }

    /// The authority's other trigger for the same arm: the cached default's own `init`
    /// hook answers 0 (`eng_table.c:233-243`). It likewise returns the cached pointer
    /// without a functional reference.
    #[test]
    fn refused_init_hook_returns_the_cached_default_without_a_reference() {
        let _g = lock_global_state();
        let nid: c_int = 0x4d8;
        let table = EngineTableSlot::new();
        // SAFETY: `table` is this test's own slot; the lhash, pile and engine are built
        // and released exactly once here.
        unsafe {
            assert!(int_table_check(&table, true));
            let raw = RawCtx::<EnginePile>::malloc();
            assert!(raw.is_some(), "the pile block allocates");
            let Some(raw) = raw else { return };
            {
                let p = raw.as_ptr();
                (*p).uptodate = 1;
                (*p).nid = nid;
                (*p).sk = OPENSSL_sk_new_null();
                assert!(!(*p).sk.is_null());
                (*p).funct = ptr::null_mut();
            }
            let raw = raw.assume_init();
            OPENSSL_LH_insert(table.load(), raw.as_ptr().cast::<c_void>());

            let tmplate = EnginePile {
                nid,
                sk: ptr::null_mut(),
                funct: ptr::null_mut(),
                uptodate: 1,
            };
            let fnd = OPENSSL_LH_retrieve(table.load(), ptr::addr_of!(tmplate).cast::<c_void>())
                .cast::<EnginePile>();
            assert_eq!(fnd, raw.as_ptr());
            let _ = raw.into_raw();

            let e = ENGINE_new();
            assert!(!e.is_null());
            (*e).init = Some(refusing_init);
            (*fnd).funct = e;
            INIT_CALLS.store(0, Ordering::SeqCst);

            let got = ossl_engine_table_select(&table, nid, c"eng_table-test".as_ptr(), 0);
            assert_eq!(got, e, "the cached-default arm must match the authority");
            assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1, "the hook ran once");
            assert_eq!((*e).funct_ref, 0, "no functional reference was acquired");
            assert_eq!(
                (*e).struct_ref.load(Ordering::Relaxed),
                1,
                "no structural reference was acquired"
            );

            (*fnd).funct = ptr::null_mut();
            engine_table_cleanup(&table);
            assert_eq!(ENGINE_free(e), 1);
        }
    }

    /// Concurrency control for the slot-access repair: `ossl_engine_table_select`
    /// must share the engine lock with a register/cleanup loop instead of reading the
    /// slot unlocked. Run under ThreadSanitizer; the pre-repair fast path (the
    /// authority's `*table == NULL` check before locking) reports a race here.
    ///
    /// This test deliberately does not take `lock_global_state`: serialising it would
    /// remove the interleaving it exists to exercise. It owns its slot and touches no
    /// other engine state beyond the engine lock, so it does not disturb its siblings.
    #[test]
    fn concurrent_select_and_cleanup_serialise_on_the_engine_lock() {
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        assert!(unsafe { crate::engine::eng_lib::run_engine_lock_init() });
        // The function-local static is the shared slot; every access goes through a table
        // helper or a slot method, which the engine lock serialises.
        static SLOT: EngineTableSlot = EngineTableSlot::new();
        let nid: c_int = 0x4d9;

        let select = std::thread::spawn(move || {
            for _ in 0..2_000 {
                // SAFETY: the helper takes the engine lock before touching the slot.
                unsafe {
                    let _ = ossl_engine_table_select(&SLOT, nid, c"eng_table-race".as_ptr(), 0);
                }
            }
        });
        let mutate = std::thread::spawn(move || {
            for _ in 0..2_000 {
                // SAFETY: both helpers serialise on the engine lock.
                unsafe {
                    assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
                    assert!(int_table_check(&SLOT, true));
                    CRYPTO_THREAD_unlock(global_engine_lock());
                    engine_table_cleanup(&SLOT);
                }
            }
        });
        assert!(select.join().is_ok(), "the select thread does not panic");
        assert!(mutate.join().is_ok(), "the mutate thread does not panic");
        assert!(SLOT.load().is_null(), "cleanup leaves the slot empty");
    }

    /// The slot is the typed replacement for the authority's `ENGINE_TABLE *` static:
    /// `store`/`load` are a round trip and `swap` is the single-owner take cleanup uses.
    #[test]
    fn slot_store_load_and_swap_round_trip() {
        // SAFETY: the lhash and the slot are this test's; the lhash is released once below.
        unsafe {
            let slot = EngineTableSlot::new();
            assert!(slot.load().is_null(), "the slot starts empty");

            let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
            assert!(!lh.is_null());
            slot.store(lh);
            assert_eq!(slot.load(), lh, "store/load is a round trip");

            let taken = slot.swap(ptr::null_mut());
            assert_eq!(taken, lh, "swap returns the pointer it replaced");
            assert!(slot.load().is_null(), "swap published the new value");
            OPENSSL_LH_free(lh);
        }
    }

    /// `engine_table_cleanup` takes the table out of the slot exactly once; the second call
    /// observes an empty slot and must not free the lhash again (a double free here aborts).
    #[test]
    fn cleanup_nulls_the_slot_and_a_second_cleanup_is_a_no_op() {
        // The callee's documented precondition: the engine lock is initialised. Without it
        // the cleanup returns before the swap (the sibling uninitialised-lock test pins that
        // arm); `run_engine_lock_init` is the crate's lock-init path.
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        assert!(unsafe { crate::engine::eng_lib::run_engine_lock_init() });
        // SAFETY: the slot and the lhash in it are this test's.
        unsafe {
            let slot = EngineTableSlot::new();
            // `int_table_check` requires the engine lock for the whole call; take it for the
            // publication only. The lhash afterwards is test-local and no other thread can
            // reach it, so the insert and cleanup below are ordered by `engine_table_cleanup`.
            assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
            let created = int_table_check(&slot, true);
            CRYPTO_THREAD_unlock(global_engine_lock());
            assert!(created, "the lhash is created");
            let lh = slot.load();
            assert!(!lh.is_null());
            let stored = make_pile(0x3347);
            OPENSSL_LH_insert(lh, stored.cast::<c_void>());

            engine_table_cleanup(&slot);
            assert!(slot.load().is_null(), "the first cleanup empties the slot");

            engine_table_cleanup(&slot);
            assert!(slot.load().is_null(), "the second cleanup is a no-op");
        }
    }

    /// C1 (B45 review check 4): `engine_table_cleanup` must return without touching the slot
    /// when `CRYPTO_THREAD_write_lock` answers 0. This thread already holding the write lock is
    /// a real single-thread acquisition-failure arm -- the lock refuses re-acquisition when
    /// `state.writer_id == Some(current_id())` (`src/runtime/thread.rs`) -- so the control needs
    /// no second thread and cannot deadlock.
    ///
    /// The `lock.is_null()` guard that precedes the acquisition is deliberately *not* covered:
    /// `CRYPTO_THREAD_write_lock(NULL)` already returns 0, so deleting that guard alone changes
    /// no observable behaviour. This control fires only when the acquisition check itself is
    /// removed (the cleanup then swaps and releases the table under a failed acquisition, and
    /// the "slot untouched" assertion fails).
    #[test]
    fn cleanup_preserves_the_table_when_the_write_lock_acquisition_fails() {
        // SAFETY: the once storage and init are `eng_lib.rs`'s.
        assert!(unsafe { crate::engine::eng_lib::run_engine_lock_init() });
        // SAFETY: the slot, the lhash and the pile are this test's; the retried cleanup is its
        // single release and the failed acquisition observes them without touching either.
        unsafe {
            let slot = EngineTableSlot::new();
            assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
            let created = int_table_check(&slot, true);
            CRYPTO_THREAD_unlock(global_engine_lock());
            assert!(created, "the lhash is created");
            let lh = slot.load();
            assert!(!lh.is_null());
            let pile = make_pile(0x3348);
            OPENSSL_LH_insert(lh, pile.cast::<c_void>());

            // No release has run yet; the pile's block address is the witness for the
            // release that the succeeding cleanup must perform exactly once.
            crate::runtime::release_probe::clear();

            // Hold the write lock on this thread: the cleanup's acquisition now fails.
            assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
            engine_table_cleanup(&slot);
            assert_eq!(
                slot.load(),
                lh,
                "a failed write-lock acquisition leaves the slot untouched"
            );
            assert!(
                crate::runtime::release_probe::take().is_none(),
                "a failed write-lock acquisition must not release the table"
            );

            // Release and retry: the cleanup now acquires the lock, empties the slot and
            // releases the pile block once.
            CRYPTO_THREAD_unlock(global_engine_lock());
            engine_table_cleanup(&slot);
            assert!(
                slot.load().is_null(),
                "the succeeding cleanup empties the slot"
            );
            let call = crate::runtime::release_probe::take()
                .expect("the succeeding cleanup releases the pile block");
            assert_eq!(
                call.ptr as usize, pile as usize,
                "the release names the pile block this slot held"
            );
            assert!(
                crate::runtime::release_probe::take().is_none(),
                "the release happens exactly once"
            );

            // Idempotence: a third call observes the empty slot and releases nothing.
            engine_table_cleanup(&slot);
            assert!(
                slot.load().is_null(),
                "a third cleanup leaves the slot empty"
            );
            assert!(
                crate::runtime::release_probe::take().is_none(),
                "a third cleanup releases nothing"
            );
        }
    }

    const UNINIT_LOCK_CHILD_ENV: &str = "OPENSSL_RS_ENG_TABLE_UNINIT_LOCK_CHILD";

    /// The callee's other documented arm: when the engine lock was never initialised,
    /// `engine_table_cleanup` returns without swapping the slot. Production cannot reach it —
    /// every public path that yields an `ENGINE` runs the lock init, and registration is the
    /// only way to enqueue the cleanup callback — so this pins the precondition rather than a
    /// supported mode. The un-swapped slot keeps the lhash (and its piles), so the observable
    /// result of this arm is a **leak**: the authority-compatible no-op, not UB. The probe
    /// reclaims the lhash so the test itself leaks nothing.
    ///
    /// The engine lock is a process-global run-once, so the observation is made in a fresh
    /// process in which this is the only test that runs.
    #[test]
    fn uninitialised_engine_lock_makes_cleanup_a_documented_no_op() {
        if std::env::var_os(UNINIT_LOCK_CHILD_ENV).is_some() {
            run_uninitialised_lock_probe();
            return;
        }

        let exe = std::env::current_exe().expect("the test binary has a path");
        let ran_and_passed = std::process::Command::new(exe)
            .args([
                "--exact",
                "engine::eng_table::tests::uninitialised_engine_lock_makes_cleanup_a_documented_no_op",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(UNINIT_LOCK_CHILD_ENV, "1")
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        assert!(
            ran_and_passed,
            "the isolated uninitialised-lock probe failed"
        );
    }

    fn run_uninitialised_lock_probe() {
        // This process runs exactly this test, so no earlier test has run the lock's once; the
        // accessor therefore still reports NULL.
        assert!(
            crate::engine::eng_lib::global_engine_lock().is_null(),
            "the child must start before the engine lock once"
        );

        // SAFETY: the slot and the lhash are this test's; the lhash is reclaimed exactly once
        // below after the no-op is observed.
        unsafe {
            let slot = EngineTableSlot::new();
            // Do not call `int_table_check`: its contract requires the engine lock, which this
            // probe deliberately leaves uninitialised. Build the same lhash directly and
            // publish it into a test-local slot no other thread can observe.
            let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
            assert!(!lh.is_null(), "the lhash is created");
            slot.store(lh);

            engine_table_cleanup(&slot);

            assert_eq!(
                slot.load(),
                lh,
                "an uninitialised lock leaves the slot untouched"
            );
            // The documented failure: the table was not released. Take it out of the slot and
            // release it here so the probe itself does not leak; production never takes this
            // arm (registration requires an ENGINE, whose constructor initialised the lock).
            assert_eq!(slot.swap(ptr::null_mut()), lh);
            OPENSSL_LH_free(lh);
        }
    }

    /// A real register -> select -> cleanup cycle through the typed slot.
    #[test]
    fn register_select_and_cleanup_round_trip_through_the_slot() {
        let _g = lock_global_state();
        let slot = EngineTableSlot::new();
        let nid: c_int = 0x4da;
        // SAFETY: the engine, the nid array and the slot are this test's; every acquired
        // reference is released before the table is cleaned up.
        unsafe {
            let e = ENGINE_new();
            assert!(!e.is_null());
            let nids = [nid];
            assert_eq!(
                engine_table_register(&slot, None, e, nids.as_ptr(), 1, 0),
                1,
                "the registration succeeds"
            );
            assert!(
                !slot.load().is_null(),
                "register created and stored the table"
            );

            let got = ossl_engine_table_select(&slot, nid, c"eng_table-test".as_ptr(), 0);
            assert_eq!(got, e, "select returns the registered engine");

            // Drop the functional references the select took, then retire the cached
            // default so the pile's destructor does not finish the engine a second time.
            assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
            // `engine_unlocked_finish` mutates the count through `e`, which the loop
            // condition cannot see; iterate over the count read under the lock instead.
            for _ in 0..(*e).funct_ref {
                assert_eq!(engine_unlocked_finish(e, 0), 1);
            }
            assert_eq!((*e).funct_ref, 0, "every functional reference is released");
            let tmplate = template(nid);
            let fnd = OPENSSL_LH_retrieve(slot.load(), ptr::addr_of!(tmplate).cast::<c_void>())
                .cast::<EnginePile>();
            assert!(!fnd.is_null(), "the registered pile is in the table");
            (*fnd).funct = ptr::null_mut();
            CRYPTO_THREAD_unlock(global_engine_lock());

            engine_table_cleanup(&slot);
            assert!(slot.load().is_null(), "cleanup empties the slot");
            assert_eq!(
                ENGINE_free(e),
                1,
                "the test's structural reference is released"
            );
        }
    }

    /// Build one pile the way `engine_table_register` does (a `RawCtx` block, every field
    /// initialised, then `assume_init` -> `into_raw`), with a NULL stack and no cached default so
    /// its destructor has nothing to finish.
    fn make_pile(nid: c_int) -> *mut EnginePile {
        let raw = RawCtx::<EnginePile>::malloc().expect("a pile block allocates");
        // SAFETY: `raw` is fresh storage for an `EnginePile`; the caller writes every field.
        unsafe {
            let p = raw.as_ptr();
            (*p).nid = nid;
            (*p).sk = ptr::null_mut();
            (*p).funct = ptr::null_mut();
            (*p).uptodate = 1;
        }
        // SAFETY: all four fields are written and `raw` is the only owner.
        unsafe { raw.assume_init() }.into_raw()
    }

    fn template(nid: c_int) -> EnginePile {
        EnginePile {
            nid,
            sk: ptr::null_mut(),
            funct: ptr::null_mut(),
            uptodate: 1,
        }
    }

    /// ADV-R1: the hash and comparator contracts must describe the **stack query template**, not
    /// only stored elements. `OPENSSL_LH_retrieve` hashes the caller's `data` key and compares it
    /// against stored nodes, so both callbacks run on `ptr::addr_of!(template)`. This test drives
    /// that path directly and also exercises the release path (`int_cleanup_cb_doall`) that
    /// actually reclaims the stored pile.
    #[test]
    fn lhash_hash_and_compare_accept_a_stack_query_template() {
        // SAFETY: the table and the one pile are this test's; the template is a live local.
        unsafe {
            let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
            assert!(!lh.is_null());
            let stored = make_pile(0x3344);
            OPENSSL_LH_insert(lh, stored.cast::<c_void>());

            let hit = template(0x3344);
            assert_eq!(
                OPENSSL_LH_retrieve(lh, ptr::addr_of!(hit).cast::<c_void>()),
                stored.cast::<c_void>(),
                "the stack template is hashed and compared like a stored element"
            );
            let miss = template(0x3355);
            assert!(
                OPENSSL_LH_retrieve(lh, ptr::addr_of!(miss).cast::<c_void>()).is_null(),
                "a template with another nid does not match"
            );

            // The release path: `int_cleanup_cb_doall` adopts and frees each stored pile.
            OPENSSL_LH_doall(lh, Some(int_cleanup_cb_doall));
            OPENSSL_LH_free(lh);
        }
    }

    unsafe extern "C" fn record_nid(
        nid: c_int,
        _sk: *mut OpenSslStack,
        _def: *mut Engine,
        arg: *mut c_void,
    ) {
        // SAFETY: `arg` is the `c_int` slot `engine_table_doall`'s caller supplied below.
        unsafe { *arg.cast::<c_int>() = nid };
    }

    /// The `doall` adapter (`int_dall`) forwards the stored pile's `nid` and borrowed members to
    /// the application callback. This is the walk `engine_table_doall` installs it for.
    #[test]
    fn engine_table_doall_forwards_each_pile_to_the_callback() {
        // SAFETY: the table, pile and argument slot are this test's.
        unsafe {
            let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
            assert!(!lh.is_null());
            let stored = make_pile(0x3346);
            OPENSSL_LH_insert(lh, stored.cast::<c_void>());

            let mut seen: c_int = -1;
            engine_table_doall(
                lh,
                Some(record_nid),
                ptr::addr_of_mut!(seen).cast::<c_void>(),
            );
            assert_eq!(seen, 0x3346, "the callback saw the pile's nid");

            OPENSSL_LH_doall(lh, Some(int_cleanup_cb_doall));
            OPENSSL_LH_free(lh);
        }
    }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(EnginePile => zero_state_sweep_engine_pile);
