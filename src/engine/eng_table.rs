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
//! The `ENGINE_TABLE **` the callers pass is therefore `*mut *mut OpenSslLhash`, and the
//! one place the authority frees `&(*table)->piles` and nulls `*table` (`:98-99`) is the
//! same `OPENSSL_LH_free` plus null here.
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
use core::sync::atomic::{AtomicU32, Ordering};

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
/// `t` must point to a live `ENGINE_TABLE *` slot, and the engine lock must be held:
/// this access is non-atomic (the crate's table statics are `AtomicPtr`s, but this
/// unit receives a `*mut *mut` view), so every access must be serialised by that lock.
unsafe fn int_table_check(t: *mut *mut OpenSslLhash, create: bool) -> bool {
    // SAFETY: `t` is a live slot per the contract.
    if !unsafe { *t }.is_null() {
        return true;
    }
    if !create {
        return false;
    }
    let lh = OPENSSL_LH_new(Some(engine_pile_hash), Some(engine_pile_cmp));
    if lh.is_null() {
        return false;
    }
    // SAFETY: `t` is a live slot per the contract.
    unsafe { *t = lh };
    true
}

/// `int engine_table_register(ENGINE_TABLE **table, ENGINE_CLEANUP_CB *cleanup,
///     ENGINE *e, const int *nids, int num_nids, int setdefault)` — `:83-149`.
///
/// # Safety
/// `table` must point to a live `ENGINE_TABLE *` slot; `e` must be a live, non-NULL
/// `ENGINE` (the crate's register/set-default wrappers always pass one, and the
/// `setdefault` arm would dereference it; the authority's wrappers check for NULL
/// before calling); `nids` must point to `num_nids` integers; `cleanup` is a caller
/// callback that must remain valid until engine cleanup.
///
/// The registered entry is a **borrow**: `e` must remain alive until it is
/// unregistered, either because the global engine list holds the structural reference
/// (`ENGINE_add`) or because the caller keeps one. The authority assumes the same;
/// [`crate::engine::eng_list`]'s removal path retires the borrow before dropping the
/// list's reference.
pub(crate) unsafe fn engine_table_register(
    table: *mut *mut OpenSslLhash,
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
    // SAFETY: `table` is a live slot.
    let added = unsafe { *table }.is_null();
    // SAFETY: `table` is a live slot.
    if !unsafe { int_table_check(table, true) } {
        // SAFETY: the engine lock is held by the caller.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
        return 0;
    }
    if added {
        // SAFETY: `cleanup` is the caller's callback.
        if unsafe { engine_cleanup_add_first(cleanup) } == 0 {
            // SAFETY: `table` is a live slot holding the lhash `int_table_check` built.
            unsafe {
                OPENSSL_LH_free(*table);
                *table = ptr::null_mut();
            }
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
        let lh = unsafe { *table };
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
/// `table` must point to a live `ENGINE_TABLE *` slot; `e` must be a live `ENGINE`.
pub(crate) unsafe fn engine_table_unregister(table: *mut *mut OpenSslLhash, e: *mut Engine) {
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
/// `table` must point to a live `ENGINE_TABLE *` slot; `e` must be a live `ENGINE`; the
/// engine lock must be held by the caller.
pub(crate) unsafe fn engine_table_unregister_locked(table: *mut *mut OpenSslLhash, e: *mut Engine) {
    // SAFETY: `table` is a live slot.
    if unsafe { int_table_check(table, false) } {
        // SAFETY: `table` holds a live lhash and `e` is the caller's engine.
        unsafe {
            OPENSSL_LH_doall_arg(*table, Some(int_unregister_cb), e.cast::<c_void>());
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
/// `table` must point to a live `ENGINE_TABLE *` slot.
pub(crate) unsafe fn engine_table_cleanup(table: *mut *mut OpenSslLhash) {
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return;
    }
    // SAFETY: `table` is a live slot.
    if !unsafe { *table }.is_null() {
        // SAFETY: `table` holds a live lhash.
        unsafe {
            OPENSSL_LH_doall(*table, Some(int_cleanup_cb_doall));
            OPENSSL_LH_free(*table);
            *table = ptr::null_mut();
        }
    }
    // SAFETY: the engine lock is held by the caller.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
}

/// `ENGINE *ossl_engine_table_select(ENGINE_TABLE **table, int nid,
///     const char *f, int l)` — `:200-297`.
///
/// `f`/`l` are the caller's `OPENSSL_FILE`/`OPENSSL_LINE`, used only by the
/// `OSSL_TRACE` calls, which are empty under this build's `no-trace`.
///
/// # Safety
/// `table` must point to a live `ENGINE_TABLE *` slot.
pub(crate) unsafe fn ossl_engine_table_select(
    table: *mut *mut OpenSslLhash,
    nid: c_int,
    f: *const c_char,
    l: c_int,
) -> *mut Engine {
    let _ = (f, l);
    // Load the config before taking the engine lock: configuration modules may register
    // engines, and that path takes the same lock.
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, ptr::null());

    // The authority checks `*table == NULL` before locking. The slot is read here through
    // a non-atomic `*mut` view, so that fast path would race a locked cleanup/register;
    // it is deliberately not reproduced (AGENTS.md §17). A NULL table takes the same
    // `select_end` refusal below, after acquiring the lock.
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return ptr::null_mut();
    }
    ERR_set_mark();
    // Check the slot inside the lock, serialised against cleanup and registration.
    // SAFETY: `table` is a live slot and the engine lock is held.
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
    let lh = unsafe { *table };
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
        let mut table: *mut OpenSslLhash = ptr::null_mut();
        // SAFETY: `table` is this test's own slot; the lhash, pile and engine are built
        // and released exactly once here.
        unsafe {
            assert!(int_table_check(&mut table, true));
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
            OPENSSL_LH_insert(table, raw.as_ptr().cast::<c_void>());

            let tmplate = EnginePile {
                nid,
                sk: ptr::null_mut(),
                funct: ptr::null_mut(),
                uptodate: 1,
            };
            let fnd = OPENSSL_LH_retrieve(table, ptr::addr_of!(tmplate).cast::<c_void>())
                .cast::<EnginePile>();
            assert_eq!(fnd, raw.as_ptr());
            let _ = raw.into_raw();

            let e = ENGINE_new();
            assert!(!e.is_null());
            (*fnd).funct = e;
            (*e).struct_ref.store(i32::MAX, Ordering::Relaxed);

            let got = ossl_engine_table_select(&mut table, nid, c"eng_table-test".as_ptr(), 0);
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
            engine_table_cleanup(&mut table);
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
        let mut table: *mut OpenSslLhash = ptr::null_mut();
        // SAFETY: `table` is this test's own slot; the lhash, pile and engine are built
        // and released exactly once here.
        unsafe {
            assert!(int_table_check(&mut table, true));
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
            OPENSSL_LH_insert(table, raw.as_ptr().cast::<c_void>());

            let tmplate = EnginePile {
                nid,
                sk: ptr::null_mut(),
                funct: ptr::null_mut(),
                uptodate: 1,
            };
            let fnd = OPENSSL_LH_retrieve(table, ptr::addr_of!(tmplate).cast::<c_void>())
                .cast::<EnginePile>();
            assert_eq!(fnd, raw.as_ptr());
            let _ = raw.into_raw();

            let e = ENGINE_new();
            assert!(!e.is_null());
            (*e).init = Some(refusing_init);
            (*fnd).funct = e;
            INIT_CALLS.store(0, Ordering::SeqCst);

            let got = ossl_engine_table_select(&mut table, nid, c"eng_table-test".as_ptr(), 0);
            assert_eq!(got, e, "the cached-default arm must match the authority");
            assert_eq!(INIT_CALLS.load(Ordering::SeqCst), 1, "the hook ran once");
            assert_eq!((*e).funct_ref, 0, "no functional reference was acquired");
            assert_eq!(
                (*e).struct_ref.load(Ordering::Relaxed),
                1,
                "no structural reference was acquired"
            );

            (*fnd).funct = ptr::null_mut();
            engine_table_cleanup(&mut table);
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
        // The heap block is the shared slot; every access goes through a table helper,
        // which the engine lock serialises.
        let slot = Box::into_raw(Box::new(ptr::null_mut::<OpenSslLhash>()));
        let slot_addr = slot as usize;
        let nid: c_int = 0x4d9;

        let select = std::thread::spawn(move || {
            let slot = slot_addr as *mut *mut OpenSslLhash;
            for _ in 0..2_000 {
                // SAFETY: the slot is the test's shared allocation and the helper takes
                // the engine lock before touching it.
                unsafe {
                    let _ = ossl_engine_table_select(slot, nid, c"eng_table-race".as_ptr(), 0);
                }
            }
        });
        let mutate = std::thread::spawn(move || {
            let slot = slot_addr as *mut *mut OpenSslLhash;
            for _ in 0..2_000 {
                // SAFETY: the slot is the test's, and both helpers serialise on the
                // engine lock.
                unsafe {
                    assert!(CRYPTO_THREAD_write_lock(global_engine_lock()) != 0);
                    assert!(int_table_check(slot, true));
                    CRYPTO_THREAD_unlock(global_engine_lock());
                    engine_table_cleanup(slot);
                }
            }
        });
        assert!(select.join().is_ok(), "the select thread does not panic");
        assert!(mutate.join().is_ok(), "the mutate thread does not panic");
        // SAFETY: both threads have joined and cleanup nulled the slot; this is its
        // single release.
        unsafe {
            assert!((*slot).is_null());
            drop(Box::from_raw(slot));
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
