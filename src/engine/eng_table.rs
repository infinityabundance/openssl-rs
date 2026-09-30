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
use crate::runtime::err::err_sites::ENG_TABLE_135;
use crate::runtime::err::raise_site;
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};
use crate::runtime::lhash::{
    OPENSSL_LH_doall, OPENSSL_LH_doall_arg, OPENSSL_LH_free, OPENSSL_LH_insert, OPENSSL_LH_new,
    OPENSSL_LH_retrieve, OpenSslLhash,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_delete_ptr, OPENSSL_sk_find, OPENSSL_sk_free,
    OPENSSL_sk_new_null, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

/// `OPENSSL_FILE` for this unit, for the two `OPENSSL_malloc`/`OPENSSL_free` coordinates.
const FILE: *const c_char = c"crypto/engine/eng_table.c".as_ptr();
/// `OPENSSL_LINE` of the pile `OPENSSL_malloc` (`:106`).
const LINE_PILE_NEW: c_int = 106;
/// `OPENSSL_LINE` of the pile `OPENSSL_free` in the failure path (`:113`).
const LINE_PILE_FREE: c_int = 113;

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
unsafe extern "C" fn engine_pile_hash(c: *const c_void) -> core::ffi::c_ulong {
    let pile = c.cast::<EnginePile>();
    // SAFETY: the lhash calls the hash with a stored pile pointer.
    unsafe { (*pile).nid as core::ffi::c_ulong }
}

/// `static int engine_pile_cmp(const ENGINE_PILE *a, const ENGINE_PILE *b)` — `:60-63`.
unsafe extern "C" fn engine_pile_cmp(a: *const c_void, b: *const c_void) -> c_int {
    let a = a.cast::<EnginePile>();
    let b = b.cast::<EnginePile>();
    // SAFETY: the lhash calls the comparison with two stored pile pointers.
    unsafe { (*a).nid - (*b).nid }
}

/// `static int int_table_check(ENGINE_TABLE **t, int create)` — `:65-77`.
///
/// # Safety
/// `t` must point to a live `ENGINE_TABLE *` slot.
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
/// `table` must point to a live `ENGINE_TABLE *` slot; `e` must be NULL or a live
/// `ENGINE`; `nids` must point to `num_nids` integers; `cleanup` is a caller callback.
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
            let raw =
                CRYPTO_malloc(size_of::<EnginePile>(), FILE, LINE_PILE_NEW) as *mut EnginePile;
            if raw.is_null() {
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            // SAFETY: `raw` is the fresh allocation; `tmplate` carries the nid.
            unsafe {
                (*raw).uptodate = 1;
                (*raw).nid = tmplate.nid;
                (*raw).sk = OPENSSL_sk_new_null();
            }
            // SAFETY: `raw` is live.
            if unsafe { (*raw).sk.is_null() } {
                // SAFETY: `raw` is not stored yet.
                unsafe { CRYPTO_free(raw.cast::<c_void>(), FILE, LINE_PILE_FREE) };
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            // SAFETY: `raw` is live.
            unsafe {
                (*raw).funct = ptr::null_mut();
                OPENSSL_LH_insert(lh, raw.cast::<c_void>());
            }
            // SAFETY: the lhash is live and now holds `raw`.
            let again = unsafe { OPENSSL_LH_retrieve(lh, ptr::addr_of!(tmplate).cast::<c_void>()) }
                .cast::<EnginePile>();
            if again != raw {
                // SAFETY: `raw` was not the stored node.
                unsafe {
                    OPENSSL_sk_free((*raw).sk);
                    CRYPTO_free(raw.cast::<c_void>(), FILE, LINE_PILE_FREE);
                }
                // SAFETY: the engine lock is held by the caller.
                unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
                return ret;
            }
            fnd = raw;
        }
        // A registration should not add duplicate entries.
        // SAFETY: `fnd` is a live pile and `e` is the caller's engine.
        unsafe {
            OPENSSL_sk_delete_ptr((*fnd).sk, e.cast::<c_void>());
        }
        // If `setdefault`, this ENGINE goes to the head of the list.
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
    // SAFETY: `table` is a live slot.
    if unsafe { int_table_check(table, false) } {
        // SAFETY: `table` holds a live lhash and `e` is the caller's engine.
        unsafe {
            OPENSSL_LH_doall_arg(*table, Some(int_unregister_cb), e.cast::<c_void>());
        }
    }
    // SAFETY: the engine lock is held by the caller.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
}

/// `static void int_cleanup_cb_doall(ENGINE_PILE *p)` — `:177-185`.
unsafe extern "C" fn int_cleanup_cb_doall(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let p = p.cast::<EnginePile>();
    // SAFETY: `p` is a live pile from the lhash.
    unsafe {
        OPENSSL_sk_free((*p).sk);
        if !(*p).funct.is_null() {
            engine_unlocked_finish((*p).funct, 0);
        }
        CRYPTO_free(p.cast::<c_void>(), FILE, LINE_PILE_FREE);
    }
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
    // Load the config before checking whether engines are available.
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, ptr::null());

    // SAFETY: `table` is a live slot.
    if unsafe { *table }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the lock is the engine lock, created by the run-once.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        return ptr::null_mut();
    }
    ERR_set_mark();
    // Check again inside the lock, racing against cleanup.
    // SAFETY: `table` is a live slot.
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
/// `table` must be NULL or a live `ENGINE_TABLE`; `cb` accepts each pile.
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
