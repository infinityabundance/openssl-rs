//! Phase 6.10a-ii — `crypto/threads_common.c`: the per-context thread-local family.
//!
//! `CRYPTO_THREAD_set_local` stores one value per key per **thread**. This family stores one
//! value per key per thread **per `OSSL_LIB_CTX`**, which is what RCU needs: a thread that
//! takes two locks belonging to two contexts must have two separate reader states, and a
//! single thread-local would make the second acquisition look like a re-entrant one on the
//! first.
//!
//! ## One operating-system key, three levels of indirection
//!
//! | level | index | holds |
//! |---|---|---|
//! | 1 | the single `master_key` | a fixed array of `CRYPTO_THREAD_LOCAL_KEY_MAX` entries |
//! | 2 | the key id | a sparse array |
//! | 3 | the `OSSL_LIB_CTX *`, cast to `uintptr_t` | the caller's data |
//!
//! Level 3's trick is worth stating because it is the reason a *sparse* array is used rather
//! than a hash or a list: libctx pointers are unique, so an address is already a key, and the
//! sparse array's tree costs only the nodes on the paths actually taken. The file's own
//! comment says so, and it is why 6.10a-i had to land first.
//!
//! ## Two things the authority states in its own comments, and both are load-bearing
//!
//! **`master_key_init` exists because the destructor would otherwise read garbage.** The
//! master key is created lazily by a run-once, so a thread that never used this API has no
//! value under the key — but `clean_master_key` is registered as the **key's destructor**, so
//! pthread calls it on every thread that *did* store something. The flag distinguishes "the
//! key was created" from "this thread has data", and without it a destructor could run against
//! an uninitialised key.
//!
//! **`CRYPTO_THREAD_run_once` is used rather than the `RUN_ONCE` macro**, and the source says
//! why: this file is compiled into the FIPS provider as well as libcrypto, FIPS suppresses the
//! `RUN_ONCE` definitions, and this is the one bit of global state that must be initialised in
//! both. That is a *build* reason rather than a behavioural one, and it is recorded here
//! because a reader comparing against another `RUN_ONCE` site would otherwise think this one
//! was an oversight.
//!
//! ## `CRYPTO_THREAD_NO_CONTEXT` is `(void *)1`, not NULL
//!
//! The sentinel lets a caller ask for "the context-free slot" explicitly, and it is **not** the
//! same slot a NULL argument uses. The fold is
//!
//! ```c
//! ctx = (ctx == CRYPTO_THREAD_NO_CONTEXT) ? NULL : ossl_lib_ctx_get_concrete(ctx);
//! ```
//!
//! so the sentinel reaches slot NULL while a NULL argument is *resolved* to the concrete default
//! context first and reaches **that object's** slot. The two differ by one indirection. The
//! first version of this module's documentation asserted they were the same slot; the unit test
//! `the_tables_appear_one_level_at_a_time` is what said otherwise, and it now pins the
//! difference rather than the equivalence.
//!
//! ## What is not released here
//!
//! `clean_master_key` releases the **tables**, not the values in them. The file's own comment
//! says the values "are still expected to be cleaned via the `ossl_init_thread_start/stop`
//! api", which is why `ossl_sa_CTX_TABLE_ENTRY_free` — which is `ossl_sa_free`, nodes only —
//! is the right free and `_free_leaves` would be wrong. D122's chain and 6.6e-ii's handler
//! table meet exactly here: RCU stores its per-thread state in this table and releases it
//! through a thread-stop handler, not through the table's own destructor.
//!
//! ## `CRYPTO_THREAD_LOCAL_ERR_KEY` is declared and read by nothing, and that is deliberate
//!
//! The authority's `crypto/err/err.c` keeps a thread's `ERR_STATE` in this family under key 3:
//! `ossl_err_get_state_int` is
//! `CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY, libctx)` with a create-on-miss, and
//! every raise writes through the same key. This crate keeps that state in a Rust
//! `thread_local!` in `src/runtime/err.rs` instead, so key 3 is declared for the reason every
//! other member of the enum is — it is part of the authority's numbering and a later reader must
//! not silently renumber it — and is stored and read by nothing.
//!
//! **That is a difference in the transcription and not in the contract, and the distinction is
//! why it is written down rather than papered over.** The family is reached only through
//! `CRYPTO_THREAD_get_local_ex` and `CRYPTO_THREAD_set_local_ex`, which are not exported from
//! `libcrypto.so.3`, are in no installed header, and are on no core dispatch table — so no
//! consumer and no provider can read a key. `RT-ERR` is 3,857 observations and it is the court
//! that would have seen the difference, because it measures the per-thread queue through
//! `ERR_get_error`, `ERR_peek_error`, `ERR_set_mark` and `ERR_pop_to_mark`, all of which the
//! crate's `thread_local!` answers identically.
//!
//! What *is* observable one level down is the other direction: a crate module that read key 3
//! would find NULL where the authority finds the state. So the condition attached to the
//! declaration below is not "when this API is used" but "when a crate module needs the state
//! through this family", and a later stratum that does has to **move** the state rather than
//! assume it is already there. That is exactly what `ERR_load_strings`'s recorded no-op and
//! `D-VERIFY-FIRST`'s rule are for: a gap a reader can name is a gap a reader will not trip on.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free};
use crate::runtime::sparse_array::{
    ossl_sa_free, ossl_sa_get, ossl_sa_new, ossl_sa_set, OpenSslSa,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_get_local, CRYPTO_THREAD_init_local, CRYPTO_THREAD_run_once,
    CRYPTO_THREAD_set_local, CryptoThreadLocal,
};

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/threads_common.c".as_ptr();

/// `OPENSSL_calloc(CRYPTO_THREAD_LOCAL_KEY_MAX, sizeof(MASTER_KEY_ENTRY))`.
const L_MKEY_ALLOC: c_int = 361;
/// `OPENSSL_free(mkey)` on the `set_local_ex` failure arm.
const L_MKEY_FREE_SET: c_int = 369;
/// `clean_master_key`'s `OPENSSL_free(mkey)`.
const L_MKEY_FREE_CLEAN: c_int = 202;

/// `#define CRYPTO_THREAD_NO_CONTEXT (void *)1` — `include/internal/threads_common.h`.
///
/// `(void *)1` rather than a named static, because the value is never dereferenced: it is a
/// token a caller passes where a context is expected.
///
/// Written as the literal `1` rather than as `ptr::dangling_mut::<c_void>()`, which clippy
/// suggests: the two happen to be the same value only because `c_void`'s alignment is 1, and
/// the sentinel's meaning is "the integer 1 as a token", not "a dangling pointer". A reader
/// compares this line against `threads_common.h`.
#[allow(clippy::manual_dangling_ptr)]
pub(crate) const CRYPTO_THREAD_NO_CONTEXT: *mut c_void = 1usize as *mut c_void;

/// `typedef enum { ... CRYPTO_THREAD_LOCAL_KEY_MAX } CRYPTO_THREAD_LOCAL_KEY_ID`.
///
/// The enum's values are its declaration order, and the order is a wire format in the same
/// sense the dispatch ids are: `RCU_KEY` is **0** and `TEVENT_KEY` is **6**, so a build that
/// reordered them would silently share tables between subsystems. Only `RCU_KEY` is used by
/// this stratum; the rest are named so the arithmetic is checkable rather than implicit.
pub(crate) type ThreadLocalKeyId = c_int;

/// `CRYPTO_THREAD_LOCAL_RCU_KEY` — the key RCU stores its per-thread reader state under.
#[allow(dead_code)] // unreachable until 6.10a-iii's RCU read path passes it
pub(crate) const CRYPTO_THREAD_LOCAL_RCU_KEY: ThreadLocalKeyId = 0;
/// `CRYPTO_THREAD_LOCAL_DRBG_PRIV_KEY` — Phase 9's.
#[allow(dead_code)] // unreachable until Phase 9 stores a DRBG private state
pub(crate) const CRYPTO_THREAD_LOCAL_DRBG_PRIV_KEY: ThreadLocalKeyId = 1;
/// `CRYPTO_THREAD_LOCAL_DRBG_PUB_KEY` — Phase 9's.
#[allow(dead_code)] // unreachable until Phase 9 stores a DRBG public state
pub(crate) const CRYPTO_THREAD_LOCAL_DRBG_PUB_KEY: ThreadLocalKeyId = 2;
/// `CRYPTO_THREAD_LOCAL_ERR_KEY` — declared, and **read by nothing**: this crate keeps a
/// thread's `ERR_STATE` in `src/runtime/err.rs`'s `thread_local!` rather than at this key. The
/// declaration is kept so the enum's numbering cannot drift, and the module note above records
/// why the difference is unreachable through the public contract and what would make it
/// reachable. Not "unreachable until this API is used" — the API is not the question.
#[allow(dead_code)] // no reader: the state lives in src/runtime/err.rs's `thread_local!`
pub(crate) const CRYPTO_THREAD_LOCAL_ERR_KEY: ThreadLocalKeyId = 3;
/// `CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY` — Phase 14's.
#[allow(dead_code)] // unreachable until the async layer lands
pub(crate) const CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY: ThreadLocalKeyId = 4;
/// `CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY` — Phase 14's.
#[allow(dead_code)] // unreachable until the async layer lands
pub(crate) const CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY: ThreadLocalKeyId = 5;
/// `CRYPTO_THREAD_LOCAL_TEVENT_KEY` — the FIPS build's per-context event key. Absent here.
#[allow(dead_code)] // the non-FIPS build has one global event key, not a per-context one
pub(crate) const CRYPTO_THREAD_LOCAL_TEVENT_KEY: ThreadLocalKeyId = 6;
/// `CRYPTO_THREAD_LOCAL_TANDEM_ID_KEY` — the FIPS tandem key.
#[allow(dead_code)] // FIPS-only
pub(crate) const CRYPTO_THREAD_LOCAL_TANDEM_ID_KEY: ThreadLocalKeyId = 7;

/// `CRYPTO_THREAD_LOCAL_KEY_MAX` — the fixed array's length, and the bound the assertions check.
pub(crate) const CRYPTO_THREAD_LOCAL_KEY_MAX: usize = 8;

/// `typedef void *CTX_TABLE_ENTRY` — `crypto/threads_common.c`.
///
/// A `void *`, so the sparse array's element type is the caller's data pointer and a table's
/// `get` answers it directly. Named here because the authority names it, and because the
/// `DEFINE_SPARSE_ARRAY_OF` instantiation in C carries the same name.
#[allow(dead_code)] // the authority's name for the instantiation; a reader looks for it here
pub(crate) type CtxTableEntry = *mut c_void;

/// `struct master_key_entry { SPARSE_ARRAY_OF(CTX_TABLE_ENTRY) *ctx_table; }`.
///
/// A one-field wrapper in C, and kept as one here: the fixed array indexed by key id is an
/// array of *structs*, so a build that changed the struct's contents would change the stride.
#[repr(C)]
pub(crate) struct MasterKeyEntry {
    /// A sparse array indexed by the libctx pointer, or NULL until the first `set`.
    pub(crate) ctx_table: *mut OpenSslSa,
}

/// The `CRYPTO_THREAD_LOCAL master_key` storage.
///
/// An `UnsafeCell` because `CRYPTO_THREAD_init_local` hands the **address** to
/// `pthread_key_create` and the accessors hand the same address to the pthread specific
/// get/set, so it must be stable and `CryptoThreadLocal`-shaped. The concurrency is the key's
/// own.
struct KeyCell(UnsafeCell<CryptoThreadLocal>);

// SAFETY: the cell holds a `pthread_key_t` written exactly once, by `init_master_key` under a
// run-once, and read afterwards only by the pthread key APIs themselves, which are
// thread-safe. Nothing here reads or writes it outside those paths.
unsafe impl Sync for KeyCell {}

/// `static CRYPTO_THREAD_LOCAL master_key`.
static MASTER_KEY: KeyCell = KeyCell(UnsafeCell::new(0));

/// `static uint8_t master_key_init = 0`.
///
/// The flag the destructor reads. See the module note: without it, `clean_master_key` could run
/// against a key that was never created.
static MASTER_KEY_INIT: AtomicBool = AtomicBool::new(false);

/// `static CRYPTO_ONCE master_once = CRYPTO_ONCE_STATIC_INIT`.
///
/// An `AtomicI32` rather than a bare `static`, because `pthread_once` writes through the
/// pointer it is given — the same defect 6.6e-ii's first run hit.
static MASTER_ONCE: AtomicI32 = AtomicI32::new(0);

/// The key, as a pointer, for the two accessors.
fn master_key_ptr() -> *mut CryptoThreadLocal {
    MASTER_KEY.0.get()
}

/// `static void clean_master_key_id(MASTER_KEY_ENTRY *entry)`.
///
/// Releases the **table only**. See the module note: the values are the caller's, and the
/// authority says so.
///
/// # Safety
/// `entry` must be live and its `ctx_table` NULL or a live array.
unsafe fn clean_master_key_id(entry: *mut MasterKeyEntry) {
    // SAFETY: `entry` is live per the contract, and `ossl_sa_free` accepts NULL.
    unsafe { ossl_sa_free((*entry).ctx_table) };
}

/// `static void clean_master_key(void *data)` — the key's destructor.
///
/// Called by pthread when the thread exits, with the value the key held. A NULL is the ordinary
/// case for a thread that touched no key of this family, and is not an error.
///
/// Declared as a **safe** `extern "C" fn`, because that is the signature the crate's
/// `CRYPTO_THREAD_init_local` takes for a key destructor and pthread's `void (*)(void *)` is
/// not an `unsafe fn` type at the ABI. The unsafe work is in the block below.
extern "C" fn clean_master_key(data: *mut c_void) {
    if data.is_null() {
        return;
    }
    let mkey = data.cast::<MasterKeyEntry>();
    // SAFETY: `data` is the fixed array this module allocated, of `CRYPTO_THREAD_LOCAL_KEY_MAX`
    // entries, so every index below is in bounds.
    unsafe {
        for i in 0..CRYPTO_THREAD_LOCAL_KEY_MAX {
            if !(*mkey.add(i)).ctx_table.is_null() {
                clean_master_key_id(mkey.add(i));
            }
        }
        CRYPTO_free(mkey.cast::<c_void>(), FILE, L_MKEY_FREE_CLEAN);
    }
}

/// `static void init_master_key(void)` — the run-once body.
///
/// `CRYPTO_THREAD_init_local` is used rather than a bare `pthread_key_create`, which matters
/// now that 6.6e-ii landed: the exported function runs `ossl_init_thread()` first, so the
/// event machinery exists before any key of this family can be used. The authority's version
/// calls `CRYPTO_THREAD_init_local` too, so that ordering is theirs and not this crate's.
///
/// A **failed** key creation leaves `master_key_init` clear, which is the whole reason the flag
/// is not set unconditionally: `get` and `set` then answer NULL and 0 rather than touching a key
/// that does not exist.
extern "C" fn init_master_key() {
    // SAFETY: the key's storage is this module's static, and `clean_master_key` is a valid
    // `extern "C"` destructor for it.
    if unsafe { CRYPTO_THREAD_init_local(master_key_ptr(), Some(clean_master_key)) } == 0 {
        return;
    }
    MASTER_KEY_INIT.store(true, Ordering::Release);
}

/// The sentinel fold both accessors do, in one place.
///
/// `CRYPTO_THREAD_NO_CONTEXT` becomes NULL, and a real context is resolved to its concrete
/// object — because the sparse array's index must be the object a caller would compare, not the
/// thread-default indirection they may have passed.
fn resolve_ctx(ctx: *mut c_void) -> *mut c_void {
    if ctx == CRYPTO_THREAD_NO_CONTEXT {
        return ptr::null_mut();
    }
    crate::context::lib_ctx_get_concrete(ctx)
}

/// `void *CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id, OSSL_LIB_CTX *ctx)`.
///
/// Answers NULL for every way there is nothing to answer: no key yet, an out-of-range id, no
/// fixed array for this thread, no table for this id, and no entry for this context. The
/// out-of-range case is `ossl_assert` under `NDEBUG`, so it is a comparison and not an abort —
/// the same build fact several other modules record.
///
/// # Safety
/// `ctx` NULL, the sentinel, or live.
#[allow(non_snake_case)] // the authority's name, kept verbatim like every other one
#[allow(dead_code)] // unreachable until 6.10a-iii's RCU read path reads it
pub(crate) unsafe fn CRYPTO_THREAD_get_local_ex(
    id: ThreadLocalKeyId,
    ctx: *mut c_void,
) -> *mut c_void {
    let ctx = resolve_ctx(ctx);

    // SAFETY: `init_master_key` is a valid `extern "C"` initialiser, and `MASTER_ONCE` is this
    // module's own storage.
    if unsafe { CRYPTO_THREAD_run_once(MASTER_ONCE.as_ptr(), Some(init_master_key)) } == 0 {
        return ptr::null_mut();
    }
    if id < 0 || id as usize >= CRYPTO_THREAD_LOCAL_KEY_MAX {
        return ptr::null_mut();
    }

    // SAFETY: the key is live per the run-once above.
    let mkey = unsafe { CRYPTO_THREAD_get_local(master_key_ptr()) }.cast::<MasterKeyEntry>();
    if mkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mkey` is the fixed array this module allocated, so `id` is in bounds.
    let table = unsafe { (*mkey.add(id as usize)).ctx_table };
    if table.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `table` is live, and the index is the context pointer as an integer by design.
    unsafe { ossl_sa_get(table, ctx as usize as u64) }
}

/// `int CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_KEY_ID id, OSSL_LIB_CTX *ctx,
/// void *data)`.
///
/// Allocates the fixed array on first use for this thread, the table on first use for this key
/// id, and the nodes on first use for this context — so the three levels appear one call at a
/// time and a failure at any of them answers 0 with the array released.
///
/// **`data == NULL` is a removal, and it removes the sparse array's entry rather than storing a
/// NULL there.** `ossl_sa_set` decrements its own count, which is what makes `ossl_sa_num` a
/// real answer about this table.
///
/// # Safety
/// `ctx` NULL, the sentinel, or live. `data` is borrowed and the caller owns it.
#[allow(non_snake_case)] // the authority's name, kept verbatim
#[allow(dead_code)] // unreachable until 6.10a-iii's RCU read path writes it
pub(crate) unsafe fn CRYPTO_THREAD_set_local_ex(
    id: ThreadLocalKeyId,
    ctx: *mut c_void,
    data: *mut c_void,
) -> c_int {
    let ctx = resolve_ctx(ctx);

    // SAFETY: as in `CRYPTO_THREAD_get_local_ex`.
    if unsafe { CRYPTO_THREAD_run_once(MASTER_ONCE.as_ptr(), Some(init_master_key)) } == 0 {
        return 0;
    }
    if id < 0 || id as usize >= CRYPTO_THREAD_LOCAL_KEY_MAX {
        return 0;
    }

    // SAFETY: the key is live per the run-once above.
    let mut mkey = unsafe { CRYPTO_THREAD_get_local(master_key_ptr()) }.cast::<MasterKeyEntry>();
    if mkey.is_null() {
        // `CRYPTO_calloc` is a SAFE function in this crate (D113), so this is unguarded.
        mkey = CRYPTO_calloc(
            CRYPTO_THREAD_LOCAL_KEY_MAX,
            core::mem::size_of::<MasterKeyEntry>(),
            FILE,
            L_MKEY_ALLOC,
        )
        .cast::<MasterKeyEntry>();
        if mkey.is_null() {
            return 0;
        }
        // SAFETY: the key is live per the run-once above.
        if unsafe { CRYPTO_THREAD_set_local(master_key_ptr(), mkey.cast::<c_void>()) } == 0 {
            // SAFETY: `mkey` is this function's own allocation and nothing else holds it.
            unsafe { CRYPTO_free(mkey.cast::<c_void>(), FILE, L_MKEY_FREE_SET) };
            return 0;
        }
    }

    // SAFETY: `mkey` is the fixed array this module allocated, so `id` is in bounds.
    let entry = unsafe { mkey.add(id as usize) };
    // SAFETY: `entry` is in bounds.
    if unsafe { (*entry).ctx_table }.is_null() {
        // `ossl_sa_new` answers NULL only when the allocation fails.
        let fresh = ossl_sa_new();
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `entry` is in bounds and is this thread's, so the write is unshared.
        unsafe { (*entry).ctx_table = fresh };
    }
    // SAFETY: the table is live now, and the index is the context pointer as an integer by
    // design.
    unsafe { ossl_sa_set((*entry).ctx_table, ctx as usize as u64, data) }
}

/// `void CRYPTO_THREAD_clean_local(void)`.
///
/// Releases this thread's whole fixed array and clears the key. **It does not release the
/// values**, so a caller that put owned data in a table and calls this leaks it: that is what
/// the thread-stop handlers are for, and the authority's comment says as much.
///
/// The `master_key_init` guard is the reason the flag exists: without it, this would read a key
/// that was never created and, on a platform where an uninitialised key returns garbage, hand
/// that garbage to `clean_master_key`.
///
/// # Safety
/// None beyond the module's own invariants; it is safe to call on a thread with no data.
#[allow(dead_code)] // unreachable until `OPENSSL_cleanup` calls it, with 6.10a-iii
pub(crate) fn clean_local() {
    if !MASTER_KEY_INIT.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the guard above plus the run-once means the key is live.
    let mkey = unsafe { CRYPTO_THREAD_get_local(master_key_ptr()) }.cast::<MasterKeyEntry>();
    if !mkey.is_null() {
        // SAFETY: `mkey` is the fixed array this module allocated for this thread.
        unsafe {
            clean_master_key(mkey.cast::<c_void>());
            CRYPTO_THREAD_set_local(master_key_ptr(), ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::sparse_array::ossl_sa_num;

    /// A marker the stored values are compared against; never dereferenced.
    static A: u8 = 0x11;
    static B: u8 = 0x22;

    fn marker(k: &'static u8) -> *mut c_void {
        (k as *const u8 as *mut u8).cast::<c_void>()
    }

    /// The three levels exist only as they are needed: a fresh thread answers NULL for every
    /// id and every context, and a `set` on one context does not make another answer.
    #[test]
    fn the_tables_appear_one_level_at_a_time() {
        clean_local();
        let ctx_a = crate::context::OSSL_LIB_CTX_new();
        let ctx_b = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx_a.is_null() && !ctx_b.is_null());
        // SAFETY: the contexts are live and the markers are this test's own.
        unsafe {
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx_a),
                ptr::null_mut()
            );
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx_a, marker(&A)),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx_a),
                marker(&A)
            );
            // A different context is a different slot: that is the whole point of the family.
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx_b),
                ptr::null_mut()
            );
            // So is a different key id.
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(
                    crate::runtime::threads_common::CRYPTO_THREAD_LOCAL_ERR_KEY,
                    ctx_a
                ),
                ptr::null_mut()
            );
            // A NULL argument is *resolved*: `ossl_lib_ctx_get_concrete` follows the thread
            // default and the array is indexed by what that resolves to, which is neither
            // `ctx_a` nor the sentinel.
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ptr::null_mut()),
                ptr::null_mut()
            );
            // The sentinel *skips* that resolution and lands in slot NULL. The two are one
            // indirection apart, and this pair of assertions is where that shows.
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(
                    CRYPTO_THREAD_LOCAL_RCU_KEY,
                    CRYPTO_THREAD_NO_CONTEXT,
                    marker(&B)
                ),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ptr::null_mut()),
                ptr::null_mut(),
                "NULL resolves to the default context, so it is not the sentinel's slot"
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, CRYPTO_THREAD_NO_CONTEXT),
                marker(&B),
                "the sentinel's own slot is reached only by the sentinel"
            );
            clean_local();
            crate::context::OSSL_LIB_CTX_free(ctx_a);
            crate::context::OSSL_LIB_CTX_free(ctx_b);
        }
    }

    /// A NULL value removes the entry rather than storing a NULL, and the table's count follows
    /// — which is what makes `clean_local`'s job and the thread-stop handler's job separable.
    #[test]
    fn a_null_value_is_a_removal() {
        clean_local();
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, marker(&A)),
                1
            );
            let table = {
                let mkey = CRYPTO_THREAD_get_local(master_key_ptr()).cast::<MasterKeyEntry>();
                assert!(!mkey.is_null());
                (*mkey.add(CRYPTO_THREAD_LOCAL_RCU_KEY as usize)).ctx_table
            };
            assert!(!table.is_null());
            // SAFETY: `table` is the live sparse array just read back.
            assert_eq!(ossl_sa_num(table), 1);
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, ptr::null_mut()),
                1
            );
            // SAFETY: as above.
            assert_eq!(ossl_sa_num(table), 0, "a NULL value is a removal");
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx),
                ptr::null_mut()
            );
            clean_local();
            crate::context::OSSL_LIB_CTX_free(ctx);
        }
    }

    /// An out-of-range key id answers NULL and 0 rather than writing past the fixed array. The
    /// authority's `ossl_assert` is non-fatal under `NDEBUG`, so this is a comparison and not an
    /// abort — and a build where it *were* an abort would be a divergence.
    #[test]
    fn an_out_of_range_key_id_is_refused() {
        clean_local();
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_KEY_MAX as c_int, ctx),
                ptr::null_mut()
            );
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_KEY_MAX as c_int, ctx, marker(&A)),
                0
            );
            assert_eq!(CRYPTO_THREAD_get_local_ex(-1, ctx), ptr::null_mut());
            assert_eq!(CRYPTO_THREAD_set_local_ex(-1, ctx, marker(&A)), 0);
            clean_local();
            crate::context::OSSL_LIB_CTX_free(ctx);
        }
    }

    /// `clean_local` releases the tables and clears the key, so a second call is a no-op and a
    /// later `get` answers NULL even for a slot that held a value.
    #[test]
    fn clean_local_clears_the_whole_array_and_is_idempotent() {
        clean_local();
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, marker(&A)),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx),
                marker(&A)
            );
            clean_local();
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx),
                ptr::null_mut(),
                "the fixed array is gone, so every id answers NULL"
            );
            // The second call finds nothing and must not fault.
            clean_local();
            crate::context::OSSL_LIB_CTX_free(ctx);
        }
    }

    /// Two key ids coexist: a value under one does not appear under another, and cleaning one
    /// leaves the other — which is what lets RCU and a future DRBG share the mechanism.
    #[test]
    fn two_key_ids_do_not_collide() {
        clean_local();
        let ctx = crate::context::OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is live.
        unsafe {
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, marker(&A)),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY, ctx, marker(&B)),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx),
                marker(&A)
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY, ctx),
                marker(&B)
            );
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, ptr::null_mut()),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ERR_KEY, ctx),
                marker(&B),
                "removing one key id leaves the other"
            );
            clean_local();
            crate::context::OSSL_LIB_CTX_free(ctx);
        }
    }
}
