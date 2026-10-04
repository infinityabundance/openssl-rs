//! Phase 16.2 — `crypto/engine/eng_dyn.c`: the dynamic ENGINE loader.
//!
//! This is the unit `ENGINE_by_id`'s miss path reaches. `crypto/engine/eng_dyn.c` defines
//! the `dynamic` built-in ENGINE — its control commands, its `ex_data` context and its
//! `dynamic_load` — and registers it with `engine_load_dynamic_int` (`:250-269`), which is
//! the entry point `crypto/init.c`'s `ossl_init_engine_dynamic` runs when the
//! `OPENSSL_INIT_ENGINE_DYNAMIC` bit is set (`crypto/init.c:328-333`, `:660-662`).
//!
//! ## Why this subphase exists, and what it closes
//!
//! Phase 13.1 transcribed `ENGINE_by_id` whole (`src/engine/eng_list.rs`) but no subphase
//! owned this unit, so the miss path's recursion into `ENGINE_by_id("dynamic")` found no
//! dynamic engine registered and took the authority's own `notfound` arm. `engine_load_dynamic_int`
//! was recorded as a Phase-16 deferral (`forensics/prerequisites.json`, D528). This module
//! lands it, and `src/runtime/init.rs` now runs the step for the `DYNAMIC` bit, so the
//! fallback is live: a caller that sets `OPENSSL_INIT_ENGINE_DYNAMIC` and then calls
//! `ENGINE_by_id("<id>")` finds `dynamic` in the registry and drives it with
//! `ENGINE_ctrl_cmd_string` — `ID`, `DIR_LOAD=2`, `DIR_ADD`, `LIST_ADD=1`, `LOAD` — exactly
//! as the authority does. When the `LOAD` refuses (no shared object under `OPENSSL_ENGINES`
//! or the compiled-in engines directory) the fallback releases the dynamic copy and answers
//! the authority's `ENGINE_R_NO_SUCH_ENGINE` message.
//!
//! ## The `dynamic`/`rdrand` built-ins, and which unit each is
//!
//! `crypto/init.c`'s `OPENSSL_INIT_ENGINE_ALL_BUILTIN` names several engines, and the
//! admitted Linux/x86-64 build registers two of them by default: `rdrand`
//! (`crypto/engine/eng_rdrand.c`) and `dynamic` (this unit). **Only `dynamic` is this
//! subphase's**: `engine_load_dynamic_int` registers the `dynamic` engine and nothing else.
//! `rdrand` is `eng_rdrand.c`'s `engine_load_rdrand_int`, a separate unit that
//! `src/engine/mod.rs` still withholds by name. So this module's registration is the
//! `dynamic` id; the plan row names both because the `ALL_BUILTIN` bit reaches both, not
//! because one function registers both.
//!
//! **The `ALL_BUILTIN` load remains a recorded boundary.** `ENGINE_load_builtin_engines`
//! (`src/engine/eng_all.rs`) is still the authority's
//! `OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL)`, and that mask carries the
//! engine bits whose subsystems (`eng_openssl.c`, `eng_rdrand.c`, the platform engines) are
//! not in this crate, so `src/runtime/init.rs` still refuses it. This subphase leaves that
//! bit's refusal in place; what it adds is the **`DYNAMIC` bit alone**, which the authority
//! honours and a caller can set directly, and the loader that bit registers.
//!
//! ## Reproduction notes
//!
//! * `dynamic_load`'s `memcpy(&cpy, e, sizeof(ENGINE))` rollback is reproduced with
//!   `ptr::copy_nonoverlapping` over `size_of::<Engine>()` bytes: the authority copies the
//!   whole structure, the crate copies the whole structure, and the `Engine` layout is
//!   already pinned (`eng_lib.rs`).
//! * `engine_add_dynamic_id` and `engine_remove_dynamic_id` are 13.1's, reached with the
//!   `bind_engine` pointer re-interpreted as `ENGINE_DYNAMIC_ID`, exactly as the authority
//!   casts it.
//! * `dynamic_set_data_ctx`'s `goto end` arms free the half-built context and return the
//!   authority's `ret`; its unconditional `ret = 1` after the lock is the authority's own
//!   shape and is kept.
//! * The `ex_data` free hook is registered through `CRYPTO_get_ex_new_index`
//!   (`CRYPTO_EX_INDEX_ENGINE`), which is what the `ENGINE_get_ex_new_index` macro expands to.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)] // the context structure's fields are the authority's names

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::dso::{
    DSO_bind_func, DSO_convert_filename, DSO_ctrl, DSO_free, DSO_load, DSO_merge, DSO_new, Dso,
    DSO_CTRL_SET_FLAGS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,
};
use crate::engine::eng_lib::{
    engine_set_all_null, global_engine_lock, ENGINE_free, ENGINE_get_ex_data,
    ENGINE_get_static_state, ENGINE_new, ENGINE_set_cmd_defns, ENGINE_set_ctrl_function,
    ENGINE_set_finish_function, ENGINE_set_flags, ENGINE_set_id, ENGINE_set_init_function,
    ENGINE_set_name, Engine, EngineCmdDefn, EngineCtrlFuncPtr, EngineGenIntFuncPtr,
};
use crate::engine::eng_list::{engine_add_dynamic_id, engine_remove_dynamic_id, ENGINE_add};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    ENG_DYN_166, ENG_DYN_213, ENG_DYN_295, ENG_DYN_301, ENG_DYN_330, ENG_DYN_339, ENG_DYN_347,
    ENG_DYN_356, ENG_DYN_364, ENG_DYN_429, ENG_DYN_440, ENG_DYN_465, ENG_DYN_498, ENG_DYN_514,
};
use crate::runtime::err::{raise_site, ERR_clear_error, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::ex_data::{CRYPTO_get_ex_new_index, CryptoExData, CRYPTO_EX_INDEX_ENGINE};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_get_mem_functions, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};

extern "C" {
    /// `size_t strlen(const char *)`.
    fn strlen(s: *const c_char) -> usize;
}

/// `OPENSSL_FILE` for the allocations and frees this unit makes, so a caller's
/// `CRYPTO_set_mem_functions` sees the authority's own coordinate.
const FILE: *const c_char = c"crypto/engine/eng_dyn.c".as_ptr();

/// `dynamic_set_data_ctx`'s `OPENSSL_zalloc(sizeof(*c))` (`:159`).
const LINE_SET_CTX_ZALLOC: c_int = 159;
/// `dynamic_data_ctx_free_func`'s `OPENSSL_free(ctx->DYNAMIC_LIBNAME)` (`:144`).
const LINE_FREE_LIBNAME: c_int = 144;
/// `dynamic_data_ctx_free_func`'s `OPENSSL_free(ctx->engine_id)` (`:145`).
const LINE_FREE_ENGINE_ID: c_int = 145;
/// `dynamic_data_ctx_free_func`'s `OPENSSL_free(ctx)` (`:147`).
const LINE_FREE_CTX: c_int = 147;
/// `dynamic_set_data_ctx`'s failure-path `OPENSSL_free(c)` through `end` (`:193`).
const LINE_FREE_CTX_END: c_int = 193;
/// `int_free_str`'s `OPENSSL_free(s)` (`:125`).
const LINE_INT_FREE_STR: c_int = 125;
/// `dynamic_ctrl`'s `OPENSSL_free(ctx->DYNAMIC_LIBNAME)` (`:309`).
const LINE_FREE_SO_PATH: c_int = 309;
/// `dynamic_ctrl`'s `OPENSSL_free(ctx->engine_id)` (`:322`).
const LINE_FREE_ID: c_int = 322;
/// `dynamic_ctrl`'s `OPENSSL_strdup` of `SO_PATH` (`:311`).
const LINE_STRDUP_SO_PATH: c_int = 311;
/// `dynamic_ctrl`'s `OPENSSL_strdup` of `ID` (`:324`).
const LINE_STRDUP_ID: c_int = 324;
/// `dynamic_ctrl`'s `OPENSSL_strdup` of the `DIR_ADD` argument (`:351`).
const LINE_STRDUP_DIR: c_int = 351;
/// `int_load`'s `OPENSSL_free(merge)` on the found path (`:384`).
const LINE_FREE_MERGE_FOUND: c_int = 384;
/// `int_load`'s `OPENSSL_free(merge)` on the not-found path (`:387`).
const LINE_FREE_MERGE_MISS: c_int = 387;

/// `ENGINE_FLAGS_BY_ID_COPY` — `include/openssl/engine.h:88`, `(int)0x0004`.
const ENGINE_FLAGS_BY_ID_COPY: c_int = 0x0004;

/// `ENGINE_CMD_BASE` — `include/openssl/engine.h:224`, the first command number a
/// caller-defined engine command may use.
const ENGINE_CMD_BASE: c_int = 200;
/// `ENGINE_CMD_FLAG_NUMERIC` — `(unsigned int)0x0001`.
const ENGINE_CMD_FLAG_NUMERIC: c_uint = 0x0001;
/// `ENGINE_CMD_FLAG_STRING` — `(unsigned int)0x0002`.
const ENGINE_CMD_FLAG_STRING: c_uint = 0x0002;
/// `ENGINE_CMD_FLAG_NO_INPUT` — `(unsigned int)0x0004`.
const ENGINE_CMD_FLAG_NO_INPUT: c_uint = 0x0004;

/// `OSSL_DYNAMIC_VERSION` — `include/openssl/engine.h:722`, `(unsigned long)0x00030000`.
const OSSL_DYNAMIC_VERSION: c_ulong = 0x0003_0000;
/// `OSSL_DYNAMIC_OLDEST` — `include/openssl/engine.h:727`, `(unsigned long)0x00030000`.
const OSSL_DYNAMIC_OLDEST: c_ulong = 0x0003_0000;

// The seven command numbers (`eng_dyn.c:33-39`), each `ENGINE_CMD_BASE + n`.
/// `DYNAMIC_CMD_SO_PATH`.
const DYNAMIC_CMD_SO_PATH: c_int = ENGINE_CMD_BASE;
/// `DYNAMIC_CMD_NO_VCHECK`.
const DYNAMIC_CMD_NO_VCHECK: c_int = ENGINE_CMD_BASE + 1;
/// `DYNAMIC_CMD_ID`.
const DYNAMIC_CMD_ID: c_int = ENGINE_CMD_BASE + 2;
/// `DYNAMIC_CMD_LIST_ADD`.
const DYNAMIC_CMD_LIST_ADD: c_int = ENGINE_CMD_BASE + 3;
/// `DYNAMIC_CMD_DIR_LOAD`.
const DYNAMIC_CMD_DIR_LOAD: c_int = ENGINE_CMD_BASE + 4;
/// `DYNAMIC_CMD_DIR_ADD`.
const DYNAMIC_CMD_DIR_ADD: c_int = ENGINE_CMD_BASE + 5;
/// `DYNAMIC_CMD_LOAD`.
const DYNAMIC_CMD_LOAD: c_int = ENGINE_CMD_BASE + 6;

/// `dynamic_v_check_fn` — `typedef unsigned long (*)(unsigned long)` (`engine.h:770`).
type DynamicVCheckFn = unsafe extern "C" fn(c_ulong) -> c_ulong;

/// `dynamic_bind_engine` — `typedef int (*)(ENGINE *, const char *, const dynamic_fns *)`
/// (`engine.h:798`).
type DynamicBindEngine =
    unsafe extern "C" fn(*mut Engine, *const c_char, *const DynamicFns) -> c_int;

/// `dyn_MEM_malloc_fn` — `void *(*)(size_t, const char *, int)` (`engine.h:740`).
type DynMemMallocFn = unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void;
/// `dyn_MEM_realloc_fn` — `void *(*)(void *, size_t, const char *, int)` (`engine.h:741`).
type DynMemReallocFn =
    unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void;
/// `dyn_MEM_free_fn` — `void (*)(void *, const char *, int)` (`engine.h:742`).
type DynMemFreeFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

/// `dynamic_MEM_fns` — `include/openssl/engine.h:743-747`.
///
/// Each slot is an `Option`, because `CRYPTO_get_mem_functions` reports NULL for an
/// uninstalled allocator and the authority's plain pointers can be NULL.
#[repr(C)]
struct DynamicMemFns {
    /// `dyn_MEM_malloc_fn malloc_fn`.
    malloc_fn: Option<DynMemMallocFn>,
    /// `dyn_MEM_realloc_fn realloc_fn`.
    realloc_fn: Option<DynMemReallocFn>,
    /// `dyn_MEM_free_fn free_fn`.
    free_fn: Option<DynMemFreeFn>,
}

/// `dynamic_fns` — `include/openssl/engine.h:753-756`, the ABI the loaded library receives.
#[repr(C)]
struct DynamicFns {
    /// `void *static_state` — compared against `ENGINE_get_static_state()` by `bind_engine`.
    static_state: *mut c_void,
    /// `dynamic_MEM_fns mem_fns`.
    mem_fns: DynamicMemFns,
}

/// `struct st_dynamic_data_ctx` — `crypto/engine/eng_dyn.c:81-115`, the per-ENGINE context
/// stored in the ENGINE's `ex_data`.
#[repr(C)]
struct DynamicDataCtx {
    /// `DSO *dynamic_dso`.
    dynamic_dso: *mut Dso,
    /// `dynamic_v_check_fn v_check`.
    v_check: Option<DynamicVCheckFn>,
    /// `dynamic_bind_engine bind_engine`.
    bind_engine: Option<DynamicBindEngine>,
    /// `char *DYNAMIC_LIBNAME`.
    DYNAMIC_LIBNAME: *mut c_char,
    /// `int no_vcheck`.
    no_vcheck: c_int,
    /// `char *engine_id`.
    engine_id: *mut c_char,
    /// `int list_add_value`.
    list_add_value: c_int,
    /// `const char *DYNAMIC_F1` — `"v_check"`.
    DYNAMIC_F1: *const c_char,
    /// `const char *DYNAMIC_F2` — `"bind_engine"`.
    DYNAMIC_F2: *const c_char,
    /// `int dir_load`.
    dir_load: c_int,
    /// `STACK_OF(OPENSSL_STRING) *dirs`.
    dirs: *mut OpenSslStack,
}

/// A `static` array of command definitions.
///
/// `EngineCmdDefn` holds raw pointers, so it is not `Sync`; the array is immutable and
/// only ever read, so the manual `Sync` is sound. `engine_dynamic` hands its address to
/// `ENGINE_set_cmd_defns`, which stores it for the life of the engine, so it must be
/// `'static`.
#[repr(transparent)]
struct SyncCmdDefns([EngineCmdDefn; 8]);
// SAFETY: the array is never mutated after this static is initialised.
unsafe impl Sync for SyncCmdDefns {}

/// `dynamic_cmd_defns[]` — `crypto/engine/eng_dyn.c:44-74`.
static DYNAMIC_CMD_DEFNS: SyncCmdDefns = SyncCmdDefns([
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_SO_PATH as c_uint,
        cmd_name: c"SO_PATH".as_ptr(),
        cmd_desc: c"Specifies the path to the new ENGINE shared library".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_STRING,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_NO_VCHECK as c_uint,
        cmd_name: c"NO_VCHECK".as_ptr(),
        cmd_desc: c"Specifies to continue even if version checking fails (boolean)".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_NUMERIC,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_ID as c_uint,
        cmd_name: c"ID".as_ptr(),
        cmd_desc: c"Specifies an ENGINE id name for loading".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_STRING,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_LIST_ADD as c_uint,
        cmd_name: c"LIST_ADD".as_ptr(),
        cmd_desc: c"Whether to add a loaded ENGINE to the internal list (0=no,1=yes,2=mandatory)"
            .as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_NUMERIC,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_DIR_LOAD as c_uint,
        cmd_name: c"DIR_LOAD".as_ptr(),
        cmd_desc: c"Specifies whether to load from 'DIR_ADD' directories (0=no,1=yes,2=mandatory)"
            .as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_NUMERIC,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_DIR_ADD as c_uint,
        cmd_name: c"DIR_ADD".as_ptr(),
        cmd_desc: c"Adds a directory from which ENGINEs can be loaded".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_STRING,
    },
    EngineCmdDefn {
        cmd_num: DYNAMIC_CMD_LOAD as c_uint,
        cmd_name: c"LOAD".as_ptr(),
        cmd_desc: c"Load up the ENGINE specified by other settings".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_NO_INPUT,
    },
    EngineCmdDefn {
        cmd_num: 0,
        cmd_name: ptr::null(),
        cmd_desc: ptr::null(),
        cmd_flags: 0,
    },
]);

/// `static int dynamic_ex_data_idx = -1` (`:121`).
///
/// Atomic because `dynamic_get_data_ctx` reads it outside the lock and the writers take
/// `global_engine_lock`; the value is a plain index, so the accesses are `Relaxed`.
static DYNAMIC_EX_DATA_IDX: AtomicI32 = AtomicI32::new(-1);

/// `static void int_free_str(char *s)` — `crypto/engine/eng_dyn.c:123-126`.
///
/// The stack element destructor: `sk_OPENSSL_STRING_pop_free(ctx->dirs, int_free_str)`.
///
/// # Safety
/// `s` must be NULL or one of this module's `CRYPTO_strdup` results.
unsafe extern "C" fn int_free_str(s: *mut c_void) {
    // SAFETY: `s` is NULL or a `CRYPTO_strdup` answer, per the caller's contract.
    unsafe { CRYPTO_free(s, FILE, LINE_INT_FREE_STR) };
}

/// `static void dynamic_data_ctx_free_func(...)` — `crypto/engine/eng_dyn.c:137-149`.
///
/// Registered as the `CRYPTO_EX_INDEX_ENGINE` free hook, so it runs when an ENGINE holding
/// a [`DynamicDataCtx`] is destroyed. The signature is `CRYPTO_EX_free`'s.
unsafe extern "C" fn dynamic_data_ctx_free_func(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if ptr.is_null() {
        return;
    }
    let ctx = ptr.cast::<DynamicDataCtx>();
    // SAFETY: `ptr` is a ctx this module allocated and stored, so every field is live.
    unsafe {
        DSO_free((*ctx).dynamic_dso);
        CRYPTO_free(
            (*ctx).DYNAMIC_LIBNAME.cast::<c_void>(),
            FILE,
            LINE_FREE_LIBNAME,
        );
        CRYPTO_free((*ctx).engine_id.cast::<c_void>(), FILE, LINE_FREE_ENGINE_ID);
        OPENSSL_sk_pop_free((*ctx).dirs, Some(int_free_str));
        CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX);
    }
}

/// The authority's `end:` tail of `dynamic_set_data_ctx` (`:190-194`): free the half-built
/// context (if still owned) and answer `ret`.
///
/// # Safety
/// `c` must be NULL or a context this module allocated whose `dirs` field is live.
unsafe fn set_data_ctx_end(c: *mut DynamicDataCtx, ret: c_int) -> c_int {
    if !c.is_null() {
        // SAFETY: `c` is a live context whose `dirs` is the stack `sk_new_null` answered
        // (NULL-safe).
        unsafe { OPENSSL_sk_free((*c).dirs) };
        // SAFETY: `c` is this function's own allocation.
        unsafe { CRYPTO_free(c.cast::<c_void>(), FILE, LINE_FREE_CTX_END) };
    }
    ret
}

/// `static int dynamic_set_data_ctx(ENGINE *e, dynamic_data_ctx **ctx)` — `:157-195`.
///
/// # Safety
/// `e` must be a live `ENGINE` and `ctx` a writable slot.
unsafe fn dynamic_set_data_ctx(e: *mut Engine, ctx: *mut *mut DynamicDataCtx) -> c_int {
    // SAFETY: `size_of` matches the type, and a zeroed context is a valid one.
    let mut c = CRYPTO_zalloc(size_of::<DynamicDataCtx>(), FILE, LINE_SET_CTX_ZALLOC)
        .cast::<DynamicDataCtx>();
    let mut ret = 0;
    if c.is_null() {
        return 0;
    }
    // SAFETY: `c` is a fresh zeroed context.
    unsafe {
        (*c).dirs = OPENSSL_sk_new_null();
        if (*c).dirs.is_null() {
            // `ERR_raise(ERR_LIB_ENGINE, ERR_R_CRYPTO_LIB)` (`:166`), then `goto end`.
            raise_site(&ENG_DYN_166);
            return set_data_ctx_end(c, ret);
        }
        (*c).DYNAMIC_F1 = c"v_check".as_ptr();
        (*c).DYNAMIC_F2 = c"bind_engine".as_ptr();
        (*c).dir_load = 1;
    }
    // SAFETY: the lock is the registry's global one.
    if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
        // SAFETY: `c` is a live context this function owns (the lock was never taken).
        return unsafe { set_data_ctx_end(c, ret) };
    }
    let idx = DYNAMIC_EX_DATA_IDX.load(Ordering::Relaxed);
    // SAFETY: `e` is live and `idx` is a registered engine index.
    let existing = unsafe { ENGINE_get_ex_data(e, idx) }.cast::<DynamicDataCtx>();
    if existing.is_null() {
        // SAFETY: `e` is live and `c` is this function's allocation.
        ret = unsafe { crate::engine::eng_lib::ENGINE_set_ex_data(e, idx, c.cast::<c_void>()) };
        if ret != 0 {
            // SAFETY: `ctx` is writable per the caller's contract.
            unsafe { *ctx = c };
            c = ptr::null_mut();
        }
    } else {
        // SAFETY: `ctx` is writable per the caller's contract.
        unsafe { *ctx = existing };
    }
    // SAFETY: the lock is held by this thread.
    unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
    ret = 1;
    // SAFETY: `c` is NULL or a live context this function still owns.
    unsafe { set_data_ctx_end(c, ret) }
}

/// `static dynamic_data_ctx *dynamic_get_data_ctx(ENGINE *e)` — `:201-236`.
///
/// # Safety
/// `e` must be a live `ENGINE`.
unsafe fn dynamic_get_data_ctx(e: *mut Engine) -> *mut DynamicDataCtx {
    if DYNAMIC_EX_DATA_IDX.load(Ordering::Relaxed) < 0 {
        // `ENGINE_get_ex_new_index(0, NULL, NULL, NULL, dynamic_data_ctx_free_func)` is the
        // macro's expansion to `CRYPTO_get_ex_new_index` (`engine.h:530`).
        let new_idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_ENGINE,
            0,
            ptr::null_mut(),
            None,
            None,
            Some(dynamic_data_ctx_free_func),
        );
        if new_idx == -1 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ENG_DYN_213) };
            return ptr::null_mut();
        }
        // SAFETY: the lock is the registry's global one.
        if unsafe { CRYPTO_THREAD_write_lock(global_engine_lock()) } == 0 {
            return ptr::null_mut();
        }
        // Avoid a race by checking again inside the lock.
        if DYNAMIC_EX_DATA_IDX.load(Ordering::Relaxed) < 0 {
            DYNAMIC_EX_DATA_IDX.store(new_idx, Ordering::Relaxed);
        }
        // SAFETY: the lock is held by this thread.
        unsafe { CRYPTO_THREAD_unlock(global_engine_lock()) };
    }
    let idx = DYNAMIC_EX_DATA_IDX.load(Ordering::Relaxed);
    // SAFETY: `e` is live and `idx` is a registered engine index.
    let mut ctx = unsafe { ENGINE_get_ex_data(e, idx) }.cast::<DynamicDataCtx>();
    if ctx.is_null() {
        // SAFETY: `e` is live and `ctx` is a local slot.
        if unsafe { dynamic_set_data_ctx(e, &mut ctx) } == 0 {
            return ptr::null_mut();
        }
    }
    ctx
}

/// `static ENGINE *engine_dynamic(void)` — `crypto/engine/eng_dyn.c:238-248`.
///
/// # Safety
/// None: the answer is a new engine or NULL. The caller owns one structural reference.
unsafe fn engine_dynamic() -> *mut Engine {
    let ret = ENGINE_new();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is a fresh engine; every setter takes it live.
    let ok = unsafe {
        ENGINE_set_id(ret, c"dynamic".as_ptr()) != 0
            && ENGINE_set_name(ret, c"Dynamic engine loading support".as_ptr()) != 0
            && ENGINE_set_init_function(ret, Some(dynamic_init)) != 0
            && ENGINE_set_finish_function(ret, Some(dynamic_finish)) != 0
            && ENGINE_set_ctrl_function(ret, Some(dynamic_ctrl)) != 0
            && ENGINE_set_flags(ret, ENGINE_FLAGS_BY_ID_COPY) != 0
            && ENGINE_set_cmd_defns(ret, DYNAMIC_CMD_DEFNS.0.as_ptr()) != 0
    };
    if !ok {
        // SAFETY: `ret` is this function's reference.
        unsafe { ENGINE_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `void engine_load_dynamic_int(void)` — `crypto/engine/eng_dyn.c:250-269`.
///
/// The entry point `crypto/init.c`'s `ossl_init_engine_dynamic` runs. The mark/pop pair
/// keeps the "already added" conflict out of the caller's error queue.
///
/// # Safety
/// The caller must accept the process-global effect the authority's own call has: it
/// registers the `dynamic` engine in the registry.
pub(crate) unsafe fn engine_load_dynamic_int() {
    // SAFETY: `engine_dynamic` allocates a fresh engine or answers NULL.
    let toadd = unsafe { engine_dynamic() };
    if toadd.is_null() {
        return;
    }
    ERR_set_mark();
    // SAFETY: `toadd` is live and unregistered.
    unsafe { ENGINE_add(toadd) };
    // SAFETY: `toadd` is this function's reference; the add took its own if it succeeded.
    unsafe { ENGINE_free(toadd) };
    ERR_pop_to_mark();
}

/// `static int dynamic_init(ENGINE *e)` — `:271-278`.
///
/// The `dynamic` engine itself can never be used, so init always fails.
unsafe extern "C" fn dynamic_init(_e: *mut Engine) -> c_int {
    0
}

/// `static int dynamic_finish(ENGINE *e)` — `:280-287`.
///
/// Never reached, because [`dynamic_init`] always fails.
unsafe extern "C" fn dynamic_finish(_e: *mut Engine) -> c_int {
    0
}

/// `static int dynamic_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))` — `:289-366`.
///
/// # Safety
/// Called through the ENGINE control surface with the authority's argument contract.
unsafe extern "C" fn dynamic_ctrl(
    e: *mut Engine,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is live per the caller's contract.
        let ctx = unsafe { dynamic_get_data_ctx(e) };
        if ctx.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ENG_DYN_295) };
            return 0;
        }
        // SAFETY: `ctx` is live.
        let initialised = unsafe { !(*ctx).dynamic_dso.is_null() };
        if initialised {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ENG_DYN_301) };
            return 0;
        }
        match cmd {
            DYNAMIC_CMD_SO_PATH => {
                let mut p = p;
                // A NULL `p` or a string of zero length is the same thing.
                // SAFETY: `p` is NULL or a NUL-terminated string per the call contract;
                // `strlen` is only reached when it is non-NULL.
                if !p.is_null() && unsafe { strlen(p.cast::<c_char>()) } < 1 {
                    p = ptr::null_mut();
                }
                // SAFETY: `ctx` is live and owns `DYNAMIC_LIBNAME`.
                unsafe {
                    CRYPTO_free(
                        (*ctx).DYNAMIC_LIBNAME.cast::<c_void>(),
                        FILE,
                        LINE_FREE_SO_PATH,
                    );
                    (*ctx).DYNAMIC_LIBNAME = if p.is_null() {
                        ptr::null_mut()
                    } else {
                        CRYPTO_strdup(p.cast::<c_char>(), FILE, LINE_STRDUP_SO_PATH)
                    };
                    c_int::from(!(*ctx).DYNAMIC_LIBNAME.is_null())
                }
            }
            DYNAMIC_CMD_NO_VCHECK => {
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).no_vcheck = c_int::from(i != 0) };
                1
            }
            DYNAMIC_CMD_ID => {
                let mut p = p;
                // SAFETY: `p` is NULL or a NUL-terminated string per the call contract;
                // `strlen` is only reached when it is non-NULL.
                if !p.is_null() && unsafe { strlen(p.cast::<c_char>()) } < 1 {
                    p = ptr::null_mut();
                }
                // SAFETY: `ctx` is live and owns `engine_id`.
                unsafe {
                    CRYPTO_free((*ctx).engine_id.cast::<c_void>(), FILE, LINE_FREE_ID);
                    (*ctx).engine_id = if p.is_null() {
                        ptr::null_mut()
                    } else {
                        CRYPTO_strdup(p.cast::<c_char>(), FILE, LINE_STRDUP_ID)
                    };
                    c_int::from(!(*ctx).engine_id.is_null())
                }
            }
            DYNAMIC_CMD_LIST_ADD => {
                if !(0..=2).contains(&i) {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&ENG_DYN_330) };
                    return 0;
                }
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).list_add_value = i as c_int };
                1
            }
            DYNAMIC_CMD_LOAD => {
                // SAFETY: `e` and `ctx` are live.
                unsafe { dynamic_load(e, ctx) }
            }
            DYNAMIC_CMD_DIR_LOAD => {
                if !(0..=2).contains(&i) {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&ENG_DYN_339) };
                    return 0;
                }
                // SAFETY: `ctx` is live.
                unsafe { (*ctx).dir_load = i as c_int };
                1
            }
            DYNAMIC_CMD_DIR_ADD => {
                // SAFETY: `p` is NULL or a NUL-terminated string per the call contract;
                // `strlen` is only reached when it is non-NULL.
                if p.is_null() || unsafe { strlen(p.cast::<c_char>()) } < 1 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&ENG_DYN_347) };
                    return 0;
                }
                // SAFETY: `p` is NUL-terminated per the branch above.
                let tmp_str = unsafe { CRYPTO_strdup(p.cast::<c_char>(), FILE, LINE_STRDUP_DIR) };
                if tmp_str.is_null() {
                    return 0;
                }
                // SAFETY: `ctx` is live, so `dirs` is the stack `dynamic_set_data_ctx` built.
                if unsafe { OPENSSL_sk_push((*ctx).dirs, tmp_str.cast::<c_void>()) } == 0 {
                    // SAFETY: `tmp_str` is this branch's allocation and was not stored.
                    unsafe { CRYPTO_free(tmp_str.cast::<c_void>(), FILE, LINE_STRDUP_DIR) };
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&ENG_DYN_356) };
                    return 0;
                }
                1
            }
            _ => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&ENG_DYN_364) };
                0
            }
        }
    })
}

/// `static int int_load(dynamic_data_ctx *ctx)` — `crypto/engine/eng_dyn.c:368-390`.
///
/// # Safety
/// `ctx` must be a live context whose `dynamic_dso` is live.
unsafe fn int_load(ctx: *mut DynamicDataCtx) -> c_int {
    // SAFETY: `ctx` is live.
    let (dir_load, dso, libname, dirs) = unsafe {
        (
            (*ctx).dir_load,
            (*ctx).dynamic_dso,
            (*ctx).DYNAMIC_LIBNAME,
            (*ctx).dirs,
        )
    };
    // Unless told not to, try a direct load.
    if dir_load != 2 {
        // SAFETY: the DSO and the name are the caller's live objects; `meth`/`flags` are the
        // authority's NULL/0.
        let loaded = unsafe { DSO_load(dso, libname, ptr::null_mut(), 0) };
        if !loaded.is_null() {
            return 1;
        }
    }
    // If we're not allowed to use `dirs`, or have none, fail.
    // SAFETY: `dirs` is the context's live stack.
    let num = unsafe { OPENSSL_sk_num(dirs) };
    if dir_load == 0 || num < 1 {
        return 0;
    }
    for loop_ in 0..num {
        // SAFETY: `dirs` is live and `loop_` is in range.
        let s = unsafe { OPENSSL_sk_value(dirs, loop_) }.cast::<c_char>();
        // SAFETY: both specs are NULL or NUL-terminated; the answer is a fresh allocation.
        let merge = unsafe { DSO_merge(dso, libname, s) };
        if merge.is_null() {
            return 0;
        }
        // SAFETY: `merge` is a fresh NUL-terminated string.
        let loaded = unsafe { DSO_load(dso, merge, ptr::null_mut(), 0) };
        if !loaded.is_null() {
            // SAFETY: `merge` is this iteration's allocation.
            unsafe { CRYPTO_free(merge.cast::<c_void>(), FILE, LINE_FREE_MERGE_FOUND) };
            return 1;
        }
        // SAFETY: `merge` is this iteration's allocation.
        unsafe { CRYPTO_free(merge.cast::<c_void>(), FILE, LINE_FREE_MERGE_MISS) };
    }
    0
}

/// `static int using_libcrypto_11(dynamic_data_ctx *ctx)` — `:401-410`.
///
/// `EVP_PKEY_base_id` is a function in OpenSSL 1.1.x and a macro (`EVP_PKEY_get_base_id`)
/// in 3.x, so its presence as a symbol marks a 1.1.x engine.
///
/// # Safety
/// `ctx` must be a live context whose `dynamic_dso` is live.
unsafe fn using_libcrypto_11(ctx: *mut DynamicDataCtx) -> c_int {
    ERR_set_mark();
    // SAFETY: `ctx` is live, so the DSO is live.
    let ret = unsafe { DSO_bind_func((*ctx).dynamic_dso, c"EVP_PKEY_base_id".as_ptr()) }.is_some();
    ERR_pop_to_mark();
    c_int::from(ret)
}

/// `static int dynamic_load(ENGINE *e, dynamic_data_ctx *ctx)` — `:412-522`.
///
/// # Safety
/// `e` and `ctx` must be live; the context must be uninitialised (the caller checks).
unsafe fn dynamic_load(e: *mut Engine, ctx: *mut DynamicDataCtx) -> c_int {
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).dynamic_dso.is_null() } {
        // SAFETY: `DSO_new` takes no arguments and raises its own errors.
        let dso = unsafe { DSO_new() };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).dynamic_dso = dso };
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).dynamic_dso.is_null() } {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).DYNAMIC_LIBNAME.is_null() } {
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).engine_id.is_null() } {
            return 0;
        }
        // SAFETY: the DSO is live; the command and flag are constants.
        unsafe {
            DSO_ctrl(
                (*ctx).dynamic_dso,
                DSO_CTRL_SET_FLAGS,
                c_long::from(DSO_FLAG_NAME_TRANSLATION_EXT_ONLY),
                ptr::null_mut(),
            );
            (*ctx).DYNAMIC_LIBNAME = DSO_convert_filename((*ctx).dynamic_dso, (*ctx).engine_id);
        }
    }
    // SAFETY: `ctx` is live.
    if unsafe { int_load(ctx) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&ENG_DYN_429) };
        // SAFETY: `ctx` is live and holds the only reference to the DSO.
        unsafe {
            DSO_free((*ctx).dynamic_dso);
            (*ctx).dynamic_dso = ptr::null_mut();
        }
        return 0;
    }
    // We have to find a bind function, otherwise it will always end badly.
    // SAFETY: `ctx` is live, so the DSO is loaded and `DYNAMIC_F2` is set.
    let sym = unsafe { DSO_bind_func((*ctx).dynamic_dso, (*ctx).DYNAMIC_F2) };
    match sym {
        // SAFETY: the symbol is `bind_engine`, whose signature `DynamicBindEngine` matches;
        // `DSO_bind_func` can only answer a `void (*)(void)`.
        Some(f) => unsafe {
            (*ctx).bind_engine = Some(core::mem::transmute::<
                unsafe extern "C" fn(),
                DynamicBindEngine,
            >(f));
        },
        None => {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).bind_engine = None };
            // SAFETY: `ctx` is live and holds the only reference to the DSO.
            unsafe {
                DSO_free((*ctx).dynamic_dso);
                (*ctx).dynamic_dso = ptr::null_mut();
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ENG_DYN_440) };
            return 0;
        }
    }
    // Do we perform version checking?
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).no_vcheck } == 0 {
        let mut vcheck_res: c_ulong = 0;
        // SAFETY: `ctx` is live and the DSO is loaded.
        let vcheck = unsafe { DSO_bind_func((*ctx).dynamic_dso, (*ctx).DYNAMIC_F1) };
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).v_check = vcheck.map(|f| {
                // The symbol is `v_check`, whose signature matches; `DSO_bind_func` can
                // only answer a `void (*)(void)`.
                core::mem::transmute::<unsafe extern "C" fn(), DynamicVCheckFn>(f)
            });
        }
        // SAFETY: `ctx` is live.
        if let Some(vc) = unsafe { (*ctx).v_check } {
            // SAFETY: `vc` is the loaded library's `v_check` and the argument is the
            // authority's `OSSL_DYNAMIC_VERSION`.
            vcheck_res = unsafe { vc(OSSL_DYNAMIC_VERSION) };
        }
        // SAFETY: `ctx` is live.
        if vcheck_res < OSSL_DYNAMIC_OLDEST || unsafe { using_libcrypto_11(ctx) } != 0 {
            // SAFETY: `ctx` is live and holds the only reference to the DSO.
            unsafe {
                (*ctx).bind_engine = None;
                (*ctx).v_check = None;
                DSO_free((*ctx).dynamic_dso);
                (*ctx).dynamic_dso = ptr::null_mut();
            }
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&ENG_DYN_465) };
            return 0;
        }
    }
    // First binary copy the ENGINE structure so that we can roll back if the hand-over
    // fails: `memcpy(&cpy, e, sizeof(ENGINE))` (`:473`).
    // SAFETY: an all-zero `Engine` is a valid one, and every byte is overwritten below.
    let mut cpy: Engine = unsafe { core::mem::zeroed() };
    // SAFETY: `e` is live and `cpy` is a distinct, equally sized object.
    unsafe {
        ptr::copy_nonoverlapping(
            e.cast::<u8>(),
            ptr::addr_of_mut!(cpy).cast::<u8>(),
            size_of::<Engine>(),
        );
    }
    // Provide the ERR, ex_data, memory and locking callbacks so the loaded library uses our
    // state rather than its own.
    let mut fns = DynamicFns {
        static_state: ENGINE_get_static_state(),
        mem_fns: DynamicMemFns {
            malloc_fn: None,
            realloc_fn: None,
            free_fn: None,
        },
    };
    // SAFETY: each output slot is writable and matches the allocator type it reports.
    unsafe {
        CRYPTO_get_mem_functions(
            &mut fns.mem_fns.malloc_fn,
            &mut fns.mem_fns.realloc_fn,
            &mut fns.mem_fns.free_fn,
        );
    }
    // Now that we have loaded the dynamic engine, make sure no `dynamic` ENGINE elements
    // will show through.
    // SAFETY: `e` is live.
    unsafe { engine_set_all_null(e) };

    // Try to bind the ENGINE onto our own ENGINE structure. The authority is
    // `!engine_add_dynamic_id(...) || !ctx->bind_engine(e, ...)`, so the bind call is
    // short-circuited away when the add fails.
    // SAFETY: `ctx` is live with `bind_engine` set (or the earlier arm returned).
    let dyn_id = unsafe { (*ctx).bind_engine }.map(|f| {
        // SAFETY: the `ENGINE_DYNAMIC_ID` cast the authority makes: `void (*)(void)`.
        unsafe { core::mem::transmute::<DynamicBindEngine, unsafe extern "C" fn()>(f) }
    });
    // SAFETY: `e` is live and `dyn_id` is the loaded library's hook.
    let add_ok = unsafe { engine_add_dynamic_id(e, dyn_id, 1) } != 0;
    let mut bind_ok = false;
    if add_ok {
        // SAFETY: both `ctx` and `e` are live; `bind_engine` is the loaded library's.
        if let Some(bind) = unsafe { (*ctx).bind_engine } {
            // SAFETY: the callback is the loaded library's and takes the ENGINE, the id and
            // the `dynamic_fns` this call built.
            bind_ok = unsafe { bind(e, (*ctx).engine_id, &fns as *const DynamicFns) } != 0;
        }
    }
    if !add_ok || !bind_ok {
        // SAFETY: `e` is live and carries the dynamic id it may have taken.
        unsafe { engine_remove_dynamic_id(e, 1) };
        // SAFETY: `ctx` is live and holds the only reference to the DSO.
        unsafe {
            (*ctx).bind_engine = None;
            (*ctx).v_check = None;
            DSO_free((*ctx).dynamic_dso);
            (*ctx).dynamic_dso = ptr::null_mut();
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&ENG_DYN_498) };
        // Copy the original ENGINE structure back.
        // SAFETY: `cpy` is the pre-binding snapshot and `e` is live and equally sized.
        unsafe {
            ptr::copy_nonoverlapping(
                ptr::addr_of!(cpy).cast::<u8>(),
                e.cast::<u8>(),
                size_of::<Engine>(),
            );
        }
        return 0;
    }
    // Do we try to add this ENGINE to the internal list too?
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).list_add_value } > 0 {
        // SAFETY: `e` is a live, fully bound engine.
        if unsafe { ENGINE_add(e) } == 0 {
            // SAFETY: `ctx` is live.
            if unsafe { (*ctx).list_add_value } > 1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&ENG_DYN_514) };
                return 0;
            }
            ERR_clear_error();
        }
    }
    1
}

const _: () = {
    // The `dynamic` engine's setters are the authority's; their pointer width is the
    // platform's. This also pins that `EngineCtrlFuncPtr` and `EngineGenIntFuncPtr` are the
    // signatures the cast above relies on (a compile-time check, no runtime cost).
    assert!(
        core::mem::size_of::<Option<EngineCtrlFuncPtr>>() == core::mem::size_of::<*const c_void>()
    );
    assert!(
        core::mem::size_of::<Option<EngineGenIntFuncPtr>>()
            == core::mem::size_of::<*const c_void>()
    );
};
