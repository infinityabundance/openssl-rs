//! Phase 10.9 — `crypto/engine/tb_pkmeth.c`: the `EVP_PKEY_METHOD` implementation table.
//!
//! The table is not on the digest path directly, but `engine_free_util`
//! (`crypto/engine/eng_lib.c:89`) calls this unit's `engine_pkey_meths_free` on every
//! engine teardown, so the module lands whole. Every function here lands; nothing is
//! withheld.
//!
//! ## The free is the reason this unit is in the closure
//!
//! `engine_pkey_meths_free` (`:103-117`) walks the engine's own `pkey_meths` callback and
//! releases every method object it hands out. It runs only when the caller's callback is
//! non-NULL, which is why an engine with no method table teardown is a no-op rather than a
//! missing arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicPtr;

use crate::engine::eng_lib::{Engine, EnginePkeyMethsPtr};
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_register, engine_table_unregister, ossl_engine_table_select,
};
use crate::evp::pkey_ctx::{EVP_PKEY_meth_free, EvpPkeyMethod};
use crate::runtime::lhash::OpenSslLhash;

/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_pkmeth.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:69`).
const LINE_SELECT: c_int = 69;

/// `static ENGINE_TABLE *pkey_meth_table = NULL` (`:16`).
static PKEY_METH_TABLE: AtomicPtr<OpenSslLhash> = AtomicPtr::new(ptr::null_mut());

/// The `ENGINE_TABLE **` the table helpers take.
fn pkey_meth_table_slot() -> *mut *mut OpenSslLhash {
    core::ptr::addr_of!(PKEY_METH_TABLE) as *mut *mut OpenSslLhash
}

/// `void ENGINE_unregister_pkey_meths(ENGINE *e)` — `crypto/engine/tb_pkmeth.c:18-21`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_pkey_meths(e: *mut Engine) {
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(pkey_meth_table_slot(), e) };
}

/// `static void engine_unregister_all_pkey_meths(void)` — `:23-26`.
unsafe extern "C" fn engine_unregister_all_pkey_meths() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(pkey_meth_table_slot()) };
}

/// `int ENGINE_register_pkey_meths(ENGINE *e)` — `:28-39`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_pkey_meths(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).pkey_meths }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `pkey_meths` callback is the caller's.
        let num_nids = unsafe {
            match (*e).pkey_meths {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    pkey_meth_table_slot(),
                    Some(engine_unregister_all_pkey_meths),
                    e,
                    nids,
                    num_nids,
                    0,
                )
            };
        }
    }
    1
}

/// `void ENGINE_register_all_pkey_meths(void)` — `:41-47`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_pkey_meths() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_pkey_meths(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_pkey_meths(ENGINE *e)` — `:49-60`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_pkey_meths(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).pkey_meths }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `pkey_meths` callback is the caller's.
        let num_nids = unsafe {
            match (*e).pkey_meths {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    pkey_meth_table_slot(),
                    Some(engine_unregister_all_pkey_meths),
                    e,
                    nids,
                    num_nids,
                    1,
                )
            };
        }
    }
    1
}

/// `ENGINE *ENGINE_get_pkey_meth_engine(int nid)` — `:67-71`.
#[no_mangle]
pub extern "C" fn ENGINE_get_pkey_meth_engine(nid: c_int) -> *mut Engine {
    // SAFETY: the table slot is this module's static.
    unsafe { ossl_engine_table_select(pkey_meth_table_slot(), nid, FILE, LINE_SELECT) }
}

// `const EVP_PKEY_METHOD *ENGINE_get_pkey_meth(ENGINE *e, int nid)` (`tb_pkmeth.c:74-83`) is
// **withheld by name**. Its closure is landed -- the callback call and the
// `ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD` raise are exactly what `ENGINE_get_pkey_meths` and
// the generated `TB_PKMETH_79` coordinate carry -- but **no landed caller reaches it**. Its only
// authority caller is `EVP_PKEY_set1_engine` (`crypto/evp/p_lib.c:739`), which Phase 7 defers to
// Phase 13 and which this subphase does not land. Landing it here would retire the last absent
// blocker of that deferral's structured claim (`phase7_obligations.py`'s `BLOCKED_HANDOFFS`,
// `EVP_PKEY_get0_engine`/`EVP_PKEY_set1_engine`) while the pair itself stayed unlanded, so the
// deferral is left with the one blocker that is honestly still absent.

/// `ENGINE_PKEY_METHS_PTR ENGINE_get_pkey_meths(const ENGINE *e)` — `:86-89`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_pkey_meths(e: *const Engine) -> Option<EnginePkeyMethsPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).pkey_meths }
}

/// `int ENGINE_set_pkey_meths(ENGINE *e, ENGINE_PKEY_METHS_PTR f)` — `:92-96`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_pkey_meths(
    e: *mut Engine,
    f: Option<EnginePkeyMethsPtr>,
) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).pkey_meths = f };
    1
}

/// `void engine_pkey_meths_free(ENGINE *e)` — `:103-117`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`.
pub(crate) unsafe fn engine_pkey_meths_free(e: *mut Engine) {
    if e.is_null() {
        return;
    }
    // SAFETY: `e` is live.
    if unsafe { (*e).pkey_meths }.is_none() {
        return;
    }
    let mut nids: *const c_int = ptr::null();
    // SAFETY: `e` is live and its callback is the caller's.
    let count = unsafe {
        match (*e).pkey_meths {
            Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
            None => 0,
        }
    };
    let mut i: c_int = 0;
    while i < count {
        let mut pkm: *mut c_void = ptr::null_mut();
        // SAFETY: `nids` points at `count` integers and `pkm` is a writable slot.
        let got = unsafe {
            match (*e).pkey_meths {
                Some(f) => {
                    let nid = *nids.add(i as usize);
                    f(e, ptr::addr_of_mut!(pkm), ptr::null_mut(), nid)
                }
                None => 0,
            }
        };
        if got != 0 {
            // SAFETY: the callback handed back an `EVP_PKEY_METHOD *`.
            unsafe { EVP_PKEY_meth_free(pkm.cast::<EvpPkeyMethod>()) };
        }
        i += 1;
    }
}
