//! Phase 10.9 — `crypto/engine/tb_asnmth.c`: the `EVP_PKEY_ASN1_METHOD` table.
//!
//! Like `tb_pkmeth.c`, this unit is in the closure because `engine_free_util`
//! (`crypto/engine/eng_lib.c:90`) calls `engine_pkey_asn1_meths_free` on teardown. It is
//! transcribed whole: the table half, the two fetch-by-name functions, and the free.
//! Nothing is withheld.
//!
//! ## The string search reads the method's own `pem_str`
//!
//! `ENGINE_get_pkey_asn1_meth_str` and `ENGINE_pkey_asn1_find_str` (`:139-221`) compare the
//! caller's name against `ameth->pem_str` with `OPENSSL_strncasecmp`, so they need the
//! crate's `EVP_PKEY_ASN1_METHOD` layout. That object is Phase 8.8's
//! (`src/evp/pkey_asn1.rs`) and its `pem_str` field is the authority's, so the search is a
//! field read here rather than a second transcription of the structure.
//!
//! `ENGINE_pkey_asn1_find_str` walks the table with `engine_table_doall` under a **read**
//! lock (`:204`), which is why the engine lock is an `RwLock` and not a mutex: the walk
//! does not mutate the table and must not block a concurrent select.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::engine::eng_lib::{up_ref, Engine, EnginePkeyAsn1MethsPtr};
use crate::engine::eng_list::{ENGINE_get_first, ENGINE_get_next};
use crate::engine::eng_table::{
    engine_table_cleanup, engine_table_doall, engine_table_register, engine_table_unregister,
    ossl_engine_table_select, EngineTableSlot,
};
use crate::evp::pkey_asn1::{EVP_PKEY_asn1_free, EvpPkeyAsn1Method};
use crate::runtime::err::err_sites::{TB_ASNMTH_200, TB_ASNMTH_213, TB_ASNMTH_92};
use crate::runtime::err::raise_site;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::runtime::str::OPENSSL_strncasecmp;
use crate::runtime::thread::{CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock};

extern "C" {
    /// `size_t strlen(const char *s)`.
    fn strlen(s: *const c_char) -> usize;
}

/// `OPENSSL_FILE` for this unit, for the `ossl_engine_table_select` coordinate.
const FILE: *const c_char = c"crypto/engine/tb_asnmth.c".as_ptr();
/// `OPENSSL_LINE` of the `ossl_engine_table_select` call (`:80`).
const LINE_SELECT: c_int = 80;

/// `static ENGINE_TABLE *pkey_asn1_meth_table = NULL` (`:26`).
static PKEY_ASN1_METH_TABLE: EngineTableSlot = EngineTableSlot::new();

/// The typed `ENGINE_TABLE *` slot the table helpers take.
pub(crate) fn pkey_asn1_meth_table_slot() -> &'static EngineTableSlot {
    &PKEY_ASN1_METH_TABLE
}

/// `void ENGINE_unregister_pkey_asn1_meths(ENGINE *e)` — `crypto/engine/tb_asnmth.c:28-31`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`]. NULL is a no-op: it cannot name a
/// registered engine, and `engine_table_unregister`'s callback dereferences a NULL cached
/// default if it is handed one.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_unregister_pkey_asn1_meths(e: *mut Engine) {
    if e.is_null() {
        return;
    }
    // SAFETY: the table slot is this module's static; `e` is the caller's engine.
    unsafe { engine_table_unregister(pkey_asn1_meth_table_slot(), e) };
}

/// `static void engine_unregister_all_pkey_asn1_meths(void)` — `:33-36`.
///
/// # Safety
/// Invoked as a cleanup-stack callback after an engine was registered through the public
/// engine API. That path (`ENGINE_new` / `ENGINE_by_id` / `ENGINE_get_first`) has already
/// initialised the engine lock, and the lock is not held when the callback runs;
/// [`engine_table_cleanup`] takes it. If the lock were uninitialised, the cleanup would
/// return before releasing the table (a documented no-op/leak, not UB).
unsafe extern "C" fn engine_unregister_all_pkey_asn1_meths() {
    // SAFETY: the table slot is this module's static.
    unsafe { engine_table_cleanup(pkey_asn1_meth_table_slot()) };
}

/// `int ENGINE_register_pkey_asn1_meths(ENGINE *e)` — `:38-49`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`]; its `pkey_asn1_meths` callback, if
/// set, must obey the authority's contract (it fills `nids` and answers the count).
#[no_mangle]
pub unsafe extern "C" fn ENGINE_register_pkey_asn1_meths(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).pkey_asn1_meths }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its `pkey_asn1_meths` callback is the caller's.
        let num_nids = unsafe {
            match (*e).pkey_asn1_meths {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    pkey_asn1_meth_table_slot(),
                    Some(engine_unregister_all_pkey_asn1_meths),
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

/// `void ENGINE_register_all_pkey_asn1_meths(void)` — `:51-57`.
#[no_mangle]
pub extern "C" fn ENGINE_register_all_pkey_asn1_meths() {
    let mut e = ENGINE_get_first();
    while !e.is_null() {
        // SAFETY: `e` is a live engine returned by the iteration.
        unsafe { ENGINE_register_pkey_asn1_meths(e) };
        // SAFETY: `ENGINE_get_next` releases `e` and references its successor.
        e = unsafe { ENGINE_get_next(e) };
    }
}

/// `int ENGINE_set_default_pkey_asn1_meths(ENGINE *e)` — `:59-70`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`]; its `pkey_asn1_meths` callback, if
/// set, must obey the authority's contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_default_pkey_asn1_meths(e: *mut Engine) -> c_int {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).pkey_asn1_meths }.is_some() {
        let mut nids: *const c_int = ptr::null();
        // SAFETY: `e` is live and its callback is the caller's.
        let num_nids = unsafe {
            match (*e).pkey_asn1_meths {
                Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
                None => 0,
            }
        };
        if num_nids > 0 {
            // SAFETY: the table slot is this module's; `nids` points at `num_nids` ints.
            return unsafe {
                engine_table_register(
                    pkey_asn1_meth_table_slot(),
                    Some(engine_unregister_all_pkey_asn1_meths),
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

/// `ENGINE *ENGINE_get_pkey_asn1_meth_engine(int nid)` — `:77-81`.
#[no_mangle]
pub extern "C" fn ENGINE_get_pkey_asn1_meth_engine(nid: c_int) -> *mut Engine {
    // SAFETY: the table slot is this module's static.
    unsafe { ossl_engine_table_select(pkey_asn1_meth_table_slot(), nid, FILE, LINE_SELECT) }
}

/// `const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth(ENGINE *e, int nid)` — `:87-96`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`]; `nid` is any NID the engine may
/// implement. The callback it selects is application-controlled.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meth(
    e: *mut Engine,
    nid: c_int,
) -> *const EvpPkeyAsn1Method {
    let mut ret: *mut c_void = ptr::null_mut();
    // SAFETY: `e` is the caller's engine.
    let f = unsafe { ENGINE_get_pkey_asn1_meths(e) };
    let ok = match f {
        // SAFETY: `f` is the caller's callback; `ret` is a writable slot.
        Some(f) => unsafe { f(e, ptr::addr_of_mut!(ret), ptr::null_mut(), nid) },
        None => 0,
    };
    if ok == 0 {
        // SAFETY: `TB_ASNMTH_92` is a generated constant whose strings are static.
        unsafe { raise_site(&TB_ASNMTH_92) };
        return ptr::null();
    }
    ret.cast::<EvpPkeyAsn1Method>()
}

/// `ENGINE_PKEY_ASN1_METHS_PTR ENGINE_get_pkey_asn1_meths(const ENGINE *e)` — `:99-102`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meths(
    e: *const Engine,
) -> Option<EnginePkeyAsn1MethsPtr> {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).pkey_asn1_meths }
}

/// `int ENGINE_set_pkey_asn1_meths(ENGINE *e, ENGINE_PKEY_ASN1_METHS_PTR f)` — `:105-109`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_set_pkey_asn1_meths(
    e: *mut Engine,
    f: Option<EnginePkeyAsn1MethsPtr>,
) -> c_int {
    // SAFETY: `e` is the caller's engine.
    unsafe { (*e).pkey_asn1_meths = f };
    1
}

/// `void engine_pkey_asn1_meths_free(ENGINE *e)` — `:116-130`.
///
/// # Safety
/// `e` must be NULL or a live `ENGINE`.
pub(crate) unsafe fn engine_pkey_asn1_meths_free(e: *mut Engine) {
    if e.is_null() {
        return;
    }
    // SAFETY: `e` is live.
    if unsafe { (*e).pkey_asn1_meths }.is_none() {
        return;
    }
    let mut nids: *const c_int = ptr::null();
    // SAFETY: `e` is live and its callback is the caller's.
    let count = unsafe {
        match (*e).pkey_asn1_meths {
            Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
            None => 0,
        }
    };
    let mut i: c_int = 0;
    while i < count {
        let mut pkm: *mut c_void = ptr::null_mut();
        // SAFETY: `nids` points at `count` integers and `pkm` is a writable slot.
        let got = unsafe {
            match (*e).pkey_asn1_meths {
                Some(f) => {
                    let nid = *nids.add(i as usize);
                    f(e, ptr::addr_of_mut!(pkm), ptr::null_mut(), nid)
                }
                None => 0,
            }
        };
        if got != 0 {
            // SAFETY: the callback handed back an `EVP_PKEY_ASN1_METHOD *`.
            unsafe { EVP_PKEY_asn1_free(pkm.cast::<EvpPkeyAsn1Method>()) };
        }
        i += 1;
    }
}

/// `const EVP_PKEY_ASN1_METHOD *ENGINE_get_pkey_asn1_meth_str(ENGINE *e, const char *str,
///     int len)` — `:139-159`.
///
/// # Safety
/// `e` must be non-NULL and point to a live [`Engine`]. When `len == -1`, `str_` must be
/// NUL-terminated; otherwise it must be readable for `len` bytes (`len == 0` reads nothing).
#[no_mangle]
pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meth_str(
    e: *mut Engine,
    str_: *const c_char,
    mut len: c_int,
) -> *const EvpPkeyAsn1Method {
    // SAFETY: `e` is the caller's engine.
    if unsafe { (*e).pkey_asn1_meths }.is_none() {
        return ptr::null();
    }
    if len == -1 {
        // SAFETY: `str_` is the caller's NUL-terminated name.
        len = unsafe { strlen(str_) } as c_int;
    }
    let mut nids: *const c_int = ptr::null();
    // SAFETY: `e` is live and its callback is the caller's.
    let nidcount = unsafe {
        match (*e).pkey_asn1_meths {
            Some(f) => f(e, ptr::null_mut(), ptr::addr_of_mut!(nids), 0),
            None => 0,
        }
    };
    let mut i: c_int = 0;
    while i < nidcount {
        let mut ameth: *mut EvpPkeyAsn1Method = ptr::null_mut();
        // SAFETY: `nids` points at `nidcount` integers and `ameth` is a writable slot.
        unsafe {
            if let Some(f) = (*e).pkey_asn1_meths {
                let nid = *nids.add(i as usize);
                f(
                    e,
                    ptr::addr_of_mut!(ameth).cast::<*mut c_void>(),
                    ptr::null_mut(),
                    nid,
                );
            }
        }
        if !ameth.is_null() {
            // SAFETY: `ameth` is the method the callback returned.
            let pem = unsafe { (*ameth).pem_str };
            // SAFETY: `pem` is the method's NUL-terminated name.
            if unsafe { strlen(pem) } as c_int == len
                // SAFETY: both names are valid for `len` bytes.
                && unsafe { OPENSSL_strncasecmp(pem, str_, len as usize) } == 0
            {
                return ameth;
            }
        }
        i += 1;
    }
    ptr::null()
}

/// `struct { ENGINE *e; const EVP_PKEY_ASN1_METHOD *ameth; const char *str; int len; }` —
/// `:161-166`.
#[repr(C)]
struct EngineFindStr {
    e: *mut Engine,
    ameth: *const EvpPkeyAsn1Method,
    str_: *const c_char,
    len: c_int,
}

/// `static void look_str_cb(int nid, STACK_OF(ENGINE) *sk, ENGINE *def, void *arg)` —
/// `:168-186`.
///
/// # Safety
///
/// `nid` is a value. `sk` must be the live `STACK_OF(ENGINE)` of the pile
/// `engine_table_doall` is walking, under the engine lock, and every element must be
/// a NULL-or-live `ENGINE` inserted by this table's registration path. `_def` is
/// unread. `arg` must be the `*mut EngineFindStr` passed to `engine_table_doall`,
/// live and exclusively borrowed for the duration of the walk; this callback writes
/// only `(*lk).e` and `(*lk).ameth` and retains neither past the call. Each engine's
/// `pkey_asn1_meths` slot is NULL or a callback governed by the ENGINE ABI.
unsafe extern "C" fn look_str_cb(
    nid: c_int,
    sk: *mut OpenSslStack,
    _def: *mut Engine,
    arg: *mut c_void,
) {
    let lk = arg.cast::<EngineFindStr>();
    // SAFETY: `lk` is the `EngineFindStr` the walk was given.
    if !unsafe { (*lk).ameth }.is_null() {
        return;
    }
    // SAFETY: `sk` is the pile's `STACK_OF(ENGINE)`.
    let n = unsafe { OPENSSL_sk_num(sk) };
    let mut i: c_int = 0;
    while i < n {
        // SAFETY: `i` is in range.
        let e = unsafe { OPENSSL_sk_value(sk, i) }.cast::<Engine>();
        let mut ameth: *mut EvpPkeyAsn1Method = ptr::null_mut();
        // SAFETY: `e` is a live engine with its `pkey_asn1_meths` callback.
        unsafe {
            if let Some(f) = (*e).pkey_asn1_meths {
                f(
                    e,
                    ptr::addr_of_mut!(ameth).cast::<*mut c_void>(),
                    ptr::null_mut(),
                    nid,
                );
            }
        }
        if !ameth.is_null() {
            // SAFETY: `ameth` is the method the callback returned.
            let pem = unsafe { (*ameth).pem_str };
            // SAFETY: the pointer is live per the caller's contract.
            let len = unsafe { (*lk).len };
            // SAFETY: `pem` is the method's NUL-terminated name and `lk.str_` the query.
            if unsafe { strlen(pem) } as c_int == len
                // SAFETY: the pointer is live per the caller's contract.
                && unsafe { OPENSSL_strncasecmp(pem, (*lk).str_, len as usize) } == 0
            {
                // SAFETY: `lk` is the caller's struct.
                unsafe {
                    (*lk).e = e;
                    (*lk).ameth = ameth;
                }
                return;
            }
        }
        i += 1;
    }
}

/// `const EVP_PKEY_ASN1_METHOD *ENGINE_pkey_asn1_find_str(ENGINE **pe, const char *str,
///     int len)` — `:188-221`.
///
/// # Safety
/// `pe` must be a writable output slot; `str_` must be readable for `len` bytes. Unlike
/// `ENGINE_get_pkey_asn1_meth_str`, `len == -1` is not a length query: the walk compares
/// `strlen(pem_str)` with `len` exactly. On a refused structural reference the authority
/// leaves `*pe` untouched and answers NULL; this function does the same.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_pkey_asn1_find_str(
    pe: *mut *mut Engine,
    str_: *const c_char,
    len: c_int,
) -> *const EvpPkeyAsn1Method {
    let mut fstr = EngineFindStr {
        e: ptr::null_mut(),
        ameth: ptr::null(),
        str_,
        len,
    };
    // SAFETY: the once storage and init are `eng_lib.rs`'s.
    if !unsafe { crate::engine::eng_lib::run_engine_lock_init() } {
        // SAFETY: `TB_ASNMTH_200` is a generated constant whose strings are static.
        unsafe { raise_site(&TB_ASNMTH_200) };
        return ptr::null();
    }
    // SAFETY: the lock exists after the once; the walk only reads the table.
    if unsafe { CRYPTO_THREAD_read_lock(crate::engine::eng_lib::global_engine_lock()) } == 0 {
        return ptr::null();
    }
    let table = PKEY_ASN1_METH_TABLE.load();
    // SAFETY: `table` is this module's static lhash; `fstr` outlives the walk.
    unsafe {
        engine_table_doall(
            table,
            Some(look_str_cb),
            ptr::addr_of_mut!(fstr).cast::<c_void>(),
        );
    }
    // SAFETY: `fstr.e` is NULL or an engine the walk found.
    let mut took_ref = true;
    if !fstr.e.is_null() {
        // SAFETY: `fstr.e` is a live engine found by the table walk and `struct_ref` its
        // refcount. The table stores a **borrowed** `ENGINE *`; the structural reference
        // this call acts for is the one `engine_list_add` took for the global engine list
        // (`ENGINE_add`), not a reference held by the table. `engine_list_remove` retires
        // that borrow (`engine_unregister_from_all_tables`) under the write lock before it
        // drops the reference, and this walk holds the read lock, so the entry is live here.
        // The caller receives exactly one new reference. A refused increment cannot hand
        // out a structural reference, so neither `*pe` nor the borrowed method pointer may
        // be returned: the authority unlocks, raises and answers NULL.
        if unsafe { up_ref(ptr::addr_of_mut!((*fstr.e).struct_ref)) } == 0 {
            took_ref = false;
            fstr.e = ptr::null_mut();
        }
    }
    if !took_ref {
        // SAFETY: the read lock is held.
        unsafe { CRYPTO_THREAD_unlock(crate::engine::eng_lib::global_engine_lock()) };
        // SAFETY: `TB_ASNMTH_213` is a generated constant whose strings are static.
        unsafe { raise_site(&TB_ASNMTH_213) };
        return ptr::null();
    }
    // SAFETY: `pe` is the caller's output slot.
    unsafe { *pe = fstr.e };
    // SAFETY: the read lock is held.
    unsafe { CRYPTO_THREAD_unlock(crate::engine::eng_lib::global_engine_lock()) };
    fstr.ameth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::eng_lib::{ENGINE_free, ENGINE_new};
    use crate::evp::pkey_asn1::EvpPkeyAsn1Method;
    use crate::test_support::lock_global_state;
    use core::sync::atomic::{AtomicPtr, Ordering};

    /// The single NID the fixture engine advertises.
    static NIDS: [c_int; 1] = [0x4d9];
    /// The method the fixture returns for the lookup arm (`NULL` when unset).
    static METHOD: AtomicPtr<EvpPkeyAsn1Method> = AtomicPtr::new(ptr::null_mut());

    /// The fixture implementation of `ENGINE_PKEY_ASN1_METHS_PTR`: the count arm fills `nids`,
    /// the method arm hands back [`METHOD`].
    unsafe extern "C" fn one_method(
        _e: *mut Engine,
        method: *mut *mut c_void,
        nids: *mut *const c_int,
        _nid: c_int,
    ) -> c_int {
        if !nids.is_null() {
            // SAFETY: `nids` is the callback's writable out-slot.
            unsafe { *nids = NIDS.as_ptr() };
            return NIDS.len() as c_int;
        }
        if !method.is_null() {
            // SAFETY: `method` is the callback's writable out-slot.
            unsafe { *method = METHOD.load(Ordering::Acquire).cast() };
            return 1;
        }
        0
    }

    /// `ENGINE_unregister_pkey_asn1_meths(NULL)` is a documented NULL-tolerant call. The
    /// pre-repair path forwarded it to `engine_table_unregister`, whose pile walk compared the
    /// NULL argument with a NULL cached default and called `engine_unlocked_finish(NULL)`.
    #[test]
    fn unregister_with_null_is_refused_before_the_pile_walk() {
        let _g = lock_global_state();
        // SAFETY: the fixture engine is created and released here; the table stores a borrow it
        // is told to retire before the release.
        unsafe {
            let e = ENGINE_new();
            assert!(!e.is_null());
            (*e).pkey_asn1_meths = Some(one_method);
            assert_eq!(ENGINE_register_pkey_asn1_meths(e), 1);
            // Pre-repair this dereferenced the pile's NULL `funct`.
            ENGINE_unregister_pkey_asn1_meths(ptr::null_mut());
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_free(e);
        }
    }

    /// A refused structural reference must not hand out the borrowed method pointer: the caller
    /// would own a pointer into an engine it has no reference to. The authority unlocks, raises
    /// `ERR_R_CRYPTO_LIB` and answers NULL, leaving `*pe` untouched.
    #[test]
    fn a_refused_structural_reference_returns_no_method() {
        let _g = lock_global_state();
        // SAFETY: every object is this test's and is released before it returns; the method is
        // stack storage whose lifetime covers the synchronous lookup.
        unsafe {
            let e = ENGINE_new();
            assert!(!e.is_null());
            let mut method: EvpPkeyAsn1Method = core::mem::zeroed();
            method.pem_str = c"TEST".as_ptr() as *mut c_char;
            METHOD.store(ptr::addr_of_mut!(method), Ordering::Release);
            (*e).pkey_asn1_meths = Some(one_method);
            assert_eq!(ENGINE_register_pkey_asn1_meths(e), 1);
            let direct = ENGINE_get_pkey_asn1_meth_str(e, c"TEST".as_ptr(), -1);
            assert_eq!(
                direct,
                ptr::addr_of!(method),
                "the fixture callback must match"
            );

            // The shared checked increment refuses `i32::MAX` without changing the count.
            (*e).struct_ref.store(i32::MAX, Ordering::SeqCst);
            let sentinel = std::ptr::dangling_mut::<Engine>();
            let mut pe = sentinel;
            let ameth = ENGINE_pkey_asn1_find_str(&mut pe, c"TEST".as_ptr(), 4);
            assert!(ameth.is_null());
            assert_eq!(
                pe, sentinel,
                "the authority leaves *pe untouched on refusal"
            );

            (*e).struct_ref.store(1, Ordering::SeqCst);
            METHOD.store(ptr::null_mut(), Ordering::Release);
            ENGINE_unregister_pkey_asn1_meths(e);
            ENGINE_free(e);
            crate::runtime::err::ERR_clear_error();
        }
    }
}
