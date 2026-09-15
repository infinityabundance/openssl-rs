//! Phase 6.6b — the name map, `crypto/core_namemap.c`.
//!
//! An `OSSL_NAMEMAP` is a bijection between *names* and small integers: one
//! number may own several names (aliases), and a name belongs to exactly one
//! number. It is how OpenSSL 3 identifies an algorithm independently of the
//! legacy `NID` space: a provider registers "SHA2-256" and gets a number, and a
//! fetch by any of its aliases finds the same algorithm. The numbers are assigned
//! in **insertion order**, one-based, which is why the pre-population order in
//! [`ossl_namemap_stored`] is a compatibility fact rather than an implementation
//! detail.
//!
//! ## The comparison is case-insensitive, and by a *bit mask* rather than a fold
//!
//! `ossl_namemap_name2num` looks its key up with `HT_SET_KEY_STRING_CASE`, which
//! pipes the name through `ossl_ht_strcase`:
//!
//! ```c
//! const long int case_adjust = ~0x20;
//! for (i = 0; i < len && src[i] != '\0'; i++)
//!     tgt[i] = case_adjust & src[i];
//! ```
//!
//! That clears bit 5 of every byte. For ASCII letters it is a case fold, which is
//! the documented intent. For **every other byte** it is a transformation with a
//! quirk: `'!'` (`0x21`) and `0x01` map to the same value, so two names that
//! differ only by bit 5 in a non-letter position are the same name to this map.
//! The quirk is reproduced rather than "fixed", because the alternative would be
//! a map that answers differently from the authority for such a name.
//!
//! The key field is `char name[64]` and the macros pass `sizeof - 1`, so a name is
//! keyed by at most its first **63** bytes: two names sharing a 63-byte prefix are
//! the same name. `ossl_namemap_name2num_n` keys by an explicit length instead,
//! which makes a *prefix* lookup possible — `name2num_n(nm, "sha256", 3)` asks for
//! "sha".
//!
//! ## `NDEBUG` is defined in the admitted build, and it decides a branch
//!
//! `ossl_assert(x)` is `OPENSSL_die(...)` in a debug build and a plain
//! `(x) != 0` under `NDEBUG`. The admitted profile's `configdata.pm` lists
//! `NDEBUG`, so the two asserts in this file are **non-fatal**: a NULL namemap
//! reaches the `ERR_R_PASSED_NULL_PARAMETER` raise rather than aborting, and the
//! `numname_insert` "cannot happen" case returns 0. Both are measured against the
//! authority's own build record rather than assumed, because the opposite
//! assumption would turn a raise into a process death.
//!
//! ## What is deferred, and where it is named
//!
//! [`ossl_namemap_stored`] is **not** pre-populated here. In the authority, the
//! first call on an empty stored namemap runs
//! `OPENSSL_init_crypto(ADD_ALL_CIPHERS | ADD_ALL_DIGESTS)` and pilfers the legacy
//! `OBJ_NAME` database and the `EVP_PKEY_ASN1_METHOD` set, then adds four RSA-PSS
//! aliases. Every one of those names takes a number, so the numbering of
//! everything registered later depends on them.
//!
//! That pre-population cannot be built before the legacy method database and
//! `OBJ_NAME_do_all` exist, which is Phase 13. It is deferred **whole** — the
//! RSA-PSS block with it — rather than half-implemented. The reason is that the
//! block is guarded by `if (ossl_namemap_empty(namemap))`: running it now would
//! make the namemap non-empty, and a later phase that added the legacy
//! pre-population would then find the guard false and skip it entirely, silently
//! leaving the legacy names out of a map that had already been populated with the
//! wrong order. Deferring both together keeps the ordering decision in one place.
//!
//! Until then a name registered by a provider gets number 1, 2, 3 … where the
//! authority would continue after the legacy names. Nothing observes that yet —
//! no export in this crate reaches a namemap — and the number is observable only
//! as `EVP_MD_get_type`-style identity, which is Phase 7's. The residual is
//! recorded in `forensics/phase6-obligations.json`'s stratum notes and in
//! `docs/PHASE-6-SUBPHASES.md`.
//!
//! ## The container is not the authority's
//!
//! The authority's `name -> number` mapping is a `crypto/hashtable/hashtable.c`
//! table: open addressing over 512 neighbourhoods, FNV-1a, with a
//! `collision_check` that turns an excessive conflict rate into
//! `CRYPTO_R_TOO_MANY_NAMES`. This module uses a `HashMap` keyed on the
//! transformed bytes. The *lookup* behaviour is identical; the difference is that
//! the authority's map can fail an insertion under a collision attack and this
//! one cannot. That failure is recorded as a residual rather than reproduced by
//! reimplementing the hash table, because reproducing it would mean reproducing
//! the *hash function* as well, and nothing observable depends on which of two
//! names occupies which slot.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::collections::HashMap;

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_NAMEMAP_INDEX};
use crate::runtime::err::err_reasons;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data, raise_site_dynamic};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

/// The authority's translation unit and the coordinates of its allocations and
/// releases, so an allocation that fails records the site a consumer would see.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/core_namemap.c".as_ptr();
const LINE_ZALLOC_MAP: c_int = 521;
const LINE_FREE_MAP: c_int = 539;
const LINE_FREE_NAME: c_int = 66;

/// `HT_DEF_KEY_FIELD_CHAR_ARRAY(name, 64)` and the macros' `sizeof - 1`.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
const KEY_BYTES: usize = 63;

/// `struct ossl_namemap_st`, from `crypto/core_namemap.c`.
///
/// `stored` is a single bit in the authority and an `int` here; it is only ever
/// tested for truth, and a bitfield's width is not observable.
pub struct OsslNamemap {
    /// `unsigned int stored : 1` — 1 when the map belongs to a library context,
    /// which makes [`ossl_namemap_free`] refuse to release it.
    stored: c_int,
    lock: *mut CryptoRwlock,
    /// `STACK_OF(NAMES) *numnames` — one `OPENSSL_STACK` of `char *` per number,
    /// indexed by `number - 1`. A real stack, because the authority's accessors
    /// take one and the order of the names within a number is insertion order.
    numnames: *mut OpenSslStack,
    /// `TSAN_QUALIFIER int max_number`. Written on **every** successful addition
    /// with the number that addition used, which for an alias appended to an
    /// existing number can be *lower* than the current value. The only reader is
    /// [`ossl_namemap_empty`], which asks whether it is zero, so the oddity is not
    /// observable — but it is reproduced, and unit-tested.
    max_number: c_int,
    /// The `name -> number` table, keyed on the transformed bytes.
    namenum: HashMap<Vec<u8>, c_int>,
}

/// `static void name_string_free(char *name)` — the destructor handed to
/// `sk_OPENSSL_STRING_pop_free`.
///
/// # Safety
/// `name` must be NULL or a pointer this module obtained from [`CRYPTO_strdup`].
unsafe extern "C" fn name_string_free(name: *mut c_void) {
    if name.is_null() {
        return;
    }
    // SAFETY: `name` came from `CRYPTO_strdup` in `numname_insert` and is released
    // exactly once, here.
    unsafe { CRYPTO_free(name, FILE, LINE_FREE_NAME) };
}

/// `static void names_free(NAMES *n)` — `sk_OPENSSL_STRING_pop_free(n, name_string_free)`.
///
/// # Safety
/// `n` must be NULL or a `STACK_OF(char *)` whose elements came from
/// [`CRYPTO_strdup`] and are not owned anywhere else.
unsafe fn names_free(n: *mut OpenSslStack) {
    // SAFETY: `n` is a live stack per the caller's contract; `pop_free` releases
    // each element with the destructor and then the stack itself.
    unsafe { OPENSSL_sk_pop_free(n, Some(name_string_free)) };
}

/// The lookup key for `len` bytes of `name`, or the empty key for a NULL name.
///
/// This is `ossl_ht_strcase`'s transform over at most [`KEY_BYTES`] bytes, which
/// is what the authority's key buffer holds after `HT_SET_KEY_STRING_CASE`.
///
/// # Safety
/// `name` must be NULL or point to at least `min(len, KEY_BYTES)` readable bytes,
/// stopping at a NUL.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
unsafe fn key(name: *const c_char, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if name.is_null() {
        return out;
    }
    let limit = if len < KEY_BYTES { len } else { KEY_BYTES };
    for i in 0..limit {
        // SAFETY: `name` is readable for `limit` bytes per the caller's contract,
        // and the loop stops at the first NUL byte, which is where a C string ends.
        let b = unsafe { *name.add(i) as u8 };
        if b == 0 {
            break;
        }
        out.push(b & !0x20);
    }
    out
}

/// `OSSL_NAMEMAP *ossl_namemap_stored(OSSL_LIB_CTX *libctx)`
///
/// The namemap owned by a library context, or NULL when the context has none.
/// The authority pre-populates an empty stored map on first use; that is deferred
/// — see the module documentation for why it is deferred *whole*.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn ossl_namemap_stored(libctx: *mut c_void) -> *mut OsslNamemap {
    lib_ctx_get_data(libctx, OSSL_LIB_CTX_NAMEMAP_INDEX).cast::<OsslNamemap>()
}

/// `OSSL_NAMEMAP *ossl_namemap_new(OSSL_LIB_CTX *libctx)`
///
/// A free-standing namemap: a lock, an empty number list and an empty table.
/// Returns NULL when any of the three cannot be created, having released whatever
/// it did create.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn ossl_namemap_new(_libctx: *mut c_void) -> *mut OsslNamemap {
    let nm = CRYPTO_zalloc(core::mem::size_of::<OsslNamemap>(), FILE, LINE_ZALLOC_MAP)
        .cast::<OsslNamemap>();
    if nm.is_null() {
        return ptr::null_mut();
    }
    let lock = CRYPTO_THREAD_lock_new();
    if lock.is_null() {
        // SAFETY: `nm` came from `CRYPTO_zalloc` just above and was never
        // published.
        unsafe { CRYPTO_free(nm.cast::<c_void>(), FILE, LINE_FREE_MAP) };
        return ptr::null_mut();
    }
    let numnames = OPENSSL_sk_new_null();
    if numnames.is_null() {
        // SAFETY: both objects came from the constructors above and are released
        // exactly once.
        unsafe {
            CRYPTO_THREAD_lock_free(lock);
            CRYPTO_free(nm.cast::<c_void>(), FILE, LINE_FREE_MAP);
        }
        return ptr::null_mut();
    }
    // SAFETY: `nm` is a fresh zeroed block that no other thread can observe yet,
    // so these are its only writes before it is published. The `namenum` field is
    // *initialised* here rather than merely zeroed: `ptr::write` overwrites the
    // zeroed bytes without reading them and without dropping anything, so no
    // invalid `HashMap` value is ever formed, and `ossl_namemap_free` reads the
    // field back only after this write has happened. (`HashMap` has no
    // all-zero representation it is sound to assume, which is why this is a
    // `write` and not a cast.)
    unsafe {
        (*nm).stored = 0;
        (*nm).lock = lock;
        (*nm).numnames = numnames;
        (*nm).max_number = 0;
        ptr::write(ptr::addr_of_mut!((*nm).namenum), HashMap::new());
    }
    nm
}

/// The table, as a Rust reference. `CRYPTO_zalloc` leaves the `HashMap`'s bytes
/// zero, which is an empty map, so a freshly allocated namemap needs no
/// initialisation beyond [`ossl_namemap_new`]'s explicit `write`.
///
/// # Safety
/// `nm` must be a live namemap.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
unsafe fn map_mut<'a>(nm: *mut OsslNamemap) -> &'a mut HashMap<Vec<u8>, c_int> {
    // SAFETY: `nm` is live per the caller's contract; the field is a `HashMap`
    // initialised by `ossl_namemap_new` and owned by this namemap.
    unsafe { &mut (*nm).namenum }
}

/// `void ossl_namemap_free(OSSL_NAMEMAP *namemap)`
///
/// Does **nothing** for a namemap that belongs to a library context — the context
/// owns it and frees it through [`ossl_stored_namemap_free`], which clears the
/// flag first. Calling this on a stored map directly is a documented no-op rather
/// than a leak, and it is what the authority does.
///
/// # Safety
/// `namemap` must be NULL or a live namemap.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_free(namemap: *mut OsslNamemap) {
    if namemap.is_null() {
        return;
    }
    // SAFETY: `namemap` is live per the caller's contract.
    if unsafe { (*namemap).stored } != 0 {
        return;
    }
    // SAFETY: the three members are this object's own and each is released once.
    unsafe {
        OPENSSL_sk_pop_free((*namemap).numnames, Some(names_stack_free));
        CRYPTO_THREAD_lock_free((*namemap).lock);
        // The table's keys and values are Rust-owned; dropping it releases them.
        drop(ptr::read(ptr::addr_of!((*namemap).namenum)));
        CRYPTO_free(namemap.cast::<c_void>(), FILE, LINE_FREE_MAP);
    }
}

/// The destructor for a whole `NAMES` stack: release every name, then the stack.
///
/// # Safety
/// `n` must be NULL or a `STACK_OF(char *)` whose elements came from
/// [`CRYPTO_strdup`] and are not owned elsewhere.
unsafe extern "C" fn names_stack_free(n: *mut c_void) {
    if n.is_null() {
        return;
    }
    // SAFETY: `n` is a `NAMES` stack per the contract.
    unsafe { names_free(n.cast::<OpenSslStack>()) };
}

/// `int ossl_namemap_empty(OSSL_NAMEMAP *namemap)` — true for NULL as well.
///
/// The authority's `TSAN_REQUIRES_LOCKING` arm takes the read lock; this platform
/// is the other arm, which reads the counter directly. Both answer the same thing
/// for every state a single-threaded caller can reach.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn ossl_namemap_empty(namemap: *mut OsslNamemap) -> c_int {
    if namemap.is_null() {
        return 1;
    }
    // SAFETY: `namemap` is live, so the field is readable.
    if unsafe { (*namemap).max_number } == 0 {
        1
    } else {
        0
    }
}

/// `int ossl_namemap_doall_names(const OSSL_NAMEMAP *namemap, int number, void (*fn)(const char *, void *), void *data)`
///
/// Calls `fn` once per name of `number`, over a **duplicate** of the name list
/// taken under the read lock — so the callback runs with the lock released and
/// cannot deadlock the map by re-entering it. The duplicate is released with
/// `sk_OPENSSL_STRING_free`, which frees the array but not the names, because the
/// originals still belong to the map.
///
/// Answers the number of names for which `fn` ran, or 0 when the number has none.
///
/// # Safety
/// `namemap` must be NULL or live; `fn` must be a valid function pointer or NULL.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_doall_names(
    namemap: *mut OsslNamemap,
    number: c_int,
    callback: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    if namemap.is_null() || number <= 0 {
        return 0;
    }
    let Some(callback) = callback else {
        return 0;
    };
    // SAFETY: `namemap` is live.
    let names = unsafe { names_of(namemap, number) };
    let mut dup = ptr::null_mut();
    if !names.is_null() {
        // SAFETY: `names` is a live name list owned by the map; `dup` is a shallow
        // copy of its pointer array.
        dup = unsafe { OPENSSL_sk_dup(names) };
    }
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `dup` is a live stack of `char *`.
    let count = unsafe { OPENSSL_sk_num(dup) };
    for i in 0..count {
        // SAFETY: `i` is within `dup`'s bounds and every element is a `char *`
        // this map owns and has not released.
        let name = unsafe { OPENSSL_sk_value(dup, i) }.cast::<c_char>();
        // SAFETY: `callback` is the caller's function pointer and `name` is a
        // NUL-terminated string that outlives the call.
        unsafe { callback(name, data) };
    }
    // SAFETY: `dup` is the copy made above and is released exactly once, without
    // its elements.
    unsafe { OPENSSL_sk_free(dup) };
    count
}

/// The name list for a number, or NULL. Caller holds the lock; the authority's
/// `sk_NAMES_value(namemap->numnames, number - 1)`.
///
/// # Safety
/// `namemap` must be live and `number` positive.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
unsafe fn names_of(namemap: *mut OsslNamemap, number: c_int) -> *mut OpenSslStack {
    // SAFETY: `namemap` is live per the contract and `numnames` is its own stack.
    unsafe { OPENSSL_sk_value((*namemap).numnames, number - 1) }.cast::<OpenSslStack>()
}

/// `int ossl_namemap_name2num(const OSSL_NAMEMAP *namemap, const char *name)`
///
/// A NULL namemap resolves to the stored one, exactly as the authority's
/// `#ifndef FIPS_MODULE` arm does — so a caller that has a context can pass NULL
/// and reach that context's map.
///
/// # Safety
/// `namemap` must be NULL or live; `name` must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_name2num(
    namemap: *mut OsslNamemap,
    name: *const c_char,
) -> c_int {
    // SAFETY: the caller's contract covers `name`, and `ossl_namemap_stored`
    // accepts a NULL context.
    unsafe { name2num_inner(namemap, name, None) }
}

/// `int ossl_namemap_name2num_n(const OSSL_NAMEMAP *namemap, const char *name, size_t name_len)`
///
/// The explicit-length form, which keys on a prefix rather than the whole name.
///
/// # Safety
/// `namemap` must be NULL or live; `name` must be NULL or readable for
/// `name_len` bytes, stopping at a NUL.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_name2num_n(
    namemap: *mut OsslNamemap,
    name: *const c_char,
    name_len: usize,
) -> c_int {
    // SAFETY: as `ossl_namemap_name2num`, with the length form's contract.
    unsafe { name2num_inner(namemap, name, Some(name_len)) }
}

/// The shared body of the two lookups.
///
/// # Safety
/// As the two callers.
unsafe fn name2num_inner(
    namemap: *mut OsslNamemap,
    name: *const c_char,
    len: Option<usize>,
) -> c_int {
    let mut nm = namemap;
    if nm.is_null() {
        // SAFETY: `ossl_namemap_stored` accepts a NULL context.
        nm = ossl_namemap_stored(ptr::null_mut());
    }
    if nm.is_null() {
        return 0;
    }
    // A NULL name keys on the empty key, which no added name can have, because
    // `ossl_namemap_add_name` refuses the empty string. The authority relies on
    // the same two facts.
    let k = if name.is_null() {
        Vec::new()
    } else {
        let limit = match len {
            None => KEY_BYTES,
            Some(l) => l,
        };
        // SAFETY: `name` is readable to `limit` bytes or to its NUL, whichever
        // comes first, per the two callers' contracts.
        unsafe { key(name, limit) }
    };
    // SAFETY: `nm` is live.
    unsafe { map_mut(nm) }.get(&k).copied().unwrap_or(0)
}

/// `const char *ossl_namemap_num2name(const OSSL_NAMEMAP *namemap, int number, int idx)`
///
/// The returned pointer belongs to the map, so it is valid only while the map is
/// not modified — the authority unlocks before returning and has the same
/// constraint.
///
/// # Safety
/// `namemap` must be NULL or live.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_num2name(
    namemap: *mut OsslNamemap,
    number: c_int,
    idx: c_int,
) -> *const c_char {
    if namemap.is_null() || number <= 0 {
        return ptr::null();
    }
    // SAFETY: `namemap` is live, so its lock is live.
    if unsafe { CRYPTO_THREAD_read_lock((*namemap).lock) } == 0 {
        return ptr::null();
    }
    let mut ret = ptr::null();
    // SAFETY: the read lock is held, so the name list cannot be released under
    // this read, and `namemap` is live.
    unsafe {
        let names = names_of(namemap, number);
        if !names.is_null() {
            ret = OPENSSL_sk_value(names, idx).cast::<c_char>();
        }
        CRYPTO_THREAD_unlock((*namemap).lock);
    }
    ret
}

/// `static int numname_insert(OSSL_NAMEMAP *namemap, int number, const char *name)`
/// — not thread safe; the caller holds the write lock.
///
/// `number <= 0` means "a new entry": a fresh name list is pushed and the number
/// becomes its one-based position. `number > 0` appends an alias to an existing
/// list, and the "cannot happen" NULL list answers 0 — the authority's
/// `ossl_assert`, which is non-fatal in this build.
///
/// # Safety
/// `namemap` must be live and write-locked; `name` must be NUL-terminated.
unsafe fn numname_insert(namemap: *mut OsslNamemap, number: c_int, name: *const c_char) -> c_int {
    // SAFETY: `namemap` is live per the contract.
    let (mut names, new_entry) = unsafe {
        if number > 0 {
            ((*namemap).numnames, false)
        } else {
            (ptr::null_mut(), true)
        }
    };
    if !new_entry {
        // SAFETY: the read is of the map's own stack.
        names = unsafe { OPENSSL_sk_value(names, number - 1) }.cast::<OpenSslStack>();
        if names.is_null() {
            return 0;
        }
    } else {
        // Creates an empty stack owned by this namemap until it is pushed.
        names = OPENSSL_sk_new_null();
        if names.is_null() {
            return 0;
        }
    }

    // SAFETY: `name` is NUL-terminated per the contract.
    let tmpname = unsafe { CRYPTO_strdup(name, FILE, LINE_FREE_NAME) };
    if tmpname.is_null() {
        if new_entry {
            // SAFETY: `names` was created above and has not been published.
            unsafe { OPENSSL_sk_free(names) };
        }
        return 0;
    }
    // SAFETY: `names` is a live stack and `tmpname` is a fresh allocation owned
    // by this namemap from here on.
    if unsafe { OPENSSL_sk_push(names, tmpname.cast::<c_void>()) } == 0 {
        if new_entry {
            // SAFETY: as above.
            unsafe { OPENSSL_sk_free(names) };
        }
        // SAFETY: `tmpname` was not stored, so it is released here and nowhere
        // else.
        unsafe { CRYPTO_free(tmpname.cast::<c_void>(), FILE, LINE_FREE_NAME) };
        return 0;
    }

    if new_entry {
        // SAFETY: `namemap` is live and write-locked; `names` is now owned by it.
        if unsafe { OPENSSL_sk_push((*namemap).numnames, names.cast::<c_void>()) } == 0 {
            // SAFETY: the push failed, so `names` is still unowned and is released
            // with its one element.
            unsafe { names_free(names) };
            return 0;
        }
        // SAFETY: the push succeeded; the one-based position is the number.
        return unsafe { OPENSSL_sk_num((*namemap).numnames) };
    }
    number
}

/// `static int namemap_add_name(OSSL_NAMEMAP *namemap, int number, const char *name)`
/// — not thread safe; the caller holds the write lock.
///
/// An existing name is returned with its **original** number, whatever `number`
/// asked for: adding "SHA2-256" to number 7 when it is already number 3 answers 3
/// and changes nothing.
///
/// # Safety
/// `namemap` must be live and write-locked; `name` must be NUL-terminated.
unsafe fn namemap_add_name(namemap: *mut OsslNamemap, number: c_int, name: *const c_char) -> c_int {
    // SAFETY: `namemap` is live per the contract, so the map is readable. The
    // write lock is held, so no other thread can be inserting.
    let existing = unsafe {
        let k = key(name, KEY_BYTES);
        map_mut(namemap).get(&k).copied().unwrap_or(0)
    };
    if existing != 0 {
        return existing;
    }

    // SAFETY: `namemap` is live and write-locked.
    let number = unsafe { numname_insert(namemap, number, name) };
    if number == 0 {
        // No raise: the authority's `numname_insert` failure path has none.
        return 0;
    }
    // SAFETY: `namemap` is live. The counter is stored unconditionally, even when
    // this addition appended an alias to an existing number and therefore lowered
    // it -- see the field's documentation.
    unsafe { (*namemap).max_number = number };

    // SAFETY: `name` is NUL-terminated per the contract.
    let k = unsafe { key(name, KEY_BYTES) };
    // SAFETY: `namemap` is live and write-locked.
    unsafe { map_mut(namemap).insert(k, number) };
    number
}

/// `int ossl_namemap_add_name(OSSL_NAMEMAP *namemap, int number, const char *name)`
///
/// Refuses the NULL name and the empty name, and resolves a NULL namemap to the
/// stored one **before** those checks — so the argument order matters to a caller
/// passing both as NULL, and it is the authority's.
///
/// # Safety
/// `namemap` must be NULL or live; `name` must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_add_name(
    namemap: *mut OsslNamemap,
    number: c_int,
    name: *const c_char,
) -> c_int {
    let mut nm = namemap;
    if nm.is_null() {
        // SAFETY: `ossl_namemap_stored` accepts a NULL context.
        nm = ossl_namemap_stored(ptr::null_mut());
    }
    if name.is_null() || nm.is_null() {
        return 0;
    }
    // SAFETY: `name` is NUL-terminated per the contract, so its first byte is
    // readable.
    if unsafe { *name } == 0 {
        return 0;
    }
    // SAFETY: `nm` is live, so its lock is live.
    if unsafe { CRYPTO_THREAD_write_lock((*nm).lock) } == 0 {
        return 0;
    }
    // SAFETY: the write lock is held, which is `namemap_add_name`'s precondition.
    let tmp_number = unsafe { namemap_add_name(nm, number, name) };
    // SAFETY: the same lock is released.
    unsafe { CRYPTO_THREAD_unlock((*nm).lock) };
    tmp_number
}

/// `int ossl_namemap_add_names(OSSL_NAMEMAP *namemap, int number, const char *names, const char separator)`
///
/// Splits `names` on `separator` and adds every part to **one** number, which is
/// `number` when the caller supplied one and otherwise the first part's. Two
/// refusals, and they are different:
///
/// * an empty part — a leading, trailing or doubled separator — raises
///   `CRYPTO_R_BAD_ALGORITHM_NAME`;
/// * a part that already belongs to a *different* number raises
///   `CRYPTO_R_CONFLICTING_NAMES`, naming the part, the number it has, and the
///   whole original string.
///
/// Both refusals answer 0 and leave nothing added: the split is checked in full
/// before any name is registered.
///
/// The conflict check is **order-dependent**, and that is a behaviour rather than
/// an accident of the loop: the number being built starts as the caller's (0 for
/// "none"), and a part only *sets* it when that part resolves to an existing
/// number. So `add_names(nm, 0, "fresh:known", ':')` sees "fresh" resolve to 0 —
/// which changes nothing, because 0 is what it already held — and then "known"
/// resolve to its number, which the 0 is replaced by. No comparison against
/// "fresh" ever happens, so the call succeeds and registers "fresh" on "known"'s
/// number. The conflict is reachable only between a part that comes *after* one
/// that already resolved. A first run of this module's unit test asserted the
/// intuitive thing instead and failed, which is how the behaviour was found.
///
/// A NULL namemap raises `ERR_R_PASSED_NULL_PARAMETER` — the authority's
/// `ossl_assert`, non-fatal in this build — whereas a NULL `names` answers 0 with
/// no error, because `OPENSSL_strdup(NULL)` fails first.
///
/// # Safety
/// `namemap` must be NULL or live; `names` must be NULL or NUL-terminated.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_namemap_add_names(
    namemap: *mut OsslNamemap,
    number: c_int,
    names: *const c_char,
    separator: c_char,
) -> c_int {
    if namemap.is_null() {
        // SAFETY: a compile-time-constant site; no message.
        unsafe { raise_site(&err_sites::CORE_NAMEMAP_321) };
        return 0;
    }
    // SAFETY: `names` is NUL-terminated per the contract; `CRYPTO_strdup` accepts
    // NULL and answers NULL.
    let tmp = unsafe { CRYPTO_strdup(names, FILE, LINE_FREE_NAME) }.cast::<c_char>();
    if tmp.is_null() {
        return 0;
    }

    // SAFETY: `namemap` is live, so its lock is live.
    if unsafe { CRYPTO_THREAD_write_lock((*namemap).lock) } == 0 {
        // SAFETY: `tmp` was not stored.
        unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE, LINE_FREE_NAME) };
        return 0;
    }

    // SAFETY: the write lock is held, which is `add_names_locked`'s precondition,
    // and `tmp` is a writable NUL-terminated copy of `names`.
    let ret = unsafe { add_names_locked(namemap, number, tmp, names, separator) };

    // SAFETY: the same lock is released, and `tmp` is released exactly once.
    unsafe {
        CRYPTO_THREAD_unlock((*namemap).lock);
        CRYPTO_free(tmp.cast::<c_void>(), FILE, LINE_FREE_NAME);
    }
    ret
}

/// The two passes of [`ossl_namemap_add_names`], with the write lock held.
///
/// The first pass only *checks*; the second registers. That split is the reason a
/// conflicting name leaves the map unmodified, and it is why the authority can
/// report the conflict with the whole original string still intact — `tmp` is the
/// copy that gets NUL-split, and `names` is the caller's untouched original.
///
/// # Safety
/// `namemap` must be live and write-locked; `tmp` must be a writable
/// NUL-terminated copy of `names`.
unsafe fn add_names_locked(
    namemap: *mut OsslNamemap,
    mut number: c_int,
    tmp: *mut c_char,
    names: *const c_char,
    separator: c_char,
) -> c_int {
    // The parts, as (offset, length) into `tmp`. Building this first is what lets
    // the check pass run before anything is registered. `tmp` is split in place,
    // exactly as the authority's `*q++ = '\0'` does, so the second pass can walk
    // it with `strlen`.
    let mut parts: Vec<*mut c_char> = Vec::new();
    // SAFETY: `tmp` is a writable NUL-terminated string per the contract.
    unsafe {
        let mut p = tmp;
        while *p != 0 {
            let q = c_strchr(p, separator);
            let next = if q.is_null() {
                p.add(c_strlen(p))
            } else {
                *q = 0;
                q.add(1)
            };
            if *p == 0 {
                // SAFETY: a compile-time-constant site; no message.
                raise_site(&err_sites::CORE_NAMEMAP_349);
                return 0;
            }
            parts.push(p);
            p = next;
        }
    }

    // The check pass: every part must either be unknown or already belong to the
    // number being built.
    for part in parts.iter() {
        // SAFETY: `part` is a NUL-terminated string inside `tmp`, and the write
        // lock is held so the map cannot change under this read.
        let this_number = unsafe {
            let k = key(*part, KEY_BYTES);
            map_mut(namemap).get(&k).copied().unwrap_or(0)
        };
        if number == 0 {
            number = this_number;
        } else if this_number != 0 && this_number != number {
            // The message is the authority's, with the *part* and the *original*
            // string; it is built here rather than in a fixed buffer because both
            // strings are caller-supplied and a truncated message would be a
            // different observation.
            let mut msg: Vec<u8> = Vec::new();
            msg.extend_from_slice(b"\"");
            // SAFETY: `part` is NUL-terminated.
            msg.extend_from_slice(unsafe { c_bytes(*part) });
            msg.extend_from_slice(
                format!(" has an existing different identity {this_number} (from \"").as_bytes(),
            );
            // SAFETY: `names` is the caller's NUL-terminated original.
            msg.extend_from_slice(unsafe { c_bytes(names) });
            msg.extend_from_slice(b"\")");
            msg.push(0);
            // SAFETY: a compile-time-constant site; `msg` is NUL-terminated and
            // outlives the call.
            unsafe { raise_site_data(&err_sites::CORE_NAMEMAP_359, msg.as_ptr().cast()) };
            return 0;
        }
    }

    // The registration pass.
    for part in parts {
        // SAFETY: `namemap` is live and write-locked, and `part` is a
        // NUL-terminated string inside `tmp`.
        let this_number = unsafe { namemap_add_name(namemap, number, part) };
        if number == 0 {
            number = this_number;
        } else if this_number != number {
            let mut msg = format!("Got number {this_number} when expecting {number}").into_bytes();
            msg.push(0);
            // SAFETY: a compile-time-constant site; `msg` is NUL-terminated and
            // outlives the call.
            unsafe { raise_site_data(&err_sites::CORE_NAMEMAP_378, msg.as_ptr().cast()) };
            return 0;
        }
    }
    number
}

/// Whether `number` was refused by the *dynamic* raise at
/// `crypto/core_namemap.c:288`. The authority chooses between
/// `CRYPTO_R_TOO_MANY_NAMES` and `ERR_R_INTERNAL_ERROR` at run time from the hash
/// table's insertion result; this module's table cannot fail an insertion, so the
/// site exists and is unreferenced — which is recorded as a residual rather than
/// papered over with a raise that could not happen.
#[allow(dead_code)] // unreachable: the candidate's map cannot fail an insertion
unsafe fn raise_too_many_names() {
    // SAFETY: a compile-time-constant site with a run-time reason; the reason is
    // the one the authority picks when the table reports a conflict.
    unsafe {
        raise_site_dynamic(
            &err_sites::CORE_NAMEMAP_288,
            err_reasons::CRYPTO_R_TOO_MANY_NAMES,
        )
    };
}

/// `strchr`, without libc.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strchr(s: *const c_char, c: c_char) -> *mut c_char {
    let mut p = s.cast_mut();
    // SAFETY: `s` is NUL-terminated per the contract, so the scan stops.
    unsafe {
        while *p != 0 {
            if *p == c {
                return p;
            }
            p = p.add(1);
        }
        ptr::null_mut()
    }
}

/// `strlen`, without libc.
///
/// # Safety
/// `s` must be NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0;
    // SAFETY: `s` is NUL-terminated per the contract, so the scan stops.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// The bytes of a NUL-terminated string, for building a message.
///
/// # Safety
/// `s` must be NULL or NUL-terminated.
unsafe fn c_bytes(s: *const c_char) -> &'static [u8] {
    if s.is_null() {
        return b"";
    }
    // SAFETY: `s` is NUL-terminated per the contract, so the length is its
    // content length and the slice is within the string.
    let n = unsafe { c_strlen(s) };
    // SAFETY: the region is `n` readable bytes, and the returned slice cannot
    // outlive the caller's use because the caller holds the only reference.
    unsafe { core::slice::from_raw_parts(s.cast::<u8>(), n) }
}

// ---------------------------------------------------------------------------
// The library context slot (index 4)
// ---------------------------------------------------------------------------

/// `void *ossl_stored_namemap_new(OSSL_LIB_CTX *libctx)`
///
/// A free-standing namemap marked as belonging to its context — the flag that
/// makes [`ossl_namemap_free`] a no-op for it.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) fn ossl_stored_namemap_new(libctx: *mut c_void) -> *mut OsslNamemap {
    let namemap = ossl_namemap_new(libctx);
    if !namemap.is_null() {
        // SAFETY: `namemap` was just created and has not been published.
        unsafe { (*namemap).stored = 1 };
    }
    namemap
}

/// `void ossl_stored_namemap_free(void *vnamemap)`
///
/// Clears the flag first, "or `ossl_namemap_free()` will do nothing" in the
/// authority's own comment.
///
/// # Safety
/// `vnamemap` must be NULL or a namemap returned by [`ossl_stored_namemap_new`]
/// and not already released.
#[allow(dead_code)] // unreachable until the stratum that calls it lands
pub(crate) unsafe fn ossl_stored_namemap_free(vnamemap: *mut OsslNamemap) {
    if vnamemap.is_null() {
        return;
    }
    // SAFETY: `vnamemap` is live per the contract.
    unsafe {
        (*vnamemap).stored = 0;
        ossl_namemap_free(vnamemap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(lit: &'static core::ffi::CStr) -> *const c_char {
        lit.as_ptr()
    }

    /// The packed code `ERR_peek_error` would report for a recorded site:
    /// `(lib & 0xff) << 23 | (reason & 0x7fffff)`, read from the generated site
    /// table rather than typed, so a wrong expectation here cannot disagree with
    /// the coordinates the authority actually uses.
    fn packed(site: &err_sites::ErrSite) -> core::ffi::c_ulong {
        (((site.lib as core::ffi::c_ulong) & 0xff) << 23)
            | ((site.reason as core::ffi::c_ulong) & 0x7f_ffff)
    }

    #[test]
    fn numbers_are_one_based_and_aliases_share_one() {
        let nm = ossl_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live for the whole test and every argument is a literal.
        unsafe {
            assert_eq!(ossl_namemap_empty(nm), 1);
            // The first name gets 1.
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"SHA2-256")), 1);
            assert_eq!(ossl_namemap_empty(nm), 0);
            // Its alias joins that number.
            assert_eq!(ossl_namemap_add_name(nm, 1, s(c"SHA256")), 1);
            // A second new name gets 2.
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"SHA2-384")), 2);
            // Lookups find both aliases of 1.
            assert_eq!(ossl_namemap_name2num(nm, s(c"SHA2-256")), 1);
            assert_eq!(ossl_namemap_name2num(nm, s(c"SHA256")), 1);
            assert_eq!(ossl_namemap_name2num(nm, s(c"SHA2-384")), 2);
            assert_eq!(ossl_namemap_name2num(nm, s(c"absent")), 0);
            // `num2name` is index-ordered within the number.
            assert_eq!(c_strlen(ossl_namemap_num2name(nm, 1, 0)), 8);
            assert_eq!(c_strlen(ossl_namemap_num2name(nm, 1, 1)), 6);
            assert!(ossl_namemap_num2name(nm, 1, 2).is_null());
            assert!(ossl_namemap_num2name(nm, 0, 0).is_null());
            assert!(ossl_namemap_num2name(nm, 99, 0).is_null());
            ossl_namemap_free(nm);
        }
    }

    /// The comparison is a bit-5 mask, so it is case-insensitive for letters and
    /// *also* collides `'!'` with `0x01`. Both halves are asserted, because the
    /// second is the part a "cleaner" implementation would get wrong.
    #[test]
    fn the_key_is_a_bit_five_mask_rather_than_a_case_fold() {
        let nm = ossl_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live and every argument is a literal.
        unsafe {
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"sha256")), 1);
            assert_eq!(ossl_namemap_name2num(nm, s(c"SHA256")), 1);
            assert_eq!(ossl_namemap_name2num(nm, s(c"ShA256")), 1);
            // `'!'` and `0x01` differ only in bit 5.
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"!")), 2);
            assert_eq!(ossl_namemap_name2num(nm, c"\x01".as_ptr()), 2);
            // And a name that differs beyond bit 5 is a different name.
            assert_eq!(ossl_namemap_name2num(nm, s(c"sha257")), 0);
            ossl_namemap_free(nm);
        }
    }

    /// The explicit-length form keys on a prefix, and a name longer than 63 bytes
    /// is keyed by its first 63 only.
    #[test]
    fn the_length_form_is_a_prefix_and_the_key_is_capped_at_63() {
        let nm = ossl_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live and every argument is a literal, except the
        // explicit-length one, whose byte count is the literal's length.
        unsafe {
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"sha256")), 1);
            assert_eq!(ossl_namemap_name2num_n(nm, s(c"sha256"), 3), 0);
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"sha")), 2);
            assert_eq!(ossl_namemap_name2num_n(nm, s(c"sha256"), 3), 2);

            // Two names differing only after byte 63 are one name.
            let a = c"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb";
            let b = c"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd";
            assert_eq!(c_strlen(a.as_ptr()), 65);
            assert_eq!(ossl_namemap_add_name(nm, 0, a.as_ptr()), 3);
            assert_eq!(ossl_namemap_name2num(nm, b.as_ptr()), 3);
            ossl_namemap_free(nm);
        }
    }

    #[test]
    fn add_names_splits_and_refuses_the_two_ways() {
        let nm = ossl_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live and every argument is a literal.
        unsafe {
            // `add_names` with a NULL namemap raises and answers 0.
            assert_eq!(
                ossl_namemap_add_names(ptr::null_mut(), 0, s(c"a:b"), b':' as c_char),
                0
            );
            assert_eq!(
                crate::runtime::err::ERR_peek_error(),
                packed(&err_sites::CORE_NAMEMAP_321),
                "the recorded coordinate for core_namemap.c:321"
            );
            crate::runtime::err::ERR_clear_error();

            // A NULL `names` answers 0 with no error.
            assert_eq!(
                ossl_namemap_add_names(nm, 0, ptr::null(), b':' as c_char),
                0
            );
            assert_eq!(crate::runtime::err::ERR_peek_error(), 0);

            // Three aliases, one number.
            assert_eq!(
                ossl_namemap_add_names(nm, 0, s(c"a:b:c"), b':' as c_char),
                1
            );
            assert_eq!(ossl_namemap_name2num(nm, s(c"b")), 1);
            assert_eq!(ossl_namemap_name2num(nm, s(c"c")), 1);

            // An empty part is BAD_ALGORITHM_NAME.
            assert_eq!(ossl_namemap_add_names(nm, 0, s(c"a::b"), b':' as c_char), 0);
            assert_eq!(
                crate::runtime::err::ERR_peek_error(),
                packed(&err_sites::CORE_NAMEMAP_349)
            );
            crate::runtime::err::ERR_clear_error();

            // The conflict check is **order-dependent**, which the first run of
            // this test found: `number` stays 0 until some part resolves to one,
            // so a part that already belongs to a number is compared only against
            // an *earlier* part's number. "fresh:a" therefore succeeds and
            // registers "fresh" on `a`'s number, because "fresh" resolved to 0 and
            // only then did "a" resolve to 1.
            assert_eq!(
                ossl_namemap_add_names(nm, 0, s(c"fresh:a"), b':' as c_char),
                1
            );
            assert_eq!(crate::runtime::err::ERR_peek_error(), 0);
            assert_eq!(ossl_namemap_name2num(nm, s(c"fresh")), 1);

            // A second number, so two parts can disagree.
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"zz")), 2);

            // Now the conflict is reachable: "zz" resolves to 2 first, and "b"
            // belongs to 1. The refusal names the part, the number it has, and the
            // whole original string, and adds nothing.
            assert_eq!(ossl_namemap_add_names(nm, 0, s(c"zz:b"), b':' as c_char), 0);
            assert_eq!(
                crate::runtime::err::ERR_peek_error(),
                packed(&err_sites::CORE_NAMEMAP_359)
            );
            crate::runtime::err::ERR_clear_error();
            assert_eq!(ossl_namemap_name2num(nm, s(c"zz")), 2);

            // `doall_names` walks one number's names in insertion order and
            // answers their count. The counter is passed by pointer, which is the
            // callback's only channel back.
            let mut count: c_int = 0;
            let counter = ptr::addr_of_mut!(count).cast::<c_void>();
            assert_eq!(ossl_namemap_doall_names(nm, 1, None, counter), 0);
            assert_eq!(ossl_namemap_doall_names(nm, 99, Some(count_cb), counter), 0);
            // Number 1 holds "a", "b", "c" and the "fresh" that the
            // order-dependent check let through; number 2 holds only "zz".
            assert_eq!(ossl_namemap_doall_names(nm, 2, Some(count_cb), counter), 1);
            assert_eq!(count, 1);
            assert_eq!(ossl_namemap_doall_names(nm, 1, Some(count_cb), counter), 4);
            assert_eq!(count, 5);

            // A NULL namemap is "empty", and a stored map is not freed by the
            // free-standing releaser.
            assert_eq!(ossl_namemap_empty(ptr::null_mut()), 1);
            ossl_namemap_free(nm);
        }
    }

    unsafe extern "C" fn count_cb(_name: *const c_char, data: *mut c_void) {
        // SAFETY: `data` is a `c_int` counter the test owns.
        unsafe { *data.cast::<c_int>() += 1 };
    }

    /// `max_number` is stored unconditionally, so appending an alias to an
    /// existing number can lower it — the authority's own oddity, reproduced.
    #[test]
    fn an_alias_lowers_the_maximum() {
        let nm = ossl_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live for the whole test.
        unsafe {
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"one")), 1);
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"two")), 2);
            assert_eq!((*nm).max_number, 2);
            // An alias of number 1 stores 1, not 2.
            assert_eq!(ossl_namemap_add_name(nm, 1, s(c"uno")), 1);
            assert_eq!((*nm).max_number, 1);
            // Still not empty, which is the only thing `max_number` decides.
            assert_eq!(ossl_namemap_empty(nm), 0);
            ossl_namemap_free(nm);
        }
    }

    /// A stored namemap is not released by `ossl_namemap_free`; the context's own
    /// destructor clears the flag first and then it is.
    #[test]
    fn the_stored_flag_gates_the_release() {
        let nm = ossl_stored_namemap_new(ptr::null_mut());
        assert!(!nm.is_null());
        // SAFETY: `nm` is live.
        unsafe {
            assert_eq!((*nm).stored, 1);
            // The free-standing releaser declines.
            ossl_namemap_free(nm);
            assert_eq!(ossl_namemap_add_name(nm, 0, s(c"still-here")), 1);
            // The context's releaser clears the flag and then releases.
            ossl_stored_namemap_free(nm);
        }
    }
}
