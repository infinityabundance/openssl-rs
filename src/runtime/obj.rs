//! Phase 3 core runtime — the object / NID database.
//!
//! `OBJ_*` is OpenSSL's OID ⇄ NID registry: the mapping between the dotted
//! object identifiers a protocol puts on the wire, the numeric NIDs the C API
//! passes around, and the human short/long names an application prints. Almost
//! every later subsystem names things through it, so its *data* and its
//! *lookup semantics* are load-bearing.
//!
//! The data is generated, not written
//! ----------------------------------
//!
//! The authority's static table has ~1500 objects and several kilobytes of
//! serialized OID bytes. It lives in `obj_table.rs`, emitted by
//! `forensics/tools/gen_nid_table.py` from the authority's own generated
//! `obj_dat.h` / `obj_mac.h` / `obj_xref.h`, byte-for-byte reproducible. The
//! reader who wants to know *what* NID 672 is should read the generated file;
//! this module implements *what the functions do*.
//!
//! The `ASN1_OBJECT` layout is a contract
//! --------------------------------------
//!
//! `ASN1_OBJECT` is opaque in the installed headers (a `typedef` in
//! `types.h`), but its layout is visible to any caller compiled against the
//! older public header, and the authority hands callers a pointer straight into
//! a static array. [`Asn1Object`] therefore reproduces the authority's
//! `struct asn1_object_st` field-for-field and in order, verified against
//! `include/crypto/asn1.h`:
//!
//! ```text
//! struct asn1_object_st {
//!     const char *sn, *ln;      /* short / long name, or NULL   */
//!     int nid;                  /* numeric id, 0 == NID_undef   */
//!     int length;               /* content octets, not DER total */
//!     const unsigned char *data;/* OID *content*, no tag/length */
//!     int flags;                /* ASN1_OBJECT_FLAG_*           */
//! };
//! ```
//!
//! `data`/`length` are the DER **content** octets: `i2d_ASN1_OBJECT` writes the
//! `06 <len>` header itself and then `memcpy`s `a->data`. This was confirmed by
//! probing the authority: `OBJ_nid2obj(NID_commonName)` yields
//! `length == 3`, `data == {0x55,0x04,0x03}` (not `{0x06,0x03,0x55,0x04,0x03}`).
//! [`OBJ_length`] and [`OBJ_get0_data`] expose exactly those fields.
//!
//! Duplicate names and the authority's exact tie-break
//! --------------------------------------------------
//!
//! Three static entries share the literal short and long name `"NULL"`
//! (`NID_ccitt`, `NID_joint_iso_ccitt`, `NID_ac_auditEntity`). A binary search
//! for a duplicate key does not return "the first" or "the smallest" — it
//! returns whichever element the *algorithm* lands on. So the generated table
//! carries the authority's own sorted index lists (`sn_objs[]`, `ln_objs[]`,
//! `obj_objs[]`) and this module reproduces the authority's `ossl_bsearch`
//! (`crypto/bsearch.c`) exactly, rather than re-sorting and hoping.
//!
//! Mutable state: the dynamic object database
//! ------------------------------------------
//!
//! On top of the static table, [`OBJ_create`] / [`OBJ_add_object`] register new
//! objects and [`OBJ_new_nid`] hands out fresh NIDs (starting at `NUM_NID`, the
//! authority's `new_nid`). That is real process-wide mutable state, guarded
//! here by a `Mutex`; the authority guards the same state with a rwlock. Newly
//! created objects are deliberately leaked and immortal, matching the
//! authority, whose added objects live until process teardown and whose
//! returned `ASN1_OBJECT *` stays valid for the life of the process.
//!
//! Deferred symbol (recorded, not invented)
//! ----------------------------------------
//!
//! `OBJ_create_objects(BIO *in)` is **not** implemented here. It parses a text
//! stream by calling `BIO_gets`, and the BIO subsystem is a later phase; there
//! is no BIO type in the crate yet. Defining it against a stub BIO, or
//! returning a plausible count without reading the stream, would be a fabricated
//! behaviour, so the symbol is left for the ABI shell to scaffold (which aborts
//! loudly). The remaining `OBJ_*` authority exports are all implemented.
//!
//! Recorded divergences
//! --------------------
//!
//! These are places where the authority's behaviour is undefined or
//! process-hostile, and `docs/UNSAFE.md` §5 forbids imitating UB rather than
//! reproducing it:
//!
//! * NULL pointers. `OBJ_sn2nid(NULL)`, `OBJ_obj2nid` on `{length>0,data=NULL}`
//!   and `OBJ_cmp(NULL, ...)` dereference NULL in the authority. Here they
//!   return the documented failure value (or, for [`OBJ_cmp`], a total order
//!   with NULL sorting before non-NULL).
//! * A negative `buf_len` in [`OBJ_obj2txt`]: the authority converts it to
//!   `size_t` for `strlcpy`, i.e. a wild copy. Here a non-positive length means
//!   "count only", which is the length-0 behaviour.
//! * `OBJ_sigid_free` followed by another lookup crashes in the authority (it
//!   frees the lock but the `CRYPTO_ONCE` initialiser will not run again, so a
//!   NULL lock is passed to `pthread_mutex_lock`). Here the registry is simply
//!   emptied and remains usable.
//! * The authority raises `ERR` entries (and, without string tables, leaves the
//!   reason text empty) on these failures. This module returns the right values
//!   but does not yet push onto the error queue: reason-string tables are an
//!   open obligation tracked by the `ERR` court, and half-populating the queue
//!   would be its own divergence.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::ffi::guard_ffi;

#[path = "obj_table.rs"]
mod obj_table;

use obj_table::*;

/// `ASN1_OBJECT_FLAG_DYNAMIC` — the object itself is heap-allocated.
pub(crate) const ASN1_OBJECT_FLAG_DYNAMIC: c_int = 0x01;
/// `ASN1_OBJECT_FLAG_DYNAMIC_STRINGS` — `sn`/`ln` are heap-allocated.
pub(crate) const ASN1_OBJECT_FLAG_DYNAMIC_STRINGS: c_int = 0x04;
/// `ASN1_OBJECT_FLAG_DYNAMIC_DATA` — `data` is heap-allocated.
pub(crate) const ASN1_OBJECT_FLAG_DYNAMIC_DATA: c_int = 0x08;

/// `OBJ_BSEARCH_VALUE_ON_NOMATCH` — return the last probed slot on a miss.
const OBJ_BSEARCH_VALUE_ON_NOMATCH: c_int = 0x01;
/// `OBJ_BSEARCH_FIRST_VALUE_ON_MATCH` — back up to the first equal slot.
const OBJ_BSEARCH_FIRST_VALUE_ON_MATCH: c_int = 0x02;

/// `OBJ_NAME_TYPE_NUM` — the first dynamically allocated name type index.
const OBJ_NAME_TYPE_NUM: c_int = 0x07;
/// `OBJ_NAME_ALIAS` — the entry names another entry rather than a value.
const OBJ_NAME_ALIAS: c_int = 0x8000;

extern "C" {
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
}

// ---------------------------------------------------------------------------
// The ABI-visible object layout
// ---------------------------------------------------------------------------

/// C-ABI projection of the authority's `struct asn1_object_st`.
///
/// The field order is the authority's (`include/crypto/asn1.h`) and must not be
/// rearranged: callers read `nid`, `length` and `data` directly, and
/// [`OBJ_nid2obj`] hands out pointers into the static table of these. The
/// `flags` word carries the `ASN1_OBJECT_FLAG_*` bits; static table entries use
/// `0`, dynamically created ones set the `DYNAMIC*` bits.
///
/// The raw pointers are written only before the object becomes reachable (at
/// construction, or table-generation time) and are never mutated afterwards,
/// which is what makes the `Send`/`Sync` assertions below sound.
#[repr(C)]
pub struct Asn1Object {
    /// Short name, or NULL.
    pub(crate) sn: *const c_char,
    /// Long name, or NULL.
    pub(crate) ln: *const c_char,
    /// Numeric id; `NID_undef` (0) means "unnamed".
    pub(crate) nid: c_int,
    /// Number of DER *content* octets in `data`.
    pub(crate) length: c_int,
    /// DER content octets, or NULL when there are none.
    pub(crate) data: *const u8,
    /// `ASN1_OBJECT_FLAG_*` bits.
    pub(crate) flags: c_int,
}

// SAFETY: every field is immutable once the object is published: static table
// entries are const data, and dynamically created objects are built under the
// registry lock and never written afterwards. Sharing `&Asn1Object` across
// threads therefore exposes no data race. The pointees (`sn`, `ln`, `data`) are
// likewise immutable for as long as the object is reachable.
unsafe impl Send for Asn1Object {}
// SAFETY: as the `Send` impl above; `&Asn1Object` is a read-only view of
// immutable, non-aliased state.
unsafe impl Sync for Asn1Object {}

// ---------------------------------------------------------------------------
// C-string helpers
// ---------------------------------------------------------------------------

/// Length of a NUL-terminated string, excluding the terminator.
///
/// # Safety
/// `p` must point to a valid NUL-terminated string.
unsafe fn c_strlen(p: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `p` is NUL-terminated, so reads stop at the terminator.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `strcmp` on `unsigned char`, as the authority's generated comparators use.
///
/// # Safety
/// Both pointers must be valid NUL-terminated strings.
unsafe fn c_strcmp(a: *const c_char, b: *const c_char) -> c_int {
    let mut i = 0usize;
    loop {
        // SAFETY: both strings are NUL-terminated, and the loop returns at the
        // first terminator, so neither read leaves the allocation.
        let (ca, cb) = unsafe { (*a.add(i) as u8 as c_int, *b.add(i) as u8 as c_int) };
        if ca != cb {
            return ca - cb;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
}

fn ascii_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// `OPENSSL_strcasecmp`, the default key comparison for `OBJ_NAME`.
///
/// # Safety
/// Both pointers must be valid NUL-terminated strings.
unsafe fn c_strcasecmp(a: *const c_char, b: *const c_char) -> c_int {
    let mut i = 0usize;
    loop {
        // SAFETY: both strings are NUL-terminated; the loop returns at the
        // first terminator.
        let (ca, cb) = unsafe {
            (
                ascii_lower(*a.add(i) as u8) as c_int,
                ascii_lower(*b.add(i) as u8) as c_int,
            )
        };
        if ca != cb {
            return ca - cb;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Copy a NUL-terminated string into a fresh `Box<[u8]>` that owns the bytes
/// (including the terminator), so a raw pointer into it stays valid.
///
/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
unsafe fn boxed_cstr(p: *const c_char) -> Option<Box<[u8]>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is NUL-terminated.
    let n = unsafe { c_strlen(p) };
    let mut v = Vec::with_capacity(n + 1);
    // SAFETY: `p` is readable for `n` bytes.
    v.extend_from_slice(unsafe { core::slice::from_raw_parts(p as *const u8, n) });
    v.push(0);
    Some(v.into_boxed_slice())
}

/// `OPENSSL_strlcpy` semantics: copy at most `size - 1` bytes and NUL-terminate.
///
/// # Safety
/// `dst` must be NULL or writable for `size` bytes; `src` NUL-terminated.
unsafe fn strlcpy_cstr(dst: *mut c_char, src: *const c_char, size: c_int) {
    if dst.is_null() || size <= 0 {
        return;
    }
    // SAFETY: `src` is NUL-terminated.
    let srclen = unsafe { c_strlen(src) };
    let cap = size as usize;
    let n = srclen.min(cap - 1);
    // SAFETY: `dst` is writable for `cap` bytes; `src` is readable for `n`.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, n);
        *dst.add(n) = 0;
    }
}

// ---------------------------------------------------------------------------
// The authority's binary search
// ---------------------------------------------------------------------------

/// Reproduce `ossl_bsearch` (`crypto/bsearch.c`) over an index list.
///
/// `cmp(i)` must compare the search key against element `i` and return the same
/// sign convention as the C comparator. Returns the index the authority's
/// algorithm would return, honouring the `OBJ_BSEARCH_*` flags.
fn bsearch_index<F>(len: usize, flags: c_int, cmp: F) -> Option<usize>
where
    F: Fn(usize) -> c_int,
{
    if len == 0 {
        return None;
    }
    let mut l = 0usize;
    let mut h = len;
    let mut i = 0usize;
    let mut c = 0i32;
    while l < h {
        i = l + (h - l) / 2;
        c = cmp(i);
        if c < 0 {
            h = i;
        } else if c > 0 {
            l = i + 1;
        } else {
            break;
        }
    }
    if c != 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH) == 0 {
        return None;
    }
    if c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH) != 0 {
        while i > 0 && cmp(i - 1) == 0 {
            i -= 1;
        }
    }
    Some(i)
}

/// Compare an object against a `(length, data)` OID pair the way `obj_cmp`
/// does: length first, then the content bytes.
fn obj_cmp_parts(a_len: c_int, a_data: *const u8, b_len: c_int, b_data: *const u8) -> c_int {
    let d = a_len.wrapping_sub(b_len);
    if d != 0 {
        return d;
    }
    if a_len == 0 {
        return 0;
    }
    if a_data.is_null() || b_data.is_null() {
        return 0;
    }
    // SAFETY: both buffers hold `a_len == b_len` bytes per the caller's
    // invariant; memcmp reads only that many.
    unsafe {
        memcmp(
            a_data as *const c_void,
            b_data as *const c_void,
            a_len as usize,
        )
    }
}

// ---------------------------------------------------------------------------
// Static-table lookups
// ---------------------------------------------------------------------------

/// `OBJ_sn2nid` against the static table only.
///
/// # Safety
/// `s` must be a valid NUL-terminated string.
unsafe fn static_sn_to_nid(s: *const c_char) -> c_int {
    let idx = bsearch_index(NUM_SN, 0, |i| {
        let e = &NID_OBJS[SN_ORDER[i] as usize];
        // SAFETY: `s` is the caller's NUL-terminated name; `e.sn` is a static
        // NUL-terminated name.
        unsafe { c_strcmp(s, e.sn) }
    });
    match idx {
        Some(i) => NID_OBJS[SN_ORDER[i] as usize].nid,
        None => NID_undef,
    }
}

/// `OBJ_ln2nid` against the static table only.
///
/// # Safety
/// `s` must be a valid NUL-terminated string.
unsafe fn static_ln_to_nid(s: *const c_char) -> c_int {
    let idx = bsearch_index(NUM_LN, 0, |i| {
        let e = &NID_OBJS[LN_ORDER[i] as usize];
        // SAFETY: as `static_sn_to_nid`.
        unsafe { c_strcmp(s, e.ln) }
    });
    match idx {
        Some(i) => NID_OBJS[LN_ORDER[i] as usize].nid,
        None => NID_undef,
    }
}

/// `ossl_obj_obj2nid`'s static OID search.
///
/// # Safety
/// `data` must be readable for `len` bytes (or `len` may be 0).
unsafe fn static_data_to_nid(data: *const u8, len: usize) -> c_int {
    let idx = bsearch_index(NUM_OBJ, 0, |i| {
        let e = &NID_OBJS[OBJ_ORDER[i] as usize];
        obj_cmp_parts(len as c_int, data, e.length, e.data)
    });
    match idx {
        Some(i) => NID_OBJS[OBJ_ORDER[i] as usize].nid,
        None => NID_undef,
    }
}

// ---------------------------------------------------------------------------
// The dynamic object database
// ---------------------------------------------------------------------------

/// A dynamically registered object and the buffers its raw pointers point into.
///
/// The `Box`es keep the pointees alive for the life of the process; moving the
/// struct (for example when the `Vec` grows) moves the *handles*, not the heap
/// allocations, so the pointers stored in `obj` remain valid.
struct AddedObject {
    obj: Box<Asn1Object>,
    _sn: Option<Box<[u8]>>,
    _ln: Option<Box<[u8]>>,
    _data: Box<[u8]>,
}

/// The added-object table. `added` is scanned linearly, exactly reproducing the
/// authority's keyed lookups for the handful of objects an application creates.
struct ObjDb {
    added: Vec<AddedObject>,
}

static OBJ_DB: Mutex<ObjDb> = Mutex::new(ObjDb { added: Vec::new() });

/// The authority's `new_nid`, starting at `NUM_NID`. `OBJ_new_nid` returns the
/// old value, i.e. `fetch_add` semantics, confirmed by probe.
static NEXT_NID: AtomicI32 = AtomicI32::new(NUM_NID as i32);

fn lock_db() -> MutexGuard<'static, ObjDb> {
    match OBJ_DB.lock() {
        Ok(guard) => guard,
        // Poisoning records a defect, not a reason to stop being able to look
        // up objects; the data we care about is not left half-written.
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Look up an added object by NID.
fn added_lookup_nid(nid: c_int) -> Option<*mut Asn1Object> {
    let db = lock_db();
    db.added
        .iter()
        .find(|e| e.obj.nid == nid)
        .map(|e| &*e.obj as *const Asn1Object as *mut Asn1Object)
}

/// Look up an added object by short (`long == false`) or long name.
///
/// # Safety
/// `s` must be a valid NUL-terminated string.
unsafe fn added_name_to_nid(s: *const c_char, long: bool) -> c_int {
    let db = lock_db();
    for e in &db.added {
        let name = if long { e.obj.ln } else { e.obj.sn };
        if name.is_null() {
            continue;
        }
        // SAFETY: both names are NUL-terminated.
        if unsafe { c_strcmp(name, s) } == 0 {
            return e.obj.nid;
        }
    }
    NID_undef
}

/// Look up an added object by OID content.
///
/// # Safety
/// `data` must be readable for `len` bytes.
unsafe fn added_data_to_nid(data: *const u8, len: usize) -> c_int {
    if len == 0 {
        return NID_undef;
    }
    let db = lock_db();
    for e in &db.added {
        if e.obj.length as usize != len || e.obj.data.is_null() {
            continue;
        }
        // SAFETY: both buffers are `len` bytes.
        if unsafe { memcmp(e.obj.data as *const c_void, data as *const c_void, len) } == 0 {
            return e.obj.nid;
        }
    }
    NID_undef
}

/// The `obj_equivalent` test used for registration conflict handling.
fn equivalent(
    e: &AddedObject,
    nid: c_int,
    data: Option<&[u8]>,
    sn: *const c_char,
    ln: *const c_char,
) -> bool {
    if e.obj.nid != nid {
        return false;
    }
    match data {
        Some(d) => {
            if e.obj.length as usize != d.len() {
                return false;
            }
            if !d.is_empty() {
                if e.obj.data.is_null() {
                    return false;
                }
                // SAFETY: both buffers are `d.len()` bytes.
                if unsafe {
                    memcmp(
                        e.obj.data as *const c_void,
                        d.as_ptr() as *const c_void,
                        d.len(),
                    )
                } != 0
                {
                    return false;
                }
            }
        }
        None => {
            if e.obj.length != 0 || !e.obj.data.is_null() {
                return false;
            }
        }
    }
    name_matches(e.obj.sn, sn) && name_matches(e.obj.ln, ln)
}

fn name_matches(stored: *const c_char, candidate: *const c_char) -> bool {
    match (stored.is_null(), candidate.is_null()) {
        (true, true) => true,
        (false, false) => {
            // SAFETY: both pointers are NUL-terminated strings.
            unsafe { c_strcmp(stored, candidate) == 0 }
        }
        _ => false,
    }
}

/// Register an object, reproducing `add_object`'s conflict handling: an exact
/// duplicate of an existing registration is accepted and returns its NID, any
/// other collision is rejected with `NID_undef`.
///
/// # Safety
/// `sn` and `ln` must be NULL or valid NUL-terminated strings.
unsafe fn db_insert(
    nid: c_int,
    data: Option<&[u8]>,
    sn: *const c_char,
    ln: *const c_char,
) -> c_int {
    let mut db = lock_db();
    let mut conflict: Option<usize> = None;
    for (i, e) in db.added.iter().enumerate() {
        let mut hit = e.obj.nid == nid;
        if !hit {
            if let Some(d) = data {
                if !d.is_empty() && e.obj.length as usize == d.len() && !e.obj.data.is_null() {
                    // SAFETY: both buffers are `d.len()` bytes.
                    if unsafe {
                        memcmp(
                            e.obj.data as *const c_void,
                            d.as_ptr() as *const c_void,
                            d.len(),
                        )
                    } == 0
                    {
                        hit = true;
                    }
                }
            }
        }
        if !hit && !sn.is_null() && !e.obj.sn.is_null() {
            // SAFETY: both names are NUL-terminated.
            if unsafe { c_strcmp(e.obj.sn, sn) == 0 } {
                hit = true;
            }
        }
        if !hit && !ln.is_null() && !e.obj.ln.is_null() {
            // SAFETY: both names are NUL-terminated.
            if unsafe { c_strcmp(e.obj.ln, ln) == 0 } {
                hit = true;
            }
        }
        if hit {
            conflict = Some(i);
            break;
        }
    }
    if let Some(i) = conflict {
        let e = &db.added[i];
        if equivalent(e, nid, data, sn, ln) {
            return nid;
        }
        return NID_undef;
    }

    let data_box: Box<[u8]> = match data {
        Some(d) => d.to_vec().into_boxed_slice(),
        None => Vec::new().into_boxed_slice(),
    };
    // SAFETY: `sn`/`ln` are NULL or valid NUL-terminated strings.
    let sn_box = unsafe { boxed_cstr(sn) };
    // SAFETY: as above.
    let ln_box = unsafe { boxed_cstr(ln) };
    let data_ptr = if data_box.is_empty() {
        core::ptr::null()
    } else {
        data_box.as_ptr()
    };
    let sn_ptr = sn_box
        .as_ref()
        .map_or(core::ptr::null(), |b| b.as_ptr() as *const c_char);
    let ln_ptr = ln_box
        .as_ref()
        .map_or(core::ptr::null(), |b| b.as_ptr() as *const c_char);
    let obj = Box::new(Asn1Object {
        sn: sn_ptr,
        ln: ln_ptr,
        nid,
        length: data_box.len() as c_int,
        data: data_ptr,
        flags: 0,
    });
    db.added.push(AddedObject {
        obj,
        _sn: sn_box,
        _ln: ln_box,
        _data: data_box,
    });
    nid
}

/// `ossl_obj_obj2nid` over both the static and dynamic tables.
fn content_to_nid(data: &[u8]) -> c_int {
    // SAFETY: `data` is a live slice, so its pointer is readable for its length.
    let nid = unsafe { static_data_to_nid(data.as_ptr(), data.len()) };
    if nid != NID_undef {
        return nid;
    }
    // SAFETY: as above.
    unsafe { added_data_to_nid(data.as_ptr(), data.len()) }
}

// ---------------------------------------------------------------------------
// Dynamic-object heap management (ASN1_OBJECT allocation)
// ---------------------------------------------------------------------------

/// Duplicate a NUL-terminated string with `malloc`, for a dynamic object.
///
/// # Safety
/// `src` must be NULL or a valid NUL-terminated string.
unsafe fn dup_cstr(src: *const c_char) -> *mut c_char {
    if src.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `src` is NUL-terminated.
    let n = unsafe { c_strlen(src) };
    // SAFETY: `malloc` returns NULL or a block of at least `n+1` bytes.
    let dst = unsafe { malloc(n + 1) } as *mut c_char;
    if dst.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `dst` is `n+1` bytes and cannot overlap `src`.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, n + 1) };
    dst
}

/// The candidate free path for objects this module allocates, mirroring
/// `ASN1_OBJECT_free`. Static table entries have no `DYNAMIC` bit and are left
/// untouched.
///
/// # Safety
/// `p` must be NULL or a pointer returned by [`dup_object`] / the dynamic
/// allocation in [`OBJ_txt2obj`], and must not be used again.
pub(crate) unsafe fn object_free(p: *mut Asn1Object) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live object per the caller's contract.
    let o = unsafe { &mut *p };
    if o.flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS != 0 {
        if !o.sn.is_null() {
            // SAFETY: allocated by `dup_cstr` and owned here.
            unsafe { free(o.sn as *mut c_void) };
        }
        if !o.ln.is_null() {
            // SAFETY: allocated by `dup_cstr` and owned here.
            unsafe { free(o.ln as *mut c_void) };
        }
        o.sn = core::ptr::null();
        o.ln = core::ptr::null();
    }
    if o.flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA != 0 {
        if !o.data.is_null() {
            // SAFETY: allocated for this object and owned here.
            unsafe { free(o.data as *mut c_void) };
        }
        o.data = core::ptr::null();
        o.length = 0;
    }
    if o.flags & ASN1_OBJECT_FLAG_DYNAMIC != 0 {
        // SAFETY: the object itself was `malloc`ed for this object.
        unsafe { free(p as *mut c_void) };
    }
}

/// `OBJ_dup`: a non-dynamic object is returned as-is (the authority does the
/// same), a dynamic one is deep-copied.
///
/// # Safety
/// `o` must be NULL or a valid object pointer.
pub(crate) unsafe fn object_dup(o: *const Asn1Object) -> *mut Asn1Object {
    if o.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `o` is a valid object pointer.
    let src = unsafe { &*o };
    if src.flags & ASN1_OBJECT_FLAG_DYNAMIC == 0 {
        return o as *mut Asn1Object;
    }
    // SAFETY: `malloc` returns NULL or a live, suitably aligned block.
    let r = unsafe { malloc(core::mem::size_of::<Asn1Object>()) } as *mut Asn1Object;
    if r.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `r` is an uninitialised block of exactly one `Asn1Object`.
    unsafe { core::ptr::write_bytes(r, 0, 1) };
    // SAFETY: `r` is a live object.
    unsafe {
        (*r).flags = src.flags
            | ASN1_OBJECT_FLAG_DYNAMIC
            | ASN1_OBJECT_FLAG_DYNAMIC_STRINGS
            | ASN1_OBJECT_FLAG_DYNAMIC_DATA;
    }
    if src.length > 0 && !src.data.is_null() {
        // SAFETY: `malloc` returns NULL or `src.length` bytes.
        let d = unsafe { malloc(src.length as usize) } as *mut u8;
        if d.is_null() {
            // SAFETY: `r` was allocated here and is not yet published.
            unsafe { free(r as *mut c_void) };
            return core::ptr::null_mut();
        }
        // SAFETY: both buffers are `src.length` bytes and do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(src.data, d, src.length as usize) };
        // SAFETY: `r` is live.
        unsafe { (*r).data = d };
    }
    // SAFETY: `r` is live.
    unsafe {
        (*r).length = src.length;
        (*r).nid = src.nid;
    }
    if !src.ln.is_null() {
        // SAFETY: `src.ln` is NUL-terminated.
        let l = unsafe { dup_cstr(src.ln) };
        if l.is_null() {
            // SAFETY: `r` is live and owned here.
            unsafe { object_free(r) };
            return core::ptr::null_mut();
        }
        // SAFETY: `r` is live.
        unsafe { (*r).ln = l };
    }
    if !src.sn.is_null() {
        // SAFETY: `src.sn` is NUL-terminated.
        let s = unsafe { dup_cstr(src.sn) };
        if s.is_null() {
            // SAFETY: `r` is live and owned here.
            unsafe { object_free(r) };
            return core::ptr::null_mut();
        }
        // SAFETY: `r` is live.
        unsafe { (*r).sn = s };
    }
    r
}

// ---------------------------------------------------------------------------
// The ASN.1 stratum's object constructors
// ---------------------------------------------------------------------------

/// `ASN1_OBJECT *ASN1_OBJECT_new(void)` — a zeroed object flagged dynamic.
///
/// The ASN.1 stratum's object layer is the caller; it is the `ASN1_OBJECT_new`
/// export. Kept here beside the object's allocator so an object is always built by
/// the module that owns `Asn1Object`'s layout.
#[allow(dead_code)] // the caller lands with Phase 5's ASN.1 surface
pub(crate) fn object_new() -> *mut Asn1Object {
    // SAFETY: `malloc` answers NULL or a live, aligned block of one object.
    let r = unsafe { malloc(core::mem::size_of::<Asn1Object>()) } as *mut Asn1Object;
    if r.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `r` is an uninitialised block of exactly one `Asn1Object`, written
    // in full before it is returned.
    unsafe {
        core::ptr::write(
            r,
            Asn1Object {
                sn: core::ptr::null(),
                ln: core::ptr::null(),
                nid: NID_undef,
                length: 0,
                data: core::ptr::null(),
                flags: ASN1_OBJECT_FLAG_DYNAMIC,
            },
        );
    }
    r
}

/// `ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
/// const char *sn, const char *ln)`.
///
/// The authority builds this on the stack and hands it to `OBJ_dup`, so the
/// result is a fresh deep copy and the caller keeps ownership of every argument.
///
/// # Safety
/// `data` must be readable for `len` bytes; `sn` and `ln` must be NULL or
/// NUL-terminated strings. All three are copied, never retained.
#[allow(dead_code)] // the caller lands with Phase 5's ASN.1 object surface
pub(crate) unsafe fn object_create(
    nid: c_int,
    data: *mut u8,
    len: c_int,
    sn: *const c_char,
    ln: *const c_char,
) -> *mut Asn1Object {
    let o = Asn1Object {
        sn,
        ln,
        nid,
        length: len,
        data,
        flags: ASN1_OBJECT_FLAG_DYNAMIC
            | ASN1_OBJECT_FLAG_DYNAMIC_STRINGS
            | ASN1_OBJECT_FLAG_DYNAMIC_DATA,
    };
    // SAFETY: `o` is a complete, valid object; `object_dup` reads it and copies
    // every field it owns, so the temporary never outlives this call.
    unsafe { object_dup(&o) }
}

/// Allocate a dynamic `ASN1_OBJECT` holding a copy of `data`, exactly as
/// `d2i_ASN1_OBJECT` builds one for an OID it does not know.
pub(crate) fn alloc_oid_object(data: &[u8]) -> *mut Asn1Object {
    // SAFETY: `malloc` returns NULL or a live, aligned block.
    let obj = unsafe { malloc(core::mem::size_of::<Asn1Object>()) } as *mut Asn1Object;
    if obj.is_null() {
        return core::ptr::null_mut();
    }
    let data_ptr = if data.is_empty() {
        core::ptr::null()
    } else {
        // SAFETY: `malloc` returns NULL or `data.len()` bytes.
        let p = unsafe { malloc(data.len()) } as *mut u8;
        if p.is_null() {
            // SAFETY: `obj` was allocated here.
            unsafe { free(obj as *mut c_void) };
            return core::ptr::null_mut();
        }
        // SAFETY: `p` is `data.len()` bytes and does not overlap `data`.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
        p
    };
    // SAFETY: `obj` is a live, uninitialised block of one `Asn1Object`.
    unsafe {
        core::ptr::write(
            obj,
            Asn1Object {
                sn: core::ptr::null(),
                ln: core::ptr::null(),
                nid: NID_undef,
                length: data.len() as c_int,
                data: data_ptr,
                flags: ASN1_OBJECT_FLAG_DYNAMIC | ASN1_OBJECT_FLAG_DYNAMIC_DATA,
            },
        );
    }
    obj
}

// ---------------------------------------------------------------------------
// OID text encoding / decoding
// ---------------------------------------------------------------------------

/// A minimal arbitrary-precision non-negative integer, sufficient for one OID
/// sub-identifier. Arc values can exceed 128 bits (`a2d_ASN1_OBJECT` uses a
/// `BIGNUM`), so the authority is not reproduced by a fixed-width integer.
#[derive(Clone)]
struct Big {
    /// Little-endian base-2^32 limbs, with no trailing zero limb.
    limbs: Vec<u32>,
}

impl Big {
    fn zero() -> Self {
        Big { limbs: Vec::new() }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn normalize(&mut self) {
        while let Some(&0) = self.limbs.last() {
            self.limbs.pop();
        }
    }

    fn mul_add_small(&mut self, m: u64, add: u64) {
        let mut carry = add;
        for limb in &mut self.limbs {
            let v = (*limb as u64) * m + carry;
            *limb = v as u32;
            carry = v >> 32;
        }
        while carry > 0 {
            self.limbs.push(carry as u32);
            carry >>= 32;
        }
    }

    /// Returns `(quotient, remainder)`.
    fn div_rem_small(&self, d: u32) -> (Big, u32) {
        let mut limbs = vec![0u32; self.limbs.len()];
        let mut rem = 0u64;
        for i in (0..self.limbs.len()).rev() {
            let cur = (rem << 32) | self.limbs[i] as u64;
            limbs[i] = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        let mut q = Big { limbs };
        q.normalize();
        (q, rem as u32)
    }

    fn cmp_small(&self, n: u32) -> core::cmp::Ordering {
        if self.limbs.is_empty() {
            return 0u32.cmp(&n);
        }
        if self.limbs.len() > 1 {
            return core::cmp::Ordering::Greater;
        }
        self.limbs[0].cmp(&n)
    }

    fn sub_small(&mut self, n: u32) {
        let mut borrow = n as u64;
        let mut i = 0usize;
        while borrow > 0 && i < self.limbs.len() {
            let cur = self.limbs[i] as u64;
            if cur >= borrow {
                self.limbs[i] = (cur - borrow) as u32;
                borrow = 0;
            } else {
                self.limbs[i] = (cur + (1u64 << 32) - borrow) as u32;
                borrow = 1;
            }
            i += 1;
        }
        self.normalize();
    }

    fn to_u32(&self) -> Option<u32> {
        if self.limbs.len() > 1 {
            None
        } else {
            self.limbs.first().copied().or(Some(0))
        }
    }

    /// Big-endian base-128 with the continuation bit, `a2d`'s wire encoding.
    fn encode_base128(&self) -> Vec<u8> {
        let mut n = self.clone();
        let mut out = Vec::new();
        loop {
            let (q, rem) = n.div_rem_small(128);
            out.push(rem as u8);
            n = q;
            if n.is_zero() {
                break;
            }
        }
        out.reverse();
        let last = out.len() - 1;
        for b in &mut out[..last] {
            *b |= 0x80;
        }
        out
    }

    /// Decimal text, as `BN_bn2dec` would produce.
    fn to_decimal(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![b'0'];
        }
        let mut n = self.clone();
        let mut digits = Vec::new();
        while !n.is_zero() {
            let (q, rem) = n.div_rem_small(10);
            digits.push(b'0' + rem as u8);
            n = q;
        }
        digits.reverse();
        digits
    }
}

/// The outcome of `a2d_ASN1_OBJECT`.
///
/// The three cases are not two: a rejection either **raises** an ASN.1 error or
/// is silent, and which one depends on where the parser gave up. A first number
/// outside `0..2`, a missing second number, a bad separator, a non-digit
/// component and a too-large second number all raise; a stream that yields no
/// content octets at all (a two-character OID such as `"12"`) returns a length of
/// zero and raises nothing, because `a2d` itself did not fail — the caller's
/// `i <= 0` test is what rejects it. Collapsing the two into one `None` would make
/// the error queue wrong for the silent case.
enum OidParse {
    /// The DER content octets.
    Ok(Vec<u8>),
    /// Rejected, and the authority raises at this site.
    Raise(&'static crate::runtime::err::err_sites::ErrSite),
    /// Rejected without raising.
    Silent,
}

/// `a2d_ASN1_OBJECT`: dotted-decimal text to DER content octets.
///
/// The structure is the authority's, including the two-character lookahead and
/// the fact that a component separator may be a **space** as well as a dot.
fn parse_oid_text(s: &[u8]) -> OidParse {
    use crate::runtime::err::err_sites::{
        A_OBJECT_105, A_OBJECT_124, A_OBJECT_78, A_OBJECT_83, A_OBJECT_92,
    };

    // An empty string still has a first character as far as `a2d` is concerned:
    // it reads the NUL terminator, which is not in `0..2`, and raises.
    let first = match s.first() {
        Some(c @ b'0'..=b'2') => (*c - b'0') as u32,
        _ => return OidParse::Raise(&A_OBJECT_78),
    };
    let mut idx = 1usize;
    if idx >= s.len() {
        return OidParse::Raise(&A_OBJECT_83);
    }
    let mut c = s[idx];
    idx += 1;

    let mut out = Vec::new();
    loop {
        if idx >= s.len() {
            break;
        }
        if c != b'.' && c != b' ' {
            return OidParse::Raise(&A_OBJECT_92);
        }
        let mut big = Big::zero();
        loop {
            if idx >= s.len() {
                break;
            }
            c = s[idx];
            idx += 1;
            if c == b' ' || c == b'.' {
                break;
            }
            if !c.is_ascii_digit() {
                return OidParse::Raise(&A_OBJECT_105);
            }
            big.mul_add_small(10, (c - b'0') as u64);
        }
        if out.is_empty() {
            if first < 2 && big.cmp_small(40) != core::cmp::Ordering::Less {
                return OidParse::Raise(&A_OBJECT_124);
            }
            big.mul_add_small(1, (first * 40) as u64);
        }
        out.extend_from_slice(&big.encode_base128());
    }
    if out.is_empty() {
        // `a2d` answered a length of zero; the caller's `i <= 0` test rejects it
        // without the parser having raised.
        OidParse::Silent
    } else {
        OidParse::Ok(out)
    }
}

/// The numeric rendering half of `OBJ_obj2txt`.
///
/// # Safety
/// `data` must be readable for `length` bytes; `buf` must be NULL or writable
/// for `max(buf_len, 0)` bytes.
unsafe fn obj2txt_numeric(
    buf: *mut c_char,
    buf_len: c_int,
    data: *const u8,
    length: c_int,
) -> c_int {
    if length > 586 {
        return -1;
    }
    let mut p = data;
    let mut remaining = length;
    let mut n: c_int = 0;
    let mut b = buf;
    let mut bl = buf_len;
    let mut first = true;

    while remaining > 0 {
        let mut big = Big::zero();
        loop {
            // SAFETY: `remaining > 0`, so `p` is inside `data[0..length]`.
            let byte = unsafe { *p };
            // SAFETY: as above; `p` advances by one over the same buffer.
            p = unsafe { p.add(1) };
            remaining -= 1;
            if remaining == 0 && (byte & 0x80) != 0 {
                return -1;
            }
            big.mul_add_small(128, (byte & 0x7f) as u64);
            if (byte & 0x80) == 0 {
                break;
            }
        }

        let arc = if first {
            first = false;
            if big.cmp_small(80) != core::cmp::Ordering::Less {
                big.sub_small(80);
                let arc = 2u32;
                n += 1;
                if !b.is_null() && bl > 1 {
                    // SAFETY: `b` is writable for `bl > 1` bytes.
                    unsafe {
                        *b = (b'0' + arc as u8) as c_char;
                        b = b.add(1);
                        *b = 0;
                    }
                    bl -= 1;
                }
                big
            } else {
                // The first byte encodes BOTH leading arcs as `40 * arc0 + arc1`.
                // `arc0` is the quotient (0 or 1 here, since the value is < 80)
                // and the value that must then be rendered is the REMAINDER. Using
                // the undivided value here is what made `1.2.840...` render as
                // `1.42.840...`.
                let (q, r) = big.div_rem_small(40);
                let arc = q.to_u32().unwrap_or(2);
                let mut rem = Big::zero();
                rem.mul_add_small(1, r as u64);
                rem.normalize();
                n += 1;
                if !b.is_null() && bl > 1 {
                    // SAFETY: `b` is writable for `bl > 1` bytes.
                    unsafe {
                        *b = (b'0' + arc as u8) as c_char;
                        b = b.add(1);
                        *b = 0;
                    }
                    bl -= 1;
                }
                rem
            }
        } else {
            big
        };

        let dec = arc.to_decimal();
        let i = dec.len() as c_int;
        if !b.is_null() {
            if bl > 1 {
                // SAFETY: `b` is writable for `bl > 1` bytes.
                unsafe {
                    *b = b'.' as c_char;
                    b = b.add(1);
                    *b = 0;
                }
                bl -= 1;
            }
            if bl > 0 && !dec.is_empty() {
                let cap = bl as usize;
                let copied = dec.len().min(cap - 1);
                // SAFETY: `b` is writable for `bl` bytes; `dec` has `copied`.
                unsafe {
                    core::ptr::copy_nonoverlapping(dec.as_ptr() as *const c_char, b, copied);
                    *b.add(copied) = 0;
                }
            }
            if i > bl {
                // SAFETY: advancing within the caller's buffer.
                b = unsafe { b.add(bl.max(0) as usize) };
                bl = 0;
            } else {
                // SAFETY: advancing within the caller's buffer.
                b = unsafe { b.add(i as usize) };
                bl -= i;
            }
        }
        n += 1 + i;
    }
    n
}

// ---------------------------------------------------------------------------
// Exported surface
// ---------------------------------------------------------------------------

/// `int OBJ_new_nid(int num)`
///
/// Returns the old counter value and advances it by `num` (`fetch_add`
/// semantics, measured against the authority: first call returns `NUM_NID`).
#[no_mangle]
pub extern "C" fn OBJ_new_nid(num: c_int) -> c_int {
    guard_ffi(NID_undef, || NEXT_NID.fetch_add(num, Ordering::SeqCst))
}

/// `ASN1_OBJECT *OBJ_nid2obj(int n)`
///
/// Returns a pointer into the static table for a known NID, or into the
/// dynamic registry for a created one; NULL for an unknown NID or a table hole.
#[no_mangle]
pub extern "C" fn OBJ_nid2obj(n: c_int) -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), || {
        if n == NID_undef
            || (n > 0 && (n as usize) < NUM_NID && NID_OBJS[n as usize].nid != NID_undef)
        {
            return &NID_OBJS[n as usize] as *const Asn1Object as *mut Asn1Object;
        }
        match added_lookup_nid(n) {
            Some(p) => p,
            None => core::ptr::null_mut(),
        }
    })
}

/// `const char *OBJ_nid2sn(int n)` — NULL when there is no such NID.
#[no_mangle]
pub extern "C" fn OBJ_nid2sn(n: c_int) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        let ob = OBJ_nid2obj(n);
        if ob.is_null() {
            core::ptr::null()
        } else {
            // SAFETY: `ob` is a live object.
            unsafe { (*ob).sn }
        }
    })
}

/// `const char *OBJ_nid2ln(int n)` — NULL when there is no such NID.
#[no_mangle]
pub extern "C" fn OBJ_nid2ln(n: c_int) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        let ob = OBJ_nid2obj(n);
        if ob.is_null() {
            core::ptr::null()
        } else {
            // SAFETY: `ob` is a live object.
            unsafe { (*ob).ln }
        }
    })
}

/// `int OBJ_sn2nid(const char *s)` — `NID_undef` for an unknown name.
///
/// # Safety
/// `s` must be NULL or a valid NUL-terminated string. (The authority
/// dereferences NULL here; that UB is not reproduced.)
#[no_mangle]
pub unsafe extern "C" fn OBJ_sn2nid(s: *const c_char) -> c_int {
    guard_ffi(NID_undef, || {
        if s.is_null() {
            return NID_undef;
        }
        // SAFETY: `s` is NUL-terminated.
        let nid = unsafe { static_sn_to_nid(s) };
        if nid != NID_undef {
            return nid;
        }
        // SAFETY: `s` is NUL-terminated.
        unsafe { added_name_to_nid(s, false) }
    })
}

/// `int OBJ_ln2nid(const char *s)` — `NID_undef` for an unknown name.
///
/// # Safety
/// `s` must be NULL or a valid NUL-terminated string. (The authority
/// dereferences NULL here; that UB is not reproduced.)
#[no_mangle]
pub unsafe extern "C" fn OBJ_ln2nid(s: *const c_char) -> c_int {
    guard_ffi(NID_undef, || {
        if s.is_null() {
            return NID_undef;
        }
        // SAFETY: `s` is NUL-terminated.
        let nid = unsafe { static_ln_to_nid(s) };
        if nid != NID_undef {
            return nid;
        }
        // SAFETY: `s` is NUL-terminated.
        unsafe { added_name_to_nid(s, true) }
    })
}

/// `int OBJ_obj2nid(const ASN1_OBJECT *o)`
///
/// An object carrying a NID returns it directly; otherwise the OID content is
/// looked up in the static table and then the dynamic registry.
///
/// # Safety
/// `a` must be NULL or a valid pointer to an `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn OBJ_obj2nid(a: *const Asn1Object) -> c_int {
    guard_ffi(NID_undef, || {
        if a.is_null() {
            return NID_undef;
        }
        // SAFETY: `a` is a valid object pointer per the caller's contract.
        let o = unsafe { &*a };
        if o.nid != NID_undef {
            return o.nid;
        }
        if o.length == 0 || o.data.is_null() {
            return NID_undef;
        }
        // SAFETY: `o.data` is readable for `o.length` bytes.
        let nid = unsafe { static_data_to_nid(o.data, o.length as usize) };
        if nid != NID_undef {
            return nid;
        }
        // SAFETY: as above.
        unsafe { added_data_to_nid(o.data, o.length as usize) }
    })
}

/// `ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name)`
///
/// With names enabled, a known short or long name maps to the static object.
/// Otherwise the text is parsed as a dotted OID. A known OID yields the shared
/// static object; an unknown one yields a heap-allocated `DYNAMIC` object that
/// the caller owns.
///
/// # Safety
/// `s` must be NULL or a valid NUL-terminated string. (The authority
/// dereferences NULL here; that UB is not reproduced.)
#[no_mangle]
pub unsafe extern "C" fn OBJ_txt2obj(s: *const c_char, no_name: c_int) -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), || {
        if s.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `s` is NUL-terminated.
        let text = unsafe { core::slice::from_raw_parts(s as *const u8, c_strlen(s)) };

        if no_name == 0 {
            // SAFETY: `s` is NUL-terminated.
            let mut nid = unsafe { static_sn_to_nid(s) };
            if nid == NID_undef {
                // SAFETY: `s` is NUL-terminated.
                nid = unsafe { static_ln_to_nid(s) };
            }
            if nid == NID_undef {
                // SAFETY: `s` is NUL-terminated.
                nid = unsafe { added_name_to_nid(s, false) };
            }
            if nid == NID_undef {
                // SAFETY: `s` is NUL-terminated.
                nid = unsafe { added_name_to_nid(s, true) };
            }
            if nid != NID_undef {
                return OBJ_nid2obj(nid);
            }
            if !text.first().is_some_and(u8::is_ascii_digit) {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    crate::runtime::err::raise_site(&crate::runtime::err::err_sites::OBJ_DAT_362)
                };
                return core::ptr::null_mut();
            }
        }

        let content = match parse_oid_text(text) {
            OidParse::Ok(c) => c,
            OidParse::Raise(site) => {
                // SAFETY: the site is a compile-time constant.
                unsafe { crate::runtime::err::raise_site(site) };
                return core::ptr::null_mut();
            }
            OidParse::Silent => return core::ptr::null_mut(),
        };
        let known = content_to_nid(&content);
        if known != NID_undef {
            return OBJ_nid2obj(known);
        }
        alloc_oid_object(&content)
    })
}

/// `int OBJ_txt2nid(const char *s)` — `NID_undef` for unknown input.
///
/// # Safety
/// `s` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OBJ_txt2nid(s: *const c_char) -> c_int {
    guard_ffi(NID_undef, || {
        if s.is_null() {
            return NID_undef;
        }
        // SAFETY: `s` is NUL-terminated.
        let obj = unsafe { OBJ_txt2obj(s, 0) };
        if obj.is_null() {
            return NID_undef;
        }
        // SAFETY: `obj` is a live object.
        let nid = unsafe { OBJ_obj2nid(obj) };
        // The authority frees the temporary; a static object carries no DYNAMIC
        // bit, so this is a no-op for the shared case.
        // SAFETY: `obj` came from `OBJ_txt2obj` and is not used afterwards.
        unsafe { object_free(obj) };
        nid
    })
}

/// `int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)`
///
/// Returns the number of bytes that *would* be written, excluding the NUL. With
/// a named object and `no_name == 0`, the long name is preferred and the return
/// is `strlen(name)` regardless of truncation; with `no_name != 0`, or for an
/// unnamed object, the OID is rendered in dotted-decimal form. A NULL or
/// zero-length buffer computes the length without writing.
///
/// # Safety
/// `buf` must be NULL or writable for `buf_len` bytes; `a` must be NULL or a
/// valid object pointer.
#[no_mangle]
pub unsafe extern "C" fn OBJ_obj2txt(
    buf: *mut c_char,
    buf_len: c_int,
    a: *const Asn1Object,
    no_name: c_int,
) -> c_int {
    guard_ffi(0, || {
        if !buf.is_null() && buf_len > 0 {
            // SAFETY: `buf` is writable for `buf_len > 0` bytes.
            unsafe { *buf = 0 };
        }
        if a.is_null() {
            return 0;
        }
        // SAFETY: `a` is a valid object pointer.
        let o = unsafe { &*a };
        if o.data.is_null() {
            return 0;
        }

        if no_name == 0 {
            // SAFETY: `a` is a valid object pointer.
            let nid = unsafe { OBJ_obj2nid(a) };
            if nid != NID_undef {
                let mut s = OBJ_nid2ln(nid);
                if s.is_null() {
                    s = OBJ_nid2sn(nid);
                }
                if !s.is_null() {
                    // SAFETY: `buf` writable for `buf_len`; `s` static.
                    unsafe { strlcpy_cstr(buf, s, buf_len) };
                    // SAFETY: `s` is a static NUL-terminated name.
                    return unsafe { c_strlen(s) as c_int };
                }
            }
        }

        // SAFETY: `o.data` is readable for `o.length` bytes; `buf` is writable
        // for `max(buf_len, 0)` bytes.
        unsafe { obj2txt_numeric(buf, buf_len, o.data, o.length) }
    })
}

/// `int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b)`
///
/// Length first, then content bytes; two zero-length objects compare equal.
/// Unlike the authority, NULL sorts before non-NULL rather than being
/// dereferenced.
///
/// # Safety
/// `a` and `b` must be NULL or valid object pointers.
#[no_mangle]
pub unsafe extern "C" fn OBJ_cmp(a: *const Asn1Object, b: *const Asn1Object) -> c_int {
    guard_ffi(0, || {
        if a.is_null() && b.is_null() {
            return 0;
        }
        if a.is_null() {
            return -1;
        }
        if b.is_null() {
            return 1;
        }
        // SAFETY: both are valid object pointers.
        let (x, y) = unsafe { (&*a, &*b) };
        obj_cmp_parts(x.length, x.data, y.length, y.data)
    })
}

/// `ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *o)`
///
/// A static (non-dynamic) object is returned unchanged; a dynamic object is
/// deep-copied with a fresh allocation the caller owns.
///
/// # Safety
/// `o` must be NULL or a valid object pointer.
#[no_mangle]
pub unsafe extern "C" fn OBJ_dup(o: *const Asn1Object) -> *mut Asn1Object {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: forwarded to `dup_object`, which handles NULL.
        unsafe { object_dup(o) }
    })
}

/// `size_t OBJ_length(const ASN1_OBJECT *obj)` — 0 for NULL.
///
/// # Safety
/// `obj` must be NULL or a valid object pointer.
#[no_mangle]
pub unsafe extern "C" fn OBJ_length(obj: *const Asn1Object) -> usize {
    guard_ffi(0, || {
        if obj.is_null() {
            return 0;
        }
        // SAFETY: `obj` is a valid object pointer.
        unsafe { (*obj).length as usize }
    })
}

/// `const unsigned char *OBJ_get0_data(const ASN1_OBJECT *obj)` — NULL for NULL.
///
/// # Safety
/// `obj` must be NULL or a valid object pointer.
#[no_mangle]
pub unsafe extern "C" fn OBJ_get0_data(obj: *const Asn1Object) -> *const u8 {
    guard_ffi(core::ptr::null(), || {
        if obj.is_null() {
            return core::ptr::null();
        }
        // SAFETY: `obj` is a valid object pointer.
        unsafe { (*obj).data }
    })
}

/// `int OBJ_create(const char *oid, const char *sn, const char *ln)`
///
/// Registers a new object and returns its freshly allocated NID, or
/// `NID_undef` if the names or OID already exist (or all arguments are NULL).
///
/// # Safety
/// Each argument must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OBJ_create(
    oid: *const c_char,
    sn: *const c_char,
    ln: *const c_char,
) -> c_int {
    guard_ffi(NID_undef, || {
        if oid.is_null() && sn.is_null() && ln.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                crate::runtime::err::raise_site(&crate::runtime::err::err_sites::OBJ_DAT_706)
            };
            return NID_undef;
        }
        if !sn.is_null() {
            // SAFETY: `sn` is a NUL-terminated string.
            if unsafe { OBJ_sn2nid(sn) } != NID_undef {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    crate::runtime::err::raise_site(&crate::runtime::err::err_sites::OBJ_DAT_713)
                };
                return NID_undef;
            }
        }
        if !ln.is_null() {
            // SAFETY: `ln` is a NUL-terminated string.
            if unsafe { OBJ_ln2nid(ln) } != NID_undef {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    crate::runtime::err::raise_site(&crate::runtime::err::err_sites::OBJ_DAT_713)
                };
                return NID_undef;
            }
        }

        let data: Option<Vec<u8>> = if oid.is_null() {
            None
        } else {
            // SAFETY: `oid` is a NUL-terminated string.
            let text = unsafe { core::slice::from_raw_parts(oid as *const u8, c_strlen(oid)) };
            let content = match parse_oid_text(text) {
                OidParse::Ok(c) => c,
                OidParse::Raise(site) => {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { crate::runtime::err::raise_site(site) };
                    return NID_undef;
                }
                OidParse::Silent => return NID_undef,
            };
            if content_to_nid(&content) != NID_undef {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    crate::runtime::err::raise_site(&crate::runtime::err::err_sites::OBJ_DAT_734)
                };
                return NID_undef;
            }
            Some(content)
        };

        let nid = OBJ_new_nid(1);
        // SAFETY: `sn`/`ln` are NULL or NUL-terminated.
        unsafe { db_insert(nid, data.as_deref(), sn, ln) }
    })
}

/// `int OBJ_add_object(const ASN1_OBJECT *obj)`
///
/// Registers a caller-built object whose NID is already allocated, returning
/// that NID, or `NID_undef` on a collision or an out-of-range NID.
///
/// # Safety
/// `obj` must be NULL or a valid object pointer whose `data`/`sn`/`ln` fields
/// obey the usual C-string/OID-buffer rules.
#[no_mangle]
pub unsafe extern "C" fn OBJ_add_object(obj: *const Asn1Object) -> c_int {
    guard_ffi(NID_undef, || {
        if obj.is_null() {
            return NID_undef;
        }
        // SAFETY: `obj` is a valid object pointer.
        let o = unsafe { &*obj };
        if o.nid < NUM_NID as c_int {
            return NID_undef;
        }
        if !o.data.is_null() {
            if o.length <= 0 {
                // A zero-length, non-NULL data pointer matches the `undef`
                // entry in the authority's `obj_objs` table, which is a
                // conflict.
                return NID_undef;
            }
            // SAFETY: `o.data` is readable for `o.length` bytes.
            if unsafe { static_data_to_nid(o.data, o.length as usize) } != NID_undef {
                return NID_undef;
            }
        }
        if !o.sn.is_null() {
            // SAFETY: `o.sn` is NUL-terminated.
            if unsafe { static_sn_to_nid(o.sn) } != NID_undef {
                return NID_undef;
            }
        }
        if !o.ln.is_null() {
            // SAFETY: `o.ln` is NUL-terminated.
            if unsafe { static_ln_to_nid(o.ln) } != NID_undef {
                return NID_undef;
            }
        }

        let data: Option<Vec<u8>> = if !o.data.is_null() && o.length > 0 {
            // SAFETY: `o.data` is readable for `o.length` bytes.
            Some(unsafe { core::slice::from_raw_parts(o.data, o.length as usize) }.to_vec())
        } else {
            None
        };
        // SAFETY: `o.sn`/`o.ln` are NULL or NUL-terminated.
        unsafe { db_insert(o.nid, data.as_deref(), o.sn, o.ln) }
    })
}

/// `const void *OBJ_bsearch_(key, base, num, size, cmp)`
///
/// The authority's binary search over a sorted array, exposed because generated
/// code uses it. Returns NULL on a miss.
///
/// # Safety
/// `base` must point to `num` elements of `size` bytes; `cmp`, when present,
/// must be a valid comparator for those elements; `key` must be whatever `cmp`
/// expects.
#[no_mangle]
pub unsafe extern "C" fn OBJ_bsearch_(
    key: *const c_void,
    base: *const c_void,
    num: c_int,
    size: c_int,
    cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> *const c_void {
    // SAFETY: forwarded to the `_ex` entry point unchanged, with flags 0.
    unsafe { OBJ_bsearch_ex_(key, base, num, size, cmp, 0) }
}

/// `const void *OBJ_bsearch_ex_(key, base, num, size, cmp, flags)`
///
/// As [`OBJ_bsearch_`], honouring `OBJ_BSEARCH_VALUE_ON_NOMATCH` and
/// `OBJ_BSEARCH_FIRST_VALUE_ON_MATCH`.
///
/// # Safety
/// As [`OBJ_bsearch_`].
#[no_mangle]
pub unsafe extern "C" fn OBJ_bsearch_ex_(
    key: *const c_void,
    base: *const c_void,
    num: c_int,
    size: c_int,
    cmp: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
    flags: c_int,
) -> *const c_void {
    guard_ffi(core::ptr::null(), || {
        if num <= 0 || size <= 0 || base.is_null() {
            return core::ptr::null();
        }
        let Some(cmp) = cmp else {
            return core::ptr::null();
        };
        // SAFETY: `base` points to `num` elements of `size` bytes and `cmp` is
        // the caller's comparator, per this function's contract.
        unsafe {
            let base_ptr = base as *const u8;
            let elem = |i: usize| base_ptr.add(i * size as usize) as *const c_void;
            let mut l = 0i32;
            let mut h = num;
            let mut i = 0i32;
            let mut c = 0i32;
            while l < h {
                i = l + (h - l) / 2;
                c = cmp(key, elem(i as usize));
                if c < 0 {
                    h = i;
                } else if c > 0 {
                    l = i + 1;
                } else {
                    break;
                }
            }
            if c != 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH) == 0 {
                return core::ptr::null();
            }
            if c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH) != 0 {
                while i > 0 && cmp(key, elem((i - 1) as usize)) == 0 {
                    i -= 1;
                }
            }
            elem(i as usize)
        }
    })
}

// ---------------------------------------------------------------------------
// Signature-algorithm cross reference
// ---------------------------------------------------------------------------

/// One `nid_triple`: signature, digest and public-key NIDs.
#[derive(Clone, Copy)]
struct SigTriple {
    sign_id: c_int,
    hash_id: c_int,
    pkey_id: c_int,
}

static SIG_ADDED: Mutex<Vec<SigTriple>> = Mutex::new(Vec::new());

fn lock_sig() -> MutexGuard<'static, Vec<SigTriple>> {
    match SIG_ADDED.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// `OBJ_find_sigid_algs` against the static table.
fn static_sig_by_sign(signid: c_int) -> Option<SigTriple> {
    let idx = bsearch_index(SIGOID_SRT.len(), 0, |i| {
        signid.wrapping_sub(SIGOID_SRT[i].0)
    })?;
    let t = SIGOID_SRT[idx];
    Some(SigTriple {
        sign_id: t.0,
        hash_id: t.1,
        pkey_id: t.2,
    })
}

/// The authority's `sigx_cmp`, with the search key as `a` and the registered
/// element as `b`: a registered `NID_undef` digest accepts any digest.
fn sigx_cmp(dig: c_int, pkey: c_int, reg: SigTriple) -> c_int {
    let ret = dig.wrapping_sub(reg.hash_id);
    if ret != 0 && reg.hash_id != NID_undef {
        return ret;
    }
    pkey.wrapping_sub(reg.pkey_id)
}

/// `OBJ_find_sigid_by_algs` against the static table.
fn static_sig_by_algs(dig: c_int, pkey: c_int) -> Option<SigTriple> {
    let idx = bsearch_index(SIGOID_XREF.len(), 0, |i| {
        let t = SIGOID_SRT[SIGOID_XREF[i] as usize];
        let reg = SigTriple {
            sign_id: t.0,
            hash_id: t.1,
            pkey_id: t.2,
        };
        sigx_cmp(dig, pkey, reg)
    })?;
    let t = SIGOID_SRT[SIGOID_XREF[idx] as usize];
    Some(SigTriple {
        sign_id: t.0,
        hash_id: t.1,
        pkey_id: t.2,
    })
}

/// `int OBJ_find_sigid_algs(int signid, int *pdig_nid, int *ppkey_nid)`
///
/// Returns 1 and fills whichever outputs are non-NULL, or 0 for an unknown
/// signature NID.
///
/// # Safety
/// `pdig_nid`/`ppkey_nid` must be NULL or writable `int` pointers.
#[no_mangle]
pub unsafe extern "C" fn OBJ_find_sigid_algs(
    signid: c_int,
    pdig_nid: *mut c_int,
    ppkey_nid: *mut c_int,
) -> c_int {
    guard_ffi(0, || {
        if signid == NID_undef {
            return 0;
        }
        let found = static_sig_by_sign(signid)
            .or_else(|| lock_sig().iter().find(|t| t.sign_id == signid).copied());
        match found {
            Some(t) => {
                if !pdig_nid.is_null() {
                    // SAFETY: `pdig_nid` is writable per the contract.
                    unsafe { *pdig_nid = t.hash_id };
                }
                if !ppkey_nid.is_null() {
                    // SAFETY: `ppkey_nid` is writable per the contract.
                    unsafe { *ppkey_nid = t.pkey_id };
                }
                1
            }
            None => 0,
        }
    })
}

/// `int OBJ_find_sigid_by_algs(int *psignid, int dig_nid, int pkey_nid)`
///
/// Returns 1 and fills `*psignid` when a signature NID is found, else 0.
///
/// # Safety
/// `psignid` must be NULL or a writable `int` pointer.
#[no_mangle]
pub unsafe extern "C" fn OBJ_find_sigid_by_algs(
    psignid: *mut c_int,
    dig_nid: c_int,
    pkey_nid: c_int,
) -> c_int {
    guard_ffi(0, || {
        if pkey_nid == NID_undef {
            return 0;
        }
        let found = static_sig_by_algs(dig_nid, pkey_nid).or_else(|| {
            lock_sig()
                .iter()
                .find(|t| (t.hash_id == dig_nid || t.hash_id == NID_undef) && t.pkey_id == pkey_nid)
                .copied()
        });
        match found {
            Some(t) => {
                if !psignid.is_null() {
                    // SAFETY: `psignid` is writable per the contract.
                    unsafe { *psignid = t.sign_id };
                }
                1
            }
            None => 0,
        }
    })
}

/// `int OBJ_add_sigid(int signid, int dig_id, int pkey_id)`
///
/// Registers a signature-algorithm triple. Returns 1 when the triple is new or
/// already present unchanged, 0 on a conflict or invalid NID.
#[no_mangle]
pub extern "C" fn OBJ_add_sigid(signid: c_int, dig_id: c_int, pkey_id: c_int) -> c_int {
    guard_ffi(0, || {
        if signid == NID_undef || pkey_id == NID_undef {
            return 0;
        }
        let existing = static_sig_by_sign(signid)
            .or_else(|| lock_sig().iter().find(|t| t.sign_id == signid).copied());
        if let Some(t) = existing {
            return c_int::from(t.hash_id == dig_id && t.pkey_id == pkey_id);
        }
        lock_sig().push(SigTriple {
            sign_id: signid,
            hash_id: dig_id,
            pkey_id,
        });
        1
    })
}

/// `void OBJ_sigid_free(void)`
///
/// Drops the dynamic signature registry. Unlike the authority, the registry
/// remains usable afterwards (the authority frees its lock and then crashes on
/// the next lookup; that defect is not reproduced).
#[no_mangle]
pub extern "C" fn OBJ_sigid_free() {
    guard_ffi((), || {
        lock_sig().clear();
    })
}

// ---------------------------------------------------------------------------
// The OBJ_NAME registry
// ---------------------------------------------------------------------------

/// C-ABI projection of `struct obj_name_st`.
#[repr(C)]
pub struct ObjName {
    /// The name type (`OBJ_NAME_TYPE_*`), without the alias bit.
    pub type_: c_int,
    /// Non-zero for an alias entry.
    pub alias: c_int,
    /// The key string, borrowed from the caller.
    pub name: *const c_char,
    /// The value string, borrowed from the caller.
    pub data: *const c_char,
}

type ObjNameHashFn = unsafe extern "C" fn(*const c_char) -> c_ulong;
type ObjNameCmpFn = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type ObjNameFreeFn = unsafe extern "C" fn(*const c_char, c_int, *const c_char);
type ObjNameDoAllFn = unsafe extern "C" fn(*const ObjName, *mut c_void);

/// Per-type callbacks registered by [`OBJ_NAME_new_index`].
#[derive(Clone, Copy, Default)]
struct NameFuncs {
    hash: Option<ObjNameHashFn>,
    cmp: Option<ObjNameCmpFn>,
    free: Option<ObjNameFreeFn>,
}

/// A registered name. `name`/`data` are borrowed, as in the authority; the
/// caller keeps them alive for as long as the entry exists.
#[derive(Clone, Copy)]
struct NameRec {
    type_: c_int,
    alias: c_int,
    name: *const c_char,
    data: *const c_char,
}

// SAFETY: the raw pointers are borrowed caller strings, read-only through this
// registry; the registry itself is only reachable behind the `NAMES` mutex.
unsafe impl Send for NameRec {}
// SAFETY: as the `Send` impl above.
unsafe impl Sync for NameRec {}

struct NameDb {
    entries: Vec<NameRec>,
    funcs: Vec<NameFuncs>,
    type_num: c_int,
}

impl NameDb {
    const fn new() -> Self {
        NameDb {
            entries: Vec::new(),
            funcs: Vec::new(),
            type_num: OBJ_NAME_TYPE_NUM,
        }
    }
}

static NAMES: Mutex<NameDb> = Mutex::new(NameDb::new());

fn lock_names() -> MutexGuard<'static, NameDb> {
    match NAMES.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Call the registered destructor for a removed/replaced entry, if any.
fn call_name_free(funcs: &[NameFuncs], type_: c_int, name: *const c_char, data: *const c_char) {
    if type_ < 0 {
        return;
    }
    if let Some(f) = funcs.get(type_ as usize).and_then(|f| f.free) {
        // SAFETY: `f` is the caller-registered destructor for this type, and
        // `name`/`data` are exactly the pointers it was handed.
        unsafe { f(name, type_, data) };
    }
}

/// Compare a searched name against a stored one, honouring any custom
/// comparator and otherwise falling back to the case-insensitive default.
fn name_eq(funcs: &[NameFuncs], type_: c_int, a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    if type_ >= 0 {
        if let Some(f) = funcs.get(type_ as usize).and_then(|f| f.cmp) {
            // SAFETY: caller-registered comparator; both strings are its
            // documented inputs.
            return unsafe { f(a, b) } == 0;
        }
    }
    // SAFETY: both are NUL-terminated strings.
    unsafe { c_strcasecmp(a, b) == 0 }
}

fn name_find(db: &NameDb, type_: c_int, name: *const c_char) -> Option<usize> {
    db.entries
        .iter()
        .position(|e| e.type_ == type_ && name_eq(&db.funcs, type_, e.name, name))
}

/// `int OBJ_NAME_init(void)` — this registry is always available, so 1.
#[no_mangle]
pub extern "C" fn OBJ_NAME_init() -> c_int {
    guard_ffi(0, || 1)
}

/// `int OBJ_NAME_new_index(hash, cmp, free)`
///
/// Allocates the next name-type index (the first is `OBJ_NAME_TYPE_NUM`, 7) and
/// records optional per-type callbacks. Unspecified callbacks use the
/// case-insensitive defaults.
#[no_mangle]
pub extern "C" fn OBJ_NAME_new_index(
    hash_func: Option<ObjNameHashFn>,
    cmp_func: Option<ObjNameCmpFn>,
    free_func: Option<ObjNameFreeFn>,
) -> c_int {
    guard_ffi(0, || {
        let mut db = lock_names();
        let ret = db.type_num;
        db.type_num = db.type_num.saturating_add(1);
        while (db.funcs.len() as c_int) < db.type_num {
            db.funcs.push(NameFuncs::default());
        }
        if ret >= 0 {
            let slot = &mut db.funcs[ret as usize];
            if let Some(h) = hash_func {
                slot.hash = Some(h);
            }
            if let Some(c) = cmp_func {
                slot.cmp = Some(c);
            }
            if let Some(f) = free_func {
                slot.free = Some(f);
            }
        }
        ret
    })
}

/// `const char *OBJ_NAME_get(const char *name, int type)`
///
/// Follows alias chains (at most ten, as the authority does) and returns the
/// stored `data` pointer, or NULL.
///
/// # Safety
/// `name` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OBJ_NAME_get(name: *const c_char, type_: c_int) -> *const c_char {
    guard_ffi(core::ptr::null(), || {
        if name.is_null() {
            return core::ptr::null();
        }
        let alias = type_ & OBJ_NAME_ALIAS;
        let plain = type_ & !OBJ_NAME_ALIAS;
        let mut cur = name;
        let mut hops = 0;
        loop {
            let found = {
                let db = lock_names();
                name_find(&db, plain, cur).map(|i| db.entries[i])
            };
            let Some(rec) = found else {
                return core::ptr::null();
            };
            if rec.alias != 0 && alias == 0 {
                hops += 1;
                if hops > 10 {
                    return core::ptr::null();
                }
                cur = rec.data;
            } else {
                return rec.data;
            }
        }
    })
}

/// `int OBJ_NAME_add(const char *name, int type, const char *data)`
///
/// Inserts or replaces an entry. Returns 1 on success.
///
/// # Safety
/// `name` and `data` must be valid NUL-terminated strings, and must outlive the
/// entry (the authority also stores them borrowed).
#[no_mangle]
pub unsafe extern "C" fn OBJ_NAME_add(
    name: *const c_char,
    type_: c_int,
    data: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if name.is_null() {
            return 0;
        }
        let alias = type_ & OBJ_NAME_ALIAS;
        let plain = type_ & !OBJ_NAME_ALIAS;
        let mut db = lock_names();
        let funcs = db.funcs.clone();
        if let Some(i) = name_find(&db, plain, name) {
            let old = db.entries[i];
            call_name_free(&funcs, old.type_, old.name, old.data);
            db.entries[i] = NameRec {
                type_: plain,
                alias,
                name,
                data,
            };
        } else {
            db.entries.push(NameRec {
                type_: plain,
                alias,
                name,
                data,
            });
        }
        1
    })
}

/// `int OBJ_NAME_remove(const char *name, int type)`
///
/// Returns 1 if an entry was removed, else 0.
///
/// # Safety
/// `name` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OBJ_NAME_remove(name: *const c_char, type_: c_int) -> c_int {
    guard_ffi(0, || {
        if name.is_null() {
            return 0;
        }
        let plain = type_ & !OBJ_NAME_ALIAS;
        let mut db = lock_names();
        let funcs = db.funcs.clone();
        match name_find(&db, plain, name) {
            Some(i) => {
                let rec = db.entries.remove(i);
                call_name_free(&funcs, rec.type_, rec.name, rec.data);
                1
            }
            None => 0,
        }
    })
}

/// `void OBJ_NAME_do_all(int type, void (*fn)(const OBJ_NAME *, void *), void *arg)`
///
/// Iteration order is the registry's internal order, which — as in the
/// authority, whose order is that of an open-addressed hash table — is not part
/// of the contract.
///
/// # Safety
/// `fn`, when present, must be a valid callback for `ObjName`.
#[no_mangle]
pub unsafe extern "C" fn OBJ_NAME_do_all(
    type_: c_int,
    f: Option<ObjNameDoAllFn>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        let Some(f) = f else {
            return;
        };
        let list: Vec<NameRec> = {
            let db = lock_names();
            db.entries
                .iter()
                .filter(|e| e.type_ == type_)
                .copied()
                .collect()
        };
        for rec in list {
            let on = ObjName {
                type_: rec.type_,
                alias: rec.alias,
                name: rec.name,
                data: rec.data,
            };
            // SAFETY: `f` is the caller's callback for `ObjName`.
            unsafe { f(&on, arg) };
        }
    })
}

/// `void OBJ_NAME_do_all_sorted(int type, void (*fn)(const Obj_NAME *, void *), void *arg)`
///
/// As [`OBJ_NAME_do_all`], ordered by `strcmp` of the name (the authority's
/// `do_all_sorted` contract).
///
/// # Safety
/// `fn`, when present, must be a valid callback for `ObjName`.
#[no_mangle]
pub unsafe extern "C" fn OBJ_NAME_do_all_sorted(
    type_: c_int,
    f: Option<ObjNameDoAllFn>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        let Some(f) = f else {
            return;
        };
        let mut list: Vec<NameRec> = {
            let db = lock_names();
            db.entries
                .iter()
                .filter(|e| e.type_ == type_)
                .copied()
                .collect()
        };
        list.sort_by(|a, b| {
            // SAFETY: both names are NUL-terminated.
            unsafe { c_strcmp(a.name, b.name) }.cmp(&0)
        });
        for rec in list {
            let on = ObjName {
                type_: rec.type_,
                alias: rec.alias,
                name: rec.name,
                data: rec.data,
            };
            // SAFETY: `f` is the caller's callback for `ObjName`.
            unsafe { f(&on, arg) };
        }
    })
}

/// `void OBJ_NAME_cleanup(int type)`
///
/// Drops every entry of `type`, or every entry when `type < 0`. The registered
/// per-type callbacks are dropped only for `type < 0`, matching the authority's
/// reset of its function stack.
#[no_mangle]
pub extern "C" fn OBJ_NAME_cleanup(type_: c_int) {
    guard_ffi((), || {
        let mut db = lock_names();
        let funcs = db.funcs.clone();
        if type_ < 0 {
            let all: Vec<NameRec> = core::mem::take(&mut db.entries);
            for rec in all {
                call_name_free(&funcs, rec.type_, rec.name, rec.data);
            }
            db.funcs.clear();
        } else {
            let mut kept = Vec::new();
            for rec in db.entries.drain(..) {
                if rec.type_ == type_ {
                    call_name_free(&funcs, rec.type_, rec.name, rec.data);
                } else {
                    kept.push(rec);
                }
            }
            db.entries = kept;
        }
    })
}

// ---------------------------------------------------------------------------
// The description-stream helper
// ---------------------------------------------------------------------------

/// The ASCII character classes `OBJ_create_objects` uses.
///
/// The authority's `ossl_isalnum` is **not** the C library's: `crypto/ctype.c`
/// carries a 128-entry table and answers false for any byte outside seven-bit
/// ASCII. Using `isalnum` here would be locale-dependent and would accept bytes
/// the authority rejects, so the classes are computed directly.
fn is_ascii_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_ascii_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_ascii_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `int OBJ_create_objects(BIO *in)`
///
/// Reads one object description per line — `OID shortname longname`, with the
/// short and long names optional — until the stream ends or a line appears that
/// the parser rejects, and returns how many objects it created. A rejection is
/// **not** an error: the count is returned and nothing is raised, which is what
/// makes this usable on a file that carries trailing commentary.
///
/// The rejections are: a read of zero or fewer bytes; a first character that is
/// not alphanumeric; an empty OID field; and `OBJ_create` itself refusing (for
/// instance because the names already exist). Each ends the scan.
///
/// # Safety
/// `in_` must be NULL or a live BIO that supports `BIO_gets`.
#[no_mangle]
pub unsafe extern "C" fn OBJ_create_objects(in_: *mut super::bio::Bio) -> c_int {
    guard_ffi(0, || {
        let mut num = 0;
        let mut buf = [0 as c_char; 512];
        loop {
            // SAFETY: `in_` is NULL or live, and `buf` is writable for 512 bytes.
            let i = unsafe { super::bio::BIO_gets(in_, buf.as_mut_ptr(), 512) };
            if i <= 0 {
                return num;
            }
            // The authority overwrites the byte *before* the terminator with a
            // NUL, so a line without its newline loses its last character.
            buf[(i - 1) as usize] = 0;
            // SAFETY: `buf` is NUL-terminated by the line above.
            let bytes = unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
            if bytes.is_empty() || !is_ascii_alnum(bytes[0]) {
                return num;
            }
            // The OID field is the leading run of digits and dots.
            let mut k = 0usize;
            while k < bytes.len() && (is_ascii_digit(bytes[k]) || bytes[k] == b'.') {
                k += 1;
            }
            let (oid, rest) = bytes.split_at(k);
            if oid.is_empty() {
                return num;
            }
            // The remaining fields are whitespace-separated tokens.
            let mut fields = rest.split(|&b| is_ascii_space(b)).filter(|t| !t.is_empty());
            let short = fields.next();
            let long = fields.next();

            // SAFETY: each buffer is NUL-terminated before use, and NULL means
            // "not supplied" as in the authority.
            let mut oid_buf = [0 as c_char; 512];
            let mut sn_buf = [0 as c_char; 512];
            let mut ln_buf = [0 as c_char; 512];
            let copy_into = |dst: &mut [c_char; 512], src: &[u8]| {
                for (d, s) in dst.iter_mut().zip(src.iter()) {
                    *d = *s as c_char;
                }
            };
            copy_into(&mut oid_buf, oid);
            let sn_ptr = match short {
                Some(t) => {
                    copy_into(&mut sn_buf, t);
                    sn_buf.as_ptr()
                }
                None => core::ptr::null(),
            };
            let ln_ptr = match long {
                Some(t) => {
                    copy_into(&mut ln_buf, t);
                    ln_buf.as_ptr()
                }
                None => core::ptr::null(),
            };
            // SAFETY: the three pointers are NULL or NUL-terminated.
            let created = unsafe { OBJ_create(oid_buf.as_ptr(), sn_ptr, ln_ptr) };
            if created == NID_undef {
                return num;
            }
            num += 1;
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
// Test-side `unsafe` blocks are all direct calls to the API under test, with
// pointers to values this test owns and whose validity it just established. The
// invariant is identical in every case, so it is stated once here rather than
// repeated at each call site. Product code keeps the crate-wide denial.
#[allow(clippy::undocumented_unsafe_blocks)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Serialises tests that touch the process-wide dynamic registries and the
    /// NID counter. The static-table tests could run in parallel, but one lock
    /// keeps the reasoning trivial.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        match TEST_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Read a raw NUL-terminated name as a Rust string. Test-only convenience.
    fn name_to_string(p: *const c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: returned by the API as a NUL-terminated name.
        let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, c_strlen(p)) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    #[test]
    fn sn_and_ln_round_trip_over_a_sample() {
        let _g = lock();
        // NID_undef really is named, and its names are the literal words.
        assert_eq!(
            name_to_string(OBJ_nid2sn(NID_undef)).as_deref(),
            Some("UNDEF")
        );
        assert_eq!(
            name_to_string(OBJ_nid2ln(NID_undef)).as_deref(),
            Some("undefined")
        );
        // A spread across the table: the two above plus an early well-known NID, a
        // signature NID, a digest, and an algorithm added in a later generation.
        for &nid in &[
            NID_undef,
            1,
            NID_commonName,
            NID_rsaEncryption,
            NID_sha256,
            NID_ED25519,
        ] {
            let sn = OBJ_nid2sn(nid);
            assert!(!sn.is_null(), "nid {nid} must have a short name");
            let ln = OBJ_nid2ln(nid);
            assert!(!ln.is_null(), "nid {nid} must have a long name");
            // SAFETY: both names are NUL-terminated strings owned by the table.
            let (sn_round, ln_round) = unsafe { (OBJ_sn2nid(sn), OBJ_ln2nid(ln)) };
            assert_eq!(sn_round, nid, "sn round trip for {nid}");
            assert_eq!(ln_round, nid, "ln round trip for {nid}");
            // The object form must agree with the NID form.
            let obj = OBJ_nid2obj(nid);
            assert!(!obj.is_null(), "nid {nid} must have an object");
            // SAFETY: `obj` is a live object returned by the table.
            assert_eq!(unsafe { OBJ_obj2nid(obj) }, nid);
        }
        // A hole in the table and an out-of-range NID are unnamed, and the
        // negative index case is guarded rather than read out of bounds.
        assert!(OBJ_nid2sn(118).is_null());
        assert!(OBJ_nid2obj(118).is_null());
        assert!(OBJ_nid2sn(999_999).is_null());
        assert!(OBJ_nid2ln(-1).is_null());
    }

    #[test]
    fn unknown_names_and_case_are_nid_undef() {
        let _g = lock();
        for bad in ["", "no-such-name", "cn", "commonname"] {
            let c = std::ffi::CString::new(bad).expect("no interior NUL");
            // SAFETY: `c` is a live NUL-terminated string.
            assert_eq!(unsafe { OBJ_sn2nid(c.as_ptr()) }, NID_undef, "{bad:?}");
            // SAFETY: as above.
            assert_eq!(unsafe { OBJ_ln2nid(c.as_ptr()) }, NID_undef, "{bad:?}");
        }
        // The literal "NULL" really is the name of three static entries.
        let null = std::ffi::CString::new("NULL").expect("no interior NUL");
        // SAFETY: `null` is a live NUL-terminated string.
        assert_ne!(unsafe { OBJ_sn2nid(null.as_ptr()) }, NID_undef);
    }

    #[test]
    fn obj_and_nid_round_trip() {
        let _g = lock();
        for &nid in &[
            NID_undef,
            1,
            NID_commonName,
            NID_sha256WithRSAEncryption,
            1500,
        ] {
            let ob = OBJ_nid2obj(nid);
            assert!(!ob.is_null(), "nid {nid} should resolve");
            // SAFETY: `ob` is a live object.
            assert_eq!(unsafe { OBJ_obj2nid(ob) }, nid);
        }
        // The static object's OID is the DER content (no tag/length).
        let cn = OBJ_nid2obj(NID_commonName);
        // SAFETY: `cn` is a live object.
        let (len, data) = unsafe { (OBJ_length(cn), OBJ_get0_data(cn)) };
        assert_eq!(len, 3);
        // SAFETY: `data` is `len` bytes.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(data, len) },
            [0x55, 0x04, 0x03]
        );
    }

    #[test]
    fn txt2nid_understands_names_and_dotted_oids() {
        let _g = lock();
        let cases: &[(&str, c_int)] = &[
            ("CN", NID_commonName),
            ("commonName", NID_commonName),
            ("2.5.4.3", NID_commonName),
            ("1.2.840.113549.1.1.1", NID_rsaEncryption),
            ("bogus", NID_undef),
            ("1.2.3.4", NID_undef),
        ];
        for &(text, want) in cases {
            let c = std::ffi::CString::new(text).expect("no interior NUL");
            // SAFETY: `c` is a live NUL-terminated string.
            assert_eq!(unsafe { OBJ_txt2nid(c.as_ptr()) }, want, "{text}");
        }
    }

    #[test]
    fn obj2txt_returns_length_and_truncates() {
        let _g = lock();
        let cn = OBJ_nid2obj(NID_commonName);
        let mut buf = [b'X' as c_char; 16];
        // Named output prefers the long name and reports its full length.
        // SAFETY: buffer is live for its length; `cn` is a live object.
        let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 16, cn, 0) };
        assert_eq!(n, 10);
        assert_eq!(name_to_string(buf.as_ptr()).as_deref(), Some("commonName"));
        // no_name forces the dotted form.
        // SAFETY: as above.
        let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 16, cn, 1) };
        assert_eq!(n, 7);
        assert_eq!(name_to_string(buf.as_ptr()).as_deref(), Some("2.5.4.3"));
        // A NULL buffer counts without writing.
        // SAFETY: NULL buffer is explicitly supported.
        assert_eq!(unsafe { OBJ_obj2txt(core::ptr::null_mut(), 0, cn, 1) }, 7);
        // SAFETY: as above.
        assert_eq!(unsafe { OBJ_obj2txt(core::ptr::null_mut(), 5, cn, 1) }, 7);
        // Truncation is NUL-terminated and still reports the full length.
        // SAFETY: `buf` is live for 4 bytes.
        let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 4, cn, 1) };
        assert_eq!(n, 7);
        assert_eq!(name_to_string(buf.as_ptr()).as_deref(), Some("2.5"));
        // A NULL object and a no-data object both yield 0.
        // SAFETY: NULL object is supported.
        assert_eq!(
            unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 16, core::ptr::null(), 0) },
            0
        );
        // SAFETY: `undef` is a live object with NULL data.
        assert_eq!(
            unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 16, OBJ_nid2obj(0), 1) },
            0
        );
    }

    #[test]
    fn obj2txt_big_and_small_arcs_round_trip() {
        let _g = lock();
        let texts = [
            "2.100.3",
            "2.5.4.3",
            "0.9.2342.19200300.100.1.25",
            "1.2.840.113549.1.9.16.3.28",
            "1.3.6.1.4.1.1722.12.2.1.16",
            "1.2.3.18446744073709551615",
            "1.2.3.340282366920938463463374607431768211456",
        ];
        for &text in &texts {
            let c = std::ffi::CString::new(text).expect("no interior NUL");
            // SAFETY: `c` is a live NUL-terminated string.
            let ob = unsafe { OBJ_txt2obj(c.as_ptr(), 1) };
            assert!(!ob.is_null(), "parse {text}");
            let mut buf = [0 as c_char; 96];
            let n = {
                // SAFETY: `buf` live for 96; `ob` live.
                unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 96, ob, 1) }
            };
            let got = name_to_string(buf.as_ptr());
            assert_eq!(got.as_deref(), Some(text), "render {text}");
            assert_eq!(n as usize, text.len());
            // SAFETY: dynamic object allocated by `OBJ_txt2obj`; not used again.
            unsafe { object_free(ob) };
        }
    }

    #[test]
    fn cmp_orders_by_length_then_content() {
        let _g = lock();
        let cn = OBJ_nid2obj(NID_commonName);
        let c = OBJ_nid2obj(NID_countryName);
        // commonName is `55 04 03` and countryName is `55 04 06`: equal length,
        // and the comparison is over the DER bytes, so the difference shows up as
        // `0x03 - 0x06` at the first differing octet. (The old expectation of 0
        // here was wrong: `OBJ_cmp` does not stop at a common prefix.)
        // SAFETY: all pointers are live objects.
        unsafe {
            assert_eq!(OBJ_cmp(cn, cn), 0, "an object equals itself");
            assert_eq!(OBJ_cmp(cn, c), 0x03 - 0x06);
            assert_eq!(OBJ_cmp(c, cn), 0x06 - 0x03);
            assert_eq!(OBJ_cmp(cn, core::ptr::null()), 1);
            assert_eq!(OBJ_cmp(core::ptr::null(), cn), -1);
            assert_eq!(OBJ_cmp(core::ptr::null(), core::ptr::null()), 0);
        }
    }

    #[test]
    fn dup_of_static_object_is_the_same_pointer() {
        let _g = lock();
        let cn = OBJ_nid2obj(NID_commonName);
        // SAFETY: `cn` is a live, non-dynamic object.
        assert_eq!(unsafe { OBJ_dup(cn) }, cn);
    }

    #[test]
    fn create_and_new_nid_register_dynamic_objects() {
        let _g = lock();
        // `OBJ_new_nid` returns the old counter value and advances it.
        let a = OBJ_new_nid(1);
        let b = OBJ_new_nid(1);
        assert_eq!(b, a + 1);
        assert!(a >= NUM_NID as c_int);

        let oid = std::ffi::CString::new("1.3.6.1.4.1.99999.1.1").unwrap();
        let sn = std::ffi::CString::new("zedtest-sn").unwrap();
        let ln = std::ffi::CString::new("zed test long name").unwrap();
        // SAFETY: all three are live NUL-terminated strings.
        let nid = unsafe { OBJ_create(oid.as_ptr(), sn.as_ptr(), ln.as_ptr()) };
        assert!(nid >= NUM_NID as c_int, "create returned {nid}");

        // The names, the numeric rendering and the raw OID all resolve to it.
        // SAFETY: live NUL-terminated strings.
        assert_eq!(unsafe { OBJ_sn2nid(sn.as_ptr()) }, nid);
        // SAFETY: as above.
        assert_eq!(unsafe { OBJ_ln2nid(ln.as_ptr()) }, nid);
        // SAFETY: as above.
        assert_eq!(unsafe { OBJ_txt2nid(oid.as_ptr()) }, nid);
        let ob = OBJ_nid2obj(nid);
        assert!(!ob.is_null());
        // SAFETY: `ob` is a live object.
        assert_eq!(unsafe { OBJ_obj2nid(ob) }, nid);
        let mut buf = [0 as c_char; 64];
        // SAFETY: `buf` live; `ob` live.
        let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 64, ob, 0) };
        assert_eq!(
            name_to_string(buf.as_ptr()).as_deref(),
            Some("zed test long name")
        );
        assert_eq!(n, 18);

        // Re-using a name or an OID is rejected.
        let sn2 = std::ffi::CString::new("zedtest-sn").unwrap();
        let oid2 = std::ffi::CString::new("1.3.6.1.4.1.99999.1.2").unwrap();
        let ln3 = std::ffi::CString::new("another long name").unwrap();
        // SAFETY: live strings.
        assert_eq!(
            unsafe { OBJ_create(oid2.as_ptr(), sn2.as_ptr(), ln3.as_ptr()) },
            NID_undef
        );
        let oid3 = std::ffi::CString::new("1.3.6.1.4.1.99999.1.1").unwrap();
        let sn4 = std::ffi::CString::new("fresh-sn").unwrap();
        // SAFETY: live strings.
        assert_eq!(
            unsafe { OBJ_create(oid3.as_ptr(), sn4.as_ptr(), core::ptr::null()) },
            NID_undef
        );

        // A create with no OID and no names is rejected outright.
        // SAFETY: all-NULL is explicitly handled.
        assert_eq!(
            unsafe { OBJ_create(core::ptr::null(), core::ptr::null(), core::ptr::null()) },
            NID_undef
        );

        // A name-only object has NULL data and length 0, so `OBJ_obj2txt`
        // returns 0 for it (the data check precedes the name lookup) — exactly
        // as the authority behaves.
        let sn5 = std::ffi::CString::new("zedtest-nameonly").unwrap();
        let ln5 = std::ffi::CString::new("zed name only").unwrap();
        // SAFETY: live strings.
        let nid5 = unsafe { OBJ_create(core::ptr::null(), sn5.as_ptr(), ln5.as_ptr()) };
        assert!(nid5 >= NUM_NID as c_int);
        let ob5 = OBJ_nid2obj(nid5);
        // SAFETY: `ob5` is live.
        assert_eq!(unsafe { OBJ_length(ob5) }, 0);
        // SAFETY: `buf` live; `ob5` live.
        assert_eq!(unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 64, ob5, 0) }, 0);
    }

    #[test]
    fn sigid_lookup_and_registration() {
        let _g = lock();
        let mut dig = -1;
        let mut pkey = -1;
        // SAFETY: out-pointers are live.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(NID_sha256WithRSAEncryption, &mut dig, &mut pkey) },
            1
        );
        assert_eq!(dig, NID_sha256);
        assert_eq!(pkey, NID_rsaEncryption);
        // SAFETY: out-pointer is live.
        let mut sign = -1;
        assert_eq!(
            unsafe { OBJ_find_sigid_by_algs(&mut sign, NID_sha256, NID_rsaEncryption) },
            1
        );
        assert_eq!(sign, NID_sha256WithRSAEncryption);
        // A "no digest" signature reports `NID_undef` for the digest.
        // SAFETY: out-pointers are live.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(NID_ED25519, &mut dig, &mut pkey) },
            1
        );
        assert_eq!(dig, NID_undef);
        assert_eq!(pkey, NID_ED25519);
        // Unknown signature, or a zero NID, is a miss.
        // SAFETY: out-pointers are live.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(999_999, &mut dig, &mut pkey) },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(NID_undef, &mut dig, &mut pkey) },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe {
                OBJ_find_sigid_algs(NID_ED25519, core::ptr::null_mut(), core::ptr::null_mut())
            },
            1
        );

        // A fresh triple registers, queries, and exact duplicates are accepted.
        assert_eq!(OBJ_add_sigid(20001, NID_sha256, NID_rsaEncryption), 1);
        assert_eq!(OBJ_add_sigid(20001, NID_sha256, NID_rsaEncryption), 1);
        assert_eq!(OBJ_add_sigid(20001, NID_sha1, NID_rsaEncryption), 0);
        assert_eq!(OBJ_add_sigid(NID_undef, NID_sha256, NID_rsaEncryption), 0);
        assert_eq!(OBJ_add_sigid(20002, NID_sha256, NID_undef), 0);
        // SAFETY: out-pointers are live.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(20001, &mut dig, &mut pkey) },
            1
        );
        assert_eq!(dig, NID_sha256);
        assert_eq!(pkey, NID_rsaEncryption);

        OBJ_sigid_free();
        // SAFETY: out-pointers are live.
        assert_eq!(
            unsafe { OBJ_find_sigid_algs(20001, &mut dig, &mut pkey) },
            0
        );
        // The registry stays usable (the authority does not survive this).
        assert_eq!(OBJ_add_sigid(20003, NID_sha256, NID_rsaEncryption), 1);
    }

    #[test]
    fn obj_name_registry_add_get_remove() {
        let _g = lock();
        assert_eq!(OBJ_NAME_init(), 1);
        let name = std::ffi::CString::new("zedtest-digest").unwrap();
        let data = std::ffi::CString::new("zedtest-data").unwrap();
        let name2 = std::ffi::CString::new("zedtest-digest2").unwrap();
        // SAFETY: live NUL-terminated strings; entries are borrowed for the
        // duration of the test.
        unsafe {
            assert_eq!(OBJ_NAME_add(name.as_ptr(), 0x01, data.as_ptr()), 1);
            // Lookup is case-insensitive by default.
            assert_eq!(OBJ_NAME_get(name.as_ptr(), 0x01), data.as_ptr());
            let upper = std::ffi::CString::new("ZEDTEST-DIGEST").unwrap();
            assert_eq!(OBJ_NAME_get(upper.as_ptr(), 0x01), data.as_ptr());
            // A different type does not match.
            assert!(OBJ_NAME_get(name.as_ptr(), 0x02).is_null());
            assert_eq!(OBJ_NAME_remove(name.as_ptr(), 0x01), 1);
            assert_eq!(OBJ_NAME_remove(name.as_ptr(), 0x01), 0);
            assert!(OBJ_NAME_get(name.as_ptr(), 0x01).is_null());

            // A fresh dynamic name type index starts at OBJ_NAME_TYPE_NUM.
            let idx = OBJ_NAME_new_index(None, None, None);
            assert!(idx >= 0x07);
            assert_eq!(OBJ_NAME_add(name2.as_ptr(), idx, data.as_ptr()), 1);
            assert_eq!(OBJ_NAME_get(name2.as_ptr(), idx), data.as_ptr());
            OBJ_NAME_cleanup(idx);
            assert!(OBJ_NAME_get(name2.as_ptr(), idx).is_null());
        }
    }

    #[test]
    fn obj_name_do_all_reports_entries() {
        let _g = lock();
        unsafe extern "C" fn count_cb(_name: *const ObjName, arg: *mut c_void) {
            // SAFETY: `arg` is the `&mut usize` passed below.
            let counter = unsafe { &mut *(arg as *mut usize) };
            *counter += 1;
        }
        let name = std::ffi::CString::new("zedtest-doall").unwrap();
        let data = std::ffi::CString::new("zedtest-doall-data").unwrap();
        let idx = OBJ_NAME_new_index(None, None, None);
        // SAFETY: live strings and a valid callback.
        unsafe {
            assert_eq!(OBJ_NAME_add(name.as_ptr(), idx, data.as_ptr()), 1);
            let mut count = 0usize;
            OBJ_NAME_do_all(idx, Some(count_cb), &mut count as *mut usize as *mut c_void);
            assert_eq!(count, 1);
            let mut count_sorted = 0usize;
            OBJ_NAME_do_all_sorted(
                idx,
                Some(count_cb),
                &mut count_sorted as *mut usize as *mut c_void,
            );
            assert_eq!(count_sorted, 1);
            OBJ_NAME_cleanup(idx);
        }
    }

    #[test]
    fn bsearch_reproduces_the_authority_algorithm() {
        extern "C" fn int_cmp(a: *const c_void, b: *const c_void) -> c_int {
            // SAFETY: the caller passes `int` arrays.
            let (x, y) = unsafe { (*(a as *const c_int), *(b as *const c_int)) };
            (x > y) as c_int - (x < y) as c_int
        }

        let arr: [c_int; 5] = [10, 20, 30, 40, 50];
        let mut key: c_int = 30;
        // SAFETY: `key` is live; `arr` has 5 `int` elements; `int_cmp` is valid.
        let p = unsafe {
            OBJ_bsearch_(
                &key as *const c_int as *const c_void,
                arr.as_ptr() as *const c_void,
                5,
                core::mem::size_of::<c_int>() as c_int,
                Some(int_cmp),
            )
        };
        assert_eq!(p as *const c_int, arr.as_ptr().wrapping_add(2));
        key = 25;
        // SAFETY: as above.
        let miss = unsafe {
            OBJ_bsearch_(
                &key as *const c_int as *const c_void,
                arr.as_ptr() as *const c_void,
                5,
                core::mem::size_of::<c_int>() as c_int,
                Some(int_cmp),
            )
        };
        assert!(miss.is_null());

        let dup: [c_int; 6] = [10, 20, 20, 20, 40, 50];
        key = 20;
        // SAFETY: as above.
        let first = unsafe {
            OBJ_bsearch_ex_(
                &key as *const c_int as *const c_void,
                dup.as_ptr() as *const c_void,
                6,
                core::mem::size_of::<c_int>() as c_int,
                Some(int_cmp),
                OBJ_BSEARCH_FIRST_VALUE_ON_MATCH,
            )
        };
        assert_eq!(first as *const c_int, dup.as_ptr().wrapping_add(1));
        key = 25;
        // SAFETY: as above.
        let nomatch = unsafe {
            OBJ_bsearch_ex_(
                &key as *const c_int as *const c_void,
                dup.as_ptr() as *const c_void,
                6,
                core::mem::size_of::<c_int>() as c_int,
                Some(int_cmp),
                OBJ_BSEARCH_VALUE_ON_NOMATCH,
            )
        };
        assert!(!nomatch.is_null());
    }

    #[test]
    fn null_pointer_guards_return_documented_failures() {
        let _g = lock();
        // SAFETY: NULL is explicitly accepted by these entry points.
        unsafe {
            assert_eq!(OBJ_sn2nid(core::ptr::null()), NID_undef);
            assert_eq!(OBJ_ln2nid(core::ptr::null()), NID_undef);
            assert_eq!(OBJ_obj2nid(core::ptr::null()), NID_undef);
            assert_eq!(OBJ_txt2nid(core::ptr::null()), NID_undef);
            assert!(OBJ_txt2obj(core::ptr::null(), 0).is_null());
            assert!(OBJ_dup(core::ptr::null()).is_null());
            assert_eq!(OBJ_length(core::ptr::null()), 0);
            assert!(OBJ_get0_data(core::ptr::null()).is_null());
            assert_eq!(OBJ_cmp(core::ptr::null(), core::ptr::null()), 0);
            assert_eq!(OBJ_add_object(core::ptr::null()), NID_undef);
        }
    }
}
