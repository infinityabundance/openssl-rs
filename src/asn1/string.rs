//! Phase 5 — `ASN1_STRING` and the fifteen types that are one.
//!
//! Every ASN.1 string type in this profile is a `typedef` of `ASN1_STRING`, and
//! the authority implements them with one macro whose two generated functions are
//! `T *T_new(void) { return ASN1_STRING_type_new(V_##T); }` and
//! `void T_free(T *x) { ASN1_STRING_free(x); }`. So the *only* difference between
//! `ASN1_IA5STRING_new()` and `ASN1_UTF8STRING_new()` is the `type` field of the
//! block they return — which makes the whole family checkable with one property,
//! and makes the exceptions the interesting part.
//!
//! The exceptions:
//!
//! * `ASN1_PRINTABLE_new`, `DIRECTORYSTRING_new` and `DISPLAYTEXT_new` are
//!   **MSTRING** items. Their constructor goes through `ASN1_item_new`, which for
//!   a MSTRING gives the string `type == V_ASN1_UNDEF` and sets
//!   `ASN1_STRING_FLAG_MSTRING`.
//! * `ASN1_NULL_new()` does **not** allocate: it answers the sentinel `1`. That
//!   lives in [`super::item`], because it is the item machinery's behaviour.
//!
//! `data` is allocated with `CRYPTO_malloc`/`CRYPTO_realloc` and released with
//! `CRYPTO_free`, because a program that installs allocation hooks must see these.
//! `ASN1_STRING_set` allocates `length + 1` bytes and writes a NUL at
//! `data[length]` — one byte past the content, which is the authority's "safety
//! precaution" and is observable to a hook.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_realloc, CRYPTO_zalloc};

/// The authority translation unit for the string primitives.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/asn1_lib.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// An owned seam block: an `ASN1_STRING` object or its `data` buffer. Both are allocated through the
/// crate's allocator seam and released with a plain `CRYPTO_free` at this module's own
/// `FILE`/`LINE`, so a caller-installed `CRYPTO_set_mem_functions` hook observes the allocation and
/// its release exactly as it observes the authority's.
///
/// Only the *ownership* is this type: [`Self::new`] and [`Self::new_zeroed`] allocate, [`Self::take`]
/// reclaims a block (or a NULL pointer, which `CRYPTO_realloc`/`CRYPTO_free` treat as empty) for
/// release, [`Self::resize`] is the authority's `CRYPTO_realloc`, [`Self::into_raw`] hands a block to
/// the C caller that owns it, and `Drop` is a held block's single release.
struct OwnedBlock {
    ptr: *mut c_uchar,
}

impl OwnedBlock {
    /// A fresh block of `len` bytes through the installed allocator, or `None` when it answers NULL.
    fn new(len: usize) -> Option<OwnedBlock> {
        let ptr = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(len, FILE.as_ptr(), LINE)
        }
        .cast::<c_uchar>();
        if ptr.is_null() {
            None
        } else {
            Some(OwnedBlock { ptr })
        }
    }

    /// A fresh, zeroed block of `len` bytes through the installed allocator, or `None` when it
    /// answers NULL.
    fn new_zeroed(len: usize) -> Option<OwnedBlock> {
        let ptr = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_zalloc(len, FILE.as_ptr(), LINE)
        }
        .cast::<c_uchar>();
        if ptr.is_null() {
            None
        } else {
            Some(OwnedBlock { ptr })
        }
    }

    /// Reclaim the block `ptr` names (`NULL` included) for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live block the crate's allocator seam produced in full (not a sub-range)
    /// and this caller owns exclusively -- the returned handle's `Drop` is its single release.
    unsafe fn take(ptr: *mut c_uchar) -> OwnedBlock {
        OwnedBlock { ptr }
    }

    /// `CRYPTO_realloc(self.ptr, len, FILE, LINE)`: on success the block is the new one and `true` is
    /// answered; on failure the original is unchanged and `false` is answered.
    fn resize(&mut self, len: usize) -> bool {
        // SAFETY: `self.ptr` is this handle's block (or NULL, which `CRYPTO_realloc` treats as an
        // allocation) and no one else owns it while the handle holds it.
        let new = unsafe { CRYPTO_realloc(self.ptr.cast::<c_void>(), len, FILE.as_ptr(), LINE) };
        if new.is_null() {
            return false;
        }
        self.ptr = new.cast::<c_uchar>();
        true
    }

    /// The writable start of the block.
    fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Give up ownership of the block to a consumer that takes it over.
    fn into_raw(self) -> *mut c_uchar {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBlock {
    /// The block's single release, through the same seam.
    fn drop(&mut self) {
        #[cfg(test)]
        crate::runtime::release_probe::record(
            crate::runtime::release_probe::Arm::Plain,
            FILE.as_ptr(),
            LINE,
        );
        // SAFETY: `self.ptr` is the block this handle owns and has not released; the authority's own
        // `CRYPTO_free` accepts NULL.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), FILE.as_ptr(), LINE) };
    }
}

#[cfg(test)]
mod release_family_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::runtime::release_probe::{self, Arm};

    /// D1-style drift guard: this family's release is the plain `CRYPTO_free` at the
    /// module's own `FILE`/`LINE` constants.
    #[test]
    fn release_is_plain_at_the_module_coordinates() {
        release_probe::clear();
        let block = OwnedBlock::new(4).expect("4 bytes allocate");
        drop(block);
        let call = release_probe::take().expect("the release was recorded");
        assert_eq!(call.arm, Arm::Plain);
        assert_eq!(call.file, FILE.as_ptr());
        assert_eq!(call.line, LINE);
    }
}

/// Read a `*const Asn1String` as a reference.
///
/// # Safety
///
/// `p` must be null or point to a live `ASN1_STRING` not mutated for the lifetime
/// of the borrow.
pub(crate) unsafe fn as_str<'a>(p: *const Asn1String) -> Option<&'a Asn1String> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live.
        Some(unsafe { &*p })
    }
}

/// Read a `*mut Asn1String` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `ASN1_STRING`.
pub(crate) unsafe fn as_str_mut<'a>(p: *mut Asn1String) -> Option<&'a mut Asn1String> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// The content octets of a string as a slice, empty for null or empty.
///
/// # Safety
///
/// `p` must be null or a live `ASN1_STRING` whose `data` holds `length` readable
/// bytes.
pub(crate) unsafe fn bytes<'a>(p: *const Asn1String) -> &'a [u8] {
    // SAFETY: the caller's contract covers `p`.
    match unsafe { as_str(p) } {
        None => &[],
        Some(s) => {
            if s.data.is_null() || s.length <= 0 {
                &[]
            } else {
                // SAFETY: the caller guarantees `data` holds `length` bytes.
                unsafe { core::slice::from_raw_parts(s.data, s.length as usize) }
            }
        }
    }
}

/// `ASN1_STRING_type_new` — a fresh string of a given type.
pub(crate) fn string_type_new(type_: c_int) -> *mut Asn1String {
    let Some(block) = OwnedBlock::new_zeroed(core::mem::size_of::<Asn1String>()) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `block` holds `size_of::<ASN1_STRING>()` zeroed bytes, a fresh valid `ASN1_STRING`;
    // the field write is the constructor's own.
    unsafe { (*block.as_ptr().cast::<Asn1String>()).type_ = type_ };
    block.into_raw().cast::<Asn1String>()
}

/// `ossl_asn1_string_embed_free`.
///
/// # Safety
///
/// `a` must be null or a live `ASN1_STRING` allocated the way this module
/// allocates, or an embedded one when `embed` is non-zero.
pub(crate) unsafe fn string_embed_free(a: *mut Asn1String, embed: c_int) {
    if a.is_null() {
        return;
    }
    // SAFETY: `a` is live.
    let (flags, data) = unsafe { ((*a).flags, (*a).data) };
    if flags & ASN1_STRING_FLAG_NDEF == 0 {
        // SAFETY: `data` came from this allocator or is null and this frame owns it exclusively.
        drop(unsafe { OwnedBlock::take(data) });
    }
    if embed == 0 {
        // SAFETY: `a` was allocated by `string_type_new`/the item machinery through this allocator
        // and this frame owns it exclusively.
        drop(unsafe { OwnedBlock::take(a.cast::<c_uchar>()) });
    }
}

/// The body of `ASN1_STRING_set`.
///
/// # Safety
///
/// `str_` must be a live, uniquely-owned `ASN1_STRING`. When `data` is non-null it
/// must be readable for `len` bytes, and when `len_in` is negative it must be a
/// NUL-terminated string.
pub(crate) unsafe fn string_set_body(
    str_: *mut Asn1String,
    data: *const u8,
    len_in: c_int,
) -> c_int {
    // SAFETY: the caller guarantees `str_` is live and uniquely owned.
    let Some(s) = (unsafe { as_str_mut(str_) }) else {
        return 0;
    };
    let len: usize = if len_in < 0 {
        if data.is_null() {
            return 0;
        }
        // SAFETY: the caller promises `data` is NUL-terminated.
        unsafe { core::ffi::CStr::from_ptr(data.cast::<c_char>()) }
            .to_bytes()
            .len()
    } else {
        len_in as usize
    };
    if len > (c_int::MAX - 1) as usize {
        // SAFETY: the raise is at the authority's own coordinate.
        unsafe { raise_site(&err_sites::ASN1_LIB_305) };
        return 0;
    }
    if s.length < 0 || (s.length as usize) <= len || s.data.is_null() {
        // SAFETY: `s.data` came from this allocator (or is null) and this frame owns it; taking it
        // makes the owner below its single release while the resize runs.
        let mut data = unsafe { OwnedBlock::take(s.data) };
        if !data.resize(len + 1) {
            // The authority restores the original pointer so the string stays valid.
            s.data = data.into_raw();
            return 0;
        }
        s.data = data.into_raw();
    }
    s.length = len as c_int;
    if !data.is_null() {
        // SAFETY: `s.data` owns `len + 1` bytes and `data` is readable for `len`.
        unsafe {
            core::ptr::copy_nonoverlapping(data, s.data, len);
            *s.data.add(len) = 0;
        }
    }
    1
}

/// `ASN1_STRING *ASN1_STRING_new(void)`
#[no_mangle]
pub extern "C" fn ASN1_STRING_new() -> *mut Asn1String {
    string_type_new(V_ASN1_OCTET_STRING)
}

/// `ASN1_STRING *ASN1_STRING_type_new(int type)`
#[no_mangle]
pub extern "C" fn ASN1_STRING_type_new(type_: c_int) -> *mut Asn1String {
    string_type_new(type_)
}

/// `void ASN1_STRING_free(ASN1_STRING *a)`
///
/// # Safety
///
/// `a` must be null or a live `ASN1_STRING`. An embedded string must not be passed:
/// the authority would free the parent's storage.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_free(a: *mut Asn1String) {
    guard_ffi((), || {
        if a.is_null() {
            return;
        }
        // SAFETY: the caller guarantees `a` is live.
        let embed = unsafe { (*a).flags } & ASN1_STRING_FLAG_EMBED;
        // SAFETY: as above.
        unsafe { string_embed_free(a, embed as c_int) };
    });
}

/// `void ASN1_STRING_clear_free(ASN1_STRING *a)`
///
/// # Safety
///
/// As [`ASN1_STRING_free`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_clear_free(a: *mut Asn1String) {
    guard_ffi((), || {
        if a.is_null() {
            return;
        }
        // SAFETY: the caller guarantees `a` is live.
        let (data, length, flags) = unsafe { ((*a).data, (*a).length, (*a).flags) };
        if !data.is_null() && flags & ASN1_STRING_FLAG_NDEF == 0 {
            // SAFETY: `data` holds `length` bytes.
            unsafe {
                crate::runtime::mem::OPENSSL_cleanse(data.cast::<c_void>(), length.max(0) as usize)
            };
        }
        // SAFETY: as above.
        unsafe { ASN1_STRING_free(a) };
    });
}

/// `int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str)`
///
/// # Safety
///
/// `dst` must be a live, uniquely-owned `ASN1_STRING`; `str_` null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_copy(dst: *mut Asn1String, str_: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        if str_.is_null() || dst.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees both are live, `dst` uniquely owned.
        let (type_, data, length, flags) =
            unsafe { ((*str_).type_, (*str_).data, (*str_).length, (*str_).flags) };
        // SAFETY: as above.
        if unsafe { string_set_body(dst, data, length) } == 0 {
            return 0;
        }
        // SAFETY: `dst` is live; the authority preserves the embed bit and copies
        // every other flag.
        unsafe {
            (*dst).flags &= ASN1_STRING_FLAG_EMBED;
            (*dst).flags |= flags & !ASN1_STRING_FLAG_EMBED;
            (*dst).type_ = type_;
        }
        1
    })
}

/// `ASN1_STRING *ASN1_STRING_dup(const ASN1_STRING *str)`
///
/// # Safety
///
/// `str_` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_dup(str_: *const Asn1String) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        if str_.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller guarantees `str_` is live.
        let type_ = unsafe { (*str_).type_ };
        let ret = string_type_new(type_);
        if ret.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `ret` is fresh and `str_` is live.
        if unsafe { ASN1_STRING_copy(ret, str_) } == 0 {
            // SAFETY: `ret` is ours.
            unsafe { string_embed_free(ret, 0) };
            return core::ptr::null_mut();
        }
        ret
    })
}

/// `int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b)`
///
/// # Safety
///
/// `a` and `b` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_cmp(a: *const Asn1String, b: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees both are null or live.
        let (al, bl) = unsafe { (as_str(a), as_str(b)) };
        let (alen, blen) = (al.map_or(0, |s| s.length), bl.map_or(0, |s| s.length));
        let diff = alen.wrapping_sub(blen);
        if diff != 0 {
            return diff;
        }
        if alen != 0 {
            // SAFETY: both hold `alen` readable bytes.
            let ab = unsafe { bytes(a) };
            // SAFETY: as above.
            let bb = unsafe { bytes(b) };
            match ab.cmp(bb) {
                core::cmp::Ordering::Equal => {}
                core::cmp::Ordering::Less => return -1,
                core::cmp::Ordering::Greater => return 1,
            }
        }
        al.map_or(0, |s| s.type_) - bl.map_or(0, |s| s.type_)
    })
}

/// `int ASN1_STRING_length(const ASN1_STRING *x)`
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_length(x: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `x` is live.
        unsafe { as_str(x) }.map_or(0, |s| s.length)
    })
}

/// `void ASN1_STRING_length_set(ASN1_STRING *x, int len)`
///
/// # Safety
///
/// `x` must be a live, uniquely-owned `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_length_set(x: *mut Asn1String, len: c_int) {
    guard_ffi((), || {
        // SAFETY: the caller guarantees `x` is live and uniquely owned.
        if let Some(s) = unsafe { as_str_mut(x) } {
            s.length = len;
        }
    });
}

/// `int ASN1_STRING_type(const ASN1_STRING *x)`
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_type(x: *const Asn1String) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `x` is live.
        unsafe { as_str(x) }.map_or(0, |s| s.type_)
    })
}

/// `const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)`
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_get0_data(x: *const Asn1String) -> *const c_uchar {
    guard_ffi(core::ptr::null(), || {
        // SAFETY: the caller guarantees `x` is live.
        unsafe { as_str(x) }.map_or(core::ptr::null(), |s| s.data)
    })
}

/// `unsigned char *ASN1_STRING_data(ASN1_STRING *x)`
///
/// # Safety
///
/// `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_data(x: *mut Asn1String) -> *mut c_uchar {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: the caller guarantees `x` is live.
        unsafe { as_str_mut(x) }.map_or(core::ptr::null_mut(), |s| s.data)
    })
}

/// `int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len)`
///
/// # Safety
///
/// `str` must be a live, uniquely-owned `ASN1_STRING`. A null `data` with a
/// non-negative `len` is accepted and only sizes the buffer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_set(
    str_: *mut Asn1String,
    data: *const c_void,
    len_in: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is `string_set_body`'s.
        unsafe { string_set_body(str_, data.cast::<u8>(), len_in) }
    })
}

/// `void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len)`
///
/// # Safety
///
/// `str` must be a live, uniquely-owned `ASN1_STRING`; `data` becomes owned by it
/// and must have been allocated compatibly.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_set0(str_: *mut Asn1String, data: *mut c_void, len: c_int) {
    guard_ffi((), || {
        // SAFETY: the caller guarantees `str_` is live and uniquely owned.
        if let Some(s) = unsafe { as_str_mut(str_) } {
            // SAFETY: `s.data` came from this allocator or is null and this frame owns it
            // exclusively.
            drop(unsafe { OwnedBlock::take(s.data) });
            s.data = data.cast::<c_uchar>();
            s.length = len;
        }
    });
}

/// The `T_new`/`T_free` pair the authority generates for every plain string type.
///
/// Both names are written out at each use, because a macro cannot build an
/// identifier and a `#[no_mangle]` symbol from one token; the macro exists so the
/// *shape* is stated once.
macro_rules! define_new_free {
    ($new:ident, $free:ident, $doc:expr, $docfree:expr, $V:expr) => {
        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $new() -> *mut Asn1String {
            string_type_new($V)
        }

        #[doc = $docfree]
        ///
        /// # Safety
        ///
        /// `x` must be null or a live string owned by the caller.
        #[no_mangle]
        pub unsafe extern "C" fn $free(x: *mut Asn1String) {
            // SAFETY: the caller's contract is `ASN1_STRING_free`'s.
            unsafe { ASN1_STRING_free(x) };
        }
    };
}

define_new_free!(
    ASN1_OCTET_STRING_new,
    ASN1_OCTET_STRING_free,
    "`ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void)`",
    "`void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *x)`",
    V_ASN1_OCTET_STRING
);
define_new_free!(
    ASN1_INTEGER_new,
    ASN1_INTEGER_free,
    "`ASN1_INTEGER *ASN1_INTEGER_new(void)`",
    "`void ASN1_INTEGER_free(ASN1_INTEGER *x)`",
    V_ASN1_INTEGER
);
define_new_free!(
    ASN1_ENUMERATED_new,
    ASN1_ENUMERATED_free,
    "`ASN1_ENUMERATED *ASN1_ENUMERATED_new(void)`",
    "`void ASN1_ENUMERATED_free(ASN1_ENUMERATED *x)`",
    V_ASN1_ENUMERATED
);
define_new_free!(
    ASN1_BIT_STRING_new,
    ASN1_BIT_STRING_free,
    "`ASN1_BIT_STRING *ASN1_BIT_STRING_new(void)`",
    "`void ASN1_BIT_STRING_free(ASN1_BIT_STRING *x)`",
    V_ASN1_BIT_STRING
);
define_new_free!(
    ASN1_UTF8STRING_new,
    ASN1_UTF8STRING_free,
    "`ASN1_UTF8STRING *ASN1_UTF8STRING_new(void)`",
    "`void ASN1_UTF8STRING_free(ASN1_UTF8STRING *x)`",
    V_ASN1_UTF8STRING
);
define_new_free!(
    ASN1_PRINTABLESTRING_new,
    ASN1_PRINTABLESTRING_free,
    "`ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void)`",
    "`void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *x)`",
    V_ASN1_PRINTABLESTRING
);
define_new_free!(
    ASN1_T61STRING_new,
    ASN1_T61STRING_free,
    "`ASN1_T61STRING *ASN1_T61STRING_new(void)`",
    "`void ASN1_T61STRING_free(ASN1_T61STRING *x)`",
    V_ASN1_T61STRING
);
define_new_free!(
    ASN1_IA5STRING_new,
    ASN1_IA5STRING_free,
    "`ASN1_IA5STRING *ASN1_IA5STRING_new(void)`",
    "`void ASN1_IA5STRING_free(ASN1_IA5STRING *x)`",
    V_ASN1_IA5STRING
);
define_new_free!(
    ASN1_GENERALSTRING_new,
    ASN1_GENERALSTRING_free,
    "`ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void)`",
    "`void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *x)`",
    V_ASN1_GENERALSTRING
);
define_new_free!(
    ASN1_UTCTIME_new,
    ASN1_UTCTIME_free,
    "`ASN1_UTCTIME *ASN1_UTCTIME_new(void)`",
    "`void ASN1_UTCTIME_free(ASN1_UTCTIME *x)`",
    V_ASN1_UTCTIME
);
define_new_free!(
    ASN1_GENERALIZEDTIME_new,
    ASN1_GENERALIZEDTIME_free,
    "`ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void)`",
    "`void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *x)`",
    V_ASN1_GENERALIZEDTIME
);
define_new_free!(
    ASN1_VISIBLESTRING_new,
    ASN1_VISIBLESTRING_free,
    "`ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void)`",
    "`void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *x)`",
    V_ASN1_VISIBLESTRING
);
define_new_free!(
    ASN1_UNIVERSALSTRING_new,
    ASN1_UNIVERSALSTRING_free,
    "`ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void)`",
    "`void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *x)`",
    V_ASN1_UNIVERSALSTRING
);
define_new_free!(
    ASN1_BMPSTRING_new,
    ASN1_BMPSTRING_free,
    "`ASN1_BMPSTRING *ASN1_BMPSTRING_new(void)`",
    "`void ASN1_BMPSTRING_free(ASN1_BMPSTRING *x)`",
    V_ASN1_BMPSTRING
);

/// The three **MSTRING** constructors, which are not plain strings.
///
/// `IMPLEMENT_ASN1_MSTRING(T, mask)` makes `T_it` an `ASN1_ITYPE_MSTRING` item and
/// `IMPLEMENT_ASN1_FUNCTIONS_name(ASN1_STRING, T)` makes `T_new`/`T_free` go
/// through `ASN1_item_new`/`ASN1_item_free` with it. For a MSTRING item
/// `asn1_primitive_new` takes the `utype = -1` branch — the type has to be
/// discovered from the encoding — and then sets `ASN1_STRING_FLAG_MSTRING`.
///
/// The result is a string whose `type` is `V_ASN1_UNDEF` and whose `flags` carry
/// `MSTRING`, built here directly rather than through the item machinery: the round
/// trip through `ASN1_item_new` produces exactly this and nothing else.
macro_rules! define_mstring {
    ($new:ident, $free:ident, $doc:expr, $docfree:expr) => {
        #[doc = $doc]
        #[no_mangle]
        pub extern "C" fn $new() -> *mut Asn1String {
            let s = string_type_new(V_ASN1_UNDEF);
            if !s.is_null() {
                // SAFETY: `s` is fresh and non-null.
                unsafe { (*s).flags |= ASN1_STRING_FLAG_MSTRING };
            }
            s
        }

        #[doc = $docfree]
        ///
        /// # Safety
        ///
        /// `x` must be null or a live string owned by the caller.
        #[no_mangle]
        pub unsafe extern "C" fn $free(x: *mut Asn1String) {
            // SAFETY: the caller's contract is `ASN1_STRING_free`'s.
            unsafe { ASN1_STRING_free(x) };
        }
    };
}

define_mstring!(
    ASN1_PRINTABLE_new,
    ASN1_PRINTABLE_free,
    "`ASN1_STRING *ASN1_PRINTABLE_new(void)`",
    "`void ASN1_PRINTABLE_free(ASN1_STRING *x)`"
);
define_mstring!(
    DIRECTORYSTRING_new,
    DIRECTORYSTRING_free,
    "`ASN1_STRING *DIRECTORYSTRING_new(void)`",
    "`void DIRECTORYSTRING_free(ASN1_STRING *x)`"
);
define_mstring!(
    DISPLAYTEXT_new,
    DISPLAYTEXT_free,
    "`ASN1_STRING *DISPLAYTEXT_new(void)`",
    "`void DISPLAYTEXT_free(ASN1_STRING *x)`"
);
// `ASN1_TIME` is the fourth MSTRING, from `a_time.c` rather than `tasn_typ.c`. Its
// `ASN1_ITYPE_MSTRING` item is declared in `crate::asn1::items`, and the constructor
// it generates is the same `utype == -1` branch as the three above — the `B_ASN1_TIME`
// mask is the item's, not the constructor's.
define_mstring!(
    ASN1_TIME_new,
    ASN1_TIME_free,
    "`ASN1_TIME *ASN1_TIME_new(void)`",
    "`void ASN1_TIME_free(ASN1_TIME *x)`"
);

/// `int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a, const ASN1_OCTET_STRING
/// *b)`
///
/// # Safety
///
/// `a` and `b` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_OCTET_STRING_cmp(
    a: *const Asn1String,
    b: *const Asn1String,
) -> c_int {
    // SAFETY: the caller's contract is `ASN1_STRING_cmp`'s.
    unsafe { ASN1_STRING_cmp(a, b) }
}

/// `int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
/// int len)`
///
/// # Safety
///
/// `str` must be a live, uniquely-owned `ASN1_OCTET_STRING`; `data` readable for
/// `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_OCTET_STRING_set(
    str_: *mut Asn1String,
    data: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: the caller's contract is `ASN1_STRING_set`'s.
    unsafe { ASN1_STRING_set(str_, data.cast(), len) }
}

/// `ASN1_OCTET_STRING *ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a)`
///
/// # Safety
///
/// `a` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn ASN1_OCTET_STRING_dup(a: *const Asn1String) -> *mut Asn1String {
    // SAFETY: the caller's contract is `ASN1_STRING_dup`'s.
    unsafe { ASN1_STRING_dup(a) }
}

/// `long` is named by the time accessors that share this module's string type.
#[allow(dead_code)]
pub(crate) type Long = c_long;

/// `char *ossl_sk_ASN1_UTF8STRING2text(STACK_OF(ASN1_UTF8STRING) *text, const char *sep,
/// size_t max_len)` — `crypto/asn1/asn1_lib.c:435-473`.
///
/// Withheld by name in 10.10 because its only authority callers were unlanded; the CMP client
/// engine is a caller, so it lands here. `max_len == 0` means no restriction; a joined length
/// above `max_len` is the covered refusal. The result is a `CRYPTO_malloc`ed C string the caller
/// owns.
///
/// # Safety
/// `text` is NULL or a live stack of live `ASN1_UTF8STRING`s; `sep` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn ossl_sk_ASN1_UTF8STRING2text(
    text: *mut crate::runtime::stack::OpenSslStack,
    sep: *const c_char,
    max_len: usize,
) -> *mut c_char {
    use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

    let sep_len = if sep.is_null() {
        0
    } else {
        // SAFETY: `sep` is NUL-terminated per the contract.
        unsafe { c_strlen(sep) }
    };
    // SAFETY: `text` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(text) };
    let mut length: usize = 0;
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range of the live stack.
        let current = unsafe { OPENSSL_sk_value(text, i) }.cast::<Asn1String>();
        if i > 0 {
            let Some(next) = length.checked_add(sep_len) else {
                return ptr::null_mut();
            };
            length = next;
        }
        // SAFETY: `current` is a live element of the stack.
        let Ok(cur_len) = usize::try_from(unsafe { ASN1_STRING_length(current) }) else {
            return ptr::null_mut();
        };
        let Some(next) = length.checked_add(cur_len) else {
            return ptr::null_mut();
        };
        length = next;
        if max_len != 0 && length > max_len {
            return ptr::null_mut();
        }
        i += 1;
    }
    // `CRYPTO_malloc(length + 1)`, line 456; the caller owns the block `Drop` would otherwise free.
    let Some(alloc_len) = length.checked_add(1) else {
        return ptr::null_mut();
    };
    let Some(result) = OwnedBlock::new(alloc_len) else {
        return ptr::null_mut();
    };

    let mut p = result.as_ptr().cast::<c_char>();
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range of the live stack.
        let current = unsafe { OPENSSL_sk_value(text, i) }.cast::<Asn1String>();
        // SAFETY: `current` is live.
        let Ok(len) = usize::try_from(unsafe { ASN1_STRING_length(current) }) else {
            return ptr::null_mut();
        };
        if i > 0 && sep_len > 0 {
            // SAFETY: `p` has room for `sep_len + 1` bytes and `sep` is readable for `sep_len`.
            unsafe { ptr::copy_nonoverlapping(sep, p, sep_len + 1) };
            // SAFETY: the copy wrote through `p`, still within the allocation.
            p = unsafe { p.add(sep_len) };
        }
        // SAFETY: `current` is live and `p` has room for `len` bytes.
        unsafe {
            ptr::copy_nonoverlapping(ASN1_STRING_get0_data(current), p.cast::<c_uchar>(), len)
        };
        // SAFETY: still within the allocation.
        p = unsafe { p.add(len) };
        i += 1;
    }
    // SAFETY: `p` is within the allocation and NUL is the terminator the authority writes.
    unsafe { *p = 0 };

    result.into_raw().cast::<c_char>()
}

/// `strlen` — a NUL-terminated C string's length.
///
/// # Safety
/// `s` is NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract.
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A negative `length` is a legal value of the exported setter, but it is not a
    /// capacity. `string_set_body` must reallocate rather than treat it as a very
    /// large buffer extent.
    #[test]
    fn a_negative_length_forces_the_set_to_reallocate() {
        // SAFETY: `s` is this frame's fresh live string; every pointer is a live local
        // buffer of the stated length and every release is this frame's own.
        unsafe {
            let s = ASN1_STRING_new();
            assert!(!s.is_null());
            assert_eq!(ASN1_STRING_set(s, b"abcdef".as_ptr().cast(), 6), 1);
            ASN1_STRING_length_set(s, -1);
            assert_eq!(ASN1_STRING_set(s, b"0123456789".as_ptr().cast(), 10), 1);
            assert_eq!(bytes(s), b"0123456789");
            ASN1_STRING_free(s);
        }
    }
}
