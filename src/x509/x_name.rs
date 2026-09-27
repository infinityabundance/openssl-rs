//! `crypto/x509/x_name.c` — the `X509_NAME` object, transcribed as far as 10.8's object core
//! reaches. Phase 10.8.
//!
//! `crypto/x509/x_name.c` is 552 lines. **The item and its whole code, as far as the object core
//! uses it, lands**: the `X509_NAME_ENTRY` and `X509_NAME` structures, both item descriptors and
//! the two template wrappers between them, the `X509_NAME` `ASN1_ITYPE_EXTERN` hooks that
//! implement the authority's "internal form then cached external form" design, the four generated
//! lifecycles, and `X509_NAME_get0_der`/`X509_NAME_set`. **One function is withheld**:
//!
//! * `X509_NAME_print` (`:502-539`) reaches `X509_NAME_oneline` (`crypto/x509/x509_obj.c`), which
//!   is not landed, and the `asn1_ex_print` hook that would call `X509_NAME_print_ex` with it is
//!   withheld with it. The extern block's `asn1_ex_print` slot is therefore **NULL**. Nothing in
//!   10.8's closure prints a name.
//!
//! ## Why the name is not a plain `ASN1_SEQUENCE`
//!
//! `X509_NAME` is a `SEQUENCE OF SET OF AttributeTypeAndValue`, but the authority stores it
//! flattened and caches **two encodings** beside it: the bytes it arrived with (`bytes`, used to
//! re-emit a name unchanged) and a canonical form (`canon_enc`, used for fast comparison). So the
//! item is an `ASN1_ITYPE_EXTERN` whose `d2i` hook decodes the internal nested-stack form and
//! then converts, and whose `i2d` hook re-encodes only when the name was modified. That structure
//! is transcribed whole, exactly as `crypto/x509/x_pubkey.c`'s extern item is in
//! `src/x509/x_pubkey.rs`.
//!
//! ## The layout
//!
//! `struct X509_name_st` and `struct X509_name_entry_st` are declared in `include/crypto/x509.h`
//! (not a public header). `courts/layout/measure-x509.c` prints the sizes and offsets the asserts
//! below carry: the entry is `object`, `value`, `set`, `size`; the name is `entries`, `modified`,
//! `bytes`, `canon_enc`, `canon_enclen`. `X509_CINF` embeds two `X509_NAME *`, and the `X509`
//! struct's offset 0 is its `X509_CINF`, so these numbers move everything in `src/x509/x_x509.rs`.
//!
//! ## The raise sites
//!
//! The landed functions raise, so `crypto/x509/x_name.c` **is** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES` (stem `X509_NAME`): `ERR_LIB_ASN1` with
//! `ERR_R_CRYPTO_LIB`/`ERR_R_BUF_LIB`/`ERR_R_NESTED_ASN1_ERROR` and `ERR_LIB_X509` with
//! `ERR_R_CRYPTO_LIB`/`ERR_R_ASN1_LIB`/`ERR_R_OBJ_LIB`. The generated table also carries the one
//! site in the withheld `X509_NAME_print`; an unused coordinate is harmless and is not evidence
//! that the function landed.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.8 arms decode a certificate from the authority's own DER and read
//! `i2d_X509_NAME` off its issuer and subject; the item-level round trip is the test module below.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_strex::ASN1_STRING_to_UTF8;
use crate::asn1::d2i::{ASN1_item_d2i, ASN1_item_ex_d2i};
use crate::asn1::der::ASN1_tag2bit;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::{ASN1_item_ex_i2d, ASN1_item_i2d};
use crate::asn1::items::{ASN1_OBJECT_it, ASN1_PRINTABLE_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::ASN1_STRING_copy;
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new, BufMem};
use crate::runtime::ctype::{ossl_isascii, ossl_isspace, ossl_tolower};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_set, OPENSSL_sk_value, OpenSslStack,
};

/// The `X509_NAME_MAX` bound `x509_name_ex_d2i` clamps a decode to (`:24`).
const X509_NAME_MAX: c_long = 1024 * 1024;

/// `ASN1_MASK_CANON` (`:388-391`) — the string types `asn1_string_canon` normalises rather than
/// copies.
const ASN1_MASK_CANON: c_ulong = B_ASN1_UTF8STRING
    | B_ASN1_BMPSTRING
    | B_ASN1_UNIVERSALSTRING
    | B_ASN1_PRINTABLESTRING
    | B_ASN1_T61STRING
    | B_ASN1_IA5STRING
    | B_ASN1_VISIBLESTRING;

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_zalloc`/`OPENSSL_malloc`/`OPENSSL_free`
/// macro expansions, and the lines each expands at.
const FILE: &core::ffi::CStr = c"crypto/x509/x_name.c";
/// `x509_name_ex_new`'s `OPENSSL_zalloc(sizeof(*ret))` (`:92`).
const LINE_ZALLOC_EX_NEW: c_int = 92;
/// `x509_name_ex_new`'s two `OPENSSL_free(ret)` sites (`:111`).
const LINE_FREE_EX_NEW: c_int = 111;
/// `x509_name_ex_free`'s `OPENSSL_free(a->canon_enc)` (`:126`).
const LINE_FREE_CANON_ENC_FREE: c_int = 126;
/// `x509_name_ex_free`'s `OPENSSL_free(a)` (`:127`).
const LINE_FREE_NAME: c_int = 127;
/// `x509_name_canon`'s `OPENSSL_free(a->canon_enc)` (`:319`).
const LINE_FREE_CANON_ENC_CANON: c_int = 319;
/// `x509_name_canon`'s `OPENSSL_malloc(a->canon_enclen)` (`:369`).
const LINE_CANON_MALLOC: c_int = 369;

/// `struct X509_name_entry_st` — `X509_NAME_ENTRY`, from `include/crypto/x509.h:31-36`.
#[repr(C)]
pub struct X509NameEntry {
    /// `ASN1_OBJECT *object` — the attribute type.
    pub(crate) object: *mut Asn1Object,
    /// `ASN1_STRING *value` — the attribute value; an `ASN1_PRINTABLE` (a MSTRING).
    pub(crate) value: *mut Asn1String,
    /// `int set` — index of the RDN sequence this entry belongs to.
    pub(crate) set: c_int,
    /// `int size` — a scratch field.
    pub(crate) size: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<X509NameEntry>() == 24);
    assert!(core::mem::offset_of!(X509NameEntry, object) == 0);
    assert!(core::mem::offset_of!(X509NameEntry, value) == 8);
    assert!(core::mem::offset_of!(X509NameEntry, set) == 16);
    assert!(core::mem::offset_of!(X509NameEntry, size) == 20);
};

/// `struct X509_name_st` — `X509_NAME`, from `include/crypto/x509.h:39-46`.
#[repr(C)]
pub struct X509Name {
    /// `STACK_OF(X509_NAME_ENTRY) *entries` — the DN components, always non-NULL.
    pub(crate) entries: *mut OpenSslStack,
    /// `int modified` — true when `bytes` needs to be rebuilt.
    pub(crate) modified: c_int,
    /// `BUF_MEM *bytes` — the cached encoding; cannot be NULL.
    pub(crate) bytes: *mut BufMem,
    /// `unsigned char *canon_enc` — the canonical encoding used for fast comparison.
    pub(crate) canon_enc: *mut c_uchar,
    /// `int canon_enclen` — the length of `canon_enc`.
    pub(crate) canon_enclen: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<X509Name>() == 40);
    assert!(core::mem::offset_of!(X509Name, entries) == 0);
    assert!(core::mem::offset_of!(X509Name, modified) == 8);
    assert!(core::mem::offset_of!(X509Name, bytes) == 16);
    assert!(core::mem::offset_of!(X509Name, canon_enc) == 24);
    assert!(core::mem::offset_of!(X509Name, canon_enclen) == 32);
};

// ---------------------------------------------------------------------------------------------
// The `X509_NAME_ENTRY` item — `ASN1_SEQUENCE(X509_NAME_ENTRY)` (`:46-49`)
// ---------------------------------------------------------------------------------------------

/// `X509_NAME_ENTRY_seq_tt` — `ASN1_SEQUENCE(X509_NAME_ENTRY)`:
/// `ASN1_SIMPLE(X509_NAME_ENTRY, object, ASN1_OBJECT)` and
/// `ASN1_SIMPLE(X509_NAME_ENTRY, value, ASN1_PRINTABLE)`.
static X509_NAME_ENTRY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"object".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value".as_ptr(),
        item: ASN1_PRINTABLE_it as *mut c_void,
    },
];

/// `X509_NAME_ENTRY_it`'s descriptor — `ASN1_SEQUENCE_END(X509_NAME_ENTRY)` at
/// `crypto/x509/x_name.c:49`.
static X509_NAME_ENTRY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_NAME_ENTRY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509NameEntry>() as c_long,
    sname: c"X509_NAME_ENTRY".as_ptr(),
};

/// `const ASN1_ITEM *X509_NAME_ENTRY_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_NAME_ENTRY)`.
#[no_mangle]
pub extern "C" fn X509_NAME_ENTRY_it() -> *const Asn1Item {
    &X509_NAME_ENTRY_ITEM
}

/// `X509_NAME_ENTRY *X509_NAME_ENTRY_new(void)` — `crypto/x509/x_name.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_NAME_ENTRY)`.
#[no_mangle]
pub extern "C" fn X509_NAME_ENTRY_new() -> *mut X509NameEntry {
    // SAFETY: `X509_NAME_ENTRY_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_NAME_ENTRY_it()).cast::<X509NameEntry>() }
}

/// `void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_free(a: *mut X509NameEntry) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_NAME_ENTRY_it()) }
}

/// `X509_NAME_ENTRY *X509_NAME_ENTRY_dup(const X509_NAME_ENTRY *a)` —
/// `IMPLEMENT_ASN1_DUP_FUNCTION(X509_NAME_ENTRY)` (`:52`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_dup(a: *const X509NameEntry) -> *mut X509NameEntry {
    // SAFETY: `a` is NULL or live per the contract; `X509_NAME_ENTRY_it()` is a static item.
    unsafe { ASN1_item_dup(X509_NAME_ENTRY_it(), a.cast()).cast::<X509NameEntry>() }
}

/// `X509_NAME_ENTRY *d2i_X509_NAME_ENTRY(X509_NAME_ENTRY **a, const unsigned char **in,
/// long len)` — `crypto/x509/x_name.c:51`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_NAME_ENTRY(
    a: *mut *mut X509NameEntry,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509NameEntry {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_NAME_ENTRY_it()).cast::<X509NameEntry>() }
}

/// `int i2d_X509_NAME_ENTRY(const X509_NAME_ENTRY *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_NAME_ENTRY(
    a: *const X509NameEntry,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_NAME_ENTRY_it()) }
}

// ---------------------------------------------------------------------------------------------
// The two wrapper templates — `ASN1_ITEM_TEMPLATE(X509_NAME_ENTRIES/X509_NAME_INTERNAL)` (`:59-64`)
// ---------------------------------------------------------------------------------------------

/// `X509_NAME_ENTRIES_item_tt` — `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, RDNS,
/// X509_NAME_ENTRY)` (`:59`).
static X509_NAME_ENTRIES_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SET_OF,
    tag: 0,
    offset: 0,
    field_name: c"RDNS".as_ptr(),
    item: X509_NAME_ENTRY_it as *mut c_void,
};

/// `X509_NAME_ENTRIES`'s descriptor — `static_ASN1_ITEM_TEMPLATE_END(X509_NAME_ENTRIES)` (`:60`).
static X509_NAME_ENTRIES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &X509_NAME_ENTRIES_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"X509_NAME_ENTRIES".as_ptr(),
};

/// `ASN1_ITEM_rptr(X509_NAME_ENTRIES)` — the address of the wrapper's item.
fn x509_name_entries_item() -> *const Asn1Item {
    &X509_NAME_ENTRIES_ITEM
}

/// `X509_NAME_INTERNAL_item_tt` — `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Name,
/// X509_NAME_ENTRIES)` (`:62-63`).
static X509_NAME_INTERNAL_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"Name".as_ptr(),
    item: x509_name_entries_item as *mut c_void,
};

/// `X509_NAME_INTERNAL`'s descriptor — `static_ASN1_ITEM_TEMPLATE_END(X509_NAME_INTERNAL)` (`:64`).
static X509_NAME_INTERNAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &X509_NAME_INTERNAL_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"X509_NAME_INTERNAL".as_ptr(),
};

/// `ASN1_ITEM_rptr(X509_NAME_INTERNAL)` — `:169`, `:269`, `:276`, `:481`.
fn x509_name_internal_item() -> *const Asn1Item {
    &X509_NAME_INTERNAL_ITEM
}

// ---------------------------------------------------------------------------------------------
// The `X509_NAME` extern item — `IMPLEMENT_EXTERN_ASN1(X509_NAME, ...)` (`:84`)
// ---------------------------------------------------------------------------------------------

/// The destructor `sk_X509_NAME_ENTRY_pop_free` passes to `OPENSSL_sk_pop_free` — the authority
/// spells it `X509_NAME_ENTRY_free`.
///
/// # Safety
/// `elem` must be NULL or an `X509_NAME_ENTRY` this crate allocated.
unsafe extern "C" fn free_name_entry(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or an `X509_NAME_ENTRY`, and `X509_NAME_ENTRY_free` accepts NULL.
    unsafe { X509_NAME_ENTRY_free(elem.cast::<X509NameEntry>()) };
}

/// `local_sk_X509_NAME_ENTRY_free` (`:131-134`) — free an inner stack **without** its elements.
///
/// # Safety
/// `ne` must be NULL or a live stack of `X509_NAME_ENTRY`.
unsafe extern "C" fn local_sk_name_entry_free(ne: *mut OpenSslStack) {
    // SAFETY: `ne` is NULL or a live stack; `OPENSSL_sk_free` accepts NULL.
    unsafe { OPENSSL_sk_free(ne) };
}

/// `local_sk_X509_NAME_ENTRY_pop_free` (`:136-139`) — free an inner stack **and** its elements.
///
/// # Safety
/// `ne` must be NULL or a live stack of `X509_NAME_ENTRY`.
unsafe extern "C" fn local_sk_name_entry_pop_free(ne: *mut OpenSslStack) {
    // SAFETY: `ne` is NULL or a live stack per the contract.
    unsafe { OPENSSL_sk_pop_free(ne, Some(free_name_entry)) };
}

/// The element thunk `OPENSSL_sk_pop_free` calls on the *outer* stack when the authority names
/// `local_sk_X509_NAME_ENTRY_free` as the destructor: each element is an inner stack, freed
/// without its entries (they have been moved into the `X509_NAME`).
///
/// # Safety
/// `elem` must be NULL or an inner `STACK_OF(X509_NAME_ENTRY)`.
unsafe extern "C" fn free_inner_stack_only(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a live stack per the contract.
    unsafe { local_sk_name_entry_free(elem.cast::<OpenSslStack>()) };
}

/// The element thunk for `local_sk_X509_NAME_ENTRY_pop_free` as the outer destructor: each inner
/// stack is freed together with whatever entries it still holds.
///
/// # Safety
/// `elem` must be NULL or an inner `STACK_OF(X509_NAME_ENTRY)`.
unsafe extern "C" fn free_inner_stack_with_entries(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a live stack per the contract.
    unsafe { local_sk_name_entry_pop_free(elem.cast::<OpenSslStack>()) };
}

/// `static int x509_name_ex_new(ASN1_VALUE **val, const ASN1_ITEM *it)` — `crypto/x509/x_name.c:90-114`.
///
/// Allocates the object, then the always-non-NULL `entries` stack and `bytes` buffer; a failure at
/// either frees what was allocated and raises. The name arrives `modified`, because nothing has
/// been encoded into `bytes` yet.
///
/// # Safety
/// `val` is a writable slot; `it` is the `X509_NAME` item (unused).
unsafe extern "C" fn x509_name_ex_new(val: *mut *mut c_void, it: *const Asn1Item) -> c_int {
    let _ = it;
    // SAFETY: the allocator takes the file/line for its mdbg record only.
    let ret = CRYPTO_zalloc(
        core::mem::size_of::<X509Name>(),
        FILE.as_ptr(),
        LINE_ZALLOC_EX_NEW,
    )
    .cast::<X509Name>();
    if ret.is_null() {
        return 0;
    }
    // SAFETY: `ret` is this call's own fresh allocation.
    unsafe {
        (*ret).entries = OPENSSL_sk_new_null();
        if (*ret).entries.is_null() {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::X509_NAME_97);
            CRYPTO_free(ret.cast(), FILE.as_ptr(), LINE_FREE_EX_NEW);
            return 0;
        }
        (*ret).bytes = BUF_MEM_new();
        if (*ret).bytes.is_null() {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::X509_NAME_101);
            OPENSSL_sk_free((*ret).entries);
            CRYPTO_free(ret.cast(), FILE.as_ptr(), LINE_FREE_EX_NEW);
            return 0;
        }
        (*ret).modified = 1;
        *val = ret.cast::<c_void>();
    }
    1
}

/// `static void x509_name_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)` —
/// `crypto/x509/x_name.c:116-129`.
///
/// # Safety
/// `pval` is NULL or a slot at a NULL or live `X509_NAME`; `it` is unused.
unsafe extern "C" fn x509_name_ex_free(pval: *mut *mut c_void, it: *const Asn1Item) {
    let _ = it;
    if pval.is_null() {
        return;
    }
    // SAFETY: `pval` is non-NULL here and points at a live `X509_NAME`.
    if unsafe { (*pval).is_null() } {
        return;
    }
    // SAFETY: `pval` points at a live `X509_NAME` per the contract.
    let a = unsafe { (*pval).cast::<X509Name>() };
    // SAFETY: `a` is live and its three owned blocks are this object's.
    unsafe {
        BUF_MEM_free((*a).bytes);
        local_sk_name_entry_pop_free((*a).entries);
        CRYPTO_free(
            (*a).canon_enc.cast(),
            FILE.as_ptr(),
            LINE_FREE_CANON_ENC_FREE,
        );
        CRYPTO_free(a.cast(), FILE.as_ptr(), LINE_FREE_NAME);
        *pval = ptr::null_mut();
    }
}

/// `static int x509_name_encode(X509_NAME *a)` — `crypto/x509/x_name.c:236-287`.
///
/// # Safety
/// `a` is a live `X509_NAME`.
unsafe fn x509_name_encode(a: *mut X509Name) -> c_int {
    let intname: *mut OpenSslStack = OPENSSL_sk_new_null();
    let mut entries: *mut OpenSslStack = ptr::null_mut();
    let mut set: c_int = -1;

    if intname.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_NAME_282) };
        return -1;
    }
    // SAFETY: `a` is live.
    let n = unsafe { OPENSSL_sk_num((*a).entries) };
    for i in 0..n {
        // SAFETY: `a` is live and `i` is in range.
        let entry = unsafe { OPENSSL_sk_value((*a).entries, i).cast::<X509NameEntry>() };
        // SAFETY: `entry` is a live element of the entries stack.
        if unsafe { (*entry).set } != set {
            // SAFETY: the stack constructor is the caller's contract here.
            entries = OPENSSL_sk_new_null();
            if entries.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::X509_NAME_282) };
                // SAFETY: `intname` is live and its elements are inner stacks it owns.
                unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_only)) };
                return -1;
            }
            // SAFETY: `intname` and `entries` are live; the push adopts `entries`.
            if unsafe { OPENSSL_sk_push(intname, entries.cast::<c_void>()) } == 0 {
                // SAFETY: `entries` is live and owned here.
                unsafe { OPENSSL_sk_free(entries) };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::X509_NAME_282) };
                // SAFETY: `intname` is live.
                unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_only)) };
                return -1;
            }
            // SAFETY: `entry` is live.
            set = unsafe { (*entry).set };
        }
        // SAFETY: `entries` is live and `entry` is a live entry the stack adopts.
        if unsafe { OPENSSL_sk_push(entries, entry.cast::<c_void>()) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_NAME_282) };
            // SAFETY: `intname` is live.
            unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_only)) };
            return -1;
        }
    }

    let mut v: *const c_void = intname.cast::<c_void>();
    // SAFETY: `v` is a live slot holding the internal-form stack; the item is static.
    let len = unsafe {
        ASN1_item_ex_i2d(
            &raw mut v,
            ptr::null_mut(),
            x509_name_internal_item(),
            -1,
            -1,
        )
    };
    // SAFETY: `a` is live and `bytes` is its own buffer.
    if unsafe { BUF_MEM_grow((*a).bytes, len.max(0) as usize) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_NAME_271) };
        // SAFETY: `intname` is live.
        unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_only)) };
        return -1;
    }
    // SAFETY: `a` is live and its buffer was just grown to `len` bytes.
    let mut p = unsafe { (*(*a).bytes).data.cast::<c_uchar>() };
    let mut v2: *const c_void = intname.cast::<c_void>();
    // SAFETY: `v2` and `p` are live slots; the item is static.
    unsafe { ASN1_item_ex_i2d(&raw mut v2, &raw mut p, x509_name_internal_item(), -1, -1) };
    // SAFETY: `intname` is live and its elements are inner stacks it owns.
    unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_only)) };
    // SAFETY: `a` is live.
    unsafe { (*a).modified = 0 };
    len
}

/// `static int asn1_string_canon(ASN1_STRING *out, const ASN1_STRING *in)` —
/// `crypto/x509/x_name.c:393-468`.
///
/// # Safety
/// `out` and `in_` are live `ASN1_STRING`s, distinct.
unsafe fn asn1_string_canon(out: *mut Asn1String, in_: *const Asn1String) -> c_int {
    // SAFETY: `in_` is live per the contract.
    if unsafe { ASN1_tag2bit((*in_).type_) } & ASN1_MASK_CANON == 0 {
        // SAFETY: both are live and distinct.
        return unsafe { ASN1_STRING_copy(out, in_) };
    }
    // SAFETY: `out` is live and writable.
    unsafe {
        (*out).type_ = V_ASN1_UTF8STRING;
        (*out).length = ASN1_STRING_to_UTF8(&raw mut (*out).data, in_);
    }
    // SAFETY: `out` is live; `length` was just written.
    if unsafe { (*out).length } == -1 {
        return 0;
    }

    // SAFETY: `out` is live and `data`/`length` describe a readable, writable block.
    unsafe {
        let mut from = (*out).data;
        let mut len = (*out).length;
        // Ignore leading spaces.
        while len > 0 && ossl_isspace(c_int::from(*from)) {
            from = from.add(1);
            len -= 1;
        }
        // Ignore trailing spaces (the authority measures this only through `len`).
        let mut end = from.add(len as usize);
        while len > 0 && ossl_isspace(c_int::from(*end.sub(1))) {
            end = end.sub(1);
            len -= 1;
        }
        let mut to = (*out).data;
        let mut i: c_int = 0;
        while i < len {
            if !ossl_isascii(c_int::from(*from)) {
                *to = *from;
                to = to.add(1);
                from = from.add(1);
                i += 1;
            } else if ossl_isspace(c_int::from(*from)) {
                *to = b' ';
                to = to.add(1);
                loop {
                    from = from.add(1);
                    i += 1;
                    if !ossl_isspace(c_int::from(*from)) {
                        break;
                    }
                }
            } else {
                *to = ossl_tolower(c_int::from(*from)) as c_uchar;
                to = to.add(1);
                from = from.add(1);
                i += 1;
            }
        }
        (*out).length = to.offset_from((*out).data) as c_int;
    }
    1
}

/// `static int i2d_name_canon(const STACK_OF(STACK_OF_X509_NAME_ENTRY) *intname,
/// unsigned char **in)` — `crypto/x509/x_name.c:470-487`.
///
/// # Safety
/// `intname` is a live stack of inner stacks; `in_` is a writable cursor or NULL.
unsafe fn i2d_name_canon(intname: *const OpenSslStack, in_: *mut *mut c_uchar) -> c_int {
    let mut len: c_int = 0;
    // SAFETY: `intname` is live per the contract.
    let n = unsafe { OPENSSL_sk_num(intname) };
    for i in 0..n {
        // SAFETY: `intname` is live and `i` is in range.
        let v = unsafe { OPENSSL_sk_value(intname, i) };
        let mut slot: *const c_void = v.cast::<c_void>();
        // SAFETY: `slot` is a live element slot; the item is static.
        let ltmp =
            unsafe { ASN1_item_ex_i2d(&raw mut slot, in_, x509_name_entries_item(), -1, -1) };
        if ltmp < 0 || len > c_int::MAX - ltmp {
            return -1;
        }
        len += ltmp;
    }
    len
}

/// `static int x509_name_canon(X509_NAME *a)` — `crypto/x509/x_name.c:311-384`.
///
/// # Safety
/// `a` is a live `X509_NAME`.
unsafe fn x509_name_canon(a: *mut X509Name) -> c_int {
    let mut entries: *mut OpenSslStack = ptr::null_mut();
    let mut set: c_int = -1;

    // SAFETY: `a` is live and `canon_enc` is this object's own block.
    unsafe {
        CRYPTO_free(
            (*a).canon_enc.cast(),
            FILE.as_ptr(),
            LINE_FREE_CANON_ENC_CANON,
        );
        (*a).canon_enc = ptr::null_mut();
    }
    // SAFETY: `a` is live.
    if unsafe { OPENSSL_sk_num((*a).entries) } == 0 {
        // SAFETY: `a` is live and writable.
        unsafe { (*a).canon_enclen = 0 };
        return 1;
    }
    let intname: *mut OpenSslStack = OPENSSL_sk_new_null();
    if intname.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_NAME_328) };
        return 0;
    }
    // SAFETY: `a` is live.
    let n = unsafe { OPENSSL_sk_num((*a).entries) };
    for i in 0..n {
        // SAFETY: `a` is live and `i` is in range.
        let entry = unsafe { OPENSSL_sk_value((*a).entries, i).cast::<X509NameEntry>() };
        // SAFETY: `entry` is live.
        if unsafe { (*entry).set } != set {
            // SAFETY: the stack constructor is the caller's contract.
            entries = OPENSSL_sk_new_null();
            if entries.is_null() {
                // SAFETY: `intname` is live.
                unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
                return 0;
            }
            // SAFETY: `intname` and `entries` are live.
            if unsafe { OPENSSL_sk_push(intname, entries.cast::<c_void>()) } == 0 {
                // SAFETY: `entries` is live and owned here; `intname` is live.
                unsafe {
                    OPENSSL_sk_free(entries);
                    raise_site(&err_sites::X509_NAME_339);
                }
                // SAFETY: `intname` is live.
                unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
                return 0;
            }
            // SAFETY: `entry` is live.
            set = unsafe { (*entry).set };
        }
        // SAFETY: `X509_NAME_ENTRY_new` is the caller's contract.
        let tmpentry = X509_NAME_ENTRY_new();
        if tmpentry.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_NAME_346) };
            // SAFETY: `intname` is live.
            unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
            return 0;
        }
        // SAFETY: `tmpentry` and `entry` are live, and `entry`'s object/value are its own.
        unsafe {
            (*tmpentry).object = OBJ_dup((*entry).object);
            if (*tmpentry).object.is_null() {
                raise_site(&err_sites::X509_NAME_351);
                X509_NAME_ENTRY_free(tmpentry);
                OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries));
                return 0;
            }
            if asn1_string_canon((*tmpentry).value, (*entry).value) == 0 {
                X509_NAME_ENTRY_free(tmpentry);
                OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries));
                return 0;
            }
            if OPENSSL_sk_push(entries, tmpentry.cast::<c_void>()) == 0 {
                raise_site(&err_sites::X509_NAME_357);
                X509_NAME_ENTRY_free(tmpentry);
                OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries));
                return 0;
            }
        }
    }

    // SAFETY: `intname` is a live stack.
    let len = unsafe { i2d_name_canon(intname, ptr::null_mut()) };
    if len < 0 {
        // SAFETY: `intname` is live.
        unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe { (*a).canon_enclen = len };
    // SAFETY: the allocator takes the file/line for its mdbg record only; `len` is positive here.
    let p = CRYPTO_malloc(len as usize, FILE.as_ptr(), LINE_CANON_MALLOC).cast::<c_uchar>();
    if p.is_null() {
        // SAFETY: `intname` is live.
        unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe { (*a).canon_enc = p };
    let mut pp = p;
    // SAFETY: `intname` is a live stack and `pp` is a writable cursor.
    unsafe { i2d_name_canon(intname, &raw mut pp) };

    // SAFETY: the entries were moved into `intname`'s inner stacks, so this frees both.
    unsafe { OPENSSL_sk_pop_free(intname, Some(free_inner_stack_with_entries)) };
    1
}

/// `static int x509_name_ex_d2i(...)` — `crypto/x509/x_name.c:141-212`.
///
/// # Safety
/// The `asn1_ex_d2i` hook's own contract: `val` is a live slot, `in_` a readable cursor of `len`
/// bytes, `it` the `X509_NAME` item, `ctx` NULL or a live `ASN1_TLC`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe extern "C" fn x509_name_ex_d2i(
    val: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
    opt: c_char,
    ctx: *mut Asn1Tlc,
) -> c_int {
    let _ = it;
    // SAFETY: `in_` is a readable cursor per the hook's contract.
    let mut p = unsafe { *in_ };
    let q = p;
    let mut intname: *mut c_void = ptr::null_mut();
    let mut nm_slot: *mut c_void = ptr::null_mut();
    let clamped = if len > X509_NAME_MAX {
        X509_NAME_MAX
    } else {
        len
    };

    // SAFETY: `intname` is a live slot, `p` a readable cursor, and the item is static.
    let ret = unsafe {
        ASN1_item_ex_d2i(
            &raw mut intname,
            &raw mut p,
            clamped,
            x509_name_internal_item(),
            tag,
            aclass,
            opt,
            ctx,
        )
    };
    if ret <= 0 {
        return ret;
    }
    let outer = intname.cast::<OpenSslStack>();

    // SAFETY: `val` is a live slot and `intname` is the decoded internal form.
    unsafe {
        if !(*val).is_null() {
            x509_name_ex_free(val, ptr::null());
        }
        if x509_name_ex_new(&raw mut nm_slot, ptr::null()) == 0 {
            OPENSSL_sk_pop_free(outer, Some(free_inner_stack_with_entries));
            raise_site(&err_sites::X509_NAME_210);
            return 0;
        }
        let nm = nm_slot.cast::<X509Name>();
        // Cache the received encoding.
        let consumed = p.offset_from(q) as usize;
        if BUF_MEM_grow((*nm).bytes, consumed) == 0 {
            X509_NAME_free(nm);
            OPENSSL_sk_pop_free(outer, Some(free_inner_stack_with_entries));
            raise_site(&err_sites::X509_NAME_210);
            return 0;
        }
        ptr::copy_nonoverlapping(q, (*(*nm).bytes).data.cast::<c_uchar>(), consumed);

        // Convert the internal representation to the flat X509_NAME.
        let n_outer = OPENSSL_sk_num(outer);
        for i in 0..n_outer {
            let entries = OPENSSL_sk_value(outer, i).cast::<OpenSslStack>();
            let n_inner = OPENSSL_sk_num(entries);
            for j in 0..n_inner {
                let entry = OPENSSL_sk_value(entries, j).cast::<X509NameEntry>();
                (*entry).set = i;
                if OPENSSL_sk_push((*nm).entries, entry.cast::<c_void>()) == 0 {
                    X509_NAME_free(nm);
                    OPENSSL_sk_pop_free(outer, Some(free_inner_stack_with_entries));
                    raise_site(&err_sites::X509_NAME_210);
                    return 0;
                }
                OPENSSL_sk_set(entries, j, ptr::null());
            }
        }
        if x509_name_canon(nm) == 0 {
            X509_NAME_free(nm);
            OPENSSL_sk_pop_free(outer, Some(free_inner_stack_with_entries));
            raise_site(&err_sites::X509_NAME_210);
            return 0;
        }
        // Every entry was moved out, so the inner stacks are now empty and freeing them without
        // their entries is the authority's own `local_sk_X509_NAME_ENTRY_free`.
        OPENSSL_sk_pop_free(outer, Some(free_inner_stack_only));
        (*nm).modified = 0;
        *val = nm.cast::<c_void>();
        *in_ = p;
    }
    ret
}

/// `static int x509_name_ex_i2d(const ASN1_VALUE **val, unsigned char **out, const ASN1_ITEM *it,
/// int tag, int aclass)` — `crypto/x509/x_name.c:214-234`.
///
/// # Safety
/// The `asn1_ex_i2d` hook's own contract.
unsafe extern "C" fn x509_name_ex_i2d(
    val: *mut *const c_void,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    let _ = (it, tag, aclass);
    // SAFETY: `val` points at a live `X509_NAME` per the hook's contract.
    let a = unsafe { (*val).cast::<X509Name>().cast_mut() };
    // SAFETY: `a` is live.
    if unsafe { (*a).modified } != 0 {
        // SAFETY: `a` is live.
        let ret = unsafe { x509_name_encode(a) };
        if ret < 0 {
            return ret;
        }
        // SAFETY: `a` is live.
        if unsafe { x509_name_canon(a) } == 0 {
            return -1;
        }
    }
    // SAFETY: `a` is live and `bytes` is non-NULL after a new/encode.
    let ret = unsafe { (*(*a).bytes).length as c_int };
    if !out.is_null() {
        // SAFETY: `out` is a writable cursor and the caller has room for `ret` bytes.
        unsafe {
            ptr::copy_nonoverlapping((*(*a).bytes).data.cast::<c_uchar>(), *out, ret as usize);
            *out = (*out).add(ret as usize);
        }
    }
    ret
}

/// `static const ASN1_EXTERN_FUNCS x509_name_ff` — `crypto/x509/x_name.c:73-82`.
///
/// Seven initialisers in the authority's order — `app_data` NULL, `asn1_ex_new`, `asn1_ex_free`,
/// `asn1_ex_clear` NULL (the default clear behaviour is fine), `asn1_ex_d2i`, `asn1_ex_i2d` — and
/// `asn1_ex_print` **withheld** (it is `X509_NAME_print_ex`, which is not landed; see the module
/// doc). Wrapped for the same reason `src/x509/x_pubkey.rs`'s `SyncExtern` is.
struct SyncExtern(Asn1ExternFuncs);

// SAFETY: a `static` compiled from constants, its fields scalars and function pointers, with no
// interior mutability reachable through the shared reference the item's `funcs` slot takes.
unsafe impl Sync for SyncExtern {}

/// The `ASN1_EXTERN_FUNCS` block named above.
static X509_NAME_FF: SyncExtern = SyncExtern(Asn1ExternFuncs {
    app_data: ptr::null_mut(),
    asn1_ex_new: Some(x509_name_ex_new),
    asn1_ex_free: Some(x509_name_ex_free),
    asn1_ex_clear: None,
    asn1_ex_d2i: Some(x509_name_ex_d2i),
    asn1_ex_i2d: Some(x509_name_ex_i2d),
    asn1_ex_print: None,
    asn1_ex_new_ex: None,
    asn1_ex_d2i_ex: None,
});

/// `X509_NAME`'s descriptor — `IMPLEMENT_EXTERN_ASN1(X509_NAME, V_ASN1_SEQUENCE, x509_name_ff)`
/// (`:84`).
static X509_NAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_EXTERN,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ptr::null(),
    tcount: 0,
    funcs: (&X509_NAME_FF.0) as *const Asn1ExternFuncs as *const c_void,
    size: 0,
    sname: c"X509_NAME".as_ptr(),
};

/// `const ASN1_ITEM *X509_NAME_it(void)` — `include/openssl/x509.h:515`.
#[no_mangle]
pub extern "C" fn X509_NAME_it() -> *const Asn1Item {
    &X509_NAME_ITEM
}

/// `X509_NAME *X509_NAME_new(void)` — `crypto/x509/x_name.c:86`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_NAME)`. For an `EXTERN` item this reaches
/// [`x509_name_ex_new`].
#[no_mangle]
pub extern "C" fn X509_NAME_new() -> *mut X509Name {
    // SAFETY: `X509_NAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_NAME_it()).cast::<X509Name>() }
}

/// `void X509_NAME_free(X509_NAME *a)` — the same macro's free half. Reaches
/// [`x509_name_ex_free`].
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_free(a: *mut X509Name) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_NAME_it()) }
}

/// `X509_NAME *X509_NAME_dup(const X509_NAME *a)` — `IMPLEMENT_ASN1_DUP_FUNCTION(X509_NAME)`
/// (`:88`).
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_dup(a: *const X509Name) -> *mut X509Name {
    // SAFETY: `a` is NULL or live per the contract; `X509_NAME_it()` is a static item.
    unsafe { ASN1_item_dup(X509_NAME_it(), a.cast()).cast::<X509Name>() }
}

/// `X509_NAME *d2i_X509_NAME(X509_NAME **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_name.c:86`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_NAME(
    a: *mut *mut X509Name,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Name {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_NAME_it()).cast::<X509Name>() }
}

/// `int i2d_X509_NAME(const X509_NAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_NAME(a: *const X509Name, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_NAME_it()) }
}

/// `int X509_NAME_set(X509_NAME **xn, const X509_NAME *name)` — `crypto/x509/x_name.c:489-500`.
///
/// # Safety
///
/// `xn` is a live slot; `name` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_set(xn: *mut *mut X509Name, name: *const X509Name) -> c_int {
    // SAFETY: `xn` is live per the contract.
    if unsafe { *xn } == name.cast_mut() {
        // SAFETY: `xn` is live.
        return c_int::from(unsafe { !(*xn).is_null() });
    }
    // SAFETY: `name` is NULL or live per the contract.
    let name_copy = unsafe { X509_NAME_dup(name) };
    if name_copy.is_null() {
        return 0;
    }
    // SAFETY: `xn` is a live slot.
    unsafe {
        X509_NAME_free(*xn);
        *xn = name_copy;
    }
    1
}

/// `int X509_NAME_get0_der(const X509_NAME *nm, const unsigned char **pder, size_t *pderlen)` —
/// `crypto/x509/x_name.c:541-552`.
///
/// # Safety
///
/// `nm` is live; each out-pointer is NULL or writable for its type.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get0_der(
    nm: *const X509Name,
    pder: *mut *const c_uchar,
    pderlen: *mut usize,
) -> c_int {
    // SAFETY: `nm` is NULL or live per the contract; `i2d_X509_NAME` accepts both.
    if unsafe { i2d_X509_NAME(nm, ptr::null_mut()) } <= 0 {
        return 0;
    }
    // SAFETY: `nm` is live and its `bytes` is non-NULL after the length-only encode.
    unsafe {
        if !pder.is_null() {
            *pder = (*(*nm).bytes).data.cast::<c_uchar>();
        }
        if !pderlen.is_null() {
            *pderlen = (*(*nm).bytes).length;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::string::{ASN1_STRING_length, ASN1_STRING_set, ASN1_STRING_type_new};
    use crate::runtime::obj::{OBJ_nid2obj, OBJ_obj2nid};

    /// Pushes one `CN=zed` entry onto a freshly built name.
    ///
    /// # Safety
    /// `nm` is a live `X509_NAME`.
    unsafe fn push_cn(nm: *mut X509Name) {
        // SAFETY: everything here is a live value this test owns.
        unsafe {
            let entry = X509_NAME_ENTRY_new();
            assert!(!entry.is_null());
            (*entry).object = OBJ_dup(OBJ_nid2obj(13)); // NID_commonName
            assert!(!(*entry).object.is_null());
            (*entry).value = ASN1_STRING_type_new(V_ASN1_UTF8STRING);
            ASN1_STRING_set((*entry).value, c"zed".as_ptr().cast(), 3);
            (*entry).set = 0;
            assert_eq!(OPENSSL_sk_push((*nm).entries, entry.cast::<c_void>()), 1);
        }
    }

    /// A name built through its own item round-trips through `i2d_X509_NAME`/`d2i_X509_NAME`,
    /// and the re-decoded copy agrees on the entry's OID and value length.
    #[test]
    fn a_name_round_trips_through_its_item() {
        // SAFETY: every call below is over live values this test owns.
        unsafe {
            let nm = X509_NAME_new();
            assert!(!nm.is_null());
            assert_eq!((*nm).modified, 1);
            push_cn(nm);

            let len = i2d_X509_NAME(nm, ptr::null_mut());
            assert!(len > 0);
            let mut buf = vec![0u8; len as usize];
            let mut p = buf.as_mut_ptr();
            assert_eq!(i2d_X509_NAME(nm, &raw mut p), len);

            let mut c = buf.as_ptr();
            let nm2 = d2i_X509_NAME(ptr::null_mut(), &raw mut c, len as c_long);
            assert!(!nm2.is_null());
            assert_eq!(OPENSSL_sk_num((*nm2).entries), 1);
            let e2 = OPENSSL_sk_value((*nm2).entries, 0).cast::<X509NameEntry>();
            assert_eq!(OBJ_obj2nid((*e2).object), 13);
            assert_eq!(ASN1_STRING_length((*e2).value), 3);

            X509_NAME_free(nm2);
            X509_NAME_free(nm);
        }
    }

    /// A name with no entries canonicalises to a NULL pointer and a zero length, which is the
    /// documented empty-name form.
    #[test]
    fn an_empty_name_has_a_null_canonical_form() {
        // SAFETY: `nm` is a live object this test owns.
        unsafe {
            let nm = X509_NAME_new();
            assert!(!nm.is_null());
            assert_eq!(x509_name_canon(nm), 1);
            assert!((*nm).canon_enc.is_null());
            assert_eq!((*nm).canon_enclen, 0);
            X509_NAME_free(nm);
        }
    }

    /// `X509_NAME_get0_der` reports the cached encoding, and forces it to exist first.
    #[test]
    fn get0_der_reports_the_cached_encoding() {
        // SAFETY: `nm` is a live object this test owns; the out-pointers are locals.
        unsafe {
            let nm = X509_NAME_new();
            push_cn(nm);
            let mut der: *const c_uchar = ptr::null();
            let mut derlen: usize = 0;
            assert_eq!(X509_NAME_get0_der(nm, &raw mut der, &raw mut derlen), 1);
            assert!(!der.is_null());
            assert!(derlen > 0);
            X509_NAME_free(nm);
        }
    }
}
