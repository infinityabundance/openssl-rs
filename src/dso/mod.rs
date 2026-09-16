//! Phase 6.9 — `crypto/dso/dso_lib.c`, the generic dynamic-object layer.
//!
//! A `DSO` is a loaded shared library: a reference-counted handle, a stack of
//! method-private handles, a filename, the filename it was *actually* loaded by, and
//! the method that knows how to load, unload, bind and translate names on this
//! platform.
//!
//! ## The layer split, and why it matters here
//!
//! `dso_lib.c` never calls `dlopen`. It calls `meth->dso_load`, `meth->dso_bind_func`
//! and so on, and the method is chosen by configuration: this profile's
//! `build/.../include/crypto/dso_conf.h` defines `DSO_DLFCN`, so
//! [`DSO_METHOD_openssl`](crate::dso::dlfcn::DSO_METHOD_openssl) returns the `dlfcn`
//! method and every platform-specific operation lives in
//! [`crate::dso::dlfcn`]. `dso_openssl.c`'s null method is the `DSO_NONE` build, which
//! is not this one; `dso_dl.c`, `dso_vms.c` and `dso_win32.c` are other platforms.
//!
//! Three generic operations are **intercepted before the method sees them**, and that
//! is a compatibility fact rather than an optimisation: `DSO_ctrl` answers
//! `DSO_CTRL_GET_FLAGS` from `dso->flags`, and `DSO_CTRL_SET_FLAGS` /
//! `DSO_CTRL_OR_FLAGS` write it, all three returning without consulting `meth->dso_ctrl`
//! at all. The `dlfcn` method supplies `NULL` for its `ctrl`, so a caller who asks for
//! any *other* command gets `DSO_R_UNSUPPORTED` and `-1`.
//!
//! ## `DSO_new_method` is not `DSO_new`, and the difference is `ex_data`
//!
//! It zeroes the object, builds the method-data stack, sets the method and creates the
//! reference count. It **does not call `CRYPTO_new_ex_data`**, and `DSO_free` does not
//! call `CRYPTO_free_ex_data`. So `ex_data` is a zeroed field that nothing in this file
//! reads or writes — reproduced as a field rather than implemented as a subsystem.
//!
//! Two failure paths do have to be exact. If the stack cannot be built, the authority
//! raises `ERR_R_CRYPTO_LIB` **because `sk_new` raises nothing of its own**, and if the
//! reference count cannot be created the stack is freed first. Both are reproduced, with
//! that ordering.
//!
//! ## The two filenames, and which one `DSO_load` stores where
//!
//! `filename` is the platform-independent name the caller gave (or the translated one
//! `DSO_load` derived from it); `loaded_filename` is what the library was *actually*
//! loaded by, and it is set **by the method's `dso_load`**, not by this layer. That is
//! why `DSO_set_filename` refuses once `loaded_filename` is non-NULL: at that point the
//! object corresponds to a loaded library and its name is no longer the caller's to
//! change.
//!
//! `DSO_load` also refuses **before** it translates anything if `ret->filename` is
//! already set, which is what makes a second `DSO_load` on the same object
//! `DSO_R_DSO_ALREADY_LOADED` rather than a reload.
//!
//! ## `DSO_pathbyaddr` and `DSO_dsobyaddr` answer a path that cannot be compared
//!
//! Both ask the method for the path of the module containing an address. In a
//! differential court the two sides are different libraries at different paths, so the
//! *text* is necessarily different and only the **size contract** is comparable:
//! `sz <= 0` answers `len + 1` (a size query), otherwise the path is truncated to
//! `sz - 1` bytes and the answer is `min(len, sz - 1) + 1`. A null address means "the
//! address of the function itself", which is how a caller asks "where am I".

//! The two files of this subsystem are both modules of `src/dso`: this one mirrors
//! `dso_lib.c`, and [`dlfcn`] mirrors `dso_dlfcn.c`.

pub mod dlfcn;

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::dso::dlfcn::DSO_METHOD_openssl;
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::ex_data::CryptoExData;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};

extern "C" {
    /// `char *dlerror(void)` — the text the two `_FAILED` reasons carry.
    fn dlerror() -> *const c_char;
    /// `size_t strlen(const char *)`.
    fn strlen(s: *const c_char) -> usize;
}

/// The authority's translation unit.
pub(crate) const FILE_LIB: *const c_char = c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c".as_ptr();

/// `DSO_new_method`'s `OPENSSL_zalloc`.
const LINE_ZALLOC: c_int = 17;
/// `DSO_new_method`'s `OPENSSL_free(ret)` on a stack failure.
const LINE_FREE_STACK_FAIL: c_int = 24;
/// `DSO_free`'s `OPENSSL_free(dso->filename)`.
const LINE_FREE_FILENAME: c_int = 75;
/// `DSO_free`'s `OPENSSL_free(dso->loaded_filename)`.
const LINE_FREE_LOADED: c_int = 76;
/// `DSO_free`'s `OPENSSL_free(dso)`.
const LINE_FREE_DSO: c_int = 78;
/// `DSO_dsobyaddr`'s `OPENSSL_malloc(len)` — `dso_lib.c`'s, not the method's.
const LINE_MALLOC_BYADDR: c_int = 311;
/// `DSO_dsobyaddr`'s `OPENSSL_free(filename)`.
const LINE_FREE_BYADDR: c_int = 316;

/// `DSO_FUNC_TYPE` — `typedef void (*DSO_FUNC_TYPE)(void)`.
pub type DsoFuncType = Option<unsafe extern "C" fn()>;

/// `typedef struct dso_st DSO` — `crypto/dso/dso_local.h`.
///
/// The field order is the authority's. `ex_data` is present for layout and is never
/// read or written, because neither `DSO_new_method` nor `DSO_free` initialises it.
#[repr(C)]
pub struct Dso {
    /// `DSO_METHOD *meth`.
    pub(crate) meth: *mut DsoMethod,
    /// `STACK_OF(void) *meth_data` — the handle list, which is the method's.
    pub(crate) meth_data: *mut OpenSslStack,
    /// `CRYPTO_REF_COUNT references`.
    pub(crate) references: AtomicI32,
    /// `int flags`.
    pub(crate) flags: c_int,
    /// `CRYPTO_EX_DATA ex_data` — zeroed and untouched.
    pub(crate) ex_data: CryptoExData,
    /// `DSO_NAME_CONVERTER_FUNC name_converter` — a caller override.
    pub(crate) name_converter: DsoNameConverterFunc,
    /// `DSO_MERGER_FUNC merger` — a caller override.
    pub(crate) merger: DsoMergerFunc,
    /// `char *filename` — the platform-independent name.
    pub(crate) filename: *mut c_char,
    /// `char *loaded_filename` — set by the method's `dso_load`, NULL when not loaded.
    pub(crate) loaded_filename: *mut c_char,
}

/// `struct dso_meth_st` — the eleven fields of `crypto/dso/dso_local.h`, in its order.
///
/// The order is load-bearing: each `.c` file that builds a method writes a positional
/// initialiser, so a field inserted in the wrong place silently reassigns the rest.
#[repr(C)]
pub struct DsoMethod {
    /// `const char *name`.
    pub(crate) name: *const c_char,
    /// `int (*dso_load)(DSO *dso)`.
    pub(crate) dso_load: Option<unsafe extern "C" fn(*mut Dso) -> c_int>,
    /// `int (*dso_unload)(DSO *dso)`.
    pub(crate) dso_unload: Option<unsafe extern "C" fn(*mut Dso) -> c_int>,
    /// `DSO_FUNC_TYPE (*dso_bind_func)(DSO *dso, const char *symname)`.
    pub(crate) dso_bind_func: Option<unsafe extern "C" fn(*mut Dso, *const c_char) -> DsoFuncType>,
    /// `long (*dso_ctrl)(DSO *dso, int cmd, long larg, void *parg)`.
    pub(crate) dso_ctrl:
        Option<unsafe extern "C" fn(*mut Dso, c_int, c_long, *mut c_void) -> c_long>,
    /// `DSO_NAME_CONVERTER_FUNC dso_name_converter`.
    pub(crate) dso_name_converter: DsoNameConverterFunc,
    /// `DSO_MERGER_FUNC dso_merger`.
    pub(crate) dso_merger: DsoMergerFunc,
    /// `int (*init)(DSO *dso)`.
    pub(crate) init: Option<unsafe extern "C" fn(*mut Dso) -> c_int>,
    /// `int (*finish)(DSO *dso)`.
    pub(crate) finish: Option<unsafe extern "C" fn(*mut Dso) -> c_int>,
    /// `int (*pathbyaddr)(void *addr, char *path, int sz)`.
    pub(crate) pathbyaddr: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>,
    /// `void *(*globallookup)(const char *symname)`.
    pub(crate) globallookup: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
}

/// `typedef char *(*DSO_NAME_CONVERTER_FUNC)(DSO *, const char *)`.
pub type DsoNameConverterFunc =
    Option<unsafe extern "C" fn(*mut Dso, *const c_char) -> *mut c_char>;
/// `typedef char *(*DSO_MERGER_FUNC)(DSO *, const char *, const char *)`.
pub type DsoMergerFunc =
    Option<unsafe extern "C" fn(*mut Dso, *const c_char, *const c_char) -> *mut c_char>;

/// `DSO_CTRL_GET_FLAGS` — `include/internal/dso.h`.
const DSO_CTRL_GET_FLAGS: c_int = 1;
/// `DSO_CTRL_SET_FLAGS`.
pub(crate) const DSO_CTRL_SET_FLAGS: c_int = 2;
/// `DSO_CTRL_OR_FLAGS`.
const DSO_CTRL_OR_FLAGS: c_int = 3;
/// `DSO_FLAG_NO_UNLOAD_ON_FREE`.
pub(crate) const DSO_FLAG_NO_UNLOAD_ON_FREE: c_int = 0x04;
/// `DSO_FLAG_NO_NAME_TRANSLATION`.
pub(crate) const DSO_FLAG_NO_NAME_TRANSLATION: c_int = 0x01;
/// `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY`.
pub(crate) const DSO_FLAG_NAME_TRANSLATION_EXT_ONLY: c_int = 0x02;
/// `DSO_FLAG_GLOBAL_SYMBOLS`.
pub(crate) const DSO_FLAG_GLOBAL_SYMBOLS: c_int = 0x20;

/// `static DSO *DSO_new_method(DSO_METHOD *meth)`
///
/// # Safety
/// `meth` must be NULL or a `'static` method.
unsafe fn new_method(meth: *mut DsoMethod) -> *mut Dso {
    let ret = CRYPTO_zalloc(core::mem::size_of::<Dso>(), FILE_LIB, LINE_ZALLOC).cast::<Dso>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is a fresh, exclusively owned block of exactly this type.
    unsafe {
        (*ret).meth_data = OPENSSL_sk_new_null();
        if (*ret).meth_data.is_null() {
            // `sk_new` raises nothing of its own, so the authority raises here.
            raise_site(&err_sites::DSO_LIB_23);
            CRYPTO_free(ret.cast::<c_void>(), FILE_LIB, LINE_FREE_STACK_FAIL);
            return ptr::null_mut();
        }
        // The `meth` argument is accepted and **discarded**: the authority assigns
        // `DSO_METHOD_openssl()` unconditionally, so `DSO_new_method` has exactly one
        // outcome whichever method the caller names. `DSO_load` passes its own argument
        // through to here, which is why a load naming an explicit method still gets the
        // openssl one.
        let _ = meth;
        (*ret).meth = DSO_METHOD_openssl();
        (*ret).references = AtomicI32::new(1);
    }
    // The authority's `CRYPTO_NEW_REF` cannot fail for an inline atomic, so its failure
    // arm (`sk_void_free` then `OPENSSL_free`, at line 30) is unreachable here. The
    // ordering it documents — the stack released before the object — is in the arm
    // above, which *is* reachable.
    // SAFETY: `ret` is live, so `(*ret).meth` is a `'static` method and `init` is one of
    // its function pointers.
    unsafe {
        if let Some(init) = (*ret).meth.as_ref().and_then(|m| m.init) {
            if init(ret) == 0 {
                DSO_free(ret);
                return ptr::null_mut();
            }
        }
    }
    ret
}

/// `DSO *DSO_new(void)`
///
/// # Safety
/// None: the answer is a new object or NULL.
#[no_mangle]
pub unsafe extern "C" fn DSO_new() -> *mut Dso {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the construct takes a method it discards.
        unsafe { new_method(ptr::null_mut()) }
    })
}

/// `int DSO_free(DSO *dso)`
///
/// A NULL object answers **1**, so a caller may free unconditionally. The unload is
/// skipped entirely when `DSO_FLAG_NO_UNLOAD_ON_FREE` is set, and a method that reports
/// a failed unload or finish leaves the object **unreleased** and raises: the object is
/// still owned by the caller at that point.
///
/// # Safety
/// `dso` must be NULL or a live object not already released.
#[no_mangle]
pub unsafe extern "C" fn DSO_free(dso: *mut Dso) -> c_int {
    guard_ffi(0, || {
        if dso.is_null() {
            return 1;
        }
        // SAFETY: `dso` is live per the contract.
        let now = unsafe { (*dso).references.fetch_sub(1, Ordering::AcqRel) };
        if now <= 0 {
            return 0;
        }
        if now > 1 {
            return 1;
        }
        // SAFETY: `dso` is live, so its method pointer is a `'static` method.
        unsafe {
            let meth = (*dso).meth;
            if (*dso).flags & DSO_FLAG_NO_UNLOAD_ON_FREE == 0 {
                if let Some(unload) = meth.as_ref().and_then(|m| m.dso_unload) {
                    if unload(dso) == 0 {
                        raise_site(&err_sites::DSO_LIB_64);
                        return 0;
                    }
                }
            }
            if let Some(finish) = meth.as_ref().and_then(|m| m.finish) {
                if finish(dso) == 0 {
                    raise_site(&err_sites::DSO_LIB_70);
                    return 0;
                }
            }
            OPENSSL_sk_free((*dso).meth_data);
            if !(*dso).filename.is_null() {
                CRYPTO_free(
                    (*dso).filename.cast::<c_void>(),
                    FILE_LIB,
                    LINE_FREE_FILENAME,
                );
            }
            if !(*dso).loaded_filename.is_null() {
                CRYPTO_free(
                    (*dso).loaded_filename.cast::<c_void>(),
                    FILE_LIB,
                    LINE_FREE_LOADED,
                );
            }
            CRYPTO_free(dso.cast::<c_void>(), FILE_LIB, LINE_FREE_DSO);
        }
        1
    })
}

/// `int DSO_flags(DSO *dso)` — 0 for NULL, which is why the answer is usable
/// unconditionally.
///
/// # Safety
/// `dso` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn DSO_flags(dso: *mut Dso) -> c_int {
    guard_ffi(0, || {
        if dso.is_null() {
            return 0;
        }
        // SAFETY: `dso` is live per the contract.
        unsafe { (*dso).flags }
    })
}

/// `int DSO_up_ref(DSO *dso)`
///
/// Unlike `BIO_up_ref`, a NULL object here is an **error** that raises, not a no-op
/// answering 0. The answer is `i > 1` after the increment, which is 1 for every
/// successful call because the count was at least 1 already.
///
/// # Safety
/// `dso` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn DSO_up_ref(dso: *mut Dso) -> c_int {
    guard_ffi(0, || {
        if dso.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_92) };
            return 0;
        }
        // SAFETY: `dso` is live.
        let i = unsafe { (*dso).references.fetch_add(1, Ordering::AcqRel) } + 1;
        c_int::from(i > 1)
    })
}

/// `DSO *DSO_load(DSO *dso, const char *filename, DSO_METHOD *meth, int flags)`
///
/// The four refusals before the method is ever asked, in the authority's order:
/// the object already has a `filename`; setting the caller's filename failed; there is
/// still no filename; the method has no `dso_load`. Each has its own reason, and a
/// call with a `dso` that already carries a name and no `filename` argument is the
/// *normal* second-call shape — which is why the already-loaded check comes first.
///
/// When this function allocated the object it frees it on any failure; when the caller
/// supplied one, a failure leaves it alone.
///
/// # Safety
/// `dso` must be NULL or live, `filename` NULL or NUL-terminated, `meth` NULL or
/// `'static`.
#[no_mangle]
pub unsafe extern "C" fn DSO_load(
    dso: *mut Dso,
    filename: *const c_char,
    meth: *mut DsoMethod,
    flags: c_int,
) -> *mut Dso {
    guard_ffi(ptr::null_mut(), || {
        let mut allocated = false;
        let ret;
        if dso.is_null() {
            // SAFETY: the construct takes a method it discards.
            ret = unsafe { new_method(meth) };
            if ret.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSO_LIB_112) };
                return ptr::null_mut();
            }
            allocated = true;
            // SAFETY: `ret` was just created and is not yet published.
            if unsafe {
                DSO_ctrl(
                    ret,
                    DSO_CTRL_SET_FLAGS,
                    c_long::from(flags),
                    ptr::null_mut(),
                )
            } < 0
            {
                // SAFETY: as above.
                unsafe { raise_site(&err_sites::DSO_LIB_118) };
                // SAFETY: `ret` is the object created above.
                unsafe { DSO_free(ret) };
                return ptr::null_mut();
            }
        } else {
            ret = dso;
        }
        // SAFETY: `ret` is live, whether the caller's or the one just created.
        unsafe {
            if !(*ret).filename.is_null() {
                raise_site(&err_sites::DSO_LIB_125);
                if allocated {
                    DSO_free(ret);
                }
                return ptr::null_mut();
            }
            if !filename.is_null() && DSO_set_filename(ret, filename) == 0 {
                raise_site(&err_sites::DSO_LIB_134);
                if allocated {
                    DSO_free(ret);
                }
                return ptr::null_mut();
            }
            if (*ret).filename.is_null() {
                raise_site(&err_sites::DSO_LIB_139);
                if allocated {
                    DSO_free(ret);
                }
                return ptr::null_mut();
            }
            let load = match (*ret).meth.as_ref().and_then(|m| m.dso_load) {
                Some(f) => f,
                None => {
                    raise_site(&err_sites::DSO_LIB_143);
                    if allocated {
                        DSO_free(ret);
                    }
                    return ptr::null_mut();
                }
            };
            if load(ret) == 0 {
                raise_site(&err_sites::DSO_LIB_147);
                if allocated {
                    DSO_free(ret);
                }
                return ptr::null_mut();
            }
        }
        ret
    })
}

/// `DSO_FUNC_TYPE DSO_bind_func(DSO *dso, const char *symname)`
///
/// # Safety
/// `dso` must be NULL or live and `symname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn DSO_bind_func(dso: *mut Dso, symname: *const c_char) -> DsoFuncType {
    guard_ffi(None, || {
        if dso.is_null() || symname.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_163) };
            return None;
        }
        // SAFETY: `dso` is live.
        unsafe {
            let bind = match (*dso).meth.as_ref().and_then(|m| m.dso_bind_func) {
                Some(f) => f,
                None => {
                    raise_site(&err_sites::DSO_LIB_167);
                    return None;
                }
            };
            // The authority assigns and *then* tests (`if ((ret = ...) == NULL)`), so the
            // method is asked **once**. Asking twice would be invisible through the ABI --
            // `dlsym` is idempotent and raises nothing OpenSSL-owned -- but it is a
            // different program, and the point of this layer is to be the same one.
            let ret = bind(dso, symname);
            if ret.is_none() {
                raise_site(&err_sites::DSO_LIB_171);
                return None;
            }
            ret
        }
    })
}

/// `long DSO_ctrl(DSO *dso, int cmd, long larg, void *parg)`
///
/// The three generic commands are answered here and **never reach the method**, which
/// is what makes `DSO_flags`/`DSO_ctrl` agree with each other on a method whose `ctrl`
/// is NULL: `GET` reads the field, `SET` stores `larg`, `OR` ORs it.
///
/// A negative answer means an error, as the authority's own comment says; a caller
/// cannot use the truthiness idiom.
///
/// # Safety
/// `dso` must be NULL or live, and `parg` whatever the command means.
#[no_mangle]
pub unsafe extern "C" fn DSO_ctrl(
    dso: *mut Dso,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    guard_ffi(-1, || {
        if dso.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_190) };
            return -1;
        }
        match cmd {
            // SAFETY: `dso` is live.
            DSO_CTRL_GET_FLAGS => return unsafe { c_long::from((*dso).flags) },
            DSO_CTRL_SET_FLAGS => {
                // SAFETY: `dso` is live.
                unsafe { (*dso).flags = larg as c_int };
                return 0;
            }
            DSO_CTRL_OR_FLAGS => {
                // SAFETY: `dso` is live.
                unsafe { (*dso).flags |= larg as c_int };
                return 0;
            }
            _ => {}
        }
        // SAFETY: `dso` is live.
        unsafe {
            let ctrl = match (*dso).meth.as_ref().and_then(|m| m.dso_ctrl) {
                Some(f) => f,
                None => {
                    raise_site(&err_sites::DSO_LIB_210);
                    return -1;
                }
            };
            ctrl(dso, cmd, larg, parg)
        }
    })
}

/// `const char *DSO_get_filename(DSO *dso)`
///
/// # Safety
/// `dso` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn DSO_get_filename(dso: *mut Dso) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if dso.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_219) };
            return ptr::null();
        }
        // SAFETY: `dso` is live.
        unsafe { (*dso).filename }
    })
}

/// `int DSO_set_filename(DSO *dso, const char *filename)`
///
/// The name is **copied**, and the previous one released — so a caller may reuse its
/// own buffer. Setting a name on an object that has been loaded is refused, because
/// `loaded_filename` being non-NULL is what "this object is a loaded library" means.
///
/// # Safety
/// `dso` must be NULL or live and `filename` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn DSO_set_filename(dso: *mut Dso, filename: *const c_char) -> c_int {
    guard_ffi(0, || {
        if dso.is_null() || filename.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_230) };
            return 0;
        }
        // SAFETY: `dso` is live.
        unsafe {
            if !(*dso).loaded_filename.is_null() {
                raise_site(&err_sites::DSO_LIB_234);
                return 0;
            }
            let copied = CRYPTO_strdup(filename, FILE_LIB, LINE_ZALLOC);
            if copied.is_null() {
                return 0;
            }
            if !(*dso).filename.is_null() {
                CRYPTO_free(
                    (*dso).filename.cast::<c_void>(),
                    FILE_LIB,
                    LINE_FREE_FILENAME,
                );
            }
            (*dso).filename = copied;
        }
        1
    })
}

/// `char *DSO_merge(DSO *dso, const char *filespec1, const char *filespec2)`
///
/// A caller-supplied `merger` wins over the method's, and
/// `DSO_FLAG_NO_NAME_TRANSLATION` suppresses both — in which case the answer is NULL
/// rather than the input, because the flag means "do not merge", not "return the first".
///
/// # Safety
/// `dso` must be NULL or live and both specs NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn DSO_merge(
    dso: *mut Dso,
    filespec1: *const c_char,
    filespec2: *const c_char,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if dso.is_null() || filespec1.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_251) };
            return ptr::null_mut();
        }
        // SAFETY: `dso` is live.
        unsafe {
            if (*dso).flags & DSO_FLAG_NO_NAME_TRANSLATION != 0 {
                return ptr::null_mut();
            }
            if let Some(merger) = (*dso).merger {
                return merger(dso, filespec1, filespec2);
            }
            if let Some(merger) = (*dso).meth.as_ref().and_then(|m| m.dso_merger) {
                return merger(dso, filespec1, filespec2);
            }
        }
        ptr::null_mut()
    })
}

/// `char *DSO_convert_filename(DSO *dso, const char *filename)`
///
/// A NULL filename means "translate the one I already have", and having none is
/// `DSO_R_NO_FILENAME`. A converter that answers NULL falls back to a **plain
/// `strdup` of the input** — so "translation failed" becomes "untranslated", not an
/// error, and `DSO_FLAG_NO_NAME_TRANSLATION` takes exactly that path.
///
/// # Safety
/// `dso` must be NULL or live and `filename` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn DSO_convert_filename(
    dso: *mut Dso,
    filename: *const c_char,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if dso.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::DSO_LIB_268) };
            return ptr::null_mut();
        }
        let mut name = filename;
        // SAFETY: `dso` is live per the guard above, so `filename` is a readable field
        // and the converter below is one of its two `'static` function pointers.
        unsafe {
            if name.is_null() {
                name = (*dso).filename;
            }
            if name.is_null() {
                raise_site(&err_sites::DSO_LIB_274);
                return ptr::null_mut();
            }
            let mut result: *mut c_char = ptr::null_mut();
            if (*dso).flags & DSO_FLAG_NO_NAME_TRANSLATION == 0 {
                if let Some(conv) = (*dso).name_converter {
                    result = conv(dso, name);
                } else if let Some(conv) = (*dso).meth.as_ref().and_then(|m| m.dso_name_converter) {
                    result = conv(dso, name);
                }
            }
            if result.is_null() {
                result = CRYPTO_strdup(name, FILE_LIB, LINE_ZALLOC);
            }
            result
        }
    })
}

/// `int DSO_pathbyaddr(void *addr, char *path, int sz)`
///
/// The method is `DSO_METHOD_openssl()`'s — the *static* method, not any object's — so
/// this works without a DSO at all. A method without `pathbyaddr` is
/// `DSO_R_UNSUPPORTED` and `-1`.
///
/// # Safety
/// `path` must be NULL or have `sz` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn DSO_pathbyaddr(addr: *mut c_void, path: *mut c_char, sz: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the method is `'static`.
        let meth = DSO_METHOD_openssl();
        // SAFETY: `meth` is the `'static` openssl method.
        let f = unsafe { (*meth).pathbyaddr };
        match f {
            Some(f) => {
                // SAFETY: the caller's contract for `path` and `sz`.
                unsafe { f(addr, path, sz) }
            }
            None => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSO_LIB_296) };
                -1
            }
        }
    })
}

/// `DSO *DSO_dsobyaddr(void *addr, int flags)`
///
/// A two-pass size query over `DSO_pathbyaddr`: ask for the length, allocate it, ask
/// again, and load only when the second answer **equals** the first — so a path that
/// grew between the two calls declines rather than loading a truncated name.
///
/// # Safety
/// `addr` must be NULL or a module address.
#[no_mangle]
pub unsafe extern "C" fn DSO_dsobyaddr(addr: *mut c_void, flags: c_int) -> *mut Dso {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: a NULL path with zero size is the authority's size query.
        let len = unsafe { DSO_pathbyaddr(addr, ptr::null_mut(), 0) };
        if len < 0 {
            return ptr::null_mut();
        }
        // SAFETY: `len` is a positive length, so the allocation is at least a byte.
        let filename = CRYPTO_malloc(len as usize, FILE_LIB, LINE_MALLOC_BYADDR).cast::<c_char>();
        let mut ret = ptr::null_mut();
        if !filename.is_null() {
            // SAFETY: `filename` has `len` writable bytes.
            if unsafe { DSO_pathbyaddr(addr, filename, len) } == len {
                // SAFETY: `filename` is NUL-terminated by the call above, and the
                // method is chosen by `DSO_load` itself (a NULL method).
                ret = unsafe { DSO_load(ptr::null_mut(), filename, ptr::null_mut(), flags) };
            }
        }
        if !filename.is_null() {
            // SAFETY: the block came from `CRYPTO_malloc`.
            unsafe { CRYPTO_free(filename.cast::<c_void>(), FILE_LIB, LINE_FREE_BYADDR) };
        }
        ret
    })
}

/// `void *DSO_global_lookup(const char *name)`
///
/// A lookup among **all** loaded modules, through the static method — `dlopen(NULL)`
/// followed by `dlsym`, in the `dlfcn` implementation.
///
/// # Safety
/// `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn DSO_global_lookup(name: *const c_char) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the method is `'static`.
        let meth = DSO_METHOD_openssl();
        // SAFETY: `meth` is the `'static` openssl method.
        let f = unsafe { (*meth).globallookup };
        match f {
            // SAFETY: `name` is NUL-terminated per the contract.
            Some(f) => unsafe { f(name) },
            None => {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::DSO_LIB_325) };
                ptr::null_mut()
            }
        }
    })
}

/// `int DSO_flags`'s companion for the string error data the method needs.
///
/// `dlfcn`'s two `ERR_raise_data` sites carry `dlerror()` text, and the authority
/// builds it with a `printf`-style format. This is that construction, factored out so
/// the two sites read the same.
///
/// # Safety
/// `site` must be a compile-time-constant site and `filename`/`symname` NULL or
/// NUL-terminated.
pub(crate) unsafe fn raise_data_load_failed(site: &err_sites::ErrSite, filename: *const c_char) {
    let mut m = b"filename(".to_vec();
    // SAFETY: `filename` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_str_or_null_literal(filename) });
    m.extend_from_slice(b"): ");
    // SAFETY: `dlerror()` answers NULL or a NUL-terminated string.
    m.extend_from_slice(unsafe { c_str_or_null_literal(dlerror()) });
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// # Safety
/// `site` must be a constant site and `symname` NULL or NUL-terminated.
pub(crate) unsafe fn raise_data_sym_failure(site: &err_sites::ErrSite, symname: *const c_char) {
    let mut m = b"symname(".to_vec();
    // SAFETY: `symname` is NUL-terminated per the contract.
    m.extend_from_slice(unsafe { c_str_or_null_literal(symname) });
    m.extend_from_slice(b"): ");
    // SAFETY: `dlerror()` answers NULL or a NUL-terminated string.
    m.extend_from_slice(unsafe { c_str_or_null_literal(dlerror()) });
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { raise_site_data(site, m.as_ptr().cast()) };
}

/// The bytes of a NUL-terminated string with the authority's **`<NULL>` literal**
/// substituted for a NULL pointer.
///
/// Both call sites pass their text through the authority's printf-style
/// `ERR_raise_data("filename(%s): %s", filename, dlerror())`, and that engine renders a
/// NULL `%s` as `<NULL>` rather than as nothing. Omitting it would be invisible while
/// `dlerror()` is non-NULL -- which it is immediately after a failed `dlopen`/`dlsym` --
/// and wrong the moment it is not, so the substitution is made unconditionally rather
/// than argued to be unreachable.
///
/// # Safety
/// `p` must be NULL or NUL-terminated.
pub(crate) unsafe fn c_str_or_null_literal<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"<NULL>";
    }
    // SAFETY: the caller guarantees a terminator, so the walk stops.
    unsafe { c_str_bytes(p) }
}

/// The authority's `ERR_add_error_data(2, "dlfcn_pathbyaddr(): ", dlerror())`.
///
/// This is the subsystem's one error site that **appends without raising**:
/// `dlfcn_pathbyaddr` has no `ERR_raise` of its own, so the text lands on whatever slot
/// is current, and on an empty queue that is a slot carrying no error code at all --
/// which is why `ERR_peek_error()` stays `0` across this failure. `ERR_add_error_data`
/// is *append*, not replace: `ERR_add_error_vdata` reuses the slot's existing
/// `MALLOCED|STRING` buffer and `strlcat`s into it.
///
/// A NULL `dlerror()` becomes the literal `<NULL>`, because that is what
/// `ERR_add_error_vdata` does to a NULL argument (`if (arg == NULL) arg = "<NULL>";`).
/// The substitution is *reachable* here in a way it is not at the load and bind sites:
/// those two fail immediately after a `dlopen`/`dlsym` that just set `dlerror`'s state,
/// whereas this one fails because `dladdr` did -- and `dladdr` does not.
pub(crate) unsafe fn add_error_data_pathbyaddr() {
    let mut m = b"dlfcn_pathbyaddr(): ".to_vec();
    // SAFETY: `dlerror()` answers NULL or a NUL-terminated string.
    m.extend_from_slice(unsafe { c_str_or_null_literal(dlerror()) });
    m.push(0);
    // SAFETY: `m` is NUL-terminated and outlives the call.
    unsafe { crate::runtime::err::openssl_rs_err_add_data(m.as_ptr().cast()) };
}

/// The bytes of a NUL-terminated string, or nothing for NULL.
///
/// # Safety
/// `p` must be NULL or NUL-terminated.
pub(crate) unsafe fn c_str_bytes<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    // SAFETY: the caller guarantees a terminator, so the walk stops.
    unsafe {
        let n = strlen(p);
        core::slice::from_raw_parts(p.cast::<u8>(), n)
    }
}

/// `guard_ffi`, re-exported so both DSO files use the one boundary.
pub(crate) use crate::ffi::guard_ffi;

/// The method-data stack accessors `dlfcn` needs, spelled as the authority spells
/// them. `sk_void_*` is `OPENSSL_sk_*` over `void *`.
///
/// # Safety
/// `dso` must be live.
pub(crate) unsafe fn meth_data_push(dso: *mut Dso, p: *mut c_void) -> c_int {
    // SAFETY: `dso` is live, so its stack is one this layer created.
    unsafe { OPENSSL_sk_push((*dso).meth_data, p) }
}

/// # Safety
/// `dso` must be live.
pub(crate) unsafe fn meth_data_num(dso: *mut Dso) -> c_int {
    // SAFETY: as above.
    unsafe { OPENSSL_sk_num((*dso).meth_data) }
}

/// # Safety
/// `dso` must be live.
pub(crate) unsafe fn meth_data_pop(dso: *mut Dso) -> *mut c_void {
    // SAFETY: as above.
    unsafe { OPENSSL_sk_pop((*dso).meth_data) }
}

/// # Safety
/// `dso` must be live and `i` in range.
pub(crate) unsafe fn meth_data_value(dso: *mut Dso, i: c_int) -> *mut c_void {
    // SAFETY: as above.
    unsafe { OPENSSL_sk_value((*dso).meth_data, i) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_object_has_the_openssl_method_a_null_name_and_flag_zero() {
        // SAFETY: `DSO_new` allocates; `DSO_free` releases.
        unsafe {
            let d = DSO_new();
            assert!(!d.is_null());
            assert!(!(*d).meth.is_null(), "the method is the static openssl one");
            assert!((*d).filename.is_null(), "no name until one is set");
            assert!((*d).loaded_filename.is_null(), "not loaded");
            assert_eq!(DSO_flags(d), 0);
            assert_eq!(DSO_get_filename(d), core::ptr::null());
            assert!(!(*d).meth_data.is_null(), "the handle stack exists");
            assert_eq!(DSO_free(d), 1);
        }
    }

    #[test]
    fn null_arguments_are_refused_except_where_the_authority_accepts_them() {
        // SAFETY: every call below passes NULL deliberately.
        unsafe {
            assert_eq!(DSO_free(core::ptr::null_mut()), 1, "freeing NULL succeeds");
            assert_eq!(DSO_flags(core::ptr::null_mut()), 0, "flags(NULL) is 0");
            assert_eq!(
                DSO_up_ref(core::ptr::null_mut()),
                0,
                "up_ref(NULL) raises and fails"
            );
            assert_eq!(
                DSO_ctrl(core::ptr::null_mut(), 1, 0, core::ptr::null_mut()),
                -1
            );
            assert!(DSO_get_filename(core::ptr::null_mut()).is_null());
        }
    }

    #[test]
    fn the_three_generic_ctrl_commands_never_reach_the_method() {
        // SAFETY: `d` is live; the three commands are the generic ones.
        unsafe {
            let d = DSO_new();
            assert_eq!(
                DSO_ctrl(d, DSO_CTRL_SET_FLAGS, 0x20, core::ptr::null_mut()),
                0
            );
            assert_eq!(DSO_flags(d), 0x20);
            assert_eq!(
                DSO_ctrl(d, DSO_CTRL_GET_FLAGS, 0, core::ptr::null_mut()),
                0x20
            );
            assert_eq!(
                DSO_ctrl(d, DSO_CTRL_OR_FLAGS, 0x04, core::ptr::null_mut()),
                0
            );
            assert_eq!(DSO_flags(d), 0x24);
            // `SET` replaces rather than merges.
            assert_eq!(DSO_ctrl(d, DSO_CTRL_SET_FLAGS, 0, core::ptr::null_mut()), 0);
            assert_eq!(DSO_flags(d), 0);
            // Any other command reaches the method's `ctrl`, which dlfcn leaves NULL.
            assert_eq!(DSO_ctrl(d, 99, 0, core::ptr::null_mut()), -1);
            DSO_free(d);
        }
    }

    #[test]
    fn up_ref_keeps_the_object_alive_and_free_counts_down() {
        // SAFETY: `d` is live.
        unsafe {
            let d = DSO_new();
            assert_eq!(DSO_up_ref(d), 1);
            assert_eq!(
                DSO_free(d),
                1,
                "one reference remains, so nothing is released"
            );
            assert_eq!(DSO_free(d), 1, "the last reference releases it");
        }
    }

    #[test]
    fn set_filename_copies_and_refuses_to_change_a_loaded_name() {
        // SAFETY: `d` is live and the literals are NUL-terminated.
        unsafe {
            let d = DSO_new();
            assert_eq!(DSO_set_filename(d, c"libcrypto.so.3".as_ptr()), 1);
            let got = DSO_get_filename(d);
            assert!(!got.is_null());
            assert_eq!(core::ffi::CStr::from_ptr(got).to_bytes(), b"libcrypto.so.3");
            // A second set replaces the first.
            assert_eq!(DSO_set_filename(d, c"other.so".as_ptr()), 1);
            assert_eq!(
                core::ffi::CStr::from_ptr(DSO_get_filename(d)).to_bytes(),
                b"other.so"
            );
            // A NULL name is refused.
            assert_eq!(DSO_set_filename(d, core::ptr::null()), 0);
            DSO_free(d);
        }
    }
}
