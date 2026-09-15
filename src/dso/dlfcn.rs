//! Phase 6.9 — `crypto/dso/dso_dlfcn.c`, the `dlfcn` method.
//!
//! The platform half of the DSO layer. This profile's `dso_conf.h` defines `DSO_DLFCN`
//! and `HAVE_DLFCN_H` and sets `DSO_EXTENSION` to `".so"`, and `configdata.pm` lists
//! `dso_dlfcn.o`, so this is the method `DSO_METHOD_openssl` returns. `dso_openssl.c`'s
//! null method is the `DSO_NONE` build, `dso_dl.c` is the `dl` build and
//! `dso_vms.c`/`dso_win32.c` are other platforms — none of them is this one, and the
//! constant `DSO_METHOD_openssl` exists in all of them.
//!
//! ## The handle stack holds exactly one entry, and that is the contract
//!
//! `meth_data` is a `STACK_OF(void)` whose single entry is the `void *` `dlopen`
//! returned. `dlfcn_load` pushes it, `dlfcn_unload` pops and `dlclose`s it, and
//! `dlfcn_bind_func` reads the **top** entry (`num - 1`) rather than the first — which is
//! the same thing for a stack of one, and is what would matter if a method ever pushed
//! more. An empty stack is `DSO_R_STACK_ERROR` in `bind_func` and a no-op success in
//! `unload`, and the two are different answers on purpose.
//!
//! ## `dlfcn_load` saves and restores `errno` around `dlopen`
//!
//! Some `dlopen` implementations do not preserve `errno` even on success, so the
//! authority reads it before the call and writes it back after. That makes `errno`
//! *after* a successful load the value it had *before* it — which is observable through
//! a caller that inspects `errno`, and reproduced rather than treated as housekeeping.
//!
//! ## The name translator's rule is "no slash", not "not already translated"
//!
//! ```c
//! transform = (strchr(filename, '/') == NULL);
//! ```
//!
//! So `"foo"` becomes `"libfoo.so"`, and **`"libfoo.so"` becomes `"liblibfoo.so"`** —
//! the function has no idea what a library is called and does not try to find out. With
//! `DSO_FLAG_NAME_TRANSLATION_EXT_ONLY` only the extension is added (`"foo.so"`), and
//! the `lib` prefix is three bytes that the allocation accounts for separately from the
//! extension's four.
//!
//! ## `dlfcn_merger` treats its second argument as a directory and does not check
//!
//! Four shapes: no second spec → the first; the first is rooted (`[0] == '/'`) → the
//! first; no first → the second; otherwise `dir + "/" + name`, with **one** trailing
//! slash removed from the directory first, so `"/d/", "f"` is `/d/f` and not `/d//f`.
//! The buffer is `len + 2` where `len` already subtracted that slash, which is what
//! makes the `strcpy` pair fit.
//!
//! ## `dlfcn_pathbyaddr` answers a *size* the first time
//!
//! With `sz <= 0` it returns `len + 1` and writes nothing, so a caller can ask how much
//! room the path needs. Otherwise it copies `min(len, sz - 1)` bytes, terminates, and
//! returns the number of bytes written. A NULL `addr` means "the address of
//! `dlfcn_pathbyaddr` itself", which is how `DSO_dsobyaddr(NULL, …)` asks where the
//! library under test lives.
//!
//! In a differential court the *path* is necessarily different on the two sides, so the
//! court compares the size contract and the terminator rather than the text.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::dso::{
    guard_ffi, meth_data_num, meth_data_pop, meth_data_push, meth_data_value,
    raise_data_load_failed, raise_data_sym_failure, Dso, DsoFuncType, DsoMethod,
    DSO_FLAG_GLOBAL_SYMBOLS, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY,
};
use crate::runtime::bio::sys::{errno, set_errno};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};

extern "C" {
    /// `void *dlopen(const char *filename, int flags)`.
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    /// `void *dlsym(void *handle, const char *symbol)`.
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    /// `int dlclose(void *handle)`.
    fn dlclose(handle: *mut c_void) -> c_int;
    /// `int dladdr(void *addr, Dl_info *info)` — glibc's, one of the `_GNU_SOURCE`
    /// extensions the authority's own comment says it needs.
    ///
    /// `dlerror` is deliberately absent: this file's one `dlerror()` read moved into
    /// [`crate::dso::add_error_data_pathbyaddr`] when that site was corrected to the
    /// authority's `ERR_add_error_data` shape, and `dlfcn_load`/`dlfcn_bind_func` build
    /// their messages through `mod.rs`'s helpers, which carry their own declaration.
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
    /// `size_t strlen(const char *)`.
    fn strlen(s: *const c_char) -> usize;
    /// `char *strchr(const char *, int)`.
    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;
}

/// glibc's `Dl_info` — `struct Dl_info { const char *dli_fname; void *dli_fbase;
/// const char *dli_sname; void *dli_saddr; }`.
#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

/// `DSO_EXTENSION` — `build/.../include/crypto/dso_conf.h`, `".so"` in this profile.
const DSO_EXTENSION: &[u8] = b".so";

/// `DLOPEN_FLAG` — `RTLD_NOW` for every platform that is not OpenBSD or NetBSD, which is
/// this one.
const DLOPEN_FLAG: c_int = 2; // RTLD_NOW
/// `RTLD_GLOBAL`, which `DSO_FLAG_GLOBAL_SYMBOLS` adds.
const RTLD_GLOBAL: c_int = 0x100;
/// `RTLD_LAZY`, which `dlfcn_globallookup`'s `dlopen(NULL, …)` uses.
const RTLD_LAZY: c_int = 1;

// `DSO_MAX_TRANSLATED_SIZE` is `#define`d as 256 in the authority and read by no code
// path — a leftover of the `dlopen`-flag "hack" its own comment describes. There is
// nothing to reproduce, and this note is the record of that rather than a silent gap.

/// `static int dlfcn_load(DSO *dso)`
///
/// # Safety
/// `dso` must be live with a filename set.
unsafe extern "C" fn dlfcn_load(dso: *mut Dso) -> c_int {
    // SAFETY: `dso` is live; `DSO_convert_filename` with a NULL name translates the
    // stored one and answers a fresh allocation.
    let filename = unsafe { crate::dso::DSO_convert_filename(dso, ptr::null()) }.cast::<c_char>();
    let mut flags = DLOPEN_FLAG;
    // SAFETY: reading `errno` is safe for any caller.
    let saveerrno = unsafe { errno() };

    if filename.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_102) };
        return 0;
    }
    // SAFETY: `dso` is live.
    if unsafe { (*dso).flags } & DSO_FLAG_GLOBAL_SYMBOLS != 0 {
        flags |= RTLD_GLOBAL;
    }
    // SAFETY: `filename` is NUL-terminated by the converter.
    let ptr_ = unsafe { dlopen(filename, flags) };
    if ptr_.is_null() {
        // SAFETY: the site is constant and `filename` is NUL-terminated; the message
        // carries `dlerror()`'s text.
        unsafe { raise_data_load_failed(&err_sites::DSO_DLFCN_115, filename) };
        // SAFETY: `filename` came from `CRYPTO_strdup` inside the converter.
        unsafe { CRYPTO_free(filename.cast::<c_void>(), FILE, LINE_FREE_TRANSLATED) };
        return 0;
    }
    // SAFETY: writing `errno` is the authority's `set_sys_error`.
    unsafe { set_errno(saveerrno) };
    // SAFETY: `dso` is live.
    if unsafe { meth_data_push(dso, ptr_) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_125) };
        // SAFETY: `filename` is still owned here, and the handle was not pushed.
        unsafe {
            CRYPTO_free(filename.cast::<c_void>(), FILE, LINE_FREE_TRANSLATED);
            dlclose(ptr_);
        }
        return 0;
    }
    // `dso->loaded_filename = filename` — the object takes ownership of the translated
    // name, which is why the success path frees nothing.
    // SAFETY: `dso` is live and `filename` is the allocation just made.
    unsafe { (*dso).loaded_filename = filename };
    1
}

/// The authority's translation unit.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c".as_ptr();
/// `dlfcn_load`'s error-path `OPENSSL_free(filename)`.
const LINE_FREE_TRANSLATED: c_int = 133;
/// `dlfcn_merger`'s joins.
const LINE_MALLOC_MERGED: c_int = 234;
/// `dlfcn_name_converter`'s `OPENSSL_malloc(rsize)`.
const LINE_MALLOC_TRANSLATED: c_int = 258;

/// `static int dlfcn_unload(DSO *dso)`
///
/// An empty stack answers **1** — there is nothing to unload and that is not a failure.
/// A popped NULL is `DSO_R_NULL_HANDLE`, and the authority pushes it **back** so that a
/// retry sees the same state.
///
/// # Safety
/// `dso` must be NULL or live.
unsafe extern "C" fn dlfcn_unload(dso: *mut Dso) -> c_int {
    if dso.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_143) };
        return 0;
    }
    // SAFETY: `dso` is live.
    if unsafe { meth_data_num(dso) } < 1 {
        return 1;
    }
    // SAFETY: the stack has at least one entry.
    let ptr_ = unsafe { meth_data_pop(dso) };
    if ptr_.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_150) };
        // SAFETY: pushing the NULL back restores the state for a retry.
        unsafe { meth_data_push(dso, ptr_) };
        return 0;
    }
    // SAFETY: `ptr_` is the handle `dlfcn_load` pushed. `dlclose`'s answer is discarded,
    // as the authority's comment says it is unaware of any error from it.
    unsafe { dlclose(ptr_) };
    1
}

/// `static DSO_FUNC_TYPE dlfcn_bind_func(DSO *dso, const char *symname)`
///
/// # Safety
/// `dso` must be NULL or live and `symname` NULL or NUL-terminated.
unsafe extern "C" fn dlfcn_bind_func(dso: *mut Dso, symname: *const c_char) -> DsoFuncType {
    if dso.is_null() || symname.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_171) };
        return None;
    }
    // SAFETY: `dso` is live.
    let n = unsafe { meth_data_num(dso) };
    if n < 1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_175) };
        return None;
    }
    // The authority reads the **top** entry, not the first.
    // SAFETY: `n - 1` is in range.
    let handle = unsafe { meth_data_value(dso, n - 1) };
    if handle.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_180) };
        return None;
    }
    // SAFETY: `handle` is a live `dlopen` handle and `symname` is NUL-terminated.
    let sym = unsafe { dlsym(handle, symname) };
    if sym.is_null() {
        // SAFETY: as the raise above; the message carries `dlerror()`.
        unsafe { raise_data_sym_failure(&err_sites::DSO_DLFCN_185, symname) };
        return None;
    }
    // The authority's `union { DSO_FUNC_TYPE sym; void *dlret; } u;` — the pointer is
    // reinterpreted as a function pointer. That is the only thing a `dlsym` answer can
    // be, and `DSO_bind_func`'s caller casts it to the real prototype.
    // SAFETY: nothing calls through it here; the bits are carried through unchanged.
    Some(unsafe { core::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(sym) })
}

/// `static char *dlfcn_merger(DSO *dso, const char *filespec1, const char *filespec2)`
///
/// # Safety
/// Both specs must be NULL or NUL-terminated.
unsafe extern "C" fn dlfcn_merger(
    dso: *mut Dso,
    filespec1: *const c_char,
    filespec2: *const c_char,
) -> *mut c_char {
    let _ = dso;
    if filespec1.is_null() && filespec2.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_198) };
        return ptr::null_mut();
    }
    // SAFETY: every read below is of a NUL-terminated caller string.
    unsafe {
        // A rooted first spec rules, and so does a missing second one.
        if filespec2.is_null() || (!filespec1.is_null() && *filespec1 == b'/' as c_char) {
            return CRYPTO_strdup(filespec1, FILE, LINE_MALLOC_MERGED);
        }
        if filespec1.is_null() {
            return CRYPTO_strdup(filespec2, FILE, LINE_MALLOC_MERGED);
        }
        // The second spec is assumed to be a directory and is not checked.
        let spec2len = strlen(filespec2) as isize;
        let mut len = spec2len + strlen(filespec1) as isize;
        let mut spec2len = spec2len;
        if spec2len > 0 && *filespec2.offset(spec2len - 1) == b'/' as c_char {
            spec2len -= 1;
            len -= 1;
        }
        let merged = CRYPTO_malloc((len + 2) as usize, FILE, LINE_MALLOC_MERGED).cast::<c_char>();
        if merged.is_null() {
            return ptr::null_mut();
        }
        // `strcpy(merged, filespec2)` — `spec2len` bytes of it.
        ptr::copy_nonoverlapping(filespec2, merged, spec2len as usize);
        *merged.offset(spec2len) = b'/' as c_char;
        // `strcpy(&merged[spec2len + 1], filespec1)`.
        let n1 = strlen(filespec1);
        ptr::copy_nonoverlapping(filespec1, merged.offset(spec2len + 1), n1 + 1);
        merged
    }
}

/// `static char *dlfcn_name_converter(DSO *dso, const char *filename)`
///
/// # Safety
/// `filename` must be NUL-terminated.
unsafe extern "C" fn dlfcn_name_converter(dso: *mut Dso, filename: *const c_char) -> *mut c_char {
    // SAFETY: `filename` is NUL-terminated.
    let len = unsafe { strlen(filename) };
    let mut rsize = len + 1;
    // SAFETY: `filename` is NUL-terminated, so `strchr` answers NULL for no slash.
    let transform = unsafe { strchr(filename, b'/' as c_int) }.is_null();
    if transform {
        rsize += DSO_EXTENSION.len();
        // SAFETY: `dso` may be NULL — `DSO_flags` accepts that.
        if unsafe { crate::dso::DSO_flags(dso) } & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY == 0 {
            rsize += 3; // the length of "lib"
        }
    }
    let translated = CRYPTO_malloc(rsize, FILE, LINE_MALLOC_TRANSLATED).cast::<c_char>();
    if translated.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DSO_DLFCN_260) };
        return ptr::null_mut();
    }
    // SAFETY: `translated` has `rsize` writable bytes, and the assembled string is
    // `filename` plus an optional "lib" plus the extension — which is what `rsize` was
    // sized for.
    unsafe {
        let mut out = 0usize;
        if transform {
            // SAFETY: as above.
            let ext_only = crate::dso::DSO_flags(dso) & DSO_FLAG_NAME_TRANSLATION_EXT_ONLY != 0;
            if !ext_only {
                ptr::copy_nonoverlapping(b"lib".as_ptr().cast::<c_char>(), translated, 3);
                out += 3;
            }
            ptr::copy_nonoverlapping(filename, translated.add(out), len);
            out += len;
            ptr::copy_nonoverlapping(
                DSO_EXTENSION.as_ptr().cast::<c_char>(),
                translated.add(out),
                DSO_EXTENSION.len(),
            );
            out += DSO_EXTENSION.len();
        } else {
            ptr::copy_nonoverlapping(filename, translated, len + 1);
            out += len + 1;
        }
        *translated.add(out) = 0;
        translated
    }
}

/// `static int dlfcn_pathbyaddr(void *addr, char *path, int sz)`
///
/// # Safety
/// `path` must be NULL or have `sz` writable bytes.
unsafe extern "C" fn dlfcn_pathbyaddr(addr: *mut c_void, path: *mut c_char, sz: c_int) -> c_int {
    let mut dli = DlInfo {
        dli_fname: ptr::null(),
        dli_fbase: ptr::null_mut(),
        dli_sname: ptr::null(),
        dli_saddr: ptr::null_mut(),
    };
    let target = if addr.is_null() {
        // "The address of this function" — the authority's union of the function
        // pointer with a `void *`.
        dlfcn_pathbyaddr as *const c_void
    } else {
        addr
    };
    // SAFETY: `target` is a live code address and `dli` is a live `Dl_info`.
    if unsafe { dladdr(target, &mut dli) } != 0 {
        // SAFETY: a successful `dladdr` fills `dli_fname` with a NUL-terminated path.
        let fname = dli.dli_fname;
        // SAFETY: `fname` is NUL-terminated.
        let len = unsafe { strlen(fname) } as c_int;
        if sz <= 0 {
            return len + 1;
        }
        let mut len = len;
        if len >= sz {
            len = sz - 1;
        }
        // SAFETY: the caller guarantees `sz` writable bytes at `path`, and
        // `len <= sz - 1`.
        unsafe {
            ptr::copy_nonoverlapping(fname, path, len as usize);
            *path.add(len as usize) = 0;
        }
        return len + 1;
    }
    // The failure path is the authority's `ERR_add_error_data(2, "dlfcn_pathbyaddr():
    // ", dlerror())` -- a single **append** with no `ERR_raise`, and with the literal
    // `<NULL>` substituted for a NULL `dlerror()`. `dladdr` does not set `dlerror`'s
    // state, so the substitution really is reachable here: a caller that drained the
    // error gets `dlfcn_pathbyaddr(): <NULL>` on the authority, and did not before this
    // was corrected. `RT-DSO` compares the text.
    // SAFETY: the helper reads `dlerror()` and appends to the current error slot.
    unsafe { crate::dso::add_error_data_pathbyaddr() };
    -1
}

/// `static void *dlfcn_globallookup(const char *name)`
///
/// `dlopen(NULL, RTLD_LAZY)` gives a handle on the whole process, `dlsym` looks the name
/// up in it, and the handle is closed immediately — so the lookup sees **every** loaded
/// module rather than one library's own symbols.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe extern "C" fn dlfcn_globallookup(name: *const c_char) -> *mut c_void {
    // SAFETY: a NULL filename and `RTLD_LAZY` are the process handle.
    let handle = unsafe { dlopen(ptr::null(), RTLD_LAZY) };
    if handle.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `handle` is live and `name` is NUL-terminated.
    let ret = unsafe { dlsym(handle, name) };
    // SAFETY: `handle` came from `dlopen`.
    unsafe { dlclose(handle) };
    ret
}

/// `static DSO_METHOD dso_meth_dlfcn` — the eleven fields in `dso_local.h`'s order.
///
/// Three are NULL and their NULLness is load-bearing: a NULL `ctrl` is what makes
/// `DSO_ctrl`'s `DSO_R_UNSUPPORTED` arm reachable, and NULL `init`/`finish` are what make
/// `DSO_new_method` and `DSO_free` skip those hooks entirely.
// The method struct holds raw pointers and function pointers, none of which the
// authority mutates: `dso_meth_dlfcn` is a `static` there too. The `Sync` claim is
// therefore the same one the C declaration makes.
// SAFETY: `DsoMethod`'s fields are `'static` pointers and plain function pointers, and
// no code path writes through the reference taken here.
unsafe impl Sync for DsoMethod {}

static DSO_METH_DLFCN: DsoMethod = DsoMethod {
    name: c"OpenSSL 'dlfcn' shared library method".as_ptr(),
    dso_load: Some(dlfcn_load),
    dso_unload: Some(dlfcn_unload),
    dso_bind_func: Some(dlfcn_bind_func),
    dso_ctrl: None,
    dso_name_converter: Some(dlfcn_name_converter),
    dso_merger: Some(dlfcn_merger),
    init: None,
    finish: None,
    pathbyaddr: Some(dlfcn_pathbyaddr),
    globallookup: Some(dlfcn_globallookup),
};

/// `DSO_METHOD *DSO_METHOD_openssl(void)`
///
/// The same address on every call, so a caller can compare it.
#[no_mangle]
pub extern "C" fn DSO_METHOD_openssl() -> *mut DsoMethod {
    guard_ffi(ptr::null_mut(), || {
        // The static is immutable; the API hands out a mutable pointer because the
        // authority's method struct is not `const`.
        core::ptr::addr_of!(DSO_METH_DLFCN).cast_mut()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dso::{
        DSO_convert_filename, DSO_free, DSO_load, DSO_merge, DSO_new, DSO_set_filename,
        DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, DSO_FLAG_NO_NAME_TRANSLATION,
    };
    use core::ffi::c_long;

    #[test]
    fn the_method_is_static_and_its_name_is_the_authority_s() {
        let a = DSO_METHOD_openssl();
        assert!(!a.is_null());
        assert_eq!(a, DSO_METHOD_openssl(), "the same address every call");
        // SAFETY: `a` is the `'static` method.
        unsafe {
            assert_eq!(
                core::ffi::CStr::from_ptr((*a).name).to_bytes(),
                b"OpenSSL 'dlfcn' shared library method"
            );
            assert!((*a).dso_ctrl.is_none());
            assert!((*a).init.is_none());
            assert!((*a).finish.is_none());
        }
    }

    #[test]
    fn the_name_translator_keys_on_the_slash_and_not_on_being_translated() {
        // SAFETY: `d` is live and the literals are NUL-terminated.
        unsafe {
            let d = DSO_new();
            // No slash: prefixed and suffixed.
            let a = DSO_convert_filename(d, c"foo".as_ptr());
            assert_eq!(core::ffi::CStr::from_ptr(a).to_bytes(), b"libfoo.so");
            CRYPTO_free(a.cast::<c_void>(), FILE, 0);
            // Already suffix'd, and no slash: translated *again*.
            let b = DSO_convert_filename(d, c"libfoo.so".as_ptr());
            assert_eq!(
                core::ffi::CStr::from_ptr(b).to_bytes(),
                b"liblibfoo.so.so",
                "the rule is `no slash`, not `not already translated`: the existing \
                 extension is kept and another is appended"
            );
            CRYPTO_free(b.cast::<c_void>(), FILE, 0);
            // A slash anywhere suppresses the translation entirely.
            let c1 = DSO_convert_filename(d, c"/a/b/foo".as_ptr());
            assert_eq!(core::ffi::CStr::from_ptr(c1).to_bytes(), b"/a/b/foo");
            CRYPTO_free(c1.cast::<c_void>(), FILE, 0);
            // EXT_ONLY drops the `lib` prefix but keeps the extension.
            assert_eq!(
                crate::dso::DSO_ctrl(
                    d,
                    2,
                    c_long::from(DSO_FLAG_NAME_TRANSLATION_EXT_ONLY),
                    ptr::null_mut()
                ),
                0
            );
            let e = DSO_convert_filename(d, c"foo".as_ptr());
            assert_eq!(core::ffi::CStr::from_ptr(e).to_bytes(), b"foo.so");
            CRYPTO_free(e.cast::<c_void>(), FILE, 0);
            // NO_NAME_TRANSLATION returns the input unchanged, by `strdup`.
            assert_eq!(
                crate::dso::DSO_ctrl(
                    d,
                    2,
                    c_long::from(DSO_FLAG_NO_NAME_TRANSLATION),
                    ptr::null_mut()
                ),
                0
            );
            let f = DSO_convert_filename(d, c"foo".as_ptr());
            assert_eq!(core::ffi::CStr::from_ptr(f).to_bytes(), b"foo");
            CRYPTO_free(f.cast::<c_void>(), FILE, 0);
            DSO_free(d);
        }
    }

    #[test]
    fn the_merger_has_four_shapes_and_strips_one_trailing_slash() {
        // SAFETY: `d` is live and every literal is NUL-terminated.
        unsafe {
            let d = DSO_new();
            // `String` is not reachable without `alloc`, so the merge result is
            // compared as the bytes it is.
            let join = |a: &core::ffi::CStr, b: &core::ffi::CStr| -> [u8; 16] {
                let m = DSO_merge(d, a.as_ptr(), b.as_ptr());
                assert!(!m.is_null());
                let bytes = core::ffi::CStr::from_ptr(m).to_bytes();
                let mut out = [0u8; 16];
                out[..bytes.len()].copy_from_slice(bytes);
                CRYPTO_free(m.cast::<c_void>(), FILE, 0);
                out
            };
            assert_eq!(&join(c"a", c"b")[..3], b"b/a", "dir then name");
            assert_eq!(
                &join(c"a", c"/d/")[..4],
                b"/d/a",
                "one trailing slash is removed"
            );
            assert_eq!(&join(c"/a", c"/d")[..2], b"/a", "a rooted first spec rules");
            assert_eq!(
                &join(c"a", c"")[..2],
                b"/a",
                "an EMPTY second spec is not a missing one: the join treats it as a \
                 directory of length zero, so the answer is `/a` and not `a`"
            );
            DSO_free(d);
        }
    }

    /// The refusals `DSO_load` can make **without** a real library, which is everything
    /// a unit test may honestly assert about it. A *successful* load needs a shared
    /// object and a process that exports `DSO_new`, and that is `RT-DSO`'s job: the
    /// probe links the library under test, which a unit test cannot.
    #[test]
    fn loads_that_cannot_succeed_refuse_with_their_own_reasons() {
        // SAFETY: every literal is NUL-terminated and every object is released below.
        unsafe {
            // A name that cannot be loaded: the method's own failure, and no object is
            // returned to the caller because `DSO_load` allocated it.
            assert!(DSO_load(
                ptr::null_mut(),
                c"/nonexistent/openssl-rs/nope.so".as_ptr(),
                ptr::null_mut(),
                0
            )
            .is_null());

            // An object with no name at all, and no filename argument: `NO_FILENAME`.
            let d = DSO_new();
            assert!(DSO_load(d, ptr::null(), ptr::null_mut(), 0).is_null());
            // The caller's object survives the failure, because `DSO_load` did not
            // allocate it.
            assert_eq!(DSO_free(d), 1);

            // A name that loads nowhere: the load fails and the caller's object is
            // still theirs.
            let d2 = DSO_new();
            assert_eq!(
                DSO_set_filename(d2, c"/nonexistent/openssl-rs/nope.so".as_ptr()),
                1
            );
            assert!(DSO_load(d2, ptr::null(), ptr::null_mut(), 0).is_null());
            assert_eq!(DSO_free(d2), 1);
        }
    }

    #[test]
    fn binding_on_an_object_that_has_loaded_nothing_is_refused() {
        // SAFETY: `d` is live and the literal is NUL-terminated.
        unsafe {
            let d = DSO_new();
            // The method-data stack is empty, so `dlfcn_bind_func` answers
            // `DSO_R_STACK_ERROR` through `DSO_bind_func`.
            assert!(crate::dso::DSO_bind_func(d, c"DSO_new".as_ptr()).is_none());
            // A NULL symbol name is refused before the stack is consulted.
            assert!(crate::dso::DSO_bind_func(d, ptr::null()).is_none());
            DSO_free(d);
        }
    }
}
