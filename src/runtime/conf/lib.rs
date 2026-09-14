//! Phase 4 — CONF: `crypto/conf/conf_lib.c`, the public accessor and bridge
//! layer.
//!
//! Two APIs live here, and the reason is historical rather than architectural:
//!
//! * the **classic** API (`CONF_load`, `CONF_get_string`, `CONF_free`, …) works on
//!   a bare `LHASH_OF(CONF_VALUE)` the caller owns, and every one of those
//!   functions builds a `CONF` **by value on the stack** (`CONF_set_nconf`) and
//!   forwards. The zero-sized wrapper is why `NCONF_free_data` is reachable from
//!   `CONF_free` at all;
//! * the **NCONF** API works on a heap `CONF` created by a method table.
//!
//! ## The cached default method
//!
//! `CONF_set_nconf` lazily installs `NCONF_default()` into a file-scope pointer
//! that `CONF_set_default_method` can replace. The authority uses a plain
//! `static CONF_METHOD *` and therefore has a benign data race if two threads
//! first enter at once; the candidate uses an atomic so the race cannot become a
//! torn pointer. That is a safety divergence in *mechanism* only: the value a
//! caller observes is the same, and single-threaded order is identical.
//!
//! ## Two error-convention details worth naming
//!
//! * `NCONF_get_string` raises `CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE` when the
//!   configuration is NULL — because a NULL configuration still consults the
//!   environment, so the failure is "we looked and there was nothing", not "there
//!   is no configuration". When there *is* a configuration the reason is
//!   `CONF_R_NO_VALUE`, with `group=`/`name=` attached.
//! * `CONF_get_number` and `_CONF_get_number` bracket their work in
//!   `ERR_set_mark`/`ERR_pop_to_mark`, so a failed conversion leaves the queue
//!   exactly as it was. A caller therefore cannot detect a missing key through
//!   the error queue, which is the documented contract and not an oversight.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{self, FILE};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::conf::api::{_CONF_get_section_values, _CONF_get_string};
use crate::runtime::conf::def::NCONF_default;
use crate::runtime::conf::types::{Conf, ConfMethod, ConfValue};
use crate::runtime::err::err_sites::{
    CONF_LIB_157, CONF_LIB_191, CONF_LIB_254, CONF_LIB_267, CONF_LIB_279, CONF_LIB_289,
    CONF_LIB_294, CONF_LIB_313, CONF_LIB_316, CONF_LIB_340, CONF_LIB_359, CONF_LIB_387,
    CONF_LIB_399, CONF_LIB_58, CONF_LIB_75,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::lhash::OpenSslLhash;
use crate::runtime::stack::{OPENSSL_sk_new, OPENSSL_sk_push, OPENSSL_sk_sort, OpenSslStack};

/// `static CONF_METHOD *default_CONF_method = NULL`
static DEFAULT_CONF_METHOD: AtomicPtr<ConfMethod> = AtomicPtr::new(ptr::null_mut());

/// `void CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash)`
///
/// Installs the default method into a caller-provided `CONF` and then adopts the
/// caller's hash. The method's `init` zeroes the structure, so the order matters:
/// the hash pointer is written *after* the zeroing.
///
/// The classic API calls this with a stack `CONF`, which is why `CONF` must be
/// `repr(C)` with the authority's field order.
///
/// # Safety
/// `conf` must be writable for `size_of::<Conf>()`; `hash` NULL or a live
/// `LHASH_OF(CONF_VALUE)`.
#[no_mangle]
pub unsafe extern "C" fn CONF_set_nconf(conf: *mut Conf, hash: *mut OpenSslLhash) {
    guard_ffi((), || {
        if conf.is_null() {
            return;
        }
        let mut meth = DEFAULT_CONF_METHOD.load(Ordering::Relaxed);
        if meth.is_null() {
            meth = NCONF_default();
            DEFAULT_CONF_METHOD.store(meth, Ordering::Relaxed);
        }
        // SAFETY: `meth` is `NCONF_default()` or a caller's table, either way a
        // live method with an `init`; `conf` is writable per the caller's contract.
        match unsafe { (*meth).init } {
            Some(init) => {
                // SAFETY: `init` is the live method's own constructor and `conf`
                // is writable for `size_of::<Conf>()` per the caller's contract;
                // `init` is what zeroes that storage.
                unsafe { init(conf) };
            }
            None => return,
        }
        // SAFETY: `conf` was just initialised and is writable.
        unsafe { (*conf).data = hash };
    })
}

/// `int CONF_set_default_method(CONF_METHOD *meth)`
///
/// Installs a replacement for the method `CONF_set_nconf` will use. Always
/// succeeds, including for NULL, which makes the next `CONF_set_nconf` fall back
/// to the default again.
#[no_mangle]
pub extern "C" fn CONF_set_default_method(meth: *mut ConfMethod) -> c_int {
    guard_ffi(0, || {
        DEFAULT_CONF_METHOD.store(meth, Ordering::Relaxed);
        1
    })
}

/// `LHASH_OF(CONF_VALUE) *CONF_load(LHASH_OF(CONF_VALUE) *conf, const char *file, long *eline)`
///
/// Opens the file in binary mode, so a `\r\n` in the input reaches the parser and
/// the parser's own trailing-newline trim is what removes it. The BIO is released
/// here, before the result is returned.
///
/// # Safety
/// `conf` NULL or live; `file` NUL-terminated; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn CONF_load(
    conf: *mut OpenSslLhash,
    file: *const c_char,
    eline: *mut c_long,
) -> *mut OpenSslLhash {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `file` is NUL-terminated per the caller's contract.
        let inbio = unsafe { BIO_new_file(file, c"rb".as_ptr()) };
        if inbio.is_null() {
            // `ERR_raise(ERR_LIB_CONF, ERR_R_SYS_LIB)`: the BIO already raised its
            // own error, and it stays on the queue beneath this one.
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_58) };
            return ptr::null_mut();
        }
        // SAFETY: `conf` and `inbio` are live; `eline` is NULL or writable.
        let ret = unsafe { CONF_load_bio(conf, inbio, eline) };
        // SAFETY: `inbio` is a live BIO owned by this call.
        unsafe { BIO_free(inbio) };
        ret
    })
}

/// `LHASH_OF(CONF_VALUE) *CONF_load_fp(LHASH_OF(CONF_VALUE) *conf, FILE *fp, long *eline)`
///
/// The `FILE *` is wrapped with `BIO_NOCLOSE`, so the caller's stream survives.
///
/// # Safety
/// `conf` NULL or live; `fp` a live `FILE *`; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn CONF_load_fp(
    conf: *mut OpenSslLhash,
    fp: *mut FILE,
    eline: *mut c_long,
) -> *mut OpenSslLhash {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `fp` is a live stream per the caller's contract.
        let btmp = unsafe { BIO_new_fp(fp.cast::<c_void>(), BIO_NOCLOSE) };
        if btmp.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_75) };
            return ptr::null_mut();
        }
        // SAFETY: `conf` and `btmp` are live.
        let ret = unsafe { CONF_load_bio(conf, btmp, eline) };
        // SAFETY: `btmp` is a live BIO owned by this call; the stream it wraps is
        // not because of `BIO_NOCLOSE`.
        unsafe { BIO_free(btmp) };
        ret
    })
}

/// `LHASH_OF(CONF_VALUE) *CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp, long *eline)`
///
/// Bridges the classic API onto `NCONF_load_bio` and returns the *hash* the
/// parser filled in, which is the caller's own pointer when the load succeeded.
///
/// # Safety
/// `conf` NULL or a live hash; `bp` a live BIO; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn CONF_load_bio(
    conf: *mut OpenSslLhash,
    bp: *mut Bio,
    eline: *mut c_long,
) -> *mut OpenSslLhash {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: all-zero is a valid bit pattern for `Conf` (pointers and
        // integers), and `ctmp` is owned stack storage of exactly that type.
        let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
        // SAFETY: `ctmp` is writable storage of the right size.
        unsafe { CONF_set_nconf(&mut ctmp, conf) };
        // SAFETY: `ctmp` is initialised; `bp` is live.
        if unsafe { NCONF_load_bio(&mut ctmp, bp, eline) } != 0 {
            // SAFETY: `ctmp` is live.
            return ctmp.data;
        }
        ptr::null_mut()
    })
}

/// `STACK_OF(CONF_VALUE) *CONF_get_section(LHASH_OF(CONF_VALUE) *conf, const char *section)`
///
/// A NULL hash is a NULL answer rather than a raise; the reason is that the
/// classic API's callers use NULL to mean "no configuration loaded yet".
///
/// # Safety
/// `conf` NULL or live; `section` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_get_section(
    conf: *mut OpenSslLhash,
    section: *const c_char,
) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if conf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: all-zero is a valid bit pattern for `Conf`, and `ctmp` is owned
        // stack storage of exactly that type.
        let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
        // SAFETY: `ctmp` is writable storage of the right size.
        unsafe { CONF_set_nconf(&mut ctmp, conf) };
        // SAFETY: `ctmp` is initialised; `section` is NULL or NUL-terminated.
        unsafe { NCONF_get_section(&ctmp, section) }
    })
}

/// `char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group, const char *name)`
///
/// # Safety
/// `conf` NULL or live; `group`/`name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_get_string(
    conf: *mut OpenSslLhash,
    group: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if conf.is_null() {
            // SAFETY: `group`/`name` are NULL or NUL-terminated.
            return unsafe { NCONF_get_string(ptr::null(), group, name) };
        }
        // SAFETY: all-zero is a valid bit pattern for `Conf`, and `ctmp` is owned
        // stack storage of exactly that type.
        let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
        // SAFETY: `ctmp` is writable storage of the right size.
        unsafe { CONF_set_nconf(&mut ctmp, conf) };
        // SAFETY: `ctmp` is initialised; the strings are NULL or NUL-terminated.
        unsafe { NCONF_get_string(&ctmp, group, name) }
    })
}

/// `long CONF_get_number(LHASH_OF(CONF_VALUE) *conf, const char *group, const char *name)`
///
/// The mark/pop pair is the whole point: this returns 0 for both "the value is 0"
/// and "there is no value", and deliberately leaves no trace in the error queue.
///
/// # Safety
/// `conf` NULL or live; `group`/`name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn CONF_get_number(
    conf: *mut OpenSslLhash,
    group: *const c_char,
    name: *const c_char,
) -> c_long {
    guard_ffi(0, || {
        let mut result: c_long = 0;
        // SAFETY: the ERR mark functions take no arguments.
        crate::runtime::err::ERR_set_mark();
        let status = if conf.is_null() {
            // SAFETY: `group`/`name` are NULL or NUL-terminated.
            unsafe { NCONF_get_number_e(ptr::null(), group, name, &mut result) }
        } else {
            // SAFETY: all-zero is a valid bit pattern for `Conf`, and `ctmp` is
            // owned stack storage of exactly that type.
            let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
            // SAFETY: `ctmp` is writable storage of the right size.
            unsafe { CONF_set_nconf(&mut ctmp, conf) };
            // SAFETY: `ctmp` is initialised; the strings are NULL or
            // NUL-terminated.
            unsafe { NCONF_get_number_e(&ctmp, group, name, &mut result) }
        };
        // SAFETY: as above.
        crate::runtime::err::ERR_pop_to_mark();
        if status == 0 {
            0
        } else {
            result
        }
    })
}

/// `void CONF_free(LHASH_OF(CONF_VALUE) *conf)`
///
/// Frees the *contents* of the caller's hash and the hash itself; the caller's
/// pointer is left dangling, exactly as the authority leaves it.
///
/// # Safety
/// `conf` a live hash whose contents must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn CONF_free(conf: *mut OpenSslLhash) {
    guard_ffi((), || {
        // SAFETY: all-zero is a valid bit pattern for `Conf`, and `ctmp` is owned
        // stack storage of exactly that type.
        let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
        // SAFETY: `ctmp` is writable storage of the right size.
        unsafe { CONF_set_nconf(&mut ctmp, conf) };
        // SAFETY: `ctmp` is initialised.
        unsafe { NCONF_free_data(&mut ctmp) };
    })
}

/// `int CONF_dump_fp(LHASH_OF(CONF_VALUE) *conf, FILE *out)`
///
/// # Safety
/// `conf` live; `out` a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn CONF_dump_fp(conf: *mut OpenSslLhash, out: *mut FILE) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `out` is a live stream per the caller's contract.
        let btmp = unsafe { BIO_new_fp(out.cast::<c_void>(), BIO_NOCLOSE) };
        if btmp.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_157) };
            return 0;
        }
        // SAFETY: `conf` and `btmp` are live.
        let ret = unsafe { CONF_dump_bio(conf, btmp) };
        // SAFETY: `btmp` is a live BIO owned by this call.
        unsafe { BIO_free(btmp) };
        ret
    })
}

/// `int CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out)`
///
/// # Safety
/// `conf` live; `out` a live BIO.
#[no_mangle]
pub unsafe extern "C" fn CONF_dump_bio(conf: *mut OpenSslLhash, out: *mut Bio) -> c_int {
    guard_ffi(0, || {
        // SAFETY: all-zero is a valid bit pattern for `Conf`, and `ctmp` is owned
        // stack storage of exactly that type.
        let mut ctmp = unsafe { core::mem::zeroed::<Conf>() };
        // SAFETY: `ctmp` is writable storage of the right size.
        unsafe { CONF_set_nconf(&mut ctmp, conf) };
        // SAFETY: `ctmp` is initialised and `out` is live.
        unsafe { NCONF_dump_bio(&ctmp, out) }
    })
}

/// `CONF *NCONF_new_ex(OSSL_LIB_CTX *libctx, CONF_METHOD *meth)`
///
/// A NULL method means the default one. The `libctx` is stored verbatim and is
/// readable through `NCONF_get0_libctx`; this stratum treats it as opaque because
/// `OSSL_LIB_CTX` is Phase 6.
///
/// # Safety
/// `meth` NULL or a live method table.
#[no_mangle]
pub unsafe extern "C" fn NCONF_new_ex(libctx: *mut c_void, meth: *mut ConfMethod) -> *mut Conf {
    guard_ffi(ptr::null_mut(), || {
        let meth = if meth.is_null() {
            NCONF_default()
        } else {
            meth
        };
        // SAFETY: `meth` is live and has a `create`.
        let ret = match unsafe { (*meth).create } {
            // SAFETY: `create` is the live method's own constructor and `meth` is
            // the live method table it expects.
            Some(create) => unsafe { create(meth) },
            None => ptr::null_mut(),
        };
        if ret.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_191) };
            return ptr::null_mut();
        }
        // SAFETY: `ret` is a live configuration.
        unsafe { (*ret).libctx = libctx };
        ret
    })
}

/// `CONF *NCONF_new(CONF_METHOD *meth)`
///
/// # Safety
/// `meth` NULL or a live method table.
#[no_mangle]
pub unsafe extern "C" fn NCONF_new(meth: *mut ConfMethod) -> *mut Conf {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded under the caller's contract.
        unsafe { NCONF_new_ex(ptr::null_mut(), meth) }
    })
}

/// `void NCONF_free(CONF *conf)`
///
/// # Safety
/// `conf` NULL or a live configuration that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn NCONF_free(conf: *mut Conf) {
    guard_ffi((), || {
        if conf.is_null() {
            return;
        }
        // SAFETY: `conf` is live; `destroy` is set for every method this crate
        // publishes and for any method a caller reached this point with.
        if let Some(destroy) = unsafe { (*(*conf).meth).destroy } {
            // SAFETY: `destroy` is the live method's own destructor and `conf` is
            // the live configuration that method's `create` produced.
            unsafe { destroy(conf) };
        }
    })
}

/// `void NCONF_free_data(CONF *conf)`
///
/// Releases the configuration's *data*, leaving the `CONF` itself alive. Note
/// that the authority leaves `conf->data` dangling rather than clearing it, so a
/// second call is a caller-side double-free; that is reproduced rather than made
/// idempotent (see [`_CONF_free_data`]).
///
/// # Safety
/// `conf` NULL or live, whose data must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn NCONF_free_data(conf: *mut Conf) {
    guard_ffi((), || {
        if conf.is_null() {
            return;
        }
        // SAFETY: `conf` is live.
        if let Some(destroy_data) = unsafe { (*(*conf).meth).destroy_data } {
            // SAFETY: `destroy_data` is the live method's own data destructor and
            // `conf` is the live configuration it was created for.
            unsafe { destroy_data(conf) };
        }
    })
}

/// `OSSL_LIB_CTX *NCONF_get0_libctx(const CONF *conf)`
///
/// Returns exactly what `NCONF_new_ex` was given, including NULL. Note the
/// missing NULL guard: the authority dereferences `conf` here, so a NULL
/// configuration is a caller error rather than a defined call, and this
/// reproduces that (it will fault rather than return NULL).
///
/// # Safety
/// `conf` must be a live configuration.
#[no_mangle]
pub unsafe extern "C" fn NCONF_get0_libctx(conf: *const Conf) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `conf` is live per the caller's contract.
        unsafe { (*conf).libctx }
    })
}

/// `static int section_name_cmp(OPENSSL_CSTRING const *a, OPENSSL_CSTRING const *b)`
///
/// The stack's comparator receives pointers to *slots*, so each argument is
/// dereferenced once to reach the string.
///
/// # Safety
/// Both arguments must point at slots holding NUL-terminated strings.
unsafe extern "C" fn section_name_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack passes pointers to its own slots.
    let a = unsafe { *(a as *const *const c_char) };
    // SAFETY: as above; `b` is the other slot the stack passed.
    let b = unsafe { *(b as *const *const c_char) };
    // SAFETY: both are NUL-terminated strings owned by the configuration.
    unsafe { sys::strcmp(a, b) }
}

/// `static void collect_section_name(const CONF_VALUE *v, SECTION_NAMES *names)`
///
/// A section is a `CONF_VALUE` whose `name` is NULL, and the string pushed is the
/// section's own `section` pointer — not a copy, so it is invalidated by freeing
/// the configuration.
///
/// # Safety
/// `v` must be a live entry; `names` a live stack.
unsafe extern "C" fn collect_section_name(v: *mut c_void, names: *mut c_void) {
    let v = v as *const ConfValue;
    // SAFETY: `v` is a live entry per the callback's contract.
    if !unsafe { (*v).name }.is_null() {
        return;
    }
    // SAFETY: `names` is the stack the caller passed; a failure to push cannot be
    // reported through this signature, so it is ignored as the authority does.
    unsafe {
        OPENSSL_sk_push(names as *mut OpenSslStack, (*v).section.cast::<c_void>());
    }
}

/// `STACK_OF(OPENSSL_CSTRING) *NCONF_get_section_names(const CONF *cnf)`
///
/// The names are **sorted** with `strcmp` before being returned, and they are
/// borrowed from the configuration rather than duplicated. A NULL configuration
/// is not guarded in the authority and faults here too.
///
/// # Safety
/// `cnf` must be a live configuration with a non-NULL `data`.
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_section_names(cnf: *const Conf) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `section_name_cmp` has the comparator signature the stack wants.
        let names = OPENSSL_sk_new(Some(section_name_cmp));
        if names.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `cnf` is live per the caller's contract; `names` is live.
        unsafe {
            crate::runtime::lhash::OPENSSL_LH_doall_arg(
                (*cnf).data,
                Some(collect_section_name),
                names.cast::<c_void>(),
            );
            OPENSSL_sk_sort(names);
        }
        names
    })
}

/// `int NCONF_load(CONF *conf, const char *file, long *eline)`
///
/// # Safety
/// `conf` NULL or live; `file` NUL-terminated; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn NCONF_load(
    conf: *mut Conf,
    file: *const c_char,
    eline: *mut c_long,
) -> c_int {
    guard_ffi(0, || {
        if conf.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_254) };
            return 0;
        }
        // SAFETY: `conf` is live and its method's `load` is set for both tables
        // this crate publishes.
        match unsafe { (*(*conf).meth).load } {
            // SAFETY: `load` is the live method's own loader; `conf`, `file` and
            // `eline` satisfy its contract per the caller's own contract.
            Some(load) => unsafe { load(conf, file, eline) },
            None => 0,
        }
    })
}

/// `int NCONF_load_fp(CONF *conf, FILE *fp, long *eline)`
///
/// # Safety
/// `conf` NULL or live; `fp` a live `FILE *`; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn NCONF_load_fp(
    conf: *mut Conf,
    fp: *mut FILE,
    eline: *mut c_long,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `fp` is a live stream per the caller's contract.
        let btmp = unsafe { BIO_new_fp(fp.cast::<c_void>(), BIO_NOCLOSE) };
        if btmp.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_267) };
            return 0;
        }
        // SAFETY: `conf` and `btmp` are live.
        let ret = unsafe { NCONF_load_bio(conf, btmp, eline) };
        // SAFETY: `btmp` is a live BIO owned by this call.
        unsafe { BIO_free(btmp) };
        ret
    })
}

/// `int NCONF_load_bio(CONF *conf, BIO *bp, long *eline)`
///
/// # Safety
/// `conf` NULL or live; `bp` a live BIO; `eline` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn NCONF_load_bio(
    conf: *mut Conf,
    bp: *mut Bio,
    eline: *mut c_long,
) -> c_int {
    guard_ffi(0, || {
        if conf.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_279) };
            return 0;
        }
        // SAFETY: `conf` is live.
        match unsafe { (*(*conf).meth).load_bio } {
            // SAFETY: `load_bio` is the live method's own BIO loader; `conf`, `bp`
            // and `eline` satisfy its contract per the caller's own contract.
            Some(load_bio) => unsafe { load_bio(conf, bp, eline) },
            None => 0,
        }
    })
}

/// `STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf, const char *section)`
///
/// Two distinct failures, two distinct reasons: no configuration at all is
/// `CONF_R_NO_CONF`, a NULL section *name* is `CONF_R_NO_SECTION`.
///
/// # Safety
/// `conf` NULL or live; `section` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_section(
    conf: *const Conf,
    section: *const c_char,
) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if conf.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_289) };
            return ptr::null_mut();
        }
        if section.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_294) };
            return ptr::null_mut();
        }
        // SAFETY: `conf` and `section` are live.
        unsafe { _CONF_get_section_values(conf, section) }
    })
}

/// `char *NCONF_get_string(const CONF *conf, const char *group, const char *name)`
///
/// The lookup is attempted *first*, because a NULL configuration still consults
/// the environment; only then does the reason depend on whether a configuration
/// existed. `group` is defaulted to `""` for the message, but `name` is not — so
/// a NULL name reaches the formatter, and the formatter renders it `<NULL>`
/// (the authority's `_dopr`), which is why the message text is assembled through
/// that same engine rather than by hand.
///
/// # Safety
/// `conf` NULL or live; `group`/`name` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_string(
    conf: *const Conf,
    group: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the strings are NULL or NUL-terminated.
        let s = unsafe { _CONF_get_string(conf, group, name) };
        if !s.is_null() {
            return s;
        }
        if conf.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_313) };
            return ptr::null_mut();
        }
        // `group=%s name=%s`, with `group` defaulted to the empty string.
        let empty = c"";
        let group = if group.is_null() {
            empty.as_ptr()
        } else {
            group
        };
        // SAFETY: both strings are NULL or NUL-terminated.
        let mut msg: Vec<u8> = b"group=".to_vec();
        // SAFETY: `group` was replaced with `c""` above when it was NULL, so it is
        // a NUL-terminated string in every case.
        unsafe {
            msg.extend_from_slice(core::ffi::CStr::from_ptr(group).to_bytes());
        }
        msg.extend_from_slice(b" name=");
        if name.is_null() {
            // `_dopr` renders `%s` of NULL as the literal `<NULL>`.
            msg.extend_from_slice(b"<NULL>");
        } else {
            // SAFETY: `name` is NUL-terminated.
            msg.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes());
        }
        msg.push(0);
        // SAFETY: `msg` is NUL-terminated.
        unsafe { raise_site_data(&CONF_LIB_316, msg.as_ptr().cast::<c_char>()) };
        ptr::null_mut()
    })
}

/// `static int default_is_number(const CONF *conf, char c)`
///
/// The method-independent fallback: `ossl_isdigit`, i.e. ASCII only.
unsafe extern "C" fn default_is_number(_conf: *const Conf, c: c_char) -> c_int {
    c_int::from((b'0' as c_char..=b'9' as c_char).contains(&c))
}

/// `static int default_to_int(const CONF *conf, char c)`
unsafe extern "C" fn default_to_int(_conf: *const Conf, c: c_char) -> c_int {
    c_int::from(c) - c_int::from(b'0' as c_char)
}

/// `int NCONF_get_number_e(const CONF *conf, const char *group, const char *name, long *result)`
///
/// Parses decimal digits until the method says a character is not one, so a value
/// like `"12abc"` yields 12 and a value like `"abc"` yields 0 — both *successful*
/// calls, because the loop's exit condition is what decides. Only an overflow is
/// a failure, and it is `CONF_R_NUMBER_TOO_LARGE`.
///
/// # Safety
/// `conf` NULL or live; `group`/`name` NULL or NUL-terminated; `result` NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn NCONF_get_number_e(
    conf: *const Conf,
    group: *const c_char,
    name: *const c_char,
    result: *mut c_long,
) -> c_int {
    guard_ffi(0, || {
        if result.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_340) };
            return 0;
        }
        // SAFETY: `conf`/`group`/`name` are NULL or live as the caller promised.
        let mut str_ = unsafe { NCONF_get_string(conf, group, name) };
        if str_.is_null() {
            return 0;
        }

        // The per-method predicates override the defaults when present.
        let mut is_number: unsafe extern "C" fn(*const Conf, c_char) -> c_int = default_is_number;
        let mut to_int: unsafe extern "C" fn(*const Conf, c_char) -> c_int = default_to_int;
        if !conf.is_null() {
            // SAFETY: `conf` is live.
            unsafe {
                if let Some(f) = (*(*conf).meth).is_number {
                    is_number = f;
                }
                if let Some(f) = (*(*conf).meth).to_int {
                    to_int = f;
                }
            }
        }

        let mut res: c_long = 0;
        loop {
            // SAFETY: `str_` walks a NUL-terminated string.
            if unsafe { is_number(conf, *str_) } == 0 {
                break;
            }
            // SAFETY: as above.
            let d = unsafe { to_int(conf, *str_) };
            // `LONG_MAX` on the admitted profile.
            if res > (c_long::MAX - c_long::from(d)) / 10 {
                // SAFETY: the site is a compile-time constant, which is
                // `raise_site`'s only precondition.
                unsafe { raise_site(&CONF_LIB_359) };
                return 0;
            }
            res = res * 10 + c_long::from(d);
            // SAFETY: the digit was not the terminator.
            str_ = unsafe { str_.add(1) };
        }

        // SAFETY: `result` is writable per the caller's contract.
        unsafe { *result = res };
        1
    })
}

/// `int NCONF_dump_fp(const CONF *conf, FILE *out)`
///
/// # Safety
/// `conf` NULL or live; `out` a live `FILE *`.
#[no_mangle]
pub unsafe extern "C" fn NCONF_dump_fp(conf: *const Conf, out: *mut FILE) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `out` is a live stream per the caller's contract.
        let btmp = unsafe { BIO_new_fp(out.cast::<c_void>(), BIO_NOCLOSE) };
        if btmp.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_387) };
            return 0;
        }
        // SAFETY: `conf` and `btmp` are live.
        let ret = unsafe { NCONF_dump_bio(conf, btmp) };
        // SAFETY: `btmp` is a live BIO owned by this call.
        unsafe { BIO_free(btmp) };
        ret
    })
}

/// `int NCONF_dump_bio(const CONF *conf, BIO *out)`
///
/// # Safety
/// `conf` NULL or live; `out` a live BIO.
#[no_mangle]
pub unsafe extern "C" fn NCONF_dump_bio(conf: *const Conf, out: *mut Bio) -> c_int {
    guard_ffi(0, || {
        if conf.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_LIB_399) };
            return 0;
        }
        // SAFETY: `conf` is live.
        match unsafe { (*(*conf).meth).dump } {
            // SAFETY: `dump` is the live method's own dumper; `conf` and `out`
            // satisfy its contract per the caller's own contract.
            Some(dump) => unsafe { dump(conf, out) },
            None => 0,
        }
    })
}
