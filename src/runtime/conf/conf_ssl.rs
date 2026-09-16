//! `crypto/conf/conf_ssl.c` — the `ssl_conf` configuration module's storage.
//!
//! ## What is not here
//!
//! **Nothing, as of 6.10e.** The authority's `conf_ssl.c` has two halves and both are in
//! this file now:
//!
//! 1. a **static store** of named command sets, plus the three accessors
//!    (`conf_ssl_get`, `conf_ssl_name_find`, `conf_ssl_get_cmd`);
//! 2. a **CONF module** (`ssl_module_init`, `ssl_module_free`) that reads the
//!    configuration and fills that store, registered by `ossl_config_add_ssl_module`
//!    through `CONF_module_add`.
//!
//! The second half waited for the module registry because `ssl_module_init` reads the
//! module's own value with `CONF_imodule_get_value` and `ossl_config_add_ssl_module` is a
//! `CONF_module_add` — and D128 is the record of *which* stratum that made it: this one, not
//! libssl, because nothing in it needs libssl. It registers a store that libssl later reads
//! through `SSL_CONF`, and the store and the accessors were always here.
//!
//! ## The module's invariants, and the two that a plausible transcription loses
//!
//! `ssl_module_init` **calls the free first** (`ssl_module_free(md)` before it allocates),
//! so loading an `ssl_conf` section twice replaces the store rather than leaking it. And its
//! `err:` label calls the free **again** when the initialiser failed, so a partially-built
//! store is released rather than left half-initialised. Both are the authority's, and both are
//! observable through `conf_ssl_name_find` after a failed load.
//!
//! `ssl_module_free` takes a `CONF_IMODULE *` and **never reads it** — the store is a
//! file-level static rather than module state — so the argument exists only to match
//! `conf_finish_func`. That is why the same function is both the registry's finish hook and the
//! initialiser's own cleanup with no adapter between them.
//!
//! ## The store is still one process-global, and that is the authority's shape in 3.6.4
//!
//! Not a per-`OSSL_LIB_CTX` slot: libssl's `SSL_CONF` reads it through the process-global
//! accessors below. A configuration loaded into one context is therefore visible to another,
//! which is a real property of this version and not an oversight here.

use core::ffi::{c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::strchr;
use crate::runtime::conf::lib::NCONF_get_section;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{CONF_module_add, ConfFinishFn, ConfImodule, ConfInitFn};
use crate::runtime::err::err_sites::{CONF_SSL_75, CONF_SSL_94};
use crate::runtime::err::raise_site_dynamic_data;
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free, CRYPTO_strdup};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

/// `ERR_MAX_DATA_SIZE`, from `crypto/err/err_local.h`.
///
/// The authority's `ERR_vset_error` refuses to format a message longer than this, so one that
/// would exceed it is truncated in both implementations — and both truncate at the same byte,
/// because both format through the same `ossl_do_vsnprintf`.
const ERR_MAX_DATA_SIZE: usize = 1024;

/// `crypto/conf/conf_ssl.c`, for the coordinates of every allocation and release this module
/// makes.
///
/// `OPENSSL_free`, `OPENSSL_strdup` and `OPENSSL_calloc` are macros over the `CRYPTO_*` family
/// that fill in `OPENSSL_FILE` and `OPENSSL_LINE` at the call site, so each constant below is
/// the **line the macro expands on** rather than the line of any definition — the same
/// distinction `confmod/mod.rs` records for `conf_mod.c`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/conf/conf_ssl.c".as_ptr();

/// `OPENSSL_free(tname->name)` in `ssl_module_free`.
const L_FREE_NAME: c_int = 49;
/// `OPENSSL_free(tname->cmds[j].cmd)`.
const L_FREE_CMD: c_int = 51;
/// `OPENSSL_free(tname->cmds[j].arg)`.
const L_FREE_ARG: c_int = 52;
/// `OPENSSL_free(tname->cmds)`.
const L_FREE_CMDS: c_int = 54;
/// `OPENSSL_free(ssl_names)`.
const L_FREE_NAMES: c_int = 56;
/// `ssl_names = OPENSSL_calloc(cnt, sizeof(*ssl_names))` in `ssl_module_init`.
const L_INIT_NAMES: c_int = 80;
/// `ssl_name->name = OPENSSL_strdup(sect->name)`.
const L_INIT_NAME: c_int = 98;
/// `ssl_name->cmds = OPENSSL_calloc(cnt, ...)`.
const L_INIT_CMDS: c_int = 102;
/// `cmd->cmd = OPENSSL_strdup(name)`.
const L_INIT_CMD: c_int = 117;
/// `cmd->arg = OPENSSL_strdup(cmd_conf->value)`.
const L_INIT_ARG: c_int = 118;

/// `#define CONF_R_SSL_SECTION_NOT_FOUND 120` -- `openssl/conferr.h`.
const CONF_R_SSL_SECTION_NOT_FOUND: c_int = 120;
/// `#define CONF_R_SSL_SECTION_EMPTY 119`.
const CONF_R_SSL_SECTION_EMPTY: c_int = 119;
/// `#define CONF_R_SSL_COMMAND_SECTION_NOT_FOUND 118`.
const CONF_R_SSL_COMMAND_SECTION_NOT_FOUND: c_int = 118;
/// `#define CONF_R_SSL_COMMAND_SECTION_EMPTY 117`.
const CONF_R_SSL_COMMAND_SECTION_EMPTY: c_int = 117;

/// `SSL_CONF_CMD` — one command and its argument, as libssl reads them.
///
/// Both strings are owned by the store and released by
/// [`ossl_config_ssl_module_free`].
#[repr(C)]
pub struct SslConfCmd {
    /// `char *cmd` — the command name, with any leading dot already stripped by
    /// the module's reader.
    pub cmd: *mut c_char,
    /// `char *arg` — the argument text, or NULL when the command had none.
    pub arg: *mut c_char,
}

/// `struct ssl_conf_name_st` — one named set of commands.
#[repr(C)]
pub struct SslConfName {
    /// `char *name` — the section name the set was declared in.
    pub name: *mut c_char,
    /// `SSL_CONF_CMD *cmds` — the set, in declaration order.
    pub cmds: *mut SslConfCmd,
    /// `size_t cmd_count`
    pub cmd_count: usize,
}

/// `static struct ssl_conf_name_st *ssl_names`
///
/// One static, not a per-`OSSL_LIB_CTX` slot: that is the authority's shape in
/// this version, and libssl's `SSL_CONF` reads it through the process-global
/// accessors below. An `AtomicPtr` rather than a `static mut` so that the
/// unsynchronised-write hazard is at least named at the definition rather than
/// implied — the authority writes it under no lock either, from configuration time,
/// which is before any other thread can be reading.
static SSL_NAMES: AtomicPtr<SslConfName> = AtomicPtr::new(core::ptr::null_mut());
/// `static size_t ssl_names_count`
static SSL_NAMES_COUNT: AtomicUsize = AtomicUsize::new(0);

/// `const SSL_CONF_CMD *conf_ssl_get(size_t idx, const char **name, size_t *cnt)`
///
/// The set at `idx`, with its name and count written through the out-parameters.
/// No bounds check, matching the authority: the caller is expected to have found
/// `idx` with [`conf_ssl_name_find`].
///
/// # Safety
/// `idx` must be in range for the current store — which is to say the store must
/// be non-empty and `idx` one of its indices. `name` and `cnt` must each be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_get(
    idx: usize,
    name: *mut *const c_char,
    cnt: *mut usize,
) -> *const SslConfCmd {
    let names = SSL_NAMES.load(Ordering::Acquire);
    // SAFETY: the store is live per the caller's contract.
    let entry = unsafe { &*names.add(idx) };
    // SAFETY: both out-parameters are writable per the caller's contract.
    unsafe {
        *name = entry.name;
        *cnt = entry.cmd_count;
    }
    entry.cmds
}

/// `int conf_ssl_name_find(const char *name, size_t *idx)`
///
/// `1` with `*idx` set on a match, `0` otherwise — and `0` for a NULL name, which
/// is the authority's first check rather than a fault. Case-**sensitive**
/// (`strcmp`, not a case-insensitive compare), which is what makes the section
/// names in a configuration file exact.
///
/// # Safety
/// `name` must be NULL or a NUL-terminated C string; `idx` must be writable when a
/// match is possible.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_name_find(name: *const c_char, idx: *mut usize) -> c_int {
    if name.is_null() {
        return 0;
    }
    let names = SSL_NAMES.load(Ordering::Acquire);
    let count = SSL_NAMES_COUNT.load(Ordering::Acquire);
    let mut nm = names;
    for i in 0..count {
        // SAFETY: `nm` walks the live store, which holds `count` entries.
        if unsafe { crate::runtime::bio::sys::strcmp(name, (*nm).name) } == 0 {
            // SAFETY: `idx` is writable per the caller's contract.
            unsafe { *idx = i };
            return 1;
        }
        // SAFETY: `names` is a live array of `count` entries and `i < count`, so
        // the offset stays inside it.
        nm = unsafe { names.add(i + 1) };
    }
    0
}

/// `void conf_ssl_get_cmd(const SSL_CONF_CMD *cmd, size_t idx, char **cmdstr,
/// char **arg)`
///
/// The command and argument at `idx` of the set returned by [`conf_ssl_get`]. No
/// bounds check, as the authority: `idx` must be below the count that call
/// reported.
///
/// # Safety
/// `cmd` must be the pointer `conf_ssl_get` returned for a set whose count exceeds
/// `idx`, and both out-parameters must be writable.
#[no_mangle]
pub unsafe extern "C" fn conf_ssl_get_cmd(
    cmd: *const SslConfCmd,
    idx: usize,
    cmdstr: *mut *mut c_char,
    arg: *mut *mut c_char,
) {
    // SAFETY: `cmd` points at a live set of more than `idx` entries per the
    // caller's contract.
    let entry = unsafe { &*cmd.add(idx) };
    // SAFETY: both out-parameters are writable per the caller's contract.
    unsafe {
        *cmdstr = entry.cmd;
        *arg = entry.arg;
    }
}

/// `static void ssl_module_free(CONF_IMODULE *md)` — the store's teardown.
///
/// Releases every string the store owns, the command arrays and the name array, and resets the
/// store to empty. The argument is the module handle, which this function **does not read**:
/// the authority's takes one and ignores it too, because the store is a file-level static
/// rather than module state. That is what makes one function serve as both the registry's
/// `finish` hook and the initialiser's own cleanup.
///
/// # Safety
/// No live pointer obtained from [`conf_ssl_get`] or [`conf_ssl_get_cmd`] may be used
/// afterwards. This is the same contract the authority's version has.
pub(crate) unsafe fn ossl_config_ssl_module_free() {
    let names = SSL_NAMES.swap(core::ptr::null_mut(), Ordering::AcqRel);
    let count = SSL_NAMES_COUNT.swap(0, Ordering::AcqRel);
    if names.is_null() {
        return;
    }
    for i in 0..count {
        // SAFETY: `names` is a live array of `count` entries.
        let tname = unsafe { &mut *names.add(i) };
        // SAFETY: each pointer was produced by `CRYPTO_strdup`/`CRYPTO_calloc` at the
        // coordinate recorded beside it and is owned by this store.
        unsafe {
            CRYPTO_free(tname.name.cast(), FILE, L_FREE_NAME);
            for j in 0..tname.cmd_count {
                let cmd = &mut *tname.cmds.add(j);
                CRYPTO_free(cmd.cmd.cast(), FILE, L_FREE_CMD);
                CRYPTO_free(cmd.arg.cast(), FILE, L_FREE_ARG);
            }
            // SAFETY: `cmds` is this store's own array, and the loop above released its
            // contents rather than the array.
            CRYPTO_free(tname.cmds.cast(), FILE, L_FREE_CMDS);
        }
    }
    // SAFETY: the array came from `CRYPTO_calloc` in `ssl_module_init` below, and this is its
    // only release.
    unsafe { CRYPTO_free(names.cast(), FILE, L_FREE_NAMES) };
}

/// `static int ssl_module_init(CONF_IMODULE *md, const CONF *cnf)` — the `ssl_conf` reader.
///
/// Two levels of section, and the shape is the whole of it: the module's own value names a
/// section whose **entries** each name a *command set* section, and each entry of that section
/// is one command. So
///
/// ```text
/// openssl_conf = openssl_init
/// [openssl_init]
/// ssl_conf = ssl_sect
/// [ssl_sect]
/// system_default = system_default_sect
/// [system_default_sect]
/// CipherString = DEFAULT
/// ```
///
/// produces one command set named `system_default` holding one command, `CipherString` with
/// the argument `DEFAULT`.
///
/// Three details are contract rather than style:
///
/// * **the free runs first.** `ssl_module_free(md)` is called before the store is replaced, so
///   loading `ssl_conf` twice replaces rather than leaks. It is called again from `err:` when
///   the initialiser failed, so a half-built store is released too — which is observable as
///   `conf_ssl_name_find` answering 0 afterwards.
/// * **an empty section and a missing one are different errors**, and which of the pair is
///   raised is decided by a NULL test on the section: `sk_CONF_VALUE_num(NULL)` is 0, so both
///   reach the same branch and the *reason* is what differs.
/// * **a leading dot is stripped from a command's name.** `strchr(name, '.')` and then `name++`,
///   so `.CipherString` and `CipherString` are the same command — the dot is what a section
///   entry uses to mark a key it does not want inherited, and `conf_def.c` passes it through.
///
/// # Safety
/// `md` must be a live initialisation and `cnf` the configuration it was loaded from.
unsafe extern "C" fn ssl_module_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // SAFETY: `md` is live per the callback's contract; its value is the section name the
    // configuration gave for `ssl_conf`.
    let section = unsafe { crate::runtime::confmod::CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `section` is a NUL-terminated string owned by `md`.
    let cmd_lists = unsafe { NCONF_get_section(cnf, section) };
    // SAFETY: `cmd_lists` is NULL or the section's own stack, and `OPENSSL_sk_num` accepts
    // NULL. A NULL section is what distinguishes "not found" from "empty".
    let count = unsafe { OPENSSL_sk_num(cmd_lists) };
    if count <= 0 {
        let reason = if cmd_lists.is_null() {
            CONF_R_SSL_SECTION_NOT_FOUND
        } else {
            CONF_R_SSL_SECTION_EMPTY
        };
        // SAFETY: this thread's own error queue, the generated site's coordinates, and the
        // `section=%s` argument the authority formats.
        unsafe { raise_site_dynamic_data(&CONF_SSL_75, reason, section_message(section)) };
        return ssl_module_init_failed(md);
    }

    // `ssl_module_free(md);` — before the store is replaced, so a second load of this section
    // replaces rather than leaks. The authority's own order.
    // SAFETY: the store is this file's, and the freed function's contract is that no live
    // pointer from it is used afterwards — which is what replacing it means.
    unsafe { ossl_config_ssl_module_free() };

    // `ssl_names = OPENSSL_calloc(cnt, sizeof(*ssl_names))` — a **zeroed** array, which is what
    // makes a partially-built store safe to hand to the free.
    let names = CRYPTO_calloc(
        count as usize,
        core::mem::size_of::<SslConfName>(),
        FILE,
        L_INIT_NAMES,
    )
    .cast::<SslConfName>();
    if names.is_null() {
        return ssl_module_init_failed(md);
    }
    // SAFETY: `names` is this function's own fresh array of `count` entries, and nothing else
    // can reach it until the store is published at the end.
    unsafe { ossl_config_ssl_module_install(names, count as usize) };

    let mut i = 0;
    while i < count {
        // SAFETY: `i < count`, so this is one of `cmd_lists`' own entries.
        let sect = unsafe { OPENSSL_sk_value(cmd_lists, i) }.cast::<ConfValue>();
        // SAFETY: a `CONF_VALUE`'s `name` and `value` are NUL-terminated strings owned by the
        // `CONF`.
        let (sect_name, sect_value) = unsafe { ((*sect).name, (*sect).value) };
        // SAFETY: `cnf` is live and `sect_value` is a name the file itself provided.
        let cmds = unsafe { NCONF_get_section(cnf, sect_value) };
        // SAFETY: as for `cmd_lists` above.
        let cmd_count = unsafe { OPENSSL_sk_num(cmds) };
        if cmd_count <= 0 {
            let reason = if cmds.is_null() {
                CONF_R_SSL_COMMAND_SECTION_NOT_FOUND
            } else {
                CONF_R_SSL_COMMAND_SECTION_EMPTY
            };
            // SAFETY: this thread's own error queue, the generated site's coordinates, and the
            // `name=%s, value=%s` argument the authority formats.
            unsafe {
                raise_site_dynamic_data(
                    &CONF_SSL_94,
                    reason,
                    name_value_message(sect_name, sect_value),
                )
            };
            return ssl_module_init_failed(md);
        }

        // SAFETY: `i < count`, so this is one of the array's own entries.
        let ssl_name = unsafe { &mut *names.add(i as usize) };
        // SAFETY: `sect_name` is NUL-terminated and belongs to `cnf`, which outlives the store
        // only until the next load; the copy is what makes the store independent of it.
        ssl_name.name = unsafe { CRYPTO_strdup(sect_name, FILE, L_INIT_NAME) };
        if ssl_name.name.is_null() {
            return ssl_module_init_failed(md);
        }
        // SAFETY: as `names` above: a fresh zeroed array of `cmd_count` entries.
        let cmd_arr = CRYPTO_calloc(
            cmd_count as usize,
            core::mem::size_of::<SslConfCmd>(),
            FILE,
            L_INIT_CMDS,
        )
        .cast::<SslConfCmd>();
        if cmd_arr.is_null() {
            return ssl_module_init_failed(md);
        }
        ssl_name.cmds = cmd_arr;
        ssl_name.cmd_count = cmd_count as usize;

        let mut j = 0;
        while j < cmd_count {
            // SAFETY: `j < cmd_count`, so this is one of `cmds`' own entries.
            let cmd_conf = unsafe { OPENSSL_sk_value(cmds, j) }.cast::<ConfValue>();
            // SAFETY: as for `sect` above.
            let (cmd_key, cmd_value) = unsafe { ((*cmd_conf).name, (*cmd_conf).value) };
            // `name = strchr(cmd_conf->name, '.'); if (name != NULL) name++;` — the initial
            // dot is skipped, and only one of them: `..foo` becomes `.foo`, which is the
            // authority's `strchr`-then-increment rather than a trim of every dot.
            // SAFETY: `cmd_key` is NUL-terminated.
            let dot = unsafe { strchr(cmd_key, b'.' as c_int) };
            let bare = if dot.is_null() {
                cmd_key
            } else {
                // SAFETY: `dot` points at a byte inside `cmd_key`.
                unsafe { dot.add(1) }
            };
            // SAFETY: `bare` and `cmd_value` are NUL-terminated and owned by `cnf`.
            let (cmd_str, arg_str) = unsafe {
                (
                    CRYPTO_strdup(bare, FILE, L_INIT_CMD),
                    CRYPTO_strdup(cmd_value, FILE, L_INIT_ARG),
                )
            };
            if cmd_str.is_null() || arg_str.is_null() {
                // The authority's `goto err` releases the *whole* store, including the two
                // copies just made, because they are already linked by the time this test
                // runs. Setting them first is what makes that so.
                // SAFETY: as `ssl_name` above, and the loop index is in range.
                unsafe {
                    let cmd = &mut *cmd_arr.add(j as usize);
                    cmd.cmd = cmd_str;
                    cmd.arg = arg_str;
                }
                return ssl_module_init_failed(md);
            }
            // SAFETY: as above.
            unsafe {
                let cmd = &mut *cmd_arr.add(j as usize);
                cmd.cmd = cmd_str;
                cmd.arg = arg_str;
            }
            j += 1;
        }
        i += 1;
    }

    1
}

/// The authority's `err:` label: free the whole store, then answer 0.
///
/// One function rather than an inlined pair at each of the five failure points, because the
/// label is one place in the authority and the five jumps are what a reader should be able to
/// count.
///
/// # Safety
/// `md` is unused by the free; the contract is [`ossl_config_ssl_module_free`]'s.
fn ssl_module_init_failed(_md: *mut ConfImodule) -> c_int {
    // SAFETY: the store is this file's, and `ssl_module_free`'s contract is that no live
    // pointer obtained from it is used afterwards. The authority reaches this from its `err:`
    // label, which is why a failed load leaves `conf_ssl_name_find` answering 0.
    unsafe { ossl_config_ssl_module_free() };
    0
}

/// `void ossl_config_add_ssl_module(void)` — the `ssl_conf` module's registration.
///
/// One `CONF_module_add`, and it is one of the seven calls `OPENSSL_load_builtin_modules`
/// makes. D128 records why it is this stratum's and not libssl's.
pub(crate) fn ossl_config_add_ssl_module() {
    // SAFETY: the name is a static NUL-terminated string, and the two callbacks are the
    // registry's declared types rather than casts — `ConfInitFn` and `ConfFinishFn` are
    // `unsafe extern "C" fn` with exactly these signatures.
    unsafe {
        CONF_module_add(
            c"ssl_conf".as_ptr(),
            Some(ssl_module_init as ConfInitFn),
            Some(ssl_module_free_thunk as ConfFinishFn),
        );
    }
}

/// `ssl_module_free` in the shape `CONF_module_add` takes.
///
/// The authority truncates the same pointer to `conf_finish_func *` at the call site; the
/// registry's type here takes `*mut ConfImodule`, so the adapter exists to make the coercion
/// explicit rather than to change it.
unsafe extern "C" fn ssl_module_free_thunk(_md: *mut ConfImodule) {
    // SAFETY: the store is this file's, and no live pointer from it is used after the
    // registry decides a module is finished.
    unsafe { ossl_config_ssl_module_free() };
}

/// `"section=%s"` — the first raise's data.
///
/// A `static` buffer rather than an allocation, for the reason `confmod/mod.rs` records for its
/// three: the authority's `ERR_vset_error` allocates, the raise copies the bytes before
/// returning, and no caller holds the pointer afterwards. `BIO_snprintf` is the function
/// `ERR_vset_error` itself formats through, so the bytes match by construction.
///
/// # Safety
/// `section` must be NUL-terminated.
unsafe fn section_message(section: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: the buffer is a static of exactly the declared length, and the format string is a
    // static NUL-terminated one whose single conversion is `%s`.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"section=%s".as_ptr(),
            section,
        )
    };
    // SAFETY: the pointer is to the static written immediately above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// `"name=%s, value=%s"` — the second raise's data.
///
/// # Safety
/// Both arguments must be NUL-terminated.
unsafe fn name_value_message(name: *const c_char, value: *const c_char) -> *const c_char {
    static mut BUF: [c_char; ERR_MAX_DATA_SIZE] = [0; ERR_MAX_DATA_SIZE];
    // SAFETY: as `section_message`, with two `%s` matching the two arguments.
    unsafe {
        BIO_snprintf(
            ptr::addr_of_mut!(BUF).cast::<c_char>(),
            ERR_MAX_DATA_SIZE,
            c"name=%s, value=%s".as_ptr(),
            name,
            value,
        )
    };
    // SAFETY: as above.
    ptr::addr_of!(BUF).cast::<c_char>()
}

/// Install a store, for [`ssl_module_init`] and for the tests here.
///
/// # Safety
/// `names` must be NULL or an array of `count` live [`SslConfName`] values whose
/// strings and command arrays this module may subsequently free — that is, the
/// whole ownership must transfer. Any previous store is **not** freed by this
/// function; call [`ossl_config_ssl_module_free`] first, as [`ssl_module_init`]
/// does.
pub(crate) unsafe fn ossl_config_ssl_module_install(names: *mut SslConfName, count: usize) {
    SSL_NAMES.store(names, Ordering::Release);
    SSL_NAMES_COUNT.store(count, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_strdup};
    use std::ffi::CString;

    fn empty_store_is_empty() {
        // SAFETY: the store is empty, so nothing is freed.
        unsafe { ossl_config_ssl_module_free() };
    }

    #[test]
    fn an_empty_store_finds_nothing_and_a_null_name_is_not_a_fault() {
        empty_store_is_empty();
        let Ok(wanted) = CString::new("SECLEVEL") else {
            unreachable!()
        };
        let mut idx = usize::MAX;
        // SAFETY: `wanted` is NUL-terminated and `idx` is writable.
        unsafe {
            assert_eq!(conf_ssl_name_find(wanted.as_ptr(), &mut idx), 0);
            assert_eq!(idx, usize::MAX, "a failed search must not write idx");
            assert_eq!(conf_ssl_name_find(core::ptr::null(), &mut idx), 0);
        }
    }

    #[test]
    fn the_search_is_case_sensitive_and_finds_what_was_installed() {
        empty_store_is_empty();
        // SAFETY: the source is a static NUL-terminated literal and the file/line
        // pair is the "internal allocation" marker the crate uses on these paths.
        let name = unsafe { CRYPTO_strdup(c"SECLEVEL".as_ptr(), core::ptr::null(), 0) };
        let cmds = CRYPTO_calloc(2, core::mem::size_of::<SslConfCmd>(), core::ptr::null(), 0)
            .cast::<SslConfCmd>();
        assert!(!name.is_null() && !cmds.is_null());
        // SAFETY: `cmds` has room for two entries; both strings are fresh.
        unsafe {
            (*cmds.add(0)).cmd = CRYPTO_strdup(c"cipher".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(0)).arg = CRYPTO_strdup(c"DEFAULT".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(1)).cmd = CRYPTO_strdup(c"level".as_ptr(), core::ptr::null(), 0);
            (*cmds.add(1)).arg = core::ptr::null_mut();
        }
        let names = CRYPTO_calloc(1, core::mem::size_of::<SslConfName>(), core::ptr::null(), 0)
            .cast::<SslConfName>();
        assert!(!names.is_null());
        // SAFETY: `names` has room for one entry.
        unsafe {
            (*names).name = name;
            (*names).cmds = cmds;
            (*names).cmd_count = 2;
            ossl_config_ssl_module_install(names, 1);
        }

        let Ok(exact) = CString::new("SECLEVEL") else {
            unreachable!()
        };
        let Ok(lower) = CString::new("seclevel") else {
            unreachable!()
        };
        let mut idx = usize::MAX;
        // SAFETY: both strings are NUL-terminated; the store is live.
        unsafe {
            assert_eq!(conf_ssl_name_find(exact.as_ptr(), &mut idx), 1);
            assert_eq!(idx, 0);
            // Case matters: the authority compares with `strcmp`.
            assert_eq!(conf_ssl_name_find(lower.as_ptr(), &mut idx), 0);
        }

        // SAFETY: the store is live and `idx` is in range for it.
        unsafe {
            let mut got_name: *const c_char = core::ptr::null();
            let mut got_count = 0usize;
            let set = conf_ssl_get(0, &mut got_name, &mut got_count);
            assert_eq!(set, cmds);
            assert_eq!(got_count, 2);
            let text = std::ffi::CStr::from_ptr(got_name);
            assert_eq!(text.to_str(), Ok("SECLEVEL"));

            let mut cmd: *mut c_char = core::ptr::null_mut();
            let mut arg: *mut c_char = core::ptr::null_mut();
            conf_ssl_get_cmd(set, 0, &mut cmd, &mut arg);
            assert_eq!(std::ffi::CStr::from_ptr(cmd).to_str(), Ok("cipher"));
            assert_eq!(std::ffi::CStr::from_ptr(arg).to_str(), Ok("DEFAULT"));
            // The second entry's argument is genuinely NULL, not "": the module's
            // reader stores what it read.
            conf_ssl_get_cmd(set, 1, &mut cmd, &mut arg);
            assert!(arg.is_null());

            ossl_config_ssl_module_free();
            // The store is empty again, so nothing is found.
            assert_eq!(conf_ssl_name_find(exact.as_ptr(), &mut idx), 0);
        }
    }
}
