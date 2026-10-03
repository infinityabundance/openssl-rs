//! Phase 13.1 — `crypto/engine/eng_cnf.c`: the `engines` configuration module.
//!
//! `ENGINE_add_conf_module` (`:180-184`) registers the `engines` `CONF` module under
//! `CONF_module_add`. Its two callbacks walk a configuration's `engines` section and hand
//! each entry to `int_engine_configure`, which looks the engine up by id, feeds it the
//! pseudo-controls (`init`, `default_algorithms`, `dynamic_path`, `soft_load`) and then any
//! remaining `ENGINE_ctrl_cmd_string` the section names. This is one of 13.1's three exports.
//!
//! ## The one callee that is a later subphase's
//!
//! `int_engine_configure`'s `default_algorithms` arm calls `ENGINE_set_default_string`
//! (`crypto/engine/eng_fat.c:82-91`), which is subphase 13.3's row and is not landed yet. The
//! call is **transcribed rather than elided**: it is declared here exactly as `eng_local.h`
//! spells it and resolves to the candidate distribution shell's scaffold, the pattern
//! `src/cms/cms_sd.rs` established for the same situation (D199's reference is not the same
//! thing, but the forward-declaration rule is). When 13.3 lands `eng_fat.rs` the scaffold is
//! replaced by the real function and this declaration is dropped. It is not stubbed: the
//! authority's own call is present, and the coordinate it sits on is the authority's.
//!
//! ## The two pseudo-controls that share the configuration's own section
//!
//! `init` re-reads the *section variable* `init` through `NCONF_get_number_e` rather than the
//! control's argument, and `default_algorithms` passes its value to `ENGINE_set_default_string`.
//! Everything else the section names is forwarded to `ENGINE_ctrl_cmd_string`, with the
//! literal `EMPTY` mapped to NULL so a `NO_INPUT` command can be spelled.
//!
//! ## The `OSSL_TRACE` calls
//!
//! `OSSL_TRACE1(CONF, …)` (`:55`), `OSSL_TRACE2(CONF, …)` (`:68`) and the module-init
//! `OSSL_TRACE2(CONF, …)` (`:151-152`) are compiled out of the admitted build, which
//! configures `no-trace`; they are omitted with this sentence as their record, the convention
//! `src/evp/evp_cnf.rs` and `src/runtime/confmod/mod.rs` use (`src/runtime/trace.rs` is the
//! runtime surface they would call).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::engine::eng_ctrl::ENGINE_ctrl_cmd_string;
use crate::engine::eng_init::{ENGINE_finish, ENGINE_init};
use crate::engine::eng_lib::{ENGINE_free, Engine};
use crate::engine::eng_list::ENGINE_by_id;
use crate::ffi::guard_ffi;
use crate::runtime::bio::sys::{strchr, strcmp};
use crate::runtime::conf::lib::{NCONF_get_number_e, NCONF_get_section};
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{CONF_imodule_get_value, CONF_module_add, ConfImodule};
use crate::runtime::err::err_sites;
use crate::runtime::err::{raise_site, raise_site_data, ERR_clear_error};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};

// `ENGINE_set_default_string` is Phase 13.3's export (`crypto/engine/eng_fat.c`). It is declared
// with the authority's prototype and resolved by the candidate distribution shell's scaffold, the
// forward-reference pattern `src/cms/cms_sd.rs` uses; the module header says when it is dropped.
extern "C" {
    fn ENGINE_set_default_string(e: *mut Engine, def_list: *const c_char) -> c_int;
}

/// `static STACK_OF(ENGINE) *initialized_engines = NULL` (`:28`).
static INITIALIZED_ENGINES: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static const char *skip_dot(const char *name)` — `crypto/engine/eng_cnf.c:19-26`.
///
/// # Safety
/// `name` must be NUL-terminated.
unsafe fn skip_dot(name: *const c_char) -> *const c_char {
    // SAFETY: `name` is NUL-terminated per the contract.
    let p = unsafe { strchr(name, b'.' as c_int) };
    if p.is_null() {
        name
    } else {
        // SAFETY: `p` points at the '.' inside `name`, so `p + 1` is within the string.
        unsafe { p.add(1) }
    }
}

/// `static int int_engine_init(ENGINE *e)` — `:30-41`.
///
/// Takes a functional reference and records it on `initialized_engines` so the module's finish
/// callback can release them. A failure to record releases the functional reference again.
///
/// # Safety
/// `e` must be a live `ENGINE` or NULL; `ENGINE_init`'s own contract applies.
unsafe fn int_engine_init(e: *mut Engine) -> c_int {
    // SAFETY: `e` is live or NULL per the contract.
    if unsafe { ENGINE_init(e) } == 0 {
        return 0;
    }
    if INITIALIZED_ENGINES.load(Ordering::Acquire).is_null() {
        INITIALIZED_ENGINES.store(OPENSSL_sk_new_null(), Ordering::Release);
    }
    let st = INITIALIZED_ENGINES.load(Ordering::Acquire);
    // SAFETY: `st` is the stack just stored (or an earlier one); `e` is a live ENGINE.
    if st.is_null() || unsafe { OPENSSL_sk_push(st, e.cast::<c_void>()) } == 0 {
        // SAFETY: the functional reference was taken above and is released on this path.
        unsafe { ENGINE_finish(e) };
        return 0;
    }
    1
}

/// `static int int_engine_configure(const char *name, const char *value, const CONF *cnf)` —
/// `:43-144`.
///
/// # Safety
/// `name`/`value` must be NUL-terminated; `cnf` must be a live configuration.
unsafe fn int_engine_configure(
    name: *const c_char,
    value: *const c_char,
    cnf: *const Conf,
) -> c_int {
    let mut ret: c_int = 0;
    let mut do_init: c_long = -1;
    let mut ecmd: *mut ConfValue = ptr::null_mut();
    let mut e: *mut Engine = ptr::null_mut();
    let mut soft: c_int = 0;

    // SAFETY: `name` is NUL-terminated per the contract.
    let mut name = unsafe { skip_dot(name) };
    // SAFETY: `cnf`/`value` are live/NUL-terminated per the contract.
    let ecmds = unsafe { NCONF_get_section(cnf, value) };
    if ecmds.is_null() {
        // SAFETY: `ENG_CNF_60` is a generated constant whose strings are static.
        unsafe { raise_site(&err_sites::ENG_CNF_60) };
        return 0;
    }

    // `goto err` is the authority's single error tail. A labelled block reproduces it: every
    // `break 'configure` is one of the authority's `goto err` arms, and `ret` stays zero unless
    // the loop and the post-loop check both complete.
    'configure: {
        // SAFETY: `ecmds` is a live stack of `CONF_VALUE` pointers.
        let n = unsafe { OPENSSL_sk_num(ecmds) };
        let mut i: c_int = 0;
        while i < n {
            // SAFETY: `0 <= i < n` and every element is a `CONF_VALUE`.
            ecmd = unsafe { OPENSSL_sk_value(ecmds, i) }.cast::<ConfValue>();
            // SAFETY: `ecmd` is a live `CONF_VALUE`; an entry's `name` is NUL-terminated.
            let ctrlname = unsafe { skip_dot((*ecmd).name) };
            // SAFETY: `ecmd` is live.
            let mut ctrlvalue = unsafe { (*ecmd).value };

            // The pseudo-controls come first.
            // SAFETY: `ctrlname` is NUL-terminated; the literal is static.
            if unsafe { strcmp(ctrlname, c"engine_id".as_ptr()) } == 0 {
                name = ctrlvalue;
            // SAFETY: as above.
            } else if unsafe { strcmp(ctrlname, c"soft_load".as_ptr()) } == 0 {
                soft = 1;
            // SAFETY: as above.
            } else if unsafe { strcmp(ctrlname, c"dynamic_path".as_ptr()) } == 0 {
                // SAFETY: the literal is NUL-terminated.
                e = unsafe { ENGINE_by_id(c"dynamic".as_ptr()) };
                if e.is_null() {
                    break 'configure;
                }
                // SAFETY: `e` is live; the command name is a literal and `ctrlvalue` is
                // NUL-terminated (or NULL, the authority's `EMPTY`/`NO_INPUT` convention).
                let ok = unsafe {
                    ENGINE_ctrl_cmd_string(e, c"SO_PATH".as_ptr(), ctrlvalue, 0) != 0
                        && ENGINE_ctrl_cmd_string(e, c"LIST_ADD".as_ptr(), c"2".as_ptr(), 0) != 0
                        && ENGINE_ctrl_cmd_string(e, c"LOAD".as_ptr(), ptr::null::<c_char>(), 0)
                            != 0
                };
                if !ok {
                    break 'configure;
                }
            } else {
                if e.is_null() {
                    // SAFETY: `name` is NUL-terminated.
                    e = unsafe { ENGINE_by_id(name) };
                    if e.is_null() && soft != 0 {
                        // SAFETY: the authority clears the error the failed lookup left.
                        ERR_clear_error();
                        return 1;
                    }
                    if e.is_null() {
                        break 'configure;
                    }
                }
                // Allow the literal `EMPTY` to mean "no value", so a `NO_INPUT` control can be
                // spelled with a non-empty value. A section entry's `value` is never NULL, which
                // is why the authority's `strcmp` is not guarded.
                // SAFETY: `ctrlvalue` is NUL-terminated.
                if unsafe { strcmp(ctrlvalue, c"EMPTY".as_ptr()) } == 0 {
                    ctrlvalue = ptr::null_mut();
                }
                // SAFETY: `ctrlname` is NUL-terminated; the literal is static.
                if unsafe { strcmp(ctrlname, c"init".as_ptr()) } == 0 {
                    // SAFETY: `cnf` is live; `value`/the literal are NUL-terminated; `do_init`
                    // is a writable slot.
                    if unsafe { NCONF_get_number_e(cnf, value, c"init".as_ptr(), &mut do_init) }
                        == 0
                    {
                        break 'configure;
                    }
                    if do_init == 1 {
                        // SAFETY: `e` is a live ENGINE.
                        if unsafe { int_engine_init(e) } == 0 {
                            break 'configure;
                        }
                    } else if do_init != 0 {
                        // SAFETY: `ENG_CNF_118` is a generated constant whose strings are static.
                        unsafe { raise_site(&err_sites::ENG_CNF_118) };
                        break 'configure;
                    }
                // SAFETY: `ctrlname` is NUL-terminated; the literal is static.
                } else if unsafe { strcmp(ctrlname, c"default_algorithms".as_ptr()) } == 0 {
                    // `ENGINE_set_default_string(e, ctrlvalue)` — Phase 13.3's, declared above.
                    // SAFETY: `e` is a live ENGINE; `ctrlvalue` is NUL-terminated or NULL.
                    if unsafe { ENGINE_set_default_string(e, ctrlvalue) } == 0 {
                        break 'configure;
                    }
                // SAFETY: `e` is live; `ctrlname`/`ctrlvalue` are NUL-terminated or NULL.
                } else if unsafe { ENGINE_ctrl_cmd_string(e, ctrlname, ctrlvalue, 0) == 0 } {
                    break 'configure;
                }
            }
            i += 1;
        }
        // SAFETY: `e` is NULL or a live ENGINE.
        if !e.is_null() && do_init == -1 && unsafe { int_engine_init(e) } == 0 {
            ecmd = ptr::null_mut();
            break 'configure;
        }
        ret = 1;
    }

    if ret != 1 {
        if ecmd.is_null() {
            // SAFETY: `ENG_CNF_136` is a generated constant whose strings are static.
            unsafe { raise_site(&err_sites::ENG_CNF_136) };
        } else {
            // `section=%s, name=%s, value=%s`, with each `%s` rendered as `<NULL>` when its
            // pointer is NULL (`crypto/err/err.c`'s `_dopr`).
            // SAFETY: `ecmd` is a live `CONF_VALUE`.
            let (section, ename, evalue) =
                unsafe { ((*ecmd).section, (*ecmd).name, (*ecmd).value) };
            let mut buf: Vec<u8> = b"section=".to_vec();
            // SAFETY: each pointer is NULL or NUL-terminated.
            unsafe {
                push_cstr_or_null(&mut buf, section);
                buf.extend_from_slice(b", name=");
                push_cstr_or_null(&mut buf, ename);
                buf.extend_from_slice(b", value=");
                push_cstr_or_null(&mut buf, evalue);
            }
            buf.push(0);
            // SAFETY: `ENG_CNF_138` is a generated constant whose strings are static, and `buf`
            // is NUL-terminated.
            unsafe { raise_site_data(&err_sites::ENG_CNF_138, buf.as_ptr().cast::<c_char>()) };
        }
    }
    // SAFETY: `e` is NULL or a live ENGINE the caller owns.
    unsafe { ENGINE_free(e) };
    ret
}

/// Appends `p`'s bytes, or the literal `<NULL>` when `p` is NULL — the same helper
/// `src/evp/evp_cnf.rs` uses for the authority's `%s` of NULL.
///
/// # Safety
/// `p` must be NULL or NUL-terminated.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes());
    }
}

/// `static int int_engine_module_init(CONF_IMODULE *md, const CONF *cnf)` — `:146-168`.
///
/// # Safety
/// `md`/`cnf` must be the live module initialisation and configuration the module system
/// passes; `CONF_imodule_get_name`/`_get_value` are read from `md`.
unsafe extern "C" fn int_engine_module_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // The authority's `OSSL_TRACE2(CONF, …)` of the name and value is compiled out (no-trace).
    // SAFETY: `md` is live per the contract.
    let section = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `section` is NUL-terminated or NULL.
    let elist = unsafe { NCONF_get_section(cnf, section) };
    if elist.is_null() {
        // SAFETY: `ENG_CNF_157` is a generated constant whose strings are static.
        unsafe { raise_site(&err_sites::ENG_CNF_157) };
        return 0;
    }
    // SAFETY: `elist` is a live stack of `CONF_VALUE` pointers.
    let n = unsafe { OPENSSL_sk_num(elist) };
    let mut i: c_int = 0;
    while i < n {
        // SAFETY: `0 <= i < n` and every element is a `CONF_VALUE`.
        let cval = unsafe { OPENSSL_sk_value(elist, i) }.cast::<ConfValue>();
        // SAFETY: `cval` is a live `CONF_VALUE`; its `name`/`value` are NUL-terminated and
        // `cnf` is live.
        if unsafe { int_engine_configure((*cval).name, (*cval).value, cnf) } == 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `static void int_engine_module_finish(CONF_IMODULE *md)` — `:170-178`.
///
/// # Safety
/// `md` must be the live module initialisation, and the module must be registered on the same
/// process; `ENGINE_finish` is called on every engine `int_engine_init` recorded.
unsafe extern "C" fn int_engine_module_finish(_md: *mut ConfImodule) {
    loop {
        let st = INITIALIZED_ENGINES.load(Ordering::Acquire);
        // SAFETY: `st` is NULL or the stack `int_engine_init` built; `OPENSSL_sk_pop` accepts
        // NULL. A popped element is an ENGINE `int_engine_init` pushed.
        let e = unsafe { OPENSSL_sk_pop(st) }.cast::<Engine>();
        if e.is_null() {
            break;
        }
        // SAFETY: `e` holds a functional reference `int_engine_init` took.
        unsafe { ENGINE_finish(e) };
    }
    let st = INITIALIZED_ENGINES.load(Ordering::Acquire);
    // SAFETY: `st` is NULL or the stack this module built; it is released exactly once, and the
    // static is cleared so a later finish does not free it again.
    unsafe { OPENSSL_sk_free(st) };
    INITIALIZED_ENGINES.store(ptr::null_mut(), Ordering::Release);
}

/// `void ENGINE_add_conf_module(void)` — `crypto/engine/eng_cnf.c:180-184`.
///
/// Registers the `engines` module under `CONF_module_add`; the authority discards the answer,
/// and so does this transcription.
///
/// # Safety
///
/// The caller must accept that this writes the process-global configuration-module list, as
/// every other `*_add_conf_module` does.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_add_conf_module() {
    guard_ffi((), || {
        // SAFETY: both callbacks are `'static` `extern "C"` functions with the module types'
        // signatures; the name is a static literal.
        unsafe {
            CONF_module_add(
                c"engines".as_ptr(),
                Some(int_engine_module_init),
                Some(int_engine_module_finish),
            )
        };
    })
}
