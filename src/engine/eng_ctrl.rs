//! Phase 10.9 — `crypto/engine/eng_ctrl.c`: the control-command surface.
//!
//! The digest path never issues a control command, but this unit is part of the
//! twelve section 6 names, and its whole closure is landed — `ENGINE_CMD_DEFN` is
//! `eng_lib.rs`'s and the four functions below call nothing outside libc and the `ERR`
//! queue. It is therefore transcribed whole rather than withheld; nothing here is a stub.
//!
//! ## Two commands are handled by the framework, the rest by the engine
//!
//! An `ENGINE` may set `ENGINE_FLAGS_MANUAL_CMD_CTRL` and handle the eight "meta"
//! commands itself. Without it, `ENGINE_ctrl` intercepts them and walks the engine's own
//! `cmd_defns` list (`int_ctrl_helper`). The distinction is observable: the same command
//! number answers from the table or from the callback depending only on that flag, and
//! `ENGINE_CTRL_GET_FIRST_CMD_TYPE` on an engine with no `cmd_defns` answers `0` while the
//! rest of the family answers `-1` — a difference the authority's own comment
//! (`:71-76`) calls out.
//!
//! ## `ENGINE_CTRL_GET_NAME_FROM_CMD` uses `strcpy` on purpose
//!
//! `:110-116` writes the name into the caller's buffer with `strcpy` and returns the
//! **`strlen` of the copy**, not the precomputed length. The two agree, but the call
//! order (`strlen(strcpy(...))`) is the authority's and is reproduced.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

use crate::engine::eng_lib::{Engine, EngineCmdDefn, EngineCtrlFuncPtr};
use crate::runtime::err::err_sites::{
    ENG_CTRL_121, ENG_CTRL_130, ENG_CTRL_154, ENG_CTRL_167, ENG_CTRL_177, ENG_CTRL_191,
    ENG_CTRL_210, ENG_CTRL_230, ENG_CTRL_249, ENG_CTRL_253, ENG_CTRL_263, ENG_CTRL_271,
    ENG_CTRL_286, ENG_CTRL_303, ENG_CTRL_308, ENG_CTRL_80, ENG_CTRL_88, ENG_CTRL_99,
};
use crate::runtime::err::{raise_site, ERR_clear_error};

extern "C" {
    /// `int strcmp(const char *s1, const char *s2)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
    /// `char *strcpy(char *dst, const char *src)`.
    fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char;
    /// `size_t strlen(const char *s)`.
    fn strlen(s: *const c_char) -> usize;
    /// `long strtol(const char *nptr, char **endptr, int base)`.
    fn strtol(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_long;
}

/// `static const char *int_no_description = ""` (`:19`).
static NO_DESCRIPTION: &[u8] = b"\0";

/// `ENGINE_FLAGS_MANUAL_CMD_CTRL` (`openssl/engine.h:76`) — `(int)0x0002`.
const ENGINE_FLAGS_MANUAL_CMD_CTRL: c_int = 0x0002;

/// `ENGINE_CMD_FLAG_NUMERIC` — `(unsigned int)0x0001`.
const ENGINE_CMD_FLAG_NUMERIC: c_uint = 0x0001;
/// `ENGINE_CMD_FLAG_STRING` — `(unsigned int)0x0002`.
const ENGINE_CMD_FLAG_STRING: c_uint = 0x0002;
/// `ENGINE_CMD_FLAG_NO_INPUT` — `(unsigned int)0x0004`.
const ENGINE_CMD_FLAG_NO_INPUT: c_uint = 0x0004;

/// `ENGINE_CTRL_HAS_CTRL_FUNCTION` (`openssl/engine.h:184`).
const ENGINE_CTRL_HAS_CTRL_FUNCTION: c_int = 10;
/// `ENGINE_CTRL_GET_FIRST_CMD_TYPE` (`:189`).
const ENGINE_CTRL_GET_FIRST_CMD_TYPE: c_int = 11;
/// `ENGINE_CTRL_GET_NEXT_CMD_TYPE` (`:194`).
const ENGINE_CTRL_GET_NEXT_CMD_TYPE: c_int = 12;
/// `ENGINE_CTRL_GET_CMD_FROM_NAME` (`:199`).
const ENGINE_CTRL_GET_CMD_FROM_NAME: c_int = 13;
/// `ENGINE_CTRL_GET_NAME_LEN_FROM_CMD` (`:208`).
const ENGINE_CTRL_GET_NAME_LEN_FROM_CMD: c_int = 14;
/// `ENGINE_CTRL_GET_NAME_FROM_CMD` (`:209`).
const ENGINE_CTRL_GET_NAME_FROM_CMD: c_int = 15;
/// `ENGINE_CTRL_GET_DESC_LEN_FROM_CMD` (`:211`).
const ENGINE_CTRL_GET_DESC_LEN_FROM_CMD: c_int = 16;
/// `ENGINE_CTRL_GET_DESC_FROM_CMD` (`:212`).
const ENGINE_CTRL_GET_DESC_FROM_CMD: c_int = 17;
/// `ENGINE_CTRL_GET_CMD_FLAGS` (`:218`).
const ENGINE_CTRL_GET_CMD_FLAGS: c_int = 18;

/// The `cmd_desc` an entry with none prints.
///
/// The authority's `int_no_description` is a `const char *` to `""`; this returns the
/// same pointer semantics without naming a mutable static.
fn no_description() -> *const c_char {
    NO_DESCRIPTION.as_ptr().cast::<c_char>()
}

/// `static int int_ctrl_cmd_is_null(const ENGINE_CMD_DEFN *defn)` — `:27-32`.
///
/// # Safety
/// `defn` must be a valid `ENGINE_CMD_DEFN` pointer.
unsafe fn int_ctrl_cmd_is_null(defn: *const EngineCmdDefn) -> bool {
    // SAFETY: `defn` is valid per the contract.
    unsafe { (*defn).cmd_num == 0 || (*defn).cmd_name.is_null() }
}

/// `static int int_ctrl_cmd_by_name(const ENGINE_CMD_DEFN *defn, const char *s)` — `:34-45`.
///
/// # Safety
/// `defn` must begin a NUL-terminated-by-`cmd_num` array; `s` must be NUL-terminated.
unsafe fn int_ctrl_cmd_by_name(defn: *const EngineCmdDefn, s: *const c_char) -> c_int {
    let mut idx = 0usize;
    // SAFETY: `defn` is the array's start; `idx` advances only while the entry is non-null.
    unsafe {
        while !int_ctrl_cmd_is_null(defn.add(idx)) {
            if strcmp((*defn.add(idx)).cmd_name, s) == 0 {
                return idx as c_int;
            }
            idx += 1;
        }
    }
    -1
}

/// `static int int_ctrl_cmd_by_num(const ENGINE_CMD_DEFN *defn, unsigned int num)` — `:47-62`.
///
/// # Safety
/// `defn` must begin a NUL-terminated-by-`cmd_num` array.
unsafe fn int_ctrl_cmd_by_num(defn: *const EngineCmdDefn, num: c_uint) -> c_int {
    let mut idx = 0usize;
    // SAFETY: `defn` is the array's start; `idx` advances only while the entry is non-null.
    unsafe {
        while !int_ctrl_cmd_is_null(defn.add(idx)) && (*defn.add(idx)).cmd_num < num {
            idx += 1;
        }
        if (*defn.add(idx)).cmd_num == num {
            return idx as c_int;
        }
    }
    -1
}

/// `static int int_ctrl_helper(ENGINE *e, int cmd, long i, void *p, void (*f)(void))` —
/// `:64-123`.
///
/// # Safety
/// `e` must be a live `ENGINE` with a non-NULL `cmd_defns` for the commands that reach
/// the table; `p` must be a writable string buffer for the two string-fetch commands.
#[allow(clippy::collapsible_if)] // the authority nests the buffer test inside the command test
unsafe fn int_ctrl_helper(
    e: *mut Engine,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    let s = p.cast::<c_char>();
    // The easy one, which needs no search.
    if cmd == ENGINE_CTRL_GET_FIRST_CMD_TYPE {
        // SAFETY: `e` is live.
        let defns = unsafe { (*e).cmd_defns };
        // SAFETY: `defns` is the engine's array or NULL.
        if defns.is_null() || unsafe { int_ctrl_cmd_is_null(defns) } {
            return 0;
        }
        // SAFETY: `defns` is non-NULL.
        return unsafe { (*defns).cmd_num as c_int };
    }
    // One or two commands require a string buffer.
    if cmd == ENGINE_CTRL_GET_CMD_FROM_NAME
        || cmd == ENGINE_CTRL_GET_NAME_FROM_CMD
        || cmd == ENGINE_CTRL_GET_DESC_FROM_CMD
    {
        if s.is_null() {
            // SAFETY: `ENG_CTRL_80` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_CTRL_80) };
            return -1;
        }
    }
    // cmd_name -> cmd_num.
    if cmd == ENGINE_CTRL_GET_CMD_FROM_NAME {
        // SAFETY: `e` is live.
        let defns = unsafe { (*e).cmd_defns };
        if defns.is_null() {
            // SAFETY: `ENG_CTRL_88` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_CTRL_88) };
            return -1;
        }
        // SAFETY: `defns` is the engine's array and `s` is the caller's name.
        let idx = unsafe { int_ctrl_cmd_by_name(defns, s) };
        if idx < 0 {
            // SAFETY: `ENG_CTRL_88` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_CTRL_88) };
            return -1;
        }
        // SAFETY: `idx` is a valid index into the engine's array.
        return unsafe { (*defns.add(idx as usize)).cmd_num as c_int };
    }
    // The rest need a valid command number.
    // SAFETY: `e` is live.
    let defns = unsafe { (*e).cmd_defns };
    if defns.is_null() {
        // SAFETY: `ENG_CTRL_99` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_99) };
        return -1;
    }
    // SAFETY: `defns` is the engine's array.
    let idx = unsafe { int_ctrl_cmd_by_num(defns, i as c_uint) };
    if idx < 0 {
        // SAFETY: `ENG_CTRL_99` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_99) };
        return -1;
    }
    // SAFETY: `idx` is a valid index.
    let cdp = unsafe { defns.add(idx as usize) };
    match cmd {
        ENGINE_CTRL_GET_NEXT_CMD_TYPE => {
            // SAFETY: `cdp.add(1)` is the next entry or the terminator.
            let next = unsafe { cdp.add(1) };
            // SAFETY: `next` is a valid entry.
            if unsafe { int_ctrl_cmd_is_null(next) } {
                0
            } else {
                // SAFETY: `next` is non-null.
                unsafe { (*next).cmd_num as c_int }
            }
        }
        ENGINE_CTRL_GET_NAME_LEN_FROM_CMD => {
            // SAFETY: `cdp` is a valid entry with a name.
            unsafe { strlen((*cdp).cmd_name) as c_int }
        }
        ENGINE_CTRL_GET_NAME_FROM_CMD => {
            // SAFETY: `s` is writable and `cdp.cmd_name` non-NULL (the entry is non-null).
            unsafe { strlen(strcpy(s, (*cdp).cmd_name)) as c_int }
        }
        ENGINE_CTRL_GET_DESC_LEN_FROM_CMD => {
            // SAFETY: `cdp` is a valid entry.
            let desc = unsafe { (*cdp).cmd_desc };
            let d = if desc.is_null() {
                no_description()
            } else {
                desc
            };
            // SAFETY: `d` is NUL-terminated.
            unsafe { strlen(d) as c_int }
        }
        ENGINE_CTRL_GET_DESC_FROM_CMD => {
            // SAFETY: `cdp` is a valid entry.
            let desc = unsafe { (*cdp).cmd_desc };
            let d = if desc.is_null() {
                no_description()
            } else {
                desc
            };
            // SAFETY: `s` is writable and `d` is NUL-terminated.
            unsafe { strlen(strcpy(s, d)) as c_int }
        }
        ENGINE_CTRL_GET_CMD_FLAGS => {
            // SAFETY: `cdp` is a valid entry.
            unsafe { (*cdp).cmd_flags as c_int }
        }
        _ => {
            // SAFETY: `ENG_CTRL_121` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_CTRL_121) };
            -1
        }
    }
}

/// `int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))` — `:125-171`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_ctrl(
    e: *mut Engine,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
) -> c_int {
    if e.is_null() {
        // SAFETY: `ENG_CTRL_130` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_130) };
        return 0;
    }
    // SAFETY: `e` is live.
    let ctrl: Option<EngineCtrlFuncPtr> = unsafe { (*e).ctrl };
    let ctrl_exists = ctrl.is_some();
    match cmd {
        ENGINE_CTRL_HAS_CTRL_FUNCTION => return ctrl_exists as c_int,
        ENGINE_CTRL_GET_FIRST_CMD_TYPE
        | ENGINE_CTRL_GET_NEXT_CMD_TYPE
        | ENGINE_CTRL_GET_CMD_FROM_NAME
        | ENGINE_CTRL_GET_NAME_LEN_FROM_CMD
        | ENGINE_CTRL_GET_NAME_FROM_CMD
        | ENGINE_CTRL_GET_DESC_LEN_FROM_CMD
        | ENGINE_CTRL_GET_DESC_FROM_CMD
        | ENGINE_CTRL_GET_CMD_FLAGS => {
            // SAFETY: `e` is live.
            let manual = unsafe { (*e).flags } & ENGINE_FLAGS_MANUAL_CMD_CTRL != 0;
            if ctrl_exists && !manual {
                // SAFETY: the caller's contract; `p` is the command's argument.
                return unsafe { int_ctrl_helper(e, cmd, i, p, f) };
            }
            if !ctrl_exists {
                // SAFETY: `ENG_CTRL_154` is a generated constant whose strings are static.
                unsafe { raise_site(&ENG_CTRL_154) };
                return -1;
            }
        }
        _ => {}
    }
    if let Some(handler) = ctrl {
        // SAFETY: the handler is the engine's own `ctrl` callback.
        return unsafe { handler(e, cmd, i, p, f) };
    }
    // SAFETY: `ENG_CTRL_167` is a generated constant whose strings are static.
    unsafe { raise_site(&ENG_CTRL_167) };
    0
}

/// `int ENGINE_cmd_is_executable(ENGINE *e, int cmd)` — `:173-183`.
///
/// # Safety
/// `e` must be NULL or point to a live [`Engine`].
#[no_mangle]
pub unsafe extern "C" fn ENGINE_cmd_is_executable(e: *mut Engine, cmd: c_int) -> c_int {
    // SAFETY: `e` is the caller's engine.
    let flags = unsafe {
        ENGINE_ctrl(
            e,
            ENGINE_CTRL_GET_CMD_FLAGS,
            cmd as c_long,
            core::ptr::null_mut(),
            None,
        )
    };
    if flags < 0 {
        // SAFETY: `ENG_CTRL_177` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_177) };
        return 0;
    }
    let f = flags as c_uint;
    if f & ENGINE_CMD_FLAG_NO_INPUT == 0
        && f & ENGINE_CMD_FLAG_NUMERIC == 0
        && f & ENGINE_CMD_FLAG_STRING == 0
    {
        return 0;
    }
    1
}

/// `int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name, long i, void *p,
///     void (*f)(void), int cmd_optional)` — `:185-220`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_ctrl_cmd(
    e: *mut Engine,
    cmd_name: *const c_char,
    i: c_long,
    p: *mut c_void,
    f: Option<unsafe extern "C" fn()>,
    cmd_optional: c_int,
) -> c_int {
    if e.is_null() || cmd_name.is_null() {
        // SAFETY: `ENG_CTRL_191` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_191) };
        return 0;
    }
    // SAFETY: `e` is live.
    let has_ctrl = unsafe { (*e).ctrl }.is_some();
    // SAFETY: `e` is live and `cmd_name` is the caller's name.
    let num = if has_ctrl {
        // SAFETY: the operation's pointers are live per the caller's contract.
        unsafe {
            ENGINE_ctrl(
                e,
                ENGINE_CTRL_GET_CMD_FROM_NAME,
                0,
                cmd_name.cast_mut().cast::<c_void>(),
                None,
            )
        }
    } else {
        -1
    };
    if !has_ctrl || num <= 0 {
        if cmd_optional != 0 {
            ERR_clear_error();
            return 1;
        }
        // SAFETY: `ENG_CTRL_210` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_210) };
        return 0;
    }
    // SAFETY: `e` and `num` are the caller's engine and its command number.
    if unsafe { ENGINE_ctrl(e, num, i, p, f) } > 0 {
        1
    } else {
        0
    }
}

/// `int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
///     int cmd_optional)` — `:222-318`.
///
/// # Safety
/// The pointer arguments must be valid per the authority's C contract.
#[no_mangle]
pub unsafe extern "C" fn ENGINE_ctrl_cmd_string(
    e: *mut Engine,
    cmd_name: *const c_char,
    arg: *const c_char,
    cmd_optional: c_int,
) -> c_int {
    if e.is_null() || cmd_name.is_null() {
        // SAFETY: `ENG_CTRL_230` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_230) };
        return 0;
    }
    // SAFETY: `e` is live.
    let has_ctrl = unsafe { (*e).ctrl }.is_some();
    // SAFETY: `e` is live and `cmd_name` is the caller's name.
    let num = if has_ctrl {
        // SAFETY: the operation's pointers are live per the caller's contract.
        unsafe {
            ENGINE_ctrl(
                e,
                ENGINE_CTRL_GET_CMD_FROM_NAME,
                0,
                cmd_name.cast_mut().cast::<c_void>(),
                None,
            )
        }
    } else {
        -1
    };
    if !has_ctrl || num <= 0 {
        if cmd_optional != 0 {
            ERR_clear_error();
            return 1;
        }
        // SAFETY: `ENG_CTRL_249` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_249) };
        return 0;
    }
    // SAFETY: `e` is live and `num` its command number.
    if unsafe { ENGINE_cmd_is_executable(e, num) } == 0 {
        // SAFETY: `ENG_CTRL_253` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_253) };
        return 0;
    }
    // SAFETY: `e` is live.
    let flags = unsafe {
        ENGINE_ctrl(
            e,
            ENGINE_CTRL_GET_CMD_FLAGS,
            num as c_long,
            core::ptr::null_mut(),
            None,
        )
    };
    if flags < 0 {
        // SAFETY: `ENG_CTRL_263` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_263) };
        return 0;
    }
    let f = flags as c_uint;
    if f & ENGINE_CMD_FLAG_NO_INPUT != 0 {
        if !arg.is_null() {
            // SAFETY: `ENG_CTRL_271` is a generated constant whose strings are static.
            unsafe { raise_site(&ENG_CTRL_271) };
            return 0;
        }
        // SAFETY: `e` is live and `num` its command number.
        if unsafe { ENGINE_ctrl(e, num, 0, arg.cast_mut().cast::<c_void>(), None) } > 0 {
            return 1;
        }
        return 0;
    }
    if arg.is_null() {
        // SAFETY: `ENG_CTRL_286` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_286) };
        return 0;
    }
    if f & ENGINE_CMD_FLAG_STRING != 0 {
        // SAFETY: `e` is live and `num` its command number.
        if unsafe { ENGINE_ctrl(e, num, 0, arg.cast_mut().cast::<c_void>(), None) } > 0 {
            return 1;
        }
        return 0;
    }
    if f & ENGINE_CMD_FLAG_NUMERIC == 0 {
        // SAFETY: `ENG_CTRL_303` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_303) };
        return 0;
    }
    let mut endptr: *mut c_char = core::ptr::null_mut();
    // SAFETY: `arg` is NUL-terminated and `endptr` is a writable slot.
    let l = unsafe { strtol(arg, &mut endptr, 10) };
    // SAFETY: `arg` and `endptr` are the pointers `strtol` was given.
    if arg.cast::<c_char>() == endptr || unsafe { *endptr } != 0 {
        // SAFETY: `ENG_CTRL_308` is a generated constant whose strings are static.
        unsafe { raise_site(&ENG_CTRL_308) };
        return 0;
    }
    // SAFETY: `e` is live and `num` its command number.
    if unsafe { ENGINE_ctrl(e, num, l, core::ptr::null_mut(), None) } > 0 {
        1
    } else {
        0
    }
}
