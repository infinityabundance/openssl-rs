//! Phase 13 staging — `crypto/ui/ui_openssl.c`: the built-in console `UI_METHOD`.
//!
//! This is the *default* method: `UI_new_method` reaches it through `UI_get_default_method`,
//! which answers `&ui_openssl`, and it is what a caller gets when it asks for a pass phrase with
//! no `userdata`. It is transcribed as the authority writes it for the admitted platform
//! (`linux-x86_64`, `docs/AUTHORITY_POLICY.md`): the `TERMIOS`/`SIGACTION` arms are the ones the
//! preprocessor selects, and the VMS, MSDOS, Win32 Console and SGTTY arms are `#ifdef`-absent and
//! are **not** invented here.
//!
//! ## The platform surface, declared where it is used
//!
//! The console method is the one unit in this slice that reaches directly into libc for terminal
//! control: `termios`, `sigaction`, `fopen("/dev/tty")` and the `stdio` stream helpers. Those
//! declarations live at the bottom of this file rather than in `crate::runtime::bio::sys`
//! because that module's own contract is "only what the implemented BIO methods call", and
//! adding a terminal API there would quietly widen it. The layouts (`struct termios`,
//! `struct sigaction`) and the `SIG*`/`ECHO`/`TCSANOW` numbers are read from this machine's
//! glibc headers, the same way `src/rand/sys.rs` reads its own.
//!
//! ## Every path that could block is behind the court
//!
//! `read_string_inner` reads from `tty_in`, which `open_console` sets to `/dev/tty` or `stdin`.
//! Nothing in this crate's unit tests drives it: the tests use `UI_null` and a hand-built method,
//! never the default, so no test can reach a prompt. The `RT-PEM-KEY` court's reader arms supply
//! a password through `PEM_def_callback`'s **`userdata`** arm or a callback, which is the arm
//! that never touches the console; the arms are stated in the probe's own header.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::runtime::bio::sys::{
    errno, fclose, feof, ferror, fflush, fgets, fileno, fopen, fputs, stderr, strcmp, EINVAL,
    ENXIO, FILE,
};
use crate::runtime::bio::sys::{memcpy, strchr};
use crate::runtime::mem::OPENSSL_cleanse;
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::ui::ui_lib::{
    UI_get0_action_string, UI_get0_output_string, UI_get0_result_string, UI_get0_test_string,
    UI_get_input_flags, UI_get_string_type, UI_set_result, Ui, UiFlushFn, UiMethod, UiString,
    UIT_BOOLEAN, UIT_ERROR, UIT_INFO, UIT_PROMPT, UIT_VERIFY, UI_INPUT_FLAG_ECHO,
};

/// `NX509_SIG` — `crypto/ui/ui_openssl.c:151`. The size of the saved-signal table.
const NX509_SIG: usize = 32;

/// `BUFSIZ` — `<stdio.h>` on this platform; `read_string_inner`'s result buffer.
const BUFSIZ: usize = 8192;

/// `SIGINT` — `<signal.h>`.
const SIGINT: c_int = 2;
/// `SIGKILL` — `<signal.h>`; skipped by `pushsig` because it cannot be caught.
const SIGKILL: c_int = 9;
/// `SIGUSR1` — `<signal.h>`; skipped by both `pushsig` and `popsig`, as the authority does.
const SIGUSR1: c_int = 10;
/// `SIGUSR2` — `<signal.h>`; skipped by both.
const SIGUSR2: c_int = 12;
/// `SIGWINCH` — `<signal.h>`; reset to `SIG_DFL` after the table is installed.
const SIGWINCH: c_int = 28;

/// `ECHO` — `<termios.h>`'s `c_lflag` bit cleared to read without echoing.
const ECHO: c_uint = 0o10;
/// `TCSANOW` — `<termios.h>`'s `optional_actions` value.
const TCSANOW: c_int = 0;

/// `ENOTTY` — `<asm-generic/errno.h>`.
const ENOTTY: c_int = 25;
/// `EIO` — `<asm-generic/errno.h>`; Linux returns it for a detached terminal.
const EIO: c_int = 5;
/// `EPERM` — `<asm-generic/errno.h>`; returned under `fork()`+`execve()` from a daemon.
const EPERM: c_int = 1;
/// `ENODEV` — `<asm-generic/errno.h>`; MacOS X's "not supported by device".
const ENODEV: c_int = 19;

/// `static TTY_STRUCT tty_orig` — `crypto/ui/ui_openssl.c:173`, the terminal state to restore.
static mut TTY_ORIG: Termios = ZERO_TERMIOS;
/// `static TTY_STRUCT tty_new` — `crypto/ui/ui_openssl.c:173`, the state being installed.
static mut TTY_NEW: Termios = ZERO_TERMIOS;
/// `static FILE *tty_in` — `crypto/ui/ui_openssl.c:176`.
static mut TTY_IN: *mut FILE = ptr::null_mut();
/// `static FILE *tty_out` — `crypto/ui/ui_openssl.c:176`.
static mut TTY_OUT: *mut FILE = ptr::null_mut();
/// `static int is_a_tty` — `crypto/ui/ui_openssl.c:177`. Cleared when the terminal calls refuse.
static mut IS_A_TTY: c_int = 0;

/// `static struct sigaction savsig[NX509_SIG]` — `crypto/ui/ui_openssl.c:156`. Index 0 is never
/// used; the table is indexed `1..NX509_SIG`.
static mut SAVSIG: [SigAction; NX509_SIG] = [ZERO_SIGACTION; NX509_SIG];

/// `static volatile sig_atomic_t intr_signal` — `crypto/ui/ui_openssl.c:273`.
static mut INTR_SIGNAL: c_int = 0;

/// `static int ps` — `crypto/ui/ui_openssl.c:278`, the count of installed signal handlers.
static mut PS: c_int = 0;

/// `static int write_string(UI *ui, UI_STRING *uis)` — `crypto/ui/ui_openssl.c:203-218`.
///
/// Prints `UIT_ERROR` and `UIT_INFO` and ignores the rest, so an error or an info line reaches
/// the terminal before any prompt. Always answers `1`.
///
/// # Safety
///
/// `ui` is live; `uis` is a live queue element whose `out_string` is NUL-terminated.
unsafe extern "C" fn write_string(_ui: *mut Ui, uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live per the caller's contract.
    match unsafe { UI_get_string_type(uis) } {
        UIT_ERROR | UIT_INFO => {
            // SAFETY: `uis` is live and `out_string` is NUL-terminated.
            let s = unsafe { UI_get0_output_string(uis) };
            // SAFETY: `s` is NUL-terminated and the output stream is the session's.
            unsafe { fputs(s, TTY_OUT) };
            // SAFETY: the output stream is live for the session.
            unsafe { fflush(TTY_OUT) };
        }
        _ => {}
    }
    1
}

/// `static int read_string(UI *ui, UI_STRING *uis)` — `crypto/ui/ui_openssl.c:220-257`.
///
/// A `UIT_BOOLEAN` prints its prompt and action text and reads without stripping the newline; a
/// `UIT_PROMPT` prints its prompt and reads with the newline stripped; a `UIT_VERIFY` prints
/// `"Verifying - "` and compares the result against the test string, answering `0` on a mismatch.
/// Every path returns what `read_string_inner` returns, so the `0`/`-1` distinction survives.
///
/// # Safety
///
/// As [`write_string`], and the reader this drives reads from the session's input stream.
unsafe extern "C" fn read_string(ui: *mut Ui, uis: *mut UiString) -> c_int {
    // SAFETY: `uis` is live per the caller's contract.
    match unsafe { UI_get_string_type(uis) } {
        UIT_BOOLEAN => {
            // SAFETY: `uis` is live and both strings are NUL-terminated.
            unsafe {
                fputs(UI_get0_output_string(uis), TTY_OUT);
                fputs(UI_get0_action_string(uis), TTY_OUT);
                fflush(TTY_OUT);
            }
            // SAFETY: `ui`/`uis` are live; the echo flag is the caller's.
            return unsafe {
                read_string_inner(ui, uis, UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO, 0)
            };
        }
        UIT_PROMPT => {
            // SAFETY: `uis` is live and the prompt is NUL-terminated.
            unsafe {
                fputs(UI_get0_output_string(uis), TTY_OUT);
                fflush(TTY_OUT);
            }
            // SAFETY: `ui`/`uis` are live; the echo flag is the caller's.
            return unsafe {
                read_string_inner(ui, uis, UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO, 1)
            };
        }
        UIT_VERIFY => {
            // SAFETY: `uis` is live and the prompt is NUL-terminated.
            unsafe {
                fprintf(
                    TTY_OUT,
                    c"Verifying - %s".as_ptr(),
                    UI_get0_output_string(uis),
                );
                fflush(TTY_OUT);
            }
            // SAFETY: `ui`/`uis` are live; the echo flag is the caller's.
            let ok = unsafe {
                read_string_inner(ui, uis, UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO, 1)
            };
            if ok <= 0 {
                return ok;
            }
            // SAFETY: both strings are the queue element's own and NUL-terminated.
            if unsafe { strcmp(UI_get0_result_string(uis), UI_get0_test_string(uis)) } != 0 {
                // SAFETY: the literal is NUL-terminated and the stream is the session's.
                unsafe {
                    fputs(c"Verify failure\n".as_ptr(), TTY_OUT);
                    fflush(TTY_OUT);
                }
                return 0;
            }
        }
        _ => {}
    }
    1
}

/// `static int read_till_nl(FILE *in)` — `crypto/ui/ui_openssl.c:261-271`.
///
/// Reads in four-byte chunks until one contains a newline. Answers `0` when the stream ends
/// first, which is the `goto error` the caller takes.
///
/// # Safety
///
/// `in` is a live `FILE *`.
unsafe fn read_till_nl(in_: *mut FILE) -> c_int {
    const SIZE: usize = 4;
    let mut buf = [0 as c_char; SIZE + 1];

    loop {
        // SAFETY: `buf` is five bytes and `in_` is a live stream.
        if unsafe { fgets(buf.as_mut_ptr(), SIZE as c_int, in_) }.is_null() {
            return 0;
        }
        // SAFETY: `buf` is NUL-terminated by `fgets`.
        if !unsafe { strchr(buf.as_ptr(), b'\n' as c_int) }.is_null() {
            break;
        }
    }
    1
}

/// `static int read_string_inner(UI *ui, UI_STRING *uis, int echo, int strip_nl)` —
/// `crypto/ui/ui_openssl.c:276-368`.
///
/// The signal protocol is the reason this is not a one-liner: `pushsig` installs `recsig` over
/// every catchable signal and `popsig` restores the old table, so a Ctrl-C sets `intr_signal`
/// instead of killing the process, and the answer becomes `-1` rather than a partial read.
/// `ps` is the count of handlers installed, and the error path uses it to decide which of the
/// three teardown steps still apply.
///
/// # Safety
///
/// `ui`/`uis` are live; the session's input and output streams are the ones `open_console` set.
unsafe extern "C" fn read_string_inner(
    ui: *mut Ui,
    uis: *mut UiString,
    echo: c_int,
    strip_nl: c_int,
) -> c_int {
    let mut ok: c_int;
    let mut result = [0 as c_char; BUFSIZ];
    let maxsize: c_int = (BUFSIZ - 1) as c_int;
    let echo_eol: c_int = c_int::from(echo == 0);

    // SAFETY: the static is this unit's own.
    unsafe { INTR_SIGNAL = 0 };
    ok = 0;
    // SAFETY: the static is this unit's own.
    unsafe { PS = 0 };

    // SAFETY: the static table is this unit's own.
    unsafe { pushsig() };
    // SAFETY: the static is this unit's own.
    unsafe { PS = 1 };

    // SAFETY: `ui` is live and the session's streams are the ones `open_console` set.
    if echo == 0 && unsafe { noecho_console(ui) } == 0 {
        // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
        return unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) };
    }
    // SAFETY: the static is this unit's own.
    unsafe { PS = 2 };

    result[0] = 0;
    // SAFETY: `result` is `BUFSIZ` bytes and the stream is the session's.
    let p = unsafe { fgets(result.as_mut_ptr(), maxsize, TTY_IN) };
    if p.is_null() {
        // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
        return unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) };
    }
    // SAFETY: the stream is live for the session.
    if unsafe { feof(TTY_IN) } != 0 {
        // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
        return unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) };
    }
    // SAFETY: the stream is live for the session.
    if unsafe { ferror(TTY_IN) } != 0 {
        // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
        return unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) };
    }
    // SAFETY: `result` is NUL-terminated by `fgets`.
    let nl = unsafe { strchr(result.as_mut_ptr(), b'\n' as c_int) };
    if !nl.is_null() {
        if strip_nl != 0 {
            // SAFETY: `nl` points inside `result`, which is writable.
            unsafe { *nl = 0 };
        }
    } else {
        // SAFETY: the stream is live for the session.
        if unsafe { read_till_nl(TTY_IN) } == 0 {
            // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
            return unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) };
        }
    }
    // SAFETY: `ui`/`uis` are live and `result` is NUL-terminated.
    if unsafe { UI_set_result(ui, uis, result.as_ptr()) } >= 0 {
        ok = 1;
    }

    // SAFETY: `ui`/`uis` are live and `result` is this frame's own buffer.
    unsafe { read_string_inner_error(ui, uis, ok, echo, echo_eol, &mut result) }
}

/// `error:` of `read_string_inner` — `crypto/ui/ui_openssl.c:352-367`.
///
/// Split out so the four `goto error` sites share one transcription of the teardown rather than
/// four copies. `ps` decides which steps run; the buffer is cleansed on every path, successful
/// ones included.
///
/// # Safety
///
/// `ui`/`uis` are live; `result` is this call's own `BUFSIZ`-byte buffer.
unsafe fn read_string_inner_error(
    ui: *mut Ui,
    _uis: *mut UiString,
    mut ok: c_int,
    echo: c_int,
    echo_eol: c_int,
    result: &mut [c_char; BUFSIZ],
) -> c_int {
    // SAFETY: the static is this unit's own.
    if unsafe { INTR_SIGNAL } == SIGINT {
        ok = -1;
    }
    if echo_eol != 0 {
        // SAFETY: the literal is NUL-terminated and the stream is the session's.
        unsafe { fprintf(TTY_OUT, c"\n".as_ptr()) };
    }
    // SAFETY: the static is this unit's own, and `noecho_console` reads only the session state.
    if unsafe { PS } >= 2 && echo == 0 && unsafe { echo_console(ui) } == 0 {
        ok = 0;
    }

    // SAFETY: the static is this unit's own.
    if unsafe { PS } >= 1 {
        // SAFETY: the handlers installed by `pushsig` are the ones `popsig` restores.
        unsafe { popsig() };
    }

    // SAFETY: `result` is this frame's own array.
    unsafe { OPENSSL_cleanse(result.as_mut_ptr().cast::<c_void>(), BUFSIZ) };
    ok
}

/// `static int open_console(UI *ui)` — `crypto/ui/ui_openssl.c:371-481`.
///
/// Takes the session lock, opens `/dev/tty` for both directions (falling back to `stdin` and
/// `stderr`), and probes the terminal state with `tcgetattr`. The errno chain treats a whole set
/// of "this is not a terminal" answers as a non-fatal `is_a_tty = 0`; only an errno outside that
/// set raises `UI_R_UNKNOWN_TTYGET_ERRNO_VALUE` and refuses.
///
/// # Safety
///
/// `ui` is live and its `lock` was created by `UI_new_method`.
unsafe extern "C" fn open_console(ui: *mut Ui) -> c_int {
    // SAFETY: `ui` is live and `lock` is its own.
    if unsafe { CRYPTO_THREAD_write_lock((*ui).lock) } == 0 {
        return 0;
    }
    // SAFETY: the statics are this unit's own.
    unsafe { IS_A_TTY = 1 };

    // SAFETY: the literals are NUL-terminated and `fopen` validates its own result.
    unsafe {
        TTY_IN = fopen(c"/dev/tty".as_ptr(), c"r".as_ptr());
        if TTY_IN.is_null() {
            TTY_IN = stdin;
        }
        TTY_OUT = fopen(c"/dev/tty".as_ptr(), c"w".as_ptr());
        if TTY_OUT.is_null() {
            TTY_OUT = stderr;
        }
    }

    // SAFETY: the input stream is set above and `TTY_ORIG` is this unit's own.
    if unsafe { tcgetattr(fileno(TTY_IN), ptr::addr_of_mut!(TTY_ORIG)) } == -1 {
        // SAFETY: `errno()` reads libc's thread-local `errno` through `__errno_location`.
        let e = unsafe { errno() };
        if e == ENOTTY || e == EINVAL || e == ENXIO || e == EIO || e == EPERM || e == ENODEV {
            // SAFETY: the static is this unit's own.
            unsafe { IS_A_TTY = 0 };
        } else {
            // SAFETY: the site is a compile-time constant; the message is the authority's
            // `"errno=%d"` with the value `tcgetattr` left behind.
            unsafe { raise_unknown_ttyget(e) };
            return 0;
        }
    }
    1
}

/// `static int noecho_console(UI *ui)` — `crypto/ui/ui_openssl.c:483-517`.
///
/// Copies the saved terminal state, clears `ECHO`, and installs it when the stream is a terminal.
///
/// # Safety
///
/// `ui` is live; the session's input stream was set by [`open_console`].
unsafe extern "C" fn noecho_console(ui: *mut Ui) -> c_int {
    let _ = ui;
    // SAFETY: both statics are this unit's own and are the same type.
    unsafe {
        memcpy(
            ptr::addr_of_mut!(TTY_NEW).cast::<c_void>(),
            ptr::addr_of!(TTY_ORIG).cast::<c_void>(),
            core::mem::size_of::<Termios>(),
        );
        TTY_NEW.c_lflag &= !ECHO;
    }
    // SAFETY: the statics are this unit's own and the input stream is the session's.
    if unsafe { IS_A_TTY } != 0
        // SAFETY: the input stream is the session's and `TTY_NEW` is this unit's own.
        && unsafe { tcsetattr(fileno(TTY_IN), TCSANOW, ptr::addr_of!(TTY_NEW)) } == -1
    {
        return 0;
    }
    1
}

/// `static int echo_console(UI *ui)` — `crypto/ui/ui_openssl.c:519-548`.
///
/// The restore half of [`noecho_console`]: copies the saved state back and installs it. It has no
/// `TTY_FLAGS` edit, which is the whole difference between the two.
///
/// # Safety
///
/// As [`noecho_console`].
unsafe extern "C" fn echo_console(ui: *mut Ui) -> c_int {
    let _ = ui;
    // SAFETY: both statics are this unit's own and are the same type.
    unsafe {
        memcpy(
            ptr::addr_of_mut!(TTY_NEW).cast::<c_void>(),
            ptr::addr_of!(TTY_ORIG).cast::<c_void>(),
            core::mem::size_of::<Termios>(),
        );
    }
    // SAFETY: the statics are this unit's own and the input stream is the session's.
    if unsafe { IS_A_TTY } != 0
        // SAFETY: the input stream is the session's and `TTY_NEW` is this unit's own.
        && unsafe { tcsetattr(fileno(TTY_IN), TCSANOW, ptr::addr_of!(TTY_NEW)) } == -1
    {
        return 0;
    }
    1
}

/// `static int close_console(UI *ui)` — `crypto/ui/ui_openssl.c:550-569`.
///
/// Closes the two streams unless they are the process's own `stdin`/`stderr`, releases the session
/// lock and answers `1`. The authority has a VMS arm that could answer `0`; it is `#ifdef`-absent
/// here.
///
/// # Safety
///
/// `ui` is live and its `lock` is held by [`open_console`].
unsafe extern "C" fn close_console(ui: *mut Ui) -> c_int {
    // SAFETY: the statics are this unit's own, and `stdin`/`stderr` are the process's.
    unsafe {
        if TTY_IN != stdin {
            fclose(TTY_IN);
        }
        if TTY_OUT != stderr {
            fclose(TTY_OUT);
        }
    }
    // SAFETY: `ui` is live and `lock` is its own.
    unsafe { CRYPTO_THREAD_unlock((*ui).lock) };

    1
}

/// `static void pushsig(void)` — `crypto/ui/ui_openssl.c:573-617`.
///
/// Installs `recsig` over every signal from 1 to `NX509_SIG - 1` except `SIGUSR1`, `SIGUSR2` and
/// `SIGKILL`. The `SIGACTION` arm is the active one; the `signal()` arm is `#ifdef`-absent. The
/// final `signal(SIGWINCH, SIG_DFL)` is unconditional and so is transcribed.
///
/// # Safety
///
/// Touches only this unit's own `SAVSIG` table and the process's signal dispositions.
unsafe fn pushsig() {
    // SAFETY: the all-zero `SigAction` is a valid value and is what the authority's `memset`
    // produces.
    let mut sa: SigAction = unsafe { core::mem::zeroed() };
    sa.sa_handler = Some(recsig);

    let mut i: c_int = 1;
    while (i as usize) < NX509_SIG {
        if i == SIGUSR1 || i == SIGUSR2 || i == SIGKILL {
            i += 1;
            continue;
        }
        // SAFETY: `i` is a valid signal number, `sa` is the handler to install, and the slot is
        // this unit's own.
        unsafe { sigaction(i, ptr::addr_of!(sa), ptr::addr_of_mut!(SAVSIG[i as usize])) };
        i += 1;
    }

    // SAFETY: `SIGWINCH` is a valid signal and `SIG_DFL` is the null handler.
    unsafe { signal(SIGWINCH, None) };
}

/// `static void popsig(void)` — `crypto/ui/ui_openssl.c:619-646`.
///
/// Restores every saved disposition. Unlike `pushsig` it does **not** skip `SIGKILL`; it skips
/// only `SIGUSR1` and `SIGUSR2`, exactly as the authority writes it.
///
/// # Safety
///
/// Restores the table [`pushsig`] filled.
unsafe fn popsig() {
    let mut i: c_int = 1;
    while (i as usize) < NX509_SIG {
        if i == SIGUSR1 || i == SIGUSR2 {
            i += 1;
            continue;
        }
        // SAFETY: `i` is a valid signal number and the slot is this unit's own.
        unsafe { sigaction(i, ptr::addr_of!(SAVSIG[i as usize]), ptr::null_mut()) };
        i += 1;
    }
}

/// `static void recsig(int i)` — `crypto/ui/ui_openssl.c:648-651`.
///
/// The handler. It writes the signal number to `intr_signal` and returns, which is why `SIGINT`
/// becomes a `-1` answer rather than a process death.
///
/// # Safety
///
/// A signal handler; it writes one `static` this unit owns and async-signal-safety holds because
/// the store is a plain aligned `int`.
unsafe extern "C" fn recsig(i: c_int) {
    // SAFETY: the static is this unit's own.
    unsafe { INTR_SIGNAL = i };
}

/// `static UI_METHOD ui_openssl` — `crypto/ui/ui_openssl.c:698-706`.
///
/// `open_console`, `write_string`, no flusher, `read_string`, `close_console`, and NULL for the
/// duplicator, the destructor and the prompt constructor.
static mut UI_OPENSSL: UiMethod = UiMethod {
    name: c"OpenSSL default user interface".as_ptr().cast_mut(),
    ui_open_session: Some(open_console),
    ui_write_string: Some(write_string),
    ui_flush: None::<UiFlushFn>,
    ui_read_string: Some(read_string),
    ui_close_session: Some(close_console),
    ui_duplicate_data: None,
    ui_destroy_data: None,
    ui_construct_prompt: None,
    ex_data: crate::runtime::ex_data::CryptoExData {
        ctx: ptr::null_mut(),
        sk: ptr::null_mut(),
    },
};

/// `static const UI_METHOD *default_UI_meth = &ui_openssl` — `crypto/ui/ui_openssl.c:714`.
static mut DEFAULT_UI_METH: *const UiMethod = ptr::addr_of!(UI_OPENSSL);

/// `UI_METHOD *UI_OpenSSL(void)` — `crypto/ui/ui_openssl.c:709-712`.
///
/// Answers the address of the one `'static` console method. `OPENSSL_NO_UI_CONSOLE` is undefined
/// in this profile, so the export exists and this is its body.
///
/// # Safety
///
/// Takes no arguments and touches no caller pointer.
#[no_mangle]
pub unsafe extern "C" fn UI_OpenSSL() -> *mut UiMethod {
    ptr::addr_of_mut!(UI_OPENSSL)
}

/// `const UI_METHOD *UI_get_default_method(void)` — `crypto/ui/ui_openssl.c:727-730`.
///
/// The current default, which `UI_new_method` reaches when the caller passes NULL. It begins as
/// `&ui_openssl`; [`UI_set_default_method`] replaces it.
///
/// # Safety
///
/// Takes no arguments; the answer is NULL or a `'static` method object.
#[no_mangle]
pub unsafe extern "C" fn UI_get_default_method() -> *const UiMethod {
    // SAFETY: the static is this unit's own; only `UI_set_default_method` writes it.
    unsafe { DEFAULT_UI_METH }
}

/// `void UI_set_default_method(const UI_METHOD *meth)` — `crypto/ui/ui_openssl.c:722-725`.
///
/// A process-global setter with no locking, exactly as the authority writes it.
///
/// # Safety
///
/// `meth` is a live method object that outlives every future `UI_new`.
#[no_mangle]
pub unsafe extern "C" fn UI_set_default_method(meth: *const UiMethod) {
    // SAFETY: the static is this unit's own.
    unsafe { DEFAULT_UI_METH = meth };
}

// The two `<stdio.h>` declarations the console method needs and `crate::runtime::bio::sys` does
// not carry: a C-variadic `fprintf`, and `stdin` (which `sys` exposes only for `stderr`).
extern "C" {
    /// `int fprintf(FILE *, const char *, ...)` — `<stdio.h>`, C-variadic.
    fn fprintf(f: *mut FILE, fmt: *const c_char, ...) -> c_int;
    /// `FILE *stdin` — `<stdio.h>`, a variable of type `FILE *` on glibc.
    static mut stdin: *mut FILE;
}

// `int tcgetattr(int, struct termios *)` and `int tcsetattr(int, int, const struct termios *)` —
// `<termios.h>`.
extern "C" {
    fn tcgetattr(fd: c_int, t: *mut Termios) -> c_int;
    fn tcsetattr(fd: c_int, actions: c_int, t: *const Termios) -> c_int;
}

// `int sigaction(int, const struct sigaction *, struct sigaction *)` and
// `sighandler_t signal(int, sighandler_t)` — `<signal.h>`.
extern "C" {
    fn sigaction(signum: c_int, act: *const SigAction, oldact: *mut SigAction) -> c_int;
    fn signal(
        signum: c_int,
        handler: Option<unsafe extern "C" fn(c_int)>,
    ) -> Option<unsafe extern "C" fn(c_int)>;
}

/// `struct termios` — `<bits/termios-struct.h>`, the x86_64 glibc layout.
///
/// `NCCS` is 32, so the size is 60 with the `c_line` byte's padding and the two speed fields.
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    /// `tcflag_t c_iflag`.
    c_iflag: c_uint,
    /// `tcflag_t c_oflag`.
    c_oflag: c_uint,
    /// `tcflag_t c_cflag`.
    c_cflag: c_uint,
    /// `tcflag_t c_lflag` — the field `ECHO` lives in.
    c_lflag: c_uint,
    /// `cc_t c_line`.
    c_line: c_uchar,
    /// `cc_t c_cc[NCCS]`.
    c_cc: [c_uchar; 32],
    /// `speed_t c_ispeed`.
    c_ispeed: c_uint,
    /// `speed_t c_ospeed`.
    c_ospeed: c_uint,
}

/// The all-zero `Termios`, so the two statics can be initialised as the authority's are.
const ZERO_TERMIOS: Termios = Termios {
    c_iflag: 0,
    c_oflag: 0,
    c_cflag: 0,
    c_lflag: 0,
    c_line: 0,
    c_cc: [0; 32],
    c_ispeed: 0,
    c_ospeed: 0,
};

/// `struct sigaction` — `<bits/sigaction.h>`, the x86_64 glibc layout.
///
/// The authority sets `sa_handler` and zeroes the rest with `memset`, so the handler's union with
/// `sa_sigaction` is modelled as the eight-byte `sa_handler` slot it writes; `sa_mask` is the
/// 128-byte `sigset_t` (`unsigned long __val[16]`).
#[repr(C)]
#[derive(Clone, Copy)]
struct SigAction {
    /// `void (*sa_handler)(int)` — the first eight bytes of the handler union.
    sa_handler: Option<unsafe extern "C" fn(c_int)>,
    /// `__sigset_t sa_mask` — 16 `unsigned long`s.
    sa_mask: [u64; 16],
    /// `int sa_flags`.
    sa_flags: c_int,
    /// `void (*sa_restorer)(void)` — the padding before it is part of the layout.
    sa_restorer: Option<unsafe extern "C" fn()>,
}

/// The all-zero `SigAction`, the state `memset(&sa, 0, sizeof(sa))` produces.
const ZERO_SIGACTION: SigAction = SigAction {
    sa_handler: None,
    sa_mask: [0; 16],
    sa_flags: 0,
    sa_restorer: None,
};

const _: () = {
    assert!(core::mem::size_of::<Termios>() == 60);
    assert!(core::mem::size_of::<SigAction>() == 152);
};

/// `ERR_raise_data(ERR_LIB_UI, UI_R_UNKNOWN_TTYGET_ERRNO_VALUE, "errno=%d", errno)` —
/// `crypto/ui/ui_openssl.c:457`.
///
/// The message is formatted here rather than at the site only because `err_sites` carries the
/// coordinates and not the format; the value is the `errno` the failed `tcgetattr` left.
///
/// # Safety
///
/// Nothing: the message buffer is this function's own.
unsafe fn raise_unknown_ttyget(e: c_int) {
    use crate::runtime::bio::print::BIO_snprintf;
    use crate::runtime::err::{err_sites, raise_site_data};

    let mut msg = [0 as c_char; 32];
    // SAFETY: `msg` is a 32-byte buffer and the format and argument match.
    unsafe { BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"errno=%d".as_ptr(), e) };
    // SAFETY: the site is a compile-time constant and `msg` is NUL-terminated.
    unsafe { raise_site_data(&err_sites::UI_OPENSSL_457, msg.as_ptr()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::ui_lib::{UI_free, UI_new_method};

    /// The default method object is the console one and its callbacks are the ones `ui_openssl.c`
    /// installs. Nothing here drives the method, so no terminal is opened.
    #[test]
    fn the_default_method_is_the_console_one() {
        // SAFETY: `UI_OpenSSL` returns a `'static` object.
        let m = unsafe { UI_OpenSSL() };
        assert!(!m.is_null());
        // SAFETY: `m` is the `'static` console method. The two callbacks are checked for
        // presence rather than compared by address: a function pointer's address is not
        // guaranteed unique across codegen units, so `assert_eq!` on the pointers is not a
        // meaningful test.
        unsafe {
            assert!((*m).ui_open_session.is_some());
            assert!((*m).ui_close_session.is_some());
            assert!((*m).ui_flush.is_none());
        }
        // SAFETY: `UI_get_default_method` answers the process default.
        let d = unsafe { UI_get_default_method() };
        assert_eq!(d, m.cast_const());
    }

    /// A `UI` built over the default method reports it, and `UI_free` releases the object without
    /// touching the terminal.
    #[test]
    fn a_ui_over_the_default_method_reports_it() {
        // SAFETY: `UI_get_default_method` answers a `'static` method.
        let meth = unsafe { UI_get_default_method() };
        // SAFETY: `meth` is live.
        let ui = unsafe { UI_new_method(meth) };
        assert!(!ui.is_null());
        // SAFETY: `ui` is live.
        unsafe {
            assert_eq!((*ui).meth, meth);
            UI_free(ui);
        }
    }
}
