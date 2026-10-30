//! Phase 14.3 — `ssl/ssl_conf.c`: the `SSL_CONF_CTX` command parser.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives 14.3 `ssl_conf.c` (11 open rows). They are the configuration
//! context's lifecycle and flag accessors (`SSL_CONF_CTX_new`/`_free`/`_set_flags`/`_clear_flags`/
//! `_set1_prefix`/`_set_ssl`/`_set_ssl_ctx`), the command dispatch (`SSL_CONF_cmd`,
//! `SSL_CONF_cmd_value_type`, `SSL_CONF_cmd_argv`) and the finishing pass (`SSL_CONF_CTX_finish`).
//!
//! The command table is the one 14.3's sibling module `src/ssl/ssl_ciph.rs` serves: the
//! `cipher`/`ciphersuites` handlers call the ciphersuite setters, and `protocol`/`options`/`verify`
//! drive the option/verify words the object model landed in 14.1.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The certificate- and key-loading commands are not wired.** `cert`, `key`, `dhparam`, the
//!   `*CAfile`/`*CApath`/`*CAstore` family and `serverinfo` name loaders that are 14.7's; this
//!   module keeps every such row in the command table (so `SSL_CONF_cmd_value_type` and command
//!   *recognition* are the authority's) but the handler itself returns the authority's failure
//!   value rather than attempting a load. The court drives those rows' value types only.
//! * **The signature-algorithm and group-list commands are not wired.** `sigalgs`, `client_sigalgs`,
//!   `groups`, `curves` and `named_curve` name setters that are 14.5's; their table rows are kept
//!   and their handlers return the authority's failure value. As above, only their value types are
//!   driven.
//! * **`ssl_set_version_bound` is pulled forward from 14.5.** `min_protocol`/`max_protocol` call
//!   `ssl_set_version_bound` (`ssl/statem/statem_lib.c:2107-2156`), which is 14.5's unit; it is
//!   transcribed here because 14.3's parser is what drives it, and `src/ssl/mod.rs` records the
//!   correction.
//! * **`SSL_CONF_CTX_finish`'s `canames` hand-off is unreachable.** The authority pops a
//!   `STACK_OF(X509_NAME)` onto the context or connection; nothing in this slice installs one, so
//!   `canames` is always NULL and the stack is freed with `OPENSSL_sk_free` rather than a typed
//!   `sk_X509_NAME_pop_free`.
//! * **The configuration-context contract is narrower than the authority's.** The authority's
//!   `SSL_CONF_cmd(3)` documentation states that the context is valid but neither requires nor
//!   checks exclusive access, and the C implementation performs no such check. This crate's
//!   [`SSL_CONF_cmd`]/[`SSL_CONF_cmd_argv`] `# Safety` contracts require exclusive access to the
//!   context and to the `SSL`/`SSL_CTX` it wraps and forbid concurrent mutation. This is a
//!   documented divergence (`AGENTS.md` §17) that narrows what we accept; it changes no return
//!   value for a conforming caller (B46-D1).
//! * **An overlapping invocation is refused at run time (B46-D2).** The authority performs no
//!   check, so a re-entrant or aliased `SSL_CONF_cmd` on the same context would proceed into
//!   aliasing/UB. `SslConfCtx` now carries an `in_use` flag set on entry to
//!   [`SSL_CONF_cmd`]/[`SSL_CONF_cmd_argv`] and cleared by an RAII guard on every exit path,
//!   including panic. A second invocation while the flag is set returns the API's ordinary
//!   failure value (`0`) instead of aliasing. This is a deliberate, documented divergence: it
//!   refuses where the authority would proceed, and it is the only same-context, same-thread
//!   guarantee this crate adds beyond the authority.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)] // the handlers carry the authority's `cmd_<Name>` spellings

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::{OPENSSL_sk_free, OpenSslStack};
use crate::ssl::ssl_ciph::{SSL_CTX_set_ciphersuites, SSL_set_ciphersuites};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_lib::{
    SSL_CTX_set_block_padding_ex, SSL_CTX_set_cipher_list, SSL_CTX_set_num_tickets,
    SSL_set_block_padding_ex, SSL_set_cipher_list, SSL_set_num_tickets, Ssl, SslCtx,
};

const FILE: *const c_char = c"ssl/ssl_conf.c".as_ptr();
const FILE_SEAM: SeamFile = SeamFile::new(c"ssl/ssl_conf.c");

/// `SSL_TFLAG_INV` — `ssl_conf.c:40`.
const SSL_TFLAG_INV: c_uint = 0x1;
/// `SSL_TFLAG_TYPE_MASK` — `ssl_conf.c:42`.
const SSL_TFLAG_TYPE_MASK: c_uint = 0xf00;
/// `SSL_TFLAG_CERT` — `ssl_conf.c:46`.
const SSL_TFLAG_CERT: c_uint = 0x100;
/// `SSL_TFLAG_VFY` — `ssl_conf.c:48`.
const SSL_TFLAG_VFY: c_uint = 0x200;
/// `SSL_TFLAG_BOTH` — `SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_SERVER`.
const SSL_TFLAG_BOTH: c_uint = 0x4 | 0x8;

/// `SSL_PKEY_NUM` — `ssl_local.h`; the certificate-slot count the filename array is sized by.
const SSL_PKEY_NUM: usize = 9;

type ConfCmdFn = unsafe extern "C" fn(*mut SslConfCtx, *const c_char) -> c_int;

/// `struct ssl_flag_tbl` — `ssl_conf.c:26-31`.
struct SslFlagTbl {
    name: &'static [u8],
    name_flags: c_uint,
    option_value: u64,
}

/// `struct ssl_switch_tbl` — `ssl_conf.c:34-37`.
struct SslSwitchTbl {
    option_value: u64,
    name_flags: c_uint,
}

/// `struct ssl_conf_cmd_tbl` — `ssl_conf.c:737-743`, indexed by row. For a switch row `cmd` is
/// `None`; the authority's `#name`/`cmdopt` macro expansion puts the command's C name in
/// `str_file` and its command-line spelling in `str_cmdline`.
struct SslConfCmdTbl {
    cmd: Option<ConfCmdFn>,
    str_file: Option<&'static [u8]>,
    str_cmdline: Option<&'static [u8]>,
    flags: c_uint,
    value_type: c_uint,
}

/// `struct ssl_conf_ctx_st` — `ssl_conf.c:77-109`. Opaque to a consumer.
///
/// The type is deliberately **not** `#[repr(C)]`: the authority allocates one block and
/// hands out only the pointer, so no consumer observes the field order or the size. The
/// `in_use` field is a candidate-only addition (it has no authority counterpart) and does
/// not change any exported symbol or ABI: `SSL_CONF_CTX_new` allocates
/// `size_of::<SslConfCtx>()` through the crate's own `CRYPTO_*` seam, and every other
/// exported entry point takes/returns the opaque pointer.
pub struct SslConfCtx {
    flags: c_uint,
    prefix: *mut c_char,
    prefixlen: usize,
    ctx: *mut SslCtx,
    ssl: *mut Ssl,
    poptions: *mut u64,
    cert_filename: *mut *mut c_char,
    num_cert_filename: usize,
    pcert_flags: *mut c_long,
    pvfy_flags: *mut c_int,
    min_version: *mut c_int,
    max_version: *mut c_int,
    tbl: *const SslFlagTbl,
    ntbl: usize,
    canames: *mut OpenSslStack,
    /// Non-authority field: nonzero while a public dispatch is running on this context.
    /// All-zero (free) is the state `SSL_CONF_CTX_new`/`zeroed` produce. It is atomic so
    /// the check-and-set itself introduces no data race; it does **not** make the rest of
    /// the context thread-safe (cross-thread mutation remains outside the contract).
    in_use: AtomicBool,
}

// ---------------------------------------------------------------------------------------------
// Same-context overlap refusal (candidate-only; see B46-D2)
// ---------------------------------------------------------------------------------------------

/// RAII release of [`SslConfCtx::in_use`].
///
/// The guard stores the flag's address rather than a reference so that no shared borrow of
/// the context is live while the dispatch takes `&mut *cctx` for its handlers (the aliasing
/// shape B46-H1 removed). Its `Drop` clears the flag on every exit path, including the early
/// returns and the unwind that `guard_ffi` catches.
struct InUseGuard {
    /// Address of the `in_use` field of a context that outlives this guard.
    busy: *const AtomicBool,
}

impl Drop for InUseGuard {
    fn drop(&mut self) {
        // SAFETY: the context whose flag this guard marked is live for at least as long as
        // the guard: the guard is created and dropped inside one public dispatch call that
        // holds exclusive access to the context, and nothing in that call releases it.
        unsafe { (*self.busy).store(false, Ordering::Release) };
    }
}

/// Marks `cctx` in use for the lifetime of the returned guard, or returns `None` when a
/// public dispatch is already running on the same context.
///
/// This is not an authority operation: the authority performs no such check (B46-D2). It is
/// the candidate's deterministic replacement for allowing two overlapping dispatches to
/// alias the context.
///
/// # Safety
/// `cctx` must be non-NULL, aligned and point to a live, initialised `SslConfCtx` that
/// outlives the returned guard. The caller must hold the exclusive-access precondition of
/// the public dispatch for the whole guard lifetime.
unsafe fn enter_use(cctx: *mut SslConfCtx) -> Option<InUseGuard> {
    // SAFETY: `cctx` is live and aligned per the caller's contract; `addr_of!` creates no
    // reference, so it does not conflict with the `&mut *cctx` the handlers later take.
    let busy = unsafe { core::ptr::addr_of!((*cctx).in_use) };
    // SAFETY: `busy` is a live, aligned `AtomicBool` per the caller's contract.
    if unsafe { (*busy).swap(true, Ordering::Acquire) } {
        None
    } else {
        Some(InUseGuard { busy })
    }
}

// ---------------------------------------------------------------------------------------------
// Ownership of the context block
// ---------------------------------------------------------------------------------------------

fn flag_both(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_srv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: 0x8,
        option_value: value,
    }
}

fn flag_inv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_INV | SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_cert(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_CERT | SSL_TFLAG_BOTH,
        option_value: value,
    }
}

fn flag_vfy_cli(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_VFY | 0x4,
        option_value: value,
    }
}

fn flag_vfy_srv(name: &'static [u8], value: u64) -> SslFlagTbl {
    SslFlagTbl {
        name,
        name_flags: SSL_TFLAG_VFY | 0x8,
        option_value: value,
    }
}

/// `ssl_set_option` — `ssl_conf.c:111-144`.
///
/// # Safety
/// `cctx` must be non-NULL, aligned, and point to a live, fully initialised
/// `SslConfCtx` that this call has exclusive access to for its duration (no other
/// shared/exclusive reference and no racing raw access). Each flag pointer the selected
/// `name_flags` class uses must be NULL or point to a live, aligned field of the
/// matching type — `poptions: *mut u64`, `pvfy_flags: *mut c_int`,
/// `pcert_flags: *mut c_long` — inside an SSL/SSL_CTX that outlives the call and is not
/// concurrently written. `option_value` must fit the selected field's width; the crate's
/// own flag tables guarantee that. A NULL pointer in any of those slots is the
/// authority's documented no-op, not an error.
unsafe fn ssl_set_option(
    cctx: *mut SslConfCtx,
    name_flags: c_uint,
    option_value: u64,
    onoff: c_int,
) {
    // SAFETY: `cctx` is live per the callers' contracts.
    let c = unsafe { &mut *cctx };
    if c.poptions.is_null() {
        return;
    }
    let mut on = onoff;
    if (name_flags & SSL_TFLAG_INV) != 0 {
        on ^= 1;
    }
    match name_flags & SSL_TFLAG_TYPE_MASK {
        SSL_TFLAG_CERT => {
            let pflags = c.pcert_flags;
            if pflags.is_null() {
                return;
            }
            // SAFETY: `pcert_flags` points at the live `c_long cert_flags` field of the
            // selected SSL/SSL_CTX, and `option_value` is one of the table's 32-bit flags.
            // Each field is written through its own type; a widened view is not.
            unsafe {
                if on != 0 {
                    *pflags |= option_value as c_long;
                } else {
                    *pflags &= !(option_value as c_long);
                }
            }
        }
        SSL_TFLAG_VFY => {
            let pflags = c.pvfy_flags;
            if pflags.is_null() {
                return;
            }
            // SAFETY: `pvfy_flags` points at the live `c_int verify_mode` field. The
            // authority writes one `uint32_t` here; writing a `u64` through a widened
            // view would run four bytes past the field.
            unsafe {
                if on != 0 {
                    *pflags |= option_value as c_int;
                } else {
                    *pflags &= !(option_value as c_int);
                }
            }
        }
        _ => {
            // SAFETY: `poptions` is non-NULL (checked above) and points at a live u64.
            unsafe {
                if on != 0 {
                    *c.poptions |= option_value;
                } else {
                    *c.poptions &= !option_value;
                }
            }
        }
    }
}

/// `ssl_match_option` — `ssl_conf.c:146-160`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, live, initialised and exclusively accessible for the
/// whole call: on a match this function calls [`ssl_set_option`], which takes `&mut *cctx`
/// and writes a field of the selected `SSL`/`SSL_CTX`, so no other shared/exclusive
/// reference to either object and no racing raw access may exist. `tbl` is a safe
/// reference, so Rust already guarantees its validity; the caller must keep the name it
/// borrows valid for the call. `elem` must be readable for `len` bytes when `len >= 0`,
/// or NUL-terminated when `len == -1`; no other value is accepted. `onoff` is an integer
/// toggle with no pointer obligation.
///
/// Authority-derived: `elem`/`len` are `CONF_parse_list`'s element-callback arguments
/// (`ssl_conf.c:146-160` consumes them the same way); the candidate's only caller is
/// [`ssl_set_option_list`], which receives them from `CONF_parse_list` at `:558`. The
/// exclusivity requirement comes from [`ssl_set_option`], not from the authority's
/// documentation.
unsafe fn ssl_match_option(
    cctx: *mut SslConfCtx,
    tbl: &SslFlagTbl,
    elem: *const c_char,
    len: c_int,
    onoff: c_int,
) -> bool {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    if (c.flags & tbl.name_flags & SSL_TFLAG_BOTH) == 0 {
        return false;
    }
    let name = tbl.name;
    if len == -1 {
        // SAFETY: `elem` is NUL-terminated.
        if unsafe { core::ffi::CStr::from_ptr(elem) }.to_bytes() != name {
            return false;
        }
    } else {
        if name.len() != len as usize {
            return false;
        }
        // SAFETY: `elem` is readable for `len` bytes.
        let got = unsafe { core::slice::from_raw_parts(elem as *const u8, len as usize) };
        if !got.eq_ignore_ascii_case(name) {
            return false;
        }
    }
    // SAFETY: `cctx` is live.
    unsafe { ssl_set_option(cctx, tbl.name_flags, tbl.option_value, onoff) };
    true
}

/// `ssl_set_option_list` — `ssl_conf.c:162-190`.
///
/// # Safety
///
/// `usr` must be non-NULL and point to a live, initialised `SslConfCtx` that this callback
/// has exclusive access to for its whole duration: the body reads `tbl`/`ntbl` from the
/// context and, on a match, reaches [`ssl_match_option`] -> [`ssl_set_option`], which takes
/// `&mut *cctx` and writes a field of the selected `SSL`/`SSL_CTX`. No other reference and
/// no racing raw access may exist. `cctx.tbl` must be NULL or point to a live array of
/// `ntbl` `SslFlagTbl` values that outlives the call (NULL with `ntbl == 0` is the empty
/// list). `elem` must be NULL or readable for `len` bytes when `len >= 0`, or
/// NUL-terminated when `len == -1`. The callback stores no pointer to `elem` or `usr`.
///
/// Authority-derived: this is the `CONF_parse_list` element callback installed by
/// [`parse_option_list`] with `usr = cctx` (`:559`); `CONF_parse_list` invokes it
/// synchronously with the element pointer/length and never retains it. The context table
/// is set to a frame-local table by `parse_option_list` and cleared before it returns. The
/// exclusivity requirement is this crate's [`ssl_set_option`] contract, not an
/// authority-documented one.
unsafe extern "C" fn ssl_set_option_list(
    elem: *const c_char,
    len: c_int,
    usr: *mut c_void,
) -> c_int {
    let cctx = usr as *mut SslConfCtx;
    let mut e = elem;
    let mut l = len;
    let mut onoff = 1;
    if e.is_null() {
        return 0;
    }
    if l != -1 {
        // SAFETY: `e` is readable for `l` bytes.
        let first = unsafe { *e } as u8;
        if first == b'+' {
            // SAFETY: the token continues inside the buffer.
            e = unsafe { e.add(1) };
            l -= 1;
        } else if first == b'-' {
            // SAFETY: the token continues inside the buffer.
            e = unsafe { e.add(1) };
            l -= 1;
            onoff = 0;
        }
    }
    // Copy the table view out of the context instead of holding `&*cctx` across the
    // loop. `ssl_match_option` reaches `ssl_set_option`, which takes `&mut *cctx`;
    // `ssl_set_option`'s contract forbids any other reference to the context for the
    // duration of that call, so the shared borrow must end before it. `tbl` denotes
    // the frame-local option table (a separate allocation from the context), not the
    // context itself.
    // SAFETY: `cctx` is live per `SSL_CONF_cmd`.
    let (tbl, ntbl) = unsafe { ((*cctx).tbl, (*cctx).ntbl) };
    for i in 0..ntbl {
        // SAFETY: `i` is in range of the table `tbl` points into, per the context's
        // invariant established by `parse_option_list`.
        let elem_tbl = unsafe { &*tbl.add(i) };
        // SAFETY: the pointers are per the callback contract; no borrow of `*cctx`
        // is live here, so `ssl_match_option`'s exclusive access is exclusive.
        if unsafe { ssl_match_option(cctx, elem_tbl, e, l, onoff) } {
            return 1;
        }
    }
    0
}

/// `protocol_from_string` — `ssl_conf.c:303-333`.
fn protocol_from_string(value: &[u8]) -> c_int {
    let table: [(&[u8], c_int); 8] = [
        (b"None", 0),
        (b"SSLv3", t::SSL3_VERSION as c_int),
        (b"TLSv1", t::TLS1_VERSION as c_int),
        (b"TLSv1.1", t::TLS1_1_VERSION as c_int),
        (b"TLSv1.2", t::TLS1_2_VERSION as c_int),
        (b"TLSv1.3", t::TLS1_3_VERSION as c_int),
        (b"DTLSv1", t::DTLS1_VERSION as c_int),
        (b"DTLSv1.2", t::DTLS1_2_VERSION as c_int),
    ];
    for (name, version) in table {
        if value == name {
            return version;
        }
    }
    -1
}

/// `dtls_ver_ordinal` — `ssl_local.h:58`.
fn dtls_ordinal(v: c_int) -> c_int {
    if v == t::DTLS1_BAD_VER as c_int {
        0xff00
    } else {
        v
    }
}

/// `ssl_set_version_bound` — `ssl/statem/statem_lib.c:2107-2156` (pulled forward from 14.5).
///
/// `pub(crate)` because the version-bound control arms (`SSL_CTRL_SET_MIN/MAX_PROTO_VERSION`,
/// `ssl/ssl_lib.c:3199-3209`) call it from `src/ssl/ssl_lib.rs`, exactly as the authority's
/// `SSL_CTX_ctrl`/`SSL_ctrl` call it from `ssl_lib.c`.
pub(crate) fn ssl_set_version_bound(
    method_version: c_int,
    version: c_int,
    bound: *mut c_int,
) -> bool {
    if version == 0 {
        // SAFETY: `bound` is a live context/connection field per the callers' contract.
        unsafe { *bound = version };
        return true;
    }
    let valid_tls = version >= t::SSL3_VERSION as c_int && version <= t::TLS1_3_VERSION as c_int;
    let valid_dtls = version == t::DTLS1_BAD_VER as c_int
        || (dtls_ordinal(version) >= dtls_ordinal(t::DTLS1_2_VERSION as c_int)
            && dtls_ordinal(version) <= dtls_ordinal(t::DTLS1_VERSION as c_int));
    if !valid_tls && !valid_dtls {
        return false;
    }
    match method_version {
        v if v == crate::ssl::ssl_lib::TLS_ANY_VERSION && valid_tls => {
            // SAFETY: `bound` is a live field.
            unsafe { *bound = version };
        }
        v if v == crate::ssl::ssl_lib::DTLS_ANY_VERSION && valid_dtls => {
            // SAFETY: `bound` is a live field.
            unsafe { *bound = version };
        }
        _ => {}
    }
    true
}

/// `min_max_proto` — `ssl_conf.c:335-349`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, live, initialised and exclusively accessible for the
/// call. When `cctx.ctx` is non-NULL it must be a live in-crate `SSL_CTX` whose `method` is
/// a live method table; when `cctx.ssl` is non-NULL it must be a live in-crate `SSL` whose
/// `defltmeth` is a live method table. `value` must be non-NULL and NUL-terminated (the
/// body reads it with `CStr::from_ptr`). `bound` must be NULL or a live, aligned, writable
/// `c_int` that outlives the call; `SSL_CONF_CTX_set_ssl`/`SSL_CONF_CTX_set_ssl_ctx`
/// establish it as the `min_proto_version`/`max_proto_version` field of that object
/// whenever `ctx`/`ssl` is non-NULL, and when both are NULL the body returns 0 before
/// reading `value` or `bound`.
///
/// Authority-derived: the protocol-name table and the version-range/method-match rules
/// are the authority's (`ssl/ssl_conf.c:303-349`, `ssl/statem/statem_lib.c:2107-2156`);
/// they are behaviour, not pointer-safety preconditions. The live-`method` obligation
/// rests on `SSL_CTX_new`/`SSL_new`, which install a non-NULL method table.
unsafe fn min_max_proto(cctx: *mut SslConfCtx, value: *const c_char, bound: *mut c_int) -> c_int {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    let method_version = if !c.ctx.is_null() {
        // SAFETY: `ctx` is live.
        unsafe { (*(*c.ctx).method).version }
    } else if !c.ssl.is_null() {
        // SAFETY: `ssl` is live.
        unsafe { (*(*c.ssl).defltmeth).version }
    } else {
        return 0;
    };
    // SAFETY: `value` is NUL-terminated.
    let v = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let new_version = protocol_from_string(v);
    if new_version < 0 {
        return 0;
    }
    c_int::from(ssl_set_version_bound(method_version, new_version, bound))
}

/// Runs one option-list handler with `cctx->tbl` pointing at `table` for the duration of the
/// parse. The authority's tables are `static`, so its pointer stays valid after the call; these
/// tables are frame-local, so the pointer is cleared before returning. Nothing reads it between
/// commands.
///
/// # Safety
/// `cctx` is live; `value` is NUL-terminated.
unsafe fn parse_option_list(
    cctx: *mut SslConfCtx,
    value: *const c_char,
    table: &[SslFlagTbl],
) -> c_int {
    // SAFETY: `cctx` is live per the caller's contract.
    unsafe {
        (*cctx).tbl = table.as_ptr();
        (*cctx).ntbl = table.len();
    }
    // SAFETY: `value` is NUL-terminated; the callback and arg are per `CONF_parse_list`.
    let rv = unsafe {
        CONF_parse_list(
            value,
            b',' as c_int,
            1,
            Some(ssl_set_option_list),
            cctx.cast::<c_void>(),
        )
    };
    // `table` lives in this frame only; leaving its address in the context would be a dangling
    // pointer once this call returns.
    // SAFETY: `cctx` is live per the caller's contract.
    unsafe {
        (*cctx).tbl = ptr::null();
        (*cctx).ntbl = 0;
    }
    rv
}

/// `cmd_Protocol` — `ssl_conf.c:280-296`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// that this call exclusively accesses for its duration: the handler writes the
/// context's `tbl`/`ntbl` and the option word of the `ctx`/`ssl` it references, so
/// neither object may be concurrently read or written. `value` must be non-NULL and
/// point to a NUL-terminated byte string readable for the whole call; the handler
/// stores no copy of the pointer. ABI: the `ConfCmdFn`
/// (`int (*)(SSL_CONF_CTX *, const char *)`) signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`src/ssl/ssl_conf.rs:1473`): it
/// refuses a NULL `cctx` at `:1522` and a NULL `value` for a typed row at `:1490`
/// before the indirect call. `cctx` provenance is `SSL_CONF_CTX_new` (`:1672`), and
/// `SSL_CONF_CTX_set_ssl`/`_set_ssl_ctx` (`:1795`/`:1839`) establish `ctx`/`ssl` as
/// NULL or live in-crate objects. The dispatch holds no shared `&SslConfCtx` across
/// `:1473` (the `&*cctx` at `:1457` ends with the lookup). `SSL_CONF_cmd`'s
/// public `# Safety` (`:1489`) now requires exclusive access to the context and
/// to the `SSL`/`SSL_CTX` it wraps and forbids concurrent mutation; the authority
/// documents neither, so this is a recorded divergence (`AGENTS.md` §17, B46-D1)
/// that narrows the accepted contract. Returns 1 only when every element matched:
/// `CONF_parse_list` stops at the first element whose callback returns `<= 0` and
/// returns that value, so a mixed list may apply its leading matches and still
/// return 0. `SSL_CONF_cmd` maps `>0` to 2 and every other value to 0.
/// `parse_option_list` clears
/// `cctx.tbl`/`ntbl` on the normal and `guard_ffi`-caught paths, so an error leaves
/// no frame-local pointer behind.
unsafe extern "C" fn cmd_Protocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_inv(b"ALL", t::SSL_OP_NO_SSL_MASK),
        flag_inv(b"SSLv2", t::SSL_OP_NO_SSLv2),
        flag_inv(b"SSLv3", t::SSL_OP_NO_SSLv3),
        flag_inv(b"TLSv1", t::SSL_OP_NO_TLSv1),
        flag_inv(b"TLSv1.1", t::SSL_OP_NO_TLSv1_1),
        flag_inv(b"TLSv1.2", t::SSL_OP_NO_TLSv1_2),
        flag_inv(b"TLSv1.3", t::SSL_OP_NO_TLSv1_3),
        flag_inv(b"DTLSv1", t::SSL_OP_NO_DTLSv1),
        flag_inv(b"DTLSv1.2", t::SSL_OP_NO_DTLSv1_2),
    ];
    // SAFETY: `cctx` is live and `value` is NUL-terminated per the caller's contract.
    unsafe { parse_option_list(cctx, value, &table) }
}

/// `cmd_Options` — `ssl_conf.c:375-416`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; the handler writes `cctx.tbl`/`ntbl` and
/// the option word of the referenced `ctx`/`ssl`, so neither object may be
/// concurrently read or written. `value` must be non-NULL and point to a
/// NUL-terminated byte string readable for the whole call; the handler stores no
/// copy of the pointer. ABI: the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490` before the call; `cctx`
/// provenance is `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx`
/// (`:1795`/`:1839`) supplying NULL-or-live members. `SSL_CONF_cmd`'s public
/// `# Safety` (`:1489`) now requires exclusive access to the context and the
/// wrapped `SSL`/`SSL_CTX` and forbids concurrent mutation; the authority
/// documents neither, so this is a recorded divergence (`AGENTS.md` §17, B46-D1)
/// that narrows the accepted contract. This handler additionally
/// tolerates a NULL `value` by returning `-3` (authority `ssl_conf.c:411-412`); that
/// arm is unreachable through `SSL_CONF_cmd`, which refuses NULL first, and the
/// dispatch maps `-3` to 0. Returns 1 only when every element matched on the parse
/// path; `CONF_parse_list` stops at the first failing element, so a mixed list may
/// apply its leading matches and still return 0. `parse_option_list` clears
/// `cctx.tbl`/`ntbl` before returning on every path, so a
/// rejected list leaves no frame-local pointer behind.
unsafe extern "C" fn cmd_Options(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_inv(b"SessionTicket", t::SSL_OP_NO_TICKET),
        flag_inv(b"EmptyFragments", t::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS),
        flag_both(b"Bugs", t::SSL_OP_ALL),
        flag_inv(b"Compression", t::SSL_OP_NO_COMPRESSION),
        flag_srv(b"ServerPreference", t::SSL_OP_SERVER_PREFERENCE),
        flag_srv(
            b"NoResumptionOnRenegotiation",
            t::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
        ),
        flag_srv(b"DHSingle", t::SSL_OP_SINGLE_DH_USE),
        flag_srv(b"ECDHSingle", t::SSL_OP_SINGLE_ECDH_USE),
        flag_both(
            b"UnsafeLegacyRenegotiation",
            t::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        ),
        flag_both(
            b"UnsafeLegacyServerConnect",
            t::SSL_OP_LEGACY_SERVER_CONNECT,
        ),
        flag_both(b"ClientRenegotiation", t::SSL_OP_ALLOW_CLIENT_RENEGOTIATION),
        flag_inv(b"EncryptThenMac", t::SSL_OP_NO_ENCRYPT_THEN_MAC),
        flag_both(b"NoRenegotiation", t::SSL_OP_NO_RENEGOTIATION),
        flag_both(b"AllowNoDHEKEX", t::SSL_OP_ALLOW_NO_DHE_KEX),
        flag_both(b"PreferNoDHEKEX", t::SSL_OP_PREFER_NO_DHE_KEX),
        flag_both(b"PrioritizeChaCha", t::SSL_OP_PRIORITIZE_CHACHA),
        flag_both(b"MiddleboxCompat", t::SSL_OP_ENABLE_MIDDLEBOX_COMPAT),
        flag_inv(b"AntiReplay", t::SSL_OP_NO_ANTI_REPLAY),
        flag_inv(b"ExtendedMasterSecret", t::SSL_OP_NO_EXTENDED_MASTER_SECRET),
        flag_inv(b"CANames", t::SSL_OP_DISABLE_TLSEXT_CA_NAMES),
        flag_both(b"KTLS", t::SSL_OP_ENABLE_KTLS),
        flag_cert(b"StrictCertCheck", t::SSL_CERT_FLAG_TLS_STRICT),
        flag_inv(
            b"TxCertificateCompression",
            t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
        ),
        flag_inv(
            b"RxCertificateCompression",
            t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
        ),
        flag_both(
            b"KTLSTxZerocopySendfile",
            t::SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE,
        ),
        flag_both(b"IgnoreUnexpectedEOF", t::SSL_OP_IGNORE_UNEXPECTED_EOF),
        flag_both(b"LegacyECPointFormats", t::SSL_OP_LEGACY_EC_POINT_FORMATS),
    ];
    if value.is_null() {
        return -3;
    }
    // SAFETY: `cctx` is live and `value` is NUL-terminated per the caller's contract.
    unsafe { parse_option_list(cctx, value, &table) }
}

/// `cmd_VerifyMode` — `ssl_conf.c:418-436`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; the handler writes `cctx.tbl`/`ntbl` and
/// the verify-mode word of the referenced `ctx`/`ssl`, so neither object may be
/// concurrently read or written. `value` must be non-NULL and point to a
/// NUL-terminated byte string readable for the whole call; the handler stores no
/// copy of the pointer. ABI: the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490`; `cctx` provenance is
/// `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx` (`:1795`/`:1839`)
/// supplying NULL-or-live members. `SSL_CONF_cmd`'s public `# Safety` (`:1489`)
/// now requires exclusive access to the context and the wrapped `SSL`/`SSL_CTX`
/// and forbids concurrent mutation; the authority documents neither, so this is a
/// recorded divergence (`AGENTS.md` §17, B46-D1) that narrows the accepted
/// contract. This handler additionally tolerates a
/// NULL `value` by returning `-3` (authority `ssl_conf.c:432-433`); that arm is
/// unreachable through `SSL_CONF_cmd`, which refuses NULL first, and the dispatch
/// maps `-3` to 0. Returns 1 only when every element matched on the parse path;
/// `CONF_parse_list` stops at the first failing element, so a mixed list may apply
/// its leading matches and still return 0. `parse_option_list` clears
/// `cctx.tbl`/`ntbl` before returning on every path.
unsafe extern "C" fn cmd_VerifyMode(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let table = [
        flag_vfy_cli(b"Peer", t::SSL_VERIFY_PEER),
        flag_vfy_srv(b"Request", t::SSL_VERIFY_PEER),
        flag_vfy_srv(
            b"Require",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
        flag_vfy_srv(b"Once", t::SSL_VERIFY_PEER | t::SSL_VERIFY_CLIENT_ONCE),
        flag_vfy_srv(
            b"RequestPostHandshake",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_POST_HANDSHAKE,
        ),
        flag_vfy_srv(
            b"RequirePostHandshake",
            t::SSL_VERIFY_PEER | t::SSL_VERIFY_POST_HANDSHAKE | t::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        ),
    ];
    if value.is_null() {
        return -3;
    }
    // SAFETY: `cctx` is live and `value` is NUL-terminated per the caller's contract.
    unsafe { parse_option_list(cctx, value, &table) }
}

/// `cmd_CipherString` — `ssl_conf.c:258-267`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; `ctx`/`ssl` must each be NULL or a live
/// context/connection of this crate that the cipher-list setters may mutate and
/// that is not concurrently accessed. `value` must point to a NUL-terminated byte
/// string readable for the call (the setters tolerate NULL as a failure, but the
/// dispatch refuses it first); the setters parse it into fresh stacks and retain no
/// reference. ABI: the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490`; `cctx` provenance is
/// `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx` (`:1795`/`:1839`)
/// supplying NULL-or-live members. `SSL_CONF_cmd`'s public `# Safety` (`:1489`)
/// now requires exclusive access to the context and the wrapped `SSL`/`SSL_CTX`
/// and forbids concurrent mutation; the authority documents neither, so this is a
/// recorded divergence (`AGENTS.md` §17, B46-D1) that narrows the accepted
/// contract. Returns 1 when the last applied setter
/// succeeded and 0 otherwise. A `NULL` result from `ssl_create_cipher_list` leaves
/// the previous lists untouched, but the authority's zero-TLS1.2-cipher arm returns
/// 0 after `ssl_create_cipher_list` has already published new
/// `cipher_list`/`cipher_list_by_id` stacks (`ssl_lib.c:3367-3379`), so a 0 return
/// can leave the new list installed. That published state is fully initialised and
/// owned by the object: the error path leaves no partial or dangling list.
unsafe extern "C" fn cmd_CipherString(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let mut rv = 1;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_cipher_list((*cctx).ctx, value);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_cipher_list((*cctx).ssl, value);
        }
    }
    c_int::from(rv > 0)
}

/// `cmd_Ciphersuites` — `ssl_conf.c:269-278`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; `ctx`/`ssl` must each be NULL or a live
/// context/connection of this crate that the ciphersuite setters may mutate and
/// that is not concurrently accessed. `value` must point to a NUL-terminated byte
/// string readable for the call (the setters tolerate NULL as a failure, but the
/// dispatch refuses it first); the setters parse it and retain no reference. ABI:
/// the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490`; `cctx` provenance is
/// `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx` (`:1795`/`:1839`)
/// supplying NULL-or-live members. `SSL_CONF_cmd`'s public `# Safety` (`:1489`)
/// now requires exclusive access to the context and the wrapped `SSL`/`SSL_CTX`
/// and forbids concurrent mutation; the authority documents neither, so this is a
/// recorded divergence (`AGENTS.md` §17, B46-D1) that narrows the accepted
/// contract. Returns 1 when the last applied setter
/// succeeded and 0 otherwise. `set_ciphersuites` does not replace the TLS 1.3 list
/// on a parse failure, but the authority's `update_cipher_list` arm
/// (`ssl_ciph.c:1381-1385`) can return 0 after the TLS 1.3 list and the paired
/// lists have already been published, so a 0 return can leave fully initialised,
/// object-owned lists installed; no partial or dangling state is retained.
unsafe extern "C" fn cmd_Ciphersuites(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    let mut rv = 1;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_ciphersuites((*cctx).ctx, value);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_ciphersuites((*cctx).ssl, value);
        }
    }
    c_int::from(rv > 0)
}

/// `cmd_MinProtocol` — `ssl_conf.c:358-361`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; the callee reads `ctx`/`ssl` and their
/// method version and writes `(*cctx).min_version`'s target on success, so neither
/// object may be concurrently accessed. `value` must be non-NULL and point to a
/// NUL-terminated byte string readable for the call: `min_max_proto` reads it with
/// `CStr::from_ptr`, so a NULL value while `ctx` or `ssl` is live is undefined
/// behaviour. ABI: the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490` before the call; `cctx`
/// provenance is `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx`
/// (`:1795`/`:1839`) supplying NULL-or-live members and a live `min_version`
/// whenever `ctx` or `ssl` is non-NULL (when both are NULL, `min_max_proto` returns
/// 0 before reading `value` or the bound). `SSL_CONF_cmd`'s public `# Safety`
/// (`:1489`) now requires exclusive access to the context and the wrapped
/// `SSL`/`SSL_CTX` and forbids concurrent mutation; the authority documents
/// neither, so this is a recorded divergence (`AGENTS.md` §17, B46-D1) that
/// narrows the accepted contract. Returns 1 when
/// `ssl_set_version_bound` accepts the name, otherwise 0; acceptance does not imply
/// a write: the bound is written only for `version == 0` and for the matching
/// `TLS_ANY_VERSION`/`DTLS_ANY_VERSION` arm, while the `_` arm returns true without
/// writing, so a rejected name and an unmatched method version both leave it
/// untouched.
unsafe extern "C" fn cmd_MinProtocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `cctx` is live.
    unsafe { min_max_proto(cctx, value, (*cctx).min_version) }
}

/// `cmd_MaxProtocol` — `ssl_conf.c:370-373`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// with exclusive access for its duration; the callee reads `ctx`/`ssl` and their
/// method version and writes `(*cctx).max_version`'s target on success, so neither
/// object may be concurrently accessed. `value` must be non-NULL and point to a
/// NUL-terminated byte string readable for the call: `min_max_proto` reads it with
/// `CStr::from_ptr`, so a NULL value while `ctx` or `ssl` is live is undefined
/// behaviour. ABI: the `ConfCmdFn` signature the command table stores.
///
/// Established by the sole caller, `SSL_CONF_cmd` (`:1473`): NULL `cctx` is refused
/// at `:1522` and a NULL `value` for a typed row at `:1490` before the call; `cctx`
/// provenance is `SSL_CONF_CTX_new` (`:1672`) with `set_ssl`/`set_ssl_ctx`
/// (`:1795`/`:1839`) supplying NULL-or-live members and a live `max_version`
/// whenever `ctx` or `ssl` is non-NULL (when both are NULL, `min_max_proto` returns
/// 0 before reading `value` or the bound). `SSL_CONF_cmd`'s public `# Safety`
/// (`:1489`) now requires exclusive access to the context and the wrapped
/// `SSL`/`SSL_CTX` and forbids concurrent mutation; the authority documents
/// neither, so this is a recorded divergence (`AGENTS.md` §17, B46-D1) that
/// narrows the accepted contract. Returns 1 when
/// `ssl_set_version_bound` accepts the name, otherwise 0; acceptance does not imply
/// a write: the bound is written only for `version == 0` and for the matching
/// `TLS_ANY_VERSION`/`DTLS_ANY_VERSION` arm, while the `_` arm returns true without
/// writing, so a rejected name and an unmatched method version both leave it
/// untouched.
unsafe extern "C" fn cmd_MaxProtocol(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `cctx` is live.
    unsafe { min_max_proto(cctx, value, (*cctx).max_version) }
}

/// `atoi` — `ssl_conf.c:726`; the leading integer `cmd_NumTickets` reads.
fn atoi_prefix(text: &str) -> c_int {
    let t = text.trim_start();
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let mut v: c_int = digits.parse().unwrap_or(0);
    if neg {
        v = -v;
    }
    v
}

/// `cmd_NumTickets` — `ssl_conf.c:723-735`.
///
/// # Safety
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx` whose
/// `ctx`/`ssl` fields are each NULL or a live context/connection of this crate; the call
/// only reads `cctx`, but it hands those handles to the `SSL_CTX_set_num_tickets` /
/// `SSL_set_num_tickets` setters, so neither object may be concurrently written.
/// `value` must be non-NULL and point to a NUL-terminated byte string readable for the
/// whole call (`SSL_CONF_cmd` refuses a NULL value for a typed command before invoking the
/// handler). ABI: the `ConfCmdFn` (`int (*)(SSL_CONF_CTX *, const char *)`) signature the
/// command table stores.
unsafe extern "C" fn cmd_NumTickets(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `value` is NUL-terminated.
    let v = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let num_tickets = atoi_prefix(&String::from_utf8_lossy(v));
    let mut rv = 0;
    if num_tickets >= 0 {
        // SAFETY: `cctx` is live; the pointers are NULL or live.
        unsafe {
            if !(*cctx).ctx.is_null() {
                rv = SSL_CTX_set_num_tickets((*cctx).ctx, num_tickets as usize);
            }
            if !(*cctx).ssl.is_null() {
                rv = SSL_set_num_tickets((*cctx).ssl, num_tickets as usize);
            }
        }
    }
    rv
}

/// `cmd_RecordPadding` — `ssl_conf.c:667-721`.
///
/// # Safety
///
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx` whose
/// `ctx`/`ssl` fields are each NULL or a live context/connection of this crate; the call
/// hands those handles to `SSL_CTX_set_block_padding_ex`/`SSL_set_block_padding_ex`, so
/// neither object may be concurrently written. `value` must be non-NULL and point to a
/// NUL-terminated byte string readable for the whole call (`SSL_CONF_cmd` refuses a NULL
/// value for a typed command). ABI: the `ConfCmdFn` signature the command table stores.
unsafe extern "C" fn cmd_RecordPadding(cctx: *mut SslConfCtx, value: *const c_char) -> c_int {
    // SAFETY: `value` is NUL-terminated.
    let bytes = unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes();
    let text = core::str::from_utf8(bytes).unwrap_or("");
    let (a, b) = match text.split_once(',') {
        Some((x, y)) => (x, Some(y)),
        None => (text, None),
    };
    let block: usize = match a.parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let hs: usize = match b {
        None => block,
        Some("") => return 0,
        Some(y) => match y.parse() {
            Ok(v) => v,
            Err(_) => return 0,
        },
    };
    let mut rv = 0;
    // SAFETY: `cctx` is live; the pointers are NULL or live.
    unsafe {
        if !(*cctx).ctx.is_null() {
            rv = SSL_CTX_set_block_padding_ex((*cctx).ctx, block, hs);
        }
        if !(*cctx).ssl.is_null() {
            rv = SSL_set_block_padding_ex((*cctx).ssl, block, hs);
        }
    }
    rv
}

/// A command whose named unit is a later subphase: recognised by the table, refused by the
/// handler (recorded in the module header). It reads no argument and contains no unsafe
/// operation, so it is a safe `extern "C" fn`.
extern "C" fn cmd_unwired(_cctx: *mut SslConfCtx, _value: *const c_char) -> c_int {
    0
}

/// `SSL_CONF_CMD`/`SSL_CONF_CMD_STRING`/`SSL_CONF_CMD_SWITCH` rows — `ssl_conf.c:758-841`.
///
/// The order is the authority's, because `ctrl_switch_option` indexes the switch table by this
/// row's position (`ssl_conf.c:953-968`).
fn commands() -> Vec<SslConfCmdTbl> {
    let cmdstr =
        |f: ConfCmdFn, file: &'static [u8], cmdline: Option<&'static [u8]>, flags: c_uint| {
            SslConfCmdTbl {
                cmd: Some(f),
                str_file: Some(file),
                str_cmdline: cmdline,
                flags,
                value_type: t::SSL_CONF_TYPE_STRING as c_uint,
            }
        };
    let cmdtype = |f: ConfCmdFn,
                   file: &'static [u8],
                   cmdline: Option<&'static [u8]>,
                   flags: c_uint,
                   vt: u64| {
        SslConfCmdTbl {
            cmd: Some(f),
            str_file: Some(file),
            str_cmdline: cmdline,
            flags,
            value_type: vt as c_uint,
        }
    };
    let switch = |name: &'static [u8], flags: c_uint| SslConfCmdTbl {
        cmd: None,
        str_file: None,
        str_cmdline: Some(name),
        flags,
        value_type: t::SSL_CONF_TYPE_NONE as c_uint,
    };

    vec![
        switch(b"no_ssl3", 0),
        switch(b"no_tls1", 0),
        switch(b"no_tls1_1", 0),
        switch(b"no_tls1_2", 0),
        switch(b"no_tls1_3", 0),
        switch(b"bugs", 0),
        switch(b"no_comp", 0),
        switch(b"comp", 0),
        switch(b"no_tx_cert_comp", 0),
        switch(b"tx_cert_comp", 0),
        switch(b"no_rx_cert_comp", 0),
        switch(b"rx_cert_comp", 0),
        switch(b"ecdh_single", 0x8),
        switch(b"no_ticket", 0),
        switch(b"serverpref", 0x8),
        switch(b"legacy_renegotiation", 0),
        switch(b"client_renegotiation", 0x8),
        switch(b"legacy_server_connect", 0x4),
        switch(b"no_renegotiation", 0),
        switch(b"no_resumption_on_reneg", 0x8),
        switch(b"no_legacy_server_connect", 0x4),
        switch(b"allow_no_dhe_kex", 0),
        switch(b"prefer_no_dhe_kex", 0),
        switch(b"prioritize_chacha", 0x8),
        switch(b"strict", 0),
        switch(b"no_middlebox", 0),
        switch(b"anti_replay", 0x8),
        switch(b"no_anti_replay", 0x8),
        switch(b"no_etm", 0),
        switch(b"no_ems", 0),
        switch(b"legacy_ec_point_formats", 0),
        cmdstr(cmd_unwired, b"SignatureAlgorithms", Some(b"sigalgs"), 0),
        cmdstr(
            cmd_unwired,
            b"ClientSignatureAlgorithms",
            Some(b"client_sigalgs"),
            0,
        ),
        cmdstr(cmd_unwired, b"Curves", Some(b"curves"), 0),
        cmdstr(cmd_unwired, b"Groups", Some(b"groups"), 0),
        cmdstr(cmd_unwired, b"ECDHParameters", Some(b"named_curve"), 0x8),
        cmdstr(cmd_CipherString, b"CipherString", Some(b"cipher"), 0),
        cmdstr(cmd_Ciphersuites, b"Ciphersuites", Some(b"ciphersuites"), 0),
        cmdstr(cmd_Protocol, b"Protocol", None, 0),
        cmdstr(cmd_MinProtocol, b"MinProtocol", Some(b"min_protocol"), 0),
        cmdstr(cmd_MaxProtocol, b"MaxProtocol", Some(b"max_protocol"), 0),
        cmdstr(cmd_Options, b"Options", None, 0),
        cmdstr(cmd_VerifyMode, b"VerifyMode", None, 0),
        cmdtype(
            cmd_unwired,
            b"Certificate",
            Some(b"cert"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"PrivateKey",
            Some(b"key"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ServerInfoFile",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAPath",
            Some(b"chainCApath"),
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAFile",
            Some(b"chainCAfile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ChainCAStore",
            Some(b"chainCAstore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAPath",
            Some(b"verifyCApath"),
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAFile",
            Some(b"verifyCAfile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"VerifyCAStore",
            Some(b"verifyCAstore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAFile",
            Some(b"requestCAFile"),
            0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAFile",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAPath",
            None,
            0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAPath",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_DIR,
        ),
        cmdtype(
            cmd_unwired,
            b"RequestCAStore",
            Some(b"requestCAStore"),
            0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"ClientCAStore",
            None,
            0x8 | 0x20,
            t::SSL_CONF_TYPE_STORE,
        ),
        cmdtype(
            cmd_unwired,
            b"DHParameters",
            Some(b"dhparam"),
            0x8 | 0x20,
            t::SSL_CONF_TYPE_FILE,
        ),
        cmdstr(
            cmd_RecordPadding,
            b"RecordPadding",
            Some(b"record_padding"),
            0,
        ),
        cmdstr(cmd_NumTickets, b"NumTickets", Some(b"num_tickets"), 0x8),
    ]
}

/// `ssl_cmd_switches` — `ssl_conf.c:844-891`, the same order as the switch rows above.
fn switches() -> [SslSwitchTbl; 31] {
    [
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_SSLv3,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_1,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_2,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TLSv1_3,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALL,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TX_CERTIFICATE_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RX_CERTIFICATE_COMPRESSION,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_SINGLE_ECDH_USE,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_TICKET,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_SERVER_PREFERENCE,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_CLIENT_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_SERVER_CONNECT,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_SERVER_CONNECT,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ALLOW_NO_DHE_KEX,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_PREFER_NO_DHE_KEX,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_PRIORITIZE_CHACHA,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_CERT_FLAG_TLS_STRICT,
            name_flags: SSL_TFLAG_CERT,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ANTI_REPLAY,
            name_flags: SSL_TFLAG_INV,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ANTI_REPLAY,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_ENCRYPT_THEN_MAC,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_NO_EXTENDED_MASTER_SECRET,
            name_flags: 0,
        },
        SslSwitchTbl {
            option_value: t::SSL_OP_LEGACY_EC_POINT_FORMATS,
            name_flags: 0,
        },
    ]
}

/// `ssl_conf_cmd_skip_prefix` — `ssl_conf.c:893-912`.
///
/// # Safety
/// `cctx` must be non-NULL, aligned, and point to a live, initialised `SslConfCtx`
/// (read-only for this call). `cctx.prefix` must be NULL or point to `cctx.prefixlen`
/// readable, initialised bytes, with `prefixlen <= isize::MAX`. `pcmd` must be NULL or
/// `pcmd` must be NULL or
/// point to a writable, aligned `*const c_char` slot whose current value is NULL or a
/// pointer into a NUL-terminated allocation that stays valid for the call; when the prefix
/// is stripped the slot is advanced by `prefixlen` (or by one for `-`) bytes *within that
/// same allocation*, and the body checks that the remaining string is longer than the
/// prefix before advancing.
unsafe fn skip_prefix(cctx: *mut SslConfCtx, pcmd: *mut *const c_char) -> bool {
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    if pcmd.is_null() {
        return false;
    }
    // SAFETY: `pcmd` is non-NULL and points at a live `const char *` per the caller's contract.
    let inner = unsafe { *pcmd };
    if inner.is_null() {
        return false;
    }
    let cmd = inner;
    // SAFETY: `cmd` is NUL-terminated.
    let s = unsafe { core::ffi::CStr::from_ptr(cmd) }.to_bytes();
    if !c.prefix.is_null() {
        if s.len() <= c.prefixlen {
            return false;
        }
        // SAFETY: `prefix` is NUL-terminated and `prefixlen` bytes long.
        let pre = unsafe { core::slice::from_raw_parts(c.prefix as *const u8, c.prefixlen) };
        let head = &s[..c.prefixlen];
        if (c.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 && head != pre {
            return false;
        }
        if (c.flags & t::SSL_CONF_FLAG_FILE as c_uint) != 0 && !head.eq_ignore_ascii_case(pre) {
            return false;
        }
        // SAFETY: the prefix is within the string.
        unsafe { *pcmd = cmd.add(c.prefixlen) };
    } else if (c.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 {
        if s.first() != Some(&b'-') || s.len() < 2 {
            return false;
        }
        // SAFETY: the string is non-empty.
        unsafe { *pcmd = cmd.add(1) };
    }
    true
}

/// `ssl_conf_cmd_allowed` — `ssl_conf.c:915-927`.
fn cmd_allowed(cctx: &SslConfCtx, row: &SslConfCmdTbl) -> bool {
    let tfl = row.flags;
    let cfl = cctx.flags;
    if (tfl & 0x8) != 0 && (cfl & 0x8) == 0 {
        return false;
    }
    if (tfl & 0x4) != 0 && (cfl & 0x4) == 0 {
        return false;
    }
    if (tfl & 0x20) != 0 && (cfl & 0x20) == 0 {
        return false;
    }
    true
}

/// `ssl_conf_cmd_lookup` — `ssl_conf.c:929-951`, returning the row index.
fn cmd_lookup(cctx: &SslConfCtx, cmd: &[u8], table: &[SslConfCmdTbl]) -> Option<usize> {
    for (i, row) in table.iter().enumerate() {
        if !cmd_allowed(cctx, row) {
            continue;
        }
        if (cctx.flags & t::SSL_CONF_FLAG_CMDLINE as c_uint) != 0 {
            if let Some(cl) = row.str_cmdline {
                if cmd == cl {
                    return Some(i);
                }
            }
        }
        if (cctx.flags & t::SSL_CONF_FLAG_FILE as c_uint) != 0 {
            if let Some(fl) = row.str_file {
                if cmd.eq_ignore_ascii_case(fl) {
                    return Some(i);
                }
            }
        }
    }
    None
}

/// `ctrl_switch_option` — `ssl_conf.c:953-968`.
///
/// # Safety
/// `cctx` must satisfy [`ssl_set_option`]'s whole contract: non-NULL, aligned, live,
/// initialised, exclusively accessible for this call, with each flag pointer the
/// selected switch row uses either NULL or pointing to a live, aligned field of the
/// right type in an object that outlives the call. `idx` needs no precondition: it is
/// bounds-checked against the private switch table and an out-of-range value returns 0
/// without touching `cctx`.
unsafe fn ctrl_switch_option(cctx: *mut SslConfCtx, idx: usize) -> c_int {
    let sw = switches();
    if idx >= sw.len() {
        return 0;
    }
    // SAFETY: `cctx` is live.
    unsafe { ssl_set_option(cctx, sw[idx].name_flags, sw[idx].option_value, 1) };
    1
}

/// The body of [`SSL_CONF_cmd`] and [`SSL_CONF_cmd_argv`], separated so the latter can run
/// it while holding the same in-use guard instead of re-entering the guarded public entry
/// point.
///
/// # Safety
/// As [`SSL_CONF_cmd`], except that the caller must already hold the context's in-use guard
/// (or otherwise have established exclusive access). `cctx` must be non-NULL.
unsafe fn ssl_conf_cmd_inner(
    cctx: *mut SslConfCtx,
    cmd: *const c_char,
    value: *const c_char,
) -> c_int {
    if cctx.is_null() || cmd.is_null() {
        return 0;
    }
    let mut p = cmd;
    // SAFETY: `cctx` and `cmd` are per the guards above.
    if !unsafe { skip_prefix(cctx, &mut p) } {
        return -2;
    }
    // SAFETY: `p` points into the (NUL-terminated) command string.
    let name = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
    let table = commands();
    // SAFETY: `cctx` is live.
    let c = unsafe { &*cctx };
    let Some(idx) = cmd_lookup(c, name, &table) else {
        return -2;
    };
    let row = &table[idx];
    if row.value_type == t::SSL_CONF_TYPE_NONE as c_uint {
        // SAFETY: `cctx` is live.
        return unsafe { ctrl_switch_option(cctx, idx) };
    }
    if value.is_null() {
        return -3;
    }
    let Some(f) = row.cmd else {
        return -2;
    };
    // SAFETY: `cctx` and `value` are live per the caller's contract.
    let rv = unsafe { f(cctx, value) };
    if rv > 0 {
        return 2;
    }
    if rv != -2 {
        0
    } else {
        rv
    }
}

/// `int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value)` —
/// `ssl/ssl_conf.c:970-1010`.
///
/// # Safety
///
/// `cctx` must be NULL or point to a live, initialised `SslConfCtx` that this call has
/// exclusive access to for its whole duration: no other thread may read or write the
/// context, and no other shared or exclusive reference to it may be live. When
/// `cctx.ctx`/`cctx.ssl` are non-NULL they must be live in-crate `SSL_CTX`/`SSL` objects
/// that this call also has exclusive access to: the handlers write their option, verify,
/// cipher-list and protocol-bound fields, and [`SSL_CONF_cmd_argv`] also writes
/// `cctx.flags`, so no other thread may mutate or read them concurrently.
///
/// `cmd` must be NULL or NUL-terminated and readable for the call. `value` must be
/// non-NULL and NUL-terminated for every typed row (`value_type != SSL_CONF_TYPE_NONE`);
/// for a switch row or an unrecognised command the authority permits NULL and this
/// function never dereferences it on those paths, so NULL is accepted there. Any non-NULL
/// `value` must be readable for the whole call; no pointer is retained.
///
/// Authority-derived / documented divergence (`AGENTS.md` §17): the pinned authority's
/// `SSL_CONF_cmd(3)` documentation requires neither exclusive access nor the absence of
/// concurrent mutation, and the C implementation performs no check. This contract
/// therefore *narrows* what this crate accepts rather than changing behaviour: a caller
/// that follows the authority's documented usage (configure one `SSL_CTX`/`SSL` through
/// one context at a time) already satisfies it, while concurrent use is outside the
/// supported contract rather than silently treated as safe.
///
/// Same-thread overlap (`AGENTS.md` §17, B46-D2): an invocation that overlaps a dispatch
/// already in progress on the same `cctx` is refused deterministically with `0`; it is not
/// allowed to alias the context. This diverges from the authority, which would proceed, and
/// is the mechanism that closes the same-thread half of the exclusivity gap.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd(
    cctx: *mut SslConfCtx,
    cmd: *const c_char,
    value: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if cctx.is_null() || cmd.is_null() {
            return 0;
        }
        // SAFETY: `cctx` is non-NULL and live per the caller's contract and outlives this
        // call. Marking it before the body refuses an overlapping invocation (including
        // one issued from a handler) instead of allowing it to alias the context.
        let Some(_in_use) = (unsafe { enter_use(cctx) }) else {
            return 0;
        };
        // SAFETY: `cctx`/`cmd`/`value` are per the caller's contract; `_in_use` holds the
        // context for this call and is released on every exit path (including unwind).
        unsafe { ssl_conf_cmd_inner(cctx, cmd, value) }
    })
}

/// `int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)` —
/// `ssl/ssl_conf.c:1012-1044`.
///
/// # Safety
///
/// `cctx` must be NULL or a live, initialised `SslConfCtx` with the same exclusive-access
/// and no-concurrent-mutation requirements as [`SSL_CONF_cmd`], including the
/// `SSL`/`SSL_CTX` it wraps: this function writes `cctx.flags` before dispatch. `pargc`
/// must be NULL or point to a live, aligned, writable `c_int` that this call has
/// exclusive access to. `pargv` must be NULL or point to a live, writable
/// `*mut *mut c_char` whose `*pargv` is NULL or points to a readable array of
/// NUL-terminated C strings that this call has exclusive access to: at least `*pargc`
/// entries when `pargc` is non-NULL and positive, otherwise at least two entries (the
/// authority reads `argv[0]` and, for a two-argument command, `argv[1]`). When `pargc`
/// is non-NULL it is decremented by the number of arguments consumed. Neither the array
/// nor its strings are retained.
///
/// Authority-derived / documented divergence (`AGENTS.md` §17): as for [`SSL_CONF_cmd`],
/// the authority's documentation does not require exclusive access; this contract
/// narrows what the crate accepts without changing behaviour. An invocation overlapping a
/// dispatch already in progress on the same context is refused with `0` (B46-D2), and a
/// NULL `cctx` is now rechecked and answered with `0` instead of being dereferenced.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd_argv(
    cctx: *mut SslConfCtx,
    pargc: *mut c_int,
    pargv: *mut *mut *mut c_char,
) -> c_int {
    guard_ffi(0, || {
        if cctx.is_null() {
            return 0;
        }
        // SAFETY: `cctx` is non-NULL and live per the caller's contract and outlives this
        // call. The guard is held across the whole body, so a nested `SSL_CONF_cmd` (or a
        // second `SSL_CONF_cmd_argv`) is refused rather than aliasing the context.
        let Some(_in_use) = (unsafe { enter_use(cctx) }) else {
            return 0;
        };
        // SAFETY: `pargc` is NULL or points at a live `int` per the caller's contract.
        let count0 = if pargc.is_null() {
            0
        } else {
            // SAFETY: `pargc` is non-NULL, so it points at a live `int` per the caller.
            unsafe { *pargc }
        };
        if !pargc.is_null() && count0 == 0 {
            return 0;
        }
        if pargv.is_null() {
            return 0;
        }
        // SAFETY: `pargv` dereferences per the caller's contract.
        let argv = unsafe { *pargv };
        if argv.is_null() {
            return 0;
        }
        // The authority reads `**pargv` only when `pargc` is NULL or positive.
        if !pargc.is_null() && count0 <= 0 {
            return 0;
        }
        // SAFETY: `argv[0]` is the argument per the caller's contract.
        let arg = unsafe { *argv };
        if arg.is_null() {
            return 0;
        }
        // SAFETY: `pargc` is NULL or points at a live `int` per the caller's contract.
        let argn = if pargc.is_null() || count0 > 1 {
            // SAFETY: `argv[1]` is present per the caller's contract.
            unsafe { *argv.add(1) }
        } else {
            ptr::null_mut()
        };
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags &= !(t::SSL_CONF_FLAG_FILE as c_uint);
            (*cctx).flags |= t::SSL_CONF_FLAG_CMDLINE as c_uint;
        }
        // SAFETY: `cctx`/`arg`/`argn` are per `SSL_CONF_cmd`'s contract. The inner body is
        // used so this call does not re-enter the guarded public entry point.
        let rv = unsafe { ssl_conf_cmd_inner(cctx, arg, argn) };
        if rv > 0 {
            // SAFETY: `pargv`/`pargc` are per the caller's contract.
            unsafe {
                *pargv = argv.add(rv as usize);
                if !pargc.is_null() {
                    *pargc -= rv;
                }
            }
            return rv;
        }
        if rv == -2 {
            return 0;
        }
        if rv == 0 {
            return -1;
        }
        rv
    })
}

/// `int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd)` —
/// `ssl/ssl_conf.c:1046-1055`.
///
/// # Safety
/// `cctx` live; `cmd` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_cmd_value_type(
    cctx: *mut SslConfCtx,
    cmd: *const c_char,
) -> c_int {
    guard_ffi(t::SSL_CONF_TYPE_UNKNOWN as c_int, || {
        if cctx.is_null() {
            return t::SSL_CONF_TYPE_UNKNOWN as c_int;
        }
        let mut p = cmd;
        // SAFETY: `cctx` is live.
        if unsafe { skip_prefix(cctx, &mut p) } {
            // SAFETY: `p` points into the command string.
            let name = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
            let table = commands();
            // SAFETY: `cctx` is live.
            let c = unsafe { &*cctx };
            if let Some(idx) = cmd_lookup(c, name, &table) {
                return table[idx].value_type as c_int;
            }
        }
        t::SSL_CONF_TYPE_UNKNOWN as c_int
    })
}

/// `SSL_CONF_CTX *SSL_CONF_CTX_new(void)` — `ssl/ssl_conf.c:1057-1062`.
///
/// # Safety
/// The returned pointer is owned by the caller and released with [`SSL_CONF_CTX_free`].
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_new() -> *mut SslConfCtx {
    guard_ffi(ptr::null_mut(), || {
        // The context block is a `CRYPTO_zalloc` at the authority's own size/site; `into_raw`
        // hands it to the caller, which returns it to `SSL_CONF_CTX_free`.
        let Some(buf) = OwnedBuf::new_zeroed(core::mem::size_of::<SslConfCtx>(), FILE_SEAM, 1059)
        else {
            return ptr::null_mut();
        };
        buf.into_raw().cast::<SslConfCtx>()
    })
}

/// `int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx)` — `ssl/ssl_conf.c:1064-1101`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_finish(cctx: *mut SslConfCtx) -> c_int {
    guard_ffi(0, || {
        if cctx.is_null() {
            return 0;
        }
        // The private-key back-fill runs only under `SSL_CONF_FLAG_REQUIRE_PRIVATE`, which this
        // slice never installs; `canames` is always NULL, so the hand-off is a no-op.
        1
    })
}

/// `void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx)` — `ssl/ssl_conf.c:1114-1122`.
///
/// # Safety
/// `cctx` must be NULL or a live context, and not used after this call.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_free(cctx: *mut SslConfCtx) {
    guard_ffi((), || {
        if cctx.is_null() {
            return;
        }
        // The authority's teardown of the context's member buffers, before the block release.
        // SAFETY: `cctx` is live and owned here.
        unsafe {
            free_cert_filename(&mut *cctx);
            CRYPTO_free((*cctx).prefix.cast(), FILE, 0);
            OPENSSL_sk_free((*cctx).canames);
        }
        // Reclaim the block a matching `SSL_CONF_CTX_new` handed out; its single release is `Drop`.
        // SAFETY: `cctx` is the live block `SSL_CONF_CTX_new` gave up per the caller's contract,
        // not released before.
        // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL is the authority's own no-op `free(NULL)`.
        drop(unsafe { OwnedBuf::adopt_plain(cctx.cast(), FILE_SEAM, 1120) });
    })
}

/// `unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags)` —
/// `ssl/ssl_conf.c:1124-1128`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_flags(cctx: *mut SslConfCtx, flags: c_uint) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags |= flags;
            (*cctx).flags
        }
    })
}

/// `unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags)` —
/// `ssl/ssl_conf.c:1130-1134`.
///
/// # Safety
/// `cctx` must point to a live configuration context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_clear_flags(cctx: *mut SslConfCtx, flags: c_uint) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            (*cctx).flags &= !flags;
            (*cctx).flags
        }
    })
}

/// `int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)` —
/// `ssl/ssl_conf.c:1136-1151`.
///
/// # Safety
/// `cctx` live; `pre` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set1_prefix(
    cctx: *mut SslConfCtx,
    pre: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        let mut tmp: *mut c_char = ptr::null_mut();
        if !pre.is_null() {
            // SAFETY: `pre` is NUL-terminated; `CRYPTO_strdup` copies it.
            tmp = unsafe { CRYPTO_strdup(pre, FILE, 1140) };
            if tmp.is_null() {
                return 0;
            }
        }
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            CRYPTO_free((*cctx).prefix.cast(), FILE, 0);
            (*cctx).prefix = tmp;
            (*cctx).prefixlen = if tmp.is_null() {
                0
            } else {
                core::ffi::CStr::from_ptr(tmp).to_bytes().len()
            };
        }
        1
    })
}

/// `void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl)` — `ssl/ssl_conf.c:1153-1179`.
///
/// # Safety
/// `cctx` live; `ssl` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_ssl(cctx: *mut SslConfCtx, ssl: *mut Ssl) {
    guard_ffi((), || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            let c = &mut *cctx;
            c.ssl = ssl;
            c.ctx = ptr::null_mut();
            free_cert_filename(c);
            if ssl.is_null() {
                c.poptions = ptr::null_mut();
                c.min_version = ptr::null_mut();
                c.max_version = ptr::null_mut();
                c.pcert_flags = ptr::null_mut();
                c.pvfy_flags = ptr::null_mut();
                return;
            }
            c.poptions = &mut (*ssl).options;
            c.min_version = &mut (*ssl).min_proto_version;
            c.max_version = &mut (*ssl).max_proto_version;
            c.pvfy_flags = &mut (*ssl).verify_mode;
            c.pcert_flags = if (*ssl).cert.is_null() {
                ptr::null_mut()
            } else {
                &mut (*(*ssl).cert).cert_flags
            };
            let arr = CRYPTO_zalloc(
                SSL_PKEY_NUM * core::mem::size_of::<*mut c_char>(),
                FILE,
                1168,
            )
            .cast::<*mut c_char>();
            c.cert_filename = arr;
            if !arr.is_null() {
                c.num_cert_filename = SSL_PKEY_NUM;
            }
        }
    })
}

/// `void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx)` — `ssl/ssl_conf.c:1181-1203`.
///
/// # Safety
/// `cctx` live; `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SslConfCtx, ctx: *mut SslCtx) {
    guard_ffi((), || {
        // SAFETY: `cctx` is live per the caller's contract.
        unsafe {
            let c = &mut *cctx;
            c.ctx = ctx;
            c.ssl = ptr::null_mut();
            free_cert_filename(c);
            if ctx.is_null() {
                c.poptions = ptr::null_mut();
                c.min_version = ptr::null_mut();
                c.max_version = ptr::null_mut();
                c.pcert_flags = ptr::null_mut();
                c.pvfy_flags = ptr::null_mut();
                return;
            }
            c.poptions = &mut (*ctx).options;
            c.min_version = &mut (*ctx).min_proto_version;
            c.max_version = &mut (*ctx).max_proto_version;
            c.pvfy_flags = &mut (*ctx).verify_mode;
            c.pcert_flags = if (*ctx).cert.is_null() {
                ptr::null_mut()
            } else {
                &mut (*(*ctx).cert).cert_flags
            };
            let arr = CRYPTO_zalloc(
                SSL_PKEY_NUM * core::mem::size_of::<*mut c_char>(),
                FILE,
                1192,
            )
            .cast::<*mut c_char>();
            c.cert_filename = arr;
            if !arr.is_null() {
                c.num_cert_filename = SSL_PKEY_NUM;
            }
        }
    })
}

/// `free_cert_filename` — `ssl_conf.c:1103-1112`.
///
/// # Safety
/// `c` is a live, initialised `SslConfCtx` borrowed exclusively for the call (the `&mut`
/// states that). `c.cert_filename` must be NULL or the base pointer of an allocation from
/// this crate's `CRYPTO_zalloc`/`CRYPTO_malloc` seam of at least
/// `c.num_cert_filename * size_of::<*mut c_char>()` bytes; every one of those
/// `num_cert_filename` slots must be NULL or the base of a `CRYPTO_*` string allocation
/// that `c` exclusively owns and that has not already been released. The function frees
/// each non-NULL slot and then the array, once, and clears both fields; a pointer from a
/// different allocator, a short extent, or a slot owned elsewhere is undefined behaviour.
unsafe fn free_cert_filename(c: &mut SslConfCtx) {
    if c.cert_filename.is_null() {
        return;
    }
    // SAFETY: the array has `num_cert_filename` slots per its allocation.
    unsafe {
        for i in 0..c.num_cert_filename {
            CRYPTO_free(*c.cert_filename.add(i).cast::<*mut c_void>(), FILE, 0);
        }
        CRYPTO_free(c.cert_filename.cast(), FILE, 0);
    }
    c.cert_filename = ptr::null_mut();
    c.num_cert_filename = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new};

    /// The verify-mode words of an `SSL`/`SSL_CTX` are `int`s. Writing them through
    /// a widened `u64` view (as the pre-repair code did for both flag classes) runs
    /// four bytes past the field. The four-byte heap allocation is what lets the
    /// address sanitizer observe that overrun; without the instrument the value
    /// assertion still pins the bits that must be written.
    #[test]
    fn a_verify_option_writes_only_its_own_word() {
        let mut options: u64 = 0;
        let mut word: Box<c_int> = Box::new(0);
        // SAFETY: the context is this frame's zero-initialised storage (raw pointers and
        // integers, all-zero is valid), and both pointers refer to live fields above.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.poptions = &raw mut options;
        cctx.pvfy_flags = &raw mut *word;

        // SAFETY: `cctx` is live and the pointer fields are this frame's live storage.
        unsafe { ssl_set_option(&raw mut cctx, SSL_TFLAG_VFY, t::SSL_VERIFY_PEER, 1) };

        assert_eq!(*word, t::SSL_VERIFY_PEER as c_int);
    }

    /// The option tables are frame-local, unlike the authority's `static` ones. A command
    /// must not leave their address in the context once the parse returns.
    #[test]
    fn an_option_command_does_not_retain_its_frame_local_table() {
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state and every field is a
        // raw pointer, `usize` or integer.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;

        // SAFETY: `cctx` is this frame's live context; both strings are literals and
        // NUL-terminated. File mode recognises the row by its `Options` spelling.
        let rv = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"Bugs".as_ptr()) };
        assert_eq!(rv, 2, "the option list was accepted");
        assert!(
            cctx.tbl.is_null() && cctx.ntbl == 0,
            "the context retained a pointer to the handler's stack table"
        );
    }

    /// C2 control for the `ConfCmdFn` dispatch boundary: `SSL_CONF_cmd` reaches
    /// `cmd_Options` through the `SslConfCmdTbl.cmd` slot with a live `SslConfCtx`
    /// and a NUL-terminated value, applies two independent effects, clears the
    /// frame-local table, and refuses a NULL value before the indirect call. The
    /// direct call pins the handler's own NULL arm, which the dispatch never
    /// supplies. Mutating `cmd_Options`'s `value.is_null()` guard makes the final
    /// assertion fail (recorded in the B46 receipt).
    #[test]
    fn conf_cmd_dispatch_feeds_a_live_ctx_and_does_not_retain_the_value() {
        let mut options: u64 = 0;
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state and every field
        // is a raw pointer, `usize` or integer.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;
        cctx.poptions = &raw mut options;

        // SAFETY: `cctx` is this frame's live context; both literals are
        // NUL-terminated. File mode recognises the row by its `Options` spelling.
        let set = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"Bugs".as_ptr()) };
        assert_eq!(set, 2, "the handler accepted the option");
        assert_ne!(
            options & t::SSL_OP_ALL,
            0,
            "the callback wrote the live option word"
        );
        assert!(
            cctx.tbl.is_null() && cctx.ntbl == 0,
            "the context retained a pointer to the handler's stack table"
        );

        // A second dispatch with a different value must take effect independently.
        // SAFETY: as above; both strings are distinct NUL-terminated literals.
        let cleared =
            unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"-Bugs".as_ptr()) };
        assert_eq!(cleared, 2, "the second handler call accepted the option");
        assert_eq!(
            options & t::SSL_OP_ALL,
            0,
            "the callback retained state from the first value"
        );

        // SAFETY: as above. The dispatch refuses NULL before the indirect call and
        // answers the authority's `bad_value` result (`-3`).
        let null = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), ptr::null()) };
        assert_eq!(null, -3, "a NULL value is refused as a bad value");
        assert_eq!(
            options & t::SSL_OP_ALL,
            0,
            "a refused value changes no state"
        );

        // SAFETY: `cctx` is live and the NULL arm returns before any dereference.
        let direct = unsafe { cmd_Options(&raw mut cctx, ptr::null()) };
        assert_eq!(direct, -3, "the handler's own NULL arm returns -3");
    }

    /// C3 control for the `min_max_proto`/`ssl_set_version_bound` contract: a real
    /// `SSL_CTX`'s bound is written only for a name the authority's protocol table
    /// recognises, and an unrecognised name is refused without touching the bound.
    /// Mutating `protocol_from_string`'s unrecognised-name answer (the `-1`) so that
    /// it returns a valid version makes the refusal assertions fail (recorded in the
    /// B47 receipt).
    #[test]
    fn conf_cmd_min_max_protocol_bounds_are_range_checked() {
        // SAFETY: the method is a process-lifetime static; the constructor returns an
        // owned context.
        let ctx = unsafe { SSL_CTX_new(TLS_method()) };
        assert!(!ctx.is_null(), "SSL_CTX_new");
        // SAFETY: no arguments; the returned context is owned here.
        let cctx = unsafe { SSL_CONF_CTX_new() };
        assert!(!cctx.is_null(), "SSL_CONF_CTX_new");
        // SAFETY: both objects are live and exclusively ours for this test, and both
        // are released exactly once at the end.
        unsafe {
            SSL_CONF_CTX_set_flags(cctx, t::SSL_CONF_FLAG_FILE as c_uint);
            SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
        }
        // SAFETY: `ctx` is live and exclusively ours; the constructor zeroes both bounds.
        assert_eq!(unsafe { (*ctx).min_proto_version }, 0);

        // SAFETY: both objects are live and exclusively accessible; the literal is
        // NUL-terminated and the dispatch refuses any NULL before the handler.
        let accepted = unsafe { SSL_CONF_cmd(cctx, c"MinProtocol".as_ptr(), c"TLSv1.2".as_ptr()) };
        assert_eq!(accepted, 2, "a recognised protocol name is accepted");
        // SAFETY: `ctx` is live and exclusively ours.
        let written_min = unsafe { (*ctx).min_proto_version };
        assert_eq!(
            written_min,
            t::TLS1_2_VERSION as c_int,
            "the accepted name writes the live bound"
        );

        // SAFETY: `ctx` is live and exclusively ours; the read is a plain field access.
        let before = unsafe { (*ctx).min_proto_version };
        // SAFETY: as above. "TLSv1.4" is outside the authority's protocol table.
        let refused = unsafe { SSL_CONF_cmd(cctx, c"MinProtocol".as_ptr(), c"TLSv1.4".as_ptr()) };
        assert_eq!(refused, 0, "an unrecognised protocol name is refused");
        // SAFETY: `ctx` is live and exclusively ours.
        let after_min = unsafe { (*ctx).min_proto_version };
        assert_eq!(
            after_min, before,
            "a refused name leaves the bound untouched"
        );

        // SAFETY: as above; the dispatch answers -3 without reading `value`.
        let null = unsafe { SSL_CONF_cmd(cctx, c"MaxProtocol".as_ptr(), ptr::null()) };
        assert_eq!(null, -3, "a NULL value is refused as a bad value");
        // SAFETY: `ctx` is live and exclusively ours.
        assert_eq!(unsafe { (*ctx).max_proto_version }, 0);

        // SAFETY: both objects are live and exclusively ours; each is released once.
        unsafe {
            SSL_CONF_CTX_free(cctx);
            SSL_CTX_free(ctx);
        }
    }

    /// Exercises the multi-element path through `ssl_set_option_list`, which is where
    /// the context borrow used to be held across the `&mut *cctx` inside
    /// `ssl_set_option`. Two matching elements force the loop to run more than once
    /// with a mutable write between iterations; the mixed and all-failing lists pin
    /// `CONF_parse_list`'s "stops at the first failing element" return contract.
    ///
    /// This is a functional control only: from safe test code the aliasing itself is
    /// not observable, and the assertions would still pass if the shared borrow were
    /// reintroduced. Miri/Tree Borrows is required to test the borrowing discipline;
    /// that check is NOT_RUN under the FAST gate.
    #[test]
    fn option_list_applies_leading_matches_and_reports_failures() {
        let mut options: u64 = 0;
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state and every field
        // is a raw pointer, `usize` or integer.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;
        cctx.poptions = &raw mut options;

        // Both elements match: the loop must apply both and report success.
        // SAFETY: `cctx` is this frame's live context; the literal is NUL-terminated.
        let both = unsafe {
            SSL_CONF_cmd(
                &raw mut cctx,
                c"Options".as_ptr(),
                c"Bugs,MiddleboxCompat".as_ptr(),
            )
        };
        assert_eq!(both, 2, "an all-matching list succeeds");
        assert_ne!(options & t::SSL_OP_ALL, 0, "the first element applied");
        assert_ne!(
            options & t::SSL_OP_ENABLE_MIDDLEBOX_COMPAT,
            0,
            "the second element applied after the first mutable call"
        );
        assert!(
            cctx.tbl.is_null() && cctx.ntbl == 0,
            "the context retained a pointer to the handler's stack table"
        );

        // A leading match followed by a failure: the match is applied, but the list
        // as a whole returns 0 because `CONF_parse_list` stops at the failing element.
        // SAFETY: as above; the literal is NUL-terminated.
        let mixed = unsafe {
            SSL_CONF_cmd(
                &raw mut cctx,
                c"Options".as_ptr(),
                c"-Bugs,NoSuchOption".as_ptr(),
            )
        };
        assert_eq!(mixed, 0, "a mixed list does not succeed as a whole");
        assert_eq!(
            options & t::SSL_OP_ALL,
            0,
            "the leading `-Bugs` was applied before the failure"
        );
        assert!(
            cctx.tbl.is_null() && cctx.ntbl == 0,
            "the failure path also clears the frame-local table"
        );

        // An entirely failing list changes no state and still clears the table.
        let before = options;
        // SAFETY: as above; the literal is NUL-terminated.
        let none =
            unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"NoSuchOption".as_ptr()) };
        assert_eq!(none, 0, "an unmatched list is rejected");
        assert_eq!(options, before, "a rejected list changes no state");
        assert!(
            cctx.tbl.is_null() && cctx.ntbl == 0,
            "a rejected list leaves no frame-local pointer behind"
        );
    }

    /// C4 control for the same-context overlap refusal (B46-D2).
    ///
    /// A handler receives the same raw `*mut SslConfCtx` and can only re-enter through the
    /// public entry point, so holding the guard here is exactly the state a real dispatch
    /// presents to a handler that calls back into `SSL_CONF_cmd`. Mutating `SSL_CONF_cmd`
    /// to skip `enter_use` makes the re-entrant call succeed and this test fail (recorded in
    /// the B46 receipt).
    #[test]
    fn a_reentrant_dispatch_is_refused_and_leaves_the_context_usable() {
        let mut options: u64 = 0;
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state; the added `in_use`
        // field is an `AtomicBool`, whose all-zero value is `false`.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;
        cctx.poptions = &raw mut options;

        // A normal call first, so the refused call is compared against real applied state.
        // SAFETY: `cctx` is this frame's live context; the literal is NUL-terminated.
        let first = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"Bugs".as_ptr()) };
        assert_eq!(first, 2, "the first call succeeds");
        assert_ne!(
            options & t::SSL_OP_ALL,
            0,
            "the first call applied its option"
        );

        // Enter the in-use state exactly as an in-flight public dispatch does.
        // SAFETY: `cctx` is live and exclusively ours for this test.
        let in_flight = unsafe { enter_use(&raw mut cctx) };
        assert!(
            in_flight.is_some(),
            "the context was free before the overlap"
        );
        assert!(
            cctx.in_use.load(Ordering::Acquire),
            "the guard marks the context in use"
        );

        // The re-entrant call is refused with 0 and changes no state.
        // SAFETY: as above; the literal is a distinct NUL-terminated string.
        let reentrant =
            unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"-Bugs".as_ptr()) };
        assert_eq!(reentrant, 0, "an overlapping invocation is refused");
        assert_ne!(
            options & t::SSL_OP_ALL,
            0,
            "the refused invocation changed no state"
        );

        // Releasing the in-flight guard makes the context usable again.
        drop(in_flight);
        assert!(
            !cctx.in_use.load(Ordering::Acquire),
            "dropping the guard clears the flag"
        );
        // SAFETY: as above; the literal is NUL-terminated.
        let after = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"-Bugs".as_ptr()) };
        assert_eq!(after, 2, "the context is usable after the overlap");
        assert_eq!(
            options & t::SSL_OP_ALL,
            0,
            "the post-overlap call applied its option"
        );
    }

    /// C5 control for guard release: every early error exit must clear `in_use` (the RAII
    /// guard drops on `return` and on unwind), otherwise the context would be permanently
    /// unusable after one rejected command.
    #[test]
    fn the_in_use_guard_is_cleared_on_every_error_exit() {
        let mut options: u64 = 0;
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;
        cctx.poptions = &raw mut options;

        // Unrecognised command -> -2, after the guard was taken.
        // SAFETY: `cctx` is live; the literals are NUL-terminated.
        let unknown =
            unsafe { SSL_CONF_cmd(&raw mut cctx, c"NoSuchCommand".as_ptr(), c"x".as_ptr()) };
        assert_eq!(unknown, -2, "an unrecognised command is refused");
        assert!(
            !cctx.in_use.load(Ordering::Acquire),
            "the guard is cleared after the -2 exit"
        );

        // Typed row with a NULL value -> -3, after the guard was taken.
        // SAFETY: as above; the dispatch refuses NULL before reading it.
        let null = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), ptr::null()) };
        assert_eq!(null, -3, "a NULL value for a typed row is refused");
        assert!(
            !cctx.in_use.load(Ordering::Acquire),
            "the guard is cleared after the -3 exit"
        );

        // A handler-originated failure (unmatched option) is also an error exit.
        // SAFETY: as above; the literal is NUL-terminated.
        let unmatched =
            unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"NoSuchOption".as_ptr()) };
        assert_eq!(unmatched, 0, "an unmatched option is rejected");
        assert!(
            !cctx.in_use.load(Ordering::Acquire),
            "the guard is cleared after the handler error exit"
        );

        // The context still works after all three errors.
        // SAFETY: as above; the literal is NUL-terminated.
        let good = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), c"Bugs".as_ptr()) };
        assert_eq!(good, 2, "the context remains usable after the errors");
        assert_ne!(
            options & t::SSL_OP_ALL,
            0,
            "the recovery call applied its option"
        );
    }

    /// C6 control: the guard does not refuse ordinary sequential calls.
    #[test]
    fn sequential_dispatches_are_not_refused_by_the_in_use_guard() {
        let mut options: u64 = 0;
        // SAFETY: all-zero is the authority's `OPENSSL_zalloc` state.
        let mut cctx: SslConfCtx = unsafe { core::mem::zeroed() };
        cctx.flags = (t::SSL_CONF_FLAG_FILE | t::SSL_CONF_FLAG_CLIENT) as c_uint;
        cctx.poptions = &raw mut options;

        for (value, expected_set) in [(c"Bugs".as_ptr(), true), (c"-Bugs".as_ptr(), false)] {
            // SAFETY: `cctx` is live and the literal is NUL-terminated; sequential calls
            // are serialised by the caller, so each must take and release the guard.
            let rv = unsafe { SSL_CONF_cmd(&raw mut cctx, c"Options".as_ptr(), value) };
            assert_eq!(rv, 2, "a sequential dispatch is not refused");
            assert_eq!(
                options & t::SSL_OP_ALL != 0,
                expected_set,
                "each sequential dispatch applied its own value"
            );
            assert!(
                !cctx.in_use.load(Ordering::Acquire),
                "the guard is released before the next sequential call"
            );
        }
    }
}
