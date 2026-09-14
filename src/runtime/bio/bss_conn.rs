//! Phase 4 — `BIO_s_connect`, the connecting-socket BIO.
//!
//! A connect BIO is a socket BIO with a **name** and a state machine in front of
//! it. Every read, write and several controls will run the machine if it has not
//! reached `OK`, so "connect happened" is not something the caller has to ask
//! for: the first `BIO_write` performs the name lookup, creates the socket,
//! connects, and only then writes.
//!
//! ## The state machine, and why the order is the contract
//!
//!     BEFORE → GET_ADDR → CREATE_SOCKET → CONNECT → OK
//!                                  ↑           │
//!                                  └───────────┘   (next address after a failure)
//!                                              ↓
//!                                    BLOCKED_CONNECT → OK
//!                                              ↓
//!                                         CONNECT_ERROR
//!
//! Three properties of that ordering are observable and reproduced:
//!
//! * **Every address the resolver returned is tried.** A failed `connect(2)`
//!   that is not retryable moves to the *next* address and builds a fresh socket,
//!   rather than failing outright. A caller that only ever connects to a
//!   multi-homed localhost would never see this.
//! * **A retryable failure is not an error.** It parks in `BLOCKED_CONNECT` with
//!   `BIO_RR_CONNECT` and *pops the error mark* it set, so the queue is left with
//!   only what the caller would have seen had it never tried.
//! * **Failure to reach `OK` re-raises `BIO_R_CONNECT_ERROR`.** The terminal state
//!   raises on the *next* pass through the machine, not where the failure
//!   happened; that is why a caller sees `BIO_R_CONNECT_ERROR` rather than the
//!   `BIO_R_NBIO_CONNECT_ERROR` of the branch that failed.
//!
//! ## The datagram variant
//!
//! `BIO_C_SET_SOCK_TYPE(SOCK_DGRAM)` makes the machine build a **datagram** BIO
//! over the connected socket once `connect(2)` succeeds, and every subsequent
//! read and write is forwarded to it (`BIO_new_dgram`'s peer/ancillary handling is
//! what DTLS needs). That forward is why `conn_read` cannot simply call
//! `readsocket`: it must carry the inner BIO's retry flags back out.
//!
//! ## TCP Fast Open and kernel TLS
//!
//! Both are compiled out of this build profile, and the build record is what says
//! so: the authority was configured `no-tfo` and `no-ktls`. The kernel headers
//! define `TCP_FASTOPEN`, `TCP_FASTOPEN_CONNECT` and the `SOL_TLS` options, so
//! inferring the profile from the platform gets both wrong — `RT-BIO-CONN`
//! measured `BIO_C_SET_TFO` answering 0, which is the `default` arm, not the
//! fast-open case.
//!
//! The consequences are reproduced rather than papered over: `BIO_C_SET_TFO` falls
//! through to `default` and answers 0; `tfo_first` is written by the connect-mode
//! control and read by nothing; and `BIO_CTRL_SET_KTLS` and its three siblings
//! reach `default` and answer 0 as well.
//!
//! ## Fault boundaries
//!
//! The authority dereferences `b->ptr` in `conn_callback_ctrl` and in `conn_free`
//! without checking it, so calling either on a BIO whose `create` failed faults.
//! That is not reachable through `BIO_new_connect` (which frees the BIO when the
//! hostname cannot be set) and is not probed; this module makes the same
//! assumption the authority does.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_CONN_123, BSS_CONN_155, BSS_CONN_166, BSS_CONN_178, BSS_CONN_181, BSS_CONN_215,
    BSS_CONN_245, BSS_CONN_248, BSS_CONN_259, BSS_CONN_754, BSS_CONN_758, BSS_CONN_764,
    BSS_CONN_775, BSS_CONN_810, BSS_CONN_825, BSS_CONN_841, BSS_CONN_856,
};
use crate::runtime::err::{raise_site, raise_site_data, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};

use super::addr::{self, BioAddr};
use super::addr_info::{
    BIO_ADDRINFO_address, BIO_ADDRINFO_family, BIO_ADDRINFO_free, BIO_ADDRINFO_next,
    BIO_ADDRINFO_protocol, BIO_ADDRINFO_socktype, BIO_lookup, BioAddrInfo, BIO_LOOKUP_CLIENT,
    BIO_PARSE_PRIO_HOST,
};
use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{
    Bio, BioInfoCb, BioMethod, BIO_FAMILY_IPANY, BIO_FAMILY_IPV4, BIO_FAMILY_IPV6,
    BIO_FLAGS_IN_EOF, BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_RR_CONNECT,
    BIO_TYPE_CONNECT,
};

/// `INVALID_SOCKET`.
const INVALID_SOCKET: c_int = -1;

/// The method name the authority reports for a connect BIO.
const CONNECT_NAME: &[u8] = b"socket connect\0";

/// `assert(INT_MAX)` — the authority's bound on what `conn_puts` will write.
const INT_MAX: c_int = c_int::MAX;

/// `BIO_CONN_S_BEFORE` — no parameter has been supplied yet.
const BIO_CONN_S_BEFORE: c_int = 1;
/// `BIO_CONN_S_GET_ADDR` — the name is resolved.
const BIO_CONN_S_GET_ADDR: c_int = 2;
/// `BIO_CONN_S_CREATE_SOCKET` — a socket is created for the current address.
const BIO_CONN_S_CREATE_SOCKET: c_int = 3;
/// `BIO_CONN_S_CONNECT` — the socket is connected.
const BIO_CONN_S_CONNECT: c_int = 4;
/// `BIO_CONN_S_OK` — connected.
const BIO_CONN_S_OK: c_int = 5;
/// `BIO_CONN_S_BLOCKED_CONNECT` — a non-blocking connect is in progress.
const BIO_CONN_S_BLOCKED_CONNECT: c_int = 6;
/// `BIO_CONN_S_CONNECT_ERROR` — the terminal failure state.
const BIO_CONN_S_CONNECT_ERROR: c_int = 7;

/// The compiled-in method table returned by `BIO_s_connect`.
static CONNECT_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_CONNECT,
    name: CONNECT_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(conn_write),
    bread: Some(bread_conv),
    bread_old: Some(conn_read),
    bputs: Some(conn_puts),
    bgets: Some(conn_gets),
    ctrl: Some(conn_ctrl),
    create: Some(conn_new),
    destroy: Some(conn_free),
    callback_ctrl: Some(conn_callback_ctrl),
    sendmmsg: Some(conn_sendmmsg),
    recvmmsg: Some(conn_recvmmsg),
};

/// `bio_connect_st` — the state machine's parameters and results.
#[repr(C)]
struct BioConnect {
    /// One of the `BIO_CONN_S_*` states.
    state: c_int,
    /// The family the caller asked for; `BIO_FAMILY_IPANY` until it is set.
    connect_family: c_int,
    /// `SOCK_STREAM` unless the caller asked for datagrams.
    connect_sock_type: c_int,
    /// The hostname half of the name, owned.
    param_hostname: *mut c_char,
    /// The service half, owned.
    param_service: *mut c_char,
    /// The `BIO_SOCK_*` option bits `BIO_connect` is called with.
    connect_mode: c_int,
    /// Set when fast open is requested, and cleared after the first write. The
    /// fast-open path itself is compiled out of this build profile (`no-tfo`), so
    /// this is written by the mode control and read by nothing.
    tfo_first: c_int,
    /// The resolver's list, owned.
    addr_first: *mut BioAddrInfo,
    /// The element of that list currently being tried.
    addr_iter: *const BioAddrInfo,
    /// The state-transition callback, borrowed from the caller.
    info_callback: *mut BioInfoCb,
    /// A datagram BIO over the connected socket, owned, for `SOCK_DGRAM`.
    dgram_bio: *mut Bio,
}

/// The method data of a live connect BIO.
///
/// # Safety
/// `b` must be a live connect BIO whose `create` has succeeded.
unsafe fn data_of(b: *mut Bio) -> *mut BioConnect {
    // SAFETY: `conn_new` stored a `BioConnect` here and only `conn_free` removes
    // it.
    unsafe { (*b).ptr.cast::<BioConnect>() }
}

/// Render a C string argument for an `ERR_raise_data` format the way `_dopr`
/// does: a NULL pointer prints as `<NULL>`.
fn push_cstr(out: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        out.extend_from_slice(b"<NULL>");
        return;
    }
    // SAFETY: `p` is NUL-terminated per the caller's contract.
    let n = unsafe { sys::strlen(p) };
    // SAFETY: `p` is readable for `n` bytes.
    out.extend_from_slice(unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) });
}

/// Build a two-argument `ERR_raise_data` message, NUL-terminated.
///
/// The authority formats these with `BIO_vsnprintf`, so the text is byte-for-byte
/// what `_dopr` produces — including `<NULL>` for a missing half of the name.
fn fmt_two(prefix: &str, sep: &str, suffix: &str, a: *const c_char, b: *const c_char) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(prefix.as_bytes());
    push_cstr(&mut out, a);
    out.extend_from_slice(sep.as_bytes());
    push_cstr(&mut out, b);
    out.extend_from_slice(suffix.as_bytes());
    out.push(0);
    out
}

/* ------------------------------------------------------------------------- */
/* Construction and teardown.                                               */
/* ------------------------------------------------------------------------- */

/// `static BIO_CONNECT *BIO_CONNECT_new(void)`
fn connect_new() -> *mut BioConnect {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let ret =
        CRYPTO_zalloc(core::mem::size_of::<BioConnect>(), ptr::null(), 0).cast::<BioConnect>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is a fresh, zeroed allocation.
    unsafe {
        (*ret).state = BIO_CONN_S_BEFORE;
        (*ret).connect_family = BIO_FAMILY_IPANY;
        (*ret).connect_sock_type = sys::SOCK_STREAM;
    }
    ret
}

/// `static void BIO_CONNECT_free(BIO_CONNECT *a)`
///
/// # Safety
/// `a` must be NULL or a block from [`connect_new`] that has not been freed.
unsafe fn connect_free(a: *mut BioConnect) {
    // SAFETY: `a` is NULL or a block from `connect_new` per the caller's contract;
    // `as_mut` performs the null check that makes NULL total.
    let Some(c) = (unsafe { a.as_mut() }) else {
        return;
    };
    // SAFETY: `c` is live and the two strings are owned.
    unsafe {
        CRYPTO_free(c.param_hostname.cast(), ptr::null(), 0);
        CRYPTO_free(c.param_service.cast(), ptr::null(), 0);
        BIO_ADDRINFO_free(c.addr_first);
        CRYPTO_free(a.cast(), ptr::null(), 0);
    }
}

/// `const BIO_METHOD *BIO_s_connect(void)`
#[no_mangle]
pub extern "C" fn BIO_s_connect() -> *const BioMethod {
    guard_ffi(ptr::null(), || &CONNECT_METHOD)
}

/// `static int conn_new(BIO *bi)`
///
/// # Safety
/// `bi` must be the BIO `BIO_new` is constructing.
unsafe extern "C" fn conn_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 0;
        (*bi).num = INVALID_SOCKET;
        (*bi).flags = 0;
    }
    let data = connect_new();
    if data.is_null() {
        return 0;
    }
    // SAFETY: `bi` is live and `data` is a fresh allocation.
    unsafe {
        (*bi).ptr = data.cast();
    }
    1
}

/// `static void conn_close_socket(BIO *bio)`
///
/// The half-close is issued only when the machine reached `OK`, so a BIO that
/// never connected does not `shutdown(2)` a descriptor that was never connected —
/// which would raise `ENOTCONN` for the process, not just for this call.
///
/// # Safety
/// `bio` must be a live connect BIO.
unsafe fn conn_close_socket(bio: *mut Bio) {
    // SAFETY: `bio` is a live connect BIO per the caller's contract, so `create`
    // succeeded and stored a `BioConnect` in `ptr`.
    let data = unsafe { data_of(bio) };
    // SAFETY: `bio` is live, so its `num` field is a readable descriptor slot.
    if unsafe { (*bio).num } != INVALID_SOCKET {
        // SAFETY: `data` is live.
        if unsafe { (*data).state } == BIO_CONN_S_OK {
            // SAFETY: the descriptor is live.
            unsafe { sys::shutdown((*bio).num, sys::SHUT_RDWR) };
        }
        // SAFETY: the descriptor is live.
        unsafe { super::bss_sock::BIO_closesocket((*bio).num) };
        // SAFETY: `bio` is live.
        unsafe { (*bio).num = INVALID_SOCKET };
    }
}

/// `static int conn_free(BIO *a)`
///
/// The private state and the descriptor are released only when the BIO owns
/// them; the inner datagram BIO is released unconditionally, because it owns its
/// own descriptor.
///
/// # Safety
/// `a` must be NULL or a live connect BIO.
unsafe extern "C" fn conn_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live.
    let data = unsafe { data_of(a) };
    // SAFETY: `data` is live and `dgram_bio` is owned by it; `BIO_free` accepts
    // NULL.
    unsafe { super::BIO_free((*data).dgram_bio) };
    // SAFETY: `a` and `data` are live.
    unsafe {
        if (*a).shutdown != 0 {
            conn_close_socket(a);
            connect_free(data);
            (*a).ptr = ptr::null_mut();
            (*a).flags = 0;
            (*a).init = 0;
        }
    }
    1
}

/* ------------------------------------------------------------------------- */
/* The state machine.                                                       */
/* ------------------------------------------------------------------------- */

/// `static int conn_create_dgram_bio(BIO *b, BIO_CONNECT *c)`
///
/// # Safety
/// `b` must be a live connect BIO and `c` its data.
unsafe fn create_dgram_bio(b: *mut Bio, c: *mut BioConnect) -> c_int {
    // SAFETY: `c` is live.
    if unsafe { (*c).connect_sock_type } != sys::SOCK_DGRAM {
        return 1;
    }
    // SAFETY: `b.num` is a live descriptor and the new BIO does not own it (the
    // connect BIO closes it).
    let dgram = unsafe { super::bss_dgram::BIO_new_dgram((*b).num, 0) };
    if dgram.is_null() {
        // SAFETY: `c` is live.
        unsafe { (*c).state = BIO_CONN_S_CONNECT_ERROR };
        return 0;
    }
    // SAFETY: `c` is live.
    unsafe { (*c).dgram_bio = dgram };
    1
}

/// `BIO_set_retry_special(b)` — `BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY`.
fn set_retry_special(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe {
        (*b).flags |= BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY;
    }
}

/// `BIO_clear_retry_flags(b)`.
fn clear_retry_flags(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe {
        (*b).flags &= !(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
    }
}

/// `static int conn_state(BIO *b, BIO_CONNECT *c)`
///
/// # Safety
/// `b` must be a live connect BIO and `c` its data.
unsafe fn conn_state(b: *mut Bio, c: *mut BioConnect) -> c_int {
    let mut ret: c_int = -1;
    // SAFETY: `c` is live.
    let cb = unsafe { (*c).info_callback };

    'outer: loop {
        // The match is wrapped in a labelled block so the two ways out of a C
        // `switch` are distinguishable. A `break` inside the switch lands *after*
        // it — which is the info-callback block below — while `goto exit_loop`
        // skips that. Writing both as `break 'outer` would silently drop the
        // callback, and writing both as a plain continue would run it where the
        // authority does not: `RT-BIO-CONN` catches the second mistake, because a
        // callback that returns 0 (the failing arm's own result) stops the machine
        // before the terminal `CONNECT_ERROR` state raises.
        'switch: {
            // SAFETY: `c` and `b` are live.
            match unsafe { (*c).state } {
                BIO_CONN_S_BEFORE => {
                    // SAFETY: `c` is live.
                    if unsafe { (*c).param_hostname }.is_null()
                        // SAFETY: `c` is live.
                        && unsafe { (*c).param_service }.is_null()
                    {
                        let msg = fmt_two(
                            "hostname=",
                            " service=",
                            "",
                            // SAFETY: `c` is live, so its two string fields are readable.
                            unsafe { (*c).param_hostname },
                            // SAFETY: as above.
                            unsafe { (*c).param_service },
                        );
                        // SAFETY: the site is a compile-time constant and `msg` is a
                        // NUL-terminated buffer.
                        unsafe { raise_site_data(&BSS_CONN_123, msg.as_ptr().cast()) };
                        break 'outer;
                    }
                    // SAFETY: `c` is live.
                    unsafe { (*c).state = BIO_CONN_S_GET_ADDR };
                }
                BIO_CONN_S_GET_ADDR => {
                    // The `BIO_FAMILY_IPV6` arm's sibling raise is not compiled on this
                    // platform: the authority writes it in the `else` of a `if (1)`, so
                    // with IPv6 available it cannot be reached.
                    // SAFETY: `c` is live; `connect_family` is one of the
                    // initialised integer fields.
                    let family = match unsafe { (*c).connect_family } {
                        BIO_FAMILY_IPV6 => sys::AF_INET6,
                        BIO_FAMILY_IPV4 => sys::AF_INET,
                        BIO_FAMILY_IPANY => sys::AF_UNSPEC,
                        _ => {
                            // SAFETY: the site is a compile-time constant.
                            unsafe { raise_site(&BSS_CONN_155) };
                            break 'outer;
                        }
                    };
                    // SAFETY: `c` and `b` are live; the lookup allocates the list,
                    // which `BIO_CONNECT_free` releases.
                    let rc = unsafe {
                        BIO_lookup(
                            (*c).param_hostname,
                            (*c).param_service,
                            BIO_LOOKUP_CLIENT,
                            family,
                            (*c).connect_sock_type,
                            ptr::addr_of_mut!((*c).addr_first),
                        )
                    };
                    if rc == 0 {
                        break 'outer;
                    }
                    // SAFETY: `c` is live.
                    unsafe {
                        if (*c).addr_first.is_null() {
                            // SAFETY: the site is a compile-time constant.
                            raise_site(&BSS_CONN_166);
                            break 'outer;
                        }
                        (*c).addr_iter = (*c).addr_first;
                        (*c).state = BIO_CONN_S_CREATE_SOCKET;
                    }
                }
                BIO_CONN_S_CREATE_SOCKET => {
                    // SAFETY: `c` is live and `addr_iter` non-NULL from the arm above.
                    let iter = unsafe { (*c).addr_iter };
                    // SAFETY: `iter` is a live node.
                    let fd = super::bio_sock2::BIO_socket(
                        unsafe { BIO_ADDRINFO_family(iter) },
                        unsafe { BIO_ADDRINFO_socktype(iter) },
                        unsafe { BIO_ADDRINFO_protocol(iter) },
                        0,
                    );
                    // The descriptor becomes `ret` before the callback sees it: the
                    // authority assigns the syscall's result to the same variable it
                    // hands the info callback, so the callback observes the fd.
                    ret = fd;
                    if fd == INVALID_SOCKET {
                        let msg = fmt_two(
                            "calling socket(",
                            ", ",
                            ")",
                            // SAFETY: `c` is live, so its two string fields are readable.
                            unsafe { (*c).param_hostname },
                            // SAFETY: as above.
                            unsafe { (*c).param_service },
                        );
                        // SAFETY: the sites are compile-time constants and `msg` is
                        // NUL-terminated.
                        unsafe {
                            raise_site_dynamic_data(
                                &BSS_CONN_178,
                                sys::errno(),
                                msg.as_ptr().cast(),
                            );
                            raise_site(&BSS_CONN_181);
                        }
                        break 'outer;
                    }
                    // SAFETY: `b` and `c` are live.
                    unsafe {
                        (*b).num = fd;
                        (*c).state = BIO_CONN_S_CONNECT;
                    }
                }
                BIO_CONN_S_CONNECT => {
                    clear_retry_flags(b);
                    // SAFETY: `ERR_set_mark` manipulates the calling thread's queue.
                    crate::runtime::err::ERR_set_mark();

                    // SAFETY: `c` is live.
                    let mut opts = unsafe { (*c).connect_mode };
                    // SAFETY: `c` is live and on this arm `addr_iter` points into the
                    // chain the lookup just built.
                    let iter = unsafe { (*c).addr_iter };
                    // SAFETY: `iter` is a live node.
                    if unsafe { BIO_ADDRINFO_socktype(iter) } == sys::SOCK_STREAM {
                        opts |= sys::BIO_SOCK_KEEPALIVE;
                    }
                    // SAFETY: `iter` is live; `BIO_connect` reads the address.
                    let rc = unsafe {
                        super::bio_sock2::BIO_connect((*b).num, BIO_ADDRINFO_address(iter), opts)
                    };
                    // As for the socket above: the callback sees `BIO_connect`'s own
                    // result, which is why a successful connect reports 1 here rather
                    // than the state's value.
                    ret = rc;
                    // SAFETY: `b` is live.
                    unsafe { (*b).retry_reason = 0 };
                    if rc == 0 {
                        // SAFETY: `ret` is a live local and `errno` is thread-local.
                        if super::bss_sock::BIO_sock_should_retry(0) != 0 {
                            set_retry_special(b);
                            // SAFETY: `b` and `c` are live.
                            unsafe {
                                (*c).state = BIO_CONN_S_BLOCKED_CONNECT;
                                (*b).retry_reason = BIO_RR_CONNECT;
                            }
                            // SAFETY: `ERR_pop_to_mark` manipulates the queue.
                            crate::runtime::err::ERR_pop_to_mark();
                            break 'outer;
                        }
                        // SAFETY: `iter` is a live node.
                        let next = unsafe { BIO_ADDRINFO_next(iter) };
                        if !next.is_null() {
                            // SAFETY: `c` and `b` are live; the descriptor is
                            // replaced, so the old one is closed first.
                            unsafe {
                                (*c).addr_iter = next;
                                super::bss_sock::BIO_closesocket((*b).num);
                                (*c).state = BIO_CONN_S_CREATE_SOCKET;
                            }
                            // SAFETY: `ERR_pop_to_mark` manipulates the queue.
                            crate::runtime::err::ERR_pop_to_mark();
                            break 'switch;
                        }
                        // SAFETY: `ERR_clear_last_mark` manipulates the queue.
                        crate::runtime::err::ERR_clear_last_mark();
                        let msg = fmt_two(
                            "calling connect(",
                            ", ",
                            ")",
                            // SAFETY: `c` is live, so its two string fields are readable.
                            unsafe { (*c).param_hostname },
                            // SAFETY: as above.
                            unsafe { (*c).param_service },
                        );
                        // SAFETY: the site is a compile-time constant and `msg` is
                        // NUL-terminated.
                        unsafe {
                            raise_site_dynamic_data(
                                &BSS_CONN_215,
                                sys::errno(),
                                msg.as_ptr().cast(),
                            );
                            (*c).state = BIO_CONN_S_CONNECT_ERROR;
                        }
                        break 'switch;
                    }
                    // SAFETY: `ERR_clear_last_mark` manipulates the queue.
                    crate::runtime::err::ERR_clear_last_mark();
                    // SAFETY: `b` and `c` are live.
                    unsafe {
                        if create_dgram_bio(b, c) == 0 {
                            break 'switch;
                        }
                        (*c).state = BIO_CONN_S_OK;
                    }
                }
                BIO_CONN_S_BLOCKED_CONNECT => {
                    // SAFETY: `b.num` is a live descriptor; `time(NULL)` is the
                    // authority's "now", used as the absolute wait bound.
                    let waited = super::bss_sock::BIO_socket_wait(unsafe { (*b).num }, 0, unsafe {
                        sys::time(ptr::null_mut())
                    });
                    if waited == 0 {
                        // Still blocked: the loop re-enters this state.
                    } else {
                        // SAFETY: `b.num` is a live descriptor.
                        let i = super::bss_sock::BIO_sock_error(unsafe { (*b).num });
                        if i != 0 {
                            clear_retry_flags(b);
                            // SAFETY: `c` is live and `addr_iter` points at the node the
                            // failed connect was attempted against.
                            let iter = unsafe { (*c).addr_iter };
                            // SAFETY: `iter` is a live node.
                            let next = unsafe { BIO_ADDRINFO_next(iter) };
                            if !next.is_null() {
                                // SAFETY: `c` and `b` are live.
                                unsafe {
                                    (*c).addr_iter = next;
                                    super::bss_sock::BIO_closesocket((*b).num);
                                    (*c).state = BIO_CONN_S_CREATE_SOCKET;
                                }
                                break 'switch;
                            }
                            let msg = fmt_two(
                                "calling connect(",
                                ", ",
                                ")",
                                // SAFETY: `c` is live, so its two string fields are readable.
                                unsafe { (*c).param_hostname },
                                // SAFETY: as above.
                                unsafe { (*c).param_service },
                            );
                            // SAFETY: the sites are compile-time constants and `msg`
                            // is NUL-terminated.
                            unsafe {
                                raise_site_dynamic_data(&BSS_CONN_245, i, msg.as_ptr().cast());
                                raise_site(&BSS_CONN_248);
                            }
                            ret = 0;
                            break 'outer;
                        }
                        // SAFETY: `b` and `c` are live.
                        unsafe {
                            if create_dgram_bio(b, c) == 0 {
                                break 'switch;
                            }
                            (*c).state = BIO_CONN_S_OK;
                        }
                    }
                }
                BIO_CONN_S_CONNECT_ERROR => {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&BSS_CONN_259) };
                    ret = 0;
                    break 'outer;
                }
                BIO_CONN_S_OK => {
                    ret = 1;
                    break 'outer;
                }
                _ => break 'outer,
            }
        }

        if !cb.is_null() {
            // `BIO_info_cb *` in C is the function pointer itself, not the address
            // of one, so the stored value is a code address and calling through it
            // must not dereference the pointer. Transmuting is how that is spelled
            // on this side of the ABI.
            // SAFETY: `cb` is either NULL (checked) or a `BIO_info_cb` the caller
            // installed through `BIO_callback_ctrl`. `transmute_copy` reinterprets
            // the pointer-sized code address `cb` holds as the function pointer; it
            // must not dereference `cb`, which would read the function's own bytes.
            let f: BioInfoCb = unsafe { core::mem::transmute_copy(&cb) };
            // SAFETY: `b` and `c` are live; `f` is the caller's callback.
            let r = unsafe { f(b, (*c).state, ret) };
            if r == 0 {
                return 0;
            }
            ret = r;
        }
    }

    if !cb.is_null() {
        // SAFETY: as above; `cb` holds the callback's code address, and
        // `transmute_copy` reinterprets those bits without dereferencing it.
        let f: BioInfoCb = unsafe { core::mem::transmute_copy(&cb) };
        // SAFETY: `b` and `c` are live.
        ret = unsafe { f(b, (*c).state, ret) };
    }
    ret
}

/* ------------------------------------------------------------------------- */
/* Read and write.                                                          */
/* ------------------------------------------------------------------------- */

/// `BIO_get_retry_flags(b)` — the two retry bits.
fn retry_flags(b: *mut Bio) -> c_int {
    // SAFETY: `b` is live.
    unsafe { (*b).flags & (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) }
}

/// `static int conn_read(BIO *b, char *out, int outl)`
///
/// # Safety
/// `b` must be a live connect BIO; `out` must be NULL or writable for `outl`
/// bytes.
unsafe extern "C" fn conn_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `b` is a live connect BIO per the caller's contract, so `create`
    // succeeded and stored a `BioConnect` in `ptr`.
    let data = unsafe { data_of(b) };
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).state } != BIO_CONN_S_OK {
        // SAFETY: `b` and `data` are live.
        ret = unsafe { conn_state(b, data) };
        if ret <= 0 {
            return ret;
        }
    }
    // SAFETY: `data` is live, from the `data_of` above.
    if !unsafe { (*data).dgram_bio }.is_null() {
        clear_retry_flags(b);
        // SAFETY: the inner BIO is live and `out` is writable per the caller's
        // contract.
        ret = unsafe { super::BIO_read((*data).dgram_bio, out.cast(), outl) };
        // SAFETY: `b` is live.
        unsafe {
            (*b).flags |= retry_flags((*data).dgram_bio);
        }
        return ret;
    }
    if out.is_null() {
        return ret;
    }
    // SAFETY: `errno` is thread-local and always writable.
    unsafe { sys::set_errno(0) };
    // SAFETY: `b.num` is a live descriptor; `out` is writable for `outl` bytes.
    let raw = unsafe { sys::recv((*b).num, out.cast(), outl as usize, 0) as c_int };
    ret = raw;
    clear_retry_flags(b);
    if ret <= 0 {
        if super::bss_sock::BIO_sock_should_retry(ret) != 0 {
            // SAFETY: `b` is live.
            unsafe { (*b).flags |= super::BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY };
        } else if ret == 0 {
            // SAFETY: `b` is live.
            unsafe { (*b).flags |= BIO_FLAGS_IN_EOF };
        }
    }
    ret
}

/// `static int conn_write(BIO *b, const char *in, int inl)`
///
/// # Safety
/// `b` must be a live connect BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn conn_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    // SAFETY: `b` is a live connect BIO per the caller's contract, so `create`
    // succeeded and stored a `BioConnect` in `ptr`.
    let data = unsafe { data_of(b) };
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).state } != BIO_CONN_S_OK {
        // SAFETY: `b` and `data` are live.
        let rc = unsafe { conn_state(b, data) };
        if rc <= 0 {
            return rc;
        }
    }
    // SAFETY: `data` is live, from the `data_of` above.
    if !unsafe { (*data).dgram_bio }.is_null() {
        clear_retry_flags(b);
        // SAFETY: the inner BIO is live and `in_` is readable per the contract.
        let ret = unsafe { super::BIO_write((*data).dgram_bio, in_.cast(), inl) };
        // SAFETY: `b` is live.
        unsafe {
            (*b).flags |= retry_flags((*data).dgram_bio);
        }
        return ret;
    }
    // SAFETY: `errno` is thread-local and always writable.
    unsafe { sys::set_errno(0) };
    // Neither the `OSSL_TFO_SENDTO` fast-open `sendto(2)` nor the kernel-TLS
    // control message is compiled in this build profile; the write is plain.
    // SAFETY: the descriptor and the buffer are live.
    let ret = unsafe { sys::send((*b).num, in_.cast(), inl as usize, 0) as c_int };
    clear_retry_flags(b);
    if ret <= 0 && super::bss_sock::BIO_sock_should_retry(ret) != 0 {
        // SAFETY: `b` is live.
        unsafe { (*b).flags |= super::BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY };
    }
    ret
}

/// `static int conn_puts(BIO *bp, const char *str)`
///
/// # Safety
/// `bp` must be a live connect BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn conn_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `str_` is NUL-terminated per the method contract.
    let n = unsafe { sys::strlen(str_) };
    if n > INT_MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `str_` is valid for `n` bytes.
    unsafe { conn_write(bp, str_, n as c_int) }
}

/// `int conn_gets(BIO *bio, char *buf, int size)`
///
/// Reads one byte at a time until a newline or the buffer is one byte short of
/// full, so the result is always terminated and never includes more than one
/// line. A read that returns 0 is end-of-stream, and then a zero-length string is
/// a *success*; a read that fails is not.
///
/// # Safety
/// `bio` must be NULL or a live connect BIO; `buf` must be NULL or writable for
/// `size` bytes.
unsafe extern "C" fn conn_gets(bio: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    if buf.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_754) };
        return -1;
    }
    if size <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_758) };
        return -1;
    }
    // SAFETY: `buf` is writable for `size` bytes.
    unsafe { *buf = 0 };
    // SAFETY: `bio` is non-NULL here (checked), so its `ptr` field is readable.
    if bio.is_null() || unsafe { (*bio).ptr }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_764) };
        return -1;
    }
    // SAFETY: `bio` is a live connect BIO here: non-NULL with a non-NULL `ptr`.
    let data = unsafe { data_of(bio) };
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).state } != BIO_CONN_S_OK {
        // SAFETY: `bio` and `data` are live.
        let rc = unsafe { conn_state(bio, data) };
        if rc <= 0 {
            return rc;
        }
    }
    // SAFETY: `data` is live, from the `data_of` above.
    if !unsafe { (*data).dgram_bio }.is_null() {
        // A datagram socket has no lines to read, and saying so is the contract.
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_775) };
        return -1;
    }
    // SAFETY: `errno` is thread-local and always writable.
    unsafe { sys::set_errno(0) };

    let mut ret: c_int = 0;
    let mut cursor = buf;
    let mut left = size;
    while left > 1 {
        // SAFETY: `cursor` points inside the caller's buffer, which has at least
        // `left` writable bytes remaining.
        let got = unsafe { sys::recv((*bio).num, cursor.cast(), 1, 0) as c_int };
        ret = got;
        clear_retry_flags(bio);
        if ret <= 0 {
            if super::bss_sock::BIO_sock_should_retry(ret) != 0 {
                // SAFETY: `bio` is live.
                unsafe { (*bio).flags |= super::BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY };
            } else if ret == 0 {
                // SAFETY: `bio` is live.
                unsafe { (*bio).flags |= BIO_FLAGS_IN_EOF };
            }
            break;
        }
        // SAFETY: `cursor` is writable and `left > 1` so the byte fits.
        let byte = unsafe { *cursor };
        // SAFETY: `left > 1` means `cursor` is inside the caller's buffer, so
        // advancing by one stays at or before the terminator slot.
        cursor = unsafe { cursor.add(1) };
        left -= 1;
        if byte == b'\n' as c_char {
            break;
        }
    }
    // SAFETY: `cursor` is within the buffer.
    unsafe { *cursor = 0 };
    let produced = (cursor as usize).wrapping_sub(buf as usize) as c_int;
    // SAFETY: `bio` is live: it was non-NULL with a non-NULL `ptr` above.
    if ret > 0 || unsafe { (*bio).flags } & BIO_FLAGS_IN_EOF != 0 {
        produced
    } else {
        ret
    }
}

/* ------------------------------------------------------------------------- */
/* conn_ctrl.                                                               */
/* ------------------------------------------------------------------------- */

/// `static long conn_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live connect BIO and `ptr` must be appropriate for `cmd`.
unsafe extern "C" fn conn_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    // SAFETY: `b` is a live connect BIO per the caller's contract, so `create`
    // succeeded and stored a `BioConnect` in `ptr`.
    let data = unsafe { data_of(b) };

    match cmd {
        super::BIO_CTRL_RESET => {
            ret = 0;
            // SAFETY: `b` and `data` are live.
            unsafe {
                (*data).state = BIO_CONN_S_BEFORE;
                conn_close_socket(b);
                BIO_ADDRINFO_free((*data).addr_first);
                (*data).addr_first = ptr::null_mut();
                (*data).addr_iter = ptr::null();
                (*b).flags = 0;
            }
        }
        super::BIO_C_DO_STATE_MACHINE => {
            // SAFETY: `b` and `data` are live.
            ret = unsafe {
                if (*data).state != BIO_CONN_S_OK {
                    conn_state(b, data) as c_long
                } else {
                    1
                }
            };
        }
        super::BIO_C_GET_CONNECT => {
            if ptr.is_null() {
                ret = 0;
            } else if num == 0 {
                // SAFETY: `data` is live; the caller passes `const char **`.
                unsafe { *ptr.cast::<*const c_char>() = (*data).param_hostname };
            } else if num == 1 {
                // SAFETY: as above.
                unsafe { *ptr.cast::<*const c_char>() = (*data).param_service };
            } else if num == 2 {
                // SAFETY: `data` is live and the caller passes a pointer slot.
                unsafe {
                    let iter = (*data).addr_iter;
                    *ptr.cast::<*const c_char>() = BIO_ADDRINFO_address(iter).cast();
                }
            } else if num == 3 {
                // SAFETY: `data` is live.
                let iter = unsafe { (*data).addr_iter };
                // SAFETY: `iter` is a live node.
                let family = unsafe { BIO_ADDRINFO_family(iter) };
                ret = match family {
                    sys::AF_INET6 => BIO_FAMILY_IPV6 as c_long,
                    sys::AF_INET => BIO_FAMILY_IPV4 as c_long,
                    // SAFETY: `data` is live.
                    0 => (unsafe { (*data).connect_family }) as c_long,
                    _ => -1,
                };
            } else if num == 4 {
                // SAFETY: `data` is live.
                ret = unsafe { (*data).connect_mode } as c_long;
            } else {
                ret = 0;
            }
        }
        super::BIO_C_SET_CONNECT => {
            if ptr.is_null() {
                // The authority only acts when `ptr` is non-NULL and leaves `ret`
                // at 1 otherwise.
            } else {
                // SAFETY: `b` is live.
                unsafe { (*b).init = 1 };
                if num == 0 {
                    // A host:service spec is parsed, and the service is only
                    // replaced when the spec actually carried one.
                    // SAFETY: `data` is live; `ptr` is a NUL-terminated string.
                    unsafe {
                        let hold = (*data).param_service;
                        CRYPTO_free((*data).param_hostname.cast(), ptr::null(), 0);
                        (*data).param_hostname = ptr::null_mut();
                        let rc = super::addr_info::BIO_parse_hostserv(
                            ptr.cast(),
                            ptr::addr_of_mut!((*data).param_hostname),
                            ptr::addr_of_mut!((*data).param_service),
                            BIO_PARSE_PRIO_HOST,
                        );
                        ret = rc as c_long;
                        if hold != (*data).param_service {
                            CRYPTO_free(hold.cast(), ptr::null(), 0);
                        }
                    }
                } else if num == 1 {
                    // SAFETY: `data` is live; `ptr` is a NUL-terminated string.
                    unsafe {
                        CRYPTO_free((*data).param_service.cast(), ptr::null(), 0);
                        (*data).param_service = CRYPTO_strdup(ptr.cast(), ptr::null(), 0);
                        if (*data).param_service.is_null() {
                            ret = 0;
                        }
                    }
                } else if num == 2 {
                    // SAFETY: `data` is live and `ptr` is a `BIO_ADDR *`.
                    unsafe {
                        let a = ptr.cast::<BioAddr>();
                        let host = addr::BIO_ADDR_hostname_string(a, 1);
                        let service = addr::BIO_ADDR_service_string(a, 1);
                        ret = c_long::from(!host.is_null() && !service.is_null());
                        if ret != 0 {
                            CRYPTO_free((*data).param_hostname.cast(), ptr::null(), 0);
                            (*data).param_hostname = host;
                            CRYPTO_free((*data).param_service.cast(), ptr::null(), 0);
                            (*data).param_service = service;
                            BIO_ADDRINFO_free((*data).addr_first);
                            (*data).addr_first = ptr::null_mut();
                            (*data).addr_iter = ptr::null();
                        } else {
                            CRYPTO_free(host.cast(), ptr::null(), 0);
                            CRYPTO_free(service.cast(), ptr::null(), 0);
                        }
                    }
                } else if num == 3 {
                    // SAFETY: the caller passes an `int *` through `BIO_int_ctrl`.
                    unsafe { (*data).connect_family = *ptr.cast::<c_int>() };
                } else {
                    ret = 0;
                }
            }
        }
        super::BIO_C_SET_SOCK_TYPE => {
            // SAFETY: `data` is live.
            let past_binding = unsafe { (*data).state } >= BIO_CONN_S_GET_ADDR;
            if (num != sys::SOCK_STREAM as c_long && num != sys::SOCK_DGRAM as c_long)
                || past_binding
            {
                ret = 0;
            } else {
                // SAFETY: `data` is live.
                unsafe { (*data).connect_sock_type = num as c_int };
                ret = 1;
            }
        }
        super::BIO_C_GET_SOCK_TYPE => {
            // SAFETY: `data` is live.
            ret = unsafe { (*data).connect_sock_type } as c_long;
        }
        super::BIO_C_GET_DGRAM_BIO => {
            // SAFETY: `data` is live; the caller passes a `BIO **`.
            unsafe {
                if (*data).dgram_bio.is_null() {
                    ret = 0;
                } else {
                    *ptr.cast::<*mut Bio>() = (*data).dgram_bio;
                    ret = 1;
                }
            }
        }
        super::BIO_CTRL_DGRAM_GET_PEER | super::BIO_CTRL_DGRAM_DETECT_PEER_ADDR => {
            // SAFETY: `b` and `data` are live.
            unsafe {
                if (*data).state != BIO_CONN_S_OK {
                    // Best effort: the state machine is advanced, and its result is
                    // deliberately discarded.
                    conn_state(b, data);
                }
                let iter = (*data).addr_iter;
                let dg = if (*data).state >= BIO_CONN_S_CREATE_SOCKET && !iter.is_null() {
                    BIO_ADDRINFO_address(iter)
                } else {
                    ptr::null()
                };
                if dg.is_null() {
                    ret = 0;
                } else {
                    let size = addr::sockaddr_size(dg);
                    let mut n = num;
                    if n == 0 || n > size as c_long {
                        n = size as c_long;
                    }
                    sys::memcpy(ptr, dg.cast(), n as usize);
                    ret = n;
                }
            }
        }
        super::BIO_CTRL_GET_RPOLL_DESCRIPTOR | super::BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
            // SAFETY: `b` and `data` are live.
            unsafe {
                if (*data).state != BIO_CONN_S_OK {
                    conn_state(b, data);
                }
                if (*data).state >= BIO_CONN_S_CREATE_SOCKET {
                    let pd = ptr.cast::<super::BioPollDescriptor>();
                    (*pd).r#type = super::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD;
                    (*pd).value.fd = (*b).num;
                } else {
                    ret = 0;
                }
            }
        }
        super::BIO_C_SET_NBIO => {
            // SAFETY: `data` is live.
            unsafe {
                if num != 0 {
                    (*data).connect_mode |= sys::BIO_SOCK_NONBLOCK;
                } else {
                    (*data).connect_mode &= !sys::BIO_SOCK_NONBLOCK;
                }
                if !(*data).dgram_bio.is_null() {
                    // `BIO_set_nbio(b, n)` is `BIO_ctrl(b, BIO_C_SET_NBIO, n, NULL)`.
                    ret = super::BIO_ctrl(
                        (*data).dgram_bio,
                        super::BIO_C_SET_NBIO,
                        num,
                        ptr::null_mut(),
                    );
                }
            }
        }
        super::BIO_C_SET_CONNECT_MODE => {
            // SAFETY: `data` is live.
            unsafe {
                (*data).connect_mode = num as c_int;
                (*data).tfo_first = c_int::from(num & sys::BIO_SOCK_TFO as c_long != 0);
            }
        }
        super::BIO_C_GET_FD => {
            // SAFETY: `b` is live; the caller passes NULL or an `int *`.
            unsafe {
                if (*b).init != 0 {
                    let ip = ptr.cast::<c_int>();
                    if !ip.is_null() {
                        *ip = (*b).num;
                    }
                    ret = (*b).num as c_long;
                } else {
                    ret = -1;
                }
            }
        }
        super::BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).shutdown } as c_long;
        }
        super::BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` is live.
            unsafe { (*b).shutdown = num as c_int };
        }
        super::BIO_CTRL_PENDING | super::BIO_CTRL_WPENDING => {
            ret = 0;
        }
        super::BIO_CTRL_FLUSH => {
            // Falls through, leaving `ret` at its initialised 1.
        }
        super::BIO_CTRL_DUP => {
            // The duplicate inherits the name, the family and the mode, and the
            // callback, but not the resolved addresses or the descriptor.
            // SAFETY: `b` and `data` are live; `ptr` is the duplicate BIO.
            unsafe {
                let dbio = ptr.cast::<Bio>();
                if !(*data).param_hostname.is_null() {
                    conn_ctrl(
                        dbio,
                        super::BIO_C_SET_CONNECT,
                        0,
                        (*data).param_hostname.cast(),
                    );
                }
                if !(*data).param_service.is_null() {
                    conn_ctrl(
                        dbio,
                        super::BIO_C_SET_CONNECT,
                        1,
                        (*data).param_service.cast(),
                    );
                }
                conn_ctrl(
                    dbio,
                    super::BIO_C_SET_CONNECT,
                    3,
                    ptr::addr_of!((*data).connect_family).cast_mut().cast(),
                );
                conn_ctrl(
                    dbio,
                    super::BIO_C_SET_CONNECT_MODE,
                    (*data).connect_mode as c_long,
                    ptr::null_mut(),
                );
                super::BIO_callback_ctrl(dbio, super::BIO_CTRL_SET_CALLBACK, (*data).info_callback);
            }
        }
        super::BIO_CTRL_SET_CALLBACK => {
            // The callback is set through the callback control; this one only
            // reports that it did nothing.
            ret = 0;
        }
        super::BIO_CTRL_GET_CALLBACK => {
            // SAFETY: the caller passes a `BIO_info_cb **`.
            unsafe { *ptr.cast::<*mut BioInfoCb>() = (*data).info_callback };
        }
        super::BIO_CTRL_EOF => {
            // SAFETY: `b` is live.
            ret = c_long::from(unsafe { (*b).flags } & BIO_FLAGS_IN_EOF != 0);
        }
        // There is no kernel-TLS case in this method for this build profile: the
        // authority was configured `no-ktls`, so `BIO_CTRL_SET_KTLS` and its three
        // siblings fall through to `default` and answer 0.
        _ => {
            ret = 0;
        }
    }
    ret
}

/// `static long conn_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)`
///
/// # Safety
/// `b` must be a live connect BIO; `fp` is the callback the command carries.
unsafe extern "C" fn conn_callback_ctrl(b: *mut Bio, cmd: c_int, fp: *mut BioInfoCb) -> c_long {
    let mut ret: c_long = 1;
    // SAFETY: `b` is a live connect BIO per the caller's contract, so `create`
    // succeeded and stored a `BioConnect` in `ptr`.
    let data = unsafe { data_of(b) };
    if cmd == super::BIO_CTRL_SET_CALLBACK {
        // SAFETY: `data` is live.
        unsafe { (*data).info_callback = fp };
    } else {
        ret = 0;
    }
    ret
}

/* ------------------------------------------------------------------------- */
/* The message batches.                                                     */
/* ------------------------------------------------------------------------- */

/// `static int conn_sendmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
/// size_t num_msgs, uint64_t flags, size_t *msgs_processed)`
///
/// # Safety
/// `bio` must be NULL or a live connect BIO; `msg` must point at `num_msgs`
/// entries of `stride` bytes; `msgs_processed` must be writable.
unsafe extern "C" fn conn_sendmmsg(
    bio: *mut Bio,
    msg: *mut super::BioMsg,
    stride: usize,
    num_msgs: usize,
    flags: u64,
    msgs_processed: *mut usize,
) -> c_int {
    // SAFETY: the caller's out-parameter.
    unsafe { *msgs_processed = 0 };
    if bio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_810) };
        return 0;
    }
    // SAFETY: `bio` is a live connect BIO here: non-NULL per the check above.
    let data = unsafe { data_of(bio) };
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).state } != BIO_CONN_S_OK {
        // SAFETY: `bio` and `data` are live.
        let rc = unsafe { conn_state(bio, data) };
        if rc <= 0 {
            return 0;
        }
    }
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).dgram_bio }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_825) };
        return 0;
    }
    // SAFETY: the inner BIO is live and the message array is the caller's.
    unsafe {
        super::BIO_sendmmsg(
            (*data).dgram_bio,
            msg,
            stride,
            num_msgs,
            flags,
            msgs_processed,
        )
    }
}

/// `static int conn_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride,
/// size_t num_msgs, uint64_t flags, size_t *msgs_processed)`
///
/// # Safety
/// As for [`conn_sendmmsg`].
unsafe extern "C" fn conn_recvmmsg(
    bio: *mut Bio,
    msg: *mut super::BioMsg,
    stride: usize,
    num_msgs: usize,
    flags: u64,
    msgs_processed: *mut usize,
) -> c_int {
    // SAFETY: the caller's out-parameter.
    unsafe { *msgs_processed = 0 };
    if bio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_841) };
        return 0;
    }
    // SAFETY: `bio` is a live connect BIO here: non-NULL per the check above.
    let data = unsafe { data_of(bio) };
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).state } != BIO_CONN_S_OK {
        // SAFETY: `bio` and `data` are live.
        let rc = unsafe { conn_state(bio, data) };
        if rc <= 0 {
            return 0;
        }
    }
    // SAFETY: `data` is live, from the `data_of` above.
    if unsafe { (*data).dgram_bio }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BSS_CONN_856) };
        return 0;
    }
    // SAFETY: the inner BIO is live and the message array is the caller's.
    unsafe {
        super::BIO_recvmmsg(
            (*data).dgram_bio,
            msg,
            stride,
            num_msgs,
            flags,
            msgs_processed,
        )
    }
}

/// `BIO *BIO_new_connect(const char *str)`
///
/// The BIO is freed again when the name cannot be set, so a caller never sees a
/// half-configured connect BIO.
///
/// # Safety
/// `str_` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_connect(str_: *const c_char) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_new` allocates and runs `conn_new`.
        let ret = unsafe { super::BIO_new(BIO_s_connect()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // `BIO_set_conn_hostname(ret, str)`.
        // SAFETY: `ret` is a fresh connect BIO and `str_` is a C string.
        if unsafe { conn_ctrl(ret, super::BIO_C_SET_CONNECT, 0, str_.cast_mut().cast()) } != 0 {
            return ret;
        }
        // SAFETY: `ret` is live and this is the only owner.
        unsafe { super::BIO_free(ret) };
        ptr::null_mut()
    })
}
// `BIO_RR_ACCEPT` is the accept BIO's retry reason; `bss_acpt` owns it.
