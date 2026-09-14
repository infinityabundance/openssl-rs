//! Phase 4 — `BIO_s_accept`, the listening-socket BIO.
//!
//! An accept BIO is a **chain owner**. Its state machine creates the listening
//! socket, and reaching `OK` does not mean "connected": it means an inbound
//! connection was accepted and pushed as this BIO's `next_bio`, where the rest of
//! the chain — a TLS BIO, a buffering BIO — can be built above it.
//!
//!     BEFORE → GET_ADDR → CREATE_SOCKET → LISTEN → ACCEPT → OK
//!                                                    ↑       │
//!                                                    └───────┘  (next accept)
//!
//! ## Behaviours the state machine's shape produces
//!
//! * **`LISTEN` stops there and reports success.** The authority returns 1 from
//!   the machine as soon as the socket is listening, *before* accepting, so a
//!   caller that only wants the bound port gets it without blocking. The next
//!   call resumes at `ACCEPT`.
//! * **`ACCEPT` with a chain already in place is a no-op that succeeds.**
//!   `if (b->next_bio != NULL) { c->state = OK; break; }` — so a second `BIO_do_accept`
//!   on a BIO that already has a connection does nothing rather than accepting a
//!   second one.
//! * **`OK` with no chain goes back to `ACCEPT`.** That is what makes an accept
//!   BIO reusable: once the chain is popped or freed, the next read blocks for a
//!   new connection instead of reporting end-of-stream forever.
//! * **A failed `BIO_listen` closes the socket it created.** So does a failed
//!   `BIO_sock_info`. The descriptor is not left dangling for the caller to
//!   clean up, and `b->num` is reset to `INVALID_SOCKET` with it.
//! * **`BIO_C_GET_ACCEPT` reports the port that was actually bound**, cached from
//!   `BIO_sock_info` after `listen(2)`. That is the only way a caller that asked
//!   for port 0 can learn what the kernel chose.
//!
//! ## TCP Fast Open
//!
//! `BIO_SOCK_TFO` can be recorded in the bind mode, but the authority was
//! configured `no-tfo`, so nothing consumes it: `BIO_listen`'s server-side
//! fast-open branch is compiled out and `BIO_C_SET_TFO` does not exist in
//! `conn_ctrl`. The bit is still observable through `BIO_get_bind_mode`.
//!
//! ## `BIO_C_SET_ACCEPT` takes its argument in two shapes
//!
//! Four of its six sub-commands carry a string or a BIO in `ptr`, and two ignore
//! `ptr` entirely and only look at `num` — and those two turn the corresponding
//! bind mode *off* when `ptr` is NULL. That asymmetry is why the control has two
//! branches rather than one.
//!
//! ## Fault boundaries
//!
//! The authority dereferences `b->ptr` in `acpt_free` and `acpt_ctrl` without
//! checking it. That is not reachable through `BIO_new_accept` (which frees the
//! BIO when the name cannot be set) and is not probed; this module makes the same
//! assumption.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_ACPT_157, BSS_ACPT_203, BSS_ACPT_212, BSS_ACPT_233, BSS_ACPT_236,
};
use crate::runtime::err::{raise_site, raise_site_data, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};

use super::addr::{self, BioAddr};
use super::addr_info::{
    BIO_ADDRINFO_address, BIO_ADDRINFO_family, BIO_ADDRINFO_free, BIO_ADDRINFO_next,
    BIO_ADDRINFO_protocol, BIO_ADDRINFO_socktype, BIO_lookup, BioAddrInfo, BIO_LOOKUP_SERVER,
    BIO_PARSE_PRIO_SERV,
};
use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{
    Bio, BioMethod, BIO_FAMILY_IPANY, BIO_FAMILY_IPV4, BIO_FAMILY_IPV6, BIO_RR_ACCEPT,
    BIO_TYPE_ACCEPT,
};

/// `INVALID_SOCKET`.
const INVALID_SOCKET: c_int = -1;

/// The method name the authority reports for an accept BIO.
const ACCEPT_NAME: &[u8] = b"socket accept\0";

/// `assert(INT_MAX)` — the authority's bound on what `acpt_puts` will write.
const INT_MAX: c_int = c_int::MAX;

/// `ACPT_S_BEFORE` — no parameter has been supplied yet.
const ACPT_S_BEFORE: c_int = 1;
/// `ACPT_S_GET_ADDR` — the name is resolved.
const ACPT_S_GET_ADDR: c_int = 2;
/// `ACPT_S_CREATE_SOCKET` — a listening socket is created.
const ACPT_S_CREATE_SOCKET: c_int = 3;
/// `ACPT_S_LISTEN` — the socket is bound and listening.
const ACPT_S_LISTEN: c_int = 4;
/// `ACPT_S_ACCEPT` — an inbound connection is accepted.
const ACPT_S_ACCEPT: c_int = 5;
/// `ACPT_S_OK` — a connection is in the chain.
const ACPT_S_OK: c_int = 6;

/// The compiled-in method table returned by `BIO_s_accept`.
static ACCEPT_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_ACCEPT,
    name: ACCEPT_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(acpt_write),
    bread: Some(bread_conv),
    bread_old: Some(acpt_read),
    bputs: Some(acpt_puts),
    bgets: None,
    ctrl: Some(acpt_ctrl),
    create: Some(acpt_new),
    destroy: Some(acpt_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `bio_accept_st` — the listening parameters and the two cached addresses.
#[repr(C)]
struct BioAccept {
    /// One of the `ACPT_S_*` states.
    state: c_int,
    /// The family the caller asked for.
    accept_family: c_int,
    /// The `BIO_SOCK_*` option bits `BIO_listen` is called with.
    bind_mode: c_int,
    /// The `BIO_SOCK_*` option bits an *accepted* socket is created with.
    accepted_mode: c_int,
    /// The hostname half of the name, owned.
    param_addr: *mut c_char,
    /// The service half, owned.
    param_serv: *mut c_char,
    /// The listening descriptor.
    accept_sock: c_int,
    /// The resolver's list, owned.
    addr_first: *mut BioAddrInfo,
    /// The element of that list currently being tried.
    addr_iter: *const BioAddrInfo,
    /// The address actually bound, which differs from the request when the port
    /// was 0.
    cache_accepting_addr: BioAddr,
    /// Its hostname as a string, owned, or NULL.
    cache_accepting_name: *mut c_char,
    /// Its service as a string, owned, or NULL.
    cache_accepting_serv: *mut c_char,
    /// The peer address of the accepted connection.
    cache_peer_addr: BioAddr,
    /// Its hostname as a string, owned, or NULL.
    cache_peer_name: *mut c_char,
    /// Its service as a string, owned, or NULL.
    cache_peer_serv: *mut c_char,
    /// The chain an accepted socket is pushed onto, owned when set by the caller.
    bio_chain: *mut Bio,
}

/// The method data of a live accept BIO.
///
/// # Safety
/// `b` must be a live accept BIO whose `create` has succeeded.
unsafe fn data_of(b: *mut Bio) -> *mut BioAccept {
    // SAFETY: `acpt_new` stored a `BioAccept` here and only `acpt_free` removes
    // it.
    unsafe { (*b).ptr.cast::<BioAccept>() }
}

/// Render a two-argument `ERR_raise_data` message the way `_dopr` does, with
/// `<NULL>` for a missing argument.
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

/// Append a C string argument, or `<NULL>` when the pointer is NULL.
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

/* ------------------------------------------------------------------------- */
/* Construction and teardown.                                               */
/* ------------------------------------------------------------------------- */

/// `static BIO_ACCEPT *BIO_ACCEPT_new(void)`
fn accept_new() -> *mut BioAccept {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let ret = CRYPTO_zalloc(core::mem::size_of::<BioAccept>(), ptr::null(), 0).cast::<BioAccept>();
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is a fresh, zeroed allocation.
    unsafe {
        (*ret).accept_family = BIO_FAMILY_IPANY;
        (*ret).accept_sock = INVALID_SOCKET;
    }
    ret
}

/// `static void BIO_ACCEPT_free(BIO_ACCEPT *a)`
///
/// # Safety
/// `a` must be NULL or a block from [`accept_new`] that has not been freed.
unsafe fn accept_free(a: *mut BioAccept) {
    let Some(c) = (unsafe { a.as_mut() }) else {
        return;
    };
    // SAFETY: `c` is live; all six strings and the chain are owned.
    unsafe {
        CRYPTO_free(c.param_addr.cast(), ptr::null(), 0);
        CRYPTO_free(c.param_serv.cast(), ptr::null(), 0);
        BIO_ADDRINFO_free(c.addr_first);
        CRYPTO_free(c.cache_accepting_name.cast(), ptr::null(), 0);
        CRYPTO_free(c.cache_accepting_serv.cast(), ptr::null(), 0);
        CRYPTO_free(c.cache_peer_name.cast(), ptr::null(), 0);
        CRYPTO_free(c.cache_peer_serv.cast(), ptr::null(), 0);
        super::BIO_free(c.bio_chain);
        CRYPTO_free(a.cast(), ptr::null(), 0);
    }
}

/// `const BIO_METHOD *BIO_s_accept(void)`
#[no_mangle]
pub extern "C" fn BIO_s_accept() -> *const BioMethod {
    guard_ffi(ptr::null(), || &ACCEPT_METHOD)
}

/// `static int acpt_new(BIO *bi)`
///
/// Unlike the socket and connect methods, this one sets `shutdown` to 1 itself,
/// because the accept BIO always owns the listening socket it creates.
///
/// # Safety
/// `bi` must be the BIO `BIO_new` is constructing.
unsafe extern "C" fn acpt_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 0;
        (*bi).num = INVALID_SOCKET;
        (*bi).flags = 0;
    }
    let ba = accept_new();
    if ba.is_null() {
        return 0;
    }
    // SAFETY: `bi` and `ba` are live.
    unsafe {
        (*bi).ptr = ba.cast();
        (*ba).state = ACPT_S_BEFORE;
        (*bi).shutdown = 1;
    }
    1
}

/// `static void acpt_close_socket(BIO *bio)`
///
/// The listening socket is shut down *and* closed, because accepting sockets are
/// half-closed by a peer's `connect` otherwise.
///
/// # Safety
/// `bio` must be a live accept BIO.
unsafe fn acpt_close_socket(bio: *mut Bio) {
    let c = unsafe { data_of(bio) };
    // SAFETY: `c` is live.
    if unsafe { (*c).accept_sock } != INVALID_SOCKET {
        // SAFETY: `c` is live and the descriptor is owned.
        unsafe {
            sys::shutdown((*c).accept_sock, sys::SHUT_RDWR);
            // `closesocket` rather than `BIO_closesocket`, exactly as the source.
            sys::close((*c).accept_sock);
            (*c).accept_sock = INVALID_SOCKET;
            (*bio).num = INVALID_SOCKET;
        }
    }
}

/// `static int acpt_free(BIO *a)`
///
/// # Safety
/// `a` must be NULL or a live accept BIO.
unsafe extern "C" fn acpt_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live.
    let data = unsafe { data_of(a) };
    // SAFETY: `a` is live.
    unsafe {
        if (*a).shutdown != 0 {
            acpt_close_socket(a);
            accept_free(data);
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

/// `static int acpt_state(BIO *b, BIO_ACCEPT *c)`
///
/// # Safety
/// `b` must be a live accept BIO and `c` its data.
unsafe fn acpt_state(b: *mut Bio, c: *mut BioAccept) -> c_int {
    let mut bio: *mut Bio = ptr::null_mut();
    let mut s: c_int = -1;
    let mut ret: c_int = -1;
    //
    // The authority has two ways out of this machine and they are not the same:
    // `goto end` skips the cleanup, `goto exit_loop` runs it. Three arms leave by
    // `end` having deliberately parked the socket in the BIO (`s = -1`, or the new
    // socket pushed into the chain), and closing that descriptor as "unused" would
    // break the connection. `RT-BIO-CONN` measured exactly that: the accepted
    // socket was closed on the way out and every subsequent read failed with
    // `EBADF`.
    let mut cleanup = true;

    'outer: loop {
        // SAFETY: `c` is live.
        match unsafe { (*c).state } {
            ACPT_S_BEFORE => {
                // SAFETY: `c` is live.
                if unsafe { (*c).param_addr }.is_null() && unsafe { (*c).param_serv }.is_null() {
                    let msg = fmt_two(
                        "hostname=",
                        ", service=",
                        "",
                        unsafe { (*c).param_addr },
                        unsafe { (*c).param_serv },
                    );
                    // SAFETY: the site is a compile-time constant and `msg` is
                    // NUL-terminated.
                    unsafe { raise_site_data(&BSS_ACPT_157, msg.as_ptr().cast()) };
                    break 'outer;
                }
                // A new bind invalidates every cached name: they describe the
                // previous listening socket, not the next one.
                // SAFETY: `c` is live and all four strings are owned.
                unsafe {
                    CRYPTO_free((*c).cache_accepting_name.cast(), ptr::null(), 0);
                    (*c).cache_accepting_name = ptr::null_mut();
                    CRYPTO_free((*c).cache_accepting_serv.cast(), ptr::null(), 0);
                    (*c).cache_accepting_serv = ptr::null_mut();
                    CRYPTO_free((*c).cache_peer_name.cast(), ptr::null(), 0);
                    (*c).cache_peer_name = ptr::null_mut();
                    CRYPTO_free((*c).cache_peer_serv.cast(), ptr::null(), 0);
                    (*c).cache_peer_serv = ptr::null_mut();
                    (*c).state = ACPT_S_GET_ADDR;
                }
            }
            ACPT_S_GET_ADDR => {
                // The `BIO_FAMILY_IPV6` arm's sibling raise is not compiled on this
                // platform; see the connect method's note.
                let family = match unsafe { (*c).accept_family } {
                    BIO_FAMILY_IPV6 => sys::AF_INET6,
                    BIO_FAMILY_IPV4 => sys::AF_INET,
                    BIO_FAMILY_IPANY => sys::AF_UNSPEC,
                    _ => {
                        // SAFETY: the site is a compile-time constant.
                        unsafe { raise_site(&BSS_ACPT_203) };
                        break 'outer;
                    }
                };
                // SAFETY: `c` is live; the lookup allocates the list, which
                // `BIO_ACCEPT_free` releases. The socket type is always a stream:
                // the authority hard-codes `SOCK_STREAM` here rather than using
                // the bind mode.
                let rc = unsafe {
                    BIO_lookup(
                        (*c).param_addr,
                        (*c).param_serv,
                        BIO_LOOKUP_SERVER,
                        family,
                        sys::SOCK_STREAM,
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
                        raise_site(&BSS_ACPT_212);
                        break 'outer;
                    }
                    (*c).addr_iter = (*c).addr_first;
                    (*c).state = ACPT_S_CREATE_SOCKET;
                }
            }
            ACPT_S_CREATE_SOCKET => {
                // SAFETY: `ERR_set_mark` manipulates the queue.
                crate::runtime::err::ERR_set_mark();
                let iter = unsafe { (*c).addr_iter };
                // SAFETY: `iter` is a live node.
                s = super::bio_sock2::BIO_socket(
                    unsafe { BIO_ADDRINFO_family(iter) },
                    unsafe { BIO_ADDRINFO_socktype(iter) },
                    unsafe { BIO_ADDRINFO_protocol(iter) },
                    0,
                );
                if s == INVALID_SOCKET {
                    // SAFETY: `iter` is a live node.
                    let next = unsafe { BIO_ADDRINFO_next(iter) };
                    if !next.is_null() {
                        // SAFETY: `c` is live.
                        unsafe { (*c).addr_iter = next };
                        // SAFETY: `ERR_pop_to_mark` manipulates the queue.
                        crate::runtime::err::ERR_pop_to_mark();
                        continue 'outer;
                    }
                    // SAFETY: `ERR_clear_last_mark` manipulates the queue.
                    crate::runtime::err::ERR_clear_last_mark();
                    let msg = fmt_two(
                        "calling socket(",
                        ", ",
                        ")",
                        unsafe { (*c).param_addr },
                        unsafe { (*c).param_serv },
                    );
                    // SAFETY: the sites are compile-time constants and `msg` is
                    // NUL-terminated.
                    unsafe {
                        raise_site_dynamic_data(&BSS_ACPT_233, sys::errno(), msg.as_ptr().cast());
                        raise_site(&BSS_ACPT_236);
                    }
                    break 'outer;
                }
                // SAFETY: `c` and `b` are live.
                unsafe {
                    (*c).accept_sock = s;
                    (*b).num = s;
                    (*c).state = ACPT_S_LISTEN;
                }
                s = -1;
            }
            ACPT_S_LISTEN => {
                let iter = unsafe { (*c).addr_iter };
                // SAFETY: `c` is live; `BIO_listen` reads the address and the
                // bind mode.
                let ok = unsafe {
                    super::bio_sock2::BIO_listen(
                        (*c).accept_sock,
                        BIO_ADDRINFO_address(iter),
                        (*c).bind_mode,
                    )
                };
                if ok == 0 {
                    // SAFETY: `c` and `b` are live.
                    unsafe {
                        super::bss_sock::BIO_closesocket((*c).accept_sock);
                        (*c).accept_sock = INVALID_SOCKET;
                        (*b).num = INVALID_SOCKET;
                    }
                    break 'outer;
                }
                // The bound address is read back so a caller that asked for port 0
                // can learn what the kernel chose.
                // SAFETY: `c` is live.
                let info = unsafe {
                    let mut info = super::bio_sock2::SockInfoUnion {
                        addr: ptr::addr_of_mut!((*c).cache_accepting_addr),
                    };
                    super::bio_sock2::BIO_sock_info(
                        (*c).accept_sock,
                        super::bio_sock2::BIO_SOCK_INFO_ADDRESS,
                        &mut info,
                    )
                };
                if info == 0 {
                    // SAFETY: `c` and `b` are live.
                    unsafe {
                        super::bss_sock::BIO_closesocket((*c).accept_sock);
                        (*c).accept_sock = INVALID_SOCKET;
                        (*b).num = INVALID_SOCKET;
                    }
                    break 'outer;
                }
                // SAFETY: `c` is live and the two slots are owned.
                unsafe {
                    CRYPTO_free((*c).cache_accepting_name.cast(), ptr::null(), 0);
                    CRYPTO_free((*c).cache_accepting_serv.cast(), ptr::null(), 0);
                    let a = ptr::addr_of!((*c).cache_accepting_addr);
                    (*c).cache_accepting_name = addr::BIO_ADDR_hostname_string(a, 1);
                    (*c).cache_accepting_serv = addr::BIO_ADDR_service_string(a, 1);
                    (*c).state = ACPT_S_ACCEPT;
                }
                s = -1;
                ret = 1;
                cleanup = false;
                break 'outer;
            }
            ACPT_S_ACCEPT => {
                // A chain is already in place, so there is nothing to accept.
                // SAFETY: `b` and `c` are live.
                if !unsafe { (*b).next_bio }.is_null() {
                    // SAFETY: `c` is live.
                    unsafe { (*c).state = ACPT_S_OK };
                    continue 'outer;
                }
                clear_retry_flags(b);
                // SAFETY: `b` and `c` are live.
                unsafe {
                    (*b).retry_reason = 0;
                    CRYPTO_free((*c).cache_peer_name.cast(), ptr::null(), 0);
                    (*c).cache_peer_name = ptr::null_mut();
                    CRYPTO_free((*c).cache_peer_serv.cast(), ptr::null(), 0);
                    (*c).cache_peer_serv = ptr::null_mut();
                    s = super::bio_sock2::BIO_accept_ex(
                        (*c).accept_sock,
                        ptr::addr_of_mut!((*c).cache_peer_addr),
                        (*c).accepted_mode,
                    );
                }
                if s < 0 {
                    if super::bss_sock::BIO_sock_should_retry(s) != 0 {
                        set_retry_special(b);
                        // SAFETY: `b` is live.
                        unsafe { (*b).retry_reason = BIO_RR_ACCEPT };
                        break 'outer;
                    }
                    ret = s;
                    break 'outer;
                }
                // SAFETY: the descriptor is live and the new BIO owns it.
                bio = unsafe { super::bss_sock::BIO_new_socket(s, super::BIO_CLOSE) };
                if bio.is_null() {
                    break 'outer;
                }
                // The accepted socket inherits the listening BIO's callbacks, so a
                // caller that set them once does not have to set them again.
                // SAFETY: both BIOs are live.
                unsafe {
                    let cb_ex = super::BIO_get_callback_ex(b);
                    super::BIO_set_callback_ex(bio, cb_ex);
                    let cb = super::BIO_get_callback(b);
                    super::BIO_set_callback(bio, cb);
                    let arg = super::BIO_get_callback_arg(b);
                    super::BIO_set_callback_arg(bio, arg);
                }
                // A caller-supplied chain is duplicated and the new socket put at
                // its end, so each connection gets its own copy of the chain.
                // SAFETY: `c` is live.
                if !unsafe { (*c).bio_chain }.is_null() {
                    // SAFETY: the chain is live.
                    let dbio = unsafe { super::BIO_dup_chain((*c).bio_chain) };
                    if dbio.is_null() {
                        break 'outer;
                    }
                    // SAFETY: both BIOs are live.
                    if unsafe { super::BIO_push(dbio, bio) }.is_null() {
                        break 'outer;
                    }
                    bio = dbio;
                }
                // SAFETY: `b` and `bio` are live.
                if unsafe { super::BIO_push(b, bio) }.is_null() {
                    break 'outer;
                }
                bio = ptr::null_mut();
                // SAFETY: `c` is live and the two slots are owned.
                unsafe {
                    let a = ptr::addr_of!((*c).cache_peer_addr);
                    (*c).cache_peer_name = addr::BIO_ADDR_hostname_string(a, 1);
                    (*c).cache_peer_serv = addr::BIO_ADDR_service_string(a, 1);
                    (*c).state = ACPT_S_OK;
                }
                ret = 1;
                cleanup = false;
                break 'outer;
            }
            ACPT_S_OK => {
                // The chain was handed back to the caller, so the next call
                // accepts again.
                // SAFETY: `b` and `c` are live.
                if unsafe { (*b).next_bio }.is_null() {
                    // SAFETY: `c` is live.
                    unsafe { (*c).state = ACPT_S_ACCEPT };
                    continue 'outer;
                }
                ret = 1;
                cleanup = false;
                break 'outer;
            }
            _ => {
                ret = 0;
                cleanup = false;
                break 'outer;
            }
        }
    }

    if cleanup {
        // SAFETY: `bio` is a live BIO if it was created, and `s` a live descriptor
        // if it was accepted; at most one of the two is non-empty on these paths.
        unsafe {
            if !bio.is_null() {
                super::BIO_free(bio);
            } else if s >= 0 {
                super::bss_sock::BIO_closesocket(s);
            }
        }
    }
    ret
}

/// `BIO_set_retry_special(b)`.
fn set_retry_special(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe {
        (*b).flags |= super::BIO_FLAGS_IO_SPECIAL | super::BIO_FLAGS_SHOULD_RETRY;
    }
}

/// `BIO_clear_retry_flags(b)`.
fn clear_retry_flags(b: *mut Bio) {
    // SAFETY: `b` is live.
    unsafe {
        (*b).flags &= !(super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY);
    }
}

/* ------------------------------------------------------------------------- */
/* Read and write.                                                          */
/* ------------------------------------------------------------------------- */

/// `static int acpt_read(BIO *b, char *out, int outl)`
///
/// The first read on an unconnected accept BIO **blocks until a peer connects**,
/// because the state machine runs until the chain exists. The retry state is
/// cleared on entry and copied from the chain's head on the way out, so a
/// non-blocking caller sees the head BIO's retry flags, not the accept BIO's.
///
/// # Safety
/// `b` must be a live accept BIO; `out` must be NULL or writable for `outl`
/// bytes.
unsafe extern "C" fn acpt_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    clear_retry_flags(b);
    let data = unsafe { data_of(b) };
    loop {
        // SAFETY: `b` is live.
        if !unsafe { (*b).next_bio }.is_null() {
            break;
        }
        // SAFETY: `b` and `data` are live.
        let rc = unsafe { acpt_state(b, data) };
        if rc <= 0 {
            return rc;
        }
    }
    // SAFETY: the chain head is live and `out` is writable per the contract.
    let ret = unsafe { super::BIO_read((*b).next_bio, out.cast(), outl) };
    // SAFETY: `b` is live.
    unsafe { super::BIO_copy_next_retry(b) };
    ret
}

/// `static int acpt_write(BIO *b, const char *in, int inl)`
///
/// # Safety
/// `b` must be a live accept BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn acpt_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    clear_retry_flags(b);
    let data = unsafe { data_of(b) };
    loop {
        // SAFETY: `b` is live.
        if !unsafe { (*b).next_bio }.is_null() {
            break;
        }
        // SAFETY: `b` and `data` are live.
        let rc = unsafe { acpt_state(b, data) };
        if rc <= 0 {
            return rc;
        }
    }
    // SAFETY: the chain head is live and `in_` is readable per the contract.
    let ret = unsafe { super::BIO_write((*b).next_bio, in_.cast(), inl) };
    // SAFETY: `b` is live.
    unsafe { super::BIO_copy_next_retry(b) };
    ret
}

/// `static int acpt_puts(BIO *bp, const char *str)`
///
/// # Safety
/// `bp` must be a live accept BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn acpt_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `str_` is NUL-terminated per the method contract.
    let n = unsafe { sys::strlen(str_) };
    if n > INT_MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `str_` is valid for `n` bytes.
    unsafe { acpt_write(bp, str_, n as c_int) }
}

/* ------------------------------------------------------------------------- */
/* acpt_ctrl.                                                               */
/* ------------------------------------------------------------------------- */

/// `static long acpt_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live accept BIO and `ptr` must be appropriate for `cmd`.
unsafe extern "C" fn acpt_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    let data = unsafe { data_of(b) };

    match cmd {
        super::BIO_CTRL_RESET => {
            ret = 0;
            // SAFETY: `b` and `data` are live.
            unsafe {
                (*data).state = ACPT_S_BEFORE;
                acpt_close_socket(b);
                BIO_ADDRINFO_free((*data).addr_first);
                (*data).addr_first = ptr::null_mut();
                (*data).addr_iter = ptr::null();
                (*b).flags = 0;
            }
        }
        super::BIO_C_DO_STATE_MACHINE => {
            // Unlike the connect method, this one always runs the machine: there
            // is no "already done" short circuit, because accepting again is a
            // legitimate request.
            // SAFETY: `b` and `data` are live.
            ret = unsafe { acpt_state(b, data) } as c_long;
        }
        super::BIO_C_SET_ACCEPT => {
            if !ptr.is_null() {
                if num == 0 {
                    // A `host:service` spec is parsed with service priority, and
                    // the service is only replaced when the spec carried one.
                    // SAFETY: `data` is live; `ptr` is a NUL-terminated string.
                    unsafe {
                        let hold = (*data).param_serv;
                        CRYPTO_free((*data).param_addr.cast(), ptr::null(), 0);
                        (*data).param_addr = ptr::null_mut();
                        let rc = super::addr_info::BIO_parse_hostserv(
                            ptr.cast(),
                            ptr::addr_of_mut!((*data).param_addr),
                            ptr::addr_of_mut!((*data).param_serv),
                            BIO_PARSE_PRIO_SERV,
                        );
                        ret = rc as c_long;
                        if hold != (*data).param_serv {
                            CRYPTO_free(hold.cast(), ptr::null(), 0);
                        }
                        if ret > 0 {
                            (*b).init = 1;
                        }
                    }
                } else if num == 1 {
                    // SAFETY: `data` is live; `ptr` is a NUL-terminated string.
                    unsafe {
                        CRYPTO_free((*data).param_serv.cast(), ptr::null(), 0);
                        (*data).param_serv = CRYPTO_strdup(ptr.cast(), ptr::null(), 0);
                        if (*data).param_serv.is_null() {
                            ret = 0;
                        } else {
                            (*b).init = 1;
                        }
                    }
                } else if num == 2 {
                    // SAFETY: `data` is live.
                    unsafe { (*data).bind_mode |= sys::BIO_SOCK_NONBLOCK };
                } else if num == 3 {
                    // SAFETY: `data` is live; `ptr` is a `BIO *` the caller lends.
                    unsafe {
                        super::BIO_free((*data).bio_chain);
                        (*data).bio_chain = ptr.cast::<Bio>();
                    }
                } else if num == 4 {
                    // SAFETY: the caller passes an `int *` through `BIO_int_ctrl`.
                    unsafe { (*data).accept_family = *ptr.cast::<c_int>() };
                } else if num == 5 {
                    // The bit is recorded and nothing consults it: the authority was
                    // configured `no-tfo`, so `BIO_listen`'s server-side fast-open
                    // branch does not exist. Recorded rather than dropped, because
                    // `BIO_get_bind_mode` reports it back.
                    // SAFETY: `data` is live.
                    unsafe { (*data).bind_mode |= sys::BIO_SOCK_TFO };
                }
            } else if num == 2 {
                // SAFETY: `data` is live.
                unsafe { (*data).bind_mode &= !sys::BIO_SOCK_NONBLOCK };
            } else if num == 5 {
                // SAFETY: `data` is live.
                unsafe { (*data).bind_mode &= !sys::BIO_SOCK_TFO };
            }
        }
        super::BIO_C_SET_NBIO => {
            // The *accepted* socket's mode, not the listening socket's.
            // SAFETY: `data` is live.
            unsafe {
                if num != 0 {
                    (*data).accepted_mode |= sys::BIO_SOCK_NONBLOCK;
                } else {
                    (*data).accepted_mode &= !sys::BIO_SOCK_NONBLOCK;
                }
            }
        }
        super::BIO_C_SET_FD => {
            // The caller hands over a listening socket it already made, so the
            // machine starts at `ACCEPT` with no name and no resolver list.
            // SAFETY: `b` and `data` are live; `ptr` is an `int *`.
            unsafe {
                (*b).num = *ptr.cast::<c_int>();
                (*data).accept_sock = (*b).num;
                (*data).state = ACPT_S_ACCEPT;
                (*b).shutdown = num as c_int;
                (*b).init = 1;
            }
        }
        super::BIO_C_GET_FD => {
            // SAFETY: `b` and `data` are live; `ptr` is NULL or an `int *`.
            unsafe {
                if (*b).init != 0 {
                    let ip = ptr.cast::<c_int>();
                    if !ip.is_null() {
                        *ip = (*data).accept_sock;
                    }
                    ret = (*data).accept_sock as c_long;
                } else {
                    ret = -1;
                }
            }
        }
        super::BIO_C_GET_ACCEPT => {
            // SAFETY: `b` and `data` are live.
            unsafe {
                if (*b).init == 0 {
                    ret = -1;
                } else if num == 0 && !ptr.is_null() {
                    *ptr.cast::<*mut c_char>() = (*data).cache_accepting_name;
                } else if num == 1 && !ptr.is_null() {
                    *ptr.cast::<*mut c_char>() = (*data).cache_accepting_serv;
                } else if num == 2 && !ptr.is_null() {
                    *ptr.cast::<*mut c_char>() = (*data).cache_peer_name;
                } else if num == 3 && !ptr.is_null() {
                    *ptr.cast::<*mut c_char>() = (*data).cache_peer_serv;
                } else if num == 4 {
                    let iter = (*data).addr_iter;
                    let family = if iter.is_null() {
                        0
                    } else {
                        BIO_ADDRINFO_family(iter)
                    };
                    ret = match family {
                        sys::AF_INET6 => BIO_FAMILY_IPV6 as c_long,
                        sys::AF_INET => BIO_FAMILY_IPV4 as c_long,
                        0 => (*data).accept_family as c_long,
                        _ => -1,
                    };
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
        super::BIO_C_SET_BIND_MODE => {
            // SAFETY: `data` is live. Note this *replaces* the mode rather than
            // setting a bit, unlike `BIO_C_SET_ACCEPT`'s two flag sub-commands.
            unsafe { (*data).bind_mode = num as c_int };
        }
        super::BIO_C_GET_BIND_MODE => {
            // SAFETY: `data` is live.
            ret = unsafe { (*data).bind_mode } as c_long;
        }
        super::BIO_CTRL_DUP => {
            // Falls through; the accept method's duplicate does nothing, because
            // the listening socket cannot be shared.
        }
        super::BIO_CTRL_EOF => {
            // Unlike the socket method's flag test, this one forwards to the
            // chain, and an empty chain reports "not at end of stream".
            // SAFETY: `b` is live.
            unsafe {
                if (*b).next_bio.is_null() {
                    ret = 0;
                } else {
                    ret = super::BIO_ctrl((*b).next_bio, cmd, num, ptr);
                }
            }
        }
        _ => {
            ret = 0;
        }
    }
    ret
}

/// `BIO *BIO_new_accept(const char *str)`
///
/// # Safety
/// `str_` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_accept(str_: *const c_char) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_new` allocates and runs `acpt_new`.
        let ret = unsafe { super::BIO_new(BIO_s_accept()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // `BIO_set_accept_name(ret, str)`.
        // SAFETY: `ret` is a fresh accept BIO and `str_` is a C string.
        if unsafe { acpt_ctrl(ret, super::BIO_C_SET_ACCEPT, 0, str_.cast_mut().cast()) } > 0 {
            return ret;
        }
        // SAFETY: `ret` is live and this is the only owner.
        unsafe { super::BIO_free(ret) };
        ptr::null_mut()
    })
}
