//! Phase 4 — `BIO_s_datagram`, the kernel datagram socket BIO.
//!
//! This is `crypto/bio/bss_dgram.c` minus its SCTP half, which this build profile
//! excludes: `OPENSSL_NO_SCTP` is defined, so the authority's
//! `BIO_s_datagram_sctp`, `BIO_new_dgram_sctp`, `BIO_dgram_is_sctp` and
//! `BIO_dgram_sctp_*` are all recorded `excluded_by_build_profile` in the atlas
//! and there is nothing to reconstruct for them.
//!
//! ## What the method actually owns
//!
//! Unlike `BIO_s_socket`, a datagram BIO carries a **peer address**, a **local
//! address** and a small amount of protocol state: whether the socket is
//! connected, the last socket error, a cached path MTU, a peek mode, a
//! destination-address-enable flag and, for DTLS, two timers. Almost every
//! control below is a question about that state rather than about the socket.
//!
//! ## Three behaviours that are easy to get backwards
//!
//! * `BIO_CTRL_DGRAM_MTU_DISCOVER` returns **the result of `setsockopt(2)`** —
//!   zero on success — not a success boolean, so a caller testing it for
//!   truthiness reads the opposite of a caller testing `< 0`.
//! * `BIO_CTRL_DGRAM_QUERY_MTU` subtracts the header overhead from the kernel's
//!   value, caches the result, and answers `0` — not `-1` — for a family that is
//!   neither IPv4 nor IPv6.
//! * `BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE` reports success when the requested
//!   state is *already* the state, because the authority leaves `ret` at its
//!   initial `1` and only clears it when `setsockopt(2)` fails.
//!
//! ## The local-address mechanism
//!
//! On this platform the authority compiles the `SUPPORT_LOCAL_ADDR` block
//! (`IP_PKTINFO` and `IPV6_RECVPKTINFO` are both available, and this is not AIX),
//! so `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP` is `1`, the batch paths pack
//! `IP_PKTINFO`/`IPV6_PKTINFO` ancillary data on send and decode it on receive,
//! and a receive whose control data holds no matching record **clears** the
//! caller's address rather than failing the transfer. All of that is reproduced.
//!
//! ## Ancillary data is byte-addressed
//!
//! The authority's control buffers are `unsigned char` arrays that it casts to
//! `struct cmsghdr *`. That cast is only incidentally aligned and C tolerates
//! it. Here every record is walked through byte pointers and its header read
//! with an unaligned load ([`sys::cmsg_hdr`]), so the same buffer contents are
//! interpreted without a misaligned dereference.
//!
//! ## Fault boundaries
//!
//! `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE` writes through its pointer without
//! checking it, so a NULL argument faults in the authority. That is recorded as
//! a divergence (`docs/SECURITY_DIVERGENCE_POLICY.md`); here the arm is total and
//! simply does not write. The authority's other datagram faults — a NULL `ptr`
//! to `SET_PEER`/`CONNECT`/`SET_CONNECTED`, a NULL `int *` to `BIO_C_SET_FD`, a
//! NULL `timeval *` to the timeout controls — are not probed, and this module
//! makes the same assumption the authority does for each of them.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BSS_DGRAM_1231, BSS_DGRAM_1301, BSS_DGRAM_1307, BSS_DGRAM_1402, BSS_DGRAM_1410, BSS_DGRAM_1420,
    BSS_DGRAM_1604, BSS_DGRAM_1613, BSS_DGRAM_337, BSS_DGRAM_366, BSS_DGRAM_414, BSS_DGRAM_650,
    BSS_DGRAM_659, BSS_DGRAM_806, BSS_DGRAM_833, BSS_DGRAM_836, BSS_DGRAM_862, BSS_DGRAM_889,
    BSS_DGRAM_892, BSS_DGRAM_939, BSS_DGRAM_961,
};
use crate::runtime::err::{
    raise_site, raise_site_data, raise_site_dynamic, raise_site_dynamic_data,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::addr::{self, BioAddr};
use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{
    Bio, BioMethod, BIO_DGRAM_CAP_HANDLES_DST_ADDR, BIO_DGRAM_CAP_HANDLES_SRC_ADDR,
    BIO_DGRAM_CAP_PROVIDES_DST_ADDR, BIO_DGRAM_CAP_PROVIDES_SRC_ADDR, BIO_FLAGS_READ,
    BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_TYPE_DGRAM,
};

/// The method name the authority reports for a datagram BIO.
const DGRAM_NAME: &[u8] = b"datagram socket\0";

/// `assert(INT_MAX)` — the authority's bound on what `dgram_puts` will write.
const INT_MAX: c_int = c_int::MAX;

/// The compiled-in method table returned by `BIO_s_datagram`.
static DGRAM_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_DGRAM,
    name: DGRAM_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(dgram_write),
    bread: Some(bread_conv),
    bread_old: Some(dgram_read),
    bputs: Some(dgram_puts),
    bgets: None,
    ctrl: Some(dgram_ctrl),
    create: Some(dgram_new),
    destroy: Some(dgram_free),
    callback_ctrl: None,
    sendmmsg: Some(dgram_sendmmsg),
    recvmmsg: Some(dgram_recvmmsg),
};

/// `BIO_MAX_MSGS_PER_CALL` — the authority's cap on one `sendmmsg`/`recvmmsg`
/// batch. It exists because each message is translated into a stack-allocated
/// `struct mmsghdr`, `struct iovec` and control buffer, so the batch size is
/// what bounds the stack, and a caller with more messages is expected to call
/// again.
const BIO_MAX_MSGS_PER_CALL: usize = 64;

/// The larger of two `usize` values, in a `const` context.
const fn max_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// `BIO_CMSG_ALLOC_LEN` — the control buffer each translated message gets.
///
/// The authority's definition is `max(CMSG_SPACE(sizeof(in6_pktinfo)),
/// CMSG_SPACE(sizeof(in_pktinfo)), CMSG_SPACE(sizeof(in_addr)))`: the largest
/// ancillary record any family it might use can produce. It is computed here
/// from those same three sizes rather than written down, so the value cannot
/// drift away from the record layout, and a unit test pins both.
const BIO_CMSG_ALLOC_LEN: usize = max_usize(
    sys::cmsg_space(core::mem::size_of::<sys::In6PktInfo>()),
    max_usize(
        sys::cmsg_space(core::mem::size_of::<sys::InPktInfo>()),
        sys::cmsg_space(core::mem::size_of::<sys::InAddr>()),
    ),
);

/* ------------------------------------------------------------------------- */
/* OSSL_TIME, the subset the two datagram timers need.                       */
/* ------------------------------------------------------------------------- */

/// `OSSL_TIME` — nanoseconds since the Unix epoch, as `include/internal/time.h`
/// defines it.
///
/// Only the operations the three timer paths use are provided. The rest of the
/// OSSL_TIME API belongs to a later stratum; this is an internal helper, not an
/// export, and it exists so the timers can be reconstructed faithfully rather
/// than approximated with `std::time`.
#[derive(Clone, Copy)]
struct OsslTime(u64);

/// `OSSL_TIME_SECOND`.
const OSSL_TIME_SECOND: u64 = 1_000_000_000;
/// `OSSL_TIME_MS`.
const OSSL_TIME_MS: u64 = OSSL_TIME_SECOND / 1000;
/// `OSSL_TIME_US`.
const OSSL_TIME_US: u64 = OSSL_TIME_MS / 1000;

impl OsslTime {
    /// `ossl_time_zero()`.
    const ZERO: Self = Self(0);

    /// `ossl_ticks2time(t)`.
    const fn ticks(t: u64) -> Self {
        Self(t)
    }

    /// `ossl_time_is_zero(t)`.
    fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// `ossl_time_subtract(a, b)` — saturating at zero, as `safe_sub_time` does.
    fn subtract(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// `ossl_time_compare(a, b)`.
    fn compare(self, other: Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }

    /// `ossl_time_from_timeval(tv)`.
    ///
    /// A negative `tv_sec` is `ossl_time_zero()`. The authority guards that with
    /// `#ifndef __DJGPP__`; DJGPP is not this platform, so the guard is always
    /// compiled in and is reproduced without a conditional. Both multiplications
    /// are wrapping, as the authority's are.
    fn from_timeval(tv: sys::Timeval) -> Self {
        if tv.tv_sec < 0 {
            return Self::ZERO;
        }
        let secs = (tv.tv_sec as u64).wrapping_mul(OSSL_TIME_SECOND);
        let usecs = (tv.tv_usec as u64).wrapping_mul(OSSL_TIME_US);
        Self(secs.wrapping_add(usecs))
    }

    /// `ossl_time_to_timeval(t)`.
    ///
    /// Rounds nanoseconds up to the next microsecond, so a non-zero time can
    /// never become a zero `timeval`; on overflow it becomes
    /// `ossl_time_infinite()`, as the authority's `safe_add_time` does.
    fn to_timeval(self) -> sys::Timeval {
        let rounded = self.0.checked_add(OSSL_TIME_US - 1).unwrap_or(u64::MAX);
        sys::Timeval {
            tv_sec: (rounded / OSSL_TIME_SECOND) as c_long,
            tv_usec: ((rounded % OSSL_TIME_SECOND) / OSSL_TIME_US) as c_long,
        }
    }
}

/// `ossl_time_now()` — the wall clock, in nanoseconds since the epoch.
///
/// The authority calls `gettimeofday(2)` and returns `ossl_time_zero()` when it
/// fails. `crypto/time.c` is not a Phase 4 file, so a failure arm here has no
/// recorded raise site; a `gettimeofday` failure is not reachable with a valid
/// process clock, and the value returned on failure is the authority's.
fn ossl_time_now() -> OsslTime {
    let mut tv = sys::Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a live local and the timezone argument is NULL.
    if unsafe { sys::gettimeofday(&mut tv, ptr::null_mut()) } < 0 {
        return OsslTime::ZERO;
    }
    if tv.tv_sec <= 0 {
        return if tv.tv_usec <= 0 {
            OsslTime::ZERO
        } else {
            OsslTime::ticks((tv.tv_usec as u64).wrapping_mul(OSSL_TIME_US))
        };
    }
    let micros = (tv.tv_sec as u64)
        .wrapping_mul(1_000_000)
        .wrapping_add(tv.tv_usec as u64);
    OsslTime::ticks(micros.wrapping_mul(OSSL_TIME_US))
}

/* ------------------------------------------------------------------------- */
/* The method's private data.                                               */
/* ------------------------------------------------------------------------- */

/// `bio_dgram_data` — everything the method keeps beyond the socket itself.
///
/// Both timers are **absolute** wall-clock times, because `ossl_time_now()` is
/// the epoch clock and `BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT` stores whatever
/// `timeval` it is handed. A caller therefore passes a deadline, not a duration;
/// `dgram_adjust_rcv_timeout` is where that becomes visible.
#[repr(C)]
struct BioDgramData {
    /// The peer address, used for `sendto` while the socket is unconnected.
    peer: BioAddr,
    /// The local address, refreshed from the socket by `BIO_C_SET_FD`.
    local_addr: BioAddr,
    /// Whether the socket has a peer.
    connected: c_uint,
    /// The last socket error a read or write saw, for the timer-expiry controls.
    last_error: c_uint,
    /// The cached path MTU.
    mtu: c_uint,
    /// The DTLS handshake deadline, or zero when no timer is armed.
    next_timeout: OsslTime,
    /// The socket's own `SO_RCVTIMEO`, saved so a read can restore it.
    socket_timeout: OsslTime,
    /// Whether reads use `MSG_PEEK`.
    peekmode: c_uint,
    /// Whether destination-address reception is enabled on the socket.
    local_addr_enabled: c_char,
}

/// The method data of a live datagram BIO.
///
/// # Safety
/// `b` must be a live datagram BIO whose `create` has already run.
unsafe fn data_of(b: *mut Bio) -> *mut BioDgramData {
    // SAFETY: `dgram_new` stored a `BioDgramData` here and only `dgram_free`
    // removes it.
    unsafe { (*b).ptr.cast::<BioDgramData>() }
}

/* ------------------------------------------------------------------------- */
/* Construction and teardown.                                               */
/* ------------------------------------------------------------------------- */

/// `const BIO_METHOD *BIO_s_datagram(void)`
#[no_mangle]
pub extern "C" fn BIO_s_datagram() -> *const BioMethod {
    guard_ffi(ptr::null(), || &DGRAM_METHOD)
}

/// `BIO *BIO_new_dgram(int fd, int close_flag)`
///
/// As for `BIO_new_socket`, the authority goes through `BIO_set_fd` rather than
/// assigning the fields, and that is what sets `init`, closes any previous
/// descriptor, refreshes the local address and detects whether the socket is
/// already connected. Assigning directly would leave an uninitialised BIO.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_new` allocates and runs `dgram_new`.
        let bio = unsafe { super::BIO_new(BIO_s_datagram()) };
        if bio.is_null() {
            return ptr::null_mut();
        }
        // `BIO_set_fd(b, fd, c)` is `BIO_int_ctrl(b, BIO_C_SET_FD, c, fd)`, which
        // passes the descriptor by address as the control requires.
        // SAFETY: `bio` is a fresh datagram BIO.
        unsafe { super::BIO_int_ctrl(bio, super::BIO_C_SET_FD, close_flag as c_long, fd) };
        bio
    })
}

/// `static int dgram_new(BIO *bi)`
///
/// # Safety
/// `bi` must be the BIO `BIO_new` is constructing.
unsafe extern "C" fn dgram_new(bi: *mut Bio) -> c_int {
    // SAFETY: `CRYPTO_zalloc` returns nulled memory of the requested size.
    let data = CRYPTO_zalloc(core::mem::size_of::<BioDgramData>(), ptr::null(), 0);
    if data.is_null() {
        return 0;
    }
    // SAFETY: `bi` is live and `data` is a fresh block of exactly this type.
    unsafe {
        (*bi).ptr = data;
    }
    1
}

/// `static int dgram_free(BIO *a)`
///
/// # Safety
/// `a` must be NULL or a live datagram BIO.
unsafe extern "C" fn dgram_free(a: *mut Bio) -> c_int {
    let Some(b) = (unsafe { a.as_mut() }) else {
        return 0;
    };
    // SAFETY: `b` is live.
    if unsafe { dgram_clear(b) } == 0 {
        return 0;
    }
    // SAFETY: `dgram_new` allocated this block and `destroy` runs once.
    unsafe {
        CRYPTO_free(b.ptr, ptr::null(), 0);
    }
    1
}

/// `static int dgram_clear(BIO *a)`
///
/// Closes the descriptor when the BIO owns it and resets `init` and `flags`. The
/// `flags` reset is the reason a cleared datagram BIO reports no retry state —
/// `BIO_new_dgram` on an existing BIO therefore starts from a clean slate.
///
/// # Safety
/// `a` must be NULL or a live datagram BIO.
unsafe extern "C" fn dgram_clear(a: *mut Bio) -> c_int {
    let Some(b) = (unsafe { a.as_mut() }) else {
        return 0;
    };
    if b.shutdown != 0 {
        if b.init != 0 {
            // SAFETY: the BIO owns the descriptor.
            super::bss_sock::BIO_closesocket(b.num);
        }
        b.init = 0;
        b.flags = 0;
    }
    1
}

/* ------------------------------------------------------------------------- */
/* The receive-timeout bracket and the local address.                        */
/* ------------------------------------------------------------------------- */

/// `static void dgram_adjust_rcv_timeout(BIO *b)`
///
/// When a DTLS timer is armed, `SO_RCVTIMEO` is shortened to the time left
/// before it fires — never lengthened, and never below one microsecond — so a
/// blocking read returns in time for the caller to run the timer. The socket's
/// own timeout is read and remembered rather than assumed, and it is read
/// **before** the deadline is compared against the clock, as in the authority.
///
/// # Safety
/// `b` must be a live datagram BIO.
unsafe fn dgram_adjust_rcv_timeout(b: *mut Bio) {
    let data = unsafe { data_of(b) };
    if unsafe { (*data).next_timeout }.is_zero() {
        return;
    }
    let sock = unsafe { (*b).num };
    let mut tv = sys::Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut sz = core::mem::size_of::<sys::Timeval>() as sys::SockLen;
    // SAFETY: `sock` is live; `tv`/`sz` are live locals.
    if unsafe {
        sys::getsockopt(
            sock,
            sys::SOL_SOCKET,
            sys::SO_RCVTIMEO,
            ptr::from_mut(&mut tv).cast(),
            &mut sz,
        )
    } < 0
    {
        // SAFETY: the site and message are compile-time constants.
        unsafe {
            raise_site_dynamic_data(
                &BSS_DGRAM_337,
                sys::errno(),
                c"calling getsockopt()".as_ptr(),
            )
        };
    } else {
        // SAFETY: `data` is live.
        unsafe { (*data).socket_timeout = OsslTime::from_timeval(tv) };
    }

    let next = unsafe { (*data).next_timeout };
    let mut timeleft = next.subtract(ossl_time_now());
    if timeleft.compare(OsslTime::ticks(OSSL_TIME_US)) == core::cmp::Ordering::Less {
        timeleft = OsslTime::ticks(OSSL_TIME_US);
    }

    let socket_timeout = unsafe { (*data).socket_timeout };
    if socket_timeout.is_zero() || socket_timeout.compare(timeleft) != core::cmp::Ordering::Less {
        let short = timeleft.to_timeval();
        // SAFETY: `sock` is live; `short` is a live local of the size passed.
        if unsafe {
            sys::setsockopt(
                sock,
                sys::SOL_SOCKET,
                sys::SO_RCVTIMEO,
                ptr::from_ref(&short).cast(),
                core::mem::size_of::<sys::Timeval>() as sys::SockLen,
            )
        } < 0
        {
            // SAFETY: the site and message are compile-time constants.
            unsafe {
                raise_site_dynamic_data(
                    &BSS_DGRAM_366,
                    sys::errno(),
                    c"calling setsockopt()".as_ptr(),
                )
            };
        }
    }
}

/// `static void dgram_reset_rcv_timeout(BIO *b)`
///
/// Restores the timeout saved by [`dgram_adjust_rcv_timeout`]. Nothing is
/// restored when no timer is armed, which is why the save and the restore are
/// both gated on `next_timeout`: a BIO whose timer was never armed must not have
/// its socket timeout rewritten.
///
/// # Safety
/// `b` must be a live datagram BIO.
unsafe fn dgram_reset_rcv_timeout(b: *mut Bio) {
    let data = unsafe { data_of(b) };
    if unsafe { (*data).next_timeout }.is_zero() {
        return;
    }
    let tv = unsafe { (*data).socket_timeout }.to_timeval();
    // SAFETY: `b.num` is live; `tv` is a live local.
    if unsafe {
        sys::setsockopt(
            (*b).num,
            sys::SOL_SOCKET,
            sys::SO_RCVTIMEO,
            ptr::from_ref(&tv).cast(),
            core::mem::size_of::<sys::Timeval>() as sys::SockLen,
        )
    } < 0
    {
        // SAFETY: the site and message are compile-time constants.
        unsafe {
            raise_site_dynamic_data(
                &BSS_DGRAM_414,
                sys::errno(),
                c"calling setsockopt()".as_ptr(),
            )
        };
    }
}

/// `static void dgram_update_local_addr(BIO *b)`
///
/// `getsockname(2)` writes **directly into** the stored local address, without
/// clearing first, so a shorter family leaves the previous address's remaining
/// bytes in place. On failure the address is cleared and the call still
/// succeeds — the authority's own comment says that "should not be possible".
///
/// # Safety
/// `b` must be a live datagram BIO.
unsafe fn dgram_update_local_addr(b: *mut Bio) {
    let data = unsafe { data_of(b) };
    // SAFETY: `data` is live.
    let target = unsafe { ptr::addr_of_mut!((*data).local_addr) };
    let mut len = addr::AUTHORITY_ADDR_SIZE as sys::SockLen;
    // SAFETY: `b.num` is live; `target` is at least `AUTHORITY_ADDR_SIZE` bytes
    // long and `len` says so.
    if unsafe { sys::getsockname((*b).num, addr::sockaddr_noconst(target), &mut len) } < 0 {
        // SAFETY: `target` is live and writable.
        unsafe { addr::clear_addr(target) };
    }
}

/// `static int dgram_get_sock_family(BIO *b)`
///
/// The family the control-message code keys off is the **local address's** —
/// not the peer's, and not the socket's — so it is whatever `getsockname(2)`
/// last left there.
///
/// # Safety
/// `b` must be a live datagram BIO.
unsafe fn dgram_get_sock_family(b: *mut Bio) -> c_int {
    let data = unsafe { data_of(b) };
    let own = unsafe { addr::view_in(ptr::addr_of!((*data).local_addr)) };
    c_int::from(own.sin_family)
}

/// `static int enable_local_addr(BIO *b, int enable)`
///
/// Turns `IP_PKTINFO` (IPv4) or `IPV6_RECVPKTINFO` (IPv6) on or off. A family it
/// does not handle answers `0`, and so does a failed `setsockopt(2)`; a caller
/// therefore cannot tell "unsupported" from "refused", which is exactly why
/// `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP` exists.
///
/// # Safety
/// `b` must be a live datagram BIO.
unsafe fn enable_local_addr(b: *mut Bio, enable: c_int) -> c_int {
    let af = unsafe { dgram_get_sock_family(b) };
    let sock = unsafe { (*b).num };
    let len = core::mem::size_of::<c_int>() as sys::SockLen;
    if af == sys::AF_INET {
        // SAFETY: `sock` is live; `enable` is a live local of the length passed.
        let rc = unsafe {
            sys::setsockopt(
                sock,
                sys::IPPROTO_IP,
                sys::IP_PKTINFO,
                ptr::from_ref(&enable).cast(),
                len,
            )
        };
        return (rc >= 0) as c_int;
    }
    if af == sys::AF_INET6 {
        // SAFETY: as above, at the IPv6 level.
        let rc = unsafe {
            sys::setsockopt(
                sock,
                sys::IPPROTO_IPV6,
                sys::IPV6_RECVPKTINFO,
                ptr::from_ref(&enable).cast(),
                len,
            )
        };
        return (rc >= 0) as c_int;
    }
    0
}

/* ------------------------------------------------------------------------- */
/* Read and write.                                                          */
/* ------------------------------------------------------------------------- */

/// `static int dgram_read(BIO *b, char *out, int outl)`
///
/// A NULL `out` is not a read at all: the authority's whole body sits inside
/// `if (out != NULL)` and the function answers its initialised `0` without
/// touching the socket or the retry flags. Note also that a successful read from
/// an **unconnected** socket records the sender as the peer, which is why a
/// second `BIO_read` on the same BIO will `write(2)` rather than `sendto(2)`.
///
/// # Safety
/// `b` must be a live datagram BIO; `out` must be NULL or writable for `outl`
/// bytes.
unsafe extern "C" fn dgram_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() {
        return 0;
    }
    let data = unsafe { data_of(b) };
    // SAFETY: `errno` is thread-local and always writable.
    unsafe { sys::set_errno(0) };
    let mut peer = addr::zeroed();
    let peer_ptr = ptr::addr_of_mut!(peer);
    let mut len = addr::AUTHORITY_ADDR_SIZE as sys::SockLen;
    // SAFETY: `b` is a live datagram BIO.
    unsafe { dgram_adjust_rcv_timeout(b) };
    let flags = if unsafe { (*data).peekmode } != 0 {
        sys::MSG_PEEK
    } else {
        0
    };
    // SAFETY: `out` is writable for `outl` bytes; `peer` is live and `len` says
    // how much of it the kernel may use.
    let raw = unsafe {
        sys::recvfrom(
            (*b).num,
            out.cast(),
            outl as usize,
            flags,
            addr::sockaddr_noconst(peer_ptr),
            &mut len,
        )
    };
    let ret = raw as c_int;

    if unsafe { (*data).connected } == 0 && ret >= 0 {
        // `BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, &peer)` — through the control
        // entry point, exactly as the authority calls it.
        // SAFETY: `b` is a live datagram BIO; `peer` is live.
        unsafe { dgram_ctrl(b, super::BIO_CTRL_DGRAM_SET_PEER, 0, peer_ptr.cast()) };
    }

    // `BIO_clear_retry_flags(b)` followed by `BIO_set_retry_read(b)`.
    // SAFETY: `b` and `data` are live.
    unsafe {
        (*b).flags &= !(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        if raw < 0 && dgram_should_retry(ret) != 0 {
            (*b).flags |= BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY;
            (*data).last_error = sys::errno() as c_uint;
        }
    }

    // SAFETY: `b` is a live datagram BIO.
    unsafe { dgram_reset_rcv_timeout(b) };
    ret
}

/// `static int dgram_write(BIO *b, const char *in, int inl)`
///
/// A connected socket uses `write(2)`; an unconnected one uses `sendto(2)` with
/// the stored peer, whose length comes from `BIO_ADDR_sockaddr_size`. For a peer
/// whose family is `AF_UNSPEC` that length is the 112-byte size of a `BIO_ADDR`,
/// which is what an unset peer means and what the authority sends.
///
/// # Safety
/// `b` must be a live datagram BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn dgram_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    let data = unsafe { data_of(b) };
    // SAFETY: `errno` is thread-local and always writable.
    unsafe { sys::set_errno(0) };
    let connected = unsafe { (*data).connected };
    // SAFETY: the descriptor and the buffer are live per the caller's contract.
    let raw = unsafe {
        if connected != 0 {
            sys::write((*b).num, in_.cast(), inl as usize)
        } else {
            let peer = ptr::addr_of!((*data).peer);
            sys::sendto(
                (*b).num,
                in_.cast(),
                inl as usize,
                0,
                addr::sockaddr(peer),
                addr::sockaddr_size(peer),
            )
        }
    };

    // SAFETY: `b` and `data` are live.
    unsafe {
        (*b).flags &= !(BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        if raw <= 0 && dgram_should_retry(raw as c_int) != 0 {
            (*b).flags |= BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY;
            (*data).last_error = sys::errno() as c_uint;
        }
    }
    raw as c_int
}

/// `static int dgram_puts(BIO *bp, const char *str)`
///
/// # Safety
/// `bp` must be a live datagram BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn dgram_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `str_` is NUL-terminated per the method contract.
    let n = unsafe { sys::strlen(str_) };
    if n > INT_MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `str_` is valid for `n` bytes.
    unsafe { dgram_write(bp, str_, n as c_int) }
}

/// `static int BIO_dgram_should_retry(int i)`
///
/// Only a zero or `-1` return consults the socket error; a positive return is
/// success and never retries. `BIO_dgram_non_fatal_error(ENOTCONN)` is `0`, so
/// unlike the socket classifier this one does not treat a lost peer as a retry.
fn dgram_should_retry(i: c_int) -> c_int {
    if i == 0 || i == -1 {
        // SAFETY: `errno` is thread-local and always readable.
        return super::retry::BIO_dgram_non_fatal_error(unsafe { sys::errno() });
    }
    0
}

/* ------------------------------------------------------------------------- */
/* The MTU helpers.                                                         */
/* ------------------------------------------------------------------------- */

/// `static long dgram_get_mtu_overhead(BIO_ADDR *addr)`
///
/// The header bytes one IP datagram costs: 28 for IPv4 (20 IP + 8 UDP), 48 for
/// IPv6, and 28 for anything else. An IPv4-mapped IPv6 address counts as IPv4,
/// because that is what the packet on the wire is.
///
/// # Safety
/// `addr_` must be a live [`BioAddr`].
unsafe fn dgram_get_mtu_overhead(addr_: *const BioAddr) -> c_long {
    match unsafe { addr::BIO_ADDR_family(addr_) } {
        sys::AF_INET => 28,
        sys::AF_INET6 => {
            let mut tmp = sys::In6Addr { s6_addr: [0; 16] };
            // SAFETY: `addr_` is live and `tmp` is a live 16-byte local.
            let ok = unsafe {
                addr::BIO_ADDR_rawaddress(
                    addr_,
                    ptr::from_mut(&mut tmp).cast::<c_void>(),
                    ptr::null_mut(),
                )
            };
            if ok != 0 && is_v4_mapped(&tmp) {
                28
            } else {
                48
            }
        }
        _ => 28,
    }
}

/// `IN6_IS_ADDR_V4MAPPED` — `::ffff:a.b.c.d`.
///
/// The authority's macro maps this to a comparison of the first three 32-bit
/// words on Linux, which is the same test as the byte comparison here.
fn is_v4_mapped(a: &sys::In6Addr) -> bool {
    a.s6_addr[..10] == [0u8; 10] && a.s6_addr[10] == 0xff && a.s6_addr[11] == 0xff
}

/* ------------------------------------------------------------------------- */
/* dgram_ctrl.                                                              */
/* ------------------------------------------------------------------------- */

/// `static long dgram_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live datagram BIO, and `ptr` must be appropriate for `cmd`.
unsafe extern "C" fn dgram_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    let data = unsafe { data_of(b) };

    match cmd {
        super::BIO_CTRL_RESET => {
            // The authority also assigns `num = 0`, which has no observable
            // effect because `num` is not read again on this path.
            ret = 0;
        }
        super::BIO_CTRL_INFO => {
            ret = 0;
        }
        super::BIO_C_SET_FD => {
            // SAFETY: `b` is live; `ptr` is an `int *` per this control's contract.
            unsafe {
                dgram_clear(b);
                (*b).num = *ptr.cast::<c_int>();
                (*b).shutdown = num as c_int;
                (*b).init = 1;
                dgram_update_local_addr(b);
            }
            let mut ss = sys::SockAddrStorage {
                ss_family: sys::AF_UNSPEC as sys::SaFamily,
                __pad: [0; 126],
            };
            let mut ss_len = core::mem::size_of::<sys::SockAddrStorage>() as sys::SockLen;
            // SAFETY: `b.num` is live; `ss`/`ss_len` are live locals.
            if unsafe {
                sys::getpeername(
                    (*b).num,
                    ptr::from_mut(&mut ss).cast::<sys::SockAddr>(),
                    &mut ss_len,
                )
            } == 0
            {
                // SAFETY: `data`, `ss` and the peer slot are live.
                unsafe {
                    addr::make_from_sockaddr(
                        ptr::addr_of_mut!((*data).peer),
                        ptr::from_ref(&ss).cast::<sys::SockAddr>(),
                    );
                    (*data).connected = 1;
                }
            }
            // A previously enabled destination-address option is re-applied to the
            // new descriptor, and dropped when the new socket refuses it.
            if unsafe { (*data).local_addr_enabled } != 0 {
                // SAFETY: `b` is a live datagram BIO.
                if unsafe { enable_local_addr(b, 1) } < 1 {
                    // SAFETY: `data` is live.
                    unsafe { (*data).local_addr_enabled = 0 };
                }
            }
        }
        super::BIO_C_GET_FD => {
            // SAFETY: `b` is live; `ptr` is NULL or an `int *`.
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
            // A datagram socket reports no buffered bytes: the kernel's queue is
            // not the BIO's, and `BIO_pending` is a question about the BIO.
            ret = 0;
        }
        super::BIO_CTRL_DUP | super::BIO_CTRL_FLUSH => {
            ret = 1;
        }
        super::BIO_CTRL_DGRAM_CONNECT => {
            // SAFETY: `data` is live; `ptr` is a `BIO_ADDR *`.
            unsafe {
                addr::make_from_sockaddr(
                    ptr::addr_of_mut!((*data).peer),
                    addr::sockaddr(ptr.cast::<BioAddr>()),
                );
            }
        }
        super::BIO_CTRL_DGRAM_MTU_DISCOVER => {
            let mut a = addr::zeroed();
            let mut addr_len = addr::AUTHORITY_ADDR_SIZE as sys::SockLen;
            // SAFETY: `b.num` is live; `a` is a live address.
            if unsafe {
                sys::getsockname(
                    (*b).num,
                    addr::sockaddr_noconst(ptr::addr_of_mut!(a)),
                    &mut addr_len,
                )
            } < 0
            {
                ret = 0;
            } else {
                let family = c_int::from(unsafe { addr::view_in(&a) }.sin_family);
                let sock = unsafe { (*b).num };
                let len = core::mem::size_of::<c_int>() as sys::SockLen;
                match family {
                    sys::AF_INET => {
                        let val: c_int = sys::IP_PMTUDISC_DO;
                        // SAFETY: `sock` is live; `val` is a live local.
                        let rc = unsafe {
                            sys::setsockopt(
                                sock,
                                sys::IPPROTO_IP,
                                sys::IP_MTU_DISCOVER,
                                ptr::from_ref(&val).cast(),
                                len,
                            )
                        };
                        ret = rc as c_long;
                        if rc < 0 {
                            // SAFETY: the site and message are constants.
                            unsafe {
                                raise_site_dynamic_data(
                                    &BSS_DGRAM_650,
                                    sys::errno(),
                                    c"calling setsockopt()".as_ptr(),
                                )
                            };
                        }
                    }
                    sys::AF_INET6 => {
                        let val: c_int = sys::IPV6_PMTUDISC_DO;
                        // SAFETY: as above, at the IPv6 level.
                        let rc = unsafe {
                            sys::setsockopt(
                                sock,
                                sys::IPPROTO_IPV6,
                                sys::IPV6_MTU_DISCOVER,
                                ptr::from_ref(&val).cast(),
                                len,
                            )
                        };
                        ret = rc as c_long;
                        if rc < 0 {
                            // SAFETY: the site and message are constants.
                            unsafe {
                                raise_site_dynamic_data(
                                    &BSS_DGRAM_659,
                                    sys::errno(),
                                    c"calling setsockopt()".as_ptr(),
                                )
                            };
                        }
                    }
                    _ => ret = -1,
                }
            }
        }
        super::BIO_CTRL_DGRAM_QUERY_MTU => {
            let mut a = addr::zeroed();
            let mut addr_len = addr::AUTHORITY_ADDR_SIZE as sys::SockLen;
            // SAFETY: `b.num` is live; `a` is a live address.
            if unsafe {
                sys::getsockname(
                    (*b).num,
                    addr::sockaddr_noconst(ptr::addr_of_mut!(a)),
                    &mut addr_len,
                )
            } < 0
            {
                ret = 0;
            } else {
                let family = c_int::from(unsafe { addr::view_in(&a) }.sin_family);
                let sock = unsafe { (*b).num };
                let mut val: c_int = 0;
                let mut sockopt_len = core::mem::size_of::<c_int>() as sys::SockLen;
                let mut queried = false;
                match family {
                    sys::AF_INET => {
                        // SAFETY: `sock` is live; `val`/`sockopt_len` are locals.
                        let rc = unsafe {
                            sys::getsockopt(
                                sock,
                                sys::IPPROTO_IP,
                                sys::IP_MTU,
                                ptr::from_mut(&mut val).cast(),
                                &mut sockopt_len,
                            )
                        };
                        queried = rc >= 0 && val >= 0;
                    }
                    sys::AF_INET6 => {
                        // SAFETY: as above, at the IPv6 level.
                        let rc = unsafe {
                            sys::getsockopt(
                                sock,
                                sys::IPPROTO_IPV6,
                                sys::IPV6_MTU,
                                ptr::from_mut(&mut val).cast(),
                                &mut sockopt_len,
                            )
                        };
                        queried = rc >= 0 && val >= 0;
                    }
                    _ => {}
                }
                if family != sys::AF_INET && family != sys::AF_INET6 {
                    ret = 0;
                } else if !queried {
                    ret = 0;
                } else {
                    // SAFETY: `data` is live; `a` is a live address.
                    let overhead = unsafe { dgram_get_mtu_overhead(ptr::addr_of!(a)) };
                    let mtu = (val as c_long - overhead) as c_uint;
                    // SAFETY: `data` is live.
                    unsafe { (*data).mtu = mtu };
                    ret = mtu as c_long;
                }
            }
        }
        super::BIO_CTRL_DGRAM_GET_FALLBACK_MTU => {
            // SAFETY: `data` is live.
            let peer = unsafe { ptr::addr_of!((*data).peer) };
            // SAFETY: `peer` is live and the helper only reads the address.
            let mut r = -unsafe { dgram_get_mtu_overhead(peer) };
            // SAFETY: `peer` is live.
            match unsafe { addr::BIO_ADDR_family(peer) } {
                sys::AF_INET => r += 576,
                sys::AF_INET6 => {
                    let mut tmp = sys::In6Addr { s6_addr: [0; 16] };
                    // SAFETY: `peer` is live; `tmp` is a live 16-byte local.
                    let ok = unsafe {
                        addr::BIO_ADDR_rawaddress(
                            peer,
                            ptr::from_mut(&mut tmp).cast::<c_void>(),
                            ptr::null_mut(),
                        )
                    };
                    if ok != 0 && is_v4_mapped(&tmp) {
                        r += 576;
                    } else {
                        r += 1280;
                    }
                }
                _ => r += 576,
            }
            ret = r;
        }
        super::BIO_CTRL_DGRAM_GET_MTU => {
            // SAFETY: `data` is live.
            return unsafe { (*data).mtu } as c_long;
        }
        super::BIO_CTRL_DGRAM_SET_MTU => {
            // SAFETY: `data` is live.
            unsafe { (*data).mtu = num as c_uint };
            ret = num;
        }
        super::BIO_CTRL_DGRAM_SET_CONNECTED => {
            // SAFETY: `data` is live; `ptr` is NULL or a `BIO_ADDR *`.
            unsafe {
                if !ptr.is_null() {
                    (*data).connected = 1;
                    addr::make_from_sockaddr(
                        ptr::addr_of_mut!((*data).peer),
                        addr::sockaddr(ptr.cast::<BioAddr>()),
                    );
                } else {
                    (*data).connected = 0;
                    addr::clear_addr(ptr::addr_of_mut!((*data).peer));
                }
            }
        }
        super::BIO_CTRL_DGRAM_GET_PEER => {
            // SAFETY: `data` is live.
            let peer = unsafe { ptr::addr_of!((*data).peer) };
            // SAFETY: `peer` is live.
            let size = unsafe { addr::sockaddr_size(peer) };
            let mut n = num;
            if n == 0 || n > size as c_long {
                n = size as c_long;
            }
            // SAFETY: `ptr` is writable for `n` bytes per this control's contract,
            // and `peer` holds that many readable bytes.
            unsafe { sys::memcpy(ptr, peer.cast(), n as usize) };
            ret = n;
        }
        super::BIO_CTRL_DGRAM_SET_PEER => {
            // SAFETY: `data` is live; `ptr` is a `BIO_ADDR *`.
            unsafe {
                addr::make_from_sockaddr(
                    ptr::addr_of_mut!((*data).peer),
                    addr::sockaddr(ptr.cast::<BioAddr>()),
                );
            }
        }
        super::BIO_CTRL_DGRAM_DETECT_PEER_ADDR => {
            // SAFETY: `data` is live.
            let stored = unsafe { ptr::addr_of_mut!((*data).peer) };
            let mut xaddr = addr::zeroed();
            let xptr = ptr::addr_of_mut!(xaddr);
            // SAFETY: `stored` is live.
            let p: *mut BioAddr = if unsafe { addr::BIO_ADDR_family(stored) } == sys::AF_UNSPEC {
                let mut xlen = addr::AUTHORITY_ADDR_SIZE as sys::SockLen;
                // SAFETY: `b.num` is live; `xaddr`/`xlen` are live locals.
                let rc =
                    unsafe { sys::getpeername((*b).num, addr::sockaddr_noconst(xptr), &mut xlen) };
                // SAFETY: `xptr` is live.
                if rc == 0 && unsafe { addr::BIO_ADDR_family(xptr) } != sys::AF_UNSPEC {
                    xptr
                } else {
                    return 0;
                }
            } else {
                stored
            };
            // SAFETY: `p` is live.
            let size = unsafe { addr::sockaddr_size(p) };
            let mut n = num;
            if n == 0 || n > size as c_long {
                n = size as c_long;
            }
            // SAFETY: `ptr` is writable for `n` bytes, and `p` holds that many.
            unsafe { sys::memcpy(ptr, p.cast(), n as usize) };
            ret = n;
        }
        super::BIO_C_SET_NBIO => {
            // SAFETY: `b` is live.
            let sock = unsafe { (*b).num };
            if super::bss_sock::BIO_socket_nbio(sock, (num != 0) as c_int) == 0 {
                ret = 0;
            }
        }
        super::BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT => {
            // SAFETY: `ptr` is a `struct timeval *` per this control's contract.
            let tv = unsafe { *ptr.cast::<sys::Timeval>() };
            // SAFETY: `data` is live.
            unsafe { (*data).next_timeout = OsslTime::from_timeval(tv) };
        }
        super::BIO_CTRL_DGRAM_SET_RECV_TIMEOUT => {
            // SAFETY: the descriptor is live; `ptr` is a `struct timeval *`.
            let rc = unsafe {
                sys::setsockopt(
                    (*b).num,
                    sys::SOL_SOCKET,
                    sys::SO_RCVTIMEO,
                    ptr,
                    core::mem::size_of::<sys::Timeval>() as sys::SockLen,
                )
            };
            ret = rc as c_long;
            if rc < 0 {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_dynamic_data(
                        &BSS_DGRAM_806,
                        sys::errno(),
                        c"calling setsockopt()".as_ptr(),
                    )
                };
            }
        }
        super::BIO_CTRL_DGRAM_GET_RECV_TIMEOUT => {
            let mut sz = core::mem::size_of::<sys::Timeval>() as sys::SockLen;
            // SAFETY: the descriptor is live; `ptr`/`sz` are live per the
            // contract.
            let rc = unsafe {
                sys::getsockopt((*b).num, sys::SOL_SOCKET, sys::SO_RCVTIMEO, ptr, &mut sz)
            };
            // The authority assigns the syscall's result to the return value
            // before testing it, so a failure returns -1 rather than the
            // initialised 1.
            ret = rc as c_long;
            if rc < 0 {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_dynamic_data(
                        &BSS_DGRAM_833,
                        sys::errno(),
                        c"calling getsockopt()".as_ptr(),
                    )
                };
            } else if sz as usize != core::mem::size_of::<sys::Timeval>() {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_data(
                        &BSS_DGRAM_836,
                        c"Unexpected getsockopt(SO_RCVTIMEO) return size".as_ptr(),
                    )
                };
                ret = -1;
            } else {
                ret = sz as c_long;
            }
        }
        super::BIO_CTRL_DGRAM_SET_SEND_TIMEOUT => {
            // SAFETY: the descriptor is live; `ptr` is a `struct timeval *`.
            let rc = unsafe {
                sys::setsockopt(
                    (*b).num,
                    sys::SOL_SOCKET,
                    sys::SO_SNDTIMEO,
                    ptr,
                    core::mem::size_of::<sys::Timeval>() as sys::SockLen,
                )
            };
            ret = rc as c_long;
            if rc < 0 {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_dynamic_data(
                        &BSS_DGRAM_862,
                        sys::errno(),
                        c"calling setsockopt()".as_ptr(),
                    )
                };
            }
        }
        super::BIO_CTRL_DGRAM_GET_SEND_TIMEOUT => {
            let mut sz = core::mem::size_of::<sys::Timeval>() as sys::SockLen;
            // SAFETY: the descriptor is live; `ptr`/`sz` are live per the
            // contract.
            let rc = unsafe {
                sys::getsockopt((*b).num, sys::SOL_SOCKET, sys::SO_SNDTIMEO, ptr, &mut sz)
            };
            // As for the receive control: the syscall's result is the return
            // value before the error tests run.
            ret = rc as c_long;
            if rc < 0 {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_dynamic_data(
                        &BSS_DGRAM_889,
                        sys::errno(),
                        c"calling getsockopt()".as_ptr(),
                    )
                };
            } else if sz as usize != core::mem::size_of::<sys::Timeval>() {
                // SAFETY: the site and message are constants.
                unsafe {
                    raise_site_data(
                        &BSS_DGRAM_892,
                        c"Unexpected getsockopt(SO_SNDTIMEO) return size".as_ptr(),
                    )
                };
                ret = -1;
            } else {
                ret = sz as c_long;
            }
        }
        // Both expiry controls share one arm because the authority falls through
        // from the send one to the receive one, and both read the same stored
        // errno. `EAGAIN` is the value that means "timed out" here.
        super::BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP | super::BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP => {
            // SAFETY: `data` is live.
            if unsafe { (*data).last_error } == sys::EAGAIN as c_uint {
                ret = 1;
                // SAFETY: `data` is live.
                unsafe { (*data).last_error = 0 };
            } else {
                ret = 0;
            }
        }
        super::BIO_CTRL_DGRAM_MTU_EXCEEDED => {
            // SAFETY: `data` is live.
            if unsafe { (*data).last_error } == sys::EMSGSIZE as c_uint {
                ret = 1;
                // SAFETY: `data` is live.
                unsafe { (*data).last_error = 0 };
            } else {
                ret = 0;
            }
        }
        super::BIO_CTRL_DGRAM_SET_DONT_FRAG => {
            // SAFETY: `data` is live.
            let peer = unsafe { ptr::addr_of!((*data).peer) };
            // SAFETY: `peer` is live.
            let family = unsafe { addr::BIO_ADDR_family(peer) };
            let sock = unsafe { (*b).num };
            let len = core::mem::size_of::<c_int>() as sys::SockLen;
            match family {
                sys::AF_INET => {
                    let val: c_int = if num != 0 {
                        sys::IP_PMTUDISC_PROBE
                    } else {
                        sys::IP_PMTUDISC_DONT
                    };
                    // SAFETY: `sock` is live; `val` is a live local.
                    let rc = unsafe {
                        sys::setsockopt(
                            sock,
                            sys::IPPROTO_IP,
                            sys::IP_MTU_DISCOVER,
                            ptr::from_ref(&val).cast(),
                            len,
                        )
                    };
                    ret = rc as c_long;
                    if rc < 0 {
                        // SAFETY: the site and message are constants.
                        unsafe {
                            raise_site_dynamic_data(
                                &BSS_DGRAM_939,
                                sys::errno(),
                                c"calling setsockopt()".as_ptr(),
                            )
                        };
                    }
                }
                sys::AF_INET6 => {
                    // `IPV6_DONTFRAG` is available on this platform, so the
                    // authority takes the boolean-value branch here rather than the
                    // `IPV6_MTU_DISCOVER` one it uses for IPv4.
                    let val: c_int = if num != 0 { 1 } else { 0 };
                    // SAFETY: `sock` is live; `val` is a live local.
                    let rc = unsafe {
                        sys::setsockopt(
                            sock,
                            sys::IPPROTO_IPV6,
                            sys::IPV6_DONTFRAG,
                            ptr::from_ref(&val).cast(),
                            len,
                        )
                    };
                    ret = rc as c_long;
                    if rc < 0 {
                        // SAFETY: the site and message are constants.
                        unsafe {
                            raise_site_dynamic_data(
                                &BSS_DGRAM_961,
                                sys::errno(),
                                c"calling setsockopt()".as_ptr(),
                            )
                        };
                    }
                }
                _ => ret = -1,
            }
        }
        super::BIO_CTRL_DGRAM_GET_MTU_OVERHEAD => {
            // SAFETY: `data` is live and the helper only reads the peer.
            ret = unsafe { dgram_get_mtu_overhead(ptr::addr_of!((*data).peer)) };
        }
        // Two control numbers share this arm. `BIO_CTRL_DGRAM_SET_PEEK_MODE` was
        // first defined with the value of `BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE`,
        // and the authority answers both to preserve binary compatibility. The
        // value must not be "corrected" here.
        super::BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE | super::BIO_CTRL_DGRAM_SET_PEEK_MODE => {
            // SAFETY: `data` is live.
            unsafe { (*data).peekmode = num as c_uint };
        }
        super::BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP => {
            // `SUPPORT_LOCAL_ADDR` is compiled in for this platform.
            ret = 1;
        }
        super::BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE => {
            let want: c_int = c_int::from(num > 0);
            // SAFETY: `data` is live.
            if want != c_int::from(unsafe { (*data).local_addr_enabled }) {
                // SAFETY: `b` is a live datagram BIO.
                if unsafe { enable_local_addr(b, want) } < 1 {
                    ret = 0;
                } else {
                    // SAFETY: `data` is live.
                    unsafe { (*data).local_addr_enabled = want as c_char };
                }
            }
        }
        super::BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE => {
            // The authority writes `*(int *)ptr` without checking `ptr`, so a NULL
            // argument faults. Recorded divergence: this arm does not write, and
            // the value it would have written is the one it returns.
            // SAFETY: `data` is live.
            let enabled = c_int::from(unsafe { (*data).local_addr_enabled });
            let ip = ptr.cast::<c_int>();
            if ip.is_null() {
                ret = enabled as c_long;
            } else {
                // SAFETY: `ip` is non-NULL and writable per this control's
                // contract.
                unsafe { *ip = enabled };
            }
        }
        super::BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS => {
            ret = (BIO_DGRAM_CAP_HANDLES_DST_ADDR
                | BIO_DGRAM_CAP_HANDLES_SRC_ADDR
                | BIO_DGRAM_CAP_PROVIDES_DST_ADDR
                | BIO_DGRAM_CAP_PROVIDES_SRC_ADDR) as c_long;
        }
        super::BIO_CTRL_GET_RPOLL_DESCRIPTOR | super::BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
            // SAFETY: `ptr` is a `BIO_POLL_DESCRIPTOR *` per this control's
            // contract.
            unsafe {
                let pd = ptr.cast::<super::BioPollDescriptor>();
                (*pd).r#type = super::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD;
                (*pd).value.fd = (*b).num;
            }
        }
        _ => {
            ret = 0;
        }
    }

    // "Normalize if error": any negative return becomes exactly `-1`, so a caller
    // cannot see which of several failing syscalls produced it.
    if ret < 0 {
        ret = -1;
    }
    ret
}

/* ------------------------------------------------------------------------- */
/* Control-message translation.                                             */
/* ------------------------------------------------------------------------- */

/// `static void translate_msg(BIO *b, struct msghdr *mh, struct iovec *iov,
/// unsigned char *control, BIO_MSG *msg)`
///
/// The peer is named only when the socket is **unconnected**: a connected socket
/// sends with `msg_name = NULL` and lets the kernel use the socket's peer. The
/// `msg_namelen` comes from the *local* address's family, as in the authority,
/// and a non-NULL peer of a family that is neither IPv4 nor IPv6 yields length 0
/// — which is what makes a `BIO_sendmmsg` to an unset peer a `sendto` with no
/// address rather than an error.
///
/// # Safety
/// `b` must be a live datagram BIO; `mh`, `iov`, `control` and `msg` must be
/// live and mutually distinct.
unsafe fn translate_msg(
    b: *mut Bio,
    mh: *mut sys::Msghdr,
    iov: *mut sys::Iovec,
    control: *mut u8,
    msg: *mut super::BioMsg,
) {
    // SAFETY: the caller passes live pointers.
    unsafe {
        (*iov).iov_base = (*msg).data;
        (*iov).iov_len = (*msg).data_len;
    }
    let data = unsafe { data_of(b) };
    let connected = unsafe { (*data).connected };
    let family = unsafe { dgram_get_sock_family(b) };
    // SAFETY: `mh`, `iov` and `msg` are live and distinct.
    unsafe {
        let peer = (*msg).peer.cast::<BioAddr>();
        if connected == 0 {
            (*mh).msg_name = if peer.is_null() {
                ptr::null_mut()
            } else {
                addr::sockaddr(peer).cast_mut().cast()
            };
            (*mh).msg_namelen = if peer.is_null() {
                0
            } else if family == sys::AF_INET {
                core::mem::size_of::<sys::SockAddrIn>() as sys::SockLen
            } else if family == sys::AF_INET6 {
                core::mem::size_of::<sys::SockAddrIn6>() as sys::SockLen
            } else {
                0
            };
        } else {
            (*mh).msg_name = ptr::null_mut();
            (*mh).msg_namelen = 0;
        }
        (*mh).msg_iov = iov;
        (*mh).msg_iovlen = 1;
        let want_local = !(*msg).local.is_null();
        (*mh).msg_control = if want_local {
            control.cast()
        } else {
            ptr::null_mut()
        };
        (*mh).msg_controllen = if want_local { BIO_CMSG_ALLOC_LEN } else { 0 };
        (*mh).msg_flags = 0;
    }
}

/// `static int extract_local(BIO *b, MSGHDR_TYPE *mh, BIO_ADDR *local)`
///
/// Walks the returned ancillary records for one matching the socket's family and
/// fills `local` from it, taking the **port** and, for IPv6, the **scope id**
/// from the BIO's own local address: the kernel's record carries only the
/// destination address. Returns 0 when nothing matches, which the callers turn
/// into a cleared address rather than a failed transfer.
///
/// # Safety
/// `b` must be a live datagram BIO; `mh` must be live with a control buffer
/// readable for `msg_controllen` bytes; `local` must be live and writable.
unsafe fn extract_local(b: *mut Bio, mh: *mut sys::Msghdr, local: *mut BioAddr) -> c_int {
    // SAFETY: `mh` is live.
    let mut cmsg = unsafe { sys::cmsg_firsthdr(mh) };
    while !cmsg.is_null() {
        // SAFETY: `b` is live.
        let af = unsafe { dgram_get_sock_family(b) };
        // SAFETY: `cmsg` is a record inside the control buffer.
        let hdr = unsafe { sys::cmsg_hdr(cmsg) };
        if af == sys::AF_INET
            && hdr.cmsg_level == sys::IPPROTO_IP
            && hdr.cmsg_type == sys::IP_PKTINFO
        {
            // SAFETY: the record type says the payload is an `in_pktinfo`.
            let info = unsafe {
                sys::cmsg_data(cmsg)
                    .cast::<sys::InPktInfo>()
                    .read_unaligned()
            };
            // SAFETY: `b` and `local` are live; the local address holds the port.
            unsafe {
                let own = addr::view_in(ptr::addr_of!((*data_of(b)).local_addr));
                let mut sin = addr::view_in(local);
                sin.sin_addr = info.ipi_addr;
                sin.sin_family = sys::AF_INET as sys::SaFamily;
                sin.sin_port = own.sin_port;
                addr::store_in(local, sin);
            }
            return 1;
        }
        if af == sys::AF_INET6
            && hdr.cmsg_level == sys::IPPROTO_IPV6
            && hdr.cmsg_type == sys::IPV6_PKTINFO
        {
            // SAFETY: the record type says the payload is an `in6_pktinfo`.
            let info = unsafe {
                sys::cmsg_data(cmsg)
                    .cast::<sys::In6PktInfo>()
                    .read_unaligned()
            };
            // SAFETY: `b` and `local` are live; the local address holds the port
            // and scope id.
            unsafe {
                let own = addr::view_in6(ptr::addr_of!((*data_of(b)).local_addr));
                let mut sin6 = addr::view_in6(local);
                sin6.sin6_addr = info.ipi6_addr;
                sin6.sin6_family = sys::AF_INET6 as sys::SaFamily;
                sin6.sin6_port = own.sin6_port;
                sin6.sin6_scope_id = own.sin6_scope_id;
                sin6.sin6_flowinfo = 0;
                addr::store_in6(local, sin6);
            }
            return 1;
        }
        // Not our record; move to the next.
        // SAFETY: `cmsg` is a record in this buffer.
        cmsg = unsafe { sys::cmsg_nxthdr(mh, cmsg) };
    }
    0
}

/// `static int pack_local(BIO *b, MSGHDR_TYPE *mh, const BIO_ADDR *local)`
///
/// Builds the outgoing ancillary record. The port — and, for IPv6, the scope id
/// — must be zero or match the socket's own, because this API cannot override
/// the source port; a mismatch raises `BIO_R_PORT_MISMATCH` and returns 0 **after
/// the record has already been written**, so the caller's buffer is left
/// describing a send that will not happen.
///
/// # Safety
/// `b` must be a live datagram BIO; `mh` must be live with a writable control
/// buffer of at least `BIO_CMSG_ALLOC_LEN` bytes; `local` must be live.
unsafe fn pack_local(b: *mut Bio, mh: *mut sys::Msghdr, local: *const BioAddr) -> c_int {
    let af = unsafe { dgram_get_sock_family(b) };
    if af == sys::AF_INET {
        // SAFETY: `mh` is live and its control buffer is writable per the
        // caller's contract; `local` is live.
        unsafe {
            let control = (*mh).msg_control.cast::<u8>();
            sys::cmsg_set_hdr(
                control,
                sys::Cmsghdr {
                    cmsg_len: sys::cmsg_len(core::mem::size_of::<sys::InPktInfo>()),
                    cmsg_level: sys::IPPROTO_IP,
                    cmsg_type: sys::IP_PKTINFO,
                },
            );
            let want = addr::view_in(local);
            let info = sys::InPktInfo {
                ipi_ifindex: 0,
                ipi_spec_dst: want.sin_addr,
                ipi_addr: sys::InAddr { s_addr: 0 },
            };
            sys::cmsg_data(control)
                .cast::<sys::InPktInfo>()
                .write_unaligned(info);
            let have = addr::view_in(ptr::addr_of!((*data_of(b)).local_addr));
            if want.sin_port != 0 && have.sin_port != want.sin_port {
                raise_site(&BSS_DGRAM_1231);
                return 0;
            }
            (*mh).msg_controllen = sys::cmsg_space(core::mem::size_of::<sys::InPktInfo>());
        }
        return 1;
    }
    if af == sys::AF_INET6 {
        // SAFETY: as above, for the IPv6 record.
        unsafe {
            let control = (*mh).msg_control.cast::<u8>();
            sys::cmsg_set_hdr(
                control,
                sys::Cmsghdr {
                    cmsg_len: sys::cmsg_len(core::mem::size_of::<sys::In6PktInfo>()),
                    cmsg_level: sys::IPPROTO_IPV6,
                    cmsg_type: sys::IPV6_PKTINFO,
                },
            );
            let want6 = addr::view_in6(local);
            let info = sys::In6PktInfo {
                ipi6_addr: want6.sin6_addr,
                ipi6_ifindex: 0,
            };
            sys::cmsg_data(control)
                .cast::<sys::In6PktInfo>()
                .write_unaligned(info);
            let have6 = addr::view_in6(ptr::addr_of!((*data_of(b)).local_addr));
            if want6.sin6_port != 0 && have6.sin6_port != want6.sin6_port {
                raise_site(&BSS_DGRAM_1301);
                return 0;
            }
            if want6.sin6_scope_id != 0 && have6.sin6_scope_id != want6.sin6_scope_id {
                raise_site(&BSS_DGRAM_1307);
                return 0;
            }
            (*mh).msg_controllen = sys::cmsg_space(core::mem::size_of::<sys::In6PktInfo>());
        }
        return 1;
    }
    0
}

/* ------------------------------------------------------------------------- */
/* The message batches.                                                     */
/* ------------------------------------------------------------------------- */

/// The stack storage one translated batch uses, mirroring the authority's three
/// parallel arrays.
struct Batch {
    /// One `struct mmsghdr` per message.
    mh: [sys::Mmsghdr; BIO_MAX_MSGS_PER_CALL],
    /// One `struct iovec` per message.
    iov: [sys::Iovec; BIO_MAX_MSGS_PER_CALL],
    /// One control buffer per message.
    control: [[u8; BIO_CMSG_ALLOC_LEN]; BIO_MAX_MSGS_PER_CALL],
}

impl Batch {
    /// A zeroed batch.
    ///
    /// This is equivalent to the authority's stack allocation: every field
    /// `translate_msg` reads is written before use, and `msg_len` is an output
    /// the syscall fills. `0` is never a valid file descriptor in the
    /// `BIO_FLAGS_DGRAM` sense, so nothing here can be mistaken for live state.
    fn zeroed() -> Self {
        Self {
            // SAFETY: `Mmsghdr` is a `repr(C)` aggregate of null pointers,
            // integers and a byte array; all-zero is a valid value.
            mh: unsafe { core::mem::zeroed() },
            iov: [sys::Iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            }; BIO_MAX_MSGS_PER_CALL],
            control: [[0u8; BIO_CMSG_ALLOC_LEN]; BIO_MAX_MSGS_PER_CALL],
        }
    }
}

/// The `BIO_MSG` at index `i` of a strided array.
///
/// # Safety
/// `msg` must be an array of at least `i + 1` messages of `stride` bytes each.
unsafe fn msg_at(msg: *mut super::BioMsg, stride: usize, i: usize) -> *mut super::BioMsg {
    // SAFETY: the caller guarantees the element exists.
    unsafe { msg.cast::<u8>().add(i * stride).cast::<super::BioMsg>() }
}

/// `static int dgram_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg,
/// uint64_t flags, size_t *num_processed)`
///
/// # Safety
/// `b` must be a live datagram BIO; `msg` must point at `num_msg` messages of
/// `stride` bytes; `num_processed` must be writable.
unsafe extern "C" fn dgram_sendmmsg(
    b: *mut Bio,
    msg: *mut super::BioMsg,
    stride: usize,
    num_msg: usize,
    _flags: u64,
    num_processed: *mut usize,
) -> c_int {
    // The authority's `translate_flags` defines no flags and returns 0.
    let sysflags: c_int = 0;

    // SAFETY: `num_processed` is the caller's out-parameter.
    unsafe { *num_processed = 0 };
    if num_msg == 0 {
        return 1;
    }
    let mut num_msg = num_msg;
    if num_msg > isize::MAX as usize {
        num_msg = isize::MAX as usize;
    }
    if num_msg > BIO_MAX_MSGS_PER_CALL {
        num_msg = BIO_MAX_MSGS_PER_CALL;
    }

    // SAFETY: `b` is live.
    let have_local_enabled = unsafe { (*data_of(b)).local_addr_enabled };
    let mut batch = Batch::zeroed();

    for i in 0..num_msg {
        // SAFETY: `msg` holds `num_msg` elements and `i < num_msg`.
        let m = unsafe { msg_at(msg, stride, i) };
        // SAFETY: `b` and the `i`th entries of the three arrays are live and
        // distinct.
        unsafe {
            translate_msg(
                b,
                ptr::addr_of_mut!(batch.mh[i]).cast::<sys::Msghdr>(),
                ptr::addr_of_mut!(batch.iov[i]),
                batch.control[i].as_mut_ptr(),
                m,
            );
            if !(*m).local.is_null() {
                if have_local_enabled == 0 {
                    raise_site(&BSS_DGRAM_1402);
                    *num_processed = 0;
                    return 0;
                }
                let local = (*m).local.cast::<BioAddr>();
                if pack_local(
                    b,
                    ptr::addr_of_mut!(batch.mh[i]).cast::<sys::Msghdr>(),
                    local,
                ) < 1
                {
                    raise_site(&BSS_DGRAM_1410);
                    *num_processed = 0;
                    return 0;
                }
            }
        }
    }

    // SAFETY: the descriptor is live and `batch.mh` holds `num_msg` live entries.
    let ret =
        unsafe { sys::sendmmsg((*b).num, batch.mh.as_mut_ptr(), num_msg as c_uint, sysflags) };
    if ret < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site_dynamic(&BSS_DGRAM_1420, sys::errno()) };
        // SAFETY: the out-parameter is live.
        unsafe { *num_processed = 0 };
        return 0;
    }

    for i in 0..ret as usize {
        // SAFETY: `msg` holds at least `ret` elements.
        unsafe {
            let m = msg_at(msg, stride, i);
            (*m).data_len = batch.mh[i].msg_len as usize;
            (*m).flags = 0;
        }
    }
    // SAFETY: the out-parameter is live.
    unsafe { *num_processed = ret as usize };
    1
}

/// `static int dgram_recvmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg,
/// uint64_t flags, size_t *num_processed)`
///
/// Two asymmetries with the send path are deliberate and reproduced. A caller
/// that asked for a local address without enabling it fails **before** the
/// syscall here, where the send path fails inside its loop. And a message whose
/// ancillary data holds no record for our family gets a *cleared* address rather
/// than an error, because several real platforms omit the record for loopback
/// traffic.
///
/// # Safety
/// As for [`dgram_sendmmsg`].
unsafe extern "C" fn dgram_recvmmsg(
    b: *mut Bio,
    msg: *mut super::BioMsg,
    stride: usize,
    num_msg: usize,
    _flags: u64,
    num_processed: *mut usize,
) -> c_int {
    let sysflags: c_int = 0;

    // SAFETY: `num_processed` is the caller's out-parameter.
    unsafe { *num_processed = 0 };
    if num_msg == 0 {
        return 1;
    }
    let mut num_msg = num_msg;
    if num_msg > isize::MAX as usize {
        num_msg = isize::MAX as usize;
    }
    if num_msg > BIO_MAX_MSGS_PER_CALL {
        num_msg = BIO_MAX_MSGS_PER_CALL;
    }

    // SAFETY: `b` is live.
    let have_local_enabled = unsafe { (*data_of(b)).local_addr_enabled };
    let mut batch = Batch::zeroed();

    for i in 0..num_msg {
        // SAFETY: `msg` holds `num_msg` elements and `i < num_msg`.
        let m = unsafe { msg_at(msg, stride, i) };
        // SAFETY: the destination objects are live and distinct.
        unsafe {
            translate_msg(
                b,
                ptr::addr_of_mut!(batch.mh[i]).cast::<sys::Msghdr>(),
                ptr::addr_of_mut!(batch.iov[i]),
                batch.control[i].as_mut_ptr(),
                m,
            );
            if !(*m).local.is_null() && have_local_enabled == 0 {
                raise_site(&BSS_DGRAM_1604);
                *num_processed = 0;
                return 0;
            }
        }
    }

    // SAFETY: the descriptor is live and `batch.mh` holds `num_msg` live entries.
    let ret = unsafe {
        sys::recvmmsg(
            (*b).num,
            batch.mh.as_mut_ptr(),
            num_msg as c_uint,
            sysflags,
            ptr::null_mut(),
        )
    };
    if ret < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site_dynamic(&BSS_DGRAM_1613, sys::errno()) };
        // SAFETY: the out-parameter is live.
        unsafe { *num_processed = 0 };
        return 0;
    }

    for i in 0..ret as usize {
        // SAFETY: `msg` holds at least `ret` elements.
        unsafe {
            let m = msg_at(msg, stride, i);
            (*m).data_len = batch.mh[i].msg_len as usize;
            (*m).flags = 0;
            if !(*m).local.is_null() {
                let local = (*m).local.cast::<BioAddr>();
                if extract_local(
                    b,
                    ptr::addr_of_mut!(batch.mh[i]).cast::<sys::Msghdr>(),
                    local,
                ) < 1
                {
                    // No record for our family: clear rather than fail.
                    addr::clear_addr(local);
                }
            }
        }
    }
    // SAFETY: the out-parameter is live.
    unsafe { *num_processed = ret as usize };
    1
}

/* ------------------------------------------------------------------------- */
/* Unit tests: the transcribed kernel ABI.                                   */
/* ------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    /// The `struct msghdr`/`iovec`/`mmsghdr`/`cmsghdr` layout is the Linux
    /// x86-64 kernel ABI, not a choice: `sendmsg(2)`, `recvmsg(2)`, `sendmmsg(2)`
    /// and `recvmmsg(2)` are handed these pointers directly. A wrong field order
    /// would show up only as a syscall failure or a confused address, so the
    /// sizes and offsets are pinned here instead.
    #[test]
    fn kernel_message_structs_match_the_linux_abi() {
        assert_eq!(core::mem::size_of::<sys::Iovec>(), 16);
        assert_eq!(core::mem::size_of::<sys::Msghdr>(), 56);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_name), 0);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_namelen), 8);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_iov), 16);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_iovlen), 24);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_control), 32);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_controllen), 40);
        assert_eq!(core::mem::offset_of!(sys::Msghdr, msg_flags), 48);
        assert_eq!(core::mem::size_of::<sys::Mmsghdr>(), 64);
        assert_eq!(core::mem::offset_of!(sys::Mmsghdr, msg_len), 56);
        assert_eq!(core::mem::size_of::<sys::Cmsghdr>(), 16);
        assert_eq!(core::mem::size_of::<sys::InPktInfo>(), 12);
        assert_eq!(core::mem::size_of::<sys::In6PktInfo>(), 20);
        assert_eq!(core::mem::size_of::<sys::Timeval>(), 16);
    }

    /// `BIO_CMSG_ALLOC_LEN` is derived from the same three sizes the authority
    /// maximises over, so this checks the derivation rather than restating a
    /// second source of truth.
    #[test]
    fn cmsg_allocation_holds_the_largest_record() {
        assert_eq!(BIO_CMSG_ALLOC_LEN, 40);
        assert_eq!(sys::cmsg_space(core::mem::size_of::<sys::In6PktInfo>()), 40);
        assert_eq!(sys::cmsg_space(core::mem::size_of::<sys::InPktInfo>()), 32);
        assert_eq!(sys::cmsg_space(core::mem::size_of::<sys::InAddr>()), 24);
        assert_eq!(sys::cmsg_len(core::mem::size_of::<sys::InPktInfo>()), 28);
        assert_eq!(sys::cmsg_data_offset(), 16);
    }

    /// The control-message walk must agree with the record builder: two records
    /// of different lengths walk in order and the walk stops at the end.
    #[test]
    fn cmsg_records_walk_in_order() {
        const BUF: usize = 64;
        let mut buf = [0u8; BUF];
        let first_len = sys::cmsg_len(core::mem::size_of::<sys::InAddr>());
        let second_len = sys::cmsg_len(core::mem::size_of::<sys::InPktInfo>());
        let second_at = sys::cmsg_align(first_len);
        let total = second_at + sys::cmsg_align(second_len);
        assert!(total <= BUF, "the test buffer must hold both records");

        // SAFETY: both offsets and their headers stay inside `buf`.
        unsafe {
            sys::cmsg_set_hdr(
                buf.as_mut_ptr(),
                sys::Cmsghdr {
                    cmsg_len: first_len,
                    cmsg_level: sys::IPPROTO_IP,
                    cmsg_type: sys::IP_PKTINFO,
                },
            );
            sys::cmsg_set_hdr(
                buf.as_mut_ptr().add(second_at),
                sys::Cmsghdr {
                    cmsg_len: second_len,
                    cmsg_level: sys::IPPROTO_IP,
                    cmsg_type: sys::IP_PKTINFO,
                },
            );
        }

        let mh = sys::Msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: buf.as_mut_ptr().cast(),
            msg_controllen: total,
            msg_flags: 0,
        };

        // SAFETY: `mh` is live with a control buffer of `total` bytes.
        let a = unsafe { sys::cmsg_firsthdr(&mh) };
        assert!(!a.is_null());
        // SAFETY: the walk only reads headers inside the buffer.
        let b = unsafe { sys::cmsg_nxthdr(&mh, a) };
        assert_eq!(b as usize - a as usize, second_at);
        // SAFETY: as above.
        let end = unsafe { sys::cmsg_nxthdr(&mh, b) };
        assert!(end.is_null(), "the walk must stop after the last record");

        // A buffer shorter than one header has no records at all.
        let empty = sys::Msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: buf.as_mut_ptr().cast(),
            msg_controllen: core::mem::size_of::<sys::Cmsghdr>() - 1,
            msg_flags: 0,
        };
        // SAFETY: the walk cannot dereference anything in an empty buffer.
        assert!(unsafe { sys::cmsg_firsthdr(&empty) }.is_null());

        // A record that claims to be shorter than a header ends the walk rather
        // than stepping off the end.
        let mut truncated = [0u8; BUF];
        // SAFETY: the header fits in `truncated`.
        unsafe {
            sys::cmsg_set_hdr(
                truncated.as_mut_ptr(),
                sys::Cmsghdr {
                    cmsg_len: 1,
                    cmsg_level: sys::IPPROTO_IP,
                    cmsg_type: sys::IP_PKTINFO,
                },
            );
        }
        let bad = sys::Msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: truncated.as_mut_ptr().cast(),
            msg_controllen: BUF,
            msg_flags: 0,
        };
        // SAFETY: the short record's own length stops the walk before any read
        // outside the buffer.
        assert!(unsafe { sys::cmsg_nxthdr(&bad, truncated.as_mut_ptr()) }.is_null());
    }

    /// The `OSSL_TIME` helpers must round the way `include/internal/time.h` does:
    /// up to the next microsecond, so a non-zero time never becomes zero.
    #[test]
    fn ossl_time_round_trips_and_rounds_up() {
        let tv = OsslTime::ticks(1).to_timeval();
        assert_eq!((tv.tv_sec, tv.tv_usec), (0, 1));
        assert_eq!(OsslTime::ticks(OSSL_TIME_US).to_timeval().tv_usec, 1);
        assert_eq!(OsslTime::ZERO.to_timeval().tv_usec, 0);
        // Subtraction saturates at zero rather than wrapping.
        assert!(OsslTime::ticks(5).subtract(OsslTime::ticks(9)).is_zero());
        // A timeval round-trips exactly when it is a whole number of
        // microseconds, which is what `SO_RCVTIMEO` always holds.
        let back = OsslTime::from_timeval(sys::Timeval {
            tv_sec: 2,
            tv_usec: 500_000,
        })
        .to_timeval();
        assert_eq!((back.tv_sec, back.tv_usec), (2, 500_000));
    }

    /// `IN6_IS_ADDR_V4MAPPED` must accept `::ffff:a.b.c.d` and nothing else that
    /// merely begins with zeros.
    #[test]
    fn v4_mapped_detection() {
        let mut mapped = sys::In6Addr { s6_addr: [0; 16] };
        mapped.s6_addr[10] = 0xff;
        mapped.s6_addr[11] = 0xff;
        mapped.s6_addr[12] = 127;
        mapped.s6_addr[15] = 1;
        assert!(is_v4_mapped(&mapped));

        let mut loopback = sys::In6Addr { s6_addr: [0; 16] };
        loopback.s6_addr[15] = 1;
        assert!(!is_v4_mapped(&loopback));

        let mut almost = mapped;
        almost.s6_addr[10] = 0xfe;
        assert!(!is_v4_mapped(&almost));
    }
}
