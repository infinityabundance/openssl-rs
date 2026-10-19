//! Phase 4 — `BIO_ADDRINFO` and the resolver entry points.
//!
//! `BIO_ADDRINFO` is the chain `BIO_lookup` returns. It is opaque
//! (`struct bio_addrinfo_st` is never defined in a public header), so the layout
//! is ours, but the *behaviour* is thoroughly measured and then confirmed against
//! the pinned source, because several parts are surprising:
//!
//! * **`res` is written only on success.** The authority hands `res` straight to
//!   `getaddrinfo`, which leaves it untouched when it fails. Measured with a
//!   sentinel pointer: after a failed lookup the sentinel is still there, so a
//!   caller cannot rely on `*res` being NULLed. This implementation matches.
//! * **`AI_ADDRCONFIG` is set only when the host is non-NULL *and* the family is
//!   `AF_UNSPEC`**, and `AI_PASSIVE` only for `BIO_LOOKUP_SERVER`. That
//!   combination is why an `AF_INET6` server lookup with a NULL host succeeds on a
//!   host with no IPv6 configuration when `AI_ADDRCONFIG` alone would fail.
//! * **There is a one-shot retry.** When `AI_ADDRCONFIG` was set and the lookup
//!   fails, the authority clears it, sets `AI_NUMERICHOST`, retries once, and
//!   reports the *first* failure's `gai_strerror` text if the retry also fails.
//! * **Every resolver failure raises the same code** —
//!   `ERR_PACK(ERR_LIB_BIO, 0, ERR_R_SYS_LIB)` — but at three different recorded
//!   coordinates (`bio_addr.c:746`, `:751`, `:767`) and with `gai_strerror` as the
//!   error *data*. `ERR_get_error_line_data` observes both, so the coordinates are
//!   reproduced from the generated site table rather than invented.
//! * **The family is validated explicitly** and rejected with
//!   `BIO_R_UNSUPPORTED_PROTOCOL_FAMILY` at `bio_addr.c:698`, before any resolver
//!   call — so `BIO_lookup_ex(…, 999, …)` does not reach `getaddrinfo`.
//! * `BIO_lookup` is exactly `BIO_lookup_ex(…, protocol = 0, …)`.
//! * For `AF_UNIX` the *host* is the socket path and the chain is built directly
//!   by `addrinfo_wrap`; no resolver is involved, and a NULL host faults in the
//!   authority (recorded divergence).
//!
//! The resolver-built addresses are stored **verbatim**: the authority casts
//! glibc's `struct sockaddr` to a `BIO_ADDR`, so an address from this path holds a
//! network-order port, unlike one built by `BIO_ADDR_rawmake`. See `addr.rs` D37.
//!
//! On Linux the authority's `gethostbyname`/`getservbyname` fallback is compiled
//! out (`#ifndef AI_PASSIVE`) and the `AF_UNSPEC` string fallback in `addr_strings`
//! likewise, so neither is implemented here. That is a *configuration* fact, not a
//! simplification: the admitted authority is a glibc build with `AI_PASSIVE`.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BIO_ADDR_590, BIO_ADDR_593, BIO_ADDR_698, BIO_ADDR_707, BIO_ADDR_744, BIO_ADDR_746,
    BIO_ADDR_751, BIO_ADDR_767,
};
use crate::runtime::err::{raise_site, raise_site_data, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strndup};
use crate::runtime::owned_str::OwnedStr;

use super::addr::{make_from_sockaddr, BIO_ADDR_new, BIO_ADDR_rawmake, BioAddr};
use super::bss_sock::BIO_sock_init;
use super::sys;
use crate::runtime::mem_coords::SeamFile;

/// `BIO_LOOKUP_CLIENT`.
pub const BIO_LOOKUP_CLIENT: c_int = 0;
/// `BIO_LOOKUP_SERVER`.
pub const BIO_LOOKUP_SERVER: c_int = 1;

/// `BIO_PARSE_PRIO_HOST`.
pub const BIO_PARSE_PRIO_HOST: c_int = 0;
/// `BIO_PARSE_PRIO_SERV`.
pub const BIO_PARSE_PRIO_SERV: c_int = 1;

/// `EAI_SYSTEM`: the resolver could not report through a name.
const EAI_SYSTEM: c_int = -11;
/// `EAI_MEMORY`: the resolver ran out of memory.
const EAI_MEMORY: c_int = -10;

/// The `file`/`line` recorded by an allocation, mirroring the authority's.
const ALLOC_FILE: &CStr = c"crypto/bio/bio_addr.c";
/// See [`ALLOC_FILE`].
const ALLOC_LINE: c_int = 0;

/// One `BIO_ADDRINFO`: an address plus the socket facts the resolver reported.
///
/// The authority's struct is layout-compatible with `struct addrinfo` so that
/// `getaddrinfo` can write into it directly; ours is not, because we copy. The
/// accessors are functions in both cases, so nothing observable depends on it.
#[repr(C)]
pub struct BioAddrInfo {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: usize,
    /// Owned. Freed by [`BIO_ADDRINFO_free`].
    addr: *mut BioAddr,
    next: *mut BioAddrInfo,
}

/// An owned `BioAddrInfo` node: the authority's own `CRYPTO_malloc`/`memset` block whose single
/// release is `Drop`, so a node is never freed by hand at a call site.
///
/// The node owns its `addr` member too (the authority releases the address before the node in
/// `BIO_ADDRINFO_free`), so `Drop` is the exact per-node cleanup. Ownership transfers to the
/// chain (and then to the C caller) with [`Self::into_raw`]; [`Self::take`] reclaims a node at
/// `BIO_ADDRINFO_free`.
struct OwnedNode {
    ptr: ptr::NonNull<BioAddrInfo>,
}

impl OwnedNode {
    /// Allocate and zero a fresh node, or `None` when the allocator answers NULL -- the
    /// authority's `alloc_node`.
    fn new() -> Option<OwnedNode> {
        let raw = CRYPTO_malloc(
            core::mem::size_of::<BioAddrInfo>(),
            ALLOC_FILE.as_ptr(),
            ALLOC_LINE,
        )
        .cast::<BioAddrInfo>();
        let ptr = ptr::NonNull::new(raw)?;
        // SAFETY: `ptr` is a fresh writable block of `size_of::<BioAddrInfo>()` bytes this
        // handle owns; the all-zero image is a valid node (three integers, a `usize` and two
        // nullable raw pointers), exactly the state the authority's own `memset` leaves.
        unsafe {
            sys::memset(
                ptr.as_ptr().cast::<c_void>(),
                0,
                core::mem::size_of::<BioAddrInfo>(),
            )
        };
        Some(OwnedNode { ptr })
    }

    /// The node's address, for the fields this module fills before linking it.
    fn as_ptr(&self) -> *mut BioAddrInfo {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the node to the chain that links it, or to the C caller.
    fn into_raw(self) -> *mut BioAddrInfo {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Adopt a live node for release by `Drop`, or `None` for NULL.
    ///
    /// # Safety
    /// `ptr` is NULL or a live node this module allocated and has not released; ownership of
    /// the node and of its `addr` member transfers to the handle, whose `Drop` is their single
    /// release.
    unsafe fn take(ptr: *mut BioAddrInfo) -> Option<OwnedNode> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedNode { ptr })
    }
}

impl Drop for OwnedNode {
    fn drop(&mut self) {
        // SAFETY: `p` is a live node this handle owns and has not released; `addr` is NULL or
        // the live `BIO_ADDR` the node owns. The release order is the authority's: the address
        // first, then the node block, both at the allocation's own seam coordinates.
        unsafe {
            let p = self.ptr.as_ptr();
            let addr = (*p).addr;
            if !addr.is_null() {
                super::addr::BIO_ADDR_free(addr);
            }
            CRYPTO_free(p.cast::<c_void>(), ALLOC_FILE.as_ptr(), ALLOC_LINE);
        }
    }
}

/// `const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai)`
///
/// # Safety
/// `bai` must be NULL or point at a live [`BioAddrInfo`] (or the tail of such a
/// chain). The returned pointer borrows the next node's ownership from the chain.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_next(bai: *const BioAddrInfo) -> *const BioAddrInfo {
    // SAFETY: `bai` is NULL or a live node per the caller's contract; `as_ref`
    // makes NULL total instead of dereferencing it.
    guard_ffi(ptr::null(), || match unsafe { bai.as_ref() } {
        Some(b) => b.next,
        None => ptr::null(),
    })
}

/// `int BIO_ADDRINFO_family(const BIO_ADDRINFO *bai)`
///
/// # Safety
/// `bai` must be NULL or point at a live, readable [`BioAddrInfo`].
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_family(bai: *const BioAddrInfo) -> c_int {
    // SAFETY: `bai` is NULL or a live node per the caller's contract; `as_ref`
    // makes NULL total.
    guard_ffi(0, || unsafe { bai.as_ref().map_or(0, |b| b.family) })
}

/// `int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai)`
///
/// # Safety
/// `bai` must be NULL or point at a live, readable [`BioAddrInfo`].
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_socktype(bai: *const BioAddrInfo) -> c_int {
    // SAFETY: `bai` is NULL or a live node per the caller's contract; `as_ref`
    // makes NULL total.
    guard_ffi(0, || unsafe { bai.as_ref().map_or(0, |b| b.socktype) })
}

/// `int BIO_ADDRINFO_protocol(const BIO_ADDRINFO *bai)`
///
/// Not a plain field read: a stored protocol of 0 is *derived* from the socket
/// type, except for `AF_UNIX` where it stays 0. The authority's resolver path
/// usually fills the field, so the derivation is easy to overlook.
///
/// # Safety
/// `bai` must be NULL or point at a live, readable [`BioAddrInfo`].
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_protocol(bai: *const BioAddrInfo) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bai` is NULL or a live node per the caller's contract; `as_ref`
        // makes NULL total.
        let Some(b) = (unsafe { bai.as_ref() }) else {
            return 0;
        };
        if b.protocol != 0 {
            return b.protocol;
        }
        if b.family == sys::AF_UNIX {
            return 0;
        }
        match b.socktype {
            sys::SOCK_STREAM => sys::IPPROTO_TCP,
            sys::SOCK_DGRAM => sys::IPPROTO_UDP,
            _ => 0,
        }
    })
}

/// `const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai)`
///
/// Borrowed: the address belongs to the node and must not be freed by the caller.
///
/// # Safety
/// `bai` must be NULL or point at a live, readable [`BioAddrInfo`]. The returned
/// pointer is borrowed from the node and stays valid only while the chain does.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_address(bai: *const BioAddrInfo) -> *const BioAddr {
    // SAFETY: `bai` is NULL or a live node per the caller's contract; `as_ref`
    // makes NULL total.
    guard_ffi(ptr::null(), || match unsafe { bai.as_ref() } {
        Some(b) => b.addr,
        None => ptr::null(),
    })
}

/// `void BIO_ADDRINFO_free(BIO_ADDRINFO *bai)`
///
/// Walks the whole chain, freeing each node's address and then the node. The
/// authority splits this by family — `freeaddrinfo` for a resolver chain, a manual
/// walk for one built by `addrinfo_wrap` — because its resolver chain *is* glibc's
/// list. Ours is always our own, so the walk is unconditional; the observable
/// (everything is released, nothing is returned) is the same.
///
/// # Safety
/// `bai` must be NULL or the head of an owned [`BioAddrInfo`] chain built by this
/// module, not already freed. Every node's address and the node itself are
/// released; the caller must not use them afterwards.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDRINFO_free(bai: *mut BioAddrInfo) {
    guard_ffi((), || {
        let mut cur = bai;
        while !cur.is_null() {
            // SAFETY: `cur` is a live node allocated by `OwnedNode::new`.
            let next = unsafe { (*cur).next };
            // SAFETY: `cur` is a live node this module allocated and has not released;
            // `Drop` frees its address and the node block, in the authority's order.
            drop(unsafe { OwnedNode::take(cur) });
            cur = next;
        }
    })
}

/// `int addrinfo_wrap(int family, int socktype, const void *where, size_t wherelen, unsigned short port, BIO_ADDRINFO **bai)`
///
/// The authority's own chain builder, used only for `AF_UNIX` on a platform with
/// `getaddrinfo`. The socket facts come from the arguments and the address is a
/// `BIO_ADDR_rawmake` of `where`.
///
/// # Safety
/// `bai` must be writable and `where` readable for `wherelen` bytes.
unsafe fn addrinfo_wrap(
    family: c_int,
    socktype: c_int,
    where_: *const c_void,
    wherelen: usize,
    port: u16,
    bai: *mut *mut BioAddrInfo,
) -> c_int {
    let Some(node) = OwnedNode::new() else {
        // SAFETY: `bai` is writable per the contract; the authority's own
        // `if ((*bai = OPENSSL_zalloc(...)) == NULL) return 0;` writes NULL here.
        unsafe { *bai = ptr::null_mut() };
        return 0;
    };
    let node_ptr = node.as_ptr();
    // SAFETY: `node_ptr` is freshly allocated and zeroed; `bai` is writable.
    unsafe {
        (*node_ptr).family = family;
        (*node_ptr).socktype = socktype;
        if socktype == sys::SOCK_STREAM {
            (*node_ptr).protocol = sys::IPPROTO_TCP;
        }
        if socktype == sys::SOCK_DGRAM {
            (*node_ptr).protocol = sys::IPPROTO_UDP;
        }
        if family == sys::AF_UNIX {
            (*node_ptr).protocol = 0;
        }
        let addr = BIO_ADDR_new();
        if !addr.is_null() {
            // The authority refuses a family/`where` combination `BIO_ADDR_rawmake`
            // rejects (notably an `AF_UNIX` path that leaves no room for its NUL);
            // taking the block unconditionally would return success with an
            // `AF_UNSPEC` address instead.
            if BIO_ADDR_rawmake(addr, family, where_, wherelen, port) != 0 {
                (*node_ptr).addr = addr;
            } else {
                super::addr::BIO_ADDR_free(addr);
            }
        }
        (*node_ptr).next = ptr::null_mut();
        if (*node_ptr).addr.is_null() {
            // The handle's `Drop` releases the address (if any) and then the node, exactly
            // the authority's `BIO_ADDRINFO_free(node)` cleanup.
            *bai = ptr::null_mut();
            return 0;
        }
        *bai = node.into_raw();
    }
    1
}

/// `int BIO_lookup(const char *host, const char *service, enum BIO_lookup_type lookup_type, int family, int socktype, BIO_ADDRINFO **res)`
///
/// # Safety
/// `host` and `service` must be NULL or NUL-terminated; `res` must be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_lookup(
    host: *const c_char,
    service: *const c_char,
    lookup_type: c_int,
    family: c_int,
    socktype: c_int,
    res: *mut *mut BioAddrInfo,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract for `BIO_lookup_ex` is a superset of this.
        unsafe { BIO_lookup_ex(host, service, lookup_type, family, socktype, 0, res) }
    })
}

/// `int BIO_lookup_ex(const char *host, const char *service, int lookup_type, int family, int socktype, int protocol, BIO_ADDRINFO **res)`
///
/// # Safety
/// `host` and `service` must be NULL or NUL-terminated; `res` must be writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_lookup_ex(
    host: *const c_char,
    service: *const c_char,
    lookup_type: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    res: *mut *mut BioAddrInfo,
) -> c_int {
    guard_ffi(0, || {
        if res.is_null() {
            // The authority passes `res` straight to `getaddrinfo`, which faults.
            // Total by policy: an out-parameter the callee cannot write is a
            // caller error, and a NULL `res` reaches this check before any syscall.
            return 0;
        }

        // SAFETY: the family is validated before any use of `res`.
        let family = match family {
            sys::AF_INET | sys::AF_INET6 | sys::AF_UNIX | sys::AF_UNSPEC => family,
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_ADDR_698) };
                return 0;
            }
        };

        if family == sys::AF_UNIX {
            // The authority calls `strlen(host)` here, so a NULL host faults.
            // Total by policy: report the same failure the wrap would.
            if host.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_ADDR_707) };
                return 0;
            }
            // SAFETY: `host` is a NUL-terminated string.
            let hlen = unsafe { sys::strlen(host) };
            // SAFETY: `host` is readable for `hlen` bytes, and `res` is writable.
            if unsafe { addrinfo_wrap(family, socktype, host.cast::<c_void>(), hlen, 0, res) } == 1
            {
                return 1;
            }
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_ADDR_707) };
            return 0;
        }

        if BIO_sock_init() != 1 {
            return 0;
        }

        // SAFETY: `AddrInfo` is a plain C struct of integers and pointers for which
        // an all-zero bit pattern is the documented "no hints" state.
        let mut hints: sys::AddrInfo = unsafe { core::mem::zeroed() };
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_protocol = protocol;
        if !host.is_null() && family == sys::AF_UNSPEC {
            hints.ai_flags |= sys::AI_ADDRCONFIG;
        }
        if lookup_type == BIO_LOOKUP_SERVER {
            hints.ai_flags |= sys::AI_PASSIVE;
        }

        let mut old_ret: c_int = 0;
        let mut list: *mut sys::AddrInfo;
        loop {
            list = ptr::null_mut();
            // SAFETY: `hints` is a fully initialised `struct addrinfo`, `host` and
            // `service` are NULL or NUL-terminated, and `list` is writable.
            let rc = unsafe { sys::getaddrinfo(host, service, &hints, &mut list) };
            match rc {
                0 => break,
                EAI_SYSTEM => {
                    // SAFETY: the sites are compile-time constants and the message
                    // is a static NUL-terminated string.
                    unsafe {
                        raise_site_dynamic_data(
                            &BIO_ADDR_744,
                            sys::errno(),
                            c"calling getaddrinfo()".as_ptr(),
                        );
                        raise_site(&BIO_ADDR_746);
                    }
                    return 0;
                }
                EAI_MEMORY => {
                    let reported = if old_ret != 0 { old_ret } else { rc };
                    // SAFETY: the site is a compile-time constant and
                    // `gai_strerror` returns a static string for a known code.
                    unsafe { raise_site_data(&BIO_ADDR_751, sys::gai_strerror(reported)) };
                    return 0;
                }
                _ => {
                    if hints.ai_flags & sys::AI_ADDRCONFIG != 0 {
                        hints.ai_flags &= !sys::AI_ADDRCONFIG;
                        hints.ai_flags |= sys::AI_NUMERICHOST;
                        old_ret = rc;
                        continue;
                    }
                    let reported = if old_ret != 0 { old_ret } else { rc };
                    // SAFETY: as above.
                    unsafe { raise_site_data(&BIO_ADDR_767, sys::gai_strerror(reported)) };
                    return 0;
                }
            }
        }

        // Convert the resolver's list into our own chain, preserving order. The
        // authority hands the list back as-is, which is why it can use
        // `freeaddrinfo` on it; we copy instead, so the addresses are stored
        // verbatim to keep every observable byte identical.
        let mut head: *mut BioAddrInfo = ptr::null_mut();
        let mut tail: *mut BioAddrInfo = ptr::null_mut();
        let mut cur = list;
        while !cur.is_null() {
            // SAFETY: `cur` is a node of glibc's list, which is live until
            // `freeaddrinfo` below.
            let ai = unsafe { &*cur };
            let Some(node) = OwnedNode::new() else {
                break;
            };
            let node_ptr = node.as_ptr();
            let addr = BIO_ADDR_new();
            // SAFETY: `node_ptr` and `addr` are freshly allocated.
            unsafe {
                (*node_ptr).family = ai.ai_family;
                (*node_ptr).socktype = ai.ai_socktype;
                (*node_ptr).protocol = ai.ai_protocol;
                (*node_ptr).addrlen = ai.ai_addrlen as usize;
                (*node_ptr).next = ptr::null_mut();
                if !addr.is_null() && !ai.ai_addr.is_null() {
                    // `BIO_ADDR_make` handles the families the resolver returns and
                    // clears the rest, which is exactly the authority's cast.
                    if make_from_sockaddr(addr, ai.ai_addr) == 1 {
                        (*node_ptr).addr = addr;
                    } else {
                        super::addr::BIO_ADDR_free(addr);
                    }
                } else if !addr.is_null() {
                    super::addr::BIO_ADDR_free(addr);
                }
            }
            // Ownership transfers into the chain; the chain is released by
            // `BIO_ADDRINFO_free`, which adopts each node.
            let node_ptr = node.into_raw();
            if tail.is_null() {
                head = node_ptr;
            } else {
                // SAFETY: `tail` is the last node linked so far.
                unsafe { (*tail).next = node_ptr };
            }
            tail = node_ptr;
            cur = ai.ai_next;
        }

        // SAFETY: `list` came from `getaddrinfo` and is not used again.
        unsafe { sys::freeaddrinfo(list) };

        if head.is_null() {
            // Either the resolver returned an empty list, which cannot happen for
            // a successful lookup, or our conversion ran out of memory. The
            // authority has no equivalent path to raise from, so this returns
            // failure with an empty queue rather than inventing a coordinate.
            return 0;
        }

        // SAFETY: `res` is writable; write only on success, as the authority does.
        unsafe { *res = head };
        1
    })
}

/// `const char *strchr(const char *s, int c)` over a NUL-terminated string.
///
/// # Safety
/// `s` must be a NUL-terminated C string.
unsafe fn find_char(s: *const c_char, needle: c_char) -> *const c_char {
    let mut p = s;
    loop {
        // SAFETY: `s` is NUL-terminated, so the scan stops at its terminator.
        let c = unsafe { *p };
        if c == needle {
            return p;
        }
        if c == 0 {
            return ptr::null();
        }
        // SAFETY: the scan has not yet reached the terminator, so `p` points at
        // an in-bounds byte and `p + 1` is at or before the terminator.
        p = unsafe { p.add(1) };
    }
}

/// `const char *strrchr(const char *s, int c)` over a NUL-terminated string.
///
/// # Safety
/// `s` must be a NUL-terminated C string.
unsafe fn find_last_char(s: *const c_char, needle: c_char) -> *const c_char {
    let mut last = ptr::null();
    let mut p = s;
    loop {
        // SAFETY: `s` is NUL-terminated.
        let c = unsafe { *p };
        if c == needle {
            last = p;
        }
        if c == 0 {
            return last;
        }
        // SAFETY: the scan has not yet reached the terminator, so `p` points at
        // an in-bounds byte and `p + 1` is at or before the terminator.
        p = unsafe { p.add(1) };
    }
}

/// `int BIO_parse_hostserv(const char *hostserv, char **host, char **service, enum BIO_hostserv_priorities hostserv_prio)`
///
/// Splits `hostserv` into a host and a service. The empty spelling of either half
/// becomes NULL, and so does a lone `*`; an unbracketed string with more than one
/// colon is *ambiguous* rather than being guessed at, which is why a bare IPv6
/// literal fails while a bracketed one succeeds.
///
/// # Safety
/// `hostserv` must be a NUL-terminated C string; `host` and `service` must each be
/// NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_parse_hostserv(
    hostserv: *const c_char,
    host: *mut *mut c_char,
    service: *mut *mut c_char,
    hostserv_prio: c_int,
) -> c_int {
    guard_ffi(0, || {
        if hostserv.is_null() {
            // The authority dereferences `hostserv` immediately; total by policy.
            return 0;
        }

        let mut h: *const c_char = ptr::null();
        let mut hl: usize = 0;
        let mut p: *const c_char = ptr::null();
        let mut pl: usize = 0;

        // SAFETY: `hostserv` is NUL-terminated.
        if unsafe { *hostserv } == b'[' as c_char {
            // SAFETY: `hostserv` is a NUL-terminated string per the caller's
            // contract, which is `find_char`'s precondition.
            let close = unsafe { find_char(hostserv, b']' as c_char) };
            if close.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_ADDR_593) };
                return 0;
            }
            // SAFETY: `close` points at the `]` and `h` is `hostserv + 1`, so
            // `h` precedes or equals `close` within the same allocation.
            h = unsafe { hostserv.add(1) };
            // SAFETY: both pointers are derived from `hostserv` and ordered, so
            // the signed distance is in bounds.
            hl = unsafe { close.offset_from(h) } as usize;
            // SAFETY: `close` points at the non-NUL `]`, so `close + 1` is at or
            // before the terminator.
            let after = unsafe { close.add(1) };
            // SAFETY: `after` is at or before the terminator.
            match unsafe { *after } {
                0 => p = ptr::null(),
                c if c == b':' as c_char => {
                    // SAFETY: `after` points at the non-NUL `:`, so `after + 1`
                    // is at or before the terminator.
                    p = unsafe { after.add(1) };
                    // SAFETY: `p` is a NUL-terminated suffix of `hostserv`.
                    pl = unsafe { sys::strlen(p) };
                }
                _ => {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&BIO_ADDR_593) };
                    return 0;
                }
            }
        } else {
            // SAFETY: `hostserv` is a NUL-terminated string per the caller's
            // contract, which is the precondition of both scan helpers.
            let last = unsafe { find_last_char(hostserv, b':' as c_char) };
            // SAFETY: as above.
            let first = unsafe { find_char(hostserv, b':' as c_char) };
            if first != last {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_ADDR_590) };
                return 0;
            }
            if !first.is_null() {
                h = hostserv;
                // SAFETY: `first` points at the `:` and `hostserv` is the start of
                // the same allocation, so `hostserv` precedes or equals it.
                hl = unsafe { first.offset_from(hostserv) } as usize;
                // SAFETY: `first` points at the non-NUL `:`, so `first + 1` is at
                // or before the terminator.
                p = unsafe { first.add(1) };
                // SAFETY: `p` is a NUL-terminated suffix of `hostserv`.
                pl = unsafe { sys::strlen(p) };
            } else if hostserv_prio == BIO_PARSE_PRIO_HOST {
                h = hostserv;
                // SAFETY: `h` is NUL-terminated.
                hl = unsafe { sys::strlen(h) };
            } else {
                p = hostserv;
                // SAFETY: `p` is NUL-terminated.
                pl = unsafe { sys::strlen(p) };
            }
        }

        // SAFETY: `p` is a non-NULL NUL-terminated suffix of `hostserv`, which is
        // `find_char`'s precondition.
        if !p.is_null() && !unsafe { find_char(p, b':' as c_char) }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_ADDR_593) };
            return 0;
        }

        if !h.is_null() && !host.is_null() {
            // SAFETY: `h` is non-NULL here and `hl == 1` asserts one readable byte,
            // so the `*h` read is in bounds.
            let empty = hl == 0 || (hl == 1 && unsafe { *h } == b'*' as c_char);
            if empty {
                // SAFETY: `host` is writable per the caller's contract.
                unsafe { *host = ptr::null_mut() };
            } else {
                // SAFETY: `h` is readable for `hl` bytes and the duplicate is this call's
                // own seam block until it is handed to the out-parameter.
                let Some(copied) = (unsafe {
                    OwnedStr::adopt(
                        CRYPTO_strndup(h, hl, ALLOC_FILE.as_ptr(), ALLOC_LINE),
                        SeamFile::new(ALLOC_FILE),
                        ALLOC_LINE,
                    )
                }) else {
                    return 0;
                };
                // SAFETY: `host` is writable.
                unsafe { *host = copied.into_raw() };
            }
        }

        if !p.is_null() && !service.is_null() {
            // SAFETY: `p` is non-NULL here and `pl == 1` asserts one readable byte,
            // so the `*p` read is in bounds.
            let empty = pl == 0 || (pl == 1 && unsafe { *p } == b'*' as c_char);
            if empty {
                // SAFETY: `service` is writable per the caller's contract.
                unsafe { *service = ptr::null_mut() };
            } else {
                // SAFETY: `p` is readable for `pl` bytes and the duplicate is this call's
                // own seam block until it is handed to the out-parameter.
                let Some(copied) = (unsafe {
                    OwnedStr::adopt(
                        CRYPTO_strndup(p, pl, ALLOC_FILE.as_ptr(), ALLOC_LINE),
                        SeamFile::new(ALLOC_FILE),
                        ALLOC_LINE,
                    )
                }) else {
                    // The host half, if this call wrote it, is released again; the
                    // out-parameter is left NULL so the caller cannot double-free.
                    //
                    // The `h != NULL` guard is the authority's own (`bio_addr.c`
                    // frees `*host` only when `h != NULL && host != NULL`): with `h ==
                    // NULL` the host branch never ran, so `*host` is the caller's
                    // value and is left untouched.
                    if !h.is_null() && !host.is_null() {
                        // SAFETY: `*host` is writable and was written by the host
                        // branch above, so it is NULL or this call's allocation.
                        let existing = unsafe { *host };
                        // SAFETY: `existing` is NULL or the block `CRYPTO_strndup` produced
                        // above, which this call owns and no one else will release.
                        let owner = unsafe {
                            OwnedStr::adopt(existing, SeamFile::new(ALLOC_FILE), ALLOC_LINE)
                        };
                        if let Some(owner) = owner {
                            drop(owner);
                            // SAFETY: `host` is writable per the caller's contract;
                            // clearing it prevents the caller double-freeing.
                            unsafe { *host = ptr::null_mut() };
                        }
                    }
                    return 0;
                };
                // SAFETY: `service` is writable.
                unsafe { *service = copied.into_raw() };
            }
        }

        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free as free_c;

    fn parse(input: &CStr, prio: c_int) -> (c_int, Option<String>, Option<String>) {
        let mut host: *mut c_char = ptr::null_mut();
        let mut service: *mut c_char = ptr::null_mut();
        // SAFETY: `input` is NUL-terminated and both out-parameters are writable.
        let rc = unsafe { BIO_parse_hostserv(input.as_ptr(), &mut host, &mut service, prio) };
        let take = |p: *mut c_char| -> Option<String> {
            if p.is_null() {
                return None;
            }
            // SAFETY: `p` is a NUL-terminated string from `CRYPTO_strndup`.
            let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
            // SAFETY: the caller owns and no longer uses `p`.
            unsafe { free_c(p.cast::<c_void>(), ALLOC_LOCAL_FILE.as_ptr(), 0) };
            Some(s)
        };
        (rc, take(host), take(service))
    }

    const ALLOC_LOCAL_FILE: &CStr = c"crypto/bio/bio_addr.c";

    #[test]
    fn host_and_service_split_like_the_authority() {
        assert_eq!(
            parse(c"example.com:443", BIO_PARSE_PRIO_HOST),
            (1, Some("example.com".into()), Some("443".into()))
        );
        assert_eq!(
            parse(c"example.com", BIO_PARSE_PRIO_HOST),
            (1, Some("example.com".into()), None)
        );
        assert_eq!(
            parse(c":443", BIO_PARSE_PRIO_HOST),
            (1, None, Some("443".into()))
        );
        assert_eq!(
            parse(c"[::1]:443", BIO_PARSE_PRIO_HOST),
            (1, Some("::1".into()), Some("443".into()))
        );
        assert_eq!(
            parse(c"[::1]", BIO_PARSE_PRIO_HOST),
            (1, Some("::1".into()), None)
        );
        assert_eq!(parse(c"", BIO_PARSE_PRIO_HOST), (1, None, None));
        assert_eq!(parse(c":", BIO_PARSE_PRIO_HOST), (1, None, None));
        // PRIO_SERV reads a bare string as the service.
        assert_eq!(
            parse(c"example.com", BIO_PARSE_PRIO_SERV),
            (1, None, Some("example.com".into()))
        );
        assert_eq!(
            parse(c"host:443", BIO_PARSE_PRIO_SERV),
            (1, Some("host".into()), Some("443".into()))
        );
        // A lone `*` for either half means NULL.
        assert_eq!(
            parse(c"*:443", BIO_PARSE_PRIO_HOST),
            (1, None, Some("443".into()))
        );
        assert_eq!(
            parse(c"host:*", BIO_PARSE_PRIO_HOST),
            (1, Some("host".into()), None)
        );
    }

    #[test]
    fn ambiguous_and_malformed_forms_fail_with_the_authority_reason() {
        // Two colons and no brackets: refused rather than guessed at.
        assert_eq!(parse(c"::1", BIO_PARSE_PRIO_HOST), (0, None, None));
        assert_eq!(parse(c"a:b:c", BIO_PARSE_PRIO_HOST), (0, None, None));
        // Junk after a bracket: refused.
        assert_eq!(parse(c"[::1]x", BIO_PARSE_PRIO_HOST), (0, None, None));
        // A colon in the service half names no service.
        assert_eq!(parse(c"host:a:b", BIO_PARSE_PRIO_HOST), (0, None, None));
    }

    #[test]
    fn a_unix_path_that_cannot_be_terminated_is_refused() {
        // `BIO_ADDR_rawmake` requires `wherelen + 1 <= sizeof(sun_path)`; 107 bytes is the
        // last path length with room for the NUL, and 108 is the first that has none.
        let mut last_fit_bytes = vec![b'a'; 107];
        last_fit_bytes.push(0);
        let mut too_long_bytes = vec![b'a'; 108];
        too_long_bytes.push(0);
        let Ok(last_fit) = CStr::from_bytes_with_nul(&last_fit_bytes) else {
            return;
        };
        let Ok(too_long) = CStr::from_bytes_with_nul(&too_long_bytes) else {
            return;
        };

        let mut res: *mut BioAddrInfo = ptr::null_mut();
        // SAFETY: both paths are NUL-terminated, `res` is writable, and the remaining
        // arguments are the AF_UNIX lookup the authority supports.
        let ok = unsafe {
            BIO_lookup(
                last_fit.as_ptr(),
                ptr::null(),
                BIO_LOOKUP_CLIENT,
                sys::AF_UNIX,
                sys::SOCK_STREAM,
                &mut res,
            )
        };
        assert_eq!(ok, 1);
        assert!(!res.is_null());
        // SAFETY: `res` is the chain this call just built and has not released.
        unsafe { BIO_ADDRINFO_free(res) };

        let mut res: *mut BioAddrInfo = ptr::null_mut();
        // SAFETY: as above; the authority refuses this path and writes NULL to `res`.
        let refused = unsafe {
            BIO_lookup(
                too_long.as_ptr(),
                ptr::null(),
                BIO_LOOKUP_CLIENT,
                sys::AF_UNIX,
                sys::SOCK_STREAM,
                &mut res,
            )
        };
        assert_eq!(refused, 0);
        assert!(res.is_null());
    }

    #[test]
    fn a_host_out_parameter_of_null_still_succeeds() {
        let mut service: *mut c_char = ptr::null_mut();
        // SAFETY: `hostserv` is NUL-terminated, `host` is legitimately NULL, and
        // `service` is writable.
        let rc = unsafe {
            BIO_parse_hostserv(
                c"example.com:443".as_ptr(),
                ptr::null_mut(),
                &mut service,
                0,
            )
        };
        assert_eq!(rc, 1);
        assert!(!service.is_null());
        // SAFETY: `service` is ours to free.
        unsafe { free_c(service.cast::<c_void>(), ALLOC_LOCAL_FILE.as_ptr(), 0) };
    }
}
