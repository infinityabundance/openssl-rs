//! Phase 4 — `BIO_ADDR`, the address value type `libssl` and BIO use everywhere.
//!
//! `BIO_ADDR` is opaque (`typedef union bio_addr_st BIO_ADDR`), so the layout is
//! ours; what has to match is the *behaviour*. Every behaviour below was measured
//! against the authority (`courts/phase4/discover_bio_addr.c`) and then confirmed
//! against the pinned source, because the two disagreed with the documentation.
//!
//! ## The port is stored, not converted
//!
//! This is the single most easily-mistaken part of the whole stratum.
//! `BIO_ADDR_rawmake` assigns `sin_port = port` **without `htons`**, and
//! `BIO_ADDR_rawport` returns the field **without `ntohs`**. So a `rawmake`
//! address carries the host-order port in a network-order field. The consequence
//! is that `BIO_ADDR_rawport` *looks* correct — it returns the number the caller
//! passed — while the bytes a socket syscall reads are byte-swapped. Only a
//! socket-layer observation can see it, which is why `RT-BIO-ADDR` alone was not
//! enough and the socket courts exist. See `docs/DECISIONS.md` D37.
//!
//! `BIO_ADDR_service_string` inherits the same asymmetry rather than correcting
//! it: `addr_strings` hands the address to `getnameinfo`, which un-swaps whatever
//! is in the field. So `rawmake(…, 8080)` reports service `"36895"`, while a
//! `BIO_lookup` result for the same port reports `"8080"` — because a lookup
//! address is a *real* `sockaddr` from the resolver and its field holds
//! `htons(8080)`. Both were measured, and both are reproduced.
//!
//! ## Other measured non-obvious behaviour
//!
//! * `BIO_ADDR_new()` leaves the family `AF_UNSPEC`, and `BIO_ADDR_rawaddress()`
//!   on an `AF_UNSPEC` address **fails** (`0`) rather than reporting a length.
//! * `BIO_ADDR_rawaddress()` treats `*l` as an **out** parameter: a caller passing
//!   `*l = 1` gets back `*l = 4` and a 4-byte copy, not the documented failure.
//!   The caller's contract is that the buffer is large enough, so this is parity.
//! * `BIO_ADDR_rawmake()` validates family and length **before** clearing, so a
//!   rejected call leaves the previous address intact.
//! * `AF_UNIX` `rawmake` bounds the length by `wherelen + 1 > sizeof(sun_path)`
//!   but then copies with `strncpy` semantics — that is, to the NUL, ignoring
//!   `wherelen` for the copy itself.
//! * `BIO_ADDR_path_string()` returns NULL for every family except `AF_UNIX`.
//! * `addr_strings` always asks `getnameinfo` for **both** the host and the
//!   service, even when only one is wanted, and on failure raises
//!   `ERR_LIB_BIO`/`ERR_R_SYS_LIB` with `gai_strerror` as data. A NULL result and
//!   a raised error therefore arrive together, which a court that only compares
//!   the returned pointer would miss.
//!
//! ## Fault boundaries
//!
//! Recorded, not reproduced (`docs/SECURITY_DIVERGENCE_POLICY.md`,
//! `D-BIO-ADDR-1`/`D-BIO-ADDR-2`): the authority dereferences a NULL address in
//! `BIO_ADDR_clear`, `BIO_ADDR_rawaddress`, `BIO_ADDR_rawport`, `BIO_ADDR_family`,
//! `BIO_ADDR_hostname_string`, `BIO_ADDR_service_string` and
//! `BIO_ADDR_path_string`, and copies from a NULL `where` in `BIO_ADDR_rawmake`.
//! Those entry points here are total and return the harmless value instead.
//! `BIO_ADDR_free(NULL)`, `BIO_ADDR_dup(NULL)`, `BIO_ADDR_copy(NULL, …)` and
//! `BIO_ADDRINFO_next(NULL)` are defined by the authority and matched exactly.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BIO_ADDR_251, BIO_ADDR_256};
use crate::runtime::err::{raise_site_data, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};

use super::bss_sock::BIO_sock_init;
use super::sys;

/// The `file`/`line` recorded by an allocation, mirroring the authority's
/// `__FILE__`/`__LINE__` so a leak report points at this module.
const ALLOC_FILE: &CStr = c"crypto/bio/bio_addr.c";
/// See [`ALLOC_FILE`].
const ALLOC_LINE: c_int = 0;

/// `NI_MAXHOST` — the host buffer `addr_strings` hands to `getnameinfo`.
const NI_MAXHOST: usize = 1025;
/// `NI_MAXSERV` — the service buffer `addr_strings` hands to `getnameinfo`.
const NI_MAXSERV: usize = 32;

/// `EAI_SYSTEM`: `getnameinfo`/`getaddrinfo` could not report through a name.
const EAI_SYSTEM: c_int = -11;

/// A `BIO_ADDR`: a family plus the largest socket address this stratum stores.
///
/// Opaque to callers, so this is not ABI. `ss_family` is zero (`AF_UNSPEC`) for a
/// newly created address, which is observable through `BIO_ADDR_family`.
#[repr(C)]
pub struct BioAddr {
    /// The stored address. Only the bytes meaningful for the family are read.
    sa: sys::SockAddrStorage,
}

/// The `sin_addr`/`sin6_addr`/`sun_path` region starts after the family word.
const ADDR_OFFSET: usize = 2;

/// # Safety
/// `ap` must be NULL or point at a live [`BioAddr`].
unsafe fn family_of(ap: *const BioAddr) -> c_int {
    match unsafe { ap.as_ref() } {
        // The authority dereferences here; this entry point is total by policy.
        None => sys::AF_UNSPEC,
        Some(a) => c_int::from(a.sa.ss_family),
    }
}

/// `BIO_ADDR_sockaddr_size` — the length `getnameinfo` is told to read.
///
/// # Safety
/// `ap` must point at a live [`BioAddr`].
unsafe fn sockaddr_size(ap: *const BioAddr) -> sys::SockLen {
    match unsafe { family_of(ap) } {
        sys::AF_INET => core::mem::size_of::<sys::SockAddrIn>() as sys::SockLen,
        sys::AF_INET6 => core::mem::size_of::<sys::SockAddrIn6>() as sys::SockLen,
        sys::AF_UNIX => core::mem::size_of::<sys::SockAddrUn>() as sys::SockLen,
        _ => core::mem::size_of::<BioAddr>() as sys::SockLen,
    }
}

/// Allocate a zeroed address, or NULL if the allocator refused.
fn alloc_zeroed() -> *mut BioAddr {
    let raw = CRYPTO_malloc(
        core::mem::size_of::<BioAddr>(),
        ALLOC_FILE.as_ptr(),
        ALLOC_LINE,
    );
    let p = raw.cast::<BioAddr>();
    if !p.is_null() {
        // SAFETY: `p` is a fresh block of `size_of::<BioAddr>()` bytes.
        unsafe { sys::memset(p.cast::<c_void>(), 0, core::mem::size_of::<BioAddr>()) };
    }
    p
}

/// # Safety
/// `p` must be NULL or a pointer returned by [`alloc_zeroed`] that has not been freed.
unsafe fn free_addr(p: *mut BioAddr) {
    if !p.is_null() {
        // SAFETY: `p` came from `CRYPTO_malloc` and has not been freed.
        unsafe { CRYPTO_free(p.cast::<c_void>(), ALLOC_FILE.as_ptr(), ALLOC_LINE) };
    }
}

/// `void BIO_ADDR_clear(BIO_ADDR *ap)`
///
/// The authority faults on NULL; this is total by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_clear(ap: *mut BioAddr) {
    guard_ffi((), || {
        // SAFETY: the caller passes NULL or a live address.
        unsafe { clear_addr(ap) };
    })
}

/// # Safety
/// `ap` must be NULL or point at a live, writable [`BioAddr`].
pub(crate) unsafe fn clear_addr(ap: *mut BioAddr) {
    let Some(a) = (unsafe { ap.as_mut() }) else {
        return;
    };
    // SAFETY: `a` is live. The family word is set to `AF_UNSPEC`, which is zero,
    // so the memset alone would suffice; it is kept explicit because the
    // authority spells it out.
    unsafe {
        sys::memset(
            ptr::from_mut(a).cast::<c_void>(),
            0,
            core::mem::size_of::<BioAddr>(),
        );
        a.sa.ss_family = sys::AF_UNSPEC as sys::SaFamily;
    }
}

/// `BIO_ADDR_make` — fill an address from a `struct sockaddr`.
///
/// Clears the whole address first, then copies exactly the family's sockaddr, so
/// bytes outside that family are zero. Returns 0 for a family the authority does
/// not know.
///
/// # Safety
/// `dst` must be NULL or live and writable; `sa` must be NULL or point at a
/// readable `struct sockaddr` whose family indicates the bytes actually present.
pub(crate) unsafe fn make_from_sockaddr(dst: *mut BioAddr, sa: *const sys::SockAddr) -> c_int {
    if dst.is_null() || sa.is_null() {
        return 0;
    }
    // SAFETY: both pointers are non-NULL and live per the caller's contract.
    unsafe {
        let base = dst.cast::<u8>();
        sys::memset(base.cast::<c_void>(), 0, core::mem::size_of::<BioAddr>());
        match c_int::from((*sa).sa_family) {
            sys::AF_INET => {
                sys::memcpy(
                    base.cast::<c_void>(),
                    sa.cast::<c_void>(),
                    core::mem::size_of::<sys::SockAddrIn>(),
                );
                1
            }
            sys::AF_INET6 => {
                sys::memcpy(
                    base.cast::<c_void>(),
                    sa.cast::<c_void>(),
                    core::mem::size_of::<sys::SockAddrIn6>(),
                );
                1
            }
            sys::AF_UNIX => {
                sys::memcpy(
                    base.cast::<c_void>(),
                    sa.cast::<c_void>(),
                    core::mem::size_of::<sys::SockAddrUn>(),
                );
                1
            }
            _ => 0,
        }
    }
}

/// `BIO_ADDR *BIO_ADDR_new(void)`
#[no_mangle]
pub extern "C" fn BIO_ADDR_new() -> *mut BioAddr {
    guard_ffi(ptr::null_mut(), alloc_zeroed)
}

/// `void BIO_ADDR_free(BIO_ADDR *ap)`
///
/// A NULL argument is a no-op in the authority; matched.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_free(ap: *mut BioAddr) {
    guard_ffi((), || {
        // SAFETY: the caller passes NULL or an owned address.
        unsafe { free_addr(ap) };
    })
}

/// `BIO_ADDR *BIO_ADDR_dup(const BIO_ADDR *ap)`
///
/// A NULL argument yields NULL; matched.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_dup(ap: *const BioAddr) -> *mut BioAddr {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the caller passes NULL or a live address.
        let Some(src) = (unsafe { ap.as_ref() }) else {
            return ptr::null_mut();
        };
        let dst = alloc_zeroed();
        if dst.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `dst` is freshly allocated and `src` is live and distinct.
        let copied = unsafe { copy_addr(dst, src) };
        if copied != 1 {
            // SAFETY: `dst` came from `alloc_zeroed` and has not been published.
            unsafe { free_addr(dst) };
            return ptr::null_mut();
        }
        dst
    })
}

/// `int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src)`
///
/// Either argument being NULL fails; an `AF_UNSPEC` source clears the
/// destination rather than copying; any other family copies that family's
/// sockaddr. Matched against the authority.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_copy(dst: *mut BioAddr, src: *const BioAddr) -> c_int {
    guard_ffi(0, || {
        if dst.is_null() || src.is_null() {
            return 0;
        }
        // SAFETY: both pointers are non-NULL; `src` is live and `dst` is writable
        // per the caller's contract.
        unsafe { copy_addr(dst, &*src) }
    })
}

/// The shared body of `BIO_ADDR_copy`.
///
/// # Safety
/// `dst` must be live and writable and `src` live and readable.
unsafe fn copy_addr(dst: *mut BioAddr, src: *const BioAddr) -> c_int {
    if unsafe { (*src).sa.ss_family } == sys::AF_UNSPEC as sys::SaFamily {
        // SAFETY: `dst` is live and writable.
        unsafe { clear_addr(dst) };
        return 1;
    }
    // SAFETY: `dst` is live and writable; `src.sa` is the address to copy, and
    // both start with the family word so the cast only ever reads that.
    unsafe { make_from_sockaddr(dst, ptr::addr_of!((*src).sa).cast::<sys::SockAddr>()) }
}

/// `int BIO_ADDR_family(const BIO_ADDR *ap)`
///
/// The authority faults on NULL; this returns `AF_UNSPEC` by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_family(ap: *const BioAddr) -> c_int {
    guard_ffi(sys::AF_UNSPEC, || {
        // SAFETY: the caller passes NULL or a live address.
        unsafe { family_of(ap) }
    })
}

/// `int BIO_ADDR_rawmake(BIO_ADDR *ap, int family, const void *where, size_t wherelen, unsigned short port)`
///
/// Validates family and length **before** touching `ap`, so a rejected call keeps
/// the previous address. The port is stored **as given**, without `htons`; see
/// the module comment.
///
/// # Safety
/// `where` must be readable for `wherelen` bytes and, for `AF_UNIX`, its NUL must
/// be within `sizeof(sun_path) - 1` bytes; `ap` must be live.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_rawmake(
    ap: *mut BioAddr,
    family: c_int,
    where_: *const c_void,
    wherelen: usize,
    port: u16,
) -> c_int {
    guard_ffi(0, || {
        let Some(a) = (unsafe { ap.as_mut() }) else {
            return 0;
        };
        if where_.is_null() {
            return 0;
        }
        let base = ptr::from_mut(a).cast::<u8>();
        match family {
            sys::AF_INET => {
                if wherelen != core::mem::size_of::<sys::InAddr>() {
                    return 0;
                }
                // SAFETY: `base` is the start of a live `BioAddr` and every field
                // written lies inside it; `where_` is readable for 4 bytes.
                unsafe {
                    sys::memset(
                        base.cast::<c_void>(),
                        0,
                        core::mem::size_of::<sys::SockAddrIn>(),
                    );
                    let sin = base.cast::<sys::SockAddrIn>();
                    (*sin).sin_family = sys::AF_INET as sys::SaFamily;
                    // Deliberately no `htons`: this is what the authority stores.
                    (*sin).sin_port = port;
                    (*sin).sin_addr.s_addr = ptr::read_unaligned(where_.cast::<u32>());
                }
                1
            }
            sys::AF_INET6 => {
                if wherelen != core::mem::size_of::<sys::In6Addr>() {
                    return 0;
                }
                // SAFETY: as above, with a 16-byte read from `where_`.
                unsafe {
                    sys::memset(
                        base.cast::<c_void>(),
                        0,
                        core::mem::size_of::<sys::SockAddrIn6>(),
                    );
                    let sin6 = base.cast::<sys::SockAddrIn6>();
                    (*sin6).sin6_family = sys::AF_INET6 as sys::SaFamily;
                    (*sin6).sin6_port = port;
                    sys::memcpy(
                        (*sin6).sin6_addr.s6_addr.as_mut_ptr().cast::<c_void>(),
                        where_,
                        16,
                    );
                }
                1
            }
            sys::AF_UNIX => {
                let cap = core::mem::size_of::<sys::SockAddrUn>() - ADDR_OFFSET;
                if wherelen + 1 > cap {
                    return 0;
                }
                // SAFETY: `base` is a live `BioAddr`; the loop below reads from
                // `where_` until its NUL or `cap - 1` bytes, which is exactly what
                // `strncpy(sun_path, where, sizeof(sun_path) - 1)` does. `where_`
                // is a NUL-terminated string per the caller's contract, and the
                // read is bounded to `cap - 1` bytes in the worst case.
                unsafe {
                    sys::memset(
                        base.cast::<c_void>(),
                        0,
                        core::mem::size_of::<sys::SockAddrUn>(),
                    );
                    let sun = base.cast::<sys::SockAddrUn>();
                    (*sun).sun_family = sys::AF_UNIX as sys::SaFamily;
                    let dst = (*sun).sun_path.as_mut_ptr().cast::<u8>();
                    let src = where_.cast::<u8>();
                    let mut i = 0usize;
                    while i < cap - 1 {
                        let byte = *src.add(i);
                        if byte == 0 {
                            break;
                        }
                        *dst.add(i) = byte;
                        i += 1;
                    }
                }
                1
            }
            _ => 0,
        }
    })
}

/// `int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)`
///
/// `*l` is an out parameter: it receives the address length whenever a family is
/// known, and `p` receives the bytes when it is non-NULL. `AF_UNSPEC` fails.
///
/// # Safety
/// `l` must be NULL or writable; `p` must be NULL or writable for the address
/// length of the family, which the caller owns (`bio.h` documents 16 bytes).
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_rawaddress(
    ap: *const BioAddr,
    p: *mut c_void,
    l: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller passes NULL or a live address.
        let Some(a) = (unsafe { ap.as_ref() }) else {
            return 0;
        };
        let base = ptr::from_ref(a).cast::<u8>();
        let (len, addrptr) = match c_int::from(a.sa.ss_family) {
            // SAFETY: for each family the family word was written by
            // `BIO_ADDR_rawmake` or `make_from_sockaddr`, so the address bytes
            // below are initialised.
            sys::AF_INET => unsafe {
                let sin = base.cast::<sys::SockAddrIn>();
                (4usize, ptr::from_ref(&(*sin).sin_addr).cast::<c_void>())
            },
            sys::AF_INET6 => unsafe {
                let sin6 = base.cast::<sys::SockAddrIn6>();
                (16usize, ptr::from_ref(&(*sin6).sin6_addr).cast::<c_void>())
            },
            sys::AF_UNIX => unsafe {
                let sun = base.cast::<sys::SockAddrUn>();
                // The stored path is NUL-terminated and the family's sockaddr was
                // zeroed before the copy, so the length is the string length.
                (
                    sys::strlen((*sun).sun_path.as_ptr()),
                    (*sun).sun_path.as_ptr().cast::<c_void>(),
                )
            },
            _ => return 0,
        };
        if !p.is_null() {
            // SAFETY: `p` is writable for `len` bytes per the caller's contract,
            // and `addrptr` points at `len` initialised bytes.
            unsafe { sys::memcpy(p, addrptr, len) };
        }
        if !l.is_null() {
            // SAFETY: `l` is the caller's out-parameter.
            unsafe { *l = len };
        }
        1
    })
}

/// `unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)`
///
/// Returns the stored field **as stored**, which for a `rawmake` address is the
/// value the caller passed and for a resolver address is in network order. See
/// the module comment. The authority faults on NULL; this returns 0 by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_rawport(ap: *const BioAddr) -> u16 {
    guard_ffi(0, || {
        // SAFETY: the caller passes NULL or a live address.
        let Some(a) = (unsafe { ap.as_ref() }) else {
            return 0;
        };
        let base = ptr::from_ref(a).cast::<u8>();
        match c_int::from(a.sa.ss_family) {
            // SAFETY: the family word implies the corresponding field was set.
            sys::AF_INET => unsafe {
                base.cast::<sys::SockAddrIn>()
                    .as_ref()
                    .map_or(0, |s| s.sin_port)
            },
            sys::AF_INET6 => unsafe {
                base.cast::<sys::SockAddrIn6>()
                    .as_ref()
                    .map_or(0, |s| s.sin6_port)
            },
            _ => 0,
        }
    })
}

/// Write a `u16` as decimal into `dst`, the way the authority's
/// `BIO_snprintf(serv, sizeof(serv), "%d", …)` does.
///
/// # Safety
/// `dst` must be writable for `len` bytes.
unsafe fn write_decimal(dst: *mut c_char, len: usize, value: u16) {
    if len == 0 {
        return;
    }
    let mut digits = [0u8; 5];
    let mut n = 0usize;
    let mut v = value;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let count = core::cmp::min(n + 1, len);
    // SAFETY: `dst` is writable for `len` bytes; at most `count` are written.
    unsafe {
        for i in 0..count - 1 {
            *dst.add(i) = digits[n - 1 - i] as c_char;
        }
        *dst.add(count - 1) = 0;
    }
}

/// `addr_strings` — the shared body of `BIO_ADDR_hostname_string` and
/// `BIO_ADDR_service_string`.
///
/// Always asks `getnameinfo` for both names, as the authority does, and raises on
/// failure. Returns `(ok, hostname, service)`, where an unrequested name is NULL.
///
/// # Safety
/// `ap` must point at a live [`BioAddr`].
unsafe fn addr_strings(
    ap: *const BioAddr,
    numeric: c_int,
    want_host: bool,
    want_service: bool,
) -> (bool, *mut c_char, *mut c_char) {
    if BIO_sock_init() != 1 {
        return (false, ptr::null_mut(), ptr::null_mut());
    }

    let base = unsafe { ptr::addr_of!((*ap).sa) }.cast::<sys::SockAddr>();
    let addrlen = unsafe { sockaddr_size(ap) };
    let flags = if numeric != 0 {
        sys::NI_NUMERICHOST | sys::NI_NUMERICSERV
    } else {
        0
    };

    // The authority initialises both buffers to the empty string, which is what
    // makes its `serv[0] == '\0'` fallback well defined.
    let mut host = [0 as c_char; NI_MAXHOST];
    let mut serv = [0 as c_char; NI_MAXSERV];
    // SAFETY: `base` points at an address of the family in `ss_family` and
    // `addrlen` is that family's size; both output buffers are sized as
    // `getnameinfo` requires.
    let rc = unsafe {
        sys::getnameinfo(
            base,
            addrlen,
            host.as_mut_ptr(),
            NI_MAXHOST as sys::SockLen,
            serv.as_mut_ptr(),
            NI_MAXSERV as sys::SockLen,
            flags,
        )
    };
    if rc != 0 {
        // SAFETY: the site is a compile-time constant and the message is a
        // static NUL-terminated string.
        unsafe {
            if rc == EAI_SYSTEM {
                raise_site_dynamic_data(
                    &BIO_ADDR_251,
                    sys::errno(),
                    c"calling getnameinfo()".as_ptr(),
                );
            } else {
                raise_site_data(&BIO_ADDR_256, sys::gai_strerror(rc));
            }
        }
        return (false, ptr::null_mut(), ptr::null_mut());
    }

    if serv[0] == 0 {
        // SAFETY: `serv` is a 32-byte buffer and the decimal form of a `u16` needs
        // at most six bytes including the terminator.
        unsafe { write_decimal(serv.as_mut_ptr(), NI_MAXSERV, BIO_ADDR_rawport(ap)) };
    }

    // SAFETY: `host` and `serv` are NUL-terminated after a successful
    // `getnameinfo`, or after the decimal fallback above.
    let hostname = unsafe {
        if want_host {
            CRYPTO_strdup(host.as_ptr(), ALLOC_FILE.as_ptr(), ALLOC_LINE)
        } else {
            ptr::null_mut()
        }
    };
    // SAFETY: as above.
    let service = unsafe {
        if want_service {
            CRYPTO_strdup(serv.as_ptr(), ALLOC_FILE.as_ptr(), ALLOC_LINE)
        } else {
            ptr::null_mut()
        }
    };

    if (want_host && hostname.is_null()) || (want_service && service.is_null()) {
        // SAFETY: each is either NULL or a string this function allocated.
        unsafe {
            if !hostname.is_null() {
                CRYPTO_free(hostname.cast::<c_void>(), ALLOC_FILE.as_ptr(), ALLOC_LINE);
            }
            if !service.is_null() {
                CRYPTO_free(service.cast::<c_void>(), ALLOC_FILE.as_ptr(), ALLOC_LINE);
            }
        }
        return (false, ptr::null_mut(), ptr::null_mut());
    }

    (true, hostname, service)
}

/// `char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric)`
///
/// The authority faults on NULL; this returns NULL by policy. The result is
/// `OPENSSL_strdup`-allocated, so the caller frees it with `OPENSSL_free`.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_hostname_string(
    ap: *const BioAddr,
    numeric: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if ap.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ap` is live.
        let (ok, hostname, _) = unsafe { addr_strings(ap, numeric, true, false) };
        if ok {
            hostname
        } else {
            ptr::null_mut()
        }
    })
}

/// `char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)`
///
/// Reports whatever `getnameinfo` makes of the stored port, so a `rawmake`
/// address reports a byte-swapped service while a resolver address does not; both
/// are reproduced. The authority faults on NULL; this returns NULL by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_service_string(
    ap: *const BioAddr,
    numeric: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if ap.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ap` is live.
        let (ok, _, service) = unsafe { addr_strings(ap, numeric, false, true) };
        if ok {
            service
        } else {
            ptr::null_mut()
        }
    })
}

/// `char *BIO_ADDR_path_string(const BIO_ADDR *ap)`
///
/// NULL for every family except `AF_UNIX`. The authority faults on NULL; this
/// returns NULL by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_path_string(ap: *const BioAddr) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the caller passes NULL or a live address.
        let Some(a) = (unsafe { ap.as_ref() }) else {
            return ptr::null_mut();
        };
        if c_int::from(a.sa.ss_family) != sys::AF_UNIX {
            return ptr::null_mut();
        }
        let base = ptr::from_ref(a).cast::<u8>();
        // SAFETY: the family word implies `sun_path` was set and is NUL-terminated.
        let path = unsafe {
            base.cast::<sys::SockAddrUn>()
                .as_ref()
                .map(|u| u.sun_path.as_ptr())
        };
        match path {
            // SAFETY: `sun_path` is a NUL-terminated C string.
            Some(p) => unsafe { CRYPTO_strdup(p, ALLOC_FILE.as_ptr(), ALLOC_LINE) },
            None => ptr::null_mut(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// Copy a returned C string out and free it with the same allocator the
    /// caller would use (`OPENSSL_free` is `CRYPTO_free`).
    fn take(p: *mut c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: `p` is a NUL-terminated string allocated by `CRYPTO_strdup`.
        let text = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        // SAFETY: `p` came from `CRYPTO_strdup` and is not used afterwards.
        unsafe { CRYPTO_free(p.cast::<c_void>(), ALLOC_FILE.as_ptr(), ALLOC_LINE) };
        Some(text)
    }

    fn make_v4(a: *mut BioAddr, addr: [u8; 4], port: u16) -> c_int {
        // SAFETY: `a` is a live address and `addr` is readable for 4 bytes.
        unsafe { BIO_ADDR_rawmake(a, sys::AF_INET, addr.as_ptr().cast::<c_void>(), 4, port) }
    }

    #[test]
    fn a_fresh_address_is_af_unspec_with_no_address() {
        let a = BIO_ADDR_new();
        assert!(!a.is_null());
        // SAFETY: `a` came from `BIO_ADDR_new`.
        unsafe {
            assert_eq!(BIO_ADDR_family(a), sys::AF_UNSPEC);
            assert_eq!(BIO_ADDR_rawport(a), 0);
            let mut len = 12345usize;
            let mut buf = [0u8; 16];
            assert_eq!(
                BIO_ADDR_rawaddress(a, buf.as_mut_ptr().cast::<c_void>(), &mut len),
                0
            );
            assert_eq!(len, 12345, "a failing rawaddress must not touch *l");
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn ipv4_round_trips_with_the_port_stored_verbatim() {
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live.
        unsafe {
            assert_eq!(make_v4(a, [127, 0, 0, 1], 8080), 1);
            assert_eq!(BIO_ADDR_family(a), sys::AF_INET);
            // The authority stores the port without `htons` and returns the field
            // without `ntohs`, so this reads back the caller's own value.
            assert_eq!(BIO_ADDR_rawport(a), 8080);
            let mut buf = [0u8; 16];
            let mut len = buf.len();
            assert_eq!(
                BIO_ADDR_rawaddress(a, buf.as_mut_ptr().cast::<c_void>(), &mut len),
                1
            );
            assert_eq!(len, 4);
            assert_eq!(&buf[..4], &[127, 0, 0, 1]);
            // The *stored field* is the observable the socket layer sees; it is
            // `htons(8080)` only in a resolver-built address.
            assert_eq!((*a.cast::<sys::SockAddrIn>()).sin_port, 8080);
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn a_rejected_rawmake_leaves_the_previous_address_intact() {
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live.
        unsafe {
            assert_eq!(make_v4(a, [10, 0, 0, 1], 1234), 1);
            let four = [10u8, 0, 0, 2];
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_INET, four.as_ptr().cast(), 3, 0),
                0
            );
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_UNSPEC, four.as_ptr().cast(), 4, 0),
                0
            );
            assert_eq!(BIO_ADDR_rawmake(a, 999, four.as_ptr().cast(), 4, 0), 0);
            assert_eq!(BIO_ADDR_family(a), sys::AF_INET);
            assert_eq!(BIO_ADDR_rawport(a), 1234);
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn service_string_unswaps_whatever_is_in_the_port_field() {
        // Measured against the authority: a rawmake address with 80 reports
        // "20480", with 443 "47873", with 1 "256" -- because `getnameinfo`
        // un-swaps a field that already holds the host-order value.
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live for the whole block.
        unsafe {
            for (port, expected) in [(80u16, "20480"), (443, "47873"), (1, "256"), (0, "0")] {
                assert_eq!(make_v4(a, [127, 0, 0, 1], port), 1);
                assert_eq!(
                    take(BIO_ADDR_service_string(a, 1)).as_deref(),
                    Some(expected)
                );
            }
            assert_eq!(make_v4(a, [127, 0, 0, 1], 80), 1);
            assert_eq!(
                take(BIO_ADDR_hostname_string(a, 1)).as_deref(),
                Some("127.0.0.1")
            );
            assert_eq!(BIO_ADDR_path_string(a), ptr::null_mut());
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn a_resolver_shaped_address_reports_the_network_order_port() {
        // The other side of the same asymmetry: an address whose field holds the
        // network-order port reports the *correct* service and a swapped rawport.
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live, and `sa` is a fully initialised `sockaddr_in`.
        unsafe {
            let mut sa: sys::SockAddrIn = core::mem::zeroed();
            sa.sin_family = sys::AF_INET as sys::SaFamily;
            sa.sin_port = sys::htons(8080);
            // `s_addr`'s *memory* bytes are the network-order address, so a
            // native-endian read of the dotted quad is what puts 127.0.0.1 there.
            sa.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            assert_eq!(
                make_from_sockaddr(a, ptr::from_ref(&sa).cast::<sys::SockAddr>()),
                1
            );
            assert_eq!(BIO_ADDR_rawport(a), 36895, "the field read verbatim");
            assert_eq!(take(BIO_ADDR_service_string(a, 1)).as_deref(), Some("8080"));
            assert_eq!(
                take(BIO_ADDR_hostname_string(a, 1)).as_deref(),
                Some("127.0.0.1")
            );
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn unix_addresses_carry_their_path() {
        let a = BIO_ADDR_new();
        let path = c"/tmp/openssl-rs.sock";
        // SAFETY: `a` is live and `path` is a NUL-terminated literal.
        unsafe {
            let bytes = path.to_bytes_with_nul();
            assert_eq!(
                BIO_ADDR_rawmake(
                    a,
                    sys::AF_UNIX,
                    bytes.as_ptr().cast::<c_void>(),
                    bytes.len(),
                    0
                ),
                1
            );
            assert_eq!(BIO_ADDR_family(a), sys::AF_UNIX);
            assert_eq!(BIO_ADDR_rawport(a), 0);
            assert_eq!(
                take(BIO_ADDR_path_string(a)).as_deref(),
                Some("/tmp/openssl-rs.sock")
            );
            assert_eq!(
                take(BIO_ADDR_service_string(a, 1)).as_deref(),
                Some("/tmp/openssl-rs.sock")
            );
            let mut len = 0usize;
            assert_eq!(BIO_ADDR_rawaddress(a, ptr::null_mut(), &mut len), 1);
            assert_eq!(len, bytes.len() - 1, "the path length excludes the NUL");
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn unix_rawmake_ignores_wherelen_for_the_copy_but_bounds_it() {
        // `strncpy` semantics: the copy runs to the NUL, so a `wherelen` shorter
        // than the string does not truncate it, while a `wherelen` that would
        // overflow `sun_path` is rejected outright.
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live and the literal is NUL-terminated.
        unsafe {
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_UNIX, c"/tmp/abc".as_ptr().cast(), 4, 0),
                1
            );
            assert_eq!(take(BIO_ADDR_path_string(a)).as_deref(), Some("/tmp/abc"));

            // No NUL inside `sun_path - 1` bytes: the copy fills the field even
            // though only 4 bytes were declared readable, which is what `strncpy`
            // does and is why `wherelen` is only a bound, not a length.
            let long = [b'x'; 110];
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_UNIX, long.as_ptr().cast(), 4, 0),
                1
            );
            let path = take(BIO_ADDR_path_string(a)).expect("a path");
            assert_eq!(path.len(), 107, "copied to the destination's capacity");

            // The bound itself is `wherelen + 1 > sizeof(sun_path)`, so 107 is
            // the largest accepted value and 108 is refused.
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_UNIX, long.as_ptr().cast(), 107, 0),
                1
            );
            assert_eq!(
                BIO_ADDR_rawmake(a, sys::AF_UNIX, long.as_ptr().cast(), 108, 0),
                0
            );
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn clear_duplicate_and_copy_agree_with_the_authority() {
        let a = BIO_ADDR_new();
        // SAFETY: every pointer below is live for the whole block.
        unsafe {
            assert_eq!(make_v4(a, [192, 0, 2, 7], 4660), 1);

            let dup = BIO_ADDR_dup(a);
            assert!(!dup.is_null() && dup != a);
            assert_eq!(BIO_ADDR_family(dup), sys::AF_INET);
            assert_eq!(BIO_ADDR_rawport(dup), 4660);

            BIO_ADDR_clear(dup);
            assert_eq!(BIO_ADDR_family(dup), sys::AF_UNSPEC);
            assert_eq!(BIO_ADDR_rawport(dup), 0);

            assert_eq!(BIO_ADDR_copy(dup, a), 1);
            assert_eq!(BIO_ADDR_rawport(dup), 4660);

            // An AF_UNSPEC source clears rather than failing.
            let empty = BIO_ADDR_new();
            assert_eq!(BIO_ADDR_copy(dup, empty), 1);
            assert_eq!(BIO_ADDR_family(dup), sys::AF_UNSPEC);
            BIO_ADDR_free(empty);

            BIO_ADDR_free(dup);
            BIO_ADDR_free(a);
        }
    }

    #[test]
    fn the_defined_null_arguments_survive_and_the_undefined_ones_are_total() {
        // Authority-defined: free(NULL) is a no-op, dup(NULL) is NULL,
        // copy(NULL, ...) is 0.
        // SAFETY: the authority-defined cases pass NULL; the total cases are the
        // candidate's safe behaviour, which is what is being asserted.
        unsafe {
            BIO_ADDR_free(ptr::null_mut());
            assert!(BIO_ADDR_dup(ptr::null()).is_null());
            let a = BIO_ADDR_new();
            assert_eq!(BIO_ADDR_copy(ptr::null_mut(), a), 0);
            assert_eq!(BIO_ADDR_copy(a, ptr::null()), 0);
            BIO_ADDR_free(a);

            assert_eq!(BIO_ADDR_family(ptr::null()), sys::AF_UNSPEC);
            assert_eq!(BIO_ADDR_rawport(ptr::null()), 0);
            assert_eq!(
                BIO_ADDR_rawaddress(ptr::null(), ptr::null_mut(), ptr::null_mut()),
                0
            );
            assert!(BIO_ADDR_hostname_string(ptr::null(), 1).is_null());
            assert!(BIO_ADDR_service_string(ptr::null(), 1).is_null());
            assert!(BIO_ADDR_path_string(ptr::null()).is_null());
            BIO_ADDR_clear(ptr::null_mut());
        }
    }
}
