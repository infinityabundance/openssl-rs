//! Phase 4 — `BIO_ADDR`, the address value type `libssl` and BIO use everywhere.
//!
//! `BIO_ADDR` is opaque (`typedef union bio_addr_st BIO_ADDR`), so the layout is
//! ours; what has to match is the *behaviour*. The authority was measured with
//! `courts/phase4/discover_bio_addr.c` before any of this was written, and several
//! of its behaviours are not what the documentation suggests:
//!
//! * `BIO_ADDR_new()` leaves the family `AF_UNSPEC`, and `BIO_ADDR_rawaddress()`
//!   on an `AF_UNSPEC` address **fails** (`0`) rather than reporting a length.
//! * `BIO_ADDR_rawaddress()` treats `*l` as an **out** parameter: a caller that
//!   passes `*l = 1` gets back `*l = 4` and a 4-byte copy, not a failure. The
//!   caller's contract is that the buffer is large enough (`bio.h` documents 16
//!   bytes as sufficient for any family this type carries), so this is parity and
//!   not a memory-safety divergence.
//! * `BIO_ADDR_rawmake()` validates the family and the `wherelen` **before**
//!   clearing, so a rejected call leaves the previous address intact. Measured:
//!   after a successful `AF_INET` make and a rejected `AF_UNSPEC` make, the family
//!   is still `AF_INET` and the port still the earlier one.
//! * `BIO_ADDR_rawport()` returns a **host-order** port (`ntohs` of the stored
//!   field), which is the useful convention, but `BIO_ADDR_service_string()`
//!   reports the **byte-swapped** value: port 80 prints as `20480`, 443 as
//!   `47873`. The model that reproduces every measured case is that the authority
//!   builds a temporary socket address whose port field receives the *host-order*
//!   value with no `htons`, so `getnameinfo` then un-swaps it. The same model
//!   explains the `AF_UNIX` result, where glibc's `getnameinfo` returns
//!   `"localhost"` for the host and the path for the service.
//! * `BIO_ADDR_path_string()` returns NULL for every family except `AF_UNIX`.
//! * `AF_UNIX` addresses round-trip their path, and `BIO_ADDR_rawport` is `0`.
//!
//! Fault boundaries are recorded, not reproduced (`docs/SECURITY_DIVERGENCE_POLICY.md`):
//! the authority dereferences a NULL argument in `BIO_ADDR_clear`,
//! `BIO_ADDR_rawaddress`, `BIO_ADDR_rawport`, `BIO_ADDR_family`,
//! `BIO_ADDR_hostname_string`, `BIO_ADDR_service_string` and
//! `BIO_ADDR_path_string`, and each case was measured in its own process by
//! `courts/phase4/bio_addr_null_calls.c`. Those entry points here are total: they
//! return the harmless value instead of faulting. `BIO_ADDR_free(NULL)`,
//! `BIO_ADDR_dup(NULL)`, `BIO_ADDR_copy(NULL, ...)` and `BIO_ADDRINFO_next(NULL)`
//! are defined by the authority and are matched exactly.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};

use super::sys;

/// The `file`/`line` recorded by an allocation, mirroring the authority's
/// `__FILE__`/`__LINE__` so a leak report points at this module.
const ALLOC_FILE: &CStr = c"crypto/bio/bio_addr.c";
/// See [`ALLOC_FILE`].
const ALLOC_LINE: c_int = 0;

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

/// Allocate a zeroed address, or NULL if the allocator refused.
fn alloc_zeroed() -> *mut BioAddr {
    // `CRYPTO_malloc` returns NULL or a fresh block of at least the requested
    // size, which is then fully initialised before it is returned.
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

/// `void BIO_ADDR_clear(BIO_ADDR *ap)`
///
/// The authority faults on NULL; this is total by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_clear(ap: *mut BioAddr) {
    guard_ffi((), || {
        // SAFETY: the caller passes NULL or a live address; a NULL payload is
        // unreachable because the pointer itself is only written when non-NULL.
        let Some(a) = (unsafe { ap.as_mut() }) else {
            return;
        };
        // SAFETY: `a` is a live address.
        unsafe {
            sys::memset(
                ptr::from_mut(a).cast::<c_void>(),
                0,
                core::mem::size_of::<BioAddr>(),
            )
        };
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
        // SAFETY: `dst` is a fresh block and `src` is live; they cannot overlap.
        unsafe {
            sys::memcpy(
                dst.cast::<c_void>(),
                ptr::from_ref(src).cast::<c_void>(),
                core::mem::size_of::<BioAddr>(),
            );
        }
        dst
    })
}

/// `int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src)`
///
/// Either argument being NULL fails; matched against the authority.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_copy(dst: *mut BioAddr, src: *const BioAddr) -> c_int {
    guard_ffi(0, || {
        if dst.is_null() || src.is_null() {
            return 0;
        }
        // SAFETY: both pointers are non-NULL and, per the caller's contract, live
        // and distinct.
        unsafe {
            sys::memcpy(
                dst.cast::<c_void>(),
                src.cast::<c_void>(),
                core::mem::size_of::<BioAddr>(),
            );
        }
        1
    })
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
/// the previous address. Ports are stored in network order.
///
/// # Safety
/// `where` must be readable for `wherelen` bytes, and `ap` must be live.
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
                if wherelen != 4 {
                    return 0;
                }
                // SAFETY: `base` is the start of a live `BioAddr`; every field
                // written is inside it, and `where_` is readable for 4 bytes.
                unsafe {
                    sys::memset(base.cast::<c_void>(), 0, core::mem::size_of::<BioAddr>());
                    let sin = base.cast::<sys::SockAddrIn>();
                    (*sin).sin_family = sys::AF_INET as sys::SaFamily;
                    (*sin).sin_port = sys::htons(port);
                    (*sin).sin_addr.s_addr = core::ptr::read_unaligned(where_.cast::<u32>());
                }
                1
            }
            sys::AF_INET6 => {
                if wherelen != 16 {
                    return 0;
                }
                // SAFETY: as above, with a 16-byte read from `where_`.
                unsafe {
                    sys::memset(base.cast::<c_void>(), 0, core::mem::size_of::<BioAddr>());
                    let sin6 = base.cast::<sys::SockAddrIn6>();
                    (*sin6).sin6_family = sys::AF_INET6 as sys::SaFamily;
                    (*sin6).sin6_port = sys::htons(port);
                    sys::memcpy(
                        (*sin6).sin6_addr.s6_addr.as_mut_ptr().cast::<c_void>(),
                        where_,
                        16,
                    );
                }
                1
            }
            sys::AF_UNIX => {
                let max = core::mem::size_of::<sys::SockAddrUn>() - ADDR_OFFSET;
                if wherelen > max {
                    return 0;
                }
                // SAFETY: as above, with a `wherelen`-byte read that the length
                // check above bounds to the destination's capacity.
                unsafe {
                    sys::memset(base.cast::<c_void>(), 0, core::mem::size_of::<BioAddr>());
                    let sun = base.cast::<sys::SockAddrUn>();
                    (*sun).sun_family = sys::AF_UNIX as sys::SaFamily;
                    sys::memcpy(
                        (*sun).sun_path.as_mut_ptr().cast::<c_void>(),
                        where_,
                        wherelen,
                    );
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
/// `l` must be NULL or writable; `p` must be NULL or writable for the length of
/// the address family, which the caller owns (`bio.h` documents 16 bytes).
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
            // `BIO_ADDR_rawmake`, so the address bytes below are initialised.
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
                // The stored path is NUL-terminated and `sun_path` is zeroed by
                // the clear, so the length is the string length, not the capacity.
                (
                    sys::strlen((*sun).sun_path.as_ptr()),
                    (*sun).sun_path.as_ptr().cast::<c_void>(),
                )
            },
            _ => return 0,
        };
        if !l.is_null() {
            // SAFETY: `l` is the caller's out-parameter.
            unsafe { *l = len };
        }
        if !p.is_null() {
            // SAFETY: `p` is writable for `len` bytes per the caller's contract,
            // and `addrptr` points at `len` initialised bytes.
            unsafe { sys::memcpy(p, addrptr, len) };
        }
        1
    })
}

/// `unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)`
///
/// Host order, as the authority returns it. The authority faults on NULL; this
/// returns 0 by policy.
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
                sys::ntohs(
                    base.cast::<sys::SockAddrIn>()
                        .as_ref()
                        .map_or(0, |s| s.sin_port),
                )
            },
            sys::AF_INET6 => unsafe {
                sys::ntohs(
                    base.cast::<sys::SockAddrIn6>()
                        .as_ref()
                        .map_or(0, |s| s.sin6_port),
                )
            },
            _ => 0,
        }
    })
}

/// Format an address through `getnameinfo`, reproducing the authority's inputs.
///
/// The temporary socket address is built with the **host-order** port in the port
/// field, which is what makes `BIO_ADDR_service_string` report a byte-swapped
/// number; see the module comment. `AF_UNIX` is passed through unchanged so that
/// glibc's own `AF_UNIX` handling (`"localhost"` / the path) is observed.
fn getnameinfo_dup(ap: *const BioAddr, want_host: bool, numeric: bool) -> *mut c_char {
    // SAFETY: the caller checked `ap` is live.
    let a = unsafe { &*ap };
    let mut store: sys::SockAddrStorage = sys::SockAddrStorage {
        ss_family: 0,
        __pad: [0; 126],
    };
    let base = ptr::from_mut(&mut store).cast::<u8>();
    match c_int::from(a.sa.ss_family) {
        sys::AF_INET => {
            // SAFETY: `store` is at least as large as `SockAddrIn`.
            unsafe {
                let src = ptr::from_ref(a).cast::<sys::SockAddrIn>().as_ref();
                if let Some(src) = src {
                    let dst = base.cast::<sys::SockAddrIn>();
                    (*dst).sin_family = src.sin_family;
                    (*dst).sin_addr = src.sin_addr;
                    // Deliberate: the raw port value, not `htons`ed. This is what
                    // the authority passes, and it is observable.
                    (*dst).sin_port = sys::ntohs(src.sin_port);
                }
            }
        }
        sys::AF_INET6 => {
            // SAFETY: `store` is at least as large as `SockAddrIn6`.
            unsafe {
                if let Some(src) = ptr::from_ref(a).cast::<sys::SockAddrIn6>().as_ref() {
                    let dst = base.cast::<sys::SockAddrIn6>();
                    (*dst).sin6_family = src.sin6_family;
                    (*dst).sin6_addr = src.sin6_addr;
                    (*dst).sin6_scope_id = src.sin6_scope_id;
                    (*dst).sin6_port = sys::ntohs(src.sin6_port);
                }
            }
        }
        sys::AF_UNIX => {
            // SAFETY: `store` is at least as large as `SockAddrUn`.
            unsafe {
                sys::memcpy(
                    base.cast::<c_void>(),
                    ptr::from_ref(a).cast::<c_void>(),
                    core::mem::size_of::<sys::SockAddrUn>(),
                );
            }
        }
        _ => return ptr::null_mut(),
    }

    let mut host = [0 as c_char; 1025];
    let mut serv = [0 as c_char; 32];
    let flags = match (want_host, numeric) {
        (true, true) => sys::NI_NUMERICHOST,
        (false, true) => sys::NI_NUMERICSERV,
        _ => 0,
    };
    // SAFETY: `store` holds an initialised address of the family in `ss_family`;
    // the output buffers are sized as `getnameinfo` requires.
    let rc = unsafe {
        sys::getnameinfo(
            base.cast::<sys::SockAddr>(),
            core::mem::size_of::<sys::SockAddrStorage>() as sys::SockLen,
            if want_host {
                host.as_mut_ptr()
            } else {
                ptr::null_mut()
            },
            if want_host {
                host.len() as sys::SockLen
            } else {
                0
            },
            if want_host {
                ptr::null_mut()
            } else {
                serv.as_mut_ptr()
            },
            if want_host {
                0
            } else {
                serv.len() as sys::SockLen
            },
            flags,
        )
    };
    if rc != 0 {
        return ptr::null_mut();
    }
    let text = if want_host {
        host.as_ptr()
    } else {
        serv.as_ptr()
    };
    // SAFETY: the buffer `getnameinfo` filled is NUL-terminated by its contract.
    unsafe { CRYPTO_strdup(text, ALLOC_FILE.as_ptr(), ALLOC_LINE) }
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
        getnameinfo_dup(ap, true, numeric != 0)
    })
}

/// `char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric)`
///
/// Reports the byte-swapped port for `AF_INET`/`AF_INET6` and the path for
/// `AF_UNIX`; both are reproduced rather than corrected. The authority faults on
/// NULL; this returns NULL by policy.
#[no_mangle]
pub unsafe extern "C" fn BIO_ADDR_service_string(
    ap: *const BioAddr,
    numeric: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if ap.is_null() {
            return ptr::null_mut();
        }
        getnameinfo_dup(ap, false, numeric != 0)
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
    fn ipv4_round_trips_with_a_host_order_port() {
        let a = BIO_ADDR_new();
        // SAFETY: `a` is live.
        unsafe {
            assert_eq!(make_v4(a, [127, 0, 0, 1], 8080), 1);
            assert_eq!(BIO_ADDR_family(a), sys::AF_INET);
            assert_eq!(BIO_ADDR_rawport(a), 8080);
            let mut buf = [0u8; 16];
            let mut len = buf.len();
            assert_eq!(
                BIO_ADDR_rawaddress(a, buf.as_mut_ptr().cast::<c_void>(), &mut len),
                1
            );
            assert_eq!(len, 4);
            assert_eq!(&buf[..4], &[127, 0, 0, 1]);
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
    fn service_string_reports_the_byte_swapped_port() {
        // Measured against the authority: 80 -> "20480", 443 -> "47873", 1 -> "256".
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
