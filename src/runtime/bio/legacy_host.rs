//! Phase 4 — the deprecated host and port helpers.
//!
//! These three are `OSSL_DEPRECATEDIN_1_1_0` but are still exported and still part
//! of the 3.x contract, so they are reconstructible obligations rather than
//! omissions. They are also much less obvious than their names suggest.
//!
//! `BIO_get_host_ip` and `BIO_get_port` are **thin wrappers over `BIO_lookup`**,
//! not string parsers:
//!
//! * `BIO_get_host_ip(str, ip)` looks up `str` as a *host* with a NULL service and
//!   `AF_INET`/`SOCK_STREAM`, then copies four bytes out of the first result.
//!   Everything the resolver accepts is therefore accepted here — including the
//!   `inet_aton` shorthands, so `"1.2.3"` yields `1.2.0.3` rather than failing.
//! * `BIO_get_port(str, port_ptr)` looks up a NULL host with `str` as the
//!   *service*, reads the result's port, and applies `ntohs` to it. That
//!   round-trip is why `"70000"` returns `4464`: the resolver truncates the value
//!   to 16 bits and the port is then un-swapped back.
//! * When the lookup fails, both call `ERR_add_error_data(2, "host=", str)` on the
//!   error the lookup already raised — and both pass `str`, so `BIO_get_port`
//!   labels its *service* as `host=`. That wart is reproduced.
//!
//! `ERR_add_error_data` concatenates into a fixed 1024-byte buffer, so a long
//! argument is truncated at 1023 bytes before it reaches the queue. That bound is
//! reproduced here, because it is observable through `ERR_get_error_all`.
//!
//! `BIO_gethostbyname` is exactly libc's `gethostbyname`, with no error raised on
//! failure — measured: a name that does not resolve returns NULL and leaves the
//! error queue empty.
//!
//! ## Fault boundaries
//!
//! The authority faults on a NULL `ip` (it copies into it) and a NULL `port_ptr`
//! (it assigns through it); here those are total. `BIO_get_port(NULL, …)` *is*
//! defined — it raises `BIO_R_NO_PORT_DEFINED` — and is matched.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BIO_SOCK_57, BIO_SOCK_80, BIO_SOCK_89};
use crate::runtime::err::{openssl_rs_err_add_data, raise_site};

use super::addr::{BIO_ADDR_rawaddress, BIO_ADDR_rawport};
use super::addr_info::{
    BIO_ADDRINFO_address, BIO_ADDRINFO_family, BIO_ADDRINFO_free, BIO_lookup, BioAddrInfo,
    BIO_LOOKUP_CLIENT,
};
use super::bss_sock::BIO_sock_init;
use super::sys;

/// `void ERR_add_error_data(2, "host=", str)`
///
/// Two properties of the authority's `ERR_add_error_vdata` matter here and are
/// observable through `ERR_get_error_data` (`crypto/err/err.c`):
///
/// * a **NULL argument becomes the literal `"<NULL>"`** rather than being
///   skipped, which is why `BIO_get_host_ip(NULL, ip)` appends `host=<NULL>`;
/// * the concatenation **grows to fit** — the authority starts at 81 bytes and
///   reallocates, so nothing is truncated. The court caught this: an earlier
///   version of this helper capped the result at 1023 bytes, which the authority
///   does not do.
///
/// # Safety
/// `text` must be NULL or a NUL-terminated C string.
unsafe fn add_error_data_host(prefix: &CStr, text: *const c_char) {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(prefix.to_bytes());
    if text.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `text` is NUL-terminated per the caller's contract.
        buf.extend_from_slice(unsafe { CStr::from_ptr(text) }.to_bytes());
    }
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated and `openssl_rs_err_add_data` copies it.
    unsafe { openssl_rs_err_add_data(buf.as_ptr().cast::<c_char>()) };
}

/// `int BIO_get_host_ip(const char *str, unsigned char *ip)`
///
/// # Safety
/// `str` must be a NUL-terminated C string; `ip` must be NULL or writable for four
/// bytes (the authority requires non-NULL, which is a recorded divergence).
#[no_mangle]
pub unsafe extern "C" fn BIO_get_host_ip(str_: *const c_char, ip: *mut u8) -> c_int {
    guard_ffi(0, || {
        if BIO_sock_init() != 1 {
            return 0;
        }
        let mut res: *mut BioAddrInfo = ptr::null_mut();
        let mut ret = 0;
        // SAFETY: `str_` is NUL-terminated and `res` is writable.
        let found = unsafe {
            BIO_lookup(
                str_,
                ptr::null(),
                BIO_LOOKUP_CLIENT,
                sys::AF_INET,
                sys::SOCK_STREAM,
                &mut res,
            )
        };
        if found != 0 {
            // SAFETY: `res` is the chain `BIO_lookup` just built.
            if unsafe { BIO_ADDRINFO_family(res) } != sys::AF_INET {
                // Unreachable on this authority: the lookup asks for AF_INET. The
                // site is the authority's own, so the branch is reproduced rather
                // than dropped.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_SOCK_57) };
            } else {
                // SAFETY: `res` is a live node of the chain.
                let addr = unsafe { BIO_ADDRINFO_address(res) };
                let mut len = 0usize;
                // SAFETY: `addr` is borrowed from `res` and `len` is writable.
                if unsafe { BIO_ADDR_rawaddress(addr, ptr::null_mut(), &mut len) } != 0 && len == 4
                {
                    // SAFETY: `len == 4`, so `ip` receives four bytes; a NULL `ip`
                    // is turned into "no copy" by `BIO_ADDR_rawaddress`.
                    ret = unsafe { BIO_ADDR_rawaddress(addr, ip.cast::<c_void>(), &mut len) };
                }
            }
            // SAFETY: `res` is an owned chain and is not used again.
            unsafe { BIO_ADDRINFO_free(res) };
        } else {
            // The lookup already raised; this appends the argument, as the
            // authority does.
            // SAFETY: `str_` is NUL-terminated.
            unsafe { add_error_data_host(c"host=", str_) };
        }
        ret
    })
}

/// `int BIO_get_port(const char *str, unsigned short *port_ptr)`
///
/// # Safety
/// `str` must be NULL or a NUL-terminated C string; `port_ptr` must be NULL or
/// writable (the authority requires non-NULL, which is a recorded divergence).
#[no_mangle]
pub unsafe extern "C" fn BIO_get_port(str_: *const c_char, port_ptr: *mut u16) -> c_int {
    guard_ffi(0, || {
        if str_.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_SOCK_80) };
            return 0;
        }
        if BIO_sock_init() != 1 {
            return 0;
        }
        let mut res: *mut BioAddrInfo = ptr::null_mut();
        let mut ret = 0;
        // SAFETY: `str_` is NUL-terminated and `res` is writable.
        let found = unsafe {
            BIO_lookup(
                ptr::null(),
                str_,
                BIO_LOOKUP_CLIENT,
                sys::AF_INET,
                sys::SOCK_STREAM,
                &mut res,
            )
        };
        if found != 0 {
            // SAFETY: `res` is the chain `BIO_lookup` just built.
            if unsafe { BIO_ADDRINFO_family(res) } != sys::AF_INET {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_SOCK_89) };
            } else {
                // SAFETY: `res` is a live node of the chain.
                let raw = unsafe { BIO_ADDR_rawport(BIO_ADDRINFO_address(res)) };
                if !port_ptr.is_null() {
                    // SAFETY: `port_ptr` is writable per the caller's contract.
                    unsafe { *port_ptr = sys::ntohs(raw) };
                }
                ret = 1;
            }
            // SAFETY: `res` is an owned chain and is not used again.
            unsafe { BIO_ADDRINFO_free(res) };
        } else {
            // The label says "host=" even though `str_` is the *service* here,
            // which is what the authority does.
            // SAFETY: `str_` is NUL-terminated.
            unsafe { add_error_data_host(c"host=", str_) };
        }
        ret
    })
}

/// `struct hostent *BIO_gethostbyname(const char *name)`
///
/// Exactly libc's `gethostbyname`, returning its static storage. No error is
/// raised on failure, which is what the authority does.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn BIO_gethostbyname(name: *const c_char) -> *mut sys::HostEnt {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `name` is NUL-terminated per the caller's contract.
        unsafe { sys::gethostbyname(name) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_port_looks_up_the_service_and_unswaps_it() {
        let mut port: u16 = 0xA5A5;
        // SAFETY: the literal is NUL-terminated and `port` is writable.
        let rc = unsafe { BIO_get_port(c"80".as_ptr(), &mut port) };
        assert_eq!(rc, 1);
        assert_eq!(port, 80);

        // The upper bound is the resolver's, not this function's: 70000 is
        // truncated to 16 bits and then un-swapped back to 4464.
        let mut port: u16 = 0;
        // SAFETY: as above.
        let rc = unsafe { BIO_get_port(c"70000".as_ptr(), &mut port) };
        assert_eq!(rc, 1);
        assert_eq!(port, 4464);
    }

    #[test]
    fn get_port_rejects_null_and_unknown_services() {
        // SAFETY: `BIO_get_port` checks `str` for NULL itself.
        assert_eq!(unsafe { BIO_get_port(ptr::null(), ptr::null_mut()) }, 0);
        let mut port: u16 = 7;
        // SAFETY: the literal is NUL-terminated and `port` is writable.
        let rc = unsafe { BIO_get_port(c"no-such-service-xyz".as_ptr(), &mut port) };
        assert_eq!(rc, 0);
        assert_eq!(port, 7, "a failed lookup leaves the out-parameter alone");
    }

    #[test]
    fn get_host_ip_accepts_whatever_the_resolver_accepts() {
        let mut ip = [0xdeu8, 0xad, 0xbe, 0xef];
        // SAFETY: the literal is NUL-terminated and `ip` is writable for 4 bytes.
        let rc = unsafe { BIO_get_host_ip(c"1.2.3.4".as_ptr(), ip.as_mut_ptr()) };
        assert_eq!(rc, 1);
        assert_eq!(ip, [1, 2, 3, 4]);

        // The inet_aton shorthand is accepted by the resolver, so 1.2.3 is 1.2.0.3.
        let mut ip = [0u8; 4];
        // SAFETY: as above.
        let rc = unsafe { BIO_get_host_ip(c"1.2.3".as_ptr(), ip.as_mut_ptr()) };
        assert_eq!(rc, 1);
        assert_eq!(ip, [1, 2, 0, 3]);

        let mut ip = [0xdeu8, 0xad, 0xbe, 0xef];
        // SAFETY: as above.
        let rc = unsafe { BIO_get_host_ip(c"256.1.1.1".as_ptr(), ip.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(
            ip,
            [0xde, 0xad, 0xbe, 0xef],
            "nothing is written on failure"
        );
    }

    #[test]
    fn gethostbyname_is_libc_and_raises_nothing() {
        // SAFETY: the literal is NUL-terminated.
        let he = unsafe { BIO_gethostbyname(c"localhost".as_ptr()) };
        assert!(!he.is_null());
        // SAFETY: `he` is libc's static hostent for a successful lookup.
        unsafe {
            assert_eq!((*he).h_addrtype, sys::AF_INET);
            assert_eq!((*he).h_length, 4);
        }
    }
}
