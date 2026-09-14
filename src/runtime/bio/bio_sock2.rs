//! Phase 4 — the socket-layer entry points.
//!
//! `BIO_socket`, `BIO_connect`, `BIO_bind` and `BIO_listen` are the documented way
//! to build a socket for `libssl` without going through a BIO at all, and the three
//! deprecated helpers (`BIO_get_accept_socket`, `BIO_accept`, `BIO_set_tcp_ndelay`)
//! are still exported. Together with `BIO_sock_info` they are the only part of BIO
//! that hands a raw file descriptor to the caller, which makes them the layer where
//! `BIO_ADDR`'s stored bytes become *observable*: `BIO_bind` and `BIO_connect` pass
//! the address straight to a syscall, so a port stored in the wrong order binds or
//! connects to the wrong port. That is why D37's correction needed this court and
//! not the `BIO_ADDR` one.
//!
//! Three patterns are worth knowing before reading the bodies, because they are the
//! contract rather than incidental style:
//!
//! * **A syscall failure raises two errors.** The authority raises
//!   `ERR_LIB_SYS` with the current `errno` and the text `"calling …()"`, *then*
//!   raises `ERR_LIB_BIO` with its own reason. Both are on the queue, so a probe has
//!   to drain it to compare them; observing only `ERR_peek_error` would see the
//!   first one and stop.
//! * **A retryable failure raises nothing.** `BIO_connect` and `BIO_accept_ex` ask
//!   `BIO_sock_should_retry` first, so a non-blocking connect in progress returns
//!   failure with an *empty* error queue. An implementation that raised
//!   unconditionally would look correct in a blocking test and differ here.
//! * **`-1` is the invalid socket, and it is not always an error.** `BIO_accept`
//!   returns `-2` for a retryable failure, which is neither a descriptor nor the
//!   failure the caller might assume.
//!
//! Configuration notes, all from the admitted build record rather than from the
//! platform: the authority was configured `no-tfo`, so **every** TCP-Fast-Open
//! branch in this file is compiled out — `OSSL_TFO_*` is guarded by
//! `TCP_FASTOPEN && !OPENSSL_NO_TFO`, and the option is disabled. The kernel
//! headers define `TCP_FASTOPEN` and `TCP_FASTOPEN_CONNECT`, so inferring the
//! profile from the headers alone gives the wrong answer; the build record does
//! not. `no-ktls` is set for the same build, and it is why nothing here consults
//! the kernel-TLS options either.
//!
//! What *is* live, from the container's headers: `IPV6_V6ONLY`, `SO_TYPE`,
//! `SOL_TCP` and `FIONBIO`, and their constants are the platform's (`SOMAXCONN`
//! in particular is 4096 here, not the 128 a reader might assume).

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BIO_SOCK2_108, BIO_SOCK2_110, BIO_SOCK2_183, BIO_SOCK2_185, BIO_SOCK2_215, BIO_SOCK2_228,
    BIO_SOCK2_230, BIO_SOCK2_237, BIO_SOCK2_239, BIO_SOCK2_291, BIO_SOCK2_299, BIO_SOCK2_301,
    BIO_SOCK2_312, BIO_SOCK2_314, BIO_SOCK2_323, BIO_SOCK2_325, BIO_SOCK2_341, BIO_SOCK2_343,
    BIO_SOCK2_353, BIO_SOCK2_355, BIO_SOCK2_430, BIO_SOCK2_432, BIO_SOCK2_51, BIO_SOCK2_53,
    BIO_SOCK2_86, BIO_SOCK2_97, BIO_SOCK2_99, BIO_SOCK_301, BIO_SOCK_303, BIO_SOCK_314,
    BIO_SOCK_410, BIO_SOCK_412, BIO_SOCK_416, BIO_SOCK_421,
};
use crate::runtime::err::{raise_site, raise_site_dynamic_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::addr::{
    sockaddr, sockaddr_noconst, sockaddr_size, zeroed, BIO_ADDR_family, BIO_ADDR_hostname_string,
    BIO_ADDR_service_string, BioAddr,
};
use super::addr_info::{
    BIO_ADDRINFO_address, BIO_ADDRINFO_family, BIO_ADDRINFO_free, BIO_ADDRINFO_protocol,
    BIO_ADDRINFO_socktype, BIO_lookup, BioAddrInfo, BIO_LOOKUP_SERVER, BIO_PARSE_PRIO_SERV,
};
use super::bss_sock::{BIO_closesocket, BIO_sock_init, BIO_sock_should_retry, BIO_socket_nbio};
use super::sys;

/// `INVALID_SOCKET`.
const INVALID_SOCKET: c_int = -1;

/// `int BIO_socket(int domain, int socktype, int protocol, int options)`
///
/// `options` is accepted and unused, as in the authority.
#[no_mangle]
pub extern "C" fn BIO_socket(
    domain: c_int,
    socktype: c_int,
    protocol: c_int,
    _options: c_int,
) -> c_int {
    guard_ffi(INVALID_SOCKET, || {
        if BIO_sock_init() != 1 {
            return INVALID_SOCKET;
        }
        // SAFETY: `socket` is a direct syscall wrapper with no pointer arguments.
        let fd = unsafe { sys::socket(domain, socktype, protocol) };
        if fd == -1 {
            // SAFETY: the sites are compile-time constants and the message is a
            // static NUL-terminated string.
            unsafe {
                raise_site_dynamic_data(&BIO_SOCK2_51, sys::errno(), c"calling socket()".as_ptr());
                raise_site(&BIO_SOCK2_53);
            }
            return INVALID_SOCKET;
        }
        fd
    })
}

/// The `setsockopt` failure shape both `BIO_connect` and `BIO_listen` use.
///
/// # Safety
/// The two sites are compile-time constants and `msg` must be a static
/// NUL-terminated string.
unsafe fn raise_setsockopt(
    sys_site: &crate::runtime::err::err_sites::ErrSite,
    bio_site: &crate::runtime::err::err_sites::ErrSite,
    msg: *const c_char,
) {
    // SAFETY: the sites are compile-time constants and `msg` is a static string.
    unsafe {
        raise_site_dynamic_data(sys_site, sys::errno(), msg);
        raise_site(bio_site);
    }
}

/// `int BIO_connect(int sock, const BIO_ADDR *addr, int options)`
///
/// # Safety
/// `addr` must be NULL or point at a live [`BioAddr`].
#[no_mangle]
pub unsafe extern "C" fn BIO_connect(sock: c_int, addr: *const BioAddr, options: c_int) -> c_int {
    guard_ffi(0, || {
        if sock == INVALID_SOCKET {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_SOCK2_86) };
            return 0;
        }
        if BIO_socket_nbio(sock, c_int::from((options & sys::BIO_SOCK_NONBLOCK) != 0)) == 0 {
            return 0;
        }
        let on: c_int = 1;
        if options & sys::BIO_SOCK_KEEPALIVE != 0 {
            // SAFETY: `on` is readable for its own size.
            let rc = unsafe {
                sys::setsockopt(
                    sock,
                    sys::SOL_SOCKET,
                    sys::SO_KEEPALIVE,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if rc != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_97,
                        &BIO_SOCK2_99,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        if options & sys::BIO_SOCK_NODELAY != 0 {
            // SAFETY: `on` is readable for its own size.
            let rc = unsafe {
                sys::setsockopt(
                    sock,
                    sys::IPPROTO_TCP,
                    sys::TCP_NODELAY,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if rc != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_108,
                        &BIO_SOCK2_110,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        // `BIO_SOCK_TFO` is inert in this build profile: the authority was
        // configured `no-tfo`, so the fast-open branch does not exist and the
        // option is simply carried in `options` to `connect(2)` and below.
        // SAFETY: `addr` is NULL or live, and `sockaddr_size` reads only its family
        // word and the bytes that family implies.
        let rc = unsafe { sys::connect(sock, sockaddr(addr), sockaddr_size(addr)) };
        if rc == -1 {
            // A retryable failure is not an error, and raises nothing.
            if BIO_sock_should_retry(-1) == 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_183,
                        &BIO_SOCK2_185,
                        c"calling connect()".as_ptr(),
                    )
                };
            }
            return 0;
        }
        1
    })
}

/// `int BIO_bind(int sock, const BIO_ADDR *addr, int options)`
///
/// # Safety
/// `addr` must be NULL or point at a live [`BioAddr`].
#[no_mangle]
pub unsafe extern "C" fn BIO_bind(sock: c_int, addr: *const BioAddr, options: c_int) -> c_int {
    guard_ffi(0, || {
        if sock == INVALID_SOCKET {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_SOCK2_215) };
            return 0;
        }
        let on: c_int = 1;
        if options & sys::BIO_SOCK_REUSEADDR != 0 {
            // SAFETY: `on` is readable for its own size.
            let rc = unsafe {
                sys::setsockopt(
                    sock,
                    sys::SOL_SOCKET,
                    sys::SO_REUSEADDR,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if rc != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_228,
                        &BIO_SOCK2_230,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        // SAFETY: `addr` is NULL or live; `sockaddr_size` reads only what the
        // family implies.
        let rc = unsafe { sys::bind(sock, sockaddr(addr), sockaddr_size(addr)) };
        if rc != 0 {
            // SAFETY: as above. The authority notes errno "may be 0" here, and
            // passes it through either way.
            unsafe { raise_setsockopt(&BIO_SOCK2_237, &BIO_SOCK2_239, c"calling bind()".as_ptr()) };
            return 0;
        }
        1
    })
}

/// `int BIO_listen(int sock, const BIO_ADDR *addr, int options)`
///
/// # Safety
/// `addr` must be NULL or point at a live [`BioAddr`].
#[no_mangle]
pub unsafe extern "C" fn BIO_listen(sock: c_int, addr: *const BioAddr, options: c_int) -> c_int {
    guard_ffi(0, || {
        if sock == INVALID_SOCKET {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_SOCK2_291) };
            return 0;
        }
        let mut socktype: c_int = 0;
        let mut socktype_len = core::mem::size_of::<c_int>() as sys::SockLen;
        // SAFETY: the out-parameters are writable for the sizes passed.
        let rc = unsafe {
            sys::getsockopt(
                sock,
                sys::SOL_SOCKET,
                sys::SO_TYPE,
                ptr::addr_of_mut!(socktype).cast(),
                ptr::addr_of_mut!(socktype_len),
            )
        };
        if rc != 0 || socktype_len != core::mem::size_of::<c_int>() as sys::SockLen {
            // SAFETY: as for the other syscall failures.
            unsafe {
                raise_setsockopt(
                    &BIO_SOCK2_299,
                    &BIO_SOCK2_301,
                    c"calling getsockopt()".as_ptr(),
                )
            };
            return 0;
        }
        if BIO_socket_nbio(sock, c_int::from((options & sys::BIO_SOCK_NONBLOCK) != 0)) == 0 {
            return 0;
        }
        let mut on: c_int = 1;
        if options & sys::BIO_SOCK_KEEPALIVE != 0 {
            // SAFETY: `on` is readable for its own size.
            let r = unsafe {
                sys::setsockopt(
                    sock,
                    sys::SOL_SOCKET,
                    sys::SO_KEEPALIVE,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if r != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_312,
                        &BIO_SOCK2_314,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        if options & sys::BIO_SOCK_NODELAY != 0 {
            // SAFETY: `on` is readable for its own size.
            let r = unsafe {
                sys::setsockopt(
                    sock,
                    sys::IPPROTO_TCP,
                    sys::TCP_NODELAY,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if r != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_323,
                        &BIO_SOCK2_325,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        // Linux sets `IPV6_V6ONLY` explicitly because its default differs from
        // Windows'.
        // SAFETY: `addr` is NULL or a live address, which `BIO_ADDR_family`
        // handles.
        if unsafe { BIO_ADDR_family(addr) } == sys::AF_INET6 {
            on = c_int::from((options & sys::BIO_SOCK_V6_ONLY) != 0);
            // SAFETY: `on` is readable for its own size.
            let r = unsafe {
                sys::setsockopt(
                    sock,
                    sys::IPPROTO_IPV6,
                    sys::IPV6_V6ONLY,
                    ptr::addr_of!(on).cast(),
                    core::mem::size_of::<c_int>() as sys::SockLen,
                )
            };
            if r != 0 {
                // SAFETY: as above.
                unsafe {
                    raise_setsockopt(
                        &BIO_SOCK2_341,
                        &BIO_SOCK2_343,
                        c"calling setsockopt()".as_ptr(),
                    )
                };
                return 0;
            }
        }
        // `BIO_bind` is called with the *same* options, so `BIO_SOCK_REUSEADDR`
        // reaches it from here.
        // SAFETY: `addr` is NULL or a live address, as for the family read above.
        if unsafe { BIO_bind(sock, addr, options) } == 0 {
            return 0;
        }
        if socktype != sys::SOCK_DGRAM {
            // SAFETY: `sock` is a live descriptor.
            let r = unsafe { sys::listen(sock, sys::SOMAXCONN) };
            if r == -1 {
                // SAFETY: as for the other syscall failures.
                unsafe {
                    raise_setsockopt(&BIO_SOCK2_353, &BIO_SOCK2_355, c"calling listen()".as_ptr())
                };
                return 0;
            }
        }
        // The server-side fast-open `setsockopt` after `listen(2)` is compiled out
        // by the same `no-tfo`.
        1
    })
}

/// `int BIO_accept_ex(int accept_sock, BIO_ADDR *addr_, int options)`
///
/// # Safety
/// `addr_` must be NULL or point at a live, writable [`BioAddr`].
#[no_mangle]
pub unsafe extern "C" fn BIO_accept_ex(
    accept_sock: c_int,
    addr_: *mut BioAddr,
    options: c_int,
) -> c_int {
    guard_ffi(INVALID_SOCKET, || {
        // The authority keeps a local `BIO_ADDR` and points at it when the caller
        // passes NULL. Its local is uninitialised; zeroing is equivalent here
        // because `accept` overwrites the family's sockaddr and nothing else reads it.
        let mut local = zeroed();
        let addr = if addr_.is_null() {
            ptr::addr_of_mut!(local)
        } else {
            addr_
        };
        let mut len = core::mem::size_of::<BioAddr>() as sys::SockLen;

        // SAFETY: `addr` is live and writable for `len` bytes, which is the size of
        // the storage `accept` will fill.
        let accepted =
            unsafe { sys::accept(accept_sock, sockaddr_noconst(addr), ptr::addr_of_mut!(len)) };
        if accepted == INVALID_SOCKET {
            if BIO_sock_should_retry(accepted) == 0 {
                // SAFETY: the sites are compile-time constants and the message is
                // a static string.
                unsafe {
                    raise_site_dynamic_data(
                        &BIO_SOCK2_430,
                        sys::errno(),
                        c"calling accept()".as_ptr(),
                    );
                    raise_site(&BIO_SOCK2_432);
                }
            }
            return INVALID_SOCKET;
        }
        if BIO_socket_nbio(
            accepted,
            c_int::from((options & sys::BIO_SOCK_NONBLOCK) != 0),
        ) == 0
        {
            // The authority closes through `BIO_closesocket`, which is a safe call.
            BIO_closesocket(accepted);
            return INVALID_SOCKET;
        }
        accepted
    })
}

/// `int BIO_sock_info(int sock, enum BIO_sock_info_type type, union BIO_sock_info_u *info)`
///
/// # Safety
/// For `BIO_SOCK_INFO_ADDRESS`, `info` must be a writable `union BIO_sock_info_u`
/// whose `addr` member points at a live, writable [`BioAddr`].
#[no_mangle]
pub unsafe extern "C" fn BIO_sock_info(
    sock: c_int,
    type_: c_int,
    info: *mut SockInfoUnion,
) -> c_int {
    guard_ffi(0, || {
        match type_ {
            BIO_SOCK_INFO_ADDRESS => {
                if info.is_null() {
                    // The authority dereferences `info->addr`; total by policy.
                    return 0;
                }
                // SAFETY: `info` is a writable union per the caller's contract.
                let addr = unsafe { (*info).addr };
                if addr.is_null() {
                    // The authority forms `&addr->sa` from a NULL address and hands
                    // it to `getsockname`; total by policy.
                    return 0;
                }
                let mut addr_len = core::mem::size_of::<BioAddr>() as sys::SockLen;
                // SAFETY: `addr` is live and writable for `addr_len` bytes.
                let rc = unsafe {
                    sys::getsockname(sock, sockaddr_noconst(addr), ptr::addr_of_mut!(addr_len))
                };
                if rc == -1 {
                    // SAFETY: the sites are compile-time constants.
                    unsafe {
                        raise_site_dynamic_data(
                            &BIO_SOCK_410,
                            sys::errno(),
                            c"calling getsockname()".as_ptr(),
                        );
                        raise_site(&BIO_SOCK_412);
                    }
                    return 0;
                }
                if addr_len as usize > core::mem::size_of::<BioAddr>() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&BIO_SOCK_416) };
                    return 0;
                }
                1
            }
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_SOCK_421) };
                0
            }
        }
    })
}

/// `union BIO_sock_info_u` — one member, `BIO_ADDR *addr`.
#[repr(C)]
pub struct SockInfoUnion {
    /// The address the caller allocated for `BIO_sock_info` to fill in.
    pub addr: *mut BioAddr,
}

/// `BIO_SOCK_INFO_ADDRESS`.
pub const BIO_SOCK_INFO_ADDRESS: c_int = 0;

/// `int BIO_set_tcp_ndelay(int s, int on)`
///
/// Raises nothing: the return value is the only report.
#[no_mangle]
pub extern "C" fn BIO_set_tcp_ndelay(s: c_int, on: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `on` is readable for its own size.
        let rc = unsafe {
            sys::setsockopt(
                s,
                sys::SOL_TCP,
                sys::TCP_NODELAY,
                ptr::addr_of!(on).cast(),
                core::mem::size_of::<c_int>() as sys::SockLen,
            )
        };
        c_int::from(rc == 0)
    })
}

/// `int BIO_get_accept_socket(char *host, int bind_mode)`
///
/// # Safety
/// `host` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn BIO_get_accept_socket(host: *mut c_char, bind_mode: c_int) -> c_int {
    guard_ffi(INVALID_SOCKET, || {
        let mut h: *mut c_char = ptr::null_mut();
        let mut p: *mut c_char = ptr::null_mut();
        let mut res: *mut BioAddrInfo = ptr::null_mut();

        // SAFETY: `host` is NUL-terminated and both out-parameters are writable.
        // Note the priority: this helper reads the string as `service:host` order,
        // which is `BIO_PARSE_PRIO_SERV`.
        let parsed = unsafe {
            super::addr_info::BIO_parse_hostserv(host, &mut h, &mut p, BIO_PARSE_PRIO_SERV)
        };
        if parsed == 0 {
            // The parse raised, and the authority returns without freeing because
            // its out-parameters were never written.
            return INVALID_SOCKET;
        }

        if BIO_sock_init() != 1 {
            // SAFETY: each temporary is NULL or owned by this function.
            return unsafe { cleanup_res(INVALID_SOCKET, res, h, p) };
        }

        // SAFETY: `h` and `p` are NULL or NUL-terminated, and `res` is writable.
        let found = unsafe {
            BIO_lookup(
                h,
                p,
                BIO_LOOKUP_SERVER,
                sys::AF_UNSPEC,
                sys::SOCK_STREAM,
                &mut res,
            )
        };
        if found == 0 {
            // SAFETY: each temporary is NULL or owned by this function.
            return unsafe { cleanup_res(INVALID_SOCKET, res, h, p) };
        }

        // SAFETY: `res` is a live chain whose accessors are total on NULL.
        let s = BIO_socket(
            unsafe { BIO_ADDRINFO_family(res) },
            unsafe { BIO_ADDRINFO_socktype(res) },
            unsafe { BIO_ADDRINFO_protocol(res) },
            0,
        );
        if s == INVALID_SOCKET {
            // SAFETY: each temporary is NULL or owned by this function.
            return unsafe { cleanup_res(INVALID_SOCKET, res, h, p) };
        }

        let options = if bind_mode != 0 {
            sys::BIO_SOCK_REUSEADDR
        } else {
            0
        };
        // SAFETY: `res` is a live chain and its first address is a live BIO_ADDR.
        if unsafe { BIO_listen(s, BIO_ADDRINFO_address(res), options) } == 0 {
            // The authority closes through `BIO_closesocket`, which is a safe call.
            BIO_closesocket(s);
            // SAFETY: each temporary is NULL or owned by this function.
            return unsafe { cleanup_res(INVALID_SOCKET, res, h, p) };
        }

        // SAFETY: each temporary is NULL or owned by this function.
        unsafe { cleanup_res(s, res, h, p) }
    })
}

/// Free the temporaries of `BIO_get_accept_socket` and answer with `s`.
///
/// # Safety
/// Each pointer must be NULL or owned by the caller, as `BIO_get_accept_socket`
/// produced them.
unsafe fn cleanup_res(s: c_int, res: *mut BioAddrInfo, h: *mut c_char, p: *mut c_char) -> c_int {
    // SAFETY: `res` is NULL or an owned chain; `h`/`p` are NULL or owned strings
    // from `CRYPTO_strndup`.
    unsafe {
        BIO_ADDRINFO_free(res);
        if !h.is_null() {
            CRYPTO_free(h.cast(), ptr::null(), 0);
        }
        if !p.is_null() {
            CRYPTO_free(p.cast(), ptr::null(), 0);
        }
    }
    s
}

/// `int BIO_accept(int sock, char **ip_port)`
///
/// The deprecated wrapper. `-2` means "retryable", which is neither a descriptor
/// nor the `-1` a caller might expect from a failure.
///
/// # Safety
/// `ip_port` must be NULL or writable; on success with a non-NULL `ip_port` the
/// caller owns the string and frees it with `OPENSSL_free`.
#[no_mangle]
pub unsafe extern "C" fn BIO_accept(sock: c_int, ip_port: *mut *mut c_char) -> c_int {
    guard_ffi(INVALID_SOCKET, || {
        // The authority keeps the accepted address on the stack.
        let mut res = zeroed();
        // SAFETY: `res` is live and writable.
        let mut ret = unsafe { BIO_accept_ex(sock, ptr::addr_of_mut!(res), 0) };
        if ret == INVALID_SOCKET {
            if BIO_sock_should_retry(ret) != 0 {
                return -2;
            }
            // SAFETY: the sites are compile-time constants and the message is a
            // static string.
            unsafe {
                raise_site_dynamic_data(&BIO_SOCK_301, sys::errno(), c"calling accept()".as_ptr());
                raise_site(&BIO_SOCK_303);
            }
            return ret;
        }

        if !ip_port.is_null() {
            // SAFETY: `res` is a live address.
            let host = unsafe { BIO_ADDR_hostname_string(ptr::addr_of!(res), 1) };
            // SAFETY: as above.
            let port = unsafe { BIO_ADDR_service_string(ptr::addr_of!(res), 1) };
            let joined = if !host.is_null() && !port.is_null() {
                // SAFETY: both are NUL-terminated byte strings.
                let hl = unsafe { sys::strlen(host) };
                // SAFETY: as above.
                let pl = unsafe { sys::strlen(port) };
                let size = hl + pl + 2;
                // SAFETY: `CRYPTO_zalloc(0)` never happens here because the size is
                // at least 2.
                let buf = CRYPTO_zalloc(size, ptr::null(), 0).cast::<c_char>();
                if !buf.is_null() {
                    // SAFETY: `buf` has room for `hl + pl + 2` bytes including the
                    // terminator and the colon.
                    unsafe {
                        sys::memcpy(buf.cast(), host.cast(), hl);
                        *buf.add(hl) = b':' as c_char;
                        sys::memcpy(buf.add(hl + 1).cast(), port.cast(), pl);
                        *buf.add(hl + 1 + pl) = 0;
                    }
                }
                buf
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_SOCK_314) };
                ptr::null_mut()
            };

            // SAFETY: `ip_port` is writable per the caller's contract.
            unsafe { *ip_port = joined };

            if joined.is_null() {
                // The authority closes through `BIO_closesocket`, a safe call.
                BIO_closesocket(ret);
                ret = INVALID_SOCKET;
            }
            // SAFETY: each is NULL or an allocation from `CRYPTO_strdup`.
            unsafe {
                if !host.is_null() {
                    CRYPTO_free(host.cast(), ptr::null(), 0);
                }
                if !port.is_null() {
                    CRYPTO_free(port.cast(), ptr::null(), 0);
                }
            }
        }
        ret
    })
}
