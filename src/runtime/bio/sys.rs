//! Phase 4 — the operating-system surface BIO stands on.
//!
//! BIO is the layer where OpenSSL meets the operating system: files, file
//! descriptors, sockets, datagrams and the resolver. This module is the complete
//! list of libc entry points the BIO implementation calls, declared once, with
//! the types the platform actually uses.
//!
//! ## Why declarations rather than a dependency
//!
//! `Cargo.toml` declares *no* dependencies, deliberately: the dependency surface
//! is part of the supply-chain contract (`docs/CUSTODIAN_CONTRACT.md` §3). A
//! `libc`-style crate would be a build-time dependency on a third party's
//! transcription of the same headers, so this module transcribes the small subset
//! this stratum needs directly from the platform the authority was built for
//! (`linux`/`x86_64`).
//!
//! ## Scope
//!
//! Only what the implemented BIO methods call is declared. A declaration with no
//! caller is a maintenance liability dressed as completeness, and the
//! prohibition in `forensics/tools/check_forbidden_dependencies.py` already keeps
//! the *link* honest. Types are spelled exactly as the platform ABI expects
//! (`socklen_t`, `sa_family_t`, `in_port_t` are all `u16`/`u32` on this target,
//! and `struct sockaddr_storage` must be large enough for every family).

#![allow(dead_code)]
// Declarations are shared by the method modules; not every
// one is referenced from every build profile.

// The aliases below deliberately mirror the C spellings (`size_t`, `c_ulong`)
// because they appear in transcribed prototypes, where matching the header is the
// point. Renaming them to Rust case would make the declarations harder to check
// against the source they were taken from.
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_short, c_uint, c_void};

/// `size_t`, spelled for readability in the declarations below.
pub type size_t = usize;

// ---------------------------------------------------------------------------
// File descriptors and files
// ---------------------------------------------------------------------------

/// `FILE` from `<stdio.h>`, opaque here.
#[repr(C)]
pub struct FILE {
    _opaque: [u8; 0],
}

extern "C" {
    /// `FILE *fopen(const char *, const char *)`.
    pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE;
    /// `int fclose(FILE *)`.
    pub fn fclose(f: *mut FILE) -> c_int;
    /// `size_t fread(void *, size_t, size_t, FILE *)`.
    pub fn fread(ptr: *mut c_void, size: size_t, nmemb: size_t, f: *mut FILE) -> size_t;
    /// `size_t fwrite(const void *, size_t, size_t, FILE *)`.
    pub fn fwrite(ptr: *const c_void, size: size_t, nmemb: size_t, f: *mut FILE) -> size_t;
    /// `int fflush(FILE *)`.
    pub fn fflush(f: *mut FILE) -> c_int;
    /// `char *fgets(char *, int, FILE *)`.
    pub fn fgets(s: *mut c_char, n: c_int, f: *mut FILE) -> *mut c_char;
    /// `int fputs(const char *, FILE *)`.
    pub fn fputs(s: *const c_char, f: *mut FILE) -> c_int;
    /// `int fseek(FILE *, long, int)`.
    pub fn fseek(f: *mut FILE, off: c_long, whence: c_int) -> c_int;
    /// `long ftell(FILE *)`.
    pub fn ftell(f: *mut FILE) -> c_long;
    /// `int fileno(FILE *)`.
    pub fn fileno(f: *mut FILE) -> c_int;
    /// `int feof(FILE *)`.
    pub fn feof(f: *mut FILE) -> c_int;
    /// `int ferror(FILE *)`.
    pub fn ferror(f: *mut FILE) -> c_int;
    /// `int setvbuf(FILE *, char *, int, size_t)`.
    pub fn setvbuf(f: *mut FILE, buf: *mut c_char, mode: c_int, size: size_t) -> c_int;

    /// `ssize_t read(int, void *, size_t)`.
    pub fn read(fd: c_int, buf: *mut c_void, n: size_t) -> isize;
    /// `ssize_t write(int, const void *, size_t)`.
    pub fn write(fd: c_int, buf: *const c_void, n: size_t) -> isize;
    /// `int close(int)`.
    pub fn close(fd: c_int) -> c_int;
    /// `off_t lseek(int, off_t, int)`.
    pub fn lseek(fd: c_int, off: i64, whence: c_int) -> i64;
    /// `int open(const char *, int, ...)` — the two-argument form is used only.
    pub fn open(path: *const c_char, flags: c_int) -> c_int;
    /// `int fcntl(int, int, ...)`.
    pub fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int;
    /// `int ioctl(int, unsigned long, ...)`.
    pub fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
}

/// `c_ulong` alias kept local so the declaration above reads like the header.
pub type c_ulong = core::ffi::c_ulong;

/// `O_RDONLY` on Linux.
pub const O_RDONLY: c_int = 0;
/// `O_WRONLY` on Linux.
pub const O_WRONLY: c_int = 1;
/// `O_RDWR` on Linux.
pub const O_RDWR: c_int = 2;
/// `O_CREAT` on Linux.
pub const O_CREAT: c_int = 0o100;
/// `O_TRUNC` on Linux.
pub const O_TRUNC: c_int = 0o1000;
/// `O_APPEND` on Linux.
pub const O_APPEND: c_int = 0o2000;

/// `SEEK_SET`.
pub const SEEK_SET: c_int = 0;
/// `SEEK_CUR`.
pub const SEEK_CUR: c_int = 1;
/// `SEEK_END`.
pub const SEEK_END: c_int = 2;

/// `F_GETFL` on Linux.
pub const F_GETFL: c_int = 3;
/// `F_SETFL` on Linux.
pub const F_SETFL: c_int = 4;
/// `O_NONBLOCK` on Linux.
pub const O_NONBLOCK: c_int = 0o4000;

// ---------------------------------------------------------------------------
// errno
// ---------------------------------------------------------------------------

extern "C" {
    /// The thread-local `errno` location, as glibc exposes it.
    #[link_name = "__errno_location"]
    pub fn errno_location() -> *mut c_int;
}

/// Read the calling thread's `errno`.
///
/// # Safety
/// Calls into libc; safe for any caller, but `unsafe` because it is an FFI call.
pub unsafe fn errno() -> c_int {
    // SAFETY: `__errno_location` returns a valid pointer to this thread's errno.
    unsafe { *errno_location() }
}

// `errno` values this stratum branches on, from `<errno.h>` on Linux.
/// `EINTR`.
pub const EINTR: c_int = 4;
/// `EAGAIN` (equal to `EWOULDBLOCK` on Linux).
pub const EAGAIN: c_int = 11;
/// `EWOULDBLOCK`.
pub const EWOULDBLOCK: c_int = 11;
/// `EINPROGRESS`.
pub const EINPROGRESS: c_int = 115;
/// `EALREADY`.
pub const EALREADY: c_int = 114;
/// `ENOTCONN`.
pub const ENOTCONN: c_int = 107;
/// `ECONNREFUSED`.
pub const ECONNREFUSED: c_int = 111;
/// `ECONNRESET`.
pub const ECONNRESET: c_int = 104;
/// `ENOBUFS`.
pub const ENOBUFS: c_int = 105;
/// `EMSGSIZE`.
pub const EMSGSIZE: c_int = 90;
/// `ENOMEM`.
pub const ENOMEM: c_int = 12;

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/// `socklen_t`.
pub type SockLen = c_uint;
/// `sa_family_t`.
pub type SaFamily = u16;
/// `in_port_t`.
pub type InPort = u16;

/// `struct sockaddr` — the common prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddr {
    /// Address family.
    pub sa_family: SaFamily,
    /// Opaque address bytes.
    pub sa_data: [u8; 14],
}

/// `struct in_addr`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InAddr {
    /// Network-order IPv4 address.
    pub s_addr: u32,
}

/// `struct sockaddr_in`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    /// `AF_INET`.
    pub sin_family: SaFamily,
    /// Network-order port.
    pub sin_port: InPort,
    /// IPv4 address.
    pub sin_addr: InAddr,
    /// Zero padding.
    pub sin_zero: [u8; 8],
}

/// `struct in6_addr`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct In6Addr {
    /// The 16 address bytes.
    pub s6_addr: [u8; 16],
}

/// `struct sockaddr_in6`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn6 {
    /// `AF_INET6`.
    pub sin6_family: SaFamily,
    /// Network-order port.
    pub sin6_port: InPort,
    /// Flow information.
    pub sin6_flowinfo: u32,
    /// IPv6 address.
    pub sin6_addr: In6Addr,
    /// Scope identifier.
    pub sin6_scope_id: u32,
}

/// `struct sockaddr_un`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrUn {
    /// `AF_UNIX`.
    pub sun_family: SaFamily,
    /// Path, NUL-terminated.
    pub sun_path: [c_char; 108],
}

/// `struct sockaddr_storage` — large enough for every family this stratum uses.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrStorage {
    /// Family of the stored address.
    pub ss_family: SaFamily,
    /// Padding to the platform's storage size.
    pub __pad: [u8; 126],
}

/// `AF_UNSPEC`.
pub const AF_UNSPEC: c_int = 0;
/// `AF_UNIX`.
pub const AF_UNIX: c_int = 1;
/// `AF_INET`.
pub const AF_INET: c_int = 2;
/// `AF_INET6`.
pub const AF_INET6: c_int = 10;

/// `SOCK_STREAM`.
pub const SOCK_STREAM: c_int = 1;
/// `SOCK_DGRAM`.
pub const SOCK_DGRAM: c_int = 2;

/// `SOL_SOCKET`.
pub const SOL_SOCKET: c_int = 1;
/// `SO_ERROR`.
pub const SO_ERROR: c_int = 4;
/// `SO_REUSEADDR`.
pub const SO_REUSEADDR: c_int = 2;
/// `SO_KEEPALIVE`.
pub const SO_KEEPALIVE: c_int = 9;
/// `SO_RCVBUF`.
pub const SO_RCVBUF: c_int = 8;
/// `SO_SNDBUF`.
pub const SO_SNDBUF: c_int = 7;
/// `SO_RCVTIMEO`.
pub const SO_RCVTIMEO: c_int = 20;
/// `SO_SNDTIMEO`.
pub const SO_SNDTIMEO: c_int = 21;
/// `IPPROTO_TCP`.
pub const IPPROTO_TCP: c_int = 6;
/// `IPPROTO_UDP`.
pub const IPPROTO_UDP: c_int = 17;
/// `IPPROTO_IPV6`.
pub const IPPROTO_IPV6: c_int = 41;
/// `IPV6_V6ONLY`.
pub const IPV6_V6ONLY: c_int = 26;
/// `TCP_NODELAY`.
pub const TCP_NODELAY: c_int = 1;

/// `MSG_PEEK`.
pub const MSG_PEEK: c_int = 2;
/// `MSG_DONTWAIT`.
pub const MSG_DONTWAIT: c_int = 0x40;

/// `POLLIN`.
pub const POLLIN: c_short = 0x001;
/// `POLLOUT`.
pub const POLLOUT: c_short = 0x004;
/// `POLLERR`.
pub const POLLERR: c_short = 0x008;
/// `POLLHUP`.
pub const POLLHUP: c_short = 0x010;
/// `POLLNVAL`.
pub const POLLNVAL: c_short = 0x020;

/// `struct pollfd`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    /// The descriptor.
    pub fd: c_int,
    /// Requested events.
    pub events: c_short,
    /// Returned events.
    pub revents: c_short,
}

/// `struct timeval`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    /// Seconds.
    pub tv_sec: c_long,
    /// Microseconds.
    pub tv_usec: c_long,
}

extern "C" {
    /// `int socket(int, int, int)`.
    pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    /// `int connect(int, const struct sockaddr *, socklen_t)`.
    pub fn connect(fd: c_int, addr: *const SockAddr, len: SockLen) -> c_int;
    /// `int bind(int, const struct sockaddr *, socklen_t)`.
    pub fn bind(fd: c_int, addr: *const SockAddr, len: SockLen) -> c_int;
    /// `int listen(int, int)`.
    pub fn listen(fd: c_int, backlog: c_int) -> c_int;
    /// `int accept(int, struct sockaddr *, socklen_t *)`.
    pub fn accept(fd: c_int, addr: *mut SockAddr, len: *mut SockLen) -> c_int;
    /// `ssize_t send(int, const void *, size_t, int)`.
    pub fn send(fd: c_int, buf: *const c_void, n: size_t, flags: c_int) -> isize;
    /// `ssize_t recv(int, void *, size_t, int)`.
    pub fn recv(fd: c_int, buf: *mut c_void, n: size_t, flags: c_int) -> isize;
    /// `ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t)`.
    pub fn sendto(
        fd: c_int,
        buf: *const c_void,
        n: size_t,
        flags: c_int,
        addr: *const SockAddr,
        len: SockLen,
    ) -> isize;
    /// `ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *)`.
    pub fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        n: size_t,
        flags: c_int,
        addr: *mut SockAddr,
        len: *mut SockLen,
    ) -> isize;
    /// `int setsockopt(int, int, int, const void *, socklen_t)`.
    pub fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const c_void,
        len: SockLen,
    ) -> c_int;
    /// `int getsockopt(int, int, int, void *, socklen_t *)`.
    pub fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut c_void,
        len: *mut SockLen,
    ) -> c_int;
    /// `int getsockname(int, struct sockaddr *, socklen_t *)`.
    pub fn getsockname(fd: c_int, addr: *mut SockAddr, len: *mut SockLen) -> c_int;
    /// `int getpeername(int, struct sockaddr *, socklen_t *)`.
    pub fn getpeername(fd: c_int, addr: *mut SockAddr, len: *mut SockLen) -> c_int;
    /// `int shutdown(int, int)`.
    pub fn shutdown(fd: c_int, how: c_int) -> c_int;
    /// `int poll(struct pollfd *, nfds_t, int)`.
    pub fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
    /// `int select(int, fd_set *, fd_set *, fd_set *, struct timeval *)`.
    pub fn select(
        nfds: c_int,
        readfds: *mut c_void,
        writefds: *mut c_void,
        exceptfds: *mut c_void,
        timeout: *mut Timeval,
    ) -> c_int;
}

/// `SHUT_WR`.
pub const SHUT_WR: c_int = 1;
/// `SHUT_RDWR`.
pub const SHUT_RDWR: c_int = 2;

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// `struct addrinfo`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddrInfo {
    /// Flags.
    pub ai_flags: c_int,
    /// Address family.
    pub ai_family: c_int,
    /// Socket type.
    pub ai_socktype: c_int,
    /// Protocol.
    pub ai_protocol: c_int,
    /// Address length.
    pub ai_addrlen: SockLen,
    /// Address.
    pub ai_addr: *mut SockAddr,
    /// Canonical name.
    pub ai_canonname: *mut c_char,
    /// Next entry.
    pub ai_next: *mut AddrInfo,
}

extern "C" {
    /// `int getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **)`.
    pub fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const AddrInfo,
        res: *mut *mut AddrInfo,
    ) -> c_int;
    /// `void freeaddrinfo(struct addrinfo *)`.
    pub fn freeaddrinfo(res: *mut AddrInfo);
    /// `const char *gai_strerror(int)`.
    pub fn gai_strerror(code: c_int) -> *const c_char;
    /// `int getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int)`.
    pub fn getnameinfo(
        addr: *const SockAddr,
        addrlen: SockLen,
        host: *mut c_char,
        hostlen: SockLen,
        serv: *mut c_char,
        servlen: SockLen,
        flags: c_int,
    ) -> c_int;
    /// `const char *inet_ntop(int, const void *, char *, socklen_t)`.
    pub fn inet_ntop(
        af: c_int,
        src: *const c_void,
        dst: *mut c_char,
        size: SockLen,
    ) -> *const c_char;
    /// `int inet_pton(int, const char *, void *)`.
    pub fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    /// `unsigned short htons(unsigned short)`.
    pub fn htons(x: u16) -> u16;
    /// `unsigned short ntohs(unsigned short)`.
    pub fn ntohs(x: u16) -> u16;
    /// `struct servent *getservbyname(const char *, const char *)`.
    pub fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut ServEnt;
    /// `struct hostent *gethostbyname(const char *)`.
    pub fn gethostbyname(name: *const c_char) -> *mut HostEnt;
}

/// `struct servent`.
#[repr(C)]
pub struct ServEnt {
    /// Service name.
    pub s_name: *mut c_char,
    /// Alias list.
    pub s_aliases: *mut *mut c_char,
    /// Network-order port.
    pub s_port: c_int,
    /// Protocol name.
    pub s_proto: *mut c_char,
}

/// `struct hostent`.
#[repr(C)]
pub struct HostEnt {
    /// Host name.
    pub h_name: *mut c_char,
    /// Alias list.
    pub h_aliases: *mut *mut c_char,
    /// Address family.
    pub h_addrtype: c_int,
    /// Address length.
    pub h_length: c_int,
    /// Address list.
    pub h_addr_list: *mut *mut c_char,
}

/// `AI_PASSIVE`.
pub const AI_PASSIVE: c_int = 0x0001;
/// `AI_CANONNAME`.
pub const AI_CANONNAME: c_int = 0x0002;
/// `AI_NUMERICHOST`.
pub const AI_NUMERICHOST: c_int = 0x0004;
/// `AI_NUMERICSERV`.
pub const AI_NUMERICSERV: c_int = 0x0400;
/// `AI_ADDRCONFIG`.
pub const AI_ADDRCONFIG: c_int = 0x0020;

/// `NI_NUMERICHOST`.
pub const NI_NUMERICHOST: c_int = 1;
/// `NI_NUMERICSERV`.
pub const NI_NUMERICSERV: c_int = 2;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

extern "C" {
    /// `void *malloc(size_t)`.
    pub fn malloc(n: size_t) -> *mut c_void;
    /// `void *realloc(void *, size_t)`.
    pub fn realloc(p: *mut c_void, n: size_t) -> *mut c_void;
    /// `void free(void *)`.
    pub fn free(p: *mut c_void);
    /// `void *memcpy(void *, const void *, size_t)`.
    pub fn memcpy(dst: *mut c_void, src: *const c_void, n: size_t) -> *mut c_void;
    /// `void *memmove(void *, const void *, size_t)`.
    pub fn memmove(dst: *mut c_void, src: *const c_void, n: size_t) -> *mut c_void;
    /// `void *memset(void *, int, size_t)`.
    pub fn memset(dst: *mut c_void, c: c_int, n: size_t) -> *mut c_void;
    /// `size_t strlen(const char *)`.
    pub fn strlen(s: *const c_char) -> size_t;
    /// `int memcmp(const void *, const void *, size_t)`.
    pub fn memcmp(a: *const c_void, b: *const c_void, n: size_t) -> c_int;
    /// `char *strdup(const char *)`.
    pub fn strdup(s: *const c_char) -> *mut c_char;
    /// `char *strndup(const char *, size_t)`.
    pub fn strndup(s: *const c_char, n: size_t) -> *mut c_char;
    /// `long strtol(const char *, char **, int)`.
    pub fn strtol(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_long;
    /// `int snprintf(char *, size_t, const char *, ...)` — declared with the
    /// C-variadic ABI and called only through the C adapters in `bio_variadic.c`.
    pub fn snprintf(buf: *mut c_char, n: size_t, fmt: *const c_char, ...) -> c_int;
    /// `int vsnprintf(char *, size_t, const char *, va_list)`.
    pub fn vsnprintf(buf: *mut c_char, n: size_t, fmt: *const c_char, ap: *mut c_void) -> c_int;
    /// `void syslog(int, const char *, ...)`.
    pub fn syslog(priority: c_int, fmt: *const c_char, ...);
    /// `int usleep(useconds_t)`.
    pub fn usleep(usec: c_uint) -> c_int;
    /// `time_t time(time_t *)`.
    pub fn time(t: *mut c_long) -> c_long;
    /// `int gettimeofday(struct timeval *, void *)`.
    pub fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int;
    /// `void *memchr(const void *, int, size_t)`.
    pub fn memchr(s: *const c_void, c: c_int, n: size_t) -> *mut c_void;
    /// `int isdigit(int)`.
    pub fn isdigit(c: c_int) -> c_int;
    /// `int isspace(int)`.
    pub fn isspace(c: c_int) -> c_int;
}
