//! Phase 9 staging — the platform (`libc`) surface the random layer's seeding
//! arm stands on.
//!
//! This is the `sys`-style companion to `crate::runtime::bio::sys`: the same
//! discipline — declarations transcribed from the platform headers rather than
//! taken from a `libc` dependency, because `Cargo.toml` declares no dependencies
//! and the dependency surface is part of the supply-chain contract
//! (`docs/CUSTODIAN_CONTRACT.md` §3) — applied to the calls the seeding arm of
//! `providers/implementations/rands/seeding/rand_unix.c` and
//! `crypto/rand/randfile.c` make.
//!
//! ## Shared items are imported, never redefined
//!
//! `Timespec`, `size_t`, `errno`, `EINTR` and the `O_*` flags already live in
//! `crate::runtime::bio::sys`. They are brought into scope below rather than
//! copied, so a layout or a value has exactly one definition. If this file is
//! merged into that module the `use` is redundant (same scope) and should be
//! deleted; while it is a standalone module the `use` is what keeps the
//! definitions single.
//!
//! ## Headers read to produce this file
//!
//! The admitted platform is `linux`/`x86_64` (`docs/AUTHORITY_POLICY.md`). The
//! values and layouts below were read from *this machine's* installed glibc
//! headers, which on this host live directly under `/usr/include` (the Debian
//! multiarch `/usr/include/x86_64-linux-gnu/...` path named in the task does not
//! exist here):
//!
//! * `<sys/random.h>` — `getentropy`.
//! * `<bits/struct_stat.h>` — the `struct stat` layout, pulled in by
//!   `<sys/stat.h>`; `<bits/typesizes.h>` — `__DEV_T_TYPE`/`__INO_T_TYPE`/
//!   `__MODE_T_TYPE` widths and `__FD_SETSIZE`.
//! * `<sys/select.h>`, `<bits/select.h>` — `fd_set`, `FD_SETSIZE`, the
//!   `__FD_ZERO`/`__FD_SET` macros.
//! * `<sys/shm.h>`, `<bits/shm.h>`, `<bits/ipc.h>` — the SysV shared-memory
//!   calls and their constants.
//! * `<sys/utsname.h>`, `<bits/utsname.h>` — `struct utsname`.
//! * `<sys/stat.h>` — the `S_IRUSR`/`S_IRGRP`/`S_IROTH` mode bits and `fstat`.
//! * `<time.h>`, `<bits/time.h>` — `clock_gettime`, `CLOCK_REALTIME`.
//! * `<unistd.h>` — `getpid`, `syscall`.
//! * `<stdlib.h>` — `atoi`.
//! * `<fcntl.h>` — `open`.
//! * `<asm/unistd_64.h>` (via `<sys/syscall.h>`) — `__NR_getrandom`.
//! * `<asm-generic/errno.h>` — `ENOSYS`.
//!
//! The authority citations are to
//! `forensics/authorities/src/openssl-3.6.4/providers/implementations/rands/seeding/rand_unix.c`
//! and `forensics/authorities/src/openssl-3.6.4/crypto/rand/randfile.c`.
//!
//! ## Deliberate omissions
//!
//! Only what the seeding arm calls is declared; `stat`, `fdopen`, `chmod`,
//! `setbuf`, `clearerr`, `O_BINARY`, `S_ISREG` and `S_IRWXU`/`S_IRWXG`/`S_IRWXO`
//! belong to the `crypto/rand/randfile.c` half and are not part of this surface.
//! No `#[no_mangle]` and no weak-symbol shim is introduced here.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]
// Declarations are shared by the seeding units; not every one is referenced
// from every build profile.

// The aliases below deliberately mirror the C spellings (`size_t`, `dev_t`,
// `mode_t`) because they appear in transcribed prototypes, where matching the
// header is the point. Renaming them to Rust case would make the declarations
// harder to check against the source they were taken from.
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};

// Shared with the BIO platform module — imported, not redefined. `errno` is the
// wrapper `crate::runtime::bio::sys::errno`, `EINTR` its constant, and the
// `O_*` flags its Linux values.
//
// **`open` is here for a different reason than the rest** (docs/DECISIONS.md D302): it is not
// shared but *owned* by that module. The header declares `int open(const char *, int, ...)`, so a
// second declaration here with a narrower arity is a compile error
// (`clashing_extern_declarations`) -- and the narrower arity was the crate's, until the random
// layer's `randfile.c` needed `open(path, O_WRONLY | O_CREAT, 0600)`. The prototype was widened in
// its one home rather than duplicated, and both arities are correct calls against it.
//
// The two `O_*` flags are imported for `randfile.c`'s arm, which is staged and not yet integrated:
// its `open(path, O_WRONLY | O_CREAT, 0600)` is the only caller. The allow says so rather than the
// import being dropped and re-added by that commit, because the flags belong to the same header
// surface this file exists to declare once.
#[allow(unused_imports)]
pub(crate) use crate::runtime::bio::sys::{
    close, errno, gettimeofday, open, read, select, size_t, strchr, time, Timespec, Timeval, EINTR,
    O_CREAT, O_RDONLY, O_WRONLY,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `CLOCK_REALTIME` — `<bits/time.h>`, `0` on Linux. The `OSSL_POSIX_TIMER_OKAY`
/// arm of `get_time_stamp` is the one compiled on this profile
/// (`rand_unix.c:788`).
pub(crate) const CLOCK_REALTIME: c_int = 0;

/// `__NR_getrandom` for the admitted `x86_64` (non-`__ILP32__`) kernel ABI.
///
/// Verified twice: `/usr/include/asm/unistd_64.h:322` defines it as `318`, and
/// the authority's own fallback table defines the identical value for `__x86_64__`
/// without `__ILP32__` (`rand_unix.c:283`). It is *not* the `asm-generic` value
/// (278) nor the x32 value (`__X32_SYSCALL_BIT + 318`).
///
/// `non_upper_case_globals` is allowed on this one item rather than module-wide: the spelling is
/// the header's macro name and the authority's own `__NR_getrandom` use, and renaming it to
/// `__NR_GETRANDOM` here would break the correspondence a reader checks it against.
#[allow(non_upper_case_globals)]
pub(crate) const __NR_getrandom: c_long = 318;

/// `ENOSYS` — `<asm-generic/errno.h>:18`, `38`. The seeding arm distinguishes a
/// kernel without `getrandom(2)` from a real failure with `errno == ENOSYS`
/// (`rand_unix.c:365`).
pub(crate) const ENOSYS: c_int = 38;

/// `IPC_CREAT` — `<bits/ipc.h>`, `01000` octal.
pub(crate) const IPC_CREAT: c_int = 0o1000;

/// `SHM_RDONLY` — `<bits/shm.h>`, `010000` octal; the flag `shmat` is given.
pub(crate) const SHM_RDONLY: c_int = 0o10000;

/// `S_IRUSR` — `<sys/stat.h>` (`__S_IREAD`, `<bits/stat.h>`), `0400` octal.
///
/// Typed `c_int`, not `mode_t`, because the call site is
/// `shmget(key, 1, IPC_CREAT | S_IRUSR | S_IRGRP | S_IROTH)` (`rand_unix.c:485`)
/// and `shmget`'s third parameter is an `int`: the `|` must be over `c_int`s.
pub(crate) const S_IRUSR: c_int = 0o400;

/// `S_IRGRP` — `<sys/stat.h>`, `(S_IRUSR >> 3)` = `040` octal.
pub(crate) const S_IRGRP: c_int = 0o40;

/// `S_IROTH` — `<sys/stat.h>`, `(S_IRGRP >> 3)` = `04` octal.
pub(crate) const S_IROTH: c_int = 0o4;

// The three `S_IRWX*` masks, added by D302. The staging file omitted them as belonging to
// `randfile.c`'s half, and it largely does -- but `rand_unix.c` compares the **whole permission
// mask** with them when it decides whether a `/dev/*` path is still the device it recorded:
// `(rd.mode ^ st.st_mode) & !(S_IRWXU | S_IRWXG | S_IRWXO)`. So the seeding arm needs them, and the
// omission was a measurement error in the staging file rather than a boundary.

/// `S_IRWXU` — `<sys/stat.h>`, `0700` octal (`S_IRUSR | S_IWUSR | S_IXUSR`).
pub(crate) const S_IRWXU: mode_t = 0o700;
/// `S_IRWXG` — `<sys/stat.h>`, `070` octal.
pub(crate) const S_IRWXG: mode_t = 0o70;
/// `S_IRWXO` — `<sys/stat.h>`, `07` octal.
pub(crate) const S_IRWXO: mode_t = 0o7;

// The file-type mask and the regular-file bit, added by D312 with `randfile.c`. `S_ISREG(m)` is
// `((m) & S_IFMT) == S_IFREG` in `<sys/stat.h>`; `randfile.c:57-58` defines exactly that fallback
// itself when the platform has no macro, so the crate's `s_isreg` below is the header's own test
// spelled once rather than a second interpretation of it.

/// `S_IFMT` — `<sys/stat.h>`, `0170000` octal: the file-type bits of `st_mode`.
pub(crate) const S_IFMT: mode_t = 0o170000;
/// `S_IFREG` — the type bit of a regular file.
pub(crate) const S_IFREG: mode_t = 0o100000;
/// `S_IFDIR` — the type bit of a directory.
pub(crate) const S_IFDIR: mode_t = 0o040000;

/// `S_ISREG(m)` — `<sys/stat.h>`.
#[inline]
pub(crate) const fn s_isreg(mode: mode_t) -> bool {
    mode & S_IFMT == S_IFREG
}

/// `FD_SETSIZE` — `<sys/select.h>`'s alias of `__FD_SETSIZE`, `1024`
/// (`<bits/typesizes.h>`). `c_int` because the call site compares a descriptor
/// to it directly: `fd < FD_SETSIZE` (`rand_unix.c:470`).
pub(crate) const FD_SETSIZE: c_int = 1024;

/// `__NFDBITS` — `<sys/select.h>`'s `(8 * (int) sizeof (__fd_mask))`, i.e. 64
/// bits per word on x86-64.
const NFDBITS: usize = 8 * core::mem::size_of::<c_long>();

/// Number of words in an `fd_set` — `<sys/select.h>`'s
/// `__FD_SETSIZE / __NFDBITS`, i.e. 16.
const FD_WORDS: usize = FD_SETSIZE as usize / NFDBITS;

// ---------------------------------------------------------------------------
// Integer types
// ---------------------------------------------------------------------------

/// `dev_t` — `__DEV_T_TYPE` is `__UQUAD_TYPE` (`<bits/typesizes.h>`), i.e. a
/// 64-bit `unsigned long long`. Used for both `st_dev` and `st_rdev`.
pub(crate) type dev_t = u64;

/// `ino_t` — `__INO_T_TYPE` is `__SYSCALL_ULONG_TYPE`
/// (`<bits/typesizes.h>`), a 64-bit `unsigned long` on this LP64 target.
pub(crate) type ino_t = u64;

/// `mode_t` — `__MODE_T_TYPE` is `__U32_TYPE` (`<bits/typesizes.h>`), a 32-bit
/// `unsigned int`.
pub(crate) type mode_t = u32;

// ---------------------------------------------------------------------------
// struct stat
// ---------------------------------------------------------------------------

/// `struct stat` from `<sys/stat.h>` on glibc/x86-64.
///
/// The layout is the header's (`<bits/struct_stat.h>`, the `__x86_64__` arm
/// without `__USE_TIME64_REDIRECTS`, which is the profile the authority is built
/// for): `st_dev`@0, `st_ino`@8, `st_nlink`@16, `st_mode`@24, `st_uid`@28,
/// `st_gid`@32, `__pad0`@36, `st_rdev`@40, `st_size`@48, `st_blksize`@56,
/// `st_blocks`@64, and then `st_atim`/`st_mtim`/`st_ctim` (three `struct
/// timespec`) plus `__glibc_reserved[3]` filling 72..144. The total is
/// **144 bytes**, alignment 8.
///
/// The seeding arm reads `st_dev`, `st_ino`, `st_mode` and `st_rdev`
/// (`rand_unix.c:521-525`, `rand_unix.c:545-548`); `st_size` is included because
/// `randfile.c` reads it. The fields the call sites do not read are private
/// padding rather than named public fields: the offsets and the total size are
/// still exactly the header's, but no caller can accidentally start reading a
/// field whose type this surface has not committed to. A sparse
/// "read-fields-plus-guessed-bytes" struct would be one miscount away from a
/// silent out-of-bounds read, so the byte counts here are the header's, not an
/// estimate.
#[repr(C)]
pub(crate) struct Stat {
    /// `st_dev` — the device the inode lives on.
    pub st_dev: dev_t,
    /// `st_ino` — the inode's serial number.
    pub st_ino: ino_t,
    /// `st_nlink` at 16..24 (`nlink_t`, 64-bit unsigned); not read here.
    __pad_nlink: u64,
    /// `st_mode` — file type and permission bits.
    pub st_mode: mode_t,
    /// `st_uid` (4) + `st_gid` (4) + `__pad0` (4) at 28..40; not read here.
    __pad_uid_gid: [u8; 12],
    /// `st_rdev` — the device number for a device inode.
    pub st_rdev: dev_t,
    /// `st_size` — size in bytes (`off_t`, 64-bit signed).
    pub st_size: i64,
    /// `st_blksize` + `st_blocks` + `st_atim` + `st_mtim` + `st_ctim` +
    /// `__glibc_reserved[3]` at 56..144; not read by the seeding arm.
    __pad_tail: [u8; 88],
}

impl Stat {
    /// A zeroed `struct stat`, as the authority's `struct stat sb;` on a function's stack frame.
    ///
    /// Written as a struct literal so that every field is accounted for at compile time: a field
    /// added later cannot be forgotten here, which a `MaybeUninit` zeroing would not catch. This is
    /// `OsslLibCtx::ZEROED`'s shape and its reason.
    ///
    /// The landing callers are `RAND_load_file` and `RAND_write_file`, which declare
    /// `struct stat sb;` on their stack frames; they land with the RAND front (D312).
    #[allow(dead_code)] // the landing callers are `RAND_load_file`/`RAND_write_file` (the RAND front)
    pub(crate) const ZEROED: Stat = Stat {
        st_dev: 0,
        st_ino: 0,
        __pad_nlink: 0,
        st_mode: 0,
        __pad_uid_gid: [0; 12],
        st_rdev: 0,
        st_size: 0,
        __pad_tail: [0; 88],
    };
}

// ---------------------------------------------------------------------------
// struct utsname
// ---------------------------------------------------------------------------

/// `struct utsname` from `<sys/utsname.h>`.
///
/// `_UTSNAME_LENGTH` is `65` (`<bits/utsname.h>`), and glibc defines
/// `_UTSNAME_DOMAIN_LENGTH` to the same value, so the struct always reserves six
/// fields on this platform. The last is spelled `domainname` under `_GNU_SOURCE`
/// and `__domainname` under strict POSIX namespacing; the layout is identical.
/// `uname` writes all six.
#[repr(C)]
pub(crate) struct Utsname {
    /// `sysname` — the operating-system name.
    pub sysname: [c_char; 65],
    /// `nodename` — the node name on the network.
    pub nodename: [c_char; 65],
    /// `release` — the kernel release string (`atoi`-parsed by the caller).
    pub release: [c_char; 65],
    /// `version` — the kernel version string.
    pub version: [c_char; 65],
    /// `machine` — the hardware type.
    pub machine: [c_char; 65],
    /// `domainname` (a.k.a. `__domainname`) — the NIS/YP domain name.
    pub domainname: [c_char; 65],
}

// ---------------------------------------------------------------------------
// fd_set
// ---------------------------------------------------------------------------

/// `fd_set` from `<sys/select.h>`.
///
/// glibc's member is `__fds_bits`, an array of `__fd_mask` (`long int`)
/// words of which `__FD_SETSIZE / __NFDBITS` are meaningful (16 here). Under
/// XPG4.2 namespacing (`__USE_XOPEN`) the same member is named `fds_bits`; the
/// layout does not change, and `fds_bits` is the name used here.
#[repr(C)]
pub(crate) struct FdSet {
    /// One bit per descriptor.
    pub fds_bits: [c_long; FD_WORDS],
}

/// `FD_ZERO(set)` — `<sys/select.h>`, glibc's `__FD_ZERO` in `<bits/select.h>`.
///
/// The macro zeroes every word of the set; this is that loop, written as a
/// single array write. Safe, because the reference carries the precondition the C
/// leaves to the caller.
pub(crate) fn fd_zero(set: &mut FdSet) {
    set.fds_bits = [0; FD_WORDS];
}

/// `FD_SET(fd, set)` — `<sys/select.h>`, glibc's `__FD_SET` in `<bits/select.h>`.
///
/// Reproduces the macro's arithmetic: `__FD_ELT(fd) = fd / __NFDBITS` selects the
/// word and `__FD_MASK(fd) = 1UL << (fd % __NFDBITS)` selects the bit inside it.
///
/// The C macro performs no bounds check, so an out-of-range descriptor is the caller's contract
/// violation in both languages -- but unlike the C, an out-of-range `fd` here would index past
/// `fds_bits`. The index is therefore masked into the set, which is *defined* for every input
/// rather than UB, and the divergence is stated: the authority would write out of bounds and this
/// would set a bit in another word.
pub(crate) fn fd_set(fd: c_int, set: &mut FdSet) {
    let elt = (fd as usize / NFDBITS) % FD_WORDS;
    let mask = (1u64 << (fd as usize % NFDBITS)) as c_long;
    set.fds_bits[elt] |= mask;
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

extern "C" {
    /// `int clock_gettime(clockid_t, struct timespec *)` — `<time.h>`.
    /// `clockid_t` is `__S32_TYPE`, i.e. `int` (`<bits/typesizes.h>`). Called
    /// through the safe wrapper below.
    #[link_name = "clock_gettime"]
    fn clock_gettime_raw(clk_id: c_int, tp: *mut Timespec) -> c_int;

    /// `int getentropy(void *, size_t)` — `<sys/random.h>`.
    ///
    /// The authority probes this symbol as **weak** —
    /// `extern int getentropy(void *, size_t) __attribute__((weak));`
    /// (`rand_unix.c:358`) — so that libcrypto still links against a libc whose
    /// `getentropy` is absent. Rust has no weak-symbol mechanism, and inventing
    /// one (a `dlsym` probe, a build-script test) is out of scope for this
    /// surface. This declaration therefore binds the symbol **strongly**: on a
    /// toolchain/libc that truly lacks `getentropy` the link fails, where the
    /// authority's link would not. That limitation is recorded, not hidden.
    ///
    /// The `pub(crate) unsafe fn getentropy` below is the callable form.
    #[link_name = "getentropy"]
    fn getentropy_strong(buf: *mut c_void, buflen: size_t) -> c_int;

    /// `long syscall(long number, ...)` — `<unistd.h>`. Variadic, exactly as
    /// declared; this surface calls it only as
    /// `syscall(__NR_getrandom, buf, buflen, 0)` (`rand_unix.c:392`).
    pub(crate) fn syscall(num: c_long, ...) -> c_long;

    /// `int fstat(int, struct stat *)` — `<sys/stat.h>`. On x86-64 this is the
    /// 64-bit-inode entry point (`fstat64` has the same shape), so no
    /// `_FILE_OFFSET_BITS` redirection applies. Called through the safe wrapper
    /// below.
    #[link_name = "fstat"]
    fn fstat_raw(fd: c_int, buf: *mut Stat) -> c_int;

    /// `int stat(const char *, struct stat *)` — `<sys/stat.h>`, the path form of the same entry
    /// point. Added by D312 for `randfile.c`'s `RAND_write_file`, which refuses to overwrite a
    /// path that exists and is not a regular file. Called through the safe wrapper below.
    #[link_name = "stat"]
    fn stat_raw(path: *const c_char, buf: *mut Stat) -> c_int;

    /// `int chmod(const char *, mode_t)` — `<sys/stat.h>`. Added by D312: `RAND_write_file`
    /// tightens a new seed file to `0600` **after** writing it, and the authority's own comment
    /// says why the order matters rather than the call.
    #[link_name = "chmod"]
    fn chmod_raw(path: *const c_char, mode: mode_t) -> c_int;

    /// `int shmget(key_t, size_t, int)` — `<sys/shm.h>`. `key_t` is
    /// `__S32_TYPE`, i.e. `int` (`<bits/typesizes.h>`), which is why the key is
    /// declared `c_int` rather than a distinct alias. Called through the safe
    /// wrapper below.
    #[link_name = "shmget"]
    fn shmget_raw(key: c_int, size: size_t, shmflg: c_int) -> c_int;

    /// `void *shmat(int, const void *, int)` — `<sys/shm.h>`.
    pub(crate) fn shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void;

    /// `int shmdt(const void *)` — `<sys/shm.h>`. The authority passes its
    /// cached mapping (or null) unconditionally (`rand_unix.c:427`).
    pub(crate) fn shmdt(shmaddr: *const c_void) -> c_int;

    /// `int uname(struct utsname *)` — `<sys/utsname.h>`. Called through the safe
    /// wrapper below.
    #[link_name = "uname"]
    fn uname_raw(buf: *mut Utsname) -> c_int;

    /// `int atoi(const char *)` — `<stdlib.h>`. Used to parse the leading
    /// kernel-version fields of `un.release` (`rand_unix.c:459-461`). Called
    /// through the safe wrapper below.
    #[link_name = "atoi"]
    fn atoi_raw(s: *const c_char) -> c_int;
}

// ---------------------------------------------------------------------------
// Safe wrappers — the calls whose precondition is *unconditional*
// ---------------------------------------------------------------------------
//
// These six functions are `unsafe` in Rust only because C says so: none of them has a pointer
// argument that the caller must keep alive, and none can fail in a way that depends on how it is
// called. `rand_unix.c` and `randfile.c` call them from bodies that are otherwise safe, so the
// transcription would have needed an `unsafe` block at each site purely to satisfy the compiler --
// and an `unsafe` block that guards nothing is an `unsafe` block a reader learns to skip. The
// declarations above are `_raw` and these wrappers carry the names the transcript uses, which is
// the same shape `crate::runtime::bio::sys::errno` already has over `__errno_location`.
//
// The functions that are *genuinely* unsafe stay unsafe: `shmat`/`shmdt` take a pointer the caller
// owns, `syscall` is variadic, and `fstat`'s wrapper is safe only because it takes `&mut Stat`
// rather than a raw pointer.

use crate::runtime::bio::sys::getpid as getpid_raw;

/// `pid_t getpid(void)`.
pub(crate) fn getpid() -> c_int {
    // SAFETY: `getpid` takes no arguments, dereferences none, and cannot fail per POSIX.
    unsafe { getpid_raw() }
}

/// `int clock_gettime(clockid_t, struct timespec *)`, with the out-parameter as a reference so the
/// borrow checker covers what the C signature leaves to the caller.
pub(crate) fn clock_gettime(clk_id: c_int, tp: &mut Timespec) -> c_int {
    // SAFETY: `tp` is a live, exclusively borrowed `Timespec`, which is the whole precondition.
    unsafe { clock_gettime_raw(clk_id, tp) }
}

/// `int fstat(int, struct stat *)`, with the buffer as a reference.
pub(crate) fn fstat(fd: c_int, buf: &mut Stat) -> c_int {
    // SAFETY: `buf` is a live, exclusively borrowed `Stat`, which is the whole precondition.
    unsafe { fstat_raw(fd, buf) }
}

/// `int stat(const char *, struct stat *)`, with the buffer as a reference.
///
/// # Safety
/// `path` must be NUL-terminated and live for the call; the kernel reads it and writes only
/// through `buf`.
pub(crate) unsafe fn stat(path: *const c_char, buf: &mut Stat) -> c_int {
    // SAFETY: `path` is NUL-terminated per the contract and `buf` is live and exclusive.
    unsafe { stat_raw(path, buf) }
}

/// `int chmod(const char *, mode_t)`.
///
/// # Safety
/// `path` must be NUL-terminated and live for the call.
pub(crate) unsafe fn chmod(path: *const c_char, mode: mode_t) -> c_int {
    // SAFETY: `path` is NUL-terminated per the contract; `mode` is a scalar.
    unsafe { chmod_raw(path, mode) }
}

/// `int shmget(key_t, size_t, int)`.
pub(crate) fn shmget(key: c_int, size: size_t, shmflg: c_int) -> c_int {
    // SAFETY: every argument is a scalar; no pointer is passed to the kernel.
    unsafe { shmget_raw(key, size, shmflg) }
}

/// `int uname(struct utsname *)`, with the buffer as a reference.
pub(crate) fn uname(buf: &mut Utsname) -> c_int {
    // SAFETY: `buf` is a live, exclusively borrowed `Utsname`, which is the whole precondition.
    unsafe { uname_raw(buf) }
}

/// `int atoi(const char *)`.
///
/// Safe because the only precondition is that `s` is NUL-terminated, and a `*const c_char` that
/// reaches a transcription of C is a C string by construction -- the same reading
/// `crate::runtime::str::OPENSSL_strlen` takes. A non-NUL-terminated pointer is a caller error in
/// both languages and is not something this wrapper can check.
pub(crate) fn atoi(s: *const c_char) -> c_int {
    // SAFETY: the caller's contract, stated above: `s` is a NUL-terminated C string.
    unsafe { atoi_raw(s) }
}

// ---------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------

/// Call `getentropy(2)` and return its raw result (`0` on success, `-1` on
/// error).
///
/// This is the callable stand-in for the authority's weak-symbol probe
/// (`rand_unix.c:356-361`). Because [`getentropy_strong`] is bound strongly, the
/// "symbol is absent" branch of the authority cannot be reproduced; a caller
/// that needs to detect a kernel without `getentropy` inspects `errno` for
/// [`ENOSYS`] exactly as the authority does, rather than testing the symbol.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes; on success `getentropy` writes all
/// of them. (The kernel rejects `buflen > 256` with `EIO`.)
pub(crate) unsafe fn getentropy(buf: *mut c_void, buflen: size_t) -> c_int {
    // SAFETY: the caller guarantees `buf` is writable for `buflen` bytes, which is `getentropy`'s own contract.
    unsafe { getentropy_strong(buf, buflen) }
}

#[cfg(test)]
mod tests {
    //! The platform surface, exercised against the running kernel.
    //!
    //! This module exists because the seeding arm that needs these declarations is staged rather
    //! than landed, so without it the whole file would be `allow(dead_code)` and nothing in the
    //! repository would have ever *called* one of these declarations. A binding that is never
    //! called is a binding whose ABI is unverified -- and the ones here are the kind that fail
    //! silently: a wrong `struct stat` offset makes `fstat` answer a plausible wrong device, and a
    //! wrong `__NR_getrandom` makes `syscall` return `-ENOSYS` rather than fault.
    //!
    //! Every assertion is a fact about Linux/x86-64 that the authority's own code relies on, cited
    //! to the header or the call site it came from.

    use super::*;

    /// `stat` fills the layout this module declares, and `S_ISREG` reads the type bits out of it.
    ///
    /// **This is the runtime half of the layout proof.** `the_stat_layout_is_the_platforms` below
    /// pins the offsets against a table measured from the container's own headers; this test makes
    /// the *kernel* write through them, so a struct whose field types disagree with the kernel's
    /// would show up as a mode that is not a directory rather than as a plausible number. The path
    /// form (`stat`) is used rather than `fstat` alone because D312 landed exactly that call for
    /// `randfile.c`, and a declaration of `stat` that never ran would be an unverified ABI.
    #[test]
    fn stat_reads_the_file_type_through_the_declared_layout() {
        let mut sb = Stat {
            st_dev: 0,
            st_ino: 0,
            __pad_nlink: 0,
            st_mode: 0,
            __pad_uid_gid: [0; 12],
            st_rdev: 0,
            st_size: 0,
            __pad_tail: [0; 88],
        };
        // SAFETY: the path is a NUL-terminated literal and `sb` is a live, exclusively borrowed
        // `Stat`, which is the whole precondition.
        assert_eq!(unsafe { stat(c"/".as_ptr(), &mut sb) }, 0, "stat(\"/\")");
        assert!(sb.st_mode & S_IFMT == S_IFDIR, "/ is a directory");
        assert!(!s_isreg(sb.st_mode), "and not a regular file");

        // SAFETY: as above.
        if unsafe { stat(c"/etc/hostname".as_ptr(), &mut sb) } == 0 {
            assert!(s_isreg(sb.st_mode), "/etc/hostname is a regular file");
            assert!(sb.st_size > 0, "st_size reads through the declared offset");
        }
    }

    /// `S_ISREG` is the header's test, and the permission bits are not part of the type.
    #[test]
    fn the_file_type_test_is_the_headers() {
        assert_eq!(S_IFMT, 0o170000);
        assert_eq!(S_IFREG, 0o100000);
        assert_eq!(S_IFDIR, 0o040000);
        assert!(s_isreg(S_IFREG));
        assert!(s_isreg(S_IFREG | 0o600));
        assert!(!s_isreg(S_IFDIR));
        assert!(!s_isreg(S_IFDIR | 0o777));
    }

    /// The constants are the headers' values, not plausible ones. A single wrong octal in
    /// `shmget`'s flag word would create a segment with the wrong permissions and still succeed.
    #[test]
    fn the_constants_are_the_headers_values() {
        assert_eq!(CLOCK_REALTIME, 0, "bits/time.h");
        assert_eq!(ENOSYS, 38, "asm-generic/errno.h");
        assert_eq!(
            __NR_getrandom, 318,
            "asm/unistd_64.h, not asm-generic's 278"
        );
        assert_eq!(IPC_CREAT, 0o1000);
        assert_eq!(SHM_RDONLY, 0o10000);
        assert_eq!(S_IRUSR, 0o400);
        assert_eq!(S_IRGRP, 0o40);
        assert_eq!(S_IROTH, 0o4);
        assert_eq!(S_IRWXU, 0o700);
        assert_eq!(S_IRWXG, 0o70);
        assert_eq!(S_IRWXO, 0o7);
        assert_eq!(FD_SETSIZE, 1024);
        assert_eq!(NFDBITS, 64);
        assert_eq!(FD_WORDS, 16);
    }

    /// **The `struct stat` layout, field by field.** This is the assertion the seeding arm's
    /// device-identity check stands on: `rand_unix.c` compares `st_dev`/`st_ino`/`st_mode`/
    /// `st_rdev` against what it recorded, and an offset error would make that comparison
    /// *accidentally* true or false rather than fail loudly.
    #[test]
    fn the_stat_layout_is_the_glibc_x86_64_arm() {
        assert_eq!(core::mem::size_of::<Stat>(), 144, "bits/struct_stat.h");
        assert_eq!(core::mem::align_of::<Stat>(), 8);
        assert_eq!(core::mem::offset_of!(Stat, st_dev), 0);
        assert_eq!(core::mem::offset_of!(Stat, st_ino), 8);
        assert_eq!(core::mem::offset_of!(Stat, st_mode), 24);
        assert_eq!(core::mem::offset_of!(Stat, st_rdev), 40);
        assert_eq!(core::mem::offset_of!(Stat, st_size), 48);
        assert_eq!(
            core::mem::size_of::<dev_t>(),
            8,
            "__DEV_T_TYPE is __UQUAD_TYPE"
        );
        assert_eq!(
            core::mem::size_of::<ino_t>(),
            8,
            "__INO_T_TYPE is __SYSCALL_ULONG_TYPE"
        );
        assert_eq!(
            core::mem::size_of::<mode_t>(),
            4,
            "__MODE_T_TYPE is __U32_TYPE"
        );
    }

    /// `Utsname` is six `_UTSNAME_LENGTH`-byte fields, and `uname` fills them.
    #[test]
    fn uname_fills_six_fields_and_the_release_parses() {
        assert_eq!(core::mem::size_of::<Utsname>(), 6 * 65);
        // SAFETY: `Utsname` is `[c_char; 65]` arrays, for which all-zero is a valid value.
        let mut un: Utsname = unsafe { core::mem::zeroed() };
        assert_eq!(uname(&mut un), 0, "uname(2) succeeds on Linux");
        assert_eq!(un.sysname[5], 0, "Linux is NUL-terminated");
        let sysname: [u8; 5] = core::array::from_fn(|i| un.sysname[i] as u8);
        assert_eq!(sysname, *b"Linux");
        // `rand_unix.c:459-461` parses the major and minor out of `release` with `atoi` and
        // `strchr`. Both are exercised the way the call site uses them.
        let major = atoi(un.release.as_ptr());
        assert!(major >= 2, "a Linux kernel major above 2, got {major}");
        // SAFETY: `un.release` is a NUL-terminated array of 65 bytes.
        let dot = unsafe { strchr(un.release.as_ptr(), b'.' as c_int) };
        assert!(
            !dot.is_null(),
            "a release always has a dot: {:?}",
            un.release
        );
    }

    /// `atoi` is the C one, including its tolerance of leading space and its stop at the first
    /// non-digit. `rand_unix.c` depends on both.
    #[test]
    fn atoi_is_the_c_atoi() {
        assert_eq!(atoi(c"4.8".as_ptr()), 4);
        assert_eq!(atoi(c"12x".as_ptr()), 12);
        assert_eq!(atoi(c"  7".as_ptr()), 7);
        assert_eq!(atoi(c"".as_ptr()), 0);
        assert_eq!(atoi(c"not-a-number".as_ptr()), 0);
    }

    /// `getpid` is this process's, and `clock_gettime(CLOCK_REALTIME)` answers a plausible wall
    /// clock -- which is what `get_time_stamp` (`rand_unix.c:782-802`) mixes into the nonce.
    #[test]
    fn getpid_and_clock_gettime_answer_this_process() {
        assert!(getpid() > 0);
        // SAFETY: `Timespec` is two integers, for which all-zero is a valid value.
        let mut ts: Timespec = unsafe { core::mem::zeroed() };
        assert_eq!(clock_gettime(CLOCK_REALTIME, &mut ts), 0);
        assert!(
            ts.tv_sec > 1_600_000_000,
            "the realtime clock is past 2020, got {}",
            ts.tv_sec
        );
    }

    /// `fd_zero` then `fd_set` sets exactly the bit `FD_SET` would, in the word
    /// `fd / __NFDBITS`, with the mask `1 << (fd % __NFDBITS)`.
    #[test]
    fn fd_zero_and_fd_set_agree_with_the_macro() {
        let mut set = FdSet {
            fds_bits: [-1; FD_WORDS],
        };
        fd_zero(&mut set);
        assert!(
            set.fds_bits.iter().all(|w| *w == 0),
            "FD_ZERO clears every word"
        );
        fd_set(0, &mut set);
        assert_eq!(set.fds_bits[0], 1, "descriptor 0 is bit 0 of word 0");
        fd_set(65, &mut set);
        assert_eq!(set.fds_bits[1], 1 << 1, "descriptor 65 is bit 1 of word 1");
        fd_set(63, &mut set);
        assert_eq!(
            set.fds_bits[0],
            1 | (1 << 63),
            "descriptor 63 is the top bit of word 0"
        );
        assert_eq!(set.fds_bits[2], 0);
    }

    /// **The documented divergence, asserted as one.** glibc's `FD_SET` performs no bounds check,
    /// so an out-of-range descriptor writes past the set; this masks the index so the write stays
    /// inside. The test pins the defined behaviour rather than leaving it to be discovered.
    #[test]
    fn fd_set_masks_an_out_of_range_descriptor_into_the_set() {
        let mut set = FdSet {
            fds_bits: [0; FD_WORDS],
        };
        fd_set(FD_SETSIZE + 3, &mut set);
        // 1027 / 64 = 16, masked to word 0; 1027 % 64 = 3.
        assert_eq!(set.fds_bits[0], 1 << 3);
    }

    /// `fstat` over a descriptor this crate opened, with the `Stat` offsets checked against the
    /// kernel's answer rather than against a constant: `/dev/urandom` and `/dev/null` are
    /// character devices, which is what `S_IFCHR` says, and their `st_rdev` is non-zero while a
    /// regular file's is not.
    #[test]
    fn fstat_reports_a_character_device_for_dev_urandom() {
        // SAFETY: a NUL-terminated path and a two-argument `open` against the C prototype.
        let fd = unsafe { open(c"/dev/urandom".as_ptr(), O_RDONLY) };
        assert!(fd >= 0, "opening /dev/urandom for reading");
        // SAFETY: `Stat` is a byte image of `struct stat`, for which all-zero is valid.
        let mut st: Stat = unsafe { core::mem::zeroed() };
        assert_eq!(fstat(fd, &mut st), 0);
        assert_eq!(
            st.st_mode & 0o170000,
            0o020000,
            "S_IFCHR: /dev/urandom is a character device, so st_mode's type bits are 2"
        );
        assert_ne!(st.st_dev, 0);
        // SAFETY: `fd` came from `open` above and is closed exactly once.
        unsafe { close(fd) };
    }

    /// `getentropy` fills the buffer, and refuses more than 256 bytes.
    #[test]
    fn getentropy_fills_the_buffer_and_has_the_kernels_limit() {
        let mut buf = [0u8; 32];
        // SAFETY: `buf` is a live, writable 32-byte buffer.
        let rc = unsafe { getentropy(buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, 0, "getentropy(2) succeeds");
        assert!(
            buf.iter().any(|b| *b != 0),
            "32 random bytes are not all zero"
        );

        let mut big = [0u8; 257];
        // SAFETY: `big` is a live, writable 257-byte buffer; the kernel's answer is the assertion.
        let rc = unsafe { getentropy(big.as_mut_ptr().cast(), big.len()) };
        assert_eq!(rc, -1, "getentropy(2) refuses buflen > 256 with EINVAL");
    }

    /// The `syscall` path with this profile's number reaches `getrandom(2)`. This is the one that
    /// proves `__NR_getrandom` is right rather than merely remembered: a wrong number answers
    /// `-1` with `ENOSYS` instead of filling the buffer.
    #[test]
    fn the_syscall_getrandom_path_answers_bytes() {
        let mut buf = [0u8; 16];
        // SAFETY: `__NR_getrandom` is this profile's number and `buf` is live for 16 bytes.
        let rc = unsafe {
            syscall(
                __NR_getrandom,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        assert_eq!(
            rc, 16,
            "getrandom wrote 16 bytes; -1 with ENOSYS would mean a wrong number"
        );
        assert!(buf.iter().any(|b| *b != 0));
    }
}
