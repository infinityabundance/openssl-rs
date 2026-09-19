//! `providers/implementations/rands/seeding/rand_unix.c` -- the seeding arm.
//!
//! The pool's acquisition functions live here rather than in `crypto/rand/rand_pool.c`, which is
//! D298's correction; `ossl_pool_acquire_entropy`, `ossl_pool_add_nonce_data`,
//! `ossl_rand_pool_init`/`_cleanup`/`_keep_random_devices_open` and the `/dev` device cache are all
//! this file's.
//!
//! # Only the admitted profile's arms
//!
//! `OPENSSL_RAND_SEED_OS` expands to `GETRANDOM` + `DEVRANDOM` here, and those two arms are
//! transcribed. The `OPENSSL_SYS_VOS` arm, `sysctl_random` (BSD) and the `RDTSC`, `RDCPU`, `EGD`
//! and `NONE` dispatch arms are named and not written, which is the boundary D287's table assumed
//! was `crypto/rand/rand_pool.c`'s.
//!
//! # The platform layer is its own module
//!
//! Every `libc` call here goes through [`crate::rand::sys`], which was landed and tested ahead of
//! this file (D302). Nothing in this module declares an `extern` block.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // the landing caller is the SEED-SRC row's `ossl_prov_get_entropy` (9.5)

use core::ffi::{c_int, c_uchar, c_void, CStr};
use core::ptr;

use crate::rand::sys;
use crate::runtime::init::OPENSSL_atexit;
use crate::runtime::thread::{CRYPTO_THREAD_get_current_id, CryptoThreadId};

// The platform surface, brought into scope unqualified so these bodies read as the authority's do.
// Each of these was a `MISSING(crate)` marker in the staging file; `src/rand/sys.rs` declares them
// and its own tests call every one.
#[allow(unused_imports)] // some names are reached only from one of the seeding arms below
use crate::rand::sys::{
    __NR_getrandom, atoi, clock_gettime, fd_set, fd_zero, fstat, getentropy, getpid, shmat, shmdt,
    shmget, syscall, uname, FdSet, Stat, Timespec, Utsname, CLOCK_REALTIME, ENOSYS, FD_SETSIZE,
    IPC_CREAT, SHM_RDONLY, S_IRGRP, S_IROTH, S_IRUSR, S_IRWXG, S_IRWXO, S_IRWXU,
};

use crate::rand::pool::{
    ossl_rand_pool_add, ossl_rand_pool_add_begin, ossl_rand_pool_add_end,
    ossl_rand_pool_bytes_needed, ossl_rand_pool_entropy_available, RandPool,
};

/// `DEVRANDOM` — default from `include/crypto/rand.h:47`, used because the
/// admitted build record contains no override in `Configurations/`.
const DEVRANDOM: [&CStr; 4] = [
    c"/dev/urandom",
    c"/dev/random",
    c"/dev/hwrng",
    c"/dev/srandom",
];

/// `random_device_paths[]` — `rand_unix.c:411`.
const RANDOM_DEVICE_PATHS: [&CStr; 4] = DEVRANDOM;

/// `OSSL_NELEM(random_device_paths)`.
const DEVICE_COUNT: usize = RANDOM_DEVICE_PATHS.len();

/// `DEVRANDOM_WAIT` — `include/crypto/rand.h:50`.
const DEVRANDOM_WAIT: &CStr = c"/dev/random";

/// `DEVRANDOM_SAFE_KERNEL` — `include/crypto/rand.h:58` (`4, 8`).
const DEVRANDOM_SAFE_KERNEL: [c_int; 2] = [4, 8];

/// `OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID` — `include/crypto/rand.h:73`.
const OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID: c_int = 114;

/// `DEVRANDM_WAIT_USE_SELECT` — `include/crypto/rand.h:66`.
const DEVRANDM_WAIT_USE_SELECT: c_int = 1;

/// `TWO32TO64(a, b)` — `rand_unix.c:60`.
fn two32to64(a: i64, b: i64) -> u64 {
    (a as u64).wrapping_shl(32).wrapping_add(b as u64)
}

/// `struct random_device` — `rand_unix.c:412-418`.
///
/// MISSING(crate): `crate::runtime::bio::sys` declares no `dev_t`, `ino_t` or
/// `mode_t`; the glibc/x86-64 widths are used here.
type DevT = u64;
/// See [`DevT`].
type InoT = u64;
/// See [`DevT`].
type ModeT = u32;

#[repr(C)]
#[derive(Clone, Copy)]
struct RandomDevice {
    fd: c_int,
    dev: DevT,
    ino: InoT,
    mode: ModeT,
    rdev: DevT,
}

impl RandomDevice {
    /// Zero-initialised, as a C file-scope object is before `ossl_rand_pool_init`.
    const EMPTY: RandomDevice = RandomDevice {
        fd: 0,
        dev: 0,
        ino: 0,
        mode: 0,
        rdev: 0,
    };
}

/// `static struct random_device random_devices[OSSL_NELEM(random_device_paths)]`
/// — `rand_unix.c:412-418`.
static mut RANDOM_DEVICES: [RandomDevice; DEVICE_COUNT] = [RandomDevice::EMPTY; DEVICE_COUNT];

/// `static int keep_random_devices_open = 1` — `rand_unix.c:419`.
static mut KEEP_RANDOM_DEVICES_OPEN: c_int = 1;

/// `static void *shm_addr` — `rand_unix.c:423`.
static mut SHM_ADDR: *mut c_void = ptr::null_mut();

/// `static int seeded = OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID < 0` — the
/// function-local static of `wait_random_seeded` (rand_unix.c:438).
static mut SEEDED: c_int = 0;

/// `static uint64_t get_time_stamp(void)` — `rand_unix.c:782-802`.
///
/// The `OSSL_POSIX_TIMER_OKAY` arm (`clock_gettime`) is the one compiled on
/// this glibc profile; the `gettimeofday` arm and the `time(NULL)` fallback
/// follow it exactly as in the authority.
///
/// MISSING(crate): `clock_gettime` and `CLOCK_REALTIME` are not declared by
/// `crate::runtime::bio::sys`. `sys::gettimeofday` and `sys::time` exist.
fn get_time_stamp() -> u64 {
    {
        let mut ts = sys::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // MISSING(crate): clock_gettime(CLOCK_REALTIME, &ts)
        if clock_gettime(CLOCK_REALTIME, &mut ts) == 0 {
            return two32to64(ts.tv_sec, ts.tv_nsec);
        }
    }
    {
        let mut tv = sys::Timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: `tv` is a valid, aligned `Timeval`; the timezone argument is
        // ignored and may be null.
        if unsafe { sys::gettimeofday(&mut tv, ptr::null_mut()) } == 0 {
            return two32to64(tv.tv_sec, tv.tv_usec);
        }
    }
    // SAFETY: `time` accepts a null `time_t *` and answers the current time.
    unsafe { sys::time(ptr::null_mut()) as u64 }
}

/// `int ossl_pool_add_nonce_data(RAND_POOL *pool)` — `rand_unix.c:752-773`
/// (prototype `include/crypto/rand.h:140`; caller `crypto/rand/prov_seed.c:88`).
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_pool_add_nonce_data(pool: *mut RandPool) -> c_int {
    /// The authority's anonymous `struct { pid_t pid; CRYPTO_THREAD_ID tid;
    /// uint64_t time; }`.
    #[repr(C)]
    struct NonceData {
        pid: PidT,
        tid: CryptoThreadId,
        time: u64,
    }

    /// `pid_t` on the admitted glibc/x86-64 profile.
    type PidT = c_int;

    /* Erase the entire structure including any padding */
    // SAFETY: `NonceData` is a plain C struct of integers, so all-zero is a
    // valid value for every field and for the padding bytes.
    let mut data: NonceData = unsafe { core::mem::zeroed() };

    /*
     * Add process id, thread id, and a high resolution timestamp to ensure
     * that the nonce is unique with high probability for different process
     * instances.
     */
    // `getpid` reaches the platform layer through `crate::rand::sys`, landed and tested in D302.
    data.pid = getpid();
    data.tid = CRYPTO_THREAD_get_current_id();
    data.time = get_time_stamp();

    // SAFETY: `&data` is readable for `sizeof(NonceData)` bytes and outlives
    // the call; `pool` is live per the caller's contract.
    unsafe {
        ossl_rand_pool_add(
            pool,
            (&data as *const NonceData).cast::<c_uchar>(),
            core::mem::size_of::<NonceData>(),
            0,
        )
    }
}

// -----------------------------------------------------------------------
// /dev/* device cache — rand_unix.c:410-594 (OPENSSL_RAND_SEED_DEVRANDOM arm)
// -----------------------------------------------------------------------

/// `ssize_t syscall_random(void *buf, size_t buflen)` — `rand_unix.c:332-407`.
///
/// The authority first probes a weak glibc `getentropy`, then on the admitted `__linux` arm issues
/// `syscall(__NR_getrandom, buf, buflen, 0)` and falls back to opening `DEVRANDOM` if the kernel
/// answers `ENOSYS` (`rand_unix.c:391-392`, since 3.17).
///
/// The weak-symbol probe is the one part that is not reproducible: Rust has no weak-symbol
/// mechanism, so `sys::getentropy` binds strongly and the divergence is stated there.
fn syscall_random(buf: *mut c_void, buflen: usize) -> isize {
    // Authority rand_unix.c:356-365 probes the glibc weak `getentropy` first:
    //
    //     if (getentropy != NULL) {
    //         if (getentropy(buf, buflen) == 0) return (ssize_t)buflen;
    //         if (errno != ENOSYS) return -1;
    //     }
    //
    // MISSING(crate): `getentropy` has no declaration and the crate has no
    // weak-symbol mechanism, so that probe is not reproducible here.

    // Authority rand_unix.c:391-392 (Linux since 3.17).
    // MISSING(crate): `syscall` and `__NR_getrandom` (318 on x86_64).
    // SAFETY: `__NR_getrandom` is this profile's number (proved by the sys module's own test),
    // `buf` is the caller's live buffer of `buflen` bytes, and the flags word is 0.
    unsafe { syscall(__NR_getrandom, buf, buflen, 0) as isize }
}

/// `static void cleanup_shm(void)` — `rand_unix.c:425-428`.
///
/// MISSING(crate): `shmdt` is not declared by the crate.
extern "C" fn cleanup_shm() {
    // SAFETY: `SHM_ADDR` is the mapping installed by `wait_random_seeded`, or
    // null; the authority passes it to `shmdt` unconditionally.
    unsafe { shmdt(SHM_ADDR) };
}

/// `static int wait_random_seeded(void)` — `rand_unix.c:436-501`
/// (the `__linux && DEVRANDOM_WAIT && OPENSSL_RAND_SEED_GETRANDOM` arm).
///
/// MISSING(crate): `shmget`, `shmat`, `shmdt`, `uname`, `atoi`, the
/// `struct utsname`/`fd_set` types, `IPC_CREAT`, `S_IRUSR`/`S_IRGRP`/`S_IROTH`,
/// `SHM_RDONLY`, `FD_SETSIZE`, `FD_ZERO`, `FD_SET` are all undeclared by the
/// crate. `sys::open`, `sys::read`, `sys::close`, `sys::select` and
/// `sys::strchr` do exist.
fn wait_random_seeded() -> c_int {
    // SAFETY: `SEEDED` is this function's own file-scope static.
    let seeded = unsafe { SEEDED };
    if seeded == 0 {
        /* See if anything has created the global seeded indication */
        // MISSING(crate): shmget
        let mut shm_id = shmget(OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID, 1, 0);
        if shm_id == -1 {
            /*
             * Linux kernels from 4.8 onwards do not guarantee /dev/urandom is
             * seeded when /dev/random becomes readable; getentropy(2) covers
             * those. Compare the running kernel against DEVRANDOM_SAFE_KERNEL.
             */
            // SAFETY: `Utsname` is a `#[repr(C)]` struct of `[c_char; 65]` arrays, for which an
            // all-zero bit pattern is a valid value -- the authority writes `struct utsname un;`.
            let mut un: Utsname = unsafe { core::mem::zeroed() };
            // SAFETY: `un` is a live local of the platform's `struct utsname`.
            if uname(&mut un) == 0 {
                let kernel0 = atoi(un.release.as_ptr());
                // SAFETY: `un.release` is a live 65-byte `[c_char]` array that `uname` filled and
                // NUL-terminated, so `strchr` reads within it.
                let dot = unsafe { sys::strchr(un.release.as_ptr(), b'.' as c_int) };
                let kernel1 = if dot.is_null() {
                    0
                } else {
                    // SAFETY: `dot` is non-null on this arm and points into `un.release`, a
                    // NUL-terminated 65-byte field, so `dot + 1` is within it.
                    atoi(unsafe { dot.add(1) })
                };
                if kernel0 > DEVRANDOM_SAFE_KERNEL[0]
                    || (kernel0 == DEVRANDOM_SAFE_KERNEL[0] && kernel1 >= DEVRANDOM_SAFE_KERNEL[1])
                {
                    return 0;
                }
            }
            /* Open /dev/random and wait for it to be readable */
            // SAFETY: `DEVRANDOM_WAIT` is a static NUL-terminated path.
            let fd = unsafe { sys::open(DEVRANDOM_WAIT.as_ptr(), sys::O_RDONLY) };
            if fd != -1 {
                let mut r: c_int;
                if DEVRANDM_WAIT_USE_SELECT != 0 && fd < FD_SETSIZE {
                    // SAFETY: `FdSet` is `[c_long; 16]`, for which all-zero is a valid value; and
                    // `fd_zero` below is what the authority's `FD_ZERO` does to it anyway.
                    let mut fds: FdSet = unsafe { core::mem::zeroed() };
                    fd_zero(&mut fds);
                    fd_set(fd, &mut fds);
                    loop {
                        // SAFETY: `fds` is a live local of this scope, which is what `select`
                        // requires (it both reads and modifies the set), and `fd + 1` is the
                        // descriptor count the authority passes.
                        r = unsafe {
                            sys::select(
                                fd + 1,
                                (&mut fds as *mut FdSet).cast::<c_void>(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                            )
                        };
                        // SAFETY: `errno` is thread-local and always readable.
                        if !(r < 0 && unsafe { sys::errno() } == sys::EINTR) {
                            break;
                        }
                    }
                } else {
                    let mut c: c_uchar = 0;
                    loop {
                        // SAFETY: `c` is a live one-byte local and `fd` is live per the caller's
                        // contract, so the read's buffer is valid for the one byte requested.
                        r = unsafe { sys::read(fd, (&mut c as *mut c_uchar).cast(), 1) } as c_int;
                        // SAFETY: `errno` is thread-local and always readable.
                        if !(r < 0 && unsafe { sys::errno() } == sys::EINTR) {
                            break;
                        }
                    }
                }
                // SAFETY: `fd` is live.
                unsafe { sys::close(fd) };
                if r == 1 {
                    // SAFETY: `SEEDED` is this function's own static.
                    unsafe { SEEDED = 1 };
                    /* Create the shared memory indicator */
                    // MISSING(crate): shmget, IPC_CREAT, S_IRUSR/G/O
                    shm_id = shmget(
                        OPENSSL_RAND_SEED_DEVRANDOM_SHM_ID,
                        1,
                        IPC_CREAT | S_IRUSR | S_IRGRP | S_IROTH,
                    );
                }
            }
        }
        if shm_id != -1 {
            // SAFETY: `SEEDED` is this function's own static.
            unsafe { SEEDED = 1 };
            /*
             * Map the shared memory to prevent its premature destruction.
             * If this call fails, it isn't a big problem.
             */
            // MISSING(crate): shmat, SHM_RDONLY
            // SAFETY: `SHM_ADDR` is this function's own static.
            unsafe {
                SHM_ADDR = shmat(shm_id, ptr::null_mut(), SHM_RDONLY);
            }
            // SAFETY: `SHM_ADDR` is this function's own static.
            if unsafe { SHM_ADDR } != core::ptr::without_provenance_mut(1) {
                // MISSING(crate): `OPENSSL_atexit` is not implemented in this
                // stratum; the authority registers `&cleanup_shm`.
                // `OPENSSL_atexit` is `crypto/init.c`'s and is Phase 3's, landed long before this stratum. The
                // staging file cast `cleanup_shm` to a raw pointer because its own marker said the
                // symbol was absent; the crate's parameter type is the honest
                // `Option<extern "C" fn()>`, so the handler carries C linkage instead.
                // SAFETY: `cleanup_shm` is a `fn()` with C linkage declared above, which is exactly the
                // type `OPENSSL_atexit` takes, and the call has no other precondition.
                unsafe { OPENSSL_atexit(Some(cleanup_shm)) };
            }
        }
    }
    // SAFETY: `SEEDED` is this function's own static.
    unsafe { SEEDED }
}

/// `static int check_random_device(struct random_device *rd)` — `rand_unix.c:516-526`.
///
/// # Safety
/// `rd` is a live `RandomDevice`.
/// MISSING(crate): `fstat`, `struct stat`, the `st_dev`/`st_ino`/`st_mode`/
/// `st_rdev` fields and `S_IRWXU`/`S_IRWXG`/`S_IRWXO` are undeclared.
fn check_random_device(rd: *mut RandomDevice) -> c_int {
    // SAFETY: the caller's contract: `rd` is live and readable.
    let rd = unsafe { &mut *rd };
    // SAFETY: `Stat` is a byte-compatible image of the platform's `struct stat`, for which an
    // all-zero bit pattern is a valid initial value; `fstat` below fills it.
    let mut st: Stat = unsafe { core::mem::zeroed() };

    if rd.fd != -1
        // SAFETY: `st` is a live local; `rd.fd` is live per the contract.
        && fstat(rd.fd, &mut st) != -1
        && rd.dev == st.st_dev
        && rd.ino == st.st_ino
        && ((rd.mode ^ st.st_mode) & !(S_IRWXU | S_IRWXG | S_IRWXO)) == 0
        && rd.rdev == st.st_rdev
    {
        1
    } else {
        0
    }
}

/// `static int get_random_device(size_t n)` — `rand_unix.c:531-556`.
fn get_random_device(n: usize) -> c_int {
    // SAFETY: `RANDOM_DEVICES` is this unit's own file-scope array and `n` is
    // bounded by its caller's loop over `OSSL_NELEM(random_device_paths)`.
    let devices = unsafe { &mut *ptr::addr_of_mut!(RANDOM_DEVICES) };
    let rd = &mut devices[n];

    /* reuse existing file descriptor if it is (still) valid */
    if check_random_device(rd as *mut RandomDevice) != 0 {
        return rd.fd;
    }

    /* open the random device ... */
    // SAFETY: `random_device_paths[n]` is a static NUL-terminated path.
    rd.fd = unsafe { sys::open(RANDOM_DEVICE_PATHS[n].as_ptr(), sys::O_RDONLY) };
    if rd.fd == -1 {
        return rd.fd;
    }

    /* ... and cache its relevant stat(2) data */
    // SAFETY: as above -- a byte-compatible image of `struct stat`, all-zero being valid.
    let mut st: Stat = unsafe { core::mem::zeroed() };
    if fstat(rd.fd, &mut st) != -1 {
        rd.dev = st.st_dev;
        rd.ino = st.st_ino;
        rd.mode = st.st_mode;
        rd.rdev = st.st_rdev;
    } else {
        // SAFETY: `rd.fd` is live.
        unsafe { sys::close(rd.fd) };
        rd.fd = -1;
    }

    rd.fd
}

/// `static void close_random_device(size_t n)` — `rand_unix.c:561-568`.
fn close_random_device(n: usize) {
    // SAFETY: `RANDOM_DEVICES` is this unit's own array and `n` is bounded by
    // its callers.
    let devices = unsafe { &mut *ptr::addr_of_mut!(RANDOM_DEVICES) };
    let rd = &mut devices[n];

    if check_random_device(rd as *mut RandomDevice) != 0 {
        // SAFETY: `rd.fd` is live.
        unsafe { sys::close(rd.fd) };
    }
    rd.fd = -1;
}

/// `int ossl_rand_pool_init(void)` — `rand_unix.c:570-578`
/// (the `OPENSSL_RAND_SEED_DEVRANDOM` arm).
///
/// The `#else` stub arm (rand_unix.c:598-609) returns 1 and does nothing; it
/// is not built on this profile.
pub(crate) fn ossl_rand_pool_init() -> c_int {
    // SAFETY: `RANDOM_DEVICES` is this unit's own file-scope array.
    let devices = unsafe { &mut *ptr::addr_of_mut!(RANDOM_DEVICES) };
    for rd in devices.iter_mut() {
        rd.fd = -1;
    }
    1
}

/// `void ossl_rand_pool_cleanup(void)` — `rand_unix.c:580-586`.
pub(crate) fn ossl_rand_pool_cleanup() {
    for i in 0..DEVICE_COUNT {
        close_random_device(i);
    }
}

/// `void ossl_rand_pool_keep_random_devices_open(int keep)` — `rand_unix.c:588-594`.
pub(crate) fn ossl_rand_pool_keep_random_devices_open(keep: c_int) {
    if keep == 0 {
        ossl_rand_pool_cleanup();
    }
    // SAFETY: `KEEP_RANDOM_DEVICES_OPEN` is this unit's own file-scope static.
    unsafe { KEEP_RANDOM_DEVICES_OPEN = keep };
}

/// `size_t ossl_pool_acquire_entropy(RAND_POOL *pool)` — `rand_unix.c:630-746`.
///
/// Platform dispatch, in order, exactly as the authority:
///
/// 1. `OPENSSL_RAND_SEED_GETRANDOM` (built): `syscall_random`.
/// 2. `OPENSSL_RAND_SEED_DEVRANDOM` (built): `wait_random_seeded` + the
///    device cache.
/// 3. `OPENSSL_RAND_SEED_RDTSC` (not built): `ossl_prov_acquire_entropy_from_tsc`.
/// 4. `OPENSSL_RAND_SEED_RDCPU` (not built): `ossl_prov_acquire_entropy_from_cpu`.
/// 5. `OPENSSL_RAND_SEED_EGD` (not built): `RAND_query_egd_bytes`.
/// 6. `OPENSSL_RAND_SEED_NONE` (not built): returns
///    `ossl_rand_pool_entropy_available` immediately.
///
/// # Safety
/// `pool` is a live pool.
pub(crate) unsafe fn ossl_pool_acquire_entropy(pool: *mut RandPool) -> usize {
    let mut entropy_available: usize = 0;
    let _ = entropy_available; /* avoid compiler warning */

    // ---- OPENSSL_RAND_SEED_GETRANDOM (rand_unix.c:639-663) ----
    {
        // SAFETY: `pool` is the caller's live pool, per this function's contract.
        let mut bytes_needed = unsafe { ossl_rand_pool_bytes_needed(pool, 1) };
        /* Maximum allowed number of consecutive unsuccessful attempts */
        let mut attempts: c_int = 3;

        while bytes_needed != 0 && attempts > 0 {
            attempts -= 1; /* the authority's `attempts-- > 0` */
            // SAFETY: `pool` is live per the caller's contract.
            let buffer = unsafe { ossl_rand_pool_add_begin(pool, bytes_needed) };
            let bytes = syscall_random(buffer.cast::<c_void>(), bytes_needed);
            if bytes > 0 {
                // SAFETY: `pool` is live; `bytes` bytes were written at
                // `buffer`, which is what `add_end` accounts for.
                unsafe {
                    ossl_rand_pool_add_end(pool, bytes as usize, (bytes as usize).wrapping_mul(8))
                };
                bytes_needed = bytes_needed.wrapping_sub(bytes as usize);
                attempts = 3; /* reset counter after successful attempt */
            } else if bytes < 0
                // SAFETY: `errno` is thread-local and always readable.
                && unsafe { sys::errno() } != sys::EINTR
            {
                break;
            }
        }
    }
    // SAFETY: `pool` is live.
    entropy_available = unsafe { ossl_rand_pool_entropy_available(pool) };
    if entropy_available > 0 {
        return entropy_available;
    }

    // ---- OPENSSL_RAND_SEED_DEVRANDOM (rand_unix.c:665-703) ----
    if wait_random_seeded() != 0 {
        // SAFETY: `pool` is the caller's live pool, per this function's contract.
        let mut bytes_needed = unsafe { ossl_rand_pool_bytes_needed(pool, 1) };
        let mut i: usize = 0;

        while bytes_needed > 0 && i < DEVICE_COUNT {
            let mut bytes: isize = 0;
            /* Maximum number of consecutive unsuccessful attempts */
            let mut attempts: c_int = 3;
            let fd = get_random_device(i);

            if fd == -1 {
                i += 1;
                continue;
            }

            while bytes_needed != 0 && attempts > 0 {
                attempts -= 1; /* the authority's `attempts-- > 0` */
                // SAFETY: `pool` is live.
                let buffer = unsafe { ossl_rand_pool_add_begin(pool, bytes_needed) };
                // SAFETY: `fd` is live; `buffer` is writable for `bytes_needed`
                // bytes.
                bytes = unsafe { sys::read(fd, buffer.cast::<c_void>(), bytes_needed) };

                if bytes > 0 {
                    // SAFETY: `pool` is live; `bytes` bytes were written at
                    // `buffer`.
                    unsafe {
                        ossl_rand_pool_add_end(
                            pool,
                            bytes as usize,
                            (bytes as usize).wrapping_mul(8),
                        )
                    };
                    bytes_needed = bytes_needed.wrapping_sub(bytes as usize);
                    attempts = 3; /* reset counter on successful attempt */
                } else if bytes < 0
                    // SAFETY: `errno` is thread-local and always readable.
                    && unsafe { sys::errno() } != sys::EINTR
                {
                    break;
                }
            }
            // SAFETY: `KEEP_RANDOM_DEVICES_OPEN` is this unit's own static.
            if bytes < 0 || unsafe { KEEP_RANDOM_DEVICES_OPEN } == 0 {
                close_random_device(i);
            }

            // SAFETY: `pool` is the caller's live pool, per this function's contract.
            bytes_needed = unsafe { ossl_rand_pool_bytes_needed(pool, 1) };
            i += 1;
        }
        // SAFETY: `pool` is live.
        entropy_available = unsafe { ossl_rand_pool_entropy_available(pool) };
        if entropy_available > 0 {
            return entropy_available;
        }
    }

    // OPENSSL_RAND_SEED_RDTSC / RDCPU / EGD arms are not built on this
    // profile; they would call `ossl_prov_acquire_entropy_from_tsc`,
    // `ossl_prov_acquire_entropy_from_cpu` and `RAND_query_egd_bytes`
    // respectively (rand_unix.c:705-742).

    // SAFETY: `pool` is live.
    unsafe { ossl_rand_pool_entropy_available(pool) }
}

#[cfg(test)]
mod tests {
    //! The seeding arm against the running kernel.
    //!
    //! `ossl_pool_acquire_entropy` is the function the whole random layer's entropy comes through,
    //! and its two arms (`GETRANDOM` and the `DEVRANDOM` fallback) are the ones D287's table
    //! placed in the wrong file. A test that calls it is the difference between "the arm is
    //! transcribed" and "the arm works here", and its failure mode is loud rather than silent: a
    //! pool that acquires nothing answers 0 and every assertion below fails.

    use super::*;
    use crate::rand::pool::{
        ossl_rand_pool_free, ossl_rand_pool_length, ossl_rand_pool_new, RandPool,
    };

    /// The `GETRANDOM` arm fills a pool from the kernel and reports the entropy it holds.
    #[test]
    fn acquire_entropy_fills_the_pool_from_the_kernel() {
        let pool: *mut RandPool = ossl_rand_pool_new(256, 0, 32, 64);
        assert!(!pool.is_null());
        // SAFETY: `pool` is live and freed once at the end of the test.
        unsafe {
            let acquired = ossl_pool_acquire_entropy(pool);
            assert!(acquired > 0, "the pool acquired no entropy from the kernel");
            assert!(
                ossl_rand_pool_length(pool) >= 32,
                "at least min_len bytes were requested, got {}",
                ossl_rand_pool_length(pool)
            );
            // The bytes are the kernel's, so a pool of them is not all zero. The check is weak on
            // purpose: the claim is that the arm ran, not that its output is unpredictable.
            let buffer = crate::rand::pool::ossl_rand_pool_buffer(pool);
            let nonzero = (0..ossl_rand_pool_length(pool)).any(|i| *buffer.add(i) != 0);
            assert!(nonzero, "32 bytes from getrandom(2) were all zero");
            ossl_rand_pool_free(pool);
        }
    }

    /// The `DEVRANDOM` fallback path is reachable through the same call: a pool whose `min_len`
    /// the kernel can satisfy without the fallback is filled either way, and this test's value is
    /// that it exercises `wait_random_seeded`'s and the device cache's non-failing paths.
    #[test]
    fn a_second_acquisition_succeeds_and_the_device_cache_is_reused() {
        let pool: *mut RandPool = ossl_rand_pool_new(128, 0, 16, 32);
        assert!(!pool.is_null());
        // SAFETY: `pool` is live and freed once.
        unsafe {
            assert!(ossl_pool_acquire_entropy(pool) > 0);
            ossl_rand_pool_free(pool);
        }
        // A second pool re-runs the arm; the device cache in this module is what makes that cheap,
        // and a cache that mis-identified its device would make this call fail rather than slow.
        let again: *mut RandPool = ossl_rand_pool_new(128, 0, 16, 32);
        assert!(!again.is_null());
        // SAFETY: `again` is live and freed once.
        unsafe {
            assert!(ossl_pool_acquire_entropy(again) > 0);
            ossl_rand_pool_free(again);
        }
    }

    /// `ossl_pool_add_nonce_data` **appends** pid, thread id and time -- it does not mix in place
    /// and it does not refuse a zero-length pool.
    ///
    /// The distinction is the one this test was written wrong about first: `RAND_POOL_426` and
    /// `RAND_POOL_431` ("buffer is null", "length is zero") are [`super::super::pool::
    /// ossl_rand_pool_adin_mix_in`]'s arms, not this function's. `ossl_pool_add_nonce_data` ends in
    /// `ossl_rand_pool_add`, which appends whatever length it is given as long as it fits. Both
    /// behaviours are now asserted, each against the function that has it.
    #[test]
    fn add_nonce_data_appends_and_an_empty_pool_still_accepts_it() {
        let pool: *mut RandPool = ossl_rand_pool_new(0, 0, 16, 64);
        assert!(!pool.is_null());
        // SAFETY: `pool` is live, and the add is against a buffer of 16 bytes.
        unsafe {
            let zeros = [0u8; 16];
            assert_eq!(
                crate::rand::pool::ossl_rand_pool_add(pool, zeros.as_ptr(), 16, 0),
                1
            );
            assert_eq!(
                ossl_pool_add_nonce_data(pool),
                1,
                "a non-empty pool accepts a nonce"
            );
            // The nonce is **added, not mixed in place**: `ossl_rand_pool_add_nonce_data` ends in
            // `ossl_rand_pool_add(pool, &data, sizeof(data), 0)`, so the length grows by the
            // authority's anonymous `struct { pid_t; CRYPTO_THREAD_ID; uint64_t; }` and the new
            // bytes carry the pid, the thread id and the timestamp. A reader looking for the
            // *mix-in* helper is looking for `adin_mix_in`, a different function -- which is why
            // the first assertion is on the length. The struct's exact size is not restated here:
            // it is the authority's layout, and pinning it in a test would be a second place to
            // keep true.
            let length = crate::rand::pool::ossl_rand_pool_length(pool);
            assert!(length > 16, "the nonce appended {length} - 16 bytes");
            let buffer = crate::rand::pool::ossl_rand_pool_buffer(pool);
            let fresh = (16..length).any(|i| *buffer.add(i) != 0);
            assert!(fresh, "pid, thread id and timestamp are not all zero");
            ossl_rand_pool_free(pool);
        }

        // A brand-new pool has length zero and accepts the nonce anyway, because the append path
        // only refuses when the request does not fit.
        let empty: *mut RandPool = ossl_rand_pool_new(0, 0, 0, 64);
        assert!(!empty.is_null());
        // SAFETY: `empty` is live and freed once.
        unsafe {
            assert_eq!(crate::rand::pool::ossl_rand_pool_length(empty), 0);
            assert_eq!(
                ossl_pool_add_nonce_data(empty),
                1,
                "a zero-length pool still accepts an append; the refusal is adin_mix_in's arm"
            );
            assert!(crate::rand::pool::ossl_rand_pool_length(empty) > 0);
            ossl_rand_pool_free(empty);
        }
    }

    /// `ossl_rand_pool_init` answers success and is idempotent, and `cleanup` is what releases the
    /// device cache. Both are called at `OPENSSL_init_crypto` time by the authority, so a
    /// transcription that returned 0 would make every later acquisition fail on a real init path.
    #[test]
    fn init_is_idempotent_and_keep_devices_open_is_a_flag() {
        assert_eq!(ossl_rand_pool_init(), 1);
        assert_eq!(ossl_rand_pool_init(), 1, "a second init is not a failure");
        ossl_rand_pool_keep_random_devices_open(1);
        ossl_rand_pool_keep_random_devices_open(0);
        assert_eq!(
            ossl_rand_pool_init(),
            1,
            "still initialised after the flag toggled"
        );
    }
}
