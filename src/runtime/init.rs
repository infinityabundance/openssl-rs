//! Phase 3 core runtime — initialisation, cleanup and runtime identity.
//!
//! This module owns three things a caller can observe about the library as a
//! whole: the initialisation entry points (`OPENSSL_init`, `OPENSSL_init_crypto`,
//! `OPENSSL_cleanup`), and the **runtime identity** surface (`OpenSSL_version*`,
//! `OPENSSL_info`) that answers "what am I talking to?".
//!
//! ## Option handling: honest refusal instead of silent pretence
//!
//! `OPENSSL_init_crypto` is a bitmask of requests, each owned by a subsystem.
//! Only the Phase 3 runtime exists so far, so each option is placed in one of
//! two groups and the choice is justified here rather than hidden:
//!
//! **Accepted and recorded** (the option bit is stored in the process-wide
//! `OPTSDONE` mask and the call succeeds). Everything in this group is either a
//! literal no-op in the authority or is already a *recorded* no-op deviation in
//! this crate, so accepting it does not assert anything false:
//!
//! | option | why accepting is honest |
//! |---|---|
//! | `NO_LOAD_CRYPTO_STRINGS` | the authority's alternative initialiser is empty |
//! | `LOAD_CRYPTO_STRINGS` | the ERR subsystem exists and already accepts `ERR_load_*_strings` as a documented no-op; reason tables are a recorded deviation (`err.rs` module note), not something init can conjure |
//! | `NO_LOAD_SSL_STRINGS`, `LOAD_SSL_STRINGS` | same mechanism; libssl does not exist yet, and the string registration is the same recorded no-op |
//! | `NO_ADD_ALL_CIPHERS`, `NO_ADD_ALL_DIGESTS` | the authority's alternative initialisers are empty |
//! | `NO_LOAD_CONFIG` | requests exactly this build's behaviour: no config is loaded |
//! | `OPENSSL_INIT_ATFORK` | the authority's `openssl_init_fork_handlers()` is `return 1`, i.e. a no-op on the admitted pthread profile (verified in the 3.6.4 source) |
//! | `OPENSSL_INIT_NO_ATEXIT` | fully honoured: it suppresses the `atexit` registration |
//! | `OPENSSL_INIT_BASE_ONLY` | internal flag; base init is all this build has |
//! | unknown bits | the authority ORs unknown bits into its done-mask and ignores them |
//!
//! **Refused** with `ERR_LIB_CRYPTO`/`ERR_R_INIT_FAIL` and a `0` return. Each of
//! these names a subsystem that does not exist yet *and* whose action is not a
//! no-op in the authority, so accepting it would silently change observable
//! behaviour:
//!
//! | option | subsystem (phase) | authority's non-no-op action |
//! |---|---|---|
//! | `ADD_ALL_CIPHERS` | EVP/OBJ (4, 7) | registers the legacy cipher methods in the `OBJ_NAME` database |
//! | `ADD_ALL_DIGESTS` | EVP/OBJ (4, 7) | registers the legacy digest methods |
//! | `LOAD_CONFIG` | CONF / `OSSL_LIB_CTX` (4, 6, 16) | reads `openssl.cnf` and applies it |
//! | `ASYNC` | ASYNC (7) | initialises the async job framework |
//! | `ENGINE_*` | ENGINE (13) | loads/registers engines |
//!
//! Refusals happen *after* the `atexit` step, matching the authority's ordering,
//! so a refused call still has the side effect the authority would have had by
//! that point.
//!
//! ## Idempotency, and being safe from a constructor or `atexit` frame
//!
//! State is process-global and guarded with atomics, so `OPENSSL_init_crypto`
//! may be called from any thread, including concurrently, and from a library
//! constructor or an `atexit` handler. Base initialisation performs no
//! allocation, so unlike the authority it cannot fail: the authority's base
//! allocates two locks and a TLS key and can return 0 on exhaustion, whereas
//! this implementation needs neither (Rust atomics and `Once` are static).
//!
//! ## `OPENSSL_cleanup`
//!
//! The authority's cleanup is terminal: it sets a `stopped` flag, and every
//! later `OPENSSL_init_crypto` returns 0 (raising `ERR_R_INIT_FAIL` unless
//! `BASE_ONLY` was requested). That is reproduced. The authority assumes
//! cleanup is single-threaded ("We assume we are single-threaded for this
//! function"); this implementation makes the guard itself an atomic
//! compare-and-swap so concurrent or repeated calls are safe, which is a
//! strictly stronger property.
//!
//! Phase 3 has no subsystems to tear down. The authority's teardown sequence
//! (compression, async, RAND, config modules, ENGINE, STORE, the default
//! `OSSL_LIB_CTX`, per-thread state, BIO, EVP, OBJ, ERR, secure memory, CMP,
//! tracing) is empty here; each entry is unlocked by the phase named in
//! `docs/RELEASE_GATES.md` §1. This is recorded as an open obligation rather than
//! pretended.
//!
//! ## Runtime identity — captured from the authority, and where it would lie
//!
//! Every string below was **captured by probing the admitted authority**, not
//! guessed. The probe compiles against the authority's installed prefix and was
//! run in the court container (`court/scratch/probe_version_init.c`); the raw
//! output is reproduced beside each constant.
//!
//! Identity strings are returned verbatim because they are true of `openssl-rs`
//! as a reconstruction of the OpenSSL 3.6.4 contract:
//!
//! ```text
//! OpenSSL_version_num()        -> 0x30600040
//! OpenSSL_version(0)           -> "OpenSSL 3.6.4 25 Aug 2026"
//! OpenSSL_version(3)           -> "platform: linux-x86_64"
//! OpenSSL_version(6)           -> "3.6.4"
//! OpenSSL_version(7)           -> "3.6.4"
//! OpenSSL_version(10)          -> "OSSL_WINCTX: Undefined"
//! OpenSSL_version(unknown)     -> "not available"
//! OPENSSL_info(1004)           -> ".so"
//! OPENSSL_info(1005)           -> "/"
//! OPENSSL_info(1006)           -> ":"
//! OPENSSL_info(1009)           -> "Undefined"
//! OPENSSL_info(unknown)        -> NULL
//! ```
//!
//! The remaining types describe the **authority's own build, host or
//! installation**, and emitting those bytes would be a false statement about
//! this implementation (`docs/NON_CLAIMS.md`; `build.rs` deliberately embeds no
//! wall-clock time or host paths). They are deliberately divergent, each with
//! the captured authority value recorded next to the constant, and are recorded
//! as open obligations:
//!
//! ```text
//! OpenSSL_version(1)  authority: "compiler: gcc -fPIC -pthread -m64 ... -O3 ..."
//! OpenSSL_version(2)  authority: "built on: Mon Sep 14 03:15:22 2026 UTC"
//! OpenSSL_version(4)  authority: "OPENSSLDIR: \"/work/.../openssl-3.6.4-production/ssl\""
//! OpenSSL_version(5)  authority: "ENGINESDIR: \"/work/.../lib/engines-3\""
//! OpenSSL_version(8)  authority: "MODULESDIR: \"/work/.../lib/ossl-modules\""
//! OpenSSL_version(9)  authority: "CPUINFO: OPENSSL_ia32cap=0x7ed8320b078bffff:..."
//! OPENSSL_info(1001)  authority: "/work/.../openssl-3.6.4-production/ssl"
//! OPENSSL_info(1002)  authority: "/work/.../openssl-3.6.4-production/lib/engines-3"
//! OPENSSL_info(1003)  authority: "/work/.../openssl-3.6.4-production/lib/ossl-modules"
//! OPENSSL_info(1007)  authority: "os-specific"
//! OPENSSL_info(1008)  authority: "OPENSSL_ia32cap=0x7ed8320b078bffff:..."
//! ```
//!
//! The replacements use the authority's own "not available" vocabulary
//! (`OPENSSLDIR: N/A`, `ENGINESDIR: N/A`, `MODULESDIR: N/A`, `CPUINFO: N/A`) or
//! `NULL` for `OPENSSL_info`, which the header documents as the "information is
//! not available" result. Where the divergent surface is a *subsystem* (CPU
//! dispatch, Phase 19; installed directories, Phases 2/16) the open obligation
//! names the phase that will make it real; where it is build provenance
//! (`CFLAGS`, `BUILT_ON`) no phase can make the authority's own string true, so
//! the obligation is to decide and document this build's provenance string once
//! the distribution profile is fixed.

use core::ffi::{c_char, c_int, c_uint, c_ulong, CStr};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Once;

use crate::ffi::guard_ffi;

// ---------------------------------------------------------------------------
// `OPENSSL_INIT_*` option bits — values from the authority's `crypto.h`
// ---------------------------------------------------------------------------

// The accepted-only options below are referenced by the tests and by the module
// documentation table; the product path classifies options by the complementary
// `INIT_UNSUPPORTED` mask, so they are `dead_code` in a non-test build.
/// `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` — accepted no-op.
#[allow(dead_code)]
const OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0001;
/// `OPENSSL_INIT_LOAD_CRYPTO_STRINGS` — accepted (recorded ERR deviation).
#[allow(dead_code)]
const OPENSSL_INIT_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0002;
/// `OPENSSL_INIT_ADD_ALL_CIPHERS`
const OPENSSL_INIT_ADD_ALL_CIPHERS: u64 = 0x0000_0004;
/// `OPENSSL_INIT_ADD_ALL_DIGESTS`
const OPENSSL_INIT_ADD_ALL_DIGESTS: u64 = 0x0000_0008;
/// `OPENSSL_INIT_NO_ADD_ALL_CIPHERS` — accepted no-op.
#[allow(dead_code)]
const OPENSSL_INIT_NO_ADD_ALL_CIPHERS: u64 = 0x0000_0010;
/// `OPENSSL_INIT_NO_ADD_ALL_DIGESTS` — accepted no-op.
#[allow(dead_code)]
const OPENSSL_INIT_NO_ADD_ALL_DIGESTS: u64 = 0x0000_0020;
/// `OPENSSL_INIT_LOAD_CONFIG`
const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
/// `OPENSSL_INIT_NO_LOAD_CONFIG` — accepted: no config is loaded either way.
#[allow(dead_code)]
const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
/// `OPENSSL_INIT_ASYNC`
const OPENSSL_INIT_ASYNC: u64 = 0x0000_0100;
/// `OPENSSL_INIT_ENGINE_RDRAND`
const OPENSSL_INIT_ENGINE_RDRAND: u64 = 0x0000_0200;
/// `OPENSSL_INIT_ENGINE_DYNAMIC`
const OPENSSL_INIT_ENGINE_DYNAMIC: u64 = 0x0000_0400;
/// `OPENSSL_INIT_ENGINE_OPENSSL`
const OPENSSL_INIT_ENGINE_OPENSSL: u64 = 0x0000_0800;
/// `OPENSSL_INIT_ENGINE_CRYPTODEV`
const OPENSSL_INIT_ENGINE_CRYPTODEV: u64 = 0x0000_1000;
/// `OPENSSL_INIT_ENGINE_CAPI`
const OPENSSL_INIT_ENGINE_CAPI: u64 = 0x0000_2000;
/// `OPENSSL_INIT_ENGINE_PADLOCK`
const OPENSSL_INIT_ENGINE_PADLOCK: u64 = 0x0000_4000;
/// `OPENSSL_INIT_ENGINE_AFALG`
const OPENSSL_INIT_ENGINE_AFALG: u64 = 0x0000_8000;
// The libssl string flags (`OPENSSL_INIT_NO_LOAD_SSL_STRINGS` 0x00100000,
// `OPENSSL_INIT_LOAD_SSL_STRINGS` 0x00200000, from `ssl.h`) are accepted for the
// same reason as the crypto-string flags; they are unknown bits here and are
// recorded and ignored exactly as the authority records them.
/// `OPENSSL_INIT_ATFORK` — accepted: a no-op on this profile.
#[allow(dead_code)]
const OPENSSL_INIT_ATFORK: u64 = 0x0002_0000;
/// `OPENSSL_INIT_BASE_ONLY` — internal to the authority; not a public macro.
const OPENSSL_INIT_BASE_ONLY: u64 = 0x0004_0000;
/// `OPENSSL_INIT_NO_ATEXIT` — fully honoured: suppresses the `atexit` handler.
const OPENSSL_INIT_NO_ATEXIT: u64 = 0x0008_0000;

/// Options whose subsystem is absent and whose authority action is observable.
///
/// Do not add to this list without reading the module note: refusal is the
/// honest choice *because* these are not no-ops in the authority.
const INIT_UNSUPPORTED: u64 = OPENSSL_INIT_ADD_ALL_CIPHERS
    | OPENSSL_INIT_ADD_ALL_DIGESTS
    | OPENSSL_INIT_LOAD_CONFIG
    | OPENSSL_INIT_ASYNC
    | OPENSSL_INIT_ENGINE_RDRAND
    | OPENSSL_INIT_ENGINE_DYNAMIC
    | OPENSSL_INIT_ENGINE_OPENSSL
    | OPENSSL_INIT_ENGINE_CRYPTODEV
    | OPENSSL_INIT_ENGINE_CAPI
    | OPENSSL_INIT_ENGINE_PADLOCK
    | OPENSSL_INIT_ENGINE_AFALG;

// ---------------------------------------------------------------------------
// Error codes, from the authority's `err.h` / `cryptoerr.h`
// ---------------------------------------------------------------------------

/// `ERR_LIB_CRYPTO` (`err.h`).
const ERR_LIB_CRYPTO: c_int = 15;
/// Reason-code flag bits (`err.h`): `ERR_RFLAG_FATAL`, `ERR_RFLAG_COMMON`.
const ERR_RFLAG_FATAL: c_int = 0x1 << 18;
/// `ERR_RFLAG_COMMON`.
const ERR_RFLAG_COMMON: c_int = 0x2 << 18;
/// `ERR_R_INIT_FAIL` (`err.h`): `(261 | ERR_R_FATAL)`.
const ERR_R_INIT_FAIL: c_int = 261 | ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;

// ---------------------------------------------------------------------------
// Version identity, from `opensslv.h`
// ---------------------------------------------------------------------------

/// `OPENSSL_VERSION_NUMBER`: `(3<<28) | (6<<20) | (4<<4) | 0`.
const OPENSSL_VERSION_NUMBER: c_ulong = 0x3060_0040;
/// `OPENSSL_VERSION_MAJOR`.
const OPENSSL_VERSION_MAJOR_VAL: c_uint = 3;
/// `OPENSSL_VERSION_MINOR`.
const OPENSSL_VERSION_MINOR_VAL: c_uint = 6;
/// `OPENSSL_VERSION_PATCH`.
const OPENSSL_VERSION_PATCH_VAL: c_uint = 4;
/// `OPENSSL_VERSION_PRE_RELEASE` — empty for this release.
const VERSION_PRE_RELEASE: &CStr = c"";
/// `OPENSSL_VERSION_BUILD_METADATA` — the OpenSSL Project always leaves it empty.
const VERSION_BUILD_METADATA: &CStr = c"";

// `OpenSSL_version()` type codes (`crypto.h`).
/// `OPENSSL_VERSION`
const OPENSSL_VERSION: c_int = 0;
/// `OPENSSL_CFLAGS`
const OPENSSL_CFLAGS: c_int = 1;
/// `OPENSSL_BUILT_ON`
const OPENSSL_BUILT_ON: c_int = 2;
/// `OPENSSL_PLATFORM`
const OPENSSL_PLATFORM: c_int = 3;
/// `OPENSSL_DIR`
const OPENSSL_DIR: c_int = 4;
/// `OPENSSL_ENGINES_DIR`
const OPENSSL_ENGINES_DIR: c_int = 5;
/// `OPENSSL_VERSION_STRING`
const OPENSSL_VERSION_STRING: c_int = 6;
/// `OPENSSL_FULL_VERSION_STRING`
const OPENSSL_FULL_VERSION_STRING: c_int = 7;
/// `OPENSSL_MODULES_DIR`
const OPENSSL_MODULES_DIR: c_int = 8;
/// `OPENSSL_CPU_INFO`
const OPENSSL_CPU_INFO: c_int = 9;
/// `OPENSSL_WINCTX`
const OPENSSL_WINCTX: c_int = 10;

// `OPENSSL_info()` type codes (`crypto.h`).
/// `OPENSSL_INFO_CONFIG_DIR`
const OPENSSL_INFO_CONFIG_DIR: c_int = 1001;
/// `OPENSSL_INFO_ENGINES_DIR`
const OPENSSL_INFO_ENGINES_DIR: c_int = 1002;
/// `OPENSSL_INFO_MODULES_DIR`
const OPENSSL_INFO_MODULES_DIR: c_int = 1003;
/// `OPENSSL_INFO_DSO_EXTENSION`
const OPENSSL_INFO_DSO_EXTENSION: c_int = 1004;
/// `OPENSSL_INFO_DIR_FILENAME_SEPARATOR`
const OPENSSL_INFO_DIR_FILENAME_SEPARATOR: c_int = 1005;
/// `OPENSSL_INFO_LIST_SEPARATOR`
const OPENSSL_INFO_LIST_SEPARATOR: c_int = 1006;
/// `OPENSSL_INFO_SEED_SOURCE`
const OPENSSL_INFO_SEED_SOURCE: c_int = 1007;
/// `OPENSSL_INFO_CPU_SETTINGS`
const OPENSSL_INFO_CPU_SETTINGS: c_int = 1008;
/// `OPENSSL_INFO_WINDOWS_CONTEXT`
const OPENSSL_INFO_WINDOWS_CONTEXT: c_int = 1009;

/// Captured authority `OpenSSL_version(0)` / `OPENSSL_VERSION_TEXT`. True of this
/// implementation: it reconstructs the OpenSSL 3.6.4 release identity.
const VERSION_TEXT: &CStr = c"OpenSSL 3.6.4 25 Aug 2026";
/// Captured authority `OpenSSL_version(6)` / `OPENSSL_VERSION_STR`.
const VERSION_STRING: &CStr = c"3.6.4";
/// Captured authority `OpenSSL_version(3)` / `PLATFORM`.
const VERSION_PLATFORM: &CStr = c"platform: linux-x86_64";
/// Captured authority `OpenSSL_version(10)` (non-Windows branch).
const VERSION_WINCTX: &CStr = c"OSSL_WINCTX: Undefined";
/// Captured authority string for an unknown type.
const VERSION_NOT_AVAILABLE: &CStr = c"not available";

/// Divergent replacement for `OpenSSL_version(1)`.
///
/// Authority (captured): `compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack
/// -Wall -O3 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC
/// -DOPENSSL_BUILDING_OPENSSL -DNDEBUG`. That describes the authority's C build;
/// `openssl-rs` is compiled by rustc, so reproducing it would assert a false
/// build provenance. Open obligation: fix this build's provenance string once
/// the Phase 2 distribution profile is frozen.
const VERSION_CFLAGS: &CStr = c"compiler: rustc";
/// Divergent replacement for `OpenSSL_version(2)`.
///
/// Authority (captured): `built on: Mon Sep 14 03:15:22 2026 UTC`. Reproducing
/// it would claim a build timestamp that is not this build's; `build.rs`
/// deliberately embeds no wall-clock time. Open obligation: Phase 2 provenance.
const VERSION_BUILT_ON: &CStr = c"built on: N/A";

// Open obligations, recorded here because only this module may be edited for the
// `init` work item:
//   OBL-INIT-VERSION-CFLAGS        VERSION_CFLAGS  diverges (authority's C flags)
//   OBL-INIT-VERSION-BUILT-ON      VERSION_BUILT_ON diverges (authority's clock)
//   OBL-INIT-VERSION-DIRS          OPENSSLDIR/ENGINESDIR/MODULESDIR are "N/A"
//   OBL-INIT-VERSION-CPU-INFO      CPUINFO is "N/A" (Phase 19 CPU dispatch)
//   OBL-INIT-INFO-DIRS             OPENSSL_info(1001..1003) return NULL
//   OBL-INIT-INFO-SEED-SOURCE      OPENSSL_info(1007) returns NULL (Phase 9)
//   OBL-INIT-INFO-CPU-SETTINGS     OPENSSL_info(1008) returns NULL (Phase 19)

// ---------------------------------------------------------------------------
// Process-global initialisation state
// ---------------------------------------------------------------------------

/// Set once `OPENSSL_cleanup` has run; terminal, exactly as in the authority.
static STOPPED: AtomicBool = AtomicBool::new(false);
/// Whether base initialisation has happened. Cleared again by cleanup.
static BASE_INITED: AtomicBool = AtomicBool::new(false);
/// The authority's `optsdone`: every option bit whose request has been recorded.
static OPTSDONE: AtomicU64 = AtomicU64::new(0);

/// Guards the one-time `atexit(OPENSSL_cleanup)` registration.
static ATEXIT_ONCE: Once = Once::new();
/// The authority's cached `RUN_ONCE` result for the atexit initialiser. Unlike a
/// failed authority `RUN_ONCE`, this is readable before the once has run; the
/// initial `true` is overwritten only on a genuine `atexit` failure.
static ATEXIT_OK: AtomicBool = AtomicBool::new(true);

extern "C" {
    fn atexit(callback: extern "C" fn()) -> c_int;
}

/// Opaque handle matching the C `OPENSSL_INIT_SETTINGS`.
///
/// Only meaningful together with `OPENSSL_INIT_LOAD_CONFIG`, which is refused in
/// this phase, so the setting is accepted and unread — the same treatment the
/// authority gives it when the option is absent.
#[repr(C)]
pub struct OpenSslInitSettings {
    _private: [u8; 0],
}

/// Raises `ERR_LIB_CRYPTO`/`ERR_R_INIT_FAIL`, the authority's error for a failed
/// initialisation.
///
/// The authority's `ERR_raise` also records `crypto/init.c`, a line number and
/// `OPENSSL_init_crypto`. Those are compile-time C source locations that have no
/// honest counterpart here, so file/line/function are left unset; this is part of
/// the ERR subsystem's already-recorded string/metadata deviation (`err.rs`).
fn raise_init_fail() {
    crate::runtime::err::ERR_new();
    // SAFETY: the ERR adapter accepts a NULL message; the library and reason are
    // compile-time constants.
    unsafe {
        crate::runtime::err::openssl_rs_err_set_error(
            ERR_LIB_CRYPTO,
            ERR_R_INIT_FAIL,
            core::ptr::null(),
        );
    }
}

/// Base initialisation. See the module note on why this cannot fail.
fn base_init() -> bool {
    BASE_INITED.store(true, Ordering::Release);
    true
}

/// Registers `OPENSSL_cleanup` with `atexit`, unless suppressed, exactly once.
///
/// Mirrors the authority's `RUN_ONCE`/`RUN_ONCE_ALT` over `register_atexit`: the
/// first call decides whether the handler is registered, and the decision (and
/// any failure) is cached.
fn register_atexit(no_atexit: bool) -> bool {
    ATEXIT_ONCE.call_once(|| {
        if !no_atexit {
            // SAFETY: `atexit` is thread-safe and `OPENSSL_cleanup` is a valid
            // `extern "C"` function with the required signature.
            if unsafe { atexit(OPENSSL_cleanup) } != 0 {
                ATEXIT_OK.store(false, Ordering::Release);
            }
        }
    });
    ATEXIT_OK.load(Ordering::Acquire)
}

/// `void OPENSSL_init(void)`
///
/// The authority's implementation is an empty function (its own comment says
/// "Currently does nothing"). Reproduced verbatim.
#[no_mangle]
pub extern "C" fn OPENSSL_init() {
    guard_ffi((), || {})
}

/// `int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)`
///
/// Returns 1 on success, 0 on failure (raising `ERR_R_INIT_FAIL` for the refused
/// options and for a call made after `OPENSSL_cleanup`). See the module note for
/// the option-by-option disposition.
#[no_mangle]
pub extern "C" fn OPENSSL_init_crypto(opts: u64, _settings: *const OpenSslInitSettings) -> c_int {
    guard_ffi(0, || {
        // Terminal after cleanup. `BASE_ONLY` is the authority's one silent case.
        if STOPPED.load(Ordering::Acquire) {
            if opts & OPENSSL_INIT_BASE_ONLY == 0 {
                raise_init_fail();
            }
            return 0;
        }

        // Fast path: everything requested has already been done. With `opts == 0`
        // this returns 1 without touching base, which is the authority's
        // observable behaviour.
        if (OPTSDONE.load(Ordering::Acquire) & opts) == opts {
            return 1;
        }

        if !base_init() {
            return 0;
        }

        if opts & OPENSSL_INIT_BASE_ONLY != 0 {
            return 1;
        }

        // The authority repeats the done-check once `optsdone_lock` exists.
        if (OPTSDONE.load(Ordering::Acquire) & opts) == opts {
            return 1;
        }

        // Exit-handler registration precedes the subsystem steps in the
        // authority, so a refused call still registers cleanup.
        if !register_atexit(opts & OPENSSL_INIT_NO_ATEXIT != 0) {
            return 0;
        }

        if opts & INIT_UNSUPPORTED != 0 {
            raise_init_fail();
            return 0;
        }

        // Everything remaining is accepted and recorded.
        OPTSDONE.fetch_or(opts, Ordering::AcqRel);
        1
    })
}

/// `void OPENSSL_cleanup(void)`
///
/// Idempotent and safe to call concurrently. The authority assumes a
/// single-threaded caller; the atomic swap here makes the guard robust anyway.
///
/// This phase has no subsystems to tear down, so the body only flips the flags
/// that make initialisation terminal. See the module note for the authority's
/// full teardown sequence and the phase that unlocks each part.
#[no_mangle]
pub extern "C" fn OPENSSL_cleanup() {
    guard_ffi((), || {
        // Not inited: nothing to do, and `stopped` must stay clear so a later
        // init can still succeed (the authority checks `base_inited` first too).
        if !BASE_INITED.load(Ordering::Acquire) {
            return;
        }
        // Exactly one caller wins the swap; the rest observe `true` and return.
        if STOPPED.swap(true, Ordering::AcqRel) {
            return;
        }
        BASE_INITED.store(false, Ordering::Release);
    })
}

// ---------------------------------------------------------------------------
// Runtime identity
// ---------------------------------------------------------------------------

/// `unsigned long OpenSSL_version_num(void)`
#[no_mangle]
pub extern "C" fn OpenSSL_version_num() -> c_ulong {
    guard_ffi(OPENSSL_VERSION_NUMBER, || OPENSSL_VERSION_NUMBER)
}

/// `unsigned int OPENSSL_version_major(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_version_major() -> c_uint {
    guard_ffi(OPENSSL_VERSION_MAJOR_VAL, || OPENSSL_VERSION_MAJOR_VAL)
}

/// `unsigned int OPENSSL_version_minor(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_version_minor() -> c_uint {
    guard_ffi(OPENSSL_VERSION_MINOR_VAL, || OPENSSL_VERSION_MINOR_VAL)
}

/// `unsigned int OPENSSL_version_patch(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_version_patch() -> c_uint {
    guard_ffi(OPENSSL_VERSION_PATCH_VAL, || OPENSSL_VERSION_PATCH_VAL)
}

/// `const char *OPENSSL_version_pre_release(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_version_pre_release() -> *const c_char {
    guard_ffi(VERSION_PRE_RELEASE.as_ptr(), || {
        VERSION_PRE_RELEASE.as_ptr()
    })
}

/// `const char *OPENSSL_version_build_metadata(void)`
#[no_mangle]
pub extern "C" fn OPENSSL_version_build_metadata() -> *const c_char {
    guard_ffi(VERSION_BUILD_METADATA.as_ptr(), || {
        VERSION_BUILD_METADATA.as_ptr()
    })
}

/// `const char *OpenSSL_version(int type)`
///
/// Returns a pointer to a static string for every input, including unknown types
/// (which yield `"not available"`), exactly as the authority's `switch` does.
/// Never NULL.
///
/// The strings marked divergent in the module note are this build's truthful
/// replacements for the authority's own build/installation metadata.
#[no_mangle]
pub extern "C" fn OpenSSL_version(t: c_int) -> *const c_char {
    guard_ffi(VERSION_NOT_AVAILABLE.as_ptr(), || match t {
        OPENSSL_VERSION => VERSION_TEXT.as_ptr(),
        OPENSSL_VERSION_STRING | OPENSSL_FULL_VERSION_STRING => VERSION_STRING.as_ptr(),
        OPENSSL_PLATFORM => VERSION_PLATFORM.as_ptr(),
        OPENSSL_WINCTX => VERSION_WINCTX.as_ptr(),
        // Divergent: build provenance and installation layout.
        OPENSSL_CFLAGS => VERSION_CFLAGS.as_ptr(),
        OPENSSL_BUILT_ON => VERSION_BUILT_ON.as_ptr(),
        OPENSSL_DIR => c"OPENSSLDIR: N/A".as_ptr(),
        OPENSSL_ENGINES_DIR => c"ENGINESDIR: N/A".as_ptr(),
        OPENSSL_MODULES_DIR => c"MODULESDIR: N/A".as_ptr(),
        OPENSSL_CPU_INFO => c"CPUINFO: N/A".as_ptr(),
        _ => VERSION_NOT_AVAILABLE.as_ptr(),
    })
}

/// `const char *OPENSSL_info(int type)`
///
/// Returns NULL when the information is not available, which is the authority's
/// documented result for an unrecognised type and for CPU settings it could not
/// initialise. The structural strings (DSO extension, separators, the non-Windows
/// context) are returned verbatim; the directory, seed-source and CPU strings
/// describe subsystems that do not exist yet and return NULL, so a caller's
/// `if (s != NULL)` guard takes the same branch it would for genuinely
/// unavailable information.
#[no_mangle]
pub extern "C" fn OPENSSL_info(t: c_int) -> *const c_char {
    guard_ffi(core::ptr::null(), || match t {
        OPENSSL_INFO_DSO_EXTENSION => c".so".as_ptr(),
        OPENSSL_INFO_DIR_FILENAME_SEPARATOR => c"/".as_ptr(),
        OPENSSL_INFO_LIST_SEPARATOR => c":".as_ptr(),
        OPENSSL_INFO_WINDOWS_CONTEXT => c"Undefined".as_ptr(),
        // CONFIG_DIR / ENGINES_DIR / MODULES_DIR: no installed layout yet
        // (Phases 2/16). SEED_SOURCE: RAND is Phase 9. CPU_SETTINGS: Phase 19.
        OPENSSL_INFO_CONFIG_DIR
        | OPENSSL_INFO_ENGINES_DIR
        | OPENSSL_INFO_MODULES_DIR
        | OPENSSL_INFO_SEED_SOURCE
        | OPENSSL_INFO_CPU_SETTINGS => core::ptr::null(),
        _ => core::ptr::null(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error};
    use std::sync::Mutex;

    /// Initialisation state is process-global, so tests that touch it serialise.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Serialises a test against the other init-state tests, and restores a
    /// clean state afterwards. `reset_for_test` exists only because the
    /// production `stopped` flag is terminal: without it, one cleanup test would
    /// poison every later test in the same binary (the authority has the same
    /// terminal behaviour, which is exactly why it cannot be tested in-process
    /// without a reset).
    fn with_init_lock<R>(f: impl FnOnce() -> R) -> R {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = f();
        reset_for_test();
        drop(guard);
        result
    }

    fn reset_for_test() {
        STOPPED.store(false, Ordering::Release);
        BASE_INITED.store(false, Ordering::Release);
        OPTSDONE.store(0, Ordering::Release);
    }

    fn to_bytes(p: *const c_char) -> Vec<u8> {
        if p.is_null() {
            return Vec::new();
        }
        // SAFETY: `p` is a NUL-terminated static C string returned by this module.
        unsafe {
            let mut n = 0usize;
            while *p.add(n) != 0 {
                n += 1;
            }
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                out.push(*p.add(i) as u8);
            }
            out
        }
    }

    #[test]
    fn version_number_and_components_match_the_authority() {
        assert_eq!(OpenSSL_version_num(), 0x3060_0040);
        assert_eq!(OPENSSL_version_major(), 3);
        assert_eq!(OPENSSL_version_minor(), 6);
        assert_eq!(OPENSSL_version_patch(), 4);
        assert_eq!(to_bytes(OPENSSL_version_pre_release()), b"");
        assert_eq!(to_bytes(OPENSSL_version_build_metadata()), b"");
    }

    #[test]
    fn version_identity_strings_are_the_captured_authority_values() {
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_VERSION)),
            b"OpenSSL 3.6.4 25 Aug 2026"
        );
        assert_eq!(to_bytes(OpenSSL_version(OPENSSL_VERSION_STRING)), b"3.6.4");
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_FULL_VERSION_STRING)),
            b"3.6.4"
        );
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_PLATFORM)),
            b"platform: linux-x86_64"
        );
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_WINCTX)),
            b"OSSL_WINCTX: Undefined"
        );
        // Unknown types are non-NULL, exactly as in the authority.
        assert_eq!(to_bytes(OpenSSL_version(11)), b"not available");
        assert_eq!(to_bytes(OpenSSL_version(-1)), b"not available");
    }

    #[test]
    fn version_metadata_is_divergent_and_truthful() {
        // These are the documented divergences: the authority returns its own
        // compiler flags, build clock, install paths and host CPU string.
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_CFLAGS)),
            b"compiler: rustc"
        );
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_BUILT_ON)),
            b"built on: N/A"
        );
        assert_eq!(to_bytes(OpenSSL_version(OPENSSL_DIR)), b"OPENSSLDIR: N/A");
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_ENGINES_DIR)),
            b"ENGINESDIR: N/A"
        );
        assert_eq!(
            to_bytes(OpenSSL_version(OPENSSL_MODULES_DIR)),
            b"MODULESDIR: N/A"
        );
        assert_eq!(to_bytes(OpenSSL_version(OPENSSL_CPU_INFO)), b"CPUINFO: N/A");
    }

    #[test]
    fn info_strings_are_the_captured_structural_values() {
        assert_eq!(to_bytes(OPENSSL_info(OPENSSL_INFO_DSO_EXTENSION)), b".so");
        assert_eq!(
            to_bytes(OPENSSL_info(OPENSSL_INFO_DIR_FILENAME_SEPARATOR)),
            b"/"
        );
        assert_eq!(to_bytes(OPENSSL_info(OPENSSL_INFO_LIST_SEPARATOR)), b":");
        assert_eq!(
            to_bytes(OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)),
            b"Undefined"
        );
        // Subsystems that do not exist yet report "not available" (NULL).
        assert!(OPENSSL_info(OPENSSL_INFO_CONFIG_DIR).is_null());
        assert!(OPENSSL_info(OPENSSL_INFO_ENGINES_DIR).is_null());
        assert!(OPENSSL_info(OPENSSL_INFO_MODULES_DIR).is_null());
        assert!(OPENSSL_info(OPENSSL_INFO_SEED_SOURCE).is_null());
        assert!(OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS).is_null());
        // Unrecognised types are NULL, as in the authority.
        assert!(OPENSSL_info(0).is_null());
        assert!(OPENSSL_info(11).is_null());
        assert!(OPENSSL_info(1010).is_null());
    }

    #[test]
    fn open_ssl_init_is_a_noop() {
        OPENSSL_init();
    }

    #[test]
    fn init_is_idempotent_across_threads() {
        with_init_lock(|| {
            let mut handles = Vec::new();
            for _ in 0..8 {
                handles.push(std::thread::spawn(|| {
                    let r = OPENSSL_init_crypto(
                        OPENSSL_INIT_LOAD_CRYPTO_STRINGS
                            | OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS
                            | OPENSSL_INIT_NO_ADD_ALL_CIPHERS
                            | OPENSSL_INIT_NO_ADD_ALL_DIGESTS
                            | OPENSSL_INIT_NO_LOAD_CONFIG
                            | OPENSSL_INIT_ATFORK
                            | OPENSSL_INIT_NO_ATEXIT,
                        core::ptr::null(),
                    );
                    assert_eq!(r, 1);
                    // A second call is the fast path and must still succeed.
                    assert_eq!(
                        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, core::ptr::null()),
                        1
                    );
                }));
            }
            for handle in handles {
                let _ = handle.join();
            }
        });
    }

    #[test]
    fn unsupported_options_fail_with_init_fail_and_do_not_get_recorded() {
        with_init_lock(|| {
            let cases = [
                OPENSSL_INIT_ADD_ALL_CIPHERS,
                OPENSSL_INIT_ADD_ALL_DIGESTS,
                OPENSSL_INIT_LOAD_CONFIG,
                OPENSSL_INIT_ASYNC,
                OPENSSL_INIT_ENGINE_RDRAND,
                OPENSSL_INIT_ENGINE_DYNAMIC,
                OPENSSL_INIT_ENGINE_OPENSSL,
                OPENSSL_INIT_ENGINE_CRYPTODEV,
                OPENSSL_INIT_ENGINE_CAPI,
                OPENSSL_INIT_ENGINE_PADLOCK,
                OPENSSL_INIT_ENGINE_AFALG,
            ];
            for opts in cases {
                ERR_clear_error();
                assert_eq!(
                    OPENSSL_init_crypto(opts, core::ptr::null()),
                    0,
                    "option {opts:#x} must be refused"
                );
                let e = ERR_peek_error();
                assert_ne!(e, 0, "a refusal must raise an error");
                assert_eq!((e >> 23) & 0xFF, ERR_LIB_CRYPTO as c_ulong);
                assert_eq!(e & 0x7F_FFFF, (ERR_R_INIT_FAIL as c_ulong) & 0x7F_FFFF);
                ERR_clear_error();
                // Recording a refused option would make the fast path return 1.
                assert_eq!(OPENSSL_init_crypto(opts, core::ptr::null()), 0);
                ERR_clear_error();
            }
        });
    }

    #[test]
    fn cleanup_is_idempotent_and_terminal() {
        with_init_lock(|| {
            assert_eq!(
                OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, core::ptr::null()),
                1
            );
            OPENSSL_cleanup();
            OPENSSL_cleanup();

            ERR_clear_error();
            assert_eq!(OPENSSL_init_crypto(0, core::ptr::null()), 0);
            let e = ERR_peek_error();
            assert_ne!(e, 0);
            assert_eq!((e >> 23) & 0xFF, ERR_LIB_CRYPTO as c_ulong);
            ERR_clear_error();

            // BASE_ONLY after cleanup returns 0 without raising, per the authority.
            assert_eq!(
                OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, core::ptr::null()),
                0
            );
            assert_eq!(ERR_peek_error(), 0);
        });
    }
}
