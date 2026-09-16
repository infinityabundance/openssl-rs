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
//! | `NO_LOAD_CRYPTO_STRINGS` | the authority's alternative initialiser is empty, and it wins over `LOAD_CRYPTO_STRINGS` when both bits are set, exactly as `RUN_ONCE_ALT` does |
//! | `LOAD_CRYPTO_STRINGS` | **implemented**: loads the generic ERR tables and every library in `ossl_err_load_crypto_strings`, which is what makes a reason string visible at all (`docs/DECISIONS.md` D19) |
//! | `NO_LOAD_SSL_STRINGS` | as `NO_LOAD_CRYPTO_STRINGS` |
//! | `LOAD_SSL_STRINGS` | **implemented**: loads library 20's reason table, which `err_all.c` deliberately excludes from the crypto set |
//! | `NO_ADD_ALL_CIPHERS`, `NO_ADD_ALL_DIGESTS` | the authority's alternative initialisers are empty |
//! | `NO_LOAD_CONFIG` | requests exactly this build's behaviour: no config is loaded |
//! | `LOAD_CONFIG` | **accepted**: the config step succeeds having loaded nothing, which is the authority's own answer when no config file exists. Applying a config file that *does* exist is Phase 6 (D86) |
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
//! Cleanup also calls `err_cleanup()`, which releases the error-string registry.
//! Because `ossl_err_get_state_int` begins with
//! `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY)`, a stopped library hands out no
//! `ERR_STATE` at all: every `ERR_*` call becomes a no-op and **no** error is
//! recorded, including the one a refused `OPENSSL_init_crypto` would otherwise
//! raise. That is measured by the RT-ERR probe's `stopped` section. The rest of
//! the authority's teardown (compression, async, RAND, config modules, ENGINE,
//! STORE, the default `OSSL_LIB_CTX`, BIO, EVP, OBJ, secure memory, CMP,
//! tracing) is empty here; each entry is unlocked by the phase named in
//! `docs/RELEASE_GATES.md` §1, and the Phase 3 ledger records what is deferred.
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
/// `OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS` — the authority's alternative
/// initialiser is empty, and this registry starts empty, so nothing is needed.
const OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0001;
/// `OPENSSL_INIT_LOAD_CRYPTO_STRINGS` — loads the generic tables and the crypto
/// set of library reason tables.
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
pub(crate) const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
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
// The libssl string flags come from `ssl.h`: `NO_LOAD_SSL_STRINGS` 0x00100000
// and `LOAD_SSL_STRINGS` 0x00200000. The SSL reason table lives in libcrypto
// (`crypto/ssl_err.c`) but is loaded by its own flag, which is why they are not
// part of the crypto set.
/// `OPENSSL_INIT_NO_LOAD_SSL_STRINGS` — empty alternative initialiser.
const OPENSSL_INIT_NO_LOAD_SSL_STRINGS: u64 = 0x0010_0000;
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` — loads library 20's reason table.
const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x0020_0000;
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
///
/// `OPENSSL_INIT_LOAD_CONFIG` was on this list until Phase 5 needed it: the
/// authority's config step is
/// `CONF_modules_load_file_ex(global_default, NULL, NULL, DEFAULT_CONF_MFLAGS)`,
/// and `DEFAULT_CONF_MFLAGS` includes `CONF_MFLAGS_IGNORE_MISSING_FILE`, so a
/// profile with no default config file gets a *successful* no-op — which is what
/// `ASN1_STRING_TABLE_get` observes first and what the RT-ASN1-STR court measured.
/// See `docs/DECISIONS.md` D86.
const INIT_UNSUPPORTED: u64 = OPENSSL_INIT_ADD_ALL_CIPHERS
    | OPENSSL_INIT_ADD_ALL_DIGESTS
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
///
/// `providers`' `core_get_params` answers this for `OSSL_PROV_PARAM_CORE_VERSION`, which is
/// why it is `pub(crate)` rather than private to this module.
pub(crate) const VERSION_STRING: &CStr = c"3.6.4";
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
/// Only meaningful together with `OPENSSL_INIT_LOAD_CONFIG`, whose settings form
/// is not implemented: the non-null form is accepted and unread, and the null form
/// — the one `ASN1_STRING_TABLE_get` uses — loads nothing and succeeds. See
/// `docs/DECISIONS.md` D86.
///
/// **There is one definition of this type, and it lives with the code that fills
/// it.** It used to be a zero-sized opaque placeholder here, because this module
/// never reads the settings: `OPENSSL_INIT_LOAD_CONFIG` is *accepted* having loaded
/// nothing, which is the authority's answer when no configuration file exists, so
/// the pointer its callers pass was never dereferenced. That was fine while nothing
/// produced a real one, and it stopped being fine the moment `OPENSSL_config` did:
/// two `#[repr(C)]` types with the same name and different definitions is a
/// placeholder that will silently accept a wrong pointer when Phase 6.9 teaches
/// this function to read the settings.
///
/// So the definition is re-exported from `crypto/conf/conf_lib.c`'s Rust home,
/// which is where `OPENSSL_INIT_new` and the setters already are. A module cycle is
/// the price, and it is not a real one: Rust modules are not compilation units, and
/// the authority has the same shape — `crypto.h` declares
/// `OPENSSL_init_crypto` and `types.h` declares the settings struct, neither
/// owning the other.
pub use crate::runtime::conf::init_settings::OpenSslInitSettings;

/// Raises `ERR_LIB_CRYPTO`/`ERR_R_INIT_FAIL`, the authority's error for a failed
/// initialisation, **at the authority's own raise site**.
///
/// `crypto/init.c:504` inside `OPENSSL_init_crypto` is where the authority raises
/// this, and `ERR_get_error_all` hands the translation unit, line and function
/// straight to the caller, so the coordinates come from the generated table
/// rather than being left blank.
fn raise_init_fail() {
    // The generated table must agree with the reason this module documents; a
    // drift in the generator would otherwise silently change the raised code.
    debug_assert_eq!(crate::runtime::err::err_sites::INIT_504.lib, ERR_LIB_CRYPTO);
    debug_assert_eq!(
        crate::runtime::err::err_sites::INIT_504.reason,
        ERR_R_INIT_FAIL
    );
    // SAFETY: the site is a compile-time constant whose pointers are static.
    unsafe { crate::runtime::err::raise_site(&crate::runtime::err::err_sites::INIT_504) };
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

        // Error strings, in the authority's order: the crypto tables (which
        // `err_all.c` defines as the generic tables plus the crypto set, and
        // deliberately excludes SSL) and then the SSL ones.
        //
        // Each pair is a `RUN_ONCE_ALT` partnership in the authority, and the
        // *first* of the pair to be seen wins. That matters when a caller sets
        // both bits: `NO_LOAD | LOAD` marks the once as done without loading, so
        // the `LOAD` branch is skipped. The `NO_LOAD` body is otherwise empty,
        // and the registry already starts empty, so nothing is undone.
        if opts & OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS != 0 {
            // The alternative initialiser ran; it does nothing.
        } else if opts & OPENSSL_INIT_LOAD_CRYPTO_STRINGS != 0 {
            crate::runtime::err::load_crypto_strings();
        }
        if opts & OPENSSL_INIT_NO_LOAD_SSL_STRINGS != 0 {
            // The alternative initialiser ran; it does nothing.
        } else if opts & OPENSSL_INIT_LOAD_SSL_STRINGS != 0 {
            crate::runtime::err::load_ssl_strings();
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

        // The config step. The authority's structure is two independent tests:
        // `NO_LOAD_CONFIG` runs the alternative initialiser (which only marks the
        // configuration as done) and `LOAD_CONFIG` runs the real one, which is
        // `ossl_config_int` -> `CONF_modules_load_file_ex(global_default, NULL,
        // NULL, DEFAULT_CONF_MFLAGS)`. That call needs `OSSL_LIB_CTX` and the
        // module registry, both Phase 6.
        //
        // What this crate can honour is the *outcome* on a profile with no
        // configuration source: `DEFAULT_CONF_MFLAGS` carries
        // `CONF_MFLAGS_IGNORE_MISSING_FILE`, so a missing file is not an error and
        // the step succeeds having loaded nothing. It succeeds that way here for
        // every profile, which is the divergence recorded as D86: a config file
        // that *does* exist is not applied until Phase 6 lands the loader.
        //
        // The authority's re-entrancy guard (`in_init_config_local`) protects
        // against `OBJ_` calls made from inside config parsing; nothing here
        // parses config, so there is nothing to re-enter.
        if opts & OPENSSL_INIT_NO_LOAD_CONFIG != 0 {
            // The alternative initialiser ran; it does nothing.
        } else if opts & OPENSSL_INIT_LOAD_CONFIG != 0 {
            // Nothing to load yet; see above.
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
/// The authority's teardown sequence ends with `err_cleanup()` (via
/// `crypto/init.c`), which frees the error-string hash. That is observable: after
/// cleanup, `ERR_*` operations are refused because
/// `ossl_err_get_state_int`'s `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY)`
/// returns 0, and string lookups see an empty registry. Both are reproduced
/// here, and the RT-ERR probe measures them.
///
/// The rest of the authority's teardown (compression, async, RAND, config
/// modules, ENGINE, STORE, the default `OSSL_LIB_CTX`, BIO, EVP, OBJ, secure
/// memory, CMP, tracing) is empty here; each entry is unlocked by the phase named
/// in `docs/RELEASE_GATES.md` §1. This is a recorded open obligation rather than
/// a pretence.
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
        // `err_cleanup()`: the string registry is released.
        crate::runtime::err::unload_strings();
    })
}

/// Whether `OPENSSL_cleanup` has run. Exposed so the `ERR` subsystem can model
/// `ossl_err_get_state_int`'s refusal to hand out a state once the library is
/// stopped.
pub(crate) fn stopped() -> bool {
    STOPPED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Fatal reporting, and the fork hooks
// ---------------------------------------------------------------------------

/// `void OPENSSL_die(const char *message, const char *file, int line)`
///
/// The authority's fatal-error path: `OPENSSL_showfatal("%s:%d: OpenSSL internal
/// error: %s\n", file, line, message)` and then, on every non-Windows platform,
/// `abort()`.
///
/// Three details are contract rather than cosmetics, and each is reproduced:
///
/// * the text goes to **fd 2 directly**, so it is not interleaved with anything
///   `stdio` has buffered — the authority's `vfprintf(stderr, ...)` is unbuffered
///   for the same reason;
/// * a NULL `file` renders as `(null)`, which is what glibc's `%s` does and what
///   the authority therefore prints;
/// * `abort()` follows unconditionally. A caller that reached here has decided the
///   process cannot continue, so there is no fall-through to a return value.
///
/// A court can observe this exactly: run it in a child, and compare the exit
/// status (SIGABRT) and the bytes on stderr. Nothing else in this module may be
/// relied on afterwards, which is what `abort` means.
///
/// # Safety
/// `message` and `file` must each be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_die(message: *const c_char, file: *const c_char, line: c_int) {
    let mut out: Vec<u8> = Vec::with_capacity(128);
    // SAFETY: `file` and `message` are each NULL or NUL-terminated per the
    // caller's contract, which `c_str_bytes` documents.
    let (file_bytes, message_bytes) = unsafe { (c_str_bytes(file), c_str_bytes(message)) };
    out.extend_from_slice(file_bytes.unwrap_or(b"(null)"));
    out.push(b':');
    out.extend_from_slice(line.to_string().as_bytes());
    out.extend_from_slice(b": OpenSSL internal error: ");
    out.extend_from_slice(message_bytes.unwrap_or(b"(null)"));
    out.push(b'\n');
    write_all_fd2(&out);
    // SAFETY: `abort` has no preconditions and does not return, so nothing after
    // this line runs. The declared return type is `void` because that is the
    // authority's, and `ABI-PROTOTYPE` compares it; `!` here would be a different
    // declaration of the same call.
    unsafe { abort() }
}

/// The bytes of a NUL-terminated C string, or `None` for NULL.
///
/// # Safety
/// `p` must be NULL or a NUL-terminated C string.
unsafe fn c_str_bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` is NUL-terminated per the caller's contract.
    Some(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes())
}

/// Write to fd 2, ignoring the result exactly as `vfprintf(stderr, ...)`'s caller
/// does: there is nothing useful to do if stderr is closed, and the authority
/// continues to `abort()` regardless.
fn write_all_fd2(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: `bytes` is a live slice and the offsets stay inside it.
        let n = unsafe {
            crate::runtime::bio::sys::write(
                2,
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return;
        }
        written += n as usize;
    }
}

/// `void OPENSSL_fork_prepare(void)`
///
/// An empty function on this profile, and that is the authority's own body:
/// `crypto/threads_lib.c` compiles the three hooks only for `OPENSSL_SYS_UNIX`
/// and `!OPENSSL_NO_DEPRECATED_3_0`, and gives all three an empty body because
/// glibc's `pthread_atfork` machinery already covers what they used to do. The
/// profile defines neither exclusion, which was measured rather than assumed.
///
/// They remain real exports because a precompiled binary links against them, and
/// the Phase 2 loader court resolves them at their declared ELF version.
#[no_mangle]
pub extern "C" fn OPENSSL_fork_prepare() {}

/// `void OPENSSL_fork_parent(void)` — empty on this profile; see
/// [`OPENSSL_fork_prepare`].
#[no_mangle]
pub extern "C" fn OPENSSL_fork_parent() {}

/// `void OPENSSL_fork_child(void)` — empty on this profile; see
/// [`OPENSSL_fork_prepare`].
#[no_mangle]
pub extern "C" fn OPENSSL_fork_child() {}

unsafe extern "C" {
    /// `void abort(void)`, from `<stdlib.h>`.
    fn abort() -> !;
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
            // The refusal raises ... nothing. `err_cleanup()` has released the
            // string registry and `ossl_err_get_state_int` now returns NULL,
            // because its `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY)` fails
            // once `stopped` is set. Every `ERR_*` call is therefore a no-op and
            // the queue stays empty. Measured by the RT-ERR probe's `stopped`
            // section, which asserts code 0 on both sides.
            assert_eq!(ERR_peek_error(), 0);

            // BASE_ONLY after cleanup returns 0 without raising, per the authority.
            assert_eq!(
                OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, core::ptr::null()),
                0
            );
            assert_eq!(ERR_peek_error(), 0);
        });
    }
}
