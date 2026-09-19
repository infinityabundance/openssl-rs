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
//! | `NO_LOAD_CONFIG` | **implemented**: runs the authority's alternative initialiser, `ossl_no_config_int`, which sets the process-wide `openssl_configured` flag and loads nothing. It is the *same* once `LOAD_CONFIG` claims, so `NO_LOAD_CONFIG | LOAD_CONFIG` sets the flag and then loads nothing — the authority's behaviour, not an accident of ordering |
//! | `LOAD_CONFIG` | **implemented**: runs `ossl_config_int`, which is `CONF_modules_load_file_ex` against the global default context with the caller's settings, or with `DEFAULT_CONF_MFLAGS` when there are none. A missing file is not an error — `DEFAULT_CONF_MFLAGS` carries `CONF_MFLAGS_IGNORE_MISSING_FILE` — so the no-configuration-file case is a *successful* no-op, which is what `ASN1_STRING_TABLE_get` observes first. 6.10c; supersedes D86, which recorded the load as absent |
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
//! Refusals happen *after* the `atexit` step and **before** the config step,
//! matching the authority's ordering: `init.c` tests `ADD_ALL_*`, `ASYNC` and the
//! `ENGINE_*` bits ahead of its `OPENSSL_INIT_LOAD_CONFIG` block, so a refused call
//! still has the side effects the authority would have had by that point and does
//! **not** have the ones it would not. That distinction was unobservable while the
//! config step loaded nothing; it stopped being unobservable in 6.10c, and the
//! position below is the correction.
//!
//! ## Idempotency, and being safe from a constructor or `atexit` frame
//!
//! State is process-global and guarded with atomics, so `OPENSSL_init_crypto`
//! may be called from any thread, including concurrently, and from a library
//! constructor or an `atexit` handler.
//!
//! Base initialisation **can** now fail, and it is the authority's failure shape:
//! the authority allocates two locks and a TLS key there and returns 0 on
//! exhaustion; this implementation's locks are `CRYPTO_atomic_*` calls, which
//! cannot fail, but the TLS key is a real `pthread_key_create`, which can. So
//! `ossl_init_base`'s run-once is modelled with a sticky result rather than as a
//! flag that is simply set: a base initialisation that failed leaves
//! `base_inited` clear and every later `OPENSSL_init_crypto` answers 0, exactly as
//! `RUN_ONCE(&base, ossl_init_base)` does once `base_ossl_ret_` holds 0.
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

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::Once;

use crate::ffi::guard_ffi;
use crate::runtime::conf::sap::{ossl_config_int, ossl_no_config_int};
use crate::runtime::confmod::ossl_config_modules_free;
use crate::runtime::thread::{
    CRYPTO_THREAD_cleanup_local, CRYPTO_THREAD_get_local, CRYPTO_THREAD_init_local,
    CRYPTO_THREAD_run_once, CRYPTO_THREAD_set_local,
};

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
pub(crate) const OPENSSL_INIT_ADD_ALL_CIPHERS: u64 = 0x0000_0004;
/// `OPENSSL_INIT_ADD_ALL_DIGESTS`
pub(crate) const OPENSSL_INIT_ADD_ALL_DIGESTS: u64 = 0x0000_0008;
/// `OPENSSL_INIT_NO_ADD_ALL_CIPHERS` — accepted no-op.
#[allow(dead_code)]
const OPENSSL_INIT_NO_ADD_ALL_CIPHERS: u64 = 0x0000_0010;
/// `OPENSSL_INIT_NO_ADD_ALL_DIGESTS` — accepted no-op.
#[allow(dead_code)]
const OPENSSL_INIT_NO_ADD_ALL_DIGESTS: u64 = 0x0000_0020;
/// `OPENSSL_INIT_LOAD_CONFIG`
pub(crate) const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;
/// `OPENSSL_INIT_NO_LOAD_CONFIG`
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
/// `OPENSSL_INIT_BASE_ONLY` — internal to the authority; not a public macro. `pub(crate)` because
/// `rand_lib.c`'s `ossl_rand_ctx_new` calls `OPENSSL_init_crypto(OPENSSL_INIT_BASE_ONLY, NULL)`,
/// and a second literal for the same flag is a second thing that can drift.
pub(crate) const OPENSSL_INIT_BASE_ONLY: u64 = 0x0004_0000;
/// The two legacy-adder bits, which are **accepted and do nothing yet**.
///
/// The authority's action for `OPENSSL_INIT_ADD_ALL_CIPHERS` is
/// `openssl_add_all_ciphers_int()` -- one hundred and sixty-odd
/// `EVP_add_cipher(EVP_aes_...)` calls over primitives this crate does not have yet, which is why
/// `crypto/evp/c_allc.c` and `c_alld.c` are Phase 13's. What the authority *returns* is 1 with
/// nothing raised, and `OpenSSL_add_all_algorithms_noconf()` is a macro over exactly these two
/// bits -- so a refusal here is a caller-visible failure where the authority has none.
///
/// They were on `INIT_UNSUPPORTED` until D161, which is the decision entry that retired them and
/// the one that records why: the table staying empty is a contents divergence recorded in
/// `docs/PHASE-7-SUBPHASES.md`, and the call *failing* was a behaviour divergence that no record
/// named. `RT-EVP-NAMES` measured the difference, because `EVP_CIPHER_do_all`'s first statement is
/// one of these calls and the probe reads the error queue after it.
///
/// The single expression below is the whole action, and it is written as an expression rather than
/// as a comment so that Phase 13 has one line to replace rather than a paragraph to find.
fn add_all_legacy_methods(opts: u64) {
    let _ = opts;
}

/// `OPENSSL_INIT_NO_ATEXIT` — fully honoured: suppresses the `atexit` handler.
const OPENSSL_INIT_NO_ATEXIT: u64 = 0x0008_0000;

/// Options whose subsystem is absent and whose authority action is observable.
///
/// Do not add to this list without reading the module note: refusal is the
/// honest choice *because* these are not no-ops in the authority.
///
/// `OPENSSL_INIT_LOAD_CONFIG` was on this list until Phase 5 needed it, and it left
/// the list for good in Phase 6.10c: the authority's config step is
/// `CONF_modules_load_file_ex(global_default, NULL, NULL, DEFAULT_CONF_MFLAGS)`,
/// and `DEFAULT_CONF_MFLAGS` includes `CONF_MFLAGS_IGNORE_MISSING_FILE`, so a
/// profile with no default config file gets a *successful* no-op — which is what
/// `ASN1_STRING_TABLE_get` observes first and what the RT-ASN1-STR court measured.
/// See `docs/DECISIONS.md` D86 for the phase in which the loader was absent, and
/// the entry that supersedes it for the phase in which it arrived.
const INIT_UNSUPPORTED: u64 = OPENSSL_INIT_ASYNC
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
/// Whether base initialisation has happened. Cleared again by cleanup, and only ever set on
/// **success**, so it is the authority's `base_inited` rather than a "we tried" flag.
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

/// `static CRYPTO_ONCE base = CRYPTO_ONCE_STATIC_INIT;`
///
/// `pthread_once` writes this field and nothing else does, so it is storage rather than state
/// this crate interprets; an `AtomicI32` is the crate's way of having addressable mutable
/// storage without a `static mut`.
static BASE_ONCE: AtomicI32 = AtomicI32::new(0);

/// The `RUN_ONCE` macro's own `base_ossl_ret_` — what `ossl_init_base` answered, kept for
/// every later `RUN_ONCE(&base, ossl_init_base)` to read.
///
/// This is **not** `BASE_INITED`, and the difference is not cosmetic: `OPENSSL_cleanup`
/// clears `base_inited` on the way out, while `base_ossl_ret_` stays 1 forever, because
/// a `CRYPTO_ONCE` cannot be un-run. A reader who took `base_init`'s answer from
/// `BASE_INITED` would make a second `OPENSSL_init_crypto` after a cleanup report a
/// *base-initialisation failure* rather than the terminal refusal the authority gives —
/// which is what the unit tests caught the moment this pair was split.
static BASE_ONCE_RET: AtomicI32 = AtomicI32::new(0);

/// `static CRYPTO_THREAD_LOCAL in_init_config_local;` — `crypto/init.c`.
///
/// The **re-entrancy guard** around configuration loading. `OPENSSL_init_crypto`'s `LOAD_CONFIG`
/// step sets this thread's slot to a non-NULL sentinel before it loads a configuration, and
/// because a module's initialiser may create an object — which calls `OBJ_` functions, which
/// call `OPENSSL_init_crypto` — the nested call sees a non-NULL slot and skips the config step
/// rather than parsing the same file again.
///
/// The authority **never clears it**. That is not an oversight to correct: the slot stays set
/// for the life of the thread, and the observable consequence is that after a failed
/// configuration load, a second `OPENSSL_init_crypto(LOAD_CONFIG)` on the *same* thread takes
/// the skip path and answers 1, while the same call on a *different* thread re-enters the once
/// and answers the once's recorded 0. The crate reproduces both halves, which is why this slot
/// is set and not restored. `OPENSSL_cleanup` deletes the key, which is the only release.
static IN_INIT_CONFIG_LOCAL: AtomicU32 = AtomicU32::new(0);

/// `(void *)-1` — the sentinel the authority stores in the slot above.
///
/// Any non-NULL value would serve the test the authority makes, and the exact value is
/// unobservable through the API, so the authority's own is used rather than a fresh `1`.
const CONFIG_LOADING: *mut c_void = usize::MAX as *mut c_void;

/// `static CRYPTO_ONCE config = CRYPTO_ONCE_STATIC_INIT;` — `crypto/init.c`.
///
/// One `CRYPTO_ONCE` shared by three bodies: `ossl_init_config`, `ossl_init_config_settings`
/// and `ossl_init_no_config`. Which one runs is decided by *which entry point reaches it first*
/// — that is what the authority's `RUN_ONCE`/`RUN_ONCE_ALT` pair means — and the value it
/// recorded is what every later reader gets.
static CONFIG_ONCE: AtomicI32 = AtomicI32::new(0);

/// The `RUN_ONCE` macro's `config_ossl_ret_`. Written by whichever body ran, read by every
/// later `RUN_ONCE`/`RUN_ONCE_ALT` on [`CONFIG_ONCE`].
static CONFIG_ONCE_RET: AtomicI32 = AtomicI32::new(0);

/// `static const OPENSSL_INIT_SETTINGS *conf_settings = NULL;` — `crypto/init.c`.
///
/// The authority publishes the caller's settings pointer here under `init_lock` for the duration
/// of the `RUN_ONCE_ALT`, so that the alternative body can read it. An `AtomicPtr` store/load
/// provides exactly what the lock provides — the alternative body sees the pointer the caller
/// published and no other — so the lock itself is not modelled. It is stored and cleared around
/// the once, as the authority stores and clears it.
static CONF_SETTINGS: AtomicPtr<OpenSslInitSettings> = AtomicPtr::new(core::ptr::null_mut());

/// `DEFINE_RUN_ONCE_STATIC(ossl_init_config)` — the `settings == NULL` body.
///
/// A **safe** `extern "C" fn` of no arguments, because that is the type
/// [`CRYPTO_THREAD_run_once`] takes.
extern "C" fn ossl_init_config() {
    // SAFETY: NULL is the argument that asks for the default file and the default flag word,
    // and does not dereference anything.
    let ret = unsafe { ossl_config_int(core::ptr::null()) };
    CONFIG_ONCE_RET.store(ret, Ordering::Release);
}

/// `DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_config_settings, ossl_init_config)`.
///
/// Read `CONF_SETTINGS` rather than taking a parameter, because a once body takes none. The
/// pointer is published by the caller that is inside the once, so this read sees it.
extern "C" fn ossl_init_config_settings() {
    let settings = CONF_SETTINGS.load(Ordering::Acquire);
    // SAFETY: `settings` was published by the caller inside this once and is the caller's live
    // object; `ossl_config_int`'s contract is exactly that.
    let ret = unsafe { ossl_config_int(settings) };
    CONFIG_ONCE_RET.store(ret, Ordering::Release);
}

/// `DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_config, ossl_init_config)`.
///
/// The `OSSL_TRACE(INIT, "ossl_no_config_int()\n")` above its body is compiled out in this
/// profile, which is `no-trace`.
extern "C" fn ossl_init_no_config() {
    ossl_no_config_int();
    CONFIG_ONCE_RET.store(1, Ordering::Release);
}

/// `RUN_ONCE`/`RUN_ONCE_ALT` over [`CONFIG_ONCE`] with `body` as the alternative initialiser.
///
/// Both macros, and the single shape they share: run the body if the once has not run, then
/// answer the recorded result. `RUN_ONCE_ALT(once, initalt, init)` expands to
/// `(CRYPTO_THREAD_run_once(once, initalt##_ossl_) ? init##_ossl_ret_ : 0)` and
/// `RUN_ONCE(once, init)` to `(CRYPTO_THREAD_run_once(once, init##_ossl_) ? init##_ossl_ret_ : 0)`
/// — and because `DEFINE_RUN_ONCE_STATIC_ALT` writes the **same** `init##_ossl_ret_` as its
/// primary, both are this function with a different body.
fn run_config_once(body: extern "C" fn()) -> c_int {
    // SAFETY: the once is this module's own static, initially zero, and the body is a safe
    // `extern "C" fn` of no arguments.
    let ran = unsafe { CRYPTO_THREAD_run_once(CONFIG_ONCE.as_ptr(), Some(body)) };
    if ran == 0 {
        // `pthread_once` failed, which is what makes the authority's `RUN_ONCE` answer 0 rather
        // than the recorded value.
        return 0;
    }
    CONFIG_ONCE_RET.load(Ordering::Acquire)
}

/// `int loading = CRYPTO_THREAD_get_local(&in_init_config_local) != NULL;`
fn config_loading() -> bool {
    // SAFETY: the key was created by `base_init` and this function is only reachable through
    // `OPENSSL_init_crypto`, which returns 0 when `base_init` failed. It has not been deleted,
    // because `OPENSSL_cleanup` is the only deleter and every caller past it is refused.
    let value = unsafe { CRYPTO_THREAD_get_local(IN_INIT_CONFIG_LOCAL.as_ptr()) };
    !value.is_null()
}

/// `CRYPTO_THREAD_set_local(&in_init_config_local, (void *)-1)`.
///
/// Answers false only when the platform refuses the store, which the authority treats as a
/// failed initialisation rather than a warning.
fn set_config_loading() -> bool {
    // SAFETY: as `config_loading`, and the value is a sentinel that is never dereferenced and
    // never freed — the authority's own `(void *)-1`.
    unsafe { CRYPTO_THREAD_set_local(IN_INIT_CONFIG_LOCAL.as_ptr(), CONFIG_LOADING) != 0 }
}

/// `DEFINE_RUN_ONCE_STATIC(ossl_init_base)` — the authority's base step, minus the two locks
/// this crate's equivalents do not need.
///
/// The authority's body allocates `optsdone_lock` and `init_lock`, calls `OPENSSL_cpuid_setup()`,
/// calls `ossl_init_thread()`, creates the configuration re-entrancy key, and sets `base_inited`.
/// This crate's `OPTSDONE` and `CONF_SETTINGS` are atomics, so neither lock has anything to
/// protect; `OPENSSL_cpuid_setup` and the CPU dispatch it feeds are Phase 19 and are a recorded
/// open obligation. What is left is the two calls that can fail, and both are made.
///
/// `ossl_init_thread()` is reached through [`CRYPTO_THREAD_init_local`], which calls it first
/// for exactly the reason the authority's body calls it first: a key created before the thread
/// event machinery exists would be usable by a caller who then registered a handler against a
/// thread-local list that had nowhere to go. The relative order is therefore the authority's,
/// and it is not an accident of which function happens to contain the call.
fn base_init() -> bool {
    // SAFETY: the once is this module's own static, initially zero, and the body is a safe
    // `extern "C" fn` of no arguments.
    let ran = unsafe { CRYPTO_THREAD_run_once(BASE_ONCE.as_ptr(), Some(init_base_body)) };
    if ran == 0 {
        // `pthread_once` failed, which is what makes `RUN_ONCE` answer 0 rather than the
        // recorded value.
        return false;
    }
    BASE_ONCE_RET.load(Ordering::Acquire) != 0
}

/// The `ossl_init_base` body, in the shape `CRYPTO_THREAD_run_once` takes.
extern "C" fn init_base_body() {
    // SAFETY: the key is this module's own static and the destructor is NULL, which is the
    // authority's argument. A second call would leak a key, which is why this body is inside a
    // run-once.
    if unsafe { CRYPTO_THREAD_init_local(IN_INIT_CONFIG_LOCAL.as_ptr(), None) } == 0 {
        BASE_ONCE_RET.store(0, Ordering::Release);
        return;
    }
    BASE_INITED.store(true, Ordering::Release);
    BASE_ONCE_RET.store(1, Ordering::Release);
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
pub extern "C" fn OPENSSL_init_crypto(opts: u64, settings: *const OpenSslInitSettings) -> c_int {
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

        // The two legacy-adder bits, at the authority's own position in the sequence:
        // after the `atexit` registration and the two string loads, and **before** the
        // config step. The action is `add_all_legacy_methods`'s, and the answer is
        // ignored exactly as the authority ignores the adders' -- neither can fail in
        // this profile.
        add_all_legacy_methods(
            opts & (OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS),
        );

        // The refusal, at the authority's own position in the sequence: after the
        // `atexit` registration and the two string loads, and **before** the config
        // step. A caller who asks for `ADD_ALL_CIPHERS | LOAD_CONFIG` is therefore
        // refused without a configuration having been read, which is what the
        // authority does — see the module note.
        if opts & INIT_UNSUPPORTED != 0 {
            raise_init_fail();
            return 0;
        }

        // The config step, in the authority's own two-part shape.
        //
        // The two tests are **not** symmetric, and the asymmetry is observable. The
        // first is `RUN_ONCE_ALT(&config, ossl_init_no_config, ossl_init_config)`, so
        // `NO_LOAD_CONFIG` claims the shared `config` once and records 1; the second is
        // a plain `if (opts & OPENSSL_INIT_LOAD_CONFIG)` block that then reaches
        // `RUN_ONCE(&config, ossl_init_config)` — which, the once already having run,
        // answers the recorded 1 without calling the loader. So
        // `NO_LOAD_CONFIG | LOAD_CONFIG` marks the process configured and loads
        // nothing, which is why the two bits are two `if`s here and not an `else if`.
        //
        // The re-entrancy guard is the authority's and is load-bearing now that a
        // configuration really is parsed: a module's initialiser creates objects, and
        // `OBJ_create` calls `OPENSSL_init_crypto`, so without the guard a load would
        // call itself. The slot is **set and never cleared**, exactly as upstream —
        // see [`IN_INIT_CONFIG_LOCAL`] for why that is reproduced rather than tidied.
        if opts & OPENSSL_INIT_NO_LOAD_CONFIG != 0 && run_config_once(ossl_init_no_config) == 0 {
            return 0;
        }
        if opts & OPENSSL_INIT_LOAD_CONFIG != 0 && !config_loading() {
            if !set_config_loading() {
                return 0;
            }
            let ret = if settings.is_null() {
                run_config_once(ossl_init_config)
            } else {
                // The authority publishes the pointer for the duration of the once,
                // under `init_lock`, and clears it after.
                CONF_SETTINGS.store(settings.cast_mut(), Ordering::Release);
                let r = run_config_once(ossl_init_config_settings);
                CONF_SETTINGS.store(core::ptr::null_mut(), Ordering::Release);
                r
            };
            // `if (ret <= 0) return 0;` — a failed configuration load fails the
            // initialisation, and because the step is above the `OPTSDONE` union
            // the failure is not recorded as done. It is *sticky* all the same: the
            // once has run, so a later call reads the recorded 0 rather than
            // retrying.
            if ret <= 0 {
                return 0;
            }
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

/// `typedef struct ossl_init_stop_st OPENSSL_INIT_STOP` — `crypto/init.c`.
///
/// `next` is a raw pointer, so the node is allocated with `CRYPTO_malloc` rather than `Box`:
/// an application that installs its own allocator through `CRYPTO_set_mem_functions` must see
/// these exactly as it sees the authority's, and Phase 3's memory-debug court reads the
/// coordinates back.
#[repr(C)]
struct OpenSslInitStop {
    /// The handler `OPENSSL_atexit` was given.
    handler: extern "C" fn(),
    /// The next node, or NULL.
    next: *mut OpenSslInitStop,
}

/// `static OPENSSL_INIT_STOP *stop_handlers = NULL`.
///
/// An atomic pointer rather than a `static mut`, because `OPENSSL_atexit` has no lock in the
/// authority either — the list is a lock-free push, and the drain in `OPENSSL_cleanup` is
/// single-threaded by the same assumption the authority states for that whole function.
static STOP_HANDLERS: AtomicPtr<OpenSslInitStop> = AtomicPtr::new(core::ptr::null_mut());

/// The authority's translation unit and line, so a failing allocation records what a
/// consumer would see from the authority.
const FILE_INIT: *const c_char = c"../../src/openssl-3.6.4/crypto/init.c".as_ptr();
/// `OPENSSL_atexit`'s `OPENSSL_malloc(sizeof(*newhand))`.
const L_ATEXIT_NEWHAND: c_int = 750;
/// `OPENSSL_cleanup`'s `OPENSSL_free(lasthandler)`.
const L_CLEANUP_FREE_HANDLER: c_int = 403;

/// `int OPENSSL_atexit(void (*handler)(void))`
///
/// Registers `handler` to run when the library is cleaned up, and answers 0 only when the
/// node cannot be allocated.
///
/// **The DSO-pinning block is not compiled in this profile, and that is a build fact rather
/// than a simplification.** The authority guards it with
/// `#if !defined(OPENSSL_USE_NODELETE) && !defined(OPENSSL_NO_PINSHARED)`, and this profile's
/// `configdata.pm` records `lib_cppflags => "-DOPENSSL_USE_NODELETE -DL_ENDIAN"`. So
/// `OPENSSL_USE_NODELETE` **is** defined, the whole block — the Win32
/// `GetModuleHandleEx` route and the `DSO_dsobyaddr(handler, DSO_FLAG_NO_UNLOAD_ON_FREE)`
/// route with it — is skipped, and what remains is the three-line push below. A reader
/// comparing this against `init.c` will find the block and should find this paragraph with
/// it: the `DSO_dsobyaddr` call is *not* missing, it is absent from the authority's compiled
/// form too.
///
/// There is no `OPENSSL_INIT_NO_ATEXIT` check here, and there should not be: that flag
/// suppresses the **`atexit(OPENSSL_cleanup)` registration**, which is a different mechanism
/// (`register_atexit` above), not the registration of a caller's own handler.
///
/// # Safety
/// `handler` must be a valid `extern "C"` function with no parameters.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_atexit(handler: Option<extern "C" fn()>) -> c_int {
    guard_ffi(0, || {
        // The authority dereferences `handlersym.func = handler` without a NULL test when the
        // pinning block is compiled in; with it out, a NULL handler would be stored and then
        // *called* by `OPENSSL_cleanup`. Refusing it here is a divergence, and it is the
        // narrow, fail-closed kind the project takes deliberately: calling NULL in the
        // library's own teardown is a fault, and a NULL handler is meaningless either way.
        let Some(handler) = handler else {
            return 0;
        };
        // `CRYPTO_malloc` is a SAFE function in this crate (D113), so this is unguarded.
        let newhand = crate::runtime::mem::CRYPTO_malloc(
            core::mem::size_of::<OpenSslInitStop>(),
            FILE_INIT,
            L_ATEXIT_NEWHAND,
        )
        .cast::<OpenSslInitStop>();
        if newhand.is_null() {
            return 0;
        }
        // SAFETY: `newhand` is this function's own allocation, so both writes are to owned
        // storage, and the push is a single release store.
        unsafe {
            (*newhand).handler = handler;
            (*newhand).next = STOP_HANDLERS.load(Ordering::Acquire);
            STOP_HANDLERS.store(newhand, Ordering::Release);
        }
        1
    })
}

/// The drain, called from `OPENSSL_cleanup` after `OPENSSL_thread_stop`.
fn run_atexit_handlers() {
    loop {
        let node = STOP_HANDLERS.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if node.is_null() {
            return;
        }
        let mut curr = node;
        while !curr.is_null() {
            // SAFETY: `curr` is a node this module allocated, still owned until freed below.
            let (handler, next) = unsafe { ((*curr).handler, (*curr).next) };
            handler();
            // SAFETY: `curr` is live and owned here, and `next` was read before the free.
            unsafe {
                crate::runtime::mem::CRYPTO_free(
                    curr.cast::<core::ffi::c_void>(),
                    FILE_INIT,
                    L_CLEANUP_FREE_HANDLER,
                );
            }
            curr = next;
        }
    }
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
        // The authority's order inside `OPENSSL_cleanup`, for the three it has: stop this
        // thread's event handlers first (`OPENSSL_thread_stop`, which the authority calls
        // directly because the thread library does not always run the destructor for the last
        // thread), then the caller's `OPENSSL_atexit` handlers, then the thread-event
        // machinery itself.
        crate::runtime::thread_events::OPENSSL_thread_stop();
        run_atexit_handlers();
        // The authority frees its two locks here and then releases the configuration
        // re-entrancy key. The locks have no counterpart, but the key does, and it must go
        // before `ossl_cleanup_thread` for the authority's reason: deleting a key does not run
        // destructors in other threads, so the thread-event teardown is what actually drains
        // them and it comes later.
        // SAFETY: the key was created by `base_init`, which is what got us here — `BASE_INITED`
        // is set only after it succeeded — and this is its only deleter.
        unsafe { CRYPTO_THREAD_cleanup_local(IN_INIT_CONFIG_LOCAL.as_ptr()) };
        // `ossl_config_modules_free()`. The authority's comment places it here for a
        // dependency reason and not for tidiness: *"ossl_config_modules_free() can end up in
        // ENGINE code so must be called before engine_cleanup_int()"*. It is
        // `CONF_modules_unload(1)` followed by the registry's own teardown, so an unload that
        // a module's `finish` callback triggers still finds a live registry, and a second
        // unload after it returns early rather than walking a freed list.
        ossl_config_modules_free();
        crate::runtime::thread_events::ossl_cleanup_thread();
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
        // `BASE_INITED` is restored to what the **once** recorded, not to `false`:
        // `ossl_init_base` runs under a `CRYPTO_ONCE`, and a `CRYPTO_ONCE` cannot be
        // un-run, so a test that cleared this flag would be asserting a state the
        // authority's own structures cannot reach. `BASE_ONCE_RET` is the authority's
        // `base_ossl_ret_` and is what `base_init` answers from — which is what makes
        // this the right value to restore rather than an arbitrary `true`.
        BASE_INITED.store(
            BASE_ONCE_RET.load(Ordering::Acquire) != 0,
            Ordering::Release,
        );
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

    /// The refused options are the ones whose subsystem is genuinely absent. **The two
    /// legacy-adder bits are not among them**, and the test says so in its own name: they were
    /// until D161, which is the entry that retired them because the authority answers 1 and
    /// `OpenSSL_add_all_algorithms_noconf()` is a macro over exactly those two bits.
    #[test]
    fn the_legacy_adder_bits_are_accepted_and_raise_nothing() {
        with_init_lock(|| {
            for opts in [OPENSSL_INIT_ADD_ALL_CIPHERS, OPENSSL_INIT_ADD_ALL_DIGESTS] {
                ERR_clear_error();
                assert_eq!(
                    OPENSSL_init_crypto(opts, core::ptr::null()),
                    1,
                    "option {opts:#x} must be accepted"
                );
                assert_eq!(ERR_peek_error(), 0, "an accepted option raises nothing");
                /* And it is recorded, so the second call takes the fast path and still answers 1. */
                assert_eq!(OPENSSL_init_crypto(opts, core::ptr::null()), 1);
                assert_eq!(ERR_peek_error(), 0);
            }
        });
    }

    #[test]
    fn unsupported_options_fail_with_init_fail_and_do_not_get_recorded() {
        with_init_lock(|| {
            let cases = [
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
