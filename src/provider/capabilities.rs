//! Phase 8 — the default provider's capability up-call (`providers/common/capabilities.c`).
//!
//! `OSSL_PROVIDER_get_capabilities(prov, "TLS-GROUP", cb, arg)` reaches the provider's
//! `OSSL_FUNC_PROVIDER_GET_CAPABILITIES` entry, which `providers/defltprov.c:747-748` binds to
//! `ossl_prov_get_capabilities`. That one function is the whole of
//! `providers/common/capabilities.c` (`forensics/authorities/src/openssl-3.6.4/providers/common/capabilities.c`,
//! 344 lines), and this module is its transcription. The unit defines exactly one external name —
//! `ossl_prov_get_capabilities` — compiled into the default provider
//! (`forensics/atlas/internal-symbols.json` records its translation unit as
//! `providers/common/libdefault-lib-capabilities.c` and its declaration in
//! `providers/common/include/prov/providercommon.h`). The two walkers and the four tables below are
//! `static` in the authority and stay module-private here; none of them is exported.
//!
//! The court that drives the up-call is `courts/phase8/rt_provider_cap_probe.c` (`RT-PROVIDER-CAP`),
//! and its five capability arms — load, `TLS-GROUP`, `TLS-SIGALG`, the callback refusal, and an
//! unclaimed capability — are the observables this file is measured against. Row 8.2 of
//! `docs/PHASE-8-SUBPHASES.md` recorded from the bootstrap until **D411** that this up-call was
//! absent; D411 is the pass that landed it, so that row now reads as landed rather than as a gap.
//!
//! ## The profile compiles every conditional block, so the tables are their full sizes
//!
//! Every `#if` in the authority guards on a macro the admitted profile leaves **undefined**.
//! `forensics/authorities/build/openssl-3.6.4-production/include/openssl/configuration.h` (the
//! measured build) defines none of `OPENSSL_NO_EC`, `OPENSSL_NO_DH`, `OPENSSL_NO_ML_KEM`,
//! `OPENSSL_NO_ML_DSA`, `OPENSSL_NO_ECX`, `OPENSSL_NO_EC2M` or `OPENSSL_NO_TLS_DEPRECATED_EC`, and
//! `FIPS_MODULE` is not defined for the default provider. So, independently recounted from the
//! authority:
//!
//! * `group_list[]` (`capabilities.c:49-94`) is **44** rows, indices `0..=43`;
//! * `param_group_list[][11]` (`capabilities.c:153-257`) is **59** rows — every one of the
//!   `OPENSSL_NO_EC`/`OPENSSL_NO_DH`/`OPENSSL_NO_ML_KEM`/`OPENSSL_NO_ECX`/`OPENSSL_NO_EC2M`/
//!   `OPENSSL_NO_TLS_DEPRECATED_EC`/`FIPS_MODULE` guards is entered;
//! * `sigalg_constants_list[3]` (`capabilities.c:286-290`) is **3** rows;
//! * `param_sigalg_list[][10]` (`capabilities.c:315-319`) is **3** rows, its `OPENSSL_NO_ML_DSA`
//!   guard being satisfied.
//!
//! Because the tables are always present, the two walkers' `#if`-guarded "the table is absent,
//! so answer 1 without walking" arm (`capabilities.c:262`/`:324`) is dead in this profile and is
//! not transcribed; the walk always runs, exactly as the authority's compiled body does.
//!
//! ## The aliasing the two tables carry, and why it is transcribed literally
//!
//! `TLS_GROUP_ENTRY` (`capabilities.c:96-122`) and `TLS_SIGALG_ENTRY` (`capabilities.c:292-313`)
//! bind each parameter's `data` two different ways:
//!
//! * the three string parameters bind `data` to the *string literal's own address* with
//!   `data_size = sizeof(literal)` — the length **including the NUL**, so the literal
//!   `"X25519MLKEM768"` measures 15 and the empty literal measures 1;
//! * the value parameters bind `data` to the *address of a field of a table row*
//!   (`(unsigned int *)&group_list[idx].group_id` and so on), so a callback that reads a value
//!   reads it out of the row the entry indexes.
//!
//! Both are reproduced exactly below: the string parameters hand the `'static` literal through
//! [`param_utf8_string_with`], and the value parameters hand `core::ptr::addr_of!` of the row field,
//! which is a constant address (`GROUP_LIST` and `SIGALG_CONSTANTS_LIST` are `static`, so the
//! pointers into them are fixed for the life of the image). This is the same field-address aliasing
//! `src/self_test_core.rs`'s object records for its three string fields.
//!
//! The two sigalg `MIN_TLS`/`MAX_TLS`/`MIN_DTLS`/`MAX_DTLS` names alias the same four strings as
//! their group counterparts (`core_names.h:152-155` and `:165-168`), and the authority keeps four
//! macros naming four literals twice; the four `const`s below are kept separate for the same reason.
//!
//! SPDX-License-Identifier: Apache-2.0

// The group-ID spellings are the authority's (`internal/tlsgroups.h`), and renaming them to Rust
// case would break the correspondence the tables are diffed against. The precedent is
// `src/bn/prime_data.rs`.
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};

use crate::ml_kem::{ML_KEM_1024_SECBITS, ML_KEM_512_SECBITS, ML_KEM_768_SECBITS};
use crate::params::{
    OsslParam, END, OSSL_PARAM_INTEGER, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UNSIGNED_INTEGER,
};
use crate::provider::cipher::param_utf8_string_with;
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::selftest::OsslCallback;

// ---------------------------------------------------------------------------------------------
// `prov_ssl.h`'s five version macros, the only ones the two constant tables name
// ---------------------------------------------------------------------------------------------

/// `TLS1_VERSION` — `include/openssl/prov_ssl.h:24` (`0x0301`).
const TLS1_VERSION: c_int = 0x0301;
/// `TLS1_2_VERSION` — `prov_ssl.h:26` (`0x0303`).
const TLS1_2_VERSION: c_int = 0x0303;
/// `TLS1_3_VERSION` — `prov_ssl.h:27` (`0x0304`).
const TLS1_3_VERSION: c_int = 0x0304;
/// `DTLS1_VERSION` — `prov_ssl.h:28` (`0xFEFF`).
const DTLS1_VERSION: c_int = 0xFEFF;
/// `DTLS1_2_VERSION` — `prov_ssl.h:29` (`0xFEFD`).
const DTLS1_2_VERSION: c_int = 0xFEFD;

// ---------------------------------------------------------------------------------------------
// The capability name strings — `core_names.h:149-173`
// ---------------------------------------------------------------------------------------------

/// `OSSL_CAPABILITY_TLS_GROUP_ALG` — `include/openssl/core_names.h:149` (`"tls-group-alg"`).
const OSSL_CAPABILITY_TLS_GROUP_ALG: *const c_char = c"tls-group-alg".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_ID` — `core_names.h:150` (`"tls-group-id"`).
const OSSL_CAPABILITY_TLS_GROUP_ID: *const c_char = c"tls-group-id".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_IS_KEM` — `core_names.h:151` (`"tls-group-is-kem"`).
const OSSL_CAPABILITY_TLS_GROUP_IS_KEM: *const c_char = c"tls-group-is-kem".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS` — `core_names.h:152` (`"tls-max-dtls"`).
const OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS: *const c_char = c"tls-max-dtls".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_MAX_TLS` — `core_names.h:153` (`"tls-max-tls"`).
const OSSL_CAPABILITY_TLS_GROUP_MAX_TLS: *const c_char = c"tls-max-tls".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS` — `core_names.h:154` (`"tls-min-dtls"`).
const OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS: *const c_char = c"tls-min-dtls".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_MIN_TLS` — `core_names.h:155` (`"tls-min-tls"`).
const OSSL_CAPABILITY_TLS_GROUP_MIN_TLS: *const c_char = c"tls-min-tls".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_NAME` — `core_names.h:156` (`"tls-group-name"`).
const OSSL_CAPABILITY_TLS_GROUP_NAME: *const c_char = c"tls-group-name".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL` — `core_names.h:157` (`"tls-group-name-internal"`).
const OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL: *const c_char = c"tls-group-name-internal".as_ptr();
/// `OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS` — `core_names.h:158` (`"tls-group-sec-bits"`).
const OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS: *const c_char = c"tls-group-sec-bits".as_ptr();

/// `OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT` — `core_names.h:159` (`"tls-sigalg-code-point"`).
const OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT: *const c_char = c"tls-sigalg-code-point".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME` — `core_names.h:162` (`"tls-sigalg-iana-name"`).
const OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME: *const c_char = c"tls-sigalg-iana-name".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_NAME` — `core_names.h:169` (`"tls-sigalg-name"`).
const OSSL_CAPABILITY_TLS_SIGALG_NAME: *const c_char = c"tls-sigalg-name".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_OID` — `core_names.h:170` (`"tls-sigalg-oid"`).
const OSSL_CAPABILITY_TLS_SIGALG_OID: *const c_char = c"tls-sigalg-oid".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS` — `core_names.h:171` (`"tls-sigalg-sec-bits"`).
const OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS: *const c_char = c"tls-sigalg-sec-bits".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS` — `core_names.h:168`; the **same string** as
/// `OSSL_CAPABILITY_TLS_GROUP_MIN_TLS` (`:155`), and a separate `const` because the authority has
/// two macros naming one literal.
const OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS: *const c_char = c"tls-min-tls".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS` — `core_names.h:166`; aliases `..._GROUP_MAX_TLS`.
const OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS: *const c_char = c"tls-max-tls".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS` — `core_names.h:167`; aliases `..._GROUP_MIN_DTLS`.
const OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS: *const c_char = c"tls-min-dtls".as_ptr();
/// `OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS` — `core_names.h:165`; aliases `..._GROUP_MAX_DTLS`.
const OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS: *const c_char = c"tls-max-dtls".as_ptr();

// ---------------------------------------------------------------------------------------------
// The group IDs `group_list[]` references — `include/internal/tlsgroups.h`
// ---------------------------------------------------------------------------------------------

/// `OSSL_TLS_GROUP_ID_sect163k1` — `tlsgroups.h:14` (`0x0001`).
const OSSL_TLS_GROUP_ID_sect163k1: c_uint = 0x0001;
/// `OSSL_TLS_GROUP_ID_sect163r1` — `tlsgroups.h:15` (`0x0002`).
const OSSL_TLS_GROUP_ID_sect163r1: c_uint = 0x0002;
/// `OSSL_TLS_GROUP_ID_sect163r2` — `tlsgroups.h:16` (`0x0003`).
const OSSL_TLS_GROUP_ID_sect163r2: c_uint = 0x0003;
/// `OSSL_TLS_GROUP_ID_sect193r1` — `tlsgroups.h:17` (`0x0004`).
const OSSL_TLS_GROUP_ID_sect193r1: c_uint = 0x0004;
/// `OSSL_TLS_GROUP_ID_sect193r2` — `tlsgroups.h:18` (`0x0005`).
const OSSL_TLS_GROUP_ID_sect193r2: c_uint = 0x0005;
/// `OSSL_TLS_GROUP_ID_sect233k1` — `tlsgroups.h:19` (`0x0006`).
const OSSL_TLS_GROUP_ID_sect233k1: c_uint = 0x0006;
/// `OSSL_TLS_GROUP_ID_sect233r1` — `tlsgroups.h:20` (`0x0007`).
const OSSL_TLS_GROUP_ID_sect233r1: c_uint = 0x0007;
/// `OSSL_TLS_GROUP_ID_sect239k1` — `tlsgroups.h:21` (`0x0008`).
const OSSL_TLS_GROUP_ID_sect239k1: c_uint = 0x0008;
/// `OSSL_TLS_GROUP_ID_sect283k1` — `tlsgroups.h:22` (`0x0009`).
const OSSL_TLS_GROUP_ID_sect283k1: c_uint = 0x0009;
/// `OSSL_TLS_GROUP_ID_sect283r1` — `tlsgroups.h:23` (`0x000A`).
const OSSL_TLS_GROUP_ID_sect283r1: c_uint = 0x000A;
/// `OSSL_TLS_GROUP_ID_sect409k1` — `tlsgroups.h:24` (`0x000B`).
const OSSL_TLS_GROUP_ID_sect409k1: c_uint = 0x000B;
/// `OSSL_TLS_GROUP_ID_sect409r1` — `tlsgroups.h:25` (`0x000C`).
const OSSL_TLS_GROUP_ID_sect409r1: c_uint = 0x000C;
/// `OSSL_TLS_GROUP_ID_sect571k1` — `tlsgroups.h:26` (`0x000D`).
const OSSL_TLS_GROUP_ID_sect571k1: c_uint = 0x000D;
/// `OSSL_TLS_GROUP_ID_sect571r1` — `tlsgroups.h:27` (`0x000E`).
const OSSL_TLS_GROUP_ID_sect571r1: c_uint = 0x000E;
/// `OSSL_TLS_GROUP_ID_secp160k1` — `tlsgroups.h:28` (`0x000F`).
const OSSL_TLS_GROUP_ID_secp160k1: c_uint = 0x000F;
/// `OSSL_TLS_GROUP_ID_secp160r1` — `tlsgroups.h:29` (`0x0010`).
const OSSL_TLS_GROUP_ID_secp160r1: c_uint = 0x0010;
/// `OSSL_TLS_GROUP_ID_secp160r2` — `tlsgroups.h:30` (`0x0011`).
const OSSL_TLS_GROUP_ID_secp160r2: c_uint = 0x0011;
/// `OSSL_TLS_GROUP_ID_secp192k1` — `tlsgroups.h:31` (`0x0012`).
const OSSL_TLS_GROUP_ID_secp192k1: c_uint = 0x0012;
/// `OSSL_TLS_GROUP_ID_secp192r1` — `tlsgroups.h:32` (`0x0013`).
const OSSL_TLS_GROUP_ID_secp192r1: c_uint = 0x0013;
/// `OSSL_TLS_GROUP_ID_secp224k1` — `tlsgroups.h:33` (`0x0014`).
const OSSL_TLS_GROUP_ID_secp224k1: c_uint = 0x0014;
/// `OSSL_TLS_GROUP_ID_secp224r1` — `tlsgroups.h:34` (`0x0015`).
const OSSL_TLS_GROUP_ID_secp224r1: c_uint = 0x0015;
/// `OSSL_TLS_GROUP_ID_secp256k1` — `tlsgroups.h:35` (`0x0016`).
const OSSL_TLS_GROUP_ID_secp256k1: c_uint = 0x0016;
/// `OSSL_TLS_GROUP_ID_secp256r1` — `tlsgroups.h:36` (`0x0017`).
const OSSL_TLS_GROUP_ID_secp256r1: c_uint = 0x0017;
/// `OSSL_TLS_GROUP_ID_secp384r1` — `tlsgroups.h:37` (`0x0018`).
const OSSL_TLS_GROUP_ID_secp384r1: c_uint = 0x0018;
/// `OSSL_TLS_GROUP_ID_secp521r1` — `tlsgroups.h:38` (`0x0019`).
const OSSL_TLS_GROUP_ID_secp521r1: c_uint = 0x0019;
/// `OSSL_TLS_GROUP_ID_brainpoolP256r1` — `tlsgroups.h:39` (`0x001A`).
const OSSL_TLS_GROUP_ID_brainpoolP256r1: c_uint = 0x001A;
/// `OSSL_TLS_GROUP_ID_brainpoolP384r1` — `tlsgroups.h:40` (`0x001B`).
const OSSL_TLS_GROUP_ID_brainpoolP384r1: c_uint = 0x001B;
/// `OSSL_TLS_GROUP_ID_brainpoolP512r1` — `tlsgroups.h:41` (`0x001C`).
const OSSL_TLS_GROUP_ID_brainpoolP512r1: c_uint = 0x001C;
/// `OSSL_TLS_GROUP_ID_x25519` — `tlsgroups.h:42` (`0x001D`).
const OSSL_TLS_GROUP_ID_x25519: c_uint = 0x001D;
/// `OSSL_TLS_GROUP_ID_x448` — `tlsgroups.h:43` (`0x001E`).
const OSSL_TLS_GROUP_ID_x448: c_uint = 0x001E;
/// `OSSL_TLS_GROUP_ID_brainpoolP256r1_tls13` — `tlsgroups.h:44` (`0x001F`).
const OSSL_TLS_GROUP_ID_brainpoolP256r1_tls13: c_uint = 0x001F;
/// `OSSL_TLS_GROUP_ID_brainpoolP384r1_tls13` — `tlsgroups.h:45` (`0x0020`).
const OSSL_TLS_GROUP_ID_brainpoolP384r1_tls13: c_uint = 0x0020;
/// `OSSL_TLS_GROUP_ID_brainpoolP512r1_tls13` — `tlsgroups.h:46` (`0x0021`).
const OSSL_TLS_GROUP_ID_brainpoolP512r1_tls13: c_uint = 0x0021;
/// `OSSL_TLS_GROUP_ID_ffdhe2048` — `tlsgroups.h:54` (`0x0100`).
const OSSL_TLS_GROUP_ID_ffdhe2048: c_uint = 0x0100;
/// `OSSL_TLS_GROUP_ID_ffdhe3072` — `tlsgroups.h:55` (`0x0101`).
const OSSL_TLS_GROUP_ID_ffdhe3072: c_uint = 0x0101;
/// `OSSL_TLS_GROUP_ID_ffdhe4096` — `tlsgroups.h:56` (`0x0102`).
const OSSL_TLS_GROUP_ID_ffdhe4096: c_uint = 0x0102;
/// `OSSL_TLS_GROUP_ID_ffdhe6144` — `tlsgroups.h:57` (`0x0103`).
const OSSL_TLS_GROUP_ID_ffdhe6144: c_uint = 0x0103;
/// `OSSL_TLS_GROUP_ID_ffdhe8192` — `tlsgroups.h:58` (`0x0104`).
const OSSL_TLS_GROUP_ID_ffdhe8192: c_uint = 0x0104;
/// `OSSL_TLS_GROUP_ID_mlkem512` — `tlsgroups.h:59` (`0x0200`).
const OSSL_TLS_GROUP_ID_mlkem512: c_uint = 0x0200;
/// `OSSL_TLS_GROUP_ID_mlkem768` — `tlsgroups.h:60` (`0x0201`).
const OSSL_TLS_GROUP_ID_mlkem768: c_uint = 0x0201;
/// `OSSL_TLS_GROUP_ID_mlkem1024` — `tlsgroups.h:61` (`0x0202`).
const OSSL_TLS_GROUP_ID_mlkem1024: c_uint = 0x0202;
/// `OSSL_TLS_GROUP_ID_SecP256r1MLKEM768` — `tlsgroups.h:62` (`0x11EB`).
const OSSL_TLS_GROUP_ID_SecP256r1MLKEM768: c_uint = 0x11EB;
/// `OSSL_TLS_GROUP_ID_X25519MLKEM768` — `tlsgroups.h:63` (`0x11EC`).
const OSSL_TLS_GROUP_ID_X25519MLKEM768: c_uint = 0x11EC;
/// `OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024` — `tlsgroups.h:64` (`0x11ED`).
const OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024: c_uint = 0x11ED;

// ---------------------------------------------------------------------------------------------
// The two parameter constructors the entry macros need
// ---------------------------------------------------------------------------------------------

/// `OSSL_PARAM_uint(key, addr)` — `include/openssl/params.h:33-35`: the `OSSL_PARAM_DEFN` form
/// with type `OSSL_PARAM_UNSIGNED_INTEGER`, `data_size = sizeof(unsigned int)` and `return_size =
/// OSSL_PARAM_UNMODIFIED`.
///
/// The crate's `param_uint` (`src/provider/cipher.rs`) is the same constructor **without** the
/// address — the zero-`data` form the `*_gettable_params` definition lists use — so the two-argument
/// macro the capability entries spell needs its own helper. `param_utf8_string_with` is the same
/// distinction already drawn for strings.
const fn param_uint_with(key: *const c_char, data: *mut c_void) -> OsslParam {
    OsslParam {
        key,
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data,
        data_size: core::mem::size_of::<c_uint>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

/// `OSSL_PARAM_int(key, addr)` — `params.h:31-32`: `{ key, OSSL_PARAM_INTEGER, addr, sizeof(int),
/// OSSL_PARAM_UNMODIFIED }`. The signed sibling of [`param_uint_with`], and the reason the
/// authority's `int` fields (`mintls`, `maxtls`, `mindtls`, `maxdtls`, `is_kem`, and the sigalg
/// bounds) reach the callback as `OSSL_PARAM_INTEGER`.
const fn param_int_with(key: *const c_char, data: *mut c_void) -> OsslParam {
    OsslParam {
        key,
        data_type: OSSL_PARAM_INTEGER,
        data,
        data_size: core::mem::size_of::<c_int>(),
        return_size: OSSL_PARAM_UNMODIFIED,
    }
}

// ---------------------------------------------------------------------------------------------
// `group_list[]` — `capabilities.c:28-94`
// ---------------------------------------------------------------------------------------------

/// `TLS_GROUP_CONSTANTS` — `capabilities.c:28-36`. The seven fields are the ABI the entries index
/// into; the `#[repr(C)]` field order is what makes `addr_of!` of each field the authority's address.
#[repr(C)]
struct TlsGroupConstants {
    /// `unsigned int group_id` — the TLS group ID.
    group_id: c_uint,
    /// `unsigned int secbits` — bits of security.
    secbits: c_uint,
    /// `int mintls` — minimum TLS version, `-1` unsupported.
    mintls: c_int,
    /// `int maxtls` — maximum TLS version, `0` for undefined.
    maxtls: c_int,
    /// `int mindtls` — minimum DTLS version, `-1` unsupported.
    mindtls: c_int,
    /// `int maxdtls` — maximum DTLS version, `0` for undefined.
    maxdtls: c_int,
    /// `int is_kem` — indicates utility as a KEM.
    is_kem: c_int,
}

/// `group_list[]` — `capabilities.c:49-94`. The indices are a compile-time fact the
/// `param_group_list` rows reference by number, so this table carries **no** conditional arm and
/// every row is present (see the module header). FFDHE security bits are `BN_security_bits()`'s
/// (`capabilities.c:45-47`); the ML-KEM hybrids carry the ML-KEM bits.
///
/// `#[rustfmt::skip]` keeps the authority's one-row-per-line shape and its `/* n */` index
/// comments, so the table can be diffed against `capabilities.c:50-93` row by row.
#[rustfmt::skip]
static GROUP_LIST: [TlsGroupConstants; 44] = [
    /*  0 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect163k1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  1 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect163r1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  2 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect163r2, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  3 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect193r1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  4 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect193r2, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  5 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect233k1, secbits: 112, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  6 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect233r1, secbits: 112, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  7 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect239k1, secbits: 112, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  8 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect283k1, secbits: 128, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /*  9 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect283r1, secbits: 128, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 10 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect409k1, secbits: 192, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 11 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect409r1, secbits: 192, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 12 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect571k1, secbits: 256, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 13 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_sect571r1, secbits: 256, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 14 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp160k1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 15 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp160r1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 16 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp160r2, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 17 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp192k1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 18 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp192r1, secbits: 80, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 19 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp224k1, secbits: 112, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 20 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp224r1, secbits: 112, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 21 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp256k1, secbits: 128, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 22 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp256r1, secbits: 128, mintls: TLS1_VERSION, maxtls: 0, mindtls: DTLS1_VERSION, maxdtls: 0, is_kem: 0 },
    /* 23 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp384r1, secbits: 192, mintls: TLS1_VERSION, maxtls: 0, mindtls: DTLS1_VERSION, maxdtls: 0, is_kem: 0 },
    /* 24 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_secp521r1, secbits: 256, mintls: TLS1_VERSION, maxtls: 0, mindtls: DTLS1_VERSION, maxdtls: 0, is_kem: 0 },
    /* 25 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP256r1, secbits: 128, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 26 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP384r1, secbits: 192, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 27 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP512r1, secbits: 256, mintls: TLS1_VERSION, maxtls: TLS1_2_VERSION, mindtls: DTLS1_VERSION, maxdtls: DTLS1_2_VERSION, is_kem: 0 },
    /* 28 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_x25519, secbits: 128, mintls: TLS1_VERSION, maxtls: 0, mindtls: DTLS1_VERSION, maxdtls: 0, is_kem: 0 },
    /* 29 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_x448, secbits: 224, mintls: TLS1_VERSION, maxtls: 0, mindtls: DTLS1_VERSION, maxdtls: 0, is_kem: 0 },
    /* 30 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP256r1_tls13, secbits: 128, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 31 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP384r1_tls13, secbits: 192, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 32 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_brainpoolP512r1_tls13, secbits: 256, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 33 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_ffdhe2048, secbits: 112, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 34 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_ffdhe3072, secbits: 128, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 35 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_ffdhe4096, secbits: 128, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 36 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_ffdhe6144, secbits: 128, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 37 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_ffdhe8192, secbits: 192, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 0 },
    /* 38 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_mlkem512, secbits: ML_KEM_512_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
    /* 39 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_mlkem768, secbits: ML_KEM_768_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
    /* 40 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_mlkem1024, secbits: ML_KEM_1024_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
    /* 41 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_X25519MLKEM768, secbits: ML_KEM_768_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
    /* 42 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_SecP256r1MLKEM768, secbits: ML_KEM_768_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
    /* 43 */ TlsGroupConstants { group_id: OSSL_TLS_GROUP_ID_SecP384r1MLKEM1024, secbits: ML_KEM_1024_SECBITS as c_uint, mintls: TLS1_3_VERSION, maxtls: 0, mindtls: -1, maxdtls: -1, is_kem: 1 },
];

// ---------------------------------------------------------------------------------------------
// `TLS_GROUP_ENTRY` and `param_group_list[][11]` — `capabilities.c:96-257`
// ---------------------------------------------------------------------------------------------

/// `TLS_GROUP_ENTRY(tlsname, realname, algorithm, idx)` — `capabilities.c:96-122`, as ten
/// parameters plus the `OSSL_PARAM_END` terminator.
///
/// The strings take `sizeof(literal)` (NUL included) as their `data_size`; the seven value
/// parameters take `addr_of!` of the indexed `GROUP_LIST` row's field, so their `data` points into
/// the row and a callback reads the row's own value.
const fn tls_group_entry(
    tlsname: &CStr,
    realname: &CStr,
    algorithm: &CStr,
    idx: usize,
) -> [OsslParam; 11] {
    [
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_GROUP_NAME,
            tlsname.as_ptr() as *mut c_void,
            tlsname.to_bytes_with_nul().len(),
        ),
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
            realname.as_ptr() as *mut c_void,
            realname.to_bytes_with_nul().len(),
        ),
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_GROUP_ALG,
            algorithm.as_ptr() as *mut c_void,
            algorithm.to_bytes_with_nul().len(),
        ),
        param_uint_with(
            OSSL_CAPABILITY_TLS_GROUP_ID,
            core::ptr::addr_of!(GROUP_LIST[idx].group_id) as *mut c_void,
        ),
        param_uint_with(
            OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
            core::ptr::addr_of!(GROUP_LIST[idx].secbits) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
            core::ptr::addr_of!(GROUP_LIST[idx].mintls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
            core::ptr::addr_of!(GROUP_LIST[idx].maxtls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
            core::ptr::addr_of!(GROUP_LIST[idx].mindtls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
            core::ptr::addr_of!(GROUP_LIST[idx].maxdtls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
            core::ptr::addr_of!(GROUP_LIST[idx].is_kem) as *mut c_void,
        ),
        END,
    ]
}

/// `param_group_list[][11]` — `capabilities.c:153-257`, the **59** rows this profile compiles, in
/// the authority's order. Each row's fourth argument is the index into [`GROUP_LIST`] above; the
/// first three are the TLS name, the provider-internal group name and the key-management algorithm
/// (`capabilities.c:124-135`), and aliases repeat every field but the first.
///
/// Every `#if`/`#ifndef` in the authority is satisfied in this profile (module header), so the rows
/// run contiguously from the `X25519MLKEM768` hybrid through the deprecated NIST and binary-field
/// curves to `secp256k1`. `#[rustfmt::skip]` keeps one row per line so the order the walker visits
/// is visible, which is the one thing a court compares entry by entry.
#[rustfmt::skip]
static PARAM_GROUP_LIST: [[OsslParam; 11]; 59] = [
    tls_group_entry(c"X25519MLKEM768", c"", c"X25519MLKEM768", 41),
    tls_group_entry(c"x25519", c"X25519", c"X25519", 28),
    tls_group_entry(c"x448", c"X448", c"X448", 29),
    tls_group_entry(c"secp256r1", c"prime256v1", c"EC", 22),
    tls_group_entry(c"P-256", c"prime256v1", c"EC", 22), /* Alias of above */
    tls_group_entry(c"secp384r1", c"secp384r1", c"EC", 23),
    tls_group_entry(c"P-384", c"secp384r1", c"EC", 23), /* Alias of above */
    tls_group_entry(c"secp521r1", c"secp521r1", c"EC", 24),
    tls_group_entry(c"P-521", c"secp521r1", c"EC", 24), /* Alias of above */
    tls_group_entry(c"ffdhe2048", c"ffdhe2048", c"DH", 33),
    tls_group_entry(c"ffdhe3072", c"ffdhe3072", c"DH", 34),
    tls_group_entry(c"MLKEM512", c"", c"ML-KEM-512", 38),
    tls_group_entry(c"MLKEM768", c"", c"ML-KEM-768", 39),
    tls_group_entry(c"MLKEM1024", c"", c"ML-KEM-1024", 40),
    tls_group_entry(c"brainpoolP256r1", c"brainpoolP256r1", c"EC", 25),
    tls_group_entry(c"brainpoolP384r1", c"brainpoolP384r1", c"EC", 26),
    tls_group_entry(c"brainpoolP512r1", c"brainpoolP512r1", c"EC", 27),
    tls_group_entry(c"brainpoolP256r1tls13", c"brainpoolP256r1", c"EC", 30),
    tls_group_entry(c"brainpoolP384r1tls13", c"brainpoolP384r1", c"EC", 31),
    tls_group_entry(c"brainpoolP512r1tls13", c"brainpoolP512r1", c"EC", 32),
    tls_group_entry(c"SecP256r1MLKEM768", c"", c"SecP256r1MLKEM768", 42),
    tls_group_entry(c"SecP384r1MLKEM1024", c"", c"SecP384r1MLKEM1024", 43),
    tls_group_entry(c"ffdhe4096", c"ffdhe4096", c"DH", 35),
    tls_group_entry(c"ffdhe6144", c"ffdhe6144", c"DH", 36),
    tls_group_entry(c"ffdhe8192", c"ffdhe8192", c"DH", 37),
    tls_group_entry(c"sect163k1", c"sect163k1", c"EC", 0),
    tls_group_entry(c"K-163", c"sect163k1", c"EC", 0), /* Alias of above */
    tls_group_entry(c"sect163r1", c"sect163r1", c"EC", 1),
    tls_group_entry(c"sect163r2", c"sect163r2", c"EC", 2),
    tls_group_entry(c"B-163", c"sect163r2", c"EC", 2), /* Alias of above */
    tls_group_entry(c"sect193r1", c"sect193r1", c"EC", 3),
    tls_group_entry(c"sect193r2", c"sect193r2", c"EC", 4),
    tls_group_entry(c"sect233k1", c"sect233k1", c"EC", 5),
    tls_group_entry(c"K-233", c"sect233k1", c"EC", 5), /* Alias of above */
    tls_group_entry(c"sect233r1", c"sect233r1", c"EC", 6),
    tls_group_entry(c"B-233", c"sect233r1", c"EC", 6), /* Alias of above */
    tls_group_entry(c"sect239k1", c"sect239k1", c"EC", 7),
    tls_group_entry(c"sect283k1", c"sect283k1", c"EC", 8),
    tls_group_entry(c"K-283", c"sect283k1", c"EC", 8), /* Alias of above */
    tls_group_entry(c"sect283r1", c"sect283r1", c"EC", 9),
    tls_group_entry(c"B-283", c"sect283r1", c"EC", 9), /* Alias of above */
    tls_group_entry(c"sect409k1", c"sect409k1", c"EC", 10),
    tls_group_entry(c"K-409", c"sect409k1", c"EC", 10), /* Alias of above */
    tls_group_entry(c"sect409r1", c"sect409r1", c"EC", 11),
    tls_group_entry(c"B-409", c"sect409r1", c"EC", 11), /* Alias of above */
    tls_group_entry(c"sect571k1", c"sect571k1", c"EC", 12),
    tls_group_entry(c"K-571", c"sect571k1", c"EC", 12), /* Alias of above */
    tls_group_entry(c"sect571r1", c"sect571r1", c"EC", 13),
    tls_group_entry(c"B-571", c"sect571r1", c"EC", 13), /* Alias of above */
    tls_group_entry(c"secp160k1", c"secp160k1", c"EC", 14),
    tls_group_entry(c"secp160r1", c"secp160r1", c"EC", 15),
    tls_group_entry(c"secp160r2", c"secp160r2", c"EC", 16),
    tls_group_entry(c"secp192k1", c"secp192k1", c"EC", 17),
    tls_group_entry(c"secp192r1", c"prime192v1", c"EC", 18),
    tls_group_entry(c"P-192", c"prime192v1", c"EC", 18), /* Alias of above */
    tls_group_entry(c"secp224k1", c"secp224k1", c"EC", 19),
    tls_group_entry(c"secp224r1", c"secp224r1", c"EC", 20),
    tls_group_entry(c"P-224", c"secp224r1", c"EC", 20), /* Alias of above */
    tls_group_entry(c"secp256k1", c"secp256k1", c"EC", 21),
];

/// `static int tls_group_capability(OSSL_CALLBACK *cb, void *arg)` — `capabilities.c:260-271`.
///
/// One callback per [`PARAM_GROUP_LIST`] row, in row order, stopping at the first refusal: the
/// authority's `if (!cb(param_group_list[i], arg)) return 0;` (`:265-267`). The rest of the body is
/// the "the table is absent, so answer 1" arm the profile does not compile.
///
/// The authority calls `cb` with no NULL guard, so a NULL `cb` faults there; this answers 0 and
/// never walks, which is the crate's recorded treatment of a caller-supplied callback that is not
/// there.
///
/// # Safety
///
/// `arg` is passed to `cb` unchanged and must be whatever `cb` expects; `cb`, when present, is a
/// live `OSSL_CALLBACK`.
unsafe fn tls_group_capability(cb: Option<OsslCallback>, arg: *mut c_void) -> c_int {
    let Some(cb) = cb else {
        return 0;
    };

    let mut i = 0usize;
    while i < PARAM_GROUP_LIST.len() {
        // SAFETY: `PARAM_GROUP_LIST[i]` is a `'static` row terminated by `OSSL_PARAM_END`, `cb` is
        // the caller's live callback, and `arg` is passed through untouched.
        if unsafe { cb(PARAM_GROUP_LIST[i].as_ptr(), arg) } == 0 {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// `sigalg_constants_list[3]` and `param_sigalg_list[][10]` — `capabilities.c:275-320`
// ---------------------------------------------------------------------------------------------

/// `TLS_SIGALG_CONSTANTS` — `capabilities.c:277-284`, the six fields each sigalg entry indexes.
#[repr(C)]
struct TlsSigalgConstants {
    /// `unsigned int code_point` — the TLS SignatureScheme code point.
    code_point: c_uint,
    /// `unsigned int sec_bits` — bits of security.
    sec_bits: c_uint,
    /// `int min_tls` — minimum TLS version, `-1` unsupported.
    min_tls: c_int,
    /// `int max_tls` — maximum TLS version, `0` for undefined.
    max_tls: c_int,
    /// `int min_dtls` — minimum DTLS version, `-1` unsupported.
    min_dtls: c_int,
    /// `int max_dtls` — maximum DTLS version, `0` for undefined.
    max_dtls: c_int,
}

/// `sigalg_constants_list[]` — `capabilities.c:286-290`. Three rows, ML-DSA-44/65/87's code points
/// `0x0904`/`0x0905`/`0x0906`, each TLS 1.3 only and DTLS-unsupported.
static SIGALG_CONSTANTS_LIST: [TlsSigalgConstants; 3] = [
    TlsSigalgConstants {
        code_point: 0x0904,
        sec_bits: 128,
        min_tls: TLS1_3_VERSION,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
    TlsSigalgConstants {
        code_point: 0x0905,
        sec_bits: 192,
        min_tls: TLS1_3_VERSION,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
    TlsSigalgConstants {
        code_point: 0x0906,
        sec_bits: 256,
        min_tls: TLS1_3_VERSION,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
];

/// `TLS_SIGALG_ENTRY(tlsname, algorithm, oid, idx)` — `capabilities.c:292-313`, as nine parameters
/// plus the terminator. The two `OSSL_PARAM_uint` values are `code_point`/`sec_bits`; the four
/// `OSSL_PARAM_int` values are the TLS/DTLS bounds, each `addr_of!` into the indexed
/// [`SIGALG_CONSTANTS_LIST`] row.
const fn tls_sigalg_entry(
    tlsname: &CStr,
    algorithm: &CStr,
    oid: &CStr,
    idx: usize,
) -> [OsslParam; 10] {
    [
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,
            tlsname.as_ptr() as *mut c_void,
            tlsname.to_bytes_with_nul().len(),
        ),
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_SIGALG_NAME,
            algorithm.as_ptr() as *mut c_void,
            algorithm.to_bytes_with_nul().len(),
        ),
        param_utf8_string_with(
            OSSL_CAPABILITY_TLS_SIGALG_OID,
            oid.as_ptr() as *mut c_void,
            oid.to_bytes_with_nul().len(),
        ),
        param_uint_with(
            OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].code_point) as *mut c_void,
        ),
        param_uint_with(
            OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].sec_bits) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].min_tls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].max_tls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].min_dtls) as *mut c_void,
        ),
        param_int_with(
            OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,
            core::ptr::addr_of!(SIGALG_CONSTANTS_LIST[idx].max_dtls) as *mut c_void,
        ),
        END,
    ]
}

/// `param_sigalg_list[][10]` — `capabilities.c:315-319`. Three rows, in the authority's order,
/// naming the ML-DSA IANA spellings, the provider algorithm names and the `id-ml-dsa-*` OIDs.
static PARAM_SIGALG_LIST: [[OsslParam; 10]; 3] = [
    tls_sigalg_entry(c"mldsa44", c"ML-DSA-44", c"2.16.840.1.101.3.4.3.17", 0),
    tls_sigalg_entry(c"mldsa65", c"ML-DSA-65", c"2.16.840.1.101.3.4.3.18", 1),
    tls_sigalg_entry(c"mldsa87", c"ML-DSA-87", c"2.16.840.1.101.3.4.3.19", 2),
];

/// `static int tls_sigalg_capability(OSSL_CALLBACK *cb, void *arg)` — `capabilities.c:322-332`.
/// The same walk as [`tls_group_capability`], over [`PARAM_SIGALG_LIST`]'s three rows, with the
/// same NULL-`cb` treatment.
///
/// # Safety
///
/// As [`tls_group_capability`]: `arg` is passed to `cb` unchanged; `cb`, when present, is live.
unsafe fn tls_sigalg_capability(cb: Option<OsslCallback>, arg: *mut c_void) -> c_int {
    let Some(cb) = cb else {
        return 0;
    };

    let mut i = 0usize;
    while i < PARAM_SIGALG_LIST.len() {
        // SAFETY: `PARAM_SIGALG_LIST[i]` is a `'static` row terminated by `OSSL_PARAM_END`, `cb` is
        // the caller's live callback, and `arg` is passed through untouched.
        if unsafe { cb(PARAM_SIGALG_LIST[i].as_ptr(), arg) } == 0 {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// `ossl_prov_get_capabilities` — `capabilities.c:334-344`
// ---------------------------------------------------------------------------------------------

/// `int ossl_prov_get_capabilities(void *provctx, const char *capability, OSSL_CALLBACK *cb,
/// void *arg)` — `capabilities.c:334-344`.
///
/// A `strcasecmp` on `capability` selects the walk: `"TLS-GROUP"` and `"TLS-SIGALG"` claim their
/// arms, and everything else falls through to `0` (`:342-343`), which the court's unclaimed-name
/// arm observes. `provctx` is unused, exactly as in the authority; the signature keeps the
/// parameter for the `OSSL_FUNC_provider_get_capabilities_fn` prototype.
///
/// The authority dereferences `capability` in its first `OPENSSL_strcasecmp`, so a NULL there
/// faults; this answers 0 without comparing, the crate's recorded treatment of a NULL string.
///
/// The name is **not** `#[no_mangle]`: this is the default provider's internal up-call, reached
/// through the dispatch table at `defltprov.c:747-748` and not reachable by symbol from a consumer,
/// so it is not in `symbols-libcrypto.json`.
///
/// # Safety
///
/// `capability` is NULL or a NUL-terminated string; `cb`, when present, is a live `OSSL_CALLBACK`;
/// `arg` is whatever `cb` expects.
pub(crate) unsafe extern "C" fn ossl_prov_get_capabilities(
    _provctx: *mut c_void,
    capability: *const c_char,
    cb: Option<OsslCallback>,
    arg: *mut c_void,
) -> c_int {
    if capability.is_null() {
        return 0;
    }
    // SAFETY: `capability` is non-NULL and NUL-terminated per the contract; the second argument is
    // a `'static` literal.
    if unsafe { OPENSSL_strcasecmp(capability, c"TLS-GROUP".as_ptr()) } == 0 {
        // SAFETY: `cb` is the caller's callback and `arg` is the caller's own; the walker handles a
        // NULL callback and passes both through unchanged.
        return unsafe { tls_group_capability(cb, arg) };
    }
    // SAFETY: as above.
    if unsafe { OPENSSL_strcasecmp(capability, c"TLS-SIGALG".as_ptr()) } == 0 {
        // SAFETY: as above.
        return unsafe { tls_sigalg_capability(cb, arg) };
    }

    // We don't support this capability.
    0
}
